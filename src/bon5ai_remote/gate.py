"""Viewer pairing: one-time codes traded for viewer tokens, both held only as digests.

Three rules are load-bearing:

* **Codes are minted only over the admin socket**, a Unix socket in a 0700
  directory, so minting takes a shell as this user. No public route creates a code.
* **A viewer is bound to one tmux session**, by the session's id and creation time.
  When it ends, its viewers see "Session ended" and must pair again; a new session
  never inherits old viewers.
* **Nothing here writes to the terminal.** The stream comes from a read-only,
  ignore-size tmux client, and asciinema's local server has no input path.

Codes and viewers live in memory, so restarting the gate signs every viewer out.
"""

from __future__ import annotations

import hashlib
import http.client
import re
import secrets
import socket
import threading
import time
from collections import deque

CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I/L
CODE_LENGTH = 8
# Wrong codes are counted per client when a trusted proxy names the client, else in one
# shared bucket: behind Funnel every request comes from 127.0.0.1. A named client is
# locked out after FAILURE_LIMIT wrong codes in the window. The shared bucket never
# locks anyone out: that would let anyone keep the owner from pairing with ten requests
# every ten minutes. The listener slows every wrong answer down instead (web.FAILURE_DELAY,
# with a cap on how many may wait at once), which bounds guessing at a rate the 40-bit
# code space laughs at, and the terminal is told once the window holds FAILURE_LIMIT
# wrong codes from anywhere, so guessing is noticed.
FAILURE_LIMIT = 10
FAILURE_WINDOW_SECONDS = 600
MAX_STREAMS = 4

PLAYER_ASSETS = {"/player.js": (re.compile(r'src="(asciinema-player\.min\.[0-9a-f]+\.js)"'), "text/javascript"),
                 "/player.css": (re.compile(r'href="(asciinema-player\.[0-9a-f]+\.css)"'), "text/css")}
# Asciinema's viewer page loads its symbol font with a root-absolute url. The gate may
# be mounted under a path in public, so that url would leave the mount and the browser
# would never receive the file. Only a name this shape is proxied, and only if the
# current index actually references it.
_FONT_FACE = re.compile(r"@font-face\s*\{(?P<body>[^{}]*)\}", re.IGNORECASE)
_FONT_URL = re.compile(r"""url\((?P<q>['"])(?P<path>/[^'"]+)(?P=q)\)""")
FONT_NAME = re.compile(r"[A-Za-z0-9._-]+\.woff2")


class InvalidCode(Exception):
    def __init__(self, failures: int):
        super().__init__(failures)
        self.failures = failures


class Throttled(Exception):
    pass


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def normalize_code(typed: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", typed.upper())


def new_code(length: int = CODE_LENGTH) -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(length))


def stream_up(addr: tuple[str, int] | None) -> bool:
    if addr is None:
        return False
    try:
        socket.create_connection(addr, timeout=1).close()
    except OSError:
        return False
    return True


def stream_get(addr: tuple[str, int] | None, path: str) -> bytes | None:
    if addr is None:
        return None
    conn = http.client.HTTPConnection(*addr, timeout=5)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        return response.read() if response.status == 200 else None
    except OSError:
        return None
    finally:
        conn.close()


def symbol_fonts(index: str) -> tuple[str, dict[str, str]]:
    """Asciinema's @font-face rules, with each font url made relative to the page.

    The rules live in the stream's index, not in the player stylesheet the gate
    already proxies, so copying that stylesheet alone drops the symbol font. A
    root-absolute url is rewritten to the file's name; the browser then requests
    it from the gate, under the mount, the same way it requests the player.
    """
    files: dict[str, str] = {}

    def repl(match: re.Match) -> str:
        path = match.group("path")
        name = path.rsplit("/", 1)[-1]
        if not FONT_NAME.fullmatch(name):
            return match.group(0)
        files[name] = path
        return f'url("{name}")'

    faces = []
    for match in _FONT_FACE.finditer(index):
        body = _FONT_URL.sub(repl, match.group("body"))
        if "font-display" not in body:
            body = body.rstrip() + "\n  font-display: block;\n"
        faces.append("@font-face {" + body + "}")
    return ("\n".join(faces) + "\n") if faces else "", files


class Gate:
    def __init__(self, *, code_ttl: int, viewer_ttl: int, session_lookup, host_attached, stream_address,
                 on_viewers=lambda session, count: None, on_guessing=lambda failures: None, clock=time.time):
        self.code_ttl = code_ttl
        self.viewer_ttl = viewer_ttl
        self.session_lookup = session_lookup
        self.host_attached = host_attached
        self.stream_address = stream_address
        self.on_viewers = on_viewers
        self.on_guessing = on_guessing
        self.clock = clock
        self._lock = threading.Lock()
        self._codes: dict[str, tuple[str, float]] = {}
        self._viewers: dict[str, tuple[str, float]] = {}
        self._failures: dict[str, deque[float]] = {}
        self._all_failures: deque[float] = deque()
        self._streams: dict[str, list[str]] = {}  # session -> the viewer of each open stream
        self._sizes: dict[str, tuple[int, int]] = {}  # viewer -> the terminal size its page asked for
        self._assets: dict[str, bytes] = {}

    def _prune(self, now: float) -> None:
        for table in (self._codes, self._viewers):
            for key in [key for key, (_, expires) in table.items() if expires <= now]:
                del table[key]
        for key in [key for key in self._sizes if key not in self._viewers]:
            del self._sizes[key]
        cutoff = now - FAILURE_WINDOW_SECONDS
        for client in list(self._failures):
            window = self._failures[client]
            while window and window[0] <= cutoff:
                window.popleft()
            if not window:
                del self._failures[client]
        while self._all_failures and self._all_failures[0] <= cutoff:
            self._all_failures.popleft()

    def mint(self, ttl: int | None = None) -> str | None:
        session = self.session_lookup()
        if session is None:
            return None
        code = new_code()
        now = self.clock()
        with self._lock:
            self._prune(now)
            self._codes[digest(code)] = (session, now + (ttl or self.code_ttl))
        return f"{code[:4]}-{code[4:]}"

    def claim(self, typed: str, client: str = "") -> str:
        """Trade a code for a viewer token. Codes work once.

        `client` is the address a trusted proxy reported, or "" when clients can't be told
        apart. Only a named client is ever locked out (Throttled); see FAILURE_LIMIT."""
        code = normalize_code(typed)
        now = self.clock()
        noticed = False
        with self._lock:
            self._prune(now)
            window = self._failures.setdefault(client, deque()) if client else None
            if window is not None and len(window) >= FAILURE_LIMIT:
                raise Throttled()
            entry = self._codes.pop(digest(code), None)
            if entry is None:
                if window is not None:
                    window.append(now)
                self._all_failures.append(now)
                noticed = len(self._all_failures) == FAILURE_LIMIT  # once per window
                failures = len(window) if window is not None else len(self._all_failures)
            else:
                token = secrets.token_urlsafe(32)
                self._viewers[digest(token)] = (entry[0], now + self.viewer_ttl)
        if entry is None:
            if noticed:
                self.on_guessing(FAILURE_LIMIT)
            raise InvalidCode(failures)
        return token

    def viewer_session(self, token: str) -> str | None:
        if not token:
            return None
        now = self.clock()
        with self._lock:
            self._prune(now)
            entry = self._viewers.get(digest(token))
        return entry[0] if entry else None

    def live_viewer_session(self, token: str) -> str | None:
        """The viewer's session, but only while it is still the running one. A viewer of an
        ended session is revoked here, so its cookie can't watch whatever session comes next."""
        session = self.viewer_session(token)
        if session is None:
            return None
        if self.session_lookup() != session:
            self.revoke(token)
            return None
        return session

    def revoke(self, token: str) -> None:
        with self._lock:
            self._viewers.pop(digest(token), None)
            self._sizes.pop(digest(token), None)

    def revoke_all(self) -> int:
        with self._lock:
            count = len(self._viewers)
            self._viewers.clear()
            self._sizes.clear()
        return count

    def viewer_count(self) -> int:
        with self._lock:
            return sum(len(watching) for watching in self._streams.values())

    def request_size(self, token: str, size: tuple[int, int]) -> bool:
        """Remember the terminal size a viewer's page asked for. False if token is no viewer."""
        key = digest(token)
        with self._lock:
            self._prune(self.clock())
            if key not in self._viewers:
                return False
            self._sizes[key] = size
        return True

    def requested_size(self, token: str) -> tuple[int, int] | None:
        with self._lock:
            return self._sizes.get(digest(token))

    def sole_viewer_size(self, session: str, token: str | None = None) -> tuple[int, int] | None:
        """The size asked for by the one viewer watching the session: None while nobody or
        more than one stream is watching, or that viewer asked for none, or isn't token."""
        with self._lock:
            self._prune(self.clock())
            watching = self._streams.get(session, [])
            if len(watching) != 1 or (token is not None and watching[0] != digest(token)):
                return None
            return self._sizes.get(watching[0])

    def status(self, token: str) -> dict | None:
        session = self.viewer_session(token)
        if session is None:
            return None
        if self.session_lookup() != session:
            self.revoke(token)
            return {"state": "ended"}
        if not stream_up(self.stream_address()):
            state = "stream-down"
        elif not self.host_attached():
            state = "host-away"
        else:
            state = "live"
        with self._lock:
            viewers = len(self._streams.get(session, []))
        return {"state": state, "viewers": viewers}

    def open_stream(self, session: str, token: str) -> bool:
        with self._lock:
            watching = self._streams.setdefault(session, [])
            if len(watching) >= MAX_STREAMS:
                return False
            watching.append(digest(token))
            count = len(watching)
        self.on_viewers(session, count)
        return True

    def close_stream(self, session: str, token: str) -> None:
        with self._lock:
            watching = self._streams.get(session, [])
            if digest(token) in watching:
                watching.remove(digest(token))
            count = len(watching)
            if not count:
                self._streams.pop(session, None)
        self.on_viewers(session, count)

    def player_asset(self, path: str) -> bytes | None:
        """The player JS/CSS from asciinema's own server, so player and stream always match."""
        pattern, _ = PLAYER_ASSETS[path]
        addr = self.stream_address()
        index = stream_get(addr, "/")
        match = index and pattern.search(index.decode(errors="replace"))
        if not match:
            return None
        name = match.group(1)  # content-hashed, so a cached copy never goes stale
        with self._lock:
            cached = self._assets.get(name)
        if cached is None:
            cached = stream_get(addr, f"/{name}")
            if cached is not None:
                with self._lock:
                    self._assets[name] = cached
        return cached

    def symbol_font_sheet(self) -> tuple[str, dict[str, str]] | None:
        """The symbol-font CSS and the upstream path of each file. None if the stream is down."""
        index = stream_get(self.stream_address(), "/")
        if index is None:
            return None
        return symbol_fonts(index.decode(errors="replace"))

    def symbol_font(self, name: str) -> bytes | None:
        """One symbol font from the stream, or None when the stream is down or has no such file."""
        sheet = self.symbol_font_sheet()
        if sheet is None or name not in sheet[1]:
            return None
        with self._lock:
            cached = self._assets.get(name)
        if cached is None:
            cached = stream_get(self.stream_address(), sheet[1][name])
            if cached is not None:
                with self._lock:
                    self._assets[name] = cached
        return cached
