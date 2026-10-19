"""Everything the gate asks of tmux, always against one dedicated server.

The shared session lives on its own tmux server (``tmux -S <runtime>/tmux.sock``),
not the user's everyday one, so no bug here and no agent token can reach a session
the user did not share.

Two details of tmux's command line decide how text is typed into a pane:

* ``--`` ends the options, or text such as ``-R`` would be read as a flag
  (``send-keys -R`` resets the terminal).
* An argument that ends in ``;`` is a command separator to tmux: it strips the
  ``;`` and, if a backslash precedes it, turns that backslash into the ``;``.
  ``literal_arg`` escapes the last ``;`` so the text arrives exactly as given.
"""

from __future__ import annotations

import re
import secrets
import subprocess
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path

PANE_ID = re.compile(r"%\d{1,6}")
# tmux prints a separator tab literally but escapes a tab inside a value (a window name, a
# path) as the two characters "\t", so free-text fields can't break the split.
SEP = "\t"
PANE_FIELDS = ("pane_id", "session_id", "session_created", "window_index", "window_active", "pane_active",
               "pane_pid", "alternate_on", "pane_in_mode", "pane_dead", "pane_width", "pane_height",
               "cursor_x", "cursor_y", "pane_current_command", "window_name", "pane_current_path")
PANE_FORMAT = SEP.join("#{%s}" % name for name in PANE_FIELDS)


def printable(value: str) -> str:
    """A tmux-reported name (window, command, path) with control characters made visible.
    A process can name itself anything, escape sequences included."""
    return "".join(ch if unicodedata.category(ch)[0] != "C" else "?" for ch in value)


@dataclass(frozen=True)
class Pane:
    id: str
    session_key: str
    window_index: int
    window_active: bool
    pane_active: bool
    pid: int
    alternate_on: bool
    in_mode: bool
    dead: bool
    width: int
    height: int
    cursor_x: int
    cursor_y: int
    command: str
    window_name: str
    path: str

    @classmethod
    def parse(cls, line: str) -> Pane | None:
        values = line.split(SEP)
        if len(values) < len(PANE_FIELDS):
            return None
        if len(values) > len(PANE_FIELDS):
            # A raw tab got through in a free-text field. The fixed fields come first and
            # the path last, so give the extra pieces to the window name between them.
            fixed = len(PANE_FIELDS) - 2
            values = values[:fixed] + [SEP.join(values[fixed:-1]), values[-1]]
        raw = dict(zip(PANE_FIELDS, values))
        try:
            return cls(id=raw["pane_id"], session_key=f"{raw['session_id']}@{raw['session_created']}",
                       window_index=int(raw["window_index"]), window_active=raw["window_active"] == "1",
                       pane_active=raw["pane_active"] == "1", pid=int(raw["pane_pid"]),
                       alternate_on=raw["alternate_on"] == "1", in_mode=raw["pane_in_mode"] == "1",
                       dead=raw["pane_dead"] == "1", width=int(raw["pane_width"]),
                       height=int(raw["pane_height"]), cursor_x=int(raw["cursor_x"]),
                       cursor_y=int(raw["cursor_y"]), command=printable(raw["pane_current_command"]),
                       window_name=printable(raw["window_name"]), path=printable(raw["pane_current_path"]))
        except ValueError:
            return None


def literal_arg(text: str) -> str:
    """Text for ``send-keys -l --`` that tmux's argument parser leaves as it is."""
    return text[:-1] + "\\;" if text.endswith(";") else text


def foreground_pgid(pid: int, run=subprocess.run) -> int | None:
    """The terminal's foreground process group, as seen from the process pid (ps works on Linux and macOS)."""
    try:
        result = run(["ps", "-o", "tpgid=", "-p", str(pid)], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


class Tmux:
    def __init__(self, socket: Path, session: str, run=subprocess.run):
        self.socket = socket
        self.session = session
        self._run = run

    # ---- plumbing -----------------------------------------------------------------
    def _call(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess | None:
        try:
            return self._run(["tmux", "-S", str(self.socket), *args], input=stdin, capture_output=True,
                             text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return None

    def out(self, *args: str) -> str | None:
        """Stripped stdout, or None if tmux failed or isn't there."""
        result = self._call(*args)
        return result.stdout.strip() if result is not None and result.returncode == 0 else None

    def raw(self, *args: str) -> str | None:
        result = self._call(*args)
        return result.stdout if result is not None and result.returncode == 0 else None

    def ok(self, *args: str, stdin: str | None = None) -> bool:
        result = self._call(*args, stdin=stdin)
        return result is not None and result.returncode == 0

    @property
    def target(self) -> str:
        """The session's current window, matched by exact name."""
        return f"={self.session}:"

    # ---- the session ----------------------------------------------------------------
    def session_key(self) -> str | None:
        # Id plus creation time: tmux reuses ids after a server restart, so the id
        # alone could let a new session inherit an old session's viewers and agents.
        return self.out("display-message", "-p", "-t", self.target, "#{session_id}@#{session_created}") or None

    def has_session(self) -> bool:
        return self.ok("has-session", "-t", f"={self.session}")

    def host_attached(self) -> bool:
        """True while a writable client (a person's terminal) is attached."""
        out = self.out("list-clients", "-t", f"={self.session}", "-F", "#{client_readonly}")
        return bool(out) and "0" in out.split()

    def last_human_input(self) -> float | None:
        """When a writable client last sent a key, in epoch seconds."""
        out = self.out("list-clients", "-t", f"={self.session}", "-F", "#{client_readonly} #{client_activity}")
        times = []
        for line in (out or "").splitlines():
            readonly, _, activity = line.partition(" ")
            if readonly == "0" and activity.isdigit():
                times.append(float(activity))
        return max(times) if times else None

    def set_option(self, name: str, value: str) -> bool:
        return self.ok("set-option", "-q", "-t", self.target, name, value)

    def unset_option(self, name: str) -> bool:
        return self.ok("set-option", "-q", "-u", "-t", self.target, name)

    def get_option(self, name: str) -> str | None:
        return self.out("show-options", "-q", "-v", "-t", self.target, name) or None

    def display(self, message: str) -> None:
        """Show a message on every writable client of the session."""
        out = self.out("list-clients", "-t", f"={self.session}", "-F", "#{client_readonly} #{client_name}")
        for line in (out or "").splitlines():
            readonly, _, name = line.partition(" ")
            if readonly == "0" and name:
                self.ok("display-message", "-c", name, "-d", "5000", message.replace("#", "##"))

    def window_size(self) -> tuple[int, int, str] | None:
        """(width, height, status) of the session's current window."""
        out = self.out("display-message", "-p", "-t", self.target, "#{window_width} #{window_height} #{status}")
        try:
            width, height, status = (out or "").split()
            return int(width), int(height), status
        except ValueError:
            return None

    # ---- panes ----------------------------------------------------------------------
    def active_pane(self) -> str | None:
        pane = self.out("display-message", "-p", "-t", self.target, "#{pane_id}")
        return pane if pane and PANE_ID.fullmatch(pane) else None

    def panes(self) -> list[Pane]:
        out = self.out("list-panes", "-s", "-t", f"={self.session}", "-F", PANE_FORMAT)
        return [pane for pane in map(Pane.parse, (out or "").splitlines()) if pane]

    def pane(self, pane_id: str) -> Pane | None:
        if not PANE_ID.fullmatch(pane_id):
            return None
        out = self.out("display-message", "-p", "-t", pane_id, PANE_FORMAT)
        return Pane.parse(out) if out else None

    def capture(self, pane_id: str, history: int = 0) -> tuple[list[str], list[str]] | None:
        """(visible lines, history lines), plain text with trailing spaces removed.

        No -e (escape sequences stay out of what an agent reads) and no -J (a wrapped
        line stays two rows, so the cursor row still matches a line)."""
        if not PANE_ID.fullmatch(pane_id):
            return None
        visible = self.raw("capture-pane", "-p", "-t", pane_id)
        if visible is None:
            return None
        lines = [line.rstrip() for line in visible.split("\n")]
        if lines and lines[-1] == "":
            lines.pop()
        older: list[str] = []
        if history > 0:
            text = self.raw("capture-pane", "-p", "-t", pane_id, "-S", f"-{history}", "-E", "-1")
            older = [line.rstrip() for line in (text or "").split("\n")]
            if older and older[-1] == "":
                older.pop()
        return lines, older

    # ---- writing --------------------------------------------------------------------
    def send_literal(self, pane_id: str, text: str) -> bool:
        return PANE_ID.fullmatch(pane_id) is not None and self.ok("send-keys", "-t", pane_id, "-l", "--",
                                                                  literal_arg(text))

    def send_keys(self, pane_id: str, keys: list[str]) -> bool:
        """Named keys only; callers pass names from an allowlist."""
        return PANE_ID.fullmatch(pane_id) is not None and self.ok("send-keys", "-t", pane_id, *keys)

    def paste(self, pane_id: str, text: str) -> bool:
        """Paste through a private, single-use buffer: bracketed if the program asked for it."""
        if not PANE_ID.fullmatch(pane_id):
            return False
        name = f"bon5ai-{secrets.token_hex(8)}"
        if not self.ok("load-buffer", "-b", name, "-", stdin=text):
            return False
        if self.ok("paste-buffer", "-p", "-d", "-b", name, "-t", pane_id):
            return True
        self.ok("delete-buffer", "-b", name)
        return False


def human_typing(tmux: Tmux, window_seconds: float = 2.0, clock=time.time) -> bool:
    last = tmux.last_human_input()
    return last is not None and clock() - last < window_seconds
