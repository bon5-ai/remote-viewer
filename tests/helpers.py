"""Fakes shared by the tests: a clock, a tmux that records what it was asked, and configs."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import socket
import threading
from pathlib import Path

from bon5ai_remote.audit import Audit
from bon5ai_remote.config import Config, Listener
from bon5ai_remote.state import State
from bon5ai_remote.tmux import Pane

STATIC = Path(__file__).resolve().parent.parent / "src" / "bon5ai_remote" / "static"
PUBLIC = "https://term.example.test/remote/"
SECRET = "test-proxy-secret"


class Clock:
    def __init__(self, now: float = 1_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


def make_pane(pane_id: str = "%1", **overrides) -> Pane:
    values = dict(id=pane_id, session_key="$1@100", window_index=0, window_active=True, pane_active=True,
                  pid=4242, alternate_on=False, in_mode=False, dead=False, width=80, height=24, cursor_x=12,
                  cursor_y=0, command="bash", window_name="bash", path="/home/someone")
    values.update(overrides)
    return Pane(**values)


class FakeTmux:
    """Answers like tmux for one session and records every write."""

    def __init__(self):
        self.session = "$1@100"
        self.host = True
        self.human = None
        self.options: dict[str, str] = {}
        self.messages: list[str] = []
        self.writes: list[tuple] = []
        self.panes_by_id = {"%1": make_pane("%1")}
        self.screen = ["someone@box:~$"]
        self.after_enter = None  # called when Enter is sent, to simulate a command running

    def session_key(self):
        return self.session

    def has_session(self):
        return self.session is not None

    def host_attached(self):
        return self.host

    def last_human_input(self):
        return self.human

    def set_option(self, name, value):
        self.options[name] = value
        return True

    def unset_option(self, name):
        self.options.pop(name, None)
        return True

    def get_option(self, name):
        return self.options.get(name)

    def display(self, message):
        self.messages.append(message)

    def active_pane(self):
        return "%1"

    def panes(self):
        return list(self.panes_by_id.values())

    def pane(self, pane_id):
        return self.panes_by_id.get(pane_id)

    def capture(self, pane_id, history=0):
        if pane_id not in self.panes_by_id:
            return None
        return list(self.screen), (["older line"] * min(history, 3))

    def send_literal(self, pane_id, text):
        self.writes.append(("text", pane_id, text))
        self.screen[-1] += text
        return True

    def send_keys(self, pane_id, keys):
        self.writes.append(("keys", pane_id, list(keys)))
        if "Enter" in keys and self.after_enter:
            self.after_enter()
        return True

    def paste(self, pane_id, text):
        self.writes.append(("paste", pane_id, text))
        return True


def make_listener(**overrides) -> Listener:
    values = dict(host="127.0.0.1", port=8095, public_url=PUBLIC, viewer=True, mcp=True,
                  allowed_hosts=("box.tailnet.test",), proxy_header="", client_ip_header="", deny_funnel=False)
    values.update(overrides)
    return Listener(**values)


def make_config(tmp: Path | None = None, *, listeners=None, **overrides) -> Config:
    tmp = tmp or Path("/nonexistent")
    values = dict(session="share", tmux_socket=tmp / "tmux.sock", runtime_dir=tmp, state_dir=tmp,
                  admin_socket=tmp / "admin.sock", audit_log=tmp / "audit.jsonl",
                  listeners=tuple(listeners or [make_listener()]), code_ttl=600, viewer_ttl=3600,
                  agent_ttl=3600, access_token_ttl=600, client_metadata_documents=False, static_dir=STATIC)
    values.update(overrides)
    return Config(**values)


def make_state(cfg: Config | None = None, tmux: FakeTmux | None = None, clock=None, fetch_metadata=None,
               audit_path: Path | None = None) -> State:
    cfg = cfg or make_config()
    return State(cfg, tmux=tmux or FakeTmux(), audit=Audit(audit_path), clock=clock, fetch_metadata=fetch_metadata)


# ---- a stand-in for asciinema's local server ----------------------------------------------------
STREAM_INDEX = b"""<!DOCTYPE html>
<link rel="stylesheet" href="asciinema-player.17fff37791ea2096.css">
<style>
    @font-face {
      font-family: "Symbols Nerd Font";
      src: local(SymbolsNerdFont-Regular),
           url("/SymbolsNerdFont-Regular.64622a496f8fd2e6.woff2") format("woff2");
    }
    body { margin: 0; }
</style>
<script src="asciinema-player.min.ebe963dd3b632abe.js"></script>
"""
STREAM_FONT = b"wOF2-symbol-font"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def read_head(sock: socket.socket) -> tuple[bytes, bytes]:
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 16384:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, sep, rest = buf.partition(b"\r\n\r\n")
    return head + sep, rest


class FakeStream:
    """Answers /ws with a real websocket handshake and one binary frame, and serves the
    index plus the symbol font the player page references. Records every request head."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.address = self.sock.getsockname()
        self.requests: list[str] = []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        with contextlib.closing(conn):
            try:
                head, _ = read_head(conn)
            except OSError:
                return
            text = head.decode(errors="replace")
            self.requests.append(text)
            path = text.split("\r\n", 1)[0].split(" ")[1] if text.startswith("GET ") else ""
            headers = {line.split(":", 1)[0].lower(): line.split(":", 1)[1].strip()
                       for line in text.split("\r\n")[1:] if ":" in line}
            if path == "/ws":
                accept = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"] + WS_GUID).encode()).digest())
                conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                             b"Sec-WebSocket-Accept: " + accept + b"\r\nSec-WebSocket-Protocol: v1.alis\r\n\r\n"
                             + bytes([0x82, 5]) + b"FRAME")
                try:
                    conn.recv(1024)  # hold the connection until the gate closes it
                except OSError:
                    pass
            elif path == "/":
                self._send(conn, 200, STREAM_INDEX, "text/html")
            elif path == "/SymbolsNerdFont-Regular.64622a496f8fd2e6.woff2":
                self._send(conn, 200, STREAM_FONT, "font/woff2")
            elif path == "/asciinema-player.min.ebe963dd3b632abe.js":
                self._send(conn, 200, b"// player", "text/javascript")
            else:
                self._send(conn, 404, b"no\n", "text/plain")

    @staticmethod
    def _send(conn, status, body, content_type):
        conn.sendall(f"HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\n"
                     f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)

    def close(self):
        self.sock.close()


def jsonrpc(method: str, params: dict | None = None, request_id: int = 1) -> str:
    message = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return json.dumps(message)
