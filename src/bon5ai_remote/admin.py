"""The admin socket: how a shell on this machine mints viewer codes and approves agents.

It is a Unix socket in the 0700 runtime directory, created 0600, and on Linux the
peer's uid is checked as well. Holding a shell as this user is what authorizes
everything here; the public listeners have no route that does any of it.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import socket
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from .agents import GRANT_ID, SCOPES, NotFound
from .config import CODE_TTL_RANGE
from .state import State
from .tmux import PANE_ID

log = logging.getLogger("bon5ai_remote.admin")
MAX_BODY = 8192


def peer_uid(sock: socket.socket) -> int | None:
    if not hasattr(socket, "SO_PEERCRED"):
        return None  # macOS: the socket's 0700 directory is the check
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)[1]


class AdminServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def verify_request(self, request, client_address) -> bool:
        uid = peer_uid(request)
        return uid is None or uid == os.getuid()


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "tmux-remote-viewer-admin"
    sys_version = ""

    @property
    def state(self) -> State:
        return self.server.state

    def address_string(self) -> str:
        return "admin"  # AF_UNIX peers have no address

    def log_message(self, fmt: str, *args) -> None:
        log.debug("admin " + fmt, *args)

    def send_json(self, code: int, payload) -> None:
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def fail(self, code: int, message: str) -> None:
        self.send_json(code, {"error": message})

    def body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 0 < length <= MAX_BODY:
            return {}
        try:
            value = json.loads(self.rfile.read(length))
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}

    # ---- routes ---------------------------------------------------------------------------
    def do_GET(self) -> None:
        state = self.state
        if self.path == "/status":
            session = state.tmux.session_key()
            return self.send_json(200, {
                "session": state.cfg.session, "running": session is not None,
                "stream": state.stream_address() is not None, "viewers": state.gate.viewer_count(),
                "agents": len(state.agents.grants()), "pending": len(state.agents.pending()),
                "listeners": [{"address": item.name, "publicUrl": item.public_url, "viewer": item.viewer,
                               "mcp": item.mcp} for item in state.cfg.listeners]})
        if self.path == "/agent/requests":
            return self.send_json(200, {"requests": state.agents.pending()})
        if self.path == "/agent/grants":
            now = state.agents.clock()
            return self.send_json(200, {"grants": [grant.as_dict(now) for grant in state.agents.grants()]})
        self.fail(404, "not found")

    def do_POST(self) -> None:
        state = self.state
        body = self.body()
        if self.path == "/pair":
            ttl = body.get("ttl", state.cfg.code_ttl)
            low, high = CODE_TTL_RANGE
            if not isinstance(ttl, int) or isinstance(ttl, bool) or not low <= ttl <= high:
                return self.fail(400, f"A code can last {low // 60} to {high // 60} minutes.")
            code = state.gate.mint(ttl)
            if code is None:
                return self.fail(409, f"No tmux session named '{state.cfg.session}' is running. "
                                      "Start one with: tmux-remote-viewer share")
            return self.send_json(200, {"code": code, "ttl": ttl})
        if self.path in ("/agent/approve", "/agent/token"):
            return self.grant(body, direct=self.path == "/agent/token")
        if self.path == "/agent/deny":
            try:
                state.agents.deny(str(body.get("id", "")))
            except NotFound as error:
                return self.fail(404, str(error))
            return self.send_json(200, {"ok": True})
        if self.path == "/agent/revoke":
            grant_id = None if body.get("all") is True else body.get("id")
            if grant_id is None and body.get("all") is not True:
                return self.fail(400, 'give "id" or "all": true')
            if grant_id is not None and not (isinstance(grant_id, str) and GRANT_ID.fullmatch(grant_id)):
                return self.fail(400, "id must look like g-1234abcd")
            dropped = state.agents.revoke(grant_id, reason=str(body.get("reason") or "revoked at the terminal"))
            if body.get("viewers"):
                state.gate.revoke_all()
            if dropped or grant_id is None:
                state.tmux.display(f"Agent access revoked ({len(dropped)} grant{'s' if len(dropped) != 1 else ''}).")
            return self.send_json(200, {"revoked": [grant.id for grant in dropped]})
        if self.path == "/agent/retarget":
            pane = self.pane(body.get("pane"))
            if pane is None:
                return
            try:
                grant = state.agents.retarget(str(body.get("id", "")), pane)
            except NotFound as error:
                return self.fail(404, str(error))
            return self.send_json(200, {"grant": grant.as_dict(state.agents.clock())})
        self.fail(404, "not found")

    def pane(self, requested) -> str | None:
        """The pane to bind: the one asked for, or the session's active pane. Must be in the session."""
        session = self.state.tmux.session_key()
        if session is None:
            self.fail(409, f"No tmux session named '{self.state.cfg.session}' is running.")
            return None
        pane_id = requested or self.state.tmux.active_pane()
        pane = self.state.tmux.pane(pane_id) if isinstance(pane_id, str) and PANE_ID.fullmatch(pane_id) else None
        if pane is None or pane.session_key != session:
            self.fail(400, f"{pane_id!r} is not a pane of the shared session.")
            return None
        return pane.id

    def grant(self, body: dict, *, direct: bool) -> None:
        state = self.state
        scope = body.get("scope")
        if scope not in SCOPES:
            return self.fail(400, f"scope must be one of {', '.join(SCOPES)}")
        ttl = body.get("ttl")
        if ttl is not None and (not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 60):
            return self.fail(400, "ttl must be a number of seconds, at least 60")
        pane = self.pane(body.get("pane"))
        if pane is None:
            return
        session = state.tmux.session_key()
        if direct:
            listener = state.cfg.mcp_listener()
            if listener is None:
                return self.fail(409, "No listener has mcp = true.")
            grant, token = state.agents.mint_direct(scope=scope, pane_id=pane, session_key=session,
                                                    resources=listener.resources(),
                                                    label=str(body.get("label") or "token file"), ttl=ttl)
            return self.send_json(200, {"grant": grant.as_dict(state.agents.clock()), "token": token,
                                        "url": f"http://{listener.host}:{listener.port}/mcp"
                                        if listener.loopback_hosts else listener.public_url + "mcp"})
        try:
            grant = state.agents.approve(str(body.get("id", "")), scope=scope, pane_id=pane, session_key=session,
                                         ttl=ttl)
        except NotFound as error:
            return self.fail(404, str(error))
        self.send_json(200, {"grant": grant.as_dict(state.agents.clock())})


def start_admin(path: Path, state: State) -> AdminServer:
    path.unlink(missing_ok=True)
    previous = os.umask(0o177)  # the socket is created 0600
    try:
        server = AdminServer(str(path), AdminHandler)
    finally:
        os.umask(previous)
    server.state = state
    threading.Thread(target=server.serve_forever, name="admin", daemon=True).start()
    return server


# ---- client -------------------------------------------------------------------------------------
class GateNotRunning(Exception):
    pass


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: Path, timeout: float):
        super().__init__("gate", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self._path))


def call(path: Path, method: str, route: str, payload: dict | None = None, timeout: float = 10) -> tuple[int, dict]:
    conn = _UnixConnection(path, timeout)
    try:
        body = json.dumps(payload).encode() if payload is not None else None
        conn.request(method, route, body=body, headers={"Content-Type": "application/json"} if body else {})
        response = conn.getresponse()
        data = response.read()
    except OSError as error:  # no socket, nobody listening, or a path the kernel won't take
        raise GateNotRunning(str(error)) from None
    finally:
        conn.close()
    try:
        return response.status, json.loads(data or b"{}")
    except ValueError:
        return response.status, {"error": data.decode(errors="replace")}
