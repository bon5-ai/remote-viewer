"""`bon5ai-remote serve`: the gate process. One admin socket, one or more listeners."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import sys

import anyio
import uvicorn
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings

from .admin import start_admin
from .config import Config, Listener, ensure_private_dir
from .mcp_server import build_server
from .state import State
from .web import build_app

log = logging.getLogger("bon5ai_remote")
HOUSEKEEPING_SECONDS = 5
RETRY_SECONDS = 10
MAX_MCP_BODY = 64 * 1024


class QuietPolls(logging.Filter):
    """Viewers poll /status and the authorize page polls its status every few seconds."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) == 5 and args[4] == 200:
            path = str(args[2]).split("?", 1)[0]
            return not path.endswith(("/status", "/authorize-status"))
        return True


class ListenerServer(uvicorn.Server):
    @contextlib.contextmanager
    def capture_signals(self):
        # uvicorn installs handlers per server and the last one wins; serve() handles
        # SIGTERM and SIGINT once, for every listener.
        yield


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    logging.getLogger("uvicorn.access").addFilter(QuietPolls())
    logging.getLogger("mcp").setLevel(logging.WARNING)


class Listeners:
    """Run one uvicorn server per listener. A listener that can't bind (its address isn't
    up yet, say a docker bridge at boot) retries on its own; the others keep serving."""

    def __init__(self, state: State):
        self.state = state
        self.stopping = anyio.Event()
        self.current: dict[str, uvicorn.Server] = {}

    def stop(self) -> None:
        self.stopping.set()
        for server in self.current.values():
            server.should_exit = True

    def server(self, listener: Listener) -> uvicorn.Server:
        return ListenerServer(uvicorn.Config(build_app(self.state, listener), host=listener.host, port=listener.port,
                                             lifespan="off", log_config=None, server_header=False,
                                             proxy_headers=False, ws_max_size=1 << 20, timeout_graceful_shutdown=3))

    async def run(self, listener: Listener) -> None:
        while not self.stopping.is_set():
            server = self.current[listener.name] = self.server(listener)
            try:
                await server.serve()
            except (SystemExit, OSError):  # uvicorn exits when it can't bind, after logging why
                log.warning("listener %s could not start (see above); retrying in %ss", listener.name, RETRY_SECONDS)
            with anyio.move_on_after(RETRY_SECONDS):
                await self.stopping.wait()

    async def housekeeping(self) -> None:
        while not self.stopping.is_set():
            await anyio.to_thread.run_sync(self.state.refresh_badges)
            with anyio.move_on_after(HOUSEKEEPING_SECONDS):
                await self.stopping.wait()


async def serve(cfg: Config) -> None:
    ensure_private_dir(cfg.runtime_dir)
    state = State(cfg)
    manager = StreamableHTTPSessionManager(
        build_server(state), json_response=True, stateless=True, max_request_body_size=MAX_MCP_BODY,
        # The Guard in web.py checks Host for every route; Origin is checked at /mcp.
        security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False))
    state.mcp_manager = manager
    listeners = Listeners(state)
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, listeners.stop)

    admin = start_admin(cfg.admin_socket, state)
    for listener in cfg.listeners:
        roles = " + ".join(role for role, on in (("viewer", listener.viewer), ("mcp", listener.mcp)) if on)
        log.info("listening on %s for %s (%s)%s", listener.name, listener.public_url, roles,
                 f", requiring {listener.proxy_header}" if listener.proxy_header else "")
    log.info("tmux session '%s' on %s; admin socket %s", cfg.session, cfg.tmux_socket, cfg.admin_socket)
    try:
        async with manager.run(), anyio.create_task_group() as group:
            for listener in cfg.listeners:
                group.start_soon(listeners.run, listener)
            group.start_soon(listeners.housekeeping)
    finally:
        admin.shutdown()
        admin.server_close()
        cfg.admin_socket.unlink(missing_ok=True)


def run(cfg: Config) -> None:
    configure_logging()
    asyncio.run(serve(cfg))
