"""The gate's shared state: tmux, viewer pairing, agent grants and the audit log."""

from __future__ import annotations

import threading

from . import cimd, stream
from .agents import AgentAuth, Grant
from .audit import Audit
from .config import Config, ConfigError, is_loopback, parse_address
from .gate import Gate
from .tmux import Tmux

STREAM_OPTION = "@bon5ai_stream"
STREAM_PID_OPTION = "@bon5ai_stream_pid"
VIEWERS_OPTION = "@bon5ai_viewers"
AGENTS_OPTION = "@bon5ai_agents"
PENDING_OPTION = "@bon5ai_pending"


def badge_text(value: str) -> str:
    # The status line expands #[...] and #(...) sequences; a client name must not.
    return value.replace("#", "")


class State:
    def __init__(self, cfg: Config, *, tmux: Tmux | None = None, audit: Audit | None = None,
                 fetch_metadata=None, clock=None, stream_owned=stream.owner_alive):
        self.cfg = cfg
        self.tmux = tmux or Tmux(cfg.tmux_socket, cfg.session)
        self.audit = audit or Audit(cfg.audit_log)
        self.stream_owned = stream_owned
        extra = {"clock": clock} if clock else {}
        self.gate = Gate(code_ttl=cfg.code_ttl, viewer_ttl=cfg.viewer_ttl, session_lookup=self.tmux.session_key,
                         host_attached=self.tmux.host_attached, stream_address=self.stream_address,
                         on_viewers=self._viewers_changed, on_guessing=self._guessing, **extra)
        if fetch_metadata is None and cfg.client_metadata_documents:
            fetch_metadata = cimd.fetch
        self.agents = AgentAuth(agent_ttl=cfg.agent_ttl, access_ttl=cfg.access_token_ttl,
                                allowed_redirect_uris=cfg.allowed_redirect_uris, fetch_metadata=fetch_metadata,
                                on_event=self._agent_event, **extra)
        self.mcp_manager = None  # set by the server once the MCP session manager runs
        self._badges: dict[str, str] = {}
        self._badge_lock = threading.Lock()

    # ---- tmux-backed facts ----------------------------------------------------------
    def stream_address(self) -> tuple[str, int] | None:
        """asciinema's local server for the session, as `share` recorded it.

        Loopback only, and only while the stream wrapper `share` started still owns it.
        The gate relays that server and serves its player script to every viewer, so a
        port whose owner is gone (asciinema crashed, say) must not be trusted: any local
        user could bind it next."""
        value = self.tmux.get_option(STREAM_OPTION)
        pid = self.tmux.get_option(STREAM_PID_OPTION) or ""
        if not value or not pid.isdigit():
            return None
        try:
            host, port = parse_address(value)
        except ConfigError:
            return None
        if not is_loopback(host) or not self.stream_owned(int(pid), value):
            return None
        return (host, port)

    def session_alive(self, grant: Grant) -> bool:
        """True while the grant's tmux session still runs; otherwise the grant is revoked."""
        if self.tmux.session_key() == grant.session_key:
            return True
        self.agents.revoke(grant.id, reason="session ended")
        return False

    # ---- callbacks --------------------------------------------------------------------
    def _viewers_changed(self, session: str, count: int) -> None:
        # `share` puts #{@bon5ai_viewers} in the status line, so the person at the
        # terminal can see when someone is watching.
        if self.tmux.session_key() == session:
            self.tmux.set_option(VIEWERS_OPTION, str(count))

    def _guessing(self, failures: int) -> None:
        self.audit.record("viewer.guessing", failures=failures)
        self.tmux.display(f"{failures} wrong viewer codes in 10 minutes: someone may be guessing. "
                          "Pairing stays open; wrong answers are slowed down.")

    def _agent_event(self, kind: str, **fields) -> None:
        self.audit.record(f"agent.{kind}", **fields)
        self.refresh_badges()

    def refresh_badges(self) -> None:
        """Keep the status line's agent and pending-request badges current."""
        self.agents.prune()
        grants = self.agents.grants()
        pending = self.agents.pending()
        names = [f"{badge_text(grant.client_name)} ({grant.scope})" for grant in grants[:2]]
        if len(grants) > 2:
            names.append(f"+{len(grants) - 2}")
        values = {AGENTS_OPTION: ("agent: " + ", ".join(names)) if grants else "",
                  PENDING_OPTION: ("agent request " + " ".join(item["id"] for item in pending[:3])) if pending else ""}
        with self._badge_lock:
            changed = {name: value for name, value in values.items() if self._badges.get(name) != value}
            self._badges.update(changed)
        for name, value in changed.items():
            if value:
                self.tmux.set_option(name, value)
            else:
                self.tmux.unset_option(name)
