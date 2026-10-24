"""tmux-remote-viewer: share a tmux session with browsers (read-only) and with paired agents (MCP).

    tmux-remote-viewer share              start or rejoin the shared session (prints a QR code the first time)
    tmux-remote-viewer code               mint another viewer pairing code
    tmux-remote-viewer agent approve      approve an agent that is signing in, choosing its scope and pane
    tmux-remote-viewer agent list         list agent grants;   agent revoke <id> | --all
    tmux-remote-viewer serve              run the gate (normally from the service)
    tmux-remote-viewer doctor             check the installation
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .admin import GateNotRunning, call
from .agents import SCOPE_HELP, SCOPES
from .config import (CONFIG_ENV, SECRET_ENV, Config, ConfigError, config_dir, ensure_private_dir, is_loopback,
                     load)
from .gate import stream_up
from .state import AGENTS_OPTION, PENDING_OPTION, STREAM_OPTION, STREAM_PID_OPTION, VIEWERS_OPTION
from .stream import owner_alive
from .tmux import Tmux

MIN_TMUX = (3, 2)
MIN_ASCIINEMA = (3, 0)
SERVICE = "tmux-remote-viewer"
LAUNCHD_LABEL = "ai.bon5.remote-viewer"
DURATION = re.compile(r"(\d+)\s*([smhd]?)")


class Exit(Exception):
    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


# ---- helpers ------------------------------------------------------------------------------
def self_command(cfg_arg: str | None) -> list[str]:
    """How to run this CLI again from tmux or a service: an absolute path, not $PATH.

    ``-P`` keeps the working directory off ``sys.path``. Without it, ``python -m`` would
    import a ``bon5ai_remote`` package (or a ``json.py``) planted in whatever directory the
    command happens to run from: Claude Code runs the headersHelper in the project it has
    open, and the kill key runs in the shared session's directory.
    """
    command = [sys.executable, "-P", "-m", "bon5ai_remote"]
    return command + (["--config", str(Path(cfg_arg).expanduser().resolve())] if cfg_arg else [])


def parse_duration(value: str) -> int:
    match = DURATION.fullmatch(value.strip())
    if not match:
        raise argparse.ArgumentTypeError("use a duration like 90m, 8h or 2d")
    number, unit = int(match.group(1)), match.group(2) or "s"
    return number * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def human_duration(seconds: int) -> str:
    if seconds >= 3600:
        hours, rest = divmod(seconds, 3600)
        return f"{hours}h" + (f"{rest // 60:02d}m" if rest >= 60 else "")
    return f"{seconds // 60}m" if seconds >= 60 else f"{seconds}s"


def admin(cfg: Config, method: str, route: str, payload: dict | None = None) -> dict:
    try:
        status, body = call(cfg.admin_socket, method, route, payload)
    except GateNotRunning:
        raise Exit("The gate isn't running. Start it with `systemctl --user start tmux-remote-viewer` "
                   "(after `tmux-remote-viewer install-service`) or run `tmux-remote-viewer serve`.") from None
    if status >= 400:
        raise Exit(body.get("error") or f"the gate answered {status}")
    return body


def inside_share(cfg: Config) -> bool:
    return os.environ.get("TMUX", "").split(",", 1)[0] == str(cfg.tmux_socket)


def tty_input(prompt: str) -> str:
    """Read an answer from the controlling terminal, not from a pipe."""
    # Two handles: "r+" would need a seekable file, and a terminal never is.
    try:
        with open("/dev/tty", "w") as out, open("/dev/tty") as answer:
            out.write(prompt)
            out.flush()
            return answer.readline().strip()
    except OSError:
        raise Exit("This needs an interactive terminal (or pass --yes with every choice given).") from None


def qr_lines(text: str) -> list[str]:
    try:
        import segno
    except ImportError:
        return []
    buffer = io.StringIO()
    segno.make(text, error="m").terminal(out=buffer, compact=True, border=2)
    return buffer.getvalue().splitlines()


def viewer_url(cfg: Config) -> str | None:
    return next((listener.public_url for listener in cfg.listeners if listener.viewer), None)


def print_code(cfg: Config, code: str, ttl: int) -> None:
    url = viewer_url(cfg)
    print()
    if url:
        # The code rides in the fragment, which a browser never sends anywhere; the page
        # claims it and clears it from the address bar.
        for line in qr_lines(f"{url}#code={code}"):
            print("    " + line)
        print(f"\n    Scan with a phone's camera, or enter the code at {url}")
    print(f"    Pairing code:  {code}    (expires in {human_duration(ttl)}, works once)\n")


def tool_version(command: list[str]) -> tuple[int, ...] | None:
    try:
        out = subprocess.run(command, capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"(\d+)\.(\d+)", out)
    return (int(match.group(1)), int(match.group(2))) if match else None


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# ---- share and code -------------------------------------------------------------------------
STATUS_BADGES = ("#{?" + PENDING_OPTION + ",#[reverse] #{" + PENDING_OPTION + "} #[default] ,}"
                 "#{?" + AGENTS_OPTION + ",#[reverse] #{" + AGENTS_OPTION + "} #[default] ,}"
                 "#{?" + VIEWERS_OPTION + ",#[reverse] #{" + VIEWERS_OPTION + "} watching #[default] ,}")


def configure_session(cfg: Config, tmux: Tmux, cfg_arg: str | None) -> None:
    target = f"={cfg.session}:"
    # The badges are how the person at the terminal knows someone is watching or typing.
    tmux.ok("set-option", "-t", target, "status", "on")
    current = tmux.out("show-options", "-gv", "status-right") or ""
    tmux.ok("set-option", "-t", target, "status-right", STATUS_BADGES + current)
    tmux.ok("set-option", "-t", target, "status-right-length", "160")
    if cfg.kill_key:
        revoke = shlex.join(self_command(cfg_arg) + ["agent", "revoke", "--all", "--quiet"])
        tmux.ok("bind-key", cfg.kill_key, "run-shell", "-b", revoke)


def ensure_stream(cfg: Config, tmux: Tmux) -> None:
    current = tmux.get_option(STREAM_OPTION)
    pid = tmux.get_option(STREAM_PID_OPTION) or ""
    if current and pid.isdigit() and owner_alive(int(pid), current):
        host, _, port = current.rpartition(":")
        if port.isdigit() and stream_up((host, int(port))):
            return
    listen = f"127.0.0.1:{free_port()}"
    ensure_private_dir(cfg.state_dir)
    log_path = cfg.state_dir / "stream.log"
    # Created 0600 by the gate, whatever the umask: asciinema's errors can quote the session.
    fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "ab") as log_file:
        # A new session, so the stream outlives this SSH connection, as the tmux session does.
        process = subprocess.Popen([sys.executable, "-P", "-m", "bon5ai_remote.stream",
                                    "--socket", str(cfg.tmux_socket), "--session", cfg.session, "--listen", listen],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log_file,
                                   start_new_session=True, close_fds=True)
    # The gate trusts the port only while this pid is the wrapper that owns it.
    tmux.set_option(STREAM_PID_OPTION, str(process.pid))
    tmux.set_option(STREAM_OPTION, listen)
    host, port = listen.split(":")
    for _ in range(30):
        if stream_up((host, int(port))):
            return
        time.sleep(0.1)
    print(f"tmux-remote-viewer: the viewer stream did not start; see {log_path}", file=sys.stderr)


def cmd_share(cfg: Config, args) -> int:
    if inside_share(cfg):
        raise Exit("Already inside the shared session. Detach first (Ctrl-b d).")
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise Exit("share needs an interactive terminal.")
    for tool in ("tmux", "asciinema"):
        if not shutil.which(tool):
            raise Exit(f"{tool} is not installed. Run `tmux-remote-viewer doctor` for details.")
    ensure_private_dir(cfg.tmux_socket.parent)
    tmux = Tmux(cfg.tmux_socket, cfg.session)
    created = False
    if not tmux.has_session():
        size = shutil.get_terminal_size()
        env = {key: value for key, value in os.environ.items() if key != "TMUX"}
        subprocess.run(["tmux", "-S", str(cfg.tmux_socket), "new-session", "-d", "-s", cfg.session,
                        "-x", str(size.columns), "-y", str(size.lines)], env=env, check=True)
        configure_session(cfg, tmux, args.config)
        created = True
    ensure_stream(cfg, tmux)
    if created and not args.no_code:
        try:
            body = admin(cfg, "POST", "/pair")
        except Exit as error:
            print(f"tmux-remote-viewer: no pairing code: {error}", file=sys.stderr)
        else:
            print_code(cfg, body["code"], body["ttl"])
            tty_input("Press Enter to open the shared session. ")
    if os.environ.get("TMUX"):
        print("tmux-remote-viewer: opening the shared session inside your tmux; its prefix key goes to the outer one.",
              file=sys.stderr)
    env = {key: value for key, value in os.environ.items() if key != "TMUX"}
    os.execvpe("tmux", ["tmux", "-S", str(cfg.tmux_socket), "attach-session", "-t", f"={cfg.session}"], env)
    return 0


def cmd_code(cfg: Config, args) -> int:
    if inside_share(cfg):
        print("tmux-remote-viewer: viewers of this session (and agents reading it) will see this code.",
              file=sys.stderr)
    body = admin(cfg, "POST", "/pair", {"ttl": args.ttl} if args.ttl else None)
    print_code(cfg, body["code"], body["ttl"])
    return 0


# ---- agents -----------------------------------------------------------------------------------
def describe_request(item: dict) -> str:
    who = (f"{item['client']} (verified: {item['clientHost']})" if item["verified"]
           else f"\"{item['client']}\" (self-registered: the name is not verified)")
    where = item["redirectHost"]
    if not item.get("loopback", True):
        where += " (a hosted service: anyone using it could have started this sign-in)"
    return f"{item['id']}  {who}, returns to {where}, {item['age']}s ago"


def choose_scope(args) -> str:
    if args.scope:
        return args.scope
    print("Scope:")
    for name in SCOPES:
        print(f"  [{name[0]}]{name[1:]:<9} {SCOPE_HELP[name]}")
    answer = tty_input("Scope [o/s/c]: ").lower()
    for name in SCOPES:
        if answer in (name, name[0]):
            return name
    raise Exit("No scope chosen; nothing approved.")


def choose_pane(cfg: Config, args) -> str:
    tmux = Tmux(cfg.tmux_socket, cfg.session)
    panes = tmux.panes()
    if not panes:
        raise Exit(f"No tmux session named '{cfg.session}' is running.")
    active = next((pane for pane in panes if pane.window_active and pane.pane_active), panes[0])
    if args.pane:
        return args.pane
    if len(panes) == 1 or args.yes:
        return active.id
    print("Pane:")
    for pane in panes:
        mark = "*" if pane.id == active.id else " "
        print(f"  {mark} {pane.id:<5} window {pane.window_index} \"{pane.window_name}\", running {pane.command}")
    answer = tty_input(f"Pane [{active.id}]: ") or active.id
    return answer if answer.startswith("%") else f"%{answer}"


def cmd_agent_requests(cfg: Config, args) -> int:
    requests = admin(cfg, "GET", "/agent/requests")["requests"]
    if not requests:
        print("No agent is waiting for approval.")
    for item in requests:
        print(describe_request(item))
    return 0


def cmd_agent_approve(cfg: Config, args) -> int:
    requests = admin(cfg, "GET", "/agent/requests")["requests"]
    if not requests:
        raise Exit("No agent is waiting. Start the sign-in from the agent first (for Claude Code: /mcp).")
    if args.id:
        wanted = args.id.upper().replace("-", "")
        item = next((item for item in requests if item["id"] == wanted), None)
        if item is None:
            raise Exit(f"No waiting request {args.id}.")
    elif len(requests) == 1 and not args.yes and requests[0].get("loopback", True):
        item = requests[0]  # one request, returning to this machine: the usual Claude Code case
    else:
        # A sign-in that returns to a hosted service could have been started by anyone who
        # uses that service, so it is approved only by the ID on the page you opened.
        raise Exit("Name the request to approve; it is the ID shown on the sign-in page:\n  "
                   + "\n  ".join(describe_request(item) for item in requests))
    print(describe_request(item))
    print("Approve only a request whose ID is on a sign-in page you opened yourself.\n")
    scope = choose_scope(args)
    pane = choose_pane(cfg, args)
    ttl = args.ttl or cfg.agent_ttl
    if not args.yes:
        answer = tty_input(f"Give {item['client']} {scope} access to pane {pane} of \"{cfg.session}\" "
                           f"for {human_duration(ttl)}? [y/N] ")
        if answer.lower() not in ("y", "yes"):
            admin(cfg, "POST", "/agent/deny", {"id": item["id"]})
            print("Denied.")
            return 1
    grant = admin(cfg, "POST", "/agent/approve", {"id": item["id"], "scope": scope, "pane": pane, "ttl": ttl})["grant"]
    print(f"Approved: grant {grant['id']}. The agent's browser page finishes the sign-in now.")
    print(f"Revoke it with `tmux-remote-viewer agent revoke {grant['id']}`"
          + (f", or every agent with prefix + {cfg.kill_key} in the session." if cfg.kill_key else "."))
    return 0


def cmd_agent_deny(cfg: Config, args) -> int:
    admin(cfg, "POST", "/agent/deny", {"id": args.id.upper()})
    print("Denied.")
    return 0


def cmd_agent_list(cfg: Config, args) -> int:
    grants = admin(cfg, "GET", "/agent/grants")["grants"]
    if not grants:
        print("No agent has access.")
    for grant in grants:
        idle = "never used" if grant["idle"] is None else f"last call {grant['idle']}s ago"
        print(f"{grant['id']}  {grant['client']}  {grant['scope']}  pane {grant['pane']}  "
              f"expires in {human_duration(grant['expiresIn'])}  {idle}")
    return 0


def cmd_agent_revoke(cfg: Config, args) -> int:
    if not args.all and not args.id:
        raise Exit("Name a grant (see `tmux-remote-viewer agent list`) or pass --all.")
    payload = {"all": True, "viewers": args.viewers} if args.all else {"id": args.id}
    revoked = admin(cfg, "POST", "/agent/revoke", payload)["revoked"]
    if not args.quiet:
        print(f"Revoked {len(revoked)} grant{'s' if len(revoked) != 1 else ''}."
              + (" Viewers signed out too." if args.all and args.viewers else ""))
    return 0


def cmd_agent_retarget(cfg: Config, args) -> int:
    grant = admin(cfg, "POST", "/agent/retarget", {"id": args.id, "pane": args.pane})["grant"]
    print(f"{grant['id']} now uses pane {grant['pane']}.")
    return 0


def cmd_agent_token(cfg: Config, args) -> int:
    out = Path(args.out).expanduser()
    pane = choose_pane(cfg, args)
    body = admin(cfg, "POST", "/agent/token", {"scope": args.scope, "pane": pane, "ttl": args.ttl,
                                                 "label": args.label})
    out.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp: a new 0600 file of ours with an unpredictable name, never one someone planted.
    fd, temporary = tempfile.mkstemp(prefix=f".{out.name}.", dir=out.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(body["token"] + "\n")
        os.replace(temporary, out)
    except BaseException:
        os.unlink(temporary)
        raise
    grant = body["grant"]
    helper = shlex.join(self_command(args.config) + ["agent", "headers", str(out.resolve())])
    print(f"Token for \"{grant['client']}\" ({grant['scope']}, pane {grant['pane']}, "
          f"{human_duration(grant['expiresIn'])}) written to {out} (mode 0600).")
    print("It stops working when it expires, when the session ends, or when the gate restarts.\n")
    print("Add it to Claude Code without the token appearing anywhere:\n")
    config = {"type": "http", "url": body["url"], "headersHelper": helper}
    print(f"  claude mcp add-json tmux-remote-viewer {shlex.quote(json.dumps(config))}\n")
    return 0


def cmd_agent_headers(cfg: Config, args) -> int:
    if sys.stdout.isatty() and not args.force:
        raise Exit("This prints a credential. It is meant to run as an MCP headersHelper, not in a terminal.")
    path = Path(args.file).expanduser()
    try:
        info = path.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Exit(f"{path} must be yours and mode 0600.")
        token = path.read_text().strip()
    except OSError as error:
        raise Exit(f"Cannot read the token file: {error}") from error
    print(json.dumps({"Authorization": f"Bearer {token}"}))
    return 0


# ---- operations -----------------------------------------------------------------------------
def cmd_serve(cfg: Config, args) -> int:
    from .server import run
    run(cfg)
    return 0


def check(ok: bool | None, message: str) -> bool:
    mark = {True: "ok  ", False: "FAIL", None: "warn"}[ok]
    print(f"[{mark}] {message}")
    return ok is not False


def cmd_doctor(cfg: Config, args) -> int:
    good = True
    tmux_version = tool_version(["tmux", "-V"])
    good &= check(tmux_version is not None and tmux_version >= MIN_TMUX,
                  f"tmux {'.'.join(map(str, tmux_version)) if tmux_version else 'not found'} (need 3.2 or later)")
    asciinema_version = tool_version(["asciinema", "--version"])
    good &= check(asciinema_version is not None and asciinema_version >= MIN_ASCIINEMA,
                  f"asciinema {'.'.join(map(str, asciinema_version)) if asciinema_version else 'not found'} "
                  "(need 3.0 or later for `stream`)")
    check(True, f"config: {cfg.config_path or 'defaults (no config file)'}")
    try:
        ensure_private_dir(cfg.runtime_dir)
        check(True, f"runtime directory {cfg.runtime_dir} is private")
    except ConfigError as error:
        good &= check(False, str(error))
    for listener in cfg.listeners:
        roles = " + ".join(role for role, on in (("viewer", listener.viewer), ("mcp", listener.mcp)) if on)
        check(True, f"listener {listener.name} → {listener.public_url} ({roles})")
        public = not is_loopback(urlsplit(listener.public_url).hostname or "")
        if public and not listener.proxy_header:
            check(None, f"  no proxy_header: anything that reaches {listener.name} directly is treated like your "
                        "proxy. That's fine when only the proxy can reach it (docs/deploy/reverse-proxy.md)")
    try:
        status = admin(cfg, "GET", "/status")
        check(True, "the gate is running")
        running = "is running" if status["running"] else "is not running (tmux-remote-viewer share)"
        check(status["running"] or None, f"tmux session '{cfg.session}' {running}")
        if status["running"]:
            check(status["stream"] or None, "the viewer stream is " + ("up" if status["stream"] else "down"))
    except Exit as error:
        good &= check(False, str(error))
    try:
        users = {line.split()[0] for line in subprocess.run(["who"], capture_output=True, text=True,
                                                            timeout=5).stdout.splitlines() if line.strip()}
        others = users - {os.environ.get("USER", "")}
        if others:
            check(None, "other users are logged in: any local user can connect to the asciinema stream's "
                        "loopback port, so they could watch the shared session")
    except (OSError, subprocess.TimeoutExpired):
        pass
    return 0 if good else 1


def cmd_config(cfg: Config, args) -> int:
    print(f"config file   {cfg.config_path or '(none; defaults)'}")
    print(f"session       {cfg.session}")
    print(f"tmux socket   {cfg.tmux_socket}")
    print(f"admin socket  {cfg.admin_socket}")
    print(f"audit log     {cfg.audit_log}")
    print(f"proxy secret  {'set' if cfg.proxy_secret else 'not set'}")
    print(f"viewer resize {'on' if cfg.viewer_resize else 'off'}")
    for listener in cfg.listeners:
        print(f"listener      {listener.name} → {listener.public_url} viewer={listener.viewer} mcp={listener.mcp}"
              f" proxy_header={listener.proxy_header or '-'} allowed_hosts={','.join(listener.allowed_hosts) or '-'}")
    return 0


SYSTEMD_UNIT = """\
[Unit]
Description=BON5AI Remote Viewer gate
Documentation=https://github.com/bon5-ai/remote-viewer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Optional: {secret_env}=... (the proxy secret). Keep secrets out of this unit file.
EnvironmentFile=-%h/.config/bon5ai-remote/env
ExecStart={exec_start}
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
UMask=0077

[Install]
WantedBy=default.target
"""

LAUNCHD_PLIST = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{arguments}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>Umask</key><integer>63</integer>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"""


def cmd_install_service(cfg: Config, args) -> int:
    command = self_command(args.config) + ["serve"]
    if sys.platform == "darwin":
        from xml.sax.saxutils import escape
        arguments = "\n".join(f"    <string>{escape(part)}</string>" for part in command)
        text = LAUNCHD_PLIST.format(label=LAUNCHD_LABEL, arguments=arguments,
                                    log=escape(str(cfg.state_dir / "gate.log")))
        path = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
        enable = [["launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)]]
        print("macOS: the proxy secret must be in the environment launchd gives the agent, or in "
              "proxy_secret_file (recommended).")
    else:
        text = SYSTEMD_UNIT.format(exec_start=shlex.join(command), secret_env=SECRET_ENV)
        path = config_dir().parent / "systemd" / "user" / f"{SERVICE}.service"
        enable = [["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", SERVICE]]
    if args.print:
        print(text, end="")
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    print(f"Wrote {path}")
    cfg.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.enable:
        for step in enable:
            subprocess.run(step, check=True)
        print("Started.")
    else:
        print("Start it with:\n  " + "\n  ".join(shlex.join(step) for step in enable))
    if sys.platform.startswith("linux"):
        print("To keep it running while you are logged out: loginctl enable-linger $USER")
    return 0


# ---- argument parsing -------------------------------------------------------------------------
def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="tmux-remote-viewer", description="Share a tmux session read-only with "
                                   "browsers, and with paired agents over MCP.")
    root.add_argument("--config", help=f"config file (default: {config_dir() / 'config.toml'}; or ${CONFIG_ENV})")
    root.add_argument("--version", action="version", version=f"tmux-remote-viewer {__version__}")
    sub = root.add_subparsers(dest="command", required=True, metavar="command")

    share = sub.add_parser("share", help="start or rejoin the shared tmux session")
    share.add_argument("--no-code", action="store_true", help="don't mint a viewer code for a new session")
    share.set_defaults(run=cmd_share)
    code = sub.add_parser("code", help="mint a viewer pairing code (and QR code)")
    code.add_argument("--ttl", type=parse_duration,
                      help="how long the code works, from 1m to 1h, e.g. 30m (default: code_ttl_seconds, 10m)")
    code.set_defaults(run=cmd_code)
    sub.add_parser("serve", help="run the gate in the foreground").set_defaults(run=cmd_serve)
    sub.add_parser("doctor", help="check the installation").set_defaults(run=cmd_doctor)
    sub.add_parser("config", help="show the effective configuration").set_defaults(run=cmd_config)
    service = sub.add_parser("install-service", help="install the gate as a user service (systemd or launchd)")
    service.add_argument("--enable", action="store_true", help="also start it now and at login")
    service.add_argument("--print", action="store_true", help="print the unit instead of writing it")
    service.set_defaults(run=cmd_install_service)

    agent = sub.add_parser("agent", help="approve and manage agents").add_subparsers(dest="agent_command",
                                                                                      required=True, metavar="action")
    agent.add_parser("requests", help="list agents waiting for approval").set_defaults(run=cmd_agent_requests)
    approve = agent.add_parser("approve", help="approve a waiting agent")
    approve.add_argument("id", nargs="?", help="the request ID shown on the agent's sign-in page")
    approve.add_argument("--scope", choices=SCOPES)
    approve.add_argument("--pane", help="pane id such as %%3 (default: the active pane)")
    approve.add_argument("--ttl", type=parse_duration, help="how long the grant lasts, e.g. 8h (default: 12h)")
    approve.add_argument("--yes", action="store_true", help="don't ask; needs the request ID and --scope")
    approve.set_defaults(run=cmd_agent_approve)
    deny = agent.add_parser("deny", help="deny a waiting agent")
    deny.add_argument("id")
    deny.set_defaults(run=cmd_agent_deny)
    agent.add_parser("list", help="list agent grants").set_defaults(run=cmd_agent_list)
    revoke = agent.add_parser("revoke", help="revoke a grant, or all of them")
    revoke.add_argument("id", nargs="?")
    revoke.add_argument("--all", action="store_true")
    revoke.add_argument("--viewers", action="store_true", help="with --all: sign every browser viewer out too")
    revoke.add_argument("--quiet", action="store_true")
    revoke.set_defaults(run=cmd_agent_revoke)
    retarget = agent.add_parser("retarget", help="point a grant at another pane")
    retarget.add_argument("id")
    retarget.add_argument("--pane", required=True)
    retarget.set_defaults(run=cmd_agent_retarget)
    token = agent.add_parser("token", help="mint a grant whose token is read by an MCP headersHelper (no OAuth)")
    token.add_argument("--scope", choices=SCOPES, required=True)
    token.add_argument("--pane")
    token.add_argument("--ttl", type=parse_duration)
    token.add_argument("--label", default="token file", help="the name shown in the status line")
    token.add_argument("--out", required=True, help="file to write the token to (created 0600)")
    token.add_argument("--yes", action="store_true", help=argparse.SUPPRESS)
    token.set_defaults(run=cmd_agent_token)
    headers = agent.add_parser("headers", help="print the Authorization header for a token file (headersHelper)")
    headers.add_argument("file")
    headers.add_argument("--force", action="store_true", help="print even to a terminal")
    headers.set_defaults(run=cmd_agent_headers)
    return root


def main(argv: list[str] | None = None) -> None:
    args = parser().parse_args(argv)
    try:
        cfg = load(args.config)
        sys.exit(args.run(cfg, args))
    except ConfigError as error:
        sys.exit(f"tmux-remote-viewer: config: {error}")
    except Exit as error:
        print(f"tmux-remote-viewer: {error}", file=sys.stderr)
        sys.exit(error.code)
    except KeyboardInterrupt:
        sys.exit(130)

