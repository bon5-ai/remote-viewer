"""Configuration: one TOML file, plus the environment for the one secret.

The file holds nothing secret, so it can be shared or committed. The secret is
the value a fronting proxy (CloudFront, say) adds to every request so the gate
can refuse traffic that went around it. It comes from BON5AI_REMOTE_PROXY_SECRET
or from a file named by ``proxy_secret_file``, never from the TOML itself.

Paths follow the XDG layout:

* config   $XDG_CONFIG_HOME/bon5ai-remote/config.toml
* state    $XDG_STATE_HOME/bon5ai-remote/       (audit log, stream log)
* runtime  $XDG_RUNTIME_DIR/bon5ai-remote/      (admin socket, tmux socket; 0700)
"""

from __future__ import annotations

import ipaddress
import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

CONFIG_ENV = "BON5AI_REMOTE_CONFIG"
SECRET_ENV = "BON5AI_REMOTE_PROXY_SECRET"
SECRET_FILE_ENV = "BON5AI_REMOTE_PROXY_SECRET_FILE"
RUNTIME_ENV = "BON5AI_REMOTE_RUNTIME_DIR"
MAX_SOCKET_PATH = 100  # sun_path is 104 bytes on macOS and 108 on Linux, including the NUL
APP = "bon5ai-remote"

SESSION_NAME = re.compile(r"[A-Za-z0-9_-]{1,32}")
KILL_KEY = re.compile(r"(?:[CM]-)?[A-Za-z0-9]")
HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,64}")
HOST_VALUE = re.compile(r"[a-z0-9.\-]+(?::\d{1,5})?|\[[0-9a-f:]+\](?::\d{1,5})?")

TOP_KEYS = {"session", "tmux_socket", "code_ttl_seconds", "viewer_ttl_seconds", "agent_ttl_seconds",
            "access_token_ttl_seconds", "kill_key", "allowed_redirect_uris", "client_metadata_documents",
            "audit_log", "allow_private_listen", "proxy_secret_file", "listener"}
LISTENER_KEYS = {"address", "public_url", "viewer", "mcp", "allowed_hosts", "proxy_header",
                 "client_ip_header", "deny_funnel"}


class ConfigError(Exception):
    pass


def parse_address(value: str) -> tuple[str, int]:
    host, sep, port = str(value).rpartition(":")
    if not sep or not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ConfigError(f"address {value!r} must be host:port")
    return host.strip("[]"), int(port)


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _non_global(host: str) -> bool:
    """A literal address that is not routable on the internet, and not 0.0.0.0 or ::."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not ip.is_global and not ip.is_unspecified and not ip.is_multicast


def _host_port(netloc: str, scheme: str) -> str:
    """netloc with the scheme's default port dropped, lowercased: what a Host header says."""
    netloc = netloc.lower()
    default = {"http": ":80", "https": ":443"}[scheme]
    return netloc[: -len(default)] if netloc.endswith(default) else netloc


@dataclass(frozen=True)
class Listener:
    host: str
    port: int
    public_url: str  # always ends with "/"
    viewer: bool = True
    mcp: bool = True
    allowed_hosts: tuple[str, ...] = ()
    proxy_header: str = ""
    client_ip_header: str = ""
    deny_funnel: bool = False

    @property
    def name(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def mount(self) -> str:
        """The public path prefix, "" at a host's root or e.g. "/remote"."""
        return urlsplit(self.public_url).path.rstrip("/")

    @property
    def public_host(self) -> str:
        parts = urlsplit(self.public_url)
        return _host_port(parts.netloc, parts.scheme)

    @property
    def loopback_hosts(self) -> frozenset[str]:
        if not is_loopback(self.host):
            return frozenset()
        return frozenset({f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"[::1]:{self.port}"})

    def host_allowed(self, host: str) -> bool:
        """The Host header check: the defence against DNS rebinding."""
        host = host.lower()
        return host == self.public_host or host in self.loopback_hosts or host in self.allowed_hosts

    def base_url(self, host: str) -> str:
        """Where this request's client sees the gate. A loopback Host means a local client
        talking to the gate directly; everything else came in through the public URL."""
        host = host.lower()
        if host in self.loopback_hosts:
            return f"http://{host}/"
        return self.public_url

    def resources(self) -> frozenset[str]:
        """Every MCP URL this listener answers to: the public one and the loopback ones."""
        return frozenset({self.public_url + "mcp", *(f"http://{h}/mcp" for h in self.loopback_hosts)})


@dataclass(frozen=True)
class Config:
    session: str
    tmux_socket: Path
    runtime_dir: Path
    state_dir: Path
    admin_socket: Path
    audit_log: Path
    listeners: tuple[Listener, ...]
    config_path: Path | None = None
    code_ttl: int = 600
    viewer_ttl: int = 12 * 3600
    agent_ttl: int = 12 * 3600
    access_token_ttl: int = 3600
    kill_key: str = "X"
    allowed_redirect_uris: tuple[str, ...] = ()
    client_metadata_documents: bool = True
    proxy_secret: str = field(default="", repr=False)
    static_dir: Path = Path(__file__).resolve().parent / "static"

    def mcp_listener(self) -> Listener | None:
        return next((listener for listener in self.listeners if listener.mcp), None)


# ---- paths ------------------------------------------------------------------------
def _xdg(env, name: str, fallback: str) -> Path:
    value = env.get(name)
    return Path(value) if value and os.path.isabs(value) else Path.home() / fallback


def config_dir(env=os.environ) -> Path:
    return _xdg(env, "XDG_CONFIG_HOME", ".config") / APP


def default_config_path(env=os.environ) -> Path:
    return config_dir(env) / "config.toml"


def default_state_dir(env=os.environ) -> Path:
    return _xdg(env, "XDG_STATE_HOME", ".local/state") / APP


def default_runtime_dir(env=os.environ) -> Path:
    override = env.get(RUNTIME_ENV)
    if override and os.path.isabs(override):
        return Path(override)
    runtime = env.get("XDG_RUNTIME_DIR")
    if runtime and os.path.isabs(runtime):
        return Path(runtime) / APP
    # macOS and minimal Linux: $TMPDIR is per user on macOS; /tmp is shared, which is why
    # ensure_private_dir refuses a directory someone else created first.
    return Path(env.get("TMPDIR") or "/tmp") / f"{APP}-{os.getuid()}"


def ensure_private_dir(path: Path) -> Path:
    """Create path 0700, or refuse one that another user could have planted or can read."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ConfigError(f"{path} must be a directory owned by you with mode 0700 "
                          f"(it is {oct(info.st_mode & 0o777)}); fix it or remove it")
    return path


# ---- loading ----------------------------------------------------------------------
def _ttl(data: dict, key: str, default: int, low: int, high: int) -> int:
    value = data.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ConfigError(f"{key} must be a whole number of seconds between {low} and {high}")
    return value


def _strings(value, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{key} must be a list of strings")
    return tuple(value)


def _flag(data: dict, key: str, default: bool) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{key} must be true or false")
    return value


def normalize_public_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(f"public_url {value!r} must be an absolute http(s) URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ConfigError(f"public_url {value!r} must not carry credentials, a query or a fragment")
    if parts.scheme == "http" and not is_loopback(parts.hostname):
        raise ConfigError(f"public_url {value!r} must be https unless it is a loopback address: "
                          "viewer cookies are Secure and OAuth requires https")
    path = parts.path if parts.path.endswith("/") else parts.path + "/"
    return f"{parts.scheme}://{parts.netloc.lower()}{path}"


def _listener(data: dict, allow_private: bool) -> Listener:
    unknown = set(data) - LISTENER_KEYS
    if unknown:
        raise ConfigError(f"unknown listener setting(s): {', '.join(sorted(unknown))}")
    host, port = parse_address(data.get("address", "127.0.0.1:8095"))
    if not is_loopback(host) and not (allow_private and _non_global(host)):
        raise ConfigError(f"listener address {host} must be loopback. Put a proxy or tunnel in front "
                          "(Tailscale, CloudFront, Caddy); to bind a private address such as a docker "
                          "bridge gateway, set allow_private_listen = true")
    public_url = normalize_public_url(data.get("public_url") or f"http://127.0.0.1:{port}/")
    proxy_header = data.get("proxy_header", "")
    client_ip_header = data.get("client_ip_header", "")
    for key, value in (("proxy_header", proxy_header), ("client_ip_header", client_ip_header)):
        if not isinstance(value, str) or (value and not HEADER_NAME.fullmatch(value)):
            raise ConfigError(f"{key} must be an HTTP header name")
    if client_ip_header and not proxy_header:
        raise ConfigError("client_ip_header is only trusted behind a proxy_header; set both or neither")
    allowed_hosts = tuple(host.lower() for host in _strings(data.get("allowed_hosts", []), "allowed_hosts"))
    for allowed in allowed_hosts:
        if not HOST_VALUE.fullmatch(allowed):
            raise ConfigError(f"allowed_hosts entry {allowed!r} must be a host or host:port")
    return Listener(host=host, port=port, public_url=public_url,
                    viewer=_flag(data, "viewer", True), mcp=_flag(data, "mcp", True),
                    allowed_hosts=allowed_hosts, proxy_header=proxy_header,
                    client_ip_header=client_ip_header, deny_funnel=_flag(data, "deny_funnel", False))


def _redirect_uri(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.fragment:
        raise ConfigError(f"allowed_redirect_uris entry {value!r} must be an https URL without a fragment")
    return value


def _read_secret(path: Path) -> str:
    info = path.stat()
    if info.st_mode & 0o077:
        raise ConfigError(f"{path} holds the proxy secret, so it must not be readable by others (chmod 600)")
    return path.read_text().strip()


def load(path: Path | str | None = None, env=os.environ) -> Config:
    explicit = path or env.get(CONFIG_ENV)
    config_path = Path(explicit).expanduser() if explicit else default_config_path(env)
    data: dict = {}
    if config_path.exists():
        with config_path.open("rb") as handle:
            try:
                data = tomllib.load(handle)
            except tomllib.TOMLDecodeError as error:
                raise ConfigError(f"{config_path}: {error}") from None
    elif explicit:
        raise ConfigError(f"{config_path} does not exist")

    unknown = set(data) - TOP_KEYS
    if unknown:
        raise ConfigError(f"unknown setting(s) in {config_path}: {', '.join(sorted(unknown))}")

    session = data.get("session", "share")
    if not isinstance(session, str) or not SESSION_NAME.fullmatch(session):
        raise ConfigError("session must be 1-32 letters, digits, '-' or '_'")
    kill_key = data.get("kill_key", "X")
    if not isinstance(kill_key, str) or (kill_key and not KILL_KEY.fullmatch(kill_key)):
        raise ConfigError("kill_key must be one key such as X or M-x, or \"\" to bind none")

    allow_private = _flag(data, "allow_private_listen", False)
    raw_listeners = data.get("listener") or [{}]
    if not isinstance(raw_listeners, list) or not all(isinstance(item, dict) for item in raw_listeners):
        raise ConfigError("[[listener]] must be a table array")
    listeners = tuple(_listener(item, allow_private) for item in raw_listeners)
    if len({(item.host, item.port) for item in listeners}) != len(listeners):
        raise ConfigError("two listeners use the same address")

    runtime = default_runtime_dir(env)
    tmux_socket = data.get("tmux_socket") or ""
    state_dir = default_state_dir(env)
    audit_log = data.get("audit_log") or ""

    secret = env.get(SECRET_ENV, "").strip()
    secret_file = data.get("proxy_secret_file") or env.get(SECRET_FILE_ENV, "")
    if not secret and secret_file:
        secret = _read_secret(Path(secret_file).expanduser())
    if any(item.proxy_header for item in listeners) and not secret:
        raise ConfigError(f"a listener sets proxy_header, but no secret is configured: set {SECRET_ENV} "
                          "or proxy_secret_file. Refusing to start with the check silently off")

    tmux_path = Path(tmux_socket).expanduser() if tmux_socket else runtime / "tmux.sock"
    for socket_path in (tmux_path, runtime / "admin.sock"):
        if len(os.fsencode(socket_path)) > MAX_SOCKET_PATH:
            raise ConfigError(f"{socket_path} is too long for a Unix socket ({len(os.fsencode(socket_path))} bytes; "
                              f"about {MAX_SOCKET_PATH} fit). Set {RUNTIME_ENV} to a shorter directory")
    return Config(
        session=session,
        tmux_socket=tmux_path,
        runtime_dir=runtime,
        state_dir=state_dir,
        admin_socket=runtime / "admin.sock",
        audit_log=Path(audit_log).expanduser() if audit_log else state_dir / "audit.jsonl",
        listeners=listeners,
        config_path=config_path if config_path.exists() else None,
        code_ttl=_ttl(data, "code_ttl_seconds", 600, 60, 3600),
        viewer_ttl=_ttl(data, "viewer_ttl_seconds", 12 * 3600, 300, 7 * 86400),
        agent_ttl=_ttl(data, "agent_ttl_seconds", 12 * 3600, 300, 7 * 86400),
        access_token_ttl=_ttl(data, "access_token_ttl_seconds", 3600, 60, 86400),
        kill_key=kill_key,
        allowed_redirect_uris=tuple(_redirect_uri(uri) for uri in
                                    _strings(data.get("allowed_redirect_uris", []), "allowed_redirect_uris")),
        client_metadata_documents=_flag(data, "client_metadata_documents", True),
        proxy_secret=secret,
    )
