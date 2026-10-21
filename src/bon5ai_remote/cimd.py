"""Fetch an OAuth Client ID Metadata Document, the one URL the gate fetches for a stranger.

With CIMD a client's id *is* an https URL, and the authorization server reads the
client's name and redirect URIs from it. That means a request to /authorize can
make the gate fetch an arbitrary URL, so the fetch is fenced in:

* https only, default certificate verification, no credentials in the URL;
* every address the name resolves to must be globally routable (including the
  IPv4 address inside a mapped, 6to4, Teredo or NAT64 IPv6 address), and the
  connection goes to the address that was checked, not a second lookup
  (no DNS-rebinding to 127.0.0.1 or the cloud metadata endpoint);
* no redirects, a 64 KB cap, JSON only, and one 5-second deadline for the whole
  fetch. A watchdog shuts the socket when it passes, so a server that drips a
  byte at a time can't hold the fetch (and a worker thread) any longer.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from urllib.parse import unquote, urlsplit

MAX_BYTES = 64 * 1024
DEADLINE = 5.0
NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


class MetadataError(Exception):
    pass


class TransportError(MetadataError):
    """No answer at all (no DNS, no connection, a timeout), as opposed to an answer that was refused.

    Only these may be remembered for a moment: CIMD says an authorization server "MUST NOT
    cache error responses" nor "documents which are invalid or malformed"."""


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a vetted IP, with SNI and certificate checks against the original name."""

    def __init__(self, host: str, address: str, port: int, context: ssl.SSLContext, timeout: float):
        super().__init__(host, port, context=context, timeout=timeout)
        self._address = address
        self.raw_socket: socket.socket | None = None

    def connect(self) -> None:
        self.raw_socket = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(self.raw_socket, server_hostname=self.host)


def is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.version == 6:
        if int(ip) >> 32 == 0:
            return False  # ::a.b.c.d (IPv4-compatible, deprecated) and ::, ::1
        embedded = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if embedded is None and any(ip in network for network in NAT64):
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if embedded is not None:
            return is_public(embedded)
    return ip.is_global and not ip.is_multicast


def _abort(holder: dict, expired: threading.Event) -> None:
    """Wake whatever read the fetch is blocked in: shutdown, unlike close, interrupts it."""
    expired.set()
    raw = getattr(holder.get("conn"), "raw_socket", None)
    if raw is not None:
        try:
            raw.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def _global_address(host: str, port: int, resolve) -> str:
    try:
        infos = resolve(host, port, type=socket.SOCK_STREAM)
    except OSError as error:
        raise TransportError(f"cannot resolve {host}") from error
    addresses = [info[4][0] for info in infos]
    if not addresses:
        raise TransportError(f"cannot resolve {host}")
    for address in addresses:
        if not is_public(ipaddress.ip_address(address.split("%", 1)[0])):
            raise MetadataError(f"{host} resolves to a non-public address")
    return addresses[0]


def check_url(url: str) -> tuple[str, int, str]:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise MetadataError("a client_id URL must be https")
    if parts.username or parts.password or parts.fragment:
        raise MetadataError("a client_id URL must not carry credentials or a fragment")
    if not parts.path or parts.path == "/":
        raise MetadataError("a client_id URL must have a path")
    if any(unquote(segment) in (".", "..") for segment in parts.path.split("/")):
        raise MetadataError("a client_id URL must not contain . or .. path segments")
    try:
        port = parts.port or 443
    except ValueError as error:
        raise MetadataError("bad port") from error
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    return parts.hostname, port, target


def fetch(url: str, *, resolve=socket.getaddrinfo, context: ssl.SSLContext | None = None,
          connection_class=_PinnedHTTPSConnection, deadline: float = DEADLINE) -> dict:
    host, port, target = check_url(url)
    # The deadline covers the name lookup too. getaddrinfo itself can't be interrupted, so a
    # resolver that answers late still holds this thread for its own timeout, but nothing
    # after it: whatever the lookup took is gone from the connection's budget.
    started = time.monotonic()
    expired = threading.Event()
    holder: dict = {}
    watchdog = threading.Timer(deadline, _abort, args=(holder, expired))
    watchdog.daemon = True
    watchdog.start()
    conn = None
    try:
        address = _global_address(host, port, resolve)
        remaining = deadline - (time.monotonic() - started)
        if expired.is_set() or remaining <= 0:
            raise TransportError("client metadata took too long")
        conn = holder["conn"] = connection_class(host, address, port, context or ssl.create_default_context(),
                                                 remaining)
        conn.request("GET", target, headers={"Accept": "application/json", "User-Agent": "tmux-remote-viewer"})
        response = conn.getresponse()
        if response.status != 200:
            raise MetadataError(f"client metadata answered {response.status}")
        if "json" not in (response.getheader("Content-Type") or ""):
            raise MetadataError("client metadata is not JSON")
        body = response.read(MAX_BYTES + 1)
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise TransportError(f"cannot fetch client metadata: {error}") from error
    finally:
        watchdog.cancel()
        if conn is not None:
            conn.close()
    if expired.is_set():  # a read cut short by the watchdog can look like a clean end of file
        raise TransportError("client metadata took too long")
    if len(body) > MAX_BYTES:
        raise MetadataError("client metadata is too large")
    try:
        document = json.loads(body)
    except ValueError as error:
        raise MetadataError("client metadata is not valid JSON") from error
    if not isinstance(document, dict):
        raise MetadataError("client metadata must be a JSON object")
    return document
