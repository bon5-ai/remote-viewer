"""Agent pairing: OAuth 2.1 for MCP clients, approved by a person at the terminal.

1. A client registers (bounded dynamic registration) or names itself with a URL
   whose metadata document the gate fetches (CIMD).
2. ``/authorize`` opens a *pending request*. The browser shows a short request ID
   and holds a secret cookie; nothing secret is typed into the browser.
3. The person runs ``tmux-remote-viewer agent approve`` in a shell on this machine and
   picks a scope and a pane. That creates a *grant* and a one-time auth code.
4. The browser's poll receives the redirect carrying the code, and the client
   trades code + PKCE verifier at ``/token`` for an access and a refresh token.

The scope is the person's choice at approval, never the client's. Every code
and token is held only as a digest, in memory. A grant ends when it is revoked,
when it expires, or when its tmux session ends (checked on every call), so a
restart of the gate or of the session signs every agent out.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
import unicodedata
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

from .gate import CODE_ALPHABET, digest, new_code, normalize_code

SCOPES = ("observe", "suggest", "control")
SCOPE_RANK = {name: rank for rank, name in enumerate(SCOPES)}
SCOPE_HELP = {"observe": "read the screen",
              "suggest": "type text without pressing Enter, at a shell prompt",
              "control": "type, press keys and run commands"}

REQUEST_ID_LENGTH = 4
PENDING_TTL = 300
PENDING_LINGER = 60  # an expired request stays long enough for its page to say so
MAX_PENDING = 10
MAX_PENDING_PER_CLIENT = 3
AUTH_CODE_TTL = 60
USED_CODE_MEMORY = 600
REFRESH_GRACE = 30  # two parallel refreshes must not look like token theft
MAX_CLIENTS = 100
CLIENT_IDLE_TTL = 7 * 86400  # a registration nobody has used for a week is forgotten
MAX_TOKENS_PER_GRANT = 5  # live access tokens, and refresh tokens kept for reuse detection
MAX_METADATA_CACHE = 50
METADATA_CACHE_TTL = 600
METADATA_FAILURE_TTL = 60  # a host that failed isn't fetched again for this long
MAX_REDIRECT_URIS = 5
MAX_URI_LENGTH = 512
MAX_NAME_LENGTH = 64
WRITE_LIMIT = 20
WRITE_WINDOW = 10

VERIFIER = re.compile(r"[A-Za-z0-9\-._~]{43,128}")
CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
GRANT_ID = re.compile(r"g-[0-9a-f]{8}")
REQUEST_ID = re.compile(r"[A-Z0-9]{%d}" % REQUEST_ID_LENGTH)


class OAuthError(Exception):
    """An error with an RFC 6749 error code, safe to show the client."""

    def __init__(self, error: str, description: str):
        super().__init__(description)
        self.error = error
        self.description = description


class NotFound(Exception):
    pass


class Busy(Exception):
    pass


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def clean_name(value) -> str:
    """A display name with no control, format (bidi, zero-width) or odd space characters."""
    if not isinstance(value, str):
        return ""
    kept = "".join(ch for ch in value if ch == " " or unicodedata.category(ch)[0] not in "CZ")
    return " ".join(kept.split())[:MAX_NAME_LENGTH]


def is_loopback_redirect(uri: str) -> bool:
    try:
        parts = urlsplit(uri)
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return False
    return (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "::1", "localhost")
            and parts.username is None and parts.password is None and not parts.fragment)


def redirect_matches(registered: str, requested: str) -> bool:
    """Exact match, except that a loopback redirect may use any port (RFC 8252 §7.3)."""
    if registered == requested:
        return True
    if not (is_loopback_redirect(registered) and is_loopback_redirect(requested)):
        return False
    a, b = urlsplit(registered), urlsplit(requested)
    return a.hostname == b.hostname and (a.path or "/") == (b.path or "/") and a.query == b.query


def with_params(uri: str, params: dict) -> str:
    query = urlencode({key: value for key, value in params.items() if value is not None})
    return uri + ("&" if "?" in uri else "?") + query


@dataclass(frozen=True)
class Client:
    id: str
    name: str
    redirect_uris: tuple[str, ...]
    verified: bool  # True when the name came from a metadata document at the client_id URL
    created: float

    @property
    def host(self) -> str | None:
        return urlsplit(self.id).hostname if self.verified else None


@dataclass
class Pending:
    id: str
    browser: str  # digest of the browser's cookie
    client: Client
    redirect_uri: str
    challenge: str
    state: str | None
    resource: str
    issuer: str
    client_ip: str
    created: float
    expires: float
    outcome: str | None = None  # "approved" | "denied"
    redirect: str | None = None  # plaintext until the browser has collected it
    delivered: bool = False


@dataclass(frozen=True)
class AuthCode:
    grant_id: str
    client_id: str
    redirect_uri: str
    challenge: str
    resource: str
    expires: float


@dataclass
class Refresh:
    grant_id: str
    expires: float
    rotated_at: float | None = None
    successor: dict | None = None  # the response it was rotated into, kept only for the grace window


@dataclass
class Grant:
    id: str
    session_key: str
    pane_id: str
    scope: str
    client_id: str
    client_name: str
    verified: bool
    resources: frozenset[str]
    created: float
    expires: float
    last_used: float | None = None
    writes: deque = field(default_factory=deque)
    access_keys: deque = field(default_factory=deque)
    refresh_keys: deque = field(default_factory=deque)

    def allows(self, scope: str) -> bool:
        return SCOPE_RANK[self.scope] >= SCOPE_RANK[scope]

    def as_dict(self, now: float) -> dict:
        return {"id": self.id, "client": self.client_name, "verified": self.verified, "scope": self.scope,
                "pane": self.pane_id, "expiresIn": max(0, int(self.expires - now)),
                "idle": None if self.last_used is None else int(now - self.last_used)}


class AgentAuth:
    def __init__(self, *, agent_ttl: int, access_ttl: int, allowed_redirect_uris=(), fetch_metadata=None,
                 on_event=lambda kind, **fields: None, clock=time.time):
        self.agent_ttl = agent_ttl
        self.access_ttl = access_ttl
        self.allowed_redirect_uris = frozenset(allowed_redirect_uris)
        self.fetch_metadata = fetch_metadata
        self.on_event = on_event
        self.clock = clock
        self._lock = threading.Lock()
        self._clients: dict[str, Client] = {}
        self._client_seen: dict[str, float] = {}
        self._metadata: dict[str, tuple[Client, float]] = {}
        self._metadata_failures: dict[str, float] = {}
        self._pending: dict[str, Pending] = {}
        self._codes: dict[str, AuthCode] = {}
        self._used_codes: dict[str, tuple[str, float]] = {}
        self._grants: dict[str, Grant] = {}
        self._access: dict[str, tuple[str, float]] = {}
        self._refresh: dict[str, Refresh] = {}

    # ---- housekeeping ---------------------------------------------------------------
    def _prune(self, now: float) -> list[Grant]:
        expired = [grant for grant in self._grants.values() if grant.expires <= now]
        for grant in expired:
            self._drop_grant(grant.id)
        for key in [key for key, item in self._pending.items() if item.expires + PENDING_LINGER <= now]:
            del self._pending[key]
        for key in [key for key, item in self._codes.items() if item.expires <= now]:
            del self._codes[key]
        for key in [key for key, (_, forget) in self._used_codes.items() if forget <= now]:
            del self._used_codes[key]
        for key in [key for key, (_, expires) in self._access.items() if expires <= now]:
            del self._access[key]
        for key in [key for key, item in self._refresh.items() if item.expires <= now]:
            del self._refresh[key]
        for item in self._refresh.values():
            if item.successor is not None and now - item.rotated_at > REFRESH_GRACE:
                item.successor = None  # the plaintext of a rotated pair lives only as long as the grace
        in_use = self._clients_in_use()
        for key in [key for key, seen in self._client_seen.items()
                    if key not in in_use and seen + CLIENT_IDLE_TTL <= now]:
            self._clients.pop(key, None)
            del self._client_seen[key]
        for key in [key for key, (_, expires) in self._metadata.items() if expires <= now]:
            del self._metadata[key]
        for key in [key for key, until in self._metadata_failures.items() if until <= now]:
            del self._metadata_failures[key]
        return expired

    def _clients_in_use(self) -> set[str]:
        return {grant.client_id for grant in self._grants.values()} | {
            item.client.id for item in self._pending.values() if item.outcome is None}

    def prune(self) -> None:
        with self._lock:
            expired = self._prune(self.clock())
        for grant in expired:
            self.on_event("expired", grant=grant.id, client=grant.client_name)

    def _drop_grant(self, grant_id: str) -> Grant | None:
        grant = self._grants.pop(grant_id, None)
        if grant is not None:
            for key in grant.access_keys:
                self._access.pop(key, None)
            for key in grant.refresh_keys:
                self._refresh.pop(key, None)
            for key in [key for key, item in self._codes.items() if item.grant_id == grant_id]:
                del self._codes[key]
            self._client_seen[grant.client_id] = self.clock()
        return grant

    # ---- clients ----------------------------------------------------------------------
    def redirect_allowed(self, uri: str) -> bool:
        return len(uri) <= MAX_URI_LENGTH and (is_loopback_redirect(uri) or uri in self.allowed_redirect_uris)

    def register(self, metadata) -> Client:
        """Dynamic client registration (RFC 7591), for public clients only."""
        if not isinstance(metadata, dict):
            raise OAuthError("invalid_client_metadata", "The body must be a JSON object.")
        uris = metadata.get("redirect_uris")
        if (not isinstance(uris, list) or not 0 < len(uris) <= MAX_REDIRECT_URIS
                or not all(isinstance(uri, str) for uri in uris)):
            raise OAuthError("invalid_redirect_uri", f"Give 1 to {MAX_REDIRECT_URIS} redirect_uris.")
        for uri in uris:
            if not self.redirect_allowed(uri):
                raise OAuthError("invalid_redirect_uri",
                                 "Redirect URIs must be http://localhost, http://127.0.0.1 or http://[::1] "
                                 "(any port), or listed in this server's allowed_redirect_uris.")
        if metadata.get("token_endpoint_auth_method", "none") != "none":
            raise OAuthError("invalid_client_metadata",
                             "Only public clients are supported: token_endpoint_auth_method must be none.")
        grant_types = metadata.get("grant_types", ["authorization_code", "refresh_token"])
        if not isinstance(grant_types, list) or not set(grant_types) <= {"authorization_code", "refresh_token"}:
            raise OAuthError("invalid_client_metadata", "grant_types may be authorization_code and refresh_token.")
        response_types = metadata.get("response_types", ["code"])
        if not isinstance(response_types, list) or not set(response_types) <= {"code"}:
            raise OAuthError("invalid_client_metadata", "response_types may only be code.")
        now = self.clock()
        client = Client(id="client-" + secrets.token_urlsafe(16),
                        name=clean_name(metadata.get("client_name")) or "Unnamed client",
                        redirect_uris=tuple(uris), verified=False, created=now)
        with self._lock:
            self._prune(now)
            if len(self._clients) >= MAX_CLIENTS:
                # Make room by forgetting the least recently used registration that nothing
                # depends on. A flood of registrations can't lock registration, and can't
                # touch a client that has a grant or a sign-in in progress.
                in_use = self._clients_in_use()
                idle = [key for key in self._clients if key not in in_use]
                if not idle:
                    raise OAuthError("temporarily_unavailable", "Too many registered clients. Try again later.")
                oldest = min(idle, key=lambda key: self._client_seen.get(key, 0))
                del self._clients[oldest]
                self._client_seen.pop(oldest, None)
            self._clients[client.id] = client
            self._client_seen[client.id] = now
        return client

    def client(self, client_id: str) -> Client | None:
        """Look a client up, fetching its metadata document if its id is a URL. May do network I/O."""
        if not isinstance(client_id, str) or not client_id:
            return None
        now = self.clock()
        if not client_id.startswith("https://"):
            with self._lock:
                client = self._clients.get(client_id)
                if client is not None:
                    self._client_seen[client_id] = now
                return client
        if self.fetch_metadata is None:
            return None
        host = urlsplit(client_id).hostname or ""
        with self._lock:
            cached = self._metadata.get(client_id)
            failed_until = self._metadata_failures.get(host, 0)
        if cached and cached[1] > now:
            return cached[0]
        if failed_until > now:
            return None
        try:
            document = self.fetch_metadata(client_id)
        except Exception:  # noqa: BLE001 - any failure to fetch means "no such client"
            document = None
        client = self._client_from_document(client_id, document, now) if document is not None else None
        if client is None:
            with self._lock:
                self._metadata_failures[host] = now + METADATA_FAILURE_TTL
            return None
        if client is not None:
            with self._lock:
                if len(self._metadata) >= MAX_METADATA_CACHE:
                    self._metadata.pop(next(iter(self._metadata)))
                self._metadata[client_id] = (client, now + METADATA_CACHE_TTL)
        return client

    def _client_from_document(self, client_id: str, document, now: float) -> Client | None:
        if not isinstance(document, dict) or document.get("client_id") != client_id:
            return None
        if document.get("token_endpoint_auth_method", "none") != "none":
            return None
        uris = document.get("redirect_uris")
        if not isinstance(uris, list) or not all(isinstance(uri, str) for uri in uris):
            return None
        allowed = tuple(uri for uri in uris[:20] if self.redirect_allowed(uri))
        if not allowed:
            return None
        name = clean_name(document.get("client_name")) or urlsplit(client_id).hostname or "client"
        return Client(id=client_id, name=name, redirect_uris=allowed, verified=True, created=now)

    # ---- authorization requests ---------------------------------------------------------
    def check_redirect(self, client: Client, redirect_uri: str) -> bool:
        return self.redirect_allowed(redirect_uri) and any(
            redirect_matches(registered, redirect_uri) for registered in client.redirect_uris)

    def start(self, *, client: Client, redirect_uri: str, challenge: str, state: str | None, resource: str,
              issuer: str, client_ip: str = "") -> tuple[Pending, str]:
        if not CHALLENGE.fullmatch(challenge or ""):
            raise OAuthError("invalid_request", "A PKCE code_challenge (S256) is required.")
        now = self.clock()
        secret = secrets.token_urlsafe(32)
        with self._lock:
            self._prune(now)
            live = [item for item in self._pending.values() if item.outcome is None and item.expires > now]
            if len(live) >= MAX_PENDING or sum(item.client_ip == client_ip for item in live) >= MAX_PENDING_PER_CLIENT:
                raise Busy()
            request_id = new_code(REQUEST_ID_LENGTH)
            while request_id in self._pending:
                request_id = new_code(REQUEST_ID_LENGTH)
            pending = Pending(id=request_id, browser=digest(secret), client=client, redirect_uri=redirect_uri,
                              challenge=challenge, state=state, resource=resource, issuer=issuer,
                              client_ip=client_ip, created=now, expires=now + PENDING_TTL)
            self._pending[request_id] = pending
        self.on_event("requested", request=request_id, client=client.name, verified=client.verified,
                      redirect=urlsplit(redirect_uri).netloc)
        return pending, secret

    def pending(self) -> list[dict]:
        now = self.clock()
        with self._lock:
            self._prune(now)
            items = [item for item in self._pending.values() if item.outcome is None and item.expires > now]
        return [{"id": item.id, "client": item.client.name, "verified": item.client.verified,
                 "clientHost": item.client.host, "redirectHost": urlsplit(item.redirect_uri).netloc,
                 "age": int(now - item.created), "expiresIn": int(item.expires - now)}
                for item in sorted(items, key=lambda item: item.created)]

    def _open_request(self, request_id: str, now: float) -> Pending:
        pending = self._pending.get(normalize_code(request_id))
        if pending is None or pending.outcome is not None or pending.expires <= now:
            raise NotFound(f"No open request {request_id!r}. It may have expired; start the login again.")
        return pending

    def approve(self, request_id: str, *, scope: str, pane_id: str, session_key: str,
                ttl: int | None = None) -> Grant:
        if scope not in SCOPES:
            raise ValueError(f"scope must be one of {', '.join(SCOPES)}")
        ttl = min(ttl or self.agent_ttl, self.agent_ttl)
        now = self.clock()
        with self._lock:
            self._prune(now)
            pending = self._open_request(request_id, now)
            grant = Grant(id=f"g-{secrets.token_hex(4)}", session_key=session_key, pane_id=pane_id, scope=scope,
                          client_id=pending.client.id, client_name=pending.client.name,
                          verified=pending.client.verified, resources=frozenset({pending.resource}),
                          created=now, expires=now + ttl)
            self._grants[grant.id] = grant
            code = secrets.token_urlsafe(32)
            self._codes[digest(code)] = AuthCode(grant.id, pending.client.id, pending.redirect_uri, pending.challenge,
                                                 pending.resource, now + AUTH_CODE_TTL)
            pending.outcome = "approved"
            pending.redirect = with_params(pending.redirect_uri, {"code": code, "state": pending.state,
                                                                   "iss": pending.issuer})
        self.on_event("approved", request=pending.id, grant=grant.id, client=grant.client_name, scope=scope,
                      pane=pane_id)
        return grant

    def deny(self, request_id: str) -> None:
        now = self.clock()
        with self._lock:
            pending = self._open_request(request_id, now)
            pending.outcome = "denied"
            pending.redirect = with_params(pending.redirect_uri, {
                "error": "access_denied", "error_description": "The request was denied at the terminal.",
                "state": pending.state, "iss": pending.issuer})
        self.on_event("denied", request=pending.id, client=pending.client.name)

    def poll(self, browser_secret: str, request_id: str) -> dict | None:
        """What the waiting page shows. The redirect is handed out once, then forgotten."""
        if not browser_secret:
            return None
        now = self.clock()
        with self._lock:
            pending = self._pending.get(request_id)
            if pending is None or not hmac.compare_digest(pending.browser, digest(browser_secret)):
                return None
            result = {"id": pending.id, "client": pending.client.name, "verified": pending.client.verified,
                      "clientHost": pending.client.host, "redirectHost": urlsplit(pending.redirect_uri).netloc,
                      "expiresIn": max(0, int(pending.expires - now))}
            if pending.outcome is None and pending.expires <= now:
                pending.outcome = "expired"
                pending.redirect = with_params(pending.redirect_uri, {
                    "error": "access_denied", "error_description": "The request expired before it was approved.",
                    "state": pending.state, "iss": pending.issuer})
            result["state"] = pending.outcome or "pending"
            if pending.outcome and not pending.delivered:
                result["redirect"] = pending.redirect
                pending.redirect = None
                pending.delivered = True
        return result

    # ---- tokens -------------------------------------------------------------------------
    def _usable(self, grant: Grant | None, now: float) -> bool:
        return grant is not None and grant.expires > now

    @staticmethod
    def _keep(keys: deque, table: dict, key: str) -> None:
        """Track a grant's token, dropping its oldest once the grant holds too many."""
        keys.append(key)
        while len(keys) > MAX_TOKENS_PER_GRANT:
            table.pop(keys.popleft(), None)

    def _issue(self, grant: Grant, now: float, *, refresh: bool) -> dict:
        access = secrets.token_urlsafe(32)
        access_expires = min(now + self.access_ttl, grant.expires)
        self._access[digest(access)] = (grant.id, access_expires)
        self._keep(grant.access_keys, self._access, digest(access))
        response = {"access_token": access, "token_type": "Bearer",
                    "expires_in": int(access_expires - now), "scope": grant.scope}
        if refresh:
            token = secrets.token_urlsafe(32)
            self._refresh[digest(token)] = Refresh(grant.id, grant.expires)
            self._keep(grant.refresh_keys, self._refresh, digest(token))
            response["refresh_token"] = token
        return response

    def exchange_code(self, *, code: str, client_id: str, redirect_uri: str, verifier: str,
                      resource: str | None) -> dict:
        now = self.clock()
        key = digest(code or "")
        revoked = None
        try:
            with self._lock:
                self._prune(now)
                entry = self._codes.pop(key, None)
                if entry is None:
                    used = self._used_codes.get(key)
                    if used is not None:  # a replayed code: whoever holds it, the grant is no longer safe
                        revoked = self._drop_grant(used[0])
                    raise OAuthError("invalid_grant", "The authorization code is unknown, expired or already used.")
                self._used_codes[key] = (entry.grant_id, now + USED_CODE_MEMORY)
                if client_id != entry.client_id or redirect_uri != entry.redirect_uri:
                    raise OAuthError("invalid_grant", "The code was issued to another client or redirect URI.")
                if not VERIFIER.fullmatch(verifier or "") or not hmac.compare_digest(s256(verifier), entry.challenge):
                    raise OAuthError("invalid_grant", "PKCE verification failed.")
                if resource and resource != entry.resource:
                    raise OAuthError("invalid_target", "The resource does not match the authorization request.")
                grant = self._grants.get(entry.grant_id)
                if not self._usable(grant, now):
                    raise OAuthError("invalid_grant", "The grant has been revoked or has expired.")
                return self._issue(grant, now, refresh=True)
        finally:
            if revoked is not None:
                self.on_event("revoked", grant=revoked.id, client=revoked.client_name,
                              reason="authorization code reused")

    def refresh(self, *, token: str, client_id: str, resource: str | None) -> dict:
        now = self.clock()
        revoked = None
        try:
            with self._lock:
                self._prune(now)
                entry = self._refresh.get(digest(token or ""))
                if entry is None:
                    raise OAuthError("invalid_grant", "The refresh token is unknown or expired.")
                grant = self._grants.get(entry.grant_id)
                if not self._usable(grant, now) or grant.client_id != client_id:
                    raise OAuthError("invalid_grant", "The refresh token does not belong to this client.")
                if resource and resource not in grant.resources:
                    raise OAuthError("invalid_target", "The resource does not match this grant.")
                if entry.rotated_at is not None:
                    if now - entry.rotated_at <= REFRESH_GRACE and entry.successor is not None:
                        # A retry of the same refresh (two requests in flight, a lost response):
                        # the same successor again, never a second independent chain.
                        return dict(entry.successor)
                    revoked = self._drop_grant(grant.id)  # reuse of a rotated token: assume it was stolen
                    raise OAuthError("invalid_grant", "The refresh token was already used.")
                response = self._issue(grant, now, refresh=True)
                entry.rotated_at = now
                entry.successor = dict(response)
                return response
        finally:
            if revoked is not None:
                self.on_event("revoked", grant=revoked.id, client=revoked.client_name, reason="refresh token reused")

    def mint_direct(self, *, scope: str, pane_id: str, session_key: str, resources: frozenset[str],
                    label: str, ttl: int | None = None) -> tuple[Grant, str]:
        """A grant and a bearer token without OAuth, for clients that read a header from a helper."""
        if scope not in SCOPES:
            raise ValueError(f"scope must be one of {', '.join(SCOPES)}")
        now = self.clock()
        ttl = min(ttl or self.agent_ttl, self.agent_ttl)
        grant = Grant(id=f"g-{secrets.token_hex(4)}", session_key=session_key, pane_id=pane_id, scope=scope,
                      client_id="direct", client_name=clean_name(label) or "token file", verified=False,
                      resources=resources, created=now, expires=now + ttl)
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._prune(now)
            self._grants[grant.id] = grant
            self._access[digest(token)] = (grant.id, grant.expires)
            self._keep(grant.access_keys, self._access, digest(token))
        self.on_event("approved", grant=grant.id, client=grant.client_name, scope=scope, pane=pane_id,
                      direct=True)
        return grant, token

    def authenticate(self, token: str, resource: str) -> Grant | None:
        if not token:
            return None
        now = self.clock()
        with self._lock:
            entry = self._access.get(digest(token))
            if entry is None or entry[1] <= now:
                return None
            grant = self._grants.get(entry[0])
            if not self._usable(grant, now) or resource not in grant.resources:
                return None
            grant.last_used = now
            return grant

    def revoke_token(self, token: str) -> None:
        """RFC 7009: revoking either token of a grant ends the grant."""
        key = digest(token or "")
        with self._lock:
            grant_id = (self._access.get(key) or (None,))[0]
            if grant_id is None and key in self._refresh:
                grant_id = self._refresh[key].grant_id
            grant = self._drop_grant(grant_id) if grant_id else None
        if grant is not None:
            self.on_event("revoked", grant=grant.id, client=grant.client_name, reason="revoked by client")

    # ---- grants -------------------------------------------------------------------------
    def grants(self) -> list[Grant]:
        now = self.clock()
        with self._lock:
            self._prune(now)
            return sorted(self._grants.values(), key=lambda grant: grant.created)

    def grant(self, grant_id: str) -> Grant | None:
        with self._lock:
            return self._grants.get(grant_id)

    def revoke(self, grant_id: str | None = None, *, reason: str) -> list[Grant]:
        """Revoke one grant, or every grant when grant_id is None."""
        with self._lock:
            ids = list(self._grants) if grant_id is None else [grant_id]
            dropped = [grant for grant in map(self._drop_grant, ids) if grant is not None]
        for grant in dropped:
            self.on_event("revoked", grant=grant.id, client=grant.client_name, reason=reason)
        return dropped

    def retarget(self, grant_id: str, pane_id: str) -> Grant:
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None:
                raise NotFound(f"No grant {grant_id!r}.")
            grant.pane_id = pane_id
        self.on_event("retargeted", grant=grant.id, client=grant.client_name, pane=pane_id)
        return grant

    def allow_write(self, grant: Grant) -> bool:
        now = self.clock()
        with self._lock:
            while grant.writes and grant.writes[0] <= now - WRITE_WINDOW:
                grant.writes.popleft()
            if len(grant.writes) >= WRITE_LIMIT:
                return False
            grant.writes.append(now)
            return True


__all__ = ["AgentAuth", "Busy", "CODE_ALPHABET", "Client", "Grant", "GRANT_ID", "NotFound", "OAuthError", "REQUEST_ID",
           "SCOPES", "SCOPE_HELP", "SCOPE_RANK", "clean_name", "is_loopback_redirect", "redirect_matches", "s256"]
