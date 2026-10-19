"""The public listeners: the viewer page and its stream, the OAuth endpoints, and /mcp.

Every request first passes the Guard:

* its Host header must be one this listener answers to (the DNS-rebinding defence);
* behind a proxy, it must carry the proxy's shared secret header, or it gets a 404
  (that stops anyone from going straight to the proxy's origin, around the proxy);
* the listener's public path prefix (e.g. /remote) is removed, so the routes
  work the same whether a proxy stripped it (Tailscale Funnel does) or not.

The viewer cookie and the authorize cookie are HttpOnly, Secure, SameSite=Strict
and carry no Path, so they default to the directory they were set from: the public
mount behind a proxy, / when the gate is reached directly.
"""

from __future__ import annotations

import functools
import hmac
import ipaddress
import json
import logging
from urllib.parse import parse_qs, urlsplit

import anyio
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidURI

from .agents import PENDING_LINGER, PENDING_TTL, REQUEST_ID, SCOPES, Busy, OAuthError, with_params
from .config import Listener
from .gate import FONT_NAME, PLAYER_ASSETS, InvalidCode, Throttled
from .state import State

log = logging.getLogger("bon5ai_remote")

COOKIE = "bon5ai_remote"
PENDING_COOKIE = "bon5ai_authorize"
MAX_CLAIM_BYTES = 1024
MAX_FORM_BYTES = 8192
METADATA_FETCHES = 4  # client metadata fetches at once, in their own threads (not the shared pool)
REVALIDATE_SECONDS = 30
SERVER_NAME = "BON5AI Remote Viewer"

# The player compiles its terminal emulator from WebAssembly and sets inline
# styles, hence 'wasm-unsafe-eval' and the style 'unsafe-inline'. No inline script.
VIEWER_CSP = ("default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; "
              "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
              "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
# The authorize page renders a client's self-chosen name, so it gets the strictest policy.
AUTHORIZE_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; "
                 "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
API_CSP = "default-src 'none'; frame-ancestors 'none'"
COMMON_HEADERS = (("cache-control", "no-store"),
                  ("cross-origin-resource-policy", "same-origin"),
                  ("referrer-policy", "no-referrer"),
                  ("x-content-type-options", "nosniff"),
                  ("x-frame-options", "DENY"),
                  ("x-robots-tag", "noindex"))

STATIC = {"/": ("index.html", "text/html; charset=utf-8", VIEWER_CSP),
          "/remote.js": ("remote.js", "text/javascript; charset=utf-8", VIEWER_CSP),
          "/remote.css": ("remote.css", "text/css; charset=utf-8", VIEWER_CSP),
          "/authorize.js": ("authorize.js", "text/javascript; charset=utf-8", AUTHORIZE_CSP),
          "/fonts/CascadiaMono.woff2": ("fonts/CascadiaMono.woff2", "font/woff2", VIEWER_CSP),
          "/fonts/CascadiaMonoItalic.woff2": ("fonts/CascadiaMonoItalic.woff2", "font/woff2", VIEWER_CSP)}


# ---- responses ----------------------------------------------------------------------------
def respond(body: bytes | str, status: int = 200, content_type: str = "text/plain; charset=utf-8",
            csp: str = API_CSP, headers=()) -> Response:
    response = Response(body, status_code=status, headers={"content-type": content_type})
    for name, value in COMMON_HEADERS:
        response.headers[name] = value
    response.headers["content-security-policy"] = csp
    for name, value in headers:
        response.headers.append(name, value)
    return response


def respond_json(payload, status: int = 200, headers=()) -> Response:
    return respond(json.dumps(payload).encode(), status, "application/json", headers=headers)


def cookie(name: str, value: str, max_age: int) -> tuple[str, str]:
    # Written by hand: Starlette's set_cookie defaults to Path=/ and SameSite=Lax,
    # which would widen the cookie to the whole host and weaken it.
    return "set-cookie", f"{name}={value}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict"


@functools.cache
def static_bytes(static_dir, name: str) -> bytes:
    return (static_dir / name).read_bytes()


async def read_body(request: Request, limit: int) -> bytes | None:
    """The request body, or None if it is larger than limit."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        return None
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            return None
    return bytes(body)


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


# ---- the guard ------------------------------------------------------------------------------
class Guard:
    def __init__(self, app, listener: Listener, secret: str):
        self.app = app
        self.listener = listener
        self.secret = secret.encode()

    async def deny(self, scope, receive, send, status: int, text: str) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        await respond(text, status)(scope, receive, send)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        headers = Headers(scope=scope)
        host = headers.get("host", "").lower()
        if not self.listener.host_allowed(host):
            log.warning("refused Host %r on %s; if that is your proxy's origin name, add it to allowed_hosts",
                        host[:100], self.listener.name)
            return await self.deny(scope, receive, send, 421, "Misdirected request\n")
        trusted_proxy = False
        if self.listener.proxy_header:
            presented = headers.get(self.listener.proxy_header, "").encode()
            if not hmac.compare_digest(presented, self.secret):
                return await self.deny(scope, receive, send, 404, "Not found\n")
            trusted_proxy = True
        if self.listener.deny_funnel and "tailscale-funnel-request" in headers:
            return await self.deny(scope, receive, send, 404, "Not found\n")
        path = scope["path"]
        mount = self.listener.mount
        if mount and (path == mount or path.startswith(mount + "/")):
            path = path[len(mount):] or "/"
        client = ""
        if trusted_proxy and self.listener.client_ip_header:
            client = client_address(headers.get(self.listener.client_ip_header, ""), self.listener.client_ip_header)
        scope = {**scope, "path": path, "raw_path": path.encode(), "bon5ai.base": self.listener.base_url(host),
                 "bon5ai.client": client, "bon5ai.listener": self.listener}
        await self.app(scope, receive, send)


def client_address(value: str, header: str) -> str:
    """The client's IP from a trusted proxy header, or "" if it can't be read.

    CloudFront-Viewer-Address is always address:port, with IPv6 unbracketed, so its
    port is cut at the last colon (a compressed IPv6 address plus ":port" would
    otherwise still parse as an address). Other headers carry a bare address; from a
    list (X-Forwarded-For) the last one, which your proxy added. The first is whatever
    the client chose to send."""
    if header.lower() == "cloudfront-viewer-address":
        value = value.strip().rsplit(":", 1)[0]
    else:
        value = value.rsplit(",", 1)[-1].strip()
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return ""


def allowed_origins(scope) -> set[str]:
    listener: Listener = scope["bon5ai.listener"]
    return {origin_of(scope["bon5ai.base"]), origin_of(listener.public_url)}


# ---- the app ----------------------------------------------------------------------------------
def build_app(state: State, listener: Listener):
    static_dir = state.cfg.static_dir

    def static(request: Request) -> Response:
        name, content_type, csp = STATIC[request.scope["path"]]
        return respond(static_bytes(static_dir, name), 200, content_type, csp)

    def token_of(request) -> str:
        return request.cookies.get(COOKIE, "")

    # ---- viewer ----------------------------------------------------------------------------
    def status(request: Request) -> Response:
        result = state.gate.status(token_of(request))
        if result is None:
            return respond_json({"state": "unpaired"}, 401)
        headers = [cookie(COOKIE, "", 0)] if result["state"] == "ended" else []
        return respond_json(result, headers=headers)

    async def claim(request: Request) -> Response:
        body = await read_body(request, MAX_CLAIM_BYTES)
        try:
            typed = str(json.loads(body or b"").get("code", ""))
        except (ValueError, AttributeError):
            return respond_json({"error": "Enter the code from your terminal."}, 400)
        client = request.scope["bon5ai.client"]
        try:
            token = state.gate.claim(typed, client)
        except Throttled:
            log.warning("claim refused: too many wrong codes%s", f" from {client}" if client else "")
            return respond_json({"error": "Too many wrong codes. Wait a few minutes and try again."}, 429)
        except InvalidCode as refusal:
            log.warning("wrong code (%d)%s", refusal.failures, f" from {client}" if client else "")
            return respond_json({"error": "That code isn't valid or has expired."}, 400)
        log.info("viewer paired")
        state.audit.record("viewer.paired", client=client or None)
        return respond_json({"ok": True}, headers=[cookie(COOKIE, token, state.cfg.viewer_ttl)])

    async def leave(request: Request) -> Response:
        state.gate.revoke(token_of(request))
        return respond_json({"state": "unpaired"}, headers=[cookie(COOKIE, "", 0)])

    def player_asset(request: Request) -> Response:
        if state.gate.live_viewer_session(token_of(request)) is None:
            return respond("Not paired\n", 401)
        path = request.scope["path"]
        body = state.gate.player_asset(path)
        if body is None:
            return respond("The stream isn't running.\n", 502)
        return respond(body, 200, PLAYER_ASSETS[path][1], VIEWER_CSP)

    def player_fonts(request: Request) -> Response:
        if state.gate.live_viewer_session(token_of(request)) is None:
            return respond("Not paired\n", 401)
        sheet = state.gate.symbol_font_sheet()
        if sheet is None:
            return respond("The stream isn't running.\n", 502)
        return respond(sheet[0], 200, "text/css; charset=utf-8", VIEWER_CSP)

    def symbol_font(request: Request) -> Response:
        name = request.path_params["name"] + ".woff2"
        if not FONT_NAME.fullmatch(name):
            return respond("Not found\n", 404)
        if state.gate.live_viewer_session(token_of(request)) is None:
            return respond("Not paired\n", 401)
        if state.gate.symbol_font_sheet() is None:
            return respond("The stream isn't running.\n", 502)
        body = state.gate.symbol_font(name)
        if body is None:
            return respond("Not found\n", 404)
        return respond(body, 200, "font/woff2", VIEWER_CSP)

    async def websocket(ws: WebSocket) -> None:
        token = ws.cookies.get(COOKIE, "")
        # The live check, not just a valid token: a cookie from an ended session must not
        # watch the next one (and would be counted under the old session, out of the badge).
        session = await anyio.to_thread.run_sync(state.gate.live_viewer_session, token)
        origin = ws.headers.get("origin")
        if session is None or (origin is not None and origin not in allowed_origins(ws.scope)):
            await ws.close(code=1008)
            return
        if not await anyio.to_thread.run_sync(state.gate.open_stream, session):
            await ws.close(code=1013)
            return
        upstream = None
        try:
            address = await anyio.to_thread.run_sync(state.stream_address)
            if address is None:
                await ws.close(code=1011)
                return
            try:
                # Only the handshake goes upstream: no cookie, no origin, no proxy from the environment.
                upstream = await ws_connect(f"ws://{address[0]}:{address[1]}/ws",
                                            subprotocols=ws.scope.get("subprotocols") or None, compression=None,
                                            max_size=None, open_timeout=5, ping_interval=None, proxy=None,
                                            user_agent_header=None)
            except (OSError, TimeoutError, InvalidHandshake, InvalidURI):
                await ws.close(code=1011)
                return
            await ws.accept(subprotocol=upstream.subprotocol)
            await relay(ws, upstream, lambda: state.gate.live_viewer_session(token) == session)
        finally:
            with anyio.CancelScope(shield=True):  # a cancelled relay must still count the viewer out
                if upstream is not None:
                    await upstream.close()
                await anyio.to_thread.run_sync(state.gate.close_stream, session)

    routes = []
    if listener.viewer:
        routes += [Route(path, static) for path in STATIC if not path.startswith("/authorize")]
        routes += [Route("/status", status), Route("/claim", claim, methods=["POST"]),
                   Route("/leave", leave, methods=["POST"]), Route("/player.js", player_asset),
                   Route("/player.css", player_asset), Route("/player-fonts.css", player_fonts),
                   Route("/{name:str}.woff2", symbol_font),
                   WebSocketRoute("/ws", websocket)]
    else:
        routes += [Route("/", lambda request: respond(f"{SERVER_NAME}: this address serves agents at /mcp.\n")),
                   Route("/remote.css", static)]  # the authorize page's stylesheet
    if listener.mcp:
        routes += oauth_routes(state, listener, static)
    return Guard(Starlette(routes=routes), listener, state.cfg.proxy_secret)


async def relay(ws: WebSocket, upstream, still_valid) -> None:
    """Pass frames both ways, keeping text and binary apart, until either side closes."""
    async with anyio.create_task_group() as group:
        async def from_browser() -> None:
            try:
                while True:
                    message = await ws.receive()
                    if message["type"] == "websocket.disconnect":
                        break
                    if message.get("bytes") is not None:
                        await upstream.send(message["bytes"])
                    elif message.get("text") is not None:
                        await upstream.send(message["text"])
            except (ConnectionClosed, WebSocketDisconnect, RuntimeError):
                pass
            group.cancel_scope.cancel()

        async def from_upstream() -> None:
            code, reason = 1000, ""
            try:
                async for message in upstream:
                    if isinstance(message, bytes):
                        await ws.send_bytes(message)
                    else:
                        await ws.send_text(message)
                code, reason = upstream.close_code or 1000, upstream.close_reason or ""
            except ConnectionClosed as closed:
                code = closed.rcvd.code if closed.rcvd else 1011
            except (WebSocketDisconnect, RuntimeError):
                pass
            try:
                await ws.close(code=code if 1000 <= code < 5000 and code not in (1005, 1006, 1015) else 1011,
                               reason=reason)
            except RuntimeError:
                pass
            group.cancel_scope.cancel()

        async def revalidate() -> None:
            while True:
                await anyio.sleep(REVALIDATE_SECONDS)
                if not await anyio.to_thread.run_sync(still_valid):
                    try:
                        await ws.close(code=1008)
                    except RuntimeError:
                        pass
                    group.cancel_scope.cancel()
                    return

        group.start_soon(from_browser)
        group.start_soon(from_upstream)
        group.start_soon(revalidate)


# ---- OAuth and MCP ----------------------------------------------------------------------------
def oauth_routes(state: State, listener: Listener, static) -> list:
    agents = state.agents

    def base(request) -> str:
        return request.scope["bon5ai.base"]

    def issuer(request) -> str:
        return base(request).rstrip("/")

    def resource_metadata(request: Request) -> Response:
        return respond_json({"resource": base(request) + "mcp", "authorization_servers": [issuer(request)],
                             "scopes_supported": list(SCOPES), "bearer_methods_supported": ["header"],
                             "resource_name": SERVER_NAME})

    def server_metadata(request: Request) -> Response:
        root = base(request)
        document = {
            "issuer": issuer(request),
            "authorization_endpoint": root + "authorize",
            "token_endpoint": root + "token",
            "registration_endpoint": root + "register",
            "revocation_endpoint": root + "revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": list(SCOPES),
            "client_id_metadata_document_supported": agents.fetch_metadata is not None,
            "authorization_response_iss_parameter_supported": True,
        }
        if request.scope["path"].startswith("/.well-known/openid-configuration"):
            # Served for clients whose discovery falls back to OpenID Connect's path, which is
            # the only one reachable when the gate is mounted under a path (e.g. /remote/).
            # No ID tokens are issued: code flow only, so the signing algorithm is "none".
            document |= {"jwks_uri": root + "jwks.json", "subject_types_supported": ["public"],
                         "id_token_signing_alg_values_supported": ["none"]}
        return respond_json(document)

    def jwks(request: Request) -> Response:
        return respond_json({"keys": []})

    def refuse_page(message: str, status: int = 400) -> Response:
        return respond(f"{SERVER_NAME}\n\n{message}\n", status)

    limiter: list[anyio.CapacityLimiter] = []  # created on first use, inside the event loop

    async def lookup_client(client_id: str):
        if not client_id.startswith("https://"):
            return agents.client(client_id)  # a registered client: memory only
        # A metadata document is a network fetch a stranger can ask for. It gets its own few
        # threads, so slow servers can't starve the pool every other route runs in.
        if not limiter:
            limiter.append(anyio.CapacityLimiter(METADATA_FETCHES))
        return await anyio.to_thread.run_sync(agents.client, client_id, limiter=limiter[0])

    async def authorize(request: Request) -> Response:
        query = request.query_params
        client = await lookup_client(query.get("client_id", ""))
        if client is None:
            return refuse_page("Unknown client. Remove the MCP server from your agent and add it again.")
        redirect_uri = query.get("redirect_uri", "")
        if not agents.check_redirect(client, redirect_uri):
            return refuse_page("That redirect URI is not registered for this client, or this server does not "
                               "allow it. Redirects must go to localhost unless listed in allowed_redirect_uris.")
        state_param = query.get("state")
        if state_param is not None and len(state_param) > 512:
            return refuse_page("The state parameter is too long.")

        def back(error: str, description: str) -> Response:
            return RedirectResponse(with_params(redirect_uri, {"error": error, "error_description": description,
                                                               "state": state_param, "iss": issuer(request)}), 302)

        if query.get("response_type") != "code":
            return back("unsupported_response_type", "Only the authorization code flow is supported.")
        if query.get("code_challenge_method") != "S256":
            return back("invalid_request", "PKCE with code_challenge_method=S256 is required.")
        resource = query.get("resource") or base(request) + "mcp"
        if resource != base(request) + "mcp":
            return back("invalid_target", f"This server's resource is {base(request)}mcp.")
        try:
            pending, secret = agents.start(client=client, redirect_uri=redirect_uri,
                                           challenge=query.get("code_challenge", ""), state=state_param,
                                           resource=resource, issuer=issuer(request),
                                           client_ip=request.scope["bon5ai.client"])
        except OAuthError as error:
            return back(error.error, error.description)
        except Busy:
            return refuse_page("Too many logins are waiting for approval. Try again in a few minutes.", 429)
        log.info("agent login %s waiting for approval (%s)", pending.id, client.name)
        # One cookie per request, so two sign-ins in one browser don't collide.
        return respond("", 303, headers=[("location", f"authorize-wait?request={pending.id}"),
                                         cookie(f"{PENDING_COOKIE}_{pending.id}", secret,
                                                PENDING_TTL + PENDING_LINGER)])

    def authorize_wait(request: Request) -> Response:
        page = static_bytes(state.cfg.static_dir, "authorize.html")
        return respond(page, 200, "text/html; charset=utf-8", AUTHORIZE_CSP)

    def authorize_status(request: Request) -> Response:
        request_id = request.query_params.get("request", "")
        result = None
        if REQUEST_ID.fullmatch(request_id):
            result = agents.poll(request.cookies.get(f"{PENDING_COOKIE}_{request_id}", ""), request_id)
        if result is None:
            return respond_json({"state": "unknown"}, 404)
        return respond_json(result)

    def form_value(form: dict, key: str) -> str:
        values = form.get(key, [])
        if len(values) > 1:
            raise OAuthError("invalid_request", f"{key} was given more than once.")
        return values[0] if values else ""

    async def token(request: Request) -> Response:
        no_cache = [("pragma", "no-cache")]
        body = await read_body(request, MAX_FORM_BYTES)
        if body is None:
            return respond_json({"error": "invalid_request", "error_description": "The request is too large."}, 413)
        try:
            form = parse_qs(body.decode("utf-8"), max_num_fields=20)
            grant_type = form_value(form, "grant_type")
            resource = form_value(form, "resource") or None
            client_id = form_value(form, "client_id")
            if grant_type == "authorization_code":
                result = agents.exchange_code(code=form_value(form, "code"), client_id=client_id,
                                              redirect_uri=form_value(form, "redirect_uri"),
                                              verifier=form_value(form, "code_verifier"), resource=resource)
            elif grant_type == "refresh_token":
                result = agents.refresh(token=form_value(form, "refresh_token"), client_id=client_id,
                                        resource=resource)
            else:
                raise OAuthError("unsupported_grant_type", "Use authorization_code or refresh_token.")
        except (UnicodeDecodeError, ValueError):
            return respond_json({"error": "invalid_request", "error_description": "Malformed form body."}, 400,
                                no_cache)
        except OAuthError as error:
            return respond_json({"error": error.error, "error_description": error.description}, 400, no_cache)
        return respond_json(result, headers=no_cache)

    async def register(request: Request) -> Response:
        body = await read_body(request, MAX_FORM_BYTES)
        if body is None:
            return respond_json({"error": "invalid_client_metadata", "error_description": "Too large."}, 413)
        try:
            client = agents.register(json.loads(body or b"null"))
        except ValueError:
            return respond_json({"error": "invalid_client_metadata", "error_description": "Body must be JSON."},
                                400)
        except OAuthError as error:
            return respond_json({"error": error.error, "error_description": error.description},
                                503 if error.error == "temporarily_unavailable" else 400)
        log.info("registered agent client %r", client.name)
        return respond_json({"client_id": client.id, "client_id_issued_at": int(client.created),
                             "client_name": client.name, "redirect_uris": list(client.redirect_uris),
                             "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                             "token_endpoint_auth_method": "none"}, 201)

    async def revoke(request: Request) -> Response:
        body = await read_body(request, MAX_FORM_BYTES) or b""
        try:
            form = parse_qs(body.decode("utf-8"), max_num_fields=20)
            agents.revoke_token(form_value(form, "token"))
        except (UnicodeDecodeError, ValueError, OAuthError):
            pass
        return respond_json({})

    mount = listener.mount
    prm_paths = {"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"}
    as_paths = {"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"}
    if mount:  # RFC 8414 path insertion, for proxies that route the host's /.well-known/ to the gate
        prm_paths.add(f"/.well-known/oauth-protected-resource{mount}/mcp")
        as_paths |= {f"/.well-known/oauth-authorization-server{mount}", f"/.well-known/openid-configuration{mount}"}
    return ([Route(path, resource_metadata) for path in sorted(prm_paths)]
            + [Route(path, server_metadata) for path in sorted(as_paths)]
            + [Route("/jwks.json", jwks), Route("/authorize", authorize),
               Route("/authorize-wait", authorize_wait), Route("/authorize-status", authorize_status),
               Route("/authorize.js", static),
               Route("/token", token, methods=["POST"]), Route("/register", register, methods=["POST"]),
               Route("/revoke", revoke, methods=["POST"]), Route("/mcp", McpEndpoint(state))])


class McpEndpoint:
    """Bearer-token front door to the MCP session manager."""

    def __init__(self, state: State):
        self.state = state

    async def __call__(self, scope, receive, send) -> None:
        request = Request(scope)
        base = scope["bon5ai.base"]
        if request.method != "POST":
            # Stateless JSON mode has no server-to-client stream to open with GET.
            return await respond("Use POST.\n", 405, headers=[("allow", "POST")])(scope, receive, send)
        origin = request.headers.get("origin")
        if origin is not None and origin not in allowed_origins(scope):
            return await respond("Forbidden origin\n", 403)(scope, receive, send)
        challenge = f'Bearer resource_metadata="{base}.well-known/oauth-protected-resource/mcp"'
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return await respond_json({"error": "invalid_token", "error_description": "Sign in first."}, 401,
                                      [("www-authenticate", challenge)])(scope, receive, send)
        grant = self.state.agents.authenticate(token.strip(), base + "mcp")
        if grant is None or not await anyio.to_thread.run_sync(self.state.session_alive, grant):
            return await respond_json(
                {"error": "invalid_token", "error_description": "The token is unknown, expired or revoked, or "
                                                                "its terminal session ended."}, 401,
                [("www-authenticate", challenge + ', error="invalid_token"')])(scope, receive, send)
        scope["bon5ai.grant"] = grant
        await self.state.mcp_manager.handle_request(scope, receive, send)
