"""The listener end to end: viewer routes, the websocket relay, OAuth discovery and sign-in, /mcp."""

import json
import secrets
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.testclient import TestClient

from bon5ai_remote import gate as gate_module
from bon5ai_remote import mcp_server
from bon5ai_remote import web as web_module
from bon5ai_remote.agents import s256
from bon5ai_remote.mcp_server import build_server
from bon5ai_remote.web import COOKIE, build_app, client_address
from helpers import PUBLIC, SECRET, STREAM_FONT, FakeStream, FakeTmux, jsonrpc, make_config, make_listener, make_state

HOST = "https://term.example.test"
WS_HOST = {"host": "term.example.test"}  # TestClient's websockets otherwise say Host: testserver
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
               "MCP-Protocol-Version": "2025-06-18"}
web_module.FAILURE_DELAY = 0.0  # wrong codes are slowed down in production; one test checks that on its own


class WithLifespan:
    """Runs the MCP session manager for the TestClient's lifetime, as serve() does."""

    def __init__(self, app, manager):
        self.app = app
        self.manager = manager

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await receive()
            async with self.manager.run():
                await send({"type": "lifespan.startup.complete"})
                await receive()
            await send({"type": "lifespan.shutdown.complete"})
            return
        await self.app(scope, receive, send)


class ListenerCase(unittest.TestCase):
    listener_overrides: dict = {}
    proxy_secret = ""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.stream = FakeStream()
        self.tmux = FakeTmux()
        self.tmux.options["@bon5ai_stream"] = f"{self.stream.address[0]}:{self.stream.address[1]}"
        self.tmux.options["@bon5ai_stream_pid"] = "4242"  # make_state's owner check says it is ours
        self.listener = make_listener(**self.listener_overrides)
        self.audit_path = Path(self.tmp.name) / "audit.jsonl"
        self.state = make_state(make_config(listeners=[self.listener], proxy_secret=self.proxy_secret),
                                self.tmux, audit_path=self.audit_path)
        manager = StreamableHTTPSessionManager(build_server(self.state), json_response=True, stateless=True,
                                               security_settings=TransportSecuritySettings(
                                                   enable_dns_rebinding_protection=False))
        self.state.mcp_manager = manager
        self.client = TestClient(WithLifespan(build_app(self.state, self.listener), manager), base_url=HOST)
        self.client.__enter__()
        self._fg = mcp_server.foreground_pgid
        mcp_server.foreground_pgid = lambda pid: pid  # the shell owns the terminal

    def tearDown(self):
        mcp_server.foreground_pgid = self._fg
        self.client.__exit__(None, None, None)
        self.stream.close()
        self.tmp.cleanup()

    def pair(self) -> str:
        response = self.client.post("/remote/claim", json={"code": self.state.gate.mint()})
        self.assertEqual(response.status_code, 200)
        return response.headers["set-cookie"]


class ViewerTests(ListenerCase):
    def test_cookie_is_exactly_strict_and_directory_scoped(self):
        cookie = self.pair()
        name, _, rest = cookie.partition("=")
        self.assertEqual(name, COOKIE)
        attributes = [part.strip() for part in rest.split(";")[1:]]
        self.assertEqual(attributes, ["Max-Age=3600", "HttpOnly", "Secure", "SameSite=Strict"])

    def test_page_is_served_with_and_without_the_prefix(self):
        for path in ("/", "/remote/"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Remote Viewer", response.content)
            self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
            self.assertEqual(response.headers["cache-control"], "no-store")

    def test_terminal_font_is_served(self):
        response = self.client.get("/remote/fonts/CascadiaMono.woff2")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "font/woff2")
        self.assertTrue(response.content.startswith(b"wOF2"))

    def test_unknown_paths_404(self):
        for path in ("/admin", "/pair", "/../pyproject.toml", "/static/index.html", "/token"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 404 if path != "/token" else 405, path)
            # Starlette's own error pages carry none of these; the gate's must.
            self.assertEqual(response.headers["content-security-policy"], web_module.API_CSP, path)
            self.assertEqual(response.headers["x-frame-options"], "DENY", path)
        self.assertEqual(self.client.post("/pair").status_code, 404)  # minting is admin-socket only
        # A trailing slash is not redirected (the redirect would point outside the mount).
        self.assertEqual(self.client.get("/remote/remote.js/").status_code, 404)

    def test_stream_is_served_only_while_its_owner_lives(self):
        # The gate serves whatever answers on the recorded port to every viewer, so once
        # the wrapper `share` started is gone, the port is not trusted even if something
        # still answers there.
        cookie = self.pair().split(";")[0]
        self.assertEqual(self.client.get("/remote/status").json()["state"], "live")
        self.state.stream_owned = lambda pid, listen: False
        self.assertEqual(self.client.get("/remote/status").json()["state"], "stream-down")
        self.assertEqual(self.client.get("/remote/player.js", headers={"cookie": cookie}).status_code, 502)
        self.state.stream_owned = lambda pid, listen: True
        del self.tmux.options["@bon5ai_stream_pid"]  # recorded by an older `share`: no owner, no trust
        self.assertEqual(self.client.get("/remote/status").json()["state"], "stream-down")

    def test_claim_takes_json_from_the_page_only(self):
        good = self.state.gate.mint()
        # A text/plain post needs no CORS preflight, so any site could make a browser send it.
        response = self.client.post("/remote/claim", content=json.dumps({"code": good}),
                                    headers={"content-type": "text/plain"})
        self.assertEqual(response.status_code, 415)
        response = self.client.post("/remote/claim", json={"code": good}, headers={"sec-fetch-site": "cross-site"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(self.state.gate._all_failures), 0)  # neither counted as a guess
        self.assertEqual(self.client.post("/remote/claim", json={"code": good},
                                          headers={"sec-fetch-site": "same-origin"}).status_code, 200)

    def test_a_flood_of_wrong_codes_never_locks_the_owner_out(self):
        for _ in range(gate_module.FAILURE_LIMIT * 2):
            self.assertEqual(self.client.post("/remote/claim", json={"code": "AAAA-AAAA"}).status_code, 400)
        self.assertEqual(self.client.post("/remote/claim", json={"code": self.state.gate.mint()}).status_code, 200)
        self.assertEqual(len(self.tmux.messages), 1)  # the terminal was told, once
        self.assertIn("wrong viewer codes", self.tmux.messages[0])
        with open(self.audit_path) as handle:
            kinds = [json.loads(line)["event"] for line in handle]
        self.assertIn("viewer.guessing", kinds)

    def test_a_wrong_code_waits_for_its_answer(self):
        web_module.FAILURE_DELAY = 0.3
        try:
            started = time.monotonic()
            self.assertEqual(self.client.post("/remote/claim", json={"code": "AAAA-AAAA"}).status_code, 400)
            self.assertGreaterEqual(time.monotonic() - started, 0.3)
            started = time.monotonic()
            self.assertEqual(self.client.post("/remote/claim", json={"code": self.state.gate.mint()}).status_code, 200)
            self.assertLess(time.monotonic() - started, 0.3)  # a right answer is never delayed
        finally:
            web_module.FAILURE_DELAY = 0.0

    def test_status_needs_a_viewer(self):
        self.assertEqual(self.client.get("/remote/status").status_code, 401)
        self.pair()
        self.assertEqual(self.client.get("/remote/status").json(), {"state": "live", "viewers": 0})

    def test_wrong_code(self):
        response = self.client.post("/remote/claim", json={"code": "AAAA-AAAA"})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("set-cookie", response.headers)

    def test_ended_session_clears_the_cookie(self):
        self.pair()
        self.tmux.session = "$2@300"
        response = self.client.get("/remote/status")
        self.assertEqual(response.json(), {"state": "ended"})
        self.assertIn("Max-Age=0", response.headers["set-cookie"])

    def test_symbol_font_is_proxied_for_a_viewer_only(self):
        name = "SymbolsNerdFont-Regular.64622a496f8fd2e6.woff2"
        self.assertEqual(self.client.get("/remote/player-fonts.css").status_code, 401)
        self.assertEqual(self.client.get(f"/remote/{name}").status_code, 401)
        self.pair()
        css = self.client.get("/remote/player-fonts.css")
        self.assertEqual(css.status_code, 200)
        self.assertIn(f'url("{name}")', css.text)
        font = self.client.get(f"/remote/{name}")
        self.assertEqual(font.content, STREAM_FONT)
        self.assertEqual(self.client.get("/remote/not-a-font.woff2").status_code, 404)

    def test_host_header_is_checked(self):
        response = self.client.get("/remote/", headers={"host": "evil.test"})
        self.assertEqual(response.status_code, 421)
        self.assertEqual(self.client.get("/", headers={"host": "box.tailnet.test"}).status_code, 200)
        self.assertEqual(self.client.get("/", headers={"host": "127.0.0.1:8095"}).status_code, 200)

    def test_websocket_needs_a_viewer(self):
        from starlette.websockets import WebSocketDisconnect
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect("/remote/ws", subprotocols=["v1.alis"], headers=WS_HOST) as ws:
                ws.receive_bytes()
        self.assertEqual(self.stream.requests, [])

    def test_websocket_refuses_a_foreign_origin(self):
        from starlette.websockets import WebSocketDisconnect
        cookie = self.pair().split(";")[0]
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect("/remote/ws", headers={**WS_HOST, "cookie": cookie,
                                                                      "origin": "https://evil.test"}) as ws:
                ws.receive_bytes()

    def test_a_viewer_of_an_ended_session_cannot_watch_the_next_one(self):
        from starlette.websockets import WebSocketDisconnect
        cookie = self.pair().split(";")[0]
        self.tmux.session = "$2@200"  # the session ended and a new one started
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect("/remote/ws", subprotocols=["v1.alis"],
                                               headers={**WS_HOST, "cookie": cookie, "origin": HOST}) as ws:
                ws.receive_bytes()
        self.assertFalse([request for request in self.stream.requests if request.startswith("GET /ws")])
        self.assertEqual(self.client.get("/remote/player.js", headers={"cookie": cookie}).status_code, 401)

    def test_only_the_players_subprotocol_goes_upstream(self):
        from starlette.websockets import WebSocketDisconnect
        cookie = self.pair().split(";")[0]
        # Anything else the browser offers is left out, even when it is not a valid token
        # (which used to raise a ValueError from the websockets library, a 500).
        with self.client.websocket_connect("/remote/ws", subprotocols=["a b", "v1.alis"],
                                           headers={**WS_HOST, "cookie": cookie, "origin": HOST}) as ws:
            self.assertEqual(ws.accepted_subprotocol, "v1.alis")
            self.assertEqual(ws.receive_bytes(), b"FRAME")
        self.assertIn("Sec-WebSocket-Protocol: v1.alis\r\n", self.stream.requests[-1])
        self.assertNotIn("a b", self.stream.requests[-1])
        # Without the player's protocol, the stream's answer (which names it) is a bad
        # handshake: the socket closes cleanly.
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect("/remote/ws", subprotocols=["a b"],
                                               headers={**WS_HOST, "cookie": cookie, "origin": HOST}) as ws:
                ws.receive_bytes()

    def test_websocket_is_relayed_with_only_handshake_headers(self):
        cookie = self.pair().split(";")[0]
        with self.client.websocket_connect("/remote/ws", subprotocols=["v1.alis"],
                                           headers={**WS_HOST, "cookie": cookie, "origin": HOST}) as ws:
            self.assertEqual(ws.accepted_subprotocol, "v1.alis")
            self.assertEqual(ws.receive_bytes(), b"FRAME")
            self.assertEqual(self.tmux.options["@bon5ai_viewers"], "1")
            ws.send_text("hello")  # the stream is one-way: nothing a browser sends reaches asciinema
            ws.send_bytes(b"\x00\x01")
            time.sleep(0.2)
            self.assertEqual(self.stream.inbound, [])
        upstream = self.stream.requests[-1]
        self.assertTrue(upstream.startswith("GET /ws HTTP/1.1"))
        self.assertIn("Sec-WebSocket-Protocol: v1.alis", upstream)
        self.assertNotIn("Cookie", upstream)
        self.assertNotIn("Origin", upstream)
        for _ in range(50):  # the relay counts the viewer out even though it was cancelled
            if self.tmux.options["@bon5ai_viewers"] == "0":
                break
            time.sleep(0.02)
        self.assertEqual(self.tmux.options["@bon5ai_viewers"], "0")


class ProxySecretTests(ListenerCase):
    listener_overrides = {"proxy_header": "X-Origin-Verify", "client_ip_header": "CloudFront-Viewer-Address"}
    proxy_secret = SECRET

    def test_requests_without_the_secret_get_404(self):
        self.assertEqual(self.client.get("/remote/").status_code, 404)
        self.assertEqual(self.client.get("/remote/", headers={"X-Origin-Verify": "wrong"}).status_code, 404)
        self.assertEqual(self.client.get("/remote/", headers={"X-Origin-Verify": SECRET}).status_code, 200)

    def test_client_address_scopes_the_lockout(self):
        headers = {"X-Origin-Verify": SECRET, "CloudFront-Viewer-Address": "2001:db8::1:51234"}
        for _ in range(gate_module.FAILURE_LIMIT):
            self.client.post("/remote/claim", json={"code": "AAAA-AAAA"}, headers=headers)
        self.assertEqual(self.client.post("/remote/claim", json={"code": "AAAA-AAAA"},
                                          headers={**headers, "CloudFront-Viewer-Address": "2001:db8::1:60000"})
                         .status_code, 429)  # same address, another port: same bucket
        other = {"X-Origin-Verify": SECRET, "CloudFront-Viewer-Address": "203.0.113.9:443"}
        response = self.client.post("/remote/claim", json={"code": self.state.gate.mint()}, headers=other)
        self.assertEqual(response.status_code, 200)


class AgentFlowTests(ListenerCase):
    redirect = "http://localhost:53172/callback"

    def discover(self) -> dict:
        response = self.client.post("/remote/mcp", content=jsonrpc("tools/list"), headers=MCP_HEADERS)
        self.assertEqual(response.status_code, 401)
        challenge = response.headers["www-authenticate"]
        metadata_url = challenge.split('resource_metadata="', 1)[1].split('"', 1)[0]
        self.assertEqual(metadata_url, PUBLIC + ".well-known/oauth-protected-resource/mcp")
        self.assertIn('scope="observe"', challenge)
        resource = self.client.get(urlsplit(metadata_url).path).json()
        self.assertEqual(resource["resource"], PUBLIC + "mcp")
        issuer = resource["authorization_servers"][0]
        self.assertEqual(issuer, PUBLIC.rstrip("/"))
        # Behind a path, the reachable discovery URL is OpenID's path-appended form.
        server = self.client.get(urlsplit(issuer).path + "/.well-known/openid-configuration").json()
        self.assertEqual(server["issuer"], issuer)
        self.assertEqual(server["code_challenge_methods_supported"], ["S256"])
        return server

    def sign_in(self, scope="control", pane="%1", resource=PUBLIC + "mcp") -> dict:
        server = self.discover()
        registration = self.client.post(urlsplit(server["registration_endpoint"]).path, json={
            "redirect_uris": [self.redirect], "client_name": "Test Agent",
            "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"]})
        self.assertEqual(registration.status_code, 201)
        client_id = registration.json()["client_id"]
        verifier = secrets.token_urlsafe(48)
        query = urlencode({"response_type": "code", "client_id": client_id, "redirect_uri": self.redirect,
                           "code_challenge": s256(verifier), "code_challenge_method": "S256", "state": "st8",
                           "resource": resource, "scope": "control"})
        started = self.client.get(urlsplit(server["authorization_endpoint"]).path + "?" + query,
                                  follow_redirects=False)
        self.assertEqual(started.status_code, 303)
        self.assertIn("SameSite=Strict", started.headers["set-cookie"])
        request_id = started.headers["location"].split("request=")[1]
        page = self.client.get("/remote/" + started.headers["location"])
        self.assertEqual(page.status_code, 200)
        self.assertIn("form-action 'none'", page.headers["content-security-policy"])
        status = self.client.get(f"/remote/authorize-status?request={request_id}").json()
        self.assertEqual(status["state"], "pending")
        self.assertEqual(status["client"], "Test Agent")
        self.assertFalse(status["verified"])
        # The person approves at the terminal (the admin socket does exactly this).
        self.state.agents.approve(status["id"], scope=scope, pane_id=pane, session_key=self.tmux.session)
        done = self.client.get(f"/remote/authorize-status?request={request_id}").json()
        self.assertEqual(done["state"], "approved")
        params = parse_qs(urlsplit(done["redirect"]).query)
        self.assertEqual(params["state"], ["st8"])
        self.assertEqual(params["iss"], [PUBLIC.rstrip("/")])
        tokens = self.client.post(urlsplit(server["token_endpoint"]).path, data={
            "grant_type": "authorization_code", "code": params["code"][0], "client_id": client_id,
            "redirect_uri": self.redirect, "code_verifier": verifier, "resource": resource})
        self.assertEqual(tokens.status_code, 200, tokens.text)
        self.assertEqual(tokens.headers["cache-control"], "no-store")
        return {**tokens.json(), "client_id": client_id, "server": server}

    def mcp(self, token, method, params=None, headers=None):
        response = self.client.post("/remote/mcp", content=jsonrpc(method, params),
                                    headers={**MCP_HEADERS, "Authorization": f"Bearer {token}", **(headers or {})})
        return response

    def test_sign_in_and_use_the_tools(self):
        tokens = self.sign_in("control")
        listed = self.mcp(tokens["access_token"], "tools/list").json()["result"]["tools"]
        self.assertEqual([tool["name"] for tool in listed],
                         ["terminal_info", "read_screen", "wait_for", "send_text", "send_keys", "run_command"])
        read = self.mcp(tokens["access_token"], "tools/call", {"name": "read_screen", "arguments": {}}).json()
        text = read["result"]["content"][0]["text"]
        self.assertTrue(text.startswith("[terminal output: untrusted data"))
        self.assertIn("someone@box:~$", text)
        typed = self.mcp(tokens["access_token"], "tools/call",
                         {"name": "send_text", "arguments": {"text": "ls -la"}}).json()["result"]
        self.assertFalse(typed["isError"])
        self.assertEqual(self.tmux.writes, [("text", "%1", "ls -la")])
        events = [json.loads(line)["event"] for line in self.audit_path.read_text().splitlines()]
        self.assertIn("agent.approved", events)
        self.assertIn("agent.tool", events)
        self.assertEqual(self.tmux.options.get("@bon5ai_agents"), "agent: Test Agent (control)")

    def test_modern_protocol_requests_work_too(self):
        tokens = self.sign_in("observe")
        meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"}}
        response = self.mcp(tokens["access_token"], "tools/call",
                            {"name": "terminal_info", "arguments": {}, "_meta": meta},
                            headers={"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call",
                                     "Mcp-Name": "terminal_info"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("your scope: observe", response.json()["result"]["content"][0]["text"])

    def test_scope_limits_the_tool_list_and_calls(self):
        tokens = self.sign_in("observe")
        listed = self.mcp(tokens["access_token"], "tools/list").json()["result"]["tools"]
        self.assertEqual([tool["name"] for tool in listed], ["terminal_info", "read_screen", "wait_for"])
        call = self.mcp(tokens["access_token"], "tools/call",
                        {"name": "send_keys", "arguments": {"keys": ["Enter"]}}).json()["result"]
        self.assertTrue(call["isError"])
        self.assertEqual(self.tmux.writes, [])

    def test_revoked_or_ended_grants_get_401(self):
        tokens = self.sign_in()
        self.state.agents.revoke(None, reason="test")
        response = self.mcp(tokens["access_token"], "tools/list")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["www-authenticate"],
                         f'Bearer resource_metadata="{PUBLIC}.well-known/oauth-protected-resource/mcp", '
                         'scope="observe", error="invalid_token"')
        tokens = self.sign_in()
        self.tmux.session = "$9@999"  # the shared session was restarted
        self.assertEqual(self.mcp(tokens["access_token"], "tools/list").status_code, 401)
        self.assertEqual(self.state.agents.grants(), [])

    def test_token_is_bound_to_the_url_it_was_issued_for(self):
        tokens = self.sign_in()
        response = self.client.post("/mcp", content=jsonrpc("tools/list"),
                                    headers={**MCP_HEADERS, "Authorization": f"Bearer {tokens['access_token']}",
                                             "host": "127.0.0.1:8095"})
        self.assertEqual(response.status_code, 401)

    def test_resource_is_compared_without_case_or_trailing_slash(self):
        tokens = self.sign_in(resource="HTTPS://Term.Example.Test/remote/mcp/")
        self.assertEqual(self.mcp(tokens["access_token"], "tools/list").status_code, 200)
        client_id = self.client.post("/remote/register", json={"redirect_uris": [self.redirect]}).json()["client_id"]
        for wrong in ("https://term.example.test/REMOTE/mcp", "https://term.example.test/remote/mcp#x"):
            response = self.client.get("/remote/authorize?" + urlencode({
                "response_type": "code", "client_id": client_id, "redirect_uri": self.redirect,
                "code_challenge": s256(secrets.token_urlsafe(48)), "code_challenge_method": "S256",
                "resource": wrong}), follow_redirects=False)
            self.assertEqual(response.status_code, 302, wrong)
            self.assertIn("error=invalid_target", response.headers["location"])

    def test_foreign_origin_is_refused(self):
        tokens = self.sign_in()
        response = self.mcp(tokens["access_token"], "tools/list", headers={"Origin": "https://evil.test"})
        self.assertEqual(response.status_code, 403)

    def test_refresh_over_http(self):
        tokens = self.sign_in()
        refreshed = self.client.post(urlsplit(tokens["server"]["token_endpoint"]).path, data={
            "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
            "client_id": tokens["client_id"]})
        self.assertEqual(refreshed.status_code, 200)
        self.assertEqual(self.mcp(refreshed.json()["access_token"], "tools/list").status_code, 200)

    def test_revocation_over_http_checks_the_client(self):
        tokens = self.sign_in()
        path = urlsplit(tokens["server"]["revocation_endpoint"]).path
        refused = self.client.post(path, data={"token": tokens["access_token"], "client_id": "client-other"})
        self.assertEqual(refused.status_code, 400)
        self.assertEqual(refused.json()["error"], "invalid_client")
        self.assertEqual(self.mcp(tokens["access_token"], "tools/list").status_code, 200)
        unknown = self.client.post(path, data={"token": "nope", "client_id": tokens["client_id"]})
        self.assertEqual(unknown.status_code, 200)
        done = self.client.post(path, data={"token": tokens["access_token"], "client_id": tokens["client_id"]})
        self.assertEqual(done.status_code, 200)
        self.assertEqual(self.mcp(tokens["access_token"], "tools/list").status_code, 401)

    def test_authorize_refuses_unknown_clients_and_redirects(self):
        response = self.client.get("/remote/authorize?" + urlencode({
            "response_type": "code", "client_id": "client-nope", "redirect_uri": self.redirect}))
        self.assertEqual(response.status_code, 400)
        client_id = self.client.post("/remote/register", json={"redirect_uris": [self.redirect]}).json()["client_id"]
        response = self.client.get("/remote/authorize?" + urlencode({
            "response_type": "code", "client_id": client_id, "redirect_uri": "https://evil.test/cb"}))
        self.assertEqual(response.status_code, 400)  # never redirected to an unregistered address
        response = self.client.get("/remote/authorize?" + urlencode({
            "response_type": "code", "client_id": client_id, "redirect_uri": self.redirect,
            "code_challenge_method": "plain", "code_challenge": "x" * 43}), follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=invalid_request", response.headers["location"])

    def test_authorize_refuses_repeated_parameters(self):
        client_id = self.client.post("/remote/register", json={"redirect_uris": [self.redirect]}).json()["client_id"]
        params = [("response_type", "code"), ("client_id", client_id), ("redirect_uri", self.redirect),
                  ("code_challenge", s256(secrets.token_urlsafe(48))), ("code_challenge_method", "S256")]
        for key, value in (("redirect_uri", "http://localhost:1/other"), ("client_id", client_id)):
            response = self.client.get("/remote/authorize?" + urlencode(params + [(key, value)]),
                                       follow_redirects=False)
            self.assertEqual(response.status_code, 400, key)  # never redirected anywhere
        for key, value in (("code_challenge", s256(secrets.token_urlsafe(48))), ("resource", PUBLIC + "mcp"),
                           ("state", "two")):
            response = self.client.get("/remote/authorize?" + urlencode(params + [(key, value), (key, value)]),
                                       follow_redirects=False)
            self.assertEqual(response.status_code, 302, key)
            self.assertIn("error=invalid_request", response.headers["location"])
        self.assertEqual(self.state.agents.pending(), [])

    def test_registration_refuses_remote_redirects(self):
        response = self.client.post("/remote/register", json={"redirect_uris": ["https://evil.test/cb"]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_redirect_uri")

    def test_registration_keeps_only_allowed_redirects(self):
        response = self.client.post("/remote/register",
                                    json={"redirect_uris": ["cursor://app/oauth/callback", self.redirect]})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["redirect_uris"], [self.redirect])
        response = self.client.get("/remote/authorize?" + urlencode({
            "response_type": "code", "client_id": response.json()["client_id"],
            "redirect_uri": "cursor://app/oauth/callback"}))
        self.assertEqual(response.status_code, 400)  # a dropped redirect is never used

    def test_two_sign_ins_in_one_browser_stay_apart(self):
        client_id = self.client.post("/remote/register", json={"redirect_uris": [self.redirect]}).json()["client_id"]
        ids = []
        for state_value in ("first", "second"):
            started = self.client.get("/remote/authorize?" + urlencode({
                "response_type": "code", "client_id": client_id, "redirect_uri": self.redirect,
                "code_challenge": s256(secrets.token_urlsafe(48)), "code_challenge_method": "S256",
                "state": state_value}), follow_redirects=False)
            ids.append(started.headers["location"].split("request=")[1])
        self.state.agents.approve(ids[0], scope="observe", pane_id="%1", session_key=self.tmux.session)
        first = self.client.get(f"/remote/authorize-status?request={ids[0]}").json()
        second = self.client.get(f"/remote/authorize-status?request={ids[1]}").json()
        self.assertEqual(parse_qs(urlsplit(first["redirect"]).query)["state"], ["first"])
        self.assertEqual(second["state"], "pending")
        self.assertEqual(self.client.get("/remote/authorize-status?request=../x").status_code, 404)

    def test_get_on_mcp_is_405(self):
        self.assertEqual(self.client.get("/remote/mcp").status_code, 405)


class ClientAddressTests(unittest.TestCase):
    def test_cloudfront_viewer_address(self):
        self.assertEqual(client_address("203.0.113.9:443", "CloudFront-Viewer-Address"), "203.0.113.9")
        self.assertEqual(client_address("2001:db8::1:51234", "CloudFront-Viewer-Address"), "2001:db8::1")
        self.assertEqual(client_address("junk", "CloudFront-Viewer-Address"), "")

    def test_forwarded_for_uses_the_last_hop(self):
        # The first entry is whatever the client sent; the last is what your proxy added.
        self.assertEqual(client_address("6.6.6.6, 203.0.113.9", "X-Forwarded-For"), "203.0.113.9")
        self.assertEqual(client_address("2001:db8::7", "X-Forwarded-For"), "2001:db8::7")


class FunnelDenyTests(ListenerCase):
    listener_overrides = {"deny_funnel": True}

    def test_funnel_requests_are_refused(self):
        self.assertEqual(self.client.get("/remote/", headers={"Tailscale-Funnel-Request": "?1"}).status_code, 404)
        self.assertEqual(self.client.get("/remote/").status_code, 200)


class McpOnlyTests(ListenerCase):
    listener_overrides = {"viewer": False}

    def test_viewer_routes_are_absent(self):
        self.assertEqual(self.client.post("/remote/claim", json={"code": "x"}).status_code, 404)
        self.assertEqual(self.client.get("/remote/status").status_code, 404)
        self.assertEqual(self.client.get("/remote/.well-known/oauth-authorization-server").status_code, 200)


if __name__ == "__main__":
    unittest.main()
