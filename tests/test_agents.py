"""Agent grants: registration, approval at the terminal, codes, tokens and their lifecycle."""

import secrets
import unittest
from urllib.parse import parse_qs, urlsplit

from bon5ai_remote import agents, cimd
from bon5ai_remote.agents import AgentAuth, OAuthError, s256
from helpers import Clock

RESOURCE = "https://term.example.test/mcp"
ISSUER = "https://term.example.test"
REDIRECT = "http://localhost:53172/callback"


class Flow:
    """One client's way through the authorization flow."""

    def __init__(self, auth: AgentAuth, redirect=REDIRECT):
        self.auth = auth
        self.client = auth.register({"redirect_uris": [redirect], "client_name": "Claude Code"})
        self.verifier = secrets.token_urlsafe(48)
        self.redirect = redirect

    def start(self, **overrides):
        values = dict(client=self.client, redirect_uri=self.redirect, challenge=s256(self.verifier),
                      state="xyz", resource=RESOURCE, issuer=ISSUER)
        values.update(overrides)
        self.pending, self.secret = self.auth.start(**values)
        return self.pending

    def approve(self, scope="control"):
        return self.auth.approve(self.pending.id, scope=scope, pane_id="%1", session_key="$1@100")

    def code(self) -> str:
        result = self.auth.poll(self.secret, self.pending.id)
        params = parse_qs(urlsplit(result["redirect"]).query)
        return params["code"][0]

    def tokens(self, **overrides):
        values = dict(code=self.code(), client_id=self.client.id, redirect_uri=self.redirect,
                      verifier=self.verifier, resource=RESOURCE)
        values.update(overrides)
        return self.auth.exchange_code(**values)


class AgentAuthTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.events = []
        self.auth = AgentAuth(agent_ttl=3600, access_ttl=600, clock=self.clock,
                              on_event=lambda kind, **fields: self.events.append((kind, fields)))

    def test_full_flow(self):
        flow = Flow(self.auth)
        flow.start()
        self.assertEqual([item["id"] for item in self.auth.pending()], [flow.pending.id])
        self.assertEqual(self.auth.poll(flow.secret, flow.pending.id)["state"], "pending")
        grant = flow.approve("suggest")
        redirect = self.auth.poll(flow.secret, flow.pending.id)["redirect"]
        params = parse_qs(urlsplit(redirect).query)
        self.assertTrue(redirect.startswith(REDIRECT + "?"))
        self.assertEqual(params["state"], ["xyz"])
        self.assertEqual(params["iss"], [ISSUER])
        self.assertNotIn("redirect", self.auth.poll(flow.secret, flow.pending.id))  # handed out once
        tokens = self.auth.exchange_code(code=params["code"][0], client_id=flow.client.id, redirect_uri=REDIRECT,
                                         verifier=flow.verifier, resource=RESOURCE)
        self.assertEqual(tokens["scope"], "suggest")
        self.assertEqual(tokens["token_type"], "Bearer")
        self.assertIs(self.auth.authenticate(tokens["access_token"], RESOURCE), grant)

    def test_scope_is_the_persons_choice(self):
        flow = Flow(self.auth)
        flow.start()
        flow.approve("observe")
        self.assertEqual(flow.tokens()["scope"], "observe")

    def test_pkce_is_required_and_checked(self):
        flow = Flow(self.auth)
        with self.assertRaises(OAuthError):
            flow.start(challenge="")
        flow.start()
        flow.approve()
        with self.assertRaisesRegex(OAuthError, "PKCE"):
            flow.tokens(verifier=secrets.token_urlsafe(48))

    def test_code_is_single_use_and_replay_revokes_the_grant(self):
        flow = Flow(self.auth)
        flow.start()
        grant = flow.approve()
        code = flow.code()
        tokens = self.auth.exchange_code(code=code, client_id=flow.client.id, redirect_uri=REDIRECT,
                                         verifier=flow.verifier, resource=RESOURCE)
        with self.assertRaises(OAuthError):
            self.auth.exchange_code(code=code, client_id=flow.client.id, redirect_uri=REDIRECT,
                                    verifier=flow.verifier, resource=RESOURCE)
        self.assertIsNone(self.auth.authenticate(tokens["access_token"], RESOURCE))
        self.assertIsNone(self.auth.grant(grant.id))
        self.assertIn("revoked", [kind for kind, _ in self.events])

    def test_code_expires_and_is_bound_to_client_and_redirect(self):
        flow = Flow(self.auth)
        flow.start()
        flow.approve()
        code = flow.code()
        other = Flow(self.auth)
        with self.assertRaisesRegex(OAuthError, "another client"):
            self.auth.exchange_code(code=code, client_id=other.client.id, redirect_uri=REDIRECT,
                                    verifier=flow.verifier, resource=RESOURCE)
        flow2 = Flow(self.auth)
        flow2.start()
        flow2.approve()
        code2 = flow2.code()
        self.clock.now += agents.AUTH_CODE_TTL + 1
        with self.assertRaises(OAuthError):
            self.auth.exchange_code(code=code2, client_id=flow2.client.id, redirect_uri=REDIRECT,
                                    verifier=flow2.verifier, resource=RESOURCE)

    def test_audience_is_bound(self):
        flow = Flow(self.auth)
        flow.start()
        flow.approve()
        with self.assertRaises(OAuthError):
            flow.tokens(resource="https://elsewhere.test/mcp")
        flow = Flow(self.auth)
        flow.start()
        flow.approve()
        tokens = flow.tokens()
        self.assertIsNone(self.auth.authenticate(tokens["access_token"], "https://elsewhere.test/mcp"))

    def test_resource_comparison_is_canonical(self):
        for same in ("HTTPS://Term.Example.Test/mcp", "https://term.example.test/mcp/",
                     "https://term.example.test:443/mcp"):
            self.assertTrue(agents.same_resource(same, RESOURCE), same)
        for other in ("https://term.example.test/MCP", "https://term.example.test/mcp#x", "term.example.test/mcp",
                      "https://term.example.test:8443/mcp", "http://term.example.test/mcp",
                      "https://u@term.example.test/mcp", "", None):
            self.assertFalse(agents.same_resource(other, RESOURCE), other)
        self.assertEqual(agents.canonical_resource("http://[::1]:8095/mcp"), "http://[::1]:8095/mcp")

    def test_token_request_resource_may_differ_only_in_case_and_slash(self):
        flow = Flow(self.auth)
        flow.start()
        flow.approve()
        tokens = flow.tokens(resource="HTTPS://TERM.EXAMPLE.TEST/mcp/")
        self.assertIsNotNone(self.auth.authenticate(tokens["access_token"], RESOURCE))
        refreshed = self.auth.refresh(token=tokens["refresh_token"], client_id=flow.client.id,
                                      resource="https://Term.Example.Test/mcp")
        self.assertIn("access_token", refreshed)
        with self.assertRaises(OAuthError) as caught:
            self.auth.refresh(token=refreshed["refresh_token"], client_id=flow.client.id,
                              resource="https://term.example.test/other")
        self.assertEqual(caught.exception.error, "invalid_target")

    def test_refresh_rotates_and_detects_reuse(self):
        flow = Flow(self.auth)
        flow.start()
        flow.approve()
        first = flow.tokens()
        second = self.auth.refresh(token=first["refresh_token"], client_id=flow.client.id, resource=RESOURCE)
        # A retry within the grace window gets the same successor, not a second chain.
        retry = self.auth.refresh(token=first["refresh_token"], client_id=flow.client.id, resource=RESOURCE)
        self.assertEqual(retry, second)
        self.clock.now += agents.REFRESH_GRACE + 1
        with self.assertRaisesRegex(OAuthError, "already used"):
            self.auth.refresh(token=first["refresh_token"], client_id=flow.client.id, resource=RESOURCE)
        # Reuse after the window means theft: the whole grant is gone.
        self.assertIsNone(self.auth.authenticate(second["access_token"], RESOURCE))
        with self.assertRaises(OAuthError):
            self.auth.refresh(token=second["refresh_token"], client_id=flow.client.id, resource=RESOURCE)

    def test_tokens_per_grant_are_bounded(self):
        flow = Flow(self.auth)
        flow.start()
        grant = flow.approve()
        tokens = flow.tokens()
        for _ in range(200):
            tokens = self.auth.refresh(token=tokens["refresh_token"], client_id=flow.client.id, resource=RESOURCE)
        self.assertLessEqual(len(self.auth._access), agents.MAX_TOKENS_PER_GRANT)
        self.assertLessEqual(len(self.auth._refresh), agents.MAX_TOKENS_PER_GRANT)
        self.assertIs(self.auth.authenticate(tokens["access_token"], RESOURCE), grant)

    def test_refresh_needs_the_same_client(self):
        flow = Flow(self.auth)
        flow.start()
        flow.approve()
        tokens = flow.tokens()
        with self.assertRaises(OAuthError):
            self.auth.refresh(token=tokens["refresh_token"], client_id="client-someone-else", resource=None)

    def test_access_token_never_outlives_the_grant(self):
        auth = AgentAuth(agent_ttl=3600, access_ttl=86400, clock=self.clock)
        flow = Flow(auth)
        flow.start()
        flow.auth.approve(flow.pending.id, scope="observe", pane_id="%1", session_key="s", ttl=300)
        self.assertLessEqual(flow.tokens()["expires_in"], 300)

    def test_grant_expires(self):
        flow = Flow(self.auth)
        flow.start()
        flow.approve()
        tokens = flow.tokens()
        self.clock.now += 3601
        self.assertIsNone(self.auth.authenticate(tokens["access_token"], RESOURCE))
        self.assertEqual(self.auth.grants(), [])

    def test_revoke_one_and_all(self):
        grants = []
        for _ in range(3):
            flow = Flow(self.auth)
            flow.start()
            grants.append(flow.approve())
        self.assertEqual([grant.id for grant in self.auth.revoke(grants[0].id, reason="test")], [grants[0].id])
        self.assertEqual(len(self.auth.revoke(None, reason="test")), 2)
        self.assertEqual(self.auth.grants(), [])

    def test_revocation_endpoint_ends_the_grant(self):
        flow = Flow(self.auth)
        flow.start()
        flow.approve()
        tokens = flow.tokens()
        self.auth.revoke_token(tokens["refresh_token"], flow.client.id)
        self.assertIsNone(self.auth.authenticate(tokens["access_token"], RESOURCE))
        self.auth.revoke_token(tokens["refresh_token"], flow.client.id)  # already gone: not an error

    def test_only_the_client_a_token_was_issued_to_can_revoke_it(self):
        flow = Flow(self.auth)
        flow.start()
        flow.approve()
        tokens = flow.tokens()
        other = self.auth.register({"redirect_uris": [REDIRECT]})
        for client_id in (other.id, None):
            with self.assertRaises(OAuthError) as caught:
                self.auth.revoke_token(tokens["access_token"], client_id)
            self.assertEqual(caught.exception.error, "invalid_client")
        self.assertIsNotNone(self.auth.authenticate(tokens["access_token"], RESOURCE))
        _, direct = self.auth.mint_direct(scope="observe", pane_id="%1", session_key="$1@100",
                                          resources=frozenset({RESOURCE}), label="nightly")
        self.auth.revoke_token(direct, None)  # a token file has no OAuth client; its holder may end it
        self.assertIsNone(self.auth.authenticate(direct, RESOURCE))

    def test_deny_and_expiry_send_the_browser_back_with_an_error(self):
        flow = Flow(self.auth)
        flow.start()
        self.auth.deny(flow.pending.id)
        result = self.auth.poll(flow.secret, flow.pending.id)
        self.assertEqual(result["state"], "denied")
        self.assertIn("error=access_denied", result["redirect"])
        flow = Flow(self.auth)
        flow.start()
        self.clock.now += agents.PENDING_TTL + 1
        result = self.auth.poll(flow.secret, flow.pending.id)
        self.assertEqual(result["state"], "expired")
        self.assertIn("error=access_denied", result["redirect"])
        with self.assertRaises(agents.NotFound):
            self.auth.approve(flow.pending.id, scope="observe", pane_id="%1", session_key="s")

    def test_pending_requests_are_capped(self):
        for n in range(agents.MAX_PENDING_PER_CLIENT):
            Flow(self.auth).start(client_ip="198.51.100.7")
        with self.assertRaises(agents.Busy):
            Flow(self.auth).start(client_ip="198.51.100.7")
        for n in range(agents.MAX_PENDING - agents.MAX_PENDING_PER_CLIENT):
            Flow(self.auth).start(client_ip=f"203.0.113.{n}")
        with self.assertRaises(agents.Busy):
            Flow(self.auth).start(client_ip="192.0.2.1")

    def test_wrong_browser_secret_sees_nothing(self):
        flow = Flow(self.auth)
        flow.start()
        flow.approve()
        self.assertIsNone(self.auth.poll("not-the-secret", flow.pending.id))
        self.assertIsNone(self.auth.poll("", flow.pending.id))
        other = Flow(self.auth)
        other.start()
        self.assertIsNone(self.auth.poll(flow.secret, other.pending.id))  # a secret opens only its own request

    def test_rate_limit(self):
        flow = Flow(self.auth)
        flow.start()
        grant = flow.approve()
        for _ in range(agents.WRITE_LIMIT):
            self.assertTrue(self.auth.allow_write(grant))
        self.assertFalse(self.auth.allow_write(grant))
        self.clock.now += agents.WRITE_WINDOW + 1
        self.assertTrue(self.auth.allow_write(grant))


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.auth = AgentAuth(agent_ttl=3600, access_ttl=600, clock=self.clock,
                              allowed_redirect_uris=["https://chat.example.test/oauth/callback"])

    def test_only_loopback_or_allowlisted_redirects(self):
        for uri in ("https://evil.test/cb", "http://localhost.evil.test/cb", "http://127.0.0.1@evil.test/cb",
                    "http://localhost:99999/cb", "https://chat.example.test/oauth/callback/extra"):
            with self.assertRaises(OAuthError, msg=uri):
                self.auth.register({"redirect_uris": [uri]})
        for uri in ("http://localhost:1234/callback", "http://127.0.0.1/cb", "http://[::1]:8/cb",
                    "https://chat.example.test/oauth/callback"):
            self.auth.register({"redirect_uris": [uri]})

    def test_redirects_it_cannot_allow_are_dropped(self):
        # Grok Bot's registration: an app scheme, an https callback and a loopback one.
        client = self.auth.register({"redirect_uris": [
            "cursor://anysphere.cursor-mcp/oauth/callback", "https://chat.example.test/oauth/callback",
            "http://localhost:8787/callback"]})
        self.assertEqual(client.redirect_uris,
                         ("https://chat.example.test/oauth/callback", "http://localhost:8787/callback"))
        self.assertFalse(self.auth.check_redirect(client, "cursor://anysphere.cursor-mcp/oauth/callback"))
        self.assertTrue(self.auth.check_redirect(client, "https://chat.example.test/oauth/callback"))
        with self.assertRaises(OAuthError):  # nothing left to keep
            self.auth.register({"redirect_uris": ["cursor://anysphere.cursor-mcp/oauth/callback",
                                                  "https://evil.test/cb"]})

    def test_loopback_redirect_may_change_port(self):
        client = self.auth.register({"redirect_uris": ["http://localhost:1000/callback"]})
        self.assertTrue(self.auth.check_redirect(client, "http://localhost:2000/callback"))
        self.assertFalse(self.auth.check_redirect(client, "http://localhost:2000/other"))
        self.assertFalse(self.auth.check_redirect(client, "http://127.0.0.1:1000/callback"))

    def test_public_clients_only(self):
        with self.assertRaises(OAuthError):
            self.auth.register({"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "client_secret_basic"})

    def test_names_are_cleaned(self):
        client = self.auth.register({"redirect_uris": [REDIRECT],
                                     "client_name": "Claude‮ edoC​\nCode " + "x" * 200})
        self.assertNotIn("‮", client.name)
        self.assertNotIn("​", client.name)
        self.assertNotIn("\n", client.name)
        self.assertLessEqual(len(client.name), agents.MAX_NAME_LENGTH)

    def test_registrations_are_bounded_without_ever_locking(self):
        first = self.auth.register({"redirect_uris": [REDIRECT]})
        flow = Flow(self.auth)  # a client with a sign-in in progress is never evicted
        flow.start()
        for _ in range(agents.MAX_CLIENTS * 3):
            self.clock.now += 1
            self.auth.register({"redirect_uris": [REDIRECT]})
        self.assertLessEqual(len(self.auth._clients), agents.MAX_CLIENTS)
        self.assertIsNone(self.auth.client(first.id))  # the least recently used idle one went
        self.assertIsNotNone(self.auth.client(flow.client.id))

    def test_registration_refuses_only_when_every_client_is_in_use(self):
        for _ in range(agents.MAX_CLIENTS):
            flow = Flow(self.auth)
            flow.start()
            flow.approve()  # every registered client now holds a live grant
        with self.assertRaisesRegex(OAuthError, "Too many"):
            self.auth.register({"redirect_uris": [REDIRECT]})
        self.auth.revoke(None, reason="test")
        self.auth.register({"redirect_uris": [REDIRECT]})  # revoked clients can make room again

    def test_clients_are_forgotten_after_a_week_unused(self):
        client = self.auth.register({"redirect_uris": [REDIRECT]})
        self.clock.now += agents.CLIENT_IDLE_TTL + 1
        self.auth.register({"redirect_uris": [REDIRECT]})  # prunes
        self.assertIsNone(self.auth.client(client.id))

    def test_metadata_document_clients(self):
        url = "https://agent.example.test/oauth/client.json"
        document = {"client_id": url, "client_name": "Example Agent", "redirect_uris": [REDIRECT, "https://x.test/"]}
        auth = AgentAuth(agent_ttl=3600, access_ttl=600, clock=self.clock, fetch_metadata=lambda u: document)
        client = auth.client(url)
        self.assertTrue(client.verified)
        self.assertEqual(client.host, "agent.example.test")
        self.assertEqual(client.redirect_uris, (REDIRECT,))  # the non-loopback one isn't allowed here
        document["client_id"] = "https://someone-else.test/client.json"
        auth = AgentAuth(agent_ttl=3600, access_ttl=600, clock=self.clock, fetch_metadata=lambda u: document)
        self.assertIsNone(auth.client(url))  # a document must name itself

    def test_metadata_documents_with_a_client_secret_are_refused(self):
        url = "https://agent.example.test/oauth/client.json"
        for extra in ({"client_secret": "s3cret"}, {"client_secret_expires_at": 0}):
            document = {"client_id": url, "client_name": "Example Agent", "redirect_uris": [REDIRECT], **extra}
            auth = AgentAuth(agent_ttl=3600, access_ttl=600, clock=self.clock, fetch_metadata=lambda u: document)
            self.assertIsNone(auth.client(url), extra)

    def test_unreachable_metadata_urls_are_not_refetched_for_a_moment(self):
        calls = []

        def fetch(url):
            calls.append(url)
            raise OSError("down")
        auth = AgentAuth(agent_ttl=3600, access_ttl=600, clock=self.clock, fetch_metadata=fetch)
        for _ in range(3):
            self.assertIsNone(auth.client("https://slow.example.test/a.json"))
        self.assertEqual(len(calls), 1)  # the same URL is remembered
        auth.client("https://slow.example.test/b.json")
        self.assertEqual(len(calls), 2)  # but not the whole host
        self.clock.now += agents.METADATA_FAILURE_TTL + 1
        auth.client("https://slow.example.test/a.json")
        self.assertEqual(len(calls), 3)

    def test_a_bad_url_cannot_lock_out_its_host(self):
        good = "https://agent.example.test/oauth/client.json"
        calls = []

        def fetch(url):
            calls.append(url)
            if url != good:
                raise cimd.MetadataError("client metadata answered 404")
            return {"client_id": good, "client_name": "Example Agent", "redirect_uris": [REDIRECT]}
        auth = AgentAuth(agent_ttl=3600, access_ttl=600, clock=self.clock, fetch_metadata=fetch)
        self.assertIsNone(auth.client("https://agent.example.test/nonexistent"))
        self.assertIsNotNone(auth.client(good))  # a stranger's 404 on the same host changes nothing
        self.assertIsNone(auth.client("https://agent.example.test/nonexistent"))
        self.assertEqual(calls.count("https://agent.example.test/nonexistent"), 2)  # error answers aren't cached

    def test_invalid_documents_are_not_cached(self):
        url = "https://agent.example.test/oauth/client.json"
        document = {"client_id": "https://someone-else.test/client.json", "redirect_uris": [REDIRECT]}
        calls = []

        def fetch(u):
            calls.append(u)
            return dict(document)
        auth = AgentAuth(agent_ttl=3600, access_ttl=600, clock=self.clock, fetch_metadata=fetch)
        self.assertIsNone(auth.client(url))
        document["client_id"] = url  # the client fixes its document
        self.assertIsNotNone(auth.client(url))
        self.assertEqual(len(calls), 2)

    def test_unknown_clients(self):
        self.assertIsNone(self.auth.client("client-nope"))
        self.assertIsNone(self.auth.client("https://agent.example.test/client.json"))  # CIMD off


if __name__ == "__main__":
    unittest.main()
