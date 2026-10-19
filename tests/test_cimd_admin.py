"""The metadata-document fetch's fences, and the admin socket."""

import ipaddress
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from bon5ai_remote import cimd
from bon5ai_remote.admin import call, start_admin
from helpers import FakeTmux, make_config, make_state


def resolver(*addresses):
    def resolve(host, port, type=None):
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
                for a in addresses]
    return resolve


class FakeResponse:
    def __init__(self, status=200, body=b"{}", content_type="application/json"):
        self.status = status
        self._body = body
        self._type = content_type

    def getheader(self, name):
        return self._type if name.lower() == "content-type" else None

    def read(self, limit):
        return self._body[:limit]


def connection(response, seen):
    class Connection:
        def __init__(self, host, address, port, context, timeout):
            seen.update(host=host, address=address, port=port)

        def request(self, method, target, headers):
            seen["target"] = target

        def getresponse(self):
            return response

        def close(self):
            pass
    return Connection


class MetadataFetchTests(unittest.TestCase):
    URL = "https://agent.example.test/oauth/client.json"

    def test_url_rules(self):
        for url in ("http://agent.example.test/c.json", "https://agent.example.test/", "https://u:p@x.test/c",
                    "https://x.test/c#frag", "https:///c"):
            with self.assertRaises(cimd.MetadataError, msg=url):
                cimd.check_url(url)

    def test_private_addresses_are_refused(self):
        for address in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "fd00::1", "100.100.100.100"):
            with self.assertRaises(cimd.MetadataError, msg=address):
                cimd.fetch(self.URL, resolve=resolver("93.184.215.14", address),
                           connection_class=connection(FakeResponse(), {}))

    def test_ipv6_that_embeds_a_private_ipv4_is_refused(self):
        for address in ("::ffff:127.0.0.1", "64:ff9b::a00:5", "64:ff9b::a9fe:a9fe", "2002:0a00:0005::1",
                        "::10.0.0.5", "::", "2001:0:4136:e378:8000:63bf:f5ff:fffe"):
            self.assertFalse(cimd.is_public(ipaddress.ip_address(address)), address)
        for address in ("93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c", "64:ff9b::5db8:d70e"):
            self.assertTrue(cimd.is_public(ipaddress.ip_address(address)), address)

    def test_a_slow_server_is_cut_off_at_the_deadline(self):
        class Raw:
            def __init__(self):
                self.closed = threading.Event()

            def shutdown(self, how):
                self.closed.set()

        class Dripping:
            def __init__(self, host, address, port, context, timeout):
                self.raw_socket = Raw()

            def request(self, method, target, headers):
                pass

            def getresponse(self):
                self.raw_socket.closed.wait(10)  # blocks like a read until the watchdog shuts the socket
                return FakeResponse(body=b'{"partial": true}')

            def close(self):
                pass

        started = time.monotonic()
        with self.assertRaisesRegex(cimd.MetadataError, "too long"):
            cimd.fetch(self.URL, resolve=resolver("93.184.215.14"), connection_class=Dripping, deadline=0.3)
        self.assertLess(time.monotonic() - started, 2)

    def test_connects_to_the_checked_address(self):
        seen = {}
        document = cimd.fetch(self.URL, resolve=resolver("93.184.215.14"),
                              connection_class=connection(FakeResponse(body=b'{"client_id": "x"}'), seen))
        self.assertEqual(document, {"client_id": "x"})
        self.assertEqual(seen, {"host": "agent.example.test", "address": "93.184.215.14", "port": 443,
                                "target": "/oauth/client.json"})

    def test_response_rules(self):
        for response in (FakeResponse(status=302), FakeResponse(content_type="text/html"),
                         FakeResponse(body=b"x" * (cimd.MAX_BYTES + 10)), FakeResponse(body=b"[1]"),
                         FakeResponse(body=b"not json")):
            with self.assertRaises(cimd.MetadataError):
                cimd.fetch(self.URL, resolve=resolver("93.184.215.14"), connection_class=connection(response, {}))


class AdminSocketTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.tmux = FakeTmux()
        self.state = make_state(make_config(self.dir), self.tmux)
        self.path = self.dir / "admin.sock"
        self.server = start_admin(self.path, self.state)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def test_socket_is_private_and_mints(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        status, body = call(self.path, "POST", "/pair")
        self.assertEqual(status, 200)
        self.assertRegex(body["code"], r"^[A-Z0-9]{4}-[A-Z0-9]{4}$")

    def test_no_session_no_code(self):
        self.tmux.session = None
        status, body = call(self.path, "POST", "/pair")
        self.assertEqual(status, 409)

    def test_revoke_needs_an_id_or_all(self):
        self.assertEqual(call(self.path, "POST", "/agent/revoke", {})[0], 400)
        self.assertEqual(call(self.path, "POST", "/agent/revoke", {"id": "nope"})[0], 400)
        self.assertEqual(call(self.path, "POST", "/agent/revoke", {"all": True}), (200, {"revoked": []}))
        self.assertIn("Agent access revoked (0 grants).", self.tmux.messages)

    def test_direct_token_is_bound_to_a_pane_of_the_session(self):
        self.assertEqual(call(self.path, "POST", "/agent/token", {"scope": "observe", "pane": "%9"})[0], 400)
        self.assertEqual(call(self.path, "POST", "/agent/token", {"scope": "root"})[0], 400)
        status, body = call(self.path, "POST", "/agent/token", {"scope": "observe", "label": "ci"})
        self.assertEqual(status, 200)
        grant = self.state.agents.authenticate(body["token"], "http://127.0.0.1:8095/mcp")
        self.assertEqual((grant.scope, grant.pane_id, grant.client_name), ("observe", "%1", "ci"))

    def test_approve_unknown_request(self):
        status, body = call(self.path, "POST", "/agent/approve", {"id": "ZZZZ", "scope": "observe"})
        self.assertEqual(status, 404)

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "peer credentials are Linux-only")
    def test_peer_uid_is_ours(self):
        from bon5ai_remote.admin import peer_uid
        sock = socket.socket(socket.AF_UNIX)
        sock.connect(str(self.path))
        self.assertEqual(peer_uid(sock), os.getuid())
        sock.close()


if __name__ == "__main__":
    unittest.main()
