"""Viewer pairing rules: codes, viewers, lockout, streams."""

import unittest

from bon5ai_remote import gate
from helpers import STREAM_INDEX, Clock


class FakeSession:
    def __init__(self):
        self.session = "$1@100"
        self.host = True
        self.stream = ("127.0.0.1", 9)
        self.viewer_counts = []
        self.notices = []

    def gate(self, clock):
        return gate.Gate(code_ttl=600, viewer_ttl=3600, session_lookup=lambda: self.session,
                         host_attached=lambda: self.host, stream_address=lambda: self.stream,
                         on_viewers=lambda session, count: self.viewer_counts.append(count),
                         on_guessing=self.notices.append, clock=clock)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.fake = FakeSession()
        self.gate = self.fake.gate(self.clock)
        self.up = True
        self._stream_up = gate.stream_up
        gate.stream_up = lambda addr: self.up and addr is not None

    def tearDown(self):
        gate.stream_up = self._stream_up

    def test_code_shape(self):
        code = self.gate.mint()
        self.assertRegex(code, r"^[A-Z0-9]{4}-[A-Z0-9]{4}$")
        self.assertTrue(set(code.replace("-", "")) <= set(gate.CODE_ALPHABET))

    def test_claim_accepts_sloppy_typing_once(self):
        code = self.gate.mint()
        token = self.gate.claim(f"  {code.lower().replace('-', ' ')} ")
        self.assertEqual(self.gate.status(token), {"state": "live", "viewers": 0})
        with self.assertRaises(gate.InvalidCode):
            self.gate.claim(code)

    def test_expired_code_is_refused(self):
        code = self.gate.mint()
        self.clock.now += 601
        with self.assertRaises(gate.InvalidCode):
            self.gate.claim(code)

    def test_code_lifetime_can_be_chosen(self):
        early, late = self.gate.mint(1800), self.gate.mint(1800)
        self.clock.now += 1799
        self.assertTrue(self.gate.claim(early))
        self.clock.now += 2
        with self.assertRaises(gate.InvalidCode):
            self.gate.claim(late)

    def test_no_session_no_code(self):
        self.fake.session = None
        self.assertIsNone(self.gate.mint())

    def test_wrong_codes_never_lock_the_shared_bucket(self):
        # Behind Funnel every client is "". Locking that bucket would let anyone keep the
        # owner from pairing with ten requests every ten minutes; the listener's delay is
        # the brake instead, and the terminal is told once.
        code = self.gate.mint()
        for n in range(gate.FAILURE_LIMIT * 3):
            with self.assertRaises(gate.InvalidCode) as refused:
                self.gate.claim("AAAA-AAAA")
            self.assertEqual(refused.exception.failures, n + 1)
        self.assertEqual(self.fake.notices, [gate.FAILURE_LIMIT])
        self.assertTrue(self.gate.claim(code))  # a good code works at any point
        self.assertNotIn("", self.gate._failures)

    def test_the_guessing_notice_repeats_once_per_window(self):
        for _ in range(gate.FAILURE_LIMIT):
            with self.assertRaises(gate.InvalidCode):
                self.gate.claim("AAAA-AAAA")
        self.clock.now += gate.FAILURE_WINDOW_SECONDS + 1
        for _ in range(gate.FAILURE_LIMIT):
            with self.assertRaises(gate.InvalidCode):
                self.gate.claim("AAAA-AAAA", client="198.51.100.7")  # named clients count too
        self.assertEqual(self.fake.notices, [gate.FAILURE_LIMIT, gate.FAILURE_LIMIT])

    def test_lockout_is_per_client_when_the_client_is_known(self):
        for _ in range(gate.FAILURE_LIMIT):
            with self.assertRaises(gate.InvalidCode):
                self.gate.claim("AAAA-AAAA", client="198.51.100.7")
        with self.assertRaises(gate.Throttled):
            self.gate.claim("AAAA-AAAA", client="198.51.100.7")
        # The owner, on another address, can still pair; so can one the proxy can't name.
        self.assertTrue(self.gate.claim(self.gate.mint(), client="203.0.113.9"))
        self.assertTrue(self.gate.claim(self.gate.mint()))
        self.clock.now += gate.FAILURE_WINDOW_SECONDS + 1
        self.assertTrue(self.gate.claim(self.gate.mint(), client="198.51.100.7"))

    def test_rotating_addresses_never_lock_anyone_else_out(self):
        for n in range(gate.FAILURE_LIMIT * 20):
            with self.assertRaises(gate.InvalidCode):
                self.gate.claim("AAAA-AAAA", client=f"198.51.100.{n % 250}-{n}")
        self.assertEqual(self.fake.notices, [gate.FAILURE_LIMIT])
        self.assertTrue(self.gate.claim(self.gate.mint(), client="203.0.113.9"))

    def test_viewer_is_bound_to_its_session(self):
        token = self.gate.claim(self.gate.mint())
        self.fake.session = "$1@200"  # same id, new creation time: a different session
        self.assertEqual(self.gate.status(token), {"state": "ended"})
        self.assertIsNone(self.gate.status(token))  # and the viewer is gone

    def test_states(self):
        token = self.gate.claim(self.gate.mint())
        self.fake.host = False
        self.assertEqual(self.gate.status(token)["state"], "host-away")
        self.up = False
        self.assertEqual(self.gate.status(token)["state"], "stream-down")

    def test_viewer_expires(self):
        token = self.gate.claim(self.gate.mint())
        self.clock.now += 3601
        self.assertIsNone(self.gate.status(token))

    def test_stream_limit_and_viewer_count(self):
        session = self.fake.session
        token = self.gate.claim(self.gate.mint())
        for _ in range(gate.MAX_STREAMS):
            self.assertTrue(self.gate.open_stream(session, token))
        self.assertFalse(self.gate.open_stream(session, token))
        self.gate.close_stream(session, token)
        self.assertEqual(self.fake.viewer_counts, [1, 2, 3, 4, 3])
        self.assertEqual(self.gate.viewer_count(), 3)

    def test_only_the_one_watching_viewer_has_a_size(self):
        session = self.fake.session
        first, second = self.gate.claim(self.gate.mint()), self.gate.claim(self.gate.mint())
        self.assertTrue(self.gate.request_size(first, (60, 30)))
        self.assertTrue(self.gate.request_size(second, (100, 40)))
        self.assertFalse(self.gate.request_size("not-a-viewer", (60, 30)))
        self.assertIsNone(self.gate.sole_viewer_size(session))  # nobody is watching yet
        self.gate.open_stream(session, first)
        self.assertEqual(self.gate.sole_viewer_size(session), (60, 30))
        self.assertEqual(self.gate.sole_viewer_size(session, first), (60, 30))
        self.assertIsNone(self.gate.sole_viewer_size(session, second))  # paired, but not the one watching
        self.gate.open_stream(session, second)
        self.assertIsNone(self.gate.sole_viewer_size(session))  # two watching: nobody's size
        self.gate.close_stream(session, first)
        self.assertEqual(self.gate.sole_viewer_size(session), (100, 40))
        self.gate.revoke(second)
        self.assertIsNone(self.gate.sole_viewer_size(session))  # a revoked viewer's size goes with it
        self.assertIsNone(self.gate.requested_size(second))

    def test_a_size_expires_with_its_viewer(self):
        token = self.gate.claim(self.gate.mint())
        self.gate.request_size(token, (60, 30))
        self.gate.open_stream(self.fake.session, token)
        self.clock.now += 3601
        self.assertIsNone(self.gate.sole_viewer_size(self.fake.session))
        self.assertIsNone(self.gate.requested_size(token))


class SymbolFontTests(unittest.TestCase):
    def test_symbol_font_url_stays_on_the_mount(self):
        # The index url is root-absolute. Left alone, a browser at /remote/ would
        # request it from the site root and the glyph font would never load.
        css, files = gate.symbol_fonts(STREAM_INDEX.decode())
        name = "SymbolsNerdFont-Regular.64622a496f8fd2e6.woff2"
        self.assertEqual(files, {name: f"/{name}"})
        self.assertIn(f'url("{name}")', css)
        self.assertNotIn('url("/', css)
        self.assertNotIn("margin", css)  # the rest of the page's style block is not the font
        self.assertIn("font-display: block", css)


if __name__ == "__main__":
    unittest.main()
