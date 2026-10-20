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
        self.lockouts = 0

    def gate(self, clock):
        return gate.Gate(code_ttl=600, viewer_ttl=3600, session_lookup=lambda: self.session,
                         host_attached=lambda: self.host, stream_address=lambda: self.stream,
                         on_viewers=lambda session, count: self.viewer_counts.append(count),
                         on_lockout=self.lockout, clock=clock)

    def lockout(self):
        self.lockouts += 1


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

    def test_wrong_codes_lock_pairing_for_the_window(self):
        code = self.gate.mint()
        for _ in range(gate.FAILURE_LIMIT):
            with self.assertRaises(gate.InvalidCode):
                self.gate.claim("AAAA-AAAA")
        with self.assertRaises(gate.Throttled):
            self.gate.claim(code)  # even a good code, until the window passes
        self.clock.now += gate.FAILURE_WINDOW_SECONDS + 1
        self.assertTrue(self.gate.claim(self.gate.mint()))

    def test_lockout_is_per_client_when_the_client_is_known(self):
        for _ in range(gate.FAILURE_LIMIT):
            with self.assertRaises(gate.InvalidCode):
                self.gate.claim("AAAA-AAAA", client="198.51.100.7")
        with self.assertRaises(gate.Throttled):
            self.gate.claim("AAAA-AAAA", client="198.51.100.7")
        # The owner, on another address, can still pair.
        self.assertTrue(self.gate.claim(self.gate.mint(), client="203.0.113.9"))

    def test_global_ceiling_holds_against_rotating_addresses(self):
        for n in range(gate.GLOBAL_FAILURE_LIMIT):
            with self.assertRaises(gate.InvalidCode):
                self.gate.claim("AAAA-AAAA", client=f"198.51.100.{n % 250}-{n}")
        self.assertEqual(self.fake.lockouts, 1)
        with self.assertRaises(gate.Throttled):
            self.gate.claim(self.gate.mint(), client="203.0.113.9")

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
        for _ in range(gate.MAX_STREAMS):
            self.assertTrue(self.gate.open_stream(session))
        self.assertFalse(self.gate.open_stream(session))
        self.gate.close_stream(session)
        self.assertEqual(self.fake.viewer_counts, [1, 2, 3, 4, 3])
        self.assertEqual(self.gate.viewer_count(), 3)


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
