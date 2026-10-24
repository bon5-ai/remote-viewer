"""A viewer's size holds only while the host is away and that viewer is the one watching."""

import json
import tempfile
import unittest
from pathlib import Path

from bon5ai_remote import sizing
from bon5ai_remote.stream import SIZE_OPTION, wanted_size
from helpers import FakeTmux, make_config, make_state


def wrapper_poll(tmux: FakeTmux) -> None:
    """One poll of the stream wrapper. asciinema's terminal takes the wanted size, and while
    the hidden client is the only one attached, tmux sizes the window to it."""
    cols, rows = wanted_size(tmux)
    if not tmux.host:
        tmux.window = (cols, rows - 1, "on")


class SizerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit_path = Path(self.tmp.name) / "audit.jsonl"
        self.tmux = FakeTmux()
        self.tmux.host = False  # detached; the window keeps the host's 120x39 plus a status line
        self.state = make_state(make_config(viewer_resize=True), self.tmux, audit_path=self.audit_path)
        self.gate = self.state.gate
        self.sizer = self.state.sizer
        self.viewer = self.watch()

    def tearDown(self):
        self.tmp.cleanup()

    def watch(self) -> str:
        token = self.gate.claim(self.gate.mint())
        self.gate.open_stream(self.tmux.session, token)
        return token

    def events(self) -> list[str]:
        if not self.audit_path.exists():
            return []
        return [json.loads(line)["event"] for line in self.audit_path.read_text().splitlines()]

    def test_takes_the_viewers_size_and_gives_it_back(self):
        result = self.sizer.request(self.viewer, 60, 30)
        self.assertTrue(result["active"])
        self.assertEqual(result["size"], (60, 30))
        self.assertEqual(self.tmux.options[sizing.HOST_SIZE_OPTION], "120x40")  # status line included
        self.assertEqual(self.tmux.options[SIZE_OPTION], "60x30")
        wrapper_poll(self.tmux)
        self.assertEqual(self.tmux.window, (60, 29, "on"))
        self.gate.close_stream(self.tmux.session, self.viewer)  # the viewer stops watching
        self.assertEqual(self.tmux.options[SIZE_OPTION], "120x40")
        wrapper_poll(self.tmux)
        self.assertEqual(self.tmux.window, (120, 39, "on"))
        self.sizer.reconcile()  # back at the host's size: the stream follows the window again
        self.assertNotIn(SIZE_OPTION, self.tmux.options)
        self.assertNotIn(sizing.HOST_SIZE_OPTION, self.tmux.options)
        self.assertEqual(self.events(), ["viewer.resize", "viewer.resize-ended"])

    def test_a_second_viewer_brings_back_the_host_size(self):
        self.sizer.request(self.viewer, 60, 30)
        wrapper_poll(self.tmux)
        second = self.watch()
        self.assertEqual(self.tmux.options[SIZE_OPTION], "120x40")
        self.assertFalse(self.sizer.describe(self.viewer)["active"])
        self.assertFalse(self.sizer.request(second, 50, 20)["active"])  # nor does the newcomer get its own
        self.assertEqual(self.tmux.options[SIZE_OPTION], "120x40")
        wrapper_poll(self.tmux)
        self.gate.close_stream(self.tmux.session, second)  # one viewer again: its size comes back
        self.assertEqual(self.tmux.options[SIZE_OPTION], "60x30")
        self.assertTrue(self.sizer.describe(self.viewer)["active"])

    def test_the_host_attaching_takes_the_session_back_at_once(self):
        self.sizer.request(self.viewer, 60, 30)
        wrapper_poll(self.tmux)
        self.tmux.host = True
        self.tmux.window = (200, 49, "on")  # tmux sizes the window to the host's terminal
        self.assertEqual(wanted_size(self.tmux), (200, 50))  # and the stream follows it, before the gate looks
        self.assertFalse(self.sizer.describe(self.viewer)["active"])
        self.sizer.reconcile()
        self.assertNotIn(SIZE_OPTION, self.tmux.options)
        self.assertNotIn(sizing.HOST_SIZE_OPTION, self.tmux.options)
        self.tmux.host = False  # detached again: the viewer's size returns, and the host's new size is saved
        self.sizer.reconcile()
        self.assertEqual(self.tmux.options[sizing.HOST_SIZE_OPTION], "200x50")
        self.assertEqual(self.tmux.options[SIZE_OPTION], "60x30")

    def test_nothing_changes_while_the_host_is_attached(self):
        self.tmux.host = True
        result = self.sizer.request(self.viewer, 60, 30)
        self.assertFalse(result["active"])
        self.assertEqual(result["size"], (60, 30))  # held for when the host detaches
        self.assertNotIn(SIZE_OPTION, self.tmux.options)
        self.assertEqual(self.events(), [])

    def test_a_viewer_that_is_not_watching_changes_nothing(self):
        bystander = self.gate.claim(self.gate.mint())  # paired, but no stream open
        self.assertFalse(self.sizer.request(bystander, 60, 30)["active"])
        self.assertNotIn(SIZE_OPTION, self.tmux.options)
        self.assertIsNone(self.sizer.request("not-a-viewer", 60, 30))

    def test_sizes_are_held_within_the_limits(self):
        self.assertEqual(self.sizer.request(self.viewer, 5, -3)["size"], sizing.MIN_SIZE)
        self.assertEqual(self.sizer.request(self.viewer, 10**9, 10**9)["size"], sizing.MAX_SIZE)
        self.assertEqual(self.tmux.options[SIZE_OPTION], "400x150")

    def test_off_it_only_hands_back_a_size_left_from_before(self):
        # A gate that had viewer_resize on stopped while a viewer's size held. Restarted with it
        # off, it takes nobody's size but still puts the host's back.
        tmux = FakeTmux()
        tmux.host = False
        tmux.options.update({SIZE_OPTION: "60x30", sizing.HOST_SIZE_OPTION: "120x40"})
        tmux.window = (60, 29, "on")
        state = make_state(make_config(), tmux)
        token = state.gate.claim(state.gate.mint())
        state.gate.open_stream(tmux.session, token)
        self.assertFalse(state.sizer.request(token, 50, 20)["active"])
        self.assertEqual(tmux.options[SIZE_OPTION], "120x40")
        wrapper_poll(tmux)
        state.sizer.reconcile()
        self.assertEqual(tmux.window, (120, 39, "on"))
        self.assertNotIn(SIZE_OPTION, tmux.options)


if __name__ == "__main__":
    unittest.main()
