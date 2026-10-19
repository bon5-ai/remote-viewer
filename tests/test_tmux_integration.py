"""Against a real tmux server on a private socket. Skipped when tmux isn't installed."""

import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from bon5ai_remote.tmux import PANE_FIELDS, SEP, Pane, Tmux, foreground_pgid, literal_arg

HAVE_TMUX = shutil.which("tmux") is not None


def wait_for(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


class PaneParseTests(unittest.TestCase):
    FIXED = ["%3", "$1", "100", "0", "1", "1", "4242", "0", "0", "0", "80", "24", "0", "0"]

    def test_names_are_made_printable(self):
        pane = Pane.parse(SEP.join(self.FIXED + ["evil\x1b]0;pwned\x07", "win", "/tmp"]))
        self.assertEqual(pane.command, "evil?]0;pwned?")

    def test_a_raw_tab_does_not_lose_the_pane(self):
        pane = Pane.parse(SEP.join(self.FIXED + ["bash", "my", "window", "/home/x"]))
        self.assertEqual((pane.command, pane.window_name, pane.path), ("bash", "my?window", "/home/x"))
        self.assertIsNone(Pane.parse(SEP.join(self.FIXED[:5])))
        self.assertEqual(len(PANE_FIELDS), len(self.FIXED) + 3)


@unittest.skipUnless(HAVE_TMUX, "tmux is not installed")
class RealTmuxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.socket = Path(self.tmp.name) / "t.sock"
        subprocess.run(["tmux", "-S", str(self.socket), "-f", "/dev/null", "new-session", "-d", "-s", "share",
                        "-x", "100", "-y", "20", "env", "-i", "PS1=$ ", "HOME=/tmp", "PATH=/usr/bin:/bin",
                        "bash", "--norc", "--noprofile"], check=True)
        self.tmux = Tmux(self.socket, "share")
        self.pane = self.tmux.active_pane()
        self.assertTrue(wait_for(lambda: "$" in "".join(self.tmux.capture(self.pane)[0])))

    def tearDown(self):
        subprocess.run(["tmux", "-S", str(self.socket), "kill-server"], capture_output=True)
        self.tmp.cleanup()

    def screen(self) -> str:
        return "\n".join(self.tmux.capture(self.pane)[0])

    def test_text_arrives_exactly(self):
        # A trailing ';' is a command separator to tmux and "-R" looks like a flag; both must arrive as typed.
        for text in ("echo a;", "-R", "x\\;", ";"):
            self.tmux.send_keys(self.pane, ["C-u"])
            self.assertTrue(self.tmux.send_literal(self.pane, text))
            self.assertTrue(wait_for(lambda: self.screen().rstrip().endswith("$ " + text)),
                            f"{text!r} arrived as {self.screen().splitlines()[-1]!r}")

    def test_literal_arg(self):
        self.assertEqual(literal_arg("a;"), "a\\;")
        self.assertEqual(literal_arg("a\\;"), "a\\\\;")
        self.assertEqual(literal_arg("plain"), "plain")

    def test_run_and_read(self):
        self.tmux.send_literal(self.pane, "echo hello-$((40+2))")
        self.tmux.send_keys(self.pane, ["Enter"])
        self.assertTrue(wait_for(lambda: "hello-42" in self.screen()))
        pane = self.tmux.pane(self.pane)
        self.assertEqual(pane.session_key, self.tmux.session_key())
        self.assertTrue(pane.window_active)
        self.assertFalse(pane.in_mode)
        self.assertTrue(wait_for(lambda: foreground_pgid(self.tmux.pane(self.pane).pid) == pane.pid))

    def test_foreground_changes_while_a_command_runs(self):
        pid = self.tmux.pane(self.pane).pid
        self.tmux.send_literal(self.pane, "sleep 2")
        self.tmux.send_keys(self.pane, ["Enter"])
        self.assertTrue(wait_for(lambda: foreground_pgid(pid) not in (None, pid)))
        self.tmux.send_keys(self.pane, ["C-c"])
        self.assertTrue(wait_for(lambda: foreground_pgid(pid) == pid))

    def test_paste_uses_a_private_buffer(self):
        self.assertTrue(self.tmux.paste(self.pane, "echo one\necho two"))
        self.tmux.send_keys(self.pane, ["Enter"])
        self.assertTrue(wait_for(lambda: "two" in self.screen()))
        buffers = subprocess.run(["tmux", "-S", str(self.socket), "list-buffers"], capture_output=True,
                                 text=True).stdout
        self.assertNotIn("bon5ai-", buffers)  # deleted after pasting

    def test_options_and_copy_mode(self):
        self.assertTrue(self.tmux.set_option("@bon5ai_test", "x y"))
        self.assertEqual(self.tmux.get_option("@bon5ai_test"), "x y")
        self.tmux.unset_option("@bon5ai_test")
        self.assertIsNone(self.tmux.get_option("@bon5ai_test"))
        subprocess.run(["tmux", "-S", str(self.socket), "copy-mode", "-t", self.pane], check=True)
        self.assertTrue(self.tmux.pane(self.pane).in_mode)

    def test_unknown_pane_and_bad_ids(self):
        self.assertIsNone(self.tmux.pane("%999"))
        self.assertIsNone(self.tmux.pane("share"))
        self.assertFalse(self.tmux.send_literal("-t", "x"))


if __name__ == "__main__":
    unittest.main()
