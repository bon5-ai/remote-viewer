"""The stream wrapper must size asciinema's terminal to the tmux window plus its status line."""

import os
import shlex
import subprocess
import sys
import unittest
from pathlib import Path

from bon5ai_remote import stream
from bon5ai_remote.tmux import Tmux
from helpers import FakeTmux


def runner(stdout, returncode=0):
    def run(args, **kwargs):
        run.args = args
        return subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr="")
    return run


class StreamSizeTests(unittest.TestCase):
    def tmux(self, run):
        return Tmux(Path("/run/x/tmux.sock"), "share", run=run)

    def test_window_plus_status_line(self):
        run = runner("108 33 on\n")
        self.assertEqual(stream.client_size(self.tmux(run)), (108, 34))
        self.assertIn("=share:", run.args)  # exact session name, current window
        self.assertEqual(run.args[:3], ["tmux", "-S", "/run/x/tmux.sock"])  # the dedicated server only

    def test_status_off_and_multi_line(self):
        self.assertEqual(stream.client_size(self.tmux(runner("80 24 off\n"))), (80, 24))
        self.assertEqual(stream.client_size(self.tmux(runner("80 22 2\n"))), (80, 24))

    def test_no_session(self):
        self.assertIsNone(stream.client_size(self.tmux(runner("", returncode=1))))

    def test_tmux_missing(self):
        def run(*args, **kwargs):
            raise FileNotFoundError("tmux")
        self.assertIsNone(stream.client_size(self.tmux(run)))

    def test_follows_the_window_unless_the_gate_asked_and_its_client_is_alone(self):
        tmux = FakeTmux()
        tmux.window = (100, 30, "on")
        self.assertEqual(stream.wanted_size(tmux), (100, 31))
        tmux.options[stream.SIZE_OPTION] = "60x20"
        self.assertEqual(stream.wanted_size(tmux), (100, 31))  # the host's terminal sizes the window
        tmux.host = False
        self.assertEqual(stream.wanted_size(tmux), (60, 20))
        for bad in ("0x20", "60x", "60x20 ", "60X20", "123456x20", ""):
            tmux.options[stream.SIZE_OPTION] = bad
            self.assertEqual(stream.wanted_size(tmux), (100, 31), bad)
        tmux.session = None
        self.assertIsNone(stream.wanted_size(tmux))

    def test_command_attaches_read_only_to_the_dedicated_socket(self):
        argv = stream.command(Path("/run/a dir/tmux.sock"), "share", "127.0.0.1:4100")
        self.assertEqual(argv[:5], ["asciinema", "stream", "--quiet", "--local", "127.0.0.1:4100"])
        attach = shlex.split(argv[-1])
        self.assertEqual(attach[0], "exec")
        self.assertEqual(attach[1:4], ["tmux", "-S", "/run/a dir/tmux.sock"])
        self.assertIn("read-only,ignore-size", attach)

    def test_children_uses_pgrep(self):
        run = runner("101\n102\n")
        self.assertEqual(stream.children(7, run), [101, 102])
        self.assertEqual(run.args, ["pgrep", "-P", "7"])


class OwnerTests(unittest.TestCase):
    """The gate trusts the stream port only while the wrapper `share` started owns it."""

    LISTEN = "127.0.0.1:4100"

    def test_judges_uid_and_command_line(self):
        me = os.getuid()
        wrapper = ["python", "-P", "-m", "bon5ai_remote.stream", "--socket", "/x", "--session", "s",
                   "--listen", self.LISTEN]
        cases = [((me, wrapper), True),
                 ((me + 1, wrapper), False),  # alive, but another user's
                 ((me, ["python", "-m", "http.server"]), False),  # the pid was reused
                 ((me, wrapper[:-1] + ["127.0.0.1:4101"]), False),  # ours, but not for this port
                 (None, False)]
        for found, expected in cases:
            self.assertEqual(stream.owner_alive(os.getpid(), self.LISTEN, argv_of=lambda pid: found), expected, found)

    def test_a_dead_pid_is_never_the_owner(self):
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait()
        self.assertFalse(stream.owner_alive(child.pid, self.LISTEN, argv_of=lambda pid: (os.getuid(), ["x"])))

    def test_reads_a_real_process(self):
        # A child whose argv looks like the wrapper's, without needing tmux or asciinema.
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)",
                                  "bon5ai_remote.stream", "--listen", self.LISTEN])
        try:
            self.assertTrue(stream.owner_alive(child.pid, self.LISTEN))
            self.assertFalse(stream.owner_alive(child.pid, "127.0.0.1:4101"))
        finally:
            child.kill()
            child.wait()
        self.assertFalse(stream.owner_alive(child.pid, self.LISTEN))


if __name__ == "__main__":
    unittest.main()
