"""The stream wrapper must size asciinema's terminal to the tmux window plus its status line."""

import shlex
import subprocess
import unittest
from pathlib import Path

from bon5ai_remote import stream
from bon5ai_remote.tmux import Tmux


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


if __name__ == "__main__":
    unittest.main()
