"""The command line's prompts, answered on a real controlling terminal."""

import argparse
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from bon5ai_remote import cli

PROMPT = b"Scope [o/s/c]: "
# The child execs a fresh interpreter: running Python in a fork of this multi-threaded
# test process can deadlock, on macOS above all.
CHILD = ("import os; from bon5ai_remote import cli; "
         "os._exit(0 if cli.tty_input('Scope [o/s/c]: ') == 'c' else 1)")


def read_until(fd: int, marker: bytes, timeout: float = 10) -> bytes:
    seen = b""
    deadline = time.monotonic() + timeout
    while marker not in seen and time.monotonic() < deadline:
        if select.select([fd], [], [], 0.1)[0]:
            try:
                seen += os.read(fd, 1024)
            except OSError:  # EIO: the child exited
                break
    return seen


def wait(pid: int, timeout: float = 10) -> int | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            return os.waitstatus_to_exitcode(status)
        time.sleep(0.05)
    return None


class TtyInputTests(unittest.TestCase):
    def test_reads_an_answer_from_the_controlling_terminal(self):
        pid, fd = pty.fork()  # the child gets a new session with the pty as its controlling terminal
        if pid == 0:
            try:
                os.execv(sys.executable, [sys.executable, "-c", CHILD])
            finally:
                os._exit(127)
        code = None
        try:
            seen = read_until(fd, PROMPT)
            self.assertIn(PROMPT, seen)
            os.write(fd, b"c\n")
            code = wait(pid)
            self.assertEqual(code, 0, seen + read_until(fd, b"\n\n", 1))
        finally:
            os.close(fd)
            if code is None:  # never leave a child behind, whatever failed
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)


class ArgumentTests(unittest.TestCase):
    def test_code_ttl(self):
        self.assertEqual(cli.parser().parse_args(["code", "--ttl", "30m"]).ttl, 1800)
        self.assertIsNone(cli.parser().parse_args(["code"]).ttl)  # the gate's code_ttl_seconds


class ApproveTests(unittest.TestCase):
    """Which waiting request `agent approve` picks when no ID is given."""

    def request(self, loopback: bool) -> dict:
        return {"id": "K7QM", "client": "Claude Code", "verified": False, "clientHost": None,
                "redirectHost": "localhost:53172" if loopback else "chat.example.test", "loopback": loopback,
                "age": 20, "expiresIn": 280}

    def approve(self, requests, **args):
        calls = []

        def admin(cfg, method, path, body=None):
            calls.append((method, path, body))
            return {"requests": requests}
        original = cli.admin
        cli.admin = admin
        try:
            with self.assertRaises(cli.Exit) as caught:  # stops at the scope prompt, or at the ID check
                cli.cmd_agent_approve(None, argparse.Namespace(id=None, yes=False, scope=None, pane=None, ttl=None,
                                                               **args))
        finally:
            cli.admin = original
        return str(caught.exception)

    def test_a_lone_request_returning_to_this_machine_is_picked(self):
        message = self.approve([self.request(loopback=True)])
        self.assertNotIn("Name the request", message)  # it got as far as asking for a scope

    def test_a_hosted_callback_needs_the_id_from_the_page(self):
        # Anyone using the hosted service could have started it, so the ID on the page you
        # opened is the only thing that ties the request to you.
        message = self.approve([self.request(loopback=False)])
        self.assertIn("Name the request", message)
        self.assertIn("hosted service", message)

    def test_describe_marks_hosted_callbacks(self):
        self.assertIn("anyone using it", cli.describe_request(self.request(loopback=False)))
        self.assertNotIn("anyone using it", cli.describe_request(self.request(loopback=True)))


class SelfCommandTests(unittest.TestCase):
    """The re-invocation command (headersHelper, kill key, service) must not import from
    the directory it runs in: a cloned repository could plant a package there."""

    def test_a_planted_package_in_the_working_directory_is_ignored(self):
        with tempfile.TemporaryDirectory() as cwd:
            planted = Path(cwd) / "bon5ai_remote"
            planted.mkdir()
            (planted / "__init__.py").write_text("")
            (planted / "__main__.py").write_text("import sys; print('PLANTED'); sys.exit(99)\n")
            result = subprocess.run(cli.self_command(None) + ["--help"], cwd=cwd,
                                    capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("PLANTED", result.stdout)
        self.assertIn("tmux-remote-viewer", result.stdout)

    def test_config_path_is_absolute(self):
        command = cli.self_command("~/x/config.toml")
        self.assertEqual(command[-2], "--config")
        self.assertTrue(Path(command[-1]).is_absolute())


if __name__ == "__main__":
    unittest.main()
