"""The command line's prompts, answered on a real controlling terminal."""

import os
import pty
import select
import signal
import sys
import time
import unittest

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


if __name__ == "__main__":
    unittest.main()
