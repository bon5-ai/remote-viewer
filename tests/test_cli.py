"""The command line's prompts, answered on a real controlling terminal."""

import os
import pty
import select
import time
import unittest

from bon5ai_remote import cli


class TtyInputTests(unittest.TestCase):
    def test_reads_an_answer_from_the_controlling_terminal(self):
        pid, fd = pty.fork()  # the child gets a new session with the pty as its controlling terminal
        if pid == 0:
            try:
                os._exit(0 if cli.tty_input("Scope [o/s/c]: ") == "c" else 1)
            except BaseException:
                os._exit(2)
        try:
            seen = b""
            deadline = time.monotonic() + 10
            while b"Scope [o/s/c]: " not in seen and time.monotonic() < deadline:
                if select.select([fd], [], [], 0.1)[0]:
                    try:
                        seen += os.read(fd, 1024)
                    except OSError:  # EIO: the child exited without prompting
                        break
            self.assertIn(b"Scope [o/s/c]: ", seen)
            os.write(fd, b"c\n")
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
