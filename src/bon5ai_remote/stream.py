"""Run the asciinema stream for the shared tmux session, sized to its window.

``asciinema stream --headless`` fixes the terminal size when it starts. When the
tmux window was later made smaller, viewers saw tmux's dot-filled margin around it,
and when it was made larger, they saw it cropped. This gives asciinema a real
terminal instead: a pty sized to the tmux window plus its status line, resized
whenever the window changes. On each resize asciinema gets SIGWINCH, resizes the
hidden read-only tmux client to match, and streams a resize event. The browser
player then re-fits the new grid to the viewport.

``tmux-remote-viewer share`` starts this in its own session, so it outlives the SSH
connection. It exits when asciinema does, which happens when the tmux session
ends. Its pty output, a copy of the session, is read and discarded.

Stopping it (SIGTERM, SIGHUP or SIGINT) stops asciinema too. That takes more than
closing the pty: asciinema ignores SIGTERM and SIGHUP, and outlived the wrapper
when it was killed. Instead, ``stop`` ends the hidden tmux client, after which
asciinema exits on its own. A SIGKILL is the fallback.

    python -m bon5ai_remote.stream --socket PATH --session NAME --listen 127.0.0.1:PORT
"""

from __future__ import annotations

import argparse
import fcntl
import os
import pty
import select
import shlex
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

from .tmux import Tmux

POLL_SECONDS = 1.0
STOP_GRACE_SECONDS = 3.0


class Stop(Exception):
    pass


def on_signal(signum, frame):
    raise Stop()


def status_lines(value: str) -> int:
    """Rows tmux's status line takes, from the `status` option: off, on, or 2-5."""
    if value == "off":
        return 0
    return int(value) if value.isdigit() else 1


def client_size(tmux: Tmux) -> tuple[int, int] | None:
    """(cols, rows) a client needs to show the session's current window exactly."""
    size = tmux.window_size()
    if size is None:
        return None
    width, height, status = size
    return width, height + status_lines(status)


def set_size(fd: int, size: tuple[int, int]) -> None:
    cols, rows = size
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def children(pid: int, run=subprocess.run) -> list[int]:
    """Direct children of pid. pgrep works on Linux and macOS alike."""
    try:
        result = run(["pgrep", "-P", str(pid)], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [int(line) for line in result.stdout.split() if line.isdigit()]


def stop(pid: int) -> None:
    """End asciinema by ending the tmux client it runs, then SIGKILL if that isn't enough."""
    for child in children(pid):
        try:
            os.kill(child, signal.SIGTERM)  # tmux detaches the client; the session is untouched
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + STOP_GRACE_SECONDS
    while time.monotonic() < deadline:
        if os.waitpid(pid, os.WNOHANG)[0]:
            return
        time.sleep(0.1)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)


def command(socket_path: Path, session: str, listen: str) -> list[str]:
    # exec: asciinema runs this through sh -c, and stop() needs the tmux client to be
    # asciinema's own child rather than a shell's.
    attach = shlex.join(["tmux", "-S", str(socket_path), "attach-session", "-t", f"={session}",
                         "-f", "read-only,ignore-size"])
    return ["asciinema", "stream", "--quiet", "--local", listen, "--command", f"exec {attach}"]


def run(socket_path: Path, session: str, listen: str) -> int:
    tmux = Tmux(socket_path, session)
    size = client_size(tmux)
    if size is None:
        print(f"tmux-remote-viewer stream: no tmux session named '{session}'", file=sys.stderr)
        return 1
    argv = command(socket_path, session, listen)
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, on_signal)
    pid, master = pty.fork()
    if pid == 0:
        try:
            set_size(0, size)  # before exec, so asciinema starts at the right size
            # The player emulates xterm-256color whatever the real terminal is.
            os.environ["TERM"] = "xterm-256color"
            os.environ.pop("TMUX", None)
            os.execvp(argv[0], argv)
        finally:
            os._exit(127)

    checked = time.monotonic()
    try:
        while True:
            try:
                ready, _, _ = select.select([master], [], [], POLL_SECONDS)
                if ready and not os.read(master, 65536):
                    break
            except OSError:  # EIO once asciinema has exited and the pty is gone
                break
            if time.monotonic() - checked >= POLL_SECONDS:
                checked = time.monotonic()
                current = client_size(tmux)
                if current and current != size:
                    set_size(master, current)
                    size = current
    except Stop:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)  # a second signal must not cut stop() short
        stop(pid)
        return 0
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m bon5ai_remote.stream")
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--session", required=True)
    parser.add_argument("--listen", required=True)
    args = parser.parse_args(argv)
    sys.exit(run(args.socket, args.session, args.listen))


if __name__ == "__main__":
    main()
