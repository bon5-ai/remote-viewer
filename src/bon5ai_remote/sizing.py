"""Give the shared session its one viewer's size while the host is away (`viewer_resize`).

The window normally takes the size of the host's terminal, and a viewer's player scales
that grid to fit its screen. With viewer_resize on, the viewer page asks for the grid
that fills its screen at the text size it picked, and the session takes that size while
all of this holds:

* the host is away: no writable client is attached;
* exactly one stream is open, and its viewer is the one that asked.

The gate never resizes a window itself. While the host is away, the stream's hidden
client is the only one attached and tmux sizes the window to it, so the gate puts the
size it wants in stream.SIZE_OPTION and the stream wrapper gives the hidden client that
size. When the host attaches, tmux sizes the window to the host's terminal again at once.

When the rules stop holding with the host still away (the viewer left, or a second one
started watching), the session goes back to the size it had before, saved in
HOST_SIZE_OPTION. Both options live in tmux, so a restarted gate still finishes that.
A size changes as fast as the wrapper polls: once a second, however often it is asked.
"""

from __future__ import annotations

import threading

from .stream import SIZE_OPTION, client_size, format_size, parse_size

MIN_SIZE = (20, 8)  # (cols, rows) of asciinema's terminal, the status line included
MAX_SIZE = (400, 150)
HOST_SIZE_OPTION = "@bon5ai_host_size"


def clamp(cols: int, rows: int) -> tuple[int, int]:
    return (min(max(cols, MIN_SIZE[0]), MAX_SIZE[0]), min(max(rows, MIN_SIZE[1]), MAX_SIZE[1]))


class Sizer:
    def __init__(self, tmux, gate, audit, *, enabled: bool):
        self.tmux = tmux
        self.gate = gate
        self.audit = audit
        self.enabled = enabled
        self._lock = threading.Lock()

    def wanted(self) -> tuple[int, int] | None:
        """The size the one watching viewer asked for, while it may have it."""
        if not self.enabled:
            return None
        session = self.tmux.session_key()
        size = self.gate.sole_viewer_size(session) if session else None
        return size if size and not self.tmux.host_attached() else None

    def reconcile(self) -> None:
        """Bring the session's size in line with the rules. Called whenever a viewer asks for
        a size or a stream opens or closes, and by the gate's housekeeping, which notices the
        host detaching and finishes handing a size back."""
        with self._lock:
            saved = parse_size(self.tmux.get_option(HOST_SIZE_OPTION))
            wanted = self.wanted()
            if wanted is not None:
                if saved is None:
                    current = client_size(self.tmux)
                    if current is None:
                        return
                    self.tmux.set_option(HOST_SIZE_OPTION, format_size(current))
                    self.audit.record("viewer.resize", cols=wanted[0], rows=wanted[1],
                                      host_cols=current[0], host_rows=current[1])
                self._ask(wanted)
            elif saved is not None:
                if self.tmux.host_attached() or client_size(self.tmux) == saved:
                    # The host's terminal sizes the session again, or it is back at the saved size:
                    # either way the stream can follow the window.
                    self.tmux.unset_option(SIZE_OPTION)
                    self.tmux.unset_option(HOST_SIZE_OPTION)
                    self.audit.record("viewer.resize-ended")
                else:
                    self._ask(saved)

    def _ask(self, size: tuple[int, int]) -> None:
        value = format_size(size)
        if self.tmux.get_option(SIZE_OPTION) != value:
            self.tmux.set_option(SIZE_OPTION, value)

    def request(self, token: str, cols: int, rows: int) -> dict | None:
        """A viewer page's size, within the limits. None if token is no viewer."""
        if not self.gate.request_size(token, clamp(cols, rows)):
            return None
        self.reconcile()
        return self.describe(token)

    def describe(self, token: str) -> dict:
        """What the viewer page needs: whether its size is the session's, the size the gate
        holds for it, and the limits."""
        session = self.tmux.session_key()
        sole = session is not None and self.gate.sole_viewer_size(session, token) is not None
        return {"active": self.enabled and sole and not self.tmux.host_attached(),
                "size": self.gate.requested_size(token), "min": MIN_SIZE, "max": MAX_SIZE}
