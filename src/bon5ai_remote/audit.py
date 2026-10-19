"""Append-only JSON-lines audit log of what agents did and who allowed it.

Records approvals, revocations and every write an agent made, with the text it
typed. Never records tokens or codes. The file is created 0600.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path


class Audit:
    def __init__(self, path: Path | None, clock=time.time):
        self.path = path
        self.clock = clock
        self._lock = threading.Lock()

    def record(self, event: str, **fields) -> None:
        if self.path is None:
            return
        line = json.dumps({"ts": round(self.clock(), 3), "event": event, **fields}, ensure_ascii=False)
        try:
            with self._lock:
                self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    os.write(fd, (line + "\n").encode())
                finally:
                    os.close(fd)
        except OSError as error:
            print(f"audit log {self.path}: {error}", file=sys.stderr, flush=True)
