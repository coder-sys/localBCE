"""A file-backed stand-in for the shard's TPM counter, for tests only: no module under app/ imports it.

The file lives outside the store directory, so restoring a copy of the store does not restore it.  It holds
``RR/TEST-ONLY-COUNTER/v1\0`` · u8 written · u64 value.  Every change is made under an exclusive lock file and lands by
writing a temp file, fsync and rename, so two processes never both move c to c+1 and a kill never leaves a short file.
Read returns the value, or None while the counter is defined but never written.  The first increment writes 1.  A short
or garbled file is ``counter_unavailable``.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from app.right_rail_gate_producer import GateProducerError

MAGIC = b"RR/TEST-ONLY-COUNTER/v1\x00"


class TestOnlyCounter:
    __test__ = False  # not a test case, whatever the name says
    kind = "TEST-ONLY"

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    def read(self) -> int | None:
        try:
            data = self._path.read_bytes()
        except FileNotFoundError:
            return None
        if len(data) != len(MAGIC) + 9 or not data.startswith(MAGIC) or data[len(MAGIC)] > 1:
            raise GateProducerError("counter_unavailable")
        return int.from_bytes(data[-8:], "big") if data[len(MAGIC)] else None

    def increment(self) -> int:
        with self._locked():
            value = (self.read() or 0) + 1
            self._write(bytes([1]) + value.to_bytes(8, "big"))
            return value

    def clear(self) -> None:
        """Test only: the counter was never defined (a replaced device)."""
        self._path.unlink(missing_ok=True)

    def _locked(self):
        return _Lock(self._path.with_name(self._path.name + ".lock"))

    def _write(self, body: bytes) -> None:
        temp = self._path.with_name(self._path.name + ".tmp")
        with open(temp, "wb") as out:
            out.write(MAGIC + body)
            out.flush()
            os.fsync(out.fileno())
        for attempt in range(200):  # Windows refuses the rename while a reader has the file open
            try:
                os.replace(temp, self._path)
                return
            except PermissionError:
                if attempt == 199:
                    raise
                time.sleep(0.005)


class _Lock:
    """An exclusive lock file: created with O_EXCL, removed on exit; waits up to 30 seconds."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def __enter__(self) -> None:
        deadline = time.monotonic() + 30
        while True:
            try:
                os.close(os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
                return
            except (FileExistsError, PermissionError):  # Windows: a lock being deleted refuses with PermissionError
                if time.monotonic() > deadline:
                    raise GateProducerError("counter_unavailable") from None
                time.sleep(0.002)

    def __exit__(self, *exc) -> None:
        self._path.unlink(missing_ok=True)
