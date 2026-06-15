from __future__ import annotations

import json
import atexit
import os
import subprocess
import threading
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List


FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
HELPER_DIR = Path(__file__).resolve().parent / "poseidon_helper"
HELPER_EXE = HELPER_DIR / "target" / "release" / "blind-ledger-poseidon-helper.exe"
HELPER_CRATE = "pso-poseidon"
HELPER_CRATE_VERSION = "0.3.6"


def _cargo_exe() -> str:
    candidate = Path.home() / ".cargo" / "bin" / "cargo.exe"
    return str(candidate if candidate.exists() else "cargo")


@lru_cache(maxsize=1)
def ensure_helper_built() -> Path:
    sources = [HELPER_DIR / "src" / "main.rs", HELPER_DIR / "Cargo.toml"]
    needs_build = not HELPER_EXE.exists()
    if not needs_build:
        exe_mtime = HELPER_EXE.stat().st_mtime
        needs_build = any(source.exists() and source.stat().st_mtime > exe_mtime for source in sources)
    if needs_build:
        subprocess.run(
            [_cargo_exe(), "build", "--release"],
            cwd=HELPER_DIR,
            text=True,
            capture_output=True,
            check=True,
        )
    return HELPER_EXE


def _normalize_field(value: int) -> str:
    value = int(value)
    if value < 0:
        raise ValueError("Poseidon field inputs must be non-negative")
    return str(value % FIELD_MODULUS)


def _poseidon_many_once(normalized: List[List[str]]) -> List[int]:
    proc = subprocess.run(
        [str(ensure_helper_built())],
        input=json.dumps(normalized),
        text=True,
        capture_output=True,
        check=True,
    )
    return [int(value) for value in json.loads(proc.stdout)]


class _PoseidonWorker:
    def __init__(self) -> None:
        self.proc = subprocess.Popen(
            [str(ensure_helper_built()), "--server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()

    def request(self, normalized: List[List[str]]) -> List[int]:
        if self.proc.stdin is None or self.proc.stdout is None or self.proc.poll() is not None:
            raise RuntimeError("poseidon helper worker is not running")
        self.proc.stdin.write(json.dumps(normalized, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("poseidon helper worker closed stdout")
        response = json.loads(line)
        if "error" in response:
            raise RuntimeError(str(response["error"]))
        return [int(value) for value in response["ok"]]


_worker: _PoseidonWorker | None = None
_worker_lock = threading.Lock()


def _close_worker() -> None:
    global _worker
    if _worker is not None:
        _worker.close()
        _worker = None


atexit.register(_close_worker)


def poseidon_many(rows: Iterable[Iterable[int]]) -> List[int]:
    normalized = [[_normalize_field(value) for value in row] for row in rows]
    if os.environ.get("BLIND_LEDGER_POSEIDON_ONESHOT") == "1":
        return _poseidon_many_once(normalized)
    global _worker
    with _worker_lock:
        if _worker is None:
            _worker = _PoseidonWorker()
        try:
            return _worker.request(normalized)
        except Exception:
            _close_worker()
            return _poseidon_many_once(normalized)


def poseidon_hash(fields: Iterable[int]) -> int:
    return poseidon_many([fields])[0]
