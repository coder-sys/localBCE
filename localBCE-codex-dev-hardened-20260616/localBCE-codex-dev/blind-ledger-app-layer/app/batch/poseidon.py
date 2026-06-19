from __future__ import annotations

import atexit
import hashlib
import json
import os
import subprocess
import tempfile
import threading
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List


FIELD_MODULUS = 2**251 + 17 * 2**192 + 1
HELPER_DIR = Path(__file__).resolve().parent / "poseidon_helper"
HELPER_CRATE = "starknet-crypto"
HELPER_CRATE_VERSION = "0.8.1"
MAX_POSEIDON_ROWS = 4096
MAX_POSEIDON_FIELDS_PER_ROW = 128
DOMAIN_TAG_BASE = 2**200

DOMAIN_TAGS = {
    "claim_source": DOMAIN_TAG_BASE + 1,
    "oracle": DOMAIN_TAG_BASE + 2,
    "normalized_facts": DOMAIN_TAG_BASE + 3,
    "fee": DOMAIN_TAG_BASE + 4,
    "address": DOMAIN_TAG_BASE + 5,
    "nullifier": DOMAIN_TAG_BASE + 6,
    "payment": DOMAIN_TAG_BASE + 7,
    "ruleset": DOMAIN_TAG_BASE + 8,
    "denial_attestation": DOMAIN_TAG_BASE + 9,
    "forced_inclusion": DOMAIN_TAG_BASE + 10,
    "data_availability": DOMAIN_TAG_BASE + 11,
    "batch": DOMAIN_TAG_BASE + 12,
}
DOMAIN_VALUES = frozenset(DOMAIN_TAGS.values())
POSEIDON_KAT_EXPECTED = 332184976776898736928338766737013820391112203641325445640782612418251159048


def domain_tag(name: str) -> int:
    try:
        return DOMAIN_TAGS[name]
    except KeyError as exc:
        raise ValueError(f"unknown Poseidon domain tag: {name}") from exc


def _helper_target_dir() -> Path:
    override = os.environ.get("BLIND_LEDGER_POSEIDON_TARGET_DIR") or os.environ.get("CARGO_TARGET_DIR")
    if override:
        if os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"} and os.environ.get(
            "BL_ALLOW_CUSTOM_POSEIDON_TARGET"
        ) != "1":
            raise RuntimeError("custom Poseidon target directory is disabled in production")
        return Path(override).expanduser().resolve()
    if os.name == "nt":
        digest = hashlib.sha256(str(HELPER_DIR).encode("utf-8")).hexdigest()[:12]
        return Path(tempfile.gettempdir()) / f"blind-ledger-stark-poseidon-{digest}"
    return HELPER_DIR / "target"


def _helper_exe() -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return _helper_target_dir() / "release" / f"blind-ledger-poseidon-helper{suffix}"


def _cargo_exe() -> str:
    candidate = Path.home() / ".cargo" / "bin" / "cargo.exe"
    return str(candidate if candidate.exists() else "cargo")


@lru_cache(maxsize=1)
def ensure_helper_built() -> Path:
    helper_exe = _helper_exe()
    sources = [HELPER_DIR / "src" / "main.rs", HELPER_DIR / "Cargo.toml"]
    needs_build = not helper_exe.exists()
    if not needs_build:
        exe_mtime = helper_exe.stat().st_mtime
        needs_build = any(source.exists() and source.stat().st_mtime > exe_mtime for source in sources)
    if needs_build:
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(_helper_target_dir())
        subprocess.run(
            [_cargo_exe(), "build", "--release", "--locked"],
            cwd=HELPER_DIR,
            env=env,
            text=True,
            capture_output=True,
            check=True,
        )
    verify_poseidon_helper(helper_exe)
    return helper_exe


def _normalize_field(value: int) -> str:
    value = int(value)
    if value < 0 or value >= FIELD_MODULUS:
        raise ValueError("Cairo field inputs must be canonical field elements")
    return str(value)


def _validate_domain(row: List[str]) -> None:
    if not row:
        raise ValueError("Poseidon row must contain a domain tag")
    if len(row) < 2:
        raise ValueError("Poseidon row must contain domain tag and arity")
    if len(row) > MAX_POSEIDON_FIELDS_PER_ROW:
        raise ValueError("Poseidon row has too many fields")
    if int(row[0]) not in DOMAIN_VALUES:
        raise ValueError("Poseidon row missing recognized domain tag")
    arity = int(row[1])
    if arity != len(row) - 2:
        raise ValueError("Poseidon row arity mismatch")


def _domain_row(domain: str, fields: Iterable[int]) -> list[int]:
    payload = list(fields)
    return [domain_tag(domain), len(payload), *payload]


def _assert_row_limits(rows: List[List[str]]) -> None:
    if len(rows) > MAX_POSEIDON_ROWS:
        raise ValueError("Poseidon request has too many rows")
    for row in rows:
        _validate_domain(row)


def _poseidon_many_once(normalized: List[List[str]]) -> List[int]:
    proc = subprocess.run(
        [str(ensure_helper_built())],
        input=json.dumps(normalized),
        text=True,
        capture_output=True,
        check=True,
    )
    return [int(value) for value in json.loads(proc.stdout)]


def verify_poseidon_helper(helper_exe: Path | None = None) -> None:
    helper = helper_exe or _helper_exe()
    kat_row = _domain_row("claim_source", [1, 2, 3])
    normalized = [[_normalize_field(value) for value in kat_row]]
    proc = subprocess.run(
        [str(helper)],
        input=json.dumps(normalized),
        text=True,
        capture_output=True,
        check=True,
    )
    value = int(json.loads(proc.stdout)[0])
    if value != POSEIDON_KAT_EXPECTED:
        raise RuntimeError("poseidon_helper_kat_mismatch")


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
    _assert_row_limits(normalized)
    if os.environ.get("BLIND_LEDGER_POSEIDON_ONESHOT") == "1":
        return _poseidon_many_once(normalized)
    global _worker
    with _worker_lock:
        if _worker is None:
            _worker = _PoseidonWorker()
        try:
            return _worker.request(normalized)
        except Exception as exc:
            _close_worker()
            if os.environ.get("BL_ALLOW_POSEIDON_WORKER_FALLBACK") == "1":
                return _poseidon_many_once(normalized)
            raise RuntimeError("poseidon helper worker failed closed") from exc


def poseidon_hash(fields: Iterable[int]) -> int:
    return poseidon_many([fields])[0]


def domain_poseidon_hash(domain: str, fields: Iterable[int]) -> int:
    return poseidon_hash(_domain_row(domain, fields))
