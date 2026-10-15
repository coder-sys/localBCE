"""The gate's decide layer at stage 1 (decide-layer-v1 section 4): one cold ``gate_rules`` run per shard batch, synthetic,
activation=false.

The frame is the vector directive text (F2(a)): the tenant's snapshot header, then ``load`` of the shard's sealed
``adds`` against the newest sealed header's state digest (the anchor, read from the signed store, never from memory),
then the registry's ``owners`` answer and the lines.  Lean folds the adds onto the genesis sets dated ``asof`` and
decides only if they hash to the anchor; else the shard decides nothing (``state_mismatch``).  A worker holding the anchor's state is sent
``resume ANCHOR H`` instead (H: SHA3-512 of the adds, which binds their order); a ``RULES_STATE_MISMATCH`` reply falls back to ``load``.  Every outcome, the
state digest after the batch, its ``adds`` and the ids to free come from Lean; Python holds no policy and never
decodes the rows.  At genesis (no sealed batch) the header's empty sets are the shard's sets.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from typing import NamedTuple, Sequence

from app import minimal_clearance_verifier_process as process

from app import right_rail_gate_codec as gate
from app import right_rail_gate_idreg as idreg
from app import right_rail_gate_producer as producer


class GateDecideError(RuntimeError):
    """``state_mismatch``: the sealed adds do not hash to the signed anchor; ``frame_injection``: a head line or line
    body holds a line break (it could add directives after the real ``load``); ``genesis_sets``: the registry settled
    ids for a shard with no sealed batch (``genesis()`` starting sets, which load cannot carry until L4);
    ``rules_refused``: any other refusal, timeout included.  ``frame_injection`` and ``genesis_sets`` come before the
    registry reserve, so they write nothing.  ``commit``: ``stale_answer``, a batch was sealed or the shard's in-flight
    rows changed since the answer (nothing sealed; decide again); ``settle_pending``, sealed but not settled (no token
    out; the next ``decide`` settles it, never re-commit); ``registry_restored``, a HOLD answer (nothing to seal)."""


FRAME_CAP = 1 << 20  # the largest frame the worker takes; Lean's own limit (``process.WORKER_MAX_FRAME_BYTES``) is far above it


class RulesWorker:
    """A long-lived ``gate_rules_worker`` (the one-shot's process start and arena are paid once, not per batch): u32 BE frames
    of the same vector text, answered with the same output lines minus ``RULES_SOURCE``; the one-shot runs ``Run.runText``, the worker ``Resident.frame`` (a ``resume`` line answers as the full ``load``; ``holds`` is the digest of the state it keeps).  Any
    failure (a killed or hung worker, a stray byte, an oversize answer) closes it and raises ``rules_refused``; the next call
    starts a fresh one.  A frame over ``FRAME_CAP`` goes to the one-shot exe (``decide``), by size, never after a
    failure: a decide takes some 700 times its frame in memory (measured), so the 1 GB job cap stops a batch near 1.5 MiB."""

    TIMEOUT_SECONDS = 600.0
    RECYCLE_COMMIT_BYTES = 400_000_000  # replaced between batches, never mid-batch, so slow growth never reaches the job cap
    JOB_MEMORY_CAP_BYTES = 1_000_000_000

    def __init__(self, exe: Path) -> None:
        self.exe, self._worker, self._workspace, self._lock, self.holds = exe, None, None, threading.Lock(), None

    def close(self) -> None:
        with self._lock:
            self._close()

    def _close(self) -> None:
        worker, workspace, self._worker, self._workspace, self.holds = self._worker, self._workspace, None, None, None
        if worker is not None:
            worker.close()
        if workspace is not None:
            shutil.rmtree(workspace, ignore_errors=True)

    def run(self, data: bytes) -> list[str]:
        with self._lock:
            try:
                if self._worker is not None and not self._worker.alive:
                    self._close()
                if self._worker is None:
                    exe = self.exe.read_bytes()
                    self._workspace = Path(tempfile.mkdtemp(prefix="rr-rules-"))
                    self._worker = process.launch_contained_worker(
                        self.exe, workspace=self._workspace, job_memory_cap_bytes=self.JOB_MEMORY_CAP_BYTES,
                        expected_executable_size_bytes=len(exe), expected_executable_sha256=hashlib.sha256(exe).digest())
                answer = self._worker.exchange(data, response_cap_bytes=process.WORKER_MAX_FRAME_BYTES,
                                               timeout_seconds=self.TIMEOUT_SECONDS).decode("utf-8")
                if self._worker.commit_bytes() > self.RECYCLE_COMMIT_BYTES:
                    self._close()
                return answer.splitlines()
            except Exception as error:  # a timeout, an OS error or bad UTF-8 is a refusal too, never an untyped escape
                self._close()
                raise GateDecideError("rules_refused") from error


    def hold(self, digest: bytes | None) -> None:  # the state digest the last frame left; a recycled worker holds none
        with self._lock:
            self.holds = digest if self._worker is not None else None


class Answer(NamedTuple):
    lines: list[str]  # ``RULES_LINE`` bodies, one per line, waiting lines included
    free: list[int]
    digest: bytes  # the state digest after the batch: the next header's ``state_digest``
    adds: bytes
    idreg: tuple[int, bytes]  # the registry's (n, head) after the reserve
    seen: bytes | None  # the shard's last sealed checkpoint digest before the reserve
    rows: list[int]  # the registry rows the reserve wrote: the shard's whole in-flight set after it


def _reads_ok(rows: list[str]) -> bool:
    """One ``RULES_READS``, lowercase hex of u32 today ‖ four 64-byte pins ‖ u32 |P| ‖ P, P a READ-SET/v2 record."""
    try:
        b = bytes.fromhex(rows[0]) if len(rows) == 1 else b""
    except ValueError:
        return False
    return (len(b) >= 264 and b.hex() == rows[0] and int.from_bytes(b[260:264], "big") == len(b) - 264
            and b[264:].startswith(b"RR/GATE/READ-SET/v2\0"))


def _hold(lines: Sequence[str], reason: str) -> Answer:
    return Answer([f"{line} HOLD {reason}" for line in lines], [], b"", b"", (0, b""), None, [])


def decide(exe: str, frame: Path, head: Sequence[str], asof: int, prod: producer.ShardProducer | None,
           reg: idreg.IdRegistry | None, ids: Sequence[int], lines: Sequence[str], worker: RulesWorker | None = None) -> Answer:
    """Settle the producer's shard's previous batch and reserve ``ids`` (the registry transaction), then decide ``lines`` (the
    ``line`` directive bodies) against the shard's verified sets: on ``worker`` (no frame file) when the frame fits its cap,
    else on the one-shot ``exe``.  With no registry (a refused boot: design idreg-restore 4) every line is HOLD
    ``registry_restored`` and nothing is reserved, decided, sealed or checkpointed; a registry whose nonce a refused boot
    fenced HOLDs every line ``registry_not_booted`` the same way."""
    if any("\n" in s or "\r" in s for s in [*head, *lines]):
        raise GateDecideError("frame_injection")
    if reg is None:
        return _hold(lines, "registry_restored")
    k, anchor = prod.shard, prod.anchor()
    if anchor is None and reg.settled(k):
        raise GateDecideError("genesis_sets")
    seen = prod.tip()
    try:
        owners, n, reg_head = reg.reserve(k, ids, sealed=prod.sealed_frees())
    except idreg.IdRegistryError as e:  # a refused boot fenced this handle's nonce
        if str(e) != "registry_not_booted":
            raise
        return _hold(lines, str(e))
    f = len({i for i, s, w in owners if s == k and not w})  # fresh RESERVE rows: the reserve's last f, nothing before in flight
    adds, served = prod.sealed_adds(), []

    def run(sync: str | None) -> list[str]:
        data = "\n".join([*head, "case batch", *([sync] if sync else []),
                          "owners " + " ".join([str(k)] + [f"{i}:{s}:{int(w)}" for i, s, w in owners]),
                          *(f"line {line}" for line in lines), "commit", "end 0"]).encode("utf-8")
        served[:] = [worker is not None and len(data) <= FRAME_CAP]
        if served[0]:
            return worker.run(data)
        frame.write_bytes(data)
        try:
            return subprocess.run([exe, str(frame)], capture_output=True, text=True, timeout=600).stdout.splitlines()
        except subprocess.TimeoutExpired as e:
            raise GateDecideError("rules_refused") from e

    out = run(f"resume {anchor.hex()} {hashlib.sha3_512(adds).hexdigest()}") if worker is not None and anchor and worker.holds == anchor else []
    if not out or any(r.startswith("RULES_STATE_MISMATCH") for r in out):
        if worker is not None and worker.holds:
            worker.close()  # the old state is freed before the load builds the new one: no 2x peak
        out = run(f"load {asof} {adds.hex() or '-'} {anchor.hex()}" if anchor else None)
    got: dict[str, list[str]] = {}
    for row in out:
        tag, _, body = row.partition(" ")
        got.setdefault(tag, []).append(body)
    if "RULES_VECTORS=PASS checked=0 expected=0 failed=0" not in out or {"RULES_FREE", "RULES_DIGEST", "RULES_ADDS"} - got.keys() \
            or not _reads_ok(got.get("RULES_READS", [])):
        raise GateDecideError("state_mismatch" if "RULES_STATE_MISMATCH" in got else "rules_refused")
    digest = bytes.fromhex(got["RULES_DIGEST"][0])
    if worker is not None and served[0]:
        worker.hold(digest if anchor is not None else None)  # genesis keeps no adds stream: the next batch loads
    return Answer(got.get("RULES_LINE", []), [int(i) for i in got["RULES_FREE"][0].split()], digest,
                  bytes.fromhex(got["RULES_ADDS"][0]), (n, reg_head), seen, list(range(n - f + 1, n + 1)))


def commit(prod: producer.ShardProducer, reg: idreg.IdRegistry, program: str, leaves: Sequence[gate.TokenLeaf],
           ans: Answer, created_at: int):
    """Seal the decided batch, settle it in the registry, and only then return (checkpoint, signed, tokens).  The order is
    the rollback check: before any token is out, a SETTLE follows the batch's RESERVE rows, so a store (with or without its
    mark) restored to before the batch is ``registry_rewound`` at boot and at each ``decide``.  A crash or a refused
    settle between the two loses nothing: no token is out, and the next ``decide`` settles the sealed batch first.  The
    answer is sealed only while the shard's last seal and in-flight rows are those it saw: a later decide's reserve
    frees its ids (a seal would pay them while another shard may reserve them), and a re-commit of a sealed answer would
    put its ids in two token sets.  A HOLD answer (no state digest) is never sealed."""
    if not ans.digest:
        raise GateDecideError("registry_restored")
    if prod.tip() != ans.seen or reg.in_flight(prod.shard) != ans.rows:
        raise GateDecideError("stale_answer")
    out = prod.commit(program, leaves, state_digest=ans.digest, created_at=created_at, idreg=ans.idreg, free=ans.free,
                      adds=ans.adds)
    try:
        reg.settle(prod.shard, ans.rows, ans.free)
    except idreg.IdRegistryError as error:
        raise GateDecideError("settle_pending") from error
    return out
