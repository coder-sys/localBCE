"""The gate's decide layer at stage 1 (decide-layer-v1 section 4): one cold ``gate_rules`` run per shard batch, synthetic,
activation=false.

The frame is the vector directive text (F2(a)): the tenant's snapshot header, then ``load`` of the shard's sealed
``adds`` against the newest sealed header's state digest (the anchor, read from the signed store, never from memory),
then the registry's ``owners`` answer and the lines.  Lean folds the adds onto the genesis sets dated ``asof`` and
decides only if they hash to the anchor; else the shard decides nothing (``state_mismatch``).  Every outcome, the
state digest after the batch, its ``adds`` and the ids to free come from Lean; Python holds no policy and never
decodes the rows.  At genesis (no sealed batch) the header's empty sets are the shard's sets.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import NamedTuple, Sequence

from app import right_rail_gate_codec as gate
from app import right_rail_gate_idreg as idreg
from app import right_rail_gate_producer as producer


class GateDecideError(RuntimeError):
    """``state_mismatch``: the sealed adds do not hash to the signed anchor; ``frame_injection``: a head line or line
    body holds a line break (it could add directives after the real ``load``); ``genesis_sets``: the registry settled
    ids for a shard with no sealed batch (``genesis()`` starting sets, which load cannot carry until L4);
    ``rules_refused``: any other refusal, timeout included.  ``frame_injection`` and ``genesis_sets`` come before the
    registry reserve, so they write nothing.  ``commit``: ``already_sealed``, the answer's batch is sealed;
    ``settle_pending``, sealed but not settled (no token out; the next ``decide`` settles it, never re-commit)."""


class Answer(NamedTuple):
    lines: list[str]  # ``RULES_LINE`` bodies, one per line, waiting lines included
    free: list[int]
    digest: bytes  # the state digest after the batch: the next header's ``state_digest``
    adds: bytes
    idreg: tuple[int, bytes]  # the registry's (n, head) after the reserve


def decide(exe: str, frame: Path, head: Sequence[str], asof: int, prod: producer.ShardProducer, reg: idreg.IdRegistry,
           k: int, ids: Sequence[int], lines: Sequence[str]) -> Answer:
    """Settle shard ``k``'s previous batch and reserve ``ids`` (the registry transaction), then decide ``lines`` (the
    ``line`` directive bodies) against the shard's verified sets."""
    if any("\n" in s or "\r" in s for s in [*head, *lines]):
        raise GateDecideError("frame_injection")
    anchor = prod.anchor()
    if anchor is None and reg.settled(k):
        raise GateDecideError("genesis_sets")
    owners, n, reg_head = reg.reserve(k, ids, sealed=prod.sealed_frees())
    frame.write_text("\n".join([*head, "case batch", *([f"load {asof} {prod.sealed_adds().hex() or '-'} {anchor.hex()}"] if anchor else []),
                                "owners " + " ".join([str(k)] + [f"{i}:{s}:{int(w)}" for i, s, w in owners]),
                                *(f"line {line}" for line in lines), "commit", "end 0"]), "utf-8")
    try:
        out = subprocess.run([exe, str(frame)], capture_output=True, text=True, timeout=600).stdout.splitlines()
    except subprocess.TimeoutExpired as e:
        raise GateDecideError("rules_refused") from e
    got: dict[str, list[str]] = {}
    for row in out:
        tag, _, body = row.partition(" ")
        got.setdefault(tag, []).append(body)
    if "RULES_VECTORS=PASS checked=0 expected=0 failed=0" not in out or {"RULES_FREE", "RULES_DIGEST", "RULES_ADDS"} - got.keys():
        raise GateDecideError("state_mismatch" if "RULES_STATE_MISMATCH" in got else "rules_refused")
    return Answer(got.get("RULES_LINE", []), [int(i) for i in got["RULES_FREE"][0].split()], bytes.fromhex(got["RULES_DIGEST"][0]),
                  bytes.fromhex(got["RULES_ADDS"][0]), (n, reg_head))


def commit(prod: producer.ShardProducer, reg: idreg.IdRegistry, k: int, program: str, leaves: Sequence[gate.TokenLeaf],
           ans: Answer, created_at: int):
    """Seal the decided batch, settle it in the registry, and only then return (checkpoint, signed, tokens).  The order is
    the rollback check: before any token is out, a SETTLE follows the batch's RESERVE rows, so a store (with or without its
    mark) restored to before the batch is ``registry_rewound`` at boot and at each ``decide``.  A crash or a refused
    settle between the two loses nothing: no token is out, and the next ``decide`` settles the sealed batch first.  An
    answer with adds reserved rows ending at its own n, so a newest batch sealed at that n is this answer: a second seal
    would put its ids in two token sets and its adds twice into the load."""
    if ans.adds and (prod.sealed_frees() or (0,))[0] == ans.idreg[0]:
        raise GateDecideError("already_sealed")
    out = prod.commit(program, leaves, state_digest=ans.digest, created_at=created_at, idreg=ans.idreg, free=ans.free,
                      adds=ans.adds)
    try:
        reg.settle(k, ans.idreg[0], ans.free)
    except idreg.IdRegistryError as error:
        raise GateDecideError("settle_pending") from error
    return out
