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

from app import right_rail_gate_idreg as idreg
from app import right_rail_gate_producer as producer


class GateDecideError(RuntimeError):
    """``state_mismatch``: the sealed adds do not hash to the signed anchor; ``rules_refused``: any other refusal."""


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
    owners, n, reg_head = reg.reserve(k, ids, sealed=prod.sealed_frees())
    anchor = prod.anchor()
    frame.write_text("\n".join([*head, "case batch", *([f"load {asof} {prod.sealed_adds().hex() or '-'} {anchor.hex()}"] if anchor else []),
                                "owners " + " ".join([str(k)] + [f"{i}:{s}:{int(w)}" for i, s, w in owners]),
                                *(f"line {line}" for line in lines), "commit", "end 0"]), "utf-8")
    out = subprocess.run([exe, str(frame)], capture_output=True, text=True, timeout=600).stdout.splitlines()
    got: dict[str, list[str]] = {}
    for row in out:
        tag, _, body = row.partition(" ")
        got.setdefault(tag, []).append(body)
    if "RULES_VECTORS=PASS checked=0 expected=0 failed=0" not in out or "RULES_DIGEST" not in got:
        raise GateDecideError("state_mismatch" if "RULES_STATE_MISMATCH" in got else "rules_refused")
    return Answer(got.get("RULES_LINE", []), [int(i) for i in got["RULES_FREE"][0].split()], bytes.fromhex(got["RULES_DIGEST"][0]),
                  bytes.fromhex(got["RULES_ADDS"][0]), (n, reg_head))
