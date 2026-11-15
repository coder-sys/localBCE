"""Signer-free decision check (test-only tool, not a unittest; docs/integration/TRUNK_STEP2_FRAME_DESIGN.md 7.1): the PAIRS
corpus of tests/test_gate_throughput.py (``corpus()``, 2,000 lines, 4 lines a payment, 5% of lines dated outside enrollment)
for both corpora (``RR_GATE_BENCH_CORPUS`` unset and ``realistic``) at batch sizes 100 and 2000, each batch's request frame
built directly (``_gate_shards.request`` and ``right_rail_gate_decide.request_frame``, as test_flat_worker does) under the
signer-free authority (``RR_GATE_UNSIGNED=1``: _gate_authority_unsigned), run through ``gate_engine_unsigned`` (one resident
process per corpus, launched with the contained worker's environment), the head chained batch to batch.  It writes, per
corpus, the sorted (line id, "OUTCOME REASONS") pairs and their digest, computed by test_gate_throughput's own
``pairs_digest`` (the one ``PAIRS_DIGEST`` pins), to the JSON file named on the command line.

    cd rightrail && python -m tests.gate_unsigned_pairs OUT.json [ENGINE_EXE]

Any refusal stops the run with a nonzero exit and writes nothing: an answer that is not OK, a whole-batch HOLD (grant or key
set not admitted), an unreadable answer, a dead engine, any engine stderr, a wrong key-set pin in the authority record, a head
that does not chain, or a corpus line with no decision.  The pairs carry no engine hash, so the before and after trees of
step 2 must give the same file (``digest`` per corpus); ``matches_PAIRS_DIGEST`` is expected, not required (7.1 item 6).
Synthetic, nonpayment, non-PHI."""

from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_SWITCH = os.environ.get("RR_GATE_UNSIGNED")
if _SWITCH not in (None, "1"):
    raise SystemExit(f"STOP RR_GATE_UNSIGNED={_SWITCH!r}: this tool runs only on the signer-free authority (1)")
os.environ["RR_GATE_UNSIGNED"] = "1"

from app import right_rail_gate_chain as chain  # noqa: E402
from app import right_rail_gate_codec as gate  # noqa: E402
from app import right_rail_gate_decide as decider  # noqa: E402
from tests import _gate_shards as g  # noqa: E402
from tests import test_gate_throughput as tg  # noqa: E402

UNSIGNED = Path(g.rules.LEAN) / ".lake" / "build" / "bin" / "gate_engine_unsigned.exe"
LINES, BATCHES, CORPORA = 2000, (100, 2000), ((False, None), (True, "realistic"))
SHARD = 0
TIMEOUT_SECONDS = 600  # per answer and for the exit, as RulesWorker.run_frame


class Refused(Exception):
    """A refusal anywhere in a run: the check fails, and no pairs are written."""


def _env(workspace: Path) -> dict[str, str]:
    """The contained worker's environment (minimal_clearance_verifier_process._environment_block): no RR_FLAT_* or other
    variable of this process reaches the engine."""
    system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    windir = os.environ.get("WINDIR") or system_root
    if not system_root or not windir:
        raise Refused("no SystemRoot/WINDIR to build the contained worker's environment")
    return {"SystemRoot": system_root, "WINDIR": windir, "PATH": str(Path(system_root) / "System32"),
            "LEAN_ABORT_ON_PANIC": "1", "TEMP": str(workspace), "TMP": str(workspace)}


class Engine:
    """``gate_engine_unsigned DIR 0`` over a pipe, one process for a whole corpus (as the throughput bench's one RulesWorker)."""

    def __init__(self, exe: Path, store: Path, workspace: Path) -> None:
        self.err = open(workspace / "engine.stderr", "w+b")
        self.p = subprocess.Popen([str(exe), str(store.absolute()).replace("\\", "/"), str(SHARD)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=self.err, cwd=workspace, env=_env(workspace))

    def _read_answer(self) -> bytes:
        head = self.p.stdout.read(4)
        return self.p.stdout.read(struct.unpack(">I", head)[0]) if len(head) == 4 else b""

    def send(self, data: bytes, n: int) -> bytes:
        try:
            self.p.stdin.write(struct.pack(">I", len(data) + 1) + b"\x04" + data)
            self.p.stdin.flush()
        except OSError as error:
            raise Refused(f"batch {n}: the engine pipe failed: {error!r}") from error
        box: list = []
        reader = threading.Thread(target=lambda: box.append(self._read_answer()), daemon=True)
        reader.start()
        reader.join(TIMEOUT_SECONDS)  # as RulesWorker.run_frame: a stuck engine is a refusal, not a hang
        if reader.is_alive() or not box:
            self.p.kill()
            raise Refused(f"batch {n}: no answer within {TIMEOUT_SECONDS} s (engine killed)")
        out = box[0]
        self.err.flush()
        self.err.seek(0)
        said = self.err.read()
        if said:
            raise Refused(f"batch {n}: the engine wrote stderr: {said[-600:]!r}")
        if not out:
            raise Refused(f"batch {n}: no answer (engine exit {self.p.poll()})")
        return out

    def close(self) -> None:
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            code = self.p.wait(timeout=TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
            self.err.close()
            raise Refused(f"the engine did not exit within {TIMEOUT_SECONDS} s (killed)")
        self.err.close()
        if code != 0:
            raise Refused(f"the engine exited {code}")


def run(exe: Path, release: bytes, realistic: bool, batch: int) -> dict[int, tuple[str, bool]]:
    """Line id -> ("OUTCOME REASONS", dated outside enrollment?) for the whole corpus, as test_gate_throughput collects
    ``statuses`` (whole-answer HOLD rows are refusals here)."""
    statuses: dict[int, tuple[str, bool]] = {}
    with mock.patch.dict(os.environ, {"RR_GATE_BENCH_CORPUS": "realistic"} if realistic else {}), \
            mock.patch.object(tg, "N", LINES), mock.patch.object(tg, "BATCH", batch), \
            tempfile.TemporaryDirectory(prefix="rr-unsigned-") as tmp:
        if not realistic:
            os.environ.pop("RR_GATE_BENCH_CORPUS", None)  # restored by patch.dict on exit
        work = Path(tmp)
        (work / "ws").mkdir()
        eng = Engine(exe, work / "idx0", work / "ws")
        try:
            pin, keys, grant = g.PIN, g.KEYS, g.GRANT
            prev, floors = chain.genesis(SHARD, g.ASOF, pin), (0, 0)
            for n, (payments, bad) in enumerate(tg.corpus(), 1):
                requests = [g.request(p, SHARD, v, bad) for p, v in payments.items()]
                if len(requests) > gate.MAX_BATCH:
                    raise Refused(f"batch {n}: {len(requests)} requests, over MAX_BATCH ({gate.MAX_BATCH})")
                frame = decider.request_frame(g.HEAD, SHARD, n, g.ASOF, prev, pin, floors, keys, grant, release, (),
                                              [gate.encode_decide_request(r) for r in requests])
                out = eng.send(frame, n)
                try:
                    why, recs, new, root, auth, pays, adds = decider._answer(out, frame)
                except decider.GateDecideError as error:
                    raise Refused(f"batch {n}: unreadable answer: {error}") from error
                if why is not None:
                    raise Refused(f"batch {n}: refused: {why}")
                stored = auth + root + b"".join(adds)  # as _decide_frame: the chain step body the producer stores
                if auth[:len(pin)] != pin:
                    raise Refused(f"batch {n}: keyset_pin")
                if chain.step_adds(prev, stored) != new:
                    raise Refused(f"batch {n}: chain_mismatch")
                floors = tuple(max(a, b) for a, b in zip(floors, chain.floors_of(stored)))  # tenant.raise_floors
                covered = [(r.payment_id, len(r.lines)) for r, y in zip(requests, pays) if "SCOPE" not in y.reasons]
                owners = [(pid, i) for pid, size in covered for i in range(size)]  # _decide_frame's owners
                status = {}
                for rec in recs:  # g.decide_batch: a record names its line by position
                    pid, at = owners[rec.index]
                    status[payments[int(pid[4:])][at]] = f"{rec.outcome} {','.join(rec.reasons) or '-'}"
                statuses.update({i: (s, i in bad) for i, s in status.items()})
                prev = new
        except BaseException:
            try:  # keep the batch's own refusal: a close failure after it must not replace it
                eng.p.kill()
                eng.close()
            except Exception:
                pass
            raise
        eng.close()
    if sorted(statuses) != list(range(1, LINES + 1)):
        raise Refused(f"{len(set(range(1, LINES + 1)) - set(statuses))} corpus lines have no decision")
    if any(s.startswith("ALLOW") for s, b in statuses.values() if b):
        raise Refused("a line dated outside enrollment was ALLOWed")
    return statuses


def main(argv: list[str]) -> int:
    if len(argv) not in (1, 2):
        print(__doc__, file=sys.stderr)
        return 64
    out, exe = Path(argv[0]), Path(argv[1]) if len(argv) == 2 else UNSIGNED
    if not exe.is_file():
        raise SystemExit(f"STOP {exe} is missing: build it with `lake build gate_engine_unsigned` in lean/")
    if not g._authority()["unsigned"]:
        raise SystemExit("STOP the harness did not select the signer-free authority")
    body = exe.read_bytes()
    release = gate.sha3_512(body)  # the release a host names for the program it launched (RulesWorker.launched_release)
    result = {"tool": "tests/gate_unsigned_pairs.py", "engine": str(exe), "engine_sha3_512": release.hex(), "lines": LINES,
              "corpora": {}}
    try:
        for realistic, label in CORPORA:
            for batch in BATCHES:
                statuses = run(exe, release, realistic, batch)
                digest = tg.pairs_digest(statuses)
                result["corpora"][f"{label or 'default'}/{batch}"] = {
                    "realistic": realistic, "batch": batch, "digest": digest,
                    "matches_PAIRS_DIGEST": digest == tg.PAIRS_DIGEST[realistic, batch],
                    "pairs": [[i, s] for i, (s, _) in sorted(statuses.items())]}
                print(f"UNSIGNED_PAIRS {label or 'default'} batch={batch} digest={digest} "
                      f"matches_PAIRS_DIGEST={digest == tg.PAIRS_DIGEST[realistic, batch]}", flush=True)
    except Refused as error:
        print(f"UNSIGNED_PAIRS REFUSED: {error}", file=sys.stderr)
        return 1
    out.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
