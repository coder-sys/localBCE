"""A core past the per-core posting cap through the pinned engine: nothing on stderr (no "index out of bounds", no PANIC), and every
decision equals the one-shot rules model on the same lines.  Synthetic, nonpayment, non-PHI."""

import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import right_rail_gate_codec as gate  # noqa: E402
from app import right_rail_gate_decide as decider  # noqa: E402
from tests import _gate_shards as g  # noqa: E402
from tests import test_flat_worker as fw  # noqa: E402
from tests import test_right_rail_gate_formats as fx  # noqa: E402

LINES, BATCH = 6000, 2000


def corpus(i: int) -> tuple[gate.DecideRequest, str]:
    """One member, day and procedure for every line (one core), payee, rendering provider and units spread so no single key is capped."""
    key = g.member(fw.MEMBERS[0], 0)
    payee, rendering, units = i % 4, (i // 4) % 4, 1 + (i // 16) % 10
    cents, lid = 12500 * units, f"L{i:0>31}"
    line = gate.encode_line("FFS_CLAIM", lid, key, f"P{payee}", f"R{rendering}", 20270201, "C99213", units, cents)
    req = gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CLAIM", f"cmd-{i}", f"pay-{i}", key, f"P{payee}", cents, fx.PERIOD, (line,),
                             tuple(sorted((fx.D[2], fx.D[5]))))
    q = g.nat(fw.u16(fx.PROGRAM.encode()) + fw.u16(f"pay-{i}".encode()))
    row = f"{g.nat(lid.encode())}:{q} FFS_CLAIM {g.nat(key)} {g.nat(f'P{payee}'.encode())} {g.nat(f'R{rendering}'.encode())} 20270201 " \
          f"{g.nat(b'C99213')} {units} {cents}"
    return req, row


def run(exe: Path, tmp: Path):
    """Decisions per batch (as ``fw.status``), the model's rows per batch, and the engine's stderr as (line count, first lines)."""
    store = tmp / exe.stem
    store.mkdir()
    seen: list = [0, []]  # stderr lines, the first few of them (the engine can print millions)

    def drain(f) -> None:
        for x in f:
            seen[0] += 1
            if len(seen[1]) < 20:
                seen[1].append(x.decode("utf-8", "replace").rstrip())

    eng = fw.Engine.__new__(fw.Engine)
    eng.release = gate.sha3_512(fw.ENGINE.read_bytes())
    eng.p = subprocess.Popen([str(exe), str(store).replace("\\", "/"), "0"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    reader = threading.Thread(target=drain, args=(eng.p.stderr,))
    reader.start()
    data = decider.request_frame(g.HEAD, 0, 1, g.ASOF, fw.GENESIS, g.PIN, (0, 0), g.KEYS, g.GRANT, eng.release, (), [])
    why, _, head, _, _, _, _ = fw.read(data, eng.send(data))
    got, rows_by_batch = [], []
    for start in range(0, LINES, BATCH):
        made = [corpus(i) for i in range(start, start + BATCH)]
        data = decider.request_frame(g.HEAD, 0, 2 + start // BATCH, g.ASOF, head, g.PIN, fw.floors(head), g.KEYS, g.GRANT, eng.release, (),
                                     [gate.encode_decide_request(r) for r, _ in made])
        why, recs, head, _, _, _, _ = fw.read(data, eng.send(data))
        if why is not None:
            break
        got.append(fw.status(recs, [row for _, row in made]))
        rows_by_batch.append([row for _, row in made])
    eng.close()
    reader.join()
    return got, rows_by_batch, tuple(seen)


@unittest.skipUnless(os.name == "nt" and fw.ENGINE.is_file() and fw.ONE.is_file(), f"OVERCAP NOT RUN: {fw.ENGINE} or {fw.ONE} is missing")
class OverCapTests(unittest.TestCase):
    def test_core_past_the_cap_is_decided_like_the_model_with_a_clean_stderr(self) -> None:
        """The per-key engine (gate_engine) decides exactly as the one-shot rules model.  The rows-file engine (gate_hist3)
        caps per core: its first batch (core still under the cap) equals the model, and every line after the core passes capN rows is HOLD
        with POSTING_CAP.  All of them leave stderr empty."""
        for name in os.environ.get("RR_OVERCAP_EXES", "gate_engine,gate_hist3").split(","):
            with self.subTest(exe=name), tempfile.TemporaryDirectory() as tmp:
                got, rows, (count, first) = run(fw.BIN / f"{name}.exe", Path(tmp))
                print(f"OVERCAP {name}: stderr lines {count}, first {first[:20]}", flush=True)
                self.assertEqual(len(got), LINES // BATCH, "the engine refused or stopped")
                want = fw.one_shot(rows, Path(tmp))
                if name == "gate_hist3":
                    self.assertEqual(got[0], want[0])
                    for batch in got[1:]:
                        self.assertEqual({v.split()[0] for v in batch.values()}, {"HOLD"})
                        self.assertTrue(all("POSTING_CAP" in v.split()[1].split(",") for v in batch.values()))
                else:
                    self.assertEqual(got, want)
                self.assertEqual((count, first), (0, []), "the engine wrote to stderr")


if __name__ == "__main__":
    unittest.main()
