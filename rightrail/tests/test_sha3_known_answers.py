"""Known-answer vectors for the engine's SHA3 paths (lean/BlindLedger/Gate/Engine3/Bench.lean, `engine3_bench kat`).

The expected digests come from Python's hashlib, independent of the Lean code.  Message lengths sit on both sides of the
SHA3-512 rate (72) and the SHA3-256 rate (136) block edges, plus a multi-block message.  The fused SHA3-512 with an offset
range and a prefix, `Bin.HB`, the SHA3-256 spec and the one-block key digest are each checked.  Synthetic, non-PHI."""
import hashlib
import subprocess
import unittest

from tests import test_flat_worker as fw

LENGTHS = (0, 1, 71, 72, 73, 135, 136, 137, 143, 144, 145, 5000)
KEY_DOM = b"RR/GATE/KEY2/v1\x00"
SEC = bytes((i * 29 + 5) % 256 for i in range(32))


def msg(n: int, salt: int = 0) -> bytes:
    return bytes((i * 131 + n * 7 + salt) % 256 for i in range(n))


def hx(b: bytes) -> str:
    return b.hex() or "-"


class KnownAnswers(unittest.TestCase):
    def test_vectors(self):
        lines, want = [], []
        for n in LENGTHS:
            m = msg(n)
            for op, expect in (("s512", hashlib.sha3_512(m)), ("hb", hashlib.sha3_512(m)), ("s256", hashlib.sha3_256(m))):
                lines.append(f"{op} {hx(m)}")
                want.append(expect.hexdigest())
            for pre_len in (0, 5, 72):
                pre, junk = msg(pre_len, 1), msg(3, 2)
                lines.append(f"s512r {hx(pre)} {hx(junk)} {hx(m)}")
                want.append(hashlib.sha3_512(pre + m).hexdigest())
            if n <= 86:  # the one-block key digest (`shortMax`)
                lines.append(f"key256 {hx(SEC)} {hx(m)}")
                want.append(hashlib.sha3_256(KEY_DOM + SEC + m).hexdigest())
        run = subprocess.run([str(fw.BIN / "engine3_bench.exe"), "kat"], input="\n".join(lines) + "\n", capture_output=True,
                             text=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        got = run.stdout.split()
        self.assertEqual(len(got), len(want), run.stdout + run.stderr)
        bad = [lines[i][:60] for i in range(len(want)) if got[i] != want[i]]
        self.assertEqual(bad, [], f"{len(bad)} of {len(want)} digests differ")


if __name__ == "__main__":
    unittest.main()
