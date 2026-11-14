"""The engine's byte request decoder against the list decoder (`decodeReqFast`) on damaged frames.

Real frames (`request_frame`) are cut short, given oversize lengths, bit-flipped (with the digest left stale, and with it made
right again so the damage reaches the body) and replaced by random bytes.  `decode_fuzz` runs both decoders on every frame; they
must give the same refusal word, or the same request, and the run must exit 0.  Needs the exe: `lake build decode_fuzz`."""
import hashlib
import os
import random
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from app import right_rail_gate_decide as decider
from app import right_rail_gate_codec as gate
from tests import _gate_shards as g
from tests import test_flat_worker as fw

EXE = Path(os.environ.get("DECODE_FUZZ_EXE", fw.BIN / "decode_fuzz.exe"))
HDR = 82
DOMAIN = b"RR/GATE/FRAME/v1\x00"


def redigest(f: bytes) -> bytes:
    return f[:18] + hashlib.sha3_512(DOMAIN + f[HDR:]).digest() + f[HDR:] if len(f) >= HDR else f


def base_frames(rng: random.Random) -> list[bytes]:
    release = bytes(range(64))
    out = []
    for k, n in ((0, 1), (0, 3), (1, 5), (2, 0)):
        reqs, _ = fw.batch(rng, k, n)
        out.append(decider.request_frame(g.HEAD, 0, k + 1, g.ASOF, bytes(64), g.PIN, (0, 0), g.KEYS, g.GRANT, release, (),
                                         [gate.encode_decide_request(r) for r in reqs]))
    return out


def damaged(rng: random.Random, f: bytes) -> list[bytes]:
    out = [f[:rng.randrange(len(f))] for _ in range(40)] + [f[:HDR], f[:HDR - 1], f + b"\x00", f + bytes(rng.randrange(256) for _ in range(9))]
    for _ in range(300):                                    # bit flips: digest stale, then digest made right
        b = bytearray(f)
        for _ in range(rng.choice((1, 1, 2, 5))):
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
        out += [bytes(b), redigest(bytes(b))]
    for _ in range(100):                                    # a field set to an extreme value (lengths, counts), digest right
        b = bytearray(f)
        at = rng.randrange(HDR, len(b))
        w = rng.choice((1, 2, 4))
        b[at:at + w] = bytes(rng.choice((0, 255)) for _ in range(min(w, len(b) - at)))
        out.append(redigest(bytes(b)))
    for _ in range(40):                                     # a cut with the digest made right, and a request cut inside
        out.append(redigest(f[:rng.randrange(HDR, len(f))]))
    return out


class DecodeFuzz(unittest.TestCase):
    def test_byte_decoder_refuses_where_the_list_decoder_does(self):
        rng = random.Random(20261103)
        frames = base_frames(rng)
        cases = list(frames)
        for f in frames:
            cases += damaged(rng, f)
        cases += [bytes(rng.randrange(256) for _ in range(rng.randrange(0, 400))) for _ in range(200)]
        cases += [b"RRDQ\x01\x00" + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200))) for _ in range(100)]
        cases += [struct.pack(">I", 7) + bytes(7), b"", b"R"]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "frames.bin"
            path.write_bytes(b"".join(struct.pack(">I", len(c)) + c for c in cases))
            r = subprocess.run([str(EXE), str(path)], capture_output=True, text=True, timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        print(r.stdout.strip())
        fields = dict(kv.split("=") for kv in r.stdout.split()[1:])
        self.assertEqual(int(fields["frames"]), len(cases))
        self.assertEqual(int(fields["mismatches"]), 0)
        self.assertGreaterEqual(int(fields["accepted"]), len(frames))   # the undamaged frames are read
        self.assertGreater(int(fields["refused"]), len(cases) // 2)     # and the damaged ones are not all accepted


if __name__ == "__main__":
    unittest.main()
