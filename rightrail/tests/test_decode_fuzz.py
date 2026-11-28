"""The engine's byte request decoder against the list decoder (`decodeReqFast`) on damaged frames.

Real frames (`request_frame`) are bit-flipped, given extreme field values, cut short, extended and replaced by random bytes.
`decode_fuzz` runs both decoders on every frame; they must give the same refusal word, or the same request, and the run must
exit 0.  No decoder reads the header's digest (the checker recomputes it), so damage reaches the body as it is.  A cut or
extended frame is never read (`decodeReq_trailing`).  Needs the exe: `lake build decode_fuzz`."""
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


def base_frames(rng: random.Random) -> list[bytes]:
    release = bytes(range(64))
    out = []
    # the last two present rule-set records (their bytes are not read by the decoders, only their lengths and order)
    for k, n, records in ((0, 1, ()), (0, 3, ()), (1, 5, ()), (2, 0, ()), (1, 2, (bytes(range(90)),)), (2, 1, (b"\x07" * 5, b""))):
        reqs, _ = fw.batch(rng, k, n)
        out.append(decider.request_frame(g.HEAD, 0, k + 1, g.ASOF, bytes(64), g.PIN, (0, 0, 0, bytes(64)), g.KEYS, g.GRANT, release, (),
                                         [gate.encode_decide_request(r) for r in reqs], rulesets=records))
    return out


def flipped(rng: random.Random, f: bytes) -> list[bytes]:
    out = []
    for _ in range(600):                                    # bit flips
        b = bytearray(f)
        for _ in range(rng.choice((1, 1, 2, 5))):
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
        out.append(bytes(b))
    for _ in range(100):                                    # a field set to an extreme value (lengths, counts)
        b = bytearray(f)
        at = rng.randrange(HDR, len(b))
        w = rng.choice((1, 2, 4))
        b[at:at + w] = bytes(rng.choice((0, 255)) for _ in range(min(w, len(b) - at)))
        out.append(bytes(b))
    return out


def cut(rng: random.Random, f: bytes) -> list[bytes]:
    """Shorter and longer than a frame that is read: anywhere, inside the body, at the header's end, with bytes after it."""
    return ([f[:rng.randrange(len(f))] for _ in range(40)] + [f[:rng.randrange(HDR, len(f))] for _ in range(40)]
            + [f[:HDR], f[:HDR - 1], f + b"\x00", f + bytes(rng.randrange(256) for _ in range(9))])


def run(cases: list[bytes]) -> dict:
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "frames.bin"
        path.write_bytes(b"".join(struct.pack(">I", len(c)) + c for c in cases))
        r = subprocess.run([str(EXE), str(path)], capture_output=True, text=True, timeout=600)
    if r.returncode:
        raise AssertionError(r.stdout + r.stderr)
    print(r.stdout.strip())
    fields = {k: int(v) for k, v in (kv.split("=") for kv in r.stdout.split()[1:])}
    assert (fields["frames"], fields["mismatches"]) == (len(cases), 0), fields
    return fields


class DecodeFuzz(unittest.TestCase):
    def test_byte_decoder_refuses_where_the_list_decoder_does(self):
        rng = random.Random(20261103)
        frames = base_frames(rng)
        cases = list(frames)
        for f in frames:
            cases += flipped(rng, f)
        cases += [bytes(rng.randrange(256) for _ in range(rng.randrange(0, 400))) for _ in range(200)]
        cases += [b"RRDQ\x02\x00" + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200))) for _ in range(100)]
        self.assertGreaterEqual(run(cases)["accepted"], len(frames))   # the undamaged frames are read
        short = [c for f in frames for c in cut(rng, f)] + [struct.pack(">I", 7) + bytes(7), b"", b"R"]
        self.assertEqual(run(short)["accepted"], 0)                    # and no cut or extended frame is


if __name__ == "__main__":
    unittest.main()
