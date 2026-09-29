"""ML-DSA-87 worker and Lean verifier checks: NIST ACVP known answers, custody files, differential test.

The worker (``rust/gate_mldsa87``) links AWS-LC's FIPS 204 internal functions for the known-answer modes.
The Lean verifier (``BlindLedger.Gate.MlDsa87``, run through ``gate_vectors``) is written from the FIPS 204 text.
Both are judged against NIST's ACVP sigVer cases and against each other on mutated signatures and keys.
Synthetic, non-PHI.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from app import right_rail_gate_signer as signer

TESTS = Path(__file__).resolve().parent
VECTORS = TESTS / "gate_vectors"
GATE_VECTORS = TESTS.parent / "lean" / ".lake" / "build" / "bin" / "gate_vectors.exe"
NEEDS_LEAN = unittest.skipUnless(GATE_VECTORS.is_file(), f"LEAN VECTORS NOT RUN: {GATE_VECTORS} is missing; build gate_vectors")
PK, SK, SIG, SEED = 2592, 4896, 4627, 32
BETA, OMEGA = 120, 75


def kat(mode: str, data: bytes, size: int) -> bytes:
    return signer._run(signer.BINARY, signer.PIN, (mode,), data, size)


def kat_verify(pk: bytes, message: bytes, signature: bytes) -> bool:
    """AWS-LC's verdict on M' = ``message``; the worker takes a fixed-width signature."""
    verdict = kat("kat-verify", pk + signature + message, 1)
    if verdict not in (b"\x00", b"\x01"):
        raise signer.GateSignerError("mldsa87_verify_output")
    return verdict == b"\x01"


def lean_vectors(path: Path) -> str:
    """The Lean ``gate_vectors`` verdict line for one vector file."""
    done = subprocess.run([str(GATE_VECTORS), str(path)], capture_output=True, text=True, timeout=1800, check=False)
    return done.stdout.strip().splitlines()[-1] if done.stdout.strip() else done.stderr.strip()


def records(name: str, kind: str) -> list[list[bytes]]:
    """The hex fields of the ``kind`` lines of an ACVP vector file; ``accept`` becomes 1 and ``reject`` 0."""
    rows = [line.split(" ") for line in (VECTORS / name).read_text("ascii").splitlines() if line and line[0] != "#"]
    return [[b"\x01" if x == "accept" else b"\x00" if x == "reject" else bytes.fromhex(x) for x in row[1:]] for row in rows if row[0] == kind]


def header_counts(name: str, expected_kind: str) -> tuple[int, dict[str, int]]:
    """Included case count for ``expected_kind`` groups and the excluded counts by group kind, from the header."""
    included, excluded = 0, {}
    for line in (VECTORS / name).read_text("ascii").splitlines():
        words = line.split(" ")
        if line.startswith("# included ") and words[2] == expected_kind:
            included += int(words[-1].split("=")[1])
        elif line.startswith("# excluded ") and words[2] == expected_kind:
            excluded[words[4]] = excluded.get(words[4], 0) + int(words[-1].split("=")[1])
    return included, excluded


class AcvpTests(unittest.TestCase):
    def test_acvp_mldsa87_keygen(self) -> None:
        cases = records("mldsa87_acvp_gen.vectors", "keygen")
        self.assertEqual(len(cases), header_counts("mldsa87_acvp_gen.vectors", "keyGen")[0])
        for seed, pk, sk in cases:
            self.assertEqual(kat("kat-keygen", seed, PK + SK), pk + sk)
        print(f"ACVP ML-DSA-87 keyGen: {len(cases)} cases, all exact")

    def test_acvp_mldsa87_siggen(self) -> None:
        cases = records("mldsa87_acvp_gen.vectors", "siggen")
        included, excluded = header_counts("mldsa87_acvp_gen.vectors", "sigGen")
        self.assertEqual(len(cases), included)
        self.assertEqual(sorted(excluded), ["external-preHash", "internal-externalMu"])
        for sk, rnd, message, signature in cases:
            self.assertEqual(kat("kat-sign", sk + rnd + message, SIG), signature)
        print(f"ACVP ML-DSA-87 sigGen: {len(cases)} cases exact (deterministic and hedged); excluded {excluded}")

    def test_acvp_mldsa87_sigver_awslc(self) -> None:
        cases = records("mldsa87_acvp.vectors", "mldsa87")
        included, excluded = header_counts("mldsa87_acvp.vectors", "sigVer")
        self.assertEqual(len(cases), included)
        self.assertEqual(sorted(excluded), ["external-preHash", "internal-externalMu"])
        for verdict, pk, message, signature in cases:
            self.assertEqual(kat_verify(pk, message, signature), verdict == b"\x01")
        print(f"ACVP ML-DSA-87 sigVer (AWS-LC): {len(cases)} cases; excluded {excluded}")

    @NEEDS_LEAN
    def test_acvp_mldsa87_sigver_lean(self) -> None:
        included = header_counts("mldsa87_acvp.vectors", "sigVer")[0]
        self.assertEqual(lean_vectors(VECTORS / "mldsa87_acvp.vectors"), f"GATE_VECTORS=PASS checked={included} expected={included} failed=0")


def _flip(data: bytes, bit: int) -> bytes:
    return data[: bit // 8] + bytes([data[bit // 8] ^ (1 << bit % 8)]) + data[bit // 8 + 1 :]


def _put(data: bytes, at: int, value: bytes) -> bytes:
    return data[:at] + value + data[at + len(value) :]


class DifferentialTests(unittest.TestCase):
    @NEEDS_LEAN
    def test_lean_and_awslc_agree_on_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            handle = str(Path(tmp) / "diff.key")
            pk = signer.keygen(handle)
            cases: list[tuple[bytes, bytes, bytes, bool]] = []  # pk, M', signature, expected verdict
            hints = SIG - OMEGA - 8  # start of HintBitUnpack's y (omega + k bytes)
            for n in range(8):
                message = b"\x00\x00" + f"RR/GATE/DIFFERENTIAL/{n}".encode() * (n + 1)
                sig = signer.sign(handle, message[2:])
                cases.append((pk, message, sig, True))
                boundaries = [0, 63 * 8, 64 * 8, *((64 + 640 * i) * 8 for i in range(1, 8)), hints * 8, (SIG - 1) * 8]
                cases += [(pk, message, _flip(sig, bit), False) for bit in [*range(n, SIG * 8, 97), *boundaries]]
                cases += [(_flip(pk, bit), message, sig, False) for bit in [*range(n, PK * 8, 97), 31 * 8, 32 * 8, (PK - 1) * 8]]
                cases += [(pk, _flip(message, 16 + n), sig, False)]
                y = sig[hints:]
                edges = [
                    _put(sig, hints, bytes([9, 9]) + y[2:]),  # equal indices: not strictly increasing
                    _put(sig, hints + OMEGA, bytes([OMEGA + 1] * 8)),  # more than omega hints
                    _put(sig, hints + OMEGA - 1, bytes([1])),  # nonzero padding after the last hint
                    _put(sig, 64, bytes([BETA & 255, 0])),  # z[0][0] rewritten: a z at the norm bound region
                ]
                cases += [(pk, message, edge, False) for edge in edges]
            lines = [f"mldsa87 {'accept' if ok else 'reject'} {p.hex()} {m.hex()} {s.hex()}" for p, m, s, ok in cases]
            path = Path(tmp) / "diff.vectors"
            path.write_text("\n".join([*lines, f"end {len(lines)}"]) + "\n", "ascii", newline="\n")
            with ThreadPoolExecutor(min(2, os.cpu_count() or 1)) as pool:  # a worker process per case; at most 2 side by side
                verdicts = list(pool.map(lambda c: kat_verify(*c[:3]), cases))
            self.assertEqual(verdicts, [c[3] for c in cases])
            self.assertEqual(lean_vectors(path), f"GATE_VECTORS=PASS checked={len(cases)} expected={len(cases)} failed=0")
        print(f"differential: {len(cases)} cases, AWS-LC and Lean agree on every one")


def _dpapi_seal(data: bytes, entropy: bytes) -> bytes:
    """Seal ``data`` under the current user's DPAPI key with the given entropy (test-side, for foreign blobs)."""

    class Blob(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("pb", ctypes.POINTER(ctypes.c_char))]

    def blob(value: bytes) -> Blob:
        return Blob(len(value), ctypes.cast(ctypes.create_string_buffer(value, len(value)), ctypes.POINTER(ctypes.c_char)))

    out = Blob()
    keep = (blob(data), blob(entropy))
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(keep[0]), None, ctypes.byref(keep[1]), None, None, 1, ctypes.byref(out)):
        raise OSError("CryptProtectData")
    sealed = ctypes.string_at(out.pb, out.cb)
    ctypes.windll.kernel32.LocalFree(out.pb)
    return sealed


class CustodyTests(unittest.TestCase):
    def test_custody_never_overwrites_and_rejects_foreign_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "epoch-1.key"
            pk = signer.keygen(str(key))
            before = key.read_bytes()
            self.assertEqual(signer.public_key(str(key)), pk)
            self.assertTrue(kat_verify(pk, b"\x00\x00msg", signer.sign(str(key), b"msg")))
            with self.assertRaises(signer.GateSignerError):
                signer.keygen(str(key))
            self.assertEqual(key.read_bytes(), before)
            seed = bytes(range(SEED))
            for name, blob in (("tampered", before[:-1] + bytes([before[-1] ^ 1])), ("truncated", before[:-8]),
                               ("other-entropy", _dpapi_seal(seed, b"RR/GATE/KEY-FILE/v2\x00")), ("empty", b"")):
                foreign = Path(tmp) / f"{name}.key"
                foreign.write_bytes(blob)
                with self.subTest(name), self.assertRaises(signer.GateSignerError):
                    signer.public_key(str(foreign))
                with self.subTest(name), self.assertRaises(signer.GateSignerError):
                    signer.sign(str(foreign), b"msg")
            # The specified entropy and DPAPI scope are what the worker expects: this blob is accepted
            good = Path(tmp) / "known-seed.key"
            good.write_bytes(_dpapi_seal(seed, b"RR/GATE/KEY-FILE/v1\x00"))
            self.assertEqual(signer.public_key(str(good)), kat("kat-keygen", seed, PK + SK)[:PK])

    def test_worker_has_no_seed_mode(self) -> None:
        seed = bytes(range(SEED))
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "raw-seed.key"
            raw.write_bytes(seed)
            for args, data in ((("public-key", str(raw)), b""), (("sign", str(raw)), b"msg"), (("public-key",), seed),
                               (("sign",), seed + b"msg"), (("verify", str(raw)), b""), (("kat-keygen", str(raw)), seed)):
                with self.subTest(args), self.assertRaises(signer.GateSignerError):
                    signer._run(signer.BINARY, signer.PIN, args, data, PK)


if __name__ == "__main__":
    unittest.main()
