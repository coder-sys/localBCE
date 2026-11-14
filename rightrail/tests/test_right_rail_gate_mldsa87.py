"""ML-DSA-87 worker and Lean verifier checks: NIST ACVP known answers, custody files, differential test.

The worker (``rust/gate_mldsa87``) links AWS-LC's FIPS 204 internal functions for the known-answer modes.
The Lean verifier (``BlindLedger.Gate.MlDsa87``, run through ``gate_vectors``) is written from the FIPS 204 text.
Both are judged against NIST's ACVP sigVer cases and against each other on mutated signatures and keys.
Synthetic, non-PHI.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeout
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from app import right_rail_gate_signer as signer

TESTS = Path(__file__).resolve().parent
VECTORS = TESTS / "gate_vectors"
GATE_VECTORS = TESTS.parent / "lean" / ".lake" / "build" / "bin" / "gate_vectors.exe"
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

    def test_acvp_mldsa87_sigver_lean(self) -> None:
        included = header_counts("mldsa87_acvp.vectors", "sigVer")[0]
        self.assertEqual(lean_vectors(VECTORS / "mldsa87_acvp.vectors"), f"GATE_VECTORS=PASS checked={included} expected={included} failed=0")


def _flip(data: bytes, bit: int) -> bytes:
    return data[: bit // 8] + bytes([data[bit // 8] ^ (1 << bit % 8)]) + data[bit // 8 + 1 :]


def _put(data: bytes, at: int, value: bytes) -> bytes:
    return data[:at] + value + data[at + len(value) :]


def hint_edges(sig: bytes, at: int) -> list[bytes]:
    """Signatures whose hint block (omega indices, then 8 cumulative counts) breaks exactly one HintBitUnpack rule,
    built from this signature's own counts: indices out of order or equal inside one polynomial, a count above
    omega, a nonzero byte after the last index."""
    y = bytearray(sig[at:])
    ends = list(y[OMEGA:])
    edges = []
    start = 0
    for end in ends:
        if end - start >= 2:  # a polynomial with two or more hints
            edges += [_put(sig, at + start, bytes([y[start + 1], y[start]])), _put(sig, at + start + 1, bytes([y[start]]))]
            break
        start = end
    edges.append(_put(sig, at + OMEGA + 7, bytes([OMEGA + 1])))
    if ends[7] < OMEGA:
        edges.append(_put(sig, at + OMEGA - 1, bytes([1])))
    return edges


class DifferentialTests(unittest.TestCase):
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
                edges = hint_edges(sig, hints) + [_put(sig, 64, bytes([BETA, 0, sig[66] & 0xF0]))]  # z[0][0] = gamma1 - beta
                cases += [(pk, message, edge, False) for edge in edges]
            lines = [f"mldsa87 {'accept' if ok else 'reject'} {p.hex()} {m.hex()} {s.hex()}" for p, m, s, ok in cases]
            path = Path(tmp) / "diff.vectors"
            path.write_text("\n".join([*lines, f"end {len(lines)}"]) + "\n", "ascii", newline="\n")
            with ThreadPoolExecutor(min(4, os.cpu_count() or 1)) as pool, ThreadPoolExecutor(1) as lean:  # a worker process per case, at most 4 side by side, while Lean checks the one file
                lean_verdict = lean.submit(lean_vectors, path)
                verdicts = list(pool.map(lambda c: kat_verify(*c[:3]), cases))
            self.assertEqual(verdicts, [c[3] for c in cases])
            self.assertEqual(lean_verdict.result(), f"GATE_VECTORS=PASS checked={len(cases)} expected={len(cases)} failed=0")
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
                               (("sign",), seed + b"msg"), ((), seed + b"msg"), (("verify", str(raw)), b""), (("kat-keygen", str(raw)), seed)):
                with self.subTest(args), self.assertRaises(signer.GateSignerError):
                    signer._run(signer.BINARY, signer.PIN, args, data, PK)
            # the resident server answers only a call with no arguments at all: a valid frame under any argument is refused
            handle = str(Path(tmp) / "served.key")
            signer.keygen(handle)
            path = os.path.abspath(handle).encode()
            frame = (2 + len(path) + 3).to_bytes(4, "big") + len(path).to_bytes(2, "big") + path + b"msg"
            for args in (("",), ("sign",), ("public-key",), ("keygen",), ("verify",), ("kat-sign",), ("sign", handle, "x")):
                with self.subTest(args):
                    done = signer._exec(signer.BINARY, signer.PIN, args, frame)
                    self.assertEqual((done.returncode, done.stdout), (2, b""))


@unittest.skipUnless(os.name == "nt", "resident signer is Windows-only")
class ResidentSignerTests(unittest.TestCase):
    def setUp(self) -> None:
        signer._close_server()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(signer._close_server)
        # a mutant that hangs (self-deadlock, retry loop) must fail its test, not stall the run: every sign gets a hard 45 s
        real = signer.sign

        def bounded(*args):
            future = Future()

            def run() -> None:
                try: future.set_result(real(*args))
                except BaseException as error: future.set_exception(error)

            threading.Thread(target=run, daemon=True).start()
            try: return future.result(45.0)
            except FutureTimeout: raise AssertionError("signer.sign hung")

        for patch in (mock.patch.object(signer, "sign", bounded), mock.patch.object(signer, "_SERVE", threading.Lock())):
            patch.start()
            self.addCleanup(patch.stop)

    def key(self, name: str) -> tuple[str, bytes]:
        handle = str(Path(self.tmp.name) / name)
        return handle, signer.keygen(handle)

    def launches(self):
        return mock.patch.object(signer.process, "launch_contained_worker", wraps=signer.process.launch_contained_worker)

    def test_a_sign_verifies(self) -> None:
        # a hedged signature ends in 0x0A about 1 time in 256, which would hide a missing flush: sign enough to hit a miss
        # also CRLF translation, 0x1A and NUL must cross both pipes untouched: binary messages, and signatures that carry 0x0A and 0x1A
        handle, pk = self.key("a.key")
        messages = [m + bytes([i]) for i in range(16) for m in (b"", b"\n\r\n\x1a\x00\xff" * 1000)]
        with self.launches() as launch:  # one launch for every sign
            sigs = [signer.sign(handle, m) for m in messages]
        self.assertEqual(launch.call_count, 1)
        self.assertTrue(all(signer.verify(pk, m, sig) for m, sig in zip(messages, sigs)))
        self.assertTrue(any(b"\n" in sig for sig in sigs) and any(b"\x1a" in sig for sig in sigs))
        hb, pkb = self.key("ab.key")  # the key is not cached: a second handle signs under its own key
        sig = signer.sign(hb, b"msg")
        self.assertEqual((signer.verify(pkb, b"msg", sig), signer.verify(pk, b"msg", sig)), (True, False))

    def test_e_size_refusals(self) -> None:
        handle, _ = self.key("e.key")
        self.assertEqual(len(signer.sign(handle, b"x" * 65536)), SIG)
        raw = Path(self.tmp.name) / "raw.key"
        raw.write_bytes(bytes(range(SEED)))
        for args in ((handle, b"x" * 65537), ("k" * 32768, b"m"), (handle + chr(0xD800), b"m"), (str(raw), b"m")):
            with self.assertRaises(signer.GateSignerError):
                signer.sign(*args)
        os.remove(handle)  # a deleted key fails closed
        with self.assertRaises(signer.GateSignerError):
            signer.sign(handle, b"m")
        self.assertIsNone(signer._SERVER[0])

    def test_g_error_closes_without_retry(self) -> None:
        handle, _ = self.key("g.key")
        for fault in ({"side_effect": RuntimeError("x")}, {"return_value": b"short"}):  # an exchange error, then a short signature
            signer.sign(handle, b"m")
            with self.launches() as launch, mock.patch.object(type(signer._SERVER[0]), "exchange", **fault), self.assertRaises(signer.GateSignerError):
                signer.sign(handle, b"m")
            self.assertEqual(launch.call_count, 0)
            self.assertIsNone(signer._SERVER[0])
        self.assertEqual(len(signer.sign(handle, b"m")), SIG)
        other = Path(self.tmp.name) / "other.sha256"  # the pin is checked on every call
        other.write_bytes(b"0" * 64)
        with mock.patch.object(signer, "PIN", other), self.assertRaisesRegex(signer.GateSignerError, "pin_mismatch"):
            signer.sign(handle, b"m")
        self.assertIsNone(signer._SERVER[0])
        self.assertEqual(len(signer.sign(handle, b"m")), SIG)

    def test_h_child_dies_between_calls(self) -> None:
        handle, pk = self.key("h.key")
        signer.sign(handle, b"m")
        signer._SERVER[0].close()  # a closed worker is relaunched by the next sign
        with self.launches() as launch:
            self.assertTrue(signer.verify(pk, b"m0", signer.sign(handle, b"m0")))
        self.assertEqual(launch.call_count, 1)
        worker = signer._SERVER[0]
        self.assertTrue(worker._kernel32.TerminateJobObject(worker._job, 1))
        with self.assertRaises(signer.GateSignerError):
            signer.sign(handle, b"m1")
        self.assertIsNone(signer._SERVER[0])
        with self.launches() as launch:
            sig = signer.sign(handle, b"m2")
        self.assertEqual(launch.call_count, 1)
        self.assertTrue(signer.verify(pk, b"m2", sig))

    def test_i_hung_child_times_out(self) -> None:
        handle, pk = self.key("i.key")
        signer.sign(handle, b"m")
        worker = signer._SERVER[0]
        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtSuspendProcess.argtypes = [ctypes.c_void_p]
        self.assertEqual(ntdll.NtSuspendProcess(worker._process), 0)  # a child that never answers
        exchange = type(worker).exchange  # the 30 s production timeout is fixed in sign(); only this test shortens it
        with mock.patch.object(type(worker), "exchange", lambda self, frame, **kw: exchange(self, frame, **{**kw, "timeout_seconds": 1.0})):
            with self.assertRaisesRegex(signer.GateSignerError, "failed"):
                signer.sign(handle, b"m1")
        self.assertIsNone(signer._SERVER[0])
        self.assertTrue(signer.verify(pk, b"m2", signer.sign(handle, b"m2")))

    def test_k_nul_handle(self) -> None:  # refused in Python before anything is sent: the worker is neither killed nor relaunched
        handle, pk = self.key("k.key")
        signer.sign(handle, b"m")
        worker, pid = signer._SERVER[0], lambda: ctypes.WinDLL("kernel32").GetProcessId(ctypes.c_void_p(signer._SERVER[0]._process))
        before = pid()
        with self.launches() as launch, self.assertRaisesRegex(signer.GateSignerError, "input"):
            signer.sign("a\x00b", b"m")
        self.assertTrue(signer.verify(pk, b"m2", signer.sign(handle, b"m2")))
        self.assertEqual((launch.call_count, signer._SERVER[0] is worker, pid()), (0, True, before))

    def test_l_exit_leaves_no_private_copy(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            temp = Path(scratch) / "t"
            temp.mkdir()
            code = "import sys; from app import right_rail_gate_signer as s; s.keygen(sys.argv[1]); s.sign(sys.argv[1], b'm')"
            env = {**os.environ, "TEMP": str(temp), "TMP": str(temp)}
            done = subprocess.run([sys.executable, "-c", code, str(Path(scratch) / "l.key")], cwd=signer.ROOT, env=env,
                                  capture_output=True, timeout=120, check=False)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(sorted(p.name for p in temp.rglob("*-rr_gate_mldsa87.exe")), [])
            self.assertEqual(list(temp.iterdir()), [])

    def test_o_handle_forms_and_threads(self) -> None:
        a, pka = self.key("o.key")
        folder = Path(self.tmp.name) / "k\u00e9y-\u9375-\U0001f511"
        folder.mkdir()
        b = str(folder / "p.key")
        pkb, work = signer.keygen(b), [(t, i) for t in range(2) for i in range(8)]
        with self.launches() as launch, ThreadPoolExecutor(2) as pool:  # 2 threads x 8 signs, one launch, all verify
            sigs = list(pool.map(lambda ti: signer.sign(a, bytes(ti)), work))
        self.assertEqual(launch.call_count, 1)
        self.assertTrue(all(signer.verify(pka, bytes(ti), sig) for ti, sig in zip(work, sigs)))
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.tmp.name)  # a relative handle resolves against this process, not the worker's directory
        self.assertTrue(signer.verify(pka, b"m", signer.sign("o.key", b"m")))
        self.assertTrue(signer.verify(pkb, b"m", signer.sign(b, b"m")))  # non-ASCII key directory

    def test_r_malformed_frames_exit_2(self) -> None:
        handle, _ = self.key("r.key")
        path, exe = os.path.abspath(handle).encode(), str(signer._private_copy(signer.BINARY)[0])
        run = lambda data: subprocess.run([exe], input=data, capture_output=True, timeout=30, check=False)
        frame = lambda plen, rest, length=None: (len(rest) + 2 if length is None else length).to_bytes(4, "big") + plen.to_bytes(2, "big") + rest
        good = frame(len(path), path + b"msg")
        for name, data in (("three bytes", b"\x00" * 3), ("len 1", b"\x00\x00\x00\x01\x00"), ("plen 0", frame(0, b"")), ("plen len-1", frame(4, b"abc", 5)),
                           ("len over bound, full body sent (not EOF)", frame(32767, b"a" * (32767 + 65537))), ("non-UTF-8 path", frame(2, b"\xff\xfemsg")),
                           ("message over 64 KiB", frame(len(path), path + b"x" * 65537))):
            with self.subTest(name):
                done = run(data)
                self.assertEqual((done.returncode, done.stdout, done.stderr), (2, b"", b""))
        done = run(good + b"\x00\x00")
        self.assertEqual((done.returncode, done.stdout[:4], len(done.stdout), done.stderr), (2, SIG.to_bytes(4, "big"), 4 + SIG, b""))
        self.assertEqual(run(good).returncode, 0)


@unittest.skipUnless(os.name == "nt", "resident verifier is Windows-only")
class ResidentVerifierTests(unittest.TestCase):
    ASK = (2, signer.framed(b""))  # INDEX of an empty checkpoint: a real answer, REJECT

    def setUp(self) -> None:
        self.addCleanup(signer._close_server)

    def test_one_launch_answers_and_a_malformed_frame_refuses(self) -> None:
        with mock.patch.object(signer.process, "launch_contained_worker", wraps=signer.process.launch_contained_worker) as launch:
            self.assertEqual({signer.gate_verify(*self.ASK) for _ in range(5)}, {"GATE_VERIFY=REJECT"})
            with self.assertRaises(signer.GateSignerError):
                signer.gate_verify(9, b"")  # unknown mode: the verifier exits 2 without an answer
            self.assertEqual((signer.gate_verify(*self.ASK), launch.call_count), ("GATE_VERIFY=REJECT", 2))

    def test_death_hang_and_garbled_or_short_frames_refuse(self) -> None:
        for fault in ({"side_effect": signer.process.VerifierProcessError("worker_exchange")}, {"side_effect": signer.process.VerifierProcessError("worker_timeout")},
                      {"return_value": b""}, {"return_value": b"\x07ACCEPT"}, {"return_value": b"\x00ACC\xff"}):
            signer.gate_verify(*self.ASK)
            with mock.patch.object(type(signer._VSERVER[0]), "exchange", **fault), self.assertRaises(signer.GateSignerError):
                signer.gate_verify(*self.ASK)
            self.assertIsNone(signer._VSERVER[0])


if __name__ == "__main__":
    unittest.main()
