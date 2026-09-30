"""The pinned worker and correction exes' I/O loops: same bytes out, same exit codes (lean-partials-v1)."""

import hashlib
import os
import subprocess
import unittest
from pathlib import Path

from app import right_rail_financial_engine as engine
from app import right_rail_financial_semantic_adapter as adapter
from tests import test_right_rail_financial_semantic_adapter as adapter_tests

ROOT = Path(__file__).resolve().parent.parent
CORRECTION = ROOT / "artifacts" / "engine-correction" / "blind_financial_correction.exe"
VECTORS = CORRECTION.parent / "vectors"
ENV = {"SystemRoot": os.environ.get("SystemRoot", r"C:\Windows")}
MAX_FRAME = adapter.MAX_WIRE_BYTES + 1  # Lean maxWorkerFrameBytes
REJECT = b"\x00\x00\x00\x01\x01"  # frame(workerRespond(b"")): decode rejected


def frame(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def run(exe: Path, data: bytes, *args: str) -> tuple[int, bytes, bytes]:
    done = subprocess.run([exe, *args], input=data, env=ENV, capture_output=True, timeout=120)
    return done.returncode, done.stdout, done.stderr


@unittest.skipUnless(os.name == "nt", "pinned Windows exes")
class WorkerLoopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        exe = engine.EVALUATOR_PATH
        assert hashlib.sha256(exe.read_bytes()).digest() == engine.EVALUATOR_ARTIFACT_SHA256
        fixture = adapter_tests.RightRailFinancialSemanticAdapterTests()
        fixture.setUp()
        try:
            store = fixture._build_base()
            connection = store._connect()
            connection.execute("BEGIN")
            authority = adapter.TrustedAuthorityContext.from_authority(store.trusted_authority)
            verification = {"scope": store._scope_value(), "owner_id": store.owner_id, "mode": store.mode}
            ids = [row[0] for row in connection.execute("SELECT obligation_id FROM obligations ORDER BY obligation_id")]
            cls.a, cls.b = (
                adapter.live_evaluation_input(connection, obligation_id=i, authority_context=authority,
                                              evaluation_time_ms=store.clock.value + 1, verification=verification)[0]
                for i in (ids[0], ids[-1])
            )
            connection.execute("ROLLBACK")
            connection.close()
        finally:
            fixture.doCleanups()
        cls.exe = exe
        cls.frames = [cls.a, cls.b, cls.a[:-1], b"", cls.a, bytes(7), cls.b]
        cls.single = {f: run(exe, frame(f))[1] for f in set(cls.frames)}

    def test_empty_input_is_clean_eof(self) -> None:
        self.assertEqual(run(self.exe, b""), (0, b"", b""))

    def test_batched_answers_equal_single_answers(self) -> None:
        for frames in (self.frames, self.frames[::-1]):
            expected = b"".join(self.single[f] for f in frames)
            self.assertEqual(run(self.exe, b"".join(map(frame, frames))), (0, expected, b""))
        self.assertEqual(self.single[b""], REJECT)
        self.assertEqual(self.single[self.a][4], 0)  # evaluated tag
        self.assertEqual(engine._evaluate_wire(self.a), self.single[self.a][5:])

    def test_truncated_frame_stops_with_65_after_good_answers(self) -> None:
        good = frame(self.a) + frame(b"")
        expected = self.single[self.a] + REJECT
        last = frame(self.b)
        for cut in (1, 2, 3, 4, 5, len(last) - 1):
            self.assertEqual(run(self.exe, good + last[:cut]), (65, expected, b""), cut)

    def test_oversize_length_stops_with_65_before_reading_the_body(self) -> None:
        for tail in ((MAX_FRAME + 1).to_bytes(4, "big"), (MAX_FRAME + 1).to_bytes(4, "big") + frame(b"") * 3,
                     b"\xff\xff\xff\xff"):
            self.assertEqual(run(self.exe, frame(b"") + tail), (65, REJECT, b""))

    def test_largest_frame_is_answered(self) -> None:
        self.assertEqual(run(self.exe, frame(bytes(MAX_FRAME))), (0, REJECT, b""))

    def test_hundred_thousand_frames_run_in_constant_stack(self) -> None:
        n = 100_000
        self.assertEqual(run(self.exe, frame(b"") * n), (0, REJECT * n, b""))

    def test_byte_at_a_time_writer_gets_the_same_answers(self) -> None:
        data = frame(self.a) + frame(b"") + frame(self.b)
        proc = subprocess.Popen([self.exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
        for i in range(len(data)):
            proc.stdin.write(data[i:i + 1])
            proc.stdin.flush()
        out, err = proc.communicate(timeout=120)
        self.assertEqual((proc.returncode, out, err), (0, self.single[self.a] + REJECT + self.single[self.b], b""))


@unittest.skipUnless(os.name == "nt", "pinned Windows exes")
class CorrectionReadTests(unittest.TestCase):
    APPLY = engine.CORRECTION_TRANSITION_ARGUMENTS
    REUSE = ("--assess-correction-reuse",)
    LIMIT = engine.MAX_CORRECTION_TRANSITION_BYTES

    @classmethod
    def setUpClass(cls) -> None:
        assert hashlib.sha256(CORRECTION.read_bytes()).digest() == engine.CORRECTION_TRANSITION_ARTIFACT_SHA256

    def test_vector_whole_and_streamed(self) -> None:
        request = (VECTORS / "request.bin").read_bytes()
        expected = (VECTORS / "result.expected.bin").read_bytes()
        self.assertEqual(run(CORRECTION, request, *self.APPLY), (0, expected, b""))
        proc = subprocess.Popen([CORRECTION, *self.APPLY], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=ENV)
        for i in range(0, len(request), 997):
            proc.stdin.write(request[i:i + 997])
            proc.stdin.flush()
        out, err = proc.communicate(timeout=120)
        self.assertEqual((proc.returncode, out, err), (0, expected, b""))

    def test_transition_bounds(self) -> None:
        for data, reason in ((b"", "decode"), (bytes(self.LIMIT), "decode"),
                             (bytes(self.LIMIT + 1), "too-large"), (bytes(self.LIMIT + 70_000), "too-large")):
            code, out, err = run(CORRECTION, data, *self.APPLY)
            self.assertEqual((code, out), (72, b""), len(data))
            self.assertIn(f"FINANCIAL_ERROR=correction-transition-input-{reason}".encode(), err)

    def test_reuse_bounds(self) -> None:
        for data, reason in ((b"", "decode"), (bytes(3 * self.LIMIT + 1), "too-large")):
            code, out, err = run(CORRECTION, data, *self.REUSE)
            self.assertEqual((code, out), (75, b""), len(data))
            self.assertIn(f"FINANCIAL_ERROR=correction-reuse-input-{reason}".encode(), err)


class TotalModelTests(unittest.TestCase):
    def test_model_files_define_no_partial_or_fixpoint(self) -> None:
        for relative in ("Financial/WorkerLaws.lean", "Gate/MlDsa87Laws.lean"):
            text = (ROOT / "lean" / "BlindLedger" / relative).read_text(encoding="utf-8")
            self.assertNotIn("partial_fixpoint", text, relative)
            self.assertNotIn("partial def", text, relative)
