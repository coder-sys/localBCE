"""Test-only: the retired worker pin and the current one answer every live request kind with the same bytes.

The retired exe is read from git (RETIRED_REV, a commit that carries it) into a scratch folder, so no second
binary is committed. Frames: the Lean-encoded vectors (BLFIN02, BLFCMD03, BLFPAY01, BLFOFA01), the committed payment
frames and offset request, and BLFDPQ01 requests built by the engine's own encoder."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from app import minimal_clearance_verifier_process as process
from app import right_rail_financial_engine as engine

ROOT = Path(__file__).resolve().parent.parent
RETIRED_REV = "744b8002"
RETIRED_SHA256 = "c0432c63721b8f75e74cfcdb42656197dabe0969bf8dcfae5f43ea8cc9b784d1"
WIRE_VECTORS = ROOT / "lean" / ".lake" / "build" / "bin" / "wire_vectors.exe"
CAP = 8 * 1024 * 1024 + 1


def _frames() -> dict[str, bytes]:
    frames = {}
    for line in subprocess.run([str(WIRE_VECTORS)], capture_output=True, text=True, check=True).stdout.splitlines():
        name, _, hexed = line.partition(" ")
        if hexed:
            frames["wire:" + name] = bytes.fromhex(hexed)
    for name, hexed in json.loads((ROOT / "tests" / "fixtures" / "payment_frames.json").read_text(encoding="utf-8")).items():
        frames["payment:" + name] = bytes.fromhex(hexed)
    vectors = ROOT / "artifacts" / "engine-correction" / "vectors"
    frames["offset:request"] = b"BLFOFA01" + (vectors / "request.bin").read_bytes()
    frames["offset:request_unbound"] = b"BLFOFA01" + (vectors / "request_unbound.bin").read_bytes()
    obligation = {"shortfall_cents": 300_000, "owed_cents": 10_000_000, "received_cash_cents": 9_700_000, "claimed_adjustment_cents": 300_000,
                  "lawful_adjustment_cents": 300_000, "amount_satisfied": 1, "reporting_complete": 1, "verification_status": "SUPPORTED"}
    for label, actions, case in (
        ("none", [], None),
        ("ready", [("action:1", 1, False, "READY", False, 300_000, 0)], "OPEN"),
        ("acknowledged", [("action:1", 1, False, "ACKNOWLEDGED", True, 300_000, 100_000)], "AUTHORIZED"),
        ("two", [("action:1", 1, False, "CANCELLED", False, 100_000, 0), ("action:2", 2, True, "READY", False, 200_000, 50_000)], "OPEN"),
    ):
        frames["package:" + label] = engine._encode_package_request(obligation, actions, [(9_700_000, 1)], [(300_000, "AUTHORIZED")], 1, 0, case)
    return frames


def _answers(exe: Path, size: int, digest: bytes, frames: dict[str, bytes]) -> dict[str, bytes]:
    answers = {}
    for name, frame in frames.items():  # a fresh worker per frame: a refusal or exit must not hide the next answer
        workspace = Path(tempfile.mkdtemp(prefix="rr-equiv-", dir=os.environ.get("E3_SCRATCH")))
        worker = process.launch_contained_worker(exe, workspace=workspace, job_memory_cap_bytes=engine.EVALUATOR_JOB_MEMORY_CAP_BYTES,
                                                 expected_executable_size_bytes=size, expected_executable_sha256=digest)
        try:
            answers[name] = worker.exchange(frame, response_cap_bytes=CAP, timeout_seconds=engine.EVALUATOR_TIMEOUT_SECONDS)
        except Exception as error:
            answers[name] = ("exit:" + type(error).__name__).encode()
        finally:
            worker.close()
            shutil.rmtree(workspace, ignore_errors=True)
    return answers


@unittest.skipUnless(os.name == "nt" and WIRE_VECTORS.is_file(), "needs Windows and a built wire_vectors")
class RetiredPinEquivalence(unittest.TestCase):
    def test_every_live_request_kind_gets_the_same_answer_bytes(self) -> None:
        retired = subprocess.run(["git", "show", f"{RETIRED_REV}:artifacts/engine-evaluator/blind_financial_worker.exe"], cwd=ROOT,
                                 capture_output=True, check=True).stdout
        self.assertEqual(hashlib.sha256(retired).hexdigest(), RETIRED_SHA256)
        scratch = Path(tempfile.mkdtemp(prefix="rr-retired-", dir=os.environ.get("E3_SCRATCH")))
        self.addCleanup(shutil.rmtree, scratch, ignore_errors=True)
        old_exe = scratch / "blind_financial_worker.exe"
        old_exe.write_bytes(retired)
        frames = _frames()
        kinds = {frame[:8] for frame in frames.values()}
        self.assertLessEqual({b"BLFIN02\x00", b"BLFCMD03", b"BLFPAY01", b"BLFOFA01", b"BLFDPQ01"} - kinds, {b"BLFIN02\x00"}, kinds)
        new = _answers(engine.EVALUATOR_PATH, engine.EVALUATOR_ARTIFACT_SIZE_BYTES, engine.EVALUATOR_ARTIFACT_SHA256, frames)
        old = _answers(old_exe, len(retired), bytes.fromhex(RETIRED_SHA256), frames)
        self.assertEqual([name for name in frames if old[name] != new[name]], [])
        self.assertTrue(any(answer[:1] == b"\x00" for answer in new.values()), "no frame was answered; the check proves nothing")


if __name__ == "__main__":
    unittest.main()
