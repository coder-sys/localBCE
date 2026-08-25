from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest

from app.minimal_clearance_verification_queue import IssuedOperationStatement, OperationTemplate, QueueConfig, VerifierResult
from app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime, VerificationRuntimeError


class _Verifier:
    def verify(self, stream, statement):
        raw = stream.read()
        stream.read()
        value = json.loads(raw[len(_PROOF_MAGIC) + 4:].decode("ascii"))
        embedded = IssuedOperationStatement(bytes.fromhex(value["operation_ref"]), value["assertion_identifier"], value["assertion_version"], value["state_profile_version"], value["valid_from_ms"], value["valid_until_ms"], value["batch_position"], None if value["batch_root"] is None else bytes.fromhex(value["batch_root"]), None if value["approved_source_registry_root"] is None else bytes.fromhex(value["approved_source_registry_root"]), tuple(value["qualification_flags"]))
        return VerifierResult(True, embedded.operation_ref, embedded.assertion_identifier, embedded.assertion_version, embedded.state_profile_version, embedded.valid_from_ms, embedded.valid_until_ms, embedded.batch_position, embedded.batch_root, embedded.approved_source_registry_root, "synthetic-v7-unqualified", "ok", qualification_flags=embedded.qualification_flags)


_PROOF_MAGIC = b"BL/SYNTHETIC-QUEUE-PROOF/v7\x00"


def _proof(statement: IssuedOperationStatement) -> bytes:
    raw = statement.canonical_bytes
    return _PROOF_MAGIC + len(raw).to_bytes(4, "big") + raw


class RuntimeV7Tests(unittest.TestCase):
    def test_runtime_requires_explicit_synthetic_backend_and_creates_no_workspace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bl-runtime-v7-") as directory:
            root = Path(directory)
            with self.assertRaises(VerificationRuntimeError) as raised:
                MinimalClearanceVerificationRuntime(root=root)
            self.assertEqual(str(raised.exception), "runtime_backend_unqualified")
            runtime = MinimalClearanceVerificationRuntime(root=root, verifier=_Verifier(), config=QueueConfig("runtime-v7", 4))
            try:
                statement = runtime.issue_operation(template=OperationTemplate("assertion", 1, "state-profile-v7", 0, 10**15))
                runtime.submit_handoff(operation_ref=statement.operation_ref, proof_stream=io.BytesIO(_proof(statement)))
                result = runtime.run(max_jobs=1)
                self.assertEqual(result.verified, 1)
                self.assertFalse(any(path.is_dir() and "workspace" in path.name.lower() for path in root.iterdir()))
                self.assertFalse(runtime.support_summary()["path_custody"])
            finally:
                runtime.close()

    def test_runtime_reports_startup_recovery_once(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bl-runtime-recovery-v7-") as directory:
            root = Path(directory)
            config = QueueConfig("runtime-recovery-v7", 4)
            runtime = MinimalClearanceVerificationRuntime(root=root, verifier=_Verifier(), config=config)
            statement = runtime.issue_operation(template=OperationTemplate("recovery", 1, "state-profile-v7", 0, 10**15))
            runtime.submit_handoff(operation_ref=statement.operation_ref, proof_stream=io.BytesIO(_proof(statement)))
            runtime._store._claim_next()
            runtime.close()
            restarted = MinimalClearanceVerificationRuntime(root=root, verifier=_Verifier(), config=config)
            try:
                self.assertEqual(restarted._recovered_leases, 1)
                self.assertEqual(restarted.run(max_jobs=1).outcome, "EMPTY")
            finally:
                restarted.close()


if __name__ == "__main__":
    unittest.main()
