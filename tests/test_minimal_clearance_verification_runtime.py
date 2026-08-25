from __future__ import annotations

import io
from pathlib import Path
import tempfile
import unittest

from app.minimal_clearance_verification_queue import OperationStatement, QueueConfig, VerifierResult
from app.minimal_clearance_verification_runtime import MinimalClearanceVerificationRuntime, VerificationRuntimeError


class _Verifier:
    def verify(self, stream, statement, operation_ref):
        stream.read()
        stream.read()
        return VerifierResult(True, operation_ref, statement.assertion_identifier, statement.assertion_version, statement.state_profile_version, statement.valid_from_ms, statement.valid_until_ms, statement.batch_position, statement.batch_root, "synthetic-v7-unqualified", "ok", qualification_flags=statement.qualification_flags)


class RuntimeV7Tests(unittest.TestCase):
    def test_runtime_requires_explicit_synthetic_backend_and_creates_no_workspace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bl-runtime-v7-") as directory:
            root = Path(directory)
            with self.assertRaises(VerificationRuntimeError) as raised:
                MinimalClearanceVerificationRuntime(root=root)
            self.assertEqual(str(raised.exception), "runtime_backend_unqualified")
            runtime = MinimalClearanceVerificationRuntime(root=root, verifier=_Verifier(), config=QueueConfig("runtime-v7", 4))
            try:
                runtime.admit(statement=OperationStatement("assertion", 1, "state-profile-v7", 0, 100), proof_stream=io.BytesIO(b"synthetic-proof"))
                result = runtime.run(max_jobs=1)
                self.assertEqual(result.verified, 1)
                self.assertFalse(any(path.is_dir() and "workspace" in path.name.lower() for path in root.iterdir()))
                self.assertFalse(runtime.support_summary()["path_custody"])
            finally:
                runtime.close()


if __name__ == "__main__":
    unittest.main()
