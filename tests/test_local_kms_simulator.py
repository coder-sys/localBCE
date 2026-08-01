from __future__ import annotations

import base64
import os
import unittest
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from tools.encrypted_witness_envelope import oaep_label_for_context
from tools.local_kms_simulator import LocalKmsSimulator


class LocalKmsSimulatorTests(unittest.TestCase):
    def test_simulator_is_forbidden_in_production(self) -> None:
        from tools.local_kms_simulator import LocalKmsClient

        with mock.patch.dict(os.environ, {"BL_ENV": "production"}):
            with self.assertRaisesRegex(RuntimeError, "forbidden in production"):
                LocalKmsClient.from_environment()

    def test_separate_process_unwrap_audit_replay_revocation_and_outage(self) -> None:
        simulator = LocalKmsSimulator(agency_id="agency-a", key_id="wrap-key-a")
        client = simulator.start()
        public = serialization.load_pem_public_key(
            base64.b64decode(client.public_key()["public_key_pem_b64"])
        )
        dek = b"d" * 32
        context = "a" * 64
        wrapped = public.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=oaep_label_for_context(context),
            ),
        )
        self.assertEqual(
            dek,
            client.unwrap_key(
                wrapped,
                "wrap-key-a",
                agency_id="agency-a",
                request_id="request-1",
                context_sha256=context,
            ),
        )
        with self.assertRaisesRegex(RuntimeError, "replay rejected"):
            client.unwrap_key(
                wrapped,
                "wrap-key-a",
                agency_id="agency-a",
                request_id="request-1",
                context_sha256=context,
            )
        self.assertEqual("unwrap_succeeded", client.audit_events()[0]["event"])

        with self.assertRaisesRegex(RuntimeError, "wrapped key authentication failed"):
            client.unwrap_key(
                wrapped,
                "wrap-key-a",
                agency_id="agency-a",
                request_id="request-wrong-context",
                context_sha256="b" * 64,
            )

        legacy_wrapped = public.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        with self.assertRaisesRegex(RuntimeError, "wrapped key authentication failed"):
            client.unwrap_key(
                legacy_wrapped,
                "wrap-key-a",
                agency_id="agency-a",
                request_id="request-legacy-unbound",
                context_sha256=context,
            )
        client.revoke()
        with self.assertRaisesRegex(RuntimeError, "revoked"):
            client.unwrap_key(
                wrapped,
                "wrap-key-a",
                agency_id="agency-a",
                request_id="request-2",
                context_sha256=context,
            )
        simulator.stop()
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            client.public_key()


if __name__ == "__main__":
    unittest.main()
