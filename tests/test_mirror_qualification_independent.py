"""Focused public-error retention checks for qualification verification."""

from __future__ import annotations

import traceback
import unittest
from unittest.mock import patch

from app.mirror import qualification_independent as qualification


def _manifest_raw() -> bytes:
    dependencies = [
        {
            "dependency_id": dependency_id,
            "owner": qualification.DEPENDENCY_OWNERS[dependency_id],
            "required": True,
            "state": "MISSING",
            "evidence": None,
        }
        for dependency_id in sorted(qualification.DEPENDENCY_IDS)
    ]
    operations = [
        {
            "operation_id": operation_id,
            "owner": "STATE_OPERATIONS_AUTHORITY",
            "required": True,
            "state": "PRESENT_UNVERIFIED",
            "evidence_class": qualification.REHEARSAL_EVIDENCE_CLASS,
            "observed_rpo_seconds": None,
            "observed_rto_ms": None,
            "fault_codes": [],
            "proof": None,
        }
        for operation_id in sorted(qualification.OPERATION_IDS)
    ]
    value: dict[str, object] = {
        "schema": qualification.SCHEMA,
        "schema_version": qualification.SCHEMA_VERSION,
        "profile_binding": {
            "profile_id": qualification.PROFILE_ID,
            "version": qualification.PROFILE_VERSION,
            "profile_digest": qualification.PROFILE_DIGEST,
        },
        "subject": qualification.SUBJECT,
        "scope": qualification.SCOPE,
        "as_of": 1,
        "owners": qualification.OWNER_REGISTRY,
        "components": qualification.COMPONENT_CONTRACTS,
        "external_ports": qualification.EXTERNAL_PORT_CONTRACTS,
        "dependencies": dependencies,
        "operations": operations,
        "custody": None,
        "readiness": {
            "software_contract_verified": True,
            "synthetic_rehearsal_evidence_verified": False,
            "external_evidence_authenticated_current": False,
            "operational_qualification_verified": False,
            "unresolved_blockers": [
                "SYNTHETIC_REHEARSAL_EVIDENCE_INCOMPLETE",
                "EXTERNAL_AUTHENTICATED_EVIDENCE_UNAVAILABLE",
                "PRODUCTION_CUSTODY_UNQUALIFIED",
                "PRODUCTION_OPERATIONS_UNQUALIFIED",
                "CONTROLLED_SHADOW_NOT_AUTHORIZED",
                "PRODUCTION_QUALIFICATION_UNIMPLEMENTED",
            ],
            "final_claim": qualification.READINESS_NOT_READY,
        },
        "pilot_state": qualification.REHEARSAL_NOT_READY,
        "gap_ledger": qualification.GAP_LEDGER,
        "flags": qualification.FIXED_FLAGS,
        "authority": qualification.AUTHORITY_FLAGS,
        "manifest_id": None,
        "prior_artifact_id": None,
        "prior_stage_id": None,
        "artifact_id": None,
        "current_stage_id": None,
        "transition_id": None,
    }
    core = qualification._core_without_custody(value)
    key_id = "SYNTHETIC_QUALIFICATION_KEY_V1"
    key_epoch = 1
    key = qualification._synthetic_key(key_id, key_epoch)
    seed = qualification._canonical(
        {
            "profile_id": qualification.PROFILE_ID,
            "manifest_core_digest": qualification._digest("manifest-core", core),
            "purpose": qualification.CUSTODY_PURPOSE,
        }
    )
    ciphertext = qualification._crypt(seed, key)
    envelope = {
        "schema": "synthetic-envelope-encryption-v1",
        "key_id": key_id,
        "key_epoch": key_epoch,
        "ciphertext": ciphertext.hex(),
        "tag": qualification._tag(key, {"schema": "synthetic-envelope-encryption-v1", "key_id": key_id, "key_epoch": key_epoch}, ciphertext),
        "plaintext_digest": qualification._raw_digest("envelope-plaintext", seed),
    }
    audit = [{"action": "SEAL", "key_id": key_id, "key_epoch": key_epoch, "status": "OBSERVED"}]
    value["custody"] = {
        "mode": "SYNTHETIC_DETERMINISTIC_ENVELOPE",
        "key_id": key_id,
        "key_epoch": key_epoch,
        "key_state": "ACTIVE",
        "envelope": envelope,
        "audit": audit,
        "audit_root": qualification._digest("custody-audit", audit),
        "envelope_digest": qualification._digest("custody-envelope", envelope),
        "encryption_at_rest_qualified": False,
        "production_key_custody": False,
    }
    value["manifest_id"] = qualification._digest("manifest-id", core)
    value["artifact_id"] = qualification._digest("artifact-id", qualification._identity_body(value))
    value["current_stage_id"] = qualification._digest(
        "stage-id",
        {
            "manifest_id": value["manifest_id"],
            "pilot_state": qualification.REHEARSAL_NOT_READY,
            "readiness": qualification.READINESS_NOT_READY,
            "prior_artifact_id": None,
            "prior_stage_id": None,
        },
    )
    value["transition_id"] = qualification._digest(
        "transition-id",
        {
            "artifact_id": value["artifact_id"],
            "prior_artifact_id": None,
            "prior_stage_id": None,
            "current_stage_id": value["current_stage_id"],
        },
    )
    return qualification._canonical(value)


class QualificationIndependentErrorTests(unittest.TestCase):
    def _assert_redacted(self, action, expected: str, canary: str) -> None:
        with self.assertRaises(qualification.IndependentQualificationError) as caught:
            action()
        error = caught.exception
        rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
        self.assertEqual(str(error), expected)
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertTrue(error.__suppress_context__)
        self.assertNotIn(canary, repr(error) + rendered)

    def test_current_prior_and_nested_verifier_errors_are_fixed_and_redacted(self) -> None:
        canary = "PHI_CANARY Bearer SECRET C:\\Users\\private\\record"
        current = b'{"current":"' + canary.encode("ascii")
        self._assert_redacted(lambda: qualification.verify_artifact(current), "qualification:parse", canary)

        valid = _manifest_raw()
        self.assertTrue(qualification.verify_artifact(valid)["accepted"])
        prior = b'{"prior":"' + canary.encode("ascii")
        self._assert_redacted(
            lambda: qualification.verify_artifact(valid, prior_raw=prior),
            "qualification:parse",
            canary,
        )

        with patch.object(qualification, "_validate_custody", side_effect=ValueError(canary)):
            self._assert_redacted(lambda: qualification.verify_artifact(valid), "qualification:verification", canary)


if __name__ == "__main__":
    unittest.main()
