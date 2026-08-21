"""Fixture-only ports for the controlled-shadow runtime tests.

Nothing in this module authenticates an external authority.  The verifier is
explicitly marked fixture-only and can produce only the nonqualified
``SYNTHETIC_REHEARSAL`` mode.  The evaluator returns aggregate observations,
never source records or business decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Mapping

from app.mirror import controlled_shadow_runtime as runtime
from app.mirror import controlled_shadow_runtime_independent as independent


@dataclass
class SyntheticClock:
    value: int = 1_100

    def now(self) -> int:
        return self.value

    def advance(self, seconds: int) -> None:
        if type(seconds) is not int or seconds < 0:
            raise ValueError("fixture:clock-advance")
        self.value += seconds


class SyntheticAuthorizationVerifier:
    """Fixture-only authorization-shaped verifier; never state authority."""

    verifier_id = "SYNTHETIC_SHADOW_AUTHORIZER_V1"
    verifier_epoch = 1
    mode = independent.MODE_SYNTHETIC
    fixture_only = True

    def verify(self, input_raw: bytes) -> runtime.VerifiedShadowAuthorizationV1:
        value = independent._parse(input_raw, maximum=independent.MAX_AUTH_BYTES)
        if set(value) != {"schema", "profile", "manifest"} or value["schema"] != independent.AUTH_INPUT_SCHEMA:
            raise ValueError("fixture:authorization-input")
        profile = independent.verify_profile(value["profile"])
        manifest = value["manifest"]
        if not isinstance(manifest, dict):
            raise ValueError("fixture:authorization-manifest")
        profile_digest = independent.profile_digest(profile)
        manifest_digest = independent._digest("upstream-manifest", manifest)
        body: dict[str, object] = {
            "evidence_sha3_512": hashlib.sha3_512(input_raw).hexdigest(),
            "evidence_byte_length": len(input_raw),
            "profile_digest": profile_digest,
            "manifest_digest": manifest_digest,
            "source_policy_digest": manifest["source_policy_digest"],
            "scope": profile["scope"],
            "mode": self.mode,
            "terms_digest": profile["governance_evidence_digest"],
            "retention_policy_digest": profile["privacy_evidence_digest"],
            "revocation_head_digest": profile["quarantine_head_root"],
            "authority_identity_digest": profile["governance_artifact_id"],
            "valid_from": profile["authorization_effective_start"] + 50,
            "valid_until": profile["authorization_effective_end"] - 50,
            "observed_at": profile["authorization_effective_start"] + 100,
            "verifier_id": self.verifier_id,
            "verifier_epoch": self.verifier_epoch,
            "external_authority_authenticated": False,
            "zero_phi": True,
            "state_owned": True,
        }
        return runtime.VerifiedShadowAuthorizationV1(
            authorization_id=independent._digest("authorization-id", body),
            **body,
        )


@dataclass
class SyntheticShadowEvaluator:
    """Fixture-only bounded aggregate evaluator."""

    clock: SyntheticClock
    results: Mapping[int, str] = field(default_factory=lambda: {0: "PARITY", 1: "DISCREPANCY", 2: "INDETERMINATE"})
    evaluator_id: str = "SYNTHETIC_SHADOW_EVALUATOR_V1"
    evaluator_epoch: int = 1
    fail_once: Mapping[int, str] = field(default_factory=dict)
    _failed: set[int] = field(default_factory=set, init=False, repr=False)

    def evaluate(self, input_raw: bytes) -> runtime.VerifiedShadowEvaluationV1:
        value = independent._parse(input_raw, maximum=independent.MAX_EVALUATOR_BYTES)
        if set(value) != {"schema", "profile_digest", "manifest_digest", "session_id", "slot_number", "attempt", "mode"} or value["schema"] != independent.EVALUATOR_INPUT_SCHEMA:
            raise ValueError("fixture:evaluator-input")
        slot = int(value["slot_number"])
        if slot in self.fail_once and slot not in self._failed:
            self._failed.add(slot)
            raise runtime.RuntimeEvaluatorRetryable(self.fail_once[slot])
        result = self.results.get(slot, "INDETERMINATE")
        if result == "PARITY":
            aggregate = {"evaluated": 1, "matched": 1, "differing": 0, "unknown": 0}
        elif result == "DISCREPANCY":
            aggregate = {"evaluated": 1, "matched": 0, "differing": 1, "unknown": 0}
        else:
            result = "INDETERMINATE"
            aggregate = {"evaluated": 1, "matched": 0, "differing": 0, "unknown": 1}
        body: dict[str, object] = {
            "session_id": value["session_id"],
            "profile_digest": value["profile_digest"],
            "slot_number": slot,
            "attempt": int(value["attempt"]),
            "input_digest": independent._raw_digest(input_raw),
            "evaluator_id": self.evaluator_id,
            "evaluator_epoch": self.evaluator_epoch,
            "result": result,
            "aggregate": aggregate,
            "observed_at": self.clock.now(),
            "completed_at": self.clock.now(),
            "zero_phi": True,
        }
        return runtime.VerifiedShadowEvaluationV1(result_digest=independent._digest("evaluation-result", body), **body)


__all__ = ["SyntheticClock", "SyntheticAuthorizationVerifier", "SyntheticShadowEvaluator"]
