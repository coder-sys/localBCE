"""C0 differential parity harness for the S2 scalar controls.

This module is the only S2 bridge that imports the C0 fixture.  The C1-C4
relation module remains independent of claim and payment implementations.  A
candidate-specific root is never compared to a C0 root here; parity is checked
at the semantic boundary and every candidate must reject the same negative
classes.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512

from experiments.bl_pq512_crypto_foundation.c0_control_fixture import (
    build_c0_control_fixture,
)
from experiments.bl_pq512_crypto_foundation.scalar_state_relation_controls import (
    CANDIDATE_IDS,
    C0_NEGATIVE_CASE_NAMES,
    PROFILE_CLAIM_SLOTS,
    STATUS as S2_STATUS,
    ScalarBatchResult,
    ScalarRelationError,
    build_scalar_control_batch,
    build_scalar_negative_corpus,
    run_all_scalar_controls,
    scalar_parity_summary,
    verify_negative_case,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


STATUS: str = "S2_C0_DIFFERENTIAL_PARITY_V1_SYNTHETIC_NONPRODUCTION"


@dataclass(frozen=True, slots=True)
class ScalarC0ParityRecord:
    profile_id: str
    c0_manifest_length: int
    c0_manifest_sha3_512_hex: str
    candidate_ids: tuple[str, ...]
    positive_semantic_digest_sha3_512_hex: str
    negative_case_names: tuple[str, ...]
    negative_rejection_families: tuple[tuple[str, tuple[str, ...]], ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "s2_status": S2_STATUS,
            "profile_id": self.profile_id,
            "c0_manifest_length": self.c0_manifest_length,
            "c0_manifest_sha3_512_hex": self.c0_manifest_sha3_512_hex,
            "candidate_ids": list(self.candidate_ids),
            "positive_semantic_digest_sha3_512_hex": self.positive_semantic_digest_sha3_512_hex,
            "negative_case_names": list(self.negative_case_names),
            "negative_rejection_families": {
                name: list(families) for name, families in self.negative_rejection_families
            },
        }


def _expected_c0_summary(fixture) -> dict[str, object]:
    return {
        "profile_id": fixture.profile_id,
        "claim_slots": fixture.claim_slots,
        "map_geometry": tuple(
            (item.lane, item.operation_count, item.access_rows, item.position_rows)
            for item in fixture.map_results
        ),
        "membership_absence": tuple(
            (item.lane, True, True) for item in fixture.map_results
        ),
        "state_changes": tuple(
            (
                item.lane,
                item.root_before_hex != item.root_after_hex,
                item.update_root_before_hex != item.update_root_after_hex,
                item.cursor_after - item.cursor_before,
                item.update_cursor_after - item.update_cursor_before,
            )
            for item in fixture.map_results
        ),
        "case_outcomes": fixture.payment.case_outcomes,
        "money": (
            fixture.payment.total_plan_payable_cents,
            fixture.payment.total_debits_cents,
            fixture.payment.total_credits_cents,
        ),
    }


def _require_positive_parity(fixture, batch, result: ScalarBatchResult) -> None:
    actual = scalar_parity_summary(batch, result)
    expected = _expected_c0_summary(fixture)
    for field in expected:
        if actual[field] != expected[field]:
            raise ScalarRelationError(f"s2_c0_positive_parity_mismatch:{field}")


def build_c0_parity_records() -> tuple[ScalarC0ParityRecord, ...]:
    """Run positive and negative parity for both frozen C0 profiles."""

    records: list[ScalarC0ParityRecord] = []
    for profile_id in PROFILE_CLAIM_SLOTS:
        fixture = build_c0_control_fixture(PROFILES[profile_id])
        batch = build_scalar_control_batch(profile_id)
        results = run_all_scalar_controls(batch)
        for result in results:
            _require_positive_parity(fixture, batch, result)
        semantic_digests = {result.semantic_digest_512 for result in results}
        if len(semantic_digests) != 1:
            raise ScalarRelationError("s2_c0_positive_semantic_digest_divergence")
        rejection_families: list[tuple[str, tuple[str, ...]]] = []
        for case in build_scalar_negative_corpus(profile_id):
            if case.name not in C0_NEGATIVE_CASE_NAMES:
                raise ScalarRelationError("s2_c0_negative_case_set_mismatch")
            families = tuple(
                verify_negative_case(candidate_id, case) for candidate_id in CANDIDATE_IDS
            )
            if len(families) != len(CANDIDATE_IDS) or any(not family for family in families):
                raise ScalarRelationError(f"s2_c0_negative_parity_mismatch:{case.name}")
            rejection_families.append((case.name, families))
        records.append(
            ScalarC0ParityRecord(
                profile_id,
                fixture.fixture_manifest_length,
                fixture.fixture_manifest_sha3_512_hex,
                CANDIDATE_IDS,
                next(iter(semantic_digests)).hex(),
                tuple(name for name, _ in rejection_families),
                tuple(rejection_families),
            )
        )
    return tuple(records)


def parity_manifest_sha3_512_hex(records: tuple[ScalarC0ParityRecord, ...]) -> str:
    """Hash the bounded public parity record for documentation readback."""

    payload = "|".join(
        ":".join(
            (
                record.profile_id,
                str(record.c0_manifest_length),
                record.c0_manifest_sha3_512_hex,
                record.positive_semantic_digest_sha3_512_hex,
                ",".join(record.negative_case_names),
            )
        )
        for record in records
    ).encode("ascii")
    return sha3_512(payload).hexdigest()


__all__ = (
    "STATUS",
    "ScalarC0ParityRecord",
    "build_c0_parity_records",
    "parity_manifest_sha3_512_hex",
)
