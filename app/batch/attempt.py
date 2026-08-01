from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from app.batch.poseidon import FIELD_MODULUS, domain_poseidon_hash
from app.batch.stark_encoding import encode_claim, pack_felt_text
from app.canonical_encoding import digest_bytes
from app.models import SharedContext


ATTEMPT_RECORD_SCHEMA: Final[int] = 1
ATTEMPT_NULLIFIER_DOMAIN: Final[str] = "BL/ATTEMPT-NULLIFIER/LEGACY/v1"
ATTEMPT_NULLIFIER_PUBLIC_SALT: Final[str] = "BL/ATTEMPT-NULLIFIER/PUBLIC-SALT/v1"
SYNTHETIC_SOURCE_AUTHORITY_ID: Final[str] = "BL-SYNTH-GOV-INTAKE-V1"

REVISION_KIND_ORIGINAL: Final[int] = 1
REVISION_KIND_CORRECTION: Final[int] = 2
REVISION_KIND_REPLACEMENT: Final[int] = 3
REVISION_KIND_VOID: Final[int] = 4
_REVISION_KINDS: Final[frozenset[int]] = frozenset(
    {
        REVISION_KIND_ORIGINAL,
        REVISION_KIND_CORRECTION,
        REVISION_KIND_REPLACEMENT,
        REVISION_KIND_VOID,
    }
)


@dataclass(frozen=True)
class GovernedClaimAttempt:
    """Authority-issued identity for one immutable adjudication attempt.

    Only original version-one attempts are enabled in the current synthetic
    profile. Correction/replacement/void records are represented by the schema
    but require the lifecycle authority and parent-state rules before use.
    """

    source_authority_id: str
    source_claim_id: str
    attempt_version: int
    revision_kind: int
    parent_attempt_version: int

    def validate_for_claim(self, ctx: SharedContext, *, original_only: bool = True) -> None:
        pack_felt_text(self.source_authority_id)
        pack_felt_text(self.source_claim_id)
        if self.source_claim_id != ctx.claim_id:
            raise ValueError("attempt_source_claim_id_mismatch")
        if not isinstance(self.attempt_version, int) or isinstance(self.attempt_version, bool):
            raise ValueError("attempt_version_invalid")
        if not isinstance(self.parent_attempt_version, int) or isinstance(self.parent_attempt_version, bool):
            raise ValueError("attempt_parent_version_invalid")
        if self.attempt_version < 1 or self.attempt_version >= 2**32:
            raise ValueError("attempt_version_invalid")
        if self.parent_attempt_version < 0 or self.parent_attempt_version >= 2**32:
            raise ValueError("attempt_parent_version_invalid")
        if not isinstance(self.revision_kind, int) or isinstance(self.revision_kind, bool):
            raise ValueError("attempt_revision_kind_invalid")
        if self.revision_kind not in _REVISION_KINDS:
            raise ValueError("attempt_revision_kind_invalid")
        if self.revision_kind == REVISION_KIND_ORIGINAL:
            if self.attempt_version != 1 or self.parent_attempt_version != 0:
                raise ValueError("attempt_original_lifecycle_invalid")
        elif self.attempt_version <= 1 or self.parent_attempt_version != self.attempt_version - 1:
            raise ValueError("attempt_revision_lifecycle_invalid")
        if original_only and (
            self.revision_kind != REVISION_KIND_ORIGINAL
            or self.attempt_version != 1
            or self.parent_attempt_version != 0
        ):
            raise ValueError("attempt_revision_pending_lifecycle_authority")


def synthetic_original_attempt(
    ctx: SharedContext,
    *,
    source_authority_id: str = SYNTHETIC_SOURCE_AUTHORITY_ID,
) -> GovernedClaimAttempt:
    """Deterministic synthetic fixture; never an authority for production issuance."""

    attempt = GovernedClaimAttempt(
        source_authority_id=source_authority_id,
        source_claim_id=ctx.claim_id,
        attempt_version=1,
        revision_kind=REVISION_KIND_ORIGINAL,
        parent_attempt_version=0,
    )
    attempt.validate_for_claim(ctx)
    return attempt


def legacy_attempt_identity_commitment(attempt: GovernedClaimAttempt, ctx: SharedContext) -> int:
    attempt.validate_for_claim(ctx, original_only=False)
    encoded = encode_claim(ctx)
    return domain_poseidon_hash(
        "claim_source",
        [
            ATTEMPT_RECORD_SCHEMA,
            pack_felt_text(attempt.source_authority_id),
            pack_felt_text(ctx.payer_id),
            encoded.provider_npi,
            pack_felt_text(attempt.source_claim_id),
            attempt.attempt_version,
            attempt.revision_kind,
            attempt.parent_attempt_version,
        ],
    )


def legacy_attempt_claim_snapshot_commitment(ctx: SharedContext) -> int:
    encoded = encode_claim(ctx)
    return domain_poseidon_hash(
        "claim_source",
        [
            ATTEMPT_RECORD_SCHEMA,
            encoded.member_id,
            encoded.service_date,
            encoded.service_lines_commitment,
            encoded.diagnosis_commitment,
            encoded.diagnosis_count,
            encoded.total_charge_cents,
            encoded.service_line_count,
        ],
    )


def legacy_attempt_record_commitment(attempt: GovernedClaimAttempt, ctx: SharedContext) -> int:
    return domain_poseidon_hash(
        "claim_source",
        [
            ATTEMPT_RECORD_SCHEMA,
            legacy_attempt_identity_commitment(attempt, ctx),
            legacy_attempt_claim_snapshot_commitment(ctx),
        ],
    )


def _field_from_record(record_type: str, fields: list[object]) -> int:
    return int.from_bytes(digest_bytes(record_type, fields), "big") % FIELD_MODULUS


def legacy_attempt_nullifier(
    attempt: GovernedClaimAttempt,
    ctx: SharedContext,
    *,
    governed_pepper: str,
) -> int:
    """Legacy felt nullifier derived from the stable governed attempt identity.

    The strict-PQ SHA3-512 nullifier is a separate sidecar value and must never
    be derived from this felt.  Mutable claim content, payer/provider fields,
    adjudication, policy/oracle facts, and batch context are deliberately
    excluded: changing any of them must not mint a new key for the same
    governed attempt.
    """

    if not governed_pepper:
        raise ValueError("attempt_governed_pepper_empty")
    attempt.validate_for_claim(ctx, original_only=False)
    domain_field = _field_from_record(
        "attempt_nullifier_domain_field",
        [ATTEMPT_NULLIFIER_DOMAIN, ATTEMPT_NULLIFIER_PUBLIC_SALT, governed_pepper],
    )
    record_field = _field_from_record(
        "attempt_nullifier_record_field",
        [
            ATTEMPT_NULLIFIER_DOMAIN,
            ATTEMPT_NULLIFIER_PUBLIC_SALT,
            governed_pepper,
            attempt.source_authority_id,
            attempt.source_claim_id,
            attempt.attempt_version,
            attempt.revision_kind,
            attempt.parent_attempt_version,
        ],
    )
    value = domain_poseidon_hash("nullifier", [domain_field, record_field])
    if value <= 0 or value >= FIELD_MODULUS - 1:
        raise ValueError("attempt_nullifier_reserved_value")
    return value
