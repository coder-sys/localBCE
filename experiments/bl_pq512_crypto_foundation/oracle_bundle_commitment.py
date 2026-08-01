"""Throughput-optimal, audit-linked oracle commitment for Wave 1B.

The proof-facing commitment hashes one fixed bundle per claim in parallel and
then hashes the ordered leaf-digest vector.  A separate binary audit tree reuses
the exact same leaf digests.  A source authority signs both roots together, so
the fast execution surface never discards the independently auditable surface.

This module is synthetic/nonactivating until the complete Wave 1B proof and
attestation verifier select the surrounding suite.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import hmac
import re
from typing import Final, Sequence

from experiments.fixed_shape_claim_air.profile import (
    AUTHORIZATIONS_PER_CLAIM,
    PROFILES,
    CalibrationProfile,
)
from experiments.fixed_shape_claim_air.semantics import (
    ClaimSlot,
    SlotKind,
    validate_slot_shape,
)


STATUS: Final[str] = (
    "WAVE1B_ORACLE_BUNDLE_EXECUTION_AND_AUDIT_COMMITMENTS_V1_NONACTIVATING"
)
RATE_BYTES: Final[int] = 72
DIGEST_BYTES: Final[int] = 64
TOKEN_CHARS: Final[int] = 64
TOKEN_ENCODED_BYTES: Final[int] = 42
AUTHORIZATION_FLAGS_BYTES: Final[int] = 19

BUNDLE_MAGIC: Final[bytes] = b"BLPQORB1"
EXECUTION_ROOT_MAGIC: Final[bytes] = b"BLPQOXR1"
AUDIT_NODE_MAGIC: Final[bytes] = b"BLPQOAN1"
AUDIT_ROOT_MAGIC: Final[bytes] = b"BLPQOAR1"
ATTESTATION_MAGIC: Final[bytes] = b"BLPQOAT1"

_FIRST_ALPHABET: Final[str] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_TAIL_ALPHABET: Final[str] = _FIRST_ALPHABET + "-"
_FIRST_INDEX: Final[dict[str, int]] = {
    value: index for index, value in enumerate(_FIRST_ALPHABET)
}
_TAIL_INDEX: Final[dict[str, int]] = {
    value: index for index, value in enumerate(_TAIL_ALPHABET)
}
_TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Z0-9][A-Z0-9-]{0,63}\Z")
_TOKEN_RADIX: Final[int] = len(_TAIL_ALPHABET)
_TOKEN_RANK_LIMIT: Final[int] = _TOKEN_RADIX**TOKEN_CHARS

_PROFILE_CODES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}
_CODE_PROFILES: Final[dict[int, str]] = {
    value: key for key, value in _PROFILE_CODES.items()
}

FACT_NAMES: Final[tuple[str, ...]] = (
    "eligibility_active",
    "provider_enrolled",
    "provider_not_suspended",
    "not_deceased",
    "duplicate_claim",
    "program_integrity_hold",
)

BUNDLE_BYTES: Final[int] = (
    len(BUNDLE_MAGIC)
    + 1  # profile code
    + 4  # slot index
    + 1  # real/fact flags
    + AUTHORIZATION_FLAGS_BYTES
    + AUTHORIZATIONS_PER_CLAIM * TOKEN_ENCODED_BYTES
)


def _profile_code(profile_id: str) -> int:
    if type(profile_id) is not str or profile_id not in _PROFILE_CODES:
        raise ValueError("oracle_bundle_profile_unknown")
    return _PROFILE_CODES[profile_id]


def _permutations(preimage_bytes: int) -> int:
    if type(preimage_bytes) is not int or preimage_bytes < 0:
        raise ValueError("oracle_bundle_preimage_length_invalid")
    return preimage_bytes // RATE_BYTES + 1


def encode_authorization_token(token: str) -> bytes:
    """Encode the exact canonical-token language into its optimal 42 bytes.

    Empty plus all valid length-1-through-64 tokens has exactly ``37**64``
    values.  Rank zero is empty; a length-L token occupies
    ``[37**(L-1), 37**L)``.  No variable length or ambiguous padding exists.
    """

    if type(token) is not str:
        raise TypeError("oracle_bundle_token_not_text")
    if token == "":
        rank = 0
    else:
        if _TOKEN_PATTERN.fullmatch(token) is None:
            raise ValueError("oracle_bundle_token_not_canonical")
        length = len(token)
        tail_power = _TOKEN_RADIX ** (length - 1)
        rank = tail_power + _FIRST_INDEX[token[0]] * tail_power
        for index, value in enumerate(token[1:], start=1):
            rank += _TAIL_INDEX[value] * (_TOKEN_RADIX ** (length - 1 - index))
    if not 0 <= rank < _TOKEN_RANK_LIMIT:
        raise AssertionError("oracle_bundle_token_rank_out_of_range")
    encoded = rank.to_bytes(TOKEN_ENCODED_BYTES, "big")
    if int.from_bytes(encoded, "big") != rank:
        raise AssertionError("oracle_bundle_token_encoding_not_exact")
    return encoded


def decode_authorization_token(encoded: bytes) -> str:
    if type(encoded) is not bytes or len(encoded) != TOKEN_ENCODED_BYTES:
        raise ValueError("oracle_bundle_token_encoding_length_invalid")
    rank = int.from_bytes(encoded, "big")
    if rank >= _TOKEN_RANK_LIMIT:
        raise ValueError("oracle_bundle_token_rank_noncanonical")
    if rank == 0:
        return ""

    length = 1
    tail_power = 1
    while rank >= tail_power * _TOKEN_RADIX:
        tail_power *= _TOKEN_RADIX
        length += 1
    if length > TOKEN_CHARS:
        raise ValueError("oracle_bundle_token_length_noncanonical")
    remainder = rank - tail_power
    first_index, remainder = divmod(remainder, tail_power)
    if not 0 <= first_index < len(_FIRST_ALPHABET):
        raise ValueError("oracle_bundle_token_first_symbol_noncanonical")
    out = [_FIRST_ALPHABET[first_index]]
    for exponent in range(length - 2, -1, -1):
        power = _TOKEN_RADIX**exponent
        digit, remainder = divmod(remainder, power)
        out.append(_TAIL_ALPHABET[digit])
    if remainder != 0:
        raise AssertionError("oracle_bundle_token_decode_remainder")
    token = "".join(out)
    if encode_authorization_token(token) != encoded:
        raise ValueError("oracle_bundle_token_reencoding_mismatch")
    return token


@dataclass(frozen=True, slots=True)
class OracleFacts:
    eligibility_active: bool
    provider_enrolled: bool
    provider_not_suspended: bool
    not_deceased: bool
    duplicate_claim: bool
    program_integrity_hold: bool

    def __post_init__(self) -> None:
        if any(type(getattr(self, name)) is not bool for name in FACT_NAMES):
            raise TypeError("oracle_bundle_fact_not_boolean")


@dataclass(frozen=True, slots=True)
class OracleAuthorization:
    line_enabled: bool
    required: bool
    present: bool
    token: str

    def __post_init__(self) -> None:
        if any(
            type(value) is not bool
            for value in (self.line_enabled, self.required, self.present)
        ):
            raise TypeError("oracle_bundle_authorization_flag_not_boolean")
        encode_authorization_token(self.token)
        if not self.line_enabled and (self.required or self.present or self.token):
            raise ValueError("oracle_bundle_disabled_authorization_not_zero")
        if self.present and not self.token:
            raise ValueError("oracle_bundle_present_authorization_token_missing")


@dataclass(frozen=True, slots=True)
class OracleBundle:
    profile_id: str
    slot_index: int
    slot_is_real: bool
    facts: OracleFacts
    authorizations: tuple[OracleAuthorization, ...]

    def __post_init__(self) -> None:
        profile = PROFILES.get(self.profile_id)
        _profile_code(self.profile_id)
        if profile is None:
            raise ValueError("oracle_bundle_profile_unknown")
        if type(self.slot_index) is not int or not 0 <= self.slot_index < profile.claim_slots:
            raise ValueError("oracle_bundle_slot_index_invalid")
        if type(self.slot_is_real) is not bool:
            raise TypeError("oracle_bundle_slot_kind_not_boolean")
        if not isinstance(self.facts, OracleFacts):
            raise TypeError("oracle_bundle_facts_required")
        if (
            type(self.authorizations) is not tuple
            or len(self.authorizations) != AUTHORIZATIONS_PER_CLAIM
            or any(not isinstance(value, OracleAuthorization) for value in self.authorizations)
        ):
            raise TypeError("oracle_bundle_authorizations_invalid")
        if not self.slot_is_real:
            if any(getattr(self.facts, name) for name in FACT_NAMES):
                raise ValueError("oracle_bundle_cover_facts_not_zero")
            if any(
                value.line_enabled or value.required or value.present or value.token
                for value in self.authorizations
            ):
                raise ValueError("oracle_bundle_cover_authorizations_not_zero")


def oracle_bundle_from_slot(profile: CalibrationProfile, slot: ClaimSlot) -> OracleBundle:
    if not isinstance(profile, CalibrationProfile):
        raise TypeError("oracle_bundle_calibration_profile_required")
    validate_slot_shape(slot)
    if not 0 <= slot.slot_index < profile.claim_slots:
        raise ValueError("oracle_bundle_slot_outside_profile")
    facts = OracleFacts(*(getattr(slot, name) for name in FACT_NAMES))
    authorizations = tuple(
        OracleAuthorization(
            line_enabled=index < len(slot.service_lines),
            required=(
                slot.service_lines[index].requires_prior_authorization
                if index < len(slot.service_lines)
                else False
            ),
            present=(
                slot.service_lines[index].authorization_present
                if index < len(slot.service_lines)
                else False
            ),
            token=(
                slot.service_lines[index].prior_authorization
                if index < len(slot.service_lines)
                else ""
            ),
        )
        for index in range(AUTHORIZATIONS_PER_CLAIM)
    )
    return OracleBundle(
        profile.profile_id,
        slot.slot_index,
        slot.slot_kind is SlotKind.REAL,
        facts,
        authorizations,
    )


def encode_oracle_bundle(bundle: OracleBundle) -> bytes:
    if not isinstance(bundle, OracleBundle):
        raise TypeError("oracle_bundle_required")
    bundle.__post_init__()
    facts = int(bundle.slot_is_real)
    for offset, name in enumerate(FACT_NAMES, start=1):
        facts |= int(getattr(bundle.facts, name)) << offset

    authorization_flags = 0
    for index, authorization in enumerate(bundle.authorizations):
        base = 3 * index
        authorization_flags |= int(authorization.line_enabled) << base
        authorization_flags |= int(authorization.required) << (base + 1)
        authorization_flags |= int(authorization.present) << (base + 2)

    out = bytearray(BUNDLE_MAGIC)
    out.append(_profile_code(bundle.profile_id))
    out.extend(bundle.slot_index.to_bytes(4, "big"))
    out.append(facts)
    out.extend(authorization_flags.to_bytes(AUTHORIZATION_FLAGS_BYTES, "little"))
    for authorization in bundle.authorizations:
        out.extend(encode_authorization_token(authorization.token))
    encoded = bytes(out)
    if len(encoded) != BUNDLE_BYTES:
        raise AssertionError("oracle_bundle_encoded_length_mismatch")
    return encoded


def decode_oracle_bundle(encoded: bytes) -> OracleBundle:
    if type(encoded) is not bytes or len(encoded) != BUNDLE_BYTES:
        raise ValueError("oracle_bundle_encoded_length_invalid")
    if encoded[: len(BUNDLE_MAGIC)] != BUNDLE_MAGIC:
        raise ValueError("oracle_bundle_magic_mismatch")
    cursor = len(BUNDLE_MAGIC)
    profile_id = _CODE_PROFILES.get(encoded[cursor])
    cursor += 1
    if profile_id is None:
        raise ValueError("oracle_bundle_profile_code_unknown")
    slot_index = int.from_bytes(encoded[cursor : cursor + 4], "big")
    cursor += 4
    fact_flags = encoded[cursor]
    cursor += 1
    if fact_flags & 0x80:
        raise ValueError("oracle_bundle_fact_flags_noncanonical")
    authorization_flags = int.from_bytes(
        encoded[cursor : cursor + AUTHORIZATION_FLAGS_BYTES], "little"
    )
    cursor += AUTHORIZATION_FLAGS_BYTES
    if authorization_flags >> (3 * AUTHORIZATIONS_PER_CLAIM):
        raise ValueError("oracle_bundle_authorization_flags_noncanonical")

    authorizations: list[OracleAuthorization] = []
    for index in range(AUTHORIZATIONS_PER_CLAIM):
        token = decode_authorization_token(
            encoded[cursor : cursor + TOKEN_ENCODED_BYTES]
        )
        cursor += TOKEN_ENCODED_BYTES
        base = 3 * index
        authorizations.append(
            OracleAuthorization(
                bool((authorization_flags >> base) & 1),
                bool((authorization_flags >> (base + 1)) & 1),
                bool((authorization_flags >> (base + 2)) & 1),
                token,
            )
        )
    if cursor != len(encoded):
        raise AssertionError("oracle_bundle_decode_cursor_mismatch")
    facts = OracleFacts(
        *(bool((fact_flags >> offset) & 1) for offset in range(1, 7))
    )
    bundle = OracleBundle(
        profile_id,
        slot_index,
        bool(fact_flags & 1),
        facts,
        tuple(authorizations),
    )
    if encode_oracle_bundle(bundle) != encoded:
        raise ValueError("oracle_bundle_reencoding_mismatch")
    return bundle


def oracle_bundle_leaf_digest(bundle: OracleBundle) -> bytes:
    return sha3_512(encode_oracle_bundle(bundle)).digest()


def authorization_audit_record(bundle: OracleBundle, index: int) -> bytes:
    """Return one fixed, independently addressable authorization record."""

    if not isinstance(bundle, OracleBundle):
        raise TypeError("oracle_bundle_required")
    if type(index) is not int or not 0 <= index < AUTHORIZATIONS_PER_CLAIM:
        raise ValueError("oracle_bundle_authorization_index_invalid")
    value = bundle.authorizations[index]
    flags = (
        int(value.line_enabled)
        | (int(value.required) << 1)
        | (int(value.present) << 2)
    )
    return b"".join(
        (
            b"BLPQOAV1",
            bytes((_profile_code(bundle.profile_id),)),
            bundle.slot_index.to_bytes(4, "big"),
            bytes((index, flags)),
            encode_authorization_token(value.token),
        )
    )


@dataclass(frozen=True, slots=True)
class OracleCommitments:
    profile_id: str
    leaf_digests: tuple[bytes, ...]
    execution_root: bytes
    audit_root: bytes
    audit_levels: tuple[tuple[bytes, ...], ...]

    def __post_init__(self) -> None:
        profile = PROFILES.get(self.profile_id)
        if profile is None or len(self.leaf_digests) != profile.claim_slots:
            raise ValueError("oracle_commitments_profile_geometry_invalid")
        if any(
            type(value) is not bytes or len(value) != DIGEST_BYTES
            for value in self.leaf_digests
        ):
            raise ValueError("oracle_commitments_leaf_digest_invalid")
        if any(
            type(value) is not bytes or len(value) != DIGEST_BYTES
            for value in (self.execution_root, self.audit_root)
        ):
            raise ValueError("oracle_commitments_root_invalid")


def _audit_node(
    profile_id: str,
    *,
    child_height: int,
    position: int,
    left: bytes,
    right: bytes,
) -> bytes:
    if not 0 <= child_height <= 8 or not 0 <= position <= 0xFFFF:
        raise ValueError("oracle_audit_node_position_invalid")
    if any(type(value) is not bytes or len(value) != DIGEST_BYTES for value in (left, right)):
        raise ValueError("oracle_audit_node_child_invalid")
    preimage = b"".join(
        (
            AUDIT_NODE_MAGIC,
            bytes((_profile_code(profile_id), child_height)),
            position.to_bytes(2, "big"),
            left,
            right,
        )
    )
    if len(preimage) != 140 or _permutations(len(preimage)) != 2:
        raise AssertionError("oracle_audit_node_schedule_changed")
    return sha3_512(preimage).digest()


def build_oracle_commitments(
    profile: CalibrationProfile,
    bundles: Sequence[OracleBundle],
) -> OracleCommitments:
    if not isinstance(profile, CalibrationProfile):
        raise TypeError("oracle_commitments_profile_required")
    materialized = tuple(bundles)
    if len(materialized) != profile.claim_slots:
        raise ValueError("oracle_commitments_bundle_count_invalid")
    for index, bundle in enumerate(materialized):
        if not isinstance(bundle, OracleBundle):
            raise TypeError("oracle_commitments_bundle_invalid")
        if bundle.profile_id != profile.profile_id or bundle.slot_index != index:
            raise ValueError("oracle_commitments_bundle_order_invalid")

    leaves = tuple(oracle_bundle_leaf_digest(bundle) for bundle in materialized)
    execution_preimage = b"".join(
        (
            EXECUTION_ROOT_MAGIC,
            bytes((_profile_code(profile.profile_id),)),
            profile.claim_slots.to_bytes(2, "big"),
            *leaves,
        )
    )
    execution_root = sha3_512(execution_preimage).digest()

    levels: list[tuple[bytes, ...]] = [leaves]
    current = leaves
    child_height = 0
    while len(current) > 1:
        current = tuple(
            _audit_node(
                profile.profile_id,
                child_height=child_height,
                position=offset // 2,
                left=current[offset],
                right=current[offset + 1],
            )
            for offset in range(0, len(current), 2)
        )
        levels.append(current)
        child_height += 1
    if child_height != profile.claim_source_tree_depth:
        raise AssertionError("oracle_audit_tree_depth_mismatch")
    audit_preimage = b"".join(
        (
            AUDIT_ROOT_MAGIC,
            bytes((_profile_code(profile.profile_id), child_height)),
            profile.claim_slots.to_bytes(2, "big"),
            current[0],
        )
    )
    audit_root = sha3_512(audit_preimage).digest()
    return OracleCommitments(
        profile.profile_id,
        leaves,
        execution_root,
        audit_root,
        tuple(levels),
    )


@dataclass(frozen=True, slots=True)
class OracleAuditProof:
    profile_id: str
    position: int
    bundle: bytes
    siblings: tuple[bytes, ...]
    audit_root: bytes


def oracle_audit_proof(
    commitments: OracleCommitments,
    bundle: OracleBundle,
) -> OracleAuditProof:
    if not isinstance(commitments, OracleCommitments) or not isinstance(bundle, OracleBundle):
        raise TypeError("oracle_audit_proof_inputs_invalid")
    if commitments.profile_id != bundle.profile_id:
        raise ValueError("oracle_audit_proof_profile_mismatch")
    position = bundle.slot_index
    encoded = encode_oracle_bundle(bundle)
    if not hmac.compare_digest(
        sha3_512(encoded).digest(), commitments.leaf_digests[position]
    ):
        raise ValueError("oracle_audit_proof_bundle_not_committed")
    siblings = tuple(
        commitments.audit_levels[height][(position >> height) ^ 1]
        for height in range(len(commitments.audit_levels) - 1)
    )
    return OracleAuditProof(
        bundle.profile_id,
        position,
        encoded,
        siblings,
        commitments.audit_root,
    )


def verify_oracle_audit_proof(proof: OracleAuditProof) -> OracleBundle:
    if not isinstance(proof, OracleAuditProof):
        raise TypeError("oracle_audit_proof_required")
    profile = PROFILES.get(proof.profile_id)
    if profile is None:
        raise ValueError("oracle_audit_proof_profile_unknown")
    if type(proof.position) is not int or not 0 <= proof.position < profile.claim_slots:
        raise ValueError("oracle_audit_proof_position_invalid")
    if type(proof.siblings) is not tuple or len(proof.siblings) != profile.claim_source_tree_depth:
        raise ValueError("oracle_audit_proof_sibling_count_invalid")
    if any(type(value) is not bytes or len(value) != DIGEST_BYTES for value in proof.siblings):
        raise ValueError("oracle_audit_proof_sibling_invalid")
    if type(proof.audit_root) is not bytes or len(proof.audit_root) != DIGEST_BYTES:
        raise ValueError("oracle_audit_proof_root_invalid")
    bundle = decode_oracle_bundle(proof.bundle)
    if bundle.profile_id != proof.profile_id or bundle.slot_index != proof.position:
        raise ValueError("oracle_audit_proof_bundle_binding_invalid")
    value = sha3_512(proof.bundle).digest()
    cursor = proof.position
    for child_height, sibling in enumerate(proof.siblings):
        if cursor & 1:
            left, right = sibling, value
        else:
            left, right = value, sibling
        value = _audit_node(
            proof.profile_id,
            child_height=child_height,
            position=cursor >> 1,
            left=left,
            right=right,
        )
        cursor >>= 1
    audit_preimage = b"".join(
        (
            AUDIT_ROOT_MAGIC,
            bytes((_profile_code(proof.profile_id), len(proof.siblings))),
            profile.claim_slots.to_bytes(2, "big"),
            value,
        )
    )
    if not hmac.compare_digest(sha3_512(audit_preimage).digest(), proof.audit_root):
        raise ValueError("oracle_audit_proof_root_mismatch")
    return bundle


def oracle_attestation_message(
    profile_id: str,
    *,
    snapshot_id: str,
    signer_epoch: int,
    execution_root: bytes,
    audit_root: bytes,
) -> bytes:
    _profile_code(profile_id)
    if type(snapshot_id) is not str or _TOKEN_PATTERN.fullmatch(snapshot_id) is None:
        raise ValueError("oracle_attestation_snapshot_id_invalid")
    if type(signer_epoch) is not int or not 0 <= signer_epoch <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("oracle_attestation_signer_epoch_invalid")
    if any(
        type(value) is not bytes or len(value) != DIGEST_BYTES
        for value in (execution_root, audit_root)
    ):
        raise ValueError("oracle_attestation_root_invalid")
    snapshot = snapshot_id.encode("ascii")
    return b"".join(
        (
            ATTESTATION_MAGIC,
            bytes((_profile_code(profile_id), len(snapshot))),
            snapshot,
            signer_epoch.to_bytes(8, "big"),
            execution_root,
            audit_root,
        )
    )


def oracle_commitment_schedule(profile: CalibrationProfile) -> dict[str, object]:
    if not isinstance(profile, CalibrationProfile):
        raise TypeError("oracle_commitment_schedule_profile_required")
    leaf_permutations = _permutations(BUNDLE_BYTES)
    execution_root_bytes = (
        len(EXECUTION_ROOT_MAGIC) + 1 + 2 + profile.claim_slots * DIGEST_BYTES
    )
    execution_root_permutations = _permutations(execution_root_bytes)
    proof_permutations = (
        profile.claim_slots * leaf_permutations + execution_root_permutations
    )
    audit_permutations = 2 * (profile.claim_slots - 1) + 2
    return {
        "status": STATUS,
        "profileId": profile.profile_id,
        "bundleBytes": BUNDLE_BYTES,
        "leafPreimageBytes": BUNDLE_BYTES,
        "leafPermutations": leaf_permutations,
        "executionRootPreimageBytes": execution_root_bytes,
        "executionRootPermutations": execution_root_permutations,
        "proofSpongePermutations": proof_permutations,
        "proofKeccakRoundRows": proof_permutations * 24,
        "auditSpongePermutationsOutsideProof": audit_permutations,
        "auditProofBytes": profile.claim_source_tree_depth * DIGEST_BYTES,
        "sameLeafDigests": True,
        "attestationBindsBothRoots": True,
        "proofSuiteId": None,
        "activationAllowed": False,
    }


def oracle_commitment_summary() -> dict[str, object]:
    return {
        "status": STATUS,
        "tokenLanguageCardinality": str(_TOKEN_RANK_LIMIT),
        "tokenEncodedBytes": TOKEN_ENCODED_BYTES,
        "bundleBytes": BUNDLE_BYTES,
        "profiles": [
            oracle_commitment_schedule(profile) for profile in PROFILES.values()
        ],
        "proofSuiteId": None,
        "activationAllowed": False,
    }


def oracle_commitment_canonical_sha3_512() -> str:
    import json

    encoded = json.dumps(
        oracle_commitment_summary(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return sha3_512(b"BL/PQ512/WAVE1B/ORACLE-COMMITMENT-SUMMARY/v1" + encoded).hexdigest()


__all__: Sequence[str] = (
    "BUNDLE_BYTES",
    "OracleAuditProof",
    "OracleAuthorization",
    "OracleBundle",
    "OracleCommitments",
    "OracleFacts",
    "STATUS",
    "authorization_audit_record",
    "build_oracle_commitments",
    "decode_authorization_token",
    "decode_oracle_bundle",
    "encode_authorization_token",
    "encode_oracle_bundle",
    "oracle_attestation_message",
    "oracle_audit_proof",
    "oracle_bundle_from_slot",
    "oracle_bundle_leaf_digest",
    "oracle_commitment_canonical_sha3_512",
    "oracle_commitment_schedule",
    "oracle_commitment_summary",
    "verify_oracle_audit_proof",
)
