"""Compact, reversible claim-source commitment candidate for Wave 1A.

The historical synthetic tree hashes an 8,525-byte generic record wrapper for
each full claim.  This candidate commits the same claim-source facts in one
fixed 5,648-byte bundle, orders leaves by the already constrained slot index,
and hashes every dense-tree node once.  It is deliberately nonactivating: the
source-authority signature/epoch verifier and the complete executable AIR must
bind this root before it can replace any governed reference root.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import hmac
import json
import re
from typing import Final, Sequence

from experiments.fixed_shape_claim_air.profile import (
    DIAGNOSES_PER_CLAIM,
    PROFILES,
    SERVICE_LINES_PER_CLAIM,
    CalibrationProfile,
)
from experiments.fixed_shape_claim_air.semantics import (
    ClaimSlot,
    RevisionKind,
    SlotKind,
    validate_batch,
    validate_slot_shape,
)

from .oracle_bundle_commitment import (
    TOKEN_ENCODED_BYTES,
    decode_authorization_token,
    encode_authorization_token,
)


STATUS: Final[str] = (
    "WAVE1A_COMPACT_CLAIM_SOURCE_COMMITMENT_V2_NONACTIVATING_AIR_BINDING_OPEN"
)
BUNDLE_MAGIC: Final[bytes] = b"BLPQCSB2"
NODE_MAGIC: Final[bytes] = b"BLPQCSN2"
ROOT_MAGIC: Final[bytes] = b"BLPQCST2"
SUMMARY_DOMAIN: Final[bytes] = b"BL/PQ512/CLAIM-SOURCE-COMMITMENT-SUMMARY/v2"
DIGEST_BYTES: Final[int] = 64
DIAGNOSIS_BYTES: Final[int] = 17
PROCEDURE_BYTES: Final[int] = 11
NPI_BYTES: Final[int] = 11
NODE_PREIMAGE_BYTES: Final[int] = 140
ROOT_PREIMAGE_BYTES: Final[int] = 76

_PROFILE_CODES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}
_CODE_PROFILES: Final[dict[int, str]] = {
    value: key for key, value in _PROFILE_CODES.items()
}
_REVISION_CODES: Final[dict[RevisionKind, int]] = {
    RevisionKind.COVER: 0,
    RevisionKind.ORIGINAL: 1,
    RevisionKind.CORRECTION: 2,
    RevisionKind.REPLACEMENT: 3,
    RevisionKind.VOID: 4,
}
_CODE_REVISIONS: Final[dict[int, RevisionKind]] = {
    value: key for key, value in _REVISION_CODES.items()
}
_DIAGNOSIS = re.compile(r"[A-Z0-9.]{1,16}\Z")
_PROCEDURE = re.compile(r"[A-Z0-9]{2,10}\Z")
_NPI = re.compile(r"[0-9]{10}\Z")

CLAIM_SOURCE_BUNDLE_BYTES: Final[int] = (
    len(BUNDLE_MAGIC)
    + 1  # profile code
    + 2  # slot index
    + 1  # real flag
    + TOKEN_ENCODED_BYTES  # source authority
    + 8  # source sequence
    + TOKEN_ENCODED_BYTES  # claim id
    + TOKEN_ENCODED_BYTES  # member id
    + NPI_BYTES
    + 4  # attempt version
    + 1  # revision kind
    + 4  # parent attempt version
    + 4  # total charge
    + 4  # patient responsibility
    + 1  # diagnosis count
    + DIAGNOSES_PER_CLAIM * DIAGNOSIS_BYTES
    + 1  # service-line count
    + SERVICE_LINES_PER_CLAIM
    * (
        1  # original line index
        + TOKEN_ENCODED_BYTES  # line id
        + PROCEDURE_BYTES
        + 4  # charge
        + 4  # units
        + TOKEN_ENCODED_BYTES  # prior authorization
    )
)


def _profile_code(profile_id: str) -> int:
    if type(profile_id) is not str or profile_id not in _PROFILE_CODES:
        raise ValueError("claim_source_profile_unknown")
    return _PROFILE_CODES[profile_id]


def _ascii_sort_key(value: str) -> tuple[int, bytes]:
    raw = value.encode("ascii")
    return len(raw), raw


def _npi_check_digit_ok(value: str) -> bool:
    if _NPI.fullmatch(value) is None:
        return False
    payload = f"80840{value[:9]}"
    total = 0
    for index, character in enumerate(reversed(payload)):
        digit = int(character)
        if index % 2 == 0:
            doubled = digit * 2
            total += doubled // 10 + doubled % 10
        else:
            total += digit
    return (10 - total % 10) % 10 == int(value[9])


def _line_sort_key(
    line: "ClaimSourceLine",
) -> tuple[tuple[int, bytes], int, int, tuple[int, bytes], tuple[int, bytes]]:
    return (
        _ascii_sort_key(line.procedure_code),
        line.charge_cents,
        line.units_cents,
        encode_authorization_token(line.prior_authorization),
        encode_authorization_token(line.line_id),
    )


def _fixed_ascii(
    value: str,
    *,
    capacity: int,
    pattern: re.Pattern[str],
    allow_empty: bool,
    label: str,
) -> bytes:
    if type(value) is not str:
        raise TypeError(f"claim_source_{label}_not_text")
    if value == "":
        if not allow_empty:
            raise ValueError(f"claim_source_{label}_empty")
        raw = b""
    else:
        if pattern.fullmatch(value) is None:
            raise ValueError(f"claim_source_{label}_not_canonical")
        raw = value.encode("ascii")
    if len(raw) > capacity:
        raise ValueError(f"claim_source_{label}_too_long")
    return bytes((len(raw),)) + raw.ljust(capacity, b"\x00")


def _decode_fixed_ascii(
    encoded: bytes,
    *,
    capacity: int,
    pattern: re.Pattern[str],
    allow_empty: bool,
    label: str,
) -> str:
    if type(encoded) is not bytes or len(encoded) != capacity + 1:
        raise ValueError(f"claim_source_{label}_encoding_length_invalid")
    length = encoded[0]
    if length > capacity or any(encoded[1 + length :]):
        raise ValueError(f"claim_source_{label}_padding_noncanonical")
    try:
        value = encoded[1 : 1 + length].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"claim_source_{label}_not_ascii") from exc
    if value == "":
        if not allow_empty:
            raise ValueError(f"claim_source_{label}_empty")
    elif pattern.fullmatch(value) is None:
        raise ValueError(f"claim_source_{label}_not_canonical")
    if _fixed_ascii(
        value,
        capacity=capacity,
        pattern=pattern,
        allow_empty=allow_empty,
        label=label,
    ) != encoded:
        raise ValueError(f"claim_source_{label}_reencoding_mismatch")
    return value


@dataclass(frozen=True, slots=True)
class ClaimSourceLine:
    original_line_index: int
    line_id: str
    procedure_code: str
    charge_cents: int
    units_cents: int
    prior_authorization: str


@dataclass(frozen=True, slots=True)
class ClaimSourceBundle:
    profile_id: str
    slot_index: int
    slot_is_real: bool
    source_authority_id: str
    source_sequence: int
    claim_id: str
    member_id: str
    provider_npi: str
    attempt_version: int
    revision_kind: RevisionKind
    parent_attempt_version: int
    total_charge_cents: int
    patient_responsibility_cents: int
    diagnoses: tuple[str, ...]
    service_lines: tuple[ClaimSourceLine, ...]

    def __post_init__(self) -> None:
        profile = PROFILES.get(self.profile_id)
        _profile_code(self.profile_id)
        if profile is None or type(self.slot_index) is not int or not (
            0 <= self.slot_index < profile.claim_slots
        ):
            raise ValueError("claim_source_slot_index_invalid")
        if type(self.slot_is_real) is not bool:
            raise TypeError("claim_source_slot_kind_not_boolean")
        for label, value, allow_empty in (
            ("source_authority", self.source_authority_id, not self.slot_is_real),
            ("claim_id", self.claim_id, not self.slot_is_real),
            ("member_id", self.member_id, True),
        ):
            encoded = encode_authorization_token(value)
            if not allow_empty and not any(encoded):
                raise ValueError(f"claim_source_{label}_empty")
        for label, value, maximum in (
            ("source_sequence", self.source_sequence, 0xFFFFFFFFFFFFFFFF),
            ("attempt_version", self.attempt_version, 0xFFFFFFFF),
            ("parent_attempt_version", self.parent_attempt_version, 0xFFFFFFFF),
            ("total_charge", self.total_charge_cents, 0xFFFFFFFF),
            (
                "patient_responsibility",
                self.patient_responsibility_cents,
                0xFFFFFFFF,
            ),
        ):
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError(f"claim_source_{label}_out_of_range")
        if not isinstance(self.revision_kind, RevisionKind):
            raise TypeError("claim_source_revision_kind_invalid")
        if self.provider_npi != "" and not _npi_check_digit_ok(self.provider_npi):
            raise ValueError("claim_source_provider_npi_not_canonical")
        if type(self.diagnoses) is not tuple or len(self.diagnoses) > DIAGNOSES_PER_CLAIM:
            raise ValueError("claim_source_diagnosis_count_invalid")
        if any(_DIAGNOSIS.fullmatch(value) is None for value in self.diagnoses):
            raise ValueError("claim_source_diagnosis_not_canonical")
        if self.diagnoses != tuple(sorted(self.diagnoses, key=_ascii_sort_key)):
            raise ValueError("claim_source_diagnosis_order_invalid")
        if len(set(self.diagnoses)) != len(self.diagnoses):
            raise ValueError("claim_source_diagnosis_duplicate")
        if type(self.service_lines) is not tuple or len(self.service_lines) > SERVICE_LINES_PER_CLAIM:
            raise ValueError("claim_source_service_line_count_invalid")
        for line in self.service_lines:
            if not isinstance(line, ClaimSourceLine):
                raise TypeError("claim_source_line_invalid")
            if type(line.original_line_index) is not int or not (
                0 <= line.original_line_index < SERVICE_LINES_PER_CLAIM
            ):
                raise ValueError("claim_source_line_index_invalid")
            if not any(encode_authorization_token(line.line_id)):
                raise ValueError("claim_source_line_id_empty")
            if _PROCEDURE.fullmatch(line.procedure_code) is None:
                raise ValueError("claim_source_procedure_not_canonical")
            encode_authorization_token(line.prior_authorization)
            for label, value in (
                ("line_charge", line.charge_cents),
                ("line_units", line.units_cents),
            ):
                if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                    raise ValueError(f"claim_source_{label}_out_of_range")
        if self.service_lines != tuple(sorted(self.service_lines, key=_line_sort_key)):
            raise ValueError("claim_source_service_line_order_invalid")
        if len({line.line_id for line in self.service_lines}) != len(self.service_lines):
            raise ValueError("claim_source_line_id_duplicate")
        if len({line.original_line_index for line in self.service_lines}) != len(
            self.service_lines
        ):
            raise ValueError("claim_source_original_line_index_duplicate")
        if sum(line.charge_cents for line in self.service_lines) != self.total_charge_cents:
            raise ValueError("claim_source_total_charge_mismatch")
        if self.slot_is_real and (
            self.source_sequence == 0
            or self.attempt_version != 1
            or self.revision_kind is not RevisionKind.ORIGINAL
            or self.parent_attempt_version != 0
        ):
            raise ValueError("claim_source_real_attempt_not_current_canonical")
        if not self.slot_is_real and (
            self.source_authority_id
            or self.source_sequence
            or self.claim_id
            or self.member_id
            or self.provider_npi
            or self.attempt_version
            or self.revision_kind is not RevisionKind.COVER
            or self.parent_attempt_version
            or self.total_charge_cents
            or self.patient_responsibility_cents
            or self.diagnoses
            or self.service_lines
        ):
            raise ValueError("claim_source_cover_not_canonical_zero")


def claim_source_bundle_from_slot(
    profile: CalibrationProfile, slot: ClaimSlot
) -> ClaimSourceBundle:
    if not isinstance(profile, CalibrationProfile):
        raise TypeError("claim_source_profile_required")
    validate_slot_shape(slot)
    if not 0 <= slot.slot_index < profile.claim_slots:
        raise ValueError("claim_source_slot_outside_profile")
    return ClaimSourceBundle(
        profile.profile_id,
        slot.slot_index,
        slot.slot_kind is SlotKind.REAL,
        slot.source_authority_id,
        slot.source_sequence,
        slot.claim_id,
        slot.member_id,
        slot.provider_npi,
        slot.attempt_version,
        slot.revision_kind,
        slot.parent_attempt_version,
        slot.total_charge_cents,
        slot.patient_responsibility_cents,
        tuple(slot.diagnoses),
        tuple(
            ClaimSourceLine(
                line.original_line_index,
                line.line_id,
                line.procedure_code,
                line.charge_cents,
                line.units_cents,
                line.prior_authorization,
            )
            for line in slot.service_lines
        ),
    )


def encode_claim_source_bundle(bundle: ClaimSourceBundle) -> bytes:
    if not isinstance(bundle, ClaimSourceBundle):
        raise TypeError("claim_source_bundle_required")
    bundle.__post_init__()
    out = bytearray(BUNDLE_MAGIC)
    out.append(_profile_code(bundle.profile_id))
    out.extend(bundle.slot_index.to_bytes(2, "big"))
    out.append(int(bundle.slot_is_real))
    out.extend(encode_authorization_token(bundle.source_authority_id))
    out.extend(bundle.source_sequence.to_bytes(8, "big"))
    out.extend(encode_authorization_token(bundle.claim_id))
    out.extend(encode_authorization_token(bundle.member_id))
    out.extend(
        _fixed_ascii(
            bundle.provider_npi,
            capacity=10,
            pattern=_NPI,
            allow_empty=True,
            label="provider_npi",
        )
    )
    out.extend(bundle.attempt_version.to_bytes(4, "big"))
    out.append(_REVISION_CODES[bundle.revision_kind])
    out.extend(bundle.parent_attempt_version.to_bytes(4, "big"))
    out.extend(bundle.total_charge_cents.to_bytes(4, "big"))
    out.extend(bundle.patient_responsibility_cents.to_bytes(4, "big"))
    out.append(len(bundle.diagnoses))
    for index in range(DIAGNOSES_PER_CLAIM):
        value = bundle.diagnoses[index] if index < len(bundle.diagnoses) else ""
        out.extend(
            _fixed_ascii(
                value,
                capacity=16,
                pattern=_DIAGNOSIS,
                allow_empty=True,
                label="diagnosis",
            )
        )
    out.append(len(bundle.service_lines))
    for index in range(SERVICE_LINES_PER_CLAIM):
        if index < len(bundle.service_lines):
            line = bundle.service_lines[index]
            out.append(line.original_line_index)
            out.extend(encode_authorization_token(line.line_id))
            out.extend(
                _fixed_ascii(
                    line.procedure_code,
                    capacity=10,
                    pattern=_PROCEDURE,
                    allow_empty=False,
                    label="procedure",
                )
            )
            out.extend(line.charge_cents.to_bytes(4, "big"))
            out.extend(line.units_cents.to_bytes(4, "big"))
            out.extend(encode_authorization_token(line.prior_authorization))
        else:
            out.extend(bytes(1 + TOKEN_ENCODED_BYTES + PROCEDURE_BYTES + 4 + 4 + TOKEN_ENCODED_BYTES))
    encoded = bytes(out)
    if len(encoded) != CLAIM_SOURCE_BUNDLE_BYTES:
        raise AssertionError("claim_source_bundle_length_mismatch")
    return encoded


def decode_claim_source_bundle(encoded: bytes) -> ClaimSourceBundle:
    if type(encoded) is not bytes or len(encoded) != CLAIM_SOURCE_BUNDLE_BYTES:
        raise ValueError("claim_source_bundle_encoding_length_invalid")
    if encoded[: len(BUNDLE_MAGIC)] != BUNDLE_MAGIC:
        raise ValueError("claim_source_bundle_magic_mismatch")
    cursor = len(BUNDLE_MAGIC)

    def take(count: int) -> bytes:
        nonlocal cursor
        value = encoded[cursor : cursor + count]
        if len(value) != count:
            raise ValueError("claim_source_bundle_truncated")
        cursor += count
        return value

    profile_id = _CODE_PROFILES.get(take(1)[0])
    if profile_id is None:
        raise ValueError("claim_source_profile_code_unknown")
    slot_index = int.from_bytes(take(2), "big")
    real_flag = take(1)[0]
    if real_flag not in (0, 1):
        raise ValueError("claim_source_real_flag_not_boolean")
    source_authority = decode_authorization_token(take(TOKEN_ENCODED_BYTES))
    source_sequence = int.from_bytes(take(8), "big")
    claim_id = decode_authorization_token(take(TOKEN_ENCODED_BYTES))
    member_id = decode_authorization_token(take(TOKEN_ENCODED_BYTES))
    provider_npi = _decode_fixed_ascii(
        take(NPI_BYTES),
        capacity=10,
        pattern=_NPI,
        allow_empty=True,
        label="provider_npi",
    )
    attempt_version = int.from_bytes(take(4), "big")
    revision_kind = _CODE_REVISIONS.get(take(1)[0])
    if revision_kind is None:
        raise ValueError("claim_source_revision_code_unknown")
    parent_attempt_version = int.from_bytes(take(4), "big")
    total_charge = int.from_bytes(take(4), "big")
    patient_responsibility = int.from_bytes(take(4), "big")
    diagnosis_count = take(1)[0]
    if diagnosis_count > DIAGNOSES_PER_CLAIM:
        raise ValueError("claim_source_diagnosis_count_invalid")
    diagnoses = tuple(
        _decode_fixed_ascii(
            take(DIAGNOSIS_BYTES),
            capacity=16,
            pattern=_DIAGNOSIS,
            allow_empty=True,
            label="diagnosis",
        )
        for _ in range(DIAGNOSES_PER_CLAIM)
    )
    if any(diagnoses[diagnosis_count:]) or any(
        not value for value in diagnoses[:diagnosis_count]
    ):
        raise ValueError("claim_source_diagnosis_prefix_noncanonical")
    service_count = take(1)[0]
    if service_count > SERVICE_LINES_PER_CLAIM:
        raise ValueError("claim_source_service_line_count_invalid")
    lines: list[ClaimSourceLine] = []
    zero_line = bytes(
        1 + TOKEN_ENCODED_BYTES + PROCEDURE_BYTES + 4 + 4 + TOKEN_ENCODED_BYTES
    )
    for index in range(SERVICE_LINES_PER_CLAIM):
        raw = take(len(zero_line))
        if index >= service_count:
            if raw != zero_line:
                raise ValueError("claim_source_disabled_line_not_zero")
            continue
        line_cursor = 0

        def line_take(count: int) -> bytes:
            nonlocal line_cursor
            value = raw[line_cursor : line_cursor + count]
            line_cursor += count
            return value

        original_index = line_take(1)[0]
        line_id = decode_authorization_token(line_take(TOKEN_ENCODED_BYTES))
        procedure = _decode_fixed_ascii(
            line_take(PROCEDURE_BYTES),
            capacity=10,
            pattern=_PROCEDURE,
            allow_empty=False,
            label="procedure",
        )
        charge = int.from_bytes(line_take(4), "big")
        units = int.from_bytes(line_take(4), "big")
        authorization = decode_authorization_token(line_take(TOKEN_ENCODED_BYTES))
        if line_cursor != len(raw):
            raise AssertionError("claim_source_line_cursor_mismatch")
        lines.append(
            ClaimSourceLine(
                original_index,
                line_id,
                procedure,
                charge,
                units,
                authorization,
            )
        )
    if cursor != len(encoded):
        raise AssertionError("claim_source_bundle_cursor_mismatch")
    bundle = ClaimSourceBundle(
        profile_id,
        slot_index,
        bool(real_flag),
        source_authority,
        source_sequence,
        claim_id,
        member_id,
        provider_npi,
        attempt_version,
        revision_kind,
        parent_attempt_version,
        total_charge,
        patient_responsibility,
        diagnoses[:diagnosis_count],
        tuple(lines),
    )
    if encode_claim_source_bundle(bundle) != encoded:
        raise ValueError("claim_source_bundle_reencoding_mismatch")
    return bundle


def claim_source_leaf_digest(bundle: ClaimSourceBundle) -> bytes:
    return sha3_512(encode_claim_source_bundle(bundle)).digest()


def _node_preimage(
    profile_id: str,
    *,
    child_height: int,
    position: int,
    left: bytes,
    right: bytes,
) -> bytes:
    if type(child_height) is not int or not 0 <= child_height <= 8:
        raise ValueError("claim_source_node_height_invalid")
    if type(position) is not int or not 0 <= position <= 0xFFFF:
        raise ValueError("claim_source_node_position_invalid")
    if any(type(value) is not bytes or len(value) != DIGEST_BYTES for value in (left, right)):
        raise ValueError("claim_source_node_child_invalid")
    preimage = b"".join(
        (
            NODE_MAGIC,
            bytes((_profile_code(profile_id), child_height)),
            position.to_bytes(2, "big"),
            left,
            right,
        )
    )
    if len(preimage) != NODE_PREIMAGE_BYTES:
        raise AssertionError("claim_source_node_preimage_length_mismatch")
    return preimage


def _root_preimage(
    profile_id: str, *, tree_height: int, claim_slots: int, top: bytes
) -> bytes:
    if type(tree_height) is not int or not 0 <= tree_height <= 9:
        raise ValueError("claim_source_tree_height_invalid")
    if type(claim_slots) is not int or claim_slots != 1 << tree_height:
        raise ValueError("claim_source_tree_geometry_invalid")
    if type(top) is not bytes or len(top) != DIGEST_BYTES:
        raise ValueError("claim_source_tree_top_invalid")
    preimage = b"".join(
        (
            ROOT_MAGIC,
            bytes((_profile_code(profile_id), tree_height)),
            claim_slots.to_bytes(2, "big"),
            top,
        )
    )
    if len(preimage) != ROOT_PREIMAGE_BYTES:
        raise AssertionError("claim_source_root_preimage_length_mismatch")
    return preimage


@dataclass(frozen=True, slots=True)
class ClaimSourceCommitments:
    profile_id: str
    leaf_digests: tuple[bytes, ...]
    root: bytes
    levels: tuple[tuple[bytes, ...], ...]


@dataclass(frozen=True, slots=True)
class ClaimSourceProof:
    profile_id: str
    position: int
    bundle: bytes
    siblings: tuple[bytes, ...]
    root: bytes


def build_claim_source_commitments(
    profile: CalibrationProfile, slots: Sequence[ClaimSlot]
) -> ClaimSourceCommitments:
    if not isinstance(profile, CalibrationProfile):
        raise TypeError("claim_source_profile_required")
    materialized = tuple(slots)
    validate_batch(profile, materialized)
    bundles = tuple(
        claim_source_bundle_from_slot(profile, slot) for slot in materialized
    )
    leaves = tuple(claim_source_leaf_digest(bundle) for bundle in bundles)
    levels: list[tuple[bytes, ...]] = [leaves]
    current = leaves
    for child_height in range(profile.claim_source_tree_depth):
        current = tuple(
            sha3_512(
                _node_preimage(
                    profile.profile_id,
                    child_height=child_height,
                    position=offset // 2,
                    left=current[offset],
                    right=current[offset + 1],
                )
            ).digest()
            for offset in range(0, len(current), 2)
        )
        levels.append(current)
    if len(current) != 1:
        raise AssertionError("claim_source_tree_not_reduced_to_one")
    root = sha3_512(
        _root_preimage(
            profile.profile_id,
            tree_height=profile.claim_source_tree_depth,
            claim_slots=profile.claim_slots,
            top=current[0],
        )
    ).digest()
    return ClaimSourceCommitments(profile.profile_id, leaves, root, tuple(levels))


def claim_source_proof(
    commitments: ClaimSourceCommitments, bundle: ClaimSourceBundle
) -> ClaimSourceProof:
    if not isinstance(commitments, ClaimSourceCommitments) or not isinstance(
        bundle, ClaimSourceBundle
    ):
        raise TypeError("claim_source_proof_inputs_invalid")
    if commitments.profile_id != bundle.profile_id:
        raise ValueError("claim_source_proof_profile_mismatch")
    position = bundle.slot_index
    encoded = encode_claim_source_bundle(bundle)
    if not hmac.compare_digest(
        sha3_512(encoded).digest(), commitments.leaf_digests[position]
    ):
        raise ValueError("claim_source_bundle_not_committed")
    return ClaimSourceProof(
        bundle.profile_id,
        position,
        encoded,
        tuple(
            commitments.levels[height][(position >> height) ^ 1]
            for height in range(len(commitments.levels) - 1)
        ),
        commitments.root,
    )


def verify_claim_source_proof(proof: ClaimSourceProof) -> ClaimSourceBundle:
    if not isinstance(proof, ClaimSourceProof):
        raise TypeError("claim_source_proof_required")
    profile = PROFILES.get(proof.profile_id)
    if profile is None or type(proof.position) is not int or not (
        0 <= proof.position < profile.claim_slots
    ):
        raise ValueError("claim_source_proof_position_invalid")
    if type(proof.siblings) is not tuple or len(proof.siblings) != profile.claim_source_tree_depth:
        raise ValueError("claim_source_proof_sibling_count_invalid")
    if any(type(value) is not bytes or len(value) != DIGEST_BYTES for value in proof.siblings):
        raise ValueError("claim_source_proof_sibling_invalid")
    if type(proof.root) is not bytes or len(proof.root) != DIGEST_BYTES:
        raise ValueError("claim_source_proof_root_invalid")
    bundle = decode_claim_source_bundle(proof.bundle)
    if bundle.profile_id != proof.profile_id or bundle.slot_index != proof.position:
        raise ValueError("claim_source_proof_bundle_binding_invalid")
    value = sha3_512(proof.bundle).digest()
    cursor = proof.position
    for child_height, sibling in enumerate(proof.siblings):
        left, right = (sibling, value) if cursor & 1 else (value, sibling)
        value = sha3_512(
            _node_preimage(
                proof.profile_id,
                child_height=child_height,
                position=cursor >> 1,
                left=left,
                right=right,
            )
        ).digest()
        cursor >>= 1
    observed = sha3_512(
        _root_preimage(
            proof.profile_id,
            tree_height=len(proof.siblings),
            claim_slots=profile.claim_slots,
            top=value,
        )
    ).digest()
    if not hmac.compare_digest(observed, proof.root):
        raise ValueError("claim_source_proof_root_mismatch")
    return bundle


def claim_source_commitment_schedule(profile: CalibrationProfile) -> dict[str, object]:
    if not isinstance(profile, CalibrationProfile):
        raise TypeError("claim_source_profile_required")
    leaf_permutations = CLAIM_SOURCE_BUNDLE_BYTES // 72 + 1
    node_permutations = NODE_PREIMAGE_BYTES // 72 + 1
    root_permutations = ROOT_PREIMAGE_BYTES // 72 + 1
    sponge_permutations = (
        profile.claim_slots * leaf_permutations
        + (profile.claim_slots - 1) * node_permutations
        + root_permutations
    )
    return {
        "status": STATUS,
        "profileId": profile.profile_id,
        "bundleBytes": CLAIM_SOURCE_BUNDLE_BYTES,
        "leafPermutations": leaf_permutations,
        "nodePreimageBytes": NODE_PREIMAGE_BYTES,
        "nodePermutations": node_permutations,
        "nodeInvocations": profile.claim_slots - 1,
        "rootPreimageBytes": ROOT_PREIMAGE_BYTES,
        "rootPermutations": root_permutations,
        "proofSpongePermutations": sponge_permutations,
        "proofKeccakRoundRows": sponge_permutations * 24,
        "membershipProofBytes": profile.claim_source_tree_depth * DIGEST_BYTES,
        "slotOrderedLeaves": True,
        "reversibleEncoding": True,
        "sourceAuthorityBindingConstrained": False,
        "proofSuiteId": None,
        "activationAllowed": False,
    }


def claim_source_commitment_summary() -> dict[str, object]:
    return {
        "status": STATUS,
        "profiles": [
            claim_source_commitment_schedule(profile) for profile in PROFILES.values()
        ],
        "proofSuiteId": None,
        "activationAllowed": False,
    }


def claim_source_commitment_canonical_sha3_512() -> str:
    encoded = json.dumps(
        claim_source_commitment_summary(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return sha3_512(SUMMARY_DOMAIN + encoded).hexdigest()


__all__: Sequence[str] = (
    "CLAIM_SOURCE_BUNDLE_BYTES",
    "ClaimSourceBundle",
    "ClaimSourceCommitments",
    "ClaimSourceLine",
    "ClaimSourceProof",
    "STATUS",
    "build_claim_source_commitments",
    "claim_source_bundle_from_slot",
    "claim_source_commitment_canonical_sha3_512",
    "claim_source_commitment_schedule",
    "claim_source_commitment_summary",
    "claim_source_leaf_digest",
    "claim_source_proof",
    "decode_claim_source_bundle",
    "encode_claim_source_bundle",
    "verify_claim_source_proof",
)
