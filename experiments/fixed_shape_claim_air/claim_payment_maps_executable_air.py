"""Executable claim-to-authenticated-payment-map bridge.

The bridge removes host trust from economic class selection, fixed value
encodings, benefit/reserve/payable arithmetic, and the four fixed upsert links.
Key-derivation SHA3 calls, authorization-use aggregation, operation-log SHA3,
and the final state/public composition remain explicit open boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from .authenticated_payment_maps_executable_air import (
    AuthenticatedPaymentMapsAirInstance,
    build_authenticated_payment_maps_executable_air,
    build_authenticated_payment_maps_sha3_interface_program,
)
from .authenticated_payment_maps_reference import (
    AuthenticatedPaymentMapBatchTransition,
    member_benefit_key_preimage,
    payer_reserve_key_preimage,
    payment_dummy_key_preimage,
    payment_operation_log_preimage,
    payment_operation_preimage,
    provider_obligation_key_preimage,
    provider_payable_key_preimage,
)
from .application_sha3_executable_air import (
    ApplicationSha3AirInstance,
    Sha3Call,
    build_application_sha3_executable_air,
    build_application_sha3_interface_air,
    build_application_sha3_interface_program,
    combine_application_sha3_executable_air,
    combine_application_sha3_interface_air,
)
from .claim_semantics_executable_air import build_claim_semantics_executable_air
from .claim_source_arrays_executable_air import (
    ClaimSourceArraysAirInstance,
    build_claim_source_arrays_executable_air,
)
from .executable_air import (
    AirProgram,
    AirTable,
    Expr,
    Identity,
    LookupArgument,
    LookupSide,
    TraceTable,
    boolean,
    cell,
    const,
    freeze_columns,
)
from .profile import PROFILES, SERVICE_LINES_PER_CLAIM
from .payment import derive_slot_economics
from .semantics import ClaimSlot, SlotKind, StructuralError, evaluate_slot
from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    TOKEN_ENCODED_BYTES,
    encode_authorization_token,
)


PROGRAM_ID: Final[str] = "BL-WAVE1A-CLAIM-PAYMENT-MAPS-AIR-v1"
_VALUE_NAMES: Final[tuple[str, ...]] = (
    "benefit",
    "obligation",
    "reserve",
    "payable",
)
_BENEFIT_TAG: Final[bytes] = b"BLBEN003"
_OBLIGATION_TAG: Final[bytes] = b"BLOBG003"
_BALANCE_TAG: Final[bytes] = b"BLBAL003"
_U16_BASE: Final[int] = 1 << 16
_PAYMENT_KEY_DOMAIN: Final[bytes] = b"BL/PQ512/PAYMENT-MAP/RANK-KEY/v2"
_PAYMENT_KEY_CAPACITY: Final[int] = 169
_KEY_LANES: Final[tuple[str, ...]] = (
    "benefit",
    "obligation",
    "reserve",
    "payable",
)
_KEY_APPROVAL_LENGTHS: Final[tuple[int, ...]] = (139, 136, 33, 43)
_KEY_APPROVAL_CODES: Final[tuple[int, ...]] = (1, 2, 3, 4)
_KEY_DUMMY_CODES: Final[tuple[int, ...]] = (0x11, 0x12, 0x13, 0x14)


@dataclass(frozen=True, slots=True)
class ClaimPaymentMapsAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    payment_maps: AuthenticatedPaymentMapsAirInstance
    source_arrays: ClaimSourceArraysAirInstance | None = None
    application_sha3: ApplicationSha3AirInstance | None = None
    call_index_offset: int = 0
    key_derivations_constrained: bool = False
    authorization_uses_constrained: bool = False
    operation_log_constrained: bool = False
    payment_map_hashes_constrained: bool = False
    key_derivation_ports_constrained: bool = False
    operation_log_ports_constrained: bool = False
    payment_map_hash_ports_constrained: bool = False
    sha3_interface_only: bool = False
    sha3_call_prefix: int = 0

    def __post_init__(self) -> None:
        if self.key_derivations_constrained:
            table_names = {table.name for table in self.program.tables}
            lookup_names = {lookup.name for lookup in self.program.lookups}
            if self.source_arrays is None or self.application_sha3 is None or not {
                "claim_payment_key_material",
                "claim_source_scalar",
                "claim_source_token_link",
                "sha3_round_batch",
                "sha3_message_batch",
                "sha3_digest_batch",
            }.issubset(table_names) or not {
                "claim_payment_keys_match_operations",
                "claim_payment_key_scalars_match_source",
                "claim_payment_key_authority_rank_matches_source",
                "claim_payment_key_claim_rank_matches_source",
                "claim_payment_key_member_rank_matches_source",
                "claim_payment_key_sha3_messages",
                "claim_payment_key_sha3_digests",
            }.issubset(lookup_names):
                raise StructuralError("claim_payment_maps_air_false_completion_claim")
        if self.authorization_uses_constrained:
            table_names = {table.name for table in self.program.tables}
            lookup_names = {lookup.name for lookup in self.program.lookups}
            if (
                "claim_service" not in table_names
                or "claim_payment_map_slot" not in table_names
                or "claim_payment_authorization_uses" not in lookup_names
            ):
                raise StructuralError("claim_payment_maps_air_false_completion_claim")
        if self.operation_log_constrained:
            table_names = {table.name for table in self.program.tables}
            lookup_names = {lookup.name for lookup in self.program.lookups}
            if not {
                "sha3_round_batch",
                "sha3_message_batch",
                "sha3_digest_batch",
            }.issubset(table_names) or not {
                "claim_payment_log_sha3_messages",
                "claim_payment_log_sha3_digest",
            }.issubset(lookup_names):
                raise StructuralError("claim_payment_maps_air_false_completion_claim")
        if self.payment_map_hashes_constrained and not self.payment_maps.hashes_constrained:
            raise StructuralError("claim_payment_maps_air_false_completion_claim")
        lookup_names = {lookup.name for lookup in self.program.lookups}
        if self.sha3_interface_only and any(
            (
                self.key_derivations_constrained,
                self.operation_log_constrained,
                self.payment_map_hashes_constrained,
            )
        ):
            raise StructuralError("claim_payment_maps_air_false_completion_claim")
        if self.key_derivation_ports_constrained and (
            not self.sha3_interface_only
            or self.application_sha3 is None
            or self.source_arrays is None
            or not {
                "claim_payment_key_sha3_messages",
                "claim_payment_key_sha3_digests",
            }.issubset(lookup_names)
        ):
            raise StructuralError("claim_payment_maps_air_false_completion_claim")
        if self.operation_log_ports_constrained and (
            not self.sha3_interface_only
            or not {
                "claim_payment_log_sha3_messages",
                "claim_payment_log_sha3_digest",
            }.issubset(lookup_names)
        ):
            raise StructuralError("claim_payment_maps_air_false_completion_claim")
        if self.payment_map_hash_ports_constrained and (
            not self.sha3_interface_only
            or not self.payment_maps.hash_ports_constrained
        ):
            raise StructuralError("claim_payment_maps_air_false_completion_claim")
        if type(self.sha3_call_prefix) is not int or self.sha3_call_prefix < 0:
            raise StructuralError("claim_payment_maps_air_call_prefix_invalid")


def _append(columns: dict[str, list[int]], name: str, value: int) -> None:
    columns.setdefault(name, []).append(value)


def _append_bytes(
    columns: dict[str, list[int]], prefix: str, value: bytes
) -> None:
    if type(value) is not bytes or len(value) != 64:
        raise StructuralError("claim_payment_maps_air_value_width_invalid")
    for index, byte in enumerate(value):
        _append(columns, f"{prefix}_{index}", byte)


def _u16_from_value(prefix: str, metric: int, limb: int) -> Expr:
    start = 10 + metric * 8
    high = start + 6 - 2 * limb
    return 256 * cell(f"{prefix}_{high}") + cell(f"{prefix}_{high + 1}")


def _u64_limbs(value: bytes, metric: int = 0) -> tuple[int, ...]:
    start = 10 + metric * 8
    number = int.from_bytes(value[start : start + 8], "big")
    return tuple((number >> (16 * limb)) & 0xFFFF for limb in range(4))


def _addition_carries(
    before: tuple[int, ...], delta: tuple[int, ...], after: tuple[int, ...]
) -> tuple[int, ...]:
    carry = 0
    result: list[int] = []
    for left, addend, expected in zip(before, delta, after, strict=True):
        total = left + addend + carry
        if total & 0xFFFF != expected:
            raise StructuralError("claim_payment_maps_air_arithmetic_witness_invalid")
        carry = total >> 16
        result.append(carry)
    if carry:
        raise StructuralError("claim_payment_maps_air_arithmetic_overflow")
    return tuple(result)


def _fixed_value_identities(
    prefix: str,
    active: Expr,
    tag: bytes,
    payload_size: int,
    rows: int,
) -> tuple[Identity, ...]:
    identities: list[Identity] = []
    fixed = tag + payload_size.to_bytes(2, "big")
    for index in range(64):
        value = cell(f"{prefix}_{index}")
        if index < 10:
            expression = value - active * fixed[index]
        elif index >= 10 + payload_size:
            expression = value
        else:
            expression = (1 - active) * value
        identities.append(
            Identity(f"{prefix}_canonical_{index}", expression, 0, rows)
        )
    return tuple(identities)


def _zero_value_identities(prefix: str, rows: int) -> tuple[Identity, ...]:
    return tuple(
        Identity(f"{prefix}_zero_{index}", cell(f"{prefix}_{index}"), 0, rows)
        for index in range(64)
    )


def _add_u64_identities(
    label: str,
    before_prefix: str,
    before_metric: int,
    after_prefix: str,
    after_metric: int,
    delta: tuple[Expr, ...],
    active: Expr,
    rows: int,
) -> tuple[Identity, ...]:
    identities: list[Identity] = []
    for limb in range(4):
        carry = cell(f"{label}_carry_{limb}")
        carry_in = const(0) if limb == 0 else cell(f"{label}_carry_{limb - 1}")
        equation = (
            _u16_from_value(before_prefix, before_metric, limb)
            + delta[limb]
            + carry_in
            - _u16_from_value(after_prefix, after_metric, limb)
            - _U16_BASE * carry
        )
        identities.extend(
            (
                Identity(f"{label}_carry_boolean_{limb}", boolean(carry), 0, rows),
                Identity(f"{label}_addition_{limb}", active * equation, 0, rows),
                Identity(
                    f"{label}_inactive_carry_{limb}", (1 - active) * carry, 0, rows
                ),
            )
        )
    identities.append(
        Identity(f"{label}_no_overflow", cell(f"{label}_carry_3"), 0, rows)
    )
    return tuple(identities)


def _operation_values(prefix: str, index: Expr) -> tuple[Expr, ...]:
    return (
        index,
        cell(f"{prefix}_insert"),
        *(cell(f"{prefix}_key_{byte}") for byte in range(64)),
        *(cell(f"{prefix}_before_{byte}") for byte in range(64)),
        *(cell(f"{prefix}_after_{byte}") for byte in range(64)),
    )


def _map_operation_values(index: Expr) -> tuple[Expr, ...]:
    return (
        index,
        cell("is_insert"),
        *(cell(f"key_{byte}") for byte in range(64)),
        *(cell(f"value_before_{byte}") for byte in range(64)),
        *(cell(f"value_after_{byte}") for byte in range(64)),
    )


def _operation_message_expressions(domain: bytes) -> tuple[Expr, ...]:
    values: list[Expr] = [const(byte) for byte in domain]
    values.extend(cell(f"slot_index_byte_{index}") for index in range(2))
    values.append(
        65 * cell("approval") + 68 * cell("denial") + 67 * cell("cover")
    )
    for label in ("allowed", "responsibility", "payment"):
        values.extend(cell(f"{label}_byte_{index}") for index in range(4))
    for name in _VALUE_NAMES:
        values.extend(cell(f"{name}_key_{index}") for index in range(64))
    for name in _VALUE_NAMES:
        for phase in ("before", "after"):
            values.extend(cell(f"{name}_{phase}_{index}") for index in range(64))
    return tuple(values)


def _log_prefix_expressions(domain: bytes) -> tuple[Expr, ...]:
    return (
        *(const(byte) for byte in domain),
        *(cell(f"operation_log_before_{index}") for index in range(64)),
        *(cell(f"sequence_byte_{index}") for index in range(8)),
        *(cell(f"slot_index_byte_{index}") for index in range(2)),
    )


def _profile_for_slots(rows: int):
    matches = tuple(profile for profile in PROFILES.values() if profile.claim_slots == rows)
    if len(matches) != 1:
        raise StructuralError("claim_payment_key_profile_unknown")
    return matches[0]


def _key_class(lane: str, witness: str) -> str:
    return f"{witness}_{lane}"


def _key_message_expression(position: int) -> Expr:
    if not 0 <= position < _PAYMENT_KEY_CAPACITY:
        raise StructuralError("claim_payment_key_position_invalid")
    if position < len(_PAYMENT_KEY_DOMAIN):
        return const(_PAYMENT_KEY_DOMAIN[position])
    if position == len(_PAYMENT_KEY_DOMAIN):
        return sum(
            (
                code * cell(_key_class(lane, "approval"))
                for lane, code in zip(_KEY_LANES, _KEY_APPROVAL_CODES, strict=True)
            ),
            sum(
                (
                    code * cell(_key_class(lane, "dummy"))
                    for lane, code in zip(_KEY_LANES, _KEY_DUMMY_CODES, strict=True)
                ),
                const(0),
            ),
        )

    approval = const(0)
    # Benefit: scope commitment followed by the canonical member rank.
    if 33 <= position < 97:
        approval += cell("approval_benefit") * cell(f"scope_byte_{position - 33}")
    elif 97 <= position < 139:
        approval += cell("approval_benefit") * cell(f"member_rank_{position - 97}")
    # Obligation: source authority rank, claim rank, revision tuple, then NPI.
    if 33 <= position < 75:
        approval += cell("approval_obligation") * cell(
            f"authority_rank_{position - 33}"
        )
    elif 75 <= position < 117:
        approval += cell("approval_obligation") * cell(f"claim_rank_{position - 75}")
    elif 117 <= position < 121:
        approval += cell("approval_obligation") * cell(f"attempt_byte_{position - 117}")
    elif position == 121:
        approval += cell("approval_obligation") * cell("revision_byte_0")
    elif 122 <= position < 126:
        approval += cell("approval_obligation") * cell(f"parent_byte_{position - 122}")
    elif 126 <= position < 136:
        approval += cell("approval_obligation") * cell(f"npi_byte_{position - 126}")
    # Reserve has no payload.  Payable is the exact ten-byte NPI.
    if 33 <= position < 43:
        approval += cell("approval_payable") * cell(f"npi_byte_{position - 33}")

    dummy = const(0)
    dummy_active = sum(
        (cell(_key_class(lane, "dummy")) for lane in _KEY_LANES),
        const(0),
    )
    if 33 <= position < 97:
        dummy = dummy_active * cell(f"settlement_byte_{position - 33}")
    elif 97 <= position < 105:
        dummy = dummy_active * cell(f"epoch_byte_{position - 97}")
    elif 105 <= position < 169:
        dummy = dummy_active * cell(f"scope_byte_{position - 105}")
    return approval + dummy


def _payment_key_sha3(
    slots: tuple[ClaimSlot, ...],
    transition: AuthenticatedPaymentMapBatchTransition,
    *,
    call_index_offset: int = 0,
    interface_only: bool = False,
) -> tuple[
    ApplicationSha3AirInstance,
    AirTable,
    TraceTable,
    tuple[LookupArgument, ...],
    ClaimSourceArraysAirInstance,
]:
    rows = len(slots)
    if type(call_index_offset) is not int or call_index_offset < 0:
        raise StructuralError("claim_payment_key_call_offset_invalid")
    if rows != len(transition.transitions):
        raise StructuralError("claim_payment_key_slot_count_mismatch")
    profile = _profile_for_slots(rows)
    source = build_claim_source_arrays_executable_air(profile, slots)
    scope = transition.before.benefit_scope.commitment_512()
    settlement = transition.before.strong_settlement_domain_id_512
    epoch = transition.before.epoch.to_bytes(8, "big")
    columns: dict[str, list[int]] = {}
    calls: list[Sha3Call] = []

    for slot, payment in zip(slots, transition.transitions, strict=True):
        approval = int(payment.witness_class == "approval")
        authority_rank = encode_authorization_token(slot.source_authority_id)
        claim_rank = encode_authorization_token(slot.claim_id)
        member_rank = encode_authorization_token(slot.member_id)
        approval_messages = (
            (
                member_benefit_key_preimage(
                    slot.member_id, benefit_scope=transition.before.benefit_scope
                ),
                provider_obligation_key_preimage(slot),
                payer_reserve_key_preimage(),
                provider_payable_key_preimage(slot.provider_npi),
            )
            if slot.slot_kind is SlotKind.REAL
            else (b"", b"", b"", b"")
        )
        dummy_messages = tuple(
            payment_dummy_key_preimage(lane, settlement, transition.before.epoch, scope)
            for lane in (b"BENEFIT", b"OBLIGATION", b"RESERVE", b"PAYABLE")
        )
        for lane_index, (lane, upsert) in enumerate(
            zip(_KEY_LANES, payment.upserts, strict=True)
        ):
            call_index = (
                call_index_offset
                + slot.slot_index * len(_KEY_LANES)
                + lane_index
            )
            message = (
                approval_messages[lane_index]
                if approval
                else dummy_messages[lane_index]
            )
            if len(message) > _PAYMENT_KEY_CAPACITY:
                raise StructuralError("claim_payment_key_message_overflow")
            if sha3_512(message).digest() != upsert.key_512:
                raise StructuralError("claim_payment_key_digest_mismatch")
            calls.append(Sha3Call(f"payment_key_{call_index}", message, _PAYMENT_KEY_CAPACITY))
            _append(columns, "slot_index", slot.slot_index)
            _append(columns, "call_index", call_index)
            _append(columns, "lane_index", lane_index)
            for candidate in _KEY_LANES:
                _append(columns, f"is_{candidate}", int(candidate == lane))
            _append(columns, "approval", approval)
            for witness in ("approval", "dummy"):
                for candidate in _KEY_LANES:
                    _append(
                        columns,
                        _key_class(candidate, witness),
                        int(candidate == lane and (approval if witness == "approval" else not approval)),
                    )
            _append(columns, "message_length", len(message))
            padded = message + bytes(_PAYMENT_KEY_CAPACITY - len(message))
            for index, value in enumerate(padded):
                _append(columns, f"message_byte_{index}", value)
            for prefix, value in (
                ("authority_rank", authority_rank),
                ("claim_rank", claim_rank),
                ("member_rank", member_rank),
                ("scope_byte", scope),
                ("settlement_byte", settlement),
                ("epoch_byte", epoch),
            ):
                for index, byte in enumerate(value):
                    _append(columns, f"{prefix}_{index}", byte)
            _append(columns, "is_real", int(slot.slot_kind is SlotKind.REAL))
            _append(columns, "npi_length_byte_0", 10 if slot.slot_kind is SlotKind.REAL else 0)
            npi = slot.provider_npi.encode("ascii") if slot.provider_npi else bytes(10)
            if len(npi) != 10:
                raise StructuralError("claim_payment_key_npi_width_invalid")
            for index, byte in enumerate(npi):
                _append(columns, f"npi_byte_{index}", byte)
            for prefix, value in (
                ("attempt", slot.attempt_version.to_bytes(4, "big")),
                ("parent", slot.parent_attempt_version.to_bytes(4, "big")),
            ):
                for index, byte in enumerate(value):
                    _append(columns, f"{prefix}_byte_{index}", byte)
            revision = (
                {
                    "ORIGINAL": 1,
                    "CORRECTION": 2,
                    "REPLACEMENT": 3,
                    "VOID": 4,
                }[slot.revision_kind.value]
                if slot.slot_kind is SlotKind.REAL
                else 0
            )
            _append(columns, "revision_byte_0", revision)
            for index, byte in enumerate(upsert.key_512):
                _append(columns, f"digest_byte_{index}", byte)

    sha3 = (
        build_application_sha3_interface_air(tuple(calls))
        if interface_only
        else build_application_sha3_executable_air(tuple(calls))
    )
    material_rows = rows * len(_KEY_LANES)
    frozen = freeze_columns(columns)
    identities: list[Identity] = [
        Identity("payment_key_approval_boolean", boolean(cell("approval")), 0, material_rows),
        Identity(
            "payment_key_lane_sum",
            sum((cell(f"is_{lane}") for lane in _KEY_LANES), const(0)) - 1,
            0,
            material_rows,
        ),
        Identity(
            "payment_key_lane_index",
            cell("lane_index")
            - sum(
                (index * cell(f"is_{lane}") for index, lane in enumerate(_KEY_LANES)),
                const(0),
            ),
            0,
            material_rows,
        ),
        Identity(
            "payment_key_call_index",
            cell("call_index")
            - call_index_offset
            - 4 * cell("slot_index")
            - cell("lane_index"),
            0,
            material_rows,
        ),
    ]
    for lane in _KEY_LANES:
        identities.extend(
            (
                Identity(
                    f"payment_key_is_{lane}_boolean",
                    boolean(cell(f"is_{lane}")),
                    0,
                    material_rows,
                ),
                Identity(
                    f"payment_key_approval_{lane}",
                    cell(f"approval_{lane}") - cell("approval") * cell(f"is_{lane}"),
                    0,
                    material_rows,
                ),
                Identity(
                    f"payment_key_dummy_{lane}",
                    cell(f"dummy_{lane}") - (1 - cell("approval")) * cell(f"is_{lane}"),
                    0,
                    material_rows,
                ),
                Identity(
                    f"payment_key_approval_{lane}_boolean",
                    boolean(cell(f"approval_{lane}")),
                    0,
                    material_rows,
                ),
                Identity(
                    f"payment_key_dummy_{lane}_boolean",
                    boolean(cell(f"dummy_{lane}")),
                    0,
                    material_rows,
                ),
            )
        )
    identities.append(
        Identity(
            "payment_key_message_length",
            cell("message_length")
            - sum(
                (
                    length * cell(f"approval_{lane}")
                    for lane, length in zip(_KEY_LANES, _KEY_APPROVAL_LENGTHS, strict=True)
                ),
                _PAYMENT_KEY_CAPACITY
                * sum((cell(f"dummy_{lane}") for lane in _KEY_LANES), const(0)),
            ),
            0,
            material_rows,
        )
    )
    for position in range(_PAYMENT_KEY_CAPACITY):
        identities.append(
            Identity(
                f"payment_key_message_byte_{position}",
                cell(f"message_byte_{position}") - _key_message_expression(position),
                0,
                material_rows,
            )
        )
    repeated_inputs = (
        "is_real",
        "npi_length_byte_0",
        *(f"npi_byte_{index}" for index in range(10)),
        *(f"attempt_byte_{index}" for index in range(4)),
        "revision_byte_0",
        *(f"parent_byte_{index}" for index in range(4)),
        *(f"authority_rank_{index}" for index in range(TOKEN_ENCODED_BYTES)),
        *(f"claim_rank_{index}" for index in range(TOKEN_ENCODED_BYTES)),
        *(f"member_rank_{index}" for index in range(TOKEN_ENCODED_BYTES)),
        *(f"scope_byte_{index}" for index in range(64)),
        *(f"settlement_byte_{index}" for index in range(64)),
        *(f"epoch_byte_{index}" for index in range(8)),
    )
    for name in repeated_inputs:
        identities.append(
            Identity(
                f"payment_key_repeat_{name}",
                (1 - cell("is_payable")) * (cell(name, 1) - cell(name)),
                0,
                material_rows - 1,
                "transition",
            )
        )
    fixed_names = (
        "slot_index",
        "call_index",
        "lane_index",
        *(f"is_{lane}" for lane in _KEY_LANES),
    )
    table = AirTable(
        "claim_payment_key_material",
        tuple(frozen),
        material_rows,
        tuple(identities),
        MappingProxyType({name: frozen[name] for name in fixed_names}),
    )
    trace = TraceTable(table.name, frozen)

    operation_sources = tuple(
        LookupSide(
            "claim_payment_map_slot",
            const(1),
            (
                cell("slot_index"),
                const(lane_index),
                cell("approval"),
                *(cell(f"{lane}_key_{index}") for index in range(64)),
            ),
            0,
            rows,
        )
        for lane_index, lane in enumerate(_KEY_LANES)
    )
    operations = LookupArgument(
        "claim_payment_keys_match_operations",
        operation_sources,
        (
            LookupSide(
                table.name,
                const(1),
                (
                    cell("slot_index"),
                    cell("lane_index"),
                    cell("approval"),
                    *(cell(f"digest_byte_{index}") for index in range(64)),
                ),
                0,
                material_rows,
            ),
        ),
    )
    scalar_names = (
        "is_real",
        "npi_length_byte_0",
        *(f"npi_byte_{index}" for index in range(10)),
        *(f"attempt_byte_{index}" for index in range(4)),
        "revision_byte_0",
        *(f"parent_byte_{index}" for index in range(4)),
    )
    scalar_source_names = (
        "real_byte_0",
        "npi_length_byte_0",
        *(f"npi_byte_{index}" for index in range(10)),
        *(f"attempt_byte_{index}" for index in range(4)),
        "revision_byte_0",
        *(f"parent_byte_{index}" for index in range(4)),
    )
    scalars = LookupArgument(
        "claim_payment_key_scalars_match_source",
        (
            LookupSide(
                "claim_source_scalar",
                const(1),
                (
                    cell("slot_index"),
                    *(cell(name) for name in scalar_source_names),
                ),
                0,
                rows,
            ),
        ),
        (
            LookupSide(
                table.name,
                cell("is_benefit"),
                (cell("slot_index"), *(cell(name) for name in scalar_names)),
                0,
                material_rows,
            ),
        ),
    )
    rank_lookups: list[LookupArgument] = []
    for label, selector in (
        ("authority", "is_authority"),
        ("claim", "is_claim_id"),
        ("member", "is_member"),
    ):
        rank_lookups.append(
            LookupArgument(
                f"claim_payment_key_{label}_rank_matches_source",
                (
                    LookupSide(
                        "claim_source_token_link",
                        cell(selector),
                        (
                            cell("slot_index"),
                            *(cell(f"rank_byte_{index}") for index in range(TOKEN_ENCODED_BYTES)),
                        ),
                        0,
                        source.traces["claim_source_token_link"].rows,
                    ),
                ),
                (
                    LookupSide(
                        table.name,
                        cell("is_benefit"),
                        (
                            cell("slot_index"),
                            *(cell(f"{label}_rank_{index}") for index in range(TOKEN_ENCODED_BYTES)),
                        ),
                        0,
                        material_rows,
                    ),
                ),
            )
        )
    message_sources: list[LookupSide] = []
    for position in range(_PAYMENT_KEY_CAPACITY):
        message_sources.extend(
            LookupSide(
                table.name,
                cell(f"dummy_{lane}"),
                (cell("call_index"), const(position), cell(f"message_byte_{position}")),
                0,
                material_rows,
            )
            for lane in _KEY_LANES
        )
        message_sources.extend(
            LookupSide(
                table.name,
                cell(f"approval_{lane}"),
                (cell("call_index"), const(position), cell(f"message_byte_{position}")),
                0,
                material_rows,
            )
            for lane, length in zip(_KEY_LANES, _KEY_APPROVAL_LENGTHS, strict=True)
            if position < length
        )
    messages = LookupArgument(
        "claim_payment_key_sha3_messages",
        tuple(message_sources),
        (
            LookupSide(
                "sha3_message_batch",
                cell("live"),
                (cell("call_index"), cell("position"), cell("value")),
                0,
                sha3.traces["sha3_message_batch"].rows,
            ),
        ),
    )
    digests = LookupArgument(
        "claim_payment_key_sha3_digests",
        (
            LookupSide(
                "sha3_digest_batch",
                const(1),
                (cell("call_index"), *(cell(f"value_{index}") for index in range(64))),
                0,
                sha3.traces["sha3_digest_batch"].rows,
            ),
        ),
        (
            LookupSide(
                table.name,
                const(1),
                (cell("call_index"), *(cell(f"digest_byte_{index}") for index in range(64))),
                0,
                material_rows,
            ),
        ),
    )
    return sha3, table, trace, (
        operations,
        scalars,
        *rank_lookups,
        messages,
        digests,
    ), source


def _payment_log_sha3(
    slots: tuple[ClaimSlot, ...],
    transition: AuthenticatedPaymentMapBatchTransition,
    *,
    call_index_offset: int = 0,
    interface_only: bool = False,
) -> tuple[ApplicationSha3AirInstance, tuple[LookupArgument, ...]]:
    if type(call_index_offset) is not int or call_index_offset < 0:
        raise StructuralError("claim_payment_log_call_offset_invalid")
    economics = tuple(derive_slot_economics(slot) for slot in slots)
    operation_messages = tuple(
        payment_operation_preimage(
            slot.slot_index,
            payment.witness_class,
            slot_economics,
            payment.upserts,
        )
        for slot, slot_economics, payment in zip(
            slots, economics, transition.transitions, strict=True
        )
    )
    operation_digests = tuple(
        sha3_512(message).digest() for message in operation_messages
    )
    log_messages = tuple(
        payment_operation_log_preimage(
            payment.operation_log_root_before_512,
            transition.before.sequence,
            slot.slot_index,
            digest,
        )
        for slot, payment, digest in zip(
            slots, transition.transitions, operation_digests, strict=True
        )
    )
    calls = tuple(
        Sha3Call(f"payment_operation_{index}", message, len(message))
        for index, message in enumerate(operation_messages)
    ) + tuple(
        Sha3Call(f"payment_log_{index}", message, len(message))
        for index, message in enumerate(log_messages)
    )
    sha3 = (
        build_application_sha3_interface_air(calls)
        if interface_only
        else build_application_sha3_executable_air(calls)
    )
    rows = len(slots)
    operation_domain_length = len(operation_messages[0]) - (2 + 1 + 12 + 12 * 64)
    log_domain_length = len(log_messages[0]) - (64 + 8 + 2 + 64)
    operation_expressions = _operation_message_expressions(
        operation_messages[0][:operation_domain_length]
    )
    log_prefix_expressions = _log_prefix_expressions(
        log_messages[0][:log_domain_length]
    )
    if len(operation_expressions) != len(operation_messages[0]):
        raise StructuralError("claim_payment_operation_preimage_width_mismatch")
    if len(log_prefix_expressions) + 64 != len(log_messages[0]):
        raise StructuralError("claim_payment_log_preimage_width_mismatch")

    message_sources: list[LookupSide] = []
    for position, expression in enumerate(operation_expressions):
        message_sources.append(
            LookupSide(
                "claim_payment_map_slot",
                const(1),
                (
                    cell("slot_index") + call_index_offset,
                    const(position),
                    expression,
                ),
                0,
                rows,
            )
        )
    for position, expression in enumerate(log_prefix_expressions):
        message_sources.append(
            LookupSide(
                "claim_payment_map_slot",
                const(1),
                (
                    cell("slot_index") + call_index_offset + rows,
                    const(position),
                    expression,
                ),
                0,
                rows,
            )
        )
    digest_offset = len(log_prefix_expressions)
    for index in range(64):
        message_sources.append(
            LookupSide(
                "sha3_digest_batch",
                const(1),
                (
                    cell("call_index") + rows,
                    const(digest_offset + index),
                    cell(f"value_{index}"),
                ),
                0,
                rows,
            )
        )
    message_lookup = LookupArgument(
        "claim_payment_log_sha3_messages",
        tuple(message_sources),
        (
            LookupSide(
                "sha3_message_batch",
                cell("live"),
                (cell("call_index"), cell("position"), cell("value")),
                0,
                sha3.traces["sha3_message_batch"].rows,
            ),
        ),
    )
    digest_lookup = LookupArgument(
        "claim_payment_log_sha3_digest",
        (
            LookupSide(
                "sha3_digest_batch",
                const(1),
                (
                    cell("call_index") - call_index_offset - rows,
                    *(cell(f"value_{index}") for index in range(64)),
                ),
                rows,
                2 * rows,
            ),
        ),
        (
            LookupSide(
                "claim_payment_map_slot",
                const(1),
                (
                    cell("slot_index"),
                    *(cell(f"operation_log_after_{index}") for index in range(64)),
                ),
                0,
                rows,
            ),
        ),
    )
    return sha3, (message_lookup, digest_lookup)


def _bridge_table(
    slots: tuple[ClaimSlot, ...],
    transition: AuthenticatedPaymentMapBatchTransition,
) -> tuple[AirTable, TraceTable, tuple[LookupArgument, ...]]:
    if len(slots) != len(transition.transitions):
        raise StructuralError("claim_payment_maps_air_slot_count_mismatch")
    columns: dict[str, list[int]] = {}
    for slot, payment in zip(slots, transition.transitions, strict=True):
        result = evaluate_slot(slot)
        approval = int(result.decision == 1)
        denial = int(slot.slot_kind is SlotKind.REAL and not approval)
        cover = int(slot.slot_kind is SlotKind.COVER)
        _append(columns, "slot_index", slot.slot_index)
        _append(columns, "is_real", int(slot.slot_kind is SlotKind.REAL))
        _append(columns, "decision", result.decision)
        _append(columns, "approval", approval)
        _append(columns, "denial", denial)
        _append(columns, "cover", cover)
        slot_bytes = slot.slot_index.to_bytes(2, "big")
        for index, byte in enumerate(slot_bytes):
            _append(columns, f"slot_index_byte_{index}", byte)
        for label, value in (
            ("allowed", result.allowed_cents),
            ("responsibility", slot.patient_responsibility_cents if approval else 0),
            ("payment", result.payment_cents),
        ):
            _append(columns, f"{label}_limb_0", value & 0xFFFF)
            _append(columns, f"{label}_limb_1", value >> 16)
            for index, byte in enumerate(value.to_bytes(4, "big")):
                _append(columns, f"{label}_byte_{index}", byte)
        authorization_uses = sum(
            int(line.requires_prior_authorization and line.authorization_present)
            for line in slot.service_lines
        )
        _append(columns, "authorization_uses", authorization_uses)
        for index, byte in enumerate(transition.before.sequence.to_bytes(8, "big")):
            _append(columns, f"sequence_byte_{index}", byte)
        _append_bytes(
            columns, "operation_log_before", payment.operation_log_root_before_512
        )
        _append_bytes(
            columns, "operation_log_after", payment.operation_log_root_after_512
        )

        for name, upsert in zip(_VALUE_NAMES, payment.upserts, strict=True):
            _append(columns, f"{name}_insert", int(upsert.mode == "insert"))
            _append_bytes(columns, f"{name}_key", upsert.key_512)
            _append_bytes(columns, f"{name}_before", upsert.value_before_512)
            _append_bytes(columns, f"{name}_after", upsert.value_after_512)

        payment_delta = (result.payment_cents & 0xFFFF, result.payment_cents >> 16, 0, 0)
        allowed_delta = (result.allowed_cents & 0xFFFF, result.allowed_cents >> 16, 0, 0)
        responsibility = slot.patient_responsibility_cents if approval else 0
        responsibility_delta = (responsibility & 0xFFFF, responsibility >> 16, 0, 0)
        arithmetic = (
            (
                "benefit_allowed",
                _u64_limbs(payment.benefit_upsert.value_before_512, 0),
                allowed_delta,
                _u64_limbs(payment.benefit_upsert.value_after_512, 0),
            ),
            (
                "benefit_responsibility",
                _u64_limbs(payment.benefit_upsert.value_before_512, 1),
                responsibility_delta,
                _u64_limbs(payment.benefit_upsert.value_after_512, 1),
            ),
            (
                "benefit_visits",
                _u64_limbs(payment.benefit_upsert.value_before_512, 2),
                (approval, 0, 0, 0),
                _u64_limbs(payment.benefit_upsert.value_after_512, 2),
            ),
            (
                "benefit_authorization_uses",
                _u64_limbs(payment.benefit_upsert.value_before_512, 3),
                (authorization_uses, 0, 0, 0),
                _u64_limbs(payment.benefit_upsert.value_after_512, 3),
            ),
            (
                "reserve",
                _u64_limbs(payment.reserve_upsert.value_after_512),
                payment_delta,
                _u64_limbs(payment.reserve_upsert.value_before_512),
            ),
            (
                "payable",
                _u64_limbs(payment.payable_upsert.value_before_512),
                payment_delta,
                _u64_limbs(payment.payable_upsert.value_after_512),
            ),
        )
        for label, before, delta, after in arithmetic:
            for limb, carry in enumerate(_addition_carries(before, delta, after)):
                _append(columns, f"{label}_carry_{limb}", carry)

    rows = len(slots)
    identities: list[Identity] = []
    for name in (
        "is_real",
        "decision",
        "approval",
        "denial",
        "cover",
        *(f"{value}_insert" for value in _VALUE_NAMES),
    ):
        identities.append(Identity(f"{name}_boolean", boolean(cell(name)), 0, rows))
    identities.extend(
        (
            Identity(
                "slot_index_bytes",
                cell("slot_index")
                - 256 * cell("slot_index_byte_0")
                - cell("slot_index_byte_1"),
                0,
                rows,
            ),
            Identity("approval_decision", cell("approval") - cell("decision"), 0, rows),
            Identity("cover_kind", cell("cover") - (1 - cell("is_real")), 0, rows),
            Identity(
                "denial_kind",
                cell("denial") - cell("is_real") * (1 - cell("decision")),
                0,
                rows,
            ),
            Identity(
                "class_partition",
                cell("approval") + cell("denial") + cell("cover") - 1,
                0,
                rows,
            ),
            Identity(
                "nonapproval_benefit_update",
                (1 - cell("approval")) * cell("benefit_insert"),
                0,
                rows,
            ),
            Identity(
                "obligation_insert_shape",
                cell("obligation_insert") - cell("approval"),
                0,
                rows,
            ),
            Identity("reserve_update_shape", cell("reserve_insert"), 0, rows),
            Identity(
                "nonapproval_payable_update",
                (1 - cell("approval")) * cell("payable_insert"),
                0,
                rows,
            ),
        )
    )
    for label in ("allowed", "responsibility", "payment"):
        identities.extend(
            (
                Identity(
                    f"{label}_high_limb_bytes",
                    cell(f"{label}_limb_1")
                    - 256 * cell(f"{label}_byte_0")
                    - cell(f"{label}_byte_1"),
                    0,
                    rows,
                ),
                Identity(
                    f"{label}_low_limb_bytes",
                    cell(f"{label}_limb_0")
                    - 256 * cell(f"{label}_byte_2")
                    - cell(f"{label}_byte_3"),
                    0,
                    rows,
                ),
            )
        )
    if rows > 1:
        for byte in range(64):
            identities.append(
                Identity(
                    f"operation_log_chain_{byte}",
                    cell(f"operation_log_after_{byte}")
                    - cell(f"operation_log_before_{byte}", 1),
                    0,
                    rows - 1,
                    "transition",
                )
            )

    approval = cell("approval")
    identities.extend(
        _fixed_value_identities(
            "benefit_after", approval, _BENEFIT_TAG, 32, rows
        )
    )
    identities.extend(
        _fixed_value_identities(
            "benefit_before",
            approval * (1 - cell("benefit_insert")),
            _BENEFIT_TAG,
            32,
            rows,
        )
    )
    identities.extend(_zero_value_identities("obligation_before", rows))
    identities.extend(
        _fixed_value_identities(
            "obligation_after", approval, _OBLIGATION_TAG, 16, rows
        )
    )
    for prefix, active in (
        ("reserve_before", approval),
        ("reserve_after", approval),
        ("payable_before", approval * (1 - cell("payable_insert"))),
        ("payable_after", approval),
    ):
        identities.extend(
            _fixed_value_identities(prefix, active, _BALANCE_TAG, 8, rows)
        )

    for byte in range(4):
        identities.append(
            Identity(
                f"obligation_payment_high_zero_{byte}",
                cell(f"obligation_after_{10 + byte}"),
                0,
                rows,
            )
        )
    identities.extend(
        (
            Identity(
                "obligation_payment_high_limb",
                cell("payment_limb_1")
                - 256 * cell("obligation_after_14")
                - cell("obligation_after_15"),
                0,
                rows,
            ),
            Identity(
                "obligation_payment_low_limb",
                cell("payment_limb_0")
                - 256 * cell("obligation_after_16")
                - cell("obligation_after_17"),
                0,
                rows,
            ),
        )
    )
    for index, expected in enumerate(b"OPEN"):
        identities.append(
            Identity(
                f"obligation_open_{index}",
                cell(f"obligation_after_{18 + index}") - approval * expected,
                0,
                rows,
            )
        )

    money = {
        "allowed": (cell("allowed_limb_0"), cell("allowed_limb_1"), const(0), const(0)),
        "responsibility": (
            cell("responsibility_limb_0"),
            cell("responsibility_limb_1"),
            const(0),
            const(0),
        ),
        "payment": (cell("payment_limb_0"), cell("payment_limb_1"), const(0), const(0)),
    }
    identities.extend(
        _add_u64_identities(
            "benefit_allowed",
            "benefit_before",
            0,
            "benefit_after",
            0,
            money["allowed"],
            approval,
            rows,
        )
    )
    identities.extend(
        _add_u64_identities(
            "benefit_authorization_uses",
            "benefit_before",
            3,
            "benefit_after",
            3,
            (cell("authorization_uses"), const(0), const(0), const(0)),
            approval,
            rows,
        )
    )
    identities.extend(
        _add_u64_identities(
            "benefit_responsibility",
            "benefit_before",
            1,
            "benefit_after",
            1,
            money["responsibility"],
            approval,
            rows,
        )
    )
    identities.extend(
        _add_u64_identities(
            "benefit_visits",
            "benefit_before",
            2,
            "benefit_after",
            2,
            (const(1), const(0), const(0), const(0)),
            approval,
            rows,
        )
    )
    identities.extend(
        _add_u64_identities(
            "reserve",
            "reserve_after",
            0,
            "reserve_before",
            0,
            money["payment"],
            approval,
            rows,
        )
    )
    identities.extend(
        _add_u64_identities(
            "payable",
            "payable_before",
            0,
            "payable_after",
            0,
            money["payment"],
            approval,
            rows,
        )
    )

    trace = TraceTable("claim_payment_map_slot", freeze_columns(columns))
    table = AirTable(
        trace.name,
        tuple(trace.columns),
        rows,
        tuple(identities),
        MappingProxyType({"slot_index": tuple(range(rows))}),
    )
    claim_values = (
        cell("slot_index"),
        cell("is_real"),
        cell("decision"),
        cell("allowed_limb_0"),
        cell("allowed_limb_1"),
        cell("responsibility_limb_0"),
        cell("responsibility_limb_1"),
        cell("payment_limb_0"),
        cell("payment_limb_1"),
    )
    lookups = (
        LookupArgument(
            "claim_payment_result_binding",
            (LookupSide("claim_result", const(1), claim_values, 0, rows),),
            (LookupSide(trace.name, const(1), claim_values, 0, rows),),
        ),
        LookupArgument(
            "claim_payment_authorization_uses",
            (
                LookupSide(
                    "claim_service",
                    cell("is_last"),
                    (cell("slot_index"), cell("authorization_count_after")),
                    0,
                    rows * SERVICE_LINES_PER_CLAIM,
                ),
            ),
            (
                LookupSide(
                    trace.name,
                    const(1),
                    (cell("slot_index"), cell("authorization_uses")),
                    0,
                    rows,
                ),
            ),
        ),
        LookupArgument(
            "claim_payment_benefit_operation",
            (
                LookupSide(
                    trace.name,
                    const(1),
                    _operation_values("benefit", cell("slot_index")),
                    0,
                    rows,
                ),
            ),
            (
                LookupSide(
                    "benefit__ordered_map_operation",
                    const(1),
                    _map_operation_values(cell("operation_index")),
                    0,
                    rows,
                ),
            ),
        ),
        LookupArgument(
            "claim_payment_obligation_operation",
            (
                LookupSide(
                    trace.name,
                    const(1),
                    _operation_values("obligation", cell("slot_index")),
                    0,
                    rows,
                ),
            ),
            (
                LookupSide(
                    "obligation__ordered_map_operation",
                    const(1),
                    _map_operation_values(cell("operation_index")),
                    0,
                    rows,
                ),
            ),
        ),
        LookupArgument(
            "claim_payment_ledger_operations",
            (
                LookupSide(
                    trace.name,
                    const(1),
                    _operation_values("reserve", 2 * cell("slot_index")),
                    0,
                    rows,
                ),
                LookupSide(
                    trace.name,
                    const(1),
                    _operation_values("payable", 2 * cell("slot_index") + 1),
                    0,
                    rows,
                ),
            ),
            (
                LookupSide(
                    "ledger__ordered_map_operation",
                    const(1),
                    _map_operation_values(cell("operation_index")),
                    0,
                    2 * rows,
                ),
            ),
        ),
    )
    return table, trace, lookups


def _shift_key_sha3_lookup_rows(
    lookups: tuple[LookupArgument, ...],
    *,
    call_rows: int,
    message_rows: int,
) -> tuple[LookupArgument, ...]:
    def shift(side: LookupSide) -> LookupSide:
        offset = (
            call_rows
            if side.table == "sha3_digest_batch"
            else message_rows
            if side.table == "sha3_message_batch"
            else 0
        )
        return LookupSide(
            side.table,
            side.selector,
            side.values,
            side.row_start + offset,
            side.row_stop + offset,
            side.weight,
        )

    return tuple(
        LookupArgument(
            lookup.name,
            tuple(shift(side) for side in lookup.sources),
            tuple(shift(side) for side in lookup.destinations),
        )
        for lookup in lookups
    )


def build_claim_payment_maps_executable_air(
    slots: Sequence[ClaimSlot],
    transition: AuthenticatedPaymentMapBatchTransition,
    *,
    shard_index_bits: int = 24,
    compose_operation_log_sha3: bool = False,
    compose_key_sha3: bool = False,
    compose_map_sha3: bool = False,
    interface_only: bool = False,
    sha3_call_prefix: int = 0,
    call_index_offset: int = 0,
) -> ClaimPaymentMapsAirInstance:
    materialized = tuple(slots)
    if not materialized:
        raise StructuralError("claim_payment_maps_air_slots_required")
    if type(compose_operation_log_sha3) is not bool:
        raise StructuralError("claim_payment_maps_air_log_composition_flag_invalid")
    if type(compose_key_sha3) is not bool:
        raise StructuralError("claim_payment_maps_air_key_composition_flag_invalid")
    if type(compose_map_sha3) is not bool:
        raise StructuralError("claim_payment_maps_air_map_composition_flag_invalid")
    if type(interface_only) is not bool:
        raise StructuralError("claim_payment_maps_air_interface_flag_invalid")
    if type(sha3_call_prefix) is not int or sha3_call_prefix < 0:
        raise StructuralError("claim_payment_maps_air_call_prefix_invalid")
    if sha3_call_prefix and (not interface_only or compose_map_sha3):
        raise StructuralError("claim_payment_maps_air_call_prefix_invalid")
    if type(call_index_offset) is not int or call_index_offset < 0:
        raise StructuralError("claim_payment_maps_air_call_offset_invalid")
    claim = build_claim_semantics_executable_air(materialized)
    payment_maps = build_authenticated_payment_maps_executable_air(
        transition,
        shard_index_bits=shard_index_bits,
        compose_sha3=compose_map_sha3,
        interface_only=interface_only,
        call_index_offset=call_index_offset,
    )
    bridge_table, bridge_trace, bridge_lookups = _bridge_table(
        materialized, transition
    )
    map_sha3 = payment_maps.application_sha3
    map_call_rows = 0 if map_sha3 is None else len(map_sha3.digests)
    map_message_rows = (
        0 if map_sha3 is None else map_sha3.traces["sha3_message_batch"].rows
    )
    if compose_key_sha3:
        key_sha3, key_table, key_trace, key_lookups, source_arrays = _payment_key_sha3(
            materialized,
            transition,
            call_index_offset=call_index_offset + map_call_rows + sha3_call_prefix,
            interface_only=interface_only,
        )
    else:
        key_sha3 = None
        source_arrays = None
        key_table = None
        key_trace = None
        key_lookups = ()
    key_call_rows = 0 if key_sha3 is None else len(key_sha3.digests)
    key_message_rows = (
        0 if key_sha3 is None else key_sha3.traces["sha3_message_batch"].rows
    )
    if map_sha3 is not None and key_sha3 is not None:
        key_lookups = _shift_key_sha3_lookup_rows(
            key_lookups,
            call_rows=map_call_rows,
            message_rows=map_message_rows,
        )
    if compose_operation_log_sha3:
        payment_log_sha3, payment_log_lookups = _payment_log_sha3(
            materialized,
            transition,
            call_index_offset=(
                call_index_offset
                + map_call_rows
                + sha3_call_prefix
                + key_call_rows
            ),
            interface_only=interface_only,
        )
        if map_sha3 is not None or key_sha3 is not None:
            payment_log_lookups = _shift_key_sha3_lookup_rows(
                payment_log_lookups,
                call_rows=map_call_rows + key_call_rows,
                message_rows=map_message_rows + key_message_rows,
            )
    else:
        payment_log_sha3 = None
        payment_log_lookups = ()

    application_batches = tuple(
        value for value in (map_sha3, key_sha3, payment_log_sha3) if value is not None
    )
    if len(application_batches) > 1:
        application_sha3 = (
            combine_application_sha3_interface_air(application_batches)
            if interface_only
            else combine_application_sha3_executable_air(application_batches)
        )
    elif application_batches:
        application_sha3 = application_batches[0]
    else:
        application_sha3 = None
    application_tables = () if application_sha3 is None else application_sha3.program.tables
    application_lookups = () if application_sha3 is None else application_sha3.program.lookups
    application_traces = {} if application_sha3 is None else dict(application_sha3.traces)
    source_tables = () if source_arrays is None else source_arrays.program.tables
    source_lookups = () if source_arrays is None else source_arrays.program.lookups
    source_traces = {} if source_arrays is None else dict(source_arrays.traces)
    key_material_tables = () if key_table is None else (key_table,)
    key_material_traces = {} if key_trace is None else {key_trace.name: key_trace}
    if map_sha3 is None:
        payment_map_tables = payment_maps.program.tables
        payment_map_lookups = payment_maps.program.lookups
    else:
        map_sha_table_names = {table.name for table in map_sha3.program.tables}
        map_sha_lookup_names = {lookup.name for lookup in map_sha3.program.lookups}
        payment_map_tables = tuple(
            table
            for table in payment_maps.program.tables
            if table.name not in map_sha_table_names
        )
        payment_map_lookups = tuple(
            lookup
            for lookup in payment_maps.program.lookups
            if lookup.name not in map_sha_lookup_names
        )
    program = AirProgram(
        PROGRAM_ID,
        (
            *claim.program.tables,
            *payment_map_tables,
            bridge_table,
            *source_tables,
            *key_material_tables,
            *application_tables,
        ),
        (
            *claim.program.lookups,
            *payment_map_lookups,
            *bridge_lookups,
            *source_lookups,
            *application_lookups,
            *payment_log_lookups,
            *key_lookups,
        ),
    )
    traces = MappingProxyType(
        {
            **dict(claim.traces),
            **dict(payment_maps.traces),
            bridge_trace.name: bridge_trace,
            **source_traces,
            **key_material_traces,
            **application_traces,
        }
    )
    return ClaimPaymentMapsAirInstance(
        program,
        traces,
        payment_maps,
        source_arrays,
        application_sha3,
        call_index_offset,
        key_derivations_constrained=compose_key_sha3 and not interface_only,
        authorization_uses_constrained=True,
        operation_log_constrained=compose_operation_log_sha3 and not interface_only,
        payment_map_hashes_constrained=compose_map_sha3 and not interface_only,
        key_derivation_ports_constrained=compose_key_sha3 and interface_only,
        operation_log_ports_constrained=compose_operation_log_sha3 and interface_only,
        payment_map_hash_ports_constrained=compose_map_sha3 and interface_only,
        sha3_interface_only=interface_only,
        sha3_call_prefix=sha3_call_prefix,
    )


def build_claim_payment_maps_sha3_interface_program(
    instance: ClaimPaymentMapsAirInstance,
) -> tuple[AirProgram, tuple[int, ...]]:
    """Add map hash ports to a key/log interface without allocating map SHA traces."""

    if (
        not isinstance(instance, ClaimPaymentMapsAirInstance)
        or not instance.sha3_interface_only
        or instance.application_sha3 is None
        or not instance.key_derivation_ports_constrained
        or not instance.operation_log_ports_constrained
        or instance.payment_map_hash_ports_constrained
    ):
        raise StructuralError("claim_payment_interface_program_input_invalid")
    map_program, map_capacities = build_authenticated_payment_maps_sha3_interface_program(
        instance.payment_maps,
        call_index_offset=instance.call_index_offset,
    )
    if instance.sha3_call_prefix != len(map_capacities):
        raise StructuralError("claim_payment_interface_program_prefix_mismatch")
    application_capacities = tuple(
        call.capacity for call in instance.application_sha3.calls
    )
    capacities = map_capacities + application_capacities
    interface = build_application_sha3_interface_program(capacities)
    sha_tables = {
        "sha3_message_batch",
        "sha3_digest_batch",
        "sha3_digest_byte_batch",
    }
    normalization = "application_sha3_digest_byte_normalization"
    tables = tuple(
        table for table in instance.program.tables if table.name not in sha_tables
    )
    map_message_rows = build_application_sha3_interface_program(
        map_capacities
    ).tables[0].rows
    shifted = tuple(
        _shift_key_sha3_lookup_rows(
            (lookup,),
            call_rows=len(map_capacities),
            message_rows=map_message_rows,
        )[0]
        for lookup in instance.program.lookups
        if lookup.name != normalization
    )
    map_bindings = tuple(
        lookup
        for lookup in map_program.lookups
        if lookup.name
        in {
            "payment_maps_sha3_message_binding",
            "payment_maps_sha3_digest_binding",
        }
    )
    if len(map_bindings) != 2:
        raise StructuralError("claim_payment_interface_program_map_bindings_missing")
    return (
        AirProgram(
            PROGRAM_ID,
            (*tables, *interface.tables),
            (*interface.lookups, *map_bindings, *shifted),
            instance.program.public_inputs,
        ),
        capacities,
    )


__all__ = [
    "ClaimPaymentMapsAirInstance",
    "build_claim_payment_maps_executable_air",
    "build_claim_payment_maps_sha3_interface_program",
]
