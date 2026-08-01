"""Historical Wave 1A relation-inventory estimator and dimension ledger.

This module records the schedule that R33 proposed for a future backend. It
verifies the composed *host* relation and commits to metadata, but it does not
contain trace cells, polynomial identities, boundary/transition constraints,
lookup-multiset arguments, or a serialized verifier statement. Its dimensions
are estimates and MUST NOT be used as theorem inputs.

Hash, challenge, commitment, composition, and proof ports remain typed and
abstract.  No current S-two proof path is called; no proof bytes are created;
the rejected QM31/Blake2s suite is not promoted.  Consequently this module is
historical inventory evidence only: it is not an AIR, a STARK, a production
verifier, or activation authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import hmac
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from app.batch.pq_tree_reference import require_synthetic_reference_enabled

from .authenticated_payment_maps_reference import SPARSE_MAP_DEPTH
from .profile import (
    AUTHORIZATIONS_PER_CLAIM,
    LEGACY_NULLIFIER_TREE_DEPTH,
    POLICY_TREE_DEPTH,
    STRONG_NULLIFIER_TREE_DEPTH,
    CalibrationProfile,
)
from .semantics import SlotKind, StructuralError
from .wave1a_relation_reference import (
    PUBLIC_OUTPUT_NAMES,
    Wave1AReferenceRelation,
    verify_wave1a_reference_relation,
)


PHYSICAL_RELATION_STATUS: Final[str] = (
    "WAVE1A_DECLARED_RELATION_INVENTORY_NOT_EXECUTABLE_AIR_NONACTIVATING"
)
HASH_PORT_ID: Final[str] = "SHA3_512_CONSTRAINT_PORT_V1_UNINSTANTIATED"
LEGACY_HASH_PORT_ID: Final[str] = "STARKNET_POSEIDON_CONSTRAINT_PORT_V1"
CHALLENGE_PORT_ID: Final[str] = "BL_PQ512_TYPED_CHALLENGE_PORT_V1_UNINSTANTIATED"
COMMITMENT_PORT_ID: Final[str] = "BL_PQ512_TYPED_COMMITMENT_PORT_V1_UNINSTANTIATED"
PROOF_SUITE_ID: Final[None] = None
ACTIVATION_ALLOWED: Final[bool] = False
MAX_D_EFF_ENVELOPE: Final[int] = 1 << 111

_PROGRAM_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/PHYSICAL-RELATION-PROGRAM/v1"
_TRACE_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/PHYSICAL-RELATION-TRACE/v1"
_SLOT_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/PHYSICAL-SLOT/v1"


def _next_power_of_two(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise StructuralError("wave1a_air_row_count_invalid")
    return 1 << (value - 1).bit_length()


def _ascii(label: str, value: object) -> bytes:
    if type(value) is not str:
        raise StructuralError(f"wave1a_air_{label}_must_be_text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise StructuralError(f"wave1a_air_{label}_must_be_ascii") from exc
    if not encoded or len(encoded) > 0xFFFF:
        raise StructuralError(f"wave1a_air_{label}_length_invalid")
    return len(encoded).to_bytes(2, "big") + encoded


@dataclass(frozen=True, slots=True)
class ColumnFamily:
    name: str
    width: int
    purpose: str

    def __post_init__(self) -> None:
        _ascii("column_family_name", self.name)
        _ascii("column_family_purpose", self.purpose)
        if type(self.width) is not int or self.width <= 0:
            raise StructuralError("wave1a_air_column_family_width_invalid")


@dataclass(frozen=True, slots=True)
class ConstraintFamily:
    name: str
    count: int
    maximum_degree: int

    def __post_init__(self) -> None:
        _ascii("constraint_family_name", self.name)
        if type(self.count) is not int or self.count <= 0:
            raise StructuralError("wave1a_air_constraint_count_invalid")
        if type(self.maximum_degree) is not int or not 1 <= self.maximum_degree <= 8:
            raise StructuralError("wave1a_air_constraint_degree_invalid")


@dataclass(frozen=True, slots=True)
class PhysicalAirTable:
    name: str
    logical_rows: int
    padded_rows: int
    column_families: tuple[ColumnFamily, ...]
    constraint_families: tuple[ConstraintFamily, ...]
    lookup_message_width: int
    commitment_group: str

    def __post_init__(self) -> None:
        _ascii("table_name", self.name)
        _ascii("commitment_group", self.commitment_group)
        if type(self.logical_rows) is not int or self.logical_rows <= 0:
            raise StructuralError("wave1a_air_logical_rows_invalid")
        if self.padded_rows != _next_power_of_two(self.logical_rows):
            raise StructuralError("wave1a_air_padded_rows_invalid")
        if type(self.column_families) is not tuple or not self.column_families:
            raise StructuralError("wave1a_air_column_families_required")
        if type(self.constraint_families) is not tuple or not self.constraint_families:
            raise StructuralError("wave1a_air_constraint_families_required")
        if type(self.lookup_message_width) is not int or not 0 <= self.lookup_message_width <= 64:
            raise StructuralError("wave1a_air_lookup_width_invalid")

    @property
    def trace_columns(self) -> int:
        return sum(value.width for value in self.column_families)

    @property
    def constraint_count(self) -> int:
        return sum(value.count for value in self.constraint_families)

    @property
    def maximum_degree(self) -> int:
        return max(value.maximum_degree for value in self.constraint_families)

    @property
    def padded_cells(self) -> int:
        return self.padded_rows * self.trace_columns


def _columns(*values: tuple[str, int, str]) -> tuple[ColumnFamily, ...]:
    return tuple(ColumnFamily(*value) for value in values)


def _constraints(*values: tuple[str, int, int]) -> tuple[ConstraintFamily, ...]:
    return tuple(ConstraintFamily(*value) for value in values)


def _table(
    name: str,
    rows: int,
    columns: tuple[ColumnFamily, ...],
    constraints: tuple[ConstraintFamily, ...],
    lookup_width: int,
    group: str,
) -> PhysicalAirTable:
    return PhysicalAirTable(
        name,
        rows,
        _next_power_of_two(rows),
        columns,
        constraints,
        lookup_width,
        group,
    )


def _table_schedule(profile: CalibrationProfile) -> tuple[PhysicalAirTable, ...]:
    k = profile.claim_slots
    dimensions = profile.logical_dimensions()
    oracle_leaves = dimensions["oracle_leaves"]
    service_rows = dimensions["service_line_rows"]
    return (
        _table(
            "canonical_witness",
            k,
            _columns(
                ("control_and_counts", 24, "slot kind, enable flags, bounded counts, cursor"),
                ("canonical_identifiers", 96, "lengths, chunks, lifecycle, and ordering keys"),
                ("money_and_range_limbs", 96, "u32 claim values and checked u64 aggregates"),
                ("governance_binding", 40, "profile, epoch, domain, authority, and registry lanes"),
            ),
            _constraints(
                ("boolean_and_range", 192, 2),
                ("canonical_ordering", 96, 3),
                ("fixed_shape_and_cursor", 64, 2),
                ("governance_equality", 48, 2),
            ),
            16,
            "private_main",
        ),
        _table(
            "claim_gate_and_money",
            k,
            _columns(
                ("r26_decision_money_kernel", 267, "13 gates, priority, u32 limbs/bits, u64 carries"),
                ("authenticated_predicate_inputs", 64, "source, oracle, policy, and authorization results"),
            ),
            _constraints(
                ("r26_kernel_constraints", 476, 3),
                ("predicate_authentication_links", 128, 3),
                ("exact_batch_conservation", 48, 3),
            ),
            24,
            "private_main",
        ),
        _table(
            "service_lines",
            service_rows,
            _columns(
                ("line_control", 16, "claim/line indices, enable, canonical order"),
                ("line_identifiers", 48, "procedure, line, authorization chunks"),
                ("line_money", 72, "u32 values, limbs, and range bits"),
                ("line_policy_links", 24, "fee and authorization lookup messages"),
            ),
            _constraints(
                ("line_canonicality", 96, 3),
                ("line_money_ranges", 192, 2),
                ("line_totals_and_gates", 80, 3),
                ("disabled_line_zeroing", 64, 2),
            ),
            20,
            "private_main",
        ),
        _table(
            "diagnoses",
            dimensions["diagnosis_rows"],
            _columns(
                ("diagnosis_control", 12, "claim/position/enable/order"),
                ("diagnosis_chunks", 24, "canonical code chunks"),
            ),
            _constraints(
                ("diagnosis_canonicality", 48, 2),
                ("diagnosis_order_and_padding", 32, 3),
            ),
            8,
            "private_main",
        ),
        _table(
            "oracle_facts",
            dimensions["fact_rows"],
            _columns(
                ("fact_control", 16, "claim/fact indices, type, enable"),
                ("fact_value", 40, "typed value, signer, epoch, validity"),
                ("fact_membership_link", 24, "legacy and wide root messages"),
            ),
            _constraints(
                ("fact_type_and_range", 64, 2),
                ("fact_signer_epoch", 48, 3),
                ("fact_claim_binding", 48, 3),
            ),
            12,
            "private_main",
        ),
        _table(
            "authorizations",
            dimensions["authorization_rows"],
            _columns(
                ("authorization_control", 16, "claim/line index and enable"),
                ("authorization_record", 56, "token, provider, member, dates, signer, epoch"),
                ("authorization_membership_link", 24, "oracle membership messages"),
            ),
            _constraints(
                ("authorization_canonicality", 80, 2),
                ("authorization_subject_and_date", 80, 3),
                ("authorization_signer_epoch", 48, 3),
                ("authorization_padding", 32, 2),
            ),
            12,
            "private_main",
        ),
        _table(
            "claim_source_tree",
            k * profile.claim_source_tree_depth,
            _columns(
                ("path_control", 12, "claim, level, direction, enable"),
                ("legacy_poseidon_path", 12, "legacy leaf, sibling, parent"),
                ("wide_sha3_path", 48, "full-width leaf, sibling, parent limbs"),
                ("authority_binding", 24, "source authority and epoch message"),
            ),
            _constraints(
                ("path_schedule", 32, 2),
                ("legacy_path_port", 32, 3),
                ("wide_path_port", 64, 3),
                ("authority_root_binding", 32, 2),
            ),
            16,
            "authenticated_paths",
        ),
        _table(
            "oracle_tree",
            oracle_leaves * profile.oracle_tree_depth,
            _columns(
                ("path_control", 12, "leaf, level, direction, fact class"),
                ("legacy_poseidon_path", 12, "legacy leaf, sibling, parent"),
                ("wide_sha3_path", 48, "full-width leaf, sibling, parent limbs"),
            ),
            _constraints(
                ("path_schedule", 32, 2),
                ("legacy_path_port", 32, 3),
                ("wide_path_port", 64, 3),
            ),
            12,
            "authenticated_paths",
        ),
        _table(
            "policy_and_ruleset_tree",
            service_rows * POLICY_TREE_DEPTH,
            _columns(
                ("query_control", 16, "claim/line/level/direction/presence"),
                ("policy_record", 40, "procedure, fee, TAR flag, ruleset/version"),
                ("legacy_poseidon_path", 12, "legacy dictionary path"),
                ("wide_sha3_path", 48, "wide sparse dictionary path"),
            ),
            _constraints(
                ("query_schedule", 48, 2),
                ("membership_or_nonmembership", 96, 3),
                ("fee_and_tar_binding", 64, 3),
                ("ruleset_version_authority", 48, 3),
            ),
            20,
            "authenticated_paths",
        ),
        _table(
            "legacy_replay_transition",
            k * 2 * LEGACY_NULLIFIER_TREE_DEPTH,
            _columns(
                ("path_control", 16, "slot/read-write/level/direction"),
                ("full_predecessor_record", 24, "low/key/high/index relation"),
                ("poseidon_path", 16, "leaf, sibling, parent, domain"),
            ),
            _constraints(
                ("nonmembership_order", 64, 3),
                ("read_write_root_chain", 64, 3),
                ("path_and_slot_schedule", 48, 2),
            ),
            12,
            "authenticated_state",
        ),
        _table(
            "strong_replay_transition",
            (k + 1) * 2 * STRONG_NULLIFIER_TREE_DEPTH,
            _columns(
                ("path_control", 16, "slot/salt/read-write/level/direction"),
                ("full_512_bit_keys", 96, "predecessor, target, successor limbs"),
                ("sha3_path", 48, "leaf, sibling, parent full-width limbs"),
                ("derivation_binding", 40, "A12 preimage and salt-use typed links"),
            ),
            _constraints(
                ("full_key_nonmembership", 128, 3),
                ("read_write_root_chain", 128, 3),
                ("a12_derivation_and_salt_use", 96, 3),
                ("path_and_slot_schedule", 64, 2),
            ),
            24,
            "authenticated_state",
        ),
        _table(
            "benefit_accumulator_map",
            k * 2 * SPARSE_MAP_DEPTH,
            _columns(
                ("path_control", 16, "slot/read-write/level/direction/reserved"),
                ("full_key_and_record", 72, "member key and four u64 accumulator fields"),
                ("sha3_path", 48, "leaf, sibling, parent full-width limbs"),
            ),
            _constraints(
                ("benefit_checked_updates", 128, 3),
                ("reserved_zero_to_zero", 48, 2),
                ("sha3_root_chain_port", 128, 3),
            ),
            20,
            "authenticated_state",
        ),
        _table(
            "provider_obligation_map",
            k * 2 * SPARSE_MAP_DEPTH,
            _columns(
                ("path_control", 16, "slot/read-write/level/direction/reserved"),
                ("full_key_and_record", 72, "claim/provider key, amount, status"),
                ("sha3_path", 48, "leaf, sibling, parent full-width limbs"),
            ),
            _constraints(
                ("unique_obligation_insert", 128, 3),
                ("reserved_zero_to_zero", 48, 2),
                ("sha3_root_chain_port", 128, 3),
            ),
            20,
            "authenticated_state",
        ),
        _table(
            "private_asset_ledger_map",
            k * 4 * SPARSE_MAP_DEPTH,
            _columns(
                ("path_control", 20, "slot/account/read-write/level/direction/reserved"),
                ("full_key_and_balance", 72, "payer/provider keys and checked u64 balances"),
                ("sha3_path", 48, "leaf, sibling, parent full-width limbs"),
                ("transfer_link", 32, "debit, credit, payable, asset registry"),
            ),
            _constraints(
                ("funded_reserve_debit", 128, 3),
                ("provider_payable_credit", 128, 3),
                ("transfer_conservation", 64, 3),
                ("reserved_zero_to_zero", 64, 2),
                ("sha3_root_chain_port", 160, 3),
            ),
            24,
            "authenticated_state",
        ),
        _table(
            "payment_operation_log",
            k,
            _columns(
                ("operation_control", 16, "slot/class/sequence and fixed lane selectors"),
                ("economic_values", 40, "allowed, responsibility, payable, debit, credit"),
                ("map_roots_and_keys", 160, "four keys and six before/after subroots"),
                ("sha3_log_state", 32, "previous/next log commitments"),
            ),
            _constraints(
                ("operation_typing", 64, 2),
                ("map_root_links", 128, 2),
                ("economic_conservation", 64, 3),
                ("sha3_log_append_port", 64, 3),
            ),
            20,
            "authenticated_state",
        ),
        _table(
            "ordered_public_statement",
            len(PUBLIC_OUTPUT_NAMES),
            _columns(
                ("field_control", 8, "fixed index and output type"),
                ("legacy_felt", 16, "canonical 32-byte Stark felt limbs"),
                ("binding_links", 64, "relation, governance, state, and batch links"),
            ),
            _constraints(
                ("exact_twelve_field_order", 48, 2),
                ("canonical_felt_range", 64, 3),
                ("legacy_formula_ports", 96, 3),
                ("strong_batch_binding", 64, 3),
            ),
            16,
            "public_statement",
        ),
    )


@dataclass(frozen=True, slots=True)
class Wave1APhysicalAirProgram:
    status: str
    profile_id: str
    tables: tuple[PhysicalAirTable, ...]
    commitment_groups: tuple[str, ...]
    hash_port_id: str
    legacy_hash_port_id: str
    challenge_port_id: str
    commitment_port_id: str
    proof_suite_id: None
    activation_allowed: bool
    program_commitment_sha3_512: bytes
    d_eff_upper_bound: int

    def __post_init__(self) -> None:
        if self.status != PHYSICAL_RELATION_STATUS:
            raise StructuralError("wave1a_air_program_status_invalid")
        if type(self.tables) is not tuple or len(self.tables) != 16:
            raise StructuralError("wave1a_air_table_count_invalid")
        if len({table.name for table in self.tables}) != len(self.tables):
            raise StructuralError("wave1a_air_table_name_duplicate")
        expected_groups = tuple(sorted({table.commitment_group for table in self.tables}))
        if self.commitment_groups != expected_groups:
            raise StructuralError("wave1a_air_commitment_groups_invalid")
        if (
            self.hash_port_id != HASH_PORT_ID
            or self.legacy_hash_port_id != LEGACY_HASH_PORT_ID
            or self.challenge_port_id != CHALLENGE_PORT_ID
            or self.commitment_port_id != COMMITMENT_PORT_ID
            or self.proof_suite_id is not None
            or self.activation_allowed
        ):
            raise StructuralError("wave1a_air_security_boundary_invalid")
        if type(self.program_commitment_sha3_512) is not bytes or len(
            self.program_commitment_sha3_512
        ) != 64:
            raise StructuralError("wave1a_air_program_commitment_invalid")
        if not 0 < self.d_eff_upper_bound <= MAX_D_EFF_ENVELOPE:
            raise StructuralError("wave1a_air_d_eff_outside_envelope")

    @property
    def table_count(self) -> int:
        return len(self.tables)

    @property
    def commitment_count(self) -> int:
        return len(self.commitment_groups)

    @property
    def total_logical_rows(self) -> int:
        return sum(table.logical_rows for table in self.tables)

    @property
    def total_padded_rows(self) -> int:
        return sum(table.padded_rows for table in self.tables)

    @property
    def total_trace_columns(self) -> int:
        return sum(table.trace_columns for table in self.tables)

    @property
    def total_constraints(self) -> int:
        return sum(table.constraint_count for table in self.tables)

    @property
    def maximum_constraint_degree(self) -> int:
        return max(table.maximum_degree for table in self.tables)

    @property
    def total_lookup_message_width(self) -> int:
        return sum(table.lookup_message_width for table in self.tables)

    @property
    def total_padded_cells(self) -> int:
        return sum(table.padded_cells for table in self.tables)

    def dimensions(self) -> Mapping[str, int]:
        return MappingProxyType(
            {
                "tables": self.table_count,
                "commitments": self.commitment_count,
                "logical_rows": self.total_logical_rows,
                "padded_rows": self.total_padded_rows,
                "trace_columns_across_tables": self.total_trace_columns,
                "constraints": self.total_constraints,
                "maximum_constraint_degree": self.maximum_constraint_degree,
                "lookup_message_width_across_tables": self.total_lookup_message_width,
                "padded_cells": self.total_padded_cells,
                "d_eff_upper_bound": self.d_eff_upper_bound,
            }
        )


def _program_preimage(profile: CalibrationProfile, tables: tuple[PhysicalAirTable, ...]) -> bytes:
    chunks = [
        _PROGRAM_DOMAIN,
        _ascii("profile_id", profile.profile_id),
        _ascii("hash_port_id", HASH_PORT_ID),
        _ascii("legacy_hash_port_id", LEGACY_HASH_PORT_ID),
        _ascii("challenge_port_id", CHALLENGE_PORT_ID),
        _ascii("commitment_port_id", COMMITMENT_PORT_ID),
        len(tables).to_bytes(2, "big"),
    ]
    for table in tables:
        chunks.extend(
            (
                _ascii("table_name", table.name),
                table.logical_rows.to_bytes(8, "big"),
                table.padded_rows.to_bytes(8, "big"),
                table.trace_columns.to_bytes(4, "big"),
                table.constraint_count.to_bytes(4, "big"),
                table.maximum_degree.to_bytes(2, "big"),
                table.lookup_message_width.to_bytes(2, "big"),
                _ascii("commitment_group", table.commitment_group),
            )
        )
        for family in table.column_families:
            chunks.extend(
                (
                    _ascii("column_family_name", family.name),
                    family.width.to_bytes(4, "big"),
                    _ascii("column_family_purpose", family.purpose),
                )
            )
        for family in table.constraint_families:
            chunks.extend(
                (
                    _ascii("constraint_family_name", family.name),
                    family.count.to_bytes(4, "big"),
                    family.maximum_degree.to_bytes(2, "big"),
                )
            )
    return b"".join(chunks)


def build_wave1a_physical_air_program(
    profile: CalibrationProfile,
) -> Wave1APhysicalAirProgram:
    require_synthetic_reference_enabled()
    if not isinstance(profile, CalibrationProfile):
        raise StructuralError("wave1a_air_profile_required")
    tables = _table_schedule(profile)
    groups = tuple(sorted({table.commitment_group for table in tables}))
    max_rows = max(table.padded_rows for table in tables)
    total_constraints = sum(table.constraint_count for table in tables)
    max_degree = max(table.maximum_degree for table in tables)
    message_terms = sum(table.lookup_message_width for table in tables)
    # Conservative interface-level envelope.  Final S09 revalidation must
    # substitute the concrete SHA3/PCS/FRI implementation and every positive
    # error term; this value grants no security credit by itself.
    d_eff = max_rows * (max_degree + 1) * total_constraints * (
        message_terms + len(groups) + 1
    )
    return Wave1APhysicalAirProgram(
        PHYSICAL_RELATION_STATUS,
        profile.profile_id,
        tables,
        groups,
        HASH_PORT_ID,
        LEGACY_HASH_PORT_ID,
        CHALLENGE_PORT_ID,
        COMMITMENT_PORT_ID,
        PROOF_SUITE_ID,
        ACTIVATION_ALLOWED,
        sha3_512(_program_preimage(profile, tables)).digest(),
        d_eff,
    )


@dataclass(frozen=True, slots=True)
class PhysicalSlotBinding:
    slot_index: int
    witness_class: str
    binding_sha3_512: bytes

    def __post_init__(self) -> None:
        if type(self.slot_index) is not int or not 0 <= self.slot_index <= 511:
            raise StructuralError("wave1a_air_slot_binding_index_invalid")
        if self.witness_class not in {"approval", "denial", "cover"}:
            raise StructuralError("wave1a_air_slot_binding_class_invalid")
        if type(self.binding_sha3_512) is not bytes or len(self.binding_sha3_512) != 64:
            raise StructuralError("wave1a_air_slot_binding_digest_invalid")


@dataclass(frozen=True, slots=True)
class Wave1APhysicalRelationTrace:
    status: str
    program: Wave1APhysicalAirProgram
    relation: Wave1AReferenceRelation
    slot_bindings: tuple[PhysicalSlotBinding, ...]
    trace_commitment_sha3_512: bytes
    physical_relation_constrained: bool = False
    concrete_stark_backend_selected: bool = False
    proof_generated: bool = False
    production_usable: bool = False

    def __post_init__(self) -> None:
        if self.status != PHYSICAL_RELATION_STATUS:
            raise StructuralError("wave1a_air_trace_status_invalid")
        if len(self.slot_bindings) != len(self.relation.slots):
            raise StructuralError("wave1a_air_slot_binding_count_mismatch")
        if tuple(value.slot_index for value in self.slot_bindings) != tuple(
            range(len(self.slot_bindings))
        ):
            raise StructuralError("wave1a_air_slot_binding_order_invalid")
        if (
            self.physical_relation_constrained
            or self.concrete_stark_backend_selected
            or self.proof_generated
            or self.production_usable
        ):
            raise StructuralError("wave1a_air_trace_security_boundary_invalid")
        if type(self.trace_commitment_sha3_512) is not bytes or len(
            self.trace_commitment_sha3_512
        ) != 64:
            raise StructuralError("wave1a_air_trace_commitment_invalid")


def _slot_binding(relation: Wave1AReferenceRelation, index: int) -> PhysicalSlotBinding:
    slot = relation.slots[index]
    result = relation.claim_truth.slot_results[index]
    payment = relation.payment_map_transition.transitions[index]
    witness_class = "cover" if slot.slot_kind is SlotKind.COVER else (
        "approval" if result.decision else "denial"
    )
    raw_bits = sum(int(value) << offset for offset, value in enumerate(result.raw_gate_predicates))
    effective_bits = sum(
        int(value) << offset for offset, value in enumerate(result.effective_gate_predicates)
    )
    digest = sha3_512(
        _SLOT_DOMAIN
        + index.to_bytes(2, "big")
        + witness_class.encode("ascii")
        + result.decision.to_bytes(1, "big")
        + result.failure_code.to_bytes(1, "big")
        + result.allowed_cents.to_bytes(4, "big")
        + result.payment_cents.to_bytes(4, "big")
        + raw_bits.to_bytes(2, "big")
        + effective_bits.to_bytes(2, "big")
        + relation.replay_derivations[index].strong_sha3_512
        + payment.benefit_root_before_512
        + payment.benefit_root_after_512
        + payment.obligation_root_before_512
        + payment.obligation_root_after_512
        + payment.ledger_root_before_512
        + payment.ledger_root_after_512
        + payment.operation_log_root_before_512
        + payment.operation_log_root_after_512
    ).digest()
    return PhysicalSlotBinding(index, witness_class, digest)


def build_wave1a_physical_relation_trace(
    profile: CalibrationProfile,
    relation: Wave1AReferenceRelation,
) -> Wave1APhysicalRelationTrace:
    require_synthetic_reference_enabled()
    if not isinstance(relation, Wave1AReferenceRelation):
        raise StructuralError("wave1a_air_relation_required")
    if relation.profile_id != profile.profile_id:
        raise StructuralError("wave1a_air_relation_profile_mismatch")
    verify_wave1a_reference_relation(profile, relation)
    program = build_wave1a_physical_air_program(profile)
    bindings = tuple(_slot_binding(relation, index) for index in range(profile.claim_slots))
    commitment = sha3_512(
        _TRACE_DOMAIN
        + program.program_commitment_sha3_512
        + relation.strong_governance_commitment_sha3_512
        + relation.strong_batch_commitment_sha3_512
        + relation.payment_map_transition.before.root()
        + relation.payment_map_transition.after.root()
        + b"".join(value.to_bytes(32, "big") for value in relation.public_outputs)
        + b"".join(value.binding_sha3_512 for value in bindings)
    ).digest()
    return Wave1APhysicalRelationTrace(
        PHYSICAL_RELATION_STATUS,
        program,
        relation,
        bindings,
        commitment,
    )


def verify_wave1a_physical_relation_trace(
    profile: CalibrationProfile,
    trace: Wave1APhysicalRelationTrace,
) -> bool:
    if not isinstance(trace, Wave1APhysicalRelationTrace):
        raise StructuralError("wave1a_air_trace_required")
    observed = build_wave1a_physical_relation_trace(profile, trace.relation)
    if observed != trace:
        raise StructuralError("wave1a_air_trace_recomputation_mismatch")
    if not hmac.compare_digest(
        observed.trace_commitment_sha3_512, trace.trace_commitment_sha3_512
    ):
        raise StructuralError("wave1a_air_trace_commitment_mismatch")
    return True


def calibration_dimension_ledger(
    profiles: Sequence[CalibrationProfile],
) -> Mapping[str, Mapping[str, int]]:
    materialized = tuple(profiles)
    if not materialized:
        raise StructuralError("wave1a_air_profiles_required")
    if len({profile.profile_id for profile in materialized}) != len(materialized):
        raise StructuralError("wave1a_air_profile_duplicate")
    return MappingProxyType(
        {
            profile.profile_id: build_wave1a_physical_air_program(profile).dimensions()
            for profile in materialized
        }
    )


__all__ = [
    "ACTIVATION_ALLOWED",
    "CHALLENGE_PORT_ID",
    "COMMITMENT_PORT_ID",
    "HASH_PORT_ID",
    "LEGACY_HASH_PORT_ID",
    "MAX_D_EFF_ENVELOPE",
    "PHYSICAL_RELATION_STATUS",
    "PROOF_SUITE_ID",
    "ColumnFamily",
    "ConstraintFamily",
    "PhysicalAirTable",
    "PhysicalSlotBinding",
    "Wave1APhysicalAirProgram",
    "Wave1APhysicalRelationTrace",
    "build_wave1a_physical_air_program",
    "build_wave1a_physical_relation_trace",
    "calibration_dimension_ledger",
    "verify_wave1a_physical_relation_trace",
]
