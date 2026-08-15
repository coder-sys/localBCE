"""Complete one-engine Wave 1A semantic and cryptographic composition."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Mapping

from .a12_nullifier_executable_air import A12NullifierAirInstance
from .application_sha3_executable_air import (
    ApplicationSha3AirInstance,
    INTERFACE_PROGRAM_ID,
)
from .air_composition import (
    AirFragment,
    Sha3ComposedComponent,
    Sha3ProgramFragment,
    compose_boolean_sha3_air_components,
    compose_boolean_sha3_program_fragments,
    compose_sha3_interface_components,
    compose_sha3_interface_program_fragments,
    merge_air_fragments,
)
from .claim_payment_maps_executable_air import ClaimPaymentMapsAirInstance
from .claim_source_claim_executable_air import ClaimSourceClaimAirInstance
from .claim_truth_global_executable_air import ClaimTruthGlobalAirInstance
from .executable_air import (
    AirProgram,
    AirTable,
    LookupArgument,
    LookupSide,
    PublicInputBinding,
    TraceTable,
    cell,
    const,
)
from .master_public_composition import MasterPublicAirInstance
from .profile import CalibrationProfile
from .replay_ordered_map_executable_air import ReplayOrderedMapAirInstance
from .salt_use_tag_executable_air import SaltUseTagAirInstance
from .semantics import StructuralError
from .wave1a_global_sha3_capacity_schedule import (
    build_wave1a_global_sha3_capacity_schedule,
)


PROGRAM_ID: Final[str] = "BL-WAVE1A-GLOBAL-EXECUTABLE-AIR-v1"
_SHA_PROGRAM_ID: Final[str] = "BL-WAVE1A-GLOBAL-SHA3-COMPOSITION-v1"
_REQUIRED_GLOBAL_LINK_NAMES: Final[tuple[str, ...]] = (
    "wave1a_master_truth_links",
    "wave1a_master_authority_links",
    "wave1a_master_cover_domain_link",
    "wave1a_master_cover_nonce_link",
    "wave1a_master_cover_epoch_link",
    "wave1a_master_payment_domain_link",
    "wave1a_master_payment_epoch_link",
    "wave1a_master_claim_slot_links",
    "wave1a_master_a12_nullifier_links",
    "wave1a_master_salt_use_link",
    "wave1a_master_replay_root_links",
    "wave1a_master_payment_root_links",
)
_SHA3_INTERFACE_TABLE_NAMES: Final[tuple[str, ...]] = (
    "sha3_message_batch",
    "sha3_digest_batch",
    "sha3_digest_byte_batch",
)


@dataclass(frozen=True, slots=True)
class Wave1AGlobalAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    claim_truth: ClaimTruthGlobalAirInstance
    source_claim: ClaimSourceClaimAirInstance
    a12: A12NullifierAirInstance
    salt_use: SaltUseTagAirInstance
    replay: ReplayOrderedMapAirInstance
    payment: ClaimPaymentMapsAirInstance
    master_public: MasterPublicAirInstance
    one_sha3_engine: bool = True
    all_global_links_constrained: bool = True

    def __post_init__(self) -> None:
        required = {
            "wave1a_master_truth_links",
            "wave1a_master_authority_links",
            "wave1a_master_cover_domain_link",
            "wave1a_master_cover_nonce_link",
            "wave1a_master_cover_epoch_link",
            "wave1a_master_payment_domain_link",
            "wave1a_master_payment_epoch_link",
            "wave1a_master_claim_slot_links",
            "wave1a_master_a12_nullifier_links",
            "wave1a_master_salt_use_link",
            "wave1a_master_replay_root_links",
            "wave1a_master_payment_root_links",
        }
        if (
            not self.one_sha3_engine
            or not self.all_global_links_constrained
            or any(
                tuple(table.name for table in self.program.tables).count(name) != 1
                for name in (
                    "sha3_boolean_round",
                    "sha3_boolean_absorb",
                    "sha3_boolean_digest",
                )
            )
            or {"sha3_round_batch", "sha3_truth_shared", "sha3_byte_range_shared"}
            & {table.name for table in self.program.tables}
            or not {
                "application_sha3_message_to_boolean_sha3",
                "application_sha3_digest_to_boolean_sha3",
            }.issubset(lookup.name for lookup in self.program.lookups)
            or not required.issubset(lookup.name for lookup in self.program.lookups)
        ):
            raise StructuralError("wave1a_global_false_completion_claim")


@dataclass(frozen=True, slots=True)
class Wave1AGlobalSemanticBusAirInstance:
    """Complete private Wave 1A witness with SHA3 represented by bus ports."""

    program: AirProgram
    traces: Mapping[str, TraceTable]
    sha3: ApplicationSha3AirInstance
    profile: CalibrationProfile
    claim_truth: ClaimTruthGlobalAirInstance
    source_claim: ClaimSourceClaimAirInstance
    a12: A12NullifierAirInstance
    salt_use: SaltUseTagAirInstance
    replay: ReplayOrderedMapAirInstance
    payment: ClaimPaymentMapsAirInstance
    master_public: MasterPublicAirInstance
    global_links: tuple[LookupArgument, ...]
    one_sha3_interface: bool = True
    all_global_links_constrained: bool = True

    def __post_init__(self) -> None:
        table_names = tuple(table.name for table in self.program.tables)
        interface_names = set(_SHA3_INTERFACE_TABLE_NAMES)
        boolean_names = {
            "sha3_boolean_round",
            "sha3_boolean_absorb",
            "sha3_boolean_digest",
            "sha3_round_batch",
            "sha3_truth_shared",
            "sha3_byte_range_shared",
        }
        if (
            not isinstance(self.profile, CalibrationProfile)
            or not isinstance(self.sha3, ApplicationSha3AirInstance)
            or self.sha3.program.program_id != INTERFACE_PROGRAM_ID
            or not self.one_sha3_interface
            or not self.all_global_links_constrained
            or any(table_names.count(name) != 1 for name in interface_names)
            or boolean_names.intersection(table_names)
            or set(self.traces) != set(table_names)
            or any(
                self.traces[name].columns != self.sha3.traces[name].columns
                for name in interface_names
            )
            or tuple(lookup.name for lookup in self.global_links)
            != _REQUIRED_GLOBAL_LINK_NAMES
            or not set(_REQUIRED_GLOBAL_LINK_NAMES).issubset(
                lookup.name for lookup in self.program.lookups
            )
            or any(
                binding.table in interface_names
                for binding in self.program.public_inputs
            )
            or tuple(call.capacity for call in self.sha3.calls)
            != build_wave1a_global_sha3_capacity_schedule(self.profile).capacities
        ):
            raise StructuralError("wave1a_global_semantic_bus_false_completion_claim")


def _field_bytes(instance: MasterPublicAirInstance, name: str) -> bytes:
    value = instance.master.inputs
    if name == "epoch":
        return value.epoch.to_bytes(8, "big")
    if name.startswith("claim_truth_root_"):
        return value.claim_truth_roots_512[int(name.rsplit("_", 1)[1])]
    if name.startswith("payment_lane_before_"):
        return value.payment_lane_roots_before_512[int(name.rsplit("_", 1)[1])]
    if name.startswith("payment_lane_after_"):
        return value.payment_lane_roots_after_512[int(name.rsplit("_", 1)[1])]
    direct = {
        "claim_truth_authority_digest": value.claim_truth_authority_digest_512,
        "nullifier_authority_id": value.nullifier_authority_id_512,
        "pepper_commitment": value.pepper_commitment_512,
        "settlement_domain": value.strong_settlement_domain_id_512,
        "batch_nonce": value.strong_batch_nonce_512,
        "replay_before": value.replay_root_before_512,
        "replay_after": value.replay_root_after_512,
        "operation_log_before": value.operation_log_root_before_512,
        "operation_log_after": value.operation_log_root_after_512,
        "salt_use_tag": value.salt_use_tag_512,
    }
    try:
        return direct[name]
    except KeyError as exc:
        raise StructuralError(f"wave1a_global_master_field_unknown:{name}") from exc


def _field_start(instance: MasterPublicAirInstance, name: str) -> int:
    trace = instance.master.traces["master_commitment_material_byte"]
    field_id = instance.master.field_ids[name]
    rows = tuple(
        index
        for index, observed in enumerate(trace.columns["field_id"])
        if observed == field_id
    )
    expected = len(_field_bytes(instance, name))
    if len(rows) != expected or rows != tuple(range(rows[0], rows[0] + expected)):
        raise StructuralError("wave1a_global_master_field_geometry_invalid")
    return rows[0]


def _fixed_byte_link(
    instance: MasterPublicAirInstance,
    links: tuple[tuple[str, str, str, int], ...],
    name: str,
) -> LookupArgument:
    material = instance.master.traces["master_commitment_material_byte"]
    sources: list[LookupSide] = []
    destinations: list[LookupSide] = []
    for link_id, (field_name, table, prefix, row) in enumerate(links):
        raw = _field_bytes(instance, field_name)
        start = _field_start(instance, field_name)
        for byte_index in range(len(raw)):
            sources.append(
                LookupSide(
                    material.name,
                    const(1),
                    (const(link_id), const(byte_index), cell("value")),
                    start + byte_index,
                    start + byte_index + 1,
                )
            )
            destinations.append(
                LookupSide(
                    table,
                    const(1),
                    (
                        const(link_id),
                        const(byte_index),
                        cell(f"{prefix}{byte_index}"),
                    ),
                    row,
                    row + 1,
                )
            )
    return LookupArgument(name, tuple(sources), tuple(destinations))


def _repeated_byte_link(
    instance: MasterPublicAirInstance,
    field_name: str,
    table: str,
    prefix: str,
    rows: int,
    selector,
    multiplicity: int,
    name: str,
) -> LookupArgument:
    material = instance.master.traces["master_commitment_material_byte"]
    raw = _field_bytes(instance, field_name)
    start = _field_start(instance, field_name)
    return LookupArgument(
        name,
        tuple(
            LookupSide(
                material.name,
                const(1),
                (const(byte_index), cell("value")),
                start + byte_index,
                start + byte_index + 1,
                const(multiplicity),
            )
            for byte_index in range(len(raw))
        ),
        tuple(
            LookupSide(
                table,
                selector,
                (const(byte_index), cell(f"{prefix}{byte_index}")),
                0,
                rows,
            )
            for byte_index in range(len(raw))
        ),
    )


def _global_links(
    source_claim: ClaimSourceClaimAirInstance,
    a12: A12NullifierAirInstance,
    salt_use: SaltUseTagAirInstance,
    replay: ReplayOrderedMapAirInstance,
    payment: ClaimPaymentMapsAirInstance,
    master_public: MasterPublicAirInstance,
) -> tuple[LookupArgument, ...]:
    del source_claim
    truth = _fixed_byte_link(
        master_public,
        (
            ("claim_truth_root_0", "claim_source_hash_root", "value_", 0),
            ("claim_truth_root_1", "oracle_execution_root", "execution_", 0),
            ("claim_truth_root_2", "oracle_execution_root", "audit_", 0),
            ("claim_truth_root_3", "policy_execution_root", "execution_", 0),
            ("claim_truth_root_4", "policy_execution_root", "audit_", 0),
            ("claim_truth_root_5", "ruleset_commitment", "root_", 0),
            (
                "claim_truth_authority_digest",
                "claim_truth_authority_material",
                "digest_",
                0,
            ),
        ),
        "wave1a_master_truth_links",
    )
    authority = _fixed_byte_link(
        master_public,
        (
            ("nullifier_authority_id", "a12_authority", "authority_id_", 0),
            ("pepper_commitment", "a12_authority", "commitment_", 0),
        ),
        "wave1a_master_authority_links",
    )
    cover_count = sum(
        1 - value for value in a12.traces["a12_request"].columns["is_attempt"]
    )
    cover_context_parts = (
        _repeated_byte_link(
            master_public,
            "settlement_domain",
            "a12_request",
            "cover_domain_",
            len(a12.operation_ids),
            1 - cell("is_attempt"),
            cover_count,
            "wave1a_master_cover_domain_link",
        ),
        _repeated_byte_link(
            master_public,
            "batch_nonce",
            "a12_request",
            "cover_batch_",
            len(a12.operation_ids),
            1 - cell("is_attempt"),
            cover_count,
            "wave1a_master_cover_nonce_link",
        ),
        _repeated_byte_link(
            master_public,
            "epoch",
            "a12_request",
            "cover_epoch_",
            len(a12.operation_ids),
            1 - cell("is_attempt"),
            cover_count,
            "wave1a_master_cover_epoch_link",
        ),
    )
    payment_rows = payment.traces["claim_payment_key_material"].rows
    payment_context_parts = (
        _repeated_byte_link(
            master_public,
            "settlement_domain",
            "claim_payment_key_material",
            "settlement_byte_",
            payment_rows,
            const(1),
            payment_rows,
            "wave1a_master_payment_domain_link",
        ),
        _repeated_byte_link(
            master_public,
            "epoch",
            "claim_payment_key_material",
            "epoch_byte_",
            payment_rows,
            const(1),
            payment_rows,
            "wave1a_master_payment_epoch_link",
        ),
    )
    slot_rows = len(a12.operation_ids)
    slot_link = LookupArgument(
        "wave1a_master_claim_slot_links",
        (
            LookupSide(
                "master_commitment_slot",
                const(1),
                (
                    cell("slot_index"),
                    cell("encoded_2"),
                    256 * cell("encoded_3") + cell("encoded_4"),
                    256 * cell("encoded_7") + cell("encoded_8"),
                    256 * cell("encoded_5") + cell("encoded_6"),
                    256 * cell("encoded_11") + cell("encoded_12"),
                    256 * cell("encoded_9") + cell("encoded_10"),
                    *(cell(f"raw_gate_{index}") for index in range(13)),
                    *(cell(f"effective_gate_{index}") for index in range(13)),
                ),
                0,
                slot_rows,
            ),
        ),
        (
            LookupSide(
                "claim_result",
                const(1),
                (
                    cell("slot_index"),
                    cell("decision"),
                    cell("failure_code"),
                    cell("allowed_limb_0"),
                    cell("allowed_limb_1"),
                    cell("payment_limb_0"),
                    cell("payment_limb_1"),
                    *(cell(f"raw_gate_{index}") for index in range(13)),
                    *(cell(f"effective_gate_{index}") for index in range(13)),
                ),
                0,
                slot_rows,
            ),
        ),
    )
    nullifier_link = LookupArgument(
        "wave1a_master_a12_nullifier_links",
        (
            LookupSide(
                "master_commitment_slot",
                const(1),
                (
                    cell("slot_index"),
                    *(cell(f"encoded_{17 + index}") for index in range(64)),
                ),
                0,
                slot_rows,
            ),
        ),
        (
            LookupSide(
                "a12_output",
                const(1),
                (
                    cell("request_index"),
                    *(cell(f"strong_{index}") for index in range(64)),
                ),
                0,
                slot_rows,
            ),
        ),
    )
    salt = _fixed_byte_link(
        master_public,
        (("salt_use_tag", "salt_use_tag_material", "tag_", 0),),
        "wave1a_master_salt_use_link",
    )
    replay_roots = _fixed_byte_link(
        master_public,
        (
            (
                "replay_before",
                "replay_map__ordered_map_state",
                "root_before_",
                0,
            ),
            (
                "replay_after",
                "replay_map__ordered_map_state",
                "root_after_",
                0,
            ),
        ),
        "wave1a_master_replay_root_links",
    )
    payment_root_links = [
        (f"payment_lane_before_{lane}", "payment_map_lane_state", "root_before_", lane)
        for lane in range(3)
    ] + [
        (f"payment_lane_after_{lane}", "payment_map_lane_state", "root_after_", lane)
        for lane in range(3)
    ]
    payment_root_links.extend(
        (
            ("operation_log_before", "claim_payment_map_slot", "operation_log_before_", 0),
            (
                "operation_log_after",
                "claim_payment_map_slot",
                "operation_log_after_",
                slot_rows - 1,
            ),
        )
    )
    payment_roots = _fixed_byte_link(
        master_public,
        tuple(payment_root_links),
        "wave1a_master_payment_root_links",
    )
    return (
        truth,
        authority,
        *cover_context_parts,
        *payment_context_parts,
        slot_link,
        nullifier_link,
        salt,
        replay_roots,
        payment_roots,
    )


def _wave1a_sha3_components(
    claim_truth: ClaimTruthGlobalAirInstance,
    source_claim: ClaimSourceClaimAirInstance,
    a12: A12NullifierAirInstance,
    salt_use: SaltUseTagAirInstance,
    replay: ReplayOrderedMapAirInstance,
    payment: ClaimPaymentMapsAirInstance,
    master_public: MasterPublicAirInstance,
) -> tuple[Sha3ComposedComponent, ...]:
    if (
        not isinstance(claim_truth, ClaimTruthGlobalAirInstance)
        or not (
            claim_truth.all_truth_roots_constrained
            or claim_truth.truth_root_ports_constrained
        )
        or not isinstance(source_claim, ClaimSourceClaimAirInstance)
        or not isinstance(a12, A12NullifierAirInstance)
        or not (a12.nullifier_hashes_constrained or a12.hash_ports_constrained)
        or not isinstance(salt_use, SaltUseTagAirInstance)
        or not (salt_use.tag_constrained or salt_use.hash_ports_constrained)
        or not isinstance(replay, ReplayOrderedMapAirInstance)
        or replay.application_sha3 is None
        or not (replay.hashes_constrained or replay.hash_ports_constrained)
        or not isinstance(payment, ClaimPaymentMapsAirInstance)
        or payment.application_sha3 is None
        or not (
            payment.key_derivations_constrained
            or payment.key_derivation_ports_constrained
        )
        or not (
            payment.operation_log_constrained
            or payment.operation_log_ports_constrained
        )
        or not (
            payment.payment_map_hashes_constrained
            or payment.payment_map_hash_ports_constrained
        )
        or not isinstance(master_public, MasterPublicAirInstance)
        or not (
            master_public.master.master_hashes_constrained
            or master_public.master.hash_ports_constrained
        )
    ):
        raise StructuralError("wave1a_global_components_invalid")
    truth_sha = claim_truth.composed.sha3
    offsets = [0]
    for count in (
        len(truth_sha.digests),
        len(a12.sha3.digests),
        len(salt_use.sha3.digests),
        len(replay.application_sha3.digests),
        len(payment.application_sha3.digests),
    ):
        offsets.append(offsets[-1] + count)
    if (
        salt_use.call_index_offset != offsets[2]
        or replay.call_index_offset != offsets[3]
        or payment.call_index_offset != offsets[4]
        or master_public.master.call_index_offset != offsets[5]
    ):
        raise StructuralError("wave1a_global_call_offsets_invalid")
    return (
        Sha3ComposedComponent(
            claim_truth.composed.program,
            claim_truth.composed.traces,
            truth_sha,
            offsets[0],
        ),
        Sha3ComposedComponent(a12.program, a12.traces, a12.sha3, offsets[1]),
        Sha3ComposedComponent(
            salt_use.program,
            salt_use.traces,
            salt_use.sha3,
            offsets[2],
        ),
        Sha3ComposedComponent(
            replay.program,
            replay.traces,
            replay.application_sha3,
            offsets[3],
        ),
        Sha3ComposedComponent(
            payment.program,
            payment.traces,
            payment.application_sha3,
            offsets[4],
        ),
        Sha3ComposedComponent(
            master_public.program,
            master_public.traces,
            master_public.master.sha3,
            offsets[5],
        ),
    )


def _source_claim_composition_extras(
    components: tuple[Sha3ComposedComponent, ...],
    source_claim: ClaimSourceClaimAirInstance,
) -> tuple[
    tuple[AirTable, ...],
    Mapping[str, TraceTable],
    tuple[LookupArgument, ...],
    tuple[PublicInputBinding, ...],
]:
    component_tables: dict[str, list[tuple[AirTable, TraceTable]]] = {}
    component_lookups: dict[str, list[LookupArgument]] = {}
    component_public_inputs: dict[str, list[PublicInputBinding]] = {}
    for component in components:
        sha_table_names = {table.name for table in component.sha3.program.tables}
        sha_lookup_names = {lookup.name for lookup in component.sha3.program.lookups}
        for table in component.program.tables:
            if table.name not in sha_table_names:
                component_tables.setdefault(table.name, []).append(
                    (table, component.traces[table.name])
                )
        for lookup in component.program.lookups:
            if lookup.name not in sha_lookup_names:
                component_lookups.setdefault(lookup.name, []).append(lookup)
        for binding in component.program.public_inputs:
            component_public_inputs.setdefault(binding.name, []).append(binding)

    extra_tables: list[AirTable] = []
    extra_traces: dict[str, TraceTable] = {}
    for table in source_claim.program.tables:
        trace = source_claim.traces[table.name]
        observed = component_tables.get(table.name, ())
        if observed and any(
            candidate.canonical() != table.canonical()
            or candidate_trace.name != trace.name
            or candidate_trace.columns != trace.columns
            for candidate, candidate_trace in observed
        ):
            raise StructuralError(
                f"wave1a_global_source_claim_table_conflict:{table.name}"
            )
        if not observed:
            extra_tables.append(table)
            extra_traces[table.name] = trace

    extra_lookups: list[LookupArgument] = []
    for lookup in source_claim.program.lookups:
        observed = component_lookups.get(lookup.name, ())
        if observed and any(
            candidate.canonical() != lookup.canonical() for candidate in observed
        ):
            raise StructuralError(
                f"wave1a_global_source_claim_lookup_conflict:{lookup.name}"
            )
        if not observed:
            extra_lookups.append(lookup)

    extra_public_inputs: list[PublicInputBinding] = []
    for binding in source_claim.program.public_inputs:
        observed = component_public_inputs.get(binding.name, ())
        if observed and any(candidate != binding for candidate in observed):
            raise StructuralError(
                f"wave1a_global_source_claim_public_conflict:{binding.name}"
            )
        if not observed:
            extra_public_inputs.append(binding)
    return (
        tuple(extra_tables),
        extra_traces,
        tuple(extra_lookups),
        tuple(extra_public_inputs),
    )


def build_wave1a_global_executable_air(
    claim_truth: ClaimTruthGlobalAirInstance,
    source_claim: ClaimSourceClaimAirInstance,
    a12: A12NullifierAirInstance,
    salt_use: SaltUseTagAirInstance,
    replay: ReplayOrderedMapAirInstance,
    payment: ClaimPaymentMapsAirInstance,
    master_public: MasterPublicAirInstance,
) -> Wave1AGlobalAirInstance:
    components = _wave1a_sha3_components(
        claim_truth,
        source_claim,
        a12,
        salt_use,
        replay,
        payment,
        master_public,
    )
    sha_composed = compose_boolean_sha3_air_components(_SHA_PROGRAM_ID, components)
    links = _global_links(
        source_claim,
        a12,
        salt_use,
        replay,
        payment,
        master_public,
    )
    merged = merge_air_fragments(
        PROGRAM_ID,
        (
            AirFragment(sha_composed.program, sha_composed.traces),
            AirFragment(source_claim.program, source_claim.traces),
        ),
        extra_lookups=links,
    )
    return Wave1AGlobalAirInstance(
        merged.program,
        merged.traces,
        claim_truth,
        source_claim,
        a12,
        salt_use,
        replay,
        payment,
        master_public,
    )


def build_wave1a_global_program_only(
    profile: CalibrationProfile,
    sha3_fragments: tuple[Sha3ProgramFragment, ...],
    source_claim_program: AirProgram,
    global_links: tuple[LookupArgument, ...],
) -> AirProgram:
    """Build exact full-relation verifier IR without retaining private witnesses."""

    if (
        not isinstance(profile, CalibrationProfile)
        or not sha3_fragments
        or not isinstance(source_claim_program, AirProgram)
        or type(global_links) is not tuple
    ):
        raise StructuralError("wave1a_global_program_inputs_invalid")
    expected = build_wave1a_global_sha3_capacity_schedule(profile).capacities
    observed = tuple(
        capacity for fragment in sha3_fragments for capacity in fragment.capacities
    )
    if observed != expected:
        raise StructuralError("wave1a_global_program_sha3_schedule_mismatch")
    required_links = {
        "wave1a_master_truth_links",
        "wave1a_master_authority_links",
        "wave1a_master_cover_domain_link",
        "wave1a_master_cover_nonce_link",
        "wave1a_master_cover_epoch_link",
        "wave1a_master_payment_domain_link",
        "wave1a_master_payment_epoch_link",
        "wave1a_master_claim_slot_links",
        "wave1a_master_a12_nullifier_links",
        "wave1a_master_salt_use_link",
        "wave1a_master_replay_root_links",
        "wave1a_master_payment_root_links",
    }
    if {lookup.name for lookup in global_links} != required_links:
        raise StructuralError("wave1a_global_program_links_incomplete")
    return compose_boolean_sha3_program_fragments(
        PROGRAM_ID,
        sha3_fragments,
        extra_tables=source_claim_program.tables,
        extra_lookups=(*source_claim_program.lookups, *global_links),
        extra_public_inputs=source_claim_program.public_inputs,
    )


def build_wave1a_global_semantic_bus_program_only(
    profile: CalibrationProfile,
    sha3_fragments: tuple[Sha3ProgramFragment, ...],
    source_claim_program: AirProgram,
    global_links: tuple[LookupArgument, ...],
) -> AirProgram:
    """Build the release semantic AIR with external SHA3 bus ports only."""

    if (
        not isinstance(profile, CalibrationProfile)
        or not sha3_fragments
        or not isinstance(source_claim_program, AirProgram)
        or type(global_links) is not tuple
    ):
        raise StructuralError("wave1a_global_program_inputs_invalid")
    expected = build_wave1a_global_sha3_capacity_schedule(profile).capacities
    observed = tuple(
        capacity for fragment in sha3_fragments for capacity in fragment.capacities
    )
    if observed != expected:
        raise StructuralError("wave1a_global_program_sha3_schedule_mismatch")
    required_links = {
        "wave1a_master_truth_links",
        "wave1a_master_authority_links",
        "wave1a_master_cover_domain_link",
        "wave1a_master_cover_nonce_link",
        "wave1a_master_cover_epoch_link",
        "wave1a_master_payment_domain_link",
        "wave1a_master_payment_epoch_link",
        "wave1a_master_claim_slot_links",
        "wave1a_master_a12_nullifier_links",
        "wave1a_master_salt_use_link",
        "wave1a_master_replay_root_links",
        "wave1a_master_payment_root_links",
    }
    if {lookup.name for lookup in global_links} != required_links:
        raise StructuralError("wave1a_global_program_links_incomplete")
    return compose_sha3_interface_program_fragments(
        PROGRAM_ID,
        sha3_fragments,
        extra_tables=source_claim_program.tables,
        extra_lookups=(*source_claim_program.lookups, *global_links),
        extra_public_inputs=source_claim_program.public_inputs,
    )


def build_wave1a_global_semantic_bus_executable_air(
    profile: CalibrationProfile,
    claim_truth: ClaimTruthGlobalAirInstance,
    source_claim: ClaimSourceClaimAirInstance,
    a12: A12NullifierAirInstance,
    salt_use: SaltUseTagAirInstance,
    replay: ReplayOrderedMapAirInstance,
    payment: ClaimPaymentMapsAirInstance,
    master_public: MasterPublicAirInstance,
) -> Wave1AGlobalSemanticBusAirInstance:
    """Compose the complete private Wave 1A witness over external SHA3 ports.

    The returned traces and ``sha3.calls`` are prover-private inputs.  This
    constructor does not serialize either into a proof or public statement.
    """

    if not isinstance(profile, CalibrationProfile):
        raise StructuralError("wave1a_global_program_inputs_invalid")
    components = _wave1a_sha3_components(
        claim_truth,
        source_claim,
        a12,
        salt_use,
        replay,
        payment,
        master_public,
    )
    capacities = tuple(
        call.capacity for component in components for call in component.sha3.calls
    )
    if capacities != build_wave1a_global_sha3_capacity_schedule(profile).capacities:
        raise StructuralError("wave1a_global_program_sha3_schedule_mismatch")
    links = _global_links(
        source_claim,
        a12,
        salt_use,
        replay,
        payment,
        master_public,
    )
    if tuple(lookup.name for lookup in links) != _REQUIRED_GLOBAL_LINK_NAMES:
        raise StructuralError("wave1a_global_program_links_incomplete")
    fragments = tuple(
        Sha3ProgramFragment(
            component.program,
            tuple(call.capacity for call in component.sha3.calls),
            component.call_index_offset,
        )
        for component in components
    )
    expected_program = build_wave1a_global_semantic_bus_program_only(
        profile,
        fragments,
        source_claim.program,
        links,
    )
    (
        source_tables,
        source_traces,
        source_lookups,
        source_public_inputs,
    ) = _source_claim_composition_extras(components, source_claim)
    composed = compose_sha3_interface_components(
        PROGRAM_ID,
        components,
        extra_tables=source_tables,
        extra_traces=source_traces,
        extra_lookups=(*source_lookups, *links),
        extra_public_inputs=source_public_inputs,
    )
    if composed.program.canonical_bytes() != expected_program.canonical_bytes():
        raise StructuralError("wave1a_global_semantic_bus_program_mismatch")
    return Wave1AGlobalSemanticBusAirInstance(
        composed.program,
        composed.traces,
        composed.sha3,
        profile,
        claim_truth,
        source_claim,
        a12,
        salt_use,
        replay,
        payment,
        master_public,
        links,
    )


__all__ = (
    "Wave1AGlobalAirInstance",
    "Wave1AGlobalSemanticBusAirInstance",
    "build_wave1a_global_executable_air",
    "build_wave1a_global_program_only",
    "build_wave1a_global_semantic_bus_executable_air",
    "build_wave1a_global_semantic_bus_program_only",
)
