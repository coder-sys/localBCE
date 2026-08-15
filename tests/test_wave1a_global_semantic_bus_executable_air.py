from __future__ import annotations

from hashlib import sha3_512
import os
from types import SimpleNamespace
from unittest import mock

import pytest

from app.batch.pq_nullifier_derivation import (
    AttemptReplayIdentityV1,
    CoverReplayContextV2,
    NullifierDerivationAuthorityV1,
    REVISION_KIND_ORIGINAL,
)
from experiments.bl_pq512_crypto_foundation.claim_truth_pq_authority import (
    ClaimTruthAuthorityRegistryV1,
    ClaimTruthRootsV1,
    sign_claim_truth_roots,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.fixed_shape_claim_air import wave1a_global_executable_air as global_air
from experiments.fixed_shape_claim_air.a12_nullifier_executable_air import (
    AttemptNullifierAirRequest,
    CoverNullifierAirRequest,
    build_a12_nullifier_executable_air,
)
from experiments.fixed_shape_claim_air.air_composition import Sha3ProgramFragment
from experiments.fixed_shape_claim_air.application_sha3_executable_air import (
    Sha3Call,
    build_application_sha3_interface_air,
)
from experiments.fixed_shape_claim_air.claim_payment_maps_executable_air import (
    build_claim_payment_maps_executable_air,
)
from experiments.fixed_shape_claim_air.claim_source_claim_executable_air import (
    build_claim_source_claim_executable_air,
)
from experiments.fixed_shape_claim_air.claim_source_commitment_executable_air import (
    build_claim_source_commitment_executable_air,
)
from experiments.fixed_shape_claim_air.claim_truth_authority_executable_air import (
    build_claim_truth_authority_executable_air,
)
from experiments.fixed_shape_claim_air.claim_truth_global_executable_air import (
    build_claim_truth_global_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import (
    AirProgram,
    AirTable,
    LookupArgument,
    LookupSide,
    TraceTable,
    cell,
    const,
    evaluate_program,
)
from experiments.fixed_shape_claim_air.master_inputs_adapter import (
    build_master_commitment_inputs_v2,
)
from experiments.fixed_shape_claim_air.master_public_composition import (
    build_master_public_composition,
)
from experiments.fixed_shape_claim_air.packed_execution_commitment_executable_air import (
    build_oracle_execution_commitment_executable_air,
    build_policy_execution_commitment_executable_air,
)
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.replay_ordered_map_executable_air import (
    build_replay_ordered_map_executable_air,
)
from experiments.fixed_shape_claim_air.ruleset_commitment_executable_air import (
    build_ruleset_commitment_executable_air,
)
from experiments.fixed_shape_claim_air.salt_use_tag_executable_air import (
    build_salt_use_tag_executable_air,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError
from experiments.fixed_shape_claim_air.semantics import SlotKind
from experiments.fixed_shape_claim_air.wave1a_global_sha3_capacity_schedule import (
    build_wave1a_global_sha3_capacity_schedule,
)
from tests.test_wave1a_authenticated_payment_maps_reference import FLAGS
from tests.test_wave1a_payment_log_cross_language import _transition


_GLOBAL_LINK_NAMES = (
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


def _component(name: str, value: int) -> SimpleNamespace:
    sha3 = build_application_sha3_interface_air(
        (Sha3Call(f"test_{name}", bytes((value,)), 1),)
    )
    table = AirTable(f"{name}_private", ("value",), 1, ())
    trace = TraceTable(table.name, {"value": (value,)})
    return SimpleNamespace(
        program=AirProgram(
            f"test-{name}",
            (*sha3.program.tables, table),
            sha3.program.lookups,
        ),
        traces={**sha3.traces, table.name: trace},
        sha3=sha3,
        private_table=table.name,
    )


def _inputs(monkeypatch: pytest.MonkeyPatch):
    for class_name in (
        "ClaimTruthGlobalAirInstance",
        "ClaimSourceClaimAirInstance",
        "A12NullifierAirInstance",
        "SaltUseTagAirInstance",
        "ReplayOrderedMapAirInstance",
        "ClaimPaymentMapsAirInstance",
        "MasterPublicAirInstance",
    ):
        monkeypatch.setattr(global_air, class_name, SimpleNamespace)

    parts = tuple(
        _component(name, value)
        for value, name in enumerate(
            ("truth", "a12", "salt", "replay", "payment", "master"),
            start=1,
        )
    )
    source_table = AirTable("test_source_claim", ("value",), 1, ())
    source_trace = TraceTable(source_table.name, {"value": (99,)})
    source_claim = SimpleNamespace(
        program=AirProgram("test-source-claim", (source_table,)),
        traces={source_table.name: source_trace},
    )

    truth_side = LookupSide(
        parts[0].private_table,
        const(1),
        (cell("value"),),
        0,
        1,
    )
    message_side = LookupSide(
        "sha3_message_batch",
        const(1),
        (cell("value"),),
        0,
        1,
    )
    source_side = LookupSide(
        source_table.name,
        const(1),
        (cell("value"),),
        0,
        1,
    )
    links = (
        LookupArgument(_GLOBAL_LINK_NAMES[0], (truth_side,), (message_side,)),
        *(
            LookupArgument(name, (source_side,), (source_side,))
            for name in _GLOBAL_LINK_NAMES[1:]
        ),
    )
    monkeypatch.setattr(global_air, "_global_links", lambda *_: links)
    monkeypatch.setattr(
        global_air,
        "build_wave1a_global_sha3_capacity_schedule",
        lambda _: SimpleNamespace(capacities=(1, 1, 1, 1, 1, 1)),
    )

    claim_truth = SimpleNamespace(
        composed=parts[0],
        all_truth_roots_constrained=False,
        truth_root_ports_constrained=True,
    )
    a12 = SimpleNamespace(
        program=parts[1].program,
        traces=parts[1].traces,
        sha3=parts[1].sha3,
        nullifier_hashes_constrained=False,
        hash_ports_constrained=True,
    )
    salt_use = SimpleNamespace(
        program=parts[2].program,
        traces=parts[2].traces,
        sha3=parts[2].sha3,
        call_index_offset=2,
        tag_constrained=False,
        hash_ports_constrained=True,
    )
    replay = SimpleNamespace(
        program=parts[3].program,
        traces=parts[3].traces,
        application_sha3=parts[3].sha3,
        call_index_offset=3,
        hashes_constrained=False,
        hash_ports_constrained=True,
    )
    payment = SimpleNamespace(
        program=parts[4].program,
        traces=parts[4].traces,
        application_sha3=parts[4].sha3,
        call_index_offset=4,
        key_derivations_constrained=False,
        key_derivation_ports_constrained=True,
        operation_log_constrained=False,
        operation_log_ports_constrained=True,
        payment_map_hashes_constrained=False,
        payment_map_hash_ports_constrained=True,
    )
    master = SimpleNamespace(
        sha3=parts[5].sha3,
        call_index_offset=5,
        master_hashes_constrained=False,
        hash_ports_constrained=True,
    )
    master_public = SimpleNamespace(
        program=parts[5].program,
        traces=parts[5].traces,
        master=master,
    )
    return (
        get_profile("K128_CALIBRATION"),
        claim_truth,
        source_claim,
        a12,
        salt_use,
        replay,
        payment,
        master_public,
        parts,
        links,
    )


def test_wave1a_global_semantic_bus_witness_matches_program_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, *values, parts, links = _inputs(monkeypatch)
    instance = global_air.build_wave1a_global_semantic_bus_executable_air(
        profile, *values
    )
    fragments = tuple(
        Sha3ProgramFragment(
            part.program,
            tuple(call.capacity for call in part.sha3.calls),
            index,
        )
        for index, part in enumerate(parts)
    )
    expected = global_air.build_wave1a_global_semantic_bus_program_only(
        profile,
        fragments,
        values[1].program,
        links,
    )

    assert instance.program.canonical_bytes() == expected.canonical_bytes()
    assert tuple(call.call_id for call in instance.sha3.calls) == tuple(
        f"test_{name}"
        for name in ("truth", "a12", "salt", "replay", "payment", "master")
    )
    assert tuple(call.capacity for call in instance.sha3.calls) == (1,) * 6
    assert set(instance.traces) == {table.name for table in instance.program.tables}
    assert {
        "sha3_message_batch",
        "sha3_digest_batch",
        "sha3_digest_byte_batch",
    }.issubset(instance.traces)
    assert {
        "sha3_boolean_round",
        "sha3_boolean_absorb",
        "sha3_boolean_digest",
    }.isdisjoint(instance.traces)
    evaluate_program(instance.program, instance.traces)


def test_wave1a_global_semantic_bus_rejects_mutation_and_schedule_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, *values, parts, _ = _inputs(monkeypatch)
    instance = global_air.build_wave1a_global_semantic_bus_executable_air(
        profile, *values
    )
    mutated = dict(instance.traces)
    private_name = parts[0].private_table
    mutated[private_name] = TraceTable(private_name, {"value": (2,)})
    with pytest.raises(
        StructuralError,
        match="air_lookup_multiset_mismatch:wave1a_master_truth_links",
    ):
        evaluate_program(instance.program, mutated)

    monkeypatch.setattr(
        global_air,
        "build_wave1a_global_sha3_capacity_schedule",
        lambda _: SimpleNamespace(capacities=(2, 1, 1, 1, 1, 1)),
    )
    with pytest.raises(
        StructuralError,
        match="wave1a_global_program_sha3_schedule_mismatch",
    ):
        global_air.build_wave1a_global_semantic_bus_executable_air(profile, *values)


def test_wave1a_global_semantic_bus_real_k128_witness_is_complete() -> None:
    profile = get_profile("K128_CALIBRATION")
    capacity_schedule = build_wave1a_global_sha3_capacity_schedule(profile)
    segment_runs = {
        component: tuple(
            run for run in capacity_schedule.runs if run.component == component
        )
        for component in (
            "claim_truth",
            "a12_nullifier",
            "salt_use",
            "replay_map",
            "payment",
            "master",
        )
    }
    offsets: dict[str, int] = {}
    cursor = 0
    for component, runs in segment_runs.items():
        offsets[component] = cursor
        cursor += sum(run.count for run in runs)
    assert cursor == capacity_schedule.total_calls == 46_858

    with mock.patch.dict(os.environ, FLAGS, clear=False):
        slots, _, payment_transition = _transition()
        source = build_claim_source_commitment_executable_air(
            profile,
            slots,
            call_index_offset=offsets["claim_truth"],
            interface_only=True,
        )
        oracle_offset = offsets["claim_truth"] + len(source.sha3.calls)
        oracle = build_oracle_execution_commitment_executable_air(
            profile,
            slots,
            call_index_offset=oracle_offset,
            interface_only=True,
        )
        policy_offset = oracle_offset + len(oracle.sha3.calls)
        policy = build_policy_execution_commitment_executable_air(
            profile,
            slots,
            call_index_offset=policy_offset,
            interface_only=True,
        )
        ruleset_offset = policy_offset + len(policy.sha3.calls)
        ruleset = build_ruleset_commitment_executable_air(
            profile,
            call_index_offset=ruleset_offset,
            interface_only=True,
        )

        def wide(trace: TraceTable, prefix: str) -> bytes:
            return bytes(
                trace.columns[f"{prefix}_{index}"][0] for index in range(64)
            )

        roots = ClaimTruthRootsV1(
            wide(source.traces["claim_source_hash_root"], "value"),
            wide(oracle.traces["oracle_execution_root"], "execution"),
            wide(oracle.traces["oracle_execution_root"], "audit"),
            wide(policy.traces["policy_execution_root"], "execution"),
            wide(policy.traces["policy_execution_root"], "audit"),
            ruleset.root,
        )
        ml = MlDsa87PqcryptoAdapter()
        slh = SphincsShake256fSimplePqcryptoAdapter()
        ml_public, ml_secret = ml.generate_keypair()
        slh_public, slh_secret = slh.generate_keypair()
        registry = ClaimTruthAuthorityRegistryV1(
            profile.profile_id,
            "BL-SYNTH-GOV-INTAKE-V1",
            payment_transition.before.epoch,
            sha3_512(b"BL-WAVE1A-SEMANTIC-BUS-K128").digest(),
            ml_public,
            slh_public,
        )
        envelope = sign_claim_truth_roots(
            registry,
            roots,
            ml_adapter=ml,
            ml_secret_key=ml_secret,
            slh_adapter=slh,
            slh_secret_key=slh_secret,
        )
        authority = build_claim_truth_authority_executable_air(
            registry,
            envelope,
            ml_adapter=ml,
            slh_adapter=slh,
            call_index_offset=ruleset_offset + len(ruleset.sha3.calls),
            interface_only=True,
        )
        claim_truth = build_claim_truth_global_executable_air(
            source,
            oracle,
            policy,
            ruleset,
            authority,
        )

        domain = payment_transition.before.strong_settlement_domain_id_512
        batch_nonce = sha3_512(b"BL-WAVE1A-SEMANTIC-BUS-K128-NONCE").digest()
        nullifier_authority = NullifierDerivationAuthorityV1.from_secret(
            sha3_512(b"BL-WAVE1A-SEMANTIC-BUS-K128-AUTHORITY").digest(),
            sha3_512(b"BL-WAVE1A-SEMANTIC-BUS-K128-PEPPER").digest(),
        )
        requests = tuple(
            AttemptNullifierAirRequest(
                f"slot-{slot.slot_index}",
                AttemptReplayIdentityV1(
                    slot.source_authority_id,
                    slot.claim_id,
                    slot.attempt_version,
                    REVISION_KIND_ORIGINAL,
                    slot.parent_attempt_version,
                ),
            )
            if slot.slot_kind is SlotKind.REAL
            else CoverNullifierAirRequest(
                f"slot-{slot.slot_index}",
                CoverReplayContextV2(
                    profile.profile_id,
                    domain,
                    payment_transition.before.epoch,
                    batch_nonce,
                    slot.slot_index,
                ),
                sha3_512(
                    b"BL-WAVE1A-SEMANTIC-BUS-K128-COVER"
                    + slot.slot_index.to_bytes(2, "big")
                ).digest(),
            )
            for slot in slots
        )
        a12 = build_a12_nullifier_executable_air(
            requests,
            nullifier_authority,
            interface_only=True,
        )
        salt_use = build_salt_use_tag_executable_air(
            sha3_512(b"BL-WAVE1A-SEMANTIC-BUS-K128-SALT").digest(),
            call_index_offset=offsets["salt_use"],
            interface_only=True,
        )
        replay = build_replay_ordered_map_executable_air(
            (),
            (*a12.strong_nullifiers, salt_use.tag_512),
            compose_sha3=True,
            call_index_offset=offsets["replay_map"],
            interface_only=True,
        )
        payment = build_claim_payment_maps_executable_air(
            slots,
            payment_transition,
            compose_operation_log_sha3=True,
            compose_key_sha3=True,
            compose_map_sha3=True,
            interface_only=True,
            call_index_offset=offsets["payment"],
        )
        master_inputs = build_master_commitment_inputs_v2(
            profile,
            slots,
            authority,
            a12,
            salt_use,
            replay,
            payment_transition,
            epoch=payment_transition.before.epoch,
            strong_settlement_domain_id_512=domain,
            strong_batch_nonce_512=batch_nonce,
        )
        master_public = build_master_public_composition(
            master_inputs,
            call_index_offset=offsets["master"],
            interface_only=True,
        )
        source_claim = build_claim_source_claim_executable_air(profile, slots)

        instance = global_air.build_wave1a_global_semantic_bus_executable_air(
            profile,
            claim_truth,
            source_claim,
            a12,
            salt_use,
            replay,
            payment,
            master_public,
        )

    fragments = (
        Sha3ProgramFragment(
            claim_truth.composed.program,
            tuple(call.capacity for call in claim_truth.composed.sha3.calls),
            offsets["claim_truth"],
        ),
        Sha3ProgramFragment(
            a12.program,
            tuple(call.capacity for call in a12.sha3.calls),
            offsets["a12_nullifier"],
        ),
        Sha3ProgramFragment(
            salt_use.program,
            tuple(call.capacity for call in salt_use.sha3.calls),
            offsets["salt_use"],
        ),
        Sha3ProgramFragment(
            replay.program,
            tuple(call.capacity for call in replay.application_sha3.calls),
            offsets["replay_map"],
        ),
        Sha3ProgramFragment(
            payment.program,
            tuple(call.capacity for call in payment.application_sha3.calls),
            offsets["payment"],
        ),
        Sha3ProgramFragment(
            master_public.program,
            tuple(call.capacity for call in master_public.master.sha3.calls),
            offsets["master"],
        ),
    )
    expected = global_air.build_wave1a_global_semantic_bus_program_only(
        profile,
        fragments,
        source_claim.program,
        instance.global_links,
    )
    assert instance.program.canonical_bytes() == expected.canonical_bytes()
    assert tuple(call.capacity for call in instance.sha3.calls) == (
        capacity_schedule.capacities
    )
    public_inputs = tuple(
        instance.traces[binding.table].columns[binding.column][binding.row]
        for binding in instance.program.public_inputs
    )
    evaluate_program(instance.program, instance.traces, public_inputs)
