from __future__ import annotations

import gc
from hashlib import sha3_512
import os
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

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
from experiments.bl_pq512_crypto_foundation.selected_proof_parameters import (
    derive_selected_proof_geometry,
)
from experiments.fixed_shape_claim_air.a12_nullifier_executable_air import (
    AttemptNullifierAirRequest,
    CoverNullifierAirRequest,
    build_a12_nullifier_executable_air,
)
from experiments.fixed_shape_claim_air.authenticated_payment_maps_reference import (
    build_authenticated_payment_map_transition,
)
from experiments.fixed_shape_claim_air.application_sha3_executable_air import Sha3Call
from experiments.fixed_shape_claim_air.air_binary_ir import encode_air_program
from experiments.fixed_shape_claim_air.air_composition import Sha3ProgramFragment
from experiments.fixed_shape_claim_air.claim_payment_maps_executable_air import (
    build_claim_payment_maps_executable_air,
    build_claim_payment_maps_sha3_interface_program,
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
from experiments.fixed_shape_claim_air.master_inputs_adapter import (
    build_master_commitment_inputs_v2,
)
from experiments.fixed_shape_claim_air.master_public_composition import (
    build_master_public_composition,
)
from experiments.fixed_shape_claim_air.hash_bus_snapshot import (
    encode_hash_bus_snapshot,
)
from experiments.fixed_shape_claim_air.packed_execution_commitment_executable_air import (
    build_oracle_execution_commitment_executable_air,
    build_policy_execution_commitment_executable_air,
)
from experiments.fixed_shape_claim_air.payment import derive_batch_economics
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.replay_ordered_map_executable_air import (
    build_replay_ordered_map_executable_air,
    build_replay_ordered_map_sha3_interface_program,
)
from experiments.fixed_shape_claim_air.ruleset_commitment_executable_air import (
    build_ruleset_commitment_executable_air,
)
from experiments.fixed_shape_claim_air.salt_use_tag_executable_air import (
    build_salt_use_tag_executable_air,
)
from experiments.fixed_shape_claim_air.semantics import SlotKind
from experiments.fixed_shape_claim_air.wave1a_global_executable_air import (
    _global_links,
    build_wave1a_global_program_only,
    build_wave1a_global_semantic_bus_program_only,
)
from experiments.fixed_shape_claim_air.wave1a_global_sha3_capacity_schedule import (
    build_wave1a_global_sha3_capacity_schedule,
)
from tests.test_wave1a_authenticated_payment_maps_reference import FLAGS, _slots, _state
from tests.test_wave1a_payment_log_cross_language import _transition


def _wide(trace, prefix: str) -> bytes:
    return bytes(trace.columns[f"{prefix}_{index}"][0] for index in range(64))


def test_k128_complete_wave1a_verifier_program_is_physically_assembled() -> None:
    fixture_profile = os.environ.get("BL_H4_FIXTURE_PROFILE", "K128_CALIBRATION")
    assert fixture_profile in {"K128_CALIBRATION", "K512_CALIBRATION"}
    profile = get_profile(fixture_profile)
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
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        if fixture_profile == "K128_CALIBRATION":
            slots, _, payment_transition = _transition()
        else:
            slots = _slots(profile)
            economics = derive_batch_economics(profile, slots)
            payment_transition = build_authenticated_payment_map_transition(
                profile,
                slots,
                economics,
                _state(profile),
            )
        offsets = {}
        cursor = 0
        for component, runs in segment_runs.items():
            offsets[component] = cursor
            cursor += sum(run.count for run in runs)

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
        roots = ClaimTruthRootsV1(
            _wide(source.traces["claim_source_hash_root"], "value"),
            _wide(oracle.traces["oracle_execution_root"], "execution"),
            _wide(oracle.traces["oracle_execution_root"], "audit"),
            _wide(policy.traces["policy_execution_root"], "execution"),
            _wide(policy.traces["policy_execution_root"], "audit"),
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
            sha3_512(b"BL-WAVE1A-PROGRAM-ONLY-SNAPSHOT").digest(),
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
            source, oracle, policy, ruleset, authority
        )
        truth_fragment = Sha3ProgramFragment(
            claim_truth.composed.program,
            tuple(call.capacity for call in claim_truth.composed.sha3.calls),
            offsets["claim_truth"],
        )
        truth_calls = claim_truth.composed.sha3.calls
        del source, oracle, policy, ruleset, claim_truth
        gc.collect()

        domain = payment_transition.before.strong_settlement_domain_id_512
        batch_nonce = sha3_512(b"BL-WAVE1A-PROGRAM-ONLY-BATCH-NONCE").digest()
        nullifier_authority = NullifierDerivationAuthorityV1.from_secret(
            sha3_512(b"BL-WAVE1A-PROGRAM-ONLY-NULLIFIER-AUTHORITY").digest(),
            sha3_512(b"BL-WAVE1A-PROGRAM-ONLY-PEPPER").digest(),
        )
        requests = []
        for slot in slots:
            if slot.slot_kind is SlotKind.REAL:
                requests.append(
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
                )
            else:
                requests.append(
                    CoverNullifierAirRequest(
                        f"slot-{slot.slot_index}",
                        CoverReplayContextV2(
                            profile.profile_id,
                            domain,
                            payment_transition.before.epoch,
                            batch_nonce,
                            slot.slot_index,
                        ),
                        sha3_512(
                            b"BL-WAVE1A-PROGRAM-ONLY-COVER-NONCE"
                            + slot.slot_index.to_bytes(2, "big")
                        ).digest(),
                    )
                )
        a12 = build_a12_nullifier_executable_air(
            tuple(requests),
            nullifier_authority,
            interface_only=True,
        )
        a12_fragment = Sha3ProgramFragment(
            a12.program,
            tuple(call.capacity for call in a12.sha3.calls),
            offsets["a12_nullifier"],
        )
        a12_calls = a12.sha3.calls
        salt = build_salt_use_tag_executable_air(
            sha3_512(b"BL-WAVE1A-PROGRAM-ONLY-MASTER-SALT").digest(),
            call_index_offset=offsets["salt_use"],
            interface_only=True,
        )
        salt_fragment = Sha3ProgramFragment(
            salt.program,
            tuple(call.capacity for call in salt.sha3.calls),
            offsets["salt_use"],
        )
        salt_calls = salt.sha3.calls
        replay = build_replay_ordered_map_executable_air(
            (), (*a12.strong_nullifiers, salt.tag_512)
        )
        replay_program, replay_capacities = (
            build_replay_ordered_map_sha3_interface_program(
                replay,
                call_index_offset=offsets["replay_map"],
            )
        )
        replay_fragment = Sha3ProgramFragment(
            replay_program, replay_capacities, offsets["replay_map"]
        )
        replay_calls = tuple(
            Sha3Call(
                f"snapshot_replay_{index}",
                call.message,
                len(call.message),
            )
            for index, call in enumerate(replay.ordered_map.hash_calls)
        )

        master_inputs = build_master_commitment_inputs_v2(
            profile,
            slots,
            authority,
            a12,
            salt,
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
        master_fragment = Sha3ProgramFragment(
            master_public.program,
            tuple(call.capacity for call in master_public.master.sha3.calls),
            offsets["master"],
        )
        master_calls = master_public.master.sha3.calls
        a12_link = SimpleNamespace(
            traces={"a12_request": a12.traces["a12_request"]},
            operation_ids=a12.operation_ids,
        )
        del replay, authority
        gc.collect()

        payment_runs = segment_runs["payment"]
        map_call_count = sum(run.count for run in payment_runs[:-3])
        payment = build_claim_payment_maps_executable_air(
            slots,
            payment_transition,
            compose_operation_log_sha3=True,
            compose_key_sha3=True,
            interface_only=True,
            sha3_call_prefix=map_call_count,
            call_index_offset=offsets["payment"],
        )
        payment_program, payment_capacities = (
            build_claim_payment_maps_sha3_interface_program(payment)
        )
        payment_fragment = Sha3ProgramFragment(
            payment_program, payment_capacities, offsets["payment"]
        )
        payment_calls = (
            tuple(
                Sha3Call(
                    f"snapshot_payment_map_{lane}_{index}",
                    call.message,
                    len(call.message),
                )
                for lane in ("benefit", "obligation", "ledger")
                for index, call in enumerate(payment.payment_maps.hash_calls[lane])
            )
            + payment.application_sha3.calls
        )
        payment_link = SimpleNamespace(
            traces={
                "claim_payment_key_material": payment.traces[
                    "claim_payment_key_material"
                ]
            }
        )
        del payment
        gc.collect()

        source_claim = build_claim_source_claim_executable_air(profile, slots)
        source_claim_program = source_claim.program
        del source_claim
        gc.collect()
        links = _global_links(
            SimpleNamespace(),
            a12_link,
            SimpleNamespace(),
            SimpleNamespace(),
            payment_link,
            master_public,
        )
        program = (
            build_wave1a_global_program_only(
                profile,
                (
                    truth_fragment,
                    a12_fragment,
                    salt_fragment,
                    replay_fragment,
                    payment_fragment,
                    master_fragment,
                ),
                source_claim_program,
                links,
            )
            if fixture_profile == "K128_CALIBRATION"
            else None
        )
        semantic_bus_program = build_wave1a_global_semantic_bus_program_only(
            profile,
            (
                truth_fragment,
                a12_fragment,
                salt_fragment,
                replay_fragment,
                payment_fragment,
                master_fragment,
            ),
            source_claim_program,
            links,
        )

    if fixture_profile == "K128_CALIBRATION":
        assert program is not None
        names = tuple(table.name for table in program.tables)
        assert names.count("sha3_boolean_round") == 1
        assert names.count("sha3_boolean_absorb") == 1
        assert names.count("sha3_boolean_digest") == 1
        assert {
            "sha3_round_batch",
            "sha3_truth_shared",
            "sha3_byte_range_shared",
        }.isdisjoint(names)
        assert program.maximum_degree == 11
        geometry = derive_selected_proof_geometry(program)
        assert geometry.maximum_evaluation_log_size == 26
        assert geometry.fold_round_count == 25
        assert geometry.minimum_term_soundness_bits >= 256
        encoded = encode_air_program(program)
        assert len(encoded) > 11_942_817
        assert len(program.commitment()) == 64

    semantic_bus_names = tuple(table.name for table in semantic_bus_program.tables)
    assert {
        "sha3_message_batch",
        "sha3_digest_batch",
        "sha3_digest_byte_batch",
    }.issubset(semantic_bus_names)
    assert {
        "sha3_boolean_round",
        "sha3_boolean_absorb",
        "sha3_boolean_digest",
    }.isdisjoint(semantic_bus_names)
    if program is not None:
        assert semantic_bus_program.maximum_degree < program.maximum_degree
        assert semantic_bus_program.commitment() != program.commitment()
    semantic_snapshot = encode_hash_bus_snapshot(
        profile,
        semantic_bus_program.commitment(),
        (
            *truth_calls,
            *a12_calls,
            *salt_calls,
            *replay_calls,
            *payment_calls,
            *master_calls,
        ),
    )
    assert len(semantic_snapshot) < 100_000_000
    assert semantic_snapshot[:8] == b"BLHBSN01"
    snapshot_output = os.environ.get("BL_H4_SNAPSHOT_OUT")
    if snapshot_output is not None:
        output_path = Path(snapshot_output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("xb") as output:
            output.write(semantic_snapshot)
