from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import os
from unittest import mock

import pytest

from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    encode_authorization_token,
)
from experiments.fixed_shape_claim_air.authenticated_payment_maps_reference import (
    BENEFIT_MAP_DOMAIN,
    LEDGER_MAP_DOMAIN,
    OBLIGATION_MAP_DOMAIN,
    BenefitAccumulatorRecord,
    BenefitScopeV1,
    SPARSE_MAP_DEPTH,
    build_authenticated_payment_map_transition,
    build_payment_map_state,
    member_benefit_key,
    member_benefit_key_preimage,
    payer_reserve_key_preimage,
    payment_dummy_key_preimage,
    payment_operation_preimage,
    payer_reserve_key,
    provider_payable_key,
    provider_obligation_key_preimage,
    provider_payable_key_preimage,
    verify_authenticated_payment_map_transition,
)
from experiments.fixed_shape_claim_air.payment import derive_batch_economics
from experiments.fixed_shape_claim_air.ordered_map_batch_reference import (
    build_ordered_map_batch_schedule,
    ordered_map_batch_schedule_commitment,
    require_ordered_map_batch_fits_schedule,
)
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.test_wave1a_relation_reference import _cover, _real


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


@pytest.fixture
def profile():
    return get_profile("K128_CALIBRATION")


def _benefit_scope(
    *,
    payer_authority_id: str = "SYNTH-PAYER-001",
    plan_id: str = "SYNTH-PLAN-001",
    start_day: int = 20_000,
    end_day: int = 20_365,
) -> BenefitScopeV1:
    return BenefitScopeV1(
        payer_authority_id=payer_authority_id,
        plan_id=plan_id,
        benefit_period_start_day=start_day,
        benefit_period_end_day=end_day,
    )


def _read(entries, key: bytes) -> bytes | None:
    return dict((entry.key_512, entry.value) for entry in entries).get(key)


def _state(
    profile, *, reserve: int = 1_000, benefit_scope: BenefitScopeV1 | None = None
):
    if benefit_scope is None:
        benefit_scope = _benefit_scope()
    return build_payment_map_state(
        epoch=7,
        sequence=11,
        strong_settlement_domain_id_512=sha3_512(b"PAYMENT-MAP-DOMAIN").digest(),
        benefit_scope=benefit_scope,
        payer_reserve_cents=reserve,
        operation_log_root_512=sha3_512(b"PAYMENT-MAP-LOG").digest(),
    )


def _slots(profile):
    return (
        _real(0, approved=True),
        _real(1, approved=False),
        *(_cover(index) for index in range(2, profile.claim_slots)),
    )


def test_payment_rank_key_layouts_are_exact_and_source_reusable(profile) -> None:
    slot = _slots(profile)[0]
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        state = _state(profile)
    domain = b"BL/PQ512/PAYMENT-MAP/RANK-KEY/v2"
    scope = state.benefit_scope.commitment_512()
    authority_rank = encode_authorization_token(slot.source_authority_id)
    claim_rank = encode_authorization_token(slot.claim_id)
    member_rank = encode_authorization_token(slot.member_id)

    benefit = member_benefit_key_preimage(
        slot.member_id, benefit_scope=state.benefit_scope
    )
    obligation = provider_obligation_key_preimage(slot)
    reserve = payer_reserve_key_preimage()
    payable = provider_payable_key_preimage(slot.provider_npi)
    dummy = payment_dummy_key_preimage(
        b"BENEFIT",
        state.strong_settlement_domain_id_512,
        state.epoch,
        scope,
    )

    assert benefit == domain + b"\x01" + scope + member_rank
    assert obligation == (
        domain
        + b"\x02"
        + authority_rank
        + claim_rank
        + slot.attempt_version.to_bytes(4, "big")
        + b"\x01"
        + slot.parent_attempt_version.to_bytes(4, "big")
        + slot.provider_npi.encode("ascii")
    )
    assert reserve == domain + b"\x03"
    assert payable == domain + b"\x04" + slot.provider_npi.encode("ascii")
    assert dummy == (
        domain
        + b"\x11"
        + state.strong_settlement_domain_id_512
        + state.epoch.to_bytes(8, "big")
        + scope
    )
    assert tuple(map(len, (benefit, obligation, reserve, payable, dummy))) == (
        139,
        136,
        33,
        43,
        169,
    )


@pytest.mark.parametrize("invalid_balances", ([], "", 0, False))
def test_initial_provider_balances_reject_falsey_non_mappings(
    profile, invalid_balances
) -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        with pytest.raises(
            StructuralError, match="wave1a_payment_map_provider_balances_not_mapping"
        ):
            build_payment_map_state(
                epoch=7,
                sequence=11,
                strong_settlement_domain_id_512=sha3_512(
                    b"PAYMENT-MAP-DOMAIN"
                ).digest(),
                benefit_scope=_benefit_scope(),
                payer_reserve_cents=1_000,
                operation_log_root_512=sha3_512(b"PAYMENT-MAP-LOG").digest(),
                provider_payable_balances=invalid_balances,
            )


def test_benefit_scope_is_typed_committed_and_cannot_drift(profile) -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        original = _benefit_scope()
        other_payer = _benefit_scope(payer_authority_id="SYNTH-PAYER-002")
        other_plan = _benefit_scope(plan_id="SYNTH-PLAN-002")
        other_period = _benefit_scope(start_day=20_366, end_day=20_730)
        assert len(
            {
                original.commitment_512(),
                other_payer.commitment_512(),
                other_plan.commitment_512(),
                other_period.commitment_512(),
            }
        ) == 4
        assert len(
            {
                member_benefit_key(
                    "SYNTH-MEMBER-001", benefit_scope=original
                ),
                member_benefit_key(
                    "SYNTH-MEMBER-001", benefit_scope=other_payer
                ),
                member_benefit_key(
                    "SYNTH-MEMBER-001", benefit_scope=other_plan
                ),
                member_benefit_key(
                    "SYNTH-MEMBER-001", benefit_scope=other_period
                ),
            }
        ) == 4
        assert _state(profile, benefit_scope=original).root() != _state(
            profile, benefit_scope=other_plan
        ).root()

        slots = _slots(profile)
        economics = derive_batch_economics(profile, slots)
        transition = build_authenticated_payment_map_transition(
            profile, slots, economics, _state(profile, benefit_scope=original)
        )
        assert transition.after.benefit_scope == original
        with pytest.raises(StructuralError, match="dummy_leaf_invalid"):
            replace(
                transition,
                after=replace(transition.after, benefit_scope=other_plan),
            )


def test_operation_log_commits_map_operations_not_redundant_intermediate_roots(
    profile,
) -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        slots = _slots(profile)
        economics = derive_batch_economics(profile, slots)
        transition = build_authenticated_payment_map_transition(
            profile, slots, economics, _state(profile)
        )
        payment = transition.transitions[0]
        message = payment_operation_preimage(
            0,
            payment.witness_class,
            economics.slots[0],
            payment.upserts,
        )
        for upsert in payment.upserts:
            assert upsert.key_512 in message
            assert upsert.value_before_512 in message
            assert upsert.value_after_512 in message
            assert upsert.root_before not in message
            assert upsert.root_after not in message


def test_payment_key_preimages_hash_to_all_economic_and_dummy_keys(profile) -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        slots = _slots(profile)
        economics = derive_batch_economics(profile, slots)
        transition = build_authenticated_payment_map_transition(
            profile, slots, economics, _state(profile)
        )
        approved = transition.transitions[0]
        assert sha3_512(
            member_benefit_key_preimage(
                slots[0].member_id,
                benefit_scope=transition.before.benefit_scope,
            )
        ).digest() == approved.benefit_key_512
        assert sha3_512(provider_obligation_key_preimage(slots[0])).digest() == (
            approved.obligation_key_512
        )
        assert sha3_512(payer_reserve_key_preimage()).digest() == (
            approved.reserve_key_512
        )
        assert sha3_512(provider_payable_key_preimage(slots[0].provider_npi)).digest() == (
            approved.payable_key_512
        )

        non_economic = transition.transitions[1]
        scope = transition.before.benefit_scope.commitment_512()
        for lane, observed in zip(
            (b"BENEFIT", b"OBLIGATION", b"RESERVE", b"PAYABLE"),
            (
                non_economic.benefit_key_512,
                non_economic.obligation_key_512,
                non_economic.reserve_key_512,
                non_economic.payable_key_512,
            ),
            strict=True,
        ):
            assert sha3_512(
                payment_dummy_key_preimage(
                    lane,
                    transition.before.strong_settlement_domain_id_512,
                    transition.before.epoch,
                    scope,
                )
            ).digest() == observed


def test_benefit_scope_rejects_reversed_period_and_valid_mapping_survives(
    profile,
) -> None:
    class ForgedBenefitScope(BenefitScopeV1):
        def commitment_512(self) -> bytes:
            return bytes([0xA5]) * 64

    with pytest.raises(StructuralError, match="benefit_scope_period_invalid"):
        _benefit_scope(start_day=20_365, end_day=20_000)
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        with pytest.raises(StructuralError, match="benefit_scope_required"):
            build_payment_map_state(
                epoch=7,
                sequence=11,
                strong_settlement_domain_id_512=sha3_512(
                    b"PAYMENT-MAP-DOMAIN"
                ).digest(),
                benefit_scope=False,  # type: ignore[arg-type]
                payer_reserve_cents=1_000,
                operation_log_root_512=sha3_512(b"PAYMENT-MAP-LOG").digest(),
            )
        forged_scope = ForgedBenefitScope("PAYER", "PLAN", 20_000, 20_365)
        with pytest.raises(StructuralError, match="benefit_scope_required"):
            member_benefit_key(
                "SYNTH-MEMBER-001",
                benefit_scope=forged_scope,
            )
        with pytest.raises(StructuralError, match="benefit_scope_required"):
            build_payment_map_state(
                epoch=7,
                sequence=11,
                strong_settlement_domain_id_512=sha3_512(
                    b"PAYMENT-MAP-DOMAIN"
                ).digest(),
                benefit_scope=forged_scope,
                payer_reserve_cents=1_000,
                operation_log_root_512=sha3_512(b"PAYMENT-MAP-LOG").digest(),
            )
        state = build_payment_map_state(
            epoch=7,
            sequence=11,
            strong_settlement_domain_id_512=sha3_512(
                b"PAYMENT-MAP-DOMAIN"
            ).digest(),
            benefit_scope=_benefit_scope(),
            payer_reserve_cents=1_000,
            operation_log_root_512=sha3_512(b"PAYMENT-MAP-LOG").digest(),
            provider_payable_balances={"1999999984": 17},
        )
        assert int.from_bytes(
            _read(state.ledger_entries, provider_payable_key("1999999984"))
            or b"",
            "big",
        ) == 17


def test_full_width_maps_update_economics_without_persistent_dummy_bloat(
    profile,
) -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        slots = _slots(profile)
        economics = derive_batch_economics(profile, slots)
        transition = build_authenticated_payment_map_transition(
            profile, slots, economics, _state(profile)
        )
        assert verify_authenticated_payment_map_transition(
            profile, slots, economics, transition
        )
        assert SPARSE_MAP_DEPTH == 64
        assert len(transition.transitions) == profile.claim_slots
        assert transition.transitions[0].witness_class == "approval"
        assert transition.transitions[1].witness_class == "denial"
        assert transition.transitions[2].witness_class == "cover"
        assert transition.transitions[0].benefit_root_before_512 != (
            transition.transitions[0].benefit_root_after_512
        )
        for nonapproval in transition.transitions[1:]:
            assert nonapproval.benefit_root_before_512 == nonapproval.benefit_root_after_512
            assert nonapproval.obligation_root_before_512 == nonapproval.obligation_root_after_512
            assert nonapproval.ledger_root_before_512 == nonapproval.ledger_root_after_512
            assert nonapproval.operation_log_root_before_512 != (
                nonapproval.operation_log_root_after_512
            )
            assert all(
                witness.mode == "update"
                and witness.value_before_512 == witness.value_after_512 == bytes(64)
                and len(witness.target_path) == len(witness.allocated_path) == 64
                for witness in nonapproval.upserts
            )

        assert transition.before.benefit_snapshot.next_append_index == 3
        assert transition.after.benefit_snapshot.next_append_index == 4
        assert transition.before.obligation_snapshot.next_append_index == 3
        assert transition.after.obligation_snapshot.next_append_index == 4
        assert transition.before.ledger_snapshot.next_append_index == 5
        assert transition.after.ledger_snapshot.next_append_index == 6
        assert transition.inner_node_hash_count == 404
        assert transition.inner_node_hash_count < 128 * 4 * 4 * 64 // 90
        assert tuple(
            (
                len(witness.operations),
                len(witness.positions),
                len(witness.proof_nodes),
                witness.inner_node_hash_count,
            )
            for witness in (
                transition.benefit_batch_witness,
                transition.obligation_batch_witness,
                transition.ledger_batch_witness,
            )
        ) == (
            (128, 3, 64, 132),
            (128, 3, 64, 132),
            (256, 5, 63, 134),
        )
        schedules = (
            build_ordered_map_batch_schedule(128),
            build_ordered_map_batch_schedule(128),
            build_ordered_map_batch_schedule(256),
        )
        for witness, schedule in zip(
            (
                transition.benefit_batch_witness,
                transition.obligation_batch_witness,
                transition.ledger_batch_witness,
            ),
            schedules,
            strict=True,
        ):
            require_ordered_map_batch_fits_schedule(witness, schedule)
        assert sum(value.node_hash_rows for value in schedules) == 34_026
        assert sum(value.leaf_hash_rows for value in schedules) == 2_048
        assert sum(value.sha3_call_rows for value in schedules) == 36_080
        assert sum(value.sha3_permutations for value in schedules) == 74_208
        assert ordered_map_batch_schedule_commitment(
            tuple(
                zip(
                    (
                        BENEFIT_MAP_DOMAIN,
                        OBLIGATION_MAP_DOMAIN,
                        LEDGER_MAP_DOMAIN,
                    ),
                    schedules,
                    strict=True,
                )
            )
        ).hex() == (
            "1c390b67823fc6b71233d87d4082d48082b6f9ed3ff2f7c4d5e079f5b6bff947"
            "646b41c9714e263f29a1e3722a9cab8fa158091f00f77b1c7304a21182588683"
        )

        member = BenefitAccumulatorRecord.decode(
            _read(
                transition.after.benefit_entries,
                member_benefit_key(
                    "SYNTH-MEMBER-001", benefit_scope=_benefit_scope()
                ),
            )
        )
        assert member == BenefitAccumulatorRecord(100, 20, 1, 0)
        assert len(transition.after.obligation_entries) == 1
        assert int.from_bytes(
            _read(transition.after.ledger_entries, payer_reserve_key()) or b"", "big"
        ) == 920
        assert int.from_bytes(
            _read(
                transition.after.ledger_entries,
                provider_payable_key("1999999984"),
            )
            or b"",
            "big",
        ) == 80
        assert transition.total_plan_payable_cents == 80
        assert transition.total_debits_cents == transition.total_credits_cents == 80


def test_all_cover_batch_changes_log_without_allocating_economic_records(
    profile,
) -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        slots = tuple(_cover(index) for index in range(profile.claim_slots))
        economics = derive_batch_economics(profile, slots)
        before = _state(profile)
        transition = build_authenticated_payment_map_transition(
            profile,
            slots,
            economics,
            before,
        )
        assert transition.after.benefit_snapshot.next_append_index == (
            before.benefit_snapshot.next_append_index
        )
        assert transition.after.obligation_snapshot.next_append_index == (
            before.obligation_snapshot.next_append_index
        )
        assert transition.after.ledger_snapshot.next_append_index == (
            before.ledger_snapshot.next_append_index
        )
        assert transition.after.benefit_root_512 == before.benefit_root_512
        assert transition.after.obligation_root_512 == before.obligation_root_512
        assert transition.after.private_asset_ledger_root_512 == (
            before.private_asset_ledger_root_512
        )
        assert transition.after.operation_log_root_512 != before.operation_log_root_512
        assert transition.total_plan_payable_cents == 0
        assert transition.total_debits_cents == transition.total_credits_cents == 0


def test_duplicate_obligation_underflow_and_transition_mutation_fail_closed(
    profile,
) -> None:
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        slots = _slots(profile)
        economics = derive_batch_economics(profile, slots)
        with pytest.raises(StructuralError, match="reserve_underflow"):
            build_authenticated_payment_map_transition(
                profile, slots, economics, _state(profile, reserve=79)
            )
        transition = build_authenticated_payment_map_transition(
            profile, slots, economics, _state(profile)
        )
        with pytest.raises(StructuralError, match="duplicate_obligation"):
            build_authenticated_payment_map_transition(
                profile, slots, economics, transition.after
            )
        corrupted_root = replace(
            transition.transitions[0],
            operation_log_root_after_512=sha3_512(b"CORRUPTED-OPERATION-ROOT").digest(),
        )
        with pytest.raises(StructuralError, match="endpoint_root_mismatch|root_chain_mismatch"):
            replace(
                transition,
                transitions=(corrupted_root, *transition.transitions[1:]),
            )
        corrupted_log = sha3_512(b"CORRUPTED-FINAL-OPERATION-ROOT").digest()
        corrupted_last = replace(
            transition.transitions[-1],
            operation_log_root_after_512=corrupted_log,
        )
        corrupted = replace(
            transition,
            after=replace(transition.after, operation_log_root_512=corrupted_log),
            transitions=(*transition.transitions[:-1], corrupted_last),
        )
        with pytest.raises(StructuralError, match="recomputation_mismatch"):
            verify_authenticated_payment_map_transition(
                profile, slots, economics, corrupted
            )


def test_payment_map_reference_is_disabled_in_production(profile) -> None:
    with mock.patch.dict(os.environ, {**FLAGS, "BL_ENV": "production"}, clear=False):
        with pytest.raises(RuntimeError, match="synthetic_pq_tree_reference_forbidden"):
            _state(profile)
