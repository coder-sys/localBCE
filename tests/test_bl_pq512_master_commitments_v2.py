from __future__ import annotations

from dataclasses import fields, replace
from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.master_commitments_v2 import (
    MasterCommitmentInputsV2,
    MasterEconomicTotalsV2,
    MasterSlotRecordV2,
    batch_preimage,
    build_master_commitments_v2,
    governance_preimage,
    settlement_preimage,
    value_preimage,
)


def _wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def _inputs() -> MasterCommitmentInputsV2:
    slots = tuple(
        MasterSlotRecordV2(
            slot_index=index,
            decision=1,
            failure_code=0,
            allowed_cents=100,
            payment_cents=80,
            raw_gate_bits=(1 << 13) - 1,
            effective_gate_bits=(1 << 13) - 1,
            strong_nullifier_512=_wide(f"nullifier-{index}"),
        )
        for index in range(128)
    )
    return MasterCommitmentInputsV2(
        profile_id="K128_CALIBRATION",
        epoch=7,
        strong_settlement_domain_id_512=_wide("settlement-domain"),
        strong_batch_nonce_512=_wide("batch-nonce"),
        claim_truth_roots_512=tuple(_wide(f"truth-{index}") for index in range(6)),
        claim_truth_authority_digest_512=_wide("truth-authority"),
        nullifier_authority_id_512=_wide("nullifier-authority"),
        pepper_commitment_512=_wide("pepper"),
        replay_root_before_512=_wide("replay-before"),
        replay_root_after_512=_wide("replay-after"),
        payment_lane_roots_before_512=tuple(
            _wide(f"payment-before-{index}") for index in range(3)
        ),
        payment_lane_roots_after_512=tuple(
            _wide(f"payment-after-{index}") for index in range(3)
        ),
        operation_log_root_before_512=_wide("operation-log-before"),
        operation_log_root_after_512=_wide("operation-log-after"),
        salt_use_tag_512=_wide("salt-use-tag"),
        economic_totals=MasterEconomicTotalsV2(12_800, 2_560, 10_240, 10_240, 10_240),
        slots=slots,
    )


def test_k128_master_commitment_v2_is_canonical_and_pinned() -> None:
    value = _inputs()
    result = build_master_commitments_v2(value)
    governance = governance_preimage(value)
    batch = batch_preimage(value, result.governance_512)
    conservation = value_preimage(value)
    settlement = settlement_preimage(
        value,
        result.governance_512,
        result.batch_512,
        result.value_conservation_512,
    )

    assert tuple(map(len, (governance, batch, conservation, settlement))) == (
        607,
        11_294,
        654,
        984,
    )
    assert tuple(
        digest.hex()
        for digest in (
            result.governance_512,
            result.batch_512,
            result.value_conservation_512,
            result.settlement_512,
        )
    ) == (
        "5aec9c1d6726289d216df393fc72d09a8a69df4189f8374170789cccd43edac240539aa3ffbd4fc10770cf6710664e988ad11943b3fe084fdb82be23945073e8",
        "c5b8d04d4287a7b7bacf32a84c829e162c6002e50d1b6a7f7d4639dfbed1e9a5a3e23df8403c56d539d5d57f07c3201bfba085951e7773f1c69998d7a825b051",
        "16baeb823466fe023aa282f5096c7777ecc875d92a9cbbe8e18302dda084e3a3d54573b0ee508c26e8ced42e4ff457be798bc2ddeb7cd9213e0c35148377b412",
        "a00b2dd005bdf8d64580039b743bcbe0e271656580f24720f02ae49c7bf3819fe17c599e7eb11298a79c48b4eeaed5c4f52be53306366b82986a83648cf14b68",
    )


def test_every_authoritative_input_family_changes_a_master_commitment() -> None:
    value = _inputs()
    baseline = build_master_commitments_v2(value)
    mutations = (
        replace(value, epoch=value.epoch + 1),
        replace(value, strong_settlement_domain_id_512=_wide("changed-domain")),
        replace(value, strong_batch_nonce_512=_wide("changed-nonce")),
        replace(
            value,
            claim_truth_roots_512=(_wide("changed-truth"), *value.claim_truth_roots_512[1:]),
        ),
        replace(value, claim_truth_authority_digest_512=_wide("changed-authority")),
        replace(value, nullifier_authority_id_512=_wide("changed-nullifier-authority")),
        replace(value, pepper_commitment_512=_wide("changed-pepper")),
        replace(value, replay_root_before_512=_wide("changed-replay-before")),
        replace(value, replay_root_after_512=_wide("changed-replay-after")),
        replace(
            value,
            payment_lane_roots_before_512=(
                _wide("changed-payment-before"),
                *value.payment_lane_roots_before_512[1:],
            ),
        ),
        replace(
            value,
            payment_lane_roots_after_512=(
                _wide("changed-payment-after"),
                *value.payment_lane_roots_after_512[1:],
            ),
        ),
        replace(value, operation_log_root_before_512=_wide("changed-log-before")),
        replace(value, operation_log_root_after_512=_wide("changed-log-after")),
        replace(value, salt_use_tag_512=_wide("changed-salt-tag")),
    )
    for mutation in mutations:
        assert build_master_commitments_v2(mutation) != baseline

    slots = list(value.slots)
    slots[0] = replace(
        slots[0],
        allowed_cents=101,
        payment_cents=81,
        strong_nullifier_512=_wide("changed-slot-nullifier"),
    )
    totals = MasterEconomicTotalsV2(12_801, 2_560, 10_241, 10_241, 10_241)
    assert build_master_commitments_v2(
        replace(value, slots=tuple(slots), economic_totals=totals)
    ) != baseline


def test_obsolete_aggregate_payment_authority_cannot_reenter_v2() -> None:
    names = {field.name for field in fields(MasterCommitmentInputsV2)}
    assert "payment_root_before_512" not in names
    assert "payment_root_after_512" not in names
    assert names >= {
        "payment_lane_roots_before_512",
        "payment_lane_roots_after_512",
        "operation_log_root_before_512",
        "operation_log_root_after_512",
    }


def test_totals_and_slot_values_fail_closed() -> None:
    value = _inputs()
    with pytest.raises(ValueError, match="gross_conservation"):
        replace(
            value,
            economic_totals=MasterEconomicTotalsV2(12_801, 2_560, 10_240, 10_240, 10_240),
        )
    with pytest.raises(ValueError, match="payment_total_mismatch"):
        replace(
            value,
            economic_totals=MasterEconomicTotalsV2(12_800, 2_559, 10_241, 10_241, 10_241),
        )
    with pytest.raises(ValueError, match="denied_slot_value"):
        replace(value.slots[0], decision=0)
