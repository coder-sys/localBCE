from __future__ import annotations

from hashlib import sha3_512
import os
from pathlib import Path
import subprocess
from unittest import mock

from experiments.fixed_shape_claim_air.authenticated_payment_maps_reference import (
    build_authenticated_payment_map_transition,
    member_benefit_key_preimage,
    payer_reserve_key_preimage,
    payment_dummy_key_preimage,
    payment_operation_log_preimage,
    payment_operation_preimage,
    provider_obligation_key_preimage,
    provider_payable_key_preimage,
)
from experiments.fixed_shape_claim_air.payment import derive_batch_economics
from experiments.fixed_shape_claim_air.profile import get_profile
from tests.test_wave1a_authenticated_payment_maps_reference import FLAGS, _slots, _state


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "experiments" / "bl_pq512_crypto_core"
TARGET = Path(r"C:\blpq-target")
SCHEDULE_DOMAIN = b"BL/PQ512/WAVE1A/PAYMENT-LOG-SHA3-SCHEDULE/v1\x00"
KEY_SCHEDULE_DOMAIN = b"BL/PQ512/WAVE1A/PAYMENT-KEY-SHA3-SCHEDULE/v2\x00"


def _transition():
    profile = get_profile("K128_CALIBRATION")
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        slots = _slots(profile)
        economics = derive_batch_economics(profile, slots)
        transition = build_authenticated_payment_map_transition(
            profile, slots, economics, _state(profile)
        )
    return slots, economics, transition


def _binary_input(slots, economics, transition) -> bytes:
    chunks = [
        b"BLPL1",
        transition.before.sequence.to_bytes(8, "big"),
        transition.before.operation_log_root_512,
        len(slots).to_bytes(2, "big"),
    ]
    for slot, slot_economics, payment in zip(
        slots, economics.slots, transition.transitions, strict=True
    ):
        chunks.extend(
            (
                slot.slot_index.to_bytes(2, "big"),
                {"approval": b"A", "denial": b"D", "cover": b"C"}[
                    payment.witness_class
                ],
                slot_economics.gross_allowed_cents.to_bytes(4, "big"),
                slot_economics.patient_responsibility_cents.to_bytes(4, "big"),
                slot_economics.plan_payable_cents.to_bytes(4, "big"),
                *(upsert.key_512 for upsert in payment.upserts),
                *(upsert.value_before_512 for upsert in payment.upserts),
                *(upsert.value_after_512 for upsert in payment.upserts),
                payment.operation_log_root_after_512,
            )
        )
    return b"".join(chunks)


def _expected(slots, economics, transition) -> tuple[bytes, bytes]:
    commitment = sha3_512()
    commitment.update(SCHEDULE_DOMAIN)
    commitment.update(len(slots).to_bytes(4, "big"))
    root = transition.before.operation_log_root_512
    for slot, slot_economics, payment in zip(
        slots, economics.slots, transition.transitions, strict=True
    ):
        operation = payment_operation_preimage(
            slot.slot_index,
            payment.witness_class,
            slot_economics,
            payment.upserts,
        )
        operation_digest = sha3_512(operation).digest()
        log = payment_operation_log_preimage(
            root,
            transition.before.sequence,
            slot.slot_index,
            operation_digest,
        )
        root = sha3_512(log).digest()
        assert root == payment.operation_log_root_after_512
        for message in (operation, log):
            commitment.update(len(message).to_bytes(4, "big"))
            commitment.update(message)
        commitment.update(operation_digest)
        commitment.update(root)
    return root, commitment.digest()


def test_k128_payment_log_stream_matches_python_exactly(tmp_path: Path) -> None:
    slots, economics, transition = _transition()
    input_path = tmp_path / "payment-log-k128.bin"
    input_path.write_bytes(_binary_input(slots, economics, transition))
    completed = subprocess.run(
        (
            "cargo",
            "+1.96.0",
            "run",
            "--quiet",
            "--locked",
            "--offline",
            "--target-dir",
            str(TARGET),
            "--bin",
            "payment_log_stream",
            "--",
            str(input_path),
        ),
        cwd=CRATE,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    observed = dict(
        line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line
    )
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        expected_root, expected_commitment = _expected(
            slots, economics, transition
        )
    assert expected_root.hex() == (
        "50697c64bb1ddfa0aee73d60663178c072d6f45ab4f90351479927a50db24e5d"
        "162bf7516fb9206a3c52d9144243e9c5e94635ad0b8f538915cc0384a68164e7"
    )
    assert expected_commitment.hex() == (
        "928a094b3987ad28a7f1b03de809b79f5a114c77faf3e2de691f336e9c25b9abd"
        "639c83e9c405ee6da3ae2323f50aeebeaca662aa6da6e9ca58b8b9c60325dec"
    )
    assert observed == {
        "slots": "128",
        "calls": "256",
        "permutations": "1920",
        "keccak_round_rows": "46080",
        "final_log_root": expected_root.hex(),
        "commitment": expected_commitment.hex(),
    }


def _key_messages(slots, transition):
    scope = transition.before.benefit_scope.commitment_512()
    messages = []
    for slot, payment in zip(slots, transition.transitions, strict=True):
        if payment.witness_class == "approval":
            lane_messages = (
                member_benefit_key_preimage(
                    slot.member_id,
                    benefit_scope=transition.before.benefit_scope,
                ),
                provider_obligation_key_preimage(slot),
                payer_reserve_key_preimage(),
                provider_payable_key_preimage(slot.provider_npi),
            )
        else:
            lane_messages = tuple(
                payment_dummy_key_preimage(
                    lane,
                    transition.before.strong_settlement_domain_id_512,
                    transition.before.epoch,
                    scope,
                )
                for lane in (b"BENEFIT", b"OBLIGATION", b"RESERVE", b"PAYABLE")
            )
        expected_keys = tuple(upsert.key_512 for upsert in payment.upserts)
        assert tuple(sha3_512(message).digest() for message in lane_messages) == (
            expected_keys
        )
        messages.extend(lane_messages)
    return tuple(messages)


def _key_input(slots, messages) -> bytes:
    chunks = [b"BLPK1", len(slots).to_bytes(2, "big")]
    for message in messages:
        chunks.extend(
            (
                len(message).to_bytes(2, "big"),
                message,
                sha3_512(message).digest(),
            )
        )
    return b"".join(chunks)


def _key_commitment(slots, messages) -> bytes:
    capacities = (169, 169, 169, 169)
    commitment = sha3_512()
    commitment.update(KEY_SCHEDULE_DOMAIN)
    commitment.update(len(slots).to_bytes(4, "big"))
    for ordinal, message in enumerate(messages):
        lane = ordinal % 4 + 1
        capacity = capacities[ordinal % 4]
        commitment.update(ordinal.to_bytes(4, "big"))
        commitment.update(bytes((lane,)))
        commitment.update(capacity.to_bytes(2, "big"))
        commitment.update(len(message).to_bytes(2, "big"))
        commitment.update(message)
        commitment.update(sha3_512(message).digest())
    return commitment.digest()


def test_k128_payment_key_stream_matches_python_exactly(tmp_path: Path) -> None:
    slots, _, transition = _transition()
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        messages = _key_messages(slots, transition)
    input_path = tmp_path / "payment-keys-k128.bin"
    input_path.write_bytes(_key_input(slots, messages))
    completed = subprocess.run(
        (
            "cargo",
            "+1.96.0",
            "run",
            "--quiet",
            "--locked",
            "--offline",
            "--target-dir",
            str(TARGET),
            "--bin",
            "payment_key_stream",
            "--",
            str(input_path),
        ),
        cwd=CRATE,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    observed = dict(
        line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line
    )
    expected_commitment = _key_commitment(slots, messages)
    assert expected_commitment.hex() == (
        "2139c8bcd94c946e6b03514eb7f97d241e7a364abebacc6e8b9c2a8c04b5c6c2"
        "1845219f142231e74cbf623b20c2d7bd0adc7a751be7e4e78da6201eaa02bf4d"
    )
    assert observed == {
        "slots": "128",
        "calls": "512",
        "permutations": "1536",
        "keccak_round_rows": "36864",
        "commitment": expected_commitment.hex(),
    }
