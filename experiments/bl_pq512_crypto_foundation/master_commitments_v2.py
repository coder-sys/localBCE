"""Canonical authoritative Wave 1A master commitments.

Version 2 removes the obsolete aggregate-payment roots.  The authenticated
benefit, obligation, and ledger roots plus the chained operation log are the
only economic state authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final

from experiments.fixed_shape_claim_air.profile import PROFILES


STATUS: Final[str] = "BL_WAVE1A_MASTER_COMMITMENTS_V2_NONACTIVATING"
PROTOCOL_VERSION: Final[int] = 2
GOVERNANCE_DOMAIN: Final[bytes] = b"BL/PQ512/GOVERNANCE/v2"
BATCH_DOMAIN: Final[bytes] = b"BL/PQ512/BATCH/v2"
VALUE_DOMAIN: Final[bytes] = b"BL/PQ512/VALUE-CONSERVATION/v2"
SETTLEMENT_DOMAIN: Final[bytes] = b"BL/PQ512/SETTLEMENT/v2"
_PROFILE_CODES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}


def _b64(label: str, value: object, *, nonzero: bool = True) -> bytes:
    if type(value) is not bytes or len(value) != 64 or (nonzero and not any(value)):
        raise ValueError(f"master_commitment_{label}_invalid")
    return value


def _u64(label: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"master_commitment_{label}_invalid")
    return value


@dataclass(frozen=True, slots=True)
class MasterEconomicTotalsV2:
    gross_allowed_cents: int
    patient_responsibility_cents: int
    plan_payable_cents: int
    payer_reserve_debits_cents: int
    provider_payable_credits_cents: int

    def __post_init__(self) -> None:
        for label, value in (
            ("gross_allowed", self.gross_allowed_cents),
            ("patient_responsibility", self.patient_responsibility_cents),
            ("plan_payable", self.plan_payable_cents),
            ("payer_reserve_debits", self.payer_reserve_debits_cents),
            ("provider_payable_credits", self.provider_payable_credits_cents),
        ):
            _u64(label, value)
        if self.gross_allowed_cents != (
            self.patient_responsibility_cents + self.plan_payable_cents
        ):
            raise ValueError("master_commitment_gross_conservation_invalid")
        if not (
            self.plan_payable_cents
            == self.payer_reserve_debits_cents
            == self.provider_payable_credits_cents
        ):
            raise ValueError("master_commitment_payment_conservation_invalid")

    def encode(self) -> bytes:
        return b"".join(
            value.to_bytes(8, "big")
            for value in (
                self.gross_allowed_cents,
                self.patient_responsibility_cents,
                self.plan_payable_cents,
                self.payer_reserve_debits_cents,
                self.provider_payable_credits_cents,
            )
        )


@dataclass(frozen=True, slots=True)
class MasterSlotRecordV2:
    slot_index: int
    decision: int
    failure_code: int
    allowed_cents: int
    payment_cents: int
    raw_gate_bits: int
    effective_gate_bits: int
    strong_nullifier_512: bytes

    def __post_init__(self) -> None:
        if type(self.slot_index) is not int or not 0 <= self.slot_index <= 0xFFFF:
            raise ValueError("master_commitment_slot_index_invalid")
        if type(self.decision) is not int or self.decision not in {0, 1}:
            raise ValueError("master_commitment_decision_invalid")
        if type(self.failure_code) is not int or not 0 <= self.failure_code <= 0xFFFF:
            raise ValueError("master_commitment_failure_code_invalid")
        for label, value in (
            ("allowed", self.allowed_cents),
            ("payment", self.payment_cents),
        ):
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError(f"master_commitment_{label}_invalid")
        for label, value in (
            ("raw_gate_bits", self.raw_gate_bits),
            ("effective_gate_bits", self.effective_gate_bits),
        ):
            if type(value) is not int or not 0 <= value < (1 << 13):
                raise ValueError(f"master_commitment_{label}_invalid")
        _b64("slot_nullifier", self.strong_nullifier_512)
        if self.decision == 1:
            if self.failure_code != 0 or self.payment_cents > self.allowed_cents:
                raise ValueError("master_commitment_approved_slot_invalid")
        elif self.allowed_cents != 0 or self.payment_cents != 0:
            raise ValueError("master_commitment_denied_slot_value_invalid")

    def encode(self) -> bytes:
        return b"".join(
            (
                self.slot_index.to_bytes(2, "big"),
                bytes((self.decision,)),
                self.failure_code.to_bytes(2, "big"),
                self.allowed_cents.to_bytes(4, "big"),
                self.payment_cents.to_bytes(4, "big"),
                self.raw_gate_bits.to_bytes(2, "big"),
                self.effective_gate_bits.to_bytes(2, "big"),
                self.strong_nullifier_512,
            )
        )


@dataclass(frozen=True, slots=True)
class MasterCommitmentInputsV2:
    profile_id: str
    epoch: int
    strong_settlement_domain_id_512: bytes
    strong_batch_nonce_512: bytes
    claim_truth_roots_512: tuple[bytes, ...]
    claim_truth_authority_digest_512: bytes
    nullifier_authority_id_512: bytes
    pepper_commitment_512: bytes
    replay_root_before_512: bytes
    replay_root_after_512: bytes
    payment_lane_roots_before_512: tuple[bytes, bytes, bytes]
    payment_lane_roots_after_512: tuple[bytes, bytes, bytes]
    operation_log_root_before_512: bytes
    operation_log_root_after_512: bytes
    salt_use_tag_512: bytes
    economic_totals: MasterEconomicTotalsV2
    slots: tuple[MasterSlotRecordV2, ...]

    def __post_init__(self) -> None:
        if self.profile_id not in _PROFILE_CODES:
            raise ValueError("master_commitment_profile_invalid")
        profile = PROFILES[self.profile_id]
        _u64("epoch", self.epoch)
        if self.epoch == 0:
            raise ValueError("master_commitment_epoch_invalid")
        for label, value in (
            ("settlement_domain", self.strong_settlement_domain_id_512),
            ("batch_nonce", self.strong_batch_nonce_512),
            ("claim_truth_authority_digest", self.claim_truth_authority_digest_512),
            ("nullifier_authority_id", self.nullifier_authority_id_512),
            ("pepper_commitment", self.pepper_commitment_512),
            ("replay_before", self.replay_root_before_512),
            ("replay_after", self.replay_root_after_512),
            ("operation_log_before", self.operation_log_root_before_512),
            ("operation_log_after", self.operation_log_root_after_512),
            ("salt_use_tag", self.salt_use_tag_512),
        ):
            _b64(label, value)
        if (
            type(self.claim_truth_roots_512) is not tuple
            or len(self.claim_truth_roots_512) != 6
        ):
            raise ValueError("master_commitment_truth_root_count_invalid")
        for index, value in enumerate(self.claim_truth_roots_512):
            _b64(f"truth_root_{index}", value)
        for label, values in (
            ("payment_before", self.payment_lane_roots_before_512),
            ("payment_after", self.payment_lane_roots_after_512),
        ):
            if type(values) is not tuple or len(values) != 3:
                raise ValueError(f"master_commitment_{label}_count_invalid")
            for index, value in enumerate(values):
                _b64(f"{label}_{index}", value)
        if not isinstance(self.economic_totals, MasterEconomicTotalsV2):
            raise ValueError("master_commitment_totals_invalid")
        if (
            type(self.slots) is not tuple
            or len(self.slots) != profile.claim_slots
            or any(
                not isinstance(value, MasterSlotRecordV2)
                or value.slot_index != index
                for index, value in enumerate(self.slots)
            )
        ):
            raise ValueError("master_commitment_slots_invalid")
        if sum(slot.allowed_cents for slot in self.slots) != (
            self.economic_totals.gross_allowed_cents
        ):
            raise ValueError("master_commitment_gross_total_mismatch")
        if sum(slot.payment_cents for slot in self.slots) != (
            self.economic_totals.plan_payable_cents
        ):
            raise ValueError("master_commitment_payment_total_mismatch")


@dataclass(frozen=True, slots=True)
class MasterCommitmentsV2:
    governance_512: bytes
    batch_512: bytes
    value_conservation_512: bytes
    settlement_512: bytes


def governance_preimage(value: MasterCommitmentInputsV2) -> bytes:
    return b"".join(
        (
            GOVERNANCE_DOMAIN,
            bytes((_PROFILE_CODES[value.profile_id],)),
            value.epoch.to_bytes(8, "big"),
            *value.claim_truth_roots_512,
            value.claim_truth_authority_digest_512,
            value.nullifier_authority_id_512,
            value.pepper_commitment_512,
        )
    )


def batch_preimage(value: MasterCommitmentInputsV2, governance: bytes) -> bytes:
    return b"".join(
        (
            BATCH_DOMAIN,
            bytes((_PROFILE_CODES[value.profile_id],)),
            PROTOCOL_VERSION.to_bytes(2, "big"),
            value.epoch.to_bytes(8, "big"),
            value.strong_settlement_domain_id_512,
            value.strong_batch_nonce_512,
            len(value.slots).to_bytes(2, "big"),
            _b64("governance", governance),
            value.replay_root_before_512,
            value.replay_root_after_512,
            *value.payment_lane_roots_before_512,
            *value.payment_lane_roots_after_512,
            value.operation_log_root_before_512,
            value.operation_log_root_after_512,
            *(slot.encode() for slot in value.slots),
            value.salt_use_tag_512,
        )
    )


def value_preimage(value: MasterCommitmentInputsV2) -> bytes:
    return b"".join(
        (
            VALUE_DOMAIN,
            value.epoch.to_bytes(8, "big"),
            value.strong_batch_nonce_512,
            value.economic_totals.encode(),
            *value.payment_lane_roots_before_512,
            *value.payment_lane_roots_after_512,
            value.operation_log_root_before_512,
            value.operation_log_root_after_512,
        )
    )


def settlement_preimage(
    value: MasterCommitmentInputsV2,
    governance: bytes,
    batch: bytes,
    conservation: bytes,
) -> bytes:
    return b"".join(
        (
            SETTLEMENT_DOMAIN,
            PROTOCOL_VERSION.to_bytes(2, "big"),
            value.strong_settlement_domain_id_512,
            value.strong_batch_nonce_512,
            _b64("governance", governance),
            _b64("batch", batch),
            _b64("conservation", conservation),
            value.replay_root_before_512,
            value.replay_root_after_512,
            *value.payment_lane_roots_before_512,
            *value.payment_lane_roots_after_512,
            value.operation_log_root_before_512,
            value.operation_log_root_after_512,
        )
    )


def build_master_commitments_v2(
    value: MasterCommitmentInputsV2,
) -> MasterCommitmentsV2:
    if not isinstance(value, MasterCommitmentInputsV2):
        raise TypeError("master_commitment_inputs_required")
    governance = sha3_512(governance_preimage(value)).digest()
    batch = sha3_512(batch_preimage(value, governance)).digest()
    conservation = sha3_512(value_preimage(value)).digest()
    settlement = sha3_512(
        settlement_preimage(value, governance, batch, conservation)
    ).digest()
    return MasterCommitmentsV2(governance, batch, conservation, settlement)


__all__ = (
    "MasterCommitmentInputsV2",
    "MasterCommitmentsV2",
    "MasterEconomicTotalsV2",
    "MasterSlotRecordV2",
    "batch_preimage",
    "build_master_commitments_v2",
    "governance_preimage",
    "settlement_preimage",
    "value_preimage",
)
