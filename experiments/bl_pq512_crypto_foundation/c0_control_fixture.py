"""Gate 2E-0 C0 control fixture.

This is a deterministic, synthetic control record for the already sealed Wave
1 references.  It is deliberately not a state implementation, proof, or
activation artifact.  Full-width keys and values are constructed and checked
through the existing reference relations; only bounded summaries and SHA3-512
identities leave this module's control build.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from hashlib import sha3_512
import json
from typing import Final

from app.public_inputs import PUBLIC_INPUT_FIELD_NAMES_V2
from experiments.bl_pq512_crypto_foundation.claim_batch_access_manifest import (
    ClaimBatchAccessManifest,
    CbamPrivateAccessBody,
    build_c0_claim_batch_access_manifest,
    build_c0_private_access_body,
)
from experiments.fixed_shape_claim_air.authenticated_payment_maps_reference import (
    AuthenticatedPaymentMapBatchTransition,
    AuthenticatedPaymentMapState,
    BENEFIT_MAP_DOMAIN,
    LEDGER_MAP_DOMAIN,
    OBLIGATION_MAP_DOMAIN,
    BenefitScopeV1,
    build_authenticated_payment_map_transition,
    build_payment_map_state,
    verify_authenticated_payment_map_transition,
)
from experiments.fixed_shape_claim_air.ordered_map_batch_reference import (
    OrderedMapBatchWitness,
    build_ordered_map_batch_schedule,
    build_ordered_map_batch_witness,
    require_ordered_map_batch_fits_schedule,
)
from experiments.fixed_shape_claim_air.ordered_map_reference import (
    MAX_512,
    ZERO_512,
    OrderedMapBuilder,
    OrderedMapSnapshot,
    require_ordered_map_upsert,
)
from experiments.fixed_shape_claim_air.payment import derive_batch_economics
from experiments.fixed_shape_claim_air.profile import CalibrationProfile, PROFILES
from experiments.fixed_shape_claim_air.semantics import (
    ClaimSlot,
    RevisionKind,
    ServiceLine,
    SlotKind,
    StructuralError,
    validate_slot_shape,
)


STATUS: Final[str] = "C0_CONTROL_FIXTURE_V1_SYNTHETIC_NONPRODUCTION"
PROOF_SUITE_ID: None = None
ACTIVATION_ALLOWED: Final[bool] = False
SCHEMA_VERSION: Final[str] = "blind-ledger-c0-control-fixture-v1"
H4_EXECUTION_MANIFEST_SHA3_512: Final[str] = (
    "51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2"
    "a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6"
)
_REPLAY_MAP_DOMAIN: Final[bytes] = b"R"
_FIXTURE_DOMAIN: Final[bytes] = b"BL/PQ512/C0/CONTROL-FIXTURE/v1\x00"
_STATE_DOMAIN: Final[bytes] = b"BL/PQ512/C0/STATE-ROOT/v1\x00"
_PUBLIC_DOMAIN: Final[bytes] = b"BL/PQ512/C0/PUBLIC-12-FIELDS/v1\x00"
_H4_RECORD_DOMAIN: Final[bytes] = b"BL/PQ512/C0/H4-RESOURCE-RECORD/v1\x00"
_MAP_LANES: Final[tuple[tuple[str, bytes], ...]] = (
    ("replay", _REPLAY_MAP_DOMAIN),
    ("benefit", BENEFIT_MAP_DOMAIN),
    ("obligation", OBLIGATION_MAP_DOMAIN),
    ("ledger", LEDGER_MAP_DOMAIN),
)
_NEGATIVE_CASES: Final[tuple[tuple[str, str], ...]] = (
    ("stale_read", "ordered_map_apply_state_mismatch"),
    ("omitted_write", "ordered_map_batch_endpoint_transition_mismatch"),
    ("reordered_write", "ordered_map_batch_endpoint_transition_mismatch"),
    ("duplicate_identity", "r25_duplicate_attempt_identity"),
    ("collision", "wave1a_payment_map_ledger_key_collision"),
    ("root_substitution", "ordered_map_batch_root_before_mismatch"),
    ("conflicting_update", "ordered_map_apply_root_before_mismatch"),
)


def _sha3(value: bytes) -> bytes:
    return sha3_512(value).digest()


def _wide(label: str, index: int, *, profile_id: str) -> bytes:
    value = _sha3(
        _FIXTURE_DOMAIN
        + label.encode("ascii")
        + b"/"
        + profile_id.encode("ascii")
        + b"/"
        + index.to_bytes(8, "big")
    )
    if value in {ZERO_512, MAX_512}:
        raise AssertionError("c0_control_fixture_reserved_wide_value")
    return value


def _hex(value: bytes) -> str:
    if type(value) is not bytes or len(value) != 64:
        raise ValueError("c0_control_fixture_wide_identity_required")
    return value.hex()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


@dataclass(frozen=True, slots=True)
class C0Artifact:
    name: str
    length: int
    sha3_512_hex: str

    def __post_init__(self) -> None:
        if not self.name or type(self.name) is not str:
            raise ValueError("c0_control_fixture_artifact_name_invalid")
        if type(self.length) is not int or self.length <= 0:
            raise ValueError("c0_control_fixture_artifact_length_invalid")
        if len(self.sha3_512_hex) != 128:
            raise ValueError("c0_control_fixture_artifact_identity_invalid")


@dataclass(frozen=True, slots=True)
class H4ResourceRecord:
    profile_id: str
    evidence_class: str
    execution_manifest_sha3_512_hex: str
    complete_process_seconds: str
    internal_host_peak_mb: str
    external_process_tree_peak_mb: str
    tracked_per_proof_device_mb: str
    sampled_total_gpu_mb: str
    scratch_mb: str
    pagefile_growth: str
    production_usable: bool

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class C0MapResult:
    lane: str
    map_domain_hex: str
    operation_count: int
    access_rows: int
    position_rows: int
    proof_node_rows: int
    operations_length: int
    root_before_hex: str
    root_after_hex: str
    cursor_before: int
    cursor_after: int
    membership_key_hex: str
    membership_value_hex: str
    absence_key_hex: str
    update_root_before_hex: str
    update_root_after_hex: str
    update_cursor_before: int
    update_cursor_after: int
    operations_sha3_512_hex: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class C0PaymentResult:
    payment_root_before_hex: str
    payment_root_after_hex: str
    operation_log_before_hex: str
    operation_log_after_hex: str
    total_plan_payable_cents: int
    total_debits_cents: int
    total_credits_cents: int
    case_outcomes: tuple[tuple[str, str, str], ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "payment_root_before_hex": self.payment_root_before_hex,
            "payment_root_after_hex": self.payment_root_after_hex,
            "operation_log_before_hex": self.operation_log_before_hex,
            "operation_log_after_hex": self.operation_log_after_hex,
            "total_plan_payable_cents": self.total_plan_payable_cents,
            "total_debits_cents": self.total_debits_cents,
            "total_credits_cents": self.total_credits_cents,
            "case_outcomes": [list(value) for value in self.case_outcomes],
        }


@dataclass(frozen=True, slots=True)
class C0ControlFixture:
    status: str
    schema_version: str
    profile_id: str
    claim_slots: int
    proof_suite_id: None
    activation_allowed: bool
    cbam_commitment_sha3_512_hex: str
    private_body_commitment_sha3_512_hex: str
    state_root_before_hex: str
    state_root_after_hex: str
    map_results: tuple[C0MapResult, ...]
    payment: C0PaymentResult
    public_input_names: tuple[str, ...]
    public_output_hex: tuple[str, ...]
    negative_cases: tuple[tuple[str, str], ...]
    h4_resource_record: H4ResourceRecord
    artifacts: tuple[C0Artifact, ...]
    manifest_bytes: bytes

    @property
    def fixture_manifest_sha3_512_hex(self) -> str:
        return sha3_512(self.manifest_bytes).hexdigest()

    @property
    def fixture_manifest_length(self) -> int:
        return len(self.manifest_bytes)

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "claim_slots": self.claim_slots,
            "proof_suite_id": self.proof_suite_id,
            "activation_allowed": self.activation_allowed,
            "cbam_commitment_sha3_512_hex": self.cbam_commitment_sha3_512_hex,
            "private_body_commitment_sha3_512_hex": self.private_body_commitment_sha3_512_hex,
            "state_root_before_hex": self.state_root_before_hex,
            "state_root_after_hex": self.state_root_after_hex,
            "map_results": [value.as_dict() for value in self.map_results],
            "payment": self.payment.as_dict(),
            "public_input_names": list(self.public_input_names),
            "public_output_hex": list(self.public_output_hex),
            "negative_cases": [list(value) for value in self.negative_cases],
            "h4_resource_record": self.h4_resource_record.as_dict(),
            "artifacts": [asdict(value) for value in self.artifacts],
        }


@dataclass(frozen=True, slots=True)
class C0TypedStateWitness:
    """Full private C0 witness used by the proof-native typed state AIR.

    ``C0ControlFixture`` intentionally exposes only bounded public summaries.
    This separate object keeps the exact ordered-map/payment authorities
    available to the verifier-facing AIR builder without widening that public
    fixture or serializing private keys and values.
    """

    profile: CalibrationProfile
    slots: tuple[ClaimSlot, ...]
    economics: object
    replay_before: OrderedMapSnapshot
    replay_batch: OrderedMapBatchWitness
    payment_before: AuthenticatedPaymentMapState
    payment_transition: AuthenticatedPaymentMapBatchTransition

    def __post_init__(self) -> None:
        if type(self.profile) is not CalibrationProfile:
            raise ValueError("c0_typed_state_profile_invalid")
        if type(self.slots) is not tuple or len(self.slots) != self.profile.claim_slots:
            raise ValueError("c0_typed_state_slots_invalid")
        if type(self.replay_before) is not OrderedMapSnapshot:
            raise ValueError("c0_typed_state_replay_snapshot_invalid")
        if type(self.replay_batch) is not OrderedMapBatchWitness:
            raise ValueError("c0_typed_state_replay_batch_invalid")
        if (
            self.replay_before.map_domain != self.replay_batch.map_domain
            or self.replay_before.next_append_index != self.replay_batch.next_append_index_before
            or self.replay_before.inner_root != self.replay_batch.inner_root_before
            or self.replay_before.root != self.replay_batch.root_before
        ):
            raise ValueError("c0_typed_state_replay_authority_mismatch")
        if type(self.payment_before) is not AuthenticatedPaymentMapState:
            raise ValueError("c0_typed_state_payment_before_invalid")
        if type(self.payment_transition) is not AuthenticatedPaymentMapBatchTransition:
            raise ValueError("c0_typed_state_payment_transition_invalid")
        if (
            self.payment_transition.before != self.payment_before
            or len(self.payment_transition.transitions) != len(self.slots)
        ):
            raise ValueError("c0_typed_state_payment_slot_count_invalid")

    @property
    def payment_after(self) -> AuthenticatedPaymentMapState:
        return self.payment_transition.after


def _h4_record(profile_id: str) -> H4ResourceRecord:
    if profile_id == "K128_CALIBRATION":
        values = ("29.974129", "288.412000", "681.607168", "969.999360", "not-promoted")
    elif profile_id == "K512_CALIBRATION":
        values = ("120.460733", "296.255000", "706.523136", "969.999360", "2770.337792")
    else:
        raise ValueError("c0_control_fixture_h4_profile_invalid")
    return H4ResourceRecord(
        profile_id,
        "H4_ONE_RUN_MEASURED_NONQUALIFYING",
        H4_EXECUTION_MANIFEST_SHA3_512,
        *values,
        "0.000000",
        "zero",
        False,
    )


def _line(index: int) -> ServiceLine:
    return ServiceLine(
        0,
        f"LINE-{index:04d}",
        "T1019",
        100,
        1,
        "",
        True,
        100,
        False,
        False,
    )


def _real_slot(index: int, case: str) -> ClaimSlot:
    approved = case == "approved"
    member = "SYNTH-MEMBER-001" if case in {"approved", "duplicate", "conflict"} else ""
    duplicate = case == "duplicate"
    integrity_hold = case == "conflict"
    failure_code = 0 if approved else (12 if duplicate else 13 if integrity_hold else 1)
    return ClaimSlot(
        index,
        SlotKind.REAL,
        "BL-SYNTH-GOV-INTAKE-V1",
        index + 1,
        f"BL-SYNTH-CLAIM-{index + 1:04d}",
        member,
        "1999999984",
        1,
        RevisionKind.ORIGINAL,
        0,
        ("F840",),
        (_line(index),),
        True,
        True,
        True,
        True,
        duplicate,
        integrity_hold,
        100,
        20 if approved else 0,
        1 if approved else 0,
        failure_code,
        100 if approved else 0,
        80 if approved else 0,
    )


def _cover_slot(index: int) -> ClaimSlot:
    return ClaimSlot(
        index,
        SlotKind.COVER,
        "",
        0,
        "",
        "",
        "",
        0,
        RevisionKind.COVER,
        0,
        (),
        (),
        False,
        False,
        False,
        False,
        False,
        False,
        0,
        0,
        0,
        0,
        0,
        0,
    )


def _slots(profile: CalibrationProfile) -> tuple[ClaimSlot, ...]:
    cases = ("approved", "duplicate", "conflict", "denial")
    return tuple(
        _real_slot(index, cases[index]) if index < len(cases) else _cover_slot(index)
        for index in range(profile.claim_slots)
    )


def _operation_bytes(batch: OrderedMapBatchWitness) -> bytes:
    chunks = [batch.map_domain, batch.root_before, batch.root_after]
    for operation in batch.operations:
        chunks.extend(
            (
                operation.mode.encode("ascii"),
                operation.next_append_index_before.to_bytes(8, "big"),
                operation.next_append_index_after.to_bytes(8, "big"),
                operation.key_512,
                operation.value_before_512,
                operation.value_after_512,
                operation.target_before.index.to_bytes(8, "big"),
                operation.target_after.index.to_bytes(8, "big"),
                (b"1" if operation.allocated_after is not None else b"0"),
            )
        )
    return b"".join(chunks)


def _map_result(
    lane: str,
    snapshot: OrderedMapSnapshot,
    batch: OrderedMapBatchWitness,
    membership_key: bytes,
    *,
    profile_id: str,
) -> C0MapResult:
    builder = OrderedMapBuilder(snapshot.map_domain, snapshot=snapshot)
    membership_value = builder.get(membership_key)
    if membership_value is None:
        raise AssertionError("c0_control_fixture_membership_missing")
    absence_key = _wide(f"{lane}-absence", 0, profile_id=profile_id)
    while builder.get(absence_key) is not None:
        absence_key = _wide(f"{lane}-absence", len(absence_key), profile_id=profile_id)
    if builder.get(absence_key) is not None:
        raise AssertionError("c0_control_fixture_absence_present")
    replacement = _wide(f"{lane}-correction", 0, profile_id=profile_id)
    update = builder.prove_upsert(membership_key, replacement)
    require_ordered_map_upsert(update)
    if update.mode != "update" or update.next_append_index_before != update.next_append_index_after:
        raise AssertionError("c0_control_fixture_update_not_sequential")
    builder.apply(update)
    return C0MapResult(
        lane,
        batch.map_domain.hex(),
        len(batch.operations),
        len(batch.memory_accesses),
        len(batch.positions),
        len(batch.proof_nodes),
        len(operation_bytes := _operation_bytes(batch)),
        _hex(batch.root_before),
        _hex(batch.root_after),
        batch.next_append_index_before,
        batch.next_append_index_after,
        _hex(membership_key),
        _hex(membership_value),
        _hex(absence_key),
        _hex(update.root_before),
        _hex(update.root_after),
        update.next_append_index_before,
        update.next_append_index_after,
        sha3_512(operation_bytes).hexdigest(),
    )


def _replay_fixture(profile: CalibrationProfile) -> tuple[OrderedMapSnapshot, OrderedMapBatchWitness, C0MapResult]:
    builder = OrderedMapBuilder(_REPLAY_MAP_DOMAIN)
    before = builder.snapshot()
    transitions = []
    keys = []
    for index in range(profile.claim_slots + 1):
        key = _wide("replay-key", index, profile_id=profile.profile_id)
        keys.append(key)
        witness = builder.prove_upsert(key, _wide("replay-value", index, profile_id=profile.profile_id))
        require_ordered_map_upsert(witness)
        builder.apply(witness)
        transitions.append(witness)
    after = builder.snapshot()
    batch = build_ordered_map_batch_witness(before, after, tuple(transitions))
    require_ordered_map_batch_fits_schedule(
        batch, build_ordered_map_batch_schedule(profile.claim_slots + 1)
    )
    return before, batch, _map_result(
        "replay", after, batch, keys[profile.claim_slots // 2], profile_id=profile.profile_id
    )


def _build_payment_transition(
    profile: CalibrationProfile,
) -> tuple[tuple[ClaimSlot, ...], object, AuthenticatedPaymentMapState, AuthenticatedPaymentMapBatchTransition]:
    """Build the exact payment authority once for summaries and typed AIR."""

    slots = _slots(profile)
    duplicate_identity_slots = list(slots)
    duplicate_identity_slots[1] = replace(
        duplicate_identity_slots[1],
        source_sequence=slots[0].source_sequence,
        claim_id=slots[0].claim_id,
    )
    try:
        derive_batch_economics(profile, tuple(duplicate_identity_slots))
    except StructuralError as exc:
        if str(exc) != "r25_duplicate_attempt_identity":
            raise
    else:
        raise AssertionError("c0_control_fixture_duplicate_identity_not_rejected")
    economics = derive_batch_economics(profile, slots)
    before = build_payment_map_state(
        epoch=7,
        sequence=11,
        strong_settlement_domain_id_512=_sha3(b"BL/C0/SETTLEMENT-DOMAIN"),
        benefit_scope=BenefitScopeV1("SYNTH-PAYER-001", "SYNTH-PLAN-001", 20_000, 20_365),
        payer_reserve_cents=10_000,
        operation_log_root_512=_sha3(b"BL/C0/OPERATION-LOG-BEFORE"),
    )
    transition = build_authenticated_payment_map_transition(profile, slots, economics, before)
    if not verify_authenticated_payment_map_transition(profile, slots, economics, transition):
        raise AssertionError("c0_control_fixture_payment_replay_mismatch")
    return slots, economics, before, transition


def _payment_fixture(
    profile: CalibrationProfile,
) -> tuple[object, object, C0PaymentResult, tuple[C0MapResult, ...]]:
    slots, economics, before, transition = _build_payment_transition(profile)
    first = transition.transitions[0]
    map_results = (
        _map_result(
            "benefit",
            transition.after.benefit_snapshot,
            transition.benefit_batch_witness,
            first.benefit_key_512,
            profile_id=profile.profile_id,
        ),
        _map_result(
            "obligation",
            transition.after.obligation_snapshot,
            transition.obligation_batch_witness,
            first.obligation_key_512,
            profile_id=profile.profile_id,
        ),
        _map_result(
            "ledger",
            transition.after.ledger_snapshot,
            transition.ledger_batch_witness,
            first.reserve_key_512,
            profile_id=profile.profile_id,
        ),
    )
    outcomes = (
        ("approved", "accepted", "0"),
        ("duplicate", "denied", "12"),
        ("conflict", "denied", "13"),
        ("denial", "denied", "1"),
        ("cover", "cover", "0"),
        ("correction", "rejected", "r25_revision_not_authorized"),
    )
    payment = C0PaymentResult(
        _hex(before.root()),
        _hex(transition.after.root()),
        _hex(before.operation_log_root_512),
        _hex(transition.after.operation_log_root_512),
        transition.total_plan_payable_cents,
        transition.total_debits_cents,
        transition.total_credits_cents,
        outcomes,
    )
    correction = _real_slot(0, "approved")
    correction = ClaimSlot(
        correction.slot_index,
        correction.slot_kind,
        correction.source_authority_id,
        correction.source_sequence,
        correction.claim_id,
        correction.member_id,
        correction.provider_npi,
        2,
        RevisionKind.CORRECTION,
        1,
        correction.diagnoses,
        correction.service_lines,
        correction.eligibility_active,
        correction.provider_enrolled,
        correction.provider_not_suspended,
        correction.not_deceased,
        correction.duplicate_claim,
        correction.program_integrity_hold,
        correction.total_charge_cents,
        correction.patient_responsibility_cents,
        correction.claimed_decision,
        correction.claimed_failure_code,
        correction.claimed_allowed_cents,
        correction.claimed_payment_cents,
    )
    try:
        validate_slot_shape(correction)
    except StructuralError as exc:
        if str(exc) != "r25_revision_not_authorized":
            raise
    else:
        raise AssertionError("c0_control_fixture_correction_not_rejected")
    return before, transition.after, payment, map_results


def _public_output(profile_id: str, state_before: bytes, state_after: bytes) -> tuple[str, ...]:
    common = _PUBLIC_DOMAIN + profile_id.encode("ascii") + state_before + state_after
    return tuple(
        _sha3(common + name.encode("ascii"))[:32].hex()
        for name in PUBLIC_INPUT_FIELD_NAMES_V2
    )


def _artifact(name: str, payload: bytes) -> C0Artifact:
    return C0Artifact(name, len(payload), sha3_512(payload).hexdigest())


def build_c0_control_fixture(profile: CalibrationProfile) -> C0ControlFixture:
    """Build and independently replay one exact synthetic C0 profile."""

    if type(profile) is not CalibrationProfile or PROFILES.get(profile.profile_id) != profile:
        raise ValueError("c0_control_fixture_profile_not_governed")
    cbam: ClaimBatchAccessManifest = build_c0_claim_batch_access_manifest(profile)
    tokens = tuple(
        _wide("opaque-page-token", index, profile_id=profile.profile_id)
        for index in range(cbam.access_rows)
    )
    private_body: CbamPrivateAccessBody = build_c0_private_access_body(profile, tokens)
    _, replay_batch, replay_result = _replay_fixture(profile)
    payment_before, payment_after, payment, payment_maps = _payment_fixture(profile)
    state_before = _sha3(_STATE_DOMAIN + payment_before.root() + replay_batch.root_before)
    state_after = _sha3(_STATE_DOMAIN + payment_after.root() + replay_batch.root_after)
    public_output = _public_output(profile.profile_id, state_before, state_after)
    h4 = _h4_record(profile.profile_id)
    h4_bytes = _canonical_json(h4.as_dict())
    public_bytes = b"".join(bytes.fromhex(value) for value in public_output)
    artifacts = (
        _artifact("access_manifest", cbam.encoded),
        _artifact("private_access_body", private_body.encoded),
        *(
            C0Artifact(
                f"{value.lane}_operations",
                value.operations_length,
                value.operations_sha3_512_hex,
            )
            for value in (replay_result, *payment_maps)
        ),
        _artifact("ordered_12_field_output", public_bytes),
        _artifact("h4_resource_record", _H4_RECORD_DOMAIN + h4_bytes),
    )
    payload = {
        "status": STATUS,
        "schema_version": SCHEMA_VERSION,
        "profile_id": profile.profile_id,
        "claim_slots": profile.claim_slots,
        "proof_suite_id": PROOF_SUITE_ID,
        "activation_allowed": ACTIVATION_ALLOWED,
        "cbam_commitment_sha3_512_hex": cbam.commitment_512.hex(),
        "private_body_commitment_sha3_512_hex": private_body.masked_reference_commitment_512(
            _wide("private-mask", 0, profile_id=profile.profile_id)
        ).hex(),
        "state_root_before_hex": _hex(state_before),
        "state_root_after_hex": _hex(state_after),
        "map_results": [replay_result.as_dict(), *(value.as_dict() for value in payment_maps)],
        "payment": payment.as_dict(),
        "public_input_names": list(PUBLIC_INPUT_FIELD_NAMES_V2),
        "public_output_hex": list(public_output),
        "negative_cases": [list(value) for value in _NEGATIVE_CASES],
        "h4_resource_record": h4.as_dict(),
        "artifacts": [asdict(value) for value in artifacts],
    }
    manifest = _canonical_json(payload)
    return C0ControlFixture(
        STATUS,
        SCHEMA_VERSION,
        profile.profile_id,
        profile.claim_slots,
        PROOF_SUITE_ID,
        ACTIVATION_ALLOWED,
        cbam.commitment_512.hex(),
        private_body.masked_reference_commitment_512(
            _wide("private-mask", 0, profile_id=profile.profile_id)
        ).hex(),
        _hex(state_before),
        _hex(state_after),
        (replay_result, *payment_maps),
        payment,
        tuple(PUBLIC_INPUT_FIELD_NAMES_V2),
        public_output,
        _NEGATIVE_CASES,
        h4,
        artifacts,
        manifest,
    )


def build_all_c0_control_fixtures() -> tuple[C0ControlFixture, C0ControlFixture]:
    return (
        build_c0_control_fixture(PROFILES["K128_CALIBRATION"]),
        build_c0_control_fixture(PROFILES["K512_CALIBRATION"]),
    )


def build_c0_typed_state_witness(profile: CalibrationProfile) -> C0TypedStateWitness:
    """Return the full private C0 state witness for typed AIR composition."""

    if type(profile) is not CalibrationProfile or PROFILES.get(profile.profile_id) != profile:
        raise ValueError("c0_typed_state_profile_not_governed")
    replay_before, replay_batch, _ = _replay_fixture(profile)
    slots, economics, payment_before, payment_transition = _build_payment_transition(profile)
    return C0TypedStateWitness(
        profile,
        slots,
        economics,
        replay_before,
        replay_batch,
        payment_before,
        payment_transition,
    )


__all__ = (
    "ACTIVATION_ALLOWED",
    "C0Artifact",
    "C0ControlFixture",
    "C0MapResult",
    "C0PaymentResult",
    "C0TypedStateWitness",
    "H4ResourceRecord",
    "H4_EXECUTION_MANIFEST_SHA3_512",
    "PROOF_SUITE_ID",
    "SCHEMA_VERSION",
    "STATUS",
    "build_all_c0_control_fixtures",
    "build_c0_control_fixture",
    "build_c0_typed_state_witness",
)
