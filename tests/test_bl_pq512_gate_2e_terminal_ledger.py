from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import os
from unittest import mock

import pytest

os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")

from experiments.bl_pq512_crypto_foundation.atomic_state_composition import (
    build_atomic_composition,
    canonical_relation_payload,
    derive_composition_statement,
)
from experiments.bl_pq512_crypto_foundation.c0_control_fixture import (
    build_all_c0_control_fixtures,
)
from experiments.bl_pq512_crypto_foundation.gate_2e_selection import (
    CandidateMeasurement,
    build_selection_handoff,
    select_reference_candidates,
)
from experiments.bl_pq512_crypto_foundation.gate_2e_terminal_ledger import (
    BLOCKED,
    LEDGER_STATUS,
    OBLIGATION_IDS,
    OPEN,
    REFERENCE_ONLY,
    TerminalLedger,
    TerminalLedgerContext,
    TerminalLedgerError,
    build_terminal_ledger,
    independently_verify_terminal_ledger,
)
from experiments.bl_pq512_crypto_foundation.pq_commitment_screening import (
    AUTHORITY_SUITE_IDS,
    CANDIDATE_IDS,
    AuthenticatedPublicCoinRound,
    PublicCoinAttestation,
    build_commitment,
    build_opening,
    backend_descriptor,
    derive_pre_challenge_digest,
    derive_public_coin_message_digest,
    screen_backend,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.scalar_state_relation_controls import (
    PROFILE_CLAIM_SLOTS,
    build_scalar_control_batch,
    evaluate_candidate,
)
from experiments.bl_pq512_crypto_foundation.state_migration_recovery import (
    checkpoint_from_composition,
)
from experiments.bl_pq512_crypto_foundation.state_plane import (
    StateEntry,
    StateOperation,
    StateSnapshot,
    build_state_transition,
)


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


@pytest.fixture(scope="module", autouse=True)
def _synthetic_environment():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        yield


@pytest.fixture(scope="module")
def authority_material():
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    material = {}
    for adapter, label in ((ml, b"ml"), (slh, b"slh")):
        public_key, secret_key = adapter.generate_keypair()
        material[adapter.suite_id] = (
            sha3_512(b"BL/2E-terminal/authority/" + label).digest(),
            adapter,
            public_key,
            secret_key,
        )
    return material


def _composition(authority_material):
    batch = build_scalar_control_batch("K128_CALIBRATION")
    result = evaluate_candidate("C1_SPARSE", batch)
    projection = tuple(
        sha3_512(b"BL/2E-terminal/projection/" + index.to_bytes(1, "big")).digest()[:32]
        for index in range(12)
    )
    statement = derive_composition_statement(
        batch,
        result,
        projection,
        epoch=7,
        sequence_before=22,
    )
    payload = canonical_relation_payload(result)
    mask = sha3_512(b"BL/2E-terminal/mask").digest()
    pre_challenge = derive_pre_challenge_digest(
        "TRANSPARENT_HASH_CODE",
        statement,
        payload,
        mask,
    )
    session_id = sha3_512(b"BL/2E-terminal/session").digest()
    message = derive_public_coin_message_digest(session_id, 0, pre_challenge)
    attestations = []
    adapters = {}
    for suite_id in AUTHORITY_SUITE_IDS:
        authority_id, adapter, public_key, secret_key = authority_material[suite_id]
        attestations.append(
            PublicCoinAttestation(
                authority_id,
                suite_id,
                public_key,
                message,
                adapter.sign(secret_key=secret_key, message=message),
            )
        )
        adapters[suite_id] = adapter
    attestations.sort(key=lambda item: item.authority_id_512)
    coin_round = AuthenticatedPublicCoinRound(
        session_id,
        0,
        pre_challenge,
        tuple(attestations),
    )
    artifact = build_commitment(
        "TRANSPARENT_HASH_CODE",
        statement,
        payload,
        mask,
        coin_round,
        adapters,
    )
    opening = build_opening(artifact, payload, mask, adapters)
    composition = build_atomic_composition(
        batch,
        result,
        projection,
        artifact,
        opening,
        adapters,
        epoch=7,
        sequence_before=22,
    )
    before = checkpoint_from_composition(composition, stage="before")
    after = checkpoint_from_composition(composition, stage="after")
    return batch, result, opening, adapters, composition, before, after


def _decision_and_handoff():
    measurements = []
    for profile_id in PROFILE_CLAIM_SLOTS:
        for backend_id in CANDIDATE_IDS:
            screen = screen_backend(backend_id)
            for repetition in range(2):
                measurements.append(
                    CandidateMeasurement(
                        backend_id,
                        profile_id,
                        repetition,
                        "C1_SPARSE",
                        False,
                        screen.rejection_reasons,
                        100 + repetition,
                        20 + repetition,
                        1,
                    )
                )
    decision = select_reference_candidates(tuple(measurements))
    handoff = build_selection_handoff(
        decision,
        commit_id="67a898458d9e28ada61998c5b158ebae560e10dd",
        tree_id="0c34de0fe9122f9716dc86e850aa4515ffec7da9",
        git_clean=True,
        protected_paths_clean=True,
        canonical_ops_available=False,
    )
    return decision, handoff


@pytest.fixture(scope="module")
def context(authority_material):
    batch, result, opening, adapters, composition, before, after = _composition(
        authority_material
    )
    decision, handoff = _decision_and_handoff()
    return TerminalLedgerContext(
        tuple(build_all_c0_control_fixtures()),
        composition,
        batch,
        result,
        opening,
        adapters,
        before,
        after,
        decision,
        handoff,
        True,
        True,
        False,
    )


def test_terminal_ledger_replays_reference_boundary_and_remains_blocked(context) -> None:
    ledger = build_terminal_ledger(context)
    assert isinstance(ledger, TerminalLedger)
    assert ledger.status == LEDGER_STATUS
    assert ledger.sealed is False
    assert ledger.proof_suite_id is None
    assert ledger.activation_allowed is False
    assert tuple(record.obligation_id for record in ledger.records) == OBLIGATION_IDS
    assert ledger.records[0].status == REFERENCE_ONLY
    assert ledger.records[1].status == OPEN
    assert ledger.records[7].status == BLOCKED
    assert ledger.records[9].status == BLOCKED
    assert "no_backend_admitted" in ledger.blockers
    assert "complete_simulator_missing" in ledger.blockers
    assert "complete_leakage_scan_missing" in ledger.blockers
    assert "canonical_ops_missing" in ledger.blockers
    independently_verify_terminal_ledger(ledger, context)


def test_terminal_ledger_public_encoding_contains_only_bounded_identities(context) -> None:
    ledger = build_terminal_ledger(context)
    public = ledger.as_public_dict()
    rendered = repr(public).encode("ascii")
    for lane in context.result.lanes:
        for private_value in (
            lane.membership_key_512,
            lane.membership_value_512,
            lane.absence_key_512,
        ):
            assert private_value.hex().encode("ascii") not in rendered
    assert public["proofSuiteId"] is None
    assert public["activation_allowed"] is False
    assert public["sealed"] is False


def test_terminal_ledger_carries_both_clean_readback_flags_without_claiming_selection(context) -> None:
    dirty = replace(context, git_clean=False, protected_paths_clean=False)
    with pytest.raises(TerminalLedgerError, match="handoff_git_readback_mismatch"):
        build_terminal_ledger(dirty)


def test_terminal_ledger_records_real_state_plane_without_admitting_h4(context) -> None:
    before = StateSnapshot.empty(
        context.batch.profile_id,
        capacity=context.batch.claim_slots,
        epoch=7,
    )
    operations = tuple(
        StateOperation(index, StateEntry.empty(index), StateEntry.empty(index))
        for index in range(before.capacity)
    )
    proof = build_state_transition(
        before,
        operations,
        tuple(
            sha3_512(b"BL/2E-terminal/state-projection/" + bytes((index,))).digest()[:32]
            for index in range(12)
        ),
        sha3_512(b"BL/2E-terminal/state-coin").digest(),
        sha3_512(b"BL/2E-terminal/state-mask").digest(),
    )
    ledger = build_terminal_ledger(replace(context, state_plane_proof=proof))
    assert ledger.state_plane_status == "STATE_PLANE_IMPLEMENTED_H4_PENDING"
    assert ledger.state_plane_digest_512
    assert ledger.records[5].source_id.startswith("state_plane.py+")
    assert ledger.h4_parent_bound is False
    assert ledger.proof_suite_id is None
    assert ledger.activation_allowed is False
