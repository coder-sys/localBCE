from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import os
from unittest import mock

import pytest

os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")

from experiments.bl_pq512_crypto_foundation.gate_2e_terminal_ledger import (
    TerminalLedgerContext,
    TerminalLedgerError,
    build_terminal_ledger,
    independently_verify_terminal_ledger,
)
from experiments.bl_pq512_crypto_foundation.c0_control_fixture import (
    build_all_c0_control_fixtures,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.state_migration_recovery import (
    checkpoint_from_composition,
)
from tests.test_bl_pq512_gate_2e_terminal_ledger import (
    _composition,
    _decision_and_handoff,
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
            sha3_512(b"BL/2E-terminal/attack-authority/" + label).digest(),
            adapter,
            public_key,
            secret_key,
        )
    return material


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


def test_mutated_evidence_identity_cannot_be_repaired_by_ledger_digest(context) -> None:
    ledger = build_terminal_ledger(context)
    mutated_record = replace(
        ledger.records[0],
        evidence_identity_512=bytes([ledger.records[0].evidence_identity_512[0] ^ 1])
        + ledger.records[0].evidence_identity_512[1:],
        record_digest_512=b"",
    )
    forged = replace(
        ledger,
        records=(mutated_record, *ledger.records[1:]),
        ledger_digest_512=b"",
    )
    with pytest.raises(TerminalLedgerError, match="replay_mismatch"):
        independently_verify_terminal_ledger(forged, context)


def test_sealing_and_suite_assignment_are_forbidden(context) -> None:
    ledger = build_terminal_ledger(context)
    with pytest.raises(TerminalLedgerError, match="must_remain_unsealed"):
        replace(ledger, sealed=True, ledger_digest_512=b"")
    with pytest.raises(TerminalLedgerError, match="activation_boundary_invalid"):
        replace(ledger, proof_suite_id=b"suite", ledger_digest_512=b"")


def test_checkpoint_substitution_fails_before_terminal_ledger_is_built(context) -> None:
    forged_checkpoint = replace(
        context.after_checkpoint,
        state_root_512=bytes([context.after_checkpoint.state_root_512[0] ^ 1])
        + context.after_checkpoint.state_root_512[1:],
        state_digest_512=b"",
        checkpoint_digest_512=b"",
    )
    forged_context = replace(context, after_checkpoint=forged_checkpoint)
    with pytest.raises(TerminalLedgerError, match="after_checkpoint_mismatch"):
        build_terminal_ledger(forged_context)


def test_canonical_ops_blocker_cannot_be_hidden_by_clean_flags(context) -> None:
    forged_handoff = replace(
        context.handoff,
        canonical_ops_available=True,
        handoff_digest_512=b"",
    )
    with pytest.raises(TerminalLedgerError, match="handoff_ops_readback_mismatch"):
        build_terminal_ledger(replace(context, handoff=forged_handoff))
