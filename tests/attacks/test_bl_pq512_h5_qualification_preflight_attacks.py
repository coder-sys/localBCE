from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import os
from unittest import mock

import pytest

os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")

from experiments.bl_pq512_crypto_foundation.c0_control_fixture import (
    build_all_c0_control_fixtures,
)
from experiments.bl_pq512_crypto_foundation.gate_2e_terminal_ledger import (
    TerminalLedgerError,
    TerminalLedgerContext,
    build_terminal_ledger,
)
from experiments.bl_pq512_crypto_foundation.h5_qualification_preflight import (
    H5PreflightError,
    build_h5_preflight,
    independently_verify_h5_preflight,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
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
            sha3_512(b"BL/H5-preflight/attack-authority/" + label).digest(),
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
    decision, handoff = _decision_and_handoff(canonical_ops_available=True)
    terminal_context = TerminalLedgerContext(
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
        True,
    )
    from experiments.bl_pq512_crypto_foundation.h5_qualification_preflight import (
        H5PreflightContext,
    )

    return H5PreflightContext(
        build_terminal_ledger(terminal_context),
        terminal_context,
    )


def test_forged_terminal_blockers_cannot_make_preflight_ready(context) -> None:
    ledger = context.terminal_ledger
    with pytest.raises(TerminalLedgerError, match="mandatory_blocker_missing"):
        replace(
            ledger,
            blockers=tuple(
                blocker for blocker in ledger.blockers if blocker != "no_backend_admitted"
            ),
            ledger_digest_512=b"",
        )


def test_forged_preflight_digest_and_status_cannot_be_accepted(context) -> None:
    preflight = build_h5_preflight(context)
    with pytest.raises(H5PreflightError, match="digest_mismatch"):
        replace(preflight, preflight_digest_512=b"\x01" * 64)
    with pytest.raises(H5PreflightError, match="status_must_remain_blocked"):
        replace(preflight, status="QUALIFIED", preflight_digest_512=b"")


def test_campaign_shape_cannot_be_reduced_or_marked_partial(context) -> None:
    preflight = build_h5_preflight(context)
    with pytest.raises(H5PreflightError, match="campaign_shape_invalid"):
        replace(preflight, measured_repetitions=9, preflight_digest_512=b"")
    with pytest.raises(H5PreflightError, match="campaign_status_invalid"):
        replace(preflight, campaign_status="PARTIAL", preflight_digest_512=b"")


def test_activation_and_suite_assignment_are_forbidden(context) -> None:
    preflight = build_h5_preflight(context)
    with pytest.raises(H5PreflightError, match="activation_boundary_invalid"):
        replace(preflight, proof_suite_id=b"suite", preflight_digest_512=b"")
    with pytest.raises(H5PreflightError, match="activation_boundary_invalid"):
        replace(preflight, activation_allowed=True, preflight_digest_512=b"")
