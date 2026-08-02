from __future__ import annotations

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
    TerminalLedgerContext,
    build_terminal_ledger,
)
from experiments.bl_pq512_crypto_foundation.h5_qualification_preflight import (
    H5PreflightContext,
    build_h5_preflight,
)
from experiments.bl_pq512_crypto_foundation.h6_qualification_preflight import (
    BLOCKED,
    H6_OBLIGATION_IDS,
    H6Preflight,
    H6PreflightContext,
    PREFLIGHT_BLOCKED,
    build_h6_preflight,
    independently_verify_h6_preflight,
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
            sha3_512(b"BL/H6-preflight/authority/" + label).digest(),
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
    h5_context = H5PreflightContext(
        build_terminal_ledger(terminal_context),
        terminal_context,
    )
    return H6PreflightContext(
        build_h5_preflight(h5_context),
        h5_context,
    )


def test_h6_preflight_records_all_obligations_without_closing_any(context) -> None:
    preflight = build_h6_preflight(context)
    assert isinstance(preflight, H6Preflight)
    assert preflight.status == PREFLIGHT_BLOCKED
    assert tuple(record.obligation_id for record in preflight.records) == H6_OBLIGATION_IDS
    assert all(record.status != "CLOSED" for record in preflight.records)
    assert sum(record.status == BLOCKED for record in preflight.records) >= 4
    assert preflight.h5_fresh_launch_count == 22
    assert preflight.suite_registry_module_count == 8
    assert {
        "no_backend_admitted",
        "proof_suite_unselected",
        "complete_simulator_missing",
        "complete_leakage_scan_missing",
        "h5_campaign_not_started",
        "h6_no_qualified_evidence",
    } <= set(preflight.blockers)
    assert preflight.proof_suite_id is None
    assert preflight.activation_allowed is False
    independently_verify_h6_preflight(preflight, context)


def test_h6_public_record_excludes_private_state_material(context) -> None:
    preflight = build_h6_preflight(context)
    rendered = repr(preflight.as_public_dict()).encode("ascii")
    for lane in context.h5_context.terminal_context.result.lanes:
        for private_value in (
            lane.membership_key_512,
            lane.membership_value_512,
            lane.absence_key_512,
        ):
            assert private_value.hex().encode("ascii") not in rendered
    assert preflight.as_public_dict()["proofSuiteId"] is None
    assert preflight.as_public_dict()["activation_allowed"] is False
