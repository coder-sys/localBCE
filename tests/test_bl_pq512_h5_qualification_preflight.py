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
    CAMPAIGN_NOT_STARTED,
    CANONICAL_OPS_VERIFIED,
    FRESH_LAUNCH_COUNT,
    H5Preflight,
    H5PreflightContext,
    PREFLIGHT_BLOCKED,
    PROFILE_IDS,
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
            sha3_512(b"BL/H5-preflight/authority/" + label).digest(),
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
    return H5PreflightContext(
        build_terminal_ledger(terminal_context),
        terminal_context,
    )


def test_h5_preflight_is_blocked_and_freezes_the_complete_campaign_shape(context) -> None:
    preflight = build_h5_preflight(context)
    assert isinstance(preflight, H5Preflight)
    assert preflight.status == PREFLIGHT_BLOCKED
    assert preflight.profile_ids == PROFILE_IDS
    assert preflight.warmup_count == 1
    assert preflight.measured_repetitions == 10
    assert preflight.launches_per_profile == 11
    assert preflight.fresh_launch_count == FRESH_LAUNCH_COUNT == 22
    assert preflight.campaign_status == CAMPAIGN_NOT_STARTED
    assert preflight.canonical_ops_status == CANONICAL_OPS_VERIFIED
    assert preflight.reference_hardware_ready is True
    assert {
        "gate_2e_ledger_unsealed",
        "state_plane_unselected",
        "h4_atomic_binding_deferred",
        "complete_leakage_scan_missing",
        "strict_pq_security_ledger_open",
        "proof_suite_unselected",
        "h5_campaign_not_started",
        "h5_external_monitor_not_configured",
        "h5_source_readback_not_captured",
        "h5_no_qualified_evidence",
    } <= set(preflight.blockers)
    assert preflight.proof_suite_id is None
    assert preflight.activation_allowed is False
    independently_verify_h5_preflight(preflight, context)


def test_h5_public_preflight_has_no_private_relation_bytes(context) -> None:
    preflight = build_h5_preflight(context)
    rendered = repr(preflight.as_public_dict()).encode("ascii")
    for lane in context.terminal_context.result.lanes:
        for private_value in (
            lane.membership_key_512,
            lane.membership_value_512,
            lane.absence_key_512,
        ):
            assert private_value.hex().encode("ascii") not in rendered
    assert preflight.as_public_dict()["proofSuiteId"] is None
    assert preflight.as_public_dict()["activation_allowed"] is False
