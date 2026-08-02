from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import json
import os
from pathlib import Path
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
    CLOSED,
    H6PreflightError,
    H6PreflightContext,
    build_h6_preflight,
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
            sha3_512(b"BL/H6-preflight/attack-authority/" + label).digest(),
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


def test_suite_registry_drift_cannot_be_treated_as_an_unqualified_candidate(
    context,
    tmp_path: Path,
) -> None:
    registry = json.loads(context.suite_registry_path.read_text(encoding="utf-8"))
    registry["proofSuiteId"] = "11" * 64
    mutated = tmp_path / "suite.json"
    mutated.write_text(json.dumps(registry), encoding="utf-8")
    forged_context = replace(context, suite_registry_path=mutated)
    with pytest.raises(H6PreflightError, match="suite_must_be_null"):
        build_h6_preflight(forged_context)


def test_h6_digest_and_status_mutations_are_rejected(context) -> None:
    preflight = build_h6_preflight(context)
    with pytest.raises(H6PreflightError, match="digest_mismatch"):
        replace(preflight, preflight_digest_512=b"\x01" * 64)
    with pytest.raises(H6PreflightError, match="status_must_remain_blocked"):
        replace(preflight, status="QUALIFIED", preflight_digest_512=b"")


def test_h6_obligation_cannot_be_marked_closed(context) -> None:
    preflight = build_h6_preflight(context)
    with pytest.raises(H6PreflightError, match="closed_record_forbidden"):
        replace(preflight.records[0], status=CLOSED, record_digest_512=b"")


def test_h6_activation_and_suite_assignment_are_forbidden(context) -> None:
    preflight = build_h6_preflight(context)
    with pytest.raises(H6PreflightError, match="activation_boundary_invalid"):
        replace(preflight, proof_suite_id=b"suite", preflight_digest_512=b"")
    with pytest.raises(H6PreflightError, match="activation_boundary_invalid"):
        replace(preflight, activation_allowed=True, preflight_digest_512=b"")
