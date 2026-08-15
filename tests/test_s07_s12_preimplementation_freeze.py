from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.batch.pq_suite_candidate import (
    EXPECTED_REGISTRY_CANONICAL_SHA3_512,
    SIDECAR_LAYOUT,
    SIDECAR_LENGTH,
    ActiveSuiteIdentityV1,
    CandidateSidecarV1,
    candidate_salt_use_tag,
    canonical_registry_sha3_512,
    validate_active_binding,
    validate_unqualified_registry,
)


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "docs" / "bl_pq512_suite_candidate_v1.json"
SCHEMA_PATH = ROOT / "schemas" / "bl_pq512_suite_candidate_v1.schema.json"
ABI_PATH = ROOT / "ops" / "native_stark_public_inputs_v2.json"
DOC_PATH = ROOT / "docs" / "BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md"

EXPECTED_ABI = [
    "protocolVersion",
    "settlementDomain",
    "batchNonce",
    "nullifierRootBefore",
    "nullifierRootAfter",
    "claimSourceRoot",
    "oracleFactsRoot",
    "policyRoot",
    "rulesetRoot",
    "opaqueBatchCommitment",
    "valueConservationCommitment",
    "settlementCommitment",
]


def _registry() -> dict:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def _walk(value: object):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _sidecar() -> CandidateSidecarV1:
    values = [bytes([index]) * 64 for index in range(1, 12)]
    return CandidateSidecarV1(
        profile_id=values[0],
        proof_suite_id=values[1],
        schema_id=values[2],
        verifier_artifact_identity=values[3],
        strong_settlement_domain_id=values[4],
        epoch=7,
        sequence_before=41,
        sequence_after=42,
        strong_nullifier_root_before=values[5],
        strong_nullifier_root_after=values[6],
        strong_governance_commitment=values[7],
        strong_payment_state_root_before=values[8],
        strong_payment_state_root_after=values[9],
        strong_batch_commitment=values[10],
    )


def test_registry_is_explicitly_unqualified_and_nonactivatable() -> None:
    registry = _registry()
    validate_unqualified_registry(registry)
    assert canonical_registry_sha3_512(registry) == EXPECTED_REGISTRY_CANONICAL_SHA3_512
    assert registry["status"] == "CANDIDATE_UNQUALIFIED"
    assert registry["activationAllowed"] is False
    assert registry["proofSuiteId"] is None
    assert registry["syntheticOnly"] is True
    assert all(module["moduleId"] is None for module in registry["modules"])
    hiding = registry["candidateNativeHiding"]
    assert hiding["interfaceScheduleCurrent"] is False
    assert hiding["directEvaluationRank"] == 958
    assert hiding["quotientMaskDegreeFreedom"] == 927
    assert hiding["quotientClosureProved"] is False
    assert hiding["simulatorComplete"] is False
    sha3_air = registry["candidateSha3Air"]
    assert sha3_air["coreRoundBaseColumns"] == 1_632
    assert sha3_air["traceBaseColumns"] == 1_704
    assert sha3_air["coreRoundLookupMessages"] == 1_024
    assert sha3_air["firstRoundLookupMessages"] == 1_096
    assert not any(
        key.startswith(("applicationPort", "denseSharedSchedule"))
        for key in sha3_air
    )
    assert sha3_air["interactionPackingSelected"] is False
    assert sha3_air["proofSuiteId"] is None


def test_candidate_schema_is_strict_and_preserves_null_suite_identity() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["activationAllowed"] == {"const": False}
    assert schema["properties"]["proofSuiteId"] == {"type": "null"}
    assert schema["properties"]["candidateNativeHiding"]["properties"][
        "simulatorComplete"
    ] == {"const": False}
    assert schema["properties"]["candidateNativeHiding"]["properties"][
        "interfaceScheduleCurrent"
    ] == {"const": False}
    sha3_properties = schema["properties"]["candidateSha3Air"]["properties"]
    assert not any(
        key.startswith(("applicationPort", "denseSharedSchedule"))
        for key in sha3_properties
    )
    assert schema["properties"]["candidateSha3Air"]["properties"][
        "economicMapShardIndexBits"
    ] == {"const": 24}
    assert schema["properties"]["candidateSha3Air"]["properties"][
        "economicMapPaddingMaterialized"
    ] == {"const": False}
    assert schema["properties"]["candidateSha3Air"]["properties"][
        "interactionPackingSelected"
    ] == {"const": False}
    assert schema["properties"]["sidecar"]["properties"]["encodedLength"] == {"const": 744}
    for node in _walk(schema):
        if not isinstance(node, dict) or node.get("type") != "object" or "properties" not in node:
            continue
        assert node.get("additionalProperties") is False
        assert set(node.get("required", [])) == set(node["properties"])


def test_exact_12_field_abi_is_unchanged_and_separate_from_sidecar() -> None:
    abi = json.loads(ABI_PATH.read_text(encoding="utf-8"))
    assert [field["index"] for field in abi["fields"]] == list(range(12))
    assert [field["name"] for field in abi["fields"]] == EXPECTED_ABI
    assert {field["solidity_type"] for field in abi["fields"]} == {"bytes32"}
    assert _registry()["externalAbi"] == {
        "manifest": "ops/native_stark_public_inputs_v2.json",
        "fieldCount": 12,
        "fieldWidthBytes": 32,
        "changeAllowed": False,
    }


def test_sidecar_layout_is_contiguous_exact_and_round_trips() -> None:
    registry_fields = _registry()["sidecar"]["fields"]
    observed = tuple((field["name"], field["offset"], field["length"]) for field in registry_fields)
    assert observed == SIDECAR_LAYOUT
    cursor = 0
    for _, offset, length in observed:
        assert offset == cursor
        cursor += length
    assert cursor == SIDECAR_LENGTH == 744

    sidecar = _sidecar()
    encoded = sidecar.encode()
    assert CandidateSidecarV1.decode(encoded) == sidecar
    assert hashlib.sha3_512(encoded).hexdigest() == (
        "7f89cff891d4e8a54dad9657e516dd57a675bf6faf17994fea531dbbfb9efbec"
        "425f0f11af8a8dab7eea65c7101853e72ab2652098c05ca22b37e665bdde0a6b"
    )


def test_master_salt_replay_tag_and_active_alias_bindings_are_exact() -> None:
    sidecar = _sidecar()
    active = ActiveSuiteIdentityV1(
        profile_id=sidecar.profile_id,
        proof_suite_id=sidecar.proof_suite_id,
        schema_id=sidecar.schema_id,
        verifier_artifact_identity=sidecar.verifier_artifact_identity,
        strong_settlement_domain_id=sidecar.strong_settlement_domain_id,
        epoch=sidecar.epoch,
        legacy_protocol_version_alias=(2).to_bytes(32, "big"),
        legacy_settlement_domain_alias=(17).to_bytes(32, "big"),
    )
    public_outputs = [(2).to_bytes(32, "big"), (17).to_bytes(32, "big")]
    public_outputs.extend(index.to_bytes(32, "big") for index in range(2, 12))
    assert validate_active_binding(sidecar.encode(), public_outputs, active) == sidecar
    assert candidate_salt_use_tag(bytes([0xA5]) * 64).hex() == (
        "19efd77aca927b75afed0876e377870cf9ec7c30e30f9cd5cc196471e9897d0a"
        "f3d9c0cee84d5c59e01acc9f3abddb2134b63c42098ac930fc29b538bb759b4f"
    )


def test_domains_and_modules_have_no_duplicate_identity() -> None:
    registry = _registry()
    domains = registry["domainRegistry"]
    codes = [entry["code"] for entry in domains]
    names = [entry["name"] for entry in domains]
    assert len(codes) == len(set(codes))
    assert len(names) == len(set(names))
    module_kinds = [module["kind"] for module in registry["modules"]]
    assert len(module_kinds) == len(set(module_kinds)) == 8


def test_security_budget_registry_remains_draft_and_document_is_retired() -> None:
    policy = _registry()["securityPolicy"]
    assert policy == {
        "minimumQuantumWorkFactorBits": 128,
        "securityMeaning": "WORK_ADVANTAGE_PAIR_NOT_FAILURE_PROBABILITY",
        "maximumQuantumOracleQueryExponent": 128,
        "maximumLifetimeTargetExponent": 64,
        "maximumPositiveErrorTerms": 64,
        "minimumRoundErrorExponent": 256,
        "hashOutputBits": 512,
        "residualTargetExponent": 32,
        "perDisplayedBranchAdvantageExponentBeforeConstants": 58,
        "combinedDisplayedBoundExponentBeforeConstants": 57,
        "accountingMarginBitsBeforeConstants": 25,
        "grindingCreditBits": 0,
        "maximumConservativeDEffExponent": 111,
        "status": "POLICY_DRAFT_EXTERNAL_REVIEW_REQUIRED",
    }
    document = DOC_PATH.read_text(encoding="utf-8")
    assert document.startswith("# Retired architecture evidence")
    assert "not architecture, execution, security, or release authority" in document


def test_all_unresolved_security_decisions_remain_explicit_blockers() -> None:
    blocked = set(_registry()["blockedBy"])
    assert {
        "FINAL_AIR_DIMENSIONS_AND_D_EFF",
        "DEGREE16_PRODUCTION_ARITHMETIC_FROBENIUS_AND_CONSTANT_TIME_REVIEW",
        "PQ_PUBLIC_COIN_PRODUCTION_SIGNATURE_ADAPTERS",
        "PUBLIC_COIN_LIVENESS_AND_CONTRIBUTOR_GOVERNANCE",
        "INTERACTIVE_CIRCLE_STARK_THEOREM_AND_COMPLETE_CHALLENGE_SCHEDULE",
        "COMPLETE_NATIVE_HIDING_SIMULATOR",
        "PAYMENT_STATE_IMPLEMENTATION_PARITY",
        "EXTERNAL_CRYPTOGRAPHIC_REVIEW",
        "STRONG_REPLAY_REGISTRY_IMPLEMENTATION_PARITY",
        "ACTIVE_ID_AND_ALIAS_BINDING_IMPLEMENTATION_PARITY",
    }.issubset(blocked)
    assert "APPLICABLE_QROM_THEOREM_AND_CONSTANTS" not in blocked
    assert "DEGREE16_TOWER_AND_BASIS" not in blocked
    assert _registry()["candidateFri"]["queryCount"] is None
    assert _registry()["candidateAlgebra"]["irreduciblePolynomial"] == [
        "X^2+1",
        "X^2-(2+i)",
        "X^2-u",
        "X^2-v",
    ]
    transcript = _registry()["candidateTranscript"]
    assert transcript["authoritativeMode"] == "PQ_AUTHENTICATED_PUBLIC_COIN_INTERACTIVE"
    assert transcript["fiatShamirAllowed"] is False
    assert transcript["qromReductionRequired"] is False
    assert transcript["fullSchedule"] is None
