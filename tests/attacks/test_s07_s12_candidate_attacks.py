from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest

from app.batch.pq_suite_candidate import (
    ActiveSuiteIdentityV1,
    CandidateSidecarV1,
    candidate_salt_use_tag,
    validate_active_binding,
    validate_unqualified_registry,
)


ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "docs" / "bl_pq512_suite_candidate_v1.json"


def _registry() -> dict:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def _sidecar() -> CandidateSidecarV1:
    values = [bytes([index]) * 64 for index in range(1, 12)]
    return CandidateSidecarV1(
        values[0],
        values[1],
        values[2],
        values[3],
        values[4],
        7,
        41,
        42,
        values[5],
        values[6],
        values[7],
        values[8],
        values[9],
        values[10],
    )


def _active(sidecar: CandidateSidecarV1) -> ActiveSuiteIdentityV1:
    return ActiveSuiteIdentityV1(
        sidecar.profile_id,
        sidecar.proof_suite_id,
        sidecar.schema_id,
        sidecar.verifier_artifact_identity,
        sidecar.strong_settlement_domain_id,
        sidecar.epoch,
        (2).to_bytes(32, "big"),
        (17).to_bytes(32, "big"),
    )


def _public_outputs() -> list[bytes]:
    return [(2).to_bytes(32, "big"), (17).to_bytes(32, "big")] + [
        index.to_bytes(32, "big") for index in range(2, 12)
    ]


def test_candidate_registry_rejects_activation_or_invented_suite_ids() -> None:
    registry = _registry()
    activated = copy.deepcopy(registry)
    activated["activationAllowed"] = True
    with pytest.raises(ValueError, match="activation_must_be_false"):
        validate_unqualified_registry(activated)

    invented = copy.deepcopy(registry)
    invented["proofSuiteId"] = "00" * 64
    with pytest.raises(ValueError, match="suite_id_must_be_unset"):
        validate_unqualified_registry(invented)


def test_candidate_registry_rejects_layout_gaps_overlap_and_duplicate_domains() -> None:
    for field_index, offset in ((5, 81), (6, 143)):
        mutated = copy.deepcopy(_registry())
        mutated["sidecar"]["fields"][field_index]["offset"] = offset
        with pytest.raises(ValueError, match="sidecar_layout_invalid"):
            validate_unqualified_registry(mutated)

    duplicate_code = copy.deepcopy(_registry())
    duplicate_code["domainRegistry"][1]["code"] = duplicate_code["domainRegistry"][0]["code"]
    with pytest.raises(ValueError, match="domain_code_duplicate"):
        validate_unqualified_registry(duplicate_code)

    duplicate_name = copy.deepcopy(_registry())
    duplicate_name["domainRegistry"][1]["name"] = duplicate_name["domainRegistry"][0]["name"]
    with pytest.raises(ValueError, match="domain_name_duplicate"):
        validate_unqualified_registry(duplicate_name)


def test_candidate_registry_rejects_semantic_mutations_and_malformed_entries() -> None:
    field_type = copy.deepcopy(_registry())
    field_type["sidecar"]["fields"][0]["type"] = "NONZERO_BYTES64"
    with pytest.raises(ValueError, match="sidecar_layout_invalid"):
        validate_unqualified_registry(field_type)

    module_status = copy.deepcopy(_registry())
    module_status["modules"][0]["status"] = "UNSELECTED"
    with pytest.raises(ValueError, match="module_status_invalid"):
        validate_unqualified_registry(module_status)

    hiding = copy.deepcopy(_registry())
    hiding["candidateNativeHiding"]["simulatorComplete"] = True
    with pytest.raises(ValueError, match="native_hiding_mismatch"):
        validate_unqualified_registry(hiding)

    stale_hiding = copy.deepcopy(_registry())
    stale_hiding["candidateNativeHiding"]["interfaceScheduleCurrent"] = True
    with pytest.raises(ValueError, match="native_hiding_mismatch"):
        validate_unqualified_registry(stale_hiding)

    sha3_air = copy.deepcopy(_registry())
    sha3_air["candidateSha3Air"]["interactionPackingSelected"] = True
    with pytest.raises(ValueError, match="sha3_air_mismatch"):
        validate_unqualified_registry(sha3_air)

    malformed_module = copy.deepcopy(_registry())
    malformed_module["modules"][0] = "ENCODING_FRAMING"
    with pytest.raises(ValueError, match="module_entry_invalid"):
        validate_unqualified_registry(malformed_module)

    blockers = copy.deepcopy(_registry())
    blockers["blockedBy"] = ["INVENTED_BLOCKER"] * 10
    with pytest.raises(ValueError, match="canonical_digest_mismatch"):
        validate_unqualified_registry(blockers)

    domain = copy.deepcopy(_registry())
    domain["domainRegistry"][0]["name"] = "BL/PQ512/v1/ID/INVENTED"
    with pytest.raises(ValueError, match="canonical_digest_mismatch"):
        validate_unqualified_registry(domain)


def test_sidecar_rejects_truncation_trailing_header_mutation_and_zero_ids() -> None:
    encoded = _sidecar().encode()
    for malformed in (encoded[:-1], encoded + b"\x00"):
        with pytest.raises(ValueError, match="length_mismatch"):
            CandidateSidecarV1.decode(malformed)

    mutations = (
        (0, b"X", "magic_mismatch"),
        (9, b"\x02", "version_mismatch"),
        (11, b"\x01", "flags_mismatch"),
        (15, b"\x00", "declared_length_mismatch"),
    )
    for offset, replacement, error in mutations:
        malformed = encoded[:offset] + replacement + encoded[offset + 1 :]
        with pytest.raises(ValueError, match=error):
            CandidateSidecarV1.decode(malformed)

    zero_suite = encoded[:80] + bytes(64) + encoded[144:]
    with pytest.raises(ValueError, match="proof_suite_id_must_be_nonzero"):
        CandidateSidecarV1.decode(zero_suite)


def test_sidecar_rejects_sequence_root_and_payment_state_replay() -> None:
    sidecar = _sidecar()
    with pytest.raises(ValueError, match="sequence_transition_invalid"):
        replace(sidecar, sequence_after=sidecar.sequence_before)
    with pytest.raises(ValueError, match="sequence_transition_invalid"):
        replace(sidecar, sequence_before=(1 << 64) - 1, sequence_after=0)
    with pytest.raises(ValueError, match="nullifier_root_unchanged"):
        replace(sidecar, strong_nullifier_root_after=sidecar.strong_nullifier_root_before)
    with pytest.raises(ValueError, match="payment_state_root_unchanged"):
        replace(sidecar, strong_payment_state_root_after=sidecar.strong_payment_state_root_before)


def test_active_tuple_rejects_mixed_ids_and_legacy_aliases_before_proof_work() -> None:
    sidecar = _sidecar()
    active = _active(sidecar)
    outputs = _public_outputs()

    mixed = replace(sidecar, schema_id=bytes([0xEE]) * 64)
    with pytest.raises(ValueError, match="active_schema_id_mismatch"):
        validate_active_binding(mixed.encode(), outputs, active)

    wrong_domain = outputs.copy()
    wrong_domain[1] = (18).to_bytes(32, "big")
    with pytest.raises(ValueError, match="settlement_domain_alias_mismatch"):
        validate_active_binding(sidecar.encode(), wrong_domain, active)

    wrong_protocol = outputs.copy()
    wrong_protocol[0] = (3).to_bytes(32, "big")
    with pytest.raises(ValueError, match="protocol_alias_mismatch"):
        validate_active_binding(sidecar.encode(), wrong_protocol, active)


def test_master_salt_reuse_tag_cannot_be_changed_by_context() -> None:
    salt = bytes([0xA5]) * 64
    baseline = candidate_salt_use_tag(salt)
    assert baseline == candidate_salt_use_tag(salt)
    changed = bytearray(salt)
    changed[-1] ^= 1
    assert candidate_salt_use_tag(bytes(changed)) != baseline
    with pytest.raises(ValueError, match="must_be_nonzero"):
        candidate_salt_use_tag(bytes(64))
