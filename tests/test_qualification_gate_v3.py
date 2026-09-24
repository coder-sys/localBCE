from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from tools import qualification_gate as v2_gate
from tools import qualification_gate_v3 as gate


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "qualification_gate_v3"
BLOCKERS = ROOT / "ops" / "launch_blockers.json"
NOW = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)

MODE_FIXTURES = {
    gate.DIRECT_STATE_OWNED: (
        "profile-direct-state-owned.json",
        "evidence-direct-state-owned.json",
    ),
    gate.AUTHORITATIVE_ASSERTION: (
        "profile-authoritative-assertion.json",
        "evidence-authoritative-assertion.json",
    ),
    gate.PRIVATE_ZK: (
        "profile-private-zk.json",
        "evidence-private-zk.json",
    ),
}


def _fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _pair(mode: str) -> tuple[bytes, bytes]:
    profile_name, evidence_name = MODE_FIXTURES[mode]
    return _fixture_bytes(profile_name), _fixture_bytes(evidence_name)


def _document(raw: bytes) -> dict[str, object]:
    return json.loads(raw)


def _encode(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _evaluate(
    mode: str,
    *,
    profile_raw: bytes | None = None,
    evidence_raw: bytes | None = None,
    now: datetime | str = NOW,
) -> dict[str, object]:
    fixture_profile, fixture_evidence = _pair(mode)
    return gate.evaluate(
        BLOCKERS.read_bytes(),
        fixture_profile if profile_raw is None else profile_raw,
        fixture_evidence if evidence_raw is None else evidence_raw,
        now=now,
    )


def test_current_blockers_remain_open_in_every_synthetic_example() -> None:
    document = json.loads(BLOCKERS.read_bytes())
    assert document["schema_version"] == v2_gate.BLOCKER_SCHEMA
    assert len(document["blockers"]) == len(v2_gate.BLOCKER_IDENTITY) == 8
    assert all(item["status"] == "open" for item in document["blockers"])
    assert all(item["evidenceSha3_512"] is None for item in document["blockers"])


@pytest.mark.parametrize("mode", tuple(MODE_FIXTURES))
def test_synthetic_mode_fixtures_are_structural_only_and_never_qualify(
    mode: str,
) -> None:
    result = _evaluate(mode)

    assert result["candidate_mode"] == mode
    assert result["selection_state"] == "UNSELECTED"
    assert result["qualification_state"] == "NOT_QUALIFIED"
    assert result["activation_state"] == "INACTIVE"
    assert result["proofSuiteId"] is None
    assert result["production_usable"] is False
    assert result["activation"] is False
    assert result["synthetic_only"] is True
    assert result["nonoperative"] is True
    assert result["profile_approval_validation"] == "UNVERIFIED_OFFLINE"
    assert result["mode_evidence_validation"] == "STRUCTURE_AND_BINDING_ONLY"
    assert result["v2_gate_status"] == "UNCHANGED_OPERATIVE_NO_SUBSTITUTION"
    source_binding = result["blocker_source_binding"]
    assert source_binding["binding_scope"] == "TRACKED_CHECKOUT_COPY_ONLY"
    assert source_binding["source"] == "ops/launch_blockers.json"
    assert (
        source_binding["authority_status"]
        == "VERIFIED_TRACKED_SHA3_512_AUTHORITY"
    )
    assert source_binding["supplied_matches_source"] is True
    assert (
        source_binding["source_sha3_512"]
        == source_binding["supplied_sha3_512"]
    )
    assert result["v2_open_qualification_blockers"] == [
        item[0] for item in v2_gate.BLOCKER_IDENTITY[:6]
    ]
    assert result["v2_open_activation_blockers"] == [
        item[0] for item in v2_gate.BLOCKER_IDENTITY[6:]
    ]


@pytest.mark.parametrize(
    ("mode", "throughput_decision", "mode_specific_field"),
    (
        (
            gate.DIRECT_STATE_OWNED,
            "DECISION_REQUIRED",
            "snapshot_artifact_sha3_512",
        ),
        (
            gate.AUTHORITATIVE_ASSERTION,
            "DECISION_REQUIRED",
            "signed_payload_sha3_512",
        ),
        (gate.PRIVATE_ZK, "REQUIRED", "proof_artifact_sha3_512"),
    ),
)
def test_each_evidence_mode_has_its_declared_shape_and_applicability(
    mode: str, throughput_decision: str, mode_specific_field: str
) -> None:
    profile_raw, evidence_raw = _pair(mode)
    profile = gate.parse_profile(profile_raw)
    evidence = gate.parse_evidence(evidence_raw)

    assert profile["candidate_mode"] == mode
    assert evidence["candidate_mode"] == mode
    assert profile["provenance_model"] == gate.PROVENANCE_MODELS[mode]
    assert (
        profile["proof_throughput_applicability"]["decision"]
        == throughput_decision
    )
    assert mode_specific_field in evidence["mode_evidence"]


def test_tampered_caller_blocker_bytes_reject_even_when_v2_shape_is_valid() -> None:
    profile, evidence = _pair(gate.DIRECT_STATE_OWNED)
    changed = _document(BLOCKERS.read_bytes())
    changed["blockers"][0]["status"] = "closed"
    changed["blockers"][0]["evidenceSha3_512"] = "a" * 128
    tampered = _encode(changed)

    assert v2_gate.parse_blockers(tampered)[0]["status"] == "closed"
    with pytest.raises(gate.QualificationGateV3Error):
        gate.evaluate(tampered, profile, evidence, now=NOW)


def test_missing_canonical_ops_authority_rejects(monkeypatch) -> None:
    profile, evidence = _pair(gate.DIRECT_STATE_OWNED)

    def missing_authority() -> str:
        raise FileNotFoundError("synthetic missing ops authority")

    monkeypatch.setattr(
        gate.ops_authority, "verify_ops_authority", missing_authority
    )
    with pytest.raises(gate.QualificationGateV3Error):
        gate.evaluate(BLOCKERS.read_bytes(), profile, evidence, now=NOW)


@pytest.mark.parametrize("location", ("profile", "evidence"))
def test_unknown_candidate_mode_rejects(location: str) -> None:
    profile, evidence = _pair(gate.DIRECT_STATE_OWNED)
    if location == "profile":
        changed = _document(profile)
        changed["candidate_mode"] = "UNKNOWN_MODE"
        profile = _encode(changed)
    else:
        changed = _document(evidence)
        changed["candidate_mode"] = "UNKNOWN_MODE"
        evidence = _encode(changed)

    with pytest.raises(gate.QualificationGateV3Error):
        gate.evaluate(BLOCKERS.read_bytes(), profile, evidence, now=NOW)


@pytest.mark.parametrize(
    "mode",
    (gate.DIRECT_STATE_OWNED, gate.AUTHORITATIVE_ASSERTION),
)
def test_nonprivate_soundness_does_not_close_the_v2_blocker(mode: str) -> None:
    result = _evaluate(mode)

    assert result["proofSoundnessApplicability"] == "NOT_APPLICABLE_TO_CANDIDATE_MODE"
    assert "BL-PROOF-SOUNDNESS" in result["v2_open_qualification_blockers"]
    assert "BL-PROOF-SOUNDNESS" not in result["applicable_open_qualification_blockers"]
    assert result["proofThroughputApplicability"] == "DECISION_REQUIRED"
    assert result["throughput_applicability_validation"] == "DECISION_REQUIRED"
    assert "BL-PROOF-THROUGHPUT" in result["applicable_open_qualification_blockers"]
    assert "PROOF_THROUGHPUT_APPLICABILITY_AUTHORIZATION" in result["v3_review_open"]


def test_private_mode_keeps_soundness_and_throughput_required() -> None:
    result = _evaluate(gate.PRIVATE_ZK)

    assert result["proofSoundnessApplicability"] == "REQUIRED"
    assert result["proofThroughputApplicability"] == "REQUIRED"
    assert "BL-PROOF-SOUNDNESS" in result["applicable_open_qualification_blockers"]
    assert "BL-PROOF-THROUGHPUT" in result["applicable_open_qualification_blockers"]


def test_wrong_profile_id_rejects() -> None:
    profile, evidence = _pair(gate.DIRECT_STATE_OWNED)
    changed = _document(evidence)
    changed["profile_id"] = "SYNTH-WRONG-PROFILE"

    with pytest.raises(gate.QualificationGateV3Error):
        _evaluate(
            gate.DIRECT_STATE_OWNED,
            profile_raw=profile,
            evidence_raw=_encode(changed),
        )


def test_cross_mode_artifact_and_private_failure_cannot_downgrade() -> None:
    private_profile, _ = _pair(gate.PRIVATE_ZK)
    _, direct_evidence = _pair(gate.DIRECT_STATE_OWNED)
    changed_evidence = _document(direct_evidence)
    changed_evidence["profile_id"] = _document(private_profile)["profile_id"]

    with pytest.raises(gate.QualificationGateV3Error):
        _evaluate(
            gate.PRIVATE_ZK,
            profile_raw=private_profile,
            evidence_raw=_encode(changed_evidence),
        )

    # A separately supplied non-private candidate is still unselected and
    # cannot turn a failed private-proof attempt into qualification.
    later_mode = _evaluate(gate.DIRECT_STATE_OWNED)
    assert later_mode["selection_state"] == "UNSELECTED"
    assert later_mode["qualification_state"] == "NOT_QUALIFIED"
    assert later_mode["activation"] is False

    assertion_profile, assertion_evidence = _pair(gate.AUTHORITATIVE_ASSERTION)
    changed_mode = _document(assertion_evidence)
    changed_mode["candidate_mode"] = gate.DIRECT_STATE_OWNED
    with pytest.raises(gate.QualificationGateV3Error):
        _evaluate(
            gate.AUTHORITATIVE_ASSERTION,
            profile_raw=assertion_profile,
            evidence_raw=_encode(changed_mode),
        )


def test_reused_private_proof_or_request_rejects() -> None:
    profile, evidence = _pair(gate.PRIVATE_ZK)
    changed = _document(evidence)
    mode_evidence = changed["mode_evidence"]
    mode_evidence["proof_use_state"]["used_proof_artifact_sha3_512s"] = [
        mode_evidence["proof_artifact_sha3_512"]
    ]
    mode_evidence["proof_use_state"]["used_proof_request_ids"] = [
        mode_evidence["proof_request_id"]
    ]

    with pytest.raises(gate.QualificationGateV3Error):
        _evaluate(
            gate.PRIVATE_ZK,
            profile_raw=profile,
            evidence_raw=_encode(changed),
        )


def test_stale_profile_and_evidence_intervals_reject() -> None:
    with pytest.raises(gate.QualificationGateV3Error):
        _evaluate(gate.DIRECT_STATE_OWNED, now="2027-01-01T00:00:00Z")


def test_missing_approver_rejects() -> None:
    profile, evidence = _pair(gate.DIRECT_STATE_OWNED)
    changed = _document(profile)
    del changed["approval_claim"]["approver_id"]

    with pytest.raises(gate.QualificationGateV3Error):
        _evaluate(
            gate.DIRECT_STATE_OWNED,
            profile_raw=_encode(changed),
            evidence_raw=evidence,
        )


def test_missing_private_proof_artifact_rejects() -> None:
    profile, evidence = _pair(gate.PRIVATE_ZK)
    changed = _document(evidence)
    del changed["mode_evidence"]["proof_artifact_sha3_512"]

    with pytest.raises(gate.QualificationGateV3Error):
        _evaluate(
            gate.PRIVATE_ZK,
            profile_raw=profile,
            evidence_raw=_encode(changed),
        )


def test_duplicate_nested_json_keys_reject() -> None:
    profile, _ = _pair(gate.DIRECT_STATE_OWNED)
    duplicated = profile.replace(
        b'"program_id": "SYNTH-PROGRAM"',
        b'"program_id": "SYNTH-PROGRAM", "program_id": "SYNTH-PROGRAM"',
        1,
    )
    assert duplicated != profile

    with pytest.raises(gate.QualificationGateV3Error):
        gate.parse_profile(duplicated)


@pytest.mark.parametrize("location", ("profile", "evidence"))
def test_unknown_fields_reject_at_nested_boundaries(location: str) -> None:
    profile, evidence = _pair(gate.DIRECT_STATE_OWNED)
    if location == "profile":
        changed = _document(profile)
        changed["approval_claim"]["unexpected"] = "SYNTH-UNKNOWN"
        profile = _encode(changed)
    else:
        changed = _document(evidence)
        changed["mode_evidence"]["fallback_mode"] = gate.PRIVATE_ZK
        evidence = _encode(changed)

    with pytest.raises(gate.QualificationGateV3Error):
        _evaluate(
            gate.DIRECT_STATE_OWNED,
            profile_raw=profile,
            evidence_raw=evidence,
        )


@pytest.mark.parametrize("field", ("release_sha3_512", "control_set_sha3_512"))
def test_false_release_or_control_set_binding_rejects(field: str) -> None:
    profile, evidence = _pair(gate.DIRECT_STATE_OWNED)
    changed = _document(evidence)
    changed["release_binding"][field] = "0" * 128

    with pytest.raises(gate.QualificationGateV3Error):
        _evaluate(
            gate.DIRECT_STATE_OWNED,
            profile_raw=profile,
            evidence_raw=_encode(changed),
        )


def test_asserted_not_applicable_throughput_stays_unverified() -> None:
    profile, evidence = _pair(gate.AUTHORITATIVE_ASSERTION)
    changed = _document(profile)
    changed["proof_throughput_applicability"] = {
        "decision": "NOT_APPLICABLE",
        "basis": "STATE_AND_ENGINEERING_APPROVAL_REQUIRED",
        "decision_id": "SYNTH-THROUGHPUT-DECISION-001",
        "state_approver_id": "SYNTH-STATE-APPROVER",
        "engineering_approver_id": "SYNTH-ENGINEERING-APPROVER",
        "valid_from": "2026-09-01T00:00:00Z",
        "valid_until": "2026-10-01T00:00:00Z",
        "state_attestation_sha3_512": "1" * 128,
        "engineering_attestation_sha3_512": "2" * 128,
    }
    changed["approval_claim"]["profile_binding"][
        "proof_throughput_applicability"
    ] = changed["proof_throughput_applicability"]
    result = _evaluate(
        gate.AUTHORITATIVE_ASSERTION,
        profile_raw=_encode(changed),
        evidence_raw=evidence,
    )

    assert result["qualification_state"] == "NOT_QUALIFIED"
    assert result["throughput_applicability_validation"] == "DECISION_ASSERTED_BUT_UNVERIFIED"
    assert "PROOF_THROUGHPUT_APPLICABILITY_AUTHORIZATION" in result["v3_review_open"]
    assert "BL-PROOF-THROUGHPUT" in result["applicable_open_qualification_blockers"]


@pytest.mark.parametrize(
    "mode,field",
    (
        (gate.DIRECT_STATE_OWNED, "attestation_key_id"),
        (gate.AUTHORITATIVE_ASSERTION, "signing_key_id"),
    ),
)
def test_mode_specific_attestation_identity_mismatch_rejects(
    mode: str, field: str
) -> None:
    profile, evidence = _pair(mode)
    changed = _document(evidence)
    changed["mode_evidence"][field] = "SYNTH-WRONG-KEY"

    with pytest.raises(gate.QualificationGateV3Error):
        _evaluate(mode, profile_raw=profile, evidence_raw=_encode(changed))


def test_cli_is_explicit_read_only_inspection_with_no_fallback_option(capsys) -> None:
    profile_path, evidence_path = MODE_FIXTURES[gate.DIRECT_STATE_OWNED]
    code = gate.main(
        [
            "inspect",
            "--blockers",
            str(BLOCKERS.resolve()),
            "--profile",
            str((FIXTURES / profile_path).resolve()),
            "--evidence",
            str((FIXTURES / evidence_path).resolve()),
        ]
    )
    captured = capsys.readouterr()

    assert code == 0
    result = json.loads(captured.out)
    assert captured.err == ""
    assert result["qualification_state"] == "NOT_QUALIFIED"
    assert result["selection_state"] == "UNSELECTED"
    assert result["activation"] is False

    rejected = gate.main(
        [
            "inspect",
            "--blockers",
            str(BLOCKERS.resolve()),
            "--profile",
            str((FIXTURES / profile_path).resolve()),
            "--evidence",
            str((FIXTURES / evidence_path).resolve()),
            "--fallback-mode",
            gate.PRIVATE_ZK,
        ]
    )
    rejected_output = capsys.readouterr()
    assert rejected == 2
    assert rejected_output.out == ""
    assert rejected_output.err == "qualification_gate_v3=invalid\n"
