from __future__ import annotations

import hashlib
import json
from pathlib import Path
from functools import lru_cache

import pytest

from app.batch.pq_suite_candidate import CandidateSidecarV1
from experiments.bl_pq512_crypto_foundation.built_audit_pending_release import (
    RELEASE_SCHEMA,
    ROOT,
    build_release_candidate_identity,
    qualify_release_candidate,
)
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    ENVELOPE_PREFIX_BYTES,
    MAX_ENVELOPE_BYTES,
    PROOF_PACKAGE_BYTES,
    ProductionCandidateError,
    ProductionProofEnvelope,
)


def _wide(label: str) -> bytes:
    return hashlib.sha3_512(label.encode("ascii")).digest()


def _sidecar(suite: bytes, schema: bytes, verifier: bytes) -> bytes:
    return CandidateSidecarV1(
        profile_id=_wide("profile"),
        proof_suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
        strong_settlement_domain_id=_wide("domain"),
        epoch=1,
        sequence_before=0,
        sequence_after=1,
        strong_nullifier_root_before=_wide("nullifier-before"),
        strong_nullifier_root_after=_wide("nullifier-after"),
        strong_governance_commitment=_wide("governance"),
        strong_payment_state_root_before=_wide("payment-before"),
        strong_payment_state_root_after=_wide("payment-after"),
        strong_batch_commitment=_wide("batch"),
    ).encode()


def _release_candidate(tmp_path: Path):
    artifacts: dict[str, Path] = {}
    for name in (
        "parameters",
        "program",
        "prover",
        "verifier",
        "transcript",
        "toolchain",
    ):
        path = tmp_path / name
        path.write_bytes(f"attacker-controlled-{name}".encode("ascii"))
        artifacts[name] = path
    sources = tuple(
        sorted(
            (
                ROOT
                / "experiments"
                / "bl_pq512_crypto_core"
                / "src"
                / "production_verifier.rs",
                ROOT
                / "experiments"
                / "bl_pq512_crypto_foundation"
                / "production_candidate.py",
            ),
            key=lambda path: path.relative_to(ROOT).as_posix(),
        )
    )
    return build_release_candidate_identity(
        proof_suite_id=_wide("attacker-candidate-suite"),
        proof_parameters=artifacts["parameters"],
        air_program=artifacts["program"],
        prover_executable=artifacts["prover"],
        verifier_executable=artifacts["verifier"],
        transcript_contract=artifacts["transcript"],
        toolchain=artifacts["toolchain"],
        source_files=sources,
        release_contract_schema=RELEASE_SCHEMA,
    )


@lru_cache(maxsize=1)
def _encoded() -> tuple[bytes, bytes, bytes, bytes]:
    suite = _wide("suite")
    schema = _wide("schema")
    verifier = _wide("verifier")
    envelope = ProductionProofEnvelope(
        suite_id=suite,
        schema_id=schema,
        verifier_artifact_identity=verifier,
        public_outputs=bytes(12 * 32),
        sidecar=_sidecar(suite, schema, verifier),
        proof_package=b"BLPQSPK1\x00\x02"
        + bytes(PROOF_PACKAGE_BYTES - len(b"BLPQSPK1\x00\x02")),
        transcript_evidence=b"transcript",
        evidence_commitment=_wide("evidence"),
    )
    return envelope.encode(), suite, schema, verifier


@pytest.mark.parametrize(
    ("offset", "replacement", "error"),
    (
        (0, b"X", "magic_invalid"),
        (9, b"\x01", "version_invalid"),
        (586, b"\x01", "sidecar_length_invalid"),
        (670, b"X", "sidecar_identity_mismatch"),
    ),
)
def test_prefix_substitution_rejected_before_body(
    tmp_path: Path, offset: int, replacement: bytes, error: str
) -> None:
    encoded, suite, schema, verifier = _encoded()
    mutated = bytearray(encoded)
    mutated[offset : offset + len(replacement)] = replacement
    path = tmp_path / "mutated.bin"
    path.write_bytes(mutated)
    with pytest.raises(ProductionCandidateError, match=error):
        ProductionProofEnvelope.read_file(
            path,
            evidence_commitment=_wide("evidence"),
            expected_suite_id=suite,
            expected_schema_id=schema,
            expected_verifier_artifact_identity=verifier,
        )


@pytest.mark.parametrize("mutation", ("truncate", "trailing", "zero_transcript"))
def test_exact_file_shape_rejects_truncation_and_trailing_bytes(
    tmp_path: Path, mutation: str
) -> None:
    encoded, suite, schema, verifier = _encoded()
    if mutation == "truncate":
        encoded = encoded[:-1]
    elif mutation == "trailing":
        encoded += b"X"
    else:
        proof_length = int.from_bytes(encoded[1334:1342], "big")
        offset = ENVELOPE_PREFIX_BYTES + proof_length
        encoded = encoded[:offset] + bytes(8) + encoded[offset + 8 :]
    path = tmp_path / "bad-shape.bin"
    path.write_bytes(encoded)
    with pytest.raises(ProductionCandidateError):
        ProductionProofEnvelope.read_file(
            path,
            evidence_commitment=_wide("evidence"),
            expected_suite_id=suite,
            expected_schema_id=schema,
            expected_verifier_artifact_identity=verifier,
        )


def test_claimed_large_body_is_rejected_from_length_before_allocation(tmp_path: Path) -> None:
    encoded, suite, schema, verifier = _encoded()
    claimed = MAX_ENVELOPE_BYTES - ENVELOPE_PREFIX_BYTES - 9
    mutated = encoded[:1334] + claimed.to_bytes(8, "big") + encoded[1342:]
    path = tmp_path / "claimed-large.bin"
    path.write_bytes(mutated)
    with pytest.raises(ProductionCandidateError, match="proof_length_invalid"):
        ProductionProofEnvelope.read_file(
            path,
            evidence_commitment=_wide("evidence"),
            expected_suite_id=suite,
            expected_schema_id=schema,
            expected_verifier_artifact_identity=verifier,
        )


def test_expected_identity_substitution_is_rejected(tmp_path: Path) -> None:
    encoded, _, schema, verifier = _encoded()
    path = tmp_path / "identity.bin"
    path.write_bytes(encoded)
    with pytest.raises(ProductionCandidateError, match="identity_mismatch"):
        ProductionProofEnvelope.read_file(
            path,
            evidence_commitment=_wide("evidence"),
            expected_suite_id=_wide("attacker-suite"),
            expected_schema_id=schema,
            expected_verifier_artifact_identity=verifier,
        )


def test_requester_cannot_self_pin_a_qualified_lb010_receipt(tmp_path: Path) -> None:
    candidate = _release_candidate(tmp_path)
    receipt = json.dumps(
        {
            "activationAllowed": False,
            "evidenceManifestSha3_512": _wide("invented-evidence").hex(),
            "globalProofSuiteId": None,
            "productionUsable": False,
            "proofSuiteId": candidate.proof_suite_id.hex(),
            "receiptVersion": "BL-PQ512-LB010-QUALIFICATION-RECEIPT-v1",
            "releaseCandidateIdentitySha3_512": (
                candidate.release_identity_sha3_512.hex()
            ),
            "status": "QUALIFIED",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    attacker_digest = hashlib.sha3_512(
        b"BL/PQ512/LB010/QUALIFICATION-RECEIPT/v1\x00" + receipt
    ).digest()
    with pytest.raises(
        ValueError, match="release_lb010_self_attested_receipt_forbidden"
    ):
        qualify_release_candidate(
            candidate,
            lb010_receipt=receipt,
            expected_receipt_sha3_512=attacker_digest,
        )
