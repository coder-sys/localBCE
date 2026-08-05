from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from experiments.bl_pq512_crypto_foundation.benchmark_evidence import canonical_json_bytes
from experiments.bl_pq512_crypto_foundation.h6_evidence_manifest import (
    H6EvidenceManifestError,
    _OBLIGATION_IDS,
    _check_identity,
    verify_h6_evidence_manifest,
)


ROOT = Path(__file__).resolve().parents[1]


def _check(*, obligation_id: str, status: str, stdout_path: str | None = None) -> dict[str, object]:
    if status == "CLOSED":
        assert stdout_path is not None
        stdout_file = Path(stdout_path)
        stdout = stdout_file.read_bytes()
        stdout_digest = hashlib.sha3_512(stdout).hexdigest()
        stdout_bytes = len(stdout)
        stderr_path = "stderr.empty"
        manifest_stdout_path = stdout_file.name
        exit_code: int | None = 0
        blockers: list[str] = []
    else:
        stdout_digest = "0" * 128
        stdout_bytes = 0
        stderr_path = None
        manifest_stdout_path = None
        exit_code = None
        blockers = ["not_collected"]
    check: dict[str, object] = {
        "blockers": blockers,
        "command": "test evidence command",
        "evidenceClass": "OBSERVED",
        "evidenceIdentitySha3_512": "0" * 128,
        "exitCode": exit_code,
        "obligationId": obligation_id,
        "sourceId": "test-source",
        "status": status,
        "stderrBytes": 0,
        "stderrPath": stderr_path,
        "stderrSha3_512": hashlib.sha3_512(b"").hexdigest()
        if status == "CLOSED"
        else "0" * 128,
        "stdoutBytes": stdout_bytes,
        "stdoutPath": manifest_stdout_path,
        "stdoutSha3_512": stdout_digest,
    }
    check["evidenceIdentitySha3_512"] = _check_identity(check)
    return check


def _write_manifest(tmp_path: Path, *, closed: bool = True) -> Path:
    evidence = tmp_path / "attack.stdout"
    evidence.write_bytes(b"attack_file_count=31\n31 passed\n")
    (tmp_path / "stderr.empty").write_bytes(b"")
    source_files = []
    for relative in (
        "experiments/bl_pq512_crypto_foundation/h6_evidence_manifest.py",
        "experiments/bl_pq512_crypto_foundation/h6_qualification_preflight.py",
    ):
        path = ROOT / relative
        source_files.append(
            {
                "path": relative,
                "sha3_512": hashlib.sha3_512(path.read_bytes()).hexdigest(),
                "size": path.stat().st_size,
            }
        )
    checks = [
        _check(
            obligation_id=obligation_id,
            status=("CLOSED" if closed and index == 3 else "OPEN"),
            stdout_path=str(evidence) if closed and index == 3 else None,
        )
        for index, obligation_id in enumerate(_OBLIGATION_IDS)
    ]
    value = {
        "activationAllowed": False,
        "checks": checks,
        "manifestVersion": 1,
        "proofSuiteId": None,
        "schema": "BL-PQ512-H6-EVIDENCE-MANIFEST-v1",
        "sourceFiles": source_files,
        "status": "NONACTIVATING",
    }
    path = tmp_path / "manifest.json"
    path.write_bytes(canonical_json_bytes(value) + b"\n")
    return path


def test_h6_manifest_verifies_raw_and_source_readback(tmp_path: Path) -> None:
    facts = verify_h6_evidence_manifest(_write_manifest(tmp_path))
    assert facts.closed_obligations == (_OBLIGATION_IDS[3],)
    assert len(facts.manifest_digest_512) == 64
    assert facts.check_identity(_OBLIGATION_IDS[3])


def test_h6_manifest_rejects_mutated_raw_evidence(tmp_path: Path) -> None:
    path = _write_manifest(tmp_path)
    (tmp_path / "attack.stdout").write_bytes(b"tampered\n")
    with pytest.raises(H6EvidenceManifestError, match="raw_readback_mismatch"):
        verify_h6_evidence_manifest(path)


def test_h6_manifest_rejects_noncanonical_json(tmp_path: Path) -> None:
    path = _write_manifest(tmp_path)
    value = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    with pytest.raises(H6EvidenceManifestError, match="not_canonical"):
        verify_h6_evidence_manifest(path)
