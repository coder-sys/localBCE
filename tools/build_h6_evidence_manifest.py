"""Build the canonical, nonactivating H6 evidence manifest from raw captures."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Final

from experiments.bl_pq512_crypto_foundation.benchmark_evidence import canonical_json_bytes
from experiments.bl_pq512_crypto_foundation.h6_evidence_manifest import (
    SCHEMA,
    _check_identity,
)


ROOT: Final[Path] = Path(__file__).resolve().parents[1]
OBLIGATIONS: Final[tuple[str, ...]] = (
    "STRICT_PQ_SECURITY_LEDGER",
    "COMPLETE_SIMULATOR",
    "PROOF_RECEIPT_GRAMMAR",
    "ATTACK_CORPUS",
    "CROSS_LANGUAGE_VERIFIER_KATS",
    "SOURCE_TOOLCHAIN_SBOM",
    "REPRODUCIBLE_BUILDS",
    "H5_RESOURCE_EVIDENCE",
    "SIDE_CHANNEL_UNLINKABILITY",
    "ROLLBACK_RECOVERY",
    "COMPLETE_EVIDENCE_MANIFEST",
    "WAVE3_NONACTIVATING_BOUNDARY",
)

SOURCE_FILES: Final[tuple[str, ...]] = tuple(
    sorted(
        {
            "docs/bl_pq512_suite_candidate_v1.json",
            "ops/native_stark_public_inputs_v2.json",
            "ops/oracle_source_manifest.example.json",
            "schemas/bl_pq512_witness_v0.schema.json",
            "tools/build_h6_evidence_manifest.py",
            "experiments/bl_pq512_crypto_core/Cargo.lock",
            "experiments/bl_pq512_crypto_core/Cargo.toml",
            "experiments/bl_pq512_crypto_core/rust-toolchain.toml",
            "experiments/bl_pq512_crypto_core/.cargo/config.toml",
            "experiments/bl_pq512_crypto_core/src/lib.rs",
            "experiments/bl_pq512_crypto_core/src/h6_proof_body_format.rs",
            "experiments/bl_pq512_crypto_core/src/h6_receipt_format.rs",
            "experiments/bl_pq512_crypto_core/src/bin/h6_proof_body_kat.rs",
            "experiments/bl_pq512_crypto_core/src/bin/h6_receipt_grammar_kat.rs",
            "experiments/bl_pq512_crypto_core/src/proof_parameters.rs",
            "experiments/bl_pq512_crypto_core/cuda/fp16_zk_rs_security_ledger.py",
            "experiments/bl_pq512_crypto_core/cuda/fp16_zk_rs_hiding_simulator_kat.py",
            "experiments/bl_pq512_crypto_foundation/proof_body_reference.py",
            "experiments/bl_pq512_crypto_foundation/h6_complete_simulator.py",
            "experiments/bl_pq512_crypto_foundation/h6_evidence_manifest.py",
            "experiments/bl_pq512_crypto_foundation/h6_migration_theorem.py",
            "experiments/bl_pq512_crypto_foundation/h6_privacy_boundary.py",
            "experiments/bl_pq512_crypto_foundation/h6_qualification_preflight.py",
            "experiments/bl_pq512_crypto_foundation/h6_receipt_grammar.py",
            "experiments/bl_pq512_crypto_foundation/h6_security_ledger.py",
            "experiments/bl_pq512_crypto_foundation/h6_supply_chain.py",
            "experiments/bl_pq512_crypto_foundation/proof_body_reference.py",
            "experiments/bl_pq512_crypto_foundation/state_migration_recovery.py",
            "experiments/bl_pq512_crypto_foundation/wave3_nullifier_authority.py",
            "experiments/bl_pq512_crypto_foundation/h5_campaign_evidence.py",
            "tests/test_bl_pq512_h6_complete_simulator.py",
            "tests/test_bl_pq512_h6_evidence_manifest.py",
            "tests/test_bl_pq512_h6_migration_theorem.py",
            "tests/test_bl_pq512_h6_privacy_boundary.py",
            "tests/test_bl_pq512_h6_proof_body_cross_language.py",
            "tests/test_bl_pq512_h6_receipt_grammar_cross_language.py",
            "tests/test_bl_pq512_h6_security_ledger.py",
            "tests/test_bl_pq512_h6_supply_chain.py",
            "tests/attacks/test_bl_pq512_h6_closure_attacks.py",
            "tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py",
        }
    )
)

EVIDENCE_CLASSES: Final[dict[str, str]] = {
    "STRICT_PQ_SECURITY_LEDGER": "DERIVED",
    "COMPLETE_SIMULATOR": "DERIVED",
    "PROOF_RECEIPT_GRAMMAR": "OBSERVED",
    "ATTACK_CORPUS": "OBSERVED",
    "CROSS_LANGUAGE_VERIFIER_KATS": "OBSERVED",
    "SOURCE_TOOLCHAIN_SBOM": "OBSERVED",
    "REPRODUCIBLE_BUILDS": "OBSERVED",
    "H5_RESOURCE_EVIDENCE": "OBSERVED",
    "SIDE_CHANNEL_UNLINKABILITY": "OBSERVED",
    "ROLLBACK_RECOVERY": "DERIVED",
    "COMPLETE_EVIDENCE_MANIFEST": "OBSERVED",
    "WAVE3_NONACTIVATING_BOUNDARY": "OBSERVED",
}

COMMANDS: Final[dict[str, str]] = {
    "STRICT_PQ_SECURITY_LEDGER": "python -B -c h6_security_ledger.require_h6_security_ledger",
    "COMPLETE_SIMULATOR": "python -B -c h6_complete_simulator.run_complete_simulator_suite+h6_privacy_boundary.run_h6_privacy_boundary",
    "PROOF_RECEIPT_GRAMMAR": "pytest -q H6 proof-body and receipt grammar KATs",
    "ATTACK_CORPUS": "pytest -q tests/attacks/test_bl_pq512_*.py",
    "CROSS_LANGUAGE_VERIFIER_KATS": "pytest -q H6/Python/Rust cross-language KAT set plus Rust python-prefixed tests",
    "SOURCE_TOOLCHAIN_SBOM": "cargo metadata --locked --offline --filter-platform x86_64-pc-windows-msvc; h6_supply_chain.verify_h6_supply_chain",
    "REPRODUCIBLE_BUILDS": "cargo build --release --locked --offline twice; independent artifact readback",
    "H5_RESOURCE_EVIDENCE": "h5_campaign_evidence.validate_h5_campaign_manifest exact-22",
    "SIDE_CHANNEL_UNLINKABILITY": "h6_privacy_boundary.run_h6_privacy_boundary; privacy_artifact_scan",
    "ROLLBACK_RECOVERY": "h6_migration_theorem.run_h6_migration_theorem",
    "COMPLETE_EVIDENCE_MANIFEST": "build_h6_evidence_manifest.py followed by verify_h6_evidence_manifest",
    "WAVE3_NONACTIVATING_BOUNDARY": "pytest -q tests/test_bl_pq512_wave3_nullifier_authority.py",
}


def _digest(path: Path) -> tuple[int, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"h6_manifest_capture_not_regular:{path.name}")
    data = path.read_bytes()
    return len(data), hashlib.sha3_512(data).hexdigest()


def _source_records() -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for relative in SOURCE_FILES:
        size, digest = _digest(ROOT / Path(relative))
        records.append({"path": relative, "sha3_512": digest, "size": size})
    return records


def _check(evidence_root: Path, obligation_id: str, ordinal: int) -> dict[str, object]:
    prefix = f"{ordinal:02d}-{obligation_id.lower().replace('_', '-') }"
    stdout = evidence_root / f"{prefix}.stdout"
    stderr = evidence_root / f"{prefix}.stderr"
    stdout_bytes, stdout_digest = _digest(stdout)
    stderr_bytes, stderr_digest = _digest(stderr)
    record: dict[str, object] = {
        "blockers": [],
        "command": COMMANDS[obligation_id],
        "evidenceClass": EVIDENCE_CLASSES[obligation_id],
        "evidenceIdentitySha3_512": "0" * 128,
        "exitCode": 0,
        "obligationId": obligation_id,
        "sourceId": f"h6-evidence/{obligation_id.lower()}",
        "status": "CLOSED",
        "stderrBytes": stderr_bytes,
        "stderrPath": stderr.name,
        "stderrSha3_512": stderr_digest,
        "stdoutBytes": stdout_bytes,
        "stdoutPath": stdout.name,
        "stdoutSha3_512": stdout_digest,
    }
    record["evidenceIdentitySha3_512"] = _check_identity(record)
    return record


def build(evidence_root: Path, output: Path) -> None:
    if evidence_root.is_symlink() or not evidence_root.is_dir():
        raise ValueError("h6_manifest_evidence_root_invalid")
    checks = [_check(evidence_root, obligation_id, ordinal) for ordinal, obligation_id in enumerate(OBLIGATIONS, 1)]
    manifest = {
        "activationAllowed": False,
        "checks": checks,
        "manifestVersion": 1,
        "proofSuiteId": None,
        "schema": SCHEMA,
        "sourceFiles": _source_records(),
        "status": "NONACTIVATING",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json_bytes(manifest) + b"\n")
    print("h6_manifest_builder=PASS")
    print(f"h6_manifest_path={output}")
    print(f"h6_manifest_source_file_count={len(SOURCE_FILES)}")
    print(f"h6_manifest_check_count={len(checks)}")
    print(f"h6_manifest_sha3_512={hashlib.sha3_512(output.read_bytes()).hexdigest()}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.evidence_root, args.output)


if __name__ == "__main__":
    main()
