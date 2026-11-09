#!/usr/bin/env python3
"""Validate the inactive RightRail handoff catalog and hardening lane."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "right-rail-integration" / "reports"
EXPECTED_RULESET_PIN = "95d38b6d8fc9c44b65feace024a07c22b4f11771fe6b23283ce73bbe0a7cb8e3"


class ValidationError(RuntimeError):
    pass


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValidationError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


catalog = load_module("catalog_rightrail_handoff", ROOT / "scripts" / "catalog_rightrail_handoff.py")
crosswalk = load_module(
    "build_rightrail_handoff_crosswalk",
    ROOT / "scripts" / "build_rightrail_handoff_crosswalk.py",
)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"could not read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"expected JSON object: {path}")
    return value


def verify_checkpoint(value: dict[str, Any], *, label: str) -> None:
    expected = value.get("checkpoint_sha256")
    body = {key: item for key, item in value.items() if key != "checkpoint_sha256"}
    actual = sha256_bytes(canonical_json(body))
    if expected != actual:
        raise ValidationError(f"{label} checkpoint mismatch: expected {expected}, got {actual}")


def validate_committed_outputs() -> dict[str, Any]:
    expected_outputs = crosswalk.build()
    for name, expected in expected_outputs.items():
        path = REPORTS / name
        try:
            actual = path.read_bytes()
        except OSError as exc:
            raise ValidationError(f"missing crosswalk output {path}: {exc}") from exc
        if actual != expected:
            raise ValidationError(f"stale crosswalk output: {path}")

    catalog_path = REPORTS / catalog.CATALOG_NAME
    catalog_bytes = catalog_path.read_bytes()
    records = [json.loads(line) for line in catalog_bytes.splitlines()]
    if len(records) != 1108:
        raise ValidationError(f"expected 1108 catalog records, got {len(records)}")
    if any(
        record[field] is not False
        for record in records
        for field in ("execution_allowed", "runtime_eligible", "proof_binding", "human_approved", "legally_verified")
    ):
        raise ValidationError("catalog contains an activated or approved record")

    queue_path = REPORTS / crosswalk.QUEUE_NAME
    queue = [json.loads(line) for line in queue_path.read_bytes().splitlines()]
    if len(queue) != len(records):
        raise ValidationError("review queue does not cover every catalog record")
    if {item["catalog_record_id"] for item in queue} != {item["record_id"] for item in records}:
        raise ValidationError("review queue and catalog record IDs differ")
    if any(
        item[field] is not False
        for item in queue
        for field in ("execution_allowed", "runtime_eligible", "proof_binding", "production_evidence")
    ):
        raise ValidationError("review queue activates handoff material")
    if any(item["human_decision"] is not None for item in queue):
        raise ValidationError("review queue contains a human decision")

    values = {
        "catalog_summary": read_json(REPORTS / catalog.SUMMARY_NAME),
        "security_report": read_json(REPORTS / catalog.SECURITY_NAME),
        "crosswalk_summary": read_json(REPORTS / crosswalk.SUMMARY_NAME),
        "hardening_controls": read_json(REPORTS / crosswalk.CONTROLS_NAME),
        "pq_compatibility": read_json(REPORTS / crosswalk.PQ_NAME),
        "integration_checkpoint": read_json(REPORTS / crosswalk.CHECKPOINT_NAME),
    }
    for label, value in values.items():
        verify_checkpoint(value, label=label)
    if values["catalog_summary"]["catalog_sha256"] != sha256_bytes(catalog_bytes):
        raise ValidationError("catalog bytes do not match catalog summary")
    if values["security_report"]["skipped_large_blob_count"] != 29:
        raise ValidationError("security report does not quarantine 29 skipped history blobs")
    if values["security_report"]["security_status"] != "quarantine_required":
        raise ValidationError("security report weakens quarantine status")
    if values["integration_checkpoint"]["complete_disposition_count"] != 1108:
        raise ValidationError("integration checkpoint is incomplete")
    for control in values["hardening_controls"]["controls"]:
        evidence = control.get("local_evidence")
        if not isinstance(evidence, list) or not evidence:
            raise ValidationError(f"control lacks local evidence: {control['control_id']}")
        for item in evidence:
            evidence_path = ROOT / item["path"]
            try:
                text = evidence_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise ValidationError(f"could not read local evidence {evidence_path}: {exc}") from exc
            markers = item.get("required_markers")
            if not isinstance(markers, list) or not markers:
                raise ValidationError(f"local evidence has no markers: {item['path']}")
            missing = [marker for marker in markers if marker not in text]
            if missing:
                raise ValidationError(f"local evidence markers missing from {item['path']}: {missing}")
            if not re.fullmatch(r"[a-z_]+", item.get("status", "")):
                raise ValidationError(f"invalid local evidence status: {item.get('status')}")
    return values


def validate_external_handoff(handoff_root: Path) -> None:
    outputs = catalog.build_catalog(
        handoff_root,
        ROOT / "right-rail-integration" / "reports" / "catalog_v1.jsonl",
    )
    committed = {
        catalog.CATALOG_NAME: outputs.catalog,
        catalog.SUMMARY_NAME: outputs.summary,
        catalog.SECURITY_NAME: outputs.security,
    }
    for name, expected in committed.items():
        path = REPORTS / name
        if path.read_bytes() != expected:
            raise ValidationError(f"external handoff no longer matches committed report: {name}")

    controls = read_json(REPORTS / crosswalk.CONTROLS_NAME)
    zip_path = handoff_root / "trunk-source.zip"
    try:
        archive = zipfile.ZipFile(zip_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValidationError(f"could not inspect external trunk ZIP: {exc}") from exc
    with archive:
        for control in controls["controls"]:
            source_path = control["source_path"]
            try:
                content = archive.read(source_path)
            except KeyError as exc:
                raise ValidationError(f"control source missing from trunk ZIP: {source_path}") from exc
            if sha256_bytes(content) != control["source_sha256"]:
                raise ValidationError(f"control source hash mismatch: {source_path}")
            try:
                lines = content.decode("utf-8").splitlines()
            except UnicodeDecodeError as exc:
                raise ValidationError(f"control source is not UTF-8: {source_path}") from exc
            start = control["line_start"]
            end = control["line_end"]
            if start < 1 or end < start or end > len(lines):
                raise ValidationError(f"invalid control line range: {control['control_id']}")
            if not " ".join(lines[start - 1 : end]).strip():
                raise ValidationError(f"empty control evidence range: {control['control_id']}")


def validate_runtime_boundaries() -> None:
    config = read_json(ROOT / "rust-engine" / "config.json")
    if config.get("proof_backend") != "groth16":
        raise ValidationError("Groth16 is no longer the configured default proof backend")
    main = (ROOT / "rust-engine" / "src" / "main.rs").read_text(encoding="utf-8")
    if 'unwrap_or("groth16")' not in main or 'unwrap_or("hardcoded_g1_g10")' not in main:
        raise ValidationError("Rust runtime defaults are not Groth16 plus hardcoded G1-G10")
    rules = read_json(ROOT / "rust-engine" / "rules_active_v1.json")
    if rules.get("rules_sha256") != EXPECTED_RULESET_PIN:
        raise ValidationError("rules_active_v1.json pin changed")
    rules_source = (ROOT / "rust-engine" / "src" / "rules_engine.rs").read_text(encoding="utf-8")
    if EXPECTED_RULESET_PIN not in rules_source:
        raise ValidationError("Rust G1-G10 binary pin changed")
    checkpoint = read_json(REPORTS / crosswalk.CHECKPOINT_NAME)
    required_true = (
        "groth16_default_preserved",
        "stark_attested_explicitly_gated",
        "hardcoded_g1_g10_default_preserved",
    )
    if any(checkpoint[field] is not True for field in required_true):
        raise ValidationError("integration checkpoint weakens a runtime boundary")
    required_false = (
        "external_handoff_committed",
        "sqlite_runtime_imported",
        "formal_runtime_dependency",
        "ml_dsa_runtime_activation",
    )
    if any(checkpoint[field] is not False for field in required_false):
        raise ValidationError("integration checkpoint activates an isolated lane")
    if checkpoint["stark_envelope_bytes"] != 129:
        raise ValidationError("STARK envelope length changed")
    if checkpoint["controlled_attestation_scheme"] != "secp256k1":
        raise ValidationError("controlled-attestation scheme changed")


def validate_formal_and_pq_files() -> None:
    toolchain = (ROOT / "right-rail-integration" / "formal" / "lean-toolchain").read_text(
        encoding="ascii"
    ).strip()
    if toolchain != "leanprover/lean4:v4.33.1":
        raise ValidationError("Lean toolchain is not pinned to v4.33.1")
    cargo_files = list((ROOT / "right-rail-integration" / "formal").rglob("Cargo.toml"))
    if cargo_files:
        raise ValidationError("formal lane unexpectedly adds a Rust runtime dependency")
    pq = read_json(REPORTS / crosswalk.PQ_NAME)
    if pq["ml_dsa_runtime_activation"] or pq["production_dependency_added"]:
        raise ValidationError("PQ lane is active")
    if pq["production_signature_scheme"] != "secp256k1_controlled_attestation_unchanged":
        raise ValidationError("PQ lane changes production attestation")
    if any(item["bytes_copied"] for item in pq["candidates"]):
        raise ValidationError("PQ lane claims preserved bytes were copied")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "handoff_root",
        nargs="?",
        type=Path,
        help="optional external RightRail handoff root for full byte verification",
    )
    args = parser.parse_args()
    try:
        values = validate_committed_outputs()
        validate_runtime_boundaries()
        validate_formal_and_pq_files()
        if args.handoff_root is not None:
            validate_external_handoff(args.handoff_root.resolve())
        summary = values["crosswalk_summary"]
        print(
            json.dumps(
                {
                    "status": "ok",
                    "external_handoff_verified": args.handoff_root is not None,
                    "catalog_record_count": summary["queue_record_count"],
                    "complete_disposition": summary["complete_catalog_coverage"],
                    "runtime_eligible_count": summary["runtime_eligible_count"],
                    "proof_binding_count": summary["proof_binding_count"],
                    "checkpoint_sha256": values["integration_checkpoint"]["checkpoint_sha256"],
                },
                sort_keys=True,
            )
        )
        return 0
    except (ValidationError, catalog.HandoffCatalogError, crosswalk.CrosswalkError, OSError, json.JSONDecodeError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
