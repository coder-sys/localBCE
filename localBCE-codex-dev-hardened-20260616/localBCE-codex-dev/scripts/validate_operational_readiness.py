from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_app_module() -> None:
    root = _repo_root()
    sys.path.insert(0, str(root / "blind-ledger-app-layer"))


def main() -> int:
    _load_app_module()
    from app.operational_readiness import (
        load_json,
        validate_governance_config,
        validate_launch_blockers,
        validate_monitoring_events,
        validate_production_env_template,
        validate_public_input_schema,
        validate_source_manifest,
        validate_verifier_pin_manifest,
    )

    parser = argparse.ArgumentParser(description="Validate Blind Ledger operational readiness scaffolding.")
    parser.add_argument("--repo-root", type=Path, default=_repo_root())
    args = parser.parse_args()

    repo = args.repo_root.resolve()
    checks = {
        "production env template": validate_production_env_template(repo / "ops" / "production.env.example"),
        "governance config": validate_governance_config(load_json(repo / "ops" / "governance_config.example.json")),
        "oracle source manifest": validate_source_manifest(load_json(repo / "ops" / "oracle_source_manifest.example.json")),
        "public input schema": validate_public_input_schema(load_json(repo / "ops" / "native_stark_public_inputs_v1.json")),
        "verifier pin manifest": validate_verifier_pin_manifest(load_json(repo / "ops" / "verifier_artifact_pin.example.json"), repo_root=repo),
        "monitoring events": validate_monitoring_events(load_json(repo / "ops" / "monitoring_events.json")),
        "launch blockers": validate_launch_blockers(load_json(repo / "ops" / "launch_blockers.json")),
    }

    failed = False
    for name, report in checks.items():
        status = "OK" if report.ok else "FAIL"
        print(f"[{status}] {name}")
        for error in report.errors:
            print(f"  - {error}")
        failed = failed or not report.ok
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
