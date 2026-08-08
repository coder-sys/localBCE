from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.production_readiness import (
    CANONICAL_STATE_TRANSITION_BOUNDARY,
    REQUIRED_NONEMPTY_ENV,
    REQUIRED_PRODUCTION_ENV,
    assert_production_ready,
    production_readiness,
)


def _production_env() -> dict[str, str]:
    return {
        "BL_ENV": "production",
        **REQUIRED_PRODUCTION_ENV,
        **{key: "11" * 32 for key in REQUIRED_NONEMPTY_ENV},
    }


def _closed_manifest(root: Path) -> None:
    ops = root / "ops"
    ops.mkdir()
    (ops / "launch_blockers.json").write_text(
        json.dumps(
            {
                "schema_version": "blind_ledger_launch_blockers_v1",
                "blockers": [
                    {
                        "id": "TEST-001",
                        "status": "closed",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_nonproduction_mode_does_not_claim_production_readiness() -> None:
    report = production_readiness({"BL_ENV": "test"})
    assert report.production_mode is False
    assert report.ready is True


def test_production_requires_direct_database_transition_boundary(tmp_path: Path) -> None:
    _closed_manifest(tmp_path)
    env = _production_env()
    env["BL_STATE_TRANSITION_BOUNDARY"] = "ROLLUP"
    report = production_readiness(env, repo_root=tmp_path)
    assert report.ready is False
    assert (
        f"BL_STATE_TRANSITION_BOUNDARY must be {CANONICAL_STATE_TRANSITION_BOUNDARY}"
        in report.blockers
    )


def test_complete_database_boundary_configuration_can_pass_local_gate(tmp_path: Path) -> None:
    _closed_manifest(tmp_path)
    report = production_readiness(_production_env(), repo_root=tmp_path)
    assert report.production_mode is True
    assert report.ready is True
    assert report.blockers == ()


def test_open_launch_blocker_and_legacy_marker_fail_closed(tmp_path: Path) -> None:
    ops = tmp_path / "ops"
    ops.mkdir()
    (ops / "launch_blockers.json").write_text(
        json.dumps(
            {
                "schema_version": "blind_ledger_launch_blockers_v1",
                "blockers": [{"id": "TEST-OPEN", "status": "open"}],
            }
        ),
        encoding="utf-8",
    )
    env = _production_env()
    env["BL_UNSAFE_GROTH16_MODE"] = "1"
    report = production_readiness(env, repo_root=tmp_path)
    assert report.ready is False
    assert "launch blocker TEST-OPEN is not closed" in report.blockers
    assert any("legacy proof marker" in item for item in report.blockers)


def test_assert_production_ready_raises_with_exact_blockers(tmp_path: Path) -> None:
    _closed_manifest(tmp_path)
    env = _production_env()
    env.pop("BL_STATE_SCHEMA_ROOT")
    with pytest.raises(RuntimeError, match="BL_STATE_SCHEMA_ROOT is required"):
        assert_production_ready(env, repo_root=tmp_path)
