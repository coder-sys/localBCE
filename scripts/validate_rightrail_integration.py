#!/usr/bin/env python3
"""Validate the committed RightRail catalog against the source archive."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from build_rightrail_integration_catalog import CatalogError, build_catalog, write_or_check


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARCHIVE = Path.home() / "Downloads" / "RightRail-Agent-20260919"


def main() -> int:
    archive = Path(os.environ.get("RIGHTRAIL_ARCHIVE_ROOT", DEFAULT_ARCHIVE)).resolve()
    output = ROOT / "right-rail-integration" / "reports"
    try:
        results = build_catalog(archive, verify_bytes=True)
        write_or_check(results, output, check=True)
    except CatalogError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    if results.summary["integrity_failure_count"]:
        print(
            f"[FAIL] {results.summary['integrity_failure_count']} archive entries could not be verified",
            file=sys.stderr,
        )
        return 1
    print(
        "[OK] RightRail catalog verified: "
        f"{results.summary['manifest_entry_count']} entries, "
        f"{results.summary['workspace_count']} workspaces, "
        f"checkpoint {results.summary['checkpoint_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
