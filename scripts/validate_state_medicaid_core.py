#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SRC = ROOT / "gov-rules-kg-prototype" / "src"
sys.path.insert(0, str(PACKAGE_SRC))

from gov_rules_kg.state_medicaid_core import main  # noqa: E402


DEFAULT_REGISTRY = (
    ROOT
    / "gov-rules-kg-prototype"
    / "data"
    / "source_manifests"
    / "state_medicaid_core_v1.json"
)
DEFAULT_PREFLIGHT = (
    ROOT
    / "gov-rules-kg-prototype"
    / "reports"
    / "state_medicaid_core_preflight_v1.json"
)


if __name__ == "__main__":
    arguments = sys.argv[1:] or [
        str(DEFAULT_REGISTRY),
        "--preflight",
        str(DEFAULT_PREFLIGHT),
    ]
    raise SystemExit(main(arguments))
