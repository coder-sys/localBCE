#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RULES_WORKDIR = ROOT / "gov-rules-kg-prototype"
sys.path.insert(0, str(RULES_WORKDIR / "src"))

from gov_rules_kg.rules_baseline import (  # noqa: E402
    RulesBaselineError,
    validate_rules_baseline,
)


def main() -> int:
    try:
        summary = validate_rules_baseline(RULES_WORKDIR)
    except RulesBaselineError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
