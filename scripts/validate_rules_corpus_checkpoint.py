#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RULES_SRC = ROOT / "gov-rules-kg-prototype" / "src"
sys.path.insert(0, str(RULES_SRC))

from gov_rules_kg.rules_checkpoint import (  # noqa: E402
    RulesCheckpointError,
    validate_rules_corpus_checkpoint,
)


def main() -> int:
    checkpoint_path = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    try:
        summary = validate_rules_corpus_checkpoint(ROOT, checkpoint_path)
    except (OSError, RulesCheckpointError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
