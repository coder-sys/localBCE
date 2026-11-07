#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 -m unittest \
  tests/test_rightrail_handoff_catalog.py \
  tests/test_rightrail_handoff_crosswalk.py \
  tests/test_rightrail_formal_model.py \
  tests/test_validate_rightrail_handoff.py

python3 scripts/build_rightrail_handoff_crosswalk.py --check

if [[ -n "${RIGHTRAIL_HANDOFF_ROOT:-}" ]]; then
  python3 scripts/catalog_rightrail_handoff.py "$RIGHTRAIL_HANDOFF_ROOT" --check
  python3 scripts/validate_rightrail_handoff.py "$RIGHTRAIL_HANDOFF_ROOT"
else
  python3 scripts/validate_rightrail_handoff.py
  printf '%s\n' '[WARN] RIGHTRAIL_HANDOFF_ROOT is unset; external byte verification skipped'
fi

if command -v lake >/dev/null 2>&1; then
  (cd right-rail-integration/formal && lake build)
else
  printf '%s\n' '[WARN] Lean/lake unavailable; deterministic formal model tests passed, Lean build skipped'
fi

if command -v tlc >/dev/null 2>&1; then
  (cd right-rail-integration/formal && tlc -config Settlement.cfg Settlement.tla)
else
  printf '%s\n' '[WARN] TLC unavailable; deterministic formal model tests passed, TLA+ model check skipped'
fi

python3 scripts/scan_secrets.py
git diff --check

printf '%s\n' '[OK] RightRail hardening validation passed'
