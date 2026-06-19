#!/usr/bin/env bash
set -euo pipefail

cat <<'MSG'
The flat-argument Cairo toy executable has been retired.

Run the source-level regression guard instead:
  python -m pytest blind-ledger-app-layer/tests/test_cairo_binding_source_guards.py

Production Cairo execution must use the hardened root-bound witness shape in
src/lib.cairo and must include these adversarial vectors:
  fabricated facts
  duplicate-by-omission
  procedure substitution
  free ceiling
  non-empty-slot insert
  stale root
  Python/Rust/Cairo commitment equality
MSG
