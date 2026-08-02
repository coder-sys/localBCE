#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT_DIR}/gov-rules-kg-prototype/.venv/bin/python"
ACTIVE_RULES="${ROOT_DIR}/rust-engine/rules_active_v1.json"
SHADOW_RULES="${ROOT_DIR}/gov-rules-kg-prototype/reports/claude_web_rust_shadow_rules.json"

export PATH="${HOME}/.cargo/bin:${PATH}"

[[ -x "${PYTHON}" ]] || {
  echo "missing gov-rules-kg-prototype virtualenv Python: ${PYTHON}" >&2
  exit 1
}

echo "==> Government rules mapping tests"
(
  cd "${ROOT_DIR}/gov-rules-kg-prototype"
  "${PYTHON}" -m unittest tests/test_legal_grade_foundation.py
)

echo "==> Export Claude web Rust shadow bundle"
(
  cd "${ROOT_DIR}/gov-rules-kg-prototype"
  "${PYTHON}" -m gov_rules_kg.main claude-web-export-rust-shadow
)

echo "==> Validate active and shadow rules in Rust"
(
  cd "${ROOT_DIR}/rust-engine"
  cargo run -- rules-validate "${ACTIVE_RULES}"
  cargo run -- rules-evaluate "${ACTIVE_RULES}"
  cargo run -- rules-shadow-validate "${SHADOW_RULES}"
)

echo
echo "Rules pipeline validation passed"
echo "- active G1-G10 bundle is hash-pinned and parity-gated"
echo "- Claude QA-passed candidates are Rust-validated shadow rules"
echo "- Claude shadow runtime activation and proof binding remain false"
