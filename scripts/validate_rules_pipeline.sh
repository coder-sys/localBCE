#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT_DIR}/gov-rules-kg-prototype/.venv/bin/python"
ACTIVE_RULES="${ROOT_DIR}/rust-engine/rules_active_v1.json"
SHADOW_RULES="${ROOT_DIR}/gov-rules-kg-prototype/reports/claude_web_rust_shadow_rules.json"
PROMOTION_QUEUE="${ROOT_DIR}/gov-rules-kg-prototype/reports/rules_promotion_queue_v1.json"
RULE_FACTS="${ROOT_DIR}/rust-engine/rule_facts.example.json"
SHADOW_EVALUATION="$(mktemp)"

cleanup() {
  rm -f "${SHADOW_EVALUATION}"
}
trap cleanup EXIT

export PATH="${HOME}/.cargo/bin:${PATH}"
export PYTHONPATH="${ROOT_DIR}/gov-rules-kg-prototype/src${PYTHONPATH:+:${PYTHONPATH}}"

[[ -x "${PYTHON}" ]] || {
  echo "missing gov-rules-kg-prototype virtualenv Python: ${PYTHON}" >&2
  exit 1
}

echo "==> Government rules mapping tests"
(
  cd "${ROOT_DIR}/gov-rules-kg-prototype"
  "${PYTHON}" -m unittest discover -s tests -p 'test_*.py'
)

echo "==> Phase R1 rules corpus inventory"
(
  cd "${ROOT_DIR}/gov-rules-kg-prototype"
  "${PYTHON}" -m gov_rules_kg.main rules-corpus-audit
)

echo "==> Export Claude web Rust shadow bundle"
(
  cd "${ROOT_DIR}/gov-rules-kg-prototype"
  "${PYTHON}" -m gov_rules_kg.main claude-web-export-rust-shadow
)

echo "==> Build and validate canonical R2-R3 promotion queue"
(
  cd "${ROOT_DIR}/gov-rules-kg-prototype"
  "${PYTHON}" -m gov_rules_kg.main rules-build-promotion-queue
  "${PYTHON}" -m gov_rules_kg.main rules-validate-promotion-queue
)

echo "==> Validate active and shadow rules in Rust"
(
  cd "${ROOT_DIR}/rust-engine"
  cargo run -- rules-validate "${ACTIVE_RULES}"
  cargo run -- rules-evaluate "${ACTIVE_RULES}"
  cargo run -- rules-shadow-validate "${SHADOW_RULES}"
  cargo run -- rules-promotion-queue-validate "${PROMOTION_QUEUE}"
  cargo run -- rules-shadow-evaluate "${PROMOTION_QUEUE}" "${RULE_FACTS}" > "${SHADOW_EVALUATION}"
)

echo "==> Validate non-binding all-program shadow evaluation"
"${PYTHON}" - "${SHADOW_EVALUATION}" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["schema_version"] == "localbce-rule-shadow-evaluation-v1"
assert report["runtime_activation"] is False
assert report["proof_binding"] is False
assert report["adjudication_effect"] is False
assert report["summary"] == {
    "queue_items": 226,
    "matched": 0,
    "not_matched": 0,
    "not_applicable": 221,
    "insufficient_data": 5,
}
assert len(report["results"]) == 226
PY

echo
echo "Rules pipeline validation passed"
echo "- active G1-G10 bundle is hash-pinned and parity-gated"
echo "- Claude QA-passed candidates are Rust-validated shadow rules"
echo "- Claude shadow runtime activation and proof binding remain false"
echo "- all 226 source candidates are queued across 51 programs"
echo "- canonical evidence, review, legal, and runtime promotion gates fail closed"
echo "- all-program evaluation is diagnostic only and has no adjudication effect"
