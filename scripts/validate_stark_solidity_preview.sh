#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export PATH="${HOME}/.foundry/bin:${PATH}"

echo "==> STARK Solidity preview tests"
(
  cd "${ROOT_DIR}/blind-ledger"
  forge test --match-path "test/Stark*.t.sol"
)

echo
echo "==> STARK Solidity preview validation passed"
