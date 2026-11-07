#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.asdf/shims:$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

cd "$(dirname "$0")/.."

scarb clean
scarb execute \
  --arguments "8001,1001,9001,9002,20260615,7001,1,1,1,1,1,1,1,12500,12500,12500,0,0,0,0,0,0,0,0,0" \
  --target bootloader \
  --output standard \
  --print-program-output \
  --print-resource-usage

scarb prove --execution-id 1
scarb verify --execution-id 1
