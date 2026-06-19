#!/usr/bin/env bash
set -euo pipefail

cat <<'MSG'
Proof generation for the old trusted-flag Cairo executable is disabled.

The production lane must prove the hardened binding statement in src/lib.cairo:
governed facts, governed fee row, sorted/indexed nullifier transition, canonical
amount/date encoding, and pinned on-chain roots.
MSG
