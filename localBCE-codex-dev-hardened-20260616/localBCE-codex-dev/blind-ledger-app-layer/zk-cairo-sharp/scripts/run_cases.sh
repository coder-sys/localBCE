#!/usr/bin/env bash
set -euo pipefail

cat <<'MSG'
The previous Cairo demo cases used trusted flags, an 8-slot nullifier list, and a
hardcoded fee ceiling. That interface is retired.

Install Scarb/Cairo and add execution fixtures for the hardened
HardenedClaimInput witness before using this lane for proof generation.
MSG
