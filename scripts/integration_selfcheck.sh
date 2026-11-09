#!/usr/bin/env bash
# Integration self-check (follow-up section 5). Prints PASS / FAIL / NOT-YET (phase N) per check.
# A FAIL is allowed only for work that belongs to a later phase; those print NOT-YET instead.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
pass=0; fail=0; notyet=0
line() { printf '%-18s %-9s %s\n' "$1" "$2" "$3"; }
ok()   { pass=$((pass+1)); line "$1" PASS "$2"; }
bad()  { fail=$((fail+1)); line "$1" FAIL "$2"; }
later(){ notyet=$((notyet+1)); line "$1" "NOT-YET" "(phase $2) $3"; }

# branch
br="$(git branch --show-current 2>/dev/null)"
if [ "$br" = "integration/rightrail" ] || [ "$br" = "codex/phase0-docs-selfcheck" ] || [ "${br#codex/}" != "$br" ]; then
  ok branch "on '$br' (must not be codex-dev or main)"
else
  bad branch "unexpected branch '$br'"
fi
if git merge-base --is-ancestor 3d91138 HEAD 2>/dev/null; then ok branch "HEAD descends from 3d91138"; else bad branch "HEAD does not contain 3d91138"; fi

# rightrail import
if [ -d rightrail/lean ] && [ -d rightrail/app ] && [ -d rightrail/rust ] && git merge-base --is-ancestor af020b2 HEAD 2>/dev/null; then
  ok "rightrail import" "rightrail/{lean,app,rust} present; af020b2 reachable"
else
  bad "rightrail import" "missing rightrail subtree or af020b2 not reachable"
fi

# groth16 (N-08 / D-01): must be unreachable
if grep -q '"none" | "groth16" | "stark_attested"' rust-engine/src/main.rs; then
  later "groth16" 1 "N-08/D-01: groth16 still accepted as proof_backend"
else
  ok groth16 "groth16 not accepted as proof_backend"
fi

# proof and chain code parked (RightRail is the base; D-02/D-03 no longer apply to active code)
parked_ok=1
for d in zk zk-prover stark-engine blind-ledger deprecated; do
  if [ -e "$d" ] || [ ! -d "parked/localbce/$d" ]; then parked_ok=0; fi
done
if [ "$parked_ok" -eq 1 ]; then
  ok "proof parked" "Groth16, STARK and chain roots live only under parked/localbce/"
else
  bad "proof parked" "a proof/chain root is still active or its parked copy is missing"
fi

# default config (N-07, proof gate)
if python3 -c 'import json,sys; c=json.load(open("rust-engine/config.json")); sys.exit(0 if c.get("proof_execution_enabled") is False and c.get("proof_backend")=="none" else 1)'; then
  ok "default config" "proof_execution_enabled=false, proof_backend=none"
else
  bad "default config" "default is not adjudication-only"
fi
if grep -q '"private_key"' rust-engine/config.json; then
  later "default config" 1 "N-07/D-09: Anvil private key still in rust-engine/config.json"
else
  ok "default config" "no private key in rust-engine/config.json"
fi

# single writer / lean decides: Phase 4
later "single writer" 4 "bridge/rightrail_offchain.py still writes state; owner wiring not done"
later "lean decides" 4 "Lean worker not yet called from payment path"

# CI matrix (Phase 0 remaining)
if grep -q 'windows-latest' .github/workflows/*.yml 2>/dev/null; then
  ok "ci matrix" "windows-latest present in a workflow"
else
  bad "ci matrix" "no windows-latest job yet (PR 3 item, not done)"
fi

# tracked files: no binaries, except RightRail's two pinned workers while each matches its pinned
# SHA-256 (CLEANUP_PROPOSAL item 1: kept, protected under CONST XI.2).
pinned_ok() {  # path, expected lowercase sha256
  [ "$(git ls-files -- "$1")" = "$1" ] && [ "$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1)" = "$2" ]
}
worker=rightrail/artifacts/engine-evaluator/blind_financial_worker.exe
worker_pin="$(grep -o 'SHA-256 `[0-9A-Fa-f]\{64\}`' rightrail/artifacts/engine-evaluator/PROVENANCE.md | head -1 | grep -o '[0-9A-Fa-f]\{64\}' | tr 'A-F' 'a-f')"
verify=rightrail/artifacts/gate-verify/gate_verify.exe
verify_pin="$(cut -c1-64 rightrail/artifacts/gate-verify/gate_verify.sha256 2>/dev/null)"
banned=""
for f in $(git ls-files | grep -Ei '\.(exe|zkey|ptau|wtns)$'); do
  if [ "$f" = "$worker" ] && [ -n "$worker_pin" ] && pinned_ok "$f" "$worker_pin"; then continue; fi
  if [ "$f" = "$verify" ] && [ -n "$verify_pin" ] && pinned_ok "$f" "$verify_pin"; then continue; fi
  banned="$banned $f"
done
if [ -z "$banned" ]; then ok "tracked files" "no binaries tracked except RightRail's 2 workers, each matching its pinned SHA-256"; else bad "tracked files" "tracked or unpinned:$banned"; fi

# rightrail provenance
if [ -f rightrail/IMPORTED_FROM.md ] && grep -q af020b268094ae3fd6ef5e68fe575b7e5ac40a23 rightrail/IMPORTED_FROM.md; then
  ok "rightrail import" "rightrail/IMPORTED_FROM.md names af020b2"
else
  bad "rightrail import" "rightrail/IMPORTED_FROM.md missing or does not name af020b2"
fi

# docs
missing=""
for f in STATUS.md docs/integration/INVENTORY.md docs/integration/CLEANUP_PROPOSAL.md docs/integration/THREAT_MODEL.md docs/integration/GOVERNANCE.md docs/integration/OPEN_QUESTIONS.md docs/integration/LOG.md; do
  [ -f "$f" ] || missing="$missing $f"
done
if [ -z "$missing" ]; then ok docs "all Phase 0 documents present"; else bad docs "missing:$missing"; fi

# scenarios and defects (listing only; each has its own phase)
later scenarios 1 "18 original scenarios tracked in docs/integration/LOG.md; none run yet"
later defects 1 "D-01..D-10, R-01..R-08, N-01..N-08 status in docs/integration/LOG.md; see section below"

echo
echo "summary: $pass PASS, $fail FAIL, $notyet NOT-YET"
[ "$fail" -eq 0 ] || echo "note: FAIL lines need a fix or an OPEN_QUESTIONS entry before the phase report."
exit 0
