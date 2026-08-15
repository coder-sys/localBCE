# Agent instructions for Blind Ledger

Blind Ledger is RightRail's database-backed payment-clearance system. Treat proof, policy, state,
signature, custody, clearance-transition, and downstream payment-interface code as trust-critical.

## Before editing

1. Work from this repository root.
2. Read `docs/DATABASE_ZK_ARCHITECTURE.md`, `docs/NATIVE_V3_ARCHITECTURE.md`,
   `docs/LEAN_FORMAL_KERNEL.md`, `docs/CURRENT_TECH_STACK.md`, and
   `docs/IMPLEMENTATION_ROADMAP.md`.
3. After context loss, re-read this file, `CONTINUATION_MANDATE.md`, and, when working from the full
   workspace, `STATE.md`. A published source archive may omit workspace-only continuation
   records; in that archive, use the current root documents and `RELEASE_FILE_MANIFEST.json`.
4. Use existing Python, Rust, Scarb, and CUDA installations. Keep generated outputs outside release archives.
5. For work that changes a gate, proof claim, or continuation decision, also read
   `docs/DESIGN_IDEOLOGY.md` and `docs/IMPLEMENTATION_ROADMAP.md` before acting.

## Current architecture boundary

- The application database is the operational source of truth for Blind Ledger clearance state; the
  official state payment system remains the source of truth for actual funds movement.
- An undisclosed payment-relevant assertion crossing the clearance trust boundary requires a
  mandatory application ZK proof. Evidence already lawfully held in plaintext by the state
  clearance service uses the same inspectable deterministic rule and atomic state machine without
  purposeless ZK ceremony.
- The verifier-owned automatic control set fixes the evidence mode and evaluator identity before
  admission. A caller cannot select `DIRECT_STATE_OWNED`, and a failed `PRIVATE_ZK` request cannot
  downgrade to it.
- The native verifier must accept before one atomic private-path database transaction can consume
  nullifiers and update clearance state. Proof acceptance never defaults to `CLEAR`.
- The approved target architecture gives an executable Lean kernel authority over clearance
  semantics and legal state transitions. Rust retains cryptographic proof acceptance and the
  database retains durability/concurrency. No formal-verification claim exists until the deployed
  kernel is linked to the proved definitions and every theorem/build gate passes.
- The fixed directives are `CLEAR`, `HOLD`, `HUMAN_REVIEW`, `BLOCK`, and
  `EXCEPTION_APPROVED`; the last requires a governed signed state authorization.
- Government and oracle signatures authenticate provenance and authority; they do not prove that the underlying facts are true.
- No L2, rollup, sequencer, bridge, public data-availability layer, or Solidity settlement contract is part of the current design.
- Ethereum is not a Phase 0-2 dependency. A later design may checkpoint a compact signed state root or aggregate proof directly to Ethereum L1.

## Protected trust-critical paths

Do not edit these unless the owner explicitly authorizes the exact change:

- `zk-cairo-sharp/`
- `app/batch/nullifier.py`
- `app/batch/leaf.py`
- `app/batch/stark_binding.py`
- `app/batch/merkle.py`
- `app/batch/accumulators.py`
- `app/batch/batch_orchestrator.py`
- `app/oracle_attestation.py`
- `app/public_inputs.py`
- `app/canonical_encoding.py`

## Operational authority

`ops/` is canonical. `experiments/bl_pq512_crypto_foundation/ops_authority.py` freezes its exact regular-file set, lengths, and SHA3-512 identities. Never change policy bytes merely to make a check pass.
This protects the canonical byte identity; it does not freeze documented gate predicates. Evolve a
gate through the explicit policy record below, not by mutating authoritative bytes until a check
passes.

## Claims

The repository is nonactivating. `proofSuiteId` remains null and `production_usable=false`. Do not
claim production readiness, a deployed formally verified kernel, independent audit acceptance,
real-PHI safety, real-payment authorization, or Ethereum settlement without current raw evidence.

## Gate governance and continued execution

Gates are executable controls derived from invariants; they are not sacred text. A gate predicate
can be stale, incorrect, over-broad, non-applicable to the current profile, or contradicted by
current executable behavior. When current evidence demonstrates that condition, an explicitly
authorized change may weaken, disable, suspend, replace, or relabel the gate. That is gate
evolution, not a silent bypass.

Before proceeding under a changed gate, record all of the following in the active run or design
record:

1. the gate name/version and exact predicate;
2. the invariant and failure mode the predicate was intended to protect;
3. the raw evidence showing that the predicate is stale, incorrect, over-broad, or non-applicable;
4. the disposition: retain, replace, weaken, disable, suspend, or relabel;
5. the replacement or compensating control, or an explicit statement that none exists;
6. the exact scope, profile, and duration of the disposition; and
7. the resulting claim, credit, qualification, and activation consequences.

Never change policy bytes, falsify telemetry, delete failures, hide warnings, or call a failed
predicate a pass merely to make a run succeed. A relaxed or disabled gate may support diagnosis,
synthetic exploration, or an explicitly labelled nonqualifying lane, but it cannot silently retain
the old assurance. It cannot qualify production, authorize a payment, advance `proofSuiteId`, or
enable activation unless a separately evidenced policy restores those claims. Changing a gate is
not permission to accept malformed proofs, skip independent verification, bypass atomic mutation,
exceed a physical safety limit, use real PHI or payments, or suppress an unresolved security fact.

When implementation, test, or run work is authorized, continue through successful substeps and
recoverable failures until the authorized objective is complete. A passing test, completed
document section, preflight result, compile, or discovered launch blocker is a phase boundary, not
an automatic end to the task. After each boundary, re-anchor to current repository evidence,
identify the next dependency, make the smallest correct change or run the next safe check, verify
it, and continue. Do not return a status-only handoff while requested work remains.

Classify a blocker precisely:

- A blocked launch means the named run cannot start; safe implementation, test, evidence, and
  replacement-gate work may continue.
- A blocked claim means current evidence cannot support the named claim; nonactivating work may
  continue under an honest lower claim.
- A blocked task means no safe, in-scope work remains, or an unresolved authority, protected-path,
  destructive-action, or resource-safety decision requires the owner.

Stop the affected operation rather than guess when a trust-critical fact is unresolved. Stop the
entire task only for explicit user stop, completion, an unsafe resource/identity condition, a
protected-path or destructive-action conflict requiring approval, or an unresolved ambiguity after
safe alternatives and gate review have been exhausted. An outdated gate is an investigation and
policy-evolution task, not by itself a reason to abandon the authorized objective.

## Git and source-archive continuity

Use Git continuously as the repository's change ledger. At the start and end of every phase,
before and after every run, before an archive refresh, and after archive publication, inspect and
record at minimum:

```powershell
git rev-parse HEAD
git status --short
git diff --check
git diff --name-status
```

Use `git diff`, `git diff --stat`, and targeted file reads to understand the actual change. Preserve
the dirty worktree: never use `git reset`, `git clean`, destructive checkout/revert, or broad
autofix to erase unrelated work. Do not stage or commit unrelated changes. A Git commit identifier
alone does not describe a dirty worktree; record the commit plus the relevant worktree diff or
staged-source identity for every run and archive.

For a successful archive refresh, the three retained source-archive roles are one Downloads copy,
one Desktop-root copy, and one nested Desktop source-backup copy of
`Blind-Ledger-Wave2-Source-Complete-2026-08-02.zip`. Discover them before each successful refresh;
never assume a remembered path or accept only the first three matches:

```powershell
$archiveName = 'Blind-Ledger-Wave2-Source-Complete-2026-08-02.zip'
$userRoot = [Environment]::GetFolderPath('UserProfile')
$targets = @(Get-ChildItem -LiteralPath $userRoot -Filter $archiveName -File -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName)
if ($targets.Count -ne 3) { throw "expected exactly 3 retained source archives; found $($targets.Count)" }
$identities = foreach ($target in $targets) {
    $hash = Get-FileHash -LiteralPath $target.FullName -Algorithm SHA256
    [pscustomobject]@{ Path = $target.FullName; Bytes = $target.Length; SHA256 = $hash.Hash }
}
$identities | Format-Table -AutoSize
if (@($identities.Bytes | Sort-Object -Unique).Count -ne 1 -or @($identities.SHA256 | Sort-Object -Unique).Count -ne 1) {
    throw 'the three retained source archives are not byte-identical'
}
```

The exact current role paths are discovery results, not portable policy. During a successful refresh,
if the scan finds zero, more than three, a missing role, differing lengths, or differing hashes,
classify archive custody as blocked and preserve the raw inventory; do not silently choose, delete,
or overwrite a target.
Unrelated dependency, toolchain, and research ZIPs are not source-archive targets.

Only a successful, verified run enters the source-archive refresh lifecycle. A failed, timed-out,
cancelled, or preflight-blocked run must not refresh or publish source archives and must not create
a builder receipt for that failed outcome; retain its raw evidence and Git checkpoint instead.
For a successful refresh, the archive contains only the reviewed source and documentation allowlist;
it must never contain proof outputs, generated build trees, private run artifacts,
workspace-only continuation records, real PHI, payments, or credentials. The required sequence is:

1. complete and retain the run's raw evidence and Git checkpoint;
2. create or refresh the exact reviewed `APP_RELEASE_FILE_MANIFEST.json` in a bounded staged source
   root, including every intended publishable source/documentation change and excluding generated or
   private artifacts;
3. build one fresh archive outside that source root with the deterministic builder and its exact
   readback:

   ```powershell
   py -3.14 -B -m tools.build_release_archive `
     --source-root <bounded-staged-source-root> `
     --manifest <bounded-staged-source-root>\APP_RELEASE_FILE_MANIFEST.json `
     --output <fresh-output-directory>\Blind-Ledger-Wave2-Source-Complete-2026-08-02.zip
   ```

   The checked-in builder is create-only and rejects an existing output. Resolve the staged source
   root and manifest from the current release-manifest authority; never invent an allowlist or point
   the builder directly at an existing publication target.

4. publish the verified fresh bytes to exactly the three discovered targets using the bounded
   same-directory temporary/backup publisher; retain rollback copies until all replacements pass;
5. independently read back all three targets and require equal byte length, equal SHA-256, canonical
   ZIP/CRC readback, no duplicate or unexpected entries, zero temporary publication artifacts, and
   `three_way_byte_identical=true`; and
6. retain the builder receipt, source/manifest identity, Git identity, target inventory, hashes,
   readback result, cleanup result, and any failure or skipped step with its reason.

If a successful archive refresh is attempted but the staging, manifest-generation, or three-target
publication seam is missing, do not claim the archive was refreshed. Continue implementing or
repairing that seam as the next safe dependency; the run may remain nonactivating and lower-claim
while this is resolved.
