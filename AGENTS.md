# Agent instructions for Blind Ledger

Blind Ledger is RightRail's database-backed payment-clearance system. Treat proof, policy, state,
signature, custody, clearance-transition, and downstream payment-interface code as trust-critical.

## Before editing

1. Work from this repository root.
2. Read `docs/DATABASE_ZK_ARCHITECTURE.md`, `docs/NATIVE_V3_ARCHITECTURE.md`,
   `docs/LEAN_FORMAL_KERNEL.md`, and `docs/IMPLEMENTATION_ROADMAP.md`.
   For Mirror work, also read `docs/MIRROR_ARCHITECTURE.md`.
3. After context loss, re-read this file, `CURRENT_TASK.md`, and `STATE.md`. A published source
   archive may omit workspace-only authority records; in that archive, use the current root
   documents and `RELEASE_FILE_MANIFEST.json`.
4. Use existing Python, Rust, and CUDA installations. Keep generated outputs outside release archives.
5. For work that changes a gate, proof claim, or continuation decision, also read
   `docs/DESIGN_IDEOLOGY.md` and `docs/IMPLEMENTATION_ROADMAP.md` before acting.

## Current architecture boundary

- The application database is the operational source of truth for Blind Ledger clearance state; the
  official state payment system remains the source of truth for actual funds movement.
- An undisclosed payment-relevant assertion crossing the clearance trust boundary and affecting
  automation requires a mandatory application ZK proof. Evidence already lawfully held in plaintext by the state
  clearance service uses the same inspectable deterministic rule and atomic state machine without
  purposeless ZK ceremony.
- The verifier-owned automatic control set fixes the evidence mode and evaluator identity before
  admission. A caller cannot select `DIRECT_STATE_OWNED`, and a failed `PRIVATE_ZK` request cannot
  downgrade to it.
- The native verifier must accept before one atomic private-path database transaction can consume
  nullifiers and update clearance state. Proof acceptance never defaults to `CLEAR`.
- The later mandatory target gives an executable Lean kernel authority over clearance semantics and
  legal state transitions. It is not active now: Rust retains cryptographic proof acceptance and
  the database retains durability/concurrency until the kernel is linked and every theorem/build
  gate passes.
- The fixed directives are `CLEAR`, `HOLD`, `HUMAN_REVIEW`, `BLOCK`, and
  `EXCEPTION_APPROVED`; the last requires a governed signed state authorization.
- Government and oracle signatures authenticate provenance and authority; they do not prove that the underlying facts are true.
- No L2, rollup, sequencer, bridge, public data-availability layer, or Solidity settlement contract is part of the current design.
- Ethereum is a committed later L1 checkpoint capability, not a Phase 0-2 dependency, settlement
  role, or fixed-cadence requirement.
- The executable chronology is strict: `rule_effective < event < observation < decision`. The same
  four times are bound across the request, decision, receipt, and exact retry.
- The database boundary admits one decision and exactly two accesses indexed `[0,1]`: `decision_index=0`,
  `access_count=2`, and each access carries the matching `decision_id`. Reads use observation time;
  the clearance-state write uses decision time.

## Document precedence

`AGENTS.md` owns execution and safety rules. `CURRENT_TASK.md` owns only the current bounded
objective and blockers. `STATE.md` owns verified implementation evidence and nonclaims.
`ARCHITECTURE.md` owns system boundaries and component ownership. The active `docs/` authorities
own their named technical boundaries, and `docs/DESIGN_IDEOLOGY.md` remains an independent design
contract. Retired or compatibility documents cannot override any of these authorities.

## Protected trust-critical paths

Do not edit these unless the owner explicitly authorizes the exact change:

- `app/minimal_clearance_verification_queue.py`
- `app/minimal_clearance_verification_queue_independent.py`
- `app/minimal_clearance_composition.py`
- `app/minimal_clearance_composition_independent.py`
- `experiments/longfellow_v09_native_v3/`
- `app/mirror/`

## Protected-path delegation status

The protected list above is the active default and remains owner-gated. The four bounded Mirror
grants issued on 2026-09-05 and consumed by the immutable `0607a275bb5158dd4b4c70dfcd95d0967c80b839`
base are closed historical permissions; their exact scopes and evidence remain in Git history. The
driver-reviewed Mirror patch `46a4c965464ea2cd72a3205d82652ddbf8ae51f6`, approved under the
owner-delegated engineering authority and integrated here as local commit
`57e5f1f938ff7346880c6fd6a01138cecd575712`, is limited to the exact deleted adapter/test files,
`app/mirror/source_admission.py`, and `tests/test_mirror_state_source_contract.py`. The
nonprotected source-only cleanup `6df4578aa5c98ca23ba38b563b74a075a504c483`, integrated here as
`47eb2309e08d17913bb2fc99ffb33e02dc9bffaa`, removes only unused governance aliases. These are
completed reviewed changes, not open permission; future protected changes need a new owner
delegation from the owner, or a driver-issued packet within an existing owner delegation, naming
the exact paths, tests, invariants, and evidence. This child neither extends nor revokes a separate
owner packet in another task.

The separately approved source-only deletion `d50f0f28134e40fc5a6a04028ef401f801d6596e`, integrated
here as local commit `c230aa518f95397f2dac0af8592aae93796c2b53`, removes exactly the two obsolete
Native throughput/runner wrappers and their obsolete test; no replacement Queue/runtime,
source-auth, Profile 11, or protected-path implementation was changed by that deletion.

The completed Mirror boundary remains governed by these invariants: independent Core/Ingress
reconstruction is fail-closed; every native and service release result is checked; partial release
retains exact ownership; an ambiguous POSIX descriptor is never retried; Windows unlock/handle
failures are observable and retryable only while handle identity is safe; constructor failures
release every acquired resource; and WriterAuthority is not reported closed until physical release
is resolved. The read-only export bridge selects only the independently verified current Core
`SOURCE_OBSERVATION`, rebinds it to the exact current Ingress artifact/receipt/profile, keeps the
existing exporter as sole response producer, and fails closed without mutation or raw-data leakage.
Native-release fault injection, normal close/reopen, scope/concurrency lifecycle, constructor and
close-retry regressions, independent Core/Ingress diagnostics, and export/privacy checks remain the
required evidence for any future delegated change.

## Operational authority

`ops/` is canonical. `tools/ops_authority.py` freezes its exact regular-file set, lengths, and SHA3-512 identities. Never change policy bytes merely to make a check pass.
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

## Active Profile12 protected-path delegation — 2026-09-08

The owner-delegated driver packet authorizes this existing child to implement one cohesive,
nonactivating Profile12 Queue/State integration stage. This exact grant supersedes the stale cleanup
objective in the child `CURRENT_TASK.md` and does not authorize work in the separate direct-mask
calculator checkout. Starting identity is detached HEAD
`98a3d9ea7f156653633996170c17236db804eed7` / tree
`3d8d555397b86384d57fe7db8f530134026eb037`. Before authority-record mutation, the child contained
only the preserved partial dirty patch in
`app/minimal_clearance_verification_queue.py` (67 additions, 9 deletions, source SHA-256
`0953422A72FB34974FC3BF4F0CA1A0403B8FEB02E265665573576A3A30BC4D79`).

### Exact writable grant

The implementation grant covers only:

- `app/minimal_clearance_verification_queue.py`
- `app/minimal_clearance_verification_queue_independent.py`
- `app/minimal_clearance_verification_runtime.py`, only necessary Profile12 typed plumbing
- `tests/test_minimal_clearance_verification_queue.py`
- `tests/test_minimal_clearance_verification_runtime.py`
- `tests/test_minimal_clearance_source_auth_verifier_adapter.py`
- one focused `tests/test_direct_mask_state_profile12.py` if required
- focused release/documentation expectation updates only in
  `tests/test_release_manifest_gate.py` and `tests/test_documentation_governance.py`
- this child's `AGENTS.md`, `CURRENT_TASK.md`, `STATE.md`, `README.md`, `ARCHITECTURE.md`, and
  the named authority docs only for Profile12 reconciliation and finite retired-path records.

The native adapter `app/minimal_clearance_source_auth_verifier_adapter.py` is deferred until the
driver supplies an accepted exact C binary and source-appliance identity. Until then it is
read-only, as are `app/minimal_clearance_verifier_process.py` and
`app/minimal_clearance_resource_limits.py`. `app/minimal_clearance_composition.py`, its
independent implementation, every Lean/formal/semantic candidate, `app/mirror/`,
`experiments/longfellow_v09_native_v3/`, `ops/`, dependency locks, all C/crypto checkouts, source
archives, deployment/profile-selection/payment/custody paths, and all other source paths are
protected and unchanged.

### Frozen invariants and evidence boundary

Profile12 is a clean schema break at exactly version 12; no Profile11 migration, fallback, dual
reader, aliasing, legacy proof acceptance, or compatibility relabeling is authorized. The state
owner independently issues and persists one nonzero 96-byte public coin with the exact four-draw
OS-CSPRNG rule, derives the 405-byte context from the frozen state bindings, persists only the
allowlisted public fields, and reserves exactly one 101-unit lifetime opportunity atomically at
issue before returning the request. Reservation is never refunded/reset; postcommit ambiguity
burns it. The independent checker owns independent reconstruction and exact event/row/counter/
timestamp/epoch/U/context validation. State policy, directives, source truth, native proof
acceptance, Lean semantics, and payment remain separate authorities.

This stage remains unverified/in progress until its focused tests and whole-boundary review pass.
Native adapter/process acceptance is explicitly pending the driver's exact identity packet and
must be reported as a dependency, never as a passed or silently skipped test. Keep
`proofSuiteId=null`, `production_usable=false`, `activation=false`, and
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

## Active E2E complete-path delegation — 2026-09-12

The current driver packet supersedes the preceding native-adapter deferral only for this
nonactivating integration stage. The child is the detached worktree
'C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-direct-mask-complete-path-20260912',
created from State commit '6129625a88e94d005f5dfe5fd4f6fb8e05a19793' / tree
'997e4a8e5543139ea9b81e70574eba5a44d53094d'. The accepted State/runtime correction is the
source-selected commit '6aa9e634948b6b3a40d1c3c4f07299f8fd5493db' / tree
'a8c6c2f1845686b80e9e079c807ad50c3f1deb92'; the accepted adapter source is commit
'55b1d71fc5f6fa1860225e590a6dbff5af3db2e1'; the accepted Queue caller is commit
'4f7d8d9475de5e4042af0f85c00a955259da737f'.

### Exact active write scope

The active integration may touch only:

- 'app/minimal_clearance_source_auth_verifier_adapter.py'
- 'tests/test_minimal_clearance_source_auth_verifier_adapter.py'
- 'tests/test_minimal_clearance_verification_runtime.py'
- 'app/minimal_clearance_verification_queue.py'
- 'tests/test_minimal_clearance_verification_queue.py'
- 'tests/test_direct_mask_state_profile12.py'
- 'tools/direct_mask_complete_path/'
- 'tests/test_direct_mask_source_boundary.py'
- 'tests/test_direct_mask_complete_path.py'
- exact source-only classifications in 'tools/release_manifest_gate.py' and their existing
  dynamic expectations
- narrow authority records in this file, 'CURRENT_TASK.md', and 'STATE.md'

The source-selected State/runtime files are accepted handoffs, not a license to alter the
independent verifier, composition implementation, C/vendor/crypto code, ops, selection/custody/
payment paths, Lean/formal files, deployment/profile files, or any other protected path.

### Frozen E2E boundary

The valid proof run must be one fresh source-appliance request
'DMSR0001 || u64LE1 || u32LE4096 || context64 || nonzeroU96' for exactly one State-issued
100-member batch, through the accepted source caller, the independent native verifier, the
atomic Queue/State/composition transaction, and the opaque outbox/ACK lane. The source capsule
and verifier IPC remain memory-only. The source executable pin is 275968 bytes with SHA-256
'D3A36CFAADBB1B6A3455DA44C4DC0E941C00906EC7E281199876F851C503FCA8'; the verifier pin is
240128 bytes with SHA-256
'38FB45E017D08AC11098D8837C78D02143B86753AA4F085174073C64353AC835'. The public-key header
pin is 19249 bytes with SHA-256
'ED5B965981E766AA3EFB59303D33719B6C1579C0025D615BB8354AA63AC6FAC9', with decoded public
bytes SHA-256 '91DC389CFAA01470B7F66EEE45A4AE9026D154817C754DFE22298B3FA241FFCD'.

Preprovision exact empty non-reparse source/verifier workspaces under the child
'build-complete-path' tree. The copied outer guard must retain child exit 7/0 preflight,
physical reserve '1073741824', process-tree cap '<5000000000', active process limit '1',
mutex 'Local\BlindLedgerDirectMaskBuild20260907', and cleanup/resource markers. The guard
must not capture proof bytes; only the inner Python runner may pass volatile bytes between the
source and verifier calls.

The source-only release boundary is explicit: the fixture-bound source caller, complete-path
module, CMake file, and their tests are retained in Git for evidence but excluded by exact
'SOURCE_ONLY' classifications. Keep 'proofSuiteId=null', 'production_usable=false',
'activation=false', 'NOT_QUALIFIED'/'INACTIVE'/'UNSELECTED'; synthetic State/receiver
implementations do not confer official authority or production qualification.
