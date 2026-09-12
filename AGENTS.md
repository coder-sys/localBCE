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

### Complete-path review correction — 2026-09-12

The correction is a new child commit after the advertised E2E commit
'00e864e2c9c1f9b550f667e3c5bf4759982f26b3' / tree
'77b6e97880b39aa4419762ba6ee19c522f5f6e19'; the advertised commit is not amended. The
runtime lifetime now uses its checked '__enter__'/'__exit__'/'close' ownership for the whole
acquired span, groups primary and release failures, retains failed run directories while
release or primary failure is unresolved, and wipes local capsule/handoff state before
submission failure. Native wrapper attempts are counted in append-only per-stage measurement
lists; the valid path requires exactly one source, one independent verifier, and one State-port
call. The prior commit's 'verifier_calls' value came from 'getattr(..., 1)' and is withdrawn as
independent measured evidence; only the corrected run's actual count is usable.

The suffix-only proof-file scan was removed. After the first runtime closes, the exact file
inventory is required to be ('state.sqlite',): no owner marker, SQLite journal/WAL/SHM sidecar,
source workspace file, or verifier workspace file is accepted. This reports the isolated
State/owner/SQLite inventory and does not claim OS zeroization, whole-host persistence
absence, or arbitrary byte absence.

The focused fault matrix passed 4/4 with no skips: source failure releases the owner while
retaining the failed run directory, simultaneous primary/release failure preserves both
exceptions and the directory, handoff-construction failure wipes the local capsule, and
repeated native attempts are counted without overwriting measurements. The single required
fresh guarded run passed 9/9 integration tests in 19.355s with outer child exit 7/0,
physical reserve 1073741824, minimum free bytes 2276630528, process-tree peak below
5000000000, cleanup PASS, and the shared mutex released. Its valid evidence is exactly
100 operations, one batch, one verifier acceptance, 100 durable transactions, 100
acknowledgments, 100 unique idempotency keys, zero duplicates, source_calls=1,
verifier_calls=1, state_port_calls=1, source/verifier stdout bytes 539013/0, stderr bytes
0/0, and run_artifact_inventory=['state.sqlite']. No unchanged State, adapter, or malformed
native suites were rerun by instruction; their accepted prior raw gates remain the evidence.
All nonactivation and source-only restrictions remain fixed.

## Active native arithmetic performance assignment — 2026-09-12

This fresh child is the only writable checkout for the shutdown-recovery performance phase:
'C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-direct-mask-performance-20260912'.
It was created as a detached worktree from accepted E2E commit
'51158c2db5c4d1b82c88875ea23707a6e7fa1d89' / tree
'bc779ad6ae3f0b6bf0b9e82020bae7b1f4c8f306'. The prior complete-path child and every input
checkout remain read-only.

### Immutable input identities

The performance phase may source-select only committed blobs from these inputs:

- 'pq-direct-mask-pipeline-20260908': commit
  '530e880ef6cbd5fa4e023f42d3aa66a0d213d9e2', tree
  'e1119b850c3a886a4df09f375fd50d9ac81e94d7'
- 'pq-direct-mask-vole-20260907': commit
  '392e53e2b3d5936cb9cb2681b9e2d803143b1e17', tree
  '34dc614591712efd4faca0dedc064bfd63e51a92'
- 'pq-direct-mask-fixture-20260908': commit
  '5473dd9e97841621430a05f0874bee199f631ec1', tree
  '1ec1a033fd31d891b402fd23c2072eebcc1f011f'
- 'pq-aes-circuit-export-20260907': commit
  '0bce17b884f0076f078026645bef8302b5ed1a53', tree
  '0a0872d3e7ae5aefa6742921909f70b49e58566f'
- 'vendor/faest-ref' source: commit
  'ebefcbd8adda5faf447ef3dba5103794d17b4281', tree
  'f0c2e69f3eb0735fd544d04dc3dcfcc12e275e31'; vendor files are read-only
- ML-DSA input: 'C:\Users\neers\Documents\Codex\2026-08-31\blind-zkbpp-c-profile11-extmu-v1',
  commit '9ca1ba2ccb6fa78384e3c3e21cfd3dfd0cb38eb2', tree
  '178a5f20c6738f7272cd38f77315da83650bbac0'

Imports must be exact committed paths only. Generated artifacts, dirty files, and vendor
copies are not interchangeable with these identities.

### Exact writable scope and invariants

The child may add the tracked native directories 'tools/direct_mask_{authenticated_proof,
circuit,kernel,native,pipeline,source_auth,source_proof,wire}' from the pinned pipeline plus
the exact primitive/fixture directories. Native edits are limited to child-local field
acceleration C/header sources under 'tools/direct_mask_vole', necessary nonsemantic hot-call
site/layout changes in 'tools/direct_mask_kernel'/'tools/direct_mask_circuit', and CMake/build
wiring in imported native directories. Source/proof/signature/codec implementations must remain
byte-equivalent to their inputs; vendor files are protected. A constant-time replacement and
explicitly linked symbol-isolated portable reference are allowed only if all consumers bind to
the intended implementation.

The complete-path files 'tools/direct_mask_complete_path/{complete_path.py,source_boundary.py,
CMakeLists.txt}' and 'app/minimal_clearance_source_auth_verifier_adapter.py' may change only
for explicit child-local rebuilt executable identity plumbing. State/runtime/composition/Queue
semantics, protocol bytes, filtered mode, Profile13, custody, deployment, payment, PHI, Lean,
operations, and formal sources are protected. Existing native probes may be adapted only for
actual changed behavior; no generic benchmark/controller framework is authorized.

Preserve canonical field representation/reduction, ABI/alignment/aliasing, secret-independent
control and memory access, fresh entropy, source/witness/signature binding, six masks,
transcript bytes, independent verifier linkage, retry limits, volatile proof/capsule/IPC,
atomic State/outbox/ACK behavior, and all existing guards. Hardware dispatch needs a correct
portable fallback, supported-instruction checks, and no global unsafe CPU flags or
secret-indexed tables. Profile flags remain 'proofSuiteId=null', 'production_usable=false',
inactive, unselected, and unqualified.

### Performance and evidence boundary

The accepted complete path measured 10.546812s source, 6.671242s verifier, and 17.870595s
total for one synthetic State-issued 100-operation batch. The concrete hypothesis is the
255-bit 'bf256_mul'/'bf256_mul_inplace' loop in pinned vendor 'fields.c:724-742', used by the
kernel/algebra/circuit. Measure the actual dominant calls before and after; preserve an
independently checkable portable reference and byte/arithmetic correspondence. Bounded paired
fresh complete-path samples are evidence, not p95 or qualification.

The accepted complete-path guard remains the only containment primitive: child exit 7/0
preflight, non-null exit gate, physical reserve '1073741824', process-tree cap
'<5000000000', native cap '4500000000', active process limit '1', mutex
'Local\BlindLedgerDirectMaskBuild20260907', cleanup/resource telemetry, and raw failure
retention. Adapt it only for the exact new child build/path/commands. Do not capture secret
proof/witness bytes in logs or files.

The phase is not complete until the affected native arithmetic/link/probe/acceptance/
malformed gates and a freshly built guarded source -> independent verifier -> atomic
State/ACK path pass, with exact before/after timings, retries, binary hashes, import hashes,
changed paths, warnings, failures, skips, and unresolved gates recorded. Do not claim a
material speedup, production security, official authority, or Profile13 readiness without
current raw evidence.

### Native arithmetic performance verified handoff — 2026-09-12

Repository state is detached HEAD `51158c2db5c4d1b82c88875ea23707a6e7fa1d89`, HEAD tree
`bc779ad6ae3f0b6bf0b9e82020bae7b1f4c8f306`; the worktree is intentionally uncommitted and
contains the authorized native imports, acceleration, CMake wiring, child-local executable
identity wiring, and this evidence update. No input checkout or vendor tree was modified.

The implementation adds `tools/direct_mask_vole/direct_mask_bf256_accel.{c,h}`: fixed 4x4
PCLMUL carry-less multiplication and fixed-word reduction for the pinned
`x^256+x^10+x^5+x^2+1` field, with public CPU-feature dispatch, alias-safe in-place use, and
the renamed pinned-vendor implementation retained as an independently linked portable
reference. The exact native source hashes are C
`5FC9AA99647C7F38060545F05AC45C2394A1A442C8061C5E520D1F77C50C3625` and H
`00E1D9C1E078BD35BCCA95AE76865590ED1B78969DAFBD89D85EBB7C09FF21E2`.

Import verification against the committed pipeline/primitive/fixture inputs reported exactly
`IMPORT_CHECKED=74`, `CMAKE_WIRING_DIFFS=9`, and `UNAUTHORIZED_IMPORT_ERRORS=0`. The only
additional imported-tree files are `tools/direct_mask_vole/direct_mask_bf256_accel.c` and
`.h`; `MISSING_EXPECTED_FILES=0`. All non-CMake imported source/proof/signature/codec/fixture
blobs are byte-equivalent to their pinned inputs. The nine intentional CMake differences are
the wiring files under `tools/direct_mask_authenticated_proof`, `tools/direct_mask_circuit`,
`tools/direct_mask_kernel`, `tools/direct_mask_pipeline`, `tools/direct_mask_source_auth`,
`tools/direct_mask_source_proof`, `tools/direct_mask_wire`, `tools/direct_mask_vole`, and
`tools/direct_mask_fixture`.

Current native gates:

- Rebuilt arithmetic probe: `BF256_BACKEND=pclmul PCLMUL_AVAILABLE=1`; `BF256_OUT_OF_PLACE_MATCH=PASS BF256_IN_PLACE_MATCH=PASS`; build and process exits `0`.
- Circuit probe: build/process exits `0`; `DIRECT_MASK_CIRCUIT status=PASS`; all listed negative descriptor/AES/inverse/bitness/transcript/direct-mask cases were rejected or detected.
- Kernel: `1/1 Test #1: direct_mask_kernel_full_field ... Passed`, `100% tests passed, 0 tests failed out of 1`, CTest exit `0`.
- VOLE: `VOLE_IDENTITY rows=1792 mismatches=0 delta_zero=0`, `SOURCE_PROVE_STATUS status=0 prover_calls=1`, `E2E_VERIFY_STATUS status=0`, `SOURCE_BOUND_COUNTS ... counts_equal=1`, `DIRECT_MASK_PROBE_COUNTS passed=53 failed=0`, `DIRECT_MASK_PROBE_STATUS=PASS`, build/process exits `0`.
- Fixture: `FIXTURE_IMPORTED_LIBRARY_IDENTITY=PASS count=8`; `1/1` CTest passed, build/CTest exits `0`.
- Integrated Release CTest: `100% tests passed, 0 tests failed out of 8`, total `34.02 sec`, exit `0`. The probe checks reported `CHECK_COUNT=114 FAILED=0`, `CHECK_COUNT=96 FAILED=0`, `CHECK_COUNT=58 FAILED=0`, and `CHECK_COUNT=86 FAILED=0`; all real-symbol/closure gates passed (`checked=3/2/3`, `forbidden=9/7/7`, and `checked=6/4/3/3`).

The child-local candidate identities are source executable size `276480`, SHA-256
`176B237D8277A1CF09EECE1DC58DBB9B012C9B6700C6FB8C04FEF46011FDD626`, and verifier size
`240640`, SHA-256 `37EB37C8A86C010D3C69400E26BA5DCFA9E2A75C407F48DAEC1D03586D364AEF`.
The key accelerated library `dm_faest_public.lib` is size `333298`, SHA-256
`B664A72471120AAA1D236236AE1BF7C5BB46B3989471771712566BEBD39069ED`. The default
accepted source/verifier pins remain unchanged at `275968/D3A36CFAADBB1B6A3455DA44C4DC0E941C00906EC7E281199876F851C503FCA8` and
`240128/38FB45E017D08AC11098D8837C78D02143B86753AA4F085174073C64353AC835`.

The bounded guarded pair used the existing exit `7/0` preflight, 1-GiB reserve,
`<5000000000` process-tree cap, `4500000000` native cap, active-process limit `1`, mutex,
cleanup telemetry, and memory-only proof boundary. The final candidate raw
`COMPLETE_PATH_EVIDENCE` reported `operation_count=100`, `issued_batch_count=1`,
`independent_verified_batch_count=1`, `source_calls=1`, `verifier_calls=1`,
`state_port_calls=1`, `transaction_count=100`, `outbox_acknowledged_count=100`,
`unique_idempotency_keys=100`, `receiver_duplicate_dispatches=0`,
`receiver_side_effects=100`, `reopened_without_work=true`,
`run_artifact_inventory=["state.sqlite"]`, empty source/verifier workspaces, and fixed
`proof_suite_id=null`, `production_usable=false`, `activation=false`. Candidate measured
source/verifier/total times were `5267.863/2884.734/8851.049 ms`; baseline times were
`10637.985/6845.545/18141.746 ms`, a single guarded sample reduction of
`50.49%/57.86%/51.21%` (source/verifier/total), not a p95 or qualification result. Candidate
outer telemetry was `PHYSICAL_PREFLIGHT free_bytes=3154444288 reserve_bytes=1073741824`,
minimum free `3049099264`, peak working set `80388096`, peak private `54861824`, child
exit `7/0`, cleanup `PASS`, mutex released. Baseline minimum free was `3463213056`, peak
working set `82063360`, peak private `54972416`, with the same child/cleanup result.

Intermediate command failures were corrected and are not unresolved gates: the original long
path build hit MSVC `C1083`/`FTK1011` and was rerun through the validated `Q:` mapped path;
one kernel configure received literal `$vendor`/`$oracle` paths and was rerun with quoted
arguments; one integrated CTest run initially had three `Not Run` EXCLUDE_FROM_ALL probes and
those exact nested targets were built; and a final no-configuration CTest invocation reported
`0% tests passed, 8 tests failed out of 8` with all eight `Not Run` for `Missing "-C
<config>"`, then `ctest -C Release` passed all eight. The VOLE probe explicitly reports
`REMOVED_SYNTHETIC_CHECKS count=6 reason=obsolete_local_polynomial_and_hash_path_removed
replacement=accepted_direct_mask_kernel_and_algebra_probes`; this is an existing probe
disposition, not an unreported skip. Build warnings are pre-existing pinned-vendor warnings:
`C4141` duplicate `inline`, `C4146` unsigned unary minus, and `C4244` conversion warnings;
no new acceleration-source warning or error remained. No unresolved gates or authorized
skips remain. Product, formal, custody, payment, PHI, deployment, filtered/Profile13, and
production-qualification restrictions remain fixed.
