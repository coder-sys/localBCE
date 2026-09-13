# Blind Ledger current task

Updated: 2026-09-12

## Profile12 Queue/State implementation — corrected, unverified/in progress

This child is the exclusive writable checkout for the Profile12 Queue/schema/independent/runtime/
accounting stage. The earlier project-wide cleanup objective is historical evidence only and is no
longer the current authority. The direct-mask contract calculator checkout is read-only and out of
scope.

### Exact starting identity and dirty evidence

- Authoritative product/input: `C:\Users\neers\Documents\Codex\2026-08-30\cleanup-v2\work\aggressive-obsolete-removal-20260907`
- Input HEAD/tree: `98a3d9ea7f156653633996170c17236db804eed7` /
  `3d8d555397b86384d57fe7db8f530134026eb037`; input was clean before this child.
- Exclusive writable child: this checkout, detached at the same HEAD/tree.
- Before this task's first mutation, the child had exactly one authorized dirty file:
  `app/minimal_clearance_verification_queue.py`, 67 additions and 9 deletions (76 diff lines),
  SHA-256 `0953422A72FB34974FC3BF4F0CA1A0403B8FEB02E265665573576A3A30BC4D79`.
- That partial patch is preserved as starting work/evidence. It is not accepted: it used invented
  length-only preimages, a fixed public coin, a non-independent context KAT, and retained the old
  Profile11 statement/result schema.

### Objective and exact scope

Implement the complete nonactivating Profile12 Queue/State integration stage while preserving all
existing ownership, fail-closed, retry, OS-lock, single-use handoff, wipe, and database boundaries.
The exact writable grant is limited to:

- `app/minimal_clearance_verification_queue.py`
- `app/minimal_clearance_verification_queue_independent.py`
- `app/minimal_clearance_verification_runtime.py`, only for necessary typed Profile12 plumbing
- `tests/test_minimal_clearance_verification_queue.py`
- `tests/test_minimal_clearance_verification_runtime.py`
- `tests/test_minimal_clearance_source_auth_verifier_adapter.py`
- one focused `tests/test_direct_mask_state_profile12.py` if needed
- focused expectation updates only in `tests/test_release_manifest_gate.py` and
  `tests/test_documentation_governance.py` when required by the finite retired-path cleanup
- this child's `AGENTS.md`, `CURRENT_TASK.md`, `STATE.md`, `README.md`, `ARCHITECTURE.md`,
  `docs/DATABASE_ZK_ARCHITECTURE.md`, `docs/NATIVE_V3_ARCHITECTURE.md`, and
  `docs/IMPLEMENTATION_ROADMAP.md`, plus exact finite retired-path records required by the grant.

The native adapter is not authorized yet. After the driver supplies an accepted exact C binary and
source-appliance identity, and only then, `app/minimal_clearance_source_auth_verifier_adapter.py`
may receive the exact new frame/IPC grammar. `app/minimal_clearance_verifier_process.py` and
`app/minimal_clearance_resource_limits.py` remain read-only. Composition, Lean/formal/semantic
candidate, Mirror, longfellow, ops, dependency-lock, C/crypto, source, deployment, archive,
profile-selection, real-PHI, payment, and custody paths remain unchanged.

### Frozen Profile12 contract

- `SCHEMA_VERSION` and `PROFILE_VERSION` are exactly `12`. Queue-owned serialized v10/v11
  domains and worker-format labels become v12 in both main and independent implementations. Old
  Queue databases/exports/backups reject before mutation, PRAGMA, or schema creation, with original
  bytes preserved. No migration, fallback, dual reader, legacy proof acceptance, or Profile11 alias.
- Profile token is `BLIND-DIRECT-MASK-FAEST256F-DEG3-V1`; source-auth token is
  `BLIND-MLDSA87-SOURCE-AUTH-DIRECT-MASK-V1-UNQUALIFIED`. Exactly 100 ordered state-issued
  opaque 32-byte operation references remain state-owned and unique.
- Every batch samples one independent state-issued `public_coin` U of exactly 96 bytes from the
  existing OS-CSPRNG seam, conditioned only on not-all-zero, with at most four complete samples.
  Wrong type/length, OS failure, or four zero vectors fails immediately; only an all-zero 96-byte
  sample may trigger another draw. Repeated nonzero U across batches is allowed; no uniqueness or
  seed persistence.
- Persist immutable `public_coin` in the state-owned batch identity/allowlist and immutable-row
  guards. Do not persist proof context, x, proof/frame/capsule/signature/C/T, source/witness/key
  bytes, raw-data hashes, or stable cross-batch fingerprints.
- Replace `proof_statement304` in `IssuedVerificationBatch` and `BatchVerifierResult` with
  `proof_context64` and `public_coin96`. Both producer and independent checker derive context
  independently from the exact 405-byte preimage:
  `ASCII BL/DIRECT-MASK/STATE-CONTEXT/v12 + NUL || u32LE12 || session_ref64 || ordered_root64 ||
  U96 || u64LE(valid_from_ms) || u64LE(valid_until_ms) || circuit_fingerprint64 ||
  profile_fingerprint64`, then SHA3-512.
- Circuit preimage is exactly 120 bytes:
  `BL/DIRECT-MASK/CIRCUIT-ID/v1\0 || fixed16 SBA1-SRC-CMT-v1+NUL || u32LE23 ||
  direct-mask-relation-v1 (23 ASCII bytes, no NUL) ||
  u32LE[256,3,33,8,248,229,125048,172232,0,6,512,1]`;
  fingerprint is
  `01ee8be0a1b1bbb9957a9dcbfdc1f15f510226505a735d95f9b15e73de16161bf462522589824a3f0d0193d67aaf43c97736d24e4a00b9da655403cefd38f4a8`.
- Profile preimage is exactly 248 bytes:
  `BL/DIRECT-MASK/QUEUE-PROFILE/v12\0 || u32LE12 || u16LElen(profile_token) || profile_token ||
  u16LElen(source_auth_token) || source_auth_token || circuit_fp64 || DMSP0001 || DMVI0001 ||
  u32LE[534370,539013,541781,2592,4627,64,96,101] || u64LE4294967296`;
  fingerprint is
  `306885c3f4dba50a14bd7aa9e51ce90d4b29d750d813980ed801ba2aff0159e5b256385357219c1e848f55bff8c020d08c5c59f3b63bc5a3b32b388ff794023a`.
- Context KAT uses `session_ref=bytes(range(64))`, `ordered_root=bytes(range(64,128))`,
  `U=bytes(range(96))`, validity `[6000,9000)`, and the two fingerprints; expected context is
  `931fee1e981d0c844438d08662f6853cc62db7b6ac33a789b82032b33a764997677a505644a5e86085b871ac929c4c36667460883cf3d50b658dc50223c1417d`.
  These KAT bytes are never production RNG defaults.
- Issue-time accounting is atomic: validate metadata/config epoch, capacity, current lifetime
  count and overflow/exhaustion before sampling/returning U; insert batch + 100 members + exactly
  one 101-unit reservation/attempt + counter increment + `BATCH_ISSUED` together. Every durable
  batch has the reservation, including AWAITING_HANDOFF/QUEUED/pre-lease HELD. Attempt remains 0
  before lease and 1 after its one lease; reservation is not a started verification.
- `BATCH_ISSUED` represents AWAITING_HANDOFF/attempt0 and carries reservation before/after and
  exact identity/member count. `HANDOFF_SUBMITTED` represents QUEUED/attempt0. The old claim
  charge becomes `VERIFICATION_STARTED` for LEASED/attempt1 and validates, but does not increment,
  the existing reservation. Expiry, abandonment, restart, consumed/ambiguous/malformed/transport
  failure burns the reservation and requires a fresh operation and handoff. No refund/reset.
- The independent verifier accepts only the exact lifecycle and rejects extra/missing/reordered/
  duplicate events, reservation/counter changes, changed U/context, timestamps, epochs, or attempt
  identities. HELD after issue has 2 events, after handoff 3, after lease 4. Existing completion
  semantics remain. Precommit failure rolls back; postcommit indeterminate retains the reservation.
- Runtime ownership, OS locks, descriptor lifetime, marker/reopen, partial shutdown, one-use
  handoff, and full wipe behavior remain unchanged. No source private material is received by
  Python/State. Native acceptance remains pending the driver's exact pin/appliance packet.

### Required verification and blockers

Implement and test independent context/fingerprint KATs; mutation tests for every public/config
binding and both serializers; RNG zero/shape/failure/repeated-U cases; issue pre/postcommit faults;
retry/expiry/restart/HELD at each stage; no second charge; counter exhaustion/overflow; event,
row, timestamp, epoch, U/context and attempt mutations; and existing ownership/concurrency/wipe
regressions. Keep native adapter tests pending and explicitly blocked until accepted identity input.
Use `build-state12/` only for untracked diagnostics. Do not run old Profile11/source-proof probes,
large solvers, or broad suites without a changed-input reason. Preserve all known provenance-
mismatch failures and unavailable Windows symlink skips with exact counts and reasons.

At completion, reconcile this file and `STATE.md` with actual measured evidence, inspect the whole
producer -> adapter -> Queue -> independent -> State/outbox boundary, verify protected paths and
semantic identities are unchanged, report exact commit/tree/diff/tests/warnings/skips/nonclaims,
and HOLD for driver review. Flags remain `proofSuiteId=null`, `production_usable=false`,
`activation=false`, `NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

### Measured stage evidence — 2026-09-12

The bounded State/runtime reliability correction is committed on top of the Profile12
implementation. Final focused gates were `py -3.14 -B -m py_compile` exit `0`; Queue tests
`Ran 30 tests in 8.983s`, `OK`; Runtime tests `Ran 19 tests in 5.182s`, `OK (skipped=2)`; and
Profile12 tests `Ran 29 tests in 15.660s`, `OK`. The two Runtime skips are exactly
`test_from_source_auth_passes_the_state_port_boundary` and
`test_from_source_auth_remains_nonactivating_and_unified`, both skipped because native Profile12
adapter/source identity is deferred by the active grant pending the driver's accepted exact C
binary/source-appliance packet.

The pre-fix concurrency diagnostic retained the actual per-contender chain: in 3 of 20 barrier
iterations both contenders returned `VerificationRuntimeError: runtime_scope` and
`state.sqlite.runtime-lock` remained; the instrumented native chain showed one contender's
`WriteFile` received Windows error 33 while the other read an empty marker. The corrected owner
holds a weakly-keyed in-process gate for the full native-owner lifetime, makes the newly-created
Windows handle deny concurrent write/open sharing while preserving read/delete identity tests,
maps the nested sharing/access-denied open to `runtime_already_owned`, and releases the process
gate only after native cleanup is known. A deterministic Windows partial-initialization test now
passes with one acquired owner and a `VerificationQueueError:runtime_already_owned` loser. A
100-iteration barrier stress passed `100/100`: one winner, one `runtime_already_owned` loser,
and no cleanup race.

The runtime concurrency test retains each contender's exception type, message, context type and
message, and cause type and message instead of only a string. The focused matrix still covers
the Profile12 KAT, serializer/config/context bindings, association closure across
verify/read/export/restore, exact counters and sampler draws, lifecycle/timestamp/receipt/error
closure, genuine Profile11 WAL/SHM rejection, crash/reopen, handoff wipe, and owner cleanup.
The added v12 WAL drift test proves the immutable main-image version check is only preliminary:
the live read follows WAL schema state and rejects a v11 drift before mutable PRAGMA use while
preserving the main DB and WAL bytes. No adapter/source-auth test, Profile11 proof probe, large
solver, unrelated broad suite, or protected production path was run. The stage remains synthetic,
nonactivating, unqualified, and held for driver review.

### Active E2E integration objective — 2026-09-12

This section is the current objective and supersedes the preceding 'native identity deferred'
wording for this child only. Integrate the accepted State/runtime correction
'6aa9e634948b6b3a40d1c3c4f07299f8fd5493db' / tree
'a8c6c2f1845686b80e9e079c807ad50c3f1deb92', accepted adapter source commit
'55b1d71fc5f6fa1860225e590a6dbff5af3db2e1', and accepted Queue caller commit
'4f7d8d9475de5e4042af0f85c00a955259da737f' by exact path selection. Do not wholesale-copy
authority files from those checkouts.

The deliverable is one runnable, guarded, nonactivating complete path:

'State issue (100 operations) -> public DMSR0001 source request -> fresh source capsule in
memory -> independent native verifier -> atomic Queue/State/composition commit -> opaque
outbox/ACK delivery -> independent readback/reopen'.

The valid proof path must use the pinned source executable, pinned independent verifier, and
frozen public-key header from the driver packet. It must report measured source, verifier,
State/queue, and outbox stages, exact operation/batch/row/ACK counts, workspace cleanup,
independent readback, and restart/deduplication evidence without writing proof/capsule/IPC
bytes. Use the accepted shared guard under 'build-complete-path'; the guard retains the
1-GiB reserve, '<5e9' process-tree cap, active-process limit 1, child exit 7/0 preflight,
mutex, and cleanup checks.

Required negatives are the already accepted ten native malformed-source cases from the Queue
handoff with matching inputs, plus only meaningful integration checks for altered context/U/
ordering/epoch, consumed/replayed handoffs, rejected-verifier State nonmutation, atomic
completion, receiver failure, restart, and no duplicate rows/ACK side effects. No rejected C
harness, old Profile11 probe, filtered-mode upgrade, production qualification, Lean linkage,
real PHI/payment, official receiver, or activation is in scope.

### Complete-path review correction — 2026-09-12

The advertised E2E commit '00e864e2c9c1f9b550f667e3c5bf4759982f26b3' / tree
'77b6e97880b39aa4419762ba6ee19c522f5f6e19' remains unchanged. This correction is published as
a new child commit. The runtime is now held through its checked context hooks for issue,
source, handoff, verifier, delivery, projection, and readback; primary and cleanup failures
are preserved together, failed run directories are retained until release is known, and
local capsule/handoff buffers are wiped on pre-submission failure.

Native wrapper attempts are append-counted with per-stage measurement lists. The previous
'verifier_calls' field was an assumed 'getattr(..., 1)' value and is withdrawn from the
advertised evidence. The corrected valid path reports actual source_calls=1,
verifier_calls=1, and state_port_calls=1. Persistence evidence now requires the exact
post-close run file inventory ['state.sqlite']; source/verifier workspaces are independently
empty. This is an isolated inventory check only, not a whole-host persistence or
zeroization claim.

Correction verification:

- py_compile of the changed complete-path module/test: exit 0.
- Four focused non-native fault tests: 4/4, 0 skipped, exit 0.
- Final guarded command
  '.\build-complete-path\run_guarded_complete_path_20260912.ps1 -Mode CTest
  -RunSuffix native-complete-correction-final-20260912
  -CTestRegex '^direct_mask_complete_path_integration$'': exit 0.
- Raw CTest: 'Ran 9 tests in 19.355s', 'OK', '100% tests passed, 0 tests failed out of 1',
  stderr bytes 0.
- Outer guard: child exit 7/0, reserve 1073741824, minimum free bytes 2276630528,
  peak working set 83345408, peak private bytes 53145600, cleanup PASS, mutex released.

The valid evidence contains exactly 100 operations, one State-issued batch, one independent
verifier acceptance, 100 State/composition transactions, 100 ACKs, 100 unique idempotency
keys, zero duplicate dispatches, 100 receiver side effects, successful reopen with no work,
source/verifier stdout bytes 539013/0, stderr bytes 0/0, and run_artifact_inventory
['state.sqlite']. The source and verifier measurement records report cap_enforced=true,
active_process_limit=1, child_process_count=2, process_tree_complete=true,
measurement_complete=true, cleanup_complete=true, and pagefile_growth_evidence='unavailable'.
No unchanged State, adapter, or ten-case malformed-native suites were rerun; the accepted
prior raw outputs remain the evidence. Flags remain 'proofSuiteId=null',
'production_usable=false', 'activation=false', 'NOT_QUALIFIED'/'INACTIVE'/'UNSELECTED'.

### Active native arithmetic performance objective — 2026-09-12

This fresh detached child starts at accepted E2E commit
'51158c2db5c4d1b82c88875ea23707a6e7fa1d89' / tree
'bc779ad6ae3f0b6bf0b9e82020bae7b1f4c8f306'. It owns a cohesive optimization of the already
accepted unfiltered native chain, not a protocol/profile redesign. Read-only inputs are the
committed pipeline, primitive, fixture, circuit-export, vendor, and ML-DSA identities recorded
in 'AGENTS.md'. The imported scope is exact field/kernel/circuit/native build material plus
child-local complete-path executable identity wiring; State/runtime/composition/Queue semantics,
vendor code, source/proof/signature/codec bytes, filtered mode, Profile13, and product/ops
paths remain protected.

The accepted baseline is source 10.546812s, independent verifier 6.671242s, total 17.870595s
for one synthetic 100-operation path. Establish the actual hot arithmetic call chain and
implement only exact constant-time field acceleration with a portable reference and safe CPU
dispatch. Preserve field/reduction/ABI/aliasing/protocol/transcript/signature/coin/retry/
containment/atomicity invariants. Use the existing guarded runner and mutex with its
1073741824-byte reserve, '<5000000000' process-tree cap, 4500000000 native cap, and active
process limit 1. No generic benchmark framework, extra controller, cache, raw proof logging,
or qualification claim is allowed.

Completion requires affected arithmetic equivalence, link-isolation, acceptance/rejection and
malformed gates, exact rebuilt binary identities, bounded fresh before/after complete-path
samples, and raw source/verifier/State/ACK timing and retry evidence. Reuse unchanged
State/runtime/recovery evidence; do not rerun it without a changed identity/orchestration
justification. Flags remain 'proofSuiteId=null', 'production_usable=false',
'NOT_QUALIFIED'/'INACTIVE'/'UNSELECTED'.

### Native arithmetic performance verified handoff — 2026-09-12

This child remains at detached HEAD `51158c2db5c4d1b82c88875ea23707a6e7fa1d89` / tree
`bc779ad6ae3f0b6bf0b9e82020bae7b1f4c8f306`, with the authorized changes uncommitted. The
optimization is confined to child-local `direct_mask_bf256_accel.{c,h}` and native CMake
wiring, plus exact child-performance executable identity plumbing in the complete path. The
field backend is fixed 4x4 PCLMUL with fixed-word reduction, public CPU dispatch, alias-safe
in-place behavior, and an independently linked symbol-isolated portable vendor reference.

Import identity is verified: `IMPORT_CHECKED=74`, `CMAKE_WIRING_DIFFS=9`,
`UNAUTHORIZED_IMPORT_ERRORS=0`, `MISSING_EXPECTED_FILES=0`; the only two extra files are the
acceleration C/H pair. Source/proof/signature/codec/fixture implementation blobs remain
byte-equivalent to the pinned pipeline/primitive/fixture commits. The acceleration C/H hashes
are `5FC9AA99647C7F38060545F05AC45C2394A1A442C8061C5E520D1F77C50C3625` and
`00E1D9C1E078BD35BCCA95AE76865590ED1B78969DAFBD89D85EBB7C09FF21E2`.

Verification results:

- Current arithmetic probe: `BF256_BACKEND=pclmul PCLMUL_AVAILABLE=1`; both `BF256_OUT_OF_PLACE_MATCH=PASS` and `BF256_IN_PLACE_MATCH=PASS`; build/process exit `0`.
- Circuit, kernel, VOLE, and fixture gates pass. Decisive raw lines include `DIRECT_MASK_CIRCUIT status=PASS`, `1/1 Test #1: direct_mask_kernel_full_field ... Passed`, `VOLE_IDENTITY rows=1792 mismatches=0 delta_zero=0`, `E2E_VERIFY_STATUS status=0`, `DIRECT_MASK_PROBE_COUNTS passed=53 failed=0`, `FIXTURE_IMPORTED_LIBRARY_IDENTITY=PASS count=8`, and fixture CTest `100% tests passed, 0 tests failed out of 1`.
- Integrated Release CTest: `100% tests passed, 0 tests failed out of 8`, total `34.02 sec`, exit `0`; native probe counts are `114/96/58/86` with `FAILED=0`, and all real-symbol/closure checks pass.
- Adapter unit tests: `Ran 14 tests in 4.367s`, `OK`, exit `0`.

Final child-performance identities are source `276480/176B237D8277A1CF09EECE1DC58DBB9B012C9B6700C6FB8C04FEF46011FDD626`, verifier
`240640/37EB37C8A86C010D3C69400E26BA5DCFA9E2A75C407F48DAEC1D03586D364AEF`, and accelerated
`dm_faest_public.lib` `333298/B664A72471120AAA1D236236AE1BF7C5BB46B3989471771712566BEBD39069ED`.
The default accepted pins remain source `275968/D3A36CFAADBB1B6A3455DA44C4DC0E941C00906EC7E281199876F851C503FCA8` and verifier
`240128/38FB45E017D08AC11098D8837C78D02143B86753AA4F085174073C64353AC835`.

The final guarded candidate evidence is exactly one fresh synthetic 100-operation path:
one issued/verified batch, 100 transactions, 100 ACKs, 100 unique idempotency keys, zero
duplicate dispatches, 100 receiver side effects, successful reopen with no work, exact
inventory `['state.sqlite']`, empty source/verifier workspaces, source/verifier calls
`1/1`, State-port calls `1`, and fixed `proof_suite_id=null`, `production_usable=false`,
`activation=false`. Candidate source/verifier/total measurements are
`5267.863/2884.734/8851.049 ms`; paired baseline measurements are
`10637.985/6845.545/18141.746 ms`, observed reductions `50.48%/57.86%/51.21%` in this
single guarded sample. Candidate guard telemetry: preflight free `3154444288`, reserve
`1073741824`, minimum free `3049099264`, peak working set `80388096`, peak private
`54861824`, child exit `7/0`, cleanup `PASS`, mutex released. This is measured performance
evidence only, not p95, production security, qualification, or Profile13 readiness.

Corrected intermediate conditions are retained in the handoff: long-path MSVC `C1083`/
`FTK1011`, literal `$vendor`/`$oracle` kernel arguments, three initially unavailable
EXCLUDE_FROM_ALL integrated probes, and one no-`-C Release` CTest invocation (all eight
`Not Run`, reported as 8 failed-to-run tests) were each corrected and rerun. The VOLE probe reports the explicit existing
disposition `REMOVED_SYNTHETIC_CHECKS count=6 reason=obsolete_local_polynomial_and_hash_path_removed
replacement=accepted_direct_mask_kernel_and_algebra_probes`; no final gate is skipped or
unresolved. Warnings are limited to pinned-vendor `C4141`, `C4146`, and `C4244` warnings.
State/runtime/composition/Queue semantics, vendor files, filtered mode, Profile13, product,
custody, payment, PHI, deployment, Lean, and formal paths remain protected.

### Native performance source review and remaining gates — corrective closure — 2026-09-12

The preceding native-performance records are historical. Their `51158c2...` / `bc779ad...`
identity and uncommitted-state wording are superseded by the clean committed base
`e42d3dc8ccf7891aebad8576402950cedac9ce07` / tree
`544ac79a7964a5d6cad032bdb38a64aa07aa7107`, followed by this correction's seven-path worktree
diff. The exact adapter is `app/minimal_clearance_source_auth_verifier_adapter.py`; the prior
`tools/direct_mask_complete_path/app/adapter.py` reference is invalid. Vendor, pinned
source/proof/signature/codec implementations, State/runtime/composition/Queue semantics,
filtered/Profile13, and product/custody/payment/PHI/deployment/formal paths remain untouched.

The existing standalone kernel probe now performs 65,825 pairs and 592,425 checks against the
independently linked pinned portable reference, including exact lhs/rhs/self alias and in-place
cases plus the compile-guarded portable dispatch seam. The retained raw result is
`build-performance/kernel-candidate/ctest-verbose-20260912-after-callsite.log`:

```text
BF256_ARITHMETIC_BACKEND=pclmul PCLMUL_AVAILABLE=1 FORCED_PORTABLE_SEAM=compiled
BF256_ARITHMETIC_BASIS_PAIRS=65536 BOUNDARY_VECTORS=17 BOUNDARY_PAIRS=289 CHECKS=592425 MISMATCHES=0
BF256_ARITHMETIC_STATUS=PASS
DIRECT_MASK_KERNEL status=PASS skips=0 fixture_rng=deterministic cpu_seconds=23.055
1/1 Test #1: direct_mask_kernel_full_field ....   Passed
100% tests passed, 0 tests failed out of 1
```

The fixture candidate identity target validates exact root `build-performance/q` and all eight
current candidate libraries. The successful raw build is
`build-performance/fixture-candidate/build-candidate-identity-20260912-after-arg.log`; link
inputs are retained at `build-performance/fixture-candidate/candidate-release-link-inputs-20260912.log`
and `build-performance/q/pipeline-source-cli-release-link-inputs-20260912.log`. Controlled
negative logs for wrong root, missing root, and wrong library are retained under
`build-performance/identity-negatives-20260912/`; all three rejected with expected exit `1`.

Current child binaries are source `276480/3BC225CE230433BC14DF94FEBAC47C713D94759505158BBA8FCE84B7E22C3285`
and verifier `240640/FF7E69D004BF21C5E3F7C2A43F4EDD45F73BBF3E2E812AC9A6E657416F86DA93`.
The adapter suite passed `14` tests (`OK`, exit `0`) after the verifier-pin correction. One
fresh corrected guarded candidate path passed 9/9 complete-path tests with raw stdout
`build-performance/complete-path-candidate/guarded-ctest-candidate-correction-2-20260912.stdout.log`
and outer telemetry `build-performance/complete-path-candidate/guarded-candidate-correction-2-20260912.log`.
Its evidence is one batch/100 operations, source/verifier/state-port `1/1/1`, 100 transactions,
100 ACKs, zero duplicates, 100 receiver effects, successful reopen, `['state.sqlite']`, empty
workspaces, and fixed nonactivation flags. Current stage times are
`3817.523/2711.830/7134.644 ms`; the unchanged baseline was not rerun.

All failures and limitations remain retained: the physical q-cache-path rebuild failure
(`Q_CANDIDATE_REBUILD_EXIT=-2`), the first fixture custom-target `PMB_BUILD_DIR` failure (exit
`1`), the first guarded candidate's stale one-nibble verifier pin (`HELD/verifier_transport`,
state-port `0`), the deleted old one-vector source/output, and unknown old warning totals. The
corrected q/kernel logs contain 48 pinned-vendor C4141 lines each; the candidate fixture build
contains zero warning/error lines. No final gate is skipped. This remains synthetic measured
performance evidence only: `proofSuiteId=null`, `production_usable=false`, inactive,
unselected, and unqualified. Remaining action is immutable commit verification and direct Driver
handoff.

### Immutable correction commit closure — 2026-09-12

Commit verification is complete. The native-performance correction is committed as
`800030a4a6b4899e38799934efaaefb5832a6bf6`, tree
`afbe96235f4c5d711ca0d3e689502b5e28c86b17`, parent
`e42d3dc8ccf7891aebad8576402950cedac9ce07`. HEAD is detached with no tracked modifications;
only the intentionally retained untracked `build-performance/` evidence tree remains, and
`git diff --check` is clean. The bounded phase is complete; direct Driver handoff is the next
action. Claims remain synthetic, nonactivating, and unqualified.

### Native arithmetic fallback correction and bounded optimization decision — 2026-09-12

This append-only record closes the fallback obligation and the one authorized optimization
attempt. It started from `f73378a3bf33f5356887ba1e46b758a544392507` / tree
`3418585dc5f5f6091b37db90cd50291a4db69ff6`, whose parent is
`800030a4a6b4899e38799934efaaefb5832a6bf6` and whose actual tree is
`afbe96235f4c5d711ca0d3e689502b5e28c86b17`. The six implementation/gate paths are the
acceleration C seam, kernel CMake/probe, fixture identity script, source-boundary identity, and
actual adapter identity. Vendor and protected protocol/source/proof/State/runtime/Queue,
filtered/PQ, containment, and product paths were untouched.

Fallback verification now uses a CMake-only forced-capability build of the existing probe and
the actual public `bf256_mul`/`bf256_mul_inplace` functions. Normal dispatch selected `pclmul`
with `PCLMUL_AVAILABLE=1`; forced dispatch selected `portable` with `PCLMUL_AVAILABLE=0`.
Both ran 65,536 basis pairs plus 289 boundary pairs, `CHECKS=460775 MISMATCHES=0`; normal
full-field CTest and forced arithmetic-only CTest both passed with exit `0`. The production
`dumpbin /symbols` readback exited `0` and found `DUMPBIN_FINAL_CURRENT_TEST_ONLY_MATCHES=0`.
The initial forced run caught the pinned portable reference's unsupported `dst=rhs` alias and
was retained as `MISMATCHES=131325`; the production fallback now copies both inputs at the
dispatch boundary. No pinned vendor file changed.

The tested two-level Karatsuba candidate passed corrected normal/forced arithmetic and the
eight-library identity gate, but the required guarded comparison regressed:

```text
BASELINE source_ms=3126.333 verifier_ms=2656.820 total_ms=6355.661
KARATSUBA source_ms=3505.107 verifier_ms=2696.914 total_ms=6771.051
TOTAL_REGRESSION_PERCENT=6.535748
SOURCE_REGRESSION_PERCENT=12.115600
VERIFIER_REGRESSION_PERCENT=1.509097
```

It is rejected and removed; the correct current 4x4 PCLMUL implementation is retained. The
initial Karatsuba arithmetic failure and the forced-alias failure remain in the untracked raw
evidence tree. No additional tuning or benchmark was authorized or run.

The rebuilt retained identities are source appliance `276480/25254DCBEB4FAB9A20911C874D7F633BD9953E804FE999F3AFD1C4BFAC649069`,
verifier `241152/59F5CFF5C0C0B4979705BFE3FC69329FCCB2062A73748BC72F7E6A39760CB756`, native C
`08923E5EB209FFBFB89CC489D2C21770769F0AB45F31984BBC075DDDDCF52399`, and unchanged header
`00E1D9C1E078BD35BCCA95AE76865590ED1B78969DAFBD89D85EBB7C09FF21E2`. The final q rebuild
exited `0` with exactly 48 pinned-vendor C4141 warnings and no C4146/C4244; fixture identity
passed all eight libraries at the exact child root; the adapter identity suite was `Ran 14
tests in 4.407s`, `OK`, exit `0`.

The final retained guarded path passed CTest `Ran 9 tests in 8.219s`, `100% tests passed, 0
tests failed out of 1`, total `8.84 sec`, stderr `0`, and outer exit `0`. Its exact evidence
has one issued/independently verified batch, 100 operations/transactions/ACKs/unique keys,
source/verifier/State calls `1/1/1`, zero duplicate dispatches, 100 receiver side effects,
clean reopen, `['state.sqlite']` inventory, empty workspaces, and
`proof_suite_id=null`/`production_usable=false`/`activation=false`. Guard telemetry is
child exit `7/0`, reserve `1073741824`, minimum free `3477954560`, peak working set
`80916480`, peak private `54906880`, cleanup `PASS`, mutex released, and pagefile evidence
`unavailable`. All prior failures, controlled identity negatives, warnings, unavailable old
probe output, and skipped-count statements remain preserved and are not relabelled. Remaining
action is immutable commit verification and direct Driver handoff.

### Immutable bounded native closure — 2026-09-12

The first immutable commit is `4dd3ea2ece80b43e29befe63c644e3b6b46eea61`, tree
`3061d6b77e60bb28f92ea4667bdbe72fcd7c2e50`, parent
`f73378a3bf33f5356887ba1e46b758a544392507`. It contains the six scoped implementation/identity
paths and this phase's append-only records. Verification found no tracked modifications after
the commit; only the preserved untracked `build-performance/` evidence remains. A final
docs-only closure commit and direct Driver handoff remain.

### Native arithmetic performance integration closure — corrected child-performance pair — 2026-09-12

This append-only record corrects the prior performance comparison and closes the authorized
source/fixture/native arithmetic integration. It started at detached HEAD
48268072892afe4db41d3acc50a62e555f0f2f4b, tree
3b720ca35b9943bb7b7be4f27f7c4cd0e8b20d46, parent
4dd3ea2ece80b43e29befe63c644e3b6b46eea61. The authorized tracked implementation delta is
exactly five paths; these two records are the only documentation paths added to the batch.
AGENTS.md is unchanged. Protected Queue/composition/runtime, State, vendor,
protocol/source/proof/signature/codec, filtered/PQ, product, custody/payment/PHI, deployment,
Lean, and formal paths were not touched.

Implementation identities at the start of this record are:

- app/minimal_clearance_source_auth_verifier_adapter.py:
  12580 bytes, SHA-256 E5E53A0C971BAF2E8F1AABBE340D3DFF6F6F4DF6BA2C5BE37CBCA7B7F5FF2F5C;
- tools/direct_mask_complete_path/source_boundary.py:
  11284 bytes, SHA-256 37CF0BFC9D6CB15AB69EBB3C85F78F3097482E2EE13033B8893463B413D5666D;
- tools/direct_mask_fixture/verify_imported_libraries.cmake:
  4457 bytes, SHA-256 72D3ACA9FFA63D3A1A1408966DB7ABE37A5078E3B548855FC888F3819A0064A9;
- tools/direct_mask_kernel/direct_mask_kernel.c:
  17495 bytes, SHA-256 23CE8AE880305931E526568E1E49329E10B097764696E3E818D7BDC8D07E3050;
- tools/direct_mask_kernel/direct_mask_kernel_probe.c:
  16612 bytes, SHA-256 CC0AEE1A77E7BFF720C63D6B3893671ED830363B8334FDD6702C16C76995B88D.

The two kernel C files are byte-equal to the reviewed read-only
pq-direct-mask-filter-native-20260912 checkout. The unchanged public accelerator inputs remain
direct_mask_bf256_accel.c 6013 bytes SHA-256
08923E5EB209FFBFB89CC489D2C21770769F0AB45F31984BBC075DDDDCF52399 and
direct_mask_bf256_accel.h 830 bytes SHA-256
00E1D9C1E078BD35BCCA95AE76865590ED1B78969DAFBD89D85EBB7C09FF21E2. The candidate wire
identity is 271884 bytes SHA-256
F28965F597907880CEC5218BF9558C608A48324124A363FEC1B4CDA5E97CB926; the baseline wire
identity remains 270926 bytes SHA-256
89AC129A25A84870066114EDF61B978D274474BF95FD64AA6890B2691FF4EBE9.

The prior reported pair is not child-performance evidence. Its raw CTest stdout files are
build-performance/complete-path-candidate/guarded-ctest-baseline-byte-embedding-20260912.stdout.log
(5682 bytes, SHA-256 D67661DDF12FF653FABA93F7689B5B7FA78A325224AC7DA22021AC03EE4A07A4) and
guarded-ctest-candidate-byte-embedding-20260912.stdout.log (5682 bytes, SHA-256
676CF280084594F2F607DBFE77961819D060D9B1E6D157728532FD34D70489D3); both matching stderr
files were 0 bytes with SHA-256
E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855. The reported baseline
source/verifier/queue/total values were
12627.230/6598.550/6731.938/19812.133 ms and the reported candidate values were
9884.882/6591.731/6720.608/17021.238 ms. Both ran 9/9 tests, but
DIRECT_MASK_PERFORMANCE_NATIVE was absent. complete_path.py:690 selects the
child-performance paths only when that variable equals 1; lines 727-739 then bind the child
paths and child identity profile, while lines 740-748 bind the default accepted paths. The
prior pair therefore exercised the default accepted source
275968/D3A36CFAADBB1B6A3455DA44C4DC0E941C00906EC7E281199876F851C503FCA8 and verifier
240128/38FB45E017D08AC11098D8837C78D02143B86753AA4F085174073C64353AC835. It is retained
as historical raw evidence but excluded from the performance decision.

Preserved child-performance artifacts were verified before selection. The baseline source is
276480 bytes SHA-256
25254DCBEB4FAB9A20911C874D7F633BD9953E804FE999F3AFD1C4BFAC649069 at
build-performance/baseline-byte-embedding-20260912/build-performance/fixture-candidate/Release/direct_mask_fixture_source_performance.exe;
the baseline verifier is 241152 bytes SHA-256
59F5CFF5C0C0B4979705BFE3FC69329FCCB2062A73748BC72F7E6A39760CB756 at
build-performance/baseline-byte-embedding-20260912/build-performance/q/Release/dm_pipeline_verifier_cli.exe.
The baseline child pins were applied only temporarily, the active binaries were checked against
those exact hashes, and the existing runner was invoked with
DIRECT_MASK_PERFORMANCE_NATIVE=1. The candidate copies were restored in the baseline-run
finally path and rechecked before restoring the candidate pins. The final active candidate
source is 275968 bytes SHA-256
E07865D9CE6C2644142D3EA61030BD308D5BBD09FE861C630CC5EEBE1F3FE5D9 and the final active
candidate verifier is 240640 bytes SHA-256
F35F6AF28EC2D269831CFB6BDD1C2414D439FFEC2B26C73CC39495720D9B9E5D. No mismatched
source/pin selection was run. Final source_boundary.py pins are 275968/E07865D9...3FE5D9;
final adapter pins are 240640/F35F6AF2...B9E5D.

The existing complete-path runner was used for both samples:
build-performance/complete-path-candidate/run_guarded_complete_path_20260912.ps1,
SHA-256 0D7FE1FF42E31756BF91CD239F66BC1FFA4814448332CDBD7223D07DD1EA8193. The common
guard remains Local\BlindLedgerDirectMaskBuild20260907 with a 1073741824-byte physical
reserve and a 5000000000-byte process-tree cap; the per-stage evidence cap is
4500000000 bytes and active-process limit is 1. Both samples used the same CTest build root,
CMake 4.3.3, Visual Studio 17 2022 x64, Release /O2 /Ob2 /DNDEBUG configuration, and
Python 3.14. No host priority, affinity, power, privilege, or other runtime setting was
changed. The read-only public host snapshot was AMD Ryzen 7 7840HS w/ Radeon 780M Graphics,
AuthenticAMD, 16 logical processors, 8 cores, max/current clock 3801/2516 MHz, 64-bit
address/data; pre-pair free/total visible memory was 2898832/16053108 KiB and boot was
9/12/2026 1:40:48 PM. The existing guarded public backend probe reported exactly:

BF256_BACKEND=pclmul PCLMUL_AVAILABLE=1
BF256_OUT_OF_PLACE_MATCH=PASS BF256_IN_PLACE_MATCH=PASS

Its stdout is 98 bytes SHA-256
5E8E15C057DECA9884BFC8742B928748F86AC03A4C12B4131A791DEBBA982613 and its stderr is
0 bytes SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.

Corrected matched-pair raw files and identities:

- baseline CTest stdout:
  build-performance/complete-path-candidate/guarded-ctest-extra-pair-baseline-byte-embedding-20260912.stdout.log,
  5678 bytes, SHA-256 AA53A354DB94CF4207B4284783B54CCE31CECC99F4888B8E7999951B6CD37501;
- baseline CTest stderr: matching .stderr.log, 0 bytes, SHA-256
  E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855;
- baseline outer guard:
  build-performance/complete-path-candidate/guarded-extra-pair-baseline-byte-embedding-20260912.log,
  3250 bytes, SHA-256 5553F145BD68C529C4DC8AA0F8BFBCF8699595BD49437E9646DB6B2746D8B907;
- candidate CTest stdout:
  build-performance/complete-path-candidate/guarded-ctest-extra-pair-candidate-byte-embedding-20260912.stdout.log,
  5680 bytes, SHA-256 C091155DE76AACFB2FEB42A346A85A789251BDA3F1B6F5A861ABA47AF908753D;
- candidate CTest stderr: matching .stderr.log, 0 bytes, SHA-256
  E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855;
- candidate outer guard:
  build-performance/complete-path-candidate/guarded-extra-pair-candidate-byte-embedding-20260912.log,
  3005 bytes, SHA-256 5725A282C569E9CDA8FBBA724762035AB5E97860AB57D34F1B00A12DDB72B7C0.

Raw CTest gates were:

BASELINE: Ran 9 tests in 8.593s; OK; 1/1 test passed in 10.07 sec;
100% tests passed, 0 tests failed out of 1; Total Test time (real) = 10.10 sec.
CANDIDATE: Ran 9 tests in 7.181s; OK; 1/1 test passed in 7.87 sec;
100% tests passed, 0 tests failed out of 1; Total Test time (real) = 7.88 sec.

The parsed raw COMPLETE_PATH_EVIDENCE decision fields were:

BASELINE source_call_ms=3359.885 source_measurement.elapsed_ms=3358.222
verifier_measurement.elapsed_ms=2826.300 queue_verify_state_ms=3019.394
total_path_ms=6923.729; source/verifier/state_port calls=1/1/1;
issued and independently verified batches=1/1; operations/transactions/ACKs/unique keys=100/100/100/100;
receiver_duplicate_dispatches=0 receiver_side_effects=100 reopened_without_work=true
run_artifact_inventory=["state.sqlite"] source_workspace_empty=true
verifier_workspace_empty=true proof_files_persisted=false proof_suite_id=null
production_usable=false activation=false. Source and verifier both had exit_code=0,
cap_enforced=true, active_process_limit=1, child_process_count=2,
process_tree_complete=true, measurement_complete=true, cleanup_complete=true,
pagefile_growth_evidence=unavailable, timed_out=false, stderr_bytes=0; stdout_bytes were
539013 and 0 respectively. The outer guard had preflight free 3111669760 bytes, minimum
free 3021303808 bytes, peak working/private 81965056/51642368 bytes, child exits 7/0,
cleanup PASS, and released the mutex.

CANDIDATE source_call_ms=3197.229 source_measurement.elapsed_ms=3195.852
verifier_measurement.elapsed_ms=1668.185 queue_verify_state_ms=1857.626
total_path_ms=5555.323; source/verifier/state_port calls=1/1/1;
issued and independently verified batches=1/1; operations/transactions/ACKs/unique keys=100/100/100/100;
receiver_duplicate_dispatches=0 receiver_side_effects=100 reopened_without_work=true
run_artifact_inventory=["state.sqlite"] source_workspace_empty=true
verifier_workspace_empty=true proof_files_persisted=false proof_suite_id=null
production_usable=false activation=false. Source and verifier both had exit_code=0,
cap_enforced=true, active_process_limit=1, child_process_count=2,
process_tree_complete=true, measurement_complete=true, cleanup_complete=true,
pagefile_growth_evidence=unavailable, timed_out=false, stderr_bytes=0; stdout_bytes were
539013 and 0 respectively. The outer guard had preflight free 3005677568 bytes, minimum
free 2940284928 bytes, peak working/private 82608128/55283712 bytes, child exits 7/0,
cleanup PASS, and released the mutex.

The corrected pair supports retaining the current implementation for this bounded measurement:
source call delta 162.656 ms / 4.841118%, measured source delta 162.370 ms / 4.834999%,
measured verifier delta 1158.115 ms / 40.976365%, total path delta 1368.406 ms /
19.764003%, and queue-verify/state delta 1161.768 ms. This is one matched pair on one host;
it is not p95, a qualification campaign, a production benchmark, or evidence of
production readiness.

Existing gates were not rerun in this closure because no input or defect changed and the
delegation prohibited campaign expansion: new q 8-test executions=0, new adapter 14-test
executions=0, new malformed-suite executions=0, and new 65536-pair arithmetic executions=0.
The earlier q 8/8, fixture eight-library identity, adapter 14-test, malformed ten-case,
normal/forced 460775-check arithmetic, and public symbol gates remain the recorded evidence;
no final gate is silently skipped. The current q/kernel build warning profile remains exactly
48 pinned-vendor warning C4141 lines, zero C4146/C4244 lines, and zero compiler/link error
markers; the final candidate fixture identity build had zero warning/error lines.

All earlier guarded failures, stale/missing/wrong-root identity attempts, q mapping/cache and
PMB_BUILD_DIR failures, malformed-wrapper quoting failure, forced-alias and rejected
Karatsuba failures, the failed out-of-checkout patch attempt, and their raw hashes remain
historical no-ops or rejected evidence and were not relabelled. This closure added three
procedural no-ops only: one initial command-construction syntax error before shell execution,
one read-only probe of the nonexistent shallow baseline verifier path before correcting to the
preserved deeper path, and one first parser attempt that assumed the CTest line began with
COMPLETE_PATH_EVIDENCE instead of the observed 2: prefix. None changed a file, launched a
test, or was used as evidence; the corrected parser reported
EXTRA_PAIR_EVIDENCE_GATE=PASS samples=2 failures=0. No additional pair or campaign was run.

The repository remains synthetic, nonactivating, and unqualified:
proofSuiteId=null, production_usable=false, activation=false,
NOT_QUALIFIED/INACTIVE/UNSELECTED. The implementation and this evidence record are ready for
the new immutable commit; final commit/tree/parent and clean tracked-state verification are
returned in the Driver handoff.

## Source-admission and verifier-launch closure — 2026-09-13

The source-admission child is the exclusive writable checkout for the parent-authorized durable
source-claim and verifier-launch accounting stage. The exact starting HEAD/tree were
`9971e7a70937ff652d4008efaf021bcb7b119e53` / `c4ee02e15b8ec7ffe029f8056586ea11f3d037c4`.
Immutable input base commit: `9971e7a70937ff652d4008efaf021bcb7b119e53`
Input base tree: `c4ee02e15b8ec7ffe029f8056586ea11f3d037c4`
Next bounded action: immutable commit and post-commit HEAD/tree/parent plus clean tracked-state verification.
The preserved untracked native inputs are source
`build-performance/fixture-candidate/Release/direct_mask_fixture_source_performance.exe`,
275968 bytes, SHA-256
`E07865D9CE6C2644142D3EA61030BD308D5BBD09FE861C630CC5EEBE1F3FE5D9`, and verifier
`build-performance/q/Release/dm_pipeline_verifier_cli.exe`, 240640 bytes, SHA-256
`F35F6AF28EC2D269831CFB6BDD1C2414D439FFEC2B26C73CC39495720D9B9E5D`.

The implementation adds schema/ledger v13 source admission bound to the exact Profile12 batch,
context, public coin, DMSR0001 request digest, retry policy, executable identity/configuration
digest, and public admission bounds; commits one AUTHORIZED to STARTED winner before source work;
returns and consumes a one-shot volatile launch authority; marks ambiguous source and verifier
claims UNKNOWN and holds without reproof; and charges the verifier launch once immediately before
the verifier call. The independent checker reconstructs the same request/configuration identity,
source/verifier event chains, counters, timestamps, status transitions, and shared queue schema.
The caller and complete path now use admission, start, prove, finish, and handoff in that order;
source capsule, proof, keys, and private payloads remain volatile.

Verified focused gates (all exit 0):

- `py -3.14 -B -m py_compile` over all changed Python implementation and test files: no output,
  exit `0`.
- `py -3.14 -m unittest tests.test_minimal_clearance_verification_queue tests.test_minimal_clearance_verification_runtime`:
  `Ran 49 tests in 13.666s`, `OK`.
- `py -3.14 -m unittest tests.test_direct_mask_source_boundary tests.test_direct_mask_state_profile12`:
  `Ran 40 tests in 17.618s`, `OK`.
- `py -3.14 -m unittest tests.test_minimal_clearance_source_auth_verifier_adapter`:
  `Ran 14 tests in 4.620s`, `OK`.
- Three source fault/recovery tests: `Ran 3 tests in 0.721s`, `OK`.
- Shared schema/identity cross-check:
  `QUEUE_SHARED_COLUMNS_MATCH True`, `QUEUE_SHARED_SQL_MATCH True`,
  `COMPOSITION_TABLES_MATCH True`, `COMPOSITION_SQL_KEYS_MATCH True`,
  `SCHEMA_MATCH True`, `GENESIS_HEAD_MATCH True`, `CONFIG_DIGEST_DOMAIN_AVAILABLE True 64`.

The one authorized native guarded complete path remains the only native run. Its raw gate was
`Ran 9 tests in 20.572s`, `OK`, with one source call, one verifier call, one State-port call,
one independently verified batch, 100 operations/transactions/ACKs/unique idempotency keys,
zero duplicate dispatches, `activation=false`, `production_usable=false`, and exact final
inventory `['state.sqlite']`. It was not rerun during this non-native closure; no native arithmetic
or filtered integration was replayed.

One diagnostic run of the protected legacy composition suite was not accepted as a gate:
`py -3.14 -m unittest tests.test_minimal_clearance_composition_v2 tests.test_minimal_clearance_source_auth_verifier_adapter`
reported `Ran 33 tests in 7.338s`, `FAILED (failures=18)`. Every failure was the same assertion
`('HELD', 0) != ('VERIFIED', 100)` from the unchanged composition fixture's
`batch.proof_statement` access; baseline `HEAD` already has no `proof_statement` field and the
composition implementation/test were not changed in this child. The adapter portion passed
independently (14/14 above). Two exploratory schema commands also used unavailable private names
or an incomplete QueueConfig constructor; they changed no files and were not evidence. These
diagnostics are recorded, not silently skipped.

The focused documentation-governance command was also run after adding the required active
markers: `py -3.14 -m unittest tests.test_documentation_governance` reported `Ran 11 tests in
9.754s`, `FAILED (errors=2)`. Both errors are the same six pre-existing unregistered Markdown
paths: `tools/direct_mask_authenticated_proof/README.md`, `tools/direct_mask_fixture/README.md`,
`tools/direct_mask_pipeline/README.md`, `tools/direct_mask_source_auth/README.md`,
`tools/direct_mask_source_proof/README.md`, and `tools/direct_mask_wire/README.md`. The active
marker errors were corrected; these protected release-boundary registrations were not edited.

The repository remains synthetic, nonactivating, and unqualified:
`proofSuiteId=null`, `production_usable=false`, `activation=false`,
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`. The required next action is immutable commit and
post-commit HEAD/tree/parent plus clean tracked-state verification; only the preserved untracked
`build-performance/` tree may remain.

### Immutable implementation commit — 2026-09-13

The implementation and pre-commit evidence above are now committed as
`6c65b6601af17d3f2a88f12eaf171dc174b83f69`, tree
`fa23ad45dc2bce7ea4039291e4daf40bd66979c1`, parent
`9971e7a70937ff652d4008efaf021bcb7b119e53`. The commit contains exactly the 13 authorized
tracked files listed by the staged diff. Post-commit verification reported matching HEAD/tree/
parent, commit subject `Enforce durable source admission and launch accounting`, empty staged and
unstaged diffs, clean `git diff --check`, and only the preserved untracked `build-performance/`
tree. A final docs-only closure records this post-commit state; no implementation file is to be
modified further.

### Durable admission correction closure — 2026-09-13

This append-only record supersedes the immediately preceding open correction wording. The
authorized correction started from immutable HEAD/tree
758345491bffa14df305c994c30d50f5a7d15680 /
392b5fc6b24a2b1228fd6fff6d87b725a5d89f45. The implementation correction is committed as
9e86d8ff75f00db6e52554e8494f99cb009b3033, tree
a8dc5c2b8ccc29e2586cb968d522e500d30a27f3, parent
758345491bffa14df305c994c30d50f5a7d15680, subject Close source and verifier launch races.
It contains exactly these seven tracked paths:
app/minimal_clearance_verification_queue.py,
app/minimal_clearance_verification_queue_independent.py,
tests/test_direct_mask_source_boundary.py,
tests/test_direct_mask_state_profile12.py,
tests/test_minimal_clearance_composition_v2.py,
tests/test_minimal_clearance_verification_queue.py, and
tests/test_minimal_clearance_verification_runtime.py.

Correction evidence:

- SourceAdmission validates explicit identity pins before any admission row, event, or A/S/M
  accounting mutation. The accepted pin is size 275968 and SHA-256
  D3A36CFAADBB1B6A3455DA44C4DC0E941C00906EC7E281199876F851C503FCA8; the assigned
  child-performance pin is size 275968 and SHA-256
  E07865D9CE6C2644142D3EA61030BD308D5BBD09FE861C630CC5EEBE1F3FE5D9. The negative
  runtime test covers unknown profile, mismatched size, and mismatched hash and verifies zero
  source rows, zero SOURCE_AUTHORIZED events, and A/S/M (0, 0, 0); independent verification
  still passes.
- Fresh VERIFIED/REJECTED completion requires a live verifier lease in STARTED. Rejection is
  before receipt/result/State/outbox/V writes; the focused test verifies unchanged counts, a
  LEASED batch, (RESERVED, UNRESERVED), zero V burn, and passing independent verification.
  HELD remains valid prelaunch with UNRESERVED and postlaunch with UNKNOWN; STARTED becomes
  UNKNOWN on hold.
- Independent reconstruction requires exact verifier events
  VERIFIER_STARTED, VERIFIER_COMPLETED and verifier status COMPLETED for terminal
  VERIFIED/REJECTED batches. A fabricated terminal record without those events is rejected
  with lifecycle_verifier.
- SourceLaunchAuthorization check-and-set is serialized by a small lock. The focused concurrent
  boundary test records exactly one native-stub invocation and one winner; the loser receives
  source_authorization, cannot finalize the winner as UNKNOWN, and produces no second
  entropy/work/refund effect.
- Direct completion fixtures reserve verifier work explicitly. The only composition change is a
  narrow stale _Verifier fixture correction to the current proof-context/public-coin/batch-root
  constructor; no composition implementation was changed.

Final non-native focused verification produced these actual results, all with OK:

  py -3.14 -B -m py_compile app/minimal_clearance_verification_queue.py app/minimal_clearance_verification_queue_independent.py tests/test_direct_mask_source_boundary.py tests/test_direct_mask_state_profile12.py tests/test_minimal_clearance_composition_v2.py tests/test_minimal_clearance_verification_queue.py tests/test_minimal_clearance_verification_runtime.py
  exit=0
  py -3.14 -m unittest tests.test_minimal_clearance_verification_queue tests.test_minimal_clearance_verification_runtime
  Ran 50 tests in 15.055s
  OK
  py -3.14 -m unittest tests.test_direct_mask_state_profile12 tests.test_direct_mask_source_boundary
  Ran 43 tests in 18.695s
  OK
  py -3.14 -m unittest tests.test_minimal_clearance_composition_v2 tests.test_minimal_clearance_source_auth_verifier_adapter
  Ran 33 tests in 17.684s
  OK
  py -3.14 -m unittest tests.test_minimal_clearance_verification_queue
  Ran 31 tests in 8.220s
  OK

Correction diagnostics are retained explicitly. The first state rerun reported Ran 36 tests in
17.355s, FAILED (failures=7): two stale source-configuration fixture expectations were exposed
by the pin check, and hard-coded event sequence assumptions caused the temporal and event
mutation checks to hit timestamp_binding and terminal_error_binding. Locating BATCH_COMPLETED
and preserving configuration-digest precedence corrected these fixtures. The first two-status
no-verifier attempt hit QueueBackpressureError: queue_capacity because both live leases shared
one store; isolated temporary stores corrected it. The first in-memory guard scriptblock attempt
failed before launch with Cannot bind argument to parameter Path because it is null; fixing only
the script-directory adaptation caused the guarded runs below. A first post-commit metadata probe
also produced the non-mutating fatal: fatal: ambiguous argument dAByAGUAZQA=; the quoted
read-only probe then verified the exact metadata below. None launched native work or is evidence.

Assigned binaries were not rebuilt and were rehashed after the guarded run:
  build-performance/fixture-candidate/Release/direct_mask_fixture_source_performance.exe
  SIZE=275968 SHA256=E07865D9CE6C2644142D3EA61030BD308D5BBD09FE861C630CC5EEBE1F3FE5D9
  build-performance/q/Release/dm_pipeline_verifier_cli.exe
  SIZE=240640 SHA256=F35F6AF28EC2D269831CFB6DD1C2414D439FFEC2B26C73CC39495720D9B9E5D

The adapted existing guard configured the current checkout without native build. Raw child
stdout: build-performance/guarded-configure-source-admission-20260913.stdout.log, 428 bytes,
SHA256 768DEA7EC005B2CE51D5338BCED272F050D0DC451075FBBAACDF0BC628292D00. Raw outer log:
build-performance/guarded-outer-configure-source-admission-20260913.log, 1862 bytes, SHA256
8CFC939F919E63F87D8A574BC36789275317C3AD588970AE1783E4282D060EBF. Stderr was empty with
SHA256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855. Decisive lines:
  PHYSICAL_PREFLIGHT free_bytes=2870927360 reserve_bytes=1073741824
  CHILD_EXIT_CHECK exit7=7 exit0=0
  CHILD_EXIT_STATUS label=Configure exit=0
  BUILD_LOG_FAILURE=FALSE mode=Configure
  CLEANUP=PASS label=Configure owned_process_tree=empty
  MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

Exactly one fresh guarded synthetic CTest child-performance path ran with
DIRECT_MASK_PERFORMANCE_NATIVE=1 and regex ^direct_mask_complete_path_integration$. There was
no native rebuild, unchanged native/PQ suite replay, arithmetic replay, filtered integration,
cap/target change, qualification, activation, or benchmark campaign. Raw child stdout:
build-performance/guarded-ctest-source-admission-20260913.stdout.log, 5546 bytes, SHA256
82F08E74C7479EB3A126E895F04B99C14974CC5706BEE13CCC1ECE8A0B0702B0. Raw outer log:
build-performance/guarded-outer-ctest-source-admission-20260913.log, 2885 bytes, SHA256
889FE1FE52B70B372E21BC33D28CD2AB6EC66AE615CF1A6EE5E284C5DF69BC3D. Stderr was empty with
SHA256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.

Actual guarded outer lines:
  PHYSICAL_PREFLIGHT free_bytes=2853015552 reserve_bytes=1073741824
  CHILD_EXIT_CHECK exit7=7 exit0=0
  CHILD_EXIT_STATUS label=CTest exit=0
  LIVE_PHYSICAL_SUMMARY label=CTest samples=13 min_free_bytes=2770128896 reserve_bytes=1073741824 peak_working_set_bytes=80138240 peak_private_bytes=52404224
  CLEANUP=PASS label=CTest owned_process_tree=empty
  MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

Actual child gate:
  Ran 9 tests in 6.723s
  OK
  1/1 Test #2: direct_mask_complete_path_integration ... Passed 7.17 sec
  100% tests passed, 0 tests failed out of 1
  COMPLETE_PATH_EVIDENCE {"acknowledged_operation_count": 100, "activation": false, "handoff_ms": 46.825, "independent_event_count": 100, "independent_operation_count": 100, "independent_outbox_count": 100, "independent_transaction_count": 100, "independent_verified_batch_count": 1, "issued_batch_count": 1, "operation_count": 100, "outbox_ack_ms": 151.837, "outbox_acknowledged_count": 100, "production_usable": false, "proof_files_persisted": false, "proof_suite_id": null, "queue_verify_state_ms": 1884.726, "receiver_duplicate_dispatches": 0, "receiver_side_effects": 100, "reopened_without_work": true, "run_artifact_inventory": ["state.sqlite"], "source_call_ms": 2562.087, "source_calls": 1, "source_measurement": {"active_process_limit": 1, "cap_bytes": 4500000000, "cap_enforced": true, "child_process_count": 2, "cleanup_complete": true, "elapsed_ms": 2539.9, "exit_code": 0, "measurement_complete": true, "pagefile_growth_evidence": "unavailable", "peak_private_commit_bytes": 20447232, "peak_working_set_bytes": 18817024, "private_commit_delta_bytes": 20234240, "process_tree_complete": true, "scratch_peak_bytes": 0, "stage": "source_appliance", "stderr_bytes": 0, "stdout_bytes": 539013, "timed_out": false}, "source_workspace_empty": true, "state_issue_ms": 15.218, "state_port_calls": 1, "state_sequence": 100, "total_path_ms": 4918.295, "transaction_count": 100, "unconfirmed_operation_count": 0, "unique_idempotency_keys": 100, "verifier_calls": 1, "verifier_measurement": {"active_process_limit": 1, "cap_bytes": 4500000000, "cap_enforced": true, "child_process_count": 2, "cleanup_complete": true, "elapsed_ms": 1703.88, "exit_code": 0, "measurement_complete": true, "pagefile_growth_evidence": "unavailable", "peak_private_commit_bytes": 19169280, "peak_working_set_bytes": 17129472, "private_commit_delta_bytes": 18583552, "process_tree_complete": true, "scratch_peak_bytes": 0, "stage": "independent_verifier", "stderr_bytes": 0, "timed_out": false}, "verifier_workspace_empty": true}

Earlier claimed guarded run Ran 9 tests in 20.572s has no retained raw guard evidence in the
reviewed build inventory. It was not reconstructed; the current raw child output above is the
only accepted guarded run for this correction.

The prior documentation-governance warning remains explicit and unchanged:
py -3.14 -m unittest tests.test_documentation_governance reported Ran 11 tests in 9.754s,
FAILED (errors=2), both errors listing six pre-existing unregistered Markdown paths:
tools/direct_mask_authenticated_proof/README.md, tools/direct_mask_fixture/README.md,
tools/direct_mask_pipeline/README.md, tools/direct_mask_source_auth/README.md,
tools/direct_mask_source_proof/README.md, and tools/direct_mask_wire/README.md. Required
active-marker errors were corrected; protected release-boundary registrations were not edited.

Post-commit read-only verification matched HEAD 9e86d8ff75f00db6e52554e8494f99cb009b3033,
tree a8dc5c2b8ccc29e2586cb968d522e500d30a27f3, and parent
758345491bffa14df305c994c30d50f5a7d15680; git diff --check was clean and tracked status was
clean. Only intentionally untracked build-performance/ evidence remains. The stage is synthetic
and nonactivating: proofSuiteId=null, production_usable=false, activation=false,
NOT_QUALIFIED/INACTIVE/UNSELECTED. No implementation files remain to be modified; this record
and STATE.md are the only permitted final closure edits.

### Raw evidence fidelity addendum — 2026-09-13

A post-closure byte audit corrected two transcription omissions in the immediately preceding
closure text. The assigned verifier binary is unchanged and its actual SHA-256 is
F35F6AF28EC2D269831CFB6BDD1C2414D439FFEC2B26C73CC39495720D9B9E5D (size 240640), matching
the parent grant and the retained file. The raw child line below is authoritative; it includes
peak_job_commit_bytes=21721088 in source_measurement, peak_job_commit_bytes=20447232 and
stdout_bytes=0 in verifier_measurement. The preceding closure line omitted those raw fields
and transcribed the verifier hash with one B missing; no binary or raw log changed.

  2: COMPLETE_PATH_EVIDENCE {"acknowledged_operation_count": 100, "activation": false, "handoff_ms": 46.825, "independent_event_count": 100, "independent_operation_count": 100, "independent_outbox_count": 100, "independent_transaction_count": 100, "independent_verified_batch_count": 1, "issued_batch_count": 1, "operation_count": 100, "outbox_ack_ms": 151.837, "outbox_acknowledged_count": 100, "production_usable": false, "proof_files_persisted": false, "proof_suite_id": null, "queue_verify_state_ms": 1884.726, "receiver_duplicate_dispatches": 0, "receiver_side_effects": 100, "reopened_without_work": true, "run_artifact_inventory": ["state.sqlite"], "source_call_ms": 2562.087, "source_calls": 1, "source_measurement": {"active_process_limit": 1, "cap_bytes": 4500000000, "cap_enforced": true, "child_process_count": 2, "cleanup_complete": true, "elapsed_ms": 2539.9, "exit_code": 0, "measurement_complete": true, "pagefile_growth_evidence": "unavailable", "peak_job_commit_bytes": 21721088, "peak_private_commit_bytes": 20447232, "peak_working_set_bytes": 18817024, "private_commit_delta_bytes": 20234240, "process_tree_complete": true, "scratch_peak_bytes": 0, "stage": "source_appliance", "stderr_bytes": 0, "stdout_bytes": 539013, "timed_out": false}, "source_workspace_empty": true, "state_issue_ms": 15.218, "state_port_calls": 1, "state_sequence": 100, "total_path_ms": 4918.295, "transaction_count": 100, "unconfirmed_operation_count": 0, "unique_idempotency_keys": 100, "verifier_calls": 1, "verifier_measurement": {"active_process_limit": 1, "cap_bytes": 4500000000, "cap_enforced": true, "child_process_count": 2, "cleanup_complete": true, "elapsed_ms": 1703.88, "exit_code": 0, "measurement_complete": true, "pagefile_growth_evidence": "unavailable", "peak_job_commit_bytes": 20447232, "peak_private_commit_bytes": 19169280, "peak_working_set_bytes": 17129472, "private_commit_delta_bytes": 18583552, "process_tree_complete": true, "scratch_peak_bytes": 0, "stage": "independent_verifier", "stderr_bytes": 0, "stdout_bytes": 0, "timed_out": false}, "verifier_workspace_empty": true}

Raw file identity remains
build-performance/guarded-ctest-source-admission-20260913.stdout.log, size 5546, SHA-256
82F08E74C7479EB3A126E895F04B99C14974CC5706BEE13CCC1ECE8A0B0702B0. The prior closure
record is superseded by this fidelity addendum wherever the literal raw fields or verifier hash
differ.
