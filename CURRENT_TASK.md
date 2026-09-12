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
