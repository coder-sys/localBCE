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
