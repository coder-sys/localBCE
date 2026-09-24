# Blind Ledger current task

Updated: 2026-09-24

## Lifecycle POST-LINK attestation — source-only — 2026-09-24

This bounded source stage adds a post-link Lifecycle attester in
`semantic_kernel/rust/post_link_attest.py`, binds that tool and direct pinned Cargo identity in
`semantic_kernel/rust/build.rs`, and adds focused parser/input-provenance tests in
`tests/test_lifecycle_post_link_attest.py`. The attester's future command uses pinned Cargo with
`--locked --offline --jobs 1 --target x86_64-pc-windows-gnu --release --bin lifecycle`, requires fresh
target and evidence directories outside this source root, parses Cargo JSON for exactly one
release Lifecycle executable, rechecks source and pre-link identities, checks the embedded source
manifest, and records the LLD reproducer and raw response sidecar. Unknown, missing, ambiguous,
linked, special, or unsafe reproducer entries fail closed. It preserves Cargo stdout/stderr and
does not publish a post-link receipt on failure.

No Cargo, compiler, Lean/Lake, test, checker, executable, or `git diff --check` command ran. The
new focused test module is authored but unrun. The direct finite-lane handoff has not arrived:
State still owns the v4 lane; Cleanup returned source ownership only. Do not launch the guarded
target until the lane is released directly and a fresh target-specific v4 preflight is at least
4,190,433,321 bytes free;
the 2,190,433,321-byte hard physical-free floor remains mandatory. The exact guard SHA-256 is
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`.

This source stage leaves the existing `legacy-pinned-v2` adapter mode and 6,571,008-byte
`B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881` executable pin unchanged.
Source-bound runtime mode remains closed. No final link or installed LLD reproducer has been
observed, so the tool's supported LLD archive layout is not verified. Post-use hashing also does
not prevent live-path replacement and restoration during compilation or linking. No source-to-
binary, formal-release, production, payment, PHI, or activation claim follows.

Source review found that Cargo also loads configuration from ancestor `.cargo` directories and
`CARGO_HOME`; a global `build.rustc-wrapper` could therefore change compiler execution without
appearing in the source manifest. The attester now permits only the hash-pinned project
`.cargo/config.toml`, records the checked configuration paths/files, sets an explicit absolute
`CARGO_HOME`, rejects release build-override, build-directory, `CARGO_BUILD_TARGET_DIR`, and
warning-level environment overrides, removes inherited `CARGO_TARGET_DIR` in favor of the fixed
`--target-dir`, and rechecks the configuration inventory after Cargo exits. The current host scan
found exactly one configuration file: the pinned project file, SHA-256
`385D15C7142267A1FDEE1CDA6AB13D41966B2E9557084828922F4A4EE3644E81`.
`build.rs` pins the updated attester source. The focused attester test module now has 12 methods;
none ran. Cleanup returned source ownership for the attester and `build.rs`, but the direct finite
lane handoff and compiler-specific fresh preflight are still absent. The LLD response parser still
checks explicit input basename counts rather than fully parsing response grammar/order, and
pre/post checks cannot detect a path replaced and restored during compilation. Keep source-bound
mode closed pending guarded evidence and review of these remaining limits.

## Queue claim verified-image reuse — source stage — 2026-09-24

The latest Driver packet authorizes only the Queue writer, independent Queue verifier, focused
Queue tests, and these two status records for this source stage. It supersedes the older lane-closed
wording below. After `_expire_locked`, the claim path now captures the complete independently
verified image once and carries a recursively immutable copy to the Lifecycle snapshot consumer
inside a token-scoped context binding. The binding is checked against the Queue owner, opaque claim
transaction token, current thread, exact connection identity and transaction fingerprint, expected
config, selected batch row, and its 100 ordered members. Current Composition metadata is compared
to the corresponding verified-image projection. An invalid active binding fails closed without a
fresh-scan fallback. The two pre-expiry/post-expiry checks remain; the immediate pre-claim and
Lifecycle-snapshot full scans are the only removed scans.

The accepted-claim test measured exactly two `_verify_connection` calls. A focused adversarial case
mutated the selected row on the same transaction after image capture; the stale binding rejected it
before Lifecycle evaluation, Queue rollback preserved the durable batch/attempt/metadata/event and
empty lease table, and an unmodified fresh claim retry succeeded. These checks were run under the
v4 guard with the complete Lifecycle adapter test module and 12 selected Queue cases: `Ran 29 tests
in 10.473s; OK`. The full raw child output, command, memory telemetry, and log hashes are recorded at
the top of `STATE.md`.

The fresh Python host preflight reported `3704889344` bytes, above its `3500000000`-byte start
floor, with the shared mutex absent, no relevant competing process, and no log collision. V4 then
reported preflight `3692937216`, minimum sampled free memory `3519152128`, peak working set
`152530944`, peak private bytes `100384768`, child exit `0`, cleanup `PASS`, and mutex
`RELEASED`. Pre/post `git diff --check` both exited `0`; the hard physical floor
`2190433321` bytes was not crossed. The corrected post-run host snapshot reported free physical
memory `3667693568`, mutex absent, and no relevant process. Compiler start floor remains
`4190433321` bytes; Lake/Cargo are still resource-stopped and require a new safe handoff/preflight.

The old Lifecycle executable and legacy-pinned runtime mode remain unchanged. The source-manifest
and final-link provenance source work is not compiled or attested; source-bound mode stays closed.
No adapter, Composition, runtime, Rust, Lean, DirectMask, or formal-authority path was changed for
this Queue stage. The full Queue module's other 39 test methods were not run; the focused 12-case
Queue set and all 17 Lifecycle adapter test methods passed. The optional DirectMask case (count `1`)
was not run because no DirectMask path changed. The earlier four-module broad suite still has its
recorded 1 failure and 5 errors, including the out-of-scope temporal-binding issue; this focused run
does not clear that result. One initial read-only guard lookup used an extra parent segment and
failed path resolution; the corrected path matched the exact guard hash and no process was
launched by the failed lookup. An initial post-run process inventory counted its own PowerShell
probe (PID `13828`); the corrected inventory excluded the caller and ancestors and returned zero
relevant processes. The v4 lane is now returned directly to Driver. No files were staged or
committed.

## Versioned Queue-to-State handoff — source-only supplement — 2026-09-23

The later direct Driver assignment reopens the Queue-owned Profile12 handoff boundary for this
nonactivating source stage. It supersedes the earlier Queue-owner exclusion only for these exact
paths: `app/minimal_clearance_verification_queue.py`,
`app/minimal_clearance_verification_queue_independent.py`,
`tests/test_minimal_clearance_verification_queue.py`, this file, `STATE.md`, and
`docs/LEAN_FORMAL_KERNEL.md`. The existing Profile12 protected-path grant in `AGENTS.md` remains the
path authority. Composition modules, runtime/native adapters, operational pins, schema files,
generated artifacts, and all other paths remain unchanged.

The Queue handoff is transient inside the existing schema 13 / Profile 12 atomic Queue/State
transaction. It must bind the exact 100 ordered operation identities, source-admission and
proof/attestation result, version and configuration identities, submit/claim/terminal statuses,
attempt/reservation/retry facts, and per-operation State outbox correlation. Queue's independent
decoder must reject malformed, mismatched, duplicate, stale, or replayed handoff bytes before the
State writer consumes them. The existing exact post-commit retry remains idempotent by reading the
durable result; it must not rerun the handoff or create another State/outbox mutation. Conflicting
or incomplete retries remain fail-closed. Preserve the single exact-100 transaction, schema 13 and
Profile 12, 101-unit no-refund reservation, State/Queue outbox atomicity, and all nonactivation
flags.

This is source-only while the guarded lane is closed. No Cargo/Lake/compiler/test/executable or
guard invocation is authorized until the Driver supplies the reviewed v4 guard path and hash and
directly releases the lane. Keep source-bound Lifecycle mode closed until an exact executable and
manifest identity can be reviewed; any final Cargo link closure that cannot be pinned must be
recorded as an explicit unsupported boundary, never treated as a pass.

## Lifecycle source-to-runtime provenance closure — source-only supplement — 2026-09-23

This later direct Driver assignment supplements the earlier Lifecycle source-identity scope. It
authorizes edits only to `semantic_kernel/rust/build.rs`,
`semantic_kernel/rust/src/bin/lifecycle.rs`,
`app/minimal_clearance_lifecycle_adapter.py`, narrowly affected tests in
`tests/test_minimal_clearance_lifecycle_adapter.py`, this file, `STATE.md`, and
`docs/LEAN_FORMAL_KERNEL.md`. It supersedes earlier exclusions only for those exact paths. Keep
Queue/Composition owner modules, operational pins, the retained executable, `.lake` outputs, raw
logs, archives, and every other path unchanged.

The trust chain under review is pinned Lean sources/tools/imports -> Lean objects and lifecycle
archive -> Cargo/Rust plus actual static link inputs, target, linker, and flags -> final
`lifecycle.exe` -> the existing contained runner's exact executable handle -> Python provenance
and response validation -> Queue's active SQLite transaction and successful-transition SQL
writes. Python rejects provenance before response decoding; the Queue invokes it before those
writes, so rejection follows the existing rollback path. Keep schema 13/Profile 12, Queue wire
bytes, policy/directive separation, exact-100 accounting, reservation, lease, clock, and handoff
semantics fixed.

The source design must bind generated Lean object identities, explicit static-link archive
identities, effective target/linker/profile/flags, and the versioned embedded source manifest;
the Rust success path must report that digest and its executable size/SHA-256 on stderr without
changing stdout. The adapter has one source-owned mode selector and no caller mode parameter. Its
current `legacy-pinned-v2` mode preserves the existing synthetic path only for the exact old
executable pin and empty stderr; it receives no current-source or production credit. A future
`source-bound-v1` mode must validate the report from the same contained invocation against both a
reviewed manifest digest and the fixed executable identity. A failure in that mode must reject,
never retry through legacy. The current old executable remains pinned at 6,571,008 bytes / SHA-256
`B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881`; do not replace or repin it
in this phase. Until a separately reviewed executable/manifest pair exists, source-bound runtime
qualification must remain closed.

Pre/post file hashes do not prove immutable tool use during compilation or final linking. Preserve
that concurrency and Cargo final-link limitation explicitly; if it cannot be closed, record it as
an unresolved qualification blocker. Do not add activation authority, `proofSuiteId`, or a
production claim. No compiler, Cargo, Lake, test, executable, or guard run is permitted while
Provider owns the guarded lane; after source and static review, request the lane once and wait for
the direct safe-boundary handoff before the smallest guarded verification chain.

## Lifecycle parser and source identity follow-up — source-only — 2026-09-23

The direct assignment repairs the five recorded Lean parser errors in
`semantic_kernel/lean/Admission/LifecycleKernel.lean` and binds future Lifecycle builds to reviewed
source/tool identities. Writable paths for this follow-up are exactly that Lean file,
`semantic_kernel/rust/build.rs`, focused lifecycle source-pinning tests if needed, this file,
`STATE.md`, and `docs/LEAN_FORMAL_KERNEL.md`. The existing Queue/Lean dirty and untracked files are
preserved. No other production, policy, executable, archive, or runtime adapter path is in scope.

The five fixes remove only commas between record fields in `lifecycleKernelReadConfig`,
`lifecycleKernelReadIdentity`, `lifecycleKernelReadAccounting`, `lifecycleKernelReadState`, and
`lifecycleKernelReadEvent`. Field values, decode order, tuple remainder, matching encoder order,
wire bytes, event order, state predicates, transition code, and theorem/axiom boundary are
unchanged. `LifecycleKernel.lean` is now 23,464 bytes / SHA-256
`5B6D0B4C7109946F8A26C2EDE19FC2B25447E373B50CF863BDCD04EC6488D8AC`.

`build.rs` has exact pins for ten Lean/project inputs, five Rust build/runtime inputs, four Lean
tool executables, and the complete 2,485-file Lean `.olean` tree (353,835,856 bytes; canonical
tree-manifest SHA-256
`a76983027716a67e972e8e7d5c87d8d95c0ceb888a20f453d987843620a7354a`). Its versioned manifest
uses sorted relative paths, counts, lengths, and SHA-256 values without timestamps or absolute
paths. It compiles Lifecycle, LifecycleKernel, Model, and Sha3 in a fresh source copy under Cargo
`OUT_DIR`, archives and verifies those exact objects plus the embedded manifest object, and writes
a deterministic build receipt with object/archive identities. Cargo rerun inputs cover the pinned
Lean/Rust files, Lean tool binaries, `.olean` tree, and prior pinned base objects/archive.

The focused source-pin audit initially detected two malformed Build.rs constants: the Checker
digest was mistyped and the Main digest was one character short. Both were corrected; the final
read-only audit matched all 10 Lean/project and 5 Rust inputs to their current SHA-256 values. No
new source-pinning test was added. No Lean/Lake build, Cargo build, Python test, or guard ran in this
source-only phase; the prior Lake compiler failure remains open and the parser fix is uncompiled.
The local `lifecycle.exe` remains 6,571,008 bytes / SHA-256
`B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881`; it was not replaced or
repinned. The read-only Rust entry point and adapter do not inspect the new manifest, so an old
pinned executable can still be accepted after sources change. Runtime source/manifest enforcement
and a newly reviewed executable identity are the exact remaining source-to-binary gap. All status
remains `proofSuiteId=null`, `production_usable=false`, activation `false`,
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

## Superseding native integration status — 2026-09-19

The earlier adapter-deferral text below is historical and is superseded for this bounded,
nonactivating stage by the Driver's accepted GNU-target native integration packet. Queue now
consumes the guarded static Lean archive through the Rust adapter at the Cargo target-triple
release path. This demonstrates a source-pinned build and Queue integration; it does not qualify
the deployed product, close the formal-kernel gates, select a proof suite, or authorize activation.
The preserved MSVC/CRT link failures and the initial Queue adapter-binding/path failures remain
evidence and are not relabeled as passes.

The later provenance correction is authoritative for this stage: `build.rs` compiles the C
boundary with the pinned clang recipe and links the verified object directly; the source binding
includes the C source. The actual compiled finish-operation coverage is
`source_finish_unknown`, `verifier_finish_accepted`, and `verifier_finish_unknown`. The Queue
does not claim Lean ownership of `AWAITING_HANDOFF -> QUEUED` or `QUEUED -> LEASED`; those remain
Python transitions. The governing Queue admission timeout remains 3 seconds, with Python-owned
process termination/cleanup distinct from Rust's post-call elapsed-time check.

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

### Source completion ownership correction closure — 2026-09-13

This append-only record closes the Driver-granted ownership correction from immutable HEAD
b1b8843a86cb69b1efb5703f11b8e8b533e2faea, tree
11303a2c94fad8fc3e725c7d3f71cafecb9252b4. The implementation commit is
0fb0ca1cae3ab6e77e8f3860f5e9b0a05b8fa226, tree
5617f1e7052fdda5d20d2aae55ac90263deffdc5, parent
b1b8843a86cb69b1efb5703f11b8e8b533e2faea, subject Bind source completion to consuming
invocation. It contains exactly these six tracked paths:
app/minimal_clearance_verification_queue.py,
app/minimal_clearance_verification_runtime.py,
tools/direct_mask_complete_path/source_boundary.py,
tools/direct_mask_complete_path/complete_path.py,
tests/test_direct_mask_state_profile12.py, and
tests/test_direct_mask_complete_path.py.

The shared authorization now returns an opaque volatile SourceLaunchOwnership receipt with
object-identity binding to its exact authorization and admission. The receipt has a one-shot
native-entry claim. Durable finish requires that exact receipt; authorization.consumed alone,
a wrong receipt, a stale receipt, or an unconsumed value cannot mutate the STARTED row.
complete_path acquires ownership before the native call and passes it through both success and
failure cleanup; primary and cleanup failures remain grouped. The source boundary rejects a
reused receipt before a second native entry. Crash/restart and no-refund semantics remain
unchanged.

The focused durable interleaving test records the actual result: one durable STARTED admission,
winner paused in the existing source native stub, loser consume error
QueueConflictError(source_authorization_used), loser cleanup error
QueueConflictError(source_authorization), pre-winner source snapshot STARTED with metadata
(1, 4096, 100, 1, 0) and transitions
(BATCH_ISSUED, SOURCE_AUTHORIZED, SOURCE_STARTED), stale receipt rejected, reused winner
receipt rejected as SourceBoundaryError(source_authorization), native_calls=1, winner
completed with SOURCE_COMPLETED, and independent verify_database passed. No second entropy,
work, refund, or durable transition occurred before the winner completed.

Final affected checks were actual passes:
  py -3.14 -B -m py_compile [six changed Python files] -> exit 0
  py -3.14 -m unittest tests.test_direct_mask_state_profile12
  Ran 37 tests in 18.885s / OK
  py -3.14 -m unittest tests.test_direct_mask_source_boundary
  Ran 7 tests in 0.631s / OK
  py -3.14 -m unittest tests.test_direct_mask_complete_path
  Ran 9 tests in 20.497s / OK
  py -3.14 -m unittest tests.test_minimal_clearance_verification_queue tests.test_minimal_clearance_verification_runtime
  Ran 50 tests in 14.827s / OK
  py -3.14 -m unittest tests.test_minimal_clearance_composition_v2 tests.test_minimal_clearance_source_auth_verifier_adapter
  Ran 33 tests in 18.701s / OK

The assigned binaries were unchanged:
  build-performance/fixture-candidate/Release/direct_mask_fixture_source_performance.exe
  SIZE=275968 SHA256=E07865D9CE6C2644142D3EA61030BD308D5BBD09FE861C630CC5EEBE1F3FE5D9
  build-performance/q/Release/dm_pipeline_verifier_cli.exe
  SIZE=240640 SHA256=F35F6AF28EC2D269831CFB6BDD1C2414D439FFEC2B26C73CC39495720D9B9E5D

Exactly one fresh guarded containing path ran through the existing guard with no rebuild.
The guard used DIRECT_MASK_PERFORMANCE_NATIVE=1 and regex
^direct_mask_complete_path_integration$. No unchanged native/PQ suite replay, benchmark,
filtered integration, cap/target change, qualification, or activation was performed. Raw
files are:
  build-performance/guarded-ctest-source-ownership-20260913.stdout.log
  size=5549 SHA256=6882B2E5FD07A10B3D6154F7755D422FD7F27565FD34D399469FE8ADBF81D510
  build-performance/guarded-ctest-source-ownership-20260913.stderr.log
  size=0 SHA256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
  build-performance/guarded-outer-ctest-source-ownership-20260913.log
  size=2884 SHA256=5FF4C7DB3DB5E436E1297E83DECD4C6CB17A6630BE83E567A1CF9C456030C517

The actual outer guard output was:
  PHYSICAL_PREFLIGHT free_bytes=2758893568 reserve_bytes=1073741824
  CHILD_EXIT_CHECK exit7=7 exit0=0
  CHILD_EXIT_STATUS label=CTest exit=0
  LIVE_PHYSICAL_SUMMARY label=CTest samples=13 min_free_bytes=2653110272 reserve_bytes=1073741824 peak_working_set_bytes=82153472 peak_private_bytes=53911552
  CLEANUP=PASS label=CTest owned_process_tree=empty
  MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

The actual child output was:
  Ran 9 tests in 7.075s
  OK
  1/1 Test #2: direct_mask_complete_path_integration ... Passed 7.53 sec
  100% tests passed, 0 tests failed out of 1

The raw child COMPLETE_PATH_EVIDENCE line was:
  2: COMPLETE_PATH_EVIDENCE {"acknowledged_operation_count": 100, "activation": false, "handoff_ms": 42.229, "independent_event_count": 100, "independent_operation_count": 100, "independent_outbox_count": 100, "independent_transaction_count": 100, "independent_verified_batch_count": 1, "issued_batch_count": 1, "operation_count": 100, "outbox_ack_ms": 205.729, "outbox_acknowledged_count": 100, "production_usable": false, "proof_files_persisted": false, "proof_suite_id": null, "queue_verify_state_ms": 1839.465, "receiver_duplicate_dispatches": 0, "receiver_side_effects": 100, "reopened_without_work": true, "run_artifact_inventory": ["state.sqlite"], "source_call_ms": 2437.472, "source_calls": 1, "source_measurement": {"active_process_limit": 1, "cap_bytes": 4500000000, "cap_enforced": true, "child_process_count": 2, "cleanup_complete": true, "elapsed_ms": 2415.184, "exit_code": 0, "measurement_complete": true, "pagefile_growth_evidence": "unavailable", "peak_job_commit_bytes": 21688320, "peak_private_commit_bytes": 20422656, "peak_working_set_bytes": 18243584, "private_commit_delta_bytes": 20201472, "process_tree_complete": true, "scratch_peak_bytes": 0, "stage": "source_appliance", "stderr_bytes": 0, "stdout_bytes": 539013, "timed_out": false}, "source_workspace_empty": true, "state_issue_ms": 11.877, "state_port_calls": 1, "state_sequence": 100, "total_path_ms": 4905.138, "transaction_count": 100, "unconfirmed_operation_count": 0, "unique_idempotency_keys": 100, "verifier_calls": 1, "verifier_measurement": {"active_process_limit": 1, "cap_bytes": 4500000000, "cap_enforced": true, "child_process_count": 2, "cleanup_complete": true, "elapsed_ms": 1613.941, "exit_code": 0, "measurement_complete": true, "pagefile_growth_evidence": "unavailable", "peak_job_commit_bytes": 20389888, "peak_private_commit_bytes": 19132416, "peak_working_set_bytes": 16588800, "private_commit_delta_bytes": 18460672, "process_tree_complete": true, "scratch_peak_bytes": 0, "stage": "independent_verifier", "stderr_bytes": 0, "timed_out": false}, "verifier_workspace_empty": true}

The earlier accepted 6.723s guarded run remains prior input evidence; it was not recreated.
The inherited documentation-governance warning remains explicit: 11 tests in 9.754s,
FAILED (errors=2), listing the six pre-existing unregistered README paths recorded above.
No new correction-phase test failure remained. The initial wrong architecture-path probe and
forward-slash nested apply-patch path attempt were read-only/no-op procedural failures; both
were corrected without changing protected files.

Post-implementation verification matched HEAD 0fb0ca1cae3ab6e77e8f3860f5e9b0a05b8fa226,
tree 5617f1e7052fdda5d20d2aae55ac90263deffdc5, parent
b1b8843a86cb69b1efb5703f11b8e8b533e2faea; tracked status was clean before this record
append and git diff --check was clean. The stage remains synthetic and nonactivating:
proofSuiteId=null, production_usable=false, activation=false, NOT_QUALIFIED/INACTIVE/UNSELECTED.
proofSuiteId=null, production_usable=false, activation=false, NOT_QUALIFIED/INACTIVE/UNSELECTED.

Raw child fidelity note: the preceding ownership closure transcription omitted the literal
verifier_measurement stdout_bytes=0 field. The retained raw line, copied byte-for-byte below,
is authoritative and supersedes that one transcription omission; no binary or log changed.

  2: COMPLETE_PATH_EVIDENCE {"acknowledged_operation_count": 100, "activation": false, "handoff_ms": 42.229, "independent_event_count": 100, "independent_operation_count": 100, "independent_outbox_count": 100, "independent_transaction_count": 100, "independent_verified_batch_count": 1, "issued_batch_count": 1, "operation_count": 100, "outbox_ack_ms": 205.729, "outbox_acknowledged_count": 100, "production_usable": false, "proof_files_persisted": false, "proof_suite_id": null, "queue_verify_state_ms": 1839.465, "receiver_duplicate_dispatches": 0, "receiver_side_effects": 100, "reopened_without_work": true, "run_artifact_inventory": ["state.sqlite"], "source_call_ms": 2437.472, "source_calls": 1, "source_measurement": {"active_process_limit": 1, "cap_bytes": 4500000000, "cap_enforced": true, "child_process_count": 2, "cleanup_complete": true, "elapsed_ms": 2415.184, "exit_code": 0, "measurement_complete": true, "pagefile_growth_evidence": "unavailable", "peak_job_commit_bytes": 21688320, "peak_private_commit_bytes": 20422656, "peak_working_set_bytes": 18243584, "private_commit_delta_bytes": 20201472, "process_tree_complete": true, "scratch_peak_bytes": 0, "stage": "source_appliance", "stderr_bytes": 0, "stdout_bytes": 539013, "timed_out": false}, "source_workspace_empty": true, "state_issue_ms": 11.877, "state_port_calls": 1, "state_sequence": 100, "total_path_ms": 4905.138, "transaction_count": 100, "unconfirmed_operation_count": 0, "unique_idempotency_keys": 100, "verifier_calls": 1, "verifier_measurement": {"active_process_limit": 1, "cap_bytes": 4500000000, "cap_enforced": true, "child_process_count": 2, "cleanup_complete": true, "elapsed_ms": 1613.941, "exit_code": 0, "measurement_complete": true, "pagefile_growth_evidence": "unavailable", "peak_job_commit_bytes": 20389888, "peak_private_commit_bytes": 19132416, "peak_working_set_bytes": 16588800, "private_commit_delta_bytes": 18460672, "process_tree_complete": true, "scratch_peak_bytes": 0, "stage": "independent_verifier", "stderr_bytes": 0, "stdout_bytes": 0, "timed_out": false}, "verifier_workspace_empty": true}

### Ownership receipt native-entry binding correction — 2026-09-13

Starting identity was immutable HEAD ed079dd8f68970ad2732345a747f32a4d2216a5f / tree b5c6ef2efa2ecb7609e0e3d3c349464750965eaa, with only the existing untracked build-performance/ tree. The public counterexample was confirmed: SourceLaunchOwnership(real_authorization, real_admission, object()) reached native because _begin_native checked only its local one-use flag; finish rejected it too late.

The correction adds the existing SourceLaunchAuthorization._owns() predicate inside the existing ownership entry lock, before _native_entered is set. Existing failure semantics remain source_authorization_used for receipt reuse and source_authorization for unissued, wrong-token, or unconsumed ownership. No source-boundary API, durable schema/accounting, native binary, request, orchestration, entropy, counter, or retry opportunity changed.

The existing Profile12 ownership test now constructs the fabricated public receipt with the real durable STARTED authorization/admission. It asserts SourceBoundaryError("source_authorization"), authorization.consumed == False, native_calls == 0, and unchanged durable snapshot (STARTED, (1, 4096, 100, 1, 0), (BATCH_ISSUED, SOURCE_AUTHORIZED, SOURCE_STARTED)). It then legitimately consumes the authorization and retains the paused winner/loser cleanup/no-refund interleaving, including exactly one native stub call and exact-owner completion.

Raw focused checks:
py -3.14 -B -m py_compile app/minimal_clearance_verification_queue.py tests/test_direct_mask_state_profile12.py
exit_code=0
test_source_completion_ownership_isolated_from_loser_cleanup (tests.test_direct_mask_state_profile12.Profile12StateTests.test_source_completion_ownership_isolated_from_loser_cleanup) ... ok
Ran 1 test in 0.248s
OK
exit_code=0
test_one_use_authorization_serializes_concurrent_native_entry (tests.test_direct_mask_source_boundary.DirectMaskSourceBoundaryTests.test_one_use_authorization_serializes_concurrent_native_entry) ... ok
Ran 1 test in 0.017s
OK
exit_code=0

Only queue.py and the existing Profile12 ownership test changed: 22 insertions, 3 deletions; git diff --check was clean. Post-test SHA-256 identities: queue B944E3B1D6103992DA8134561E5135C66A367F519B04C07EDA4DF1D4C073CC31; focused test F4A54985F128401702A9FEC44CCAD3348C0AFBBE34BFD20F292A53F8AF82357C; unchanged source_boundary.py 0CB820384F20101D6FABBE2A9614911FFA1573B5C052157B0519F0C4A093155D.

Skipped with explicit count/reason: new guarded/native executions 0 because valid issued receipt, request, orchestration, binaries, and prior reviewed guarded containing path are unchanged; full/unchanged suites, builds, benchmarks, filtered integration, production/activation, and real-data runs 0 because the request required focused checks only and prohibited campaign expansion. No new test, warning, or identity failure occurred. The inherited documentation-governance warning remains the recorded 11-test/2-error warning for six pre-existing unregistered README paths. Qualification remains proofSuiteId=null, production_usable=false, activation=false, NOT_QUALIFIED/INACTIVE/UNSELECTED.

## Final native receipt correction — 2026-09-19

The final correction adds null-safe native-initializer cleanup and build-time receipt freshness:
the pinned build verifies the exact four archive members against direct objects, recompiles and
hashes the C boundary, then direct-links that fresh object. Final identities are C source
`0d7a7c78592c06c71f78fbbf550b5a2f10b2621746e5d4fcaba728d40abe0dd7`, archive
`86cedcae0f9758b75c7a4a4d3de5ca9c28b05b628e08b1868b26ca74584ca13c`, combined source binding
`768f9d69ebb660875448088bfc1983862b2db46f69e773bde19b7ee0feb09de6`, and adapter
`0aeb8ccd18e4eb905c1147889bf66265c94d9dcc2311c3d699571a85cf3fb577`.

The guarded build exited 0 (cleanup PASS, mutex RELEASED); the affected verification exited 0
with `Ran 8 tests in 5.667s` and `OK`, including the null-cleanup contract and compiled finish
boundaries. An intermediate stale adapter pin produced three exact binding errors and was then
corrected and rerun successfully. This remains synthetic and nonactivating; no qualification or
deployment claim is made.

## Receipt target ordering correction — 2026-09-19

The native archive-member check now runs after fresh C compilation and compares the archive
member with the exact fresh object sent to the linker. The affected guarded build exited 0 with
minimum free bytes `4404867072`, peak private bytes `224628736`, cleanup `PASS`, and mutex
`RELEASED`.

The resulting adapter unexpectedly changed to 6472192 bytes, SHA-256
`92afee451f9f10d4ab71de2277be6b6db8798e275658c52824cb820f129c429d`, from the prior reviewed
6470656-byte `0aeb8ccd18e4eb905c1147889bf66265c94d9dcc2311c3d699571a85cf3fb577`. The mismatch
is preserved without repinning; application verification is not newly claimed.
The accepted recipe was restored by running the guard-launched inner PowerShell from
`semantic_kernel/rust`, retaining the pinned Rust compiler and crate-local linker/rustflags. The
adapter returned to 6470656 bytes, SHA-256
`0aeb8ccd18e4eb905c1147889bf66265c94d9dcc2311c3d699571a85cf3fb577`. The affected guarded
verification passed with `Ran 8 tests in 6.345s` and `OK`; no repinning or qualification claim was
made.

## Pure Queue lifecycle candidate and adapter-contract closure — 2026-09-22

The Driver accepted the pure lifecycle correction at source HEAD
`71438a3fbf5a87bb86f03d39752c4f9e391727da`, tree
`ce87d880026b7eeaafd8c0222473790d25c1ea3a`, parent
`0a81b1f856db09e83d31b0701795d486ee7a5eec`. Its exact tracked source paths are
`semantic_kernel/lean/Admission/Lifecycle.lean`, `LifecycleProofs.lean`, and
`LifecycleCases.lean`; no Python, Rust/C/native, Model/Library/Sha3/codec/Lake/toolchain, test,
ops, schema, or deployment path changed. The maintained contract is recorded in the new
Profile12 section of `docs/LEAN_FORMAL_KERNEL.md`.

The pure candidate defines the exact two-transition seam. It reconstructs configuration, batch and
ordered-member identity, source/verifier/terminal status, attempt/reservation, cumulative
A/S/M/U/V counters, transition sequence, and lease fields from the existing Queue rows under the
existing owner lock and one `BEGIN IMMEDIATE`. `queue_metadata.live_lease_count` is global and
bounded at one; selected-batch `liveLeaseCount`, claim sequence, and expiry remain local. Submit
preserves a live unrelated global lease while producing `QUEUED` plus `HANDOFF_SUBMITTED`; claim
requires global zero and atomically produces global/local lease one plus `LEASED` and
`VERIFICATION_STARTED`. Issue accounting remains cumulative with exact 101-unit reservation
intervals and `proof.used=sourceU.used*101`; Python owns authentication, token/fence/hash custody,
locking, durability, cleanup, expiry, recovery, and HELD outcomes.

The accepted guarded evidence was reused without rerun. Build suffix
`lean-lifecycle-global-lease-final-build-20260920-54` ran the exact inner command
`lake build Admission.LifecycleCases` from `semantic_kernel/lean`: child exit `0`, six jobs,
cleanup `PASS`, mutex `RELEASED`, outer exit `0`. Its child stdout is 178 bytes,
SHA-256 `C103F3FBB1C9C79546445446AD596233FABF69A740657B12BD501088487334AF`; stderr is 0 bytes,
SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`, with exact output:

```text
✔ [4/6] Built Admission.Lifecycle (3.8s)
✔ [5/6] Built Admission.LifecycleProofs (3.4s)
✔ [6/6] Built Admission.LifecycleCases (11s)
Build completed successfully (6 jobs).
```

Run suffix `lean-lifecycle-global-lease-final-run-20260920-55` ran the exact inner command
`lake env lean --run Admission/LifecycleCases.lean` from the same directory: child exit `0`,
cleanup `PASS`, mutex `RELEASED`, outer exit `0`; stdout is 30 bytes,
SHA-256 `831580C16C0BD6E398CCDDF59EF52348F13B9373453C29D45E023D92BB1B0331`, stderr is 0 bytes
with the same empty-stderr hash, and the complete result is:

```text
LIFECYCLE_CASES=PASS cases=68
```

No new source/test/build/checker/benchmark/measurement/native replay was run in this
documentation closure: count `0`, because the accepted source and raw evidence were unchanged and
the Driver prohibited replay. Historical compile failures, adapter-pin failures, native link
failures, documentation-governance warning, and all prior raw receipts remain preserved. The
existing source-pinned admission adapter does not consume `LifecycleTransition`, and no Queue
runtime call site has been added; formal release, guarded sidecar verification, demonstrated
same-lock integration, cross-language KAT, theorem-manifest/axiom, independent-kernel,
mutation/replay/recovery/resource, and deployed-link gates remain open. `proofSuiteId=null`,
`production_usable=false`, activation is false, and the status remains
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

## Driver 2 lifecycle sidecar source — 2026-09-22

The authorized nonactivating source stage adds `app/minimal_clearance_lifecycle_adapter.py`,
`semantic_kernel/lean/Admission/LifecycleKernel.lean`, the separate Rust `lifecycle` binary in
`semantic_kernel/rust/src/bin/lifecycle.rs`, its focused `build.rs` archive wiring, a read-only
same-connection snapshot entry point in
`app/minimal_clearance_verification_queue_independent.py`, and
`tests/test_minimal_clearance_lifecycle_adapter.py`. The binary framing is version 1 with a
16,384-byte input bound and 32,768-byte response bound. The adapter reconstructs validated
Profile12 identity, source/verifier/terminal, attempt/reservation, local/global lease, transition,
and accounting state; it supplies the caller's time and volatile handoff observation; and it
compares the entire Lean after-state and canonical Queue event bytes against host-planned values.

The connection helper requires an active caller transaction, performs the existing independent
database reconstruction on that same handle without configuring PRAGMAs, and makes no database
writes. It cannot prove that the caller holds the OS owner lock or used `BEGIN IMMEDIATE`; those
remain caller obligations. No Queue runtime call site was added. Python remains the sole transaction
authority, and Lean remains nonauthoritative until a separately accepted integration and release.

Static source review found and corrected Rust FFI reference reuse, changed output extraction to
bounded linear ByteArray indexing, made the hex decoder tail-recursive, and added a test assertion
that SQLite PRAGMAs remain unchanged. These edits have not been compiled or executed. No direct
finite guard handoff, fresh valid memory, or checked guard packet is present in this task, so the
explicit pre-execution gate remains closed. Skipped in this stage: 1 Lake build, 1 Cargo build, 1
focused Python test module, and 1 `git diff --check`; each remains unrun pending that handoff. The
accepted prior Build54/Run55 evidence (`LIFECYCLE_CASES=PASS cases=68`) was not replayed (count 0).
No existing adapter, archive, native object, source pin, or qualification value was repinned.

At verification checkpoint, HEAD remains `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55`. The
protected `Admission/Main.lean`, `lakefile.toml`, existing Rust `src/main.rs`, accepted
`Lifecycle.lean`/proof/cases, and `native_boundary.c` remain byte-identical to their recorded
identities. Pre-existing untracked `.lake/`, `Experiment.lean`, native linker command, and native
object files remain preserved. The separate canonical financial Queue checkout still has its
previously recorded independent-verifier source mismatch (174,590 bytes / SHA-256
`B944E3B1D6103992DA8134561E5135C66A367F519B04C07EDA4DF1D4C073CC31` versus the Queue checkout's
207,703-byte / SHA-256 `654ECAF9D7D5A8FC6E54AFC2BA4834FCB63D3AD05B8EEB7E4C7D5C3DBED174A2`, with
796 insertions and 7 deletions in the prior read-only comparison). This stage does not copy or
change that checkout. The sidecar remains unbuilt, unverified, and disconnected from production;
`proofSuiteId=null`, `production_usable=false`, activation `false`,
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

## Lifecycle adapter integrity follow-up - 2026-09-22

This bounded follow-up changed only `app/minimal_clearance_lifecycle_adapter.py`,
`tests/test_minimal_clearance_lifecycle_adapter.py`, and the truthful status records in
`CURRENT_TASK.md`, `STATE.md`, and `docs/LEAN_FORMAL_KERNEL.md`. The adapter requires the
executable's positive byte size and exact 32-byte SHA-256, forwards both values unchanged to the
contained-process API, rejects absent expected config in reconstruction and evaluation, and caps
timeout at the Queue authority's 3.0 seconds. Source tests cover accepted pinned/config-bound calls
and rejection for missing/wrong pin, missing/mismatched config, timeout above 3.0 seconds, and an
absent caller transaction, with connection immutability assertions.

The one guarded Lake check used `run_guarded_v3.ps1` SHA-256
`55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`, RunSuffix
`queue-lifecycle-kernel-20260922-r1`, and inner command `lake build Admission.LifecycleKernel`
from `semantic_kernel/lean`. The guard preflight was 3,413,000,192 free bytes; the live minimum
was 2,744,217,600, peak private bytes were 952,303,616, and the live run stayed above the
2,190,433,321-byte floor. Child exit was 1 and outer guard exit was 1. Guard self-tests reported
`CHILD_EXIT_CHECK exit7=7 exit0=0`; cleanup was `PASS` and the mutex was `RELEASED`.

The complete child output is retained at
`build-filter-native/guarded-command-queue-lifecycle-kernel-20260922-r1.stdout.log` (1,631 bytes,
SHA-256 `5A5D70EB1CCCD24BDFC4A8EDCF53AED2A5DAFC5BE2606EBA5C7A19F5AF9B8EC8`) and stderr (20 bytes,
SHA-256 `C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F`). Lean reported
`unexpected identifier; expected '}'` at `semantic_kernel/lean/Admission/LifecycleKernel.lean`
lines 156:71, 188:79, 235:65, 303:83, and 418:77, followed by `Lean exited with code 1` and
`Some required targets logged failures: Admission.LifecycleKernel`. That Lean source is outside
this follow-up's writable scope and was not changed.

STOP after the failed Lake check. Cargo build (1 planned), the focused Python test module (1), and
diff check (1) were not launched. Adapter tests therefore have no execution result. The historical
`3,409,649,664`-byte sample is below the Engine's `4,190,433,321`-byte workload-start estimate;
it is not an Engine post-handoff preflight. The corrected Queue preflight separately reported
`3,393,343,488` free bytes, above the Queue guard's floor, with `PRECHECK=PASS`; no Engine
preflight was repeated. After the Lake stop, the mutex probe was `ABSENT` and relevant build
process count was zero. The direct next lane owner is Lean Engine. After handoff, Engine must make
a fresh preflight against `4,190,433,321` bytes; if below that threshold, Engine passes the lane
to State without starting its workload. No Engine workload ran. Python remains runtime authority;
the adapter has no Queue caller and has no activation or production claim.

Execution setup notes: one preliminary host-only preflight invocation exited `1` because `$guardDir`
was unset (`Cannot bind argument to parameter 'Path' because this parameter is null.`); it launched
no workload, and the corrected preflight later passed. One wrapper-construction attempt raised
`SyntaxError: Unexpected identifier '$LASTEXITCODE'` before a shell or process launched. An
exploratory broad `rg --files` reported access denied for
`C:\Users\neers\Documents\Codex\2026-08-25-v6-focused-temp\proof-primitives-run-1` and
`C:\Users\neers\Documents\Codex\2026-08-25-v6-focused-temp\proof-primitives-run-2`; the exact
guard path was used for the authorized run.

## Claim-clock after-lock timing correction — guarded Queue verification — 2026-09-22

This bounded follow-up changed `app/minimal_clearance_verification_queue.py` and
`tests/test_minimal_clearance_verification_queue.py`, then recorded evidence in this file,
`STATE.md`, and `docs/LEAN_FORMAL_KERNEL.md`. The claim now samples its one `now` after
`BEGIN IMMEDIATE` succeeds, under the existing Queue owner lock and within the rollback-protected
transaction block. The new contention regression covers both expiry-plus-eligibility claim and
expiry rejection, verifies every time-bearing claim/event row against that sample, reservation and
global lease accounting, duplicate absence, cleanup, and independent database reconstruction.

The fresh guarded verification used `run_guarded_v3.ps1` SHA-256
`55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`, suffix
`queue-claim-clock-20260922-r2`, and exact command
`py -3.14 -B -m unittest tests.test_minimal_clearance_verification_queue` from the Queue checkout
with Python `3.14.4`. It ran 32 tests in `10.095s`, `OK`, with no warning or skip output; child and
outer exits were `0`, cleanup `PASS`, mutex `RELEASED`. One earlier guarded attempt (suffix `r1`)
ran 32 tests and failed the new regression's uppercase/lowercase event-ID expectation; the test was
corrected to `.hex().upper()` and the full focused module was rerun once. The complete failure and
success outputs, log hashes, and guard resource evidence are recorded in `STATE.md`.

The final Queue source hashes are recorded in `STATE.md`. The regression establishes post-lock
sampling in the tested Python path, not wall-clock monotonicity or time-through-COMMIT atomicity.
No Lean build/proof, executable pin, Queue runtime integration, production qualification, or
activation claim is included. The remaining next action is the direct lane handoff to Lean Engine,
which must perform its own fresh preflight for the repaired CodecLaws proof run.

## Profile12 Queue lifecycle sidecar integration — source-only stage — 2026-09-23

The current direct assignment adds the Profile12 lifecycle sidecar to successful
`submit_batch_handoff` and `_claim_next_batch` transitions. The exact writable scope is limited to
`app/minimal_clearance_lifecycle_adapter.py`, those two lifecycle callsites in the protected Queue
source, their focused tests, and this file, `STATE.md`, and `docs/LEAN_FORMAL_KERNEL.md`. The
independent checker, Composition, Lean sources, source-auth/native paths, and profile/runtime
authority remain outside this assignment.

The adapter now fixes the release path to
`semantic_kernel/rust/target/x86_64-pc-windows-gnu/release/lifecycle.exe` and fixes the expected
identity in source at 6,571,008 bytes and SHA-256
`B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881`. The local file matched that
identity. The parent supplied this reviewed synthetic pin. The retained build inputs identify the
Lifecycle Lean sources, but `build.rs` does not hash them; this is not reproducible
source-to-binary provenance and earns no release, formal, or production qualification claim.
Callers can no longer supply an executable path or expected identity through the adapter API.

The Queue checks its owner lock, enters `BEGIN IMMEDIATE`, samples its Python clock, validates the
current transaction, and invokes the sidecar before the successful submit/claim SQL writes. The
adapter reconstructs the state with the independent read-only checker on that same active
connection, derives the complete Python after-state/event plan, and requires exact Lean after-state
and canonical Queue event-byte agreement. A failure reaches the existing rollback path. Failed
submit closes/wipes only that volatile handoff and leaves the durable batch retryable with a fresh
handoff. Failed claim rolls back transaction-local expiry work before token generation or lease
mutation and leaves the attached handoff/accounting available for retry. Python remains the lock,
clock, volatile-custody, SQL, and commit authority.

The kernel has no `HELD` operation. Four existing submit branches therefore remain Python-owned:
batch identity mismatch (1), non-awaiting status (1), incomplete source admission (1), and expired
validity (1). They retain their existing `_hold_batch_locked` result/event behavior and do not call
the successful-submit transition. A claim with no eligible row is one separate no-claim path (1);
it may commit expiry housekeeping but produces no `claimNextBatch` transition. When a candidate is
selected after expiry housekeeping, all such writes remain in the same uncommitted transaction and
roll back if the claim sidecar fails.

Source SHA-256 before → after for this source stage: adapter
`D8F86B6E10C94C9B2BE9A74469482C8E8972916764D3F9002C194991B2FDC37F` →
`BBD5F7136D8749CC507C35BE5A96278CEA1D73573A8781DFADDE1E7EC887683E`; Queue
`BE8C692CF8D3EB04702BC4449EBEA425FEACF924C2AA43A90973A89B2737917B` →
`FE5D1DC4DFCB17D9FFA1810B14EC6BC1E7D3760427DD0C26C82FA0F2F8582950`; adapter tests
`6E0E6DC380B5236D7B2D2AEFF8949E277CE723FAE425B9BB79BA193F1A4E3750` →
`1F8F7F0BB34A3E86E9733E8846EC594772369A1D4D30078746483012D7EF3252`; Queue tests
`F605358181C9120ADEFEEBF47B6BEB997C5C462E2C4FC9C65D286A9BF5487410` →
`D560DE4226427A31C575C5AB384336707597E6C1B70AD7AB0DB68DC4D8510A94`.

At the source checkpoint, the 13-method adapter module and four focused Queue methods were still
pending. Their execution results are recorded in the focused lifecycle sidecar verification
follow-up below. The other 30 Queue methods were excluded by the finite focus scope (count 30);
the 68-case Lean lifecycle replay remains unrun (count 0). The previous LifecycleKernel compiler
failure remains recorded separately and was not rerun or relabelled.

At this checkpoint HEAD/tree remain `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55` /
`40d8268880072f23b4c46fc83aee2c5084184083`; no file was staged or committed. Existing dirty and
untracked Queue/Lean build work was preserved. The direct next lane is Driver's Provider App focused verification. This Queue lane is released;
no lane reservation or polling followed.

## Focused lifecycle sidecar verification follow-up — 2026-09-23

The assigned Queue checkout remained at HEAD/tree
b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55 /
40d8268880072f23b4c46fc83aee2c5084184083. The adapter and protected Queue source hashes still
match the source handoff. One guarded 17-method packet ran. It reported 15 passing methods, one
assertion failure, and one error. Inspection showed both failures were stale focused test
expectations: the missing absolute executable produced the existing OS open error 2, and the
Queue lease schema names its timestamp leased_ms. Only those two assertions were corrected; no
production source was edited.

A fresh guarded rerun of those two affected methods passed 2/2. The full 17-method set is therefore
covered by the initial packet plus the two-method correction rerun; the 17-method packet was not
repeated. The other 30 Queue methods remain outside this finite scope. No build, Lean compiler
repair, 68-case replay, or production authority claim was made. The previous LifecycleKernel
syntax failure remains open. Full raw logs, hashes, memory samples, test identities, and exact
correction details are recorded in STATE.md. The current test hashes are recorded there as well.

The Driver directly owns the next Provider App focused verification lane. The Queue lane is released;
no lane reservation or polling followed.

## Queue-local admission-to-Composition handoff — source and toolchain follow-up — 2026-09-23

This supplement clarifies the earlier versioned Queue-to-State scope. The implemented handoff binds
Queue-owned Profile 12 admission, source, verifier, result, event-chain, reservation, and retry
identities to exactly 100 ordered Queue operation refs and their same-database Composition outbox
correlation IDs. The independent decoder consumes the bounded frame inside the existing Queue
SQLite transaction, so Queue completion and the 100 local Composition transactions, events, and
outbox entries commit or roll back together.

The Queue refs identify Queue operations. They do not establish financial-owner obligation or
member identities, and they do not prove acceptance by a separately owned financial State system.
The Driver correction confirms that this Queue reference mapping is not a demonstrated P12
violation. A cross-owner versioned mapping receipt remains a proposed contract pending the
financial authority's review of identity, retries, recovery, and transaction ownership.

The source change preserves schema 13, Composition schema 4, Profile 12, exact-100 accounting, the
101-unit no-refund reservation, existing post-commit result recovery, and all nonactivation flags.
The outbox gate requires room for one exact 100-job batch before claim and verifier reservation.
A full outbox returns state_outbox_capacity without consuming the queued attempt or handoff, apart
from permitted expiry housekeeping.

The direct v4 packet passed its seven selected methods: four Lifecycle adapter checks and three
Queue outbox/handoff checks. The other 12 adapter methods and 34 Queue methods were outside the
finite packet and were not run. The complete raw result, method identities, toolchain diagnosis,
and guard telemetry are in STATE.md.

Cargo check exited 101 with E0463. Read-only inspection shows that the unqualified active stable
toolchain lacks GNU core, while the exact build-pinned 1.96.0 toolchain has the GNU target standard
library: its manifest and all 60 listed files match the exact build.rs binding hash. A follow-up
check should explicitly select 1.96.0-x86_64-pc-windows-msvc through rustup; it has not run.

Final GNU linking remains unsupported by current evidence. The repository pins target
x86_64-pc-windows-gnu, GNU link flags, the Lean Clang driver, and native C compilation for
x86_64-w64-windows-gnu. A bundled ld.lld.exe exists, but the current configuration does not select
it; Clang reports bare ld as its linker program, and no GNU ld executable was found on PATH. The
actual final linker and every Cargo-produced final-link input are not attested. Switching to the
MSVC target would change the target, ABI/runtime, ordered link contract, manifest, and executable;
it is not an authorized substitute.

The existing lifecycle.exe pin remains unchanged, source-bound mode remains closed, and no
final-link, source-to-binary, formal-release, production, or activation claim follows. HEAD/tree
remain b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55 /
40d8268880072f23b4c46fc83aee2c5084184083. No files were staged or committed. The prior dirty
and untracked work was preserved. No additional build, test, compiler, target installation, or
guarded run followed the direct lane.

## Issue result, cancellation, and Lifecycle adapter edges — source-only — 2026-09-23

Static review confirms `issue_batch` acquires the Queue owner, enters one SQLite
`BEGIN IMMEDIATE`, independently revalidates the durable image before sampling, reserves one 101-unit
proof budget and one U issuance, then writes one batch row, exactly 100 unique 32-byte ordered
Queue-owned operation refs, one attempt row, one `BATCH_ISSUED` event, and the matching counters in
that transaction. The schema enforces unique operation refs and positions; the independent database
verifier checks the committed image. These refs are Queue operation identities and do not map to a
financial owner's members or obligations.

An exception after the issue commit is attempted can leave the caller without the returned batch.
`issue_batch` now classifies ordinary exceptions from that point as
`QueueIndeterminateError("issue_result_indeterminate")`; pre-commit failures still roll back. Three
focused test methods now cover pre-commit rollback followed by a fresh issuance, post-commit
ambiguity with one durable 100-ref/101-unit record, and two concurrent issue writers serializing
their 100-ref batches and cumulative reservations. The existing lifecycle retry test also asserts
that submit/claim retries do not reserve a second 101-unit batch. These tests have not run because
the Security task still owns the single guarded lane and has not directly handed off its safe
boundary. The focused `test_direct_mask_state_profile12.py` issue-commit regression was updated to
expect the typed indeterminate error; it also remains unrun.

This typed error does not create an idempotency key or a durable resolver. `issue_batch` accepts only
the template, so after a lost result the Queue cannot distinguish a repeated request from a new
batch. A caller must not blindly retry the ambiguous issue; another issue call creates a new batch
and consumes a new reservation. After this error the durable row remains AWAITING_HANDOFF without
a caller-held batch object; it continues to occupy capacity until validity expiry or startup
recovery holds it, and its reservation is not refunded. The existing exact post-commit idempotency
for terminal Queue/State completion begins only after the batch identity is known and does not cover
issue creation.

There is no Queue cancel API, cancel event, or cancel test in the active Queue source. The accepted
Lifecycle operation type remains exactly `submitHandoff | claimNextBatch`; its `lifecycleIssueEvent`
relation describes the issue snapshot but adds no issue step. The kernel also has no cancel, expiry,
HELD, or recovery operation. Adding cancellation would require an owner contract for eligible
states, in-flight source/verifier process interruption, terminal event/result identity, retries, and
recovery. The handoff buffer has no per-stream synchronization; `_process_one_batch` starts the
verifier after a committed launch reservation; and `VerifierPort` has no cancellation method. A
concurrent cancel would need a separate process-stop and buffer-custody protocol. This task does
not invent that transition or relabel it as `fresh_handoff_required`.
The current handoff object mutates its buffer without per-stream synchronization, `_process_one_batch`
starts the verifier after a committed launch reservation, and `VerifierPort` has no cancellation
method; a concurrent cancel would need a separately defined process-stop and buffer-custody protocol.

The source-bound adapter remains closed: runtime mode is `legacy-pinned-v2`, the reviewed source
manifest digest is unset, and the pinned executable is the prior synthetic binary. The only
Lifecycle sidecar operations currently supported by Queue are successful `submitHandoff` and
`claimNextBatch`; expiry/HELD/recovery remain Queue-owned host outcomes. Final GNU linking remains
unqualified by the linker evidence recorded above. No tests, build, compiler, checker, or guarded
invocation ran in this source-only continuation; the added test count is 3, executed count is 0.

## Versioned issue request identity and GNU linker selection — source-only — 2026-09-23

The later direct Queue assignment authorizes a versioned issue-request identity in the Queue writer,
independent verifier, runtime, focused Queue/runtime tests, and this child's current-state records.
It also authorizes pinning the installed GNU LLD candidate in `semantic_kernel/rust/build.rs`. The
change leaves all other protected or untracked files untouched.

The new `issue_batch_v1(request_id, template)` API requires an exact 32-byte caller-supplied opaque
ID. The caller must generate a fresh random, non-PHI ID, persist it before the first call, and reuse
it after an ambiguous response. V1
derives the existing 32-byte `queue_batches.batch_id` as SHA3-256 of the fixed
`BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/ISSUE-REQUEST-BATCH-ID/v1\0` domain, the
8-byte big-endian Queue-ID length, the ASCII Queue ID, and the request ID. The raw request ID is not
stored. The existing immutable batch primary key is the durable mapping; schema 13, Profile 12,
DDL, event shape, exact 100 ordered Queue refs, and the single 101-unit no-refund reservation are
unchanged, so no migration or old-database rejection path is needed.

Before a v1 retry returns an existing row, Queue independently verifies the full current database,
checks the supplied template and Queue configuration, and reconstructs the exact original issue
result. Reusing an ID with a different template conflicts before another reservation. The runtime
also exposes `resolve_issue_request_v1` as a read-only full independent lookup. Concurrent same-ID
calls serialize in the existing `BEGIN IMMEDIATE` transaction and return the same batch. The old
unkeyed `issue_batch` API remains for compatibility and has no same-request retry guarantee; callers
that need recovery must use v1. Recovery is scoped to the same authoritative SQLite history and the
caller-retained ID/template/config; this adds no external backup-rollback or caller-storage guarantee.

Read-only file evidence confirms the selected installed Clang is 217,600 bytes with SHA-256
`1AEA18DCA98F91A6A7C65532ADC2567EFC775904D2A4BD28BF06731BC2C3778C`; the selected
`ld.lld.exe` is 6,772,224 bytes with SHA-256
`675E59F33F11CB90500577F116082ED4A6214FCAC3A1BAD88D6323AA0373179F`. The byte-identical
`lld.exe` sibling is not selected. `build.rs` now pins `bin/ld.lld.exe`, records canonical Clang
and selected-linker paths, copies the pinned LLD into the generated native-link directory, records
that copy's identity, and emits ordered `-B`, `-fuse-ld=lld`, `--ld-path=<pinned copy>`, and `-v`
arguments in linker-manifest v2. The fixed GNU target and Clang linker remain unchanged; the
untracked MSVC `native_linker.cmd` wrapper remains untouched.

This remains source-only. The seven focused issue crash/retry/concurrency/runtime/direct-mask test
methods and one guarded GNU Lifecycle build are pending. No build, test, compiler, checker, or guard
ran, so Clang's actual final-link command and successful GNU link are not yet verified. Security
still owns the guarded lane; continue only after its direct safe-boundary handoff. Preserve the old
source-bound adapter closure, exact executable pin, nonactivation flags, and no-payment/no-PHI
boundary.

## Queue Profile12 verified-job receipt — stopped at source-authority binding gap — 2026-09-23

The latest Founder assignment supersedes the prior source-only Queue task for a Queue-owned,
versioned canonical receipt candidate. Its writable scope is limited to
`app/minimal_clearance_verification_queue.py`,
`app/minimal_clearance_verification_queue_independent.py`, directly affected Queue tests, this
file, `STATE.md`, and the existing Queue protocol authority in `docs/LEAN_FORMAL_KERNEL.md`.
Existing dirty Runtime, Composition, Lean, native, build, ops, fixture, and recovery-snapshot state
is preserved; this increment did not edit implementation or tests.

Static tracing confirmed the existing Queue/Composition completion path runs under one
`BEGIN IMMEDIATE` transaction: it closes the batch result, then independently validates the
Queue-to-Composition handoff and applies exactly 100 verified jobs before commit. The terminal
receipt and Queue event are committed with those local Composition effects. Queue refs remain opaque
Queue-owned identities; a separate financial owner mapping or separate-store inbox/outbox is not
implemented or authorized here. Schema 13, Profile 12, the one 101-unit no-refund reservation, and
all nonactivation claims remain fixed.

The requested receipt cannot be built truthfully from the current verified result contract. The
Queue verifier result carries acceptance booleans, proof context, public coin, batch root,
`source_auth_profile`, `source_key_epoch`, result code, and qualification flags. It carries no
issuer identifier/key fingerprint, authenticated revocation snapshot, or source-manifest digest.
The source adapter receives a public key but the Queue-facing result omits its identity; the Queue
cannot independently recompute those absent values. `approved_source_registry_root` is optional and
is not validated as an issuer or revocation authority. The persisted `source_configuration_digest`
commits only to the source identity profile, executable size/hash, and retry limit, so it cannot be
relabeled as a source manifest. See the evidence and exact blockers in `STATE.md` and the Queue
protocol authority.

This is the assignment's STOP condition for an unresolved trust-critical protocol gap. No receipt
code or Queue test changes were made. Do not use `source_auth_profile` as an issuer identity, the
optional approved-source root as a revocation assertion, or the configuration digest as a manifest.
The next action is for the owner to supply the authenticated issuer/revocation and manifest contract
and authorize the trusted Queue input path that exposes it; then continue the Queue-only receipt
implementation and its focused tests. The Driver-owned project acceptance entry point and synthetic
tamper fixtures must be reused rather than duplicated. Guarded execution also remains pending a
direct safe-boundary handoff after Engine and State release the finite lane, followed by fresh v4
preflight at the supplied 2,190,433,321-byte floor and guard SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`.
### Concurrent Driver-owned instruction override — 2026-09-23

Driver added the untracked `AGENTS.override.md` at this checkout root because the full `AGENTS.md`
is 57,858 bytes, above Codex's default 32-KiB project-instruction limit. Preserve the override
without editing it; its observed identity is 2,121 bytes / SHA-256
`EBE04D834B4A0800D726E96E34541FB5EC1DF2A90251217EA6141A49FA775F6B`. Do not treat this path as
release-selected until path policy is reviewed. This concurrent instruction-loading work does not
change Queue source ownership or resolve the issuer/revocation/manifest protocol gap.

## Queue transaction clock and lease-expiry fence — source-only — 2026-09-23

This separate Queue correction is limited to `app/minimal_clearance_verification_queue.py`,
`tests/test_minimal_clearance_verification_queue.py`, this file, and `STATE.md`. It does not reopen
the stopped verified-receipt authority question above. Keep schema 13/Profile 12, Queue event and
receipt wire shapes, exact-100 Composition atomicity, 101-unit no-refund reservations, keyed exact
issue retries, non-`CLEAR` policy, and nonactivation unchanged.

The Queue now pairs its persisted local wall-clock epoch-millisecond sample with a volatile
`time.monotonic_ns()` anchor. A final pre-COMMIT fence checks fresh wall time and conservative
monotonic elapsed time for issue, handoff submission, claim, verifier-launch reservation, and
terminal success. Expiry rolls back a new issue without consuming its reservation; an expired
claim is not returned to the verifier; a late terminal success rolls back all Queue and 100-job
Composition writes, then records HELD. The volatile work item carries its lease's monotonic deadline;
startup recovery still holds every nonterminal row rather than resuming a lease. Per-batch event
timestamps that move backward are rejected, matching the existing independent verifier.

This remains a local admission fence. SQLite has no callback that atomically samples an external
clock at the durable COMMIT instant, and `SystemQueueClock` is the process machine's wall clock, not
trusted time. No clock-source, commit-latency, or external-time guarantee is claimed. The guarded
test module, `git diff --check`, builds, compilers, and other checkers remain gated until direct
Engine then State finite-lane handoff, target-specific fresh v4 preflight, the pinned guard identity,
and the documented free-space floor are all satisfied.

## Queue submitHandoff Lean decision consumption — source-only, unverified — 2026-09-23

This new bounded assignment supersedes the clock-only write scope while preserving that work. The
authorized implementation scope is app/minimal_clearance_verification_queue.py,
app/minimal_clearance_lifecycle_adapter.py, directly necessary Queue Lean/Rust binding files,
focused Queue/adapter tests, this file, and STATE.md. This increment changed only the Queue writer,
the Lifecycle adapter, those two focused test modules, and these current-state records. Existing
dirty/untracked files, including the Lean source, Rust build script, generated artifacts, source
identity pin, and earlier Queue/clock work, remain preserved.

The selected transition is successful submitHandoff. Lifecycle.lean defines its accepted
precondition and after-state/event relation: an eligible AWAITING_HANDOFF batch with source absent
or completed, no verifier reservation or selected lease, no terminal result, and no existing
handoff becomes QUEUED; the transition sets next-eligible and updated time to the supplied Queue
sample, advances the sequence once, marks the handoff attached, and preserves identity, accounting,
and reservation. Its schema-13 event is HANDOFF_SUBMITTED. The existing executable returns this
typed state and event.

The Queue already called the typed sidecar inside the owner lock and BEGIN IMMEDIATE, but the old
adapter also built a Python success plan and required Lean to match it. The adapter no longer
builds that plan for submitHandoff: it checks the decoded output's state shape, preserved fields,
event bindings, schema, and wire encoding, then returns the Lean result. The Queue now uses the
returned after-state for the batch status/timestamps and appends the returned event. Queue event
sequence assignment, canonical JSON comparison, root/digest update, per-batch timestamp ordering,
and SQLite commit remain local durability checks. claimNextBatch still uses the prior Python
cross-check and Python-written row/event fields; this is not a broad Queue runtime authority flip.

Queue-owned batch binding, source-admission completion, validity/expiry, local clock fence,
volatile-buffer custody, event-chain hashing, and HELD/recovery outcomes remain in Python. These
branches execute before or around the successful Lean transition according to the existing Queue
contract. Sidecar unavailable/malformed/mismatched output fails before the successful SQL mutation;
the transaction rolls back and the staged handoff is closed/wiped. A pre-commit fault has the same
rollback behavior. A post-commit process loss leaves the durable QUEUED history for startup
recovery, which holds it and requires a fresh handoff. The existing issue reservation remains
exactly 101 units with no charge/refund on submit; no counters or Composition/outbox rows are
changed here. Exact-100 completion atomicity, schema 13/Profile 12, non-CLEAR and nonactivation
boundaries are unchanged.

Artifact identity remains externally fixed by the adapter's expected executable path, 6,571,008
byte size, SHA-256 B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881, and wire
version 1. Runtime mode remains legacy-pinned-v2; the reviewed source-manifest digest is unset.
This pins the executable bytes but does not establish current Lean-source-to-binary provenance,
formal release, production authority, or activation. The existing claimNextBatch and lifecycle
artifact gaps remain bounded follow-up work.

Focused test updates are test_submit_round_trip_returns_lean_decision_and_preserves_transaction
and test_lifecycle_sidecar_submit_claim_event_bytes_and_independent_verify; the former rejects
state/event shape drift, reservation/counter mutation, and accidental use of the Python claim plan,
and the latter compares persisted submit fields/event bytes with the returned Lean result while
retaining independent database verification. The existing timeout/rollback/fresh-retry and
101-unit reservation assertions remain in the Queue test module.

Execution remains gated on direct Engine then State finite-lane handoff and fresh target-specific
v4 preflight with the recorded guard identity and 2,190,433,321-byte floor. Neither focused test
module was run (2 modules skipped, 0 test methods executed); git diff --check was not run (1
checker skipped); no build, compiler, or other checker ran. No test or source-to-binary pass is
claimed.

## Queue claimNextBatch Lean decision consumption — source-only, unverified — 2026-09-23

This bounded follow-up consumes the already typed `claimNextBatch` result inside the existing
Queue transaction. Writable paths are limited to `app/minimal_clearance_verification_queue.py`,
`app/minimal_clearance_lifecycle_adapter.py`, their focused test modules,
`docs/LEAN_FORMAL_KERNEL.md`, `CURRENT_TASK.md`, and `STATE.md`. Preserve all inherited dirty and
untracked files. Do not edit Lean source, Rust/build pins, binaries, owner modules, or protected
paths. No tests, builds, compilers, checkers, guard, or `git diff --check` may run until direct
Engine then State finite-lane handoff, fresh target-specific preflight, the pinned v4 guard, and the
documented 2,190,433,321-byte floor are received.

`Lifecycle.lean` defines the claim precondition, complete after-state relation, event relation, and
sound transition result. Claim preserves identity, source/verifier/terminal facts, eligibility,
validity, reservations, accounting, proof-attempt/source-epoch data, and the attached volatile
handoff. It sets the batch to LEASED, `updated_ms=now_ms`, attempt/global/local lease counts to one,
lease expiry to `now_ms+lease_duration_ms`, and both claim and transition sequence to the prior
transition sequence plus one. The schema-13 `VERIFICATION_STARTED` event binds that sequence,
batch, attempt, time, exact 100-member count, and the unchanged reservation pair. Queue-only
scheduler, capacity, table emptiness, RNG/token custody, HMAC fence, transaction/clock/commit,
event-root, expiry, HELD, and recovery responsibilities remain host-owned.

The adapter deletes `_host_claim_plan` and validates Lean's decoded claim output by type, exact
changed fields, preserved fields (including eligibility and handoff attachment), exact event
fields/reservation pair, and canonical Queue wire encoding. The shared decoder continues to require
the exact request echo. Queue consumes the typed result for its metadata count, batch state/attempt/
timestamp, lease sequence/start/expiry, token-HMAC bindings, work item, and canonical event append,
within the existing `BEGIN IMMEDIATE` and before the existing final clock fence. It does not mint a
second reservation or alter expiry/recovery semantics.

Focused adapter coverage now rejects claim after-state and event drift and a mismatched request
echo. Focused Queue integration coverage compares the returned claim decision with the committed
batch, metadata, lease, returned work item, and exact persisted event bytes, followed by the existing
independent database verification. The source and documentation hashes, exact inherited Git state,
and unexecuted gates are recorded in `STATE.md` after implementation review.

## Queue Lifecycle decision consumption — guarded verification and Driver handoff — 2026-09-24

This entry supersedes the preceding source-only/unverified status for local runtime-path testing. The authorized checkout is C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\lean-queue-20260913 at detached HEAD b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55, tree 40d8268880072f23b4c46fc83aee2c5084184083. No stage or commit was created; inherited dirty and untracked work was preserved.

The Queue writer and Lifecycle adapter source remained unchanged during guarded verification. One Queue test fixture was corrected after the broad run: test_exact_issue_retry_reads_durable_batch_after_validity_expires had supplied 64 bytes to issue_batch_v1, while the established API and independent verifier require ISSUE_REQUEST_ID_BYTES=32. It now supplies 32 bytes. The correction changed only tests/test_minimal_clearance_verification_queue.py; it does not relax the Queue API or change production logic.

### Focused guarded packet

Target-specific start floor was 3,500,000,000 physical bytes, 1,309,566,679 above the hard floor of 2,190,433,321. This was selected for Python/SQLite work, with no compiler/build planned, based on the earlier guarded Queue run (minimum free at least 4,439,969,792 bytes) and confirmed here by a 4,406,386,688-byte minimum. Guard SHA-256 was 57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB. Fresh host preflight at 2026-09-24T06:57:22.6111504Z reported 4,544,131,072 bytes available, mutex absent, zero competing guard/compiler/Queue-test processes, and zero log collisions. The v4 guard recorded exit7=7, exit0=0, child exit 0, cleanup PASS, mutex released, 21 live samples, minimum free 4,406,386,688, peak working set 150,282,240, and peak private bytes 130,654,208.

The guarded child ran git diff --check followed by py -3.14 -B -m unittest tests.test_minimal_clearance_lifecycle_adapter and 11 selected Queue cases covering returned submit/claim decisions and persisted event bytes, rollback/retry, SQLite claim lock timing, commit/lease/validity fences, exact-100 and 101-unit reservation, accepted Queue/State writes, startup recovery, and admission handoff. Raw child result: Ran 27 tests in 10.687s; OK. The full adapter module was included.

Logs:
- C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\guarded-command-queue-lifecycle-decision-focused-20260924-r1.outer.log — 4,619 bytes, SHA-256 E12BA190EFEF097E7B97628637368F696A6C63C5C9F986159590306B1D4137F1.
- Matching .stdout.log — 0 bytes, SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.
- Matching .stderr.log — 132 bytes, SHA-256 0D8B338CCED7CC98E4187B950A82F6D78C4BB1A966685B6CC3D1F245B88F1F61.

### Broader guarded suite and stop condition

A fresh preflight at 2026-09-24T07:02:23.5573466Z reported 4,644,614,144 bytes available, the exact v4 guard hash, correct Queue cwd, mutex absent, zero competing processes, no log collision, and all four requested module files present. The guarded command ran git diff --check and then py -3.14 -B -m unittest over tests.test_minimal_clearance_verification_queue, tests.test_minimal_clearance_lifecycle_adapter, tests.test_direct_mask_state_profile12, and tests.test_minimal_clearance_composition_v2. It ran 122 tests in 71.995s and exited 1: FAILED (failures=1, errors=5). Guard telemetry: 121 samples, minimum free 4,049,977,344, peak working set 178,900,992, peak private 131,608,576; exit7=7, exit0=0, cleanup PASS, mutex released. The full failed output is retained in guarded-command-queue-lifecycle-decision-broad-20260924-r1.stderr.log (9,410 bytes, SHA-256 B3271D91F8DFB20E7BFE724B51E0FDFC354B4563FB59A0F7469EF38DB0B2BD6C); stdout is empty (SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855); outer log is 17,196 bytes, SHA-256 3E834F60405BED1BEA39C44A05A419B9FAC3568C91F9FF3351BC12D37E7A024F.

The Queue exact-retry test error was traced to the 64-byte test input, corrected to the documented 32-byte contract, and rerun alone under the same guard. Fresh preflight at 2026-09-24T07:07:28.2202537Z reported 4,606,468,096 bytes available, correct cwd, exact guard hash, mutex absent, zero competing processes, and no log collision. The targeted rerun reported Ran 1 test in 0.213s; OK; git diff --check and child exit were 0; guard cleanup passed, mutex released, minimum free 4,483,731,456, peak working set 115,601,408, and peak private 77,996,032. Logs: outer 2,370 bytes/SHA-256 D13E585B6F3B2A2E5F2320144E699EA005826A82DD722DE1CDB148C0A9FC9299; stdout empty/SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855; stderr 103 bytes/SHA-256 54BABD813570A327D0E40BC8B1A64903DE4483A65DEE61172BD3131F3F50B12D.

Five other broad-suite failures remain unrerun on the corrected tree. Three Profile12 tests calling _hold_batch_locked surfaced queue_integrity_failed from _revalidate_durable_state, whose broad exception handler hides the underlying independent-verifier exception. One test attempting to issue a batch whose validity had already expired received the Queue's validity_expired rejection. A Profile12 temporal-field negative changed a persisted event time, recomputed its chain, and expected timestamp_binding; verify_database returned without raising. This last independent-checker mismatch is trust-critical and the checker/test path is outside this assignment's write scope. Per the assignment STOP condition, no further tests or source/checker edits were made, and the four-module suite was not rerun after the test-fixture correction.

### Executable identity and claim boundary

The adapter fixes semantic_kernel/rust/target/x86_64-pc-windows-gnu/release/lifecycle.exe at 6,571,008 bytes and SHA-256 B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881; the actual file matches. Runtime mode is legacy-pinned-v2 and _LIFECYCLE_SOURCE_MANIFEST_SHA256 is None. Therefore the tests establish that Queue consumes the typed result returned by the exact byte-pinned executable in the existing transaction; they do not establish that the current Lifecycle.lean/LifecycleKernel.lean source produced those bytes. No current source-bound executable attestation, formal release, deployment, production, payment, PHI, or activation claim is made. The build script's newer source-manifest pins are not evidence that this existing executable was rebuilt. The prior LifecycleKernel compiler failure and its exact evidence remain recorded earlier in STATE.md.

The current increment added only this task/state evidence, a focused source-authority reconciliation in docs/LEAN_FORMAL_KERNEL.md, and the one test-input correction. Queue source remains 243,643 bytes/SHA-256 FE57DF433AA2BEDDFE31F1E189C97B674B7A73BA4E86D42C7BD3497E3CBA7140; adapter remains 41,598 bytes/SHA-256 C6D9EC2BDCA2E1A4FE9C78F164FB84DDFF93614658B67688F4BA40200D9404E9; corrected Queue test is 131,814 bytes/SHA-256 61E69061F43C305A160A91C28CB057C5C57C8EF21C3CF60F199D62287A7B655E. No Lean/Rust build was run.

The v4 mutex is released and the finite lane is handed directly to Driver with the broad failure and provenance gap open. Work remains synthetic, nonpayment, non-PHI, nonactivating, proofSuiteId=null, and production_usable=false. A post-documentation git diff --check was skipped (1) because the trust-critical STOP condition had already fired; no further test or build is authorized in this handoff.

## Direct follow-up — Profile12 broad-suite failure closure — 2026-09-24

This direct follow-up supersedes the preceding STOP only for the five recorded broad-suite symptoms and authorizes changes to `app/minimal_clearance_verification_queue.py`, `app/minimal_clearance_verification_queue_independent.py`, `tests/test_minimal_clearance_verification_queue.py`, one focused `tests/test_direct_mask_state_profile12.py`, `CURRENT_TASK.md`, and `STATE.md`. No Queue or independent-verifier source change was needed. The only implementation-path change in this follow-up is the focused Profile12 test file; all inherited dirty and untracked files remain present and no file was staged or committed. The edited `docs/LEAN_FORMAL_KERNEL.md` was not changed; its earlier STOP paragraph remains historical and this task/state entry records the superseding result.

### Diagnosis and smallest correction

The three `_hold_batch_locked` failures were test connection-fixture errors. The contained v4 diagnostic wrapped the independent verifier and exposed `IndependentQueueError('database_pragmas')` at `app/minimal_clearance_verification_queue_independent.py:1547`, before `_revalidate_durable_state` converted it to `QueueIntegrityError('queue_integrity_failed')` at `app/minimal_clearance_verification_queue.py:2662-2664`. In each failing active transaction, the fixture's raw `sqlite3.connect` handle reported `foreign_keys=0` and `max_page_count=4294967294`; the Queue contract established by `_connect()` is `foreign_keys=1` and `max_page_count=32768`. The test now uses the relevant store's `_connect()` for all four direct `_hold_batch_locked` fixture calls (the three failing paths and the later prelease-recode setup). The state-owner and verifier production paths were not weakened or altered.

The first expiry fixture issued a window already expired at the issue clock. It now issues with a 60,000 ms validity window, then advances the deterministic test clock exactly to expiry before submission. The adjacent queued/recovery fixtures also used 100 ms and 10 ms windows that could expire inside the transaction's monotonic commit fence; they now use a 60,000 ms setup window and advance the clock after successful setup. All still exercise post-issue expiry and retain the half-open validity boundary.

The event-field negative changed sequence 4 (`VERIFIER_STARTED`) from `clock.now + 1` to `clock.now - 1`. Source review shows `+1` is a valid time: this event is constrained to be at or after `VERIFICATION_STARTED` and before the 60,000 ms lease deadline (`_verify_temporal_bindings`, lines 1340-1343); the schema has no second persisted verifier-start timestamp against which a coherent in-range rewrite could be checked. The test's previous expected `timestamp_binding` was therefore unsupported. A coherent rehash to `clock.now - 1` is backward from the preceding event and is rejected by the existing monotonic event-time check (`_verify_temporal_bindings`, lines 1265-1267) with the expected `timestamp_binding`. No checker patch or valid-time rejection was added.

### Guarded evidence

The diagnostic and every test/check run used v4 guard SHA-256 `57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`, target start floor 3,500,000,000 bytes, and hard physical-free floor 2,190,433,321 bytes. The intentionally diagnostic three-test run exited 1 with three expected test errors so the wrapper could reveal the inner exception; guard exit self-tests were 7/0, minimum free bytes were 4,508,232,704, cleanup was PASS, and the mutex was released. Its complete raw files are retained: outer 3,413 bytes / SHA-256 `CD49F1597B5DBEC34FC2EBECF6417D1B76A20AB0BB15DBA0FE922F9C36129665`; stdout 0 bytes / `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`; stderr 11,302 bytes / SHA-256 `6B1F7D4DDEB33ABCD71E5EAC29317660AB0BDE380BB67BFECAEEBA02CF38BB5E`.

Two intermediate five-case guarded runs exposed narrow expiry-fixture races and are retained. The first ran 5 tests in 3.785s and errored when a 1 ms window expired before issue commit (stderr 1,838 bytes / SHA-256 `586F797B03FD04C192F1C53F29DD1E20189C4021C8E86E1B6C5B5ECDF3DF7499`; outer 6,154 bytes / `E3FA9A63F29FE74E987BA0A5A0F403E647801BE03A5380EB08BD48A24D6E4921`). The second ran 5 tests in 3.979s and errored when a 100 ms queued fixture expired before submit commit (stderr 1,611 bytes / SHA-256 `62B26CA8D8DF5174CA16633F9B108C48617F5E529C6DC9A822B6942E4834A445`; outer 4,474 bytes / `94D28A4CDE328FEB785DC157230EA1BDE4F0EBC0313DE4E3C07C47AD6CB0DDB5`). In both cases the guard cleaned up and released its mutex; both fixture causes were corrected and rerun.

The corrected focused command passed: `py -3.14 -B -m unittest` over the five affected `Profile12StateTests` methods (`test_hold_at_issue_burns_reservation_without_refund`, `test_receipt_flags_and_orphan_results_are_closed`, `test_temporal_deadlines_and_terminal_contract_are_exact`, `test_lifecycle_specific_expiry_contract_rejects_coherent_prelease_expiry_recode`, and `test_temporal_field_matrix_rejects_backward_malformed_and_out_of_u64_values`). Raw child output: `Ran 5 tests in 4.445s; OK`; no skips. Guard minimum free was 4,506,210,304 bytes across 10 samples, peak working set 80,740,352, peak private 51,757,056, cleanup PASS, and mutex RELEASED. Logs: outer 4,555 bytes / SHA-256 `06AA0CEDC74033E3ED4CC8AFAE926E2C76FE28F8DB129612B347CB7C38E2BF41`; stdout 0 bytes / SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`; stderr 108 bytes / SHA-256 `A4B7CD0A8B9453A85AEB4027EF43452BE56BA13A9836B3F06AAC7BAF87490AB4`.

The required single fresh four-module broad command then passed: `git diff --check && py -3.14 -B -m unittest tests.test_minimal_clearance_verification_queue tests.test_minimal_clearance_lifecycle_adapter tests.test_direct_mask_state_profile12 tests.test_minimal_clearance_composition_v2`. Raw child output: `Ran 122 tests in 73.223s; OK`; zero skips or failures. Host preflight at 2026-09-24T07:43:52.1542212Z reported 4,636,020,736 bytes free, exact guard identity, mutex absent, zero relevant competing processes, and all four modules present. The guard's physical preflight was 4,617,388,032; it recorded 124 live samples, minimum free 4,465,680,384, peak working set 93,687,808, peak private 79,740,928, exit self-tests 7/0, child exit 0, cleanup PASS, and mutex RELEASED. Post-run probe reported 4,565,135,360 bytes free, mutex object absent, and zero relevant processes. Logs: outer 18,557 bytes / SHA-256 `A975C9EA6F3DC4E2BB04C29A62318BEB2DFFA81B5260AFFC2F3C60EA77990DCB`; stdout 0 bytes / SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`; stderr 228 bytes / SHA-256 `74BC0F83C931B0E0EFC208B34011FEC51E81C979EC92B05D190371D338A16E2A`.

Additional execution issues are retained and classified: one initial guarded diagnostic invocation had a PowerShell argument-binding error on `-c` and launched no child (outer 1,047 bytes / SHA-256 `88A9223491149E2E2A81F45D3250D68F1889BF0B5A372019B58327F636AC3BF4`); the corrected invocation passed the full preflight. One post-run log-reader command had a PowerShell `catch` parse error and was corrected without changing evidence. The initial combined repository inspection ran one unguarded `git diff --check`; it emitted no output but its individual exit status was not captured. Every subsequent diff check and test run was guarded. An initial unquoted `git rev-parse HEAD^{tree}` inspection failed in PowerShell and was corrected with the quoted ref; final identity is HEAD `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55`, tree `40d8268880072f23b4c46fc83aee2c5084184083`.

### Final disposition

Final identities: Queue writer 243,643 bytes / SHA-256 `FE57DF433AA2BEDDFE31F1E189C97B674B7A73BA4E86D42C7BD3497E3CBA7140`; independent checker 145,820 bytes / `3101847DE2681A105A6E9521344B332649CF76BF33B0ED082C322C3708D662CF`; Queue test 131,814 bytes / `61E69061F43C305A160A91C28CB057C5C57C8EF21C3CF60F199D62287A7B655E`; focused Profile12 test 126,749 bytes / `F37E5A4FD3A1A631EED1959AB3DF20D8DC8906494D28EBCA983F0C1FE55DF767`. The only test/source hash change in this follow-up is the focused Profile12 test. No skip or out-of-scope edit remains. The earlier Lifecycle executable provenance gap remains: mode `legacy-pinned-v2`, manifest SHA unset, so no current source-to-binary, formal-release, production, payment, PHI, or activation claim is made. Status remains synthetic, `proofSuiteId=null`, `production_usable=false`, `NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`. The finite lane is returned to Driver; the final post-record `git diff --check` is performed under the same v4 guard and its raw result is reported in the task reply.

## Lifecycle source provenance follow-up — source edits complete; guarded lane pending — 2026-09-24

This later source-only follow-up is in the same checkout at detached HEAD
`b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55`, tree
`40d8268880072f23b4c46fc83aee2c5084184083`. It preserves the inherited working tree; nothing was
staged or committed. This follow-up changed only `semantic_kernel/rust/build.rs`,
`tests/test_minimal_clearance_lifecycle_adapter.py`, `tests/test_minimal_clearance_verification_queue.py`,
and this file, `STATE.md`, and `docs/LEAN_FORMAL_KERNEL.md`. It did not change the Queue writer,
independent checker, Lifecycle Rust entry point, Lean source, executable, or `.lake` outputs.

The Lean parser source already contains the five authorized comma-only corrections in
`lifecycleKernelReadConfig`, `lifecycleKernelReadIdentity`, `lifecycleKernelReadAccounting`,
`lifecycleKernelReadState`, and `lifecycleKernelReadEvent`. The current source is 23,464 bytes,
SHA-256 `5B6D0B4C7109946F8A26C2EDE19FC2B25447E373B50CF863BDCD04EC6488D8AC`. No field, decoding,
encoding, transition, theorem, or axiom meaning was changed in those corrections.

The build manifest source was corrected so Clang and LLD records use stable relative tool roles,
not keys containing host-specific canonical paths. The canonical path equality checks remain.
`build/linker` records `toolchain/bin/clang.exe`; `link-tool/ld.lld.exe` records the verified copied
LLD file identity. The configured link arguments still select LLD, including `-fuse-ld=lld` and
`--ld-path` to the copied file. This makes the manifest path names host-independent; it does not
attest the Cargo linker process or final executable.

The adapter tests now include the missing-final-newline protocol rejection and a mocked
source-bound success that checks the manifest report and response came from the same single
contained-runner result, with the fixed executable identity passed to the runner. The Queue retry
test adds a same-invocation manifest mismatch: it expects rejection before response decoding,
one runner call, a closed volatile handoff, unchanged `AWAITING_HANDOFF`/transition-count state,
the single existing reservation, then a successful fresh retry. These are source assertions only;
they have not been executed. No Queue writer change was made.

### Retained Lifecycle compiler output and attribution

The failed child stdout at
`../pq-wide-seed-native-20260913/build-filter-native/guarded-command-queue-lifecycle-kernel-20260922-r1.stdout.log`
is 1,631 bytes, SHA-256
`5A5D70EB1CCCD24BDFC4A8EDCF53AED2A5DAFC5BE2606EBA5C7A19F5AF9B8EC8`; its stderr is 20 bytes,
SHA-256 `C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F`. It records the Lake
compiler invocation and the five parser errors at lines 156:71, 188:79, 235:65, 303:83, and
418:77, followed by `Lean exited with code 1` and the failed `Admission.LifecycleKernel` target.

There are two later 87-byte success stdout files. The `...kernel-20260922-handoff-r1.stdout.log`
file has SHA-256 `15ED5C2210FD21445879CD8CDF8C31E0F213C32E22110F12A12E2565B35411D1` and timestamp
2026-09-23 02:25:12Z; it predates the current Lean source modification and is not evidence for that
source. The `...parser-repairs-20260923-r1.stdout.log` file has SHA-256
`7078317941FA38CCE142BA58A1EB9C33EAC07FACF124F47CA422E322A6C862BB`, timestamp
2026-09-23 06:58:37Z, and empty stderr (SHA-256
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`). Its raw stdout is:

```text
✔ [5/5] Built Admission.LifecycleKernel (32s)
Build completed successfully (5 jobs).
```

That success is temporally compatible with the current Lean source and the retained
`LifecycleKernel.olean` (920,528 bytes, SHA-256
`DAB9737758C18DAF1A96C372F138E63838E80DC557641CCF93ACF0A61B34DD47`). The existing STATE entry
reports child/outer exit 0, guard cleanup and resource telemetry for this Lake-only run. However,
the corresponding `build-filter-native` directory contains the child stdout and stderr files but
no per-run outer log for `parser-repairs-20260923-r1`; the raw retained files therefore do not
independently establish the command wrapper, guard identity/telemetry, or exact source identity for
that success. Preserve the existing telemetry as a recorded claim, not as independently
reconstructed evidence. A fresh guarded Lake build is still required before claiming a guarded
pass for current sources.

### Verification gate and disposition

No Lake build, Cargo build, compiler, test command, checker, executable run, or `git diff --check`
ran during this source-only follow-up: 0 runs of each. They remain gated on one direct finite-lane
handoff from Driver, fresh target-specific v4 preflight, exact guard SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`, and the 2,190,433,321-byte
hard physical-free floor. The documented 3,500,000,000-byte start floor applies to Python/SQLite
work and explicitly does not cover Lean/Rust compilation; Driver must supply the applicable
`-MinimumStartFreeBytes` for the Lake/Cargo target before those runs.

The final-link boundary remains open: `build.rs` emits a pre-link receipt, while Cargo invokes the
actual linker after `build.rs` exits; every final-link input and the produced `lifecycle.exe` are
not yet attested. Live-path replacement during Lean compilation/linking also remains unresolved.
Runtime mode remains `legacy-pinned-v2`, executable pin remains 6,571,008 bytes / SHA-256
`B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881`, and reviewed source-manifest
digest remains unset. Keep `source-bound-v1` closed. Status remains synthetic, nonactivating,
nonpayment, non-PHI, `proofSuiteId=null`, `production_usable=false`,
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

### Driver lane sequencing update — 2026-09-24

Driver replied that State still owns the sole v4 lane and Cleanup has the next direct release for its
queued focused code-deletion verification. This Lifecycle Lake/Cargo run follows Cleanup's safe
return. No build, test, or checker may run until Driver sends a direct handoff with fresh boundary
evidence. The Python/SQLite 3,500,000,000-byte start threshold does not apply to compiler/link
stages. Record the applicable Lake/Cargo target start floors from compiler evidence after the direct
handoff; preserve the hard 2,190,433,321-byte physical-free floor.
