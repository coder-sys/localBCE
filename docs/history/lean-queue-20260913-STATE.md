# Blind Ledger current state

Updated: 2026-09-24

## Queue claim verified-image reuse — guarded Python verification — 2026-09-24

At detached HEAD `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55` / tree
`40d8268880072f23b4c46fc83aee2c5084184083`, I preserved the existing dirty/untracked work and
added only the authorized Queue claim-path reuse plus this evidence record. On the accepted claim
path, the source now performs a complete independent Queue scan before expiry and a second complete
scan after expiry. The latter produces the frozen image used by the Lifecycle snapshot, removing
the former third and fourth full scans. Batch/member equality, transaction/connection bindings,
Composition metadata projection, and fail-closed stale-image handling were added; no fallback scan
can mask an active invalid binding. Existing non-claim `_revalidate_durable_state` calls are
unchanged.

The accepted-claim Queue case measured exactly two `_verify_connection` calls: the required scan
before expiry and one after expiry. The post-expiry image fed Lifecycle reconstruction inside the
same `BEGIN IMMEDIATE` claim transaction. The same-transaction adversarial test mutated
`queue_batches.updated_ms` after image capture; the binding failed before Lifecycle evaluation,
Queue rolled back, the queued batch, attempt/reservation, metadata, and transition count returned to
their pre-claim values, the lease table stayed empty, and an unmodified claim retry succeeded.

The direct Driver handoff's earlier host-only boundary was guard SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`; free physical memory was
`3656159232` bytes, mutex absent, relevant processes `0`, and all three snapshot commands exited
`0`. This was not a launch preflight and it was below the compiler start floor `4190433321` bytes.
No Lake/Cargo/compiler run occurred. The post-run free memory `3667693568` also remained below the
compiler floor by `522739753` bytes; provenance build and final-link attestation remain resource
stopped. Source-bound Lifecycle mode stays closed.

Lifecycle provenance source changes and the retained executable were not touched here. The
executable remains on its old pin and runtime mode remains legacy-pinned; no source-to-binary,
formal-release, production, payment, PHI, or activation claim is made. The only paths edited for this
stage are the Queue writer, Queue independent verifier, Queue tests, `CURRENT_TASK.md`, and
`STATE.md`; all inherited dirty/untracked paths remain present and unchanged. No files were staged
or committed.

### Fresh host preflight and v4 run

At `2026-09-24T12:34:55.7755618Z`, the host preflight confirmed Queue checkout root
`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\lean-queue-20260913`,
HEAD/tree `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55` /
`40d8268880072f23b4c46fc83aee2c5084184083`, v4 guard SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`, free physical memory
`3704889344`, target floor `3500000000`, hard floor `2190433321`, mutex `ABSENT`,
`relevant_processes=[]`, and `log_collisions=[]`. V4's own preflight reported
`free_bytes=3692937216`; its exit self-tests were `exit7=7` and `exit0=0`. The guarded command
exited `0`, cleanup was `PASS`, and the mutex was `RELEASED`. Its 21 live samples recorded minimum
free `3519152128`, peak working set `152530944`, and peak private bytes `100384768`; the hard
physical floor was not crossed. The corrected post-run snapshot at
`2026-09-24T12:36:46.5017067Z` recorded free physical memory `3667693568`, mutex `ABSENT`, and
`relevant_processes=[]`.

The guarded child ran `git diff --check`, this unittest command, then `git diff --check` again:

```text
py -3.14 -B -m unittest tests.test_minimal_clearance_lifecycle_adapter tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_lifecycle_sidecar_submit_claim_event_bytes_and_independent_verify tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_claim_rejects_transaction_mutation_after_verified_image_capture tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_lifecycle_sidecar_failures_rollback_and_allow_fresh_retry tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_claim_clock_waits_for_sqlite_write_transaction tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_claim_commit_fence_holds_batch_when_validity_expires tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_handoff_commit_fence_holds_batch_when_validity_expires tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_lease_expiry_at_verifier_start_fence_prevents_verifier_launch tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_completion_expiry_at_commit_fence_rolls_back_composition tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_exact_100_members_and_one_101_unit_attempt_record tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_accepted_batch_commits_queue_and_all_state_rows_once tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_startup_burns_a_live_session_and_never_resumes_it tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_versioned_admission_state_handoff_binds_identity_and_rejects_replay
```

Raw child stdout and stderr, verbatim:

```text
PRE_DIFF_CHECK_EXIT=0
UNITTEST_EXIT=0
POST_DIFF_CHECK_EXIT=0
.............................
----------------------------------------------------------------------
Ran 29 tests in 10.473s

OK
```

There were no warnings, skips, failures, or errors in this focused run. The 29 tests were the full
Lifecycle adapter module (17 test methods) and 12 selected Queue methods. The other 39 Queue module
test methods were not run in this focused packet. The optional focused DirectMask test (count `1`)
was not run because its source path was unchanged. The previously recorded four-module broad run
still has `1` failure and `5` errors; this focused run does not supersede it or resolve the
out-of-scope Profile12 temporal-binding issue.

Guard evidence in
`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native`:

- `guarded-command-queue-claim-image-reuse-20260924-r1.outer.log`: 4,621 bytes, SHA-256 `ADF87A4F8558E83B093979F6988464A12320BF5C9ADDE42767871E4C4BE16F55`.
- Matching `.stdout.log`: 64 bytes, SHA-256 `8FCC20409B8912700F030075717B7753DBBFFC9B9131000EBFFDABE49A9D0112`.
- Matching `.stderr.log`: 134 bytes, SHA-256 `DF434BB9E1E5839B6C7EB6E40167999B0FE9D6ED2463595F6D2C7A0A45C91467`.
- `host-preflight-queue-claim-image-reuse-20260924-r1.json`: 2,274 bytes, SHA-256 `BA56F4396B51BAA0FC3421F44099A2BAE85083C9B48BEB5409A70B727F13AEBB`.

Source identities after the Queue change: writer 246,308 bytes / SHA-256 `0516592EDA7CE7EA5CD56AA3DCEC9F139D17976C57204C3624C7AD8D462F5FDA`; independent verifier 155,098 bytes / SHA-256 `B7F7A2417792EBDC725E8E2BB0C57AB986528EBD9FA284755BEF09C241AECE4E`; Queue tests 138,034 bytes / SHA-256 `D5439509C10FACFA8A8ACFDDEEE3E8D3286B0B3E02DEF42D65A4BC2EA54BFF91`. Relative to the pre-stage hashes/sizes, source grew by 2,665, 9,278, and 4,247 bytes respectively (16,190 total); this was an addition, not a deletion cleanup.

Discovery diagnostics: one read-only guard lookup used `..\..\pq-wide-seed-native-20260913` and failed path resolution; corrected `..\pq-wide-seed-native-20260913` resolved the expected guard with the exact SHA-256 above, and no process launched from the failed lookup. The first post-run process inventory counted its own PowerShell probe, PID `13828`; the corrected caller/ancestor-excluding inventory returned `relevant_processes=[]`. The v4 lane is returned directly to Driver.

## Superseding Queue GNU native integration — 2026-09-19

The prior Profile12/native-adapter deferral entries remain historical evidence. Under the current
Driver packet, Queue has a guarded GNU-target Lean/Rust admission integration candidate. The
candidate is nonactivating and does not alter the protocol, schema, accounting contract, proof
selection, or production claim.

The guarded Queue release build used the pinned Rust 1.96.0 host compiler, the pinned
`x86_64-pc-windows-gnu` standard library, Lean 4.33.1, the pinned GNU Lean archive, and the
existing process/mutex/memory guard. It exited `0`; the final build telemetry was minimum free
physical memory `5,456,809,984` bytes, peak private bytes `158,109,696`, cleanup `PASS`, and
mutex `RELEASED`. The adapter is
`6,466,560` bytes with SHA-256
`5836e2c0043770e89c2deefed4d4347e5aa50a4a7cb1fa4438356e7578acd098`. The linked GNU archive is
`453,614` bytes with SHA-256
`a999bb472ac6f3e8fe6c6b047982c5a45bbd013c9131fa02af433d03f3a5099c`; the source binding is
`a7111258de3b6df87669b5348ac671e5789042203e60369e46f66f238613ad60`.

The guarded full `tests.test_lean_admission_integration` run reported exactly:

```text
LEAN_ADMISSION_INTEGRATION {"artifact_sha256": "a999bb472ac6f3e8fe6c6b047982c5a45bbd013c9131fa02af433d03f3a5099c", "input_bytes": 110, "kernel_calls": 5, "source_accounting": {"a_used": 1, "m_used": 100, "s_used": 4096, "u_used": 1, "v_used": 1}, "source_binding_sha256": "a7111258de3b6df87669b5348ac671e5789042203e60369e46f66f238613ad60", "source_status": "COMPLETED", "verifier_status": "STARTED"}
....
Ran 4 tests in 2.005s

OK
```

That test guard reported minimum free physical memory `5,287,428,096`, peak private bytes
`52,588,544`, cleanup `PASS`, and mutex `RELEASED`. The earlier two-test run first failed twice
with `LeanAdmissionError: lean_admission_adapter_binding` because Queue still pointed at
`target/release`; after the exact Cargo target-triple path correction, the same two tests passed.
The earlier verifier-binding diagnostics (`5df6e0e2...` from a nonrecursive scan and
`5b839414...` from the Queue helper's double-hash bug) are retained in the guarded logs and were
corrected fail-closed; they are not qualification evidence.

The original MSVC and CRT/rust-lld link failures remain preserved as prior evidence. No production
deployment, formal-verification qualification, independent audit, private proof-suite selection,
real PHI, payment movement, or activation follows. Flags remain
`proofSuiteId=null`, `production_usable=false`, `activation=false`,
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

## Lifecycle source-to-runtime provenance closure — source-only supplement — 2026-09-23

This supplement began at detached HEAD/tree
`b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55` /
`40d8268880072f23b4c46fc83aee2c5084184083`. The existing 7 tracked modifications and 9 untracked
paths were preserved. The exact authorized paths changed in this supplement are
`semantic_kernel/rust/build.rs`, `semantic_kernel/rust/src/bin/lifecycle.rs`,
`app/minimal_clearance_lifecycle_adapter.py`,
`tests/test_minimal_clearance_lifecycle_adapter.py`, `CURRENT_TASK.md`, `STATE.md`, and
`docs/LEAN_FORMAL_KERNEL.md`. No Queue/Composition module, operational pin, retained executable,
`.lake` file, raw log, archive, or other path was edited. Nothing was staged or committed.

The trust chain is pinned Lean source/tool/`.olean` inputs -> generated Lean objects and lifecycle
archive -> Cargo/Rust and explicit static link inputs/settings -> final `lifecycle.exe` -> the
contained runner's exact executable pin -> Python attestation and response checks -> the active
Queue transaction -> successful submit/claim SQL writes. The Queue call boundary remains
`_check_lifecycle_transition_locked`; submit calls it before handoff attachment, batch update, event,
and commit, while claim calls it before token/lease writes, event, and commit. Adapter failure
continues through the existing rollback path. No Queue schema 13/Profile 12, wire, policy/directive,
exact-100, lease, reservation, clock, handoff, or commit behavior changed.

`build.rs` now emits source-manifest v2 records for pinned sources and tools, the Rust compiler and
GNU target standard-library binding, the complete `.olean` tree, the four generated Lifecycle /
Kernel / Model / Sha3 object identities, the static Lean/support/native archives explicitly passed
to the Lifecycle link, effective host/target/profile/optimization/debug/linker/Rust flags, target
configuration values, captured build environment identities, and the normalized ordered Lifecycle
link-argument list. It checks `TARGET`, `HOST`, the release profile and optimization/debug values,
the configured linker and encoded flags; it rejects the listed wrapper, compiler-flag, profile, and
toolchain environment overrides. Non-identical or malformed manifest records fail the build. The
pre-link receipt still records the lifecycle archive and objects and is not represented as a final
executable receipt.

The Rust entry point validates the embedded v2 manifest's bounded length, header, sorted canonical
record shape, numeric fields, hashes, and SHA-256 against the compile-time digest before reading the
request. On success it writes exactly one versioned provenance line to stderr with the manifest
digest and the running executable size/SHA-256; stdout remains the existing lifecycle response.
Python parses an exact bounded one-line form. `_LIFECYCLE_RUNTIME_MODE` is source-owned and is not a
caller parameter: current `legacy-pinned-v2` accepts only the existing exact old executable pin and
empty stderr, preserving the prior synthetic call path without current-source or production credit.
`source-bound-v1` requires the same invocation's valid attestation plus a reviewed manifest digest
and the exact executable pin. Its errors do not fall back to legacy. The source-manifest pin remains
unset and the legacy pin was not changed: the old executable remains 6,571,008 bytes / SHA-256
`B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881`.

The focused adapter test source adds three cases: canonical/malformed/duplicate/mismatched
provenance rejection; legacy exact-pin/empty-stderr mode and source-mode no-fallback; and a
source-bound rejection before response decoding with the active SQLite connection unchanged. These
tests were not executed in this supplement. A malformed or stale source-bound report raises before
response decode; at the protected Queue caller, failure rolls back any transaction-local writes and
the existing retry/volatile-handoff rules remain in force. A partial build can leave the old fixed
executable untouched; only the explicitly lower legacy path can use that exact old pin. A new or
partially replaced executable fails the contained runner's old pin, and source-bound mode has no
legacy fallback.

Build-time replacement-and-restore remains unresolved. Lean tools, `.olean` inputs, and linked
archives are still read from live paths; a pre/post hash cannot prove which bytes Lake or the linker
consumed during a concurrent replacement. Cargo also compiles/links after `build.rs` exits, and the
script does not attest every Cargo-produced final-link object or every profile setting supplied by
an unobservable command-line config. These residuals keep source-bound qualification closed; neither
the source manifest nor the retained legacy pin establishes reproducible source-to-current-binary
provenance. No formal release, deployed-link, production, activation, or `proofSuiteId` claim follows.

The prior authorized Lake-only run remains separate evidence: child/outer exit `0`; captured guard
stdout 87 bytes / SHA-256
`7078317941fa38cce142ba58a1eb9c33eac07facf124f47ca422e322a6c862bb`; stderr 0 bytes / SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`; cleanup PASS; mutex
RELEASED; minimum free bytes `3,063,128,064`; peak private bytes `973,877,248`. It generated eight
files under the already-untracked `semantic_kernel/lean/.lake` directory. The new
`Admission.LifecycleKernel.olean` is 920,528 bytes / SHA-256
`dab9737758c18daf1a96c372f138e63838e80dc557641ccf93acf0a61b34dd47`. This supplement did not
touch those files or rerun Lake, Cargo, a compiler, tests, the executable, or a guard.

## Native boundary provenance and finish-operation correction — 2026-09-19

The preceding native integration record is superseded by this correction record. The C boundary
now calls the generated Lean startup contract's `lean_initialize_runtime_module()` before the
Admission module initializer and rejects null/non-OK initialization results. `Admission/Main.c`
remains excluded from the Queue link; its startup contract was reconciled from the generated
source rather than imported as a second startup object.

Queue `build.rs` now invokes the pinned Lean Lake build for `Admission.Library`, compiles
`native_boundary.c` with the pinned clang/ GNU target recipe (`--sysroot` pinned Lean toolchain,
`-nostdinc`, clang include path, `-O3`, `-DNDEBUG`, `-ffp-contract=off`, section flags), verifies
the resulting object SHA-256 `6caf55657966fc957e32c569699031ea4f1f476e1ff6b9db69ccd5aea53a7635`,
and links that object directly with the three verified Admission/Sha3 objects. The source binding
now includes `native_boundary.c`: source SHA-256
`a625d17c8daa735debe816e05dc2c6cd68a9800579c8eb0fe7d3b039c6baf541`, combined binding
`b75f946a01ebe6c0e4faeda635b60b74f6cc69b0062f6e7700b1f09f94c7d4ac`.

The corrected guarded Cargo build exited `0`; minimum free physical memory was `4,159,188,992`
bytes, peak private bytes `165,277,696`, cleanup `PASS`, and mutex `RELEASED`. Final adapter
identity is size `6,470,656`, SHA-256
`430109ff8954df9832cf89533f9aa67c69a64bb8187ad71eed4eb44528c273f9`; the pinned archive receipt
is SHA-256 `f3a6d1685c7e2c14f09c92c65d0ad09dfcc7a911e0cc69c3b122b24c6b568e2d`.

The guarded compiled integration suite reported exactly:

```text
LEAN_ADMISSION_INTEGRATION {"artifact_sha256": "f3a6d1685c7e2c14f09c92c65d0ad09dfcc7a911e0cc69c3b122b24c6b568e2d", "input_bytes": 110, "kernel_calls": 5, "source_accounting": {"a_used": 1, "m_used": 100, "s_used": 4096, "u_used": 1, "v_used": 1}, "source_binding_sha256": "b75f946a01ebe6c0e4faeda635b60b74f6cc69b0062f6e7700b1f09f94c7d4ac", "source_status": "COMPLETED", "verifier_status": "STARTED"}
.....
Ran 5 tests in 4.822s

OK
```

The new test exercises the actual compiled `source_finish_unknown`,
`verifier_finish_accepted`, and `verifier_finish_unknown` operations and verifies the resulting
accounting with no refund. The two existing Python timeout/cleanup tests also passed:
`Ran 2 tests in 1.047s`, `OK`. Queue's governing admission timeout remains `3.0` seconds;
Rust's elapsed-time check is post-call accounting, while the existing Python owned-process
stream runner enforces termination/cleanup. No unsupported 2-second contract was introduced.

The Queue integration still does not claim that every Queue transition is Lean-owned:
`AWAITING_HANDOFF -> QUEUED` and `QUEUED -> LEASED` remain Python transitions. The initial wrong
include-root compile failure, five-member archive append, source-binding/adapter-identity failures,
and the earlier MSVC/CRT link failures remain preserved raw evidence and are not relabeled as
passes. The stage remains nonactivating and unqualified with
`proofSuiteId=null`, `production_usable=false`, `activation=false`,
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

## Active Profile12 Queue/State stage — corrected, unverified/in progress

This exclusive child implements the owner-delegated Profile12 Queue/schema/independent/runtime
stage from starting HEAD `98a3d9ea7f156653633996170c17236db804eed7` / tree
`3d8d555397b86384d57fe7db8f530134026eb037`. The implementation is a clean schema break at v12:
it persists one nonzero 96-byte state-issued public coin, derives the 64-byte proof context from
the exact 405-byte state binding in both producer and independent checker, and atomically inserts
the batch, 100 members, one 101-unit lifetime reservation, attempt row, counter update, and
`BATCH_ISSUED` event before returning. Claim emits `VERIFICATION_STARTED` without a second charge;
source epoch, coin/context, reservation, identity, and lifecycle bindings are checked before lease
mutation and by the independent checker. Reservations are never refunded; expiry, restart,
ambiguous commit, malformed handoff, and consumed/partial handoff paths burn them.

Measured bounded evidence in this child: `py -3.14 -B -m py_compile` exit `0`; Queue tests `30
passed`; Runtime tests `17 passed, 2 skipped`; and Profile12 focused tests `29 passed`. The two
skips are exactly the native Profile12 source-auth adapter/source-appliance identity tests,
explicitly deferred by the active grant; the native adapter, verifier process, resource limits,
C/crypto checkouts, and protected production paths were not modified. The prior concurrency
diagnostic had 3/20 iterations where both contenders returned `runtime_scope`, with an empty
marker/Windows WriteFile error chain and a remaining runtime-lock path. The corrected owner now
serializes same-process contenders, closes the Windows initialization-sharing gap, preserves
identity-bound replacement/cleanup, and retains actual per-contender error-chain fields in the
Runtime regression test. The deterministic partial-initialization test and final barrier stress
passed; the stress result was `100/100` single-owner startups with one
`runtime_already_owned` loser and no cleanup race. The focused matrix covers 15 serializer/config
mutations, five producer/independent context bindings, six missing/orphan association families
across verify/read/export/restore, 16 issue/claim counter sequence cases, actual zero-then-
nonzero sampler draws, genuine Profile11 WAL/SHM preservation, exact-u64 clock rejection,
lifecycle, receipt/error closure, timestamps, KAT, reservation, crash/reopen, and hold checks.
The added v12 WAL drift test confirms the immutable image is only a preliminary version gate and
the authoritative live read follows WAL state. No broad suite, adapter test, old Profile11 proof
probe, or large solver was run.

The implementation remains nonactivating and unqualified: `proofSuiteId=null`,
`production_usable=false`, `activation=false`, `NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`. No native
adapter acceptance, production proof backend, Lean deployment, real PHI, payment movement,
custody, or formal-verification claim follows from these synthetic local tests.

## Current cleanup disposition

This bounded cleanup started from exact clean commit
`5fe29fad1f44df961ea20f8e3397c8d2e02783d0` (tree
`c963c8d489b5295ab0a4679953161a84a624567b`). Cleanup implementation commit
`960352a8829d426b98053306fba6a2f323c7c896` (tree
`0dfdaf7eaeef48d9673750f9eafc3827c287aeb8`) removes 14 unused implementation/test files:
the five-file, 780-line SPHINCS/public-input island and nine generic, 1,434-line Native-v3 files.
It also removes seven dead CMake targets and the island's sole `pqcrypto -> cffi -> pycparser`
dependency closure. The exact wheel identities removed from the two platform artifact graphs total
53,269,389 bytes. Production now has zero Python packages and development has six.

Deep reachability implementation commit `92cb4943afa8665f99c780b6edb04e0b0cac436c` (tree
`6c0a812a1e6ff17d64527baf1a2e58c206568d94`) removes the orphan
`schemas/bl_pq512_vector_v1.schema.json`, `test_data/bl_pq512_foundation_vectors.json`, and
`test_data/bl_pq512_s09_foundation_vectors.json`: 27,251 bytes and 646 lines. Their exact
filenames, schema identity, and SHA-256/SHA3 vector identities have zero current consumers. Git
history shows that their foundation and S09 reference tests were deleted when those retired
BL-PQ512 lanes were consolidated; the current rejection authority still forbids restarting that
architecture.

The executable release classifier now reports 195 tracked files: 167 current source, 2 retained
compatibility, 3 source-only, and 23 excluded generated/private, with 169 selected by default.
The retained compatibility closure is only `app/batch/__init__.py` and
`app/batch/poseidon.py`. The operation-scoped source-assertion family, minimal-clearance Native
family, their shared fixture, Queue/Profile 11 runtime, historical raw evidence, and reproduction
records remain. Current trust-boundary code validates the minimal-clearance implementation
attestation, so deleting that family would require a broader authority change and was not done.

The pre-cleanup deleted-path history scan found 1,335 historical deletions. The corrected current
scan found 29 reference occurrences covering 24 distinct deleted paths; these remain intentional
governance negative-list/test references. The protected Queue V6 metadata comment remains unchanged
and does not authorize deleting active Queue or Native-v3 code. No operations bytes, archive,
activation state, or external checkout is changed.

## Prior candidate and release closure

The final bounded source correction is commit
`365536cc344889e4d111e7dc996cdd17c8f76d8f` (tree
`ba2b86b9a3447bfdf81f3e9300c423fed20a65e9`) in this separate child. Its reviewed integration
baseline was commit `9c0586f4303a504dee48730c4525c93277511e94` (tree
`ecd85c04af106cfdde19c07c495f570cce6db399`). The earlier immutable
`0607a275bb5158dd4b4c70dfcd95d0967c80b839` input (tree
`4571c47be35dd782045aa4f9ed35a9fb31413a2c`) and the separate v2 evidence checkout are historical
inputs outside this correction. The executable release policy at the reviewed integration
baseline is:

| Lane | Count | Selection |
| --- | ---: | --- |
| Current source | 170 | selected |
| Retained compatibility | 2 | selected only by explicit closure |
| Source-only | 3 | unselected |
| Excluded generated/private | 23 | unselected |
| Unknown/retired/legacy | 0 | fail-closed if introduced |
| Tracked total | 198 | — |
| Default selection | 172 | 170 current + 2 retained |
| Unselected total | 26 | — |

The retained closure is exactly `app/batch/__init__.py` and `app/batch/poseidon.py`. Prefix
membership is only a classification hint. Deleted
compatibility entries and the obsolete legacy registry are not release inputs. Source-only privacy
fixtures, generated evidence, private build metadata, and Profile 11 host files remain excluded.
The executable classifier reports these counts for the reviewed integration baseline. The exact
source-only paths are `profile11_complete_path.py`, `profile11_complete_path_manifest.json`, and
`profile11_source_boundary.py`. The release-policy changes are removal of the orphan
classifications for the deleted external-source test and the deleted Native throughput test;
unknown and retired path rejection remains unchanged. The previously recorded 218-tracked/
191-selected table belongs to historical source/policy/docs evidence and is not current.

## Verified evidence

- From clean deep-cleanup authority commit `8e82072854c2b194d2ad834325bc6cee059c5b05`
  (tree `93d82b9d0e193628da18d5a12d84444650911caf`), the final whole suite completed
  `3 failed, 552 passed, 4 skipped, 557 subtests passed in 586.47s`. The failures are exactly the
  three documented Native profile tests and each stops at
  `ledger:provenance-source-mismatch`. The four skips are unavailable symlink creation for the
  locked wheel, verifier executable, Mirror recovery image, and Mirror operational directory;
  focused replay reported `2 passed, 4 skipped` and no additional skip.
- The deep repository pass parsed the full Python tree, mapped static imports and file/data
  references, ran Vulture and Pyflakes, measured full branch coverage, checked every Native/CMake
  source registration, searched deleted-path history, and compared tracked blob/content hashes.
  It found no additional unprotected dead implementation cluster and no duplicate tracked file.
  Full branch coverage completed with `3 failed, 552 passed, 4 skipped, 557 subtests` and 70%
  aggregate source coverage (25,126 statements, 6,428 missed, 9,446 branches, 2,716 partial); the
  only failures were the same three `ledger:provenance-source-mismatch` tests. Native Phase 0
  `cargo check --locked --offline --all-targets`, the five-directive KAT, and all 14 negative cases
  passed; `cargo clippy` was unavailable because the installed stable toolchain has no
  `cargo-clippy.exe`. The five focused release/security/privacy/documentation tests passed
  `50 passed, 36 subtests` after the data removal.
- At clean deep-reachability commit `92cb4943afa8665f99c780b6edb04e0b0cac436c`, the disposable
  release-manifest gate selected 169 payload files and emitted a 25,272-byte manifest with SHA-256
  `5f1aacfac6efb5a7c64649a34de95417eb0ba676f88a1fb4440e26d170bfc7e5`. The disposable
  source stage was removed and no archive publication target was touched.
- Cleanup commit `960352a8829d426b98053306fba6a2f323c7c896` deletes 2,214 source/test
  lines in 14 files and reconciles CMake, dependency declarations, four platform/profile locks,
  the canonical dual-hash artifact manifest, Python SBOM, release closure, and focused tests. The
  dependency/release suite passed `27 passed, 1 skipped, 31 subtests`; the skip is the existing
  unavailable symlink capability. Static scans found no surviving runtime reference or deleted
  generic CMake target, while all required minimal-clearance sources remain registered.
- From clean record commit `8ffe6ff02e7608665085e8cb481f42c03b215ecb`, the full suite completed
  `3 failed, 552 passed, 4 skipped, 557 subtests passed in 569.60s`. The three failures are exactly
  `test_compiled_parameter_report_rejects_exactly_seven_categories`,
  `test_manifest_is_explicit_and_nonactivating`, and
  `test_symbolic_ledger_rejects_zero_or_complete_placeholders`; each failed at the unchanged
  `ledger:provenance-source-mismatch` gate. No additional failure occurred.
- Disposable release-manifest verification selected 172 payload files and emitted a 25,699-byte
  manifest with SHA-256
  `21c58b3951db69dde91a2fa0a5e4691588db4aef014fb9cc616d1b648a66e356`.
  The disposable stage and archive were removed; no publication target was touched.
- Cleanup commit `d9220535a68d652dd491fdcaa184b04068014016` is the rebased eight-file reduction from
  immutable input `52b441c138b9577122303aaf1d1769fca2d82e4b`. It removes five unreachable legacy
  money-chain modules and two obsolete money tests; the surviving proof-primitives test retains
  top-level and nested float rejection, and repository caller search found no remaining references.
- The direct-state candidate owns schema version 4. A schema-3 database or backup is rejected before
  schema creation with `database_schema_version_mismatch`, while source and backup bytes remain
  identical and recovery creates no output. V4 retry, restart, backup/restore, identity,
  concurrency, rollback, and post-commit-indeterminate paths remain synthetic evidence.
- Mirror/Provider Trust Graph and continuity are synthetic, local/current-Windows, observation-only
  evidence. They have no authenticated real source, production persistence, PHI, payment, or
  activation claim. The operational export bridge selects independently reconstructed Core
  `SOURCE_OBSERVATION`, not the Provider Trust Graph path.
- The reviewed Mirror cleanup is the exact source commit `46a4c965464ea2cd72a3205d82652ddbf8ae51f6`
  (local integration `57e5f1f938ff7346880c6fd6a01138cecd575712`): the unused external adapters and
  their fixture test are deleted, source admission retains the active NC source path, and the
  state-source contract tests cover the remaining boundary. The exact deleted module/test paths
  have no remaining file or import references. The separate source-only cleanup is
  `6df4578aa5c98ca23ba38b563b74a075a504c483` (local `47eb2309e08d17913bb2fc99ffb33e02dc9bffaa`).
- The release-policy orphan entry for the deleted external-source test was removed from
  `tools/release_manifest_gate.py`; the stale orphan entry for the deleted Native throughput test
  was removed in the same bounded reconciliation. No other classification or unknown-path guard
  was changed.
- The verifier workspace identity fix masks only volatile Windows `st_file_attributes` bits while
  retaining device/inode/link-count, directory type, reparse rejection, and entry-name checks.
  The full verifier-process suite passed `41 passed, 1 skipped, 65 subtests`; the exact skip is
  unavailable Windows symlink creation. Profile 11 source binding was reconciled to the reviewed
  runtime and verifier-process Git blobs; its focused closure passed `78 passed, 1 skipped, 129
  subtests`, with the skip the locked-dependency symlink capability check.
- Final executable verification after the correction: core/semantic suite `63 passed`; release,
  privacy, documentation, plaintext-continuity, and source-boundary suite `92 passed, 108
  subtests`; Mirror suite `170 passed, 2 skipped, 189 subtests`. The semantic CLI emitted
  `SEMANTIC_ASSURANCE_GATE=PASS property_count=13 declaration_count=14 artifact_bytes=5719040
  artifact_sha256=5e0505f83680a93fcbfe4a0e31e2fafbe0bc0a95e43854ba0e7b2e783b79e540`, with
  `PROOF_BODY_CHECK=PASS`, `INDEPENDENT_LEAN_CHECKER=PASS`, and
  `SOURCE_CLOSURE_SCAN=PASS files_scanned=12 forbidden_token_matches=0`, against external
  candidate HEAD `0f594f6333fab720127f94b1259688331befd004` and tree
  `b6eb1164f944625231cffae9ee282daadb41c389`.
- The clean disposable release readback selected 186 payload files and produced a 27,814-byte
  manifest (`ddb0ec42252f18421a51cdcb51c2136e58f7150556647fe56f1714e016f9ec61`) and a 187-entry,
  3,297,499-byte archive (`9328ddb5fdb2b8279e05d2d51f4812651ede52d2ea0b0014cd79053c345ae298`).
  Independent extracted size/hash readback passed; no publication target was touched.
- The approved source-only deletion `d50f0f28134e40fc5a6a04028ef401f801d6596e`, integrated locally
  as `c230aa518f95397f2dac0af8592aae93796c2b53`, removes exactly the two obsolete Native
  throughput/runner wrappers and their obsolete test. Replacement Queue/runtime, source-auth,
  and Profile 11 files remain present.
- Recorded sealed-baseline gates include release-policy `21 passed, 34 subtests passed`,
  active-core/security/qualification `19 passed`, proof primitives `24 passed`, and operations
  authority `ops_authority=verified`. The qualification inspection reported
  `proofSuiteId=null`, `production_usable=false`, `qualification_state=NOT_QUALIFIED`,
  `activation_state=INACTIVE`, and `selection_state=UNSELECTED`.
- On clean disposable staging of the integrated source/policy commit
  `c29d39ff796bb7056b42095dec5bc10a4a959342`, the release-manifest gate selected 193 paths and
  emitted manifest-v2 SHA-256 `2d54c478a4c5eb45736118e6ccfba726a9ad24922f085d141c012d4948979729`
  (28,959 bytes). The create-only builder completed canonical ZIP/CRC readback with 194 entries,
  3,305,354 archive bytes, payload 3,234,361 bytes, and archive SHA-256
  `ba3533641b07907255d238492906739dad1aa8e085b0d6c50a43f75cd77c47cf`; no publication target was
  refreshed.
  The earlier internal note naming `cc953b2fbb226fdcbe03a55fcb2367c26fde9ba0` for this receipt
  was a documentation error; the raw receipt is bound to `c29d39ff796bb7056b42095dec5bc10a4a959342`.
- On clean disposable staging of the final source/policy/docs commit
  `5989bb47d72b08a8e6345130e7c3f38b9757a33e` (tree
  `e3bcb94ca692fcb771a17cd6c71c67afe23bab8f`), the release-manifest gate selected 191 paths and
  emitted manifest-v2 SHA-256 `86b0c01631156ef088302ea34633f3b6c9b31e5cde1fd5a2426fbda14eba8832`
  (28,575 bytes). The create-only builder completed canonical ZIP/CRC readback with 192 entries,
  3,284,299 archive bytes, payload 3,214,292 bytes, and archive SHA-256
  `40a15ccf73c52397c586a0a34758d6bc4606c05c48534e5ca6a5957f9ea160a4`; no publication target was
  refreshed. Independent extracted readback matched every manifest hash and size, found all three
  deleted paths absent, and found the release helper present. The extracted positive helper exited
  0 with a 530-byte archive receipt; the negative helper exited 0 with
  `EXTRACTED_NEGATIVE_REJECTION=pass reason=release payload failed the structural privacy gate`.

## Unresolved trust-critical blocker

The Native-v3 trust-boundary profile remains blocked by a source-provenance mismatch. The three
known failing tests are `test_compiled_parameter_report_rejects_exactly_seven_categories`,
`test_manifest_is_explicit_and_nonactivating`, and
`test_symbolic_ledger_rejects_zero_or_complete_placeholders`; each returns
`ledger:provenance-source-mismatch`. `experiments/native_v3_trust_boundary/profile.py` pins
`UPSTREAM_MANIFEST_SHA256=A677B8A6BEA7DCA87E4370E8FA07FDFD17F345276B581629BE230022B8C0BB5D`,
while the committed `experiments/longfellow_v09_native_v3/upstream_manifest.json` is 2633 bytes
with SHA-256 `466A704DD9CE3F812FB19A73EABC44EB922113922C805B7AD17DEEB29D52A1DD`. This is an
unresolved source identity, not a predicate to weaken; no native-v3 source fix or repin was made.

## Security and nonclaims

The strict chronology is `rule_effective < event < observation < decision`; one decision and exactly
two ordered accesses (`[0,1]`, READ then WRITE) are admitted with matching `decision_id`. Reads use
observation time and the state write uses decision time. Authoritative completeness is required
before absence can affect policy; unknown, stale, malformed, replayed, reordered, duplicated,
conflicting, or cleanup-failed input fails closed.

No production proof backend is selected. DP24 remains an ideal-vector/oracle record with six numeric
inputs `UNKNOWN`; no numeric epsilon/security-bit claim follows. `proofSuiteId=null`,
`production_usable=false`, and `activation=false` remain fixed. No Lean implementation or deployed
formal-verification claim exists. Real PHI, live credentials, payment movement, HSM/FIPS custody,
official receiver, and Ethereum settlement remain outside the evidence.

Operations bytes were not edited. `tools.ops_authority verify` remains the byte-identity gate, and
the independent `docs/DESIGN_IDEOLOGY.md` contract remains intact.

## Archive and next dependency

No source archive was refreshed or published. Any disposable archive is only for internal
builder/readback verification and is not a retained publication artifact. `STATE.md` and
`CURRENT_TASK.md` remain workspace-only and excluded from source archives. A future refresh must
start from a clean reviewed manifest and independently verify builder receipt, canonical ZIP/CRC
readback, three retained targets, equal hashes, and zero publication artifacts. After this
cleanup, the next authorized semantic dependency is the Lean workstream;
a model, differential test, or generated vector cannot replace it.

## Active E2E complete-path evidence — 2026-09-12

This is the current driver-authorized integration phase. The accepted clean State/runtime
correction is '6aa9e634948b6b3a40d1c3c4f07299f8fd5493db' / tree
'a8c6c2f1845686b80e9e079c807ad50c3f1deb92'; the accepted adapter source is
'55b1d71fc5f6fa1860225e590a6dbff5af3db2e1'; and the accepted Queue source caller is
'4f7d8d9475de5e4042af0f85c00a955259da737f'. The complete-path child is
'pq-direct-mask-complete-path-20260912', currently rooted at the State candidate ancestor
'6129625a88e94d005f5dfe5fd4f6fb8e05a19793' / tree
'997e4a8e5543139ea9b81e70574eba5a44d53094d' with those handoffs source-selected by exact
path.

The complete path is source-only and nonactivating. Its single valid fresh run must use the
driver-pinned 275968-byte source executable, 240128-byte independent verifier, and frozen
public-key header, with exact empty non-reparse workspaces under 'build-complete-path'.
The source capsule and verifier IPC are volatile memory-only values. The source and verifier
processes stay inside the accepted contained-process primitive; the outer guard retains the
child exit 7/0 preflight, 1-GiB physical reserve, '<5000000000' process-tree cap, active
process limit 1, shared mutex, and cleanup markers.

The valid evidence contract is exactly one State-issued batch of 100 operations, one
independent verifier acceptance, one atomic State/composition transaction covering 100 rows,
100 opaque idempotency keys, 100 synthetic ACKs, independent State/composition readback after
reopen, and zero duplicate rows or receiver side effects. Synthetic State/receiver objects
are test authorities only; they do not claim official authority, production usability,
qualification, Lean linkage, PHI, payment, custody, or activation. Fixed flags remain
'proofSuiteId=null', 'production_usable=false', 'activation=false',
'NOT_QUALIFIED'/'INACTIVE'/'UNSELECTED'.

## Complete-path review correction evidence — 2026-09-12

The advertised E2E commit '00e864e2c9c1f9b550f667e3c5bf4759982f26b3' / tree
'77b6e97880b39aa4419762ba6ee19c522f5f6e19' was not amended. The new correction uses the
runtime's checked context ownership through the acquired lifetime, preserves primary plus
release failures, retains failed directories while ownership is uncertain, and wipes local
capsule/handoff state before submission transfer. Four focused non-native fault tests passed
with zero skips.

Native attempts are now counted from append-only wrapper records. The prior
'verifier_calls' field was an assumed fallback and is withdrawn. The final corrected run
measured source_calls=1, verifier_calls=1, and state_port_calls=1. Its exact post-close
run-file inventory was ['state.sqlite']; source and verifier workspaces were empty. This
supports only the isolated inventory and memory-only data-path claims, not whole-host
persistence absence or OS zeroization.

Final guarded CTest exited 0: 9/9 integration tests passed in 19.355s, stderr bytes 0.
The outer guard recorded child exit 7/0, reserve 1073741824, minimum free bytes 2276630528,
peak working set 83345408, peak private bytes 53145600, cleanup PASS, and released
'Local\BlindLedgerDirectMaskBuild20260907'. The valid path recorded exactly 100 operations,
one batch, one independent verifier acceptance, 100 transactions, 100 ACKs, 100 unique
idempotency keys, zero duplicates, 100 receiver side effects, successful reopen with no work,
source/verifier stdout bytes 539013/0, stderr bytes 0/0, and fixed nonactivation flags.
Unchanged State/adapter/malformed-native suites were intentionally not rerun; their accepted
raw handoff evidence remains authoritative.

## Active native arithmetic performance phase — 2026-09-12

The new performance child is rooted at accepted E2E commit
'51158c2db5c4d1b82c88875ea23707a6e7fa1d89' / tree
'bc779ad6ae3f0b6bf0b9e82020bae7b1f4c8f306'. It is a source-selected, nonactivating native
optimization phase. The accepted baseline is one synthetic 100-operation complete path at
source 10.546812s, independent verifier 6.671242s, total 17.870595s. The concrete
optimization hypothesis is the pinned vendor 255-bit 'bf256_mul'/'bf256_mul_inplace' loop;
the field, reduction, protocol, source/signature, transcript, verifier, State, outbox/ACK,
and containment contracts are unchanged.

Only exact committed native imports and child-local field/kernel/circuit/build wiring are in
scope. Vendor, source/proof/codec, State/runtime/composition/Queue, filtered/Profile13,
operations, custody, deployment, payment, PHI, Lean, and formal paths remain protected.
The existing guarded runner, exit 7/0 probes, 1073741824-byte reserve, '<5000000000'
process-tree cap, 4500000000 native cap, active process limit 1, mutex, cleanup telemetry,
and memory-only proof boundary remain mandatory. No production, qualification, p95, or
security claim follows from this phase.

## Native arithmetic performance verified evidence — 2026-09-12

The performance child remains detached at HEAD `51158c2db5c4d1b82c88875ea23707a6e7fa1d89`
 / tree `bc779ad6ae3f0b6bf0b9e82020bae7b1f4c8f306`, with authorized worktree changes not yet
committed. The native change is child-local `direct_mask_bf256_accel.{c,h}` plus CMake
wiring and complete-path identity plumbing. It implements fixed 4x4 PCLMUL GF(2^256)
multiplication with fixed-word reduction, public CPU dispatch, alias-safe in-place operation,
and a renamed, independently linked pinned-vendor portable reference. Native C/H SHA-256:
`5FC9AA99647C7F38060545F05AC45C2394A1A442C8061C5E520D1F77C50C3625` /
`00E1D9C1E078BD35BCCA95AE76865590ED1B78969DAFBD89D85EBB7C09FF21E2`.

The exact import comparison reported `IMPORT_CHECKED=74`, `CMAKE_WIRING_DIFFS=9`,
`UNAUTHORIZED_IMPORT_ERRORS=0`, `MISSING_EXPECTED_FILES=0`; only the two acceleration
files are extra. The source/proof/signature/codec/fixture implementations remain byte-identical
to the committed input identities. `dumpbin /symbols` on the accelerated library reported
both public `bf256_mul`/`bf256_mul_inplace` and external
`direct_mask_bf256_mul_portable`/`direct_mask_bf256_mul_inplace_portable`, with static
`direct_mask_bf256_mul_pclmul`; dumpbin exit was `0`.

Native and link evidence is current: the arithmetic probe reports
`BF256_BACKEND=pclmul PCLMUL_AVAILABLE=1` and
`BF256_OUT_OF_PLACE_MATCH=PASS BF256_IN_PLACE_MATCH=PASS`; circuit, kernel, VOLE, and
fixture builds/probes pass. The VOLE raw evidence includes
`VOLE_IDENTITY rows=1792 mismatches=0 delta_zero=0`, `SOURCE_PROVE_STATUS status=0
prover_calls=1`, `E2E_VERIFY_STATUS status=0`, `SOURCE_BOUND_COUNTS ... counts_equal=1`,
`DIRECT_MASK_PROBE_COUNTS passed=53 failed=0`, and `DIRECT_MASK_PROBE_STATUS=PASS`.
Integrated Release CTest reports `100% tests passed, 0 tests failed out of 8`, total
`34.02 sec`, exit `0`; the four native probe counts are `CHECK_COUNT=114/96/58/86
FAILED=0`, and all real-symbol/closure gates pass. Fixture identity reports
`FIXTURE_IMPORTED_LIBRARY_IDENTITY=PASS count=8`; adapter unit tests report `Ran 14 tests
in 4.367s` and `OK`.

Final child binaries are source `276480` bytes / SHA-256
`176B237D8277A1CF09EECE1DC58DBB9B012C9B6700C6FB8C04FEF46011FDD626`, verifier `240640`
bytes / SHA-256 `37EB37C8A86C010D3C69400E26BA5DCFA9E2A75C407F48DAEC1D03586D364AEF`, and
`dm_faest_public.lib` `333298` bytes / SHA-256
`B664A72471120AAA1D236236AE1BF7C5BB46B3989471771712566BEBD39069ED`. The old accepted
default pins remain `275968/D3A36CFAADBB1B6A3455DA44C4DC0E941C00906EC7E281199876F851C503FCA8`
and `240128/38FB45E017D08AC11098D8837C78D02143B86753AA4F085174073C64353AC835`.

The final guarded candidate `COMPLETE_PATH_EVIDENCE` is one fresh synthetic 100-operation
run: `issued_batch_count=1`, `independent_verified_batch_count=1`, `source_calls=1`,
`verifier_calls=1`, `state_port_calls=1`, `transaction_count=100`,
`outbox_acknowledged_count=100`, `unique_idempotency_keys=100`,
`receiver_duplicate_dispatches=0`, `receiver_side_effects=100`,
`reopened_without_work=true`, `run_artifact_inventory=["state.sqlite"]`, empty source and
verifier workspaces, and `proof_suite_id=null`, `production_usable=false`,
`activation=false`. Source/verifier/total measured `5267.863/2884.734/8851.049 ms`; the
paired baseline measured `10637.985/6845.545/18141.746 ms`, an observed single-sample
reduction of `50.48%/57.86%/51.21%`, not p95 or qualification evidence. Candidate guard
telemetry was preflight free `3154444288`, reserve `1073741824`, minimum free `3049099264`,
peak working set `80388096`, peak private `54861824`, child exit `7/0`, cleanup `PASS`, and
released mutex. Baseline minimum free was `3463213056`; it also passed child exit/cleanup.

Intermediate failures and skips are explicitly accounted for: the original long-path build
hit MSVC `C1083`/`FTK1011` and was moved to the validated `Q:` path; one kernel configure
used literal `$vendor`/`$oracle` and was rerun quoted; three initially unavailable
EXCLUDE_FROM_ALL integrated probes were explicitly built; and one no-`-C Release` CTest
attempt showed all eight `Not Run` (8 failed-to-run tests) with `Missing "-C <config>"`, after which the exact
Release command passed all eight. The existing VOLE probe reports
`REMOVED_SYNTHETIC_CHECKS count=6 reason=obsolete_local_polynomial_and_hash_path_removed
replacement=accepted_direct_mask_kernel_and_algebra_probes`. These are not unresolved
gates. Build warnings are pinned-vendor `C4141`, `C4146`, and `C4244`; no new acceleration
error remains. No State/runtime/composition/Queue, vendor, product, custody, payment, PHI,
deployment, Lean, formal, filtered/Profile13, activation, or production status changed.

## Native performance source review and remaining gates — corrective closure — 2026-09-12

The preceding native-performance entries are retained historical evidence. They describe the
earlier detached `51158c2db5c4d1b82c88875ea23707a6e7fa1d89` / `bc779ad6ae3f0b6bf0b9e82020bae7b1f4c8f306`
state and incorrectly describe the later `e42d3dc8ccf7891aebad8576402950cedac9ce07` correction
as uncommitted. The actual correction began at clean committed HEAD
`e42d3dc8ccf7891aebad8576402950cedac9ce07`, tree
`544ac79a7964a5d6cad032bdb38a64aa07aa7107`, parent
`cd8d3517f40ba75e7871db2d3ded1fa10daf5abe`. Before the new immutable commit, exactly these
seven tracked paths were modified: the kernel probe/CMake, fixture CMake/identity script,
child-local acceleration C seam, source-boundary executable pin, and the actual adapter
`app/minimal_clearance_source_auth_verifier_adapter.py`. The generated `build-performance/`
tree is retained untracked evidence. No vendor/input/protected implementation changed.

### Arithmetic correspondence

The existing `direct_mask_kernel_full_field` probe now checks the accelerated public
`bf256_mul`/`bf256_mul_inplace` against the independently linked pinned portable `fields.c`
reference under its CMake-only symbol rename. It covers all 65,536 ordered polynomial basis
pairs and 289 ordered pairs from 17 vectors: zero, one, all ones, each all-one limb, bit 63/64,
127/128, 191/192, 255, three dense crossing patterns, and a final dense limb-boundary vector.
Each pair checks public out-of-place, a forced portable dispatch seam, destination-as-lhs,
destination-as-rhs, public in-place lhs/rhs, public self-alias/self-in-place, and forced portable
in-place. The seam is compile-guarded by `DIRECT_MASK_BF256_TEST_SEAM`, and current production
symbol readback found zero test-seam symbols.

The complete raw transcript is
`build-performance/kernel-candidate/ctest-verbose-20260912-after-callsite.log` and reports:

```text
BF256_ARITHMETIC_BACKEND=pclmul PCLMUL_AVAILABLE=1 FORCED_PORTABLE_SEAM=compiled
BF256_ARITHMETIC_BASIS_PAIRS=65536 BOUNDARY_VECTORS=17 BOUNDARY_PAIRS=289 CHECKS=592425 MISMATCHES=0
BF256_ARITHMETIC_STATUS=PASS
FIELD_IDENTITY delta_case=0 prover=0 verifier=0 rows=172232 nonzero_leading=0 mismatches=0
DIRECT_MASK_KERNEL status=PASS skips=0 fixture_rng=deterministic cpu_seconds=23.055
1/1 Test #1: direct_mask_kernel_full_field ....   Passed
100% tests passed, 0 tests failed out of 1
KERNEL_CTEST_AFTER_CALLSITE_EXIT=0
```

Current acceleration source/header SHA-256 values are
`EF831E68E2589F68E9D99753D13758DADFE0C8F78432D9E2DCF90FD7FB8ACDDC` and
`00E1D9C1E078BD35BCCA95AE76865590ED1B78969DAFBD89D85EBB7C09FF21E2`.

### Candidate library identity and link closure

The existing fixture target validates the exact candidate root
`build-performance/q`, preserves the baseline `FIXTURE_IMPORTED_LIBRARY_IDENTITY` check, and
checks all eight candidate Release libraries by exact size and SHA-256 before the candidate
source executable target links. The successful raw log is
`build-performance/fixture-candidate/build-candidate-identity-20260912-after-arg.log`; its
decisive lines include `FIXTURE_IMPORTED_LIBRARY_IDENTITY=PASS count=8`, eight candidate
identity records, `FIXTURE_CANDIDATE_LIBRARY_IDENTITY=PASS root=.../build-performance/q count=8`,
build exit `0`, warning lines `0`, and error lines `0`. Generated candidate/source-main link
inputs are retained in
`build-performance/fixture-candidate/candidate-release-link-inputs-20260912.log` and
`build-performance/q/pipeline-source-cli-release-link-inputs-20260912.log`.

The eight current candidate library identities, in script order, are:

```text
0 C:/.../build-performance/q/Release/dm_pipeline_source.lib 3432 01809151898F2E7C9E814A0885D25EA3AF092FA412DAB7ECA0DE1C3DA44BFA94
1 C:/.../build-performance/q/Release/dm_pipeline_codec.lib 8486 C5CD2229B8A92C704E1F290114D09FAC18011C01C50B5D771055E32E20A62755
2 C:/.../build-performance/q/dm_source_proof_build/Release/dm_source_proof.lib 18486 3AF9D80DA4EE4C26D2CD464D4488A0CBCC87819971A86CD48A7B7D9D85C167B2
3 C:/.../build-performance/q/dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_source_auth.lib 18232 09735205900E2B2A1F19C02155113D1F60F171869ED537BBF0F58EC425443E6D
4 C:/.../build-performance/q/dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_wire_codec.lib 270926 89AC129A25A84870066114EDF61B978D274474BF95FD64AA6890B2691FF4EBE9
5 C:/.../build-performance/q/dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/mldsa_source_auth_wrapper.lib 141094 5DD4B6DB42FBDF78F7C0090E975ECC834A74D2E42C5F810E6C5E743C4B2228DE
6 C:/.../build-performance/q/dm_source_proof_build/Release/dm_native_fixture_source_proof.lib 33998 13A79E7AA7D44D2EA3F09D37E60D2E601954E1F9B6F8A5BDBBC19C34A3E56CFC
7 C:/.../build-performance/q/dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_faest_public.lib 333298 B7DBCBE97A19C9C1B5D77AE2A8E0D595A6EE6D98669F13856D81BB2CB8E1E551
```

The controlled negative logs at `build-performance/identity-negatives-20260912/` record three
expected exit-1 rejections: exact-root mismatch, nonexistent candidate root, and a wrong first
library with actual `8486/C5CD2229...` versus expected `3432/018091518...`. The current
`dumpbin /symbols` log is
`build-performance/q/dumpbin-faest-public-symbols-20260912.log`; it reports public
`bf256_mul`/`bf256_mul_inplace`, external `direct_mask_bf256_mul_portable`/
`direct_mask_bf256_mul_inplace_portable`, static `direct_mask_bf256_mul_pclmul`, exit `0`, and
`PRODUCTION_TEST_SEAM_SYMBOL_LINES=0`.

### Corrected child binaries and guarded path

The current child source appliance is size `276480`, SHA-256
`3BC225CE230433BC14DF94FEBAC47C713D94759505158BBA8FCE84B7E22C3285`; the current child
verifier is size `240640`, SHA-256
`FF7E69D004BF21C5E3F7C2A43F4EDD45F73BBF3E2E812AC9A6E657416F86DA93`. The actual adapter unit
suite after the pin correction reports `Ran 14 tests in 4.656s`, `OK`, exit `0`; raw log:
`build-performance/complete-path-candidate/adapter-unit-correction-20260912.log`.

The first corrected candidate run is intentionally retained as a failure: its raw CTest output
reports `complete_path_native_invocation_count`, `source_calls=1`, `verifier_calls=1`,
`state_port_calls=0`, `source_measurement_count=1`, `verifier_measurement_count=0`; the database
ended `HELD` with `verifier_transport`. The direct file hash then showed the one-nibble mismatch
between the adapter's `...004BB21C5...` pin and actual `...004BF21C5...`, which was corrected
within the allowed adapter identity plumbing. The failed raw logs remain at
`build-performance/complete-path-candidate/guarded-candidate-correction-20260912.log` and its
matching stdout/stderr files.

The required one fresh corrected guarded candidate path passed. Outer raw log:
`build-performance/complete-path-candidate/guarded-candidate-correction-2-20260912.log`;
CTest stdout/stderr:
`build-performance/complete-path-candidate/guarded-ctest-candidate-correction-2-20260912.stdout.log`
and `.stderr.log`, with stdout `5679` bytes and stderr `0` bytes. Exact raw CTest result:

```text
Ran 9 tests in 8.660s
OK
1/1 Test #2: direct_mask_complete_path_integration ...   Passed    9.30 sec
100% tests passed, 0 tests failed out of 1
Total Test time (real) =   9.31 sec
```

The raw `COMPLETE_PATH_EVIDENCE` line records one issued/verified batch, 100 operations, one
independent verifier acceptance, source/verifier/state-port calls `1/1/1`, 100 transactions,
100 ACKs, 100 unique idempotency keys, zero duplicate dispatches, 100 receiver side effects,
successful reopen with no work, exact inventory `["state.sqlite"]`, empty source/verifier
workspaces, and `proof_suite_id=null`, `production_usable=false`, `activation=false`.
Measured stages are source `3817.523 ms`, verifier `2711.830 ms`, total `7134.644 ms`.
Guard telemetry is preflight free `3948408832`, reserve `1073741824`, minimum free `3815194624`,
peak working set `81043456`, peak private `55885824`, child exits `7/0`, cleanup `PASS`, and
released `Local\\BlindLedgerDirectMaskBuild20260907`. The old accepted baseline sample was not
rerun because it is unchanged; this is one corrected candidate sample, not p95 or qualification.

### Failures, warnings, skips, and claim boundary

The physical-path q rebuild cache failure is retained at
`build-performance/q/rebuild-candidate-libraries-20260912.log` with
`Q_CANDIDATE_REBUILD_EXIT=-2`; the restored mapped-path rebuild is retained at
`rebuild-candidate-libraries-20260912-after-subst.log` with exit `0`, 48 warning-code lines,
and zero error-code lines. The first fixture target's missing `PMB_BUILD_DIR` failure is retained
at `build-performance/fixture-candidate/build-candidate-identity-20260912.log` with exit `1`;
the corrected target passed. A failed diagnostic `subst Q:` listing printed `Invalid parameter - Q:`;
`Test-Path` verified the mapping and the subsequent build passed, so that command is not treated
as successful evidence.

The corrected q and kernel build logs each contain exactly 48 pinned-vendor `warning C4141`
lines for duplicate `inline`; neither contains C4146 or C4244, and the candidate fixture build
contains zero warning/error lines. The old one-vector probe source/output was deleted after its
terminal-only run and is unavailable; it was not reconstructed. Earlier terminal-only circuit/
VOLE evidence and old warning totals/conversion wording remain unknown. No final gate is skipped.
This child remains synthetic, nonactivating, and unqualified: `proofSuiteId=null`,
`production_usable=false`, `activation=false`, `NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

## Immutable correction commit closure — 2026-09-12

The source/gate/identity correction is committed as
`800030a4a6b4899e38799934efaaefb5832a6bf6`, tree
`afbe96235f4c5d711ca0d3e689502b5e28c86b17`, parent
`e42d3dc8ccf7891aebad8576402950cedac9ce07`. Post-commit verification reported exact matching
HEAD/tree/parent, detached HEAD with no tracked modifications, and clean `git diff --check`;
the only remaining status item is the intentionally preserved untracked `build-performance/`
evidence tree. The bounded corrective phase is complete and the evidence is handed directly to
the Driver. Claims remain synthetic, nonactivating, and unqualified.

## Native arithmetic fallback correction and bounded optimization decision — 2026-09-12

The open fallback obligation was corrected from the exact reviewed state
`f73378a3bf33f5356887ba1e46b758a544392507` / tree
`3418585dc5f5f6091b37db90cd50291a4db69ff6` (parent `800030a4a6b4899e38799934efaaefb5832a6bf6`,
actual parent tree `afbe96235f4c5d711ca0d3e689502b5e28c86b17`). The forced capability is a
compile-only CMake configuration of the existing kernel probe. It calls the public
`bf256_mul`/`bf256_mul_inplace` APIs and reports the backend selected by the public dispatcher;
the normal and forced builds are not direct calls to a test wrapper.

Exact arithmetic gates:

```text
BF256_ARITHMETIC_MODE=normal_dispatch
BF256_ARITHMETIC_BACKEND=pclmul PCLMUL_AVAILABLE=1
BF256_ARITHMETIC_BASIS_PAIRS=65536 BOUNDARY_VECTORS=17 BOUNDARY_PAIRS=289 CHECKS=460775 MISMATCHES=0
BF256_ARITHMETIC_STATUS=PASS
DIRECT_MASK_KERNEL status=PASS skips=0 fixture_rng=deterministic cpu_seconds=22.326
KERNEL_FINAL_CURRENT_CTEST_EXIT=0

BF256_ARITHMETIC_MODE=forced_capability_false
BF256_ARITHMETIC_BACKEND=portable PCLMUL_AVAILABLE=0
BF256_ARITHMETIC_BASIS_PAIRS=65536 BOUNDARY_VECTORS=17 BOUNDARY_PAIRS=289 CHECKS=460775 MISMATCHES=0
BF256_ARITHMETIC_STATUS=PASS
DIRECT_MASK_KERNEL_ARITHMETIC_ONLY status=PASS
KERNEL_PORTABLE_FINAL_CURRENT_CTEST_EXIT=0
```

The initial forced public path was retained as a failure because the pinned portable
implementation overwrote an aliased RHS: `case=public_dst_rhs_alias`, expected basis products
were nonzero, actual values were zero, and the final count was `CHECKS=460775 MISMATCHES=131325`.
The production dispatch now copies both public inputs before calling the unchanged pinned
reference. The failed raw transcript is
`build-performance/kernel-portable/ctest-verbose-20260912.log`; its size/SHA are
`53244937/D29F1460601F01B1EC5A5CF3D542567EFFF5A3AE5D7B3B91CA5BF5F6938ED253`.

The authorized Karatsuba candidate used nine 64-bit carry-less products and preserved the
field/reduction/constant-time/alias/dispatch/reference invariants. Its corrected arithmetic,
forced arithmetic, candidate library identity, and guarded path all passed, but the one
fresh guarded sample regressed against the one baseline sample:

```text
BASELINE source_ms=3126.333 verifier_ms=2656.820 total_ms=6355.661
KARATSUBA source_ms=3505.107 verifier_ms=2696.914 total_ms=6771.051
TOTAL_REGRESSION_PERCENT=6.535748
SOURCE_REGRESSION_PERCENT=12.115600
VERIFIER_REGRESSION_PERCENT=1.509097
```

The candidate was therefore removed and the original 4x4 PCLMUL implementation retained. The
first incorrect cross-term run is preserved at
`build-performance/kernel-candidate/ctest-verbose-20260912-karatsuba.log`,
`75923051/FFF5D13BAEFDB7FA1C89F57FB7ED09E05CDB9CAFFB97858076E7DD6FCB1C947F`. The baseline
copy manifest is preserved at `build-performance/baseline-karatsuba-20260912/`.

Final retained identity/gate evidence:

- native C/H SHA-256:
  `08923E5EB209FFBFB89CC489D2C21770769F0AB45F31984BBC075DDDDCF52399` /
  `00E1D9C1E078BD35BCCA95AE76865590ED1B78969DAFBD89D85EBB7C09FF21E2`;
- source appliance `276480/25254DCBEB4FAB9A20911C874D7F633BD9953E804FE999F3AFD1C4BFAC649069`;
- verifier `241152/59F5CFF5C0C0B4979705BFE3FC69329FCCB2062A73748BC72F7E6A39760CB756`;
- q library 8 `dm_faest_public.lib`: `333932/F023C33E752DE95DC9D04332212D47333792EEF2424377E1B6E047E9F9B76593`;
- fixture identity: exact child root, all eight candidate libraries, exit `0`, warning/error
  lines `0` in the final incremental build;
- q rebuild: exit `0`, temporary mapping removal exit `0`, 48 `warning C4141` lines, zero
  C4146/C4244 lines;
- adapter identity: `Ran 14 tests in 4.407s`, `OK`, exit `0`;
- production symbol readback:
  `DUMPBIN_FINAL_CURRENT_EXIT=0`, `DUMPBIN_FINAL_CURRENT_SYMBOL_LINES=3293`,
  `DUMPBIN_FINAL_CURRENT_TEST_ONLY_MATCHES=0`, public/portable/static matches `27/7/6`.

Final retained complete-path raw evidence is
`build-performance/complete-path-candidate/guarded-ctest-retained-current-20260912.stdout.log`
and the matching outer log. The exact JSON line reports:

```text
acknowledged_operation_count=100
independent_event_count=100
independent_operation_count=100
independent_outbox_count=100
independent_transaction_count=100
independent_verified_batch_count=1
issued_batch_count=1
operation_count=100
outbox_acknowledged_count=100
queue_verify_state_ms=2883.041
receiver_duplicate_dispatches=0
receiver_side_effects=100
reopened_without_work=true
run_artifact_inventory=["state.sqlite"]
source_call_ms=3428.429
source_calls=1
source_measurement.elapsed_ms=3426.666
source_measurement.exit_code=0
source_measurement.cleanup_complete=true
source_measurement.cap_enforced=true
source_measurement.active_process_limit=1
source_measurement.child_process_count=2
source_measurement.process_tree_complete=true
source_measurement.measurement_complete=true
source_measurement.pagefile_growth_evidence=unavailable
state_issue_ms=12.484
state_port_calls=1
state_sequence=100
total_path_ms=6770.956
transaction_count=100
unconfirmed_operation_count=0
unique_idempotency_keys=100
verifier_calls=1
verifier_measurement.elapsed_ms=2695.773
verifier_measurement.exit_code=0
verifier_measurement.cleanup_complete=true
verifier_measurement.cap_enforced=true
verifier_measurement.active_process_limit=1
verifier_measurement.child_process_count=2
verifier_measurement.process_tree_complete=true
verifier_measurement.measurement_complete=true
verifier_measurement.pagefile_growth_evidence=unavailable
source_workspace_empty=true
verifier_workspace_empty=true
proof_suite_id=null
production_usable=false
activation=false
```

The raw CTest result is `Ran 9 tests in 8.219s`, `100% tests passed, 0 tests failed out of 1`,
total `8.84 sec`, stderr bytes `0`, exit `0`. Outer guard telemetry is preflight free
`3608154112`, reserve `1073741824`, minimum free `3477954560`, peak working set `80916480`,
peak private `54906880`, child exits `7/0`, cleanup `PASS`, mutex released, and outer exit `0`.
No test was silently skipped; the raw stdout/stderr/outer sizes and hashes are
`5680/0/3411`, `12C7E45F0ADE5BC85982084E3AE00C4C58DCF278761895DD035FEA918C1344E6` /
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` /
`19413D75AB2C37A7E9C468DB0BF3123F5CE3CACBA7E749699330BF7AF8C065C4`.

All prior q-cache, fixture-argument, stale-pin, identity-negative, warning, and unavailable
old-probe failures remain retained in their historical records. No supported speedup, p95,
qualification, production-security, activation, or Profile13 claim follows. The current
status is synthetic, nonactivating, and unqualified (`proof_suite_id=null`,
`production_usable=false`, `activation=false`, `NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`).
Remaining action is immutable commit verification and direct Driver handoff.

## Immutable bounded native closure — 2026-09-12

The first immutable phase commit is
`4dd3ea2ece80b43e29befe63c644e3b6b46eea61`, tree
`3061d6b77e60bb28f92ea4667bdbe72fcd7c2e50`, parent
`f73378a3bf33f5356887ba1e46b758a544392507`. It contains the six authorized implementation/
identity paths and the three append-only records. Exact post-commit verification reported
matching HEAD/tree/parent, detached HEAD, no tracked modifications, and clean diff-check; the
only remaining item is the intentionally preserved untracked `build-performance/` evidence
tree. The final docs-only closure commit and direct Driver handoff remain.

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

### Source-admission and verifier-launch closure — 2026-09-13

This append-only record supersedes the older Profile12-in-progress wording for the current
source-admission child. It started from immutable HEAD/tree
`9971e7a70937ff652d4008efaf021bcb7b119e53` / `c4ee02e15b8ec7ffe029f8056586ea11f3d037c4`.
Only the authorized queue, independent checker, runtime plumbing, source caller, complete-path
orchestration, focused tests, and current records are changed. The native binaries remain
untracked preserved inputs: source 275968 bytes SHA-256
`E07865D9CE6C2644142D3EA61030BD308D5BBD09FE861C630CC5EEBE1F3FE5D9` and verifier 240640 bytes
SHA-256 `F35F6AF28EC2D269831CFB6BDD1C2414D439FFEC2B26C73CC39495720D9B9E5D`.

Queue/independent schema v13 now carries a single durable public source-admission row per batch,
exact request/configuration/executable bindings, A/S_upper/M_upper/E_U and V accounting, source
AUTHORIZATION/STARTED/COMPLETED/UNKNOWN transitions, and verifier STARTED/COMPLETED/UNKNOWN
transitions. Issue atomically burns the one U issuance and the 101-unit proof reservation before
returning the batch; source admission burns A/S_upper/M_upper only after durable batch validation;
verifier V is charged in the committed lease-fenced transaction immediately before execution.
Consumed volatile authority, rollback/postcommit handling, restart recovery, handoff gating, and
independent reconstruction all fail closed without reproof or refund. No raw proof, private source
payload, key, provider identity, or secret material is persisted.

Exact successful gates were:

- `py -3.14 -B -m py_compile` over all changed implementation/test files: exit `0`, no output.
- Queue plus runtime: `Ran 49 tests in 13.666s`, `OK`.
- Source boundary plus Profile12 State: `Ran 40 tests in 17.618s`, `OK`.
- Source-auth verifier adapter: `Ran 14 tests in 4.620s`, `OK`.
- New source postcommit/ambiguous/recovery matrix: `Ran 3 tests in 0.721s`, `OK`.
- Shared schema/identity output was exactly:
  `QUEUE_SHARED_COLUMNS_MATCH True`; `QUEUE_SHARED_SQL_MATCH True`;
  `COMPOSITION_TABLES_MATCH True`; `COMPOSITION_SQL_KEYS_MATCH True`;
  `SCHEMA_MATCH True`; `GENESIS_HEAD_MATCH True`;
  `CONFIG_DIGEST_DOMAIN_AVAILABLE True 64`.

The single authorized native guarded complete-path run remains raw evidence only for the state at
that run: `Ran 9 tests in 20.572s`, `OK`; source/verifier/State-port calls `1/1/1`; one issued
and independently verified batch; 100 operations, transactions, ACKs, and unique keys; zero
duplicate dispatches; source/verifier stderr `0/0`; `run_artifact_inventory=["state.sqlite"]`;
`source_workspace_empty=true`; `verifier_workspace_empty=true`; `proof_files_persisted=false`;
`proof_suite_id=null`; `production_usable=false`; `activation=false`. It was deliberately not
rerun after the non-native closure edits, and no native arithmetic or filtered integration was
replayed.

A diagnostic protected-composition command ran 33 tests in 7.338s and failed 18 times with the
same raw assertion `AssertionError: Tuples differ: ('HELD', 0) != ('VERIFIED', 100)`. The
unchanged fixture accesses `batch.proof_statement`, which is absent in the immutable baseline
Queue API; the composition implementation and test were not changed here. The 14 adapter tests
in that combined command passed independently and are recorded above. Exploratory schema checks
that referenced unavailable private names or omitted QueueConfig constructor arguments changed no
files and were discarded as non-evidence. This is an explicit pre-existing/inapplicable warning,
not a silently skipped gate.

Documentation governance was run after the current-task marker correction:
`py -3.14 -m unittest tests.test_documentation_governance` reported `Ran 11 tests in 9.754s`,
`FAILED (errors=2)`. Both errors list the same six pre-existing unregistered Markdown paths:
`tools/direct_mask_authenticated_proof/README.md`, `tools/direct_mask_fixture/README.md`,
`tools/direct_mask_pipeline/README.md`, `tools/direct_mask_source_auth/README.md`,
`tools/direct_mask_source_proof/README.md`, and `tools/direct_mask_wire/README.md`. The marker
errors were fixed in the current record; protected release-boundary registrations remain
unchanged and this warning is explicit.

The stage remains synthetic and nonactivating, with
`proofSuiteId=null`, `production_usable=false`, `activation=false`,
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`. Final immutable commit/tree/parent and clean tracked
status verification remain to be recorded after the implementation commit; only untracked
`build-performance/` evidence is expected to remain.

### Immutable implementation commit — 2026-09-13

The source-admission implementation is committed as
`6c65b6601af17d3f2a88f12eaf171dc174b83f69`, tree
`fa23ad45dc2bce7ea4039291e4daf40bd66979c1`, parent
`9971e7a70937ff652d4008efaf021bcb7b119e53`, subject
`Enforce durable source admission and launch accounting`. The commit has exactly 13 authorized
tracked files. Verification matched the commit HEAD/tree/parent, reported empty staged and
unstaged diffs and clean `git diff --check`, and left only the intentionally untracked
`build-performance/` native evidence tree. This record-only closure is the final permitted
mutation; implementation files remain immutable.

### Durable admission correction closure — 2026-09-13

This append-only closure records the authorized correction from Docs HEAD
758345491bffa14df305c994c30d50f5a7d15680, tree
392b5fc6b24a2b1228fd6fff6d87b725a5d89f45. The implementation commit is
9e86d8ff75f00db6e52554e8494f99cb009b3033, tree
a8dc5c2b8ccc29e2586cb968d522e500d30a27f3, parent
758345491bffa14df305c994c30d50f5a7d15680, subject Close source and verifier launch races.
It changes exactly the seven tracked paths recorded in CURRENT_TASK.md.

The three reviewed boundaries are closed. SourceAdmission rejects unknown or mismatched
profile/size/SHA-256 identity before source rows, SOURCE_AUTHORIZED events, or A/S/M burns;
the accepted pin is (275968,
D3A36CFAADBB1B6A3455DA44C4DC0E941C00906EC7E281199876F851C503FCA8) and the assigned
child-performance binary is (275968,
E07865D9CE6C2644142D3EA61030BD308D5BBD09FE861C630CC5EEBE1F3FE5D9). Fresh terminal
VERIFIED/REJECTED completion requires verifier STARTED; HELD prelaunch/postlaunch semantics
remain UNRESERVED/UNKNOWN; independent reconstruction requires exactly
VERIFIER_STARTED/VERIFIER_COMPLETED and COMPLETED. Source authorization consumption is
serialized, and the concurrent test proves one native invocation and one winner. Direct
fixtures reserve verifier work; the only composition edit is a narrow current-API fixture
correction, with no composition implementation change.

Focused non-native gates were actual passes:
  py -3.14 -B -m py_compile ... -> exit 0
  queue plus runtime: Ran 50 tests in 15.055s, OK
  state plus source boundary: Ran 43 tests in 18.695s, OK
  composition plus adapter: Ran 33 tests in 17.684s, OK
  standalone queue: Ran 31 tests in 8.220s, OK
The initial state rerun (36 tests, 7 failures), first shared-store no-verifier attempt
(QueueBackpressureError: queue_capacity), first null script-directory guard attempt, and
first unquoted Git metadata probe were corrected or discarded as no-op diagnostics; their
raw conditions and reasons are recorded in CURRENT_TASK.md.

The assigned binaries were not rebuilt: source size 275968 SHA-256
E07865D9CE6C2644142D3EA61030BD308D5BBD09FE861C630CC5EEBE1F3FE5D9; verifier size 240640
SHA-256 F35F6AF28EC2D269831CFB6DD1C2414D439FFEC2B26C73CC39495720D9B9E5D. The one fresh
guarded synthetic CTest path used the existing mutex/resource/exit/cleanup gates and passed:
outer PHYSICAL_PREFLIGHT free_bytes=2853015552 reserve_bytes=1073741824, exit7=7, exit0=0,
CTest exit=0, samples=13, min_free_bytes=2770128896, cleanup PASS, mutex RELEASED. The
child reported Ran 9 tests in 6.723s, OK, one test passed, and the exact
COMPLETE_PATH_EVIDENCE JSON is retained in CURRENT_TASK.md and the raw child log.
It contains operation_count/transaction_count/independent_operation_count/ACK count/
unique_idempotency_keys all 100, one source call, one verifier call, one verified batch,
zero duplicate dispatches, receiver_side_effects=100, reopened_without_work=true, and
source_workspace_empty/verifier_workspace_empty=true. It remains activation=false,
production_usable=false, proofSuiteId=null, NOT_QUALIFIED/INACTIVE/UNSELECTED.

Raw evidence inventory:
  build-performance/guarded-configure-source-admission-20260913.stdout.log
  build-performance/guarded-outer-configure-source-admission-20260913.log
  build-performance/guarded-ctest-source-admission-20260913.stdout.log
  build-performance/guarded-outer-ctest-source-admission-20260913.log
Their sizes/hashes and empty stderr hashes are recorded in CURRENT_TASK.md. The earlier
claimed Ran 9 tests in 20.572s run had no retained raw guard evidence and was not rebuilt.
The prior documentation-governance warning remains: Ran 11 tests in 9.754s, FAILED (errors=2),
from six pre-existing unregistered README paths; protected registrations were not edited.

Post-implementation verification matched commit 9e86d8ff75f00db6e52554e8494f99cb009b3033,
tree a8dc5c2b8ccc29e2586cb968d522e500d30a27f3, parent
758345491bffa14df305c994c30d50f5a7d15680; tracked status and git diff --check were clean.
Only the intentionally untracked build-performance/ evidence tree remains. This record-only
append is the final permitted mutation; implementation files are immutable.

### Raw evidence fidelity addendum — 2026-09-13

The final byte audit found transcription omissions in the preceding closure only. The actual
assigned verifier identity is size 240640, SHA-256
F35F6AF28EC2D269831CFB6BDD1C2414D439FFEC2B26C73CC39495720D9B9E5D, matching the parent
grant and retained binary. The retained raw COMPLETE_PATH_EVIDENCE line also contains
source_measurement.peak_job_commit_bytes=21721088, verifier_measurement.peak_job_commit_bytes=20447232,
and verifier_measurement.stdout_bytes=0; those fields were omitted from the preceding
transcription. No binary or raw log changed. The exact literal line and raw-file hash are
recorded in CURRENT_TASK.md.

This addendum supersedes the preceding closure wherever the literal raw fields or verifier hash
differ. Implementation files remain immutable.

### Source completion ownership correction closure — 2026-09-13

The Driver-granted ownership correction started from Docs HEAD
b1b8843a86cb69b1efb5703f11b8e8b533e2faea/tree11303a2c94fad8fc3e725c7d3f71cafecb9252b4
and is implemented in 0fb0ca1cae3ab6e77e8f3860f5e9b0a05b8fa226/tree
5617f1e7052fdda5d20d2aae55ac90263deffdc5. Completion now requires the exact opaque
SourceLaunchOwnership receipt bound to the consuming authorization and admission; the receipt
also permits only one native entry. complete_path claims ownership before native work and uses
that receipt for success/failure cleanup. Authorization alone, wrong/stale receipts, and
reused receipts cannot finalize or re-enter another invocation.

The focused durable interleaving passed in the state suite: real STARTED row, paused winner,
loser consume source_authorization_used, loser cleanup source_authorization, unchanged
STARTED/accounting/transitions, stale receipt rejection, one native stub call, reused receipt
rejection, exact-owner SOURCE_COMPLETED finish, and independent verification. Owner failure,
postcommit, startup recovery, and no-refund seams remain covered by the existing tests.

Final affected results: compile exit 0; state 37/18.885s OK; source boundary 7/0.631s OK;
complete path 9/20.497s OK; queue/runtime 50/14.827s OK; composition/adapter 33/18.701s OK.

One fresh guarded synthetic containing path passed through the existing guard. Assigned binaries
were unchanged: source 275968/E07865D9CE6C2644142D3EA61030BD308D5BBD09FE861C630CC5EEBE1F3FE5D9,
verifier 240640/F35F6AF28EC2D269831CFB6BDD1C2414D439FFEC2B26C73CC39495720D9B9E5D. The raw
CTest stdout is 5549 bytes SHA256 6882B2E5FD07A10B3D6154F7755D422FD7F27565FD34D399469FE8ADBF81D510;
stderr is empty SHA256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855; outer
is 2884 bytes SHA256 5FF4C7DB3DB5E436E1297E83DECD4C6CB17A6630BE83E567A1CF9C456030C517. Guard
output recorded free preflight 2758893568, reserve 1073741824, exit7/0, CTest exit 0,
13 samples, minimum free 2653110272, cleanup PASS, and released mutex. Child output was
9 tests in 7.075s, OK, one passed, and its raw complete-path JSON is retained in CURRENT_TASK.md.
Counts were 100 operations/transactions/ACKs/unique keys, one source/verifier/State call,
zero duplicate dispatches, successful reopen, state.sqlite-only inventory, and empty workspaces.
proofSuiteId=null, production_usable=false, activation=false, NOT_QUALIFIED/INACTIVE/UNSELECTED.

The earlier 6.723s guarded evidence remains prior input and was not recreated. The inherited
documentation-governance warning remains six pre-existing unregistered README paths with 11
tests/2 errors; no protected registration or unrelated path was changed. This is the final
authorized ownership-correction record; implementation files remain immutable.
This is the final authorized ownership-correction record; implementation files remain immutable.

Raw fidelity note: the exact retained verifier_measurement includes stdout_bytes=0; the
preceding summary line omitted only that field. The byte-faithful raw JSON is recorded in
CURRENT_TASK.md, and no binary or raw log changed.

### Ownership receipt native-entry binding correction — 2026-09-13

At immutable HEAD ed079dd8f68970ad2732345a747f32a4d2216a5f / tree b5c6ef2efa2ecb7609e0e3d3c349464750965eaa, the public SourceLaunchOwnership(real_authorization, real_admission, object()) counterexample reached _begin_native() before finish rejected it. The correction adds authorization._owns(ownership) under the existing entry lock before setting _native_entered.

The direct Profile12 ownership test proves the fabricated receipt is rejected as SourceBoundaryError("source_authorization") before the stub, leaves authorization unconsumed, records native_calls=0, and leaves durable STARTED/accounting/transitions unchanged. Legitimate consumption then preserves the existing durable loser-cleanup/no-refund race and exactly one native call.

Focused raw results: py_compile exit_code=0; state ownership test Ran 1 test in 0.248s, OK, exit_code=0; source-boundary one-use test Ran 1 test in 0.017s, OK, exit_code=0. Only queue.py and the existing ownership test changed, with 22 insertions and 3 deletions. SHA-256 identities are queue B944E3B1D6103992DA8134561E5135C66A367F519B04C07EDA4DF1D4C073CC31, test F4A54985F128401702A9FEC44CCAD3348C0AFBBE34BFD20F292A53F8AF82357C, unchanged source_boundary.py 0CB820384F20101D6FABBE2A9614911FFA1573B5C052157B0519F0C4A093155D.

Skipped with explicit count/reason: new native/guarded runs 0 because prior valid native evidence and binaries are unchanged; full suites/builds/benchmarks/integration and qualification/activation runs 0 because this correction was restricted to focused checks. No new failures or warnings occurred; the inherited documentation-governance warning remains six unregistered README paths, 11 tests, 2 errors. The phase remains synthetic and nonactivating: proofSuiteId=null, production_usable=false, activation=false, NOT_QUALIFIED/INACTIVE/UNSELECTED.

## Queue native receipt/null-cleanup correction — 2026-09-19

This append-only section supersedes the earlier Queue native identities for the corrected
source/object/archive/binary receipt. `semantic_kernel/rust/native_boundary.c` now guards the
failure cleanup path: a null initializer is not dereferenced, while a non-null failed
initializer is released with `lean_dec_ref(initialization)` before `g_runtime_state = -1`.
The source SHA-256 is
`0d7a7c78592c06c71f78fbbf550b5a2f10b2621746e5d4fcaba728d40abe0dd7`; the freshly compiled
native object SHA-256 is
`9dcb694734e06f70dbc43aa184635ee0773057bc5a1be6a71a23e11a539548f8`.

`build.rs` now performs the pinned Lean build, verifies the archive SHA and exact archive
member list, compares extracted archive members with the direct objects, compiles the C
boundary with the pinned clang recipe, verifies that object, and direct-links the three Lean
objects plus the freshly compiled C object. The corrected archive is 454564 bytes with SHA-256
`86cedcae0f9758b75c7a4a4d3de5ca9c28b05b628e08b1868b26ca74584ca13c`; its exact members are
`Library.c.o.export`, `Model.c.o.noexport`, `Sha3.c.o.noexport`, and `native_boundary.o`.
The combined source binding is
`768f9d69ebb660875448088bfc1983862b2db46f69e773bde19b7ee0feb09de6`, and the final adapter
binary is 6470656 bytes with SHA-256
`0aeb8ccd18e4eb905c1147889bf66265c94d9dcc2311c3d699571a85cf3fb577`.

Raw guarded evidence: the corrected direct-receipt Cargo build exited 0, minimum free memory
was 4176629760 bytes, peak owned private bytes were 242708480, cleanup was PASS, and the mutex
was RELEASED. The affected verification rerun exited 0 with guard self-tests 7/0, minimum free
memory 4303130624 bytes, peak owned private bytes 59027456, cleanup PASS, and mutex RELEASED.
Its raw test output was:
`LEAN_ADMISSION_INTEGRATION {"artifact_sha256": "86cedcae0f9758b75c7a4a4d3de5ca9c28b05b628e08b1868b26ca74584ca13c", "input_bytes": 110, "kernel_calls": 5, "source_accounting": {"a_used": 1, "m_used": 100, "s_used": 4096, "u_used": 1, "v_used": 1}, "source_binding_sha256": "768f9d69ebb660875448088bfc1983862b2db46f69e773bde19b7ee0feb09de6", "source_status": "COMPLETED", "verifier_status": "STARTED"}`; followed by `Ran 8 tests in 5.667s` and `OK`.

An intermediate verification with the stale adapter pin failed exactly three compiled tests
with `LeanAdmissionError: lean_admission_adapter_binding`; after updating the adapter SHA to
the final binary identity above, the rerun passed. This failure is retained as receipt-freshness
evidence, not suppressed. The null-cleanup source-contract regression and compiled finish
coverage are included in the 8-test run. No runtime 20-test suite was rerun. Qualification
remains unchanged: proofSuiteId=null, production_usable=false, activation=false,
NOT_QUALIFIED/INACTIVE/UNSELECTED.

## Receipt target ordering correction — 2026-09-19

`build.rs` now compiles and hashes the fresh OUT_DIR `native_boundary.o` before calling
`verify_archive_members`; the archive member comparison receives that exact fresh object, which
is also the object passed to the linker. The exact member order, full byte comparisons, existing
hash pins, compiler recipe, and direct-object ABI are unchanged.

The affected guarded build with suffix `queue-fresh-native-member-receipt-20260919c` exited 0.
Raw decisive telemetry: guard self-tests `exit7=7 exit0=0`; minimum free bytes
`4404867072`; peak private bytes `224628736`; cleanup `PASS`; mutex `RELEASED`.
The earlier invocation failed before compilation because Cargo resolved the linker as missing
`x86_64-w64-mingw32-gcc` (exit 101, cleanup PASS); an explicit pin to the already accepted
Lean clang linker was used for the successful retry. A retry while the State task held the exact
mutex was rejected by the guard and was not bypassed.

The receipt check itself passed, but the resulting GNU adapter identity unexpectedly changed to
6472192 bytes, SHA-256
`92afee451f9f10d4ab71de2277be6b6db8798e275658c52824cb820f129c429d`, versus the previously
reviewed 6470656-byte `0aeb8ccd18e4eb905c1147889bf66265c94d9dcc2311c3d699571a85cf3fb577`.
This identity was preserved and not repinned. The prior 8-test evidence is therefore reused only
as historical evidence; no new application verification or qualification credit is claimed for
the changed binary.
The exact accepted inner-command recipe was then restored: the guard-launched PowerShell used
`Set-Location semantic_kernel/rust`, retained the pinned Rust compiler, and let the crate-local
`.cargo/config.toml` supply the pinned clang linker plus `-C link-self-contained=no` and
`-C panic=abort`. The resulting adapter returned to 6470656 bytes with SHA-256
`0aeb8ccd18e4eb905c1147889bf66265c94d9dcc2311c3d699571a85cf3fb577`; no repin was made.

The affected guarded verification then exited 0 with minimum free bytes `4584321024`, peak
private bytes `66498560`, cleanup `PASS`, and mutex `RELEASED`. Raw output:
`LEAN_ADMISSION_INTEGRATION {"artifact_sha256": "86cedcae0f9758b75c7a4a4d3de5ca9c28b05b628e08b1868b26ca74584ca13c", "input_bytes": 110, "kernel_calls": 5, "source_accounting": {"a_used": 1, "m_used": 100, "s_used": 4096, "u_used": 1, "v_used": 1}, "source_binding_sha256": "768f9d69ebb660875448088bfc1983862b2db46f69e773bde19b7ee0feb09de6", "source_status": "COMPLETED", "verifier_status": "STARTED"}`; followed by `Ran 8 tests in 6.345s` and `OK`.

The prior missing-linker exit 101, mutex refusal, changed 92af executable, and generated evidence
remain preserved. No unchanged 20-test replay or new C failure-path qualification was performed.

## Driver 2 lifecycle sidecar source handoff — 2026-09-22

The current source-only stage adds the typed Python adapter, a separate Lean lifecycle wire module,
a separate Rust `lifecycle` binary, bounded archive wiring, a focused adapter test module, and a
minimal read-only same-connection snapshot API in the independent Queue verifier. The protocol is
version 1 (`BLQLIN01`/`BLQLOU01`), with a 16,384-byte request bound and 32,768-byte response bound.
It reconstructs existing Queue rows on the caller's active SQLite connection, invokes only the pure
accepted `submitHandoff`/`claimNextBatch` transition, and compares the full result and canonical
Queue event bytes to host-planned values. The adapter neither owns a lock nor opens, closes,
mutates, commits, or rolls back the caller's connection; no production Queue call site was added.

Source identities at this checkpoint:

- `app/minimal_clearance_lifecycle_adapter.py`: 31,585 bytes,
  SHA-256 `5DDAF7D3E32D326B7822210E435073FD000B011A55CD443CCCC6A8F2199B66D2`.
- `app/minimal_clearance_verification_queue_independent.py`: 107,718 bytes,
  SHA-256 `863CB9F323C53102E7C041D0EF931BFE3D5FF56664C3DCEC61C927F58A8CE413`.
- `semantic_kernel/lean/Admission/LifecycleKernel.lean`: 23,006 bytes,
  SHA-256 `443FC531221AC6406387D7BE18D9A6701EF5B8F15F702DCBF24D3812B03F30F9`.
- `semantic_kernel/rust/src/bin/lifecycle.rs`: 5,340 bytes,
  SHA-256 `D564DC02964B688360EF39925FDF4056A87B8CCEE80912820A4072D3A6963242`.
- `semantic_kernel/rust/build.rs`: 14,185 bytes,
  SHA-256 `179A89898D85F74CCC835C97D5B4F68CC13C0C7A6ADC2181C81786252D489DEE`.
- `tests/test_minimal_clearance_lifecycle_adapter.py`: 20,071 bytes,
  SHA-256 `33AF02ABA6BE2C5413218A3A7CE3DE677F144CBED6084E94617931453B4EE234`.

The source review corrected Lean FFI object ownership, uses bounded linear ByteArray output access,
and decodes hex with a tail-recursive accumulator. The focused test source asserts the transaction,
pending write, PRAGMA state, event bytes, and independent database verification remain consistent.
These are source findings only: this stage ran no build, compiler, test, or checker. Exact skipped
checks are 1 Lake build, 1 Cargo build, 1 focused Python test module, and 1 `git diff --check`, all
withheld pending the task's direct finite guard handoff, fresh valid memory, absolute inner working
directory, checked child exits, and cleanup evidence. Accepted Build54/Run55 evidence was not
rerun; replay count is 0. No new execution lane was requested or acquired.

The repository remains at HEAD `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55`. `Admission/Main.lean`,
`lakefile.toml`, Rust `src/main.rs`, accepted `Lifecycle.lean`/proofs/cases, and native C remain
unchanged at their recorded hashes. Pre-existing untracked `.lake/`, `Experiment.lean`, linker
command, and native object files are preserved. The canonical financial checkout mismatch remains
as previously recorded; this stage does not copy its verifier or change that checkout. All compiled
FFI assumptions, module build/link behavior, lifecycle KATs, and same-lock integration remain
unverified. Python remains the transaction/runtime authority; `proofSuiteId=null`,
`production_usable=false`, activation `false`, `NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

## Versioned Queue issue request identity and exact GNU LLD pin — source-only — 2026-09-23

The checkout remains HEAD/tree
`b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55 / 40d8268880072f23b4c46fc83aee2c5084184083`.
No file was staged or committed. Existing dirty and untracked work, including the Queue Lifecycle
adapter, Lean candidate and `.lake`, linker wrapper, and native objects, remains preserved.

### Durable issue request v1

The Queue store and runtime now expose `issue_batch_v1(request_id, template)`. The fixed-width
request ID is exactly 32 bytes. V1 computes the existing batch primary key with
`SHA3-256(domain_v1 || len(queue_id_ascii).to_bytes(8, "big") || queue_id_ascii || request_id)`.
The domain is
`BL/NATIVE-V3/MINIMAL-CLEARANCE/VERIFICATION-QUEUE/ISSUE-REQUEST-BATCH-ID/v1\0`. The independent
implementation uses the same encoding and exposes both a same-transaction resolver for the writer
and a read-only full-database resolver. The runtime's `resolve_issue_request_v1` returns that
independently verified lookup.

The row's existing 32-byte `queue_batches.batch_id` PK durably binds the request, so no SQL table,
column, schema version, profile version, event format, export format, migration, or activation
change was made. On retry, Queue takes the existing owner and `BEGIN IMMEDIATE`, revalidates the
database, independently resolves the ID against the caller's exact template and trusted config,
and returns the same stored issue result. A template mismatch is `issue_request_conflict`; it exits
before capacity/reservation changes. If absent, normal issue creation uses the derived ID and keeps
100 distinct ordered 32-byte Queue refs, one attempt/event, and exactly one 101-unit reservation in
the existing atomic transaction. Same-ID concurrent calls serialize and resolve to one batch. The
raw ID is not persisted; the caller must supply a fresh random non-PHI ID and durably retain it.
The existing unkeyed `issue_batch`
compatibility method remains non-idempotent. Recovery covers process restart and response loss
against the same authoritative database history; external database rollback and caller-ID loss are
outside this change.

The focused source cases cover pre-commit rollback then issuance, post-commit ambiguity then
readback/retry across store restart, changed-template conflict without a second reservation,
same-ID concurrency, different-ID concurrency, and the public runtime path with independent
readback and restart recovery. The existing direct-mask issue-commit assertion remains in scope.
These seven focused methods have not run.

### Linker/toolchain source candidate

Current filesystem hashes independently reconfirmed Clang at 217,600 bytes /
`1AEA18DCA98F91A6A7C65532ADC2567EFC775904D2A4BD28BF06731BC2C3778C`, and
`ld.lld.exe` at 6,772,224 bytes /
`675E59F33F11CB90500577F116082ED4A6214FCAC3A1BAD88D6323AA0373179F`. The sibling `lld.exe`
has the same size and digest; the source explicitly selects the GNU-named `ld.lld.exe`. Existing
read-only GNU target-manifest evidence remains 60 `file:` records, all present, and its reproduced
binding `7fc52762b8d5098e5283ffa754d30cb8fab4ff1027118ef1e8ae2f83d5ec094b` matches the pin.

`build.rs` now pins `bin/ld.lld.exe`, includes canonical resolved Clang and LLD paths in its source
identity records, copies the pinned LLD into `OUT_DIR/native_link_inputs`, checks/records that
selected copy, and adds `-B<Lean bin>`, `-fuse-ld=lld`, `--ld-path=<OUT_DIR copy>`, and `-v` to the
ordered linker-argument manifest v2 and Cargo link arguments. It also requests rerun when either
the pinned tool or staged copy changes. The configured Clang and x86_64 Windows GNU target remain
fixed; no target switch or external tool installation occurred. The MSVC `native_linker.cmd` file
was not used or edited.

This changes the future source command from an unqualified default linker to an explicit
hash-pinned LLD candidate; it does not verify Clang's actual final-link invocation. The generated
copy and Cargo linker have not been run. One guarded Cargo Lifecycle build, including captured
raw `clang -v` output, remains pending. Source-bound runtime mode remains closed; the retained
executable identity is unchanged. The source-level final-link concurrency/race limitation remains.

### Verification and disposition

No Python tests (seven focused methods pending), Cargo/Lake build, compiler, checker, or guarded
command ran in this source-only continuation. `git diff --check` was not run. The Security-owned
lane has not been directly handed back. The only newly browsed technical source was the official
LLVM Clang driver documentation, which describes `-B` search prefixes and `-###`/`-v` command
reporting; the current work did not run either option. Earlier guarded lifecycle r1 failure and r2
correction remain recorded with their original raw logs; no new test result or linker-success claim
is inferred. `proofSuiteId=null`, `production_usable=false`, activation `false`, and
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED` remain unchanged.

## Pure Queue lifecycle candidate and adapter-contract closure — 2026-09-22

The accepted pure Queue lifecycle candidate is based at source commit
`71438a3fbf5a87bb86f03d39752c4f9e391727da`, tree
`ce87d880026b7eeaafd8c0222473790d25c1ea3a`, parent
`0a81b1f856db09e83d31b0701795d486ee7a5eec`, and changes only
`semantic_kernel/lean/Admission/Lifecycle.lean`, `LifecycleProofs.lean`, and
`LifecycleCases.lean`. The contract is now recorded in `docs/LEAN_FORMAL_KERNEL.md`: same-lock
`BEGIN IMMEDIATE` reconstruction from existing Queue rows, global metadata lease count versus
selected local lease shape, cumulative A/S/M/U/V accounting, exact 101 reservation chain,
submit/claim after-states/events, Python-owned token/fence/custody, HELD/expiry/recovery, and
pre-/post-COMMIT semantics.

The already-reviewed guarded evidence was reused without rerun:

- Build suffix `lean-lifecycle-global-lease-final-build-20260920-54`: exact command
  `lake build Admission.LifecycleCases`, six jobs, child/outer exit `0`, cleanup `PASS`, mutex
  `RELEASED`; child stdout 178 bytes, SHA-256
  `C103F3FBB1C9C79546445446AD596233FABF69A740657B12BD501088487334AF`; stderr 0 bytes, SHA-256
  `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.
- Run suffix `lean-lifecycle-global-lease-final-run-20260920-55`: exact command
  `lake env lean --run Admission/LifecycleCases.lean`,
  `LIFECYCLE_CASES=PASS cases=68`, child/outer exit `0`, cleanup `PASS`, mutex `RELEASED`; stdout
  30 bytes, SHA-256 `831580C16C0BD6E398CCDDF59EF52348F13B9373453C29D45E023D92BB1B0331`; stderr 0
  bytes with the same empty-stderr hash.

No new execution was authorized in this docs closure (count `0`); prior failures and receipts
remain preserved. The current 110-byte Python adapter status/counter frame has no
`LifecycleState`/`LifecycleTransition` or submit/claim operations, so Python remains runtime
authority and the same-lock adapter, release, theorem, independent-kernel, and deployment gates
remain open. `proofSuiteId=null`, `production_usable=false`, activation is `false`, and the
status remains `NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

## Lifecycle adapter input-boundary source follow-up — 2026-09-22

The authorized source follow-up hardens only `app/minimal_clearance_lifecycle_adapter.py` and its
focused source test, with this file, `CURRENT_TASK.md`, and `docs/LEAN_FORMAL_KERNEL.md` updated for
status and continuation. The adapter now requires and forwards the executable byte size and
SHA-256 pin unchanged to the contained-process API, rejects absent expected config in both
reconstruction and evaluation, and caps process timeout at 3.0 seconds. The existing process API
enforces positive exact-int size, exact 32-byte digest shape, and executable identity; its source
reports `verifier_executable_size` or `verifier_executable_identity` when a well-shaped pin is
wrong. Queue source sets `LEAN_ADMISSION_TIMEOUT_SECONDS=3.0`.

Focused source coverage includes missing and wrong executable pins, missing and mismatched config,
timeout above 3.0 seconds, and no caller transaction, with connection/transaction immutability
assertions. One guarded Lake check ran and failed at `Admission.LifecycleKernel`. The guard was
`run_guarded_v3.ps1` SHA-256
`55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`, RunSuffix
`queue-lifecycle-kernel-20260922-r1`, and inner command `lake build Admission.LifecycleKernel` from
`semantic_kernel/lean`. Guard preflight free bytes were `3,413,000,192`; live minimum free bytes
were `2,744,217,600`; peak private bytes were `952,303,616`; child and outer exits were `1`;
cleanup was `PASS`; mutex was `RELEASED`. Guard exit self-tests were `exit7=7 exit0=0`.

The exact child stdout is at
`build-filter-native/guarded-command-queue-lifecycle-kernel-20260922-r1.stdout.log`, 1,631 bytes,
SHA-256 `5A5D70EB1CCCD24BDFC4A8EDCF53AED2A5DAFC5BE2606EBA5C7A19F5AF9B8EC8`; stderr is 20 bytes,
SHA-256 `C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F`. Lean emitted five
syntax errors in `semantic_kernel/lean/Admission/LifecycleKernel.lean` at 156:71, 188:79, 235:65,
303:83, and 418:77 (`unexpected identifier; expected '}'`). That source is outside this follow-up's
write scope and was not edited. The explicit STOP after the failed check left the planned Cargo
build (1), focused Python module (1), and diff check (1) unlaunched. No adapter test result is
available; no Queue production caller was added. The adapter does not attest the OS owner lock or
`BEGIN IMMEDIATE` mode; those remain caller obligations.

At the earlier Lifecycle-adapter integrity checkpoint, the protected claim-clock issue remained
open: Queue sampled `now` before `BEGIN IMMEDIATE` in `_claim_next_batch`. That checkpoint predates
the separate exact claim-clock delegation and guarded verification recorded below. The next finite
lane recipient after this Queue follow-up is Lean Engine. The historical `3,409,649,664`-byte
sample was below Engine's
`4,190,433,321`-byte workload-start estimate and is not an Engine post-handoff preflight. Engine
must perform a fresh preflight against `4,190,433,321` bytes after handoff; if below that threshold,
Engine passes the lane to State without starting its workload. No Engine workload ran. The
corrected Queue preflight was `3,393,343,488` bytes, above the Queue guard floor, `PRECHECK=PASS`;
after Queue's failed Lake check the mutex was `ABSENT` and relevant build-process count was zero.

Operational setup evidence: one preliminary host-only preflight invocation exited `1` because
`$guardDir` was unset (`Cannot bind argument to parameter 'Path' because this parameter is null.`);
no workload started and the corrected preflight passed. One wrapper-construction attempt raised
`SyntaxError: Unexpected identifier '$LASTEXITCODE'` before shell launch. An exploratory broad
`rg --files` returned access denied for the two `proof-primitives-run-1` and
`proof-primitives-run-2` directories under `C:\Users\neers\Documents\Codex\2026-08-25-v6-focused-temp`;
the authorized run used the exact guard path.

## Claim-clock after-lock timing correction — guarded Queue verification — 2026-09-22

The exact delegated change touched only `app/minimal_clearance_verification_queue.py`,
`tests/test_minimal_clearance_verification_queue.py`, and these truthful evidence records in
`CURRENT_TASK.md`, `STATE.md`, and `docs/LEAN_FORMAL_KERNEL.md`. `_claim_next_batch` now samples its
single `now` immediately after `BEGIN IMMEDIATE` succeeds, while the existing Queue owner lock is
held and inside the rollback-protected block. That sample controls expiry, oldest-eligible
selection, lease expiry, database timestamps, and `VERIFICATION_STARTED`.

The regression `QueueV12Tests.test_claim_clock_waits_for_sqlite_write_transaction` uses the real
owner lock, a competing SQLite writer and a fake clock advanced during the blocked `BEGIN
IMMEDIATE`. It observes owner validation, attempted/acquired transaction boundaries, and a separate
zero-timeout write probe. It checks the success path (first batch expires, second becomes eligible
and receives the sole lease) and the rejection path (the only batch expires, with no claim), exact
reservation and event state, duplicate-claim absence, connection/lock cleanup, and independent
database reconstruction.

Fresh preflight before the first guarded attempt reported guard SHA-256
`55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`, free physical memory
`4554321920` bytes versus floor `2190433321`, mutex `ABSENT`, relevant Queue-test processes `0`,
and Python `3.14.4`. The guard's own `PHYSICAL_PREFLIGHT` was `4552110080` bytes on r1. Before r2,
the host preflight was `4518903808` bytes with mutex `ABSENT` and relevant Queue-test processes `0`;
the guard's own `PHYSICAL_PREFLIGHT` was `4536897536` bytes. Both attempts used the exact Queue cwd and command
`py -3.14 -B -m unittest tests.test_minimal_clearance_verification_queue`. Guard self-tests
reported `CHILD_EXIT_CHECK exit7=7 exit0=0`.

The first guarded attempt used suffix `queue-claim-clock-20260922-r1`: child and outer exit `1`,
20 live samples, minimum free memory `4453785600` bytes, peak working set `109326336` bytes, peak
private bytes `71278592`, cleanup `PASS`, mutex `RELEASED`. It ran 32 tests and failed one assertion
in the new regression because the persisted event ID is uppercase hex while `bytes.hex()` produced
lowercase expected text. This was a test-only correction to compare against `.hex().upper()`; the
Queue behavior, timing assertion, and database assertions had passed. The exact raw child output
was:

The child logs are retained under
`../pq-wide-seed-native-20260913/build-filter-native/`:

- `guarded-command-queue-claim-clock-20260922-r1.stdout.log` (0 bytes)
- `guarded-command-queue-claim-clock-20260922-r1.stderr.log` (1195 bytes)

```text
CHILD_STDOUT (0 bytes, SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855): [empty]
CHILD_STDERR (1195 bytes, SHA-256 3362354CEEB1C7A2C5871B50842FE67A9AC9B111E726B6676BE43680ECED2E68):
..F.............................
======================================================================
FAIL: test_claim_clock_waits_for_sqlite_write_transaction (tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_claim_clock_waits_for_sqlite_write_transaction) (expect_claim=True)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\lean-queue-20260913\tests\test_minimal_clearance_verification_queue.py", line 1403, in test_claim_clock_waits_for_sqlite_write_transaction
    self.assertEqual(started_event["batch_id"], eligible.batch_id.hex())
    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError: 'E21B1031DE4EA14E9A6BFE0ADB8AB2BC5EC483C2201C5FC44CF94EFE79747BCD' != 'e21b1031de4ea14e9a6bfe0adb8ab2bc5ec483c2201c5fc44cf94efe79747bcd'
- E21B1031DE4EA14E9A6BFE0ADB8AB2BC5EC483C2201C5FC44CF94EFE79747BCD
+ e21b1031de4ea14e9a6bfe0adb8ab2bc5ec483c2201c5fc44cf94efe79747bcd


----------------------------------------------------------------------
Ran 32 tests in 10.063s

FAILED (failures=1)
```

The one corrected guarded verification used suffix `queue-claim-clock-20260922-r2`. Its fresh
preflight reported `4536897536` free bytes and stayed above the same floor. The guard recorded 19
live samples, minimum free memory `4439969792` bytes, peak working set `105988096`, peak private
bytes `68710400`, child/outer exit `0`, cleanup `PASS`, and mutex `RELEASED`. The post-run probes
reported mutex `ABSENT` and relevant Queue-test process count `0`. Raw child output:

The child logs are retained under
`../pq-wide-seed-native-20260913/build-filter-native/`:

- `guarded-command-queue-claim-clock-20260922-r2.stdout.log` (0 bytes)
- `guarded-command-queue-claim-clock-20260922-r2.stderr.log` (137 bytes)

```text
CHILD_STDOUT (0 bytes, SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855): [empty]
CHILD_STDERR (137 bytes, SHA-256 64CA990F5928092CCA804766844AE113423E8C03D4CE3DD4947A336663C50F34):
................................
----------------------------------------------------------------------
Ran 32 tests in 10.095s

OK
```

Final source SHA-256 values are `BE8C692CF8D3EB04702BC4449EBEA425FEACF924C2AA43A90973A89B2737917B` for
`app/minimal_clearance_verification_queue.py` and
`F605358181C9120ADEFEEBF47B6BEB997C5C462E2C4FC9C65D286A9BF5487410` for
`tests/test_minimal_clearance_verification_queue.py`. The guard SHA-256 remains
`55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`; `git diff --check` exits
`0`. HEAD/tree remain `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55` /
`40d8268880072f23b4c46fc83aee2c5084184083`; no file was staged or committed.

This verifies the timestamp is acquired after the SQLite claim lock in the tested Python source
boundary. It makes no wall-clock monotonicity or time-through-COMMIT atomicity claim and does not
qualify production, compile/link Lean, or integrate the lifecycle executable. Python remains the
sole Queue runtime authority; `proofSuiteId=null`, `production_usable=false`, activation `false`,
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`. The next finite lane recipient is Lean Engine for its
repaired CodecLaws proof closure; it must perform its own fresh preflight.

## Profile12 Queue lifecycle sidecar source integration — unverified — 2026-09-23

The exact new assignment touched the lifecycle adapter, successful submit/claim callsites in the
protected Queue module, their focused test files, and the bounded status/contract records in
`CURRENT_TASK.md`, this file, and `docs/LEAN_FORMAL_KERNEL.md`. It did not change the independent
Queue checker, Composition, Lean source, native/source-auth code, profile selection, or runtime
qualification controls.

`app/minimal_clearance_lifecycle_adapter.py` now fixes the only production executable path to
`semantic_kernel/rust/target/x86_64-pc-windows-gnu/release/lifecycle.exe` and embeds the reviewed
synthetic pin: 6,571,008 bytes and SHA-256
`B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881`. The current local bytes
matched. The lifecycle Lean sources appear in Cargo dependency/build inputs, but the retained
`build.rs` does not hash those Lean source files. Source-to-binary reproducibility remains
unestablished; this pin supports only the supplied synthetic reviewed identity. Adapter callers
cannot supply the path, size, or digest.

Both successful Queue operations invoke the sidecar after the owner check, `BEGIN IMMEDIATE`, and
the existing Python clock sample, before their successful-transition SQL writes. The same active
connection is reconstructed read-only through the independent checker. Python derives the complete
submit/claim after-state and canonical Queue event plan from that snapshot; the bounded Lean output
must match both exactly. Submit attaches the volatile handoff only after agreement. Claim validates
the actual in-memory handoff and generates its lease token only after agreement. Any adapter,
identity, timeout, protocol, or output failure reaches the transaction rollback path. A failed
submit wipes that input handoff and leaves the stored batch awaiting a fresh handoff; failed claim
rolls back transaction-local expiry writes and leaves its attached handoff, reservation, and lease
accounting available for retry. The adapter does not commit or change the supplied connection.

The existing unsupported host outcomes are explicit. Count 4 successful-submit precondition
branches remain Python-owned `HELD` outcomes (batch binding, non-awaiting batch, incomplete source
admission, and expired validity), because the current kernel exposes no `HELD` transition. Count 1
no-eligible-row claim path can commit expiry housekeeping without a selected `claimNextBatch`
transition. On the path where expiry housekeeping and a selected claim share a transaction, sidecar
failure rolls back the whole transaction; expired in-memory handoffs are closed only after commit.

Source hashes for this assignment (before → after): adapter
`D8F86B6E10C94C9B2BE9A74469482C8E8972916764D3F9002C194991B2FDC37F` →
`BBD5F7136D8749CC507C35BE5A96278CEA1D73573A8781DFADDE1E7EC887683E`; Queue
`BE8C692CF8D3EB04702BC4449EBEA425FEACF924C2AA43A90973A89B2737917B` →
`FE5D1DC4DFCB17D9FFA1810B14EC6BC1E7D3760427DD0C26C82FA0F2F8582950`; adapter tests
`6E0E6DC380B5236D7B2D2AEFF8949E277CE723FAE425B9BB79BA193F1A4E3750` →
`1F8F7F0BB34A3E86E9733E8846EC594772369A1D4D30078746483012D7EF3252`; Queue tests
`F605358181C9120ADEFEEBF47B6BEB997C5C462E2C4FC9C65D286A9BF5487410` →
`D560DE4226427A31C575C5AB384336707597E6C1B70AD7AB0DB68DC4D8510A94`.

No test, build, independent checker, or guarded command ran during this source stage (count `0` for
each); no new output or pass claim exists. Pending focused verification comprises 13 adapter test
methods and four Queue methods: explicit binding/expiry non-invocation, contended claim, positive
submit/claim with event bytes, and timeout rollback/retry. The other 30 Queue test methods are
outside the focused packet (count `30`); the 68-case Lean lifecycle replay count is `0`. The
previous LifecycleKernel syntax failure remains an open recorded failure and was not rerun here.

HEAD/tree remain `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55` /
`40d8268880072f23b4c46fc83aee2c5084184083`. Existing dirty and untracked Queue/Lean work was
preserved; nothing was staged or committed. The assigned lane order is Security checker
verification/CodecLaws repair, one Engine guarded proof rerun, one State decision-package
verification, then Queue lifecycle verification. Nonactivation remains unchanged:
`proofSuiteId=null`, `production_usable=false`, activation `false`,
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

## Profile12 Queue lifecycle sidecar focused verification — 2026-09-23

The direct finite Queue handoff ran from checkout
C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\lean-queue-20260913,
HEAD b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55, tree
40d8268880072f23b4c46fc83aee2c5084184083. The pre-execution pins were rechecked: adapter
BBD5F7136D8749CC507C35BE5A96278CEA1D73573A8781DFADDE1E7EC887683E; protected Queue source
FE5D1DC4DFCB17D9FFA1810B14EC6BC1E7D3760427DD0C26C82FA0F2F8582950; adapter tests
1F8F7F0BB34A3E86E9733E8846EC594772369A1D4D30078746483012D7EF3252; Queue tests
D560DE4226427A31C575C5AB384336707597E6C1B70AD7AB0DB68DC4D8510A94. The fixed lifecycle
executable remained 6,571,008 bytes / SHA-256
B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881. Guard
C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\run_guarded_v3.ps1
matched SHA-256 55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D.

The first fresh host preflight reported free physical memory 3,951,755,264 bytes against floor
2,190,433,321, exact mutex absent, relevant workload process count 0, and Python launcher
C:\Users\neers\AppData\Local\Programs\Python\Launcher\py.exe. The guard's own physical preflight
reported 3,981,398,016 bytes. RunSuffix was
queue-lifecycle-sidecar-20260923-r1. Guard exit-propagation self-tests reported exit7=7 and exit0=0.
The exact focused child selection was these 17 method IDs:

- tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_caller_cannot_supply_executable_path_or_pin
- tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_missing_executable_is_rejected_without_mutating_connection
- tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_tampered_executable_is_rejected_without_mutating_connection
- tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_missing_or_mismatched_expected_config_is_rejected_without_mutation
- tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_timeout_above_queue_authority_is_rejected_without_mutating_connection
- tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_timeout_failure_is_rejected_without_mutating_connection
- tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_unknown_process_exit_fails_closed_without_mutating_connection
- tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_missing_transaction_is_rejected_without_mutating_connection
- tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_submit_round_trip_preserves_transaction_and_commits_only_host_plan
- tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_claim_acceptance_and_mutated_global_lease_precondition
- tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_submit_allows_unrelated_live_lease_and_claim_rejects_it
- tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_invalid_lifecycle_state_field_fails_closed
- tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_invalid_lifecycle_event_schema_fails_closed
- tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_binding_and_expiry_rejections_close_and_wipe_handoffs
- tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_claim_clock_waits_for_sqlite_write_transaction
- tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_lifecycle_sidecar_submit_claim_event_bytes_and_independent_verify
- tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_lifecycle_sidecar_failures_rollback_and_allow_fresh_retry

The first packet ran all 17 methods in 5.883s and ended
FAILED (failures=1, errors=1): 15 methods passed; the missing-executable assertion expected
lifecycle_process:verifier_executable_path but observed
lifecycle_process:verifier_executable_open:2, and the Queue test queried nonexistent
queue_leases.issued_ms. The authoritative process helper accepts an absolute Path then attempts the
Windows file open (app/minimal_clearance_verifier_process.py:739-745), so OS error 2 is the observed
missing-file rejection. The Queue column manifest and DDL both name leased_ms
(app/minimal_clearance_verification_queue.py:2145,2165); the claim insertion writes the sampled
now value to that column (line 3322). These were test expectation defects, not production source
changes.

The only changes in response were two focused test corrections:
- tests/test_minimal_clearance_lifecycle_adapter.py now asserts the observed
  lifecycle_process:verifier_executable_open:2 error for the missing absolute path.
- tests/test_minimal_clearance_verification_queue.py now selects leased_ms instead of issued_ms.

A fresh preflight for the affected-method rerun reported free bytes 3,920,429,056, mutex absent, and
relevant process count 0. RunSuffix was queue-lifecycle-sidecar-20260923-r2. The guard's physical
preflight was 3,874,668,544 bytes. Its exit self-tests again reported exit7=7 and exit0=0. The two
affected methods returned child and outer exit 0 in 0.610s. Live minimum free bytes were
3,797,274,624; peak working set 126,566,400; peak private bytes 87,355,392; four live samples;
cleanup PASS; owned process tree empty; mutex RELEASED. Post-run check found the mutex absent,
relevant process count 0, and free bytes 3,922,444,288.

The r1 captured child stdout is 0 bytes with SHA-256
E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855. Its complete child stderr is
at C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\guarded-command-queue-lifecycle-sidecar-20260923-r1.stderr.log,
8,035 bytes, SHA-256
1FA37528E6527B7EF1B49CE06B2A3F19A446E7C736B1FDB081C64129E622338F. The r2 child stdout is
0 bytes with the same empty-file hash. Its stderr is at
C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\guarded-command-queue-lifecycle-sidecar-20260923-r2.stderr.log,
524 bytes, SHA-256
2660E0EF4CC15909E806F7107CB4195BD674DD6AE668CE084FDA0C9973D0C9CF and reports 2 tests in
0.610s, OK.

Post-correction test SHA-256 values are
tests/test_minimal_clearance_lifecycle_adapter.py:
8303DB0812EF73F59DE9509D41D52A9EB2AFDBCD2E818ECF08128DCFE08F511B
tests/test_minimal_clearance_verification_queue.py:
F496184650597C1075ADC3BDF909B047A41EDEC62C33B041A421DCE93F4CE6FA.
The adapter and Queue source hashes remain at the pinned values above. git diff --check exited 0.
Existing dirty/untracked Queue and Lean work was preserved; nothing was staged or committed. All 17
selected method names passed across the initial packet and the two-method correction rerun. The
initial 17-method packet's failure remains retained and is not relabelled. The other 30 Queue
methods were excluded by the requested focused scope, the 68-case Lean lifecycle replay count is 0,
and no build or Lean syntax repair ran. The prior LifecycleKernel compiler failure remains open.
No lifecycle source-to-binary reproducibility, formal release, deployed-link, production,
activation, or proof-suite claim follows. The direct next lane recipient is Driver for Provider App
focused verification. The Queue lane is released; no lane reservation or polling followed.

## Lifecycle decoder and source identity follow-up — source-only — 2026-09-23

The assignment began at HEAD `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55`, tree
`40d8268880072f23b4c46fc83aee2c5084184083`. Existing dirty and untracked Queue/Lean work was
preserved. Exact changed paths are `semantic_kernel/lean/Admission/LifecycleKernel.lean`,
`semantic_kernel/rust/build.rs`, `CURRENT_TASK.md`, `STATE.md`, and `docs/LEAN_FORMAL_KERNEL.md`;
no test was added, nothing was staged, and no commit was created.

The prior guarded Lake output records five `unexpected identifier; expected '}'` parser errors at
`LifecycleKernel.lean` 156:71, 188:79, 235:65, 303:83, and 418:77. Captured child stdout is 1,631
bytes / SHA-256 `5A5D70EB1CCCD24BDFC4A8EDCF53AED2A5DAFC5BE2606EBA5C7A19F5AF9B8EC8`; stderr is 20
bytes / SHA-256 `C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F`. The source change
removes commas only between fields in the five named record constructors. Field assignments, decode
order, returned remainders, matching encoder order, wire bytes, event ordering, state predicates,
transition code, theorem statements, and axiom boundary are unchanged. Static comparison checked
Config, Identity, Accounting, State, and Event encoders. `LifecycleKernel.lean` is 23,464 bytes /
SHA-256 `5B6D0B4C7109946F8A26C2EDE19FC2B25447E373B50CF863BDCD04EC6488D8AC`; its prior source hash
was `421DC33A982C496A747EC8F3FAD9942C18651DAA6406811E8C0BCD26E08DB642`.

`build.rs` pins ten Lean/project files and five Rust build/runtime inputs, then verifies the Lean,
Lake, clang, and llvm-ar executables and the complete toolchain `.olean` import tree. The tree
contains 2,485 files / 353,835,856 bytes; its canonical `lean-olean-tree-v1` manifest hash is
`a76983027716a67e972e8e7d5c87d8d95c0ceb888a20f453d987843620a7354a`. The pinned local import
chain is LifecycleKernel -> Lifecycle -> Model -> `Std.Tactic` and `BlindLedger.Sha3` -> `Std`;
the tree pin covers the complete installed `.olean` closure, including Prelude and transitive
imports. The build script copies verified local inputs into a freshly recreated Cargo `OUT_DIR`
project and builds Library, LifecycleKernel, and Lifecycle there. It archives the fresh
LifecycleKernel, Lifecycle, Model, and Sha3 objects plus a manifest object; it verifies exact
member order and bytes and rechecks input identities after Lake. Its versioned manifest is sorted,
slash-relative, and contains counts, lengths, and SHA-256 values with no timestamp or absolute path.
The manifest symbol is forced into a future `lifecycle` link. A deterministic pre-link receipt
records the manifest hash and sizes/hashes of all four Lean objects, manifest object, and archive.
The current `.lake` tree and fixed executable were not touched in this source-only stage.

The read-only source-pin audit first failed on two authored constants, and both failures were
corrected before the final audit. Raw first failure:
`PIN_MISMATCH Lean:Admission/Checker.lean expected=7be017396c75984cdaff7d7df27f34ea9664a1c059e7751d06047e6a19d77c8a actual=7be017396c75984cdaf3177df27f34ea9664a1c059e7751d06047e6a19d77c8a`.
After that correction it reported `invalid pin length Lean:Admission/Main.lean=63`; the final Main
pin was corrected to the observed 64-character digest. The final read-only audit matched all 10
Lean/project and five Rust inputs; it reported `PASS LEAN_SOURCE_FILES=0` for the obsolete input
list. These were source-audit corrections, not Lean or Rust compiler runs.

Two exploratory read-only probes also failed and were corrected without changing files. The first
looked for the toolchain at the nonexistent project-local
`.lake/packages/lean4/lib/lean` path and PowerShell reported `Cannot find path ... because it does
not exist`; the actual pinned imports were then read from
`C:\Users\neers\.elan\toolchains\leanprover--lean4---v4.33.1\lib\lean`. An unquoted PowerShell
`git rev-parse HEAD^{tree}` probe produced `fatal: ambiguous argument 'dAByAGUAZQA='`; quoting the
Git revision expression returned the expected tree `40d8268880072f23b4c46fc83aee2c5084184083`.

No Lean/Lake build (0), Cargo build (0), Python test (0), source-pinning test (0), or guard packet
(0) ran in this phase. The corrected parser remains uncompiled; the earlier Lake child/outer exit
`1` remains an open failure. The local `lifecycle.exe` remains 6,571,008 bytes / SHA-256
`B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881`; it was not replaced or
repinned.

At this checkpoint, the receipt was pre-link and did not carry a final executable hash; the Rust
entry point did not read the manifest symbol, and the Python adapter checked only the old fixed
executable path/size/digest. The old pin could therefore be accepted after Lean sources changed.
That status is historical and is superseded by the later source-to-runtime provenance closure below:
the current exact old pin remains available only in explicitly nonqualifying `legacy-pinned-v2`
mode, while `source-bound-v1` validates the embedded manifest/report but stays closed until a
reviewed executable/manifest pair exists. The receipt still is not a final-link proof. No formal
release, deployed-link, production, or activation claim follows. `proofSuiteId=null`,
`production_usable=false`, activation `false`, `NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

Final static checks: `git diff --check` exited `0`; the untracked Lean source has zero trailing
whitespace. The final exact-source audit matched all 15 pinned local inputs; all four Lean tool
hashes matched their constants. The final worktree still has the previously dirty Queue source/tests,
adapter, `.lake/`, Experiment, linker command, and native object files; this follow-up introduced no
changes outside its five released paths. Final identities are `build.rs` 32,165 bytes / SHA-256
`BA94E63DFA40090D5A03ED69ECFBD2063B1C9C5F62DAD7E0D5043E7A58F877B1` (before
`A301CF14F60D045D1AF6A7B27657FC7E5389AD849A0B777E0E774BA6136DF2ED`), `CURRENT_TASK.md` SHA-256
`AC58519DFD81D4B2513D2950E8CCFC9DF670BD9DCF941EE86C564DC7DB735027`, and
`docs/LEAN_FORMAL_KERNEL.md` SHA-256
`D4619F25E444F7125CBD70E03DF8028FAA7424F6CCA8F057322E51E53BA9F965` (before
`9D87225D3092D38F99E1169E04780781C9C8F8AD7D650F222BC661E07D70CFDA`). HEAD/tree remain
`b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55` /
`40d8268880072f23b4c46fc83aee2c5084184083`.

## Queue-local admission-to-Composition handoff and GNU target diagnosis — 2026-09-23

### Boundary and source behavior

This Queue source stage implements a transient, bounded Queue-to-local-Composition handoff, not a
financial-owner mapping. It binds the active Profile 12 Queue and Composition configurations,
batch/template/identity, source-admission identity or explicit absence, accepted proof/source
attestation, terminal receipt identity and digest, attempt and 101-unit reservation, exact Queue
event sequence/digests, retry policy, and exactly 100 ordered Queue operation refs. Each Queue
operation ref is also the correlation ID for its local Composition outbox row. The independent
decoder reconstructs these facts from the same active SQLite transaction, rejects malformed,
mismatched, duplicate, stale, or replayed frames, and returns the jobs consumed by the existing
Composition writer.

On accepted completion, Queue terminal state and the 100 local Composition transactions, events,
and outbox rows use the same SQLite connection and transaction. Validation, writer, or pre-commit
failure follows the existing rollback path. The capacity guard requires room for one exact 100-job
batch at construction and before claim; a full outbox blocks before lease/verifier reservation and
returns state_outbox_capacity. Permitted expiry housekeeping may commit, while the selected queued
batch, attempt, reservation, and volatile handoff stay intact. The frame is transient and adds no
schema.

Startup recovery remains scoped to nonterminal AWAITING_HANDOFF, QUEUED, and LEASED batches and
closes their volatile handoffs. A durably committed VERIFIED batch is terminal and is not
reprocessed by that recovery loop. The existing exact post-commit duplicate path reads/checks the
durable Queue result and relies on Composition idempotency checks; it does not re-encode the
handoff. Separate duplicate-after-restart tests were not selected in the finite direct packet, so
that path is code-reviewed here but was not newly verified by that packet.

The Driver correction is material: Queue refs are Queue-owned operation identities, and the
evidence does not show that their use as local Composition correlation IDs violates P12. Nothing
in this handoff maps those refs to a financial owner's population, obligation, or member IDs. No
separately owned financial State transaction or acceptance receipt is implemented or claimed. A
versioned cross-owner mapping receipt, including identity authority, retries, recovery,
uniqueness/replay rules, and transaction boundary, remains a proposal pending financial-owner
review.

### Guarded packet and raw result

The finite packet began and ended at HEAD
b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55, tree
40d8268880072f23b4c46fc83aee2c5084184083. The root AGENTS and WORKSPACE_MAP hashes were
7F2826ECE69651C6AC12B58051EE25AFB4A3993EA46140813B4B6EBD46F549DB and
829B762766EF0B3D7549C5908B13E3D377819437276478025147554ADC015F89. The v4 guard
work/pq-wide-seed-native-20260913/build-filter-native/run_guarded_v4.ps1 was 16,463 bytes /
SHA-256 57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB.

Fresh preflight free bytes were 4,565,090,304 against the required 2,190,433,321-byte physical
floor. The guard observed 5,153,095,680 bytes before launch, 21 live samples, minimum free bytes
4,921,876,480, peak working set 315,392,000 bytes, peak private bytes 364,847,104, and maximum
observed process count 11. The 2 GB process-tree cap waiver was active; the physical-free floor
remained enforced. Guard self-tests reported exit7=7 and exit0=0. Cleanup was PASS, the mutex was
RELEASED, and post-check reported mutex ABSENT, relevant process count 0, and free bytes
5,151,735,808.

The staged source mirror reported 150 files / 25,328,190 bytes and identity PASS, excluding Rust
target and local native object outputs. The exact checked command was:

    cargo check --offline --locked --release --target x86_64-pc-windows-gnu --bin lifecycle

Cargo exited 101. The same finite packet ran these seven selected methods, all passing:

    tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_caller_cannot_supply_executable_path_or_pin
    tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_lifecycle_provenance_protocol_rejects_unreviewed_or_mismatched_identity
    tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_legacy_mode_is_exactly_pinned_and_source_mode_never_falls_back
    tests.test_minimal_clearance_lifecycle_adapter.LifecycleAdapterTests.test_unreviewed_lifecycle_provenance_fails_before_response_decode_without_mutation
    tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_state_outbox_requires_room_for_one_exact_batch
    tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_state_outbox_capacity_blocks_claim_before_verifier_reservation
    tests.test_minimal_clearance_verification_queue.QueueV12Tests.test_versioned_admission_state_handoff_binds_identity_and_rejects_replay

Focused stdout log: 293 bytes / SHA-256
DF94421FAFC20CC87943F682F3BBE969939C7E236606648C02C2E51E24F6B739. Complete contents:

    STAGED_SOURCE_COPY files=150 bytes=25328190 identity=PASS target_and_local_native_objects=EXCLUDED
    CARGO_COMMAND=cargo check --offline --locked --release --target x86_64-pc-windows-gnu --bin lifecycle
    CARGO_CHECK_EXIT=101
    FOCUSED_TEST_COUNT=7
    FOCUSED_TEST_EXIT=0
    TARGETED_PHASE_EXIT=101

Focused stderr log: 760 bytes / SHA-256
593ED3B14094DB7EBB1593BA01CA396F582A4D23315205A037394F52905FDA36. Complete contents,
including the failure and unittest summary:

       Compiling version_check v0.9.5
       Compiling typenum v1.20.1
       Compiling cfg-if v1.0.4
       Compiling cpufeatures v0.2.17
    error[E0463]: can't find crate for `core`
      |
      = note: the `x86_64-pc-windows-gnu` target may not be installed
      = help: consider downloading the target with `rustup target add x86_64-pc-windows-gnu`

    For more information about this error, try `rustc --explain E0463`.
    error: could not compile `cfg-if` (lib) due to 1 previous error
    warning: build failed, waiting for other jobs to finish...
    error: could not compile `cpufeatures` (lib) due to 1 previous error
    error: could not compile `typenum` (lib) due to 1 previous error
    .......
    ----------------------------------------------------------------------
    Ran 7 tests in 2.391s

    OK

The guard's outer exit was 1 because the targeted phase propagated Cargo exit 101. Tests completed
despite the Cargo failure because the child script proceeded to the explicitly selected methods.
The exact test invocation string was not included in the retained child stdout/stderr; method
identities and the seven-test result above are the retained selection evidence. The other 12
adapter methods and 34 Queue methods (46 total) were not invoked because they were outside this
finite direct packet. No unittest skip was reported. No build, test, compiler, target installation,
or guarded invocation followed the lane handoff to State.

### Read-only toolchain diagnosis and build disposition

The E0463 output alone suggests a missing target. Read-only probes distinguish two installed
toolchains. The unqualified rustup proxy resolves rustc to
C:\Users\neers\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin\rustc.exe, whose GNU
target libdir has no core rlib. build.rs instead pins
C:\Users\neers\.rustup\toolchains\1.96.0-x86_64-pc-windows-msvc\bin\rustc.exe, SHA-256
ACB138286BBE20C6CF3EC39A7E0A68C3FAB0CD949BAA2912CF466514D0D531AB. rustup component list for
that exact toolchain reports rust-std-x86_64-pc-windows-gnu installed. Its GNU target manifest
is 4,685 bytes / SHA-256
3E18BBB8B5C6AD86B8FACEEFD9AC4FB934E857DD546B82216A084546F0EC1CBE, and all 60 listed files are
present. Recomputing build.rs's role/length/content binding over the manifest and all 60 records
produced 7fc52762b8d5098e5283ffa754d30cb8fab4ff1027118ef1e8ae2f83d5ec094b, exactly matching
the source pin. The pinned rustc reports a GNU target libdir containing libcore. No target
installation is needed in that pinned toolchain.

This diagnosis was read-only and did not compile. If a direct lane is released after the current
owner lane, the next Cargo check should explicitly select the pinned toolchain:

    rustup run 1.96.0-x86_64-pc-windows-msvc cargo check --offline --locked --release --target x86_64-pc-windows-gnu --bin lifecycle

Cargo.lock, Cargo.toml, and .cargo/config.toml hashes match build.rs pins:
71A0C3F6903563C64A5C6A2C86433B32D448EBCF05C61ACD9B126F5BE28B9F45,
F2482B21D1CFFCE02766460333AF4FE0E3CBEEA20D4BE04C523868E6CAFBE9D5, and
385D15C7142267A1FDEE1CDA6AB13D41966B2E9557084828922F4A4EE3644E81. Configuration fixes the
x86_64-pc-windows-gnu target, Lean clang linker, link-self-contained=no, and panic=abort. build.rs
requires the MSVC host, GNU target, release profile, optimization level 3, no debug info, that
exact compiler path, and the matching GNU target binding.

The configured clang reports target x86_64-w64-windows-gnu. build.rs compiles native_boundary.c
and the embedded-manifest C object for x86_64-w64-windows-gnu and verifies the native object
hash. Its explicit ordered link args use GNU -Wl options and GNU/Lean static archives. Read-only
PATH probes found no ld.exe, ld.lld.exe, lld.exe, lld-link.exe, rust-lld.exe, or
x86_64-w64-mingw32-gcc. The Lean toolchain contains
C:\Users\neers\.elan\toolchains\leanprover--lean4---v4.33.1\bin\ld.lld.exe, but that file
is not on PATH; clang -print-prog-name=ld and clang -print-prog-name=ld.lld each returned bare
ld. Current configuration does not demonstrate selection of the bundled LLD, and the subordinate
linker identity is not a manifest input. Thus the pinned Rust target is available for a source
check, while a final GNU executable link remains fail-closed unsupported. A linker-selection
mechanism and exact linker hash require review and inclusion before a future final-link run.

Switching to x86_64-pc-windows-msvc would violate the fixed GNU target and target-standard binding,
change the C/Rust ABI/runtime and ordered GNU link arguments, change the embedded manifest, and
produce a different executable. Cargo check is not final-link evidence. The build script does not
attest every Cargo-produced final-link input, and live-path replacement/race limitations remain.
The lifecycle.exe pin remains 6,571,008 bytes / SHA-256
B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881. The adapter remains in
legacy-pinned-v2 mode, the reviewed manifest digest is unset, and source-bound mode remains
closed. Flags remain proofSuiteId=null, production_usable=false, activation=false,
NOT_QUALIFIED/INACTIVE/UNSELECTED.

### Source checkpoint

Queue source/test identities:

    app/minimal_clearance_verification_queue.py 222219 bytes SHA-256 579DF0201FC1443926EE1D9FF7D61573B512B37473D4EE8B67E7FD726E2482B2
    app/minimal_clearance_verification_queue_independent.py 138026 bytes SHA-256 8E8AD43BA0440E20FD6EA952A2EF5E052A30D5A4048CB5F1CE5322E94FF7973F
    tests/test_minimal_clearance_verification_queue.py 97305 bytes SHA-256 F256A7254BE8DA537E55015B4A5503F59CBFA91E1B2903106B8A831C4552277C

HEAD/tree remain b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55 /
40d8268880072f23b4c46fc83aee2c5084184083. No file was staged or committed. Existing dirty and
untracked Queue, Lifecycle, Lean, .lake, linker-command, and native-object paths were preserved.
The retained executable, .lake, target tree, guard source, raw logs, operations policy,
financial-owned paths, and archives were not edited.

## Queue issue indeterminacy and adapter-edge review — source-only — 2026-09-23

The active checkout remained at HEAD/tree
b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55 /
40d8268880072f23b4c46fc83aee2c5084184083. The prior dirty and untracked paths remain preserved;
nothing was staged or committed. This continuation changed the protected Queue module, its focused
test module, one existing Profile12 issue-commit test expectation, and the three status/contract
records named in the assignment.

The Queue source's issue path uses one `BEGIN IMMEDIATE` transaction under the existing Queue owner.
It independently revalidates before RNG, reserves one 101-unit proof budget and one U issuance,
generates 100 unique 32-byte Queue operation refs, and writes the batch, 100 ordered member rows,
one attempt, one `BATCH_ISSUED` event, and accounting together. The member schema enforces
`PRIMARY KEY(batch_id,batch_position)`, `UNIQUE(operation_ref)`, and `UNIQUE(admission_seq)`;
`_insert_batch` assigns positions 0–99 and contiguous admission sequences. No cross-owner financial
identity mapping is present or claimed.

One ambiguity was corrected in source. `issue_batch` now sets a commit-attempt marker immediately
before `connection.commit()` and raises `QueueIndeterminateError("issue_result_indeterminate")`
for ordinary exceptions after that point, including a post-commit hook or connection-close failure.
Before that point the existing transaction exception handler rolls back. This makes caller-visible
uncertainty explicit; it does not make issue creation idempotent. The method has no request identity
or lookup path, so a lost return cannot safely be inferred from the template, and blindly issuing
again creates another batch and reservation. The durable row stays `AWAITING_HANDOFF` without a
caller-held batch object, occupying capacity until validity expiry or startup recovery moves it to
`HELD`; the reservation is not refunded. The issue retry contract therefore remains limited:
pre-commit rollback permits a fresh issue; same-request recovery after an ambiguous commit is
unsupported. This distinction does not change the separate exact post-commit readback path for a
known terminal Queue/State result.

Three focused test methods were added but not executed:

- `test_issue_precommit_failure_rolls_back_before_fresh_issue` checks a pre-commit fault leaves all
  issue rows/counters unchanged, then checks one successful exact-100 issue and 101-unit reservation.
- `test_issue_postcommit_failure_is_indeterminate_and_burns_one_reservation` checks the typed error
  and independently verified durable rows after the injected post-commit fault.
- `test_issue_concurrent_writers_serialize_exact_100_member_reservations` checks that two concurrent
  issue calls serialize into two exact-100 batches with contiguous member sequences and cumulative
  reservations 0→101→202.
- `tests/test_direct_mask_state_profile12.py::test_issue_commit_boundaries_preserve_rollback_and_burn_postcommit_reservation`
  now expects `QueueIndeterminateError("issue_result_indeterminate")` for the post-commit fault;
  its durable one-reservation assertions remain unchanged.

The existing `test_lifecycle_sidecar_failures_rollback_and_allow_fresh_retry` was strengthened to
check that the single 101-unit reservation remains unchanged through submit rollback, fresh handoff,
claim rollback, and the successful claim retry. None of these tests have run in this continuation.

Current source identities after the edit:

    app/minimal_clearance_verification_queue.py 222694 bytes SHA-256 A726430F340F58EACE6256125D27062DB7ADA772D25BAB98A50BEC4553E20918
    tests/test_minimal_clearance_verification_queue.py 108571 bytes SHA-256 151071C84C794EF106513CCE1EB583EE3D02C1E85BB9E088A880FFBE0643D282
    tests/test_direct_mask_state_profile12.py 126802 bytes SHA-256 04D360EE7A67A7373D1E1A9D6569AB9E4A978B1EEB27371CC9CC1985E8D57D87

Cancellation remains unsupported. Search across the Queue module, independent verifier, Queue tests,
Lifecycle Lean source, and adapter found no `cancel` symbol or test. `Lifecycle.lean:335–338`
defines only `submitHandoff` and `claimNextBatch`; `lifecycleIssueEvent` is an initial event relation,
not a transition constructor. Neither the frozen Queue contract nor the accepted 68-case Lifecycle
evidence defines which in-flight states can be canceled, how an active source/verifier process is
stopped, or the durable event/result identity. No cancellation API or Lifecycle source change was
made. Expiry, HELD, startup recovery, and lease expiry remain existing Queue-owned host outcomes.
The handoff's mutable buffer has no per-stream synchronization; `_process_one_batch` starts the
verifier after committing its launch reservation, and `VerifierPort` has no cancellation method.
Concurrently closing the handoff would race its reads and would not define how an active external
process is stopped. The accepted Lifecycle source commit `71438a3fbf5a87bb86f03d39752c4f9e391727da`
and its 68-case evidence were not changed or rerun.

Source review confirms the supported adapter edges remain the successful `submitHandoff` and
`claimNextBatch` transitions. The adapter is still in `legacy-pinned-v2`; source-bound mode remains
closed with no reviewed manifest digest. The exact old executable is unchanged. GNU final linking
remains unsupported because the configured Clang path does not select an attested linker and the
final Cargo link inputs remain unbound; no fallback, target change, or tool installation was made.

The Security-owned guarded lane was not directly released in this continuation. No tests (count 3
new methods invoked: 0), build, compiler, checker, or guarded command ran after the source change.
`git diff --check` was also not run because the lane handoff has not occurred. Prior guarded failures
and their raw evidence remain unchanged. Current claims remain `proofSuiteId=null`,
`production_usable=false`, activation `false`, `NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

## Queue verified Profile12 receipt — trust-boundary evidence and STOP — 2026-09-23

The latest Founder increment asks for a versioned canonical receipt over verified Profile12 jobs,
including exact ordered refs, relation/profile/source and manifest identity, attempt/reservation/lease
and terminal state, accepted proof/attestation, and issuer/revocation/validity bindings. It keeps
schema 13/Profile 12, exact-100 Queue/Composition application in the same transaction, and the
101-unit no-refund reservation unchanged. A financial-owner ref-to-obligation/hospital/amount/State
mapping and separate-store inbox/outbox remain explicitly unintegrated pending a State-owned
versioned contract.

**STOP: the present Queue boundary does not supply the issuer, revocation, or source-manifest facts
needed for independent receipt authentication.** Source evidence from the current checkout:

- `BatchVerifierResult` and its strict mapping parser contain exactly
  `proof_accepted`, `source_authenticated`, `proof_context`, `public_coin`, `batch_root`,
  `source_auth_profile`, `source_key_epoch`, `result_code`, and `qualification_flags`. There is no
  issuer ID, key fingerprint, revocation root/version, or manifest digest.
- `SourceAuthVerifierConfig` accepts an ML-DSA public key and checks its byte length. The adapter
  returns only the Queue result fields above; it does not return a trusted key identity or
  revocation statement. The current Queue profile string is the fixed unqualified
  `BLIND-MLDSA87-SOURCE-AUTH-DIRECT-MASK-V1-UNQUALIFIED`, and the epoch is not a revocation
  snapshot.
- `approved_source_registry_root` is nullable template data. The current Queue/source-auth code
  does not establish that it names the signing issuer or a current revocation snapshot.
- `queue_source_admissions` persists profile/config digests, identity-profile name, executable
  size/hash, request digest, and source status. Its independently recomputed configuration digest
  is over identity-profile name, executable size/hash, and retry limit. There is no source-manifest
  digest. `queue_results` persists the existing basic receipt, accepted booleans, source profile,
  key epoch, result code, flags, time, attempt, and error; it does not persist issuer or revocation
  facts.
- A literal word-boundary search for `issuer`, `revocation`, or `revoked` across the Queue writer,
  independent verifier, source-auth adapter, focused Queue tests, and Queue protocol doc produced
  no matches (`rg` exit 1, empty output). This is a source inventory observation, not a security
  proof.

Therefore a receipt that labels `source_auth_profile` as issuer, the optional registry root as
revocation state, or `source_configuration_digest` as a manifest would make unsupported claims.
The present writable scope also excludes the source-auth adapter/runtime path that would need to
supply a trusted issuer fingerprint and authenticated revocation evidence to Queue. This is the
explicit trust-critical STOP; no implementation or test was modified for this increment.

The existing lease boundary is partly recoverable without exposing its secret token: claim sequence
is assigned as the next transition sequence, the `VERIFICATION_STARTED` event uses that sequence
and lease start time, and configured lease expiry is start plus 60 seconds. The live lease row is
deleted at terminal completion. A future receipt may bind the durable claim event sequence/time and
recomputed expiry, but must not export the raw lease token or claim that the deleted row remains
present.

The existing Queue/Composition transaction remains the supported local boundary: completion writes
terminal Queue state and applies exactly 100 verified jobs before one commit. This does not imply
an independently owned financial State acceptance. The direct-mask source profile remains
unqualified; no proof-suite, production, PHI, payment, or activation claim is made.

Checkpoint before the doc-only STOP record: HEAD/tree
`b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55` /
`40d8268880072f23b4c46fc83aee2c5084184083`. Queue source identities were writer 227,531 bytes /
SHA-256 `FD55BABFA9266A87BB859F0129E2E63BE50A575D1F3BF8E722B6A16C4CC6C10E`, independent verifier
145,820 bytes / SHA-256 `3101847DE2681A105A6E9521344B332649CF76BF33B0ED082C322C3708D662CF`, and focused Queue
tests 114,779 bytes / SHA-256 `A8BAC4D9E525ED61D6404EC3BDB2BF80D69B3C86361032C1EE01DEF8AC6A6493`. The supplied
recovery-snapshot manifest was read-only hash-checked as
`5BED13558A23898CACD66B579CBCB50A2C46915157106117D8B8EA75B453286F`; it was not restored or
modified. At task entry the worktree had 10 tracked modifications, 9 untracked paths, and no staged
changes; all were preserved. No test, checker, compiler, build, guard, or `git diff --check` ran.

Next bounded action: obtain an owner-approved trusted source-attestation contract carrying the
source manifest digest, issuer key identity, and revocation snapshot semantics into the Queue
verifier boundary. Then implement the receipt only in the authorized Queue files, independently
recompute it, and add only Queue-specific fault/retry tests while reusing Driver-owned acceptance
fixtures. Run no guarded command until Engine and State directly release the finite lane and a fresh
preflight passes the fixed v4 guard and floor above. External financial mapping and separate-store
inbox/outbox still require State's own versioned contract.
### Concurrent Driver-owned instruction override — 2026-09-23

Driver added the untracked `AGENTS.override.md` at this checkout root because the full `AGENTS.md`
is 57,858 bytes, above Codex's default 32-KiB project-instruction limit. Preserve the override
without editing it; its observed identity is 2,121 bytes / SHA-256
`EBE04D834B4A0800D726E96E34541FB5EC1DF2A90251217EA6141A49FA775F6B`. Do not treat this path as
release-selected until path policy is reviewed. This concurrent instruction-loading work does not
change Queue source ownership or resolve the issuer/revocation/manifest protocol gap.

## Queue transaction clock and lease-expiry fence — source-only, unverified — 2026-09-23

This separate clock correction was layered onto the existing dirty Queue source/test work. HEAD/tree
remain `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55` /
`40d8268880072f23b4c46fc83aee2c5084184083`; nothing was staged or committed. The pre-existing
modified Runtime, independent Queue verifier, Lean authority, Rust build script, direct-mask and
Runtime tests, plus all untracked lifecycle/Lean/linker/native artifacts and the local instruction
override, were preserved. This change touched only the Queue writer, its focused test module, and
the current-task/state records.

The writer pairs a post-lock wall-clock sample with a process-local monotonic nanosecond anchor.
Immediately before commit, issue, handoff submission, claim, verifier-launch reservation, and
terminal VERIFIED/REJECTED completion check the fresh wall sample and a ceiling-rounded monotonic
elapsed-time projection. A per-batch event append also rejects an `at_ms` earlier than the previous
event; the independent verifier already enforces this ordering and the existing lease/terminal
timestamp bindings. `_QueueWorkItem` carries the claim's volatile monotonic deadline, with no schema,
wire, or persisted monotonic field. Startup recovery still holds all nonterminal rows, so a process
restart never resumes a lease using a lost monotonic anchor.

On an issue fence expiry, the issue transaction rolls back before consuming the 101-unit reservation.
On handoff expiry, staged QUEUED state rolls back and the durable batch is held. A claim fence expiry
rolls back the lease before returning work; a post-commit expiry is held before the caller can launch
the verifier. A verifier-start fence failure leaves the launch reservation uncommitted and routes to
the existing HELD completion. If the final completion fence expires, the full Queue/Composition
transaction rolls back, including all 100 applied jobs and outbox rows, then the Queue records HELD
with the corresponding validity/lease error. Exact keyed issue retries still resolve the already
durable batch without a new time/expiry check or reservation.

The focused regression additions are:

- `test_issue_expiry_at_commit_fence_rolls_back_reservation`
- `test_issue_commit_fence_uses_monotonic_elapsed_when_wall_clock_stalls`
- `test_exact_issue_retry_reads_durable_batch_after_validity_expires`
- `test_queue_event_clock_regression_fails_closed`
- `test_handoff_commit_fence_holds_batch_when_validity_expires`
- `test_claim_commit_fence_holds_batch_when_validity_expires`
- `test_lease_expiry_at_verifier_start_fence_prevents_verifier_launch`
- `test_completion_expiry_at_commit_fence_rolls_back_composition`

`test_claim_clock_waits_for_sqlite_write_transaction` was updated to account for the post-lock
sample, the final pre-COMMIT fence, and the post-commit claim check. No Queue tests were run in this
continuation: the focused module `tests.test_minimal_clearance_verification_queue` remains unrun
(one module skipped, zero test methods executed) because the direct Engine then State lane handoff
and fresh target-specific v4 preflight have not arrived. `git diff --check` was not run (one checker
skipped for the same gate); no build, compiler, or other checker ran.

Current source identities are `app/minimal_clearance_verification_queue.py` 238,919 bytes / SHA-256
`C76143B380DC5DF4BA60CA514FB5E9B0A7C9A72269E5AEBECE49B1FC79F5E453` and
`tests/test_minimal_clearance_verification_queue.py` 129,439 bytes / SHA-256
`2B5F2939590646DE015BF2E234AEE12F24214CB2A64A57254C0D8F26F07B90A2`. `CURRENT_TASK.md` is
121,685 bytes / SHA-256
`68CFFBDD99A59A3B6A92BF6B743CCC72255B9A1140717EEC0674B24310FD319E` after its append.

The final fence is the last enforceable local admission check before calling SQLite COMMIT; SQLite
does not provide an atomic callback to sample a clock at the durable commit instant. A commit that
blocks or completes after the fence can therefore exceed a deadline, and this source change makes no
commit-time or external trusted-time claim. `SystemQueueClock` remains local machine wall time,
expressed as epoch milliseconds with integer nanosecond conversion. Schema 13/Profile 12, exact-100
atomicity, no-refund accounting, non-`CLEAR` behavior, and all nonactivation flags remain unchanged.
The earlier issuer/revocation/manifest receipt-authority STOP remains unresolved and untouched.

## Queue submitHandoff Lean decision consumption — source-only, unverified — 2026-09-23

Checkpoint remained HEAD b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55, tree
40d8268880072f23b4c46fc83aee2c5084184083; no staging or commit occurred. Before this increment,
the actual worktree had 10 modified tracked paths and 10 untracked entries. All were preserved.
This increment changed only:
- app/minimal_clearance_verification_queue.py
- app/minimal_clearance_lifecycle_adapter.py
- tests/test_minimal_clearance_verification_queue.py
- tests/test_minimal_clearance_lifecycle_adapter.py
- CURRENT_TASK.md
- STATE.md

The operation selected was successful submitHandoff, whose existing Lean source relation in
semantic_kernel/lean/Admission/Lifecycle.lean (with the bounded executable transport in
Admission/LifecycleKernel.lean) fully specifies the legal state delta and event without a
schema or theorem change. The accepted transition uses the existing Queue-sampled now_ms; it
moves the selected batch from AWAITING_HANDOFF to QUEUED, sets next-eligible/updated timestamps,
advances the transition sequence once, marks the handoff attached, and preserves the reservation,
accounting, identity, source/verifier facts, and unrelated global lease count. Its output event is
the schema-13 HANDOFF_SUBMITTED event bound to that batch and sequence. Issue creation has no
Lifecycle operation; lifecycleIssueEvent remains only the initial snapshot event.

For this edge, the adapter no longer constructs a Python success plan or compares Lean to one.
It independently reconstructs the active-transaction snapshot, sends the typed version-1 frame to
the pinned executable, binds the response to the exact request echo, decodes the typed after-state
and event, and checks output shape/preservation/event/wire constraints. The Queue consumes the
returned state for its SQL status/timestamp update and the returned event for canonical event
serialization. _append_event still derives the local next sequence, verifies exact serialized
bytes against the Lean event, rejects per-batch time regression, and writes the existing event
digest/root in the same SQLite transaction. The independent verifier and event shape are
unchanged. claimNextBatch continues its Python after-state/event cross-check and its existing
Queue-written mutation; expiry/HELD/recovery remain host-owned.

The same owner lock and BEGIN IMMEDIATE still enclose snapshot reconstruction, Lean invocation,
handoff staging, row update, event/root update, and commit. An unavailable, malformed, mismatched,
or timed-out sidecar fails before the successful mutation and rolls the transaction back; the outer
failure path closes/wipes the supplied handoff. The existing pre-commit clock fence still rolls
back a late submission. A failure after durable commit cannot undo the QUEUED row; startup recovery
holds nonterminal work and requires fresh handoff. There is no change to issue retries, the single
101-unit no-refund reservation, source admission, exact-100 Composition/outbox application,
schema 13/Profile 12, non-CLEAR behavior, or nonactivation.

The adapter fixes the executable path and expected identity at size 6,571,008 bytes / SHA-256
B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881; wire version is 1 and
runtime mode is legacy-pinned-v2. The source-manifest digest remains unset, so this is an exact
binary-byte pin, not a source-to-binary provenance or formal-release claim. No runtime-wide
production authority, proof, payment, or activation claim is made.

Post-edit source identities:
- app/minimal_clearance_verification_queue.py: 241,976 bytes,
  SHA-256 DF143927439D736A445AE38E02008358A4521478B2CA2535C321AD73628477DB
- app/minimal_clearance_lifecycle_adapter.py: 40,745 bytes,
  SHA-256 8BBA4B995C91FE88AFDD48909B29CF0F4C1FBDC94BFB1D6FDF5BB19D27628D24
- tests/test_minimal_clearance_verification_queue.py: 130,422 bytes,
  SHA-256 0DFD543BC6D1398207FD0C2169D784DA5DF8BDF2550108447D8214D9BF88B113
- tests/test_minimal_clearance_lifecycle_adapter.py: 42,230 bytes,
  SHA-256 2D06DAEEAFDEF7A085FBC0E3A67D967BD5F046DD2B8BDFDBF88FA5C1DDDE4312

The focused changes update test_submit_round_trip_returns_lean_decision_and_preserves_transaction
to reject output state/event drift, reservation/counter changes, and use of the Python claim planner;
test_lifecycle_sidecar_submit_claim_event_bytes_and_independent_verify now records the returned
typed decisions and checks the persisted submit row/event against Lean output plus independent
database verification. Existing rollback/fresh-retry and 101-unit reservation assertions remain.

No test, build, compiler, checker, guarded run, or git diff --check ran in this source-only
continuation. Skipped: Queue test module 1, Lifecycle adapter test module 1, git diff --check
1; test methods executed 0. The reason is unchanged: direct Engine then State finite-lane handoff,
fresh target-specific v4 preflight, the pinned guard, and required floor have not been received.
The existing dirty docs/LEAN_FORMAL_KERNEL.md entry was not edited under this scope and still
contains the earlier host-plan description for both success edges; this record supersedes that
implementation description for submitHandoff only. A doc reconciliation requires an authorized
scope.

Git line-ending warning correction: the first post-append Git diff emitted those two warnings twice each. Byte inspection found exactly 2 CRLF sequences in each appended record; I removed only those 4 CR bytes, preserving all text. Final Git diff/status read was warning-free.

## Queue claimNextBatch Lean decision consumption — source-only, unverified — 2026-09-23

The source-only phase began at HEAD `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55`, tree
`40d8268880072f23b4c46fc83aee2c5084184083`. Before this increment the worktree had 10 modified
tracked paths and 10 untracked entries, including prior Queue/clock work, the submitHandoff
integration, runtime/independent-checker edits, Lean/Rust work, generated artifacts, and
`AGENTS.override.md`. The increment preserved them and changed only:

- `app/minimal_clearance_verification_queue.py`
- `app/minimal_clearance_lifecycle_adapter.py`
- `tests/test_minimal_clearance_verification_queue.py`
- `tests/test_minimal_clearance_lifecycle_adapter.py`
- `docs/LEAN_FORMAL_KERNEL.md`
- `CURRENT_TASK.md`
- `STATE.md`

No stage or commit was created. Lean, Rust/build pins, binaries, owner modules, and other protected
paths were not edited.

`semantic_kernel/lean/Admission/Lifecycle.lean` remains unchanged. Its `lifecycleClaimPrecondition`,
`lifecycleClaimStateRelation`, `lifecycleClaimEventRelation`, `lifecycleStep`, and
`lifecycleStep_sound` at source lines 516–722 define the selected claim's legal state and event.
The relation preserves the source/verifier/terminal values, identity/configuration, eligibility and
validity times, attached handoff, reservation/accounting, proof-attempt count, and source-key epoch.
It sets LEASED, `updated_ms=now_ms`, attempt and global/local live-lease counts to one,
`leaseExpiresMs=now_ms+leaseDurationMs`, and both claim and transition sequence to the previous
transition sequence plus one. The event relation binds the schema-13 `VERIFICATION_STARTED` event
to that sequence/batch, attempt one, `now_ms`, 100 members, and the exact reservation pair. This
fully defines the logical selected-row decision/event needed here. It does not take over Queue
scheduling, capacity, actual lease-table validation, RNG/token custody, HMAC fencing, transaction,
clock, commit, event-root hashing, expiry, HELD, recovery, or external truth.

The adapter removes `_host_claim_plan`; claim now follows the same result-consumption pattern as
submit. It reconstructs the supplied in-transaction snapshot read-only, binds the response to the
exact encoded request echo, checks claim result types, changed fields, preserved fields (including
eligibility and handoff), exact event fields/reservation pair, and canonical Queue encoding, then
returns the decoded Lean state/event. The Queue checks the typed transition and required claim
shape before generating the volatile token. It uses Lean's result for metadata live-lease count,
batch status/attempt/time, lease attempt/sequence/start/expiry, token-HMAC bindings, work-item
fields, and `_append_lifecycle_event`. Queue's event append still assigns and verifies local
sequence/bytes and updates its digest/root in the same transaction. The existing oldest-eligible
selection, Composition capacity check for all 100 jobs, empty global lease checks, single
101-unit no-refund reservation, BEGIN IMMEDIATE, owner lock, transaction clock, pre-commit and
post-commit fences, rollback/HELD/recovery behavior, schema 13, Profile 12, and independent event
chain verification remain in place.

Focused adapter source coverage now checks there is no Python claim-plan symbol, rejects mismatched
claim state/event fields, and mutates the actual sidecar response echo to confirm rejection.
`test_lifecycle_sidecar_submit_claim_event_bytes_and_independent_verify` captures the returned
claim decision and binds it to the committed batch row, metadata count, lease fields, returned work
item, and canonical stored event before the existing independent database verifier runs. These
source assertions have not been executed in this phase.

Final source identities at the end of edits:

- `app/minimal_clearance_verification_queue.py`: 243,643 bytes,
  SHA-256 `FE57DF433AA2BEDDFE31F1E189C97B674B7A73BA4E86D42C7BD3497E3CBA7140`
- `app/minimal_clearance_lifecycle_adapter.py`: 41,598 bytes,
  SHA-256 `C6D9EC2BDCA2E1A4FE9C78F164FB84DDFF93614658B67688F4BA40200D9404E9`
- `tests/test_minimal_clearance_verification_queue.py`: 131,814 bytes,
  SHA-256 `EBC96245BE1E7D7728F5D800F772DEFBCA0EF6A90248464FC076AB1F0A5D9290`
- `tests/test_minimal_clearance_lifecycle_adapter.py`: 45,622 bytes,
  SHA-256 `6872939BB8A65AE916FF994CC3957033C60FD2E67FBE388E0238A22568760154`
- `docs/LEAN_FORMAL_KERNEL.md`: 40,921 bytes,
  SHA-256 `927D7A832301C8A937777C5550D401482604CDBFF08E6224B190795C811EA404`
- `CURRENT_TASK.md`: 128,893 bytes,
  SHA-256 `B9CB80261BE82E41EACC0E858A431FE5011022DC03281E126CC5FB95050AA5F3`

No test, build, compiler, checker, guarded command, or `git diff --check` ran. Skipped gates: Queue
test module 1, Lifecycle adapter test module 1, and `git diff --check` 1; executed test methods 0.
All are still gated on direct Engine then State finite-lane handoff, fresh target-specific
preflight, guard SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`, and the
2,190,433,321-byte physical-free floor. No build/provenance/formal-release/deployment/production
or activation claim follows. The legacy executable pin remains 6,571,008 bytes /
`B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881`, runtime mode remains
`legacy-pinned-v2`, and source-manifest digest remains unset.

Discovery diagnostics during this source-only work were non-mutating: a read attempted in the
default non-repository directory reported `Cannot find path`; one PowerShell metadata command
reported `An empty pipe element is not allowed`; and one unquoted attachment path with spaces
produced a positional-parameter error. Each was corrected by switching to the recorded checkout,
separating the metadata expression, or quoting the path, then the intended read succeeded. One
documentation patch attempt reported `apply_patch verification failed: Failed to find expected
lines`; it made no change and was reapplied against the exact current context. One combined source
read was truncated by the tool output limit and was followed by smaller targeted reads. No source
failure, runtime warning, or verifier output was generated because no runtime gate ran.

## Queue Lifecycle decision consumption — guarded evidence, blocker, and handoff — 2026-09-24

### Repository and change identity

Checkout: C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\lean-queue-20260913. HEAD b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55; tree 40d8268880072f23b4c46fc83aee2c5084184083. No stage or commit. The worktree still has 10 modified tracked paths and 10 untracked entries; inherited paths were preserved. For this verification increment, Queue and adapter production sources were not edited. The only test edit changed test_exact_issue_retry_reads_durable_batch_after_validity_expires from bytes(reversed(range(64))) to bytes(reversed(range(32))) because issue_batch_v1 and the independent verifier require exactly 32 opaque request-ID bytes. The affected test then passed. Other inherited dirty files remain unchanged.

### Guarded focused verification

The selected 3,500,000,000-byte target start floor is 1,309,566,679 above the 2,190,433,321-byte hard floor. It is appropriate for the bounded Python/SQLite suite, not a Lean/Rust compilation. Earlier guarded Queue evidence had minimum free memory at least 4,439,969,792 bytes; the focused run observed 4,406,386,688 bytes minimum, 150,282,240 peak working set, and 130,654,208 peak private. Guard SHA-256: 57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB.

Focused preflight 2026-09-24T06:57:22.6111504Z: 4,544,131,072 bytes free; correct Queue root/cwd; exact guard hash; mutex absent; zero competing guard/compiler/Queue-test processes; zero log collisions. The guard itself reported child exit checks exit7=7 exit0=0, command child exit 0, cleanup PASS, mutex released, 21 samples, and the resource values above. The child command ran git diff --check and py -3.14 -B -m unittest tests.test_minimal_clearance_lifecycle_adapter plus these Queue tests: test_lifecycle_sidecar_submit_claim_event_bytes_and_independent_verify, test_lifecycle_sidecar_failures_rollback_and_allow_fresh_retry, test_claim_clock_waits_for_sqlite_write_transaction, test_claim_commit_fence_holds_batch_when_validity_expires, test_handoff_commit_fence_holds_batch_when_validity_expires, test_lease_expiry_at_verifier_start_fence_prevents_verifier_launch, test_completion_expiry_at_commit_fence_rolls_back_composition, test_exact_100_members_and_one_101_unit_attempt_record, test_accepted_batch_commits_queue_and_all_state_rows_once, test_startup_burns_a_live_session_and_never_resumes_it, and test_versioned_admission_state_handoff_binds_identity_and_rejects_replay.

Raw unittest output: 27 tests in 10.687s; OK. Retained files in C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native:
- guarded-command-queue-lifecycle-decision-focused-20260924-r1.outer.log: 4,619 bytes, SHA-256 E12BA190EFEF097E7B97628637368F696A6C63C5C9F986159590306B1D4137F1.
- matching .stdout.log: 0 bytes, SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.
- matching .stderr.log: 132 bytes, SHA-256 0D8B338CCED7CC98E4187B950A82F6D78C4BB1A966685B6CC3D1F245B88F1F61.

### One broader guarded run — failed

Fresh preflight 2026-09-24T07:02:23.5573466Z reported 4,644,614,144 bytes free, correct Queue root/cwd, exact guard SHA-256, mutex absent, zero competing guard/compiler/Queue-test processes, no log collisions, and all four requested test modules present. The guarded command ran git diff --check followed by py -3.14 -B -m unittest tests.test_minimal_clearance_verification_queue tests.test_minimal_clearance_lifecycle_adapter tests.test_direct_mask_state_profile12 tests.test_minimal_clearance_composition_v2.

Raw result: Ran 122 tests in 71.995s; FAILED (failures=1, errors=5). Guard telemetry: internal PHYSICAL_PREFLIGHT free_bytes=4,626,808,832; 121 live samples; minimum free 4,049,977,344; peak working set 178,900,992; peak private 131,608,576; command child exit 1; cleanup PASS; mutex released. The protected physical floor was not crossed. Logs:
- guarded-command-queue-lifecycle-decision-broad-20260924-r1.outer.log — 17,196 bytes, SHA-256 3E834F60405BED1BEA39C44A05A419B9FAC3568C91F9FF3351BC12D37E7A024F.
- matching .stdout.log — 0 bytes, SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.
- matching .stderr.log — 9,410 bytes, SHA-256 B3271D91F8DFB20E7BFE724B51E0FDFC354B4563FB59A0F7469EF38DB0B2BD6C.

The broad run's Queue failure was test_exact_issue_retry_reads_durable_batch_after_validity_expires: the fixture supplied 64 bytes though the source API's ISSUE_REQUEST_ID_BYTES is 32 (app/minimal_clearance_verification_queue.py:93, 698-700; independent verifier also requires 32). The test-only input was corrected and that case rerun under the guard. Its fresh preflight 2026-09-24T07:07:28.2202537Z reported 4,606,468,096 bytes free, mutex absent, zero relevant processes, and no log collision. The child ran git diff --check and the single test; output Ran 1 test in 0.213s; OK. Guard: child exit 0, cleanup PASS, mutex released, 3 samples, minimum free 4,483,731,456, peak working set 115,601,408, peak private 77,996,032. Logs:
- guarded-command-queue-issue-retry-test-fixture-correction-20260924-r1.outer.log — 2,370 bytes, SHA-256 D13E585B6F3B2A2E5F2320144E699EA005826A82DD722DE1CDB148C0A9FC9299.
- matching .stdout.log — 0 bytes, SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.
- matching .stderr.log — 103 bytes, SHA-256 54BABD813570A327D0E40BC8B1A64903DE4483A65DEE61172BD3131F3F50B12D.

Five broad-run cases were not rerun on the corrected tree:
1. Profile12StateTests.test_hold_at_issue_burns_reservation_without_refund — _hold_batch_locked -> _revalidate_durable_state raised queue_integrity_failed.
2. Profile12StateTests.test_receipt_flags_and_orphan_results_are_closed — same surfaced queue_integrity_failed at _revalidate_durable_state.
3. Profile12StateTests.test_temporal_deadlines_and_terminal_contract_are_exact — same surfaced queue_integrity_failed at _revalidate_durable_state.
4. Profile12StateTests.test_lifecycle_specific_expiry_contract_rejects_coherent_prelease_expiry_recode — issue_batch rejected the already-expired window with QueueConflictError: validity_expired.
5. Profile12StateTests.test_temporal_field_matrix_rejects_backward_malformed_and_out_of_u64_values (field=event) — verifier did not raise the expected timestamp_binding after the test changed persisted event time and recomputed its event chain.

The first three paths call Queue._revalidate_durable_state, whose broad catch at app/minimal_clearance_verification_queue.py:2661-2664 masks the underlying exception; the current raw trace therefore reports only QueueIntegrityError: queue_integrity_failed. The fifth is a trust-critical independent-checker negative mismatch: tests/test_direct_mask_state_profile12.py:1829-1839 expects verify_database to reject the modified event, but it returns. The checker and test are outside this assignment's authorized write scope. This unresolved semantic/checker mismatch triggers the assignment STOP gate. No independent-checker or Direct Mask test change, additional affected-test rerun, or broad-suite rerun was made.

### Executable identity and nonclaims

Actual file semantic_kernel/rust/target/x86_64-pc-windows-gnu/release/lifecycle.exe: 6,571,008 bytes, SHA-256 B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881; it matches the adapter's fixed pin. Adapter runtime mode is legacy-pinned-v2 and _LIFECYCLE_SOURCE_MANIFEST_SHA256 is None (app/minimal_clearance_lifecycle_adapter.py:46-67). The Queue integration tests show the adapter result flows into SQL/event writes in the current transaction, but do not prove that current Lifecycle.lean/LifecycleKernel.lean produced this binary. No source-bound provenance, formal release, deployment, production, payment, PHI, or activation claim is made. The previously recorded LifecycleKernel compiler failure remains open; no build was run in this increment.

Source identities after the test correction:
- app/minimal_clearance_verification_queue.py: 243,643 bytes, FE57DF433AA2BEDDFE31F1E189C97B674B7A73BA4E86D42C7BD3497E3CBA7140.
- app/minimal_clearance_lifecycle_adapter.py: 41,598 bytes, C6D9EC2BDCA2E1A4FE9C78F164FB84DDFF93614658B67688F4BA40200D9404E9.
- tests/test_minimal_clearance_verification_queue.py: 131,814 bytes, 61E69061F43C305A160A91C28CB057C5C57C8EF21C3CF60F199D62287A7B655E.
- tests/test_minimal_clearance_lifecycle_adapter.py: 45,622 bytes, 6872939BB8A65AE916FF994CC3957033C60FD2E67FBE388E0238A22568760154.

Discovery/execution diagnostics, all nonmutating and corrected: the first host process scan falsely counted a read-only PowerShell process consuming an old guard log; no run launched, and a corrected strict scan returned zero. Two PowerShell commands initially failed to parse a catch clause (one post-run reader, one preflight); no file/run mutation resulted and corrected commands succeeded. One instruction read used the wrong parent path ..\AGENTS.md; it was corrected to ..\..\AGENTS.md. No production warning was emitted by the passing focused or affected rerun. The broad unittest failure is fully retained in its stderr log above.

The finite guard lane is released to Driver with the broad failure and provenance blocker open; the shared mutex was released. Status remains synthetic, nonpayment, non-PHI, proofSuiteId=null, production_usable=false, activation=false, NOT_QUALIFIED/INACTIVE/UNSELECTED. A git diff --check after these reporting-document appends was skipped once because the STOP gate had fired; the guarded source/test commands had each run git diff --check before the record append.

## Direct follow-up — Profile12 broad-suite failure closure — 2026-09-24

The direct follow-up supersedes the preceding STOP for the five recorded broad-suite symptoms only. Its writable grant covered the Queue writer, independent checker, Queue test, this one focused Profile12 test, and these task/state records. No Queue or independent-checker source change was required; only `tests/test_direct_mask_state_profile12.py` changed in the implementation scope. Inherited dirty and untracked files were preserved; no staging or commit occurred. The existing edited `docs/LEAN_FORMAL_KERNEL.md` retains the prior STOP text and was not edited because it is outside this follow-up's grant.

### Inner-verifier diagnosis and corrections

A contained guarded wrapper around `_verify_connection` in the three failing `_hold_batch_locked` tests captured `IndependentQueueError('database_pragmas')` at `app/minimal_clearance_verification_queue_independent.py:1547`. `_revalidate_durable_state` at `app/minimal_clearance_verification_queue.py:2662-2664` caught that and exposed only `QueueIntegrityError('queue_integrity_failed')`. The active fixture handles came from raw `sqlite3.connect`: the exact PRAGMA values were `foreign_keys=0`, `page_size=4096`, `max_page_count=4294967294`, `journal_mode='delete'`, `synchronous=2`. Queue `_connect()` establishes `foreign_keys=1` and `max_page_count=32768` before `BEGIN IMMEDIATE`; the failing fixture had begun the transaction before the checker attempted connection configuration. All four affected direct hold fixtures now use the corresponding store's `_connect()`. No production integrity check was suppressed.

The expiry fixture now issues a future-valid batch, then advances its deterministic clock to the validity boundary before submit. Adjacent queued/recovery fixture windows were raised from 100/10 ms to 60,000 ms, with the fake clock advanced after successful setup. This prevents issuance or submit commit fences from expiring during test setup while preserving the expected `validity_expired` outcome.

The temporal matrix previously changed event sequence 4 (`VERIFIER_STARTED`) to `clock.now + 1` and expected `timestamp_binding`. That time is semantically allowed: the independent checker constrains it to be no earlier than the preceding `VERIFICATION_STARTED` and before lease expiry (`_verify_temporal_bindings`, lines 1340-1343), with no second persisted verifier-start time as an independent anchor. The negative now changes it to `clock.now - 1`, violating the existing monotonic event-time invariant at lines 1265-1267. The test still rehashes the full transition chain and expects `timestamp_binding`; no independent-checker code or expected valid-time behavior changed.

### Guarded results and retained evidence

All v4 guarded test/check runs used guard SHA-256 `57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`, target start floor 3,500,000,000, and hard physical-free floor 2,190,433,321 bytes. The contained diagnostic intentionally ended with three test errors to expose the inner exception; guard self-tests were 7/0, minimum free bytes 4,508,232,704, cleanup PASS, mutex RELEASED. Its outer/stderr identities are 3,413 bytes / `CD49F1597B5DBEC34FC2EBECF6417D1B76A20AB0BB15DBA0FE922F9C36129665` and 11,302 bytes / `6B1F7D4DDEB33ABCD71E5EAC29317660AB0BDE380BB67BFECAEEBA02CF38BB5E`; stdout was empty / `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.

Two intermediate five-case fixture runs failed and were retained: first, `Ran 5 tests in 3.785s; FAILED (errors=1)` from the newly adjusted 1 ms window still expiring during issue commit (outer 6,154 bytes / `E3FA9A63F29FE74E987BA0A5A0F403E647801BE03A5380EB08BD48A24D6E4921`; stderr 1,838 bytes / `586F797B03FD04C192F1C53F29DD1E20189C4021C8E86E1B6C5B5ECDF3DF7499`); second, `Ran 5 tests in 3.979s; FAILED (errors=1)` from the adjacent 100 ms queued window expiring before submit commit (outer 4,474 bytes / `94D28A4CDE328FEB785DC157230EA1BDE4F0EBC0313DE4E3C07C47AD6CB0DDB5`; stderr 1,611 bytes / `62B26CA8D8DF5174CA16633F9B108C48617F5E529C6DC9A822B6942E4834A445`). Both guards completed cleanup and released the mutex; the test windows were widened and rerun.

The final focused packet passed all five affected `Profile12StateTests` methods: `Ran 5 tests in 4.445s; OK`, no skips. Guard minimum free 4,506,210,304 over 10 samples; peak working set 80,740,352; peak private 51,757,056; child exit 0; cleanup PASS; mutex RELEASED. Its outer log is 4,555 bytes / SHA-256 `06AA0CEDC74033E3ED4CC8AFAE926E2C76FE28F8DB129612B347CB7C38E2BF41`; stdout empty / `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`; stderr 108 bytes / `A4B7CD0A8B9453A85AEB4027EF43452BE56BA13A9836B3F06AAC7BAF87490AB4`.

The single required broad run then passed the four requested modules: `git diff --check && py -3.14 -B -m unittest tests.test_minimal_clearance_verification_queue tests.test_minimal_clearance_lifecycle_adapter tests.test_direct_mask_state_profile12 tests.test_minimal_clearance_composition_v2`; raw result `Ran 122 tests in 73.223s; OK`, zero skips/failures. Fresh host preflight was 4,636,020,736 bytes free, with correct root, exact guard hash, mutex absent, zero relevant processes, and all modules present. Guard internal preflight was 4,617,388,032; 124 samples, minimum free 4,465,680,384, peak working set 93,687,808, peak private 79,740,928, exit checks 7/0, child exit 0, cleanup PASS, mutex RELEASED. Post-run probe: 4,565,135,360 bytes free, mutex object absent, relevant process count 0. Logs: outer 18,557 bytes / SHA-256 `A975C9EA6F3DC4E2BB04C29A62318BEB2DFFA81B5260AFFC2F3C60EA77990DCB`; stdout 0 bytes / `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`; stderr 228 bytes / `74BC0F83C931B0E0EFC208B34011FEC51E81C979EC92B05D190371D338A16E2A`.

Tooling/discovery errors: one initial diagnostic guard invocation failed parameter binding on `-c` before running a child (outer 1,047 bytes / SHA-256 `88A9223491149E2E2A81F45D3250D68F1889BF0B5A372019B58327F636AC3BF4`); the corrected invocation completed preflight. One post-run log reader had a PowerShell `catch` parse error and was corrected. An initial unguarded combined inspection included `git diff --check`; it printed no output but did not capture that command's individual exit status. All later diff checks and tests were inside v4. An initial unquoted PowerShell `git rev-parse HEAD^{tree}` read failed; quoting the ref produced the confirmed identity.

The broad and focused tests emitted no warnings and reported no skips after correction. Final checkout remains detached HEAD `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55`, tree `40d8268880072f23b4c46fc83aee2c5084184083`; inherited changes remain uncommitted and unstaged. Final source identities: Queue writer 243,643 bytes / SHA-256 `FE57DF433AA2BEDDFE31F1E189C97B674B7A73BA4E86D42C7BD3497E3CBA7140`; independent checker 145,820 bytes / `3101847DE2681A105A6E9521344B332649CF76BF33B0ED082C322C3708D662CF`; Queue test 131,814 bytes / `61E69061F43C305A160A91C28CB057C5C57C8EF21C3CF60F199D62287A7B655E`; focused Profile12 test 126,749 bytes / `F37E5A4FD3A1A631EED1959AB3DF20D8DC8906494D28EBCA983F0C1FE55DF767`. No source-to-binary, formal-release, production, payment, PHI, or activation claim follows; Lifecycle remains legacy-pinned with no manifest digest. Status remains `proofSuiteId=null`, `production_usable=false`, `NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`. The finite lane is returned to Driver; the final post-record `git diff --check` is performed under v4 and its raw result is reported in the task reply.

## Lifecycle source provenance follow-up — source-only disposition — 2026-09-24

This follow-up started at detached HEAD/tree
`b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55` /
`40d8268880072f23b4c46fc83aee2c5084184083`. It preserved inherited edits; nothing was staged or
committed. Files changed in this follow-up are `semantic_kernel/rust/build.rs`,
`tests/test_minimal_clearance_lifecycle_adapter.py`, `tests/test_minimal_clearance_verification_queue.py`,
`CURRENT_TASK.md`, `STATE.md`, and `docs/LEAN_FORMAL_KERNEL.md`. The Queue writer, independent
checker, Rust Lifecycle entry point, Lean source, executable, and `.lake` outputs were not changed.

The build manifest record keys for Clang and LLD now use stable relative tool roles instead of
canonical host paths. Canonical path equality checks remain. The relative linker role is
`toolchain/bin/clang.exe`; the LLD role is `link-tool/ld.lld.exe`, with the verified copied-file
hash. Actual link args still select LLD, but the linker invocation and final executable are outside
the current pre-link receipt. This correction removes workspace path dependence from those record
keys; it does not prove final-link provenance.

The focused adapter test adds strict missing-final-newline rejection and a mocked one-call success
checking the source-bound report and response share the same contained-runner result and fixed
executable identity. The existing Queue rollback/retry case now also injects a source-bound report
whose manifest digest mismatches the reviewed digest. Its source assertions require one runner
call, closed volatile handoff, rejected response before decoding, unchanged durable
`AWAITING_HANDOFF` status and transition count, no duplicate reservation, and a successful fresh
retry. No test command ran, so these additions remain unverified. No Queue production writer code
changed.

The retained failed Lake stdout is 1,631 bytes / SHA-256
`5A5D70EB1CCCD24BDFC4A8EDCF53AED2A5DAFC5BE2606EBA5C7A19F5AF9B8EC8`; stderr is 20 bytes / SHA-256
`C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F`. It shows the five
`unexpected identifier; expected '}'` parser errors at `LifecycleKernel.lean` 156:71, 188:79,
235:65, 303:83, and 418:77, then Lean exit 1 and failed target `Admission.LifecycleKernel`.

The retained `...kernel-20260922-handoff-r1.stdout.log` success is 87 bytes / SHA-256
`15ED5C2210FD21445879CD8CDF8C31E0F213C32E22110F12A12E2565B35411D1` at 2026-09-23 02:25:12Z,
before the current Lean source mtime. It cannot establish a build of the current source. The later
`...parser-repairs-20260923-r1.stdout.log` is 87 bytes / SHA-256
`7078317941FA38CCE142BA58A1EB9C33EAC07FACF124F47CA422E322A6C862BB` at 2026-09-23 06:58:37Z;
its stdout says `✔ [5/5] Built Admission.LifecycleKernel (32s)` and `Build completed successfully
(5 jobs).` Its stderr is empty. This later success is temporally consistent with the current source
and the 920,528-byte `.olean` (SHA-256
`DAB9737758C18DAF1A96C372F138E63838E80DC557641CCF93ACF0A61B34DD47`). The earlier STATE entry
reports a successful guarded run and telemetry, but inspection of the named build-filter directory
found no matching per-run outer log. The child stdout hash is confirmed; the command, guard
identity/telemetry, and exact source identity cannot be independently reconstructed from the
retained child streams. Treat the earlier telemetry as a recorded claim, not independently
verified provenance. A fresh guarded Lake build remains required.

No Lake, Cargo, compiler, unittest, checker, executable, or diff-check command ran in this
follow-up: 0 runs in each category. Work remains gated on direct finite-lane handoff, fresh v4
preflight, guard SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`, the hard 2,190,433,321-byte
physical-free floor, and the applicable target start floor. The 3,500,000,000-byte value documented
for Python/SQLite work does not authorize Lean/Rust compilation; the target-specific
`-MinimumStartFreeBytes` for Lake/Cargo must be supplied before running those targets.

The final Cargo link remains outside the pre-link receipt, and replacement of live tool/input paths
during build remains unresolved. The retained executable is unchanged at 6,571,008 bytes / SHA-256
`B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881`; adapter mode remains
`legacy-pinned-v2`; the source-manifest digest remains unset. Keep source-bound mode closed. Status
remains synthetic, nonactivating, nonpayment, non-PHI, `proofSuiteId=null`,
`production_usable=false`, `NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.

### Driver lane sequencing update — 2026-09-24

Driver confirmed State owns the sole v4 lane. Cleanup has the next direct release for its queued
focused code-deletion verification; this Lifecycle Lake/Cargo run is scheduled after Cleanup's safe
return. The direct handoff with fresh boundary evidence has not arrived, so no build, test, checker,
or diff check is authorized yet. The 3,500,000,000-byte Python/SQLite start threshold does not
apply to compiler/link stages. Record target-specific Lake/Cargo start floors from compiler evidence
once the lane is released, and continue enforcing the 2,190,433,321-byte physical-free floor.

## Lifecycle POST-LINK attestation source step — 2026-09-24

### Repository and authorized change

This source-only step continued at detached HEAD
`b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55`; the commit object reports tree
`40d8268880072f23b4c46fc83aee2c5084184083`. `git cat-file -p HEAD` also reports parent
`3b8b5285064585ae896e1d88edfcbfdc37564370`. No files were staged or committed. The inherited
worktree changes and untracked files were preserved.

The prior `semantic_kernel/rust/build.rs` source identity at this step's entry was SHA-256
`F304AB072438EC037404B3D93E617F01FB873B46050F7202A84DBBE10EA8E4A6`.
The code was extended to pin the direct Cargo executable and its SHA-256, reject the
`LLD_REPRODUCE` override, version the ordered Lifecycle link-argument record, remove a stale
reproducer from its fresh Cargo `OUT_DIR`, and pass `--reproduce` only to the Lifecycle binary.
The Rust build input list now pins the adjacent attester source at 49,911 bytes / SHA-256
`F23F987C8268F24B58AF833110E908EE0FFE4AF4AB0C200F0AB9AFE96A84F478`.

Added `semantic_kernel/rust/post_link_attest.py` and
`tests/test_lifecycle_post_link_attest.py` (8 focused test methods; 8,424 bytes / SHA-256
`DC7C4F6E022D2274E8F568E5B5E4AD74401370F58861863FA32C83EBD36F37FE`). The future attester
invocation is fixed to the pinned Cargo/Rustc toolchain and
`build --locked --offline --target x86_64-pc-windows-gnu --release --bin lifecycle`; it requires
new target/evidence directories outside the source root. It checks Cargo JSON for one release
Lifecycle artifact, strictly parses the pre-link receipt/source manifest/link-argument record,
rehashes current Lean/Rust/toolchain/static inputs, verifies the embedded manifest and pre-link
output identities, hashes the LLD reproducer without extraction, maps every regular payload to a
known explicit, Cargo-target, or pinned Rust target-std input, and requires the explicit ordered
link-input basename occurrences in the response text. It retains exact Cargo logs and a
byte-identical response sidecar. Current `build.rs` is 47,919 bytes / SHA-256
`1932F252DC434CEA623727DBDA4CE1E5B7D365FB7A8B3F2076B70E20BA0CF511`.
The final JSON receipt is published only after successful checks; failures preserve the target and
logs, forward complete Cargo stdout/stderr, and do not publish a post-link receipt.

### Verification disposition and skipped work

No Cargo, Rust compiler/linker, Lean/Lake, test, checker, executable, or `git diff --check` command
ran. Executed tests: 0. Deferred: one focused Python test module (8 methods), one pinned Cargo
final-link/post-link run, and one `git diff --check`; each is blocked by the missing direct finite
lane handoff and fresh v4 preflight. The compiler/link start floor is at least 4,190,433,321 bytes;
the 2,190,433,321-byte physical-free hard floor remains mandatory. The required guard is
`../pq-wide-seed-native-20260913/build-filter-native/run_guarded_v4.ps1`, SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`. State owns the lane and
Cleanup has the next direct release. No fresh target-specific preflight or direct handoff arrived.

The retained executable remains 6,571,008 bytes / SHA-256
`B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881`; adapter mode remains
`legacy-pinned-v2`, and source-bound mode remains closed. No final Cargo link or installed pinned
LLD archive has been observed. The attester assumes an uncompressed tar with root `response.txt`,
optional root `version.txt`, and regular input payloads; unsupported metadata/layouts or unknown,
missing, ambiguous, traversal, symlink, hard-link, or special entries fail closed without a
receipt. The raw response is retained and its explicit input basenames are checked, but the full LLD
response grammar is not independently parsed. Pre/post hashing still cannot rule out replacement
and restoration of a live compiler, source, or linker input during use. These are open qualification
limits, not passes. No source-to-binary, formal-release, deployed-link, production, payment, PHI, or
activation claim follows.

Protected Queue/independent/Composition/Mirror, Lean semantic, C/native/crypto, adapter mode, old
executable, and operational pin paths were not edited by this increment. Inherited dirty changes
remain visible in the worktree and were not reset, staged, or committed.

### Inspection diagnostics

One initial local `WORKSPACE_MAP.md` lookup failed because the required map is in the Driver parent;
the correct `../../WORKSPACE_MAP.md` was then read. One PowerShell `git rev-parse` tree expression
was mangled and a follow-up printed the parent commit as the tree; the immutable commit object
readback above corrected the identity, with no mutation. One `apply_patch` attempt had an unmatched
context hunk for a nonexistent line and changed no file; the smaller corrected patches applied.
No source, test, compiler, or runtime failure was generated.

## Lifecycle Cargo configuration provenance hardening — source-only — 2026-09-24

This source-only follow-up continued at detached HEAD
`b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55`, tree
`40d8268880072f23b4c46fc83aee2c5084184083`. Inherited dirty and untracked work was preserved;
nothing was staged or committed. Cleanup returned source ownership for the exact
`semantic_kernel/rust/post_link_attest.py` and `semantic_kernel/rust/build.rs` files after source
review. No Queue, Lifecycle adapter, Lifecycle Rust, Lean, executable, or generated output was
changed in this follow-up.

### Finding and source disposition

The post-link review found that Cargo reads configuration from the current directory and its
ancestors, plus `$CARGO_HOME/config.toml`; configuration can set `build.rustc-wrapper`.
The source manifest recorded the Cargo home path but did not establish that no unreviewed global
configuration was active. The official Cargo configuration reference documents this search order
and wrapper setting: [Cargo configuration](https://doc.rust-lang.org/cargo/reference/config.html).

The attester now walks all ancestor `.cargo/config.toml` and legacy `.cargo/config` paths plus the
resolved Cargo home, allows only the current project `.cargo/config.toml` with pinned SHA-256
`385D15C7142267A1FDEE1CDA6AB13D41966B2E9557084828922F4A4EE3644E81`, records the searched paths
and found-file identity in the post-link receipt, and requires the same inventory after Cargo
returns. It resolves and explicitly sets an absolute `CARGO_HOME`, rejects the Cargo release
build-override, build-directory, `CARGO_BUILD_TARGET_DIR`, and warning-level environment
overrides, removes inherited `CARGO_TARGET_DIR` in favor of the fixed `--target-dir`, and passes
`--jobs 1` to the pinned offline/locked build. `build.rs` independently rejects the same
profile/build-directory/warning override classes and now pins the exact attester source below.

A read-only host scan across the `RUST_ROOT` configuration ancestors and the active Cargo home
found exactly one configuration file: the project `.cargo/config.toml` (182 bytes, SHA-256
`385D15C7142267A1FDEE1CDA6AB13D41966B2E9557084828922F4A4EE3644E81`). No external Cargo
configuration file was found. This observation is specific to this scan and is not a guard pass.

### Exact source identities and unrun gates

- `semantic_kernel/rust/post_link_attest.py`: 51,849 bytes, 1,151 lines, SHA-256
  `1ED03C3B57A092F3C23B0994A664EA46C5BF6FF4AE74B9FD9EFD4E21697E35A8`.
- `semantic_kernel/rust/build.rs`: 48,277 bytes, 909 lines, SHA-256
  `D29572C08D9B4E69C99C463F49F8F000A5A72660E94E1CAC5764E84F2CD90767`. Its
  `RUST_BUILD_INPUT_PINS` entry for `post_link_attest.py` is the lowercase form of the exact
  attester digest above.
- `tests/test_lifecycle_post_link_attest.py`: 11,931 bytes, 225 lines, SHA-256
  `1B6B5537C0E925F064EBD7F5A8C46EF80C9B3B8CDA1773C65A600F022D4EDBFE`; 12 test methods are
  authored, including four Cargo configuration/environment cases. They have not run.

No Cargo/Rust/Lean/Lake build, compiler, executable, test, checker, or `git diff --check` ran in
this follow-up. The direct finite-lane handoff and fresh compiler-specific v4 preflight remain
absent. The documented compiler start floor is at least 4,190,433,321 bytes; the hard
2,190,433,321-byte physical-free floor and guard SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB` remain required.

The adapter remains `legacy-pinned-v2` at 6,571,008 bytes / SHA-256
`B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881`; its reviewed source
manifest digest remains unset and source-bound mode stays closed. Post/pre configuration scans
cannot detect a configuration file replaced and restored while Cargo is running. The attester's
LLD response check still checks explicit input basename counts rather than parsing the complete
response grammar/order (`post_link_attest.py`, `verify_response_references`), and the final
compiler/linker/source live-path replacement-and-restoration risk remains open. These limits keep
the source-to-binary claim blocked pending guarded build evidence and independent review of the
raw response and output pin.
