# Blind Ledger current state

Updated: 2026-09-12

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
