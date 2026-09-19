# RightRail current state

Updated: 2026-09-19

## Current verified snapshot — follow-on v3 source/test batch

The documentation/source batch started from the integration checkout
`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-financial-workflow-20260913`,
branch `rightrail-financial-workflow-20260913`, HEAD
`de495141ad2b7c5b910bf6dd6459b7b1120eaea6`, tree
`4ea7838728ba1322d2a50edb5ede0c3deedc3a97`. Tracked status was clean. The
only untracked paths were the two driver-supplied generated executables listed
below; they are not touched or staged in this batch.

The preceding source/docs checkpoint is parent commit
`1effa625800c778367579416cb15a07555264754`, tree
`85bd334d002446c598cde41dd61283736c1e006e`. The persisted candidate contract
is `RR/FINANCIAL/OWNER/v3` with Continuity
`RR/FINANCIAL/CONTINUITY/v3`. Event IDs/heads bind before/after revisions and
commit time; the independent checker reconstructs population lifecycle order
and binds reconstructed imported counts to persisted `population_imports` state;
omitted report/evidence timestamps reuse stored identity fields.

The final guarded source/test result is exactly:

```text
Ran 46 tests in 14.878s
OK
```

The final blocker guard exited `0`; its resource summary was
`min_free_bytes=4072607744`, `reserve_floor_bytes=2576980378`,
`peak_working_set_bytes=51580928`, `peak_private_bytes=27623424`,
`CLEANUP=PASS`, and `MUTEX=RELEASED`. The complete stderr is retained in
`guarded-command-financial-followon-blockers-r10-final.stderr.log` (151 bytes,
SHA-256
`FE4014ADB6EC23EFAAE425078E8C89202273C5EA88296A0D00C69CFB815C0AB1`).

The follow-on measurement series completed at
`work/financial-measurements-v4-r1`: 3 measured samples plus 1 warmup at each
of sizes 5, 10, and 20, 12 owner SQLite databases and 12 TEST restore
databases. All measured owner and TEST restarts independently verified; all 9
measured TEST restores left source bytes unchanged. Total-ms medians were
329.150, 440.241, and 590.361 ms. Lock wait-to-acquire/transaction-held
medians were 20.024/9.507, 15.852/9.710, and 15.148/9.661 ms for sizes 5,
10, and 20. Each measured sample used one holder statement, one waiter
attempt, and one successful acquisition. Native metrics remain pending and
queue wait/age is not applicable. The measurement plan was 3 retained samples
plus 1 warmup per size; the output contains 12 owner and 12 TEST databases.

The measurement guard exited `0` with `min_free_bytes=3716636672`,
`reserve_floor_bytes=2576980378`, `peak_working_set_bytes=47734784`,
`peak_private_bytes=26390528`, `CLEANUP=PASS`, and `MUTEX=RELEASED`.
Its stdout log is 35051 bytes, SHA-256
`582E0328856AC75634E71C150AF6200300314400D8E54399A08EF0FC4D9565C3`;
stderr is 0 bytes, SHA-256
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.

The retained v2 measurement databases/logs under
`work/financial-measurements-20260919-r1` remain immutable historical v2
evidence. The earlier v2 result (`Ran 29 tests in 7.582s`, `OK`) and one
20-item observation of 379.703 ms are not v3 evidence. No numerical financial
SLA is supplied.

The four initial source blockers and the follow-on P1 checks are covered by the
guarded run; this is source-local synthetic evidence, not final acceptance or
qualification. Case 11 verifies SHADOW read-only behavior and a separate
TEST-only recovered owner through H_P3_REPLACED, including recovered restart,
duplicate action identity, disabled dispatch/egress, and unchanged source
bytes. Separate older financial suites were not present beyond the three named
RightRail financial test modules, so no additional older financial suite was
run; unrelated repository suites remain outside this bounded verification.
Current claims remain synthetic and nonactivating:
`proofSuiteId=null`, `production_usable=false`, `activation=false`,
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`. There is no real PHI, credential,
payment movement, live dispatch, deployed Lean authority, native rebuild, or
archive refresh in this batch. Final Driver whole-system review,
native/Lean replay, independent audit, and production qualification remain
pending.

Driver-supplied native inputs are unchanged and remain separate regressions:

| Path | Bytes | SHA-256 |
| --- | ---: | --- |
| `build-performance/fixture-candidate/Release/direct_mask_fixture_source_performance.exe` | 275968 | `E07865D9CE6C2644142D3EA61030BD308D5BBD09FE861C630CC5EEBE1F3FE5D9` |
| `build-performance/q/Release/dm_pipeline_verifier_cli.exe` | 240640 | `F35F6AF28EC2D269831CFB6BDD1C2414D439FFEC2B26C73CC39495720D9B9E5D` |

## Historical verified records (reference only)

The records below preserve earlier implementation, cleanup, and test evidence.
They do not override the current snapshot or close the remaining gates.

## Historical Profile12 Queue/State stage — corrected, unverified/in progress

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

## Historical cleanup disposition

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

## Historical prior candidate and release closure

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

## Historical E2E complete-path evidence — 2026-09-12

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

## Historical native arithmetic performance phase — 2026-09-12

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
SHA-256 F35F6AF28EC2D269831CFB6BDD1C2414D439FFEC2B26C73CC39495720D9B9E5D. The one fresh
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

### Documentation reconciliation status — 2026-09-13

The source-admission/ownership candidate remains synthetic and nonactivating at commit
`1306e38901b73790dfb2a973b4ac44daf2ff6869`, tree
`1d04b16d29b2b298dc93817375cd258c9762b7ef`. A reviewed 100-operation complete path exists, but
it does not establish Lean linkage, PQ qualification, production readiness, payment authority, or
activation. Earlier semantic checkouts contain Lean source and an adapter at their recorded
commits; their executable identity and integration into this candidate remain unaccepted. The
current runtime uses a synthetic State port. The fresh Lean Engine, State, Queue, and Security
children are separate owner-authorized workstreams and do not change this record until their
actual source/build/artifact evidence is reviewed.

### Financial workflow implementation and acceptance closure — 2026-09-13

The financial source phase began at `ed6f51426d0b410759d15ff69728fff708690192` /
`944114b77cb0faf230eb0518daeb86bc2a344427` with parent
`dfc74027439c97cac39d589d680d07f19360ce89`, and is implemented by source commit
`99d28687df0e7d5cf6a46e73db22f42a9902b789` /
`82087b8f740e00c55d85a4717cd45617e96d9bc8`, parent
`ed6f51426d0b410759d15ff69728fff708690192`. The commit contains exactly the eight authorized
financial owner, independent checker, Mirror, fixture, test, and CLI paths listed in
`CURRENT_TASK.md`; no protected native, Lean, archive, production, payment, or PHI path changed.

Verified guarded acceptance evidence is retained in the external `build-filter-native` evidence
directory. The final r8 child output is 5666 bytes, SHA-256
`F0859F3DC4496CD775F627DB09F70E3026EC0122C19CC197A398799F607E7D98`, and its raw decisive result
is exactly:

```text
Ran 29 tests in 7.582s

OK
```

The pass covers 9 independent-checker tests, 13 acceptance tests (CASE_01–CASE_12 plus fixture
independence), and 7 Mirror/Continuity tests. The unchanged guard recorded preflight free
`2779701248`, reserve `3221225472`, reserve floor `2576980378`, minimum free `2687946752`, peak
working-set/private `38440960/23179264`, child exits `7/0`, cleanup `PASS`, and mutex release;
the child had no warning lines and the outer command exited `0`.

The final r11 measurement retained stdout 484 bytes, SHA-256
`B2013379A5E8EFAAB55A7A7BE2234C38F9E02B68132E7C684E5ABDE24FF88905`, stderr 0 bytes, and the
following raw line:

```text
FINANCIAL_MEASUREMENT {"acceptance_cases_exercised": 1, "activation": false, "build_population_ms": 273.799, "continuity_package_bytes": 123215, "continuity_table_count": 15, "final_action_count": 1, "final_conflict_count": 1, "final_evidence_count": 27, "final_flow_ms": 73.507, "final_payment_count": 3, "independent_verify_and_continuity_ms": 29.173, "population_items": 20, "production_usable": false, "support_records": 20, "target_status": "NOT_SUPPLIED", "total_ms": 379.703}
```

The measurement guard recorded preflight free `2964697088`, minimum free `2922229760`, peak
working-set/private `33034240/18784256`, child exits `7/0`, cleanup `PASS`, mutex release, and
outer exit `0`. This is one bounded observation only; no percentile, financial SLA, qualification,
or production claim follows.

The retained r1/r2/r7 failures and corrections are documented in `CURRENT_TASK.md`; none was
silently converted to a pass. r3 was a PowerShell `-c` parameter ambiguity, r4 had zero child
output and no evidence, r5/r6/r9 were unchanged physical-reserve preflight refusals, and r10 was
the corrected-launcher `ModuleNotFoundError: No module named 'app'`. Unchanged native regression
executions were 0 because replay was prohibited and pins were unchanged; archive refresh,
production/activation, and real-data/payment executions were also 0. The six pre-existing
unregistered README paths remain the inherited documentation-governance warning (11 tests, 2
errors). The only untracked path is `build-performance/`. Claims remain synthetic and
nonactivating: `proofSuiteId=null`, `production_usable=false`, `activation=false`,
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`.
