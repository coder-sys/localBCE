# Blind Ledger current state

Updated: 2026-09-08

## Active Profile12 Queue/State stage — unverified/in progress

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

Measured bounded evidence in this child: Profile12 focused tests `15 passed`; queue tests `29
passed`; runtime tests `17 passed, 2 skipped`. The two skips are the native Profile12
source-auth adapter/source-appliance identity tests, explicitly deferred by the active grant; the
native adapter, verifier process, resource limits, C/crypto checkouts, and protected production
paths were not modified. `py -3.14 -B -m py_compile` passed for the changed implementation and
tests. Focused read-only schema-gate, export/read/restore, lifecycle, counter, receipt-closure,
orphan-result, timestamp, KAT, reservation, and hold checks passed through `verify_database` and
the independent export/read/restore paths. No broad suite, adapter test, old Profile11 probe, or
large solver was run.

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
