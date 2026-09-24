# RightRail current state

Updated: 2026-09-24

## Current verified snapshot

Canonical checkout:

C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-financial-workflow-20260913

Branch: rightrail-financial-workflow-20260913.

The current delivery contains the corrected v5 Python financial slice and its
maintained documentation. Git HEAD, tree, and status are authoritative after
the final known-path commit. The two driver-supplied untracked executables
under build-performance/ were preserved unchanged.

The v5 owner, independent checker, Mirror, CLI, Continuity, and measurement
harness are synthetic and state-local. The Python owner remains the sole
transaction writer for obligations, evaluations, cases, determinations,
corrections, balances, and action/outbox identity. SHADOW is query-only; TEST
restore is isolated/non-live; dispatch and egress remain disabled.

## Review disposition — ACCEPTED NARROWLY; owner-local synthetic v5

The Driver reviewed the actual two-file correction and raw affected evidence.
The bounded synthetic Python v5 owner-local correctness scope is ACCEPTED
NARROWLY at commit `43406b4f1dcc5c944350ba690d512e1cc45f9393`, tree
`deaca25fc735ba407e801383f8e0b5c687894037`. The prior broad review packet is
retained evidence and the residual ownership and chronology corrections are
locally re-verified. This narrow disposition does not close the full original
A-E, native, reservation, executable Lean/adapter, or production qualification
gates.

The prior guarded affected run compiled the relevant Python paths and ran all
three affected suites:

PROCESS_BOUNDARY precommit returncode=73 stdout='PHASE=BEFORE_REJECT\nPHASE=PRECOMMIT_AFTER_MUTATION\n' stderr=''
PROCESS_BOUNDARY postcommit returncode=74 stdout='PHASE=BEFORE_REJECT\nPHASE=POSTCOMMIT_AFTER_COMMIT\n' stderr=''
Ran 63 tests in 26.573s
OK

Guard decisive output: child exit 0; minimum free bytes 3797897216; reserve
3221225472; effective floor 2576980378; peak private bytes 29360128;
CLEANUP=PASS; MUTEX=RELEASED. Raw files:

- work/pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-correction2-focused-r8.stdout.log
- work/pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-correction2-focused-r8.stderr.log

The residual focused packet used the unchanged guard and the absolute project
cwd. Its raw logs are:

- work/pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-residual-focused-r2.stdout.log
- work/pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-residual-focused-r2.stderr.log

Its complete child result was:

```text
Ran 5 tests in 4.254s
OK
```

The guard also reported `exit7=7 exit0=0`, child exit `0`, minimum free bytes
`3106156544`, reserve `3221225472`, effective floor `2576980378`, peak private
bytes `30777344`, `CLEANUP=PASS`, and `MUTEX=RELEASED`.

Source identities for the prior broad packet are:

- owner: 68D1AF3DE2B5072FDD7A6D05DD297E2B5A95687E1453E80CCBFB49A2ADF694D9
- independent checker: FE1CCDCA057FE36391FF9A9BCD9B4CD73ADAC9A934D3DB88D040E5F6BB1D5A55
- acceptance test: FD456CF52EB783513AC3143690659A9888F0E9810E2B3996E7C7F939874A935B
- Mirror test: 3099F0846BABF9953A9A34E65E760EBE223FD5D38DAC3B1CEE0C35C355258C75
- measurement harness: A50C73BD4231385900B378327492FF1DFC5F2A16CE8125752D3C76DB7EE13437

Current post-correction source identities are:

- owner: 45D2F3F0468642BE471CF365A7C6AF63B98836430AEEA796FD6A461CECE19846
- acceptance test: B9312E8DE63D80861C88924E800CFE0771BB1EA7D0EE72DF2BC56E802CF6017B
- Mirror test: 3099F0846BABF9953A9A34E65E760EBE223FD5D38DAC3B1CEE0C35C355258C75

The acceptance additions independently reconstruct the complete populated
evaluation receipt: scope, obligation/evaluation/revision, Control Pack,
sorted unique evidence record-digest bindings, authority/time, every result
field, result digest, and receipt digest. The exact receipt is checked across
owner query/evaluate, restart, Mirror, CLI, and SHADOW restore without using
the owner digest or evaluator to construct the expected value.

Determination coverage includes malformed and bad digest references,
missing-reference and current-receipt chronology rejection, stale references
after a real evidence/revision change, unchanged rejected requests, and the
same consumed reference under a different action. The final consumed-reference negative case reaches the
revision conflict before any mutation; a separate lower-level consumption
branch is not fabricated because current revision invariants make it
unreachable. Real CLI coverage proves authorize-offset success, exact retry as
DUPLICATE, and changed-binding conflict. Existing tamper-copy tests retain
invalid authority/pack/evidence/projection coverage.

Continuity restore now constructs and verifies in a private attempt directory,
captures the private attempt identity before publication, publishes with an
atomic no-replace link, verifies the published destination still has that
identity, checks destination sidecars, and cleans only demonstrably owned
attempt/published identities. Pre-link and post-link destination races,
foreign -wal/-shm sidecars, genuine owned-failure cleanup, and normal
SHADOW/TEST restore are covered. Cleanup failures are surfaced as
continuity_restore_cleanup; they are not silently ignored.

The v2/v3/v4 matrix copies disposable current bytes, changes only schema/version
tags, and verifies fail-closed store/package rejection, unchanged source bytes,
and no destination. No authentic old-schema compatibility claim is made; these
are tag-only rejection checks.

## Retained bounded measurement (pre-residual correction)

Raw measurement logs:

- work/pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-final-r4.stdout.log
- work/pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-final-r4.stderr.log

The child completion receipt reports:

schema=RR/FINANCIAL/MEASUREMENT-SERIES/v1
type=complete status=PASS
sizes=[5,10,20] samples_per_size=3 warmups_per_size=1
output_root=work/financial-measurements-v5-final-r4
owner=68D1AF3DE2B5072FDD7A6D05DD297E2B5A95687E1453E80CCBFB49A2ADF694D9
independent_checker=FE1CCDCA057FE36391FF9A9BCD9B4CD73ADAC9A934D3DB88D040E5F6BB1D5A55
all_reference_checks_passed=true all_source_bytes_unchanged=true
owner_databases=12 test_databases=12 acquisition_failures=0

Measured aggregate medians:

| size | total ms | wait ms | held ms | transactions |
| ---: | ---: | ---: | ---: | ---: |
| 5 | 504.762 | 1.390 | 6.236 | 51 |
| 10 | 793.516 | 1.460 | 7.373 | 84 |
| 20 | 1261.848 | 1.469 | 7.291 | 150 |

The outer guard completed with child exit 0, 18 samples, minimum free bytes
3767709696, peak private bytes 24268800, CLEANUP=PASS, and MUTEX=RELEASED.
The retained child JSON stdout file SHA-256 is:
2F5C1062F00C7A3FA5A3BA1F802EAEB62C1C90441851BEA18F0BA02F7CB81B0A.
The wrapper stderr was empty, SHA-256
E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.
The measurement is a bounded local observation, not an SLA; native metrics
remain pending and Queue wait/age are not applicable to this owner slice. It is
source-bound to owner
`68D1AF3DE2B5072FDD7A6D05DD297E2B5A95687E1453E80CCBFB49A2ADF694D9` before the
residual correction, not the current owner, and was not rerun. The r4
invocation used absolute script/output paths and script-derived
`REPOSITORY_ROOT`/`sys.path`, but did not change the child cwd from the guard
default; this invocation deviation is retained as historical evidence.

## Retained failures, warnings, and skips

The residual r1 attempt launched guarded `cmd.exe` and completed both guard
self-tests (`child-exit-7=7`, `child-exit-0=0`), then the main command and
wrapper exited 1 before Python tests. Its raw stderr (SHA-256
`B243E3431CF3FD2DA74278615CAA676AD4F4F806E23B19FCD398E83A7B02390D`) was:

```text
The filename, directory name, or volume label syntax is incorrect.
```

The corrected residual r2 run had no test warnings or skips. Earlier correction attempts remain
raw evidence: the first 63-test attempt had two errors (hard-coded
evaluation revision and an incorrectly indexed CLI argument); one guarded
attempt stopped at 2521305088 < 2576980378 for the memory floor; the next
test run exposed the missing detail-row item_id; later runs exposed missing
io and redirect_stdout imports. The wrapper-argument attempts that passed
-c through an external PowerShell invocation were rejected before child
execution with the raw ambiguity: Parameter cannot be processed because the
parameter name c is ambiguous. None of these failures was relabeled as a
pass. Earlier pre-correction security/test failures and all older v2/v3/v4
inputs remain in their existing raw locations and Git history.

## Open gates and nonclaims

Driver narrowly accepts the owner-local synthetic v5 slice recorded above; this
does not close the full original A-E, native verification-to-commit,
native metrics, executable Lean linkage/refinement, Queue/Composition
integration, reservation, independent audit, authenticated sources, custody,
real PHI, live dispatch, payment movement, or production qualification. Engine
is implementing and correcting executable Lean modules and the concrete
adapter contract, but runtime authority does not switch away from the Python
owner.

Current claims remain:

proofSuiteId=null, production_usable=false, activation=false,
NOT_QUALIFIED/INACTIVE/UNSELECTED, synthetic, nonpayment, and non-PHI.

Preserve the fixed twenty-hospital/$1,000,000 fixture and hand-derived cents,
Queue schema 13/Profile 12, Composition schema 4, exact 100-reference
protocol, source ownership/reservation, Queue/State/outbox atomicity,
non-CLEAR guard, and all native/C/crypto/Lean boundaries.

## Supplemental v6 correction evidence — locally verified, pending Driver review

The v6 owner correction now compares each superseding funding receipt's
sampled `recorded_at_ms` with its immediate parent's recorded time before any
receipt, projection, event, or financial-meta mutation. The independent
verifier already rejects that chronology when the child is earlier. Exact
receipt retries remain before clock sampling. This comparison is not a claim
that the injected clock is atomic or globally monotonic.

Every v6 `_write()` with durable changes builds the exact canonical
Continuity-v6 package on the same connection inside the active
`BEGIN IMMEDIATE` transaction, before `COMMIT`; export delegates to that same
builder. The cap remains exactly 8 MiB and the row cap remains 10,000. V5
continues to use its original `_read()` export path and does not receive the new
precommit check. The owner constructor's direct commit creates only genesis
metadata/identity; ordinary mutations use `_write()`, Continuity restore uses
`owner._write()`, and Mirror delegates commands to the owner.

The new clock-rollback test verifies the chronology error, unchanged exported
bytes, table counts and complete meta row, independent verification, and exact
duplicate behavior without another clock sample. The near-cap test records
below-cap positive writes, previews candidate package bytes using the active
transaction connection, proves the next public receipt fails with
`continuity_package_size`, compares bytes/counts/meta before and after, and
independently verifies and TEST-restores the exported state before and after
rejection. The cap and v5 behavior were not weakened.

### v6 test-run history

The raw child log pairs listed here are retained under
`../pq-wide-seed-native-20260913/build-filter-native/` with names
`guarded-command-financial-v6-state-20260922-<suffix>.stdout.log` and the
matching `.stderr.log`; suffixes are `r1`, `r2`, `r3`, `final`, `final-r2`,
and `final-r3`.

- `r1`: test collection stopped before tests because
  `PERIOD_ONE_SCOPE` was undefined at
  `tests/rightrail_financial_expected_cases.py:251`. Child stdout (20 bytes)
  SHA-256 `4434B00F9E40FE1DA2DE15D5DCFB297B70C45B3DC7021AA402F4C87D05E340DC`;
  stderr (2,204 bytes) SHA-256
  `6C1C494E53DF8F2C245F67765ABB5094894E4CA1298037C861DCB479913AC703`.
- `r2`: `Ran 67 tests in 29.552s`; `FAILED (failures=1, errors=6)`.
  Failures include missing scope for independent Continuity checks, missing
  `_hex` in funding verification, and the v2/v3/v4 expected-code mismatch.
  Child stdout (251 bytes) SHA-256
  `F4E6D5EBFC01F02D67388F75A4C9FBFF33D95908D34915DD6B7F7718BD923D8E`;
  stderr (14,054 bytes) SHA-256
  `8B43353493CEB7CE535706DAD7BD9F97CF2C79B1132B4513161DB63765113329`.
- Prior-source `r3`: `Ran 67 tests in 55.586s` / `OK`, no warnings or skips.
  Child stdout (251 bytes) SHA-256
  `3843E881F0573496623238FA0D2AFABDB3416EE18E91703FA4F81F7902B40CEE`;
  stderr (172 bytes) SHA-256
  `3251FF86A0165969173BEE919E82226F5E2CC6B60FA93B2B226C499F8EB08331`.
- First post-handoff attempt (`financial-v6-state-20260922-final`) ran 69
  tests in 35.922s and had one test assertion failure: actual package growth
  `4046` bytes, estimate `4040`. The brittle estimate was replaced with a
  rollback-only preview through the exact package builder. Child stdout (230
  bytes) SHA-256
  `DE792E063EA22A4B1E6AA7172E789871AB9B96A9BF70E4466C26F1B73E6A3429`;
  stderr (914 bytes) SHA-256
  `EE7E181E309867B9136F82B0F52A8E5A455A8EF4641D1B81C932722B21E80AD6`.
  This was a test failure, not a guard resource stop; cleanup and mutex
  release passed.
- `final-r2`: 69 tests in 95.630s / `OK`, before the final v5 read-path
  preservation adjustment. Child stdout (230 bytes) SHA-256
  `DE792E063EA22A4B1E6AA7172E789871AB9B96A9BF70E4466C26F1B73E6A3429`;
  stderr (174 bytes) SHA-256
  `72EE50E9644C09DFDF88FD863969985C3051CF09CB064141EDDCF6BC59B3DE16`.
- Final-source `final-r3`: `Ran 69 tests in 95.180s` / `OK`; no warnings
  or skips. The run covered acceptance, independent-checker and Mirror test
  modules. Child stdout (230 bytes) SHA-256
  `DE792E063EA22A4B1E6AA7172E789871AB9B96A9BF70E4466C26F1B73E6A3429`;
  stderr (174 bytes) SHA-256
  `B0B78E35C9B9996B8636D3268BFA39D18A6912ECC54105F8A88FC5EC301009F8`.
  Both child exit and wrapper exit were `0`; guard self-tests were `7/0`;
  samples `169`; minimum free bytes `4386463744`; peak working set
  `141508608`; peak private bytes `125403136`; cleanup `PASS`; mutex
  `RELEASED`.
  Exact Python invocation was
  `C:\Users\neers\AppData\Roaming\uv\python\cpython-3.11-windows-x86_64-none\python.exe -c "import os, unittest; os.chdir(r'C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-financial-workflow-20260913'); unittest.main(module=None)" tests.test_right_rail_financial_acceptance tests.test_right_rail_financial_independent tests.test_right_rail_financial_mirror`.
  The final child logs emitted no warnings or skipped-test notices.

Final-run raw child logs are at
`../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v6-state-20260922-final-r3.stdout.log`
and its `.stderr.log` companion. The guard SHA-256 was
`55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`; reserve
`3221225472`, effective floor `2190433321`, process-tree cap `2000000000`,
mutex `Local\BlindLedgerDirectMaskBuild20260907`. Fresh preflight at
`2026-09-23T03:26:51Z` found a free mutex, zero relevant external processes,
and `4530003968` free bytes; the guard's own preflight was `4530880512` bytes.
The pre-run `git diff --check` exited `0`.

Final v6 source/test SHA-256 values:

- owner `4880160AA34377A0263AAE6597549E914511F0628CECAFDACD7D71E87FCFD8D6`
- independent checker `E595EA269565F2DF7524CDDFE2C878591D616350E7794244FA930517734102A1`
- Mirror `F28FC979CBAD7FA04196860739D814183C5B22C6ABDB445147C1EF8C95A76C5B`
- expected cases `A8D07CDDE31756A17FC8FB397FD0D93681D18C6DD4F722F3B4F7A69AC4E89653`
- acceptance tests `B9960B88B91C0950D112486BE1EF3C2AB1027547713986AB5D798A8B651043C5`

### Formal and system nonclaims

The direct Engine handoff reported its finite CodecLaws proof-chain run failed
with 18 compiler error headers; `CodecLawsCheck` and
`blind_financial_axioms` were skipped (2); 54 warnings remain in the full raw
stdout. No theorem result or proof artifact is established, and the stale
`blind_financial_axioms.exe` is not evidence. Raw stdout (77,980 bytes) SHA-256
`1742153417C0AF4F50609ECAE31615303E8A26940DA01909F202AA1741392E6F` is at
`../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-codeclaws-proofchain-20260923-engine-1790132237849.stdout.log`;
stderr is 20 bytes, SHA-256
`C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F`, exact
text `error: build failed`. Security owns the Lean source repair; State ran
no Lean build.

The v6 correction is locally verified and pending Driver review. It does not
expand the narrow owner-local v5 disposition or establish clock atomicity,
authenticated funding, State approval, recipient cash, payment authorization,
official confirmation, live dispatch, PHI use, executable Lean linkage,
whole-system qualification, or production readiness. Current claims remain
`proofSuiteId=null`, `production_usable=false`, `activation=false`, synthetic,
nonpayment, and non-PHI. No files were staged or committed. Unrelated dirty
and untracked paths, including `build-performance/`, were preserved.

## C05 per-obligation decision package — source-ready (2026-09-23)

- Added a read-only Owner/Mirror per-obligation decision package. Owner reads
  one snapshot and returns the exact current evaluation receipt, case,
  determination/action/outbox acknowledgment, scoped cash/reporting facts,
  approved control-pack/rule identity, authority identity, and paginated typed
  references. No table or policy authority was added.
- The Mirror redacts raw payload/source-byte, content-digest, input-snapshot,
  private-proof, and display-label fields. Acknowledgment includes an explicit
  zero-cash-effect value. Owner pagination is capped at 200 rows and offset
  10,000, with an 8 MiB bounded package output.
- Added an independent read-only database entrypoint that fully verifies the
  owner state and reconstructs the package, rather than accepting Owner output
  as its oracle. It checks receipt digests, typed references, page metadata,
  linked rows, and derived conclusions.
- The hand-derived fixture remains 20 recipients / 100,000,000 cents
  ($1,000,000). H's ACK does not change its 9,700,000 cents cash record or
  300,000 cents shortfall. In the final contradictory-evidence state, the
  intentional `RESOLVED` plus `CONFLICT_VISIBLE` pair is preserved; package
  assessment is `CONFLICTED` with the linked payment, reporting, and conflict
  references and both conflicting amounts.
- Authored focused tests for current/wrong/stale receipts, omission,
  contradictory evidence, pagination/cap, no durable mutation, independent
  reconstruction, Mirror redaction, and v6 TEST restore. No C05 test or
  checker has run. `git diff --check` exited `0`.
- Guarded lane state from direct routing: Security owns current guarded checker
  verification, then Engine owns the ordered proof rerun, then Engine must
  directly hand the clean lane to State. State must not poll or reserve. After
  that direct handoff, perform a fresh guard/mutex/process/resource/log
  preflight and one focused guarded run only.
- HEAD remains `8f75f527ae6717001978ac7401853c2aaae55f2b` (tree
  `05d6df5bf4c36a9e267f2b471a86764a242f227e`). Source edits are within the
  authorized Owner, independent checker, Mirror, expected-case, acceptance,
  and Mirror-test files; `CURRENT_TASK.md` and `STATE.md` were updated for
  this handoff. No stage/commit. Protected `build-performance/` and
  pre-existing unrelated dirty paths were preserved. Two new untracked docs
  appeared during this phase—`docs/SOURCE_RECEIVER_CONTRACTS.md` and
  `docs/STATE_SIDE_OPERATIONS_ARCHITECTURE.md`—and were not touched.

Source/test SHA-256 values at this source-ready handoff:

- Owner `8EEA69734ED1B57A2BEDC4B99FA3F85DB44DD80761CA5668CD1D25D277A44094`
- Independent checker `7630D5DC7BBA486C5CEA74E9226594C4B28D4ECED955189090465986AE703239`
- Mirror `082031E84A899A654BCCED6A1F3C3FD267286FEE20F532FD14C76937652BE1D9`
- Expected cases `248703BEC5DFA3FCA80192E1B1F87BC495E3E2C20F7EE9B08011FE99A044E6C2`
- Acceptance tests `9DD486A361233441E6868862D4665CA34EF7BE7ACBADB53C2E8ECA26A62E442C`
- Mirror tests `8258B0262333278FA75A520837CE000557965309D1F331D9B552C8E8F97E8D4A`

## C05 focused guarded verification — PASS (2026-09-23)

This follow-up supersedes the source-ready statement above that C05 had not
yet run. The direct Engine-to-State handoff was received at a clean idle
boundary. The Engine's fresh proof-workload preflight did not meet its
start estimate; State treated it as no proof-run receipt and launched no
Engine proof targets. Engine proof and formal claims remain unchanged.

Repository boundary at this run: branch rightrail-financial-workflow-20260913,
HEAD 8f75f527ae6717001978ac7401853c2aaae55f2b, tree
05d6df5bf4c36a9e267f2b471a86764a242f227e. The six C05 source/test SHA-256
values matched the source-ready values in the preceding section. Guard
C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\run_guarded_v3.ps1
matched SHA-256
55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D.
Its unchanged policy is reserve 3,221,225,472 bytes, floor 2,190,433,321
bytes (32% tolerance), process-tree cap 2,000,000,000 bytes, and mutex
Local\BlindLedgerDirectMaskBuild20260907.

Fresh State workload preflight passed: free physical memory was
4,026,306,560 bytes; required start was 2,441,239,593 bytes, calculated as
the guard floor plus twice the prior full State run's 125,403,136-byte peak
private use. Relevant process count was 0. The mutex probe acquired and
released. Python 3.11 interpreter and build/log directory existed, and both
designated log paths were absent. Pre-run git diff --check exited 0.

One guarded invocation ran exactly these three methods and no other test
targets:

C:\Users\neers\AppData\Roaming\uv\python\cpython-3.11-windows-x86_64-none\python.exe -c "import os, unittest; os.chdir(r'C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-financial-workflow-20260913'); unittest.main(module=None)" tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_decision_package_tracks_evidence_and_keeps_ack_separate_from_cash tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_v6_decision_package_survives_test_restore tests.test_right_rail_financial_mirror.FinancialMirrorTests.test_c05_decision_package_is_sanitized_bounded_and_ack_is_not_cash

Complete child stderr output (106 bytes):

...
----------------------------------------------------------------------
Ran 3 tests in 1.598s

OK

Child stdout was empty (0 bytes), SHA-256
E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.
Child stderr SHA-256:
DEE8383CB26DAD458DD3F2F10161F6AC6E11F78080E79A2252DA9ECB137FBFE3.
Raw logs:

- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-c05-decision-package-20260923-r1.stdout.log
- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-c05-decision-package-20260923-r1.stderr.log

Guard decisive output: preflight free bytes 4,066,770,944, reserve 3,221,225,472,
floor 2,190,433,321; child self-tests exit7=7 and exit0=0; final child exit 0;
5 live samples; minimum free bytes 4,005,203,968; peak working set
37,163,008 bytes; peak private bytes 21,262,336; cleanup PASS; mutex RELEASED.
Wrapper exit was 0. Post-run mutex probe acquired and released. Final
git diff --check exited 0.

No selected test was skipped and no warning or failure was emitted. The final
working-tree status set was unchanged from preflight: 12 modified tracked paths
and 6 pre-existing untracked paths. C05 source and test files remain the only
code/test changes for this package, with CURRENT_TASK.md and STATE.md updated
to record verification. The protected build-performance/ tree and unrelated
dirty/untracked files were untouched. Nothing was staged or committed. This
verification establishes only the three focused C05 tests; it does not qualify
Lean proofs, the wider system, or production readiness.

## C05 source-only correction handoff — guarded verification pending (2026-09-23)

This entry supersedes the preceding C05 focused guarded PASS as evidence for
the corrected hashes below. Its earlier 3-test pass and raw logs remain valid
for the pre-correction source identities only. No test, checker, guard, build,
compiler, or native/Lean command was invoked for this correction.

The Owner now selects the current delivery action by action revision and the
current determination by resulting revision, each with a deterministic ID
tie-break. The independent checker applies revision ordering in its current
projection and package reconstruction. In historical evaluation-input
reconstruction it resolves snapshotted action IDs to their immutable stored
action revisions. No stored input snapshot or digest contract changed.
Completion-time calculations continue to sort by determination and payment
event times.

The independent verifier bounds and clones the caller decision package before
opening SQLite. Its local cap is 8 MiB minus 512 bytes, with maximum depth 32
and node count 250,000. It counts the compact sorted ASCII-escaped JSON form,
rejects cycles, and returns decision-package:input-limit for byte/depth/node/
cycle limits. Unsupported nested values and keys return decision-package:
input. The independent checker still does not import the Owner.

Mirror removes input_snapshot_digest only from its sanitized decision_package.
Owner evaluation receipts and FinancialMirror.current_evaluation_receipt
retain it. Owner receipt construction and independent receipt verification
were not changed.

Two acceptance test methods were added: a valid clock-rollback chronology
where a later action revision has earlier decision/creation times, and
pre-open rejection of oversized, over-depth, and self-referential package
input. The existing Mirror sanitizer method now asserts digest retention on
the receipt API and redaction in the decision-package view. These tests were
authored but not run: 0 executed, 0 framework-reported skips because no runner
was invoked. One focused guarded packet is deferred until Driver directly
hands State a safe lane after Provider. State did not poll or reserve the lane.

Source-only static checks: git diff --check exited 0 with no output. The
timestamp-based current action/determination search exited 1 with no matches;
revision-based current selection paths were listed. Separate static output
confirmed chronological completion readers remain unchanged. There was no
schema, stored wire/input, authority, or production-claim change. No line or
byte reduction was requested; the correction and its acceptance coverage are
additive.

Repository identity at handoff: branch rightrail-financial-workflow-20260913,
HEAD 8f75f527ae6717001978ac7401853c2aaae55f2b, tree
05d6df5bf4c36a9e267f2b471a86764a242f227e. Final status remained 12 modified
tracked paths and 8 untracked entries. State touched only the authorized
Owner, independent checker, Mirror, acceptance test, Mirror test, CURRENT_TASK,
and this STATE note. The expected-case fixture remained unchanged at SHA-256
248703BEC5DFA3FCA80192E1B1F87BC495E3E2C20F7EE9B08011FE99A044E6C2. Nothing
was staged or committed. The protected build-performance/ directory and all
unrelated dirty/untracked work were preserved.

The two additional untracked Docs deliveries were confirmed by Driver as
separately owned and authorized; both were left untouched:

- docs/FINANCIAL_STAFF_WORKSPACE_ARCHITECTURE.md — SHA-256
  7C897E35D10B5D2E40B9411BF0FED0E45C4B1059104B549AE6CB7C5684E727F6
- docs/SWITCH_TRANSFER_ARCHITECTURE.md — SHA-256
  E8F50FD0B3AA3FAB4CB5F02DB8B5B1D37C41B69E1925F615A525B46EF70D82AC

Source/test SHA-256 before and after correction:

- app/right_rail_financial_owner.py: before
  8EEA69734ED1B57A2BEDC4B99FA3F85DB44DD80761CA5668CD1D25D277A44094; after
  484B4CAAAE0828765081B8E236BC1F39404748AAA32E7F715453615A9753951D
- app/right_rail_financial_owner_independent.py: before
  7630D5DC7BBA486C5CEA74E9226594C4B28D4ECED955189090465986AE703239; after
  E393623867D104B2A9A098586209574A735DCA674272162CD2F1DA61E566B055
- app/right_rail_financial_mirror.py: before
  082031E84A899A654BCCED6A1F3C3FD267286FEE20F532FD14C76937652BE1D9; after
  9027C56D9A1B49C615CD6CDAB0250471346C1767714A095D75A90C940279B51A
- tests/test_right_rail_financial_acceptance.py: before
  9DD486A361233441E6868862D4665CA34EF7BE7ACBADB53C2E8ECA26A62E442C; after
  CC02C55EC2932A2EB1D7A6739D8DF569619FFDB3D54A9054BF0FBD877531A725
- tests/test_right_rail_financial_mirror.py: before
  8258B0262333278FA75A520837CE000557965309D1F331D9B552C8E8F97E8D4A; after
  E5A23AD8AE6D4F340F96FD269446E9AE10815C4987369263ED56F9D1A4020423

Documentation identities: CURRENT_TASK.md before
1077F8BCA45ADF314FAF370FB2FE160C9D3A1E97285BEC662566008A0B7BED54 and after
F964210FA8CF696EFA4456058FC341051ACF2079727ABFBA4A86A3BC9494AC10. STATE.md
before this addition was EA7938EFA5F6E5038BEEA2E1C6ABBAAF0ACFE550158ED7E4D272748509E6467A;
its final post-edit hash is reported in the handoff.

Post-edit line references: Owner current delivery 1632-1634 and package
selection 3290-3299; independent bounded input 489-601, historical revision
binding 2637-2654, current projection 2835-2837, and package selection
3660-3663; Mirror redaction set 48-50; acceptance methods 2873-3004; Mirror
test assertions 163-214.

Read-only tooling warnings and recoveries: initial lookups of ../AGENTS.md and
../WORKSPACE_MAP.md were one parent directory too shallow; the correct Driver
files at ../../AGENTS.md and ../../WORKSPACE_MAP.md were read. An unquoted
PowerShell git rev-parse HEAD^{tree} failed after argument parsing changed the
tree expression; quoting it returned the expected tree above. Two broad patch
attempts failed context verification, and one patch-string parse error
prevented apply_patch from being called. Hash checks confirmed no content
change from those failed attempts; the scoped edits were then applied in
smaller patches. No execution-lane or data warnings occurred.

## C05 guarded verification and post-failure correction — r1 FAIL, r2 PASS (2026-09-23)

This entry supersedes the preceding source-only note's pending-run status and
records both guarded attempts without relabeling r1. The Driver directly
handed State the lane for one run. Guard identity and policy were unchanged:
`run_guarded_v3.ps1` SHA-256
`55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`,
reserve `3,221,225,472` bytes, floor `2,190,433,321` bytes, process-tree cap
`2,000,000,000` bytes, mutex
`Local\BlindLedgerDirectMaskBuild20260907`. The workload-specific threshold
was floor plus twice the prior `125,403,136`-byte State peak private use:
`2,441,239,593` bytes. The guarded lane was not reserved or polled.

### r1 — all five requested methods; one failure

Fresh preflight passed with free physical memory `3,271,307,264` bytes,
relevant process count `0`, absent designated logs, a new/acquired/released
mutex probe, matching source hashes, and `git diff --check` exit `0`. The
guard's actual build directory is beside the wrapper at
`../pq-wide-seed-native-20260913/build-filter-native/acceleration-correction`;
the wrapper defines `$BuildRoot=$ScriptDirectory` and derives its build
directory there. The run suffix was
`financial-c05-source-correction-20260923-r1`.

Exactly these five methods ran in one guarded Command:

- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_decision_package_tracks_evidence_and_keeps_ack_separate_from_cash`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_v6_decision_package_survives_test_restore`
- `tests.test_right_rail_financial_mirror.FinancialMirrorTests.test_c05_decision_package_is_sanitized_bounded_and_ack_is_not_cash`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_current_action_and_determination_follow_revision_after_clock_rollback`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_independent_package_input_is_bounded_before_database_open`

The child and outer invocation exited `1`; four methods passed and the final
method failed. No skips were reported. Complete raw child stderr (the child
stdout file is empty):

```text
....F
======================================================================
FAIL: test_c05_independent_package_input_is_bounded_before_database_open (tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_independent_package_input_is_bounded_before_database_open)
----------------------------------------------------------------------
app.right_rail_financial_owner_independent.IndependentFinancialError: decision-package:input

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-financial-workflow-20260913\tests\test_right_rail_financial_acceptance.py", line 2987, in test_c05_independent_package_input_is_bounded_before_database_open
    assert_rejected_before_open(oversized)
  File "C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-financial-workflow-20260913\tests\test_right_rail_financial_acceptance.py", line 2982, in assert_rejected_before_open
    with self.assertRaisesRegex(IndependentFinancialError, "decision-package:input-limit"):
AssertionError: "decision-package:input-limit" does not match "decision-package:input"

----------------------------------------------------------------------
Ran 5 tests in 4.039s

FAILED (failures=1)
```

Raw r1 child logs:

- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-c05-source-correction-20260923-r1.stdout.log` — 0 bytes; SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.
- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-c05-source-correction-20260923-r1.stderr.log` — 1,384 bytes; SHA-256 `F2207E975CA0837B74B956766863EACCBD8D6978B9A3D4A1589D994A788724E7`.

Complete r1 wrapper transcript, captured from the guarded invocation; outer
`exec_command` exit code was `1`:

```text
PHYSICAL_PREFLIGHT free_bytes=3221684224 reserve_bytes=3221225472 reserve_floor_bytes=2190433321 tolerance_percent=32
LAUNCH label=child-exit-7 pid=24472 command=cmd.exe
LIVE_SAMPLE label=child-exit-7 index=1 free_bytes=3213975552 working_set_bytes=0 private_bytes=0 process_count=0
CHILD_EXIT_STATUS label=child-exit-7 exit=7
LIVE_PHYSICAL_SUMMARY label=child-exit-7 samples=1 min_free_bytes=3213975552 reserve_bytes=3221225472 peak_working_set_bytes=0 peak_private_bytes=0 reserve_floor_bytes=2190433321 tolerance_percent=32
CLEANUP=PASS label=child-exit-7 owned_process_tree=empty
LAUNCH label=child-exit-0 pid=17668 command=cmd.exe
LIVE_SAMPLE label=child-exit-0 index=1 free_bytes=3206574080 working_set_bytes=0 private_bytes=0 process_count=0
CHILD_EXIT_STATUS label=child-exit-0 exit=0
LIVE_PHYSICAL_SUMMARY label=child-exit-0 samples=1 min_free_bytes=3206574080 reserve_bytes=3221225472 peak_working_set_bytes=0 peak_private_bytes=0 reserve_floor_bytes=2190433321 tolerance_percent=32
CLEANUP=PASS label=child-exit-0 owned_process_tree=empty
CHILD_EXIT_CHECK exit7=7 exit0=0
LAUNCH label=Command pid=17684 command=C:\Users\neers\AppData\Roaming\uv\python\cpython-3.11-windows-x86_64-none\python.exe
LIVE_SAMPLE label=Command index=1 free_bytes=3199549440 working_set_bytes=28864512 private_bytes=16986112 process_count=2
LIVE_SAMPLE label=Command index=2 free_bytes=3150684160 working_set_bytes=36622336 private_bytes=20480000 process_count=2
LIVE_SAMPLE label=Command index=3 free_bytes=3153707008 working_set_bytes=37781504 private_bytes=21970944 process_count=2
LIVE_SAMPLE label=Command index=4 free_bytes=3145826304 working_set_bytes=37117952 private_bytes=21372928 process_count=2
LIVE_SAMPLE label=Command index=5 free_bytes=3146649600 working_set_bytes=36646912 private_bytes=20811776 process_count=2
LIVE_SAMPLE label=Command index=6 free_bytes=3143274496 working_set_bytes=45903872 private_bytes=29757440 process_count=2
LIVE_SAMPLE label=Command index=7 free_bytes=3136045056 working_set_bytes=45903872 private_bytes=29757440 process_count=2
LIVE_SAMPLE label=Command index=8 free_bytes=3165835264 working_set_bytes=0 private_bytes=0 process_count=0
CHILD_EXIT_STATUS label=Command exit=1
LIVE_PHYSICAL_SUMMARY label=Command samples=8 min_free_bytes=3136045056 reserve_bytes=3221225472 peak_working_set_bytes=45903872 peak_private_bytes=29757440 reserve_floor_bytes=2190433321 tolerance_percent=32
CLEANUP=PASS label=Command owned_process_tree=empty
RUNNER_FAILURE reason=Command child exited 1
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907
```

Post-r1 relevant process count was `0`; a fresh mutex probe was new,
acquired, and released; `git diff --check` exited `0`. The failure was not a
resource or guard failure. `IndependentFinancialError` subclasses
`RuntimeError`, so the bounded-input dict/list mutation handlers caught and
rewrote the intended `decision-package:input-limit` exception as
`decision-package:input`.

### Narrow source correction and r2 — affected acceptance methods pass

The correction adds `except IndependentFinancialError: raise` before the
`except RuntimeError` iterator-mutation mapping in both input-container loops
at `app/right_rail_financial_owner_independent.py:578` and `:593`. It changes
only exception propagation; it leaves size/depth/node limits, input snapshot,
database-open ordering, schema, and authority unchanged. The post-fix checker
SHA-256 is
`1FD251FBF2A7F121FFE2644B71A125FE6054FDBA3A5C0B743D6C13D3C0350CC9`.
Driver reviewed r1 and explicitly authorized one fresh preflight and one new
affected-method guarded run. Static test-source inspection showed methods 1,
2, 4, and 5 call `verify_decision_package`; the Mirror sanitizer method 3 does
not and its relevant source/test remained unchanged.

R2 used suffix `financial-c05-source-correction-20260923-r2`. Fresh preflight
matched the guard and all five C05 source/test hashes; free memory was
`3,373,367,296` bytes against threshold `2,441,239,593`; relevant process count
was `0`; the mutex probe was new/acquired/released; both r2 log paths were
absent; Python 3.11 and the wrapper's exact build/CMake/CTest paths existed;
and `git diff --check` exited `0`.

The single r2 guarded Command ran exactly these four methods:

- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_decision_package_tracks_evidence_and_keeps_ack_separate_from_cash`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_v6_decision_package_survives_test_restore`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_current_action_and_determination_follow_revision_after_clock_rollback`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_independent_package_input_is_bounded_before_database_open`

Complete child stderr (stdout file is empty):

```text
....
----------------------------------------------------------------------
Ran 4 tests in 3.347s

OK
```

No skips or warnings were reported. The child and outer invocation exited
`0`. Raw r2 child logs:

- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-c05-source-correction-20260923-r2.stdout.log` — 0 bytes; SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.
- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-c05-source-correction-20260923-r2.stderr.log` — 107 bytes; SHA-256 `272E2B5D7198403932883ACAAFCA4DB10CE736E8282933B2AD2D8996B364CC26`.

Complete r2 wrapper transcript; outer invocation exited `0`:

```text
PHYSICAL_PREFLIGHT free_bytes=3364487168 reserve_bytes=3221225472 reserve_floor_bytes=2190433321 tolerance_percent=32
LAUNCH label=child-exit-7 pid=51680 command=cmd.exe
LIVE_SAMPLE label=child-exit-7 index=1 free_bytes=3364085760 working_set_bytes=0 private_bytes=0 process_count=0
CHILD_EXIT_STATUS label=child-exit-7 exit=7
LIVE_PHYSICAL_SUMMARY label=child-exit-7 samples=1 min_free_bytes=3364085760 reserve_bytes=3221225472 peak_working_set_bytes=0 peak_private_bytes=0 reserve_floor_bytes=2190433321 tolerance_percent=32
CLEANUP=PASS label=child-exit-7 owned_process_tree=empty
LAUNCH label=child-exit-0 pid=29640 command=cmd.exe
LIVE_SAMPLE label=child-exit-0 index=1 free_bytes=3353989120 working_set_bytes=0 private_bytes=0 process_count=0
CHILD_EXIT_STATUS label=child-exit-0 exit=0
LIVE_PHYSICAL_SUMMARY label=child-exit-0 samples=1 min_free_bytes=3353989120 reserve_bytes=3221225472 peak_working_set_bytes=0 peak_private_bytes=0 reserve_floor_bytes=2190433321 tolerance_percent=32
CLEANUP=PASS label=child-exit-0 owned_process_tree=empty
CHILD_EXIT_CHECK exit7=7 exit0=0
LAUNCH label=Command pid=30856 command=C:\Users\neers\AppData\Roaming\uv\python\cpython-3.11-windows-x86_64-none\python.exe
LIVE_SAMPLE label=Command index=1 free_bytes=3369267200 working_set_bytes=26546176 private_bytes=12738560 process_count=2
LIVE_SAMPLE label=Command index=2 free_bytes=3347673088 working_set_bytes=36569088 private_bytes=20783104 process_count=2
LIVE_SAMPLE label=Command index=3 free_bytes=3355836416 working_set_bytes=37609472 private_bytes=21946368 process_count=2
LIVE_SAMPLE label=Command index=4 free_bytes=3348488192 working_set_bytes=36691968 private_bytes=20807680 process_count=2
LIVE_SAMPLE label=Command index=5 free_bytes=3344715776 working_set_bytes=45858816 private_bytes=30302208 process_count=2
LIVE_SAMPLE label=Command index=6 free_bytes=3332399104 working_set_bytes=45858816 private_bytes=30302208 process_count=2
LIVE_SAMPLE label=Command index=7 free_bytes=3354009600 working_set_bytes=0 private_bytes=0 process_count=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=7 min_free_bytes=3332399104 reserve_bytes=3221225472 peak_working_set_bytes=45858816 peak_private_bytes=30302208 reserve_floor_bytes=2190433321 tolerance_percent=32
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907
```

Post-r2 boundary check: relevant process count `0`; mutex was new,
acquired, and released; `git diff --check` exited `0`. Repository remains on
branch `rightrail-financial-workflow-20260913`, HEAD
`8f75f527ae6717001978ac7401853c2aaae55f2b`, tree
`05d6df5bf4c36a9e267f2b471a86764a242f227e`, with 12 modified tracked paths
and 8 untracked entries. Nothing was staged or committed. The two Docs-owned
deliveries remained unchanged at SHA-256
`7C897E35D10B5D2E40B9411BF0FED0E45C4B1059104B549AE6CB7C5684E727F6` and
`E8F50FD0B3AA3FAB4CB5F02DB8B5B1D37C41B69E1925F615A525B46EF70D82AC`.
The Current Task record SHA-256 after its C05 update is
`0C832CF627DC4B65EF5E185AA1362D1DAB41A48FE2B081D7077A690B43FF55D0`;
the final STATE.md hash is reported at handoff rather than self-referenced.

Read-only tooling diagnostics and recoveries during this phase: an initial
process-name substring query reported two false positives (the invoking
PowerShell and an unrelated documentation-search PowerShell); an exact
executable/guard-script query then reported zero relevant processes. An
initial build-directory probe incorrectly looked under this app's protected
`build-performance/`; inspection of the wrapper's `$BuildRoot` corrected the
probe to the guard-owned `build-filter-native/acceleration-correction`, and no
execution occurred during the failed probe. One malformed exploratory `rg`
target produced `rg: \AGENTS.md: The system cannot find the file specified
(os error 2)` and a separate broad read-only search was interrupted with
Ctrl+C (exit `1`); no files were changed. Two initial r2 raw-log inspection
commands had a missing quote and exited `1` with empty output; corrected
read-only commands returned both complete logs. One combined final hash/status
command also exited `1` with empty output from a missing quote; the corrected
command returned the final repo identity, status counts, staged count, diff
check, and evidence headings. These were tooling errors, not guard or test
failures. No test was skipped silently.

At the clean boundary, State sent a direct lane handoff to the active `Lean
Engine` task under Driver direction. Engine acknowledged the handoff and began
its fresh preflight, with CodecLaws as its only target if its source/guard and
memory gates pass; that proof result is not yet available in this State task.
State did not reserve the lane. This narrow C05 evidence does not qualify the
broader system, Lean proofs, native/Queue/Composition paths, or production.

## C02/C03 v7 population-manifest source packet — UNVERIFIED (2026-09-23)

The worktree now contains an unverified v7 source/test packet. The last narrow
accepted baseline remains the owner-local synthetic v5 disposition recorded
above. No v7 guarded test, compilation, independent checker batch, native
build, or Lean target ran. The pending lane handoff and fresh preflight remain
required; there was no polling or lane reservation in this phase.

The v7 owner binds each population to an immutable authority-approved exact
roster manifest and current lineage head. It enforces one-to-one binding,
explicit supersession, roster membership during chunked staging, exact
persisted membership at source completion/validation/publication, and
schema-version gates for v5/v6 writes. Supersession and publication serialize
through the owner transaction boundary; published manifests cannot be
superseded. Continuity v7 includes immutable manifest/member/binding rows and
a reconstructable head projection. The independent checker reconstructs
manifest digests, membership digests, approval/authority, lineage, event
ordering, current heads, bindings, and population completion from database and
package inputs. Mirror emits only bounded status/count/digest fields and no
roster or source-owner details.

Static review also found that chunk staging could replace a mismatched
persisted `imported_count` projection with a fresh SQL count. The owner now
rejects that drift before a chunk write and before setting source completion;
the acceptance suite contains a regression case that records the unchanged
database package, item count, and event list. The semantic adapter test fixes
the first-period v1 roster and asserts the established population-object key
set remains unchanged.

The packet is limited to:

- `app/right_rail_financial_owner.py`
- `app/right_rail_financial_owner_independent.py`
- `app/right_rail_financial_mirror.py`
- `tests/rightrail_financial_expected_cases.py`
- `tests/test_right_rail_financial_acceptance.py`
- `tests/test_right_rail_financial_independent.py`
- `tests/test_right_rail_financial_mirror.py`
- `tests/test_right_rail_financial_semantic_adapter.py`
- Maintained status/product docs: `CURRENT_TASK.md`, `STATE.md`, `README.md`,
  and `ARCHITECTURE.md`

No v7 verification result or acceptance is claimed. The previous v5 test
records and source hashes are historical and must not be presented as evidence
for this packet. `docs/IMPLEMENTATION_ROADMAP.md` and
`docs/LEAN_FORMAL_KERNEL.md` were already dirty and were not edited in this
phase. The untracked `build-performance/` executables and untracked
Driver/Docs-owned Markdown files were preserved. Nothing was staged or
committed.

## C02/C03 v7 retained guarded failures and C05/Mirror source continuation — UNVERIFIED (2026-09-23)

This entry updates the earlier v7 packet status. Two guarded attempts ran and
both failed. All r1/r2 stdout, stderr, and complete guard transcripts remain
preserved at the paths and hashes recorded below. No v7 pass or acceptance is
claimed. Later source/test changes remain unverified.

### r1 — 15 methods, 13 passed, 2 failed

Guard SHA-256:
`55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`.
The fresh preflight was `3,151,753,216` free bytes; minimum sampled free
memory was `3,077,791,744`, above the `2,190,433,321`-byte floor. Peak
working set was `40,058,880` bytes and peak private bytes `24,707,072`.
Self-tests were `exit7=7 exit0=0`; cleanup passed; mutex released. The child
and outer invocation exited `1`. Exact child summary:

```text
Ran 15 tests in 5.779s

FAILED (failures=2)
```

No skips or test warnings were reported. The failures were:

```text
test_rehashed_population_history_rejects_invalid_completion_lifecycle
  expected history:population-stage-order; got history:predecessor

test_partial_population_history_binds_persisted_count_through_restart_and_restore
  expected sequence 3; got sequence 4
```

R1 complete raw files under
`../pq-wide-seed-native-20260913/build-filter-native/`:

- `guarded-command-financial-v7-population-manifest-20260923-r1.stdout.log` — 2,546 bytes; SHA-256 `99BC92A03EAA2C29BB4DC04BDFAF92D6103B8E0EBEDD3037206F9C112D28BE52`.
- `.stderr.log` — 5,252 bytes; SHA-256 `39F5C6DC649DE13C2530505995BB129E8E332C7A2F8019CDC203C5A0E0FF96F0`.
- `.transcript.stdout.log` — 2,973 bytes; SHA-256 `6C004385F8A0604CABB3BEA59150AE1DC5517ED0B3B2C585E123C1DDC29495A3`.
- `.transcript.stderr.log` — 0 bytes; SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.

The initial helper correction changed the genesis domain by schema and changed the
expected partial-history sequence to 4. It did not preserve the manifest
registration timestamp.

### r2 — two affected methods, 2 failures

R2 ran only the two affected independent-history methods. Fresh preflight free
memory was `3,136,262,144`; minimum free bytes were `3,076,796,416`, above the
same floor. Peak working set was `32,665,600`; peak private bytes were
`17,678,336`. Self-tests were `exit7=7 exit0=0`; cleanup passed; mutex
released. Child and outer exits were `1`. Exact child summary:

```text
Ran 2 tests in 1.155s

FAILED (failures=2)
```

No skips or test warnings were reported. The raw r2 failures were:

```text
test_rehashed_population_history_rejects_invalid_completion_lifecycle
  expected history:population-stage-order; got population-manifest:event-binding

test_partial_population_history_binds_persisted_count_through_restart_and_restore
  expected history:population-imported-binding; got population-manifest:event-binding
  failing variant: removed
```

R2 complete raw files:

- `guarded-command-financial-v7-population-manifest-20260923-r2.stdout.log` — 485 bytes; SHA-256 `82221A5E7761BAA27770892A6807463CCF8F74E768617640EC78B614898CDC0F`.
- `.stderr.log` — 4,470 bytes; SHA-256 `33B40025F0FD8E515185C43749C6F465A33A2A84CF7F2C58368939953DF42CD6`.
- `.transcript.stdout.log` — 1,986 bytes; SHA-256 `FB571795E7996DFAAEDBD7BB23D97E57E8B7F9B7C1995A05AC1FBB89C8685D9B`.
- `.transcript.stderr.log` — 0 bytes; SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.

The event-binding failure occurs because the test helper retimed the
`POPULATION_MANIFEST` event while the manifest row retains immutable
`registered_at_ms`. The current unverified helper preserves that event
timestamp and uses `base + sequence` for later population events, after the
schema-specific genesis correction.

### Current source-only continuation

After r2, the independent-history fixture helper was corrected as above; no
test has run since. Additional authorized source/test changes now:

- Add C05 contract v2 on v7. The owner includes the published population ID,
  manifest ID/version/digest, exact member ID/count, member digest, published
  status, and internal exact-roster completeness in `population_binding`.
  v5/v6 keep C05 v1.
- Reconstruct the v7 binding inside the owner's single decision-package read
  snapshot and independently rebuild it from the verifier's read transaction.
  The C05 package puts this binding beside the obligation/evaluation receipt,
  determinations, action, and outbox acknowledgment; negative tests alter
  manifest version, digest, and exact member ID, then check restore equality
  plus independent reconstruction.
- Redact population and manifest identifiers/digests/member IDs from Mirror
  status, list/detail, and C05 views; remove aggregate IDs for population
  history events. The safe C05 Mirror block retains only status, completeness,
  source-complete flag, manifest version, and member count.
- Add an exact-roster test that deliberately uses a source digest unrelated
  to local bytes to show that exact membership is an internal caller-asserted
  property. No source bytes, external attestation, approved State roster, or
  independent denominator is present.

The source-authentication and completeness gates remain open: the synthetic
approver/authority fields and source digest are caller assertions; staging
does not authenticate input bytes or values; no separately pinned
denominator evidence exists. Full Continuity exports retain source lineage
for state-side recovery and are not qualified for staff/external distribution;
field-level approval/access controls are not implemented here. No production
or live-authority conclusion follows.

No tests, Python compilation, checker, native build, or Lean target ran after
r2. The Driver reported that the guarded wrapper's required
`Get-CimInstance Win32_OperatingSystem` memory observation now returns
`Access denied` in the managed sandbox. No guarded workload was launched
after that notice. Queue has the finite guarded lane first; State did not
poll, reserve, or launch work against it. Resume v7 verification only after a
fresh safe preflight/memory route and explicit lane handoff.

Repository state at this source/docs handoff: branch
`rightrail-financial-workflow-20260913`, HEAD
`8f75f527ae6717001978ac7401853c2aaae55f2b`, tree
`05d6df5bf4c36a9e267f2b471a86764a242f227e`. Nothing was staged or committed.
The pre-existing dirty protected roadmap/kernel files, Queue/Engine/Security
trees, untracked `build-performance/` executables, and seven untracked
Driver/Docs-owned Markdown files were preserved. This packet remains
unverified and does not claim external State approval, denominator
completeness, live payment, activation, or production usability.
Read-only/tooling diagnostics for this handoff: one initial documentation edit
cell failed at JavaScript parsing before PowerShell launched; it made no file
changes and was rerun successfully. One read of the retained r2 guard transcript
failed with a missing quote and empty output; the corrected read returned the
complete preserved transcript. No workload was launched from either failed
command, and no test was skipped.

## Queue/State mapping receipt boundary — proposed, source/docs-only (2026-09-23)

This continuation preserves r1 and r2 as failures and supersedes the earlier
current-blocker statement about CIM denial. The latest Driver update reports
CIM access works in Driver context; Queue owns the finite guarded lane first.
No State lane handoff or fresh target preflight was received or run here. The
current Driver-root operating authority names v4 guard SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`,
requires target-specific `-MinimumStartFreeBytes`, and waives the former
2,000,000,000-byte aggregate process cap. The 2,190,433,321-byte physical
floor, mutex, process-tree sampling/cleanup, self-tests, and checked exits
remain. The v4 policy supersedes v3 only for future runs; r1/r2 keep their
historical v3 guard identity and actual limits.

The Driver clarified that Profile 12's “state owner” may mean Queue's own
stateful owner, with Queue `issue_batch` generating the 100 proof-operation
references. This does not establish a Profile 12 violation; Profile 12 and its
100-reference protocol remain untouched. Queue proof-operation references,
State population member IDs, and financial obligation IDs are separate
identities. The verified integration gap is the absence of an implemented
receipt binding Queue-local references and Queue/Composition's separate
database transaction to the financial owner's population/obligation
identities. No shared database or live financial acceptance path is claimed.

Static inspection of the State-owned owner, independent checker, Mirror, and
semantic adapter found no Queue mapping-receipt ingestion/verifier. The v7
manifest and C05 v2 bind only State population/member/manifest lineage. The
proposed additive contract
`RR/FINANCIAL/QUEUE-STATE-MAPPING-RECEIPT/v1` would carry a unique receipt ID
and canonical digest; authenticated Queue issuer/schema/Profile 12/batch
identity and canonical digest of the exact 100-reference set, with
order/canonicalization defined by the approved Queue contract; State scope and
population/manifest/version/digest/member-digest; and explicit mapping edges
to State member ID, obligation ID, and applicable obligation revision. It
would require exact-replay `DUPLICATE`, changed-content conflict, explicit
version/predecessor lineage for mapping changes, and durable owner-local
outbox/inbox retry and recovery. Each database would commit only its own
state; the proposal makes no cross-database atomicity claim. This is a
specification only; it is not a current runtime receipt or proof that Queue
references are State financial evidence. ControlPack `source_refs` remain
distinct State policy/source references.

The following remain authority questions, so cardinality and effects were not
implemented: meaning/namespace/order/canonicalization/uniqueness/lifetime of
each Queue ref; the mapping relation and coverage/duplicate-edge rules across
100 Queue refs and 20 State members; receipt issuer and
authentication/trust-root/key rotation/revocation; whether mapping targets a
manifest/member or a published obligation and revision, and when it is
issued; Queue/State acknowledgment, retry, timeout, partial-delivery,
correction/supersession, and compensation rules across the two databases; and
whether acceptance records provenance only or can be consumed as evidence.
It must remain distinct from official determination, action, acknowledgment,
and cash absent separate State policy. No 5:1 or other mapping ratio is
assumed.

No owner/checker/Mirror/adapter API, Profile 12, Queue/Composition database,
or live financial acceptance behavior changed. One read-only broad repository
`rg` search returned Queue test/source match lines; it made no file changes,
and subsequent inspection stayed within State-owned code. No tests,
compilation, checker, native build, or Lean target ran. Current modified
tracked and untracked counts remain as recorded above; no files were staged or
committed.

## C02/C03 and C05 v7 selected guarded verification — PASS (2026-09-23)

This later evidence supersedes the earlier statement that no test ran after r2;
the earlier r1/r2 raw failures remain preserved and unchanged. R3 ran the two
focused independent-history methods. The lifecycle-tamper method passed. The
partial-history method errored because the independent checker correctly
rejected a tampered continuity package with
`history:population-imported-binding`, but the test did not assert that
expected rejection. The r3 child stderr is 2,162 bytes, SHA-256
`513B08B81A4042B011911A91CD4CF462959AB6D682FF8F91F9E48334CC6982A1`; it
reports `Ran 2 tests in 1.459s` and `FAILED (errors=1)`. The source checker's
integrity rule was not changed. The test now wraps the package verification in
`assertRaisesRegex(IndependentFinancialError,
"history:population-imported-binding")`; owner rejection and Continuity
restore-integrity/no-destination assertions remain. R4 verifies this correction.

Engine directly handed the lane to State after a fresh no-run preflight:
physical free `5,042,085,888` bytes, target/effective floor `2,190,433,321`,
mutex absent, zero relevant processes, and exact guard SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`. Each
subsequent v4 invocation also passed its own fresh wrapper preflight and
self-tests (`exit7=7 exit0=0`):

| Run | Selected tests | Preflight free | Minimum free | Peak working/private | Child result |
| --- | ---: | ---: | ---: | ---: | --- |
| r4 focused | 2 | 5,071,097,856 | 5,017,796,608 | 34,787,328 / 19,144,704 | 0; cleanup pass; mutex released |
| r5 regression | 15 | 4,994,174,976 | 4,897,669,120 | 38,580,224 / 22,405,120 | 0; cleanup pass; mutex released |
| r6 C05 binding | 1 | 5,118,107,648 | 5,067,141,120 | 37,142,528 / 21,655,552 | 0; cleanup pass; mutex released |

All runs used `-MinimumStartFreeBytes 2190433321`, physical floor
`2,190,433,321`, nominal reserve `3,221,225,472`, 32% tolerance, and v4 guard
SHA-256 `57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`.
R4's child output is 0-byte stdout (empty-file SHA-256
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`) and
105-byte stderr SHA-256
`4ECF7A9DEEAB5D114E1F41628C9B3BB8AC05922DA2170AB4D8106E282ACD5DEF`:
`..`, `Ran 2 tests in 2.851s`, `OK`. R5 output is 0-byte stdout (same empty
SHA-256) and 120-byte stderr SHA-256
`386EFB1CB2B113C2FC31FF50F24EC592C1A34F0D070B636AE59472DBE5A90A3C`:
`...............`, `Ran 15 tests in 10.287s`, `OK`. R6 output is 0-byte
stdout (same empty SHA-256) and 103-byte stderr SHA-256
`B3283D678D784BC79BD900B0DCBA81C817F890962DD2288064682CE5149E454B`:
`.`, `Ran 1 test in 1.412s`, `OK`. The full per-process guard samples were
emitted inline in the task command outputs; no separate transcript files were
created for r4-r6. No tests were skipped. Across the three invocations there
were 18 passing executions and 16 unique selected method IDs because the two
focused methods also appear in the 15-method set.

The two r4 methods were:

- `tests.test_right_rail_financial_independent.IndependentFinancialCheckerTests.test_rehashed_population_history_rejects_invalid_completion_lifecycle`
- `tests.test_right_rail_financial_independent.IndependentFinancialCheckerTests.test_partial_population_history_binds_persisted_count_through_restart_and_restore`

The r5 15-method set was:

- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_population_import_requires_manifest_without_mutation`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v6_funding_owner_rejects_population_writes_without_mutation`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_population_same_count_substitution_stays_incomplete_and_unpublishable`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_population_manifest_retry_authorization_supersession_and_binding`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_concurrent_population_manifest_supersession_has_one_winner`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_continuity_v7_reconstructs_manifest_and_rejects_tampered_rows`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_population_staging_rejects_imported_count_projection_drift`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_population_count_backpressure_preserves_prior_chunks`
- `tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_population_duplicate_member_is_rejected_before_source_completion`
- `tests.test_right_rail_financial_independent.IndependentFinancialCheckerTests.test_valid_owner_fixture_reconstructs_projection_and_identity`
- `tests.test_right_rail_financial_independent.IndependentFinancialCheckerTests.test_rehashed_population_history_rejects_invalid_completion_lifecycle`
- `tests.test_right_rail_financial_independent.IndependentFinancialCheckerTests.test_partial_population_history_binds_persisted_count_through_restart_and_restore`
- `tests.test_right_rail_financial_mirror.FinancialMirrorTests.test_population_status_reports_manifest_completeness_without_roster`
- `tests.test_right_rail_financial_semantic_adapter.RightRailFinancialSemanticAdapterTests.test_cash_claim_snapshot_is_locked_canonical_and_read_only`
- `tests.test_right_rail_financial_semantic_adapter.RightRailFinancialSemanticAdapterTests.test_snapshot_boundary_rebuilds_against_owner_and_rejects_self_rehashed_tamper`

R6 ran
`tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_v7_population_revision_binding_is_verified_and_restored`.
It checks the v2 package's population binding, independent reconstruction,
manifest-version/digest/member tampering, restored package equality, and
integrity. Owner `decision_package` builds the obligation, receipt, population
binding, and linked rows inside one `_read_snapshot()` (owner line 3959);
independent `verify_decision_package` verifies the owner DB and reconstructs/
compares that package in one read-only transaction (checker line 3950). The
selected tests support this narrow synthetic boundary only.

Current source hashes: owner
`5130AE06B1AB98883AE63F2782F1DF7D14C10BAB93E495AF9E6225746278EE86`,
independent checker
`6B9EBD25F9D6AC84D82CEC0E2437AAD9AF70828B2A9B1D8FA8EA8AB2AD1F60B4`, and
independent test
`FA41DDAF3E2B9B31D76A11B8041B4C94E75578E097D54E08F6BB40A2B88796D5`.
After r6, a fresh no-run probe confirmed guard identity unchanged,
`MUTEX=ABSENT`, and `RELEVANT_PROCESS_COUNT=0`; the lane was handed directly to
Cleanup. Existing dirty work and both protected build-performance executables
remain preserved; nothing was staged or committed. The caller-provided
`source_digest` remains an assertion, not external byte authentication or
denominator proof. No Queue-to-State receipt, 100:20 mapping, shared database,
or cross-database atomicity was implemented or inferred. No full-suite,
production, payment, activation, or system qualification is claimed.

## Lean correction transition — fail-closed source handoff (2026-09-23)

This entry records source changes only. It supersedes the earlier Python
correction mutation status for new reject_offset_and_authorize_correction
requests. The Owner no longer performs the Python determination, claim, case,
action, outbox, recompute, and event writes for this operation. It rejects
before any database mutation when the Engine v1 transition is absent, and it
still rejects if the readiness gate is bypassed.

For pre-existing correction rows, retries now require the evaluation identity
and digest, expected revision, decision time, and deterministic determination
ID. Changed request bindings reject. This remains State-side handling of
previously committed rows; the v1 Engine decision/result path is not wired.

The Engine task supplied the operation identity and the distinction between
the current read-only BLFIN02/BLFRES02 protocol and the new BLFCMD01/BLFCRES1
protocol. It has not supplied the exact new field layout, golden vectors, a
fresh guarded executable SHA-256, or a directly returned guarded lane. No
Engine binary was run. The parent also supplied the convergence requirement to
capture consulted dependencies and durable follow-up identities. The currently
forwarded operation contract does not define the dependency receipt result
fields. No dependency schema or guessed identities were added. The existing
action outbox is the only current durable correction follow-up.

Three focused test methods were added or changed for the gate, owner-level
absence/bypass refusal, and postcommit response-loss/exact-retry/changed-input/
post-ACK behavior. None ran. No test, compiler, checker, build, guard,
preflight, or native/Lean process was invoked for this source-only change.
There are no raw logs or verifier results for it. This is not verification of
the new tests or successful Lean-controlled correction behavior.

Repository identity at this handoff: branch
rightrail-financial-workflow-20260913, HEAD
8f75f527ae6717001978ac7401853c2aaae55f2b, tree
05d6df5bf4c36a9e267f2b471a86764a242f227e. The six focused source/test hashes
are recorded in CURRENT_TASK.md. The semantic snapshot adapter, independent
checker, Mirror, Engine Lean repository, protected paths, and pre-existing
dirty/untracked work were not edited by this source change. Nothing was staged
or committed.

Remaining work is to obtain Engine's direct handoff and exact v1 artifact/wire,
implement the State request/result boundary and atomic accepted-delta apply,
record actual dependencies and the durable follow-up identities from the
transaction's real reads, then run only the scoped correction checks under
fresh v4 preflight. The first correction operation must be locally verified and
the lane handed directly to Driver before the separately authorized next
Continuity optimization slice. proofSuiteId=null, production_usable=false,
activation=false, and the synthetic, nonpayment, non-PHI, dispatch-disabled
boundary remain unchanged.

## Lean correction transition — source adapter continuation, not verified (2026-09-23)

Engine directly returned the finite lane at HEAD
`907e32de63ab0d8133f2a7aff1441b06a1a884e8`. The Engine application source
supplies the BLFCMD01 request layout, BLFCRES1 result layout, consulted
dependency facts, durable follow-up identities, and ordered effects. State now
has a strict candidate encoder/decoder and an Owner accepted-result adapter.
The request captures the authenticated locked snapshot, current receipt,
authority, claim, control pack, complete unique-key observations for action ID,
determination ID, and evaluation consumption, plus their common event
sequence/history head. Result validation binds the exact seven effects,
dependency set, follow-up identities, accepted projection, action/outbox/case,
and event intent. The Owner derives the post-transition BLFIN02 snapshot from
the pre-state, compares the complete bytes with Engine's resulting input, and
decodes the nested BLFRES02 result against that derived snapshot.

The accepted delta is applied under the existing Owner write transaction.
Owner recomputes its determination and action digests, persists the
determination, claim rejection, case, action, outbox, Lean financial result and
evaluation receipt, updates the obligation projection with a revision/current-
evaluation CAS, appends the receipt-enriched event, and checks the persisted
bindings. The correction path does not call Python `_recompute_obligation`.
New successful responses use the existing `CORRECTION_AUTHORIZED` API status;
committed exact retries remain duplicate-only. This source implementation has
not been executed.

All three executable/vector pins remain unset:
`CORRECTION_TRANSITION_ARTIFACT_SHA256=None`,
`CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256=None`, and
`CORRECTION_TRANSITION_RESULT_VECTOR_SHA256=None`. No artifact hash, golden
vector, or accepted executable result is available. The path remains
fail-closed for new correction requests.

Resource evidence: the directly handed-off Engine lane used guarded wrapper
SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`. Its
target-specific start requirement was `4,190,433,321` bytes; the earlier
preflight found `2,896,142,336`, short by `1,294,290,985`, and launched zero
targets. A fresh read-only host snapshot later found `2,585,198,592` bytes free:
`394,765,271` above the physical floor `2,190,433,321`, but `1,605,234,729`
below the target-specific start requirement. Mutex
`Local\BlindLedgerDirectMaskBuild20260907` was absent and the scoped relevant-
process query returned 0. The lane was not transferred to Lean Queue because
the target-specific resource gate remains unsatisfied.

No test, build, compiler, Lean process, or guarded target ran. A local
`git diff --check` was invoked (exit 0); the complete output was two working-
copy line-ending warnings, one each for `CURRENT_TASK.md` and `STATE.md`, that
Git will replace CRLF with LF on a future touch. This is not behavior
verification. No files were staged or committed. Pre-existing dirty/untracked
work and protected `build-performance/` files were preserved. Current claims
remain `proofSuiteId=null`, `production_usable=false`, `activation=false`,
synthetic, nonpayment, non-PHI, and dispatch-disabled.

### Later Driver probe and direct Engine lane handoff

The Driver then reported a later no-run probe with `5,386,178,560` bytes free,
above the documented full Engine start threshold `4,190,433,321`; probe exit 0,
mutex absent, and 0 relevant Lake/Lean/Cargo/CMake/CTest/Clang/link/guard-wrapper
processes. This supersedes the lower-memory snapshot above. State sent the one
lane directly to the existing Lean Engine task
`01a0cb32-559d-7ad1-8dfc-d5933637d0d9`. Engine must perform a new launch-time
v4 preflight; the reported snapshot does not authorize a launch. The requested
sequence is the correction-only guarded target first, followed by broader
checker/KAT targets only if their own current documented start condition still
passes. No guarded target has run from State.

Current focused working-tree SHA-256 identities are recorded in
`CURRENT_TASK.md`: Engine adapter `C9B74B441C3E7BF8DA1CFB2B8F98004D366FE1B1A930D9891C8BF7CE74E615E2`,
Owner `06BF05E098C26D81503CBC922B21D708BCCCB99C8E9D912E9D53332C58DC9548`,
and unchanged semantic adapter `23F6D1FBE59542F9F0B778D0D20236325CC3618017363F86C33BE38A0FC6618F`.
The three focused test hashes are also recorded there; none of those tests ran.
These are source identities, not executable/vector verification.

## Engine correction artifact/vector evidence and State release gate (2026-09-24)

State rechecked the actual Engine Git root
`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\lean-engine-20260913`.
HEAD is `907e32de63ab0d8133f2a7aff1441b06a1a884e8`; the working tree remains
dirty and no Engine file was changed by State. The exact source identities
match Engine's compiled-state table:

| Engine file | Bytes | SHA-256 |
| --- | ---: | --- |
| `CorrectionTransition/Types.lean` | 12,310 | `9D6A5A7F1B086106511D9AA7CFDD2B20EC0514E14780F88229D42BBEE709F03C` |
| `CorrectionTransition/Transition.lean` | 25,674 | `342F3B1DF777095D75FD12970F29DFBC09AC06DCF48147EFF804EBA78E9021AE` |
| `CorrectionTransition/Codec.lean` | 45,575 | `8236E7E14658F7510DE363D120C089A4969B71C4A82FB2AED186956FD3E491FB` |
| `blind_financial_correction.exe` | 6,245,376 | `E911E8844130155E4615D284D6D29A597B6E441DC45101D411EE8422EAE684B9` |

The retained exact vectors are under
`C:\Users\neers\AppData\Local\Temp\engine-correction-vectors-20260923-r2`.
Read-only file hashes were:

| Vector | Bytes | SHA-256 |
| --- | ---: | --- |
| `request.bin` | 3,357 | `13F832E80B93CC55D17ADD29470A2CD789CFCED1CBCF5A055FCBA3ECB927B537` |
| `result.expected.bin` | 5,589 | `312AB06C76D6F6F2F40CF93F9EE37DA328161B733FE7D5567E0694B85D3AE18E` |
| `result.actual.bin` | 5,589 | `312AB06C76D6F6F2F40CF93F9EE37DA328161B733FE7D5567E0694B85D3AE18E` |
| `reuse-request.bin` | 9,887 | `DD7DDC27FEEDFDFD26540AB6B1F7D37E6BE49768583FB1EA3AB02F85C8390DC6` |
| `reuse-result.expected.bin` | 53 | `8C50EC33F30B520CC7452C3618577228B6B51B59B68A1935549461FAD2615379` |
| `reuse-result.actual.bin` | 53 | `8C50EC33F30B520CC7452C3618577228B6B51B59B68A1935549461FAD2615379` |
| `run-vectors.cmd` | 859 | `B3360C71FA9F8337096A3E111A633A9B3CF1CC6B67F0AAA9B2F130FAE334982B` |

Engine's `STATE.md` records the exact final comparisons:

```text
VECTOR_COMPARE=result.expected.bin EXPECTED_BYTES=5589 ACTUAL_BYTES=5589 BYTE_FOR_BYTE_EQUAL=True MAGIC=424C464352455331 EXPECTED_SHA256=312AB06C76D6F6F2F40CF93F9EE37DA328161B733FE7D5567E0694B85D3AE18E ACTUAL_SHA256=312AB06C76D6F6F2F40CF93F9EE37DA328161B733FE7D5567E0694B85D3AE18E
VECTOR_COMPARE=reuse-result.expected.bin EXPECTED_BYTES=53 ACTUAL_BYTES=53 BYTE_FOR_BYTE_EQUAL=True MAGIC=424C464352563031 EXPECTED_SHA256=8C50EC33F30B520CC7452C3618577228B6B51B59B68A1935549461FAD2615379 ACTUAL_SHA256=8C50EC33F30B520CC7452C3618577228B6B51B59B68A1935549461FAD2615379
```

The corresponding final vector-exec stdout/stderr files are each 0 bytes with
the empty SHA-256; the equality lines above are retained in Engine `STATE.md`.
State independently rechecked the actual and expected file sizes/hashes. The
TEMP cleanup inventory remains present: Engine records cleanup skipped after
one Windows command-line-length failure and two automatic-review rejections;
State removed nothing.

The final narrow build raw files are
`../pq-wide-seed-native-20260913/build-filter-native/guarded-command-engine-correction-runtime-narrow-20260923-r6.stdout.log`
and `.stderr.log`. The command exited `0`, built 32 jobs, and emitted 1,013
stdout bytes/SHA-256
`085D480883A473D24EF72C399742A1421E0E07F8FB3B69EC4FF294702F9FC4EF`; stderr
was 0 bytes/empty SHA-256. The complete substantive warning was:

```text
warning: BlindLedger/Financial/CorrectionTransition/Transition.lean:46:5: Variable name `bindings` is not explicitly referenced.

Hint: The binding can be removed (if unused) or named `_` (if used implicitly). Alternatively, prefix the name with `_` to silence this warning:
  [apply] _bindings

Note: This linter can be disabled with `set_option linter.unusedVariables false`
```

Final correction/reuse KAT raw files are
`../pq-wide-seed-native-20260913/build-filter-native/guarded-command-engine-correction-transition-kat-20260923-r2.stdout.log`
and `.stderr.log`: exit `0`, 32/32 gates, stdout 2,740 bytes/SHA-256
`DE2F1616767FFEE1DA521476F18AF64EA907F7E33100577FDE8B6D2A14163019`, stderr
0 bytes/empty SHA-256. The complete stdout is retained in that raw file. The
earlier r1 KAT failure is also retained: exit `74`, 31/32 gates, stdout 2,696
bytes/SHA-256 `F4242527AC1485A2A0A039E8747DA9E00245F57D52EFEDBC1BBFB2932198F600`,
stderr 50 bytes/SHA-256
`DA5F1EE11009D7EA501E3ADFE1FCF3FE6FADF2CE5311F0FCCCCEECEDA4D20BD5`; the only
failed gate was `owner_domain_digest_vectors`. Engine corrected its source and
the final r2 KAT passed. Engine `STATE.md` retains earlier corrected compiler
failures and their exact raw-log identities: narrow r1-r5 (106, 16, 18, 18,
and 11 error lines respectively), full CLI r1 (4), and vector helper r1 (7).

### State source review and unmet handoff

Read-only source review confirmed the Python BLFCRES1 mutation parser follows
Lean `readOptionalMutation` field order. The accepted Owner helper performs
all database effects inside the existing `_write()` `BEGIN IMMEDIATE`
transaction and validates the returned input/result before mutation. This is
source inspection only; State has not exercised the executable, persistence,
retry, or rollback path.

The State correction pins remain `None` in
`app/right_rail_financial_engine.py:34-36`; `require_correction_transition_v1`
still rejects new calls. Source use of the request/result vector constants is
currently only a non-`None` gate at lines 807-809; no call site checks their
length or compares them to vector bytes. The successful-path acceptance helper
also constructs `FinancialOwner` without a release. Before claiming a bound
State release, add exact vector identity assertions to the integration test
fixture and pass an explicit immutable correction release to only the scoped
successful-path Owners; keep the default fail-closed.

The Engine task is idle, latest turn `01a0d1ad-2ec5-7de2-b3e8-e5d568ca9500`
completed without an assistant handoff message. Its prior handoff targeted the
separate Driver task `01a0cb35-a28d-7ed1-9bfd-01e31ce68f30`, not this State
task `01a0cb32-5c56-7073-a400-2f084a32566f`. State sent explicit status and
handoff requests to Engine; no direct release to this State task has arrived.
No fresh State v4 target-specific preflight or current State mutex/process
snapshot was taken. State targets launched: `0`; focused Owner transaction
tests run: `0`. The four identified candidate methods remain unrun:
`test_case_04_reject_and_authorize_correction`,
`test_v5_action_requires_current_evaluation_and_exact_retry_identity`,
`test_case_05_ack_without_cash_and_immutable_action_retry`, and
`test_correction_refuses_missing_or_bypassed_transition_without_mutation`.
Reason: the required Engine-to-State release and fresh State launch admission
are not present. No code was changed, staged, or committed; `build-performance/`
and all other pre-existing State dirty/untracked files remain untouched.
Nonclaims remain `proofSuiteId=null`, `production_usable=false`,
`activation=false`, synthetic, nonpayment, non-PHI, and dispatch-disabled.

## Direct Driver release and State integration preparation (2026-09-24)

The Driver directly transferred the finite lane to State task
`01a0cb32-5c56-7073-a400-2f084a32566f`. This supersedes the preceding
Engine-to-State wait requirement. Driver handoff evidence reports the active
v4 guard SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`, Engine
correction executable SHA-256
`E911E8844130155E4615D284D6D29A597B6E441DC45101D411EE8422EAE684B9` and
6,245,376 bytes, 4,955,971,584 bytes of free physical memory, the shared
mutex absent, and zero relevant processes. This is handoff evidence only;
State still requires its own fresh no-run snapshot and v4 admission.

Source preparation pins the artifact size/SHA and exact request/result vector
SHAs in `FinancialCorrectionTransitionRelease`; admission rejects any
identity mismatch. The release remains frozen, and Owner construction remains
fail-closed by default. Only successful-path acceptance fixtures explicitly
construct it after hashing the retained executable and checking the retained
request/result bytes and byte-for-byte expected/actual result equality. The
integration continues through the contained process runner and existing
`BEGIN IMMEDIATE` Owner transaction, including precommit rollback and
postcommit exact-retry handling.

Planned guarded packet: the release immutability/identity tests, CASE04,
CASE05, CASE08, CASE10, v5 exact retry/conflict, and missing/bypassed release
refusal. Target-specific
`-MinimumStartFreeBytes=2400000000` is documented for the Python/SQLite
integration packet with its pinned 6.2 MB Engine executable; the required v4
physical-free floor remains 2,190,433,321 bytes. No State preflight, test,
Owner transaction, or guarded target has run for this direct release yet.

The preceding correction-release gate statement is historical and is
superseded here. Claims remain `proofSuiteId=null`, `production_usable=false`,
`activation=false`, synthetic, nonpayment, non-PHI, and dispatch-disabled.

## Direct State correction transition — final verified evidence (2026-09-24)

This entry closes the finite State integration lane. Git identity remains branch rightrail-financial-workflow-20260913, HEAD 8f75f527ae6717001978ac7401853c2aaae55f2b, and index tree 05d6df5bf4c36a9e267f2b471a86764a242f227e. Nothing was staged or committed.

The lane changed these files: app/right_rail_financial_engine.py, app/right_rail_financial_owner.py, tests/test_right_rail_financial_engine.py, tests/test_right_rail_financial_acceptance.py, README.md, ARCHITECTURE.md, docs/RIGHTRAIL_FULL_STACK_TARGET.md, CURRENT_TASK.md, and STATE.md. Owner binds the Engine result to the exact derived post-transition financial snapshot before mutation. The expected snapshot derives claimed adjustment, case status, and delivery status from the validated transition delta. The path remains inside the existing BEGIN IMMEDIATE transaction and does not call Python _recompute_obligation.

### Final selected verification

Fresh preflight log: ../pq-wide-seed-native-20260913/build-filter-native/state-correction-integration-20260924-r7.state-snapshot.log, 771 bytes, SHA-256 4D30E3AB9E90C0AEADC133F386B95281EE2FAF41C911044593318D25927322C8. It records the expected branch/HEAD/index tree, 2,400,000,000-byte target start floor, 2,190,433,321-byte physical floor, 4,603,625,472 bytes free, exact v4 guard SHA, mutex absent, zero relevant processes, planned logs clear, and STATE_PREFLIGHT=PASS.

Guarded command: python -m unittest -v with PYTHONPATH set to this checkout and PYTHONDONTWRITEBYTECODE=1, selecting these nine tests:

~~~text
tests.test_right_rail_financial_engine.RightRailFinancialEngineTests.test_correction_transition_release_is_immutable_and_pins_artifact_and_vectors
tests.test_right_rail_financial_engine.RightRailFinancialEngineTests.test_correction_transition_gate_rejects_missing_and_wrong_release_type
tests.test_right_rail_financial_engine.RightRailFinancialEngineTests.test_correction_transition_digest_accepts_owner_bytes_and_checked_hex
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_case_04_reject_and_authorize_correction
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_case_05_ack_without_cash_and_immutable_action_retry
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_case_08_revision_race_one_winner_one_stale_loser
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_case_10_interrupted_import_restart_and_disabled_dispatch
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v5_action_requires_current_evaluation_and_exact_retry_identity
tests.test_right_rail_financial_semantic_adapter.RightRailFinancialSemanticAdapterTests.test_correction_refuses_missing_or_bypassed_transition_without_mutation
~~~

Complete child test result:

~~~text
Ran 9 tests in 9.650s

OK
~~~

Guard r7: self-test exits 7 and 0; target exit 0; CLEANUP=PASS; MUTEX=RELEASED. It sampled 18 target-process boundaries, minimum free memory 4,395,999,232 bytes, peak working set 89,157,632 bytes, and peak private bytes 57,384,960 bytes. Exact process-boundary output:

~~~text
PROCESS_BOUNDARY precommit returncode=73 stdout='PHASE=BEFORE_REJECT\nPHASE=PRECOMMIT_AFTER_MUTATION\n' stderr=''
PROCESS_BOUNDARY postcommit returncode=74 stdout='PHASE=BEFORE_REJECT\nPHASE=POSTCOMMIT_AFTER_COMMIT\n' stderr=''
~~~

Raw final integration logs:
- state-correction-integration-20260924-r7.runner.stdout.log — 4,240 bytes, SHA-256 0AE106A965E9A3C919F8140B7B544FC5D5198BED820769883BD5FAB1FA1C6F98
- state-correction-integration-20260924-r7.runner.stderr.log — 840 bytes, SHA-256 018966BF53CB60E3BE45739D0B615E36EC0CD64FB2DC331E24320CE44F76DDFF; three completed PowerShell progress records, each “Preparing modules for first use”; no warning or error text
- guarded-command-state-correction-integration-20260924-r7.stdout.log — 230 bytes, SHA-256 DE792E063EA22A4B1E6AA7172E789871AB9B96A9BF70E4466C26F1B73E6A3429
- guarded-command-state-correction-integration-20260924-r7.stderr.log — 2,027 bytes, SHA-256 C5273CBE5CFDB49E85CC4A21175476E0A7DB88341907CC1617B4C1DA6B6A738C; contains the complete nine-test output above and no warning

Wrapper smoke r9 passed with a fresh 2,400,000,000-byte start-floor preflight: v4 self-test exits 7/0, where.exe cmd.exe exit 0, CLEANUP=PASS, MUTEX=RELEASED. Snapshot SHA-256 00932FA6F0E9E095F3E334A82F55240397BB8FFD029EBA9FC5EBDAF18A124847; runner stdout SHA-256 0B056D80E87FAC09D06F6C6C412D25FC704C6D362DA4BEDE22743CD16B102963; child stdout was 29 bytes, SHA-256 97D597793EC8307B71F3CFB8A6754BE45BF4C548914367F4DC9AF315C3A93D9B, and child stderr was empty. Its guarded command stderr has only the successful self-test/cleanup record.

Postrun snapshot: ../pq-wide-seed-native-20260913/build-filter-native/state-correction-integration-20260924-r7.postrun-snapshot.log, 649 bytes, SHA-256 08AE77EFA719130823142F0515012F4A9D203CEF6A0CB2303E8E286854F89C6B. It records 4,624,928,768 bytes free, mutex absent, zero relevant processes, and the original branch/HEAD/index tree.

### Retained integration failures and diagnostic evidence

Every failed integration run r1-r6 retained its raw runner and guarded-child output in ../pq-wide-seed-native-20260913/build-filter-native. Each v4 guard completed self-tests 7/0, recorded the child exit as 1, reported CLEANUP=PASS, and released the mutex. Test counts and exact output identities:

~~~text
run  tests  failures/errors       runner stdout bytes and SHA-256                                            guarded child stderr bytes and SHA-256
r1   8      3 failures/3 errors   3417 A37C31AB657D4AC981DA9BA0F4CB23246F60DB7DDC832567A6980C5BCDC392EC  9736 832D1709043FEC04E1CC23EE56BF2FCA70C73D7870112135B485F8A24676A752
r2   8      2 failures/3 errors   3294 00258C416E80BA080B40A2092CD04A6CA079FEA156BDEF2B9BA28A40EA0D7723  8757 4FC5EC9381DEE58D4FED3AA37503B240E002555779AB3775883C000E206D5455
r3   9      2 failures/3 errors   3418 3ED7B5278F7A4CD81BFB346E4EE192A26AEBB1BC13E7809F7362E3888B9D7C65  8873 43E31D131E36C77E7D6D2AADFE940968604B4DEBB56E2E019450774BAEAF0899
r4   9      2 failures/3 errors   3419 8CEBA6CD1AD3810259FE851518CBFE289DF28D4F056F56FE8D02E7F0DDEF529F  9969 4038FA7F184E3A52A732391F2F6DA2E20C55520F961F00BA16D8AC0FAB2B04D2
r5   9      2 failures/3 errors   3417 2CE803AE0D56DBFD757F95ACD06D2525DECAF9F103F01DB47DBF0D288C41FE5C  9969 2EB035C604A5E96F47AD1183AD6CBEC900FD3ED59D34701C0F76073CF726DB53
r6   9      2 failures/3 errors   3295 80849205773EED527973FB0691854A6D16B17D5F2D6A165378A79CADA62FAFF1  9969 8CE489670D4DE9836337143BCC8BE93E74417AC5B0688F22B9E176C08BA5581B
~~~

In r1-r2, CASE04, CASE05, and CASE10 errored with correction_transition_failed. r1 also failed CASE08, the v5 retry expectation, and the missing/bypassed-transition expectation. r2 failed CASE08 and the v5 retry expectation. In r3, CASE04/05/10 reached the Lean transition but failed with evaluation_revision_conflict; the Lean result was REJECTED/EVALUATION_CONFLICT with unresolved CURRENT_EVALUATION_BINDING because the input timestamp was 1774828800036 while the saved receipt timestamp was 1774828800035. The input was corrected to bind the receipt timestamp. In r4 the mapped result failed with correction_result_input_binding; diagnostic decoding reported lowercase determinations_0_authority_digest where the semantic codec expects uppercase hex. The six emitted digest encodings were corrected. In r5 the 2,327-byte expected BLFIN02 input and Lean resulting input were byte-identical, both SHA-256 2C2541B901019C70EA00C36166B83B720C18F83669E1034B0ED66FCF7C285645, but nested BLFRES02 validation rejected stale result_claimed_adjustment_cents. The expected claimed projection was corrected for the rejected claim. In r6 the remaining nested mismatch was result_case_status; expected case and latest-action delivery projections were corrected. R7 passed.

Diagnostic packet raw output hashes:
- d1: stdout BA4A9E4EE9DA21A29B965E77592E39E150AB00ACD2C7FA2561154C27FF6435E1; stderr C02675A624D4A665D30682C1BF8931E89FA165AF906CDA196C36BA38EC6CE229; engine_correction_authority_digest
- d2: stdout 9D108C42FF62A026A3D71A1B39385EB1DBD5A63A795B504B18C4B0AE5A00564F; stderr 630773B07B195A350001698A2747690D17B161B28064FEE513F856C6F2F72ED5; receipt/input evaluation timestamps differ by one millisecond and Lean reports EVALUATION_CONFLICT/CURRENT_EVALUATION_BINDING
- d3: stdout 29C0580F30F389D3FAF1A36EDC9E8E57744AFAD4B9607432F003225A88B6D786; stderr 48725CD8C94A4D4A68B9DEEA3164242B7012F8A53A9F8EC629B332B7DA86D68D; engine_correction_result_input_delta
- d4: stdout 9FDBCB234B12D0BD6C0E3C16A0DDCFD84757307959B7A4B6C3DEB09AB54FE76F; stderr AB2C877C1E6A89EDBC73DD9866B7493EA0C7BEEE0BA4B9B0227D7615A45E5F2C; determinations_0_authority_digest codec mismatch
- d5: stdout ECCA4FED0A6980CAB3035970889C74B6B7B3111034B71D76E270EABBD0033B4C; stderr ED68957C1E817A4BE2BF5378CA4751CD7AF7E152A437DCD023573C8EE6EEA25F; equal expected/actual BLFIN02 input hashes and no first differing byte, followed by nested result mismatch
- d6: stdout C6148A8685608304EEE476E9212126521BDD71F7B9D9D02D369A1C23458F55CB; stderr 0F4F80B67A57741902356BBC702E50B9BB4EEF55076D55301E69059340B29093; result_claimed_adjustment_cents
- d8: stdout 67C761DF34996A4B80B7DB39DDE9D691AC7FF5608272EC48F8C8CAC6EE308184; stderr 89838340B086C21B664C8EC86B262F4DC8C334D5A5184E9182D51501ACF71E7B; result_case_status

Other retained setup failures: the r3 State preflight snapshot passed, but the v4 wrapper invocation then failed before target start with “A positional parameter cannot be found that accepts argument '0'.” Its 405-byte runner stderr SHA-256 is F20DDDBDD1472EC238558D8E715A3448C9C2DFD418C3B26ED065BABBEB721F6E; runner stdout is empty (SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855). Diagnostic helper r7 failed PowerShell parsing before guard start (“Missing expression after ','” and “Unexpected token 'import'”); runner stderr SHA-256 61631D493C6FD9802DAC0F87E77EB739B760D77BF64B94E9E43C5AB18274011D and stdout empty (SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855). Guarded diagnostic r8 ran one test and exposed result_case_status; stdout SHA-256 67C761DF34996A4B80B7DB39DDE9D691AC7FF5608272EC48F8C8CAC6EE308184 and stderr SHA-256 89838340B086C21B664C8EC86B262F4DC8C334D5A5184E9182D51501ACF71E7B. State wrapper r8 failed before v4 start because Start-Process could not find the assumed $PSHOME\powershell.exe; no guard, self-test, child, mutex, or target process started. The 383-byte launch-error record SHA-256 is C211608F8AD756A752713F1037866252506714A5B298E7547F9C066760CC40A5. No failure log was overwritten.

### Scope and nonclaims

Selected tests skipped: 0. No broad suite, compiler, or formal proof was run in this finite State lane. The semantic adapter, independent checker, Mirror, Queue, Composition, and Lean sources were not changed for this lane. The protected build-performance/ directory was not touched. The checkout has additional pre-existing dirty and untracked work; it remains unstaged and untouched by this handoff. No commit was created. Claims remain proofSuiteId=null, production_usable=false, activation=false, synthetic, nonpayment, non-PHI, and dispatch-disabled. Handoff message sent to Driver task 01a0cb35-a28d-7ed1-9bfd-01e31ce68f30 after final verification.

## State continuity admission and correction follow-up — verified bounded lane (2026-09-24)

### Scope and invariants

This later finite State lane modified only the authorized owner, independent checker, Mirror, acceptance/Mirror tests, and four maintained Markdown authorities. It did not change the prior direct Engine correction lane. Branch remains rightrail-financial-workflow-20260913 at HEAD 8f75f527ae6717001978ac7401853c2aaae55f2b; index tree remains 05d6df5bf4c36a9e267f2b471a86764a242f227e. No file was staged or committed.

The v6/v7 owner now maintains the private SQLite table right_rail_continuity_admission with one table_name, row_count, and row_bytes record per exported table. Its exact shape is checked against SQLite PRAGMA table_info notnull metadata. The table is not included in the Continuity payload. TEMP triggers on the owner write connection update row counts and canonical exported-row byte totals in the same transaction as each exported-row insert/update/delete. Before COMMIT, _write calculates the exact canonical package size from that cache and rejects a row-count or 8 MiB package overflow. It no longer serializes all exported rows on every unrelated write. The 10,000-row limit and 8 MiB package cap are unchanged; v5 behavior is unchanged.

Opening an old v6/v7 store prevalidates schema version, configuration scope, dispatch/egress mode, owner and authority identity, genesis, and anchor before migration. Under BEGIN IMMEDIATE, it creates and backfills the cache, checks the package bound, and commits. Owner reopen and the independent verifier recompute counts and canonical row bytes from the source tables, then compare the exact cache and independently computed package size. Continuity format and payload table sets remain unchanged.

An accepted correction event now has a durable correction_followup v1 extension appended in the same transaction as its existing history, evaluation, determination, case, action, and outbox changes. The extension binds the accepted Engine artifact, Control Pack, trusted authority, input and result evaluation receipts, determination digest, evidence bindings, dependency families, bounded read observations, and intended outputs. Owner derives CURRENT, REOPENED, or REVIEW_REQUIRED from the correction event and one current decision package. Mirror builds the explanation, state report, and corporate-safe support payload from that package, and drains event-backed follow-ups through a bounded repeatable page. Acknowledgment remains distinct from cash; a later acknowledgment reopens follow-up review. The focused CASE10 test confirms recovery around both precommit and postcommit process exits and repeat drain behavior.

### Final guarded verification

Fresh State preflight snapshot: ../pq-wide-seed-native-20260913/build-filter-native/state-continuity-admission-followup-20260924-r6.state-snapshot.log, 2,197 bytes, SHA-256 50A90624938E7929BBEB80F04DFF2C0454F828C8EF834F688D9A465B868C5454. It records the expected repo, branch, HEAD, index tree, 29 status entries, target start floor 2,400,000,000 bytes, physical-free floor 2,190,433,321 bytes, 3,955,126,272 bytes free at start, exact v4 wrapper SHA-256 57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB, mutex absent, zero relevant processes, and planned logs clear. The snapshot preserves all nine authorized source/test/document hashes and both protected executable hashes.

Command: python -m unittest -v under guarded v4, with PYTHONPATH set to this checkout and PYTHONDONTWRITEBYTECODE=1. Selected methods:

~~~text
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v6_continuity_admission_migration_prevalidates_identity
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v6_continuity_admission_cache_is_independently_recomputed
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v6_continuity_admission_row_cap_rolls_back_all_deltas
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v7_continuity_admission_row_cap_rolls_back_all_deltas
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v6_continuity_admission_cost_tracks_changed_work
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v6_continuity_package_cap_is_checked_before_commit
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_case_04_reject_and_authorize_correction
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_case_10_interrupted_import_restart_and_disabled_dispatch
tests.test_right_rail_financial_mirror.FinancialMirrorTests.test_correction_followup_outputs_resume_and_reopen_through_mirror
tests.test_right_rail_financial_mirror.FinancialMirrorTests.test_c05_decision_package_is_sanitized_bounded_and_ack_is_not_cash
tests.test_right_rail_financial_mirror.FinancialMirrorTests.test_continuity_export_validate_restore_restart_and_readback
~~~

Complete raw unittest result (the 11 method lines are preserved in the linked raw log):

~~~text
Ran 11 tests in 78.721s
OK
~~~

The test stderr is guarded-command-state-continuity-admission-followup-20260924-r6.stderr.log, 2,317 bytes, SHA-256 C51F70D539E64840AA70B65A4A1DB97E64DEC2E38725D1F68DA5BA15ABABF0F2. Child stdout is guarded-command-state-continuity-admission-followup-20260924-r6.stdout.log, 1,379 bytes, SHA-256 C8B0E888AC872C7D4C324A1DD277F8397EFAB4817EF6276274208D3AA9DD350A. It preserves the performance record and exact process-boundary evidence:

~~~text
PROCESS_BOUNDARY precommit returncode=73 stdout='PHASE=BEFORE_REJECT\nPHASE=PRECOMMIT_AFTER_MUTATION\n' stderr=''
PROCESS_BOUNDARY postcommit returncode=74 stdout='PHASE=BEFORE_REJECT\nPHASE=POSTCOMMIT_AFTER_COMMIT\n' stderr=''
~~~

The one-run synthetic timing medians (three samples per cell) were:

| Unrelated funding rows | Package bytes before samples | Full package preview median (ms) | Incremental commit median (ms) |
| ---: | ---: | ---: | ---: |
| 0 | 2,676 | 12.477 | 15.634 |
| 250 | 614,819 | 39.232 | 22.568 |
| 1,000 | 2,451,572 | 121.397 | 34.731 |
| 3,000 | 7,351,572 | 317.104 | 65.605 |

These are bounded local observations from this fixture, not an SLA or production capacity claim. The measurement method and each raw sample are in the child stdout log.

Guarded v4 raw summary: child exit 0; 134 resource samples; minimum free bytes 3,745,914,880; reserve 3,221,225,472; peak working set 154,206,208 bytes; peak private bytes 136,974,336; physical floor 2,190,433,321; CLEANUP=PASS; MUTEX=RELEASED. Runner stdout is state-continuity-admission-followup-20260924-r6.runner.stdout.log, 18,729 bytes, SHA-256 A1C313569F4C2B26AC4BF3ED6CE9FC951410BB5838113172D5B8788D24D0B7D4. Runner stderr was empty (0 bytes; SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855). Selected methods skipped: 0.

Corrected post-run verification: ../pq-wide-seed-native-20260913/build-filter-native/state-continuity-admission-followup-20260924-r6.postrun-verification.log, 3,329 bytes, SHA-256 955B28EEB3D45C14D22B10F6197210A29C7B42B7F6905FE56AEAC28F59E41024. At that post-run checkpoint, before this documentation update, it confirms the same branch, HEAD, index tree, 29-entry status and status hash as preflight; all nine allowed-file hashes and both build-performance executable hashes match preflight; v4 wrapper identity matches; no relevant process remains; mutex is absent; and the test child exited 0 with cleanup pass. Protected executables retained these exact hashes: direct_mask_fixture_source_performance.exe E07865D9CE6C2644142D3EA61030BD308D5BBD09FE861C630CC5EEBE1F3FE5D9; dm_pipeline_verifier_cli.exe F35F6AF28EC2D269831CFB6BDD1C2414D439FFEC2B26C73CC39495720D9B9E5D.

### Retained pre-final attempts, failures, and corrections

No failure log was overwritten. These are the exact outcomes; preflight stops and wrapper setup failures launched no test methods.

| Attempt | Outcome and decisive evidence | Preserved raw evidence |
| --- | --- | --- |
| r1 | State preflight STOP: repo_identity_match=False because Git printed the same root with forward slashes while the expected path used Windows separators. Other recorded gates passed; 3,238,785,024 bytes were free, mutex absent, and no relevant process was active. No v4 target ran. | state-continuity-admission-followup-20260924-r1.state-snapshot.log; 1,749 bytes; SHA-256 9483DC71E7547FC93B35D8B94B12C6832A51D2B4B296CCD8E482F4C58142C6B0 |
| r2 | Fresh preflight passed with 3,729,956,864 bytes free, but nested PowerShell argument binding stopped before v4 child launch. Exact error: “Parameter cannot be processed because the parameter name 'm' is ambiguous. Possible matches include: -Mode -MinimumStartFreeBytes.” No test methods ran. | state-continuity-admission-followup-20260924-r2.state-snapshot.log; 1,876 bytes; SHA-256 9896C1B081EE14ED8F62BCD7AAF3799F8B009074DF6EC5742F59B9D262DAEB18. Runner stdout empty, SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855; runner stderr 463 bytes, SHA-256 A41B015FD61B270BDD01776272F7D9DE6D38B0118EFC52CEDD5A077ACE4EBB0E. |
| r3 | Guarded packet ran 11 tests in 2.444s and returned FAILED (errors=11), all continuity_admission_schema. Both owner and independent cache-shape checks read PRAGMA table_info index 5 (pk) while comparing against notnull=1. Corrected both checks to read index 3. No skips. Guard child exit 1; minimum free bytes 4,087,898,112; CLEANUP=PASS and MUTEX=RELEASED. | Snapshot 1,876 bytes, SHA-256 22F39CFBBEC2BA04194059283A3D63E288964E35ECCAACE879FC117D2FBA22BE; runner stdout 3,046 bytes, SHA-256 978129CC8676181DA2DC3FE7437C24625016D23E1579B80559C85D06F33006FD; runner stderr and child stdout empty, each SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855; child stderr 25,416 bytes, SHA-256 03B7C12D96C88802AC84A3B03FD388AAF2C1268401C1409EAE9124C23030BFE1. |
| r4 | 11 tests in 91.877s: FAILED (failures=1, errors=5); no skips. Migration prevalidation returned schema_version_incompatible for a same-version scope mismatch where the test required schema_identity; five correction paths exposed KeyError: evidence_bindings because _insert_evaluation intentionally returns only receipt digests and result fields. Fixed the version comparison to inspect an actual version change, and used the already validated evidence bindings inserted into the result evaluation. Child exit 1; minimum free bytes 2,684,796,928; CLEANUP=PASS and MUTEX=RELEASED. | Snapshot SHA-256 443ED6CC2D0854D73F77BA91F4FC4742440939FE42FFC90666CF4F5303D4182C; runner stdout 19,008 bytes, SHA-256 B1738B74CBC683C029F343025477EEE85EEECCD2E2F9A51AD571A26715EF864F; runner stderr empty SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855; child stdout 1,154 bytes, SHA-256 315E998937EFFB6DA5A4CF3DB265C67CC10DDB334916A2C3DE2EB0AD3893DD91; child stderr 12,613 bytes, SHA-256 B8A94BBD1D237BF00D7732423843A18315E12D08B180B96C831FCB35B19B4638. |
| r5 | 11 tests in 73.763s: FAILED (errors=5); no failures or skips. Three Owner/restore cases exposed the independent verifier applying its bytes-only _blob64 validator to the persisted hex-string determination digest; Mirror drain exposed NameError: json is not defined; one C05 test indexed the paginated response as a list and raised KeyError: 0. Corrected the verifier to decode checked hex, imported json, and selected the first item from the page's items field. Child exit 1; minimum free bytes 3,290,255,360; CLEANUP=PASS and MUTEX=RELEASED. | Snapshot SHA-256 7CE9FF1BC62C34A12729C36059062C22C42EE3D3CB57B73C342839418C0469F0; runner stdout 17,769 bytes, SHA-256 D1A67BF8CAC7199D478BAB90764531C627EAEE22C6B1C94ECF217EA5A17EB1D9; runner stderr empty SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855; child stdout 1,147 bytes, SHA-256 3B1218E67A059266B01428EF79A27D79B824E80D136EC4074BBF262D61666429; child stderr 11,538 bytes, SHA-256 76DA0E6E8E9AF64D2B6C3D96DB1CDFE2B5C8FCBE0FE73F8634436EA3DBA2A0B4. |

The first r6 post-run audit wrote POSTRUN=STOP with repo_identity_matches_preflight=False and python_bytecode_write_suppressed=False while test_run_pass=True. Its checker expected one key per line although the preflight snapshot grouped its header fields, and it queried the new shell's environment rather than the child command's PYTHONDONTWRITEBYTECODE=1 setting. The failed audit is retained as state-continuity-admission-followup-20260924-r6.postrun-snapshot.log, 2,818 bytes, SHA-256 AF613B226FA38DC6285601A96377A85771190C349316ED5054EB080F2B18E387. The corrected post-run verification parses the grouped header, independently checks the current identities, records the original STOP and passes.

### Scope and nonclaims

The nine follow-up paths are app/right_rail_financial_owner.py, app/right_rail_financial_owner_independent.py, app/right_rail_financial_mirror.py, tests/test_right_rail_financial_acceptance.py, tests/test_right_rail_financial_mirror.py, CURRENT_TASK.md, STATE.md, ARCHITECTURE.md, and docs/RIGHTRAIL_FULL_STACK_TARGET.md. The checkout retained its pre-existing additional dirty and untracked work; status still has 29 entries and nothing was staged or committed. build-performance/ was read only for identity checks and both executables are unchanged. No broad suite, compiler, formal proof, or r7 9/9 packet was run for this lane. The final evidence is selected synthetic local evidence only: proofSuiteId=null, production_usable=false, activation=false, NOT_QUALIFIED/INACTIVE/UNSELECTED, nonpayment, non-PHI, synthetic, and dispatch-disabled. It does not establish full v7 acceptance, independent external exit, formal proof/linkage, whole-system qualification, or production authority.

## Private snapshot index set — source-only handoff (2026-09-24)

### Repository and authorized scope

This assignment's source and test preparation is complete; correctness,
SQLite, `EXPLAIN QUERY PLAN`, and cost validation remain pending. Repository:
`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-financial-workflow-20260913`.
Branch: `rightrail-financial-workflow-20260913`. HEAD:
`8f75f527ae6717001978ac7401853c2aaae55f2b`. Index tree:
`05d6df5bf4c36a9e267f2b471a86764a242f227e`. The pre-documentation status had
29 entries. No files were staged or committed.

Edited paths for this assignment only:

- `app/right_rail_financial_owner.py`
- `app/right_rail_financial_owner_independent.py`
- `tests/test_right_rail_financial_acceptance.py`
- `tests/test_right_rail_financial_independent.py`
- `CURRENT_TASK.md`
- `STATE.md`

No semantic adapter change was needed; its query spelling already matched the
target. Other dirty/untracked paths and protected build-performance binaries
were left untouched.

SHA-256 identities after source/test authoring:

| Path | SHA-256 |
| --- | --- |
| `app/right_rail_financial_owner.py` | `725D37C53E973E680D176AE82A6AB8923387F7DC62980BC172C262104761ED09` |
| `app/right_rail_financial_owner_independent.py` | `CC6B2353DB0C3C32E2AE04BB670EF1D29993F7C90FF4F2D26023611709FA6F1F` |
| `tests/test_right_rail_financial_acceptance.py` | `96447BBECBDE9924D188678E8601D59AC86C4D4AF59E1378B80F7498287F3E70` |
| `tests/test_right_rail_financial_independent.py` | `647448E1DE6FEF963AD39CFC87A4AFA8ADA37384C75FFBDC34E0D57347EFC1A6` |
| `CURRENT_TASK.md` | `521B6A4C9D0276E30A9BB855ADB1A9715C6D994DBB83720D388F744BA4751C7D` |
| `app/right_rail_financial_semantic_adapter.py` (unchanged control) | `23F6D1FBE59542F9F0B778D0D20236325CC3618017363F86C33BE38A0FC6618F` |

Protected binaries were read-only hash checked at their actual nested paths:
`build-performance/fixture-candidate/Release/direct_mask_fixture_source_performance.exe`
is `E07865D9CE6C2644142D3EA61030BD308D5BBD09FE861C630CC5EEBE1F3FE5D9`, and
`build-performance/q/Release/dm_pipeline_verifier_cli.exe` is
`F35F6AF28EC2D269831CFB6BDD1C2414D439FFEC2B26C73CC39495720D9B9E5D`.
`STATE.md`'s final identity is recorded in the handoff after this entry is
written.

### Prepared index and migration behavior

The v6/v7 private index set uses `PRAGMA user_version=1` and contains exactly
these ordinary, nonunique, nonpartial indexes:

| Index | Definition |
| --- | --- |
| `rr_financial_v1_evidence_item_id` | `evidence(item_id,evidence_id)` |
| `rr_financial_v1_claims_obligation_id` | `claimed_adjustments(obligation_id,claim_id)` |
| `rr_financial_v1_cases_obligation_id` | `cases(obligation_id,case_id)` |
| `rr_financial_v1_actions_obligation_id` | `actions(obligation_id,action_id)` |
| `rr_financial_v1_conflicts_obligation_id` | `financial_conflicts(obligation_id,conflict_id)` |
| `rr_financial_v1_evaluations_obligation_revision` | `evaluations(obligation_id,revision)` |
| `rr_financial_v1_determinations_obligation_id` | `determinations(obligation_id,determination_id)` |

The conflicts query is a real per-obligation snapshot read and has no prior
covering index. Payments by obligation is covered by its existing unique
`(obligation_id,common_origin_id)` index prefix. The determination point lookup
by `input_evaluation_id` is covered by its unique constraint. These two
existing indexes are query-plan controls, not duplicate candidates.

On v6/v7 opens/restores, the owner first validates scope, schema identity,
nonactivating mode, owner and authority, genesis, and history anchor within the
existing `BEGIN IMMEDIATE` admission transaction. It validates the existing
Continuity admission cache when present, or creates/backfills it and enforces
the package bound before index installation. The complete user-created index
inventory, normalized definitions, SQLite uniqueness/origin/partial metadata,
key order, collation, and sort direction are checked before commit. Cache
migration, index creation, and marker update commit together and roll back
together. The independent checker repeats exact inventory and metadata
validation for v6/v7. v5 exits before index handling and retains marker 0 and
no new indexes.

No Continuity table/payload set is changed; indexes do not enter serialized
bytes or digests, and existing limits and semantics are intended to remain
unchanged. Independent `_verify_events` remains a complete ordered
`financial_events` scan and validates the event history; no
history-independent correction claim is made.

### Prepared tests and deferred gates

Six focused methods are authored:

- `RightRailFinancialAcceptanceTests.test_v5_owner_does_not_install_private_snapshot_indexes`
- `RightRailFinancialAcceptanceTests.test_v6_v7_private_snapshot_index_migration_prevalidates_identity_and_preserves_restore`
- `RightRailFinancialAcceptanceTests.test_private_snapshot_index_upgrade_serializes_concurrent_openers`
- `RightRailFinancialAcceptanceTests.test_owner_rejects_unapproved_or_mismatched_private_indexes_without_repair`
- `RightRailFinancialAcceptanceTests.test_v7_private_snapshot_indexes_avoid_scans_in_bounded_fixture`
- `IndependentFinancialCheckerTests.test_private_index_inventory_rejects_unapproved_and_mismatched_indexes`

**Methods executed: 0; runner skips: 0.** Cleanup owns the sole v4 lane, so no
tests, checker, SQLite open/migration, `EXPLAIN QUERY PLAN`, or cost measurement
was launched. No run logs or verifier output exist for this assignment. The
plan fixture uses SQL-shaped rows and does not prove financial-semantic or
event-history validity.

After a direct State safe-lane handoff, take a fresh State-specific preflight
and use `../pq-wide-seed-native-20260913/build-filter-native/run_guarded_v4.ps1`,
SHA-256 `57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`,
with `-MinimumStartFreeBytes=2400000000` and physical-free floor
2,190,433,321 bytes. Run only the authorized focused correctness,
query-plan/cost, and independent-inventory checks once. Record complete
trust-critical output, warning/failure/skip counts, storage/timing samples,
guard resource/cleanup results, and fresh post-run identities. Plan benefit,
migration correctness, and cost acceptability remain unverified until then.

## Private snapshot indexes — guarded focused lane completed (2026-09-24)

### Identity and preflight

This entry supersedes the preceding source-only handoff for validation status.
The direct Driver-to-State lane was returned after Queue reported child and
outer exit 0, cleanup pass, mutex released, and a corrected zero-process/absent
mutex postrun scan. State then took its own fresh preflight before running the
selected tests. Repository identity remained branch
`rightrail-financial-workflow-20260913`, HEAD
`8f75f527ae6717001978ac7401853c2aaae55f2b`, index tree
`05d6df5bf4c36a9e267f2b471a86764a242f227e`, 29 status entries, and zero staged
paths. No commit was created.

The first State snapshot stopped and launched no guarded command:
`../pq-wide-seed-native-20260913/build-filter-native/state-private-snapshot-index-20260924-r1.state-snapshot.log`,
8,825 bytes, SHA-256
`C3694448A616DC6794B4B63E5508860C175EE92409C689BD637169C868801357`. It
recorded `STATE_PREFLIGHT=STOP` for two audit-input errors: the hand-entered
expected `dm_pipeline_verifier_cli.exe` hash had `C` where the prior evidence
and actual file have `B` at zero-based hex offset 41, and a broad `cmd.exe` filter
counted 23 Codex MCP service launchers as task-relevant. The raw snapshot
contains their process command lines. The actual protected binary hash matched
the prior recorded value; no target started under this STOP.

The corrected fresh State preflight passed at 2026-09-24 12:56:22 UTC:
`../pq-wide-seed-native-20260913/build-filter-native/state-private-snapshot-index-20260924-r2.state-snapshot.log`,
8,771 bytes, SHA-256
`18DA22CCCF21810743D491AA96F2E16618732CAD21C49B2D4ADDC6C0EAB2D931`.
Observed free physical memory was 3,528,105,984 bytes, above the
2,400,000,000-byte target start floor and 2,190,433,321-byte hard floor. The
v4 wrapper matched SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`, the
mutex was absent, zero relevant Python/Lake/Lean/Cargo/Rust/CMake/CTest/guard
processes were present, all nine code/test/document/control/protected hashes
matched, planned log paths were clear, and no paths were staged. It separately
recorded the 23 Codex MCP `cmd.exe` service launchers; their command lines did
not match the relevant lane process filter.

### Exact guarded command and test result

The guarded v4 invocation used command mode, target floor 2,400,000,000 bytes,
`PYTHONPATH` set to this checkout, and `PYTHONDONTWRITEBYTECODE=1`. Its child
command was:

~~~text
python.exe -m unittest -v
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v5_owner_does_not_install_private_snapshot_indexes
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v6_v7_private_snapshot_index_migration_prevalidates_identity_and_preserves_restore
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_private_snapshot_index_upgrade_serializes_concurrent_openers
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_owner_rejects_unapproved_or_mismatched_private_indexes_without_repair
tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v7_private_snapshot_indexes_avoid_scans_in_bounded_fixture
tests.test_right_rail_financial_independent.IndependentFinancialCheckerTests.test_private_index_inventory_rejects_unapproved_and_mismatched_indexes
~~~

Complete unittest stderr output:

~~~text
test_v5_owner_does_not_install_private_snapshot_indexes (tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v5_owner_does_not_install_private_snapshot_indexes) ... ok
test_v6_v7_private_snapshot_index_migration_prevalidates_identity_and_preserves_restore (tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v6_v7_private_snapshot_index_migration_prevalidates_identity_and_preserves_restore) ... ok
test_private_snapshot_index_upgrade_serializes_concurrent_openers (tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_private_snapshot_index_upgrade_serializes_concurrent_openers) ... ok
test_owner_rejects_unapproved_or_mismatched_private_indexes_without_repair (tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_owner_rejects_unapproved_or_mismatched_private_indexes_without_repair) ... ok
test_v7_private_snapshot_indexes_avoid_scans_in_bounded_fixture (tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v7_private_snapshot_indexes_avoid_scans_in_bounded_fixture) ... ok
test_private_index_inventory_rejects_unapproved_and_mismatched_indexes (tests.test_right_rail_financial_independent.IndependentFinancialCheckerTests.test_private_index_inventory_rejects_unapproved_and_mismatched_indexes) ... ok

----------------------------------------------------------------------
Ran 6 tests in 3.129s

OK
~~~

Result: 6 passed, 0 failures, 0 errors, 0 skips. The v6/v7 migration test
preserved the exact Continuity package bytes, verified owner reopen and
restore, and called `verify_integrity()` on valid stores; that method invokes
the independent verifier. `_verify_events` remains a complete ordered scan of
`financial_events`. The independent checker continues to reject forged or
mismatched index inventories without mutation.

### Raw query plans and bounded costs

The plan fixture had 20 obligations, 20 rows per obligation per table, 400
rows per table across nine tables, and a 2,025,991-byte Continuity package.
Before the indexes, evidence, claims, cases, actions, conflicts, evaluations,
and determinations-by-obligation plans scanned their tables; the action
subquery for outbox also scanned actions. Afterward, every one of those eight
scan operations searched an index. The exact plans were:

| Query | Before | After |
| --- | --- | --- |
| evidence by item | `SCAN evidence USING INDEX sqlite_autoindex_evidence_1` | `SEARCH evidence USING INDEX rr_financial_v1_evidence_item_id (item_id=?)` |
| payments by obligation | `SEARCH payments USING INDEX sqlite_autoindex_payments_2 (obligation_id=?)`; `USE TEMP B-TREE FOR ORDER BY` | same search; `USE TEMP B-TREE FOR ORDER BY` |
| claims by obligation | `SCAN claimed_adjustments USING INDEX sqlite_autoindex_claimed_adjustments_1` | `SEARCH claimed_adjustments USING INDEX rr_financial_v1_claims_obligation_id (obligation_id=?)` |
| cases by obligation | `SCAN cases USING INDEX sqlite_autoindex_cases_1` | `SEARCH cases USING INDEX rr_financial_v1_cases_obligation_id (obligation_id=?)` |
| actions by obligation | `SCAN actions USING INDEX sqlite_autoindex_actions_1` | `SEARCH actions USING INDEX rr_financial_v1_actions_obligation_id (obligation_id=?)` |
| outbox by obligation actions | `SEARCH action_outbox USING INDEX sqlite_autoindex_action_outbox_1 (action_id=?)`; `LIST SUBQUERY 1`; `SCAN actions` | `SEARCH action_outbox USING INDEX sqlite_autoindex_action_outbox_1 (action_id=?)`; `LIST SUBQUERY 1`; `SEARCH actions USING COVERING INDEX rr_financial_v1_actions_obligation_id (obligation_id=?)` |
| conflicts by obligation | `SCAN financial_conflicts USING INDEX sqlite_autoindex_financial_conflicts_1` | `SEARCH financial_conflicts USING INDEX rr_financial_v1_conflicts_obligation_id (obligation_id=?)` |
| evaluations by obligation | `SCAN evaluations`; `USE TEMP B-TREE FOR ORDER BY` | `SEARCH evaluations USING INDEX rr_financial_v1_evaluations_obligation_revision (obligation_id=?)` |
| determinations by obligation | `SCAN determinations USING INDEX sqlite_autoindex_determinations_1` | `SEARCH determinations USING INDEX rr_financial_v1_determinations_obligation_id (obligation_id=?)` |
| determination by input evaluation | `SEARCH determinations USING INDEX sqlite_autoindex_determinations_2 (input_evaluation_id=?)` | same search |

Thus no tested query plan retained a full table scan. Payment ordering still
uses a temporary B-tree, while its existing unique index continues to search
by obligation; no duplicate payment index was added. The unique
`input_evaluation_id` index remains a search control.

The captured three-sample read timings, milliseconds, are preserved in the
child stdout profile. Medians were:

| Query | Before | After | Change |
| --- | ---: | ---: | ---: |
| actions by obligation | 0.1531 | 0.1064 | -30.5% |
| cases by obligation | 0.1370 | 0.0908 | -33.7% |
| claims by obligation | 0.1272 | 0.0918 | -27.8% |
| conflicts by obligation | 0.3024 | 0.0962 | -68.2% |
| determination by input evaluation (existing-index control) | 0.0601 | 0.0925 | +53.9% |
| determinations by obligation | 0.1923 | 0.2645 | +37.5% |
| evaluations by obligation | 0.2674 | 0.1737 | -35.0% |
| evidence by item | 0.1599 | 0.1302 | -18.6% |
| outbox by obligation actions | 0.2633 | 0.1255 | -52.3% |
| payments by obligation | 0.1053 | 0.1038 | -1.4% |

Two initial postprocessing attempts cast a half-integer sample index with
PowerShell rounding and selected the wrong order statistic; those provisional
numbers were discarded. The medians above were recomputed from the raw sample
arrays using the middle sorted sample for three observations. The child JSON
profile and hash in the evidence table remain authoritative.

Median insertion transaction time was 13.5395 ms before and 11.8994 ms after
(-12.1%). Storage was 1,265,664 bytes without the indexes and 1,396,736 bytes
with them, a 131,072-byte delta (10.36% of this small baseline). The package
remained below the unchanged 8 MiB cap. These are one-run, three-sample local
observations, not an SLA: two read medians increased, one payment ordering
sort remains, and no production-scale latency or capacity claim follows.

### Guard, postrun, and retained audit stops

The v4 runner stdout records the exact policy, preflight, self-tests, samples,
child status, cleanup, and mutex result. Guard preflight free memory was
3,572,645,888 bytes. Self-test exits were 7 and 0; the selected command exited
0. It used eight resource samples, minimum free memory 3,460,608,000 bytes,
peak working set 54,321,152 bytes, peak private bytes 30,777,344 bytes,
`CLEANUP=PASS`, and `MUTEX=RELEASED`. Runner stderr was empty. Corrected
postrun audit r3 passed at 2026-09-24 13:04:45 UTC: status remained 29,
staged paths 0, protected and source hashes matched, relevant processes 0, and
mutex absent.

Postrun audit r2 is retained with `STATE_POSTRUN=STOP` because its copied
expected protected verifier hash repeated the `C`/`B` typo; it did not indicate
a changed binary. The corrected r3 audit compares to the previously passing
r2 preflight and verifies the actual hash
`F35F6AF28EC2D269831CFB6BDD1C2414D439FFEC2B26C73CC39495720D9B9E5D`.
Both STOP snapshots are preserved rather than overwritten.

Raw evidence (all under
`../pq-wide-seed-native-20260913/build-filter-native/`):

| Evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| r1 State preflight STOP | 8,825 | `C3694448A616DC6794B4B63E5508860C175EE92409C689BD637169C868801357` |
| r2 State preflight PASS | 8,771 | `18DA22CCCF21810743D491AA96F2E16618732CAD21C49B2D4ADDC6C0EAB2D931` |
| r2 postrun audit STOP | 4,052 | `D9E40FAA914E85D1E3FCD8FE3ACD0BD13F02BACAF04A6D60CBAF8BD371BABA7B` |
| r3 corrected postrun PASS | 4,411 | `D13783F063DBAC04AB424A7710D07C633F8C747159223835BF6B4060AF833E92` |
| guarded child stdout (complete plan/cost JSON) | 3,955 | `FE9FEF0D5AFB28032BFEF6907AAB43F60A995022BBCC08985253D76D05691A33` |
| guarded child stderr (complete unittest output) | 1,465 | `7EC953CB69300FC177B48EC3473A40C23FFCDC0E50EFD5D6A0606724B4191D98` |
| v4 runner stdout (complete resource/exit/cleanup record) | 3,001 | `1DE5E8F2D116DD29C2DBB65969F9CD21492259F8144375B50F81B317922E223D` |
| v4 runner stderr | 0 | `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` |

Post-lane `CURRENT_TASK.md` SHA-256 is
`F3582401A2401029C31AEA4808438403EE087DFD96946616B364877245095DF8`.
The source/test identities remain those listed in the preceding
source-preparation table; `STATE.md`'s final SHA-256 is recorded in the Driver
return message after this entry is complete. `git diff --check -- CURRENT_TASK.md
STATE.md` exited 0 without whitespace errors and emitted these line-ending
warnings:

~~~text
warning: in the working copy of 'CURRENT_TASK.md', CRLF will be replaced by LF the next time Git touches it
warning: in the working copy of 'STATE.md', CRLF will be replaced by LF the next time Git touches it
~~~

These are Git line-ending notices; no normalization was performed.

No warnings, test failures, errors, or skips were recorded in the guarded r2
run. Source/test hashes matched the preceding source-preparation table at
preflight and postrun. The only unverified claims remain broad-scale
performance, external independent audit, formal/native integration, and
whole-system or production qualification. The lane is safe to return to Driver;
all six tests passed, evidence is preserved, and nothing was staged/committed.

## Staff workspace verified snapshot — source-only, unverified (2026-09-24)

The current working tree adds a same-connection Owner read bundle, a Mirror allowlist and RR/FINANCIAL/STAFF-READ-ENVELOPE/v1 binding, direct bounded decision-package reads, and staff revision dependencies checked by Owner transactions. ACK exact retry/conflict handling remains ahead of stale-revision rejection. Correction remains dependent on the explicit pinned Engine release; the staff workflow accepts a release by injection and defaults to no release, preserving fail-closed behavior. No Python correction fallback was introduced.

A manual browser-source audit found and fixed a digest-width mismatch: envelope/query/snapshot/resource digests and the digest of the verifier result are SHA-256 (64 hex characters), while Owner history/evaluation/Control Pack digests are SHA3-512 (128 hex characters). The browser now validates each field with its matching width. This was source inspection only.

Verification status: no tests, compiler, JavaScript runtime, build, checker, or guarded command ran for this delta because no fresh direct lane handoff was available for the staff packet. The three focused test files were skipped (3 files; reason: execution lane not released). There is no local runtime or test evidence for these staff changes; do not infer that the UI validation, query counts, race tests, retries, rollback, or recovery pass. The earlier selected Engine/Owner correction tests recorded above do not verify this delta.

Scope and claims remain synthetic, state-local, nonactivating, nonpayment, non-PHI, dispatch-disabled, and without an external freshness checkpoint. The unkeyed local envelope detects accidental inconsistency but does not authenticate data against an administrator who can rewrite the Owner database and response. No production, independent-audit, formal-linkage, or whole-system qualification claim follows. No files were staged or committed; protected executables and unrelated dirty paths remain preserved.

## Switch synthetic shadow replay — source-only, unverified (2026-09-24)

Repository/commit at start: canonical checkout
`rightrail-financial-workflow-20260913`, branch
`rightrail-financial-workflow-20260913`, HEAD
`8f75f527ae6717001978ac7401853c2aaae55f2b`. The worktree already contained
the source-only staff snapshot delta and other Driver/State changes; these
were preserved. `build-performance/` was not touched. `WORKSPACE_MAP.md` and
path-scoped `app/AGENTS.md` / `tests/AGENTS.md` were absent in this checkout.
The root `AGENTS.md`, `CURRENT_TASK.md`, `STATE.md`, `ARCHITECTURE.md`, roadmap,
and named Switch/Continuity authorities were reviewed before mutation.

Added `app/right_rail_financial_switch.py`. It accepts only an independently
verified schema-v7 Continuity SHADOW package with one fully published
population, exact active manifest binding, exact member roster, and approved
Control Pack. It builds bounded canonical `RR/SWITCH/REPLAY-INPUT/v1` bytes
containing the exact package in base64 and binds Owner id/schema/revision/
history head, scope/period, population manifest and membership, Control Pack
digest/rules/effective interval, source version/digest and cutoff watermark,
Owner authority, cohort approval and test identity, receiver/pending-work
boundary, reference authority/reviewer/source/tool identity, and candidate
release/tool identity. Unknown versions, keys, result
fields, member sets, wrong input bindings, missing approval/reference, and
unreconciled aggregates fail closed.

Reference and candidate receive the same immutable `bytes` object. The typed
result contract is limited to member owed amounts and aggregate population
total. Differences classify as MATCHED, EXPECTED (with explicit policy
reference), FORBIDDEN, UNEXPLAINED, or UNKNOWN/incomplete. Reports include
input/result digests, expected/received member counts, omissions, extras,
rejected records, difference paths and values, elapsed time, partial
memory/resource measurements, and reference/candidate identity.
Source classification, cohort approval, and reference independence are
caller-asserted; OS/network egress isolation is not enforced here. Candidate
authority is NONE; transfer is unauthorized. The module does not import
Owner/Mirror/Engine, receive a database/path, write incumbent state, dispatch,
or expose transfer/cutover/rollback APIs. Callers must provide evaluators that
run inside an independently enforced no-egress environment; this code does not
attest that boundary. Only canonical bytes are passed as evaluator arguments;
a caller-supplied callable could still capture an Owner/database. The report
therefore labels evaluator-closure isolation and timeout enforcement as
unverified, peak memory as unavailable, and difference-policy approval as
caller-asserted.

Added `tests/test_right_rail_financial_switch.py` with five authored methods.
The synthetic fixture restores a Continuity package into a separate SHADOW
database, compares hand-derived fixture amounts with a candidate reading the
same immutable snapshot, injects a one-cent member delta, and checks member and
total differences while incumbent and shadow package bytes remain unchanged.
Other methods cover missing approval/reference (no evaluator calls), a tampered
package, mismatched approval binding, unknown result fields, and forbidden-
difference reporting. Approval/reference identifiers are test-only fixture
assertions; they do not establish external cohort approval, reference
independence, or a complete alternative financial obligation evaluator.

Verification status: source review only. Manual review corrected the closed
result-field allowlist to accept its already-required authority binding; this
has not been runtime-verified. Five Switch tests were authored, zero executed.
No build, test runner, compiler, checker, native/Lean process, or guarded
command ran. The current v4 finite lane requires a new direct handoff
and fresh target preflight before executing the focused tests. The earlier
staff snapshot delta remains source-only and unverified; its note above was
not rewritten.

Changed paths for this slice: `app/right_rail_financial_switch.py`,
`tests/test_right_rail_financial_switch.py`, `CURRENT_TASK.md`, and `STATE.md`.
No files were staged or committed. No runtime isolation, memory ceiling,
external approval, full obligation calculation, transfer, activation, or
production-qualification claim is made.

## Switch CLI path — source-only, unverified (2026-09-24)

This follow-up used the existing local financial CLI at
`tools/right_rail_financial_cli.py`; it did not create a second CLI or service.
The existing global Owner database and scope options are optional at parse
time, while every Owner command still requires them in `_owner`. Switch command
branches execute before `_owner` and require no database or invented
State/program identity.

`switch-prepare` reads the exact package bytes, calls
`FinancialMirror.validate_continuity_package` (Owner plus independent
Continuity verification), checks v7 SHADOW and disabled dispatch/egress, then
calls `prepare_shadow_replay_input` and creates a canonical replay-input file
without replacing an existing path. It invokes no external evaluator.
`switch-compare` repeats package verification and uses the same preparation
logic through `run_shadow_replay`, then validates supplied result documents
against the regenerated input SHA-256, producer identity, exact membership,
typed owed cents, and aggregate. It reports only precomputed-result comparison;
the external evaluator timings are unavailable. Missing/invalid approval,
permission/provenance, reference, candidate, or result data produce
INCOMPLETE/UNKNOWN. A candidate whose ID equals the claimed cohort approver or
reference authority/reviewer is rejected before any result comparison.

The five new CLI methods cover preparation plus multi-member difference
comparison, missing approval/reference, missing permission provenance, direct
candidate self-approval, and a result bound to another input. Together with the
five existing Switch methods, 10 methods are authored; 0 executed. No test,
Python runtime, build, compiler, checker, or guarded command ran. The current
v4 lane still requires the direct handoff and fresh target preflight; the
latest Engine runner failure in the separate owner packet was not retried and
was not treated as preflight evidence. The staff snapshot delta remains
untouched and unverified.

The CLI reports source classification, approval authenticity, reference
independence, and expected-difference approval as caller-asserted. It does not
run evaluator code or enforce an external OS/network sandbox. It remains a
local read-only result comparator over owed amounts and totals; no Owner write,
restore, dispatch, second writer, transfer, cutover, or rollback path was added.
Changed paths for this follow-up: `app/right_rail_financial_switch.py`,
`tools/right_rail_financial_cli.py`,
`tests/test_right_rail_financial_cli_switch.py`, `README.md`,
`docs/SWITCH_TRANSFER_ARCHITECTURE.md`, `CURRENT_TASK.md`, and `STATE.md`.
No files were staged or committed; preserve all other dirty paths and the
protected `build-performance/` executables.

## Offline synthetic service kit — source-only, not assembled (2026-09-24)

Authored `tools/right_rail_financial_service_kit.py` and its post-extraction
scenario/server launchers. The defined ZIP_STORED archive uses fixed member
times and create-only creation. Its strict manifest lists each included file's
size and SHA-256, records CPython 3.11.15 and an empty third-party Python
dependency lock, hashes the full runtime tree, includes all selected State
source/test/UI dependencies, every Engine `.lean` source and the Lean toolchain
and Lake lock/config files, and pins the correction executable plus request,
expected-result, and actual-result vectors. Queue is not included; its
manifest blocker is exactly `queue.lifecycle_source_bound_runtime` with status
`MISSING/BLOCKED`.

`verify` requires an independently delivered expected archive SHA-256 and
checks archive bytes, exact members, per-file hashes/sizes, embedded State
Engine pins, Lean source-manifest digest, toolchain/lock hashes, and strict
Engine build receipt/log bindings. The receipt schema is documented in
`docs/FINANCIAL_SERVICE_KIT.md`; the tool will not create one. Extraction
requires a new destination and preserves a partial directory if interrupted.
The `run` command rechecks both archive and extracted tree before invoking one
focused end-to-end scenario with the bundled runtime and a temporary Owner
workspace. `serve` rechecks the same pins and starts the existing loopback-only
staff app against an explicit empty TEST Owner workspace.

The scenario now injects a server-side socket close after the Owner correction
method returns and before any response bytes are sent. It then checks one
determination/action/event and one sequence increment, independent Owner
integrity reconstruction, exact retry as `DUPLICATE` with identical
Continuity bytes, same-owner staff/Mirror readback, SHADOW restore with writes
and dispatch disabled, and no-replacement restore semantics. This source
assertion has not run; it is not runtime evidence.

Assembly is blocked on Engine provenance. Current correction executable:
6,245,376 bytes, SHA-256
`E911E8844130155E4615D284D6D29A597B6E441DC45101D411EE8422EAE684B9`. Current
Engine `CorrectionTransition/Transition.lean`: SHA-256
`E982BA7871E45138BD6AAF72434E4F43D17105D42F60413FEB3B57816AD3F01D`. The
prior recorded compile source was
`342F3B1DF777095D75FD12970F29DFBC09AC06DCF48147EFF804EBA78E9021AE`; no
Engine-produced receipt currently binds the exact source manifest to the
retained executable. Do not generate a replacement receipt locally or infer
that source hash and executable hash imply a build link. The historical pinned
CPython executable is 3.11.15,
`F1D8D2AA2A8AD7C74B6C6300B29CFDBCB484FC7FFAD99B7FBFE1E31C048343B9`; the kit
has not hashed/copied the complete runtime into an archive.

No direct v4 lane handoff and fresh target-specific preflight have been
received for the service-kit packet. The latest known guard probe failure is
`Access denied` before physical preflight or child launch, outer exit 1, with
no cleanup evidence. Do not retry it or treat it as handoff/preflight proof.
The State kit packet's target-specific `-MinimumStartFreeBytes` is unset and
must not inherit a value from another packet. Separately, the assembler
requires the exact Engine build guard threshold from the authorized Engine
handoff and binds it into the manifest against the receipt. Neither threshold
has been inferred from the other. The receipt schema has no signature; receipt
consistency is checked, while producer authenticity depends on the authorized
handoff.
The kit does not enforce host-level outbound network blocking; an offline
execution boundary must be supplied externally when required.
No Python process, test, build, compiler, checker, archive operation, or kit
command ran in this packet. One service integration method was authored and
not executed; the 10 Switch methods remain unexecuted as recorded above. No
archive was created or service started. No warning or test failure was
produced because no verifier/test command ran; source-to-binary receipt and
lane-release requirements remain open.

Source paths changed for this continuation: `README.md`,
`docs/FINANCIAL_SERVICE_KIT.md`, `tools/right_rail_financial_service_kit.py`,
`tools/service_kit/run_scenario.py`, `tools/service_kit/run_server.py`, and
`tests/test_right_rail_financial_staff_server.py`. Earlier dirty work and
`build-performance/` remain preserved; nothing was staged or committed.
Claims remain `proofSuiteId=null`, `production_usable=false`,
`activation=false`, synthetic, nonpayment, non-PHI, and dispatch-disabled.
