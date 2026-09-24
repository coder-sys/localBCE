# RightRail current task

Updated: 2026-09-24

## Objective and working identity

This checkout is the canonical synthetic financial application:

C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-financial-workflow-20260913

Branch: rightrail-financial-workflow-20260913.

The current delivery integrates the corrected v5 Python owner/checker,
same-owner Mirror and CLI coverage, Continuity restore ownership, affected
acceptance tests, and the seven maintained child Markdown files. Git HEAD,
tree, and status are authoritative after integration. The two untracked
build-performance executables are preserved evidence and must not be touched.

The bounded responsibility remains State Control Pack, Blind Ledger owner,
same-owner Mirror, bounded Continuity State, and deferred Switch. The workflow
is synthetic, state-local, nonactivating, nonpayment, and non-PHI.

## Required v5 contract and local disposition

Owner and Continuity identities are RR/FINANCIAL/OWNER/v5 and
RR/FINANCIAL/CONTINUITY/v5. v2/v3/v4 inputs reject fail-closed without
mutation. The v5 evaluation receipt contract
RR/FINANCIAL/EVALUATION-RECEIPT/v1 binds scope, identity/revision, Control
Pack, sorted unique evidence record-digest bindings, authority/time, result
fields, result digest, and receipt digest. Determinations bind explicit
evaluation identity/digest and expected revision before one atomic
determination/action/outbox transition. Exact retries are DUPLICATE; changed
identity or input is a conflict.

`STATE.md` records the narrow Driver acceptance for this owner-local synthetic
v5 correctness slice. That acceptance is not whole-system qualification:
native verification-to-commit, executable Lean linkage/refinement,
Queue/Composition integration, authenticated sources, custody, independent
audit, real PHI, live dispatch, payment movement, and production activation
remain separate gates.

## Prior broad verification

The required guarded command compiled the relevant owner, checker, Mirror,
fixture, CLI, and measurement-harness paths, then ran the acceptance,
independent-checker, and Mirror suites. The exact raw logs are:

- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-correction2-focused-r8.stdout.log
- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-correction2-focused-r8.stderr.log

Decisive child output:

PROCESS_BOUNDARY precommit returncode=73 stdout='PHASE=BEFORE_REJECT\nPHASE=PRECOMMIT_AFTER_MUTATION\n' stderr=''
PROCESS_BOUNDARY postcommit returncode=74 stdout='PHASE=BEFORE_REJECT\nPHASE=POSTCOMMIT_AFTER_COMMIT\n' stderr=''
Ran 63 tests in 26.573s
OK

The guard reported child exit 0, minimum free bytes 3797897216, reserve
3221225472, effective floor 2576980378, peak private bytes 29360128,
CLEANUP=PASS, and MUTEX=RELEASED. The final owner SHA-256 is
68D1AF3DE2B5072FDD7A6D05DD297E2B5A95687E1453E80CCBFB49A2ADF694D9; the
independent checker SHA-256 remains
FE1CCDCA057FE36391FF9A9BCD9B4CD73ADAC9A934D3DB88D040E5F6BB1D5A55.

The residual correction packet was then run under the unchanged guard from the
absolute project cwd. Its raw logs are:

- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-residual-focused-r2.stdout.log
- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-residual-focused-r2.stderr.log

Decisive child output:

```text
Ran 5 tests in 4.254s
OK
```

The packet covered normal CASE11 restore, integrity-failure cleanup, the
existing pre-link destination race, the post-link replacement race, and a
current-receipt `evaluation_chronology` rejection with unchanged continuity.
The guard reported `exit7=7 exit0=0`, child exit `0`, minimum free bytes
`3106156544`, reserve `3221225472`, effective floor `2576980378`, peak
private bytes `30777344`, `CLEANUP=PASS`, and `MUTEX=RELEASED`. Current source
identities are owner
`45D2F3F0468642BE471CF365A7C6AF63B98836430AEEA796FD6A461CECE19846` and
acceptance test
`B9312E8DE63D80861C88924E800CFE0771BB1EA7D0EE72DF2BC56E802CF6017B`.

Coverage includes an independently reconstructed populated evaluation receipt
through owner query/evaluate, reopen, Mirror, CLI, and SHADOW restore; bad,
stale, pre-evaluation, unchanged-rejection, and same-reference determination
cases; real CLI success, exact retry, and changed-binding conflict; private
atomic restore attempt publication with foreign destination/sidecar
preservation and owned-failure cleanup; and v2/v3/v4 tag-only store/package
rejection without destination creation. The v2/v3/v4 cases are explicitly
schema/version-tag rejection checks, not proof of compatibility with authentic
historical schemas.

## Retained bounded measurement (pre-residual correction)

The final guarded measurement raw logs are:

- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-final-r4.stdout.log
- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-final-r4.stderr.log

The child receipt is type=complete, status=PASS, schema
RR/FINANCIAL/MEASUREMENT-SERIES/v1, at
work/financial-measurements-v5-final-r4. It records sizes 5, 10, and 20,
one warmup plus three measured samples per size, 12 owner databases and 12
TEST restore databases, owner
68D1AF3DE2B5072FDD7A6D05DD297E2B5A95687E1453E80CCBFB49A2ADF694D9, checker
FE1CCDCA057FE36391FF9A9BCD9B4CD73ADAC9A934D3DB88D040E5F6BB1D5A55, all
reference checks true, all source bytes unchanged, and zero acquisition
failures.

Measured aggregate medians are total/wait/held milliseconds:

| size | total | wait | held | transactions |
| ---: | ---: | ---: | ---: | ---: |
| 5 | 504.762 | 1.390 | 6.236 | 51 |
| 10 | 793.516 | 1.460 | 7.373 | 84 |
| 20 | 1261.848 | 1.469 | 7.291 | 150 |

The outer r4 measurement guard had child exit 0, 18 samples, minimum free
bytes 3767709696, peak private bytes 24268800, CLEANUP=PASS, and
MUTEX=RELEASED. The retained child JSON stdout file SHA-256 is
2F5C1062F00C7A3FA5A3BA1F802EAEB62C1C90441851BEA18F0BA02F7CB81B0A; stderr
was empty with SHA-256
E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.
This is a bounded local observation, not an SLA or production qualification;
native metrics are pending and Queue wait/age are not applicable to this
owner slice. It is source-bound to the pre-residual owner hash
`68D1AF3DE2B5072FDD7A6D05DD297E2B5A95687E1453E80CCBFB49A2ADF694D9`, not the
current owner, and was not rerun for this focused correction packet. The r4
invocation used absolute script/output paths and script-derived
`REPOSITORY_ROOT`/`sys.path`, but left the child cwd at the guard default; this
invocation deviation is retained as historical evidence.

## Retained failures and next gates

Earlier raw failures remain evidence: the first residual focused launch did
start guarded `cmd.exe` and complete both guard self-tests
(`child-exit-7=7`, `child-exit-0=0`), then the main command and wrapper exited 1
before Python tests. Its raw stderr (SHA-256
`B243E3431CF3FD2DA74278615CAA676AD4F4F806E23B19FCD398E83A7B02390D`) was:

```text
The filename, directory name, or volume label syntax is incorrect.
```

The corrected residual r2 launch passed. Earlier correction runs had two test
errors (hard-coded evaluation revision and a CLI argument replacement);
another run stopped at 2521305088 < 2576980378 for the required memory floor;
the next run exposed the independent detail-row item_id assumption; two later
runs exposed missing io and redirect_stdout test imports. The final r8 rerun
passed. These failures were corrected in scope and were not silently
relabeled. Earlier pre-correction review failures remain in their original raw
logs and Git history.

`STATE.md` is the acceptance authority for the narrow Driver disposition. Next
work is the separate native, formal, operational, and production gates. Engine
is implementing and correcting executable Lean modules and the concrete
adapter contract, but no runtime authority switch is allowed until a pinned
executable Lean artifact and refinement/linkage evidence exist.

## Protected boundary and claims

Preserve the fixed twenty-hospital/$1,000,000 fixture, hand-derived cents,
Queue schema 13/Profile 12, Composition schema 4, exact 100-reference
protocol, source ownership/reservation, Queue/State/outbox atomicity,
non-CLEAR guard, and native/C/crypto/Lean boundaries.

Claims remain proofSuiteId=null, production_usable=false, activation=false,
NOT_QUALIFIED/INACTIVE/UNSELECTED, synthetic, nonpayment, and non-PHI. The
Python owner is not a deployed formal authority, official processor, payment
system, or independent audit.

## Executable-Lean cutover-path candidate (2026-09-20)

The scoped candidate adds `app/right_rail_financial_semantic_adapter.py` and
`tests/test_right_rail_financial_semantic_adapter.py`. The producer consumes
only the sole owner's already-open transaction connection and an explicit
current or historical `TrustedAuthorityContext`; it performs bounded reads,
recomputes owner/checker digests and projections, authenticates authority,
pack, evidence, evaluation, determination, action, conflict, case, payment,
reversal, reporting, and continuity facts, and returns an immutable canonical
snapshot. It has no database open, write, revision advance, receipt/lease/
reservation table, native proof, activation, or runtime authority switch.

The handed-off binary seam is the exact Engine `BLFIN02`/`BLFRES02` contract:
raw ASCII magic, u16 big-endian string/list framing, u64 big-endian naturals,
raw 64-byte digests, explicit mode/provenance/pack/payment/claim/
determination/case/action/result tags, stored-order lists, canonical result
re-encoding, strict snapshot binding, and no result digest or trailing bytes.
The adapter remains owner-side; Lean field/version ownership stays with Engine.

Final guarded evidence for this candidate:

- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-semantic-adapter-codec-focused-r10.stdout.log`
- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-semantic-adapter-codec-focused-r10.stderr.log`
- child output: `Ran 6 tests in 3.649s` / `OK`
- guard: child exit `0`, `exit7=7`, `exit0=0`, minimum free bytes
  `2757058560`, effective floor `2576980378`, `CLEANUP=PASS`,
  `MUTEX=RELEASED`

The prior r8 attempt stopped before child execution at
`2515009536 < 2576980378`; r9 then exposed and corrected one independent
fixture arithmetic error (`10000000 - 9700000 = 300000` shortfall). Those
failures remain raw evidence and were not relabeled. The final candidate is
still not a runtime authority switch, formal refinement proof, native proof,
production qualification, payment system, or activation claim.

## Semantic adapter correction and Engine handoff (2026-09-20)

The correction pass keeps the owner as the sole writer and changes only the two scoped source/test
files. Snapshot construction now calls the existing `verify_database_connection` on the same active
owner transaction with explicit expected config, scope, authority, mode, owner identity, and optional
continuity epoch. The adapter no longer treats its former partial meta/identity checks as the database
trust boundary. Public snapshot construction requires an internal validation token, while public decode
rebuilds the snapshot from the supplied owner connection and compares exact canonical bytes; a checksum
is never treated as authorization. JSON columns are bounded before parse and fail closed on depth or
recursion. Delivery projection uses the owner's latest `(created_at_ms, action_id)` rule, and historical
authority is checked against verified store metadata even when the context is labelled `HISTORICAL`.

The final focused Python run was performed before the standing memory-policy update under the then-current
guard and actual repository cwd. Its raw logs are:

- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-semantic-adapter-correction-final-r8.stdout.log`
- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-semantic-adapter-correction-final-r8.stderr.log`

The complete child result was `Ran 8 tests in 5.162s` / `OK`; child and wrapper exit were `0`, guard
self-tests were `exit7=7 exit0=0`, minimum free bytes were `2835030016`, cleanup was `PASS`, and the
mutex was `RELEASED`. The stderr log SHA-256 is
`454BEE092C892F832E339A82EBDF46B8C7E4DEF9F2E80707046ABE9C122A7AE8`. Earlier guarded stops and
expectation-only failures remain raw evidence; none was relabelled as a pass.

The current shared guard policy is now SHA-256
`55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`, with 32% total nominal-reserve
tolerance, effective floor `2190433321`, unchanged 2,000,000,000-byte process cap, and unchanged mutex.
The policy smoke receipt is `../pq-wide-seed-native-20260913/build-filter-native/standing-memory-policy-20260920.outer.log`
with SHA-256 `19B094717DEC935A9BB3D7E492929BC605C2336DD1870FEAF2A6DEC394CDEE50`; it is guard
validation only, not workload evidence. Prior logs retain their actual 20% policy.

The same focused suite was rerun after that policy update under the current guard and actual repository
cwd. Its raw logs are:

- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-semantic-adapter-correction-current-r1.stdout.log`
- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-semantic-adapter-correction-current-r1.stderr.log`

The complete child result was `Ran 8 tests in 5.219s` / `OK`; child and wrapper exit were `0`, guard
self-tests were `exit7=7 exit0=0`, minimum free bytes were `2757775360`, peak private bytes were
`21536768`, cleanup was `PASS`, and the mutex was `RELEASED`. The stdout log is empty with SHA-256
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`; the stderr log SHA-256 is
`89C0AD949189823D42651A5061FFD63DD2C8AAB3CE7291BACE459A52881DF02F`. This is Python owner-side
correction evidence only; it does not qualify the Lean seam or change runtime authority.

The Engine source checkpoint is commit `907e32de63ab0d8133f2a7aff1441b06a1a884e8`, tree
`49d758924e298d935c16ffddacdadd945dec5f93`. A fresh full `lake build blind_financial` under the
current guard stopped fail-closed at minimum free `2122395648 < 2190433321` (preflight `2796630016`,
sample 20, peak private `1933692928`, process count `7`); cleanup and mutex release passed. The existing
`blind_financial.exe` (5,995,520 bytes, SHA-256
`DFCA506260A5A5F5C0A8DE42B72D3DFD15000EC6E3DD5B8BBA8C4CDB5F2490F3`) is stale-or-partial and is not
accepted. The staged Types target did pass once under the current guard with child self-tests `7/0`,
minimum free `2868494336`, child/wrapper exit `0`, and cleanup/mutex release PASS. Specification then
failed closed twice: r2 had preflight `2573328384`, minimum free `1994338304 < 2190433321`, peak
private `972124160`; the direct-handoff r3 had preflight `2544488448`, minimum free
`2064375808 < 2190433321`, peak private `971595776`. Both had child self-tests `7/0`, cleanup PASS,
and mutex RELEASED. Per the no-repeat rule, dependent Evaluation/Theorems/Executable/Cli/link stages
and the KAT/vector were not run at that checkpoint. The later fresh-artifact handoff and representative
cross-language evidence are recorded below; no runtime-authority claim is made.

## Cross-language conformance and Engine handoff (2026-09-20)

The existing semantic-adapter test file contains one real-owner conformance test that invokes only a
fresh pinned Engine executable through `--evaluate`. It covers an authorized offset, the same history
restored into SHADOW and TEST, a rejected-and-acknowledged correction, and the final
duplicate/conflict/reversal/replacement/reporting history. Expected cents and semantic statuses come
from the independent fixture expectations, not from adapter output. The helper requires explicit
`BLIND_FINANCIAL_EXE` and `BLIND_FINANCIAL_EXE_SHA256` handoff values, rejects the known stale hash,
uses bounded binary stdin/stdout/stderr, a 30-second timeout, kill-and-collect cleanup, and a post-run
artifact rehash. It decodes raw BLFRES02 bytes with the owner-bound adapter and checks the owner
database hash is unchanged.

The fresh Engine source is commit `907e32de63ab0d8133f2a7aff1441b06a1a884e8`, tree
`49d758924e298d935c16ffddacdadd945dec5f93`. The accepted artifact is
`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\lean-engine-20260913\semantic_kernel\lean\.lake\build\bin\blind_financial.exe`,
`6001664` bytes, SHA-256
`398E6D16922D23F71F52074F151553DCE75467723D4C624A8D7B71076FA24D03`. The known stale
`5995520`-byte artifact with SHA-256
`DFCA506260A5A5F5C0A8DE42B72D3DFD15000EC6E3DD5B8BBA8C4CDB5F2490F3` remains forbidden.

The guarded KAT run is recorded in:

- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-kat-20260920-r1-resourcewindow.stdout.log`
- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-kat-20260920-r1-resourcewindow.stderr.log`

It reports `KAT_COUNT=30`, every gate `PASS`, `THEOREM_MANIFEST_COUNT=38`, and
`FINANCIAL_KERNEL_RESULT=PASS`; child/wrapper exit was `0`, self-tests were `exit7=7 exit0=0`,
minimum free bytes were `3326943232`, cleanup was `PASS`, and the mutex was `RELEASED`. The raw
stdout is 3697 bytes with SHA-256
`9FB16AF467CF03F3E6E4F34F0CB5D9AAFD3BF869C3C19BA4132BEE0AD7ED01C3`; stderr is empty with SHA-256
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.

The guarded owner-history conformance run is recorded in:

- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-owner-engine-conformance-20260920-r1-resourcewindow.stdout.log`
- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-owner-engine-conformance-20260920-r1-resourcewindow.stderr.log`

Its raw child result is `Ran 1 test in 2.186s` / `OK`; the five histories above were exercised with
child/wrapper exit `0`, self-tests `7/0`, preflight `3041083392`, minimum free `2920316928`, peak
private `80666624`, cleanup `PASS`, and mutex `RELEASED`. Stdout is empty with SHA-256
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`; stderr is 103 bytes with
SHA-256 `D5E9E7AD3546C946F21693BADAC5A5967658AB6B2751A3EE7F93D367B568A3D2`.

The guarded exact wire vector is recorded in:

- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-owner-wire-vector-20260920-r1-resourcewindow.stdout.log`
- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-owner-wire-vector-20260920-r1-resourcewindow.stderr.log`

For `scenario=authorized_offset`, `BLFIN02_INPUT_LEN=2526` and SHA-256
`C94A16DA6F2EA33C153F7E0890F95434ABD6F051C6F69FE7D7B1F39985E72344`; the fresh executable returned
exit `0` with zero stderr and `BLFRES02_OUTPUT_LEN=552`, SHA-256
`278D98485EBE968C88AC0E85BCCD4F69C5B7FF1A38F0B20681DD7E79C82A7598`. The raw stdout is 6514 bytes
with SHA-256 `B4937496909BF2477CF352AF17460F010FBEF9E20BD3D0266A6D8A6619A738B4`; it retains the
complete input/output hex. Guard minimum free bytes were `3350384640`, peak private bytes
`82468864`, self-tests were `7/0`, cleanup was `PASS`, and mutex was `RELEASED`.

State's post-handoff retry is also retained as a fail-closed resource event in
`../pq-wide-seed-native-20260913/build-filter-native/guarded-command-semantic-adapter-engine-conformance-current-r2.stdout.log`
and its `.stderr.log` companion: preflight was `2236633088`, guard self-tests were `exit7=7 exit0=0`,
the Python command launched, and the guard then stopped at minimum free bytes
`2171011072 < 2190433321`. Cleanup was `PASS` and the mutex was `RELEASED`; whether the nested Lean
process was reached is not established. The stdout log is empty with SHA-256
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`; stderr is 194 bytes with
SHA-256 `3A3D9A8F37C1DBB1287B84413B1C1D1453109BFECDACB39915FF65F7C1324EE9` and contains the
begun test name before the guard stop. This is a resource failure, not a conformance result.
The representative cross-language vector is now evidenced, but it remains synthetic/nonactivating and
does not create runtime, formal, native, payment, or production authority.

The separate proof-only `CodecLaws`/`AxiomCheck` closure remains pending in the Engine worktree. Its
first new compile stopped at minimum free `2143604736 < 2190433321`, peak private `1225388032`, with
empty child stdout/stderr, cleanup `PASS`, and mutex `RELEASED`; no retry was launched after host free
memory fell to `1906061312`. The Engine's dirty proof-only files remain outside this checkout, and no
theorem or axiom pass is claimed by the KAT or representative conformance evidence above.

## Contained Engine application port (2026-09-20)

The new read-only application port is `app/right_rail_financial_engine.py` with focused coverage in
`tests/test_right_rail_financial_engine.py`. It accepts an immutable explicit release configuration,
preflights the configured executable size/SHA-256 without environment reload, rebuilds the validated
snapshot from the caller's already-active owner connection, encodes BLFIN02, calls only the existing
`run_contained_verifier_stream` lane, and strictly validates/decodes BLFRES02 against that same
snapshot. It does not open, close, commit, roll back, write, advance a revision, create a result
ledger, or switch runtime authority. Failure errors contain stable codes only; child output and
evidence are not included.

The stream primitive change is limited to an optional keyword-only per-call memory cap. Its default
remains exactly `4,500,000,000` bytes for existing callers; the financial release enforces and passes
exactly `2,000,000,000` bytes and a finite timeout no greater than `30.0` seconds. The financial bounds remain distinct: canonical snapshot JSON is
`4 * 1024 * 1024` bytes, BLFIN02 input is `8 * 1024 * 1024` bytes, and binary BLFRES02 output is
`1 * 1024 * 1024` bytes. The fixed accepted synthetic artifact is
`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\lean-engine-20260913\semantic_kernel\lean\.lake\build\bin\blind_financial.exe`,
`6001664` bytes, SHA-256
`398E6D16922D23F71F52074F151553DCE75467723D4C624A8D7B71076FA24D03`; this remains a
representative synthetic/nonactivating artifact, not production or formal authority.

Final guarded focused evidence is in:

- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-engine-port-20260920-r8.stdout.log`
- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-engine-port-20260920-r8.stderr.log`

Raw child result: `Ran 7 tests in 1.368s` / `OK`; the five new application-port tests and two
stream-cap tests all passed. The real accepted-Engine test independently checked input length `2526`,
input SHA-256 `C94A16DA6F2EA33C153F7E0890F95434ABD6F051C6F69FE7D7B1F39985E72344`, output length
`552`, output SHA-256 `278D98485EBE968C88AC0E85BCCD4F69C5B7FF1A38F0B20681DD7E79C82A7598`,
hand-derived cents/status values, unchanged owner database hash, and an active caller transaction.
The wrapper reported child exit `0`, guard self-tests `exit7=7 exit0=0`, preflight free bytes
`3886694400`, minimum free bytes `3820642304`, peak private bytes `28651520`,
`CLEANUP=PASS`, and `MUTEX=RELEASED`. The stdout log is empty, `0` bytes, SHA-256
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`; stderr is `1632` bytes,
SHA-256 `C6E74E35AC00A539556BED24C68F034CDF11082D2D9DFFE1FAFABF48B943F597`.

Earlier diagnostic attempts remain preserved and uncounted as final acceptance: r3 had an outer guard
exit `0` but empty child logs from an argument-flattening invocation; r4 discovered 16 tests because
the old semantic-adapter class was imported (8 old tests passed and its environment-dependent real
conformance test failed), with total `1` failure and `5` errors; r5 ran 7 tests with `6` failures and
`2` errors; r6 and r7 were successful intermediate child runs. The accepted r8 run was not replayed
for this correction. Changed-file hashes after r9c are: `app/right_rail_financial_engine.py`
`3E750452B18ACAD652C67C5071B3389F46431DD1F19706797C13B1CFF6100796`,
`tests/test_right_rail_financial_engine.py`
`2E30D2BBF3730513A2A008368620F55C9D7A04D4A14D01506430900248D7BDC4`,
`app/minimal_clearance_verifier_process.py`
`7039009D43298B34BFD4C1F1B6B5CDF8EC7BF41DD101033295FBA3E44B069523`, and
`tests/test_minimal_clearance_verifier_process.py`
`EAAF96E49A531ED13744CAAFAD007ABF391B95B930E1A80038BF55400DD968AC`. The frozen semantic adapter
hash remains `23F6D1FBE59542F9F0B778D0D20236325CC3618017363F86C33BE38A0FC6618F`.

## Bounded post-r8 correction (2026-09-20)

The application release boundary is now finite `0 < timeout_seconds <= 30.0`; `30.0` is accepted and
values above it fail before launch. `FinancialEngineRelease` is an explicit trusted owner/operator
configuration. It is never reconstructed from the database, request, result, or environment; only
the recorded `6001664`-byte artifact and SHA-256 pin above have accepted execution evidence. Other
self-consistent pins are not automatically release-qualified. The caller retains its transaction,
read snapshot, locks, and pending writes across verification/invocation; serialization, commit,
rollback, and retry decisions remain with the sole owner.

The affected regression keeps a disposable TEMP marker and owner-controlled savepoint on the same
connection through both an accepted fake contained result and a containment failure. It captures the
connection passed to snapshot reconstruction, proves the pending marker survives each return, and
only then rolls back/releases each savepoint from the caller side. This remains a read-only,
non-authoritative comparison port with `proofSuiteId=null`, `production_usable=false`, and no
production callsite, schema change, or runtime authority switch.

The accepted r8 invocation's factual limits remain unchanged: its child inserted the repository in
`sys.path` but did not set an absolute inner child cwd, so the guard-default cwd deviation remains;
its child/self-test/guard observations were child exit `0`, self-tests `7/0`, minimum free bytes
`3820642304`, peak private bytes `28651520`, cleanup `PASS`, and mutex `RELEASED`. The command text
contained `exit $LASTEXITCODE`, but only `r.output` was printed, so returned outer-exit metadata was
not independently displayed. No r8 rerun is used for this correction.

The affected guarded correction run is recorded in:

- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-engine-port-20260920-r9c-affected.stdout.log`
- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-engine-port-20260920-r9c-affected.stderr.log`

The child began by changing into the absolute repository checkout, then ran only the timeout-boundary
and pending-savepoint tests: `Ran 2 tests in 0.462s` / `OK`. The wrapper reported child exit `0`,
self-tests `exit7=7 exit0=0`, preflight free bytes `3790729216`, minimum free bytes `3738796032`,
peak private bytes `23916544`, `CLEANUP=PASS`, and `MUTEX=RELEASED`. Stdout is empty, `0` bytes,
SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`; stderr is `497`
bytes, SHA-256 `601C3CF241FB78EFE39C27171334D20D302D6971F810C83E5B553E46F42498B1`. The first
affected attempt was blocked before preflight by the held mutex; the next retry reached the guard but
failed before Python with the raw Windows filename-syntax error. Neither was counted as test evidence.

## v6 funding chronology and Continuity bound correction (2026-09-23)

The scoped v6 correction retains `RR/FINANCIAL/OWNER/v6` and
`RR/FINANCIAL/CONTINUITY/v6`. A funding supersession now rejects a sampled
`recorded_at_ms` earlier than its immediate parent before inserting a receipt,
changing the current funding projection, appending an event, or advancing meta.
The exact duplicate path remains before clock sampling. This enforces the
independent checker's existing `<` chronology rule; it does not establish an
atomic or globally monotonic clock.

Every v6 owner `_write()` transaction with durable changes now serializes the
exact canonical Continuity package on the same connection while its
`BEGIN IMMEDIATE` transaction is open and rejects an over-8-MiB package before
`COMMIT`. The exporter uses that same serializer. The 8 MiB and 10,000-row
limits were not changed. The v6 exporter uses a read snapshot; v5 retains its
original `_read()` export path and gets no new precommit size gate. Initialization
only writes genesis metadata/identity; all normal owner mutations use
`_write()`, Continuity restore uses `owner._write()`, and Mirror commands
delegate to the owner. The receipt remains synthetic/unapproved funding
evidence, separate from obligations, received cash, actions, and payments.

The acceptance coverage adds (1) a clock rollback supersession rejection with
exact package/count/meta equality, independent verification, and an exact
duplicate retry without another clock sample; and (2) a bounded near-cap
scenario with successful below-cap writes, exact package preview from the
active transaction connection, rejection of the next public write, unchanged
package/count/meta, and independent verification plus TEST restore before and
after rejection.

### Retained v6 run history

The raw child logs below are stored under
`../pq-wide-seed-native-20260913/build-filter-native/` as
`guarded-command-financial-v6-state-20260922-<suffix>.stdout.log` and its
`.stderr.log` companion; `<suffix>` is `r1`, `r2`, `r3`, `final`, `final-r2`,
or `final-r3` as identified below.

- `r1` child logs are
  `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v6-state-20260922-r1.stdout.log`
  (20 bytes, SHA-256 `4434B00F9E40FE1DA2DE15D5DCFB297B70C45B3DC7021AA402F4C87D05E340DC`)
  and the `.stderr.log` companion (2,204 bytes, SHA-256
  `6C1C494E53DF8F2C245F67765ABB5094894E4CA1298037C861DCB479913AC703`).
  Test collection stopped before any test ran: `PERIOD_ONE_SCOPE` was
  undefined in `tests/rightrail_financial_expected_cases.py:251`.
- `r2` logs are the matching `r2.stdout.log` (251 bytes, SHA-256
  `F4E6D5EBFC01F02D67388F75A4C9FBFF33D95908D34915DD6B7F7718BD923D8E`)
  and `r2.stderr.log` (14,054 bytes, SHA-256
  `8B43353493CEB7CE535706DAD7BD9F97CF2C79B1132B4513161DB63765113329`).
  It ran 67 tests and failed with 1 failure and 6 errors. The retained causes
  include missing expected scope in continuity verification, an undefined
  `_hex` in funding verification, and a v2/v3/v4 expectation mismatch.
- `r3` logs are the matching `r3.stdout.log` (251 bytes, SHA-256
  `3843E881F0573496623238FA0D2AFABDB3416EE18E91703FA4F81F7902B40CEE`)
  and `r3.stderr.log` (172 bytes, SHA-256
  `3251FF86A0165969173BEE919E82226F5E2CC6B60FA93B2B226C499F8EB08331`).
  The prior-source run reported `Ran 67 tests in 55.586s` / `OK`, with no
  warning or skip output. It predates the two new correction tests.
- The first post-handoff run used suffix
  `financial-v6-state-20260922-final`. Its child logs are 230 bytes / SHA-256
  `DE792E063EA22A4B1E6AA7172E789871AB9B96A9BF70E4466C26F1B73E6A3429` and
  914 bytes / SHA-256
  `EE7E181E309867B9136F82B0F52A8E5A455A8EF4641D1B81C932722B21E80AD6`.
  It ran 69 tests in 35.922s and failed only on a brittle size prediction:
  actual growth `4046` bytes versus predicted `4040`. Guard child and outer
  exits were `1`; 66 samples completed, minimum free memory was `4446306304`,
  cleanup passed, and the mutex was released. This was not a resource stop.
- `final-r2` ran 69 tests in 95.630s / `OK` with child and outer exits `0`.
  It preceded the final v5 read-path preservation adjustment. Its logs are
  230 bytes / SHA-256
  `DE792E063EA22A4B1E6AA7172E789871AB9B96A9BF70E4466C26F1B73E6A3429` and
  174 bytes / SHA-256
  `72EE50E9644C09DFDF88FD863969985C3051CF09CB064141EDDCF6BC59B3DE16`.
- Final source was run as `run_guarded_v3.ps1 -Mode Command
  -RunSuffix financial-v6-state-20260922-final-r3`, invoking pinned Python
  3.11 and `unittest.main(module=None)` after changing to this checkout, for
  `tests.test_right_rail_financial_acceptance`,
  `tests.test_right_rail_financial_independent`, and
  `tests.test_right_rail_financial_mirror`. Result: `Ran 69 tests in 95.180s`
  / `OK`; no warnings or skips. Child exit and outer wrapper exit were `0`;
  guard self-tests were `exit7=7 exit0=0`; samples `169`; minimum free bytes
  `4386463744`; peak working set `141508608`; peak private bytes `125403136`;
  cleanup `PASS`; mutex `RELEASED`. Guard SHA-256 was
  `55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`,
  reserve `3221225472`, floor `2190433321`, and process-tree cap
  `2000000000`. The final child stdout log is 230 bytes, SHA-256
  `DE792E063EA22A4B1E6AA7172E789871AB9B96A9BF70E4466C26F1B73E6A3429`;
  stderr is 174 bytes, SHA-256
  `B0B78E35C9B9996B8636D3268BFA39D18A6912ECC54105F8A88FC5EC301009F8`.
  Exact child executable and arguments were:
  `C:\Users\neers\AppData\Roaming\uv\python\cpython-3.11-windows-x86_64-none\python.exe -c "import os, unittest; os.chdir(r'C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-financial-workflow-20260913'); unittest.main(module=None)" tests.test_right_rail_financial_acceptance tests.test_right_rail_financial_independent tests.test_right_rail_financial_mirror`.
  The child logs emitted no warning or skip notices; all earlier failures are
  retained above and in their raw logs.

The fresh preflight immediately before `final-r3` was at
`2026-09-23T03:26:51Z`: guard hash matched, mutex was free, relevant external
process count was `0`, and free memory was `4530003968` bytes versus the
`2190433321`-byte floor. The guard's own preflight was `4530880512` bytes.
`git diff --check` exited `0`.

Final source SHA-256 values:

- owner: `4880160AA34377A0263AAE6597549E914511F0628CECAFDACD7D71E87FCFD8D6`
- independent checker: `E595EA269565F2DF7524CDDFE2C878591D616350E7794244FA930517734102A1`
- Mirror: `F28FC979CBAD7FA04196860739D814183C5B22C6ABDB445147C1EF8C95A76C5B`
- expected cases: `A8D07CDDE31756A17FC8FB397FD0D93681D18C6DD4F722F3B4F7A69AC4E89653`
- acceptance tests: `B9960B88B91C0950D112486BE1EF3C2AB1027547713986AB5D798A8B651043C5`

### Formal handoff and nonclaims

The direct Engine handoff reported a failed finite proof-chain invocation:
`CodecLaws` produced 18 compiler error headers; `CodecLawsCheck` and
`blind_financial_axioms` were skipped (2); 54 warnings were retained in the
full Engine stdout log. No proof artifact or theorem result is established.
The stale `blind_financial_axioms.exe` is not evidence. The raw logs are
`../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-codeclaws-proofchain-20260923-engine-1790132237849.stdout.log`
(77,980 bytes, SHA-256
`1742153417C0AF4F50609ECAE31615303E8A26940DA01909F202AA1741392E6F`) and the
`.stderr.log` companion (20 bytes, SHA-256
`C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F`, exact
text `error: build failed`). Security owns the Lean source repair; State ran
no Lean command.

This is local verification of the synthetic v6 owner correction, pending
Driver review. It does not expand the prior narrow v5 disposition or establish
clock atomicity, authenticated funding, State approval, recipient cash,
payment authorization, official confirmation, live dispatch, PHI use,
executable Lean linkage, whole-system qualification, or production readiness.
Claims remain `proofSuiteId=null`, `production_usable=false`, and
`activation=false`. No file was staged or committed; unrelated dirty and
untracked paths, including the protected `build-performance/` executables,
were preserved.

## C05 per-obligation decision package — source-ready handoff (2026-09-23)

Source work adds `FinancialOwner.decision_package` and a read-only
`FinancialMirror.decision_package`. The owner reads one SQLite snapshot,
returns the exact current evaluation receipt, rule/control-pack and authority
identity, case, current determination/action/outbox acknowledgment, cash and
reporting state, and individually paginated typed evidence/payment/claim/
determination/action/conflict references. Page size is capped at 200,
offset at 10,000, and the canonical package at 8 MiB minus a small Mirror
wrapper margin. Optional evaluation id/result-digest inputs reject wrong or
stale bindings. No schema or policy authority changed.

Mirror recursively removes payload/source-byte, content-digest,
input-snapshot, private-proof, and display-label fields. It emits only
allow-listed action payload fields. Action acknowledgment is shown from the
durable outbox row with `cash_effect_cents=0`; cash conclusions use active
payment rows. The independent checker now verifies the full database and
reconstructs the package from a read-only snapshot, including page contents,
receipt digests, and conclusions.

The hand-derived fixture remains 20 recipients / 100,000,000 cents ($1,000,000).
H progresses from 9,700,000 cents recorded cash and a 300,000-cent shortfall,
through correction authorization and ACK, to linked payment/report evidence.
Contradictory payment evidence preserves the intended state pair
`case_status=RESOLVED` and `verification_status=CONFLICT_VISIBLE`; the new
package labels its evidence-backed assessment `CONFLICTED` and includes both
conflicting amounts and evidence IDs. It does not rewrite the owner status.

Focused tests were authored for the H chronology, wrong/stale receipt bindings,
omitted package references, pagination/caps, read-only behavior, independent
reconstruction, Mirror redaction, and v6 TEST-restore continuation. **No test
or checker was run for C05.** The finite guarded lane is currently assigned to
Security, then Engine for the ordered proof rerun; only after Engine directly
hands the clean lane to State may State perform one fresh preflight and one
focused guarded test run. Do not poll or reserve that lane. `git diff --check`
exited `0`.

Source changes are confined to the authorized owner, independent checker,
Mirror, expected-case fixture, acceptance tests, and Mirror tests. Working tree
remains at commit `8f75f527ae6717001978ac7401853c2aaae55f2b`; no files were
staged or committed. The pre-existing protected `build-performance/` tree
and unrelated dirty docs were left untouched. Two additional untracked docs
(`docs/SOURCE_RECEIVER_CONTRACTS.md` and
`docs/STATE_SIDE_OPERATIONS_ARCHITECTURE.md`) appeared during this phase and
were preserved without inspection or modification.

## C05 focused guarded verification — PASS (2026-09-23)

This follow-up supersedes the source-ready note above that C05 had not yet run.
The direct Engine-to-State handoff was received at a clean idle boundary. The
Engine preflight did not meet its proof workload start estimate; State treated
that as no proof-run receipt and launched no Engine proof targets.

The fresh State preflight matched the C05 source hashes recorded below and
guard SHA-256 55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D.
The unchanged guard policy is a 3,221,225,472-byte reserve, 2,190,433,321-byte
floor, 2,000,000,000-byte process-tree cap, and mutex
Local\BlindLedgerDirectMaskBuild20260907. Free physical memory was
4,026,306,560 bytes against a workload-specific start threshold of
2,441,239,593 bytes (guard floor plus twice the prior full State run's
125,403,136-byte peak private use). Relevant process count was 0; the mutex
probe acquired and released; designated log paths were absent; and
git diff --check exited 0.

Exactly one guarded Command invocation used run suffix
financial-c05-decision-package-20260923-r1 and the Python 3.11 interpreter.
It ran only these three test methods:

- tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_decision_package_tracks_evidence_and_keeps_ack_separate_from_cash
- tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_c05_v6_decision_package_survives_test_restore
- tests.test_right_rail_financial_mirror.FinancialMirrorTests.test_c05_decision_package_is_sanitized_bounded_and_ack_is_not_cash

All 3 passed in 1.598 seconds. No child warnings, failures, or skipped tests
were emitted. The wrapper and child exited 0; guard self-tests reported
exit7=7/exit0=0; minimum live free memory was 4,005,203,968 bytes; peak owned
working set/private bytes were 37,163,008/21,262,336; owned process cleanup
passed; and the mutex was released. Complete child output, hashes, and raw log
paths are recorded in STATE.md below. Final git diff --check exited 0.
No source code changed in this verification step, and nothing was staged or
committed.

## C05 source-only corrections — guarded verification pending (2026-09-23)

This entry supersedes the preceding C05 focused guarded PASS as evidence for
the corrected source hashes below. The earlier 3/3 result remains accurate
for its pre-correction files, but does not verify this correction packet.

The owner now selects current delivery action by action revision, with action
ID as a deterministic tie-break; the decision package selects its current
determination by resulting revision, with determination ID as a tie-break.
The independent checker uses those same revision keys in its current
projection and package reconstruction. For stored historical evaluation
inputs, it binds each snapshotted action ID to that immutable action row's
revision before reconstructing delivery status. Stored input snapshots and
their digest contract are unchanged. Completion-time calculations still use
determination and payment event times.

The independent decision-package verifier now bounds and clones caller input
before opening SQLite. The preflight counts canonical JSON bytes using the
existing compact, sorted, ASCII-escaped encoding, and limits depth to 32 and
nodes to 250,000. It rejects cycles and oversize input with
decision-package:input-limit; unsupported nested types and keys fail with
decision-package:input. The local byte cap is 8 MiB minus 512 bytes, matching
the owner's package allowance. The checker still has no owner import.

Mirror's sanitized decision_package now drops input_snapshot_digest.
Owner receipts and FinancialMirror.current_evaluation_receipt retain that
field; the owner receipt construction and independent receipt verification are
unchanged.

Two new acceptance methods cover clock rollback with a later revision and
bounded pre-open verifier rejection for oversized, over-depth, and cyclic
input. The existing Mirror sanitizer test now checks digest retention on the
receipt API and removal from the decision-package view. This phase ran zero
tests, with zero framework skips recorded because the test runner was not
invoked. No checker, guard, build, compiler, or test command ran. The one
focused guarded packet remains deferred until Driver directly hands State a
safe lane after Provider; State did not poll or reserve the lane.

Source-only static evidence: git diff --check exited 0. The static
current-selection search found no timestamp-based action or determination
selection; event-time completion ordering remains in place. No schema, stored
wire/input, authority, or production claim changed.

Repository remains on branch rightrail-financial-workflow-20260913, HEAD
8f75f527ae6717001978ac7401853c2aaae55f2b, tree
05d6df5bf4c36a9e267f2b471a86764a242f227e. The source/test pre-edit hashes
matched the handoff. This correction touched only the Owner, independent
checker, Mirror, acceptance test, and Mirror test within the authorized source
scope; no expected-case fixture was edited. No files were staged or committed.
The working tree has 12 modified tracked paths and 8 untracked entries.
Protected build-performance/ and all other unrelated work remain preserved.
The two additional untracked Docs deliveries were authorized independently
and preserved without modification:

- docs/FINANCIAL_STAFF_WORKSPACE_ARCHITECTURE.md:
  7C897E35D10B5D2E40B9411BF0FED0E45C4B1059104B549AE6CB7C5684E727F6
- docs/SWITCH_TRANSFER_ARCHITECTURE.md:
  E8F50FD0B3AA3FAB4CB5F02DB8B5B1D37C41B69E1925F615A525B46EF70D82AC

SHA-256 identities before and after this correction:

| File | Before | After |
| --- | --- | --- |
| app/right_rail_financial_owner.py | 8EEA69734ED1B57A2BEDC4B99FA3F85DB44DD80761CA5668CD1D25D277A44094 | 484B4CAAAE0828765081B8E236BC1F39404748AAA32E7F715453615A9753951D |
| app/right_rail_financial_owner_independent.py | 7630D5DC7BBA486C5CEA74E9226594C4B28D4ECED955189090465986AE703239 | E393623867D104B2A9A098586209574A735DCA674272162CD2F1DA61E566B055 |
| app/right_rail_financial_mirror.py | 082031E84A899A654BCCED6A1F3C3FD267286FEE20F532FD14C76937652BE1D9 | 9027C56D9A1B49C615CD6CDAB0250471346C1767714A095D75A90C940279B51A |
| tests/test_right_rail_financial_acceptance.py | 9DD486A361233441E6868862D4665CA34EF7BE7ACBADB53C2E8ECA26A62E442C | CC02C55EC2932A2EB1D7A6739D8DF569619FFDB3D54A9054BF0FBD877531A725 |
| tests/test_right_rail_financial_mirror.py | 8258B0262333278FA75A520837CE000557965309D1F331D9B552C8E8F97E8D4A | E5A23AD8AE6D4F340F96FD269446E9AE10815C4987369263ED56F9D1A4020423 |

Pre-edit documentation hashes were CURRENT_TASK.md
1077F8BCA45ADF314FAF370FB2FE160C9D3A1E97285BEC662566008A0B7BED54 and
STATE.md EA7938EFA5F6E5038BEEA2E1C6ABBAAF0ACFE550158ED7E4D272748509E6467A.
The final documentation hashes are recorded in the verified handoff.

Post-edit line references: owner current delivery 1632-1634 and package
selection 3290-3299; independent bounded input 489-601, historical revision
binding 2637-2654, current projection 2835-2837, and package selection
3660-3663; Mirror drop set 48-50; new acceptance methods 2873-3004; Mirror
assertions 163-214.

## C05 guarded run after source correction — 4/5; follow-up required (2026-09-23)

Driver directly handed State the guarded lane. One fresh preflight passed and
exactly one guarded Command ran only the five C05 methods listed in the
handoff. Guard self-tests passed (`exit7=7`, `exit0=0`), but the Command child
and outer invocation exited `1`: four methods passed and
`test_c05_independent_package_input_is_bounded_before_database_open` failed.
The assertion expected `decision-package:input-limit`, while the independent
checker returned `decision-package:input`. The runner reported
`Ran 5 tests in 4.039s` and `FAILED (failures=1)`; no skips were reported.

The raw child logs are
`../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-c05-source-correction-20260923-r1.stdout.log`
(0 bytes; SHA-256
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`) and
`../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-c05-source-correction-20260923-r1.stderr.log`
(1,384 bytes; SHA-256
`F2207E975CA0837B74B956766863EACCBD8D6978B9A3D4A1589D994A788724E7`).
The complete child failure output and guard transcript are in `STATE.md`.
Owned process cleanup passed, the mutex was released, post-run relevant
process count was 0, and `git diff --check` exited 0.

The failure showed that `_fail` raises `IndependentFinancialError`, a
`RuntimeError` subclass; the dict/list mutation handlers caught and
normalized that error. Both handlers now re-raise `IndependentFinancialError`
before translating iterator `RuntimeError` in
`app/right_rail_financial_owner_independent.py`. The post-fix SHA-256 is
`1FD251FBF2A7F121FFE2644B71A125FE6054FDBA3A5C0B743D6C13D3C0350CC9`.
No test or checker was run after this source edit. The single guarded-run
authorization has been used; the corrected source remains unverified pending
a new direct safe-lane handoff and guarded authorization. This is a focused
5-method result, not a broader suite or production qualification.

## C05 post-fix affected-method guarded rerun — PASS (2026-09-23)

After reviewing the retained r1 failure, Driver explicitly authorized a new
fresh preflight and one affected-method guarded rerun. The narrow independent
checker fix is described above. Four C05 acceptance methods call
`verify_decision_package`, so the rerun included those four; the Mirror
sanitizer method does not call the independent checker and its source/test
were unchanged.

The r2 guard passed its self-tests (`exit7=7`, `exit0=0`) and its Python child
and outer invocation exited `0`. The child reported `Ran 4 tests in 3.347s`
and `OK`, with no skips or warnings. Owned process cleanup passed and the
mutex was released. Raw r2 child logs and the complete guard transcript are
recorded in `STATE.md`; r1 remains a retained failed attempt. The Mirror
sanitizer method passed in r1 and its dependencies were unchanged, so all five
focused C05 methods have individual green results across the two runs, though
the corrected source was not exercised by one combined five-method command.
No broader suite, compiler, checker batch, native, or Lean target ran.

The post-fix independent checker SHA-256 is
`1FD251FBF2A7F121FFE2644B71A125FE6054FDBA3A5C0B743D6C13D3C0350CC9`;
other C05 source/test hashes match the recorded handoff. Final
`git diff --check` exited `0`; HEAD/tree are unchanged, the working tree
remains 12 modified tracked paths and 8 untracked entries, and nothing was
staged or committed. At the safe boundary, State sent the direct lane handoff
to the active `Lean Engine` task under Driver direction. Engine acknowledged
and began its fresh preflight; its proof result is not yet available. State
reports both C05 run results to Driver.

## C02/C03 population-manifest v7 source packet — pre-run snapshot (2026-09-23)

The current working tree contains a source-only v7 population-manifest
implementation. Each immutable manifest binds the synthetic scope, approved
Control Pack, cutoff, inclusion rules, source owner and source identity,
trusted authority and approver, and a separately authored exact sorted member
roster. A mutable head projection is cross-checked against immutable lineage;
supersession is explicit and serialized; each population binds to one
manifest. Staging rejects extra or duplicate members, exact persisted
membership controls source completion, and validation/publication recheck the
current manifest and stored roster. The independent checker reconstructs
manifest receipts, membership, authority, lineage, event order, heads,
bindings, and population completeness. Mirror exposes only a redacted
completeness projection. v5/v6 population writes fail before mutation, and
legacy restore requires an empty population boundary.

The in-scope implementation paths are:

- `app/right_rail_financial_owner.py`
- `app/right_rail_financial_owner_independent.py`
- `app/right_rail_financial_mirror.py`
- `tests/rightrail_financial_expected_cases.py`
- `tests/test_right_rail_financial_acceptance.py`
- `tests/test_right_rail_financial_independent.py`
- `tests/test_right_rail_financial_mirror.py`
- `tests/test_right_rail_financial_semantic_adapter.py`

The semantic-adapter fixture uses the fixed v1 roster and asserts that the
manifest metadata does not expand the frozen adapter population object. The
acceptance tests cover schema gates, roster substitution/duplicates, manifest
retry and authorization, stale bindings, supersession, concurrent
supersession, continuity tampering, and persisted imported-count drift.

This is an unverified source packet. No v7 tests, Python compilation, checker,
native build, or Lean target ran in this phase. The guarded lane remains
deferred until a direct safe-lane handoff and fresh preflight; no lane was
reserved or polled. Static review identified the owner as the sole writer,
the independent checker as the verifier, and Mirror/Continuity as read-only
surfaces; it found no authority switch or live payment path. The narrow v5
disposition above remains historical evidence and does not qualify these v7
changes.

The existing dirty `docs/IMPLEMENTATION_ROADMAP.md` and
`docs/LEAN_FORMAL_KERNEL.md`, all driver-supplied untracked documents, and both
untracked executables under `build-performance/` were left untouched. No files
were staged or committed.

## C02/C03 v7 retained guarded failures and source-only continuation — UNVERIFIED (2026-09-23)

This entry supersedes the v7 pre-run snapshot above for current status. The
guarded v7 evidence consists of two failed attempts; no v7 pass or acceptance
is claimed. The post-r2 fixture correction and subsequent C05/Mirror changes
have not been tested.

### r1 — 15 selected methods, 13 passed, 2 failed

The unchanged shared guard was SHA-256
`55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`;
the effective free-memory floor was `2,190,433,321` bytes. Preflight free
memory was `3,151,753,216` bytes; the workload minimum was `3,077,791,744`
bytes, peak working set `40,058,880`, and peak private bytes `24,707,072`.
Guard self-tests reported `exit7=7 exit0=0`; cleanup passed and the mutex was
released. The outer invocation and Python child exited `1`. The runner reported
`Ran 15 tests in 5.779s` and `FAILED (failures=2)`; no tests were skipped.

Raw r1 results are preserved under
`../pq-wide-seed-native-20260913/build-filter-native/`:

- `guarded-command-financial-v7-population-manifest-20260923-r1.stdout.log` — 2,546 bytes; SHA-256 `99BC92A03EAA2C29BB4DC04BDFAF92D6103B8E0EBEDD3037206F9C112D28BE52`.
- `.stderr.log` — 5,252 bytes; SHA-256 `39F5C6DC649DE13C2530505995BB129E8E332C7A2F8019CDC203C5A0E0FF96F0`.
- `.transcript.stdout.log` — 2,973 bytes; SHA-256 `6C004385F8A0604CABB3BEA59150AE1DC5517ED0B3B2C585E123C1DDC29495A3`.
- `.transcript.stderr.log` — 0 bytes; SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.

The two failures were:

```text
test_rehashed_population_history_rejects_invalid_completion_lifecycle
  expected: history:population-stage-order
  actual:   history:predecessor

test_partial_population_history_binds_persisted_count_through_restart_and_restore
  expected sequence: 3
  actual sequence:   4
```

The fixture rewrite helpers used the v5 genesis domain on v7 data and
retimed every event, including immutable population-manifest registration.
The corrected helper now uses the schema-versioned genesis domain, expects
sequence 4 (Control Pack, manifest registration, and two population chunks),
and preserves the manifest registration event's immutable `registered_at_ms`
while rehashing the later population events.

### r2 — two affected methods, both failed at manifest event binding

R2 ran only the two affected independent-history methods. Fresh preflight free
memory was `3,136,262,144` bytes; minimum free memory was `3,076,796,416`
bytes, peak working set `32,665,600`, and peak private bytes `17,678,336`.
Guard self-tests reported `exit7=7 exit0=0`; cleanup passed and the mutex was
released. Outer and child exits were `1`. The runner reported
`Ran 2 tests in 1.155s` and `FAILED (failures=2)`; no tests were skipped.

Raw r2 files:

- `guarded-command-financial-v7-population-manifest-20260923-r2.stdout.log` — 485 bytes; SHA-256 `82221A5E7761BAA27770892A6807463CCF8F74E768617640EC78B614898CDC0F`.
- `.stderr.log` — 4,470 bytes; SHA-256 `33B40025F0FD8E515185C43749C6F465A33A2A84CF7F2C58368939953DF42CD6`.
- `.transcript.stdout.log` — 1,986 bytes; SHA-256 `FB571795E7996DFAAEDBD7BB23D97E57E8B7F9B7C1995A05AC1FBB89C8685D9B`.
- `.transcript.stderr.log` — 0 bytes; SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.

The raw r2 assertions remain:

```text
test_rehashed_population_history_rejects_invalid_completion_lifecycle
  expected: history:population-stage-order
  actual:   population-manifest:event-binding

test_partial_population_history_binds_persisted_count_through_restart_and_restore
  expected: history:population-imported-binding
  actual:   population-manifest:event-binding
  failing variant: removed
```

The r2 event-binding failure showed that the helpers still changed the
registered manifest event's `committed_at_ms` without changing the immutable
manifest `registered_at_ms`. The timestamp-preserving correction described
above was written after r2 and has not been run.

### Source-only C05 and Mirror follow-up after r2

The authorized source/test slice now also includes these unverified changes:

- Owner C05 decision-package contract v2 for v7 adds `population_binding`:
  published population ID/status, exact-completeness flag, manifest ID/version
  and digest, member ID/count, and member digest. The owner reconstructs this
  within its single `_read_snapshot()`; the independent checker reconstructs
  the same fields from its own read transaction and rejects changed manifest
  version/digest/member ID. The v5/v6 C05 contract remains v1.
- A focused acceptance method ties the C05 obligation, evaluation receipt,
  determination, current action, and acknowledgment/outbox reference to that
  exact member; it tampers with manifest version, digest, and member ID and
  checks restore equality plus independent reconstruction.
- Mirror recursively removes `population_id`, `manifest_id`, manifest/member
  digests and member IDs from staff-facing views, and removes `aggregate_id`
  from `POPULATION` and `POPULATION_MANIFEST` history rows. C05 retains only
  status, completeness, source-complete flag, manifest version, and member
  count. Tests assert redaction from C05, obligation list/detail, population
  status, and history.
- The independent fixture test documents that `source_digest` is a caller
  assertion: exact match against the caller-supplied 20-member roster does not
  authenticate source bytes or prove external denominator completeness. No
  external State approval, authenticated source adapter/watermark, or
  separately pinned expected-denominator evidence is available here.

No tests, compilation, checker batch, native build, or Lean target ran after
r2. The current Driver instruction reports that managed-sandbox
`Get-CimInstance Win32_OperatingSystem` now returns `Access denied` and is
required by the guarded memory preflight. No guarded workload was launched
after that notice. Do not relabel r1/r2 or claim a v7 pass. The remaining
guarded verification needs a fresh safe memory path after Queue uses the
finite lane; the lane was not polled or reserved here.

The source/docs changes remain unstaged and uncommitted. The protected
`docs/IMPLEMENTATION_ROADMAP.md`, `docs/LEAN_FORMAL_KERNEL.md`, Queue/Engine/
Security paths, untracked `build-performance/` executables, and seven
untracked Driver/Docs-owned Markdown files were preserved. No live authority,
external State completeness, payment, deployment, or production claim follows.

## Queue/State mapping receipt boundary — source/docs-only continuation (2026-09-23)

This update preserves the failed r1/r2 evidence above and supersedes only the
earlier current-blocker statement that CIM access was denied. The latest
Driver update says CIM access works in Driver context, while Queue owns the
finite guarded lane first. State remains source/docs-only until a direct lane
handoff and a fresh target-specific preflight. The current Driver-root guard
is v4, SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`; every
future invocation needs the target's documented `-MinimumStartFreeBytes`.
The 2026-09-23 process-memory cap waiver leaves the 2,190,433,321-byte physical
floor, mutex, process-tree cleanup, self-tests, and checked exits in force.
No guarded invocation or State-side memory preflight ran in this continuation.

The Driver corrected the Profile 12 interpretation: its phrase “state owner”
may refer to Queue's own stateful owner, and Queue's `issue_batch` is that
owner. Queue's creation of 100 proof-operation references is not evidence of
a Profile 12 violation. Preserve the frozen Profile 12 contract and distinguish
Queue proof-operation references from State financial member and obligation
IDs. The verified gap is that the Queue-local references, the separate
Queue/Composition database transaction, and the financial owner's
population/obligation identities lack an implemented cross-owner receipt.

State owner, checker, Mirror, and semantic-adapter code currently contain no
Queue mapping-receipt ingestion or verification API. The State v7 manifest
and C05 v2 bind its own population member to a State manifest revision; they
do not assert a Queue mapping. The proposed additive envelope is
`RR/FINANCIAL/QUEUE-STATE-MAPPING-RECEIPT/v1`. It would bind a unique receipt
ID and canonical digest; authenticated Queue issuer/schema/Profile 12/batch
identity and canonical digest of the exact 100-reference set, with
order/canonicalization defined by the approved Queue contract; State scope and
exact population/manifest/version/digest/member-digest; and explicit mapping
edges to State member ID, obligation ID, and applicable obligation revision.
The mapping's cardinality and coverage predicates remain unspecified until
the relevant owners approve them; no 5:1 or other ratio is inferred.
ControlPack `source_refs` remain distinct State policy/source references.

Proposed retry semantics are exact receipt-ID/canonical-digest replay as
`DUPLICATE`, changed bytes under the same ID as conflict, and a changed
mapping under explicit version/predecessor lineage. Proposed recovery uses
durable owner-local outbox/inbox records: each database commits its own
receipt/ack state, exact replay after a crash returns the stored outcome, and
no shared database or cross-owner atomicity is claimed. This remains a
contract proposal, not a State runtime API. A Queue reference alone must not
be interpreted as a State financial identity or authorize evidence,
determination, action, cash, or an outbox transition.

Authority review questions to close before implementation:

1. What does each of the 100 Queue references identify, and what are its
   namespace, canonicalization/order, uniqueness scope, and lifetime across
   retries and batches?
2. What mapping relation is required: one Queue reference to one or many
   financial targets, many references to one target, or another explicitly
   approved relation? What exact coverage and duplicate-edge rules apply to
   the 20 State members?
3. Is the receipt issued by Queue, State, or both? What trust root, signature
   or equivalent authentication, key rotation, revocation, and source proof
   establish issuer authority and bind the 100-reference digest?
4. Is the State target a published manifest/member only, or must every edge
   include an already-created obligation ID and expected revision? At what
   point in batch issuance, population publication, and obligation creation
   is the mapping receipt produced?
5. What are the Queue and State inbox/outbox acknowledgment states, retry
   owner, timeout, partial-delivery, correction/supersession, and compensation
   rules when the two databases commit independently?
6. Does acceptance record provenance only, or can any approved consumer use
   the mapping as evidence? It must remain separate from financial
   determination, action authorization, acknowledgment, and cash unless a
   separate State policy explicitly defines those effects.

No source/API, Profile 12, Queue/Composition database, or live financial
acceptance change was made for this proposal. A read-only broad `rg` command
over `app` and `tests` returned Queue test/source match lines; no files were
modified and subsequent inspection was restricted to the State-owned modules.
No tests, Python compilation, checker, native build, or Lean target ran.

## C02/C03 and C05 v7 selected guarded verification — PASS (2026-09-23)

This entry supersedes the earlier current-status statements for the selected
State test packet only. The r3 partial-history test raised the correct
`history:population-imported-binding` error while verifying a deliberately
tampered Continuity package, but the test did not assert that expected
rejection. The test now asserts that exact checker exception; this was a test
expectation correction, not a weaker integrity condition. Owner verification,
independent database verification, restore-integrity rejection, and
no-destination assertions remain.

After Engine's direct lane release and fresh target preflight, the v4 guarded
runs reported:

- r4: both focused independent-history methods passed (`Ran 2 tests in
  2.851s`, `OK`).
- r5: the selected 15-method population/history/Mirror/semantic-adapter packet
  passed (`Ran 15 tests in 10.287s`, `OK`).
- r6: `test_c05_v7_population_revision_binding_is_verified_and_restored` passed
  (`Ran 1 test in 1.412s`, `OK`).

Each invocation used v4 SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB` and
`-MinimumStartFreeBytes 2190433321`. Each reported self-test exits 7 and 0,
checked child exit 0, `CLEANUP=PASS`, and `MUTEX=RELEASED`. The r6 completion
was followed by `MUTEX=ABSENT` and zero relevant processes before handoff to
Cleanup. This is selected synthetic regression evidence, not whole-repository,
external-source, production, or system qualification. Exact method IDs, per-run
measurements, log hashes, and nonclaims are in `STATE.md`.

## Lean correction transition boundary — source-only (2026-09-23)

This note supersedes the earlier Python-authoritative correction status for the
specific reject_offset_and_authorize_correction path. The method no longer
executes the Python determination/action/outbox/event mutation sequence for a
new correction. It returns correction_transition_unavailable unless the
versioned Engine transition is available; a readiness-gate bypass still ends
in the same rejection. Existing exact retries require the complete stored
identity, including decision time; deterministic determination-ID collisions
reject without mutation.

The Engine application module identifies
RR/FINANCIAL/CORRECTION-TRANSITION/v1 and refuses the current read-only
BLFIN02/BLFRES02 release for this operation. The exact BLFCMD01/BLFCRES1
field layout, golden request/result vectors, built artifact SHA-256, and
accepted-effect application contract have not been received. No accepted Lean
result is decoded or committed by this State checkout yet.

The runtime convergence directive also requires dependencies actually consulted
by the accepted operation and durable follow-up identities to be captured in
the same owner transaction. The forwarded Engine contract identifies the
correction action/outbox and event intent, but does not yet define a dependency
receipt/result field set. The existing action outbox remains the only current
durable correction work item; no new dependency record or follow-up identity
was invented.

Focused source changes:

- app/right_rail_financial_owner.py — fail-closed new-correction boundary,
  complete retry-binding requirement, deterministic determination collision
  check.
- app/right_rail_financial_engine.py — explicit v1 operation identity and
  unavailable-wire gate.
- tests/test_right_rail_financial_engine.py — missing/read-only release gate
  test.
- tests/test_right_rail_financial_semantic_adapter.py — owner-boundary
  absent/bypassed transition rejection with database, continuity, projection,
  claim, action, and outbox equality checks.
- tests/test_right_rail_financial_acceptance.py — postcommit response-loss,
  exact retry, changed-time conflict, and retry-after-ACK/no-cash assertions.

No tests, compiler, checker, build, or guarded command ran: the Engine lane has
not been directly returned to this task and no fresh v4 preflight was performed.
The three new/changed focused test methods remain unverified. Existing acceptance
paths that require a successful correction remain pending the real v1 adapter;
they must not be treated as passing under this fail-closed source state.

Current repository identity remains branch
rightrail-financial-workflow-20260913, HEAD
8f75f527ae6717001978ac7401853c2aaae55f2b, tree
05d6df5bf4c36a9e267f2b471a86764a242f227e. No changes were made to
app/right_rail_financial_semantic_adapter.py, the independent checker, Mirror,
or Engine Lean sources. No files were staged or committed. Claims remain
proofSuiteId=null, production_usable=false, activation=false, synthetic,
nonpayment, and non-PHI.

Current focused identities:

- Owner: F246B3D9A9804A83B97E6296074CA4B91C3B7FCD7EE8C5BA0BE8ABBC53CAAF01
- Engine adapter: A4006DBF0B461DAE4A68E3D173C57AAC06B3E5B8EF0B2814EA1F54C17C893EB7
- Semantic adapter (unchanged): 23F6D1FBE59542F9F0B778D0D20236325CC3618017363F86C33BE38A0FC6618F
- Engine test: 35C4CCB32FE89D6CCC7A2BE94AD0DD6AF2D5E54F27EACC4EED97856D58FF7910
- Semantic adapter test: 7191C827979992DC113AFB08E9AF36C2EB9A03A39BDFF04E351F6F85D2ACB702
- Acceptance test: 94514311DE91FB0A85EC260226775CA0B36346E204265552A296279706BA120D

Next action: receive Engine's direct lane handoff and exact built v1 wire/artifact evidence; then implement the strict request/result adapter, compare the complete accepted delta, atomically apply the transition and event/outbox effects, and bind actual dependencies/follow-up identities. Run only the scoped correction checks under a fresh v4 preflight. At the safe boundary, hand the lane directly to Driver with exact guard tail, raw logs, hashes, and any resource STOP.

## Lean correction transition State adapter — source-only continuation (2026-09-23)

Engine directly returned the finite lane with source handoff HEAD
`907e32de63ab0d8133f2a7aff1441b06a1a884e8`. Its application source now
provides the BLFCMD01 request and BLFCRES1 result layouts, consulted dependency
facts, durable follow-up identities, and seven-effect order. State implemented
the strict candidate request encoder/result decoder and the Owner accepted
result adapter. The request binds the locked financial snapshot, current
evaluation receipt, authority, claim, control pack, complete unique-key lookup
observations, and same-transaction history version. The result decoder rejects
unknown tags/trailing bytes and binds the accepted effects, dependencies,
follow-ups, nested financial result, and event intent. Owner derives the exact
resulting BLFIN02 input from the locked pre-state and requires byte equality,
then decodes BLFRES02 against that derived snapshot before applying any effect.

The accepted Owner path remains in the existing `BEGIN IMMEDIATE` transaction.
It binds Engine output to the Owner receipt, authority, pack, claim, evidence,
query observations, and recomputed Owner digests; writes the determination,
claim rejection, case, action, and outbox; persists the returned Lean financial
result as the resulting evaluation; CAS-updates the obligation projection;
appends the event with Owner receipt enrichment; and rechecks durable rows.
This path does not call Python `_recompute_obligation`. Successful correction
responses retain `CORRECTION_AUTHORIZED`; committed exact retries retain their
existing duplicate handling.

This is source-only. `CORRECTION_TRANSITION_ARTIFACT_SHA256`,
`CORRECTION_TRANSITION_REQUEST_VECTOR_SHA256`, and
`CORRECTION_TRANSITION_RESULT_VECTOR_SHA256` are all `None`. No built artifact,
golden vectors, or accepted executable result has been verified. The Owner
therefore still fails closed before launching a new correction transition.
Engine's directly handed-off guarded lane reported an initial target-specific
start threshold of `4,190,433,321` bytes versus `2,896,142,336` bytes free
(short by `1,294,290,985`); no target launched. The v4 guard identity is
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`.

A later read-only no-run snapshot on this host measured `2,585,198,592` bytes
free. This meets the `2,190,433,321`-byte physical floor by `394,765,271`, but
is below the target-specific `4,190,433,321`-byte start requirement by
`1,605,234,729`. `Local\BlindLedgerDirectMaskBuild20260907` was absent; the
scoped relevant-process query returned 0. No guarded target or runnable lane
was handed to Lean Queue because target-specific admission is still unmet.

No test, build, compiler, Lean process, or guarded target ran. One local
`git diff --check -- app/right_rail_financial_engine.py
app/right_rail_financial_owner.py CURRENT_TASK.md STATE.md` did run (exit 0); it
reported only Git's CRLF-to-LF working-copy warnings for `CURRENT_TASK.md` and
`STATE.md`. This is not code or behavior verification. No files were staged or
committed. Claims remain `proofSuiteId=null`, `production_usable=false`,
`activation=false`, synthetic, nonpayment, and non-PHI.

### Resource and lane-routing update

The Driver subsequently reported a fresh no-run probe: `5,386,178,560` bytes
free, above the documented Engine start threshold `4,190,433,321`; probe exit
0, the v4 mutex absent, and 0 relevant Lake/Lean/Cargo/CMake/CTest/Clang/link/
guard-wrapper processes. This supersedes the preceding lower-memory snapshot.
State sent the one lane directly to the existing Lean Engine task
`01a0cb32-559d-7ad1-8dfc-d5933637d0d9` for its own fresh launch-time v4
preflight and guarded correction-only build. The Driver snapshot is not the
launch-time admission check. Engine must stop if its fresh target-specific
condition or any v4 control fails; broader checker/KAT targets proceed only if
their own current documented start condition passes. State has not run or
forwarded a guarded target.

Current working-tree SHA-256 identities:

- `app/right_rail_financial_engine.py` — `C9B74B441C3E7BF8DA1CFB2B8F98004D366FE1B1A930D9891C8BF7CE74E615E2`
- `app/right_rail_financial_owner.py` — `06BF05E098C26D81503CBC922B21D708BCCCB99C8E9D912E9D53332C58DC9548`
- `app/right_rail_financial_semantic_adapter.py` (unchanged) — `23F6D1FBE59542F9F0B778D0D20236325CC3618017363F86C33BE38A0FC6618F`
- `tests/test_right_rail_financial_engine.py` — `35C4CCB32FE89D6CCC7A2BE94AD0DD6AF2D5E54F27EACC4EED97856D58FF7910`
- `tests/test_right_rail_financial_semantic_adapter.py` — `7191C827979992DC113AFB08E9AF36C2EB9A03A39BDFF04E351F6F85D2ACB702`
- `tests/test_right_rail_financial_acceptance.py` — `94514311DE91FB0A85EC260226775CA0B36346E204265552A296279706BA120D`

These identify current working-tree bytes only; the focused tests remain
unrun and the executable/vector pins remain unset.

## Engine correction artifact handoff — State release still pending (2026-09-24)

Read-only recheck of Engine's canonical checkout confirmed the final narrow
executable and correction vectors. Engine HEAD remains
`907e32de63ab0d8133f2a7aff1441b06a1a884e8`; the executable is 6,245,376 bytes,
SHA-256 `E911E8844130155E4615D284D6D29A597B6E441DC45101D411EE8422EAE684B9`.
Request vector SHA-256 is
`13F832E80B93CC55D17ADD29470A2CD789CFCED1CBCF5A055FCBA3ECB927B537`; expected
result vector SHA-256 is
`312AB06C76D6F6F2F40CF93F9EE37DA328161B733FE7D5567E0694B85D3AE18E`.
The detailed identities and raw log paths are appended in `STATE.md`.

Engine's final r6 narrow build and r2 correction KAT are recorded as passing,
with one Lean unused-variable warning and an earlier corrected 31/32 KAT
failure. The actual r2 request/result files under the retained TEMP vector
directory match Engine's recorded sizes and SHA-256 identities. This verifies
the evidence files and does not verify the State adapter at runtime.

The Engine task is idle but has not delivered a direct release to this State
task (`01a0cb32-5c56-7073-a400-2f084a32566f`). Its earlier handoff was to the
separate Driver task. State's three correction pins remain `None`; no fresh
State v4 launch-time preflight, State test, transaction, or guarded target ran.
The direct release and State-specific preflight remain mandatory before
setting pins or launching tests. The current vector pin constants are only
checked for non-`None` in the Engine adapter gate; next verification must bind
those identities through an explicit release test as well as the artifact
identity. Existing acceptance helpers also construct Owners without an
explicit correction release, so successful-path tests need a narrow explicit
release fixture while the default stays fail-closed.

## Direct Driver release and bounded State verification — source prepared (2026-09-24)

The Driver directly transferred this finite lane to the current State task
`01a0cb32-5c56-7073-a400-2f084a32566f`; this supersedes the preceding
Engine-to-State wait requirement. The handoff reports v4 guard SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`, Engine
artifact SHA-256
`E911E8844130155E4615D284D6D29A597B6E441DC45101D411EE8422EAE684B9`,
6,245,376 bytes, 4,955,971,584 bytes free physical memory, the shared mutex
absent, and zero relevant processes. This Driver snapshot is not State launch
admission.

State source now pins the correction artifact size/SHA and request/result
vector SHAs in the immutable Engine release. The release gate compares every
pin. The default Owner still has no release. Only explicitly configured
successful-path acceptance fixtures read and assert the retained executable
and vector bytes before creating a release. The accepted path continues to
use the existing contained process runner and Owner transaction.

The bounded packet is the immutable-release/gate tests plus CASE04 successful
correction, CASE05 acknowledgment without cash, CASE08 concurrent revision
race, CASE10 precommit/postcommit/process restart boundaries, v5 exact retry
and conflict checks, and the missing/bypassed-transition no-mutation test.
Before any guarded target, take a fresh State-specific no-run snapshot and a
v4 wrapper preflight. The documented target-specific
`-MinimumStartFreeBytes` is `2400000000` for this Python/SQLite integration
packet and its pinned 6.2 MB Engine executable; the v4 physical-free floor
remains `2190433321` bytes. No test or guarded target has run yet for this
direct release.
## Direct State correction transition — verified bounded lane (2026-09-24)

This entry supersedes “Direct Driver release and bounded State verification — source prepared.” The Driver directly released the finite lane to this State task. State pinned Engine artifact size 6,245,376 bytes and SHA-256 E911E8844130155E4615D284D6D29A597B6E441DC45101D411EE8422EAE684B9, request vector SHA-256 13F832E80B93CC55D17ADD29470A2CD789CFCED1CBCF5A055FCBA3ECB927B537, and expected/actual result vector SHA-256 312AB06C76D6F6F2F40CF93F9EE37DA328161B733FE7D5567E0694B85D3AE18E. The vectors are byte-identical: request 3,357 bytes; result 5,589 bytes.

The immutable release gate compares all three pins. Owner remains fail-closed when no release is configured. Only explicit successful-path acceptance fixtures hash the retained executable/vectors and create a release. Owner validates Engine output against the locked pre-state, derives the exact post-transition BLFIN02 input, binds the nested BLFRES02 result to that expected snapshot, and applies the transition inside its existing BEGIN IMMEDIATE transaction. The expected snapshot now derives the claim, case, and delivery projections from the validated transition delta. The correction path does not call Python _recompute_obligation.

### Final selected verification

Fresh State preflight: ../pq-wide-seed-native-20260913/build-filter-native/state-correction-integration-20260924-r7.state-snapshot.log, SHA-256 4D30E3AB9E90C0AEADC133F386B95281EE2FAF41C911044593318D25927322C8. It records branch rightrail-financial-workflow-20260913, HEAD 8f75f527ae6717001978ac7401853c2aaae55f2b, index tree 05d6df5bf4c36a9e267f2b471a86764a242f227e, target floor 2,400,000,000, physical floor 2,190,433,321, free physical memory 4,603,625,472, exact v4 guard hash, mutex absent, zero relevant processes, and planned logs clear.

Command run under guarded v4 with PYTHONPATH set to this checkout and PYTHONDONTWRITEBYTECODE=1:

~~~text
python -m unittest -v
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

Complete guarded child result:

~~~text
Ran 9 tests in 9.650s

OK
~~~

Guard r7 reported self-test exits 7 and 0, checked target exit 0, CLEANUP=PASS, MUTEX=RELEASED. The guarded target had 18 process samples, minimum free physical memory 4,395,999,232, peak working set 89,157,632, and peak private bytes 57,384,960. Process-boundary output was:

~~~text
PROCESS_BOUNDARY precommit returncode=73 stdout='PHASE=BEFORE_REJECT\nPHASE=PRECOMMIT_AFTER_MUTATION\n' stderr=''
PROCESS_BOUNDARY postcommit returncode=74 stdout='PHASE=BEFORE_REJECT\nPHASE=POSTCOMMIT_AFTER_COMMIT\n' stderr=''
~~~

Raw success logs:
- ../pq-wide-seed-native-20260913/build-filter-native/state-correction-integration-20260924-r7.runner.stdout.log — 4,240 bytes, SHA-256 0AE106A965E9A3C919F8140B7B544FC5D5198BED820769883BD5FAB1FA1C6F98
- ../pq-wide-seed-native-20260913/build-filter-native/state-correction-integration-20260924-r7.runner.stderr.log — 840 bytes, SHA-256 018966BF53CB60E3BE45739D0B615E36EC0CD64FB2DC331E24320CE44F76DDFF; PowerShell startup progress records only
- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-state-correction-integration-20260924-r7.stdout.log — 230 bytes, SHA-256 DE792E063EA22A4B1E6AA7172E789871AB9B96A9BF70E4466C26F1B73E6A3429
- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-state-correction-integration-20260924-r7.stderr.log — 2,027 bytes, SHA-256 C5273CBE5CFDB49E85CC4A21175476E0A7DB88341907CC1617B4C1DA6B6A738C

The wrapper smoke r9 also passed under a fresh 2.4-billion-byte target preflight: v4 self-test exits 7/0, where.exe cmd.exe exit 0, CLEANUP=PASS, MUTEX=RELEASED. Its snapshot and raw files are state-correction-wrapper-smoke-20260924-r9.state-snapshot.log, state-correction-wrapper-smoke-20260924-r9.runner.stdout.log, guarded-command-state-correction-wrapper-smoke-20260924-r9.stdout.log, and guarded-command-state-correction-wrapper-smoke-20260924-r9.stderr.log.

### Retained failures and corrections

All failed logs remain in ../pq-wide-seed-native-20260913/build-filter-native. Guarded integration attempts r1-r6 each completed guard self-tests 7/0, checked child exit 1, CLEANUP=PASS, and MUTEX=RELEASED. Their exact test counts, runner stdout hashes, and child stderr hashes are recorded in STATE.md. Decisive progression: r1 had 8 tests, 3 errors/3 failures from the populated runner workspace and masked unavailable-transition failure; r2 had 8 tests, 3 errors/2 failures; r3 had 9 tests, 3 errors/2 failures at current-evaluation time binding (input time was one millisecond after the saved receipt); r4 had 9 tests, 3 errors/2 failures at correction-result input binding; r5 had 9 tests, 3 errors/2 failures after the Owner digest hex-case mismatch was corrected; r6 had 9 tests, 3 errors/2 failures after the input bytes matched but the nested financial result did not match the stale claimed projection. Diagnostics isolated the exact errors: engine_correction_authority_digest; Lean EVALUATION_CONFLICT/CURRENT_EVALUATION_BINDING; determinations_0_authority_digest lowercase hex; byte-identical 2,327-byte expected/resulting input; result_claimed_adjustment_cents; then result_case_status. The corresponding input-time, digest encoding, claimed projection, and case/delivery projection defects were corrected in scope and r7 passed.

Additional failed setup attempts are preserved: State preflight r3 passed its snapshot, then its v4 wrapper invocation failed before target start with “A positional parameter cannot be found that accepts argument '0'” (405-byte runner stderr SHA-256 F20DDDBDD1472EC238558D8E715A3448C9C2DFD418C3B26ED065BABBEB721F6E); State wrapper smoke r8 failed before guard start because the assumed $PSHOME\powershell.exe path did not exist; diagnostic helper r7 failed PowerShell parsing before v4 started; guarded diagnostic r8 ran one test and exposed result_case_status. The corrected smoke r9 and integration r7 passed. No failure was overwritten or relabeled.

### Final state and scope

Postrun snapshot ../pq-wide-seed-native-20260913/build-filter-native/state-correction-integration-20260924-r7.postrun-snapshot.log SHA-256 08AE77EFA719130823142F0515012F4A9D203CEF6A0CB2303E8E286854F89C6B records 4,624,928,768 bytes free, mutex absent, zero relevant processes, and the original branch/HEAD/index tree.

Changed for this lane: app/right_rail_financial_engine.py, app/right_rail_financial_owner.py, tests/test_right_rail_financial_engine.py, tests/test_right_rail_financial_acceptance.py, README.md, ARCHITECTURE.md, docs/RIGHTRAIL_FULL_STACK_TARGET.md, CURRENT_TASK.md, and STATE.md. The semantic adapter, independent checker, Mirror, Queue, Composition, and Lean sources were not changed for this lane. Protected build-performance/ was not touched. No files were staged or committed. Skipped selected methods: 0. No broader suite, compiler, or formal proof run was in this finite State lane. Claims remain proofSuiteId=null, production_usable=false, activation=false, synthetic, nonpayment, non-PHI, and dispatch-disabled. Handoff message sent to Driver task 01a0cb35-a28d-7ed1-9bfd-01e31ce68f30 after final verification.

## State continuity admission and correction follow-up — verified bounded lane (2026-09-24)

This finite State follow-up adds a local admission cache for v6/v7 Continuity and durable correction follow-up outputs. The cache table right_rail_continuity_admission records exported row counts and canonical row-byte totals inside the owner database, but is excluded from Continuity packages. Owner write-connection TEMP triggers maintain the cache transactionally; _write uses it to enforce the existing exact 10,000-row and 8 MiB package bounds before commit without serializing every exported row on each write. Existing v6/v7 stores are identity-checked before cache migration under BEGIN IMMEDIATE, then backfilled, size-checked, and independently recomputed on open. The independent checker recomputes the cache from exported rows and verifies its schema and exact package size. v5 export and precommit behavior remain unchanged.

Accepted correction events now carry a correction_followup v1 extension in the same transaction as the existing determination, action, outbox, case, and evaluation transition. It pins the Engine artifact, Control Pack, authority, input and result receipts, determination digest, evidence bindings, read observations, dependencies, and expected output types. Owner status validation reports CURRENT, REOPENED, or REVIEW_REQUIRED against one current decision package. Mirror derives the explanation, state report, and corporate-safe support payload from that package and exposes a bounded, repeatable drain page. Acknowledgment remains distinct from cash.

### Selected verification

Guarded v4 command: python -m unittest -v with PYTHONPATH set to this checkout and PYTHONDONTWRITEBYTECODE=1. It selected these 11 methods:

- tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v6_continuity_admission_migration_prevalidates_identity
- tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v6_continuity_admission_cache_is_independently_recomputed
- tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v6_continuity_admission_row_cap_rolls_back_all_deltas
- tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v7_continuity_admission_row_cap_rolls_back_all_deltas
- tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v6_continuity_admission_cost_tracks_changed_work
- tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_v6_continuity_package_cap_is_checked_before_commit
- tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_case_04_reject_and_authorize_correction
- tests.test_right_rail_financial_acceptance.RightRailFinancialAcceptanceTests.test_case_10_interrupted_import_restart_and_disabled_dispatch
- tests.test_right_rail_financial_mirror.FinancialMirrorTests.test_correction_followup_outputs_resume_and_reopen_through_mirror
- tests.test_right_rail_financial_mirror.FinancialMirrorTests.test_c05_decision_package_is_sanitized_bounded_and_ack_is_not_cash
- tests.test_right_rail_financial_mirror.FinancialMirrorTests.test_continuity_export_validate_restore_restart_and_readback

Final child output: Ran 11 tests in 78.721s / OK; selected methods skipped: 0. The guarded child exited 0; the guard observed minimum free physical memory 3,745,914,880 bytes, peak private bytes 136,974,336, CLEANUP=PASS, and MUTEX=RELEASED. CASE10 retained process exits 73 before COMMIT and 74 after COMMIT, with recovery and repeat-drain assertions. The detailed attempt history, all raw-log hashes, and bounded performance measurements are recorded in STATE.md.

Fresh preflight snapshot: ../pq-wide-seed-native-20260913/build-filter-native/state-continuity-admission-followup-20260924-r6.state-snapshot.log, SHA-256 50A90624938E7929BBEB80F04DFF2C0454F828C8EF834F688D9A465B868C5454. It records branch rightrail-financial-workflow-20260913, HEAD 8f75f527ae6717001978ac7401853c2aaae55f2b, index tree 05d6df5bf4c36a9e267f2b471a86764a242f227e, status count 29, target start floor 2,400,000,000 bytes, physical floor 2,190,433,321 bytes, observed start free memory 3,955,126,272 bytes, and the exact v4 wrapper SHA-256 57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB.

The corrected post-run verification is ../pq-wide-seed-native-20260913/build-filter-native/state-continuity-admission-followup-20260924-r6.postrun-verification.log, SHA-256 955B28EEB3D45C14D22B10F6197210A29C7B42B7F6905FE56AEAC28F59E41024; at that post-run checkpoint, before this documentation update, it records unchanged source/docs, repo identity, status hash, and protected executable hashes, no relevant process, and absent mutex. Its predecessor .postrun-snapshot.log is retained with POSTRUN=STOP because the audit script parsed packed preflight fields as one-key-per-line and read the child-only bytecode flag from its own shell; the corrected audit records that STOP rather than overwriting it.

The State-lane source/test paths and these four maintained Markdown files are the only paths changed for this follow-up. No file was staged or committed. The two build-performance/ executables remain byte-identical to their preflight hashes. No broad suite, compiler, or formal proof ran in this finite lane. Claims remain synthetic, nonpayment, non-PHI, dispatch-disabled, proofSuiteId=null, production_usable=false, and activation=false; the results do not establish full v7 acceptance, independent external exit, formal proof linkage, or production qualification. Driver handoff follows final repository verification.

## Private snapshot index set — guarded validation complete (2026-09-24)

The current State assignment prepares a private index set for v6/v7 semantic
snapshot queries. Edited paths are limited to `app/right_rail_financial_owner.py`,
`app/right_rail_financial_owner_independent.py`,
`tests/test_right_rail_financial_acceptance.py`,
`tests/test_right_rail_financial_independent.py`, `CURRENT_TASK.md`, and
`STATE.md`. The semantic adapter was not edited because its SQL spelling
already matches the queries.

The seven indexes, all ordinary/nonunique/nonpartial, are:

| Name | Ordered columns |
| --- | --- |
| `rr_financial_v1_evidence_item_id` | `evidence(item_id,evidence_id)` |
| `rr_financial_v1_claims_obligation_id` | `claimed_adjustments(obligation_id,claim_id)` |
| `rr_financial_v1_cases_obligation_id` | `cases(obligation_id,case_id)` |
| `rr_financial_v1_actions_obligation_id` | `actions(obligation_id,action_id)` |
| `rr_financial_v1_conflicts_obligation_id` | `financial_conflicts(obligation_id,conflict_id)` |
| `rr_financial_v1_evaluations_obligation_revision` | `evaluations(obligation_id,revision)` |
| `rr_financial_v1_determinations_obligation_id` | `determinations(obligation_id,determination_id)` |

The index-set marker is `PRAGMA user_version=1`. The payment lookup is covered
by the existing unique `(obligation_id,common_origin_id)` index prefix; the
determination lookup by `input_evaluation_id` is covered by its unique
constraint. The conflicts index is included because the snapshot reads
conflicts by obligation.

Migration and inventory validation are authored for the existing
`BEGIN IMMEDIATE` v6/v7 admission path. Identity, scope, mode, authority,
genesis, and anchor validation precede migration; the existing admission cache
and package bound are checked before indexes install and commit. v5 exits
before this path. Continuity bytes, digests, bounds, and semantics remain
unchanged. The independent event verifier remains a complete ordered history
scan; no history-independent verification claim is made.

Cleanup returned the sole guarded lane directly to State. A fresh preflight
passed at 2026-09-24 12:56:22 UTC: 3,528,105,984 bytes free, both memory floors
met, mutex absent, zero task-relevant processes, and all expected source,
adapter, protected-binary, and v4-wrapper hashes matched. One earlier snapshot
stopped because of an expected-hash typo and its broad process filter counted
23 Codex MCP `cmd.exe` processes; no guarded command ran under that STOP. The
STOP and corrected preflight are retained in `STATE.md`.

The guarded v4 command ran the six authored methods: v5 index absence; v6/v7
migration, identity prevalidation, Continuity byte preservation, reopen, and
restore; concurrent openers; Owner rejection without repair; bounded plans and
cost; and independent inventory rejection. Result: `Ran 6 tests in 3.129s` / `OK`,
0 failures, 0 errors, 0 skips. Migration integrity checks invoked the
independent verifier, whose full ordered event-history scan remains unchanged.
The plan fixture remains SQL-shaped and is not financial-semantic or
event-history-valid data.

The 400-row-per-table profile changed all seven indexed snapshot plans from
full scans to index searches, and the actions index also changed the outbox
subquery from a scan to a covering search. Existing payment and
input-evaluation indexes searched before and after; the payment query still
uses a temporary B-tree for ordering. The fixture added 131,072 storage bytes
(10.36% of its no-index database). Median insertion time was 13.5395 ms before
and 11.8994 ms after. Eight of ten read-query medians decreased; the
determination-by-obligation query increased from 0.1923 ms to 0.2645 ms, and
the existing-index input-evaluation control increased from 0.0601 ms to
0.0925 ms. These are three-sample local measurements without a latency SLA;
they do not establish production performance or capacity.

The guard self-tests returned 7 and 0; the selected child exited 0. Guarded
minimum free memory was 3,460,608,000 bytes, peak private bytes 30,777,344,
cleanup passed, and the mutex was released. The corrected post-run check found
no relevant process, an absent mutex, unchanged repository identity, and
matching protected binaries. Raw snapshots, complete unittest/plan/cost logs,
their hashes, and the earlier audit STOP are recorded in `STATE.md`.

Next action: return this completed finite lane to Driver for the next owner
handoff. No file was staged or committed. The broader independent audit,
formal/native integration, production performance, and activation gates remain
separate and unclaimed.

## Staff workspace verified snapshot — source-only continuation (2026-09-24)

This bounded continuation changes the staff read and command surface in the authorized Owner, Mirror, server, browser, and focused-test paths. Owner now supplies workspace and decision-package bundles from one active SQLite read snapshot, then runs the independent reconstruction on that same connection. The workspace response includes a bounded obligation page, H detail/package/timeline, exact SUPPORT counts, identity/evaluation bindings, verification digest, and separate read costs. Mirror closes each public resource with field allowlists and binds it to a SHA-256 resource/query/snapshot envelope. The decision-package API requests only the bounded package query; it does not construct the full workspace.

Staff commands carry per-obligation dependencies. ACK, cash evidence, and reporting pass the reviewed H revision into Owner methods; ACK checks it inside BEGIN IMMEDIATE after exact duplicate/conflict handling. Correction dependencies are passed to Owner's existing pinned Engine transition path; there is no Python correction fallback. StaffWorkflow now accepts an optional explicit correction_transition_release. Its default remains unset/fail-closed; focused success-path tests construct the existing acceptance helper's pinned release. The CLI does not implicitly select an Engine artifact.

The browser verifies SHA-256 envelope fields as 64 uppercase hex characters and Owner SHA3-512 fields as 128 characters. Manual source review found and corrected the earlier single-length regex that would reject valid SHA-256 envelope/verifier digests. The UI compares H revision/evaluation/Control Pack bindings and makes no external freshness or hostile-administrator claim.

No tests, compiler, JS runtime, build, checker, or guarded command ran for this continuation. The three focused test files (test_right_rail_financial_staff_server.py, test_right_rail_financial_mirror.py, and test_right_rail_financial_independent.py) were not executed; 0 test files ran. No syntax or runtime verification is claimed. The prior finite correction lane evidence does not cover this staff workspace delta. No files were staged or committed; preserve protected build-performance/ executables and unrelated dirty paths.

## Switch synthetic shadow replay — source-only, unverified (2026-09-24)

The next bounded slice adds a Switch replay-input v1 builder/decoder and typed
population-result comparison over one independently verified schema-v7
Continuity SHADOW package. The replay binds the exact snapshot digest, Owner
schema/revision/history head, scope/period, current published manifest and
member set, Control Pack rules/effective interval, source version/digest/
watermark, Owner authority, cohort/test identity, receiver/pending-work
boundary, independent reference identity, and candidate release/tool identity.
Reference and candidate evaluators receive the same
canonical immutable bytes; output identity, membership, amount types, aggregate
reconciliation, schema, and digest bindings are checked before comparison.

The focused synthetic test fixture constructs a separate SHADOW restore,
compares hand-derived expected population amounts with a candidate derived from
the same snapshot, and asserts the member/aggregate difference plus unchanged
incumbent and shadow Continuity bytes. Negative methods cover missing
approval/reference, tampered input, approval-binding mismatch, unknown result
fields, and forbidden differences. Approval and reference records in tests are
local fixture assertions, not external approvals or an independently
qualified reference answer. The result contract covers population owed amounts
and aggregate totals only; it does not implement a complete alternative
obligation-evaluation engine.

The Switch module accepts bytes and caller-supplied evaluators only; it has no
Owner, Mirror, database, dispatch, transfer, cutover, or rollback API. It does
not verify source provenance, enforce OS/network isolation, or authenticate
cohort/reference approval claims. The `SYNTHETIC` classification is caller
asserted. Only canonical replay bytes are passed as evaluator input. A caller
could still supply a callable whose closure captures an Owner or database.
The report marks closure isolation and evaluator timeout as unverified and
peak memory as unavailable. Difference-policy approval is also caller-asserted.
The report keeps candidate authority at NONE and never grants transfer. No
evidence presently supplies external cohort/reference approvals, candidate
runtime isolation, or a resource ceiling.

Changed paths: `app/right_rail_financial_switch.py`,
`tests/test_right_rail_financial_switch.py`, `CURRENT_TASK.md`, and `STATE.md`.
Five focused Switch tests were authored and zero executed. No build, checker,
compiler, JavaScript runtime, or guarded command ran. A new direct finite-lane
handoff and fresh target preflight are required before execution. The staff
snapshot delta above remains source-only and unverified; its note was preserved.
Manual source review corrected the closed result-field allowlist to accept the
already-required authority binding; runtime behavior remains unverified.

## Switch CLI path — source-only, unverified (2026-09-24)

The existing `tools/right_rail_financial_cli.py` now has `switch-prepare` and
`switch-compare`. Both run without `--database` or a synthetic State/program
identity. Prepare calls the existing static Owner/Continuity package verifier,
requires v7 SHADOW with dispatch/egress disabled, then writes the exact
canonical replay-input bytes with create-new semantics; it runs no evaluator.
Compare re-verifies those package bytes and accepts typed reference/candidate
result documents. Their producer identities and results must bind the same
canonical input SHA-256. Missing approval/reference/result facts or invalid
sidecars return INCOMPLETE/UNKNOWN. Candidate approval identity cannot equal
the claimed cohort approver. The comparison path creates no Owner, does not
restore or mutate a database, and does not call dispatch.

The CLI uses precomputed outputs; it does not execute candidate code. It sets
external evaluator timings to unavailable and labels the report as result-file
comparison only. Source-class, cohort approval, reference independence, and
difference-policy approval remain caller assertions; the API cannot authenticate
them or enforce the external evaluator's sandbox. Comparison remains limited to
member owed amounts and aggregate totals.

Added `tests/test_right_rail_financial_cli_switch.py` with five authored
methods: two-step input preparation/result comparison with two changed members
and aggregate, missing approval/reference, missing permission provenance,
candidate self-approval, and cross-input result rejection (five total methods).
Together with the five focused module methods, ten methods are authored and
zero executed. Source review only; no Python command, test, build, compiler,
checker, or guarded process ran. Execution remains held for a direct finite v4
lane handoff and fresh target preflight. Earlier staff source changes and their
snapshot note above were left intact; nothing was staged or committed.

## Offline synthetic service kit — source-only; assembly held (2026-09-24)

Added `tools/right_rail_financial_service_kit.py` with `assemble`, `verify`,
`extract`, `run`, and `serve` commands. The archive design is deterministic
ZIP_STORED with fixed entry times, a create-only output, a strict manifest
that pins every packaged file by size and SHA-256, exact archive membership,
an independently supplied expected archive digest, and safe extraction into a
new directory. The defined package contains the State staff/Owner/Mirror/Switch
code and its source/test support; CPython 3.11.15 with its full runtime tree and
an empty third-party package lock; every Engine `.lean` source plus
`lean-toolchain`, `lakefile.toml`, and `lake-manifest.json`; the pinned
correction executable and request/result vectors; and the Engine build receipt
with its complete raw guarded stdout/stderr logs. The verifier checks the
State-side Engine/vector pins, the exact Lean source-manifest digest, toolchain
and dependency lock hashes, and the receipt/log bindings. The manifest pins
`proofSuiteId=null`, `production_usable=false`, `activation=false`, Owner mode
TEST, restore mode SHADOW, and dispatch/egress/payment movement disabled.
Queue remains
explicitly `MISSING/BLOCKED queue.lifecycle_source_bound_runtime` and will be
omitted.

The kit defines an Engine receipt schema in
`docs/FINANCIAL_SERVICE_KIT.md`; it does not synthesize a receipt or equate a
source hash with formal refinement evidence. The current executable is
6,245,376 bytes, SHA-256
`E911E8844130155E4615D284D6D29A597B6E441DC45101D411EE8422EAE684B9`. The
current Engine `CorrectionTransition/Transition.lean` hash is
`E982BA7871E45138BD6AAF72434E4F43D17105D42F60413FEB3B57816AD3F01D`; the
prior recorded compile source hash is
`342F3B1DF777095D75FD12970F29DFBC09AC06DCF48147EFF804EBA78E9021AE`. No
verified receipt binds the current source manifest to this executable, so
archive assembly is blocked. The standalone `verify` command also requires an
archive SHA-256 delivered independently.

Added the post-extraction runner at `tools/service_kit/run_scenario.py` and
the loopback startup runner at `tools/service_kit/run_server.py`. The focused
service scenario starts a TEST Owner and Mirror, forces a full HTTP response
drop after the correction command returns, independently verifies the one
determination/action/event commit, retries the exact command as
`DUPLICATE` without a second write, compares same-owner staff and Mirror
readback, then restores Continuity into SHADOW and checks write/dispatch and
destination-replacement rejection. The test's prior client-side unread-body
simulation was strengthened to close the server socket before sending any
response. This remains authored evidence only.

Verification status: 0 Python commands, tests, builds, compilers, checkers,
archive operations, or kit commands ran. The one new service scenario method
was not executed because this packet has no direct v4 lane handoff and fresh
target-specific preflight. The State kit packet's `-MinimumStartFreeBytes`
has not been set; do not reuse a threshold from another target packet. The
assembler separately requires the exact Engine build guard threshold from
the authorized Engine handoff and binds it to the receipt and archive
manifest. Neither threshold has been inferred from the other. Source-only review also
tightened archive path/type checks, preserves extraction exception details,
rejects colliding or in-kit service workspaces, and runs post-extraction
Python with bytecode writing disabled before rechecking the package; none of
these changes has been executed. The kit does not enforce host-level outbound
network blocking, so a technical offline boundary must be supplied externally.
The 10 Switch methods remain unexecuted as recorded above. No
archive was produced and no service was started. The Engine receipt schema is
not signed, so the authorized handoff remains the producer-authenticity
boundary. The known `Get-CimInstance Win32_OperatingSystem` guard probe
failure is `Access denied`
before physical preflight/child launch, outer exit 1, with no cleanup
evidence; do not retry or treat it as a safe handoff. The exact current-source
Engine build receipt and direct v4 lane release are still required before
assembling or running the kit.

Changed paths for this source-only kit slice: `README.md`,
`docs/FINANCIAL_SERVICE_KIT.md`, `tools/right_rail_financial_service_kit.py`,
`tools/service_kit/run_scenario.py`, `tools/service_kit/run_server.py`, and
`tests/test_right_rail_financial_staff_server.py`. Existing dirty and
untracked work, including `build-performance/`, remains preserved. Nothing
was staged or committed. Claims remain `proofSuiteId=null`,
`production_usable=false`, `activation=false`, synthetic, nonpayment,
non-PHI, and dispatch-disabled.
