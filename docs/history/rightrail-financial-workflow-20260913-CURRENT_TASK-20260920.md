# RightRail current task

Updated: 2026-09-20

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
