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

The bounded Python v5 slice is implemented and locally re-verified for the
current correction packet. Driver disposition remains NOT ACCEPTED pending
review of the source and raw evidence. This is not whole-system qualification:
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

The outer final measurement guard had child exit 0, 18 samples, minimum free
bytes 3767709696, peak private bytes 24268800, CLEANUP=PASS, and
MUTEX=RELEASED. The wrapper stdout SHA-256 is
2F5C1062F00C7A3FA5A3BA1F802EAEB62C1C90441851BEA18F0BA02F7CB81B0A; stderr
was empty with SHA-256
E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.
This is a bounded local observation, not an SLA or production qualification;
native metrics are pending and Queue wait/age are not applicable to this
owner slice. It is source-bound to the pre-residual owner hash
`68D1AF3DE2B5072FDD7A6D05DD297E2B5A95687E1453E80CCBFB49A2ADF694D9`, not the
current owner, and was not rerun for this focused correction packet.

## Retained failures and next gates

Earlier raw failures remain evidence: the first residual focused launch was
rejected before child execution; its stderr was exactly:

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

Driver disposition remains NOT ACCEPTED pending review. Next work is
Driver-wide review and the separate native, formal, operational,
and production gates. The active Lean direction may design/extract semantics,
but no runtime authority switch is allowed until a pinned executable Lean
artifact and refinement/linkage evidence exist.

## Protected boundary and claims

Preserve the fixed twenty-hospital/$1,000,000 fixture, hand-derived cents,
Queue schema 13/Profile 12, Composition schema 4, exact 100-reference
protocol, source ownership/reservation, Queue/State/outbox atomicity,
non-CLEAR guard, and native/C/crypto/Lean boundaries.

Claims remain proofSuiteId=null, production_usable=false, activation=false,
NOT_QUALIFIED/INACTIVE/UNSELECTED, synthetic, nonpayment, and non-PHI. The
Python owner is not a deployed formal authority, official processor, payment
system, or independent audit.
