# RightRail current state

Updated: 2026-09-20

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

## Review disposition — ACCEPTED bounded Python v5 slice

The frozen review corrections are implemented and re-verified. The final
guarded affected run compiled the relevant Python paths and ran all three
affected suites:

PROCESS_BOUNDARY precommit returncode=73 stdout='PHASE=BEFORE_REJECT\nPHASE=PRECOMMIT_AFTER_MUTATION\n' stderr=''
PROCESS_BOUNDARY postcommit returncode=74 stdout='PHASE=BEFORE_REJECT\nPHASE=POSTCOMMIT_AFTER_COMMIT\n' stderr=''
Ran 63 tests in 26.573s
OK

Guard decisive output: child exit 0; minimum free bytes 3797897216; reserve
3221225472; effective floor 2576980378; peak private bytes 29360128;
CLEANUP=PASS; MUTEX=RELEASED. Raw files:

- work/pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-correction2-focused-r8.stdout.log
- work/pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-correction2-focused-r8.stderr.log

Source identities for the final slice are:

- owner: 68D1AF3DE2B5072FDD7A6D05DD297E2B5A95687E1453E80CCBFB49A2ADF694D9
- independent checker: FE1CCDCA057FE36391FF9A9BCD9B4CD73ADAC9A934D3DB88D040E5F6BB1D5A55
- acceptance test: FD456CF52EB783513AC3143690659A9888F0E9810E2B3996E7C7F939874A935B
- Mirror test: 3099F0846BABF9953A9A34E65E760EBE223FD5D38DAC3B1CEE0C35C355258C75
- measurement harness: A50C73BD4231385900B378327492FF1DFC5F2A16CE8125752D3C76DB7EE13437

The acceptance additions independently reconstruct the complete populated
evaluation receipt: scope, obligation/evaluation/revision, Control Pack,
sorted unique evidence record-digest bindings, authority/time, every result
field, result digest, and receipt digest. The exact receipt is checked across
owner query/evaluate, restart, Mirror, CLI, and SHADOW restore without using
the owner digest or evaluator to construct the expected value.

Determination coverage includes malformed and bad digest references,
decision-before-evaluation, stale references after a real evidence/revision
change, unchanged rejected requests, and the same consumed reference under a
different action. The final consumed-reference negative case reaches the
revision conflict before any mutation; a separate lower-level consumption
branch is not fabricated because current revision invariants make it
unreachable. Real CLI coverage proves authorize-offset success, exact retry as
DUPLICATE, and changed-binding conflict. Existing tamper-copy tests retain
invalid authority/pack/evidence/projection coverage.

Continuity restore now constructs and verifies in a private attempt directory,
publishes with an atomic no-replace link, checks destination sidecars, and
cleans only demonstrably owned attempt/published identities. Destination races,
foreign -wal/-shm sidecars, genuine owned-failure cleanup, and normal
SHADOW/TEST restore are covered. Cleanup failures are surfaced as
continuity_restore_cleanup; they are not silently ignored.

The v2/v3/v4 matrix copies disposable current bytes, changes only schema/version
tags, and verifies fail-closed store/package rejection, unchanged source bytes,
and no destination. No authentic old-schema compatibility claim is made; these
are tag-only rejection checks.

## Final bounded measurement

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
Wrapper stdout SHA-256:
2F5C1062F00C7A3FA5A3BA1F802EAEB62C1C90441851BEA18F0BA02F7CB81B0A.
Wrapper stderr was empty, SHA-256
E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.
The measurement is a bounded local observation, not an SLA; native metrics
remain pending and Queue wait/age are not applicable to this owner slice.

## Retained failures, warnings, and skips

The final r8 run had no warnings or skips. Earlier correction attempts remain
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

This accepted bounded slice does not close native verification-to-commit,
native metrics, executable Lean linkage/refinement, Queue/Composition
integration, independent audit, authenticated sources, custody, real PHI,
live dispatch, payment movement, or production qualification. The active Lean
direction does not switch runtime authority away from the Python owner.

Current claims remain:

proofSuiteId=null, production_usable=false, activation=false,
NOT_QUALIFIED/INACTIVE/UNSELECTED, synthetic, nonpayment, and non-PHI.

Preserve the fixed twenty-hospital/$1,000,000 fixture and hand-derived cents,
Queue schema 13/Profile 12, Composition schema 4, exact 100-reference
protocol, source ownership/reservation, Queue/State/outbox atomicity,
non-CLEAR guard, and all native/C/crypto/Lean boundaries.
