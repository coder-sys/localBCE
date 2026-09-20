# RightRail financial workflow

This checkout contains a synthetic, state-local financial responsibility with
five explicit parts: State Control Pack, Blind Ledger owner, same-owner Mirror,
bounded Continuity State, and a deferred Switch. The official state/payment
processor remains the authority for funds movement. RightRail records
obligations, typed evidence, evaluations, determinations, authorized actions,
delivery, and descriptive cash/reporting facts; it does not move money or
authorize a live payment.

The owner is the sole writer. Mirror commands and queries that owner.
Continuity exports/restores a bounded versioned view into SHADOW or isolated
TEST/non-live state, with dispatch and egress disabled and no second live
writer. Evidence, official determination, action authorization,
acknowledgment, and cash/reporting completion are separate facts.

## Current working boundary

The branch is `rightrail-financial-workflow-20260913`. The corrected v5
owner/checker/Mirror/CLI/Continuity implementation, affected tests, and
maintained docs are the current State-owned delivery; Git HEAD, tree, and
status are authoritative after integration. Preserve the two untracked
driver-supplied executables under `build-performance/`.

The working contracts are `RR/FINANCIAL/OWNER/v5` and
`RR/FINANCIAL/CONTINUITY/v5`. v2/v3/v4 stores and packages remain preserved
historical inputs and reject fail-closed without mutation. The current Python
owner is the transaction authority. Engine is implementing and correcting
executable Lean modules and the concrete adapter contract, but no executable
Lean linkage or runtime authority switch exists.

## Fixed synthetic responsibility

The fixture is twenty hospitals and $1,000,000 total: H is owed $100,000 and
the other nineteen total $900,000. Expected values are hand-derived. The
reviewer-fixed cents are H `10,000,000`, eighteen other items `4,700,000`
each, and one other item `5,400,000`.

The required v5 evaluation contract includes versioned plaintext evaluations
and `current_evaluation_receipt(item_id)`. Receipt contract
`RR/FINANCIAL/EVALUATION-RECEIPT/v1` binds scope, evaluation/obligation/
revision, Control Pack identity, sorted evidence id/record-digest bindings,
trusted authority, timestamp, result fields, result digest, and receipt digest;
it carries references/digests only. The required determination contract binds
explicit evaluation identity/digest and expected revision to current and
historical state before one atomic determination/action/outbox transition.
Exact retries must be `DUPLICATE`; changed identity or input must be conflict.
`STATE.md` records the narrow Driver disposition for this owner-local synthetic
v5 scope. Whole-system and production qualification remain open; detailed
evidence and nonclaims are in `STATE.md`.

## Entry points

| Boundary | Source |
| --- | --- |
| Owner and schema | `app/right_rail_financial_owner.py` |
| Independent reconstruction | `app/right_rail_financial_owner_independent.py` |
| Same-owner queries, commands, Continuity | `app/right_rail_financial_mirror.py` |
| Local caller surface | `tools/right_rail_financial_cli.py` |
| Expected fixture branches | `tests/rightrail_financial_expected_cases.py` |
| Focused acceptance/checker/Mirror tests | `tests/test_right_rail_financial_*.py` |

Read the current objective and blockers in [`CURRENT_TASK.md`](CURRENT_TASK.md),
then verified evidence in [`STATE.md`](STATE.md). The system boundary is in
[`ARCHITECTURE.md`](ARCHITECTURE.md); dependency order is in
[`docs/IMPLEMENTATION_ROADMAP.md`](docs/IMPLEMENTATION_ROADMAP.md); the design
contract is [`docs/DESIGN_IDEOLOGY.md`](docs/DESIGN_IDEOLOGY.md).

## Verified evidence

The prior broad guarded affected run compiled the relevant Python paths and ran
the acceptance, independent-checker, and Mirror suites:

```text
Ran 63 tests in 26.573s
OK
```

It reported no warnings or skips. The guard also verified process-boundary
return codes `73` and `74`, child exit `0`, minimum free bytes
`3797897216`, peak private bytes `29360128`, `CLEANUP=PASS`, and
`MUTEX=RELEASED`. The owner SHA-256 is
`68D1AF3DE2B5072FDD7A6D05DD297E2B5A95687E1453E80CCBFB49A2ADF694D9`; the
independent checker is
`FE1CCDCA057FE36391FF9A9BCD9B4CD73ADAC9A934D3DB88D040E5F6BB1D5A55`.

The residual correction packet then ran under the unchanged guard from the
absolute project cwd. Its raw logs are:

- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-residual-focused-r2.stdout.log`
- `../pq-wide-seed-native-20260913/build-filter-native/guarded-command-financial-v5-residual-focused-r2.stderr.log`

It reported:

```text
Ran 5 tests in 4.254s
OK
```

The guard reported `exit7=7 exit0=0`, child exit `0`, minimum free bytes
`3106156544`, peak private bytes `30777344`, `CLEANUP=PASS`, and
`MUTEX=RELEASED`. Current owner and acceptance-test SHA-256 values are
`45D2F3F0468642BE471CF365A7C6AF63B98836430AEEA796FD6A461CECE19846` and
`B9312E8DE63D80861C88924E800CFE0771BB1EA7D0EE72DF2BC56E802CF6017B`.

The retained bounded measurement is `work/financial-measurements-v5-final-r4`:
one warmup plus three measured samples at sizes 5, 10, and 20, with 12 owner
and 12 TEST databases. It reports `type=complete`, `status=PASS`, all
reference checks true, all source bytes unchanged, and zero acquisition
failures. Total medians are `504.762`, `793.516`, and `1261.848` ms for
sizes 5, 10, and 20. This is a bounded observation, not an SLA. It is
source-bound to the pre-residual owner hash
`68D1AF3DE2B5072FDD7A6D05DD297E2B5A95687E1453E80CCBFB49A2ADF694D9`, not the
current owner, and was not rerun. Earlier failed attempts and their corrections
remain raw evidence; they are not relabeled as passes. The r4 invocation
deviation is retained in `STATE.md`; no corrected-source rerun is claimed.

## Limitations and claims

- The candidate is synthetic, local, nonactivating, nonpayment, and non-PHI:
  `proofSuiteId=null`, `production_usable=false`, and `activation=false`.
- `STATE.md` records narrow Driver acceptance for this owner-local synthetic
  v5 slice. Native metrics, native verification-to-commit, Lean executable replay/linkage,
  Queue/Composition integration, whole-system
  qualification, independent audit, real data/PHI, live dispatch, payment
  movement, and production qualification remain open.
- The v2/v3/v4 coverage is a tag-only fail-closed rejection matrix over
  disposable current bytes; it is not historical-schema compatibility evidence.
- There is no separate verification-attempt, lease, receipt-consumption, or
  Queue-reservation boundary in the financial owner. Claimed-adjustment state
  and Queue reservations remain separate.
- The fixed Queue schema 13/Profile 12, Composition schema 4, exact 100-
  reference protocol, source ownership/reservation, atomicity, non-`CLEAR`
  guard, and native/C/crypto/Lean boundaries are separate protected seams.

## Product commitments

State owns rules, data, keys, histories, interfaces, tests, and continuity
export. RightRail remains replaceable without proprietary lock-in; vendor
compatibility is free/conformant rather than a share of denials, recoveries,
penalties, or savings. Provider App economics remain separate. Corporate
support receives zero PHI and no persistent linkable claim fingerprint.
