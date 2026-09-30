# Felt-value scorecard: Hospital H

CONSTITUTION Art. XII says the demo is the scorecard. `tools/right_rail_scorecard.py`
runs the Hospital H journey through the real staff server and the real workspace page,
one fresh page per role. The data is in `scorecard/hospital_h.json`.
`tests/test_right_rail_scorecard.py` fails if any unit gets worse. After an
improvement, rewrite the file with `--write`. All counts are deterministic.
Synthetic, non-PHI, nonpayment, proofSuiteId=null, production_usable=false,
activation=false.

## The units: who feels them, and when

| Unit | Who feels it | When |
|---|---|---|
| Clicks and screens until the answer is visible | every role | each time they open the workspace |
| Needed facts missing from the page | analyst, approver, auditor, director | answering "what is happening, who owns it" |
| Rows shown as open | analyst, director | Monday scan, weekly review |
| Rows to add up by hand | director | weekly program total |
| HTTP requests | nobody directly: machine cost | every page load and command |
| Hours H is unresolved or past due (synthetic clock) | analyst, director, auditor | while the $3,000 gap is open |
| Correction and reconciliation error, in cents | approver, auditor | after the correction |
| Repeat payment message counted twice | analyst, auditor | when a message arrives again |

## Before and after

"Manual" values are assumptions from plan §4, never measurements. "Unknown"
means the plan gives no figure. "Demo before" and "after" were both measured by
this harness: "before" at 1c7ed3b (product code unchanged since e9b3727), and
"after" with this change.

| Role, moment | Unit | Manual | Demo before | After |
|---|---|---|---|---|
| Analyst, Monday | screens to answer status, owner, gap, next step | 4 (assumption) | 3 | **1** |
| | clicks | unknown | 2 | **0** |
| | rows shown as open | 20 (assumption) | 20 | 1 |
| Analyst, correction | clicks | unknown | 6 | **3** |
| | requests | unknown | 14 | **12** |
| Approver, decision | screens | 5 (assumption) | 3 | **1** |
| | clicks to see every input | unknown | 2 | **0** |
| | requests through the decision | unknown | 8 | 8 |
| Director, weekly | totals nowhere on screen (of 5) | unknown | 3 | **0** |
| | clicks | unknown | 3 | **0** |
| | rows to add by hand | 20 (assumption) | 20 | **0** |
| Auditor | clicks | unknown | 2 | **0** |
| Replacement operator | clicks through restore and reorientation | unknown | 3 | **1** |
| Case H | hours unresolved / past due | unknown | 48 / 24 | 48 / 24 |
| Accuracy | correction error, reconciliation error, double count (cents) | unknown | 0 / 0 / 0 | 0 / 0 / 0 |

Note: the page loads the case with the queue, so the package needs no
separate request or click. The hours come from the fixture's synthetic clock,
which screen changes cannot move. Paying late does not erase the missed
deadline: H stays 24 hours past due on record.

## Not shown, because the read model does not carry it

Payer, file and day, claim number, a browser re-check of a source, earlier
decisions and the stored reason, signer name, hold categories and a cure date.
"Decided by" shows only the role.

## Top friction still open (the other three of the first five were fixed)

1. **Analyst and director, Monday.** 20 of 20 rows read "Case OPEN", 19 stay
 open at the end, but only H has a real problem: the fixture never records
 the other hospitals' $900,000, though plan §4 says they received it.
 *Open:* fixture decision for the owner.
2. **Replacement operator.** Restore to Continuity TEST is enabled only
 after H's shortfall is 0, so a replacement cannot take over unfinished
 work, which plan §14 expects. Needs an owner decision.

## Article XIII items still open

- **Trap-like.** Only H opens; the 19 paid rows have no record to act on.
- **Friction.** A disabled step says why in words, but the reason for a
  decision is not stored yet (the page says so).
