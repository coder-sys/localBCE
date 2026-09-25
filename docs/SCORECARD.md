# Felt-value scorecard: Hospital H

CONSTITUTION Art. XII says the demo is the scorecard. `tools/right_rail_scorecard.py`
runs the Hospital H journey through the real staff server and the real `staff.js`,
one fresh page per role. The data is in `scorecard/hospital_h.json`.
`tests/test_right_rail_scorecard.py` fails if any unit gets worse. After an
improvement, rewrite the file with `--write`. All counts are deterministic.
Synthetic, non-PHI, nonpayment, proofSuiteId=null, production_usable=false,
activation=false.

## The units: who feels them, and when

| Unit | Who feels it | When |
|---|---|---|
| Clicks and screens until the answer is visible | every role | each time they open the workspace |
| Needed facts shown only in raw JSON, or nowhere | analyst, approver, auditor, director | answering "what is happening, who owns it" |
| Forced package reopens | state analyst | after each step of the correction |
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
| | facts only in raw JSON | unknown | 1 | **0** |
| | rows shown as open | 20 (assumption) | 20 | 20 |
| Analyst, correction | clicks | unknown | 6 | **4** |
| | forced reopens | unknown | 2 | **0** |
| | requests | unknown | 14 | 15 (see note) |
| Approver, decision | screens | 5 (assumption) | 3 | **2** |
| | clicks to see every input | unknown | 2 | **1** |
| | inputs only in raw JSON | unknown | 2 | **0** |
| | requests through the decision | unknown | 8 | 9 (see note) |
| Director, weekly | totals nowhere on screen (of 5) | unknown | 3 | **0** |
| | clicks | unknown | 3 | **0** |
| | rows to add by hand | 20 (assumption) | 20 | **0** |
| Auditor | clicks | unknown | 2 | **1** |
| | audit facts only in raw JSON | unknown | 2 | **0** |
| Replacement operator | clicks through restore and reorientation | unknown | 3 | **2** |
| | facts only in raw JSON | unknown | 1 | **0** |
| Case H | hours unresolved / past due | unknown | 48 / 24 | 48 / 24 |
| Accuracy | correction error, reconciliation error, double count (cents) | unknown | 0 / 0 / 0 | 0 / 0 / 0 |

Note: the page now reloads the package automatically after the operator's own
command. That costs one request per command, which is traded for a click. The
hours come from the fixture's synthetic clock, which screen changes cannot move.
Paying late does not erase the missed deadline: H stays 24 hours past due on
record.

## Top friction found (worst five)

1. **Director, weekly review.** Cash recorded, program shortfall and open items
   were nowhere on screen; the other 20 rows had to be added by hand. It cost 3
   clicks and still left 3 of 5 totals unanswered. *Fixed:* the three totals
   are now cards on the overview.
2. **Analyst and director, Monday.** 20 of 20 rows read "Case OPEN", and 19 stay
   open at the end, but only H has a real problem. The fixture never records the
   other hospitals' $900,000, although plan §4 says they received it. *Open:*
   this is a fixture decision for the owner.
3. **Analyst, correction.** Every button went dead after each command until the
   package was reopened by hand. That meant 2 forced reopens and no reason
   shown. *Fixed:* the package reloads after the operator's own successful
   command.
4. **Approver, auditor and analyst.** Needed facts could only be found in raw
   JSON: the owner, claim status, deadline, deciding role and evidence. It cost
   2 to 3 screens. *Fixed:* the decision panel now leads with plain facts, and
   the overview answers first.
5. **Replacement operator.** Restore to Continuity TEST is enabled only after
   H's shortfall is 0, so a replacement cannot take over unfinished work, which
   plan §14 expects. *Open:* needs an owner decision.

## Article XIII violations found

Status after this change. The Mirror redesign owns the full interaction model.

- **XIII.1, answer first.** Status, owner, gap and next step needed 2 clicks and
  raw JSON. *Fixed:* "Needs attention now" on the overview.
- **Dead connection.** A failed or stale package read wrote its message inside
  the hidden panel, so the click showed nothing. *Fixed:* the message now
  appears in the command status.
- **Dead control.** Refresh did nothing, silently, while a command was pending.
  *Fixed:* Refresh is disabled while a command runs.
- **Illogical path.** The approver's reject-offset is enabled in every session
  (observed for analyst, director and auditor). The page has no roles by
  design. *Open.*
- **Illogical path.** The "exercise wrong-role" and "exercise stale-revision"
  buttons can only ever produce a rejection, and every role sees them. *Open.*
- **Illogical path.** Record-report is enabled on Monday, before any decision
  or cash (observed). *Open.*
- **Illogical path.** Restore-test is enabled for any role once H is paid,
  including the auditor (observed). It stays disabled while a case is open; see
  friction 5. *Open.*
- **Orphan screen.** "Owner gate results" is fed only by the exercise buttons,
  which are disabled after the decision, so it reads "No gate attempts
  recorded" for good. *Open.*
- **Trap-like.** The 19 other rows show "Case OPEN", but only H can be opened or
  acted on. *Open.*
- **Trap.** After a detected Owner fork the page stays UNAVAILABLE and gives no
  reload instruction. Found by code reading, not exercised. *Open.*
- **Friction.** Disabled buttons give no reason. *Open*, though the automatic
  reload removed the common case.
- **XIII.2, no jargon or internal IDs.** Decision facts now lead in plain words.
  Digests, receipts and snapshot ids moved into a collapsed "Technical
  bindings" section. *Still open:* the header read line (snapshot id, statement
  counts), raw codes in roster rows and chronology, and raw error codes in the
  fallback error message.
