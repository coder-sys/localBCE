# Felt-value scorecard: Hospital H

CONSTITUTION Art. XII says the demo is the scorecard. `tests/instruments/right_rail_scorecard.py`
runs the Hospital H journey through the real staff server and workspace page, one
fresh page per role, into `scorecard/hospital_h.json`. `tests/test_right_rail_scorecard.py`
fails if any unit gets worse; after an improvement, rewrite the file with
`--write`. Synthetic, non-PHI, nonpayment, proofSuiteId=null,
production_usable=false, activation=false.

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

## Measured values

`scorecard/hospital_h.json` holds the current value of every unit and is the
ratchet. "Manual" baselines in it are assumptions from plan §4, never
measurements. The hours come from the fixture's synthetic clock; paying late
does not erase the missed deadline.

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
