# Pending RARC/CARC domain decision

Owner: the human policy decision for `rarc_mapping.tsv`. Status: proposed and pending co-founder
and Medi-Cal/DHCS ratification. This document records unresolved domain choices; it does not make
the mapping final, select a ruleset, or authorize payment behavior.

## Sources

- [X12 Claim Adjustment Reason Codes](https://x12.org/codes/claim-adjustment-reason-codes)
- [X12 Remittance Advice Remark Codes](https://x12.org/codes/remittance-advice-remark-codes)

The TSV is the executable mapping owner. Rows currently marked `PENDING_DOMAIN_RATIFICATION` are
`G2B_PATIENT_NOT_DECEASED`, `G4B_PROVIDER_NOT_SUSPENDED`, and `G8A_CHARGE_VALID`.

## Decisions still required

- Confirm each generic X12 CARC/RARC pair against Medi-Cal/DHCS remittance behavior.
- Decide whether every denial emits a RARC or whether CARC-only output is more exact.
- Decide claim-level versus service-line placement for each gate.
- Confirm eligibility and provider-enrollment variants against the applicable Medicaid crosswalk.

## G8 split

The current `G8A_CHARGE_VALID` row is a proposed split from a former combined charge gate. Invalid
or malformed charge data (`16/M79`) and excessive charge (`45`, with no default RARC) are different
decisions. A later policy-approved change should split them rather than treat one pair as both.

## Sign-off record

Reviewer: ____________________ Date: ____________________ Decision: approve / changes / G8 split / crosswalk review
Notes: __________________________________________________________________________________
