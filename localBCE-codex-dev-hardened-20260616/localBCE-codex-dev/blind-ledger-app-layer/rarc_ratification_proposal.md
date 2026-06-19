# RARC/CARC Ratification Proposal

Status: PROPOSED - pending co-founder and Medi-Cal policy ratification.

This document is a proposal for billing-domain review. It is not a final compliance determination. Codex checked the current `rarc_mapping.tsv` against the public X12 CARC and RARC code lists and proposes the mappings below for human sign-off.

Sources:

- X12 Claim Adjustment Reason Codes: https://x12.org/codes/claim-adjustment-reason-codes
- X12 Remittance Advice Remark Codes: https://x12.org/codes/remittance-advice-remark-codes

Human ratification required:

- Confirm that each generic X12 CARC/RARC pair is acceptable for Medi-Cal/DHCS remittance behavior.
- Confirm whether the app should emit a RARC for every denial, or omit RARC where the CARC alone is the more exact standard signal.
- Confirm whether claim-level vs service-line-level placement changes the appropriate code pair.

## Current Per-Gate Proposal

Every row below is PROPOSED - pending co-founder/Medi-Cal policy ratification.

| Gate | Denial reason | Current CARC/RARC | X12 meaning, paraphrased | Codex reasoning | Recommendation | Medi-Cal flag |
|---|---|---:|---|---|---|---|
| G1_MEMBER_ID_PRESENT | `member_id_missing` | `16` / `N382` | CARC 16: claim/service has missing or erroneous information. RARC N382: patient identifier is missing, incomplete, or invalid. | The gate fails when the member/patient identifier is absent. RARC N382 is the most direct patient-identifier remark found. | PROPOSED_SOLID | NEEDS_MEDI_CAL_POLICY_CHECK |
| G2_ELIGIBILITY_ACTIVE | `eligibility_inactive` | `27` / `N30` | CARC 27: expense after coverage ended. RARC N30: patient is ineligible for the service. | The RARC fits inactive eligibility. CARC 27 fits when inactive means coverage terminated, but other eligibility failure types may need a different CARC. | NEEDS_DECISION | NEEDS_MEDI_CAL_POLICY_CHECK |
| G3_PROVIDER_NPI_PRESENT | `provider_npi_missing` | `206` / `N290` | CARC 206: National Provider Identifier is missing. RARC N290: rendering provider primary identifier is missing, incomplete, or invalid. | The gate fails on missing provider NPI; CARC 206 and RARC N290 are more exact than generic CARC 16. | PROPOSED_SOLID | NEEDS_MEDI_CAL_POLICY_CHECK |
| G4_PROVIDER_ENROLLED | `provider_not_enrolled` | `299` / `N767` | CARC 299: billing provider is not eligible for payment. RARC N767: Medicaid requires provider enrollment before claim benefits are processed. | The gate is specifically provider enrollment in a Medicaid context. N767 is Medicaid-specific and materially better than generic provider-not-eligible codes. | PROPOSED_SOLID | NEEDS_MEDI_CAL_POLICY_CHECK |
| G5_SERVICE_LINES_PRESENT | `service_line_missing` | `16` / `M51` | CARC 16: missing/error claim information. RARC M51: procedure code is missing, incomplete, or invalid. | A missing service line means the adjudicator has no billable procedure/service data. M51 fits if the remittance treats this as missing procedure data. | PROPOSED_SOLID | NEEDS_MEDI_CAL_POLICY_CHECK |
| G6_DIAGNOSIS_PRESENT | `diagnosis_missing` | `16` / `M76` | CARC 16: missing/error claim information. RARC M76: diagnosis or condition is missing, incomplete, or invalid. | Direct match for missing diagnosis information. | PROPOSED_SOLID | NEEDS_MEDI_CAL_POLICY_CHECK |
| G7_PRIOR_AUTH_WHEN_REQUIRED | `prior_authorization_required` | `197` / `M62` | CARC 197: precertification, authorization, notification, or pre-treatment is absent. RARC M62: treatment authorization code is missing, incomplete, or invalid. | The gate fails because required authorization is absent; M62 is better than N54 when the issue is missing authorization rather than mismatch against existing authorization. | PROPOSED_SOLID | NEEDS_MEDI_CAL_POLICY_CHECK |
| G8_CHARGE_WITHIN_LIMITS | `invalid_or_excessive_charge` | `45` / `M79` | CARC 45: charge exceeds fee schedule/allowable/contracted amount. RARC M79: charge is missing, incomplete, or invalid. | Current gate combines two denial concepts: malformed/invalid charge and excessive charge. One pair cannot cleanly express both. | NEEDS_DECISION | NEEDS_MEDI_CAL_POLICY_CHECK |
| G9_NOT_DUPLICATE | `duplicate_claim` | `18` / `N702` | CARC 18: exact duplicate claim/service. RARC N702: decision based on review of previously adjudicated or in-process same/similar services. | CARC 18 is direct. N702 is a broader duplicate/review fit than crossover-specific duplicate remarks. | PROPOSED_SOLID | NEEDS_MEDI_CAL_POLICY_CHECK |
| G10_NO_PROGRAM_INTEGRITY_HOLD | `program_integrity_hold` | `216` / `N35` | CARC 216: based on payer/review-organization findings. RARC N35: program integrity or utilization review decision. | N35 directly names program integrity/utilization review; CARC 216 provides a compatible adjustment reason. | PROPOSED_SOLID | NEEDS_MEDI_CAL_POLICY_CHECK |

## G8 Split Decision

Status: PROPOSED - pending co-founder/Medi-Cal policy ratification.

Current state:

- One gate, `G8_CHARGE_WITHIN_LIMITS`, emits one denial reason: `invalid_or_excessive_charge`.
- Current mapping: CARC `45`, RARC `M79`.
- Problem: CARC `45` is about excessive/above-allowable charge, while RARC `M79` is about missing/incomplete/invalid charge. Those are different denial concepts.

Recommendation: split G8 into two separate gates in a later code-change run.

| Proposed gate | Proposed reason | Proposed CARC/RARC | Recommendation | Why |
|---|---|---:|---|---|
| G8a_CHARGE_VALID | `invalid_charge` | `16` / `M79` | PROPOSED_SOLID | Invalid/malformed/missing charge is a submission or billing-data issue; M79 directly describes invalid charge data. |
| G8b_CHARGE_WITHIN_ALLOWABLE | `excessive_charge` | `45` / no RARC by default | NEEDS_DECISION | CARC 45 directly describes a charge above fee schedule/maximum allowable. A RARC may not be needed unless Medi-Cal policy or the 835 profile requires one. |

Alternative if implementation requires every denial to carry a RARC:

- For G8b, keep CARC `45` and require the domain reviewer to choose one of:
  - blank/no RARC, with the 835 generator omitting `LQ` for that denial;
  - a Medi-Cal/DHCS-specific RARC if a program crosswalk requires one;
  - an X12 RARC only if it adds meaning beyond CARC 45.

Do not keep the combined G8 mapping as final. It is useful for prototype behavior, but it blurs two separate billing decisions and makes downstream remittance semantics weaker.

## Medi-Cal-Specific Review Checklist

Status: PROPOSED - pending co-founder/Medi-Cal policy ratification.

- Check whether Medi-Cal uses a DHCS/RAD-to-CARC/RARC crosswalk that overrides the generic X12 best fit.
- Check whether denial is claim-level or service-line-level for each gate.
- Check whether each code pair is appropriate for Medicaid managed care vs fee-for-service.
- Check whether G2 inactive eligibility should use CARC 27, CARC 30, CARC 31, CARC 32, or another eligibility-specific code depending on the precise eligibility response.
- Check whether G4 provider enrollment should use N767 for all provider-not-enrolled cases, or only when out-of-state/member-state Medicaid enrollment is the issue.
- Check whether G8b should emit no RARC, a Medi-Cal-specific RARC, or a future split reason with a more precise code.

## Proposed Sign-Off Fields

Reviewer:

Date:

Decision:

- [ ] Approve all PROPOSED_SOLID mappings.
- [ ] Approve with changes noted below.
- [ ] Require G8 split before mapping ratification.
- [ ] Require Medi-Cal/DHCS crosswalk review before any code changes.

Reviewer notes:

