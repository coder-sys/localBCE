# Batch Leaf Format

Status: duplicate-check key uses real circom-compatible Poseidon through
`pso-poseidon 0.3.6`; soundness-checked, PENDING CRYPTO AUDIT.

This file freezes the app-layer byte layout used by the batch prototype. It does
not claim production cryptographic finality. The batch proof is still a stub, but
the nullifier non-membership circuit now uses the full Poseidon field duplicate
key as the circuit nullifier.

## Canonical Encoding

Every record is encoded as:

```text
len("BL_CANONICAL_RECORD_V2") || tag("s") || "BL_CANONICAL_RECORD_V2"
len(record_type)              || tag("s") || record_type
len(field_0)                  || type_tag(field_0) || encoded_field_0
...
len(field_n)                  || type_tag(field_n) || encoded_field_n
```

Lengths are unsigned 4-byte big-endian integers. Text fields are UTF-8. Type
tags distinguish null, bool, int, float, string, bytes, and structured JSON, so
`1`, `true`, and `"1"` do not collide. Monetary amounts are integer cents before
encoding. Most batch leaf records still use SHA-256 over the canonical record
bytes. The duplicate-check key no longer uses the old SHA-256 placeholder; it is
a Poseidon field hash described below.

## Claim Record

```text
record_type = "claim_leaf"
fields =
  claim_id_hash,
  claim_fact_hash_without_operator_flags,
  member_id_hash,
  provider_npi_hash,
  service_date,
  service_lines_hash,
  diagnosis_hash,
  billed_cents,
  prior_authorization_list,
  duplicate_check_key,
  content_addressed_ruleset_record
```

## Adjudication Record

```text
record_type = "result_leaf"
fields =
  claim_id_hash,
  approved_bit,
  first_failed_gate_reason,
  carc,
  rarc,
  payable_cents,
  gate_evidence_hash,
  operator_policy_assertion_hash,
  engine_mode,
  duplicate_check_key,
  content_addressed_ruleset_record
```

## Payment Record

```text
record_type = "payment_leaf"
fields =
  batch_id,
  keyed_provider_payment_alias,
  payout_recipient_commitment,
  approved_claim_count,
  net_amount_cents,
  payment_reconciliation_commitment,
  payment_rail,
  settlement_instruction_hash,
  approved_result_commitment
```

Default rail for this build:

```text
CPN_MANAGED_PAYMENTS_STUB
```

The intended future rail is Circle Payments Network managed payments. Government
and provider users see fiat payment operations only. No operator-facing wallet UX
is introduced here.

## Duplicate Check Record

Current construction:

```text
Poseidon(
  domain_sep_with_public_salt_and_private_pepper,
  member_id_field,
  provider_npi_field,
  service_date_field,
  service_codes_field,
  billed_cents,
  frequency_type_field
)
```

Implementation: the app calls the Rust helper in
`app/batch/poseidon_helper/`, which uses `pso-poseidon 0.3.6`
(circom-compatible BN254 Poseidon). The helper output was cross-checked against
`circomlibjs 0.1.7` for known inputs.

Dictionary-linkability note: the public salt prevents cross-protocol reuse, but
does not by itself stop dictionary attacks when inputs are guessable. The private
pepper (`BL_DUPLICATE_CHECK_PEPPER`) must be deployment-secret and shared only by
authorized batch builders. If the pepper leaks, deterministic duplicate detection
also allows dictionary matching. The local default pepper is for tests only.

Circuit note: `nullifier_nonmembership.circom` v2 decomposes `nullifier`,
`leafValue`, and `nextValue` with strict 254-bit BN254 field checks, then compares
their canonical bit representations. This removes the previous 32-bit truncation.
The result is soundness-checked, PENDING CRYPTO AUDIT.

## Test Vectors

The deterministic vectors are generated from the clean sample claim
`BL-CLAIM-0001` with ruleset version:

```text
rarc_mapping_v1_pending_domain_ratification
```

The vector values are locked in the Python test suite and repeated here:

```text
claim_leaf:
77433533fa3ff01c20fdfbda929a9e6959ab324cdc4fea7febbccfe4acd1569e

result_leaf:
99cdbc2b7a13036e6eeb4edb2992cf2a287283e3025fab3cec17e4ff8011b17f

duplicate_check_key:
228296e1562d030962b31c0a41d32d5c755342081f54c630f9b7b835827cc3fe

duplicate_check_key_decimal:
15609368307267639750494857447442523018147726388577141256780492055880130151422

deprecated_duplicate_nullifier32:
2812950571

duplicate_nullifier_full_field:
15609368307267639750494857447442523018147726388577141256780492055880130151422

duplicate_leaf:
09a2e5362afcc61db5d678eb8624fd4f0e05cbb5afc308123241e2289af57fb0

payment_leaf:
68f9dc65e83b2560c89aedb63798bffd8ebcd0de0d198fd0e2b36369343dce09

claim_root_depth_10_single:
e38c0277d6517717f984d05a57b614a85a1e41877956ede991941e6555052f43

result_root_depth_10_single:
a9cbe7c28c7011fb7f7a0bc4b850964fb20e94b511ae0299910a982610b6db5b
```
