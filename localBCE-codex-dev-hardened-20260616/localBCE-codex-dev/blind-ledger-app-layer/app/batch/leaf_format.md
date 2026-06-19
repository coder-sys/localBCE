# Batch Leaf Format

Status: duplicate-check key uses Stark-field Poseidon through
`starknet-crypto 0.8.1` with mandatory first-position domain tags;
soundness-checked, PENDING CRYPTO AUDIT.

This file freezes the app-layer byte layout used by the batch prototype. It does
not claim production cryptographic finality. Real batch proof verification is
still pending and fail-closed, but the nullifier non-membership circuit now uses
the full Poseidon field duplicate key as the circuit nullifier.

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
CPN_MANAGED_PAYMENTS_PENDING
```

The intended future rail is Circle Payments Network managed payments. Government
and provider users see fiat payment operations only. No operator-facing wallet UX
is introduced here.

## Duplicate Check Record

Current construction:

```text
Poseidon_nullifier_domain(
  duplicate_domain_with_public_salt_and_private_pepper,
  member_id_field,
  provider_npi_field,
  service_date_field,
  service_codes_field,
  billed_cents,
  frequency_type_field
)
```

Implementation: the app calls the Rust helper in
`app/batch/poseidon_helper/`, which uses `starknet-crypto 0.8.1`
over the Cairo/Stark prime field. Every helper row must begin with a recognized
domain tag, so raw cross-domain hash reuse is rejected before hashing.

Dictionary-linkability note: the public salt prevents cross-protocol reuse, but
does not by itself stop dictionary attacks when inputs are guessable. The private
pepper (`BL_DUPLICATE_CHECK_PEPPER`) must be deployment-secret and shared only by
authorized batch builders. If the pepper leaks, deterministic duplicate detection
also allows dictionary matching. The local default pepper is for tests only.

Circuit note: nullifier membership is STARK-field end to end. Removed legacy
proof lanes must not be used for production settlement. Production readiness is
pinned to the Cairo-native STARK lane with a direct native STARK verifier anchor.

## Test Vectors

The deterministic vectors are generated from the clean sample claim
`BL-CLAIM-0001` with ruleset version:

```text
rarc_mapping_v1_pending_domain_ratification
```

The vector values are locked in the Python test suite and repeated here:

```text
claim_leaf:
ea2fe3ddedac8d9549f759bc2b644772ba97f19c69749021108a868518fa0f2c

result_leaf:
1ea525971e2cf2bdfe26be6c5710eb0fdc293d17aa6f4d94e910cf85f6518b4c

duplicate_check_key:
0298e5ac550cf447f2fbe579c2d73d803b80728229bd4a0db8f6c47a8e2dc13b

duplicate_check_key_decimal:
1174771596993962833874973290899502554628906843877461532234060319733819752763

duplicate_nullifier_full_field:
1174771596993962833874973290899502554628906843877461532234060319733819752763

duplicate_leaf:
c20c4a3bb2d88a206aa7b07f233c0f48589c8931c4f08214b7f0352027b67f0d

payment_leaf:
d7d41520e29afa72b51aca941652def80dc0039c730b1e2a92dc9ce04796166c

claim_root_depth_10_single:
97c39e89f7a0b4dea4633b1408c3f32718f8b28c698f05ab587a2e0f8771a1eb

result_root_depth_10_single:
662f303dd0dcebef2ab3ade4d3328eb229c3fb8a63d6627b5916144b44260001
```
