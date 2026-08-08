# Batch Leaf Format

Status: historical application-batch compatibility format. Its duplicate-check key uses
Stark-field Poseidon through `starknet-crypto 0.8.1` with mandatory first-position domain tags;
soundness-checked, PENDING CRYPTO AUDIT. This is not the authoritative BL-PQ512 nullifier or
settlement format; the authoritative product path is the SHA3-512 A12 construction in
`docs/BL_PQ512_A12_NULLIFIER_FREEZE.md`.

This file records the app-layer byte layout used by the legacy batch prototype. It does not claim
production cryptographic finality. Real batch proof verification is still pending and fail-closed;
the legacy nullifier non-membership circuit uses the full Poseidon field duplicate key only for
compatibility testing.

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
tags distinguish null, bool, int, string, bytes, and structured JSON, so `1`,
`true`, and `"1"` do not collide. Raw floats are rejected before commitment
encoding. Monetary amounts are integer cents before encoding. Most batch leaf records still use
SHA-256 over the canonical record bytes in this legacy prototype. The duplicate-check key no
longer uses the old SHA-256 stand-in; it is a Poseidon field hash described below. Neither choice
is the authoritative BL-PQ512 commitment/nullifier path.

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

Circuit note: nullifier membership in this prototype remains constrained by the sealed M31 semantic
AIR. Removed legacy proof lanes and the historical Cairo-native STARK lane must not be used for
production settlement. The current BL-PQ512 target binds the authoritative A12 SHA3-512 nullifier
operations and every SHA3 port through the shared committed bus to the Boolean hash coprocessor,
then verifies the complete heterogeneous proof atomically.

## Test Vectors

The deterministic vectors are generated from the clean sample claim
`BL-CLAIM-0001` with ruleset version:

```text
rarc_mapping_v1_pending_domain_ratification
```

The vector values are locked in the Python test suite and repeated here:

```text
claim_leaf:
2df339ed2b6e4454508e4edb6df836cca0502d5bbc71a9a5c606e9acab743602

result_leaf:
ad00baf650b78ca4b44617cd6ff577e6312a343e32042266378959270b6c1a7c

duplicate_check_key:
061ed6d047566ceba7bcd11ee8f58c9242d71ea9ed45425b2589de44b7c90469

duplicate_check_key_decimal:
2768365092342795893101599336092769498668825219058121831343131575006142202985

duplicate_nullifier_full_field:
2768365092342795893101599336092769498668825219058121831343131575006142202985

duplicate_leaf:
b9d199d7ce629985fc21302e823c05b2d697e12819d794a2a21748738a09312e

payment_leaf:
883ec91428fd05ac18929e1760fc73a4103319bb5c44170bdee5054398171c37

claim_root_depth_10_single:
0059da5df3f11d0aeb182b125f665f57a9a7204db0916e56ce100a9a399f8610

result_root_depth_10_single:
01780e2e9a727b973a8db3a75df7818b46852e171f20d6f19f9836d61284ce48
```
