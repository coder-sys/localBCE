# BL-PQ512 SHA3 hash-pad commitment security review

Updated: 2026-08-02

Decision: **rejected for Gate 2E admission**. `proofSuiteId` remains null and
activation remains disabled.

## What was actually reviewed

The nonactivating reference in
`experiments/bl_pq512_crypto_foundation/state_plane.py` commits a 512-bit
statement digest with a 512-bit mask:

```text
ciphertext = statement XOR mask
tag        = SHA3-512(parameter, public_coin, ciphertext, statement, mask)
commitment = SHA3-512(parameter, public_coin, ciphertext, tag)
```

The Python reference verifier and the Rust state-envelope verifier recompute
the same fixed-width relation. The review record is emitted by
`hash_pad_security_review.py` and is itself digest-bound.

## Positive evidence

- The ciphertext is hidden by a 512-bit XOR pad only under the exact
  one-time/uniform-mask condition. Mask reuse is not safe.
- The opening verifier checks the statement, mask, public coin, ciphertext,
  tag, and commitment digest.
- The state relation, opening, receipt, and native parser have mutation tests
  and a Python/Rust KAT.

## Why admission is rejected

The current constructor receives the authenticated public coin before it emits
the commitment, so a commit-before-coin security game is not frozen. The full
tag-hiding and binding composition therefore has no reviewed theorem under the
required protocol order.

If binding is reduced to a generic collision argument for a 512-bit SHA3
output, the conservative quantum collision model is `2^(512/3)`, below the
required 256-bit per-term floor. No Fiat-Shamir, QROM, grinding, or optimistic
collision claim receives credit.

The current construction also is not yet composed into the actual H4 AIR.
Accordingly `TRANSPARENT_HASH_CODE` remains rejected with an explicit
`hash_pad_security_review_rejected` reason; this record does not select a
backend or authorize H5. The newer clean-room `TRANSPARENT_SHAKE256_1024`
candidate is tracked in the S3 registry separately; its 1,024-bit reference
ledger closes the two local hash-pad defects but does not close H4 composition,
the complete simulator, or leakage review.

## Required next closure

Admission needs a reviewed construction with a frozen public-coin lifecycle,
an exact 256-bit post-quantum hiding/binding/composition theorem, complete
state constraints inside the H4 AIR, and independent cross-language evidence.
The tracked `ops/` authority is now the sole verified canonical tree; the former
sibling-layout blocker is closed. The remaining blockers are cryptographic
composition, complete state proof coverage, simulator/leakage closure, and H4
admission evidence.
