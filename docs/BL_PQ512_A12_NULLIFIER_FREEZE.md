# BL-PQ512 A12 nullifier freeze

Updated: 2026-07-19

Status: **A12 application semantics frozen and executable; synthetic-only; not a physical AIR,
proof-system hash, authoritative production registry, or activation approval.**

Current physical-realization note: Wave 2 preserves these exact derivations in the sealed M31
semantic AIR and binds their SHA3-512 calls through the shared committed bus to the Boolean hash
coprocessor in `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. The topology change does not alter
an A12 preimage, digest, projection, replay identity, or rotation rule.

## Security invariant

One authority-issued real attempt has exactly one replay identity for the lifetime of the replay
registry. Retries, batch selection, slot position, payer/provider/member changes, adjudication facts,
decision changes, policy/oracle changes, epoch/profile/domain changes, and proof rerandomization must
not mint a new real-attempt key. Otherwise a caller could evade duplicate detection by changing
mutable context.

Every fixed-shape cover slot instead receives a fresh, private, batch-bound key. Real and cover keys
use different domains. There is exactly one authoritative key: the full SHA3-512 digest of the
canonical preimage. The 252-bit value required by the current compatibility ABI is a proved,
nonzero modular projection of that digest. It is never a second replay identity and never has
replay, settlement, or proof authority.

## Real-attempt identity

`BL-PQ512-v1` derives a real-attempt key only from:

1. governed `sourceAuthorityId`;
2. governed `sourceClaimId`;
3. `attemptVersion`;
4. `revisionKind`; and
5. `parentAttemptVersion`.

The following are deliberately excluded: batch nonce, per-slot randomness, transport sequence,
payer/provider/member fields, claim facts and amounts, decision, policy/oracle facts, epoch, legacy
or strong domain, profile, schema, suite, and proof randomness.

V1 authorizes only the original lifecycle tuple `(attemptVersion=1, revisionKind=1,
parentAttemptVersion=0)`. Corrections, replacements, and voids are structurally rejected before
derivation. A later revision protocol must assign a distinct governed attempt version and preserve
the predecessor relationship; it may not overload mutable claim data as replay identity.

## Exact byte grammar

All integers are unsigned big-endian. `LP16(x)` is `u16be(len(x)) || x`. Text is exact ASCII and is
not normalized.

Every preimage begins with:

```text
magic          bytes[8] = "BLPQNF01"
version        u16be    = 1
domainCode     u16be
totalLength    u32be    = length of the complete preimage
body           bytes[]
```

Real-attempt domain code `257` has this body:

```text
LP16(sourceAuthorityId)       canonical token [A-Z0-9][A-Z0-9-]{0,63}
LP16(sourceClaimId)           canonical token [A-Z0-9][A-Z0-9-]{0,63}
attemptVersion                u32be
revisionKind                  u8
parentAttemptVersion          u32be
pepperLength                  u16be = 64
registryLifetimePepper        bytes[64], nonzero and private
```

Cover domain code `258` has this body:

```text
LP16(profileId)               nonempty ASCII
strongSettlementDomainId     bytes[64], nonzero
epoch                         u64be, nonzero
batchNonce                    canonical nonzero Stark felt encoded as bytes[32]
slotIndex                     u16be, 0..511
coverNonceLength              u16be = 64
privateCoverNonce             bytes[64], nonzero, fresh, and unique in the batch
```

Real slots use the all-zero 64-byte cover-nonce sentinel in the fixed-shape witness and never feed
that sentinel into cover derivation. Cover slots reject zero or duplicate nonces.

## Authoritative key and compatibility projection

The authoritative key is exactly:

```text
strongKey = SHA3-512(canonicalPreimage)
```

Let `p = 2^251 + 17*2^192 + 1`, the Stark252 field modulus, and let `OS2IP` interpret the complete
64-byte digest as one unsigned big-endian integer. The compatibility alias is exactly:

```text
compatibilityAlias = (OS2IP(strongKey) mod (p - 1)) + 1
```

Thus `1 <= compatibilityAlias < p`; zero remains reserved without a rejection/retry branch. The
executable M31 AIR proves the exact integer equation
`OS2IP(strongKey) = quotient*(p-1) + remainder`, proves `0 <= remainder < p-1`, and proves
`compatibilityAlias = remainder + 1`. Full-width equality in the strong registry is always used.

The former nine-call Starknet-Poseidon derivation remains only as a quarantined historical adapter
for already-deployed legacy fixtures. It is not part of the successor AIR, cannot influence replay
or settlement, and must not be promoted back into the authoritative relation. Exact measurement
showed that proving that adapter for one slot alone required 15,635,542 committed witness cells,
while adding no safety that is not already supplied more strongly by the full SHA3-512 key.

## Pepper authority and rotation

The pepper commitment is:

```text
SHA3-512("BLPQPEP1" || u16be(1) || u16be(64) || pepper[64])
```

An authenticated replay-registry binding stores the 64-byte authority ID and 64-byte pepper
commitment. The strong governance commitment binds both fields. Every batch must prove/use an
authority matching that persisted binding.

Pepper or authority rotation is not a batch operation. It changes every real-attempt key. A safe
rotation therefore requires an atomic full-registry migration that reconstructs all historical
keys from the governed identity ledger, proves the old/new equivalence, advances the complete
profile/epoch/checkpoint tuple, and commits all roots together. A12-v1 intentionally implements no
partial migration path: any batch-level authority or pepper mismatch fails closed with
`rotation_requires_atomic_migration`.

## Pinned synthetic vectors

For the exact fixtures in `tests/test_a12_nullifier_derivation.py`:

```text
attemptPreimageLength = 136
attemptCompatibilityAlias = 2719840164224198836297308021026973555694226107455504232196247444694262872412
attemptStrong = 9687cdef3b4a978584378a72fbfbf9ee1de0ee197239a233b39b024cc930ba5edca7bdf4509bb533f25aa0c6692f351e2cb7442fae5b4f68fe9e373368a7f95b
pepperCommitment = 82c917e3170c24bfc981ebb9f4f3376f90c6cff186b31fbb74ee30482051b1420d3cee70f1fbd13c941cfc135e72f8f5c43fd27025a08b9fd92b6ecc88b4cce1

coverPreimageLength = 206
coverCompatibilityAlias = 2006776998731126799121294315803514671534915380589210138863863076080777911642
coverStrong = d616454ce2b8f2d712d740e160f0622497c11380dfbd7f6cefaccde89ea95d59966cdb4eed848c1f0e811d38dcc4a9e7b927d2c898c09018ed5cb7cf8f435d59
```

The following values belong only to the historical application/Rust Poseidon adapter and are not
successor replay or settlement vectors:

```text
legacyAttemptNullifier = 2803046303380838580484408261874923165543787942339809658885540082145836050930
legacyClaimSourceLeaf = 2353052313618558482185397871882505396199949582779852874419840701935818967346
```

## Implementation and proof boundary

The executable application reference is `app/batch/pq_nullifier_derivation.py`. Cover v2
(`BLPQNF02`, domain code 514) is authoritative for the product path and carries a full 64-byte batch
nonce; cover v1 and its felt-sized batch nonce are historical compatibility evidence only. The composed Wave 1A
host relation derives every slot key internally and its verifier recomputes them; caller-supplied
opaque nullifiers are no longer accepted. The current legacy application and Rust semantic oracle
also omit mutable payer/provider/member and claim-record content from the replay identity.

Wave 1A now constrains the exact derivation, pepper authority, compatibility projection, salt-use
insertion, and ordered replay transition in executable AIR and global master/public boundaries.
A13/A15/A16 and S09 remain open until Wave 1B supplies the selected proof suite and authoritative
durable state/verifier integration. `proofSuiteId` remains null,
`concrete_stark_backend_selected=false`, and production
activation remains forbidden.
