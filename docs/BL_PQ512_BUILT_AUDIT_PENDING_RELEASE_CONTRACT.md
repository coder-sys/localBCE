# BL-PQ512 built-audit-pending release contract

Status: frozen narrow-component candidate contract; aggregate qualification open; nonactivating
Updated: 2026-08-08

## Decision and boundary

The current narrow selected-AIR envelope is exactly `BLPQENV1` version 2. The earlier
`BLPQEN01` version 1 transport in the S07-S12 preimplementation freeze is historical and rejected
for this component lane. An implementation must not accept version 1 as an alias or silently
convert it to version 2.

This contract can identify exact locally built candidate bytes and independently verify the one
selected AIR/FRI package carried by version 2. It cannot label any proof or release
`BUILT_AUDIT_PENDING`: the complete heterogeneous claim/payment/state/H4 theorem and its verified
aggregate evidence do not yet exist. The global `proofSuiteId` remains null,
`production_usable=false`, and activation remains forbidden. It conveys no permission for PHI,
payments, credentials, a production database, an L2, or Ethereum.

The machine-readable authority for this slice is
`schemas/bl_pq512_built_audit_pending_release_contract_v1.json`. Its exact bytes are themselves an
input to every per-release candidate identity.

## Exact narrow envelope grammar

All integers are unsigned big-endian. All lengths are byte lengths. The fixed prefix is exactly
1,342 bytes.

| Offset | Bytes | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `BLPQENV1` |
| 8 | 2 | version | exactly 2 |
| 10 | 64 | candidate proof-suite identity | nonzero; compare with the pinned release context |
| 74 | 64 | public-input schema identity | nonzero; compare with the pinned exact schema bytes |
| 138 | 64 | verifier artifact identity | nonzero; compare with the pinned release context |
| 202 | 384 | public outputs | exactly 12 ordered canonical 32-byte Stark-field encodings |
| 586 | 4 | sidecar length | exactly 744 |
| 590 | 744 | sidecar | exact `BLPQSC01` v1 sidecar; embedded identities must match the prefix |
| 1334 | 8 | proof-package length | exactly 67,108,864 |
| 1342 | 67,108,864 | proof package | exact `BLPQSPK1` version-2 package; compact core followed by canonical all-zero padding |
| next | 8 | transcript length | 1 through 16,777,216 |
| next | variable | transcript evidence | exact authenticated interactive transcript bytes |

The exact file length is `1342 + 67,108,864 + 8 + transcriptLength`, must not exceed
536,870,912 bytes, and admits no trailing byte. The envelope embeds the public outputs; they are not
an out-of-band settlement argument in this successor grammar.

## Parse-before-allocate rule

The authoritative verifier process opens one regular-file handle and obtains its bounded length.
It reads exactly the 1,342-byte prefix into fixed bounded storage, validates magic, version, all
three identities, all twelve canonical fields, the fixed sidecar and its embedded identities, and
the proof length. It then seeks over the proof bytes, reads the eight-byte transcript length, and
validates the exact total file length. Only after all those checks pass may it allocate the proof
and transcript sections separately. It must use bounded sized reads, reject allocation failure,
re-read and compare the transcript-length word on the same handle, and reject truncation, mutation,
or trailing data. Reading the entire maximum-size envelope into one byte vector before these checks
is forbidden.

The in-memory decoder enforces the same grammar for already-bounded trusted callers. File and
network adapters must use the streaming file/parser boundary, not use the in-memory API as a reason
to perform an unbounded read first.

## Frozen statement and cryptographic profile

- The ordered schema bytes are exactly `ops/native_stark_public_inputs_v2.json`: 1,807 bytes with
  SHA3-512 `cb9e2c4e248f62832f996f4c2a157985643ffef4ff09ab58002f2265cbc97347862093c77361ead8be7ce68dae9a92f9565a133491899dfb130a2f6c4acc122d`.
- The public ABI is exactly twelve `bytes32` fields in the order recorded in that file. The sidecar
  is exactly 744 bytes.
- SHA3-512 is authoritative. Proof arithmetic is M31/Fp16. Native hiding is the Construction-8.2
  candidate. The launch transcript is authenticated interactive public coin, with ML-DSA-87 and
  SLH-DSA-SHAKE-256f at the frozen dual-PQ boundary.
- The private proof package is exactly 67,108,864 bytes. Its compact-core length is explicit, every
  remaining byte must be zero, and the version-2 package commitment authenticates the entire fixed
  container. The worker rejects a core that leaves no padding. This is a fail-closed capacity gate:
  changing the pinned AIR or proof grammar requires proving it fits before a release can qualify.
- No acceptance is derived from a prover self-check, a host claim, an envelope-selected program, or
  a path name.

## Per-release candidate identity

Every release identity is the domain-separated SHA3-512 commitment to the candidate proof-suite
identity and the role, exact byte length, and SHA3-512 digest of each of these artifacts, in this
order:

1. this machine-readable release-contract schema;
2. the exact twelve-field public-input schema;
3. proof parameters;
4. AIR program;
5. prover executable;
6. verifier executable;
7. transcript contract;
8. toolchain description; and
9. a source-set commitment over unique repository-relative UTF-8 paths in strict ascending order,
   binding every path, byte length, and SHA3-512 digest.

Changing any byte, length, role, path, ordering, grammar parameter, program, executable, transcript
contract, toolchain, or governed source produces a different candidate identity. Symlinks,
non-regular files, duplicate sources, out-of-root sources, unordered sources, and files that change
during hashing are rejected.

## Independent verifier definition

For this contract, an independent verifier is a standalone authoritative verifier-only executable
and process that parses the narrow envelope and replays its selected AIR proof and authenticated
transcript without trusting a prover self-check or accepting a prover-selected verification
context. This proves that component only. The definition does **not** claim implementation
diversity: sharing reviewed verification library code with the prover package is permitted and must
not be described as an independently developed implementation.

## Aggregate LB-001/LB-010 gate

Every current candidate has status `AGGREGATE_UNQUALIFIED`. No current per-proof object may report
`BUILT_AUDIT_PENDING`.

The former caller-paired interface accepted receipt bytes together with a digest supplied in the
same request. That was self-attestation, even when the JSON and digest were internally consistent,
because no implementation opened the evidence manifest or replayed the package-specific gates.
The interface is now explicitly rejected. A requester supplying both a purported LB-010 receipt
and its matching digest cannot qualify anything.

The verified aggregate-evidence implementation remains open. Before this lifecycle can advance, a
future internal verifier must consume a governance-pinned canonical manifest, derive the exact
release/source identities itself, validate raw machine evidence for Z03-Z12, and replay standalone
receipts for the complete heterogeneous theorem. It must reject the current v2 narrow proof by
itself, H4 stdout or boolean receipts, missing/reordered components, and typed-state artifacts that
expose private execution or lack authenticated transcript evidence. Its successful result must be
an opaque verified object produced by that verifier, not caller-authored JSON.

Only after the complete verifier-safe H4 grammar, semantic-bus proof and proof-native equality,
verifier-safe typed-state component, fixed-shape composite grammar, strict-PQ ledger, and all
remaining qualification gates close may the per-proof selector be implemented to return
`BUILT_AUDIT_PENDING`. That future state remains nonactivating and cannot authorize a database
transition by itself.

## Fail-closed conditions

Stop release qualification on any v1/v2 alias, identity mismatch, schema-byte mismatch, noncanonical
public field, sidecar mismatch, zero/overflowing/excessive length, truncation, trailing byte,
allocation failure, changed file, source-set drift, artifact/toolchain drift, parser disagreement,
proof/transcript verification failure, any current caller-supplied LB-010 receipt/digest pair,
missing complete aggregate evidence, receipt/release mismatch, non-null global suite identity, or
true production/activation flag. Compatibility is not a reason to weaken one of these checks.
