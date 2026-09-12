# Direct-mask pipeline boundary

This is a synthetic, non-activating transport candidate. It owns fixed-size
binary parsing, source-to-capsule binding, verifier dispatch, bounded clearing,
and quiet process-status classification. It does not own source truth, policy,
clearance state, key custody, payment, or activation.

## Fixed grammars and statuses

The source CLI accepts exactly one `DMSI0001` input of 5,876 bytes and emits a
539,013-byte `DMSP0001` capsule only on status `0`. The capsule carries one
little-endian key epoch, the 4,627-byte source signature, and the unchanged
534,370-byte DMV1 frame; canonical `x` is not duplicated. The verifier CLI
accepts exactly one `DMVI0001` input of 541,781 bytes and emits no stdout.

Status `0` means accepted, `1` means a well-formed cryptographic rejection,
`2` means malformed transport, and `3` means an internal/resource failure.
Malformed and internal failures clear the bounded caller-owned output where an
output exists. Parser output views are committed only after a complete valid
parse; overlapping or overflowed spans fail before any output write.

## Ownership and end-to-end dependency

The source path calls the reviewed source-proof producer and owns its temporary
output only long enough to encode the capsule. The verifier path copies the
canonical `x` from the capsule's fixed DMV1 frame, then calls the reviewed
authenticated-proof verifier. The verifier link-closure gate inspects the
actual generated Release project graph and executable symbols: the shared
source-auth signer is allowed, while the source producer and native materializer
edges are forbidden. The two paths share transport codec code but do not share
producer/verifier entrypoints.

## Build and claim

Configure with the pinned read-only FAEST, direct-mask, and ML-DSA dependency
checkouts, build the three pipeline targets in Release, then run the filtered
verbose CTest probe and real symbol/closure gate. The probe performs all cheap
parser, alias, capacity, zero-length, argument, and clear checks before one
fresh OS-seeded source proof. This remains synthetic evidence only: it does not
establish cryptographic qualification, formal-kernel linkage, production
readiness, source truth, payment authority, PHI safety, or activation.
