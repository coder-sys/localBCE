# Detached direct-mask source producer

This directory is a non-activating source-owned producer for the current
direct-mask relation. It accepts caller-owned fixed spans for a 64-byte
context, a 96-byte `U`, 100 little-endian uint64 values (800 bytes), a
positive key epoch, and a positive final-retry bound. The borrowed ML-DSA-87
secret key must be exactly 4,896 bytes.

The producer snapshots each fixed input once, obtains a fresh 32-byte root
from the existing OS CSPRNG seam, reconstructs the exact native `T`/`C`
relation, encodes canonical `x`, materializes the 15,631-byte/125,048-bit
native witness, unpacks Boolean witness bits, creates one OS-randomized wire
proof, encodes the exact 544,074-byte frame, and signs `x` through the existing
source-authentication seam. Every ordinary failure clears the complete output
and wipes/free all temporary material. The output owns only volatile `x`,
signature, frame, and key epoch; clear it after bounded use. None of those
bytes may enter State, WAL, receipts, logs, backups, or another downstream
authority.

Null, exact-size, epoch, retry, inclusive-range, and alias checks run before
randomness, signing, witness work, or proof generation. The focused probe
runs cheap negatives first, then exactly one fresh OS-randomized synthetic
package, checks preservation of every caller-owned input span before clearing
the inputs and secret key, and reuses the package for source-auth, frame-size,
header, body, statement-binding, and exact serialized-`m3` mutation cases. The
producer has no authority over caller-owned global counters, source truth, or
key custody; those remain external. The retry cap is a caller-supplied bound
for one call and is not an availability, capacity, or global-budget
qualification. The focused CTest invocation filters exactly two tests:
`direct_mask_source_proof_probe` and
`direct_mask_source_proof_real_symbol_gate`. The
generated CTest files also contain inherited subdirectory registrations, but
those registrations are not selected or run by that filtered invocation. This
directory makes no production, source-truth, policy, state, payment, custody,
Lean, or activation claim.
