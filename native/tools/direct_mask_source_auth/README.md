# Detached direct-mask source authentication

This directory is a non-activating source-authentication phase for the
canonical 1,147-byte direct-mask statement `x`. It authenticates a source
signature, verifier-owned request scope, and positive key epoch. It does not
prove the relation, establish source truth, authorize a disposition, publish
state, or qualify production custody.

The signed message is exactly:

```text
ASCII `BL/DM/SOURCE-AUTH/v1` (20 bytes, no NUL)
|| uint64 little-endian positive key epoch (8 bytes)
|| canonical direct-mask statement x (1,147 bytes)
```

`dm_source_auth_sign` owns the synchronous source-side randomizer acquisition:
it uses the existing OS CSPRNG seam, never accepts a caller randomizer, keeps
no secret-key or message state, and wipes its local snapshots. The verifier
owns the expected suite, relation, descriptor, context, nonzero `U`, trusted
public key, and expected epoch. It returns only an owned authenticated `x`
snapshot plus a scoped authentication result.

Inputs are borrowed for the synchronous call and must remain valid and
unchanged until it returns. The implementation rejects input/output aliases
before destructive clearing. Ordinary signing failures wipe a disjoint output
through `min(signature_bytes, DM_SOURCE_AUTH_SIGNATURE_BYTES)`; an
input/output alias preserves the live input and returns an error. The probe is
the only place that uses deterministic ML-DSA key setup and direct wrapper
test seams.

The focused CMake target consumes the committed direct-mask wire codec and
read-only pinned FAEST, direct-mask VOLE, and ML-DSA-87 sources. It deliberately
does not add the inherited process harness, prover, or verifier executables.
