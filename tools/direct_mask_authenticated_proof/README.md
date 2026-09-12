# Detached authenticated direct-mask proof seam

This directory is a non-activating composition phase. It verifies a source
signature over the canonical direct-mask statement `x`, then decodes and
independently verifies one exact wire proof whose embedded statement is bound
byte-for-byte to that same owned `x` snapshot.

The public result owns only `x` and the positive source key epoch. It is not a
clearance directive, policy result, state transition, source-truth assertion,
proof object, production receipt, or activation signal. Native proof acceptance
and source provenance remain separate trust properties; success is returned only
when both pass for the same request-scoped statement.

The parser admits exactly one `534370`-byte frame. Size checks and conservative
alias checks run before destructive clears, allocations, or wire parsing;
ordinary failures wipe the owned result and decoded proof state. The focused
probe creates one fresh OS-CSPRNG synthetic proof from the test-only native
fixture and exercises statement, frame, signature, size, ownership, alias, and
failure-wipe attacks. It makes no real-source, production, custody, payment,
state, Lean, or activation claim.

The returned canonical `x` is volatile verifier evidence only. Callers must
clear it after its bounded use; it must never enter State, WAL, receipts, logs,
backups, or another durable or downstream authority.
