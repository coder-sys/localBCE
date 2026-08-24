# Key custody and rotation

Status: synthetic custody contract; no HSM, FIPS, named-operator, or production-activation claim.

Authority material uses algorithm-agile NIST-approved signatures at Category 1 or stronger.
Dual Category-5 signatures are required only when an explicit deployment threat model calls for it.
Signatures authenticate provenance and authority; they do not establish that the signed facts are
true. Private
keys remain inside state-owned custody; repository and release bytes contain only opaque handles,
algorithm/version identities, roots, epochs, and status.

## Release identity

Every verifier, Longfellow artifact, source-contract, schema, policy, governance, receiver, and
custody identity is pinned by exact byte length plus SHA3-512. A release may not advance its epoch
or selection state when any identity is missing, changed, duplicated, or downgraded. Audit records
contain only sanitized identity digests and lifecycle status.

## Rotation

1. Propose old root, new root, successor epoch, reason commitment, and exact release identity.
2. Obtain the configured authority signature set and timelock; add Category-5 signatures only when
   the approved threat model requires them.
3. Dry-run verification, replay, recovery, rollback, and export/restore on synthetic data.
4. Atomically publish the new root and epoch; reject partial or downgraded records.
5. Retain the prior root read-only until its retention and recovery obligations end.

Compromise pauses new state advances, preserves safe evidence, rotates custody, and creates a
non-PHI incident record. Non-PHI logs must never include raw proofs, sources, receipts, claims,
provider identities, credentials, paths, amounts, or stdout/stderr. A software KMS is limited to
synthetic qualification and is not a production configuration.
