# Key Custody And Rotation

Status: Phase 2 internal custody contract. The repository contains a software/reference
implementation and local conformance evidence only. It does not claim HSM custody, FIPS-module
validation, named operator enrollment, or production activation.

## Approved Blind Ledger authority material

- Algorithm-agile NIST-approved authority signatures at Category 1 or stronger. Dual Category-5
  signing is required only when an explicit deployment threat model calls for it.
- Signatures authenticate provenance and authority; they do not establish that the signed facts are
  true.
- Private-data wrapping: ML-KEM-1024 with AES-256-GCM and authenticated associated data.
- State and key identity: SHA3-512 roots and domain-separated commitments.
- Stored operational records: opaque handle, root digest, epoch, lifecycle status, and audit digest.

A future optional Ethereum checkpoint's classical boundary is external to Blind Ledger authority
and must never be described as end-to-end PQ protection. RSA, Ed25519, ECDSA, and classical
signatures are not accepted as Blind Ledger authority or as a fallback in signed-source adapters.

## Rules

1. Production secrets must never be stored in the repository, release ZIP, logs, or public data.
2. Only key roots, opaque handles, and algorithm/version identities belong in deployment config;
   raw private keys stay inside the provider custody boundary.
3. Every authority key has an owner, recovery path, revocation path, suite identity, and epoch.
4. Rotation is monotonic, dual-authorized, and retains the prior root for read-only verification
   until its retention obligation ends.
5. Entropy health, nonce reuse, zeroization, replay, and downgrade failures are fail-closed.
6. A suspected compromise pauses new state advances, preserves safe evidence, rotates the root,
   runs a replay scan, and produces a non-PHI incident record.
7. The local software KMS is allowed only for synthetic/sandbox qualification and is rejected in
   production configuration.

## Rotation Steps

1. Create a proposal binding old root, new root, successor epoch, reason commitment, and exact
   release identity.
2. Obtain the configured algorithm-agile authority signature set and wait the configured timelock;
   add dual Category-5 signatures only when the approved threat model requires them.
3. Dry-run old/new verification, migration, replay, recovery, and rollback against synthetic data.
4. Atomically publish the new root and epoch; reject partial or downgraded manifests.
5. Keep the old root read-only until retention and recovery obligations are complete.
6. Append only opaque digests and status to the non-PHI audit chain.
