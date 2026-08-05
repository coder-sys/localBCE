# Key Custody And Rotation

Status: procedure template. Real key custody requires human enrollment and an
external operations owner.

## Keys

Pilot and future production keys may include:

- Duplicate/nullifier PRF secret.
- Duplicate-check pepper.
- Audit data encryption key.
- Decision attestation keys.
- Rule ratification reviewer keys.
- Governance multisig signer keys.
- Oracle signing keys.
- External MPC attestation key shares and key IDs.

## Rules

1. Production secrets must never be stored in the repo.
2. Key roots, not raw private keys, belong in production configuration.
3. Every signer must have a named owner, recovery path, and revocation path.
4. Rotation must overlap old and new duplicate/nullifier epochs until
   historical duplicate checks have been migrated or explicitly retained.
5. Any key compromise triggers a pause, root rotation proposal, replay scan, and
   post-incident report.
6. `STARK_ATTESTOR_PRIVATE_KEY` is permitted only for explicit local Anvil use.
7. Sepolia uses the external-command signer with canonical JSON stdin, a fixed
   executable/argument list, approved key IDs, and a configured attestor.
8. No process may log MPC credentials, private key shares, or signing-provider
   authentication material.

## Rotation Steps

1. Open a governance proposal with old root, new root, reason, and effective
   time.
2. Pause immediately if compromise is suspected.
3. Enroll and test the new MPC key ID off-chain.
4. Wait the full timelock for the attestor change.
5. Run dry-run validation against old and new attestors and policy hashes.
6. Activate the new attestor through the timelock.
7. Revoke the old key at the signer after finalized activation and reconciliation.
8. Record the rotation in the audit log and update the private production
   environment store.
