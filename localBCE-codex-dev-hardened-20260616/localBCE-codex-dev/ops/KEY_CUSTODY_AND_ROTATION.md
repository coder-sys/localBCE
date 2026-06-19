# Key Custody And Rotation

Status: procedure template. Real key custody requires human enrollment and an
external operations owner.

## Keys

- Duplicate/nullifier PRF secret: `BL_NULLIFIER_PRF_SECRET`.
- Duplicate pepper: `BL_DUPLICATE_CHECK_PEPPER`.
- Audit data encryption key: `BL_AUDIT_DATA_ENCRYPTION_KEY_B64`.
- Decision attestation Ed25519 key.
- Rule ratification Ed25519 reviewer keys.
- Governance multisig signer keys.
- Oracle signing keys.

## Rules

1. Production secrets must never be stored in the repo or release zip.
2. Key roots, not raw private keys, belong in production environment config.
3. Every signer must have a named owner, recovery path, and revocation path.
4. Rotation must overlap old and new duplicate/nullifier epochs until historical
   duplicate checks have been migrated or explicitly retained.
5. Any key compromise triggers a pause, root rotation proposal, replay scan, and
   post-incident report.

## Rotation Steps

1. Open a governance proposal with old root, new root, reason, and effective
   time.
2. Wait the full timelock.
3. Run dry-run validation against old and new roots.
4. Activate the new root.
5. Keep the old root in read-only verification mode until retention is complete.
6. Record the rotation in the audit log and update the production env store.
