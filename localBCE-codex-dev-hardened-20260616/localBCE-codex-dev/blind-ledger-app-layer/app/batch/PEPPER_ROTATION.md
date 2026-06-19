# Duplicate Pepper Rotation

Status: soundness-checked, PENDING CRYPTO AUDIT.

The duplicate-check pepper is versioned. A rotation must never silently replace the old pepper because the same claim derives a different nullifier under a different pepper.

Procedure:

1. Admin creates a new pepper version with `BatchAuthority.rotate_duplicate_pepper`.
2. The previous pepper version is automatically retained in the overlap window.
3. During the overlap window, duplicate admission checks derive nullifiers under the current pepper and every overlap pepper.
4. A claim is quarantined as a duplicate if any active epoch nullifier is already present in the nullifier tree.
5. New accepted claims insert the current pepper version's nullifier.
6. Do not retire an overlap pepper until historical claims covered by that pepper have been migrated or a human audit signs off that the replay window is closed.

Operational rules:

- Rotation is admin-gated.
- Every rotation is appended to `pepper_rotation_log`.
- Pepper values must come from managed secret storage in production, not source code or plain environment dumps.
- Auditors must verify that all app workers, batch builders, and proof workers use the same current and overlap epoch set before accepting batches after rotation.
