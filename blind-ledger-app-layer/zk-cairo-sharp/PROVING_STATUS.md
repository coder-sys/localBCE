# Cairo / S-two Proving Status

Status as of the local WSL run:

- `scarb build`: PASS.
- `scarb test`: PASS, 12 passed / 0 failed.
- Standalone Cairo execution: PASS for approved, ineligible denied, duplicate denied,
  and excessive-charge denied cases.
- Attack execution: PASS for malformed boolean rejection, missing raw-root rejection,
  missing-batch-ID rejection, excessive-charge denial, zero-service-line denial, and
  spent-nullifier replay denial.
- Bootloader execution: PASS and emits `prover_input.json`.
- Local `scarb prove`: BLOCKED on this laptop by WSL out-of-memory.

Observed blocker:

`scarb-prove` was killed by the Linux OOM killer at roughly 7.2 GiB resident memory.
This is a machine/resource wall, not evidence that the Cairo adjudication logic is
wrong. The next proving attempt should run on a larger Linux machine or a managed
S-two/SHARP proving service.

Important caveat:

This lane is the preferred direction for native STARK verification, but it is not
yet wired to a native Ethereum verifier. The current package proves the adjudication
program in the Cairo/S-two ecosystem once sufficient proving resources are available.
Ethereum anchoring still needs the SHARP/native verifier integration step.

Security label:

Soundness-checkable prototype, PENDING CRYPTOGRAPHIC AUDIT.
