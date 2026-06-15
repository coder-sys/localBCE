# Trusted Setup Ceremony Plan

Status: PLAN ONLY. No production ceremony was run in this pass.

## Plain-English Purpose

Groth16 proofs need setup parameters. During setup, secret randomness is used and then must be destroyed. People call that secret "toxic waste" because anyone who keeps it could forge proofs later. A multi-party ceremony reduces that risk: if at least one honest participant contributes randomness and deletes their secret, the final parameters are safe from toxic-waste recovery under the Groth16 assumptions.

This plan is for a later human-run ceremony. It is not production ratification and not a cryptographic audit.

## Which Proof Paths Need This

- Needs ceremony: Groth16 circuits, including `claim_adjudication_core.circom`, `nullifier_nonmembership.circom`, and the fixed-size `zk/batch_multiclaim/` Groth16 batch circuits if they remain on the production path.
- Does not need ceremony: STARK/Winterfell/Plonky3-style transparent proof paths. Those avoid trusted setup, but may have larger proofs or more expensive verification.
- SP1 caveat: SP1 core proving is transparent/STARK-like, but the usual EVM verifier is a Groth16 or PLONK wrap. That on-chain wrapper is pairing-based and not end-to-end post-quantum.

## Current Prototype Status

The current pot19/pot20 files and zkeys in this workspace are PROTOTYPE-ONLY. They were useful for local proving, testing, and gas experiments. They must be replaced before production, or the production design must commit to a transparent STARK path and skip Groth16 entirely.

## Inputs Before Ceremony

1. Freeze exact circuit source and compiler versions.
2. Freeze circuit parameters and public-input schema.
3. Hash every source file, generated wrapper, R1CS, and tool binary.
4. Run static checks and witness/proof regression tests.
5. Have the external ZK auditor review the circuit before asking humans to bless setup artifacts.

## Phase 2 Per-Circuit Contribution Flow

For each production circuit:

1. Generate the final `.r1cs` from the audited circuit.
2. Select the appropriate prepared Powers of Tau file.
3. Create the initial circuit zkey:

```text
snarkjs groth16 setup circuit.r1cs powersOfTau_final.ptau circuit_0000.zkey
```

4. Participant 1 contributes entropy:

```text
snarkjs zkey contribute circuit_0000.zkey circuit_0001.zkey --name="participant-1" -v
```

5. Each next participant repeats with the previous zkey as input and a new output.
6. Optionally add a public beacon contribution after the human contributions.
7. Export the verification key:

```text
snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
```

8. Export the Solidity verifier only after final zkey verification:

```text
snarkjs zkey export solidityverifier circuit_final.zkey Verifier.sol
```

## Participant Instructions

Each participant must:

1. Run the contribution command on a machine they control.
2. Supply fresh entropy that they do not record or reuse.
3. Confirm the tool completed successfully.
4. Delete local temporary contribution secrets and intermediate local copies.
5. Sign an attestation listing their name/pseudonym, input zkey hash, output zkey hash, timestamp, command version, and statement that they deleted their secret entropy.

Nobody should store, remember, screenshot, or share their entropy. The security promise is that one honest deletion is enough.

## Recommended Participant Set

- Neer.
- Cofounder.
- At least one technical advisor.
- At least one outside cryptography/security reviewer.
- Optional public/community participant if the team wants public auditability.

More independent participants are better than a small private ceremony.

## Transcript And Publication

Publish:

1. Circuit source hashes.
2. Compiler/tool versions and hashes.
3. R1CS hashes.
4. Every zkey input/output hash per contribution.
5. Participant attestations.
6. Final zkey hash.
7. Verification key hash.
8. Solidity verifier hash.
9. Test proof/public-input fixtures generated after the final zkey.

Keep the transcript immutable in the repo and in a public archive before production use.

## Pre-Production Gate

Production can proceed only after one of these is true:

1. The Groth16 ceremony above is completed, verified, published, and externally audited.
2. The architecture switches to a transparent STARK path and formally removes Groth16 as a trust anchor.

Until then, every Groth16 artifact in this workspace remains prototype-only, soundness-checked where executable, PENDING CRYPTOGRAPHIC AUDIT.
