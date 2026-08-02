# STARK Runtime

## Status

The Groth16-to-STARK technical migration is complete for the selected
controlled-attestation settlement profile.

The repository now has two explicit proof backends:

- `groth16`: the default compatibility path
- `stark_attested`: an opt-in path that generates and locally verifies a real
  Winterfell proof, then authorizes settlement with a controlled secp256k1
  attestation

The live STARK validator additionally opts into the hash-pinned
`versioned_g1_g10` rules backend. The normal runtime defaults remain
`groth16` plus `hardcoded_g1_g10`.

This is not native on-chain Winterfell verification. The chain verifies the
authorized attestor signature over the exact settlement inputs and proof
commitment. The full Winterfell proof remains in the off-chain audit artifact
and is reverified locally before submission.

## STARK Flow

```text
claim_input.json
-> rust-engine G1-G10 adjudication
-> StarkBridgeInput
-> persistent indexed nullifier transition
-> production Winterfell AIR proof
-> local proof verification
-> versioned proof artifact and verifier handoff
-> 129-byte controlled-attestation proof envelope
-> StarkAttestationVerifier
-> StarkClaimsRegistry
-> settlement receipt and atomic local state update
```

The settlement envelope contains a recoverable secp256k1 signature and the
Keccak-256 commitment of the serialized Winterfell proof. It binds:

- chain ID
- verifier contract address
- registry contract address
- claim hash
- decision and failure code
- public input root
- claim-source root
- oracle-facts root
- fee-schedule root
- nullifier roots before and after
- batch root
- proof commitment
- claim amount

## Safety Properties

- Groth16 remains the default when `proof_backend` is absent or set to
  `groth16`.
- STARK settlement is enabled only by `proof_backend = "stark_attested"`.
- The attestor private key is read from `STARK_ATTESTOR_PRIVATE_KEY`; it is not
  accepted as a CLI argument or serialized into an artifact.
- The submitter key remains the runtime key in `config.json`; production use
  requires it to be distinct from the attestor key.
- Attestations are bound to one verifier, one registry, and one claim amount,
  preventing cross-registry replay and amount substitution.
- Approved claims insert a claim-derived nullifier into persistent indexed
  state.
- Denied claims settle with a no-op nullifier transition.
- State updates use a lock, generation compare-and-swap, atomic file rename,
  and post-transaction on-chain root confirmation.
- Duplicate approved claims, stale generations, root mismatches, path
  collisions, malformed proofs, invalid signatures, and replayed batches fail
  closed.
- Existing `ClaimsRegistry.sol`, Circom files, Groth16 artifacts, and the
  `adjudication_result.json` schema remain compatible.

## Build And Deploy

Build the production STARK executor:

```bash
cd stark-engine
cargo build --features production-air-winterfell \
  --bin execute_production_stark_settlement --jobs 1
```

Deploy the controlled-attestation verifier and registry with Foundry:

```bash
cd blind-ledger
export STARK_ATTESTOR=0x...
forge script script/DeployStarkAttestation.s.sol:DeployStarkAttestation \
  --rpc-url "$RPC_URL" --broadcast
```

Use `rust-engine/config.stark.example.json` as the opt-in runtime template.
Keep private keys in environment variables; do not put them in config files.

## Validation

Run the deterministic bridge and artifact chain:

```bash
bash scripts/validate_stark_bridge_chain.sh
```

Run the disposable-Anvil end-to-end STARK runtime settlement test:

```bash
bash scripts/validate_stark_runtime_settlement.sh
```

Include it in the full repository validator explicitly:

```bash
RUN_STARK_RUNTIME_SETTLEMENT=1 bash scripts/validate_localbce.sh
```

## Remaining Production Work

These are production-hardening tasks, not missing technical migration wiring:

- independent cryptographic and smart-contract audit
- production key custody, rotation, quorum, and incident procedures
- governed source-root and oracle-attestation policy
- monitoring, reconciliation, reorg handling, and recovery drills
- load, cost, and concurrency testing
- optional replacement of controlled attestation with a native or recursively
  wrapped on-chain STARK verifier

Until those gates are approved, this remains a production-shaped prototype and
must not be represented as audited or production approved.
