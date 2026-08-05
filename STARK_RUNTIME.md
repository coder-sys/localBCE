# STARK Runtime

## Status

The Groth16-to-STARK technical migration is complete for the selected
controlled-attestation settlement profile.

The repository has two explicit proof backends:

- `groth16`: the default compatibility path
- `stark_attested`: an opt-in path that generates and locally verifies a real
  Winterfell proof, then authorizes settlement with a controlled secp256k1
  attestation

The governed Sepolia pilot candidate uses parallel V2 contracts and an
external-command signer boundary. It has not been deployed or approved for
production. The live local validator additionally opts into the hash-pinned
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
-> StarkAttestationVerifierV2
-> StarkClaimsRegistryV2
-> finalized settlement journal
-> atomic local state update
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
- governed V2 policy-manifest hash

## Safety Properties

- Groth16 remains the default when `proof_backend` is absent or set to
  `groth16`.
- STARK settlement is enabled only by `proof_backend = "stark_attested"`.
- `STARK_ATTESTOR_PRIVATE_KEY` is restricted to the legacy/local path.
- Governed V2 uses `external_command`: canonical JSON is sent over stdin and a
  request-bound, allowlisted, low-s 65-byte signature is accepted over stdout.
- V2 separates the timelocked administrator, emergency pauser, and treasury.
- A 72-hour OpenZeppelin `TimelockController` governs attestor, policy,
  registry allowlist, verifier, unpause, and treasury-transfer proposals.
- V2 local state is committed only after the transaction block is covered by
  the RPC `finalized` block. There is no automatic STARK-to-Groth16 fallback.
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

Deploy V1 only for legacy/local compatibility. The governed Sepolia candidate
uses `DeployStarkGovernedV2.s.sol`; deployment requires chain ID `11155111`,
then the 2-of-3 Safe must schedule registry authorization through the 72-hour
timelock. Example addresses and pins are deliberately inactive.

```bash
cd blind-ledger
export STARK_ATTESTOR=0x...
forge script script/DeployStarkAttestation.s.sol:DeployStarkAttestation \
  --rpc-url "$RPC_URL" --broadcast
```

Use `rust-engine/config.stark.example.json` as the opt-in runtime template.
Keep private keys in environment variables; do not put them in config files.
For governed V2, use the external signer fields in that example and validate
`ops/policy_manifest.example.json` before replacing it with an approved policy.

## Validation

Run the deterministic bridge and artifact chain:

```bash
bash scripts/validate_stark_bridge_chain.sh
```

Run the disposable-Anvil end-to-end STARK runtime settlement test:

```bash
bash scripts/validate_stark_runtime_settlement.sh
bash scripts/validate_stark_v2_anvil.sh
```

Include it in the full repository validator explicitly:

```bash
RUN_STARK_RUNTIME_SETTLEMENT=1 bash scripts/validate_localbce.sh
```

## Native Verifier Candidate

`generate_native_verifier_vectors` emits vectors from the exact production
proof artifact and confirms that proof, root, decision, and failure-code
mutations are rejected by the pinned Rust Winterfell verifier. The Solidity
candidate always reverts and cannot be activated. It is intentionally not a
proof-commitment checker.

Native activation still requires a complete EVM implementation of proof
decoding, f64/quadratic arithmetic, Blake3 transcript and Merkle checks, FRI
and query verification, and AIR/public-input binding. It must then satisfy
EIP-170, gas, adversarial, and independent audit gates.

## Remaining External Gates

These are production-hardening tasks, not missing technical migration wiring:

- independent cryptographic and smart-contract audit
- production Safe creation and external MPC credentials
- Sepolia funding, deployment verification, and finalized approved/denied canaries
- governed policy/legal approval and official data-source agreements
- monitoring operations and recovery drills against the deployed addresses
- load, cost, and concurrency testing
- independent cryptographic and Solidity audits, including any native verifier

Until those gates are approved, this remains a production-shaped prototype and
must not be represented as audited or production approved.
