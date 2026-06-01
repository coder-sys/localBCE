# Redeploy Workflow

Use this workflow only when a contract, verifier, proving key, or circuit artifact intentionally changes.

## When Redeploy Is Required

Redeploy is required if any of these change:

- `zk/claim.circom`
- `zk/claim_final.zkey`
- `blind-ledger/src/Verifier.sol`
- `blind-ledger/src/ClaimsRegistry.sol`

Do not redeploy for Rust-only refactors that preserve the current Groth16 calldata and contract interface.

## Circuit Change Workflow

If `zk/claim.circom` changes:

1. Recompile the circuit.
2. Regenerate the witness artifacts.
3. Regenerate the final proving key.
4. Regenerate `blind-ledger/src/Verifier.sol`.
5. Redeploy `Groth16Verifier` and `ClaimsRegistry`.
6. Update `rust-engine/config.json` with the new `claims_registry_address`.
7. Run the Rust approved-claim flow with a fresh `claim_id`.

## Contract Redeploy Workflow

From `blind-ledger`:

```bash
forge build
forge script script/Counter.s.sol:DeployClaimsRegistry \
  --rpc-url http://127.0.0.1:8545 \
  --private-key <PRIVATE_KEY> \
  --broadcast
```

The deploy script writes `deployment.json` after deployment. Use the `claimsRegistry` value from that file as the new `rust-engine/config.json` `claims_registry_address`.

## Rust Verification Workflow

From `rust-engine`:

```bash
cargo test
cargo check
```

For an approved end-to-end flow, make sure Anvil is running, the deploy address in `config.json` is current, and `claim_input.json` uses a fresh approved `claim_id`.

Then run:

```bash
cargo run
```

## Keep Stable

- `rules_v9.json` is not active yet.
- `rules.json` and `rules_v9.json` must remain parallel.
- `denial_reason()` must remain in the Rust engine.
- Denied claims must stop before proof generation.
- Approved claims require a unique `claim_id`.
