# Ethrex / L2 Devnet Notes

Status: LOCAL DEVNET ONLY.

This run produced deployable contracts and an Anvil local-chain deployment script. It did not stand up a production L2.

## What Exists Here

- `anvil.devnet.json`: local devnet settings.
- `deploy_local_anvil.ps1`: deploys the generated Groth16 verifier, verifier adapter, claims registry, payment trigger, and governance registry to a local Anvil chain.
- `deployments/local_anvil_deployment.json`: produced when the script is run successfully.

## Ethrex Production Boundary

Ethrex can be used as Ethereum execution/L2 infrastructure, but a real production L2 is an operations program, not a code artifact. Production operation needs:

- Sequencer and proposer nodes.
- Batch submission and settlement to Ethereum L1.
- EIP-4844 blob/data-availability strategy where applicable.
- Key custody for sequencer/proposer/admin roles.
- Monitoring, alerting, incident response, and rollback playbooks.
- Upgrade governance and verifier/circuit version governance.
- Cost model for L1 data and proving.

## Current Stand-In

Anvil is used here as the local chain stand-in so the contracts can be compiled, deployed, and smoke-tested without claiming a production rollup exists.
