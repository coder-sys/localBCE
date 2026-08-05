# Governed Sepolia STARK Pilot

Status: credential-gated pilot procedure, not production approval.

The pilot uses real local Winterfell proof generation and verification followed
by governed secp256k1 controlled-attestation settlement. Solidity does not
natively verify Winterfell. Groth16 remains the default release backend until
every activation gate has independently approved evidence.

## External Inputs

Before running the pilot, owners must provide:

- a Sepolia RPC that supports the `finalized` block tag
- funded deployer and submitter keys in environment variables
- a deployed 2-of-3 Safe with three recorded owners
- a separate treasury address
- an approved external signer executable, key ID, and attestor address
- a pilot-approved policy manifest with official source records
- an Etherscan-compatible verification API credential
- reviewed approved and denied canary inputs

No private key or service credential belongs in JSON, command arguments,
artifacts, logs, or Git. The external signer continues to accept canonical JSON
over stdin and must return matching request ID, key ID, address, and a low-s
65-byte signature over stdout.

## Configure

Create reviewed live files from the inactive examples:

```bash
cp ops/stark_sepolia_pilot.example.json ops/stark_sepolia_pilot.json
cp ops/policy_manifest.example.json ops/policy_manifest.sepolia.json
```

Replace all example values, set policy status only after the separate policy
and legal review, and update the pilot config to reference the approved policy
and canary files. Public addresses and hashes may be reviewed and committed.
Credentials and runtime state must remain outside Git.

The runner materializes validated deployment pins and release profiles under
the ignored pilot artifact directory. Promote a reviewed public copy into
`ops/` only through a separate intentional commit after the pilot checkpoint.

Export the environment variables named by the live pilot config:

```bash
export SEPOLIA_RPC_URL='...'
export STARK_DEPLOYER_PRIVATE_KEY='...'
export STARK_SUBMITTER_PRIVATE_KEY='...'
export ETHERSCAN_API_KEY='...'
```

## Execute

Run each command from the repository root. Every action is idempotently
recorded under the ignored pilot artifact directory.

```bash
PILOT=ops/stark_sepolia_pilot.json

python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" validate-config
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" local-gates
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" preflight
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" deploy
```

Generate the registry-authorization schedule bundle, submit it through the
2-of-3 Safe, wait at least 72 hours, then generate and submit the execution
bundle:

```bash
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" prepare-safe --operation authorize --phase schedule
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" prepare-safe --operation authorize --phase execute
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" verify-governance --operation authorize
```

The runner does not submit Safe transactions. Human Safe review and threshold
approval are mandatory between preparation and verification.

After the external signer is provisioned and its failure tests pass:

```bash
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" signer-health
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" canary-denied
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" canary-approved
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" reconcile
```

The denied canary must finalize first and preserve the nullifier root. The
approved canary must then finalize and advance matching chain and local roots.
Both canaries use the external signer, never execute Groth16, and reconcile
twice to establish idempotency.

Exercise emergency pause and timelocked recovery after the canaries:

```bash
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" prepare-safe --operation pause --phase execute
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" verify-governance --operation pause
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" prepare-safe --operation unpause --phase schedule
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" prepare-safe --operation unpause --phase execute
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" verify-governance --operation unpause
```

Finally produce the public audit bundle and current status:

```bash
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" audit
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" validate-artifacts
python3 scripts/run_stark_sepolia_pilot.py --config "$PILOT" status
```

## Stop Conditions

Stop before deployment or canaries when the external signer, Safe approval,
funding, finalized RPC support, policy approval, or required credentials are
missing. Never substitute a temporary private-key attestor and never retry a
failed STARK settlement through Groth16.

The generated release profile remains `production_usable=false` with
`current_backend=groth16`. Legal approval and independent cryptographic,
Solidity, and operational audits are external evidence gates that repository
tooling cannot self-certify. A later human-approved release may select
`stark_attested` only after every gate is true.
