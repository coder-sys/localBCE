# Lane Decision V2

Production proof lane: `CAIRO_STARK_NATIVE`.

Production field strategy: `STARK_FIELD_END_TO_END`.

Production hash strategy: `POSEIDON_STARK_FIELD_DOMAIN_SEPARATED`.

On-chain anchor: `NATIVE_STARK_DIRECT_ANCHOR`.

## Decision

The package no longer carries the previous proof architecture as an active,
demo, or comparison lane. Native STARK settlement is the only allowed production
direction.

## Required Before Production

- Audited native STARK prover/verifier.
- Pinned verifier artifact hash matching deployed bytecode/source manifest.
- Public input schema matching `ops/native_stark_public_inputs_v1.json`.
- Governance/multisig/timelock validation.
- Oracle/source manifest ratification.
- Key custody and rotation procedures.
- Monitoring and launch-blocker signoff.

Until those are complete, production readiness must fail closed.
