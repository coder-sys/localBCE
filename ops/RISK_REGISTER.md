# Risk Register

Status: planning register. This does not approve production use.

## Current Risk Posture

- Local prototype/demo review: acceptable after Rust and Foundry checks pass.
- Controlled pilot without real payments: blocked until verifier, monitoring,
  and signer dry runs are complete.
- Real production claims/payments: blocked until production STARK proving,
  external audit, key custody, official oracle access, and compliance approval
  are complete.

## Open Risks

- Real STARK proof generation is not implemented in active localBCE.
- Native STARK verifier is not wired into `ClaimsRegistry`.
- Rules KG outputs are not active deterministic runtime rules.
- Imported app-layer and hardened folders are reference bundles until explicitly
  ported.
- Batch/nullifier/payment-root settlement is not part of the active contract
  flow.
- Production oracle access and signer custody are not configured.

## Risk Rule

Do not downgrade an open blocker to accepted risk unless the named owner signs
the exact scope and compensating controls.

