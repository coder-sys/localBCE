# Risk Register

The machine-readable launch blockers are in `ops/launch_blockers.json`.

Current risk posture:

- Prototype/demo review: acceptable after passing the buildable checks.
- Controlled pilot without real payments: possible only after verifier,
  monitoring, and signer dry runs are complete.
- Real production claims/payments: blocked until native STARK production proving,
  external audit, key custody, official oracle access, and compliance approval are
  complete.

Do not downgrade an open blocker to accepted risk unless the named owner signs
the exact scope and compensating controls.
