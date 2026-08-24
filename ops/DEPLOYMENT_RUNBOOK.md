# Deployment runbook

Status: synthetic, nonactivating control-plane candidate.

## Preflight

Run from the checkout root and retain only sanitized results:

1. `python -m tools.ops_authority`.
2. `python -m tools.qualification_gate inspect`.
3. The release-manifest source-inventory gate, causal Queue/Composition/Longfellow/Mirror owner
   tests, the privacy-artifact scan, and recovery/export verification.
4. Pin the exact release commit, verifier artifact, schema/program identities, governance roots,
   custody handles, and receiver identity. No caller may replace a pinned identity.

## Qualification and activation

Qualification is the six internal and assurance blockers marked `gate=qualification`; it requires
the qualified proof-suite, verifier and artifact identities, closed evidence, and
`production_usable=true`. Activation additionally requires the two external receiver/connectors
blockers, `activation=true`, and the same qualified pin. The current authorities are unselected,
open, and therefore must remain nonactivating. `require-production` and `require-activation` must
fail closed until their respective conditions are evidenced.

Queue owns verifier admission and independent replay. Composition owns the atomic clearance-state
mutation and official-receiver outbox. Longfellow owns only the native verifier/proof artifacts and
its bounded resource evidence. Mirror owns source intake, derived reconciliation, custody, and
export/restore recovery. A boundary uncertainty is indeterminate and is resolved only by exact
retry or independently verified recovery; no layer falls back to another owner.

The official state payment system remains the sole authority that executes any later payment after
an accepted clearance result; this runbook does not authorize funds movement.

## Recovery gate

Before a qualified release, rehearse verifier rejection, queue lease/retry/exhaustion, composition
commit uncertainty, receiver delivery-indeterminate outcomes, Mirror quarantine/reconciliation,
Longfellow cleanup, custody rotation, and backup/restore. Preserve prior known-good state when a
publication or restore outcome is uncertain. Production qualification is not claimed here.
