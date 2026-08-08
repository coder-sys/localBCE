# Monitoring And Audit Events

The canonical machine-readable inventory is `ops/monitoring_events.json`. Phase 2 services emit only
opaque commitments, versions, epochs, status, error class, and correlation digests. It never logs
PHI, claim documents, exact private amounts, private decisions, ciphertext, raw payloads, or live
credentials.

Minimum alerts:

- Any failed production-readiness or release-identity check is critical.
- Any verifier, proof-suite, schema, adapter, source epoch, key-root, image, infrastructure, or
  release identity change creates an immutable event and blocks an unapproved identity.
- Any stale source, provenance mismatch, replay, idempotency conflict, credential failure,
  circuit-breaker opening, retry exhaustion, or adapter downgrade pages without private detail.
- Any fixed-cadence queue shape or cover-slot mismatch blocks publication.
- Any key rotation, destruction, incident pause, recovery, or rollback binds the exact checkpoint
  and release identity through opaque SHA3-512 digests.
- Any transition into or out of `BUILT_AUDIT_PENDING`, `AUDIT_ACCEPTED`, or activation binds the
  exact release manifest and approving identities. Monitoring itself never performs that transition.

Retention:

- Contract and incident events: retain for the applicable compliance period.
- Adapter evidence: retain the capsule, exact source/stream digest, schema/normalization version,
  source epoch, and audit-safe error class; retain no raw source payload in the public log.
- Key rotations: retain old/new roots, successor epoch, PQ authority identities, and activation
  time as digests and metadata only.
