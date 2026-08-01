# Monitoring And Audit Events

The canonical event inventory is `ops/monitoring_events.json`.

This is the current minimum, not the completed O06/I08 audit contract. Before
`DEPLOYMENT_READY_AUDIT_PENDING`, the machine-readable inventory must cover every proof-suite,
schema, verifier, governed-root, adapter-version, source-epoch, KMS/HSM, release, deployment,
rollback, bridge, exit, and incident transition with immutable non-PHI correlation and exact
artifact identities. Event coverage and retention are internal engineering; the final independent
audit reviews the completed inventory.

Minimum production alerts:

- Any failed production readiness check is critical.
- Any verifier artifact hash change is critical.
- Any `StarkBatchSubmitted` with payment greater than approved amount must page.
- Any stale nullifier root submission must page.
- Any rule ratification failure must block executable rule export.
- Any root approval or governance role change must create an audit ticket.
- Any proof-suite, schema, verifier, adapter, source signer/epoch, image, infrastructure, or release
  identity change must create an immutable audit event and block on an unapproved identity.
- Any adapter fallback, version downgrade, stale oracle response, replay, circuit-breaker opening,
  credential failure, or provenance mismatch must alert without logging PHI.
- Any transition into or out of `BUILT_AUDIT_PENDING`, `AUDIT_ACCEPTED`, or production activation
  must bind the exact release manifest and approving identities.

Retention:

- Contract events: retain for the full compliance period.
- KG fetch and extraction logs: retain source URL, content hash, extractor notes,
  and ratification record.
- Key rotations: retain old/new roots, proposal id, signer set, and activation
  time.
