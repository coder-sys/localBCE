# Monitoring And Audit Events

The canonical event inventory is `ops/monitoring_events.json`.

Minimum production alerts:

- Any failed production readiness check is critical.
- Any verifier artifact hash change is critical.
- Any `StarkBatchSubmitted` with payment greater than approved amount must page.
- Any stale nullifier root submission must page.
- Any rule ratification failure must block executable rule export.
- Any root approval or governance role change must create an audit ticket.

Retention:

- Contract events: retain for the full compliance period.
- KG fetch and extraction logs: retain source URL, content hash, extractor notes,
  and ratification record.
- Key rotations: retain old/new roots, proposal id, signer set, and activation
  time.
