# Monitoring and audit events

This document owns the monitoring requirements; there is no machine event inventory. Monitoring
is zero-PHI, append-only, bounded, and fail-closed. Each event carries only a fixed class, release
and authority digests, epoch, sanitized status, and a non-linkable correlation digest.

## Required sanitized event classes

Qualification identity changes and proof outcomes; clearance admission, lease, retry, exhaustion,
application, delivery-indeterminate, reconciliation, and acknowledgment; Mirror intake, quarantine,
reconciliation, and recovery; custody, rotation, and incident; and backup and restore. Alerts cover
identity drift, stale or incomplete source state, replay/conflicting retry, verifier rejection,
resource-limit or cleanup failure, receiver uncertainty, recovery divergence, and unauthorized
activation transitions.

## Forbidden telemetry

Raw proof, source, receipt, claim, or provider identity; stable claimant/provider fingerprints;
amounts, nonces, credentials, keys, paths, host identifiers, stdout, stderr, payloads, and
exception text are forbidden in events, metrics, logs, exports, support, and dashboards. Monitoring
never selects a verifier, changes a blocker, mutates clearance state, or performs delivery.

Retain sanitized lifecycle and incident evidence only for the applicable state-controlled retention
period. A failed or indeterminate event remains visible as a fixed class until independently
resolved; no lower-level exception or private value is emitted.
