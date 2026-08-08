# Signed-source adapters and operations

This surviving work supplies provider-neutral adapters for government, oracle, policy, and payment sources. Each adapter binds exact source bytes or stream hash, schema/normalization version, source and tenant identity, freshness/epoch, dual-PQ authority, completeness/absence evidence, idempotency, and privacy-safe errors.

Local simulators and sandbox fixtures permit complete engineering without live credentials. Core proof semantics consume canonical evidence capsules, never vendor-specific responses and never caller-supplied facts.

Operational work covers locked configuration, custody ports, monitoring, append-only non-PHI audit events, backup/restore, rollback, recovery, conformance, and reproducible evidence.

Adapters cannot authorize payment directly. Relevant private evidence enters the mandatory proof; successful native verification and the database transition remain atomic.

No L2 or Ethereum dependency exists in this work.
