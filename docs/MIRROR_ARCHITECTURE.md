# Mirror architecture

Updated: 2026-09-05
Status: synthetic, read-only, nonactivating architecture candidate
Owner: Mirror source trust, evidence custody, reconciliation, and recovery boundary

Mirror is RightRail's read-only evidence, reconciliation, and operational-continuity product.
Provider Trust Graph is its current narrow first wedge, not the whole product. Mirror never
adjudicates a claim, issues a Blind Ledger directive, moves money, or converts observed incumbent
behavior into approved state policy.

## Smallest current boundary

```text
synthetic acquisition port (production authorization remains external)
        |
        v
Operational owner V1 -- one lock, bounded due/retry/recovery composition
        |
        v
Ingress V5 -- one bounded sanitized observation owner
        |
        v
Core V2 ---- derived graph, reconciliation, and case state
        |
        v
Recovery V2 - explicit export, restore, and publication recovery points
```

The synthetic source-side adapter and its independent verifier consume raw source bytes only at the
source boundary and emit one canonical allowlisted observation plus an opaque verification-at-time
receipt. Ingress owns scheduling, leases, attempts, quarantine, and the sole durable sanitized
observation. Core independently reconstructs derived artifacts, events, heads, reconciliation, and
case progression from that observation. Recovery owns encrypted sanitized-state bundle identity,
key/storage binding, restore, and explicit publication recovery. No layer may create a second raw
capture owner, persist source bytes, or mutate another layer's tables.

The operational owner is the exact `mirror-operational-owner-v1` composition boundary, not a new
data owner. It pins one ordinary local root, the three existing stores, one nonblocking operational
lock, one verifier-owned clock, one acquisition identity/policy/profile, and a fixed run bound of at
most sixteen eligible slots. Before acquisition it independently reconciles Ingress terminal
`QUARANTINED` artifact projections with Core's represented source projection, recovers verified
pending artifacts first through Core's idempotent batch seam, and reports `core_recovered`,
`core_ingested`, and residual `core_pending` counts without exposing identifiers. It processes
expired leases before new due work, lets Ingress perform all lease recovery and admission, calls
Core once for a nonempty new-admission batch, and creates a Recovery point only for an explicitly
supplied generation. It has no daemon, scheduler, network, raw capture, orchestration database,
automatic restore, or automatic publication path; ambiguous path, lock, store, projection, or
verifier state fails closed with a fixed operational result.

The current consolidated stores have exactly five Ingress tables, six Core tables, and three
Recovery tables. These counts are current executable grammar, not a permanent product metric;
changing them requires an ownership or recovery need, a versioned migration, and independent
reconstruction evidence.

## Source and privacy boundary

The current North Carolina FHIR profile is synthetic-only. It accepts only the exact registered
canonical Practitioner, PractitionerRole, and Location fixture resources, including one registered
changed Location. The independent source verifier rejects all other resource bytes before the
operational owner calls Ingress. Only the bounded observation counts/status/outcome and the
opaque verification-at-time receipt cross that boundary; provider, subject, credential,
enrollment, source, URL, path, raw-data, and page identities do not.

The source-side complete intake frame remains capped at 262,144 bytes and is not an Ingress/Core
field. Raw source captures, credentials, host paths, errors, stdout/stderr, exact raw-data digests,
and stable real-person or real-provider fingerprints may not enter Ingress, Core, Recovery,
support, monitoring, analytics, AI, receipts, or exports. Public failures use fixed codes. A
rejected observation must leave database bytes, logical export, support output, and durable state
unchanged.

## Provider evidence export boundary

app/mirror/provider_evidence_export_v1.py is the sole producer owner for
MIRROR_PROVIDER_EVIDENCE_EXPORT_V1. Its request is an exact canonical map containing only the
fixed request domain/version, a receiver-issued 32-byte one-time operation reference, the fixed
Blind provider-governance consumer domain, the requested aggregate evidence profile/version, and a
bounded not-before/expiry window. It contains no provider, claimant, patient, case, claim, source,
credential, URL, path, raw-data, graph, report, root, or digest identity, and it cannot select
source authorization or qualification.

The receiver-issued/randomness/provenance property of operation_ref is external to these bytes.
This boundary enforces only the exact nonzero 32-byte representation and never treats a
caller-provided digest as authorization. The receiving owner must issue and retain one-time
references and own replay consumption.

Provider selection remains an in-memory Mirror access-control decision. The selected current
primary V2 Provider Trust Graph is independently verified before this producer derives a fresh
allowlist-only aggregate: outcome enum, bounded source/coverage/record/finding/discrepancy counts,
and fixed synthetic/nonactivating authority flags. No graph object, source map, identifier, digest,
raw capture, error, credential, URL, path, PHI-shaped value, proof/signature bytes, stable export
identity, or lifecycle fragment is serialized. The export is returned only as bounded canonical
bytes; this module has no persistence, recovery, support, monitoring, logging, delivery, or replay
state.

app/mirror/provider_evidence_export_v1_independent.py is an independently implemented response
verifier. It does not import the producer, graph producer, or their schema constants. It reparses
the exact response grammar, binds the expected operation reference and fixed consumer/profile
domains, checks the current validity window, aggregate consistency, and every enum/range/authority
flag, and returns only an opaque allowlisted projection. Replay consumption is owned by the
receiving Blind governance owner; Mirror receives no Blind state or replay authority. proofSuiteId=null,
production_usable=false, activation=false, and all payment/clearance/economic authority flags
remain fixed.

This contract is a producer boundary, not a live integration or clearance interface. The
repository-local Blind graph schema is incompatible and unregistered; a later Blind governance
consumer must bind this exact contract version and operation reference before admitting evidence.
No claimant identity, public statement, proof handoff, state receipt, outbox, audit, support
artifact, payment, clearance, settlement, adjudication, policy result, or effective directive is
created here.

## Verification and recovery

Each producer boundary has a separately implemented independent parser or database reconstructor.
Canonical bytes, profile/configuration identity, predecessor and head roots, operation identity,
attempt/lease chronology, and exact retry are checked before a derived claim is accepted.
Corruption, omission, reorder, duplication, stale authority, ambiguous publication, or recovery
identity drift fails closed.

Recovery reconciliation precedes throughput optimization. Publication has one owner, preserves the
last known good target on uncertainty, and resolves uncertain outcomes only through independently
verified sanitized state. Recovery can restore the sanitized observation chain and its recorded
verification-at-time receipt; it cannot reverify source bytes or source signatures destroyed at the
source boundary. The owner and its lock/path checks cover the supported local filesystem primitives
only; hostile local administrators, filesystem ACL enforcement, remote/distributed filesystem
semantics, production storage durability/HA, backup/DR, monitoring, RPO/RTO, HSM/FIPS custody, and
state operations remain external qualification dependencies. Synthetic success does not qualify
any of those dependencies.

## External qualification dependencies

Live source authorization, legal terms, authentication, completeness, cadence, failure behavior,
state privacy/support approval, production persistence/custody, monitoring, disaster recovery, and
controlled shadow-pilot authority remain external evidence dependencies. Until they are closed,
`production_usable=false`, activation is false, and all payment, clearance, settlement,
adjudication, and production claims remain false. Mirror has no `proofSuiteId` field and no
private-proof backend dependency; a private-proof profile belongs to Blind Ledger's separate
clearance authority.

`ARCHITECTURE.md` owns Mirror's product role and separation from Blind Ledger. This document owns
Mirror's internal technical boundary. `STATE.md` owns accepted evidence and nonclaims;
`CURRENT_TASK.md` owns only the current bounded work.
