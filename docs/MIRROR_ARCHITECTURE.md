# Mirror architecture

Updated: 2026-08-24
Status: synthetic, read-only, nonactivating architecture candidate
Owner: Mirror source trust, evidence custody, reconciliation, and recovery boundary

Mirror is RightRail's read-only evidence, reconciliation, and operational-continuity product.
Provider Trust Graph is its current narrow first wedge, not the whole product. Mirror never
adjudicates a claim, issues a Blind Ledger directive, moves money, or converts observed incumbent
behavior into approved state policy.

## Smallest current boundary

```text
authorized source adapter
        |
        v
Ingress V2 -- one bounded raw intake frame owner
        |
        v
Core V3 ---- derived graph, reconciliation, and case state
        |
        v
Recovery V2 - explicit export, restore, and publication recovery points
```

Ingress owns acquisition schedule, leases, attempts, exact source/evidence pairing, quarantine,
and the sole durable raw intake frame. Core owns independently reconstructed derived artifacts,
events, heads, reconciliation, and case progression. Recovery owns encrypted bundle identity,
key/storage binding, restore, and explicit publication recovery. No layer may create a second raw
capture owner or mutate another layer's tables.

The current consolidated stores have exactly five Ingress tables, six Core tables, and three
Recovery tables. These counts are current executable grammar, not a permanent product metric;
changing them requires an ownership or recovery need, a versioned migration, and independent
reconstruction evidence.

## Source and privacy boundary

The current North Carolina FHIR profile is synthetic-only. It accepts only the exact registered
canonical Practitioner, PractitionerRole, and Location fixture resources, including one registered
changed Location. The independent verifier rejects all other resource bytes before Ingress opens a
write transaction. Credential graph identity binds the verified Practitioner bytes; enrollment
identity binds the verified PractitionerRole and Location bytes.

The complete intake frame is capped at 262,144 bytes. Raw source captures, credentials, host paths,
errors, stdout/stderr, and stable real-person or real-provider fingerprints may not enter support,
monitoring, analytics, AI, receipts, or exports. Public failures use fixed codes. A rejected capture
must leave database bytes, logical export, support output, and durable state unchanged.

## Verification and recovery

Each producer boundary has a separately implemented independent parser or database reconstructor.
Canonical bytes, profile/configuration identity, predecessor and head roots, operation identity,
attempt/lease chronology, and exact retry are checked before a derived claim is accepted.
Corruption, omission, reorder, duplication, stale authority, ambiguous publication, or recovery
identity drift fails closed.

Recovery precedes throughput optimization. Publication has one owner, preserves the last known
good target on uncertainty, and resolves uncertain outcomes only through independently verified
state. Synthetic success does not qualify production storage, HA, backup/DR, monitoring, RPO/RTO,
HSM/FIPS custody, or state operations.

## External qualification dependencies

Live source authorization, legal terms, authentication, completeness, cadence, failure behavior,
state privacy/support approval, production persistence/custody, monitoring, disaster recovery, and
controlled shadow-pilot authority remain external evidence dependencies. Until they are closed,
`proofSuiteId=null`, `production_usable=false`, activation is false, and all payment, clearance,
settlement, adjudication, and production claims remain false.

`ARCHITECTURE.md` owns Mirror's product role and separation from Blind Ledger. This document owns
Mirror's internal technical boundary. `STATE.md` owns accepted evidence and nonclaims;
`CURRENT_TASK.md` owns only the current bounded work.
