# Wave 4 adapters and operations

Updated: 2026-08-05

Status: internal engineering boundary complete and nonactivating. This document defines the
implementation contract for I01-I08 and O01-O06/O12. It does not select `proofSuiteId`, authorize
live endpoints, enroll operators, validate an HSM/FIPS module, or permit real PHI or payments.

## Boundary

Wave 4 is the provider/oracle and operational boundary. It is deliberately separate from the
containing rollup: R01-R12 remain Wave 5. It is also separate from the protected claim/state
producer and settlement paths. The Wave 4 source is:

- `app/wave4_adapters.py`: versioned provider-neutral SDK, dual-PQ provenance capsules, local
  transport/credential simulators, immutable synthetic fixtures, retries, circuit breaking,
  idempotency, replay/downgrade rejection, and the shared conformance runner;
- `app/wave4_operations.py`: isolated profiles, ML-KEM/AES-256 reference custody, key roots and
  lifecycle, entropy/zeroization/nonce controls, append-only non-PHI audit, fixed-cadence bounded
  queue, incident pause/recovery drill, and reproducible release manifest;
- `tools/wave4_conformance.py`: one offline command that exercises the complete local boundary;
- `ops/wave4_release_profile.json` and `ops/wave4_sandbox_config.json`: machine-readable
  nonactivating profile and package closure;
- `ops/monitoring_events.json`: current non-PHI monitoring inventory.

The older `app/connectors/*` helpers, `tools/local_kms_simulator.py`, and legacy proof/settlement
paths remain historical or narrow reference code. They are not silently promoted into this
boundary and are not release fallbacks.

## Adapter contract

Every adapter declares provider, adapter version, schema version, normalization version,
jurisdiction, capability, endpoint/tenant identity, and the fixed dual-PQ profile
`ML-DSA-87 + SLH-DSA-SHAKE-256f`. A request carries only opaque commitments, a bounded epoch,
deadline, and idempotency key; the local fixture lookup key is intentionally excluded from its
canonical bytes.

The response has two views:

1. private in-memory facts for the claim/rules boundary; and
2. a public `EvidenceCapsule` binding the request commitment, exact source-byte or stream hash,
   source epoch, freshness window, completeness/absence evidence, versions, idempotency key,
   audit-safe error class, authority identity, and exactly one signature from each approved PQ
   suite.

The public capsule has no raw source bytes, PHI, medical record, claim document, exact private
amount, private decision, ciphertext, credential, or caller-supplied substitute fact. Missing,
stale, expired, malformed, and replayed sources are signed fail-closed absence/error results; an
adapter never falls back to caller data or a local rules substitute.

The registry rejects unknown capabilities, duplicate identities, unsupported versions, and
downgrades. Version migration is an explicit successor operation over the old and new identity
bytes. Retry is bounded and applies only to explicit transient failures. Idempotent retries return
the identical signed capsule; a conflicting reuse of the idempotency key is rejected. The circuit
breaker opens after the configured failure count and requires a bounded cooldown.

The synthetic registry covers all I02-I07 capabilities: identity, tenant, authorization, transport,
credential, claim source, attachment, eligibility, coverage, enrollment, provider status, prior
authorization, diagnosis/procedure, document fact, fee schedule, policy, ruleset, governed root,
payment, treasury, remittance, and reconciliation. I01 is the SDK/isolation declaration and I08 is
the shared conformance/chaos/retry/migration suite.

## Operations contract

O01 provides a provider-neutral KMS/KEM port plus a software ML-KEM-1024/AES-256-GCM reference.
The reference is explicitly `software_only=true`, `hsm_backed=false`, `fips_validated=false`, and
`production_usable=false`; it is a qualification provider, not a production authority. O02 keeps
only root digests and lifecycle metadata, checks entropy and nonce reuse, and zeroizes owned
mutable buffers. O03 rejects network access, live credentials, swap, and core dumps in the
Wave 4 sandbox while retaining the 5,000,000,000-byte resident limit and strictly-below-
5,000,000,000-byte scratch limit.

O04 uses an append-only SHA3-512 audit chain with a strict non-PHI metadata allowlist. O05 emits a
fixed number of slots at every tick, fills unused slots with opaque cover commitments, bounds the
queue, and exposes one public rejection class. O06 provides pause, recovery, resume, and rollback
checkpoint binding plus a synthetic drill. O12 hashes an explicit source allowlist, rejects
generated/secret paths, and produces deterministic release evidence with `production_usable=false`
and `proofSuiteId=null`.

## Verification

From the repository root:

```text
py -3.14 -B -m pytest -q tests/test_wave4_adapters_operations.py
py -3.14 -B tools/wave4_conformance.py --repo-root .
```

The command is offline, creates no repository artifact, and must report
`network_access=false`, `live_credentials=false`, `activation_allowed=false`,
`proofSuiteId=null`, zero adapter failures, and successful operations/release checks.

## Remaining boundary

Wave 4 is internally complete only in the synthetic/sandbox sense. Live provider URLs, tenant
credentials, oracle signer enrollment, HSM/FIPS handles, governance identities, payment accounts,
legal authority, the selected proof suite, production verifier/state acceptance, the based
rollup, the final release-candidate seal, and the independent Security Audit Gate remain open.
They cannot be closed by changing a fixture, a JSON flag, or a test double.
