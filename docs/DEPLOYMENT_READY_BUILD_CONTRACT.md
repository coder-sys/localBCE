# Blind Ledger deployment-ready build contract

Updated: 2026-08-05

The frontier additions in `docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` are internal work
inside the existing 93 packages. They do not create a new external dependency, change the count, or
permit a draft Ethereum feature to block the pinned release path.

`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md` makes the based-validity decision
compulsory and assigns the complete live-map compatibility surface to R01-R12. The pinned release
baseline must remain deployable without any unshipped EIP; future fork adapters are internal
engineering, versioned, rejected by default, and fail closed.
Inherited L1 features still require fork-aware conformance before receiving benefit credit;
L1-COMPAT and L2-PARITY changes require direct implementation; OPTIONAL/RESEARCH features remain
disabled. The manifest-bound lifecycle and 23 activation triggers are part of R01-R12 completion.

The committed sparse-state and PQ commitment bake-off in
`docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md` is likewise internal work inside existing packages.
It creates no upstream-author, external-prover, hardware-service, or outside-engineer dependency.
Engineering must implement and measure the admitted candidates even when the first versions are
inefficient; inefficiency is recorded as candidate evidence, not used to skip the gate.

Status: authoritative boundary between internal engineering completion, independent security
assurance, and operator activation.

Current proof checkpoint: the H4 prototype passes one fresh K128/K512 attempt through independent
verification in 29.974129/120.460733 seconds. Gate 2E is sealed nonactivating, H5 passed the exact
22-launch p95/resource campaign, and H6 closed the twelve bounded candidate-evidence obligations.
This is still not `BUILT_AUDIT_PENDING`: the production verifier/state/custody, whole-product
release evidence, and final audit remain open. Wave 4 adapters/operations and Wave 5 R01-R12
containing-rollup engineering are complete only as local/synthetic, nonactivating boundaries.
`proofSuiteId=null`, `production_usable=false`, and the ban on real PHI/payments remain authoritative.

## Product objective

Blind Ledger engineering must be able to produce a complete, reproducible, technically deployable
release candidate without relying on an outside person or organization to design, implement, test,
integrate, or package any part of the product. The build optimizes for, in order:

1. correctness, privacy, and fail-closed security;
2. post-quantum security at every Blind Ledger-controlled trust boundary;
3. maximum throughput within those security constraints;
4. complete auditability and reproducible evidence;
5. modular replacement of proof, state, custody, rollup, government-API, and oracle components.

For the current proof wave, the reference deployment envelope forbids the retired 554-951 GB
direct-SHA3-STARK layouts. The primary implementation must pass no-swap limits of
no more than 5,000,000,000 peak resident bytes and strictly below 5,000,000,000 scratch bytes on
the measured Dell G15 5535,
then compete on the complete safe throughput frontier. The limits may be tightened by measurement;
they may not be raised merely to preserve a failed architecture. The controlling contract is
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`.

The only external assurance dependency is one final independent Security Audit Gate. Live service
credentials, government endpoints, governance signers, payment accounts, and legal authorization
are operator-supplied activation inputs. They are not missing engineering and do not prevent the
release candidate from being built and exercised against local and sandbox implementations.

The six numbered roadmap waves are internal engineering milestones. The independent audit is not a
seventh wave and cannot be used to defer design, implementation, parameter selection, performance
qualification, adapters, rollup work, deployment automation, or release evidence.

Wave 2 must close all six proof gates, including committed sparse-state/PQ-commitment selection and
the subsequent complete K128/K512 proof. A non-Merkle state selection remains nonactivating until
its versioned SHA3-512 identifier, state-equivalence proof, migration/rollback/reorganization
behavior, native hiding, strict-PQ ledger, and independent verifier all qualify.

“Maximum throughput” means the highest measured steady-state claims per second on the feasible
frontier after security, privacy, correctness, auditability, modularity, workload, reference
hardware, resource/latency envelopes, and benchmark-variance rules are frozen. Engineering must
measure every plausible safe candidate that attacks a dominant cost center, retain the rejected
alternatives and evidence, discard dominated designs, and select the highest-throughput feasible
point. It does not mean the first implementation that passes or a microbenchmark detached from a
complete fixed batch.

## The three boundaries

### 1. Internal engineering completion

Every counted roadmap package is finishable inside the repository by the Blind Ledger engineering
team. This includes the complete claim proof, native witness hiding, strict-PQ construction,
authoritative state, real verifier, based rollup, bridge/finality path, deployment automation,
government/oracle adapter framework, simulators, conformance tests, monitoring, rollback, and
reproducible release evidence.

An open-source theorem, paper, library, or upstream implementation may be used only as a pinned and
reviewed input. Its authors are not required to perform Blind Ledger engineering. If an upstream
primitive is unsuitable, the package remains an internal implementation or replacement task.

### 2. Final independent Security Audit Gate

After internal engineering completion, one independent audit reviews five workstreams:

1. AIR completeness and soundness;
2. witness hiding, FRI masking, authenticated interactive public coin, proof that launch security
   does not depend on Fiat-Shamir/QROM, and strict-PQ analysis;
3. SHA3-512 state, dual-root binding, signatures, KEMs, and parameter budgets;
4. implementation, parsers, verifier, contracts, rollup, bridge, and supply chain;
5. privacy, side channels, custody, operations, and the synthetic adversarial pilot.

These workstreams are one audit gate, are not roadmap packages, and contribute nothing to the
engineering completion denominator. Audit findings return to the owning internal package and must
be fixed and requalified. The gate passes only when all critical and high findings are closed or
formally accepted under the audit policy and every affected artifact is resealed.

### 3. Operator activation

Production activation supplies deployment-specific values through documented, versioned
configuration:

- government API base URLs, versions, tenant identifiers, and credentials;
- oracle source identities, signing keys, epochs, and governed roots;
- KMS/HSM provider coordinates and authorized key handles;
- governance signers, timelocks, chain IDs, contract addresses, and fee settings;
- payment/treasury endpoints and jurisdiction-specific authorization.

The release candidate must reject absent, placeholder, stale, unsupported, or downgraded values.
It must ship local reference providers, sandbox adapters, synthetic fixtures, and conformance tests
so that engineering completion and end-to-end deployment rehearsal do not depend on live access.
Activation is configuration and authorization, not unfinished product development.

## Deployment-ready candidate definition

The roadmap may label a build `DEPLOYMENT_READY_AUDIT_PENDING` only when all counted packages are
complete and terminal evidence proves all of the following:

- the complete fixed-shape claim relation and ordered 12-field compatibility ABI are implemented;
- native witness hiding and the selected strict-PQ proof suite are implemented and fail closed;
- no Blind Ledger-controlled authority relies on RSA, ECDSA, Ed25519, a 256-bit collision-binding
  commitment, or a non-PQ wrapper; any unavoidable external-chain classical boundary is explicitly
  isolated, never counted toward the Blind Ledger PQ claim, and protected by the authoritative
  strict-PQ application state;
- authoritative SHA3-512 state, canonical sidecar, real verifier, and atomic settlement exist;
- the based validity-rollup, data availability, L1 settlement, bridge, forced inclusion, safe exit,
  reorganization, upgrade, and recovery paths work end to end;
- every government/oracle/payment integration uses a versioned adapter contract with a local
  simulator, sandbox conformance suite, authenticated provenance, timeout/retry/idempotency policy,
  and immutable non-PHI audit events;
- no mock, development fallback, test key, caller-supplied proof result, or unpinned parameter can
  enter a release trust boundary;
- supported builds are offline, locked, reproducible, SBOM-complete, and independently readable
  from a release allowlist;
- containers, infrastructure-as-code, configuration schema, secret injection, monitoring, alerts,
  incident response, backup, restore, rollback, and one-command synthetic/sandbox deployment are
  present and tested;
- throughput, memory, scratch, I/O, proof size, verifier cost, queue capacity, and fixed-cadence
  limits have measured acceptance thresholds; the selected design is the highest-throughput
  feasible measured point under the frozen constraints, with no security or privacy gate weakened;
- the audit packet contains exact source, toolchain, dependency, proof-suite, schema, verifier,
  contract, image, infrastructure, test, and artifact identities plus raw terminal evidence.

At this state, `production_usable` remains `false`, real PHI and real payments remain forbidden, and
the release is not represented as independently audited. If the audit passes without findings that
require code changes, promotion consists only of selecting the audited release identity and
supplying authorized activation configuration.

## Proof-suite lifecycle

| State | Meaning | Activation |
| --- | --- | --- |
| `UNSELECTED` | No production suite has satisfied the full S07-S09 and release-selection boundary; `proofSuiteId` is null. This remains the current state even though nonactivating H4/H5/H6 candidate evidence exists. | Forbidden |
| `BUILT_AUDIT_PENDING` | Engineering selected, implemented, pinned, and internally qualified the exact suite. | Release-candidate testing only; `production_usable=false` |
| `AUDIT_ACCEPTED` | The independent audit accepted the exact suite and release identities. | Eligible for authorized operator activation |

Internal suite selection is a trust-critical engineering decision with explicit proofs, constants,
code, vectors, and adversarial evidence. It does not require an external reviewer to write or choose
the implementation. Independent reviewers validate the completed result at the final audit gate.

## Government API and oracle module contract

External-system integration is port-and-adapter based. Core claim semantics consume canonical,
signed, source-identified records and never vendor-specific response objects. Each adapter must:

- emit a canonical proof-carrying evidence capsule binding exact bytes or streaming hash,
  schema/normalization version, endpoint/tenant, freshness/epoch, dual-PQ authority,
  completeness/absence evidence, idempotency, and an audit-safe error class;

- declare provider, API version, schema version, jurisdiction, capability, and cryptographic profile;
- map exact source bytes into the canonical record with deterministic normalization and provenance;
- authenticate transport and payload signatures and bind source, signer, epoch, freshness, and root;
- enforce bounded input, timeouts, retries with jitter, idempotency, replay rejection, circuit
  breaking, and fail-closed behavior;
- emit immutable, correlation-safe, non-PHI audit events and measurable health signals;
- pass the shared contract suite plus recorded synthetic/sandbox fixtures;
- support parallel versioning so a new government endpoint or oracle can be added without changing
  the AIR, verifier, settlement, or unrelated adapters.

No adapter may silently fall back to caller-supplied facts, a local rules substitute, an older API,
or a weaker cryptographic profile.

FHIR R4, US Core, Bulk Data, PAS, PDex, CRD, DTR, and any X12 bridge are versioned profiles over the
provider-neutral port. They do not become AIR semantics or outside build dependencies.

## Claim and release language

Before the audit gate passes, permitted language is “technically deployment-ready, audit-pending
release candidate” only after every counted package actually closes. “Production ready,”
“production approved,” “audited,” “safe for real PHI,” and “authorized for real payments” remain
forbidden until their corresponding audit and operator-authorization conditions are met.
Every live adapter profile must produce a canonical proof-carrying evidence capsule binding exact
bytes/stream hash, schema and normalization version, endpoint/tenant, freshness/epoch, PQ authority,
completeness/absence evidence, idempotency, and an audit-safe error. FHIR/PAS/PDex/CRD/DTR are
versioned profiles over the provider-neutral port, not hard-coded product dependencies.
