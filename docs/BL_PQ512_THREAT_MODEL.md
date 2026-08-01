# Blind Ledger app-layer repository threat model

Updated: 2026-07-22

Frontier threats are specified in `docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md`: omitted
accesses/conflicts, scheduler equivocation, state-tier rollback, evidence-capsule substitution,
proof/data decoupling, draft-EIP dependency, and attributing Ethereum's classical security to BL-PQ.

## Overview

This repository is a synthetic-only research and application workspace for medical-claim ingestion, fact resolution, policy adjudication, batching, privacy-preserving proof experiments, operator/provider portals, and settlement contracts. The primary product surfaces are the Python application under `app/`, the Rust rules engine under `rules-engine-rust/`, the proving submission and worker controls under `tools/`, the portal assets, and the Solidity settlement boundary under `contracts/`. The Cairo, RISC Zero, and S-two code is currently a mixture of reference, differential, and experimental proof work rather than an approved production proof system.

The intended security outcome is that an authorized claim can change governed state only when the exact adjudication, replay, policy, oracle, and value-conservation rules are authenticated, while no patient or claim-private data becomes public or survives in unauthorized artifacts. The external Privacy V2 application boundary is exactly the ordered 12 fields defined by `ops/native_stark_public_inputs_v2.json`; its count, order, names, types, canonical field encodings, and forbidden-output boundary are trust-critical.

This repository is not production-ready. Wave 1 now seals a complete synthetic fixed-shape
executable claim AIR, but there is no qualified shared-bus Boolean hash coprocessor, independently
reviewed witness-hiding layer, selected strict post-quantum suite, production claim verifier,
authoritative atomic wide state, production KMS/HSM, or end-to-end rollup settlement path. Real PHI
is therefore outside the authorized operating scope.

The active proof threat boundary is heterogeneous: the semantic M31 AIR, hiding committed hash-call
bus, masked Fp16 Boolean GKR SHA3 coprocessor, authenticated public-coin transcript, sidecar, and
atomic verifier must all bind the same session and statement. Cross-module bus substitution,
duplicate/omitted hash calls, byte/bit ambiguity, unmasked GKR messages, partial acceptance, and
reusable detached hash receipts are first-class threats.

## Threat Model, Trust Boundaries, and Assumptions

### Assets and security objectives

The assets that matter are:

- claim contents, member identifiers, diagnoses, prior-authorization data, provider documents, exact decisions, and exact payment amounts;
- correctness and ordering of claim adjudication, denial priority, money arithmetic, payment conservation, and settlement;
- nullifier, duplicate, retry, correction, revision, governed-root, oracle, policy, ruleset, and accumulator state;
- fresh salts, peppers, nonces, witness-encryption keys, wrapping keys, authorization keys, governance keys, and future post-quantum key material;
- the exact proof statement, schema, profile, verifier artifact, 12-field ABI, proof sidecar, and cross-language encodings;
- audit evidence, operational manifests, source and dependency pins, release allowlists, and rollback history;
- service availability without exposing private differences through timing, queue shape, retries, errors, proof shape, or resource use.

The repository must preserve these invariants:

1. No unverified, caller-supplied, stale, replayed, noncanonical, differently ordered, truncated, normalized, or modulo-repaired value may advance authoritative state.
2. Python, Rust, Cairo, RISC/reference models, the selected AIR, verifier, and settlement boundary must agree exactly on every applicable byte, root, decision, amount, commitment, rejection reason, and state transition.
3. Every real attempt and every cover slot must have the required domain-separated nullifier behavior; approval, denial, and padding must not create distinguishable public state or proof shapes.
4. Proofs must authenticate the exact governed sources, policy, oracle facts, schema, profile, verifier artifact, prior state, next state, and value conservation before any atomic update.
5. Public outputs, chain data, proofs, queues, logs, crashes, backups, and release artifacts must not reveal PHI or private decisions/amounts. Encrypted private records remain outside public data availability.
6. Development fallbacks, synthetic attestations, mock verifiers, local KMS simulation, and unverified settlement paths must fail closed in production.
7. Strict post-quantum claims require the authenticated wide state, proof metadata, transcript, commitment scheme, query parameters, signatures, and key-establishment surfaces—not merely twelve approximately 251-bit compatibility values.
8. Release output must come from an exact reviewed allowlist, be deterministically rebuilt and read back, exclude generated/proof/private artifacts, and preserve source/verifier/ops pins.

### Actors and trust boundaries

- **External provider or submitter.** Controls claim payloads, X12-like input, portal request bodies, attachment names and bytes, provider messages, batch submissions, and potentially malformed or adversarial encodings. This actor is not trusted to state eligibility, enrollment, authorization, fee, duplicate, or integrity facts.
- **Portal caller.** Controls HTTP headers, bearer tokens, path parameters, object identifiers, and JSON bodies exposed by `app/operator_portal.py`. Authentication, role enforcement, provider-tenant isolation, attachment access, output encoding, and rate/resource controls form a trust boundary.
- **Government operator, administrator, auditor, and governance signer.** Controls approved environment configuration, roots, manifests, submitter enrollment, policy artifacts, and operational actions. These roles are privileged but must remain separated and auditable; one compromised role must not silently become proof authority, KMS authority, and settlement authority.
- **Official fact and policy sources.** Connector results and oracle attestations cross from external administrative systems into the adjudication witness. They must be authenticated, source-identified, temporally valid, and bound to governed roots rather than accepted because a caller supplied plausible facts.
- **Rules and encoding boundary.** Python orchestration crosses into the Rust rules engine and into canonical field, money, Merkle, Poseidon, and claim-source encodings. Subprocess I/O, JSON parsing, error handling, and fallback selection are security boundaries.
- **Proving and custody boundary.** Encrypted witness envelopes cross into the queue and isolated proving worker in `tools/proving_submission.py`, `tools/proving_job_runner.py`, and `tools/isolated_proving_worker.py`. Authentication, path identity, key unwrap, plaintext lifetime, RAM staging, cleanup, crash behavior, and process isolation are critical. The local KMS simulator is not trusted for production.
- **Proof/verifier boundary.** Private witness execution crosses into a proof, exact public statement, verifier, and state update. The present S-two prototype is validity-only and the settlement tests use mocks; neither is a trusted production boundary.
- **Settlement boundary.** Public calldata and contract calls are attacker-visible and may be attacker-submitted. `StarkBatchSettlementV2.sol` relies on authorized submitters, canonical fields, governed roots, replay protection, schema/artifact pins, and a real verifier that does not yet exist in this repository.
- **Developer, build, dependency, and release boundary.** Source changes, vendored S-two, compiler/toolchain selection, Python dependencies, build caches, test fixtures, manifests, rollback copies, and release packaging are developer-controlled inputs. A compromised dependency or stale pin can invalidate all higher-level evidence.

### Assumptions

Real PHI, real production keys, real government signer enrollment, and real payment authority are absent from this workspace. Tests and examples are expected to be synthetic. Future production is assumed to provide independently administered KMS/HSM custody, authenticated official data sources, reviewed deployment isolation, and independent cryptographic and implementation audits; the repository does not currently supply those assurances.

Environment variables, policy/root manifests, and toolchain selection are operator/developer-controlled rather than attacker-controlled in a correctly deployed system. Findings that require an already-compromised build host or all governance/KMS administrators remain relevant to defense in depth but are calibrated below an unauthenticated remote path to the same outcome unless they defeat an intended separation-of-duties control.

The Ethereum/rollup implementation is incomplete and is not treated as a mitigating security boundary. Prototype, test, documentation, and reference-only code does not become production evidence merely because its tests pass.

## Attack Surface, Mitigations, and Attacker Stories

Frontier implementations must reject a prover omitting a state page/conflict from CBAM; a scheduler
reordering conflicting retries; resurrection of an unauthenticated cold root; normalization of
different source bytes to one evidence capsule; acceptance of unavailable proof data; or activation
of an unfinished native-rollup path. Required controls are fixed-capacity manifests, independent
reconstruction, deterministic DAGs, versioned migrations, exact-byte/stream commitments,
reconstruction tests, and fail-closed settlement modes.

### Claim ingestion, canonicalization, and adjudication

Adversarial claims can target X12 parsing, Unicode/text normalization, duplicate keys, length/count bounds, money rounding, service-line ordering, ambiguous encodings, missing evidence, and first-failure priority. A realistic attacker story is a provider crafting two representations that Python, Rust, Cairo, or settlement interpret differently, thereby changing approval, payment, nullifier identity, or roots.

Existing controls include explicit canonical encoders, field bounds, structured money parsing, source-root membership checks, denial-order tests, and cross-language known-answer tests. The highest-risk residual class is any parser or semantic path that accepts alternate encodings or silently falls back to a weaker rules implementation.

### Portal, authorization, and tenant isolation

The FastAPI portal exposes readiness, batch, review, audit, provider packet, message, attachment, action, and reset endpoints. Realistic attacks include stolen or guessed local tokens used outside development, missing role checks, provider cross-tenant object access, attachment path traversal, unsafe content serving, stored or reflected script injection, CSRF when browser credentials are introduced, excessive upload/resource consumption, and sensitive error or audit responses.

The code uses per-principal token configuration, constant-time token comparison, role checks, and provider identity comparisons. Production must not use local example tokens, and every object lookup and file response must independently enforce tenant ownership and safe resolved paths.

### Fact sources, policy, governance, and replay state

An attacker may fabricate eligibility, enrollment, fee, prior-authorization, duplicate, or integrity facts; use a stale governed root; forge nonmembership; reorder operations; replay a batch; or exploit a partial state update. Root membership alone is insufficient if the root is not governed, fresh, source-authenticated, and tied to the same raw records and operation sequence used by the wide post-quantum state.

Existing controls include governed-root checks, nullifier transitions, attempt lifecycle checks, signer thresholds/timelocks in the V1 contract, artifact/schema pins, nonce consumption, and extensive negative tests. Production requires atomic legacy/wide state advancement and recovery/migration semantics that are still open.

### Proving, witness privacy, and cryptographic soundness

Relevant attacks include unconstrained witness values, incomplete AIR coverage, malformed or malleable proof parsing, transcript/domain confusion, reused masking randomness, insufficient FRI/query parameters, deterministic or linkable proofs, trace/proof shape leakage, denial/timing leakage, and a verifier authenticating fewer values than settlement consumes.

The 12-field V2 boundary removes direct public amounts/counts, but commitments alone do not hide a witness. The custom S-two prototype demonstrates a narrow fast validity proof only; current S-two lacks the required witness hiding. The selected native hiding and BL-PQ512 profile require formal analysis and independent review. RISC Zero and Cairo remain semantic oracles, not production-performance or end-to-end privacy evidence.

### Key custody, queues, processes, and artifacts

Envelope parsers, queue records, filesystem paths, subprocess arguments, RAM files, cleanup handlers, crash dumps, swap, backups, logs, and retained build/proof artifacts can disclose plaintext or enable substitution. RSA wrapping and P-256/Ed25519-class authorization surfaces are classical and prevent an end-to-end post-quantum claim.

Existing controls reject plaintext witness queues in production mode, authenticate principal/agency/count bindings, validate envelope encodings, isolate decryption in a worker, stage sensitive arguments in RAM where supported, scan artifacts fail closed, and block unauthenticated encrypted envelopes from release. Production still needs an approved hybrid PQ KEM, HSM-backed authorization, constant-time/no-co-tenant operations, and reviewed destruction/recovery controls.

### Settlement, verifier, and release integrity

An attacker can submit malformed public fields, replay nonces, race prior state, substitute governed roots, swap verifier artifacts, deploy a test verifier, exploit mock behavior, or package stale/unreviewed source and generated artifacts. Existing V2 contract checks reject noncanonical fields, unauthorized submitters, stale/unchanged roots, replayed nonces, test verifiers, and schema/artifact drift.

There is no production `IBlindLedgerClaimVerifierV2` implementation here, and current Solidity tests cannot establish proof soundness. The deterministic exact-allowlist archive builder, mirrored ops files, hash pins, privacy scanner, no-clobber publication, and readback checks mitigate release substitution, but release remains blocked without a reviewed V2 manifest and clean staging tree.

### Availability and side channels

Oversized claims, deep trees, proof jobs, repeated submissions, parser bombs, expensive malformed proofs, queue flooding, and toolchain subprocess hangs can exhaust CPU, memory, disk, or worker slots. Even when data remains encrypted, timing, proof bytes, batch cadence, retry behavior, root equality, and error distinctions may reveal witness class.

Bounds, fixed-shape design goals, timeout-aware worker logic, fixed-capacity campaigns, and measured gates provide partial mitigation. Fixed cadence, cover traffic, uniform failures, production rate limits, queue isolation, and side-channel review remain open.

## Severity Calibration (Critical, High, Medium, Low)

### Critical

Critical issues plausibly allow unauthenticated or low-privilege attackers to expose real PHI at scale, recover production key material, forge a proof or bypass the verifier to advance authoritative settlement/payment state, defeat nullifier/replay protection across the system, or ship a release containing plaintext witnesses while all intended gates report success. A complete AIR/verifier soundness failure or remote compromise of the production KMS/prover boundary is critical.

### High

High issues include cross-provider or cross-agency claim access, authorization bypass on privileged batch/governance actions, fabricated policy/oracle facts that change adjudication, independently exploitable stale-root or partial-update paths, persistent PHI leakage in logs/crash/queue artifacts, verifier/schema/artifact substitution requiring some operational foothold, or a malicious dependency/build input that reaches a production release.

### Medium

Medium issues include bounded denial of service, limited metadata or timing disclosure that does not reveal claim contents, sensitive path or configuration disclosure without a direct follow-on compromise, one-user object leakage with strong preconditions, or a production hardening gap that violates defense in depth but cannot change adjudication or settlement under the documented deployment assumptions.

### Low

Low issues include developer-only or synthetic-only weaknesses that are provably unreachable in production, non-sensitive version or diagnostics disclosure, low-impact UI hardening gaps, and maintainability problems with no demonstrated confidentiality, integrity, authorization, or availability impact. Open architectural blockers are not mislabeled as exploitable findings unless a current runtime path incorrectly presents them as safe or production-capable.

Repository: target_sha256_d77e640ac3f4e6013bf9ef4b711a8d6f94e4f70f03b78efebd06f2473045db10
Version: codex-security-snapshot/v1:sha256:382c02a9a9890251f167f3e28023ae4a2caf67c28ee24075a69b587bb6b9b20e

