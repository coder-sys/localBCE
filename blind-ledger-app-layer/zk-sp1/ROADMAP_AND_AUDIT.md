# Roadmap And Audit Gates

Status: not code-complete, not production-secure, PENDING CRYPTOGRAPHIC AUDIT.

## Real Oracle Data-Source Access And Signed Feeds

What it is: signed attestations for eligibility, provider enrollment, provider suspension status, prior authorization, and not-deceased checks from authoritative sources such as CA-MMIS, death master file access, suspended-provider lists, and payer/provider systems.

Why it is not a tonight code task: credentials, data-sharing agreements, source-specific schemas, legal review, uptime/SLA design, key custody, and audit logging are external access and governance work.

What it needs: source contracts or credentials, signing keys or HSM-backed attestations, replay protection, validity windows, revocation handling, and a canonical attestation schema bound into the proof inputs.

Severity: critical. Without this, the proof can prove unverified submitter assertions.

## In-Circuit Payment-Sum Reconciliation And Multi-Claim Linkage

What it is: the production proof must enforce that each provider net payment equals the sum of approved payable amounts, and that every approved claim/nullifier in the batch is covered by the multi-claim transition with distinctness and insert-chain linkage.

Why it is not a tonight code task: it changes the proof statement and requires circuit/AIR design, witness generation, public-input schema updates, verifier generation, and external ZK review.

What it needs: audited batch circuit/zkVM program, exact public inputs for claim root/result root/payment root/nullifier roots, test vectors for tampered sums and duplicate/nullifier attacks, and verifier integration.

Severity: critical. App-layer reconciliation is now enforced before payment leaf construction, but proof-level enforcement remains the load-bearing production requirement.

## Hardened Off-Chain Proving Enclave

What it is: the environment that builds witnesses, generates proofs, protects oracle/prover keys, and relays accepted batches.

Why it is not a tonight code task: it is infrastructure, key custody, monitoring, host hardening, incident response, and operations work.

What it needs: isolated prover hosts, signed builds, hardware-backed keys, auditable logs, least-privilege relayer credentials, disaster recovery, and change-control around prover/verifier updates.

Severity: high. A compromised prover or relayer can feed false inputs or block valid batches even if the verifier is correct.

## Provider Authentication

What it is: strong authentication and authorization for provider submissions, delegated billing agents, and payment-destination changes.

Why it is not a tonight code task: it requires identity proofing, provider enrollment workflows, admin recovery policy, and integration with real payer/provider systems.

What it needs: MFA, role/organization binding, payment-destination approval workflow, audit trail, fraud-monitoring hooks, and revocation.

Severity: high. Crypto settlement integrity does not help if the submitter identity or payout endpoint is compromised.

## Full SP1 Proving Under WSL/Linux

What it is: generating real SP1 proofs and wrapped EVM proofs for the adjudication guest.

Why it is not a tonight code task: the native Windows path is blocked by missing `protoc` and Unix-specific SP1 prover/JIT dependencies. The proving path should run in WSL/Linux with the protobuf compiler installed.

What it needs: WSL/Linux build, Rust/SP1 toolchain, `protoc`, RAM headroom, proof generation/verification logs, and measured verifier gas if using the EVM wrapper.

Severity: medium-high for the SP1 path. The existing guest/lib tests are useful, but they are not a substitute for real proof generation.

## Trusted-Setup Ceremony

What it is: the production Groth16 setup process for any Groth16 circuit kept on the production path.

Why it is not a tonight code task: a trusted setup is a human ceremony with multiple participants, transcript publication, and verification. It cannot be faked by generating local zkeys.

What it needs: follow `zk/TRUSTED_SETUP_CEREMONY_PLAN.md`, freeze audited circuits, collect independent contributions, publish transcript, and verify final parameters.

Severity: critical if Groth16 remains in production. If the design commits to a transparent STARK path instead, this gate can be removed for that path.
