# Audit And Build Spec

Status: SPEC ONLY. This document does not claim production security. The ceiling is soundness-checked where locally tested, PENDING CRYPTO AUDIT.

## Unified Binding Circuit

What it is: one production proof statement that binds claim roots, result roots, payment roots, nullifier transitions, ruleset roots, fee-schedule lookup, padding rules, and per-claim positional indexes into a single non-malleable public input layout.

Why not tonight's code: the existing Groth16 claim circuit and Winterfell/SP1 experiments do not contain this full batch statement. Building it requires a new circuit/AIR/zkVM program, witness generator, public-input schema, verifier, and audit.

What it needs: public inputs for claimRoot, resultRoot, paymentRoot, nullifierRootBefore, nullifierRootAfter, rulesetRoot, feeScheduleRoot, batchCommitment, claimCount, paymentCount, and verifier key id. Per-claim constraints must enforce claim leaf to result leaf consistency, approved result to payment sum consistency, denied result to zero payment, duplicate nullifier consumption, padding inertness, index bounds, and fee schedule inclusion bound to procedure code and service date.

Severity: critical. Without this, app-side checks can be correct while the proof statement remains under-bound.

## Per-Member And Per-Period Accumulators

What it is: cumulative state beside the nullifier tree for caps, deductibles, visit limits, unit limits, and prior authorization consumption.

Why not tonight's code: these are state machines, not one-claim predicates. They need domain policy, update ordering, replay rules, and migration strategy.

What it needs: accumulator roots per member and benefit period, update proofs, prior-auth nullifier domains, state snapshots, appeal/audit reconstruction, and Medi-Cal policy review.

Severity: critical for real claims. Single-claim gates cannot enforce cumulative limits.

## From-Genesis Migration

What it is: when the real binding circuit ships, rebuild the nullifier and accumulator trees from canonical genesis and re-prove transitions from the first accepted production batch.

Why not tonight's code: the final circuit does not exist yet, and migration must be rehearsed with the exact production schema.

What it needs: frozen genesis constants, replayable batch log, deterministic witness builder, migration proof, rollback plan, and external audit.

Severity: high. A bad migration can strand or corrupt duplicate-prevention state.

## Bridge Finality And Idempotency

What it is: payment and L2 bridge operations must wait for finality, retry safely, and never double-submit on reorgs, network retries, or relayer restarts.

Why not tonight's code: this depends on the selected L2, bridge, payment provider, operational runbooks, and finality assumptions.

What it needs: idempotency keys, finality thresholds, retry store, reconciliation job, alerting, manual repair playbook, and partner/provider API behavior.

Severity: high. Correct proofs do not prevent operational double payment.

## Root-Contention Lease

What it is: an off-chain lease so multiple builders do not race against the same current root and waste work or create stale submissions.

Why not tonight's code: local locking exists, but distributed builders need durable coordination.

What it needs: lease service, timeout policy, signed builder identity, abandoned-lease recovery, and chain-state reconciliation.

Severity: medium-high. The contract rejects stale roots, but without leases the system can thrash.

## Temporal And Effective-Dated Rulesets

What it is: the proof must bind the service date to the correct ruleset, fee schedule, provider status, eligibility status, and authorization status effective on that date.

Why not tonight's code: it requires policy data, effective-date modeling, source attestations, and domain review.

What it needs: ruleset timeline root, effective-date inclusion proofs, service-date range checks, transition policy, and Medi-Cal legal review.

Severity: critical for regulatory correctness.

## In-Circuit Asymmetric Oracle Verification

What it is: eligibility, enrollment, suspension, death, prior-auth, and fee schedule facts verified inside the proof against pinned public keys or threshold signatures.

Why not tonight's code: the current Ed25519 module is an app-layer interface only. It does not verify signatures inside Groth16, STARK, or SP1 proofs, and it does not connect to real feeds.

What it needs: real oracle feeds, HSM custody, threshold signing policy, key rotation, replay cache, revocation, in-circuit signature gadget or zkVM verification, and audit.

Severity: critical. Without it, proofs can still prove submitter-provided facts.

## PQ-Honest Anchor

What it is: either use a transparent STARK/FRI verifier at the on-chain trust anchor, or stop claiming end-to-end post-quantum security.

Why not tonight's code: SP1/RISC Zero EVM paths usually SNARK-wrap the proof with Groth16 or PLONK, which is pairing-based and not post-quantum at the on-chain anchor. Native FRI/STARK verification on EVM is expert work and expensive.

What it needs: measured gas for the chosen anchor, native transparent verifier design if pursuing end-to-end PQ, or product/legal language that limits PQ claims to off-chain proof generation.

Severity: high for public claims and architecture positioning.

## Governance Multisig, Timelock, And Immutable Verifier Trust Root

What it is: production verifier/ruleset/governance changes require multisig approval, timelock delay, emergency policy, event monitoring, and clear immutable trust roots.

Why not tonight's code: local contracts now reject last-admin removal and verifier replacement, but production governance is an operational and legal control plane.

What it needs: multisig signers, timelock contract, key custody, role playbooks, incident process, migration keys, and audit logs.

Severity: critical. A correct proof system can still be defeated by weak upgrade governance.

