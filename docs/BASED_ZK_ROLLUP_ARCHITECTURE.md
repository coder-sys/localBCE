# Blind Ledger based ZK-rollup architecture

Status: architectural source of truth for the target system.

Updated: 2026-08-05

Current inner-proof execution checkpoint: the newest dated section of `../STATE.md`; the original
transfer record is `../WAVE2_HANDOFF_2026-07-26.md`. The GPU accelerates only untrusted field
arithmetic inside the selected claim-proof topology. The manifest-bound H4 prototype now passes the
real native-masked GKR, Construction 8.2 PCS, atomic one/four-shard coordinator, parsing, and
independent verification in 29.974129 seconds for K128 and 120.460733 seconds for K512. This does
not change the rollup architecture, settlement trust boundary, ordered 12-field public ABI, package
count, or activation status. Gate 2E is sealed nonactivating, H5 passed the exact 22-launch campaign,
and H6 closed the twelve bounded candidate-evidence records. The production L2/L1 verifier path,
durable state/custody, `proofSuiteId`, and activation remain open/disabled.

Planning boundary: `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` makes R01-R12 counted internal
engineering packages. The rollup, bridge, finality, deployment automation, and sandbox end-to-end
path are not deferred to an outside integrator. One final independent Security Audit Gate follows
whole-product completion; live network credentials and authorizations are activation inputs.

Every engineer and AI agent working on proof, settlement, privacy, sequencing, data availability,
bridging, or finality must read this document before proposing or editing those systems.

Inner-proof topology addendum: the L2 claim verifier target is the atomic heterogeneous proof in
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`, not the historical Cairo proof or a monolithic
direct-SHA3 STARK. The containing rollup must bind the exact semantic-AIR, shared-bus, hash-
coprocessor, sidecar, and verifier identities selected by Wave 2/3.

Ethereum-roadmap compatibility and its maturity gates are defined in
`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`. It inventories every live-map EIP and
planned through-line. Its 2026-08-05 live-map refresh covers 60 underlying links, including all
23 EIPs, and records which L1 behavior requires a based-rollup adapter. Draft/Review/Stagnant
items are versioned compatibility targets, not dependencies of the deployment-ready baseline.

## Decision

Blind Ledger's compulsory containing architecture is an Ethereum-settled, EVM-compatible, based
validity rollup:

- Ethereum L1 provides canonical sequencing, data availability for public rollup state, settlement,
  and objective finality.
- Ethereum proposers/builders order L2 transactions through a based-sequencing design. Blind Ledger
  must not depend on a permanently privileged centralized sequencer for canonical inclusion.
- A validity proof authenticates every accepted L2 state transition. Based sequencing alone does not
  prove execution correctness.
- Blind Ledger claim proofs execute and verify inside the L2. The L2 validity proof then proves to
  Ethereum that the verifier and settlement logic executed correctly.
- Patient and claim records remain in government-controlled encrypted storage. Public L1/L2 data
  contains commitments, roots, proofs, and the minimum public financial state only.
- EIP-8079 native execution, EIP-8025 optional execution proofs, and leanVM may be future outer-chain
  adapters. None can replace based ordering, mandatory validity, or the Blind Ledger inner proof.

This is not a decision to clone Robinhood Chain. Robinhood Chain is a finance-focused Ethereum L2
built on Arbitrum Nitro with a dedicated sequencer and optimistic fraud-proof finality. It is a useful
operational comparison, but it is not a based validity rollup.

Primary references:

- Robinhood Chain: https://docs.robinhood.com/chain/
- Robinhood canonical bridge and challenge period: https://docs.robinhood.com/chain/bridging/
- Based sequencing definition: https://ethresear.ch/t/based-rollups-superpowers-from-l1-sequencing/15016
- Ethereum ZK-rollup settlement model: https://ethereum.org/developers/docs/scaling/zk-rollups/
- Taiko based-rollup reference architecture: https://taiko.xyz/solutions

### Versioned settlement modes

The release architecture has three non-overlapping modes:

1. a pinned conventional validity-rollup mode with Blind Ledger's own L2 transition proof and L1 verifier;
2. an optional native-rollup adapter only after EIP-8079 or a successor is finalized, implemented,
   independently tested, and preserves every Blind Ledger invariant; and
3. fail-closed recovery, which stops state advances but preserves exits/evidence and never bypasses proofs.

FOCIL compatibility carries only bounded opaque transaction or proof-job commitments. No inclusion
list, calldata, blob, or DA recovery object may contain raw or encrypted PHI. PeerDAS/cell-aware
transport and proof/data coupling require reconstruction and withholding tests. Ethereum's current
classical cryptography remains an explicit external boundary and does not make the system end-to-end PQ.

### How an L1 upgrade propagates into this based L2

L1 and L2 are coupled, but they are not the same machine:

| L1 change | Automatic effect | Required Blind Ledger response |
| --- | --- | --- |
| Consensus, proposer/builder, slot, or finality rule | The canonical L1 supplies the new ordering/timing/finality behavior. | Do not implement another consensus. Upgrade the observer, timing, reorg, settlement, bridge/exit and fault-test logic before relying on it. |
| DA, blob/cell, payload, networking, or Engine API rule | Canonical clients transport data under the new rule. | Upgrade the exact batch publisher, retriever, reconstruction, proof/data binding, monitoring and rollback adapters. |
| L1 EVM, gas, precompile, transaction, receipt, or state-proof rule | L1 contracts and submission transactions execute under the new fork. | Upgrade L1 contract assumptions and tooling. Also upgrade the L2 executor/prover/verifier when the selected L2 EVM compatibility profile mirrors that rule. |
| Optional native proof, frame, nonce, root, privacy, or mempool feature | Nothing changes unless Blind Ledger chooses the feature. | Keep rejected by default; adopt only through a versioned R11 migration after finality, interoperability, security, privacy, PQ, rollback and measured-benefit gates. |
| Research/north-star item | No deployable effect. | Monitor only; grant no implementation, capacity or security credit. |

“Lockstep” means Blind Ledger freezes the exact final L1 fork bill, implements and rehearses all
affected adapters before activation, switches the manifest-bound integration atomically, and pauses
new batch publication on an unknown/partial fork while preserving safe exits from the last supported
finalized state. It does not mean copying drafts or reimplementing L1 consensus. The authoritative
23-EIP classification, triggers and package owners are in
`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`.

## Trust boundaries

### Ethereum L1

L1 is the final court. It must contain or enforce:

- the canonical L2 state root;
- the rollup validity-proof verifier;
- public rollup data commitments and Ethereum blob/calldata availability;
- the canonical bridge and asset escrow;
- forced inclusion and censorship escape paths;
- delayed, transparent protocol upgrades with an emergency scope that cannot silently bypass proofs;
- finality only after Ethereum accepts the corresponding state transition.

### Blind Ledger L2

The L2 is the fast execution environment. It contains:

- EVM-compatible provider and government workflows;
- the Blind Ledger claim-proof verifier;
- nullifier, policy, oracle, accumulator, and payment-commitment state;
- settlement logic that advances state only after the exact claim proof and exact public statement
  are authenticated;
- no raw patient data, diagnoses, claim documents, prior-authorization documents, or exact private
  claim/payment amounts in public state, events, calldata, or blobs.

### Government private systems

Government-controlled systems contain:

- encrypted patient and claim records;
- KMS/HSM private keys and authorization policy;
- isolated proof workers and private witnesses;
- selective auditor access, legal hold, retention, rotation, and crypto-erasure controls;
- a durable mapping from private records to public commitments without putting decryptable medical
  records on a public chain.

The local KMS simulator tests this interface only. It is deliberately forbidden in production.

## Two proof layers

Blind Ledger requires two distinct proofs. They must never be described as interchangeable.

1. The claim proof proves private healthcare/payment rules, governed inputs, nullifier transitions,
   and value conservation without revealing private claims or amounts.
2. The rollup proof proves the entire L2 state transition, including successful execution of the
   claim-proof verifier and settlement contract, to Ethereum L1.

Ethereum security is inherited only when the L1 rollup contract verifies the rollup proof, binds it
to the previous and next L2 state roots, and has sufficient public data to reconstruct the public L2
state. An off-chain claim proof by itself does not create an Ethereum-secured L2.

## Public and private data availability

Public rollup state must remain independently reconstructible from Ethereum data. That public state
is limited to accounts, balances or committed balances, nullifier roots, governed roots, protocol
messages, opaque batch commitments, and proofs.

Medical records are not public rollup state. They remain encrypted in government storage. Ethereum
stores only a binding commitment. Loss of private records must not permit theft, forged settlement,
or an invalid state transition. Exit and recovery designs must not require publishing patient data.

Permanently publishing encrypted medical records is not accepted as privacy merely because the
decryption key is currently unavailable.

## Canonical Privacy V2 public statement

The claim-proof boundary has two authenticated layers.

The external application statement remains the ordered 12-field `bytes32` ABI in
`ops/native_stark_public_inputs_v2.json`:

1. `protocolVersion`
2. `settlementDomain`
3. `batchNonce`
4. `nullifierRootBefore`
5. `nullifierRootAfter`
6. `claimSourceRoot`
7. `oracleFactsRoot`
8. `policyRoot`
9. `rulesetRoot`
10. `opaqueBatchCommitment`
11. `valueConservationCommitment`
12. `settlementCommitment`

The selected `BL-PQ512-v1` proof profile adds authenticated SHA3-512 nullifier state, governed-root
context, master batch binding, suite/schema identity, epoch, and sequence inside the proof envelope
and verifier-maintained state. These values do not add fields to the external `Submission`, but they
are part of the security boundary. Twelve Stark-field values alone cannot provide the selected
strict quantum collision target.

The complete claim-proof decision, impossibility boundary, backend roles, and STOP gates are in
`docs/PQ_ZK_SECURITY_ARCHITECTURE.md`.

It must not expose:

- exact approved or paid amounts;
- claim, approval, or denial counts;
- per-claim decisions or failure codes;
- patient, member, provider-document, diagnosis, or authorization data;
- raw or encrypted medical-record payloads.

Small-batch and timing inference remain part of the threat model. Padding and state-transition design
must be reviewed before claiming that approval/denial or batch size is hidden.

## Current critical gap

The current V1 source is not this target architecture:

- Cairo `batch_main` returns 12 inner values.
- `StarkBatchSettlement` accepts a separate caller-supplied array of 21 public inputs.
- The repository contains only `INativeStarkVerifier`; it contains no production implementation.
- Solidity tests use a mock verifier that ignores the proof and public inputs.
- Exact approved/payment totals and claim ciphertext are public in the V1 settlement path.

No production or Ethereum-security claim is permitted until one real verifier authenticates the exact
ordered Cairo output consumed by settlement. Caller-supplied values that are not part of the proven
statement must never advance canonical state.

## Privacy V2 implementation checkpoint

The first parallel V2 ABI uses 12 exact Cairo outputs and a settlement contract that reconstructs
those same 12 values internally. It removes public amount/count/payload fields, binds settlement
domain and nonce, and uses salted opaque/value commitments.

The external layout is retained, but old denied-case values are not immutable: the selected privacy
profile requires every real claim and every padding slot to perform a nullifier transition. The new
proof profile, schema/artifact identity, and known-answer vectors must make that semantic change
explicit; it must never be silently presented as the old proof relation.

The checkpoint remains experimental. Wave 1 seals the fixed-shape executable claim AIR and exact
SHA3 schedule, H4/Gate 2E now supply a sealed nonactivating state-bound context, and the exact H5
campaign passes its strict p95/resource gates. The proof suite is still not activated: complete H6
theorem/simulator/grammar/supply-chain/privacy/migration qualification, the production claim
verifier, and the containing rollup remain unfinished. Upstream unmasked S-two receipts remain
validity-only and are not approved for real PHI.

## Required implementation sequence

1. Select and pin the based validity-rollup stack and its Ethereum L1 contracts.
2. Preserve the ordered 12-field application ABI while separately versioning and pinning the full
   authenticated proof envelope and `BL-PQ512-v1` verifier context.
3. Preserve the sealed fixed-shape semantic AIR and implement the shared-bus Boolean SHA3
   coprocessor, native hiding, uniform nullifier transition, authoritative shadow state, and new
   KATs; do not silently reinterpret the old proof relation.
4. Implement and internally qualify the real claim-proof verifier on L2; submit its exact release
   identity to the final audit after whole-product engineering completion.
5. Remove exact amounts, counts, decisions, and claim ciphertext from public settlement.
6. Bind the L2 verifier execution into the rollup state-transition proof accepted on Ethereum.
7. Add forced inclusion, safe exits, upgrade delays, data reconstruction, and disaster recovery.
   Include opaque FOCIL-compatible submission, proof/data coupling, keyed replay, cell-aware DA
   reconstruction, recent-root checkpoints, and a disabled-by-default native-rollup adapter.
8. Generate a real proof over synthetic claims, verify it through the real L2 verifier, produce a rollup proof, and
   verify the resulting state transition through the Ethereum L1 contracts.
9. Produce reproducible one-command sandbox deployment, recovery, rollback, and audit evidence.
10. Complete the one independent Security Audit Gate over cryptography, implementation, rollup,
    bridge, privacy, side channels, supply chain, and operations.

## Non-negotiable release gates

- No mock verifier in deployment tests or release evidence.
- No mismatch between proof output length/order and settlement input length/order.
- No governance or emergency path that can advance roots without the required proof.
- No PHI or decryptable medical-record payload in L1/L2 calldata, blobs, events, logs, or artifacts.
- No production use of local rules-engine fallback or local KMS simulation.
- No claim of Ethereum finality before L1 proof acceptance.
- No claim of full privacy until small-batch, timing, metadata, and recovery-path inference tests pass.
- No PHI proof generation until the selected backend has audited zero-knowledge witness hiding.
- No strict post-quantum claim until the application roots, proof PCS/Merkle/FRI commitments,
  Fiat-Shamir transcript, verifier identity, state anchors, signatures, KEMs, and multi-target
  analysis meet the declared profile.
- No `DEPLOYMENT_READY_AUDIT_PENDING` claim until all 93 internal roadmap packages close.
- No production activation until the final independent audit accepts the exact release identities
  and operators supply authorized configuration.

## Change discipline

Changes to this decision require a dated architecture decision, threat-model update, migration plan,
new known-answer vectors, attack tests, full regression tests, and independent review. Documentation
or tests must never be weakened to make an incompatible proof or verifier appear valid.
