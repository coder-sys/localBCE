# Ethereum Strawmap compatibility contract

Updated: 2026-08-01

Status: current architecture and roadmap contract for the containing Ethereum rollup. This
document records a source snapshot and engineering consequences; it does not claim that a draft
EIP will ship, that an estimated date is a commitment, or that R01-R12 are implemented.

## Non-negotiable product decision

Blind Ledger **is an Ethereum-settled, EVM-compatible based validity rollup**. This is compulsory:

- Ethereum determines canonical transaction ordering and finality. A permanent privileged
  sequencer, sequencer committee, or operator-controlled canonical fork is prohibited.
- Every accepted L2 state transition requires the pinned Blind Ledger claim proof and the containing
  rollup validity proof. An optimistic-only path, re-execution-only path, or optional proof is not
  an accepted release mode.
- The release baseline must work against a pinned, deployed Ethereum fork without relying on any
  Draft, Review, Stagnant, research, or estimated Strawmap item.
- EIP-8079 native rollups may later provide a versioned execution/verification adapter. They may
  not make sequencing non-based, replace the Blind Ledger proof, or become a release dependency
  before their specification, implementation, test vectors, and security boundary are final.
- Public Ethereum data availability carries only fixed-shape, non-PHI rollup data. Encryption,
  an encrypted mempool, or a private L1 transfer proposal never authorizes PHI, private claim
  documents, exact private amounts, or decision metadata in calldata, blobs, logs, tickets, or
  ciphertext envelopes.

## Source snapshot and authority

The live source was read from [strawmap.org](https://strawmap.org/) and its linked Google Drawing,
not from a PDF, screenshot, or secondary transcription. The Drawing identifier is
`1GkcGfQv9kxgrYQMyu0BYGcZya0gIDG_wQ7GsFJEsdzY`; its live label said “updated Jul 29, 2026.”
The fetched SVG SHA-256 was
`6514BA52E8EABDDE9162F460E3BAAC52BA0DBA62BA5AA0EAE546FBCB6C7163C8`.

All 23 EIPs linked by that map were read from the canonical `ethereum/EIPs` repository. The
sorted `filename:SHA-256` manifest itself hashes to
`D18D3AB07B30535E647B2E23665958A229934C99318371C61E0C567650561AB2`.
Linked primary specification, research, and project sites were used to interpret non-EIP nodes:
`protocol.ethereum.foundation`, `pq.ethereum.org`, `ethereum.org`, Ethereum Research,
`ethereum/consensus-specs`, `ethereum/cryptography-specs`, `ethp2p/ethp2p`,
`leanEthereum/leanSpec`, `leanEthereum/leanMultisig`, `Verified-zkEVM/evm-asm`, and the
linked leanVM/leanDA material.

The Strawmap describes itself as a work-in-progress “strawman,” rough consensus, and EF takes—not
authoritative Ethereum governance. Its arrows are through-lines, not hard dependencies, and its
emoji mark uncertainty. All Core Devs decisions, final EIPs, deployed fork specifications, and
pinned client behavior outrank it. Therefore:

1. shipped/final fork behavior is a current compatibility input;
2. Review items are high-priority conformance targets but not assumed deployed;
3. Draft items receive versioned, fail-closed adapter design and tests;
4. Stagnant items are research or rejection evidence, never current dependencies; and
5. map dates and throughput labels are projections until a deployed fork and measurements prove them.

### Canonical source index

The linked EIP sources are:
[7503](https://eips.ethereum.org/EIPS/eip-7503),
[7732](https://eips.ethereum.org/EIPS/eip-7732),
[7773](https://eips.ethereum.org/EIPS/eip-7773),
[7805](https://eips.ethereum.org/EIPS/eip-7805),
[7919](https://eips.ethereum.org/EIPS/eip-7919),
[7928](https://eips.ethereum.org/EIPS/eip-7928),
[7938](https://eips.ethereum.org/EIPS/eip-7938),
[7999](https://eips.ethereum.org/EIPS/eip-7999),
[8007](https://eips.ethereum.org/EIPS/eip-8007),
[8025](https://eips.ethereum.org/EIPS/eip-8025),
[8070](https://eips.ethereum.org/EIPS/eip-8070),
[8077](https://eips.ethereum.org/EIPS/eip-8077),
[8079](https://eips.ethereum.org/EIPS/eip-8079),
[8081](https://eips.ethereum.org/EIPS/eip-8081),
[8136](https://eips.ethereum.org/EIPS/eip-8136),
[8141](https://eips.ethereum.org/EIPS/eip-8141),
[8142](https://eips.ethereum.org/EIPS/eip-8142),
[8184](https://eips.ethereum.org/EIPS/eip-8184),
[8198](https://eips.ethereum.org/EIPS/eip-8198),
[8200](https://eips.ethereum.org/EIPS/eip-8200),
[8250](https://eips.ethereum.org/EIPS/eip-8250),
[8272](https://eips.ethereum.org/EIPS/eip-8272), and
[8297](https://eips.ethereum.org/EIPS/eip-8297).

The non-EIP primary sources include:
[protocol specifications](https://protocol.ethereum.foundation),
[consensus specs](https://github.com/ethereum/consensus-specs),
[cryptography specs](https://github.com/ethereum/cryptography-specs),
[PQ Ethereum](https://pq.ethereum.org/),
[Ethereum quantum roadmap](https://ethereum.org/roadmap/future-proofing/quantum-resistance/),
[ethp2p](https://github.com/ethp2p/ethp2p),
[leanSpec](https://github.com/leanEthereum/leanSpec),
[leanXMSS specification path](https://github.com/leanEthereum/leanSpec/tree/main/src/lean_spec/spec/crypto/xmss),
[leanMultisig](https://github.com/leanEthereum/leanMultisig),
[evm-asm](https://github.com/Verified-zkEVM/evm-asm),
[fast confirmation](https://fastconfirm.it),
[proof of custody](https://ethresear.ch/t/a-0-001-bit-proof-of-custody/7409),
[ephemeral-key PQ migration](https://ethresear.ch/t/achieving-quantum-safety-through-ephemeral-key-pairs-and-account-abstraction/24273),
[VOPS](https://ethresear.ch/t/a-pragmatic-path-towards-validity-only-partial-statelessness-vops/22236),
[PQ validator key registry](https://ethresear.ch/t/exploring-the-design-space-for-a-post-quantum-public-key-registry-for-ethereum-validators/25040),
[hyper-scaled state](https://ethresear.ch/t/hyper-scaling-state-by-creating-new-forms-of-state/24052),
[minimal VDF](https://ethresear.ch/t/minimal-vdf-randomness-beacon/3566),
[gas futures](https://ethresear.ch/t/on-in-protocol-gas-futures/23698),
[lean-chain privacy](https://ethresear.ch/t/the-extremely-lean-chain/25369#p-61091-phase-2-privacy-7),
[51-percent recovery](https://ethresear.ch/t/timeliness-detectors-and-51-attack-recovery-in-blockchains/6925),
[attester–includer separation](https://ethresear.ch/t/towards-attester-includer-separation/21306/1),
[decoupled consensus](https://ethresear.ch/t/unblocking-faster-finality-with-decoupled-consensus/24527/1),
[dynamically available/PQ heartbeat](https://ethresear.ch/t/why-ethereum-needs-a-dynamically-available-protocol/24418#p-59055-a-near-term-benefit-post-quantum-readiness-and-post-quantum-heartbeat-6),
and the [RISC-V proposal](https://ethereum-magicians.org/t/long-term-l1-execution-layer-proposal-replace-the-evm-with-risc-v/23617).
No PDF was used as an authority for this snapshot.

## Complete linked-EIP decision matrix

| EIP | Snapshot status | Strawmap role | Binding Blind Ledger decision |
| --- | --- | --- | --- |
| 7503 | Stagnant | Zero-Knowledge Wormholes / private ETH | Research-only L1 privacy interop. Its burn/remint, nullifier, receipt/state-branch and curve-SNARK design is not the Blind Ledger privacy primitive and does not meet the strict-PQ boundary. |
| 7732 | Review | ePBS | R07 must model bid/reveal, payload timeliness, payload withholding, delayed execution validation, PTC behavior, builder/proposer/attester collusion, empty blocks, and reorgs. No relay or builder is trusted. |
| 7773 | Draft Meta | Glamsterdam fork | Track the exact fork bill. At this snapshot scheduled core items include 7708, 7732, 7778, 7843, 7928, 7954, 7976, 7981, 8024, and 8037; networking includes 7975, 8070, 8136, 8159, and 8189. Pin the final fork spec, not this draft list. |
| 7805 | Draft | FOCIL | R07/R10 accept only opaque, bounded, non-PHI commitments through forced inclusion. Test committee equivocation, duplicate and invalid entries, nonce/balance conflicts, view freeze, builder invalidation, conditional inclusion, unavailable IL data, and reorg/retry identity. |
| 7919 | Stagnant Meta | Pureth / purges | No dependency. Preserve its goals—verifiable/completable block, transaction, and receipt data; simpler RPC trust; serialization cleanup—as compatibility research only. |
| 7928 | Review | Block-Level Access Lists (BALs) | Replace the stale EIP-7707 tracker. R01/R02/R07/R08 must support exact accessed/changed state and post-transaction diffs, Engine API changes, deterministic ordering, reconstruction, and adversarial phantom-read/gas cases. Ethereum BALs are public execution artifacts; they are not the private, fixed-padded CBAM. |
| 7938 | Stagnant Informational | Exponential gas-limit increase / 3x per year | Projection only. Never size Blind Ledger from this schedule or claim future L1 capacity. Capacity gates use the pinned fork and measured limits. |
| 7999 | Draft | Unified multidimensional pricing | R01/R06/R08/R11 model execution, blob, and calldata resources independently. A scalar fee must not hide saturation, and current fee constants must not be hard-coded as future economics. Test reserve-price, packing, FOCIL classification, and builder-centralization edge cases. |
| 8007 | Draft Meta | Glamsterdam repricing | Pin final opcode/precompile/state/transaction gas costs in the selected EVM and prover. Gas changes are compatibility inputs, not Blind Ledger proof-security parameters. Differential gas tests must cover every finally included repricing. |
| 8025 | Draft | Optional execution proofs / 2-of-3 direction | Optional Ethereum execution proofs may be a shadow-verification and interoperability input only. They cannot replace authoritative re-execution, the production L2 verifier, the Blind Ledger proof, or the mandatory rollup validity proof. Bind proof type, guest, chain config, block, public inputs, and size; reject unknown types. |
| 8070 | Draft Networking | Sparse blobpool | R08 tests partial-cell fetch, custody-set changes, provider/sampler selection, reconstruction, selective withholding, eclipse/Sybil/free-rider behavior, sampling noise, truncated responses, and rollback. Its probabilistic availability numbers are not Blind Ledger guarantees. |
| 8077 | Draft Networking | Announce transaction nonce | Treat announced address/nonce as untrusted hints until the transaction hash and payload verify. Mismatches are protocol violations; they never mutate attempt/nullifier state. |
| 8079 | Draft | Native rollups | Optional adapter only. The proposed `EXECUTE` precompile, proof/security model, custom-feature limits, tests, and reference implementation remain incomplete/TBD. Based sequencing and mandatory Blind Ledger validity remain invariant. |
| 8081 | Draft Meta | Hegotá fork | Track the final fork bill. At this snapshot FOCIL is scheduled and frame transactions are considered; proposed lists are not deployed behavior. |
| 8136 | Draft Networking | Cell-level deltas | R08 supports partial-message negotiation without preferring peers into a network partition. Test missing-cell latency, group-ID spam, score neutrality, old-peer fallback, reconstruction, and rollback. |
| 8141 | Draft | Frame transactions | High-priority account-abstraction/PQ migration adapter. Preserve exact chain, sender, nonce, frame, signature, payer, blob, atomic-batch, revert/log, gas, mempool, and expiry semantics. Arbitrary signatures and a PQ off-ramp do not automatically establish Blind Ledger PQ authority; only pinned accepted schemes do. |
| 8142 | Draft | Block-in-Blobs / leanDA direction | R08 binds execution payload, payload-blob count/order, commitments, proofs, BAL/witness, header fields, reconstruction, and rollup proof atomically. KZG remains external classical Ethereum risk and receives no Blind Ledger PQ credit. Never place private claim data in payload blobs. |
| 8184 | Draft | LUCID encrypted mempool | MEV/censorship-resistance research and future transport adapter only. The draft deliberately does not enshrine a satisfactory PQ encryption scheme and uses off-protocol key publishers, tickets, commitments, delayed key release, and ChaCha20-Poly1305 envelopes. It is not PHI transport, storage, witness hiding, or a strict-PQ claim. Test non-reveal, bad keys, rejected payload recovery, ticket charging, nonce use, and FOCIL interaction. |
| 8198 | Draft | Quick slots | R06/R07 must be slot-duration-parameterized. Shorter slots improve based-rollup latency, but gas/blob-per-block, issuance, churn, weak-subjectivity windows, DA windows, deadlines, propagation, and hardware assumptions change. No hard-coded 12-second timing and no 8-second claim before deployment. |
| 8200 | Draft | EVMify long-tail precompiles | R01/R02 track exact final RIPEMD-160, MODEXP, and BLAKE2f bytecode/gas semantics and differential vectors. EVMification may simplify the outer prover; it does not replace SHA3-512 or the Blind Ledger inner proof. |
| 8250 | Draft | Keyed nonces | Relevant to shared private senders and throughput. Bind the strictly ordered bounded nonce-key set, sequence, sender, signature hash, protocol storage, first-use gas, consumption, and replay atomically. It complements—but never substitutes for—retry-stable Blind Ledger attempt/nullifier identity. |
| 8272 | Draft | Recent roots | Relevant to privacy-root validation without arbitrary mutable mempool reads. Bind source address/salt/source ID, slot, root, signed envelope, usable window, system storage and introspection. Reject current/future, expired, absent, overwritten, duplicate, and ambiguous roots. It does not make an Ethereum root the authoritative private Blind Ledger state commitment. |
| 8297 | Draft | Partitioned binary tree | Track as Ethereum state/witness migration. Binary arity, zones, content-addressed code, locality, absent/zero rules, insertion/deletion, fork conversion, proof bounds, and the final hash all require exact vectors. The draft hash is explicitly not final; it cannot select Gate 2E state or grant PQ credit. |

## Planned-upgrade through-lines beyond the 23 EIPs

The map contains planned nodes that are not yet one EIP. They remain explicit compatibility
work—not hidden assumptions.

### Consensus layer

- ePBS, FOCIL, attester–proposer separation, attester–includer separation, and distributed block
  building change who can order, include, withhold, or attest. The based-ordering test harness must
  inject each role independently.
- Decoupled consensus, fast confirmation, quick slots, faster L1 finality, one-round finality,
  a 128K attester cap, and a later return toward one million attesters change latency and fault
  timing. R06/R07 use fork-aware clocks and distinguish preconfirmation, head, justification,
  finality, and safe withdrawal. A fast signal is never finality.
- Mandatory one-of-one and optional two-of-three proofs of custody change DA evidence. R08 accepts
  only the deployed rule and still independently reconstructs required rollup data.
- Secret proposers, a minimal VDF randomness beacon, timeliness detectors, and automatic 51-percent
  attack recovery require censorship/reorg/recovery tests. Blind Ledger never treats proposer,
  builder, committee, or preconfirmation identity as a privacy or correctness oracle.
- The beacon/leanCL specification merge, leanCL, a PQ public-key registry, leanXMSS attestations,
  a PQ heartbeat, and real-time CL proofs are tracked external migrations. Ethereum consensus
  classical risk remains explicit until the deployed chain actually completes those migrations.

### Data layer

- PeerDAS is the current basis; sparse blobpool, cell deltas, local reconstruction, blob streaming,
  higher DA, leanDA block sampling, PQ leanDA sampling, and a possible removal of the blob
  transaction type form one migration chain.
- R08 owns a versioned data envelope and adapters. It binds rollup proof, L2 batch/state,
  Ethereum block/fork, payload/blob/cell commitments, reconstruction result, and finality.
- The “teragas L2 / 1 Gbyte per second” label is a north-star projection, not capacity evidence.
  Admission control uses measured end-to-end proving, verification, DA, reconstruction, and finality.

### Execution layer

- BALs, multidimensional pricing, gas-limit increases, repricing, Pureth purges, and gigagas L1
  targets change witness shape, fees, and throughput. They never relax the 5,000 MB host gate,
  proof theorem, fixed privacy schedule, or measured admission controller.
- Frames, keyed nonces, recent roots, encrypted mempool, optional execution proofs, native rollups,
  EVMification, zkEVM, canonical `evm-asm`, a possible RISC-V ISA, and a tech-debt reset are
  versioned outer-execution surfaces. No one of them replaces the selected inner proof.
- The partitioned binary tree, validity-only partial statelessness, decentralized/endgame state,
  and hyper-scaled new forms of state are Ethereum state research. Gate 2E independently selects
  Blind Ledger's authoritative private state under its own theorem, hiding, migration, and resource
  gates.
- Long- and short-dated gas/blob futures are economic research. They cannot bypass bounded admission,
  create unbacked capacity promises, or change consensus/finality truth.

### Post-quantum, privacy, and networking

- Ethereum's published PQ milestones are I* (PQ key registry), J* (PQ signature precompiles),
  L* (PQ attestations, real-time CL proofs, leanVM), M* (PQ aggregation and PQ-safe blobs), then
  full PQ consensus, transactions, and sampling. These are planning milestones, not guaranteed fork
  commitments.
- `leanVM` aggregates large hash-based Ethereum signatures. It is an external consensus/data
  component. It does not replace the specialized M31/Fp16 Blind Ledger semantic/GKR/PCS proof,
  prove the sealed claim relation, or satisfy native witness hiding.
- `leanSpec`, `leanXMSS`, `leanMultisig`, the Lean 4 cryptography specifications, and
  leanDA require pinned source identity, vectors, independent verification, and deployed-fork
  conformance before they affect release claims.
- Ephemeral-key/account-abstraction migration, PQ transaction signatures, native/private L1
  shielded transfers, a privacy pool/wormholes, and zkzk frames are external compatibility and
  privacy research. Blind Ledger keeps dual-PQ authority, fixed observable shape, and its private
  data boundary regardless of Ethereum feature availability.
- `ethp2p` unification and broadcast changes require version negotiation, bounded parsers,
  duplicate/reorder/drop handling, peer diversity, and denial-of-service tests.
- PQ leanSPHINCS transaction/mempool work, plus map-labelled SFI and CFI, remain unselected
  external research surfaces. Their exact meaning and acceptance semantics must be pinned from a
  final specification before any adapter is enabled; labels alone authorize nothing.
- The map's performance north stars—lower latency, greater throughput, and multiple hardness
  dimensions—are aligned goals, never permission to reduce security or report projections as runs.

## Required R01-R12 implementation contract

| Package | Strawmap-derived acceptance work |
| --- | --- |
| R01 | Pin exact deployed EL/CL fork specs, EVM, based-validity stack, source commits, licenses, and feature matrix. Release must not require an unshipped item. |
| R02 | Reproducible local EL/CL/L2 environment with selectable fork profiles, slot duration, gas/blob schedule, transaction formats, BAL/data modes, and deterministic fixtures. |
| R03 | Production verifier binds the exact Blind Ledger proof, rollup proof, chain/fork IDs, state, data envelope, verifier identity, and proof-suite identity. Optional EIP-8025/8079 paths are separate rejected-by-default adapters. |
| R04 | Atomic state transition binds retry-stable attempt/nullifier identity, old/new private state, Ethereum/L2 roots, ordering, BAL/CBAM boundary, recent-root references, keyed nonces, migration, and receipt. |
| R05 | L2 prover differentially executes every supported final fork rule and proves the complete state transition; EVM repricing or state-tree changes cannot silently alter semantics. |
| R06 | Settlement distinguishes head, safe, justified, finalized, reorged, and recovered states under fork-aware timing; no preconfirmation or quick-slot signal is called finality. |
| R07 | Based ordering has no privileged canonical sequencer and covers ePBS, FOCIL, builder/committee withholding, delayed payloads, reorgs, duplicates, nonce conflict, and forced opaque inclusion. |
| R08 | Non-PHI DA envelope, payload/blob/cell commitment equality, proof/data coupling, partial fetch, reconstruction, retention, withholding, and fork migration all fail closed. |
| R09 | Bridge deposits/withdrawals bind canonical finalized state, proof, replay domain, chain/fork, amount commitment, recipient, delay, and recovery; no draft privacy feature is trusted. |
| R10 | Forced inclusion, escape, and recovery accept only bounded opaque commitments and preserve privacy, retry identity, censorship resistance, and safe finality across reorgs. |
| R11 | Versioned adapters, fork activation, migration, rollback, emergency pause, and downgrade prevention cover every supported EIP surface. Unknown or partially supported fork features reject. |
| R12 | Synthetic claim-to-finalized-Ethereum and rollback tests run against the pinned baseline plus explicit future-fork profiles; raw receipts prove ordering, data reconstruction, proofs, state, and finality. |

These obligations refine the existing 12 packages; they add no package and mark none complete.

## Release gates and prohibited shortcuts

Before R01 selection and again before R12 qualification:

1. fetch current canonical EIP and fork sources; record commit hashes and status changes;
2. enumerate the exact final fork bill and client versions;
3. map every enabled feature to producer, parser, verifier, state, DA, migration, and test ownership;
4. reject unknown fields, proof types, transaction types, signature schemes, hash choices, fork IDs,
   data modes, or partial adapter support;
5. run differential final-fork vectors and adversarial based-ordering/DA/finality tests;
6. prove the public data envelope contains no prohibited private field or metadata channel; and
7. keep Ethereum's remaining ECC, BLS, KZG, pairing, and other classical dependencies explicit in
   the composed security ledger.

Prohibited shortcuts are: treating the Strawmap as governance; treating dates or north-star labels
as capacity; depending on Draft/Review/Stagnant behavior; using EIP-7503 or LUCID as Blind Ledger
privacy; using leanVM or optional execution proofs as the Blind Ledger verifier; equating BAL with
CBAM; placing PHI in encrypted public DA; trusting a builder, relay, proposer, committee, or key
publisher; calling preconfirmation finality; or claiming end-to-end PQ while Ethereum's selected
settlement fork retains classical cryptography.
