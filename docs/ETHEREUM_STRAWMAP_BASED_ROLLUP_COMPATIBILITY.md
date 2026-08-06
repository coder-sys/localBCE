# Ethereum Strawmap compatibility contract

Updated: 2026-08-05

Status: current architecture and roadmap contract for the containing Ethereum rollup. This
document records a source snapshot and engineering consequences; it does not claim that a draft
EIP will ship, that an estimated date is a commitment, or that the local R01-R12 fixture is a live
Ethereum deployment.

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

The following paragraphs preserve the prior 2026-08-01 snapshot for provenance; the current
2026-08-05 refresh is recorded below. The prior snapshot was read from [strawmap.org](https://strawmap.org/) and its linked Google Drawing,
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

The local/synthetic R01-R12 implementation is `app/wave5_rollup.py`. It uses a pinned baseline and
future-shadow profile, records all 23 EIP maturity entries, rejects unshipped/optional features by
default, and exercises based ordering, finalized settlement, commitment-only DA, bridge, exits,
migration, and rollback. It is internal nonactivating evidence, not proof that a live Ethereum
client or production L2 verifier is present.

## 2026-08-05 live link audit

The live Strawmap page and linked Google Drawing were fetched as HTML/SVG on 2026-08-05,
without a browser plugin, screenshot, or PDF. The Drawing identifier is
`1GkcGfQv9kxgrYQMyu0BYGcZya0gIDG_wQ7GsFJEsdzY`. The current raw source readback was:

```text
strawmap_html_status=200
strawmap_html_bytes=16732
strawmap_html_sha256=3cb5d371ec515a84e3260cf6bb26ead1117247e90c8aa0938ab75fff25776a04
drawing_svg_status=200
drawing_svg_bytes=2176494
drawing_svg_sha256=f6eb66b2f1899eee675490aee037d74801f1aaf7292bd9c677a971a07b7b72bc
unique_underlying_url_count=60
eip_url_count=23
non_eip_url_count=37
normalized_url_manifest_sha256=ad41badff1dfac6fd1a27b8b290610b9b9de64aef1fb6b67aefe0ccd096902ad
```

All 23 EIP pages and their current `ethereum/EIPs` source files were read. The current sorted
`filename:SHA-256` manifest hashes to
`86414227b3c9f8c86e01b7b1634f9693350e572644835a5cbae246160ee51c49`. EIP-8070 is now marked
`Review` rather than `Draft`; the other current status labels are recorded in the matrix below.

The 37 non-EIP links contain 36 non-PDF links and one PDF. All 36 non-PDF links were fetched
successfully except the linked public Google document, which returned HTTP 401 for its direct URL
and the `embedded`, `output=html`, `rm=minimal`, and `headers=false` public variants. The PDF
`https://eprint.iacr.org/2020/025.pdf` was intentionally skipped at the owner's direction. No
PDF reader or browser plugin was used. The inaccessible document and skipped PDF receive no
authority or compatibility credit.

### L1 ownership versus based-rollup response

All 23 EIPs are L1-owned proposals or L1 fork/meta inputs. L1-owned means Ethereum clients,
consensus, execution, networking, or fork governance would implement the change; Blind Ledger
must observe and bind the final deployed behavior rather than reimplement Ethereum consensus.

| Disposition | Links | Blind Ledger response |
| --- | --- | --- |
| L1 behavior the based rollup must observe or bind | EIP-7732, 7805, 7928, 8070, 8077, 8136, 8142, 8198, 8297; the consensus, cryptography, networking, blob-streaming, reconstruction, finality, and gas-repricing references | Versioned L1 observer, Engine/transaction/receipt/DA parsers, based-ordering tests, finality/reorg handling, reconstruction, and rollback. Never reimplement L1 consensus or call a preconfirmation finality. |
| L1 fork or execution changes requiring conditional compatibility | EIP-7773, 7999, 8007, 8081, 8200; Hegotá repricing and Ethereum fork notes | Pin the deployed fork bill and client behavior. Update the L2 executor/prover only when the selected L2 profile mirrors the final L1 rule; never implement a draft bill as if scheduled. |
| Optional L1/L2 adapter, rejected by default | EIP-8025, 8079, 8141, 8184, 8250, 8272; PQ frame, native-rollup, encrypted-mempool, keyed-nonce, and recent-root research | Keep disabled until final specification, interoperable implementation, threat review, privacy/PQ review, differential tests, migration, rollback, and measured benefit. None may replace based ordering, the mandatory rollup proof, or the Blind Ledger proof. |
| Research, meta, economics, or context only | EIP-7503, 7919, 7938; RISC-V, proof-of-custody, ephemeral-key, VOPS, PQ-validator, hyper-state, VDF, gas-futures, lean-chain, recovery, attester/includer, decoupled-consensus, dynamic-availability, fast-confirmation, leanVM, social, and video links | Monitor and use only to anticipate a future boundary. No implementation, capacity, privacy, PQ, or finality credit is granted until a final deployed specification enters the compatibility manifest. |

The non-EIP source families read in this refresh were `protocol.ethereum.foundation`, Ethereum
consensus and cryptography specifications, `ethp2p`, `leanSpec` and its XMSS path, `leanMultisig`
(which currently redirects to `leanVM`), `Verified-zkEVM/evm-asm`, the two blob transport/
reconstruction notes, Hegotá repricing notes, two Ethereum Notes pages, twelve Ethereum Research
pages, the RISC-V proposal, two linked EIP pull requests, fast confirmation, leanVM data-
availability slides, the EF protocol page, one YouTube explanation, and four X profile pages.
The last two are context only, not technical authority.

The current map also links these additional URLs that were not present in the prior source index:

- [map more-info document](https://docs.google.com/document/d/e/2PACX-1vRtpbntq45GCTG3srzetWDkjsF1d-60iXL1rVeumnJW-Gbm343oV5Xvm3O6rALKJjXgr4mpL1a0uT4t/pub) -- HTTP 401; no authority credit;
- [EIP-11772 pull request](https://github.com/ethereum/EIPs/pull/11772) and [EIP-12081 pull request](https://github.com/ethereum/EIPs/pull/12081) -- L1 proposal context only;
- [blob streaming note](https://hackmd.io/@gMH0wL_0Sr69C7I7inO8MQ/B125sCUtZx), [local blob reconstruction note](https://hackmd.io/@marcopolo/SJrlt4Uubl), and [Hegotá repricing notes](https://misilva73.github.io/hegota-repricings/) -- L1 DA/gas compatibility context;
- [leanVM Reed-Solomon/DA slides](https://frisitano.github.io/slides/decks/leanvm-fold-in-circuit-das-2026-05-08/index.html?v=20260708155502%231) -- external L1/DA research only;
- [one-round finality note](https://notes.ethereum.org/@yannvon/S1wIxIDqbe) and [long-tail cleanup note](https://notes.ethereum.org/@JustinDrake/BkPH7AXSfl) -- L1 consensus/serialization context;
- [RISC-V execution-layer proposal](https://ethereum-magicians.org/t/long-term-l1-execution-layer-proposal-replace-the-evm-with-risc-v/23617) -- L1 execution research only;
- [leanConsensus APS video](https://www.youtube.com/watch?v=5OOzMqCOoKM) -- L1 consensus context only;
- [Justin Drake](https://x.com/drakefjustin), [Toni Wahrstätter](https://x.com/nero_eth), [soispoke](https://x.com/soispoke), and [Vitalik Buterin](https://x.com/VitalikButerin) profiles -- non-authoritative context only; and
- [the linked research paper](https://eprint.iacr.org/2020/025.pdf) -- intentionally not read because the owner requested no PDF tooling.

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
| 8070 | Review Networking | Sparse blobpool | R08 tests partial-cell fetch, custody-set changes, provider/sampler selection, reconstruction, selective withholding, eclipse/Sybil/free-rider behavior, sampling noise, truncated responses, and rollback. Its probabilistic availability numbers are not Blind Ledger guarantees. |
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

## Operational impact classes: what arrives automatically and what Blind Ledger must build

“Ethereum ships it” does not imply either “Blind Ledger must reimplement it” or “Blind Ledger has
nothing to do.” Use these exact classes:

| Class | Meaning | Blind Ledger obligation |
| --- | --- | --- |
| **INHERIT** | The property is supplied by the canonical L1 clients/validator network: for example, a shorter slot or different proposer/builder pipeline. | Do not reimplement L1 consensus. Update fork-aware observation, timing, reorg/finality assumptions, monitoring, fixtures, and capacity measurements before relying on the benefit. |
| **L1-COMPAT** | The change alters an interface or artifact Blind Ledger directly consumes or produces: Engine API, transaction envelope, gas/blob accounting, DA object, proof/witness, header, receipt, or L1 contract behavior. | Implement the exact versioned adapter, parser, producer, verifier binding, migration, attacks, and rollback before the fork activates. Unknown variants fail closed. |
| **L2-PARITY** | The final fork changes EVM execution semantics that the selected EVM-compatible L2 promises to mirror. | Upgrade the L2 executor, state-transition prover, gas accounting, trace/witness schema, verifier vectors, and fork ID atomically. If the L2 deliberately does not mirror an L1 feature, record that exception and prove ordinary EVM application compatibility remains exact. |
| **OPTIONAL** | The feature can improve the design but is not needed for the pinned based-validity baseline. | Keep it disabled and rejected by default. Enable only through R11 after a final spec, pinned implementation, threat review, differential tests, migration, rollback, and measured benefit. |
| **RESEARCH** | The item is Stagnant, underspecified, a north star, or unsuitable for Blind Ledger’s theorem/privacy/PQ boundary. | No release code or capacity/security credit. Preserve the rejection or watch condition and revisit only on a material authoritative change. |

Every **INHERIT** item therefore causes at least configuration and conformance work. Every
**L1-COMPAT** or **L2-PARITY** item causes direct implementation work. **OPTIONAL** and **RESEARCH**
items must not silently enter the dependency graph.

### Exact 23-EIP impact and trigger matrix

| EIP | Impact class | What L1 supplies | Direct Blind Ledger work | Trigger and owning packages |
| --- | --- | --- | --- | --- |
| 7503 | RESEARCH | Nothing deployed; proposed L1 private transfer mechanism only. | No protocol work. Keep its burn/remint/nullifier and non-PQ proof assumptions out of bridge, privacy, and claim semantics. | Re-open only if a successor reaches a scheduled fork and passes PQ/privacy review; R09/R11. |
| 7732 | INHERIT + L1-COMPAT | ePBS ordering, bid/reveal, PTC, and delayed execution-validation behavior. | Fork-aware L1 observer; builder/payload/sidecar correlation; withholding, empty-block, reorg, and delayed-validation tests; never trust a relay/builder preconfirmation. | Final fork inclusion or supported-client devnet; R02/R06/R07/R12. |
| 7773 | L1-COMPAT + conditional L2-PARITY | The final Glamsterdam fork bill and activated EL/CL rules. | Replace the draft bill with the final one; pin fork digest, clients, Engine API, EVM/gas/receipt/network rules; run every included-EIP adapter and differential vector. | Fork scope frozen by Ethereum governance; R01/R02/R05/R11/R12. |
| 7805 | INHERIT + L1-COMPAT | L1 inclusion-list censorship resistance. | Make the based inbox/batcher consume only bounded opaque commitments; handle IL views, duplicates, invalid/conflicting transactions, unavailable ILs, builder invalidation, reorgs, and retry identity. | FOCIL scheduled in a supported fork; R02/R07/R10/R12. |
| 7919 | RESEARCH | No deployed Pureth behavior. | No dependency. Track only concrete final replacements affecting block/transaction/receipt serialization or RPC proofs. | A component EIP becomes final/scheduled; R01/R02/R11. |
| 7928 | L1-COMPAT + conditional L2-PARITY | Public block-level access lists, state diffs, Engine API objects, and reconstruction inputs. | Parse/validate deterministic BAL ordering and diffs; bind BAL-derived public artifacts to block/fork/data receipts; test phantom reads and gas attacks. Keep private CBAM separate. Mirror inside the L2 only if the selected L2 EVM fork adopts BAL semantics. | Final fork inclusion/client schema freeze; R01/R02/R04/R05/R07/R08/R11/R12. |
| 7938 | INHERIT + RESEARCH | Only actual future gas-limit votes/forks create capacity. | Read measured live gas limits into multidimensional admission control; never use the stagnant 3x/year projection. | Deployed gas-limit change; R02/R06/R08/R12. |
| 7999 | L1-COMPAT + conditional L2-PARITY | A final multidimensional L1 fee/resource market if adopted. | Version fee estimation, batch packing, admission, and receipts across execution/blob/calldata dimensions; bind resource vector and fork ID; test saturation and reserve-price failures. Mirror L2 fee semantics only if selected. | Final scheduled specification; R01/R02/R05/R06/R08/R11/R12. |
| 8007 | L1-COMPAT + L2-PARITY for mirrored EVM rules | Final opcode, precompile, state, and transaction repricings. | Update L1 submission/settlement gas envelopes and, for mirrored rules, L2 executor/prover gas tables and differential out-of-gas/refund vectors atomically. | Each repricing included in a final fork; R01/R02/R05/R06/R11/R12. |
| 8025 | OPTIONAL | Optional Ethereum execution-proof gossip/verification. | Default-reject all proof types. A later shadow verifier must bind proof type, guest, chain config, block, inputs, and size and cannot replace mandatory validity/re-execution. | Final spec plus at least two interoperable clients and measured value; R03/R06/R11/R12. |
| 8070 | INHERIT + L1-COMPAT | Sparse EL blobpool sampling/provider behavior. | Use supported client APIs; update publisher/retriever health, custody-set handling, partial availability, reconstruction and retention tests; never treat its probabilities as proof of BL availability. | Supported clients enable eth/72/successor; R02/R08/R11/R12. |
| 8077 | INHERIT + L1-COMPAT at broadcaster boundary | More efficient untrusted transaction announcements. | If BL operates a broadcaster, parse nonce/address hints as unauthenticated, verify fetched hash/payload, penalize mismatches, and never mutate L2 state from an announcement. | Supported networking version enabled; R02/R07/R11. |
| 8079 | OPTIONAL | Possible native L1 execution/verification precompile for rollups. | Keep disabled. Later adapter must bind exact precompile version, chain/fork, execution config, state, proof and unsupported-feature policy while retaining based sequencing and BL validity. | Final EIP, production clients, reference tests, security review, and measured advantage; R01/R03/R05/R11/R12. |
| 8081 | L1-COMPAT + conditional L2-PARITY | Final Hegotá fork bill. | Same fork-bill procedure as 7773; do not implement the draft proposal list as if scheduled. | Fork scope frozen by Ethereum governance; R01/R02/R05/R11/R12. |
| 8136 | INHERIT + L1-COMPAT | More bandwidth-efficient cell-delta propagation among capable peers. | Negotiate partial messages, retain old-peer fallback, reconstruct and verify full required data, and test latency, group-ID spam, score neutrality, partitioning, rollback, and mixed networks. | Client/spec support enabled; R02/R08/R11/R12. |
| 8141 | OPTIONAL + conditional L2-PARITY | Native frame transaction/account-abstraction format and future PQ-signature off-ramp. | Baseline remains ordinary supported transactions. If selected for L2 parity or L1 submission, implement canonical envelope/signature/frame/payer/blob/atomic-revert/receipt/gas/mempool semantics and reject unknown schemes. | Final fork inclusion plus wallet/client ecosystem readiness; R01/R02/R04/R05/R09/R11/R12. |
| 8142 | L1-COMPAT | Execution payload carried and reconstructed through payload blobs, with BAL/witness/header coupling. | Version DA envelope and Engine API; bind payload-blob count/order, commitments/proofs, header, BAL/witness, rollup proof and reconstruction; test withholding, corruption, fee competition and rollback. | Final fork inclusion and stable client APIs; R02/R03/R05/R08/R11/R12. |
| 8184 | OPTIONAL/RESEARCH, disabled for private claims | Public commit-before-reveal encrypted mempool behavior. | Do not use for PHI or witness transport. If later used for non-PHI L1 submission, isolate tickets/ciphertexts/key publishers and test non-reveal, bad keys, fee/nonce charging, rejected-payload recovery and FOCIL interaction. | Final spec plus satisfactory PQ encryption/custody review; R02/R07/R10/R11. |
| 8198 | INHERIT + L1-COMPAT | Shorter configurable slots and proportionally changed gas/blob/timing parameters. | Remove hard-coded slot assumptions; update deadlines, finality/reorg windows, batch cadence, gas/blob per-block limits, weak-subjectivity/DA windows, monitoring and p95 capacity. Faster based-rollup latency is inherited only after these pass. | Scheduled slot-duration change; R02/R06/R07/R08/R09/R10/R12. |
| 8200 | L1-COMPAT + L2-PARITY for mirrored precompiles | Final EVM bytecode replacements and gas behavior for long-tail precompiles. | Pin bytecode/codehash/gas at L1; if mirrored, update L2 executor/prover and differential vectors for RIPEMD-160, MODEXP and BLAKE2f. Do not touch BL SHA3-512 authority. | Each replacement finalized and scheduled; R01/R02/R05/R11/R12. |
| 8250 | OPTIONAL + conditional L2-PARITY | Protocol-managed keyed nonces for frame transactions. | If frames are selected, bind sorted bounded nonce keys, common sequence, sender, signature hash, storage, first-use gas, consumption and replay. Preserve separate retry-stable attempt/nullifier identity. | 8141 and 8250 final/scheduled and shared-sender throughput benefit measured; R04/R05/R07/R11/R12. |
| 8272 | OPTIONAL + conditional L2-PARITY | Protocol recent-root references for frame validation. | If selected, bind writer/salt/source ID/slot/root/window/system storage/signed envelope; reject current/future/expired/absent/overwritten/duplicate roots; keep BL private state authoritative. | 8141 and 8272 final/scheduled with a proven privacy-root use case; R04/R05/R07/R11/R12. |
| 8297 | INHERIT + L1-COMPAT; optional L2-PARITY | A different L1 state tree, witness/proof shape, and possibly hash after finalization. | L1 clients own the tree. Update any light-client/storage-proof/witness adapter and vectors. Adopt it inside L2 only through Gate 2E/R11 equivalence, migration, privacy, PQ and resource gates; never copy a draft hash. | Final tree/hash/fork conversion and client proof APIs; R01/R02/R04/R05/R06/R11/R12. |

### Non-EIP through-line action summary

| Through-line | Inherited L1 effect | Direct Blind Ledger response |
| --- | --- | --- |
| Faster confirmation/finality, decoupled or one-round consensus, attester caps | Potentially lower based-rollup latency and different safety/liveness windows. | Fork-aware observer and bridge/exit policies must use the deployed safe/finalized semantics; measure again and never infer finality from a fast head signal. |
| Secret proposers, distributed building, VDF, attester–includer separation, 51-percent recovery | Different censorship, role, randomness, and recovery behavior. | Expand R07/R10 fault injection and remove role-identity assumptions; bind recovery to canonical finalized evidence. |
| Higher DA, streaming, leanDA/PQ sampling, removal of blob transaction type | More or differently transported public bandwidth. | R08 must version the publisher/retriever/reconstruction envelope; capacity rises only after complete measured publication and independent reconstruction. |
| Gigagas/teragas and gas/blob futures | Potential capacity/economic changes. | Admission and fee models consume live measured resource vectors; no projected multiplier or future capacity is pre-sold. |
| leanCL/leanVM/leanXMSS/PQ registry/PQ precompiles/PQ blobs | Gradual reduction of Ethereum’s external classical risk. | Track deployed primitives in the composed security ledger and adapters. Do not alter the specialized BL proof or claim end-to-end PQ early. |
| Frames, ephemeral keys, private ETH/privacy pools/zkzk frames | Potential account and privacy interoperability. | Optional, non-PHI adapters only; BL fixed shape, custody, nullifier/state, and dual-PQ authority remain independent. |
| VOPS, hyper-scaled/endgame state, RISC-V/evm-asm, SFI/CFI, tech-debt reset | Possible future execution/state architecture changes. | Research/watch until specifications stabilize; then enter R01/R11 through explicit equivalence and migration gates, never by inference from the map. |

## Lockstep L1 upgrade lifecycle

Blind Ledger moves in lockstep by preparing before L1 activation and failing safely at activation,
not by copying every draft immediately:

1. **Discover:** R01 records the EIP/source commit, status, fork proposal, affected EL/CL/Engine/
   networking/EVM/DA surfaces, and impact class. A map label alone cannot enable code.
2. **Scope freeze:** when Ethereum freezes a fork bill, R01 produces an
   `ethereum_compat_manifest` containing chain/genesis identity, fork name/digest/epoch or
   timestamp, EL/CL client commits, included EIPs, Engine API version, transaction/receipt types,
   EVM revision, gas/precompile schedule, slot/finality constants, blob/cell parameters, state/
   witness format, and explicitly disabled optional features.
3. **Implement:** R02-R11 update only the affected adapters and theorem boundaries identified above.
   Every parser and verifier dispatches on the manifest’s exact fork/version; no “latest” behavior.
4. **Differential test:** run canonical upstream vectors plus cross-client/devnet fixtures, old/new
   fork-boundary blocks, malformed/unknown variants, reorgs, rollback, DA withholding, and privacy
   scans. L2-PARITY changes compare executor, prover, independent verifier, and receipt.
5. **Rehearse:** before L1 activation, R12 runs the complete synthetic claim-to-finalized-Ethereum
   path on the exact release candidates, including one rollback and mixed old/new peer/client cases.
6. **Activate atomically:** the supported L1 fork manifest, L1 observer, DA publisher/retriever,
   settlement contracts/configuration, L2 EVM/prover when applicable, verifier, monitoring, and
   rollback plan activate as one governed version.
7. **Fail closed but preserve exits:** if the observed fork digest, Engine payload, transaction/
   receipt type, proof type, DA mode, or EVM revision is unknown or only partially supported, stop
   accepting and publishing new L2 batches. Continue observing L1 and permit only the reviewed safe
   exit/recovery path from the last supported finalized state.
8. **Post-activation verify:** reconcile canonical blocks, receipts, DA reconstruction, finality,
   bridge accounting, and p95 resource/capacity evidence before claiming the inherited benefit.

The compatibility manifest is configuration/evidence, not a new roadmap package. R01 owns its
schema and source pins; R11 owns activation/migration/rollback; R12 owns end-to-end qualification.

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

These obligations refine the existing 12 packages; the local/synthetic fixture now satisfies their
internal engineering boundary, while live-client, production-verifier, deployment, audit, and
activation claims remain expressly outside this evidence.

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
