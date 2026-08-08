# Blind Ledger rejected architecture ledger

Updated: 2026-08-02

Status: authoritative non-executable rejection record. Entries here preserve why a path failed and
what evidence remains useful. Nothing in this file is an approved fallback, dependency, acceptance
format, or activation path.

Former active documents containing complete intermediate measurements and decision sequences are
preserved under `history/`. Their imperative language is non-executable. Use this ledger for the
rejection decision, `history/` for verbatim provenance, and current architecture documents for
implementation.

## Dedicated L2 / based-rollup architecture

Decision: rejected and removed from the active source tree.

The application does not need a second execution chain. Its throughput, ordering, idempotency,
recovery, and payment workflow belong in a strong state-owned database. Mandatory application ZK
provides private rule enforcement; a native verifier can gate one atomic database transition.
Adding an L2 duplicated state, proof, availability, sequencing, bridge, upgrade, and incident
surfaces without proving source honesty, policy correctness, signer integrity, or database
availability.

Ethereum remains admissible later as a direct compact checkpoint destination. Public checkpoints
must contain no PHI and cannot replace the operational database or mandatory application proof.
The removed Wave 5 code and contracts remain recoverable from Git history.

## RISC Zero 3.0.5 backend

Decision: removed from the active source tree.

The isolated experiment verified one non-development receipt and matched the ordered 12-field
Python commitment envelope. Its measured proving time was 1,472.797364 seconds and verification
time was 0.134665 seconds. It did not prove the full claim parser, governed policy and oracle
membership, sequential nullifier transition, payment state, native Blind Ledger proof composition,
or Ethereum settlement transition. More importantly, it is not the selected absolute-PQ proof
boundary and would add a second proof stack, guest toolchain, receipt grammar, and dependency graph
without satisfying the frozen theorem.

The removed workspace and guest lock SHA-256 values were:

- `2D4B81A46864741474432DE6C01FCE0AAA119E7D10F96B29788CB3C0A7C084A7`;
- `F8B76FE443668B989FC71C2C310755CC5A79F8C14F292B92F44DEFFD4B1342C6`.

The two originally ignored lockfiles are preserved outside the source tree under
`cache/retired-source-locks/20260731-risc0/`. The tracked source remains recoverable from the Git
parent of the cleanup commit. Reintroduction requires a new theorem-level security decision, not a
performance comparison.

## Official Stwo/QM31/Blake2s experiment

Decision: removed from the active source tree.

The narrow experiment proved aggregate decision and value-conservation constraints quickly, but
the pinned default was validity-only, `witness_hiding=false`, nominally about 13 security bits in
the recorded profile, and bound to QM31, Blake2s, a small FRI configuration, and proof-of-work.
Those choices violate the selected degree-16 Fp16 challenge, SHA3-512 authority, authenticated
interactive public coin, native hiding, and 256-bit composed-security requirements. Its
hiding-required mode correctly failed before trace allocation.

Retained identities:

- upstream commit `aeceb74c58184d7886ebd7f34a7453fee714ca40`;
- source tree `debdb3804a656654016896c4d292293fe07ccff3`;
- archive SHA-256 `AF979C0BA6F6D1F1BCFDF4AB8D6B444E83F65FC2C6471BF404CCE5B063C329E6`;
- wrapper lock SHA-256 `D8136C780F28D9503E979AA895DAEE51D63B293EE414E739AD1D6FFA660B402F`;
- vendored lock SHA-256 `F245C0DFCB724F1D40DCACE6B3D58C8827F2D647C7CB22FA02A1026F985E62D5`;
- no-std check lock SHA-256 `7EFC72ECC6FAB4CF014AD5676200FAB10B7528CB75800C6EF2507C1EC184A342`;
- Apache-2.0 license SHA-256 `6FC3AE0CC00EEAC4C08B33D060CE3725438DCDE152DC571E08F3D8E6F86B3B8F`.

The source remains recoverable from the Git parent of the cleanup commit. The selected Rust core
may retain independently implemented Circle/field reference algebra where it is part of current
tests; that is not a dependency on or activation of the removed Stwo backend.

## Direct monolithic SHA3 AIR/STARK layouts

Decision: rejected as release architectures; narrow differential code may remain only where a
current test imports it.

The monolithic path has a 9,034,606,313,472-byte live-memory lower bound. Its disk-streaming model
requires 950,757,738,236 bytes of scratch, and simple de-duplication still projects
554,259,695,356 bytes. All exceed the 5,000,000,000-byte resident and strictly-below-5,000,000,000-
byte scratch gates by orders of magnitude. The selected shared-bus semantic lane plus Boolean GKR
eliminates duplicate full-source replay.

## Generic typed-AIR oracle lifetime as the complete H4 route

Decision: rejected as the complete-proof storage architecture. The typed C0 AIR remains the
authoritative executable semantic/differential oracle and its native readback seam remains useful;
this rejection is limited to proving it as a second full generic main/interaction/composition
oracle owner beside H4.

The exact K128 v5 program has 56 tables, 79 lookups, 1,806 public inputs, and a 23,906,457-byte
binary. The native `GENERIC_AIR_ORACLE_LAYOUT_V1` model derives 13,808,394,080 persistent oracle
bytes plus 1,135,869,952 peak temporary bytes, for 14,944,264,032 proof-owned peak scratch bytes.
That is 2.99 times the immutable strictly-below-5,000,000,000-byte scratch cap. The separate
22,975,297,336-byte required-free-space value includes filesystem headroom and a volume reserve;
it is not substituted for the proof-owned scratch comparison.

Source-level lookup shaving cannot repair a route whose 4,775,739,392-byte main oracle already
nearly consumes the entire scratch cap and whose persistent lifetime retains main, interaction,
composition, trees, and witness concurrently. Reconsideration requires an implemented and
independently verified lifetime architecture that never owns the aggregate oracles concurrently,
preserves openings/composition/DEEP verification exactly, beats the complete H4 boundary, and
passes the unchanged scratch gate. A model or plan alone cannot restore eligibility.

## Retired Hint-MLWE 392-bit gate and hidden-state affine screen

Decision: retained as reference source only; removed from active test collection.

The `experiments/bl_pq512_hint_mlwe_392/` directory records the former 392-bit feasibility
profile and its hidden-state affine projection. It is not the current 256-bit security ledger,
the selected Construction 8.2 proof path, a production commitment backend, or a Gate 2E/H5/H6
qualification input. It lacks the complete reduction/composition theorem, reviewed estimator
evidence, authenticated interactive transcript proof, and qualified K128/K512 resource evidence.
Its positive tests therefore supplied no current release or trust-boundary protection and were
removed from active pytest collection on 2026-08-05. The source, README, historical bounds, and
rejection rationale remain available for reference; the removal does not promote or activate this
construction.

The standalone positive `oracle_layout_optimizer` tests were also removed from active collection.
Their expected optimizer identity and profile minima were stale (the focused run reported 54
passes and 2 failures), and no current selected producer, verifier, manifest, or qualification
record imports that optimizer. The source and attack-side hard-boundary rejection tests remain,
so removing the stale positive gate does not remove the current rejection evidence or admit the
generic typed-AIR oracle lifetime route.

## Quadratic all-pairs state-key uniqueness as the H4 relation

Decision: rejected as the selected H4 uniqueness architecture; retained as an executable
differential and attack control.

The control checks all unordered slot pairs in both before/after phases using the injective
two-Fp16 key packing, Boolean selector witnesses, inverse nonzero checks, four sparse GKR layers,
message-before-challenge public coin, and two final PCS input claims. Duplicate source keys cannot
be repaired by selector or inverse forgery. The compact relation also exposed and corrected a
pre-existing raw-output declaration mismatch: the implemented relation has 26 constraints, not 28.

Exact release controls independently verified:

| Capacity | Pairs/phase | Source bytes | Authenticated rounds | Prove seconds | Verify seconds |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 8,128 | 4,194,304 | 142 | 21.902903 | 2.878161 |
| 512 | 130,816 | 67,108,864 | 174 | 426.679855 | 38.789283 |

The K512 uniqueness proof alone is 2.37 times the 180-second complete-proof ceiling before the
hash proof, state commitment, simulator, or receipt work. CPU/GPU overlap cannot rescue a stage
that exceeds the entire complete boundary. Reconsideration requires a complete-boundary measured
sub-180-second result without weakening fixed capacity, both-phase uniqueness, authenticated coin,
PCS binding, hiding, or the 512-slot workload. Gate 2E proceeds with a subquadratic construction.

## BaseFold, zkDeepFold, and older PCS lanes

Decision: off the active path.

BaseFold planning and benchmarks were superseded by Construction 8.2 random-padded interleaved
Reed--Solomon. zkDeepFold was investigated but never joined to the selected proof. The inequality
`2^18 > 473 * 21^2` proves only the retired `mu=21`, `s=473` simulator's interpolation condition;
it provides no hiding, composition, query-reduction, implementation, or measurement credit here.
Old BLPQPRF1, incomplete answer-code, and incomplete Merkle geometries are rejected by the current
retired-format KAT and are not fallback parsers.

The five standalone BaseFold benchmark/ledger binaries and the isolated BaseFold hiding module were
removed from `bl_pq512_crypto_core` on 2026-07-31 after a repository-wide reference check found no
current importer. Construction 8.2 implementation and verifier code were not changed.

## B=64, merged layers, and scalar replay

Decision: rejected.

B=64 was a nonprotocol arithmetic spike and did not preserve the selected wiring/masking schedule.
Its standalone Rust binary was removed from the selected crate on 2026-07-31.
The merged degree-11 theta/degree-3 chi path relied on an invalid characteristic-two shortcut,
increased degree, and was slower than the seven-layer control. Scalar full-source replay and
duplicate row/codeword representations add avoidable work and memory. The current B=16 plan uses
seven explicit layers, a 3.225600 MB one-time topology upload, same-source aliases, one-pass semantic
hash/shard capture, and exactly one 48-layer future worker.

## Cairo-only and deleted Solidity-mock settlement

Decision: retained only as protected semantic and settlement references.

The Cairo source is not the selected strict-PQ proof backend. The former Solidity verifier was a
mock and was deleted with the L2 design. Neither path may claim production database authorization
or Ethereum-secured settlement.

## Rejection discipline

A rejected path can return only after a written first-principles review proves that it satisfies
the complete theorem, strict privacy and PQ boundaries, exact ABI and atomic state binding, current
resource gates, independent verification, and a measured advantage. Fashion, familiarity, or a
component benchmark is insufficient.

## Historical provenance index

| Rejected or superseded area | Detailed preserved evidence |
| --- | --- |
| RISC Zero and Stwo experiments | This ledger, dated `STATE.md` sections, and Git history before cleanup commit `960d5a1` |
| Direct SHA3 AIR/STARK resource failures | Archived throughput-plan sections 3-5 and dated `STATE.md` measurements |
| BaseFold, zkDeepFold, and legacy PCS grammars | Archived throughput/coprocessor documents and the retired-format KAT |
| B=64, merged layers, scalar replay, excess worker lifetime | Archived coprocessor sections 8.1-8.2 and H3/H4 records |
| Superseded H3/H4 timing/resource checkpoints | Archived roadmap, throughput plan, crate README, and dated `STATE.md` sections |
| Current accepted replacement | `CURRENT_TECH_STACK.md`, the active coprocessor contract, and active source |

The archive split changes documentation routing only. It does not restore code, alter proof bytes
or the execution manifest, or grant qualification credit to a historical result.
