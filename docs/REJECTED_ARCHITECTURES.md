# Blind Ledger rejected architecture ledger

Updated: 2026-08-02

Status: authoritative non-executable rejection record. Entries here preserve why a path failed and
what evidence remains useful. Nothing in this file is an approved fallback, dependency, acceptance
format, or activation path.

Former active documents containing complete intermediate measurements and decision sequences are
preserved under `history/`. Their imperative language is non-executable. Use this ledger for the
rejection decision, `history/` for verbatim provenance, and current architecture documents for
implementation.

## Rejected Ethereum-roadmap shortcuts

The exact accepted outer-chain contract is
`ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`. The following shortcuts are rejected:

| Rejected shortcut | Reason |
| --- | --- |
| A dedicated or committee sequencer as canonical release ordering | Violates the compulsory based-rollup decision. Ethereum ordering must determine the canonical L2 history. |
| Optimistic-only, re-execution-only, or optional validity | Fails the mandatory Blind Ledger claim-proof plus containing rollup-validity boundary. |
| EIP-7707 as the current access-list tracker | Stagnant and absent from the live map; EIP-7928 BAL is the current Review surface. Historical mentions may remain only in history. |
| EIP-7503 wormholes as Blind Ledger privacy/PQ | Stagnant, different burn/remint semantics, and the proposed curve proof does not satisfy the strict-PQ/private claim theorem. |
| EIP-8184 LUCID as PHI transport or PQ encryption | The draft explicitly lacks an enshrined satisfactory PQ encryption scheme and introduces public tickets/commitments plus off-protocol key release. |
| EIP-8025 optional execution proofs as the production verifier | Optional/shadow evidence cannot replace authoritative execution, the Blind Ledger verifier, or mandatory rollup validity. |
| EIP-8079 native rollups as a release prerequisite | Draft with security, tests, and reference implementation incomplete/TBD; admissible only as a later versioned adapter. |
| Ethereum leanVM as the Blind Ledger inner proof | It targets Ethereum PQ-signature aggregation and does not prove the sealed claim relation, state transition, native hiding, or atomic receipt. |
| Ethereum BAL as private CBAM | BAL is a public execution/witness artifact; CBAM is a fixed-padded private semantic access contract. |
| Draft gas/slot/DA north stars as measured capacity | Roadmap labels and EIP projections are not deployed fork behavior or end-to-end Blind Ledger measurements. |
| Encrypted claim/medical payloads in public DA | Encryption does not remove metadata, retention, custody, or future-decryption risk and violates the strict privacy boundary. |

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

## Cairo-only and Solidity-mock settlement

Decision: retained only as protected semantic and settlement references.

The Cairo source is not the selected strict-PQ proof backend. The Solidity verifier used in tests
is a mock, the repository lacks a production `INativeStarkVerifier`, and the historical Cairo
output/settlement schema mismatch is unresolved. Neither path may claim Ethereum-secured settlement.

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
