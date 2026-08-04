# Claim-proof zero-knowledge backend decision

Original qualification decision: 2026-07-12

Updated: 2026-08-02

Status: the removed RISC Zero qualification remains dated historical evidence only. Its active
selection and source tree are superseded by `docs/CURRENT_TECH_STACK.md` and the rejection record
in `docs/REJECTED_ARCHITECTURES.md`. The custom strict-PQ
path now produces manifest-bound K128 and four-shard K512 H4 prototypes through independent
verification in 29.974129/120.460733 seconds. Gate 2E state selection, the H5 repeated p95/resource
campaign, H6 suite qualification, and final suite selection remain open.

`docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` separates internal implementation from the final audit.
No external party is required to choose or build the backend. The exact internally qualified suite
may become `BUILT_AUDIT_PENDING`; only the later audit can make it eligible for production
activation.

## Current production-target decision

The selected target is heterogeneous: a fixed-shape application-specific M31 semantic AIR plus a
shared-bus Boolean GKR SHA3 coprocessor over Fp16, both under one native-hiding,
dual-PQ-authenticated interactive public-coin session and the `BL-PQ512-v1` shadow-state profile.
S-two/Circle-STARK remains the algebra/PCS basis for the semantic module, not the SHA3 coprocessor.
The H4 bus PCS is Construction 8.2 of ePrint 2026/391 over random-padded interleaved
Reed--Solomon codewords; zkDeepFold/BaseFold remains a retired differential control.

Current Wave 1 (historical Wave 1A) seals the synthetic nonactivating executable relation. Current
Wave 2 (historical Wave 1B) owns the theorem-matched proof and throughput recovery; current Wave 3
(historical Wave 1C) later owns authoritative verifier/state/custody. The active execution plan is
`docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md`.

Frontier candidates in `docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` are conditional bake-offs,
not a replacement decision. The H4 K128/K512 evidence strengthens the heterogeneous primary path.
An alternative may replace it only after complete evidence under the identical statement,
security, privacy, state, resource, repeat-campaign, and independent-verification gates proves a
strictly better feasible point.

The v1 regression kernel proof is exactly 28,643,096 bytes at 945 queries. The authoritative
`BLPQPRF2` path independently verified a 6,755,933-byte compact proof in its latest real dual-PQ run;
that compact result is historical pre-H4 grammar evidence rather than a complete application proof.
The active Construction 8.2 H4 path now completes K128/K512 through independent verification with
288.412/296.255 MB internal host peaks, 969.999360 MB per-proof tracked device state, and
0.000000 MB scratch. The 9.03 TB monolithic, 950.76 GB streamed, and 554.26 GB de-duplicated
direct-SHA3-STARK layouts remain retired. These one-run results do not select the suite: 2E state
selection, the complete simulator/composition ledger, H5/H6, and the final identities remain open.
No backend is selected merely because a toy, kernel, component, or single successful proof is fast
or small.

The current H4 state-composed bridge is a fixed-shape nineteen-claim integration seam with exact
6,727/6,995 K128/K512 schedules. It covers operation/snapshot equality, Boolean presence,
empty-slot zeroing, and linear square-free uniqueness. Conditioned simulator mechanics are closed;
complete proof artifact leakage, backend admission, H5, and H6 remain open and nonactivating.

R24's exact pre-implementation continuation is
`docs/BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md`. It permanently rejects the current
QM31/Blake2s/default S-two suite for BL-PQ512, records a conditional wider-field/SHA3-512 direction,
and deliberately leaves the candidate suite ID unset and nonactivatable.

R33 historically supplied the nonactivating Wave 1A host semantic input to this decision. It adds authenticated
per-member/provider payment maps and a 16-table relation-inventory estimator with declared
K128/K256/K512 dimensions and Python/`no_std` Rust declaration parity. A later audit proved that the
estimator has no trace cells or constraint equations, so its dimensions are not theorem inputs.
Successor Wave 1 work replaced that handoff with the sealed executable relation and exact global
SHA3 schedule. This chronology does not change the rejected-suite decision, `proofSuiteId=null`, or
activation status.

R35 was the historical sibling-backend construction stage. Its Python/`no_std` Rust scalar
references covered
Fp8-excluding OODS, conjugate-pair degree correction, Circle-FRI folds, and typed SHA3-512 mixed-
domain commitments. The Python control plane adds unselected theorem-parameter candidates, exact
typed challenge ordering, mandatory pre-challenge FRI masks, and the pre-dense-schedule 16-table hiding worksheet.
The current K512/beta-1 interface schedule additionally binds all six variable-width attached
domains, globally nonresetting batching-power offsets, and all 17 gap-inclusive folds in matching
Python/Rust KATs. This is interface evidence; final SHA3-expanded oracle widths remain unset.
The direct Circle trace-evaluation map additionally has an exact cross-language CRT certificate for
multiple degree-16 and base-domain evaluations. The canonical quotient mask and source-aligned split
rule also match across languages, and a byte-oriented SHA3-512 AIR now freezes a 1,632-column/1,024-
lookup core and 1,704-column/1,096-first-round-lookup sponge envelope at composed degree 3 with FIPS
KAT parity. Historical inventories classified 52 and later 50 live SHA3 callsites, followed by an
interim 55-site drift reconciliation. H0 now independently scans both governed source trees and
reconciles 79/79 current callsites, 39 `AIR_REQUIRED`, with exact dynamic measurements for all five
post-R36 additions and fail-closed new-file/noncanonical-form attacks. Both earlier K128
host-recomputation envelopes are historical and forbidden for parameter use. The sealed semantic
topology uses one exact 2,133-byte
oracle bundle per claim plus one ordered execution root; a separate audit tree reuses the leaf
digests. Together with the compact dense claim tree this costs 14,322/28,644/57,288 permutations at
K128/K256/K512. Non-dense
application-port scheduling, final split log-degree/prover integration and lookup-interaction expansion, the Circle simulator, production scalar/SIMD prover/verifier,
parameter selection, and proof-level qualification were open at that checkpoint. The later H4
Construction 8.2 implementation supersedes that implementation status without rewriting the R35
evidence.

This is not approval to publish current S-two receipts for private witnesses. Current S-two is
validity-only. Its production role remains blocked until all trace, quotient, DEEP, FRI, lookup,
interactive public-coin, randomness, strict post-quantum parameter, implementation, and side-channel
gates in `docs/PQ_ZK_SECURITY_ARCHITECTURE.md` pass internal qualification and the exact release
later passes the final independent audit. The internally selected transcript construction is in
`docs/BL_PQ512_S09_INTERNAL_SOLUTION.md`; it does not promote the current kernel.

Backend roles are now:

| Backend | Role |
| --- | --- |
| S-two/Circle-STARK | Primary algebra/performance base for the custom sibling implementation. Upstream QM31, hash, Fiat-Shamir, grinding, and non-hiding defaults are not BL-PQ512 parameters. |
| Shared-bus Boolean GKR over Fp16 | Primary SHA3 coprocessor implementation path. H4 passes the real bridge, native masks, Construction 8.2 PCS, atomic verifier, one-run resource gates, and complete K128/K512 prototypes. The state/composition ledger, repeated H5 campaign, H6 suite qualification, and activation remain open. |
| Shout-like/Twist-like memory checking | Nonactivating read-only/read-write state bake-off against the optimized endpoint-multiproof/sorted-memory control; it must preserve the SHA3-512 root bridge and exact Blind Ledger transcript/security profile. |
| Persistent memory / IRONDICT-derived dictionary / projection RAM / Two-Shuffles relation | Mandatory Wave 2 committed sparse-state bake-off behind one state interface. Published pairing, KZG, VOLE, structured-setup, random-oracle, or two-party backends are not adopted. |
| Jindo / Grand Danois / Hachi / RoKoko-style commitments | Isolated native-hiding PQ commitment experiments for the state bake-off. Each remains unselected pending exact assumptions, parameters, field mapping, public-coin composition, grammar, independent verifier, and laptop evidence. |
| VEIL | Alternative GKR/multilinear hiding-wrapper research only; no reported paper overhead is Blind Ledger qualification evidence. |
| Neo/SuperNeo | Post-K128 lattice folding research only, behind a separate Module-SIS/Ajtai security and parameter review. |
| Plonky3/WHIR/alternative FRI work | Independent Keccak, hiding, proof-size, and query-reduction research only; no audited or theorem-compatible drop-in is assumed. |
| RISC Zero | Semantic and differential oracle plus experimental fallback. The generic VM is not the selected production performance or strict-PQ path. |
| Existing Cairo/S-two statement | Semantic, known-answer, and performance reference only; it is not witness-hiding. |

No currently available backend is a production-ready drop-in satisfying the complete claim,
audited witness hiding, authenticated interactive public coin, exact settlement compatibility, and
the selected strict quantum target. The application relation and H4 K128/K512 prototypes exist;
qualified repeated proof/resource evidence, authoritative state, production settlement verifier,
and final suite identity remain open.

## Historical 2026-07-12 qualification decision

Use a pinned RISC Zero zkVM guest as the leading Privacy V2 claim-proof path. Keep Cairo/S-two as a
differential reference until the complete statement is migrated, but do not publish S-two receipts
for PHI-bearing witnesses.

This paragraph records the decision at the time of the isolated qualification. It is not the current
production recommendation.

This choice does not alter the based-rollup design. The claim receipt is verified inside the L2;
the separate rollup proof still authenticates the resulting L2 state transition to Ethereum.

## Evidence

- RISC Zero's official repository states that only journal outputs are revealed, private inputs and
  execution state remain hidden, default parameters provide perfect zero-knowledge, and the prover
  has an official CUDA feature: https://github.com/risc0/risc0#readme
- RISC Zero's published proof-system description defines its receipt as a zero-knowledge proof of
  RISC-V execution: https://dev.risczero.com/proof-system-in-detail.pdf
- Starknet's official S-two documentation states that current S-two does not provide the
  zero-knowledge feature and exposes unmasked witness commitments:
  https://docs.starknet.io/learn/S-two-book/why-stwo
- Noir/Barretenberg provides genuine zero-knowledge and Solidity verification, but migrating the
  existing Rust policy engine and full Merkle/nullifier behavior would require a separate circuit
  rewrite: https://noir-lang.org/docs/getting_started_manually
- SP1 is an audited Rust zkVM candidate with an Ethereum verifier ecosystem, but the reviewed
  official material did not state the medical-data witness-hiding boundary as explicitly as RISC
  Zero's security statement: https://github.com/succinctlabs/sp1

## Why not an outer wrapper first

An outer proof would need to verify the exact S-two receipt while keeping that inner receipt and its
witness commitments private. No compatible, audited in-guest S-two verifier exists in this archive.
Writing one would add a second cryptographic implementation before solving the existing verifier
gap. A direct Rust guest is the smaller auditable path because existing policy code can be reused.

This reasoning remains relevant to the historical RISC Zero experiment. It does not override the
later measurements, strict-PQ requirement, or selected custom-AIR design.

## Qualification scope

The removed RISC Zero experiment proved and locally verified the exact 12-field V2 commitment
envelope against a Python-generated Starknet Poseidon vector. Its identities and rejection record
are preserved in `REJECTED_ARCHITECTURES.md` and Git history; no RISC Zero source or build path
remains active.

The experiment does not close production blockers. Full adjudication, oracle and policy membership,
Merkle paths, sequential nullifier updates, fixed-size padding, payment state, Ethereum-compatible
receipt compression, Solidity verifier pinning, and independent audit remain required.

The later complete-claim RISC Zero attempt was stopped before proof completion. It reported `191`
segments, at least `199,229,440` guest cycles, and `17` completed intervals totaling `5,464`
seconds. The resulting `17.052680`-hour figure was a linear projection, not a completed proof time.
