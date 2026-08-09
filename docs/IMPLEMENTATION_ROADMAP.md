# Implementation roadmap

Updated: 2026-08-08
Authority: `docs/DATABASE_ZK_ARCHITECTURE.md`

## Scope

This roadmap stops at Phase 2. No L2, rollup, sequencer, bridge, Solidity settlement, or public data-availability system is being built. Ethereum is not a dependency through Phase 2.

All **81 counted packages are internal engineering work**. The reconciled ledger is **33 complete and 48 open**. Completion means local, synthetic, nonactivating evidence only; it never means deployment-ready.

H4 fresh prototype evidence recorded 29.974129 seconds for K128 and 120.460733 seconds for K512. The later qualified H5 campaign recorded p95 32.360845 and 148.861885 seconds. Neither record selects a production suite.

## Phase 0 - architecture correction

- Make the state-owned database authoritative for workflow and payment state.
- Require a mandatory application ZK proof for every payment-relevant private decision.
- Define the native-verifier-to-atomic-database boundary.
- Retire the L2-only R01-R12 code, contracts, operational files, and active documentation.
- Preserve exact proof, policy, state, source, signature, privacy, and activation invariants.

## Phase 1 - surviving system reconciliation

- Keep the fixed 12-field Privacy V2 ABI and authenticated sidecar.
- Keep SHA3-512 authority, M31/Fp16 arithmetic, GKR, Construction-8.2 hiding, authenticated interactive public coin, and dual-PQ signing boundaries.
- Route successful native verification directly into one fail-closed database transition.
- Keep provider-app preflight local and nonauthoritative.
- Reconcile readiness, launch-blocker, evidence, and operator configuration around the database boundary.

## Phase 2 - local qualification

- Prove and verify fixed K128/K512 workloads reproducibly.
- Test parser limits, forged receipts, stale roots, replay, duplicate nullifiers, conflicting retries, concurrency, rollback, and recovery.
- Qualify transaction isolation, idempotency, append-only audit commitments, backup/restore, and
  write-ahead external anti-rollback reservation/finalization recovery.
- Produce an audit-pending evidence packet while `proofSuiteId=null`, `production_usable=false`, and real PHI/payments remain forbidden.

## Start here next

**LB-006 and LB-007 are complete only at the local, synthetic, nonactivating boundary.** LB-007 now
adds the proof-authorized Privacy V2 migration/rollback/recovery transaction, exact subprocess
restart retry, sealed OS-random fresh evidence, mixed-version race rejection, immutable domain
history, fixed-shape differential/privacy checks, and a real dual-PQ Rust proof-to-native-verifier-
to-SQLite lane. Neither closure selects a production database, custody system, proof suite, or
activation profile.

The attempted combined **LB-001/LB-010** run reached a mandatory architecture STOP. The current
`BLPQENV1` version-2 envelope independently verifies one pinned selected AIR/FRI package and its
authenticated transcript, but the only end-to-end fixture is not the complete Wave1A
claim/payment/replay/state theorem. The H4 coordinator retains resource data and child-output
digests rather than a verifier-safe proof, and the typed-state binding retains private execution
material while omitting replayable authenticated transcript evidence. A caller-paired LB-010
receipt/digest path was removed; aggregate status is now always `AGGREGATE_UNQUALIFIED`.

The next bounded major run is to freeze and implement the missing complete-proof composition in
this order:

1. A verifier-safe H4 proof grammar and pure verifier that retain commitments, claims, round
   messages, masked terminals, Construction-8.2 openings/frontiers, and exact authenticated
   transcript evidence without coefficients or witness material.
2. A complete `build_wave1a_global_semantic_bus_program_only` trace producer and proof-native
   equality tying its committed M31 port table to the Fp16 H4 source commitment.
3. A verifier-safe typed-state component containing only the selected proof package,
   authenticated transcript, and public root/payment/replay bindings.
4. A fixed-shape version-3 composite envelope and standalone verifier, followed by raw
   machine-derived Z03-Z12 qualification, including the complete strict-PQ union ledger.

No version-2 receipt, H4 stdout assertion, host comparison, or synthetic manifest may substitute
for those components. `proofSuiteId=null`, `production_usable=false`, and real PHI/payments remain
forbidden. LB-009 and T01-T14 remain after this proof boundary. Exact source/test ownership and
package acceptance statements are canonical in
`experiments/bl_pq512_crypto_foundation/internal_package_matrix.py`.

## Package ledger

| ID | Scope | Status |
| --- | --- | --- |
| S01 | Security foundation 01 | Complete - local, synthetic, nonactivating |
| S02 | Runtime/profile selection | Open - candidate runtime and production suite remain unselected |
| S03 | Security foundation 03 | Complete - local, synthetic, nonactivating |
| S04 | Sidecar and suite/state identity | Open - final suite/state identity is not selected |
| S05 | Security foundation 05 | Complete - local, synthetic, nonactivating |
| S06 | Security foundation 06 | Complete - local, synthetic, nonactivating |
| S07 | Composed security ledger | Open - production qualification remains incomplete |
| S08 | Field/PCS/query parameters | Open - parameters remain candidate-only |
| S09 | Proof grammar and transcript | Open - production identity remains unset |
| S10 | Migration/rotation policy | Open - final policy remains unselected |
| S11 | Reproducible release and SBOM | Open - whole-product closure remains incomplete |
| S12 | Statement and acceptance contract | Open - complete release contract remains incomplete |
| A01 | Fixed profile dimensions | Open - final capacity qualification remains incomplete |
| A02 | Witness/private-slot serialization | Open - final serialization remains unselected |
| A03 | Ordering and canonical encoding | Open - deployment-edge equality remains incomplete |
| A04 | Real/dummy/cover collision boundary | Open - complete proof equality remains incomplete |
| A05 | Fixed-shape qualification | Open - complete-boundary shape evidence remains incomplete |
| A06 | Adjudication gates | Open - final proof qualification remains incomplete |
| A07 | Durable claim-source binding | Open - database registry and proof binding remain incomplete |
| A08 | Durable oracle binding | Open - authority registry and proof binding remain incomplete |
| A09 | Durable policy/ruleset registries | Open - database registries remain incomplete |
| A10 | Adjudication ordering | Open - final proof qualification remains incomplete |
| A11 | Durable payment/state plane | Open - local transactional reference passes; production topology, migration, and qualification remain incomplete |
| A12 | Executable claim and state AIR 12 | Complete - local, synthetic, nonactivating |
| A13 | State-operation proof binding | Open - local native-proof-to-database binding passes; final selected release binding remains incomplete |
| A14 | Wide-value public projection | Open - whole-boundary convergence remains incomplete |
| A15 | Durable authoritative roots | Open - root/master selection remains incomplete |
| A16 | Claim prover/verifier integration | Open - real candidate proof reaches the local database reference; final suite/release integration remains incomplete |
| Z01 | Proof, hiding, and verifier 01 | Complete - local, synthetic, nonactivating |
| Z02 | Entropy and zeroization | Open - worker-owned OS entropy and zeroization pass locally; complete production boundary remains incomplete |
| Z03 | Semantic witness masking | Open - complete composition remains incomplete |
| Z04 | Auxiliary/lookup masking | Open - complete inventory remains incomplete |
| Z05 | Quotient/composition randomization | Open - production qualification remains incomplete |
| Z06 | Domain separation/raw-opening exclusion | Open - complete qualification remains incomplete |
| Z07 | Implicit-query masking | Open - complete inventory remains incomplete |
| Z08 | PCS masks and folding entropy | Open - production qualification remains incomplete |
| Z09 | Transcript custody and statement binding | Open - durable custody remains incomplete |
| Z10 | Strict-PQ parameter qualification | Open - hard gate remains unresolved |
| Z11 | Abort/retry/crash simulator | Open - complete simulator qualification remains incomplete |
| Z12 | Parser/fuzz/unlinkability | Open - fixed 64 MiB component grammar passes; whole-product qualification remains incomplete |
| P01 | Performance and qualification 01 | Complete - local, synthetic, nonactivating |
| P02 | Performance and qualification 02 | Complete - local, synthetic, nonactivating |
| P03 | Performance and qualification 03 | Complete - local, synthetic, nonactivating |
| P04 | Performance and qualification 04 | Complete - local, synthetic, nonactivating |
| P05 | Performance and qualification 05 | Complete - local, synthetic, nonactivating |
| P06 | Performance and qualification 06 | Complete - local, synthetic, nonactivating |
| P07 | Performance and qualification 07 | Complete - local, synthetic, nonactivating |
| P08 | Performance and qualification 08 | Complete - local, synthetic, nonactivating |
| P09 | Performance and qualification 09 | Complete - local, synthetic, nonactivating |
| P10 | Performance and qualification 10 | Complete - local, synthetic, nonactivating |
| P11 | Performance and qualification 11 | Complete - local, synthetic, nonactivating |
| P12 | Performance and qualification 12 | Complete - local, synthetic, nonactivating |
| T01 | Whole-product vector schema | Open - canonical schema is not frozen |
| T02 | Approved-claim KATs | Open - cross-implementation closure remains incomplete |
| T03 | Denial/priority KATs | Open - final proof evidence remains incomplete |
| T04 | Dummy/padding/mixed KATs | Open - final proof evidence remains incomplete |
| T05 | Capacity/boundary KATs | Open - final proof evidence remains incomplete |
| T06 | Replay/retry/revision KATs | Open - final proof evidence remains incomplete |
| T07 | Source/policy/oracle/signer attacks | Open - final-proof attack closure remains incomplete |
| T08 | Money/serialization attacks | Open - final-proof attack closure remains incomplete |
| T09 | Proof/profile/schema rebinding | Open - attack closure remains incomplete |
| T10 | Whole-product property/fuzz coverage | Open - coverage remains incomplete |
| T11 | Artifact/linkability scan | Open - whole-product scan remains incomplete |
| T12 | Leakage/shape qualification | Open - whole-product qualification remains incomplete |
| T13 | Complete-boundary resource measurement | Open - final measurement remains incomplete |
| T14 | Language/proof/attack/integrity convergence | Open - final convergence remains incomplete |
| O01 | Operations and release evidence 01 | Complete - local, synthetic, nonactivating |
| O02 | Operations and release evidence 02 | Complete - local, synthetic, nonactivating |
| O03 | Operations and release evidence 03 | Complete - local, synthetic, nonactivating |
| O04 | Operations and release evidence 04 | Complete - local, synthetic, nonactivating |
| O05 | Operations and release evidence 05 | Complete - local, synthetic, nonactivating |
| O06 | Operations and release evidence 06 | Complete - local, synthetic, nonactivating |
| I01 | Signed-source and external adapters 01 | Complete - local, synthetic, nonactivating |
| I02 | Signed-source and external adapters 02 | Complete - local, synthetic, nonactivating |
| I03 | Signed-source and external adapters 03 | Complete - local, synthetic, nonactivating |
| I04 | Signed-source and external adapters 04 | Complete - local, synthetic, nonactivating |
| I05 | Signed-source and external adapters 05 | Complete - local, synthetic, nonactivating |
| I06 | Signed-source and external adapters 06 | Complete - local, synthetic, nonactivating |
| I07 | Signed-source and external adapters 07 | Complete - local, synthetic, nonactivating |
| I08 | Signed-source and external adapters 08 | Complete - local, synthetic, nonactivating |
| O12 | Reproducible whole-product evidence | Complete - local, synthetic, nonactivating |

## Final independent Security Audit Gate - not counted

After all 48 open internal packages close and the exact release reaches `BUILT_AUDIT_PENDING`, one independent gate reviews proof soundness and privacy, strict-PQ assumptions, native verifier/parser safety, signed-source authority, database atomicity and recovery, custody, adapters, supply chain, and operations. Audit findings return to the owning package.

## Beyond Phase 2

Production database/custody integration, live credentials, legal/payment authorization, independent audit acceptance, and operator activation are later work. A compact periodic Ethereum L1 checkpoint may be designed later as an additive public commitment; it is not an execution layer and cannot weaken mandatory application ZK.
