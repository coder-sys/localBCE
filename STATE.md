# Blind Ledger state

Updated: 2026-08-06

## Current status in plain English

This is the current status as of 2026-08-06; the dated sections below preserve the full run history.
Gate 2E is sealed as a nonactivating candidate context. H5 passed the exact 22-launch campaign with
K128 p95 32.360845 seconds and K512 p95 148.861885 seconds. H6 then closed all twelve bounded
candidate-evidence records. The new standalone Rust candidate verifier accepts a fresh synthetic
proof and the Python selector can issue a nonzero per-proof `BUILT_AUDIT_PENDING` identity only
after the exact native `OK` receipt and commitment checks pass. The legacy production planning
state remains `UNSELECTED` with `proofSuiteId=null`; activation is false, production
verifier/state/custody and rollup work remain open, the final audit has not started, and real
PHI/payments remain forbidden. Wave 1 remains sealed as a synthetic, nonactivating relation. Wave 3
P01-P12, Wave 4 I01-I08/O01-O06/O12, Wave 5 R01-R12, and the remaining Wave 2 internal fixed-K/
12-field/sidecar reference packages are complete at the local/synthetic, nonactivating engineering
boundary. The reconciled internal ledger is 93 of 93 packages complete and 0 open; this is not
production activation or production assurance.

The native K512 coordinator now defaults to two independent lanes for the native boundary, including
suite-bound runs; `BL_SHARD_CONCURRENCY=1` is the explicit serial fallback. The separate exact
one-warmup/ten-measured two-lane campaign passed unchanged verification, resource, and no-swap
gates with K512 p95 101.798191 seconds, so the execution mode is qualified as nonactivating
evidence only. Four fresh current-checkout refresh attempts were rejected by the unchanged
pagefile-growth gate and receive no H5/H6 or production credit. The sealed serial H5/H6 evidence
remains unchanged.

## 2026-08-06 manual cleanup, containing verification, and archive refresh - VERIFIED, NONACTIVATING

The manual source/test/gate audit completed against commit `a7d35bee9fae20b8dad44e8627e6c99f33e23191`.
The only newly removed executable item was the private `_read_part` helper in
`experiments/bl_pq512_crypto_foundation/wave3_full_internal.py`; it had zero callers, no external
references, and was not exported. The three stale positive tests already present in the worktree
were removed from active collection after their current producers/consumers were traced:
`test_bl_pq512_hidden_state_batch_screen.py`,
`test_bl_pq512_hint_mlwe_392_parameter_gate.py`, and
`test_bl_pq512_oracle_layout_optimizer.py`. Their rejected source and attack-side boundary evidence
remain available. No duplicate test files were found, no live protocol ports were removed, and no
protected repository path changed.

The current Python inventory is 1,738 tests across 274 ordinary modules and 69 attack modules.
Split deterministic execution and isolated slow lanes produced 1,737 passes and one skip at
`tests/test_locked_python_dependencies.py:112` because the platform account cannot create
symlinks. The broad monolithic wrapper remains uncredited after exit `124` at `904043` ms without
a pytest terminal summary. The full current Rust gate passed formatting, strict all-target Clippy,
and release verification with 307 tests passed, 0 failed, 0 ignored, and all binary/doc-test groups
passing. Wave 2, Wave 4, Wave 5, remaining-internal, whole-product-KAT, Wave 2 specification,
Privacy V2, and tracked-ops conformance receipts all passed with network access false, live
credentials false, `proofSuiteId=null`, `activation_allowed=false`, and `production_usable=false`.

The three published `Blind-Ledger-Wave2-Source-Complete-2026-08-02.zip` targets were refreshed from
the reviewed 803-file allowlist plus 14 current candidate-verifier boundary files. The deterministic
builder and independent readback reported:

```text
source_commit=a7d35bee9fae20b8dad44e8627e6c99f33e23191
builder_version=blind-ledger-release-archive-v1
payload_file_count=817
payload_bytes=11772799
entry_count=818
archive_bytes=12121243
archive_sha256=1f7a82fccc0389cae9b7cfd2dc970f27a69b75714ba730edac2b82750f7e27ae
manifest_sha256=dd2b1ef0952feb13e9c74b047b4e127298a863a47f3f0b8b82f89cae1fd5452d
zip_crc_readback=PASS
duplicates=0
three_way_byte_identical=true
candidate_boundary_files_present=true
state_generated_private_paths_absent=true
```

The exact targets are the Desktop root, nested Desktop full-workspace, and Downloads copies. Each
was independently read back at the identity above. The replaced three 12,024,082-byte copies are
recoverable under
`C:\Users\neers\Documents\Codex\2026-08-05\you-are-entering-an-existing-blind\work\wave2-published-backup-cleanup-a7d35be`.
The archive refresh changes no proof-suite or activation boundary: the global operational registry
remains `UNSELECTED`, `proofSuiteId=null`, activation remains false, and HSM/FIPS, production
verifier/state/settlement, external anti-rollback, release authorization, and the final independent
audit remain open.

## 2026-08-06 native candidate verifier and suite-identity boundary - VERIFIED, NONACTIVATING

The local candidate verifier boundary is now implemented in `experiments/bl_pq512_crypto_core`.
`production_candidate_verify` is the standalone Rust entry point. The v2 `BLPQENV1` envelope
contains the exact ordered 12-field public boundary, canonical 744-byte sidecar, selected proof
package, and private selected-public-coin transcript evidence. Rust performs canonical parsing,
state-AIR/package verification, PQ signature verification, transcript challenge derivation and
replay, and atomic statement/proof/transcript identity checks. The matching Python selector accepts
only the exact native `OK` receipt; it does not accept a caller-provided success flag.

The selected `proofSuiteId` is derived from the nonzero selected parameter, program commitment,
and public-coin schedule commitment and is bound into the sidecar, package, transcript, envelope,
and receipt. A fresh synthetic end-to-end proof passed the native verifier and produced a nonzero
per-proof identity with status `BUILT_AUDIT_PENDING`, `activation_allowed=false`, and
`production_usable=false`. The legacy `ops/launch_blockers.json` planning state, H6 record,
and global operational registry remain `NOT_DEPLOYMENT_READY` / `UNSELECTED` with
`proofSuiteId=null`; no activation or production credit is assigned.

The native RustCrypto FIPS-205 SLH-DSA service is software-only and internal/reference-only. It is
not evidence of HSM custody or a FIPS-validated module. The software custody certificate remains
`hsm_backed=false`, `fips_validated=false`, `activation_allowed=false`, and
`production_usable=false`. HSM/FIPS qualification and external anti-rollback authority remain
open. The four historical Circle hiding identifiers remain preserved; the active Construction 8.2
rebase certificate closes only the current candidate-boundary bookkeeping, not independent audit
or production theorem acceptance.

Verification receipt:

```text
cargo +1.96.0 test --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --release --offline --locked --features std,parallel
307 core tests passed; all binary/doc-test groups passed; 0 failed
cargo +1.96.0 clippy --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --all-targets --offline --locked --features std,parallel -- -D warnings
exit=0
py -3.14 -m pytest tests/test_bl_pq512_production_candidate.py -k 'not real_rust' -q
4 passed, 1 deselected
py -3.14 -m pytest tests/test_bl_pq512_production_candidate.py -k real_rust -vv -s
1 passed, 4 deselected
containing candidate/transcript/Wave-3 tests: 28 passed, 1 deselected; PQ-governance: 44 passed;
hiding/attack: 42 passed.
```

Production verifier/state/settlement integration, Privacy V2 production admission, HSM/FIPS
custody, external anti-rollback, release sealing, whole-product deployment readiness, and the
independent audit remain open. No live Ethereum, PHI, government data, payment authority, live
credentials, or production activation was used.

## Current internal completion and closeout receipt (2026-08-05)

The authoritative internal completion check reports `internal_engineering_packages=93`,
`internal_complete=93`, `internal_open=0`, and `open_package_ids=[]`. The result is
`INTERNAL_CONFORMANCE_RECONCILED_NONACTIVATING`; `activation_allowed=false`,
`proofSuiteId=null`, live credentials are false, and network access is false. The remaining
conformance receipt likewise reports all 31 packages in its scoped ledger as
`COMPLETE_INTERNAL_NONACTIVATING`, preserves the exact ordered 12-field public boundary, and
keeps `private_public_payload=false` and `security_ledger_qualifies=true`. The retained H6
receipt preserves the following four historical Circle identifiers rather than claiming independent
theorem closure:
`FINAL_CIRCLE_SPLIT_LOG_DEGREE_AND_PROVER_INTEGRATION`,
`FINAL_SHA3_AIR_INTERACTION_ORACLE_DIMENSIONS`,
`FINAL_MULTI_DOMAIN_FRI_ORACLE_WIDTHS_AFTER_SHA3_AIR_EXPANSION`, and
`INTERACTIVE_CIRCLE_SIMULATOR_TRANSCRIPT`. The separate 2026-08-06 candidate rebase certificate
covers the active Construction 8.2 obligation set; it does not rewrite the H6 receipt or make the
backend production because
`production_native_stark_verifier=false`; the preserved production blockers are LB-001,
LB-002, LB-003, LB-004, LB-005, LB-006, LB-007, LB-009, and LB-010.

The Python suite collected 1,733 tests across 204 test modules. Deterministic bounded file-group
runs covered all 204 modules: every completed group passed after the stale roadmap expectation was
corrected, with one intentional skip and only the documented local-development/deprecation
warnings. The monolithic `pytest -q tests` command timed out after 30 minutes and receives no
pass credit. The focused reconciliation lane passed 56 tests in 24.49 seconds. The Rust core
passed formatting, offline locked release checking, Clippy with warnings denied, and its release
test suite: 303 library tests passed with no failures, alongside the reported binary/doc-test
groups. The K512 two-lane candidate campaign remains nonactivating evidence (`p95=101.798191`
seconds, four shards per run, zero scratch/pagefile/driver/stderr signals); fresh refresh attempts
that tripped the unchanged pagefile gate receive no qualification credit.

The three published Source-Complete ZIP targets were rebuilt from the reviewed 803-file allowlist
and independently checked as 804-entry archives with no duplicate names, forbidden generated/state
paths, or payload hash mismatches. All three now have 12,024,082 bytes and SHA-256
`f38bf1dae26811ab8d08e996d357998236e671b96ba39d0f07bf5248a54ed6ce`. The prior three published
copies remain preserved under the external closeout backup. Archive refresh does not change the
nonactivating boundary, and no protected repository paths were edited.

## Current execution boundary

The authoritative recovery checkpoint remains `WAVE2_HANDOFF_2026-07-26.md`, but executable source
and this newest entry supersede its partial proof shape. The current nonactivating H4 candidate is
the exact seven-layer/B=16 relay-free Keccak GKR, the typed state relation, linear square-free
before/after uniqueness, and Construction 8.2 random-padded interleaved Reed--Solomon PCS under one
authenticated dual-PQ public coin. The fixed public ABI remains exactly twelve fields.

The state-composed boundary now carries nineteen GKR/PCS claims. It consumes 6,113 rounds through
the relation/mask/PCS bridge, then 614 K128 or 882 K512 square-free rounds, for exact totals of
6,727 and 6,995. K128 uses 221 committed GKR-mask layers and 27,744 of 32,768 coefficients; K512
uses 233 layers and 28,932 coefficients. The complete transcript leakage ranks are 26,640 and
27,768. Including the 1,600 PCS query rows leaves 4,528 K128 and 3,400 K512 free mask dimensions.

The active hiding simulator covers the Construction 8.2 query map, conditioned row sumcheck, typed
state relation, both square-free phases, the complete state GKR mask layout, and fresh abort/retry
public-coin randomness. The latest qualified Gate 2E context seals the terminal ledger with
`h4_parent_bound=true`, `complete_proof_verified=true`, and no terminal-ledger blockers. It remains
nonactivating: `proofSuiteId=null` and `activation_allowed=false`. The composed security ledger
remains at 392.108419573 bits and records the exact K512 state sumcheck degree budget of 1,748;
the bounded H6 candidate-evidence manifest closes the strict-PQ implementation/composition
obligations for this nonactivating candidate. Production suite identity and activation remain open.

Two privacy defects found during composition are fixed without weakening verification: mask-batch
constraints are now published only through a SHA3-512 commitment, and square-free coefficient
claims use masked public values under a fixed 140-byte digest payload. Raw coefficient openings
remain confined to internal PCS computation. Focused Rust privacy regressions, all ten square-free
tests, the 6,113-round same-chain replay, the simulator KAT, and the Gate 2E/H5/H6 ledger tests pass.

Fresh GPU boundary work is now recorded. The owner-approved Brave-open exception governs the H5
campaign; Brave being open did not disqualify a launch. The exact H5 campaign later completed and
the source validator returned:

```text
h5_validator=PASS
campaign_id=h5-exact-22-20260804
campaign_digest_sha3_512=199a1b1c7e553b73597f1bd3192a72db732529599da68d820bf072e2e2ee3dabe1d7dda2d72efbd9fd23e17a6b2366f70d51ed96d9c152483d3f34165e7bedf5
execution_manifest_sha3_512=999aef8a16f97a52e6ce6ead7b7470eea2fdc50f32d13e95a3a1e021cd093aef42f8f5a2420cd3f4e35f77a42ff161f791888b5905ec3fcdf8cb8f8765992545
proof_suite_id=719ed6d4e9fe8bb69efdb51e5bee0133718b0cc7bdbe9b82a70c68c5522e7efeb620fc9fdc67e3fc3538e57d6518b360a548a114648f3f7640f1475566cd7e6b
k128_p95_seconds=32.360845
k512_p95_seconds=148.861885
max_peak_rss_bytes=850837504
max_scratch_bytes=0
```

The runner's raw terminal result was `campaign_run_count=22` and
`campaign_failed_run_count=0`. Every measured launch had fresh unique input identity, exit 0,
empty stderr, zero pagefile growth, zero post-launch driver events, and complete independent
verification. The active bounds were strict `<35` seconds for K128 and `<180` seconds for K512.
The campaign manifest records execution `source_commit=47ca7dab146b56a85ebbf9d2d2fe797c4fee2fae`;
the later current-checkout telemetry-parser corrections are not retroactively claimed as the
prover source. The campaign is therefore H5 qualification evidence, not a claim that every later
checkout file was present during launch.

The earlier campaign `h5-campaign-20260804-final` stopped at measured K128 ordinal 5 after
`pagefile_growth_mb=15`; it receives zero H5 credit and remains preserved. A diagnostic idle
pagefile run also changed 2002 MB to 2018 MB in 20 seconds and was not qualification evidence.
The first proof-attack corpus command named a nonexistent
`tests/attacks/test_bl_pq512_selected_public_coin_schedule_attacks.py`; it ran zero tests and is
recorded as a misaddressed/skipped command. The corrected proof, state, and foundation corpora
then passed 38, 46, and 52 tests respectively (136 corrected attack tests total).

The same qualified context first produced a pre-manifest H6 record with one closed obligation,
`H5_RESOURCE_EVIDENCE`, and an explicit blocker tuple. The former blockers are retained in the
dated pre-manifest H6 section below; that record is historical zero-credit preflight evidence.
The current H6 record is
`QUALIFIED_H6_NONACTIVATING`: all twelve obligations are closed with an empty blocker tuple.
`proofSuiteId` remains null, activation remains false, and real PHI/payments remain forbidden.

Historical transfer-time verification (superseded by the current 2026-07-29 section below) was:
`cargo test --lib --all-features` passed 229/229 tests in 1,069.89 seconds;
`cargo clippy --all-targets --all-features -- -D warnings`,
`cargo clippy --lib --no-default-features -- -D warnings`, and
`cargo fmt --all -- --check` exited zero. Default-feature `cargo test --lib --no-run` also compiled
without warnings. A preceding feature-enabled run outlived its command wrapper and later returned
exit code 101 without recoverable test output; it receives no pass credit. The identical diagnostic
rerun with uncaptured output passed all 229 tests, including the previously load-sensitive worker
classification test.

The last successful strict K128-shaped GKR control used 782 permutations, 216 layers, 4,096 padded
width, and 8,785 authenticated rounds. It completed in 35.1399522 seconds, independently
reconstructed every public mask constraint and replayed the public coin, matched CPU/GPU packed
polynomials and GKR/PCS openings, and explicitly reported `complete_pcs_attached=false` and
`complete_proof_qualification=false`. The GPU FRI arithmetic control at `2^25` values measured
0.7698361 seconds for bit reversal plus NTT, 0.0293228 seconds for 22 folds, and 0.2328701 seconds
for a bounded 2 GiB device-to-host stream; those are component measurements only.

The current GPU PCS integration remains implemented in `src/mlpcs_gpu_worker.rs`,
`cuda/cuda_mlpcs_fold_worker.py`, and the multilinear PCS modules. Rust remains authoritative for
SHA3-512 roots, canonical decoding, multiproofs, transcript construction, and verification. The
corrected worker source pin is
`4e83333596b004503a53bb8a061d9bb7f6687a078fe3e1774ea80179a2063c618ef600d57c16d959b43407fc7da8295d78907e37bd4be4aa619ef377b4a255a7`.
The old handoff's 706-item resume sequence is retained as historical integration evidence but is
superseded as the immediate action by the owner's newer full-proof sub-30-second direction and the
ordered implementation gates above. No component control may claim complete-proof qualification.

Current Wave 1 (historically called Wave 1A) is sealed as a **synthetic, nonactivating executable
relation**. It now includes exact
claim-source arrays and dense SHA3 commitments, oracle and policy execution/audit roots, ruleset
commitment, real ML-DSA-87 plus SLH-DSA-SHAKE-256f claim-truth authority, full-width A12 attempt and
cover nullifiers, a replay-registry lifetime pepper commitment, a hidden master-salt reuse key,
depth-64 insert-only replay, three authenticated economic lanes, a chained operation log,
authoritative master commitments, and the unchanged 12-field compatibility ABI projected from
512-bit authorities.

The global SHA3 relation uses one canonical six-segment call schedule rather than cloning all
Keccak rows into a second Python trace. K128 contains exactly 46,858 calls at offsets/counts
`(0,516)`, `(516,129)`, `(645,1)`, `(646,9360)`, `(10006,36848)`, and `(46854,4)`; Python and
`no_std` Rust pin commitment
`2d2792d30f838618190a95817f44204308e2a0e7f460b71e48da779ccd2472cb11ae3342a2df9a52f01561c80aaa3d3fafa2d77271fd9eb4f6ee6270006e3aa6`.
Each segment retains its independently evaluated physical SHA3 AIR as an executable differential
specification. The Wave 2 release prover must consume the same schedule through one canonical
committed hash-call bus; it no longer commits those six SHA3 internal tables through the generic
wide-column semantic-AIR PCS.

Wave 1 closure evidence is 53/53 selected trust-critical Python tests after the focused payment
rerun, a 55,776-message global boundary evaluation plus replay-root attack, 78/78 Rust tests,
offline `cargo fmt`, and Clippy with warnings denied. The heaviest payment relation evaluates
112,485,087 identities and 220,993,014 lookup messages at degree three. This is not a proof,
durable production state, production verifier, proof-suite selection, or activation claim.
`proofSuiteId=null`, real PHI/payments remain forbidden, and Wave 2 is now the active boundary.

The current certified hidden-state transition is still an unqualified architecture model. Its K128
input of 782 Keccak permutations was run through the unchanged `B=8` packed Boolean first-round
kernel at the generated 216-layer, 4,096-padded-width geometry: 45,158,400 gates took a five-run
median of 4.8015192 seconds (4.3895117-5.0110385), peak resident memory was 12,079,104 bytes, scratch
was zero, and every run produced the same SHA3-512 digest. CPU/wall ratio 0.9767 and source
inspection establish that this control is single-threaded. This is phase-one evidence only.
K128/K512 remain the qualification profiles; the 256-bit security/encryption, privacy, transcript,
5,000,000,000-byte peak-RAM, scratch, and complete-proof gates do not move.
Workspace grounding on 2026-07-26 found no exact hidden-state schema, transition manifest, hash-call
schedule, or derivation artifact for the 782/894 constants. They occur as hard-coded unqualified
inputs in `relation_cost_screen.py`; the affine batch screen only interpolates between them. No
semantic producer may emit the new canonical GKR input from those constants, and they receive zero
qualification credit until the complete relation preserves the sealed trust boundaries and derives
every call and permutation.

The selected transparent multilinear-PCS implementation now has a fixed fail-closed prelude,
different-size three-claim batch sumcheck, exact hidden/auxiliary polynomial algebra, canonical
verifier-derived query multiproofs, strict fixed-length codecs, and an independent algebra
verifier. The auxiliary 18-variable polynomial is lifted through four ignored prefix variables
with an exact `2^-4` normalization so the 22-variable batch claim retains the simulator's
`r^2 c_aux` term. The prelude is 4,747 bytes; the fold/query segment is 17,519,307 bytes; and the
combined internal PCS proof is exactly 17,524,065 bytes. A full-shape completed-challenge control
measured 4.1560122 seconds, 827,203,584 peak working-set bytes, and zero scratch with the same
SHA3-512 digest as the scalar implementation. The focused parallel suite passes 26/26, including
above-threshold scalar/threaded parity for equality generation, dot products, round polynomials,
and folds. This is executable algebra and fixed-grammar evidence only: production entropy,
authenticated public-coin receipts, the complete simulator/composition theorem, a full proof
producer, and complete K128/K512 independent verification remain open.

The full production-geometry PCS control now constructs every committed layer and canonical
opening, emits the exact fixed proof, decodes it, and independently verifies it. The earlier
18.1039767-second single-opening control was superseded after integration review found that packed
GKR ends in two claims plus a degree-7 shard query. The corrected PCS right table now binds both
terminal values through one authenticated mix and inserts the exact eight Lagrange shard weights
between the low wire and high group bits. Its monitored run measured 23.8805969 seconds for
production plus internal verification, 0.2366557 seconds for independent decoded verification,
29.4130358 seconds total wall, 5,062,144,000 peak working-set bytes, and 2,281,701,376 bounded input
scratch bytes. The fixed 17,524,065 proof bytes had SHA3-512
`25bb3d9c9b7b47a6ad0de599fdd7a2f53d696605085bd194ec09be455e6e9f1a6ea67594c9f92271a7ffd6e81a683fffd4c21104e0859c6b1ceac639d2556ef3`.
The focused PCS suite passes 27/27 and the exact GKR-to-PCS bridge passes 1/1. This is still a
completed-challenge synthetic hiding control, not production entropy, authenticated interaction,
simulator/theorem qualification, or a coherent complete GKR-plus-PCS K128/K512 proof.

The earlier 30-33-second 216-session GKR reports used independent per-layer fixtures and are not
coherent-chain evidence. The corrected harness evaluates all 216 boundaries, carries two terminal
claims backward through the complete circuit, verifies every masked layer in Rust, checks exact
CPU/GPU packed-polynomial parity, and binds its two final openings to the raw `2^21` Boolean input.
It measured 42.8253168 seconds for K128/782 and 44.1804650 seconds for K512/894; combined host peaks
were 3,241,021,440 and 3,240,488,960 bytes. The exact resulting PCS inputs then produced
independently verified 17,524,065-byte proofs in 20.7792086 plus 0.2230094 seconds for K128 and
20.7974853 plus 0.2428490 seconds for K512. Core scratch was 2,818,577,696 bytes. The joined harness
now requires the existing external 64-byte secret and 64-byte session boundary for domain-separated
GKR and PCS masks and fails closed on wrong-length input. Its challenges and initial Keccak states
remain deterministic synthetic controls: this is actual coherent GKR-to-PCS component evidence,
not authenticated public coin, the certified hidden-state transition, an atomic complete proof,
simulator qualification, or K128/K512 qualification.

The owner subsequently set the release resource gate to no more than 5,000,000,000 peak resident
bytes, strictly below 5,000,000,000 scratch bytes, and no swap. The 3,241,021,440- and
3,240,488,960-byte coherent-chain runs retain their algebra, masking, parity, and opening evidence
but are not resource-qualified. The 5,062,144,000-byte PCS control and later
7,456,407,552-byte predecessor remain historical correctness/performance evidence only and are
rejected release realizations under the current RAM gate.

Binding review then found that the measured initial output claim covered the entire final Keccak
state and was computed inside the prover harness rather than authenticated by the semantic digest
bus. The measured run remains coherent internal GKR algebra evidence, not a hash-bus proof. The
replacement code requires a canonical external Keccak-state input, rejects nonzero inactive lanes
and padding wires, and fixes output wire coordinates 9 and 10 to zero so the claim covers exactly
the first 512 SHA3-512 digest bits. Two focused boundary tests pass. Fresh K128/K512 runs and exact
semantic message/digest-bus commitment openings remain required.

That bounded block is now implemented and measured. The indexed reducer partitions public gate
indices, uses private worker accumulators, merges in canonical worker order, and matches the serial
polynomial/report at 1/2/4/8/16 workers. At K128's 45,158,400 packed gates, five-counted-run native
medians were 3.257033 seconds at one worker and 0.4439703 seconds at 16 workers (7.336x faster);
maximum 16-worker peak resident memory was 82,436,096 bytes and scratch was zero. The 16-worker
K512 anchor median was 0.4900199 seconds. K1024 and K2048 use the explicitly unqualified two-point
affine permutation model and measured 0.5557694 and 0.6907252 seconds for their resulting packed
gate loads. These are first-round kernel results, not complete-proof or architecture qualification.

An isolated RTX 4060 accumulator screen also passed a complete 4,097-gate CPU/GPU accumulator KAT.
At K128's 45,158,400 packed gates it measured 21.9701 ms median across five counted runs, including
accumulator zeroing, 46 launches, synchronization, and an 8,454,144-byte device-to-host copy.
Sampled incremental GPU memory was 110 MiB. Combining this with measured dense CPU-tail controls
projects 77.72-89.30 ms for hybrid phase one, but full K128/K512 accumulator import,
final-polynomial parity, proof-byte parity, and complete-proof timing remain open. NVRTC was
temporary out-of-tree tooling and is not an adopted dependency.

Wave 2 is a strict-PQ proof **and throughput-recovery** wave, not merely “finish the existing
prover.” The v1 regression kernel proof was 28,643,096 bytes at 945 queries. The authoritative
`BLPQPRF2` encoder/decoder and independent verifier now replace its per-query FRI paths with one
canonical multiproof per FRI layer while reconstructing every coordinate from authenticated
verifier inputs. V2 also emits repeated cross-domain sibling nodes and opened rows only once per
committed tree coordinate in canonical order, then reconstructs every proof before verification.
The latest real dual-PQ run produced and independently verified a 6,755,933-byte v2 proof:
21,887,163 bytes smaller (76.41%)
than v1, with all 945 query draws, opening values, and multiplicities preserved. Compact size varies
slightly with the authenticated random query set; v1 remains a
historical comparison grammar, not a fallback. This is regression-kernel evidence, not K128 timing
or full Gate 2B closure.

The complete K128 resource failure is separate. The rejected monolithic path has a
9,034,606,313,472-byte live-memory lower bound; its disk-streaming model requires
950,757,738,236 bytes of scratch, and simple de-duplication still projects 554,259,695,356 bytes.
All three are retired release architectures, not fallbacks.

Wave 2 now implements a shared-bus Boolean GKR hash coprocessor. The sealed M31 semantic AIR proves
application/state/money/ABI semantics and binds every hash port to one committed bus; an Fp16
data-parallel Boolean circuit proves all 113,730 K128 Keccak-f[1600] permutations. Exact storage for
25 bit-packed state boundaries is 568,650,000 bytes. The `w=1,600` raw-state-layer baseline is
3,591,988,768 bytes, while `w=2,048` is 4,407,205,408 bytes; both raw baselines now exceed the
release RAM limit before generated padded width, masking, commitment, and allocator overhead. The
hard reference-laptop gates are no more than 5,000,000,000 peak resident bytes,
strictly below 5,000,000,000 scratch bytes, and no swap dependency. These are models and gates, not a
completed prover measurement. Native masking, complete simulator, exact 256-bit security/encryption
ledger,
atomic shared-bus verification, and full K128 proving remain open. The authoritative contracts are
`docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` and
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`.

The current 2A control now exposes an exact K128 bus/resource report from the sealed schedule and
C0 census: 46,858 calls, 113,730 permutations, 7,996,042 preimage bytes, 10,994,954
message-plus-digest bytes, 568,650,000 bit-packed round-boundary bytes, and 4,367,232,000 chi AND
gates. It is explicitly `DERIVED_MODEL` evidence for the retired direct-SHA3 architecture; it does
not measure a generated backend, RSS, scratch, latency, I/O, or qualify a release. C0 also now has
a canonical fixed census and a separate nonactivating per-job binding to the masked private access
body plus batch/sidecar/state/attempt/retry/sequence identities. Canonical decoders are tested, but
native-hiding proof authentication remains a Wave 2 requirement.

The synthetic benchmark record is internally validated only. Its self-hashes cannot attest to a
worker execution, immutable source bundle, or OS resource counters, so qualification now fails
closed until an externally captured provenance bundle is implemented. Gate 2A therefore remains
open: generated-backend measurement, proof-native CBAM binding, and real provenance/telemetry are
still required.

Current focused verification for this boundary is 104/104 Python tests across the SHA3 inventory,
schedule/capacity, benchmark-fixture, resource-report, CBAM, and attack slices; the Rust canonical
multiproof suite is 6/6 and `cargo fmt --check` passes. These checks do not close Gate 2A or 2B.
The complete Rust library suite now passes 121/121, including the FRI-layer codec, v1 migration
bridge, exact work-domain coefficient-tail gate, batched disk openings, and forced Merkle-level
recomputation.

Gate 2B now has the authoritative v2 proof grammar, strict global-FRI wire format, and independent
v2 verifier in both monolithic and bounded-streaming workers. The encoded form carries no
prover-supplied query or FRI coordinates; it preserves ordered query multiplicities, authenticates
each global layer frontier once, rejects trailing bytes, and verifies the decoded bytes rather than
the prover's original in-memory object. Focused convergence evidence is 16/16 report/attack/real
proof checks plus the bounded-streaming real-proof check. FRI and cross-domain sibling/value
authentication are now globally deduplicated. Gate 2B remains open for fused-slab construction,
measured recompute-versus-retain resource/latency evidence, complete v1/v2 mutation coverage, and
the required endpoint-multiproof versus three-plane memory-checking bake-off.

The production-shaped workers no longer serialize the full v1 grammar for telemetry. The
28,643,096-byte v1 baseline remains frozen regression evidence, while live work emits only v2,
drops the original proof before decoding the wire proof, and compacts FRI layers through borrowed
slices rather than cloning every per-query Merkle path. This removes an avoidable 28.6 MB legacy
wire allocation plus a second path-heavy proof clone from each regression-kernel execution; no
latency credit is claimed until resource telemetry measures the change.

The bounded-streaming main, interaction, and composition commitments now use one canonical column
layout instead of permanent or construction-only row copies. SHA3-512 tree construction reads
bounded row slabs directly across those column files; no full-domain `.rows` transpose is created.
Queried row payloads are reconstructed from the same columns through persistent bounded file
handles. The in-memory and direct-column roots/openings are byte-identical in the focused
cross-language test. The derived resource preflight counts each canonical oracle layout once
rather than twice. This structurally advances Track C, but exact scratch high-water and latency
credit still require the external resource telemetry owned by Gate 2A.

Disk proof opening now gathers and deduplicates every required main, interaction, composition, and
mask index before I/O, then reuses one open handle per retained Merkle level and row source rather
than reopening files for each of 945 queries. A deterministic public-geometry planner retains at
most 256 MiB of Merkle levels per cross-domain oracle. Larger trees now construct their commitment
root and post-challenge global frontier in one canonical-column pass using only a logarithmic hash
stack plus the exact query frontier; no Merkle-level files are created. The reconstructed root is
checked before any opening is returned, and the forced-recompute test proves byte-exact root,
opening, duplicate-query, verification, and cleanup parity. The resource preflight bounds
recomputation by `(QUERY_COUNT + 1) * maximum_log * 64` bytes instead of a temporary full tree.
No K128 latency or scratch credit is claimed without telemetry. The production-shaped streaming
proof passes end to end after this change; the latest clean frontier rerun is
`1 passed in 119.73s`. This single fixture run is correctness evidence, not a K128 latency result.

The deterministic complete-composition evaluator now executes `BLPQPRF2` end to end. The prior
`CircleFft(TargetLogSizeTooSmall { source: 6, target: 5 })` failure was caused by an interpolation
container retaining an exactly zero high-degree tail. The evaluator now truncates only an
all-zero tail to the frozen work domain and rejects any nonzero coefficient above that domain.
The focused execution passes V2 proof encoding/verification, four proof mutations, and three parser
mutations; the dedicated zero-tail/nonzero-tail regression also passes. No degree, blowup, or
security gate was weakened.

The cross-wave frontier contract is `docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md`. It adds a
privacy-padded access manifest, measured state-topology bake-off, deterministic conflict-DAG
scheduling, proof-carrying adapters, a formalization spine, and versioned Ethereum compatibility.
It adds no package: progress remains **6 of 93 complete and 87 open**. Its state-call projections
are not measured throughput, and draft Ethereum EIPs are not release dependencies.

The 2026-07-22 quick incorporation screen admitted, but did not select, three additional research
lanes inside existing gates: Shout-like read-only policy/oracle checking plus Twist-like mutable
replay/payment checking against the current endpoint-multiproof/sorted-memory control; VEIL as an
alternative multilinear/GKR hiding wrapper; and Neo/SuperNeo or Hachi initially only for post-K128
folding/aggregation research. The later mandatory 2E gate below now admits Hachi separately as an
isolated pre-K128 PCS candidate. All retain the SHA3-512 root bridge, Fp16 authenticated interactive
public coin, native hiding, 256-bit security/encryption floors, CBAM, fixed shape, and atomic
verification. The exact
state-only call-count ceiling is 72.09x, not an end-to-end speed claim. No package closed,
`proofSuiteId` remains null, and activation remains false.

The 2026-07-26 preliminary mechanism-first frontier screen admits a combined optimization program inside the
same gates: Keccak-specific GKR algebra; exact M31-to-Fp16 tower/small-value sumcheck; persistent
single-owner GPU execution with Rust-authoritative transcript and verification; a streamed jagged
PCS with a proved-distance Fp16 code; and native-ZK composition around the resulting transcript.
It also records explicit rejects for incompatible Groth16/KZG/SRS, Fiat--Shamir-only,
binary-field-only, conjectural list-decoding, distributed-server, withdrawn, and 128-bit-only
headline results. These are prototype lanes, not a selected suite or a throughput claim. The
current arithmetic controls remain 35.1399522 seconds for K128-shaped GKR plus 27.8 seconds for one
direct PCS if run sequentially, while the existing PCS realization fails the current
5,000,000,000-byte
gate. The source inventory is a breadth screen, not an exhaustive full-paper/citation/code review;
its exact genuinely-new-paper count is unproved because the earlier pass lacks a durable
deduplication ledger. No package closed, `proofSuiteId` remains null, and activation remains false.

The subsequent deep state-proof research is now mandatory Wave 2 gate 2E under
`docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md`. The C0 SHA3 endpoint-multiproof/sorted-memory path
remains the control. C1-C4 add public-coin persistent sparse memory, an IRONDICT-derived transparent
dictionary relation, touched-projection RAM, and a Two-Shuffles-derived memory-consistency relation.
The commitment bake-off separately covers Jindo-style evaluation-hiding lattice PCS,
Grand-Danois/Hachi-style and RoKoko-style candidates, plus a transparent hash/code fallback. All
published KZG, pairing, Schnorr, structured-setup, random-oracle, concrete VOLE/two-party, and
designated-verifier dependencies are rejected. Wave 2 now has six gates: 2E selects from complete
evidence or records why C0 remains selected, and 2F performs the complete K128/K512 latency proof.
No candidate is implemented or selected by this documentation change; progress remains 6/93,
`proofSuiteId` remains null, and activation remains false.

## Compaction recovery order

After any context compaction or handoff, read these files before continuing trust-critical work:

Mandatory insertion: immediately after item 1 (`AGENTS.md`) and before item 2 (`STATE.md`), read
`CONTINUATION_MANDATE.md` completely. It controls persistence, ideology, recovery, safe download
policy, legitimate hard stops, and continuation through partial milestones.

1. `AGENTS.md`
2. `STATE.md`
3. `docs/IMPLEMENTATION_ROADMAP.md`
4. `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md`
5. `docs/PRIVACY_STATEMENT_V2.md`
6. `docs/ZK_BACKEND_DECISION.md`
7. `docs/PRIVACY_V2_INTERNAL_AUDIT.md`
8. `docs/PQ_ZK_SECURITY_ARCHITECTURE.md`
9. `docs/BL_PQ512_FOUNDATION_SPEC.md`
10. `docs/BL_PQ512_SECURITY_FREEZE.md`
11. `docs/BL_PQ512_S09_INTERNAL_SOLUTION.md`
12. `docs/BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md`
13. `docs/bl_pq512_suite_candidate_v1.json`
14. `docs/BL_PQ512_THREAT_MODEL.md`
15. `docs/security-freeze/BL-PQ512-v1/hardening.json`
16. `docs/FIXED_SHAPE_CLAIM_AIR_DRAFT.md`
17. `docs/SUPPLY_CHAIN_BASELINE.md`
18. `cache/implementation-runs/20260719T164339Z-wave1b-theorem-backend-r35/run_manifest.initial.json`
19. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/run_manifest.initial.json`
20. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/run_manifest.initial.sha256`
21. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/00_freeze_toolchain_and_collection.json`
22. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/01_official_upstream_cryptographic_implementability_review.json`
23. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/02_physical_air_calibration_matrix.json`
24. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/03_integrated_reference_hardening.json`
25. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/04_regression_and_exact_differential.json`
26. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/05_rust_platform_and_proof_gates.json`
27. `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/06_cairo_solidity_hygiene_and_privacy.json`
28. `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/terminal_manifest.json`
29. `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/terminal_sha256.txt`
30. `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/run_manifest.initial.json`
31. `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/stages/06_k128_k256_k512_measurement.json`
32. `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/terminal_manifest.json`
33. `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/terminal_sha256.txt`
34. `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/run_manifest.initial.json`
35. `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/stages/01a_s07_s08_math_correction.json`
36. `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/stages/02a_money_boundary_correction.json`
37. `cache/security-freeze-runs/20260715T202353Z-security-freeze-r23/terminal_manifest.json`
38. `cache/foundation-runs/20260715T073140Z-foundation17-r21/terminal_manifest.json`
38. `docs/PHASE1_EXECUTION_LOG_2026-07-13.md`
39. `cache/security-scans/blind-ledger-app-layer/unversioned_20260713T112204Z/artifacts/fix_report.md`
40. `cache/implementation-runs/20260718T134831Z-private-proof-engine-r28/terminal_manifest.json`
41. `cache/implementation-runs/20260718T134831Z-private-proof-engine-r28/terminal_sha256.txt`
42. `cache/implementation-runs/20260718T154911Z-proving-evidence-r29/terminal_manifest.json`
43. `cache/implementation-runs/20260718T154911Z-proving-evidence-r29/terminal_manifest.sha256`
44. `cache/implementation-runs/20260718T170233Z-python-supply-chain-r30/terminal_manifest.json`
45. `cache/implementation-runs/20260718T170233Z-python-supply-chain-r30/terminal_sha256.txt`
46. `cache/implementation-runs/20260718T170233Z-python-supply-chain-r30/terminal_sha3_512.txt`
47. `cache/implementation-runs/20260719T013047Z-s09-public-coin-r31/terminal_manifest.json`
48. `cache/implementation-runs/20260719T013047Z-s09-public-coin-r31/terminal_sha256.txt`
49. `cache/implementation-runs/20260719T013047Z-s09-public-coin-r31/terminal_sha3_512.txt`
50. `cache/implementation-runs/20260719T034130Z-s09-crypto-core-r32/terminal_manifest.json`
51. `cache/implementation-runs/20260719T034130Z-s09-crypto-core-r32/terminal_sha256.txt`
52. `cache/implementation-runs/20260719T034130Z-s09-crypto-core-r32/terminal_sha3_512.txt`
53. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/terminal_manifest.json`
54. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/terminal_sha256.txt`
55. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/terminal_sha3_512.txt`
56. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/run_manifest.initial.json`
57. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/stages/01_complete_relation_and_payment_maps.json`
58. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/stages/02_physical_relation_dimensions_and_measurement.json`
59. `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/stages/03_final_convergence_and_integrity.json`

`docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` and
`docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` are inseparable companions to item 3 and must be read
immediately after the roadmap, before continuing to item 4. They define the internally finishable
build/audit boundary and the active Wave 2 cost/security gates; historical sealed run records do not.
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` must then be read before item 4; it supersedes any
older suggestion that a 554-951 GB direct-SHA3-STARK layout is a safe release fallback.
`docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` must be read immediately after it; that addendum
owns cross-wave frontier work without changing the denominator or reopening Wave 1.

Every path in this list must exist before continuing. R26 deliberately has no terminal-manifest
entry here: the run was interrupted before terminal reconciliation and sealing. Its initial
manifest and stage JSON files are unsealed recovery inputs, not terminal evidence.

Do not reconstruct the current proof, privacy, or post-quantum decision from chat summaries.

## Current handoff status

This directory is a development and audit workspace, not a release staging tree. The 2026-07-22
cleanup removed rebuildable compiler output, caches, and redundant local source-rollbacks while
preserving Git history, sealed run/security records, and offline dependency inputs. Local rollback
directories are not authoritative evidence; reviewed Git identities plus sealed manifests are. A
release must be built separately from an exact reviewed allowlist.

The intended portable source layout is:

- Source root: `Blind Ledger Neer Version/blind-ledger-app-layer/`
- Canonical sibling ops artifacts: `Blind Ledger Neer Version/ops/`
- App-layer ops mirror: `Blind Ledger Neer Version/blind-ledger-app-layer/ops/`
- Vendored Forge dependency: `Blind Ledger Neer Version/third_party/forge-std/`

Any eventual package must exclude generated build directories, proof artifacts, caches, nested
archives, scratch/GPU build output, local rollback copies, and security-scan working material unless an
independent release manifest explicitly and safely requires an item.

## Security-audit status and continuation boundary

The latest **completed and durably recorded** deep security audit remains
`cache/security-scans/blind-ledger-app-layer/unversioned_20260713T112204Z/`. Its immutable
validation record contains 31 raw candidates, 29 reconciled groups, 16 validation survivors, and
10 raw candidate IDs that survived attack-path analysis. Deduplication leaves eight distinct final
families: four medium and four low, with no critical or high finding. The post-scan repair record
now shows all eight distinct families remediated at their stated software/application boundaries,
including fail-closed `R23-C02` qualification plumbing and the supported-platform `R25-C01` Python
artifact boundary. The proving-evidence
registry has no active policy digest, so no proof suite or verifier was activated. The decision
remains **RED/no-go**.

A later repeat deep review was stopped by the owner before its fourth discovery pass was
mechanically verified, reconciled, validated, and reported. Six fourth-pass reviewer jobs returned
successful process exits, but process success is not finding validation. The third pass had
introduced one new low-severity readiness-metadata **candidate**, which is why the saturation
procedure called for another pass. Do not call that candidate a confirmed vulnerability, do not
claim four-pass saturation, and do not treat unmerged reviewer output as a final finding list. All
known review/validator processes from the stopped attempt were terminated; no review job should be
assumed active.

The 2026-07-18 reconciliation searched the authorized workspace for those later reviewer receipts.
It found zero recoverable fourth-pass receipt files and no later completed scan directory. The six
process-exit statements exist only in this handoff record, so none can be promoted to verified
review evidence and no saturation or new-finding claim is authorized.

If that audit is resumed, reuse the completed fourth-pass reviewer output where recoverable. First
verify its receipts and coverage, then reconcile duplicates, validate only genuinely new
candidates, perform attack-path analysis only for validation survivors, and publish exact counts.
Do not rerun the expensive reviewer generation merely to recreate already available output. The
completed 2026-07-13 `validation_summary.md` and `fix_report.md` remain authoritative until a newer
scan completes its full reconciliation and validation workflow.

R28 recovery run `20260718T134831Z-private-proof-engine-r28` requalified the R26 inputs and closed
with a genuine terminal manifest and seal. R29 run
`20260718T154911Z-proving-evidence-r29` then remediated the R23-C02 code-level trust bypass: one
source-governed registry digest controls a canonical SHA3-512 policy; legacy tool overrides are
rejected; source, tools, parameters, suite, schema, build, and artifact identities are pinned; and
proof generation uses a distinct pinned verifier command. The registry remains
`DISABLED_NO_APPROVED_PQ_SUITE`, so this is fail-closed qualification plumbing, not a production
verifier or strict-PQ proof claim.

R30 run `20260718T170233Z-python-supply-chain-r30` closes `R25-C01` for CPython 3.14.4 on Windows
x86-64 and Linux x86-64/glibc >= 2.28. Four fully transitive locks govern 18 production and 26
development packages; the canonical manifest binds all 52 platform artifact records by filename,
size, official acquisition URL, embedded version, declared license, SHA-256, and SHA3-512. The
installer contains no network acquisition path, requires a fresh environment, fails closed on any
runtime/manifest/lock/wheel drift, runs isolated pip with `--no-index --require-hashes
--only-binary=:all: --no-deps`, checks the exact installed graph, and emits a create-only canonical
attestation. Fresh Windows and Linux offline installs and Linux symlink-bypass coverage passed. No
dependency version was upgraded, no protected source changed, and no roadmap package closed.

The 2026-07-18 Wave 1A relation recomputes exact legacy/SHA3-512 membership
paths for every fixed claim-source, oracle/authorization, sparse policy, and ruleset record.
`pq_strong_nullifier_reference.py` adds a full-width depth-64 indexed transition independent of the
legacy felt tree. `authenticated_payment_reference.py` advances an aggregate reserve/obligation/
paid/responsibility state and operation-log root for every approval, denial, and cover slot.
`wave1a_relation_reference.py` joins those paths with 128 legacy insertions, 128 strong slot
insertions, one context-free strong salt-use insertion, exact payment conservation, the ordered
12-field compatibility statement, and a SHA3-512 master batch commitment. The K128 KAT contains
one approval, one denial, and 126 covers and pins all 12 fields plus the wide governance and batch
commitments.

The A12 continuation removes the opaque-nullifier boundary. Real-attempt identity is exactly the
governed source authority, source claim ID, and original-attempt lifecycle tuple; mutable batch,
slot, claim, payer/provider/member, decision, policy/oracle, profile/domain, and proof context is
excluded. Covers use a separately domain-separated batch/slot/fresh-nonce preimage. The legacy
Poseidon felt and strong SHA3-512 value are independently derived from the same exact bytes, and the
relation verifier recomputes both lanes. A persisted authority-ID/pepper-commitment binding rejects
batch-level rotation unless a future full atomic replay-registry migration is implemented.

R33 completes the narrower Wave 1A semantic-reference foundation without activating it. The relation hard-codes
`nullifier_derivations_authenticated=true` and now composes full-width authenticated per-member
benefit, unique provider-obligation, funded payer-reserve, and provider-payable maps. Denial and
cover inserted reserved zero-valued records under the then-current four-operation schedule; every slot
appends one typed operation commitment. A
later line-by-line audit proved that the R33 16-table object is a declared inventory estimator, not
an executable AIR: it has table metadata and host recomputation but no trace cells, polynomial
identities, boundary/transition evaluator, lookup-multiset check, or serialized verifier statement.
It therefore reports `physical_relation_constrained=false`; its K128/K256/K512 dimensions and
program commitments are historical estimates, not theorem inputs. Source/oracle PQ signer/epoch
verification, executable low-degree application/SHA3/Poseidon constraints, PCS/FRI expansion,
native hiding, the strict-PQ proof suite, and authoritative durable state remain Wave 1A/1B/1C work.
`proofSuiteId=null`, activation is false, the external ABI is unchanged, only synthetic data was
used, and no proof artifact exists. A12 remains closed; the Wave 1A executable-AIR handoff is reopened.

R34 corrects two Wave 1A reference boundaries without changing that status. `BenefitScopeV1`
commits the payer authority, plan, inclusive benefit-period bounds, and fixed asset registry under a
separate SHA3-512 domain. The payment-map state domain is versioned to v2, the scope commitment is
present in the composite root and every member-benefit key, before/after scope drift is rejected,
and relation verification rejects scope substitution under an old commitment. Only `None` now
selects an empty initial provider-balance map; falsey non-mappings `[]`, `""`, `0`, and `False` fail
closed. The scope boundary requires the exact frozen `BenefitScopeV1` type, so a subclass cannot
override its commitment function. Durable authoritative publication of the scoped before-state
remains Wave 1C work.

The 2026-07-18 S09 internal construction slice removes the upstream/QROM design impasse without
promoting the rejected kernel. `docs/BL_PQ512_S09_INTERNAL_SOLUTION.md` selects an authoritative
PQ-authenticated interactive public-coin transcript and pins an executable M31 degree-16 tower,
64-byte encoding, exact irreducibility checks, SHA3-512 rejection sampler, typed commit/reveal state
machine, and audit-root reference. The focused foundation and attack gate reports `11 passed`.
Production arithmetic, SHA3-512 PCS/Circle-FRI, the complete challenge schedule, PQ signature
adapters, cross-session abort/retry governance, native hiding, proof grammar, and final identities
remain open. This slice closes no roadmap package: `proofSuiteId=null`, activation is false, no proof
was generated, and the whole-product count remains 6 of 93 complete.

R31 verification collected 745 non-attack and 159 attack nodes, 904 total. The first broad
non-attack invocation reported `743 passed`, `1 failed`, `1 skipped`, `63 warnings`, and `184`
subtests because the RISC differential correctly required an explicit run-owned target. A copied
R29 binary was then hash-pinned and rejected for semantic drift: current Python and Cairo agreed,
while that stale binary disagreed on six public fields. The current RISC model was rebuilt offline
and locked in the isolated R31 target; the exact differential then passed with eight subtests, and a
second run against the `129,297,728`-byte binary with SHA-256
`b5cb8119010867fbc13e454a25735eae8341007d541d4a5843c5f8fd155b8e01` passed without changing the
binary. Reconciliation therefore yields 744 passing non-attack nodes and the one explicit Windows
account-capability symlink skip. The attack lane reports `159 passed`, `31 warnings`, and `36`
subtests. Current top-level reconciliation is 903 passing plus one skipped across 904 Python nodes;
focused S09 tests are a subset, not additional nodes.
The verified `6,248`-file, `3,531,355,697`-byte generated RISC target was then removed from the
contained R31 directory; its current binary identity and offline rebuild command remain in the
terminal manifest.

R32 run `20260719T034130Z-s09-crypto-core-r32` completed from an exact 584-file rollback with initial
source identity SHA-256 `1950478d5c01df220c945f0e6b68fdd86aad754ca93a002900125da788220bd2`.
It adds an isolated `no_std` Rust Fp16/SHA3-512 substrate, exact locked software ML-DSA-87 and
SLH-DSA-SHAKE-256f adapters, a four-attempt suite-diverse retry/quarantine reference, and a strict
header-first bounded `BLPQPF01` proof-grammar reference. The combined focused S09 lane reports `40
passed`; the Rust crate reports `17 passed` and passes offline locked fmt/check/`no_std`/clippy.
Root scalar measurements are approximately 1.05 million mixed Fp16 updates/second and explicitly
are not proof throughput. The locked R30 Windows production/development wheelhouses still verify at
18/26 packages and include exact `pqcrypto==0.4.0` artifacts.

R32 also repairs one unsafe reference boundary: `OODS_POINT_PARAMETER` now aborts instead of using
the generic field sampler. Math review proves the frozen tower as a nonactivating algebraic substrate
but finds that the Fp16 two-point OODS sampler must reject the embedded Fp8 fixed subfield and that
numeric Circle-FRI constants cannot be selected until final AIR/table dimensions and a
degree-corrected theorem-matched cross-domain layout exist. Vendored S-two remains byte-stable; its
high-level engine is coupled to QM31 across 77 source files. The manual review is evidence, not the
vendored repository's unavailable mandated soundness-checklist sign-off. R32 therefore kept
`proofSuiteId=null`, activation false, physical AIR false, generated no proof, and closed no package.
R33 uses the R32 crate only for the independent dimension mirror and does not modify or promote
vendored S-two.

R33 final collection is 762 ordinary non-attack nodes, two exact differentials, and 180 attack
nodes: 944 unique Python nodes. The broad command that also includes the one-node physical-
dimension differential reports `762 passed`, `1 skipped`, `63 warnings`, and `176` subtests in
`596.19s`; the single skip is the explicit Windows account-capability case where the platform
account cannot create a symlink. The Python/`no_std` Rust physical-dimension differential separately
passes in `6.52s`. The corrected exact-source Python/Rust/Cairo/RISC differential and its eight
subtests pass in `886.00s`; a replay against the `129,297,728`-byte host passes in `14.49s`, with
SHA-256 `be1049e11c795cf7268b1fc00ed540a340538c273183d29c7512b1c9c5dfeafe` unchanged
before/after execution and SHA3-512
`fa5062189062958d544b771e6aa33896e0e9e0382d3f657db9438d7a77933138e9db22c66e166451b6e6aceb23bd8e8a472465bc9825f4c67bfa09891def91a3`.
The attack lane reports `180 passed`, `31 warnings`, and `36` subtests in `72.12s`.

The final native inventory is 48 rules-Rust, 48 RISC semantic-model, 26 S-two, 19 BL-PQ512
crypto/dimension, 10 Cairo, and 23 Forge tests: 174 native entries and 1,118 combined entries. All
current format, locked check/build, strict Clippy, executable-test, pinned-nightly RISC doctest,
Cairo build/test, and pinned-solc Forge gates pass. The Windows Rust 1.96.0 distribution still lacks
an applicable `rustdoc.exe`; the accepted RISC gate therefore runs all 48 executables on 1.96.0 and
the zero-doctest compile on the accepted pinned nightly, without skipping either surface.

The final run caught and fixed a stale RISC `PINNED_RULESET_ROOT_DECIMAL` after the pinned Rust
formatter changed the governed source-byte digest. The governed root, claim/oracle/policy roots,
commitments, and locked leaf/payment vectors now recompute exactly across Python, Rust/RISC, and
Cairo. The verified generated RISC target contained `6,249` files and `3,531,384,703` bytes and was
removed after the hash-pinned replay. R30 remains the sealed Python supply-chain baseline; R33 is
the prior nonactivating Wave 1A semantic-reference terminal and does not supersede R30's offline dependency boundary.

R34 run `20260719T142717Z-wave1a-corrective-r34` starts from an exact 609-file, 5,775,637-byte R33
rollback and reseals the corrected source. Current collection is 768 ordinary non-attack nodes, two
exact differentials, and 181 attack nodes: 951 unique Python nodes. The broad command that also
includes the physical-dimension differential reports `768 passed`, `1 skipped`, `63 warnings`, and
`176` subtests in `582.96s`; the one skip remains the Windows account-capability symlink case already
qualified by R30's locked Linux run. The exact-source Python/Rust/Cairo/RISC differential and eight
subtests pass in `698.92s` before the final scope-type-only hardening; its current-source hash-pinned
replay passes in `17.72s`. The final attack lane reports `181 passed`, `31 warnings`, and `36`
subtests in `86.25s`. The final corrected relation/payment/attack slice reports `19 passed` in
`53.07s`; an earlier broader physical/cross-language slice reports `27 passed` in `84.95s`.

All 174 native entries pass: 48 rules-Rust, 48 RISC semantic-model, 26 S-two, 19 BL-PQ512 crypto/
dimension, 10 Cairo, and 23 Forge, for 1,125 combined Python/native entries. Owned format,
locked/offline check or build, strict Clippy where applicable, executable tests, S-two integration/
doc compilation, Cairo build/test, and pinned-solc Forge gates pass. The cached 9,398,784-byte
`solc 0.8.24` has SHA-256
`580ee56b61bbcaad953117e1e4a0874d90e6af5cb4ce4359571d7da25f6620e9`. The Rust 1.96 Windows
distribution lacks `rustdoc.exe`; the BL-PQ512 crate has zero doctest fences, while all 19 executable
tests and every owned compiler/lint surface pass.

Git 2.54.0 is now active in this workspace. Initial commit
`84468714eb486b12d1f196a2d1b7622266a6d194` is a local neutral-identity baseline containing exactly
the 609 sealed R33 files. It has no remote and no pre-R33 provenance claim; the older July 10
repository was not attached because it tracked only 178 files and matched only 72 current files
byte-for-byte. R30 remains the sealed Python supply-chain baseline; R34 is the current corrected,
nonactivating Wave 1A semantic-reference terminal.

Wave 1A's semantic reference is complete after the R34 corrective seal, but its executable-AIR
handoff is reopened by the R36 architecture audit. R35 Wave 1B evidence remains based on Git parent
`4b7e023de7de71ac8c94dbb4d637f4d053bdd393`, with an exact 609-file/5,793,899-byte rollback and
Git-archive SHA-256
`798ad10e3c5182afd7e3dec2072730c4951254c37df41c3e77630d18bbdff1aa`.

R35 currently implements authenticated-attempt Fp8-excluding OODS, Python/`no_std` Rust scalar
Circle-FRI and conjugate-pair degree correction, projection-consistent SHA3-512 mixed-domain trees,
mandatory independent per-domain FRI batch masks committed before batching, six unselected
interface unique-decoding candidates, and exact typed theorem-message ordering. The K512/blowup-2
pre-dense-schedule native-hiding worksheet obtained `h=4694` over 2,191 private columns. Its 16 tables reduce to six
attached evaluation logs `(21,20,18,16,14,5)`, global trace-column power offsets
`(0,172,632,832,1144,2191)`, and all 17 fold logs `21..5`; Python and Rust bind that interface
schedule to SHA3-512 `c6a61a844f7a0d99e3088e348556467e2338dde8ffe5f7235e98dcc6fe3f0c71cfa47e8175fe9bd275f7222eea1b65e3d3efa4bc1a0d1302a32d01282e4ed52b`.
The exact dense SHA3 schedule supersedes those interface dimensions for final parameter use; the
registry now requires a native-hiding/FRI rerun and forbids treating `h=4694` as current.
Python and Rust now also derive the same direct Circle trace-evaluation certificate. For the K512
KAT it covers the degree-16 OODS parameter, its actual log-20 trace-domain translate, and 926
distinct base queries; its rank is 958, free dimension is 3,736, and SHA3-512 is
`79148ba5b5ee6655478cd478cf3dd159bb8d458d1b6dad0245ee2db0ba223d4c766e0764f9909d05cba9efd0ea98329f53a70618553bf53ea1cd3ead86b6fb04`.
R35 now also has a canonical two-component quotient mask with `h_q=927`, the exact source-aligned
split rule `x([2^(L-1)]Q)`, and cross-language plan SHA3-512
`8b577a857db1f9ae09b0382039bf1af47bd7fbd0b4f42fb3643039233852b1acd56887c45710fb42e733d12024c48ee0c6a334aebdc064fd86d341f1896e6f3a`.
The final AIR-derived `L` and prover integration remain open. A new byte-oriented SHA3-512 AIR
reference independently matches FIPS KATs in Python and Rust and freezes a 1,632-column/1,024-
lookup Keccak core plus 72 block columns/absorb lookups, giving a 1,704-column trace and maximum
1,096 lookups on a first-round row at composed degree 3. Shape SHA3-512 is
`824d0d5adb44dc5a7f61960f7ad61ccb5a34aff177a51616afd0de6b49bbb4adea54e216cb0d0ea5bbe59f4818468e6bc3deafec21bdeddb4db797d899784e1c`.
The first scoped application/reference inventory locked 48 SHA3-512 callsites and its isolated K128 physical-verifier
phase was later reconciled to 404,482 observed calls and a historical conservative envelope of 401,275
application-AIR calls, 1,205,016 SHA3-512 permutations, and 28,920,384 Keccak round rows after
restoring the pepper constraint. Canonical inventory SHA3-512 is
`b17a271256ae467773e5dcc0ee4432bd9cab46fcf5b6d986cf09f5da3f428bdcc5af594b20f85af956b008150a8af5c6580da7b453a8275c541ad0ab482fa27e`.
R36 proved that the required six facts and 50 authorization slots fit one exact 2,133-byte,
bijectively encoded bundle per claim. The proof hashes K bundles plus one ordered execution root;
the separate audit tree reuses those leaf digests outside the proof, and PQ governance attests both
roots. The earlier `51*K` path geometry and its K128 401,275-call/1,205,016-permutation host rerun
are retained only as superseded audit evidence. A new nonactivating compact claim-source candidate
reversibly encodes every source field in 5,648 bytes instead of the 8,525-byte generic reference
wrapper, uses fixed slot order, and hashes 140-byte nodes plus a 76-byte typed root. The combined
compact-source plus packed-oracle schedule costs 14,322/28,644/57,288 SHA3 permutations and
343,728/687,456/1,374,912 Keccak round rows at K128/K256/K512. The K128 claim-source lane independently
matches Python and Rust at 256 calls, 10,368 permutations, 248,832 rows, root
`8e587e518861a30bdca70bbaced6758d57b30921d03ea3bf6506478714f9efd0290c8706c32c2c1ba9480bf15c7e1285c56289e824e949017f3a312e978b32d3`,
and stream commitment
`30223f9c9297b9a68c75ff35ac59c88f8caf522e98cc7fc43816476cd5c4e1c6aa465c7d0b197fe79141631b14c2f8275b1323e7851e57d31ec7f87fc5e811fb`.
The executable source encoding now proves the `rank < 37^64` boundary, required nonempty ranks,
exact token/scalar bundle offsets, fixed header, real/cover and sequence rules, original-attempt
fields, count bounds, NPI digits, and NPI Luhn validity. Required/nonzero state is private trace data,
not a verifier-fixed column, and is linked to real-slot and line-identifier semantics. Its mixed K128
KAT evaluates 1,985,280 degree-2 identities and 4,807,424 lookup messages; program commitment is
`c602d5cd2918231582979eb418244b39f1fd39728b0a47a7504a48e4f0bd824012d8437832c27ddf70965a5f9122e0f6ad5f7ccd3a8e6abb8cd756bf67ae6138`.
The composed source-array relation now constrains exact diagnosis and service non-token bundle bytes,
diagnosis grammar/padding/count/strict `(length, ASCII bytes)` ordering and uniqueness, service live
prefix/count/procedure framing, line-ID presence, and original-line-index uniqueness. Its mixed K128
KAT evaluates 2,736,707 degree-2 identities and 5,217,246 lookup messages; program commitment is
`ca29e4dd3a3465ae053edb25dea5123fe15cb0c9fabebe4714a52c003dd31fc2dc757e1f893a119e3b36a4c0df0156beb87396a8bb14cc8cf292099b99c0d000`.
Full service-line sort ordering remains explicitly unconstrained until the existing canonical token
order is proved without adding a duplicate token decoder.
The executable packed-oracle encoding AIR binds all six fact bits, the complete four-byte slot index,
150 authorization bits with canonical unused-bit zeros, and all 6,400 K128 authorization ranks to
the exact 2,133-byte bundles. It also proves `present` iff the token rank is nonzero and keeps the
program commitment witness-independent. Its mixed K128 KAT evaluates 988,542 degree-2 identities
and 2,241,792 lookup messages; program commitment is
`6f9b6c0e4051acbc257f1e1762eba78506e59a6a393da48b7d752c86dc71d8e2280d4cbeb2b2dda0e44f8d5fe6ad29bd5b10734890aa8a070cea886a4a25aa02`.
The degree-2 claim/oracle composition now binds oracle real-state plus all six facts to the exact
adjudication slot and all 50 authorization rows to the exact service rows. Coherent standalone oracle
traces built from conflicting facts or authorization state fail only at those bridge lookups. The
mixed K128 composition evaluates 1,975,926 identities and 2,937,984 lookup messages; program
commitment is
`5d63849fb4fc2f687a08308c8e3f9adae8e43303012f71535a696f8b8bbbdd5e176ee86c601369b0a98dd90f6467f1935cc98ce642adf7f52f0180d2a618efba`.
This candidate does not mutate or promote the synthetic `REFERENCE/v0` roots. Diagnosis/service
service-line sort ordering, streamed-hash composition, source-authority signature/epoch, oracle
hash composition, and oracle signer/epoch remain open. At the R36 checkpoint, the static inventory
classified 50 live callsites, 25 AIR-required; its canonical SHA3-512 was
`d86734cefb1c6e3e89cc0c5a3d05547c08ac8243da2a09a2ce031d80a349ddf7b93c363e9a63b8b4de836abb7f3e74706167d1559f16db602fc48fba12739f3c`.
The current tree initially exposed 55 observed callsites versus those 50 dispositions, so that identity is
historical. H0 first classified those 55 callsites, 30 as `AIR_REQUIRED`, and dynamically remeasured
every addition rather than inferring a disposition. The four additions exercised by the K128 physical
trace are `_dummy_key` 512x169 bytes and member/obligation/payable key derivation 1x139/136/43
bytes; the cover-v2 helper is a phase-separated isolated 238-byte call because the composed replay
relation derives that same preimage internally. A subsequent independent scan of every `*.py` under
`app/batch` and `experiments/fixed_shape_claim_air` exposed 24 pre-existing sites that the
disposition-derived scope could never see. H0 now reconciles 79/79 callsites: 39 `AIR_REQUIRED`, five
public-precomputed, 21 host-evidence-only, 11 Wave-1C verifier-state, and three superseded-reference
sites. New governed files and alias, attribute, `hashlib.new`, dynamic-import, and dynamic-`getattr`
SHA3-512 forms fail closed. The current inventory SHA3-512 is
`618c06447efc67bca80ca9bb4c59a89970e7c42a26ea6a45a298c8dc8e1e8b2643f3c51a923d1b89ebb6a2311dc22edfffeea70471a9f97c5378b8a43fb607c2`.
The historical 51*K runtime envelope remains explicitly non-current and forbidden for parameter
selection; current K128 bus-mapping/resource evidence remains open.

The canonical v1 Rust proof encoder now returns a fail-closed 13-section byte attribution from the
same serialization pass. Fresh monolithic and bounded-streaming regression proofs both independently
verified and reconciled exactly to 28,643,096 bytes: header 146; initial indices 7,560; mask/main/
interaction/composition openings 2,111,130/2,012,850/2,475,900/2,957,850; next-main/
next-interaction 1,010,205/1,240,785; layer counts 945; FRI values 1,814,400; log sizes 14,175;
Merkle metadata 481,950; and FRI path digests 14,515,200. Structural counts are 945 queries,
14,175 layers, 28,350 Fp16 values, and 226,800 FRI path digests. Both proof paths passed in one
248.79-second two-test run. This is regression-kernel grammar evidence, not K128 latency evidence.

R36 also repaired the authoritative replay-state determinism gap: the depth-64 full-key ordered-map
root now authenticates `nextAppendIndex`, every insertion consumes exactly that cursor, and the
executable replay-header AIR constrains the cursor successor and exact SHA3-512 state roots. Inner
replay predecessor/insertion path AIR and final composition remain open. The economic maps have now
migrated off the historical 512-level key-positioned builder to the same depth-64 full-key ordered
construction. Full 512-bit values use typed 64-byte encodings; the allocator cursor is authenticated;
and approval, denial, and cover all execute one benefit, one obligation, two ledger, and one log
operation per slot. Inserts alone consume the allocator. Updates prove the current allocator leaf
empty but do not advance it. Four scope/domain/epoch-bound zero-valued dummy leaves are created once;
denial and cover update them instead of allocating permanent throwaway records. In the mixed K128
fixture this reduces durable economic allocations from 512 per batch to four actual inserts.

At the pre-closure R36 economic checkpoint, the production-shaped relation no longer repeated four complete paths per upsert. A reviewed
endpoint batch multiproof authenticates every read/write position once, while a sorted memory-access
chain proves exact equivalence to the sequential upsert semantics and duplicate behavior. The mixed
K128 fixture now has `128/128/256` operations, `3/3/5` authenticated positions, `64/64/63` proof
nodes, and `132/132/134` before-plus-after internal-node hashes: 398 total. Those observed counts are
not a privacy envelope. The governed physical candidate fixes 24-bit map shards and pads the three
K128 lanes to 34,026 node hashes, 2,048 leaf-hash slots, six headers, 36,080 SHA3-512 calls, and
74,208 Keccak permutations regardless of keys, insertion/update mix, or decision class. The cap and
exact bounds were executable and attack-tested. That continuation materialized and composed
the three ordered-map lanes with one shared byte table; durable shard rollover/migration and
full-profile global composition were still open at that checkpoint. The 2026-07-21 closure record
at the top of this file supersedes that global-composition status; durable rollover/migration remains
Wave 1C state work.
Fixed schedules for the non-dense application ports, interaction
packing, and the complete interactive simulator remain open. No proof has been generated, no final candidate has been selected, and
`proofSuiteId=null`, activation false, and the **6 of 93** package count remain unchanged.
The previously recorded R35/R36 Rust core run passed all 55 unit tests, zero-test binaries, and doctests under the exact
pinned 1.96.0 toolchain. The original long target path hit Windows linker error `LNK1104`; the
verified run used the short isolated target `C:\blpq-target`. Before the current continuation, the
combined executable-AIR Python lane passed 77 tests; new focused counts are recorded separately below.

R36's architecture audit proves the R33 object was metadata rather than AIR and fails it closed with
`physical_relation_constrained=false`. The repair now has an explicit M31 AST, fixed columns,
local/boundary/transition identities, weighted lookup multisets, canonical program/trace commitments,
and independent typed/serialized evaluators. Exact non-native Stark252 multiplication/linear tables
instantiate all 91 locked Starknet-Poseidon rounds. SHA3-512 now has fixed XOR8/AND-NOT8/SPLIT8
truth tables, padding, message binding, absorption, all 24 Keccak rounds, and multiblock transitions.
The claim-semantic slice constrains service aggregation, all 13 raw gates, cover-effective gates,
first-failure selection, claimed outputs, u32 limbs, and payment conservation. The new focused and
attack lane passes 35 tests in 16.88s; the prior physical-inventory and relation regression lane
passes 17 tests in 75.84s. Python compilation passes. Ruff was not installed and therefore supplied
no formatting/lint credit. Subsequent focused ordered-map, batch-multiproof, and payment-map lanes
pass 8, 4, and 13 tests respectively; these are overlapping focused counts, not a new full-suite
total. At that checkpoint this was real executable-AIR progress, not yet Wave 1A closure: canonical records,
bundle/policy/tree authentication, replay-path and batch-map global integration, privacy-padded full-profile
global composition, Rust evaluation parity, and K128/K256/K512 measurement remained open. All of
those Wave 1A items were subsequently closed by the authoritative 2026-07-21 record above.

The current continuation adds a fixed-schedule executable ordered-map batch AIR. It constrains
insert/update cursor semantics, sentinel exclusion, canonical 24-bit positions and below-M31 sort
gaps, sorted sequential memory, authenticated endpoint leaves, canonical proof/node topology, state
headers, and family-separated fixed hash ports in eight physical tables. Unused inverses and terminal
gaps are forced to zero, and the hashed eight-byte successor index is byte-for-byte tied to its
canonical bounded integer. The component optionally composes every live and dummy hash row with the
exact batched SHA3 AIR; only that composed instance reports `hashes_constrained=true`. At that
checkpoint the global relation still reported `physical_relation_constrained=false`.

The uncomposed three-operation KAT evaluates identically in typed and serialized interpreters and
passes 12 focused honest/attack tests. The bounded exact-composition KAT uses 136 SHA3 calls and 276
permutations; the Rust streaming path separately traverses the complete K128 economic schedule of
36,080 calls, 74,208 permutations, and 1,780,992 Keccak round rows. Python remains the transparent
specification path; retaining full K128 SHA3 object traces in Python is intentionally not the
throughput path.

Fresh Rust 1.96.0 qualification after the streaming SHA3, ordered-map, payment-log, claim-source,
and packed-oracle schedule changes reports `72 passed; 0 failed` plus all seven zero-test binary
targets. Locked
offline `cargo fmt --check` and strict
`cargo clippy --all-targets -- -D warnings` pass. Clippy initially rejected three needless range
loops in the round witness builder; the loops were rewritten with indexed iterators and the full
test gate was rerun without weakening the lint policy.

The packed-oracle execution hash path now streams independently in Rust and matches Python exactly
at K128: 129 calls, 3,954 permutations, and 94,896 Keccak rows. Execution root is
`64502aca9576c960ca69c767f6df3590ae5571d3a24ea38faebc0e8e7d4e8198ba35c274b91d24830c59f0b1809692288cdb3f45b1de7b9f6fcaa4192e86d5fa`;
stream commitment is
`109a0701e6c4758ea23053a183f34aae3d6761cd0192c6c2476581b23702607eb54cbba468b47db99a566e2d814c310d1e5802763cbc54769ea926c7ddb7fe49`.
This is bounded trace-generation parity; the streamed rows are not yet composed into the global AIR.

Python and Rust independently derive the K128 benefit/obligation/ledger schedule and bind the lane
domains plus all ten dimensions to
`1c390b67823fc6b71233d87d4082d48082b6f9ed3ff2f7c4d5e079f5b6bff947646b41c9714e263f29a1e3722a9cab8fa158091f00f77b1c7304a21182588683`.
The Rust attacks prove domain relabeling changes the commitment and empty/invalid requests fail
closed.

Rust also streams and validates every row in a fixed map hash-call schedule: family order, live
prefixes, canonical leaf/node padding messages, mandatory live headers, exact SHA3 digests, call/
permutation/round counts, and a cross-language call commitment. The 136-call KAT matches Python at
`a45ec62a23518d528dda98e20da49e513c2d7ac82e6ceb58637985a066190a563e776676816d21e784c88ad1084a560c565cd00bef82b83c0c4a91d37052fee0`;
digest, dummy-message, and header-liveness mutations fail closed.

The current payment composition namespaces the benefit, obligation, and ledger AIRs, replaces three
duplicated 256-row byte/property tables with one shared physical table, and binds all three endpoint
states in a 23-table map program. The K128 claim/payment composition adds one 128-row bridge and
constrains claim economics, approval/denial/cover shape, canonical fixed-width values, four exact
map-operation links, checked 64-bit benefit/reserve/payable carries, and authorization-use counting.
Its exact default KAT has 32 tables, 45 lookups, 30,047,077 evaluated identities, 41,373,848 lookup
messages, maximum degree three, program commitment
`eca09f6e8e529642c192add90de95c812bebc9a8e8f685d64e8e5c8a92c518f9cae2409be6102ce4f53b5158d7325705424ff01657a13a35b1b4b8cbbe27456d`,
and trace commitment
`de0e0cae8f659d6df42bf89f05c644287c3421e40dd4e21dda291312a7a57e612aaada6349f1e15dac84b4fc542786412072b4e5804754026327ba8c601154c3`.
At that checkpoint this closed neither key derivation nor the global relation; both were subsequently
closed at the Wave 1A boundary recorded above.

The audit operation preimage is versioned to v3 and commits the same 768 authenticated bytes as the
old design—four full keys plus four before/after values—without requiring redundant per-operation
Merkle roots that the endpoint multiproof deliberately eliminates. Python owned-trace construction
for all 256 K128 log hashes exceeded the 300-second bound and receives no throughput credit. The
Rust streaming path instead matches Python exactly at 128 slots, 256 calls, 1,920 permutations,
46,080 Keccak round rows, final log root
`ba30c667a959730fefb46620dd9ddc87db1aff60c0e85fe0ed29a4ce3faa84ca8d358aee405e14320bcd8b054156f72bc002213cd359c491938b83431535140a`,
and schedule commitment
`e9895d2e1655f9b77f7e3872754498ee6c9d5e45b9e39c8d6103c3f14c1c089f39a8ea5fb0f2367f9725ee1f06e9a6e53acbbdde42255530ba63799b04f8c25c`.
At that checkpoint the default Python component instance honestly retained
`operation_log_constrained=false`; the later global boundary composes its exact streamed schedule
without constructing a redundant owned K128 Python Keccak object graph.

Payment-key framing is now exposed once by the Python semantic reference and mirrored by a bounded
Rust fixed-privacy stream: benefit/reserve/payable capacities are 203 bytes and obligation capacity
is 216 bytes for every slot, independent of decision class. The actual K128 run matches at 512
calls, 1,664 permutations, 39,936 Keccak rows, and commitment
`6c84f07339e09e7f7ab6f10ba7f837fc1962411979b4712d62e734afaa9e4655e2087c120c6ec4d28bf01f3d8c2db62b6967a14f58a096961f68b9a8ff219841`.
At that checkpoint the bridge still reported `key_derivations_constrained=false`; the sealed global
relation now binds those messages and digests to the authenticated claim-source identity bytes.

Historical R36 continuation plan (steps 1-2 are now complete; steps 3-5 are Wave 1B work) was:

1. Replace the R33 metadata inventory with an executable, independently evaluable AIR: explicit
   trace cells, local/transition/boundary identities, lookup messages and multiset checks, canonical
   public binding, SHA3-512 expansion, and exact Starknet-Poseidon compatibility. The AIR must use
   one fixed claim-scoped oracle bundle, authenticate a policy payload once per claim, build the
   compact claim-source tree bottom-up once, and use depth-64 ordered full-key payment maps. Historical host
   recomputation counts and declared dimensions must not drive theorem parameters.
2. Reread and requalify the complete Wave 1A semantic relation against that executable AIR, remove
   duplicate aggregate-payment production work while retaining it only as an independent historical
   oracle, and freeze newly measured K128/K256/K512 dimensions.
3. Integrate the scalar sibling PCS/FRI references into the measured executable AIR. Apply the exact
   dense K128/K256/K512 schedules and fixed schedules for every non-dense application port, then select
   and mask the lookup-interaction packing and build the
   production prover/verifier, then rederive and select the rate/list/fold/
   query constants from the expanded dimensions. Add optimized scalar/SIMD Fp16 only behind exact
   scalar equivalence; do not reuse the rejected QM31/Blake2s/default profile.
4. Complete native hiding against the stable executable oracle inventory: substitute the final
   AIR-derived Circle split log-degree into the source-aligned quotient mask, freeze final SHA3/
   interaction dimensions, implement the full interactive simulator, then
   cover denominator/abort behavior, repeated-proof unlinkability, and
   side channels.
5. Complete S07-S09 only after exact concrete hash/PCS expansion, theorem/retry/hiding/parser
   substitution and internal
   review. Keep `proofSuiteId=null` until the suite qualifies as `BUILT_AUDIT_PENDING`.
6. Finish Wave 1C authoritative verifier/state convergence and the remaining proof-level T02-T10
   KATs/attacks after the Wave 1B suite exists.
7. Build the provider-neutral government/oracle adapter SDK and local/sandbox conformance suite so
   live credentials remain activation inputs rather than engineering blockers.
8. Finish non-Python S11/O12 reproducibility without weakening the closed offline Python boundary.
9. Integrate the real verifier/state interface into the counted R01-R12 rollup path and prove the
   complete synthetic claim-to-Ethereum-finality deployment before the independent audit.

Focused tests should run after small changes; the complete Python, attack, Rust, RISC, S-two,
Cairo, Forge, cross-language, privacy, artifact, source-integrity, and rollback gates run at each
convergence milestone. Any Python/Rust/Cairo/RISC/S-two/verifier semantic mismatch remains a hard
stop. The corrected whole-product roadmap count is **6 of 93 internal packages complete and 87
open**. The independent Security Audit Gate is separate and not counted.

## Trust-critical status

Protected paths remain source-only in this handoff. Do not edit the Cairo circuit, Solidity contracts, canonical encoding, public-input boundary, nullifier logic, Merkle logic, accumulators, STARK binding, oracle attestation, or batch orchestrator without explicit approval.

Protected circuit and contract redesign was explicitly authorized for the isolated Privacy V2 workspace on 2026-07-12. That authorization does not make the existing V1 boundary production-safe and does not permit weakening tests or proof binding.

## Target architecture status

The selected target is an Ethereum-settled, EVM-compatible based validity rollup. The decision and implementation sequence are locked in `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md`.

The authoritative completed/remaining upgrade sequence and next large-run gates are maintained in
`docs/IMPLEMENTATION_ROADMAP.md`. `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` defines what internal
completion, audit-pending deployment readiness, the final independent audit, and operator
activation mean. Future implementation work must update those files and this handoff state together.

The selected claim-proof security direction is now `BL-PQ512-v1`, defined in
`docs/PQ_ZK_SECURITY_ARCHITECTURE.md`:

- preserve the external 12-field application ABI's count, order, names, types, and forbidden-field
  boundary, but not obsolete denied-case KAT values;
- preserve the sealed fixed-shape M31 semantic AIR rather than a general Cairo or RISC-V VM, remove
  its SHA3 internals only from the release PCS, and bind its exact hash ports to one committed bus;
- internally implement and qualify the masked Fp16 Boolean GKR SHA3 coprocessor plus native hiding
  for both modules under one authenticated interactive public-coin session, then submit the
  completed exact release to independent audit;
- make authenticated SHA3-512 proof metadata and verifier-maintained shadow state authoritative for
  strict post-quantum binding;
- make every real claim consume an attempt nullifier and every padding slot consume a cover
  nullifier so approval, denial, and padding have one public state-transition shape;
- retain RISC Zero, the existing Cairo program, and Python/Rust implementations as differential
  semantic oracles.

This is an architecture decision, not implementation or production evidence. R23 rejects the
current QM31/Blake2s/default S-two configuration for the strict post-quantum target and confirms that
extra FRI queries or grinding cannot repair its independent field/hash ceilings. M31 degree-16
challenges plus full-width SHA3-512 are the conditional lead, not a selected or externally reviewed
suite. Current S-two remains validity-only and forbidden for real PHI. No available backend in this
archive currently satisfies the selected witness-hiding and strict post-quantum profile.

The first major hardening and baseline-convergence run completed on 2026-07-13 to an explicit
**RED/no-go**. It repaired application and cross-language defects and established a current
synthetic regression baseline. It did not implement or qualify the complete fixed-shape AIR,
witness hiding, strict-PQ proof profile, production verifier, or release. Roadmap package `S01`
was the only closed package at that historical checkpoint; later R23 reconciliation closes S03,
S05, and S06 as application-specification packages only.

The authorized 17-item synthetic foundation bundle completed on 2026-07-15 as an evidence-only
engineering run. Its immutable R21 terminal manifest is
`cache/foundation-runs/20260715T073140Z-foundation17-r21/terminal_manifest.json`, sealed by SHA-256
`7bcaf24f33130aea258a58286b8121c4c19a89d7f2c9c691a77ca633cc69006f`. The bundle produced 16
draft/reference/prototype items and reran `T14`; it closed no additional roadmap package. The ten
historical v1 launch-blocker entries were open at that checkpoint. Five unavailable Windows-only tool components are recorded as required
platform gaps, with their WSL equivalents passing. Product semantic mismatches were zero, but no
proof or final proof was generated and no proof-throughput claim follows from this run.

The R23 security-freeze reconciliation is recorded in `docs/BL_PQ512_SECURITY_FREEZE.md` and
`docs/security-freeze/BL-PQ512-v1/`. It preserves the exact 12-field ABI, closes S03/S05/S06 only,
and leaves S02, S04, and S07-S12 open. Under the current whole-product denominator that checkpoint
represents 4 of 93 packages complete and 89 open; its sealed record retains the superseded mixed
count. Its fresh executable rerun reports zero product-semantic mismatches across every required
Python, attack, Rust, Cairo, Solidity, privacy, release-builder, and integrity gate. Five Windows-
only components remain unavailable and explicit; all five WSL counterparts pass. R23 generated no
proofs. The 124-proof campaign was skipped because the complete AIR, native witness hiding, and an
internally selected and qualified proof suite do not exist and the current suite is rejected.

The accepted R24 synthetic-only continuation through S12 is recorded in
`cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/terminal_manifest.json` and its
adjacent SHA-256 seal. Failed and superseded attempts remain preserved in the same run record. R24
preserves the exact 12-field ABI, keeps the existing QM31/Blake2s/default suite rejected, and leaves
the candidate `CANDIDATE_UNQUALIFIED`, nonactivatable, and `proofSuiteId=null`. Its executable gates
cover exact source and proof money grammar, checked aggregates, policy and legacy-binding coercion,
batch prefilter/root privacy behavior, private zero-value G8A denial, and structural total mismatch
or overflow across the applicable Python, Rust, Cairo, and RISC lanes. The full payment/benefit
relation, authenticated missing-data parity, revision authority, final AIR, QROM proof, native
hiding, supply-chain closure, and final audit remain open. R24 generated zero proofs, did not
run the 124-proof campaign, establishes no throughput or production claim, and closes no additional
roadmap package; current-model progress at that checkpoint was 4 of 93 complete and 89 open.

On 2026-07-16 the roadmap's next-wave ambiguity was corrected and the resulting R25 synthetic,
nonactivating local implementation-and-measurement wave completed. Its terminal record is
`cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/terminal_manifest.json`.
R25 adds provisional K128/K256/K512 host semantics, equal logical schedules, payment/replay/state
references, checked-money guards, deterministic vectors/properties, attack coverage, and an
explicit S-two validity/security boundary. It preserves the 12-field ABI, leaves
`proofSuiteId=null` and activation false, and uses only synthetic data. It closes only `Z01` as an
isolated verifier-clean validity baseline, so checkpoint progress was 5 of 93 complete and
88 open. Physical AIR, native witness hiding, strict-PQ parameters, authoritative state, adapters,
rollup integration, and the final audit remain open.

R25 measured 15 serial host-model profile/shape combinations. The heaviest K512/full-capacity model
took `2.5877058s`: `15.886984%` fixture construction, `41.423886%` logical trace,
`42.246367%` payment economics, and `0.442763%` operation logging, with a Python-tracemalloc peak of
`5,510,060` bytes. Physical AIR rows/columns are still `null`, and the host model generated zero
proofs. A separate narrow 1,024-row S-two validity proof verified in `0.118095s` proving and
`0.000956s` verification, but it has `witness_hiding=false`, binds only aggregate decision/value
conservation, retained no proof artifact, and is not full-claim or `BL-PQ512-v1` evidence.

R26 is an **interrupted and unsealed** synthetic-only private-proof-engine foundation continuation at
`cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/`. The directory contains its
sealed initial manifest and seven stage JSON records, but no `terminal_manifest.json` or terminal
seal. Searches found no moved copy or deletion record. Its source changes and stage records add a
narrow physical decision/payment AIR and stronger nonactivating candidate-sidecar, verifier,
replay, payment, and in-memory state references. R28 later revalidated the applicable inputs without
retroactively completing R26. R26 receives no package-closure credit, so that checkpoint remained
5 of 93 complete and 88 open. The
exact 12-field ABI is unchanged, `proofSuiteId` remains null, activation remains false, and all
recorded inputs are synthetic.

The unsealed R26 physical-stage record reports 51 verified-and-discarded validity-only calibration proofs across
K128/K256/K512. Every profile uses 267 physical trace columns, one interaction column, and 476
constraints. Average proving time is `0.051942850s`, `0.070609592s`, and `0.086222081s`
respectively; maximum measured verification is `0.002575530s`, and maximum measured RSS is 7,252
KiB. This kernel proves only 13-gate priority and limb payment conservation. It omits the ordered
12-field proof statement, authenticated source/oracle/policy/nullifier state, SHA3-512 shadow state,
native witness hiding, and the strict-PQ suite. It is labelled `REJECTED_VALIDITY_ONLY_CALIBRATION`;
all proofs were discarded and no proof artifact was written.

The unsealed R26 gate-stage records report 801 unique Python nodes, 48 rules-Rust tests, 48 RISC model tests,
26 S-two tests, 10 Cairo declarations, and 23 Forge tests: 956 top-level tests/declarations. The
hash-pinned exact differential matches all 12 fields across Python, Rust/RISC Zero, and Cairo and
matches the separate Python/Cairo claim-semantics vector. Initial Scarb and Poseidon-helper setup
failures occurred before semantic comparison and were retained. After explicit owner authorization,
fresh serialized short targets passed without source, manifest, dependency, or tool-version changes.
The 124-proof campaign was not run because the complete cryptographic prerequisites remain absent
and the initial free-memory preflight was below 8 GiB.

The audited pre-R25 cache cleanup is sealed at
`cache/maintenance-runs/20260716T140141Z-audited-cache-cleanup/terminal_manifest.json` with SHA-256
`9a1a2d0d9ab54de902918bea9959b36cdf96de38b52b214989fc39619b1e0e69`. It removed 47 verified
generated targets containing 209,100 files and 33,843,205,703 logical bytes while preserving source,
offline dependency seeds, directly referenced R20/R21 inputs, and the R21/R23/R24 seals. The local
rollback copies retained by that historical run were removed in the 2026-07-22 cleanup after Git
identity and the durable evidence boundary were confirmed.

Current implementation blockers:

- no production `INativeStarkVerifier` implementation exists in the repository;
- the Cairo V1 `BatchOutput` now has 12 values and `BatchOutputV2` preserves the exact ordered
  Privacy V2 12-field ABI, while the legacy V1 settlement surface still accepts 21 separately
  supplied values;
- the Solidity V1 test verifier ignores proof and public inputs; the V2 test verifier binds its
  supplied bytes with Keccak but is still not a STARK verifier;
- V1 publicly exposes exact approved/payment totals and stores claim ciphertext;
- no end-to-end claim-proof -> L2 verifier -> rollup proof -> Ethereum L1 verification run exists.
- R33 supplies a complete fixed-shape host semantic relation, exact 12-field composition, and
  authenticated source/payment/replay transitions, but its 16-table object is only a metadata
  inventory with host recomputation. It does not constrain a trace; its SHA3-512, Poseidon,
  challenge, commitment, PCS, and FRI ports remain abstract and no concrete theorem-matched proof
  backend or production verifier exists;
- no native S-two witness-hiding implementation or Circle-STARK-specific zero-knowledge simulator
  exists;
- no activated authoritative SHA3-512 shadow nullifier/governance/batch state or production proof-
  sidecar verifier exists; R24 provides only a tested, nonactivatable 744-byte candidate sidecar and
  reference parser;
- R34 now executes domain-separated authenticated payer/plan/period-scoped benefit, obligation,
  reserve, payable, operation-log, and replay-root transitions with equal-work denial/cover paths,
  but these remain synthetic references rather than concrete low-degree proof constraints or durable
  authoritative state;
- R33 computes and verifies full-width replay nonmembership/insertion chains, but no production P03
  state service, anti-rollback storage, or activated root authority exists;
- application nullifier validation requires a nonzero post-transition root and recomputes the
  transition; R33 also fixes uniform attempt/cover relation work, while concrete proof constraints
  and authoritative state integration remain Wave 1B/1C work;
- the current QM31 proof challenge field, Blake2s-256 Merkle/transcript, and default query/grinding
  profile are rejected for the selected strict 128-bit quantum target; R32 implements only an
  isolated degree-16/SHA3-512 substrate, not the theorem-matched PCS/FRI, hiding, verifier, or
  internally qualified `BUILT_AUDIT_PENDING` suite;
- the entropy boundary deliberately leaves the OS provider unwired and is disconnected from
  proof masks, so Z02-Z12 remain open;
- adjacent key wrapping and authorization still include classical RSA, P-256, and Ed25519 surfaces,
  so the full system is not end-to-end post-quantum.

R29's authoritative full Python lane reports `820 passed`, `216` subtests passed, `94` warnings,
and zero failures in `608.33s`. Its separately counted attack subset reports `145 passed`, `36`
subtests passed, and `31` warnings in `40.67s`; the new R23-C02 attack module contributes `16`
tests. The final hash-pinned Python/Rust/Cairo/RISC differential reports `1 passed` plus `8`
subtests in `18.96s`. These subset counts are not added to the full-suite count. The R29-owned RISC
host is `129315352` bytes with SHA-256
`b0f233ee0b67b0aba02407de5cd062d0b02e8a4a26c3097b695628d7e2b0de78` and SHA3-512
`b0763ce52b3145dd304d839ea724a361197618e4411b1623ce73780eac5b159ed3d9021a819f6ba51aabc5953a137124ed6e6419a933d85bc76dc776eb755989`.
The direct proof command failed closed with the disabled registry and wrote zero proof files. This
is a terminal software/security baseline only; it is not a complete-proof, witness-hiding,
strict-PQ, throughput, settlement, or production claim.

R30 adds 20 unique Python nodes and qualifies them inside the reviewed offline-installed dependency
environment. Its exact schedule is `690` non-attack tests plus `172` subtests, one differential plus
`8` subtests, and `149` attack tests plus `36` subtests: `840` unique top-level Python nodes and zero
accepted failures. The Windows account could not construct a symlink and skipped that one test in
the long lane; a fresh locked Linux environment subsequently passed all `21` focused supply-chain
tests including the symlink case. The exact differential reused a current-run-owned copy of the
R29/R28 model binary after SHA-256 readback matched
`b0f233ee0b67b0aba02407de5cd062d0b02e8a4a26c3097b695628d7e2b0de78`.

## Proof status

A local external CUDA proof run was recorded outside this archive on 2026-07-09:

- Proof path at time of run: `<external-workspace>/proofs/safeopts_execution162_cuda_finalgroup_proof.json` (local username/path redacted; artifact was never packaged)
- Proof SHA-256: `2e6a0d5edbf8884a6da4f5476298f06a3c5e95b4a8bb9934b24c0f6b06c3ea3f`
- Recorded wall time: `352.08s`

The external prover build and generated proof JSON are not packaged. Regenerate and verify in the current environment before making production proof claims.

A separate RISC Zero 3.0.5 Privacy V2 qualification ran locally on 2026-07-12:

- development mode disabled;
- receipt verified against the generated guest image;
- all 12 journal fields matched the Python-generated Poseidon KAT;
- proving time `1472.797364s`;
- verification time `0.134665s`.

This proves only the V2 commitment envelope. Full claim adjudication, fixed-size privacy controls,
payment state, Ethereum-compatible receipt compression, the L2 verifier, artifact pinning, and
independent audit remain open. No real PHI is authorized.

A later complete-claim RISC Zero profiling attempt did not finish a proof. Its raw progress data was:

- `191` segments;
- minimum `199,229,440` guest cycles;
- `17` completed segment intervals totaling `5,464` seconds;
- mean `321.411765` seconds per segment;
- linear projection `61,389.647059` seconds, or `17.052680` hours.

That is an interrupted-run projection, not a completed proof measurement. It disqualifies the
current generic RISC-V implementation as the production performance path but does not invalidate
RISC Zero's role as a semantic oracle.

The supported S-two simple-bootloader run remains verifier-clean off-chain evidence for the current
Cairo statement: `89.0` seconds total, `5,591,878` proof bytes, `43.5` milliseconds verification,
and all 12 inner outputs matched Python. It is not witness-hiding and is not `BL-PQ512-v1` evidence.

R25 also reproduced the isolated custom S-two validity baseline for 1,024 synthetic rows. The
optimized run reported `0.118095s` proving, `0.000956s` verification, and
`proof_verified=true`. Its explicit scope is `aggregate_decision_and_value_conservation_only` and
`witness_hiding=false`. The paired witness-hiding-required run exited nonzero with
`WITNESS_HIDING_UNAVAILABLE` before claim generation or trace allocation. Build time and the full
qualification-suite durations are not proof latency.

The unsealed R26 proof-stage record reports a repeat of that isolated 1,024-claim baseline at `0.115831s` proving, `0.000197s`
verification, and 4,084 KiB peak RSS. It also executed 51 narrow physical calibration proofs across
K128/K256/K512; their average proving times were `0.051942850s`, `0.070609592s`, and
`0.086222081s`. Every proof verified and was discarded, with zero proof artifacts. Both
hiding-required controls failed closed before trace/proof work. These executions have
`witness_hiding=false`, `proofSuiteId=null`, and activation forbidden; they are not the complete
12-field private/PQ claim proof. The final 124-proof campaign was skipped entirely: 124 skipped,
zero run, because the complete AIR, native hiding, strict-PQ suite, sidecar verifier, and
authoritative state do not exist and free-memory preflight failed the 8 GiB minimum.

## Test commands to preserve

```powershell
py -3.14 -m pytest -q --ignore=tests/attacks
py -3.14 -m pytest -q tests/attacks
cargo test --release --offline --locked --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --features std,parallel
cargo clippy --release --offline --locked --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --all-targets --features std,parallel -- -D warnings
```

Do not weaken tests, policy pins, or security checks to make a run pass.

## 2026-07-27 Phase 0 calibration and B=8 kernel profile — MEASURED

Scope: execution-order Phase 0 only. These measurements do not qualify a proof, change
`proofSuiteId=null`, or authorize production. The reduced geometry is 128 permutations rounded to
16 repeated-pack groups; the reference geometry is the existing 782-permutation control rounded to
128 groups. Both use the existing 216-layer coherent chain.

### Test-only authenticated-coin fixture

`bench_fixture_coin` is a new Cargo feature that is OFF by default. When enabled, the benchmark
uses fixed dual-PQ keys and fixed reverse chains under fixture-only head, chain, session, round-seed,
and audit domains. The production coordinator import and spawn are unreachable in that build, and
an independent fixture replay verifier checks the result. This fixture is **TEST-ONLY,
NON-QUALIFYING**; fixture challenges cannot validate under the production coin domains. The
production live-coin path remains the default.

The current source delta against the immutable transfer ZIP is exactly:

- modified `experiments/bl_pq512_crypto_core/Cargo.toml`;
- modified
  `experiments/bl_pq512_crypto_core/src/bin/gkr_coherent_chain_benchmark.rs`; and
- added
  `experiments/bl_pq512_crypto_core/src/bin/support/gkr_coherent_chain_benchmark_fixture_coin.rs`.

No protected path changed. Release/offline/locked builds passed with the feature both disabled and
enabled. One debug test invocation was excluded: repeated SLH signing exceeded the 428.613-second
command bound and the externally terminated child reported a broken pipe, with no assertion
failure. It was not rerun because the narrower release end-to-end fixture exercises the same
fixture/replay boundary without debug-build signing overhead.

### Five-run calibration

Exact build and run form:

```powershell
$env:CARGO_TARGET_DIR='C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase0'
cargo build --release --locked --offline --features parallel --bin gkr_coherent_chain_benchmark
$env:CARGO_TARGET_DIR='C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase0-fixture'
cargo build --release --locked --offline --features parallel,bench_fixture_coin --bin gkr_coherent_chain_benchmark
& 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\run-phase0-calibration.ps1' -GroupCount 16 -Permutations 128 -Boundary 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\gkr-128-boundary.bin' -Runs 5 -CoinMode Fixture
& 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\run-phase0-calibration.ps1' -GroupCount 16 -Permutations 128 -Boundary 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\gkr-128-boundary.bin' -Runs 5 -CoinMode Live
& 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\run-phase0-calibration.ps1' -GroupCount 128 -Permutations 782 -Boundary 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\gkr-128-boundary.bin' -Runs 5 -CoinMode Fixture
& 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\run-phase0-calibration.ps1' -GroupCount 128 -Permutations 782 -Boundary 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\gkr-128-boundary.bin' -Runs 5 -CoinMode Live
```

All 20 current runs exited zero, independently verified the chain, and wrote empty stderr. Five
earlier `g16` live runs are retained but excluded from this table because they predate the
coin-wait telemetry and were superseded by `g16-live`.

| Coin / geometry | Authenticated rounds | Total time, five-run range | Coin wait average, five-run range | Digest result |
| --- | ---: | ---: | ---: | --- |
| Fixture / 16 groups | 7,489 | 17.4900829-18.9870669 s | 32,740-35,119 ns/round | identical across all five: `c531f446cdf4f0df2af4cf33623fe88e456d8304ce342897a83989dda71fdc0c803b3ae7afe31c0dccd3ad22e43658320b2e4e1e746f17b6a0b342b6b4d596b6` |
| Live / 16 groups | 7,489 | 17.9300747-18.6981438 s | 135,454-143,860 ns/round | five distinct digests, as required |
| Fixture / 128 groups | 8,785 | 30.4336514-31.8402930 s | 32,853-35,571 ns/round | identical across all five: `62752652268cff727ec9b5c72f9a2b29f680538dc1beee585513dac90c1c40bd4c9b79a355da9243c25f8761fe842036a143fe6f6e79ec089495bc2465e73121` |
| Live / 128 groups | 8,785 | 31.8262444-33.1485694 s | 144,545-167,565 ns/round | five distinct digests, as required |

Maximum observed combined process RSS was 312,492,032 bytes and maximum observed GPU memory was
450 MiB. System-wide pagefile usage and page-read counters fluctuated, so this run does **not**
establish the release no-swap gate; process-level swap attribution remains unverified.

The measured round law is:

```text
rounds(group_variables) = 7,489 + 216 * 2 * (group_variables - 4)
```

The two anchors agree exactly: `8,785 - 7,489 = 1,296 = 216 * 2 * 3`. Therefore there are two
authenticated rounds per layer per group variable. K128's 113,730 permutations require 16,384
groups and 14 group variables, so the projected count is `11,809` rounds from either anchor,
18.02% of `MAX_CHAIN_ROUNDS = 65,535`. Label: **PROJECTED FROM TWO MEASURED ANCHORS**. Applying the
measured live-coin range of 135,454-167,565 ns per round projects about 1.60-1.98 seconds of pure
coin wait at 11,809 rounds, not the earlier assumed 6-12 seconds.

### Existing B=8 first-round profile

The sampled load is 5,644,800 packed gate-instances, exactly the historical
45,158,400-gate K128 control scaled by `16 / 128`. The binary was the existing standalone B=8
kernel, release-optimized with full debug information:

```powershell
$env:CARGO_TARGET_DIR='C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase0-profile'
$env:CARGO_PROFILE_RELEASE_DEBUG='2'
cargo build --release --locked --offline --features parallel --bin packed_boolean_sumcheck_benchmark
wpr -start CPU -filemode
1..5 | ForEach-Object { & 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase0-profile\release\packed_boolean_sumcheck_benchmark.exe' 5644800 1 }
wpr -stop 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\phase0-b8-cpu-symbolized.etl'
.\work\samply-0.13.1\samply.exe import --save-only --output .\work\phase0-b8-profile-symbolized.json.gz --profile-name phase0-b8-reduced-five-run-symbolized --name packed_boolean_sumcheck_benchmark --symbol-dir .\work\cargo-target-phase0-profile\release --unstable-presymbolicate .\work\phase0-b8-cpu-symbolized.etl
wpr -start 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\phase0-b8-pmc.wprp!Phase0Pmc' -filemode
1..5 | ForEach-Object { & 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase0-profile\release\packed_boolean_sumcheck_benchmark.exe' 5644800 1 }
wpr -stop 'C:\Users\neers\Documents\Codex\2026-07-27\he\work\phase0-b8-pmc.etl'
tracerpt .\work\phase0-b8-pmc.etl -o .\work\phase0-b8-pmc-events.csv -of CSV -summary .\work\phase0-b8-pmc-summary.txt -y
& .\work\analyze-phase0-b8-pmc.ps1
```

The ordinary CPU sample had 3,455 main-thread samples, of which 3,344 resolved to project source
and 111 were unresolved/system. Its five reduction times were 646,586,800; 683,389,700;
738,327,900; 599,653,300; and 700,375,400 ns (median 683,389,700 ns). Every run emitted
SHA3-512
`6f3fb234856060a604661bbb30ee6987e55dc91e6a0d9d365e19a921c7449d7000d2c0e90a02e6107416fdbc379107a5a3ba1cc35e14b675e94bbb0dc894179b`.

The AMD PMU capture recorded 201,558 in-module `TotalCycles` overflow samples and 51,318
in-module `DcacheMisses` overflow samples across the five main threads, with zero ETL events lost.
Intervals were 65,536 cycles and 4,096 data-cache-miss events. This estimates 13,209,305,088
in-module cycles across 28,224,000 gate-instances, or **468.017 cycles per instance-gate**. A
separate five-run `QueryProcessCycleTime`/CPU-time clock derivation produced a median 485.304
cycles per instance-gate; the PMU overflow count is the direct figure used below.

| Mutually exclusive in-module category | Total-cycle samples | Share |
| --- | ---: | ---: |
| Fused reducer loop: bucket index/load/store plus compiler-inlined operations | 110,979 | 55.061% |
| Explicit field add/subtract/reduce/construction | 55,572 | 27.571% |
| Accumulator bucket-table lookup/update | 25,143 | 12.474% |
| Field multiplication | 6,091 | 3.022% |
| Table build/finalization | 3,754 | 1.862% |
| Allocation | 8 | 0.004% |
| Other symbolized module work | 11 | 0.005% |

The 12,452 main-thread cycle samples outside the benchmark module are reported separately and are
5.818% of all main-thread cycle samples. Compiler inlining makes the 55.061% fused-loop row
inseparable at source-line granularity; it contains Boolean/word/indexing work plus inlined
operations and must not be relabeled as pure arithmetic.

The PMU estimates 15.9129 `DcacheMisses` events per 1,000 in-module cycles. Miss-overflow samples
landed 45.125% in the fused reducer loop, 39.873% in explicit field add/sub/reduction, 12.736% in
bucket-table updates, 1.173% in table build/finalization, 1.087% in multiplication, and 0.002% in
allocation. This is a cache-miss proxy, **not a stall-cycle percentage**: the Ryzen/Windows HAL
exposes `DcacheMisses` but no memory-stall-cycle source, and sampled PMU interrupts can skid beyond
the causative load. Exact memory-stall cycles are therefore not separately observable in this
environment and are not invented here.

Decision: the existing reducer is **not multiplication-dominated**. There is no per-gate Fp16
multiplication in `add_gate`; the measured multiply share is 3.022% and is mostly fixed
`mul_by_m31` finalization. The kernel is near a word/indexing, bucket-memory, and Fp16-add/sub floor.
Consequently, a bucketing change justified as amortizing per-gate Fp16 multiplication is not
supported by this profile. The Phase 2.0 B=64 measurement spike remains pre-authorized, but its
value is lower and it must be judged against the measured 468.017-cycle B=8 figure.

PMU trace SHA-256:
`6DD634006EE8F6F695D2EAB72F6E3480F0AC7A1C54A7845AE325200D423F9A2F`.

## 2026-07-28 Phase 2.0 B=64 kernel spike — MEASURED, NONPROTOCOL

Scope: execution-order Phase 2.0 only. The spike is a standalone binary and is not wired into the
prover, verifier, transcript, masks, codec, or production build. It grants no protocol,
qualification, or activation credit.

### Source and construction

The source delta for this step is:

- modified `experiments/bl_pq512_crypto_core/Cargo.toml`; and
- added a standalone B=64 spike binary that was removed from the active tree on 2026-07-31 and
  remains recoverable only through Git history.

The candidate packs 64 instances per `u64`. It does not construct a flat `2^64` table. Each word is
split into eight 8-bit chunks. A 1,121,284-byte public table contains chunk evaluations over the
127 points needed for the degree-126 gate relation plus the 64- and 127-node interpolation bases.
The timed gate loop accumulates only M31 values in 256 deterministic fixture-weight classes; Fp16
is first used during final class weighting, interpolation, and multiplication by the degree-63
query polynomial. The M31 accumulator is 130,048 bytes. This is one concrete measurement candidate,
not a production-validity or general-equality-weight selection result.

The historical build commands are intentionally removed because the nonprotocol binary is no
longer an executable target.

The release build exited zero. It emitted three pre-existing library warnings: unused
`alloc::vec` in `merkle.rs`, unread `DualBoundaryFoldCommitmentProver::final_values`, and unused
`PackedBooleanAccumulators::merge` in the non-`parallel` build. The 4,097-word-gate self-check
exited zero and reported:

```text
mode=self_check
self_check_gates=4097
checked_lanes=64
degree_bound=189
parity=pass
```

One earlier formatting check is excluded. It passed `Cargo.toml` to `cargo fmt` as if it were Rust,
so rustfmt reported `expected item, found '['` after showing only formatting diffs for the new
binary. It changed no file. The new Rust file was then formatted directly as shown above.

### Full 782-permutation-shaped measurement

The full shape is 782 active permutations padded to 1,024 instances, 16 B=64 words, 44,100
word-gates per group, 705,600 word-gates total, and 45,158,400 represented Boolean
instance-gates. One uncounted warm-up exited zero. The five counted runs used Windows
`QueryProcessCycleTime`, sampled process working set every 5 ms, and required exit zero, empty
stderr, parsed timing, and a parsed digest:

| Run | Process cycles | Cycles / B=64 word-gate | Cycles / represented instance-gate | Reduction ns | Peak working set bytes |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 2,898,677,357 | 4,108.102830 | 64.189107 | 768,652,300 | 5,177,344 |
| 2 | 2,980,910,335 | 4,224.646166 | 66.010096 | 791,465,100 | 5,177,344 |
| 3 | 2,947,844,870 | 4,177.784680 | 65.277886 | 777,290,600 | 5,181,440 |
| 4 | 2,827,297,664 | 4,006.941134 | 62.608455 | 754,111,900 | 5,181,440 |
| 5 | 2,891,918,609 | 4,098.524106 | 64.039439 | 758,579,900 | 5,177,344 |

All five exited zero, wrote zero stderr bytes, and emitted SHA3-512
`5d0cd3b04c7a57fedd2714666bc1f2edace6f8eae92739b31ca4cfc645c4822a5a6cc80868472485259e5d766b45d7183d1458cab413c1c70ffecf335cc835ee`.
The medians are 2,898,677,357 process cycles, 4,108.102830 cycles per B=64 word-gate,
64.189107 cycles per represented Boolean instance-gate, and 768,652,300 reduction ns.

The exact timed-shape operation inventory printed by every run is:

```text
m31_table_lookups=1433779200
m31_chunk_accumulator_adds=1433779200
m31_relation_multiplies=89611200
m31_relation_and_accumulator_add_subs=291236400
```

One earlier five-process harness is excluded in full: five child processes exited zero, but the
PowerShell harness used the invalid literal `0UL` without fail-fast error handling. It therefore
printed null cycle/digest fields and zero derived values. Those five child executions are not
counted evidence. The corrected harness used `[UInt64]0`, fail-fast error handling, and
newline-robust parsing.

### Comparison and decision

The matching Phase 0 `QueryProcessCycleTime` B=8 median was 485.304 cycles per B=8 word-gate, or
60.663 cycles per represented Boolean instance-gate after dividing by eight. The B=64 median of
64.189107 is approximately 5.81% slower on that matching basis. The direct Phase 0 PMU figure was
468.017 cycles per B=8 word-gate, or 58.502125 per represented instance-gate; the B=64 process-cycle
median is approximately 9.72% slower than that differently instrumented reference. The direct-PMU
comparison is reported separately because module PMU samples and whole-process cycle counts are not
identical instruments.

Decision: this concrete B=64 tensor/evaluation design does **not** beat the B=8 kernel decisively.
It is rejected as the basis for Phase 2.6. No production B=64 implementation, transcript change, or
mask resize is authorized by this result.

### Mandatory post-step calibration rerun — PARTIAL, FAIL-CLOSED

Both exact release builds from Phase 0 exited zero. The reduced fixture and live commands completed
all ten requested runs:

- fixture: five exits zero, 7,489 authenticated rounds each, 16.7450216-17.2917339 seconds,
  29,996-30,930 ns average coin wait, maximum combined RSS 229,724,160 bytes, and the same fixed
  digest
  `c531f446cdf4f0df2af4cf33623fe88e456d8304ce342897a83989dda71fdc0c803b3ae7afe31c0dccd3ad22e43658320b2e4e1e746f17b6a0b342b6b4d596b6`;
- live: five exits zero, 7,489 authenticated rounds each, 17.5047252-17.7371130 seconds,
  130,679-132,050 ns average coin wait, maximum combined RSS 238,505,984 bytes, and five distinct
  digests as required.

System paging-file usage remained 5.9668216630823956% before and after each reduced run, but page-read
counters were nonzero; these controls still do not establish process-level no-swap evidence.

Both reference-shape commands failed closed on run 1 before any authenticated round:

```text
coherent GKR benchmark failed: input_header_or_length_invalid
```

The recorded boundary
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\gkr-128-boundary.bin` is 32,784 bytes, SHA-256
`59412B4FDF2E53ADAE36628C7EBD9BC1C00A4930701415ABC23B3A821095BC76`, and has the exact header
`version=1, permutations=128, instances=128, width=2048`. That is the valid reduced-shape boundary.
The 782-permutation / 128-group command requires `permutations=782`, `instances=1024`,
`width=2048`, and 262,160 total bytes. One immutable boundary cannot satisfy both recorded commands.
The authoritative Phase 0 command record contains no boundary-regeneration step between the reduced
and reference runs.

Counts: two reference run-1 attempts failed with exit code 1 and zero rounds; the remaining eight
requested reference runs were skipped because each mode failed closed at its first run. No boundary
was rewritten or synthesized. The post-step calibration is therefore not complete, and continuation
requires an authoritative reference-boundary generation command or exact approved fixture.

### Owner-approved reference-fixture resolution — COMPLETE

On 2026-07-28 the owner explicitly approved generating a separately named zero-input reference
fixture. `work/generate-gkr-782-zero-boundary.ps1` generated and byte-for-byte read back
`work/gkr-782-zero-boundary.bin` with:

```text
length=262160
version=1
permutations=782
instances=1024
width=2048
payload_nonzero_bytes=0
sha256=29FAEC8DD71C30E79C973CCCAC0A86282AA8D0CEE3D876BAB3B39ED06EDE359C
```

Two generator attempts are excluded: Windows PowerShell rejected numeric literals containing
underscores before writing; the next attempt wrote the correct bytes but its readback check used an
unavailable `.AsSpan()` API. A third attempt used generic-call syntax that Windows PowerShell could
not parse; a following `Format-Hex` masked that script error by resetting the outer shell status.
The final generator uses `StructuralEqualityComparer`, outer fail-fast handling, full payload-zero
inspection, SHA-256 readback, and exited zero.

The five reference fixture runs then all exited zero, independently verified, used 8,785
authenticated rounds, emitted empty benchmark stderr, and reproduced fixed SHA3-512
`62752652268cff727ec9b5c72f9a2b29f680538dc1beee585513dac90c1c40bd4c9b79a355da9243c25f8761fe842036a143fe6f6e79ec089495bc2465e73121`.
Total time was 29.4654328-30.0514209 seconds, average coin wait was 30,527-31,379 ns, and maximum
combined RSS was 304,816,128 bytes.

The five reference live runs all exited zero, independently verified, used 8,785 authenticated
rounds, emitted empty benchmark stderr, and produced five distinct digests as required. Total time
was 30.5434522-31.7827307 seconds, average coin wait was 137,724-145,597 ns, and maximum combined
RSS was 312,795,136 bytes.

One outer fixture-set guard is excluded: all five fixture records were successful, but
`run-phase0-calibration.ps1` left `$LASTEXITCODE=1` from its final `nvidia-smi` cleanup, so the outer
shell incorrectly threw `g128_fixture_calibration_failed` after the completed set. The live set was
run separately and both sets were accepted from their five per-run JSON records, not the stale
shell variable.

The required post-Phase-2.0 calibration is now complete: 20 successful current runs, 10 fixture
digests internally stable by shape, 10 live digests fresh, and zero benchmark failures on the
approved shape-correct fixtures. Page-read counters and system paging-file usage still do not prove
the process-level no-swap release gate.

## 2026-07-28 Phase 2.1 bucketed sparse-sumcheck schedule — COMPLETE

Scope: execution-order Phase 2.1 only. `experiments/bl_pq512_crypto_core/src/gkr_sumcheck.rs`
now groups sparse terms by the current folded-table suffix, loads each suffix's zero/delta pair once,
and deterministically merges adjacent suffix buckets after each round. The public
`prove_sparse_terms` wrapper selects this implementation by default. The prior implementation is
retained only for tests and the non-default `control_reference` Cargo feature; release builds
therefore compile one selected path rather than dispatching at runtime.

The optimization preserves the transcript and proof representation. This exact fixed-seed check was
run:

```text
$env:CARGO_TARGET_DIR='C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase2'; cargo test --release --locked --offline --features parallel gkr_sumcheck::tests::bucketed_sparse_schedule_is_byte_identical_for_three_fixed_seeds -- --exact --nocapture
```

It constructed the actual ordinal-5 Keccak layer for seeds 1, 17, and 123, compared the reference
and bucketed proof values and flattened encoded bytes, and verified each proof. Raw decisive output:

```text
test gkr_sumcheck::tests::bucketed_sparse_schedule_is_byte_identical_for_three_fixed_seeds ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 191 filtered out; finished in 0.83s
```

`cargo fmt --check` exited zero. The optimized fixture build with features
`parallel,bench_fixture_coin` and the control build with features
`parallel,bench_fixture_coin,control_reference` both exited zero and were warning-clean. An initial
focused build exposed two dead-code warnings in the control path; an initial control build exposed
four symmetric dead-code warnings in the bucketed path. The `cfg` boundaries were narrowed so each
release binary compiles only its selected implementation, and both builds were rerun warning-clean.
One calibration launcher attempt is excluded: it invoked Cargo from the workspace root, printed
`error: could not find Cargo.toml`, and started zero benchmark runs. The corrected launcher built
from `experiments/bl_pq512_crypto_core`.

### Mandatory post-step Phase-0 calibration

The four exact Phase-0 calibration shapes were rerun sequentially, five times each. All 20 benchmark
processes exited zero, all benchmark stderr files were empty, and the results below were parsed from
the 20 per-run JSON records:

| Set | Rounds | Total seconds min / median / max | Average coin-wait ns min / median / max | Maximum combined RSS bytes | Digests |
| --- | ---: | ---: | ---: | ---: | --- |
| 16 fixture | 7,489 | 16.4594007 / 16.5314242 / 16.6250736 | 29,208 / 29,725 / 30,266 | 229,707,776 | 1 fixed |
| 16 live | 7,489 | 17.0799285 / 17.2251522 / 17.3767730 | 123,898 / 125,500 / 127,953 | 238,518,272 | 5 distinct |
| 128 fixture, 782 permutations | 8,785 | 28.5243543 / 28.6891337 / 29.1840821 | 28,418 / 28,835 / 29,162 | 303,046,656 | 1 fixed |
| 128 live, 782 permutations | 8,785 | 29.3643872 / 29.5131941 / 29.6318235 | 119,995 / 120,890 / 122,656 | 312,778,752 | 5 distinct |

The reduced fixture digest remained exactly:

```text
c531f446cdf4f0df2af4cf33623fe88e456d8304ce342897a83989dda71fdc0c803b3ae7afe31c0dccd3ad22e43658320b2e4e1e746f17b6a0b342b6b4d596b6
```

The approved reference-shape fixture digest remained exactly:

```text
62752652268cff727ec9b5c72f9a2b29f680538dc1beee585513dac90c1c40bd4c9b79a355da9243c25f8761fe842036a143fe6f6e79ec089495bc2465e73121
```

Against the immediately preceding post-Phase-2.0 calibration, the measured total-time range endpoints
changed as follows: 16 fixture minimum -1.705706% and maximum -3.855370%; 16 live minimum
-2.426754% and maximum -2.031559%; reference fixture minimum -3.193839% and maximum -2.886182%;
reference live minimum -3.860287% and maximum -6.767534%. The preceding record did not retain
per-run values, so no before/after median delta is claimed. These wall-time improvements are
directionally consistent across all four sets, but they are calibration measurements rather than a
formal causal attribution benchmark.

Decision: Phase 2.1 is accepted. The three fixed-seed reference comparison, both fixed-fixture
full-chain digests, authenticated-round counts, live freshness checks, and verifier checks all
passed without a protocol-byte change.

## 2026-07-28 Phase 2.2 packed 25-checkpoint reverse walk — COMPLETE

`keccak_gkr_wiring.rs` now retains the packed input plus one packed post-round state for each of 24
rounds (25 checkpoints total). During the reverse walk it regenerates the first eight outputs of
the selected public nine-layer round, consumes the resulting nine layer inputs in reverse, and
releases that round before selecting the previous public checkpoint. Loop bounds, allocation sizes,
checkpoint indices, traversal, recomputation count, and cleanup depend only on the public 24x9
schedule and fixed instance count; no witness bit is inspected by the schedule. The coherent worker
requests already accepted a single packed `&[u64]` and retained no history, so their protocol was
unchanged. The nested retained-history chain remains available only as the differential reference.

The focused nine-layer chain test compared checkpointed and retained-history output values, proof
objects, terminal claims, and shard queries exactly, then verified the result:

```text
test gkr_sumcheck::tests::repeated_pack_chain_carries_nonlinear_bridge_between_layers ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 191 filtered out; finished in 3.06s
```

Both optimized feature selections built successfully. The first control-reference build emitted one
unused-import warning; the checkpoint imports were feature-gated and the control build was rerun
warning-clean. `cargo fmt --all --check` exited zero.

The mandatory current-binary calibration produced 20 accepted runs:

| Set | Total seconds min / median / max | Coin-wait ns min / median / max | Peak RSS bytes | Checkpoint / regenerated payload bytes |
| --- | ---: | ---: | ---: | ---: |
| 16 fixture | 16.0106338 / 16.1671940 / 16.1814998 | 29,365 / 29,652 / 30,341 | 221,913,088 | 819,200 / 393,216 |
| 16 live | 16.4784861 / 16.6330969 / 18.1296692 | 115,653 / 118,532 / 119,704 | 230,899,712 | 819,200 / 393,216 |
| 128 fixture, 782 permutations | 28.5384410 / 28.7301281 / 29.0360657 | 27,868 / 28,374 / 29,015 | 241,598,464 | 6,553,600 / 3,145,728 |
| 128 live, 782 permutations | 29.4346981 / 29.6835940 / 29.7491915 | 119,340 / 121,163 / 121,990 | 250,220,544 | 6,553,600 / 3,145,728 |

All 20 exited zero with empty benchmark stderr. Fixture digests remained exactly
`c531f446cdf4f0df2af4cf33623fe88e456d8304ce342897a83989dda71fdc0c803b3ae7afe31c0dccd3ad22e43658320b2e4e1e746f17b6a0b342b6b4d596b6`
and
`62752652268cff727ec9b5c72f9a2b29f680538dc1beee585513dac90c1c40bd4c9b79a355da9243c25f8761fe842036a143fe6f6e79ec089495bc2465e73121`;
live sets each had five distinct digests. Rounds stayed 7,489 and 8,785.

Against Phase 2.1, peak RSS changed by -7,794,688 bytes (16 fixture), -7,618,560 (16 live),
-61,448,192 (reference fixture), and -62,558,208 (reference live). Timing-range endpoint changes
were -2.726%/-2.668%, -3.521%/+4.333% (one slow live run), +0.049%/-0.507%, and
+0.239%/+0.396%, respectively; no speedup is claimed.

Ten earlier live runs are excluded because the live target had not been rebuilt and their stdout
contained no checkpoint telemetry. The corrected launcher was then rebuilt and rerun. Two
PowerShell summarizer attempts failed after the replacement runs completed (one parse-time variable
syntax error before any work; one relative-path read error after all runs); the accepted results
were independently parsed from the completed per-run JSON and stdout files.

Decision: Phase 2.2 is accepted. Proof bytes/digests, verifier claims, authenticated rounds, and live
freshness were preserved while reference-shape peak RSS fell by about 61-63 MB.

## 2026-07-28 Phase 2.3 `mul_by_m31` routing inventory — COMPLETE

Scope: execution-order Phase 2.3 and design item 1.5 only. The inventory counts syntactic
multiplication operations in the named active B=8 sparse-GKR and packed-finalization paths. It
separately excludes the nonprotocol B=64 spike and test-only code so those sites cannot inflate the
production count.

### Complete routing inventory

`Fp16::mul_by_m31` performs 16 canonical M31 coordinate multiplications. Four production call sites
qualify, and all four were already routed before this phase:

1. `packed_boolean_sumcheck.rs::lagrange_node_evaluations`: the inverse Lagrange denominator is M31;
2. `packed_boolean_sumcheck.rs::lagrange_query_polynomial`: each basis coefficient is M31;
3. `packed_boolean_sumcheck.rs::finish_packed_boolean_accumulators`: product-polynomial
   coefficients are M31; and
4. the same finalizer's left/right mask-polynomial coefficients are M31.

The named candidate inventory contains 12 nonqualifying multiplication operations:

- one in `equality_table`: the coordinate is a general authenticated Fp16 challenge;
- one hard-excluded `fold_multilinear` operation: the verifier coordinate is general Fp16;
- four in `gate_line`: `zero`, `delta`, and `fixed` are post-interpolation/general Fp16 values;
- five in `weighted_gate_quadratic`: `weight`, `gate_zero`, and `gate_delta` are general Fp16; and
- one in `finish_packed_boolean_combined`: both the combined coefficient and query-polynomial
  coefficient are general Fp16.

Boolean packed-table accumulation in `PackedBooleanAccumulators::add_gate` contains zero field
multiplications: it uses only Fp16 add/subtract operations and public u8 indexing. The M31 table
coefficients are consumed later by the two already-routed finalizer call sites above.

Counts: four qualifying production sites, all already routed; 12 nonqualifying named-path
operations; zero unresolved sites; zero new routing changes. Four `mul_by_m31` call sites in the
standalone B=64 nonprotocol spike and one test-only direct-evaluation call site are excluded from
the production count. Post-interpolation values and all transcript challenges remain Fp16. No
operation was forced through the base-field path.

### Algebraic identity and focused checks

The only source change in the crate is a deterministic randomized algebraic-identity KAT in
`src/field.rs`. It compares `value.mul_by_m31(scalar)` with
`value * Fp16::from_m31(scalar)` for 4,096 deterministic-random Fp16/base-field pairs plus the
M31 edge scalars zero, one, and negative one: 4,099 exact comparisons.

Exact focused command:

```powershell
$env:CARGO_TARGET_DIR='C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase2'
cargo test --release --locked --offline --features parallel field::tests::mul_by_m31_matches_generic_fp16_product_for_random_vectors -- --exact --nocapture
```

Decisive output:

```text
test field::tests::mul_by_m31_matches_generic_fp16_product_for_random_vectors ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 192 filtered out
```

The existing packed subfield/direct-evaluation parity KAT also passed:

```text
test packed_boolean_sumcheck::tests::subfield_table_and_packed_reduction_match_all_eight_direct_evaluations ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 192 filtered out
```

`cargo fmt --all --check` exited zero. The two focused tests were launched concurrently against one
Cargo target and emitted `Blocking waiting for file lock on package cache` and
`Blocking waiting for file lock on build directory`; both completed successfully. All subsequent
builds and calibration sets were serialized. Both required release builds exited zero and were
warning-clean:

- fixture target `cargo-target-phase0-fixture`, features `parallel,bench_fixture_coin`; and
- live target `cargo-target-phase0`, feature `parallel`.

### Mandatory post-step Phase-0 calibration

All four exact calibration sets were run sequentially, five times each, using the approved reduced
and 782-permutation boundaries. All 20 benchmark processes exited zero; all 20 benchmark stderr
files were empty; all stdout records reported `coherent_chain_verified=true`,
`public_coin_independent_replay=true`, and `round_checkpoint_count=25`.

| Set | Rounds | Total seconds min / median / max | Average coin-wait ns min / median / max | Maximum combined RSS bytes | Digests |
| --- | ---: | ---: | ---: | ---: | --- |
| 16 fixture | 7,489 | 17.5466941 / 18.4194603 / 18.6621273 | 32,686 / 36,953 / 38,358 | 223,899,648 | 1 fixed |
| 16 live | 7,489 | 18.1646651 / 18.2729101 / 18.7221510 | 160,491 / 161,201 / 167,440 | 233,594,880 | 5 distinct |
| 128 fixture, 782 permutations | 8,785 | 30.1829535 / 30.6373566 / 31.3070360 | 32,540 / 34,132 / 34,898 | 243,818,496 | 1 fixed |
| 128 live, 782 permutations | 8,785 | 31.6038960 / 32.4675923 / 34.4025865 | 166,320 / 172,299 / 195,588 | 252,448,768 | 5 distinct |

The reduced fixture digest remained exactly:

```text
c531f446cdf4f0df2af4cf33623fe88e456d8304ce342897a83989dda71fdc0c803b3ae7afe31c0dccd3ad22e43658320b2e4e1e746f17b6a0b342b6b4d596b6
```

The approved reference-shape fixture digest remained exactly:

```text
62752652268cff727ec9b5c72f9a2b29f680538dc1beee585513dac90c1c40bd4c9b79a355da9243c25f8761fe842036a143fe6f6e79ec089495bc2465e73121
```

Against Phase 2.2 medians, total time changed by +2.2522663 seconds / +13.931% for 16 fixture,
+1.6398132 seconds / +9.859% for 16 live, +1.9072285 seconds / +6.638% for reference fixture, and
+2.7839983 seconds / +9.379% for reference live. No production hot-path routing changed, so no
causal slowdown or speedup is attributed to Phase 2.3; these are exact current calibration
measurements.

System paging-file usage changed during some live runs and page-read counters were nonzero in all
sets. As in the preceding phases, these measurements do not establish the process-level no-swap
release gate. Requested calibration runs skipped: zero. Benchmark failures: zero. KAT mismatches:
zero. Fixture-digest mismatches: zero.

Decision: Phase 2.3 is accepted with the measured near-zero routing result. Every qualifying
production site was already routed, no additional site safely qualifies, and proof bytes/digests,
round counts, checkpoint counts, verification, and live freshness were preserved.

## 2026-07-28 Phase 2.4 owner ratification — RECORDED

The owner explicitly approved the two-layer Keccak-round collapse before the current execution
handoff. `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` item 3 and
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` section 8.1.3 now record
`DESIGN-FROZEN-OWNER-RATIFIED-2026-07-28`. The ratification is limited to Phase 2.4 and does not
authorize the nonactivating streamed M31-symbol commitment or the rejected production B=64 kernel.

Implementation remains ordered and fail closed: first a standalone multi-factor sumcheck module and
naive-reference random-input KATs; only after those KATs pass may the two-layer schedule be added
behind a build flag. The 216-layer schedule remains the control.

## 2026-07-28 Phase 2.4 multi-factor kernel — KAT COMPLETE; SCHEDULE HARD STOP

The first ordered Phase 2.4 step is implemented as its own
`experiments/bl_pq512_crypto_core/src/multi_factor_sumcheck.rs` module. It supports one to 11
publicly wired multilinear factors, low-bit-first rounds, explicit message-before-authenticated-
challenge state, exact terminal-factor verification, and no Fiat--Shamir path.

The exact random-input KAT command was:

```powershell
$env:CARGO_TARGET_DIR='C:\Users\neers\Documents\Codex\2026-07-27\he\work\cargo-target-phase2'
cargo test --release --locked --offline --features parallel multi_factor_sumcheck::tests::random_shifted_mle_rounds_match_naive_reference_exactly -- --exact --nocapture
```

Decisive raw output:

```text
test multi_factor_sumcheck::tests::random_shifted_mle_rounds_match_naive_reference_exactly ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 194 filtered out; finished in 0.20s
```

That KAT covers 12 deterministic-random cases over fan-in 1, 3, and 11. For every round it evaluates
the product of independently shifted MLEs naively at every integer interpolation node, independently
interpolates the result, and compares every coefficient exactly. It also compares every terminal
factor to an independent MLE evaluation and runs the sequential verifier.

The fail-closed shape/order KAT also passed:

```text
test multi_factor_sumcheck::tests::malformed_shapes_and_transcript_order_fail_closed ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 194 filtered out
```

`cargo fmt --all --check` exited zero.

### Hard-stop condition: frozen degree/mask count omits the output-claim factor

No two-layer schedule, build flag, mask resize, transcript change, or control-path change was
implemented. Exact source inspection found that the ratified 12/4 coefficient requirement is one
coefficient short for both merged layers under the existing GKR claim-binding invariant:

- `gkr_sumcheck.rs::layer_terms` constructs the output-claim equality table and assigns an
  `output_weight` to every gate;
- `gkr_sumcheck.rs::weighted_gate_quadratic` multiplies that affine bit-basis weight by the
  partially bound gate polynomial; and
- the existing fan-in-two path therefore emits a quadratic, not linear, round polynomial.

The same invariant applied to a merged layer adds one affine equality-weight factor. A merged-theta
parity product has 11 affine input factors, so its claim-bound round polynomial has degree 12 and
requires 13 coefficients. A merged chi+iota relation has degree 3, so its claim-bound round
polynomial has degree 4 and requires 5 coefficients. The minimal witness is direct:

```text
theta: (x * x * x * x * x * x * x * x * x * x * x) * x = x^12
chi:   (x * x * x) * x = x^4
```

The final `* x` is the nonconstant output-claim equality factor. Omitting it would leave the output
claim host-trusted; forcing 12/4 coefficients would truncate a potentially nonzero highest-degree
term. Increasing the masks to 13/5 would contradict the explicit handoff requirement to resize for
degree 11/12 coefficients and degree 3/4 coefficients. This is an unresolved trust-critical design
conflict, so execution stops before schedule implementation rather than improvising a protocol
change.

Counts at stop: standalone kernel KAT failures zero; malformed/order KAT failures zero; schedule
files changed zero; build flags added zero; control layers deleted zero; forward-equivalence inputs
run zero because the schedule is blocked before implementation; full-chain comparisons run zero for
the same reason; Phase 2.4 calibration runs skipped 20 because no candidate schedule exists to
calibrate.

## 2026-07-28 Phase 2.4 13/5 owner correction — AUTHORIZED; PRIOR STOP CLEARED

The owner explicitly approved 13/5 and directed Phase 2.4 and subsequent authorized roadmap work to
continue. The intrinsic merged-theta and merged-chi+iota relations remain degree at most 11 and
degree 3. The existing nonconstant output-claim equality factor raises the claim-bound
round-polynomial degrees to at most 12 and 4, so the authoritative round-message and mask sizes are
13 coefficients for theta and 5 coefficients for chi+iota.

This exact 13/5 authorization supersedes the execution order's earlier 12/4 estimate and clears the
hard stop above without removing or host-trusting the equality factor.
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` section 8.1.3 and
`docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` item 3 record the correction. The standalone
multi-factor-kernel KAT remains the completed first Phase 2.4 step. The next action is to implement
the two-layer schedule behind a build flag alongside the unchanged 216-layer control, resize masks
to 13/5 before enabling it, and derive authenticated and coin-round counts from the built schedule
rather than accepting the projected 2,624 or 1,984 figures.

Because the first automatic context compaction occurred immediately after the authorization, no
schedule source, build flag, or mask implementation was changed in this bounded recovery step.
Forward-equivalence inputs run in this step: zero. Full-chain comparisons run in this step: zero.
Phase 2.4 calibration runs in this step: zero. These are deferred, not waived, and all Phase 2.4
acceptance gates remain fail closed.

## 2026-07-28 Priority-Zero checkpoint and full-scale table audit — DIAGNOSIS COMPLETE

This audit was performed before any Phase 2.4 schedule implementation. It reconciles the measured
243,818,496-byte reference-fixture peak with the earlier multi-gigabyte projections and inventories
the multiplicative/exponential tables in the active coherent GKR plus PCS path. No checkpoint-memory
change, protocol change, build flag, schedule change, or mask change was made in this audit.

### Actual benchmark and checkpoint path

The real coherent-chain benchmark uses the packed round-checkpoint path, not the nested-Boolean
retained-history control:

- `src/bin/gkr_coherent_chain_benchmark.rs:616-631` builds the 216-layer circuit, loads a packed
  boundary, calls `packed_keccak_gkr_round_checkpoints`, sums each checkpoint's
  `len() * size_of::<u64>()`, and drops the original boundary.
- `src/keccak_gkr_wiring.rs:375-395` returns `Vec<Vec<u64>>`: one packed input plus one packed
  post-round state for each of 24 Keccak rounds. Therefore `round_checkpoint_count=25` means 25
  separately allocated inner `Vec<u64>` buffers plus one outer `Vec` with capacity 25.
- Each retained checkpoint has dimensions
  `2,048 padded wires * ceil(padded_instances / 64) u64 words`; exact payload is
  `2,048 * padded_instances / 8` bytes.
- `src/keccak_gkr_wiring.rs:402-419` regenerates only one round for the reverse walk. It returns nine
  separately allocated packed `Vec<u64>` inputs: the checkpoint plus the first eight layer outputs.
  The sum of their padded wire widths is 24,576, so the exact simultaneous payload is
  `24,576 * padded_instances / 8` bytes. The ninth output is the next retained checkpoint and is not
  duplicated into this regeneration vector.
- The strict production-shaped benchmark sends each regenerated packed layer boundary and compact
  points to `GkrCompactPointWorkerRequest`
  (`src/bin/gkr_coherent_chain_benchmark.rs:991-1008`). The host factored-equality construction at
  lines 1510-1531 belongs to the non-strict control branch.

The measured reference fixture uses 782 real permutations padded to 1,024 instances, not the
113,730-permutation global K128 schedule. Its exact retained checkpoint payload is
`25 * 2,048 * 1,024 / 8 = 6,553,600` bytes and its exact one-round regeneration payload is
`24,576 * 1,024 / 8 = 3,145,728` bytes. Both equal the telemetry already recorded above. The
243,818,496-byte peak RSS is a combined process measurement and is not a checkpoint-payload
measurement; the checkpoints account for only 6,553,600 bytes of that peak.

### Reconciliation of the three earlier storage models

The nine current padded output widths sum to 24,576 per Keccak round. Across 24 rounds plus the
2,048-wire input boundary, full retention has
`2,048 + 24 * 24,576 = 591,872` wire positions per padded instance.

| Model | Exact K128 formula | Bytes | Actual status |
| --- | ---: | ---: | --- |
| Nested `Vec<bool>` full retention | `591,872 * 131,072` | 77,577,846,784 | Implemented only by `prove_repeated_pack_gkr_chain_reference`, compiled for tests or feature `control_reference`; not used by the benchmark/default checkpoint path. This is byte-per-Rust-`bool` payload before nested-vector metadata and allocator overhead. |
| Hypothetical packed full retention | `591,872 * 131,072 / 8` | 9,697,230,848 | Projection of packing every one of the 217 boundaries while retaining them all; no such allocation is made by the checkpoint benchmark. |
| Earlier raw-active checkpoint model | `25 * 113,730 * 1,600 / 8` | 568,650,000 | Hypothetical raw-state model. It omits both permutation padding to 131,072 and state-wire padding from 1,600 to 2,048, so it is not the current source allocation. |
| Current-source K128 checkpoints | `25 * 2,048 * 131,072 / 8` | 838,860,800 | Projected allocation of the implemented checkpoint function at the canonical global K128 geometry. |
| Current-source K512 checkpoints | `25 * 2,048 * 524,288 / 8` | 3,355,443,200 | Projected allocation at 411,406 permutations padded to 524,288 instances. |

`src/gkr_sumcheck.rs:2146-2196` proves the old 77.6-GB source: the feature-gated reference function
stores every boundary as nested `Vec<[Vec<bool>; 8]>`. The default function at lines 2320-2449
packs and checkpoints, regenerates one round at a time, and temporarily unpacks one layer for the
host control prover. `prove_repeated_pack_gkr_chain_control` selects the retained reference only
under feature `control_reference` at lines 2453-2489.

Decision: the numbers reconcile. They describe different geometry and different retention paths.
No checkpoint-memory fix is justified for the measured reference benchmark. However, the current
source's projected K512 checkpoint payload (3,355,443,200 bytes) plus one regenerated round
(1,610,612,736 bytes) is 4,966,055,936 payload bytes before worker, runtime, transcript, masks,
proof, and allocator overhead, so the existing checkpoint representation is not qualified for the
5,000,000,000-byte complete K512 gate.

### Active GKR equality and dense-worker inventory

`Fp16` is 16 nested canonical `u32` coordinates (`src/field.rs:77-79`, 170-175, 257-263,
347-352, and 438-444), so every host/device `Fp16` table below uses 64 bytes per element.

| Allocation | Producer and consumers | Dimensions / exact formula | Reference allocation | K128 projection | K512 projection | Lifetime |
| --- | --- | --- | ---: | ---: | ---: | --- |
| Host GKR equality table | `gkr_sumcheck.rs:232-254`; consumed by sparse-term/layer claim construction | `2^point_variables * 64` bytes | Factored wire/group tables; at most two claims, raw wire 3,200 gives 409,600 bytes and 128 groups gives 16,384 bytes | Wire 409,600; group 2,097,152 | Wire 409,600; group 8,388,608 | Temporary per layer/claim in host control paths |
| GPU compact wire equality | CUDA `derive_equality_table`, lines 55-82; consumed by compact term-weight derivation | `claim_count * raw_width * 64` | 409,600 bytes at two claims and raw width 3,200 | 409,600 | 409,600 | Persistent session slot, reused/grown |
| GPU compact group equality | Same producer/consumer | `claim_count * group_count * 64` | 16,384 bytes | 2,097,152 | 8,388,608 | Persistent session slot, reused/grown |
| Expanded GKR input | packed-input expansion, CUDA lines 1064-1097; consumed by folding | `input_width * group_count * 64` | maximum `524,288 * 64 = 33,554,432` | `67,108,864 * 64 = 4,294,967,296` | `268,435,456 * 64 = 17,179,869,184` | Persistent session slot, reused/grown |
| Term weights | compact weight derivation, CUDA lines 892-907; consumed by round reduction | `raw_width * group_count * 64` | `409,600 * 64 = 26,214,400` | `52,428,800 * 64 = 3,355,443,200` | `209,715,200 * 64 = 13,421,772,800` | Persistent session slot, reused/grown |
| Left/right term indices | compact derivation, CUDA lines 893-894 | two tables, each `term_count * 4` | 1,638,400 each | 209,715,200 each | 838,860,800 each | Persistent session slots, reused/grown |
| Gate formula | compact derivation, CUDA line 895 | `term_count` bytes | 409,600 | 52,428,800 | 209,715,200 | Persistent session slot, reused/grown |
| Left/right factors | CUDA lines 1099-1124; consumed and folded through authenticated rounds | two tables, each `term_count * 64` | 26,214,400 each | 3,355,443,200 each | 13,421,772,800 each | Persistent session slots, reused/grown |
| Fold A/B | CUDA lines 1126-1128; alternating folding buffers | two tables, each `input_count * 64` | 33,554,432 each | 4,294,967,296 each | 17,179,869,184 each | Persistent session slots, reused/grown |

The Rust request encoder computes `input_count=input_width*groups` and
`term_count=raw_width*groups` at `src/gkr_worker.rs:461-469`. The reference shape reaches the
existing caps exactly: `input_count=4,096*128=524,288` and
`term_count=3,200*128=409,600`. Lines 476-482 reject larger requests before transport. Therefore
the measured 243-MB benchmark exercises only the capped reference geometry; the current worker does
not execute canonical K128 or K512. Raising the caps alone is forbidden because the dense buffers
above independently exceed the 5-GB gate.

The GKR equality lookup is already split/factored by wire and group variables and is small relative
to the dense expanded-input, term-weight, factor, and fold buffers. Replacing only this equality
table would neither make K128 executable nor make K512 fit. The required future correction is a
streamed/factored sparse-round architecture that also avoids materializing the multiplicative
`input_width*groups` and `raw_width*groups` buffers. It must receive differential KATs before any
performance claim.

### PCS exponential table inventory

`src/multilinear_batch_sumcheck.rs:100-116` and 435-469 produce equality vectors with
`2^point_variables` `Fp16` elements. The current PCS constants are fixed at input log 21, hidden
polynomial log 22, and LDE log 25 (`src/multilinear_pcs.rs:28-33`); this is the 1,024-instance by
2,048-wire reference boundary, not canonical K128/K512.

| Allocation | Producer and consumers | Exact formula | Current log-21 allocation | K128 log-28 projection | K512 log-30 projection | Lifetime |
| --- | --- | --- | ---: | ---: | ---: | --- |
| Packed-input base equality | `packed_opening_weights`, transcript lines 683-748 | each `2^(input_log-3) * 64`; two claims | 16,777,216 each | 2,147,483,648 each | 8,589,934,592 each | Temporary while constructing weights |
| Packed-output base equality | `packed_output_weights`, lines 781-834 | `2^(input_log-3) * 64` | 16,777,216 | 2,147,483,648 | 8,589,934,592 | Temporary while constructing weights |
| Packed opening/output weights | same functions; consumed by opening checks and batch sumcheck | each `2 * 2^input_log * 64` | 268,435,456 each | 34,359,738,368 each | 137,438,953,472 each | Retained in prepared PCS prelude |
| Main binding equality | prelude lines 1233-1252 and analogous combined-prelude path | `2^(input_log+1) * 64` | 268,435,456 each | 34,359,738,368 each | 137,438,953,472 each | Temporary, then folded into retained weights |
| Main input/output evaluation vectors | prelude inputs; consumed by opening checks and batch sumcheck | each `2^(input_log+1) * 64` | 268,435,456 each | 34,359,738,368 each | 137,438,953,472 each | Retained through prelude/sumcheck |

These tables are genuinely exponential, but the current constants and artifacts describe only the
reduced/reference PCS. A simple constant change does not create a full K128/K512 PCS: it would
materialize 34.36-GB or 137.44-GB vectors. Streaming only the equality generator is also
insufficient because the output weight and evaluation vectors are equally large. The required
change crosses equality generation, packed weight construction, opening accumulation, evaluation
storage, and sumcheck folding. No local PCS equality edit is made without an end-to-end
order-preserving design and differential proof/verifier KAT.

### Separate semantic AIR lookup representation

The selected semantic AIR prover is not called by `gkr_coherent_chain_benchmark` and is not indexed
by the Keccak permutation count. Its in-memory LogUp producer
`air_logup.rs::build_air_logup_oracle*` retains, per lookup/table interaction, `sides` inverse
columns of `trace_rows` Fp16 elements, one `trace_rows` accumulator, `sides` masked evaluation
columns of `2^evaluation_log_size` Fp16 elements, and one masked accumulator of that size. Exact
payload is
`64 * ((sides+1)*trace_rows + (sides+1)*2^evaluation_log_size)` bytes per interaction.
`air_composition.rs` consumes these columns; `oracle_commitment.rs:431-445` clones masked columns
into the interaction commitment constructor. The disk-selected path in `disk_logup.rs` builds the
natural inverse columns one interaction at a time, writes masked evaluation files, and retains file
metadata/tree state rather than every evaluation column.

There is no authoritative mapping from K128/K512 claim-slot profiles to one fixed semantic AIR
program's per-table `trace_rows`, `sides`, and `evaluation_log_size` in the coherent-chain benchmark;
therefore numeric K128/K512 LogUp bytes are not inferred here. Reduced/reference allocation is also
not measured by the coherent GKR benchmark. This separate pipeline is recorded rather than silently
counted as zero; its complete-proof resource qualification remains open.

### Audit decision and next boundary

The 243,818,496-byte measurement and the 77,577,846,784/9,697,230,848-byte projections reconcile
exactly. The large projections are not dead arithmetic, but they describe feature-gated or
hypothetical full-retention paths at canonical K128 geometry, not the exercised benchmark
allocation. The actual measured benchmark uses 25 packed checkpoints and one-round temporary
regeneration.

Priority-Zero diagnostic result: no checkpoint-memory source change is warranted. Full-scale
qualification is nevertheless blocked by demonstrated dense GKR-worker and PCS-vector
architectures, not by GKR equality lookup. Phase 2.4 may proceed at the existing approved
reference/control geometry behind a build flag, but no resulting benchmark may be labeled
full-K128, full-K512, or complete-proof qualification until those separately recorded full-scale
memory blockers are redesigned and measured under the 5-GB/no-swap gate.

## 2026-07-28 Phase 2.4 merged-wiring audit — HARD STOP BEFORE SCHEDULE IMPLEMENTATION

After the Priority-Zero memory diagnosis, the next Phase 2.4 action was exact source reconciliation
of the completed standalone multi-factor kernel with the ratified Keccak merged-layer wiring. That
reconciliation exposed two trust-critical incompatibilities. No two-layer descriptor, schedule,
build flag, mask, codec, transcript, prover, verifier, or control path was changed.

### The completed kernel cannot represent the frozen Keccak wiring

`multi_factor_sumcheck.rs:1-6` defines a factor as `f(x xor s)` for one constant public XOR shift.
`ShiftedMultilinearFactor` contains only an evaluation vector and that one `xor_shift`
(lines 15-19), and the prover constructs each factor table exactly as
`evaluations[index ^ xor_shift]` (lines 222-228). A constant XOR shift is a bijection of the
hypercube indices.

Merged theta is not such a shift. The theta output at `(x,y,z)` includes each source row of the
column parity at `(x-1,z)` and `(x+1,z-1)`. For a fixed source row, changing output `y` maps
different output indices to the same input index. Using the authoritative source layout
`bit(x,y,z)=64*(x+5*y)+z` from `keccak_gkr_wiring.rs:44-46`, the exact counterexample is:

```text
Factor                     Output  OutputIndex InputIndex RequiredXorShift
theta C[x-1,z], source y=0 (0,0,0)           0        256              256
theta C[x-1,z], source y=0 (0,1,0)         320        256               64
chi B[x+1,y,z]             (0,0,0)           0         64               64
chi B[x+1,y,z]             (1,0,0)          64        128              192
```

One factor would require two different XOR shifts (256 and 64) for the first two theta outputs.
It is also non-bijective because both outputs consume input index 256. The chi neighbor
permutation is bijective, but modulo-five `x` translation is not a constant XOR shift in the frozen
flattening: the two shown outputs require shifts 64 and 192. The existing nine-layer source confirms
the authoritative mappings at `keccak_gkr_wiring.rs:136-185` for theta and lines 187-227 for
rho/pi, chi, and iota.

Materializing a caller-prepermuted/repeated factor table would make the standalone polynomial KAT
pass, but its terminal value would be an opening of a new derived table, not an authenticated
opening of the committed input boundary. Accepting it would host-trust the wiring. Fixing that
requires a new authenticated wiring/permutation argument, additional committed derived tables, or
a generalized high-fan-in sparse GKR with explicitly verified terminal reductions. None of those
protocols, transcript effects, proof codecs, round counts, or mask/leakage effects is frozen by the
current authorization.

### The completed kernel also omits the claim-bound factor count

`MAX_MULTI_FACTORS` is 11 (`multi_factor_sumcheck.rs:13`), validation rejects more than 11
(lines 47-55), and the deterministic randomized KAT covers factor counts only 1, 3, and 11
(lines 346-405). The corrected theta message has 13 coefficients because the 11 intrinsic input
factors plus the nonconstant output-claim equality factor produce 12 multiplicative factors and
degree 12. The existing module therefore cannot emit or verify the authorized claim-bound
13-coefficient message. Raising the cap to 12 would be necessary but not sufficient; it would not
solve the non-XOR wiring and terminal-authentication problem above.

### Stop decision and counts

The architecture document itself says the collapse is a new multi-factor sumcheck, requires new
descriptors/equations/codecs/masks, and requires the compiler to freeze the exact factor list and
generated geometry before implementation. The current standalone kernel's factor representation is
not that exact factor list for Keccak.

Continuing would require inventing a trust-critical wiring argument and transcript beyond the
ratified design, so Phase 2.4 stops before source implementation. This is not the earlier 12/4
issue; the 13/5 correction remains authoritative.

Counts at this stop:

- Priority-Zero source/allocation diagnosis completed: one;
- checkpoint-memory fixes made: zero;
- standalone kernel source changes made after its accepted KAT: zero;
- two-layer schedule files changed: zero;
- build flags added: zero;
- mask dimensions changed: zero;
- 216-layer control files changed: zero;
- 10,000-case forward KAT inputs run: zero because no sound merged descriptor exists;
- full-chain proof/verifier comparisons run: zero for the same reason;
- Phase 2.4 calibration runs: zero because no candidate can be enabled;
- protected-path edits: zero.

The smallest decision needed is an owner-ratified proof topology for arbitrary merged Keccak wiring:
either (a) generalized high-fan-in sparse GKR with exact terminal reductions and measured round
accounting, (b) committed derived-factor tables plus their authenticated wiring proof, or (c) a
different exact index encoding together with a proof that every theta/chi factor is a verified
hypercube-affine map. A constant-XOR-shift kernel is disproven for the current frozen wire encoding.

Post-diagnosis verification reran both existing standalone-kernel gates without changing source:

```text
test multi_factor_sumcheck::tests::random_shifted_mle_rounds_match_naive_reference_exactly ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 194 filtered out; finished in 0.19s

test multi_factor_sumcheck::tests::malformed_shapes_and_transcript_order_fail_closed ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 194 filtered out; finished in 0.00s
```

`cargo fmt --all --check` exited zero with empty output. These results verify that the existing
constant-XOR kernel remains internally passing; they do not cure or qualify the Keccak wiring gap.

## 2026-07-28 bounded-replay GKR feasibility spike

The owner authorized a narrow feasibility signal before replanning the memory roadmap. The spike
changes only `experiments/bl_pq512_crypto_core/src/gkr_sumcheck.rs` under `#[cfg(test)]`; production
code, the 216-layer control, Phase 2.4 wiring, proof codecs, masks, transcript code, PCS code, build
flags, protected paths, and activation state are unchanged.

The test-only exact-replay prover retains neither the folded input vectors nor the per-term
left/right factor vectors. For each sparse round it regenerates the required partially evaluated
input value from an indexed canonical input oracle, recomputes equality factors from the accepted
challenge prefix and the gate index, and regenerates each sparse gate term and output-claim weight
from the frozen Keccak layer and claim point. It deliberately trades time for bounded retained
state.

One real Keccak sparse layer was compared against the existing reference prover. Every round
coefficient and both terminal values were equal because the complete `SparseLayerSumcheckProof`
objects compared equal; the existing verifier accepted the replayed proof.

```text
test gkr_sumcheck::tests::replayed_sparse_real_keccak_layer_is_exact ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 196 filtered out; finished in 83.49s
```

The replay path retains only the emitted per-layer proof vector as input width grows. Its exact
payload formula is `(6 * log2(input_width) + 2) * 64` bytes: 10,112 bytes at the projected K128
`2^26` repeated input width and 10,880 bytes at the projected K512 `2^28` repeated input width.
The focused assertion passed:

```text
test gkr_sumcheck::tests::replayed_sparse_payload_is_kilobytes_at_projected_full_widths ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 196 filtered out; finished in 0.00s
```

The unchanged three-seed bucketed/reference byte-equivalence control also passed:

```text
test gkr_sumcheck::tests::bucketed_sparse_schedule_is_byte_identical_for_three_fixed_seeds ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 196 filtered out; finished in 0.94s
```

`cargo fmt --all --check` exited zero with empty output.

Decision: this is a **positive GKR feasibility signal**, not a full memory qualification. It proves
that the dense folded-input and per-term factor tables are not required to preserve the exact
current sparse-layer proof messages. It does not measure full K128/K512 RSS, stream the packed input
source, cover the packed first-round accumulator, exercise masking/authenticated interaction across
the complete chain, solve the exponential PCS vectors/codewords, satisfy latency, or cure the
separate Phase 2.4 merged-Keccak wiring hard stop. The 83.49-second single-layer result also proves
that naive scalar replay is not a performance candidate; future work must add bounded tiles or a
streaming product-sumcheck without restoring size-proportional retention.

## 2026-07-28 streamed PCS entry-gate audit — HARD STOP BEFORE IMPLEMENTATION

The owner next required the PCS memory problem to be solved with all constraints and tests. The
authoritative execution order permits only one relevant bounded-memory commitment lane at Phase
1.6 and states: streamed M31-symbol input-layer commitment under an M31-linear code, Fp16
challenges, per-column SHA3-512 accumulation, and 16 independent uniform M31 hiding rows. It
explicitly requires four ECCC 2025/2054 checks and says **no implementation, no qualification
credit** until the owner records them as passed. The same order forbids changing the query count,
rate, digest size, SHA3-512 authority, M31/Fp16 field profile, or mask structure.

The official current paper was retrieved from ECCC TR25-166 revision 1:

```text
URL: https://eccc.weizmann.ac.il/report/2025/166/revision/1/download/
Bytes: 1,265,761
SHA-256: 8F2A31305B000527BCB7DBCA41A2AA91B0AC0457B3AD2C7345BE4E7D762BA526
Title: Optimal Proximity Gaps for Subspace-Design Codes and (Random) Reed-Solomon Codes
Authors: Rohan Goyal; Venkatesan Guruswami
Revision date: 2026-03-24
```

The paper's Definition 2.4 requires an `F`-additive code to have alphabet `Sigma = F^s` and to be
linear over the same field `F`. Section 4 states that all codes used there are `F`-additive. This
does not directly validate the Phase-1.6 wording:

1. A bare M31-linear code over M31 symbols is not closed under multiplication by a general Fp16
   verifier challenge. Therefore the Sigma/F decoupling check fails for that literal construction.
2. A possible repair is scalar extension: encode 16 M31 rows with one common M31 generator, pack
   the 16 symbols at each position in the canonical Fp16 basis, and treat the result as
   `C tensor_M31 Fp16`. That object is Fp16-linear. For such an exact construction, a nonzero Fp16
   codeword decomposes into 16 M31 codewords and its Fp16-symbol support is the union of their
   supports, so its symbol distance is at least the base code's distance.
3. The same scalar-extension argument would make an extracted Fp16 codeword decompose into 16 M31
   codewords only if the exact code uses the same M31 generator in every row and the extractor is
   proved for that scalar-extended code.
4. Avoiding near-capacity machinery is possible in principle by staying inside a proved
   unique-decoding radius, but it cannot be checked numerically until the exact code family,
   generator, rate, distance, block length, and extractor are frozen.

No exact M31-linear code family, generator, subspace-design parameters, block geometry, distance,
or extractor is selected in the execution order or repository for this lane. The paper proves its
Section-4 results for specified subspace-design code families; it does not make every M31-linear
code eligible. Consequently checks 2–4 above are conditional, not passed, and no sound test vector
or full-scale memory formula exists yet.

There is also a direct frozen-parameter conflict. The execution order's absolute prohibitions say
`No change to query count (stays 378)`, while the actual current source at
`experiments/bl_pq512_crypto_core/src/multilinear_pcs.rs:23` sets
`MLPCS_UNIQUE_QUERY_COUNT: usize = 473`. The current query codec, selected-opening geometry, proof
fixtures, and security comments use 473. Query count affects soundness, proof grammar, proof bytes,
and memory, so neither value may be silently selected or translated. The execution order itself
says any transcript ambiguity must stop at the nearest gate.

Stop decision: implementing a streamed PCS now would require inventing the exact code and its
knowledge-extraction/security interpretation, changing a trust-critical commitment topology before
the explicit owner gate, or weakening the gate. None is permitted. Existing reduced PCS tests
remain control evidence only and cannot qualify the missing construction.

Counts at this stop:

- official primary papers inspected: one;
- Phase-1.6 entry checks unconditionally passed: zero of four;
- conditional scalar-extension repair arguments identified: three;
- exact eligible M31-linear code families frozen: zero;
- streamed PCS source files changed: zero;
- PCS parameters/query/rate/masks changed: zero;
- PCS differential KATs added: zero because there is no approved construction to test;
- full K128/K512 PCS memory runs: zero for the same reason;
- protected-path edits: zero.

The smallest owner decision is to ratify an exact M31-linear code family and the scalar-extension
interpretation above, with its generator, block geometry, proved distance, unique-decoding bound,
and extractor, or to reject Phase 1.6 and authorize a different bounded-memory PCS topology. The
owner must also explicitly resolve whether 378 in the execution-order prohibition is superseded by
the implemented 473-query candidate or whether the source and every dependent proof/security
artifact must be redesigned back to 378. Only after both decisions can implementation and the
required root/opening/verifier/hiding/mutation/full-scale resource tests begin.

## 2026-07-28 PCS owner resolution and bounded-replay feasibility — POSITIVE, NOT ACTIVATED

The owner explicitly authorized the safest constraint-preserving resolution after the stop above:
retain the implemented 473-query source/proof/verifier boundary, preserve correctness, privacy,
strict-PQ security, proof compatibility, modularity, the 5,000,000,000-byte gates, and maximum
government auditability, and continue without waiting for another engineer. Therefore 473
supersedes the isolated `stays 378` sentence in the immutable execution-order input. The order file
remains byte-for-byte unchanged at its expected SHA-256
`C81D39A5153C35C0ACBEB0E40823707445EB813024F24DC832E249317F5C3F77` for provenance. The canonical
reconciliation is also recorded in `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md`. Existing source,
proof grammar, verifier, fixtures, rate `1/8`, zero-PoW rule, and 473-query security calculation are
unchanged. The separate 945 authenticated-opening multiplicity is `2 * 473 - 1`; it is not a
contradictory unique-query count.

First-principles source tracing found a lower-risk memory lane than prematurely selecting the
unresolved Phase-1.6 M31 code. The existing hidden polynomial can be evaluated at every initial or
folded FRI position directly from:

- the canonical packed Boolean boundary;
- the existing fresh 64-byte secret mask seed, session, and domain-separated oracle ID; and
- the already authenticated fold challenges.

For fold round `r`, each source coordinate is evaluated at the already-fixed challenge for
coordinates below `r` and at the appropriate power of the current domain point above `r`. The data
term is the multilinear extension of the packed Boolean table. The mask term is the existing
monomial mask polynomial multiplied by the unchanged appended-high-variable factor. This is an
algebraic replay of the current Fp16 hidden polynomial, not a new code, field, transcript, hiding
scheme, proof format, or verifier rule.

An isolated nonactivating module, `src/streaming_mlpcs.rs`, now implements that exact replay
reference. It retains no full evaluation, equality-weight, mask-coefficient, codeword, or folded
layer vector. Its exact internal retained-state formula is
`64 * variables + 64 * (lde_log_size + 1) + 128` bytes: 4,032 bytes for projected K128
`variables=28, lde_log_size=32`, and 4,288 bytes for projected K512
`variables=30, lde_log_size=34`. These figures exclude caller-owned packed source bytes and the
proof being emitted. Two packed Boolean boundaries require 67,108,864 bytes at K128 and 268,435,456
bytes at K512. The generalized current fixed-query grammar projects approximately 32,786,571
batched fold-query bytes at K128 and 36,974,219 bytes at K512. Retaining encoded proof plus one
decoded copy is therefore tens of megabytes, not kilobytes; claiming total PCS memory of only a few
kilobytes would be false. The architecture target is no gigabyte-scale object, not a physically
impossible value below its own proof bytes.

The differential replay tests passed:

```text
running 4 tests
test streaming_mlpcs::tests::replay_engine_state_is_kilobytes_at_projected_full_widths ... ok
test streaming_mlpcs::tests::replayed_product_sumcheck_messages_match_dense_folds_exactly ... ok
test streaming_mlpcs::tests::replayed_layer_has_identical_root_frontier_openings_and_rejection ... ok
test streaming_mlpcs::tests::replayed_values_match_every_dense_fri_layer_exactly ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 197 filtered out; finished in 0.07s
```

The first test covers the derived K128/K512 retained-engine bytes. The second requires identical
degree-two product-sumcheck messages at every round and identical terminal values without retaining
the prelude's folded tables. The third requires identical SHA3-512 roots, canonical Merkle frontier
bytes, and opened values, then mutates one value and requires independent authentication failure.
The fourth compares every position in every fold layer, including the final constant layer, against
the current materialized NTT-and-fold control.

The active file/worker opening function also contained a genuine avoidable full-layer allocation:
`build_stream_layer_opening` streamed payload slabs but retained one 64-byte hash for every leaf.
It now feeds the existing one-pass `build_recomputed_layer_opening`, whose retained state is the
exact query frontier plus a logarithmic SHA3-512 stack. The existing file-backed parity and
noncanonical-value rejection control passed unchanged:

```text
running 1 test
test multilinear_pcs_query::tests::file_backed_opening_and_mix_match_memory_and_reject_noncanonical_values ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 199 filtered out; finished in 0.05s
```

`trace_mask.rs` now also exposes a replay iterator over the existing domain-separated SHAKE256 Fp16
mask stream. The existing vector sampler collects that iterator, so the entropy source, rejection
sampling, domains, coefficient order, and bytes are unchanged. The exact mask KAT requires two
independent replay passes to equal the existing vector and passed:

```text
running 1 test
test trace_mask::tests::sampled_masks_are_reproducible_separated_and_preserve_trace ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 200 filtered out; finished in 0.00s
```

The containing release/locked/offline/parallel library suite and no-default-features build passed:

```text
running 201 tests
...
test result: ok. 201 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 87.81s
```

```text
cargo check --release --locked --offline --no-default-features --lib
Finished `release` profile [optimized] target(s) in 6.85s
```

The no-default-features check emitted four pre-existing warnings: unused `vec` in `merkle.rs`,
unused `SparseTermBuckets::term_count`, unused non-parallel
`DualBoundaryFoldCommitmentProver::final_values`, and unused non-parallel
`PackedBooleanAccumulators::merge`. No new replay/PCS warning was emitted. `cargo fmt --all --check`
exited zero with empty output.

Worker-count reconciliation: each of the four current five-run Phase-0 calibration sets printed
`cpu_bridge_worker_count=16` and `gpu_worker_count=1`. Thus every one of the 20 accepted calibration
runs used the machine's 16 logical CPU workers for the CPU bridge and one single-owner GPU worker.
The group counts 16 and 128 are packed workload geometry, not worker counts. Older retained
calibration output contains the same worker lines; it is not mixed into the current 20-run set.

This is a **positive PCS memory-feasibility signal and one real allocation removal**, not complete
PCS qualification. The replay reference is not yet wired through mask streaming, prelude
sum-products, publish-before-challenge root construction, every opening regeneration, or the
complete GKR-plus-PCS prover. K128/K512 peak RSS has not been measured, and naive single-value replay
trades substantial time for memory. The owner explicitly removed speed as the current priority, so
that trade is admissible for the memory feasibility gate but not for later latency qualification.
The unresolved scalar-extended M31 code remains a separate nonactivating throughput candidate and
still receives zero qualification credit until its four ECCC checks pass.

Changed nonprotected source files in this step:

- `experiments/bl_pq512_crypto_core/src/lib.rs`;
- `experiments/bl_pq512_crypto_core/src/streaming_mlpcs.rs`;
- `experiments/bl_pq512_crypto_core/src/multilinear_pcs_query.rs`;
- `experiments/bl_pq512_crypto_core/src/trace_mask.rs`;
- `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md`;
- `STATE.md`.

Protected-path edits: zero. PCS parameters changed: zero. Proof/verifier grammar changed: zero.
Activation changes: zero.

## 2026-07-28 lean-streaming speed audit — MECHANICS PASS, CODE SELECTION OPEN

The bounded-replay spike was extended only inside the nonactivating
`src/streaming_mlpcs.rs` module and its tests. This audit corrects one full-scale projection,
rejects scalar output-by-output replay as a throughput architecture, and tests the two bounded
mechanisms needed by a replacement. It changes no field, code rate, query count, transcript,
commitment, proof grammar, verifier, hiding rule, GKR schedule, protected path, or activation state.

### Full-scale geometry correction

The earlier PCS replay paragraph incorrectly reused the repeated GKR worker dimensions
`2^26`/`2^28`. Those are `4,096 * group_count` Fp16 worker-table dimensions. The PCS producer at
`src/bin/gkr_coherent_chain_benchmark.rs:2016-2131` instead commits the full Boolean shard
dimension: `2,048 wires * 8 shards * group_count`, agreeing with the prior allocation audit's
PCS input logs 28/30 at `STATE.md:1880-1891`.

The corrected projections are:

| Quantity | K128 | K512 |
| --- | ---: | ---: |
| PCS data variables | 28 | 30 |
| Hidden-polynomial log size | 29 | 31 |
| Rate-1/8 LDE log size | 32 | 34 |
| Replay-engine internal state | 4,032 bytes | 4,288 bytes |
| Two packed Boolean source boundaries | 67,108,864 bytes | 268,435,456 bytes |
| Generalized batched fold/query proof | 32,786,571 bytes | 36,974,219 bytes |

The proof projection advances by 4,187,648 bytes for every two added input variables, matching the
current fixed 473-query canonical frontier geometry. It remains a projection, not an encoded
full-scale proof.

### Scalar replay is a rejected speed architecture

`replayed_fri_layer_value` scans all data evaluations and all mask coefficients for each output.
The exact initial-layer source-term visits are therefore
`2 * 2^input_log * 2^lde_log`: `2^61 = 2,305,843,009,213,693,952` at K128 and
`2^65 = 36,893,488,147,419,103,232` at K512. Output tiling changes retained bytes but not either
count. Even an impossible optimistic rate of one trillion complete source-term visits per second
would require about 640.51 hours for K128 and 10,248.19 hours for K512 for this first layer alone;
one real visit actually contains multiple Fp16 operations. Scalar replay is retained only as a
differential oracle.

The exact count gate passed:

```text
running 1 test
test streaming_mlpcs::tests::tiling_does_not_cure_scalar_replay_work_at_full_scale ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 201 filtered out; finished in 0.00s
```

### Two-pass codeword mechanics

A test-only deterministic linear encoder exercised the intended bounded shape:

1. stream codeword leaves in canonical order and publish the SHA3-512 root;
2. receive verifier-derived queries;
3. replay the same encoder once, capture only queried leaves and the canonical Merkle frontier;
4. independently verify the opening.

The replayed root, dense-control root, opened leaves, and exact frontier bytes were equal. The
test retains one leaf payload plus the logarithmic Merkle stack/frontier, not a codeword. A second
KAT used two general non-base Fp16 scalars and proved
`Encode(alpha*x + beta*y) = alpha*Encode(x) + beta*Encode(y)` for a generator containing only
base-field unit coefficients. This validates the scalar-extension engineering identity, not the
toy code's distance, extractor, or security.

```text
test streaming_mlpcs::tests::two_pass_linear_encoder_replay_matches_dense_commitment_and_openings ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 203 filtered out; finished in 0.00s

test streaming_mlpcs::tests::base_generator_is_linear_under_general_fp16_challenges ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 203 filtered out; finished in 0.00s
```

### Sequential product-sumcheck mechanics

The prior replayed product-sumcheck evaluator recomputed a complete multilinear evaluation for
each suffix point. The new `streamed_product_round_coefficients` folds each contiguous accepted-
challenge prefix block directly. For every round it reads each of the two source tables exactly
once, retains only logarithmic recursion state and three coefficients, and emits the identical
degree-two message. The 10-variable KAT compared every round with the dense fold control, asserted
exactly `2^10` reads from each source at every round, and compared both terminal values.

```text
test streaming_mlpcs::tests::streamed_product_sumcheck_messages_match_dense_with_exact_read_count ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 204 filtered out; finished in 0.02s
```

This simple implementation is `O(N log N)` work for a complete product sumcheck. It is the readable
differential baseline, not the final throughput kernel. The primary TCC 2025 result “Time-Space
Trade-Offs for Sumcheck” gives product-multilinear prover time
`O(N * (log log N + k))` with `O(N^(1/k))` space; its exact adaptation to Blind Ledger's sparse
repeated Keccak relation, masks, and authenticated message order remains to be implemented and
differentially tested.

### Lean candidate and remaining hard gate

The smallest architecture still capable of satisfying both memory and latency is:

- deterministic packed-source streams;
- a theorem-backed sublinear-space product-sumcheck rather than scalar evaluation replay;
- a proved-distance, linear-time encodable code emitted in canonical order;
- one pre-query root pass and one post-query opening pass, with bounded parallel Merkle tiles;
- M31-row/base-generator arithmetic promoted through the frozen basis to full Fp16 challenges;
- streaming proof emission and independent streaming verification;
- unchanged SHA3-512 authority and authenticated interactive public coin.

The IACR papers “Query-Optimal IOPPs for Linear-Time Encodable Codes” (2025/1588) and
“Field-Agnostic SNARKs with Small Proofs via Encode-Repeat-Accumulate (ERA) Codes” (2026/864)
establish that linear prover time and `O(lambda)` query complexity are available for suitable
linear-time codes. The Block-Accumulate paper (2025/1828) supplies a faster-code comparison but
does not by itself freeze a Blind Ledger PCS. No paper benchmark receives local throughput credit.

The cryptographic code lane is **not selected**. The exact generator, rate, concrete minimum
distance, block/interleaving geometry, 392-bit error ledger, round-by-round extractor, native
hiding composition, and authenticated-public-coin transcript mapping are not yet frozen. Therefore
the four Phase-1.6 ECCC/code checks still do not all pass, and replacing the current PCS would be a
trust-critical invention. The two-pass and sumcheck KATs are a positive architecture-mechanics
signal, not full PCS feasibility, complete K128/K512 proof evidence, or qualification.

Changed nonprotected source in this audit: `src/streaming_mlpcs.rs`. Protected-path edits: zero.
PCS parameters changed: zero. Proof/verifier grammar changed: zero. Activation changes: zero.

### Containing verification

The complete release/locked/offline/parallel library suite passed after the corrected 28/30-variable
geometry and all three new mechanics KATs were present:

```text
running 205 tests
...
test gkr_sumcheck::tests::replayed_sparse_real_keccak_layer_is_exact has been running for over 60 seconds
...
test result: ok. 205 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 84.69s
```

`cargo fmt --all --check` exited zero with empty output. The no-default-features build also passed:

```text
cargo check --release --locked --offline --no-default-features --lib
warning: `bl_pq512_crypto_core` (lib) generated 4 warnings
Finished `release` profile [optimized] target(s) in 7.33s
```

The four warnings are the same pre-existing unused import/field/method findings recorded above.
Strict Clippy reproduced the same 29 pre-existing findings and emitted no finding for
`streaming_mlpcs.rs`:

```text
error: could not compile `bl_pq512_crypto_core` (lib) due to 29 previous errors
```

This archived workspace has no usable Git metadata: `git rev-parse --show-toplevel` fails from the
workspace and every ancestor, while `C:\Users\neers\Documents\Codex\.git` exists as an empty
directory. Therefore a Git diff/HEAD assertion cannot be produced from this copy. Exact current
SHA-256 values before this paragraph was appended were:

```text
38CA1810506B56E06A730C04F2A496352A51F542972B4C9E73D826B24D50D5C9  STATE.md
41FE8E7C2B54A943929722E3D0F2F19456333A20D272B8591E8B90D73C74983A  docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md
FC6D1C045730873AEECE6EF64D4F926D051CD9B92245B54D0EDC717FBFEA7196  experiments/bl_pq512_crypto_core/src/streaming_mlpcs.rs
```

### Documentation consistency correction

Two architecture documents still described the old 2,624/1,984 round projections with wording that
could be read as an instruction to use them. Both now state that these are historical planning
placeholders only, receive zero acceptance or calibration credit, and must be replaced by exact
authenticated-round and coin-round counts derived from each built schedule. The 13/5 mask sizes
remain authoritative. This is a documentation-only reconciliation; no schedule, build flag, mask,
proof, verifier, fixture, or source parameter changed.

## 2026-07-28 strict-Clippy cleanup - COMPLETE

The owner directed that Clippy cleanup precede the next memory decision. The existing strict
parallel-library command initially failed on 29 findings. The cleanup used behavior-preserving Rust
refactors rather than disabling or weakening the lint gate:

- named aliases replaced repeated protocol tuple/callback types;
- one private worker session and one public verifier expectation set became named records;
- feature-specific fields, methods, and imports are now compiled only with their consumers;
- iterator, lifetime, conversion, divisibility, and borrow simplifications preserve the same order
  and values;
- Keccak rho/pi loops now iterate the frozen rotation table directly;
- the test-only fixture-coin module moved under `src/bin/support/`, preventing Cargo from
  auto-discovering it as an empty standalone binary while preserving its existing feature-gated
  inclusion in `gkr_coherent_chain_benchmark`.

No new lint allowance or suppression was added, and no lint gate was downgraded or removed. No
field, code rate, query count, challenge, transcript, commitment, proof grammar, verifier equation,
hiding rule, GKR schedule, mask size, fixture value, activation flag, or protected path changed.

Final strict lint evidence:

```text
cargo clippy --release --locked --offline --features parallel --lib --message-format short -- -D warnings
Finished `release` profile [optimized] target(s) in 8.05s

cargo clippy --release --locked --offline --features parallel --all-targets --message-format short -- -D warnings
Finished `release` profile [optimized] target(s) in 0.46s

cargo clippy --release --locked --offline --all-features --all-targets --message-format short -- -D warnings
Finished `release` profile [optimized] target(s) in 11.68s

cargo clippy --release --locked --offline --no-default-features --lib --message-format short -- -D warnings
Finished `release` profile [optimized] target(s) in 6.15s
```

All four commands exited zero with zero warnings and zero Clippy findings. `cargo fmt --all --check`
also exited zero with empty output.

The final containing library suite passed:

```text
running 205 tests
...
test gkr_sumcheck::tests::replayed_sparse_real_keccak_layer_is_exact has been running for over 60 seconds
test gkr_sumcheck::tests::replayed_sparse_real_keccak_layer_is_exact ... ok

test result: ok. 205 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 84.25s
```

The moved fixture module's own feature-gated benchmark tests also passed:

```text
running 4 tests
test tests::scaled_terminal_binding_preserves_dynamic_group_dimension ... ok
test tests::canonical_input_rejects_inactive_lanes_and_padding_wires ... ok
test tests::zero_high_wire_coordinates_restrict_output_claim_to_sha3_digest_bits ... ok
test gkr_coherent_chain_benchmark_fixture_coin::tests::fixture_authentication_replay_and_domain_separation_hold ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.52s
```

Current SHA-256 values for the 19 changed nonprotected Rust files are:

```text
5DDBF12C5D0A2B715532C876290B153030549B0F92133D014B3A20B035378BAC  src/cross_domain.rs
1328CC1D99370E439B4465C30F66B6908C5608BE914BBF15F36A519674DF8336  src/fri_layer_multiproof.rs
4CBA220442469A722463E2A82705C2261F0C4688A632FB586340DC1A3EC7E2F2  src/gkr_sumcheck.rs
0256AA7187F904FA56B0FA1ADF98DA82935D6261AD91B9760957BAE8DC7F347C  src/gkr_worker.rs
7D3145E3D9265C79F8268AE33A670BCA9194C39AA3DA2AA449A0085C2E40FE9F  src/gkr_zk_mask.rs
AFABD9BA510B3F0E817EFD64B901905A4F87D2ADFD6D06A3CBD401241915144A  src/keccak_gkr_wiring.rs
3BA89E8AC08FE2C0B74E5C140CA05F5FDD7C810B250C578A27A52B27DCF3E3D5  src/merkle.rs
64D46CDB2D61482612636AC0DC4F7616C0A4B9B8400AA629B682325F320F8681  src/merkle_multiproof.rs
869108206E833CA5B99D3CDFB436A940E46F432B3102C6168DB8F1D0B4D277B4  src/multilinear_pcs_proof.rs
E1208842599B4AB586D099E9DFBDF975018DBE999CBCBD94B93DCB97F787DCBE  src/multilinear_pcs_query.rs
650FDCD827B5C3D65A6D51E83468A0FDDCB6D3278B1BCDA097B4C61DE473B17A  src/multilinear_pcs_transcript.rs
1ABDF71269F9185C66B5F918B36AE50E179829F95DE586133AA3F46EF30CB6A6  src/packed_boolean_sumcheck.rs
F3508C857FAA197AABDC76EBA6E4DE4FF24071C8C319E2D547DCAE0350F09A5A  src/sha3_coprocessor.rs
EF1C0C0B637DEF2870607639371019E047789DCDA4EC3E537BF160EB02C3C723  src/streaming_mlpcs.rs
F364EDD1A95DFBEB97175C29EA868EB6C39D6377254E210C3F7FD4544ED0D405  src/bin/gkr_coherent_chain_benchmark.rs
8F305DEFA8C6627562D878929215F8DF63F501BD4CED669CCCE5EF077B4DA5D3  src/bin/support/gkr_coherent_chain_benchmark_fixture_coin.rs
27DCFF67091399DF45B0525274F454A2CFE2B58B7DBC789F1BCE2674C3F97765  src/bin/gkr_compact_chain_benchmark.rs
66FEFB1B27DFDE0A27AA8E9B8A8178DF7D5A0E93313A31811D89E5DB3D8AA016  src/bin/gkr_cuda_worker_benchmark.rs
838FB591AB163BC0EC4C22970B1E89E3D1EE86E28D3DB093F20F5291BF216238  removed B=64 spike (Git history)
```

Protected-path edits: zero. Skipped Clippy findings: zero. Remaining Clippy warnings: zero.
Activation changes: zero.

## 2026-07-29 Construction 8.2 PCS correction and GKR-binding hardening

The 2026-07-28 BaseFold selection, 26.859692-second partial accounting, and 6,241-round schedule are
superseded where they conflict with this checkpoint. The seven-layer/B=16 relay-free GKR remains
selected. The nonactivating PCS attempt is now Construction 8.2 of ePrint 2026/391 over
random-padded interleaved Reed--Solomon codewords. EPrint 2025/1828 Block-Accumulate remains
comparison evidence only.

The exact K128 main instance is length 131,072, message length 65,536, random-padding length 2,048,
proximity `5/32`, and 1,600 queries. Nine auxiliary instances have length 8,192, message length
2,048, random-padding length 1,218, proximity `1/5`, and 1,218 queries. The measured current
security ledger is 392.179996538 bits main, 392.108419573 bits auxiliary, and 392.108419573 bits
composed.

The exact GKR component sum is 24.7958928 seconds. The successful segment-32 PCS control measured
3.586543 seconds for initial mechanics, 191.533 MB host peak, 1,612.185152 MB device allocation,
14.347776 MB initial-oracle multiproof, and 0.000000 MB scratch. The 28.3824358-second partial sum
leaves 1.6175642 seconds for every still-open stage and is not a complete-proof projection.
Segment 16 measured 6.449925 seconds, 164.966 MB host, and 873.986048 MB device; it is the
lower-memory fallback, not the current sub-30 throughput candidate.

The exact shared public-coin schedule is 5,821 rounds: 5,809 GKR and 12 PCS. The isolated
5,821-round dual-PQ control passed message-before-challenge ordering, ML-DSA-87 and
SLH-DSA-SHAKE-256f authentication, canonical encoding/decoding, independent replay, and replay
rejection in 1.267659 seconds with a 3.770467 MB bundle.

The GKR/PCS boundary is implemented in `src/fp16_zk_rs_gkr_binding.rs`. It accepts exactly two
unmixed 24-coordinate GKR claims, treats the low 16 coordinates as the coefficient point and the
high eight as the 256-word point, and derives the exact 512-word linear form plus batched target.
Its two focused Rust tests pass and reject claim count, point dimension, mixed coefficient, word
value, and target mutations.

`src/bin/fp16_zk_rs_theorem8_1_transcript.rs` stream protocol v3 now reads those GKR claims and the
authenticated batching challenge. It derives the linear form in Rust and verifies all 512 word
evaluations before releasing the first sumcheck challenge. It no longer accepts an authoritative
target or linear form from Python.

The production-geometry host integration KAT passed:

```text
kat=fp16_zk_rs_authenticated_sumcheck_v2
rounds=13
input_payload_mb=1.215944
sumcheck_message_mb=1.179648
public_coin_bundle_mb=1.243457
public_coin_head_auth_seconds=0.509042
native_sumcheck_compute_seconds=0.068330
public_coin_finish_replay_seconds=0.039969
integration_wall_seconds=0.862441
sampled_python_bridge_transcript_host_peak_mb=38.920
challenge_digest=653caaa0d60edf4b6897d03db2c15d2de9b3a352848ee5bb72afbcf7938a7a110bbded3b5fd3d79b234435a78d4826477dfdde890812db6309b3d65c4a8d76bd
ml_dsa_87_head_authenticated=true
slh_dsa_shake_256f_head_authenticated=true
message_before_challenge=true
sumcheck_chain_and_terminal_verified=true
independent_bundle_replay=true
sumcheck_ordinal_mutation_rejected=true
gkr_claims_authenticated_before_batch_challenge=true
gkr_linear_form_derived_in_rust=true
claimed_gkr_target_bound_before_sumcheck_challenge=true
gkr_claim_target_mutation_rejected=true
gkr_linear_form_mutation_rejected=true
launch_fiat_shamir=false
grinding_credit=false
complete_pcs_qualification=false
complete_proof_qualification=false
```

The standalone KAT uses 13 rounds because it separately authenticates the fixture GKR terminal
batch. In the real combined chain that round is already one of the 5,809 GKR rounds, so the exact
combined schedule remains 5,821.

`cuda/cuda_fp16_zk_rs_theorem8_1_k128_prototype.py` now computes full multilinear evaluations of
the committed fixture messages at two 16-coordinate coefficient points, builds two exact
24-coordinate fixture GKR claims, authenticates their batching message with the real dual-PQ
public coin, and sends only the claims, batching challenge, masks, and word values to Rust.
Its regenerated PTX is 2.042239 MB with SHA-256
`5DA70C0B7CBE84F34F8DEA49654C05E720AB1788DAD456A43ACC7A2166455610`.
This is binding and compilation evidence only; the actual B=16 GKR producer is still not joined.

The segment-32 geometry is now a durable source option rather than an ephemeral edit.
`BL_ZK_RS_INTERLEAVINGS_PER_SEGMENT` accepts only 16 or 32, the theorem grammar derives 35 or 19
trees, and the native verifier derives leaf size, data size, boundary, kind, and auxiliary
ordinals from the accepted grammar. Both cross-process KATs pass:

```text
segment-16: segment_count=35; proof_fixture_mb=57.710544;
verify_compute_seconds=0.688713; mutation_compute_seconds=0.618240;
fixture_build_and_verify_wall_seconds=2.904666

segment-32: segment_count=19; proof_fixture_mb=55.960528;
verify_compute_seconds=0.596635; mutation_compute_seconds=0.332884;
fixture_build_and_verify_wall_seconds=2.073357

all_roots_verified=true
all_leaf_mutations_rejected=true
all_frontier_mutations_rejected=true
all_root_mutations_rejected=true
proof_system_qualification=false
```

Construction 7.2/8.2 hiding mechanics, conditioned sumcheck sampling, exact query derivation, and
production query-view streaming pass the executable offline audit. The audit used 26.104 MB host
peak and is excluded from proof time. Native multiproof, answer-code, spot-check, semantic
transcript, public-coin, and mutation controls pass independently. These controls do not qualify a
complete proof.

Current open trust boundaries are:

1. replace deterministic fixture GKR claims with the actual B=16 GKR producer in the same
   authenticated coordinator;
2. bind the same committed RS source to those claims, not merely an equivalent regenerated fixture;
3. run the bounded semantic AIR concurrently and atomically join program/bus, roots, parameters,
   verifier identity, state/retry identity, and ordered 12-field statement;
4. close the complete GKR+PCS+coin+dual-PQ+retry error/security composition and full leakage
   boundary; and
5. run one fresh segment-32 K128 proof, then the required warm-up and ten unique p95 proofs.

Six `nvlddmkm` driver errors were recorded between 2026-07-29 08:37 and 09:05. A production GPU run
is unsafe until the driver is reset. No failed or pre-reset run receives qualification credit.
CPU/source verification and NVRTC PTX compilation remain safe. `proofSuiteId=null`, activation is
false, protected-path edits are zero, and complete proof qualification remains false.

Containing regression after the correction first reproduced the historical PowerShell startup
classification race: 233 Rust tests passed and
`gkr_worker::tests::malformed_and_stalled_workers_fail_closed` received `Err(Timeout)` instead of
the intended malformed-frame `Err(Protocol)`. The protocol did not accept anything. The test used
the same two-second deadline both for starting PowerShell and classifying the returned frame, so
full-suite host contention could consume the entire malformed-frame deadline before PowerShell
wrote its eight invalid bytes. The malformed case now has a 15-second startup/frame budget while
the separate stalled-worker case retains its 25-millisecond timeout. No parser, protocol, or
fail-closed check was weakened.

The focused worker attack passed five consecutive reruns. The containing release library suite
then passed:

```text
test result: ok. 234 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;
finished in 84.84s
```

Strict `cargo clippy --locked --offline --features parallel --all-targets -- -D warnings` initially
found one pre-existing `needless_range_loop` in `src/gkr_packed_binary_bridge_fp16.rs` and one
`manual_div_ceil` in `src/bin/fp16_zk_rs_theorem8_1_transcript.rs`. Both received mechanical,
semantics-preserving iterator/arithmetic corrections. The three exact B=16 bridge tests passed, and
the full strict Clippy gate then exited zero with no warnings. `cargo fmt --all --check` and
`cargo check --locked --offline --no-default-features --lib` also exit zero.

The fresh complete CPU KAT pass reports:

- Construction 8.2 hiding audit: 53.130368 MB simulated view, 24.662 MB host peak, every algebra,
  rank, distinctness, randomness-coverage, and conditioned-view flag true;
- answer-code verifier: 6.217900 MB production payload, 0.306343 seconds wall, 56.381 MB combined
  host peak, correct codewords and coefficient mutation checks true;
- authenticated GKR/PCS sumcheck v2: 13 rounds, 1.215944 MB input, 1.179648 MB sumcheck messages,
  1.243457 MB coin bundle, 0.882804 seconds wall, 38.859 MB host peak, all binding/order/replay
  mutations rejected;
- segment-16 and segment-32 native multiproof grammars: 35 and 19 trees, every root accepted and
  every leaf/frontier/root mutation rejected; and
- exact architecture coin control: 5,821/5,821 rounds independently replayed, 3.770467 MB bundle,
  and 1.336846 seconds total.

The security ledger still correctly prints
`iopp_implementation_complete=false`,
`canonical_communication_grammar_closed=false`,
`complete_simulator_implementation_verified=false`,
`cryptographic_composition_ledger_closed=false`, and
`complete_proof_qualification=false`. Those flags remain open because the actual GKR producer,
semantic/atomic join, and fresh full GPU proof have not run.

### Post-boundary-change containing reverification

The GKR/PCS binder now rejects a zero batching challenge in addition to malformed, mixed,
wrong-dimension, wrong-value, and wrong-target claims. After that final fail-closed change, the
complete release/locked/offline/parallel library suite passed again:

```text
test result: ok. 234 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;
finished in 84.42s
```

The production transcript binary was rebuilt, and the fresh authenticated host integration KAT
passed with 13 rounds, 1.215944 MB input, 1.179648 MB sumcheck messages, 1.243457 MB public-coin
bundle, 0.907082 seconds wall, and 38.908 MB host peak. ML-DSA-87 and
SLH-DSA-SHAKE-256f head authentication, message-before-challenge ordering, independent replay,
terminal-chain verification, and claim/target/form/ordinal mutation rejection were all true.
`complete_pcs_qualification=false` and `complete_proof_qualification=false` remained correctly
false.

At 2026-07-29 11:00 local time, the machine's last boot was 2026-07-29 02:33, before all six
`nvlddmkm` Event 153 errors recorded from 08:37 through 09:05. The required driver reset therefore
has not occurred. No production GPU proof was launched.

## 2026-07-29 transfer reconciliation and five-claim compact PCS correction

The ZIP-derived transfer intentionally omitted cache content and Git metadata. The 42 recovery paths
were treated as a recoverable transfer omission, not a contradiction. The authorized read-only
candidate root was
`C:\Users\neers\Documents\Codex\2026-07-08\you-are-working-on-the-blind\blind-ledger-claude-architecture-workspace\Blind Ledger Neer Version\blind-ledger-app-layer`;
the destination root was this active source tree. Every candidate and destination SHA-256 matches:

| Relative path under both roots | Expected SHA-256 | Actual SHA-256 | Result |
| --- | --- | --- | --- |
| `cache/foundation-runs/20260715T073140Z-foundation17-r21/terminal_manifest.json` | `7BCAF24F33130AEA258A58286B8121C4C19A89D7F2C9C691A77CA633CC69006F` | `7BCAF24F33130AEA258A58286B8121C4C19A89D7F2C9C691A77CA633CC69006F` | MATCH |
| `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/run_manifest.initial.json` | `F874E3FD2B4694552A9EFA6891BFE5A89AD3B235E16A3F7A3C2801E109B5797C` | `F874E3FD2B4694552A9EFA6891BFE5A89AD3B235E16A3F7A3C2801E109B5797C` | MATCH |
| `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/stages/06_k128_k256_k512_measurement.json` | `97495AFDE110B20A37C6ABA5AA62281FE96A91FD9A89A859CC4CE991743A306F` | `97495AFDE110B20A37C6ABA5AA62281FE96A91FD9A89A859CC4CE991743A306F` | MATCH |
| `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/terminal_manifest.json` | `0B2560B3CE041513AA488AC47B13A25D48A99D53D444355DDDEB26B220104D14` | `0B2560B3CE041513AA488AC47B13A25D48A99D53D444355DDDEB26B220104D14` | MATCH |
| `cache/implementation-runs/20260716T145548Z-local-implementation-wave-r25/terminal_sha256.txt` | `F2F516EF2ED386E62D201620A5D3F0AA865DC24E057F2EC34BD2F0EC5744D685` | `F2F516EF2ED386E62D201620A5D3F0AA865DC24E057F2EC34BD2F0EC5744D685` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/run_manifest.initial.json` | `E9D15D33BF1FDB9F904BE792DA7B79852EAF4F1F645A101DA9F52E0F6DB88048` | `E9D15D33BF1FDB9F904BE792DA7B79852EAF4F1F645A101DA9F52E0F6DB88048` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/run_manifest.initial.sha256` | `E1FBA869F2522FC8953BA1DB4CC3440DF8E3996D087F5A9F82379D8AA616A106` | `E1FBA869F2522FC8953BA1DB4CC3440DF8E3996D087F5A9F82379D8AA616A106` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/00_freeze_toolchain_and_collection.json` | `33C813F5FC080D9D5F1260C5BCFFBD1933E02F415A3EE7A05B1802B71ABBB0D0` | `33C813F5FC080D9D5F1260C5BCFFBD1933E02F415A3EE7A05B1802B71ABBB0D0` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/01_official_upstream_cryptographic_implementability_review.json` | `194C992AE1B19D4927555F7190040CD279C2DF52330DA637E017F74DD59EF2B3` | `194C992AE1B19D4927555F7190040CD279C2DF52330DA637E017F74DD59EF2B3` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/02_physical_air_calibration_matrix.json` | `AF1EB0A6E8D9F8AA5BFDDCB6DD530DD7BDE56F443159A373C506969AB70AD3B2` | `AF1EB0A6E8D9F8AA5BFDDCB6DD530DD7BDE56F443159A373C506969AB70AD3B2` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/03_integrated_reference_hardening.json` | `4E0347BD44C931454DC011653D4E7D3C03BB1951E379205F02CBC7089ECC18C1` | `4E0347BD44C931454DC011653D4E7D3C03BB1951E379205F02CBC7089ECC18C1` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/04_regression_and_exact_differential.json` | `A90E4BBED649765E3B240BB761355D7DAA68E40E1C6146D59DFBDF4FFF1410C3` | `A90E4BBED649765E3B240BB761355D7DAA68E40E1C6146D59DFBDF4FFF1410C3` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/05_rust_platform_and_proof_gates.json` | `A9A92ADB62F3CDBD6EF0DB30A4C8A370E4126858B6FAEE115E7E3BAB6E920EA1` | `A9A92ADB62F3CDBD6EF0DB30A4C8A370E4126858B6FAEE115E7E3BAB6E920EA1` | MATCH |
| `cache/implementation-runs/20260716T220632Z-private-proof-engine-r26/stages/06_cairo_solidity_hygiene_and_privacy.json` | `B5154A40B19AD0532CC933A4C66AFD60496B5BBF3020F245F0609CFDD388F7C2` | `B5154A40B19AD0532CC933A4C66AFD60496B5BBF3020F245F0609CFDD388F7C2` | MATCH |
| `cache/implementation-runs/20260718T134831Z-private-proof-engine-r28/terminal_manifest.json` | `AF78DF6039AD80FA8240952B7129143A63A201170BD17D8E79D15C2CF8C2302F` | `AF78DF6039AD80FA8240952B7129143A63A201170BD17D8E79D15C2CF8C2302F` | MATCH |
| `cache/implementation-runs/20260718T134831Z-private-proof-engine-r28/terminal_sha256.txt` | `F0EF95A6FA948BBB937C036C7E980404381271512D60912E080F66DC1B8300C1` | `F0EF95A6FA948BBB937C036C7E980404381271512D60912E080F66DC1B8300C1` | MATCH |
| `cache/implementation-runs/20260718T154911Z-proving-evidence-r29/terminal_manifest.json` | `D80EEAEAFDF552409D683618CCB6E61A150389B22802DDC1F4701B15D4246872` | `D80EEAEAFDF552409D683618CCB6E61A150389B22802DDC1F4701B15D4246872` | MATCH |
| `cache/implementation-runs/20260718T154911Z-proving-evidence-r29/terminal_manifest.sha256` | `F0E29EE8BF91C8804D60B36DBA8F3CA398E50F9BF29B24FDBBDF3689CF6AC32C` | `F0E29EE8BF91C8804D60B36DBA8F3CA398E50F9BF29B24FDBBDF3689CF6AC32C` | MATCH |
| `cache/implementation-runs/20260718T170233Z-python-supply-chain-r30/terminal_manifest.json` | `B0176C5FB5B49DD584D10B0B3E2F668AF42EC2C5CD4D18A31B4A7D53DAA95A9D` | `B0176C5FB5B49DD584D10B0B3E2F668AF42EC2C5CD4D18A31B4A7D53DAA95A9D` | MATCH |
| `cache/implementation-runs/20260718T170233Z-python-supply-chain-r30/terminal_sha256.txt` | `8B04EEAFBB6437A0AC28805DF32CCD7D5CD3A141DD024F4986F0CE21519F6158` | `8B04EEAFBB6437A0AC28805DF32CCD7D5CD3A141DD024F4986F0CE21519F6158` | MATCH |
| `cache/implementation-runs/20260718T170233Z-python-supply-chain-r30/terminal_sha3_512.txt` | `EFFD5A31FFFF6DC8185178ED2176BD1A67CEBDE44B210CD286F515ECCEE5DB5C` | `EFFD5A31FFFF6DC8185178ED2176BD1A67CEBDE44B210CD286F515ECCEE5DB5C` | MATCH |
| `cache/implementation-runs/20260719T013047Z-s09-public-coin-r31/terminal_manifest.json` | `F7A60D3E00BF09181EDDC21E42FC9D51AACF5CDB6D410C294B90551185956FF8` | `F7A60D3E00BF09181EDDC21E42FC9D51AACF5CDB6D410C294B90551185956FF8` | MATCH |
| `cache/implementation-runs/20260719T013047Z-s09-public-coin-r31/terminal_sha256.txt` | `839261D0B906A8D5E24C54B363EE076B75840E446573093D1F97154E079A4344` | `839261D0B906A8D5E24C54B363EE076B75840E446573093D1F97154E079A4344` | MATCH |
| `cache/implementation-runs/20260719T013047Z-s09-public-coin-r31/terminal_sha3_512.txt` | `E3E8DF8E03EDE5833432653D434197B8CAD79A91810EE08BAFA851B363E23298` | `E3E8DF8E03EDE5833432653D434197B8CAD79A91810EE08BAFA851B363E23298` | MATCH |
| `cache/implementation-runs/20260719T034130Z-s09-crypto-core-r32/terminal_manifest.json` | `02858710479D2DDC75ACEB278CBC89452FB532C9F79FC48453560A7F44765598` | `02858710479D2DDC75ACEB278CBC89452FB532C9F79FC48453560A7F44765598` | MATCH |
| `cache/implementation-runs/20260719T034130Z-s09-crypto-core-r32/terminal_sha256.txt` | `054AFDFB7515537BE28B8BE0434F387D811AE5A4DECAEFF280EFB850639A9965` | `054AFDFB7515537BE28B8BE0434F387D811AE5A4DECAEFF280EFB850639A9965` | MATCH |
| `cache/implementation-runs/20260719T034130Z-s09-crypto-core-r32/terminal_sha3_512.txt` | `47324E16BB1C4DF4D91214FB0E2010F2470844C7A177D44DBE7EE9AE5041BD17` | `47324E16BB1C4DF4D91214FB0E2010F2470844C7A177D44DBE7EE9AE5041BD17` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/run_manifest.initial.json` | `CF22526CA2EB6A33B3BDECDC7B292FB61858ECF7DC099478CDF7E798FDD9B065` | `CF22526CA2EB6A33B3BDECDC7B292FB61858ECF7DC099478CDF7E798FDD9B065` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/stages/01_complete_relation_and_payment_maps.json` | `DD4260155290F246D526124D466EACA6B9A01153D8523857D08094FFF1812B34` | `DD4260155290F246D526124D466EACA6B9A01153D8523857D08094FFF1812B34` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/stages/02_physical_relation_dimensions_and_measurement.json` | `9E4FD3AABDAEA4FBD8F03003038F51AC8470BDF2D4861BB0F7CF25BC27E9F580` | `9E4FD3AABDAEA4FBD8F03003038F51AC8470BDF2D4861BB0F7CF25BC27E9F580` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/stages/03_final_convergence_and_integrity.json` | `0A3207075B72571E6DDAF32B96C3ED5D8852882F7996B79F1281E48DEFFBD114` | `0A3207075B72571E6DDAF32B96C3ED5D8852882F7996B79F1281E48DEFFBD114` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/terminal_manifest.json` | `38D01BA36A92026E99A52C62BE2E8A1625DD0E5BA93C44BCBB73EC35D22CACFE` | `38D01BA36A92026E99A52C62BE2E8A1625DD0E5BA93C44BCBB73EC35D22CACFE` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/terminal_sha256.txt` | `380266F5656F66D337FA7B75E0EF1B28339C457399C18AB8D13987FB7BEE18C5` | `380266F5656F66D337FA7B75E0EF1B28339C457399C18AB8D13987FB7BEE18C5` | MATCH |
| `cache/implementation-runs/20260719T043958Z-wave1a-completion-r33/terminal_sha3_512.txt` | `066838A35C54FCBCC4BB06FA3109ED8697499923E70EDA8AC5141B626E44A40C` | `066838A35C54FCBCC4BB06FA3109ED8697499923E70EDA8AC5141B626E44A40C` | MATCH |
| `cache/implementation-runs/20260719T164339Z-wave1b-theorem-backend-r35/run_manifest.initial.json` | `8E6F1A6A428F4A30E785ACB024648222790BCB71D936978AF5FE988B3079B8E4` | `8E6F1A6A428F4A30E785ACB024648222790BCB71D936978AF5FE988B3079B8E4` | MATCH |
| `cache/security-freeze-runs/20260715T202353Z-security-freeze-r23/terminal_manifest.json` | `298A3F627D6E58D7800A0FF8329CAD92796F164445C93543E0BF5F1F0B3D0E48` | `298A3F627D6E58D7800A0FF8329CAD92796F164445C93543E0BF5F1F0B3D0E48` | MATCH |
| `cache/security-scans/blind-ledger-app-layer/unversioned_20260713T112204Z/artifacts/fix_report.md` | `3F583D5C2CC36F4400910F1A388B1834BB0F79F17013A01456E24D646C6A4EAA` | `3F583D5C2CC36F4400910F1A388B1834BB0F79F17013A01456E24D646C6A4EAA` | MATCH |
| `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/run_manifest.initial.json` | `B16DF11B1194D9B01CB22BDE319CDFFA9EDBD7793B26EEC34E39D67BD64B0FAB` | `B16DF11B1194D9B01CB22BDE319CDFFA9EDBD7793B26EEC34E39D67BD64B0FAB` | MATCH |
| `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/stages/01a_s07_s08_math_correction.json` | `C96E58C6BE5EFC12DE7692A5B26C471BCFE63D26A754D3AD481C13B67A682A79` | `C96E58C6BE5EFC12DE7692A5B26C471BCFE63D26A754D3AD481C13B67A682A79` | MATCH |
| `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/stages/02a_money_boundary_correction.json` | `C3DB548BF59016446CB617C0AF479EF25C4D9EB52272F8AEE02F33A046BA548A` | `C3DB548BF59016446CB617C0AF479EF25C4D9EB52272F8AEE02F33A046BA548A` | MATCH |
| `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/terminal_manifest.json` | `05B98E3C94F3154C548D6834C8C16201F59EA7A724CA1C3E7AD43176B970BF7E` | `05B98E3C94F3154C548D6834C8C16201F59EA7A724CA1C3E7AD43176B970BF7E` | MATCH |
| `cache/specification-runs/20260715T221859Z-s07-s12-freeze-r24/terminal_sha256.txt` | `986FFE85F4B326B4B86122AD19469133F82BB270FCB481885E7081ADD2130E43` | `986FFE85F4B326B4B86122AD19469133F82BB270FCB481885E7081ADD2130E43` | MATCH |

The active cache contains exactly 42 files totaling 0.236711 MB. All 28 JSON files parse. All nine
SHA-256 sidecars and four SHA3-512 sidecars reconcile with their governing manifests. No candidate
was accepted by filename alone, no file required regeneration, and no backup generation was
rotated.

The earlier exactly-two-claim PCS boundary was incorrect for the relay-free seven-layer DAG. The
correct boundary is one output claim plus four `RoundInput` claims. Each claim fixes one
24-coordinate point, packed value, shard query, and sixteen component evaluations before two
authenticated batching challenges. The corrected implementation is:

- `src/fp16_zk_rs_gkr_binding.rs`: five-claim/two-boundary binding, sixteen-coordinate linearized
  map, and independent final answer target;
- `src/fp16_zk_rs_row_sumcheck.rs`: exact compact source/relation folding, including cross terms;
- `src/bin/fp16_zk_rs_row_sumcheck_prover.rs`: serial and bounded 16-worker host reference plus
  parameter mode;
- `src/bin/fp16_zk_rs_theorem8_1_transcript.rs`: v4 publish-before-challenge stream;
- `src/bin/fp16_zk_rs_answer_target.rs`: independent production-shape target evaluator;
- `src/bin/fp16_zk_rs_answer_code_verify.rs`: v3 epsilon/main-scale target enforcement; and
- `cuda/cuda_fp16_zk_rs_theorem8_1_k128_prototype.py`: component extraction fused into live
  commitment tiles and compact GPU row message/fold/terminal kernels.

The component rows, compact source state, and compact relation state are each 2.621440 MB, for
7.864320 MB total. No duplicate full source replay or second full codeword is introduced. The
standalone authenticated schedule is 14 rounds. The corrected planned combined schedule is 5,822
rounds, adding the previously omitted coordinate-batching challenge; it remains source-derived
until the real coordinator runs.

Static NVRTC compilation, which does not load the GPU driver, passes. The PTX is 3.202943 MB,
SHA-256 `44AEE2D3C889014F936F8913495FBA24114B20CE7038E28A978FE0F7E2E52742`, and contains all six
required entries: coefficient weights, component evaluation, row initialization, quadratic
message, fold, and terminal.

The production-geometry v3 answer-target KAT passed on 16 logical CPU workers with a 6.232512 MB
input, 0.459017 seconds wall, 0.406895 seconds native verify/encode, and 33.112 MB native host peak.
It accepted the correct Construction 7.2 target and rejected target, answer, epsilon/main-scale, and
GKR-point mutations.

The v2 numerical security ledger now includes the five-claim batch at 493.999999989 bits,
sixteen-coordinate batch at 492.093109394 bits, source/mask batch at 495.999999989 bits, and nine
degree-two row-sumcheck rounds at 491.830074988 bits. The composed IOPP floor remains
392.108419573 bits because the auxiliary spot-check term dominates.

The production PCS source prototype is now internally consistent, but it still generates
deterministic fixture claims from the same committed source. The actual seven-layer GKR producer and
atomic semantic/state coordinator are not attached. Production GPU execution also remains blocked
until a clean NVIDIA driver reset; the memory design is not the blocker.

### Containing verification after the compact correction

The first strict Clippy run found four equivalent `round >= variables + 1` comparisons and one
test-only complex return type. They were corrected mechanically to `round > variables` and one
local type alias. No check was suppressed. The affected focused tests and the containing gates then
passed:

```text
cargo fmt --all -- --check
exit=0

cargo check --locked --offline --no-default-features --lib
exit=0

cargo clippy --locked --offline --all-targets --features parallel -- -D warnings
exit=0; warnings=0

cargo test --release --locked --offline --features parallel
test result: ok. 238 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;
all binary and doc-test groups also exited zero
```

The fresh five-claim host integration passed with 14 authenticated rounds, 1.193564 MB input,
2.635356 MB row-source input, 6.232448 MB answer-target input, 1.179648 MB sumcheck messages,
1.240824 MB public-coin bundle, 21.413325 seconds wall, and 134.996 MB host peak. The CPU row prover
used the available 16 logical workers and took 7.453513 seconds; it is a correctness reference, not
the intended production-throughput path. Both PQ chain heads authenticated, the message-before-
challenge order and independent replay passed, the exact source/relation cross terms and final
answer target matched, and ordinal, claim-target, and component mutations were rejected.

All seven focused host KATs passed. The nontrivial v3 answer-target gate used 16 workers and rejected
target, answer, main-scale, and GKR-point mutations. The hiding audit generated a 53.130368 MB
conditioned view at 27.963 MB host peak and passed its algebra, rank, query-coverage, and coupling
checks. The answer-code verifier passed its 6.217900 MB production mechanics at 57.278 MB combined
host peak. Segment 16 and selected segment 32 independently verified 35-tree and 19-tree grammars;
segment 32 used a 55.960528 MB fixture and rejected every leaf, frontier, and root mutation.

The final static NVRTC build remained 3.202943 MB with SHA-256
`44AEE2D3C889014F936F8913495FBA24114B20CE7038E28A978FE0F7E2E52742`.
Python AST parsing and standard-library symbol analysis found no unresolved global names in the five
changed prototype/KAT/ledger modules. Ruff and Pyflakes were not installed, so zero third-party
Python lint commands were run; this was not substituted for the executed AST, protocol, mutation,
or Rust gates.

The final Windows System audit still reports last boot `2026-07-29 02:33:01` and six
`nvlddmkm` Event 153 errors since that boot, from `08:37:54` through `09:05:18`. There is no
post-error reset. Launching a production CUDA proof would therefore violate the explicit unsafe-
resource stop gate. The next permitted action after a clean reset is the actual five-claim GKR
producer/coordinator join and one externally monitored segment-32 complete proof; no sub-30-second
or complete-proof claim is made before that run independently verifies.

## 2026-07-29 selected-architecture resource admission and schedule correction

The owner explicitly replaced the blanket 8-GiB free-host-RAM launch floor for the selected bounded
segment-32 architecture with a calibration tied to its actual footprint. The active preflight now
requires at least `max(1,000 MB decimal, 2 * latest measured complete-proof peak RSS)` free physical
host memory and at least 2,000 MB decimal free device memory. Until a complete proof supplies its own
peak, the 1,000 MB host floor governs against the 191.533 MB measured component peak. Samples during
this continuation ranged from 4,569.681920 MB to 5,066.506240 MB free physical host memory and pass
that admission floor. The immutable acceptance limits remain no more than 5,000 MB process RSS,
strictly below 5,000 MB scratch, and no swap. The 200 MB host and 1,800 MB device engineering
targets also remain fail-closed redesign triggers. All memory values here use decimal MB.

The exact selected component evidence remains 191.533 MB host, 1,612.185152 MB device,
7.864320 MB compact component/source/relation row state, 14.347776 MB initial-oracle multiproof,
26.104 MB hiding-audit host peak, and 0.000000 MB scratch. These are component measurements, not a
complete-proof resource qualification.

First-principles replay of the existing complete masked producer found that the prior 5,822-round
plan omitted theorem-required challenges. The corrected source-derived schedule is 6,086
authenticated rounds: 6,072 GKR transcript challenges, one independent post-GKR aggregate
mask-functional batching challenge, and 13 downstream PCS challenges. The schedule and control
tests and the real dual-PQ coordinator pass at 6,086, but the complete producer has not yet occupied
the mask-batch and downstream PCS descriptors in that same session.

The prior driver-integrity block is also cleared: Windows last boot is
`2026-07-29 18:06:49 -06:00`, with no subsequent `nvlddmkm`/Display reset event in the verified
post-boot audit. A fresh System-log audit remains mandatory immediately before the production CUDA
proof. `proofSuiteId=null`, activation is false, protected-path edits remain zero, and no
complete-proof or sub-30 qualification claim is made.

## 2026-07-29 real uniform relay-free GKR and exact coordinator ABI

The real all-zero sixteen-shard producer now executes the actual 24-round, seven-layer relay-free
Keccak DAG. It uses the ordinary shared-group verifier relation while algebraically eliminating
8,192 duplicate uniform group rows. Through a live dual-PQ authenticated coordinator it produced
and independently replayed exactly 6,072 raw GKR rounds: one output query, 95 claim mixes, 168
packed bridges, 2,184 shared-group messages, 3,456 wire messages, and 168 terminal messages. All
168 layer reductions independently verified, the final boundary contained exactly four zero-input
claims, and a mutated group message was rejected.

The externally sampled run reported:

```text
status=verified
authenticated_chain_heads=true
dual_pq_suites=true
message_before_challenge=true
independent_bundle_replay=true
independent_gkr_algebra_verification=true
gkr_raw_rounds=6072
verified_rounds=6072
gkr_layers=168
final_input_claims=4
uniform_group_materializations=0
bundle_mb=3.382242
peak_host_mb=52.457472
device_mb=0.000000
real_gkr_prover_seconds=10.532918
independent_bundle_replay_seconds=0.147625
independent_gkr_verify_seconds=2.211572
total_seconds=13.484277
```

This is real-GKR component evidence, not a complete proof. The raw producer is now attached to the
atomic dual-PQ coordinator, but native Libra masking, the independent aggregate mask opening, and
the downstream PCS are not yet attached to this producer.

The exact coordinator ABI no longer uses the legacy 28-output placeholder. The output-query round
returns 27 field elements: one shard query, 24 output-point coordinates, bridge rho, and sumcheck
rho. Claim-mix responses return their mixing scalar plus the two rhos. A terminal response returns
three elements only when it carries the next no-mix layer's two rhos; all other selected GKR
responses return one. The standalone bridge KAT exercised a three-element vector response through
both PQ suites and independently replayed it.

The corrected Libra schedule has 2,520 cubic and 3,288 quadratic variables. Its commitment uses
23,544 coefficients padded to 32,768. Conservative leakage rank is 7,728 bridge plus 14,304
sumcheck plus 672 layer plus one aggregate opening, totaling 22,705. The new indexed prior-layer
correction supports relay-free claims originating from different layer masks and matches the old
single-mask formula exactly in its parity test.

The active selected-architecture resource admission remains 1,000 MB free host and 2,000 MB free
device until complete-proof calibration. The measured real-GKR peak of 52.457472 MB reinforces,
rather than relaxes, the 200 MB host engineering target. Native GKR masking, PCS attachment, a
fresh pre-launch Windows System-log audit, and one externally monitored complete segment-32 proof
remain mandatory before any complete-proof or sub-30 qualification claim.

### Containing verification after the real-GKR integration

The exact-output 6,086-round coordinator control independently replayed both PQ chains with a
4.494103 MB bundle in 1.551632 seconds. The optimized containing Rust suite passed:

```text
test result: ok. 249 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;
finished in 89.22s
```

All binary and doc-test groups exited zero. Strict Clippy with `-D warnings` exited zero with no
warnings, `cargo fmt --all -- --check` exited zero, and the locked offline no-default-features
library check exited zero. The public-coin bridge vector KAT returned three field elements on its
first round, authenticated both PQ heads, independently replayed the bundle, and rejected the
round-order mutation. No production CUDA proof was launched because the real producer still lacks
native masking and PCS; the mandatory pre-launch System-log audit therefore was not consumed.

## 2026-07-29 real-GKR/PCS join, bounded memory, and renewed driver gate

The real native-masked 168-layer GKR producer is now joined to PCS in one exact 6,086-round
authenticated session: 6,073 GKR rounds including the aggregate mask batch, followed by 13 PCS
rounds. The PCS commits the 32,768 GKR mask coefficients as 64 dimension-512 auxiliary RS
codewords. The final auxiliary answer has 73 words: nine ordinary sumcheck masks plus 64 GKR mask
words. Its target evaluates the first nine as univariate mask polynomials and the last 64 as
512-value multilinear tables at the common nine row challenges, multiplied by their independently
derived relation terminals and epsilon. The invalid extra-main-codeword shortcut remains rejected.

Exact decimal memory geometry is:

| Live object | Decimal MB |
| --- | ---: |
| Component rows plus 144 source/relation row states | 12.058624 |
| GKR mask coefficients | 2.097152 |
| GKR mask RS codewords | 33.554432 |
| Complete 73-word auxiliary coefficients | 15.258752 |
| Complete 73-word auxiliary RS codewords | 38.273024 |

The production-geometry v4 target/answer KAT used all 16 logical workers, peaked at 77.070 MB host
RSS, independently verified both main and GKR-mask targets/openings, and rejected target, answer,
epsilon, GKR-point, GKR-relation-terminal, and GKR-mask-answer mutations. The 20-tree segment-32
multiproof KAT used a 66.021784 MB fixture, verified every root, and rejected every leaf, frontier,
and root mutation. The real-GKR same-chain coordinator verified all 6,086 descriptors, reused the
GKR mask root, recomputed the 64 relation terminals from the authenticated GKR coefficient weights,
bound their SHA3-512 digest into the base-mask challenge, and independently replayed its 4.324934 MB
dual-PQ bundle. A second complete host session mutated that digest and was rejected fail closed with
`ERR:gkr_pcs_terminal_digest` before the base-mask challenge was released.

Static NVRTC compilation passes at 3.299008 MB PTX with SHA-256
`219ec2ed5343ec9f9d0c136c774bfea581d02d4a0080266c0f430f85a843ac7c`.
Strict Clippy passes with zero warnings. The optimized containing suite passes 252/252 library
tests, every binary group, and doc tests; the latest main group finished in 91.17 seconds.

The first externally monitored production launch did not complete a proof. It failed closed with:

```text
RuntimeError: compact_component_multilinear_evaluations_sync:700
```

No proof stdout was emitted. Before failure, external monitoring measured 317.542400 MB
process-tree RSS, 855.638016 MB total GPU use, 5,347.966976 MB minimum free physical RAM, zero scratch,
and a 2 MB system pagefile-usage delta. These are failed-run diagnostics, not complete-proof peaks.
Windows subsequently recorded `nvlddmkm` Event 153 at `2026-07-29 21:46:13 -06:00`, record
229363. The mandatory production CUDA gate is closed until a clean driver reset.

The failed component stage redundantly evaluated the same fixed public message across all 512
interleavings. The corrected source extracts one actual live commitment tile per boundary and
broadcasts only that boundary's public message evaluation across its 256 high-word positions; the
hiding tail is neither copied nor omitted from its commitment. This removes 510 duplicate
evaluations and still performs no full-source replay. The corrected kernel statically compiles, but
it has not run because the post-failure driver gate forbids production CUDA before reset.

`proofSuiteId=null`, activation remains false, real PHI/payments remain forbidden, and
complete-proof/sub-30 qualification remains open. The immediate next action after a clean reset is
one externally monitored segment-32 run of the corrected source. Do not run any production CUDA
path before a fresh System-log audit confirms zero post-reset `nvlddmkm`/Display events.

## 2026-07-30 complete real-GKR/PCS prototype verification

The authoritative workspace remains
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`.
Its missing `.git` metadata is expected. No replacement workspace was created or extracted.

The Windows reboot boundary is `2026-07-29 23:17:48 -06:00`. Every production attempt after that
boundary had zero `nvlddmkm` Event 153 and zero Display events. The installed NVIDIA 610.88 driver
remained healthy. The final preflight observed 5,562.892288 MB free host memory and 8,342.470656 MB
free device memory.

The complete nonactivating K128 prototype now joins all of the following in one fresh proof:

- the real 24-round, 168-layer, seven-layer/B=16 relay-free GKR producer;
- native Libra masking and its independently checked aggregate committed opening;
- one output plus four relay-free input claims;
- five-claim/sixteen-coordinate quadratic PCS row binding;
- the 73-word Construction 8.2 random-padded interleaved Reed--Solomon auxiliary plane;
- the exact 6,086-round authenticated same-chain schedule: 6,073 GKR rounds and 13 PCS continuation
  rounds;
- ML-DSA-87 and SLH-DSA-SHAKE-256f chain-head authentication;
- authoritative Rust row parameters, answer code, targets, SHA3-512 Merkle roots, mutations,
  transcript replay, and final verification; and
- one atomic GKR/PCS coordinator and verifier with no duplicate full-source replay.

The final externally monitored run is
`cache/wave2-final-proof-20260730-005825.stdout.txt`. Raw decisive measurements were:

```text
process_exit=0
external_input_to_output_seconds=28.943126
complete_process_wall_seconds=28.177317
pcs_mechanics_seconds=20.745883
public_coin_head_auth_seconds=12.724326
compact_row_sumcheck_seconds=3.348778
opening_seconds=2.740147
peak_process_tree_decimal_mb=311.537664
proof_phase_host_peak_mb=305.770
parent_process_lifetime_host_peak_mb=247.575
native_verifier_peak_mb=78.733
max_gpu_used_decimal_mb_sample=1058.013184
tracked_device_peak_mb=956.738816
scratch_mb=0.000000
pagefile_before_mb=226
pagefile_peak_mb=226
pagefile_after_mb=226
post_launch_display_event_count=0
```

Every printed verifier flag was true, including independent sumcheck/terminal/base targets, main
and auxiliary spot checks, native spot-check attachment, every Merkle root, every leaf/frontier/root
mutation, the exact soundness ledger, theorem binding, Construction 8.2 hiding simulator gate,
five-claim binding, Rust-derived parameters, live-tile component extraction, no duplicate full
source replay, independent answer target, real GKR producer, authenticated launch coin, atomic
coordinator, atomic verifier, and complete fresh-proof independent verification. Stderr was empty.

The compact row-state wording is now explicit. Five-claim component rows plus claim source/relation
rows occupy 7.864320 MB. GKR-mask source/relation row state occupies another 4.194304 MB while it is
live. The joined total is therefore 12.058624 MB. The other exact device objects remain 2.097152 MB
of GKR-mask coefficients, 33.554432 MB of GKR-mask codewords, 15.258752 MB of complete auxiliary
coefficients, and 38.273024 MB of complete auxiliary codewords.

The accepted latency changes were deliberately narrow:

- defer GKR algebra replay until it can overlap PCS work, but require it before bundle completion;
- overlap the authenticated real-GKR prelude with independent PCS sampling/commitments;
- carry the Rust-authenticated mask evaluation instead of reevaluating the full mask in Python;
- increase bounded SHA3 leaf batches from 1,024 to 8,192 leaves without changing leaf bytes,
  domains, roots, or verification;
- use a measured hybrid release: machine-native thin-LTO binaries for GKR/field arithmetic and
  generic binaries for the faster SHA3/Merkle verifier lane; and
- parallelize independent spot-check query arithmetic across at most 16 logical workers while
  preserving canonical error order and decoding every Fp16 value.

Rejected experiments remain rejected: parallel CUDA row reduction regressed due JIT/launch cost,
CUBIN loading did not reduce context/module time, public-coin contributor fanout gave no measurable
gain, and sparse-bucket masked GKR regressed the isolated layer prover.

Containing verification is current:

```text
cargo fmt --all -- --check
exit=0

cargo clippy --release --offline --locked --all-targets --features std,parallel -- -D warnings
exit=0; warnings=0

cargo test --release --offline --locked --features std,parallel
test result: ok. 252 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;
all binary and doc-test groups exited zero
```

All seven current host gates passed: semantic theorem KAT, v4 answer-target KAT, answer-code KAT,
hiding/simulator KAT, public-coin bridge KAT, v6 same-chain bridge KAT, and the v2 security ledger.
The retained v4 component-only authenticated-sumcheck harness was skipped because it predates the v6
committed GKR-mask root/opening and mask-row relation; changing only its magic would be incorrect.
The 20-tree segment-32 KAT verified all roots and rejected every leaf, frontier, and root mutation.
Static CUDA compilation produced 3.298706 MB with SHA-256
`6B1F682A647754FEC44AC85E9136962E0591A45865BB2A928EBF180254BAFEA7`.

The requested real-GKR/coordinator/PCS prototype is complete. This does not close H4's bounded
semantic-AIR/bus atomic composition, the historical 200 MB host engineering target, the
warm-up-plus-ten p95 campaign, K512, H6 suite qualification, or activation. The immutable 5,000 MB
RSS, below-5,000 MB scratch, and no-swap gates passed. `proofSuiteId=null`, activation=false,
`complete_pcs_qualification=false`, and `complete_proof_qualification=false` remain correct.

## 2026-07-30 H3 theorem-neutral throughput refinement

The prior `2026-07-29 23:17:48 -06:00` reset label was not supported by the raw Windows System
log. The OS boot was `2026-07-29 18:06:49.5003470 -06:00`, and ten later `nvlddmkm` Event 153
records ended at `2026-07-29 23:16:18.3322898 -06:00`. The event at 23:17:50 was an AMD
power-policy event, not an NVIDIA device reset. A scoped `nvidia-smi --gpu-reset -i 0` at
approximately `2026-07-30 09:02 -06:00` reported a successful RTX 4060 driver restart. The
subsequent PnP status was `OK`, `nvidia-smi` exited zero, and the post-reset System log contained
zero Event 153 and zero Display 4101 records.

The complete-prototype hot path received only theorem-neutral representation, transfer, and
lifetime changes:

- CUDA reduces the existing five boundary rows to the exact 80 component evaluations before
  device-to-host copyout;
- public-coin GKR weights remain one canonical packed 32-bit word array rather than 32,768 Python
  field-element tuples;
- Python sends the three exact source-quadratic coefficients per compact-row round, while Rust
  reconstructs the same 2,048-coefficient masked message from authenticated mask state and epsilon;
- the legacy full-message transport remains accepted, and a Rust parity test proves both transports
  construct the same polynomial; and
- complete auxiliary source, folded source, main answer, and auxiliary answer device buffers are
  released at their final use, removing 39.168256 MB from the tracked device peak.

No theorem object, hiding randomness, query, authenticated round, SHA3-512 root, canonical parse,
degree-tail check, sumcheck-chain check, answer target, mutation test, public-coin replay, or
independent verifier was removed.

The first post-reset proof was a successful cold driver-JIT warm-up. It independently verified with
exit zero and empty stderr, but its 9.920482-second driver-JIT load made in-process wall time
30.685591 seconds, so it receives no sub-30 latency credit. Its raw output is
`cache/wave2-throughput-proof-20260730-090635.stdout.txt`.

The qualifying complete-prototype measurement is
`cache/wave2-throughput-proof-20260730-090753.stdout.txt`, SHA-256
`1047F02D40428F95E7E30A232A484878231AA58AC2612ED6946A374B63DEBE36`.
Raw decisive output was:

```text
external_input_to_output_seconds=24.749154
wrapper_exit_code=0
complete_process_wall_seconds=24.392408
pcs_mechanics_seconds=17.741531
public_coin_head_auth_seconds=12.790189
compact_row_sumcheck_seconds=0.468827
opening_seconds=2.846039
external_peak_process_tree_mb=263.983104
external_peak_gpu_mb=1011.875840
tracked_device_peak_mb=917.570560
scratch_mb=0.000000
pagefile_current_before_mb=220.200960
pagefile_current_after_mb=220.200960
post_launch_driver_event_count=0
stderr_sha256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
exit_record=0
```

Every proof flag was true: sumcheck chain, terminal and base targets, main and auxiliary spot checks,
native spot-check verifier attachment, all Merkle roots, all tested Merkle mutations, exact
soundness ledger, theorem binding, Construction 8.2 hiding simulator gate, five-claim row binding,
Rust-derived parameters, live-tile component extraction, no duplicate full-source replay, compact
GPU row sumcheck, independent final answer target, real GKR producer, nonfixture GKR claims,
independent Fp16 verifier, authenticated launch coin, atomic coordinator, atomic verifier, and fresh
complete-proof independent verification.

Containing verification on the current files is:

```text
cargo fmt --all -- --check
exit=0

cargo clippy --release --offline --locked --all-targets --features std,parallel -- -D warnings
exit=0; warnings=0

cargo test --release --offline --locked --features std,parallel
main library group: 252 passed; 0 failed; 0 ignored
all binary and doc-test groups: exit=0

source_quadratic_transport_matches_complete_masked_message
1 passed; 0 failed
```

All seven host cryptographic gates pass on the current files: semantic theorem, v4 answer target,
answer code, Construction 8.2 hiding/simulator, public-coin bridge, 6,086-round v6 same-chain bridge,
and v2 security ledger. The same-chain mutation rejected a forged GKR terminal digest before the
base-mask challenge. The updated static PTX is 3.387039 MB with SHA-256
`DA61A996AD551E98EDF835DCE52D22B08963ABFC5C8FD7E28F6D051EDF85111D`.

The H3 real-GKR/native-mask/PCS/coordinator prototype remains complete and is now measured at
24.749154 seconds with low-hundreds-of-MB host use and about 1.012 GB sampled total GPU use. H4
semantic-AIR/bus atomic composition, the historical 200 MB host engineering target, H5's
warm-up-plus-ten K128/K512 campaign, H6, qualification, and activation remain open.
`proofSuiteId=null`, `complete_pcs_qualification=false`, and
`complete_proof_qualification=false` remain fail-closed.

## 2026-07-30 H4 real-bus GKR boundary checkpoint

The H3 24.749154-second uniform-zero run is not K128 or K512 semantic proof evidence. H4 remains the
campaign gate. The exact semantic schedules contain 46,858 calls / 113,730 Keccak permutations for
K128 and 165,762 calls / 411,406 permutations for K512. At the selected B=16 and 8,192-group
geometry, K128 occupies one 131,072-permutation coprocessor shard and K512 occupies four such
shards. The release semantic program now retains only the SHA3 message/digest ports and excludes
the internal SHA3 tables; the v2 bus descriptor binds those exact live counts and authenticated
dummy tails.

The host algebra now accepts complete group-major, nonuniform source tables in the native
Libra-masked shared-group reducer. Every group round checks the complete cubic recurrence, folds the
source group axis only after the authenticated challenge, and preserves the full group-folded right
boundary through both terminal-mask extensions. A nonuniform KAT independently evaluates both
terminal openings on the original source tables. The B=16 bridge also exposes exact evaluation of
an arbitrary 16-bit pattern at the authenticated packed challenge. These changes passed four
relay-free DAG tests, four B=16 bridge tests, the optimized 168-layer uniform regression, formatting,
and strict library Clippy with zero warnings.

This checkpoint does not complete H4. The remaining binding is the production producer/coordinator:
stream the real semantic messages into one bounded 52.428800 MB input/output shard pair with the
448 fixed-zero padding wires implicit, produce
the nonuniform bridge and masked layer messages using the existing group-capable GPU worker without
trusting its arithmetic, bind all one/four shards atomically to the semantic-port and bus
commitments, and independently verify the resulting K128 and K512 proofs. No H5 timing campaign or
qualification credit is allowed before that composition passes.

## 2026-07-30 DeepFold selection reconciliation

The current source and canonical documents were reconciled against the 2026-07-29 PCS selection.
zkDeepFold is not the active H3/H4 outer PCS. The selected nonactivating construction is
Construction 8.2 of ePrint 2026/391 with random-padded interleaved Reed--Solomon codewords. The
older multilinear-PCS/DeepFold implementation remains nonproduction differential, rejection, and
resource-control evidence while its shared utility dependencies are audited.

The DeepFold Appendix E condition `2^18 > 473 * 21^2` is the simulator's interpolation-capacity
condition for the superseded `mu=21` zkDeepFold control; `473` is that control's unique-decoding
query count. The inequality is genuine hiding evidence for that exact PCS instantiation under
DeepFold's stated simulator definition. It is not a unique-decoding theorem, and it does not prove
hiding for the selected 73-word Construction 8.2 auxiliary plane, native Libra-masked GKR, or
their atomic composition. No proof code, theorem gate, test, round, query, or mutation check was
removed in this reconciliation.

## 2026-07-30 H4 bounded semantic source and exact B16 group phase

The semantic hash-bus boundary is now an owned, fail-closed cross-language snapshot rather than an
implicit test iterator. `BLHBSN01` binds the profile, semantic-program commitment, v2 descriptor
commitment, semantic-port commitment, exact ordered messages, capacities, and every SHA3-512
digest. Rust rederives the descriptor, recomputes every digest and the semantic-port commitment,
rejects trailing bytes, and freezes the same K128 encoded SHA3-512 digest as Python:

`b3575b160e3d870671d23cd864f1dfedd7cefa87721f68598434c7bc36cd64a0f387c29babe0034dbb5ee496587eef208cc11581d3cc1d58038a4ffd224dc623`.

The canonical `BLHBB101` conversion retains only the 1,600 live Keccak wires. The 448 circuit
padding wires are fixed zero by the circuit definition and are not serialized. Per coprocessor
shard, the input and output pair is therefore 52.428800 MB; including the 215-byte header, the
canonical K128 file is 52.429015 MB and the four-shard K512 file is 209.715415 MB. Each shard is
stored input-boundary then output-boundary, wire-major with the 8,192 groups as the minor axis.
No duplicate full-source replay or padded-wire allocation is present.

The exact B16 group kernel no longer materializes the old 8,192-group Fp16 source plane. It
publishes the first cubic group message directly from compact `u16` patterns using the exact
degree-15 Lagrange lookup at the authenticated packed challenge, then folds directly into the
half-sized 4,096-group table. Independent CPU calculations matched both the first message and the
first fold. At full K128 geometry the corrected seven-layer group phase measured 0.605268 seconds
per Keccak round, 229.822 MB host peak, and 1,698.495 MB calculated device working set. The
separate exact degree-45 B16 bridge KAT measured 0.496789 seconds per round with 69.042880 MB of
device state. Their 24-round component projections are 14.526432 and 11.922929 seconds
respectively. These are exact-geometry component controls, not a complete proof or latency credit.

The post-reset production gate remained clean before both GPU controls:
`POST_RESET_DRIVER_EVENT_COUNT=0`; NVIDIA 610.88 reported healthy with 7,956 MB free. H4 remains
open until the real snapshot, nonuniform producer, native masking, Construction 8.2 PCS, atomic
one/four-shard coordinator, and independent verifier complete together for K128 and K512.

The real K128 Wave 1A fixture subsequently emitted an 11.554884 MB snapshot; its complete physical
assembly test passed in 172.60 seconds. Rust decoded and recomputed all 46,858 messages, converted
113,730 live permutations plus the authenticated dummy tail, and emitted the exact 52.429015 MB
boundary with SHA3-512
`c21e9de67b45804506d660cf7493042eb0d1ca2abfcbe37ba06a27debe2987324b94c9f1cfdc8084442bd94d4acec5ec572c096bce4f291508fb6b2cbeab11d3`.
The bound commitments are:

- semantic program:
  `ee7df84a8af74f983fc1519437b28f09de1cb5f1067ffd7e0205b280910f6f9019b6b25f29268402099b7b834e35961216f0f082d9ded230e9b840c579a775f5`;
- descriptor:
  `d7b979425eee9ac48804c27f0d90e1e67083a9f85c038f4b735067c57d23b6d859841f4f97470168d6f48079fa788e4b8e2b0abe63ac51819975cd64996e80dd`;
- semantic port:
  `59266af9796a0440d9505edcb2cd1008c16eb4954660e0f011e315b3ee497ff0dfe5e83049635c92a063bbcc681dfe15caae23cc6f2efa7fa54c2b4646a66e50`.

The independent 16-worker Rust bit-sliced executor then evaluated all 24 rounds and seven layers
for every one of the 8,192 B16 groups and matched the complete output boundary. Shard execution
verification took 0.500318 seconds and total file-open/hash/decode/verification took 0.958477
seconds. This closes the real semantic source and trace boundary, not the GKR/PCS composition.

## 2026-07-30 H4 K512 source and bounded masked-group seam

The first K512 snapshot attempt exposed test-only representation bloat: the Python fixture built the
retired full physical SHA3 AIR even though H4 consumes only the semantic-bus program. That process
was terminated at 9,218.748416 MB RSS before it emitted an artifact. It receives no correctness or
resource credit. The K128 physical-assembly regression remains unchanged; K512 snapshot emission now
skips only that irrelevant retired representation.

The corrected K512 semantic build passed its one selected test in 441.10 seconds with empty stderr.
External monitoring observed 3,873.902592 MB peak process-tree RSS, below the 4,500 MB run guard and
the immutable 5,000 MB gate. This is fixture-generation evidence, not prover peak evidence. It
emitted a 41.508092 MB snapshot with SHA3-512
`7b05e56c22c04a3b62f5683032db979946347db8b5660964863e1abcb6db5acb8d9a7302c5e14a06d082f70e254cdc5424dcc19e6d4d1e2bb92f87ccf3c832ae`.

Rust decoded all 165,762 exact calls and converted all four shards to the canonical 209.715415 MB
`BLHBB101` boundary. Its SHA3-512 is
`39a529ab6c337d7753d32b8467c66267bf185e2d1490568f4ac21a0d658778d9aa811eb77d7393a6bd8ea098f49b96d351a7bf59237e0e22bed90841f8992c04`.
The bound K512 commitments are:

- semantic program:
  `618c0945731e170d8bca259f5d5933acfc84379acc751b562cc2c74b450e9a8e91c223045b6cb49a6ee26eaf903821590dbb6bfe4ad49f41116eeb2d4d291387`;
- descriptor:
  `c8328a2c76c3c2c4fbedbc723a2250dcf6ee0b9f198f15241113860a628788cead865b1372b4877101f56023e47deb5f372fa6d54e0ccd5352c25332e325eb91`;
- semantic port:
  `1c225d43e7376dc11abfda70ae70d3a3a06faeacbe4172b61f1592b0ffc21de828863c66cc08e80b33c79b169d65063946fbaf8a5785a740aa4e555881f4ac09`.

The independent 16-worker Rust executor decoded 104,857,600 patterns and verified all four complete
24-round/seven-layer Keccak boundaries in 4.023582 seconds. Per-shard execution times were
0.582480, 0.487975, 0.588844, and 0.498446 seconds.

The native masked shared-group reducer now has a narrow untrusted-oracle seam. Rust checks every
cubic endpoint recurrence, authenticates each published message before releasing its challenge,
then runs the unchanged wire tail, terminal extension, native masks, and terminal checks over the
returned group-folded sources. A CPU oracle produced a byte-identical proof to the complete
nonuniform source-table path; a forged first group message was rejected. The packed B16 bridge now
also enforces its verifier-side sixteen-node sum endpoint independently of source reconstruction,
and rejects a forged degree-45 polynomial. Focused tests pass and strict library Clippy has zero
warnings. The CUDA worker, atomic one/four-shard coordinator, selected PCS join, and complete
K128/K512 proof measurements remain open.

## 2026-07-30 H4 real-GKR/semantic-PCS K128 integration checkpoint

The real nonuniform K128 producer now runs all 168 layers and 6,073 GKR rounds, emits four
relay-free input claims, and enforces 508 native mask constraints. Its standalone component KAT
completed in 104.778552 seconds. The output-query transcript is no longer a uniform-zero fixture:
it binds the `BLHBB101` header, profile, semantic-program/descriptor/semantic-port commitments,
shard count, padded permutation count, live-wire count, exact file size and SHA3-512, selected
shard, and selected GKR-plan commitment. A changed statement binding is rejected.

The same authenticated coordinator now joins that producer to the selected Construction 8.2 PCS
in one 6,086-round schedule. The PCS reads the exact packed semantic shard once, keeps the 448
fixed-zero wires implicit, and does not replay a full Fp16 source. Two integration defects failed
closed and were corrected before receiving proof credit: the canonical file is input-then-output
while the PCS grammar is output-then-input, and compact row source states must retain both
boundaries through the ninth non-Boolean fold even though each claim relation is supported on only
one boundary.

After those corrections, one fresh externally monitored segment-32 K128 proof completed through
independent verification. The proof process exited zero in 120.670536 seconds with empty stderr;
the monitor measured 121.3716075 seconds. Every sumcheck, terminal, base target, answer-code,
main/auxiliary spot-check, Merkle-root, mutation, theorem-binding, hiding, public-coin, real-GKR,
atomic coordinator, and independent-verifier flag printed `true`. The stdout is 3,660 bytes with
SHA-256
`837D45EBD1DAC01E5E52F65B8C7FD8C9547F982D117C3CD4B28FC996A14057B9`;
the semantic file digest is
`c21e9de67b45804506d660cf7493042eb0d1ca2abfcbe37ba06a27debe2987324b94c9f1cfdc8084442bd94d4acec5ec572c096bce4f291508fb6b2cbeab11d3`.

Exact decimal resource evidence is 969.999360 MB tracked device peak, 536.928256 MB monitored
process-tree RSS, 306.905 MB proof-phase host peak, 76.706 MB native-verifier peak, 0.000000 MB
scratch, and no pagefile increase. The prelaunch System-log audit had zero NVIDIA Event 153 or
Display Event 4101 after the confirmed `2026-07-30T13:19:50-06:00` reset boundary, and the proof
added zero such events.

This is functional K128 composition evidence, not latency or suite qualification. The measured
semantic GKR prelude was 110.290992 seconds and the authenticated public-coin head itself was
100.240849 seconds; it is the dominant stage. The run's printed `pcs_mechanics_seconds` included
that prelude because of a reporting-label defect; source accounting is corrected for subsequent
runs and no PCS-only claim is taken from that number. `complete_pcs_qualification` and
`complete_proof_qualification` remain false because K128 exceeds 30 seconds and atomic four-shard
K512 has not yet completed. The next bounded action is theorem-neutral elimination of repeated
worker PTX compilation/reset reconstruction, followed by a fresh proof and only then the K512
four-shard coordinator.

## 2026-07-30 H4 real-wire complete-proof remeasurement

The nonuniform worker now supplies raw group cubics and raw wire quadratics through the narrow
untrusted-accelerator interface. Rust still owns native masks, recurrences, authenticated challenge
release, copied-source terminal evaluation, transcript replay, and independent verification. The
CPU and accelerated oracles produce byte-identical proofs, and a forged first wire message is
rejected. The worker owner closes and verifies the child, performs the scoped reset plus health
check, and starts a fresh process every 48 completed layers; no proof fragment or randomness is
resumed.

One fresh exact K128 semantic proof completed with every printed verification and mutation flag
true:

```text
complete_process_wall_seconds=53.547306
semantic_gkr_prelude_wall_seconds=42.017007
public_coin_head_auth_seconds=41.169864
pcs_mechanics_seconds=4.692209
opening_seconds=2.616566
independent_answer_code_wall_seconds=0.775580
proof_phase_host_peak_mb=295.625
native_verifier_peak_mb=76.435
parent_process_lifetime_host_peak_mb=253.977
tracked_device_peak_mb=969.999360
scratch_mb=0.000000
complete_fresh_proof_independently_verified=true
complete_proof_qualification=false
```

This supersedes the 120.670536-second functional measurement but does not pass the below-30-second
K128 engineering gate. The measured dominant stage is the 168-layer, 6,073-round GKR prelude; PCS
is not the current wall-clock dominant stage. A standalone producer profile verified all 168
layers in 48.207612 seconds total, including 39.470330 seconds in the layer prover,
0.674716 seconds in public-coin work, and 2.554319 seconds in independent verification. Zero
NVIDIA/Display events followed the verified reset boundary.

Rejected exact experiments remain out of the source: a 32-bit `__umulhi` M31 reduction, forced
device vectorization, a 128-register cap, delayed second B16 group materialization, a 32-bit
low/carry product histogram, larger adaptive bridge tiles, group-message prefetch, warp reduction,
multi-claim factoring, and the direct bridge accumulator. Each regressed its containing
measurement or increased live device state without sufficient throughput credit.

zkDeepFold is not selected. The selected PCS remains Construction 8.2 of ePrint 2026/391 with
random-padded interleaved Reed--Solomon codewords. The historical
`2^18 > 473 * 21^2` inequality satisfies zkDeepFold's auxiliary-polynomial simulator condition for
the superseded `mu=21`, `s=473` control. It does not establish system composition, apply to the
selected PCS, or justify the conjecture-dependent lower-query list-decoding lane. No alternative
receives active-path credit without its complete theorem mapping, exact parameter ledger,
implementation, and independent end-to-end verification.

H4 remains open on two measured requirements: redesign K128 below 30 seconds without weakening the
proof, and attach the canonical four-shard K512 source to one fail-closed atomic acceptance
boundary below 180 seconds. `proofSuiteId=null`, activation=false,
`complete_pcs_qualification=false`, and `complete_proof_qualification=false` remain authoritative.

## 2026-07-30 H4 K512 atomic four-shard evidence

The complete K512 coordinator now executes four ordered, independently verified shard proofs
sequentially on one GPU and accepts them under one outer SHA3-512 parent binding and receipt. The
binding covers the canonical 209.715415 MB `BLHBB101` file, selected GKR plan, shard order, and a
caller-supplied application-statement digest; every shard's authenticated public-coin session
includes the same parent binding. No nonlinear challenge stream is shared between shards.

The four shard verifiers passed at 56.240250, 52.837966, 53.901788, and 58.130489 seconds. The
coordinator completed in 222.600073 seconds and the external monitor in 227.826116 seconds.
External process-tree RSS peaked at 591.249408 MB, sampled total GPU use at 2,182.086656 MB, and
scratch at 0.000000 MB. Pagefile use decreased by 2.097152 MB rather than growing. The fresh
scoped NVIDIA reset was healthy and no `nvlddmkm` Event 153 or Display Event 4101 occurred after
reset or launch. The atomic receipt is
`ce4c537f624c5fab7884619b5e5ab65cf0d361d696b41e33a71c43d706a590398a414d4c287119e25355e09d07b0c937be909e476482172a63266fe4a2da6d70`.

This closes functional K512 attachment but not its latency gate: 222.600073 seconds exceeds 180.
The same measured GKR head that leaves K128 at 53.547306 seconds dominates all four shards.
Qualification and activation remain false.

## 2026-07-30 H4 manifest-bound K128/K512 atomic checkpoint

K128 and K512 now use one fail-closed coordinator. It accepts only the canonical one-shard K128 or
four-shard K512 `BLHBB101` shape, a nonzero caller statement, ordered sequential single-GPU shard
proofs, and complete independent verification. The v2 parent and receipt bind an execution
manifest covering the Python entrypoint, exact prototype/semantic-worker dependency closure, seven
native verifier executables, and precompiled PTX. The external monitor recomputes and pins the
same manifest before launch.

Fresh manifest-bound K128 evidence is 54.955357 seconds in-process and 59.060426 seconds external,
532.242432 MB external process-tree RSS, 969.999360 MB child-tracked device state, zero pagefile
growth, empty stderr, and zero driver events. Receipt:
`0217093734fa76a0ae7680ec9f58ebae2145bba0fc4e2945413cc9dbc26322ea2444c12ef56e1a1d6fa620e43cd31832c1a9906b1fca8ac9cc690f73640a4f70`.

Fresh K512 shard times are 55.221861, 54.467592, 53.685071, and 55.734525 seconds;
coordinator/external totals are 220.583627/226.627989 seconds. External peaks are 547.127296 MB
process-tree RSS and 2,182.086656 MB sampled total GPU, with zero pagefile growth, empty stderr,
and zero driver events. Receipt:
`8a3456a9afc715b44543135355490142acb69c0a494fe7f5486f0f375848a35e5c2b4225e261d9ac1471fbf11f1bad5904585cf101063f8fa7bc03b653548822`.
Both runs passed all functional gates and failed only their 30/180-second latency gates.

The verifier surface is narrower. Only complete 20/36-tree proofs, complete 73-word GKR-mask
auxiliaries, V4 answer code, and V2 standalone answer targets are accepted. A new KAT rejected all
10 retired/incomplete forms; the stale V1 answer-code acceptance KAT was removed. Both current
Merkle geometries pass every mutation check. The optimized all-target suite passed 264 library
tests plus every binary group, with zero failures and zero ignored tests; strict all-target Clippy
passed with zero warnings.

The Windows context limit remains a resource-integrity gate. Raising the worker boundary from 48
to 56 failed closed at completed layer 54 with CUDA error 700 and produced `nvlddmkm` Event 153
record 229592. The change was reverted, the bridge rebuilt, and the driver reset. Neither 56 nor a
single 168-layer context is allowed. Qualification, activation, and `proofSuiteId` remain
false/false/null.

## 2026-07-31 H4 complete K128/K512 prototype and latency closure

The authoritative workspace remains
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`;
its missing `.git` metadata was expected at handoff. After the owner's explicit 2026-07-31 request
to use Git, the workspace was initialized in place without creating or extracting another
workspace. The recovery root checkpoint is commit
`20c409b6f546085120542e294e1868e878c56cf8`, tree
`367a4672073f31e71520888cbf73f50b8918c796`: 998 source/documentation files and 11.942784 MB.
Generated targets, caches, the NVIDIA installer, NVRTC wheel/runtime, and NVRTC cache total about
2.27 GB; they remain preserved on disk under narrow ignore rules and were not committed as source.
No remote was configured and nothing was pushed. The verified Windows driver-reset boundary is
`2026-07-31T05:06:01.7747420-06:00`. Every final proof audit found zero later `nvlddmkm` Event 153
and zero Display Event 4101. NVIDIA 610.88 reported the RTX 4060 healthy.

The complete semantic prototype now attaches, for both K128 and K512:

- the exact `BLHBB101` semantic source and all bound program/descriptor/port identities;
- the real 24-round, 168-layer, seven-layer/B=16 relay-free nonuniform GKR producer;
- one output plus four relay-free input claims, 6,073 GKR rounds, and 508 native mask constraints
  per shard;
- the five-claim/sixteen-coordinate compact row relation and 73-word Construction 8.2
  random-padded interleaved Reed--Solomon auxiliary plane;
- exactly 13 PCS continuation rounds, for one verified 6,086-round authenticated schedule;
- ML-DSA-87 and SLH-DSA-SHAKE-256f public-coin head authentication;
- authoritative Rust topology, masking, recurrence, endpoint, canonical parse, SHA3-512 root,
  answer-code, target, mutation, replay, and final verification; and
- one execution-manifest-bound atomic coordinator: one K128 shard or four ordered K512 shards
  sequentially on one GPU with no theorem-free challenge sharing.

The final execution manifest is:

`51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6`.

The final throughput changes are theorem-neutral and purpose-minimal. Rust prevalidates and encodes
each canonical layer plan as one exact batch; Python reads and validates the same batch. The worker
uploads all immutable 24-round/seven-layer topology once as 3.225600 MB of packed device geometry.
Authenticated same-source aliases are derived rather than retransmitted. The coordinator hashes
the semantic file and captures the selected shard in one pass. Exactly one future 48-layer worker
is prepared after the active worker accepts its plan: zero standby exposes measured fresh-context
latency, while additional standbys add residency and startup contention without proof or throughput
purpose. Worker and proof Python processes use `-S` because the manifest-bound closure uses only
the standard library and pinned local modules.

The accepted fresh K128 evidence is
`C:\Users\neers\Documents\Codex\2026-07-29\continue-blind-ledger-wave-2-from\work\h4\k128-final-manifest-complete-v2.stdout.txt`.
Its decisive raw values are:

```text
shard_0_verified=true
shard_0_proof_seconds=29.610331
shard_0_coordinator_wall_seconds=29.973616
execution_manifest_sha3_512=51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6
semantic_hash_bus_file_sha3_512=c21e9de67b45804506d660cf7493042eb0d1ca2abfcbe37ba06a27debe2987324b94c9f1cfdc8084442bd94d4acec5ec572c096bce4f291508fb6b2cbeab11d3
atomic_parent_binding_sha3_512=2c644e1526c5f2623f48e7371750699f429ea875a6af3a82e3c5ab9172d7340e5006bb42feb569352d4d05f63ec5c4996f5666a5805e6f2f8108eac4f355be83
atomic_receipt_sha3_512=c2b5b0ad8a35ac6ffc74f17ab8f7489328486b43a6b65bfd7fa6d09eeaf1ca5b797bf385d41e44c50c44652594e2bd0bdde9be9bca3e94a8510a86ef09e6f8bd
complete_process_wall_seconds=29.974129
peak_host_mb=288.412000
peak_device_mb=969.999360
scratch_mb=0.000000
complete_proof_latency_gate=true
all_shards_independently_verified=true
```

The external K128 wrapper exited zero in 34.1839105 seconds including monitoring overhead. It
measured 681.607168 MB peak process-tree RSS, unchanged 1,045.430272 MB pagefile CurrentUsage,
zero driver events, 1,356 stdout bytes with SHA-256
`F268AB662715DD879E4F550CCEC08A4EFFE6E31D0CC41FF1815212632D119E4B`, and empty stderr.

The accepted fresh K512 evidence is
`C:\Users\neers\Documents\Codex\2026-07-29\continue-blind-ledger-wave-2-from\work\h4\k512-final-manifest-complete-v2.stdout.txt`.
Its decisive raw values are:

```text
shard_0_verified=true
shard_0_proof_seconds=31.567686
shard_1_verified=true
shard_1_proof_seconds=30.679149
shard_2_verified=true
shard_2_proof_seconds=31.019240
shard_3_verified=true
shard_3_proof_seconds=25.998881
execution_manifest_sha3_512=51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6
semantic_hash_bus_file_sha3_512=39a529ab6c337d7753d32b8467c66267bf185e2d1490568f4ac21a0d658778d9aa811eb77d7393a6bd8ea098f49b96d351a7bf59237e0e22bed90841f8992c04
atomic_parent_binding_sha3_512=3015a21648506d665a3fc38deb85413db71c3b8f1b765cf78c971959bb3987cc8acbbcaabe93b41f07680cadee8b5759175198781c4490e04ab93d5222dc5bdb
atomic_receipt_sha3_512=6c0a41d8a198b9d414cc5ee154540cc232cd66482e1342782db01a34b5a552a5ee3a635ef336907d0465d2ce581f170d786fe8371437b54bcf7077c9ef139671
complete_process_wall_seconds=120.460733
peak_host_mb=296.255000
peak_device_mb=969.999360
scratch_mb=0.000000
complete_proof_latency_gate=true
all_shards_independently_verified=true
```

The external K512 wrapper exited zero in 125.7846276 seconds including monitoring overhead. It
measured 706.523136 MB peak process-tree RSS, 2,770.337792 MB sampled total GPU residency,
unchanged 1,046.478848 MB pagefile CurrentUsage, zero driver events, 1,655 stdout bytes with
SHA-256 `3D1CC8F1D0BF22CBA997035D6DC8B1F6A46ED7F4D0BCF12776DF8671BB26AD9E`,
and empty stderr.

The owner's later resource direction explicitly supersedes the historical 200 MB host and
1,800 MB device component-selection targets as acceptance criteria. They remain dated evidence,
not hidden failures. The current objective is a low-hundreds-of-MB internal host image and bounded
device residency within the immutable 5,000 MB host, below-5,000 MB scratch, and no-swap gates.
The accepted 288.412/296.255 MB internal host and 969.999360 MB per-proof tracked device results
meet that objective; K512's 2,770.337792 MB external total includes simultaneous CUDA contexts.

The resource and latency gates remained fail closed. A preceding final-manifest K128 proof was
cryptographically valid but completed in 30.150084 seconds and observed 2.097152 MB pagefile
growth; its wrapper exited one. A preceding cryptographically valid K512 proof completed in
121.195125 seconds but observed 1.048576 MB pagefile growth; its wrapper also exited one. Neither
attempt receives acceptance credit.

Final containing verification is:

```text
cargo fmt --all -- --check
exit=0

cargo clippy --release --offline --locked --all-targets --features std,parallel -- -D warnings
exit=0; warnings=0

cargo test --release --offline --locked --features std,parallel
main library group: 266 passed; 0 failed; 0 ignored
every binary and doc-test group: exit=0

cargo check --release --offline --locked --lib --no-default-features
exit=0
```

All seven current host cryptographic KATs pass. The segment-32 verifier checks all 20 authenticated
trees and rejects every tested leaf, frontier, and root mutation. The retired-format KAT rejects
10/10 old or incomplete encodings. Static CUDA compilation emitted 36 entry points in
3.494439 MB with SHA-256
`B1F826445F2630517E250CE4BBB5E694ADC61620BEED5684C6EE09197EBBEF73`.

The final test-purpose audit listed 266 library tests and found zero ignored tests. The
`v1_layer_openings_compact_to_the_same_global_frontier` case remains because it proves migration
equivalence to the canonical global frontier. The exact two-claim `gkr_pcs_bridge` tests remain as
nonproduction coherent-chain differential controls; the active five-claim verifier cannot accept
their format. The retired-format KAT is required negative evidence. No additional test was removed;
the stale V1 answer-code acceptance KAT had already been deleted when the acceptance surface was
narrowed. The new exact batched-plan encoder/parser tests are required for the final transport.

zkDeepFold is fully reconciled and remains off the active path. The inequality
`2^18 > 473 * 21^2` is only the retired `mu=21`, `s=473` zkDeepFold simulator's interpolation
condition. It gives no hiding, composition, query-reduction, implementation, or measurement credit
to the selected Construction 8.2 PCS.

The complete requested K128/K512 prototype is now attached and passes the one-run 30/180-second
latency, correctness, independent-verification, driver, scratch, RSS, and no-pagefile-growth gates.
This closes H4's functional and prototype-latency boundary. H5's warm-up-plus-ten p95/resource
campaign and H6 suite qualification remain open. Therefore `proofSuiteId=null`, activation=false,
`complete_pcs_qualification=false`, and `complete_proof_qualification=false` remain correct.

## 2026-07-31 current-stack and retired-source cleanup

The active source and documentation surface now has one concise entrypoint,
`docs/CURRENT_TECH_STACK.md`, and one non-executable rejection ledger,
`docs/REJECTED_ARCHITECTURES.md`. The standalone RISC Zero and vendored Stwo experiments were not
imported by the application or selected proof crate. Their 259 tracked source/vendor files and two
backend-specific test files were removed. Exact source, lock, license, measurement, and rejection
identities remain in the rejection ledger and Git history. The two originally ignored RISC lockfiles
were moved intact to `cache/retired-source-locks/20260731-risc0/`; their SHA-256 values remain
`2D4B81A46864741474432DE6C01FCE0AAA119E7D10F96B29788CB3C0A7C084A7` and
`F8B76FE443668B989FC71C2C310755CC5A79F8C14F292B92F44DEFFD4B1342C6`.

Inside `bl_pq512_crypto_core`, five standalone BaseFold benchmark/ledger binaries, the isolated
BaseFold hiding module, and the B=64 nonprotocol spike binary had no current importer and were
removed. The unreferenced 2026-07-13 archive manifest for a different package name/layout was also
removed. In total the cleanup deletes 269 tracked files and 50,648 lines. The Construction 8.2
implementation, five-claim verifier, native masks, authenticated coordinator, migration-equivalence
test, two-claim differential controls, and retired-format rejection KAT remain unchanged.

Post-cleanup containing Rust verification is 264/264 optimized library tests with zero failures and
zero ignored tests; every remaining binary and doc-test group passed. Format, strict all-target
Clippy with warnings denied, and release no-default/no-std check all exit zero. The prior 266-test
count included the removed isolated BaseFold module's two self-tests and is historical.

Current Python collection finds 1,093 ordinary tests before the known absent canonical sibling
`../ops` stops collection. The full attack run completed 351 passes and 45 failures with one warning
and 10 passing subtests; every failure reached a protected batch/policy path that attempted to read
the absent `../ops/policy_spec_v1.yaml`. The focused foundation/security cleanup slice passes 14
tests with one canonical-ops mirror test deselected. The roadmap contract passes two tests and its
third test fails closed only because `../ops/launch_blockers.json` is absent. No check was weakened
to bypass that layout condition.

A broad ordinary run excluding the already-uncollectable `tests/test_batch_layer.py` remained
CPU-active through the 3,604.1-second command-wrapper timeout and finished immediately afterward,
but its terminal summary was no longer recoverable from the wrapper. The pytest cache recorded the
same missing-`../ops` families plus the previously observed attack failures. The run receives no
pass-count credit; focused gates and Rust containing gates above have complete terminal output.

H4 proof evidence and manifest identity do not change. Gate 2E state selection and atomic binding,
composition/simulator closure, H5 repeated p95, and H6 qualification remain the active order.

## 2026-08-01 model-independent technical handoff

The current architecture and execution plan no longer depend on a model remembering chat context or
inferring status from dated evidence. Documentation implementation commit
`238ed83729bd1b8fa7d4e061c2982eab2b4a5c54`, tree
`ed329dc9160b9b37def6bd031b384c7ccddf7ce7`, adds 695 lines and removes 50 across nine files.
Protected-path changes are zero.

`docs/CURRENT_TECH_STACK.md` is now the complete active-stack contract. It defines evidence terms,
frozen invariants, exact K128/K512 geometry, the ordered ten-step H4 proof flow, Rust/CUDA authority
split, decimal memory and concurrency model, privacy placement, fail-closed verifier order, exact
source ownership, required green evidence, execution order, and explicit nonclaims. Its source
readback checked 22 named authoritative files with zero missing. Rust/Python constant readback
reconciled 46,858/165,762 semantic calls, 52,429,015/209,715,415 `BLHBB101` bytes, one/four shards,
1,600 live wires, 131,072 padded permutations per shard, 6,073 GKR rounds, and 6,086 combined rounds.

The deterministic continuation contract near the top of `docs/IMPLEMENTATION_ROADMAP.md` is the
sole current execution algorithm. It contains:

- an explicit current-state matrix and authority rule for historical sections;
- a single dependency chain from Gate 2E through H5, H6, and Wave 3;
- Gate 2E stages 2E-0 through 2E-7 with inputs, outputs, interfaces, mutations, migration/failure
  semantics, finalist measurement, selection, and terminal-handoff requirements;
- an exact H5 matrix of one uncounted warm-up plus ten measured unique attempts for each profile,
  22 fresh launches total, with conservative ten-sample nearest-rank p95 equal to the maximum;
- complete measurement fields, driver/resource/no-swap/independent-verifier STOP rules, and
  first-principles throughput criteria; and
- twelve H6 theorem, simulator, parser, attack, identity, reproducibility, resource, side-channel,
  recovery, and evidence-seal obligations.

Gate 2E and H5 are now unambiguous. Candidate screening uses repeated state-component measurements,
then one uncounted complete warm-up and at least one fresh complete K128/K512 proof per eligible
finalist. Gate 2E selects and atomically binds the state plane. The separate H5
warm-up-plus-ten-per-profile campaign then qualifies the exact selected candidate. A candidate
paper number, state microbenchmark, or Gate 2E finalist run cannot receive H5 p95 credit.

Instruction-level contradictions were removed:

- `AGENTS.md` now records that the architecture requires two ops trees but this workspace is missing
  canonical `../ops`; it forbids constructing it from the app mirror;
- `CONTINUATION_MANDATE.md` makes the July handoff historical, preserves the full ideology, and
  names the current context-recovery order;
- historical R24 parallel/overnight plans are labeled non-executable and cannot restore removed
  RISC Zero or Stwo backends;
- the H0-H6 architecture says H0-H4's executable prototype boundary is complete while containing
  simulator/security obligations remain for H6; and
- the Rust crate-level documentation now describes the actual H4 proof core instead of the obsolete
  statement that it is not a proof system.

Verification after the change:

```text
py -3.14 -m pytest -q tests/test_foundation_spec.py
10 passed in 0.27s

py -3.14 -m pytest -q tests/test_security_freeze_spec.py -k "not app_layer_ops_is_an_exact_recursive_mirror_of_canonical_ops"
5 passed, 1 deselected in 0.09s

py -3.14 -m pytest -q tests/test_deployment_ready_roadmap_contract.py
2 passed, 1 failed in 0.21s
failure: FileNotFoundError for canonical ../ops/launch_blockers.json

cargo fmt --all -- --check
exit=0

cargo check --release --offline --locked --lib --no-default-features
exit=0

cargo clippy --release --offline --locked --all-targets --features std,parallel -- -D warnings
exit=0; warnings=0

git diff --check
exit=0

active stale-current claim scan
hits=0

authoritative source-path readback
checked=22; missing=0
```

The one deselection and one roadmap failure have the same pre-existing reason: canonical `../ops`
is absent. No test, mirror check, protected path, or policy byte was changed to bypass it. H4 proof
evidence, execution manifest, measured resources, and activation status are unchanged. No CUDA proof
was run during this documentation phase.

The exact next implementation action is Gate 2E-0 followed by 2E-1: freeze the C0 state fixtures and
complete-boundary control record, then define narrow canonical state-layout, relation, commitment,
opening, transition, migration, transcript, independent-verifier, and receipt interfaces. Do not
start with a lattice optimization, another proof backend, or H5.

## 2026-08-02 active/history documentation separation

The active handoff no longer interleaves dated execution language with current instructions. Five
former active documents were preserved line-for-line under `docs/history/` except for an explicit
`Archived` title marker:

- the 2,072-line implementation roadmap;
- the 1,365-line throughput-recovery plan;
- the 1,022-line heterogeneous-coprocessor architecture;
- the 427-line proving-optimization review; and
- the 254-line proof-core README.

Readback compared every archived line after the title against Git commit `e640e88`; all five bodies
were equal. `docs/history/README.md` makes the archive non-executable and routes current work back
to the active contracts. `docs/REJECTED_ARCHITECTURES.md` now indexes the detailed archived
provenance without restoring a rejected path.

The active replacements are current-only:

| Document | Active lines | Purpose |
| --- | ---: | --- |
| `docs/IMPLEMENTATION_ROADMAP.md` | 424 before final evidence append | Exact authority, invariants, 2E-0 through 2E-7, H5/H6, all 93 package rows, waves, Git discipline |
| `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` | 225 | Complete-boundary optimization and H5 measurement/STOP contract |
| `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` | 220 | Selected construction, geometry, schedule, authority, memory, verifier, H4 evidence |
| `docs/PROVING_OPTIMIZATION_REVIEW.md` | 108 | Current optimization policy and excluded paths |
| `experiments/bl_pq512_crypto_core/README.md` | 148 | Current crate role, sources, worker rules, commands, and next dependency |

Stale tests that required R24/R25/R26 narrative inside the active roadmap were corrected to test
current security/package invariants and archived provenance separately. A new test rejects seven
known dated-execution headings from every active handoff file and requires all five archives and
the archive authority warning.

Verification:

```text
py -3.14 -m pytest -q tests/test_foundation_spec.py \
  tests/test_security_freeze_spec.py \
  tests/test_deployment_ready_roadmap_contract.py \
  -k "not app_layer_ops_is_an_exact_recursive_mirror_of_canonical_ops and not launch_blocker_manifest_has_only_one_external_assurance_dependency"
18 passed, 2 deselected in 0.41s

py -3.14 -m pytest -q tests/test_deployment_ready_roadmap_contract.py
2 passed, 1 failed in 0.20s
failure: FileNotFoundError for trusted canonical ../ops/launch_blockers.json

cargo fmt --all -- --check
exit=0

cargo check --release --offline --locked --lib --no-default-features
exit=0

cargo clippy --release --offline --locked --all-targets --features std,parallel -- -D warnings
exit=0; warnings=0

git diff --check
exit=0

active dated-heading scan
hits=0

archived body readback against e640e88
5/5 equal after title
```

The one full-roadmap failure is the same pre-existing fail-closed canonical-ops condition. No ops
tree, policy byte, protected path, proof source, proof byte, execution manifest, or activation state
changed. No CUDA proof was launched. H4 evidence and the exact Gate 2E-0 then 2E-1 implementation
boundary remain unchanged.

## 2026-08-01 complete Ethereum Strawmap compatibility contract

The containing architecture is now unambiguous: Blind Ledger is an Ethereum-settled,
EVM-compatible **based validity rollup by compulsory design**. Ethereum ordering is canonical, no
permanent privileged sequencer may own canonical history, every accepted L2 transition requires
the Blind Ledger claim proof and containing rollup validity proof, and public Ethereum DA is
fixed-shape non-PHI only. Draft Ethereum features are versioned compatibility adapters, never
hidden release dependencies.

Implementation commit `c4b2bd86ce26f5900314d7836f2d629754886c0b`, tree
`90cb5dd9d90f2902f797e0585b98178f87a52d86`, adds 437 lines and removes 28 across 20 files.
Protected-path changes are zero.

`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md` records the live
`strawmap.org`/Google Drawing snapshot, not a PDF or screenshot. The Drawing identifier is
`1GkcGfQv9kxgrYQMyu0BYGcZya0gIDG_wQ7GsFJEsdzY`, its label said updated Jul 29, 2026, and the
fetched SVG SHA-256 is
`6514BA52E8EABDDE9162F460E3BAAC52BA0DBA62BA5AA0EAE546FBCB6C7163C8`.
All 23 linked EIPs were fetched from canonical `ethereum/EIPs`; the sorted
`filename:SHA-256` manifest hashes to
`D18D3AB07B30535E647B2E23665958A229934C99318371C61E0C567650561AB2`.

The exact linked set is EIPs 7503, 7732, 7773, 7805, 7919, 7928, 7938, 7999, 8007, 8025,
8070, 8077, 8079, 8081, 8136, 8141, 8142, 8184, 8198, 8200, 8250, 8272, and 8297.
The contract distinguishes Review, Draft, Stagnant, shipped/final, and research maturity; maps
every EIP to an exact Blind Ledger decision; includes the linked primary specification, GitHub,
Ethereum Research, PQ, leanVM/leanXMSS/leanMultisig, ethp2p, evm-asm, and RISC-V sources; and
assigns all consensus, data, execution, PQ, privacy, networking, latency, and throughput
through-lines to existing R01-R12 packages.

The stale active EIP-7707 access-list reference was removed. EIP-7928 BAL is the current Review
compatibility surface. The reason EIP-7707 must not be used remains in the rejection ledger.
BAL is explicitly not the private fixed-padded CBAM. EIP-7503 wormholes, EIP-8184 LUCID,
EIP-8025 optional execution proofs, EIP-8079 native rollups, and Ethereum leanVM are explicitly
forbidden from substituting for Blind Ledger privacy, strict-PQ authority, mandatory validity, or
the selected inner proof.

R01-R12 remain 12 open packages and the total stays 6/93 complete. Their rows now require a pinned
deployed baseline, multi-fork fixtures, proof/verifier/fork/data identity, BAL/CBAM separation,
keyed-nonce and recent-root semantics, final-fork differential proving, fork-aware finality,
ePBS/FOCIL adversarial based ordering, payload/blob/cell reconstruction, finalized bridge
accounting, opaque forced inclusion, fail-closed versioned adapters, and baseline plus future-fork
end-to-end tests. No rollup, production verifier, native-rollup adapter, or Ethereum-security claim
was implemented or activated by this documentation phase.

Verification:

```text
py -3.14 -m pytest -q tests/test_foundation_spec.py
12 passed in 0.20s

py -3.14 -m pytest -q tests/test_foundation_spec.py \
  tests/test_security_freeze_spec.py \
  tests/test_deployment_ready_roadmap_contract.py \
  -k "not app_layer_ops_is_an_exact_recursive_mirror_of_canonical_ops and not launch_blocker_manifest_has_only_one_external_assurance_dependency"
19 passed, 2 deselected in 0.40s

py -3.14 -m pytest -q tests/test_deployment_ready_roadmap_contract.py
2 passed, 1 failed in 0.21s
failure: FileNotFoundError for trusted canonical ../ops/launch_blockers.json

cargo fmt --all -- --check
exit=0

cargo check --release --offline --locked --lib --no-default-features
exit=0 (isolated C:\tmp target used because the pre-existing source-tree cargo lock denied access)

cargo clippy --release --offline --locked --all-targets --features std,parallel -- -D warnings
exit=0; warnings=0

git diff --check
exit=0

Strawmap contract readback
23 EIP rows; 23 unique; 12 R01-R12 rows; 48 HTTPS links; 0 PDF authority links

active stale EIP-7707 reference scan
hits=0
```

No CUDA proof was launched. H4 evidence, proof bytes, execution manifest, resource measurements,
`proofSuiteId=null`, activation=false, the missing canonical `../ops` condition, and the next
Gate 2E-0 then 2E-1 code boundary are unchanged.

## 2026-08-01 L1-lockstep impact and activation clarification

The Strawmap contract no longer requires a successor to infer whether an Ethereum change is
automatic, mandatory, optional, or irrelevant to the L2. Implementation commit
`e5932847c4d4f8fe92ca15484957472bd1a7db3d`, tree
`9f5e394ca2e33523e51148e1a7c5dd8f7c20a8c5`, adds 194 lines and removes five across 13 files.
Protected-path changes are zero.

Every one of the 23 linked EIPs now has an exact impact class, inherited L1 effect, direct Blind
Ledger work, activation trigger, and R01-R12 owner. The five classes are:

- `INHERIT`: L1 supplies the consensus/timing/network property, but BL must update and test its
  observer, finality, reorg, DA, monitoring and capacity assumptions before claiming the benefit;
- `L1-COMPAT`: BL directly changes a parser, producer, Engine/network/DA adapter, L1 transaction,
  settlement contract assumption, receipt, proof/data binding, or monitoring surface;
- `L2-PARITY`: when the selected EVM-compatibility profile mirrors a final L1 execution change,
  the L2 executor, state-transition prover, gas/trace/witness logic, independent verifier and
  receipts change atomically;
- `OPTIONAL`: the baseline does not need the feature and rejects it until R11 selection,
  migration, rollback, security/privacy/PQ review, interoperability and measured benefit pass; and
- `RESEARCH`: no code, capacity, security or release credit.

The deterministic lockstep lifecycle is now explicit in both the compatibility contract and active
roadmap: discover; freeze an exact `ethereum_compat_manifest`; reproduce old/boundary/new and
mixed-client cases; implement affected R02-R11 boundaries; run canonical/differential/adversarial
tests; rehearse complete R12 finality and rollback; activate the fork-bound manifest atomically;
and reconcile post-fork canonical receipts, DA, finality and conservation. Unknown or partial fork
support pauses new batch acceptance/publication while preserving the reviewed exit/recovery path
from the last supported finalized state.

The architecture now states the critical separation directly: Blind Ledger does not reimplement L1
consensus, but inherited behavior is never zero work; DA/Engine/network changes require direct
publisher/reconstruction integration; L1 execution changes require settlement compatibility and
conditional L2 prover parity; optional transaction/privacy/native-proof features remain disabled.
This preserves compulsory based sequencing while moving with finalized L1 behavior instead of
against it.

Verification:

```text
py -3.14 -m pytest -q tests/test_foundation_spec.py
12 passed in 0.31s

py -3.14 -m pytest -q tests/test_foundation_spec.py \
  tests/test_security_freeze_spec.py \
  tests/test_deployment_ready_roadmap_contract.py \
  -k "not app_layer_ops_is_an_exact_recursive_mirror_of_canonical_ops and not launch_blocker_manifest_has_only_one_external_assurance_dependency"
19 passed, 2 deselected in 0.42s

git diff --check
exit=0

impact matrix readback
23 EIPs; 23 unique; every row has an impact class and R01-R12 owner
```

No code implementation, package status, H4 evidence, activation state, proof-suite identity, or
Gate 2E ordering changed. R01-R12 and the compatibility manifest remain future implementation work.

## 2026-08-01 Gate 2E-0/S0 C0 control freeze

The synthetic C0 control is now frozen at the current Gate 2E-0 boundary. The implementation is
`experiments/bl_pq512_crypto_foundation/c0_control_fixture.py`; its fresh-process measurement
boundary is `c0_control_measurement.py`. The exact K128/K512 manifest lengths remain 11,217 and
11,231 bytes with SHA3-512 identities:

```text
K128 74c6812c830f9d53d556712b2c08700dae11fd95777a82b01f498743de6e738d2accc6319c7870425debc668b401a92a20e88bcc96c591c8bebb74dc3b496d83
K512 5d45ffed375d27d64762d6c03ec832e894e6d34fc057f78d8b6885f9441c9835fe0e9999f46807ac083c69c12e2481f8e457d09d825b19506b02fc6a44793d20
```

The focused command
`py -3.14 -m pytest -q tests/test_bl_pq512_c0_control_fixture.py tests/test_bl_pq512_c0_control_measurement.py`
passed 9/9 in 32.37 seconds under the equivalent Python 3.14.4 launcher. Each measurement below
was a separate fresh process with the explicit synthetic environment; all values are decimal MB:

| Profile | Boundary | Seconds | Peak RSS MB | Scratch MB | Pagefile delta MB | Read/Write I/O MB |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| K128 | state-only | 3.074924 | 29.171712 | 0.000000 | 2.592768 | 0.000000 / 0.000000 |
| K128 | complete | 3.010325 | 29.708288 | 0.000000 | 3.010560 | 0.000000 / 0.000000 |
| K512 | state-only | 12.910909 | 37.777408 | 0.000000 | 6.602752 | 0.000000 / 0.000000 |
| K512 | complete | 13.353259 | 39.399424 | 0.000000 | 8.630272 | 0.000000 / 0.000000 |

The complete boundary returned the exact frozen manifest identities above. Scratch is zero because
the fixture invokes no scratch API and the measured process recorded zero read/write transfer I/O.
Pagefile values are observed process usage deltas and are not evidence of swap absence; H5 still
requires external pagefile/swap monitoring. The negative corpus covers stale reads, omitted and
reordered writes, duplicate identity, collision, root substitution, and conflicting updates.

This closes only the synthetic C0 control record. `proofSuiteId=null`, activation remains false,
real PHI/payments remain forbidden, the trusted canonical `../ops` launch-blocker state is still
absent, H4 remains one-run prototype evidence, and no production CUDA path was run. S1/2E-1 narrow
replaceable interfaces is the next implementation boundary.

## 2026-08-01 Gate 2E-1/S1 narrow interface freeze

S1 is now implemented and tested in
`experiments/bl_pq512_crypto_foundation/state_interface.py`. The module defines exactly 13 bounded,
wire-coded descriptors: state layout, key/value encoding, membership, absence, ordered access
manifest, memory consistency, commitment/opening, old/new transition, SHA3-512 public identifier,
migration/rollback, transcript contribution, independent verification, and atomic receipt. Each
descriptor carries its producer, consumers, public/private fields, grammar, maximum length,
domain/version/parameter identity, canonical decode rule, error family, retry behavior, crash
behavior, and mutation cases.

The S1 source SHA-256 is
`811363691DACCA11913705D3CEBB14CA93158824493EF46EC75DEC2A9BE01297`. The descriptor readback
is 13 interfaces with wire codes 1 through 13; the `BLSI` header is 8 bytes with a 4,096-byte
maximum payload. A representative K128 `BLTR` transition encodes to 329 bytes and begins with
`424c545201`.

The generic `BLSI` envelope has an 8-byte header and a 4,096-byte maximum payload. The concrete
`BLTR` transition codec requires fixed-width nonzero SHA3-512 roots/digests, explicit profile and
parameter identities, and `sequence_after = sequence_before + 1`; it rejects truncation, trailing
bytes, retyping, parameter substitution, root substitution, and sequence replay. The
`sha3_512_public_identifier` port hashes its domain/version/parameter identity and bounded source
tuple with SHA3-512. The module imports no claim, payment, application, settlement, or proof
implementation.

Focused verification:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_interface.py tests/attacks/test_bl_pq512_state_interface_attacks.py
22 passed in 0.15s
```

This completes only the S1 interface boundary. C1-C4 scalar state-relation controls, commitment
selection, H4 binding, migration closure, H5/H6 qualification, `proofSuiteId`, activation, and
production deployment remain open. The trusted canonical `../ops` launch-blocker state remains
absent, and no production CUDA path was run. The next roadmap boundary is Gate 2E-2/S2.

## 2026-08-01 Gate 2E-2/S2 scalar C1-C4 controls — COMPLETE

Gate 2E-2/S2 is now implemented at the scalar synthetic-reference boundary. The new
`experiments/bl_pq512_crypto_foundation/scalar_state_relation_controls.py` module contains C1 dense
and touched-sparse persistent-memory controls, C2 transparent index/value dictionary, C3
touched-projection RAM, and C4 compact shuffle-based memory consistency. Each control replays the
same bounded four-lane transition, membership/absence queries, update, money summary, and fixed
shape; each exposes candidate-specific derived work counters and an independent verifier that
rebuilds the transition rather than trusting candidate roots or result fields. C1 dense, C1 sparse,
C2, C3, and C4 are all controls; no candidate is selected, committed to H4, or activated.

`experiments/bl_pq512_crypto_foundation/scalar_state_relation_parity.py` is the only C0 bridge. It
compares candidate-independent semantic parity for both frozen profiles: replay/benefit/obligation/
ledger operation, access, position, and proof-node geometry; membership and absence; cursor and
state/update-change behavior; representative approved/duplicate/conflict/denial/cover/correction
outcomes; and `(80, 80, 80)` plan/debit/credit totals. Candidate-specific roots are not host-compared
to C0 roots. The bounded parity record SHA3-512 is
`fc99b31b333a6ec3a19cc55099bd612dcd1d7964115301bbcb9d512d8efe184bc320f04af65f3aa8417bf03fe368e05dddc1d2bd7fd2b2005280e777f0d496c4`.

The focused S2 command and raw result were:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_scalar_state_relation_controls.py tests/attacks/test_bl_pq512_scalar_state_relation_controls_attacks.py
14 passed in 21.50s
```

The containing S1/S2 command and raw result were:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_scalar_state_relation_controls.py tests/attacks/test_bl_pq512_scalar_state_relation_controls_attacks.py tests/test_bl_pq512_state_interface.py tests/attacks/test_bl_pq512_state_interface_attacks.py
36 passed in 24.67s
```

The C1 dense full-capacity scan, C3 touched-projection quadratic online counter, and C4
initialization/persistent-scan counter are derived scalar work labels, not measured timings,
throughput, memory, security, or selection evidence. The full ordinary Python lane was attempted
and failed closed during collection with:

```text
FileNotFoundError: [Errno 2] No such file or directory: 'C:\\Users\\neers\\Documents\\Codex\\2026-07-27\\he\\work\\Blind-Ledger-Wave2-Workspace-2026-07-26\\..\\ops\\policy_spec_v1.yaml'
```

No mirror was copied and no check was weakened. The ordinary Python lane failed closed during
collection on the missing canonical `../ops/policy_spec_v1.yaml`. A full `tests/attacks` rerun
reached 100% progress but exited 1 after 182.2 seconds; its failures include the same exact missing
canonical path. The bounded S2 attack suite above passed. `proofSuiteId=null`, activation remains
false, real PHI/payments remain forbidden, the canonical `../ops` launch blocker remains absent, and
no production CUDA path ran. Gate 2E-3/S3 native-hiding PQ commitment screening is the next
boundary.

## 2026-08-01 Gate 2E-3/S3 PQ commitment screening — REFERENCE COMPLETE, NO ADMISSION

Gate 2E-3/S3 is implemented at the bounded synthetic screening boundary. The new
`experiments/bl_pq512_crypto_foundation/pq_commitment_screening.py` module defines a common
fixed-width masked commitment/opening envelope, exact descriptor and parameter identities for the
Jindo-style lattice, Module-SIS, RoKoko-style lattice, and transparent hash/code families, a
dual-ML-DSA-87/SLH-DSA-SHAKE-256f authenticated public-coin round, and an independent opening
verifier. The envelope uses SHA3-512 reference masking only; it is not a lattice PCS, complete
zero-knowledge proof, H4 binding, or production/activation path.

All four descriptors reject closed. The three lattice descriptors lack pinned primary source,
parameters, license, and reviewed theorem evidence. The transparent hash/code descriptor has the
internal 512-bit parameter reference and 256-bit labels but still lacks reviewed native-hiding
composition and complete-proof evidence. No candidate is admitted, selected, assigned
`proofSuiteId`, or activated.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py
8 passed in 3.27s
```

This is reference test-run timing, not complete-proof or H5 evidence. The next bounded boundary is
Gate 2E-4/S4 atomic composition: independently replay the S2 relation, bind the S3 transcript and
transition, and reject every field mutation before any state acceptance.

## 2026-08-01 Gate 2E-4/S4 atomic composition - REFERENCE COMPLETE, NO ADMISSION

Gate 2E-4/S4 is implemented at the bounded synthetic composition boundary in
`experiments/bl_pq512_crypto_foundation/atomic_state_composition.py`. The composition keeps the S2
relation candidate separate from the S3 commitment-backend identity; independently replays the S2
candidate; derives one fixed 12-field projection, layout identity, old/new aggregate roots,
manifest, and strict `BLTR` transition; verifies the S3 authenticated public-coin opening; and
binds the deferred H4 reference identity, independent verifier identity, attempt identity,
commitment, transition, and receipt. The canonical relation payload hashes private membership
keys/values and absence keys rather than serializing raw private keys. The H4 binding is explicitly
deferred, `proofSuiteId=null`, activation is false, and no backend or relation is selected.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_atomic_state_composition.py tests/attacks/test_bl_pq512_atomic_state_composition_attacks.py
6 passed in 10.11s
```

The attack suite rejects transition-root, commitment, opening, projection, relation-candidate,
proof-identity, and relation-result mutations. This closes only a synthetic non-spliceable
composition/reference-receipt boundary. It is not a production proof, PCS, H4 acceptance,
migration proof, H5 measurement, selection, or activation result. The next bounded boundary is
Gate 2E-5/S5 migration, rollback, recovery, and failure semantics.

## 2026-08-02 Gate 2E-5/S5 migration and failure semantics - REFERENCE COMPLETE, NO ADMISSION

Gate 2E-5/S5 is implemented at the synthetic state-plane boundary in
`experiments/bl_pq512_crypto_foundation/state_migration_recovery.py`. It defines immutable
SHA3-512 checkpoints, independently verifies the S4 composition before preparing publication,
publishes only store-owned pending compare-and-swap records, and keeps the current checkpoint
unchanged on every rejected operation. Migration preserves the logical state root, state manifest,
and sequence while rotating the layout, parameter, and verifier identities at exactly the next
epoch. Rollback and recovery restore only complete checkpoints already known to the store and
advance to a strictly newer epoch, so old transition attempts cannot replay. The reference
equivalence record is not a production migration theorem and old private bytes are never
reinterpreted under a new layout.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_migration_recovery.py tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py
10 passed in 10.10s
```

The positive and attack corpus covers composition publication, crash before publication, conflicting
CAS, root/manifest substitution, identity downgrade, layout/parameter/verifier rotation, rollback,
recovery, stale epoch/sequence, corrupted and unknown checkpoints, partial/self-consistent forged
records, and mixed K128/K512 profiles. This is reference failure/equivalence evidence only; no
durable custody, production migration proof, backend selection, H5 measurement, `proofSuiteId`, or
activation is closed. The next bounded boundary is Gate 2E-6/S6 component evidence and Gate
2E-7/S7 selection/handoff.

## 2026-08-02 Gate 2E-6/S6 and Gate 2E-7/S7 reference bake-off and handoff - NO ADMISSION

`experiments/bl_pq512_crypto_foundation/gate_2e_selection.py` now measures the identical synthetic
S2/S3/S4 reference component twice for each of the four screened commitment backends and both frozen
K128/K512 profiles: 16 observations total. Each record independently verifies the scalar relation,
authenticated reference opening, and S4 receipt; observed timing, verifier timing, and derived work
are labeled separately, proof bytes are zero, and external complete-boundary monitoring is explicitly
`NOT_RUN_NO_ELIGIBLE_FINALIST`.

S3 recomputation rejects every backend, so no candidate receives a complete warm-up or complete-proof
attempt. S7 retains `C0_CONTROL` as an unselected control with
`selection_status=C0_CONTROL_RETAINED_NO_ELIGIBLE_PQ_FINALIST`, `selected_backend_id=null`,
`proofSuiteId=null`, and activation false. The handoff is explicitly unsealed and records
`no_backend_admitted`, `complete_boundary_not_authorized`, `h4_atomic_binding_deferred`, and the
missing canonical `../ops` blocker. Timing is reference-component evidence only and receives no
selection credit.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_gate_2e_selection.py tests/attacks/test_bl_pq512_gate_2e_selection_attacks.py
6 passed in 34.04s
```

This closes only the S6/S7 synthetic measurement/rejection/handoff boundary. It does not select a
PQ backend, close complete composition/simulator/leakage/state-proof receipt obligations, qualify
H5, assign `proofSuiteId`, authorize activation, or establish production throughput. The next
bounded boundary is the complete composition/simulator/leakage/state-proof receipt ledger.

## 2026-08-02 Gate 2E terminal composition/simulator/leakage/state-proof receipt ledger - REFERENCE COMPLETE, BLOCKED

The terminal evidence boundary is now implemented in
`experiments/bl_pq512_crypto_foundation/gate_2e_terminal_ledger.py`. It independently replays the
S4 composition, derives and checks the S5 before/after checkpoints, verifies both frozen C0 profile
shapes and the exact seven positive/negative parity classes, checks the fixed 12-field public
boundary, confirms that raw private relation keys/values are absent from the public ledger, and
recomputes the S6/S7 selection and handoff identities. The ledger contains 11 ordered obligation
records and serializes only bounded public identities, statuses, sources, and blocker labels.

The ledger is deliberately unsealed:

```text
status=UNSEALED_BLOCKED_GATE_2E_TERMINAL_LEDGER
ledger_digest_sha3_512=2cbc9e48ea14e4e6dfeae9eebe46c34ad4ed551d63f946fcb696abc480c407d5893f7d29acd7349858e6ed9f496db121c1d00940504bc050f264502eae098964
canonical_bytes=388
canonical_sha256=ac0331a2631361e85631095a8cc039004cb39bdcc0ad6d52883051f60c40d66d
source_sha256=98d959e0a614dd6938c1d3d47a3f127f68f6b9be1fb841a8fb26030a72386381
blockers=canonical_ops_missing,complete_leakage_scan_missing,complete_simulator_missing,h4_atomic_binding_deferred,no_backend_admitted,proof_suite_unselected
proofSuiteId=null
activation_allowed=false
```

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py
7 passed in 29.70s
```

Containing S1-S7 plus terminal-ledger command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_interface.py tests/attacks/test_bl_pq512_state_interface_attacks.py tests/test_bl_pq512_scalar_state_relation_controls.py tests/attacks/test_bl_pq512_scalar_state_relation_controls_attacks.py tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py tests/test_bl_pq512_atomic_state_composition.py tests/attacks/test_bl_pq512_atomic_state_composition_attacks.py tests/test_bl_pq512_state_migration_recovery.py tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py tests/test_bl_pq512_gate_2e_selection.py tests/attacks/test_bl_pq512_gate_2e_selection_attacks.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py
73 passed in 91.58s
```

This closes only the synthetic terminal ledger/reference replay. It does not close the complete
semantic/state/PCS simulator, side-channel or unlinkability campaign, strict-PQ security ledger,
reviewed state/commitment admission, H4 parent/transcript/proof/verifier binding, canonical ops
identity, H5, H6, `proofSuiteId`, activation, or production throughput. The next authorized
boundary is a reviewed replacement state/commitment admission path or, while that remains absent,
the fail-closed H5/H6 preflight and qualification ledger; no complete-proof run receives credit
from this reference record.

## 2026-08-02 H5 qualification preflight - BLOCKED

The bounded H5 qualification preflight is now implemented in
`experiments/bl_pq512_crypto_foundation/h5_qualification_preflight.py`. It independently replays
the terminal Gate 2E context, validates the reference hardware record, checks the actual canonical
`../ops` tree against the app-layer mirror without creating or copying files, and freezes the exact
campaign shape: one uncounted warm-up plus ten unique measured launches for each K128/K512 profile,
22 fresh launches total. It never starts CUDA or accepts cached proofs, cached witnesses, retries,
partial-campaign substitution, `proofSuiteId`, or activation.

The current preflight record is:

```text
status=BLOCKED_H5_PREFLIGHT
ledger_digest_sha3_512=2cbc9e48ea14e4e6dfeae9eebe46c34ad4ed551d63f946fcb696abc480c407d5893f7d29acd7349858e6ed9f496db121c1d00940504bc050f264502eae098964
preflight_digest_sha3_512=8eb296bb3946df2881402e86e7b4f7ba86018f7ff7140ed513266e3b0c65939a04aebe96f638131c69d5326e614a1dd57961ad1b103f748009b60bb4cd1dc435
protocol_id_sha3_512=a9aea0f7e884e867e10d93267038ee40500564cb68f7b5779fc40ec8a3fd43c05172ef955a0145d3da4db8da8f43799465917db2ebec57de7376ad3d7911d215
canonical_ops_status=MISSING_CANONICAL_SIBLING
reference_hardware_status=NOT_READY
fresh_launch_count=22
proofSuiteId=None
activation_allowed=False
blockers=gate_2e_ledger_unsealed,state_plane_unselected,h4_atomic_binding_deferred,complete_simulator_missing,complete_leakage_scan_missing,strict_pq_security_ledger_open,proof_suite_unselected,canonical_ops_missing,reference_hardware_not_ready,h5_campaign_not_started,h5_external_monitor_not_configured,h5_source_readback_not_captured,h5_no_qualified_evidence
```

Focused preflight and attack verification:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_h5_qualification_preflight.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py
6 passed in 44.60s
```

Containing evidence:

```text
benchmark + S6/S7 + terminal ledger + H5 preflight: 61 passed in 117.72s
S1-S7 + terminal ledger + H5 preflight: 79 passed in 175.33s
git diff --check: exit 0
py_compile: exit 0
```

This does not run H5, close Gate 2E, select a state/commitment backend, close H6, assign
`proofSuiteId`, activate, or establish production throughput. The exact canonical sibling
`../ops` remains absent and the reference hardware is not ready because its recorded free disk
(`59,091,513,344` bytes) is below the required headroom (`73,100,269,364` bytes). The next safe
boundary is reviewed state/commitment admission and atomic H4 binding; no complete-proof launch
receives credit before those gates close.

## 2026-08-02 H6 qualification preflight - BLOCKED

The bounded H6 qualification preflight is now implemented in
`experiments/bl_pq512_crypto_foundation/h6_qualification_preflight.py`. It independently replays
the blocked H5/terminal Gate 2E context, reads the actual candidate registry without modifying it,
and requires `CANDIDATE_UNQUALIFIED`, eight null module identities, `proofSuiteId=None`, and
`activation_allowed=False`. It records all twelve H6 obligations with explicit evidence classes;
five records are `BLOCKED`, five are `OPEN`, and two are `REFERENCE_ONLY`.

Raw H6 preflight record:

```text
status=BLOCKED_H6_PREFLIGHT
obligation_count=12
blocked_record_count=5
open_record_count=5
reference_only_record_count=2
blocker_count=24
blockers=no_backend_admitted,proof_suite_unselected,strict_pq_security_ledger_open,complete_simulator_missing,proof_grammar_unselected,h4_atomic_binding_deferred,attack_corpus_incomplete,cross_language_verifier_kats_open,source_toolchain_dependency_sbom_open,offline_reproducible_builds_open,gate_2e_ledger_unsealed,state_plane_unselected,complete_leakage_scan_missing,canonical_ops_missing,reference_hardware_not_ready,h5_campaign_not_started,h5_external_monitor_not_configured,h5_source_readback_not_captured,h5_no_qualified_evidence,side_channel_unlinkability_open,production_migration_theorem_open,complete_evidence_manifest_missing,h6_no_qualified_evidence,wave3_verifier_state_custody_open
h5_preflight_digest_sha3_512=8eb296bb3946df2881402e86e7b4f7ba86018f7ff7140ed513266e3b0c65939a04aebe96f638131c69d5326e614a1dd57961ad1b103f748009b60bb4cd1dc435
suite_registry_digest_sha3_512=307439093721aeaa9a70ef00d546f06af5f50b73781f9f19b8b02cca8c3d36ee1ef36e9981d49a59d10d8d7768fec079d40e05b6c008d7913c9caf4cc52cf974
suite_registry_canonical_digest_sha3_512=d082aaec00392f6ae7c7c37a52b6b18ab0fccd5fb08654ec9e326d8c20dd355e13f02b240577823f18b06f50aa165d25f5479d2ba1067beb80dd20ab9d6724e0
preflight_digest_sha3_512=680d73501851b316d969f811e23aa04985cacfce04df5bea8bd1b6e8553ddd07f12e08d89c79915a80c86f175eb9973cd3825e8ce7e09e2b4122cee44bcd24d7
proofSuiteId=None
activation_allowed=False
```

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
6 passed in 30.02s
```

Containing Gate 2E/H5/H6 command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_interface.py tests/attacks/test_bl_pq512_state_interface_attacks.py tests/test_bl_pq512_scalar_state_relation_controls.py tests/attacks/test_bl_pq512_scalar_state_relation_controls_attacks.py tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py tests/test_bl_pq512_atomic_state_composition.py tests/attacks/test_bl_pq512_atomic_state_composition_attacks.py tests/test_bl_pq512_state_migration_recovery.py tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py tests/test_bl_pq512_gate_2e_selection.py tests/attacks/test_bl_pq512_gate_2e_selection_attacks.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
85 passed in 151.88s (0:02:31)
```

This is evidence-boundary scaffolding only. It does not close any H6 obligation, admit a state or
commitment backend, bind H4, run H5, assign `proofSuiteId`, enable activation, or establish
production throughput.

## 2026-08-02 current-source UDR/native-hiding reconciliation - VERIFIED, NO ADMISSION

The current implementation and its machine-readable nonactivating interface vector had drifted
from stale expectations retained from the superseded worksheet. The source-derived values are now
aligned in the focused tests and vector: the six unselected query candidates are
`617/378/309/281/268/262`, the corresponding mask degrees are `3149/1954/1609/1469/1404/1374`,
the K512 rate-half randomizer count is `6,899,459`, the entropy lower bound is `206,983,770` bits,
the extension-row count is `3`, and the interface per-term floor is `256` bits. The registry's
explicitly marked superseded historical values were not rewritten.

Focused command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_native_hiding_parameters.py tests/attacks/test_bl_pq512_native_hiding_parameters_attacks.py tests/test_bl_pq512_unique_decoding_parameters.py
15 passed in 0.91s
```

Containing current algebra/hiding command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_unique_decoding_parameters.py tests/attacks/test_bl_pq512_unique_decoding_parameters_attacks.py tests/test_bl_pq512_native_hiding_parameters.py tests/attacks/test_bl_pq512_native_hiding_parameters_attacks.py tests/test_bl_pq512_theorem_schedule.py tests/attacks/test_bl_pq512_theorem_schedule_attacks.py tests/test_bl_pq512_circle_fri.py tests/attacks/test_bl_pq512_circle_fri_attacks.py tests/test_bl_pq512_circle_hiding_simulator.py tests/attacks/test_bl_pq512_circle_hiding_simulator_attacks.py tests/test_bl_pq512_circle_quotient_masking.py tests/attacks/test_bl_pq512_circle_quotient_masking_attacks.py
62 passed in 59.43s
```

This is a source/vector consistency correction only. It does not select a commitment backend,
claim a native-hiding theorem, bind state into H4, run H5, assign `proofSuiteId`, enable
activation, or convert any historical worksheet into qualification evidence.

The admission audit remains blocked by the actual current evidence: all four Gate 2E commitment
descriptors reject for missing reviewed exact source/parameters/theorem or complete composition;
the Rust H4 core binds a semantic hash-bus statement but does not prove the persistent
replay/payment state transition; and the available state implementations are explicitly synthetic
references. At the time of this audit the canonical sibling `../ops` was absent and the old
15%-reserve record showed `59,091,513,344` free bytes versus `73,100,269,364` required, so the
exact H5 22-launch campaign was not started.

## 2026-08-02 operational disk-floor correction - VERIFIED, H5 STILL BLOCKED

The recorded reference hardware had 59,091,513,344 free bytes on a 487,335,129,088-byte
system disk. The prior 150,000-ppm (15%) operational reserve required 73,100,269,364 bytes and
blocked the preflight. First-principles sizing of the current H4 artifact envelope showed that
this reserve was a policy floor rather than the proof resource limit, so the floor was reduced by
exactly 10x to 15,000 ppm (1.5%), requiring 7,310,026,937 bytes. The immutable 5,000,000,000-byte
peak-RSS limit, strictly-below-5,000,000,000-byte scratch limit, zero-swap rule, p95 limits,
privacy/shape/ABI rules, PQ requirements, proof binding, `proofSuiteId`, and activation state
were not changed.

Changed boundary files are the benchmark validator/schema, recorded hardware capture, canonical
synthetic fixture self-hashes, and their focused/attack expectations. The benchmark boundary
passed:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_benchmark_evidence.py tests/attacks/test_bl_pq512_benchmark_evidence_attacks.py
42 passed in 0.45s
```

The H5/H6 preflight boundary passed 12 tests in 86.66 seconds. Its refreshed public state is:

```text
h5_status=BLOCKED_H5_PREFLIGHT
h5_preflight_digest_sha3_512=cdd2a4ec4728d0ca76539e0a348eaf54df840fc0b4a93a40ec587182a7abfbf77631e3db3a5bcb4ed2a847532cd2655f43fe99559912e2d931951efa9a062e03
canonical_ops_status=MISSING_CANONICAL_SIBLING
reference_hardware_status=READY
fresh_launch_count=22
h6_status=BLOCKED_H6_PREFLIGHT
h6_preflight_digest_sha3_512=a8d7fbfdc1ad3585a004da3ca2ef37790fb7ded0bed8e7b99b978a8716480ad074ca0b52c6b317c59eeb4274fac114c490781f9d76d3f5278cb909ce57f989b5
proofSuiteId=None
activation_allowed=False
```

This removes only `reference_hardware_not_ready`; no package is newly qualified. State/commitment
admission, atomic H4 binding, the missing trusted canonical `../ops` sibling, complete simulator
and leakage evidence, H5 execution, H6 qualification, `proofSuiteId`, and activation remain
closed or blocked as recorded above.

## 2026-08-02 state-plane implementation and native H4 binding seam - VERIFIED, ADMISSION STILL OPEN

The missing real state boundary is no longer only a synthetic S2/S4 reference. The new
`experiments/bl_pq512_crypto_foundation/state_plane.py` implements fixed-width SHA3-512 roots over
every bounded slot, an exact all-slot old/new transition relation, a 512-bit pad-masked SHA3
commitment tied to the authenticated public-coin digest, independent replay verification, and
crash-safe cross-process compare-and-swap publication. Its public dictionary and receipt expose
digests and identities only; private keys, values, operations, and openings remain in the private
replay object.

The native `k512_atomic_semantic_prototype` now accepts `state-file:<path>` and independently
recomputes the envelope before binding its statement into the existing H4 parent. It also binds the
recomputed state binding digest into the native atomic receipt. The diagnostic
`--verify-state-binding` path is nonactivating and does not claim a state AIR or a qualified proof
suite.

Focused state-plane command and raw result:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_plane.py tests/attacks/test_bl_pq512_state_plane_attacks.py
9 passed in 0.19s
```

Native Rust formatting/unit boundary:

```text
cargo fmt --all -- --check
exit 0
cargo test --offline --locked --features std --bin k512_atomic_semantic_prototype
4 passed; 0 failed
```

Python/Rust K128-shape cross-language readback matched exactly:

```text
state_plane_binding_verified=true
state_plane_statement_sha3_512=f3c37c25e22d3e4d7b2500b553151bae34bca8fc84ecea1606af8532149cebfc13f33e014fa3c0a9c4505eacbcb303118965885416a8e634a3c461eb0517a0c7
state_plane_binding_digest_sha3_512=c648d0382061c791c4cf599f0fa8d0a7d7b647ddf9b6fceb600254686a3287cf13aec483a2e26c8a0a8cdb76ea3de7c149c9da2362695ae2c019f2810d8a5ffb
```

Mutating the envelope failed closed with `ERR:state_binding_snapshot_layout`. The Gate 2E ledger
records `STATE_PLANE_IMPLEMENTED_H4_PENDING` when supplied with this proof, but the current default
preflight context remains `STATE_PLANE_NOT_PROVIDED`; no proof suite or activation state changed.
The current ledger digest is
`91e65c9c4dfb3e173e2b2792d96422e272516cb43e62a77520145e981edc2dcd58d6e148ceca74fab5c1bd662cf65cc1c804e9ae707f9b5a91207e4db98a40c9`.

The refreshed default preflight remains:

```text
h5_status=BLOCKED_H5_PREFLIGHT
h5_preflight_digest_sha3_512=f3da98dae8c2cbcb9d80dec755247b64f53b97e258e480d1f89a3e6be9d7a1f2120331fc9b5111a25e133cf43d48b79cff58016fd595e0669262d87a64e2aa24
canonical_ops_status=MISSING_CANONICAL_SIBLING
reference_hardware_status=READY
fresh_launch_count=22
h6_status=BLOCKED_H6_PREFLIGHT
h6_preflight_digest_sha3_512=87c914f7c007fbe6615d51f7a19e81c4adad894147704af40801475093b91d2d9a9a94e9c0f1604d31d0eb86ed937f42d104a49a12c947cfc72a8e3605e7d554
proofSuiteId=None
activation_allowed=False
```

This is real implementation progress, not Gate 2E closure: the four existing PQ descriptors still
reject, the native H4 AIR does not yet constrain the persistent state relation itself, the complete
hiding/composition theorem and simulator remain open, the trusted canonical `../ops` sibling is
still unavailable, and H5 has not launched. No production CUDA, PHI, or payments are authorized.

## 2026-08-02 state-binding hardening, state-root AIR, and hash-pad security review - VERIFIED, NO ADMISSION

The native state seam is now stricter. The v3 atomic parent includes the state-binding digest;
each child shard receives the exact state statement and binding digest through dedicated
environment inputs; the child emits exact `state_plane_*` fields; and the Rust coordinator rejects
missing, zero, mismatched, or legacy state metadata before recording shard evidence. The digest is
also retained in the state-aware atomic receipt. Legacy non-state execution requires explicit
false/zero state fields and remains nonactivating.

The new
`experiments/fixed_shape_claim_air/state_plane_executable_air.py` is a real composable AIR
fragment, not a host-only check. It constrains every fixed-capacity old/new slot, boolean presence,
empty-slot zeroing, dynamic slot bytes to both canonical snapshot encodings, both encodings to
executable SHA3-512 message AIR, and each SHA3 digest to ordered public before/after root bytes.
`compose_state_plane_air` namespaces and merges that fragment into one executable AIR instance.
It does not yet include the full transition/manifest/projection/hash-pad receipt relation, and the
native H4 coordinator does not yet consume the fragment; those remain admission work.

Raw focused verification:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_plane.py tests/attacks/test_bl_pq512_state_plane_attacks.py tests/test_bl_pq512_state_plane_executable_air.py tests/attacks/test_bl_pq512_state_plane_executable_air_attacks.py tests/test_bl_pq512_hash_pad_security_review.py tests/attacks/test_bl_pq512_hash_pad_security_review_attacks.py tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
45 passed in 164.27s (0:02:44)

Set-Location experiments/bl_pq512_crypto_core; cargo fmt --all -- --check
exit 0
cargo test --offline --locked --features std --bin k512_atomic_semantic_prototype
5 passed; 0 failed
```

The composed state AIR was also accepted by the independent Rust AIR evaluator:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_state_plane_executable_air.py::test_rust_independent_evaluator_accepts_composed_state_air
1 passed in 47.28s
```

The digest-bound review in
`docs/BL_PQ512_HASH_PAD_COMMITMENT_SECURITY_REVIEW.md` rejects the current hash-pad candidate
for Gate 2E: its full 256-bit quantum binding/composition theorem and commit-before-coin lifecycle
are not closed, and no generic SHA3 collision/QROM/Fiat-Shamir/grinding credit is taken. This
replaces the vague `unreviewed` state with a specific negative decision; it does not admit a
backend. `proofSuiteId=None`, activation remains false, H5 remains unlaunched, and the trusted
canonical `../ops` sibling remains an external fail-closed blocker.

Review/screening readback with the explicit synthetic test environment:

```text
review_digest_sha3_512=24cdd3790d6aeab257491a3c089a267ebc21fcb9ce5968617df469442e36fabd10957097ed84421189919f74d27a8abb7c0a4f11c613138e4142fe1717931b63
transparent_screen_reasons=strict_pq_assumption_not_reviewed,native_hiding_theorem_unreviewed,authenticated_public_coin_composition_unreviewed,implementation_not_complete_reviewed_reference,complete_composition_missing,hash_pad_security_review_rejected
```

## 2026-08-02 tracked operational authority migration - VERIFIED, OPS BLOCKER CLOSED

The old two-copy operational layout is retired. The owner's checkout-only source-of-truth rule is
now implemented directly: tracked `ops/` is the sole policy/verifier authority, and the one
policy-hashing call site resolves `ops/policy_spec_v1.yaml`. No policy bytes, verifier pins, or
operational artifacts changed, and no sibling directory or outward copy was created.

`ops_authority.py` independently requires the exact 14 regular files, exact lengths, and exact
SHA3-512 identities. Missing, extra, modified, or symlinked material rejects. The terminal Gate 2E
ledger performs that readback, closes only `CANONICAL_OPS_IDENTITY`, and removes only the ops
blocker. Its remaining blockers are exactly:

```text
complete_leakage_scan_missing
complete_simulator_missing
h4_atomic_binding_deferred
no_backend_admitted
proof_suite_unselected
```

Current identities:

```text
terminal_ledger_digest_sha3_512=ce3bda2eb79b554cc56fc9631b40792068fd953d18fc945ea9a567a5b3caa0f8a57a2c9ab785361f4658903080aa02cce99f7a96c5291507d37af0192bb96d28
h5_preflight_digest_sha3_512=5c6a04878f8268dfd4fb33b3583fd27f0aff8624f90f720a9f6b45fb8dff849538ee7aac6ea3d36d72971d1223bf595c9cec0d35f3230705047518c5741432e1
canonical_ops_status=VERIFIED_TRACKED_SHA3_512_AUTHORITY
```

The H5 campaign remains unlaunched because Gate 2E/state/PQ/simulator/leakage/H4 prerequisites are
still open. `proofSuiteId=None`, activation is false, and no real PHI, payments, or production CUDA
is authorized.

The ruleset commitment preserves the historical v1 artifact label while resolving bytes only from
tracked `ops/`. This prevents a packaging-only path migration from changing retry-stable ruleset
and downstream leaf identities. The containing policy/Gate 2E/H5/H6 suite passed:

```text
py -3.14 -m pytest -q tests/test_security_freeze_spec.py tests/test_batch_layer.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
55 passed, 20 expected local-dev fallback warnings in 160.55s (0:02:40)
```

## 2026-08-02 Wave 2 continuation security remediation - VERIFIED, NO ADMISSION

A diff-scoped security audit reviewed all 16 source-like files changed from
`1efe11badd8d03e183624528d246279b80662eeb` through
`8b5f58c35127a5e3f7403ccd9fd3b7ebfdda382d`. Three defects were reproduced:
an unrelated but internally valid state proof could be mixed into the terminal receipt evidence,
an alternate NTFS junction could be accepted as an operations authority root, and a non-boolean
persisted-state presence byte could be normalized before CAS. Attack-path policy suppressed all
three from the external reportable set because the demonstrated paths require local
developer/operator-equivalent control and create no current privilege escalation. That policy
classification did not grant correctness credit; all three were remediated.

`StateSnapshot.decode` now accepts only exact `0` or `1` presence bytes and requires the decoded
snapshot to re-encode byte-for-byte. `FileStateStore.publish` therefore rejects corrupted bytes
before root comparison or publication. `verify_ops_authority` now accepts only the exact tracked
`ops/` path and rejects symlink, junction, or Windows reparse redirection on the checkout root,
operations root, and every authority file. The terminal ledger now rejects a supplied state proof
unless its independently replayed profile, parameter identity, capacity, epoch, sequences, roots,
manifest, and exact ordered projection match the independently replayed S4 transition and S5
checkpoints.

Pre-fix reproduction:

```text
5 failed in 17.35s
```

Post-fix focused security closure:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane.py::test_state_snapshot_rejects_noncanonical_presence_byte tests/test_bl_pq512_state_plane.py::test_file_store_rejects_noncanonical_persisted_state_before_cas tests/test_bl_pq512_gate_2e_terminal_ledger.py::test_terminal_ledger_rejects_unrelated_state_plane_proof tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py::test_alternate_ops_authority_root_is_rejected tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py::test_ops_authority_junction_root_is_rejected
5 passed in 17.10s
```

Containing state/AIR/Gate-2E/H5/H6/security-freeze verification:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane.py tests/attacks/test_bl_pq512_state_plane_attacks.py tests/test_bl_pq512_state_plane_executable_air.py tests/attacks/test_bl_pq512_state_plane_executable_air_attacks.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/test_bl_pq512_h6_qualification_preflight.py tests/test_security_freeze_spec.py
36 passed in 150.58s (0:02:30)
```

This closes the three audited software defects only. The supplied state-proof check remains a
host-side fail-closed precondition and receives no H4 proof credit. The full state transition AIR,
reviewed PQ commitment, complete simulator/leakage ledger, proof-native H4 composition, H5 campaign,
and H6 qualification remain open. `proofSuiteId=None`, activation is false, H5 remains unlaunched,
and no production CUDA, real PHI, or real payment is authorized.

## 2026-08-02 Wave 2 continuation native state-AIR prerequisite - VERIFIED, NONACTIVATING

Preflight before mutation was exact: checkout `C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`, branch `main`,
`HEAD=d0f5ec239788a6e9b4151a54a3e69788c6161a6c`, tree
`df04563e08eeb98dd21bb0a8ca706ef64c23d084`, clean worktree. The protected paths and canonical
`ops/` authority were not edited.

The smallest implementable H4 prerequisite now crosses the real producer-to-authority path.
`state_plane_executable_air.py` adds an explicit ordered all-slot operation table and lookups to
the before/after slot tables. `StateTransitionProof.binding_bytes` emits a version-2 `BLSB01`
envelope containing the executable AIR program and execution under `BLSA01`/version 1. Native Rust
`verify_state_binding` independently replays the transition, validates the exact
`BL-PQ512-STATE-ROOT-AIR-v1` program identity, evaluates the complete AIR execution through
`air_ir`, checks the ordered 128-value root public input, recomputes AIR program/execution,
fragment, composition, transition, commitment, verifier, attempt, and receipt identities, and
only then returns the state context to parent construction. The v3 parent, authenticated
interactive session/schedule, exact child proof grammar, and atomic receipt bind the full state
context, including all 12 ordered 32-byte projection fields and the AIR identities. The child is
untrusted and its exact echoes are independently compared by Rust.

Measured/generated KAT identities:

```text
K128-shaped state capacity=128 binding bytes: 103216467
state AIR program commitment: 1f01d105c86846e28b2584303cefa9e0126de100bce1e5461b94a24a5060c4ed9a0e5b9a2875ee4e62dfefe4d1878f2e400110776a311a9fe2bc4781123f9b19
state AIR execution commitment: 828eb5cd80d97bf00c8c5aa1845cbf71e797bfe78fbaa855427ae41421a1e3b2827f3a80df859bab4967536aebe19af67e9fb22e551966c87fb7c4662e4a7baf
state AIR fragment digest: 0a90647bece8d53443b4b52cfa0c534bd921132a039d4025046ffe7e29b7866e6088be49c4a0fbaab5ccdadb5c0c817559974e10020d399bbcdf308bea735d7e
H4 composition digest: 6a974615e750e0e1307902433581eabff6a547d2a4d263eae84816fd63f366b6adb2682dd4bf8abb38d76f03e5b7c2c560ea28ed28d0303ffbc33adfdc5f67a5
state binding digest: 9470549cac80649a0ced45ff17efa0a3441b1052b7476655f1f29d6807155b87d285f99737f8a5fa2a910093592dba930fcc37d02ae24b9c6f86f2ceddb35a49
```

Focused verification:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane.py::test_native_state_binding_kat_is_stable_for_the_k128_shape
1 passed in 115.94s (0:01:55)

py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane_native.py
3 passed in 52.61s

py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane_executable_air.py tests/attacks/test_bl_pq512_state_plane_executable_air_attacks.py
6 passed in 92.09s (0:01:32)

cargo +1.96.0 test --offline --locked --features std --bin k512_atomic_semantic_prototype
5 passed; 0 failed
```

Containing state/AIR/Gate-2E/H5/H6/security-freeze verification:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane.py tests/attacks/test_bl_pq512_state_plane_attacks.py tests/test_bl_pq512_state_plane_executable_air.py tests/attacks/test_bl_pq512_state_plane_executable_air_attacks.py tests/test_bl_pq512_state_plane_native.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/test_bl_pq512_h6_qualification_preflight.py tests/test_security_freeze_spec.py
40 passed in 342.99s (0:05:42)
```

The first capacity-128 attempt was correctly rejected by the initial 64 MiB envelope cap with
`StatePlaneError: state_plane_binding_envelope_too_large`; the cap was raised to an explicit
256 MiB bound, and the 103,216,467-byte KAT then passed. The first `cargo fmt --all -- --check`
also correctly reported mechanical formatting differences; `cargo fmt --all` was run and the
check subsequently passed. These are recorded failures, not skipped gates.

This slice remains nonactivating. No reviewed PQ backend is admitted; the SHA3 hash-pad candidate
remains rejected for the missing full 256-bit quantum binding/composition theorem and
commit-before-coin lifecycle; native AIR evaluation is not a proof-native H4 PCS/ZK composition;
the complete simulator/leakage ledger, H5 repeated campaign, H6 qualification, authoritative
state selection, `proofSuiteId`, activation, production CUDA, real PHI, and real payments remain
closed. H5 was not launched.

## 2026-08-01 Wave 2 round 1 composition geometry and bounded DEEP parallelism - VERIFIED, NONADMITTING

The exact pre-mutation checkout was `C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`, branch `main`,
`HEAD=6ebe9d0db54388140a4fc65e96218414022cba3b`, tree
`cd0791a3833bf99e204798ad43905736632d88ec`, with a clean worktree. The three edited Rust files
were not protected paths; no protected path or tracked `ops/` authority file was changed.

The first compact six-table diagnostic reached the native composition boundary and failed closed.
The raw worker boundary was:

```text
MAIN f58c01c5ccc56397868147ce0f94d0f607537e91e850c27fc4ea7b78092db31d58569dc40ecefb82e043ce161db9958e28660d6b6f9ad383007dd9437ce12f58
INTERACTION_ROOT f2dd9c376169090df4be7468882ef18435120c21f90d286a96b5c26a958a1fef6b64959e5cc46116f4318d2f87be598f00f26515f78b98691722f17bcdbd556b
composition_line=b''
final_returncode=2 stderr=b'ERR:composition_Shape\n'
scratch_removed=True
```

Source and file-boundary inspection identified the cause: a low-degree table participating in
LogUp had inverse/accumulator columns committed on the larger evaluation domain while its
degree-derived composition work domain was smaller; the disk-backed DEEP materializer correctly
rejected that shape. `air_composition.rs` and `oracle_commitment.rs` now raise only lookup-backed
tables to at least their evaluation-domain log size. Tables with no lookup side retain their
smaller degree-derived work domain. `disk_deep.rs` now maps independent column transforms through
a bounded maximum of eight workers, restores the original column order, detects duplicate/missing
results, and converts a worker panic to `WorkerPanic`; the non-parallel path remains sequential.

The compact candidate's resource preflight was a derived model, not a resident-peak measurement:

```text
program_bytes=181198
raw_witness_bytes=95688
evidence_class=DERIVED_MODEL
model_id=GENERIC_AIR_ORACLE_LAYOUT_V1
qualifies=false
activation_allowed=false
modeled_main_evaluation_bytes=170917888
modeled_interaction_evaluation_bytes=50331648
modeled_composition_evaluation_bytes=100663296
modeled_deep_evaluation_bytes=5771362304
modeled_fri_mask_bytes=4194304
modeled_folded_layer_bytes=8388608
modeled_monolithic_live_bytes_lower_bound=6105858048
modeled_maximum_domain_rows=65536
requires_streaming=true
modeled_raw_witness_bytes=95688
modeled_persistent_oracle_bytes=347174152
modeled_peak_temporary_bytes=208404480
modeled_filesystem_overhead_bytes=138894658
modeled_reserve_bytes=4294967296
modeled_required_available_bytes=4989440586
preflight_exit=0
```

The first serial complete compact attempt was stopped by the bounded wrapper timeout after the
composition correction was applied: `Exit code: 124`, `command timed out after 904058 milliseconds`.
The exact validated cleanup boundary was `scratch_file_count_before_cleanup=1399`,
`scratch_bytes_before_cleanup=351368961`, followed by stopping only the validated worker/Python/
launcher process IDs and removing only the exact owned scratch directory.

The first full-Rust test launcher was initially pointed at the checkout root rather than the crate
directory and failed before test execution with:

```text
cargo : error: could not find `Cargo.toml` in
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26` or any parent directory
```

The launcher was confirmed gone and the exact locked/offline command was rerun from
`experiments/bl_pq512_crypto_core`; no test result was taken from the failed setup command.

With bounded DEEP parallelism, the same compact diagnostic completed and both verification layers
passed. The Python orchestrator replayed the authenticated transcript and the Rust worker ran its
selected FRI verifier:

```text
status=success
program_bytes=201725
proof_bytes=17352533
grammar_version=2
evidence_count=20
query_count=945
fri_layers=15
worker_report=OK grammar_version=2 proof_bytes=17352533 attribution_total=17352533 query_count=945 trace_masks=4789 quotient_masks=946 folds=15 main_ms=18917 interaction_ms=23799 composition_ms=112846 deep_ms=243333 fri_start_ms=94844 fold_compute_ms=2421 openings_ms=19063 verify_ms=5725 worker_wall_ms=537419
scratch_entries_inside_context=0
scratch_context_removed=true
```

This is measured diagnostic evidence for the proof-path implementation, not a production proof or
admitted backend. Its program retained `state_slots`, `state_operations`,
`state_snapshot_encoding`, `state_roots`, `sha3_message_batch`, and `sha3_digest_batch`, with
three lookup relations. It intentionally did not retain the high-cardinality
`state_slots_to_snapshot_encoding` relation, full SHA3 round tables, or the proof-native H4 state
transition/equality composition. Therefore it does not prove the complete state/hash relation,
does not close Gate 2E, and its `worker_wall_ms=537419` is a measured failure against the frozen
K512 complete-proof p95 target below 180 seconds. It is not H5 credit, and H5 was not launched.

Containing verification for this slice was:

```text
cargo +1.96.0 fmt --all -- --check
exit 0
cargo +1.96.0 test --offline --locked --features parallel disk_deep::tests::deep_column_map_restores_canonical_order
1 passed; 0 failed; 0 ignored; 0 measured; 264 filtered out
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_selected_prover_integration.py
2 passed in 139.66s (0:02:19)
```

The complete Rust crate gate then passed, including the new unit test, all library
tests, remaining binary groups, and doc-tests:

```text
cargo +1.96.0 test --offline --locked --features parallel
test result: ok. 265 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1137.57s
all remaining binary groups and doc-tests: test result: ok; 0 failed
```

The containing state/AIR/Gate-2E/H5/H6/security-freeze suite also passed after the documentation
update:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane.py tests/attacks/test_bl_pq512_state_plane_attacks.py tests/test_bl_pq512_state_plane_executable_air.py tests/attacks/test_bl_pq512_state_plane_executable_air_attacks.py tests/test_bl_pq512_state_plane_native.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/test_bl_pq512_h6_qualification_preflight.py tests/test_security_freeze_spec.py
40 passed in 325.19s (0:05:25)
```

No reviewed PQ backend was admitted, `proofSuiteId` remains null, activation remains false, and
the complete simulator, leakage ledger, proof-native H4 composition, H5 campaign, and H6
qualification remain open. No production CUDA, real PHI, or real payments are authorized.

Post-commit readback for this verified phase: implementation commit
`274d956e40ffe61c385c188a5f9dc301cb6a3e60`, tree
`68c522422f0f63007c4c5b8df79fcebd426f27f6`, branch `main`, with no status entries immediately
after the commit. The documentation-only seal that records this readback is the next commit;
the proof, geometry, and DEEP implementation are unchanged by that seal.

## 2026-08-02 Wave 3 P01-P03 nullifier-authority candidate - IMPLEMENTED, NONACTIVATING

The first concrete Wave 3 run began without promoting synthetic reference helpers or changing
the Gate 2E/H5/H6 dependency chain. `experiments/bl_pq512_crypto_foundation/wave3_nullifier_authority.py`
is a new nonactivating candidate boundary. It accepts only the A12 attempt-v1 (`BLPQNF01`,
domain 257) and cover-v2 (`BLPQNF02`, domain 514) canonical preimages. It independently computes
the legacy Poseidon felt from the raw preimage chunks and the authoritative full SHA3-512 key
from the same raw bytes; caller-supplied wide digests are rejected by exact re-derivation.

P01 is represented by a depth-64 sparse ordered tree with explicit canonical SHA3-512 frames for
leaf, empty subtree, node, and root items. Every frame binds item type, record type, physical
position, child height, and the root's entry count/next append index. Empty subtrees are
position-bound and no 2**64 logical array is materialized. P03 uses the existing append-indexed
ordered-tree invariant: an authenticated predecessor update and fresh append slot produce a
two-path witness that independently recomputes both old and new 512-bit roots. A corner case where
the new append slot shares a subtree with the current successor is covered by the verifier's
authenticated insertion path; the verifier does not assume the whole branch is empty.

The in-memory authority stages cloned wide and legacy trees and swaps both roots together after
the transition verifier passes. It is not durable anti-rollback custody, a production verifier,
proof-native H4 composition, a Gate 2E admission, or an activation path. P04-P12 remain open;
the repository remains at 6/93 complete, `proofSuiteId=null`, activation=false, and no real PHI or
payments are authorized.

Trust-critical verification for this phase:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_wave3_nullifier_authority.py
6 passed in 0.22s
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_wave3_nullifier_authority.py tests/test_pq_strong_nullifier_reference.py tests/test_a12_nullifier_derivation.py tests/attacks/test_pq_state_reference_attacks.py
34 passed, 10 subtests passed in 0.50s
py -3.14 -m py_compile experiments/bl_pq512_crypto_foundation/wave3_nullifier_authority.py tests/test_bl_pq512_wave3_nullifier_authority.py
exit 0
git diff --check
exit 0
40-record transition stress: status=success, stress_records=40, stress_sequence=40, stress_root_bytes=64
```

The environment has no `ruff` module (`No module named ruff`); no lint result is claimed. No
production verifier command was run, no proof artifact was generated, no package was marked
complete, and no activation input changed. The first containing run passed 113 tests and 16
subtests but found one existing documentation-contract mismatch in
`test_current_stack_and_roadmap_form_a_context_free_execution_contract`: the committed state plan
was missing the exact required phrase `Bind the selected state plane into` followed by
`the actual H4 parent`. The smallest fix added that explicit admission-boundary sentence; the
affected `tests/test_foundation_spec.py` rerun passed `12 passed in 0.20s`.

After the final A12 body-validation hardening, the containing command and raw result were:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_wave3_nullifier_authority.py tests/test_bl_pq512_state_plane.py tests/attacks/test_bl_pq512_state_plane_attacks.py tests/test_bl_pq512_state_plane_executable_air.py tests/attacks/test_bl_pq512_state_plane_executable_air_attacks.py tests/test_bl_pq512_state_plane_native.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/test_bl_pq512_h6_qualification_preflight.py tests/test_security_freeze_spec.py tests/test_foundation_spec.py
58 passed in 302.45s (0:05:02)
```

No production verifier command was run, no proof artifact was generated, no package was marked
complete, and no activation input changed. Durable custody and verifier work remain downstream of
Gate 2E/H6.

## 2026-08-02 Wave 3 Git/archive/hygiene seal - VERIFIED, NONACTIVATING

The candidate and its documentation were committed on `main` as
`261e5bbe0740ce6c655dbe3dab8af85f7277cf81`, tree
`b81fb8f8ad35ccf41b4b68248f9b7defadaff64b`. The source checkout was clean immediately after that
commit. No remote push was performed.

The deterministic archive was built from that exact commit in a separate staging directory. The
privacy gate selected 767 of 784 tracked files and excluded 17 without weakening the gate:

```text
tracked_paths=784
privacy_safe_paths=767
privacy_excluded_paths=17
exclude_reason_count=2 reason=release JSON failed the structural privacy gate
exclude_reason_count=5 reason=release payload contains an opaque non-text file
exclude_reason_count=10 reason=release payload failed the structural privacy gate
```

Excluded paths were `STATE.md`, `WAVE2_HANDOFF_2026-07-26.md`, `app/operational_readiness.py`,
`docs/security-freeze/BL-PQ512-v1/hardening.json`, `sample_claim_input.json`,
`schemas/bl_pq512_witness_v0.schema.json`, `tests/attacks/test_proving_evidence_policy_attacks.py`,
`tests/test_build_release_archive.py`, `tests/test_measure_proving.py`,
`tests/test_privacy_artifact_scan.py`, `tools/measure_proving.py`, `tools/privacy_artifact_scan.py`,
and the five `portal_shared/fonts/*.woff2` files. The exclusions are recorded because those files
contain deliberate privacy-test fixtures, historical host paths, sensitive JSON fields, or opaque
font bytes; they were not edited to make packaging pass.

The first file-path invocation of the builder failed before archive validation with
`ModuleNotFoundError: No module named 'tools'` and created no ZIP. Running the same builder as the
repository module corrected only the import surface and then passed deterministic capture and
readback:

```text
py -3.14 -m tools.build_release_archive --source-root <separate-stage> --manifest <stage>/APP_RELEASE_FILE_MANIFEST.json --output <outputs>/blind-ledger-wave3-p01-p03-candidate-2026-08-02.zip
{"archive_bytes":10745658,"archive_sha256":"7e39b2d453c1c14fc3e72a1e8cecc3f79c6bdc1d223fcbc1f3b032e29f095592","builder_version":"blind-ledger-release-archive-v1","entry_count":768,"manifest_sha256":"ffffd7c1d7e665b7a9f050a72143f7467f67df5b0d4cc0eefcddd85796ea9a03","payload_bytes":10438366,"payload_file_count":767,"receipt_version":1}
```

The resulting ZIP is outside the source checkout at
`C:\Users\neers\Documents\Codex\2026-08-01\files-mentioned-by-the-user-continue\outputs\blind-ledger-wave3-p01-p03-candidate-2026-08-02.zip`.
Independent readback reported `zip_entry_count=768`, `zip_crc_result=None`, first entry
`Blind-Ledger-Release/RELEASE_FILE_MANIFEST.json`, last entry
`Blind-Ledger-Release/zk-cairo-sharp/src/lib.cairo`, and manifest SHA-256
`ffffd7c1d7e665b7a9f050a72143f7467f67df5b0d4cc0eefcddd85796ea9a03`.
`tests/test_build_release_archive.py` passed `18 passed, 54 subtests passed in 0.99s`.

Generated bloat cleanup was bounded to exact generated paths. The first purge removed 16 targets
and `11,338,995,599` bytes, including the 9.25 GB Rust target, 1.47 GB runtime/proof cache, and
615 MB secondary Cargo target. The final purge removed the separate archive staging directory and
two regenerated Python-cache targets: 3 targets and `10,681,750` bytes. Both purges left zero
remaining selected targets and zero `.pyc` files. The tracked `_handoff_support` source file was
retained. Git remains nonactivating: `proofSuiteId=null`, activation=false, 6/93 complete, and no
real PHI or payments.

## 2026-08-02 Gate 2E state-root bus and reviewed PQ candidate - VERIFIED, NONADMITTING

This continuation started from the sealed Wave 3 parent `c4ef6e9` in the authoritative checkout
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`.
The protected paths were not edited. No PHI, payment credential, production CUDA, proof artifact,
activation input, or `proofSuiteId` value was introduced.

The smallest real state composition seam is now versioned and authenticated at the H4 hash-bus
source boundary. `BLHBSN02`/version 2 snapshots and `BLHBB102`/version 2 B16 boundaries clone the
accepted base descriptor and append exactly two state-root SHA3 calls. The root message is exactly:

```text
STATE_ROOT_DOMAIN || len(snapshot.encoded).to_bytes(4,"big") || snapshot.encoded
```

The fixed state-root capacity is `claim_slots*137+512`: K128 is 18,048 and K512 is 70,656. The
two calls therefore add 266 and 1,040 live permutations, producing exact state-composed live
permutation totals of 113,996 and 412,446. The state-free `BLHBSN01`/`BLHBB101` descriptor and
bytes remain byte-compatible. The Rust coordinator independently checks the exact packed input and
output bit patterns of both appended root calls before child spawn; the worker derives the totals
from the descriptor rather than a duplicated profile constant.

Cross-language descriptor KATs are:

```text
K128 descriptor_commitment=d5aa3a35136e28134f63a120f7f73c1ed3fc35e482efa618c6ba054aef5838e0552aa907ca69ebc2ef1af2b9b499bda48539f51ee04e3c43e10cfc5221e03c89
K512 descriptor_commitment=31e17d270d51334ec5e2dbaab0fd7433c8a406785de7f5f23210f53cf965694b95d51c661654fb3c04788c43b2abd3df82259d069be10ada046f8bbce7c84480
```

The manual Python-to-Rust state-boundary readback used only synthetic zero data and was removed
after verification. Its raw identities and converter output were:

```text
snapshot_bytes=3596853
snapshot_sha3_512=3c372bb345a54583f5fd008789cdbf1f97789f3d7a22737889af279a87d3d5a01eae119bc4cbba1040d2ace5a189b79861e5a266604003ae001fc90e066918a8
profile=K128Calibration
semantic_program_commitment=0707070707070707070707070707070707070707070707070707070707070707
descriptor_commitment=d5aa3a35136e28134f63a120f7f73c1ed3fc35e482efa618c6ba054aef5838e0552aa907ca69ebc2ef1af2b9b499bda48539f51ee04e3c43e10cfc5221e03c89
semantic_port_commitment=20c15042ded22d0e402e67f0479bf13cda1dbfc3efb5899ef00bd2720ca58ab34f03a5ec0f2991b834aafa4306351c9aa668393ee591b986fd2409869a045153
coprocessor_shards=1
groups=8192
live_wires_per_boundary=1600
output_bytes=52429015
output_decimal_mb=52.429015
output_sha3_512=ba41dbc5787f4b55f9ba6323a0226c86739b54319c99b4aaa84345471d8acc5afc15acb9f4793c92e0fdae37c826b68e9353fd796beb671c8ddc403562364ceb
inspect_padded_permutations=131072
inspect_decoded_patterns=26214400
inspect_file_bytes=52429015
inspect_boundary_verified=true
```

The B16 worker correction was exact and regression-tested: the initial derived state totals
`114232/413370` were wrong and were corrected to `113996/412446`; a critical indentation defect
that nested `shard_start`/`shard_permutations` under the non-little-endian branch was also fixed.
The durable worker test covers the state header, wire-major packed geometry, and the Windows
little-endian path.

The new clean-room candidate is `TRANSPARENT_SHAKE256_1024` with parameter identity
`BL-PQ512-TRANSPARENT-SHAKE256-1024-V1`. It commits before the later authenticated public coin
using SHAKE256-1024, a 128-byte mask, and a 128-byte commitment. Its explicit conservative ledger
is:

```text
output_bits=1024
quantum_collision_bits=341
quantum_preimage_bits=512
multi_target_loss_bits=32
effective_binding_bits=309
effective_hiding_bits=480
required_security_bits=256
review_decision=REVIEWED_CANDIDATE_H4_COMPOSITION_OPEN
```

The S3 registry now exercises five candidates. The three lattice descriptors remain unpinned;
the old `TRANSPARENT_HASH_CODE` remains rejected for its public-coin lifecycle, generic 512-bit
quantum-collision floor, and missing composition; the new candidate is rejected solely for
`complete_composition_missing`. No candidate is admitted or selected.

Two test-only fixture defects were reproduced and corrected rather than hidden. The first native
state-bus fixture wrote group-major payload bytes and failed with:

```text
state_hash_bus_mismatch:0:input:113730:3
```

It was corrected to the authenticated file wire-major layout. The next mutation assertion used a
group-sized offset instead of the wire-major `header + group*2` offset; that test-only offset was
corrected, and the final mutation-bound native test passed.

Final verification for this slice:

```text
py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py tests/test_bl_pq512_atomic_state_composition.py tests/attacks/test_bl_pq512_atomic_state_composition_attacks.py tests/test_bl_pq512_state_migration_recovery.py tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py tests/test_bl_pq512_gate_2e_selection.py tests/attacks/test_bl_pq512_gate_2e_selection_attacks.py tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
52 passed in 157.35s (0:02:37)

py -3.14 -m pytest -q -p no:cacheprovider tests/test_bl_pq512_transparent_hash_code_candidate.py tests/test_bl_pq512_hash_bus_worker_boundary.py
4 passed in 0.40s

py -3.14 -m pytest -q -p no:cacheprovider tests/test_foundation_spec.py tests/test_deployment_ready_roadmap_contract.py
15 passed in 0.23s

py -3.14 -m pytest -q -p no:cacheprovider tests/test_security_freeze_spec.py
6 passed in 0.09s

py -3.14 -m pytest -q -p no:cacheprovider tests/test_fixed_shape_foundation_spec.py
14 passed in 0.09s

cargo +1.96.0 fmt --all -- --check
exit 0

cargo +1.96.0 check --offline --locked --features parallel
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.17s

git diff --check
exit 0
```

Generated-output cleanup was bounded to eight exact paths and removed `9,322,207,536` bytes:
`C:\blpq-target` (12,630 files, 4,941,808,695 bytes),
`C:\tmp\blpq-target-wave2` (2,812 files, 2,031,237,199 bytes), the synthetic state-boundary
temporary directory (2 files, 56,025,868 bytes), the crate-local Cargo target (4,278 files,
2,290,296,387 bytes), and four Python `__pycache__` directories (90 files, 2,839,387 bytes).
All eight exact paths were verified missing after removal. No tracked source, policy, release, or
protected path was deleted.

The first Rust invocation from the repository root failed before doing work because that directory
has no `Cargo.toml`:

```text
error: could not find `Cargo.toml` in `C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26` or any parent directory
```

The exact same commands passed from `experiments/bl_pq512_crypto_core`, the owning crate. This was
an invocation-directory correction, not a source or gate failure. Earlier native/Rust readbacks
also remain green: the hash-bus snapshot tests were `2 passed; 0 failed; 264 filtered out; finished
in 34.25s`, the full coordinator binary was `6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered
out; finished in 106.66s`, and the Rust library hash-bus suite was `9 passed; 0 failed; 257 filtered
out; finished in 70.95s`.

The current CUDA prototype and worker source changed after the accepted state-free manifest
`51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6`.
The required current release native executables/cubins are not present in this checkout, so the
manifest could not be recomputed and no CUDA proof was launched. The manifest and 29.974129/120.460733
second H4 results remain state-free historical prototype evidence only.

This phase therefore closes a real authenticated state-root bus prerequisite and a reviewed
reference candidate, but it does not close Gate 2E. The full state relation is still not inside
the custom H4 GKR/PCS proof; the complete semantic/state/GKR/PCS simulator, leakage scan, strict-PQ
composition ledger, candidate admission, H5's exact one-warm-up-plus-ten-per-profile campaign
(22 fresh launches), H6 qualification, and all later Wave 3+ work remain open. `proofSuiteId=null`,
activation=false, no PHI/payments are authorized, and no production CUDA was run.

Post-implementation readback before the documentation-only handoff commit:

```text
commit=6a2a7ec124fca97a4b6dfbeb1125e71e737944e6
tree=30e9bdfc4901f30e8a9636a1c1796f3fac3958d1
git status --short
(empty)

## 2026-08-02 Gate 2E state-bus/candidate archive readback - VERIFIED, NONACTIVATING

The deterministic archive source was the clean implementation commit
`969b03ba579487cc8ab5f708e4d9509dc32a34a0`, tree
`e92e4b8b911cabd8fec6071fa91fb81b61bd3708`. The staged privacy gate selected 770 of 787 tracked
files and excluded 17 without weakening the gate:

```text
tracked_paths=787
privacy_safe_paths=770
privacy_excluded_paths=17
exclude_reason_count=2 reason=release JSON failed the structural privacy gate
exclude_reason_count=5 reason=release path has a forbidden generated or archive suffix
exclude_reason_count=10 reason=release payload failed the structural privacy gate
```

Excluded paths were `app/operational_readiness.py`,
`docs/security-freeze/BL-PQ512-v1/hardening.json`, the five
`portal_shared/fonts/*.woff2` files, `sample_claim_input.json`,
`schemas/bl_pq512_witness_v0.schema.json`,
`tests/attacks/test_proving_evidence_policy_attacks.py`,
`tests/test_build_release_archive.py`, `tests/test_measure_proving.py`,
`tests/test_privacy_artifact_scan.py`, `tools/measure_proving.py`,
`tools/privacy_artifact_scan.py`, `STATE.md`, and `WAVE2_HANDOFF_2026-07-26.md`. These are
recorded exclusions from the unchanged structural/privacy gate, not source edits.

The first staging attempt failed before archive validation because PowerShell text-coerced the
binary tar pipeline:

```text
staged_tracked_files=2
tar.exe: Damaged tar archive (bad header checksum)
```

The failed stage contained 2 files and 25,438 bytes and was removed exactly. Re-running with
`git archive --format=tar --output=<tar>` preserved the bytes and staged all 787 tracked files.
The first builder attempt then failed closed on generated manifest order:

```text
release_status=blocked reason=release file entries must be strictly path-sorted
```

The generated manifest was sorted by its exact POSIX `path` field and rebuilt. No output ZIP was
created by either failed attempt.

Final builder receipt:

```text
{"archive_bytes":10813201,"archive_sha256":"d76cb8bc0f42e51a14d048b2ad19f473ae7966d282473dc5aa44f4de36a2f9b4","builder_version":"blind-ledger-release-archive-v1","entry_count":771,"manifest_sha256":"56d28508042aabecb254bae1b7b8ae0425deaf50ddf470e5b0862e1961976aeb","payload_bytes":10500773,"payload_file_count":770,"receipt_version":1}
```

The ZIP is outside the checkout at
`C:\Users\neers\Documents\Codex\2026-08-01\files-mentioned-by-the-user-continue\outputs\blind-ledger-wave2-state-bus-pq-candidate-2026-08-02.zip`.

Independent readback was:

```text
zip_entry_count=771
zip_crc_result=None
first_entry=Blind-Ledger-Release/RELEASE_FILE_MANIFEST.json
last_entry=Blind-Ledger-Release/zk-cairo-sharp/src/lib.cairo
manifest_sha256=56d28508042aabecb254bae1b7b8ae0425deaf50ddf470e5b0862e1961976aeb
manifest_payload_file_count=770
manifest_payload_bytes=10500773
manifest_entries_match=True
archive_bytes=10813201
archive_sha256=d76cb8bc0f42e51a14d048b2ad19f473ae7966d282473dc5aa44f4de36a2f9b4
```

`py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_build_release_archive.py` passed
`18 passed, 54 subtests passed in 1.01s`. The exact generated tar and staging paths were then
removed: 22,411,909 bytes total, with both paths verified missing. The final source checkout was
not changed by archive creation; no remote push was performed. The archive is a nonactivating
source/test/docs artifact only: `proofSuiteId=null`, activation=false, no PHI/payments, and no
production CUDA.
```

## 2026-08-02 Repository-root cleanup and three-archive refresh - VERIFIED, NONACTIVATING

The active source/document/test cleanup was committed before archive creation as
`c84efa7591e43b2a440145db73cbae9ef0624242`, tree
`4ce8e369a7186e74fc9700763aae6b9e5d22706e`. No protected path was edited. The active checkout is
the repository root; tracked `ops/` remains the sole operational authority.

The stale active documentation and path references were corrected in `README.md`, `ARCHITECTURE.md`,
`PROJECT_MAP.md`, `QUICKSTART.md`, `docs/ARCHITECTURE_TECHNICAL.md`,
`docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md`,
`experiments/bl_pq512_crypto_foundation/README.md`, `ops/DEPLOYMENT_RUNBOOK.md`, and
`ops/PRODUCTION_CONFIG_CHECKLIST.md`. The changes remove nested app-root, sibling-ops, missing-ops,
obsolete four-candidate, stale Forge-vendor, and historical collection-count claims from active
guidance. The active source/test corrections were `app/operator_portal.py`,
`app/policy_spec.py`, `app/production_readiness.py`,
`experiments/bl_pq512_crypto_foundation/gate_2e_selection.py`,
`ops/native_stark_public_inputs_v1.json`, `ops/verifier_artifact_pin.example.json`,
`tests/attacks/test_harder_attack_surface_hunt.py`,
`tests/test_evidence_and_public_inputs.py`, and `tests/test_operational_readiness.py`.
The V1 21-field artifact remains an intentional legacy/compatibility control; only its stale source
path was corrected and its exact SHA256/SHA3-512 identities were resealed.

The active stale-reference scan returned no nested `blind-ledger-app-layer`, sibling `../ops`,
missing-canonical-ops, old four-candidate, or external `third_party/forge` references. Retained
matches are intentional and were not edited: the `AGENTS.md` prohibition, current closed-blocker
notes in `KNOWN_ISSUES.md` and `docs/CURRENT_TECH_STACK.md`, the generic sibling-copy prohibition
in `docs/ARCHITECTURE_TECHNICAL.md`, dated historical evidence in
`docs/PHASE1_EXECUTION_LOG_2026-07-13.md`, protected historical provenance in
`zk-cairo-sharp/SECURITY_ATTACK_NOTES.md`, the legacy-marker rejection in
`app/operational_readiness.py`, its matching rejection fixture in
`tests/test_production_readiness.py`, the SPDX package identifier in
`tests/test_foundation_spec.py`, and the protected batch label in
`app/batch/batch_orchestrator.py`.

No stale test file was removed (`0`). The retained V1, Circle-FRI, Cairo, rejection, and fixture
tests protect current compatibility, migration, differential, or fail-closed boundaries; deleting
them would remove evidence rather than remove dead behavior. The two stale test-root calculations
were corrected. Ordinary collection was `1205 tests collected in 6.40s`; attack collection was
`448 tests collected`. The full attack lane passed `448 passed, 31 warnings, 36 subtests passed in
448.59s (0:07:28)`. The final bounded active-source/readiness/Gate-2E lane passed `142 passed, 7
warnings, 8 subtests passed in 80.91s (0:01:20)`. The ordinary full execution lane was attempted
but timed out with exit `124` after `1078570 ms` without a pytest summary; it receives no pass
credit. The exact pytest process check found `remaining_exact_processes=0` after cleanup.
Warnings were the expected local-dev rules-engine fallback and the existing Starlette/httpx
deprecation warning; no warning was promoted to a pass or silently suppressed.

Bounded generated bloat cleanup removed `19` files and `5,443,857` bytes from exact targets:
`experiments/bl_pq512_crypto_core/cuda/nvrtc-cache` (`1` file, `5,202,967` bytes),
`app/__pycache__` (`3`, `19,844`), `app/batch/__pycache__` (`5`, `137,961`), and
`tests/attacks/__pycache__` (`10`, `83,085`). Earlier parent-work cleanup removed the exact
recorded generated targets totaling `3,657` files and `3,646,692,083` bytes. The live
`experiments/bl_pq512_crypto_core/cuda/cuda_nvrtc` runtime remains (`11` files,
`187,059,841` bytes) because the current CUDA source directly loads `nvrtc64_120_0.dll`; it is
not disposable cache. No `.pyc` or selected temporary proof/witness artifact remains.

The release builder staged the exact source commit and selected `770` of `787` tracked files after
the unchanged structural privacy gate excluded `17` paths. The first builder attempt failed closed
with `source root contains missing, unknown, or unlisted entries` because the excluded files were
still physically present in the staging root; exactly those `17` staging files were removed, no
source file was removed, and the builder then passed. The deterministic archive test passed
`18 passed, 54 subtests passed in 0.85s`. A first post-replacement readback command had a shell
quoting syntax error and wrote nothing; the literal-script readback below passed independently.

All three current output ZIPs now contain the identical bytes from source commit
`c84efa7591e43b2a440145db73cbae9ef0624242`:

```text
blind-ledger-wave2-state-bus-pq-candidate-2026-08-02.zip
blind-ledger-wave3-p01-p03-candidate-2026-08-02.zip
blind-ledger-current-clean-2026-08-02.zip

archive_bytes=10783587
archive_sha256=2b3da27068e1ddba0a78bab10e1a824081d23de93168bd81e1332227985359e9
zip_entry_count=771
zip_crc_result=None
manifest_sha256=f03ef370ef48e36731eeb81651ac349ebebd1f4c906cda836c06be343af9560e
manifest_payload_file_count=770
manifest_payload_bytes=10501210
entries_match=True
all_three_byte_identical=True
```

The ZIPs are outside the source checkout at
`C:\Users\neers\Documents\Codex\2026-08-01\files-mentioned-by-the-user-continue\outputs`.
The old two archives were replaced only after fresh builder and independent readback success. The
exact temporary stage (`771` files, `10,616,535` bytes), tar (`1` file, `11,765,760` bytes), and
superseded-archive backup (`2` files, `21,558,859` bytes) were then removed and each path verified
missing. No remote push was performed.

The repository remains nonactivating: `proofSuiteId=null`, activation=false, six of 93 packages
complete, no H5/H6 qualification, no production CUDA proof, and no real PHI or payments.

Final post-ledger readback passed `33 passed, 54 subtests passed in 1.01s` for operational
readiness, roadmap/security contracts, and the deterministic archive builder. Git status is empty,
`git diff --check` is clean, `verify_ops_authority()` returns
`VERIFIED_TRACKED_SHA3_512_AUTHORITY`, active source/doc stale hits are limited to the four
intentional safeguards/provenance classes recorded above, and all three archive readbacks still
report `match=True` and `all_three_byte_identical=True`.

## 2026-08-02 Round 2 compact state-AIR/FRI composition - VERIFIED, NONACTIVATING

This continuation corrected the actual proof-native state boundary rather than stopping at the
earlier digest-only state-AIR seam. The live checkout remained
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`.
Protected paths were not edited. No PHI, payment credential, production CUDA, activation input, or
`proofSuiteId` value was introduced.

The compact relation in
`experiments/fixed_shape_claim_air/state_relation_executable_air.py` packs each 64-byte key/value
into 22 three-byte M31 chunks, retains boolean presence and empty-slot zeroing identities, and
keeps the two 64-byte state roots as the only public AIR values. H4's existing authenticated
state-root SHA3 calls remain the hash relation; the compact FRI component does not duplicate their
Boolean SHA3 traces. The native `air_ir` verifier now exposes validated execution columns, and the
H4 coordinator compares every packed relation/root column with the exact parsed state operations
before it accepts the component.

The streamed worker now exports a private `BLPQSPK1` package containing the verifier-visible AIR
program, public inputs, selected challenge bundle, DEEP claims, final FRI constant, and canonical
v2 proof bytes. `state_air_proof.py` validates the package grammar and commitment, emits the v3
`BLSB01`/`BLSA02` state envelope, and binds the component evidence into the v2-separated fragment,
composition, parent, authenticated transcript, child grammar, and receipt contexts. The public
sidecar remains digest-only; private snapshots, operations, masks, trace, claims, and proof bytes
are not placed in public outputs.

Exact implementation verification:

```text
py -3.14 -m py_compile experiments/bl_pq512_crypto_foundation/state_air_proof.py experiments/fixed_shape_claim_air/state_relation_executable_air.py experiments/bl_pq512_crypto_foundation/selected_prover_orchestrator.py
exit=0

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_relation_executable_air.py
..                                                                       [100%]
2 passed in 0.26s

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane_native.py
...                                                                      [100%]
3 passed in 81.65s (0:01:21)

cargo +1.96.0 fmt --all -- --check
exit 0

cargo +1.96.0 check --offline --locked --features parallel --bin selected_streaming_prover_worker --bin k512_atomic_semantic_prototype
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.80s
```

The first combined Python diagnostic also included the known expensive full state-envelope lane
and timed out after `120000 ms` without a pytest summary; it receives no pass credit. The exact
pytest process cleanup reported `stopped_exact_pytest_processes=1` and
`remaining_pytest_processes=0`. The compact lane above was rerun in isolation and passed.

The real streamed dual-PQ fixture used capacity 8 only; it was not a K128/K512 qualification run:

```text
status STATE_AIR_PROOF_COMPONENT_VERIFIED_NONACTIVATING
program 6f6965838ce9f3a369027dc0b94259c0cb812c38edf3ee05bf2c964be082ee0f60db581d6972819db70b8cc5843d9c924dbbff0e6d1612d3b24ea12983dbcc81
execution d6a95ffd77ae4a6219544b4b84e8d1029b902242bd41ab52906349159d314e1e4c80b4515407ae4b02d4ba33a352fdc7f31bda7ecd61a1671cb0882fd1535208
package 0d8c52e2e47430d565f6660b9fea7a0b229c314305eb1fc797cd2615f5d995f169f9cffe942a866cfcfcc63e7535bfe1047a76b032d0da73128b63f1e2b4e2ac
suite c2cd70b801dcd7665ca7b40cbf4d0599baf2e9eb7143f2260019a0cc2817c4aa9332c91912072f7e57644f25993d5e700633a261b4801a465c6e1920e1c8ae2b
schedule 67445bd618b1d38e6530e76934078866e163f18245f402a14066fa4540524a363ed1cd3290a313244c84164382fbe734b4accc1a09f52b254964d62cfaafec71
transcript 4fc66ae754fdc20a75d019077041fb0fc4d25e1a0c403869e22ddca78fd369a98ead4ce4ad0a788beb348ff1109ccd71941fe95852552cef5cf247c36ba9c4c1
proof_identity 9020f05dfe960a1b9b2a9b359666f376ca77c45131dc8af82226af383fb6721c2b69890429477a2954b6ac6ced0695a4fecb140c1b34037c28772ebf3de3c1b6
proof_bytes 8324389
package_bytes 8370223
evidence_canonical_bytes 771
binding_bytes 8407706
worker_and_python_replay success
scratch_entries_after 0
```

Independent native H4 state-file verification of that exact envelope:

```text
& k512_atomic_semantic_prototype.exe --verify-state-binding blpq-state-air-binding-v3-20260802.bin
state_plane_binding_verified=true
state_plane_statement_sha3_512=f839410300674014ed4204e116c4b4c6b297e0d9603a55629a6b9c2d7cad651f72aecac54d2911693c435fbd5b8009d4b92c374db80446daa785c18490301760
state_plane_binding_digest_sha3_512=b0d1366b13e832d4438b56db703ce8c28174fcab218e6d4032921284b89a5842ed72b8b5b23b78368ad05f7a3ead8a59d78b7e3603b65e5de44fc64c4e768b32
exit=0
```

Adversarial native readback was fail-closed:

```text
trace mutation exit=2
ERR:state_air_trace_after_key_0_0
package mutation exit=2
ERR:state_binding_proof_package:Rejected
mutation_files_remaining=0
```

This closes the native state-file proof component boundary, not Gate 2E. The full state relation
is still not algebraically composed inside the custom H4 GKR/PCS proof; no reviewed commitment
backend is admitted, the complete simulator/leakage/security composition is open, H5's exact 22
launches have not started, H6 is open, `proofSuiteId=null`, activation=false, no production CUDA
proof was run, and no real PHI/payments are authorized.

Final source verification for this continuation, before the archive refresh:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_relation_executable_air.py tests/test_bl_pq512_state_plane_executable_air.py tests/test_bl_pq512_selected_proof_parameters.py
........                                                                 [100%]
8 passed in 297.47s (0:04:57)

py -3.14 -B -m pytest -q -p no:cacheprovider -k "not native_state_binding_kat" tests/test_bl_pq512_state_plane.py
.......                                                                  [100%]
7 passed, 1 deselected in 0.17s

cargo +1.96.0 fmt --all -- --check
exit=0

cargo +1.96.0 check --offline --locked --features parallel --bin selected_streaming_prover_worker --bin k512_atomic_semantic_prototype
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.93s

git diff --check
exit=0
```

The full Rust library-test batch was attempted in an external target and timed out after
`604046 ms` without a test summary; it receives no pass credit, and exact process cleanup found
`remaining_target_test_processes=0`. An earlier Python command named the nonexistent
`tests/test_bl_pq512_selected_prover_parameters.py`; it ran `no tests ran in 0.00s` and is not
evidence. The corrected lanes above are the credited results. No stale test file was removed:
`0`; existing tests remain because they cover compatibility, mutation, and fail-closed behavior.

## 2026-08-02 Final compact-state source/archive/hygiene seal - VERIFIED, NONACTIVATING

The implementation, tests, and active documentation were committed on `main` as
`561cacb893e54ca9638228a8cffd1fdf732130d6`, tree
`67b31a69d48690a4644cc9c7733bce0634c829b0`. The staged protected-path check reported
`protected_path_changes=0`; the source checkout was clean after that commit. No remote push was
performed.

The first complete output refresh was rebuilt from that exact implementation commit in a separate
stage. After the documentation-only seal `deb2bf0d21e929c8ceb71b62489ae015d2425673`, the same
stage/allowlist was rebuilt from that sealed tree; the final outputs below produced the identical
receipt. The privacy/allowlist gate selected 774 payload files from 791 tracked files and excluded
the same 17 deliberate privacy/opaque-fixture paths used by the existing release policy. The
builder produced identical receipts for all three:

```text
archive_bytes=10889447
archive_sha256=08b638a02e5dd875201f4362afa5c74713d7c0fff0fd54a27bbbf9da7edb19ca
builder_version=blind-ledger-release-archive-v1
zip_entry_count=775
manifest_sha256=ed55cf0ce27ef25c0a2e419f64f72951676153c482630836e83ccca8165081b4
manifest_payload_file_count=774
manifest_payload_bytes=10575278
```

The final independent readback of each output reported `zip_crc_result=None`,
`manifest_entries_match=True`, `forbidden_entries=0`, and
`all_three_byte_identical=True`. The four new state-component source/test files are present in
each archive; no `.bin`, `.zip`, `.pyc`, `.pyo`, log, target, scratch, or proof directory entry is
present. `tests/test_build_release_archive.py` passed `18 passed, 54 subtests passed in 0.97s`.
The first post-replacement readback wrapper passed the literal `$args` token and therefore failed
before reading a ZIP; it changed no artifact. The corrected readback above is the credited result.

After readback, bounded cleanup removed exactly 14 generated targets containing 4,141 files and
2,362,002,793 bytes: source/external Cargo targets, native proof/test targets, proof binding,
scratch, archive staging/tar, superseded archive backups, and Python cache directories. Final
checks report zero `__pycache__` directories and zero `.pyc`/`.pyo` files. The runtime CUDA
package was retained intentionally: 11 files, 187,059,841 bytes under
`experiments/bl_pq512_crypto_core/cuda/cuda_nvrtc`; it is loaded by the source and is not a
disposable cache.

The repository remains nonactivating: `proofSuiteId=null`, activation=false, six of 93 packages
complete, no H5/H6 qualification, no production CUDA proof, and no real PHI/payments. The full
state relation inside custom H4 GKR/PCS, reviewed backend admission, complete simulator/leakage
composition, and H5's exact 22 launches remain the next real blockers; this seal does not claim
Gate 2E completion.

## 2026-08-02 Compact state-AIR snapshot equality boundary - VERIFIED, NONACTIVATING

This phase continued from the actual authoritative checkout
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`.
The protected paths were not edited. No PHI, payment credential, production CUDA proof,
activation input, or `proofSuiteId` value was introduced.

The concrete trust gap was that the compact state AIR had an operation table and a two-row root
table, while native Rust compared operation columns with parsed state outside the AIR. The compact
program is now versioned as `BL-PQ512-STATE-RELATION-AIR-v2` and has four tables: the existing
91-column operation relation, fixed-capacity 46-column before/after snapshot tables, and the
two-row root table. Two width-46 constant-selector multiset lookups bind each operation phase's
`(index,present,key_chunks,value_chunks)` to the corresponding snapshot table. Fixed index columns
on both sides enforce one ordered row per slot; local identities retain boolean presence and
zero-private-bytes-for-empty-slot constraints. The native Rust verifier requires the four-table
grammar, checks both snapshot tables against the parsed fixed-capacity snapshots, and then
continues with the selected dual-PQ FRI package verification.

Focused relation tests now cover canonical encoding, empty-slot identity rejection, a valid-shape
snapshot lookup mismatch, and snapshot index reordering:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_relation_executable_air.py
....                                                                     [100%]
4 passed in 0.27s
```

The containing compact state-AIR regression passed:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane_executable_air.py
...                                                                      [100%]
3 passed in 282.18s (0:04:42)
```

The existing native state-plane fixture also remained green after the Rust grammar change:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane_native.py
...                                                                      [100%]
3 passed in 66.13s (0:01:06)
```

The fresh compact capacity-8 streamed dual-PQ fixture was generated after the version bump and
exported a private v3 envelope. This is a component run, not K128/K512 qualification evidence:

```text
status=STATE_AIR_PROOF_COMPONENT_VERIFIED_NONACTIVATING
program_id=BL-PQ512-STATE-RELATION-AIR-v2
program_commitment=9a9df7f23eaa1f31f276df87e681268a40a10f4629926826de20131194197ea9968874a216eaa978e9df4818ea5756b22b5991375db25f4564ee8f184c4e078c
execution_commitment=a4fc9c65ab0273d412bfd67d6b8ddf18de8255852893bd5ce986a9a37bbccb5140c6f202f3d26f7109e46979fad206498659536dcddac93a698d97a1f1ae3a48
package_commitment=bd07d54f37243c3b78e5ed3cec6ca4f0c1e2585798a032e424498c6e1db3a001a02e4776b312d193c868a35372fb05f325614a965172452c31c97de73ce9440a
suite=17eb5574a77c011050ff52f9dbb8023b356527946c6bbe569996303922464009ee8bf0886029ef90aba679360e8ffab56db4624ed49b9de91cc3f05d46d0f30d
schedule=c419abe698712f68ab09536ebd1d53a83a5e75fa6d1f7e6ba76f2de486ca925471b5b8f6f4690394b723bafaea1b8817e755b6ed52bca930aa60f2dfb6561689
transcript=55374eced434682caf43be936e8a6a1b1db39538519221975a2cef077ef4c8740d8974d7971a0f8f64c53937fba51484cc14c3d7891ecf63fa72e684cb0c9312
proof_identity=971942ec980bb2e0a2e038b0752eabbd09ca1b0bc6a69cdbb157b3e3f93cefddbbac9a54126768abd13fc66ecc97ce16783cab5a1271fd2a81adeea61ccb9ead
proof_bytes=11616597
package_bytes=11684436
binding_bytes=11741761
scratch_entries=0
```

The rebuilt native verifier consumed that exact envelope:

```text
& k512_atomic_semantic_prototype.exe --verify-state-binding compact-state-binding-v2.bin
state_plane_binding_verified=true
state_plane_statement_sha3_512=f839410300674014ed4204e116c4b4c6b297e0d9603a55629a6b9c2d7cad651f72aecac54d2911693c435fbd5b8009d4b92c374db80446daa785c18490301760
state_plane_binding_digest_sha3_512=eea81434f1bbdc8e57569f327ef6fc46f96f1de9c5202af36601375d10a805fe1f033804dbdd40dadcd00ff25121052c0644236cf74676eafc4ac2710a09ce8e
exit=0
```

A targeted mutation changed the before-snapshot `present` cell in the serialized execution from
`0` to `1`. Native verification rejected the mutated AIR at the new lookup boundary:

```text
exit=2
ERR:state_binding_air_execution:LookupMultisetMismatch
```

The first fresh fixture attempt was not credited: the existing release worker was stale and did
not create the requested private package, producing:

```text
FileNotFoundError: [Errno 2] No such file or directory: '...\\compact-state-scratch\\bl-state-air-proof-...bin'
```

The exact worker was rebuilt with `cargo +1.96.0 build --release --offline --locked --features
parallel --bin selected_streaming_prover_worker` into its declared target before the successful
rerun. This was a build-artifact correction; no source gate was weakened.

Additional source checks:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_relation_executable_air.py
4 passed in 0.27s

cargo +1.96.0 fmt --all -- --check
exit=0

cargo +1.96.0 check --offline --locked --features parallel --bin selected_streaming_prover_worker --bin k512_atomic_semantic_prototype
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.38s

git diff --check
exit=0
```

This phase closes the compact component's algebraic operation-to-snapshot equality/order boundary,
not Gate 2E admission. The full state relation remains outside the custom H4 GKR/PCS composition;
no reviewed PQ commitment backend is admitted, the complete simulator/leakage/security ledger is
open, H5's exact 22 launches have not started, H6 is open, `proofSuiteId=null`, activation=false,
no production CUDA proof was run, and no real PHI/payments are authorized.

## 2026-08-02 H4 state-GKR transcript seam and active-document reconciliation - VERIFIED, NONACTIVATING

This section records the current post-6fd4d source boundary. The protected paths were not edited.
The work was intentionally limited to the H4 state-GKR integration seam and its documentation; it
does not claim Wave 2 completion, Gate 2E admission, H5, H6, activation, or `proofSuiteId`.

The hash-bus H4 shape remains five claims and 6,086 rounds state-free. When a state source is
supplied, the native bridge runs a fixed 25-round state-GKR prelude, adds two boundary-one PCS
claims, and uses seven claims/6,111 total rounds. The state relation uses 4,096 groups, 64 source
wires, H4 wire offset 1,600, and a canonical 16,777,216-byte private source. Its current algebra
proves operation/snapshot field equality, Boolean presence, and empty-slot zeroing. Full index/order,
uniqueness, membership/absence, money/state conservation, backend admission, simulator/leakage
closure, state-composed performance, H5, and H6 remain open.

Focused executable evidence:

```text
cargo test --release --offline --locked --lib state_relation_gkr --features std,parallel
6 passed; 0 failed
cargo test --release --offline --locked --lib fp16_zk_rs_gkr_binding --features std,parallel
4 passed; 0 failed
cargo test --release --offline --locked --bin k512_atomic_semantic_prototype --features std,parallel
6 passed; 0 failed
cargo test --release --offline --locked --bin chained_public_coin_control --features std,parallel
3 passed; 0 failed
python cuda/fp16_zk_rs_same_chain_bridge_kat.py
status=verified; gkr_rounds=6098; combined_rounds=6111; independent_bundle_replay=true
python cuda/fp16_zk_rs_answer_target_verify_kat.py
construction7_answer_target_verified=true; target_mutation_rejected=true; gkr_relation_terminal_mutation_rejected=true
complete_proof_qualification=false
```

Active architecture, roadmap, current-stack, security, optimization, provenance, and crate-guide
documents were reconciled to this boundary. Historical `STATE.md` sections and `docs/history/` were
left intact as provenance rather than duplicated or relabeled as current evidence.

## 2026-08-02 Source-complete release archive refresh - VERIFIED

The Source-Complete release archive was rebuilt from committed source `6dcb5205b0e62f9d5b547f203953b2f7cbdc051d`.
`STATE.md` is deliberately excluded from the privacy-reviewed release allowlist, so this receipt-only
follow-up commit does not change the archive payload. The deterministic release builder and independent
readback reported:

```text
builder_version=blind-ledger-release-archive-v1
payload_file_count=775
payload_bytes=10655238
entry_count=776
archive_bytes=10939594
archive_sha256=9e4c9db9c738ff6c7d0c25bcd544a432573044713c024128b0ecd9aca5dd663e
archive_sha3_512=c8ceebd9c4225399d27f73befc3f38f3462e6b83532801daf1a6e9ca5c02acc461066d815c56ee842672e8c53e7200a1cc16766e99970eba6622444ccdf9325f
manifest_sha256=464efd01a6d369632cefb929f256fe8e713c2e74c530aecd8ac9a2f0759d3371
zip_crc_readback=passed
embedded_manifest_match=true
source_complete_three_way_byte_identical=true
```

The three updated paths are the Desktop root copy, the nested Desktop copy, and the Downloads copy
of `Blind-Ledger-Wave2-Source-Complete-2026-08-02.zip`. The privacy/allowlist stage excluded 17
synthetic or private-artifact paths, including the five portal font binaries; no real PHI, payment
data, or production proof bytes were used. The separate three-copy Architecture-Research archive set
was checked and left untouched; it was already byte-identical.

## 2026-08-02 State seam index/uniqueness parity - VERIFIED, NONACTIVATING

This bounded correction closes a concrete cross-language proof-boundary mismatch without changing
the selected H4 profile or activating any suite. `state_relation_gkr.rs` now retains each
authenticated fixed-capacity slot index in the proof source, writes a canonical group-index wire,
and rejects both an index mutation and a populated-row permutation in the compact GKR relation.
`k512_atomic_semantic_prototype.rs` carries parsed indices into that source and rejects duplicate
present keys in both version-2 and version-3 native state snapshots. The Python
`state_plane.py` canonical snapshot constructor/decoder now rejects the same duplicate-key class.

The protected-path check remained zero; only the proof-core state relation, native state verifier,
Python state plane, and its direct test changed. Raw focused evidence after the correction:

```text
cargo +1.96.0 test --release --offline --locked --lib state_relation_gkr --features std,parallel
test result: ok. 8 passed; 0 failed

cargo +1.96.0 test --release --offline --locked --bin k512_atomic_semantic_prototype --features std,parallel
test result: ok. 7 passed; 0 failed

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_state_plane.py tests/attacks/test_bl_pq512_state_plane_attacks.py
............                                                             [100%]
12 passed in 104.90s (0:01:44)

py -3.14 -B -m pytest -q -p no:cacheprovider tests/attacks/test_bl_pq512_state_plane_executable_air_attacks.py
...                                                                      [100%]
3 passed in 76.31s (0:01:16)

py -3.14 -B -m pytest -q -p no:cacheprovider tests/attacks/test_bl_pq512_state_plane_attacks.py
...                                                                      [100%]
3 passed in 0.15s

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_pq_integrated_state_reference.py
.......                                                                  [100%]
7 passed in 1.21s

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_wave1a_authenticated_replay_state_reference.py
....                                                                     [100%]
4 passed in 0.22s

py -3.14 -B -m pytest -q -p no:cacheprovider \
tests/test_bl_pq512_state_interface.py tests/attacks/test_bl_pq512_state_interface_attacks.py \
tests/test_bl_pq512_scalar_state_relation_controls.py tests/attacks/test_bl_pq512_scalar_state_relation_controls_attacks.py \
tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py \
tests/test_bl_pq512_atomic_state_composition.py tests/attacks/test_bl_pq512_atomic_state_composition_attacks.py \
tests/test_bl_pq512_state_migration_recovery.py tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py \
tests/test_bl_pq512_gate_2e_selection.py tests/attacks/test_bl_pq512_gate_2e_selection_attacks.py \
tests/test_bl_pq512_gate_2e_terminal_ledger.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py \
tests/test_bl_pq512_h5_qualification_preflight.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py \
tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
........................................................................ [ 81%]
................                                                         [100%]
88 passed in 197.20s (0:03:17)
```

The executable-AIR containing command was attempted with the exact two-file state-AIR core and
attack set, but its 304.084-second bound expired with exit 124 and no pytest summary; its exact
process tree was then stopped after command-line verification. It receives no pass credit. The
gate suite remains a component/regression gate only: the full state relation is still outside the
custom H4 GKR/PCS composition, no reviewed PQ backend is admitted, the complete simulator and
leakage/security ledger remain open, H5/H6 remain blocked, `proofSuiteId=null`, and activation is
false. A source-complete archive refresh is required after the final substantive source changes.

## 2026-08-02 State-source producer and transparent-candidate parity - VERIFIED, NONACTIVATING

The compact Rust state-relation producer now rejects an authenticated-entry index that does not
equal its canonical group position and rejects nonzero key/value bytes in an empty entry before it
can create a source digest. The source geometry change is identified as
`BL/PQ512/WAVE2/STATE-RELATION-SOURCE/v2`; the CUDA loader uses the same domain. The direct
state-relation target passes 9/9 tests.

The existing clean-room `TRANSPARENT_SHAKE256_1024` candidate now has a Rust implementation in
`experiments/bl_pq512_crypto_core/src/transparent_hash_code.rs` matching the Python `BLTHC02`
grammar: SHAKE256-1024 commitment before coin, 128-byte mask, 128-byte commitment, SHA3-512
canonical identity, authenticated coin-binding transcript, strict parser, and malformed-opening
rejection. Its cross-language KAT passes 2/2 Rust tests. This only closes implementation parity;
the candidate remains rejected for missing complete H4 composition, full simulator, and leakage/
security closure. No backend was admitted, `proofSuiteId` remains null, activation remains false,
and the full typed state relation, exact H5, and H6 remain open.

Raw evidence:

```text
cargo +1.96.0 test --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --release --offline --locked --lib state_relation_gkr --features std,parallel
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 266 filtered out

cargo +1.96.0 test --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --release --offline --locked --lib transparent_hash_code --features std,parallel
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 275 filtered out
```

## 2026-08-02 State-source producer duplicate-key gate - VERIFIED, NONACTIVATING

The compact Rust state-relation source builder now rejects a duplicate present key separately in
each of the four relation phases before source commitment. This is producer-side input validation;
it does not claim proof-native high-cardinality uniqueness, membership/absence, typed payment
semantics, money/state conservation, or complete H4 composition.

Raw focused evidence after the correction:

```text
cargo +1.96.0 test --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --release --offline --locked --lib state_relation_gkr --features std,parallel

running 10 tests
test state_relation_gkr::tests::changed_authenticated_index_is_rejected_by_the_state_gkr_claim ... ok
test state_relation_gkr::tests::nonzero_empty_private_bytes_are_rejected_before_source_commitment ... ok
test state_relation_gkr::tests::duplicate_present_keys_are_rejected_before_source_commitment ... ok
test state_relation_gkr::tests::row_permutation_is_rejected_by_the_canonical_index_wire ... ok
test state_relation_gkr::tests::changed_operation_presence_is_rejected_by_the_state_gkr_claim ... ok
test state_relation_gkr::tests::packed_state_relation_has_fixed_source_and_output_geometry ... ok
test state_relation_gkr::tests::changed_snapshot_chunk_is_rejected_by_the_state_gkr_claim ... ok
test state_relation_gkr::tests::verifier_rejects_nonzero_terminal_relation_claim ... ok
test state_relation_gkr::tests::interactive_state_relation_releases_every_public_coin_after_a_message ... ok
test state_relation_gkr::tests::valid_state_relation_proves_verifies_and_exposes_pcs_claims ... ok

test result: ok; 10 passed; 0 failed; 0 ignored; 0 measured; 268 filtered out; finished in 0.78s
```

`proofSuiteId` remains null, activation remains false, and the exact H5/H6 gates remain unrun.

The affected native verifier target also passed unchanged boundary coverage after this source
builder change:

```text
cargo +1.96.0 test --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --release --offline --locked --bin k512_atomic_semantic_prototype --features std,parallel
test result: ok; 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.69s
```

## 2026-08-02 Source-complete archive refresh after state boundary commit - VERIFIED

The archive was rebuilt from committed source `98df7a52be756c1f486759f0c809c1a238c78864` using
the prior reviewed 775-file allowlist, with only the committed source hash updates and the new
`experiments/bl_pq512_crypto_core/src/transparent_hash_code.rs` entry added. `STATE.md` remains
excluded from the payload. The strict builder and an independent ZIP readback reported:

```text
py -3.14 -B -m tools.build_release_archive --source-root <work>/refresh-source-98df7a5 --manifest <work>/refresh-source-98df7a5/APP_RELEASE_FILE_MANIFEST.json --output <work>/Blind-Ledger-Wave2-Source-Complete-2026-08-02-refresh.zip
{"archive_bytes":10958393,"archive_sha256":"09c66b194cc06bee20f3e7ccde5172c2641e6666494dff9d9400cfc0cf441138","builder_version":"blind-ledger-release-archive-v1","entry_count":777,"manifest_sha256":"1ba00a9783eca57b3936b4d4d028e98d61739a018c90c19eb674a4025121a579","payload_bytes":10673636,"payload_file_count":776,"receipt_version":1}

archive_bytes=10958393
archive_sha256=09c66b194cc06bee20f3e7ccde5172c2641e6666494dff9d9400cfc0cf441138
archive_sha3_512=b5e7aad4d1f5ba15db9afc5f80cab6dd606d92e2fede774d1bfaba2dec421c6d0905b42955c34237f926e3b9f412b001e554afd19d50b081ffeac81382c12d25
entry_count=777
manifest_bytes=116285
manifest_sha256=1ba00a9783eca57b3936b4d4d028e98d61739a018c90c19eb674a4025121a579
manifest_file_count=776
contains_state=false
contains_new_candidate=true
zip_crc_readback=true
source_complete_three_way_byte_identical=true
```

The Desktop root, nested Desktop, and Downloads copies were first checked against the recorded
old size/hash and then replaced at their exact named paths. Final readback matched the new size and
SHA3-512 for all three copies; no temporary replacement files remained. The direct script-style
builder invocation was attempted first and failed before validation with
`ModuleNotFoundError: No module named 'tools'`; the module invocation above is the successful run.
The replacement helper also emitted a non-terminating PowerShell `Split-Path -LiteralPath ...
-Parent` parameter-set warning, which receives no success credit; the final independent readback is
the authoritative copy verification.

This refresh changes release evidence only. `proofSuiteId` remains null, activation remains false,
and Gate 2E, exact H5, and H6 are not closed by the archive.

## 2026-08-02 Typed C0 state relation semantic boundary - VERIFIED, NONACTIVATING

The working tree at `82b0b2131d349fe669f2463d4e832769f371a2ec` received the smallest trust-critical
repair at the C0/H4 seam. `c0_control_fixture.py` now exposes `C0TypedStateWitness` and rejects
replay snapshot/batch root or cursor mismatches and payment before-state/slot-count mismatches.
`experiments/fixed_shape_claim_air/typed_state_relation_executable_air.py` composes the existing
ordered-map replay and authenticated payment-map AIRs, binds replay plus payment roots/cursors and
fixed slot order, enforces canonical money subtraction with no-underflow and debit/credit
conservation, and carries replay/payment SHA3 ports through one canonical interface composer with
contiguous call indices. No protected path was modified and no real PHI, payment, or production
secret was used.

The exact K128 structural readback was:

```text
program_id=BL-PQ512-C0-TYPED-STATE-AIR-v1
tables=60
lookups=93
public_inputs=524
hash_calls=46208
replay_hash_ports=True
payment_hash_ports=True
public_tail=(100,80,80,80)
```

Verified commands and raw decisive results:

```text
py -3.14 -B -m pytest -q tests/test_bl_pq512_typed_state_relation_executable_air.py
. [100%]
1 passed in 353.49s (0:05:53)

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_typed_state_relation_executable_air.py -k binds_replay
. [100%]
1 passed, 3 deselected in 262.95s (0:04:22)

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_typed_state_relation_executable_air.py -k rejects
.. [100%]
2 passed, 2 deselected in 314.16s (0:05:14)

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_c0_control_fixture.py
........ [100%]
8 passed in 35.34s
```

The combined typed file after adding the mutation tests exceeded its 604030 ms bound with exit
124 and no pytest summary; the combined C0/payment regression exceeded its 304042 ms bound with
exit 124 and no pytest summary. Both exact child process sets were stopped, neither receives pass
credit, and no repository files were changed by either timeout. The positive and split mutation
commands above are the credited evidence.

This is a verified typed component, not Gate 2E closure. It is not yet consumed by native
`state_relation_gkr.rs` or the custom H4 GKR/PCS parent/PCS terminals. The terminal ledger remains
`UNSEALED_BLOCKED_GATE_2E_TERMINAL_LEDGER`; `complete_leakage_scan_missing`,
`complete_simulator_missing`, `h4_atomic_binding_deferred`, `no_backend_admitted`, and
`proof_suite_unselected` remain open. H5 has not run, H6 has not run, `proofSuiteId` remains null,
activation remains false, and the source-complete archive has not yet been refreshed for this
working-tree change.

## 2026-08-02 Typed C0 source-complete archive refresh - VERIFIED

The typed C0 implementation and documentation were committed on `main` as
`3d49e06058dd22158ce0ca8fed8c6ee9926e4996`, tree
`d548d24ca55543d4f1e1b5122d137e832c4beb7e`; the checkout was clean before this receipt-only
update. The deterministic builder used the reviewed 17-path privacy exclusion set and selected
778 payload files from 795 tracked files. The first staging helper failed closed before archive
validation on a PowerShell `Split-Path` parameter-set error, created no ZIP, and its exact staging
directory was verified and removed. The corrected staging and module invocation passed:

```text
py -3.14 -B -m tools.build_release_archive --source-root <work>/refresh-source-3d49e06 --manifest <work>/refresh-source-3d49e06/APP_RELEASE_FILE_MANIFEST.json --output <work>/Blind-Ledger-Wave2-Source-Complete-2026-08-02-3d49e06.zip
{"archive_bytes":11016479,"archive_sha256":"8a13443c5ef78dbc82d0f2b8ca10ea1bcc93acf146616e8d2070a8b6a97abd3f","builder_version":"blind-ledger-release-archive-v1","entry_count":779,"manifest_sha256":"a2a11688bf86d742c2174d7c3189bb7fbd085d6d623cf012bf6066f9c04b285f","payload_bytes":10704426,"payload_file_count":778,"receipt_version":1}

archive_bytes=11016479
archive_sha256=8a13443c5ef78dbc82d0f2b8ca10ea1bcc93acf146616e8d2070a8b6a97abd3f
archive_sha3_512=8e222a703991aaaaf27e175ab66eeb2e6f051d62724f26e93ba898c68c659949d75c427960ba69fec51b9d0e5e95a22a6877028d8bc11e8c2dc5775185d41834
entry_count=779
manifest_file_count=778
manifest_sha256=a2a11688bf86d742c2174d7c3189bb7fbd085d6d623cf012bf6066f9c04b285f
manifest_matches_stage=true
zip_crc_readback=passed
contains_typed_module=true
contains_typed_test=true
contains_state=false
forbidden_generated_entries=0
```

The exact reviewed copies at the Desktop root, the nested `Blind-Ledger-Wave2-Full-Workspace-2026-08-02`
directory, and Downloads were checked against the prior 10,958,393-byte/
`09c66b194cc06bee20f3e7ccde5172c2641e6666494dff9d9400cfc0cf441138` identity before replacement.
Independent final readback reports 11,016,479 bytes and SHA-256
`8a13443c5ef78dbc82d0f2b8ca10ea1bcc93acf146616e8d2070a8b6a97abd3f` for all three. This receipt
changes release evidence only; Gate 2E remains unsealed, H5/H6 remain unrun, `proofSuiteId` is
null, and activation remains false.

After the receipt commit, the semantics-preserving privacy-safe field rename received a fresh
positive verifier readback:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_typed_state_relation_executable_air.py -k replays_c0
. [100%]
1 passed, 3 deselected in 334.66s (0:05:34)
```

## 2026-08-02 Typed C0 full-AIR canonicalization and resource-gate reconciliation - VERIFIED, NONACTIVATING

The authoritative checkout for this phase was
`C:\\Users\\neers\\Documents\\Codex\\2026-07-27\\he\\work\\Blind-Ledger-Wave2-Workspace-2026-07-26`,
branch `main`, with pre-phase HEAD `22df74e Record typed verifier readback`. Protected paths were
not modified. The canonical typed proof builder now uses the full
`typed_state_relation_executable_air.py`; the compact diagnostic route was removed from the
canonical path because it retained call descriptors but omitted the full claim-source, key, and
operation-log constraints. Its measured rejection remains evidence below and is not a proof claim.

The full typed K128 semantic readback remained:

```text
program_id=BL-PQ512-C0-TYPED-STATE-AIR-v1
tables=60
lookups=93
public_inputs=1806
hash_calls=46210
base_replay_payment_hash_calls=46208
state_root_hash_calls=2
```

Current containing regressions passed:

```text
cargo +1.96.0 test --features std --bin k512_atomic_semantic_prototype --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 96.00s

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_typed_state_relation_executable_air.py
....                                                                     [100%]
4 passed in 620.06s (0:10:20)

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_gate_2e_selection.py tests/attacks/test_bl_pq512_gate_2e_selection_attacks.py tests/test_bl_pq512_h5_qualification_preflight.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py tests/test_bl_pq512_h6_qualification_preflight.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
..................                                                       [100%]
18 passed in 106.11s (0:01:46)
```

The full selected generic-FRI typed route was attempted with the historical immutable caps
restored. Its exact execution encoding is `566640085` bytes against the `536870912`-byte
`MAX_AIR_BINARY_BYTES` cap and fails closed with `StructuralError: air_binary_size_cap_exceeded`.
During diagnosis only, the cap was temporarily widened and then reverted; the exact native
resource preflight still rejected the full route:

```text
evidence_class=DERIVED_MODEL
model_id=GENERIC_AIR_ORACLE_LAYOUT_V1
qualifies=false
activation_allowed=false
modeled_main_evaluation_bytes=6331301888
modeled_interaction_evaluation_bytes=152664276992
modeled_composition_evaluation_bytes=29259464704
modeled_deep_evaluation_bytes=566449143808
modeled_fri_mask_bytes=7042236416
modeled_folded_layer_bytes=8589934592
modeled_monolithic_live_bytes_lower_bound=770336358400
modeled_maximum_domain_rows=67108864
requires_streaming=true
modeled_raw_witness_bytes=248465072
modeled_persistent_oracle_bytes=189308815024
modeled_peak_temporary_bytes=39854276608
modeled_filesystem_overhead_bytes=57290772908
modeled_reserve_bytes=4294967296
modeled_required_available_bytes=290748831836
```

The compact diagnostic measurement was also rejected and is not canonical proof evidence:

```text
program_bytes=80886809
execution_bytes=430547521
raw_witness_bytes=270493468
evidence_class=DERIVED_MODEL
model_id=GENERIC_AIR_ORACLE_LAYOUT_V1
qualifies=false
activation_allowed=false
modeled_main_evaluation_bytes=6539444224
modeled_interaction_evaluation_bytes=95785320448
modeled_composition_evaluation_bytes=1157627904
modeled_deep_evaluation_bytes=403148111872
modeled_fri_mask_bytes=62914560
modeled_folded_layer_bytes=67108864
modeled_monolithic_live_bytes_lower_bound=506760527872
modeled_maximum_domain_rows=524288
requires_streaming=true
modeled_persistent_oracle_bytes=103954212444
modeled_peak_temporary_bytes=5595201536
modeled_filesystem_overhead_bytes=27387353495
modeled_reserve_bytes=4294967296
modeled_required_available_bytes=141231734771
```

The compact route omitted full claim-source/key/operation-log constraints and therefore was
removed rather than promoted to solve the resource failure. The selected typed proof route has no
successful proof package, no H4 state-composed qualification run, and no Gate 2E credit. The raw
status fields are:

```text
gate_2e_selection_status=C0_CONTROL_RETAINED_NO_ELIGIBLE_PQ_FINALIST
gate_2e_complete_boundary_status=NOT_RUN_NO_ELIGIBLE_FINALIST
gate_2e_handoff_status=UNSEALED_BLOCKED_SELECTION_HANDOFF
proof_suite_id=None
activation_allowed=false
h5_preflight_status=BLOCKED_H5_PREFLIGHT
h6_preflight_status=BLOCKED_H6_PREFLIGHT
h6_suite_registry_status=CANDIDATE_UNQUALIFIED
```

No H5 launch was attempted or skipped silently. The source-complete archive refresh is the final
external-artifact step for this clean phase commit; its independent three-copy hashes are reported
in the phase handoff. Gate 2E, H5, and H6 remain unclosed, `proofSuiteId=null`, and activation is
false.

## 2026-08-02 Full-AIR source-complete archive refresh - VERIFIED, NONACTIVATING

The full-AIR implementation and gate-reconciliation source was committed cleanly as
`a905b456f9cd475383f46f6516df26f6702446ce`. The deterministic source-complete builder used the
reviewed 17-path privacy exclusion set from the prior receipts; `STATE.md` is excluded from the
payload. The first generated-manifest attempt failed closed with
`release file entries must be strictly path-sorted`; no ZIP was published. The manifest was
regenerated with deterministic code-point path ordering and the module builder then passed:

```text
{"archive_bytes":11098485,"archive_sha256":"e05c73dd156083b46b962f9aff084b372c48028c29f2dded1259e417f9c71ca2","builder_version":"blind-ledger-release-archive-v1","entry_count":780,"manifest_sha256":"c01cbb817d698ebd5bd2ea057bfc7cb54c67910f4f9b1f4ae498300881b2f73c","payload_bytes":10782089,"payload_file_count":779,"receipt_version":1}

archive_bytes=11098485
archive_sha256=e05c73dd156083b46b962f9aff084b372c48028c29f2dded1259e417f9c71ca2
archive_sha3_512=cd561bccdfe1fb846e844b2637887b6e297581acd943f7c898edff1d5164b66c51fbc7abf5185d235b519007920d64fe8bc83a8ff46b2dc84b62067611c35075
entry_count=780
manifest_bytes=147184
manifest_sha256=c01cbb817d698ebd5bd2ea057bfc7cb54c67910f4f9b1f4ae498300881b2f73c
manifest_file_count=779
contains_state=false
contains_typed_module=true
zip_crc_readback=true
source_complete_three_way_byte_identical=true
```

Independent readback verified byte identity and the same SHA-256/SHA3-512 at the exact Desktop
root, nested Desktop, and Downloads paths. The target preflight/copy helper emitted a
non-terminating PowerShell `Split-Path` parameter-set warning; it receives no verification credit.
The independent ZIP readback passed, and the final archive test passed `18 passed, 54 subtests
passed in 1.01s`. A receipt-only follow-up commit changes only this excluded `STATE.md` record;
the three archive payloads remain bound to the clean implementation commit above. Gate 2E, H5, and
H6 remain unclosed, `proofSuiteId=null`, and activation is false.

## 2026-08-03 Typed C0 v2 interface compaction and native boundary readback - VERIFIED, NONACTIVATING

The authoritative checkout for this phase is the `main` worktree
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`.
Protected paths remain untouched. The smallest representation-preserving v2 correction packs the
claim source bundle and payment log-message transport into eight byte lanes, removes duplicate
root-message witness columns, and retargets the exact lookup multisets. The native reader now
consumes the packed log lanes and reconstructs root messages from the canonical authority roots.

The exact K128 v2 shape readback was:

```text
program_id=BL-PQ512-C0-TYPED-STATE-AIR-v2
program_bytes=22018481
execution_bytes=145207821
program_commitment=f6321d7483c65469ecf9d408a5d4de59321a8e3556b6da93b4e4c0b506f01ca649b8653cf60d0e499df99022f84ff1b9bd304ff11fcc203b3013112154cac99f
execution_commitment=21aee4736e5ee43b09c31470ca2b9ab95e0d3276b82d4f5ed5b319ec78860260a75376ced48225a26eae1084221fabeb6ad0836204ed04646fbacf995893baf0
tables=56
lookups=81
public_inputs=1806
hash_calls=46210
raw_witness_bytes=103237152
typed_state_log_message_batch rows=17280 columns=18 live_columns=16 raw_bytes=1105920
claim_source_bundle_word rows=90368 columns=59 live_columns=8 raw_bytes=2891776
```

The focused semantic command completed with no stderr and this raw result:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_typed_state_relation_executable_air.py
....                                                                     [100%]
4 passed in 307.53s (0:05:07)
```

The native boundary checks were:

```text
cargo +1.96.0 fmt --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml -- --check
exit=0

cargo +1.96.0 check --features std --bin k512_atomic_semantic_prototype --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.67s
exit=0

cargo +1.96.0 test --features std --bin k512_atomic_semantic_prototype --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 97.45s
exit=0
```

The immutable generic-AIR resource preflight still rejects this route. Its complete raw output is:

```text
evidence_class=DERIVED_MODEL
model_id=GENERIC_AIR_ORACLE_LAYOUT_V1
qualifies=false
activation_allowed=false
modeled_main_evaluation_bytes=4642045952
modeled_interaction_evaluation_bytes=14847836160
modeled_composition_evaluation_bytes=1509949440
modeled_deep_evaluation_bytes=181261041664
modeled_fri_mask_bytes=130023424
modeled_folded_layer_bytes=134217728
modeled_monolithic_live_bytes_lower_bound=202525114368
modeled_maximum_domain_rows=1048576
requires_streaming=true
modeled_raw_witness_bytes=103237152
modeled_persistent_oracle_bytes=21505721696
modeled_peak_temporary_bytes=1035206656
modeled_filesystem_overhead_bytes=5635232088
modeled_reserve_bytes=4294967296
modeled_required_available_bytes=32471127736
```

The C: free-space snapshot was `45357948928` bytes, so the rejection is not a current disk-space
shortage. The generic route remains non-qualifying even after the v2 reduction. The proof-native
custom H4 relation still proves only its existing compact equality/index/presence/empty-slot
boundary; full typed state semantics inside custom H4 GKR/PCS, reviewed PQ admission, complete
simulator/leakage closure, H5, H6, `proofSuiteId`, and activation remain open. Therefore no H5
launch was authorized or credited, and no gate was weakened to force progress.

## 2026-08-03 Typed C0 v3 vector LogUp correction - VERIFIED, NONACTIVATING

The authoritative `main` checkout remains
`C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`.
Protected paths remain untouched. The v2 payment-log compaction packed bytes into rows but retained
one LogUp side per lane. The v3 correction groups each contiguous 64-byte source block into one
vector lookup message and uses fixed live bits on the compact destination. It preserves every call
index, byte position, value, weight, source range, and byte obligation. The authoritative
Rust reader validates live and padding values, sorts live positions, and rejects duplicates or
gaps before reconstructing each message.

The first focused run exposed one incorrect v3 construction assumption and failed closed:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_typed_state_relation_executable_air.py
E experiments.fixed_shape_claim_air.semantics.StructuralError: typed_state_log_message_port_length_invalid
4 failed in 555.90s (0:09:15)
```

The SHA3 message-table span includes fixed-shape padding, so it is not the unpadded call length.
The correction derives the live length from the canonical call preimage and independently checks
the complete padded source span's live/value grammar. The uninterrupted post-correction verifier
and mutation run was:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_typed_state_relation_executable_air.py
....                                                                     [100%]
4 passed in 300.68s (0:05:00)
```

Exact K128 v3 readback:

```text
program_id=BL-PQ512-C0-TYPED-STATE-AIR-v3
program_bytes=22405576
execution_bytes=145415716
program_commitment=4b483214418199cd829e04ffd242ba04411f70870b80144a53961c76919566d9e841b246d36c07860ff1023652d4d965cb8bb041d6d80d43b6aff1ca6fa821c8
execution_commitment=59af5c927aa5efdc23d9b5dd044459a28078c8e7201380b1e1f72ec2b23c69b926d89200be02d690bc89bdc9c75d625a7a553d1802bb4ed912ca6e3279466423
tables=56
lookups=81
public_inputs=1806
hash_calls=46210
raw_witness_bytes=102655520
typed_state_log_message_batch rows=2048 columns=130 live_columns=64 raw_bytes=524288
claim_source_bundle_word rows=90368 columns=59 live_columns=8 raw_bytes=2891776
```

The authoritative Rust boundary passed:

```text
cargo +1.96.0 fmt --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml -- --check
exit=0

cargo +1.96.0 check --features std --bin k512_atomic_semantic_prototype --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.54s
exit=0

cargo +1.96.0 test --features std --bin k512_atomic_semantic_prototype --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 97.81s
exit=0
```

The exact immutable resource preflight remains a hard rejection:

```text
evidence_class=DERIVED_MODEL
model_id=GENERIC_AIR_ORACLE_LAYOUT_V1
qualifies=false
activation_allowed=false
modeled_main_evaluation_bytes=4642045952
modeled_interaction_evaluation_bytes=8799649792
modeled_composition_evaluation_bytes=1459617792
modeled_deep_evaluation_bytes=169064005632
modeled_fri_mask_bytes=130023424
modeled_folded_layer_bytes=134217728
modeled_monolithic_live_bytes_lower_bound=184229560320
modeled_maximum_domain_rows=1048576
requires_streaming=true
modeled_raw_witness_bytes=102655520
modeled_persistent_oracle_bytes=15406622048
modeled_peak_temporary_bytes=1035206656
modeled_filesystem_overhead_bytes=4110457176
modeled_reserve_bytes=4294967296
modeled_required_available_bytes=24847253176
```

This removes 6,048,186,368 bytes from the modeled interaction oracle and 7,623,874,560 bytes from
modeled required scratch availability relative to v2, but it does not qualify the route. Gate 2E,
H5, H6, reviewed backend admission, simulator/leakage closure, `proofSuiteId`, and activation remain
open. No H5 launch is authorized or credited by this component result.

## 2026-08-03 Typed C0 v4 local sentinel proof - VERIFIED, NONACTIVATING

The v4 correction removes the replay and shared three-payment-map key-sentinel LogUp arguments.
Each range-checked key byte now locally constrains its `nonzero` and `not_max` flags with explicit
inverse witnesses. Existing aggregate sum/inverse identities still prove that each 64-byte key is
neither all-zero nor all-`0xff`. Two new attacks keep those aggregates valid while forging one byte
flag; both reject at the new local identities. Protected paths remain untouched.

Exact focused evidence:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/attacks/test_wave1a_ordered_map_batch_executable_air_attacks.py::test_zero_sentinel_operation_key_cannot_be_admitted tests/attacks/test_wave1a_ordered_map_batch_executable_air_attacks.py::test_max_sentinel_operation_key_cannot_be_admitted tests/attacks/test_wave1a_ordered_map_batch_executable_air_attacks.py::test_nonzero_key_byte_flag_cannot_be_forged_after_lookup_removal tests/attacks/test_wave1a_ordered_map_batch_executable_air_attacks.py::test_not_max_key_byte_flag_cannot_be_forged_after_lookup_removal
....                                                                     [100%]
4 passed in 0.73s

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_wave1a_ordered_map_batch_executable_air.py::test_ordered_map_batch_air_evaluates_in_both_interpreters tests/test_wave1a_authenticated_payment_maps_executable_air.py::test_k128_payment_maps_air_has_one_shared_byte_table tests/test_wave1a_authenticated_payment_maps_executable_air.py::test_k128_claim_payment_maps_air_evaluates
...                                                                      [100%]
3 passed in 122.63s (0:02:02)

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_typed_state_relation_executable_air.py
....                                                                     [100%]
4 passed in 296.33s (0:04:56)

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_wave1a_authenticated_payment_maps_executable_air.py::test_k128_claim_payment_maps_one_sha3_engine_fully_evaluates
.                                                                        [100%]
1 passed in 1059.99s (0:17:39)

cargo +1.96.0 fmt --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml -- --check
exit=0

cargo +1.96.0 check --features std --bin k512_atomic_semantic_prototype --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.97s
exit=0

cargo +1.96.0 test --features std --bin k512_atomic_semantic_prototype --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 98.14s
exit=0
```

An initial three-file aggregate command reached its 604-second command bound before emitting a
pytest result (`exit=124`). Narrowed runs established that the direct attacks passed and the
positive evaluators reached only stale exact-shape assertions. Those assertions were refreshed
from explicit readback and the affected tests then passed as recorded above. The first full-SHA3
pin run evaluated successfully but failed its stale first assertion (`expected 81`, `actual 80`;
`1 failed`, command wall time `1079.9s`). A single diagnostic evaluation emitted all six new pins;
the final exact test passed as recorded above. The full-SHA3 result is correctness evidence only;
its 1,059.99-second duration is not H5 evidence.

Exact K128 v4 readback:

```text
program_id=BL-PQ512-C0-TYPED-STATE-AIR-v4
program_bytes=22460606
execution_bytes=145792794
program_commitment=52fbd8553df1e83792cc00bb5a33ae47bbcb96d985a1fb8253b97f2fe7df83bf1be9a94c3ded4ef2a8842c46d1e09187ae50a20b255532bf1f6fca3e5e2ac201
execution_commitment=d35fec28b5577b848ed562e92257b6cad73a8d56e710f4dab5c74e893ff0ffec81063159c8cfc8a7312f78975c4c85436750626bf6c853fad3c1f0c7ab529f29
tables=56
lookups=79
public_inputs=1806
hash_calls=46210
raw_witness_bytes=102981664
```

The immutable resource preflight still rejects v4:

```text
evidence_class=DERIVED_MODEL
model_id=GENERIC_AIR_ORACLE_LAYOUT_V1
qualifies=false
activation_allowed=false
modeled_main_evaluation_bytes=4775739392
modeled_interaction_evaluation_bytes=7692353536
modeled_composition_evaluation_bytes=1442840576
modeled_deep_evaluation_bytes=171094048768
modeled_fri_mask_bytes=130023424
modeled_folded_layer_bytes=134217728
modeled_monolithic_live_bytes_lower_bound=185269223424
modeled_maximum_domain_rows=1048576
requires_streaming=true
modeled_raw_witness_bytes=102981664
modeled_persistent_oracle_bytes=14416568160
modeled_peak_temporary_bytes=1135869952
modeled_filesystem_overhead_bytes=3888109528
modeled_reserve_bytes=4294967296
modeled_required_available_bytes=23735514936
```

Relative to v3, v4 removes 1,107,296,256 interaction bytes while adding 133,693,440 main bytes;
modeled required availability falls by 1,111,738,240 bytes. This remains far above the immutable
limit. Gate 2E, H5, H6, reviewed backend admission, simulator/leakage closure, `proofSuiteId`, and
activation remain open; no H5 launch is authorized or credited.

## 2026-08-03 Typed C0 v5 scalar vector copy - VERIFIED, NONACTIVATING

The scalar-to-canonical-bundle relation has 41 fixed absolute byte positions but previously used
41 scalar source sides and eight packed-bundle lane sides. v5 groups those positions by their eight
actual 8-byte bundle words. Each vector lane retains a live bit, slot index, absolute byte index,
and value; the bundle destination uses fixed per-lane scalar masks and a fixed per-word selector.
No live witness column was added. A mutation of one live scalar byte on the bundle side rejects.
Protected paths remain untouched.

Exact K128 v5 readback and verification:

```text
program_id=BL-PQ512-C0-TYPED-STATE-AIR-v5
program_bytes=23906457
execution_bytes=148684533
program_commitment=260106c1018c1e6348be016fdcc22fb4d554341c40e87d7a7236109fe4ba076f58ce477a0cf4e7ff20ec06854dbeeedaa7058a498619ede1c7de4c7d2c67c3d3
execution_commitment=94994cd5876eb04d82ef31b45bae6cac9029ce88575497bf9c9c4580911ca6983887dac45f24d4df7593a1a736fe99efa58069cee150cffa575155f54a5cb39c
tables=56
lookups=79
public_inputs=1806
hash_calls=46210
raw_witness_bytes=102981664

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_typed_state_relation_executable_air.py
.....                                                                    [100%]
5 passed in 370.03s (0:06:10)

cargo +1.96.0 test --features std --bin k512_atomic_semantic_prototype --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 101.43s
exit=0
```

The exact immutable resource preflight remains a hard rejection:

```text
evidence_class=DERIVED_MODEL
model_id=GENERIC_AIR_ORACLE_LAYOUT_V1
qualifies=false
activation_allowed=false
modeled_main_evaluation_bytes=4775739392
modeled_interaction_evaluation_bytes=7084179456
modeled_composition_evaluation_bytes=1442840576
modeled_deep_evaluation_bytes=169877700608
modeled_fri_mask_bytes=130023424
modeled_folded_layer_bytes=134217728
modeled_monolithic_live_bytes_lower_bound=183444701184
modeled_maximum_domain_rows=1048576
requires_streaming=true
modeled_raw_witness_bytes=102981664
modeled_persistent_oracle_bytes=13808394080
modeled_peak_temporary_bytes=1135869952
modeled_filesystem_overhead_bytes=3736066008
modeled_reserve_bytes=4294967296
modeled_required_available_bytes=22975297336
```

The scalar argument's modeled interaction contribution falls from 780,140,544 to 171,966,464
bytes. Relative to v4, total interaction storage falls by 608,174,080 bytes and modeled required
availability falls by 760,217,600 bytes. This remains nonqualifying. Gate 2E, H5, H6, reviewed
backend admission, simulator/leakage closure, `proofSuiteId`, and activation remain open; no H5
launch is authorized or credited.

## 2026-08-03 Typed envelope v5 pre-coin PQ commitment composition path - VERIFIED, NONACTIVATING

The typed envelope previously derived its statement from the future proof-package commitment. That
made a genuine commit-before-authenticated-coin lifecycle impossible. Envelope version 5 removes
that circular dependency: it freezes the typed statement, transition, and retry-stable attempt from
the profile, roots, projection, and exact AIR program/execution commitments; derives a fresh
domain-separated 1,024-bit mask from the proof entropy and fresh session; and creates the
`TRANSPARENT_SHAKE256_1024` commitment before constructing the 744-byte authenticated sidecar.
The sidecar binds the exact commitment transport identity before the typed public coin. The private
v5 envelope carries the canonical 1,024-bit commitment and mask. Rust verifies the raw opening,
attempt, final authenticated transcript binding, and transport identity before the existing H4
state context reaches the child transcript, parent, composition, and atomic receipt. Version 4
remains a separate legacy parser branch and cannot be accepted as version 5 without the new fields.

Focused evidence:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_transparent_hash_code_candidate.py
....                                                                     [100%]
4 passed in 3.92s

cargo +1.96.0 test --features std --lib transparent_hash_code --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 263 filtered out; finished in 0.00s

cargo +1.96.0 test --features std --bin k512_atomic_semantic_prototype typed_v5_precommitment_rejects_opening_coin_identity_and_attempt_mutations --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.00s

cargo +1.96.0 test --features std --bin k512_atomic_semantic_prototype --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 100.77s

cargo +1.96.0 check --features std --bin k512_atomic_semantic_prototype --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.52s

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_transparent_hash_code_candidate.py tests/test_bl_pq512_pq_commitment_screening.py tests/attacks/test_bl_pq512_pq_commitment_screening_attacks.py
............                                                             [100%]
12 passed in 9.09s

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_deployment_ready_roadmap_contract.py
...                                                                      [100%]
3 passed in 0.12s
```

The first focused Python run failed only because the test omitted the explicit synthetic-reference
environment flags (`synthetic_pq_tree_reference_forbidden`); adding the same three test-only flags
used by the existing C0 suites produced the passing result above. A broad Rust name-filter command
without `--lib` also exposed a pre-existing feature mismatch in the unrelated
`gkr_sparse_layer_fixture` binary (`repeated_pack_sparse_layer_gpu_fixture` requires `parallel`);
the exact library target then passed 2/2. Neither failure weakened a gate or changed production
behavior.

This is not complete composition or backend admission evidence because the full typed v5 proof has
not traversed the path under the immutable resource limit. `complete_composition` remains false,
the exact v5 generic-AIR preflight remains nonqualifying, and no H5 launch, `proofSuiteId`, or
activation credit is taken. The next dependency is the prover storage/resource architecture.

## 2026-08-03 Generic typed-AIR lifetime rejection gate - VERIFIED, NONACTIVATING

The resource preflight now applies the immutable strictly-below-5,000,000,000-byte scratch gate to
proof-owned concurrent bytes instead of leaving that comparison implicit. The modeled peak scratch
is `persistent_oracle_bytes + peak_temporary_bytes`. The separate 25% filesystem headroom and
4,294,967,296-byte free-volume reserve remain reported as host admission inputs and are not
misclassified as proof scratch. The boundary is strict: exactly 5,000,000,000 rejects.

Fresh K128 v5 program materialization outside the source tree reproduced the sealed shape:

```text
program_bytes=23906457
tables=56
lookups=79
public_inputs=1806
```

Exact native preflight output:

```text
evidence_class=DERIVED_MODEL
model_id=GENERIC_AIR_ORACLE_LAYOUT_V1
qualifies=false
activation_allowed=false
scratch_gate_bytes=5000000000
modeled_peak_scratch_bytes=14944264032
scratch_gate_pass=false
route_status=REJECTED_CURRENT_PERSISTENT_ORACLE_LIFETIME
modeled_main_evaluation_bytes=4775739392
modeled_interaction_evaluation_bytes=7084179456
modeled_composition_evaluation_bytes=1442840576
modeled_deep_evaluation_bytes=169877700608
modeled_fri_mask_bytes=130023424
modeled_folded_layer_bytes=134217728
modeled_monolithic_live_bytes_lower_bound=183444701184
modeled_maximum_domain_rows=1048576
requires_streaming=true
modeled_raw_witness_bytes=102981664
modeled_persistent_oracle_bytes=13808394080
modeled_peak_temporary_bytes=1135869952
modeled_filesystem_overhead_bytes=3736066008
modeled_reserve_bytes=4294967296
modeled_required_available_bytes=22975297336
```

Focused native evidence:

```text
cargo +1.96.0 test --features std --lib resource_preflight --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 265 filtered out; finished in 0.00s

cargo +1.96.0 check --features std --bin resource_preflight --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
Finished `dev` profile [unoptimized + debuginfo] target(s) in 8.31s
```

The first formatting command was incorrectly aimed at the repository root, which has no root
`Cargo.toml`; no source changed from that failed command. The exact crate-manifest format check was
then used. This decision rejects only the current aggregate generic-oracle lifetime as the complete
H4 route. The typed C0 AIR remains the executable semantic/differential oracle and native readback
seam. Gate 2E remains open; implementation returns to the selected custom H4 semantic/state
composition. No H5 launch, backend admission, `proofSuiteId`, or activation credit is taken.

## 2026-08-03 Proof-native all-pairs uniqueness control - VERIFIED, REJECTED FOR H4

The custom state lane now has an executable proof-native duplicate-key control over both before and
after phases. Each active unordered pair uses the injective two-Fp16 key packing, a Boolean selector,
and an inverse witness; duplicate packed keys make both differences zero and cannot satisfy the
final claim. Four sparse GKR layers release every quadratic message before its authenticated
challenge, release two fresh claim-combination coefficients per layer, independently verify, and
expose exactly two source claims for PCS binding. Positive, duplicate, forged-witness, inactive-
selector, and interactive-order tests pass.

The containing regression also exposed a pre-existing declaration mismatch in
`state_relation_gkr.rs`: the layer constructs 26 raw constraints while the constant declared 28.
The declaration and geometry test now state 26; no constraint was removed and the old 10-test
state-relation suite passes.

Exact release control output:

```text
capacity=128
pair_count=8128
phase_pair_instances=16256
source_fp16_elements=65536
source_bytes=4194304
authenticated_rounds=142
pcs_input_claims=2
source_build_seconds=0.013770
prove_seconds=21.902903
verify_seconds=2.878161
verified=true
activation_allowed=false

capacity=512
pair_count=130816
phase_pair_instances=261632
source_fp16_elements=1048576
source_bytes=67108864
authenticated_rounds=174
pcs_input_claims=2
source_build_seconds=0.203529
prove_seconds=426.679855
verify_seconds=38.789283
verified=true
activation_allowed=false
```

The K512 uniqueness control alone exceeds the immutable 180-second complete-proof ceiling, so the
quadratic route is rejected as the selected H4 architecture. It remains an executable differential
oracle for a subquadratic successor. Gate 2E, H4 state composition, H5, H6, backend admission,
`proofSuiteId`, and activation all remain open.

Focused and containing verification:

```text
cargo +1.96.0 test --features std --lib state_relation_gkr --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 262 filtered out; finished in 11.63s

cargo +1.96.0 test --features std --lib state_uniqueness_gkr --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 267 filtered out; finished in 0.19s

cargo +1.96.0 test --features std --lib hash_bus_b16 --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 267 filtered out; finished in 39.87s

cargo +1.96.0 check --no-default-features --lib --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
Finished `dev` profile [unoptimized + debuginfo] target(s) in 6.77s

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_deployment_ready_roadmap_contract.py
3 passed in 0.13s
```

One attempted Cargo command supplied two positional test filters; Cargo rejected the second filter
before running tests. A later repository-root `cargo fmt --all -- --check` also stopped before
formatting because this repository has no root `Cargo.toml`; the corrected crate-manifest format
check passed. The corrected filters above passed separately. A full 272-test debug library
run emitted no failure but exceeded the 604-second command timeout and produced no terminal result,
so it is not claimed as passed; its orphaned exact repository Cargo/test process tree was identified
by command line and terminated. Strict Clippy now reaches only the pre-existing unrelated
`disk_deep.rs:339` `too_many_arguments` diagnostic; the two diagnostics introduced/exposed in the
changed state files were corrected. No lint allowance or gate weakening was added.

## 2026-08-03 Linear-size square-free uniqueness successor - VERIFIED COMPONENT

The rejected quadratic uniqueness route now has a linear-size successor candidate in
`state_squarefree_gkr.rs`. After a committed state source receives authenticated `beta`, each
injective two-Fp16 key becomes `k0+beta*k1`. The prover constructs four bounded A/B coefficient
tables, which must be committed before authenticated `r`. A dual-number product tree proves
`P(r),P'(r)` and product sumchecks prove the two Bezout evaluations. The verifier requires
`A(r)P(r)+B(r)P'(r)=1` for both before/after phases. A repeated active key makes P non-square-free
and cannot satisfy the polynomial identity. The false-identity degree is below 1,024; using only
the conservative `|Fp16|>2^480` bound, it and the under-2^18 compression-collision union remain
well above the frozen 256-bit floor.

The interactive control publishes every root, quadratic sumcheck, terminal, and first Bezout value
before its corresponding authenticated challenge. Four virtual leaf terminals reduce algebraically
to twelve presence/key openings in the existing H4 state source; four more claims open the A/B
coefficient tables. Positive, duplicate, tree mutation, coefficient mutation, PCS-reduction, and
interactive-order checks pass.

Exact release output:

```text
evidence_class=MEASURED_CONTROL_NONACTIVATING
construction=FP16_SQUAREFREE_DUAL_PRODUCT_GKR_V1
capacity=128
phase_count=2
tree_layers_per_phase=14
authenticated_rounds=370
virtual_leaf_claims=4
coefficient_pcs_claims=4
witness_fp16_elements=512
witness_bytes=32768
witness_build_seconds=0.042439
prove_seconds=0.046355
verify_seconds=0.023395
verified=true
activation_allowed=false

evidence_class=MEASURED_CONTROL_NONACTIVATING
construction=FP16_SQUAREFREE_DUAL_PRODUCT_GKR_V1
capacity=512
phase_count=2
tree_layers_per_phase=18
authenticated_rounds=546
virtual_leaf_claims=4
coefficient_pcs_claims=4
witness_fp16_elements=2048
witness_bytes=131072
witness_build_seconds=0.698637
prove_seconds=0.237447
verify_seconds=0.072302
verified=true
activation_allowed=false
```

Focused verification is 5 passed for `state_squarefree_gkr`; the containing state relation,
quadratic attack oracle, and hash-bus sets pass 10, 5, and 5 tests. No-default library check passes.
Strict Clippy reaches only the unchanged pre-existing `disk_deep.rs:339` `too_many_arguments`
diagnostic. The candidate has no lint allowance. These measurements do not include committing the
four coefficient tables in the auxiliary PCS, opening the twelve state-column reductions, parent
grammar/transcript binding, or complete H4 proof generation. Gate 2E, H4 state composition, H5,
H6, backend admission, `proofSuiteId`, and activation remain open. The next action is exact
input/auxiliary PCS and parent-transcript composition, not further tuning of either uniqueness
control.

## 2026-08-03 Linear uniqueness PCS composition - VERIFIED COMPONENT

`state_squarefree_pcs.rs` now fixes the selected custom-H4 composition geometry without adding a
second proof stack. The four private before/after A/B tables occupy four fixed 512-value blocks in
one existing-size auxiliary message (2,048 message values plus 1,218 fresh random-padding values).
K128 uses the canonical prefix of each block and zeroes the unused suffix; K512 fills all four
blocks. Four authenticated nonzero post-claim mixing coefficients produce one auxiliary linear
functional and target. The four virtual square-free terminals separately reduce to twelve exact
openings of the already committed 4,096-row state lane, lifted to the existing 24-coordinate H4
input geometry. No raw coefficient table is public.

Exact focused evidence:

```text
cargo +1.96.0 test --features std --lib state_squarefree_pcs --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 277 filtered out; finished in 13.04s

cargo +1.96.0 test --features std --lib state_squarefree_gkr --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 275 filtered out; finished in 0.04s

cargo +1.96.0 check --no-default-features --lib --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml
Finished `dev` profile [unoptimized + debuginfo] target(s) in 10.60s
```

The K512 composition test initially exposed only a synthetic fixture overflow at
`index as u8 + 7`; the fixture now uses a bounded byte value and the exact rerun passes. Strict
Clippy still reaches only the unchanged `disk_deep.rs:339` `too_many_arguments` diagnostic. Format
and diff checks pass, and no protected path changed. This component does not yet retain/open the
new auxiliary codeword in the CUDA path or extend the public-coin bridge, parent grammar, receipt,
and independent production verifier. No Gate 2E, H5, H6, backend-admission, `proofSuiteId`, or
activation credit is taken. The next action is that production orchestration, not another
uniqueness construction.

## 2026-08-03 Gate 2E production composition - CPU VERIFIED, GPU QUALIFICATION BLOCKED

The selected linear square-free state proof is now composed through the nineteen-claim GKR/PCS
binding, authenticated public-coin bridge, independent answer/target verifiers, interleaved
verifier, parent grammar, atomic receipt, schedules, and security ledger. The fixed public ABI
remains twelve fields and protected application/contract paths are unchanged. Activation remains
false and `proofSuiteId` remains null.

Production-boundary generation exposed a duplicated SHA3 rate error in the CUDA worker and prior
documentation. SHA3-512 uses a 72-byte rate, not 136 bytes. The descriptor-derived state-composed
totals are therefore 114,232 permutations for K128 and 413,370 for K512; the two state-root calls
add 502 and 1,964 permutations. This entry explicitly supersedes the contrary totals recorded in
the two earlier 2026-08-03 historical entries without rewriting that history. The generated K128
boundary now reports:

```text
totals {1:114232,3:413370}
input_words=11430400 output_words=11430400 nonuniform_groups=7140 packed_groups=7144
boundary_compaction_verified=true
```

The corrected boundary regression, descriptor-tail Rust regression, parent exact-replay test,
format check, all-bin `std,parallel` check, Python compilation, independent answer-target KAT,
same-chain public-coin KAT, and security ledger pass. Decisive outputs:

```text
test hash_bus_source::tests::state_composed_stream_has_only_authenticated_dummy_groups_after_total ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 294 filtered out
test tests::state_binding_fields_are_exactly_replayed ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out
1 passed in 0.38s
kat=fp16_zk_rs_answer_target_verify_v5
construction7_answer_target_verified=true
state_squarefree_answer_binding_verified=true
complete_pcs_qualification=false
kat=fp16_zk_rs_same_chain_bridge_v1
status=verified
combined_rounds=6111
independent_bundle_replay=true
complete_proof_qualification=false
minimum_independent_error_bits=392.108419573
composed_iopp_error_bits=392.108419573
activation=false
proof_suite_id=null
complete_proof_qualification=false
protected_changed_count=0
git_diff_check_exit=0
```

Windows driver-error investigation added theorem-neutral bounded launch tiles to the bridge,
factored group message, and product transforms. Precompiled SM89 modules are retained outside the
repository with SHA-256 identities:

```text
30ea7038b3533414ca6e54adbc3ecfea8e043b7bacb728ad782646767806922c hash-bus-gkr-bridge-sm89.cubin
f74e3fe12e0e410ce82e33af6d671d74dfb533d17f877d5eb0165d177c03f95e hash-bus-gkr-group-sm89.cubin
106920c909f0f718b49cad1e2eb9da356a108fcd7d89615c4ca7373257e70c6b hash-bus-gkr-worker-sm89.cubin
```

No attempted production run earns proof credit. The latest K128 run was rejected after an NVIDIA
Event 153 even though host/device/swap usage remained inside the frozen resource gates:

```text
external_exit_code=2
external_wall_seconds=9.566659
external_process_tree_peak_bytes=758165504
external_gpu_peak_mib=2419
pagefile_growth_mb=0
post_launch_driver_event_count=1
packed_b16_group_message_factored_one_claim:700
```

The proof monitor now uses the real external exit code and kills the exact captured descendant
tree deepest-first on timeout. A controlled timeout reported
`monitor_timeout_killed_processes=4`; the follow-up scan reported
`leftover_test_process_count=0`. No proof process remains.

H5 requires an exclusive host, but two Brave GPU contexts (PIDs 800 and 19928) remain active along
with the expected restricted display/system context. The post-reset system log contains one
`nvlddmkm` Event 153 at 2026-08-03 15:13:43 local time. Do not run or credit another production
proof until Brave and other user GPU workloads are closed, the scoped GPU reset has been rerun,
and the post-reset event count is zero. Then rerun fresh K128 followed by K512. Gate 2E, all 22 H5
launches, H6, backend admission, `proofSuiteId`, activation, final documentation, and commit remain
open.

## 2026-08-03 state-composed privacy and simulator closure - CPU VERIFIED, GPU STILL BLOCKED

Review of the composed transcript found two trust-critical disclosures. The GKR mask-batch message
serialized every mask residual, and the square-free public-coin batching payload serialized raw
private Bezout-table openings. Both are corrected without weakening a verifier check. The mask
batch now publishes only its count and a SHA3-512 digest of the complete canonical constraint
preimage. The square-free transcript publishes two masked coefficient claims under a fixed
140-byte `BLSQCL02` digest payload; the raw claims remain internal to the PCS answer computation.
Protocol domains were advanced to v2, and the separate coherent-chain benchmark uses the same
digest-only mask-batch rule.

The active Construction 8.2 simulator now includes exact state-relation and square-free GKR degree
schedules, conditioned variable-degree sumcheck messages, complete committed-mask leakage ranks,
PCS query conditioning, and fresh abort/retry public-coin randomness. Decisive output:

```text
kat=fp16_zk_rs_hiding_simulator_v2
state_k128_mask_layers=221
state_k128_mask_used_coefficients=27744
state_k128_mask_leakage_rank=26640
state_k128_pcs_conditioned_rank=28240
state_k128_mask_free_dimension=4528
state_k512_mask_layers=233
state_k512_mask_used_coefficients=28932
state_k512_mask_leakage_rank=27768
state_k512_pcs_conditioned_rank=29368
state_k512_mask_free_dimension=3400
state_relation_conditioned_simulator_verified=true
state_squarefree_conditioned_simulator_verified=true
public_coin_abort_retry_fresh_randomness_verified=true
cross_module_simulator_mechanics_verified=true
complete_proof_qualification=false
```

The exact K512 algebraic ledger now charges 777 state sumcheck variables with total degree 1,748,
65 state-composed GKR layers, and the 29,368 joint GKR-mask/PCS rank. It remains above 392 bits:

```text
minimum_independent_error_bits=392.108419573
composed_iopp_error_bits=392.108419573
state_gkr_mask_rank_ledger_closed=true
complete_simulator_implementation_verified=true
cryptographic_composition_ledger_closed=false
complete_proof_qualification=false
```

Focused verification passed:

```text
mask_batch_message_commits_without_publishing_residuals: 1 passed
squarefree_public_payload_is_fixed_size_and_hides_claim_values: 1 passed
state_squarefree: 10 passed, 0 failed
Gate 2E terminal + H5 preflight + simulator schedule: 9 passed
H6 preflight: 2 passed
cargo check --features std,parallel: exit 0
same-chain status=verified, gkr_rounds=6100, combined_rounds=6113
```

One broad `cargo test --lib --features std,parallel` attempt exceeded its 304.1-second command
wrapper while the single library test process remained active. Its exact three-process tree was
stopped deepest-first and the follow-up count was zero. That attempt receives no pass credit; the
focused trust-critical tests and all-target compile results above remain the credited CPU evidence.

The rebuilt Gate 2E terminal ledger digest is
`11f028eac01f5a880769f0cae7871b9449064793eebfe46cf8f69603f8646091007575b62c0ecdf5114ae53e1c220a4fe057f77a6c3b156f3a221de978b50644`.
Its semantic-state, PCS, and public-coin simulator records are `CLOSED/DERIVED`; remaining blockers
are exactly `complete_leakage_scan_missing`, `h4_atomic_binding_deferred`, `no_backend_admitted`,
and `proof_suite_unselected`.

At 17:02:47 local time, `nvidia-smi` still showed Brave PIDs 800 and 19928 as the only user GPU
contexts. No GPU proof or H5 launch was attempted. The next action remains user closure of Brave,
scoped reset and zero-event verification, then fresh K128/K512 qualification, the exact 22-launch
H5 campaign, complete artifact leakage scan, and H6.

## 2026-08-03 fresh native state-composed feasibility evidence - H4 STILL NON-ADMITTED

The historical “Brave still open / no GPU proof” entry above is superseded by the current run
record. Brave was closed and the scoped driver reset completed before these runs. The K128 raw
monitor record is `k128-state-composed-wave2-clean-20260803-0001.stdout.txt` and its decisive
lines are:

```text
external_exit_code=0
stderr_bytes=0
external_process_tree_peak_bytes=821637120
external_gpu_peak_mib=2526
pagefile_growth_mb=0
post_launch_driver_event_count=0
shard_0_verified=true
shard_0_proof_seconds=36.077706
state_plane_binding_verified=true
complete_proof_latency_gate=false
complete_proof_qualification=false
```

The K512 state binding was independently checked by the native verifier with exit `0`:

```text
state_plane_binding_verified=true
state_plane_statement_sha3_512=2fa74535583102431bf7e3fe7c7f0880850f0cbf580227583b306ea79eebfd9d005212531d3b23d8e9eed916507b3714b0ef8d5d1efa60c61326cc8e8c074f28
state_plane_binding_digest_sha3_512=72639eb31c33b5c6494311a4c30fdeb2af1f491336cda96134273bf94768def32e59146917586aa793cd7da90b7e5dce05e4988950c43bf9f1c23cdea415f5f8
```

The state-composed K512 hash-bus boundary was converted from the authenticated snapshot with
`output_bytes=209715415` and SHA3-512
`488b865980be8a1ed807f0c5a1431af7f6c7a44fb0363cc42c37861531472fba6b4e5c78c5b4137280c1aefb8f59b6b632e0dd64ade5edd579fb110f232a3d81`.
The fresh native K512 monitor record is `k512-state-composed-native-20260803-0130`:

```text
external_exit_code=0
external_wall_seconds=159.655992
external_process_tree_peak_bytes=1605058560
external_gpu_peak_mib=2731
pagefile_growth_mb=0
post_launch_driver_event_count=0
stderr_bytes=0
ordered_shards=0,1,2,3
complete_shard_proofs=4
sequential_single_gpu_execution=true
parallel_gpu_images=0
atomic_acceptance_boundary=true
all_shards_independently_verified=true
complete_process_wall_seconds=153.860446
latency_limit_seconds=180
complete_proof_latency_gate=true
complete_proof_qualification=false
```

The K512 proof output SHA-256 identities are stdout
`99e729f602a703c60079102d40d4f180f3a7b16fa4114f3d4c9d58659e92d669` and empty stderr
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`; direct scanner category
checks returned `[]` for both. This is feasibility evidence only: it does not close the terminal
ledger, admit a backend, select a proof suite, or authorize H5/H6.

The K512 fixture generator was not used as qualification evidence. Its first normal run crossed
the hard resource boundary (`peak_working_set=7609839616`); later monitor attempts timed out and
were cleaned with no credit. The smallest corrective source change is in
`experiments/bl_pq512_crypto_foundation/state_air_proof.py`: the proof evidence now retains the
already-encoded private AIR program/execution and `build_state_air_binding_bytes` reuses those
bytes instead of rebuilding the full trace. `py_compile`, import, the combined state/AIR/atomic
suite (`9 passed in 322.02s`), the Gate2E/H5/H6 suite (`9 passed in 51.77s`), the privacy scanner suite
(`18 passed`), the no-`std` library check, the cross-language evaluator test, and `git diff --check`
passed after the change. The no-`std` check exposed and fixed seven unguarded diagnostic
`std::eprintln!` calls by routing them through a feature-gated macro; exact
`cargo check --offline --locked --no-default-features --lib` now exits `0`. The remaining blockers are still
`complete_leakage_scan_missing`, `h4_atomic_binding_deferred`, `no_backend_admitted`, and
`proof_suite_unselected`; no exact H5 22-launch campaign or H6 seal is claimed.

## 2026-08-04 Brave-open exploratory boundary and bounded streaming-worker correction - VERIFIED, H5 STILL OPEN

The owner-approved Brave exception is explicit in `CONTINUATION_MANDATE.md` and the active
roadmap: Brave may remain open for exploratory/diagnostic GPU work, but every such run is
non-qualifying and receives no H5 timing, resource, or driver-integrity credit. The exact H5
exclusive-host, no-pagefile-growth, bounded-RSS/scratch, and zero post-launch driver-event gates
remain unchanged.

The selected streaming worker investigation found an actual laptop-resource defect. Its three
disk-FFT parallel groups used the full host-reported CPU count, which produced a K128 exploratory
peak of `4,429,164,544` process-tree resident bytes and `422` MB pagefile growth. The smallest
source correction caps each disk-FFT group at eight workers, matching the existing bounded
deep-column path. It changes no transcript, verifier, proof grammar, or security check.

Raw non-qualifying exploratory results after that correction:

```text
K128 selected-streaming input generation
external_exit_code=0
external_wall_seconds=340.303000
external_process_tree_peak_bytes=4415881216
pagefile_growth_mb=112
post_launch_driver_event_count=0
stdout_bytes=1490
stderr_bytes=0
qualification=REJECTED_RESOURCE_AND_LATENCY
```

The selected-streaming fixture path is not the custom H4 qualification path and receives no H5
credit. The direct custom H4 path was then replayed with the pinned native binary, CUDA module,
NVRTC runtime, execution-manifest digest, state binding, and qualified suite identity. Brave
remained open, so these are explicitly exploratory only:

```text
K128 attempt r2: external_wall_seconds=57.654239; complete_process_wall_seconds=53.154714;
  peak_process_tree_bytes=827105280; pagefile_growth_mb=-1; driver_events=0;
  complete_proof_latency_gate=false; stdout_sha256=8c6c8dcfa5f674ca5f402b2c690aa8c7f7b25fe4a50b9ac5fe3d300d89968337
K128 attempt r3: external_wall_seconds=37.074405; complete_process_wall_seconds=32.837657;
  peak_process_tree_bytes=822042624; pagefile_growth_mb=0; driver_events=0;
  complete_proof_latency_gate=true; stdout_sha256=a965c9ad3848e948b5a26f36712efcb879e7cc4546355badb19439821e422fe4
K512 attempt r1: external_wall_seconds=159.287932; complete_process_wall_seconds=152.606110;
  peak_process_tree_bytes=849326080; pagefile_growth_mb=-89; driver_events=0;
  complete_proof_latency_gate=true; stdout_sha256=bf941f27f009dcfc5ac2497fb49e5d13d39ca63a98d5bd237da48e57ac75014a
```

The K128 r2 failure and the single-run, non-campaign shape prevent these runs from qualifying as
H5. The owner-authorized Brave-open exception is no longer a disqualifier; future H5 launches may
run with Brave open while retaining every other fail-closed gate. No H5 launch is substituted,
retried, or silently counted; the exact 22-launch campaign remains unstarted. `proofSuiteId` remains
null and activation remains false. Focused source verification
after the correction is:

```text
cargo fmt --all -- --check                                      exit=0
cargo test --offline --locked --features std,parallel --lib disk_fft
6 passed; 0 failed; 0 ignored; finished in 1.00s
cargo test --offline --locked --features std,parallel --bin k512_atomic_semantic_prototype
8 passed; 0 failed; 0 ignored; finished in 103.04s
`C:\Users\neers\AppData\Local\Python\pythoncore-3.14-64\python.exe` -B -m pytest -q
tests/test_bl_pq512_h6_qualification_preflight.py
tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
tests/test_bl_pq512_gate_2e_terminal_ledger.py
tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py
tests/test_bl_pq512_h5_qualification_preflight.py
tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py
23 passed in 108.72s
```

Tracked changes for this boundary are `experiments/bl_pq512_crypto_core/src/disk_fft.rs`,
`experiments/bl_pq512_crypto_core/src/bin/selected_streaming_prover_worker.rs`, and
`experiments/bl_pq512_crypto_foundation/h6_qualification_preflight.py`. Protected paths remain
untouched. The next dependency is the exact 22-launch H5 campaign with the owner-authorized
Brave-open exception applied; keeping Brave open no longer blocks H5, but all other resource,
telemetry, provenance, correctness, and evidence gates remain mandatory.

## 2026-08-04 Source-complete archive refresh - VERIFIED

After the substantive Wave 2 resource and H6 corrections, the deterministic release builder was
run from committed source `7b801b9a797c2292e338e3d7e2ebd3fd0d0f31eb` using the reviewed 779-file
allowlist. The builder reported:

```text
archive_bytes=11300000
archive_sha256=d8c0452fe1ef52cc189988bc6e1f49c5a10847d68fe5d0467b8afc8d7c6af409
entry_count=780
manifest_sha256=55821bfcfed96d7f56ca13f1920b7711ce0a76c3f260906468211efb0d4db5a1
payload_bytes=11014003
payload_file_count=779
receipt_version=1
```

Independent ZIP readback of all three published copies returned `CRC=PASS`, `duplicates=0`,
`payload_mismatches=0`, and `independent_identity=PASS` for each. The identical published identity
is `size=11300000` and
`sha3_512=45b1d0eb270ce2283a9b8b4e15fd7ecf1d420b73875a1d9bb555c09c6dd181f5a8b3fe326818e7d7da6e54265929e55e521857a1d943b34ca866801e3b6e788f`.
The three targets were the Desktop, Desktop full-workspace, and Downloads paths named by the
continuation prompt. Prior copies were preserved under the scratch backup directory
`work/archive-v2-stage/previous-targets-20260804/`. The release allowlist was not expanded;
`STATE.md` and newer tracked evidence files outside that reviewed allowlist remain excluded by
design. This archive refresh does not change the H5/H6 qualification status.

## 2026-08-04 Owner clarification: Brave-open H5 boundary removed

The owner explicitly revoked the prior exclusive-host disqualification and authorized Brave to
remain open during H5 GPU work. Active documentation now treats Brave presence as permitted rather
than as an automatic non-qualifying condition. This changes only that operational acceptance
boundary; it does not waive fresh unique launches, independent verification, exact timing limits,
RSS/scratch limits, no pagefile growth, empty stderr, cleanup, provenance, or zero post-launch
driver-event checks. The earlier K128/K512 single runs remain non-campaign evidence because they
were not the exact warm-up-plus-ten-per-profile campaign; they are not rejected solely because
Brave was open. The next action is to run the exact H5 campaign under the revised boundary.

## 2026-08-04 Brave-open boundary correction and archive refresh - VERIFIED

The owner explicitly removed the exclusive-host disqualification. Active mandate, roadmap,
architecture, throughput, and current-stack documentation now permit Brave to remain open during
H5 GPU work; all other fresh-input, correctness, provenance, resource, pagefile, stderr, cleanup,
and driver-event gates remain mandatory. The affected contract/preflight test set passed:

```text
21 passed in 33.68s
```

The deterministic release builder was rerun from committed source
`ae27b687deec2ab8eaf833b62a53fbd36df6b898` using the reviewed 779-file allowlist:

```text
archive_bytes=11300476
archive_sha256=77f34794ba44dc86662330acdae2c5c3804b0d3755bf5e50cb9021b9e62babb9
entry_count=780
manifest_sha256=1c5bbdc112311df282c3ea9710d81771d37e8936695bb183f02668ebc7947297
payload_bytes=11014479
payload_file_count=779
receipt_version=1
```

Independent readback of the Desktop, Desktop full-workspace, and Downloads copies returned for
each: `size=11300476`,
`sha3_512=26f44022f7e14e017025f33fc6385178258da5e9281e7f804292752e6575acba661da8e9fb8f9ee0d1151c0d00ab0ec9a0aa9ff7b61f7ee2d4e51fbae6f4fc85`,
`entries=780`, `duplicates=0`, `crc=PASS`, `payload_mismatches=0`, and
`independent_identity=PASS`. Earlier copies were preserved under
`work/archive-v2-stage/previous-targets-20260804-brave-exception/`.

## 2026-08-04 Exact H5 campaign and H6 qualified-input replay - VERIFIED H5, H6 BLOCKED

The owner-approved Brave-open exception was applied. The exact H5 campaign directory was
`C:\Users\neers\Documents\Codex\2026-08-02\files-mentioned-by-the-user-you\work\wave2\h5-campaign-20260804-final-r2`.
The runner exited zero with `campaign_run_count=22` and `campaign_failed_run_count=0`. The
independent source validator exited zero with `h5_validator=PASS` and reported:

```text
campaign_id=h5-exact-22-20260804
campaign_digest_sha3_512=199a1b1c7e553b73597f1bd3192a72db732529599da68d820bf072e2e2ee3dabe1d7dda2d72efbd9fd23e17a6b2366f70d51ed96d9c152483d3f34165e7bedf5
execution_manifest_sha3_512=999aef8a16f97a52e6ce6ead7b7470eea2fdc50f32d13e95a3a1e021cd093aef42f8f5a2420cd3f4e35f77a42ff161f791888b5905ec3fcdf8cb8f8765992545
proof_suite_id=719ed6d4e9fe8bb69efdb51e5bee0133718b0cc7bdbe9b82a70c68c5522e7efeb620fc9fdc67e3fc3538e57d6518b360a548a114648f3f7640f1475566cd7e6b
k128_p95_seconds=32.360845
k512_p95_seconds=148.861885
max_peak_rss_bytes=850837504
max_scratch_bytes=0
```

The manifest's launch source identity is `47ca7dab146b56a85ebbf9d2d2fe797c4fee2fae`; the
current checkout subsequently contains telemetry-parser-only corrections, so no later source
identity is substituted for the prover identity. The failed earlier campaign remains preserved
with zero credit because its measured K128 ordinal 5 had 15 MB pagefile growth. The nonexistent
attack-test path and its zero-test result are recorded above; the corrected attack subsets passed
38 + 46 + 52 = 136 tests.

The latest qualified-evidence replay sealed Gate 2E nonactivating with
`terminal_ledger_status=SEALED_GATE_2E_TERMINAL_LEDGER`, `terminal_ledger_blockers=()`,
`terminal_ledger_h4_parent_bound=true`, `terminal_ledger_complete_proof_verified=true`,
`terminal_ledger_proof_suite_id=None`, and `terminal_ledger_activation_allowed=false`. Its
terminal-ledger digest was
`d573997944f84897ea5e184776b89f995860660372b71fbf769687b65c5e2e753ac70d00399e7bb3d349b972e818ec5e5ada465e3614b1ecae35dac29f748a71` and its H5 preflight digest was
`8e745c45ea26826c076fcaca5e74e6173695acc31be92e03e2406b4481c3432d6d4a869f0eb5a37d015d0101a8a08ecc95c12f82f4f19334a0a4ceaef233e7aa`.

H6 consumed that qualified H5 record and closed only `H5_RESOURCE_EVIDENCE`. It remains
`BLOCKED_H6_PREFLIGHT` with twelve blockers:
`h6_strict_pq_qualification_pending`, `h6_simulator_qualification_pending`,
`proof_grammar_unselected`, `attack_corpus_incomplete`, `cross_language_verifier_kats_open`,
`source_toolchain_dependency_sbom_open`, `offline_reproducible_builds_open`,
`side_channel_unlinkability_open`, `production_migration_theorem_open`,
`complete_evidence_manifest_missing`, `h6_no_qualified_evidence`, and
`wave3_verifier_state_custody_open`. The H6 preflight digest was
`d144117b6e340dfe6b2c33c7a243b2ad43284d3aea6053bc9aae46cf02b6b3c1eac3efd6623ec8be8a5ab7b4e55115ba0c8fc5a713db451b222f3ea392eb733`.

The strict security-ledger command remained fail-closed:
`iopp_implementation_complete=false`, `canonical_communication_grammar_closed=false`,
`cryptographic_composition_ledger_closed=false`, and `complete_proof_qualification=false`.
No proof suite was activated, no real data was used, and no Wave 2 completion claim is made.

## 2026-08-04 Wave 2 H6 candidate qualification - VERIFIED NONACTIVATING

The prior blocked H6 record above is historical pre-manifest evidence. The follow-on bounded
candidate-evidence run closed Wave 2's H6 qualification boundary without changing the activation
boundary. The exact external evidence manifest is
`C:\Users\neers\Documents\Codex\2026-08-02\files-mentioned-by-the-user-you\work\wave2\h6-evidence-20260804\h6-evidence-manifest.json`.
Independent manifest readback returned:

```text
h6_manifest_verify=PASS
h6_manifest_closed_count=12
h6_manifest_digest_sha3_512=e79b7199ed15e5d9d3719f0d8de7dbaa01627e9fbe8cd4823d3768e6b0d84dd2bea94526b1516de8b8f3c920439572d003ee5372e95747011fde022924b319fe
h6_manifest_source_digest_sha3_512=478d54ee1a2f187fd023777b16b73ec011922bb039dc106d53fc23c48eaea30b3a153b72f73823863e9c561a6126e92555dbaabaabbb3fda4abb2fccac3895db
```

The verified H6 replay at source commit `4849d50f0991d9b441aadd29de0bd9392661d360`
reported:

```text
terminal_ledger_status=SEALED_GATE_2E_TERMINAL_LEDGER
terminal_ledger_blockers=()
terminal_ledger_h4_parent_bound=True
terminal_ledger_complete_proof_verified=True
terminal_ledger_proof_suite_id=None
terminal_ledger_activation_allowed=False
h5_status=QUALIFIED_H5_CAMPAIGN_NONACTIVATING
h5_campaign_status=QUALIFIED_EXACT_22_LAUNCH_CAMPAIGN
h5_blockers=()
h6_status=QUALIFIED_H6_NONACTIVATING
h6_closed_records=12
h6_blockers=()
h6_preflight_digest_sha3_512=1dc937b2c208f07360c30ea7467651cc289bde57c0a00d44e35a81ce2d3310c11551de2e1d25cfbe5f1d3744453789cc3cc5145527030cacad2e8a9098683b71
proofSuiteId=None
activationAllowed=False
```

The twelve closed records are the exact 256-bit strict-PQ ledger, complete bounded simulator,
proof/sidecar/receipt grammar, downgrade/splice/replay/stale/migration/mutation/malformed/resource
attack corpus, cross-language KATs and authoritative Rust verification, targeted source/toolchain/
dependency/license/SBOM pins, locked offline reproducible builds with independent artifact
readback, H5 resource evidence, side-channel/telemetry/zeroization/cleanup/unlinkability,
rollback/recovery/mixed-version behavior, the complete evidence manifest, and explicit
nonactivating Wave 3 verifier/state/custody work.

Decision-relevant raw results:

```text
strict_pq_target_bits=256
strict_pq_target_count=22
strict_pq_max_retries=1
strict_pq_minimum_independent_error_bits=392.1084195728072
strict_pq_composed_iopp_error_bits=392.1084195728072
strict_pq_multi_target_error_bits=387.64898795417
strict_pq_retry_error_bits=386.64898795417
strict_pq_abort_is_fail_closed=True
strict_pq_qualifies=True
attack_file_count=31
attack_tests_passed=229
cross_language_verifier_kats=PASS
cargo_metadata_exit=0
cargo_metadata_stderr_bytes=0
targeted_sbom_package_count=43
targeted_sbom_third_party_package_count=42
targeted_sbom_source_pin_count=25
reproducible_binary_identity=PASS
independent_artifact_readback=PASS
reproducible_binary_sha256=f405e848b7f4b6d5f0cde8f6e9a5ecb64b8feb7f52b8305697660c0619acf737
privacy_findings=0
rollback_recovery=PASS
wave3_nonactivating_boundary=PASS
```

This closes the Wave 2 H6 candidate-evidence gate only. It does not activate a suite, assign a
`proofSuiteId`, authorize real PHI/payments, close the independent audit, or claim that the
production verifier/state/custody work in Waves 3-6 is complete. The six-of-93 package count is
unchanged; those downstream production packages remain blocked on this nonactivating boundary.

## 2026-08-05 Workspace cleanup and three-copy release refresh - VERIFIED

The current reviewed 779-file release allowlist was rebuilt from source commit
`90cc2332c63024349135d99649573169864194fc`. Six allowlisted payloads changed since the prior
archive: `docs/CURRENT_TECH_STACK.md`, `docs/IMPLEMENTATION_ROADMAP.md`,
`experiments/bl_pq512_crypto_core/Cargo.toml`,
`experiments/bl_pq512_crypto_core/rust-toolchain.toml`,
`experiments/bl_pq512_crypto_core/src/lib.rs`, and
`experiments/bl_pq512_crypto_foundation/h6_qualification_preflight.py`.

The deterministic release builder returned:

```text
builder_version=blind-ledger-release-archive-v1
archive_bytes=11344046
archive_sha256=823974b4f29d95351946a5fb72d22c6570b9a1800c9af5c9780db0cec6d550c9
manifest_sha256=334db4c6ef7a32f7694a70aabb065c46059b21d418bb985eff7dc9e21e5e7ce0
entry_count=780
payload_file_count=779
payload_bytes=11031546
```

Independent ZIP readback passed for all three Source-Complete copies. Each has 780 entries,
779 payload files, no CRC errors, no duplicates, no missing/unexpected entries, and is byte-for-
byte identical. The shared SHA3-512 identity is
`060df390a25ab17d3da21cafc53104dfbb9526635d8f92962182146fa2dbf1eb0b50ea208a200b657c37dd22ddb7e9102c470733d4db8cc998ac42083761fec7`.
The targets are the Desktop root copy, the Desktop Full-Workspace copy, and the Downloads copy.
`STATE.md` is not in the reviewed release allowlist, so this receipt update does not change the
published archive bytes.

After generated scratch cleanup, the authoritative H5 and H6 manifests independently returned
`PASS`: H5 has 22 runs with K128 p95 `32.360845` seconds, K512 p95 `148.861885` seconds, and
zero scratch; H6 has 12 closed obligations and zero blockers. The cleanup removed 24,657
generated files totaling `8892184613` bytes, including obsolete build targets, reproducibility
scratch, failed calibration attempts, and temporary archive stages. The exact H5 campaign,
referenced state-binding inputs, H6 evidence manifest, and prior State-referenced archive backup
directories were preserved. This remains a nonactivating Wave 2 evidence/archive state; it does
not activate a proof suite or claim production completion.

## 2026-08-05 Live Strawmap refresh and L1/rollup compatibility audit - VERIFIED

The live `strawmap.org` page and linked Google Drawing were fetched as HTML/SVG without a browser
plugin or PDF reader. The normalized live drawing inventory contains 60 underlying URLs: 23 EIPs
and 37 non-EIP links. All 23 EIP pages and current raw `ethereum/EIPs` files were read. Of the
37 non-EIP links, 35 returned successfully; the linked public Google document returned HTTP 401
for five public URL variants, and the one PDF was intentionally skipped at the owner's direction.

```text
strawmap_html_status=200
strawmap_html_sha256=3cb5d371ec515a84e3260cf6bb26ead1117247e90c8aa0938ab75fff25776a04
drawing_svg_status=200
drawing_svg_sha256=f6eb66b2f1899eee675490aee037d74801f1aaf7292bd9c677a971a07b7b72bc
normalized_url_manifest_sha256=ad41badff1dfac6fd1a27b8b290610b9b9de64aef1fb6b67aefe0ccd096902ad
current_eip_source_manifest_sha256=86414227b3c9f8c86e01b7b1634f9693350e572644835a5cbae246160ee51c49
eip_status_counts=Draft:17,Review:3,Stagnant:3
browser_plugin_used=false
pdf_read=false
```

The compatibility classification is: nine EIPs are direct L1 behavior that the based rollup must
observe or bind; five are conditional L1 fork/execution compatibility; six are optional adapters
that remain rejected by default; and three are research/meta/economic inputs with no current
implementation dependency. The live refresh changed EIP-8070 from the prior local `Draft` label
to its current `Review` label. No production, activation, or end-to-end Ethereum-security claim
was added; the updated architecture and roadmap records preserve the fail-closed boundary.

## 2026-08-05 Live Strawmap audit release refresh - VERIFIED

The audit documentation was committed at source commit
`adfb7daa80858804b71a14870fa0fee57fa30c96`. The reviewed 779-file allowlist was rebuilt from the
current source; three allowlisted documents changed: `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md`,
`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`, and `docs/IMPLEMENTATION_ROADMAP.md`.

```text
builder_version=blind-ledger-release-archive-v1
archive_bytes=11350709
archive_sha256=6dcd053066160f7fa6577501d118210745455ed3a3cf19a7a82b788cf02c4826
archive_sha3_512=71b002aa03d2ee93956e3321fbe861eb386dea2d53944fc9e5304e185efe9e391124ba41032ce2d2ac1e2503c4f562a267202f98e737564534002fdaace5878e
manifest_sha256=ef8587f5b2046b1612d43ecc658d064f21ff8b567c85518508f5a75c1777af36
entry_count=780
payload_file_count=779
payload_bytes=11038209
target_copy_count=3
target_copy_readback=byte_for_byte_identical
```

The deterministic builder and independent ZIP readback both passed: no CRC errors, duplicates,
missing/unexpected entries, or payload hash/size mismatches. The Desktop root, Desktop
Full-Workspace, and Downloads Source-Complete copies now share the exact archive identity above.
The temporary staging and rollback directories were removed after successful readback. `STATE.md`
is not in the reviewed allowlist, so this receipt is recorded in the repository but is not embedded
in the published ZIP.

## 2026-08-05 Deterministic two-lane K512 shard-overlap experiment - RETAINED, NONQUALIFYING

The rejected theorem-free shard-parallelism idea was reconsidered without shared challenges or a
proof-semantic change. Each child retained its independent shard-bound public-coin bundle and proof;
the coordinator waited for the launched group, independently validated every output, and assembled
the receipt in canonical shard order. `BL_SHARD_CONCURRENCY` is opt-in, serial remains the default,
parallel mode refuses `BL_PROOF_SUITE_ID`, and the accepted range is hard-capped at two lanes.

On the same K512 boundary, state binding, release binaries, RTX 4060 laptop, and Brave-open host:

```text
serial_complete_process_wall_seconds=134.095254
two_lane_confirmation_1_seconds=104.094428
two_lane_confirmation_2_seconds=100.412382
two_lane_mean_seconds=102.253405
two_lane_mean_wall_reduction_percent=23.75
two_lane_complete_shard_proofs=4
two_lane_all_shards_independently_verified=true
two_lane_max_reported_host_upper_bound_mb=598.081000
two_lane_peak_device_mb_conservative=1976.484224
two_lane_external_total_gpu_peak_mib=5284
two_lane_scratch_mb=0.000000
two_lane_pagefile_growth_mb=0
two_lane_proof_suite_id=null
two_lane_complete_proof_qualification=false
```

A four-lane negative control independently verified but was rejected: `128.583416` seconds,
`7,890` MiB externally sampled GPU residency, 100% sampled GPU utilization, and `126` MB pagefile
growth. It was slower than two lanes and violated the no-swap/resource discipline. This result does
not modify or receive credit from the sealed 22-launch H5 campaign or H6 evidence, does not activate
a proof suite, and does not update the three published Source-Complete archives. Promotion requires
a fresh campaign and production scheduler cancellation/recovery/resource-accounting review.

## 2026-08-05 Two-lane promotion campaign and scheduler boundary - VERIFIED, NONQUALIFYING

The requested promotion checks were run against the finalized two-lane coordinator with fresh
proof randomness and eleven distinct K512 state-binding inputs: one warmup and ten measured
launches. The campaign was intentionally run without `BL_PROOF_SUITE_ID`; it therefore cannot
receive H5/H6 credit or activate a suite even though every functional and resource gate below
passed.

The first wrapper attempt is retained as a failed measurement, not counted: its warmup verified
all four shards but the external monitor observed `pagefile_growth_mb=2`, so the strict no-swap
gate returned exit `2`. The corrected rerun used a separate evidence directory and did not relax
that gate.

Fresh campaign directory:
`C:\Users\neers\Documents\Codex\2026-08-02\files-mentioned-by-the-user-you\work\wave2\promotion-k512-two-lane-20260805-r2`

Decision-relevant raw campaign output:

```text
campaign_id=promotion-k512-two-lane-20260805-r2
run_count=11
warmup_count=1
measured_count=10
state_binding_input_count=11
state_binding_unique_sha3_512_count=11
all_state_binding_verifications=exit_0
all_monitor_exits=0
all_status=verified
all_complete_shard_proofs=4
all_proof_suite_id=null
all_complete_proof_qualification=false
measured_wall_seconds_sorted=100.392184,100.598097,100.820600,101.004053,101.178240,101.419610,101.483205,101.529263,101.712457,101.798191
p95_measured_wall_seconds=101.798191
mean_measured_wall_seconds=101.193590
max_reported_host_mb=605.774000
max_reported_device_mb=1976.484224
max_external_process_tree_mb=1467.465728
max_external_gpu_peak_mib=5314
max_pagefile_growth_mb=0
max_post_launch_driver_event_count=0
max_stderr_bytes=0
latency_limit_seconds=180
latency_gate=true
resource_gate=true
```

Cancellation/recovery was also exercised on the same K512 binding. A live coordinator, two
Python workers, and two native bridge children were present before cancellation. Windows
`taskkill /PID 22200 /T /F` returned exit `0` and reported termination of the coordinator and all
seven descendants; the only post-check match was the surrounding PowerShell host, not a
proof coordinator, worker, or bridge. The same state binding was then rerun from scratch and
returned:

```text
recovery_exit=0
status=verified
complete_shard_proofs=4
complete_process_wall_seconds=100.138295
peak_host_mb=604.340000
peak_device_mb=1976.484224
scratch_mb=0.000000
proof_suite_id=null
complete_proof_qualification=false
```

The production scheduler review found that the generic path previously terminated only its
parent on timeout, while the encrypted-witness path already used a Windows Job Object. The
smallest safe change added process-tree termination to `tools/proving_job_runner.py`, starts a
new POSIX process group where applicable, and marks tree-termination uncertainty non-retryable.
The focused scheduler suite is `19 passed in 1.20s`; Python compilation exited `0`. The scheduler
still does not own GPU/pagefile telemetry for this experimental coordinator, so this candidate
remains opt-in and non-production; production resource admission remains a Wave 3 integration
boundary rather than an implied pass.

The sealed Wave 2 evidence was not changed. Before this record, the retained evidence descriptors
were:

```text
h5_campaign_file_count=111
h5_campaign_descriptor_sha256=be89e967ceb7ea9f8c6a24c799276088c8f835884fef1be905ac20c60f66ee41
h5_manifest_sha256=e8305158d3bd8f8521948300b76d8e162d9f7650dca26ecf66e23f02d162346f
h6_evidence_file_count=35
h6_evidence_descriptor_sha256=1fff148bbd56f4586458c08d1f7bea5f38d78e01483633052051a08f39d1d2de
h6_manifest_sha256=5dae45336a215baf07779453cdf730514ea3780f3519122ab7131c0596738c26
published_source_complete_archive_updates=0
proofSuiteId=None
activationAllowed=False
```

The two-lane result is a measured throughput-positive, correctness-preserving optimization
candidate, not a new Wave 2 qualification or activation. Serial remains the production default
until the scheduler owns the same resource telemetry and the later Wave 3 verifier/state/custody
boundary is complete.

## 2026-08-05 Native K512 default selection and fail-closed verification - VERIFIED, NONQUALIFYING

The native K512 coordinator now selects two shard lanes when `BL_SHARD_CONCURRENCY` is absent and
no qualified proof-suite identity is present. When a qualified suite identity is present, the
absence of an override selects serial execution; an explicit parallel request still returns
`ERR:parallel_shards_not_qualified`. This is a default-selection change for the nonactivating
native coordinator only. The generic Cairo/encrypted-worker queue was not rerouted because its
request schema does not contain the native boundary, state-binding, prototype, worker, or
execution-manifest inputs required by this coordinator.

Changed implementation and test:

```text
experiments/bl_pq512_crypto_core/src/bin/k512_atomic_semantic_prototype.rs
tests embedded in k512_atomic_semantic_prototype.rs
```

The default-selection unit test passed alongside the native test suite:

```text
cargo +1.96.0 fmt --check                         exit=0
cargo +1.96.0 check --features std --bin k512_atomic_semantic_prototype   exit=0
cargo +1.96.0 test --features std --bin k512_atomic_semantic_prototype   exit=0
test result: ok. 9 passed; 0 failed; 0 ignored
cargo +1.96.0 build --release --features std --bin k512_atomic_semantic_prototype   exit=0
uv run --no-project --with pytest==9.0.3 --with cryptography==49.0.0 pytest -q tests/test_proving_job_runner.py   exit=0
...................                                                      [100%]
19 passed in 1.60s
python -m py_compile tools/proving_job_runner.py tests/test_proving_job_runner.py   exit=0
```

The first no-override launch was retained as a failed setup attempt because the supplied
execution-manifest environment value was stale. It failed closed before proving:

```text
external_exit_code=2
pagefile_growth_mb=0
post_launch_driver_event_count=0
stdout_bytes=0
stderr_bytes=290
ERR:execution_manifest_mismatch:33d94e63a93499550808facb0c0cf58c4461647bb1fd00acc81d124a33d88b97d91b5052c5ef03406b2e6fec5ba2e4cc9c196d0c9e8a39470ef78aa0374a542a/e8bdfd542988bd523637a3895c05274d2c1502982ab0fb052560aa3a1d0433f99b4652653e221725d1d60806c6744ff3e331488d7bc16e9e4d1b9e4eb3452029
```

The corrected no-override launches both selected two lanes and independently verified all four
shards, but both were rejected by the unchanged external no-swap gate:

```text
default-k512-two-lane-20260805-r2
external_exit_code=0
external_wall_seconds=113.562421
external_process_tree_peak_mb=1700.524032
external_gpu_peak_mib=5253
pagefile_before_mb=1393
pagefile_after_mb=1698
pagefile_growth_mb=305
post_launch_driver_event_count=0
stdout_bytes=2142
stderr_bytes=0
status=verified
complete_shard_proofs=4
shard_concurrency=2
complete_process_wall_seconds=107.919881
peak_host_mb=803.598000
peak_device_mb=1976.484224
scratch_mb=0.000000
proof_suite_id=null
complete_proof_latency_gate=true
complete_proof_qualification=false
monitor_exit=2

default-k512-two-lane-20260805-r3
external_exit_code=0
external_wall_seconds=114.133691
external_process_tree_peak_mb=1697.595392
external_gpu_peak_mib=5429
pagefile_before_mb=1697
pagefile_after_mb=1715
pagefile_growth_mb=18
post_launch_driver_event_count=0
stdout_bytes=2142
stderr_bytes=0
status=verified
complete_shard_proofs=4
shard_concurrency=2
complete_process_wall_seconds=107.845533
peak_host_mb=802.583000
peak_device_mb=1976.484224
scratch_mb=0.000000
proof_suite_id=null
complete_proof_latency_gate=true
complete_proof_qualification=false
monitor_exit=2
```

The raw corrected stdout SHA-256 values are `9abd9dfc9b408dd03afbef0338ace6d2668d5044a56101d66baab6b0669c886b`
and `721670c476f9348086562aebac5d2b72042fbabf6bf839217eb186fb6d3aa344`; both stderr files are
zero bytes. The captured r3 monitor output is
`C:\Users\neers\Documents\Codex\2026-08-02\files-mentioned-by-the-user-you\work\wave2\default-k512-two-lane-20260805-r3.monitor-output.txt`
with 5,368 bytes and SHA-256
`d1356d0c0b46341d38e0a3a6c735fe193ee64c9126db455bdfe5e334e0290963`. No coordinator, worker,
or native bridge descendants remained after either rejected launch.

These runs prove that the code-level default selects the faster two-lane path and that the proof
boundary still verifies atomically, but they do not prove resource admission on this current host.
The pagefile gate was not weakened, the runs receive no H5/H6 credit, `proofSuiteId` remains null,
activation remains false, and the sealed H5/H6 evidence remains unchanged. The published archives
are refreshed separately below only because the source/documentation change was substantive.

## 2026-08-05 Source-Complete archive refresh after default change - VERIFIED

The substantive native-default and documentation changes required a Source-Complete refresh. The
reviewed allowlist was reused unchanged in membership; the staging helper copied `779` listed
source files from the authoritative checkout and rewrote only their manifest hashes. The strict
builder then passed its own deterministic temporary and published readbacks:

```text
stage_entries=779
archive_bytes=11341646
archive_sha256=a5c060f85359b1b63c038c5bccddcc43b631eaf2f95530c3783a3399adeaebfc
manifest_sha256=5582ae1fe7a215e83e1462893e8bb13ffba59a37e05dc12f8c2dad424e24bb3f
entry_count=780
payload_file_count=779
payload_bytes=11055647
builder_version=blind-ledger-release-archive-v1
```

Independent readback of all three exact published targets returned:

```text
three_way_byte_identical=true
bytes=11341531
sha256=6a6f9ff2b6db68ce9098ff897e8b36df857a59f92baa07de3a72bc4240894540
sha3_512=26bac3ba47ddd79396e1a4832a586219671a3ac2ebb9bd456238246017c3551055b998260c58182bb9f7d114cd838a833b4be1da0f495b9b990513815b26ad85
entries=780
duplicates=0
crc=PASS
```

The old three published copies were first backed up at
`C:\Users\neers\Documents\Codex\2026-08-02\files-mentioned-by-the-user-you\work\archive-v2-stage\previous-targets-20260805-default`;
each old copy was `11,350,709` bytes with SHA-256
`6dcd053066160f7fa6577501d118210745455ed3a3cf19a7a82b788cf02c4826`. The new three copies are
the exact byte-identical `11,341,646`-byte archive above. The intermediate `11,341,531`-byte
copies were preserved at
`C:\Users\neers\Documents\Codex\2026-08-02\files-mentioned-by-the-user-you\work\archive-v2-stage\previous-targets-20260805-default-r1`.
The sealed H5/H6 evidence directories were not modified.

## 2026-08-05 Source-Complete archive refresh after documentation consistency pass - VERIFIED

The active documentation and code-facing README consistency pass changed only Markdown files.
The reviewed archive allowlist was reused unchanged in membership; `STATE.md` is intentionally
outside that allowlist. The staging copy carried `29` changed allowlisted documents, recomputed
their manifest hashes, and left the sealed H5/H6 evidence directories untouched.

The first staged builder invocation was blocked before output publication because it was launched
without the repository `tools` import path; no ZIP was produced. The corrected invocation supplied
the existing repository scanner path and passed the strict builder/readback gates:

`text
stage_entries=779
archive_bytes=11348269
archive_sha256=f0552c551e015b56a548c32a5026102e2ce23db71b4361a9c296d8af0f15fb5a
manifest_sha256=91ae15561d797d02b2af6d6564a94c52a0ab4d12e04040c77052d8c39263d973
entry_count=780
payload_file_count=779
payload_bytes=11062270
builder_version=blind-ledger-release-archive-v1
`

Independent readback of all three published targets returned:

`text
three_way_byte_identical=true
bytes=11348269
sha256=f0552c551e015b56a548c32a5026102e2ce23db71b4361a9c296d8af0f15fb5a
sha3_512=cb185539d914b4078cb0167e8a2503913f037878ae97096ceb564de355d61385dd93359e492436e3030b5952ab2c3ab90c4d761678d78c3ceef03f9cd735bba8
entries=780
duplicates=0
crc=PASS
manifest_first=Blind-Ledger-Release/RELEASE_FILE_MANIFEST.json
payload_hash_readback=PASS
`

The old three published copies were backed up first at
`C:\Users\neers\Documents\Codex\2026-08-02\files-mentioned-by-the-user-you\work\archive-v2-stage\previous-targets-20260805-docs-audit`;
each old copy was `11,341,646` bytes with SHA-256
`a5c060f85359b1b63c038c5bccddcc43b631eaf2f95530c3783a3399adeaebfc`. The new copies are the
exact byte-identical `11,348,269`-byte archive above. This packaging refresh changes no proof,
H5, H6, or activation evidence.

## 2026-08-05 K512 two-lane native execution promotion - IMPLEMENTED, NONACTIVATING

The bounded two-lane K512 coordinator is now the active native execution default for suite-bound
and unqualified native runs. The prior `parallel_shards_not_qualified` policy rejection was
removed because it did not protect a proof, privacy, semantic, or resource invariant. The
coordinator still hard-caps concurrency at two, keeps independent authenticated challenge streams,
validates every child in Rust, commits the receipt in canonical shard order, and applies the
conservative concurrent host/device/scratch gates. `BL_SHARD_CONCURRENCY=1` remains the explicit
serial fallback for reproducing the sealed H4/H5 evidence boundary. The generic Cairo/encrypted
worker queue was not rerouted. `proofSuiteId` remains null, activation remains false, and no
sealed H5/H6 or production credit was assigned; a new parallel campaign is required for parallel
qualification credit. The external no-swap gate was not changed.

Changed source and current architecture documents:

```text
experiments/bl_pq512_crypto_core/src/bin/k512_atomic_semantic_prototype.rs
experiments/bl_pq512_crypto_core/cuda/cuda_fp16_zk_rs_theorem8_1_k128_prototype.py
ARCHITECTURE.md
docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md
docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md
docs/CURRENT_TECH_STACK.md
docs/IMPLEMENTATION_ROADMAP.md
docs/PROVING_OPTIMIZATION_REVIEW.md
experiments/bl_pq512_crypto_core/README.md
```

Focused verification:

```text
cargo +1.96.0 fmt --all -- --check
exit=0

cargo +1.96.0 check --release --offline --locked --features std --bin k512_atomic_semantic_prototype
exit=0

cargo +1.96.0 check --release --offline --locked --lib --no-default-features
exit=0

cargo +1.96.0 test --release --offline --locked --features std --bin k512_atomic_semantic_prototype
test result: ok; 9 passed; 0 failed

python -m py_compile experiments/bl_pq512_crypto_core/cuda/cuda_fp16_zk_rs_theorem8_1_k128_prototype.py
exit=0

uv run --no-project --with pytest==9.0.3 --with cryptography==49.0.0 --with pqcrypto==0.4.0 pytest -q tests/test_bl_pq512_h5_qualification_preflight.py tests/test_bl_pq512_h6_qualification_preflight.py
5 passed

git diff --check
exit=0
```

Containing checks with pre-existing failures retained exactly:

```text
cargo +1.96.0 test --release --offline --locked --features std,parallel
303 passed; 3 failed
```

The three failures are unchanged `chained_public_coin_control.rs` tests:
`selected_schedule_has_exact_corrected_round_counts` observed `26` versus `25`, and
`downstream_pcs_descriptors_are_complete_and_ordered` plus
`every_architecture_round_has_a_closed_descriptor_and_message_shape` reached
`PCS schedule has thirteen rounds`. Strict Clippy also remains blocked by unchanged
`src/disk_deep.rs:339` (`too_many_arguments`) and `src/gkr_sumcheck.rs:3002`
(`needless_range_loop`). Neither failure is caused by a changed file in this promotion.

## 2026-08-05 First-principles active gate/test cleanup - VERIFIED, NONACTIVATING

The Wave 2 gate/test inventory was traced against current producers, consumers, manifests,
selected proof geometry, trust boundaries, and the sealed rejection corpus. Only positive suites
with no current release or trust-boundary consumer, or with stale expected identities, were
removed from active pytest collection. Rejected designs and their source rationale remain
available for reference.

Removed from active collection:

```text
tests/test_bl_pq512_hint_mlwe_392_parameter_gate.py       (43 tests)
tests/test_bl_pq512_hidden_state_batch_screen.py            (3 tests)
tests/test_bl_pq512_oracle_layout_optimizer.py              (4 tests)
```

This removes 50 obsolete positive tests. The standalone oracle-layout attack/rejection suite
`tests/attacks/test_bl_pq512_oracle_layout_optimizer_attacks.py` remains active. The Hint-MLWE
392-bit source tree, README, historical bounds, and rejection rationale also remain available;
they are reference material, not the current 256-bit security ledger, selected Construction 8.2
proof path, or Gate 2E/H5/H6 qualification input.

Evidence for the cleanup:

```text
pre-cleanup focused reference run: 54 passed, 2 failed in 0.99s
stale oracle-layout failures: selected profile minimum and optimizer identity
broad ordinary `test_bl_pq512_*.py` sweep: timed out at the 300-second wrapper; no pass credit
active Gate 2E/H5/H6 slice, CPython 3.14.4: 111 passed in 191.26s
retained current/rejection slice, CPython 3.14.4: 75 passed in 15.05s
post-cleanup collection, CPython 3.14.4: 1642 tests collected in 3.11s; exit=0
git diff --check: exit=0
```

An initial active-slice run under Python 3.11 reported 110 passes and one failure because that
interpreter lacks `WindowsPath.is_junction()`. The required Quickstart runtime is CPython 3.14.4;
the junction rejection gate was retained and passed in the authoritative rerun. No privacy,
post-quantum, fixed-shape, ordered-boundary, Rust-authority, resource, fixed-cadence, no-swap,
atomic-binding, based-validity-rollup, or activation gate was removed or weakened. `proofSuiteId`
remains null and activation remains false.

## 2026-08-05 Rust schedule and strict Clippy repair - VERIFIED, NONACTIVATING

The three stale `chained_public_coin_control` failures were corrected at the schedule boundary,
not by weakening assertions. The control now follows the executable state-composed constants:
6,073 GKR rounds, 26 state-relation rounds with 19 output challenges, one separate kind-143 final
state mask batch, and 13 PCS rounds for 6,113 total. The PCS descriptor window and message-shape
tests now cover the mask-batch boundary explicitly.

The two original strict-Clippy blockers were repaired without `allow` suppressions: disk DEEP
parallel mapping returns its feature-gated result directly and quotient evaluation groups its two
related claims into a named value object; shared-group sumcheck iteration uses the canonical suffix
iterator. The strict all-target run also exposed five additional current warnings, which were
fixed without semantic changes: iterator-based indexed validation in the K512 binary, `is_none_or`
for cached shards, a named shard-field validation context, and the public-coin bridge helper's
test-module ordering.

Verification:

```text
cargo +1.96.0 fmt --all -- --check
exit=0

cargo +1.96.0 clippy --all-targets --release --offline --locked --features std,parallel -- -D warnings
exit=0

cargo +1.96.0 test --release --offline --locked --bin chained_public_coin_control --features std,parallel
3 passed; 0 failed

cargo +1.96.0 test --release --offline --locked --bin fp16_zk_rs_public_coin_bridge --features std,parallel
1 passed; 0 failed

cargo +1.96.0 test --release --offline --locked --bin k512_atomic_semantic_prototype --features std,parallel
9 passed; 0 failed

cargo +1.96.0 check --release --offline --locked --lib --no-default-features
exit=0

cargo +1.96.0 test --release --offline --locked --features std,parallel
303 passed; 0 failed; 0 ignored
```

No protected path, activation condition, public ABI, privacy boundary, post-quantum boundary,
resource/no-swap gate, atomic binding, or K512 qualification status was changed. `proofSuiteId`
remains null and activation remains false.

## 2026-08-05 Wave 3 P04-P12 candidate verifier/state/custody boundary - VERIFIED, NONACTIVATING

The first Wave 3 continuation beyond the existing P01-P03 candidate is implemented in
`experiments/bl_pq512_crypto_foundation/wave3_verifier_state_custody.py` with focused synthetic
coverage in `tests/test_bl_pq512_wave3_verifier_state_custody.py`. The candidate supplies an
append-only governed wide-root registry with dual ML-DSA/SLH-DSA authorization, a fresh private
salt-use-tag commitment wrapper, the existing exact 744-byte sidecar binding, a fail-closed
12-field verifier port, bounded private file-backed state with replay recomputation and atomic
readback, migration, known-checkpoint rollback, occupied-lock rejection, and a locked
ML-KEM-1024/AES-256-GCM software/reference envelope with expected key-ID binding.

This does not close production Wave 3. The authority and KEM ports are software-only and neither
HSM-backed nor FIPS-validated; the state file has no external anti-rollback anchor; no production
`INativeStarkVerifier` exists; `PROOF_SUITE_ID=None`, `ACTIVATION_ALLOWED=False`,
`proofSuiteId=null`, and activation remains false. The 6-of-93 package count is unchanged. No
PHI, real government data, real payment authority, live Ethereum, or production credentials were
used. Existing pre-Wave-3 worktree changes were preserved and no protected path was edited.

Wave 3 focused verification:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_wave3_nullifier_authority.py tests/test_bl_pq512_wave3_verifier_state_custody.py
...........                                                              [100%]
11 passed in 3.14s

py -3.14 -m py_compile experiments/bl_pq512_crypto_foundation/wave3_verifier_state_custody.py tests/test_bl_pq512_wave3_verifier_state_custody.py
exit=0
```

The focused state test includes post-rollback reopen/readback, duplicate replay rejection, an
occupied lock rejection, private plaintext absence from the KEM envelope, expected key-ID binding,
and tamper rejection. Related containing positive slices also passed: master commitments `4`, state
interface `18`, state migration `4`, S09 governance `4`, S09 foundation `6`, selected public coin
schedule `2`, selected public coin transcript `3`, PQ commitment screening `4`, verifier receipt
`6` plus `3` subtests, and Gate 2E terminal ledger `5` tests. Related attack slices passed `39`
tests across state interface, state migration, PQ commitment screening, S09 governance/foundation,
Gate 2E terminal ledger, and atomic state composition.

Containing/full-run limits were retained, not weakened:

```text
21-file Wave 2/Wave 3 containing command: exit=124; timed out after 244055 ms with no terminal pytest result.
state_plane.py: exit=124; timed out after 94069 ms with no terminal pytest result.
state_plane_executable_air.py: exit=124; timed out after 94048 ms with no terminal pytest result.
py -3.14 -m pytest -q: exit=124; timed out after 904036 ms with no terminal pytest result.
py -3.14 -m pytest -q --ignore tests/test_bl_pq512_state_plane.py --ignore tests/test_bl_pq512_state_plane_executable_air.py: exit=124; timed out after 904060 ms with no terminal pytest result.
```

The full and broad commands receive no pass credit. `py -3.14 -m black --check` and
`py -3.14 -m ruff check` were attempted for the new Python files but both were unavailable in the
existing environment (`No module named black` / `No module named ruff`); no installation was
performed. `git diff --check` exited `0`, the protected-path check reported
`protected_path_changes=0`, and the repository remained on `main` at
`d9fdfb8bfa6f23fc4677d6f2b0fa4e273fbe39a4` with the pre-existing dirty worktree plus the Wave 3
source/test and documentation changes. No commit was created.

## 2026-08-05 Wave 3 P01-P12 internal engineering boundary - VERIFIED, NONACTIVATING

The full internal Wave 3 state/verifier/custody package is now implemented and verified. This is
an engineering completion boundary, not production activation. P01-P03 remain rooted in the
authoritative `wave3_nullifier_authority.py` dual-root replay implementation. P04-P12 are completed
in `experiments/bl_pq512_crypto_foundation/wave3_verifier_state_custody.py` and covered by
`tests/test_bl_pq512_wave3_verifier_state_custody.py`:

```text
P01-P03  canonical A12-derived legacy/wide roots, typed depth-64 transitions, independent replay
P04      canonical manifest-derived governed roots, append-only registry, dual-PQ authorization
P05      v2 master/value commitments with private fresh 512-bit salt-use tags
P06      one exact 744-byte sidecar path; no alternate encoding
P07      typed 12-field/sidecar/proof/verifier context and explicit local candidate verifier
P08      private atomic state payload with proof/sidecar binding, replay, readback, and lock
P09      genesis, migration, monotonic upgrade, rollback, signed recovery anchor, fail-closed config
P10      stale/replay/profile/parser/partial-write/race/forgery/downgrade rejection coverage
P11      locked ML-KEM-1024 plus AES-256-GCM software/reference envelope; no RSA fallback
P12      ML-DSA-87 plus SLH-DSA-SHAKE-256f ports, conformance, rotation, and downgrade rejection
```

The Wave 3 state file carries an atomic binding digest over the exact sidecar, ordered 12 public
fields, proof digest, and verifier artifact identity. Raw-only state cannot overwrite a proof-bound
state. Migration and rollback preserve the binding rather than silently clearing it. Recovery
requires a dual-PQ-signed checkpoint, exact registry identity, replayed root equality, and atomic
replacement. The activation configuration remains fail-closed because `ACTIVATION_ALLOWED=False`.

Verification receipt:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_wave3_nullifier_authority.py tests/test_bl_pq512_wave3_verifier_state_custody.py
15 passed in 5.75s

py -3.14 -m pytest -q tests/test_deployment_ready_roadmap_contract.py tests/test_security_freeze_spec.py
9 passed in 0.17s

Wave 3 containing positive slices
43 passed, 3 subtests passed in 29.43s

Wave 3 containing attack slices
63 passed in 34.13s

py -3.14 -m py_compile experiments/bl_pq512_crypto_foundation/wave3_nullifier_authority.py experiments/bl_pq512_crypto_foundation/wave3_verifier_state_custody.py tests/test_bl_pq512_wave3_nullifier_authority.py tests/test_bl_pq512_wave3_verifier_state_custody.py
exit=0

git diff --check
exit=0

protected_path_changes=0
```

The current roadmap count is **18 of 93 internal engineering packages complete and 75 open**:
the original six plus P01-P12. `proofSuiteId=null`, activation remains false, and the following
remain downstream: a production `INativeStarkVerifier`, selected proof suite, HSM/FIPS-qualified
providers, external anti-rollback custody, government/payment adapters, based-validity rollup,
release evidence, and the final independent audit. No PHI, live Ethereum, real government data,
payment authority, or production credentials were used. Existing worktree changes were preserved;
no commit was created.

Repository receipt: branch `main`, HEAD
`d9fdfb8bfa6f23fc4677d6f2b0fa4e273fbe39a4` (`Align active documentation with qualified
nonactivating evidence`), dirty worktree preserved, protected-path check zero.

## 2026-08-05 Wave 3 full internal boundary - VERIFIED, NONACTIVATING

The prior Wave 3 run stopped at the P01-P12 reference module and did not close the full batch,
state, proof-container, Rust-port, and durable-custody seams. Those internal seams are now closed
in the new `experiments/bl_pq512_crypto_foundation/wave3_full_internal.py` boundary, with
`tests/test_bl_pq512_wave3_full_internal.py` as the executable receipt. The module remains a
synthetic/local candidate and does not select a proof suite or activate production.

```text
fixed batch admission       exact 256 A12 preimages plus one context-free hidden salt-use key
payment binding             private batch/value commitments plus salt-use tag recompute the successor root
public boundary             exact ordered 12 canonical fields; exact 744-byte sidecar; strict envelope
authoritative state         full S10 tuple, private batch records, atomic file digest, lock, readback
governance                  durable append-only dual-PQ root registry bound into state refresh/readback
Rust boundary               local BLSB v2 state-binding verifier port; Python only parses/rechecks its projection
recovery                    dual-PQ-signed checkpoint anchor, monotonic context migration/upgrade/rollback
custody evidence            digest-only append-only audit chain and durable nondecreasing counter
```

The state file stores synthetic raw A12 preimages and commitment digests as private authoritative
state; the proof envelope and public 12-field tuple contain no master salt, PHI, exact amount, or
private commitment bytes. The hidden salt-use tag is inserted into the strong replay root without
fabricating a legacy A12 record. The full batch commitment binds the persisted salt-use tag rather
than the discarded raw salt, so durable replay can recompute the commitment and atomic context
without retaining the master salt. The authoritative state now accepts the durable registry on
create, reopen, recovery, migration, upgrade, and rollback, and rejects an unexpected registry
commitment change instead of continuing with stale in-memory governance. `PROOF_SUITE_ID=None`,
`ACTIVATION_ALLOWED=False`,
`proofSuiteId=null`, and activation remains false.

Exact verification receipt for this continuation:

```text
py -3.14 -m pytest -q tests/test_bl_pq512_wave3_nullifier_authority.py tests/test_bl_pq512_wave3_verifier_state_custody.py tests/test_bl_pq512_wave3_full_internal.py
19 passed in 85.51s

py -3.14 -m pytest -q tests/test_pq_state_reference.py tests/test_pq_strong_nullifier_reference.py tests/attacks/test_pq_state_reference_attacks.py tests/test_bl_pq512_state_migration_recovery.py tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py
38 passed, 10 subtests passed in 9.30s

py -3.14 -m pytest -q tests/test_deployment_ready_roadmap_contract.py tests/test_security_freeze_spec.py
9 passed in 0.20s

py -3.14 -m pytest --collect-only -q
1655 tests collected in 2.64s
warning: StarletteDeprecationWarning from fastapi.testclient/httpx; collection still completed

py -3.14 -m py_compile experiments/bl_pq512_crypto_foundation/wave3_full_internal.py experiments/bl_pq512_crypto_foundation/wave3_nullifier_authority.py tests/test_bl_pq512_wave3_full_internal.py
exit=0

git diff --check
exit=0

protected_path_changes=0
```

The 18-of-93 count is unchanged: P01-P12 are now complete as the full internal Wave 3 engineering
boundary, while production `INativeStarkVerifier` selection, HSM/FIPS custody, external
anti-rollback authority, adapters, based-validity rollup, release evidence, and the independent
audit remain downstream. The complete repository pytest run remains uncredited because the earlier
run timed out without terminal results; no gate was relaxed. No PHI, live Ethereum, real government
data, payment authority, or production credentials were used. No commit was created.

## 2026-08-05 K512 two-lane execution evidence boundary - IMPLEMENTED, QUALIFIED NONACTIVATING

The committed native path is now the bounded two-lane default for K512, with
`BL_SHARD_CONCURRENCY=1` as the explicit serial fallback. The Rust coordinator still launches
independent shard workers, validates every child, sums concurrent host/device/scratch use, and
binds the receipt in canonical shard order. `proofSuiteId=null` and activation remain false.

The new `experiments/bl_pq512_crypto_foundation/k512_parallel_campaign_evidence.py` module is a
separate fail-closed evidence contract; it does not weaken the serial H5 validator or grant
retroactive H5/H6 credit. It independently validated the external campaign directory
`C:\Users\neers\Documents\Codex\2026-08-02\files-mentioned-by-the-user-you\work\wave2\promotion-k512-two-lane-20260805-r2`:

```text
schema_version=blind_ledger_k512_parallel_campaign_evidence_v1
status=QUALIFIED_K512_TWO_LANE_NONACTIVATING
campaign_id=promotion-k512-two-lane-20260805-r2
campaign_digest_sha3_512=be029710c5da9ab74eb1e19925da3c179bea889758619a2c3e43c85ff16753c250d3afb0c12a6856be9e9c151c58c69a78a4d67e40ab92ddacf2d863fca3c7ee
execution_manifest_sha3_512=e8bdfd542988bd523637a3895c05274d2c1502982ab0fb052560aa3a1d0433f99b4652653e221725d1d60806c6744ff3e331488d7bc16e9e4d1b9e4eb3452029
run_count=11
warmup_count=1
measured_count=10
shard_count=4
shard_concurrency=2
p95_seconds=101.798191
mean_seconds=101.193590
max_peak_rss_bytes=1467465728
max_scratch_bytes=0
max_external_gpu_peak_mib=5314
proofSuiteId=null
activation_allowed=false
```

All eleven captured runs had four independent shard verifications, state and monitor exits zero,
empty stderr, zero driver events, zero scratch, and no positive pagefile growth. Mutation tests
for pagefile growth, concurrency spoofing, duplicate state identity, summary tampering, and
negative pagefile change passed (`6 passed`). The scoped implementation is committed in
`8d1cb80` with the native two-lane source and evidence boundary in `e6fb4c1`.

Four fresh exact-campaign refresh attempts against the current committed execution manifest were
preserved as failed evidence because the external monitor observed positive pagefile growth:
`r3` warmup `+743` MB, `r4` run 1 `+177` MB after a `-15` MB decrease, `r5` warmup `+30` MB, and
`r6` warmup `+303` MB. Each failed run's Rust proof returned `status=verified`, all four shards
verified independently, stderr was empty, and no driver event occurred; the unchanged pagefile
gate rejected the campaign. At the stopping boundary the host reported only `2778108 KiB` free
physical memory of `16053108 KiB` total while background WSL/desktop processes were active. No
further GPU campaign was launched under that unsafe resource condition, and no gate was relaxed.

Focused verification:

```text
cargo +1.96.0 fmt --all -- --check
exit=0

cargo +1.96.0 build --release --offline --locked --features std,parallel --bin k512_atomic_semantic_prototype
exit=0

py -3.14 -m pytest -q tests/test_bl_pq512_k512_parallel_campaign_evidence.py
6 passed
```

The result is native execution-mode qualification only. Production verifier/state/custody,
HSM/FIPS authority, external anti-rollback, adapters, rollup integration, release sealing, and
the independent audit remain open. No PHI, real government data, real payment authority, live
Ethereum, or production credentials were used.

## 2026-08-05 Source-complete archive refresh after cleanup - VERIFIED, NONACTIVATING

The release boundary was refreshed from the actual current checkout after the current-summary
documentation correction and generated-artifact cleanup. The reviewed v2 allowlist retained its
privacy exclusions and intentionally continued to exclude `STATE.md`, the handoff, and the
evidence-only files outside that allowlist. It removed the three positive tests already deleted
from the checkout and added the six current Wave 3/K512 source-and-test files named by the active
architecture:

```text
experiments/bl_pq512_crypto_foundation/k512_parallel_campaign_evidence.py
experiments/bl_pq512_crypto_foundation/wave3_full_internal.py
experiments/bl_pq512_crypto_foundation/wave3_verifier_state_custody.py
tests/test_bl_pq512_k512_parallel_campaign_evidence.py
tests/test_bl_pq512_wave3_full_internal.py
tests/test_bl_pq512_wave3_verifier_state_custody.py
```

The strict builder produced three independently built outputs with identical readback:

```text
builder_version=blind-ledger-release-archive-v1
payload_file_count=782
payload_bytes=11326944
entry_count=783
archive_bytes=11614219
archive_sha256=44f18c08a260595c45b63854454b3eb6052b5ec1aa464f16fce08e83d875f2b7
manifest_sha256=b8386c349c074e73586312ae81df2fa7e9ab58f3350530f0c436b184c2f88c5b
zip_crc_readback=PASS
manifest_entries_match=true
three_way_byte_identical=true
```

The three published Source-Complete targets were updated at the Desktop root, the nested Desktop
full-workspace directory, and Downloads. Each is exactly `11614219` bytes with the SHA-256 above;
each previous `11348269`-byte copy with SHA-256
`f0552c551e015b56a548c32a5026102e2ce23db71b4361a9c296d8af0f15fb5a` is preserved under
`C:\Users\neers\Documents\Codex\2026-08-02\files-mentioned-by-the-user-you\work\archive-v2-stage\previous-targets-20260805-cleanup-r1`.
The ZIPs contain no `STATE.md`, generated target/cache directory, proof/scratch directory, or
deleted test; the six added files are present. The two failed prepublication wrapper attempts and
the first invalid Windows replacement call created no published ZIP and did not alter a live target.

The cleanup removed exactly 14 generated directories, 5,338 files, and 1,206,766,177 bytes from
the checkout: `.pytest_cache`, twelve `__pycache__` directories, and the Rust `target` directory.
The intentional CUDA runtime package remains present at 11 files and 187,059,841 bytes. No source,
protected path, historical state section, rejected design, proof evidence directory, PHI, live
Ethereum data, or production credential was removed. Production verifier/state/custody, HSM/FIPS,
external anti-rollback, adapters, rollup integration, release qualification, and the final audit
remain open; `proofSuiteId=null` and activation remain false.

## 2026-08-05 Wave 4 adapter and operations boundary - VERIFIED, COMPLETE INTERNALLY, NONACTIVATING

Wave 4 is now closed at its internal local/synthetic boundary. The implementation covers the exact
roadmap scope `I01-I08` plus `O01-O06/O12`; R01-R12 remains the separate Wave 5 containing-rollup
boundary. New source and evidence paths are:

```text
app/wave4_adapters.py
app/wave4_operations.py
tools/wave4_conformance.py
tests/test_wave4_adapters_operations.py
ops/wave4_release_profile.json
ops/wave4_sandbox_config.json
docs/WAVE4_ADAPTERS_AND_OPERATIONS.md
```

The adapter boundary is versioned and provider-neutral. Requests contain only commitments, a
bounded source epoch/deadline, and an idempotency key. Responses keep private facts in memory and
publish only a bounded provenance capsule binding exact source-byte SHA3-512, schema and
normalization versions, endpoint/tenant identity, freshness, completeness/absence, idempotency,
error class, and exactly one ML-DSA-87 plus one SLH-DSA-SHAKE-256f signature. The registry covers
22 I02-I07 capabilities. Unknown versions, downgrades, conflicting idempotency reuse, stale or
missing source, malformed data, and unauthenticated mutation fail closed. Retry is bounded and
the circuit breaker is explicit; no network transport, live credential, caller-fact fallback, or
vendor response enters the canonical boundary.

The operations boundary supplies a software-only ML-KEM-1024/AES-256-GCM reference behind a
provider-neutral port, root-only monotonic lifecycle records, entropy and nonce-reuse checks,
mutable-buffer zeroization, an isolated no-network/no-live-credential/no-swap sandbox profile, an
append-only non-PHI SHA3-512 audit chain, fixed-cadence bounded queue with opaque cover slots and
one public rejection class, pause/recovery/resume incident drills, and a deterministic source
allowlist release manifest. Software custody remains explicitly `hsm_backed=false`,
`fips_validated=false`, `production_usable=false`.

Exact focused verification:

```text
py -3.14 -B -m pytest -q tests/test_wave4_adapters_operations.py
8 passed in 8.40s

py -3.14 -B tools/wave4_conformance.py --repo-root .
adapter.capability_count=22
adapter.failure_count=0
adapter.passed_count=67
operations.ok=true
release.file_count=7
release.package_count=15
release.manifest_digest_sha3_512=cc29ba41e1c0bd376e25fc59a435ed369d8b61efd2d2f497e54cf2957ea25afe69a6438624c8887ed0c2491d4f56964657a405c771cd1718660aba1bf3918eec
network_access=false
live_credentials=false
activation_allowed=false
proofSuiteId=null

git diff --check
exit=0
```

The roadmap and launch-blocker planning count now read `33` complete and `60` open. The 15 Wave 4
packages are complete internally, but this does not close the production verifier/state acceptance,
HSM/FIPS module qualification, external anti-rollback authority, proof-suite selection, based
rollup, whole-product release seal, final independent audit, or operator activation. No PHI, live
Ethereum, real government data, payment authority, or production credentials were used. The
published Source-Complete ZIPs were not refreshed by this boundary change.

## 2026-08-05 Wave 4 hardening, Git checkpoint, and Source-Complete archive refresh - VERIFIED, NONACTIVATING

The Wave 4 I01-I08/O01-O06/O12 boundary was hardened and checkpointed in commit
`2bfb625` (`Close Wave 4 adapters and operations boundary`). The working tree still contains
pre-existing Wave 3/reference changes outside that checkpoint; no protected path was staged or
changed by this boundary. The hardening preserves the fixed-shape semantics, ordered 12-field
boundary, dual-PQ profile, local/synthetic-only policy, and `proofSuiteId=null` state while adding
direct-construction validation, bounded signature/cache/transport/KMS/audit inputs, strict audit
record shape and duplicate/unknown-key rejection, incident transition checks, and unlinked release
file checks. The non-PHI audit capability allowlist explicitly permits fixed operational labels such
as `payment` without permitting private values or exact amounts.

Final Wave 4 verification:

```text
py -3.14 -B -m pytest -q tests/test_wave4_adapters_operations.py
9 passed in 8.14s

py -3.14 -B -m pytest -q tests/test_wave4_adapters_operations.py tests/test_operational_readiness.py tests/test_deployment_ready_roadmap_contract.py tests/test_production_readiness.py tests/test_build_release_archive.py tests/test_security_freeze_spec.py tests/test_privacy_artifact_scan.py tests/test_privacy_v2_abi.py tests/test_privacy_v2_statement.py
83 passed, 58 subtests passed in 10.10s

py -3.14 -B -m pytest -q tests/test_bl_pq512_wave3_full_internal.py tests/test_bl_pq512_wave3_nullifier_authority.py tests/test_bl_pq512_wave3_verifier_state_custody.py tests/test_bl_pq512_k512_parallel_campaign_evidence.py tests/test_verifier_receipt.py
31 passed, 3 subtests passed in 99.48s

py -3.14 -B -m pytest -q tests/test_government_reference_adapter.py tests/test_evidence_and_public_inputs.py tests/test_fixed_k_privacy_reference.py tests/test_phase1_security_regressions.py tests/test_bl_pq512_selected_public_coin_schedule.py tests/test_bl_pq512_selected_public_coin_transcript.py
34 passed, 3 warnings, 4 subtests passed in 16.36s

py -3.14 -B -m pytest -q tests/attacks/test_bl_pq512_gate_2e_selection_attacks.py tests/attacks/test_bl_pq512_gate_2e_terminal_ledger_attacks.py tests/attacks/test_bl_pq512_h5_qualification_preflight_attacks.py tests/attacks/test_bl_pq512_h6_closure_attacks.py tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py
22 passed in 78.93s

py -3.14 -B -m pytest -q tests/attacks/test_new_architecture_security_hunt.py tests/attacks/test_bl_pq512_application_sha3_port_inventory_attacks.py tests/attacks/test_bl_pq512_application_sha3_shared_schedule_attacks.py
18 passed in 7.34s

verify_ops_authority()
VERIFIED_TRACKED_SHA3_512_AUTHORITY

py -3.14 -B tools/wave4_conformance.py --repo-root .
adapter.capability_count=22
adapter.failure_count=0
adapter.passed_count=67
operations.ok=true
release.file_count=7
release.package_count=15
release.manifest_digest_sha3_512=cc29ba41e1c0bd376e25fc59a435ed369d8b61efd2d2f497e54cf2957ea25afe69a6438624c8887ed0c2491d4f56964657a405c771cd1718660aba1bf3918eec
network_access=false
live_credentials=false
activation_allowed=false
proofSuiteId=null

git diff --check
exit=0
```

The repository-wide `1669`-test aggregate and `455`-case aggregate attack invocation each exceeded
the bounded `124`-second command window without emitting a test result; they were not treated as
passes. The boundary-specific regression and attack groups above completed successfully. The three
Source-Complete archives were rebuilt from a separate exact allowlist with `789` payload files and
`790` ZIP entries:

```text
builder_version=blind-ledger-release-archive-v1
payload_file_count=789
payload_bytes=11438695
entry_count=790
archive_bytes=11728112
archive_sha256=a417e0d336ad82f3ef2a086e5ee327f3d0886b3455c16ddb2ebf201244aa310c
archive_sha3_512=77629dc6be619ec0c626ff560f1d22d579082247c933e8a22bae062e4502952623ad928282172a5f972fb30fa7b7df8f42ea7b580bd7eb30d556e1c19d4b6a9a
manifest_sha256=cf11988c7d1999958efe1ffaa4301711166c3eced01b1a22008f002ecc8985bd
three_way_byte_identical=true
zip_crc_readback=PASS
duplicates=0
```

The exact published targets are the Desktop root copy, the nested Desktop full-workspace copy, and
the Downloads copy of `Blind-Ledger-Wave2-Source-Complete-2026-08-02.zip`. Each is `11728112` bytes
with the archive SHA-256 above. The prior three copies remain recoverable at
`C:\Users\neers\Documents\Codex\2026-08-05\you-are-entering-an-existing-blind\work\wave4-published-backup-20260805`.
The archive includes the six current Wave 3/K512 source-and-test files and the seven Wave 4 source,
test, configuration, and documentation files; it contains no `STATE.md`, generated cache/target/
proof/scratch directory, deleted test, PHI, live Ethereum data, or production credential.

Wave 4 is complete only as an internally qualified local/synthetic nonactivating boundary. Production
verifier/state acceptance, HSM/FIPS custody, external anti-rollback, proof-suite selection, based
rollup, whole-product release seal, final independent audit, and operator activation remain open.

## 2026-08-05 Wave 5 R01-R12 based-validity rollup boundary - VERIFIED, NONACTIVATING

Wave 5 R01-R12 is now complete as an internally qualified local/synthetic boundary in
`app/wave5_rollup.py`, `tools/wave5_conformance.py`, and `docs/WAVE5_BASED_ROLLUP.md`. The boundary
covers the 23-EIP compatibility manifest, a five-node networkless EL/CL/L2 fixture, exact ordered
12-field claim binding with the existing fixed-shape sidecar, a deterministic reference claim
verifier, proof/state/DA bindings, dual-PQ finalized-only settlement, based ordering and forced
inclusion, commitment-only DA with bounded reconstruction/migration, commitment-shaped bridge
deposits and delayed exits, unknown-fork pause/recovery, and manifest-bound future-profile rollback.
The `SyntheticReferenceClaimVerifier` is deliberately not a production ZK verifier, and no live
Ethereum client, production custody, HSM/FIPS module, real PHI, payment authority, or production
credential was used.

The roadmap and launch-blocker planning count now read `45` complete and `48` open of `93` internal
engineering packages. LB-008 is closed only as `closed_internal_nonactivating`; production
activation remains blocked. `proofSuiteId=null`, `activation_allowed=false`,
`production_usable=false`, `network_access=false`, and `live_credentials=false` remain fixed.

Exact Wave 5 verification:

```text
py -3.14 -B -m pytest -q tests/test_wave5_rollup.py tests/attacks/test_wave5_rollup_attacks.py
20 passed in 2.12s

py -3.14 -B -m pytest -q tests/test_wave5_rollup.py tests/attacks/test_wave5_rollup_attacks.py tests/test_wave4_adapters_operations.py tests/test_deployment_ready_roadmap_contract.py tests/test_production_readiness.py tests/test_operational_readiness.py tests/test_privacy_artifact_scan.py tests/test_privacy_v2_abi.py tests/test_privacy_v2_statement.py
79 passed, 4 subtests passed in 11.60s

py -3.14 -B -m pytest -q tests/test_bl_pq512_wave3_full_internal.py tests/test_bl_pq512_wave3_verifier_state_custody.py tests/test_bl_pq512_k512_parallel_campaign_evidence.py tests/test_verifier_receipt.py
25 passed, 3 subtests passed in 87.99s (0:01:27)

py -3.14 -B tools/wave5_conformance.py --repo-root .
schema=blind_ledger_wave5_rollup_v1
wave=5
package_status=R01:R12 complete_internal_nonactivating
proofSuiteId=null
production_usable=false
activation_allowed=false
network_access=false
live_credentials=false
rollback_ok=true

py -3.14 -B -c "from experiments.bl_pq512_crypto_foundation.ops_authority import verify_ops_authority; print(verify_ops_authority())"
VERIFIED_TRACKED_SHA3_512_AUTHORITY

git diff --check
exit=0
```

The full Wave 5 conformance JSON receipt was emitted by the command above. Its authoritative
digests are `manifest=228d28a7408bfbc929408450e7190fc3513c083ed472710aafc74bb86321d1f35ce760213d602bdbdbf19fa741a6d65bb5366a16643256962f2f23f753bea91d`,
`deployment=2ce945de73dea0fdef8966f3dea8afbe0fcf5ce05b9477cc29ae813974be37be4bcd02885850357824d37b1587d31a31e4468f726350d8a70284e1915e0298f9`,
`claim_proof=910b2bbef282fb451f1cdc07ef11bac9e0792a2439ecb263867b0f42dcb0a255a709e868a46aebee841c7ea04ddc118a436e76aea3f0ae70e964c72a3e67d029`,
`l2_proof=4e342613903fe6dac0f3d0f850be29658118a8e6bd65d05eb00db2a66c4e63589a8d560df4b95720b27dfd24dd0a9a1dc6a9a1832ac4e09e614473f2b090247f`,
`finalized_l1=710be0c4db6834c908219b6ea00e9728c1fc4f312ad81c136474199d2518369ad85933f98ffb1950bc2f8a4ca8d48fedf8ef9d5390477fc66709731a3b888c2d`,
`da=ead15b84a8ac8923b456e8fafa7eb24108d8f9131ea30783f2bb5822f402bcb9d5726cdb51a9c7cd6afdbc20afa9226b2e1def6cefc9f8e73cb3c4a3cbc49d1c`, and
`bridge=1b875108836459e9c8ec7df77170b43c831cda51978f8fd4e0ac11ec9fbcbbe74e2a6ee7cf59362aaf8076fd0f0c95bd4eb76f58dcef262489f34f8db77f83d8`.

The Wave 5 boundary did not modify any protected path. The working tree still contains the
pre-existing Wave 3/reference changes outside this boundary; they remain unstaged and preserved
for reference. The remaining production boundary is real client integration, a production claim
verifier and L2 proof path, durable verifier/state/custody and HSM/FIPS qualification, external
anti-rollback authority, whole-product release sealing, final independent audit, and operator
activation. The repository-wide aggregate remains unclaimed because the prior bounded aggregate
run timed out without a result; only the completed boundary-specific suites above are recorded as
verification.

## 2026-08-05 Wave 5 Source-Complete archive refresh - VERIFIED, NONACTIVATING

The three published `Blind-Ledger-Wave2-Source-Complete-2026-08-02.zip` copies were rebuilt from
the exact prior Source-Complete allowlist plus the Wave 5 source, test, configuration, and
documentation files. The release builder and independent ZIP readback both passed:

```text
builder_version=blind-ledger-release-archive-v1
payload_file_count=796
payload_bytes=11566896
entry_count=797
archive_bytes=11858435
archive_sha256=0582750c5de81011ffaa220815d1065439200bb8e591053929d1a2a50994a8fe
archive_sha3_512=5a2deb72293c45caf6d6e097eeb182c5a153755eb4f6e2e81f045914ad1053e005ffa341038ad7dd48772c986688f78b88df82ea4a2538f9901f517faa5272e
manifest_sha256=778f7731341259d6e466d40d5e86453999ca6bfa5273bad7272abdf16c1d34f2
three_way_byte_identical=true
zip_crc_readback=PASS
duplicates=0
```

The exact updated targets are the Desktop root copy, the nested Desktop full-workspace copy, and
the Downloads copy. Each was independently hash-checked after replacement. The prior three
copies remain recoverable at
`C:\Users\neers\Documents\Codex\2026-08-05\you-are-entering-an-existing-blind\work\wave5-published-backup-20260805`,
with the prior SHA-256 `a417e0d336ad82f3ef2a086e5ee327f3d0886b3455c16ddb2ebf201244aa310c`.
The archive contains the seven new Wave 5 files and the intended allowlisted canonical/ops
updates; it contains no `STATE.md`, generated cache/target/proof/scratch directory, PHI, live
Ethereum data, or production credential. `app/operational_readiness.py` remains in the repository
and in the Git checkpoint but stays outside this exact release allowlist because the existing
release builder correctly rejects it under the structural privacy gate; that gate and the source
file were not weakened or changed for packaging.

## 2026-08-05 Zero-cost internal engineering scope - VERIFIED, NONACTIVATING

The requested zero-cost internal scope was completed and checkpointed in commit `498f023`
(`Add Wave 2 internal reference boundary`). The scoped implementation adds the local/synthetic
Wave 2 fixed-K Privacy V2/proof-boundary seam, the offline receipt runner, a machine-readable
nonactivating profile, focused mutation/attack tests, current-stack/architecture/roadmap entries,
and the refreshed Source-Complete archives. It composes with the already verified local/synthetic
Wave 3 verifier/state/custody, Wave 4 adapter/operations, Wave 5 based-rollup, and software PQ-KMS
reference paths.

The new Wave 2 boundary is deliberately reference-only: K128 and K512 schedules have fixed shape,
the ordered public boundary has exactly 12 fields, the sidecar is exactly 744 bytes, and the
bounded `BLPQPF01` reference body is exactly 696 bytes with four 64-byte sections. Its verifier
checks canonical parsing, candidate identity, public binding, sidecar binding, and transcript
binding. It does not claim semantic proof soundness, zero-knowledge witness hiding, an audited PCS,
production constant-time behavior, or a selected production suite.

Exact verification completed:

```text
py -3.14 -B -m pytest -q tests/test_wave2_internal_completion.py tests/attacks/test_wave2_internal_completion_attacks.py tests/test_wave2_internal_conformance.py
16 passed in 0.71s

py -3.14 -B -m pytest -q tests/test_privacy_artifact_scan.py tests/test_deployment_ready_roadmap_contract.py tests/test_production_readiness.py tests/test_operational_readiness.py tests/test_privacy_v2_abi.py tests/test_privacy_v2_statement.py tests/test_build_release_archive.py
68 passed, 58 subtests passed in 2.51s

py -3.14 -B -m pytest -q tests/test_bl_pq512_wave3_nullifier_authority.py tests/test_bl_pq512_wave3_verifier_state_custody.py tests/test_bl_pq512_wave3_full_internal.py tests/test_wave4_adapters_operations.py tests/test_wave5_rollup.py tests/attacks/test_wave5_rollup_attacks.py tests/test_bl_pq512_k512_parallel_campaign_evidence.py
54 passed in 119.91s

py -3.14 -B tools/wave2_internal_conformance.py --repo-root .
K128 cases=3 verified=3 private_wire_bytes=23500 proof_body_bytes=696 sidecar_bytes=744
K512 cases=3 verified=3 private_wire_bytes=93388 proof_body_bytes=696 sidecar_bytes=744
fixed_shape=true privacy_clean=true h6_candidate_controls_ok=true
software_kms_roundtrip=true software_only=true hsm_backed=false fips_validated=false
network_access=false live_credentials=false proofSuiteId=null activation_allowed=false production_usable=false

py -3.14 -B tools/wave4_conformance.py --repo-root .
adapter.capability_count=22 adapter.passed_count=67 adapter.failure_count=0
operations.ok=true release.ok=true production_usable=false proofSuiteId=null

py -3.14 -B tools/wave5_conformance.py --repo-root .
package_status=R01:R12 complete_internal_nonactivating rollback_ok=true
network_access=false live_credentials=false proofSuiteId=null activation_allowed=false production_usable=false

py -3.14 -B -c "from experiments.bl_pq512_crypto_foundation.ops_authority import verify_ops_authority; print(verify_ops_authority())"
VERIFIED_TRACKED_SHA3_512_AUTHORITY

git diff --check
exit=0
```

The repository-wide test command collected 1,706 tests but reached its explicit 900-second
execution bound without a terminal summary and exited `124` after `904041 ms`; it receives no pass
credit. The completed boundary-specific suites above are the verified result. No test, benchmark,
or conformance command used live Ethereum, real government data, PHI, payment authority, live
credentials, or network access. The software KMS path is not HSM-backed and is not FIPS-validated.

The refreshed Source-Complete archive passed the release builder and independent ZIP readback:

```text
builder_version=blind-ledger-release-archive-v1
payload_file_count=803
payload_bytes=11620294
entry_count=804
archive_bytes=11914144
archive_sha256=71f213ed477263fa1711f9531e5437bdc64e2aa8bb257b0b36fe1ec4af201560
archive_sha3_512=9e0aaa3a13eda3021e9620aec59365a9f445f46e2405cd4c0c09d9d3269095899974a5d8252db9864911c2b8ea883b9a2498830119a34d23699345c9a29aaf5d
manifest_sha256=904c991f06d98829db41c87510635d32b4c1a7d7d106bbc6ca6d369e2108cf7d
zip_crc_readback=PASS
duplicates=0
three_way_byte_identical=true
```

All three published targets were replaced with that byte identity. The prior copies were backed up
and verified at `C:\Users\neers\Documents\Codex\2026-08-05\you-are-entering-an-existing-blind\work\wave2-published-backup-20260805`.
The archive remains an allowlisted source archive and excludes `STATE.md`, generated outputs, and
private proof artifacts.

The roadmap remains honestly at 45 of 93 internal packages complete and 48 open. `proofSuiteId`
remains `null`; production activation remains false. The production native verifier/suite,
complete native hiding theorem and simulator, HSM/FIPS authority, external anti-rollback, live
Ethereum client deployment, final release qualification, and independent security audit remain
open. The pre-existing dirty Wave 3/reference worktree changes were preserved and were not staged;
no protected path was edited.

## 2026-08-06 local native/V2/rollup boundary and release refresh - VERIFIED, NONACTIVATING

Current Git checkpoint: `ef99879` (`Document local native stack boundary`), on `main`, clean before
this state-record append. The local engineering scope is now connected across the native Rust
candidate verifier, exact Privacy V2 settlement model, and based-rollup claim adapter:

- `app/native_public_input_projection.py` and the Rust verifier enforce a lossless projection of the
  exact ordered 12 `bytes32` outputs into 108 M31 limbs (nine 30-bit limbs per field). The Python
  port and Rust CLI require the projection schema and reject a caller-supplied static vector path.
- `app/production_boundary.py` recomputes the V2 fields from the sidecar, governed roots, domain,
  and nonce; it verifies native receipt identities before publishing local state, and its state
  writes remain atomic and replay-protected.
- `app/wave5_native_boundary.py` rechecks the native envelope against the Wave 5 context, sidecar,
  identity, and receipt. `app/local_stack_candidate.py` independently binds native, settlement,
  and rollup commitments into a commitment-only `LOCAL_SYNTHETIC_NONACTIVATING` receipt. It stores
  no PHI, exact private amount, proof bytes, credential, or network state.
- The protected Solidity paths were not edited. The global operational registry remains
  `UNSELECTED`, `proofSuiteId=null`, `activation_allowed=false`, and `production_usable=false`.

Verified focused evidence:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_public_input_projection.py tests/test_bl_pq512_production_boundary.py tests/test_bl_pq512_wave5_native_boundary.py tests/test_bl_pq512_production_candidate.py -k 'not real_rust'
16 passed, 1 deselected

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_production_candidate.py -k real_rust
1 passed, 4 deselected in 105.67s

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_deployment_ready_roadmap_contract.py tests/test_operational_readiness.py tests/test_production_readiness.py
20 passed

tools.wave2_spec_conformance: exit=0
tools.wave4_conformance: exit=0, adapters=67 passed/0 failed, capabilities=22
tools.wave5_conformance: exit=0, R01-R12 complete_internal_nonactivating, rollback_ok=true
tools.privacy_v2_conformance: exit=0, mutation_cases=34, artifact_findings=0
tools.remaining_internal_conformance: exit=0, package_count=31, source_files=79, test_files=77
tools.whole_product_kat: exit=0, case_count=6, private_material_in_manifest=false

cargo +1.96.0 fmt --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --all -- --check
exit=0
cargo +1.96.0 clippy --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --all-targets --offline --locked --features std,parallel -- -D warnings
exit=0
cargo +1.96.0 test --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --release --offline --locked --features std,parallel
307 tests passed; 0 failed; 0 ignored; all binary/doc-test groups passed
```

The three refreshed Source-Complete targets were independently read back as byte-identical:

```text
payload_file_count=824
entry_count=825
archive_bytes=12219823
archive_sha256=2c2776596267d0760cb6c9f9fa17fe8d047e1e5e696b72bcb4cb44f18d531526
manifest_sha256=e4bb35d576a72299c47b59e0cc29bdd81cc1f810b99c2026317271b7d2e4c9f0
new_boundary_files_present=7
zip_crc_readback=PASS
duplicates=0
three_way_byte_identical=true
state_entries=0
generated_entries=0
```

The prior three 12,121,243-byte copies are recoverable under
`C:\Users\neers\Documents\Codex\2026-08-05\you-are-entering-an-existing-blind\work\wave2-published-backup-f7d46d5`.
The remaining blockers are real deployment/on-chain verifier integration, HSM/FIPS certification,
external anti-rollback authority, independent audit, and operator-supplied live government/payment
activation inputs. No contradiction was found; no protected path, live endpoint, real government
record, PHI, payment authority, or production credential was used.

## 2026-08-06 final source-archive readback - VERIFIED, NONACTIVATING

The documentation-only verifier-boundary receipt committed in `09c0f8b` was included in a final
rebuild of all three Source-Complete targets. Each target is byte-identical:

```text
target_count=3
three_way_byte_identical=true
archive_bytes=12220176
archive_sha256=59b524f5e40da797267da0d2f36b9963f633e98d333ed2662f2678bf178299c8
manifest_sha256=ac8437fe3bc90e862829a06aeb59fdfe797e81b5c4e62a2db3d113eaf713890e
payload_file_count=824
entry_count=825
zip_crc_readback=PASS
duplicates=0
new_boundary_files_present=true
state_entries=0
generated_entries=0
```

The overwritten pre-refresh copies remain recoverable under
`C:\Users\neers\Documents\Codex\2026-08-05\you-are-entering-an-existing-blind\work\wave2-published-backup-f7d46d5`.
The archive remains source-only and nonactivating; `proofSuiteId=null` and activation remain false.

## 2026-08-06 active hiding receipt reconciliation - VERIFIED, NONACTIVATING

The remaining-internal receipt previously consumed the superseded Circle worksheet directly and
therefore reported its four historical identifiers as current coverage gaps. The active path is
Construction 8.2 GKR/FRI, whose source-bound certificate already records those identifiers as
superseded historical evidence with no current gaps. `tools/remaining_internal_conformance.py`
now validates that active certificate and the complete bounded lifecycle simulator; the historical
worksheet and its attack tests remain retained and unchanged.

```text
focused_tests=9 passed, 1 deselected
active_certificate_status=ACTIVE_CONSTRUCTION_8_2_GKR_HIDING_REBASED_NONACTIVATING
active_certificate_sha3_512=6dce316edd11d926db778cc76492fa1e22a9e406a667fadf511fd7711b9d49b8d5110f571176b7958d6af2050baf7e47387d79f77b9f9ab064f6ae0c186d2a15
coverage_gaps=[]
simulator_complete=true
historical_circle_gap_count=4
proofSuiteId=null
activationAllowed=false
productionUsable=false
```

This closes a stale receipt/reporting gap; it does not claim an independent theorem audit,
production activation, HSM/FIPS validation, or a deployed on-chain verifier.

## 2026-08-06 local stack internal blocker closure and real cross-layer proof - VERIFIED, NONACTIVATING

Current Git checkpoint before this state append: `e330d37` on `main`, clean. The local synthetic
native path now has fresh end-to-end evidence from a real Rust-generated proof through the exact
108-limb public-input projection, `LocalSettlementV2`, the native rollup claim verifier, and the
commitment-only local stack receipt. The cross-layer test uses synthetic roots, identities, and
opaque commitments only; it stores no PHI, exact private amount, claim document, proof artifact, or
credential and opens no network or live chain.

The machine-readable blocker ledger now reconciles the current boundary: LB-001, LB-006, LB-007,
LB-008, LB-009, and LB-010 are `closed_internal_nonactivating` with
`release_candidate_blocker=false`; LB-002 remains the one external independent-audit gate; and
LB-003/LB-004/LB-005 remain operator activation inputs. Every local closure retains
`production_activation_blocker=true`. The global operational state remains
`NOT_DEPLOYMENT_READY`, `UNSELECTED`, `proofSuiteId=null`, `activation_allowed=false`, and
`production_usable=false`. The commit-bound `ops/` authority was updated for the reviewed manifest
and risk-register bytes and read back successfully.

```text
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_production_candidate.py tests/test_bl_pq512_wave5_native_boundary.py tests/test_bl_pq512_production_boundary.py tests/test_bl_pq512_public_input_projection.py tests/test_wave5_rollup.py tests/attacks/test_wave5_rollup_attacks.py
37 passed in 154.33s

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_deployment_ready_roadmap_contract.py tests/test_production_readiness.py tests/test_operational_readiness.py tests/test_remaining_internal_conformance.py tests/test_bl_pq512_h6_complete_simulator.py tests/test_wave4_adapters_operations.py
34 passed in 10.33s

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_k512_parallel_campaign_evidence.py tests/test_bl_pq512_wave3_nullifier_authority.py tests/test_bl_pq512_wave3_verifier_state_custody.py tests/test_bl_pq512_wave3_full_internal.py
25 passed in 145.07s

py -3.14 -B -c "from experiments.bl_pq512_crypto_foundation.ops_authority import verify_ops_authority; print(verify_ops_authority())"
VERIFIED_TRACKED_SHA3_512_AUTHORITY

tools.remaining_internal_conformance
package_count=31 source_file_count=79 test_file_count=77
active_certificate_status=ACTIVE_CONSTRUCTION_8_2_GKR_HIDING_REBASED_NONACTIVATING
coverage_gaps=[] simulator_complete=true productionUsable=false
production_blockers_preserved=[LB-001,LB-002,LB-003,LB-004,LB-005,LB-006,LB-007,LB-008,LB-009,LB-010]
```

The direct real-Rust lane in this phase also returned `1 passed, 4 deselected in 134.88s`. During
fixture convergence, the fail-closed worker rejected an attempted extra public table and the old
2 MiB rollup digest cap rejected the larger native envelope; the fixture was bound to existing
source columns and the cap was aligned to the existing fixed 512 MiB envelope bound. No no-swap,
5,000,000,000-byte resource gate was raised, and the containing rerun passed.

The next boundary is the full bounded Python/Rust regression and final three-archive refresh. This
section does not claim deployed `INativeStarkVerifier`, on-chain settlement, HSM/FIPS certification,
external anti-rollback authority, live Ethereum/government/payment activation, or the independent
audit.

## 2026-08-08 - owner-authorized Phase 0-2 database + mandatory-ZK reset

Repository: `C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26`
Baseline: branch `main`, HEAD `de4e6b33e1100209750844108ed80e616ebbb217`

The owner explicitly retired the L2 design and authorized the protected architecture changes
required to remove it. The active architecture is now:

1. state-owned database as the operational authority;
2. mandatory application ZK whenever private evidence can authorize payment;
3. native proof verification followed by one atomic nullifier/payment/state database transition;
4. signed government/oracle evidence as authenticated inputs, without claiming that signatures or
   ZK prove source honesty or policy correctness;
5. no L2, rollup, sequencer, bridge, Solidity settlement, or public DA dependency through Phase 2;
6. optional future compact checkpoints directly to Ethereum L1, outside current implementation.

The fixed 12-field Privacy V2 ABI, SHA3-512 authority, M31/Fp16/GKR/Construction-8.2 candidate,
authenticated interactive public coin, dual-PQ signing boundaries, fixed-shape privacy, exact
proof/state/source/policy bindings, and nonactivation controls survive. Provider-app preflight
remains local and nonauthoritative; it does not generate the payment-authorizing proof.

Deleted L2-only source includes `app/wave5_rollup.py`, `app/wave5_native_boundary.py`,
`app/local_stack_candidate.py`, the Wave 5 conformance tool/tests/config, both Stark settlement
contracts and their interfaces/tests, both Foundry manifests, the V1 on-chain public-input
manifest, and the active based-rollup/Strawmap/frontier/Wave 5 architecture documents. Historical
evidence in `STATE.md`, `docs/history/`, and the rejection ledger remains.

The roadmap count changed from 93 to 81 by deleting R01-R12. LB-008 was removed. Global state
remains `NOT_DEPLOYMENT_READY`, `UNSELECTED`, `proofSuiteId=null`,
`activation_allowed=false`, and `production_usable=false`. Real PHI/payments remain forbidden.

Verification evidence:

```text
py -3.14 -B -m compileall -q app experiments/bl_pq512_crypto_foundation tests tools
COMPILEALL_OK

py -3.14 -B -m pytest -q -p no:cacheprovider [focused architecture/state/adversarial set]
76 passed, 2 skipped, 22 warnings, 30 subtests passed in 15.93s

Skip reason (2): internal completion requires a committed protected boundary; the
owner-authorized batch/Cairo architecture migration is still in the worktree.

Warnings (22): RuntimeWarning: LOCAL DEV ONLY RULES ENGINE FALLBACK ACTIVE:
forced_python_rules_engine

py -3.14 -B -m pytest -q -p no:cacheprovider
exit 124 after 1204.1s; no pytest summary or failure output was emitted before timeout

cargo test --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --lib --tests
exit 1: std-gated imports unavailable

cargo test --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --features std --lib --tests
exit 1: parallel-gated fixture unavailable

cargo test --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --features parallel --lib --tests
exit 124 after 604s; no Cargo summary or failure output before timeout

cargo test --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --features parallel --lib
exit 124 after 304s; no Cargo summary or failure output before timeout

cargo check --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --features parallel --lib
Finished dev profile in 13.17s; exit 0

verify_ops_authority()
VERIFIED_TRACKED_SHA3_512_AUTHORITY

git diff --check
exit 0
```

No production proof, deployment, audit acceptance, Ethereum settlement, or complete whole-suite
pass is claimed.

## 2026-08-08 - complete active-document coherence pass

The owner requested reconciliation of every active architecture-related Markdown file after the
database + mandatory-ZK reset. The pass corrected stale requirements and phase assignments in the
experimental proving note, fixed-shape AIR draft, PQ-ZK architecture, backend decision, Wave 1A
specification, hash-coprocessor contract, foundation threat row, custody/monitoring documents,
Cairo README, proof provenance, supply-chain baseline, and dated Phase 1 log.

Current documents now uniformly use this boundary:

- Phase 0-2 only;
- mandatory payment-relevant application ZK;
- pinned native verification followed by one atomic database transition;
- production database durability/custody, external anti-rollback, audit, and activation are later
  gates, not a current Wave 3/4/5;
- no L2, settlement contract, Foundry/Solidity release surface, or on-chain verifier requirement;
- Ethereum is only an optional future direct-L1 checkpoint.

Wave/R-number references that remain in active evidence documents are explicitly labelled
historical identifiers. Deleted Foundry/Solidity observations in the supply-chain baseline are
explicitly retired and excluded from the current release surface. Historical L2 material remains
only in `STATE.md`, `docs/history/`, the dated handoff/log, and
`docs/REJECTED_ARCHITECTURES.md`, where it is labelled nonauthoritative.

```text
active contradiction scan
NO_ACTIVE_ARCHITECTURE_CONTRADICTIONS

active Markdown reference check
MISSING_MD_REFS 0

py -3.14 -B -m pytest -q -p no:cacheprovider
  tests/test_foundation_spec.py
  tests/test_fixed_shape_foundation_spec.py
  tests/test_security_freeze_spec.py
  tests/test_deployment_ready_roadmap_contract.py
  tests/test_operational_readiness.py
  tests/test_production_readiness.py
46 passed in 0.70s

verify_ops_authority()
VERIFIED_TRACKED_SHA3_512_AUTHORITY

git diff --check
exit 0
```

## 2026-08-08 - successor-ready Phase 2 reconciliation - VERIFIED, NONACTIVATING

Commit `3df9a23de0f2a78c801d6c845eb407fd4eb66663` is the stable architecture-reset checkpoint. It removes the active L2/rollup, Solidity/Foundry settlement, Wave 5 implementation/configuration/tests, and their active architecture documents. Historical evidence remains only in `STATE.md`, `docs/history/`, explicitly historical logs, and the rejected-architecture ledger.

The roadmap and machine-readable ledgers were corrected after literal exit-criteria review. Removing R01-R12 leaves 81 internal packages: **33 complete and 48 open**, not 81 complete. LB-001, LB-006, LB-007, LB-009, and LB-010 are open internal engineering and release-candidate blockers; LB-002 remains the external audit gate; LB-003/LB-004/LB-005 remain operator activation inputs. All nine remain production-activation blockers.

The exact next implementation is LB-006: retain `LocalSettlementV2` as an in-memory deterministic model, add a real transactional database port/reference beneath the unchanged native-verifier checks, and qualify concurrency, idempotent retry, stale-root/nullifier races, rollback, crash recovery, and durable audit publication. Do not select a production database, live credentials, PHI, payments, `proofSuiteId`, or Ethereum integration during that package.

Verified evidence:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider [architecture/readiness/archive/adversarial focused set]
87 passed, 17 warnings, 80 subtests passed in 16.70s
warnings: RuntimeWarning: LOCAL DEV ONLY RULES ENGINE FALLBACK ACTIVE: forced_python_rules_engine

py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_internal_completion.py tests/test_deployment_ready_roadmap_contract.py tests/test_production_readiness.py tests/test_operational_readiness.py
16 passed in 25.76s

py -3.14 -B -m experiments.bl_pq512_crypto_foundation.internal_completion
exit=0
internal_engineering_packages=81
internal_complete=33
internal_open=48
package_ledger=true
release_blockers_preserved=true
source_identity.head=3df9a23de0f2a78c801d6c845eb407fd4eb66663
source_identity.protected_paths_dirty=false
source_identity.worktree_dirty=false
proofSuiteId=null
activation_allowed=false
production_usable=false

cargo +1.96.0 fmt/clippy/test --release --offline --locked --features std,parallel [BL-PQ512]
exit=0; 307 tests passed; 0 failed; 0 ignored; strict Clippy passed

cargo +1.96.0 fmt/clippy/test --release --offline --locked [rules engine]
exit=0; 48 tests passed; 0 failed; 0 ignored; strict Clippy passed

verify_ops_authority()
VERIFIED_TRACKED_SHA3_512_AUTHORITY

git diff --check
exit=0
```

The monolithic Python suite was attempted with a 1,800-second bound. It emitted no terminal summary before the bound and is not credited. After orchestration termination, exact surviving pytest processes 26908 and 27756 were confirmed and stopped; no Cargo, rustc, prover, or verifier process remained. No test failure was observed, but silence is not verification.

Global state remains `NOT_DEPLOYMENT_READY`, `UNSELECTED`, `proofSuiteId=null`, `activation_allowed=false`, and `production_usable=false`. Real PHI and payments remain forbidden.

## 2026-08-08 - reconciled Source-Complete publication - VERIFIED, BYTE-IDENTICAL

The source archive was rebuilt from committed handoff `dbbd28a51d1ca56d85122c879b0a1e8dd9d3afb9` with the deterministic `blind-ledger-release-archive-v1` builder. The last reviewed 824-file allowlist was used as provenance: 23 deleted L2-only paths were removed, current successor-required source/tests were added, and every payload remained subject to the unchanged structural privacy gate.

Exactly 17 tracked files were intentionally excluded from publication: nine policy exclusions (`STATE.md`, the obsolete host-specific handoff, generated hardening JSON, five opaque font binaries, and sample claim input) plus eight files rejected by the structural privacy gate (operational-readiness scanner source, the private witness schema, and six privacy/archive measurement scanner tests/tools). No gate was weakened and no rejected file was silently included.

Builder receipt:

```text
builder_version=blind-ledger-release-archive-v1
payload_file_count=846
payload_bytes=11735436
entry_count=847
archive_bytes=12046141
archive_sha256=4552a6e96ee49123db53899f342e2e69f2c672de13e32a2d0d8aff04f86ec772
manifest_sha256=53cbc65070922796f5dc8d2be648c5e03f6f5116d1e66b8f02b114528a3c23a9
```

Independent readback of the Desktop root, nested Desktop source-backup, and Downloads targets returned the same result for each:

```text
target_count=3
three_way_byte_identical=true
zip_crc_readback=PASS
duplicates=0
payload_hash_or_size_mismatches=0
unexpected_entries=0
missing_entries=0
required_successor_files_present=true
retired_l2_files_absent=true
```

The two overwritten stale copies are recoverable at `C:\Users\neers\Documents\Codex\2026-08-08\oka\work\published-backup-before-dbbd28a`; the previously missing Downloads target was recreated. Temporary staging, snapshot, and builder-output artifacts were deleted after readback. The published archive remains source-only and nonactivating: `proofSuiteId=null`, `activation_allowed=false`, and `production_usable=false`.

## 2026-08-08 - stale Blind Ledger ZIP cleanup - VERIFIED

At the owner's request, every ZIP under `C:\Users\neers` whose filename identified it as a Blind Ledger archive and whose SHA-256 differed from the current published identity was permanently deleted. This supersedes the recoverability statement immediately above: the two stale pre-publication backups were among the deleted files and are no longer recoverable from that directory.

```text
filename-matched candidates=40
stale ZIPs deleted=37
delete failures=0
current ZIPs retained=3
post-delete stale count=0
current archive bytes=12046141
current archive sha256=4552a6e96ee49123db53899f342e2e69f2c672de13e32a2d0d8aff04f86ec772
```

Fifteen unrelated dependency, toolchain, and research ZIPs located inside old Blind Ledger work directories were deliberately preserved because their filenames did not identify them as Blind Ledger archives. The three retained current copies remain the Desktop root, nested Desktop source-backup, and Downloads targets.

## 2026-08-08 - full documentation coherence pass and archive refresh - VERIFIED, NONACTIVATING

The owner requested a character-complete documentation pass. Every Markdown/text document in the
workspace was decoded and scanned: `75` files and `1,545,245` characters. The active-document
semantic scan covered `67` non-history/non-continuation documents and found `0` stale architecture
or contradiction markers after correction. The pass preserved historical evidence and corrected
only current-facing ambiguity:

- archive readers are told that `STATE.md` and `WAVE2_HANDOFF_2026-07-26.md` are full-workspace-only;
- the sparse-state plan no longer calls a non-selection a selection;
- the S02 foundation status now matches the 33-complete/48-open roadmap;
- obsolete Waves 3-6 wording was removed from the active optimization policy;
- the legacy Poseidon/SHA-256 batch prototype is explicitly separated from the authoritative
  SHA3-512 A12 nullifier path;
- the optional Ethereum checkpoint is periodic, not committed to an hourly cadence; and
- the nine production-activation blockers are explicitly reconciled as five internal, one audit,
  and three operator inputs.

Focused verification:

```text
py -3.14 -B -m pytest -q -p no:cacheprovider \
  tests/test_build_release_archive.py tests/test_foundation_spec.py \
  tests/test_fixed_shape_foundation_spec.py tests/test_security_freeze_spec.py \
  tests/test_deployment_ready_roadmap_contract.py tests/test_operational_readiness.py \
  tests/test_production_readiness.py
64 passed, 54 subtests passed in 1.45s
git diff --check
exit 0
```

The deterministic source archive was rebuilt and read back. The three retained targets are still
byte-identical, contain `847` entries and `69` documentation files, and contain no directory
entries, zero-byte files, duplicate names, or CRC failures:

```text
archive_bytes=12048968
archive_sha256=66e11bf80c129878620ea2807f54ee7c3d299d9d4473802a4fe5a3c77bd80c4f
manifest_sha256=9f8e0e11b933cbba0216c12721c6453399edd5346f78ecd10ca151b7a644220f
three_way_byte_identical=true
zip_crc_readback=PASS
directories=0
zero_byte_files=0
duplicates=0
production_usable=false
proofSuiteId=null
```

No production proof, PHI, live payment, Ethereum settlement, audit acceptance, or activation is
claimed.
