# Blind Ledger Wave 2 handoff

Updated: 2026-07-26

Status: authoritative clean-text checkpoint for the next Codex task. The owner paused execution
while the first complete semantic GKR-plus-GPU-PCS integration run was still unverified. Do not
restore old browser or PDF state. Do not infer completion from a benchmark, projection, compiled
binary, or interrupted process.

## Start here

Read these files completely, in this order:

1. `AGENTS.md`
2. `WAVE2_HANDOFF_2026-07-26.md`
3. `CONTINUATION_MANDATE.md`
4. `STATE.md`
5. `docs/IMPLEMENTATION_ROADMAP.md`, especially `Current large run: Wave 2`
6. `docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md`
7. `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`
8. `docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md`
9. `ARCHITECTURE.md`
10. `experiments/bl_pq512_crypto_core/README.md`

Then inspect the dirty tree with `git status --short`. Preserve every pre-existing change. The
snapshot is intentionally not a clean commit: most Wave 2 source is untracked relative to
`main` at `4b7e023de7de71ac8c94dbb4d637f4d053bdd393`.

The immediate source reading order is:

1. `experiments/bl_pq512_crypto_core/src/bin/gkr_coherent_chain_benchmark.rs`
2. `experiments/bl_pq512_crypto_core/src/multilinear_pcs_proof.rs`
3. `experiments/bl_pq512_crypto_core/src/multilinear_pcs_transcript.rs`
4. `experiments/bl_pq512_crypto_core/src/multilinear_pcs_query.rs`
5. `experiments/bl_pq512_crypto_core/src/mlpcs_gpu_worker.rs`
6. `experiments/bl_pq512_crypto_core/src/gkr_worker.rs`
7. `experiments/bl_pq512_crypto_core/cuda/cuda_mlpcs_fold_worker.py`
8. `experiments/bl_pq512_crypto_core/cuda/cuda_gkr_interactive_worker.py`

## Frozen product boundary

The following constraints did not move:

- absolute post-quantum design with at least 128-bit quantum security;
- a 256-bit cryptographic security/encryption floor for every theorem/error term and the composed
  security ledger;
- SHA3-512 is the sole authoritative public hash, state identifier, and transcript digest;
- Fp16/M31 arithmetic;
- authenticated interactive public coin, with no launch Fiat-Shamir or grinding;
- fixed-shape privacy, native hiding, fail-closed parsing and verification;
- no trusted setup, curves, RSA, pairings, external proving service, or host-trusted shortcut;
- the GPU is an untrusted accelerator; Rust recomputation and verification are authoritative;
- K128 below 60 seconds p95 and K512 below 180 seconds p95;
- peak resident memory no more than 5,000,000,000 bytes, scratch strictly below
  5,000,000,000 bytes, and no swap;
- a warm-up plus ten unique K128 and K512 batches with independent verification before
  qualification;
- Wave 1/A12 semantics and the 12-field compatibility ABI remain sealed;
- `proofSuiteId=null`; real PHI, payment credentials, and production activation remain forbidden.

Do not change the security target, statement, hash authority, privacy shape, or roadmap merely to
make a run pass.

## Verified current evidence

### Strict coherent GKR control

The current 782-permutation K128-shaped strict control passed independent reconstruction of every
public mask constraint, all sumcheck recurrences and terminal gates, public-coin replay, CPU/GPU
packed-polynomial equality, and equality of the GKR/PCS input openings.

| Field | Measured value |
| --- | ---: |
| Circuit geometry | 216 layers, 4,096 padded width |
| Authenticated GKR rounds | 8,785 |
| Total time | 35.1399522 seconds |
| GPU sparse time | 27.8003750 seconds |
| Strict mask aggregate time | 2.1389443 seconds |
| Complete PCS attached | false |
| Complete proof qualification | false |

Earlier packaged Q6 controls measured 32.5750 seconds at K128/782 and 32.7924 seconds at K512/894.
They were strict component controls without PCS and receive zero complete-proof qualification
credit.

### PCS memory corrections

The current source implements:

- bounded Merkle multiproofs from leaf hashes using only current and next levels;
- file-backed input/output codewords with exact size and canonical-decode checks;
- in-place parallel folds;
- no owned 2 GB encoded payload;
- removal of two redundant full 256 MB equality tables;
- authentication of the first prelude round before allocating the mixed FRI layer.

The resulting CPU file-backed peak was estimated historically at roughly 2.8-3.1 GB, down from the
old 7.5 GB path. The current owner criterion is no more than 5,000,000,000 peak resident bytes
(5 GB decimal), with no swap dependency. The estimate is not a completed measurement and therefore
still receives no resource-qualification credit;
only an externally monitored complete run below the exact byte limit can pass.

Focused evidence passed:

- file-backed opening/mix equality with the memory path and noncanonical rejection;
- retained, recomputed, and bounded Merkle proof byte equality;
- parallel/in-place batch fold equality with the scalar path;
- three PCS transcript tests;
- two PCS proof-codec tests.

The latest full Rust run executed 191 tests: 190 passed and one failed.
`gkr_worker::tests::malformed_and_stalled_workers_fail_closed` observed `Err(Timeout)` instead of
the expected `Err(Protocol)` during a parallel full-suite PowerShell worker launch. The exact
isolated rerun passed. Do not report 191/191; the full-suite classification race remains unresolved
unless reproduced and corrected with the smallest fail-closed change.

### GPU FRI arithmetic evidence

The production-geometry scratch control used 706 input coefficients/endpoints:

| Measurement | Value |
| --- | ---: |
| Domain | `2^25` Fp16 values |
| Value bytes | 2,147,483,648 |
| Power bytes | 134,217,728 |
| Bit reversal plus NTT | 0.7698361 seconds |
| Twenty-two folds | 0.0293228 seconds |
| Bounded 2 GiB device-to-host stream | 0.2328701 seconds |
| Fold KAT | final repetition equals multilinear evaluation |
| Endpoint KAT | external production endpoints equal |

The scratch program is outside this source snapshot at
`C:\Users\neers\Documents\Codex\2026-07-25\blind-ledger-clean-recovery\work\cuda_mlpcs_ntt_benchmark.py`.
These numbers establish GPU arithmetic and KAT behavior only. They do not establish a complete
proof, transcript, memory, or qualification result.

## Implemented but not end-to-end verified

The new GPU PCS path is:

- `cuda/cuda_mlpcs_fold_worker.py`: field mixing and folds only;
- `src/mlpcs_gpu_worker.rs`: bounded binary transport;
- `src/multilinear_pcs_query.rs`: streams every layer back to Rust;
- Rust recomputes SHA3-512 roots, canonical values, and Merkle multiproofs;
- the existing Rust verifier remains authoritative;
- reset/replay supports verifier-derived query openings;
- no extra 2 GB scratch file is introduced.

The worker is included in the pinned CUDA bundle. Its authoritative SHA3-512 source pin is:

`4e83333596b004503a53bb8a061d9bb7f6687a078fe3e1774ea80179a2063c618ef600d57c16d959b43407fc7da8295d78907e37bd4be4aa619ef377b4a255a7`

The identity-pin test and release build passed after that correction. The Python worker now adds its
own directory to `sys.path` before importing the pinned CUDA helpers. That import correction also
passed an isolated startup smoke check. The transport has never completed an end-to-end PCS proof.

## Failed and interrupted complete-proof attempts

1. The first launch failed immediately with `gkr_cuda_bundle:WorkerIdentity`. The stored pin had
   mistakenly used SHA-512 rather than SHA3-512. The pin above is the corrected value.
2. The second launch ran for 77 seconds, then failed closed because
   `cuda_mlpcs_fold_worker.py` could not import `cuda_fp16_tower_kat`. Rust returned
   `interactive_pcs:Query(Shape)`. Before failure, the monitored Rust working set peaked at
   1,982,533,632 bytes. The import path was corrected afterward.
3. The third launch began after the import correction, but the owner stopped it after about
   4.8 seconds to prepare this handoff. It emitted no completed proof result.

No proof process remains running. There is no K128 complete proof, K512 complete proof, ten-run
qualification, simulator qualification, or complete 256-bit security/encryption ledger.

## External reusable artifacts

These large artifacts are deliberately not duplicated into the source ZIP. Their exact current
paths, byte lengths, and SHA3-512 digests are:

| Artifact | Bytes | SHA3-512 |
| --- | ---: | --- |
| `semantic-gkr-706-entropy.bin` | 128 | `302f6915f1a50c5810a376466b2f25068185f25ebbe6ce60e9de70d2405a7525671eaddedc93c099d825cc5cce0831282c0a992905273fc5d41de9240ceff7e7` |
| `semantic-gkr-706-input.bin` | 262,160 | `3a652923a0515b91d99370996f41a36fb6b670ac4fa4ccceb7a96a71a8e024998d6f1f620f40fa9339f7aa49cf6947f0e646636b937331607344850c69bef625` |
| `semantic-gkr-706-output.bin` | 262,160 | `53a384cdff597b0ae7afe38e068eaa4587ecf31171b6b5125035586997ce6402f3300e0dcdb4d6c4232f60ce1960d10d114bec7420126f402e3cc2fb1dec7948` |
| `semantic-gkr-706-input-coefficients.bin` | 268,435,456 | `87a956ac74017681069ea8418b321d560630cd1e368921c1fc80cb4c0517df07243d5976753b38d41569dcec44bb70a99c2d4fbb47fdeaf902f5ec73b7b974de` |
| `semantic-gkr-706-output-coefficients.bin` | 268,435,456 | `6e7d09cd64be37662b92b9e79788a411ab03bf2acf803271456537d2561bb7441a1244975a35812ac18e4d78bdac047963e72f462a4019f23eeeaa651701b7ad` |
| `semantic-gkr-706-openings.bin` | 3,984 | `2ea6de9639b705066186316d0fb02056e1b5bde991264e0bb31a25de25c3ee092910fc41019695ed0af7821b4c56ed719867ab75d9d1bbac2364fc5650445f3f` |
| `complete-proof-scratch/input-codeword.bin` | 2,147,483,648 | `6ad7e56495706b429ce9f0aa2dd18e2b9c35feb85eeb09efe9eff6ad5b7a15931cdade4eb80d72dd3b2c3f7eed36d325e842f66f22149438a796743f25094df2` |
| `complete-proof-scratch/output-codeword.bin` | 2,147,483,648 | `8f7458f29f9e23bfd007c16b496d71bfe232df1a79c2630b8c6b0204964f31ced3e8325335669646ddabf71ff29867cfa206fc8c43021d4543e5d61797b7ac66` |

The first six files are under:

`C:\Users\neers\Documents\Codex\2026-07-25\blind-ledger-clean-recovery\work`

The two codewords are under its `complete-proof-scratch` child directory. Recompute and compare
SHA3-512 before reusing any artifact. The 706-permutation input is a semantic integration control,
not canonical K128 qualification.

## Exact resume boundary

Do not redesign and do not broaden tests. Resume with the smallest sequence that can answer whether
the new GPU PCS path is correct:

1. Confirm the corrected SHA3-512 worker pin and the worker-local import path.
2. Run one focused worker protocol/KAT at real 706 geometry, or a reduced strict transport test if
   the full transport cannot yet distinguish protocol failure from arithmetic failure.
3. Run exactly one complete 706 semantic integration proof with `BL_MLPCS_GPU_FOLD=1`, reusing the
   verified artifacts above. Monitor process working set, system available memory, and scratch
   externally. Require all of:
   - `complete_pcs_attached=true`;
   - `pcs_independent_verify=true`;
   - `public_coin_independent_replay=true`;
   - `semantic_output_boundary_verified=true`;
   - process exit code zero.
4. If it fails, preserve the raw fail-closed error and fix only its demonstrated cause.
5. Only after one complete proof passes, run the containing Rust suite under controlled load and
   resolve the worker error-classification race if it reproduces.
6. Then generate fresh K128 and K512 proofs and perform the mandated warm-up plus ten unique batch
   qualification with independent verification and measured p95 time, RAM, scratch, and no swap.
7. Complete the simulator, composition, security, privacy/leakage, rollback, atomicity, and
   fail-closed proof obligations before closing Wave 2.

Even a successful 706 integration run must continue to print
`complete_proof_qualification=false`; qualification requires the later gates above.

## Roadmap position

Wave 2 remains active. In plain English: the fast GKR engine is substantially implemented, the
memory-safe PCS path is substantially implemented, and the GPU PCS arithmetic looks fast. The
pieces have not yet completed one atomic proof together. Security/simulator closure and repeated
K128/K512 qualification remain after integration.

Gate status:

- 2A: open;
- 2B: substantially implemented but open;
- 2C: substantial GKR/PCS implementation, open;
- 2D: active integration, open;
- 2E: open until the complete proof and 256-bit security/encryption ledger close;
- 2F: not started.

The roadmap stays as-is. This handoff changes evidence status and resumption order, not the
architecture or security target.

## Dedicated workspace package

The transfer archive is named `Blind-Ledger-Wave2-Workspace-2026-07-26.zip`. It contains the entire
dirty source tree and Git metadata plus
`_handoff_support/cuda_mlpcs_ntt_benchmark.py`. Rebuild-only `cache`, `target`, `node_modules`,
virtual-environment, Python bytecode, and tool-cache directories are excluded. The external
multi-gigabyte artifacts listed above are not duplicated into the ZIP.
