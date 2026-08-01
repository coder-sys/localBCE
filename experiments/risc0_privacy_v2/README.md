# RISC Zero Privacy V2 qualification

Status: isolated backend qualification; not a production claim proof or verifier.

Current role: semantic/differential oracle only. The active Wave 2 release topology is the sealed
M31 semantic AIR plus shared-bus Fp16 Boolean GKR SHA3 coprocessor in
`../../docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`; no RISC Zero timing or receipt is evidence
for that topology's throughput or strict-PQ qualification.

This experiment proves one exact property with RISC Zero 3.0.5: private commitment inputs and
private exact totals produce the same ordered 12 public fields as Blind Ledger's Python/Cairo
Privacy V2 statement. The receipt is verified against the generated guest image ID, development
mode is disabled at compile time, and the public journal is checked against a Python-generated
Starknet Poseidon known-answer vector.

It does **not** yet prove the full claim parser, policy adjudication, oracle membership, Merkle
paths, sequential nullifier transition, payment accumulator, or Ethereum settlement transition.
No real claim or PHI is permitted in this experiment.

## Local run

RISC Zero 3.0.5 must be installed in WSL. From this directory:

```bash
./run_local.sh test
./run_local.sh prove
```

The host prints `proof_verified=true` only after local receipt verification and
`journal_matches_python_poseidon_kat=true` only after all 12 fields match.

CUDA is optional and is never silently selected. It requires a compatible NVIDIA driver and CUDA
toolkit, including `nvcc`, then an explicit build:

```bash
./run_local.sh prove-cuda
```

The wrapper places generated Cargo output under
`$HOME/.cache/blind-ledger-risc0-privacy-v2-target`, outside the release source tree. This is
required because production-readiness checks intentionally reject alternate proof-system build
artifacts inside the packaged application tree. The CPU proof is local and free. No Bonsai or
external proving service is used.

## Verified qualification run

On 2026-07-12, the pinned 3.0.5 host generated and locally verified a non-development receipt:

- `proof_verified=true`
- `journal_matches_python_poseidon_kat=true`
- 12 public fields matched exactly
- proving: `1472.797364` seconds
- verification: `0.134665` seconds

This result qualifies the commitment envelope only. It does not change the promotion gates below.

## Promotion gates

1. Port the complete V2 statement, reusing the Rust rules engine where semantics match.
2. Differentially compare every output and rejection condition against Python and Cairo vectors.
3. Prove fixed-size padding and metadata-leakage controls; an unchanged public nullifier root is
   observable and does not hide an all-denied batch.
4. Generate an Ethereum-compatible succinct receipt, pin the guest image and verifier artifacts,
   and make the L2 settlement contract reconstruct the exact journal.
5. Complete independent cryptographic, Solidity, privacy, and operational review before PHI use.
