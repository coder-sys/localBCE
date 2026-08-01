# Experimental implementations

Everything under this directory is isolated research code. It is not imported by the running
Blind Ledger application and is not a production proof or settlement path unless a separate,
reviewed integration explicitly says otherwise.

The current integration target is
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`: sealed M31 semantic AIR plus one hiding committed
bus and masked Fp16 Boolean GKR SHA3 coprocessor. Existing Cairo, RISC Zero, direct SHA3 AIR, and
narrow S-two experiments are differential or scale controls, not competing active release lanes.

## Current experiment

- `stwo_batch_air/`: official-Stwo custom AIR for aggregate decision and value-conservation
  constraints, with packed SIMD claim lanes, Rayon proving, a LogUp running-state relation,
  positive proof verification, and negative tamper tests.
- `risc0_privacy_v2/`: pinned RISC Zero 3.0.5 witness-hiding qualification for the exact
  12-field Privacy V2 journal and Python-generated Poseidon known-answer vector. It is not yet the
  full adjudication proof or an Ethereum verifier integration.

Read `docs/EXPERIMENTAL_PROVING_AND_PRIVACY.md` before evaluating performance or security claims.
