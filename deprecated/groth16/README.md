# Retired Groth16 Reference

The Groth16 claim path is retired under D-01/N-08. Nothing in this directory is
part of the Rust runtime, the Foundry source tree, or a deployment workflow.
The files remain only for review and historical comparison.

The original circuit did not bind the claim identity or amount to public
inputs. Its verifier and registry must not be deployed or called.

## Moved source hashes

```text
8662b2a331f4624692efbfb5ab4316525bc3d8c6a3bd9e269ffd7af6f38dd3ee  zk/claim.circom
c1d8a127c695610d9fd0bb6db27c531f9ae5449ee2a06e9fa10e9f74c8432904  blind-ledger/src/ClaimsRegistry.sol
6a9569406d0ee2f6996755ce2bda6184ec3b0d47dcd6e4110821b3cf3d5c13d6  blind-ledger/src/Verifier.sol
a6ba8fc5a78d7039a07e63c7269f21b4d786796373ecaaed26465f62a7994534  blind-ledger/script/Counter.s.sol
1202099256be371cf0caa8ec3db0bb6c16def2ea1abfdbff4d92512c3b1d3bbc  blind-ledger/test/ClaimsRegistry.t.sol
10a70ba7da7956cf419195a0302418d5194fa77372a4125c18767b1c2d30fa29  blind-ledger/test/DeploymentJson.t.sol
```

## Tracked artifacts awaiting cleanup approval

These artifacts remain in `zk/` because their move or removal is not approved
in `docs/integration/CLEANUP_PROPOSAL.md`. They are not reachable from the Rust
runtime after D-01, but they still fail the repository tracked-artifact check.

```text
f5e7cb6c63562d7def779692b23e6b0167cd73952c44f6230d98180b93d2b2f1  zk/claim.r1cs
741bc712e886ed8792372bfefe94f16b6945393ce22713bfc97e9297fb0f2c26  zk/claim.sym
d27f45db876e959e4919cbc89e73268ddc92c2d6cdeaf7ca715a9f1914da2cfd  zk/claim_0000.zkey
9546d201e8b626c3e8b5ca4e60b73457fd3309b7a685641610beabee42d350dd  zk/claim_final.zkey
86aa4c2492f1c5cc80f2b975197d22d8a3d3de2305cced76a20657abbae1c3ad  zk/claim_js/claim.wasm
4995a2e6b01432f76182abec6a831fdaf7f840384035072002ccaa43101b14d4  zk/claim_js/generate_witness.js
3bfca49ee5489996a827a1e5a0c8a1f558dbd99e657c7591f5b32e0d33189ce4  zk/claim_js/witness_calculator.js
53d0e9d1a3576412ada39a82c8ffadd7f110c1b13de56d89b52a472ce5e5edf4  zk/powersOfTau28_hez_final_10.ptau
cf988e0abf9208493530bd5d382e5db7f6e80013d34a9bd3552d66ca21ceb5b3  zk/proof.json
5cd2dcf8f321ff5701096598e501c069c602de1ef39849b8e2904f8ae882797f  zk/public.json
4ec00b9f70edd5f3abd10b28d4a784df0f21915e146eb89159cd2e57a7c6540f  zk/verification_key.json
cb62f353946ce9afb7c3181cc57e316ca46058dcab94b75a88c4e038f7216a13  zk/witness.wtns
```
