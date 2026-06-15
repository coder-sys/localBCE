# Blind Ledger Cofounder Handoff

This is the slim technical handoff package. It is meant for review, repo import,
and cofounder/domain discussion. It excludes the huge local proving artifacts,
toolchains, generated build outputs, and runtime dumps from the full reproducible
archive.

## What This Contains

- App-layer Python claim flow, batch orchestration, 835 generator, fallback rules
  engine, provider aliasing, and tests.
- Rust rules engine source and tests.
- Solidity contracts and Forge tests.
- Groth16 circuit source files and ZK helper source where useful.
- Winterfell STARK PoC source/report files.
- SP1 glue/source/tests and audit notes.
- Production-binding circuit lane:
  - compiled Circom circuit source,
  - local witness/tamper-check runner,
  - local Groth16 smoke-proof runner,
  - proof/run reports.
  - `v0` is retained as the first compiled skeleton.
  - `v1` adds governed Merkle
    membership for oracle facts, fee/prior-auth rows, recipient address book, and
    a sparse nullifier insertion proof.
  - `v2` is the current security-relevant circuit: it adds a trusted parsed-claim
    `claimSourceRoot`, binds normalized claim facts to that root, and derives the
    nullifier from the pinned claim-source leaf plus member/provider/service
    identity.
- Architecture, reconciliation, RARC/CARC proposal, action-map, and security notes.
- SHA256 manifest for every file in this slim handoff package.

## What This Excludes

- `target/`
- `node_modules/`
- `.git/`
- `__pycache__/`
- local toolchains and toolchain download logs
- generated Circom build directories
- `.ptau`, `.zkey`, `.wtns`, `.r1cs`, `.sym`, `.wasm`
- local proof/runtime dumps
- previous giant full-build zip files

Those excluded files are useful for local reproduction or archival, but they are
not what a cofounder needs for review or a clean GitHub repo.

## Last Verified Test Gate

As of the package run on 2026-06-15:

- Python tests: 162 passed.
- Rust rules engine tests: 27 passed using the no-doctest command
  (`23 unit + 4 integration`; full doctests remain blocked by the local Windows
  rustdoc toolchain issue).
- Forge contract tests: 64 passed using the workspace Foundry 1.7.1 binary.
- Production-binding Circom circuit:
  - v0 compiles to R1CS with 7,696 constraints, but v0 is only a binding skeleton.
  - v1 compiles to R1CS with 53,199 constraints.
  - v2 compiles to R1CS with 58,506 constraints.
  - v2 approved witness passes.
  - v2 ineligible-denied witness passes.
  - v2 fabricated oracle facts reject.
  - v2 fake fee ceiling rejects.
  - v2 raw-hash double-pay attempt rejects.
  - v2 member-swap collision/grief attempt rejects.
  - v2 procedure-substitution attempt rejects.
  - v2 recipient redirect rejects.
  - v2 prior-auth bypass rejects.
  - v2 duplicate replay / forged non-membership rejects.
  - v2 over-wide amount rejects.
- Production-binding Groth16 smoke proof:
  - approved proof verifies,
  - tampered public decision rejects,
  - v2 proof size was 803 bytes in the local smoke run.
- Rust/Python adjudication equivalence remained PASS.
- SP1 host/prover script is still blocked on native Windows by missing `protoc`
  and Unix-specific SP1 prover/JIT dependencies; use WSL/Linux for that path.

## Current Trust Label

Soundness-checked where locally executable, PENDING CRYPTOGRAPHIC AUDIT.

Do not label the ZK/circuit layer production-secure yet. The app layer and
contract tests are green, but the cryptographic proof systems, circuit semantics,
governance process, and Medi-Cal policy correctness still require human/domain
review and external audit.

## Important Notes

- The payment bridge remains a stub/integration placeholder, not real money
  movement.
- Circle/FedNow access is partnership/access work, not just code.
- Generic RARC/CARC mappings are proposed and need cofounder/domain ratification.
- Batch proof architecture is the right gas-reduction direction, but production
  batch proving and verifier economics remain careful-track work.
- SP1/RISC Zero style EVM verifier wrappers are pairing-based SNARK wraps at the
  on-chain anchor, so they are not end-to-end post-quantum on-chain.
- Latest source-review fixes included in this package: payment inclusion now has
  `paymentCount` bounds; combined batch commitments bind `verifierKeyId` and
  `paymentCount`; payment leaves bind recipient commitments and approved-result
  commitments; result leaves bind gate evidence, engine mode, and matching claim
  identity; claim leaves separate claim facts from operator policy assertions;
  CLM/service-line total mismatch is rejected; duplicate identity survives pepper
  rotation.
- Latest catastrophic-gap closure pass: batch proof verification is fail-closed
  unless a real verifier accepts; the representative one-claim batch proof is no
  longer treated as blessing all approved claims; provider payment netting is
  reconciled before payment leaves are built; oracle attestations are scaffolded
  with signed-test acceptance and forged/unsigned rejection in strict mode; the
  Groth16 trusted-setup ceremony remains a planned human event, not something
  faked in this repo.
- Latest consolidated hardening pass: typed canonical encoding blocks delimiter
  and type-confusion hash collisions; app/witness inputs now reject noncanonical
  IDs, malformed dates/codes, fractional cents, negative/over-width amounts, and
  missing production secrets; oracle attestations now use an Ed25519 public-key
  interface with claim binding, validity windows, and replay hooks; batch
  contracts reject reused combined commitments, reused payment roots, arbitrary
  genesis roots, payment-without-nullifier-advance, single-claim adapters as
  batch checkers, and test verifiers outside explicit test mode.
- Honest blocker: field-native Poseidon roots across Python and Solidity were
  not implemented in this pass because no audited Solidity Poseidon
  implementation matching the local `pso-poseidon::new_circom` helper is
  vendored. No fake Poseidon or SHA mod-reduction was introduced.
- Latest production-binding closure: Claude correctly identified that the first
  compiled circuit (`v0`) still allowed prover-chosen oracle facts, fee ceilings,
  recipients, prior-auth flags, and nullifier state. `v1` was added to close
  those specific holes with governed Merkle membership and sparse nullifier
  insertion checks. Claude then correctly identified the v1 free-claim-story gap:
  `rawClaimHash` was still just a label unless normalized facts were pinned to a
  trusted parser output. `v2` closes that by requiring a Merkle proof under
  `claimSourceRoot` and deriving the nullifier from the pinned claim-source leaf.
  Important caveat: this is still a Circom/Groth16 smoke lane, not an end-to-end
  post-quantum lane. The verifier/contract must pin `claimSourceRoot`,
  `oracleFactsRoot`, `feeScheduleRoot`, `addressBookRoot`, `rulesetRoot`, and the
  nullifier root to governed state. Ed25519 oracle signatures are not verified
  inside this circuit, and the nullifier construction still needs external
  cryptographic audit.
