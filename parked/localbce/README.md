# Parked: localBCE proof and chain code

RightRail (`rightrail/`) is the base system. localBCE is wired into it without
Groth16, STARK, or Solidity/on-chain settlement
(`docs/integration/RIGHTRAIL_BASE_PLAN.md`).

Everything under this folder was moved here with `git mv`. It is parked, not deleted:
history is intact (`git log --follow <path>`), and each path mirrors where it
lived before, so `parked/localbce/stark-engine` was `stark-engine`.

Nothing here is built, tested, or run by CI, and no active code may depend on
it. Reviving any part needs an explicit decision recorded in
`docs/integration/CLEANUP_PROPOSAL.md`.

| Parked path | What it was |
|---|---|
| `zk/`, `deprecated/groth16/` | Groth16 circuit, keys and retired sources (runtime already retired in PR #4) |
| `stark-engine/`, `zk-prover/` | Winterfell STARK engine and SP1 prover |
| `blind-ledger/` | Foundry contracts: ClaimsRegistry, STARK registry and verifier |
| `blind-ledger-app-layer/{contracts,l2,zk,zk-stark,zk-sp1,zk-cairo-sharp,zk-production-binding}/` | App-layer contracts, devnet, and proof research lanes |
| `rust-engine/src/stark_activation.rs`, `rust-engine/config.stark.example.json`, `rust-engine/tests/stark_default_activation.rs` | STARK runtime activation for the adjudicator |
| `STARK_*.md` | STARK design and checkpoint notes |
| `scripts/` | STARK, Sepolia, Anvil and OpenZeppelin validators and the handoff crosswalk builder |
| `ops/*.example.json` | STARK deployment pins, release profile, Sepolia pilot, policy manifest |
| `tests/`, `scripts/tests/` | Tests for the parked scripts |

The STARK code removed from `rust-engine/src/main.rs` is recoverable from Git
history at `e746f58` (`git show e746f58:rust-engine/src/main.rs`).
