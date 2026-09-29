# Provenance: blind_financial_worker.exe

Lake build of `lean/` at commit `1786e5c29140a21bbb8fd99d48a35ccd49fa1c62` (tree
`e4a0ed382236dc94ba6ba190e0a3f0be58e12902`), toolchain `leanprover/lean4:v4.33.1`.

- 5,707,776 bytes; SHA-256 `BE5EB80EB4BD43A97846A4FB6CAA54FAF4E1DB6629B43B9705D0657C7E8AE891`;
  the engine module pins both.
- Guarded fresh-stage build (`C:/Users/neers/rrb/logs/m1-stage2-a4.guard.log`); it reproduced
  `blind_financial_correction.exe` byte for byte, so that pin is unchanged.
- Worker laws use `propext`, `Classical.choice`, `Quot.sound` only. Record: `docs/CORE_REDESIGN.md`.
