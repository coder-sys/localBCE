# Provenance: blind_financial_worker.exe

Lake build of `lean/` (Git tree `e6f6aa67f44ea6fde606723a72973a57ed23b019`) after the unshipped decision-package v1/v2 model was cut, toolchain `leanprover/lean4:v4.36.0`.

- 7,425,536 bytes; SHA-256 `4BAE13D7ADCA231AC2EB66BCA4BA4906DADF824AF91C9BB2C020E1068E4A1213`; the engine module pins both.
- Built in-tree under the guard (`dp-build1`); the live TCB gate was regenerated on that build (`tcb-live-20261110011757`). Two fresh cold builds of `git archive 7cae185e lean` (`dp-stagea-a33`, `dp-stageb-a1`) each gave this worker byte for byte; `gate_verify` and `gate_engine` equal `tools/tcb_report.txt`, and `gate_rules` is the same in both builds.
- Worker laws use `propext`, `Classical.choice`, `Quot.sound` only.
- Why it moved: the worker's import closure holds the receipt types and codec, from which the unshipped v1/v2 input and projection model was removed. The decision the worker makes is unchanged.

- Moved again (2026-11-22, branch lean436-20261122): the worker decodes each frame in place with `Cursor.decodeFinancialInput` (equal to the list decoder by `Cursor.decodeFinancialInput_eq`) and sizes its read buffer from the frame length; the list decoder cost 24 bytes of memory per frame byte on Lean 4.36.0. Decisions unchanged. Built in-tree under the guard (`l436-b1`); the live TCB gate was regenerated on that build.

Every earlier pin is in `artifacts/engine-correction/RETIRED_PINS` with its commit.
