# Provenance: blind_financial_worker.exe

Lake build of `lean/` (Git tree `e6f6aa67f44ea6fde606723a72973a57ed23b019`) after the unshipped decision-package v1/v2 model was cut, toolchain `leanprover/lean4:v4.33.1`.

- 6,510,592 bytes; SHA-256 `2AC5F5EB783AC99111B4A28B35DF6F23F47E773C2F10A281C01BC02E878841D8`; the engine module pins both.
- Built in-tree under the guard (`dp-build1`); the live TCB gate was regenerated on that build (`tcb-live-20261110011757`). Two fresh cold builds of `git archive 7cae185e lean` (`dp-stagea-a33`, `dp-stageb-a1`) each gave this worker byte for byte; `gate_verify` and `gate_engine` equal `tools/tcb_report.txt`, and `gate_rules` is the same in both builds.
- Worker laws use `propext`, `Classical.choice`, `Quot.sound` only.
- Why it moved: the worker's import closure holds the receipt types and codec, from which the unshipped v1/v2 input and projection model was removed. The decision the worker makes is unchanged.

Every earlier pin is in `artifacts/engine-correction/RETIRED_PINS` with its commit.
