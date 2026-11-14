# RightRail

RightRail is a full-stack system for state Medicaid agencies and their
providers. Its product is one evidence record: the approved rule, the evidence,
open disagreements, the official's decision and the next action stay connected
until the work is done, and the state can replay the record and leave at any
time. The first paid jobs, from 2028, are a replay test before a late
claims-system replacement goes live and a read-only view for caseworkers and
county offices; eligibility evidence is the center of 2028 to 2030. The end
state is an inline gate that every Medicaid payment passes before money goes
out, under rules the state approves and signs. The state's own payment system
holds or releases the money; RightRail never moves it. The rollout order and
first jobs are in `docs/RIGHTRAIL_FULL_STACK_TARGET.md` section 2.

**Standing claims.** Member, claim and payment data in this repository are
synthetic; tests may also read public non-PHI reference data. It is
state-local, nonpayment and non-PHI, and moves no money. `proofSuiteId=null`,
`production_usable=false`, `activation=false`. Passing tests here is evidence
about this code, not a release qualification.

## The six products

What each one is, and what is real today, is in `ARCHITECTURE.md`; what runs is
in `STATUS.md`.

- **State Control Pack:** the state-approved rules and population, with the bounded export and restore of the record.
- **Blind Ledger:** the operating record and its one writer; the payment gate is its end-state function.
- **Mirror:** the read-only workspace for finance staff, caseworkers and county offices.
- **Switch:** read-only replay of the record against a candidate system.
- **Provider App:** a retail pre-submission checker sold to providers; nothing state-side depends on it.
- **Provider Trust Graph:** read-only provider evidence from public sources, its own product.

## What is formally verified, and how to check it

Lean code, proved against stated theorems, makes each consequential money
decision (correction transitions, payment and reversal accounting, gate
decision rules, checkpoint and token formats); a Python owner then commits
the answer. If a pinned executable fails, the command fails closed.

- `lean/` is one Lake workspace (`lake build`; toolchain in
  `lean/lean-toolchain`) with no unfinished proofs (`tests/test_no_sorry_source.py`).
- Proofs may rely only on Lean's standard axioms propext, Quot.sound and
  Classical.choice; `sorryAx`, `Lean.ofReduceBool` and user axioms are refused
  (each theorem's list is pinned).
- `tools/STMT_PIN.txt` pins one SHA3-512 root over every pinned theorem
  statement and everything it depends on. `tests/test_statement_pin.py`
  recomputes it.
- `tools/tcb_report.txt` lists, per shipped executable, every constant it
  reaches. All are proof-backed except the named exceptions that `STATUS.md`
  lists. `tools/tcb_pin.ps1` recomputes it
  and `tests/test_tcb_gate.py` gates it.
- `conformance/` holds byte-level specifications and test vectors, including
  must-reject cases, for formats an independent implementation must match
  (pinned by `conformance/MANIFEST.sha256`).

## Layout

| Path | Contents |
|---|---|
| `CONSTITUTION.md` | The governing rules |
| `STATUS.md` | Current state, open items, next steps |
| `ARCHITECTURE.md` | How the code fits together today |
| `docs/` | Target architecture, evidence model, SBOM, TLA+ model |
| `app/` | Payer app: owner, checker, Mirror, Switch, Provider Trust Graph, gate adapters, staff workspace |
| `lean/` | Lean sources and proofs |
| `rust/` | Rust ML-DSA-87 signer used by the gate |
| `conformance/` | Wire specifications and test vectors |
| `artifacts/` | Pinned executables; `PROVENANCE` gives source commit and hash |
| `tools/` | CLI, service kit, proof-goal files, statement and TCB pins |
| `tests/` | Test suite, vectors and fixtures |
| `provider_app/` | Provider App: pre-submission checker |
| `parked/` | Release producer, parked until a release is planned |

## Run the tests

```powershell
python -m pytest
```

This runs `tests/` (`pytest parked` runs the parked work). Many tests need a
built `lean/.lake`. `provider_app` is a separate project; run its tests from
inside it. The maintainers run all builds and tests through a resource guard
(Constitution X.2).

Development dependencies install offline from a hash-pinned wheelhouse
(`requirements-dev.txt`); production has no Python package dependency.

```powershell
python -m pip install --no-index --find-links <wheelhouse> --require-hashes --only-binary=:all: --no-deps -r requirements-dev.txt
```

The staff workspace runs loopback-only on a synthetic TEST owner:
`python -m app.right_rail_financial_staff_server --port 8765 --workspace <dir>`.
