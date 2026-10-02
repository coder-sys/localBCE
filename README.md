# RightRail

RightRail gives a state Medicaid agency one operating record for a consequential
responsibility that crosses plans, providers and contractors. The first one is a
recurring financial responsibility such as a state-directed hospital payment
program. RightRail keeps the approved rule, the evidence, open disagreements,
the official's decision and the next action connected until the work is done.
Existing processors and payment systems keep moving the money; RightRail never
does.

It is five parts on one small foundation: **Control Pack** (the state-approved
rules), **Blind Ledger** (the one financial writer), **Mirror** (the staff
workspace over that writer), **Continuity State** (bounded export and restore)
and **Switch** (shadow comparison before any transfer). Lean decides each
consequential step; the Python owner commits it.

The reference scenario is synthetic: twenty hospitals and $1,000,000, where
Hospital H is owed $100,000 (the other nineteen total $900,000) and ends up
$3,000 short. Expected cents are derived by hand, never by the code under test.

## Read first

`CONSTITUTION.md` (supreme rules), `STATUS.md` (the only status), `ARCHITECTURE.md`
(how the code fits today), `docs/RIGHTRAIL_FULL_STACK_TARGET.md` (the target),
`docs/DESIGN_IDEOLOGY.md` (engineering principles) and `AGENTS.md`.

## How to run

All builds and tests go through the guard; never run them bare
(Constitution X.2), through `C:/Users/neers/rrb/tools/rr_guarded.ps1`. The
default `pytest` configuration runs `tests/` and excludes `parked/`.

**Python dependencies** install offline only, into a fresh virtual environment,
from a pre-provisioned wheelhouse (pip refuses any wheel whose SHA-256 differs
from `requirements-dev.txt`):

```powershell
python -m pip install --no-index --find-links <wheelhouse> --require-hashes --only-binary=:all: --no-deps -r requirements-dev.txt
```

Production has no Python package dependency; development adds only pytest and
its five dependencies. Changing any means re-pinning hashes and updating
`docs/SBOM.python.spdx.json`.

**Staff workspace** (loopback only, synthetic TEST owner):

```powershell
python -m app.right_rail_financial_staff_server --port 8765 --workspace <dir>
```

Corrections run on the pinned evaluator worker (`artifacts/engine-evaluator/`).
`--resume-existing-workspace` reopens and re-verifies an existing TEST
database instead of reseeding it.

**CLI** over an existing owner database:
`python -m tools.right_rail_financial_cli --database <db> summary` (also
`list-obligations`, `obligation-detail`, `history`, `reject-offset-and-authorize-correction`,
`acknowledge-action`, `record-payment-evidence` and more; see `--help`).

**Offline service kit:** `python -m tools.right_rail_financial_service_kit`
with `assemble`, `verify`, `extract`, `run` (the one end-to-end scenario) and
`serve`. Assembly needs an Engine build receipt from a fresh guarded build.

**Provider Trust Graph view:** `python -m tools.provider_trust_graph_view
--artifact <graph> --request <request> --operation-ref <ref> --now <seconds>`.
