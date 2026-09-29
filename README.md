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

| File | What it is |
| --- | --- |
| `CONSTITUTION.md` | Supreme rules. Every change complies with it. |
| `STATUS.md` | The only status: what runs, what is unrun, blockers, next steps. |
| `ARCHITECTURE.md` | How the code fits together today. |
| `docs/RIGHTRAIL_FULL_STACK_TARGET.md` | The complete target the code is building toward. |
| `docs/DESIGN_IDEOLOGY.md` | Engineering principles (source of Constitution Article XI). |
| `AGENTS.md` | Short instructions for AI agents working here. |

## Layout

| Path | Contents |
| --- | --- |
| `app/` | Financial owner, independent checker, Mirror, Switch, Engine port, staff server; direct-state-owned clearance seam; `app/mirror/` Provider Trust Graph |
| `lean/` | The one Lake workspace (package `RightRail`, library `BlindLedger`): financial semantics, the correction transition, the semantic kernel |
| `artifacts/engine-correction/` | The pinned correction executable and its `PROVENANCE.md` |
| `tools/` | CLI, offline service kit, privacy scanner |
| `tests/` | Product tests (`pytest` default run) |
| `provider_app/` | Provider App pre-submission checker (separate product) |
| `native/guard/` | Guarded runner for every heavy build or test |
| `parked/` | Parked work, off the critical path (`parked/README.md`) |

## How to run

All builds and tests go through the guard; never run them bare
(Constitution X.2). See `native/guard/README.md`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File native\guard\run.ps1 -Suite financial-correction
```

Suites live in `native/guard/suites.json` (`financial-correction`,
`service-kit-scenario`, `lean-engine-build`, `selftest`). The default `pytest`
configuration runs `tests/` and excludes `parked/`.

**Python dependencies** are installed offline only, into a fresh virtual
environment, from a pre-provisioned wheelhouse; pip refuses any wheel whose
SHA-256 differs from `requirements-dev.txt` (its header has the command).
Production has no Python package dependency (`requirements.txt` is empty);
development adds only pytest and its five dependencies. Changing any of them
means acquiring and reviewing new wheels, re-pinning their hashes and updating
`docs/SBOM.python.spdx.json`.

**Staff workspace** (loopback only, synthetic TEST owner):

```powershell
python -m app.right_rail_financial_staff_server --port 8765 --workspace <dir> `
  --correction-transition-executable <absolute path to artifacts\engine-correction\blind_financial_correction.exe> `
  --correction-transition-workspace <absolute empty dir>
```

Both correction paths must be absolute. Without them the server starts, but
correction commands fail closed. `--resume-existing-workspace` reopens and
re-verifies an existing TEST database instead of reseeding it.

**CLI** over an existing owner database:
`python -m tools.right_rail_financial_cli --database <db> summary` (also
`list-obligations`, `obligation-detail`, `history`, `reject-offset`,
`acknowledge`, `record-payment` and more; see `--help`).

**Offline service kit:** `python -m tools.right_rail_financial_service_kit`
with `assemble`, `verify`, `extract`, `run` (the one end-to-end scenario) and
`serve`. Assembly needs an Engine build receipt from a fresh guarded build.

**Provider Trust Graph view:** `python -m tools.provider_trust_graph_view
--artifact <graph> --request <request> --operation-ref <ref> --now <seconds>`.
