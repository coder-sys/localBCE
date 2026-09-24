# Qualification candidate current task

Updated 2026-09-24. This is the independent qualification checkout at
work/rightrail-qualification-gate-v3-20260923, Git baseline
2a1b573f91e8f3a5c5b1e44fc55594b9ee3b19c1 / tree
96bd66ae2de1004a3eb1f98467c0e31e489eb4e4. The current worktree is dirty;
preserve all pre-existing v3 gate, Continuity, and task-record changes.

## Follow-up request: separate runnable service kit

This is an additional deliverable request, distinct from the source-and-evidence
ZIP described below. The requested kit would package and launch the actual
synthetic Financial Owner/Lean correction service, with a same-owner staff and
Mirror surface, independent reconstruction, exact retry after response loss,
and an isolated Continuity SHADOW restore. It would need one assemble command,
one archive/source-pin verification command, and one extracted-package run
command, with exact dependency and source/binary identities.

### Ownership disposition

This checkout cannot author that product distribution. Its `AGENTS.md` permits
only its own qualification/acceptance tools, focused synthetic fixtures, and
task records, and makes product roots and release artifacts read-only
(`AGENTS.md:19-24`). A runnable server/package is State-owned product and
distribution behavior. No service source, executable, database package,
archive, installer, or run command was created here, and no product root was
modified.

A focused owner packet was sent to the active Lean State task on 2026-09-24:
`01a0cb32-5c56-7073-a400-2f084a32566f` (“Lean State”). It asks State to own
the kit in the financial product root, preserve the owner as sole writer,
implement/review the startup release injection, pin and rebuild Engine from
current source, prove the requested correction/retry/reconstruction and
SHADOW restore scenarios, and include Queue only when exact source-to-binary
provenance and runtime boundaries are reviewed. A short follow-up carries the
latest memory-floor and guard evidence. The message tool confirmed delivery to
that task; no implementation or review response is recorded here.

### Exact blockers carried to State

- `FinancialOwner` accepts an explicit correction transition release and
  defaults it to `None` (`app/right_rail_financial_owner.py:1616`). The staff
  server accepts injection in `StaffWorkflow` (`app/right_rail_financial_staff_server.py:112-151`),
  but normal `serve()` constructs `StaffWorkflow()` without one
  (`:686-690`), and the CLI exposes `--port` only (`:703-706`). The Owner's
  existing explicit-release path is not a packaged startup path.
- Engine `CorrectionTransition/Transition.lean` is 40,732 bytes,
  SHA-256 `E982BA7871E45138BD6AAF72434E4F43D17105D42F60413FEB3B57816AD3F01D`.
  The existing executable is 6,245,376 bytes,
  SHA-256 `E911E8844130155E4615D284D6D29A597B6E441DC45101D411EE8422EAE684B9`.
  Engine STATE binds that executable to a prior Transition source identity of
  25,674 bytes / SHA-256
  `342F3B1DF777095D75FD12970F29DFBC09AC06DCF48147EFF804EBA78E9021AE`.
  Current Transition source is uncompiled and unverified, so that executable
  cannot be represented as built from the current source. The known request
  vector is 3,357 bytes / SHA-256
  `13F832E80B93CC55D17ADD29470A2CD789CFCED1CBCF5A055FCBA3ECB927B537`; the
  expected result is 5,589 bytes / SHA-256
  `312AB06C76D6F6F2F40CF93F9EE37DA328161B733FE7D5567E0694B85D3AE18E`.
- Queue is not eligible for inclusion on current evidence. Its adapter says
  `legacy-pinned-v2`, `_LIFECYCLE_SOURCE_MANIFEST_SHA256=None`; the retained
  executable is 6,571,008 bytes / SHA-256
  `B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881`.
  Source-bound mode remains closed. Unless Queue supplies reviewed exact
  source-to-binary provenance and a reviewed runtime boundary, the kit
  manifest must say `MISSING/BLOCKED queue.lifecycle_source_bound_runtime`
  and omit Queue runtime behavior.
- The canonical target records bounded, no-replace producer-local Continuity
  restore evidence, while the independent replacement exercise remains open
  (`docs/RIGHTRAIL_FULL_STACK_TARGET.md`, Continuity and exit section). The
  requested package-specific SHADOW, query-only, no-dispatch, no-second-writer
  behavior has not been verified by this checkout. Keep that scenario blocked
  until the State owner supplies exact package/runtime evidence.

### Execution disposition and preserved work

No kit assemble, verify, or run command executed (3 skipped actions); no
compiler/build, test, or checker ran (0 executions). This checkout lacks the
direct finite-lane handoff required by its `AGENTS.md`, and the requested
service package is outside its ownership. Engine STATE records the v4 wrapper
failure as `RUNNER_FAILURE reason=Access denied\x20`, outer exit 1,
`MUTEX=RELEASED`, with no `PHYSICAL_PREFLIGHT`, launch, child-exit line, or
`CLEANUP=PASS`. The latest separate Driver-reported CIM sample was
4,063,748,096 bytes against Engine's 4,190,433,321-byte target start floor,
126,685,225 bytes below; Engine STATE says that sample is not the wrapper's
physical preflight or launch authorization. Do not retry or lower a floor.

The separate source-and-evidence ZIP workstream below remains source-only:
its 17 focused tests have 0 executions, its 69 identities (67 source payloads,
2 hash-only executable identities) are policy counts, its 8 evidence slots
remain MISSING, and the target ZIP remains unassembled/unverified. All eight
external gates remain open or unselected: issuer, revocation, source-to-binary
provenance, custody, approved profile, receiver, independent audit, and
release control. Claims remain `proofSuiteId=null`,
`production_usable=false`, `activation=false`; no release or production claim
follows.

At this handoff the direct Git roots were rechecked: qualification HEAD/tree
`2a1b573f91e8f3a5c5b1e44fc55594b9ee3b19c1` /
`96bd66ae2de1004a3eb1f98467c0e31e489eb4e4` (11 dirty entries before this
record edit); Financial HEAD/tree `8f75f527ae6717001978ac7401853c2aaae55f2b` /
`05d6df5bf4c36a9e267f2b471a86764a242f227e` (36 dirty entries); Engine
`907e32de63ab0d8133f2a7aff1441b06a1a884e8` /
`49d758924e298d935c16ffddacdadd945dec5f93` (33 dirty entries); Queue
`b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55` /
`40d8268880072f23b4c46fc83aee2c5084184083` (150 dirty entries). All product
root dirty work remains untouched.

## Objective

Provide one fixed-scope, offline, deterministic source-and-evidence bundle
assembler and verifier for one synthetic financial correction operation.
Integrate its local byte validation into tools/project_acceptance.py.
Capture the exact Lean toolchain/dependency locks and correction source
closures, theorem and axiom-check source, canonical vectors, State owner and
adapter/refinement/checker sources, Queue Lifecycle source/build/link inputs
and hash-only executable identities, Control Pack fixture, schema handling,
Mirror/report/support/Continuity sources, source/receiver contracts, workspace
map bytes, Git/dirty source identities, and supplied raw run logs.

The fixed inventory currently defines 69 file identities across four direct
Git roots: 67 required source payload entries and two hash-only executable
entries. The manifest defines 21 components, eight evidence slots, and eight
external gates. These are policy counts; required source presence and archive
assembly have not been executed or verified.

Static review added bounded descriptor-based reads for source payloads,
evidence files/logs, workspace-map snapshots, and archive input/readback. The
CLI reuses one parsed and validated manifest for archive and live-source
verification. File and component inventories remain fixed policy tuples; no
generic release framework or extensible manifest language was added.

Keep missing, failed, empty, skipped, stale, and structurally invalid evidence
visible. Raw command and guard streams are retained as archive members when
provided. Evidence freshness uses a required canonical UTC evaluation time
when evidence is present, making archive validation reproducible; that caller
input is not an authenticated clock. Self-asserted runner, issuer, signature,
and revocation fields cannot verify evidence.

The archive stays synthetic, nonpayment, non-PHI, and nonactivating.
proofSuiteId=null, production_usable=false, and activation=false remain
fixed. No schema, Control Pack instance, deployment profile, receiver, custody,
issuer/revocation authority, independent audit, source-to-binary provenance,
integration runner, or release control is selected. Integration/release stay
blocked; activation stays unselected. Do not change
tools/qualification_gate_v3.py or ops/launch_blockers.json.

## Commands

Run these commands from the qualification checkout root. The target output
directory currently exists; the assembler requires an existing directory and
refuses to overwrite an existing archive. Assemble the user-facing candidate at
C:\Users\neers\Documents\Codex\2026-09-24\rightrail-release-bundle\outputs\right_rail_synthetic_correction_bundle.zip:

    python -m tools.deployment_bundle --workspace-root C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1 --output C:\Users\neers\Documents\Codex\2026-09-24\rightrail-release-bundle\outputs\right_rail_synthetic_correction_bundle.zip

Verify archive bytes, then compare the captured source snapshot with current
local worktrees:

    python -m tools.deployment_bundle --verify-bundle C:\Users\neers\Documents\Codex\2026-09-24\rightrail-release-bundle\outputs\right_rail_synthetic_correction_bundle.zip --workspace-root C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1

Both commands are offline. Verification reports structural/source identity
only and keeps release blocked. The assembler refuses output under the
Driver's work directory so the archive cannot alter a captured worktree.
The existing project acceptance entry point remains:

    python -m tools.project_acceptance --workspace-root C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1 --phase development

## Current phase and gate

Source-only implementation and static review are complete. The focused test
file contains 17 test methods; zero test executions, builds, checkers, or
bundle assemblies have been run for this source identity. The output
directory exists, but the target archive is absent. Eight evidence slots
therefore remain MISSING.

All tests, builds, checkers, acceptance commands, bundle assembly, and bundle
verification require a new direct finite-lane handoff, fresh target-specific
v4 preflight, guard SHA-256
57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB, and
the 2,190,433,321-byte physical-free floor. The documented bounded-Python
start threshold is 3,221,225,472 bytes; fresh preflight and guard cleanup
remain mandatory. No direct handoff has been received for this checkout.

The exact recent Engine guard failure is recorded in the Driver Engine
STATE.md: RUNNER_FAILURE reason=Access denied\x20, outer exit 1,
MUTEX=RELEASED, no PHYSICAL_PREFLIGHT, no launch, and no CLEANUP=PASS.
Driver's external free-memory observation is not a guard preflight or a lane
grant. Do not retry the guard, lower a floor, or substitute another counter.

## Next bounded step

After a direct lane handoff and fresh preflight, run the 17 focused synthetic
acceptance tests under the documented bounded-Python threshold. Repair
failures without weakening checks. Then assemble the archive to the exact
outputs path above and run the read-only verification command with the
workspace root. Capture complete guard and command logs, child/outer exits,
cleanup, mutex release, archive/source hashes, component counts, evidence
statuses, and all warnings. Stop if preflight or cleanup fails.

The financial owner still fails closed at
correction_transition_unavailable for the current Engine transition. The
candidate cannot attest current Engine/State execution, formal proof results,
approved configuration, receiver, or release authority from source hashes.
All product roots remain read-only inputs. Keep every existing launch blocker
open and do not claim production or live activation.
