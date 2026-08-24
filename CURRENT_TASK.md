# Blind Ledger and Mirror current task

Updated: 2026-08-24

SOURCE WORKSPACE: C:\Users\neers\Documents\Codex\2026-07-27\he\work\Blind-Ledger-Wave2-Workspace-2026-07-26
CONTROLLED INTEGRATION WORKTREE: C:\Users\neers\Documents\Codex\2026-08-23\blind-ledger-mirror-sol-driver-v2\work\controlled-integration-both-20260824
PHASE: Combined controlled integration candidate; authoritative main remains read-only; no archive action.

## Objective

Verify and integrate the accepted Blind Ledger and Mirror candidate histories from the common clean
base `b74356a0659360223c9b5007f33cb57d4e8f1fd9`, synthesize the authority records once, and leave
one clean candidate for explicit promotion review. Do not start the breaking Native amount/state
revision from stale product branches.

## Exact integrated inputs

Blind Ledger source head: `a5870965122fc5b4f7312b6723b3ac9e5e2454a5` (36 linear commits).
Its current boundary is verifier custody, durable independent Queue V4 promotion, single-owner
runtime/recovery, atomic composition, and official-system handoff/acknowledgment. The final
promotion cleanup correction was personally diff-reviewed; broader test totals remain worker-run
evidence unless separately identified.

Mirror source head: `5b91f03db089445588526d533a9069bddf56ce92` (41 linear commits). Its
current boundary is consolidated Ingress/Core/Recovery ownership plus the synthetic NC FHIR
source contract. The final correction was personally inspected: exact registered fixture bytes are
required before Ingress mutation, and graph credential/enrollment identities bind the verified
resource bytes. Its suite totals remain worker-run evidence.

The two histories have zero path overlap across all 77 commits. Both were replayed in source order
onto the common base without conflict. At replay tip `78084d5dc1290ad9cf906186bc06838a6a530ebb`,
all 55 final Blind paths were byte-equal to the Blind source head and all 71 final Mirror paths were
byte-equal to the Mirror source head.

## Current integration gate

The candidate must pass documentation governance, release/path classification, zero-PHI/privacy
scans, focused Blind queue/composition/runtime checks, and focused Mirror source/Ingress/Core/
Recovery checks. Failures must be classified causally; no gate, warning, or skip may be hidden.
After a clean synthesis commit, promotion to authoritative main remains a separate explicit Git
operation.

## Next product dependency

After this candidate is accepted, Blind Ledger's next breaking seam is Native statement/state
revision: bind one private proposed amount through a public hiding commitment, derive the authorized
commitment from the effective directive, and use one canonical sequential state identity. The old
composition must reject that grammar until its own reviewed versioned upgrade.

Mirror's next seam is a single operational owner around authenticated acquisition scheduling,
leases, bounded due work, retry eligibility, and recovery. It may not add a daemon framework,
second raw owner, payment authority, or synthetic production claim.

## Fixed nonclaims

`proofSuiteId=null`, `production_usable=false`, and activation remain false. No production proof
backend, Lean clearance authority, live source authorization, PHI approval, official receiver,
payment movement, settlement, HSM/FIPS custody, production persistence, HA/DR, monitoring, or state
operational approval is claimed. The incumbent adjudicates and official state systems move money.
