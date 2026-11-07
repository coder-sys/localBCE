# Open questions (human decisions needed)

Items marked DECIDED or RESOLVED stay listed so their history is readable.

1. Tracked binaries and ZK artifacts (`.exe`, `.zkey`, `.ptau`, `.wtns`). DECIDED 2026-11-07 (owner approval, agent judgment): the four parked Groth16 files are removed, recoverable from Git history; RightRail's two pinned worker `.exe` files are kept and checked against their pinned SHA-256. See CLEANUP_PROPOSAL items 1-2.
2. Claim-identity HMAC key management (CLAIM-IDENTITY/v1, from the earlier roadmap): who holds the key, and how is it rotated? Not decided. Under `RIGHTRAIL_BASE_PLAN.md`, member and line identity are RightRail's (`idWidth` identifiers, owner-held keys); this item is open until the RightRail lead says whether localBCE still needs its own claim key.
3. RESOLVED: PR #2 (import) was merged.
4. CI runs on `pull_request` for every branch base. Confirmed the workflow triggers on PRs into `integration/rightrail` (it has an unrestricted `pull_request:` trigger). Verified by PR #1's run.
5. Windows coverage. DECIDED 2026-11-07: `windows-smoke` runs `cargo test` and both Python suites (`scripts/tests`, `tests`). Passed locally on Windows with Python 3.10 (37 and 49 tests); not yet run in CI. The Postgres-backed rules pipeline stays Linux-only, and RightRail's own suite waits for its guard script (plan §7 item 1).
6. RESOLVED: the D-01/N-08 work was merged as PR #4 (`e746f58`).
7. Human review (Phase 2 parity, 98 lines). DECIDED 2026-11-07 (plan §7 item 6): RightRail's HUMAN_REVIEW on stale or unverified data and bad dates replaces localBCE's outright approve or deny.
8. G7 and capitation. DECIDED 2026-11-07: a capitation member-month duplicate is R2 (`CAP_MEMBER_MONTH_DUPLICATE`); G7 maps to R2 as well as R4.
9. Unresolved set and line identity (22 lines). DECIDED 2026-11-07: accepted as R-rule semantics with no localBCE counterpart.
10. First failing gate versus all reasons. DECIDED 2026-11-07: RightRail reports every reason.
11. `RR/RULES/CONTENT/v1` is a localBCE proposal. OPEN: RightRail treats formats and digest domains as protected (CONST XI.2); adopting it needs an XI.2 record and an `rr-core` review, which wait for the RightRail lead (plan §7 item 2).
12. Phase 3-4 blockers. OPEN: no `rr_guarded.ps1`, no Lean toolchain, and no `rr-core`/`rr-review` on this machine. Phase 3 (new Lean rules and evidence) and the Phase 4 work inside `rightrail/` (837 adapter, owner as single writer) need them; retiring the bridge and the Rust reference follows from those.
