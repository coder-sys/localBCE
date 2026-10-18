# Open questions (human decisions needed)

1. Tracked binaries and ZK artifacts (`.exe`, `.zkey`, `.ptau`, `.wtns`): approve removal/move per CLEANUP_PROPOSAL items 1–2?
2. Claim-identity HMAC key management (CLAIM-IDENTITY/v1, Phase 2): who holds the key, and how is it rotated? Not decided.
3. Is `integration/rightrail` allowed to receive PR #2 (import) before the Windows CI job is green on it? Proposed: yes for the import only, since it adds no runtime code.
4. CI runs on `pull_request` for every branch base. Confirmed the workflow triggers on PRs into `integration/rightrail` (it has an unrestricted `pull_request:` trigger). Verified by PR #1's run.
5. The Windows job added in PR 3 runs only the gate unit test. Full Windows coverage of the existing suites is not in Phase 0 and needs a decision on which known failures to record.
6. D-01/N-08 branch `codex/phase1-d01-n08` is pushed at `c6809326`, but the connected GitHub API returned `403 Resource not accessible by integration` when creating its protected-change PR, and the in-app GitHub browser is signed out. A human must open a draft PR from `codex/phase1-d01-n08` into `integration/rightrail`; do not merge it without protected-change approval.
