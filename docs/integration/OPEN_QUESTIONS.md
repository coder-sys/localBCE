# Open questions (human decisions needed)

1. Tracked binaries and ZK artifacts (`.exe`, `.zkey`, `.ptau`, `.wtns`): approve removal/move per CLEANUP_PROPOSAL items 1–2?
2. Claim-identity HMAC key management (CLAIM-IDENTITY/v1, Phase 2): who holds the key, and how is it rotated? Not decided.
3. Is `integration/rightrail` allowed to receive PR #2 (import) before the Windows CI job is green on it? Proposed: yes for the import only, since it adds no runtime code.
4. CI runs on `pull_request` for every branch base. Confirmed the workflow triggers on PRs into `integration/rightrail` (it has an unrestricted `pull_request:` trigger). Verified by PR #1's run.
5. The Windows job added in PR 3 runs only the gate unit test. Full Windows coverage of the existing suites is not in Phase 0 and needs a decision on which known failures to record.
