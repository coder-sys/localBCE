# Governance

- Branch and PR only. Work lands on `integration/rightrail` through PRs. Never push to `codex-dev` or `main`.
- No history rewrites on shared branches. No force-pushes.
- Protected-change PRs (CI config, signing, key handling, contracts) need a human reviewer. The agent does not approve its own.
- Commit authors: the repo's existing identity only. Do not invent authors.
- Phase boundaries: stop, post the phase report, wait for "continue".
- Deletions require an approved entry in CLEANUP_PROPOSAL.md.
