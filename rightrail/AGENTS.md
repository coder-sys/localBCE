# Contributor and agent rules

This is the single RightRail codebase. Read, in order:

1. `CONSTITUTION.md`: supreme rules. Every change must comply.
2. `STATUS.md`: what runs, what is written but unrun, blockers, next steps.
3. `docs/RIGHTRAIL_FULL_STACK_TARGET.md` and `ARCHITECTURE.md`: target and
   current boundaries.

Working rules (details in the constitution):

- All product code lives here. Do not create per-team copies of modules.
- Builds, tests and provers run only through the resource guard named in the
  constitution (X.2); never weaken or bypass it.
- Lean decides; Python adapters commit. No duplicate policy, no silent fallback.
- Each pinned executable is built from the `lean/` commit its `PROVENANCE` file names
  (`artifacts/engine-evaluator/`, `artifacts/gate-verify/`). Any later `lean/` change
  voids that claim until a guarded rebuild re-pins it.
- Private zero-knowledge is an evidence-only prototype in its own repository (Constitution IX.4).
- `STATUS.md` is edited once per trunk merge, replacing what it supersedes.
- Standing claims: CONSTITUTION VI.2. README and STATUS quote it; never state more.
- Documents: every fact has one owner and other files link to it. A new hand-written `.md` needs an entry in
  `tests/test_doc_shape.py` naming the fact it owns (a directory's own `README.md` needs none); at the cap, merge or
  delete a doc first. Raising the cap needs the written approval of the people the Constitution names.
- Never destroy uncommitted work, evidence, keys or the only copy of anything; no `git reset --hard`, `git clean` or force push.
