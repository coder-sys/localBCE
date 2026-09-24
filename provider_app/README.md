# RightRail Provider App synthetic core

This isolated child contains a local, in-memory pre-submission core for fictional provider facts. It provides bounded request parsing, an immutable effective-date rule bundle, deterministic `PASS` / `MISSING` / `HUMAN_CHECK` outcomes, explicit missing facts and versioned rule citations, plus a separately written result reconstruction checker.

The only admitted bundle is `UNAPPROVED_SYNTHETIC_FIXTURE`. It may be used in synthetic tests only. `REAL_USE` returns `HUMAN_CHECK` before any rule evaluation. A content digest binds canonical fixture bytes only; it is not issuer authority, publication rights, truth, completeness, or approval.

## Layout

- `provider_app/contracts.py` contains closed typed facts, bundle, and result records and explicit bounds.
- `provider_app/codec.py` rejects unknown or duplicate fields, floats, malformed time values, oversize input, excessive nesting, invalid rule intervals, and digest mismatch. Parser failures use stable fixed error codes, including oversized integer tokens.
- `provider_app/evaluator.py` owns pure ordered outcome semantics. `provider_app/api.py` is the narrow in-memory byte adapter; it has no storage or external I/O.
- `provider_app/checker.py` independently reconstructs the complete result using only the Python standard library. It does not import the application package.
- `schemas` contains versioned request, bundle, and result contracts. The result schema fixes all five rule identifiers by position. `vectors/synthetic-vectors-v1.json` contains 26 fictional expected cases.
- `tests` includes 9 parser rejection methods, vector evaluation and independent reconstruction, checker mutation, lifecycle accounting, and duplicate/shuffled result-schema rejection. The optional `test` dependency supplies the Draft 2020-12 `jsonschema` validator.
- `lean/ProviderApp/Semantics.lean` is a façade over the pure typed decision model in `Semantics/Model.lean`, `Codes.lean`, `Rules.lean`, `RuleEvaluation.lean`, `Result.lean`, and `Properties.lean`, pinned to Lean 4.33.1. `lean/ProviderApp/InputProtocol.lean` parses the closed, size-bounded normalized argument through typed `Tokens`, `Facts`, `Rules`, and `Bundle` modules; the Lean parser also rejects populated fact fields in `REAL_USE` mode. `Main.lean` serializes the result and runs the executable. `provider_app/lean_compare.py` checks the Lean result against Python and the independent checker, verifies source/toolchain/package-manifest/artifact hashes, and fails closed on mismatch. The parser and semantics splits target smaller Lean modules, with output isolated under `.lake/provider-lean-split-r7`; this source revision has not been compiled. The r5 guarded build stopped at the process cap. Its executable hash remains `PENDING`, so comparison fails closed. It does not replace the Python application authority. See `lean/AdapterContract.md` for fields, limits, omissions, and proof boundaries.
- `docs/PRODUCTION_BACKLOG.md` lists dependencies that require real owners, trust roots, provider decisions, and deployment-specific review.

The fixture categories, source names, references, and amount range are invented. They are not billing codes, medical rules, payer policy, authorization logic, or coverage criteria.

## Limits and nonclaims

There is no real issuer, state, payer, program, provider identity, clinical catalog, source integration, UI, persistence, network, logging, telemetry, support export, claim submission, payment, or State financial-owner path. No PHI, provider/person identifier, claim ID, or claim-derived fingerprint is accepted or emitted by the result contract. User-supplied evaluation time is fixture input, not trusted time. Claims continue only through a provider's existing approved channel outside this core.

## Verification status

The request, rule-bundle, result, and vector JSON documents passed local parsing. The final guarded Python baseline passed all 13 original unittest methods, covering 26 synthetic vectors, 9 parser rejection methods, independent result reconstruction and mutation detection, and result-schema duplicate/shuffle negatives. The pinned Lean 4.33.1 semantics file compiled with `--trust=0` after a reserved constructor was renamed. These earlier checks establish only local synthetic behavior and source compilation.

The earlier semantics compile initially failed because `partial` was parsed as a reserved keyword; the source was corrected to `partialFixture`, then recompiled successfully. Executable-build attempts then included a Lake dependency error, two resource stops with `-j1`, and a Lean internal panic with `-j0`. After splitting the parser module, the one authorized `-j1` retry stopped at the process cap after building only `Semantics`; its nested PowerShell command also emitted a preamble error (`Stop=Stop`) caused by outer-variable interpolation. No executable hash was produced, and the focused differential suite did not run. The original 13-method baseline had no failures or skips.

The executable entrypoint, artifact pins, and focused differential tests are source additions. The parser is split into its own module and the package is configured for `-j1`, but the one post-split build attempt stopped at the unchanged process cap. The executable hash, vector comparison, malformed/oversize/version negatives, direct REAL_USE fact-token rejection, output version/tag/shape negatives, divergence, timeout, and zero-mutation checks remain unverified; all eight new focused test methods were not run because no executable was built. No theorem/axiom audit, proved Python-to-Lean refinement, benchmark, or selected-provider-profile resource measurement is claimed. There is no deployment readiness or provider adoption claim. See `STATE.md` for verified status and remaining skips.
