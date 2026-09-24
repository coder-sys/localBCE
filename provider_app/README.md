# RightRail Provider App synthetic core

`provider_app/` is a separate product: a local, in-memory pre-submission core for fictional provider facts. It provides bounded request parsing, an immutable effective-date rule bundle, deterministic `PASS` / `MISSING` / `HUMAN_CHECK` outcomes, explicit missing facts and versioned rule citations, plus a separately written result reconstruction checker.

The only admitted bundle is `UNAPPROVED_SYNTHETIC_FIXTURE`. It may be used in synthetic tests only. `REAL_USE` returns `HUMAN_CHECK` before any rule evaluation. A content digest binds canonical fixture bytes only; it is not issuer authority, publication rights, truth, completeness, or approval.

## Layout

- `provider_app/contracts.py` contains closed typed facts, bundle, and result records and explicit bounds.
- `provider_app/codec.py` rejects unknown or duplicate fields, floats, malformed time values, oversize input, excessive nesting, invalid rule intervals, and digest mismatch. Parser failures use stable fixed error codes, including oversized integer tokens.
- `provider_app/evaluator.py` owns pure ordered outcome semantics. `provider_app/api.py` is the narrow in-memory byte adapter; it has no storage or external I/O.
- `provider_app/checker.py` independently reconstructs the complete result using only the Python standard library. It does not import the application package.
- `schemas` contains versioned request, bundle, and result contracts. The result schema fixes all five rule identifiers by position. `vectors/synthetic-vectors-v1.json` contains 26 fictional expected cases.
- `tests` includes 9 parser rejection methods, vector evaluation and independent reconstruction, checker mutation, lifecycle accounting, and duplicate/shuffled result-schema rejection. The optional `test` dependency supplies the Draft 2020-12 `jsonschema` validator.
- `lean/ProviderApp/Semantics.lean` is a façade over the pure typed decision model in `Semantics/Model.lean`, `Codes.lean`, `Rules.lean`, `RuleEvaluation.lean`, `Result.lean`, and `Properties.lean`, pinned to Lean 4.33.1. `lean/ProviderApp/InputProtocol.lean` parses the closed, size-bounded normalized argument through typed `Tokens`, `Facts`, `Rules`, and `Bundle` modules; it rejects populated fact fields in `REAL_USE` mode. `Main.lean` serializes the result and runs the executable. `provider_app/lean_compare.py` checks the Lean result against Python and the independent checker, verifies source/toolchain/package-manifest/artifact hashes, and fails closed on any mismatch or unpinned artifact. It does not replace the Python application authority. See `lean/AdapterContract.md` for fields, limits and omissions.

The fixture categories, source names, references, and amount range are invented. They are not billing codes, medical rules, payer policy, authorization logic, or coverage criteria.

## Limits and nonclaims

There is no real issuer, state, payer, program, provider identity, clinical catalog, source integration, UI, persistence, network, logging, telemetry, support export, claim submission, payment, or State financial-owner path. No PHI, provider/person identifier, claim ID, or claim-derived fingerprint is accepted or emitted by the result contract. User-supplied evaluation time is fixture input, not trusted time. Claims continue only through a provider's existing approved channel outside this core.

## Real-use design

A real rule bundle is issuer-signed and carries publication, version,
effective-date, expiry and withdrawal data; a wrong digest, unknown or revoked
key, or stale authority fails closed. Claim data is read only for an
authenticated provider principal and role from the provider's own identity
system; effective dates use provider-approved trusted time; claim and source
fields follow approved, versioned schemas. The only admitted bundle is the
unapproved fixture, so `REAL_USE` returns `HUMAN_CHECK`. Run status is in
`../STATUS.md`.
