# RightRail Provider App synthetic core

`provider_app/` is a separate product: a local, in-memory pre-submission core for fictional provider facts. It provides bounded request parsing, an immutable effective-date rule bundle, deterministic `PASS` / `MISSING` / `HUMAN_CHECK` outcomes, explicit missing facts and versioned rule citations, plus a separately written result reconstruction checker.

The only admitted bundle is `UNAPPROVED_SYNTHETIC_FIXTURE`. It may be used in synthetic tests only. `REAL_USE` returns `HUMAN_CHECK` before any rule evaluation. A content digest binds canonical fixture bytes only; it is not issuer authority, publication rights, truth, completeness, or approval.

## Layout

- `provider_app/contracts.py`: closed typed facts, bundle and result records, explicit bounds.
- `provider_app/codec.py`: rejects unknown or duplicate fields, floats, malformed time, oversize or deeply nested input, invalid rule intervals and digest mismatch, with stable fixed error codes.
- `provider_app/evaluator.py`: pure ordered outcome semantics. `provider_app/api.py` is the in-memory byte adapter; it has no storage or external I/O.
- `provider_app/fix_list.py`: plain-words fixes for a check result (derived view, no new format).
- `provider_app/screen.py`, `screen/`: one loopback page (`python -m provider_app.screen`): pick a synthetic case, Check, read the outcome then the fix list with citations.
- `provider_app/checker.py`: independently reconstructs the complete result using only the standard library. It does not import the application package.
- `schemas` holds the versioned request, bundle and result contracts. `vectors/synthetic-vectors-v1.json` holds 26 fictional expected cases.
- `tests` covers parser rejection, vectors, independent reconstruction and checker mutation.
- `lean/ProviderApp/` is the pure Lean decision model, pinned to Lean 4.33.1; `provider_app/lean_compare.py` compares its result with Python and the independent checker and fails closed on any mismatch or unpinned artifact. It never replaces the Python authority. See `lean/AdapterContract.md`.

The fixture categories, source names, references, and amount range are invented, not billing codes, medical rules, payer policy or coverage criteria.

## Limits and nonclaims

There is no real issuer, state, payer, provider identity, source integration, UI, persistence, network, telemetry, claim submission, payment, or State financial-owner path. No PHI, provider/person identifier, claim ID, or claim-derived fingerprint is accepted or emitted. User-supplied evaluation time is fixture input, not trusted time. Claims continue only through a provider's existing approved channel outside this core.

## Real-use design

A real rule bundle is issuer-signed with publication, version, effective-date,
expiry and withdrawal data; a wrong digest, unknown or revoked key, or stale
authority fails closed. Claim data is read only for an authenticated provider
principal, with trusted time and approved schemas. Run status is in
`../STATUS.md`.
