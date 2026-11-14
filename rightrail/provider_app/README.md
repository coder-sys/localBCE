# RightRail Provider App synthetic core

`provider_app/` is a retail product sold to providers, with nothing state-side depending on it: a local, in-memory pre-submission core for fictional provider facts. It provides bounded request parsing, an immutable effective-date rule bundle, deterministic `PASS` / `MISSING` / `HUMAN_CHECK` outcomes, explicit missing facts and versioned rule citations, plus a separately written result reconstruction checker.

The only admitted bundle is `UNAPPROVED_SYNTHETIC_FIXTURE`. It may be used in synthetic tests only. `REAL_USE` returns `HUMAN_CHECK` before any rule evaluation. A content digest binds canonical fixture bytes only; it is not issuer authority, publication rights, truth, completeness, or approval.

## Layout

- `provider_app/contracts.py`: closed typed facts, bundle and result records, explicit bounds.
- `provider_app/codec.py`: rejects unknown or duplicate fields, floats, malformed time, oversize or deeply nested input, invalid rule intervals and digest mismatch, with stable fixed error codes.
- `provider_app/evaluator.py`: pure ordered outcome semantics. `provider_app/api.py` is the in-memory byte adapter; it has no storage or external I/O.
- `provider_app/fix_list.py`: plain-words fixes for a check result (derived view, no new format).
- `provider_app/screen.py`, `screen/`: one loopback page (`python -m provider_app.screen`): pick a synthetic case, Check, read the outcome then the fix list with citations.
- `provider_app/checker.py`: independently reconstructs the complete result using only the standard library. It does not import the application package.
- `schemas` holds the versioned request, bundle and result contracts. `vectors/synthetic-vectors-v1.json` holds 26 fictional expected cases (see "Synthetic vectors" below).
- `tests` covers parser rejection, vectors, independent reconstruction and checker mutation.
- `lean/ProviderApp/` is the pure Lean decision model, pinned to Lean 4.33.1; `provider_app/lean_compare.py` compares its result with Python and the independent checker and fails closed on any mismatch or unpinned artifact. It never replaces the Python authority. See "Lean comparison contract" below.

The fixture categories, source names, references, and amount range are invented, not billing codes, medical rules, payer policy or coverage criteria.

## Limits and nonclaims

There is no real issuer, state, payer, provider identity, source integration, UI or network beyond one loopback-only synthetic check screen (`provider_app/screen.py`), persistence, outbound network, telemetry, claim submission, payment, or State financial-owner path. No PHI, provider/person identifier, claim ID, or claim-derived fingerprint is accepted or emitted. User-supplied evaluation time is fixture input, not trusted time. Claims continue only through a provider's existing approved channel outside this core.

## Real-use design

A real rule bundle is issuer-signed with publication, version, effective-date,
expiry and withdrawal data; a wrong digest, unknown or revoked key, or stale
authority fails closed. Claim data is read only for an authenticated provider
principal, with trusted time and approved schemas. A summary is in
`../STATUS.md`.

## Lean comparison contract

`ProviderApp/Semantics.lean` is an import façade over the pure model in
`ProviderApp/Semantics/` for the single unapproved synthetic fixture.
`ProviderApp/InputProtocol.lean` parses the closed normalized argument;
`ProviderApp/Main.lean` serializes the result and is the executable entrypoint.
`provider_app/provider_app/lean_compare.py` parses the request and bundle, evaluates them in
Python, checks the complete Python result with the independent checker, invokes
the pinned Lean executable, and compares every field the Lean result model
represents. It is a local diagnostic path; the Python API remains the result
authority.

### Build and artifact identity

The package under `ProviderApp/` pins `leanprover/lean4:v4.33.1` and builds
`providerAppLean.exe` with Lake, using `.lake/provider-lean-split-r7/`, with
`-j1`. Build it with `lake -d lean/ProviderApp build providerAppLean` (toolchain
v4.33.1); a rebuild changes the executable hash, so re-pin it in
`provider_app/lean_compare.py`. The adapter never
compiles, downloads, or substitutes an executable. Before each invocation it
checks the root and package toolchain pins and the hashes of `lean.exe`,
`lake.exe`, all Lean sources, the Lake file, package manifest, and exact built
executable; an absent, changed, or unpinned artifact fails closed with a fixed
error code. Summary: `../STATUS.md`.

### Input argument

The process receives exactly one ASCII argument, no stdin, and no raw JSON.
The strict Python request and bundle codecs run first, so malformed input
never reaches Lean. The normalized argument is at most 2,048 bytes; every field
is a closed token or canonical decimal integer, and none is a provider, patient,
claim, credential, or caller-selected authority field.

The argument is pipe-delimited with fixed positions (`ProviderApp/InputProtocol.lean`
holds the layout): the header `RRPA-LEAN-COMPARE/v1`, run mode and scope, the
evaluation time, the optional facts, the bundle fields, a rule count from 1
through 8, then nine fields per rule.

Dates use Python's one-based Gregorian day ordinal. Timestamps are integer
seconds from `0001-01-01T00:00:00Z`; only UTC-offset-zero timestamps with no
fractional second are accepted, and others fail with `LEAN_INPUT_UNREPRESENTABLE`
instead of being rounded. The Lean entrypoint checks that the evaluation day
agrees with the timestamp and derives the source received-day from it. The
source label and version are checked by the Python codec and omitted from the
Lean model, whose rules do not consult them. Bundle ID, fixture provenance and
issuer are closed Lean constants. The digest field is `1` only after strict
Python parsing has verified the canonical bundle digest. For `REAL_USE`, the
adapter sends empty fact tokens because the mode blocks the bundle and all
rules before fact evaluation, so no fact values reach the child process.

The Lean parser independently checks the exact header, ASCII and byte bounds,
closed tags, canonical decimals, the field count and the separator count (so
empty and trailing fields cannot be discarded). It rejects an R argument unless
all seven fact fields use the hyphen sentinel.

### Output and comparison

Lean emits one `RRPA-LEAN-RESULT/v1` line: aggregate outcome, ordered bundle
issues, all five ordered rule results (ID, citation, outcome, missing facts,
reason codes, and facts used), and aggregate missing facts. Every token is a
fixed code or a citation formed from the fixed bundle ID and bounded version
fields; the input is never echoed. On invalid input, `Main.lean` writes exactly
one fixed diagnostic line (at most 64 bytes, from the parser's closed error-code
set) to stderr, exits with status 2, and emits no stdout. The adapter requires the exact v1
header, canonical decimal counts, the five rule IDs in fixed order, closed result
codes, and no missing or trailing fields.

The adapter first requires `check_result` to accept the complete Python
result. It then inserts the actual Lean projection into that otherwise
unchanged full result envelope and asks the checker to reconstruct it before
requiring exact equality with the Python projection. Any malformed output,
nonzero exit, stderr, timeout, size-limit breach, or difference raises a
stable error and returns no result. This checks observed agreement; it is not
a proof of the Python parser's refinement into Lean.

The 26 vector cases assert four result field families (`outcome`, `issues`,
`ruleOutcomes`, `missingFacts`); the Lean projection represents all four, and
rule IDs and derived citations are also compared. The Lean result omits seven
top-level Python result fields (`contract`, `runMode`, `scope`, `evaluatedAt`,
`bundle`, `sourceBinding`, `limitation`). The independent checker still checks
them in the Python result; they are not claimed as Lean agreement.

### Resource and product limits

The adapter serializes Lean calls within one Python process and allows one
child process per comparison, a two-second deadline, a 2,048-byte input cap,
4,096 captured stdout bytes, 2,048 captured stderr bytes, and a 128 MiB
executable read cap; a process that exceeds a bound is terminated. These are
local adapter bounds, not a capacity measurement.

The path is deterministic and nonactivating, with none of the routes excluded in
"Limits and nonclaims" above. `REAL_USE`
continues to produce the existing `HUMAN_CHECK` block. Compilation and
differential agreement do not establish a theorem/axiom audit, proved
normalization, trusted time, issuer authority, provider adoption, deployment
readiness, coverage, authorization, clinical judgment, claim acceptance, or
payment.

## Synthetic vectors

`synthetic-vectors-v1.json` contains 26 fictional request/bundle cases with manually specified aggregate outcome, bundle issues, fixed rule order, and missing-fact list. The bundle template omits only its self-referential `contentDigest`; `tests/helpers.py` applies the case mutation, canonicalizes the remaining bundle members, computes SHA-256, and then encodes the canonical test bytes.

The vectors exercise PASS, MISSING, HUMAN_CHECK, missing fact enumeration, inclusive/exclusive date and amount boundaries, source completeness/conflict/replay/freshness, scope mismatch, publication, expiry, withdrawal, real-use rejection, and changed rule version. Every bundle remains `UNAPPROVED_SYNTHETIC_FIXTURE`; the vectors are not an authority catalog.

The vectors do not exercise package install/update, durable recovery, or rollback: the core has no installer, signature/revocation authority, persistence, or provider data source.
