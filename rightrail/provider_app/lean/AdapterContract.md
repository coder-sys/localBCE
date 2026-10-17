# Bounded Lean comparison contract

`ProviderApp/Semantics.lean` is an import façade over the pure model in
`ProviderApp/Semantics/` for the single unapproved synthetic fixture.
`ProviderApp/InputProtocol.lean` parses the closed normalized argument;
`ProviderApp/Main.lean` serializes the result and is the executable entrypoint.
`provider_app/lean_compare.py` parses the request and bundle, evaluates them in
Python, checks the complete Python result with the independent checker, invokes
the pinned Lean executable, and compares every field the Lean result model
represents. It is a local diagnostic path; the Python API remains the result
authority.

## Build and artifact identity

The package under `ProviderApp/` pins `leanprover/lean4:v4.33.1` and builds
`providerAppLean.exe` with Lake, using `.lake/provider-lean-split-r7/`, with
`-j1`. The adapter never
compiles, downloads, or substitutes an executable. Before each invocation it
checks the root and package toolchain pins and the hashes of `lean.exe`,
`lake.exe`, all Lean sources, the Lake file, package manifest, and exact built
executable; an absent, changed, or unpinned artifact fails closed with a fixed
error code. Run status: `../../STATUS.md`.

## Input argument

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

## Output and comparison

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

## Resource and product limits

The adapter serializes Lean calls within one Python process and allows one
child process per comparison, a two-second deadline, a 2,048-byte input cap,
4,096 captured stdout bytes, 2,048 captured stderr bytes, and a 128 MiB
executable read cap; a process that exceeds a bound is terminated. These are
local adapter bounds, not a capacity measurement.

The path is deterministic and nonactivating, with none of the routes excluded in
`../README.md`. `REAL_USE`
continues to produce the existing `HUMAN_CHECK` block. Compilation and
differential agreement do not establish a theorem/axiom audit, proved
normalization, trusted time, issuer authority, provider adoption, deployment
readiness, coverage, authorization, clinical judgment, claim acceptance, or
payment.
