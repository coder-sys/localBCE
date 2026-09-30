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
`-j1` (no Lake-wide job or memory quota is claimed). The adapter never
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

The argument is pipe-delimited. Field positions are fixed:

| Position | Meaning |
| --- | --- |
| 0 | `RRPA-LEAN-COMPARE/v1` |
| 1–2 | Run mode (`S`/`R`) and request scope (`A`/`B`) |
| 3–4 | Evaluation seconds and day ordinal |
| 5–8 | Optional service day, category, support-reference state, and cents |
| 9–11 | Optional source status, effective day, and received timestamp |
| 12–19 | Bundle version, scope, publication time, effective day range, expiry, withdrawal, and digest-match bit |
| 20 | Rule count from 1 through 8 |
| 21 onward | Nine fields per rule: ID, version, semantic, effective day range, optional category, optional minimum/maximum cents, and optional maximum source age |

Dates use Python's one-based Gregorian day ordinal. Timestamps are integer
seconds from `0001-01-01T00:00:00Z`; this adapter accepts only UTC-offset-zero
timestamps with no fractional second. Other offsets or fractional seconds fail with `LEAN_INPUT_UNREPRESENTABLE`
instead of being rounded. The Lean entrypoint checks that the evaluation day
agrees with the timestamp and derives the source received-day from its
timestamp. The source label and version are checked by the Python codec and
omitted from the Lean model, whose rules do not consult them. Bundle ID, fixture
provenance, and local-fixture issuer are supplied as closed Lean constants. The digest
field is `1` only after strict Python parsing has verified the canonical
bundle digest. For `REAL_USE`, the Python adapter sends empty fact tokens to
Lean because the mode itself blocks the bundle and all rules before fact
evaluation; this preserves the blocked-result comparison without forwarding
fact values to the child process.

The Lean parser independently checks the exact v1 header, ASCII and byte
bounds, closed tags, canonical decimal forms, the 21 + 9n field count and the
separator count (so empty and trailing fields cannot be discarded by splitting).
It rejects an R argument unless all seven fact fields at positions 5–11 use
the hyphen sentinel, making the empty-fact REAL_USE shape a parser invariant.

## Output and comparison

Lean emits one `RRPA-LEAN-RESULT/v1` line: aggregate outcome, ordered bundle
issues, all five ordered rule results (ID, citation, outcome, missing facts,
reason codes, and facts used), and aggregate missing facts. Every token is a
fixed code or a citation formed from the fixed bundle ID and bounded version
fields; the input is never echoed. On invalid input, `Main.lean` writes exactly
one fixed diagnostic line (at most 64 bytes, from the parser's closed error-code
set, unknown codes reduced to `LEAN_PROTOCOL_MALFORMED`) to stderr, flushes it,
exits with status 2, and emits no stdout. The adapter requires the exact v1
header, canonical decimal counts, the five rule IDs in fixed order, closed result
codes, and no missing or trailing fields.

The adapter first requires `check_result` to accept the complete Python
result. It then inserts the actual Lean projection into that otherwise
unchanged full result envelope and asks the checker to reconstruct it before
requiring exact equality with the Python projection. Any malformed output,
nonzero exit, stderr, timeout, size-limit breach, or difference raises a
stable error and returns no result. This checks observed agreement; it is not
a proof of the Python parser's refinement into Lean.

Each of the 26 manual vector cases asserts four result field families:
`outcome`, `issues` (mapped to `bundleIssues`), `ruleOutcomes`, and
`missingFacts`. All four are represented by the Lean projection (0 of 4
families, 0 of 104 case-field checks unrepresented); rule IDs and derived
citations are also compared. The Lean result omits seven top-level Python
result fields: `contract`, `runMode`, `scope`, `evaluatedAt`, `bundle`,
`sourceBinding`, and `limitation`. Those remain checked in the complete
Python result by the independent checker; they are not claimed as Lean
agreement.

## Resource and product limits

The adapter serializes Lean calls within one Python process and allows one
child process per comparison, a two-second child deadline, a 2,048-byte input
cap, 4,096 captured stdout bytes, 2,048 captured stderr bytes, and a 128 MiB
executable read cap; a process that exceeds a deadline or output bound is
terminated. Separate Python processes share no concurrency quota. These are
local adapter bounds, not a capacity or memory-quota measurement.

The path is deterministic and nonactivating, with none of the routes excluded in
`../README.md`. `REAL_USE`
continues to produce the existing `HUMAN_CHECK` block. Compilation and
differential agreement do not establish a theorem/axiom audit, proved
normalization, trusted time, issuer authority, provider adoption, deployment
readiness, coverage, authorization, clinical judgment, claim acceptance, or
payment.
