# Shadow run: design

Status: **approved by the owner on 2026-11-28 with changes (section 7). Built, and run once on 2026-11-28 under the
memory guard: all 13 scenarios gave their predicted outcome (section 6.1). It is a test-key run that decides nothing
and binds no one.**
Written 2026-11-28 against `codex/rightrail-trunk-e5d0f36b` at `7efc96f7` (`rightrail/` is trunk `e5d0f36b` plus the
maintainer's axiom-pin fix). Synthetic, not legally verified, nonpayment. It follows
`ELIG_EXTRACT_AND_WIRING_DESIGN.md` section 3.3 (decision D9).

**A shadow run is a test-key run. It decides nothing and binds no one.** The Rust engine decides each claim exactly as
it does today and its answer is the only decision. RightRail's answer is written to a separate record. Nothing reads
that record to change a status, and the run is off unless it is started by hand. Every record and the summary say this
in words.

Read for this design: `rightrail/tests/test_right_rail_gate_ffs.py` (`ExcludedNpiTests`, `RuleSetTests`,
`FileToDecisionTests`, the `claim` helper); `rightrail/tests/_gate_shards.py` (`Cluster`, `feeds_of`, `GRANT`, `KEYS`,
`ENGINE`); `fx.custody` in `rightrail/tests/test_right_rail_gate_formats.py`; `rightrail/app/right_rail_gate_ffs.py`
(`requests_of`, `feeds`, `ident`, `open_host`, `decide_claims`); `rightrail/app/right_rail_gate_decide.py`
(`committed_pin`, `feed`, `FEED_WIDTHS`); `rightrail/conformance/GATE_RULES_V1.md` section 3 (usable feeds);
`rightrail/artifacts/gate-verify/PROVENANCE.txt`; the baseline test logs at `C:\work\rr-baseline-logs`;
`scripts/rightrail_claim_adapter.py`; `bridge/rightrail_offchain.py`. I did not read all of
`right_rail_gate_decide.py`, the producer or the deployment slots; statements about them are marked "as I read it".

## 1. What it runs against

Checked on this machine on 2026-11-28:

| Piece | State | Basis |
|---|---|---|
| The pinned decision engine, `gate_engine.exe` | Built here by `lake build`; its SHA-256 (`8baf1ba3…`) equals the `pin gate_engine` line of trunk's `PROVENANCE.txt` | hashed today |
| Trunk's own decision tests (`test_right_rail_gate_ffs.py`) | All 111 passed on this machine in the baseline run of the RightRail clone with the test-order fixes | `pytest_fixes_py314.junit.xml` |
| The signer, `rr_gate_mldsa87.exe` | In the RightRail clone at `C:\work\rightrail`; matches its pin | checked 2026-11-28 |
| Windows | Required: trunk's host runs the Windows executables | trunk's test |

**Only the pinned engine is used (D2).** It decides by the gate's fixed rules: member death, provider death, exclusion,
enrollment, exact and near duplicates, and the service date. It runs no rule set. The child script stops if the
engine's hash is not the pin. The rows-file engine (`gate_hist3.exe`), which can run pack 1 only with a substituted
pin, is **not approved** and is not used; it would be a separate request.

No engine runs a version 2 rule set, so the G2 pack cannot be exercised.

Everything else the path needs comes from trunk's test fixtures: a key set, a grant, deployment slots, a tenant
authority, and one store per shard (eight shards). The stores are SQLite and index files in a scratch directory outside
both repositories.

### 1.1 Keys, and the one thing not yet approved (D11)

- The key set and the grant are signed with trunk's fixed test-only keys, derived in memory by the signer's
  `kat-keygen` mode. This is the arrangement approved for the G2 admission check.
- **The shard stores also need an epoch key.** Trunk's fixture (`fx.custody`) makes one per store group by calling the
  signer's `keygen` mode: a random seed, sealed with Windows DPAPI for the current user, written to a key file. Here
  the file is inside the scratch directory and is removed with it. Two store groups are used (section 2), so two key
  files are made per run.
- That is a seed file made by `keygen`, which the approved arrangement (D7: "keys in memory only, no seed file, no
  `keygen`") does not cover. **The runner therefore refuses to start unless `SHADOW_ALLOW_SCRATCH_KEYGEN=1` is set, and
  the child stops before importing RightRail or starting the signer when the job does not allow it.** I found no way
  to open trunk's stores without that key file.
- **Approved by the owner on 2026-11-28 (D11), for the scratch directory only**: the key files are never copied,
  logged or printed, and each run's report confirms that they and the scratch directory are gone. The switch is set
  for one run at a time, never left on.

### 1.2 The request route (D3)

Requests are built directly with trunk's line encoder (`encode_line`, `DecideRequest`), as trunk's own test helper
does. **This bypasses RightRail's normal claim intake** (its 837 reader and `requests_of`, with their set-aside
rules), **so a run says nothing about that path.** The only set-aside rules applied are the adapter's. Every record
carries `intake_bypassed: true` and the summary says it in words.

### 1.3 Feeds: a scenario set (D1)

RightRail decides from feeds; localBCE has only per-claim flags. The run uses a scenario set written for it,
`scripts/tests/fixtures/shadow/scenarios.json`: claims together with the feed rows they meet, and the expected outcome
of each side **stated in advance**.

- **Matched scenarios (7):** the claim's flags and the feed rows are written to say the same thing. **Agreement on
  them is by construction**: it shows the claim travelled the path and the mapping is right for that case, and nothing
  more. A test checks that each matched claim's flags are exactly what its feed rows say.
- **Scenarios expected to differ (4):** the two sides are expected to part, and the scenario says where and why.
- **Scenarios not sent (2):** the adapter sets the claim aside, so RightRail is not asked.

A feed is usable to RightRail only with at least one row and an as-of within its maximum age (90 days for the death
feeds, 31 for exclusions, 7 for enrollment), so every feed in the set has a row.

| Scenario | Kind | localBCE (the decision) | RightRail (recorded only) | Why |
|---|---|---|---|---|
| `clean_one_line` | matched | APPROVED | ALLOW | Enrolled member, clean provider, fresh feeds |
| `clean_two_lines` | matched | APPROVED | ALLOW, both lines | Two lines that add up to the total |
| `member_deceased` | matched | DENIED, G9 | HOLD, `MEMBER_DECEASED` | Death dated before the service |
| `provider_excluded` | matched | DENIED, G5 | HOLD, `PROVIDER_EXCLUDED` | Billing provider on the exclusion feed |
| `provider_deceased` | matched | DENIED, G5 | HOLD, `PROVIDER_DECEASED` | Billing provider's death dated before the service |
| `enrollment_lapsed` | matched | DENIED, G3 | HOLD, `MEMBER_NOT_ENROLLED` | The member's only span ended before the service |
| `repeat_first_claim` | matched | APPROVED | ALLOW | The claim the next batch repeats; sealed in the first batch |
| `member_absent_from_feed` | differ | APPROVED | HOLD, `MEMBER_NOT_ENROLLED` | The flags say eligible; the enrollment feed has no span for the member |
| `repeat_of_a_paid_claim` | differ | APPROVED | ANSWERED, `FFS_DUPLICATE_LINE` | A new claim id repeating a paid claim. RightRail remembers what it released; localBCE keeps no history |
| `service_date_in_the_future` | differ | APPROVED | HUMAN_REVIEW, `SERVICE_DATE_FUTURE` | The service date is after the batch date; localBCE has no rule on today's date |
| `stale_death_feed` | differ | APPROVED | HUMAN_REVIEW, `STALE_DMF` | The death feed is 104 days old (limit 90); localBCE has no freshness test |
| `claim_total_mismatch` | not sent | APPROVED | not asked (`total_mismatch`) | 126 dollars against 12500 cents of lines |
| `bad_billing_npi` | not sent | APPROVED | not asked (`bad_npi`) | The NPI fails its check digit |

The RightRail column is a prediction from reading the rules and trunk's tests. A run that gives anything else reports
the scenario as not as expected; that is a finding, not something to adjust the expectation to after the fact.

### 1.4 Eligibility (D6)

The extract writer's file for the synthetic roster is read by trunk's independent verifier inside the run, and the
summary records that it was accepted and how many fact rows it made. **No decision uses it.**

## 2. What one run does

1. Started by hand, on Windows, under the memory guard (`scripts/rr_guarded_interim.ps1`), with `SHADOW_RUN=1` and
   `SHADOW_ALLOW_SCRATCH_KEYGEN=1`. It is not part of the ordinary check set and is skipped in CI with a named reason.
2. The Rust engine decides every scenario claim, in scratch copies. These are the decisions.
3. The adapter's `request_of` turns each claim into a request or a set-aside.
4. The child script (`scripts/rightrail_shadow_child.py`, its own process, no bytecode written) decides the requests
   with the pinned engine in three steps: a first batch against fresh feeds; a second batch in the same stores, holding
   the repeat of a claim the first batch paid; and the stale-feed scenario in separate stores of its own.
5. The adapter's `result_of` maps RightRail's rows; the comparison names the category.
6. One record per claim is appended and the summary is replaced. Nothing else changes.

It writes nothing under `rightrail/` or `parked/`.

## 3. What it records

One record per claim:

| Field group | Content |
|---|---|
| Statement | The words: "Test-key run. It decides nothing and binds no one. The decision is the Rust engine's; RightRail's answer was made under test keys and synthetic feeds and is recorded for comparison only." |
| Markers | `synthetic`, `not_legally_verified`, `nonpayment`, `decides_nothing`, `test_keys`, all true |
| Claim | `claim_id`, `claim_hash`, and the member's keyed form. **No raw member id is written to any record or to the summary**; the writer refuses to write if one appears |
| localBCE | status and reason from the Rust engine, marked as the decision |
| Adapter | the request (payment id, line count, total in cents, service date) or the set-aside cause; its assumptions (the rendering party is the billing NPI, test-only); `intake_bypassed` |
| RightRail | per line and for the claim: outcome, reasons, whether it is final, marked recorded only |
| Comparison | the category; whether agreement is by construction; the expected outcomes and whether the run gave them |
| Context | the engine's file name and SHA-256 and that it is the pinned program; rule set none; the feed set and each feed's digest; batch date; "test keys"; checkpoint digests; the scenario set's digest |

One summary per run: the same statement and markers; counts by category; how many were sent, set aside and
unanswered; which scenarios were not as expected; the notes on matched scenarios and on the bypassed intake; the
extract's acceptance; whether the scratch stores were removed.

Signed checkpoints and tokens are not kept. Under test keys they authorise nothing; only their digests are noted.

## 4. Where the records go

- **Not `adjudication_result.json`.** The Rust engine's results in a run are scratch copies; the repository's file is
  not touched.
- **Not the bridge journal.** It is for adjudications, and a shadow answer is not one.
- **`state/shadow/rightrail_shadow.jsonl`** (appended) and **`state/shadow/summary.json`** (replaced). `state/` holds
  the journal already; the shadow files are local run output and are not committed (D12 asks whether to add them to
  `.gitignore`, as the journal's files are).
- **RightRail's stores** and the epoch key files live in a scratch directory and are removed when the run ends (D5).

## 5. What it cannot show until the maintainer's side exists

| Cannot be shown | Why |
|---|---|
| Any eligibility decision (G2) | No engine runs a version 2 rule set, and the engine does not carry the eligibility read |
| Benefit level, share of cost, provider type, billing codes and units, disability, physician certification | No data, reason number or language node in trunk for any of them |
| A rule set on the pinned engine | The pinned engine runs none |
| RightRail's claim intake | Bypassed (section 1.2) |
| A decision anyone is bound by | Test keys, a test grant and a test key set: no deployment, tenant authority or state signer |
| Real feeds | localBCE has no death, exclusion or enrollment data; the scenario's feeds are written by hand |
| The review path | RightRail sends a line to a person; localBCE has no queue or status for it |
| Release to a payer | The tokens a real allow produces are for a payer; none is involved |
| Linux, speed or scale | The host runs Windows executables, and thirteen claims say nothing about load |

**Agreement in a shadow run is not parity evidence beyond its scenarios**, and on matched scenarios it is by
construction. The parity report on trunk's own 265 lines remains the wider comparison.

## 6. What is built and checked

| Piece | File | In CI |
|---|---|---|
| The scenario set, 13 scenarios with expected outcomes | `scripts/tests/fixtures/shadow/scenarios.json` | checked for shape |
| Matched flags equal what the feed rows say; `differ` scenarios part only where stated | `scripts/tests/test_rightrail_shadow.py` | yes |
| The Rust engine gives each scenario its expected localBCE decision | same | yes |
| The adapter gives each scenario its expected request or set-aside | same | yes |
| The comparison, the records and the summary, from a stand-in for RightRail's answer; the statement in words; no raw member id; an unexpected answer reported | `scripts/rightrail_shadow.py`, same test | yes |
| The run refuses to start without its switches; the child makes no key without the owner's switch; only the pinned engine | same | yes |
| The run itself | `scripts/rightrail_shadow.py`, `scripts/rightrail_shadow_child.py` | no: local only, skipped with the reason named. Run once locally (section 6.1) |

### 6.1 The first run (2026-11-28)

Run once under the memory guard (exit 0, peak 179 MB, about 6 seconds), run id `shadow-20261128T073023+0000`, with the
pinned engine (`gate_engine.exe`, SHA-256 `8baf1ba3…`, equal to the pin). No expectation was changed before or after.

| Scenario | Kind | localBCE | RightRail predicted | RightRail actual | As predicted |
|---|---|---|---|---|---|
| `clean_one_line` | matched | APPROVED | ALLOW | ALLOW | yes |
| `clean_two_lines` | matched | APPROVED | ALLOW | ALLOW, both lines | yes |
| `member_deceased` | matched | DENIED | HOLD `MEMBER_DECEASED` | HOLD `MEMBER_DECEASED` | yes |
| `provider_excluded` | matched | DENIED | HOLD `PROVIDER_EXCLUDED` | HOLD `PROVIDER_EXCLUDED` | yes |
| `provider_deceased` | matched | DENIED | HOLD `PROVIDER_DECEASED` | HOLD `PROVIDER_DECEASED` | yes |
| `enrollment_lapsed` | matched | DENIED | HOLD `MEMBER_NOT_ENROLLED` | HOLD `MEMBER_NOT_ENROLLED` | yes |
| `repeat_first_claim` | matched | APPROVED | ALLOW | ALLOW | yes |
| `member_absent_from_feed` | differ | APPROVED | HOLD `MEMBER_NOT_ENROLLED` | HOLD `MEMBER_NOT_ENROLLED` | yes |
| `repeat_of_a_paid_claim` | differ | APPROVED | ANSWERED `FFS_DUPLICATE_LINE` | ANSWERED `FFS_DUPLICATE_LINE` | yes |
| `service_date_in_the_future` | differ | APPROVED | HUMAN_REVIEW `SERVICE_DATE_FUTURE` | HUMAN_REVIEW `SERVICE_DATE_FUTURE` | yes |
| `stale_death_feed` | differ | APPROVED | HUMAN_REVIEW `STALE_DMF` | HUMAN_REVIEW `STALE_DMF` | yes |
| `claim_total_mismatch` | not sent | APPROVED | not asked (`total_mismatch`) | not asked (`total_mismatch`) | yes |
| `bad_billing_npi` | not sent | APPROVED | not asked (`bad_npi`) | not asked (`bad_npi`) | yes |

13 claims: 11 sent, 2 set aside, none unanswered. Eight batches were sealed under test keys (six in the first step, one
in each of the others). The eligibility extract was accepted by trunk's independent verifier (10 fact rows) and used by
no decision.

After the run: the scratch directory (`C:\Users\amirk\rr-test-scratch\rr-shadow-8szkgpow`, under trunk's own
test scratch root, outside both repositories) no longer exists, and no key file or `rr-shadow-*` directory is left
under that root or the temp directory. The guard's log contains no key material. The records hold no raw member id.
Nothing under `rightrail/`, `parked/` or the RightRail clone changed.

What this run shows: the claim path works end to end against the pinned engine under test keys, and the gate's fixed
rules answered these thirteen cases as predicted. On the seven matched scenarios the agreement is by construction.
It shows nothing about RightRail's claim intake, eligibility, real keys or real feeds (section 5).

## 7. Decisions (owner, 2026-11-28)

| # | Decision | Decided |
|---|---|---|
| D1 | Feeds | A scenario set, including scenarios where the two sides are expected to differ (a stale feed, a member absent from the feed, an exact repeat of a paid claim), each with its expected outcome stated in advance. Agreement on matched scenarios is by construction |
| D2 | Engine | **The pinned engine only.** The rows-file engine with a substituted pin is not approved; it would be a separate request |
| D3 | Request route | Built directly, for the first run. It bypasses RightRail's normal claim intake, so the run says nothing about that path |
| D4 | Where records go | A separate file under `state/shadow/`. No raw member id in any record. Every record and the summary say in words that it is a test-key run that decides nothing and binds no one |
| D5 | Scratch stores | Removed after the run |
| D6 | Eligibility extract | Its acceptance is recorded in the summary; no decision uses it |
| D7 | Signer and test keys | The signer in the RightRail clone; trunk's test-only seeds through `kat-keygen`, in memory |
| D8 | Running trunk's code from `rightrail/` | In its own process, nothing written there |
| D9 | CI | The run is skipped in CI with its named reason; the owner accepts the skip |
| D10 | Question for the maintainer | Restated in full: **"Before a deployment exists, do you want a shadow run on the RightRail side at all, and if so which engine and which claim route should it use? Ours uses the pinned engine, test keys, hand-written feeds and requests built with your line encoder, bypassing your claim intake."** Added to the consolidated request as question 8 |

| D11 | Epoch key files made by `keygen` | **Approved, scratch directory only.** The key files are never copied, logged or printed; the report after each run confirms they and the scratch directory are gone; if a failed run keeps the scratch directory, the report says so and gives the path. `SHADOW_ALLOW_SCRATCH_KEYGEN=1` is set for one run only |

**Open:**

| # | Decision | Recommendation |
|---|---|---|
| D12 | **`state/shadow/` in `.gitignore`**, as the journal's files are | Yes, so run output is never committed by accident. Until then the run's output is untracked and is not committed |
