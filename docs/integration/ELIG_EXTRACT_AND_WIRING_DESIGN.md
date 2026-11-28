# Eligibility extract and live wiring: design

Status: **approved by the owner on 2026-11-28 with changes to D3, D6, D7, D8 and D9 (section 5). Part 1's writer and
its checks are built (section 2.5). Part 2's two pure functions are built (section 3.5); the shadow run and any live
decision are not. Nothing here loads facts into a store, runs RightRail or decides a line.**
Written 2026-11-28 against `codex/rightrail-trunk-e5d0f36b` at `6a493e04` (`rightrail/` is trunk `e5d0f36b` plus the
maintainer's axiom-pin fix). Synthetic, not legally verified, nonpayment.

Two questions:

1. How localBCE's eligibility data becomes a RightRail eligibility extract (`RRELIG01`), and whether the parked
   snapshot builder can be retargeted to produce it.
2. How a localBCE claim becomes a RightRail payment line and how the decision returns (the live wiring, old plan
   step 7).

Read for this design: `rightrail/conformance/ELIG_EXTRACT_V1.md`; `rightrail/app/right_rail_reader_elig.py` and its
independent verifier; `rightrail/tests/elig_vectors/`; `rightrail/app/right_rail_gate_ffs.py` (`member_key`,
`requests_of`, `given`, `decide_claims`, `open_host`); the row type of `rightrail/app/right_rail_x12_837.py`;
`rightrail/conformance/FLAT_V1.md` sections 1 to 2.1; `parked/localbce/scripts/elig_snapshot.py` and its fixture;
`rust-engine/src/main.rs` (`ClaimInput`, `denial_reason()`); `rust-engine/claim_input.json`; `rust-engine/rules.json`
(`date_encoding`); `bridge/rightrail_offchain.py`. I did not read all of `right_rail_gate_decide.py` or the fact store;
statements about them are marked "as I read it".

## 1. The change in shape

localBCE's Rust engine decides from **flags on the claim**: `eligibility_active`, `aid_code`,
`eligibility_period_from/thru`, `provider_enrolled`, `is_duplicate`, `recipient_not_deceased` and the rest. Whoever
builds the claim file has already looked the facts up.

RightRail decides from **data it holds itself**: feeds and facts that arrive in their own files, each with an as-of date
and a receipt, and a payment line that carries only who, what, when and how much. The line carries no flag.

So the wiring is two separate paths, and neither carries a flag across:

- eligibility data goes in as an extract file, on its own schedule (part 1);
- a claim goes in as a payment line, and a decision comes back (part 2).

## 2. Part 1: localBCE eligibility data as an `RRELIG01` extract

### 2.1 What localBCE has

localBCE has no eligibility system. It has two things:

- per-claim flags in `claim_input.json` (above), which are answers, not source records;
- the roster format the parked builder read: `as_of`, `full_roster`, and records
  `[member_id, aid code, benefit level, start, end]`. The only instance is a hand-written synthetic fixture.

The extract is built from roster records, never from claim flags: a flag has no dates, no as-of and no segment.

### 2.2 The target, and what a real roster must supply

`RRELIG01` is a fixed-width file: 120-byte records, a header, detail rows, a trailer with the row count. The reader
(`read_elig`) reads it whole or refuses it whole with one named cause, keys the member id with the tenant's secret, and
makes one eligibility fact row per detail row plus one receipt for the file.

**A real roster must supply every field below marked "required". The writer fills nothing in outside an explicit test
mode, and it never fills in a status: a missing status is refused in every mode and never defaults to eligible (D3).**

| Extract field | Width | Roster field | Required | Test-mode placeholder |
|---|---|---|---|---|
| Header `sender` | 20 | `sender` | required | none |
| Header `fseq` | 12 digits | passed by the caller, not in the roster (D4) | required | none |
| Header `asof` | date | `as_of` | required | none |
| Header `cover` | `F` or `C` | `full_roster` (true gives `F`, false gives `C`) | required | none |
| Header `scope` | 20 | `scope` | required | none |
| `member` | 20 | `member_id` | required | none |
| `segment` | 20 | `segment`, the source's own key for the segment | required | the aid code, a dash, the start date (D2) |
| `status` | 1 | `status`: `E` eligible, `N` not eligible, `P` pending, `R` presumptive | required | **none, ever** |
| `basis` | 1 | `basis`: `G` regular, `R` retroactive, `P` presumptive, `C` continuous | required | `G` |
| `program` | 20 | `program` on the record, or one `program` stated for the whole roster | required | none |
| `aid` | 10 | `aid` | required | none |
| `start` | date | `start` | required | none |
| `end` | date | `end` | optional: none is the open end, `99991231` | none |
| `determined` | date | `determined`, not after the as-of | required | the as-of date |
| `notice` | date | `notice` | required | the as-of date |
| Trailer `count` | 9 digits | the number of records | written by the writer | |

The parked builder's array form `[member_id, aid, benefit_level, start, end]` is not accepted: it carries no status,
so every record of it would be refused.

**Benefit level has no field.** A roster's `benefit_level` is accepted and dropped, and the report counts how many
were dropped. This is the same open gap as in `G2_RULESET_V2_DESIGN.md` section 6.

### 2.3 What the writer does and does not do

The writer states what the source says and nothing else. It does not key member ids, pin anything, sort for a digest,
decide whether the roster is fresh, or settle rows that disagree. In RightRail those are the reader's, the fact
store's and the gate's.

It must never produce a file the reader would refuse. Where a roster cannot be written whole (a missing required
field, an id or aid code that is not printable text of the right width, a bad date, a start after an end, two records
with one member and segment), the writer refuses the whole file with a named cause and writes nothing, as the reader
would. It never drops or repairs a record. Errors carry a cause and a record position only, never a field value.

A roster must be marked `synthetic: true`. Test mode (`--test-placeholders`) is off by default, and a file made in it
says so in its report.

### 2.4 Can the parked snapshot builder be retargeted?

**Not as it is. Decided (D1): it stays parked and a new small writer was written.**
`parked/localbce/scripts/elig_snapshot.py` (664 lines) built a "kind 7" snapshot for the old trunk's text runner.
Against the imported trunk:

| Part of the parked builder | Reusable for an `RRELIG01` writer? |
|---|---|
| Normalising: date parsing, aid-code and id checks | Yes, as ideas; the new writer has its own small versions with the extract's widths |
| Input: the array roster format | No: it has no status (section 2.2) |
| `join_windows` (aid windows joined with benefit-level windows) | No: there is no benefit level to join |
| Sorting, de-duplicating, conflict and overlap handling, "no snapshot" when stale | No: the fact store's belief and the gate's freshness guard do this now. A repeated member and segment is a refusal |
| Keying with `member_key` | No: the extract carries the raw id and the reader keys it |
| `pin_rows`, `pin_input`, `encode_row`, `fragment`, the `fits` checks | No: there is no snapshot pin and no text-runner fragment |
| Imports of `gate_rules_data` and `gate_rules_v2_ref` | Broken: `gate_rules_v2_ref.py` is not in the imported trunk, so the parked file no longer imports |
| Error discipline (cause and position only), atomic writes, refusing output paths under `rightrail/`, exit codes | Yes, as patterns; the new writer follows them |

### 2.5 What is built and checked

Built 2026-11-28: `scripts/build_elig_extract.py`, `scripts/tests/test_build_elig_extract.py` and the synthetic roster
`scripts/tests/fixtures/elig_extract/roster_v1.json`, in which every record supplies every required field.

| Check | Needs | In CI |
|---|---|---|
| The writer reproduces trunk's own golden files (`tests/elig_vectors/full.elig`, `change.elig`, `empty.elig`) byte for byte from equivalent roster input | Python only | yes |
| For each of the 17 files in trunk's `hostile.json` that a roster can express, the writer refuses with the cause the reader names. The other 23 fault the framing, filler, trailer, cover code or registry entry, which the writer makes itself; the test lists them by name | Python only | yes |
| A record lacking any required field is refused; placeholders appear only in test mode; a missing status is refused in both modes | Python only | yes |
| The localBCE roster fixture becomes a file with pinned bytes; a second run gives the same bytes; errors carry no field value | Python only | yes |
| Trunk's independent extract verifier accepts the writer's file: 10 fact rows, the receipt's counts and file digest, and no raw member id in a fact row | Trunk's `right_rail_reader_elig_independent`, run in its own process with no bytecode written. Skipped with the reason named if it cannot be imported | yes: it ran and passed on the Linux and the Windows CI jobs (run of `be54adea`, 2026-11-28) |
| The facts lead to the eligibility read the G2 pack's cases assume | Trunk's fact store and belief, in Lean | no: not attempted here |
| A gate decides a line from these facts | **Blocked**: the engine does not carry the eligibility read | no |

The first five rows are built and pass. The fifth runs trunk's independent verifier, not its main reader (which, as I
read it, imports the fee-for-service module and so needs Windows).

## 3. Part 2: a claim as a payment line, and the decision back

**`claim_input.json` does not change (D6).** The Rust engine reads it and it keeps working as it is. Everything below
is done in a converter that reads the same file.

### 3.1 The line

A RightRail line has ten fields. Trunk already has the path for fee-for-service claims: it reads an 837 file
(`right_rail_x12_837`), and `requests_of` makes one request per claim with one line per service line.

| Line field | From `claim_input.json` | Converter rule |
|---|---|---|
| flow | constant `FFS_CLAIM` | |
| member | `member_id` | Keyed by `member_key(secret, member_id)`: the same key the extract's reader gives the member, so the eligibility facts and the line meet |
| payee | `provider_npi` (billing) | Ten digits with a valid check digit, else the claim is set aside |
| rendering | no localBCE field | **Assumption, for tests only (D7): the billing NPI.** To resolve before anything real: RightRail's exclusion and provider-death rules check the rendering party as well as the payee, so a wrong rendering party hides an excluded provider |
| date | `date_of_service_from` | The stated rule below |
| procedure | `service_lines[].procedure_code` | Trunk encodes the code and its sorted modifiers; localBCE has no modifiers |
| units | `service_lines[].units` | A whole number above zero, else the claim is set aside |
| cents | `service_lines[].charge_cents` | The billed charge per line |
| id, payment | derived from billing NPI and `claim_id` | Trunk's `canonical_id`, so a resubmitted claim is the same payment and is decided once |

**The service date: a stated rule exists.** `rust-engine/rules.json` says (`date_encoding`): "All dates encoded as
integer days since 1970-01-01 (proleptic Gregorian)", and each date field's note repeats it. So the converter's rule
is: the calendar day that many days after 1970-01-01, written as `yyyymmdd`. The fixture's `20000` is 2024-10-04. A
value that is not a whole number, is negative, or lands after year 9999 is not converted: the claim is set aside
(`service_date`). The converter never guesses that a large number such as `20270310` is already a calendar date; as a
day count it is far past year 9999, so it is set aside.

One inconsistency to know about, not to fix here: the parity harness feeds `yyyymmdd` numbers to the Rust engine. That
is harmless there because the engine only compares dates with each other, but it is not the stated encoding.

**The claim total.** A claim whose `claim_amount` does not equal the sum of its `service_lines[].charge_cents` is
**set aside (`total_mismatch`), not corrected**, as trunk does. The current fixture is such a claim (`claim_amount`
1000 against one line of 100000), so the converter sets it aside; converter tests need fixtures of their own that add
up. Neither file's meaning is changed for the Rust engine.

Not carried, by design: every decision flag (`eligibility_active`, `aid_code`, `benefit_level_exists`, the eligibility
period, `soc_*`, `provider_enrolled`, `provider_type_valid`, `billing_code_valid`, `units_valid`, `is_duplicate`,
`disability_determination_valid`, `recipient_not_deceased`, `physician_certification_valid`), and the oracle and fee
schedule blocks. RightRail takes none of them from a claim.

Claim route (D5): build trunk's `ClaimLine` rows from the claim and call `requests_of` for the first tests, because it
needs no X12. That depends on a row type internal to trunk, so writing an 837 for trunk's own reader is revisited
before anything real: a deployment receives 837s.

### 3.2 The decision back

`decide_claims` returns one row per line: payment id, line position, outcome, reasons. It also returns the signed
checkpoint and tokens of each sealed batch.

**The rule for `status` (D8): only a RightRail allow on every line of the claim gives `APPROVED`. Nothing else ever
does.**

| RightRail outcome | Meaning | `status` | New fields |
|---|---|---|---|
| `ALLOW` on every line | pass | `APPROVED`, `reason: null` | outcome `ALLOW` |
| `HOLD` on any line | stopped for now | `DENIED`, `reason`: the mapped localBCE name where one exists, else the RightRail reason name | outcome `HOLD`, the RightRail reason names, `final: false` |
| `HUMAN_REVIEW` | a person decides | `DENIED` (never `APPROVED`) | outcome `HUMAN_REVIEW`, the reasons, `final: false` |
| `ANSWERED` | exact repeat of a paid line; answered, never paid again | `DENIED` (never `APPROVED`) | outcome `ANSWERED`, the reasons |
| set aside | the claim was never sent | `DENIED` (never `APPROVED`) | outcome `SET_ASIDE`, the cause, `final: false` |
| no answer, or an error | nothing was decided | no result file is written as approved; the converter reports the failure | |

**A RightRail hold is not a final denial.** A held line can be released later by a grant, a bypass or newer data, and
a reviewed line by a person. `status: "DENIED"` is the nearest of the two values the file has, kept so existing
readers keep working; it must not be read as a final adverse determination. The real outcome is in the new fields, and
`final` says whether it can still change. A reader that needs the truth reads the new fields.

New fields, added beside the existing ones so the file stays backward compatible: `rightrail_outcome`,
`rightrail_reasons`, `rightrail_final`, `rightrail_payment_id`, and for a set-aside `rightrail_set_aside_cause`.
`claim_id` and `claim_hash` stay as they are. `tx_submitted` stays `false` and `tx_hash` stays `null`: nothing here
touches a chain.

The journal (`bridge/rightrail_offchain.py`) records the result as it does now. It is transitional: inside RightRail
the one writer is `FinancialOwner`, and the signed checkpoint and tokens are the record there.

### 3.3 The shadow run (D9)

A shadow run **records RightRail's answer beside localBCE's and decides nothing.** The Rust engine decides the claim
exactly as today and writes `adjudication_result.json` unchanged. The RightRail side is written to a separate record
next to it, with the two compared. Nothing reads the RightRail answer to change a status, and it is off by default.

### 3.4 What a live decision needs, and what it would decide today

Running trunk's decision path needs, as I read `open_host` and `decide_claims`: every deployment slot authored, a
tenant authority, shards with key certificates, a grant, a key set, the pinned engine executable, and an initialised
store per shard. Trunk's own test (`tests/test_right_rail_gate_ffs.py`) sets these up with test keys.

Even with all of that, a decision today would use only the gate's fixed rules: death, exclusion, enrollment and
duplicates. `FLAT_V1.md` says this engine runs no rule set, and a frame that presents rule-set records is held as
`RULESET_NOT_RUN`. So **no G2 decision can come back through the live path yet**, however the wiring is built.

Two rules bound this work. `AGENTS.md`: nothing is silently wired into the active workflow, and inside `rightrail/` one
writer decides. So the wiring is an adapter outside `rightrail/` that is off by default, and anything that must change
inside `rightrail/` goes to the maintainer.

### 3.5 What is built, and what can be built later

Built 2026-11-28: `scripts/rightrail_claim_adapter.py` (`request_of`, `result_of`),
`scripts/tests/test_rightrail_claim_adapter.py` and the case tables `scripts/tests/fixtures/claim_adapter/claims.json`
(43 cases) and `decisions.json` (26 cases). They are pure functions: nothing calls them, and they run nothing of
RightRail's. The first, third and fourth rows below are built and pass. The ids, the member key and the NPI check are
compared with RightRail's own definitions, read from their source text. Where a hold's reason is one that two localBCE
denials share (`MEMBER_NOT_ENROLLED`: G1 and G3), the result gives the RightRail name, not a guess. A decision that is
missing, incomplete or not understood gives no result at all.

| Piece | Needs | In CI |
|---|---|---|
| Claim to line fields: a pure function with a case table (valid claim, bad NPI, zero units, total mismatch set aside, the date rule and its refusals) | Python only | yes |
| The same claim through trunk's `requests_of` gives the same line fields | Trunk's fee-for-service module, Windows | no: local only |
| Decision rows to `adjudication_result.json`: a pure function with a case table over every outcome, including that nothing but an allow gives `APPROVED` | Python only | yes |
| The Rust engine still reads every existing `claim_input.json` unchanged | The Rust engine | yes |
| A shadow run with test keys: RightRail's answer recorded beside localBCE's, deciding nothing | Trunk's path with test keys, under the memory guard | no: local only, mechanics only |
| A real decision by a deployed gate | **Blocked**: deployment, real keys, a store, the maintainer's side | no |
| A G2 decision through the gate | **Blocked**: the engine runs no rule set and does not carry the eligibility read | no |

## 4. Blocked on the RightRail side

| Item | Effect |
|---|---|
| The engine does not carry the eligibility read and runs no rule set | Eligibility facts can be loaded but no line is decided from them |
| No benefit level in the eligibility fact | The roster's benefit level is dropped |
| Deployment slots, tenant authority, key certificates, grants | A live decision cannot be made by localBCE alone; a test-key run checks mechanics only |
| Review outcomes | localBCE has no queue or status for a line a person must decide; RightRail's own review flow is the maintainer's |

## 5. Decisions (owner, 2026-11-28)

| # | Decision | Decided |
|---|---|---|
| D1 | Parked builder: revive and retarget, or a new small writer | New writer. The parked file stays parked as the record |
| D2 | Segment key when a roster gives none | Test mode only: the aid code, a dash, the start date. A real roster supplies the source's own segment key |
| D3 | Fields with no localBCE source | **Changed by the owner.** Placeholders only in an explicit test mode; outside it the writer refuses a record that lacks a required field. A missing status never defaults to eligible, in any mode. Section 2.2 lists what a real roster must supply |
| D4 | File counter (`fseq`) | The caller passes it. The writer keeps no state |
| D5 | Claim route | Build trunk's rows for the first tests; revisit writing an 837 before anything real |
| D6 | Service date format and the claim total | **Changed by the owner.** `claim_input.json` does not change. The converter applies the stated date rule (days since 1970-01-01, from `rules.json`), and sets aside a claim whose total does not equal its line sum; it corrects nothing |
| D7 | Rendering provider | The billing NPI, **for tests only**. An assumption to resolve before anything real, because the exclusion rule checks the rendering party |
| D8 | Outcomes with no localBCE status | **Changed by the owner.** Add the fields. Only a RightRail allow maps to `APPROVED`; review, answered-repeat and set-aside never do. A hold is not a final denial, and the real outcome is carried in the new fields |
| D9 | Order | Part 1, then the two pure functions of part 2, then a shadow run that records RightRail's answer beside localBCE's and decides nothing |
| D10 | Questions for the maintainer | Send the three (extract writer, claim route, review outcome) with the four already drafted |
