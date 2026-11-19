# Gate rules v2

What the payment gate's rules decide, and the vector-file grammar the rules
runner `gate_rules` reads and prints. Rules: `lean/BlindLedger/Gate/Rules/Spec.lean`
(`Spec`). Runner: `lean/BlindLedger/Gate/Rules/Run.lean` (`Run`), built as
`gate_rules` from `RulesMain` (which runs `Run.runText`). Where this page and Lean disagree, Lean wins.
Vectors: `tests/gate_rules/{rules_v2,demo_zz_v2}.vectors` (published) and
`tests/gate_rules/rules_v2_negative.vectors` (must-reject and edge cases; its output is frozen in
`rules_v2_negative.expected`). Independent checker, written from this page alone: `conformance/gate_rules_v2_ref.py`,
run by `tests/test_gate_rules_v2_spec.py`.

Version 2 is version 1 (retired at trunk step 3; `GATE_RULES_V1.md`, git keeps it) plus G2: a seventh snapshot kind,
`elig` (eligibility), five reasons read from it, and the read set `READ-SET/v5` (section 10) in place of `READ-SET/v2`.
Every version 1 answer changes: a file with no `elig` snapshot gets `STALE_ELIGIBILITY` on every line. G2 is
localBCE's aid code and benefit level gate: synthetic, not legally verified. The 7-day maximum age of `elig` is a
placeholder (localBCE's own time to live is 24 hours). This version is extended in place at step 4 if nothing is
published between.

Synthetic, non-PHI, nonpayment: `proofSuiteId=null`, `production_usable=false`,
`activation=false`. No rule yields BLOCK.

Out of scope here: `load`, `commit SHOW` (it prints section 10's bytes; `tests/test_gate_rules_vectors.py`
recomputes them), the request and grant directives
and the shard directives (multi-shard runtime; `shards_v1.vectors`), `POSTING_CAP`
(never fired by `Spec`; only the capped disk engine adds it; see the next paragraph), and the token wire
(`BlindLedger.Gate.Spec`).

`POSTING_CAP` counts per core. A line's core is its member and date and procedure for a fee-for-service line, or its
member and month for a capitation line, and every exact or near key of the line lies inside its core. A line is held
with reason `POSTING_CAP` when its core holds more than 1,024 rows (`capN`) in either set, or when its id key has more
than 1,024 postings. The core count takes the place of the exact-key and near-key counts only; an id key lies in no core
and keeps its own count. A core always holds at least as many rows as any key inside it, so this can only add a hold and never lift one. It differs from
the per-key count only when one core holds over 1,024 rows. Sign-off 2026-11-03. `gate_engine`
and the `Flat` store keep the per-key count; the combined engine (`Gate/Engine3`, verifier and mirror) counts per core. The
combined engine's differential check reports every line whose core is over the cap. The `Flat` store also holds a line
with `POSTING_CAP` when one of its own reference-feed reads is cut short (`Flat.feedCapped`: more than 1,024 rows for
the line's member in `dmf`, `span` or `elig`, or for its payee or rendering party in `pdeath` or `excl`).

## 1. Conventions

- **Numeral**: one or more ASCII digits, no sign, no `_`; leading zeros allowed;
  unbounded value (`Run.nat?`).
- **Date**: a numeral read as CCYYMMDD (`Spec.validDate`). Valid when year
  1..9999, month 1..12, day 1..days-in-month (proleptic Gregorian; leap year if
  divisible by 4, except by 100 unless by 400). Valid dates compare as numbers
  in calendar order. `dayNum` (`Spec.dayNum`) is a day count on valid dates;
  `a` is at most `n` days before `b` when `dayNum b <= dayNum a + n`.
- **Id**: member, payee, rendering party, procedure, line id, payment id, aid code: a numeral.
- **Aid code**: the number of an aid code's text (`Spec.aidId`): start at 1, then for each UTF-8 byte `b` of the text,
  in order, multiply by 256 and add `b`. So `"13"` is 78131 (1, then 1*256+49 = 305, then 305*256+51 = 78131).
- Names are the constructor names in the tables below. "Byte order" is ASCII
  order of the names.

## 2. Vector file

UTF-8 text, split at `\n`. Lines are numbered from 1 (blank and comment lines
count). On each line every `\r` is removed, then the text is split at the space
character (tabs do not split) and empty pieces are dropped (`Run.fields`). No
pieces, or a first piece starting with `#`: skipped. Otherwise the pieces are
the **fields** and the first matching directive below applies. Matching is on
the first field and the exact field count. A line no directive accepts is
malformed (section 9). State starts empty: `today` 0, no snapshots, no rows,
checkpoints at genesis (date 0, no lines), totals 0.

| Directive | Effect |
|---|---|
| `case NAME` | Clears the batch, the lines earlier commits added to each set, both checkpoints (back to genesis), the anchor, the redo list, the expected pay outcomes and the done list. Keeps `today`, snapshots, rows and totals. |
| `today D` | Sets today; `D` a numeral below 2^64 (not required to be a valid date). |
| `snap KIND ASOF COUNT PIN` | Declares (replaces) snapshot `KIND`; `ASOF`, `COUNT` numerals, `PIN` any text. Drops the rows of `KIND` read so far. `snap released` also clears the lines earlier commits added to the released set; `snap unresolved` likewise for the unresolved set. Any `KIND` is accepted; only the seven kinds below are used. |
| `drop KIND` | Removes every declaration of `KIND` (its rows stay but are unused until the next `snap KIND`, which drops them). |
| `KIND f...` | `KIND` one of `dmf`, `pdeath`, `excl`, `span`, `elig`, `released`, `unresolved`; any field count: appends a row (the fields, unparsed) to `KIND`. |
| `line ID[:PAY] FLOW MEMBER PAYEE REND DATE PROC UNITS CENTS [OUTCOME REASONS [with=IDS]]` | Adds a line to the batch. 9 fields to parse, then 0, 2 or 3 expectation fields (else malformed). With expectations, the line's expected answer is the text of the line (`lineText`, section 8), a space, then those fields joined by single spaces; nothing is checked about their content. `PAY` defaults to `ID`. `FLOW` is `FFS_CYCLE`, `FFS_CLAIM` or `CAP_820` (case-sensitive). |
| `redo PAY` | Adds the payment to the redo list; ignored when `PAY` is 256^261 or more. |
| `pay PAY OUTCOME` | Expects the payment outcome (section 7) of `PAY` at the next commit. `OUTCOME` any text. |
| `anchor HEX` | `HEX` exactly 128 characters of `0-9a-f` (lower case). Sets the anchor. |
| `commit` / `commit UNANCHORED` | Decides the batch (section 8). |
| `report` | Prints the totals (section 8). |
| `end N` | Sets the number of checked lines the run expects; `N` a numeral. |

Row parsing, when a snapshot is built (section 3): `dmf`, `pdeath`: 2 numerals
(id, date of death). `excl`: 3 (id, start, stop). `span`: 4 (member, plan,
start, stop). `elig`: 5 (member, aid code, benefit level, start, stop). `released`, `unresolved`: the 9 line fields
without expectations (`ID[:PAY] FLOW ...`). A row with another count or a bad numeral makes the snapshot missing.

## 3. Snapshots, pins, usability

A **snapshot** is `(asOf, count, rows)`. The seven kinds: 1 `dmf`, 2 `pdeath`
(provider deaths), 3 `excl` (exclusions), 4 `span` (enrollment), 5 `released`,
6 `unresolved`, 7 `elig` (eligibility). At a commit a kind is **present** only if: it is declared and
not dropped (latest declaration), all its rows parse, every row value fits its
width, and the declared PIN equals the lower-case hex SHA3-512 of the **pin
input** (`Spec.pinInput`, `Fast.pinBytes`). Otherwise it is **missing**. Its
rows are those after its latest `snap`, in file order. The declared COUNT is
not compared with the row count when pinning, only when checking usability.

Pin input: domain text, byte 0, kind as u32, `ASOF` as u32, `COUNT` as u32,
then the rows' encodings sorted in byte order and joined. Domain is
`RR/GATE/SNAPSHOT/v1` for kinds 1-4 and 7, `RR/GATE/RELEASED/v1` for 5,
`RR/GATE/UNRESOLVED/v1` for 6. Numbers are big-endian in the width given; a
value of 256^width or more does not fit.

| Kind | Row encoding (widths) |
|---|---|
| 1, 2 | id 129, date 4 |
| 3 | id 129, start 4, stop 4 |
| 4 | member 129, plan 129, start 4, stop 4 |
| 5, 6 | id 129, pay 261, flow tag 1, member 129, payee 129, rendering 129, date 4, proc 129, units 4, cents 8 |
| 7 | member 129, aid code 129, benefit level 1, start 4, stop 4 |

Flow tags: `FFS_CYCLE` 1, `FFS_CLAIM` 2, `CAP_820` 3.

**Context.** `today` is the last `today` (0 if none). The reference snapshots
`dmf`, `pdeath`, `excl`, `span`, `elig` are the present ones, else missing. The
**released read** is the present `released` with the lines earlier commits
added to released appended (count raised by their number); the **unresolved
read** likewise (`Run.grow`). Missing stays missing. The priors are the two
checkpoints (`releasedPrior`, `unresolvedPrior`). The redo list is the `redo` payments.

**Usable** (`Spec.usable`) with a maximum age and a row check: present; today
valid; asOf valid and not after today; `today` at most maxAge days after asOf;
row count equals COUNT; COUNT above 0; every row passes the check.

| Snapshot | Max age (days) | Row check |
|---|---|---|
| `dmf`, `pdeath` | 90 | date valid and not after asOf |
| `excl` | 31 | start and stop valid, start not after stop |
| `span` | 7 | start and stop valid, start not after stop |
| `elig` | 7 | start and stop valid, start not after stop, benefit level 0 or 1 (`okElig`) |

A benefit level above 1 makes the whole `elig` snapshot unusable (review, never HOLD).

**Chained** (`Spec.chained`) for a set read against its prior: present; row
count equals COUNT (0 allowed); asOf valid and not after today; prior asOf not
after asOf; every prior row is among the rows (whole-line equality).

**View** (`Spec.view`): the set read if chained, else the prior. The released
and unresolved sets below are the views (`releasedSet`, `unresolvedSet`).
**Loose** rows (`Spec.loose`) of a set read: none if chained; else the read's
rows (none if missing) that are not rows of the prior.

## 4. Keys

A line has fields id, pay, flow, member, payee, rendering, date, proc, units,
cents. Cap means flow `CAP_820` (payee is then the plan, date the first day of
the service period). Keys are number lists (`Spec.exactKey`, `nearKey`, `idKey`):

| Key | Value |
|---|---|
| exact | `[3` if cap else `1, member, payee, date, proc, units, cents]` |
| near | cap: `[0, member, date div 100]`; else `[2, member, rendering, date, proc]` |
| id | `[4, id]` |

A set's lines claim keys (`Spec.keys`, `claim`): all three, except a cap line
that is **not enrolled** (section 5, R5) and not **own** (section 7) claims
only exact and id. The **pending** keys are the claims of the unresolved set,
in order. The **seen** list is built in section 7.

## 5. Rules

For each line, in the order of section 7, every reason whose condition holds is
listed (`Spec.fires`, `decideLine`); reasons print in byte order. Let a
snapshot be **certain** for the line when it is usable and the line's date is
valid, and **unverified** when it is present, not usable, and the date is valid.

Facts: *member dead*: a `dmf` row has id = member and date < line date.
*provider dead*: a `pdeath` row has id = payee or rendering and date < line date.
*excluded*: an `excl` row has id = payee or rendering and start <= line date <=
stop. *enrolled*: a `span` row has member = line member and start <= date <=
stop and, for cap, plan = payee. *overlap* (cap lines; the date is valid when
it is used): let F and L be the first and last day of the date's month. Some
two `span` rows of the member have different plans and max(F, both starts) <=
min(L, both stops).

G2 facts. The **allowed aid codes** (`Spec.allowedAid`) are the aid codes of `"13"`, `"23"`, `"53"`, `"103"` and
`"104"`: 78131, 78387, 79155, 20000819, 20000820 (localBCE's numeric set; `"105"` and `"D3"` are not in it). An
`elig` row **covers** the line when its member = line member and start <= line date <= stop (`eligCovers`).
*aid eligible* (`aidEligible`): some covering row has an allowed aid code. *level eligible* (`levelEligible`): some
single covering row has an allowed aid code and benefit level 1. The pairing is deliberate: a covering row with an
allowed aid code and level 0 plus a covering row with level 1 and another aid code is not level eligible.

Facts read the rows of a present snapshot even when it is unusable; a missing snapshot has no rows, so no fact holds.

| Code | Class | Fires when |
|---|---|---|
| `ALREADY_DECIDED` | certain | seen holds the id key, or pending holds it. |
| `BENEFIT_LEVEL_MISSING` (G2) | certain | `elig` certain, aid eligible and not level eligible. |
| `BENEFIT_LEVEL_MISSING_UNVERIFIED` | review | `elig` unverified, aid eligible and not level eligible. |
| `CAP_MEMBER_MONTH_DUPLICATE` | certain | cap, and (seen holds the exact key, or seen holds the near key, or `span` is certain and overlap). |
| `COLLIDES_WITH_UNRESOLVED_NEAR` | review | not cap, pending holds the near key, pending lacks the exact key. |
| `DUPLICATE_OF_UNRESOLVED` | certain | pending holds the exact key, or cap and pending holds the near key. |
| `FFS_DUPLICATE_LINE` | certain | not cap, seen holds the exact key. |
| `FFS_DUPLICATE_UNVERIFIED` | review | not cap, and the exact key is the exact key of a loose row of the released read or the unresolved read. |
| `FFS_NEAR_DUPLICATE` | review | not cap, seen holds the near key, seen lacks the exact key. |
| `MEMBER_DECEASED` (R1) | certain | `dmf` certain and member dead. |
| `MEMBER_DECEASED_UNVERIFIED` | review | `dmf` unverified and member dead. |
| `MEMBER_NOT_ENROLLED` (R5) | certain | `span` certain and not enrolled. |
| `MEMBER_NOT_ENROLLED_UNVERIFIED` | review | `span` unverified and not enrolled. |
| `PROGRAM_NOT_ELIGIBLE` (G2) | certain | `elig` certain and not aid eligible. |
| `PROGRAM_NOT_ELIGIBLE_UNVERIFIED` | review | `elig` unverified and not aid eligible. |
| `PROVIDER_DECEASED` (R3) | certain | `pdeath` certain and provider dead. |
| `PROVIDER_DECEASED_UNVERIFIED` | review | `pdeath` unverified and provider dead. |
| `PROVIDER_EXCLUDED` (R3) | certain | `excl` certain and excluded. |
| `PROVIDER_EXCLUDED_UNVERIFIED` | review | `excl` unverified and excluded. |
| `SERVICE_DATE_FUTURE` | review | today < line date (plain number compare; no validity test). |
| `SERVICE_DATE_INVALID` | review | line date is not valid. |
| `STALE_DMF`, `STALE_ELIGIBILITY`, `STALE_EXCLUSION`, `STALE_PROVIDER_DEATH`, `STALE_ENROLLMENT` | review | `dmf`, `elig`, `excl`, `pdeath`, `span` respectively not usable. |
| `STALE_RELEASED`, `STALE_UNRESOLVED` | review | the released read, the unresolved read, not chained. |

R2 is `CAP_MEMBER_MONTH_DUPLICATE`; R4 is `FFS_DUPLICATE_LINE` and
`FFS_NEAR_DUPLICATE`. The `STALE_*` reasons fire on every line of the batch,
the same for all.

G2 notes. The two certain G2 codes exclude each other; G2 suppresses no other rule. An invalid service date silences G2
(`SERVICE_DATE_INVALID` carries the line); a future one does not. A member with no enrollment span and no eligible row
gets both `MEMBER_NOT_ENROLLED` and `PROGRAM_NOT_ELIGIBLE`. A missing `elig` snapshot (none declared, dropped, a row
that does not parse or fit, or a wrong pin) gives `STALE_ELIGIBILITY` alone, never an `_UNVERIFIED` G2 code. For
`CAP_820` the date read is the period start.

## 6. Outcome

No reasons: `ALLOW`. Any reason of class certain: `HOLD`. Otherwise
`HUMAN_REVIEW` (`Spec.outcomeOf`, `review`). Class review is the set marked review above.

## 7. Batch

Input: the batch lines (after section 8's `keep`), the context, no foreign ids.
Result: one decision per line, and the new checkpoints (`Spec.decideBatchIn`).

1. **Own**: a line is own when its pay is in the redo list and the released set
   holds the line (whole-line equality) (`Spec.own`).
2. **Order** (`Spec.order`, `canonical`): own lines first, then the others; each
   group sorted ascending by the number list `[flow tag, member, payee,
   rendering, date, proc, units, cents, id, pay]`, compared element by element
   (flow tag 1 `FFS_CYCLE`, 2 `FFS_CLAIM`, 3 `CAP_820`). Arrival order does not matter.
3. **Seen start** (`Spec.seen0`): all three keys of every line of the released
   set, except lines that are own and also in the batch.
4. Decide the lines in order. Each line sees the `seen` list so far; after it,
   its claim (section 4) is added to `seen`, whatever its outcome.
5. **Counterparts** (`counterparts`, printed as `with=`): the ids, in this
   order and without removing repeats, of (a) each line of the released set
   followed by the released read's loose rows, in that order, that shares any
   key (all three keys of that line) with the decided line's three keys; then (b) the
   same over the unresolved set followed by the unresolved read's loose rows,
   comparing the decided line's keys with the claim of each row.
   Earlier lines of the same batch are not listed.
6. **Payment outcome** of `P` (`Spec.payOutcome`): over the decisions whose
   line pay is `P`: `HOLD` if any is `HOLD`; else `ALLOW` if there is at least one
   and each is `ALLOW` and, when `P` is in the redo list, own; else
   `HUMAN_REVIEW` (this includes no line at all).
7. **New released lines** (`releasedLines`): lines of `ALLOW` decisions whose pay
   is not in the redo list and whose payment outcome is `ALLOW`, in decision order.
   **New unresolved lines** (`unresolvedLines`): lines of decisions that are not
   `ALLOW`, lack `ALREADY_DECIDED`, and are not own, in decision order.
8. **Next checkpoints** (`advance`): for each set, the view's asOf, the view's
   rows followed by the new lines, count = rows.

## 8. Commit and output

Items unfit for the pin (a line with any field at or above its width limit in
section 3's table: id, member, payee, rendering, proc at 256^129; pay at
256^261; date and units at 2^32; cents at 2^64) are set aside (`Run.keep`,
`unfit`): every line of a payment having an unfit line is **quarantined** and
not given to the rules; the rest is the kept batch.

`commit` runs these steps (`Run.commit`):

1. Build the context (section 3). **Anchor check**: if an anchor is set and the
   priors' **state digest** differs from it, the commit is *refused*: the
   batch, redo list, expected pays and anchor are cleared; if the commit was
   `UNANCHORED` it counts as checked 1, else failed 1 and the output line
   `RULES_UNANCHORED commit` is printed. Nothing else changes. The state digest is the lower-case
   hex SHA3-512 of `RR/GATE/STATE/v1`, byte 0, the SHA3-512 (64 bytes) of the
   released prior's pin input (domain `RELEASED`, kind 5, its asOf and count),
   then likewise for the unresolved prior (kind 6); the anchor is that hex
   (`Gate.stateDigest`, `Gate.setsDigest`). The check applies only when the anchor is set.
2. Decide the kept batch (section 7). The **answers**: each decision rendered
   (below) in decision order, plus the quarantined lines: each is
   `lineText(line) HOLD UNENCODABLE_FIELD` if it is itself unfit, else
   `lineText(line) HOLD UNENCODABLE_PAYMENT`.
3. **Check.** Let *exp* be the expected answers of the batch lines. If *exp* is
   empty: ok with 0 lines checked. Else ok when *exp* has as many entries as the
   batch (all lines, including quarantined) and sorted *exp* equals sorted answers
   (string order; equivalently the same multiset); else not ok and each sorted answer not in
   *exp* is printed as `RULES_GOT answer`. Each `pay P OUTCOME` expectation fails
   when the payment outcome of `P` differs from `OUTCOME`, where a payment with
   an unfit line is `HOLD`; each fails as `RULES_PAY P expected=OUTCOME` (`P` as the number).
   A `commit UNANCHORED` that was not refused is not ok and prints `RULES_ANCHORED commit`.
4. If not ok the commit prints, in this order: `RULES_VECTOR_MISMATCH commit`,
   the `RULES_GOT` lines, the `RULES_PAY` lines, `RULES_ANCHORED commit`. The
   runner has first printed `RULES_VECTOR_FAIL line=N` for the commit's line `N`.
5. **State**: the new released lines (7) are added to the lines kept for
   the released set and the new unresolved lines to the unresolved set;
   the priors become the new checkpoints (8); anchor, batch,
   redo and expected pays are cleared. The done list gains the decisions and,
   for each quarantined line, a decision `HOLD` with no reasons and no
   counterparts. Checked grows by (lines of the batch + number of `pay`
   expectations) when ok and the batch had expectations, by the number of `pay`
   expectations when ok and it had none, else 0. Failed grows by 1 when not ok.

The prior the check uses is the checkpoint as the earlier commit left it; at a
case start it is genesis.

Output of a line decision (`Run.render`, `lineText`): `ID:PAY FLOW MEMBER PAYEE REND DATE PROC UNITS CENTS`
(numbers in decimal, no leading zeros), a space, the outcome, a space, the reasons
joined by `,` in byte order or `-`, and when counterparts exist a space and `with=` plus the ids joined by `,`.

`report` prints, from the done list (`Run.step`), in order, `REPORT NAME lines=N cents=C ($D.CC)`
for NAME in `all`, then `ALLOW`, `HOLD`, `HUMAN_REVIEW`, then each of the 29 reasons
(including `POSTING_CAP`) in byte order; N the decisions with that outcome or
reason, C the sum of their cents, `D` = C div 100, `CC` = C mod 100 in two digits.

## 9. Output and malformed input

`gate_rules FILE` prints `RULES_SOURCE HEX` first (a build hash; not part of
this spec), then the lines produced as the file is read, then the final line
`RULES_VECTORS=PASS|FAIL checked=C expected=E failed=F`. PASS when F is 0 and
`end` was given and E = C; E is 0 if no `end`. The exit code is 0 on PASS, else 1.

A line no directive accepts (bad numeral, wrong field count, unknown first
field, bad `FLOW`, `ID:PAY` not exactly one or two parts, hex anchor of wrong
length or case, a `today` of 2^64 or more, unknown directive) prints `RULES_VECTOR_MALFORMED line=N`, adds 1 to F,
and changes nothing else.
The out-of-scope directives `load` and `commit SHOW` (the exe accepts them) count as unknown here: a v2 checker
that refuses them as malformed conforms, and `gate_rules_v2_ref.py` does.
After any other line that adds to F, `RULES_VECTOR_FAIL line=N` is printed before that line's output.
In particular a `commit` with expectations that do not match fails, and it still advances the state.

## 10. Read set (READ-SET/v5)

What a commit read, as the gate binds it (`Run.reads`; printed by the out-of-scope `commit SHOW` as `RULES_READS HEX`):
u32 today, then the five reference pins in kind order 1, 2, 3, 4, 7 (each the declared 64-byte pin of a present
snapshot, or 64 zero bytes when it is missing), then u32 |P| and P. P is `RR/GATE/READ-SET/v5`, byte 0, five slots in
the same order, u32 the redo count, each redo payment as 261 bytes in the order read, then the 64-byte state digest
the commit starts from. A slot is byte 0 for a missing snapshot, else byte 1 and the SHA3-512 of the snapshot's pin
input with domain `RR/GATE/READ-DMF/v2`, `READ-PROVIDER-DEATH/v2`, `READ-EXCLUSION/v2`, `READ-ENROLLMENT/v2`,
`READ-ELIGIBILITY/v2` respectively, the kind number unchanged (so 7 for eligibility). All numbers big-endian.
`READ-SET/v2` (four slots) is retired with version 1.

## 11. Lean names

| Clause | Name |
|---|---|
| dates | `validDate`, `dayNum`, `monthDays`, `leap` |
| usable, chained, view, loose | `usable`, `chained`, `view`, `loose`, `okDeath`, `okExclusion`, `okSpan`, `okElig` |
| keys, claims | `exactKey`, `nearKey`, `idKey`, `keys`, `claim`, `pending`, `looseKeys` |
| facts | `memberDead`, `providerDead`, `excluded`, `enrolled`, `covers`, `overlap`, `notEnrolled`, `certain`, `unverified` |
| G2 facts | `aidId`, `allowedAid`, `eligCovers`, `aidEligible`, `levelEligible`, `Elig`, `Ctx.eligibility` |
| rule table | `fires`, `Reason`, `reasons` |
| outcome | `review`, `outcomeOf`, `Outcome` |
| batch | `decideBatchIn`, `decideAll`, `decideLine`, `order`, `canonical`, `seen0`, `own`, `payOutcome`, `releasedLines`, `unresolvedLines`, `advance` |
| pins | `pinInput`, `idWidth`, `payWidth`, `Line.fields`, `Elig.fields`, `Gate.stateDigest`, `Gate.setsDigest` |
| runner | `Run.step`, `Run.commit`, `Run.parseLine`, `Run.nat?`, `Run.fields`, `Run.keep`, `Run.quarantined`, `Run.render`, `Run.runLoop`, `Run.grow`, `Run.reads` |

Maximum ages are in `fires`: 90 (`dmf`, `pdeath`), 31 (`excl`), 7 (`span`, `elig`).
