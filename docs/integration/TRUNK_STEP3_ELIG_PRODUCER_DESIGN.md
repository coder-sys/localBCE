# Trunk step 3: eligibility snapshot producer (kind 7) design

## Status and scope

- **Status: approved by the owner 2026-11-19 ("Approve defaults"), revision 2: all 17 decisions in section 12 at their defaults, including the placeholder 5% threshold (decision 9) and the overlap rule stricter than the Spec (decision 7).** Docs only. Nothing in this design has been built, edited or committed. No check was run for it. Revision 2 applies a review (see "Review" below).
- Worktree `C:\Users\sruja\Downloads\localBCE-trunk`, branch `codex/rightrail-trunk-step3` at bbd0e947 (local). `rightrail/` is RightRail trunk fc89f9e5, a zip import.
- Paths: trunk paths as rightrail/path:line at bbd0e947. Lean paths are under rightrail/lean/BlindLedger/Gate/ when written short. October paths as f16a61f4:path:line. Every line cited below was re-read for this document or comes from the read-only surveys of 2026-11-19; the Rules/Spec, Run, Frame/Spec, Flat/Model, RowsStore, ffs, decide, 834, reference-checker, gate_rules_data, g_rule_parity, main.rs and GATE_RULES_V2 lines were spot-checked against the files.
- The owner is RightRail lead and authors or approves every change inside `rightrail/` (docs/integration/TRUNK_MIGRATION_PLAN.md:7). Checks gate every commit: a failed or skipped check stops the commit.
- Synthetic, not legally verified. G2 itself is synthetic (Rules/Spec.lean:222-224), and the 7-day maximum age is a placeholder (docs/integration/TRUNK_STEP3_G2_DESIGN.md:467).

### Review (revision 2)

- 39 findings: 14 major, 25 minor (accuracy 4 major / 8 minor; safety 5 major / 8 minor; completeness 5 major / 9 minor). Several overlap (golden pin, snapshot-as-input, secret delivery, set-aside PHI).
- Applied 37 in full and 2 in part; none rejected outright. Each was checked against the code first.
  - Part 1: the conflict rule now sets a member aside on any inclusive overlap of non-identical rows, whatever the aid or level. Rows that only touch (one stops the day before the next starts) are kept: each day still has one row, so `any` cannot pick the wider one (section 4.3).
  - Part 2: the asOf rules now use one file per snapshot and refuse a future file date. The suggested "same content hash, newer date" check is not adopted: the 834 hash covers the whole file, envelope date included, so a re-enveloped replay never matches, and a row-level match would also refuse an honest unchanged roster. Replay stays a named gap (section 7, gap 3).
- What changed: corrected citations and the G2 facts of localBCE (section 3.1); split rows at the level width (2.1); conditional `_UNVERIFIED` (2.4, 2.7, 6, 8.2); POSTING_CAP engine-only (2.6); a precise conflict rule, set-aside of the whole member, a join rule and 834 inheritance of the span feed's causes (4.1-4.3); a raw pin-only entry point for the golden pin (4.4); the snapshot as a vector fragment plus a sidecar (4.5); a `fits` callback (4.6); clock, secret, PHI and kind-7-before-(b) rules (5); table 6 split into now and deferred (6); vector assembly and placement of generated files (8); effort lines (10); decisions renumbered to 17 (12).

### Why this exists

- No eligibility producer exists. rightrail/STATUS.md:122-123 says so. So does the G2 design's open list (TRUNK_STEP3_G2_DESIGN.md:438), the plan (TRUNK_MIGRATION_PLAN.md:360) and the October design (docs/integration/G2_DESIGN.md:508).
- So once step 3 (b) carries the feed, every engine line is still HUMAN_REVIEW on STALE_ELIGIBILITY until something emits a usable kind-7 snapshot. That is fail-closed, but it means the gate releases nothing without review.

### In scope

- The **snapshot builder**: source records in, a pinned, dated kind-7 snapshot out (`asOf`, `count`, rows, SNAPSHOT/v1 pin), or "no snapshot".
- The **producer contract**: what a usable snapshot promises (completeness, freshness, no conflicts, member-key parity).
- A **synthetic fixture source** for tests, and the shape of the 834 and 270/271 sources.
- Tests that cross-check the builder against tools/gate_rules_data.py, conformance/gate_rules_v2_ref.py and the `gate_rules` exe.

### Out of scope (interfaces only)

- **Frame encoding.** The Route A row layout (stride 62), the sort-or-refuse rule, state 2, `FEED_KINDS` and `PIN_WIDTHS` belong to step 2's request side and step 3 (b) (TRUNK_STEP2_FRAME_DESIGN.md:125-133, :361-367; TRUNK_STEP3_G2_DESIGN.md:55). This design only names the interface the builder hands to that encoder (section 4.6).
- **Feed transport.** `request_frame` and the host feed list (rightrail/app/right_rail_gate_decide.py:501, :512-539). Unchanged here.
- **Any signed attestation of eligibility.** The signed path reads no eligibility (decision 15, TRUNK_STEP3_G2_DESIGN.md:475). Extending it is rr-core's call (section 11).
- **Share of cost (kind 8).** Same shape, separate design, after step 4.
- **A real 270/271 reader, or an 834 aid-code extension.** Described as sources with their limits; not designed in detail.
- **The `claim_input.json` fixture converter.** It belongs to Step 7 (TRUNK_MIGRATION_PLAN.md:394); decision 16.
- **Any change to rules, Lean, pins, PROVENANCE, tcb_report, rightrail/tests/gate_rules, conformance/MANIFEST.sha256 or `proof_execution_enabled`.**

## 1. Summary

- The producer is an **untrusted, host-side adapter**. It proposes bytes; it authorizes nothing (rightrail/CONSTITUTION.md:195-200). The engine only re-derives the pin and decides.
- It turns normalized eligibility records into 267-byte canonical rows, sorts them, pins them with the **same SNAPSHOT/v1 encoding** as tools/gate_rules_data.py:29-48 and Rules/Spec.lean:618-623, and writes a dated snapshot fragment in the text runner's own grammar.
- Spliced into a vector file, that output runs today through the text runner and the reference checker, with no frame (Rules/Run.lean:195-201, :257-265). So the builder and its tests can be built **now**, before (b).
- The **key risk** is direction of failure. An omitted member fails closed (PROGRAM_NOT_ELIGIBLE, a HOLD). A fabricated, stale, wrongly-joined or wrongly-keyed **allowed-aid, level-1 row fails open** (ALLOW). Lean cannot detect either (section 7).
- **Recommended first build:** the builder plus the synthetic fixture source, test-only, outside `rightrail/` (decisions 1-3). Real sources wait for an owner decision on where aid code and benefit level come from (decisions 10-11, open questions 1-3).

## 2. The consumer contract

What the rules and the engine read. The producer must match it byte for byte.

### 2.1 Row fields and widths

| Field | Meaning | Pin width (bytes) | Range |
|---|---|---|---|
| member | member identifier number | 129 | < 256^129 |
| aid | aid code identifier number | 129 | < 256^129 |
| level | benefit level exists: 1, else 0 | 1 | 0 or 1 for a usable snapshot; 2..255 fits but is unusable; ≥ 256 does not fit (missing) |
| start | first covered day, CCYYMMDD | 4 | < 2^32, a valid date |
| stop | last covered day, inclusive, CCYYMMDD | 4 | < 2^32, a valid date, ≥ start |

- Type: `Elig {member aid level start stop}` (Rules/Spec.lean:225-230). Meaning: Rules/Spec.lean:222-224.
- Pin fields: `[(idWidth, member), (idWidth, aid), (1, level), (4, start), (4, stop)]` with `idWidth = 129` (Rules/Spec.lean:593, :608-609). Every field is big-endian (`be`, Rules/Spec.lean:598-599); `be` returns none when a value does not fit, and then `pinInput` fails (:620-622). A row is 267 bytes.
- Python mirror: `WIDTHS["elig"] = (ID, ID, 1, 4, 4)`, `ID = 129` (rightrail/tools/gate_rules_data.py:16, :18-19). The contract page row: rightrail/conformance/GATE_RULES_V2.md:108.
- **Identifier encoding.** An identifier is 0x01 followed by its bytes, read big-endian (`aidId`, Rules/Spec.lean:388; `ident`, rightrail/app/right_rail_gate_ffs.py:93-95; `aid_id`, rightrail/conformance/gate_rules_v2_ref.py:33-38).
  - **member** = `ident(member_key(secret, member_id))`: SHA3-256 under the tenant secret, then 0x01 ‖ 32 bytes (right_rail_gate_ffs.py:29-31, :93-95). This is the same derivation the 837 request side uses (right_rail_gate_ffs.py:75) and the span feed uses (:138).
  - **aid** = `ident(aid_text.encode())`. The allowed set is `[78131, 78387, 79155, 20000819, 20000820]`, which is "13", "23", "53", "103", "104" (Rules/Spec.lean:392; GATE_RULES_V2.md:174-175). "105" and "D3" are not allowed (GATE_RULES_V2.md:175).
- **Text runner grammar.** `snap elig ASOF COUNT PIN`, then rows `elig MEMBER AID LEVEL START STOP` (Rules/Run.lean:19; Run.lean:257-259; Run.lean:717). Each field is a `nat?` numeral: ASCII digits, no `_` (Run.lean:204). Example: rightrail/tests/gate_rules/shards_v1.vectors:25-35.

### 2.2 The pin

- SHA3-512 of `pinInput` (Rules/Spec.lean:618-623; GATE_RULES_V2.md:96-100):
  - "RR/GATE/SNAPSHOT/v1", then 0x00;
  - u32 kind = 7, u32 asOf, u32 count;
  - the 267-byte rows, sorted ascending by bytes, concatenated. Duplicates are kept.
- The declared count is not compared with the rows when pinning, only in usability (GATE_RULES_V2.md:93-94).
- The text runner compares the lower-case hex pin with the declared one (Run.lean:195-201). The engine's `snap` / `snapF` accept only state 1 with a matching pin (Frame/Spec.lean:319-323; Flat/Worker.lean:165-170).
- The runner refuses a present snapshot whose declared pin is the zero digest (`readPin`, Run.lean:244). The producer can never hit this by honest hashing; it is listed for completeness.
- **Today's host `feed()` must not be reused for kind 7 as is.** It numbers a kind by position plus one (right_rail_gate_decide.py:522), so appending `elig` would pin kind 5. And it pins every field wider than 4 bytes at 129 and the rest at 4 (:519), which mis-encodes `level` (1 byte). Step 2 fixes both with `FEED_KINDS` and `PIN_WIDTHS` (TRUNK_STEP2_FRAME_DESIGN.md:361-363).

### 2.3 today and asOf

- `asOf` is the snapshot's date, CCYYMMDD, set by the producer from the source (section 4.5).
- `today` comes from the host clock, and the gate trusts it (rightrail/STATUS.md:214). In the runner it is the `today D` directive (Run.lean:687-690).
- Maximum age for eligibility is 7 days, a placeholder; localBCE's own TTL is 24 hours (Rules/Spec.lean:424-427; TRUNK_STEP3_G2_DESIGN.md:131, :467).

### 2.4 Missing, stale, unverified

**Missing** (`Ctx.eligibility = none`; Rules/Spec.lean:256). Any one of:
- no `snap elig`, or `drop elig`;
- a row that is not exactly five `nat?` numerals (Run.lean:257-259);
- a value that does not fit its width (level ≥ 256 included), or asOf or count ≥ 2^32 (GATE_RULES_V2.md:89-94, :99-100; Rules/Spec.lean:598-599, :620-622);
- a pin mismatch (Run.lean:195-201);
- on the engine, frame state ≠ 1 (Frame/Spec.lean:54-55, :319-323).

**Present but not usable** (`usable today 7 okElig`, Rules/Spec.lean:305-309; GATE_RULES_V2.md:117-121). Any one of:
- today or asOf is not a valid date;
- asOf is after today;
- today is more than 7 days after asOf (age 7 is usable, age 8 is not);
- the row count is not the declared count, or count is 0;
- a row fails `okElig`: an invalid date, start after stop, or level 2..255 (Rules/Spec.lean:300).

**Consequences** (Rules/Spec.lean:181-187, :357-364, :455-459, :463-473; GATE_RULES_V2.md:206, :213-217):

| State of the snapshot | Reasons a line can get |
|---|---|
| missing | STALE_ELIGIBILITY alone (review, bypassable). Never an `_UNVERIFIED` code. |
| present, not usable | STALE_ELIGIBILITY, plus an `_UNVERIFIED` code only when the member's rows that are there are not (level) eligible (review, bypassable). An eligible member gets STALE_ELIGIBILITY alone. |
| usable | BENEFIT_LEVEL_MISSING or PROGRAM_NOT_ELIGIBLE (certain, HOLD, not bypassable), or nothing from G2 |

- `BENEFIT_LEVEL_MISSING_UNVERIFIED` needs `aidEligible && !levelEligible`, `PROGRAM_NOT_ELIGIBLE_UNVERIFIED` needs `!aidEligible`, and both need a valid line date (Rules/Spec.lean:362-364, :456, :458).
- STALE_ELIGIBILITY fires on every line of the batch (GATE_RULES_V2.md:206, :210-211).
- An invalid service date silences G2; a future one does not (GATE_RULES_V2.md:213-215).

### 2.5 How the rules read the rows

- A row **covers** a line when member matches and start ≤ line date ≤ stop (`eligCovers`, Rules/Spec.lean:394). For CAP_820 the date is the period start (GATE_RULES_V2.md:216-217).
- **aid eligible**: some covering row has an allowed aid (Rules/Spec.lean:397-398).
- **level eligible**: one single covering row has an allowed aid **and** level 1 (Rules/Spec.lean:401-402). Split rows do not pass (GATE_RULES_V2.md:177-179).
- Both are `any` over covering rows. So when two rows cover a day, the more permissive one wins. This is why overlapping rows are set aside (section 4.3).
- Facts read the rows of a present snapshot even when it is unusable (GATE_RULES_V2.md:181).

### 2.6 What the producer must supply for each outcome

- **For a certain answer:** a correct pin; a valid asOf, no later than today and at most 7 days old; count equal to the rows and above 0; every row with valid, ordered dates and level 0 or 1.
- **A usable snapshot is read as complete.** A member with no covering row gets PROGRAM_NOT_ELIGIBLE, a certain HOLD (Rules/Spec.lean:457). So every member the producer leaves out is held, not reviewed.
- **Level and aid on the same row.** A source that reports them separately must be joined before rows are built. A join emits a level-1 row only over the intersection of an aid window and a level-1 window of the **same member and the same source**. A day the level source does not cover gets level 0, or the member is set aside when the level source is in fault for it. An aid from one window is never paired with a level from another. A wrong join fabricates the one row that ALLOWs (section 2.7, last row).
- **Per-member cap.** More than 1,024 rows for one member gives POSTING_CAP, a HOLD, on the engine path only (`capN`, Flat/Model.lean:93; `feedCapped`, :362-364; decision 13, TRUNK_STEP3_G2_DESIGN.md:473). The text runner and the reference checker read whole sets and never emit it (Rules/Spec.lean:454).

### 2.7 Producer failure to reason map

| Producer failure | What the gate sees | Reason |
|---|---|---|
| no snapshot emitted | missing | STALE_ELIGIBILITY |
| wrong pin, wrong kind number, wrong field width, level ≥ 256 | missing | STALE_ELIGIBILITY |
| asOf in the future, or older than 7 days | present, not usable | STALE_ELIGIBILITY, plus an `_UNVERIFIED` code when the member's rows are not (level) eligible |
| count ≠ rows, or empty | present, not usable | as above |
| a malformed row (bad date, start > stop, level 2..255) | present, not usable | as above |
| a member left out of a usable snapshot | usable, no covering row | PROGRAM_NOT_ELIGIBLE (HOLD) |
| member keyed with the wrong secret, or member_id text not byte-identical to the 837 side | usable, no row ever matches | PROGRAM_NOT_ELIGIBLE (HOLD) on every line of that member (all members for a wrong secret) |
| aid and level on separate overlapping rows | from the builder: member set aside (section 4.3), so no covering row; from a hand-written snapshot: usable, aid eligible, not level eligible | builder: PROGRAM_NOT_ELIGIBLE (HOLD); hand-written: BENEFIT_LEVEL_MISSING (HOLD) |
| an allowed aid at level 0 only | usable, aid eligible, not level eligible | BENEFIT_LEVEL_MISSING (HOLD) |
| over 1,024 rows for one member | capped read (engine only) | POSTING_CAP (HOLD) |
| a false, stale or wrongly-joined allowed-aid, level-1 row | usable, eligible | **nothing: the line can ALLOW** |

The last row is the one failure Lean cannot catch. Section 7 covers it.

## 3. Sources

| Source | Exists in the tree | Can assert | Cannot assert | Best class |
|---|---|---|---|---|
| Synthetic fixture | partly (vectors only) | everything, by construction | anything real | certain, tests only |
| 834 enrollment | reader yes; aid and level no | member, enrollment windows | aid code, benefit level | none until extended |
| 270/271 | no | not known (no reader) | completeness beyond the members asked | excluded under decision 5 |

### 3.1 Synthetic fixture source (tests only)

- Hand-written records `(member_id text, aid text, level, start, stop)` with CCYYMMDD dates, plus `asOf`, `today` and the public test secret (decision 3). Synthetic, non-PHI.
- Existing elig data is all synthetic and hand-written: shards_v1.vectors:25-35 (every member aid "13" level 1, 19000101-99991231, members as raw small numbers, not keyed), and the G2 cases of rules_v2.vectors and its negatives (docs/integration/G2_DESIGN.md:279-291).
- October's only "producer" was a seeded `demo()` generator that wrote the same fixed elig row for every member (f16a61f4:rightrail/tools/gate_rules_data.py:68-131, row at :87). The trunk deleted it (rightrail/tools/gate_rules_data.py:7-8).
- **localBCE G2 is two per-claim scalars**, `aid_code` and `benefit_level_exists` (rust-engine/src/main.rs:235-240), with no date component. The eligibility period belongs to G3: `date_of_service_from` against `eligibility_period_from/thru` gives `G3_MONTH_OF_SERVICE_FAILED` (main.rs:241-244; rust-engine/claim_input.json:49-51). Rules/Spec.lean:222-224 cites only main.rs:235-240 for G2.
- So a fixture that turns one localBCE claim into one elig row would take aid text from `aid_code` (as `str(int)`), level from `benefit_level_exists`, and **borrow** its dates from the G3 period. That borrowing is a choice of this design, not a localBCE G2 fact. It is deferred to the Step 7 converter (decision 16); the claim_input period numbers (20000 / 19900 / 21000, claim_input.json:49-51) are not CCYYMMDD dates (open question 5).
- **No elig-rows-to-G2 inverse map exists.** scripts/g_rule_parity.py:285-320 (`derive_claim`) maps span, dmf, excl, pdeath and released rows to the G1/G3/provider/duplicate/deceased flags and holds G2 at `PASSING_FLAGS` (`aid_code: 13`, `benefit_level_exists: 1`; g_rule_parity.py:52-54, applied at :319). Its v1 comparison lines carry no eligibility (:37-38). G2_DESIGN.md:509 says the same. Building that inverse map is open work (section 9).
- **Can assert:** every field. **Class:** certain inside tests. It must never feed a production frame (decision 3).

### 3.2 834 enrollment

- The reader is rightrail/app/right_rail_x12_834.py. Its `Enrollment` row has member id, maintenance type INS03, subscriber flag INS01, plan HD04, coverage line HD03, coverage type HD01, coverage dates DTP 348/349, eligibility dates DTP 356/357, maintenance and death fields, name and address fields, and the file time (right_rail_x12_834.py:20-21, :24-51).
- **It captures no aid code and no benefit level** (right_rail_x12_834.py:24-51). It parses HD elements 1, 3 and 4 only (:164) and reads REF only for 0F (:165). A member that appears twice in one file is reported, with every row kept (:9).
- **The span feed's rules, which any 834-derived elig row must inherit** (right_rail_gate_ffs.py:98-172):
  - window: begin is the later of coverage and eligibility begin, stop the earliest of coverage end, eligibility end and any cancellation cut (INS03 or HD01 024) (:139-142, :148-151);
  - no row is given for a dependent (INS01 N, which carries the subscriber's REF*0F; `dependent_member`), a deletion (INS03 or HD01 002; `deleted`), a member in two member loops (`conflicting_rows`, :147, :154), a cancellation with neither date (`termination`), no plan or no begin date, or bad dates (:153-156);
  - a fault inside a member loop sets every row of that member aside (`member_quarantined`, :130-134); a fault outside every member loop makes the feed absent ("blind", :129-135, :172);
  - asOf is the newest `file_at` (:137), which this design does **not** reuse as is (section 4.5).
- **Can assert:** that a member was enrolled in a window, with the same member key the 837 side uses.
- **Cannot assert today:** the aid code or the benefit level. Two ways to get them, both needing an owner decision:
  - extend the 834 reader to capture a state-specific aid category. Which segment or qualifier carries it is state-specific and not known here (open question 1);
  - map plan or coverage line to an aid code through a configured table. No such table exists; any mapping would be invented (open question 2).
- **Completeness.** A usable snapshot must list every member. The 834 reader does not say whether a file is a full roster or a change file: `BGN` is only in its known-segment list (right_rail_x12_834.py:19). The LEIE feed has a precedent: a supplement gives no feed (right_rail_gate_ffs.py:136). The full-roster flag must come from file content, not from a caller argument (open question 3).
- **Class:** none until aid and level have a source. A window-only snapshot cannot be built, because every row needs an aid and a level.

### 3.3 270/271

- **No 270/271 reader or generator exists.** The X12 readers present are 820, 834, 835 and 837, and only 834 and 837 feed the claim path (rightrail/STATUS.md:215). October said the same (G2_DESIGN.md:508).
- A 271 answers an inquiry about named members. So a snapshot built from 271s is complete only for the members asked. A usable snapshot reused for a later batch within 7 days would hold every unlisted member with a non-bypassable PROGRAM_NOT_ELIGIBLE (Rules/Spec.lean:178-180, :457).
- So under decision 5 a 271 set gives **no snapshot**. A "batch-scoped" completeness class, binding the snapshot to one batch's member set and refusing reuse for any other batch, is an option for the owner, not part of this design.
- What a 271 can carry for aid code and benefit level, and how it maps to `level`, is not checked here (open question 4).
- If ever allowed, asOf would be the oldest response date in the set, so the age check is conservative.
- **Class:** excluded for now. Building it is a new reader plus a request path; not designed here.

### 3.4 MMIS eligibility extract

- Not built: "MMIS extract adapters" are listed as unbuilt (rightrail/STATUS.md:215). Named only so the owner can choose it as the real source (decision 11).

## 4. The producer pipeline

Five stages. Each stage either passes everything on or stops with a named cause. Nothing is silently dropped.

### 4.1 Normalize

- Input: source records, the tenant secret, `today` (optional; the host date, section 5), and the source's own date and completeness, both read from the source content (section 4.5, decision 5).
- Output: records `(member_id, aid_text, level, start, stop, origin)`, where `origin` is a file hash and offset or a fixture line number, like the 834 reader's offsets (right_rail_x12_834.py:49).
- **member_id** is byte-identical to what the 837 reader returns as `subscriber_id` for the same member, since `member_key` hashes `member_id.encode()` exactly (right_rail_gate_ffs.py:31, :75). The producer applies no trimming, case change or zero-padding of its own. A member_id that is empty or has leading or trailing whitespace sets the member aside (`bad_member_id`).
- **aid_text** is a canonical code string: ASCII letters and digits only, no whitespace, numeric codes without leading zeros, at most the encoder's width (section 4.6). An integer aid code becomes `str(int)`. Any other form sets the member aside (`bad_aid`), so " 13", "013" or "13 " never becomes a silently non-allowed aid.
- Dates: ISO to CCYYMMDD numbers, as `day()` does for the span feed (right_rail_gate_ffs.py:124, :172). An open end becomes 99991231 only when the source states the coverage is open (no end segment sent in a record that read cleanly), as `stop` does (:151). A missing end that comes from a parse fault is a fault, never 99991231.
- `level` must be 0 or 1. Any other value is a source fault (section 6).
- **834-derived rows** inherit exactly the span feed's window and set-aside rules (section 3.2): either reuse the ffs begin/stop/cause logic, or test parity against `ffs.feeds()`: for every member, the elig windows equal the span windows ffs emits, members ffs sets aside are never emitted, and a blind ffs read gives no snapshot.
- **Joins** of separate aid and level sources follow section 2.6: intersection only, same member and source.
- A source that is not a full roster makes the whole run stop with no snapshot (decision 5).

### 4.2 Rows

- `member = ident(member_key(secret, member_id))` (right_rail_gate_ffs.py:29-31, :93-95).
- `aid = ident(aid_text.encode())`, equal to `aidId` and `aid_id` (Rules/Spec.lean:388; gate_rules_v2_ref.py:33-38).
- Pre-validate every row against `okElig` (Rules/Spec.lean:300): valid dates, start ≤ stop, level ≤ 1; and against the widths of section 2.1.
- Pre-validate against the frame limits through the encoder's `fits(row)` callback (section 4.6), so (b) never has to send state 2. The Route A callback checks a member with the 0x01 top byte and 32 key bytes and aid text of at most 20 bytes (TRUNK_STEP2_FRAME_DESIGN.md:117, :125, :129). All five allowed codes fit.
- **Any row fault sets every row of that member key aside, across all origins**, as ffs quarantines every row of a hurt member (right_rail_gate_ffs.py:130-134, :153). Dropping only the bad row could leave an open-ended allowed row that ALLOWs.
- An aid code outside the allowed set is **kept**, not dropped. It is a real fact the rules need: it is what makes PROGRAM_NOT_ELIGIBLE certain.

### 4.3 Sort, dedupe and conflicts

- Encode each row at its pin widths (267 bytes) and sort ascending by bytes, as `sorted(rows)` does (gate_rules_data.py:43) and `mergeSort` does (Rules/Spec.lean:623).
- **Exact duplicates** (all five fields equal) are dropped before conflict checks, counting and pinning (decision 6). The pin keeps duplicates (GATE_RULES_V2.md:99-100), and `any` makes them harmless to the rules, so dropping them only keeps count honest and the snapshot small.
- **Conflict** (decision 7): a member has a conflict when two of its rows that are not exact duplicates **overlap inclusively** (`a.start ≤ b.stop` and `b.start ≤ a.stop`), whatever their aid, level or stop. That covers a different aid or level, a re-sent row with another stop, and a later row that ends coverage earlier. The member is set aside. This is this design's own policy, stricter than the Spec, whose `any` reading accepts concurrent rows (Rules/Spec.lean:397-402). The owner must confirm it.
  - Rows that only touch (one stops the day before the next starts) are not a conflict. Each day still has exactly one row, so no wider row can win.
  - The span feed is not a precedent for this: its `conflicting_rows` means a member found in two member loops (right_rail_gate_ffs.py:147, :154), and it sends overlapping spans with different plans on for the rules to decide (:171-172; CAP_MEMBER_MONTH_DUPLICATE, Rules/Spec.lean:379-385, :431).
  - Consequence: from the builder, BENEFIT_LEVEL_MISSING arises only from an allowed aid at level 0 with no overlapping row. Split aid-and-level rows reach the rules only through a hand-written snapshot (section 8.2).
- **Over 1,024 rows for one member** (counted after dedupe): the member is set aside and reported, rather than sent and capped (decision 6).
- Every set-aside member goes into the set-aside list (section 4.5) with its cause and origins, like ffs `left` (right_rail_gate_ffs.py:160-163), but never with the member id text.
- **Set-aside threshold** (decision 9): when more than 5% of the source's members (a placeholder) are set aside, the run gives no snapshot instead. That sends every line to review (bypassable) instead of holding a large share of members as "not eligible" for what is really a data fault.

### 4.4 Pin

- `pin = SHA3-512("RR/GATE/SNAPSHOT/v1" ‖ 0x00 ‖ u32 7 ‖ u32 asOf ‖ u32 count ‖ sorted rows)`.
- This is exactly the encoding of tools/gate_rules_data.py:29-48 for `snap elig`: domain SNAPSHOT/v1 (:41), kind `KINDS.index("elig") + 1 = 7` (:14, :42), widths `(129, 129, 1, 4, 4)` (:18-19), `sorted(rows)` (:43).
- **Reuse** (decision 12): rows through `gate_rules_data.row("elig", fields)` (:22-26); the head and domain written locally as gate_rules_data.py:41-43 writes them (that file has no rows-to-pin function, only text rewriting in `pin()`). `gate_rules_v2_ref.pin_bytes("elig", ...)` (gate_rules_v2_ref.py:104-112) is the independent cross-check, never the encoder.
- **Two entry points:**
  - `build(records, secret, ...)`: the keyed path, stages 4.1-4.4, with the `fits` pre-check;
  - `pin_rows(asof, rows)`: pre-keyed 5-tuples of numbers in, sort and pin out. No keying, no normalize and no `fits` pre-check (the Route A check is skipped on this path). It is what `build` calls after stage 4.3, and what the golden-pin test uses (section 8.1). It is test and internal only; no source feeds it directly.
- `count` is the number of rows after dedupe and set-aside. It is never taken from the source.

### 4.5 Dated snapshot

- **Output is a fragment**: `snap elig ASOF COUNT PIN` followed by the rows, one per line, in sorted order (Run.lean:19). It is not a standalone accepted input: a file with no `end N` and no checked lines makes `gate_rules_v2_ref.run` report `RULES_VECTORS=FAIL`, because `expected` stays None (gate_rules_v2_ref.py:126, :431-432). It is spliced into a vector file with `today`, the other snapshots, lines, `commit` and `end` (section 8.2).
- **Sidecar JSON** beside it, never inside the fragment (the runner skips only `#` lines, gate_rules_v2_ref.py:420, and the pin has no place for it). Named fields: `producer_version`, `source_hashes` (SHA3-512 of each input), `as_of`, `as_of_source` (the field it came from), `clock` (host date and timezone basis used), `count`, `set_aside`, `result` (`snapshot` or a closed `no_snapshot` cause).
- **Set-aside record**: `{member_number, cause, origins}`, where `member_number` is the keyed member number (the 0x01-prefixed key), `cause` is from the closed list of section 6, and `origins` are file hash plus byte offset or fixture line (amended 2026-11-20 with the owner's "Yes, commit": the fixture source gives `fixture:<first 16 hex of the SHA3-512>#records/i` or `#split/i`, a JSON position, since the JSON parser gives no line numbers; the full hash is in `source_hashes`). **Never the member id text, name, birth date or address**, unlike ffs `SetAside.id` (right_rail_gate_ffs.py:35, :160).
- **asOf is never later than the source** (decision 8):
  - exactly one full-roster source file per snapshot; more than one gives no snapshot (`many_sources`), so a newer file can never date rows from an older one;
  - for an 834, asOf is that file's date, from the field named in `as_of_source` (`file_at`, "when the sender says the file was made", right_rail_x12_834.py:46). It is sender-asserted transmission time, not proof that the data was current (section 7, gap 3);
  - a source date after the host's `today` gives no snapshot (`future_source`);
  - a source older than 7 days is emitted as is, asOf honest, and reported in the sidecar;
  - the producer never re-stamps an old source with today.
- **No snapshot** is an explicit result, not an empty file. An empty snapshot is unusable (count 0, Rules/Spec.lean:305-309) and would turn into `_UNVERIFIED` noise; "no snapshot" gives STALE_ELIGIBILITY alone.

### 4.6 Interface to the (b) encoder

- The builder hands the encoder `(asOf, rows as 5-tuples of numbers, pin)` or "no snapshot". It does not write frame bytes.
- The encoder supplies `fits(row) -> bool` (section 4.2). The frame limits live in the encoder, not the builder; the test tool passes a Route A `fits`. So the builder is route-independent.
- The encoder (step 2 request side and (b)) writes the 62-byte rows, the field-by-field order, the 77-byte descriptor and state 2 on a misfit (TRUNK_STEP2_FRAME_DESIGN.md:106, :125-129). It uses `FEED_KINDS["elig"] = 7` and `PIN_WIDTHS` (:361-363).
- `ffs.feeds()` stays at four feeds (TRUNK_STEP2_FRAME_DESIGN.md:366). The elig snapshot reaches `request_frame` through the six-feed form (:365-367), from a caller that adds it beside ffs.
- **No kind 7 before (b)** (decision 17): no caller adds the elig feed to `request_frame` until (b) lands with pin verification, and the six-feed caller refuses kind 7 before then. Between the step 2 commit and (b) the descriptor is bound but not pin-verified (TRUNK_STEP2_FRAME_DESIGN.md:571, :589). Today the engine reads no eligibility in that window (its Ctx is built from kinds 1-4, TRUNK_STEP3_G2_DESIGN.md:27), so this is not an ALLOW path, but the contract says so explicitly.
- Keeping the builder separate from `FEED_WIDTHS` and `feed()` (right_rail_gate_decide.py:501-524) means the route choice touches only the encoder.

## 5. Where it runs and what it trusts

- **Host side, outside the engine and outside the TCB.** "Python holds no policy" (right_rail_gate_decide.py:13). Producers are untrusted: they may propose bytes, never authorize (CONSTITUTION.md:195-200).
- **It trusts:**
  - the source files, as delivered (no signature exists on any frame feed: "Fact signatures do not exist yet", STATUS.md:71);
  - the tenant secret, which must be the one the 837 side uses (right_rail_gate_ffs.py:75);
  - the host clock for `today` (STATUS.md:214). The builder takes `today` as an input to refuse a future source date, and records in the sidecar which clock and timezone basis it used. The source date is the date part of the sender's time as sent (`file_at[:10]`, right_rail_gate_ffs.py:137); a UTC/local mismatch with the host date can shift age by one day (section 7, gap 3).
- **Secret delivery** (decision 15): the CLI reads the secret from a file path or an environment variable, never from argv (which shows in the process list and shell history). Tests pass a fixed synthetic constant in-process. The secret bytes never appear in any output, sidecar, set-aside record, log or exception text.
- **No record content in output.** The builder never prints, logs or raises with source record fields (member id, name, birth date, address). Errors name a cause and an origin only.
- **The engine trusts nothing from it** beyond consistency. It recomputes the pin over the rows sent (Frame/Spec.lean:319-323). The feed is bound into CONTEXT and each token's input for audit (rightrail/conformance/ENGINE_V3.md:637-653), which records what was read, not that it is true.
- **Placement** (decision 2).
  - Now: a test-only tool outside `rightrail/`: `scripts/elig_snapshot.py`, tests in `scripts/tests/test_elig_snapshot.py`, next to the existing g_rule_parity harness and its tests. They import `rightrail/tools/gate_rules_data.py` and `rightrail/conformance/gate_rules_v2_ref.py`, and `app.right_rail_gate_ffs` for `member_key` and `ident`, by putting those directories on `sys.path`, as scripts/tests/test_g_rule_parity.py:7 does for scripts/. No file inside `rightrail/` is edited. The tests run in `scripts/validate_localbce.sh` ("Parking guard and script tests", :32), which CI runs.
  - Later: a product module in `rightrail/app/`, one home per module (CONSTITUTION.md:129-133), with the owner's approval.
- **Build order** follows XI.6: the input and identity contract (section 2), then the bounded producer artifact (section 4), then an independent verifier (the reference checker and the exe), then mutation tests (CONSTITUTION.md:201-206).

## 6. Failure modes and their fail-closed outcome

"Now" rows can be produced by the fixture source. "Deferred" rows need a real source; until then a fixture-level stand-in tests the builder's handling.

| Failure | Producer action (cause) | Gate outcome | Testable |
|---|---|---|---|
| source missing or unreadable | no snapshot (`no_source`) | STALE_ELIGIBILITY, review | now |
| more than one source file | no snapshot (`many_sources`) | STALE_ELIGIBILITY, review | now |
| source not a full roster | no snapshot (`not_full`) | STALE_ELIGIBILITY, review | stand-in: fixture completeness false |
| no valid source date | no snapshot (`no_as_of`) | STALE_ELIGIBILITY, review | stand-in: fixture with no asOf |
| source date after host today | no snapshot (`future_source`) | STALE_ELIGIBILITY, review | now |
| fault outside a member record (as ffs "blind"); trailer missing or SE01/GE01/IEA01 counts wrong | no snapshot (`blind`, `truncated`) | STALE_ELIGIBILITY, review | deferred (834) |
| zero rows after set-aside | no snapshot (`empty`) | STALE_ELIGIBILITY, review | now |
| set-aside members above the threshold | no snapshot (`too_many_set_aside`) | STALE_ELIGIBILITY, review | now |
| the builder throws | no snapshot (`builder_error`) | STALE_ELIGIBILITY, review | now |
| fault inside one member record | set the member aside (`member_quarantined`) | that member HELD (PROGRAM_NOT_ELIGIBLE) | deferred (834); stand-in: malformed fixture row |
| dependent, deleted, cancelled or terminated member (834) | set the member aside (as ffs causes) | that member HELD | deferred (834) |
| bad member_id or aid text | set the member aside (`bad_member_id`, `bad_aid`) | that member HELD | now |
| overlapping non-identical rows | set the member aside (`conflicting_rows`) | that member HELD | now |
| level not 0 or 1, or bad dates | set the member aside (`bad_level`, `bad_dates`) | that member HELD | now |
| a value that does not fit a width or `fits` | set the member aside (`does_not_fit`) | that member HELD | now |
| over 1,024 rows for one member, after dedupe | set the member aside (`over_cap`) | that member HELD | now |
| source older than 7 days | emit as is, asOf honest | STALE_ELIGIBILITY, plus an `_UNVERIFIED` code when the member's rows are not (level) eligible; review | now |

- Every row above is fail-closed: review or HOLD, never ALLOW.
- **Set aside means HOLD, not review.** A usable snapshot has no way to say "unknown for this member" (section 2.6). This matches the span feed, where a set-aside member gets no span and so MEMBER_NOT_ENROLLED (right_rail_gate_ffs.py:153-156, :172). The threshold (decision 9) turns a noisy source into review instead.
- **A malformed row is never emitted.** Emitting it would make the whole snapshot unusable (Rules/Spec.lean:300, :309) and turn every line into review. The producer catches it first and sets the whole member aside.

## 7. Producer-trust gaps (stated honestly)

These remain after this design. None is closed by Lean.

1. **Authenticity.** No frame feed is signed (STATUS.md:71). Anyone who can drive the host can submit any rows with a self-consistent pin. The signed path, which could attest, reads no eligibility by design (Flat/Signed.lean:110-121; Scoped.lean:66-75, :93-99; decision 15 of the G2 design).
2. **Fails open on false eligibility.** A fabricated, out-of-date or wrongly-joined allowed-aid, level-1 row lets a line ALLOW. Only the source's honesty and the producer's freshness, join and conflict rules stop it.
3. **Freshness of asOf.** The producer declares asOf. Lean checks only that it is not after today and at most 7 days old (Rules/Spec.lean:305-309). Open, after this design:
   - the 834 date is sender-asserted transmission time; a re-transmitted old roster, or a sender clock behind or ahead within tolerance, gets a fresh asOf. Only a signed or otherwise attested source closes this;
   - a host clock running behind makes an out-of-date snapshot usable (asOf ≤ today, age ≤ 7), so terminated members can ALLOW (STATUS.md:214);
   - a UTC/local mismatch between the source date and `today` can add or hide one day of age;
   - the 7-day window is wider than localBCE's 24-hour TTL (TRUNK_STEP3_G2_DESIGN.md:131).
   Closed by this design: a future source date (refused), several files of different ages (refused), re-stamping (never done).
4. **Completeness.** Count is self-declared and checked only against the rows sent. An omission fails closed (HOLD), but at scale it is review and correction load on members who are in fact eligible, and those HOLDs are not bypassable (Rules/Spec.lean:178-180). A roster truncated inside a member loop could lose that member's termination; the trailer-count check (section 6) narrows this for the 834.
5. **Member-key parity.** A wrong tenant secret, or member_id text that differs by one byte from the 837 side, means no row matches: those lines HELD (section 2.7). Lean cannot detect it. Only a host-side parity test can (section 8).
6. **The step 2 window.** Between the step 2 commit and (b), the eligibility descriptor is bound into CONTEXT/v2 but not pin-verified, so a mis-pinned feed would be accepted (TRUNK_STEP2_FRAME_DESIGN.md:571, :589). Decision 17 forbids sending kind 7 then. From (b), a bad pin gives STALE_ELIGIBILITY alone (TRUNK_STEP3_G2_DESIGN.md:126).
7. **Legal basis.** The rule and its allowed set are synthetic and not legally verified (Rules/Spec.lean:222-224). D3/D4 and localBCE manual review stay named unresolved differences (TRUNK_STEP3_G2_DESIGN.md:440).
8. **No real source.** Until a source for aid code and benefit level is chosen, production stays at STALE_ELIGIBILITY on every line.

## 8. Tests and conformance

All synthetic and non-PHI. Signer-free. Generated files are written only to a temporary directory or elsewhere outside `rightrail/`, and never touch rightrail/tests/gate_rules, conformance/MANIFEST.sha256 (which pins tests/gate_rules/rules_v2.vectors, MANIFEST.sha256:1), PROVENANCE or tcb_report.

### 8.1 Builder unit tests (scripts/tests/test_elig_snapshot.py)

- Pin equality: for each fixture, the builder's pin equals `gate_rules_data.pin()` on the same `snap elig ... ?` text (gate_rules_data.py:29-48), and equals SHA3-512 of `gate_rules_v2_ref.pin_bytes("elig", ...)` (gate_rules_v2_ref.py:104-112).
- Golden pin, through `pin_rows` only: the raw tuples of shards_v1.vectors:26-35 (members 1001..9002 as plain numbers, not keyed) give `fe10794a...` byte for byte (shards_v1.vectors:25). This tests the encoder (stages 4.3-4.4) only; keying is tested by the member-key tests.
- Kind and width: a test that fails if `level` is pinned at 4 bytes or kind is pinned as 5 (the two `feed()` pitfalls, section 2.2).
- Aid encoding: `ident(b"13") == 78131`, and the five allowed codes give `allowedAid` (Rules/Spec.lean:392).
- Member-key parity: a fixture member's elig row number equals the member number a 837 request for the same member id gets under the same secret (right_rail_gate_ffs.py:75, :138).
- Normalization negatives: member_id with a trailing space, aid " 13", "013", "13 " and lower-case letters give the stated set-aside cause; an integer aid 53 gives "53".
- Conflicts: two same-aid level-1 rows where one stops earlier, overlapping: member set aside, so no covering row after the earlier stop. Touching rows: both kept. Different aid or level, overlapping: set aside.
- Whole-member set-aside: one good allowed-aid level-1 row plus one malformed row for the same member gives no row for that member.
- Join: an aid window and a level-1 window that only partly overlap give a level-1 row only over the intersection, level 0 elsewhere.
- Cap: 1,024 rows kept; 1,025 set aside; duplicates removed before counting. The cap's effect on the gate (POSTING_CAP) is tested only with (b) or the Flat engine.
- asOf: a source date after `today` gives `future_source`; two source files give `many_sources`; asOf is never today when the source is older.
- Threshold: set-aside above the placeholder gives `too_many_set_aside`.
- Order and dedupe: shuffled input gives the same output; exact duplicates are removed; count equals rows.
- Fixture secret: the fixture source refuses any secret other than the public test secret.
- No leaks: the outputs, sidecar and every error text contain no fixture member id, name or secret bytes.
- Each "now" row of table 6, and each stand-in, gives its stated action and cause.

### 8.2 Cross-check against the reference checker and the exe

- **Vector assembly** (a step of its own): for each case, a full vector file: `today`; released and unresolved snaps; usable dmf, pdeath, excl and span snapshots whose span and dmf rows are re-keyed to the same 33-byte member numbers under the test secret (as `_gate_shards._with_members` does for span and dmf, rightrail/tests/_gate_shards.py:62-77); the builder's elig fragment; lines whose member fields are the keyed member numbers; `commit`; expected OUTCOME/REASONS **written by hand from section 2**, never from a runner's output; and `end N`. Without the other feeds every line also gets STALE_* or MEMBER_NOT_ENROLLED, and the ALLOW case cannot show.
- Run each through `gate_rules_v2_ref.run` (gate_rules_v2_ref.py:416-432) and through the `gate_rules` exe, and require PASS from both and equal output, as `test_checker_output_equals_exe_output` does for the published files (rightrail/tests/test_gate_rules_v2_spec.py:45-52).
- Cases, each one line or more:
  - usable, allowed aid, level 1: no G2 reason;
  - usable, member left out: PROGRAM_NOT_ELIGIBLE;
  - usable, aid "105": PROGRAM_NOT_ELIGIBLE;
  - usable, allowed aid at level 0 only (from the builder): BENEFIT_LEVEL_MISSING;
  - usable, allowed aid at level 0 plus level 1 under another aid, overlapping: a **hand-written** snapshot that bypasses the builder (the builder would set the member aside): BENEFIT_LEVEL_MISSING;
  - asOf 7 days old: usable. 8 days, eligible member: STALE_ELIGIBILITY alone. 8 days, member with no covering allowed row: STALE_ELIGIBILITY plus PROGRAM_NOT_ELIGIBLE_UNVERIFIED;
  - no snapshot: STALE_ELIGIBILITY alone;
  - one pin byte flipped: STALE_ELIGIBILITY alone;
  - wrong secret: PROGRAM_NOT_ELIGIBLE on every line.
- The over-cap case is left out: neither the runner nor the checker emits POSTING_CAP (Rules/Spec.lean:454).
- **The exe needs a Lean build, and it must be current.** The exe check is its own gated step, not part of the default test discovery: it fails (never skips) when the exe is missing or when `runner_source_line` shows it was built from other sources (rightrail/tests/test_gate_rules_vectors.py:14, :30-34, :72-77). Building goes only through the guarded lake_trunk.ps1. A skipped exe check stops any commit; it is not a pass.

### 8.3 Later, with (b)

- ALLOW fixtures with a usable elig feed through the frame path, and `PAIRS_DIGEST` (TRUNK_STEP3_G2_DESIGN.md:55).
- `_gate_shards._with_members` re-keys only span and dmf rows (rightrail/tests/_gate_shards.py:65). Elig rows stay small numbers and would never match a frame request's member key. (b) must add "elig" there, or the shared header's elig rows match no request.
- POSTING_CAP for an over-cap member that bypasses the builder, on the capped engine.

## 9. What can be built now, and what waits

| Item | When | Waits on |
|---|---|---|
| Producer contract text (section 2.6, 4, 5, 7) | now | nothing |
| Snapshot builder (`build`, `pin_rows`), fragment, sidecar, set-aside list | now | nothing |
| Synthetic fixture source with public test secret | now | nothing |
| Tests 8.1, and 8.2 against the reference checker | now | nothing |
| Tests 8.2 against the exe | now | a guarded Lean build of `gate_rules`, current to its sources |
| Elig-rows-to-G2 inverse map for g_rule_parity (replacing `PASSING_FLAGS` for G2) | later | an owner decision; not needed by the builder |
| `claim_input.json` to fixture converter | Step 7 | TRUNK_MIGRATION_PLAN.md:394; open question 5 |
| Frame encoder (stride 62, order, state 2, `FEED_KINDS`, `PIN_WIDTHS`, Route A `fits`) | (b) | step 2 request side: rr-core's answer or the 2026-11-22 bound (TRUNK_STEP2_FRAME_DESIGN.md:5) |
| Six-feed `request_frame` caller, `_gate_shards` re-key, ALLOW fixtures | (b) | as above |
| A real source (834 extension, MMIS) | later | owner decisions 10-11; open questions 1-3 |
| 271 source | later | a batch-scoped completeness class (decision 5); open question 4 |
| Signed eligibility snapshots | later | rr-core: a SnapshotV2 `Kind` beyond 4 (SnapshotV2.lean:23-30, :68, :80) and an XI.2 change |
| Golden `gate_v1.vectors` byte reproduction | later | the signer; not needed by the producer itself |

## 10. Effort

Estimates, not measurements. Working days.

| Work | Days |
|---|---|
| Contract text and builder (normalize, rows, conflicts, join, sort, pin, fragment, sidecar, set-aside) | 1.5-2.5 |
| Synthetic fixture source and unit tests 8.1 | 1-1.5 |
| Vector and header assembly for 8.2 (re-keyed feeds, keyed lines, hand-written outcomes) | 0.5-1 |
| Cross-check 8.2 against the checker | 0.5 |
| Wiring the tests into scripts/validate_localbce.sh and the separate exe step | 0.25-0.5 |
| **Subtotal, can start now** | **3.75-6** |
| Exe cross-check: guarded Lean build of `gate_rules` plus freshness check | a separate gated step; its build wall time is not measured here and is recorded when run |
| Encoder and frame wiring for the producer side of (b) | 0.5-1, inside (b)'s own estimate (TRUNK_STEP3_G2_DESIGN.md:408-409) |
| 834 aid and level extension, with span-feed parity | unknown until open questions 1-3 are answered |
| 270/271 reader and inquiry path | unknown; a new reader |

## 11. Risks

- **False eligibility fails open** (gap 2). The design keeps every other failure closed, but this one is only as good as the source, the join and the clock.
- **HOLD load from set-aside members.** Certain HOLDs are not bypassable (Rules/Spec.lean:178-180), and they say "not eligible" when the cause is a data fault. The threshold (decision 9) caps this; the stricter conflict rule (decision 7) adds to it.
- **Two encoders drift.** The builder and gate_rules_data.py could diverge. Mitigation: `gate_rules_data.row` reused, and the equality tests of 8.1.
- **Route change.** If rr-core takes the feeds into its own v2, the row layout and member width change (TRUNK_STEP3_G2_DESIGN.md:446). The builder is route-independent; only the encoder and its `fits` move.
- **Fixture leaks into production.** A synthetic snapshot sent on a real frame would ALLOW on invented data if keyed under the production secret. Decision 3 makes the fixture source accept only a public test secret, so leaked rows match no production member key and fail closed as HOLD.
- **Secret handling.** The builder needs the tenant secret. File or environment only, never argv, never in any output, log or error (decision 15).
- **PHI.** Set-aside records and errors carry keyed member numbers and origins only (section 4.5, 5).
- **Placeholder age.** 7 days is a placeholder (decision 7 of the G2 design). Tightening it later changes which snapshots are usable, not the builder.

## 12. Decisions for the owner

Each has a one-word default.

1. **Build the builder now.** Author the route-independent builder, fixture source and tests now, before (b). Default: **now**.
2. **Placement.** `scripts/elig_snapshot.py` and `scripts/tests/test_elig_snapshot.py`, outside `rightrail/`, run by scripts/validate_localbce.sh:32; a `rightrail/app/` module only with a real source and a separate approval. Default: **outside**.
3. **Fixture source is test-only.** It accepts only a hard-coded public test secret and refuses any other, so a leaked fixture matches no production member. Default: **public-test-secret**.
4. **Output format.** A runner-grammar fragment (`snap elig` plus rows) to splice into vector files, plus a sidecar JSON with header and set-aside records (keyed members, closed causes). Default: **fragment-plus-sidecar**.
5. **Completeness.** Emit a snapshot only from one source whose content shows a full roster; anything else, 271 sets included, gives no snapshot. A batch-scoped class for 271 is a later option. Default: **full-only**.
6. **Member faults.** Any fault sets every row of the member aside (it is HELD) and is reported; exact duplicates are dropped; over 1,024 rows after dedupe is a fault. Rejected: dropping the whole snapshot on any single member fault (every line to review), and dropping only the faulty row (an open-ended row could ALLOW). Default: **set-aside**.
7. **Conflict rule.** Any inclusive overlap of non-identical rows for one member sets it aside, whatever the aid or level; touching rows are kept. Stricter than the Spec's `any`; owner to confirm. Default: **overlap**.
8. **asOf.** The single source's own date, named in the sidecar, never re-stamped; a date after host today gives no snapshot; stale sources are emitted as is so the reviewer sees `_UNVERIFIED` facts. Default: **source-date**.
9. **Set-aside threshold.** No snapshot when set-aside members exceed 5% of the source's members (placeholder), so a noisy source gives review, not mass HOLD. Default: **5-percent**.
10. **Where aid code and level come from for the 834.** Do not build until the owner names the segment or the mapping (open questions 1-2). Any 834 rows inherit the span feed's windows and causes. Default: **wait**.
11. **First real source.** None chosen in this design: 834 extension or an MMIS extract (271 excluded by decision 5). Default: **defer**.
12. **One encoder.** Rows through `gate_rules_data.row("elig", ...)`, head written as gate_rules_data.py:41-43, cross-checked against `ref.pin_bytes`. Default: **shared**.
13. **Frame-limit pre-check.** The encoder supplies `fits(row)`; the test tool passes Route A's; a misfit sets the member aside, so (b) never sends state 2 for an honest snapshot. Skipped on `pin_rows`. Default: **fits-callback**.
14. **Producer contract home.** Write the contract into this document now, and into rightrail/conformance only when the module moves into `rightrail/` (XI.7, CONSTITUTION.md:216-217). Default: **here-first**.
15. **Secret delivery.** Tests: a fixed synthetic constant in-process. CLI: a file path or environment variable, never argv. The secret appears in no output. Production holder stays open question 6. Default: **file-or-env**.
16. **localBCE claim fixtures.** Fixtures are hand-written with CCYYMMDD dates now; converting claim_input.json (and mapping its period numbers) waits for the Step 7 converter. Default: **defer**.
17. **No kind 7 before (b).** No caller adds the elig feed to `request_frame` until (b) verifies its pin; the six-feed caller refuses kind 7 before then. Default: **refuse**. Clarified 2026-11-21 (owner approved the D4 recommendation): this covers production callers. Test frames may carry a state-1 elig feed before (b), as TRUNK_STEP2_FRAME_DESIGN.md decision 21 (amended) and its signer-free check require; the elig re-key this design placed in (b) moves to step 2.

## 13. Open questions

1. Which 834 segment or qualifier carries the aid code for the target state, and is it reliably sent? The trunk reader reads none (right_rail_x12_834.py:24-51, :164-165).
2. If not in the 834, is there an approved plan-or-coverage-line to aid-code table? None exists in the tree.
3. Which 834 content shows a full roster and not a change file (for example a BGN element), and does the reader check SE01/GE01/IEA01 counts? The reader does not expose either (right_rail_x12_834.py:19).
4. What does a 271 carry for aid code and benefit level, and what does "benefit level exists" map to in it? No reader exists to check against.
5. How do localBCE's eligibility period numbers (rust-engine/claim_input.json:49-51, a G3 fact) map to CCYYMMDD dates, if the Step 7 converter borrows them for elig rows?
6. In production, who holds the tenant secret on the host, and how does the producer get it without a second copy? Both `requests_of` (right_rail_gate_ffs.py:43, used at :75) and `feeds` (:98) take it as a parameter.
7. Publish cadence: daily (to stay inside the 24-hour localBCE TTL) or at least weekly (to stay inside the 7-day placeholder)?
8. Should a later signed path attest eligibility (SnapshotV2 `Scope.ELIG = 3` exists, SnapshotV2.lean:15-21; `Kind` stops at 4, :23-30)? That is rr-core's call.
9. Is the 5% set-aside threshold the right placeholder, and should it count members or lines?
