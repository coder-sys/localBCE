# G2 as a rule-set v2 source and pack: design

Status: **approved by the owner on 2026-11-26 with changes (section 7). The CI-checkable part is built and not yet
committed (section 5). Nothing here runs in a gate.** Written 2026-11-25 against `codex/rightrail-trunk-e5d0f36b` at
`9ff13104` (`rightrail/` is trunk `e5d0f36b` plus the maintainer's axiom-pin fix). Synthetic, not legally verified,
nonpayment. This replaces `TRUNK_STEP3_G2_DESIGN.md` (G2 as fixed Lean, superseded by the maintainer's answers 4 and 5,
`HANDOFF.md` section 5).

**This pack is partial G2.** It has the program eligibility test and no benefit level test, because the eligibility
fact carries no benefit level. Reasons 24 and 25 stay unused until it does (open gap, section 6).

Read for this design: `rightrail/conformance/RULESET_V2.md` and `RULESET_V1.md`; `ruleset_v2_ref.py`;
`lean/BlindLedger/Gate/RuleSet/Spec.lean` (`ElRead`, `elRead`, `Env.fresh`, `Env.elig`, `aidClass`, `elGuard`,
`dataFires`, `noSource`, `runnable`, `pack2Conds`, `elCases`); `app/right_rail_ruleset_codec.py`;
`tests/test_ruleset_v2.py`; `conformance/ELIG_EXTRACT_V1.md`; `Engine3/HLinks.lean` (`tailsOf`); and, from `bbd0e947`,
`GATE_RULES_V2.md` section 5 and `Rules/G2Mutants.lean`.

## 1. What localBCE's G2 is today

`rust-engine/src/main.rs` `denial_reason()`, in order:

| Test | Denial |
|---|---|
| `eligibility_active != 1` | `G1_IDENTITY_VERIFICATION_FAILED` |
| `aid_code` not one of 13, 23, 53, 103, 104 | `G2_PROGRAM_ELIGIBILITY_FAILED` |
| `benefit_level_exists != 1` | `G2_BENEFIT_LEVEL_MISSING` |

Correction (2026-11-26): the first draft of this design listed the `eligibility_active` test under G2. The Rust engine
returns the G1 denial for it. G2 itself is the aid code test and the benefit level test. The pack's status test
(section 3) is therefore the counterpart of the `eligibility_active` flag, not of a G2 denial.

## 2. What a rule-set v2 pack can read

A v2 record adds source 7, the member's eligibility read, to the version 1 rule set. Per line the gate gives:

- `ans`: 0 present, 1 absent, 2 unknown, 3 conflict (the fact store's belief about the member on the line's date).
- `status`, when present: 1 eligible, 2 not eligible, 3 pending, 4 presumptive.
- `aids`: the aid codes of the facts the answer cites, each classed by the record's aid table as 1 (listed eligible),
  2 (listed not eligible) or 3 (not listed, or malformed).
- `asof`: the oldest as-of among the cited facts.

The eligibility fact carries status, basis, program, aid code and two dates. It has **no benefit level** and there is
no share-of-cost fact.

Three things are fixed in the gate and no pack can change them:

1. **Only a fresh read can hold.** Fresh means: answer present, as-of not after the batch date, and the service date at
   most the record's maximum age (1 to 10 days) after the as-of. On any other read (stale, absent, unknown, conflict) a
   `PROGRAM_NOT_ELIGIBLE` rule does not fire and the line goes to review as `PROGRAM_NOT_ELIGIBLE_UNVERIFIED`.
2. **Reasons 24 and 25 (benefit level) are refused at admission** (`NOSOURCE`), because no fact backs them.
3. **Outcome classes:** 26 holds; 27 and 28 send the line to review.

## 3. The pack

Reasons used: `PROGRAM_NOT_ELIGIBLE` (26), `PROGRAM_NOT_ELIGIBLE_UNVERIFIED` (27), `STALE_ELIGIBILITY` (28). Not used:
24 and 25 (blocked, section 6) and `MEMBER_NOT_ENROLLED` (9), which trunk's test pack uses for a "not eligible" status
but which belongs to the enrollment feed's rule in pack 1 (one rule per reason).

Ages: source 7 at **7 days, a placeholder that is not legally verified.** localBCE's own eligibility time to live is 24
hours, which would be 1. Aid table, all class 1: `103`, `104`, `13`, `23`, `53` (ascending by bytes), the list in the
Rust engine's `denial_reason()`; a test compares the two.

| Bit | Condition | Cost | Meaning |
|---|---|---|---|
| 26 | `AND[FRESH 7, DATE_OK, OR[ELIG 2 2, NOT ELIG 3 1]]` | 9 | Fresh read, and the status is "not eligible" or no cited aid code is on the list |
| 27 | `OR[NOT PRESENT 7, ELIG 1 12, ELIG 2 4]` | 7 | No as-of, an unknown or conflicting answer, or a pending status |
| 28 | `AND[PRESENT 7, NOT FRESH 7]` | 4 | There is an as-of but the read is not fresh |

Total cost 20 (limit 1,024). No `FLOW` node: the rules apply to every flow, as trunk's test pack does.

Policy choices that are **unverified**: a presumptive status is allowed; a pending status goes to review. localBCE has
only a yes/no flag, so both are new choices with no localBCE rule behind them.

What it decides (service date 20270310, batch date 20270315, as-of 20270308 unless said; the full table of 43 cases is
`rules/rightrail_packs/g2_elig_v2.expected.json`):

| Read | Reasons | Outcome |
|---|---|---|
| Eligible, aid `13`, `23`, `53`, `103` or `104`, fresh | none | allow |
| Aid `999` (well formed, not on the list), fresh | 26 | hold |
| Two rows, `13` and `999`, fresh | none | allow |
| Status not eligible, fresh | 26 | hold |
| Status pending, fresh | 27 | review |
| Status pending, aid `999`, fresh | 26, 27 | hold |
| Status presumptive, fresh | none | allow |
| Malformed aid code (`a/b`, empty, or a bad length byte), fresh | 26 | hold |
| Present answer citing no aid code, fresh | 26 | hold |
| Absent, unknown or conflict | 27 | review |
| As-of 7 days before the service date | none | allow |
| As-of 8 days before the service date | 27, 28 | review |
| Stale, aid not on the list | 27, 28 | review |
| As-of after the service date, not after the batch date | none | allow |
| As-of after the batch date | 27, 28 | review |
| Service date not a calendar date | 28 | review |

A present answer citing no aid code does not come out of the read from facts as the reference builds it: a present
answer cites at least one row and every row has an aid code.

### Forced differences (accepted by the owner, D8 and D1)

The pack cannot match localBCE's G2, or the rule the owner asked for, in four places:

1. **No eligibility fact for the member is a review, not a denial.** localBCE denies; `bbd0e947` held. The gate's fixed
   guard does not let an absent answer hold.
2. **A stale read gives 27 and 28**, not 28 alone as in `bbd0e947`: the guard adds 27 whenever a hold rule could not
   act.
3. **Benefit level is not tested at all** (open gap, section 6).
4. **A malformed aid code holds; it cannot be sent to review while an unlisted code holds.** The owner's rule (D1) is:
   hold only on a well-formed code that is not on the list, and send a malformed code to review (27), because a hold
   should rest only on usable data. The language cannot say that. The aid table gives a code class 1 or 2 only when it
   is listed; a well-formed unlisted code and a malformed one both get class 3 (`aidClass` in `Spec.lean`,
   `aid_class` in the reference), and no node tells them apart. The two choices a pack has are: hold on class 3 (this
   pack: unlisted and malformed both hold) or review on class 3 (trunk's test pack: unlisted and malformed both go to
   review). Listing every unlisted code as class 2 is not possible. A malformed code can reach the gate: the extract's
   text type allows any printable character (for example `/`), which is not a well-formed aid code. Changing the choice
   is a one-node change: move the aid test from rule 26 to rule 27. The owner decided on 2026-11-26 to keep the hold.
   This matches the Rust rule, which denies any aid code that is not on the list.

Other differences, not forced by anything the owner decided against:

- **Freshness is measured from the as-of to the service date**, not from the snapshot's as-of to today.
- **Rows that disagree on status are a conflict (review).** `bbd0e947` took any covering row with an allowed aid code.
- **Covered dates** (localBCE's G3, `eligibility_period_from/thru`) are the fact's valid dates, applied by the gate's
  belief before the pack sees anything. The pack has no node for them.

## 4. Source and files

All outside `rightrail/`, so no protected change and no XI.2 record:

| File | What |
|---|---|
| `rules/rightrail_packs/g2_elig_v2.source.json` | The source: header fields, synthetic citation, the maximum age, the aid list, the three rules as nested lists, a copy of pack 1, and the `synthetic`, `not_legally_verified` and `nonpayment` markers |
| `scripts/build_g2_ruleset_pack.py` | Encodes the source with trunk's codec (`rightrail/app/right_rail_ruleset_codec.py`) and prints each record's cost and body digest; `--check` compares with the pins. It writes nothing |
| `rules/rightrail_packs/g2_elig_v2.expected.json` | The pins: both records' digests and costs, the case table, the blocked `bbd0e947` cases |
| `scripts/tests/test_g2_ruleset_pack.py` | The checks in section 5 |

Two records come from the one source (D5): an **eligibility-only** record like trunk's test pack, for the case table
(3 rules, cost 20); and a **full** record, pack 1's thirteen rules and four ages plus these three rules and source 7
(16 rules, 5 ages, cost 102), because a shard runs under exactly one rule set and an eligibility-only record would drop
today's fact rules. The records carry placeholder bytes where signatures go: they are not signed.

## 5. What is checked

| Check | Needs | In CI | State |
|---|---|---|---|
| Both records encode, decode and re-encode to the same bytes; cost and digest pinned | Python only | yes | built |
| Each of the 43 cases fires its expected reasons on `ruleset_v2_ref.fired`, with its outcome | Python only | yes | built |
| The full record gives each line the eligibility-only record's reasons plus what pack 1 alone fires, on every flow | Python only | yes | built |
| The copy of pack 1 equals trunk's (`rightrail/tests/test_ruleset_v1_codec.py`); the aid list equals the Rust engine's | Python only | yes | built |
| A record with a rule for 24 or 25 is well formed but not admissible | Python only | yes | built |
| Mutants: each of 28 one-node changes to the pack fails a named case | Python only | yes | built |
| The same cases through Lean's `dataFires` (`ruleset_admit` EVAL lines) agree with the reference | `ruleset_admit.exe` (built locally by `lake build`; CI does not build Lean) | no | not built |
| A signed copy is admitted (`ADMIT`), and a copy with a rule for 24 is refused `NOSOURCE` | `ruleset_admit.exe` and the signer at `C:\work\rightrail`, with throwaway keys (D7) | no | not built |

Every row marked built checks the pack's logic against trunk's Python reference. None of them is a gate running the
pack (section 6).

The case table carries over what still applies from `bbd0e947`'s contexts:

| `bbd0e947` case | Here |
|---|---|
| `cOk` (allowed aid) | `eligible_13`: allow |
| `cNE` (aid 999) | `unlisted_999`: 26 |
| `cNEu` (unusable snapshot, not eligible) | `stale_unlisted`: 27 and 28 |
| `c7`, `c8` (age boundary) | `age_7_days`, `age_8_days` |
| no snapshot | `absent`: 27 |
| `cBL`, `cPair`, `cLvl2`, `cBLu` (benefit level) | blocked; listed in the expected file as `blocked: benefit level`, not run |
| `cStart`, `cStop` (inclusive bounds), `cRev` (start after stop), "any member" | not the pack's: they belong to the fact store's belief and the extract reader (`span_backwards`), on the RightRail side |

Mutants (each caught by a named case): rule 26 without `DATE_OK`, with status "eligible" for "not eligible", without
its status test, without its aid test, with the aid test not negated, and removed; aid `999` added; each of the five
codes removed, and each made class 2; age 6 and age 8; rule 27 removed, without pending, with presumptive added, with
only "unknown", with only "conflict", and without its no-as-of test; rule 28 removed, asking `FRESH` for `PRESENT`, and
without `PRESENT`.

Two things the mutants showed, both because the gate's guard already does part of the pack's work:

- **`FRESH 7` in rule 26 changes no result.** Removing it gives the same reasons on every case and on a grid of 2,016
  reads. The gate fires a `PROGRAM_NOT_ELIGIBLE` rule only on a fresh read whatever the rule asks. It is kept, as in
  trunk's test pack, so the rule reads as what it does; the test records it as an equivalent mutant.
- **Rule 27's "unknown or conflicting answer" test matters only for a read the fact store does not produce**: an
  unknown or conflicting answer that still has an as-of, on a line no hold rule could act on. On every other read the
  no-as-of test or the guard already gives 27. It is kept as a second line of defence; two cases cover it.

The mutant of `bbd0e947` "program on an unusable snapshot" cannot be written in a pack: the gate's guard is what stops
it, and trunk proves that (`elig_guard_hold`).

Not done yet: the parity harness (`g_rule_parity.py`) mapping `G2_PROGRAM_ELIGIBILITY_FAILED` to bit 26 and reporting
`G2_BENEFIT_LEVEL_MISSING` as not compared, and regenerating `G_RULE_PARITY_REPORT` (plan step M4).

## 6. Blocked on the RightRail side

| Item | Effect | Whose call |
|---|---|---|
| The engine does not carry `elRead` | `runnable` is false for every v2 record, so no gate executable runs this pack: a frame presenting it is held. Everything in section 5 is a check of the pack's logic, not of a running gate | Who builds it has not been asked of the founder |
| **Open gap: no benefit level in the eligibility fact** | Reasons 24 and 25 are refused at admission and stay unused. `G2_BENEFIT_LEVEL_MISSING` has no counterpart, so this pack is partial G2 | Founder |
| No way to tell a malformed aid code from an unlisted one | Forced difference 4 (section 3) | Maintainer (a change to the rule-set language) |
| The fact-store side of the read (inclusive dates, the member key, which sources count) | Checked only by trunk's own `elCases`; adding localBCE cases there is a change inside `rightrail/` | Maintainer, as a pull request |
| Links-file reasons field | See below | Founder (protected wire change) |

**Links file: a point to confirm with the maintainer.** His answer says a reason at 24 to 28 cannot reach the links
file until its 4-byte reasons field widens. As I read `Engine3/HLinks.lean`, `tailsOf` refuses a record only when its
mask is 2^32 or more, so bits 24 to 28 (and share of cost at 29 to 31) fit in the four bytes; bits 32 and up do not.
I read only that function and its `#guard` checks, so another limit may exist elsewhere. Either way the widening stays a
draft needing the founder's approval, and this pack does not depend on it for the checks in section 5.

## 7. Decisions (owner, 2026-11-26)

| # | Decision | Decided |
|---|---|---|
| D1 | An aid code not on the list | Hold only when the code is well formed and not on the list; a malformed code should go to review. **The language cannot express this**, so the pack holds on both and it is recorded as forced difference 4. Confirmed by the owner: keep the hold, which matches the Rust rule (it denies any code not on the list) |
| D2 | Statuses | Not eligible holds; pending goes to review; presumptive is allowed. Pending and presumptive are unverified policy choices |
| D3 | Maximum age of the eligibility read | 7 days, a placeholder that is not legally verified. localBCE's own rule is 24 hours |
| D4 | "Not eligible" status | Fires 26, not `MEMBER_NOT_ENROLLED` (9) |
| D5 | Which records to build | Both, from one source |
| D6 | Where it lives | localBCE, outside `rightrail/` |
| D7 | Signed admission check | Use the signer already built at `C:\work\rightrail`, with throwaway keys. Not built yet |
| D8 | Forced differences | Accepted. The missing benefit level test is an open gap: the pack is partial G2 until the fact carries a benefit level, and reasons 24 and 25 stay unused |
| D9 | Questions for the maintainer | Send all three: the links-file reading, who builds the engine's `elRead`, whether a benefit level field is planned |
