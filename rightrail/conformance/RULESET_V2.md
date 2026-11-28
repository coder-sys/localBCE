# Signed rule set `RR/GATE/RULESET/v2`

Draft wire format. Version 2 is version 1 ([RULESET_V1.md](RULESET_V1.md)) plus one source, the member's eligibility
facts, an aid-code table, and one condition node that reads them. Version 1 is still read, unchanged byte for byte: its
records, digests and signed messages stay valid, and no version 1 record may use anything this file adds. Built: the
Python twin codec, the Lean model with golden digests, the reference evaluator `conformance/ruleset_v2_ref.py` checked
against Lean through `ruleset_admit` (§7). Not built: no gate executable runs a version 2 record (`runnable` is false
for it), and the eligibility read (`elRead`, §5) is not yet carried by the engine. Normative model `lean/BlindLedger/Gate/RuleSet/Spec.lean`;
where this text and the model differ, the model decides. Synthetic, nonpayment, `activation=false`.

## 1. Record

The fields are version 1's (§1 there) with these changes:

| Field | Width | Rule |
|---|---|---|
| `tag` | 19 | `RR/GATE/RULESET/v2` then one zero byte |
| `nAges` | u8 | 1 to 5 |
| age | `nAges × (src u8 ‖ maxAge u16)` | as version 1, and source 7 (eligibility) is allowed |
| `nAids` | u16 | 0 to 1,024, right after the ages |
| aid | `nAids × (code ident ‖ class u8)` | `code` at most 20 bytes, strictly ascending by bytes; `class` 1 listed eligible, 2 listed not eligible |
| rule | as version 1 | `reason` may also be one of the five eligibility reasons (§4) |

- `digest = SHA3-512(body)` as in version 1. A version 1 body and a version 2 body differ in their tag, so they never
  share a digest.
- The signed message is `SHA3-512("RR/GATE/RULESET/v2/SIG" 0 ‖ body)`. A version 2 body signed under the version 1
  signature tag is not signed.

## 2. The eligibility node

| Code | Node | Operands | Cost |
|---|---|---|---|
| `22` | ELIG | `q u8 ‖ a u8`: `q = 1` answer mask (`a` 1 to 15), `q = 2` status mask (`a` 1 to 15), `q = 3` aid class (`a` 1 to 3) | 2 |

PRESENT and FRESH (`20`, `21`) take source 7 as well. A record may use ELIG, PRESENT 7 or FRESH 7 only when its age
table lists source 7, as for every other source. Any other `q` or `a` is refused.

## 3. Ceilings

Source 7's maximum age is 1 to 10 days. The other ceilings and the enrollment guard are version 1's.

## 4. What a rule set may decide

A version 2 rule may name the thirteen fact reasons of version 1 and these five (bit in brackets):
`BENEFIT_LEVEL_MISSING` (24), `BENEFIT_LEVEL_MISSING_UNVERIFIED` (25), `PROGRAM_NOT_ELIGIBLE` (26, hold),
`PROGRAM_NOT_ELIGIBLE_UNVERIFIED` (27, review), `STALE_ELIGIBILITY` (28, review). A version 1 rule may not, and a
version 1 record fires none of them whatever the read (`dataFires_v1`). Outcome classes stay fixed in the gate:
`PROGRAM_NOT_ELIGIBLE` is a hold, the other two send the line to review, and a signed staff override may clear any of
the three (`elig_reason_class`).

No fact field carries a benefit level yet, so a record with a rule for 24 or 25 decodes but is refused at admission
as `NOSOURCE`, before any other admission check (`admitW_backed`).

## 5. Evaluation

Each line comes with its eligibility read: `ans` (0 present, 1 absent, 2 unknown, 3 conflict, from
`FactBelief.belief` on kind 1), `status` (the newest statement's status when present: 1 eligible, 2 not eligible,
3 pending, 4 presumptive; else 0), `aids` (the 21-byte aid-code blocks of the cited statements) and `asof` (the oldest
receipt as-of among the facts the answer cites, so a newer fact it does not rest on never makes it fresh; none when it
cites none, as an absent, unknown or conflicting answer does, or when a cited fact's receipt is not known). The model
builds it with `elRead`.

- PRESENT 7: `asof` is some date.
- FRESH 7: `ans = 0`; `asof`, the line's date and the batch's own date are calendar dates, `asof` is not after the
  batch's date, and the line's date is at most the maximum age after `asof`. An as-of after the line's date is fresh;
  one after the batch's date is not. An absent, unknown or conflicting answer is never fresh.
- ELIG 1 a: bit `ans` of `a` is set.
- ELIG 2 a: `ans = 0`, `status ≥ 1` and bit `status - 1` of `a` is set.
- ELIG 3 a: `ans = 0` and some cited block has class `a`. A block's class is the table's class for its code when the
  block is a length byte `n ≤ 20`, then the code, then zero bytes to 21 bytes, and the code is an `ident`; it is 3 when
  the code is not in the table or the block is not of that form.

The eligibility guard is fixed in the gate, as the enrollment guard is (`elGuard`). A condition is evaluated in three
values (`eval3`) with every PRESENT 7, FRESH 7 and ELIG node unknown and every other node its value, AND false when an
operand is false and else unknown when one is unknown, OR true when an operand is true and else unknown when one is
unknown, NOT swapping true and false. A condition true or false in three values has that value whatever the read
(`eval3_sound`, `evalAt_read`). The guard covers every `PROGRAM_NOT_ELIGIBLE` rule, and every rule for another hold
reason whose condition reads source 7 and is not true in three values, so whose value depends on the read. Such a rule
holds a line only when FRESH 7 holds. On any other read (stale, with no as-of, absent, unknown or in conflict) no such
rule fires its reason, and the line goes to review as `PROGRAM_NOT_ELIGIBLE_UNVERIFIED` when such a rule could hold it
under some read: its condition is not false in three values. So a rule cannot screen out a read it may not act on; a
rule whose other nodes rule the line out (another flow, a date that is not a calendar date) leaves it alone; and a rule
for another hold reason whose other nodes already hold the line (a fresh enrollment feed with no span of the member)
holds it on any read. This holds under every rule set (`elig_guard_hold`, `elig_guard_review`, `elig_guard_narrow`).

The guard is about the read's freshness and presence only. Which aid codes and statuses hold a line or send it to
review, an aid code missing from the table or a pending status among them, is the rule set's own content, in its rules
for bits 26 and 27. The test pack's rule for bit 27 sends an unlisted or malformed aid code to review (§6); it does not
test the status, so a rule set that wants a pending status reviewed adds `ELIG 2 4` to that rule.

`elRead` is checked on a small fact corpus (a fresh fact, a stale one, no fact and so no as-of, a conflicting pair, an
agreeing pair, an unknown code, and a stale fact beside a newer one from a weaker source the answer does not cite)
against `el_read` in `conformance/ruleset_v2_ref.py`, together with the reasons the test pack fires on each read
(`elGolden`).

## 6. Test pack

The test pack is a state's eligibility rules as the product reads them, as data. Header and citations as pack 1; ages
`07 0004`; aid table `A1` 1, `A2` 1, `R7` 2. Rules, all citing 0:

| Bit | Condition |
|---|---|
| 9 | `AND[FRESH 7, DATE_OK, ELIG 2 2]` |
| 26 | `AND[FRESH 7, DATE_OK, ELIG 3 2]` |
| 27 | `OR[NOT PRESENT 7, ELIG 1 12, ELIG 3 3, AND[NOT FRESH 7, ELIG 3 2]]` |
| 28 | `AND[PRESENT 7, NOT FRESH 7]` |

An absent answer is never fresh, so no rule of the pack reads one: the guard sends it to review. Total cost 26.
Proved on it: a listed not-eligible code holds only on a fresh present answer and a valid date
(`pack2_pne`); an unlisted or malformed code on a present answer goes to review (`pack2_unlisted`); with an as-of on a
present answer, `STALE_ELIGIBILITY` fires exactly when the as-of plus 4 days is before the service date, the as-of is after the
batch's date, or a date is not a calendar date (`pack2_stale`); with no as-of the line goes to review and neither `STALE_ELIGIBILITY` nor `PROGRAM_NOT_ELIGIBLE`
fires (`pack2_no_asof`). The last two are instances of the fixed guard (§5).

## 7. Codec, golden records and the EVAL frame

- `app/right_rail_ruleset_codec.py` reads and writes both versions; a version 2 record is a dict with `"format": 2`
  and `"aids"`. `tests/test_ruleset_v2.py` checks it with must-reject cases, round trips, every proper prefix, and the
  model's golden digests (`golden2`): the test pack record (9,716 bytes) and one at every version 2 bound (103,422
  bytes; five ages at their ceilings, 1,024 aid codes of 20 bytes, version 1's other edges).
- `ruleset_admit` (unpinned, test only) takes an optional tail after its questions:
  `u16 e · (record u16 · date u32 · batch date u32 · flow u8 1-3 · answer u8 0-3 · status u8 · as-of u32 (0 none) ·
  n u8 ≤ 8 · (21-byte aid block)^n)^e`, and answers each with `EVAL i mask` (the reason bits the gate's `dataFires`
  gives in the empty context of that batch date: no reference snapshot, so sources 1 to 4 read as absent and
  `STALE_ENROLLMENT` always fires) or `EVAL i NONE` when record `i` does not decode.
  The tests compare it with `conformance/ruleset_v2_ref.py` on the test pack and on generated records and reads.
