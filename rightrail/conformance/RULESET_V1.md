# Signed rule set `RR/GATE/RULESET/v1`

Draft wire format. Built: the Python twin codec (§7) and golden digests, and Lean admission and selection run by the
unpinned `ruleset_admit` test frame (§8), and the gate's step with its proof (§9). Not built: no gate executable calls
the step yet, so the gate does not carry or run a rule set. Normative model `lean/BlindLedger/Gate/RuleSet/Spec.lean`
(`decode`, `encode`, `eval`, `cost`, `admit`, `select`); where this text and the model differ, the model decides.
Design and build order: `docs/STATE_EVIDENCE_ARCHITECTURE.md` §6.3. Synthetic, nonpayment, `activation=false`.

A rule set is the state's signed statement of which fact rules the gate applies to lines dated in a range. It carries
data only; the interpreter that runs it is Lean, fixed and proved.

## 1. Record

`record = body ‖ sigs`, at most 131,072 bytes in all (checked before any field is read). All integers are unsigned
big-endian. `ident` is a u16 length then the bytes, matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. A date is
`CCYYMMDD` as a u32 and must be a calendar date (years 0001-9999). `99991231` is the open end of a range.

| Field | Width | Rule |
|---|---|---|
| `tag` | 19 | `RR/GATE/RULESET/v1` then one zero byte |
| `state` | 64 | the state's identifier digest, as in KEYSET/v2 |
| `tenant` | ident | the tenant the rules govern |
| `version` | u32 | at least 1 |
| `prev` | 64 | the `digest` of version `version - 1`; all zero exactly when `version = 1` |
| `notBefore`, `notAfter` | u32 each | the signing window: both dates, `notBefore ≤ notAfter`, at most 31 days apart (APPROVAL/v2 `spanOk`) |
| `effFrom`, `effTo` | u32 each | the effective range over the line's date: both dates, `effFrom ≤ effTo` |
| `nEnds` | u8 | 0 to 8 |
| end | `nEnds × (version u32 ‖ to u32)` | an earlier version's range now ends on `to`; `to = 0` withdraws it for every date, else `to` is a date. Versions at least 1, strictly ascending, each below this record's `version` |
| `nCites` | u8 | 1 to 32 |
| cite | `nCites × (kind u8 ‖ ref ident ‖ date u32 ‖ doc 64)` | the legal sources: kind 1 statute, 2 regulation, 3 state plan amendment, 4 waiver or demonstration, 5 contract, 6 state policy, 7 court order; `date` a date; `doc` the SHA3-512 of the document, not all zero |
| `nAges` | u8 | 1 to 4 |
| age | `nAges × (src u8 ‖ maxAge u16)` | sources strictly ascending; `maxAge` from 1 to the source's ceiling (§3) |
| `nRules` | u8 | 1 to 64 |
| rule | `nRules × (reason u8 ‖ cite u8 ‖ expr)` | `reason` is the reason's fixed mask bit (`Reason.idx`) and must be a fact reason (§4); strictly ascending, so one rule per reason; `cite < nCites` |
| `sigs` | KEYSET/v2 signature block | `u8 m ‖ (keyId 64 ‖ sig 4627)^m`, `1 ≤ m ≤ 16`, key ids strictly ascending, nothing after |

After the rules, the total cost of all conditions (§2) must be at most 1,024 units. A record is canonical: every
accepted byte string re-encodes to itself.

- `digest = SHA3-512(body)`. It is the rule set's identity: the next version's `prev`, the payment token leaf's
  `ruleVersion`, and what a decision record cites.
- The signed message is `SHA3-512("RR/GATE/RULESET/v1/SIG" 0 ‖ body)`.

## 2. Conditions

A condition is a prefix-coded tree. Its root sits at depth 1 and no node may be deeper than 8.

| Code | Node | Operands | Cost |
|---|---|---|---|
| `01` | AND | `n u8` (2 to 8), then n conditions | 1 + operands |
| `02` | OR | `n u8` (2 to 8), then n conditions | 1 + operands |
| `03` | NOT | one condition | 1 + operand |
| `10` | FLOW | `mask u8` (1 to 7): bit 0 FFS cycle, bit 1 FFS claim, bit 2 capitation | 1 |
| `11` | DATE_OK | none: the line's date is a calendar date | 1 |
| `20` | PRESENT | `src u8`: the source's snapshot was read | 1 |
| `21` | FRESH | `src u8`: the snapshot is usable at the rule set's maximum age for it | 1 |
| `30` | HIT | `src u8 ‖ subject u8 ‖ test u8` | 2 for subject 1, 3 for subject 2 |
| `31` | OVERLAP | `src u8`, enrollment only: two plans share a day of the line's month | 2 |

- Sources: 1 member deaths, 2 provider deaths, 3 exclusions, 4 enrollment (the SNAPSHOT/v2 kind bytes). A condition
  may read only a source the record's age table lists.
- Subject: 1 the line's member, 2 the line's payee or rendering party. Test: 1 a row dated before the line's date,
  2 a row whose interval holds the line's date, 3 the same with the row's plan equal to the line's payee.
- HIT allows only: deaths/member/before, provider deaths/party/before, exclusions/party/within,
  enrollment/member/within, enrollment/member/within-plan.
- Any other code, count, source, subject or test is refused.

The interpreter is a structural recursion over this tree, so it always ends. The cost is a function of the bytes alone;
running a condition never spends more than its cost (`evalC_le`).

## 3. Ceilings

Every maximum age is at least 1 day and at most its ceiling (`Src.ceil`): deaths 90 days, provider deaths 90,
exclusions 31 (the law's, `Scoped.lean`), enrollment 10 (the product's). A record with an age outside these bounds does
not decode, so admission refuses it. A record that lists no enrollment age uses 4 days.

The enrollment guard is fixed in the gate, not in the record: when the enrollment feed is older than the record's
enrollment age, every line the record decides carries `STALE_ENROLLMENT` (review), and no hold reason whose condition
reads enrollment fires. A late feed sends the line to review, never to an allow (`enroll_stale_allow`). The guard adds
no hold reason: under a stale feed a line's hold reasons equal those it has with no feed (`enroll_stale_hold`). One
indirect effect: a suppressed `MEMBER_NOT_ENROLLED` drops the near-key relaxation, so a later line of the same member
and month may hold on `CAP_MEMBER_MONTH_DUPLICATE` (fail closed, as `Rules.claim`).

## 4. What a rule set may decide

A rule may name only these thirteen fact reasons (bit in brackets): `CAP_MEMBER_MONTH_DUPLICATE` (1, the plan-overlap
part only), `MEMBER_DECEASED` (7), `MEMBER_DECEASED_UNVERIFIED` (8), `MEMBER_NOT_ENROLLED` (9),
`MEMBER_NOT_ENROLLED_UNVERIFIED` (10), `PROVIDER_DECEASED` (12), `PROVIDER_DECEASED_UNVERIFIED` (13),
`PROVIDER_EXCLUDED` (14), `PROVIDER_EXCLUDED_UNVERIFIED` (15), `STALE_DMF` (18), `STALE_ENROLLMENT` (19),
`STALE_EXCLUSION` (20), `STALE_PROVIDER_DEATH` (21). Every other reason, each reason's outcome class (hold or review),
which reasons a bypass may override, and the enrollment guard (section 3) stay fixed in the gate.

## 5. Pack 1

Pack 1 is today's rules (GATE_RULES_V1) as data. Ages: `01 005A`, `02 005A`, `03 001F`, `04 0007`. Writing
`cert(s, x)` for `AND[FRESH s, DATE_OK, x]`, `unv(s, x)` for `AND[PRESENT s, NOT FRESH s, DATE_OK, x]`, and
`enrolled` for `OR[AND[FLOW 3, HIT 4 1 2], AND[FLOW 4, HIT 4 1 3]]`:

| Bit | Condition | Cost |
|---|---|---|
| 1 | `AND[FLOW 4, FRESH 4, DATE_OK, OVERLAP 4]` | 6 |
| 7, 8 | `cert(1, HIT 1 1 1)`, `unv(1, HIT 1 1 1)` | 5, 7 |
| 9, 10 | `cert(4, NOT enrolled)`, `unv(4, NOT enrolled)` | 13, 15 |
| 12, 13 | `cert(2, HIT 2 2 1)`, `unv(2, HIT 2 2 1)` | 6, 8 |
| 14, 15 | `cert(3, HIT 3 2 2)`, `unv(3, HIT 3 2 2)` | 6, 8 |
| 18, 19, 20, 21 | `NOT FRESH 1`, `NOT FRESH 4`, `NOT FRESH 3`, `NOT FRESH 2` | 2 each |

Total cost 82. The header, legal sources and citation indexes are the state's; test records use synthetic references
only.

## 6. Admission and selection

A decoded record is admitted in batch `kb` of the shard's chain, under the shard's admitted key-set head, after the
tenant's series, only if each holds; the first that fails is the refusal:

1. `MALFORMED`: it does not decode (any rule above, the cost bound included).
2. `SCOPE`: `state` is not the head's state, or `tenant` is not the shard's tenant.
3. `EXPIRED`: the head's day is outside the signing window.
4. `CHAIN`: not the next version, `prev` not the last version's digest, or admitted in an earlier batch than it.
5. `ENDS`: an end names no admitted version still in force on some date, or does not shorten its range.
6. `OVERLAP`: after this record's ends, its range shares a date with a range still in force.
7. `UNSIGNED`: fewer than the key set's POLICY threshold `kPolicy` of distinct employees, each with a POLICY key (role 6)
   live on the head's day (unrevoked and inside its validity window), signed the message. Roster, approver and source
   keys count for nothing here; a key set with no POLICY key admits no rule set.

An exact re-send, a record whose `digest` the series already holds, is answered with its first admission before these
checks and adds nothing to the series.

POLICY keys in KEYSET/v2 (`lean/BlindLedger/Gate/Keyset.lean`). A POLICY entry has role byte 6 and the same 2,811-byte
layout as every entry, with no scopes, kinds or caps. When at least one entry, revoked or not, has role 6, one byte
`kPolicy` follows the last entry, before the signature block; a key set with no role-6 entry has no such byte, so its
bytes and digest are what they were before POLICY keys existed. The roster quorum signs a key set that adds or revokes
POLICY keys, as for any key-set change. A key set does not decode when:

- `kPolicy` is outside 2 to 8;
- one employee, or one identity-provider subject, holds both an unrevoked POLICY key and an unrevoked key of any other
  role (ROSTER, SOURCE, APPROVER or any); a revoked key of another role beside a POLICY key is allowed;
- two unrevoked POLICY keys share an employee but not a subject, or a subject but not an employee.

A key set that does not decode admits no head, so no rule set is admitted under it.

A line of decision batch `B` (known time `K = B − 1`) runs under the one admitted rule set with `kb ≤ K` whose
range, after every end admitted by `K`, holds the line's date. A line with none is not decided, and its payment is not
released.

## 7. Python twin codec (`app/right_rail_ruleset_codec.py`)

Python carries the bytes and decides nothing. Frozen tests: `tests/test_ruleset_v1_codec.py`.

- `decode(data: bytes) -> dict`, raising `RuleSetRefused` whose `detail` names the first failing part: `length`,
  `tag`, `state`, `tenant`, `version`, `prev`, `window`, `effective`, `ends`, `cites`, `ages`, `rules`, `expr`,
  `cost`, `sigs`. A record cut short is refused at the part it stops in.
- The dict: `state` (bytes), `tenant` (str), `version`, `prev` (bytes), `not_before`, `not_after`, `eff_from`,
  `eff_to`, `ends` (list of `(version, to)`), `cites` (list of `(kind, ref, date, doc)`), `ages` (list of
  `(src, max_age)`), `rules` (list of `(bit, cite, expr)`), `sigs` (list of `(key_id, sig)`). An `expr` is a tuple:
  `("and", [..])`, `("or", [..])`, `("not", e)`, `("flow", mask)`, `("date_ok",)`, `("present", src)`,
  `("fresh", src)`, `("hit", src, subject, test)`, `("overlap", src)`.
- `encode(d: dict) -> bytes`, refusing as `decode` does anything `decode` would refuse.
- `digest(data) -> bytes` and `message(data) -> bytes` of a record that decodes.
- `cost(expr) -> int`.
- The model holds `def golden :`, `("pack1", hex)` and `("edge", hex)`: the SHA3-512 of the test's pack-1 and edge
  records, which the Lean build checks by decoding and re-encoding them.

## 8. Admission frame (`ruleset_admit`, Lean, unpinned)

Stdin is one frame and stdout one line per record, then one per question. Tests: `tests/test_ruleset_admission.py`.

`pin 64 ‖ now u32 ‖ u32‖genesis key set ‖ u16 n ‖ (day u32 ‖ u32‖key set)^n ‖ tenant (u16 length, ident) ‖ u16 r ‖
(kb u32 ‖ u32‖record)^r ‖ u16 q ‖ (K u32 ‖ D u32)^q`

The key-set chain is admitted once for day `now`; each record is then admitted in order, in batch `kb`, after the
records before it. A record line is `ADMIT version kb digest`, `DUP version kb` or `REFUSED name` (§6). A question line is
`SELECT K D version digest`, or `NONE K D` when no rule set covers the date at that known time. No admitted head: the
line `RULESET_ADMIT=NOHEAD`, exit 1. A malformed frame: stderr `RULESET_ADMIT=FRAME`, exit 2.

## 9. The gate's step (Lean `gateStep`, run by the rows-file engine)

The gate's fast deciders are proved equal to today's rules, and pack 1 decides exactly as today's rules do. So the
first rule set the gate runs must be **runnable**: version 1, no ends, in force from 00010101 to 99991231, and pack 1's
ages and rules exactly. Any other record is held as `unsupported` until the fast deciders run the interpreter itself.

A batch presents its rule-set records in the request frame's authority section, after the signed bypasses
(conformance/FRAME_V1.md section 2), so they are part of the frame's identity. A shard keeps a series head and its
version in its authority record: the digest of its admitted rule set and 1, or zero and 0 for none. An authority
record with rule-set version 0 and a nonzero digest does not follow the record before it, so a store holding one is refused
on load. For each batch `B` with requests:

- **No rule set yet.** With no record, the batch runs under none. With one record, it is admitted in batch `B` as §6
  says, under the key-set head of the batch. If it is admitted and runnable, its digest becomes the head. It governs
  from batch `B + 1`, so batch `B` still runs under none.
- **A rule set held.** The frame must present the held record again: one record, which decodes, is runnable and whose
  body digest equals the head. The batch then runs under it. The head never changes once set.
- **A shard behind the tenant.** When the frame asserts a rule-set version above the shard's, the shard admits only the
  record whose digest the frame asserts. The end of its signing window is not checked, as it may have passed for good;
  the start of the window, its signatures and every other §6 check are (`admitW_notBefore`).
- After the step, the frame's asserted rule-set floor must be met: a version below it holds `RULESET_STALE`, and the
  same version under another digest holds `RULESET_FORK`.

Any other batch is held whole and writes nothing. The hold words are `RULESET_REFUSED` (a first record §6 refuses),
`RULESET_NOT_RUN` (a first record admitted but not runnable, or more than one record), `RULESET_MISSING` (no record
while the shard holds a rule set), `RULESET_OTHER` (a record that is not the held one, or on a shard behind the tenant
not the asserted one) and `HEAD` (no key-set head to admit a first record under). A frame that presents records and
no requests is refused `RECORD`. The pinned engine runs no rule set: a batch whose frame presents a record holds
`RULESET_NOT_RUN`, and it refuses to load a store whose record holds a rule set. The checker repeats the step for every
logged batch.

The host keeps the tenant's highest rule-set version and digest over all its shards, and presents the tenant's
record, the same bytes every time, with every frame once any shard holds a rule set (and the first record before,
as below). Copies of one rule set
differ only in their signatures, which the host does not check; it compares them by their signers' key ids. It
presents the copy whose signers include every other copy's, and of copies with the same signers (randomized
signatures differ byte for byte) the lowest bytes, in whatever order they were supplied. When the signers do not
nest, a shard that already holds that rule set only reloads it and checks no signature, so it is given the lowest
copy and goes on; a frame of a shard behind the tenant, which would admit the record, holds `ruleset_copies` at the
host, after any stored frame of that shard is decided (and sealed, while it can be). Other rule sets go on.

The host takes the tenant's records from the deployment's rule-set folder, one record per file, read again before
every frame. Records are placed in the folder by rename (written beside it, then moved in), so no file is read half
written. Each entry is read by itself, every time; one not taken is named and logged. An entry that is not a file, or a
record that names another tenant, is skipped. An entry that cannot be looked at, or a file that cannot be read or does
not decode as a whole record (torn, empty or junk), might be a record that changes what is decided, so every frame of the tenant holds `ruleset_file_bad`
until it is fixed or removed; nothing read earlier stands in for it, so a running host, a restarted one and a replay of
the folder answer alike. A configured folder that is not there or cannot be listed is never read as empty, which would
lift the holds its records cause: every frame of the tenant holds `ruleset_folder_missing` until it is back. With no
folder configured there are no folder records; an empty folder path, or one naming the current directory, is refused. A record that is not taken is never
presented. The first rule set is adopted so:

- While no shard of the tenant holds a rule set, every frame presents the tenant's one version-1 record, if the folder
  holds one, and each shard admits it as its first record (above) or holds the batch. Once one shard's answer holds it,
  the tenant's floors carry it, and every other shard admits it as a shard behind the tenant.
- Two version-1 records under different digests while none is held: the host does not choose, and every frame of the
  tenant holds `ruleset_choice`. Once a rule set is held, a version-1 record of another digest is never presented.
- A record of a version above the one held (and above 1): the gate runs only a runnable version 1, so every frame of
  the tenant holds `ruleset_newer` rather than decide lines under rules the state has replaced. The record does not say
  which lines it governs until it is admitted, and the gate cannot admit it.
- Both holds come before any stored frame of the shard is decided: the stored frame is kept and waits for the cause to
  be resolved. A sealed answer is still given to an exact retry.
- A stored frame (a batch whose outcome is unknown) presents the record presented when it was built. While the tenant
  holds no rule set, one that presents a first record other than the one presented now (removed from the folder, or
  replaced by another) is never sent, whatever floors it asserts (the answer carries the grant's serial, not the
  frame's), so no shard takes up a record the folder no longer gives: every frame of the shard holds `ruleset_changed`
  and the stored frame waits, kept. Rebuilding it under the current record could lose a batch the engine already
  decided. Two ways end the wait: that record put back as the only first record, which the tenant then takes up for
  good; or another shard taking up the record presented now, after which the stored frame is sent, its answer (the
  same version under another digest) is held `ruleset_fork` and its file dropped, the floors keeping the tenant's
  record, and the shard's next frame, built in the same call, presents that record. A frame stored presenting no record takes up nothing and is decided as stored.

A sealed answer is filed and
found by its requests, grant and bypasses alone, so the record a retry presents never changes what it is given. A decided answer that would fork the
tenant (the same version under another digest) is held `ruleset_fork` before it is prepared, and the host drops its
stored frame. The engine keeps the unsealed batch in its log; the pinned engine and the rows-file engine both cut it
there when the next frame's floors have passed the batch's authority record (conformance/ENGINE_V3.md section 9), and until then answers a frame of other
requests `CONFLICT`.

The transition rule: a shard with no admitted rule set decides as today, and its token leaves keep the engine release
as their rule version. A grant that names only a rule-set digest therefore refuses those leaves.

`live_pack1` is the proof that a runnable rule set changes no decision, for a batch whose every line is in the rule
set's date range. When a runnable rule set was admitted by known time `K`, and every line of a batch lies in its range,
`replayAt` leaves no line undecided and returns exactly today's decisions. A line outside the range is not covered.
`gateStep_cur` says the rule set a batch runs under is the stored head: runnable, with that digest, and never one
admitted in the same batch. `gateStep_head` says the head moves only from zero to the digest of a runnable record that
§6 admitted. `gateStep_held` says that while a head is held, a batch passes only when it presents that record again.
`gateStep_late` says a shard behind the tenant moves its head only to the asserted digest. On the engine,
`RuleGate.after_eq` says the engine's step is `gateStep` followed by the floor check, and `after_held`, `after_late` and
`after_floor` state the same three facts for the head and version the engine writes.
