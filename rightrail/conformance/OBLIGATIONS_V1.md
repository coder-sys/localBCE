# Obligations records v1

The records of the combined store's obligations shard: the byte layout of every record kind, the rules a reader
applies, and one valid record of each kind. A second implementation needs only this file.
`app/right_rail_obligations_constants.json` carries the same widths, offsets and tags for the host, printed by the
format module's program `obligations_constants`; `tests/test_obligations_format.py` requires the tables below, that
file and the program to agree, and reads the vectors below with `conformance/obligations_v1_ref.py`, which shares no
code with the implementation.

## The record

A record of the `facts` file is 256 bytes: a 245-byte body, then an 11-byte link. Every number is little-endian.

- `num`: an unsigned number of `width` bytes.
- `blk`: `width` bytes, read as they stand.
- `lit`: `width` bytes that must hold the little-endian `value`: the tag (offset 0), a fixed code, or zeros.

A reader refuses a body that is not exactly 245 bytes or whose literal bytes differ from their value, and then
applies the record's own rules below. Any other number within its width is a value, so every accepted body has one
encoding: encoding the value read gives the same 245 bytes back.

### link

The link follows the body. `prev` is the previous record of the same chain plus one (0: none); `count` is the number
of records of the chain up to and including this one, held at 65,535 once it gets there. The chains: an obligation's
state rows, each followed by its fold record; the facts and quarantine markers of one subject; each case; the
shard's command records. A reader of a link applies the table and no other rule: any `prev` and `count` within
their widths are values.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 245 | 5 | num | prev |  |
| 250 | 2 | num | count |  |
| 252 | 4 | lit | zero | 0 |

## Tags

Every tag has an even number of one bits and any two differ in at least two bits, so one changed bit never turns a
record into one of another kind. A fact row's tag is its fact kind, with bit 7 set when the kind has an odd number of
one bits.

| record | tag |
|---|---:|
| state | 0x60 |
| case | 0x72 |
| action | 0xF3 |
| command | 0x74 |
| marker | 0x50 |
| fold | 0x65 |
| oblig | 0x8E |
| cash | 0x0F |
| claim | 0x96 |
| support | 0x17 |
| report | 0x18 |
| fund | 0x99 |
| ack | 0x9A |

## Records

Every amount and time a record holds is at most 2^63 - 1, the rules' own bound (`amountWellFormed`, `timeWellFormed`):
in the state row `cents`, `wbatch`, `owed`, `received`, `claimed`, `lawful`, `shortfall`, `overage`, `dueMs` and `atMs`; in
the case row `dueMs` and `atMs`; the action's `amount` and `atMs`; the command's `atMs`, `epoch` and `wbatch`; the facts' `owed`, `dueMs`,
`amount`, `deadlineMs`, `applicableMs` and `eventMs`; and the fold's times, amounts and `reqsum`. A body that holds
more is refused, and a writer refuses to write one.

A display field (51 or 21 bytes) is either an identifier or the start of the identifier's hash. An identifier is a
length byte `n` below the field's width, `n` bytes of text, then zeros to the end of the field. The hash form is
`0xFF`, then the first min(32, width - 1) bytes of the identifier's 32-byte hash, then zeros: in a 51-byte field 32
bytes and 18 zeros, in a 21-byte field the first 20 bytes and no zeros. A reader accepts a display field when it is
an identifier, or when its first byte is `0xFF` and every byte from the field's offset 33 on is zero.

### state (tag 0x60)

An obligation's state row (money row form 5): the obligation `ob`, its amounts, its links to the case, action, fact and command records, and its times. Rules: `mkind` 13-25; `flags` < 16; `verification` 1-3; `caseStatus` 1-5; `delivery` 1-4; `lg` < 4; every amount, time and `wbatch` < 2^63.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 0 | 1 | lit | tag | 96 |
| 1 | 1 | lit | fixed | 5 |
| 2 | 1 | num | mkind |  |
| 3 | 32 | blk | ob |  |
| 35 | 40 | lit | zero | 0 |
| 75 | 5 | lit | zero | 0 |
| 80 | 8 | num | cents |  |
| 88 | 8 | lit | zero | 0 |
| 96 | 1 | lit | zero | 0 |
| 97 | 8 | num | wbatch |  |
| 105 | 3 | num | windex |  |
| 108 | 5 | num | cause |  |
| 113 | 5 | num | link |  |
| 118 | 12 | lit | zero | 0 |
| 130 | 1 | num | reg |  |
| 131 | 8 | num | owed |  |
| 139 | 8 | num | received |  |
| 147 | 8 | num | claimed |  |
| 155 | 8 | num | lawful |  |
| 163 | 8 | num | shortfall |  |
| 171 | 8 | num | overage |  |
| 179 | 5 | num | conflicts |  |
| 184 | 1 | num | flags |  |
| 185 | 1 | num | verification |  |
| 186 | 1 | num | caseStatus |  |
| 187 | 5 | num | caseRef |  |
| 192 | 5 | num | act |  |
| 197 | 5 | num | fact |  |
| 202 | 5 | num | cmd |  |
| 207 | 8 | num | dueMs |  |
| 215 | 8 | num | atMs |  |
| 223 | 5 | num | lseq |  |
| 228 | 4 | num | pack |  |
| 232 | 5 | num | rev |  |
| 237 | 1 | num | delivery |  |
| 238 | 1 | num | lg |  |
| 239 | 6 | lit | zero | 0 |

### case (tag 0x72)

A case record: op 1 OPEN and 2 EVALUATED (status 1-5) form the case chain; op 3 ASSIGN and 4 CLOSE (status 0) the follow-through chain. Rules: `op` 1-4; `status` 1-5 when `op` ≤ 2, else 0; `lg` < 4; `dueMs` and `atMs` < 2^63.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 0 | 1 | lit | tag | 114 |
| 1 | 1 | num | op |  |
| 2 | 32 | blk | ck |  |
| 34 | 32 | blk | ob |  |
| 66 | 1 | num | status |  |
| 67 | 1 | num | role |  |
| 68 | 1 | num | acct |  |
| 69 | 2 | num | reason |  |
| 71 | 8 | num | dueMs |  |
| 79 | 8 | num | atMs |  |
| 87 | 64 | blk | conds |  |
| 151 | 5 | num | act |  |
| 156 | 5 | num | cmd |  |
| 161 | 32 | blk | assignee |  |
| 193 | 1 | num | lg |  |
| 194 | 1 | num | nt |  |
| 195 | 50 | lit | zero | 0 |

### action (tag 0xF3)

An action record: op 1 CREATE, 2 ACK, 3 CANCEL, 4 ATTEMPT; kind 1-2; status 1 READY, 2 ACKNOWLEDGED, 3 CANCELLED. `decidedMs` is the time of the determination the action carries out (the rules' `decidedAt`), on every record of
the action; it is 7 bytes, so times are below 2^56 ms, and a writer refuses a later time rather than cut it. Rules:
`op` 1-4; `akind` 1-2; `status` is a function of `op`: 1 for `op` 1 and 4, 2 for `op` 2, 3 for `op` 3, and every other pair
is refused (the fold follows the operation and the rules follow the status, so a record holds one reading); `lg` < 4;
`decidedMs` ≤ `atMs`; `ak` is not all zero (zero names no request); `amount` and `atMs` < 2^63.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 0 | 1 | lit | tag | 243 |
| 1 | 1 | num | op |  |
| 2 | 32 | blk | ak |  |
| 34 | 32 | blk | ob |  |
| 66 | 1 | num | akind |  |
| 67 | 1 | num | status |  |
| 68 | 4 | num | attempt |  |
| 72 | 8 | num | amount |  |
| 80 | 64 | blk | payload |  |
| 144 | 64 | blk | idem |  |
| 208 | 8 | num | atMs |  |
| 216 | 5 | num | claim |  |
| 221 | 5 | num | ack |  |
| 226 | 5 | num | cmd |  |
| 231 | 1 | num | lg |  |
| 232 | 1 | num | nt |  |
| 233 | 5 | num | rev |  |
| 238 | 7 | num | decidedMs |  |

### command (tag 0x74)

A command record: one per applied command. `wbatch` and `windex` are the frame's batch number and the command's place in it. Rules: `ckind` 1-12; `attr` ≤ 2; `epoch` 1 to 2^63 - 1 (the rules' authority epoch is at least 1); `lg` < 4; `atMs`, `epoch` and `wbatch` < 2^63.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 0 | 1 | lit | tag | 116 |
| 1 | 1 | num | ckind |  |
| 2 | 32 | blk | cid |  |
| 34 | 64 | blk | rqd |  |
| 98 | 64 | blk | lrq |  |
| 162 | 32 | blk | actor |  |
| 194 | 8 | num | atMs |  |
| 202 | 1 | num | role |  |
| 203 | 1 | num | attr |  |
| 204 | 5 | num | exprev |  |
| 209 | 5 | num | result |  |
| 214 | 5 | num | lseq |  |
| 219 | 8 | num | epoch |  |
| 227 | 1 | num | lg |  |
| 228 | 1 | num | nt |  |
| 229 | 8 | num | wbatch |  |
| 237 | 3 | num | windex |  |
| 240 | 5 | lit | zero | 0 |

### marker (tag 0x50)

A quarantine marker: the statement `sid` (known when `sidk` is 1, zero otherwise) of fact kind `fkind` about `subject` is held unknown for `cause` (not 0). Rules: `cause` ≠ 0; `sidk` ≤ 1; `sid` all zero when `sidk` is 0.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 0 | 1 | lit | tag | 80 |
| 1 | 2 | num | src |  |
| 3 | 1 | num | fkind |  |
| 4 | 32 | blk | subject |  |
| 36 | 5 | num | receipt |  |
| 41 | 5 | num | roff |  |
| 46 | 1 | num | cause |  |
| 47 | 1 | num | sidk |  |
| 48 | 32 | blk | sid |  |
| 80 | 165 | lit | zero | 0 |

### fold (tag 0x65)

The fold record, written right after each state row: with that row it is the obligation's state, so the next command needs neither the history nor an evaluation. A link field (`cmax`, `done`, `amax`) that is 0 names no record, and then its times and amount are 0. Rules: `cmax` = 0 → `cmaxMs` = `cmaxCents` = 0; `done` = 0 → `doneMs` = 0; `amax` = 0 → `amaxMs` = 0; `cmaxMs`, `cmaxCents`, `doneMs`, `reqsum` and `amaxMs` < 2^63.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 0 | 1 | lit | tag | 101 |
| 1 | 64 | blk | cref |  |
| 65 | 64 | blk | eacc |  |
| 129 | 5 | num | ecount |  |
| 134 | 5 | num | ccount |  |
| 139 | 8 | num | cmaxMs |  |
| 147 | 8 | num | cmaxCents |  |
| 155 | 5 | num | cmax |  |
| 160 | 8 | num | doneMs |  |
| 168 | 5 | num | done |  |
| 173 | 8 | num | reqsum |  |
| 181 | 8 | num | amaxMs |  |
| 189 | 5 | num | amax |  |
| 194 | 51 | lit | zero | 0 |

### oblig (tag 0x8E)

Fact kind 14, a population item. Rules: `op` < 3, and `vstart` ≤ `vstop` unless `op` is 2; `ecls` ≤ 4; each 51- or 21-byte identifier field (`item`, `period`) is a display field; every amount and time < 2^63.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 0 | 1 | lit | tag | 142 |
| 1 | 1 | num | op |  |
| 2 | 32 | blk | subject |  |
| 34 | 32 | blk | sid |  |
| 66 | 4 | num | vstart |  |
| 70 | 4 | num | vstop |  |
| 74 | 4 | num | lineUntil |  |
| 78 | 5 | num | receipt |  |
| 83 | 5 | num | roff |  |
| 88 | 8 | num | owed |  |
| 96 | 8 | num | dueMs |  |
| 104 | 4 | num | rule |  |
| 108 | 32 | blk | pop |  |
| 140 | 51 | blk | item |  |
| 191 | 21 | blk | period |  |
| 212 | 1 | num | ecls |  |
| 213 | 32 | lit | zero | 0 |

### cash (tag 0x0F)

Fact kind 15, a payment confirmation. `op` 0 states the payment; `op` 1 is its void (the payment's reversal), which
names the payment's statement by the same `sid`. A payment has no end: it leaves only by its void. Rules: `op` 0 or 1
(2 is refused); `vstart` ≤ `vstop`; `ecls` ≤ 4; each 51- or 21-byte identifier field (`origin`) is a display field; `amount` and `eventMs` < 2^63.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 0 | 1 | lit | tag | 15 |
| 1 | 1 | num | op |  |
| 2 | 32 | blk | subject |  |
| 34 | 32 | blk | sid |  |
| 66 | 4 | num | vstart |  |
| 70 | 4 | num | vstop |  |
| 74 | 4 | num | lineUntil |  |
| 78 | 5 | num | receipt |  |
| 83 | 5 | num | roff |  |
| 88 | 8 | num | amount |  |
| 96 | 8 | num | eventMs |  |
| 104 | 32 | blk | pays |  |
| 136 | 32 | blk | pid |  |
| 168 | 1 | num | ecls |  |
| 169 | 51 | blk | origin |  |
| 220 | 25 | lit | zero | 0 |

### claim (tag 0x96)

Fact kind 22, an offset claim. Rules: `op` < 3, and `vstart` ≤ `vstop` unless `op` is 2; `ecls` ≤ 4; each 51- or 21-byte identifier field (`claim`) is a display field; every amount and time < 2^63.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 0 | 1 | lit | tag | 150 |
| 1 | 1 | num | op |  |
| 2 | 32 | blk | subject |  |
| 34 | 32 | blk | sid |  |
| 66 | 4 | num | vstart |  |
| 70 | 4 | num | vstop |  |
| 74 | 4 | num | lineUntil |  |
| 78 | 5 | num | receipt |  |
| 83 | 5 | num | roff |  |
| 88 | 8 | num | amount |  |
| 96 | 8 | num | deadlineMs |  |
| 104 | 8 | num | eventMs |  |
| 112 | 1 | num | role |  |
| 113 | 1 | num | ecls |  |
| 114 | 51 | blk | claim |  |
| 165 | 80 | lit | zero | 0 |

### support (tag 0x17)

Fact kind 23, supporting evidence. Rules: `op` < 3, and `vstart` ≤ `vstop` unless `op` is 2; `ecls` ≤ 4; each 51- or 21-byte identifier field (`ref`) is a display field; every amount and time < 2^63.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 0 | 1 | lit | tag | 23 |
| 1 | 1 | num | op |  |
| 2 | 32 | blk | subject |  |
| 34 | 32 | blk | sid |  |
| 66 | 4 | num | vstart |  |
| 70 | 4 | num | vstop |  |
| 74 | 4 | num | lineUntil |  |
| 78 | 5 | num | receipt |  |
| 83 | 5 | num | roff |  |
| 88 | 64 | blk | content |  |
| 152 | 8 | num | applicableMs |  |
| 160 | 8 | num | eventMs |  |
| 168 | 1 | num | purpose |  |
| 169 | 1 | num | ecls |  |
| 170 | 51 | blk | ref |  |
| 221 | 24 | lit | zero | 0 |

### report (tag 0x18)

Fact kind 24, a report or its correction. Rules: `op` < 3, and `vstart` ≤ `vstop` unless `op` is 2; `ecls` ≤ 4; each 51- or 21-byte identifier field (`ref`) is a display field; every amount and time < 2^63.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 0 | 1 | lit | tag | 24 |
| 1 | 1 | num | op |  |
| 2 | 32 | blk | subject |  |
| 34 | 32 | blk | sid |  |
| 66 | 4 | num | vstart |  |
| 70 | 4 | num | vstop |  |
| 74 | 4 | num | lineUntil |  |
| 78 | 5 | num | receipt |  |
| 83 | 5 | num | roff |  |
| 88 | 64 | blk | content |  |
| 152 | 8 | num | applicableMs |  |
| 160 | 8 | num | eventMs |  |
| 168 | 1 | num | ecls |  |
| 169 | 51 | blk | ref |  |
| 220 | 25 | lit | zero | 0 |

### fund (tag 0x99)

Fact kind 25, a program funding receipt. Rules: `op` < 3, and `vstart` ≤ `vstop` unless `op` is 2; `ecls` ≤ 4; each 51- or 21-byte identifier field (`ref`) is a display field; every amount and time < 2^63.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 0 | 1 | lit | tag | 153 |
| 1 | 1 | num | op |  |
| 2 | 32 | blk | subject |  |
| 34 | 32 | blk | sid |  |
| 66 | 4 | num | vstart |  |
| 70 | 4 | num | vstop |  |
| 74 | 4 | num | lineUntil |  |
| 78 | 5 | num | receipt |  |
| 83 | 5 | num | roff |  |
| 88 | 8 | num | amount |  |
| 96 | 8 | num | eventMs |  |
| 104 | 1 | num | cclass |  |
| 105 | 1 | num | estatus |  |
| 106 | 1 | num | ecls |  |
| 107 | 51 | blk | ref |  |
| 158 | 87 | lit | zero | 0 |

### ack (tag 0x9A)

Fact kind 26, the acknowledgment of an action. Rules: `op` < 3, and `vstart` ≤ `vstop` unless `op` is 2; `ecls` ≤ 4; each 51- or 21-byte identifier field (`ackref`) is a display field; every amount and time < 2^63.

| offset | width | kind | name | value |
|---:|---:|---|---|---:|
| 0 | 1 | lit | tag | 154 |
| 1 | 1 | num | op |  |
| 2 | 32 | blk | subject |  |
| 34 | 32 | blk | sid |  |
| 66 | 4 | num | vstart |  |
| 70 | 4 | num | vstop |  |
| 74 | 4 | num | lineUntil |  |
| 78 | 5 | num | receipt |  |
| 83 | 5 | num | roff |  |
| 88 | 32 | blk | action |  |
| 120 | 64 | blk | payload |  |
| 184 | 8 | num | eventMs |  |
| 192 | 1 | num | ecls |  |
| 193 | 51 | blk | ackref |  |
| 244 | 1 | lit | zero | 0 |

## The fold

The fold record of an obligation is a function of the obligation's records in record order and of what each
record's element gives. `foldOf`, below, is that function: the engine keeps the record up to date one command at a
time, and a checker recomputes it from the records alone.

A record's element is the command's stored copy in the frame's request, found by the command record's `wbatch` and
`windex`. The fold reads from it only identifiers that no record holds, each of which may be absent: an evidence id;
a contribution id, which is the payment id of a cash row or the determination id of an offset authorization; and an
action id.

Notation: `dom(name)` is the ASCII text `RR/GATE/<name>/v1` followed by one zero byte (the constants file gives both
texts under `domains`); `H` is SHA3-512; `lp16(x)` is
the length of `x` in 2 little-endian bytes, then `x`. An identifier is the UTF-8 bytes of its text. Byte strings
compare byte by byte, and a proper prefix comes first. A link is a record's number in the `facts` file plus one, and
0 names no record.

**The fixed reference.** `cref` = `H(dom("EVALFIX") ‖ lp16(stateId) ‖ lp16(deploymentId) ‖ lp16(programId) ‖
lp16(periodId) ‖ lp16(currency) ‖ lp16(itemId) ‖ lp16(obligationId))`, with the values of the opening's element.
`cref` holds a field of the rules' evaluation result only when no command after the opening can change it. Every
other field belongs to the part of the evaluation reference that is computed per evaluation.

| result field | in `cref` | why |
|---|---|---|
| `stateId`, `deploymentId`, `programId`, `periodId`, `currency` | yes | the obligation's scope; with the item it makes the obligation key `ob`, so a command with other values names another obligation |
| `itemId` | yes | makes `ob` with the scope |
| `obligationId` | yes | the owner derives it from the item and the period, which are both fixed |
| `populationId` | no | `ob` does not include it, so a later statement could carry the same item under another population |
| `ownerId`, `mode`, `provenance` | no | they describe the evaluation's owner and how it runs, not the obligation; the same obligation can be evaluated in another mode |
| `authorityId`, `authorityEpoch`, `authorityDigest` | no | a change of authority changes them |
| `packId`, `packDigest`, `ruleVersion` | no | a new control pack or rule version changes them |
| `beforeRevision`, `afterRevision`, `evaluatedAt` | no | every command changes them |
| `evidenceIds` | no | every evidence item adds one; the fold keeps them as `eacc` and `ecount` |
| `completionAt` | no | payments, offsets and voids move it |
| `owedCents` | no | a later population statement can change it |
| `claimedAdjustmentCents`, `lawfulAdjustmentCents`, `receivedCashCents`, `shortfallCents`, `overageCents` | no | claims, payments and offsets change them |
| `cashSatisfied`, `amountSatisfied`, `timely`, `reportingComplete` | no | they follow from amounts, times and reports that commands change |
| `verificationStatus`, `caseStatus`, `deliveryStatus` | no | case and action commands change them |

**The walk.** Start with `eacc` = 64 zero bytes, `ecount` = 0, no active contributions, no open requests, an owed
amount of 0 and no latest action. Then, for each record in record order:

1. When its element gives an evidence id `e`: `eacc` = `H(dom("EVIDACC") ‖ eacc ‖ lp16(e))`, and `ecount` grows by 1.
   This holds whatever the body.
2. Then, by its tag; a body that its table or its rules refuse adds nothing more:
   * state: the owed amount becomes its `owed`, and a state row has been read.
   * cash with `op` 1 (the void): every active contribution with this record's `sid` stops, and the `sid` is
     asserted. Cash with `op` 0, when the element gives a contribution id `p` and the `sid` is not asserted: the
     contribution (`eventMs`, `amount`, `p`, this record, `sid`, `pays`) becomes active, and the `sid` is asserted. A
     statement used before, by a payment or by a void, moves no amount and adds no count, whether its payment is in
     force or was voided (a payment is not superseded, and a reversed one never comes back); its evidence id still
     counts.
   * action with `op` 1 (create), the first of its `ak`; a later create of the same `ak` moves nothing, also after
     the cancel of the `ak` (a cancelled request does not come back, and an offset does not count twice): when the element gives an action id `a`, the action (`atMs`, `a`, this record)
     becomes the latest action, unless the latest has a later `atMs`, or the same `atMs` and a greater id. Then,
     when `akind` is 1 (offset authorization) and the element gives a contribution id `d`, the contribution
     (`decidedMs`, `amount`, `d`, this record, with no `sid` and no `pays`) becomes active: an offset counts from
     the time it was decided, not the time its action was created. When `akind` is 2 (correction request), the
     request (`ak`, `amount`) opens.
   * action with `op` 3 (cancel): every open request with this `ak` closes. An offset stays active, as the rules
     count every authorized offset.
   * any other record: nothing.

**The record.** Sort the active contributions by time, then amount, then id, all ascending; where all three are
equal, the later record comes first. Then:

* `cref` as above; `eacc` and `ecount` from the walk.
* `ccount`: the number of active contributions.
* `cmax`, `cmaxMs`, `cmaxCents`: the last contribution in sorted order: its link, time and amount.
* `done`, `doneMs`: the first contribution in sorted order at which the running sum of amounts reaches the owed
  amount: its link and time. When no state row has been read, or the sum never reaches it, `done` and `doneMs` are 0, and the rules' completion
  time is not the fold's to give: it is the latest contribution's time (`cmaxMs`) when the cash received plus the
  lawful adjustment (the state row's `received` and `lawful`) reaches the owed amount, and none otherwise.
* `reqsum`: over the open requests, the amount asked less the amounts of the active contributions whose `pays` is
  the request's `ak`, each at least 0.
* `amax`, `amaxMs`: the latest action's link and time.

A link that names no record is 0, and so are its time and amount.

**A total that does not fit.** Every record's amounts and times are below 2^63, so only a total can reach it, and the
rules add with a checked sum. When the active contributions add up to 2^63 or more (so a running sum of them did at
some step), or any field of the record is 2^63 or more (`reqsum`, the open requests less their cash), or does not fit
its width, there is no fold record: a reader returns nothing, and the writer writes nothing. An identifier or an
opening field of 65,536 bytes or more does not fit `lp16`, and gives no fold record either. A total is never wrapped,
cut or raised as an error.

## Vectors

One valid body of each kind: `record` names it, `hex` is its 245 bytes, and each `field` line is a number or block
field in layout order, numbers in decimal and blocks in hex. Literal fields are not listed.

Then one valid link, as `record link` with its 11 bytes and its two fields.

Then, for every rule of every record, a body that breaks that rule and no other: `refuse`, the record, the field
whose rule it breaks, and the 245 bytes (a body the table itself refuses names `length`, or its literal field: a wrong
length, a nonzero padding byte, a wrong form byte, a link with flags). A reader must refuse each. Then bodies at the edge of a rule, which a
reader must accept: `accept`, the record, the field, the bytes.

Then the examples of the fold, each starting with `example` and its name. Each `opening` line is a field of the
opening's element, in hex. Each `input` line is a record: its number, its body, then the evidence id, the
contribution id and the action id its element gives, in hex, `-` for none. The `fold` line is the fold record that
`foldOf` gives.

* `main` owes 400,000: two payments, an offset decided before its action was created, a correction request
  created at the offset's created time with a smaller action id, cash that pays the request, and the void of the
  second payment. The offset counts from its decision, before the first payment, so the two reach 400,000 at the
  first payment.
* `void`: a void removes its payment, and what is left never reaches the amount owed: `done` is 0.
* `refused`: a cash row with `op` 2, an offset decided after its action was created, and a state row with
  verification 0. Their bodies are refused, so only their evidence ids count.
* `cancel`: a cancel closes its correction request; the cancel of an offset authorization leaves the offset.
* `floor`: cash beyond what a request asks leaves the request at 0 and does not reduce another request.
* `reqvoid`: the void of the cash that paid a request opens the request's amount again.
* `dupsid`: a second cash row of the same `sid` under another payment id and with no evidence id moves nothing.
* `reassert`: a statement asserted, voided and asserted again with a payment element adds nothing: its payment does
  not come back, and the obligation is not done.
* `big`: a request and a payment of 2^63 are refused with their records and add nothing; a request of 2^63 - 1 counts.
* `overflow`: two requests of 2^63 - 1 add up to more than 2^63 - 1: there is no fold record (`fold none`).
* `voidfirst`: a void seen before any payment of its `sid` uses the `sid`, so the payment after it adds nothing.
* `createrepeat`: the second create of an offset's `ak` adds no second offset and no later action, and the second
  create of a request's `ak` does not double the request.
* `recreate`: a create of an `ak` after its cancel adds no request.
* `zeroak`: a request whose `ak` is all zero is refused with its record, so cash with a zero `pays` (which pays none)
  is not set against it.
* `nostate`: with no state row that is read, the first payment of 1 does not complete the obligation: `done` is 0.
* `sumover`: owed 2^63 - 1 and cash of 5, then of 2^63 - 1: each fits, their sum does not, so there is no fold
  record.

```text
record state
hex 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
field mkind 19
field ob 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
field cents 30000
field wbatch 7
field windex 2
field cause 11
field link 9
field reg 1
field owed 500000
field received 200000
field claimed 30000
field lawful 30000
field shortfall 300000
field overage 0
field conflicts 1
field flags 10
field verification 2
field caseStatus 3
field caseRef 12
field act 13
field fact 14
field cmd 15
field dueMs 1767225600000
field atMs 1767225600001
field lseq 0
field pack 4
field rev 6
field delivery 1
field lg 2
record case
hex 720302030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200004ffffff00a8da769b01000001a8da769b010000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748000000000015000000000708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252600010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
field op 3
field ck 02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021
field ob 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
field status 0
field role 4
field acct 255
field reason 65535
field dueMs 1767225600000
field atMs 1767225600001
field conds 090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748
field act 0
field cmd 21
field assignee 0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526
field lg 0
field nt 1
record action
hex f301030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
field op 1
field ak 030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122
field ob 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
field akind 1
field status 1
field attempt 0
field amount 30000
field payload 0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243
field idem 05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344
field atMs 1767225600000
field claim 8
field ack 0
field cmd 21
field lg 0
field nt 2
field rev 1
field decidedMs 1767225599000
record command
hex 7408060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262700a8da769b01000002020700000000160000000000000000000300000000000000000409000000000000000102000000000000
field ckind 8
field cid 060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425
field rqd 0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546
field lrq 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
field actor 08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627
field atMs 1767225600000
field role 2
field attr 2
field exprev 7
field result 22
field lseq 0
field epoch 3
field lg 0
field nt 4
field wbatch 9
field windex 513
record marker
hex 5001000f28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647000000000000000000000101090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
field src 1
field fkind 15
field subject 28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647
field receipt 0
field roff 0
field cause 1
field sidk 1
field sid 090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728
record fold
hex 650b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b0300000000020000000000a8da769b01000030750000000000000e0000000000a8da769b0100000e00000000881300000000000002a8da769b0100000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
field cref 0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a
field eacc 0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b
field ecount 3
field ccount 2
field cmaxMs 1767225600000
field cmaxCents 30000
field cmax 14
field doneMs 1767225600000
field done 14
field reqsum 5000
field amaxMs 1767225600002
field amax 9
record oblig
hex 8e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000020a107000000000000a8da769b0100000300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021066974656d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007323032362d303100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
field op 0
field subject 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
field sid 28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647
field vstart 20260101
field vstop 20261231
field lineUntil 99991231
field receipt 5
field roff 7
field owed 500000
field dueMs 1767225600000
field rule 3
field pop 02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021
field item 066974656d2d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
field period 07323032362d303100000000000000000000000000
field ecls 0
record cash
hex 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546470525350105253501bfbef50505000000000700000000307500000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
field op 0
field subject 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
field sid 28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647
field vstart 20260101
field vstop 20260101
field lineUntil 99991231
field receipt 5
field roff 7
field amount 30000
field eventMs 1767225600000
field pays 0000000000000000000000000000000000000000000000000000000000000000
field pid 090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728
field ecls 0
field origin 086f726967696e2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000
record claim
hex 96000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000307500000000000000a8da769b01000001a8da769b010000010007636c61696d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
field op 0
field subject 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
field sid 28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647
field vstart 20260101
field vstop 20261231
field lineUntil 99991231
field receipt 5
field roff 7
field amount 30000
field deadlineMs 1767225600000
field eventMs 1767225600001
field role 1
field ecls 0
field claim 07636c61696d2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000
record support
hex 17000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414200a8da769b01000001a8da769b0100000200057265662d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
field op 0
field subject 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
field sid 28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647
field vstart 20260101
field vstop 20261231
field lineUntil 99991231
field receipt 5
field roff 7
field content 030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142
field applicableMs 1767225600000
field eventMs 1767225600001
field purpose 2
field ecls 0
field ref 057265662d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
record report
hex 18000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef505050000000007000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424300a8da769b01000001a8da769b01000000087265706f72742d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
field op 0
field subject 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
field sid 28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647
field vstart 20260101
field vstop 20261231
field lineUntil 99991231
field receipt 5
field roff 7
field content 0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243
field applicableMs 1767225600000
field eventMs 1767225600001
field ecls 0
field ref 087265706f72742d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000
record fund
hex 99000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000307500000000000000a8da769b0100000102000666756e642d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
field op 0
field subject 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
field sid 28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647
field vstart 20260101
field vstop 20261231
field lineUntil 99991231
field receipt 5
field roff 7
field amount 30000
field eventMs 1767225600000
field cclass 1
field estatus 2
field ecls 0
field ref 0666756e642d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
record ack
hex 9a000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000005060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444500a8da769b010000000561636b2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
field op 0
field subject 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
field sid 28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647
field vstart 20260101
field vstop 20261231
field lineUntil 99991231
field receipt 5
field roff 7
field action 05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324
field payload 060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445
field eventMs 1767225600000
field ecls 0
field ackref 0561636b2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
record link
hex 0a00000000050000000000
field prev 10
field count 5
refuse state mkind 60050c0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse state mkind 60051a0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse state flags 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000001002030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse state verification 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a00030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse state verification 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a04030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse state caseStatus 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02000c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse state caseStatus 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02060c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse state delivery 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000002000000000000
refuse state delivery 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000502000000000000
refuse state lg 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000104000000000000
refuse state cents 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse state owed 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b000000000900000000000000000000000000000000010000000000000080400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse state dueMs 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f00000000000000000000008001a8da769b01000000000000000400000006000000000102000000000000
refuse state atMs 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b010000000000000000008000000000000400000006000000000102000000000000
refuse state received 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000000000000000008030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse state claimed 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000000000000000000803075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse state lawful 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000000000000000000080e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse state shortfall 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d030000000000307500000000000030750000000000000000000000000080000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse state overage 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000008001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse case dueMs 720302030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200004ffffff000000000000008001a8da769b010000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748000000000015000000000708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252600010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse case atMs 720302030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200004ffffff00a8da769b0100000000000000000080090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748000000000015000000000708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252600010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse command atMs 7408060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627000000000000008002020700000000160000000000000000000300000000000000000409000000000000000102000000000000
refuse command epoch 7408060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262700a8da769b01000002020700000000160000000000000000000000000000000000000409000000000000000102000000000000
refuse command epoch 7408060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262700a8da769b01000002020700000000160000000000000000000000000000000080000409000000000000000102000000000000
refuse command wbatch 7408060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262700a8da769b01000002020700000000160000000000000000000300000000000000000400000000000000800102000000000000
refuse state wbatch 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000000000000000000800200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse action ak f30100000000000000000000000000000000000000000000000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse state length 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b010000000000000004000000060000000001020000000000
refuse state length 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b0100000000000000040000000600000000010200000000000000
refuse state zero 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000001
refuse state fixed 6006130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
refuse link zero 0a00000000050001000000
refuse oblig owed 8e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000000000000000008000a8da769b0100000300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021066974656d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007323032362d303100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse oblig dueMs 8e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000020a107000000000000000000000000800300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021066974656d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007323032362d303100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse claim amount 96000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000000000000000008000a8da769b01000001a8da769b010000010007636c61696d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse claim deadlineMs 96000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef505050000000007000000003075000000000000000000000000008001a8da769b010000010007636c61696d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse claim eventMs 96000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000307500000000000000a8da769b0100000000000000000080010007636c61696d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse support applicableMs 17000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142000000000000008001a8da769b0100000200057265662d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse support eventMs 17000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414200a8da769b01000000000000000000800200057265662d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse report applicableMs 18000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef505050000000007000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243000000000000008001a8da769b01000000087265706f72742d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse report eventMs 18000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef505050000000007000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424300a8da769b010000000000000000008000087265706f72742d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fund amount 99000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000000000000000008000a8da769b0100000102000666756e642d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fund eventMs 99000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000307500000000000000000000000000800102000666756e642d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse ack eventMs 9a000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000005060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344450000000000000080000561636b2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse case op 720002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200104ffffff00a8da769b01000001a8da769b010000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748000000000015000000000708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252600010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse case op 720502030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200004ffffff00a8da769b01000001a8da769b010000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748000000000015000000000708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252600010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse case status 720102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200004ffffff00a8da769b01000001a8da769b010000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748000000000015000000000708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252600010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse case status 720202030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200604ffffff00a8da769b01000001a8da769b010000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748000000000015000000000708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252600010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse case status 720302030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200104ffffff00a8da769b01000001a8da769b010000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748000000000015000000000708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252600010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse case lg 720302030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200004ffffff00a8da769b01000001a8da769b010000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748000000000015000000000708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252604010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse action op f300030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action op f305030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action akind f301030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action akind f301030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2003010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action status f301030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001000000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action status f301030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001040000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action status f301030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001020000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action status f301030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001030000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action status f302030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action status f302030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001030000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action status f303030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action status f303030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001020000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action status f304030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001020000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action status f304030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001030000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action amount f301030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000000000000000000800405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
refuse action atMs f301030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400000000000000800800000000000000000015000000000002010000000018a4da769b0100
refuse action lg f301030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000402010000000018a4da769b0100
refuse action decidedMs f301030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000001a8da769b0100
refuse command ckind 7400060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262700a8da769b01000002020700000000160000000000000000000300000000000000000409000000000000000102000000000000
refuse command ckind 740d060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262700a8da769b01000002020700000000160000000000000000000300000000000000000409000000000000000102000000000000
refuse command attr 7408060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262700a8da769b01000002030700000000160000000000000000000300000000000000000409000000000000000102000000000000
refuse command lg 7408060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262700a8da769b01000002020700000000160000000000000000000300000000000000040409000000000000000102000000000000
refuse marker cause 5001000f28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647000000000000000000000001090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse marker sidk 5001000f28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647000000000000000000000102090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse marker sid 5001000f28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647000000000000000000000100090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fold cmaxMs 650b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b0300000000020000000000a8da769b0100000000000000000000000000000000a8da769b0100000e00000000881300000000000002a8da769b0100000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fold cmaxCents 650b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b0300000000020000000000000000000000003075000000000000000000000000a8da769b0100000e00000000881300000000000002a8da769b0100000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fold doneMs 650b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b0300000000020000000000a8da769b01000030750000000000000e0000000000a8da769b0100000000000000881300000000000002a8da769b0100000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fold amaxMs 650b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b0300000000020000000000a8da769b01000030750000000000000e0000000000a8da769b0100000e00000000881300000000000002a8da769b0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fold cmaxMs 650b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b03000000000200000000000000000000008030750000000000000e0000000000a8da769b0100000e00000000881300000000000002a8da769b0100000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fold cmaxCents 650b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b0300000000020000000000a8da769b01000000000000000000800e0000000000a8da769b0100000e00000000881300000000000002a8da769b0100000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fold doneMs 650b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b0300000000020000000000a8da769b01000030750000000000000e0000000000000000000000800e00000000881300000000000002a8da769b0100000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fold reqsum 650b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b0300000000020000000000a8da769b01000030750000000000000e0000000000a8da769b0100000e00000000000000000000008002a8da769b0100000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fold amaxMs 650b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b0300000000020000000000a8da769b01000030750000000000000e0000000000a8da769b0100000e00000000881300000000000000000000000000800900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse oblig op 8e030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000020a107000000000000a8da769b0100000300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021066974656d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007323032362d303100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse oblig vstart 8e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647702935016f293501bfbef5050500000000070000000020a107000000000000a8da769b0100000300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021066974656d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007323032362d303100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse oblig ecls 8e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000020a107000000000000a8da769b0100000300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021066974656d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007323032362d303100000000000000000000000000050000000000000000000000000000000000000000000000000000000000000000
refuse oblig item 8e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000020a107000000000000a8da769b0100000300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202133000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007323032362d303100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse oblig item 8e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000020a107000000000000a8da769b0100000300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202101610000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000107323032362d303100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse oblig period 8e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000020a107000000000000a8da769b0100000300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021066974656d2d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000150000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse oblig period 8e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000020a107000000000000a8da769b0100000300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021066974656d2d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016100000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000
refuse cash op 0f020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546470525350105253501bfbef50505000000000700000000307500000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse cash op 0f030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546470525350105253501bfbef50505000000000700000000307500000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse cash vstart 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546470625350105253501bfbef50505000000000700000000307500000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse cash ecls 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546470525350105253501bfbef50505000000000700000000307500000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272805086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse cash amount 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546470525350105253501bfbef50505000000000700000000000000000000008000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse cash eventMs 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546470525350105253501bfbef50505000000000700000000307500000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse cash origin 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546470525350105253501bfbef50505000000000700000000307500000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627280033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse cash origin 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546470525350105253501bfbef50505000000000700000000307500000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800ff030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse claim op 96030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000307500000000000000a8da769b01000001a8da769b010000010007636c61696d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse claim vstart 96010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647702935016f293501bfbef50505000000000700000000307500000000000000a8da769b01000001a8da769b010000010007636c61696d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse claim ecls 96000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000307500000000000000a8da769b01000001a8da769b010000010507636c61696d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse claim claim 96000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000307500000000000000a8da769b01000001a8da769b01000001000161000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse support op 17030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414200a8da769b01000001a8da769b0100000200057265662d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse support vstart 17000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647702935016f293501bfbef50505000000000700000000030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414200a8da769b01000001a8da769b0100000200057265662d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse support ecls 17000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414200a8da769b01000001a8da769b0100000205057265662d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse support ref 17000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414200a8da769b01000001a8da769b0100000200330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse report op 18030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef505050000000007000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424300a8da769b01000001a8da769b01000000087265706f72742d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse report vstart 18000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647702935016f293501bfbef505050000000007000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424300a8da769b01000001a8da769b01000000087265706f72742d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse report ecls 18000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef505050000000007000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424300a8da769b01000001a8da769b01000005087265706f72742d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse report ref 18000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef505050000000007000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424300a8da769b01000001a8da769b0100000001610000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000
refuse fund op 99030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000307500000000000000a8da769b0100000102000666756e642d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fund vstart 99000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647702935016f293501bfbef50505000000000700000000307500000000000000a8da769b0100000102000666756e642d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fund ecls 99000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000307500000000000000a8da769b0100000102050666756e642d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse fund ref 99000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000307500000000000000a8da769b010000010200330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse ack op 9a030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000005060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444500a8da769b010000000561636b2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse ack vstart 9a000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647702935016f293501bfbef5050500000000070000000005060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444500a8da769b010000000561636b2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse ack ecls 9a000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000005060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444500a8da769b010000050561636b2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
refuse ack ackref 9a000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000005060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444500a8da769b0100000001610000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100
accept case status 720102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200504ffffff00a8da769b01000001a8da769b010000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748000000000015000000000708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252600010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
accept action decidedMs f301030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100
accept action status f302030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001020000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
accept action status f303030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001030000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
accept action status f304030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
accept action amount f301030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20010100000000ffffffffffffff7f0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000018a4da769b0100
accept state owed 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001ffffffffffffff7f400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
accept state overage 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000ffffffffffffff7f01000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
accept claim deadlineMs 96000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef505050000000007000000003075000000000000ffffffffffffff7f01a8da769b010000010007636c61696d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
accept ack eventMs 9a000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000005060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445ffffffffffffff7f000561636b2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
accept cash amount 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546470525350105253501bfbef50505000000000700000000ffffffffffffff7f00a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
accept command epoch 7408060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262700a8da769b01000002020700000000160000000000000000000100000000000000000409000000000000000102000000000000
accept command epoch 7408060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262700a8da769b0100000202070000000016000000000000000000ffffffffffffff7f000409000000000000000102000000000000
accept command wbatch 7408060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262700a8da769b010000020207000000001600000000000000000003000000000000000004ffffffffffffff7f0102000000000000
accept state wbatch 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003075000000000000000000000000000000ffffffffffffff7f0200000b0000000009000000000000000000000000000000000120a1070000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000
accept fold reqsum 650b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b0300000000020000000000a8da769b01000030750000000000000e0000000000a8da769b0100000e00000000ffffffffffffff7f02a8da769b0100000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
accept marker sid 5001000f28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546470000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
accept fold done 650b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b0300000000020000000000a8da769b01000030750000000000000e0000000000000000000000000000000000881300000000000002a8da769b0100000900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
accept oblig vstart 8e020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647702935016f293501bfbef5050500000000070000000020a107000000000000a8da769b0100000300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021066974656d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007323032362d303100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
accept oblig item 8e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000020a107000000000000a8da769b0100000300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021ffa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf00000000000000000000000000000000000007323032362d303100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
accept oblig period 8e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000020a107000000000000a8da769b0100000300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021066974656d2d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3000000000000000000000000000000000000000000000000000000000000000000
accept oblig item 8e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef5050500000000070000000020a107000000000000a8da769b0100000300000002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007323032362d303100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
accept cash op 0f010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546470525350105253501bfbef50505000000000700000000307500000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
accept claim ecls 96000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647052535016f293501bfbef50505000000000700000000307500000000000000a8da769b01000001a8da769b010000010407636c61696d2d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example main
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001801a060000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 3 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2032333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50510525350105253501bfbef50505000000000700000000e093040000000000e8abda769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d31 7061792d31 -
input 5 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051520525350105253501bfbef5050500000000070000000090d003000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d32 7061792d32 -
input 7 f3013c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20010100000000a0860100000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344d0afda769b01000008000000000000000000150000000000020100000000f4a9da769b0100 - 6465742d31 6163742d31
input 9 f3013d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2002010000000080380100000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344d0afda769b01000008000000000000000000150000000000020100000000d0afda769b0100 - - 6163742d30
input 11 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f203435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152530525350105253501bfbef505050000000007000000003075000000000000b8b3da769b0100003d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d33 7061792d33 -
input 13 0f010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051520525350105253501bfbef5050500000000070000000090d003000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d34 - -
input 15 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001801a060000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e49fdacae76935d174aa03daa97d5a3e77c990a90919ed21d33b726e283e812c5dc4720b2609fb2f4484e7ceccb070d23193cbce0aedca90b86be2be81ae237b804000000000300000000b8b3da769b01000030750000000000000c00000000e8abda769b010000040000000050c3000000000000d0afda769b0100000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example void
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001c0d4010000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6061626364650525350105253501bfbef50505000000000700000000a08601000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d61 7061792d61 -
input 2 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f204748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465660525350105253501bfbef5050500000000070000000050c300000000000001a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d62 7061792d62 -
input 3 0f010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f204748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465660525350105253501bfbef5050500000000070000000050c300000000000001a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d63 - -
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e337b76a6d21c358c895c09e15a0920778f5d778a77f12248bb1c93b1b9fed23e88ef41c98edad4b88de73f7638f2ad0a3bfe7d77f8efdb8fe5aaca6720a4203a0300000000010000000000a8da769b010000a086010000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example refused
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001a086010000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f0525350105253501bfbef50505000000000700000000a08601000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d61 7061792d61 -
input 2 0f020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f0525350105253501bfbef50505000000000700000000a08601000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d62 7061792d62 -
input 3 f3015152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f700102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000050c30000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000001a8da769b0100 - 6465742d7a 6163742d7a
input 4 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b000000000900000000000000000000000000000000010100000000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a00030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e005060f6d8c1d71400fd696cf5866a6d8686927ee9ea59a2bfff3e2c46f8b86db9dd411fc602e02d5e1770ab8e5afb9322e8de8b9b77c6205831fffbd09dd4e30200000000010000000000a8da769b010000a086010000000000020000000000a8da769b0100000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example cancel
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000150c3000000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 f3015a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778790102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2002010000000080380100000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - 6163742d72
input 2 f3035a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778790102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2002030000000080380100000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243440aa8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - -
input 3 f3015b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000050c30000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434414a8da769b0100000800000000000000000015000000000002010000000005a8da769b0100 - 6465742d6f 6163742d6f
input 4 f3035b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001030000000050c30000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243441ea8da769b0100000800000000000000000015000000000002010000000005a8da769b0100 - - -
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000005a8da769b01000050c3000000000000040000000005a8da769b0100000400000000000000000000000014a8da769b0100000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example floor
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000140420f0000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 f3016465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182830102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20020100000000204e0000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - 6163742d70
input 2 f30165666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283840102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2002010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434401a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - 6163742d71
input 3 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384850525350105253501bfbef50505000000000700000000307500000000000002a8da769b0100006465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d61 7061792d61 -
input 4 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f206768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485860525350105253501bfbef50505000000000700000000204e00000000000003a8da769b0100006465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d62 7061792d62 -
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e005060f6d8c1d71400fd696cf5866a6d8686927ee9ea59a2bfff3e2c46f8b86db9dd411fc602e02d5e1770ab8e5afb9322e8de8b9b77c6205831fffbd09dd4e30200000000020000000003a8da769b010000204e000000000000050000000000000000000000000000000000307500000000000001a8da769b0100000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example reqvoid
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001409c000000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 f3016e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20020100000000409c0000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - 6163742d76
input 2 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f206f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e0525350105253501bfbef50505000000000700000000409c00000000000001a8da769b0100006e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d61 7061792d61 -
input 3 0f010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f206f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e0525350105253501bfbef50505000000000700000000409c00000000000001a8da769b0100006e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d62 - -
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e005060f6d8c1d71400fd696cf5866a6d8686927ee9ea59a2bfff3e2c46f8b86db9dd411fc602e02d5e1770ab8e5afb9322e8de8b9b77c6205831fffbd09dd4e30200000000000000000000000000000000000000000000000000000000000000000000000000000000000000409c00000000000000a8da769b0100000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example dupsid
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001a086010000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2082838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a10525350105253501bfbef5050500000000070000000060ea00000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d61 7061792d61 -
input 2 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2082838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a10525350105253501bfbef5050500000000070000000060ea00000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 - 7061792d62 -
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e53beb89d03b35bef8a41b3f7678c91d655a4088f5183e1b5995b86e3e97cc03dfc42431831df5f26158f27078693b158af0be81a3ece9692659ced44e8f4b9ce0100000000010000000000a8da769b01000060ea000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example reassert
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001a086010000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a20525350105253501bfbef50505000000000700000000a08601000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d61 7061792d61 -
input 2 0f010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a20525350105253501bfbef50505000000000700000000a08601000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d62 - -
input 3 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a20525350105253501bfbef50505000000000700000000a08601000000000001a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d63 7061792d62 -
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e337b76a6d21c358c895c09e15a0920778f5d778a77f12248bb1c93b1b9fed23e88ef41c98edad4b88de73f7638f2ad0a3bfe7d77f8efdb8fe5aaca6720a4203a0300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example big
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001a086010000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 f3018c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaab0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2002010000000000000000000000800405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - 6163742d61
input 2 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f208d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabac0525350105253501bfbef50505000000000700000000000000000000008000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d61 7061792d61 -
input 3 f3018e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacad0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20020100000000ffffffffffffff7f0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - 6163742d62
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e53beb89d03b35bef8a41b3f7678c91d655a4088f5183e1b5995b86e3e97cc03dfc42431831df5f26158f27078693b158af0be81a3ece9692659ced44e8f4b9ce0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffff7f00a8da769b0100000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example overflow
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001a086010000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 f301969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b50102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20020100000000ffffffffffffff7f0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - 6163742d61
input 2 f3019798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b60102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20020100000000ffffffffffffff7f0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - 6163742d62
fold none
example voidfirst
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001a086010000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 0f010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0525350105253501bfbef50505000000000700000000a08601000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d61 - -
input 2 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0525350105253501bfbef50505000000000700000000a08601000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d62 7061792d61 -
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e005060f6d8c1d71400fd696cf5866a6d8686927ee9ea59a2bfff3e2c46f8b86db9dd411fc602e02d5e1770ab8e5afb9322e8de8b9b77c6205831fffbd09dd4e30200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example createrepeat
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b0000000009000000000000000000000000000000000150c3000000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 f301aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c90102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000050c30000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - 6465742d61 6163742d61
input 2 f301aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c90102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010000000050c30000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243440aa8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - 6465742d62 6163742d62
input 3 f301abacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9ca0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20020100000000204e0000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434405a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - 6163742d63
input 4 f301abacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9ca0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20020100000000204e0000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434414a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - 6163742d64
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000a8da769b01000050c3000000000000020000000000a8da769b0100000200000000204e00000000000005a8da769b0100000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example recreate
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001409c000000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 f301acadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacb0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20020100000000409c0000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - 6163742d61
input 2 f303acadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacb0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20020300000000409c0000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434401a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - -
input 3 f301acadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacb0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20020100000000409c0000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434402a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - 6163742d62
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a8da769b0100000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example zeroak
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001a086010000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 f30100000000000000000000000000000000000000000000000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2002010000000030750000000000000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424305060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434400a8da769b0100000800000000000000000015000000000002010000000000a8da769b0100 - - 6163742d7a
input 2 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20adaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcc0525350105253501bfbef50505000000000700000000e80300000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d61 7061792d61 -
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e53beb89d03b35bef8a41b3f7678c91d655a4088f5183e1b5995b86e3e97cc03dfc42431831df5f26158f27078693b158af0be81a3ece9692659ced44e8f4b9ce0100000000010000000000a8da769b010000e803000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example nostate
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b000000000900000000000000000000000000000000016400000000000000400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a00030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20aeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccd0525350105253501bfbef50505000000000700000000010000000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d61 7061792d61 -
fold 657062d43402f6bb0460694e297f54669b92788f0c93316165144cdd9c68330f3ceefa337cc59a2ce0feafa9beda701f77c4335720d2b23336e912afe540278a3e53beb89d03b35bef8a41b3f7678c91d655a4088f5183e1b5995b86e3e97cc03dfc42431831df5f26158f27078693b158af0be81a3ece9692659ced44e8f4b9ce0100000000010000000000a8da769b0100000100000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example sumover
opening stateId 5354
opening deploymentId 6465702d31
opening programId 70726f672d31
opening periodId 323032362d3031
opening currency 555344
opening itemId 6974656d2d31
opening obligationId 6f626c2d6974656d2d312d323032362d3031
input 0 6005130102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000000007000000000000000200000b00000000090000000000000000000000000000000001ffffffffffffff7f400d03000000000030750000000000003075000000000000e093040000000000000000000000000001000000000a02030c000000000d000000000e000000000f0000000000a8da769b01000001a8da769b01000000000000000400000006000000000102000000000000 - - -
input 1 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20afb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdce0525350105253501bfbef50505000000000700000000050000000000000000a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d61 7061792d61 -
input 2 0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf0525350105253501bfbef50505000000000700000000ffffffffffffff7f64a8da769b0100000000000000000000000000000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272800086f726967696e2d3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 65762d62 7061792d62 -
fold none
```
