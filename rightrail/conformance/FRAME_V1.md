# Engine frames v1: binary request and decision record

Status: draft. Synthetic, nonpayment, non-PHI: `proofSuiteId=null`, `production_usable=false`, `activation=false`.
The Lean model is normative: `lean/BlindLedger/Gate/Frame/Spec.lean` (codecs, the decision of a request, the record,
`join`, the human text, admission and retry), built by the `frame_statements` library. No `sorry` is left in
`Frame/Spec.lean`, `Frame/Fast.lean` or `Frame/Answer.lean`; `tests/lean_sorry_allowlist.txt` is empty and
`tests/test_no_sorry_source.py` holds it so. The host
(`app/right_rail_gate_decide.py`) builds and reads these frames today. `tests/gate_vectors/gate_v1.vectors` carries
answer vectors (`answer` lines) at answer header version 3 (see the note in section 4): `gate_vectors` requires an
accept vector to decode and re-encode to the same bytes and a reject vector to be refused (`Gate/Vectors.lean:238-241`). The history store, the chain and the state root are `FLAT_V1.md`'s.

## 1. Notation and transport

- All numbers are unsigned little-endian of the stated width: `u8`, `u16`, `u24`, `u32`, `u64`, `n21`, `n33` and `n261` for a 21-, 33- and
  261-byte number. Nothing is truncated or rounded. A value that does not fit is handled as section 3 says.
- `H` is SHA3-512 (64 bytes). `dom X` is the UTF-8 bytes of `RR/GATE/X/v1` and then one zero byte. `Z` is 64 zero bytes.
- Dates are CCYYMMDD as `u32`. A date is not converted to a day number, because an invalid date must reach the rules,
  which answer it `SERVICE_DATE_INVALID`.
- Transport: `gate_engine DIR SHARD` serves one shard's store in `DIR`. The frame is the existing u32 big-endian length,
  then tag `0x04`, then the request. The reply is a u32 big-endian length, then the answer. If the engine was started
  without `DIR SHARD`, a tag 4 frame is refused `FILES`.

## 2. Request (host to engine)

Header, 82 bytes:

| Offset | Field | Width | Rule |
|---|---|---|---|
| 0 | magic | 4 | ASCII `RRDQ` |
| 4 | version | u16 | 1 |
| 6 | shard | u32 | |
| 10 | batch | u64 | the batch number, from 1 |
| 18 | digest | 64 | `H(dom FRAME ‖ body)`; the body is every byte after the header |

Body. The sections come in this order and must use the body exactly:

1. Context, 384 bytes:

   | Offset | Field | Width | Rule |
   |---|---|---|---|
   | 0 | today | u32 | |
   | 4 | asOf | u32 | the sets' genesis date at batch 1; must be 0 at any other batch |
   | 8 | prev | 64 | the signed chain head after batch b−1; at batch 1, `chainStart(shard, sets dated asOf)` |
   | 72 | redo | u32 | redone payments that follow |
   | 76, 153, 230, 307 | DMF, provider deaths, exclusions, enrollment | 77 each | feed descriptors |

   A feed descriptor is `state u8 ‖ asOf u32 ‖ count u32 ‖ rows u32 ‖ pin 64`.
   - State 0: the feed is absent.
   - State 1: `rows` rows follow, and `pin` is the feed's SNAPSHOT/v1 pin.
   - State 2: the host had a row it could not encode, so the feed counts as missing, as a row that fails to parse does
     today.
   - States 0 and 2 carry zeros, `Z` as the pin, and no rows.
   - Lean hashes `pinInput` over the rows sent. A pin that differs makes the feed missing (`snap`), as today.
2. Feed rows, in the order DMF, provider deaths, exclusions, enrollment:
   - DMF: `member n33 ‖ date u32`, 37 bytes. A member is the product's identifier number: `0x01` then the 32-byte key, so 33 bytes.
   - Provider death: `id n21 ‖ date u32`, 25 bytes. A provider is the rules' identifier number of its identifier (`0x01`
     then the identifier's bytes), the width a line's payee and rendering provider have, so a 10-digit NPI fits.
   - Exclusion: `id n21 ‖ start u32 ‖ stop u32`, 29 bytes.
   - Enrollment span: `member n33 ‖ plan n21 ‖ start u32 ‖ stop u32`, 62 bytes.
3. Redone payments: the rules' payment number in `payWidth` = 261 bytes each (`n261`), the width the read-set digest gives it. The rules
   compare it with a line's payment number (Constitution III.3: a retry is the same canonical payment identity).
4. Authority. It is the shard's authority record that the text frame
   carried, as lengths and bytes (`blob` is `u32` length then bytes): `pin 64 ‖ floor present u8 ‖ floor u64 ‖ kfloor
   u32 ‖ grant blob ‖ key set blob ‖ release blob ‖ key steps u32, each day u32 ‖ blob ‖ bypasses u32, each blob ‖ requests u32,
   each blob`. The bytes are the state's, unchanged: the host forwards them and never re-encodes product data. The
   engine verifies the signatures, reads the lines from the request bytes (`Run.reqOf`) and derives the bypasses from the
   signed bypass requests (`Run.bypOf`). Nothing in the frame states a line or a bypass, so unsigned data never
   releases a payment. `kfloor` is the tenant's key-set epoch floor, the highest key-set epoch any shard of the tenant
   has admitted (zero asserts none): a key set below it holds the batch as `STALE_KEYSET` (`admit_keyset_floor`).

The decoder (`decodeReq`) refuses the whole frame. It checks in byte order, and the first failure names the status:

| Status | When |
|---|---|
| `LENGTH` | fewer than 82 bytes; a section ends past the body; bytes left after the authority section |
| `MAGIC` | the magic or the version is wrong |
| `DIGEST` | the body does not hash to `digest`; this is checked before any body byte is read |
| `RECORD` | any of: a feed state above 2; nonzero fields in a state 0 or 2 descriptor; `asOf ≠ 0` at a batch other than 1; a floor flag above 1 or a floor value under a clear flag; a payment request over 8 MiB or one that does not decode or whose lines do not map; two requests of one payment; requests of more than one tenant or program |

A malformed record refuses the whole frame because the frame is then untrusted. A value too wide for the store is not
malformed. It is section 3's per-line hold.

## 3. The decision

The engine computes `answers H s q` over the store state `s` before the batch. It does what `commitChunk` does today:

0. The lines (`Derived.lines`) are those of the requests the admitted grant covers, in frame order (`Run.St.lines`).
   A record's index is the line's position among them. A frame whose authority is not admitted decides nothing and
   carries the grant hold.
1. Held for width (`Run.fits`, `Run.unfit`):
   - A line with a field over its stored width answers HOLD UNENCODABLE_FIELD (rule 3).
   - Every other line of that payment answers HOLD UNENCODABLE_PAYMENT (rule 4). The payment goes to no set.
   - Every other line answers exactly as if those lines were not there (`wide_local`).
2. The lines left (`kept`) go through `fetch` and `decideFetched`. This is `decideBatchIdx` with `fcOf H q dv`, and
   `fcOf_inv` gives the decide theorems' hypothesis `FCtxInv`.

A redo value too wide for its field is left out by the host. The lines that carry it hold.

## 4. Answer (engine to host)

Note: this section keeps the earlier answer layout (u32 reasons, 16-byte records, 71/135-byte leaves, leaf codes at bits
24 and 25). The built engine answers at header version 3 (`Frame/Spec.lean:126` `ansVersion`): reasons are a u64, a rule
reason at bit `r.idx` and the leaf-only UNENCODABLE_PAYMENT and SCOPE at bits 62 and 63 (`:500-503`); a record is 20
bytes (`:591-594`), a leaf 75 or 139 (`:506-510`). The request is still version 1 (`:122`). A full page for the version-3
frames is still to come.

Header, 87 bytes:

| Offset | Field | Width | Rule |
|---|---|---|---|
| 0 | magic | 4 | ASCII `RRDA` |
| 4 | version | u16 | 1 |
| 6 | status | u8 | table below; 0 is OK |
| 7 | shard | u32 | the request's |
| 11 | batch | u64 | the request's; after OK, the store's batch count |
| 19 | lines | u32 | records that follow |
| 23 | digest | 64 | the request's digest |

When the request's header did not parse, shard, batch and digest are zero.

An OK answer continues with one record per decided line, then `head 64` (the CHAIN/v1 head after the batch), `root 64`
(Root_b, the state root after the batch) and the extension below. A refusal has `lines = 0` and nothing after the
header, and it changes no state.

Extension, added by the implementer, rr-core to confirm (a 1:1 transcription of today's text fields; `blob2` is `u16`
length then bytes):
- `hold 16`: the grant refusal word, zero padded, or all zero. When set the batch decided nothing and has no records.
- `grant 64`: the grant id the batch was decided under, all zero when none.
- `auth 208`: the shard's authority record after the batch (`Worker.encAuth`): `key-set pin 64 ‖ key-set epoch u32 ‖
  key-set head 64 ‖ day u32 ‖ checkpoint 64 ‖ grant floor u64`. The batch digest binds it (section 5). Store open, every
  replayed batch and the checkers refuse a record that changes the pin or lowers the key-set epoch or the grant floor
  from the record before it (`ChunkIo.authFollows`).
- notes `u32`, each a `blob2`: the bypass notes.
- leaves `u32`, one per request in request order, each: `outcome u8 ‖ reasons u32 (bit 24 UNENCODABLE_PAYMENT, bit 25
  SCOPE) ‖ authority u8 ‖ bypass flag u8` (0 none, 1 a bypass released the payment; any other value is refused), then
  when the flag is 1 the bypass id (64, not all zero), then `input 64` (INPUT/v6, `ENGINE_V3.md` §18). 71 or 135 bytes.
  An outcome or authority over 2, or a reason bit over 25, is refused.
  The leaf copies no request field: the host computes `input` from the request it sent, refuses the answer when they
  differ, and builds the token leaf from its own fields (`ENGINE_V3.md` §17, §25).
- adds `u32`, each a `blob2`: the rows the batch appended, in order.

Record, 16 bytes:

| Offset | Field | Width | Values |
|---|---|---|---|
| 0 | index | u24 | the line's position in the request |
| 3 | outcome | u8 | 0 ALLOW, 1 HOLD, 2 HUMAN_REVIEW |
| 4 | rule | u8 | 0 decided, joins no set; 1 joins the released set; 2 joins the unresolved set; 3 field over width; 4 another line of its payment over width; 5 joins the released set because its payment is in the engine's bypasses (rr-core to confirm) |
| 5 | reasons | u32 | bit i is `reasons[i]` (below); bits 24-31 are zero |
| 9 | chunk | u32 | counterpart reference; `0xFFFFFFFF` is none |
| 13 | row | u24 | counterpart reference; `0xFFFFFF` is none |

Reason bits, in the byte order of their names (`Rules.reasons`):

| Bits | Reasons |
|---|---|
| 0-3 | ALREADY_DECIDED, CAP_MEMBER_MONTH_DUPLICATE, COLLIDES_WITH_UNRESOLVED_NEAR, DUPLICATE_OF_UNRESOLVED |
| 4-7 | FFS_DUPLICATE_LINE, FFS_DUPLICATE_UNVERIFIED, FFS_NEAR_DUPLICATE, MEMBER_DECEASED |
| 8-11 | MEMBER_DECEASED_UNVERIFIED, MEMBER_NOT_ENROLLED, MEMBER_NOT_ENROLLED_UNVERIFIED, POSTING_CAP |
| 12-15 | PROVIDER_DECEASED, PROVIDER_DECEASED_UNVERIFIED, PROVIDER_EXCLUDED, PROVIDER_EXCLUDED_UNVERIFIED |
| 16-19 | SERVICE_DATE_FUTURE, SERVICE_DATE_INVALID, STALE_DMF, STALE_ENROLLMENT |
| 20-23 | STALE_EXCLUSION, STALE_PROVIDER_DEATH, STALE_RELEASED, STALE_UNRESOLVED |

A decision's reasons are always `reasons.filter p` (POSTING_CAP holds included), so the mask loses nothing.

Record order:
1. The decided lines, in decision order.
2. The lines held for width, in input order.

Identical input lines take their positions in input order. The record indices are a permutation of the input positions
(`records_perm`).

Counterpart reference (`firstRef`): this is the store position of the first of the line's keys whose entry gives a
counterpart. The keys are tried in the order released exact, near, id, then unresolved exact, near, id, at the state
before the batch. The position is that key entry's live row, the row `ChunkIo.lookupE` reads. A line with no
counterpart, and every line with rule 3 or 4, has none. The chunk layout must keep every chunk below 2^24−1 rows.

The decoder (`decodeAns`) checks structure only. It computes no policy. It accepts nothing but canonical bytes:
- rules 3 and 4 mean HOLD, with zero reasons and no reference;
- rule 1 means ALLOW with no reason; rule 2 means HOLD or HUMAN_REVIEW with a reason set;
- for rules 0 and 5, ALLOW exactly when no reason bit is set. Rule 5 is the only way a HOLD is released, and only for
  a payment in the engine's bypasses; the decoder cannot check that, `record_binds` does;
- chunk and row are both none or both a position;
- the indices are a permutation of `0..lines−1`;
- the answer is consumed exactly.

The host HOLDs every line of the batch on any decoder failure.

Statuses:

| Code | Word | Code | Word | Code | Word |
|---|---|---|---|---|---|
| 0 | OK | 7 | HEAD | 14 | CORRUPT |
| 1 | MAGIC | 8 | SHARD | 15 | INIT |
| 2 | LENGTH | 9 | LOCK | 16 | KILL |
| 3 | DIGEST | 10 | FILES | 17 | NUMBER |
| 4 | RECORD | 11 | IMAGE | 18 | FULL |
| 5 | NOT_NEXT | 12 | REPLAY | 19 | TREE |
| 6 | CONFLICT | 13 | IO | 20 | FRAME |
|  |  |  |  | 21 | PIN |

Codes 9-20 are the store's words of `FLAT_V1.md` §6-7. `PIN`: the store was begun under another key-set pin than the frame's. `KILL`: a batch killed a row of a chunk that is not installed, which the store refuses before writing anything. The host HOLDs every
line as `flat_<word>`, the word in lower case.

## 5. What the record binds

`join H s q r` rebuilds a line's answer from its record, the request and the state before the batch, with no policy:
- the line is the request's line at `index`;
- the outcome and reasons come from the record;
- the counterparts are recomputed as `Ix.counterparts` over the batch's fetched index, the same function the decision
  used.

`record_binds` says the joined records equal the decision values for every line. `Ans.text` is the human text, produced
on demand, and never on the decision path:
- a decision gives `Run.render`;
- rule 3 gives the line with `*` for each wide field, then ` HOLD UNENCODABLE_FIELD`;
- rule 4 gives the line, then ` HOLD UNENCODABLE_PAYMENT`.

Where each part of today's text answer is now:

| Today | Now |
|---|---|
| `RULES_LINE`: line fields | the request's line at `index` |
| `RULES_LINE`: outcome and reasons | the record's `outcome` and `reasons` |
| `RULES_LINE`: `with=` counterpart ids | recomputed by `join`; `chunk, row` names the first key entry |
| `HOLD UNENCODABLE_FIELD` / `_PAYMENT` | rules 3 and 4; a wide value is not carried (`*` in the text) |
| `RULES_ADDS` released and unresolved rows | the lines of the rule 1, rule 5 and rule 2 records, in record order (`rows_of_records`); the extension's `adds` |
| `RULES_FLAT_HEAD` head, batches, root | the trailer's head, the header's batch, the trailer's root |
| `RULES_FLAT_HEAD` batch digest | rebuilt by the host: `H(dom CHAIN ‖ 0x03 ‖ leb len(auth) ‖ auth ‖ delta)`, `auth` the extension's record and `delta` the rule 1 rows, then the rule 2 rows (`FLAT_V1.md` §2; `batchDigest_binds`) |
| `RULES_FLAT_HOLD word` | the status |
| `RULES_FLAT_COUNTERS`, `RULES_FLAT_PROF` | not in the answer (bench only) |
| `RULES_PAY`, grant hold, bypass notes | the extension's leaves, hold and notes |
| `RULES_VECTORS`, `RULES_GOT`, `RULES_VECTOR_MISMATCH` | the test runner's text frames only |

The host checks `head = H(dom CHAIN ‖ 0x02 ‖ prev ‖ digest ‖ root)` before it seals, as it does today. It signs the
head. The custody counter and the ML-DSA-87 signature are added by the host's custody when it seals the checkpoint. They
are not in the engine's answer, because the engine holds no key.

## 6. Retry (Constitution III.3)

Let n be the number of batches in the engine's log.

| Request | Answer |
|---|---|
| another shard | `SHARD` |
| batch n+1, with `prev` the engine's head (when there is no store, the genesis head `chainStart` over the shard and the key-set pin) | decided, logged with the request's digest and the answer bytes |
| batch n+1, with any other `prev` | `HEAD` |
| batch n (n > 0), with the logged digest | the logged answer, byte for byte, and no state change (`serve_retry`) |
| batch n, with another digest | `CONFLICT` (`serve_conflict`) |
| any other batch | `NOT_NEXT` (`serve_not_next`) |

The log changes only by the next batch (`serve_log`).

What this asks of the other layers (TODO slice 0, StoreLog: the durable retry log is the store's):
- The store's log entry keeps the request digest and the answer, or enough to rebuild the answer from the state before
  the batch, since the answer is a pure function of that state and the request.
- Load keeps an unsealed last batch; it no longer puts one back.
- The host keeps a request's bytes from before it sends them until it has sealed the answer. After any loss it resends
  the same bytes. It never decides that batch number again with other contents.
- A batch that was decided but not sealed is therefore sealed later or not at all; it is never replaced.
- A decided batch is never replaced while it can still seal. A batch whose commit was refused because the floors rose is voided by
  reopening the engine at the signed head, as after a crash, and nothing of it was paid; the host then drops its stored frame and builds a
  new one.

## 7. What the codec replaces

The codec has landed. The text path below is still present for the `gate_rules` test runner, and is to be deleted when
the runner moves to frames.


- The answer text path in `commitChunk`:
  - the `RULES_LINE`, `RULES_ADDS` and `RULES_FLAT_HEAD` lines;
  - `Run.quarantined`'s sorted text in the answer;
  - `hexOf` in the answer;
  - `flat init` and `flat open` (whose salt was unused).
- `Run.natStr` and its `#guard`, and `natStr_eq` where it exists. They were only for answer text speed; on-demand text
  can use `toString`.
- On the frame path: the text intake laws (`fieldsFast_eq`, `unhexFast_eq`) and the answer use of `rowBytesFast` and
  `rowBytesFast_eq`. These stay for the test runner while it reads text.
- Kept:
  - every decide theorem (`decideBatchIdx_eq`, the `FastEq` equalities, `keep_fits`);
  - the chain, chunk and store statements;
  - the transport laws in `Engine/FrameLaws.lean`;
  - the test runner's text frames.
- Regenerated: the `gate_engine` pin, wire vectors, golden vectors and the formats list.

Changes from today's behaviour:
- The store directory and shard are fixed when the engine starts.

## 8. Change record

2026-11-08: the new engine takes on the flat chain's authority record (protected change: wire format and digest domain).
- Predicate changed: the batch digest was `H(dom CHAIN ‖ 0x03 ‖ delta)` and the genesis head did not hash the key-set
  pin; it is now `H(dom CHAIN ‖ 0x03 ‖ leb len(auth) ‖ auth ‖ delta)` and `chainStart` hashes the pin. The request
  gains `kfloor u32`; the answer extension gains `auth 208`; status 21 `PIN` refuses a store begun under another key-set
  pin.
- Invariant: a signed head binds the shard's key-set pin, key-set epoch and grant floor, so a store, a replayed log or
  an answer cannot roll back to a superseded key set or a lower grant floor, or continue under another key set,
  without a SHA3-512 collision or a refusal; a key set older than the tenant's newest is refused on every shard.
- Evidence: the flat chain already binds this record and refuses these rollbacks
  (`tests/test_flat_host.py`: `test_the_shard_the_date_and_the_pin_change_the_genesis`,
  `test_a_replay_refuses_another_pin_and_a_lowered_epoch_or_floor`,
  `test_a_shard_begun_under_another_key_set_pin_cannot_continue_under_the_tenant_pin`). Under the previous digest the
  record was bound only inside the state root, which the host cannot open, so the host could not check it from the
  head, and the genesis head was the same under any key set.
- Disposition: strengthen. Replacement control: `batchDigest_binds`, `chainStepR_binds`, `chain_binds`,
  `startIn_inj`, `authFollows_iff`, `authFollows_trans`, `admit_keyset_floor`, the pin and floor checks at store open
  and replay in the engine and the checkers, and the trunk tests above.
- Scope: every store, frame and checker of the new engine from this change on, with no end date. Stores written under the
  previous digest do not open; the engine is not activated, so no such store holds product state.
- Claims withdrawn: none.

2026-11-09: provider ids widen to the line's provider width (protected change: wire format).
- Predicate changed: a provider death id, an exclusion id and an enrollment plan were `u64`; they are now `n21`, the width
  of a line's payee and rendering provider. Rows are 25, 29 and 62 bytes.
- Invariant: every provider a line can name can be sent as a feed row, so an excluded or dead provider's line meets its
  row and holds. Under `u64` a provider whose identifier number needs more than 8 bytes (any 10-digit NPI: 11 bytes)
  could not be sent; the host marked the whole feed missing, so every line went to review and the provider's own line
  could never hold `PROVIDER_EXCLUDED` or `PROVIDER_DECEASED`.
- Evidence: `Frame/Spec.lean` `pdeathC`, `exclC`, `spanC` (8-byte ids) against `Rules/Request.lean` `idNat` (a line's
  provider is `0x01` then its identifier's bytes) and the 21-byte provider field of the store line; run fl-npi-before.
- Disposition: replace. Replacement control: `tests/test_right_rail_gate_ffs.py`
  `test_a_line_billed_by_an_excluded_10_digit_npi_holds_and_a_clean_one_is_allowed` (the real engine holds the
  excluded NPI's line and allows the clean one), and the round-trip and length theorems of `Frame/Spec.lean` over the new
  widths.
- Scope: every request frame from this change on, with no end date. The host and the engine change together; the engine
  is not activated, so no frame of the previous widths is product input. Feed pins are unchanged (SNAPSHOT/v1 hashes
  ids at the rules' identifier width).
- Claims withdrawn: none.
