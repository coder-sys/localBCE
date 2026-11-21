# Trunk step 2: the frame and width change, with no new rule — design for owner approval

## Status

- **Owner decision, 2026-11-15: "Route A, bounded wait" (decisions 1 and 2).** The rr-core request (frame v2 with the two feeds, the fc89f9e5 bundle, the pinned signer, the reserved numbers) is sent by the owner; the owner approved the remaining 20 defaults the same day ("i do approve"). No date was given, so the bound is 2026-11-22 (one week) unless the owner sets another. Route-independent work starts now, in the order of section 7.1: the signer-free harness and its "before" decisions first, then the types, then the answer side.
- **Sent, 2026-11-15.** The owner sent the rr-core request (RR_CORE_REQUEST_DRAFT.md, revised the same day to attach this design, name the 2026-11-22 bound and say the answer side is built). Route-independent work done by then, local only on `codex/rightrail-trunk-step2`: the signer-free harness (a0da49e8), the types and idx lemmas (9330572b), the answer side (19e001c7) and the route-independent spec page fixes (c7ad3c65). Waiting: rr-core's answer or 2026-11-22 for the request side; the pinned signer for the final commit (Decision 20).
- Draft for owner approval, 2026-11-15, revision 3. Revision 2 applied the 21 findings of the accuracy and completeness reviews (two blockers, six majors, thirteen minors). Revision 3 applies the 7 findings of the final check (three majors, four minors): the signer-free vectors update, the `RR_GATE_UNSIGNED` switch and lazy `GENESIS`, the re-derived Route B estimate, the `verify` threading through OneProc, the DecideRows importers, the ReadB in-row offsets and two more stale docs. Each was checked against the trunk code. Nothing has been built, edited or committed for it.
- Worktree `C:\Users\sruja\Downloads\localBCE-trunk`, branch `codex/rightrail-trunk` at 5ad4dc6f. `rightrail/` is RightRail trunk fc89f9e5, a byte-identical zip import.
- This implements TRUNK_MIGRATION_PLAN.md step 2 (lines 191-277), under its Decisions 2, 3, 4, 8 and 9, which the owner approved with all defaults.
- The owner is RightRail lead and authors or approves every change inside `rightrail/`. Every protected change carries the 8-field record of rightrail/CONSTITUTION.md:174-183 (section 9). Checks gate every commit: a failed or skipped check stops the commit.
- Every Lean or TCB run goes through `scripts/rr_guarded_interim.ps1` and is labelled interim evidence.
- Paths are cited as rightrail/path:line at fc89f9e5. Lean paths are under rightrail/lean/BlindLedger/Gate/ unless written in full. "Spec" alone means Frame/Spec.lean.
- This design merges two route designs and four read-only site surveys. Where they disagreed, the choice made here is stated and listed as a decision.

## 1. Summary

### What step 2 must do

- Add two member feeds to the request frame: eligibility (pin kind 7) and share of cost (pin kind 8).
- Number answer record and leaf reason bits by `Reason.idx` (Decision 4).
- Widen the leaf and record reason fields to u64, with the leaf-only codes at bits 62 (UNENCODABLE_PAYMENT) and 63 (SCOPE).
- Add the `Elig` and `Soc` types to Rules/Spec, with no reasons and no rules.
- Update Engine3, Flat, the host, the tests and the spec pages, and re-pin `gate_engine`.
- Change no decision. `PAIRS_DIGEST` (rightrail/tests/test_gate_throughput.py:44-48) must not move. Because that test cannot run on this machine (section 7.1), a signer-free decision check carries this claim here.

### What the trunk has today

- The request side is entirely FRAME/v1:
  - `version := 1` at rightrail/lean/BlindLedger/Gate/Frame/Spec.lean:121;
  - the digest is `H(domain "FRAME" ++ body)` over the whole body (Frame/Spec.lean:169, :302; Frame/Fast.lean:2450; Engine3/DecodeB.lean:21, :173);
  - members are n33 and rows are not ordered (Frame/Spec.lean:68-73, :220-229);
  - the host sends version 1, `FRAME/v1` and unsorted rows (rightrail/app/right_rail_gate_decide.py:484, :501, :522).
- ENGINE_V3's frame v2 is specified but not built: the §17 `body′`/`rd_i` digest, the §19 rows and the §19 order rule exist only as text (rightrail/conformance/ENGINE_V3.md:603-616, :661-685).
- A §19-shaped feed decoder exists only in a test bench: `FeedsX.decode` (Engine3/RowsStore.lean:341-370, strides 36/25/29/61 with order checks), called only by Flat/DecideBench.lean:526-565.
- **ENGINE_V3 §20 steps 1 (exact rows) and 2 (store widths) are met by Engine3/hist3 only.** The pinned `gate_engine` runs the revision 1 decision path and the revision 1 Flat store (rightrail/conformance/ENGINE_V3.md:15-17).
  - Flat/DecideRows.lean is not in `gate_engine`'s closure. It imports Engine3.ExactRows (Flat/DecideRows.lean:1). Four modules import it: Engine3/RowsStore.lean:1, Engine3/Step.lean:3, Flat/DecideBench.lean:1 and Flat/DecideCut.lean:1. None of the four is in the `gate_engine` closure, which reaches Engine3 only through Engine3.Sha3Fused. Flat/Worker.lean:1-5 imports ChunkIo, Io, Rules.Run, Verify and Frame.Fast, none of which reaches it.
  - rightrail/artifacts/gate-verify/PROVENANCE.txt:116 (2026-11-01) says DecideRows was then in the closure. That note is historical; later closure changes superseded it.
  - The §20 step 2 proofs in Engine3 are also unwritten.
- INPUT/v6 and the answer extension (input, grant id, notes, adds, auth 208) are built and proved, still under answer header version 1.
- No proof is open: rightrail/tests/lean_sorry_allowlist.txt is empty and there is no `sorry` under Gate. Every proof this step touches must be fully re-proved.
- **The ML-DSA-87 signer `rr_gate_mldsa87.exe` is not on this machine** (docs/integration/LOG.md:303-307). It is needed to import the shared test harness at all: `_gate_shards.py:105` calls `au.standing()`, which signs through `fx.det_sign` and `fx.keypair` (rightrail/tests/_gate_authority.py:38, :46; rightrail/tests/test_right_rail_gate_formats.py:162-174), which run the signer binary. 29 files under rightrail/tests import that harness or a module built on it, and LOG.md:325-326 records 25 test files that cannot be collected without the signer. They include test_gate_throughput, test_decode_fuzz, test_flat_host, test_flat_worker, test_gate_authority_frames and test_right_rail_gate_decide.

### The two routes

| | Route A: FRAME/v3 = §17/§19 v2 plus two feeds | Route B: FRAME/v3 over the FRAME_V1 body |
|---|---|---|
| Request digest | `H("FRAME/v3" ‖ body′ ‖ rd_1..rd_n)`, §17 shape | `H("FRAME/v3" ‖ body)`, v1 shape |
| Rows | §19: member 32 bytes with `0x01` implied, rows ordered or refused `RECORD` | v1: member n33, no order rule |
| Row widths dmf/pdeath/excl/span/elig/soc | 36/25/29/61/62/45 | 37/25/29/62/63/46 |
| Check order | length walk, then digest, then parse | digest over raw bytes, then parse (unchanged) |
| New proofs | `walkPrime` and its lemmas, `frameV3Pre_inj`, `walk_encodeBody`, `walkFast_eq`, digest assembly, `feedOrder_decode`, member codecs under a `Lawful` with a weakened first conjunct, a chunked `decodeB_eq` hash block | two more binds in three proved decoders, which still re-proves the six-feed Spec round-trip and stab proofs, the Fast `bodyP` chain and DecodeB's `body_rel` (section 8); `contextV2Pre_inj` |
| Shared test header | small-number DMF and span rows cannot be sent; the frame header drops them (5.3) | unchanged: n33 carries small numbers |
| Answer side | identical on both routes | identical on both routes |
| Signer-free decision check | needed | needed |
| Authoring effort | about 29-47 working days (6-9.5 weeks) | about 14-23 working days (3-4.5 weeks), derived line by line in section 8 |
| Main risk | the chunked DecodeB proof and the new refusal order | a fork from ENGINE_V3 §17/§19 |
| Divergence from upstream | domain number and two descriptors only | domain number, digest, row widths and order rule |
| If upstream ships v2 later | small: re-number, or adopt theirs | all of Route A's request work is still owed, over six feeds, plus a second re-pin cycle: about Route A plus 1-1.5 weeks in total |

- If rr-core folds the two feeds into their own v2 and builds it, we import their v2 and do the answer side, the types, the test header change, the signer-free check and the re-pin: about 11-17 working days.
- Machine time is no longer the bottleneck. A full trunk build here takes about 8 minutes, and `gate_engine` reproduced the pin 2d720b52 byte for byte (docs/integration/LOG.md:311-326). One re-pin cycle (three builds, the TCB live run and the statement-pin run) is hours, not the 1-3 weeks plan step 2 estimated.
- The signer is the bottleneck for evidence. Without it the throughput digests and the full golden vectors file cannot be regenerated, so the step cannot be committed complete (Decision 20). The vectors' `answer`, `context2` and `frame3` lines need no signer and are updated here (5.3), so `gate_vectors` stays green.

### Recommendation

- **Route A**, as the plan's Decision 2 default already says. It keeps us on the specified §17/§19 shape, so the only fork from upstream is a version number and two descriptors. The cost gap to Route B is about 3-5 weeks (section 8), so this is a real owner trade-off.
- **Ask rr-core first, but do not idle.** Send the question now, together with the request for the pinned signer. Author the work that is the same on every route while waiting: the answer side, the `Elig`/`Soc` types, the DecideRows width work and the signer-free decision check. If rr-core has not answered by a date the owner sets, build FRAME/v3 as Route A.
- **Do not carry §20 steps 1 or 2 into `gate_engine`.** Both are met by Engine3/hist3 only and no code needs them in `gate_engine`; carrying them would be the §16 Flat-store replacement, which is months of work (ENGINE_V3.md:546-580).
- **Defer reading and capping the new feeds to step 3.** No rule reads them in step 2, and capping them now would add POSTING_CAP holds for data no rule uses. That departs from plan lines 233-246 and is a decision below.
- **Hold the commit for the signer by default** (Decision 20), so no known-stale pin is committed.
- Route B is cheaper by about 3-5 weeks now, but costs about 1-1.5 weeks more overall if upstream v2 lands soon. It needs the separate explicit owner word that Decision 2 requires.

## 2. Exact formats, Route A

### 2.1 Request header, 82 bytes, layout unchanged

| Offset | Field | Bytes |
|---|---|---|
| 0 | `RRDQ` | 4 |
| 4 | version u16 LE = **3** | 2 |
| 6 | shard u32 | 4 |
| 10 | batch u64 | 8 |
| 18 | digest | 64 |

All integers are little-endian, as in FRAME_V1.

### 2.2 Body and context

Offsets are from the body start (frame offset 82).

| Body offset | Field |
|---|---|
| 0 | today u32 |
| 4 | asOf u32 |
| 8 | prev 64 |
| 72 | redo count u32 |
| 76 | descriptor 1, DMF (kind 1) |
| 153 | descriptor 2, provider death (kind 2) |
| 230 | descriptor 3, exclusion (kind 3) |
| 307 | descriptor 4, enrollment span (kind 4) |
| **384** | **descriptor 5, eligibility (kind 7)** |
| **461** | **descriptor 6, share of cost (kind 8)** |
| **538** | feed rows, in feed order |

- The four existing descriptor offsets and `prev` stay put. The context section grows from 384 to 538 bytes.
- Each descriptor is 77 bytes, unchanged: `state u8 ‖ asOf u32 ‖ count u32 ‖ rows u32 (at +9) ‖ pin 64`. Its checks stay in `desc` (Frame/Spec.lean:214-218).
- After the rows: redo payments (261 bytes each), then the authority section, unchanged (Frame/Spec.lean:141-152):

      pin 64 ‖ floor flag u8 ‖ floor u64 ‖ kfloor u32 ‖ grant blob ‖ keyset blob ‖ release blob ‖
      nk u32 ‖ (epoch u32 ‖ blob)* ‖ nb u32 ‖ blob* ‖ nq u32 ‖ (len u32 ‖ request)*

- Context: `ctx = SHA3-512("RR/GATE/CONTEXT/v2" 0x00 ‖ body[0 .. c))`, where `c` is the body offset of `nq`. A new domain is needed because the context hash does not cover the header version (Frame/Spec.lean:172-180). `ctxBytes` is computed length-from-end and needs no change.
- PAYMENT/v1, INPUT/v6 and BATCH-INPUT/v1 are unchanged.

### 2.3 Rows (§19 style)

"member 32" is the n33 member with its `0x01` top byte implied. Ids are 21 bytes.

| Feed | Pin kind | Row | Bytes |
|---|---|---|---|
| DMF | 1 | member 32 ‖ date u32 | 36 |
| Provider death | 2 | id 21 ‖ date u32 | 25 |
| Exclusion | 3 | id 21 ‖ start u32 ‖ stop u32 | 29 |
| Enrollment span | 4 | member 32 ‖ plan 21 ‖ start u32 ‖ stop u32 | 61 |
| Eligibility | 7 | member 32 ‖ aid 21 ‖ level u8 ‖ start u32 ‖ stop u32 | 62 |
| Share of cost | 8 | member 32 ‖ month u32 ‖ cents u64 ‖ met u8 | 45 |

- Order rule: within each feed, rows are non-decreasing field by field, each field compared as a number. Otherwise the frame is refused `RECORD`. Comparing the member as 32 bytes or as its n33 value gives the same order.
- Host fallback: a member without the `0x01` top byte, or an id of 256^21 or more, cannot be sent. The host sends that feed as state 2. The shared test header today carries such members, so section 5.3 changes it.
- Pins are SNAPSHOT/v1 `pinInput` over the canonical `.fields` encodings, unchanged in kind (idWidth 129). Checked against 90ffd3f9:rightrail/lean/BlindLedger/Gate/Rules/Spec.lean:186-200, 558-562:
  - `Elig.fields = [(129,member),(129,aid),(1,level),(4,start),(4,stop)]`;
  - `Soc.fields = [(129,member),(4,month),(8,cents),(1,met)]`.
- No range check on `level` or `met` in the step 2 decoder. At step 3 a `level` or `met` value above 1 makes the row malformed, so the snapshot is unusable and its lines get STALE or `_UNVERIFIED`, not a value read as 0 (90ffd3f9:rightrail/lean/BlindLedger/Gate/Rules/Spec.lean:256-261, `okElig`/`okSoc`; `usable` requires every entry `ok`).

### 2.4 Digest

      c        = body offset of nq            (= |ctxBytes|, Frame/Spec.lean:172-174)
      body′    = body[0 .. c+4) ‖ len_1 u32 ‖ … ‖ len_n u32
      rd_i     = SHA3-512(request_i)
      digest   = SHA3-512("RR/GATE/FRAME/v3" 0x00 ‖ body′ ‖ rd_1 ‖ … ‖ rd_n)

This is the literal §17 formula (ENGINE_V3.md:603-616) with only the domain changed.

### 2.5 Check order

1. Header, else `MAGIC` or `LENGTH`.
2. `walk`: read only the descriptor row counts, the redo count and the authority section's counts and blob lengths. It must end exactly at the end of the frame. Any failure is `LENGTH`.
3. The digest. A mismatch is `DIGEST`.
4. The full body parse, which gives `RECORD` and the other refusals, including the order rule.

This keeps §17's "digest before reading any other body byte": the lengths are the bytes needed to form `body′`. The difference from v1: a frame whose lengths do not walk is refused `LENGTH` before `DIGEST`.

### 2.6 Answer, header version 3

- Header, 87 bytes, unchanged in layout: `RRDA ‖ version u16 = 3 ‖ status u8 ‖ shard u32 ‖ batch u64 ‖ count u32 ‖ echo 64`.
- Record, 16 → **20** bytes: `pos u24 ‖ outcome u8 ‖ rule u8 ‖ reasons u64 ‖ chunk u32 ‖ row u24`. `chunk` moves from offset 9 to 13 and `row` from 13 to 17.
- Extension:

      head 64 ‖ root 64 ‖ hold 16 ‖ grant id 64 ‖ auth 208 ‖ notes u32 (blob2)* ‖
      leaves u32, each: outcome u8 ‖ reasons u64 ‖ authority u8 ‖ flag u8 ‖ (bypass 64) ‖ input 64
      ‖ adds u32 (blob2)*

  A leaf is 71/135 → **75/139** bytes.
- `an` stays `H(domB "ANSWER" ‖ bytes before head)`. The version sits inside those bytes, so no new domain is needed.
- One `Frame.version := 3` serves request and answer; the constant is not split.

### 2.7 Bit numbering

- A rule reason sits at bit `r.idx` in records and leaves.
- Today `Reason.idx` equals the name position for all 24 reasons (Rules/Spec.lean:124-144), so no rule bit value moves in step 2. Only widths, the version and the two leaf-only codes change bytes.
- Leaf-only codes: UNENCODABLE_PAYMENT `2^24` → `2^62`, SCOPE `2^25` → `2^63`. Each is emitted alone (Rules/Run.lean:426, :483; Engine3/Step.lean:246, :253).
- `Rec.ok` stays `reasons < 2^Rules.reasons.length` (Frame/Spec.lean:568-576).
- `Leaf.ok` becomes `outcome ≤ 2 && reasons < 2^64 && reasons % 2^62 < 2^Rules.reasons.length && authority ≤ 2`. This is the loose form, matching the host rule "62/63 only in a leaf".
- `unmask` keeps name order, so `join`, `Run.render`, the "OUTCOME REASONS" text and `PAIRS_DIGEST` do not move.
- The signed masks (APPROVAL/v2 `holds`, `overrides`) are already idx-numbered and stay u32 (rightrail/lean/BlindLedger/Gate/Authority.lean:20, :89, :107). Nothing changes there in step 2.

### 2.8 Digest domains

- New: `RR/GATE/FRAME/v3\0` and `RR/GATE/CONTEXT/v2\0`. Both are free in the trunk. `FRAME/v2` appears only in ENGINE_V3.md text (:155, :610).
- `domain` always appends `/v1` (rightrail/lean/BlindLedger/Gate/Spec.lean:48), so both are Frame-local literals, as `inputV6Pre` already is (Gate/Spec.lean:203).
- Gate/Spec.lean is in both the `gate_engine` and the `gate_verify` closures. It stays untouched, so `gate_verify` does not move.

## 3. What moves the pin, and what is out of scope

- The `gate_engine` closure (root `Gate.Engine.EngineMain` in rightrail/lean/lakefile.toml:73-76) includes, among others:
  - Flat/{Bin, Chunk, ChunkIo, ChunkTheorems, Io, Model, Store, StoreLog, StoreTheorems, StoreTombs, Theorems, Worker}, Frame/{Spec, Fast}, Rules/{Fast, FastEq, Request, Run, Spec, Theorems} and Engine3/Sha3Fused;
  - Engine/{EngineMain, OneProc}, Gate/Spec, Authority, Keyset, Payer, Producer, ProducerTheorems, Verify, Batch, Anchor, AnchorTheorems, MlDsa87, OnepIndex, SnapshotV2 and Gate/Theorems.
- Frame/Spec, Frame/Fast, Flat/Worker, Rules/Spec, Engine/OneProc and Engine/EngineMain change, so `gate_engine` moves. The last three carry the `verify` parameter of sections 4.4 and 7.1, a decision-neutral refactor: Flat/Worker uses it, OneProc threads it, EngineMain passes `mlDsaOk`. Rules/RulesCrashtest.lean:10 (root of the unpinned `gate_rules_crashtest`) is a third `OneProc.run` call site and also passes `mlDsaOk`. OneProc is also embedded by `RulesMain` (`embed_OneProc`, rightrail/lean/lakefile.toml:153), so its edit moves the Run digest as well, which Rules/Spec moves anyway.
- DecideRows, Frame/Answer, PayTheorems and the other Engine3 modules are outside it. They must still build and keep `gate_hist3`/`gate_verify3` in step with `gate_engine` (§20: both engines move together, ENGINE_V3.md:702-703).
- `gate_verify` (root `Gate.VerifyCli`) shares Gate/Spec.lean with `gate_engine` but has no Rules, Frame, Flat or Engine3 import, and does not move. Neither does `blind_financial_worker`.
- **Out of scope:**
  - ENGINE_V3 §20 steps 1 and 2 in `gate_engine` (decision 3);
  - `Ctx.eligibility`/`Ctx.shareOfCost`, `ctxOf` snaps for kinds 7/8, `Feeds`, `FCtxInv`, `feedCapped`, `fcap_line`, `Ix`/`Ix.build`, `FeedsX`, ReadB reading the new rows, Engine3 `feedPins` and `snapK` for kinds 7/8, and the 1,024-fact cap for the new feeds: all deferred to step 3 with the rule that reads them (decision 6);
  - reusing `rd_i` in the bypass check (Rules/Run.lean:454, :533; Engine3/Step.lean:249);
  - `pinInputW_eq`, `feedW_eq`, `feedW_at_eq` (Engine3 keeps its sort, so they are not yet needed) and `decodeAns_leafCount`;
  - rightrail/tools/gate_rules_data.py:14-18 (text-runner kinds 7/8), which belongs to step 3 and GATE_RULES_V2.

## 4. Lean changes, in build-dependency order

### 4.1 Rules/Spec.lean (in `gate_engine`)

- After `Span` (rightrail/lean/BlindLedger/Gate/Rules/Spec.lean:189-193): `structure Elig where member aid level start stop : Nat` and `structure Soc where member month cents met : Nat`, documented "synthetic, not legally verified".
- After :531: `Elig.fields` and `Soc.fields` as in 2.3.
- The kinds comment at :510-516 gains 7 = eligibility and 8 = share of cost.
- After the `#guard` at :151:
  - `theorem idx_dense : ∀ j < reasons.length, ∃ r ∈ reasons, r.idx = j := by decide`. The plan says this comes "from the dense-idx `#guard`"; a `#guard` gives no proof term, so it is proved by `decide` (not `native_decide`, which the axiom pins forbid). Fallback if `decide` is slow: `intro j hj; interval_cases j <;> exact ⟨_, by decide, rfl⟩`.
  - `theorem reasons_len_le : reasons.length ≤ 62 := by decide`, labelled "u64 field budget minus the two leaf codes; not a total-count guard".
  - **Required:** `theorem idx_len (r : Reason) : r.idx < reasons.length` and `theorem reasons_nodup : reasons.Nodup`, moved here from Flat/DecideRows.lean:1601 and :1667 (both `decide`). The new `maskOf_lt` and `unmask_maskOf` proofs in Frame/Spec (inside `gate_engine`) need them, and Frame/Spec cannot import DecideRows without pulling it and Engine3 into the closure (Frame/Spec.lean:1-3 imports only Flat.Model, Rules.Run and Flat.Bin). DecideRows keeps its two names as one-line restatements of these, so its callers and any statement-pin entries for them stay as they are.
  - **As built (2026-11-15):** the Rules/Spec lemma is named `Rules.reasons_list_nodup`, not `reasons_nodup`, because `BlindLedger.Gate.Rules.reasons_nodup` already exists with another statement in Rules/Theorems.lean:253 (`(decideLine c seen l).reasons.Nodup`), which imports Spec. DecideRows keeps `Rows.reasons_nodup` as its restatement. Every later mention of the Rules/Spec `reasons_nodup` in this design (4.7, 4.10, 7.2) means `Rules.reasons_list_nodup`; in particular the Frame/Spec `unmask_maskOf` proof cites `reasons_list_nodup`.
  - **As built (2026-11-15), answer side:** DecideRows adds `reasons_len_le32` (`reasons.length ≤ 32`, by `decide`), used only inside DecideRows to bound the rule bits. It is not added to the axiom pins: it is a local width step, and `reasons_len_le` (≤ 62) is the pinned budget. The host's `REASON_IDX` is a literal table, and `tests/test_gate_answer_v3.py` checks it against the `Reason.idx` arms read from Rules/Spec.lean, so a reason sorting into the middle of `REASONS` cannot shift a bit unnoticed.
- No `Ctx` change (decision 6). This still moves Run's digest (`RULES_SOURCE`) and the statement pins. No rule changes.

### 4.2 Frame/Spec.lean (in `gate_engine`)

Constants (near :119-123):
- `version : Nat := 3`. Every use follows (:168, :210, :588, :606; Fast :2447, :3819; Answer :68 and others; DecodeB :171; Step :282).
- `frameDom`, `contextV2Pre b := "RR/GATE/CONTEXT/v2".toUTF8.toList ++ [0] ++ b`, `contextV2 H b := H (contextV2Pre b)`.
- `leafUnencodable : Nat := 2^62` and `leafScope : Nat := 2^63`.

Codecs (:68-73):
- `m32 n := if n / 2^256 = 1 then n % 2^256 else 2^256`. The sentinel cannot fit 32 bytes, so `le` refuses it.
- `dmfC` `[32,4]` and `spanC` `[32,21,4,4]`, decoding the member as `2^256 + m`; `ofNums` refuses `m ≥ 2^256`.
- New `eligC` `[32,21,1,4,4]` and `socC` `[32,4,8,1]`. `pdeathC` and `exclC` are unchanged.
- `rowsSorted c xs : Bool`: adjacent pairs satisfy lexicographic `≤` on `c.get`. `m32` is monotone on the valid range.

Request:
- `Req` (:90-103) and `Pre` (:267-275) gain `elig : Feed Elig` and `soc : Feed Soc` after `span`.
- `encFeed` (:131-136) guards `rowsSorted`. `feed` (:225-229): after `many`, `unless rowsSorted c rows do throw .RECORD`.
- `encodeBody` (:154-164): six `encFeed`, laid out `c ‖ prev ‖ n ‖ d1..d6 ‖ r1..r6 ‖ redo ‖ auth`.
- `decodePre` (:277-291): six `desc`, six `feed`. `decodeBody` (:293-297) copies the two fields.
- `bodyBytes` (:308-310): `538 + 36·r1 + 25·r2 + 29·r3 + 61·r4 + 62·r5 + 45·r6 + payWidth·redo + |auth|`.
- New `walkCtx (bs : Bytes) : Except Word Nat`, in the monadic shape of `decodeBody` with `cut`/`numRec`, every failure `LENGTH`: it reads the descriptor row counts, the redo count and the authority counts and blob lengths up to `nq`, and returns `c`.
- New `walk (bs : Bytes) : Except Word (Nat × List Bytes)`: `walkCtx`, then `nq` and the `(len u32 ‖ request)*` loop, ending exactly at the end. It returns `c` and the request blobs.
- New `walkPrime (bp : Bytes) : Option Nat`, the parser of `body′`: `walkCtx`, then `n`, then exactly `4n` bytes of lengths with no blobs. `walk` does not parse `body′`, because `body′` has the lengths back to back.
- New `bodyPrime b c xs := b.take (c+4) ++ (xs.map fun x => le4 x.length).flatten`, `frameV3Pre bp rds := frameDom ++ bp ++ rds.flatten`, and `frameDigest H b`.
- `encodeReq` (:166-169) writes `frameDigest`. `decodeReq` (:300-305): header, then `frameDigest` (LENGTH), then the digest compare (DIGEST), then `decodeBody`, then nothing left.
- `ReqWF` gains "each feed's rows sorted", so the round trip covers exactly what the decoder accepts.
- `ident` (:178-180): `Gate.context` → `contextV2`.
- `ctxOf`, `feedsOf`, `fcOf_inv` (:321-341): unchanged.

Answer:
- `maskOf` (:420): `reasons.foldl (fun m r => if rs.contains r then m ||| 2^r.idx else m) 0` (the same shape as Engine3's `leafBits`).
- `unmask` (:422): `reasons.filter (fun r => m.testBit r.idx)`.
- The `Rec` docstring (:408): "bit `r.idx`".
- `Leaf.ok` (:489-490) as in 2.7.
- `encLeaf` (:495) `leAll [1,8,1]`; `decLeaf` (:504) `nums [1,8,1,1]`; `encRec` (:581) and `decRec` (:594) `[3,1,1,8,4,3]`. `ansHdrBytes` (:123) stays 87.

### 4.3 Frame/Fast.lean (in `gate_engine`)

- `walkFast` over `ByteArray`, reading u32s at offsets only.
- `feedP` (:37-55, generic) gains the order check over `c.get`.
- `bodyP` (:2426-2442), `bodyS` (:3026-3042), `MtS_bodyP` (:3044-3052): six descriptors and feeds.
- `decodeReqFast` (:2445-2457): version 3, `walkFast` else LENGTH, `HB(dom ++ bs.extract 82 (82+c+4) ++ lens ++ rds)`, compare else DIGEST, then `bodyP`. This copies the context once and holds all `rd_i` at once (64 bytes per request); streaming SHA3 is a later optimisation if `_gate_bars` objects.
- `contextDomain` (:3272) → CONTEXT/v2. `contextAt` (:3282) is unchanged.
- `putRec` (:3796) and `putLeaf` (:3802): width 8. Buffer sizes (:3816-3817): `20 *` and `140 *`.

### 4.4 Flat/Worker.lean (in `gate_engine`)

- `reasonBits` (rightrail/lean/BlindLedger/Gate/Flat/Worker.lean:172): `2 ^ r.idx`.
- `leafMask` (:174-178): `Frame.leafUnencodable` and `Frame.leafScope`.
- Bench timer (:376): time the Fast digest assembly instead of `domain "FRAME"`.
- `verify` parameter: the frame path passes `mlDsaOk` (rightrail/lean/BlindLedger/Gate/Verify.lean:12) to `Run.admit` at :237, the only frame-path use. Thread it out the same way the crash point is threaded today:
  - Flat/Worker.lean: `FlatW` (:65-67, which already carries `crash : String := "none"`) gains `verify : Bytes → Bytes → Bytes → Bool := mlDsaOk`, and :237 passes `w.verify` (the `FlatW` argument of `commitBin`, :206) instead of `mlDsaOk`.
  - Engine/OneProc.lean: `run` (:77) gains a `verify` argument after `crash` and builds the initial worker as `{ crash := ← crash, verify := verify }` (:84). `serve` (:60-75) and its call `Flat.Worker.handle fw dir shard …` (:69) are unchanged, because the verifier rides in `fw`.
  - Engine/EngineMain.lean:4: `OneProc.run (pure "none") mlDsaOk args`.
  - Rules/RulesCrashtest.lean:10: `OneProc.run crashPoint mlDsaOk args`.
  - New test-only root `BlindLedger.Gate.Engine.EngineUnsigned` (rightrail/lean/BlindLedger/Gate/Engine/EngineUnsigned.lean): `main args := OneProc.run (pure "none") (fun _ _ _ => true) args`. It is the root of the `gate_engine_unsigned` exe of 7.1.
  - Decisions under `mlDsaOk` do not change.
- `feedsOf` (:80-90) and the feed reads (:250-257): unchanged (decision 6).

### 4.5 Frame/Answer.lean (outside the pin)

- 8-byte reason puts (`put b 8 d.mask.toNat`; `d.mask` stays UInt32 until step 5) in:
  - `decStep` (:72, :176) and `heldStep` (:215);
  - the held-record fold in `encodeAnsOut` (:73), which writes a zero reasons field with `putLE4 … 0` and becomes an 8-byte zero.
- Buffer sizes (:64-65): `20 *` and `140 *`.
- The `hE` proof term (:481 onward) restates `encodeAnsOut` and must match: its capacity at :482-483 (`16 *` → `20 *`, `136 *` → `140 *`) and its copy of the held fold.

### 4.6 Flat/PayTheorems.lean (outside the pin)

- `contextV2Pre_inj` beside `contextPre_inj` (rightrail/lean/BlindLedger/Gate/Flat/PayTheorems.lean:983).
- `frameV3Pre_inj` (section 4.10).

### 4.7 Flat/DecideRows.lean (outside the pin)

- Remove `idx_lt` (:1603); add `reasons_len_le32 : reasons.length ≤ 32 := by decide`, labelled "UInt32 line-mask width until step 5; not a total-count guard".
- `idx_len` (:1601) and `reasons_nodup` (:1667) become restatements of the Rules/Spec theorems (4.1).
- `Lo` (:1654): `m.toNat < 2 ^ reasons.length`.
- Replace `idx_get` (:1669-1673) by `idx_dense`. Its statement `reasons[j].idx = j` becomes false at step 3.
- Re-prove `bit_toNat` (:1609-1615), `Lo_bit` (:1659), `has_andnot` (:1715-1720), `has_mod` (:3766-3771) and `eq_zero_of_has` (:1675-1683; via `idx_dense` and `has_iff`, else `Nat.testBit_lt_two_pow`).

### 4.8 Engine3 (outside the pin; must build and stay comparable)

- ReadB.lean `feedsW` (:103-123): `o0 := Frame.hdrBytes + 538` (:106); strides 36/25/29/61 (:107-109, :114, :120); the sort is kept. Elig and soc rows are skipped, not read. The in-row offsets move too, because the member drops from 33 to 32 bytes; if only the strides changed, dates and plans would be read one byte off and `gate_hist3` would stop being comparable with `gate_engine`:
  - `mem` (:110) becomes unconditional: today it tests the n33 top byte `bs[o + 32]! == 1`, which is no longer sent. The member is read as `2^256 + getN bs o 32` and keyed from that number, mirroring RowsStore.lean:358-369.
  - DMF (:115): `⟨2^256 + getN bs o 32, ld32 bs (o + 32)⟩`, and `okD` at `o + 32` (was `o + 33`).
  - Span (:121-123): plan `getN bs (o + 32) 21` and `provAt bs (o + 32)` (were `o + 33`), start `ld32 bs (o + 53)` (was `o + 54`), stop `ld32 bs (o + 57)` (was `o + 58`), and `okW (o + 53)`.
  - Provider death and exclusion (:116-119) are unchanged.
- Step.lean:
  - `headAt` (:66): `20 *`;
  - `reasonTab` (:72-74): `(Rows.bit r, r.idx, 2 ^ r.idx)` over `Rules.reasons`, `zipIdx` dropped; docstring :76-79;
  - `leafIn` (:246) `leafScope`, (:253) `leafUnencodable`;
  - `ansW` docstring (:265) and buffer (:278) `140 *`;
  - `feedAt` (:330-334): widths `#[36,25,29,61]`, base `+ 538`; `feedKnown` (:338): `+ 538`; `feedPins` (:326) stays at 4.
- StepH.lean:138 and Verify.lean:228: record buffers `20 *`.
- Store.lean:74-77 `ansAdds`: `p + 7` → `p + 11`, flag `p + 6` → `p + 10`. Without this no logged frame opens.
- DecodeB.lean:
  - `frameDomain` (:21) removed; `bodyB` (:149-165) six feeds with the order check.
  - `decodeB` (:168-179) does `walkFast`, then hashes the requests in a **bounded** number of tasks: the request list is cut into at most K contiguous ranges (K a small constant such as the core count), one `Task.spawn` per range computes that range's `rd_i` in order, and one more task hashes `body′`. The joined digests feed the outer hash; the digest word is still checked before the parse result.
  - One task per request is not acceptable: the request count is bounded only by the 64 MiB frame (Engine/FrameLaws.lean:22, `Rules.Run.maxFrame`), and the trunk already sends a frame of ten million one-byte requests (rightrail/tests/test_gate_rules_worker.py:63-70). That test expects the frame to exhaust a 200 MB job cap; with v3 it still does (its `rd_i` alone are 640 MB), so the test keeps its meaning, but the decoder must not also create ten million tasks.
- RowsStore.lean and DecodeFuzz.lean: no change.

### 4.9 Pins and vectors

- Vectors.lean:232 stays as it is: the `context` kind checks `Gate.context`, which stays CONTEXT/v1 because Gate/Spec.lean is untouched (decision 8).
- Vectors.lean gains two kinds: `["context2", _, body, out]` with `Frame.contextV2`, and `["frame3", _, body, out]` with `Frame.frameDigest`. Frame/Spec is already imported (rightrail/lean/BlindLedger/Gate/Vectors.lean:2), so no import changes. `gate_vectors` is a default target (rightrail/lean/lakefile.toml:3) but not pinned.
- `gate_vectors` already judges the file's `answer` lines with `Frame.decodeAns` and an `encodeAns` round trip (Vectors.lean:238-241). Those lines are version-1 answers today (16-byte records, u32 leaf reasons, a bit-24 leaf; written by `answer_frame`, rightrail/tests/test_right_rail_gate_formats.py:93-107, :318-334), and the version-3 decoder refuses them (`guard (v == version)`, Frame/Spec.lean:606). So the step must update those lines in the same change, or test_right_rail_gate_formats' Lean check (:829-832, `failed=0`) fails here, with no signer involved. Section 5.3 says how they are regenerated without the signer.
- AxiomCheck.lean (:798-831), rightrail/tools/gate_print_axioms.lean (:384-400) and AXIOMS.txt (:347-363): add the new public theorems. No axiom changes are expected.

### 4.10 Theorems

New (pinned and listed in the axiom pins):
- `contextV2Pre_inj`: `contextV2Pre a = contextV2Pre b → a = b`, by `List.append_cancel_left`.
- `walkPrime` lemmas:
  - `walkPrime_bodyPrime`: `walk b = .ok (c, xs) → walkPrime (bodyPrime b c xs) = some (bodyPrime b c xs).length`;
  - `walkPrime_stab`: `walkPrime bp = some bp.length → walkPrime (bp ++ e) = some bp.length`, from a `walkCtx` stability lemma shared with `walk`. This gives prefix-freeness of `body′`.
- `frameV3Pre_inj`, stated over bodies that walk: if `walk b₁ = .ok (c₁, xs₁)`, `walk b₂ = .ok (c₂, xs₂)`, every `rd` is 64 bytes and `frameV3Pre (bodyPrime b₁ c₁ xs₁) rds₁ = frameV3Pre (bodyPrime b₂ c₂ xs₂) rds₂`, then the two `body′` are equal and `rds₁ = rds₂`. Proof: strip `frameDom`, split by `walkPrime_stab`, then the `rd` count is the `n` inside `body′` and the rest splits into 64-byte chunks. About 300-500 lines with the `walkPrime` lemmas.
- `walk_encodeBody`: `encodeBody q = some b → walk b = .ok (c, q.auth.reqs.map (·.x.toList))`, by the `encodeBody_some` destructuring (:1942-1962) and `encFeed_len` (:2199).
- `walk_ok_of_decodeBody`: a body that decodes walks to the same blobs (used by `decodeReq_inv`).
- `feedOrder_decode`: `decodeReq H bs = .ok (q, dg) →` all six feeds are `rowsSorted`.
- `walkFast_eq` and `frameDigestFast_eq`, in the pattern of `hdr_slice`/`ver_eq` (Fast.lean:3116-3122) and the append/extract lemmas at :3152-3155.
- `idx_dense`, `reasons_len_le`, `reasons_len_le32` (all `decide`), and `idx_len`, `reasons_nodup` in their new place (4.1).

Restated or re-proved:
- `Lawful` (Frame/Spec.lean:1577-1578): weaken **only the first conjunct**, to "when the row encodes": `∀ x b, leAll c.widths (c.get x) = some b → c.ofNums (c.get x) = some x`. The 32-byte member cannot satisfy the plain law for a member below 2^256.
  - Keep the second conjunct `∀ ns x, c.ofNums ns = some x → c.get x = ns` unchanged. It still holds for the member codecs (`ofNums [m, …] = ⟨2^256 + m, …⟩` for `m < 2^256`, and `get` gives back `m`), and `feedRow_dec` (:1602) uses it.
  - `feedRow_enc` (:1596) already carries the encodability hypothesis, so the change is local. Six `*C_lawful` proofs, the member ones by `Nat.div`/`mod` and `omega`.
- `decodePre_stab`/`decodeBody_stab` (:836-931), `encodeBody_some`/`encodeBody_of` (:1942-1975), `decodePre_dec`/`_enc` (:1977-2047), `decodeBody_dec`/`_enc` (:2049-2080, the `Pre` literal at :2068), `encodeBody_length` (:2211-2224).
- `decodeReq_digest` (:998), `decodeReq_trailing'`/`decodeReq_trailing` (:961-1010; simpler, because trailing bytes fail the walk), `decodeReq_inv` (:2162-2186), `decodeReq_encodeReq` (:2228; its statement's RHS `H (domain "FRAME" ++ bs.drop hdrBytes)` at :2229 becomes `frameDigest H (bs.drop hdrBytes)`), `encodeReq_decodeReq` (:2253), `decodeReq_wf` (:2261), `decodeReq_length` (:2266-2270).
- Fast: `decodeReqFast_eq'`/`decodeReqFast_eq` (:3135-3196), `bodyRec_eq` (:3056-3072), `contextAt_eq` (:3660-3667, RHS `Frame.contextV2`), `identFast_eq` (:3777-3789), the `putRec`/`putLeaf` equalities.
- Answer, Frame/Spec:
  - `unmask_maskOf` (:2748; new proof by `maskOf_testBit`, `Nat.testBit_or`, `Nat.testBit_two_pow`, `Reason.idx_inj` at Rules/Spec.lean:147, and `reasons_nodup`); `maskOf_lt` (:2971; `Nat.or_lt_two_pow` and `idx_len`); `maskOf_zero_iff` (:2977);
  - the leaf codec in both directions: `nums_leaf` (:1323-1327), `decLeaf_encLeaf` (:1329), `encLeaf_decLeaf` (:1348, `hhd` at :1362);
  - the `decExt` leaf-count proofs that run `manyO decLeaf` and use the `nums [1,4,1,1]` shape (:1441-1468);
  - `encRec_some` (:3099-3131; `e5` replaced by `2^len ≤ 2^64` from `reasons_len_le`, plus an `e8`).
  - `selM`, `mask_sum`, `unmask_sel`, `selM_lt` (:2709-2746, ~:2960) are deleted; they are not pinned.
- Answer.lean, private: `encRec_some` (:162-164), `decStep_eq` (:178-203), `heldStep_eq` (:217-231), `putLeaf_eq` (:256-280), `putRec_eq` (:1367), the `hE` term at :481 onward (4.5).
- Engine3: `leafBits_eq` (Step.lean:81-84) with `2 ^ r.idx` over `Rules.reasons`; DecodeB `body_rel` (:687) and `decodeB_eq` (:779-805) with the new hash block. The chunked hashing needs a join lemma: the flatten of the per-range `rd` lists equals the `rd` list of the whole request list, then `frameDigestFast_eq`.
- Statements unchanged, proofs to re-check: `feedsOf_inv`, `fcOf_inv`, `answer_encodes`, `refusal_word`, `inputV6Pre_inj`, `records_ok`, `decodeAns_encodeAns`, `encodeAns_decodeAns`.

## 5. Host and tests

### 5.1 rightrail/app/right_rail_gate_codec.py

- :37 `CONTEXT = b"RR/GATE/CONTEXT/v2\x00"`; docstring :178.
- Add `FRAME = b"RR/GATE/FRAME/v3\x00"` and `frame_digest(body)`, which walks lengths exactly as Lean's `walk` and raises on failure.

### 5.2 rightrail/app/right_rail_gate_decide.py

- `REASONS` (:477-482): the 24 rule codes only. Add `REASON_IDX = {name: idx}` (equal to position today), `LEAF_ONLY = {62: "UNENCODABLE_PAYMENT", 63: "SCOPE"}` and `RULE_MASK = (1 << len(REASONS)) - 1`.
- `FEED_WIDTHS` (:484): `dmf (32,4)`, `pdeath (21,4)`, `excl (21,4,4)`, `span (32,21,4,4)`, `elig (32,21,1,4,4)`, `soc (32,4,8,1)`, in this order.
- `FEED_KINDS = {dmf:1, pdeath:2, excl:3, span:4, elig:7, soc:8}`. Appending would give 5 and 6, which are RELEASED and UNRESOLVED (:505; rightrail/conformance/GATE_RULES_V1.md:75-86).
- `PIN_WIDTHS` from the `.fields` encodings. Today's `129 if w > 4 else 4` (:502) is wrong for `cents` u64 and the u8 fields.
- `feed()` (:495-507): sort rows numerically; a member must satisfy `v >> 256 == 1` and is sent as `v - 2**256`; any misfit sends the feed as state 2.
- `request_frame` (:510-522): `_le(3,2)` and `gate.frame_digest(body)`. It accepts a read set of **four** feeds, padded with two absent feeds `(bytes(77), b"")`, or of **six** feeds, and refuses any other count.
  - Four: rightrail/app/right_rail_gate_ffs.py:164-172 sends four and stays untouched (decision 11).
  - Six: `_gate_shards.feeds_of` maps over `decider.FEED_WIDTHS` (rightrail/tests/_gate_shards.py:99), so it returns six once `FEED_WIDTHS` has six entries.
- `_names` (:542-543): decode by idx, add 62/63 for leaves, return names sorted by name bytes (TOKEN needs that, rightrail/app/right_rail_gate_codec.py:399).
- `_requests` (:546-565): `range(len(FEED_WIDTHS))`; docstring CONTEXT/v2.
- `_answer` (:626-656): version 3; record mask `num(8)`, refused if `mask & ~RULE_MASK`; leaf mask `num(8)`, refused if `mask & ~(RULE_MASK | 3 << 62)`.
- Docstrings :4, :6, :430, :513-515, :547.
- Unchanged: :561, :635 (header still 82 bytes); rightrail/app/right_rail_gate_producer.py:535.

### 5.3 Tests (rightrail/tests/)

**The shared test header (blocker, Route A only).** rightrail/tests/gate_rules/shards_v1.vectors:4-24 carries DMF rows `dmf 9001 20270110`, `dmf 9002 20261120` and span rows `span 1001 501 …` through `span 9001 501 …`, whose members are small numbers with no `0x01` top byte. `_with_members` (rightrail/tests/_gate_shards.py:62-78) keeps those rows (`mine = old[f[1]] + […]`, :73) beside an n33 copy for every harness member and shard, and `HEAD = feeds_of(_HEAD)` (:102) frames them. Under the §19 member rule the host must then send the whole DMF and span feeds as state 2, so every frame built from `g.HEAD` (the throughput corpus via `decide_batch`, :222; test_decode_fuzz.py:34; and the others listed by `request_frame(g.HEAD` callers) would lose both feeds and gain STALE or `_UNVERIFIED` reasons. `PAIRS_DIGEST` would move.

Resolution:
- `_with_members` emits, for the frame header `_HEAD`, only the n33 rows, and recomputes each `snap` count and pin over them (:74-76 already recompute; they now run over the n33 rows only).
- Re-keying the small rows as n33 keys would only duplicate rows that already exist: :73 already adds `nat(member(m, k))` for every small member `m` and every shard `k`. So the small rows are dropped from the frame header.
- Why dropping them is decision-neutral on the frame path:
  1. Every frame-path request names a 32-byte member key, `member(m, k)` (_gate_shards.py:59, :210), whose number is at least 2^256, so a small-number row never matches a request's member. Today Engine3 keys such a row as `none` (Engine3/ReadB.lean:110) and the Flat worker compares numbers, so the rows are already inert.
  2. The fact cap is per key (`facts`, `feedOver`, `feedCapped`: Flat/Model.lean:268-270, :356-364), and the dropped rows are under keys no line reads, so no line's fact count changes.
  3. Usability depends on the descriptor's state, asOf, count and pin. The count and pin are recomputed over the rows sent, so both feeds stay state 1 with a matching pin.
  4. No other feed changes.
  The signer-free decision check (7.1) confirms this empirically; the argument does not replace it.
- The text runner still needs the small rows: `claim` writes small members (`1001`, `9001`; _gate_shards.py:175-181) into text spec lines, and two tests feed `g._HEAD` to the `gate_rules` text runner (test_flat_host.py:214, test_flat_worker.py:124). Add `_TEXT_HEAD` (today's header: small and n33 rows, today's pins) and point those two lines at it. The 923-byte adds row they compare holds `Line.fields` only (rightrail/lean/BlindLedger/Gate/Rules/Spec.lean:533-535), not feed pins, so the two headers' different pins do not affect that comparison.
- New test: `g.HEAD`'s DMF and span descriptors have state 1, and their pins equal SNAPSHOT/v1 pins recomputed over the rows sent.
- Other fixtures checked for members below 2^256:
  - frames derived from the rules vectors go through `g._HEAD` (test_gate_authority_frames.py:60, :84; test_flat_host.py:668, :677-683; test_right_rail_gate_chaos.py:338-339, :358; test_right_rail_gate_ffs.py:70) and are covered by the header change;
  - decode_fuzz base frames use `g.HEAD` (test_decode_fuzz.py:34) and are covered;
  - ffs fixtures use `ffs.ident(member_key(…))` (rightrail/app/right_rail_gate_ffs.py:93-95), which is n33.
- Route B does not need this change: v1 n33 rows carry small numbers.

**Signer-free harness import.** `_gate_shards.py:105-107` computes `GRANT`, `KEYS`, `GRANT_ID` and `PIN` at import, which runs the signer (`au.standing()`, `au.genesis()` → `keyset_body` → `entry` → `pk` → `fx.keypair`, rightrail/tests/_gate_authority.py; test_right_rail_gate_formats.py:162-169). Test-only, owner approval:
- Make the four names lazy through a module `__getattr__`, so call sites keep `g.GRANT`, `g.KEYS`, `g.GRANT_ID` and `g.PIN`. Laziness alone does not remove the signer: reading a lazy name still runs it.
- Which values they resolve to is set by an explicit switch, `RR_GATE_UNSIGNED=1`, read once at first use:
  - unset (the default, and every existing caller): today's signed `au.standing()`, `au.grant_id` and `au.genesis()[0]`, so nothing changes for the signer-backed tests;
  - `RR_GATE_UNSIGNED=1`: the unsigned KEYSET/v2 and APPROVAL/v2 fixture of 7.1 (`GRANT`, `KEYS`), its grant id (`GRANT_ID`: SHA3-512 of the document before its signature block, found by parsing from the front with `decider._approval`, as Lean's `encDoc` does; `au.grant_id` cannot be used, because its `fx.unsigned` finds the signature block from the end by its count byte, and an all-zero signature ends in 0x00, so it cuts one byte and gives a wrong id) and the SHA3 pin of the fixture's key-set body (`PIN`).
  - There is no silent fallback when the signer is missing: without the switch, a missing signer still fails as today, so a signed test can never quietly run on the unsigned fixture.
  - Only test-only callers set the switch: the 7.1 runner and the signer-free decode_fuzz run. Frames built under it are accepted only by `gate_engine_unsigned`; the pinned `gate_engine` refuses them at `Run.admit`.
- test_flat_worker.py:31 computes `GENESIS = chain.genesis(0, g.ASOF, g.PIN)` at module level, and test_decode_fuzz.py:18 imports test_flat_worker. Make `GENESIS` lazy too (a cached `genesis()` function, or a module `__getattr__`), so importing test_flat_worker reads no `g.PIN`. test_decode_fuzz.py:34 then reads `g.PIN`, `g.KEYS` and `g.GRANT` only when building its base frames, under the switch.

| File | Lines | Change |
|---|---|---|
| _gate_shards.py | :62-78, :81, :102 | frame header n33-only with re-computed pins; `_TEXT_HEAD`; state-1 test (above) |
| _gate_shards.py | :105-107 | lazy authority, signed by default, the unsigned fixture under `RR_GATE_UNSIGNED=1` (above) |
| test_flat_worker.py | :31 | `GENESIS` lazy (computed at first use), so the module imports without reading `g.PIN` |
| test_flat_host.py | :214 | text runner reads `g._TEXT_HEAD` |
| test_flat_worker.py | :124 | text runner reads `g._TEXT_HEAD` |
| test_right_rail_gate_formats.py | :93-107 | answer writer v3, `le(m,8)` in records and leaves |
| test_right_rail_gate_formats.py | :119-148 | six descriptors, widths (36,25,29,61,62,45), `gate.CONTEXT` (the literal CONTEXT/v1 at :144 becomes v2) |
| test_right_rail_gate_formats.py | :305-307 | **no change**: `context c0` stays the literal CONTEXT/v1 that Vectors.lean:232 checks |
| test_right_rail_gate_formats.py | :318-323 | leaf `1<<62`; record `1<<4` stays (idx 4, FFS_DUPLICATE_LINE) |
| test_right_rail_gate_formats.py | :329-331 | keep version-2 reject, add version-1 reject; bit 26 → bit 61; add leaf bit 24 reject, record bit 62 reject, leaf bit 63 accept |
| test_right_rail_gate_formats.py | `build_vectors` (:286) | add a `context2` line built with `gate.CONTEXT` (v2) and a `frame3` line; split out the signer-free lines (below) |
| test_right_rail_gate_decide.py | :41, :43, :62, :44, :54, :116 | `_le(0,8)`, version 3, `range(6)`, `* 6`; new `_answer` accept/refuse cases; rows sent sorted; non-`0x01` member → state 2; an unsorted frame refused `RECORD`; `request_frame` accepts 4 or 6 feeds and refuses 5 |
| test_right_rail_gate_ffs.py | :119 | iterate only the kinds that have a `snap` line, and assert that elig and soc are `(bytes(77), b"")`; today's `zip` over six kinds would raise `StopIteration` at :120 |
| test_flat_host.py | :271, :635, :843 | version 3; `87 + 20 *` |
| test_gate_authority_frames.py | :88, :91, :157, :251, :261, :269 | `76 + 6*77`; `gate.frame_digest`; `20 *`; `take(10)`; `+ 11` |
| test_flat_worker.py | :87-90 | six descriptors; `frame_digest` |
| _gate_bars.py | :94, :102 | `20 *`; `frame_digest` |
| test_decode_fuzz.py | :22-26, :65 | `redigest` via `frame_digest`, keeping a stale digest when the walk fails (both decoders then refuse LENGTH); `RRDQ\x03\x00`; new base frames with elig and soc present, an out-of-order row, a 32-byte member; runs on the unsigned authority of 7.1 when the signer is absent |
| test_gate_throughput.py | :37-41 | re-pin `OUTPUT_DIGEST`, `REALISTIC_DIGEST`: **blocked until the signer is available** (7.1) |
| test_gate_throughput.py | :44-48 | `PAIRS_DIGEST` **must not move** |

- New evidence, part of the signer-free check (7.1): run the PAIRS corpus again with non-empty, well-pinned elig and soc feeds, and with a mis-pinned elig feed, and assert the same sorted pairs both times. Once the signer is available, the same assertion runs in test_gate_throughput.
- rightrail/tests/gate_vectors/gate_v1.vectors, in two parts. Keep the file name (decision 13). The plan did not list this file.
  - **Signer-free lines, updated here.** The `answer` section (test_right_rail_gate_formats.py:318-334) uses only the fixed `D[...]` constants (:36), `SHARD` and `answer_frame` (:93), and the new `context2` and `frame3` lines use only `gate.CONTEXT`, `gate.frame_digest` and a synthetic body that walks (2.5). None needs the signer. Split them out of `build_vectors` into a helper `signer_free_vectors()` that `build_vectors` calls at the same place, so the full file stays byte-identical to `build_vectors()` once the signer is present. Add a mode `python -m tests.test_right_rail_gate_formats --signer-free` that rewrites only those lines in the existing file: it replaces every `answer` line and inserts `context2`/`frame3` right after `context c0`, in `build_vectors` order, and leaves every signed line byte for byte. (Hand-editing those lines to the helper's output is the fallback.) Then the Lean check `test_lean_judges_every_golden_vector` (:829-832) stays green here.
  - **Signed lines, blocked until the signer is available.** A full `python -m tests.test_right_rail_gate_formats` (:1418) and `test_python_reproduces_every_vector_byte` (:826-827) need the signer (`keypair` → `_kat`, :162-169). The full regeneration, with the signer, confirms that the signer-free update and `build_vectors` agree and shows whether any signed line moved (7.1).
- The plan names rightrail/tests/test_hostile_worker_frames.py for hostile-frame tests (plan line 269). That file covers the text worker frame and needs no change; the hostile cases for the new layout go in test_decode_fuzz.py.
- No change: _gate_shards.py:84-99 (`feeds_of` returns six feeds once `FEED_WIDTHS` has six, and `request_frame` accepts six), test_engine3_redo_cut.py:25, test_right_rail_gate_ffs.py:674 (`REASONS.index` equals idx), test_gate_rules_worker.py (its `feeds_of([])` gives six absent feeds), test_engine3_recovery.py, test_engine3_verify.py and the other wrappers that go through `request_frame`/`_answer`.
- Lean evidence outside `gate_engine`: `#guard reasons.zipIdx.all fun (r,i) => r.idx == i`. It is expected to fail at step 3 and is removed then.
- Run with the private Python `C:\Users\sruja\rr-tools\py314` and `E3_SCRATCH` set (docs/integration/LOG.md:295-345).

## 6. Spec pages and MANIFEST

- New rightrail/conformance/FRAME_V3.md: sections 2.1-2.8 of this design, the refusal words, and a note "localBCE fork number: ENGINE_V3 §17/§19 v2 plus two feeds". Top-level conformance pages are exempt from the doc cap (rightrail/tests/test_doc_shape.py:36-39).
- rightrail/conformance/FRAME_V1.md: mark superseded (:3), add a §8 change record (from :281), fix the stale "Spec 16, Fast 6, Answer 1" at :5-6, and fix the stale "No vectors are published yet." at :7: rightrail/tests/gate_vectors/gate_v1.vectors already carries answer vectors (test_right_rail_gate_formats.py:318-334), checked by `gate_vectors` (Vectors.lean:238-241).
- rightrail/lean/lakefile.toml:49, the `frame_statements` comment "statements, not yet proved; not imported by any exe": stale, because Frame/Spec and Frame/Fast are in `gate_engine`'s closure and proved. Rewrite it (for example "The binary request and answer frames (conformance/FRAME_V3.md): proved; Frame/Spec and Frame/Fast are in `gate_engine`'s closure") in the same edit that adds the `gate_engine_unsigned` exe. The lakefile is in the TCB manifest (embedded by `RulesMain`, `embed_lakefile`, :183), which moves in this step anyway.
- rightrail/conformance/ENGINE_V3.md:
  - §17 note "implemented as FRAME/v3 (FRAME_V3.md) with two more feeds";
  - :621 leaf `reasons u64`, 75/139 bytes;
  - §19 table (:666-671) gains Eligibility (62) and Share of cost (45);
  - fix :155 (stale `rq` text against §24, :769-793) and :502-504 (`inputV6Pre_inj` is proved).
- rightrail/conformance/FLAT_V1.md:156-157: `rq` is the batch identity, `Frame.ident` over CONTEXT/v2 and each INPUT/v6 (BATCH-INPUT, ENGINE_V3 §18 and §24), not any frame digest. It has been the batch identity since 4b56a94c (rightrail/lean/BlindLedger/Gate/Flat/Worker.lean:72-73, :378-379; Engine3/Store.lean:88-89; ENGINE_V3.md:615). The current text "the request frame's own digest" is already stale. :105 and :123 stay, with a note that the new feeds are capped at step 3.
- rightrail/conformance/README.md:44-45: list FRAME_V3.md as the current engine frames page and FRAME_V1.md as superseded.
- rightrail/lean/BlindLedger/Gate/Frame/Spec.lean:22-23: stale "not yet proved". rightrail/STATUS.md:64 (INPUT/v5) is fixed separately.
- rightrail/conformance/MANIFEST.sha256: re-hash FLAT_V1 (:113), FRAME_V1 (:115), ENGINE_V3 (:116) and README if it is listed; add FRAME_V3. Leave GATE_RULES_V1 (:9).

## 7. Re-pin procedure and evidence

### 7.1 The signer and the signer-free decision check

- **Blocked until the pinned signer is available:**
  - the `OUTPUT_DIGEST`/`REALISTIC_DIGEST` re-pin (test_gate_throughput.py:37-41; :106 calls `fx.custody`, which calls `signer.keygen`, test_right_rail_gate_formats.py:890-894);
  - the `PAIRS_DIGEST` assertion itself in test_gate_throughput (:151);
  - the full gate_v1.vectors regeneration and its byte-reproduction test (`build_vectors`, :286, through `keypair`/`_kat`, :162-169; :826-827). The signer-free `answer`, `context2` and `frame3` lines are not blocked: they are updated here (5.3), so `gate_vectors` keeps passing on this machine;
  - every test in a file that needs the signed authority (25 files could not be collected at step 1, LOG.md:325-326, and LOG.md:328-331 counts 194 + 52 signer failures).
- **Signer-free decision check (runs here; may not be waived under decision 19):**
  1. A test-only Lean exe `gate_engine_unsigned` (lakefile `lean_exe`, root `BlindLedger.Gate.Engine.EngineUnsigned`, not a default target, never pinned or shipped). It runs `OneProc.run` exactly as `gate_engine` does, with the `verify` parameter of 4.4 set to accept every signature.
  2. A signer-free authority fixture: a KEYSET/v2 and APPROVAL/v2 TRANSFER grant of the same shape as `au.standing()` (rightrail/tests/_gate_authority.py:106-108), with placeholder public keys and zero signatures.
  3. A runner over the PAIRS corpus (`corpus()`, test_gate_throughput.py:54-62; `request`, _gate_shards.py:206-214) that builds each batch's frame directly, as test_flat_worker.py:63 does, runs it through `gate_engine_unsigned`, chains the head, and collects sorted `(line, "OUTCOME REASONS")` pairs, for both corpora (`RR_GATE_BENCH_CORPUS` unset and `realistic`) at batch sizes 100 and 2000.
  4. Before: a scratch tree of fc89f9e5 plus the `verify` refactor (Flat/Worker, OneProc, EngineMain, RulesCrashtest), the `gate_engine_unsigned` exe, the lazy/unsigned harness (`_gate_shards` under `RR_GATE_UNSIGNED=1`, the lazy `GENESIS` of test_flat_worker.py:31, the unsigned fixture) and the runner, with the frames, the host and the answer left at version 1. After: the step 2 tree, with the same harness and runner. The pairs must be identical.
  5. The same run after the change with full well-pinned elig/soc feeds, and with a mis-pinned elig feed, must give the same pairs.
  6. Expected, not required: the pairs digest equals `PAIRS_DIGEST` (the grant has the same effect, TRANSFER with holds 0). If the before run already differs from `PAIRS_DIGEST`, the unsigned harness is not equivalent, and before-versus-after equality remains the gate.
- With the lazy authority, the lazy `GENESIS` and `RR_GATE_UNSIGNED=1` (5.3), test_decode_fuzz runs here too: decoding does not verify signatures.
- **What this means for committing step 2 (Decision 20):**
  - Default, **wait**: author and check everything that runs here (including the signer-free vectors update and `gate_vectors`), then hold the step 2 commit until the pinned signer arrives. With it, re-pin `OUTPUT_DIGEST`/`REALISTIC_DIGEST`, run the full gate_v1.vectors regeneration and its byte-reproduction test, run test_gate_throughput (the `PAIRS_DIGEST` assertion) and the other signer-dependent tests, then commit once. Authoring takes weeks, so the wait costs time only if the signer has not arrived by the end.
  - Alternative, **defer**: commit with the signer-free check as the decision evidence, and list the throughput re-pin and the full vectors regeneration as deferred in the commit message and the XI.2 record. The commit's gate_v1.vectors already carries the version-3 `answer` lines and the `context2`/`frame3` lines, so `gate_vectors` passes on it here. What is known to be stale is the `OUTPUT_DIGEST`/`REALISTIC_DIGEST` values, and the file is unconfirmed against `build_vectors` until the signer runs the byte-reproduction test. Those checks can only fail once the signer is present, and a follow-up commit is owed. This also needs the owner's explicit acceptance that "checks gate every commit" is met by the signer-free check for this commit.

### 7.2 Procedure

Following TRUNK_MIGRATION_PLAN.md lines 114-126 and Decision 9:

1. In-tree guarded `lake build` (about 8 minutes here).
2. Commit to a scratch commit; two `git archive HEAD:rightrail/lean` stages into fresh empty directories, each built under the guard.
3. Byte-match `gate_engine` across all three builds. Expected: `gate_engine` moves; `gate_verify` (bf86e5cf…) and the worker do not. A mismatch stops the step before any regen, with all three hashes recorded (Decision 8).
4. `RR_TCB_LIVE=1 RR_TCB_REGEN=1` through `scripts/rr_guarded_interim.ps1 -Modules tests.test_tcb_gate` (the regen run), then the check run with `RR_TCB_REGEN` empty; restore both variables. rightrail/tools/tcb_report.txt :1, :5 and the constant count at :19 move; :2-4 and :6 do not.
5. rightrail/artifacts/gate-verify/PROVENANCE.txt: a paragraph after :124 naming old `2d720b52…`, the new hash, size, constant count, the three build directories, "interim evidence", and that `gate_verify` and the worker did not move; the new `pin gate_engine` line at :125 (rightrail/tests/test_tcb_gate.py:145 checks it against tcb_report :5). Keep the retired `91c41e01` prose at PROVENANCE.txt:106 and :108; rightrail/tests/test_tcb_gate.py:147-153 checks that it is still named and is not the pin.
6. AXIOMS.txt and AxiomCheck.lean.
7. `python tests/test_statement_pin.py regen`, after the TCB re-pin (STMT_TCB includes the report).
   - Expected to change, in Frame: `Req`, `Pre`, `ReqWF` (rightrail/tools/STMT_PIN.txt:3663, gains "rows sorted"), `encodeBody`, `decodePre`, `decodeBody` (:3704), `decodeReq`, `decodeReq_encodeReq` (:3718, statement RHS becomes `frameDigest`), `dmfC` (:3723), `spanC` (:3808), `encFeed` (:3730), `encodeReq` (:3738), `feed` (:3743, order check), `bodyBytes`, `ident`, `maskOf`, `unmask`, `Leaf.ok`, `encLeaf`/`decLeaf`, `encRec`/`decRec`, `version`, and the new Frame constants and theorems.
   - Expected to change, in Rules: new `Rules.Elig`/`Rules.Soc`, new `idx_len`/`reasons_nodup`/`idx_dense`/`reasons_len_le`, and the Run digest constant.
   - Expected unchanged: `Rules.Reason`, `Rules.reasons`, `Gate.contextPre`, `Flat.Feeds`, and DecideRows's `idx_len`/`reasons_nodup` names if pinned (kept as restatements).
8. The signer-free decision check (7.1).
9. The signer-free vectors update (5.3) and `gate_vectors` on the result.
10. With the signer (Decision 20): re-pin the throughput digests (PAIRS unchanged), run the full gate_v1.vectors regeneration and its byte-reproduction test.
11. The full pytest suite. The failures must be exactly the environment list of step 1 (docs/integration/LOG.md:327-342); with the signer present, the signer entries leave that list.

### 7.3 Evidence for the commit

Runs here:
- all restated theorems build with no `sorry`; three byte-matched builds; the TCB check run; the statement-pin regen matching the expected list;
- the signer-free decision check: identical sorted pairs before and after, with empty feeds, full elig/soc feeds and a mis-pinned elig feed;
- `decode_fuzz` with 0 mismatches, now with elig/soc frames and hostile §19 rows, on the unsigned authority;
- the host `_answer` accept/refuse tests and `request_frame`'s 4/6 feed-count tests, where their module imports without the signer;
- the state-1 test for `g.HEAD`'s DMF and span descriptors;
- `gate_vectors` (test_right_rail_gate_formats.py:829-832) accepting gate_v1.vectors after the signer-free update of its `answer` lines and the new `context2`/`frame3` lines (5.3), with `context c0` unchanged;
- the record case `1 << 4` still decodes as FFS_DUPLICATE_LINE.

Needs the signer:
- `PAIRS_DIGEST` unchanged in test_gate_throughput, with empty feeds and with full elig/soc feeds;
- the re-pinned `OUTPUT_DIGEST`/`REALISTIC_DIGEST`;
- the full gate_v1.vectors regeneration matching the file byte for byte (test_right_rail_gate_formats.py:826-827).

## 8. Effort

Authoring days for Route A; machine time is minutes per build and hours per re-pin cycle.

| Part | Days |
|---|---|
| Rules/Spec types, width lemmas, `idx_len`/`reasons_nodup` move | 0.75-1 |
| Member codecs and `Lawful` (first conjunct only) | 1.5-2 |
| Six-feed plumbing through the Spec proofs | 1.5-2 |
| Order check, `feedOrder_decode`, `ReqWF` | 2-3 |
| `walkCtx`/`walk`, `walk_encodeBody`, digest and order lemma restatements | 3-5 |
| `walkPrime` and its lemmas, `frameV3Pre_inj`, `contextV2Pre_inj` | 2.5-4.5 |
| Fast: `walkFast_eq`, digest assembly, `bodyP` chain, context, puts | 3-5 |
| DecodeB bounded chunked decoder and `decodeB_eq` with the join lemma | 2.5-5 |
| Answer side (maskOf/unmask, Answer.lean incl. :73 and `hE`, leaf codec both ways, `decExt`, DecideRows, Engine3 leaf) | 2.5-3.5 |
| Engine3 plumbing | 1-2 |
| Shared test header: n33-only frame header, `_TEXT_HEAD`, state-1 test | 1-1.5 |
| Signer-free decision check: `verify` parameter, unsigned fixture, lazy harness, runner, before/after runs, elig/soc variants, decode_fuzz on it | 3.5-5.5 |
| Python host, tests, vectors | 2-3 |
| Pages, XI.2 record, re-pin and evidence | 1-2 |
| After the signer arrives: digests, vectors, signer-dependent tests, fallout | 0.5-1.5 |
| **Total** | **about 29-47 working days (6-9.5 weeks)** |

- Revision 1 estimated 22-38 days. The increase is the signer-free check (3.5-5.5), the test header (1-1.5), `walkPrime` (1-2 more), the chunked DecodeB (0.5-1 more), the post-signer work (0.5-1.5) and smaller items (about 1). The low end assumes the Lean proofs go as the existing patterns suggest; the high end allows for one restated proof needing a new approach.
- Route B, derived from the same table, line by line. Route B still carries six feeds through every decoder, so most plumbing rows stay; what it drops is the §19 row format, the order rule, the walk and the chunked hash.

  | Part (Route A row) | Route B | Days |
  |---|---|---|
  | Rules/Spec types, width lemmas, `idx_len`/`reasons_nodup` move | same | 0.75-1 |
  | Member codecs and `Lawful` | not needed (n33 rows) | 0 |
  | Six-feed plumbing through the Spec proofs (Req/Pre, `encodeBody`/`decodePre`, round-trip and stab proofs: Frame/Spec.lean:90-103, :154-164, :267-297, :308-310, :836-931, :1942-2080, :2211-2224) | same | 1.5-2 |
  | Order check, `feedOrder_decode`, `ReqWF` | not needed | 0 |
  | `walkCtx`/`walk` and restatements | not needed; the FRAME/v3 domain swap in `decodeReq`/`encodeReq` and their digest lemmas only | 0.25 |
  | `walkPrime`, `frameV3Pre_inj`, `contextV2Pre_inj` | `contextV2Pre_inj` only | 0.25-0.5 |
  | Fast | the `bodyP`/`bodyS`/`MtS_bodyP` chain for six feeds (Fast.lean:2426-2442, :3026-3072), context, puts; no `walkFast` or digest assembly | 1-1.5 |
  | DecodeB | `bodyB` and `body_rel` for six feeds (Engine3/DecodeB.lean:149-165, :687) with the hash block unchanged; no chunked decoder | 0.5-1 |
  | Answer side | same | 2.5-3.5 |
  | Engine3 plumbing (Step.lean:330-338, ReadB.lean:104-123, at the new 538 base) | same | 1-2 |
  | Shared test header | not needed | 0 |
  | Signer-free decision check | same | 3.5-5.5 |
  | Python host, tests, vectors | same, less the sort and member fallback | 1.5-2.5 |
  | Pages, XI.2 record, re-pin and evidence | same | 1-2 |
  | After the signer arrives | same | 0.5-1.5 |
  | **Total** | | **about 14-23 working days (3-4.5 weeks)** |

- The gap between Route A (29-47) and Route B (14-23) is about 15-24 working days, **about 3-5 weeks**.
- rr-core builds v2 with the feeds: about 11-17 working days on our side (answer side, types, test header, signer-free check, re-pin, post-signer work).
- Work that is the same on every route and can start before rr-core answers: the answer side, the types and the `idx_len` move, DecideRows, and the `verify` parameter, unsigned fixture and runner of the signer-free check. About 6-9 days.
- Options that change the Route A total: parse-first instead of walk-first saves 5-8 days (no `walkCtx`/`walkPrime`); an lp32 `body′` saves 1-2 days; capping the new feeds now adds 3-5 days; carrying §20 steps 1 and 2 into `gate_engine` adds months.

## 9. XI.2 record draft

One record in the commit message, 8 fields (rightrail/CONSTITUTION.md:174-183). The owner authors or approves it.

1. **Predicate.**
   - Request FRAME/v1: header version 1, `H("RR/GATE/FRAME/v1" 0x00 ‖ body)`, four feeds, n33 member rows, unordered rows (Frame/Spec.lean:68-73, :121, :169, :302). This covers the statement-pinned `ReqWF`, `encodeBody`, `decodePre`, `decodeBody`, `decodeReq`, `encodeReq`, `encFeed`, `feed`, `dmfC`, `spanC` and `decodeReq_encodeReq` (rightrail/tools/STMT_PIN.txt:3663-3808), whose statements bind these.
   - Context CONTEXT/v1 as the token context (Frame/Spec.lean:178-180).
   - Answer v1: position-numbered u32 reasons, leaf codes at bits 24/25, 16-byte records, 71/135-byte leaves, `Leaf.ok` below `2^26` (Frame/Spec.lean:420-422, :489-504, :578-594).
   - The codec law `Lawful`, first conjunct (Frame/Spec.lean:1577-1578), `idx_lt` and `idx_get` (Flat/DecideRows.lean:1603, :1669-1673), and the theorem statements that bind these.
   - Rules/Spec gains the `Elig` and `Soc` types, which moves Run's digest.
   - The shared test header's small-number DMF and span rows in frames (rightrail/tests/_gate_shards.py:62-78).
   - artifacts/** (the `gate_engine` pin) and tools/STMT_PIN.txt.
2. **Invariant.**
   - III.3 and II/III.5: the engine refuses a frame it cannot decode or whose digest does not match.
   - Gate K2 as written: "every token's input names everything its decision read" (ENGINE_V3.md:776). The input may name more than was read. In step 2 the eligibility and share-of-cost descriptors are bound into CONTEXT/v2 but not pin-verified, because nothing reads them: a mis-pinned elig descriptor is accepted until step 3.
   - An answer bit names one reason forever.
3. **Failure it protects against.** An engine acting on a frame whose bytes or read feeds differ from what the host committed to, or an answer whose bits are read as a different reason.
4. **Evidence it is unsuitable.**
   - A 25th reason lands on leaf bit 24 (UNENCODABLE_PAYMENT).
   - Position numbering moves every bit after the insertion point when a reason is added; G2's codes sort into the middle.
   - G2 and G4 feeds cannot be sent at all.
   - `idx_get` becomes false at step 3.
   - FRAME/v1 is not the specified v2 (ENGINE_V3.md:603-616, :661-685).
5. **Disposition.** Replace.
6. **Replacement control.**
   - FRAME_V3.md: request v3 with the §17 digest under `FRAME/v3`, §19 rows plus eligibility and share of cost, the walk-digest-parse check order; CONTEXT/v2; answer v3 with u64 fields, bits by `Reason.idx`, leaf-only codes at 62/63.
   - The theorems of section 4.10, including `frameV3Pre_inj`, `walkPrime_stab`, `contextV2Pre_inj`, `feedOrder_decode`, `walk_encodeBody`, `walkFast_eq`, `decodeB_eq`, `unmask_maskOf`, `idx_dense`.
   - Three byte-matched builds, the TCB check run, the statement-pin regen, the signer-free decision check (identical pairs before and after, with empty and full new feeds), and, with the signer, `PAIRS_DIGEST` unchanged.
7. **Scope and duration.** `gate_engine`, `gate_hist3`/`gate_verify3`, the host and the shared test header, from this commit, permanent. `gate_verify` and the worker are unchanged. Old stores, logs and `.pending.N` frames are refused, accepted while the engine is not activated (FRAME_V1.md:300-301).
8. **Claims withdrawn and left open.**
   - Withdrawn: the v1 digest, width and bit-position claims; none of FRAME_V1's assurance carries over until the restated round-trips build.
   - Open, not claimed: `pinInputW_eq`, `feedW_eq`, `feedW_at_eq`, `rd_i` reuse in the bypass check, `decodeAns_leafCount`.
   - Deferred to step 3: reading, pin-checking and capping the eligibility and share-of-cost feeds. Until then their descriptors are bound but not verified (field 2), and FLAT_V1.md:123 still covers exactly the feeds that are read.
   - ENGINE_V3 §20 steps 1 and 2 are met by Engine3/hist3 only; `gate_engine` runs the revision 1 decision path and store.
   - Two numeric width facts that are not the D8 total-count guard: `reasons.length ≤ 62` (u64 field minus the leaf codes) and `reasons.length ≤ 32` (UInt32 line masks until step 5).
   - If Decision 20 is "defer": the `OUTPUT_DIGEST`/`REALISTIC_DIGEST` re-pin and the full gate_v1.vectors regeneration are owed; the committed throughput digests are stale, and the vectors file passes `gate_vectors` but is unconfirmed against `build_vectors`.

## 10. Risks

- **The DecodeB proof.** Proving the chunked parallel-hash DecodeB equal to the spec is the largest single proof risk.
- **Check order.** Walk-first changes which word some malformed frames get (`LENGTH` before `DIGEST` or `RECORD`). The host treats all of them as refusals.
- **Fact order.** Sorting rows on the host changes the order of facts within a key for DMF and spans. Decisions are order-free below `capN` only if every rule uses `any`/`all` over `facts` (Flat/Model.lean:268). This is not proved; the signer-free check, and `PAIRS_DIGEST` once the signer is present, are the checks. Above `capN` the line is held either way.
- **Performance.**
  - The context copy in `decodeReqFast` can push the `_gate_bars` timing bars. Fallback: streaming SHA3.
  - Large request counts: the §17 preimage holds 64 bytes per request, and the decoders hold all `rd_i` at once. The 10,000,000-request frame of test_gate_rules_worker.py:70 is already expected to exhaust its 200 MB cap; frames well inside the cap now also need about 64 bytes per request more. DecodeB's task count is bounded (4.8).
- **The signer.** Without the pinned `rr_gate_mldsa87.exe` (LOG.md:295-310), the throughput digests and golden vectors cannot be regenerated and the test files that build on the shared harness cannot be collected. The signer-free check carries the decision claim here, but the step is not complete without the signer (Decision 20).
- **The unsigned harness.** It differs from the real path only in the verifier and the authority bytes. If its before run does not reproduce `PAIRS_DIGEST`, it is still a valid before-versus-after check, but a weaker one.
- **The test header split.** Two headers (frame and text) can drift apart. The state-1 test and the text-runner comparisons at test_flat_host.py:214-220 and test_flat_worker.py:124 catch drift that matters.
- **Upstream divergence.** If rr-core builds v2 differently, our v3 forks; the domain numbers could also collide. Mitigation: tell rr-core (decision 16).
- **Anonymous `⟨…⟩` constructions** of `Req`/`Pre` beyond Frame/Spec.lean:2068 show up as build errors. Builds are minutes, so the loop is cheap.
- **Statement-pin run time**, up to 1,800 s per Lean call (rightrail/tests/test_statement_pin.py:45), is the longest machine step.

## 11. Decisions for the owner

Each has a one-word default.

1. **Route.** Route A: FRAME/v3 = §17/§19 v2 plus two feeds, header 3, CONTEXT/v2, answer v3. Route B (v1 body) only by a separate explicit word. Default: **A**.
2. **Waiting for rr-core.** Ask now whether they take the feeds into v2, and ask for the pinned signer in the same message; start the route-independent work (answer side, types, DecideRows, signer-free check) at once; build Route A ourselves if there is no answer by a date the owner sets. Default: **bounded**.
3. **§20 in `gate_engine`.** ENGINE_V3 §20 steps 1 and 2 are met by Engine3/hist3 only, and the pinned `gate_engine` runs the revision 1 decision path and store. Neither step is carried into `gate_engine`; record this. Default: **skip**.
4. **Check order.** Length walk, then digest, then parse. Default: **walk**.
5. **Digest preimage.** The literal §17 form `dom ‖ body′ ‖ rd…`, not an lp32 `body′`. Default: **literal**.
6. **New feeds unread in step 2.** Defer `Ctx` fields, `ctxOf` snaps, `Feeds`/`FCtxInv`/`feedCapped`, `Ix`, ReadB reads, Engine3 pins and the 1,024 cap for elig/soc to step 3, departing from plan lines 233-246. Their descriptors are bound into CONTEXT/v2 but not pin-verified until then. Default: **defer**.
7. **One version constant.** `Frame.version := 3` for request and answer. Default: **yes**.
8. **Frame-local domains.** FRAME/v3 and CONTEXT/v2 as Frame literals; Gate/Spec.lean, which is in both the `gate_engine` and `gate_verify` closures, stays untouched, so `gate_verify` does not move. Default: **yes**.
9. **`Leaf.ok`.** Loose (low 62 bits rule bits, 62/63 free) rather than strict (alone only). Default: **loose**.
10. **Width facts.** Accept `reasons.length ≤ 62` and `≤ 32` as labelled field budgets, not D8 guards. Default: **accept**.
11. **Host read set.** `request_frame` accepts four feeds (padded with two absent ones) or six, and refuses any other count; ffs is untouched. Default: **pad**.
12. **Open proofs.** Record `pinInputW_eq`, `feedW_eq`, `feedW_at_eq`, `rd_i` reuse and `decodeAns_leafCount` as not claimed; Engine3 keeps its sort. Default: **record**.
13. **Vectors file.** Keep the name `gate_v1.vectors`; keep `context c0` as CONTEXT/v1; add `context2` and `frame3` lines and Vectors.lean kinds; update the signer-free `answer`/`context2`/`frame3` lines here (so `gate_vectors` stays green), and run the full regeneration when the signer is available. Default: **keep**.
14. **Old data.** v1 stores, logs and `.pending.N` frames are refused after the upgrade. Default: **accept**.
15. **Stale docs.** Fix in this commit: ENGINE_V3.md:155 and :502-504, FRAME_V1.md:5-6 and :7 ("No vectors are published yet"), the lakefile `frame_statements` comment (rightrail/lean/lakefile.toml:49, "not yet proved; not imported by any exe", fixed in the edit that adds `gate_engine_unsigned`), FLAT_V1.md:156-157 (`rq` is the batch identity, `Frame.ident` over CONTEXT/v2 and INPUT/v6), conformance/README.md:44-45 and Frame/Spec.lean:22-23. STATUS.md:64 separately. Default: **yes**.
16. **Tell rr-core** that FRAME/v3 and CONTEXT/v2 are taken by this layout and ask them to reserve the numbers. Default: **yes**.
17. **Field range checks.** No decoder check on `level`/`met` in step 2. At step 3 a value above 1 makes the snapshot unusable (STALE), per `okElig`/`okSoc`. Default: **none**.
18. **Commit shape.** One commit and one re-pin for the whole step, even if the answer side is authored first. Default: **one**. Amended 2026-11-21 (owner: "Yes, combined"): the request side is finished on `codex/rightrail-trunk-step3` on top of G2 (a), and one re-pin covers the step 2 request side and G2 (b) together (TRUNK_STEP3_G2_DESIGN.md decision 2). WIP commits stay separate and move no pin. The replacement for the strict before/after check on a G2-free tree (decision 19) is still to be approved.
19. **Not-run tests.** Accept the step 1 environment list (signer, browser, git history, ARM64, Python 3.14, file locks, provider-app artifact) as "not run here" for this commit. The signer-free decision check is excluded from this and may not be waived. Default: **accept**. Amended 2026-11-21 (owner: "Approve your recommendations for D2 and D4"), under the combined re-pin of decision 18: the signer-free decision check takes two forms, both required. (A) When the request side builds: pairs from the tree holding G2 (a) with v1 frames must equal pairs from the same tree with the request side on top; this needs `gate_engine_unsigned` rebuilt on the current tree first. (B) As the gate for the combined re-pin: the TRUNK_STEP3_G2_DESIGN.md 7.2 re-run, with a usable elig feed on every line the pairs must equal the recorded pre-step-2 pairs (`PAIRS_DIGEST`), and with none every former ALLOW must be HUMAN_REVIEW STALE_ELIGIBILITY. The "mis-pinned elig feed gives the same pairs" leg is run before (b) reads the feed; after (b) a mis-pinned feed is expected to send lines to review.
20. **Signer-blocked regenerations.** The `OUTPUT_DIGEST`/`REALISTIC_DIGEST` re-pin, the `PAIRS_DIGEST` assertion in test_gate_throughput and the full gate_v1.vectors regeneration with its byte-reproduction test need the pinned signer. The vectors' `answer`, `context2` and `frame3` lines do not, and are updated in this step either way, so `gate_vectors` passes here before and after the signer arrives. Wait: hold the commit until the signer arrives, then do them and commit once. Defer: commit with them listed as deferred, the throughput digests knowingly stale and the vectors file unconfirmed against `build_vectors`, with a follow-up commit owed. Default: **wait**.
21. **Shared test header.** Frames use an n33-only header (small-number DMF and span rows dropped, pins recomputed, a state-1 test added); the text runner keeps today's header as `_TEXT_HEAD`. Route A only. Default: **split**. Amended 2026-11-21 (owner: "Approve your recommendations for D2 and D4"): the split also covers the elig rows, in step 2. The frame header carries n33-only elig rows, re-keyed over the elig rows' own member list (members 1004 and 9002 have no span row), with the count and pin recomputed and elig added to the state-1 test; `_TEXT_HEAD` keeps the small elig rows, and shards_v1.vectors and its golden elig pin do not move. A well-pinned soc feed for the check is still owed (no soc rows exist yet).
22. **Signer-free harness.** Add the `verify` parameter (a `FlatW` field used at Flat/Worker.lean:237, threaded through `OneProc.run`, passed as `mlDsaOk` by EngineMain and RulesCrashtest; decision-neutral, inside this step's re-pin), the test-only `gate_engine_unsigned` exe (root `BlindLedger.Gate.Engine.EngineUnsigned`), the unsigned fixture, a lazy authority in `_gate_shards` that resolves to the fixture only under an explicit `RR_GATE_UNSIGNED=1`, and a lazy `GENESIS` in test_flat_worker. Default: **yes**.
