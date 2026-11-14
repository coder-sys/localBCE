import BlindLedger.Gate.Engine3.Load
import BlindLedger.Gate.Engine3.BatchDigest
import BlindLedger.Gate.Flat.DecideRows
import BlindLedger.Gate.Flat.Worker
import BlindLedger.Gate.Engine3.ReadB

/-! Pieces of one gate batch on the history engine: the bench phase clock, the answer's binding and leaves, the batch
    digest, the signature memo, the feed readers and the leaf check.  The batch itself runs in `StepH`.  Synthetic,
    nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.Run

open BlindLedger.Gate BlindLedger.Gate.Rules BlindLedger.Gate.Flat BlindLedger.Gate.Flat.Worker
open Std (HashMap HashSet)
open BlindLedger.Gate.Frame (Word Rec Rule AnsFrame Ext)

def nPhases : Nat := 44

/-- Bench diagnostic (`RR_E3_MEMDIAG`, `memDiag`): nanoseconds by phase of the live batch, summed.  Slots: 0 unused,
    1 byte read path, 2 spawn, 3 puts, 4 wait for the answer, 5 admit and setup, 6 events, 7 frame, 8 log append and
    sync, 9 seal file, 10 key hashing, 11 the rest of the batch after the decision (verifier),
    15 lines, 16 whole batch, 17 feeds, 18 probes, round 2 and layout, 20 store lines and rows, 21 key digests (17,
    18, 20 and 21 inside 1), 19 decideRows, 27 the spec decision (model runs only).  The history engine adds: 22 request read from the pipe, 23 decode, 24 the batch
    (decoded request to answer), 25 answer write, 26 the whole loop turn (request header read to answer written), 28 and 29
    the answer and batch digest tasks, 30 to 35 inside the answer task (30 lines root, 31 input hash, 32 leaf copy, 33 row
    push, 34 answer hash, 35 header and records), 36 the stamp clock, 37 the answer's inputs built and the tasks started,
    38 the leaf inputs (in the answer task), 39 `patchAns`, 40 the spec decoder's check of the byte decoder, 41 the spec admission's
    check of the byte admission (both only on checked batches). -/
initialize phases : IO.Ref (Array Nat) ← IO.mkRef (Array.replicate nPhases 0)

def tick (i t0 : Nat) : IO Nat := do
  let t ← IO.monoNanosNow
  phases.modify (·.modify i (· + (t - t0)))
  pure t

/-- Bench only: `x`, and the time since the last stamp added to slot `i` of `phases` (slot 36 is the clock; stamping it only
    sets it).  Strict, so `x` is computed before the stamp; the stages of a chain that depends on its predecessor are timed
    in order. -/
@[noinline] unsafe def stampImpl {α : Type} (i : Nat) (x : α) : α := unsafeBaseIO do
  let t ← IO.monoNanosNow
  phases.modify fun a => (a.modify i (· + (t - a[36]!))).set! 36 t
  pure x

@[implemented_by stampImpl] def stamp {α : Type} (_ : Nat) (x : α) : α := x

/-- The process's CPU time (user and kernel) in 100 ns units. -/
@[extern c inline "({ extern void* rr_gcp2(void) __asm__(\"GetCurrentProcess\"); extern int rr_gpt(void*, void*, void*, void*, void*) __asm__(\"GetProcessTimes\"); unsigned long long c_[2], e_[2], k_[2], u_[2]; rr_gpt(rr_gcp2(), c_, e_, k_, u_); lean_io_result_mk_ok(lean_box_uint64(k_[0] + u_[0])); })"]
opaque procCpu : IO UInt64

/-- Private bytes, working set, committed and peak committed bytes of the allocator, as four little-endian `UInt64`s;
    the allocator collects first when `c` is not 0, and with 2 prints its statistics on stderr. -/
@[extern c inline "({ extern void* rr_gcp(void) __asm__(\"GetCurrentProcess\"); extern int rr_pmi(void*, void*, unsigned) __asm__(\"K32GetProcessMemoryInfo\"); unsigned long long m[10] = {80}; size_t e0, u0, s0, r0, r1, c0, c1, pf; if (#1) mi_collect(1); if ((#1) == 2) mi_stats_print(NULL); rr_pmi(rr_gcp(), m, 80); mi_process_info(&e0, &u0, &s0, &r0, &r1, &c0, &c1, &pf); lean_object* a = lean_alloc_sarray(1, 32, 32); uint64_t* p = (uint64_t*)lean_sarray_cptr(a); p[0] = m[9]; p[1] = m[2]; p[2] = c0; p[3] = c1; lean_io_result_mk_ok(a); })"]
opaque procMem (c : UInt8) : IO ByteArray

/-- The allocator commits a segment's pages when they are first used, not when the segment is reserved (it measured 2.1 GB of
    committed memory never touched at 150k lines).  Called first in `main` of the engine and the verifier. -/
@[extern c inline "(mi_option_set_enabled(mi_option_eager_commit, 0), lean_io_result_mk_ok(lean_box(0)))"]
opaque lazyCommit : IO Unit

/-- The authority record of a store's first batch. -/
def initAuth (q : Frame.Req) : AuthRec := ⟨q.auth.pin, Keyset.Ratchet.init q.auth.pin, 0⟩

def zero64 : ByteArray := ⟨Array.replicate 64 0⟩

/-- Where an answer's head and root sit: after the header and 16 bytes a record. -/
def headAt (a : ByteArray) : Nat := Frame.ansHdrBytes + 16 * getN a 19 4

/-- `an`: the logged answer with its head and root cut out. -/
def ansBind (a : ByteArray) : ByteArray :=
  sha3_512Into ByteArray.empty (domB "ANSWER" ++ a.extract 0 (headAt a)) a (headAt a + 128) (a.size - (headAt a + 128))

/-- Each reason in `Rules.reasons` order: its bit in a line's reason mask (`Rows.bit`), its place (`Reason.idx`) and its leaf
    bit.  Computed once, so no payment searches the reason list. -/
def reasonTab : Array (UInt32 × Nat × Nat) := (Rules.reasons.zipIdx.map fun (r, i) => (Rows.bit r, r.idx, 2 ^ i)).toArray

/-- The leaf reason mask (`leafMask` of `Run.leafReasons`) of a payment that fits, whose decided lines' reason masks have
    union `m`: each reason's bit at its place in `Rules.reasons` (`Reason.idx`, as `Rows.bit`). -/
def leafBits (m : UInt32) : Nat :=
  reasonTab.foldl (fun a (b, _, p) => if m &&& b != 0 then a ||| p else a) 0

theorem leafBits_eq (m : UInt32) :
    leafBits m = Rules.reasons.zipIdx.foldl (fun a (r, i) => if m &&& Rows.bit r != 0 then a ||| 2 ^ i else a) 0 := by
  simp only [leafBits, reasonTab]
  rw [List.foldl_toArray, List.foldl_map]

/-- Byte `i` of `d`, zero past its end. -/
def byteOr0 (d : @& ByteArray) (i : Nat) : UInt8 := if h : i < d.size then d[i] else 0

/-- The eight bytes at `o` of `d` as a little-endian word, zero past its end. -/
@[noinline] def ldTail (d : @& ByteArray) (o : Nat) : UInt64 :=
  L8 (byteOr0 d o) (byteOr0 d (o + 1)) (byteOr0 d (o + 2)) (byteOr0 d (o + 3)) (byteOr0 d (o + 4)) (byteOr0 d (o + 5))
    (byteOr0 d (o + 6)) (byteOr0 d (o + 7))

@[inline] def ldSafe (d : @& ByteArray) (o : Nat) : UInt64 := if o + 8 ≤ d.size then ldu d o else ldTail d o

/-- The eight bytes of `x` in the opposite order. -/
@[inline] def bswap64 (x : UInt64) : UInt64 :=
  let x : UInt64 := ((x &&& (0x00FF00FF00FF00FF : UInt64)) <<< (8 : UInt64)) ||| ((x >>> (8 : UInt64)) &&& (0x00FF00FF00FF00FF : UInt64))
  let x : UInt64 := ((x &&& (0x0000FFFF0000FFFF : UInt64)) <<< (16 : UInt64)) ||| ((x >>> (16 : UInt64)) &&& (0x0000FFFF0000FFFF : UInt64))
  (x <<< (32 : UInt64)) ||| (x >>> (32 : UInt64))

def rowLen : Nat := 1 + Rules.Run.rowWidths.sum

/-- An appended row before its fields are written: the set tag and zeros. -/
def rowBlank (tag : UInt8) : ByteArray := ByteArray.empty.push tag ++ ⟨Array.replicate (rowLen - 1) 0⟩

def rowBlank1 : ByteArray := rowBlank 1
def rowBlank2 : ByteArray := rowBlank 2

/-- `b` with the `w` bytes at `s` of `lb` written last first, ending just before `e` (eight bytes a store while eight remain). -/
def revInto (b : ByteArray) (lb : @& ByteArray) (s w e i : Nat) : ByteArray :=
  if i + 8 ≤ w then
    revInto (BlindLedger.Semantic.Quick.set8 b (e - i - 8) (bswap64 (ldSafe lb (s + i)))) lb s w e (i + 8)
  else if i < w then revInto (b.set! (e - 1 - i) (byteOr0 lb (s + i))) lb s w e (i + 1)
  else b
termination_by w - i

/-- `b` with the `RULES_ADDS` row (set tag `tag`) of the store line at byte `o` of `lb`: `Run.rowBytesFast tag l` of the
    line `l` that `putLine` wrote there, each field big-endian at its row width from its little-endian store bytes (the
    member's `0x01` top byte implied, `isN33`).  The row is appended zeroed and its field bytes written in place. -/
def pushRowStore (b : ByteArray) (lb : @& ByteArray) (o : Nat) (tag : UInt8) : ByteArray :=
  let e0 := b.size + 1
  let b := b ++ (if tag == 1 then rowBlank1 else rowBlank2)
  let f (st : ByteArray × Nat) (s w rw : Nat) : ByteArray × Nat :=
    let (b, e) := st
    (revInto b lb (o + s) w (e + rw) 0, e + rw)
  let (b, e) := f (f (b, e0) 0 idW Rules.idWidth) idW payW Rules.payWidth
  let m := idW + payW
  let b := (b.set! e lb[o + m]!).set! (e + Rules.idWidth - 32) 1
  let (b, e) := (revInto b lb (o + m + 1) 32 (e + Rules.idWidth + 1) 0, e + Rules.idWidth + 1)
  let p := m + 33
  let (b, e) := f (f (b, e) p provW Rules.idWidth) (p + provW) provW Rules.idWidth
  let t := p + 2 * provW
  (f (f (f (f (b, e) t 4 4) (t + 4) procW Rules.idWidth) (t + 4 + procW) 4 4) (t + 8 + procW) 8 8).1


/-- How many of the first `n` bytes at `o` of `src` reach the highest nonzero one (eight at a time while they are zero). -/
def topLen (src : @& ByteArray) (o n : Nat) : Nat :=
  if n = 0 then 0
  else if 8 ≤ n ∧ ldSafe src (o + n - 8) == 0 then topLen src o (n - 8)
  else if byteOr0 src (o + n - 1) != 0 then n else topLen src o (n - 1)
termination_by n

/-- The number of LEB128 bytes of the number whose `w` bytes at `o` of `src` are little endian, below a top byte `top` at place
    `w` (none when 0). -/
def lebLen (src : @& ByteArray) (o w : Nat) (top : UInt8) : Nat :=
  let len := if top != 0 then w + 1 else topLen src o w
  if len = 0 then 1 else
  let hi : UInt8 := if top != 0 then top else byteOr0 src (o + len - 1)
  (8 * (len - 1) + Nat.log2 hi.toNat + 1 + 6) / 7

/-- The low 56 bits of `x` as eight 7-bit groups, one to a byte. -/
@[inline] def spread7 (x : UInt64) : UInt64 :=
  let y : UInt64 := (x &&& (0xFFFFFFF : UInt64)) ||| ((x &&& (0xFFFFFFF0000000 : UInt64)) <<< (4 : UInt64))
  let z : UInt64 := (y &&& (0x00003FFF00003FFF : UInt64)) ||| ((y &&& (0x0FFFC0000FFFC000 : UInt64)) <<< (2 : UInt64))
  ((z &&& (0x007F007F007F007F : UInt64)) ||| ((z &&& (0x3F803F803F803F80 : UInt64)) <<< (1 : UInt64)) : UInt64)

/-- Write at `pos` of `buf` the `nout` LEB128 bytes (`lebLen`) of that number, eight bytes a store from lane `j` on: seven source
    bytes a lane, the continuation bits set by one mask, the last byte's cleared.  The stores may write up to seven bytes past
    the number, which the next number overwrites. -/
def lebWrite (buf : ByteArray) (pos : Nat) (src : @& ByteArray) (o w : Nat) (top : UInt8) (nout j : Nat) : ByteArray :=
  if 8 * j < nout then
    let s := 7 * j
    let x : UInt64 := if s + 7 ≤ w then ldSafe src (o + s) &&& 0xFFFFFFFFFFFFFF
      else (ldSafe src (o + s) &&& ((1 <<< (8 * (w - s)).toUInt64) - 1)) ||| (top.toUInt64 <<< (8 * (w - s)).toUInt64)
    let v : UInt64 := spread7 x ||| 0x8080808080808080
    let v : UInt64 := if nout ≤ 8 * j + 8 then v &&& ~~~(0x80 <<< (8 * (nout - 1 - 8 * j)).toUInt64) else v
    lebWrite (BlindLedger.Semantic.Quick.set8 buf (pos + 8 * j) v) pos src o w top nout (j + 1)
  else buf
termination_by nout - 8 * j

/-- A buffer of at least `n` bytes. -/
def sizedBuf (n : Nat) : ByteArray := Id.run do
  let mut b := BlindLedger.Semantic.Quick.zeros
  while b.size < n do b := b ++ b
  return b

/-- The bytes of one line's ten numbers (`one` of `batchDigestB`), in `enc` order, written from `pos` of `buf`. -/
def digestLine (buf : ByteArray) (pos : Nat) (lb : @& ByteArray) (o : Nat) : ByteArray × Nat :=
  let a1 := o + idW + payW
  let n1 := lebLen lb a1 1 0
  let buf := lebWrite buf pos lb a1 1 0 n1 0
  let pos := pos + n1
  let n2 := lebLen lb (a1 + 1) 32 1
  let buf := lebWrite buf pos lb (a1 + 1) 32 1 n2 0
  let pos := pos + n2
  let n3 := lebLen lb (o + 156) provW 0
  let buf := lebWrite buf pos lb (o + 156) provW 0 n3 0
  let pos := pos + n3
  let n4 := lebLen lb (o + 177) provW 0
  let buf := lebWrite buf pos lb (o + 177) provW 0 n4 0
  let pos := pos + n4
  let n5 := lebLen lb (o + 198) 4 0
  let buf := lebWrite buf pos lb (o + 198) 4 0 n5 0
  let pos := pos + n5
  let n6 := lebLen lb (o + 202) procW 0
  let buf := lebWrite buf pos lb (o + 202) procW 0 n6 0
  let pos := pos + n6
  let n7 := lebLen lb (o + 233) 4 0
  let buf := lebWrite buf pos lb (o + 233) 4 0 n7 0
  let pos := pos + n7
  let n8 := lebLen lb (o + 237) 8 0
  let buf := lebWrite buf pos lb (o + 237) 8 0 n8 0
  let pos := pos + n8
  let n9 := lebLen lb o idW 0
  let buf := lebWrite buf pos lb o idW 0 n9 0
  let pos := pos + n9
  let n10 := lebLen lb (o + idW) payW 0
  (lebWrite buf pos lb (o + idW) payW 0 n10 0, pos + n10)

/-- `lebPush` of `n` into `buf` at `pos`: the buffer and the next place. -/
def lebNatAt (buf : ByteArray) (pos n : Nat) : ByteArray × Nat :=
  if n < 128 then (buf.set! pos n.toUInt8, pos + 1) else lebNatAt (buf.set! pos (n % 128 + 128).toUInt8) (pos + 1) (n / 128)
termination_by n
decreasing_by omega

/-- `batchDigestFast au` of the released lines `rel` and unresolved lines `unr`, each a row of the store lines `lb`, read in
    place in `enc` order, written once into one buffer and hashed over its filled range (`batchDigestB_eq`, open: equal when
    row `i` of `lb` is the store line of line `i`). -/
def batchDigestB (lb : @& ByteArray) (au : ByteArray) (rel unr : Array Nat) : ByteArray :=
  let dom : ByteArray := ⟨(domain "CHAIN" ++ [0x03]).toArray⟩
  let buf := sizedBuf (dom.size + 10 + au.size + 32 + 290 * (rel.size + unr.size))
  let buf := dom.copySlice 0 buf 0 dom.size
  let (buf, p) := lebNatAt buf dom.size au.size
  let buf := au.copySlice 0 buf p au.size
  let one : ByteArray × Nat → Nat → ByteArray × Nat := fun (b, p) i => digestLine b p lb (lineW2 * i)
  let st := rel.foldl one (lebNatAt buf (p + au.size) rel.size)
  let (b, p) := st
  let (b, p) := unr.foldl one (lebNatAt b p unr.size)
  sha3_512Into ByteArray.empty ByteArray.empty b 0 p

/-- A request's leaf with its input not yet computed, the request, and the admitted grant's id. -/
abbrev LeafIn := Frame.Leaf × Run.Req × ByteArray

/-- Request `x`'s leaf but its input: `Run.emitWith` (`Run.uncovered` when no entry of the grant covers
    it), then `leafOf`.  `ent`: the request's entry (`entriesOf`); `gid`: the grant's id as bytes; `unf`: a line of it does
    not fit; `f` its payment's bits (1 a HOLD line, 2 a line that is not an own ALLOW, 4 any line, 8 a released line that
    was not ALLOW, 16 a bypass releases it (`Rows.Out.byd`), 32 it goes at HOLD authority (`Rows.Out.lft`,
    `Run.limited`)) and `m` the union of its lines' reason masks. -/
def leafIn (a : Run.Admitted) (gid : ByteArray) (x : Run.Req) (ent : Option Authority.Entry) (unf : Bool) (f : UInt8)
    (m : UInt32) : LeafIn :=
  let r := x.ra
  let z := Gate.zeroDigest
  let (o, rs, au, bp) : Outcome × Nat × Gate.Authority × Bytes :=
    match ent with
    | none => (if r.flow.ruled then .HOLD else .HUMAN_REVIEW, 2 ^ 25, .OBSERVE, z)
    | some en =>
      let bp : Bytes := match a.byps.filter (fun b => b.program == r.programId.toList && b.payment == r.paymentId.toList) with
        | [y] => if !unf && f &&& 16 != 0 && y.request == Run.hB x.x && y.id != z then y.id else z
        | _ => z
      let o0 : Outcome := if f &&& 1 != 0 then .HOLD else if f &&& 4 != 0 && f &&& 2 == 0 then .ALLOW else .HUMAN_REVIEW
      let o : Outcome := if unf then .HOLD else if bp != z || f &&& 32 != 0 then .ALLOW else o0
      (o, if unf then 2 ^ 24 else leafBits m, en.authority, bp)
  let leaf : Frame.Leaf :=
    { outcome := Frame.outCode o, reasons := rs, authority := [Gate.Authority.OBSERVE, .HOLD, .TRANSFER].idxOf au
      bypass := bp.toByteArray, input := .empty }
  (leaf, x, gid)

/-- `Frame.Fast.linesRootA` with each line's leaf hash read in place after its domain. -/
def linesRootS (ls : List ByteArray) : ByteArray :=
  if ls.isEmpty then Gate.zeroDigest.toByteArray
  else Frame.Fast.treeRootA treeFuel (ls.map (hashDom (Frame.Fast.linesDomain.push 0)))

/-- The answer of a decided batch (word OK, head and root zero) in one buffer of its final size, its `an` and the batch's
    identity (`Frame.ident`): the records `recs` (`nr` of 16 bytes), the grant id (the leaves', zero when there are none),
    the notes, each request's leaf (`ls`) with its input (`INPUT/v6` over the context `ctx` and the payment digest over
    its lines root) computed here, and the rows the sets gain, lines `rel` (tag 1) then `unr` (tag 2) of the store lines
    `lb`. -/
def ansW (tm : Bool) (shard batch : Nat) (dg recs : ByteArray) (nr : Nat) (au : ByteArray) (notes : List ByteArray)
    (ls : Array LeafIn) (ctx : ByteArray) (lb : ByteArray) (rel unr : Array Nat) : ByteArray × ByteArray × ByteArray :=
  let blob (x : ByteArray) : Nat := 2 + x.size
  let nAdd := rel.size + unr.size
  let grant := match ls[0]? with
    | some (_, _, g) => g
    | none => noExt.grant
  -- the header (magic, version, word, shard, batch, record count), the digest, the records, head and root, the hold
  let cap := (4 + 19) + dg.size + recs.size + 2 * zero64.size + noExt.hold.size + grant.size + au.size + notes.foldl (· + blob ·) 4 +
    nAdd * (2 + rowLen) + 4 + 136 * ls.size + 4
  let st (i : Nat) {α : Type} (x : α) : α := if tm then stamp i x else x
  let b := st 36 (Frame.Fast.putL (ByteArray.emptyWithCapacity cap) Frame.magicAns)
  let put := Frame.Fast.put
  let b := put (put (put (put (put b 2 Frame.version) 1 (Word.code .OK)) 4 shard) 8 batch) 4 nr
  let b := b ++ dg ++ recs ++ zero64 ++ zero64 ++ noExt.hold ++ grant ++ au
  let b := st 35 (notes.foldl Frame.Fast.putBlob2 (put b 4 notes.length))
  let inPre := Frame.Fast.inputDomain ++ ctx
  let (b, rqs) := ls.foldl (fun (b, rqs) (l, x, _) =>
    let root := st 30 (linesRootS x.ra.lines)
    let input := st 31 (hashDom inPre (Frame.Fast.payDigestR x root))
    (st 32 (Frame.Fast.putLeaf b { l with input }), rqs.push input)) (put b 4 ls.size, Array.mkEmpty ls.size)
  let b := st 33 (unr.foldl (fun b i => pushRowStore (put b 2 rowLen) lb (lineW2 * i) 2)
    (rel.foldl (fun b i => pushRowStore (put b 2 rowLen) lb (lineW2 * i) 1) (put b 4 nAdd)))
  (b, st 34 (ansBind b), Frame.Fast.batchInputFast ctx rqs)

/-- `f ()` on another core.  With a profile its nanoseconds go to slot `i`; `ok` (true of every result) makes the clock
    wait for the value. -/
def spawnT {α : Type} (prof : Option (IO.Ref (Array Nat))) (i : Nat) (ok : α → Bool) (f : Unit → α) : BaseIO (Task α) :=
  match prof with
  | none => pure (Task.spawn f)
  | some pr => BaseIO.asTask do
    let t0 ← IO.monoNanosNow
    let x := f ()
    let t1 ← if ok x then IO.monoNanosNow else pure t0
    pr.modify fun a => a.modify i (· + (t1 - t0))
    pure x

/-- The ML-DSA-87 verdicts this process has computed, by `sigKey`. -/
initialize sigCache : IO.Ref (HashMap ByteArray Bool) ← IO.mkRef {}

/-- SHA3-512 of the key and the message, each after its length (4 bytes), then the signature. -/
def sigKey (pk msg sig : Bytes) : ByteArray :=
  let lp (b : ByteArray) (x : Bytes) : ByteArray := Frame.Fast.putL (Frame.Fast.put b 4 x.length) x
  Bin.HB (Frame.Fast.putL (lp (lp (ByteArray.emptyWithCapacity (8 + pk.length + msg.length + sig.length)) pk) msg) sig)

unsafe def mlDsaMemoImpl (pk msg sig : Bytes) : Bool := unsafeBaseIO do
  let k := sigKey pk msg sig
  if let some v := (← sigCache.get).get? k then return v
  let v := mlDsaOk pk msg sig
  sigCache.modify fun m => (if 4096 ≤ m.size then {} else m).insert k v
  return v

/-- `mlDsaOk`, each verdict computed once a process.  `sigCache_sound` (open): a cached verdict is `mlDsaOk`'s of the
    same key, message and signature, unless SHA3-512 collides. -/
@[implemented_by mlDsaMemoImpl] def mlDsaMemo (pk msg sig : Bytes) : Bool := mlDsaOk pk msg sig

/-- Per feed kind, the bytes (77-byte descriptor, then rows) of the last feed whose pin `snapF` checked; empty for none. -/
initialize feedPins : IO.Ref (Array ByteArray) ← IO.mkRef #[.empty, .empty, .empty, .empty]

/-- Feed `k`'s descriptor and rows in request bytes `bs`, as (descriptor offset, rows offset, rows length), at
    `ReadB.feedsW`'s offsets. -/
def feedAt (bs : ByteArray) (k : Nat) : Nat × Nat × Nat :=
  let nrows (j : Nat) : Nat := getN bs (Frame.hdrBytes + 76 + 77 * j + 9) 4
  let w : Array Nat := #[37, 25, 29, 62]
  let o := (List.range k).foldl (fun o j => o + w[j]! * nrows j) (Frame.hdrBytes + 384)
  (Frame.hdrBytes + 76 + 77 * k, o, w[k]! * nrows k)

/-- Whether feed `k` of `bs` has the bytes of `known`, a feed whose pin was checked. -/
def feedKnown (known bs : ByteArray) (k : Nat) : Bool :=
  !known.isEmpty && Frame.hdrBytes + 384 ≤ bs.size &&
    let (d, o, n) := feedAt bs k
    o + n ≤ bs.size && known.size == 77 + n && Frame.Fast.sameBytes known bs 0 d 77 &&
      Frame.Fast.sameBytes known bs 77 o n

/-- `snapF`, with the pin taken as checked when `known` (`feedKnown_det`, open: the decoded feed is a function of its
    descriptor and row bytes, so equal bytes give `snapF`'s value). -/
def snapK {α : Type} (known : Bool) (kind : Nat) (fields : α → List (Nat × Nat)) (f : Frame.Feed α) :
    Option (Snapshot α × Bytes) :=
  if known && f.state == 1 then some (⟨f.asOf, f.count, f.rows⟩, f.pin) else snapF kind fields f

/-- `Run.fits` by shifts, with no power of 256 (`fitsS_eq`, open: `n >>> 8w = 0 ↔ n < 256 ^ w`). -/
def fitsS (l : Line) : Bool := l.fields.all fun (w, n) => n >>> (8 * w) == 0

/-- Whether answer `ab` is, byte for byte, the encoding of its own decoding with each leaf replaced by the spec's
    (`leafOf` of the spec payment `pays` and the leaf's own input, which the host recomputes from the request). -/
def leavesMatch (pays : List Run.Pay) (ab : ByteArray) : Bool :=
  match Frame.decodeAns ab.toList with
  | some f => pays.length == f.ext.leaves.length &&
      Frame.Fast.encodeAnsFast { f with ext := { f.ext with leaves := (pays.zip f.ext.leaves).map fun (m, l) => leafOf m l.input } } == ab
  | none => false

end BlindLedger.Gate.Engine3.Run
