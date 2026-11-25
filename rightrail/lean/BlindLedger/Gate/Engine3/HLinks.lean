import BlindLedger.Gate.Engine3.Hist
import BlindLedger.Gate.FactStore

/-! # Links files of the rows-file store (fact record design §2.7)

One file per row set, `released.links` and `unresolved.links`.  Record `seq` is the 32 bytes at `32 * seq`, the links
record of row `seq` of the set's rows file, as `FactStore.linksP` writes it: the previous row of the set with the same
member, payee and rendering provider (each plus one, 40 bits; 0 none), then the row's batch (40 bits), the index of its
record in that batch's answer (24 bits), the record's reason bits (32 bits), its rule (1 released, 2 unresolved, 5
released by bypass) and the day of the batch's authority record (32 bits).  Little endian.

The answer fields come from the answer alone: a set's rows are the lines of its records in record order (rule 1 and 5
records for the released set, rule 2 for the unresolved one: `Frame.rows_of_records`), so the `k`-th row a batch adds to
a set gets the `k`-th such record.  The links come from the order of the rows.  So a links file is a projection of the
log, kept as the rows file is: appended in the same pass as the rows and not synced per batch (a clean stop syncs it), cut
at open to the rows the log confirms, and computed from the log after a start that is not trusted.  A trusted start (a
clean stop, or an open this process completed) reads the file and computes each record's links again from the rows: the
file is kept up to the first record whose links differ or whose rule is not its set's (1 or 5 released, 2 unresolved),
and the records after it are computed from the frames' answers.  The other answer fields of a kept record are not
computed again: damage behind a completed sync is outside the threat model.

What is proved and what is tested.  `FactStore.links_projection` is proved over records already derived: the writer of a
prefix, loaded and extended by the rest, is the writer of the whole list.  That the answers give those records
(`tailsOf`) and that this load keeps what `FactStore.loadLinks` keeps (here the kept prefix may end inside a batch) are
checked by `#guard`s and the crash test, not proved.

Heads.  Per set, three `Index` tables name, per member, payee and rendering provider, the newest row of the set naming it.
A slot is a hint: the row it names is read and its key compared, so a table's 8 bytes a key decide nothing.  A key's
table words are the store key's digest of its bytes (`Hist.hashOf`), so keys that share a prefix do not share words.
The tables are built at open from the rows and hold nothing the files do not.
Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.Links

open BlindLedger.Gate BlindLedger.Gate.Flat

def linkW : Nat := 32
def tailW : Nat := 17

/-- The offset and width in a row of chain `c`'s key: the member, the payee, the rendering provider
    (`FactStore.memberOf`, `payeeOf`, `renderingOf`). -/
def keyAt (c : Nat) : Nat × Nat := if c == 0 then (124, 32) else if c == 1 then (156, 21) else (177, 21)

/-- The table words of chain `c`'s key in row `r`. -/
def words (ctx : KeyCtx) (c : Nat) (r : ByteArray) : UInt64 × UInt64 :=
  let (o, w) := keyAt c
  Hist.hashOf ctx (r.extract o (o + w)) false

/-- Rows `a` and `b` hold the same bytes at `[o, o + w)`. -/
def sameAt (a b : ByteArray) (o w : Nat) : Bool := Id.run do
  for i in [o:o + w] do
    if a.get! i != b.get! i then return false
  return true

/-- Where row `r` joins chain `c` of table `ix`: the newest row with its key plus one (0 none), that row's slot, and the
    key's table words.  Every row a hint names is read (`rec`) and compared. -/
def look (ctx : KeyCtx) (rec : Nat → IO ByteArray) (ix : Index.Idx) (c : Nat) (r : ByteArray) :
    IO (Nat × Option Nat × UInt64 × UInt64) := do
  let (h1, h2) := words ctx c r
  let (o, w) := keyAt c
  for (s, pos) in Hist.hintsOf ix h1 h2 do
    if sameAt (← rec s) r o w then return (s + 1, some pos, h1, h2)
  return (0, none, h1, h2)

/-- Row `j` made the newest row of its key, at the place `look` found. -/
def join (ix : Index.Idx) (j : Nat) : Nat × Option Nat × UInt64 × UInt64 → Index.Idx
  | (_, some pos, _, _) => ix.set pos (Index.withSeq (ix.get pos) j)
  | (_, none, h1, h2) => ix.insert h1 h2 j

/-- The three links of a record, appended to `b`. -/
def putLinks (b : ByteArray) (m p q : Nat) : ByteArray :=
  Frame.Fast.put (Frame.Fast.put (Frame.Fast.put b 5 m) 5 p) 5 q

/-- The answer fields of a record (`FactStore.tailC`), appended to `b`. -/
def putTail (b : ByteArray) (batch windex reasons rule day : Nat) : ByteArray :=
  Frame.Fast.put (Frame.Fast.put (Frame.Fast.put (Frame.Fast.put (Frame.Fast.put b 5 batch) 3 windex) 4 reasons) 1 rule) 4 day

/-- The answer fields of the rows answer `a` adds, 17 bytes a row: released (rule 1 and 5 records) and unresolved (rule 2),
    each in record order, with the answer's batch and the day of its authority record (the record after the batch).  None
    when the answer is too short for its records and authority record, its batch does not fit 40 bits, or a record's
    reasons (a u64 field) do not fit the row's 4 bytes. -/
def tailsOf (a : ByteArray) : Option (ByteArray × ByteArray) := Id.run do
  let nr := getN a 19 4
  let au := Frame.ansHdrBytes + 20 * nr + 128 + 16 + 64
  let batch := getN a 11 8
  if a.size < au + authLen || 2 ^ 40 ≤ batch then return none
  let o := au + 132
  let day := (a.get! o).toNat <<< 24 ||| (a.get! (o + 1)).toNat <<< 16 ||| (a.get! (o + 2)).toNat <<< 8 ||| (a.get! (o + 3)).toNat
  let mut rel := ByteArray.empty
  let mut unr := ByteArray.empty
  for i in [0:nr] do
    let p := Frame.ansHdrBytes + 20 * i
    let rule := (a.get! (p + 4)).toNat
    let m := getN a (p + 5) 8
    if 2 ^ 32 ≤ m then return none
    if rule == 2 then unr := putTail unr batch i m rule day
    else if rule == 1 || rule == 5 then rel := putTail rel batch i m rule day
  return some (rel, unr)

/-- One set's links file (`n` records) and its head tables: member, payee, rendering provider. -/
structure LSide where
  fd : UInt32
  n : Nat
  mem : Index.Idx
  pay : Index.Idx
  ren : Index.Idx

/-- Rows `ls.n ..` of set `st` (already in its rows file) get their records, with the answer fields `tails` (17 bytes a
    row), appended in one write. -/
def LSide.put (ls : LSide) (ctx : KeyCtx) (st : Hist.Side) (tails : ByteArray) : IO LSide := do
  let ⟨fd, n, m, p, q⟩ := ls
  let mut m := m
  let mut p := p
  let mut q := q
  let k := tails.size / tailW
  let rec_ := Hist.recOf st.f st.mem
  let mut out := ByteArray.emptyWithCapacity (linkW * k)
  for i in [0:k] do
    let j := n + i
    let r ← rec_ j
    let a ← look ctx rec_ m 0 r
    let b ← look ctx rec_ p 1 r
    let c ← look ctx rec_ q 2 r
    out := tails.copySlice (tailW * i) (putLinks out a.1 b.1 c.1) (linkW * i + 15) tailW false
    m := join m j a
    p := join p j b
    q := join q j c
  if k != 0 then
    if (← Io.pgWrite fd (linkW * n).toUInt64 out) != 0 then throw (IO.userError "links file: write failed")
  return ⟨fd, n + k, m, p, q⟩

/-- A rule the links file of set `u` (true: unresolved) may hold. -/
def ruleOf (u : Bool) (rule : UInt8) : Bool := if u then rule == 2 else rule == 1 || rule == 5

/-- Set `st`'s links file at `path`, beside its rows (exact by then); `u` the unresolved set.  `trusted`: the store's
    files are trusted (a clean stop, or an open this process completed).  A trusted file is cut to the rows and kept up
    to the first record whose links are not the ones the rows give, or whose rule is not its set's (`ruleOf`); any other
    file is emptied.  The tables are those of the rows whose records are kept.  The file is closed if the load throws. -/
def LSide.load (ctx : KeyCtx) (path : String) (st : Hist.Side) (u trusted : Bool) : IO LSide := do
  let fd ← Io.pgOpen path
  if fd == 0xFFFFFFFF then throw (IO.userError s!"links file {path}: open failed")
  try
    let size := (← System.FilePath.metadata path).byteSize.toNat
    let k0 := if trusted then min (size / linkW) st.f.n else 0
    let rec_ := Hist.recOf st.f st.mem
    let mut m := Index.Idx.new 10
    let mut p := Index.Idx.new 10
    let mut q := Index.Idx.new 10
    let mut k := 0
    let mut ok := true
    while ok && k < k0 do
      let cnt := min 4096 (k0 - k)
      let rows ← st.f.fetch k cnt
      let got ← Io.pgRead fd (linkW * k).toUInt64 (linkW * cnt).toUSize
      if got.size != linkW * cnt then break
      for i in [0:cnt] do
        let r := rows.extract (RowsFile.recW * i) (RowsFile.recW * (i + 1))
        let a ← look ctx rec_ m 0 r
        let b ← look ctx rec_ p 1 r
        let c ← look ctx rec_ q 2 r
        let rule := got.get! (linkW * i + 27)
        if putLinks .empty a.1 b.1 c.1 != got.extract (linkW * i) (linkW * i + 15) || !ruleOf u rule then
          ok := false
          break
        m := join m k a
        p := join p k b
        q := join q k c
        k := k + 1
    if size != linkW * k then
      if (← Io.pgTrunc fd (linkW * k).toUInt64) != 0 then throw (IO.userError s!"links file {path}: cut failed")
    return ⟨fd, k, m, p, q⟩
  catch e =>
    let _ ← Io.pgClose fd
    throw e

def LSide.close (ls : LSide) : IO Unit := do
  let _ ← Io.pgClose ls.fd

/-- Both sets' links files. -/
structure Two where
  rel : LSide
  unr : LSide

def Two.close (lk : Two) : IO Unit := do
  lk.rel.close
  lk.unr.close

def Two.sync (lk : Two) : IO Unit := do
  if (← Io.pgSync lk.rel.fd) != 0 || (← Io.pgSync lk.unr.fd) != 0 then throw (IO.userError "links file: sync failed")

/-- The answer fields `tr`, `tu` are one per row the sets `rel`, `unr` hold past the links files. -/
def Two.fits (lk : Two) (rel unr : Hist.Side) (tr tu : ByteArray) : Bool :=
  lk.rel.n + tr.size / tailW == rel.f.n && lk.unr.n + tu.size / tailW == unr.f.n

def Two.put (lk : Two) (ctx : KeyCtx) (rel unr : Hist.Side) (tr tu : ByteArray) : IO Two := do
  let ⟨lr, lu⟩ := lk
  return ⟨← lr.put ctx rel tr, ← lu.put ctx unr tu⟩

/-- After a load: the records the files lack, from the answers of the frames.  `ns[j]` is the sets' row counts after frame
    `j`, and `ansOf j` frame `j`'s answer, checked against its trailer.  None when an answer cannot be read or does not
    give each row it added one record. -/
def Two.extend (lk : Two) (ctx : KeyCtx) (rel unr : Hist.Side) (ns : Array (Nat × Nat))
    (ansOf : Nat → IO (Option ByteArray)) : IO (Option Two) := do
  let ⟨lr, lu⟩ := lk
  let mut lr := lr
  let mut lu := lu
  let mut r0 := 0
  let mut u0 := 0
  for j in [0:ns.size] do
    let (r1, u1) := ns[j]!
    if lr.n < r1 || lu.n < u1 then
      let some a ← ansOf j | return none
      let some (tr, tu) := tailsOf a | return none
      if tr.size != tailW * (r1 - r0) || tu.size != tailW * (u1 - u0) then return none
      if lr.n < r1 then lr ← lr.put ctx rel (tr.extract (tailW * (lr.n - r0)) tr.size)
      if lu.n < u1 then lu ← lu.put ctx unr (tu.extract (tailW * (lu.n - u0)) tu.size)
    r0 := r1
    u0 := u1
  return some ⟨lr, lu⟩

/-! ## The encoders against the specification (`FactStore`) -/

section Checks
open BlindLedger.Gate.FactStore BlindLedger.Gate.Obligations

def zs (n : Nat) : ByteArray := ByteArray.mk (Array.replicate n 0)

/-- An answer of batch 9 with three records (rules 2, 0 and 5) and an authority record of day 20260301. -/
def sampleAns : ByteArray :=
  let put := Frame.Fast.put
  let r (i rule mask : Nat) := put (put (put (put (put (put .empty 3 i) 1 0) 1 rule) 8 mask) 4 0) 3 0
  put (put (zs 11) 8 9) 4 3 ++ zs 64 ++ r 4 2 0x11 ++ r 0 0 0x2 ++ r 7 5 0x40 ++ zs (128 + 16 + 64) ++
    zs 132 ++ ByteArray.mk #[0x01, 0x35, 0x25, 0xCD] ++ zs (authLen - 136)

#guard tailsOf sampleAns == some ((tailC.enc ⟨9, 2, 0x40, 5, 20260301⟩).toByteArray,
  (tailC.enc ⟨9, 0, 0x11, 2, 20260301⟩).toByteArray)
#guard tailsOf (sampleAns.extract 0 (sampleAns.size - 1)) == none
-- a record's reasons beyond 4 bytes
#guard tailsOf (sampleAns.set! (Frame.ansHdrBytes + 9) 1) == none
#guard [(0, 0, 0), (1, 2 ^ 40 - 1, 7), (2 ^ 40, 3, 0)].all fun (m, p, q) =>
  let t : LinkTail := ⟨2 ^ 40 - 1, 2 ^ 24 - 1, 2 ^ 32 - 1, 1, 99991231⟩
  putTail (putLinks .empty m p q) t.batch t.windex t.reasons t.rule t.day ==
    (linksP.out (sampleRow 1 2 3, t) [⟨m, 1⟩, ⟨p, 1⟩, ⟨q, 1⟩]).toByteArray

end Checks

end BlindLedger.Gate.Engine3.Links
