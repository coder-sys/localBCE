import BlindLedger.X12.Split

/-! The chunk driver: the file is read in blocks and cut into units; each unit is folded by `readUnit` from what the
    fold keeps between interchanges (`Carry`), and its output is written in file order.  Memory is set by the block
    size, the unit length, the number of units read at once, the longest stretch of the file with no cut in it (a
    stretch with none is one unit) and the interchange controls seen (`Ctl`, at most 125 MB), not by the length of the
    file.

    A cut is where the fold itself is between interchanges: right after an interchange its `IEA` closed, with only white
    space up to the next header.  Headers found by their bytes alone are only candidates (a header's text can stand
    inside an element of an interchange with another terminator): the unit that ends at a candidate is folded with the
    bytes after it in view, and the candidate is a cut only when that fold reached it right after an `IEA` (the flag of
    `outerWith`).  Otherwise the unit is read again up to the last place inside it where its own fold was at a cut (the
    `cut` its carry records), or, with none, up to a candidate at least twice as far; nothing is refused for its length.
    The fold's part of putting the units together is `outerWith_split`, in `Split.lean`; that the units' outputs, one
    after another, are the whole-file fold's output with every offset moved by its unit's start is tested, not proved,
    by `tests/test_x12_stream.py`: word by word, each word is the whole read's, or differs from it by the unit's start
    at bit 0, 16 or 24, or by the length of the side text before the unit at bit 24 (where words pack offsets).

    Units are read `par` at a time, each from an empty carry but the first; their carries are joined in order, and a
    unit one of whose interchange controls (`Carry.ctls`) is in the set taken before it is read again from the joined
    carry (the controls are all its events depend on in the carry), so the output does not depend on `par` (tested byte
    for byte by the same test, not proved).

    Stream layout: for each unit of the file a block (tag 7, start, length, event bytes, side bytes, then those), and at
    the end the closing bytes of `trailer` (a file-level event when the file has no interchange, then tag 8); a stream
    that does not end with them is incomplete and must be refused whole. -/

namespace BlindLedger.X12

/-- The first interchange header that starts at or after `i` and lies whole in `d`, by its bytes alone. -/
partial def nextIsa (d : ByteArray) (i : Nat) : Option Nat :=
  let j := findB d 73 i d.size
  if j ≥ d.size then none else if (isaAt d j).isSome then some j else nextIsa d (j + 1)

/-- Up to `k` candidate unit ends: headers from `i` on, each at least `low` after the one before. -/
def unitEnds (w : ByteArray) (low : Nat) : Nat → Nat → Array Nat → Array Nat
  | 0, _, acc => acc
  | k + 1, i, acc =>
    match nextIsa w i with
    | none => acc
    | some j => unitEnds w low k (j + low) (acc.push j)

@[specialize] partial def streamX12 {σ : Type} [SetReader σ] (kind : ByteArray) (inp out : IO.FS.Handle)
    (blk lowMark par : Nat) : IO Unit := do
  let low := max lowMark 1
  let par := max par 1
  let rec drain (acc : Nat) : IO Nat := do
    let b ← inp.read blk.toUSize
    if b.size == 0 then pure acc else drain (acc + b.size)
  -- `w` is the file from `base` on, as read so far; the first unit ends at the first candidate at or after `first`;
  -- `bad` is the farthest end, from `base`, of a unit already found not to end at a cut (0 for none); no header starts
  -- at or after `first` and before `seen` (a header is its first 106 bytes, so a stretch with none is searched once)
  let rec go (w : ByteArray) (base : Nat) (eof : Bool) (c : Carry) (first bad seen : Nat) : IO Unit := do
    let wait := !eof && w.size < first + par * low + 106
    let ends := if wait then #[] else unitEnds w low par (max first seen) #[]
    if ends.isEmpty then
      if !eof then
        let b ← inp.read blk.toUSize
        -- `w` is not shared here, so the bytes are added in place (its room doubles when it grows)
        go (w ++ b) base (b.size == 0) c first bad (if wait then seen else w.size - 105)
      else
        -- the rest of the file is the last unit; after a cut it starts with a header, so it is empty only for an empty
        -- file, whose block of length 0 is the whole-file read's
        let (c', o, _) := readUnit (σ := σ) kind base c w w.size
        out.write (unitBlock base w.size o)
        out.write (trailer c')
    else
      -- the first unit is read here, after the others are started (so with `par` 1 no task is made)
      let mut jobs := #[]
      let mut at0 := ends[0]!
      for e in ends.extract 1 ends.size do
        let s := at0
        let ud := w.extract s (e + 106)
        let b := base + s
        jobs := jobs.push (s, e, ud, Task.spawn fun _ => readUnit (σ := σ) kind b { first := false } ud (e - s))
        at0 := e
      let e0 := ends[0]!
      let ud0 := w.extract 0 (e0 + 106)
      jobs := #[(0, e0, ud0, Task.pure (readUnit (σ := σ) kind base c ud0 e0))] ++ jobs
      let mut c := c
      -- where the next round starts, where its first unit ends at the earliest, and its `bad`
      let mut next := (ends.back!, low, 0)
      for (s, e, ud, t) in jobs do
        let (cu, o, ok) := t.get
        -- a unit read from the empty carry is probed against the one set of controls taken before it
        let clash := s > 0 && cu.ctls.any c.taken.contains
        let (cu, o, ok) := if clash then readUnit (σ := σ) kind (base + s) c ud (e - s) else (cu, o, ok)
        -- (`c` never has `stop`: the stream ends where a unit sets it)
        if cu.stop then
          let rest ← if eof then pure 0 else drain 0
          out.write (unitBlock (base + s) (w.size - s + rest) o)
          out.write (trailer (if s == 0 || clash then cu else c.join cu))
          return
        if !ok then
          -- not a cut: this unit is read again, up to the last cut its fold passed, or, with none (or when it ended at
          -- such a cut, below a known failure), up to a candidate twice as far as the farthest failure; that farthest
          -- failure grows at least every second time, so the reading goes on
          let bad := if s == 0 then bad else 0
          next := (s, if cu.cut > 0 && e - s > bad then cu.cut else 2 * max bad (e - s), max bad (e - s))
          -- the later units of this round are not used; they are let finish before the next round starts, so no more
          -- than `par` units are ever read at once
          for (_, _, _, t') in jobs do
            discard <| IO.wait t'
          break
        out.write (unitBlock (base + s) (e - s) o)
        -- joined only once the unit is kept (a unit that is read again leaves `c` as it was)
        c := if s == 0 || clash then cu else c.join cu
      let (s, first, bad) := next
      go (if s == 0 then w else w.extract s w.size) (base + s) eof c first bad 0
  let b ← inp.read blk.toUSize
  go b 0 (b.size == 0) {} low 0 0

end BlindLedger.X12
