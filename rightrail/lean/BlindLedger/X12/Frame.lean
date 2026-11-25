import BlindLedger.X12.Base
import BlindLedger.X12.Cause
import Std.Data.HashSet

/-! The X12 envelope as a fold over segments: interchange, group and set framing, counts and control numbers, the
    lossless repairs, and the hand-over of each live set's segments to a set reader.  Written in the order of the
    checks of the Python envelope (`app/right_rail_x12.py`), which is the test-only reference. -/

namespace BlindLedger.X12

open Std

/-- One segment of the input: its body is bytes `s` up to `e` (whitespace trimmed).  `idEnd` and `q2` to `q10` are the
    places of its first ten element separators (`e` for each one that is not there): found in one pass when the segment
    is made, so that element `k` is read between two of them without a rescan. -/
structure Seg where
  s : Nat := 0
  e : Nat := 0
  idEnd : Nat := 0
  q2 : Nat := 0
  q3 : Nat := 0
  q4 : Nat := 0
  q5 : Nat := 0
  q6 : Nat := 0
  q7 : Nat := 0
  q8 : Nat := 0
  q9 : Nat := 0
  q10 : Nat := 0
  sep : UInt8 := 42

/-- The delimiters an interchange header names. -/
structure Delims where
  sep : UInt8
  sub : UInt8
  term : UInt8
  rep : Nat  -- 256 when there is no repetition separator
  control : Nat  -- the range word of ISA13
  stampOk : Bool

/-- What a set reader is told about its set. -/
structure SetCtx where
  off : Nat
  control : Nat
  fileDate : Nat
  fileTime : Nat
  group : Nat
  ichg : Nat

/-- A set reader: a state, a step for each segment of its set, and a finish. -/
class SetReader (σ : Type) where
  init : σ
  step : ByteArray → Delims → Seg → SetCtx → σ → Out → σ × Out
  finish : ByteArray → Delims → SetCtx → σ → Out → Out
  notCause : Cause

/-! ## Segments -/

@[inline] def isSpace (c : UInt8) : Bool := c == 32 || c == 9 || c == 13 || c == 10

@[inline] def segId (c0 c1 c2 : Nat) : Nat := c0 * 65536 + c1 * 256 + c2

/-- The packed segment id of `A-Z0-9` of two or three characters; 0 when the id is not that. -/
def packId (d : ByteArray) (s e : Nat) : Nat :=
  let ok (c : UInt8) := isDig c || (65 ≤ c && c ≤ 90)
  if e - s == 2 && ok (d.get! s) && ok (d.get! (s + 1)) then segId 0 (d.get! s).toNat (d.get! (s + 1)).toNat
  else if e - s == 3 && ok (d.get! s) && ok (d.get! (s + 1)) && ok (d.get! (s + 2)) then
    segId (d.get! s).toNat (d.get! (s + 1)).toNat (d.get! (s + 2)).toNat
  else 0

@[inline] def pk (s : String) : Nat :=
  let l := s.toUTF8
  if l.size == 2 then segId 0 (l.get! 0).toNat (l.get! 1).toNat else segId (l.get! 0).toNat (l.get! 1).toNat (l.get! 2).toNat

/-- The byte at `i`, or 0 beyond the end (as `d[i]!`), read without boxing. -/
@[inline] def gb (d : ByteArray) (i : USize) : UInt8 := if h : i.toNat < d.size then d.uget i h else 0

theorem us_succ {i n : USize} (h : i < n) : (i + 1).toNat = i.toNat + 1 := by
  have h1 : i.toNat < n.toNat := USize.lt_iff_toNat_lt.mp h
  have h2 : n.toNat < USize.size := n.toNat_lt_size
  rw [USize.toNat_add, USize.toNat_one, Nat.mod_eq_of_lt (by change _ < USize.size; omega)]

/-- The first index in `i`..`n` holding the byte `c`, else `n`, on machine words (no overflow checks or boxing in the
    loop).  The loops here are written as tail calls: a `while` loop in do-notation is some twenty times slower in
    compiled code.  Sizes are below 2^64, so this is `findB` of the plain Nat reading. -/
def findU (d : ByteArray) (c : UInt8) (i n : USize) : USize :=
  if h : i < n then (if gb d i == c then i else findU d c (i + 1) n) else n
termination_by n.toNat - i.toNat
decreasing_by
  have := us_succ h
  have := USize.lt_iff_toNat_lt.mp h
  omega

/-- The first index in `i`..`n` holding the byte `c`, else `n`. -/
def findB (d : ByteArray) (c : UInt8) (i n : Nat) : Nat := (findU d c i.toUSize n.toUSize).toNat

/-- The first index at or after `i`, below `n`, that is not white space. -/
def skipSp (d : ByteArray) (i n : Nat) : Nat :=
  if i < n then (if isSpace d[i]! then skipSp d (i + 1) n else i) else i
termination_by n - i

/-- The last index at or before `e`, above `s`, with white space only after it removed. -/
def backSp (d : ByteArray) (s e : Nat) : Nat :=
  if s < e then (if isSpace d[e - 1]! then backSp d s (e - 1) else e) else e
termination_by e - s

/-- The number of `sep` in `i`..`e`. -/
def cntGo (d : ByteArray) (sep : UInt8) (e i k : Nat) : Nat :=
  if i < e then cntGo d sep e (i + 1) (if d[i]! == sep then k + 1 else k) else k
termination_by e - i

def seenGo (d : ByteArray) (i : Nat) (tab : ByteArray) : ByteArray :=
  if i < d.size then seenGo d (i + 1) (tab.set! d[i]!.toNat 1) else tab
termination_by d.size - i

/-- Which byte values occur in the file: a pass done once, so that a segment needs the slower look (for a byte above
    127, or the repetition separator) only when the file has such bytes. -/
def byteSeen (d : ByteArray) : ByteArray := seenGo d 0 (ByteArray.mk (Array.replicate 256 0))

def anyHigh (tab : ByteArray) : Bool := (List.range 128).any fun i => tab[128 + i]! != 0

/-- The separator after the one at `q` (or `e`). -/
@[inline] def nxtSep (d : ByteArray) (sep : UInt8) (e q : Nat) : Nat := if q < e then findB d sep (q + 1) e else e

/-- The segment body `s`..`e`, split at `sep`: one pass, no substring, no table. -/
def mkSeg (d : ByteArray) (s e : Nat) (sep : UInt8) : Seg :=
  let q1 := findB d sep s e
  let q2 := nxtSep d sep e q1
  let q3 := nxtSep d sep e q2
  let q4 := nxtSep d sep e q3
  let q5 := nxtSep d sep e q4
  let q6 := nxtSep d sep e q5
  let q7 := nxtSep d sep e q6
  let q8 := nxtSep d sep e q7
  let q9 := nxtSep d sep e q8
  let q10 := nxtSep d sep e q9
  { s := s, e := e, idEnd := q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, sep := sep }

/-- `c` occurs in `i`..`e` (on machine words, as `findU`). -/
def hasU (d : ByteArray) (c : UInt8) (i e : USize) : Bool :=
  if h : i < e then (gb d i == c || hasU d c (i + 1) e) else false
termination_by e.toNat - i.toNat
decreasing_by
  have := us_succ h
  have := USize.lt_iff_toNat_lt.mp h
  omega

/-- `c` occurs in `i`..`e`. -/
def hasByte (d : ByteArray) (c : UInt8) (i e : Nat) : Bool := hasU d c i.toUSize e.toUSize

/-- A byte above 127 occurs in `i`..`e`. -/
def hasHigh (d : ByteArray) (i e : Nat) : Bool :=
  if i < e then (d[i]! ≥ 128 || hasHigh d (i + 1) e) else false
termination_by e - i

/-- The index of the `k`-th (1-based) `sep` at or after `i` below `e`, else `e`. -/
def nthSep (d : ByteArray) (sep : UInt8) (i e k : Nat) : Nat :=
  if i < e then
    if d[i]! == sep then (if k == 1 then i else nthSep d sep (i + 1) e (k - 1)) else nthSep d sep (i + 1) e k
  else e
termination_by e - i

/-- The place of the `k`-th (1-based) element separator, else `e`. -/
def segQ (d : ByteArray) (sg : Seg) (k : Nat) : Nat :=
  match k with
  | 1 => sg.idEnd | 2 => sg.q2 | 3 => sg.q3 | 4 => sg.q4 | 5 => sg.q5
  | 6 => sg.q6 | 7 => sg.q7 | 8 => sg.q8 | 9 => sg.q9 | 10 => sg.q10
  | _ => nthSep d sg.sep sg.q10 sg.e (k - 9)

/-- Element `k` (1-based) as a range up to its first sub-element separator; `(0, 0)` when absent. -/
def el (d : ByteArray) (sub : UInt8) (sg : Seg) (k : Nat) : Nat × Nat :=
  let i := segQ d sg k
  if k == 0 || i ≥ sg.e then (0, 0) else
    let s := i + 1
    (s, findB d sub s (segQ d sg (k + 1)))

def elpGo (d : ByteArray) (sub : UInt8) (p e : Nat) (i q st : Nat) : Nat × Nat :=
  if i < e then
    if d[i]! == sub then
      if q == p then (st, i) else elpGo d sub p e (i + 1) (q + 1) (i + 1)
    else elpGo d sub p e (i + 1) q st
  else if q == p then (st, e) else (0, 0)
termination_by e - i

/-- Sub-element `p` (1-based) of element `k`. -/
def elp (d : ByteArray) (sub : UInt8) (sg : Seg) (k p : Nat) : Nat × Nat :=
  let i := segQ d sg k
  if k == 0 || i ≥ sg.e then (0, 0) else
    let s := i + 1
    elpGo d sub p (segQ d sg (k + 1)) s 1 s

def nsubGo (d : ByteArray) (sub : UInt8) (e i q : Nat) : Nat :=
  if i < e then nsubGo d sub e (i + 1) (if d[i]! == sub then q + 1 else q) else q
termination_by e - i

/-- How many sub-elements element `k` has (0 when it is absent). -/
def nsub (d : ByteArray) (sub : UInt8) (sg : Seg) (k : Nat) : Nat :=
  let i := segQ d sg k
  if k == 0 || i ≥ sg.e then 0 else
    let s := i + 1
    nsubGo d sub (segQ d sg (k + 1)) s 1

/-! ## The interchange header -/

/-- The framing of an interchange header at `p`: needs 106 bytes. -/
def isaAt (d : ByteArray) (p : Nat) : Option Delims := Id.run do
  if p + 106 > d.size then return none
  if !(d.get! p == 73 && d.get! (p + 1) == 83 && d.get! (p + 2) == 65) then return none
  let sep := d.get! (p + 3)
  let sub := d.get! (p + 104)
  let term := d.get! (p + 105)
  let bad (c : UInt8) : Bool := c ≥ 128 || latin1Alnum c || c == 32
  if sep == sub || sep == term || sub == term || bad sep || bad sub || bad term then return none
  -- the 17 fields, by their lengths
  let lens : Array Nat := #[3, 2, 10, 2, 10, 2, 15, 2, 15, 6, 4, 1, 5, 9, 1, 1, 1]
  let mut starts : Array Nat := #[]
  let mut i := p
  let mut idx := 0
  for l in lens do
    starts := starts.push i
    let mut j := 0
    while j < l do
      if d.get! (i + j) == sep then return none
      j := j + 1
    i := i + l
    if idx < 16 then
      if d.get! i != sep then return none
      i := i + 1
    idx := idx + 1
  if i != p + 105 then return none
  let f13 := starts[13]!
  let mut k := 0
  while k < 9 do
    if !isDig (d.get! (f13 + k)) then return none
    k := k + 1
  let mut rep : Nat := 256
  let f12 := starts[12]!
  if eqB d f12 (f12 + 5) "00501".toUTF8 then
    let r := d.get! (starts[11]!)
    if !(latin1Alnum r || r == 32 || r == sep || r == sub || r == term) then rep := r.toNat
  let stampOk := Id.run do
    let ds := starts[9]!
    let cs := starts[10]!
    let mut ok := true
    for k in [0:6] do
      if !isDig (d.get! (ds + k)) then ok := false
    for k in [0:4] do
      if !isDig (d.get! (cs + k)) then ok := false
    if !ok then return false
    let two (o : Nat) : Nat := (d.get! o - 48).toNat * 10 + (d.get! (o + 1) - 48).toNat
    if two cs ≥ 24 || two (cs + 2) ≥ 60 then return false
    let yy := two ds
    let mm := two (ds + 2)
    let dd := two (ds + 4)
    let okOf (y : Nat) : Bool :=
      let leap := y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
      let dim := if mm == 2 then (if leap then 29 else 28) else if mm == 4 || mm == 6 || mm == 9 || mm == 11 then 30 else 31
      1 ≤ mm && mm ≤ 12 && 1 ≤ dd && dd ≤ dim
    return okOf (2000 + yy) || okOf (1900 + yy)
  return some { sep, sub, term, rep, control := rng f13 (f13 + 9), stampOk }

end BlindLedger.X12
