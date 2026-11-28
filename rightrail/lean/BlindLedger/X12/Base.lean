/-! The X12 reader's byte helpers and its cause list.

Every offset here is a byte offset into the input.  A text field is never copied: it is a range word, the offset times
2^24 plus the length (a segment is at most 2 MiB, so a length is below 2^24).  Range words name bytes of the input;
a range word with bit 62 set names bytes of the side text the reader appends (decimal numbers in set-aside details). -/

namespace BlindLedger.X12

/-! ## Bytes -/

@[inline] def isDig (c : UInt8) : Bool := 48 ≤ c && c ≤ 57

/-- Python's `str.isalnum` on the 256 Latin-1 characters: the ASCII letters and digits, and ª ² ³ µ ¹ º ¼ ½ ¾ and À-ÿ
    without × and ÷. -/
def latin1Alnum (c : UInt8) : Bool :=
  isDig c || (65 ≤ c && c ≤ 90) || (97 ≤ c && c ≤ 122) || c == 0xAA || c == 0xB2 || c == 0xB3 || c == 0xB5 ||
  c == 0xB9 || c == 0xBA || (0xBC ≤ c && c ≤ 0xBE) || (0xC0 ≤ c && c ≠ 0xD7 && c ≠ 0xF7)

/-- A range word: bytes `s` up to `e`. -/
@[inline] def rng (s e : Nat) : Nat := s * 16777216 + (e - s)
@[inline] def rngStart (r : Nat) : Nat := (r % 4611686018427387904) / 16777216
@[inline] def rngLen (r : Nat) : Nat := r % 16777216
/-- The side-text flag of a range word. -/
def sideFlag : Nat := 4611686018427387904

/-- The bytes `i`.. of `d` equal the bytes `j`.. of `l`, up to `l`'s end. (Loops are tail calls: a `while` loop in
    do-notation is some twenty times slower in compiled code.) -/
def eqFrom (d : ByteArray) (s : Nat) (l : ByteArray) (j : Nat) : Bool :=
  if j < l.size then (d[s + j]! == l[j]! && eqFrom d s l (j + 1)) else true
termination_by l.size - j

/-- The bytes `s` to `e` of `d` are the bytes of `l`. -/
def eqB (d : ByteArray) (s e : Nat) (l : ByteArray) : Bool := e - s == l.size && eqFrom d s l 0

/-- The bytes `s1`.. and `s2`.. of `d`, `n` of them, are equal. -/
def sameB (d : ByteArray) (s1 s2 n : Nat) : Bool :=
  if h : n = 0 then true else d[s1 + n - 1]! == d[s2 + n - 1]! && sameB d s1 s2 (n - 1)
termination_by n
decreasing_by omega

/-- The first index at or after `i`, below `e`, that is not an ASCII digit. -/
def skipDig (d : ByteArray) (i e : Nat) : Nat :=
  if i < e then (if isDig d[i]! then skipDig d (i + 1) e else i) else i
termination_by e - i

/-- The first index at or after `i`, below `e`, that is not a `0`. -/
def skipZero (d : ByteArray) (i e : Nat) : Nat :=
  if i < e then (if d[i]! == 48 then skipZero d (i + 1) e else i) else i
termination_by e - i

/-- The digits `i`..`e`, as a number added after `acc` (the caller has checked they are digits). -/
def digVal (d : ByteArray) (i e acc : Nat) : Nat :=
  if i < e then digVal d (i + 1) e (acc * 10 + (d[i]! - 48).toNat) else acc
termination_by e - i

/-- The first `j` digits of the fraction `fs`..`fe`, short ones padded with zeros, as a number. -/
def fracVal (d : ByteArray) (fs fe j places acc : Nat) : Nat :=
  if j < places then fracVal d fs fe (j + 1) places (acc * 10 + (if fs + j < fe then (d[fs + j]! - 48).toNat else 0)) else acc
termination_by places - j

/-- `d` from `s` up to `e` is valid UTF-8 by Python's strict rules: no overlong form, no surrogate, nothing above U+10FFFF. -/
def validUtf8 (d : ByteArray) (s e : Nat) : Bool := Id.run do
  let mut i := s
  while i < e do
    let c := d.get! i
    if c < 0x80 then
      i := i + 1
    else
      let (n, lo, hi) : Nat × UInt8 × UInt8 :=
        if 0xC2 ≤ c && c ≤ 0xDF then (1, 0x80, 0xBF)
        else if c == 0xE0 then (2, 0xA0, 0xBF)
        else if 0xE1 ≤ c && c ≤ 0xEC then (2, 0x80, 0xBF)
        else if c == 0xED then (2, 0x80, 0x9F)
        else if c == 0xEE || c == 0xEF then (2, 0x80, 0xBF)
        else if c == 0xF0 then (3, 0x90, 0xBF)
        else if 0xF1 ≤ c && c ≤ 0xF3 then (3, 0x80, 0xBF)
        else if c == 0xF4 then (3, 0x80, 0x8F)
        else (0, 0, 0)
      if n == 0 || i + n ≥ e then return false
      let c1 := d.get! (i + 1)
      if c1 < lo || c1 > hi then return false
      let mut j := 2
      while j ≤ n do
        let cj := d.get! (i + j)
        if cj < 0x80 || cj > 0xBF then return false
        j := j + 1
      i := i + n + 1
  return true

/-- `d` from `s` up to `e` is valid UTF-8 of exactly three code points, none of them U+FFFD: its text has length 3. -/
def threeChars (d : ByteArray) (s e : Nat) : Bool := Id.run do
  if !validUtf8 d s e then return false
  let mut n := 0
  let mut i := s
  while i < e do
    let c := d.get! i
    if c &&& 0xC0 != 0x80 then n := n + 1
    if c == 0xEF && i + 2 < e && d.get! (i + 1) == 0xBF && d.get! (i + 2) == 0xBD then return false
    i := i + 1
  return n == 3

/-! ## Numbers and dates -/

/-- A real calendar date of year 1 or later in the eight ASCII digits `yyyymmdd` of `d`, as that number, else 0. -/
def date8 (d : ByteArray) (s e : Nat) : Nat := Id.run do
  if e - s != 8 then return 0
  if skipDig d s e != e then return 0
  let v := digVal d s e 0
  let y := v / 10000
  let m := v / 100 % 100
  let dd := v % 100
  if y < 1 || m < 1 || m > 12 || dd < 1 then return 0
  let leap := y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
  let dim := if m == 2 then (if leap then 29 else 28) else if m == 4 || m == 6 || m == 9 || m == 11 then 30 else 31
  if dd > dim then return 0
  return v

/-- A clock of 4, 6, 7 or 8 ASCII digits with hour below 24 and minute and second below 60, as `hhmmss`; `none` otherwise. -/
def clock (d : ByteArray) (s e : Nat) : Option Nat := Id.run do
  let n := e - s
  if !(n == 4 || n == 6 || n == 7 || n == 8) then return none
  let mut i := s
  while i < e do
    if !isDig (d.get! i) then return none
    i := i + 1
  let two (k : Nat) : Nat := (d.get! (s + k) - 48).toNat * 10 + (d.get! (s + k + 1) - 48).toNat
  let h := two 0
  let m := two 2
  let sec := if n > 4 then two 4 else 0
  if h ≥ 24 || m ≥ 60 || sec ≥ 60 then return none
  return some (h * 10000 + m * 100 + sec)

/-- A decimal as an exact count of 10^-`places`: an optional minus, then digits or digits with a point, the digits past
    `places` all zero and at most 15 integer digits; `none` otherwise. -/
def scaled (d : ByteArray) (s e : Nat) (places : Nat) : Option Int := Id.run do
  let neg := s < e && d[s]! == 45
  let ws := if neg then s + 1 else s
  let we := skipDig d ws e
  let mut fs := we
  let mut fe := we
  if we < e then
    if d[we]! != 46 then return none
    fs := we + 1
    fe := skipDig d fs e
    if fe != e || fe == fs then return none
  else if we == ws then return none
  let w := skipZero d ws we
  if we - w > 15 then return none
  if fs + places < fe && skipZero d (fs + places) fe != fe then return none
  let v := digVal d w we 0
  let f := fracVal d fs fe 0 places 0
  let mag : Int := (v * 10 ^ places + f : Nat)
  return some (if neg then -mag else mag)

/-! ## Output -/

/-- A little-endian 64-bit word appended. -/
def pushW (b : ByteArray) (v : Nat) : ByteArray :=
  (List.range 8).foldl (fun b i => b.push (v / 256 ^ i % 256).toUInt8) b

/-- A little-endian 64-bit word written at `p` of `b` (which must have room). -/
@[inline] def setW (b : ByteArray) (p : Nat) (v : Nat) : ByteArray :=
  let u := v.toUInt64
  b.set! p u.toUInt8 |>.set! (p + 1) (u >>> 8).toUInt8 |>.set! (p + 2) (u >>> 16).toUInt8 |>.set! (p + 3) (u >>> 24).toUInt8
    |>.set! (p + 4) (u >>> 32).toUInt8 |>.set! (p + 5) (u >>> 40).toUInt8 |>.set! (p + 6) (u >>> 48).toUInt8 |>.set! (p + 7) (u >>> 56).toUInt8

/-- A signed amount as a word: two's complement, so an absent amount is never a zero (the caller writes a presence word). -/
@[inline] def wordOfInt (v : Int) : Nat := if v < 0 then (18446744073709551616 + v).toNat else v.toNat

/-- The reader's output so far: the first `len` bytes of `ev` are the event words (`ev` is longer, to grow by doubling,
    and a byte store is much cheaper than a push); the side text is what range words flagged `sideFlag` point into. -/
structure Out where
  ev : ByteArray := ByteArray.empty
  len : Nat := 0
  side : ByteArray := ByteArray.empty

/-- `n` or more zero bytes (64 doublings at most), made by doubling: a copy of a block is far cheaper than an array of
    boxed zeros. -/
def zerosGo (n : Nat) : Nat → ByteArray → ByteArray
  | 0, b => b
  | f + 1, b => if b.size < n then zerosGo n f (b ++ b) else b

def zeros (n : Nat) : ByteArray := zerosGo n 64 (ByteArray.mk (Array.replicate 4096 0))

def Out.grow : Out → Out
  | ⟨ev, len, side⟩ => ⟨if ev.size < 4096 then ev ++ zeros 4096 else ev ++ ev, len, side⟩

@[inline] def Out.w (o : Out) (v : Nat) : Out :=
  match (if o.len + 8 > o.ev.size then o.grow else o) with
  | ⟨ev, len, side⟩ => ⟨setW ev len v, len + 8, side⟩
@[inline] def Out.wi (o : Out) (v : Int) : Out := o.w (wordOfInt v)

/-- Room for `bytes` more bytes: the buffer is doubled until they fit. -/
def Out.reserveFuel (o : Out) (bytes : Nat) : Nat → Out
  | 0 => o
  | f + 1 => if o.len + bytes > o.ev.size then Out.reserveFuel o.grow bytes f else o

@[inline] def Out.reserve (o : Out) (bytes : Nat) : Out := if o.len + bytes > o.ev.size then o.reserveFuel bytes 64 else o

/-- Five words written with one room check and one rebuild of the record. -/
@[inline] def Out.w5 (o : Out) (a b c d e : Nat) : Out :=
  match o.reserve 40 with
  | ⟨ev, p, side⟩ => ⟨setW (setW (setW (setW (setW ev p a) (p + 8) b) (p + 16) c) (p + 24) d) (p + 32) e, p + 40, side⟩

/-- The words of `a` from index `i` on, written at byte `p`; the room is already reserved. -/
def putArr (ev : ByteArray) (p : Nat) (a : Array Nat) (i : Nat) : ByteArray :=
  if i < a.size then putArr (setW ev p a[i]!) (p + 8) a (i + 1) else ev
termination_by a.size - i

/-- The words of `r` after those of `o`. -/
def Out.append (o r : Out) : Out :=
  match o with
  | ⟨ev, len, side⟩ => ⟨r.ev.copySlice 0 ev len r.len false, len + r.len, side⟩

/-- The event words, then the side text. -/
def Out.bytes (o : Out) : ByteArray := o.ev.extract 0 o.len ++ o.side

/-- A decimal number as side text: its range word. -/
def Out.num (o : Out) (v : Int) : Out × Nat :=
  let t := (toString v).toUTF8
  let ofs := o.side.size
  ({ o with side := o.side ++ t }, sideFlag + ofs * 16777216 + t.size)

end BlindLedger.X12
