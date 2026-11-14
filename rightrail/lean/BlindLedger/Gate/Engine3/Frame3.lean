import BlindLedger.Gate.Engine3.Chunk
import BlindLedger.Gate.Flat.Io
import BlindLedger.Gate.Engine3.Sha3Range

/-! The frame, trailer and state root of conformance/ENGINE_V3.md section 6, the retry rule of section 9 and the holds
    of section 8 as running code.

    The request and answer are opaque bytes here; the trailer takes their digests (`rq`, `an`), the batch digest `bd`
    and the authority record `au` as values from the wire codec.  A well-formed trailer decodes to one that encodes to
    the same bytes (`Trailer.decode_encode`).  `retryF` is `retry3` over digests and bytes; `holdPayF` is
    `holdPay` in one pass; the stage functions are `widthStage`, `blockStage`, `budgetStage` and the `rowsFull` test of
    `run3` (equalities stated, not yet proved). -/

namespace BlindLedger.Gate.Engine3

open BlindLedger.Gate.Rules BlindLedger.Gate.Flat BlindLedger.Semantic
open Std (HashMap)

def domB (name : String) : ByteArray := Bin.bytesOf (domain name)

/-- SHA3-512 of the domain `name`, then the pieces; the last piece is read in place, not copied (`hD_eq`). -/
def hD (name : String) (parts : List ByteArray) : ByteArray :=
  let x := parts.getLastD ByteArray.empty
  sha3_512Into ByteArray.empty (parts.dropLast.foldl (· ++ ·) (domB name)) x 0 x.size

theorem hD_eq (name : String) (parts : List ByteArray) :
    hD name parts = sha3_512 (parts.foldl (· ++ ·) (domB name)) := by
  unfold hD; dsimp only
  rw [sha3_512Into_spec _ _ _ _ _ (by omega), ByteArray.empty_append, Nat.zero_add, ByteArray.extract_zero_size]
  rcases parts.eq_nil_or_concat with h | ⟨l, b, h⟩
  · subst h; exact congrArg sha3_512 ByteArray.append_empty
  · subst h; rw [List.concat_eq_append, List.dropLast_concat, List.getLastD_concat, List.foldl_append]; rfl

/-! ## Trailer -/

def put32 (b : ByteArray) (v : Nat) : ByteArray := putN b v 4
def put64n (b : ByteArray) (v : Nat) : ByteArray := putN b v 8

/-- `bSeal` while no window is sealing. -/
def noSeal : Nat := 2 ^ 64 - 1

structure Trailer where
  shard : Nat
  batches : Nat
  hr : Head
  hu : Head
  nx : Nat
  bOpen : Nat
  bSeal : Nat
  sealEv : Option Nat
  installEv : Option (Nat × ByteArray)
  reclaimEv : Option Nat
  au : ByteArray
  rq : ByteArray
  an : ByteArray
  replaced : ByteArray
  prev : ByteArray
  bd : ByteArray
  root : ByteArray
  head : ByteArray

def putHead (b : ByteArray) (h : Head) : ByteArray := put64n (put64n (put32 b h.asOf) h.count) h.n

/-- `seal u8 ‖ chunk u32 ‖ install u8 ‖ chunk u32 ‖ leaf 64 ‖ reclaim u8 ‖ chunk u32`; zeros when absent. -/
def putEvents (b : ByteArray) (t : Trailer) : ByteArray :=
  let b := match t.sealEv with | some c => put32 (b.push 1) c | none => put32 (b.push 0) 0
  let b := match t.installEv with | some x => put32 (b.push 1) x.1 ++ x.2 | none => put32 (b.push 0) 0 ++ zeroBlock 64
  match t.reclaimEv with | some c => put32 (b.push 1) c | none => put32 (b.push 0) 0

def Trailer.encode (t : Trailer) : ByteArray :=
  let b := put32 (domB "STORE/FRAME4") t.shard
  let b := putHead (putHead (put64n b t.batches) t.hr) t.hu
  let b := put64n (put64n (put64n b t.nx) t.bOpen) t.bSeal
  putEvents b t ++ t.au ++ t.rq ++ t.an ++ t.replaced ++ t.prev ++ t.bd ++ t.root ++ t.head

def trailerLen : Nat := (domB "STORE/FRAME4").size + 4 + 8 + 20 + 20 + 24 + 79 + 208 + 7 * 64

def getHead (b : ByteArray) (o : Nat) : Head := ⟨getN b o 4, getN b (o + 4) 8, getN b (o + 12) 8⟩

/-- An optional event: flag 0 or 1, and zero bytes when absent. -/
def getFlag (b : ByteArray) (o : Nat) : Option (Option Nat) :=
  match b[o]! with
  | 0 => if getN b (o + 1) 4 == 0 then some none else none
  | 1 => some (some (getN b (o + 1) 4))
  | _ => none

/-- Strict: the exact length, the domain, and canonical absent events. -/
def Trailer.decode (b : ByteArray) : Option Trailer := do
  guard (b.size == trailerLen)
  let d := (domB "STORE/FRAME4").size
  guard (b.extract 0 d == domB "STORE/FRAME4")
  let o := d + 4 + 8 + 20 + 20 + 24
  let sl ← getFlag b o
  let inst ← getFlag b (o + 5)
  let leaf := b.extract (o + 10) (o + 74)
  guard (inst.isSome || (leaf.data.all (· == 0)))
  let rec' ← getFlag b (o + 74)
  let p := o + 79
  pure ⟨getN b d 4, getN b (d + 4) 8, getHead b (d + 12), getHead b (d + 32), getN b (d + 52) 8, getN b (d + 60) 8,
    getN b (d + 68) 8, sl, inst.map (·, leaf), rec', b.extract p (p + 208), b.extract (p + 208) (p + 272),
    b.extract (p + 272) (p + 336), b.extract (p + 336) (p + 400), b.extract (p + 400) (p + 464),
    b.extract (p + 464) (p + 528), b.extract (p + 528) (p + 592), b.extract (p + 592) (p + 656)⟩

/-- The state root: the chunk tree's root, the two heads, the next install number, the key digest `ks`, the window
    starts, the sealing chunk, and the authority record and the digests the trailer carries. -/
def rootFour (t : Trailer) (tree ks : ByteArray) (sealing : Option Nat) : ByteArray :=
  let e := ByteArray.empty
  hD "STORE/STATE4" [put32 e t.shard, put64n e t.batches, tree, putHead (putHead e t.hr) t.hu, put64n e t.nx, ks,
    put64n e t.bOpen, put64n e t.bSeal, put32 e (sealing.getD 0xFFFFFFFF), t.au, t.rq, t.an, t.replaced]

/-- The chain head signed for a batch. -/
def chainHead (prev bd root4 : ByteArray) : ByteArray := hD "CHAIN" [ByteArray.mk #[2], prev, bd, root4]

def storeKs (sec : ByteArray) : ByteArray := hD "STORE/KEY" [sec]

def replacedDigest (pending : ByteArray) : ByteArray := hD "STORE/REPLACED" [pending]

/-! ## Frame -/

def frameMagic : ByteArray := ByteArray.mk #[0x52, 0x52, 0x46, 0x34]

/-- The first 16 bytes of a frame whose three parts have the sizes `rq`, `an` and `tr`. -/
def frameHead (rq an tr : Nat) : ByteArray :=
  putN (putN (putN (ByteArray.emptyWithCapacity 16 ++ frameMagic) rq 4) an 4) tr 4

def encodeFrame (rq an tr : ByteArray) : ByteArray :=
  (ByteArray.emptyWithCapacity (16 + rq.size + an.size + tr.size) ++ frameHead rq.size an.size tr.size) ++ rq ++ an ++ tr

/-- A frame's place in the log. -/
structure FrameRef where
  off : Nat
  rq : Nat
  an : Nat
  tr : Nat
  deriving Inhabited

def FrameRef.len (f : FrameRef) : Nat := 16 + f.rq + f.an + f.tr

def parseHdr (h : ByteArray) (off : Nat) : Option FrameRef :=
  if h.size == 16 && h.extract 0 4 == frameMagic then some ⟨off, getN h 4 4, getN h 8 4, getN h 12 4⟩ else none

/-! ## Retry -/

structure FrF where
  rq : ByteArray
  bytes : ByteArray

def FrF.eq (a b : FrF) : Bool := a.rq == b.rq && a.bytes == b.bytes

/-! ## Holds -/

/-- Row numbers would reach 2^40. -/
def rowsFullF (hr hu : Head) (n : Nat) : Bool := (2 ^ 40 ≤ hr.n + n) || (2 ^ 40 ≤ hu.n + n)

/-! ## Round trip -/

/-- An optional event as written: the flag, then the chunk number (zeros when absent). -/
def evL : Option Nat → List UInt8
  | some c => 1 :: lN c 4
  | none => 0 :: lN 0 4

/-- The install leaf as written: 64 zero bytes when there is no install. -/
def installLeaf : Option (Nat × ByteArray) → ByteArray
  | some x => x.2
  | none => zeroBlock 64

theorem lN_mod : ∀ (w v : Nat), lN (v % 256 ^ w) w = lN v w
  | 0, _ => rfl
  | w + 1, v => by
    have h1 : UInt8.ofNat (v % 256 ^ (w + 1)) = UInt8.ofNat v := by
      apply UInt8.toNat_inj.mp
      rw [UInt8.toNat_ofNat', UInt8.toNat_ofNat', show (2 : Nat) ^ 8 = 256 from rfl, Nat.pow_succ, Nat.mod_mul_left_mod]
    have h2 : (v % 256 ^ (w + 1)) >>> 8 = (v >>> 8) % 256 ^ w := by
      rw [Nat.shiftRight_eq_div_pow, Nat.shiftRight_eq_div_pow, show (2 : Nat) ^ 8 = 256 from rfl, Nat.pow_succ']
      exact Nat.mod_mul_right_div_self v 256 (256 ^ w)
    simp only [lN, h1, h2, lN_mod w]

theorem evL_length (e : Option Nat) : (evL e).length = 5 := by cases e <;> simp [evL, lN_length]

theorem bytes_ext {a b : ByteArray} (h : a.toList = b.toList) : a = b := by
  rw [Bin.toList_eq', Bin.toList_eq'] at h
  cases a; cases b
  exact congrArg ByteArray.mk (Array.toList_inj.mp h)

theorem getN_pre {b : ByteArray} {pre : List UInt8} {v w o : Nat} (h : pre ++ lN v w <+: b.toList)
    (ho : pre.length = o) : getN b o w = v % 256 ^ w := by
  obtain ⟨s, hs⟩ := h
  exact getN_tl w b pre s v o hs.symm ho

theorem getFlag_pre {b : ByteArray} {pre : List UInt8} {e : Option Nat} {o : Nat} (h : pre ++ evL e <+: b.toList)
    (ho : pre.length = o) : getFlag b o = some (e.map (· % 256 ^ 4)) := by
  obtain ⟨s, hs⟩ := h
  have hb : ∀ c suf, b.toList = pre ++ c :: suf → b[o]! = c := by
    intro c suf hl
    have hlt : o < b.toList.length := by rw [hl]; simp; omega
    have hq : b.toList[o]? = some c := by rw [hl, List.getElem?_append_right (by omega)]; simp [← ho]
    rw [Bin.getBang' b o (by rw [Bin.size_eq_length']; exact hlt)]
    rw [List.getElem?_eq_getElem hlt] at hq
    exact Option.some.inj hq
  cases e with
  | some c =>
    have h1 := hb 1 (lN c 4 ++ s) (by rw [← hs]; simp [evL])
    have h2 := getN_tl 4 b (pre ++ [1]) s c (o + 1) (by rw [← hs]; simp [evL]) (by simp [ho])
    simp [getFlag, h1, h2]
  | none =>
    have h1 := hb 0 (lN 0 4 ++ s) (by rw [← hs]; simp [evL])
    have h2 := getN_tl 4 b (pre ++ [0]) s 0 (o + 1) (by rw [← hs]; simp [evL]) (by simp [ho])
    simp [getFlag, h1, h2]

theorem extract_pre {b x : ByteArray} {pre : List UInt8} {o e : Nat} (h : pre ++ x.toList <+: b.toList)
    (ho : pre.length = o) (he : e = o + x.size) : b.extract o e = x := by
  obtain ⟨s, hs⟩ := h
  apply bytes_ext
  rw [Bin.toList_extract', ← hs, he, ← ho, Bin.size_eq_length']
  simp

theorem putEvents_tl (b : ByteArray) (t : Trailer) : (putEvents b t).toList =
    b.toList ++ evL t.sealEv ++ evL (t.installEv.map Prod.fst) ++ (installLeaf t.installEv).toList ++ evL t.reclaimEv := by
  rcases t with ⟨_, _, _, _, _, _, _, _ | c, _ | x, _ | r, _, _, _, _, _, _, _, _⟩ <;>
    simp [putEvents, evL, installLeaf, put32, putN_tl, push_tl', Bin.toList_append']

theorem encode_tl (t : Trailer) : t.encode.toList = (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++
    lN t.hr.asOf 4 ++ lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++
    lN t.nx 8 ++ lN t.bOpen 8 ++ lN t.bSeal 8 ++ evL t.sealEv ++ evL (t.installEv.map Prod.fst) ++
    (installLeaf t.installEv).toList ++ evL t.reclaimEv ++ t.au.toList ++ t.rq.toList ++ t.an.toList ++ t.replaced.toList ++
    t.prev.toList ++ t.bd.toList ++ t.root.toList ++ t.head.toList := by
  simp only [Trailer.encode, putHead, put32, put64n, Bin.toList_append', putEvents_tl, putN_tl, List.append_assoc]

set_option hygiene false in
/-- Closes `pre ++ x <+: t.encode.toList` when `pre ++ x` is a run of leading fields of `encode_tl`. -/
local macro "pfx" : tactic =>
  `(tactic| (rw [hE]; repeat (first | with_reducible exact List.prefix_refl _ |
    refine List.IsPrefix.trans ?_ (List.prefix_append _ _))))

set_option hygiene false in
/-- Closes a length or offset equation over the fields of `encode_tl`. -/
local macro "lenx" : tactic =>
  `(tactic| (simp only [List.length_append, List.length_nil, lN_length, evL_length, ← Bin.size_eq_length', hau, hrq, han,
    hrp, hpv, hbd, hrt, hhd, hlf] <;> omega))

/-- A trailer whose digests and record have their wire sizes decodes, and the decoded trailer encodes to the same bytes
    (numbers are read back modulo their field widths).  The install leaf must be 64 bytes, as the writer emits it. -/
theorem Trailer.decode_encode (t : Trailer) (hleaf : ∀ x, t.installEv = some x → x.2.size = 64)
    (h : t.au.size = 208 ∧ t.rq.size = 64 ∧ t.an.size = 64 ∧ t.replaced.size = 64 ∧
    t.prev.size = 64 ∧ t.bd.size = 64 ∧ t.root.size = 64 ∧ t.head.size = 64) :
    ∃ t', Trailer.decode t.encode = some t' ∧ t'.encode = t.encode := by
  obtain ⟨hau, hrq, han, hrp, hpv, hbd, hrt, hhd⟩ := h
  have hlf : (installLeaf t.installEv).size = 64 := by
    cases hi : t.installEv with
    | none => rfl
    | some x => exact hleaf x hi
  have hE := encode_tl t
  have hsz : t.encode.size = trailerLen := by
    rw [Bin.size_eq_length', hE]
    simp only [List.length_append, lN_length, evL_length, ← Bin.size_eq_length', hau, hrq, han, hrp, hpv, hbd, hrt, hhd,
      hlf]
    unfold trailerLen
    omega
  have hdom : t.encode.extract 0 (domB "STORE/FRAME4").size = domB "STORE/FRAME4" :=
    extract_pre (pre := []) (by simp only [List.nil_append]; pfx) rfl (by omega)
  have f0 : getN t.encode (domB "STORE/FRAME4").size 4 = t.shard % 256 ^ 4 :=
    getN_pre (pre := (domB "STORE/FRAME4").toList) (by pfx) (by lenx)
  have f1 : getN t.encode ((domB "STORE/FRAME4").size + 4) 8 = t.batches % 256 ^ 8 :=
    getN_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4) (by pfx) (by lenx)
  have f2 : getN t.encode ((domB "STORE/FRAME4").size + 12) 4 = t.hr.asOf % 256 ^ 4 :=
    getN_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8) (by pfx) (by lenx)
  have f3 : getN t.encode ((domB "STORE/FRAME4").size + 16) 8 = t.hr.count % 256 ^ 8 :=
    getN_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4) (by pfx) (by lenx)
  have f4 : getN t.encode ((domB "STORE/FRAME4").size + 24) 8 = t.hr.n % 256 ^ 8 :=
    getN_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8) (by pfx) (by lenx)
  have f5 : getN t.encode ((domB "STORE/FRAME4").size + 32) 4 = t.hu.asOf % 256 ^ 4 :=
    getN_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8) (by pfx) (by lenx)
  have f6 : getN t.encode ((domB "STORE/FRAME4").size + 36) 8 = t.hu.count % 256 ^ 8 :=
    getN_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4) (by pfx) (by lenx)
  have f7 : getN t.encode ((domB "STORE/FRAME4").size + 44) 8 = t.hu.n % 256 ^ 8 :=
    getN_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8) (by pfx) (by lenx)
  have f8 : getN t.encode ((domB "STORE/FRAME4").size + 52) 8 = t.nx % 256 ^ 8 :=
    getN_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8) (by pfx) (by lenx)
  have f9 : getN t.encode ((domB "STORE/FRAME4").size + 60) 8 = t.bOpen % 256 ^ 8 :=
    getN_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8)
      (by pfx) (by lenx)
  have f10 : getN t.encode ((domB "STORE/FRAME4").size + 68) 8 = t.bSeal % 256 ^ 8 :=
    getN_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8 ++
      lN t.bOpen 8) (by pfx) (by lenx)
  have g0 : getFlag t.encode ((domB "STORE/FRAME4").size + 76) = some (t.sealEv.map (· % 256 ^ 4)) :=
    getFlag_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8 ++
      lN t.bOpen 8 ++ lN t.bSeal 8) (by pfx) (by lenx)
  have g1 : getFlag t.encode ((domB "STORE/FRAME4").size + 81) = some ((t.installEv.map Prod.fst).map (· % 256 ^ 4)) :=
    getFlag_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8 ++
      lN t.bOpen 8 ++ lN t.bSeal 8 ++ evL t.sealEv) (by pfx) (by lenx)
  have g2 : t.encode.extract ((domB "STORE/FRAME4").size + 86) ((domB "STORE/FRAME4").size + 150) = installLeaf t.installEv :=
    extract_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8 ++
      lN t.bOpen 8 ++ lN t.bSeal 8 ++ evL t.sealEv ++ evL (t.installEv.map Prod.fst)) (by pfx) (by lenx) (by lenx)
  have g3 : getFlag t.encode ((domB "STORE/FRAME4").size + 150) = some (t.reclaimEv.map (· % 256 ^ 4)) :=
    getFlag_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8 ++
      lN t.bOpen 8 ++ lN t.bSeal 8 ++ evL t.sealEv ++ evL (t.installEv.map Prod.fst) ++ (installLeaf t.installEv).toList)
      (by pfx) (by lenx)
  have x0 : t.encode.extract ((domB "STORE/FRAME4").size + 155) ((domB "STORE/FRAME4").size + 363) = t.au :=
    extract_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8 ++
      lN t.bOpen 8 ++ lN t.bSeal 8 ++ evL t.sealEv ++ evL (t.installEv.map Prod.fst) ++ (installLeaf t.installEv).toList ++
      evL t.reclaimEv) (by pfx) (by lenx) (by lenx)
  have x1 : t.encode.extract ((domB "STORE/FRAME4").size + 363) ((domB "STORE/FRAME4").size + 427) = t.rq :=
    extract_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8 ++
      lN t.bOpen 8 ++ lN t.bSeal 8 ++ evL t.sealEv ++ evL (t.installEv.map Prod.fst) ++ (installLeaf t.installEv).toList ++
      evL t.reclaimEv ++ t.au.toList) (by pfx) (by lenx) (by lenx)
  have x2 : t.encode.extract ((domB "STORE/FRAME4").size + 427) ((domB "STORE/FRAME4").size + 491) = t.an :=
    extract_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8 ++
      lN t.bOpen 8 ++ lN t.bSeal 8 ++ evL t.sealEv ++ evL (t.installEv.map Prod.fst) ++ (installLeaf t.installEv).toList ++
      evL t.reclaimEv ++ t.au.toList ++ t.rq.toList) (by pfx) (by lenx) (by lenx)
  have x3 : t.encode.extract ((domB "STORE/FRAME4").size + 491) ((domB "STORE/FRAME4").size + 555) = t.replaced :=
    extract_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8 ++
      lN t.bOpen 8 ++ lN t.bSeal 8 ++ evL t.sealEv ++ evL (t.installEv.map Prod.fst) ++ (installLeaf t.installEv).toList ++
      evL t.reclaimEv ++ t.au.toList ++ t.rq.toList ++ t.an.toList) (by pfx) (by lenx) (by lenx)
  have x4 : t.encode.extract ((domB "STORE/FRAME4").size + 555) ((domB "STORE/FRAME4").size + 619) = t.prev :=
    extract_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8 ++
      lN t.bOpen 8 ++ lN t.bSeal 8 ++ evL t.sealEv ++ evL (t.installEv.map Prod.fst) ++ (installLeaf t.installEv).toList ++
      evL t.reclaimEv ++ t.au.toList ++ t.rq.toList ++ t.an.toList ++ t.replaced.toList) (by pfx) (by lenx) (by lenx)
  have x5 : t.encode.extract ((domB "STORE/FRAME4").size + 619) ((domB "STORE/FRAME4").size + 683) = t.bd :=
    extract_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8 ++
      lN t.bOpen 8 ++ lN t.bSeal 8 ++ evL t.sealEv ++ evL (t.installEv.map Prod.fst) ++ (installLeaf t.installEv).toList ++
      evL t.reclaimEv ++ t.au.toList ++ t.rq.toList ++ t.an.toList ++ t.replaced.toList ++ t.prev.toList)
      (by pfx) (by lenx) (by lenx)
  have x6 : t.encode.extract ((domB "STORE/FRAME4").size + 683) ((domB "STORE/FRAME4").size + 747) = t.root :=
    extract_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8 ++
      lN t.bOpen 8 ++ lN t.bSeal 8 ++ evL t.sealEv ++ evL (t.installEv.map Prod.fst) ++ (installLeaf t.installEv).toList ++
      evL t.reclaimEv ++ t.au.toList ++ t.rq.toList ++ t.an.toList ++ t.replaced.toList ++ t.prev.toList ++
      t.bd.toList) (by pfx) (by lenx) (by lenx)
  have x7 : t.encode.extract ((domB "STORE/FRAME4").size + 747) ((domB "STORE/FRAME4").size + 811) = t.head :=
    extract_pre (pre := (domB "STORE/FRAME4").toList ++ lN t.shard 4 ++ lN t.batches 8 ++ lN t.hr.asOf 4 ++
      lN t.hr.count 8 ++ lN t.hr.n 8 ++ lN t.hu.asOf 4 ++ lN t.hu.count 8 ++ lN t.hu.n 8 ++ lN t.nx 8 ++
      lN t.bOpen 8 ++ lN t.bSeal 8 ++ evL t.sealEv ++ evL (t.installEv.map Prod.fst) ++ (installLeaf t.installEv).toList ++
      evL t.reclaimEv ++ t.au.toList ++ t.rq.toList ++ t.an.toList ++ t.replaced.toList ++ t.prev.toList ++
      t.bd.toList ++ t.root.toList) (by pfx) (by lenx) (by lenx)
  have hg : (((t.installEv.map Prod.fst).map (· % 256 ^ 4)).isSome || (installLeaf t.installEv).data.all (· == 0)) = true := by
    cases t.installEv with
    | some x => rfl
    | none => rw [installLeaf, show (zeroBlock 64).data = Array.replicate 64 0 from rfl, Array.all_replicate]; rfl
  have hb : ∀ x : ByteArray, (x == x) = true := fun x => by show (x.data == x.data) = true; exact beq_self_eq_true _
  have hin : ∀ o : Option (Nat × ByteArray), evL ((((o.map Prod.fst).map (· % 256 ^ 4)).map (·, installLeaf o)).map Prod.fst) =
      evL (o.map Prod.fst) ∧ installLeaf (((o.map Prod.fst).map (· % 256 ^ 4)).map (·, installLeaf o)) = installLeaf o := by
    intro o
    cases o with
    | none => exact ⟨rfl, rfl⟩
    | some x => exact ⟨congrArg (List.cons 1) (lN_mod 4 x.1), rfl⟩
  have hev : ∀ e : Option Nat, evL (e.map (· % 256 ^ 4)) = evL e := by
    intro e
    cases e with
    | none => rfl
    | some c => exact congrArg (List.cons 1) (lN_mod 4 c)
  refine ⟨⟨t.shard % 256 ^ 4, t.batches % 256 ^ 8, ⟨t.hr.asOf % 256 ^ 4, t.hr.count % 256 ^ 8, t.hr.n % 256 ^ 8⟩,
    ⟨t.hu.asOf % 256 ^ 4, t.hu.count % 256 ^ 8, t.hu.n % 256 ^ 8⟩, t.nx % 256 ^ 8, t.bOpen % 256 ^ 8,
    t.bSeal % 256 ^ 8, t.sealEv.map (· % 256 ^ 4),
    ((t.installEv.map Prod.fst).map (· % 256 ^ 4)).map (·, installLeaf t.installEv), t.reclaimEv.map (· % 256 ^ 4),
    t.au, t.rq, t.an, t.replaced, t.prev, t.bd, t.root, t.head⟩, ?_, ?_⟩
  · simp only [Trailer.decode, getHead, Nat.add_assoc, Nat.reduceAdd]
    rw [hsz, hdom, f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, g0, g1, g2, g3, x0, x1, x2, x3, x4, x5, x6, x7]
    simp only [hb, beq_self_eq_true, Option.bind_eq_bind, Option.bind_some]
    rw [hg]
    simp [guard]
  · apply bytes_ext
    rw [encode_tl, encode_tl]
    simp only [lN_mod, hev, (hin t.installEv).1, (hin t.installEv).2]

end BlindLedger.Gate.Engine3
