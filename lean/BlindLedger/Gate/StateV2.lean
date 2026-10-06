/-
STATE/v2 goals r4 (rr-core, 2026-10-06). Placed in the Lean tree at S1 (state-v2 branch); proofs land in steps.
Revises state-v2-goals-r3-20261006.lean against review-state-v2-r3-20261006.md (GO WITH FIXES, all 9 accepted).
Design: state-v2-design-r4-body-20261006.md. Read against rightrail-main 6a528e3 (Gate Lean and producer.py as
688bdd6): Gate/Spec.lean (digestBytes :24, zeroDigest :46, beNat :80, identField :156, WireFlow.ruled :166,
inputCommitment :183, linesRoot :212, pLine :277, Request :289-326, Checkpoint :342-377, Leaf :420-476,
decodeToken :490), Gate/Producer.lean (storedOfAny :13, isV2 :17, follows :23, publishOkAny :66-73),
Gate/Verify.lean (acceptsAny :39), Gate/Anchor.lean (setsDigest :16), Gate/Rules/Spec.lean (Line :130,
Ctx :170, Line.fields :458, pinInput :462, shardSets :520).
§1-§7: r3 text unchanged except r3's duplicate `beNat` (= Gate.beNat, Spec.lean:80) removed and
`decideRegT_perm` moved to §8b and RESTATED (it now names `paysOf`, defined in §7).
§8 is new. One mechanism per bug class:
  signing and custody state = one append-only signed-package log, CAS-appended off machine (fixes 1, 7, 8);
  the decision = custody's own `plan` (base + decideIdx); nothing courier-made is trusted (fix 2);
  the base = a function of the log: empty log -> the permit's base, else the last entry's header; no version
    test (fix 3); the permit's base takes no clock input, so migration cannot sit in the ticket window (fix 5);
  money fields = one PayRow per payment, compared by one permutation check (fix 4);
  order independence = one restated `decideRegT_perm` + `runT_perm` (fix 6);
  the last checkpoint = verified under `lastCert` inside `certsOk` (fix 9).
Goals RESTATED: decideRegT_perm (+ next sets Perm, counts, dates, paysOf), migrate_binds (permit base,
  runT equality, no redate-0 wrapper), chain_sound (logRunOk, independent counter, PayRow Perm; keeps the
  stateDigest conclusion), mark_advances -> entry_appends + head_advances (log terms).
Goals NEW: runT_perm, entryIn_inj, log_binds, invB_iff, v1_reach_inv, pLineFull_agrees, payNat_fits,
  lineOf_fits, reasonCode_ascending, custody_binds, rebuild_sound, reach_inv, never_twice, reconcile_ok,
  no_wedge, rollback_detected, restore_resumes.
Goals/defs DROPPED and why: Ticket, Tip, tipOf, Tip.genesis, Mark, atMark, Mark.step, permitMark, r3 Boot and
  reconcile (the log head and length replace the mark; r3's `tipOf n == mark.tip ||` re-sign path is gone,
  re-release resends log bytes); payNum, outcomeOf, tokTriple (PayRow/tokRow bind every money field); migrate,
  Base, baseOf, decideAt (permitBase/baseDigest; no isV2 test); lastDigest (follows already checks
  eventHead == p.digest, Producer.lean:28); segIn, segIn_inj (entryIn, entryIn_inj); publishOkV2,
  publishV2_binds, anchor_chain (custodyOk, custody_binds); r3 chainOk, trueSets, chain_sound_from (logRunOk,
  shardSetsT, chain_sound); r3 beNat (duplicate of Gate.beNat).
KEPT unchanged: tokens perm + length shape, tableOk, localDay_valid, localDay_mono, V1Collision, runT,
  redate, invB, eps, and the r3 §1-§7 theorems.
Every def is concrete; `sorry` stands only in theorem bodies. No axioms. PQ only: ML-DSA-87 via acceptsAny.
-/

import BlindLedger.Gate.Producer
import BlindLedger.Gate.Anchor
import BlindLedger.Gate.Rules.ShardRun

namespace BlindLedger.Gate.StateV2
open BlindLedger.Gate BlindLedger.Gate.Rules

/-! ## 1. Domains, hash length, collisions -/

/-- v2 twin of `domain` (Spec.lean:48 hard-codes /v1). -/
def dom2 (name : String) : Bytes := ("RR/GATE/" ++ name ++ "/v2").toUTF8.toList ++ [0]

def ND : Bytes := dom2 "STATE-NODE"
def PD : Bytes := dom2 "STATE-POST"
def KD : Bytes := dom2 "STATE-KEY"

def HashLen (H : Bytes → Bytes) : Prop := ∀ x, (H x).length = digestBytes

/-- A collision between two named input lists. -/
def Collision (H : Bytes → Bytes) (A B : List Bytes) : Prop := ∃ x ∈ A, ∃ y ∈ B, x ≠ y ∧ H x = H y

/-! ## 2. Injective key bytes (M4) and paths -/

/-- Field widths after the tag byte. 0 CAP near, 1/3 exact, 2 FFS near, 4 id, 5 CAP day
    [member, month, payee, date], 6 CAP invalid-date [member, month], 7 ROW (Line.fields order). -/
def keyWidths : Nat → Option (List Nat)
  | 0 | 6 => some [idWidth, 4]
  | 1 | 3 => some [idWidth, idWidth, 4, idWidth, 4, 8]
  | 2 => some [idWidth, idWidth, 4, idWidth]
  | 4 => some [idWidth]
  | 5 => some [idWidth, 4, idWidth, 4]
  | 7 => some [idWidth, payWidth, 1, idWidth, idWidth, idWidth, 4, idWidth, 4, 8]
  | _ => none

/-- `none` if the tag is unknown, the arity is wrong or a value overflows its width (`be`, Spec.lean:449). -/
def keyBytes : Key → Option Bytes
  | [] => none
  | t :: xs => do
    let ws ← keyWidths t
    if ws.length ≠ xs.length then none else
    let bs ← (ws.zip xs).mapM fun (w, n) => be w n
    pure (t.toUInt8 :: bs.flatten)

def rowKey (l : Line) : Key := 7 :: (Line.fields l).map (·.2)
def dayKey (l : Line) : Key := [5, l.member, l.date / 100, l.payee, l.date]
def badDayKey (l : Line) : Key := [6, l.member, l.date / 100]

/-- The keys a stored row sits under: `keys`; unresolved CAP rows also under their day key (valid date)
    or bad-day key, which make the CAP near claim local (`pending_near_cap`). -/
def rowKeys (u : Bool) (x : Line) : List Key :=
  keys x ++ (if u && isCap x then [if validDate x.date then dayKey x else badDayKey x] else [])

def pathOf (H : Bytes → Bytes) (kb : Bytes) : Bytes := H (KD ++ kb)

theorem keyBytes_inj {a b : Key} {x : Bytes} (ha : keyBytes a = some x) (hb : keyBytes b = some x) :
    a = b := sorry

theorem rowKey_inj {l m : Line} {x : Bytes} (hl : keyBytes (rowKey l) = some x)
    (hm : keyBytes (rowKey m) = some x) : l = m := sorry

/-- An encodable row has encodable keys (so the per-line guard in `decideIdx` covers every probe of it). -/
theorem rowKey_enc_keys (u : Bool) (l : Line) (h : (keyBytes (rowKey l)).isSome = true) :
    ∀ q ∈ rowKeys u l, (keyBytes q).isSome = true := sorry

/-! ## 3. Sparse Merkle map (C1 closed) -/

abbrev Map := List (Bytes × Bytes)   -- (64-byte path, value under 2^32 bytes)

def emptyIn : Bytes := ND ++ [2]
def leafIn (p v : Bytes) : Bytes := ND ++ 0 :: (p ++ natBE 4 v.length ++ v)
def nodeIn (l r : Bytes) : Bytes := ND ++ 1 :: (l ++ r)

/-- C1: a leaf is admissible only with a 64-byte path and a value under 2^32 bytes (`natBE 4` never
    wraps). Checked in `hashPf`, `pfInputs`, `lookupPf` and `minimal`. -/
def leafOk (p v : Bytes) : Bool := p.length == digestBytes && decide (v.length < 2 ^ 32)

/-- C1: with fixed 64-byte paths the leaf preimage parses one way. -/
theorem leafIn_inj {p p' v v' : Bytes} (hp : p.length = digestBytes) (hp' : p'.length = digestBytes)
    (h : leafIn p v = leafIn p' v') : p = p' ∧ v = v' := sorry

/-- Bit `d` of a path, most significant first. -/
def bit (p : Bytes) (d : Nat) : Bool := (p.getD (d / 8) 0).toNat / 2 ^ (7 - d % 8) % 2 == 1

/-- Canonical root: a lone key sits at the first depth where it is alone; no keys is the empty hash.
    A function of the key set only. Fuel 513 covers 512-bit paths. -/
def rootAt (H : Bytes → Bytes) : Nat → Nat → Map → Bytes
  | _, _, [] => H emptyIn
  | _, _, [(p, v)] => H (leafIn p v)
  | 0, _, _ => []
  | f + 1, d, m => H (nodeIn (rootAt H f (d + 1) (m.filter fun e => !bit e.1 d))
                              (rootAt H f (d + 1) (m.filter fun e => bit e.1 d)))

/-- Every hash input `rootAt` computes (the true side of a collision). -/
def treeInputs (H : Bytes → Bytes) : Nat → Nat → Map → List Bytes
  | _, _, [] => [emptyIn]
  | _, _, [(p, v)] => [leafIn p v]
  | 0, _, _ => []
  | f + 1, d, m =>
    let l := m.filter fun e => !bit e.1 d
    let r := m.filter fun e => bit e.1 d
    nodeIn (rootAt H f (d + 1) l) (rootAt H f (d + 1) r) :: (treeInputs H f (d + 1) l ++ treeInputs H f (d + 1) r)

def root (H : Bytes → Bytes) (m : Map) : Bytes := rootAt H 513 0 m
def lookup (m : Map) (k : Bytes) : Option Bytes := (m.find? (·.1 == k)).map (·.2)
def upsert (m : Map) (ws : Map) : Map := ws.foldl (fun m (k, v) => (k, v) :: m.filter (·.1 != k)) m

/-- Pruned tree in preorder; wire tags 0 opaque, 1 empty, 2 leaf, 3 node. -/
inductive Proof
  | opaque (h : Bytes)
  | empty
  | leaf (p v : Bytes)
  | node (l r : Proof)

def hashPf (H : Bytes → Bytes) : Proof → Bytes
  | .opaque h => h
  | .empty => H emptyIn
  | .leaf p v => if leafOk p v then H (leafIn p v) else []
  | .node l r => H (nodeIn (hashPf H l) (hashPf H r))

def pfInputs (H : Bytes → Bytes) : Proof → List Bytes
  | .opaque _ => []
  | .empty => [emptyIn]
  | .leaf p v => if leafOk p v then [leafIn p v] else []
  | .node l r => nodeIn (hashPf H l) (hashPf H r) :: (pfInputs H l ++ pfInputs H r)

/-- `some none`: proved absent (empty, or an admissible leaf with a different full path). `none`:
    unproved (opaque, inadmissible leaf, or deeper than 512 bits: Low depth bound). -/
def lookupPf : Nat → Proof → Bytes → Option (Option Bytes)
  | _, .opaque _, _ => none
  | _, .empty, _ => some none
  | _, .leaf p v, k => if leafOk p v then some (if p == k then some v else none) else none
  | d, .node l r, k =>
    if d < 512 then (if bit k d then lookupPf (d + 1) r k else lookupPf (d + 1) l k) else none

/-- Minimal: every non-opaque part has a probe below it, opaque hashes are 64 bytes, leaves are
    admissible, depth under 512. Bounds witness bytes (frame DoS). -/
def minimal : Nat → Proof → List Bytes → Bool
  | _, .opaque h, _ => h.length == digestBytes
  | d, .node l r, ks => decide (d < 512) && !ks.isEmpty && minimal (d + 1) l (ks.filter (!bit · d)) &&
      minimal (d + 1) r (ks.filter (bit · d))
  | _, .leaf p v, ks => leafOk p v && !ks.isEmpty
  | _, .empty, ks => !ks.isEmpty

def verifyMulti (H : Bytes → Bytes) (r : Bytes) (ks : List Bytes) (pf : Proof) : Bool :=
  r.length == digestBytes && ks.all (·.length == digestBytes) && hashPf H pf == r &&
    ks.all (fun k => (lookupPf 0 pf k).isSome) && minimal 0 pf ks

def MapOk (m : Map) : Prop :=
  (m.map (·.1)).Nodup ∧ ∀ e ∈ m, e.1.length = digestBytes ∧ e.2.length < 2 ^ 32

/-- C1: presence and absence both sound. True as stated: a forged leaf must have a 64-byte path
    (`leafOk`), so equal leaf bytes give equal path and value (`leafIn_inj`); leaf, node and empty
    preimages differ in their tag byte; every child hash is 64 bytes, so `nodeIn` splits one way. -/
theorem smt_sound (H : Bytes → Bytes) (hH : HashLen H) (m : Map) (hm : MapOk m) (ks : List Bytes)
    (pf : Proof) (hv : verifyMulti H (root H m) ks pf = true) (k : Bytes) (hk : k ∈ ks) :
    lookupPf 0 pf k = some (lookup m k) ∨ Collision H (pfInputs H pf) (treeInputs H 513 0 m) := sorry

theorem root_perm (H : Bytes → Bytes) (m m' : Map) (hm : MapOk m) (hp : m.Perm m') :
    root H m = root H m' := sorry

/-- The canonical subtree of `m` from depth `d` with no opaque part. -/
def build : Nat → Nat → Map → Proof
  | _, _, [] => .empty
  | _, _, [(p, v)] => .leaf p v
  | 0, _, _ => .opaque []
  | f + 1, d, m => .node (build f (d + 1) (m.filter fun e => !bit e.1 d)) (build f (d + 1) (m.filter fun e => bit e.1 d))

/-- New tree from a verified proof plus writes (upsert only; a leaf or empty that gains keys is rebuilt
    canonically). An opaque part on a write path is impossible after `verifyMulti` (kept unchanged). -/
def upsertPf : Nat → Nat → Proof → Map → Proof
  | _, _, pf, [] => pf
  | f, d, .empty, ws => build f d ws
  | f, d, .leaf p v, ws => build f d (if ws.any (·.1 == p) then ws else (p, v) :: ws)
  | f + 1, d, .node l r, ws => .node (upsertPf f (d + 1) l (ws.filter fun e => !bit e.1 d))
      (upsertPf f (d + 1) r (ws.filter fun e => bit e.1 d))
  | _, _, pf, _ => pf

theorem multi_update_sound (H : Bytes → Bytes) (hH : HashLen H) (m ws : Map) (hm : MapOk m) (hw : MapOk ws)
    (ks : List Bytes) (pf : Proof) (hv : verifyMulti H (root H m) ks pf = true) (hs : ∀ e ∈ ws, e.1 ∈ ks) :
    hashPf H (upsertPf 513 0 pf ws) = root H (upsert m ws) ∨
      Collision H (pfInputs H pf) (treeInputs H 513 0 m) := sorry

/-- The honest multiproof: `m`'s canonical tree cut to the paths `ks`. -/
def prune (H : Bytes → Bytes) : Nat → Nat → Map → List Bytes → Proof
  | f, d, m, [] => .opaque (rootAt H f d m)
  | _, _, [], _ :: _ => .empty
  | _, _, [(p, v)], _ :: _ => .leaf p v
  | 0, _, _, _ => .opaque []
  | f + 1, d, m, ks => .node (prune H f (d + 1) (m.filter fun e => !bit e.1 d) (ks.filter (!bit · d)))
      (prune H f (d + 1) (m.filter fun e => bit e.1 d) (ks.filter (bit · d)))

theorem prune_complete (H : Bytes → Bytes) (hH : HashLen H) (m : Map) (hm : MapOk m) (ks : List Bytes)
    (hk : ∀ k ∈ ks, k.length = digestBytes) : verifyMulti H (root H m) ks (prune H 513 0 m ks) = true := sorry

/-! ## 4. Posting lists (H2, M-b): append-only, row order, Spec.lean:198-206 shape -/

def K : Nat := 8

/-- One posting: row position u64, then the row id (`be`: `none` on overflow, never a wrap). -/
def postEntry (pos id : Nat) : Option Bytes := do
  let a ← be 8 pos
  let b ← be idWidth id
  pure (a ++ b)

def listRoot (H : Bytes → Bytes) (xs : List Bytes) : Bytes := treeRoot H PD 64 (xs.map (leafHash H PD))

/-- Node preimages of one `pairUp` level (an odd last element is carried, no preimage). -/
def levelInputs (d : Bytes) : List Bytes → List Bytes
  | a :: b :: rest => (d ++ 1 :: (a ++ b)) :: levelInputs d rest
  | _ => []

def treeInputsL (H : Bytes → Bytes) (d : Bytes) : Nat → List Bytes → List Bytes
  | _, [_] => []
  | 0, _ => []
  | f + 1, xs => levelInputs d xs ++ treeInputsL H d f (pairUp H d xs)

/-- Every hash input behind `listRoot H xs` (H-a, true side). -/
def listInputs (H : Bytes → Bytes) (xs : List Bytes) : List Bytes :=
  xs.map (fun x => PD ++ 0 :: x) ++ treeInputsL H PD 64 (xs.map (leafHash H PD))

/-- Frontier: (height, subtree root), lowest height first; one push is O(log n). -/
def carry (H : Bytes → Bytes) : Nat → Nat → Bytes → List (Nat × Bytes) → List (Nat × Bytes)
  | f + 1, h, r, (h', l) :: rest =>
    if h == h' then carry H f (h + 1) (nodeHash H PD l r) rest else (h, r) :: (h', l) :: rest
  | _, h, r, fs => (h, r) :: fs

def frontierPush (H : Bytes → Bytes) (fs : List (Nat × Bytes)) (x : Bytes) : List (Nat × Bytes) :=
  carry H 64 0 (leafHash H PD x) fs

def frontierRoot (H : Bytes → Bytes) : List (Nat × Bytes) → Bytes
  | [] => []
  | (_, r) :: rest => rest.foldl (fun acc e => nodeHash H PD e.2 acc) r

/-- Heights present in the frontier of `n` entries: the set bits of `n`, ascending. -/
def peaksOf (n : Nat) : List Nat := (List.range 64).filter fun i => n / 2 ^ i % 2 == 1

/-- Key leaf value: entry count u64, then the frontier roots (lowest height first). At most
    8 + 64*64 bytes, so under 2^32. -/
def keyVal (n : Nat) (fs : List (Nat × Bytes)) : Option Bytes := do
  let c ← be 8 n
  pure (c ++ (fs.map (·.2)).flatten)

def chunks : Nat → Bytes → List Bytes
  | 0, _ => []
  | f + 1, b => if b.isEmpty then [] else b.take 64 :: chunks f (b.drop 64)

def parseKeyVal (v : Bytes) : Option (Nat × List (Nat × Bytes)) :=
  let n := beNat (v.take 8)
  if v.length == 8 + 64 * (peaksOf n).length then some (n, (peaksOf n).zip (chunks 64 (v.drop 8))) else none

theorem listRoot_frontier (H : Bytes → Bytes) (xs : List Bytes) (hn : xs.length < 2 ^ 64) :
    frontierRoot H (xs.foldl (frontierPush H) []) = listRoot H xs := sorry

theorem frontier_peaks (H : Bytes → Bytes) (hH : HashLen H) (xs : List Bytes) (hn : xs.length < 2 ^ 64) :
    (xs.foldl (frontierPush H) []).map (·.1) = peaksOf xs.length := sorry

theorem keyVal_parse (H : Bytes → Bytes) (hH : HashLen H) (xs : List Bytes) (v : Bytes)
    (h : keyVal xs.length (xs.foldl (frontierPush H) []) = some v) :
    parseKeyVal v = some (xs.length, xs.foldl (frontierPush H) []) := sorry

/-- First-K check: from the hashes of the first `min K n` entries and sibling hashes `pf`, rebuild the
    root level by level; returns the root and every preimage hashed (H-a, witness side). -/
def firstKRun (H : Bytes → Bytes) (d : Bytes) : Nat → Nat → List Bytes → List Bytes → Option (Bytes × List Bytes)
  | _, 1, [r], [] => some (r, [])
  | 0, _, _, _ => none
  | f + 1, n, ks, pf =>
    let odd := ks.length % 2 == 1 && decide (ks.length < n)
    if ks.isEmpty || decide (n ≤ 1) || decide (n < ks.length) || (odd && pf.isEmpty) then none else
    let ks' := if odd then ks ++ pf.take 1 else ks
    let pf' := if odd then pf.drop 1 else pf
    (firstKRun H d f ((n + 1) / 2) (pairUp H d ks') pf').map fun (r, ins) => (r, levelInputs d ks' ++ ins)

def verifyFirstK (H : Bytes → Bytes) (r : Bytes) (n : Nat) (ys pf : List Bytes) : Bool :=
  decide (1 ≤ n) && ys.length == min K n && ys.all (·.length == 8 + idWidth) &&
    pf.all (·.length == digestBytes) && (firstKRun H PD 64 n (ys.map (leafHash H PD)) pf).any (·.1 == r)

def firstKInputs (H : Bytes → Bytes) (n : Nat) (ys pf : List Bytes) : List Bytes :=
  ys.map (fun y => PD ++ 0 :: y) ++ ((firstKRun H PD 64 n (ys.map (leafHash H PD)) pf).map (·.2)).getD []

/-- The honest sibling list for the first `j` of level `lv`. -/
def firstKPf (H : Bytes → Bytes) (d : Bytes) : Nat → Nat → List Bytes → List Bytes
  | 0, _, _ => []
  | f + 1, j, lv =>
    if lv.length ≤ 1 then [] else
    (if j % 2 == 1 && decide (j < lv.length) then [lv.getD j []] else []) ++
      firstKPf H d f ((j + 1) / 2) (pairUp H d lv)

theorem firstK_sound (H : Bytes → Bytes) (hH : HashLen H) (xs ys pf : List Bytes) (hn : xs.length < 2 ^ 64)
    (hv : verifyFirstK H (listRoot H xs) xs.length ys pf = true) :
    ys = xs.take K ∨ Collision H (firstKInputs H xs.length ys pf) (listInputs H xs) := sorry

theorem firstK_complete (H : Bytes → Bytes) (hH : HashLen H) (xs : List Bytes) (h1 : 1 ≤ xs.length)
    (hn : xs.length < 2 ^ 64) (hx : ∀ x ∈ xs, x.length = 8 + idWidth) :
    verifyFirstK H (listRoot H xs) xs.length (xs.take K)
      (firstKPf H PD 64 (min K xs.length) (xs.map (leafHash H PD))) = true := sorry

/-! ## 5. Carried semantics and the reachable-state invariant (H5) -/

/-- Reachable states: ids unique across both sets (rows unique, rel ∩ unr = ∅, `own` false on
    unresolved rows) and counts exact. -/
def Inv (rel unr : Snapshot Line) : Prop :=
  ((rel.entries ++ unr.entries).map (·.id)).Nodup ∧ rel.count = rel.entries.length ∧
    unr.count = unr.entries.length

/-- The view is already proved: `carried_sets` (DecideLayer.lean:28). -/
theorem carried_loose (t : Nat) (s : Snapshot Line) : loose t s (some s) = [] := sorry

theorem carried_chained (t : Nat) (s : Snapshot Line) (hc : s.count = s.entries.length) :
    chained t s (some s) = (validDate s.asOf && decide (s.asOf ≤ t)) := sorry

/-- `seen0` as a count comparison; the excluded count comes from ROW probes of the batch. -/
theorem seen0_count (c₀ : Ctx) (rel unr : Snapshot Line) (b : List Line) (q : Key) :
    (seen0 (carried c₀ rel unr) b).contains q =
      decide ((rel.entries.filter fun x => c₀.redo.contains x.pay && b.contains x && (keys x).contains q).length
        < (rel.entries.filter fun x => (keys x).contains q).length) := sorry

/-- The CAP near claim is local: day keys of today's covering spans, invalid dates, or the aggregate key
    when enrollment is unusable. Exact and id keys are always claimed. -/
theorem pending_near_cap (c₀ : Ctx) (rel unr : Snapshot Line) (hi : Inv rel unr) (m mo : Nat) :
    (pending (carried c₀ rel unr)).contains [0, m, mo] =
      unr.entries.any fun x => nearKey x == [0, m, mo] &&
        (!usable c₀.today 7 okSpan c₀.enrollment || !validDate x.date || enrolled c₀ x) := sorry

/-! ## 5b. Dated sets (H-c), v2 only. `decideReg`/`advance` (Rules/Spec.lean:236-239, :500) stay as they
    are, so v1 replay, `loadAdds` and v1 pins are unchanged; v2 decides with `decideRegT` (dates only). -/

/-- Monotone: the date moves to `today` only when the set read was chained and today is valid. -/
def bumpIf (ok : Bool) (today a : Nat) : Nat := if ok && validDate today then today else a

def bumpRes (c : Ctx) (r : Result) : Result :=
  { r with
    released := { r.released with asOf := bumpIf (chained c.today c.releasedPrior c.released) c.today r.released.asOf },
    unresolved := { r.unresolved with
      asOf := bumpIf (chained c.today c.unresolvedPrior c.unresolved) c.today r.unresolved.asOf } }

def decideRegT (c : Ctx) (k : Nat) (os : List Owner) (b : List Line) : Result := bumpRes c (decideReg c k os b)

def shardSetsT (k : Nat) (g : Snapshot Line × Snapshot Line) (ts : List Batch) : Snapshot Line × Snapshot Line :=
  ts.foldl (fun s t => let r := decideRegT (carried t.ctx s.1 s.2) k t.owners t.lines; (r.released, r.unresolved)) g

def addsOfT (k : Nat) (g : Snapshot Line × Snapshot Line) : List Batch → List (List Line × List Line)
  | [] => []
  | t :: ts => let c := carried t.ctx g.1 g.2; let r := decideRegT c k t.owners t.lines
               batchFresh c r :: addsOfT k (r.released, r.unresolved) ts

/-- v2 replay: each batch is dated `localDay` of its ticket (§8). -/
def bumpSet (t : Nat) (s : Snapshot Line) : Nat :=
  bumpIf (s.entries.length == s.count && validDate s.asOf && decide (s.asOf ≤ t)) t s.asOf

def replayT (g : Snapshot Line × Snapshot Line) (as : List (Nat × (List Line × List Line))) :
    Snapshot Line × Snapshot Line :=
  as.foldl (fun s (t, a) => (⟨bumpSet t s.1, s.1.entries.length + a.1.length, s.1.entries ++ a.1⟩,
                             ⟨bumpSet t s.2, s.2.entries.length + a.2.length, s.2.entries ++ a.2⟩)) g

/-- KEPT. Added beside `replay_addsOf` (DecideLayer.lean:52-55, unchanged): whole snapshots, dates included. -/
theorem replayT_addsOfT (k : Nat) (g : Snapshot Line × Snapshot Line) (ts : List Batch) :
    replayT g ((ts.map (·.ctx.today)).zip (addsOfT k g ts)) = shardSetsT k g ts := sorry

def genesisSets (t : Nat) : Snapshot Line × Snapshot Line := (⟨t, 0, []⟩, ⟨t, 0, []⟩)

theorem genesis_chained (t : Nat) (ht : validDate t = true) :
    chained t (genesisSets t).1 (some (genesisSets t).1) = true ∧
      chained t (genesisSets t).2 (some (genesisSets t).2) = true := sorry

theorem asOf_mono (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (rel unr : Snapshot Line) :
    rel.asOf ≤ (decideRegT (carried c₀ rel unr) k os b).released.asOf ∧
      unr.asOf ≤ (decideRegT (carried c₀ rel unr) k os b).unresolved.asOf := sorry

/-- A dated set stays dated: after a batch on a valid `today` not before it, it is dated `today`. -/
theorem asOf_step (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (rel unr : Snapshot Line)
    (hi : Inv rel unr) (hr : validDate rel.asOf = true) (hu : validDate unr.asOf = true)
    (ht : validDate c₀.today = true) (hrt : rel.asOf ≤ c₀.today) (hut : unr.asOf ≤ c₀.today) :
    (decideRegT (carried c₀ rel unr) k os b).released.asOf = c₀.today ∧
      (decideRegT (carried c₀ rel unr) k os b).unresolved.asOf = c₀.today := sorry

/-- STALE_RELEASED fires on a carried, dated set only when the clock went back. -/
theorem stale_released_iff (c₀ : Ctx) (rel unr : Snapshot Line) (hc : rel.count = rel.entries.length)
    (hv : validDate rel.asOf = true) (seen : List Key) (l : Line) :
    fires (carried c₀ rel unr) seen l .STALE_RELEASED = !decide (rel.asOf ≤ c₀.today) := sorry

theorem inv_step (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (rel unr : Snapshot Line)
    (hi : Inv rel unr) :
    let r := decideRegT (carried c₀ rel unr) k os b
    Inv r.released r.unresolved := sorry


/-! ## 6. STATE/v2 head and digest (H-d, M-a) -/

structure Head where
  relAsOf : Nat
  unrAsOf : Nat
  relCount : Nat
  unrCount : Nat
  relRoot : Bytes
  unrRoot : Bytes
  deriving DecidableEq

/-- M-a: `be`, so an out-of-width date or count is `none` (fail closed), never a wrap. -/
def headIn (h : Head) : Option Bytes := do
  let a ← be 4 h.relAsOf
  let b ← be 4 h.unrAsOf
  let c ← be 8 h.relCount
  let d ← be 8 h.unrCount
  guard (h.relRoot.length = digestBytes ∧ h.unrRoot.length = digestBytes)
  pure (dom2 "STATE" ++ a ++ b ++ c ++ d ++ h.relRoot ++ h.unrRoot)

def digestV2 (H : Bytes → Bytes) (h : Head) : Option Bytes := (headIn h).map H

/-- Postings of key `q` in set `s`: (position, id) of each row stored under `q`, in row order. -/
def postings (u : Bool) (s : List Line) (q : Key) : Option (List Bytes) :=
  (s.zipIdx.filter fun (x, _) => (rowKeys u x).contains q).mapM fun (x, i) => postEntry i x.id

/-- The intended map of a set (H-d): per row its ROW leaf (position u64); per key its count and
    frontier. `none` on any overflow or a path collision. -/
def setMap (H : Bytes → Bytes) (u : Bool) (s : List Line) : Option Map := do
  let rows ← s.zipIdx.mapM fun (x, i) => do
    let kb ← keyBytes (rowKey x)
    let v ← be 8 i
    pure (pathOf H kb, v)
  let ks ← ((s.flatMap (rowKeys u)).eraseDups).mapM fun q => do
    let kb ← keyBytes q
    let es ← postings u s q
    let v ← keyVal es.length (es.foldl (frontierPush H) [])
    pure (pathOf H kb, v)
  let m := rows ++ ks
  guard (m.map (·.1)).Nodup
  pure m

def headOf (H : Bytes → Bytes) (rel unr : Snapshot Line) : Option Head := do
  let a ← setMap H false rel.entries
  let b ← setMap H true unr.entries
  pure ⟨rel.asOf, unr.asOf, rel.count, unr.count, root H a, root H b⟩

def genesisHead (H : Bytes → Bytes) (t : Nat) : Head := ⟨t, t, 0, 0, H emptyIn, H emptyIn⟩

theorem headOf_genesis (H : Bytes → Bytes) (t : Nat) :
    headOf H (genesisSets t).1 (genesisSets t).2 = some (genesisHead H t) := sorry

theorem setMap_ok (H : Bytes → Bytes) (hH : HashLen H) (u : Bool) (s : List Line) (m : Map)
    (h : setMap H u s = some m) : MapOk m := sorry

/-- Every hash input behind one set's map: key paths, posting lists, tree (H-d). -/
def setInputs (H : Bytes → Bytes) (u : Bool) (s : List Line) : List Bytes :=
  let qs := (s.flatMap (rowKeys u)).eraseDups
  (s.map rowKey ++ qs).filterMap (fun q => (keyBytes q).map (KD ++ ·)) ++
    qs.flatMap (fun q => listInputs H ((postings u s q).getD [])) ++
    ((setMap H u s).map (treeInputs H 513 0)).getD []

def stateInputs (H : Bytes → Bytes) (rel unr : Snapshot Line) : List Bytes :=
  ((headOf H rel unr).bind headIn).toList ++ setInputs H false rel.entries ++ setInputs H true unr.entries

theorem stateV2_binds (H : Bytes → Bytes) (hH : HashLen H) (rel unr rel' unr' : Snapshot Line)
    (hi : Inv rel unr) (hi' : Inv rel' unr') (h h' : Head) (d : Bytes)
    (ha : headOf H rel unr = some h) (ha' : headOf H rel' unr' = some h')
    (he : digestV2 H h = some d) (he' : digestV2 H h' = some d) :
    (rel = rel' ∧ unr = unr') ∨ Collision H (stateInputs H rel unr) (stateInputs H rel' unr') := sorry

/-! ## 7. The indexed decision (H2 output, H5 refinement, H-a) -/

/-- M-b: each count is per key (rows stored under that key), not distinct counterparts. -/
structure DecisionV2 where
  line : Line
  outcome : Outcome
  reasons : List Reason
  /-- Per key of `keys line`, per set: (unresolved?, path, rows under this key, posting root). -/
  hits : List (Bool × Bytes × Nat × Bytes)
  /-- First K counterparts: position merge of the per-key first-K lists, duplicates removed. -/
  firstK : List Nat

structure Witness where
  anchor : Head
  relPf : Proof
  unrPf : Proof
  /-- (unresolved?, path, count, first min K n entries, sibling hashes). -/
  lists : List (Bool × Bytes × Nat × List Bytes × List Bytes)

structure OutV2 where
  decisions : List DecisionV2
  fresh : List Line × List Line
  free : List Nat
  head : Head
  digest : Bytes
  /-- Fix 3: per payment (pay, payOutcome, Σ line cents), first-seen order. The only source of token fields. -/
  pays : List (Nat × Outcome × Nat)

/-- A verified probe: absent keys have `n = 0`; ROW keys `n = 1`. -/
structure Hit where
  unr : Bool
  key : Key
  path : Bytes
  n : Nat
  peaks : List (Nat × Bytes)
  first : List Bytes

def daysIn (mo : Nat) : List Nat := ((List.range 31).map fun i => mo * 100 + i + 1).filter validDate

/-- The unresolved keys that show the CAP near claim [0, m, mo] (`pending_near_cap`). -/
def capProbes (c₀ : Ctx) (m mo : Nat) : List Key :=
  if !usable c₀.today 7 okSpan c₀.enrollment then [[0, m, mo]] else
  [6, m, mo] :: ((entries c₀.enrollment).filter (·.member == m)).flatMap fun s =>
    ((daysIn mo).filter fun d => decide (s.start ≤ d) && decide (d ≤ s.stop)).map fun d => [5, m, mo, s.plan, d]

/-- Probes Lean computes itself (never from the courier): keys and ROW of every ready line in both trees,
    CAP probes, and the id key of every WAIT id (`pendingOf`). -/
def probeKeys (c₀ : Ctx) (k : Nat) (os : List Owner) (bb : List Line) : List Key × List Key :=
  let ids := (pendingOf k os).map fun i => [4, i]
  (((bb.flatMap fun l => keys l ++ [rowKey l]) ++ ids).eraseDups,
   ((bb.flatMap fun l => rowKeys true l ++ [rowKey l] ++
      (if isCap l then capProbes c₀ l.member (l.date / 100) else [])) ++ ids).eraseDups)

/-- `some none`: unencodable key (no stored row has it, count 0). `none`: refused. -/
def probe (H : Bytes → Bytes) (pf : Proof) (w : Witness) (u : Bool) (q : Key) : Option (Option Hit) :=
  match keyBytes q with
  | none => some none
  | some kb =>
    let p := pathOf H kb
    match lookupPf 0 pf p with
    | none => none
    | some none => some (some ⟨u, q, p, 0, [], []⟩)
    | some (some v) =>
      if q.head? == some 7 then (if v.length == 8 then some (some ⟨u, q, p, 1, [], []⟩) else none) else
      match parseKeyVal v, w.lists.find? (fun e => e.1 == u && e.2.1 == p) with
      | some (n, pk), some (_, _, n', ys, fp) =>
        if decide (1 ≤ n) && n' == n && verifyFirstK H (frontierRoot H pk) n ys fp then
          some (some ⟨u, q, p, n, pk, ys⟩) else none
      | _, _ => none

def findHit (hs : List Hit) (u : Bool) (q : Key) : Option Hit := hs.find? fun h => h.unr == u && h.key == q

/-- What the indexed decision reads: frame context, verified hits, each set's date check, ready lines. -/
structure Ix where
  c₀ : Ctx
  hs : List Hit
  relOk : Bool
  unrOk : Bool
  bb : List Line

namespace Ix

def cnt (x : Ix) (u : Bool) (q : Key) : Nat := ((findHit x.hs u q).map (·.n)).getD 0
def firstOf (x : Ix) (u : Bool) (q : Key) : List Bytes := ((findHit x.hs u q).map (·.first)).getD []
def inRel (x : Ix) (l : Line) : Bool := decide (0 < x.cnt false (rowKey l))
def ownQ (x : Ix) (l : Line) : Bool := x.c₀.redo.contains l.pay && x.inRel l

/-- `seen0` by count (`seen0_count`). -/
def seen0Has (x : Ix) (q : Key) : Bool :=
  decide (((x.bb.filter x.ownQ).eraseDups.filter fun y => (keys y).contains q).length < x.cnt false q)

/-- `pending` by count (`pending_near_cap` for the CAP near key). -/
def pendQ (x : Ix) : Key → Bool
  | [0, m, mo] => (capProbes x.c₀ m mo).any fun q => decide (0 < x.cnt true q)
  | q => decide (0 < x.cnt true q)

def claimQ (x : Ix) (l : Line) : List Key :=
  if isCap l && notEnrolled x.c₀ l && !x.ownQ l then [exactKey l, idKey l] else keys l

/-- `fires` on the carried context, read through the index. -/
def firesQ (x : Ix) (seen : List Key) (l : Line) (r : Reason) : Bool :=
  let sh := fun q => seen.contains q || x.seen0Has q
  match r with
  | .ALREADY_DECIDED => sh (idKey l) || x.pendQ (idKey l)
  | .CAP_MEMBER_MONTH_DUPLICATE => isCap l &&
      (sh (exactKey l) || sh (nearKey l) || certain x.c₀ 7 okSpan x.c₀.enrollment l && overlap x.c₀ l)
  | .COLLIDES_WITH_UNRESOLVED_NEAR => !isCap l && x.pendQ (nearKey l) && !x.pendQ (exactKey l)
  | .DUPLICATE_OF_UNRESOLVED => x.pendQ (exactKey l) || isCap l && x.pendQ (nearKey l)
  | .FFS_DUPLICATE_LINE => !isCap l && sh (exactKey l)
  | .FFS_DUPLICATE_UNVERIFIED => false
  | .FFS_NEAR_DUPLICATE => !isCap l && sh (nearKey l) && !sh (exactKey l)
  | .STALE_RELEASED => !x.relOk
  | .STALE_UNRESOLVED => !x.unrOk
  | r => fires x.c₀ [] l r

def mergeFirst (ls : List (List Bytes)) : List Nat :=
  let es := (ls.flatten.map fun e => (beNat (e.take 8), beNat (e.drop 8))).mergeSort fun a b => decide (a.1 ≤ b.1)
  (es.eraseDups.take K).map (·.2)

/-- `counterparts.take K`: released lines sharing a key, then unresolved lines whose claim does. -/
def firstKQ (x : Ix) (l : Line) : List Nat :=
  let unrQs := [exactKey l, idKey l] ++
    (if isCap l then capProbes x.c₀ l.member (l.date / 100) else [nearKey l])
  (mergeFirst ((keys l).map (x.firstOf false)) ++ mergeFirst (unrQs.map (x.firstOf true))).take K

def hitsQ (H : Bytes → Bytes) (x : Ix) (l : Line) : List (Bool × Bytes × Nat × Bytes) :=
  (keys l).flatMap fun q => [false, true].filterMap fun u =>
    (findHit x.hs u q).map fun h => (u, h.path, h.n, frontierRoot H h.peaks)

def decideAllQ (H : Bytes → Bytes) (x : Ix) : List Key → List Line → List DecisionV2
  | _, [] => []
  | seen, l :: ls =>
    let rs := reasons.filter (x.firesQ seen l)
    { line := l, outcome := outcomeOf rs, reasons := rs, hits := x.hitsQ H l, firstK := x.firstKQ l } ::
      decideAllQ H x (x.claimQ l ++ seen) ls

def orderQ (x : Ix) (b : List Line) : List Line := canonical (b.filter x.ownQ) ++ canonical (b.filter fun y => !x.ownQ y)

def payOutcomeQ (x : Ix) (ds : List DecisionV2) (p : Nat) : Outcome :=
  let ls := ds.filter (·.line.pay == p)
  if ls.any (·.outcome == .HOLD) then .HOLD
  else if !ls.isEmpty && ls.all fun d => d.outcome == .ALLOW && (!x.c₀.redo.contains p || x.ownQ d.line) then .ALLOW
  else .HUMAN_REVIEW

def releasedQ (x : Ix) (ds : List DecisionV2) : List Line :=
  ((ds.filter (·.outcome == .ALLOW)).map (·.line)).filter fun l =>
    !x.c₀.redo.contains l.pay && payOutcomeQ x ds l.pay == .ALLOW

def unresolvedQ (x : Ix) (ds : List DecisionV2) : List Line :=
  (ds.filter fun d => d.outcome != .ALLOW && !d.reasons.contains .ALREADY_DECIDED && !x.ownQ d.line).map (·.line)

end Ix

/-- The leaves a batch writes into one tree: ROW leaf per new row at its position; per key the count and
    frontier after appending its new postings (O(log n) per key). -/
def writes (H : Bytes → Bytes) (u : Bool) (hs : List Hit) (c0 : Nat) (xs : List Line) : Option Map := do
  let rows ← xs.zipIdx.mapM fun (x, j) => do
    let kb ← keyBytes (rowKey x)
    let v ← be 8 (c0 + j)
    pure (pathOf H kb, v)
  let ks ← ((xs.flatMap (rowKeys u)).eraseDups).mapM fun q => do
    let kb ← keyBytes q
    let h ← findHit hs u q
    let es ← (xs.zipIdx.filter fun (x, _) => (rowKeys u x).contains q).mapM fun (x, j) => postEntry (c0 + j) x.id
    let v ← keyVal (h.n + es.length) (es.foldl (frontierPush H) h.peaks)
    pure (pathOf H kb, v)
  let m := rows ++ ks
  guard (m.map (·.1)).Nodup
  pure m

/-- One batch, stateless: every proof re-checked (no trusted memory). `none` = RULES_STATE_MISMATCH. -/
def decideIdx (H : Bytes → Bytes) (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (anchor : Bytes)
    (w : Witness) : Option OutV2 := do
  let a := w.anchor
  guard (digestV2 H a = some anchor)
  let bb := ready k os b
  guard ((bb.all fun l => (keyBytes (rowKey l)).isSome) = true)
  let (qr, qu) := probeKeys c₀ k os bb
  let pr := qr.filterMap fun q => (keyBytes q).map (pathOf H)
  let pu := qu.filterMap fun q => (keyBytes q).map (pathOf H)
  guard ((verifyMulti H a.relRoot pr w.relPf && verifyMulti H a.unrRoot pu w.unrPf) = true)
  let hr ← qr.mapM (probe H w.relPf w false)
  let hu ← qu.mapM (probe H w.unrPf w true)
  let relOk := validDate a.relAsOf && decide (a.relAsOf ≤ c₀.today)
  let unrOk := validDate a.unrAsOf && decide (a.unrAsOf ≤ c₀.today)
  let x : Ix := ⟨c₀, hr.filterMap id ++ hu.filterMap id, relOk, unrOk, bb⟩
  let ds := Ix.decideAllQ H x (idSeen (foreignOf k os bb)) (x.orderQ bb)
  let rl := x.releasedQ ds
  let ul := x.unresolvedQ ds
  let wr ← writes H false x.hs a.relCount rl
  let wu ← writes H true x.hs a.unrCount ul
  let head : Head := ⟨bumpIf relOk c₀.today a.relAsOf, bumpIf unrOk c₀.today a.unrAsOf,
    a.relCount + rl.length, a.unrCount + ul.length,
    hashPf H (upsertPf 513 0 w.relPf wr), hashPf H (upsertPf 513 0 w.unrPf wu)⟩
  let dg ← digestV2 H head
  let added := (rl ++ ul).map (·.id)
  let free := (pendingOf k os).filter fun i =>
    !added.contains i && x.cnt false [4, i] == 0 && x.cnt true [4, i] == 0
  let pays := (ds.map (·.line.pay)).eraseDups.map fun p =>
    (p, x.payOutcomeQ ds p, ((ds.filter (·.line.pay == p)).map (·.line.cents)).sum)
  pure ⟨ds, (rl, ul), free, head, dg, pays⟩

/-- Spec twin of `OutV2.pays`. `ready` (Rules/Spec.lean:487) drops whole payments, so every pay here is complete. -/
def paysOf (c : Ctx) (ds : List Decision) : List (Nat × Outcome × Nat) :=
  (ds.map (·.line.pay)).eraseDups.map fun p =>
    (p, payOutcome c ds p, ((ds.filter (·.line.pay == p)).map (·.line.cents)).sum)

/-- H-a: every input the courier supplies: anchor preimage, probe paths, both proofs, every first-K run. -/
def witnessInputs (H : Bytes → Bytes) (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (w : Witness) :
    List Bytes :=
  let (qr, qu) := probeKeys c₀ k os (ready k os b)
  (headIn w.anchor).toList ++ (qr ++ qu).filterMap (fun q => (keyBytes q).map (KD ++ ·)) ++
    pfInputs H w.relPf ++ pfInputs H w.unrPf ++
    w.lists.flatMap fun (_, _, n, ys, fp) => firstKInputs H n ys fp

/-- The true hits of a line: per key, per set, (path, rows under the key, posting root). -/
def trueHits (H : Bytes → Bytes) (rel unr : Snapshot Line) (l : Line) : List (Bool × Bytes × Nat × Bytes) :=
  (keys l).flatMap fun q => [false, true].filterMap fun u => (keyBytes q).map fun kb =>
    let es := (postings u (if u then unr.entries else rel.entries) q).getD []
    (u, pathOf H kb, es.length, listRoot H es)

/-- RESTATED: + `o.pays = paysOf`. -/
theorem decideIdx_refines (H : Bytes → Bytes) (hH : HashLen H) (c₀ : Ctx) (k : Nat) (os : List Owner)
    (b : List Line) (rel unr : Snapshot Line) (hi : Inv rel unr) (h : Head) (ha : headOf H rel unr = some h)
    (d : Bytes) (hd : digestV2 H h = some d) (w : Witness) (o : OutV2) (hr : decideIdx H c₀ k os b d w = some o) :
    (let c := carried c₀ rel unr
     let r := decideRegT c k os b
     o.decisions.map (fun d => (d.line, d.outcome, d.reasons)) =
       r.decisions.map (fun d => (d.line, d.outcome, d.reasons)) ∧
     o.decisions.map (·.firstK) = r.decisions.map (·.counterparts.take K) ∧
     o.decisions.map (·.hits) = r.decisions.map (trueHits H rel unr ·.line) ∧
     o.fresh = batchFresh c r ∧ o.pays = paysOf c r.decisions ∧
     headOf H r.released r.unresolved = some o.head ∧ digestV2 H o.head = some o.digest) ∨
    Collision H (witnessInputs H c₀ k os b w) (stateInputs H rel unr) := sorry

/-- H5: WAIT ids are probed as id keys in both trees; does not reuse `hp` (DecideLayer.lean:111). -/
theorem freeIdx_refines (H : Bytes → Bytes) (hH : HashLen H) (c₀ : Ctx) (k : Nat) (os : List Owner)
    (b : List Line) (rel unr : Snapshot Line) (hi : Inv rel unr) (h : Head) (ha : headOf H rel unr = some h)
    (d : Bytes) (hd : digestV2 H h = some d) (w : Witness) (o : OutV2) (hr : decideIdx H c₀ k os b d w = some o) :
    (let r := decideRegT (carried c₀ rel unr) k os b
     o.free = settleFree r.released.entries r.unresolved.entries (pendingOf k os)) ∨
    Collision H (witnessInputs H c₀ k os b w) (stateInputs H rel unr) := sorry

/-- The honest witness. -/
def witnessOf (H : Bytes → Bytes) (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line)
    (rel unr : Snapshot Line) (h : Head) : Witness :=
  let (qr, qu) := probeKeys c₀ k os (ready k os b)
  let paths := fun (qs : List Key) => qs.filterMap fun q => (keyBytes q).map (pathOf H)
  let lists := fun (u : Bool) (s : List Line) (qs : List Key) => qs.filterMap fun q => do
    let kb ← keyBytes q
    guard (q.head? ≠ some 7)
    let es ← postings u s q
    guard (es ≠ [])
    pure (u, pathOf H kb, es.length, es.take K, firstKPf H PD 64 (min K es.length) (es.map (leafHash H PD)))
  ⟨h, prune H 513 0 ((setMap H false rel.entries).getD []) (paths qr),
      prune H 513 0 ((setMap H true unr.entries).getD []) (paths qu),
      lists false rel.entries qr ++ lists true unr.entries qu⟩

/-- Liveness: an honest witness is refused only on a named collision or an unrepresentable next state. -/
theorem decideIdx_complete (H : Bytes → Bytes) (hH : HashLen H) (c₀ : Ctx) (k : Nat) (os : List Owner)
    (b : List Line) (rel unr : Snapshot Line) (hi : Inv rel unr) (h : Head) (ha : headOf H rel unr = some h)
    (d : Bytes) (hd : digestV2 H h = some d)
    (hb : (ready k os b).all (fun l => (keyBytes (rowKey l)).isSome) = true)
    (hn : (let r := decideRegT (carried c₀ rel unr) k os b; (headOf H r.released r.unresolved).bind headIn).isSome) :
    (decideIdx H c₀ k os b d (witnessOf H c₀ k os b rel unr h)).isSome ∨
      Collision H (witnessInputs H c₀ k os b (witnessOf H c₀ k os b rel unr h)) (stateInputs H rel unr) := sorry

/-! ## 8. r4: time, order independence, the signed-package log, permit, rows, custody, crash model, chain -/

/-! ### 8a. Time (KEPT from r3 §8a; no Ticket structure: the clock reading is `secs : Nat`) -/

/-- Civil date CCYYMMDD of a Unix second count (Hinnant civil_from_days). Unix seconds cannot name 23:59:60. -/
def civilOf (secs : Nat) : Nat :=
  let z := secs / 86400 + 719468
  let era := z / 146097
  let doe := z - era * 146097
  let yoe := (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
  let y := yoe + era * 400
  let doy := doe - (365 * yoe + yoe / 4 - yoe / 100)
  let mp := (5 * doy + 2) / 153
  let d := doy - (153 * mp + 2) / 5 + 1
  let m := if mp < 10 then mp + 3 else mp - 9
  (if m ≤ 2 then y + 1 else y) * 10000 + m * 100 + d

/-- Fix 7: the state's UTC offsets as (from-instant, offset seconds), pinned with the engine (the G5 pin);
    changed only by a re-pin. -/
abbrev OffsetTable := List (Nat × Int)

def offsetAt (tbl : OffsetTable) (s : Nat) : Int := (((tbl.filter (·.1 ≤ s)).getLast?).map (·.2)).getD 0

/-- `today` of an instant: the civil date at the state's local time. Integer arithmetic only. -/
def localDay (tbl : OffsetTable) (s : Nat) : Nat := civilOf ((s : Int) + offsetAt tbl s).toNat

def maxOff : Int := 14 * 3600

/-- Starts at 0, strictly ascending, |offset| ≤ 14 h, and no change moves the local day back. -/
def tableOk (tbl : OffsetTable) : Bool :=
  (tbl.head?.map (·.1)) == some 0 &&
  tbl.all (fun e => decide (-maxOff ≤ e.2 ∧ e.2 ≤ maxOff)) &&
  (tbl.zip tbl.tail).all fun (a, b) => decide (a.1 < b.1) &&
    decide (civilOf ((b.1 : Int) - 1 + a.2).toNat ≤ civilOf ((b.1 : Int) + b.2).toNat)

theorem localDay_valid (tbl : OffsetTable) (hT : tableOk tbl = true) (s : Nat) (hs : s + 50400 < 253402300800) :
    validDate (localDay tbl s) = true := sorry

theorem localDay_mono (tbl : OffsetTable) (hT : tableOk tbl = true) (s s' : Nat) (h : s ≤ s') :
    localDay tbl s ≤ localDay tbl s' := sorry

/-- Custody signs only within `eps` seconds of its own clock reading `secs`; Lean decides on `localDay tbl secs`. -/
def eps : Nat := 120

/-! ### 8b. Order independence (fix 6) -/

/-- RESTATED (fix 6; moved here from §5b because it names `paysOf`): a reordered base gives the same
    decisions, next sets equal up to order with equal counts and dates, and the same pays. -/
theorem decideRegT_perm (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (rel unr rel' unr' : Snapshot Line)
    (hr : rel.entries.Perm rel'.entries) (hu : unr.entries.Perm unr'.entries)
    (hc : rel.count = rel'.count ∧ unr.count = unr'.count ∧ rel.asOf = rel'.asOf ∧ unr.asOf = unr'.asOf) :
    let r := decideRegT (carried c₀ rel unr) k os b
    let r' := decideRegT (carried c₀ rel' unr') k os b
    r.decisions.map (fun d => (d.line, d.outcome, d.reasons)) =
      r'.decisions.map (fun d => (d.line, d.outcome, d.reasons)) ∧
    r.released.entries.Perm r'.released.entries ∧ r.unresolved.entries.Perm r'.unresolved.entries ∧
    r.released.count = r'.released.count ∧ r.unresolved.count = r'.unresolved.count ∧
    r.released.asOf = r'.released.asOf ∧ r.unresolved.asOf = r'.unresolved.asOf ∧
    paysOf (carried c₀ rel unr) r.decisions = paysOf (carried c₀ rel' unr') r'.decisions := sorry

/-- KEPT from r3: the dated spec along batches: per batch, (line, outcome, reasons) and pays. -/
def runT (k : Nat) (g : Snapshot Line × Snapshot Line) :
    List Batch → List (List (Line × Outcome × List Reason) × List (Nat × Outcome × Nat))
  | [] => []
  | t :: ts =>
    let c := carried t.ctx g.1 g.2
    let r := decideRegT c k t.owners t.lines
    (r.decisions.map (fun d => (d.line, d.outcome, d.reasons)), paysOf c r.decisions) ::
      runT k (r.released, r.unresolved) ts

/-- NEW. `decideRegT_perm` by induction on the batches. -/
theorem runT_perm (k : Nat) (g g' : Snapshot Line × Snapshot Line)
    (hr : g.1.entries.Perm g'.1.entries) (hu : g.2.entries.Perm g'.2.entries)
    (hc : g.1.count = g'.1.count ∧ g.2.count = g'.2.count ∧ g.1.asOf = g'.1.asOf ∧ g.2.asOf = g'.2.asOf)
    (ts : List Batch) : runT k g ts = runT k g' ts := sorry

/-! ### 8c. The signed-package log (fixes 1, 8) -/

/-- One signed package: log index, previous log head (64 bytes), the signed checkpoint (header ‖ ML-DSA-87
    signature), its tokens, and the set rows Lean appended (so a lost database is rebuilt by replay). -/
structure Entry where
  idx : Nat
  prev : Bytes
  signed : Bytes
  tokens : List Bytes
  fresh : List Line × List Line
  deriving DecidableEq

def rowBytes (l : Line) : Option Bytes := ((Line.fields l).mapM fun (w, n) => be w n).map List.flatten

/-- Fix 8: digests are `digestBytes` = 64 (Spec.lean:24). Every variable part is length-prefixed; rows are
    fixed width (`Line.fields`). -/
def entryIn (e : Entry) : Option Bytes := do
  guard (e.prev.length = digestBytes)
  let i ← be 8 e.idx
  let ls ← be 4 e.signed.length
  let nt ← be 2 e.tokens.length
  let ts ← e.tokens.mapM fun t => do pure ((← be 4 t.length) ++ t)
  let r ← e.fresh.1.mapM rowBytes
  let u ← e.fresh.2.mapM rowBytes
  let nr ← be 8 r.length
  let nu ← be 8 u.length
  pure (dom2 "STATE-LOG" ++ i ++ e.prev ++ ls ++ e.signed ++ nt ++ ts.flatten ++ nr ++ r.flatten ++ nu ++ u.flatten)

def entryDigest (e : Entry) : Option Bytes := (entryIn e).map sha3

/-- The log head: `zeroDigest` for the empty log, else the last entry's digest. The r3 Mark is this value. -/
def logHead (log : List Entry) : Option Bytes :=
  match log.getLast? with
  | none => some zeroDigest
  | some e => entryDigest e

/-- Entry i has index i and names the head of the first i entries. -/
def logOk (log : List Entry) : Bool :=
  log.zipIdx.all fun (e, i) => e.idx == i && logHead (log.take i) == some e.prev

/-- A digest equal to `zeroDigest`: the only non-collision way two heads of different-length logs can meet. -/
def ZeroPre (H : Bytes → Bytes) (A : List Bytes) : Prop := ∃ x ∈ A, H x = zeroDigest

theorem entryIn_inj {e e' : Entry} {x : Bytes} (h : entryIn e = some x) (h' : entryIn e' = some x) : e = e' := sorry

/-- NEW. A head names its whole log. -/
theorem log_binds (hH : HashLen sha3) (log log' : List Entry) (hl : logOk log = true) (hl' : logOk log' = true)
    (hs : (logHead log).isSome) (he : logHead log = logHead log') :
    log = log' ∨ Collision sha3 (log.filterMap entryIn) (log'.filterMap entryIn) ∨
      ZeroPre sha3 ((log ++ log').filterMap entryIn) := sorry

/-! ### 8d. Permit and the base (fixes 1, 3, 5) -/

/-- The permit's base: a new shard's genesis day, or the v1 cutover (last v1 signed checkpoint and its sets). -/
inductive PermitBase
  | genesis (day : Nat)
  | v1 (header : Bytes) (rel unr : Snapshot Line)

/-- Written once at provisioning and stored as the off-machine log's genesis record. `ctrBase` is the TPM
    NV counter's value when the shard's counter was defined (TPM 2.0 starts a new counter at the TPM's highest). -/
structure Permit where
  tenant : Bytes
  shard : Nat
  ctrBase : Nat
  base : PermitBase

def redate (t : Nat) (g : Snapshot Line × Snapshot Line) : Snapshot Line × Snapshot Line :=
  ({ g.1 with asOf := t }, { g.2 with asOf := t })

def invB (rel unr : Snapshot Line) : Bool :=
  decide (((rel.entries ++ unr.entries).map (·.id)).Nodup) && rel.count == rel.entries.length &&
    unr.count == unr.entries.length

/-- Ids are unique (`invB`), so every order of the same set sorts to the same list: rebuild is deterministic. -/
def canon (s : Snapshot Line) : Snapshot Line := { s with entries := s.entries.mergeSort fun a b => a.id ≤ b.id }

/-- Fix 5: no clock input, so the v1 check (setsDigest over the whole v1 sets, then invB) runs at boot,
    before custody reads the clock. A refusal is the defined quarantine: no v2 signing; the shard stays on
    its v1 producer, alerted (body §5). -/
def permitBase (tbl : OffsetTable) (p : Permit) : Option (Snapshot Line × Snapshot Line) :=
  match p.base with
  | .genesis t => if validDate t then some (genesisSets t) else none
  | .v1 b r u => do
    let s ← storedOfAny sha3 b
    guard (s.checkpoint.tenantId = p.tenant ∧ s.checkpoint.shardId = p.shard)
    guard (setsDigest sha3 r u = some s.checkpoint.stateDigest)
    guard (invB r u = true)
    let m := localDay tbl s.checkpoint.createdAt
    guard (validDate m = true)
    pure (redate m (canon r, canon u))

/-- Fix 3: the base is a function of the log. Empty log: the permit's base (migration iff the permit is v1).
    Otherwise: the last entry's header. No version test. -/
def baseDigest (tbl : OffsetTable) (p : Permit) (log : List Entry) : Option Bytes :=
  match log.getLast? with
  | some e => (storedOfAny sha3 e.signed).map (·.checkpoint.stateDigest)
  | none => do
    let g ← permitBase tbl p
    let h ← headOf sha3 g.1 g.2
    digestV2 sha3 h

/-- The checkpoint the next one follows: the last log entry, else the permit's v1 header, else none. -/
def lastOf (p : Permit) (log : List Entry) : Option Bytes :=
  match log.getLast? with
  | some e => some e.signed
  | none => match p.base with
    | .v1 b _ _ => some b
    | .genesis _ => none

/-- KEPT from r3: the STATE/v1 collision `loadAdds_binds` (DecideLayer.lean:185-196) names. -/
def V1Collision (H : Bytes → Bytes) (a b r u : Snapshot Line) : Prop :=
  ∃ A B A' B', pinInput "RR/GATE/RELEASED/v1" 5 Line.fields a = some A ∧
    pinInput "RR/GATE/UNRESOLVED/v1" 6 Line.fields b = some B ∧
    pinInput "RR/GATE/RELEASED/v1" 5 Line.fields r = some A' ∧
    pinInput "RR/GATE/UNRESOLVED/v1" 6 Line.fields u = some B' ∧
    ∃ x y, x ≠ y ∧ H x = H y ∧ ((x, y) = (A, A') ∨ (x, y) = (B, B') ∨
      (x, y) = (Gate.domain "STATE" ++ H A ++ H B, Gate.domain "STATE" ++ H A' ++ H B'))

theorem invB_iff (rel unr : Snapshot Line) : invB rel unr = true ↔ Inv rel unr := sorry

/-- NEW (fix 5): every reachable v1 state passes `invB`, so the quarantine is unreachable without a collision.
    Route: Rules/Shards.lean:120,132 and `inv_step` (the dates do not enter `Inv`). -/
theorem v1_reach_inv (k : Nat) (ts : List Batch) :
    Inv (shardSets k (genesisSets 0) ts).1 (shardSets k (genesisSets 0) ts).2 := sorry

/-- RESTATED (fixes 2, 5): the cutover sets are the true v1 sets up to order, dated by the v1 header, and every
    later batch decides and pays as on the true sets; else a v1 collision. -/
theorem migrate_binds (hH : HashLen sha3) (tbl : OffsetTable) (p : Permit) (b : Bytes) (r' u' : Snapshot Line)
    (hp : p.base = .v1 b r' u') (g : Snapshot Line × Snapshot Line) (hg : permitBase tbl p = some g)
    (r u : Snapshot Line) (hi : Inv r u)
    (hd : ∃ s, storedOfAny sha3 b = some s ∧ setsDigest sha3 r u = some s.checkpoint.stateDigest)
    (k : Nat) (ts : List Batch) :
    (∃ m, g.1.entries.Perm r.entries ∧ g.2.entries.Perm u.entries ∧ Inv g.1 g.2 ∧
       runT k g ts = runT k (redate m (r, u)) ts) ∨ V1Collision sha3 r' u' r u := sorry

/-! ### 8e. Requests and lines (fix 4): Lean decodes `Request.lines` itself -/

/-- `WireLine` (Spec.lean:271) with every field `pLine` skips. -/
structure WireLineFull where
  flow : WireFlow
  lineId : Bytes
  memberKey : Bytes
  payeeRef : Bytes
  rendering : Bytes
  date : Nat
  proc : Bytes
  units : Nat
  cents : Nat

def pLineFull : P WireLineFull := do
  let flow ← tag flows
  let lineId ← ident
  let memberKey ← take memberKeyBytes
  let payeeRef ← ident
  let rendering ← ident
  let date ← nat 4
  let proc ← ident
  let units ← nat 4
  let cents ← nat 8
  pure { flow, lineId, memberKey, payeeRef, rendering, date, proc, units, cents }

/-- The widened parser accepts exactly what `pLine` (Spec.lean:277-287) accepts. -/
theorem pLineFull_agrees (x : Bytes) :
    parse pLine maxLineBytes x =
      (parse pLineFull maxLineBytes x).map fun l => ⟨l.flow, l.memberKey, l.payeeRef, l.cents⟩ := sorry

/-- The rules' identifier numbers (Rules/Spec.lean:87-104): a 0x01 byte, then the bytes, big-endian. -/
def idNat (x : Bytes) : Nat := beNat (1 :: x)

/-- `pay` is the program id and the payment id, each u16-length. -/
def payNat (program pay : Bytes) : Nat := idNat (identField program ++ identField pay)

def flowOf : WireFlow → Option Flow
  | .FFS_CYCLE => some .FFS_CYCLE
  | .FFS_CLAIM => some .FFS_CLAIM
  | .CAP_820 => some .CAP_820
  | .SDP => none
  | .PLAN_PAY => none

def lineOf (pay : Nat) (l : WireLineFull) : Option Line :=
  (flowOf l.flow).map fun f =>
    ⟨idNat l.lineId, pay, f, idNat l.memberKey, idNat l.payeeRef, idNat l.rendering, l.date, idNat l.proc,
      l.units, l.cents⟩

def linesOf (r : Request) : Option (List Line) :=
  r.lines.mapM fun x => (parse pLineFull maxLineBytes x).bind (lineOf (payNat r.programId r.paymentId))

/-- One tenant, one program, each payment once. -/
def reqsOf (tenant program : Bytes) (reqs : List Bytes) : Option (List Request) := do
  let rs ← reqs.mapM decodeRequest
  guard (rs.all fun r => r.tenantId == tenant && r.programId == program)
  guard (rs.map (·.paymentId)).Nodup
  pure rs

/-- The lines Lean decides: every line of every ruled request. -/
def batchLines (rs : List Request) : Option (List Line) :=
  ((rs.filter (·.flow.ruled)).mapM linesOf).map List.flatten

theorem payNat_fits (program pay : Bytes) (hp : identOk program = true) (hq : identOk pay = true) :
    payNat program pay < 256 ^ payWidth := sorry

/-- A decoded line always has a row key, so `decideIdx`'s guard (§7) never refuses a decoded batch. -/
theorem lineOf_fits (r : Request) (hr : ∃ x, decodeRequest x = some r) (ls : List Line) (h : linesOf r = some ls) :
    ls.all (fun l => (keyBytes (rowKey l)).isSome) = true := sorry

/-! ### 8f. PayRow and tokens (fix 4): every money field, one permutation check -/

structure PayRow where
  pay : Nat
  outcome : WireOutcome
  cents : Nat
  flow : WireFlow
  member : Bytes
  payee : Bytes
  period : Bytes
  linesRoot : Bytes
  reasons : List Bytes
  commit : Bytes
  deriving DecidableEq

def reasonName : Reason → String
  | .ALREADY_DECIDED => "ALREADY_DECIDED" | .CAP_MEMBER_MONTH_DUPLICATE => "CAP_MEMBER_MONTH_DUPLICATE"
  | .COLLIDES_WITH_UNRESOLVED_NEAR => "COLLIDES_WITH_UNRESOLVED_NEAR"
  | .DUPLICATE_OF_UNRESOLVED => "DUPLICATE_OF_UNRESOLVED" | .FFS_DUPLICATE_LINE => "FFS_DUPLICATE_LINE"
  | .FFS_DUPLICATE_UNVERIFIED => "FFS_DUPLICATE_UNVERIFIED" | .FFS_NEAR_DUPLICATE => "FFS_NEAR_DUPLICATE"
  | .MEMBER_DECEASED => "MEMBER_DECEASED" | .MEMBER_DECEASED_UNVERIFIED => "MEMBER_DECEASED_UNVERIFIED"
  | .MEMBER_NOT_ENROLLED => "MEMBER_NOT_ENROLLED"
  | .MEMBER_NOT_ENROLLED_UNVERIFIED => "MEMBER_NOT_ENROLLED_UNVERIFIED"
  | .PROVIDER_DECEASED => "PROVIDER_DECEASED" | .PROVIDER_DECEASED_UNVERIFIED => "PROVIDER_DECEASED_UNVERIFIED"
  | .PROVIDER_EXCLUDED => "PROVIDER_EXCLUDED" | .PROVIDER_EXCLUDED_UNVERIFIED => "PROVIDER_EXCLUDED_UNVERIFIED"
  | .SERVICE_DATE_FUTURE => "SERVICE_DATE_FUTURE" | .SERVICE_DATE_INVALID => "SERVICE_DATE_INVALID"
  | .STALE_DMF => "STALE_DMF" | .STALE_ENROLLMENT => "STALE_ENROLLMENT" | .STALE_EXCLUSION => "STALE_EXCLUSION"
  | .STALE_PROVIDER_DEATH => "STALE_PROVIDER_DEATH" | .STALE_RELEASED => "STALE_RELEASED"
  | .STALE_UNRESOLVED => "STALE_UNRESOLVED"

def reasonCode (r : Reason) : Bytes := (reasonName r).toUTF8.toList

/-- Rows are built from `reasons` filtered, so the leaf's ascending check (Spec.lean:472) always holds. -/
theorem reasonCode_ascending (xs : List Reason) (h : xs.Sublist reasons) : ascending (xs.map reasonCode) = true := sorry

def wireOf : Outcome → WireOutcome
  | .ALLOW => .ALLOW
  | .HOLD => .HOLD
  | .HUMAN_REVIEW => .HUMAN_REVIEW

/-- Constants of the custody exe, pinned with it (G5): never read from a request or a courier. -/
structure Consts where
  grant : Bytes
  rule : Bytes
  engine : Bytes
  authority : Authority

def optPin {α : Type} (name : String) (kind : Nat) (fields : α → List (Nat × Nat)) :
    Option (Snapshot α) → Option Bytes
  | none => some [0]
  | some s => (pinInput name kind fields s).map fun x => 1 :: sha3 x

/-- Everything a decision read besides the request: the four external snapshots, the redo list, and the base. -/
def readSetOf (c₀ : Ctx) (base : Bytes) : Option Bytes := do
  let a ← optPin "RR/GATE/READ-DMF/v2" 1 Death.fields c₀.dmf
  let b ← optPin "RR/GATE/READ-PROVIDER-DEATH/v2" 2 Death.fields c₀.providerDeaths
  let e ← optPin "RR/GATE/READ-EXCLUSION/v2" 3 Exclusion.fields c₀.exclusions
  let n ← optPin "RR/GATE/READ-ENROLLMENT/v2" 4 Span.fields c₀.enrollment
  let r ← be 4 c₀.redo.length
  let rs ← c₀.redo.mapM (be payWidth)
  pure (sha3 (dom2 "READ-SET" ++ a ++ b ++ e ++ n ++ r ++ rs.flatten ++ base))

/-- The row of one request. Unruled flows: HUMAN_REVIEW, the request's amount, no reasons. Ruled: Lean's pay
    (outcome, Σ line cents) and the reasons of its lines; a ruled pay Lean did not decide (WAIT) has no row. -/
def rowOf (pays : List (Nat × Outcome × Nat)) (ds : List (Line × Outcome × List Reason)) (rset : Bytes)
    (x : Bytes × Request) : Option PayRow :=
  let (raw, r) := x
  let row : PayRow := ⟨payNat r.programId r.paymentId, .HUMAN_REVIEW, r.amountCents, r.flow, r.memberKey,
    r.payeeRef, r.period, linesRoot sha3 r.lines, [], inputCommitment sha3 raw rset⟩
  if !r.flow.ruled then some row else do
    let (_, o, cents) ← pays.find? (·.1 == row.pay)
    let rs := (ds.filter (·.1.pay == row.pay)).flatMap (·.2.2)
    pure { row with outcome := wireOf o, cents, reasons := (reasons.filter rs.contains).map reasonCode }

/-- A token's row; decision time, issue time and the exe constants must be custody's. -/
def tokRow (c : Consts) (secs : Nat) (t : Bytes) : Option PayRow := do
  let k ← decodeToken t
  let l := k.leaf
  guard (l.decidedAt = secs ∧ l.issuedAt = secs ∧ l.grantId = c.grant ∧ l.ruleVersion = c.rule ∧
    l.engineRelease = c.engine ∧ l.authority = c.authority)
  pure ⟨payNat l.programId l.paymentId, l.outcome, l.amountCents, l.flow, l.memberKey, l.payeeRef, l.period,
    l.linesRoot, l.reasonCodes, l.inputCommitment⟩

/-- KEPT shape (perm + length), RESTATED rows (fix 4). -/
def tokensOk (c : Consts) (secs : Nat) (rows : List PayRow) (tokens : List Bytes) : Bool :=
  tokens.length == rows.length && (tokens.filterMap (tokRow c secs)).isPerm rows

/-! ### 8g. Certificates (fix 9) and custody (fix 2) -/

/-- RESTATED (fix 9): `lastCert` must accept `last` (acceptsAny, Verify.lean:39); within one epoch it is the same
    bytes as `cert`; across epochs both name the same tenant and shard count. -/
def certsOk (rootPk cert lastCert : Bytes) (last : Option Bytes) (n : Stored) : Bool :=
  match last with
  | none => true
  | some b =>
    match decodeKeyCert cert, decodeKeyCert lastCert, storedOfAny sha3 b with
    | some e, some e', some p => acceptsAny rootPk lastCert b && e.tenantId == e'.tenantId &&
        e.shardCount == e'.shardCount && (p.checkpoint.epoch != n.checkpoint.epoch || cert == lastCert)
    | _, _, _ => false

/-- Fix 2: custody computes the base and the decision itself; the courier supplies only requests, external
    snapshots, owners and the witness, each re-checked. -/
def plan (tbl : OffsetTable) (p : Permit) (log : List Entry) (secs : Nat) (program : Bytes) (reqs : List Bytes)
    (c₀ : Ctx) (os : List Owner) (w : Witness) : Option (OutV2 × List PayRow) := do
  let rs ← reqsOf p.tenant program reqs
  let b ← batchLines rs
  let d ← baseDigest tbl p log
  let o ← decideIdx sha3 { c₀ with today := localDay tbl secs } p.shard os b d w
  let rset ← readSetOf c₀ d
  pure (o, (reqs.zip rs).filterMap (rowOf o.pays (o.decisions.map fun x => (x.line, x.outcome, x.reasons)) rset))

/-- Run by the Lean exe inside custody on the in-memory signature; a refusal wipes it. `ctr` is the TPM
    reading minus `p.ctrBase`, read independently of the log. `new` is header ‖ signature. Custody keeps
    `logOk log` from boot (`reconcile`), so it is a hypothesis here, not a re-check. -/
def custodyOk (tbl : OffsetTable) (c : Consts) (rootPk cert lastCert : Bytes) (p : Permit) (log : List Entry)
    (ctr secs now : Nat) (program : Bytes) (reqs : List Bytes) (c₀ : Ctx) (os : List Owner) (w : Witness)
    (new : Bytes) (tokens : List Bytes) : Option Entry := do
  let (o, rows) ← plan tbl p log secs program reqs c₀ os w
  let last := lastOf p log
  let n ← storedOfAny sha3 new
  let prev ← logHead log
  guard (ctr = log.length)
  guard (publishOkAny rootPk cert last new tokens = true ∧ certsOk rootPk cert lastCert last n = true)
  guard (n.checkpoint.tenantId = p.tenant ∧ n.checkpoint.shardId = p.shard ∧ n.checkpoint.programId = program)
  guard (n.checkpoint.stateDigest = o.digest ∧ tokensOk c secs rows tokens = true)
  guard (n.checkpoint.createdAt = secs ∧ secs ≤ now ∧ now ≤ secs + eps)
  guard ((last.bind (storedOfAny sha3)).all fun q => decide (q.checkpoint.createdAt ≤ secs))
  pure ⟨log.length, prev, new, tokens, o.fresh⟩

/-- RESTATED `mark_advances`, log terms: an accepted package is the next entry at index = length. -/
theorem entry_appends (tbl : OffsetTable) (c : Consts) (rootPk cert lastCert : Bytes) (p : Permit)
    (log : List Entry) (hl : logOk log = true) (ctr secs now : Nat) (program : Bytes) (reqs : List Bytes) (c₀ : Ctx)
    (os : List Owner) (w : Witness) (new : Bytes) (tokens : List Bytes) (e : Entry)
    (h : custodyOk tbl c rootPk cert lastCert p log ctr secs now program reqs c₀ os w new tokens = some e)
    (he : (entryIn e).isSome) :
    e.idx = log.length ∧ logHead log = some e.prev ∧ logOk (log ++ [e]) = true := sorry

theorem head_advances (hH : HashLen sha3) (log : List Entry) (e : Entry) (hl : logOk (log ++ [e]) = true)
    (he : (entryIn e).isSome) :
    logHead (log ++ [e]) ≠ logHead log ∨ Collision sha3 ((log ++ [e]).filterMap entryIn) (log.filterMap entryIn) ∨
      ZeroPre sha3 ((log ++ [e]).filterMap entryIn) := sorry

/-- NEW (replaces publishV2_binds and anchor_chain): on a true base, the signed state digest is the true next
    state's, and the tokens are the true rows up to order; else a named collision. -/
theorem custody_binds (hH : HashLen sha3) (tbl : OffsetTable) (c : Consts) (rootPk cert lastCert : Bytes)
    (p : Permit) (log : List Entry) (ctr secs now : Nat) (program : Bytes) (reqs : List Bytes) (c₀ : Ctx)
    (os : List Owner) (w : Witness) (new : Bytes) (tokens : List Bytes) (e : Entry)
    (h : custodyOk tbl c rootPk cert lastCert p log ctr secs now program reqs c₀ os w new tokens = some e)
    (rel unr : Snapshot Line) (hi : Inv rel unr)
    (hb : baseDigest tbl p log = (headOf sha3 rel unr).bind (digestV2 sha3)) :
    ∃ rs b d rset n, reqsOf p.tenant program reqs = some rs ∧ batchLines rs = some b ∧
      baseDigest tbl p log = some d ∧ readSetOf c₀ d = some rset ∧ storedOfAny sha3 new = some n ∧
      ((let cc := carried { c₀ with today := localDay tbl secs } rel unr
        let r := decideRegT cc p.shard os b
        (∃ hd, headOf sha3 r.released r.unresolved = some hd ∧ digestV2 sha3 hd = some n.checkpoint.stateDigest) ∧
        (tokens.filterMap (tokRow c secs)).Perm ((reqs.zip rs).filterMap
          (rowOf (paysOf cc r.decisions) (r.decisions.map fun x => (x.line, x.outcome, x.reasons)) rset)) ∧
        tokens.length = ((reqs.zip rs).filterMap
          (rowOf (paysOf cc r.decisions) (r.decisions.map fun x => (x.line, x.outcome, x.reasons)) rset)).length ∧
        e.fresh = batchFresh cc r) ∨
       Collision sha3 (witnessInputs sha3 { c₀ with today := localDay tbl secs } p.shard os b w)
         (stateInputs sha3 rel unr)) := sorry

/-! ### 8h. Crash model (fixes 1, 7): the off-machine CAS store is the commit point -/

/-- Durable state: local log copy, off-machine CAS store, TPM counter (minus `ctrBase`), and every package
    that ever left custody (conservatively: at the CAS, before any release). -/
structure Cust where
  log : List Entry
  off : List Entry
  ctr : Nat
  out : List Entry

inductive Boot | ok | finishCounter | behind | offBehind | stop | waitOff
  deriving DecidableEq

/-- Boot decision from the local log, the off store (none: unreachable) and the counter. -/
def reconcile (log : List Entry) (off : Option (List Entry)) (ctr : Nat) : Boot :=
  match off with
  | none => .waitOff
  | some o =>
    if !(logOk o && logOk log) then .stop
    else if log == o then (if ctr == o.length then .ok else if ctr < o.length then .finishCounter else .stop)
    else if log.isPrefixOf o && decide (ctr ≤ o.length) then .behind
    else if o.isPrefixOf log && decide (ctr ≤ log.length) then .offBehind
    else .stop

/-- Custody steps. `sign` is the CAS: it succeeds only at index = off length on head = prev; a failed CAS or a
    crash before it drops the in-memory signature. Crashes are the interleavings of these steps. -/
inductive Step : Cust → Cust → Prop
  | sign (s : Cust) (e : Entry) (ho : reconcile s.log (some s.off) s.ctr = .ok) (hc : s.off.length = e.idx)
      (hp : logHead s.off = some e.prev) (hd : (entryIn e).isSome) :
      Step s { s with off := s.off ++ [e], out := s.out ++ [e] }
  | pull (s : Cust) (e : Entry) (h : s.off[s.log.length]? = some e) : Step s { s with log := s.log ++ [e] }
  | bump (s : Cust) : Step s { s with ctr := max s.ctr s.log.length }
  | release (s : Cust) (e : Entry) (h : e ∈ s.log) : Step s { s with out := s.out ++ [e] }
  | restore (s : Cust) (j : Nat) : Step s { s with log := s.log.take j }

inductive Reach : Cust → Prop
  | init : Reach ⟨[], [], 0, []⟩
  | step {s t : Cust} : Reach s → Step s t → Reach t

theorem reach_inv (s : Cust) (h : Reach s) :
    s.log <+: s.off ∧ s.ctr ≤ s.off.length ∧ logOk s.off = true ∧ ∀ e ∈ s.out, e ∈ s.off := sorry

/-- Fix 7: at most one signed package per log index, across crashes, re-releases and restores. -/
theorem never_twice (s : Cust) (h : Reach s) (e e' : Entry) (he : e ∈ s.out) (he' : e' ∈ s.out)
    (hi : e.idx = e'.idx) : e = e' := sorry

theorem reconcile_ok (log o : List Entry) (ctr : Nat) (h : reconcile log (some o) ctr = .ok) :
    log = o ∧ ctr = o.length := sorry

/-- Every crash point boots to a defined action. -/
theorem no_wedge (s : Cust) (h : Reach s) : reconcile s.log (some s.off) s.ctr ≠ .stop := sorry

/-- A restored or lost local database resumes by pulling the off log; it never signs at an old index. -/
theorem restore_resumes (s : Cust) (h : Reach s) (j : Nat) :
    reconcile (s.log.take j) (some s.off) s.ctr = .ok ∨ reconcile (s.log.take j) (some s.off) s.ctr = .finishCounter ∨
      reconcile (s.log.take j) (some s.off) s.ctr = .behind := sorry

/-- The counter is not tautological: an off store rolled back below it never boots `ok`, and with the local log
    also short it stops. -/
theorem rollback_detected (log o : List Entry) (ctr : Nat) (h : o.length < ctr) :
    reconcile log (some o) ctr ≠ .ok ∧ (log.length < ctr → reconcile log (some o) ctr = .stop) := sorry

/-! ### 8i. Chain (fix 7): the counter is an input per step; the stateDigest conclusion is kept -/

structure SignedStep where
  program : Bytes
  reqs : List Bytes
  ctx : Ctx
  owners : List Owner
  secs : Nat
  now : Nat
  ctr : Nat
  witness : Witness
  cert : Bytes

def logRunOk (tbl : OffsetTable) (c : Consts) (rootPk : Bytes) (p : Permit) :
    List Entry → Bytes → List (SignedStep × Entry) → Bool
  | _, _, [] => true
  | log, lastCert, (s, e) :: rest =>
    custodyOk tbl c rootPk s.cert lastCert p log s.ctr s.secs s.now s.program s.reqs s.ctx s.owners s.witness
        e.signed e.tokens == some e &&
      logRunOk tbl c rootPk p (log ++ [e]) s.cert rest

def stepBatch (tbl : OffsetTable) (p : Permit) (s : SignedStep) : Option Batch := do
  let rs ← reqsOf p.tenant s.program s.reqs
  let b ← batchLines rs
  pure ⟨{ s.ctx with today := localDay tbl s.secs }, s.owners, b⟩

/-- The spec rows per step: decideRegT on the true sets, the true base digest, the step's read set. -/
def runRows (tbl : OffsetTable) (p : Permit) :
    Snapshot Line × Snapshot Line → List SignedStep → Option (List (List PayRow))
  | _, [] => some []
  | g, s :: ss => do
    let rs ← reqsOf p.tenant s.program s.reqs
    let b ← batchLines rs
    let d ← (headOf sha3 g.1 g.2).bind (digestV2 sha3)
    let rset ← readSetOf s.ctx d
    let cc := carried { s.ctx with today := localDay tbl s.secs } g.1 g.2
    let r := decideRegT cc p.shard s.owners b
    let more ← runRows tbl p (r.released, r.unresolved) ss
    pure ((s.reqs.zip rs).filterMap
      (rowOf (paysOf cc r.decisions) (r.decisions.map fun x => (x.line, x.outcome, x.reasons)) rset) :: more)

/-- The sets a lost database is rebuilt to: the permit's base, then each entry's rows dated by its header. -/
def rebuild (tbl : OffsetTable) (g : Snapshot Line × Snapshot Line) (log : List Entry) : Snapshot Line × Snapshot Line :=
  replayT g (log.map fun e =>
    (((storedOfAny sha3 e.signed).map fun n => localDay tbl n.checkpoint.createdAt).getD 0, e.fresh))

/-- RESTATED: every signed step's tokens are the true rows up to order and its header's stateDigest is the
    true sets' after the first i+1 batches; else a named collision at some step. -/
theorem chain_sound (hH : HashLen sha3) (tbl : OffsetTable) (hT : tableOk tbl = true) (c : Consts)
    (rootPk cert₀ : Bytes) (p : Permit) (g : Snapshot Line × Snapshot Line) (hg : permitBase tbl p = some g)
    (hi : Inv g.1 g.2) (steps : List (SignedStep × Entry)) (hr : logRunOk tbl c rootPk p [] cert₀ steps = true) :
    ∃ bs, (steps.map (·.1)).mapM (stepBatch tbl p) = some bs ∧
      ((∃ rows, runRows tbl p g (steps.map (·.1)) = some rows ∧
         ∀ i (s : SignedStep) (e : Entry), steps[i]? = some (s, e) →
           (e.tokens.filterMap (tokRow c s.secs)).Perm (rows.getD i []) ∧
           ∃ n h, storedOfAny sha3 e.signed = some n ∧
             headOf sha3 (shardSetsT p.shard g (bs.take (i + 1))).1 (shardSetsT p.shard g (bs.take (i + 1))).2 =
               some h ∧ digestV2 sha3 h = some n.checkpoint.stateDigest) ∨
       ∃ (i : Nat) (s : SignedStep) (e : Entry) (b : Batch), steps[i]? = some (s, e) ∧ bs[i]? = some b ∧
         Collision sha3 (witnessInputs sha3 b.ctx p.shard s.owners b.lines s.witness)
           (stateInputs sha3 (shardSetsT p.shard g (bs.take i)).1 (shardSetsT p.shard g (bs.take i)).2)) := sorry

/-- NEW: replay of the log alone (permit + entries) gives the chain's true sets (uses `replayT_addsOfT`,
    `decideIdx_refines`, and `createdAt = secs`). -/
theorem rebuild_sound (hH : HashLen sha3) (tbl : OffsetTable) (hT : tableOk tbl = true) (c : Consts)
    (rootPk cert₀ : Bytes) (p : Permit) (g : Snapshot Line × Snapshot Line) (hg : permitBase tbl p = some g)
    (hi : Inv g.1 g.2) (steps : List (SignedStep × Entry)) (hr : logRunOk tbl c rootPk p [] cert₀ steps = true)
    (bs : List Batch) (hb : (steps.map (·.1)).mapM (stepBatch tbl p) = some bs) :
    rebuild tbl g (steps.map (·.2)) = shardSetsT p.shard g bs ∨
      ∃ (i : Nat) (s : SignedStep) (e : Entry) (b : Batch), steps[i]? = some (s, e) ∧ bs[i]? = some b ∧
        Collision sha3 (witnessInputs sha3 b.ctx p.shard s.owners b.lines s.witness)
          (stateInputs sha3 (shardSetsT p.shard g (bs.take i)).1 (shardSetsT p.shard g (bs.take i)).2) := sorry

end BlindLedger.Gate.StateV2
