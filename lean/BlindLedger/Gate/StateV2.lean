/-
STATE/v2 goals r5 (rr-core, 2026-10-06). Revises r4 against review-state-v2-r4-20261006.md (GO WITH FIXES, F1-F8 all
accepted) and the lead's H1-H3. §1-§8b unchanged from r4. §8c-§8i are new. Trunk refs as r4 (Spec.lean redecides :512,
Leaf :420-444, decodeCheckpoint2 :405; Producer.lean publishOkAny :66-73; Verify.lean acceptsAny :39;
Rules/ShardRun.lean holder :202, reserveRows :214, settleRows :219, chainHead :443).

One mechanism per bug class:
  all custody state = `fold` of ONE CAS-appended off-machine tenant log, O(n) once at boot (H3: no local log copy,
    no pull, no restore). Each entry carries its registry rows; the fold holds per shard the last signed, its base,
    the sign count per epoch and the latest leaf per payment;
  rollback = an epoch-keyed TPM counter per shard compared with the fold's sign count for the cert's epoch (H1);
  second ALLOW = the fold's `payStep` (new payment at revision 0; else trunk `redecides`, or an echo of the same
    revision that is not ALLOW). Owners come from the folded registry, never from the courier (F1, F2);
  activation = one `resume` entry checked by `activation` (genesis or the sealed v1 tip under acceptsAny), once
    per shard (F3, F5, F6).
Review r4: F1 registry in the fold, owners = `answer` on it, signed registryHead = fold rhead, entries record rows.
  F2 PayRow.revision, tokens expire at secs + maxTokenLifetime, redo only through payStep. F3 `seal` entry + resume
  from the sealed tip under acceptsAny. F4 custodyOk and the fold require a v2 checkpoint. F5 tableOk at
  activation (P.tbl is pinned, so once). F6 adversary steps (rollback, foreign write, TPM clear), resume only when
  not live. F7 CORRECTED CLAIM: the four snapshots and `redo` are courier inputs; they are bound into every token by
  readSetOf (inputCommitment), and redo can only act through payStep. F8 createdAt strictly increases per shard.
H1 RESTATED (deviation from the brief): a fence on live shards alone fails: roll the off store back below shard
  k's first resume and k is not live, so a foreign resume is accepted. The counter is keyed by epoch instead:
  the TPM holds (base, value) per shard; boot is `ok` iff value - base = the fold's sign count for the cert's
  epoch. ctrBase left the permit (it was writable by whoever writes the store). A new epoch needs a ceremony,
  which needs an undefined counter, which needs a TPM clear (`cleared`).
H2: `lost` is a ghost flag set when a rollback leaves some released signed with no copy in the store (by
  bytes, not index; a current-only form fails: rollback, TPM clear, new epoch, duplicate, foreign re-write).
  never_twice holds under ¬lost and concludes the two leaves sit in the same signed; honest runs never lose;
  a released signed missing now stops its shard at boot unless the TPM was cleared.
Release only after the counter bump: CAS, bump, release. foreignWrite may place only released signeds.
Residuals (not closed by Lean; each loud): total loss of the store followed by a genesis resume; a TPM clear +
  ceremony + rollback (payer check 10 and its fork check); an adversary who READS unreleased store entries inside
  the CAS-to-bump window and rolls back forks one position (payer fork check only); a HOLD is never re-decided and a
  v1-era payment is never redone on v2 (refused, loudly); `fresh` rows are not signed: a forged copy breaks only the
  witness (refusal), never a decision; evidenceRoot stays unchecked (trunk writes zero); never_twice is per shard,
  cross-shard identity is the registry + payer check 10; any foreign junk makes the fold none and every shard
  stops; a v1 signature past the seal is refused by the payer's follows check (v2 follows the tip).
Dropped (r4): Entry (old), logHead, logOk + its lemmas, ZeroPre, log_binds, PermitBase, permitBase, baseDigest,
  lastOf, plan, entry_appends, head_advances, r4 Cust/Boot/reconcile/Step/Reach, reach_inv, reconcile_ok,
  restore_resumes, rollback_detected, SignedStep, logRunOk, stepBatch, runRows. chain_sound keeps the stateDigest
  conclusion; the token rows per step are custody_binds applied to chain_sound's base.
Kept: invB_iff with proof, V1Collision, v1_reach_inv, §8e lines, PayRow (+revision), certsOk, readSetOf.
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

/-! ### 8c. Requests and lines (r4 fix 4): Lean decodes `Request.lines` itself -/

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


/-! ### 8d. PayRow and tokens: every money field, one permutation check (F2: revision bound) -/

structure PayRow where
  pay : Nat
  revision : Nat
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


/-- What the custody exe is pinned with: offset table, root key, tenant, constants. -/
structure Pins where
  tbl : OffsetTable
  rootPk : Bytes
  tenant : Bytes
  c : Consts

/-- The row of one request. Unruled flows: HUMAN_REVIEW, the request's amount, no reasons. Ruled: Lean's pay
    (outcome, Σ line cents) and the reasons of its lines; a ruled pay Lean did not decide (WAIT) has no row.
    `rev`: the revision custody assigns (from the fold, §8g). -/
def rowOf (rev : Nat → Nat) (pays : List (Nat × Outcome × Nat)) (ds : List (Line × Outcome × List Reason))
    (rset : Bytes) (x : Bytes × Request) : Option PayRow :=
  let (raw, r) := x
  let pay := payNat r.programId r.paymentId
  let row : PayRow := ⟨pay, rev pay, .HUMAN_REVIEW, r.amountCents, r.flow, r.memberKey, r.payeeRef, r.period,
    linesRoot sha3 r.lines, [], inputCommitment sha3 raw rset⟩
  if !r.flow.ruled then some row else do
    let (_, o, cents) ← pays.find? (·.1 == pay)
    let rs := (ds.filter (·.1.pay == pay)).flatMap (·.2.2)
    pure { row with outcome := wireOf o, cents, reasons := (reasons.filter rs.contains).map reasonCode }

/-- A token's row; decision time, issue time, expiry (F2) and the exe constants must be custody's. -/
def tokRow (c : Consts) (secs : Nat) (t : Bytes) : Option PayRow := do
  let k ← decodeToken t
  let l := k.leaf
  guard (l.decidedAt = secs ∧ l.issuedAt = secs ∧ l.expiresAt = secs + maxTokenLifetime ∧ l.grantId = c.grant ∧
    l.ruleVersion = c.rule ∧ l.engineRelease = c.engine ∧ l.authority = c.authority)
  pure ⟨payNat l.programId l.paymentId, l.revision, l.outcome, l.amountCents, l.flow, l.memberKey, l.payeeRef,
    l.period, l.linesRoot, l.reasonCodes, l.inputCommitment⟩

/-- KEPT shape (perm + length). -/
def tokensOk (c : Consts) (secs : Nat) (rows : List PayRow) (tokens : List Bytes) : Bool :=
  tokens.length == rows.length && (tokens.filterMap (tokRow c secs)).isPerm rows

/-! ### 8e. Activation (F3, F5, F6): genesis, or the sealed v1 tip -/

def redate (t : Nat) (g : Snapshot Line × Snapshot Line) : Snapshot Line × Snapshot Line :=
  ({ g.1 with asOf := t }, { g.2 with asOf := t })

def invB (rel unr : Snapshot Line) : Bool :=
  decide (((rel.entries ++ unr.entries).map (·.id)).Nodup) && rel.count == rel.entries.length &&
    unr.count == unr.entries.length

/-- Ids are unique (`invB`), so every order of the same set sorts to the same list: rebuild is deterministic. -/
def canon (s : Snapshot Line) : Snapshot Line := { s with entries := s.entries.mergeSort fun a b => a.id ≤ b.id }

/-- KEPT from r3: the STATE/v1 collision `loadAdds_binds` (DecideLayer.lean:185-196) names. -/
def V1Collision (H : Bytes → Bytes) (a b r u : Snapshot Line) : Prop :=
  ∃ A B A' B', pinInput "RR/GATE/RELEASED/v1" 5 Line.fields a = some A ∧
    pinInput "RR/GATE/UNRESOLVED/v1" 6 Line.fields b = some B ∧
    pinInput "RR/GATE/RELEASED/v1" 5 Line.fields r = some A' ∧
    pinInput "RR/GATE/UNRESOLVED/v1" 6 Line.fields u = some B' ∧
    ∃ x y, x ≠ y ∧ H x = H y ∧ ((x, y) = (A, A') ∨ (x, y) = (B, B') ∨
      (x, y) = (Gate.domain "STATE" ++ H A ++ H B, Gate.domain "STATE" ++ H A' ++ H B'))

theorem invB_iff (rel unr : Snapshot Line) : invB rel unr = true ↔ Inv rel unr := by
  simp [invB, Inv, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq, and_assoc]

/-- NEW (fix 5): every reachable v1 state passes `invB`, so the quarantine is unreachable without a collision.
    Route: Rules/Shards.lean:120,132 and `inv_step` (the dates do not enter `Inv`). -/
theorem v1_reach_inv (k : Nat) (ts : List Batch) :
    Inv (shardSets k (genesisSets 0) ts).1 (shardSets k (genesisSets 0) ts).2 := sorry


/-- A shard's activation sets. `tip = none`: genesis; `some (signed, cert)`: the sealed v1 tip and its cert. -/
structure Permit where
  tip : Option (Bytes × Bytes)
  rel : Snapshot Line
  unr : Snapshot Line
  deriving DecidableEq

/-- The activation base, checked once, before custody reads the clock. Genesis: empty sets on a valid day.
    v1: the tip verifies under its cert (F3), names this tenant and shard, its stateDigest is these sets', they
    pass invB, and they are dated by the tip. tableOk refuses activation on a bad table (F5). -/
def activation (P : Pins) (k : Nat) (p : Permit) : Option (Snapshot Line × Snapshot Line) := do
  guard (tableOk P.tbl = true)
  match p.tip with
  | none =>
    guard ((p.rel, p.unr) = genesisSets p.rel.asOf ∧ validDate p.rel.asOf = true)
    pure (p.rel, p.unr)
  | some (b, cert) =>
    let s ← storedOfAny sha3 b
    guard (acceptsAny P.rootPk cert b = true ∧ s.checkpoint.tenantId = P.tenant ∧ s.checkpoint.shardId = k)
    guard (setsDigest sha3 p.rel p.unr = some s.checkpoint.stateDigest ∧ invB p.rel p.unr = true)
    let m := localDay P.tbl s.checkpoint.createdAt
    guard (validDate m = true)
    pure (redate m (canon p.rel, canon p.unr))

/-- RESTATED (review: m pinned): the activation sets are the true v1 sets up to order, dated by the tip's
    createdAt, and every later batch decides and pays as on the true sets; else a v1 collision. -/
theorem migrate_binds (hH : HashLen sha3) (P : Pins) (k : Nat) (p : Permit) (b cert : Bytes)
    (hp : p.tip = some (b, cert)) (g : Snapshot Line × Snapshot Line) (hg : activation P k p = some g)
    (r u : Snapshot Line) (hi : Inv r u) (n : Stored) (hn : storedOfAny sha3 b = some n)
    (hd : setsDigest sha3 r u = some n.checkpoint.stateDigest) (ts : List Batch) :
    (g.1.entries.Perm r.entries ∧ g.2.entries.Perm u.entries ∧ Inv g.1 g.2 ∧
       runT k g ts = runT k (redate (localDay P.tbl n.checkpoint.createdAt) (r, u)) ts) ∨
      V1Collision sha3 p.rel p.unr r u := sorry

/-! ### 8f. The tenant log and its fold (H1-H3, F1, F2, F4, F8) -/

def rowBytes (l : Line) : Option Bytes := ((Line.fields l).mapM fun (w, n) => be w n).map List.flatten


/-- One log entry's payload. `sign`: key cert, signed checkpoint (header ‖ signature), its tokens, the fresh set
    rows. `resume`: a shard's activation permit. `seal`: a shard's last v1 signed (F3, F4). -/
inductive Body
  | sign (cert signed : Bytes) (tokens : List Bytes) (fresh : List Line × List Line)
  | resume (p : Permit)
  | seal (tip : Bytes)
  deriving DecidableEq

def Body.leaves : Body → List Leaf
  | .sign _ _ ts _ => ts.filterMap fun t => (decodeToken t).map (·.leaf)
  | _ => []

def Body.signed? : Body → Option Bytes
  | .sign _ s _ _ => some s
  | _ => none

/-- One CAS-appended entry of the off-machine tenant log: position, previous entry digest, shard, the registry
    rows it adds (newest first, F1), payload. -/
structure Entry where
  idx : Nat
  prev : Bytes
  shard : Nat
  reg : List Row
  body : Body
  deriving DecidableEq

def lenBytes (x : Bytes) : Option Bytes := (be 4 x.length).map (· ++ x)

def rowsBytes (ls : List Line) : Option Bytes := do
  let n ← be 8 ls.length
  let rs ← ls.mapM rowBytes
  pure (n ++ rs.flatten)

def setBytes (s : Snapshot Line) : Option Bytes := do
  let t ← be 4 s.asOf
  let c ← be 8 s.count
  let rs ← rowsBytes s.entries
  pure (t ++ c ++ rs)

def regBytes (r : Row) : Option Bytes := do
  let a ← be 1 r.1
  let b ← be 129 r.2.1
  let c ← be 4 r.2.2
  pure (a ++ b ++ c)

def tipBytes : Option (Bytes × Bytes) → Option Bytes
  | none => some [0]
  | some (s, c) => do
    let a ← lenBytes s
    let b ← lenBytes c
    pure (1 :: a ++ b)

def bodyBytes : Body → Option Bytes
  | .sign cert s ts f => do
    let a ← lenBytes cert
    let b ← lenBytes s
    let n ← be 2 ts.length
    let t ← ts.mapM lenBytes
    let x ← rowsBytes f.1
    let y ← rowsBytes f.2
    pure (0 :: a ++ b ++ n ++ t.flatten ++ x ++ y)
  | .resume p => do
    let t ← tipBytes p.tip
    let r ← setBytes p.rel
    let u ← setBytes p.unr
    pure (1 :: t ++ r ++ u)
  | .seal t => do
    let a ← lenBytes t
    pure (2 :: a)

def entryIn (e : Entry) : Option Bytes := do
  guard (e.prev.length = digestBytes)
  let i ← be 8 e.idx
  let k ← be 4 e.shard
  let n ← be 4 e.reg.length
  let rs ← e.reg.mapM regBytes
  let b ← bodyBytes e.body
  pure (dom2 "TENANT-LOG" ++ i ++ e.prev ++ k ++ n ++ rs.flatten ++ b)

def entryDigest (e : Entry) : Option Bytes := (entryIn e).map sha3

/-- FORMAT: the entry encoding is injective where defined. -/
theorem entryIn_inj (e e' : Entry) (x : Bytes) (h : entryIn e = some x) (h' : entryIn e' = some x) : e = e' :=
  sorry

/-- FORMAT: rows are newest first, so appending older rows extends the chain under the newer ones. -/
theorem chainHead_append (H : Bytes → Bytes) (g : Bytes) (d l : List Row) :
    chainHead H g (d ++ l) = chainHead H (chainHead H g l) d := by
  induction d with
  | nil => rfl
  | cons r d ih => obtain ⟨kd, i, s⟩ := r; simp [chainHead, ih]

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


/-- Per shard, what the fold knows: signs per cert epoch (H1), the sealed v1 tip, live, the last signed and
    its cert, the base digest custody decides on, the latest leaf per payment (F2). -/
structure Shard where
  own : Nat → Nat
  sealed : Option Bytes
  live : Bool
  last : Option (Bytes × Bytes)
  base : Bytes
  pays : List (Nat × Leaf)

def Shard.init : Shard := ⟨fun _ => 0, none, false, none, zeroDigest, []⟩

structure LogState where
  len : Nat
  head : Bytes
  reg : List Row
  rhead : Bytes
  shard : Nat → Shard

def LogState.init : LogState := ⟨0, zeroDigest, [], zeroDigest, fun _ => Shard.init⟩

def upd {α : Type} (f : Nat → α) (k : Nat) (x : α) : Nat → α := fun j => if j = k then x else f j

/-- The one rule for a second decision on a payment: a new payment starts at revision 0; a known one moves
    only by trunk `redecides`, or repeats its revision with an outcome that is not ALLOW. -/
def payStep (ps : List (Nat × Leaf)) (l : Leaf) : Option (List (Nat × Leaf)) :=
  let p := payNat l.programId l.paymentId
  match ps.lookup p with
  | none => if l.revision = 0 then some ((p, l) :: ps) else none
  | some old =>
    if redecides old.revision old l then some ((p, l) :: ps.filter (·.1 != p))
    else if l.revision = old.revision ∧ l.outcome ≠ .ALLOW then some ps else none

/-- One entry. Every entry: next index, previous digest, its registry rows on top (F1). `seal`: v1 only, before
    any activation. `resume`: once per shard, from genesis or the sealed tip; it reserves and settles the base's
    ids to the shard. `sign`: a live shard, a v2 checkpoint (F4) whose registry head is the fold's, this tenant
    and shard, publishOkAny and certsOk against the last, createdAt strictly after the last (F8), every leaf
    through payStep; the cert's epoch count goes up by one (H1). -/
def push (P : Pins) (st : LogState) (e : Entry) : Option LogState := do
  guard (e.idx = st.len ∧ e.prev = st.head)
  let d ← entryDigest e
  let reg := e.reg ++ st.reg
  let rhead := chainHead sha3 st.rhead e.reg
  let k := e.shard
  let sh := st.shard k
  let sh' ← match e.body with
    | .seal t => do
      guard (isV2 t = false ∧ e.reg = [] ∧ sh.sealed = none ∧ sh.last = none ∧ sh.live = false)
      pure { sh with sealed := some t }
    | .resume p => do
      guard (sh.live = false ∧ p.tip.map (·.1) = sh.sealed)
      let g ← activation P k p
      let ids := (g.1.entries ++ g.2.entries).map (·.id)
      guard (reg = (3, 0, k) :: (2, 0, k) :: reserveRows k st.reg ids)
      guard (ids.all fun i => holder i reg == some (k, true))
      let hd ← headOf sha3 g.1 g.2
      let base ← digestV2 sha3 hd
      pure { sh with live := true, last := p.tip, base }
    | .sign cert new tokens _ => do
      guard (sh.live = true)
      let (_, rh) ← decodeCheckpoint2 new
      guard (rh = rhead)
      let n ← storedOfAny sha3 new
      let c ← decodeKeyCert cert
      guard (n.checkpoint.tenantId = P.tenant ∧ n.checkpoint.shardId = k)
      guard (publishOkAny P.rootPk cert (sh.last.map (·.1)) new tokens = true)
      guard (certsOk P.rootPk cert ((sh.last.map (·.2)).getD cert) (sh.last.map (·.1)) n = true)
      guard (((sh.last.bind fun x => storedOfAny sha3 x.1).all fun q =>
        decide (q.checkpoint.createdAt < n.checkpoint.createdAt)) = true)
      let ps ← e.body.leaves.foldlM payStep sh.pays
      pure { sh with last := some (new, cert), base := n.checkpoint.stateDigest, pays := ps,
                     own := upd sh.own c.epoch (sh.own c.epoch + 1) }
  pure { len := st.len + 1, head := d, reg, rhead, shard := upd st.shard k sh' }

/-- All custody state: the fold of the off-machine log, once, at boot (H3). -/
def fold (P : Pins) (log : List Entry) : Option LogState := log.foldlM (push P) LogState.init

/-- FORMAT: the folded registry head is the chain of the folded rows. -/
theorem registry_head (P : Pins) (log : List Entry) (st : LogState) (h : fold P log = some st) :
    st.rhead = chainHead sha3 zeroDigest st.reg := sorry

/-- Per shard and payment, revisions never go down, and an equal revision later is never ALLOW. -/
theorem revision_mono (P : Pins) (log : List Entry) (hf : (fold P log).isSome) (i j : Nat) (hij : i < j)
    (e e' : Entry) (hi : log[i]? = some e) (hj : log[j]? = some e') (hk : e.shard = e'.shard)
    (l l' : Leaf) (hl : l ∈ e.body.leaves) (hl' : l' ∈ e'.body.leaves)
    (hp : payNat l.programId l.paymentId = payNat l'.programId l'.paymentId) :
    l.revision ≤ l'.revision ∧ (l.revision = l'.revision → l'.outcome ≠ .ALLOW) := sorry

/-- An ALLOW past revision 0 re-decides an earlier ALLOW of the same shard by trunk `redecides`. -/
theorem revision_step (P : Pins) (log : List Entry) (hf : (fold P log).isSome) (j : Nat) (e' : Entry)
    (hj : log[j]? = some e') (l' : Leaf) (hl' : l' ∈ e'.body.leaves) (ha : l'.outcome = .ALLOW)
    (hr : 0 < l'.revision) :
    ∃ (i : Nat) (e : Entry) (l : Leaf), i ≤ j ∧ log[i]? = some e ∧ e.shard = e'.shard ∧ l ∈ e.body.leaves ∧
      redecides l.revision l l' = true := sorry

/-- F8: signed checkpoints of one shard have strictly increasing createdAt. -/
theorem createdAt_strict (P : Pins) (log : List Entry) (hf : (fold P log).isSome) (i j : Nat) (hij : i < j)
    (e e' : Entry) (hi : log[i]? = some e) (hj : log[j]? = some e') (hk : e.shard = e'.shard)
    (a b : Bytes) (ha : e.body.signed? = some a) (hb : e'.body.signed? = some b) (n n' : Stored)
    (hn : storedOfAny sha3 a = some n) (hn' : storedOfAny sha3 b = some n') :
    n.checkpoint.createdAt < n'.checkpoint.createdAt := sorry

/-! ### 8g. Custody: the courier supplies requests, snapshots, redo and the witness; Lean the rest -/

structure SignIn where
  ctr : Nat
  secs : Nat
  now : Nat
  program : Bytes
  reqs : List Bytes
  ctx : Ctx
  witness : Witness

/-- The revision custody assigns: 0 for a new payment; the latest + 1 if redone; else the latest. -/
def revAt (sh : Shard) (redo : List Nat) (p : Nat) : Nat :=
  match sh.pays.lookup p with
  | none => 0
  | some l => if redo.contains p then l.revision + 1 else l.revision

/-- The batch: lines Lean decodes, owners answered by the folded registry with this batch reserved (F1). -/
def batchAt (P : Pins) (st : LogState) (k : Nat) (i : SignIn) : Option (List Request × Batch) := do
  let rs ← reqsOf P.tenant i.program i.reqs
  let b ← batchLines rs
  let ids := b.map (·.id)
  let os := ids.eraseDups.filterMap (answer (reserveRows k st.reg ids))
  pure (rs, ⟨{ i.ctx with today := localDay P.tbl i.secs }, os, b⟩)

/-- Run by the Lean exe inside custody on the folded state. `i.ctr` is the TPM reading minus its base, read
    independently of the store (H1); `new` is header ‖ signature. Accepted only if the fold takes the entry. -/
def custodyOk (P : Pins) (st : LogState) (k : Nat) (cert : Bytes) (i : SignIn) (new : Bytes)
    (tokens : List Bytes) : Option Entry := do
  let sh := st.shard k
  let c ← decodeKeyCert cert
  guard (sh.live = true ∧ i.ctr = sh.own c.epoch)
  guard ((i.ctx.redo.all fun p => (sh.pays.lookup p).isSome) = true)
  let (rs, bt) ← batchAt P st k i
  let o ← decideIdx sha3 bt.ctx k bt.owners bt.lines sh.base i.witness
  let rset ← readSetOf i.ctx sh.base
  let rows2 := settleRows k (reserveRows k st.reg (bt.lines.map (·.id))) o.free
  let prs := (i.reqs.zip rs).filterMap
    (rowOf (revAt sh i.ctx.redo) o.pays (o.decisions.map fun x => (x.line, x.outcome, x.reasons)) rset)
  let n ← storedOfAny sha3 new
  guard (isV2 new = true ∧ n.checkpoint.programId = i.program ∧ n.checkpoint.stateDigest = o.digest)
  guard (n.checkpoint.createdAt = i.secs ∧ i.secs ≤ i.now ∧ i.now ≤ i.secs + eps)
  guard (tokensOk P.c i.secs prs tokens = true)
  let e : Entry := ⟨st.len, st.head, k, rows2.take (rows2.length - st.reg.length), .sign cert new tokens o.fresh⟩
  guard ((push P st e).isSome = true)
  pure e

/-- On a true base, the signed state digest is the true next state's, the tokens are the true rows (with the
    fold's revisions) up to order, and the entry carries the true fresh rows; else a named collision. -/
theorem custody_binds (hH : HashLen sha3) (P : Pins) (st : LogState) (k : Nat) (cert : Bytes) (i : SignIn)
    (new : Bytes) (tokens : List Bytes) (e : Entry) (h : custodyOk P st k cert i new tokens = some e)
    (rel unr : Snapshot Line) (hi : Inv rel unr)
    (hb : some (st.shard k).base = (headOf sha3 rel unr).bind (digestV2 sha3)) :
    ∃ (rs : List Request) (bt : Batch) (rset : Bytes) (n : Stored), batchAt P st k i = some (rs, bt) ∧
      readSetOf i.ctx (st.shard k).base = some rset ∧ storedOfAny sha3 new = some n ∧
      ((let cc := carried bt.ctx rel unr
        let r := decideRegT cc k bt.owners bt.lines
        let rows := (i.reqs.zip rs).filterMap (rowOf (revAt (st.shard k) i.ctx.redo) (paysOf cc r.decisions)
          (r.decisions.map fun x => (x.line, x.outcome, x.reasons)) rset)
        (∃ hd, headOf sha3 r.released r.unresolved = some hd ∧ digestV2 sha3 hd = some n.checkpoint.stateDigest) ∧
        (tokens.filterMap (tokRow P.c i.secs)).Perm rows ∧ tokens.length = rows.length ∧
        e.body = .sign cert new tokens (batchFresh cc r)) ∨
       Collision sha3 (witnessInputs sha3 bt.ctx k bt.owners bt.lines i.witness) (stateInputs sha3 rel unr)) :=
  sorry


/-! ### 8h. Crash and adversary model (H1, H2, F6): the CAS store is the commit point; no local copy (H3) -/

/-- Durable state: the off-machine store, the TPM counter per shard as (base, value), the cert per shard, every
    entry custody made, every entry released. `lost` is a ghost: some released signed was once absent from
    the store (set by the only step that removes entries). -/
structure Cust where
  off : List Entry
  ctr : Nat → Option (Nat × Nat)
  cert : Nat → Bytes
  made : List Entry
  out : List Entry
  cleared : Bool
  lost : Prop

def Cust.init (cert₀ : Bytes) : Cust := ⟨[], fun _ => none, fun _ => cert₀, [], [], false, False⟩

inductive Boot | ok | provision | finishCounter | stop
  deriving DecidableEq

/-- Boot: fold the store; compare the TPM count with the fold's sign count for the cert's epoch (H1). One more
    in the store than the TPM is a crash between CAS and bump; anything else stops the shard. -/
def boot (P : Pins) (s : Cust) (k : Nat) : Boot :=
  match fold P s.off, s.ctr k, decodeKeyCert (s.cert k) with
  | none, _, _ => .stop
  | some _, none, _ => .provision
  | some _, some _, none => .stop
  | some st, some (b, v), some c =>
    let n := (st.shard k).own c.epoch
    if v - b = n then .ok else if v - b + 1 = n then .finishCounter else .stop

/-- Honest steps. sign: CAS-append custody's entry; bump: then the TPM; release: only a made entry still in the
    store, only once the counter is caught up. A ceremony needs an undefined counter and a fresh epoch. -/
inductive HStep (P : Pins) : Cust → Cust → Prop
  | sign (s : Cust) (k : Nat) (st : LogState) (b v : Nat) (i : SignIn) (new : Bytes) (tokens : List Bytes)
      (e : Entry) (hf : fold P s.off = some st) (hb : boot P s k = .ok) (hc : s.ctr k = some (b, v))
      (hi : i.ctr = v - b) (he : custodyOk P st k (s.cert k) i new tokens = some e) :
      HStep P s { s with off := s.off ++ [e], made := s.made ++ [e] }
  | bump (s : Cust) (k b v : Nat) (hb : boot P s k = .finishCounter) (hc : s.ctr k = some (b, v)) :
      HStep P s { s with ctr := upd s.ctr k (some (b, v + 1)) }
  | activate (s : Cust) (e : Entry) (hs : e.body.signed? = none) (hf : (fold P (s.off ++ [e])).isSome) :
      HStep P s { s with off := s.off ++ [e] }
  | define (s : Cust) (k c : Nat) (hc : s.ctr k = none) : HStep P s { s with ctr := upd s.ctr k (some (c, c)) }
  | ceremony (s : Cust) (k : Nat) (cert : Bytes) (hc : s.ctr k = none)
      (hd : ∃ c, decodeKeyCert cert = some c ∧ ∀ st, fold P s.off = some st → (st.shard k).own c.epoch = 0) :
      HStep P s { s with cert := upd s.cert k cert }
  | release (s : Cust) (e : Entry) (hm : e ∈ s.made) (ho : e ∈ s.off) (hb : boot P s e.shard = .ok) :
      HStep P s { s with out := s.out ++ [e] }

/-- Adversary steps: roll the store back to any prefix, append any entry whose signed (if any) was released,
    clear a TPM counter. -/
inductive AStep : Cust → Cust → Prop
  | offRollback (s : Cust) (j : Nat) :
      AStep s { s with off := s.off.take j,
                       lost := s.lost ∨ ∃ e ∈ s.out, ∀ e' ∈ s.off.take j, e'.body.signed? ≠ e.body.signed? }
  | foreignWrite (s : Cust) (e : Entry)
      (hr : ∀ x, e.body.signed? = some x → ∃ e' ∈ s.out, e'.body.signed? = some x) :
      AStep s { s with off := s.off ++ [e] }
  | tpmClear (s : Cust) (k : Nat) : AStep s { s with ctr := upd s.ctr k none, cleared := true }

inductive Reach (P : Pins) (cert₀ : Bytes) : Cust → Prop
  | init : Reach P cert₀ (Cust.init cert₀)
  | honest (s s' : Cust) : Reach P cert₀ s → HStep P s s' → Reach P cert₀ s'
  | adv (s s' : Cust) : Reach P cert₀ s → AStep s s' → Reach P cert₀ s'

inductive ReachH (P : Pins) (cert₀ : Bytes) : Cust → Prop
  | init : ReachH P cert₀ (Cust.init cert₀)
  | honest (s s' : Cust) : ReachH P cert₀ s → HStep P s s' → ReachH P cert₀ s'

/-- A released signed is absent from the store now, by bytes. -/
def Gone (s : Cust) (e : Entry) : Prop := ∀ e' ∈ s.off, e'.body.signed? ≠ e.body.signed?

/-- Two released checkpoints with distinct headers and equal header hashes. -/
def ChainCollision (s : Cust) : Prop :=
  ∃ e ∈ s.out, ∃ e' ∈ s.out, ∃ (a b : Bytes) (x y : SignedCheckpoint), e.body.signed? = some a ∧
    e'.body.signed? = some b ∧ decodeAnyCheckpoint a = some x ∧ decodeAnyCheckpoint b = some y ∧
    x.header ≠ y.header ∧ sha3 x.header = sha3 y.header

private theorem cust_guard (c : Prop) [Decidable c] (x : Unit) : (guard c : Option Unit) = some x ↔ c := by
  by_cases hc : c <;> simp [guard, hc]

/-- What custody's proofs read off one push: index, length, untouched shards, and the sign count. -/
private theorem cust_push (P : Pins) (st st' : LogState) (e : Entry) (h : push P st e = some st') :
    e.idx = st.len ∧ st'.len = st.len + 1 ∧ (∀ j, j ≠ e.shard → st'.shard j = st.shard j) ∧
    (e.body.signed? = none → (st'.shard e.shard).own = (st.shard e.shard).own) ∧
    ∀ cert new tokens f, e.body = .sign cert new tokens f →
      ∃ c n, decodeKeyCert cert = some c ∧ storedOfAny sha3 new = some n ∧ n.checkpoint.shardId = e.shard ∧
        (st'.shard e.shard).own = upd (st.shard e.shard).own c.epoch ((st.shard e.shard).own c.epoch + 1) := by
  unfold push at h
  cases hb : e.body with
  | «seal» t =>
    simp [hb, Option.bind_eq_some_iff, cust_guard] at h
    obtain ⟨hg, a, _, _, rfl⟩ := h
    exact ⟨hg.1, rfl, fun j hj => by simp [upd, hj], fun _ => by simp [upd], fun _ _ _ _ h => by cases h⟩
  | resume p =>
    simp [hb, Option.bind_eq_some_iff, cust_guard] at h
    obtain ⟨hg, a, _, _, _, _, _, _, _, _, _, _, _, rfl⟩ := h
    exact ⟨hg.1, rfl, fun j hj => by simp [upd, hj], fun _ => by simp [upd], fun _ _ _ _ h => by cases h⟩
  | sign cert new tokens fresh =>
    simp [hb, Option.bind_eq_some_iff, cust_guard] at h
    obtain ⟨hg, a, _, _, _, _, _, _, n, hn, c, hc, hts, _, _, _, ps, _, rfl⟩ := h
    refine ⟨hg.1, rfl, fun j hj => by simp [upd, hj], fun h => by simp [Body.signed?] at h, ?_⟩
    intro cert' new' tokens' f' h
    cases h
    exact ⟨c, n, hc, hn, hts.2, by simp [upd]⟩

private theorem cust_fold_append (P : Pins) (l : List Entry) (e : Entry) :
    fold P (l ++ [e]) = (fold P l).bind (push P · e) := by
  (simp [fold, List.foldlM_append]) <;> rfl

private theorem cust_fold_snoc (P : Pins) (l : List Entry) (e : Entry) (st' : LogState) :
    fold P (l ++ [e]) = some st' ↔ ∃ st, fold P l = some st ∧ push P st e = some st' := by
  rw [cust_fold_append]; exact Option.bind_eq_some_iff

private theorem cust_foldlM_len (P : Pins) (l : List Entry) : ∀ (s0 st : LogState),
    l.foldlM (push P) s0 = some st → st.len = s0.len + l.length := by
  induction l with
  | nil => intro s0 st h; simp at h; subst h; simp
  | cons e l ih =>
    intro s0 st h
    simp only [List.foldlM] at h
    obtain ⟨s1, hs1, hr⟩ := Option.bind_eq_some_iff.mp h
    rw [ih s1 st hr, (cust_push P s0 s1 e hs1).2.1]
    simp only [List.length_cons]; omega

private theorem cust_fold_len (P : Pins) (l : List Entry) (st : LogState) (h : fold P l = some st) :
    st.len = l.length := by
  have := cust_foldlM_len P l LogState.init st h
  simpa [LogState.init] using this

/-- custodyOk's entry: shard k, a sign body with the given cert, signed and tokens, and the fold takes it. -/
private theorem cust_custodyOk (P : Pins) (st : LogState) (k : Nat) (cert : Bytes) (i : SignIn) (new : Bytes)
    (tokens : List Bytes) (e : Entry) (h : custodyOk P st k cert i new tokens = some e) :
    e.shard = k ∧ (∃ f, e.body = .sign cert new tokens f) ∧ ∃ st', push P st e = some st' := by
  unfold custodyOk at h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨⟨_, _⟩, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, hp, h⟩ := Option.bind_eq_some_iff.mp h
  have he := Option.some.inj h
  subst he
  exact ⟨rfl, ⟨_, rfl⟩, Option.isSome_iff_exists.mp ((cust_guard _ _).mp hp)⟩

private theorem cust_boot (P : Pins) (s : Cust) (k : Nat) (st : LogState) (b v : Nat) (c : EpochCert)
    (hf : fold P s.off = some st) (hc : s.ctr k = some (b, v)) (hd : decodeKeyCert (s.cert k) = some c) :
    boot P s k = if v - b = (st.shard k).own c.epoch then .ok
      else if v - b + 1 = (st.shard k).own c.epoch then .finishCounter else .stop := by
  simp only [boot, hf, hc, hd]

/-- H2: unless a released signed was ever lost, one shard never releases two ALLOWs for one payment and
    revision, except as the same leaf of the same signed checkpoint. -/
theorem never_twice (P : Pins) (cert₀ : Bytes) (s : Cust) (hr : Reach P cert₀ s) (hl : ¬ s.lost)
    (e e' : Entry) (he : e ∈ s.out) (he' : e' ∈ s.out) (hk : e.shard = e'.shard) (l l' : Leaf)
    (hl1 : l ∈ e.body.leaves) (hl2 : l' ∈ e'.body.leaves) (ha : l.outcome = .ALLOW) (ha' : l'.outcome = .ALLOW)
    (hp : l.programId = l'.programId ∧ l.paymentId = l'.paymentId ∧ l.revision = l'.revision) :
    (e.body.signed? = e'.body.signed? ∧ l = l') ∨ ChainCollision s := sorry

private theorem cust_honest_inv (P : Pins) (cert₀ : Bytes) (s : Cust) (hr : ReachH P cert₀ s) :
    ¬ s.lost ∧ ∀ e ∈ s.out, e ∈ s.off := by
  induction hr with
  | init => exact ⟨fun h => h, fun e he => by simp [Cust.init] at he⟩
  | honest s s' _ hs ih =>
    obtain ⟨hl, ho⟩ := ih
    cases hs with
    | sign k st b v i new tokens e => exact ⟨hl, fun x hx => List.mem_append_left _ (ho x hx)⟩
    | activate e => exact ⟨hl, fun x hx => List.mem_append_left _ (ho x hx)⟩
    | release e hm hoff hb =>
      refine ⟨hl, fun x hx => ?_⟩
      simp only [List.mem_append, List.mem_singleton] at hx
      rcases hx with hx | hx
      · exact ho x hx
      · rw [hx]; exact hoff
    | _ => exact ⟨hl, ho⟩

/-- H2: honest runs never lose a released signed. -/
theorem honest_not_lost (P : Pins) (cert₀ : Bytes) (s : Cust) (hr : ReachH P cert₀ s) :
    ¬ s.lost ∧ ∀ e ∈ s.out, ¬ Gone s e := by
  obtain ⟨hl, ho⟩ := cust_honest_inv P cert₀ s hr
  exact ⟨hl, fun e he hg => hg e (ho e he) rfl⟩

/-- H2 + H1: a released signed missing from the store stops its shard at boot, unless the TPM was cleared. -/
theorem lost_detected (P : Pins) (cert₀ : Bytes) (s : Cust) (hr : Reach P cert₀ s) (e : Entry)
    (he : e ∈ s.out) (hg : Gone s e) : s.cleared = true ∨ boot P s e.shard = .stop ∨ ChainCollision s := sorry

/-- Honest custody keeps every shard's TPM count at the fold's count for its cert epoch, or one behind. -/
private theorem cust_wedge_inv (P : Pins) (cert₀ : Bytes) (hc0 : (decodeKeyCert cert₀).isSome) (s : Cust)
    (hr : ReachH P cert₀ s) :
    (∃ st, fold P s.off = some st) ∧ (∀ k, (decodeKeyCert (s.cert k)).isSome) ∧
    (∀ k st, s.ctr k = none → fold P s.off = some st → ∀ E, (st.shard k).own E = 0) ∧
    (∀ k b v st c, s.ctr k = some (b, v) → fold P s.off = some st → decodeKeyCert (s.cert k) = some c →
      b ≤ v ∧ (v - b = (st.shard k).own c.epoch ∨ v - b + 1 = (st.shard k).own c.epoch)) := by
  induction hr with
  | init =>
    refine ⟨⟨_, rfl⟩, fun _ => hc0, fun k st _ h E => ?_, fun k b v st c h => ?_⟩
    · simp [fold, Cust.init] at h; subst h; rfl
    · simp [Cust.init] at h
  | honest s s' _ hs ih =>
    obtain ⟨hfo, hd, hz, hn⟩ := ih
    cases hs with
    | sign k0 st0 b0 v0 i new tokens e hf0 hb hc hi he =>
      obtain ⟨hsh, ⟨f, hbody⟩, st1, hp⟩ := cust_custodyOk P st0 k0 _ i new tokens e he
      subst hsh
      have hf1 : fold P (s.off ++ [e]) = some st1 := (cust_fold_snoc P s.off e st1).mpr ⟨st0, hf0, hp⟩
      obtain ⟨-, -, hoth, -, hsg⟩ := cust_push P st0 st1 e hp
      obtain ⟨c, n, hc', -, -, hown⟩ := hsg _ _ _ _ hbody
      have hok : v0 - b0 = (st0.shard e.shard).own c.epoch := by
        rw [cust_boot P s _ st0 b0 v0 c hf0 hc hc'] at hb
        split at hb
        · assumption
        · split at hb <;> cases hb
      dsimp only
      refine ⟨⟨st1, hf1⟩, hd, fun k st' hk hst E => ?_, fun k b v st' c' hk hst hdk => ?_⟩
      · have h1 := Option.some.inj (hst.symm.trans hf1)
        subst h1
        have hne : k ≠ e.shard := fun h => by rw [h, hc] at hk; cases hk
        rw [hoth k hne]; exact hz k st0 hk hf0 E
      · have h1 := Option.some.inj (hst.symm.trans hf1)
        subst h1
        by_cases hke : k = e.shard
        · subst hke
          rw [hc] at hk
          simp only [Option.some.injEq, Prod.mk.injEq] at hk
          obtain ⟨rfl, rfl⟩ := hk
          rw [hc'] at hdk
          cases hdk
          exact ⟨(hn _ _ _ _ _ hc hf0 hc').1, Or.inr (by rw [hown]; simp [upd, hok])⟩
        · rw [hoth k hke]; exact hn k b v st0 c' hk hf0 hdk
    | bump k0 b0 v0 hb hc =>
      obtain ⟨st, hf⟩ := hfo
      obtain ⟨c, hc'⟩ := Option.isSome_iff_exists.mp (hd k0)
      have hfin : v0 - b0 + 1 = (st.shard k0).own c.epoch := by
        rw [cust_boot P s k0 st b0 v0 c hf hc hc'] at hb
        split at hb
        · cases hb
        · split at hb
          · assumption
          · cases hb
      have hbv := (hn k0 b0 v0 st c hc hf hc').1
      dsimp only
      refine ⟨⟨st, hf⟩, hd, fun k st' hk hst E => ?_, fun k b v st' c' hk hst hdk => ?_⟩
      · by_cases hke : k = k0
        · subst hke; simp [upd] at hk
        · simp only [upd, if_neg hke] at hk; exact hz k st' hk hst E
      · by_cases hke : k = k0
        · subst hke
          simp [upd] at hk
          obtain ⟨rfl, rfl⟩ := hk
          have h1 := Option.some.inj (hst.symm.trans hf)
          subst h1
          rw [hc'] at hdk
          cases hdk
          exact ⟨by omega, Or.inl (by omega)⟩
        · simp only [upd, if_neg hke] at hk; exact hn k b v st' c' hk hst hdk
    | activate e hs hfo' =>
      obtain ⟨st1, hf1⟩ := Option.isSome_iff_exists.mp hfo'
      obtain ⟨st0, hf0, hp⟩ := (cust_fold_snoc P s.off e st1).mp hf1
      obtain ⟨-, -, hoth, hns, -⟩ := cust_push P st0 st1 e hp
      have hown : ∀ j, (st1.shard j).own = (st0.shard j).own := fun j => by
        by_cases hj : j = e.shard
        · subst hj; exact hns hs
        · rw [hoth j hj]
      dsimp only
      refine ⟨⟨st1, hf1⟩, hd, fun k st' hk hst E => ?_, fun k b v st' c hk hst hdk => ?_⟩
      · have h1 := Option.some.inj (hst.symm.trans hf1)
        subst h1
        rw [hown k]; exact hz k st0 hk hf0 E
      · have h1 := Option.some.inj (hst.symm.trans hf1)
        subst h1
        rw [hown k]; exact hn k b v st0 c hk hf0 hdk
    | define k0 c0 hc =>
      dsimp only
      refine ⟨hfo, hd, fun k st' hk hst E => ?_, fun k b v st' c hk hst hdk => ?_⟩
      · by_cases hke : k = k0
        · subst hke; simp [upd] at hk
        · simp only [upd, if_neg hke] at hk; exact hz k st' hk hst E
      · by_cases hke : k = k0
        · subst hke
          simp [upd] at hk
          obtain ⟨rfl, rfl⟩ := hk
          refine ⟨Nat.le_refl _, Or.inl ?_⟩
          rw [hz _ st' hc hst c.epoch]; simp
        · simp only [upd, if_neg hke] at hk; exact hn k b v st' c hk hst hdk
    | ceremony k0 cert hc hdc =>
      dsimp only
      refine ⟨hfo, fun k => ?_, hz, fun k b v st' c hk hst hdk => ?_⟩
      · by_cases hke : k = k0
        · subst hke; obtain ⟨c, hc1, -⟩ := hdc; simp [upd, hc1]
        · simp only [upd, if_neg hke]; exact hd k
      · by_cases hke : k = k0
        · subst hke; rw [hc] at hk; cases hk
        · simp only [upd, if_neg hke] at hdk; exact hn k b v st' c hk hst hdk
    | release e hm ho hb => exact ⟨hfo, hd, hz, hn⟩

/-- Honest runs never stop a shard at boot. -/
theorem no_wedge (P : Pins) (cert₀ : Bytes) (hc : (decodeKeyCert cert₀).isSome) (s : Cust)
    (hr : ReachH P cert₀ s) (k : Nat) : boot P s k ≠ .stop := by
  obtain ⟨⟨st, hf⟩, hd, -, hn⟩ := cust_wedge_inv P cert₀ hc s hr
  cases hk : s.ctr k with
  | none => simp [boot, hf, hk]
  | some bv =>
    obtain ⟨b, v⟩ := bv
    obtain ⟨c, hc'⟩ := Option.isSome_iff_exists.mp (hd k)
    rw [cust_boot P s k st b v c hf hk hc']
    obtain ⟨-, h | h⟩ := hn k b v st c hk hf hc'
    · rw [if_pos h]; decide
    · have h' : ¬ (v - b = (st.shard k).own c.epoch) := by omega
      rw [if_neg h', if_pos h]; decide

/-! ### 8i. The chain: every signed of a shard is the true state; the log alone rebuilds it -/

/-- `hist`: per signed entry of shard k, in log order, the cert and custody input it was made from. -/
def MadeBy (P : Pins) (log : List Entry) (k : Nat) (hist : List (Bytes × SignIn × Entry)) : Prop :=
  hist.map (·.2.2) = log.filter (fun e => e.shard == k && e.body.signed?.isSome) ∧
  ∀ x ∈ hist, ∃ (st : LogState) (new : Bytes) (tokens : List Bytes),
    fold P (log.take x.2.2.idx) = some st ∧ custodyOk P st k x.1 x.2.1 new tokens = some x.2.2

def histBatches (P : Pins) (log : List Entry) (k : Nat) (hist : List (Bytes × SignIn × Entry)) :
    Option (List Batch) :=
  hist.mapM fun x => do
    let st ← fold P (log.take x.2.2.idx)
    let (_, b) ← batchAt P st k x.2.1
    pure b

/-- The sets a lost database is rebuilt to: the activation base, then each signed entry's fresh rows dated by
    its header. -/
def rebuild (P : Pins) (k : Nat) (g : Snapshot Line × Snapshot Line) (log : List Entry) :
    Snapshot Line × Snapshot Line :=
  replayT g (log.filterMap fun e =>
    match e.body with
    | .sign _ new _ f =>
      if e.shard = k then (storedOfAny sha3 new).map fun n => (localDay P.tbl n.checkpoint.createdAt, f) else none
    | _ => none)

private theorem cust_hist_take (P : Pins) (log : List Entry) (k : Nat) (hist : List (Bytes × SignIn × Entry))
    (hm1 : hist.map (·.2.2) = log.filter (fun e => e.shard == k && e.body.signed?.isSome))
    (hm2 : ∀ x ∈ hist, ∃ (st : LogState) (new : Bytes) (tokens : List Bytes),
      fold P (log.take x.2.2.idx) = some st ∧ custodyOk P st k x.1 x.2.1 new tokens = some x.2.2)
    (hidx : ∀ x ∈ log, x.idx < log.length) (e : Entry) :
    ∀ y ∈ hist, ∃ (st : LogState) (new : Bytes) (tokens : List Bytes),
      fold P ((log ++ [e]).take y.2.2.idx) = some st ∧ custodyOk P st k y.1 y.2.1 new tokens = some y.2.2 := by
  intro y hy
  have hl : y.2.2 ∈ log := by
    have h : y.2.2 ∈ hist.map (·.2.2) := List.mem_map.mpr ⟨y, hy, rfl⟩
    rw [hm1] at h
    exact (List.mem_filter.mp h).1
  rw [List.take_append_of_le_length (Nat.le_of_lt (hidx _ hl))]
  exact hm2 y hy

private theorem cust_signed_inv (P : Pins) (cert₀ : Bytes) (s : Cust) (hr : ReachH P cert₀ s) :
    (∃ st, fold P s.off = some st) ∧ (∀ x ∈ s.off, x.idx < s.off.length) ∧
    ∀ k, ∃ hist, MadeBy P s.off k hist := by
  induction hr with
  | init => exact ⟨⟨_, rfl⟩, fun x hx => by simp [Cust.init] at hx, fun k => ⟨[], by simp [MadeBy, Cust.init]⟩⟩
  | honest s s' _ hs ih =>
    obtain ⟨hfo, hidx, hm⟩ := ih
    cases hs with
    | sign k0 st0 b0 v0 i new tokens e hf0 hb hc hi he =>
      obtain ⟨hsh, ⟨f, hbody⟩, st1, hp⟩ := cust_custodyOk P st0 k0 _ i new tokens e he
      have hlen : e.idx = s.off.length := by
        rw [(cust_push P st0 st1 e hp).1, cust_fold_len P s.off st0 hf0]
      dsimp only
      refine ⟨⟨st1, (cust_fold_snoc P s.off e st1).mpr ⟨st0, hf0, hp⟩⟩, fun x hx => ?_, fun k => ?_⟩
      · simp only [List.length_append, List.length_singleton]
        rcases List.mem_append.mp hx with hx | hx
        · have := hidx x hx; omega
        · rw [List.mem_singleton.mp hx, hlen]; omega
      · obtain ⟨hist, hm1, hm2⟩ := hm k
        have ht := cust_hist_take P s.off k hist hm1 hm2 hidx e
        by_cases hke : e.shard = k
        · refine ⟨hist ++ [(s.cert k0, i, e)], ?_⟩
          unfold MadeBy
          refine ⟨?_, fun y hy => ?_⟩
          · simp [List.filter_append, hm1, hke, hbody, Body.signed?]
          · rcases List.mem_append.mp hy with hy | hy
            · exact ht y hy
            · rw [List.mem_singleton.mp hy]
              have hk0 : k = k0 := hke.symm.trans hsh
              subst hk0
              exact ⟨st0, new, tokens, by simp [hlen, hf0], he⟩
        · refine ⟨hist, ?_⟩
          unfold MadeBy
          exact ⟨by simp [List.filter_append, hm1, hke], ht⟩
    | activate e hs hfo' =>
      obtain ⟨st1, hf1⟩ := Option.isSome_iff_exists.mp hfo'
      obtain ⟨st0, hf0, hp⟩ := (cust_fold_snoc P s.off e st1).mp hf1
      have hlen : e.idx = s.off.length := by
        rw [(cust_push P st0 st1 e hp).1, cust_fold_len P s.off st0 hf0]
      dsimp only
      refine ⟨⟨st1, hf1⟩, fun x hx => ?_, fun k => ?_⟩
      · simp only [List.length_append, List.length_singleton]
        rcases List.mem_append.mp hx with hx | hx
        · have := hidx x hx; omega
        · rw [List.mem_singleton.mp hx, hlen]; omega
      · obtain ⟨hist, hm1, hm2⟩ := hm k
        refine ⟨hist, ?_⟩
        unfold MadeBy
        exact ⟨by simp [List.filter_append, hm1, hs], cust_hist_take P s.off k hist hm1 hm2 hidx e⟩
    | _ => exact ⟨hfo, hidx, hm⟩

/-- Honest stores fold, and every signed entry was made by custody on the fold of its prefix. (Not for Reach:
    a foreign copy of a released signed may carry other fresh rows; that breaks only the witness.) -/
theorem custody_signed (P : Pins) (cert₀ : Bytes) (s : Cust) (hr : ReachH P cert₀ s) :
    ∃ st, fold P s.off = some st ∧ ∀ k, ∃ hist, MadeBy P s.off k hist := by
  obtain ⟨⟨st, hst⟩, -, hm⟩ := cust_signed_inv P cert₀ s hr
  exact ⟨st, hst, hm⟩

/-- Every signed of shard k carries the stateDigest of the true sets after its batch (owners from the folded
    registry); else a named collision at some step. Token rows per step: custody_binds on this base. -/
theorem chain_sound (hH : HashLen sha3) (P : Pins) (log : List Entry) (st : LogState) (hf : fold P log = some st)
    (k : Nat) (hist : List (Bytes × SignIn × Entry)) (hm : MadeBy P log k hist) (er : Entry) (p : Permit)
    (her : er ∈ log) (hk : er.shard = k) (hp : er.body = .resume p) (g : Snapshot Line × Snapshot Line)
    (hg : activation P k p = some g) (hi : Inv g.1 g.2) :
    ∃ bs, histBatches P log k hist = some bs ∧
      ((∀ (i : Nat) (x : Bytes × SignIn × Entry) (new : Bytes), hist[i]? = some x →
          x.2.2.body.signed? = some new →
          ∃ (n : Stored) (hd : Head), storedOfAny sha3 new = some n ∧
            headOf sha3 (shardSetsT k g (bs.take (i + 1))).1 (shardSetsT k g (bs.take (i + 1))).2 = some hd ∧
            digestV2 sha3 hd = some n.checkpoint.stateDigest) ∨
       ∃ (i : Nat) (x : Bytes × SignIn × Entry) (b : Batch), hist[i]? = some x ∧ bs[i]? = some b ∧
         Collision sha3 (witnessInputs sha3 b.ctx k b.owners b.lines x.2.1.witness)
           (stateInputs sha3 (shardSetsT k g (bs.take i)).1 (shardSetsT k g (bs.take i)).2)) := sorry

/-- The log alone (activation base + fresh rows) rebuilds the chain's true sets; else the same collision. -/
theorem rebuild_sound (hH : HashLen sha3) (P : Pins) (log : List Entry) (st : LogState)
    (hf : fold P log = some st) (k : Nat) (hist : List (Bytes × SignIn × Entry)) (hm : MadeBy P log k hist)
    (er : Entry) (p : Permit) (her : er ∈ log) (hk : er.shard = k) (hp : er.body = .resume p)
    (g : Snapshot Line × Snapshot Line) (hg : activation P k p = some g) (hi : Inv g.1 g.2) (bs : List Batch)
    (hb : histBatches P log k hist = some bs) :
    rebuild P k g log = shardSetsT k g bs ∨
      ∃ (i : Nat) (x : Bytes × SignIn × Entry) (b : Batch), hist[i]? = some x ∧ bs[i]? = some b ∧
        Collision sha3 (witnessInputs sha3 b.ctx k b.owners b.lines x.2.1.witness)
          (stateInputs sha3 (shardSetsT k g (bs.take i)).1 (shardSetsT k g (bs.take i)).2) := sorry

end BlindLedger.Gate.StateV2
