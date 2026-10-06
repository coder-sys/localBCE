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

/-! Field-width lemmas for the injective encodings (used from §2 on). -/

private theorem be_len {w n : Nat} {bs : Bytes} (h : be w n = some bs) : bs.length = w := by
  unfold be at h
  split at h
  · simp at h; subst h; simp
  · simp at h

private theorem be_lt {w n : Nat} {bs : Bytes} (h : be w n = some bs) : n < 256 ^ w := by
  unfold be at h
  split at h
  · assumption
  · simp at h

private theorem be_digits_succ (w n : Nat) :
    ((List.range (w + 1)).reverse.map fun i => (n / 256 ^ i % 256).toUInt8) =
    ((List.range w).reverse.map fun i => (n / 256 / 256 ^ i % 256).toUInt8) ++ [(n % 256).toUInt8] := by
  rw [List.range_succ_eq_map, List.reverse_cons, ← List.map_reverse, List.map_append, List.map_map]
  simp [Function.comp_def, Nat.pow_succ, Nat.div_div_eq_div_mul, Nat.mul_comm]

private theorem be_digits_inj : ∀ (w n m : Nat), n < 256 ^ w → m < 256 ^ w →
    ((List.range w).reverse.map fun i => (n / 256 ^ i % 256).toUInt8) =
    ((List.range w).reverse.map fun i => (m / 256 ^ i % 256).toUInt8) → n = m
  | 0, n, m, hn, hm, _ => by simp at hn hm; omega
  | w + 1, n, m, hn, hm, h => by
    rw [be_digits_succ, be_digits_succ] at h
    have hl : ∀ k : Nat, (((List.range w).reverse.map fun i => (k / 256 ^ i % 256).toUInt8)).length = w := by
      intro k; simp
    obtain ⟨h1, h2⟩ := List.append_inj h (by rw [hl, hl])
    have e1 : n / 256 = m / 256 := by
      refine be_digits_inj w _ _ (by rw [Nat.pow_succ] at hn; omega) (by rw [Nat.pow_succ] at hm; omega) ?_
      simpa using h1
    have e2 : n % 256 = m % 256 := by
      have := congrArg (fun l : List UInt8 => l.head?.map UInt8.toNat) h2
      simpa [Nat.mod_mod] using this
    omega

private theorem be_inj {w n m : Nat} {bs : Bytes} (h : be w n = some bs) (h' : be w m = some bs) : n = m := by
  have hn := be_lt h
  have hm := be_lt h'
  unfold be at h h'
  rw [if_pos hn] at h
  rw [if_pos hm] at h'
  exact be_digits_inj w n m hn hm (by rw [Option.some.inj h, Option.some.inj h'])

private theorem mapM_flat_inj {α : Type} (f : α → Option Bytes)
    (hf : ∀ a a' y y' (r r' : Bytes), f a = some y → f a' = some y' → y ++ r = y' ++ r' → a = a' ∧ r = r') :
    ∀ (l l' : List α) (ys ys' : List Bytes) (r r' : Bytes), l.length = l'.length →
      l.mapM f = some ys → l'.mapM f = some ys' → ys.flatten ++ r = ys'.flatten ++ r' → l = l' ∧ r = r' := by
  intro l
  induction l with
  | nil =>
    intro l' ys ys' r r' hl h1 h2 h
    cases l' with
    | nil => simp at h1 h2; subst h1; subst h2; simpa using h
    | cons _ _ => simp at hl
  | cons a t ih =>
    intro l' ys ys' r r' hl h1 h2 h
    cases l' with
    | nil => simp at hl
    | cons a' t' =>
      simp [List.mapM_cons, Option.bind_eq_some_iff] at h1 h2
      obtain ⟨y, hy, zs, hz, rfl⟩ := h1
      obtain ⟨y', hy', zs', hz', rfl⟩ := h2
      simp only [List.flatten_cons, List.append_assoc] at h
      obtain ⟨e1, e2⟩ := hf a a' y y' _ _ hy hy' h
      obtain ⟨e3, e4⟩ := ih t' zs zs' r r' (by simpa using hl) hz hz' e2
      exact ⟨by rw [e1, e3], e4⟩

private theorem fields_inj : ∀ (fs fs' : List (Nat × Nat)) (bs bs' : List Bytes) (r r' : Bytes),
    fs.map Prod.fst = fs'.map Prod.fst →
    (fs.mapM fun (w, n) => be w n) = some bs → (fs'.mapM fun (w, n) => be w n) = some bs' →
    bs.flatten ++ r = bs'.flatten ++ r' → fs = fs' ∧ r = r' := by
  intro fs
  induction fs with
  | nil =>
    intro fs' bs bs' r r' hw h1 h2 h
    cases fs' with
    | nil => simp at h1 h2; subst h1; subst h2; simpa using h
    | cons _ _ => simp at hw
  | cons p t ih =>
    intro fs' bs bs' r r' hw h1 h2 h
    cases fs' with
    | nil => simp at hw
    | cons p' t' =>
      obtain ⟨w, n⟩ := p
      obtain ⟨w', n'⟩ := p'
      simp at hw
      obtain ⟨rfl, hw⟩ := hw
      simp [List.mapM_cons, Option.bind_eq_some_iff] at h1 h2
      obtain ⟨y, hy, zs, hz, rfl⟩ := h1
      obtain ⟨y', hy', zs', hz', rfl⟩ := h2
      simp only [List.flatten_cons, List.append_assoc] at h
      obtain ⟨e1, e2⟩ := List.append_inj h (by rw [be_len hy, be_len hy'])
      subst e1
      obtain ⟨e3, e4⟩ := ih t' zs zs' r r' hw hz hz' e2
      have := be_inj hy hy'
      subst this
      subst e3
      exact ⟨rfl, e4⟩

private theorem mapM_be_lt : ∀ (fs : List (Nat × Nat)) (bs : List Bytes),
    (fs.mapM fun (w, n) => be w n) = some bs → ∀ p ∈ fs, p.2 < 256 ^ p.1
  | [], _, _, p, hp => by simp at hp
  | (w, n) :: t, bs, h, p, hp => by
    simp [List.mapM_cons, Option.bind_eq_some_iff] at h
    obtain ⟨y, hy, zs, hz, _⟩ := h
    rcases List.mem_cons.mp hp with rfl | hp
    · exact be_lt hy
    · exact mapM_be_lt t zs hz p hp

private theorem keyWidths_lt {t : Nat} {ws : List Nat} (h : keyWidths t = some ws) : t < 8 := by
  rcases t with _ | _ | _ | _ | _ | _ | _ | _ | t <;> first | omega | simp [keyWidths] at h

private theorem keyBytes_cons {t : Nat} {xs : List Nat} {x : Bytes} (h : keyBytes (t :: xs) = some x) :
    ∃ (ws : List Nat) (bs : List Bytes), keyWidths t = some ws ∧ ws.length = xs.length ∧
      (ws.zip xs).mapM (fun (w, n) => be w n) = some bs ∧ x = t.toUInt8 :: bs.flatten := by
  unfold keyBytes at h
  cases hw : keyWidths t with
  | none => simp [hw] at h
  | some ws =>
    by_cases hl : ws.length = xs.length
    · simp [hw, hl, Option.bind_eq_some_iff] at h
      obtain ⟨bs, hbs, hx⟩ := h
      exact ⟨ws, bs, rfl, hl, hbs, hx.symm⟩
    · simp [hw, hl] at h

private theorem Line_ext {l l' : Line} (h : Line.fields l = Line.fields l') : l = l' := by
  obtain ⟨a1, a2, f, a4, a5, a6, a7, a8, a9, a10⟩ := l
  obtain ⟨b1, b2, g, b4, b5, b6, b7, b8, b9, b10⟩ := l'
  cases f <;> cases g <;> simp_all [Line.fields, Flow.tag]

theorem keyBytes_inj {a b : Key} {x : Bytes} (ha : keyBytes a = some x) (hb : keyBytes b = some x) :
    a = b := by
  cases a with
  | nil => simp [keyBytes] at ha
  | cons t xs =>
  cases b with
  | nil => simp [keyBytes] at hb
  | cons t' xs' =>
  obtain ⟨ws, bs, hw, hl, hm, rfl⟩ := keyBytes_cons ha
  obtain ⟨ws', bs', hw', hl', hm', hx⟩ := keyBytes_cons hb
  obtain ⟨h1, h2⟩ := List.cons.inj hx
  have ht : t = t' := by
    have := congrArg UInt8.toNat h1
    have a1 := keyWidths_lt hw
    have a2 := keyWidths_lt hw'
    simp [Nat.toUInt8] at this
    omega
  subst ht
  have hws : ws = ws' := by rw [hw] at hw'; exact Option.some.inj hw'
  subst hws
  obtain ⟨hz, -⟩ := fields_inj (ws.zip xs) (ws.zip xs') bs bs' [] []
    (by rw [List.map_fst_zip (l₁ := ws) (l₂ := xs) (by omega), List.map_fst_zip (l₁ := ws) (l₂ := xs') (by omega)]) hm hm' (by simpa using h2)
  have := congrArg (List.map Prod.snd) hz
  rw [List.map_snd_zip (l₁ := ws) (l₂ := xs) (by omega), List.map_snd_zip (l₁ := ws) (l₂ := xs') (by omega)] at this
  rw [this]

theorem rowKey_inj {l m : Line} {x : Bytes} (hl : keyBytes (rowKey l) = some x)
    (hm : keyBytes (rowKey m) = some x) : l = m := by
  have h := keyBytes_inj hl hm
  have h2 : (Line.fields l).map Prod.snd = (Line.fields m).map Prod.snd := by
    simpa [rowKey] using h
  apply Line_ext
  simpa [Line.fields] using h2

/-- An encodable row has encodable keys (so the per-line guard in `decideIdx` covers every probe of it). -/
theorem rowKey_enc_keys (u : Bool) (l : Line) (h : (keyBytes (rowKey l)).isSome = true) :
    ∀ q ∈ rowKeys u l, (keyBytes q).isSome = true := by
  obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp h
  obtain ⟨ws, bs, hw, hl, hm, -⟩ := keyBytes_cons (t := 7) (xs := (Line.fields l).map Prod.snd) hx
  have hws : ws = [idWidth, payWidth, 1, idWidth, idWidth, idWidth, 4, idWidth, 4, 8] := by
    simp [keyWidths] at hw; exact hw.symm
  subst hws
  have hlt := mapM_be_lt _ _ hm
  have g : ∀ w n, (w, n) ∈ Line.fields l → n < 256 ^ w := by
    intro w n hn
    have := hlt (w, n) (by
      simp only [Line.fields, List.map_cons, List.map_nil, List.zip_cons_cons, List.zip_nil_right] at hn ⊢
      simpa using hn)
    simpa using this
  have hid := g idWidth l.id (by simp [Line.fields])
  have hmem := g idWidth l.member (by simp [Line.fields])
  have hpayee := g idWidth l.payee (by simp [Line.fields])
  have hrend := g idWidth l.rendering (by simp [Line.fields])
  have hdate := g 4 l.date (by simp [Line.fields])
  have hproc := g idWidth l.proc (by simp [Line.fields])
  have hunits := g 4 l.units (by simp [Line.fields])
  have hcents := g 8 l.cents (by simp [Line.fields])
  have hd100 : l.date / 100 < 256 ^ 4 := Nat.lt_of_le_of_lt (Nat.div_le_self _ _) hdate
  simp only [idWidth] at hid hmem hpayee hrend hproc
  intro q hq
  simp only [rowKeys, keys, exactKey, nearKey, idKey, dayKey, badDayKey, List.mem_append, List.mem_cons,
    List.mem_nil_iff, or_false] at hq
  rcases hq with (rfl | rfl | rfl) | hq
  · by_cases hc : isCap l = true <;> simp [hc, keyBytes, keyWidths, be, idWidth, hmem, hpayee, hdate, hproc, hunits, hcents]
  · by_cases hc : isCap l = true <;> simp [hc, keyBytes, keyWidths, be, idWidth, hmem, hrend, hdate, hproc, hd100]
  · simp [keyBytes, keyWidths, be, idWidth, hid]
  · by_cases hc : (u && isCap l) = true
    · by_cases hv : validDate l.date = true <;> simp [hc, hv] at hq <;> subst hq <;>
        simp [dayKey, badDayKey, keyBytes, keyWidths, be, idWidth, hmem, hpayee, hdate, hd100]
    · simp [hc] at hq

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
    (h : leafIn p v = leafIn p' v') : p = p' ∧ v = v' := by
  have hn : ∀ n, (natBE 4 n).length = 4 := by intro n; simp [natBE]
  unfold leafIn at h
  have h1 := (List.cons.inj (List.append_cancel_left h)).2
  simp only [List.append_assoc] at h1
  obtain ⟨e1, e2⟩ := List.append_inj h1 (by rw [hp, hp'])
  obtain ⟨-, e4⟩ := List.append_inj e2 (by rw [hn, hn])
  exact ⟨e1, e4⟩

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

private theorem rootAt_perm' (H : Bytes → Bytes) : ∀ (f d : Nat) (m m' : Map), m.Perm m' → rootAt H f d m = rootAt H f d m' := by
  intro f
  induction f with
  | zero =>
    intro d m m' hp
    have hl := hp.length_eq
    rcases m with _ | ⟨a, _ | ⟨b, t⟩⟩
    · rw [← hp.nil_eq]
    · have := List.perm_singleton.mp hp.symm; subst this; rfl
    · rcases m' with _ | ⟨a', _ | ⟨b', t'⟩⟩
      · simp at hl
      · simp at hl
      · simp [rootAt]
  | succ f ih =>
    intro d m m' hp
    have hl := hp.length_eq
    rcases m with _ | ⟨a, _ | ⟨b, t⟩⟩
    · rw [← hp.nil_eq]
    · have := List.perm_singleton.mp hp.symm; subst this; rfl
    · rcases m' with _ | ⟨a', _ | ⟨b', t'⟩⟩
      · simp at hl
      · simp at hl
      · simp only [rootAt]
        rw [ih (d + 1) _ _ (hp.filter _), ih (d + 1) (List.filter (fun e => bit e.1 d) (a :: b :: t)) (List.filter (fun e => bit e.1 d) (a' :: b' :: t')) (hp.filter _)]

theorem root_perm (H : Bytes → Bytes) (m m' : Map) (hm : MapOk m) (hp : m.Perm m') :
    root H m = root H m' := rootAt_perm' H _ _ _ _ hp

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

private def svPk (w n : Nat) : List Nat := (List.range w).filter fun i => n / 2 ^ i % 2 == 1

private theorem snoc_ind {α : Type} {P : List α → Prop} (h0 : P []) (hs : ∀ ys x, P ys → P (ys ++ [x])) : ∀ xs, P xs := by
  have key : ∀ n (xs : List α), xs.length = n → P xs := by
    intro n
    induction n with
    | zero => intro xs h; rw [List.length_eq_zero_iff.mp h]; exact h0
    | succ n ih =>
      intro xs h
      rcases List.eq_nil_or_concat xs with rfl | ⟨ys, x, rfl⟩
      · simp at h
      · simpa [List.concat_eq_append] using hs ys x (ih ys (by simp at h; omega))
  exact fun xs => key _ xs rfl

private theorem pk_succ (w n : Nat) : svPk (w + 1) n = (if n % 2 = 1 then [0] else []) ++ (svPk w (n / 2)).map Nat.succ := by
  unfold svPk
  rw [List.range_succ_eq_map, List.filter_cons, List.filter_map]
  have : ((fun i : Nat => n / 2 ^ i % 2 == 1) ∘ Nat.succ) = fun i => (n / 2) / 2 ^ i % 2 == 1 := by
    funext i; simp [Function.comp, Nat.pow_succ, Nat.div_div_eq_div_mul, Nat.mul_comm]
  rw [this]
  by_cases h : n % 2 = 1 <;> simp [h]

private theorem carry_peaks (H : Bytes → Bytes) : ∀ (f h : Nat) (r : Bytes) (fs : List (Nat × Bytes)) (m : Nat),
    fs.map (·.1) = (svPk f m).map (h + ·) → m + 1 < 2 ^ f →
    (carry H f h r fs).map (·.1) = (svPk f (m + 1)).map (h + ·) := by
  intro f
  induction f with
  | zero => intro h r fs m _ hm; simp at hm
  | succ f ih =>
    intro h r fs m hfs hm
    rw [pk_succ] at hfs ⊢
    by_cases hmo : m % 2 = 1
    · rw [if_pos hmo] at hfs
      rcases fs with _ | ⟨⟨h', l⟩, rest⟩
      · simp at hfs
      · simp only [List.map_cons, List.cons_append, List.nil_append, List.map_map] at hfs
        obtain ⟨e1, e2⟩ := List.cons.inj hfs
        simp only [carry]
        have e1' : h' = h := by simpa using e1
        subst e1'
        simp only [beq_self_eq_true, if_true]
        have := ih (h' + 1) (nodeHash H PD l r) rest (m / 2) (by
          rw [e2]; simp [Function.comp_def]; omega) (by omega)
        rw [this]
        have : (m + 1) % 2 = 0 := by omega
        have h2 : (m + 1) / 2 = m / 2 + 1 := by omega
        simp [this, h2, Function.comp_def]
        omega
    · rw [if_neg hmo] at hfs
      simp only [List.nil_append, List.map_map] at hfs
      have hm1 : (m + 1) % 2 = 1 := by omega
      have h2 : (m + 1) / 2 = m / 2 := by omega
      have hd : ∀ x ∈ fs, h + 1 ≤ x.1 := by
        intro x hx
        have : x.1 ∈ fs.map (·.1) := List.mem_map_of_mem hx
        rw [hfs] at this
        simp [Function.comp_def] at this
        omega
      rcases fs with _ | ⟨⟨h', l⟩, rest⟩
      · simp [carry, hm1, h2]
        simpa using hfs.symm
      · have := hd ⟨h', l⟩ (by simp)
        simp only [carry]
        have hne : (h == h') = false := by simp; simp at this; omega
        rw [hne]
        simp only [Bool.false_eq_true, if_false, List.map_cons, hm1, if_true, h2, List.cons_append, List.nil_append, List.map_map]
        simp only [List.map_cons] at hfs
        rw [hfs]; simp

private theorem svFp (H : Bytes → Bytes) : ∀ xs : List Bytes, xs.length < 2 ^ 64 →
    (xs.foldl (frontierPush H) []).map (·.1) = peaksOf xs.length := by
  intro xs
  induction xs using snoc_ind with
  | h0 => intro _; simp [peaksOf]
  | hs ys x ih =>
    intro hn
    rw [List.foldl_append]; simp only [List.foldl_cons, List.foldl_nil]
    have hn' : ys.length < 2 ^ 64 := by simp at hn; omega
    have := carry_peaks H 64 0 (leafHash H PD x) (ys.foldl (frontierPush H) []) ys.length
      (by have := ih hn'; simpa [peaksOf, svPk] using this) (by simp at hn; omega)
    simpa [frontierPush, List.length_append, peaksOf, svPk] using this

private theorem carry_len (H : Bytes → Bytes) (hH : HashLen H) : ∀ (f h : Nat) (r : Bytes) (fs : List (Nat × Bytes)),
    r.length = 64 → (∀ e ∈ fs, e.2.length = 64) → ∀ e ∈ carry H f h r fs, e.2.length = 64 := by
  intro f
  induction f with
  | zero =>
    intro h r fs hr hfs e he
    simp only [carry, List.mem_cons] at he
    rcases he with rfl | he
    · exact hr
    · exact hfs e he
  | succ f ih =>
    intro h r fs hr hfs
    rcases fs with _ | ⟨⟨h', l⟩, rest⟩
    · intro e he; simp only [carry, List.mem_cons, List.not_mem_nil, or_false] at he; subst he; exact hr
    · simp only [carry]
      split
      · exact ih _ _ rest (by simp only [nodeHash]; exact hH _) (fun e he => hfs e (List.mem_cons_of_mem _ he))
      · intro e he
        simp only [List.mem_cons] at he
        rcases he with rfl | rfl | he
        · exact hr
        · exact hfs _ (by simp)
        · exact hfs e (List.mem_cons_of_mem _ he)

private theorem fs_len (H : Bytes → Bytes) (hH : HashLen H) : ∀ xs : List Bytes,
    ∀ e ∈ xs.foldl (frontierPush H) [], e.2.length = 64 := by
  intro xs
  induction xs using snoc_ind with
  | h0 => simp
  | hs ys x ih =>
    rw [List.foldl_append]; simp only [List.foldl_cons, List.foldl_nil]
    exact carry_len H hH 64 0 _ _ (by simp only [leafHash]; exact hH _) ih

private theorem chunks_flat : ∀ (f : Nat) (ls : List Bytes), ls.length ≤ f → (∀ a ∈ ls, a.length = 64) →
    chunks f ls.flatten = ls := by
  intro f
  induction f with
  | zero => intro ls h _; have : ls = [] := List.eq_nil_of_length_eq_zero (by omega); subst this; simp [chunks]
  | succ f ih =>
    intro ls hl ha
    rcases ls with _ | ⟨a, t⟩
    · simp [chunks]
    · have ha' := ha a (by simp)
      have hne : (a ++ t.flatten).isEmpty = false := by
        cases a with
        | nil => simp at ha'
        | cons _ _ => simp
      simp only [List.flatten_cons, chunks, hne, Bool.false_eq_true, if_false]
      rw [List.take_left' ha', List.drop_left' ha', ih t (by simpa using hl) (fun x hx => ha x (by simp [hx]))]

private theorem be_eq_natBE {w n : Nat} (h : n < 256 ^ w) : be w n = some (natBE w n) := by
  unfold be natBE; rw [if_pos h]

theorem listRoot_frontier (H : Bytes → Bytes) (xs : List Bytes) (hn : xs.length < 2 ^ 64) :
    frontierRoot H (xs.foldl (frontierPush H) []) = listRoot H xs := sorry

theorem frontier_peaks (H : Bytes → Bytes) (hH : HashLen H) (xs : List Bytes) (hn : xs.length < 2 ^ 64) :
    (xs.foldl (frontierPush H) []).map (·.1) = peaksOf xs.length := svFp H xs hn

theorem keyVal_parse (H : Bytes → Bytes) (hH : HashLen H) (xs : List Bytes) (v : Bytes)
    (h : keyVal xs.length (xs.foldl (frontierPush H) []) = some v) :
    parseKeyVal v = some (xs.length, xs.foldl (frontierPush H) []) := by
  obtain ⟨c, hc, hv⟩ : ∃ c, be 8 xs.length = some c ∧ v = c ++ ((xs.foldl (frontierPush H) []).map (·.2)).flatten := by
    cases hb : be 8 xs.length with
    | none => simp [keyVal, hb] at h
    | some c => refine ⟨c, rfl, ?_⟩; simp [keyVal, hb] at h; exact h.symm
  have hlt : xs.length < 256 ^ 8 := by
    unfold be at hc; split at hc
    · assumption
    · simp at hc
  have hlt' : xs.length < 2 ^ 64 := by
    have : (256 : Nat) ^ 8 = 2 ^ 64 := by decide
    omega
  have hc' : c = natBE 8 xs.length := by
    rw [be_eq_natBE hlt] at hc; exact (Option.some.inj hc).symm
  have hfp := svFp H xs hlt'
  have hl := fs_len H hH xs
  subst hv; clear h
  generalize xs.foldl (frontierPush H) [] = fs at hfp hl ⊢
  have hcl : c.length = 8 := by rw [hc']; simp [natBE]
  have hflat : ((fs.map (·.2)).flatten).length = 64 * fs.length := by
    have : ∀ ls : List Bytes, (∀ a ∈ ls, a.length = 64) → ls.flatten.length = 64 * ls.length := by
      intro ls; induction ls with
      | nil => simp
      | cons a t ih => intro ha; (simp [ha a (by simp), ih (fun x hx => ha x (by simp [hx]))]) <;> omega
    rw [this _ (by intro a ha; rw [List.mem_map] at ha; obtain ⟨e, he, rfl⟩ := ha; exact hl e he)]; simp
  have hfsl : fs.length = (peaksOf xs.length).length := by rw [← hfp]; simp
  have hle : fs.length ≤ 64 := by
    rw [hfsl]; unfold peaksOf; exact Nat.le_trans (List.length_filter_le _ _) (by simp)
  unfold parseKeyVal
  have ht : (c ++ (fs.map (·.2)).flatten).take 8 = c := by rw [List.take_left' hcl]
  have hd : (c ++ (fs.map (·.2)).flatten).drop 8 = (fs.map (·.2)).flatten := by rw [List.drop_left' hcl]
  rw [ht, hd, hc', beNat_natBE _ _ hlt]
  have hz : ∀ l : List (Nat × Bytes), (l.map (·.1)).zip (l.map (·.2)) = l := by
    intro l; induction l with
    | nil => rfl
    | cons a t ih => simp [ih]
  have hb : ((natBE 8 xs.length ++ (fs.map (·.2)).flatten).length == 8 + 64 * (fs.map (·.1)).length) = true := by
    have : (natBE 8 xs.length).length = 8 := by rw [← hc']; exact hcl
    simp only [List.length_append, this, hflat, List.length_map, beq_iff_eq]
  rw [chunks_flat 64 _ (by simpa using hle) (by intro a ha; rw [List.mem_map] at ha; obtain ⟨e, he, rfl⟩ := ha; exact hl e he)]
  dsimp only
  rw [← hfp, if_pos hb, hz]


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

private theorem pu_take_even (H : Bytes → Bytes) (d : Bytes) : ∀ (lv : List Bytes) (j : Nat), j % 2 = 0 →
    pairUp H d (lv.take j) = (pairUp H d lv).take (j / 2)
  | [], j, _ => by simp [pairUp]
  | [a], j, h => by
    rcases j with _ | j
    · simp [pairUp]
    · have : 1 ≤ (j + 1) / 2 := by omega
      simp [pairUp, List.take_of_length_le, this]
  | a :: b :: rest, j, h => by
    rcases j with _ | _ | j
    · simp [pairUp]
    · omega
    · have := pu_take_even H d rest j (by omega)
      have e : (j + 1 + 1) / 2 = j / 2 + 1 := by omega
      simp [pairUp, this, e]

private theorem pu_len (H : Bytes → Bytes) (d : Bytes) : ∀ (lv : List Bytes), (pairUp H d lv).length = (lv.length + 1) / 2
  | [] => by simp [pairUp]
  | [a] => by simp [pairUp]
  | a :: b :: rest => by
    have := pu_len H d rest
    simp [pairUp, this]; omega

private theorem pu_len64 (H : Bytes → Bytes) (hH : HashLen H) (d : Bytes) : ∀ (lv : List Bytes), (∀ a ∈ lv, a.length = 64) →
    ∀ a ∈ pairUp H d lv, a.length = 64
  | [], _ => by simp [pairUp]
  | [a], h => by simpa [pairUp] using h
  | a :: b :: rest, h => by
    intro x hx
    simp only [pairUp, List.mem_cons] at hx
    rcases hx with rfl | hx
    · simp only [nodeHash]; exact hH _
    · exact pu_len64 H hH d rest (fun y hy => h y (by simp [hy])) x hx

private theorem fk_run (H : Bytes → Bytes) (d : Bytes) : ∀ (f : Nat) (lv : List Bytes) (j : Nat), 1 ≤ j → j ≤ lv.length →
    lv.length ≤ 2 ^ f → ∃ ins, firstKRun H d f lv.length (lv.take j) (firstKPf H d f j lv) = some (treeRoot H d f lv, ins) := by
  intro f
  induction f with
  | zero =>
    intro lv j h1 h2 h3
    rcases lv with _ | ⟨x, _ | ⟨y, t⟩⟩
    · simp at h2; omega
    · have : j = 1 := by simp at h2; omega
      subst this
      exact ⟨[], by simp [firstKRun.eq_1, treeRoot, firstKPf]⟩
    · simp at h3
  | succ f ih =>
    intro lv j h1 h2 h3
    by_cases hl : lv.length ≤ 1
    · rcases lv with _ | ⟨x, _ | ⟨y, t⟩⟩
      · simp at h2; omega
      · have : j = 1 := by simp at h2; omega
        subst this
        exact ⟨[], by simp [firstKRun.eq_1, treeRoot, firstKPf]⟩
      · simp at hl
    · have hl : 1 < lv.length := by omega
      have hlne : lv ≠ [] := by rintro rfl; simp at hl
      have hroot : treeRoot H d (f + 1) lv = treeRoot H d f (pairUp H d lv) := by
        rcases lv with _ | ⟨x, _ | ⟨y, t⟩⟩
        · simp at hl
        · simp at hl
        · simp [treeRoot]
      rw [hroot]
      have hlen := pu_len H d lv
      have hpf : firstKPf H d (f + 1) j lv = (if j % 2 == 1 && decide (j < lv.length) then [lv.getD j []] else []) ++
          firstKPf H d f ((j + 1) / 2) (pairUp H d lv) := by
        simp only [firstKPf]; rw [if_neg (by omega)]
      rw [hpf, firstKRun.eq_3 _ _ _ _ _ _ (by intro r h _ _; omega)]
      have hkl : (lv.take j).length = j := by simp; omega
      have hih : ∀ j', 1 ≤ j' → j' = (j + 1) / 2 → ∃ ins, firstKRun H d f ((lv.length + 1) / 2) ((pairUp H d lv).take j') (firstKPf H d f j' (pairUp H d lv)) = some (treeRoot H d f (pairUp H d lv), ins) := by
        intro j' hj' hjj
        have := ih (pairUp H d lv) j' hj' (by rw [hlen]; omega) (by rw [hlen]; rw [Nat.pow_succ] at h3; omega)
        rwa [hlen] at this
      by_cases hodd : j % 2 = 1 ∧ j < lv.length
      · obtain ⟨y, hy⟩ : ∃ y, lv[j]? = some y := ⟨lv[j], List.getElem?_eq_getElem hodd.2⟩
        have hpe : (j % 2 == 1 && decide (j < lv.length)) = true := by simp [hodd]
        obtain ⟨ins, hins⟩ := hih ((j + 1) / 2) (by omega) rfl
        refine ⟨levelInputs d (lv.take (j + 1)) ++ ins, ?_⟩
        have hks : lv.take j ++ List.take 1 ([lv.getD j []] ++ firstKPf H d f ((j + 1) / 2) (pairUp H d lv)) = lv.take (j + 1) := by
          simp [List.take_succ, hy]
        simp only [hkl, hpe, if_true, hks, List.drop_append]
        rw [pu_take_even H d lv (j + 1) (by omega)]
        split
        · rename_i hc; exfalso; simp [List.take_eq_nil_iff, hlne] at hc; omega
        · simp only [List.length_singleton, Nat.sub_self, List.drop_zero, List.drop_succ_cons, List.drop_nil, List.nil_append]
          rw [hins]; rfl
      · have e : ((lv.take j).length % 2 == 1 && decide ((lv.take j).length < lv.length)) = false := by
          simp [hkl]; omega
        have hpe : (j % 2 == 1 && decide (j < lv.length)) = false := by simp; omega
        have hpair : pairUp H d (lv.take j) = (pairUp H d lv).take ((j + 1) / 2) := by
          by_cases h2' : j % 2 = 0
          · rw [pu_take_even H d lv j h2']; congr 1; omega
          · have hj : j = lv.length := by omega
            rw [hj, List.take_length, ← hlen, List.take_length]
        obtain ⟨ins, hins⟩ := hih ((j + 1) / 2) (by omega) rfl
        refine ⟨levelInputs d (lv.take j) ++ ins, ?_⟩
        simp only [hkl, e, hpe, Bool.false_eq_true, if_false, List.nil_append]
        split
        · rename_i hc; exfalso; simp [List.take_eq_nil_iff, hlne] at hc; omega
        · rw [hpair, hins]; rfl

private theorem fkpf_len (H : Bytes → Bytes) (hH : HashLen H) (d : Bytes) : ∀ (f : Nat) (lv : List Bytes) (j : Nat),
    (∀ a ∈ lv, a.length = 64) → ∀ a ∈ firstKPf H d f j lv, a.length = 64 := by
  intro f
  induction f with
  | zero => intro lv j _ a ha; simp [firstKPf] at ha
  | succ f ih =>
    intro lv j hlv a ha
    simp only [firstKPf] at ha
    split at ha
    · simp at ha
    · rw [List.mem_append] at ha
      rcases ha with ha | ha
      · split at ha
        · rename_i hc
          simp at hc
          rw [List.mem_singleton] at ha; subst ha
          simp [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hc.2]
          exact hlv _ (List.getElem_mem hc.2)
        · simp at ha
      · exact ih _ _ (pu_len64 H hH d lv hlv) a ha

private theorem coll_mono (H : Bytes → Bytes) {A A' B B' : List Bytes} (hA : ∀ x ∈ A, x ∈ A') (hB : ∀ x ∈ B, x ∈ B') :
    Collision H A B → Collision H A' B' := by
  rintro ⟨x, hx, y, hy, hne, he⟩
  exact ⟨x, hA x hx, y, hB y hy, hne, he⟩

private theorem pair_prefix (H : Bytes → Bytes) (d : Bytes) : ∀ (ks T : List Bytes), (∀ a ∈ ks, a.length = 64) →
    (∀ a ∈ T, a.length = 64) → ks.length ≤ T.length → (ks.length % 2 = 0 ∨ ks.length = T.length) →
    pairUp H d ks = (pairUp H d T).take ((ks.length + 1) / 2) →
    ks = T.take ks.length ∨ Collision H (levelInputs d ks) (levelInputs d T)
  | [], T, _, _, _, _, _ => Or.inl (by simp)
  | [a], T, _, hT, hl, hp, h => by
    rcases T with _ | ⟨c, _ | ⟨e, t⟩⟩
    · simp at hl
    · left; simpa [pairUp] using h
    · have := hp; simp only [List.length_cons, List.length_nil] at this; omega
  | a :: b :: rest, T, hK, hT, hl, hp, h => by
    rcases T with _ | ⟨c, _ | ⟨e, t⟩⟩
    · simp at hl
    · simp at hl
    · have hlr : rest.length ≤ t.length := by simp only [List.length_cons] at hl; omega
      have e2 : (rest.length + 1 + 1 + 1) / 2 = (rest.length + 1) / 2 + 1 := by omega
      simp only [pairUp, List.length_cons, e2, List.take_succ_cons, List.cons.injEq] at h
      obtain ⟨h1, h2⟩ := h
      by_cases hab : d ++ 1 :: (a ++ b) = d ++ 1 :: (c ++ e)
      · have hab' : a ++ b = c ++ e := by simpa using hab
        have hac : a.length = c.length := by rw [hK a (by simp), hT c (by simp)]
        obtain ⟨rfl, rfl⟩ := List.append_inj hab' hac
        rcases pair_prefix H d rest t (fun x hx => hK x (by simp [hx])) (fun x hx => hT x (by simp [hx])) hlr
            (by simp only [List.length_cons] at hp; omega) h2 with h3 | h3
        · left; rw [List.length_cons, List.length_cons, List.take_succ_cons, List.take_succ_cons, ← h3]
        · right; exact coll_mono H (fun x hx => by simp [levelInputs, hx]) (fun x hx => by simp [levelInputs, hx]) h3
      · right
        exact ⟨d ++ 1 :: (a ++ b), by simp [levelInputs], d ++ 1 :: (c ++ e), by simp [levelInputs], hab, h1⟩

private theorem fk_base (H : Bytes → Bytes) (d : Bytes) (f : Nat) (r1 r : Bytes) (ins : List Bytes) (T : List Bytes)
    (hT : T.length = 1) (hrun : (some (r1, ([] : List Bytes)) : Option (Bytes × List Bytes)) = some (r, ins))
    (hroot : treeRoot H d f T = r) : [r1] = T.take [r1].length ∨ Collision H ins (treeInputsL H d f T) := by
  rcases T with _ | ⟨t, _ | ⟨_, _⟩⟩
  · simp at hT
  · have : treeRoot H d f [t] = t := by cases f <;> rfl
    rw [this] at hroot
    left
    obtain ⟨h, -⟩ := Prod.mk.inj (Option.some.inj hrun)
    simp [h, hroot]
  · simp at hT

private theorem tr_succ (H : Bytes → Bytes) (d : Bytes) (f : Nat) (T : List Bytes) (h : 1 < T.length) :
    treeRoot H d (f + 1) T = treeRoot H d f (pairUp H d T) := by
  rcases T with _ | ⟨x, _ | ⟨y, t⟩⟩
  · simp at h
  · simp at h
  · simp [treeRoot]

private theorem leaf_inj (H : Bytes → Bytes) : ∀ ys zs : List Bytes, ys.map (leafHash H PD) = zs.map (leafHash H PD) →
    ys = zs ∨ Collision H (ys.map (fun y => PD ++ 0 :: y)) (zs.map (fun y => PD ++ 0 :: y))
  | [], [], _ => Or.inl rfl
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h
  | y :: ys, z :: zs, h => by
    simp only [List.map_cons, List.cons.injEq] at h
    obtain ⟨h1, h2⟩ := h
    by_cases hyz : y = z
    · subst hyz
      rcases leaf_inj H ys zs h2 with h3 | h3
      · exact Or.inl (by rw [h3])
      · exact Or.inr (coll_mono H (fun x hx => by simp [hx]) (fun x hx => by simp [hx]) h3)
    · right
      refine ⟨PD ++ 0 :: y, by simp, PD ++ 0 :: z, by simp, ?_, h1⟩
      intro he
      apply hyz
      have := List.append_cancel_left he
      simpa using this

private theorem fk_sound' (H : Bytes → Bytes) (hH : HashLen H) (d : Bytes) : ∀ (f n : Nat) (ks pf : List Bytes) (r : Bytes) (ins : List Bytes),
    firstKRun H d f n ks pf = some (r, ins) → (∀ a ∈ ks, a.length = 64) → (∀ a ∈ pf, a.length = 64) →
    ∀ T : List Bytes, T.length = n → (∀ a ∈ T, a.length = 64) → treeRoot H d f T = r →
    ks = T.take ks.length ∨ Collision H ins (treeInputsL H d f T) := by
  intro f
  induction f with
  | zero =>
    intro n ks pf r ins hrun hks hpf T hT hTl hroot
    by_cases hc : ∃ r1, n = 1 ∧ ks = [r1] ∧ pf = []
    · obtain ⟨r1, rfl, rfl, rfl⟩ := hc
      rw [firstKRun.eq_1] at hrun
      exact fk_base H d 0 r1 r ins T hT hrun hroot
    · rw [firstKRun.eq_2 _ _ _ _ _ (fun r h1 h2 h3 => hc ⟨r, h1, h2, h3⟩)] at hrun; simp at hrun
  | succ f ih =>
    intro n ks pf r ins hrun hks hpf T hT hTl hroot
    by_cases hc : ∃ r1, n = 1 ∧ ks = [r1] ∧ pf = []
    · obtain ⟨r1, rfl, rfl, rfl⟩ := hc
      rw [firstKRun.eq_1] at hrun
      exact fk_base H d (f + 1) r1 r ins T hT hrun hroot
    · rw [firstKRun.eq_3 _ _ _ _ _ _ (fun r h1 h2 h3 => hc ⟨r, h1, h2, h3⟩)] at hrun
      split at hrun
      · simp at hrun
      · rename_i hg
        simp at hg
        obtain ⟨⟨⟨hne, hn1⟩, hkn⟩, hpe⟩ := hg
        have hT1 : 1 < T.length := by omega
        have hroot' : treeRoot H d f (pairUp H d T) = r := by rw [← tr_succ H d f T hT1]; exact hroot
        have step : ∀ (ks' pf' : List Bytes) (r' : Bytes) (ins' : List Bytes), (∀ a ∈ ks', a.length = 64) →
            (∀ a ∈ pf', a.length = 64) → ks'.length ≤ n → (ks'.length % 2 = 0 ∨ ks'.length = n) →
            firstKRun H d f ((n + 1) / 2) (pairUp H d ks') pf' = some (r', ins') → r' = r →
            ks' = T.take ks'.length ∨ Collision H (levelInputs d ks' ++ ins') (treeInputsL H d (f + 1) T) := by
          intro ks' pf' r' ins' hks' hpf' hl hpar hr hrr
          subst hrr
          have hrec := ih ((n + 1) / 2) (pairUp H d ks') pf' r' ins' hr (pu_len64 H hH d ks' hks') hpf'
            (pairUp H d T) (by rw [pu_len, hT]) (pu_len64 H hH d T hTl) hroot'
          have hti : treeInputsL H d (f + 1) T = levelInputs d T ++ treeInputsL H d f (pairUp H d T) := by
            rcases T with _ | ⟨x, _ | ⟨y, t⟩⟩
            · simp at hT1
            · simp at hT1
            · simp [treeInputsL]
          rw [hti]
          rcases hrec with h | h
          · have hlen := pu_len H d ks'
            rw [hlen] at h
            rcases pair_prefix H d ks' T hks' hTl (by omega) (by rcases hpar with h | h; exact Or.inl h; exact Or.inr (by omega)) h with h3 | h3
            · exact Or.inl h3
            · exact Or.inr (coll_mono H (fun x hx => by simp [hx]) (fun x hx => by simp [hx]) h3)
          · exact Or.inr (coll_mono H (fun x hx => by simp [hx]) (fun x hx => by simp [hx]) h)
        have pre : ∀ ks' : List Bytes, (∃ x, ks' = ks ++ x) → ks' = T.take ks'.length → ks = T.take ks.length := by
          rintro ks' ⟨x, rfl⟩ h
          have h2 : (ks ++ x).take ks.length = ks := by simp
          calc ks = (ks ++ x).take ks.length := h2.symm
            _ = (T.take (ks ++ x).length).take ks.length := by rw [← h]
            _ = T.take ks.length := by
              rw [List.take_take]; congr 1; simp
        by_cases hodd : (ks.length % 2 == 1 && decide (ks.length < n)) = true
        · simp only [hodd, ↓reduceIte] at hrun
          obtain ⟨⟨r', ins'⟩, hr, he⟩ := Option.map_eq_some_iff.mp hrun
          injection he with h1 h2
          subst h2
          have hodd2 : ks.length % 2 = 1 ∧ ks.length < n := by simpa using hodd
          have hpne : pf ≠ [] := hpe hodd2.1 hodd2.2
          have hl1 : (pf.take 1).length = 1 := by
            rcases pf with _ | ⟨p, ps⟩
            · exact absurd rfl hpne
            · simp
          rcases step (ks ++ pf.take 1) (pf.drop 1) r' ins'
              (fun a ha => by
                rcases List.mem_append.mp ha with h | h
                · exact hks a h
                · exact hpf a (List.mem_of_mem_take h))
              (fun a ha => hpf a (List.mem_of_mem_drop ha))
              (by simp only [List.length_append, hl1]; omega)
              (Or.inl (by simp only [List.length_append, hl1]; omega)) hr h1 with h | h
          · exact Or.inl (pre _ ⟨_, rfl⟩ h)
          · exact Or.inr h
        · simp only [hodd, Bool.false_eq_true, ↓reduceIte] at hrun
          obtain ⟨⟨r', ins'⟩, hr, he⟩ := Option.map_eq_some_iff.mp hrun
          injection he with h1 h2
          subst h2
          have hpar : ks.length % 2 = 0 ∨ ks.length = n := by
            by_cases h3 : ks.length % 2 = 1
            · right
              have : ¬ ks.length < n := fun h4 => hodd (by simp [h3, h4])
              omega
            · left; omega
          rcases step ks pf r' ins' hks hpf hkn hpar hr h1 with h | h
          · exact Or.inl h
          · exact Or.inr h

theorem firstK_sound (H : Bytes → Bytes) (hH : HashLen H) (xs ys pf : List Bytes) (hn : xs.length < 2 ^ 64)
    (hv : verifyFirstK H (listRoot H xs) xs.length ys pf = true) :
    ys = xs.take K ∨ Collision H (firstKInputs H xs.length ys pf) (listInputs H xs) := by
  simp only [verifyFirstK, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq, List.all_eq_true, Option.any_eq_true] at hv
  obtain ⟨⟨⟨⟨hn1, hys⟩, hyl⟩, hpf⟩, ⟨⟨r', ins⟩, hrun, hr⟩⟩ := hv
  have hlv : ∀ a ∈ xs.map (leafHash H PD), a.length = 64 := by
    intro a ha; rw [List.mem_map] at ha; obtain ⟨x, _, rfl⟩ := ha
    simp only [leafHash]; exact hH _
  have hlv' : ∀ a ∈ ys.map (leafHash H PD), a.length = 64 := by
    intro a ha; rw [List.mem_map] at ha; obtain ⟨x, _, rfl⟩ := ha
    simp only [leafHash]; exact hH _
  have hpf' : ∀ a ∈ pf, a.length = 64 := fun a ha => by simpa [digestBytes] using hpf a ha
  have hr' : r' = listRoot H xs := by simpa using hr
  have := fk_sound' H hH PD 64 xs.length (ys.map (leafHash H PD)) pf r' ins hrun hlv' hpf'
    (xs.map (leafHash H PD)) (by simp) hlv (by rw [hr']; rfl)
  have hfi : firstKInputs H xs.length ys pf = ys.map (fun y => PD ++ 0 :: y) ++ ins := by
    simp [firstKInputs, hrun]
  rw [hfi]
  have htk : (xs.take K).map (leafHash H PD) = (xs.map (leafHash H PD)).take (min K xs.length) := by
    rw [List.map_take]; rcases Nat.le_total K xs.length with h | h
    · rw [Nat.min_eq_left h]
    · rw [Nat.min_eq_right h]; simp [List.take_of_length_le, h]
  rcases this with h | h
  · simp only [List.length_map, hys] at h
    rw [← htk] at h
    rcases leaf_inj H ys (xs.take K) h with h3 | h3
    · exact Or.inl h3
    · right
      refine coll_mono H (fun x hx => by simp [hx]) (fun x hx => ?_) h3
      simp only [listInputs, List.mem_append, List.mem_map] at hx ⊢
      rcases hx with ⟨y, hy, rfl⟩
      exact Or.inl ⟨y, List.mem_of_mem_take hy, rfl⟩
  · right
    exact coll_mono H (fun x hx => by simp [hx]) (fun x hx => by simp [listInputs, hx]) h

theorem firstK_complete (H : Bytes → Bytes) (hH : HashLen H) (xs : List Bytes) (h1 : 1 ≤ xs.length)
    (hn : xs.length < 2 ^ 64) (hx : ∀ x ∈ xs, x.length = 8 + idWidth) :
    verifyFirstK H (listRoot H xs) xs.length (xs.take K)
      (firstKPf H PD 64 (min K xs.length) (xs.map (leafHash H PD))) = true := by
  have hlv : ∀ a ∈ xs.map (leafHash H PD), a.length = 64 := by
    intro a ha; rw [List.mem_map] at ha; obtain ⟨x, _, rfl⟩ := ha
    simp only [leafHash]; exact hH _
  have hlen : (xs.map (leafHash H PD)).length = xs.length := by simp
  obtain ⟨ins, hins⟩ := fk_run H PD 64 (xs.map (leafHash H PD)) (min K xs.length) (by simp [K]; omega)
    (by rw [hlen]; exact Nat.min_le_right _ _) (by rw [hlen]; have : (2:Nat) ^ 64 = 2 ^ 64 := rfl; omega)
  rw [hlen] at hins
  have htk : (xs.take K).map (leafHash H PD) = (xs.map (leafHash H PD)).take (min K xs.length) := by
    rw [List.map_take]
    rcases Nat.le_total K xs.length with h | h
    · rw [Nat.min_eq_left h]
    · rw [Nat.min_eq_right h, List.take_of_length_le (by omega), List.take_of_length_le (by omega)]
  unfold verifyFirstK
  simp only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq, List.all_eq_true]
  refine ⟨⟨⟨⟨h1, by simp⟩, fun y hy => by simpa using hx y (List.mem_of_mem_take hy)⟩, fun a ha => ?_⟩, ?_⟩
  · simpa [digestBytes] using fkpf_len H hH PD 64 _ _ hlv a ha
  · rw [htk, hins]; simp [listRoot]

/-! ## 5. Carried semantics and the reachable-state invariant (H5) -/

/-- Reachable states: ids unique across both sets (rows unique, rel ∩ unr = ∅, `own` false on
    unresolved rows) and counts exact. -/
def Inv (rel unr : Snapshot Line) : Prop :=
  ((rel.entries ++ unr.entries).map (·.id)).Nodup ∧ rel.count = rel.entries.length ∧
    unr.count = unr.entries.length

private theorem sv_view_self (t : Nat) (p : Snapshot Line) : view t p (some p) = p := by
  unfold view; split <;> rfl

private theorem chained_self (t : Nat) (s : Snapshot Line) :
    chained t s (some s) = (s.entries.length == s.count && validDate s.asOf && decide (s.asOf ≤ t)) := by
  have h : s.entries.all s.entries.contains = true := by
    simp only [List.all_eq_true]; intro x hx; simpa using hx
  simp [chained, h]

/-- The view is already proved: `carried_sets` (DecideLayer.lean:28). -/
theorem carried_loose (t : Nat) (s : Snapshot Line) : loose t s (some s) = [] := by
  unfold loose; split
  · rfl
  · simp [entries, List.filter_eq_nil_iff]

theorem carried_chained (t : Nat) (s : Snapshot Line) (hc : s.count = s.entries.length) :
    chained t s (some s) = (validDate s.asOf && decide (s.asOf ≤ t)) := by
  rw [chained_self, hc]; simp

private theorem sv_filter_and_lt {α : Type} (L : List α) (P Q : α → Bool) :
    (L.filter fun x => P x && Q x).length < (L.filter Q).length ↔ ∃ x ∈ L, Q x = true ∧ P x = false := by
  have hle : ∀ L : List α, (L.filter fun x => P x && Q x).length ≤ (L.filter Q).length := by
    intro L
    induction L with
    | nil => simp
    | cons a L ih =>
      by_cases hq : Q a = true <;> by_cases hp : P a = true <;> simp [hq, hp] <;> omega
  induction L with
  | nil => simp
  | cons a L ih =>
    have := hle L
    by_cases hq : Q a = true <;> by_cases hp : P a = true <;>
      simp [hq, hp, ih] <;> first | omega | skip

private theorem sv_released_carried (c₀ : Ctx) (rel unr : Snapshot Line) :
    releasedSet (carried c₀ rel unr) = rel.entries := by simp [releasedSet, carried, sv_view_self]

private theorem sv_unresolved_carried (c₀ : Ctx) (rel unr : Snapshot Line) :
    unresolvedSet (carried c₀ rel unr) = unr.entries := by simp [unresolvedSet, carried, sv_view_self]

/-- `seen0` as a count comparison; the excluded count comes from ROW probes of the batch. -/
theorem seen0_count (c₀ : Ctx) (rel unr : Snapshot Line) (b : List Line) (q : Key) :
    (seen0 (carried c₀ rel unr) b).contains q =
      decide ((rel.entries.filter fun x => c₀.redo.contains x.pay && b.contains x && (keys x).contains q).length
        < (rel.entries.filter fun x => (keys x).contains q).length) := by
  have hf : ∀ x ∈ rel.entries, (!(own (carried c₀ rel unr) x && b.contains x)) =
      !(c₀.redo.contains x.pay && b.contains x) := by
    intro x hx
    have hc : (carried c₀ rel unr).redo = c₀.redo := rfl
    simp only [own, hc, sv_released_carried]
    simp [hx]
  unfold seen0
  rw [sv_released_carried, List.filter_congr hf]
  rw [Bool.eq_iff_iff, decide_eq_true_iff, sv_filter_and_lt rel.entries
    (fun x => c₀.redo.contains x.pay && b.contains x) (fun x => (keys x).contains q)]
  simp [List.mem_flatMap, List.mem_filter]
  constructor
  · rintro ⟨x, ⟨hx, hp⟩, hq⟩; exact ⟨x, hx, hq, fun ha => hp.elim (fun h => absurd ha h) id⟩
  · rintro ⟨x, hx, hq, hp⟩; exact ⟨x, ⟨hx, Decidable.not_or_of_imp hp⟩, hq⟩

/-- The CAP near claim is local: day keys of today's covering spans, invalid dates, or the aggregate key
    when enrollment is unusable. Exact and id keys are always claimed. -/
theorem pending_near_cap (c₀ : Ctx) (rel unr : Snapshot Line) (hi : Inv rel unr) (m mo : Nat) :
    (pending (carried c₀ rel unr)).contains [0, m, mo] =
      unr.entries.any fun x => nearKey x == [0, m, mo] &&
        (!usable c₀.today 7 okSpan c₀.enrollment || !validDate x.date || enrolled c₀ x) := by
  have hd : ∀ x ∈ unr.entries, x ∉ rel.entries := by
    intro x hx hr
    have h := hi.1
    rw [List.map_append, List.nodup_append] at h
    exact h.2.2 x.id (List.mem_map.mpr ⟨x, hr, rfl⟩) x.id (List.mem_map.mpr ⟨x, hx, rfl⟩) rfl
  have hown : ∀ x ∈ unr.entries, own (carried c₀ rel unr) x = false := by
    intro x hx
    have := hd x hx
    simp only [own, sv_released_carried]
    simp [this]
  have hk : ∀ x ∈ unr.entries, ([0, m, mo] ∈ claim (carried c₀ rel unr) x) ↔
      ((nearKey x == [0, m, mo] &&
        (!usable c₀.today 7 okSpan c₀.enrollment || !validDate x.date || enrolled c₀ x)) = true) := by
    intro x hx
    have ho := hown x hx
    by_cases hcap : isCap x = true
    · have e1 : (carried c₀ rel unr).enrollment = c₀.enrollment := rfl
      have e2 : (carried c₀ rel unr).today = c₀.today := rfl
      simp [claim, notEnrolled, certain, enrolled, ho, hcap, nearKey, exactKey, idKey, keys, e1, e2]
      by_cases hE : ∃ s, s ∈ entries c₀.enrollment ∧ covers x s = true
      · have hE' : ¬ ∀ s, s ∈ entries c₀.enrollment → covers x s = false := fun h => by
          obtain ⟨s, hs, hc⟩ := hE; simp [h s hs] at hc
        by_cases hu : usable c₀.today 7 okSpan c₀.enrollment = true <;>
          by_cases hv : validDate x.date = true <;> simp [hu, hv, hE, hE'] <;> first | done | (constructor <;> rintro ⟨a, b⟩ <;> exact ⟨a.symm, b.symm⟩)
      · have hE' : ∀ s, s ∈ entries c₀.enrollment → covers x s = false := fun s hs => by
          cases h : covers x s
          · rfl
          · exact absurd ⟨s, hs, h⟩ hE
        by_cases hu : usable c₀.today 7 okSpan c₀.enrollment = true <;>
          by_cases hv : validDate x.date = true <;> simp [hu, hv, hE, eq_true hE'] <;> first | done | (constructor <;> rintro ⟨a, b⟩ <;> exact ⟨a.symm, b.symm⟩)
    · simp [claim, ho, hcap, nearKey, exactKey, idKey, keys]
  unfold pending
  rw [sv_unresolved_carried, Bool.eq_iff_iff, List.any_eq_true]
  constructor
  · intro h
    have h' : [0, m, mo] ∈ unr.entries.flatMap (claim (carried c₀ rel unr)) := by simpa using h
    obtain ⟨x, hx, hm⟩ := List.mem_flatMap.mp h'
    exact ⟨x, hx, (hk x hx).mp hm⟩
  · rintro ⟨x, hx, hm⟩
    have h' : [0, m, mo] ∈ unr.entries.flatMap (claim (carried c₀ rel unr)) :=
      List.mem_flatMap.mpr ⟨x, hx, (hk x hx).mpr hm⟩
    simpa using h'

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

private theorem bumpIf_ge {ok : Bool} {today a : Nat} (h : ok = true → a ≤ today) : a ≤ bumpIf ok today a := by
  unfold bumpIf; split
  · rename_i hh; simp [Bool.and_eq_true] at hh; exact h hh.1
  · exact Nat.le_refl _

private theorem chained_asOf_le {t : Nat} {s : Snapshot Line} (h : chained t s (some s) = true) : s.asOf ≤ t := by
  rw [chained_self] at h; simp at h; exact h.2

private theorem decideReg_carried_asOf (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (rel unr : Snapshot Line) :
    (decideReg (carried c₀ rel unr) k os b).released.asOf = rel.asOf ∧
      (decideReg (carried c₀ rel unr) k os b).unresolved.asOf = unr.asOf ∧
      (decideReg (carried c₀ rel unr) k os b).released.count = (decideReg (carried c₀ rel unr) k os b).released.entries.length ∧
      (decideReg (carried c₀ rel unr) k os b).unresolved.count = (decideReg (carried c₀ rel unr) k os b).unresolved.entries.length := by
  simp [decideReg, decideBatchIn, advance, carried, sv_view_self]

private theorem sv_carried_append (c₀ : Ctx) (rel unr : Snapshot Line) (k : Nat) (os : List Owner) (b : List Line) :
    (decideReg (carried c₀ rel unr) k os b).released.entries =
        rel.entries ++ (batchFresh (carried c₀ rel unr) (decideReg (carried c₀ rel unr) k os b)).1 ∧
      (decideReg (carried c₀ rel unr) k os b).unresolved.entries =
        unr.entries ++ (batchFresh (carried c₀ rel unr) (decideReg (carried c₀ rel unr) k os b)).2 := by
  have h1 : releasedSet (carried c₀ rel unr) = rel.entries := by simp [releasedSet, carried, sv_view_self]
  have h2 : unresolvedSet (carried c₀ rel unr) = unr.entries := by simp [unresolvedSet, carried, sv_view_self]
  simp only [batchFresh, h1, h2]
  simp [decideReg, decideBatchIn, advance, carried, sv_view_self]

private theorem decideRegT_sets (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (rel unr : Snapshot Line) :
    ∃ f1 f2, (decideRegT (carried c₀ rel unr) k os b).released =
        ⟨bumpSet c₀.today rel, rel.entries.length + f1.length, rel.entries ++ f1⟩ ∧
      (decideRegT (carried c₀ rel unr) k os b).unresolved =
        ⟨bumpSet c₀.today unr, unr.entries.length + f2.length, unr.entries ++ f2⟩ ∧
      batchFresh (carried c₀ rel unr) (decideRegT (carried c₀ rel unr) k os b) = (f1, f2) := by
  obtain ⟨e1, e2⟩ := sv_carried_append c₀ rel unr k os b
  obtain ⟨a1, a2, n1, n2⟩ := decideReg_carried_asOf c₀ k os b rel unr
  refine ⟨(batchFresh (carried c₀ rel unr) (decideReg (carried c₀ rel unr) k os b)).1,
    (batchFresh (carried c₀ rel unr) (decideReg (carried c₀ rel unr) k os b)).2, ?_, ?_, rfl⟩
  · show (⟨bumpIf (chained c₀.today rel (some rel)) c₀.today
        (decideReg (carried c₀ rel unr) k os b).released.asOf,
        (decideReg (carried c₀ rel unr) k os b).released.count,
        (decideReg (carried c₀ rel unr) k os b).released.entries⟩ : Snapshot Line) = _
    generalize (batchFresh (carried c₀ rel unr) (decideReg (carried c₀ rel unr) k os b)).1 = F at e1 ⊢
    rw [a1, n1, e1, chained_self]
    simp [bumpSet]
  · show (⟨bumpIf (chained c₀.today unr (some unr)) c₀.today
        (decideReg (carried c₀ rel unr) k os b).unresolved.asOf,
        (decideReg (carried c₀ rel unr) k os b).unresolved.count,
        (decideReg (carried c₀ rel unr) k os b).unresolved.entries⟩ : Snapshot Line) = _
    generalize (batchFresh (carried c₀ rel unr) (decideReg (carried c₀ rel unr) k os b)).2 = F at e2 ⊢
    rw [a2, n2, e2, chained_self]
    simp [bumpSet]

/-- KEPT. Added beside `replay_addsOf` (DecideLayer.lean:52-55, unchanged): whole snapshots, dates included. -/
theorem replayT_addsOfT (k : Nat) (g : Snapshot Line × Snapshot Line) (ts : List Batch) :
    replayT g ((ts.map (·.ctx.today)).zip (addsOfT k g ts)) = shardSetsT k g ts := by
  induction ts generalizing g with
  | nil => rfl
  | cons t ts ih =>
    obtain ⟨f1, f2, h1, h2, hf⟩ := decideRegT_sets t.ctx k t.owners t.lines g.1 g.2
    have := ih ((decideRegT (carried t.ctx g.1 g.2) k t.owners t.lines).released,
      (decideRegT (carried t.ctx g.1 g.2) k t.owners t.lines).unresolved)
    simp only [addsOfT, List.map_cons, List.zip_cons_cons, replayT, List.foldl_cons, shardSetsT] at this ⊢
    rw [hf, h1, h2]
    rw [h1, h2] at this
    exact this

def genesisSets (t : Nat) : Snapshot Line × Snapshot Line := (⟨t, 0, []⟩, ⟨t, 0, []⟩)

theorem genesis_chained (t : Nat) (ht : validDate t = true) :
    chained t (genesisSets t).1 (some (genesisSets t).1) = true ∧
      chained t (genesisSets t).2 (some (genesisSets t).2) = true := by
  simp [genesisSets, chained_self, ht]

theorem asOf_mono (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (rel unr : Snapshot Line) :
    rel.asOf ≤ (decideRegT (carried c₀ rel unr) k os b).released.asOf ∧
      unr.asOf ≤ (decideRegT (carried c₀ rel unr) k os b).unresolved.asOf := by
  obtain ⟨h1, h2, -, -⟩ := decideReg_carried_asOf c₀ k os b rel unr
  refine ⟨?_, ?_⟩
  · show rel.asOf ≤ bumpIf (chained c₀.today rel (some rel)) c₀.today
      (decideReg (carried c₀ rel unr) k os b).released.asOf
    rw [h1]; exact bumpIf_ge chained_asOf_le
  · show unr.asOf ≤ bumpIf (chained c₀.today unr (some unr)) c₀.today
      (decideReg (carried c₀ rel unr) k os b).unresolved.asOf
    rw [h2]; exact bumpIf_ge chained_asOf_le

/-- A dated set stays dated: after a batch on a valid `today` not before it, it is dated `today`. -/
theorem asOf_step (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (rel unr : Snapshot Line)
    (hi : Inv rel unr) (hr : validDate rel.asOf = true) (hu : validDate unr.asOf = true)
    (ht : validDate c₀.today = true) (hrt : rel.asOf ≤ c₀.today) (hut : unr.asOf ≤ c₀.today) :
    (decideRegT (carried c₀ rel unr) k os b).released.asOf = c₀.today ∧
      (decideRegT (carried c₀ rel unr) k os b).unresolved.asOf = c₀.today := by
  obtain ⟨h1, h2, -, -⟩ := decideReg_carried_asOf c₀ k os b rel unr
  have hc1 : chained c₀.today rel (some rel) = true := by
    rw [chained_self, hi.2.1]; simp [hr, hrt]
  have hc2 : chained c₀.today unr (some unr) = true := by
    rw [chained_self, hi.2.2]; simp [hu, hut]
  refine ⟨?_, ?_⟩
  · show bumpIf (chained c₀.today rel (some rel)) c₀.today
      (decideReg (carried c₀ rel unr) k os b).released.asOf = c₀.today
    rw [h1, hc1]; simp [bumpIf, ht]
  · show bumpIf (chained c₀.today unr (some unr)) c₀.today
      (decideReg (carried c₀ rel unr) k os b).unresolved.asOf = c₀.today
    rw [h2, hc2]; simp [bumpIf, ht]

/-- STALE_RELEASED fires on a carried, dated set only when the clock went back. -/
theorem stale_released_iff (c₀ : Ctx) (rel unr : Snapshot Line) (hc : rel.count = rel.entries.length)
    (hv : validDate rel.asOf = true) (seen : List Key) (l : Line) :
    fires (carried c₀ rel unr) seen l .STALE_RELEASED = !decide (rel.asOf ≤ c₀.today) := by
  show (!chained c₀.today rel (some rel)) = _
  rw [chained_self, hc]; simp [hv]

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
    headOf H (genesisSets t).1 (genesisSets t).2 = some (genesisHead H t) := by
  first | rfl | simp [headOf, setMap, genesisSets, genesisHead, root, rootAt, guard]

private theorem g1_mapM_mem {α β : Type} (f : α → Option β) :
    ∀ (xs : List α) (ys : List β), xs.mapM f = some ys → ∀ y ∈ ys, ∃ x ∈ xs, f x = some y
  | [], ys, h, y, hy => by simp [List.mapM_nil] at h; subst h; simp at hy
  | x :: xs, ys, h, y, hy => by
    simp only [List.mapM_cons] at h
    cases hx : f x with
    | none => simp [hx] at h
    | some a =>
      cases hm : xs.mapM f with
      | none => simp [hx, hm] at h
      | some bs =>
        simp [hx, hm] at h
        subst h
        rcases List.mem_cons.mp hy with rfl | hy
        · exact ⟨x, by simp, hx⟩
        · obtain ⟨x', hx', e⟩ := g1_mapM_mem f xs bs hm y hy
          exact ⟨x', by simp [hx'], e⟩

private theorem keyVal_len (H : Bytes → Bytes) (hH : HashLen H) (xs : List Bytes) (v : Bytes)
    (h : keyVal xs.length (xs.foldl (frontierPush H) []) = some v) : v.length < 2 ^ 32 := by
  have hp := keyVal_parse H hH xs v h
  unfold parseKeyVal at hp
  by_cases hb : (v.length == 8 + 64 * (peaksOf (beNat (v.take 8))).length) = true
  · have hl : v.length = 8 + 64 * (peaksOf (beNat (v.take 8))).length := by simpa using hb
    have : (peaksOf (beNat (v.take 8))).length ≤ 64 := by
      unfold peaksOf; exact Nat.le_trans (List.length_filter_le _ _) (by simp)
    omega
  · simp [hb] at hp

theorem setMap_ok (H : Bytes → Bytes) (hH : HashLen H) (u : Bool) (s : List Line) (m : Map)
    (h : setMap H u s = some m) : MapOk m := by
  unfold setMap at h
  simp only [bind, Option.bind] at h
  split at h
  · simp at h
  rename_i rows hrows
  dsimp only at h
  split at h
  · simp at h
  rename_i ks hks
  dsimp only at h
  by_cases hg : (rows.map (·.1) ++ ks.map (·.1)).Nodup
  · simp [guard, hg] at h
    subst h
    refine ⟨by simpa [List.map_append] using hg, ?_⟩
    intro e he
    rcases List.mem_append.mp he with he | he
    · obtain ⟨⟨x, i⟩, hx, hf⟩ := g1_mapM_mem _ _ _ hrows e he
      cases hk : keyBytes (rowKey x) with
      | none => simp [hk] at hf
      | some kb =>
        cases hb : be 8 i with
        | none => simp [hk, hb] at hf
        | some v =>
          simp [hk, hb] at hf
          subst hf
          exact ⟨hH _, by simp [be_len hb]⟩
    · obtain ⟨q, hq, hf⟩ := g1_mapM_mem _ _ _ hks e he
      cases hk : keyBytes q with
      | none => simp [hk] at hf
      | some kb =>
        cases hp : postings u s q with
        | none => simp [hk, hp] at hf
        | some es =>
          cases hv : keyVal es.length (es.foldl (frontierPush H) []) with
          | none => simp [hk, hp, hv] at hf
          | some v =>
            simp [hk, hp, hv] at hf
            subst hf
            exact ⟨hH _, keyVal_len H hH es v hv⟩
  · simp [guard, hg] at h


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
private theorem g1_run_agrees (s : Bytes) :
    pLine.run s = (pLineFull.run s).map fun (l, t) => (⟨l.flow, l.memberKey, l.payeeRef, l.cents⟩, t) := by
  simp only [pLine, pLineFull, StateT.run_bind, StateT.run_pure]
  rcases (tag flows).run s with _ | ⟨a, s1⟩ <;> simp
  rcases ident.run s1 with _ | ⟨b, s2⟩ <;> simp
  rcases (take memberKeyBytes).run s2 with _ | ⟨c, s3⟩ <;> simp
  rcases ident.run s3 with _ | ⟨d, s4⟩ <;> simp
  rcases ident.run s4 with _ | ⟨e, s5⟩ <;> simp
  rcases (nat 4).run s5 with _ | ⟨f, s6⟩ <;> simp
  rcases ident.run s6 with _ | ⟨g, s7⟩ <;> simp
  rcases (nat 4).run s7 with _ | ⟨h, s8⟩ <;> simp
  rcases (nat 8).run s8 with _ | ⟨i, s9⟩ <;> simp

theorem pLineFull_agrees (x : Bytes) :
    parse pLine maxLineBytes x =
      (parse pLineFull maxLineBytes x).map fun l => ⟨l.flow, l.memberKey, l.payeeRef, l.cents⟩ := by
  unfold parse
  split
  · rfl
  · rw [g1_run_agrees]
    rcases pLineFull.run x with _ | ⟨l, t⟩
    · rfl
    · cases t <;> rfl

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

private theorem g1_take {n : Nat} {s : Bytes} {p : Bytes × Bytes} (h : (take n).run s = some p) :
    p.1.length = n := by
  simp only [StateT.run, take] at h
  split at h
  · simp at h; subst h; simp; omega
  · simp at h

private theorem g1_foldl : ∀ (bs : Bytes) (acc : Nat),
    bs.foldl (fun a x => a * 256 + x.toNat) acc < (acc + 1) * 256 ^ bs.length
  | [], acc => by simp
  | x :: bs, acc => by
    have ih := g1_foldl bs (acc * 256 + x.toNat)
    have hx : x.toNat < 256 := UInt8.toNat_lt x
    have h1 : acc * 256 + x.toNat + 1 ≤ (acc + 1) * 256 := by omega
    have h2 : (acc * 256 + x.toNat + 1) * 256 ^ bs.length ≤ (acc + 1) * 256 ^ (x :: bs).length := by
      simp only [List.length_cons, Nat.pow_succ]
      calc _ ≤ ((acc + 1) * 256) * 256 ^ bs.length := Nat.mul_le_mul_right _ h1
        _ = _ := by rw [Nat.mul_assoc, Nat.mul_comm 256 (256 ^ bs.length)]
    exact Nat.lt_of_lt_of_le ih h2

private theorem g1_beNat_lt (bs : Bytes) : beNat bs < 256 ^ bs.length := by
  have := g1_foldl bs 0
  simpa [beNat] using this

private theorem g1_run_bind {α β : Type} (x : P α) (f : α → P β) (s : Bytes) (p : β × Bytes) :
    (x >>= f).run s = some p ↔ ∃ q, x.run s = some q ∧ (f q.1).run q.2 = some p := by
  rw [StateT.run_bind]
  cases hq : x.run s <;> simp

private theorem g1_run_pure {α : Type} (a : α) (s : Bytes) (p : α × Bytes) :
    (pure a : P α).run s = some p ↔ p = (a, s) := by
  rw [StateT.run_pure]; simp [eq_comm]

private theorem g1_need {c : Bool} {s : Bytes} {p : Unit × Bytes} (h : (need c).run s = some p) : c = true := by
  simp only [StateT.run, need] at h
  split at h
  · assumption
  · simp at h

private theorem g1_nat {w lo hi : Nat} {s : Bytes} {p : Nat × Bytes} (h : (nat w lo hi).run s = some p) :
    p.1 < 256 ^ w := by
  simp only [nat, g1_run_bind, g1_run_pure] at h
  obtain ⟨q, hq, r, hr, h⟩ := h
  have := g1_beNat_lt q.1
  rw [g1_take hq] at this
  subst h
  exact this

private theorem g1_ident {s : Bytes} {p : Bytes × Bytes} (h : ident.run s = some p) : identOk p.1 = true := by
  simp only [ident, blob, g1_run_bind, g1_run_pure] at h
  obtain ⟨q, ⟨q0, h0, h1⟩, r, hr, h⟩ := h
  have := g1_need hr
  subst h
  exact this

private theorem g1_pLineFull {s : Bytes} {p : WireLineFull × Bytes} (h : pLineFull.run s = some p) :
    identOk p.1.lineId = true ∧ p.1.memberKey.length = 32 ∧ identOk p.1.payeeRef = true ∧
    identOk p.1.rendering = true ∧ p.1.date < 256 ^ 4 ∧ identOk p.1.proc = true ∧ p.1.units < 256 ^ 4 ∧
    p.1.cents < 256 ^ 8 := by
  simp only [pLineFull, g1_run_bind, g1_run_pure] at h
  obtain ⟨q1, h1, q2, h2, q3, h3, q4, h4, q5, h5, q6, h6, q7, h7, q8, h8, q9, h9, h⟩ := h
  subst h
  exact ⟨g1_ident h2, g1_take h3, g1_ident h4, g1_ident h5, g1_nat h6, g1_ident h7, g1_nat h8, g1_nat h9⟩

private theorem g1_parse {α : Type} {p : P α} {lim : Nat} {b : Bytes} {a : α} (h : parse p lim b = some a) :
    ∃ t, p.run b = some (a, t) := by
  unfold parse at h
  split at h
  · simp at h
  · rcases hr : p.run b with _ | ⟨a', t⟩
    · simp [hr] at h
    · cases t
      · simp [hr] at h; subst h; exact ⟨[], rfl⟩
      · simp [hr] at h

private theorem g1_identOk_len {x : Bytes} (h : identOk x = true) : x.length ≤ 128 := by
  cases x with
  | nil => simp [identOk] at h
  | cons c r =>
    simp only [identOk, Bool.and_eq_true, decide_eq_true_eq] at h
    obtain ⟨⟨_, hl⟩, _⟩ := h
    simp; omega

private theorem g1_idNat_lt {x : Bytes} {w : Nat} (h : x.length + 1 ≤ w) : idNat x < 256 ^ w := by
  have := g1_beNat_lt (1 :: x)
  exact Nat.lt_of_lt_of_le this (Nat.pow_le_pow_right (by omega) (by simpa using h))

theorem payNat_fits (program pay : Bytes) (hp : identOk program = true) (hq : identOk pay = true) :
    payNat program pay < 256 ^ payWidth := by
  have h1 := g1_identOk_len hp
  have h2 := g1_identOk_len hq
  unfold payNat
  apply g1_idNat_lt
  simp [identField, natBE, payWidth]
  omega

private theorem g1_mapM_be : ∀ (l : List (Nat × Nat)), (∀ e ∈ l, e.2 < 256 ^ e.1) →
    (l.mapM fun (w, n) => be w n).isSome = true
  | [], _ => by simp
  | (w, n) :: l, h => by
    have h1 : (be w n).isSome = true := by
      have := h (w, n) (by simp)
      simp only at this
      simp [be, this]
    obtain ⟨bs, hbs⟩ := Option.isSome_iff_exists.mp h1
    have h2 := g1_mapM_be l (fun e he => h e (by simp [he]))
    obtain ⟨cs, hcs⟩ := Option.isSome_iff_exists.mp h2
    simp [List.mapM_cons, hbs, hcs]

private theorem g1_rowKey_some (l : Line) (h : ∀ e ∈ Line.fields l, e.2 < 256 ^ e.1) :
    (keyBytes (rowKey l)).isSome = true := by
  obtain ⟨bs, hbs⟩ := Option.isSome_iff_exists.mp (g1_mapM_be _ h)
  have hz : [idWidth, payWidth, 1, idWidth, idWidth, idWidth, 4, idWidth, 4, 8].zip
      ((Line.fields l).map (·.2)) = Line.fields l := by
    simp [Line.fields]
  have hlen : (Line.fields l).length = 10 := by simp [Line.fields]
  simp [keyBytes, rowKey, keyWidths, hz, hlen, hbs]

private theorem g1_lineOf_fits {pay : Nat} (hpay : pay < 256 ^ payWidth) {wl : WireLineFull} {l : Line}
    (hid : identOk wl.lineId = true) (hm : wl.memberKey.length = 32) (hp : identOk wl.payeeRef = true)
    (hr : identOk wl.rendering = true) (hd : wl.date < 256 ^ 4) (hpr : identOk wl.proc = true)
    (hu : wl.units < 256 ^ 4) (hc : wl.cents < 256 ^ 8) (h : lineOf pay wl = some l) :
    (keyBytes (rowKey l)).isSome = true := by
  unfold lineOf at h
  simp only [Option.map_eq_some_iff] at h
  obtain ⟨f, hf, rfl⟩ := h
  apply g1_rowKey_some
  have i1 := g1_idNat_lt (w := idWidth) (x := wl.lineId) (by have := g1_identOk_len hid; simp [idWidth]; omega)
  have i2 := g1_idNat_lt (w := idWidth) (x := wl.memberKey) (by simp [idWidth, hm])
  have i3 := g1_idNat_lt (w := idWidth) (x := wl.payeeRef) (by have := g1_identOk_len hp; simp [idWidth]; omega)
  have i4 := g1_idNat_lt (w := idWidth) (x := wl.rendering) (by have := g1_identOk_len hr; simp [idWidth]; omega)
  have i5 := g1_idNat_lt (w := idWidth) (x := wl.proc) (by have := g1_identOk_len hpr; simp [idWidth]; omega)
  have i6 : f.tag < 256 ^ 1 := by cases f <;> simp [Flow.tag]
  intro e he
  simp only [Line.fields, List.mem_cons, List.not_mem_nil, or_false] at he
  rcases he with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> simp only <;> assumption

private theorem g1_request_ids {s : Bytes} {p : Request × Bytes} (h : pRequest.run s = some p) :
    identOk p.1.programId = true ∧ identOk p.1.paymentId = true := by
  simp only [pRequest, g1_run_bind, g1_run_pure] at h
  obtain ⟨q1, h1, q2, h2, q3, h3, q4, h4, q5, h5, q6, h6, q7, h7, q8, h8, q9, h9, q10, h10, q11, h11, q12, h12,
    q13, h13, q14, h14, q15, h15, q16, h16, q17, h17, q18, h18, q19, h19, h⟩ := h
  subst h
  exact ⟨g1_ident h3, g1_ident h6⟩

/-- A decoded line always has a row key, so `decideIdx`'s guard (§7) never refuses a decoded batch. -/
theorem lineOf_fits (r : Request) (hr : ∃ x, decodeRequest x = some r) (ls : List Line) (h : linesOf r = some ls) :
    ls.all (fun l => (keyBytes (rowKey l)).isSome) = true := by
  obtain ⟨x, hx⟩ := hr
  obtain ⟨t, ht⟩ := g1_parse (by unfold decodeRequest at hx; exact hx)
  obtain ⟨hp, hq⟩ := g1_request_ids ht
  have hpay := payNat_fits r.programId r.paymentId hp hq
  simp only [List.all_eq_true]
  intro l hl
  unfold linesOf at h
  obtain ⟨y, hy, hf⟩ := g1_mapM_mem _ _ ls h l hl
  obtain ⟨wl, hwl, hlo⟩ := Option.bind_eq_some_iff.mp hf
  obtain ⟨t', ht'⟩ := g1_parse hwl
  obtain ⟨a1, a2, a3, a4, a5, a6, a7, a8⟩ := g1_pLineFull ht'
  exact g1_lineOf_fits hpay a1 a2 a3 a4 a5 a6 a7 a8 hlo


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
private theorem g1_reasons_pw : (reasons.map reasonCode).Pairwise (fun a b => lexLt a b = true) := by
  decide +kernel

private theorem g1_pw_asc : ∀ (l : List Bytes), l.Pairwise (fun a b => lexLt a b = true) → ascending l = true
  | [], _ => rfl
  | [_], _ => rfl
  | a :: b :: rest, h => by
    have h1 := List.pairwise_cons.mp h
    simp only [ascending, g1_pw_asc (b :: rest) h1.2, Bool.and_true]
    exact h1.1 b (List.mem_cons_self ..)

theorem reasonCode_ascending (xs : List Reason) (h : xs.Sublist reasons) : ascending (xs.map reasonCode) = true :=
  g1_pw_asc _ (g1_reasons_pw.sublist (h.map reasonCode))

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

private theorem lenBytes_inj {a a' y y' r r' : Bytes} (h : lenBytes a = some y) (h' : lenBytes a' = some y')
    (hx : y ++ r = y' ++ r') : a = a' ∧ r = r' := by
  unfold lenBytes at h h'
  obtain ⟨p, hp, rfl⟩ := Option.map_eq_some_iff.mp h
  obtain ⟨p', hp', rfl⟩ := Option.map_eq_some_iff.mp h'
  simp only [List.append_assoc] at hx
  obtain ⟨e1, e2⟩ := List.append_inj hx (by rw [be_len hp, be_len hp'])
  subst e1
  exact List.append_inj e2 (be_inj hp hp')

private theorem rowBytes_inj {a a' : Line} {y y' r r' : Bytes} (h : rowBytes a = some y)
    (h' : rowBytes a' = some y') (hx : y ++ r = y' ++ r') : a = a' ∧ r = r' := by
  unfold rowBytes at h h'
  obtain ⟨bs, hbs, rfl⟩ := Option.map_eq_some_iff.mp h
  obtain ⟨bs', hbs', rfl⟩ := Option.map_eq_some_iff.mp h'
  obtain ⟨e1, e2⟩ := fields_inj _ _ bs bs' r r' (by simp [Line.fields]) hbs hbs' hx
  exact ⟨Line_ext e1, e2⟩

private theorem rowsBytes_inj {a a' : List Line} {y y' r r' : Bytes} (h : rowsBytes a = some y)
    (h' : rowsBytes a' = some y') (hx : y ++ r = y' ++ r') : a = a' ∧ r = r' := by
  simp [rowsBytes, Option.bind_eq_some_iff] at h h'
  obtain ⟨p, hp, rs, hrs, rfl⟩ := h
  obtain ⟨p', hp', rs', hrs', rfl⟩ := h'
  simp only [List.append_assoc] at hx
  obtain ⟨e1, e2⟩ := List.append_inj hx (by rw [be_len hp, be_len hp'])
  subst e1
  exact mapM_flat_inj rowBytes (fun _ _ _ _ _ _ => rowBytes_inj) a a' rs rs' r r' (be_inj hp hp') hrs hrs' e2

private theorem setBytes_inj {a a' : Snapshot Line} {y y' r r' : Bytes} (h : setBytes a = some y)
    (h' : setBytes a' = some y') (hx : y ++ r = y' ++ r') : a = a' ∧ r = r' := by
  obtain ⟨t, c, es⟩ := a
  obtain ⟨t', c', es'⟩ := a'
  simp [setBytes, Option.bind_eq_some_iff] at h h'
  obtain ⟨p, hp, q, hq, z, hz, rfl⟩ := h
  obtain ⟨p', hp', q', hq', z', hz', rfl⟩ := h'
  simp only [List.append_assoc] at hx
  obtain ⟨e1, e2⟩ := List.append_inj hx (by rw [be_len hp, be_len hp'])
  subst e1
  obtain ⟨e3, e4⟩ := List.append_inj e2 (by rw [be_len hq, be_len hq'])
  subst e3
  obtain ⟨e5, e6⟩ := rowsBytes_inj hz hz' e4
  have h1 := be_inj hp hp'
  have h2 := be_inj hq hq'
  subst h1; subst h2; subst e5
  exact ⟨rfl, e6⟩

private theorem tipBytes_inj : ∀ {a a' : Option (Bytes × Bytes)} {y y' r r' : Bytes}, tipBytes a = some y →
    tipBytes a' = some y' → y ++ r = y' ++ r' → a = a' ∧ r = r'
  | none, none, y, y', r, r', h, h', hx => by
    simp [tipBytes] at h h'; subst h; subst h'; simpa using hx
  | none, some _, y, y', r, r', h, h', hx => by
    simp [tipBytes, Option.bind_eq_some_iff] at h h'
    obtain ⟨_, _, _, _, rfl⟩ := h'
    subst h
    simp at hx
  | some _, none, y, y', r, r', h, h', hx => by
    simp [tipBytes, Option.bind_eq_some_iff] at h h'
    obtain ⟨_, _, _, _, rfl⟩ := h
    subst h'
    simp at hx
  | some (s, c), some (s', c'), y, y', r, r', h, h', hx => by
    simp [tipBytes, Option.bind_eq_some_iff] at h h'
    obtain ⟨a, ha, b, hb, rfl⟩ := h
    obtain ⟨a', ha', b', hb', rfl⟩ := h'
    simp only [List.cons_append, List.cons.injEq, true_and, List.append_assoc] at hx
    obtain ⟨e1, e2⟩ := lenBytes_inj ha ha' hx
    obtain ⟨e3, e4⟩ := lenBytes_inj hb hb' e2
    subst e1; subst e3
    exact ⟨rfl, e4⟩

private theorem regBytes_inj {a a' : Nat × Nat × Nat} {y y' r r' : Bytes} (h : regBytes a = some y)
    (h' : regBytes a' = some y') (hx : y ++ r = y' ++ r') : a = a' ∧ r = r' := by
  obtain ⟨a1, a2, a3⟩ := a
  obtain ⟨b1, b2, b3⟩ := a'
  simp [regBytes, Option.bind_eq_some_iff] at h h'
  obtain ⟨p, hp, q, hq, z, hz, rfl⟩ := h
  obtain ⟨p', hp', q', hq', z', hz', rfl⟩ := h'
  simp only [List.append_assoc] at hx
  obtain ⟨e1, e2⟩ := List.append_inj hx (by rw [be_len hp, be_len hp'])
  subst e1
  obtain ⟨e3, e4⟩ := List.append_inj e2 (by rw [be_len hq, be_len hq'])
  subst e3
  obtain ⟨e5, e6⟩ := List.append_inj e4 (by rw [be_len hz, be_len hz'])
  subst e5
  have h1 := be_inj hp hp'
  have h2 := be_inj hq hq'
  have h3 := be_inj hz hz'
  subst h1; subst h2; subst h3
  exact ⟨rfl, e6⟩

private theorem bodyBytes_inj {b b' : Body} {y : Bytes} (h : bodyBytes b = some y)
    (h' : bodyBytes b' = some y) : b = b' := by
  rcases b with ⟨cert, s, ts, f⟩ | ⟨⟨tip, rel, unr⟩⟩ | ⟨t⟩ <;>
    rcases b' with ⟨cert', s', ts', f'⟩ | ⟨⟨tip', rel', unr'⟩⟩ | ⟨t'⟩ <;>
    simp [bodyBytes, Option.bind_eq_some_iff] at h h'
  · obtain ⟨a, ha, s1, hs, n, hn, tt, ht, x1, hx1, x2, hx2, rfl⟩ := h
    obtain ⟨a', ha', s1', hs', n', hn', tt', ht', x1', hx1', x2', hx2', hy⟩ := h'
    have hx := (List.cons.inj hy).2.symm
    obtain ⟨e1, e2⟩ := lenBytes_inj ha ha' hx
    obtain ⟨e3, e4⟩ := lenBytes_inj hs hs' e2
    obtain ⟨e5, e6⟩ := List.append_inj e4 (by rw [be_len hn, be_len hn'])
    subst e5
    have hl := be_inj hn hn'
    obtain ⟨e7, e8⟩ := mapM_flat_inj lenBytes (fun _ _ _ _ _ _ => lenBytes_inj) ts ts' tt tt' _ _ hl ht ht' e6
    obtain ⟨e9, e10⟩ := rowsBytes_inj hx1 hx1' e8
    obtain ⟨e11, _⟩ := rowsBytes_inj hx2 hx2' (by rw [List.append_nil, List.append_nil]; exact e10)
    subst e1; subst e3; subst e7
    exact congrArg (Body.sign cert s ts) (Prod.ext e9 e11)
  · obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, e1⟩ := h
    obtain ⟨_, _, _, _, _, _, e2⟩ := h'
    have := e1.trans e2.symm
    simp at this
  · obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, e1⟩ := h
    obtain ⟨_, _, e2⟩ := h'
    have := e1.trans e2.symm
    simp at this
  · obtain ⟨_, _, _, _, _, _, e1⟩ := h
    obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, e2⟩ := h'
    have := e1.trans e2.symm
    simp at this
  · obtain ⟨a, ha, a1, ha1, a2, ha2, rfl⟩ := h
    obtain ⟨a', ha', a1', ha1', a2', ha2', hy⟩ := h'
    have hx := (List.cons.inj hy).2.symm
    obtain ⟨e1, e2⟩ := tipBytes_inj ha ha' hx
    obtain ⟨e3, e4⟩ := setBytes_inj ha1 ha1' e2
    obtain ⟨e5, _⟩ := setBytes_inj ha2 ha2' (by rw [List.append_nil, List.append_nil]; exact e4)
    subst e1; subst e3; subst e5
    rfl
  · obtain ⟨_, _, _, _, _, _, e1⟩ := h
    obtain ⟨_, _, e2⟩ := h'
    have := e1.trans e2.symm
    simp at this
  · obtain ⟨_, _, e1⟩ := h
    obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, e2⟩ := h'
    have := e1.trans e2.symm
    simp at this
  · obtain ⟨_, _, e1⟩ := h
    obtain ⟨_, _, _, _, _, _, e2⟩ := h'
    have := e1.trans e2.symm
    simp at this
  · obtain ⟨a, ha, rfl⟩ := h
    obtain ⟨a', ha', hy⟩ := h'
    have hx := (List.cons.inj hy).2.symm
    obtain ⟨e1, _⟩ := lenBytes_inj ha ha' (by rw [List.append_nil, List.append_nil]; exact hx)
    subst e1
    rfl

private theorem entryIn_prev {e : Entry} {x : Bytes} (h : entryIn e = some x) : e.prev.length = digestBytes := by
  unfold entryIn at h
  by_cases hc : e.prev.length = digestBytes
  · exact hc
  · have hn : (guard (e.prev.length = digestBytes) : Option Unit) = none := by simp [guard, hc]; rfl
    rw [hn] at h
    simp at h

/-- FORMAT: the entry encoding is injective where defined. -/
theorem entryIn_inj (e e' : Entry) (x : Bytes) (h : entryIn e = some x) (h' : entryIn e' = some x) : e = e' := by
  have hg := entryIn_prev h
  have hg' := entryIn_prev h'
  obtain ⟨idx, prev, shard, reg, body⟩ := e
  obtain ⟨idx', prev', shard', reg', body'⟩ := e'
  simp [entryIn, guard, hg, hg', Option.bind_eq_some_iff] at h h'
  obtain ⟨i, hi, k, hk, n, hn, rs, hrs, b, hb, rfl⟩ := h
  obtain ⟨i', hi', k', hk', n', hn', rs', hrs', b', hb', hx⟩ := h'
  have hx := (List.append_cancel_left hx).symm
  obtain ⟨e1, e2⟩ := List.append_inj hx (by rw [be_len hi, be_len hi'])
  subst e1
  obtain ⟨e3, e4⟩ := List.append_inj e2 (by rw [hg, hg'])
  subst e3
  obtain ⟨e5, e6⟩ := List.append_inj e4 (by rw [be_len hk, be_len hk'])
  subst e5
  obtain ⟨e7, e8⟩ := List.append_inj e6 (by rw [be_len hn, be_len hn'])
  subst e7
  obtain ⟨e9, e10⟩ := mapM_flat_inj regBytes (fun _ _ _ _ _ _ => regBytes_inj) reg reg' rs rs' b b'
    (be_inj hn hn') hrs hrs' e8
  have e11 := bodyBytes_inj hb (by rw [e10]; exact hb')
  have := be_inj hi hi'
  have := be_inj hk hk'
  subst_vars
  rfl

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

private theorem guard_some (c : Prop) [Decidable c] (x : Unit) : (guard c : Option Unit) = some x ↔ c := by
  by_cases hc : c <;> simp [guard, hc]

private theorem push_shape (P : Pins) (st st' : LogState) (e : Entry) (h : push P st e = some st') :
    st'.reg = e.reg ++ st.reg ∧ st'.rhead = chainHead sha3 st.rhead e.reg ∧
    ∃ sh', st'.shard = upd st.shard e.shard sh' ∧
      ((∃ t, e.body = .seal t ∧ (st.shard e.shard).last = none ∧ (st.shard e.shard).live = false ∧
          sh'.pays = (st.shard e.shard).pays) ∨
       (∃ p, e.body = .resume p ∧ (st.shard e.shard).live = false ∧ sh'.pays = (st.shard e.shard).pays) ∨
       (∃ cert new tokens fresh n, e.body = .sign cert new tokens fresh ∧ (st.shard e.shard).live = true ∧
          storedOfAny sha3 new = some n ∧
          (∀ q y c, (st.shard e.shard).last = some (y, c) → storedOfAny sha3 y = some q →
            q.checkpoint.createdAt < n.checkpoint.createdAt) ∧
          sh'.last = some (new, cert) ∧ sh'.live = true ∧
          e.body.leaves.foldlM payStep (st.shard e.shard).pays = some sh'.pays)) := by
  unfold push at h
  cases hb : e.body with
  | «seal» t =>
    simp [hb, Option.bind_eq_some_iff, guard_some] at h
    obtain ⟨_, a, _, ⟨_, _, _, hl, hv⟩, rfl⟩ := h
    exact ⟨rfl, rfl, _, rfl, Or.inl ⟨t, rfl, hl, hv, rfl⟩⟩
  | resume p =>
    simp [hb, Option.bind_eq_some_iff, guard_some] at h
    obtain ⟨_, a, _, ⟨hv, _⟩, _, _, _, _, _, _, _, _, _, rfl⟩ := h
    exact ⟨rfl, rfl, _, rfl, Or.inr (Or.inl ⟨p, rfl, hv, rfl⟩)⟩
  | sign cert new tokens fresh =>
    simp [hb, Option.bind_eq_some_iff, guard_some] at h
    obtain ⟨_, a, _, hlive, _, _, _, _, n, hn, _, _, _, _, _, hg, ps, hps, rfl⟩ := h
    refine ⟨rfl, rfl, _, rfl, Or.inr (Or.inr ⟨cert, new, tokens, fresh, n, rfl, hlive, hn, ?_, rfl, hlive, hps⟩)⟩
    intro q y c hl hq
    rw [hl] at hg
    simpa [hq] using hg

/-- FORMAT: the folded registry head is the chain of the folded rows. -/
theorem registry_head (P : Pins) (log : List Entry) (st : LogState) (h : fold P log = some st) :
    st.rhead = chainHead sha3 zeroDigest st.reg := by
  have key : ∀ (log : List Entry) (s0 st : LogState), s0.rhead = chainHead sha3 zeroDigest s0.reg →
      log.foldlM (push P) s0 = some st → st.rhead = chainHead sha3 zeroDigest st.reg := by
    intro log
    induction log with
    | nil => intro s0 st h0 h; simp at h; subst h; exact h0
    | cons x rest ih =>
      intro s0 st h0 h
      simp only [List.foldlM] at h
      obtain ⟨s1, hs1, hr⟩ := Option.bind_eq_some_iff.mp h
      obtain ⟨hreg, hrh, _⟩ := push_shape P s0 s1 x hs1
      refine ih s1 st ?_ hr
      rw [hreg, hrh, chainHead_append, h0]
  exact key log LogState.init st rfl h


private theorem lookup_cons' (q p : Nat) (v : Leaf) (t : List (Nat × Leaf)) :
    ((p, v) :: t).lookup q = if q = p then some v else t.lookup q := by
  by_cases h : q = p
  · subst h; simp [List.lookup]
  · have h' : (q == p) = false := by simpa using h
    simp [List.lookup, h, h']

private theorem lookup_mem (q : Nat) (o : Leaf) : ∀ ps : List (Nat × Leaf),
    ps.lookup q = some o → o ∈ ps.map (·.2)
  | [], h => by simp [List.lookup] at h
  | (a, v) :: t, h => by
    rw [lookup_cons'] at h
    by_cases hq : q = a
    · rw [if_pos hq] at h; obtain rfl := Option.some.inj h; simp
    · rw [if_neg hq] at h; exact List.mem_cons_of_mem _ (lookup_mem q o t h)

private theorem lookup_filter_ne (ps : List (Nat × Leaf)) (p q : Nat) (hq : q ≠ p) :
    ((ps.filter (·.1 != p)).lookup q) = ps.lookup q := by
  induction ps with
  | nil => rfl
  | cons x t ih =>
    obtain ⟨a, v⟩ := x
    by_cases ha : a = p
    · subst ha; simp [ih, lookup_cons', hq]
    · simp [ha, lookup_cons', ih]

private theorem redecides_rev {o l : Leaf} (h : redecides o.revision o l = true) : l.revision = o.revision + 1 := by
  simp [redecides] at h
  omega

/-- Everything one successful `payStep` says, for the payment `p` of `l`. -/
private theorem payStep_facts {ps ps' : List (Nat × Leaf)} {l : Leaf} (h : payStep ps l = some ps') :
    (∀ o, ps.lookup (payNat l.programId l.paymentId) = some o →
      o.revision ≤ l.revision ∧ (o.revision = l.revision → l.outcome ≠ .ALLOW)) ∧
    (∃ o', ps'.lookup (payNat l.programId l.paymentId) = some o' ∧ l.revision ≤ o'.revision) ∧
    (∀ q o, ps.lookup q = some o → ∃ o', ps'.lookup q = some o' ∧ o.revision ≤ o'.revision) ∧
    (∀ x ∈ ps', x.2 = l ∨ x.2 ∈ ps.map (·.2)) ∧
    (l.outcome = .ALLOW → 0 < l.revision → ∃ o ∈ ps.map (·.2), redecides o.revision o l = true) := by
  unfold payStep at h
  rcases hl : ps.lookup (payNat l.programId l.paymentId) with _ | old
  · simp only [hl] at h
    split at h
    · obtain rfl := Option.some.inj h
      refine ⟨by simp, ⟨l, by simp [lookup_cons'], Nat.le_refl _⟩, ?_, ?_, ?_⟩
      · intro q o hq
        by_cases hqp : q = payNat l.programId l.paymentId
        · subst hqp; simp [hl] at hq
        · refine ⟨o, ?_, Nat.le_refl _⟩
          rw [lookup_cons', if_neg hqp]; exact hq
      · intro x hx
        rcases List.mem_cons.mp hx with rfl | hx
        · exact Or.inl rfl
        · exact Or.inr (List.mem_map.mpr ⟨x, hx, rfl⟩)
      · intro _ hr; omega
    · simp at h
  · simp only [hl] at h
    split at h
    · rename_i hrd
      obtain rfl := Option.some.inj h
      have hr := redecides_rev hrd
      refine ⟨?_, ⟨l, by simp [lookup_cons'], Nat.le_refl _⟩, ?_, ?_, ?_⟩
      · intro o ho; obtain rfl := Option.some.inj ho; omega
      · intro q o hq
        by_cases hqp : q = payNat l.programId l.paymentId
        · subst hqp
          obtain rfl := Option.some.inj (hl.symm.trans hq)
          exact ⟨l, by simp [lookup_cons'], by omega⟩
        · refine ⟨o, ?_, Nat.le_refl _⟩
          rw [lookup_cons', if_neg hqp, lookup_filter_ne _ _ _ hqp]; exact hq
      · intro x hx
        rcases List.mem_cons.mp hx with rfl | hx
        · exact Or.inl rfl
        · exact Or.inr (List.mem_map.mpr ⟨x, (List.mem_filter.mp hx).1, rfl⟩)
      · intro _ _
        exact ⟨old, lookup_mem _ _ _ hl, hrd⟩
    · split at h
      · rename_i hc
        obtain rfl := Option.some.inj h
        refine ⟨?_, ⟨old, hl, by omega⟩, ?_, ?_, ?_⟩
        · intro o ho; obtain rfl := Option.some.inj ho; exact ⟨by omega, fun _ => hc.2⟩
        · intro q o hq; exact ⟨o, hq, Nat.le_refl _⟩
        · intro x hx; exact Or.inr (List.mem_map.mpr ⟨x, hx, rfl⟩)
        · intro ha; exact absurd ha hc.2
      · simp at h


private theorem leaves_mono : ∀ (ls : List Leaf) (ps ps' : List (Nat × Leaf)),
    ls.foldlM payStep ps = some ps' → ∀ q o, ps.lookup q = some o →
      ∃ o', ps'.lookup q = some o' ∧ o.revision ≤ o'.revision
  | [], ps, ps', h, q, o, ho => by simp at h; subst h; exact ⟨o, ho, Nat.le_refl _⟩
  | l :: rest, ps, ps', h, q, o, ho => by
    simp only [List.foldlM] at h
    obtain ⟨ps1, h1, h2⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨o1, ho1, hle⟩ := (payStep_facts h1).2.2.1 q o ho
    obtain ⟨o2, ho2, hle2⟩ := leaves_mono rest ps1 ps' h2 q o1 ho1
    exact ⟨o2, ho2, Nat.le_trans hle hle2⟩

private theorem leaves_born : ∀ (ls : List Leaf) (ps ps' : List (Nat × Leaf)),
    ls.foldlM payStep ps = some ps' → ∀ l ∈ ls,
      ∃ o', ps'.lookup (payNat l.programId l.paymentId) = some o' ∧ l.revision ≤ o'.revision
  | [], _, _, _, l, hl => by simp at hl
  | x :: rest, ps, ps', h, l, hl => by
    simp only [List.foldlM] at h
    obtain ⟨ps1, h1, h2⟩ := Option.bind_eq_some_iff.mp h
    rcases List.mem_cons.mp hl with rfl | hl
    · obtain ⟨o1, ho1, hle⟩ := (payStep_facts h1).2.1
      obtain ⟨o2, ho2, hle2⟩ := leaves_mono rest ps1 ps' h2 _ o1 ho1
      exact ⟨o2, ho2, Nat.le_trans hle hle2⟩
    · exact leaves_born rest ps1 ps' h2 l hl

private theorem leaves_gate : ∀ (ls : List Leaf) (ps ps' : List (Nat × Leaf)),
    ls.foldlM payStep ps = some ps' → ∀ l ∈ ls, ∀ o, ps.lookup (payNat l.programId l.paymentId) = some o →
      o.revision ≤ l.revision ∧ (o.revision = l.revision → l.outcome ≠ .ALLOW) := by
  intro ls
  induction ls with
  | nil => intro ps ps' h l hl; simp at hl
  | cons x rest ih =>
    intro ps ps' h l hl o ho
    simp only [List.foldlM] at h
    obtain ⟨ps1, h1, h2⟩ := Option.bind_eq_some_iff.mp h
    rcases List.mem_cons.mp hl with rfl | hl
    · exact (payStep_facts h1).1 o ho
    · obtain ⟨o1, ho1, hle⟩ := (payStep_facts h1).2.2.1 _ o ho
      obtain ⟨h3, h4⟩ := ih ps1 ps' h2 l hl o1 ho1
      exact ⟨Nat.le_trans hle h3, fun he => h4 (by omega)⟩

private theorem leaves_mem : ∀ (ls : List Leaf) (ps ps' : List (Nat × Leaf)),
    ls.foldlM payStep ps = some ps' → ∀ y ∈ ps'.map (·.2), y ∈ ps.map (·.2) ∨ y ∈ ls
  | [], ps, ps', h, y, hy => by simp at h; subst h; exact Or.inl hy
  | x :: rest, ps, ps', h, y, hy => by
    simp only [List.foldlM] at h
    obtain ⟨ps1, h1, h2⟩ := Option.bind_eq_some_iff.mp h
    rcases leaves_mem rest ps1 ps' h2 y hy with hy1 | hy1
    · obtain ⟨z, hz, rfl⟩ := List.mem_map.mp hy1
      rcases (payStep_facts h1).2.2.2.1 z hz with h5 | h5
      · exact Or.inr (by simp [h5])
      · exact Or.inl h5
    · exact Or.inr (List.mem_cons_of_mem _ hy1)

private theorem leaves_step : ∀ (ls : List Leaf) (ps ps' : List (Nat × Leaf)),
    ls.foldlM payStep ps = some ps' → ∀ l ∈ ls, l.outcome = .ALLOW → 0 < l.revision →
      ∃ o, (o ∈ ps.map (·.2) ∨ o ∈ ls) ∧ redecides o.revision o l = true
  | [], _, _, _, l, hl, _, _ => by simp at hl
  | x :: rest, ps, ps', h, l, hl, ha, hr => by
    simp only [List.foldlM] at h
    obtain ⟨ps1, h1, h2⟩ := Option.bind_eq_some_iff.mp h
    rcases List.mem_cons.mp hl with rfl | hl
    · obtain ⟨o, ho, hrd⟩ := (payStep_facts h1).2.2.2.2 ha hr
      exact ⟨o, Or.inl ho, hrd⟩
    · obtain ⟨o, ho, hrd⟩ := leaves_step rest ps1 ps' h2 l hl ha hr
      refine ⟨o, ?_, hrd⟩
      rcases ho with ho | ho
      · obtain ⟨z, hz, rfl⟩ := List.mem_map.mp ho
        rcases (payStep_facts h1).2.2.2.1 z hz with h5 | h5
        · exact Or.inr (by simp [h5])
        · exact Or.inl h5
      · exact Or.inr (List.mem_cons_of_mem _ ho)

private theorem push_pays (P : Pins) (s0 s1 : LogState) (x : Entry) (h : push P s0 x = some s1) :
    x.body.leaves.foldlM payStep (s0.shard x.shard).pays = some (s1.shard x.shard).pays := by
  obtain ⟨_, _, sh', hsh, hc⟩ := push_shape P s0 s1 x h
  have hs : s1.shard x.shard = sh' := by rw [hsh]; simp [upd]
  rw [hs]
  rcases hc with ⟨t, hb, _, _, hp⟩ | ⟨p, hb, _, hp⟩ | ⟨cert, new, tokens, fresh, n, hb, _, _, _, _, _, hp⟩
  · rw [hp, hb]; simp [Body.leaves]
  · rw [hp, hb]; simp [Body.leaves]
  · exact hp

private theorem push_other (P : Pins) (s0 s1 : LogState) (x : Entry) (h : push P s0 x = some s1)
    (k : Nat) (hk : k ≠ x.shard) : s1.shard k = s0.shard k := by
  obtain ⟨_, _, sh', hsh, _⟩ := push_shape P s0 s1 x h
  rw [hsh]; simp [upd, hk]

private theorem push_mono (P : Pins) (s0 s1 : LogState) (x : Entry) (h : push P s0 x = some s1)
    (k q : Nat) (o : Leaf) (ho : (s0.shard k).pays.lookup q = some o) :
    ∃ o', (s1.shard k).pays.lookup q = some o' ∧ o.revision ≤ o'.revision := by
  by_cases hk : k = x.shard
  · subst hk; exact leaves_mono _ _ _ (push_pays P s0 s1 x h) q o ho
  · rw [push_other P s0 s1 x h k hk]; exact ⟨o, ho, Nat.le_refl _⟩

private theorem push_mem (P : Pins) (s0 s1 : LogState) (x : Entry) (h : push P s0 x = some s1)
    (k : Nat) (o : Leaf) (ho : o ∈ (s1.shard k).pays.map (·.2)) :
    o ∈ (s0.shard k).pays.map (·.2) ∨ (x.shard = k ∧ o ∈ x.body.leaves) := by
  by_cases hk : k = x.shard
  · subst hk
    rcases leaves_mem _ _ _ (push_pays P s0 s1 x h) o ho with h0 | h0
    · exact Or.inl h0
    · exact Or.inr ⟨rfl, h0⟩
  · rw [push_other P s0 s1 x h k hk] at ho; exact Or.inl ho

private theorem fold_gate (P : Pins) : ∀ (xs : List Entry) (s0 s : LogState),
    xs.foldlM (push P) s0 = some s →
    ∀ (k q : Nat) (o : Leaf), (s0.shard k).pays.lookup q = some o →
    ∀ (j : Nat) (y : Entry), xs[j]? = some y → y.shard = k →
    ∀ l ∈ y.body.leaves, payNat l.programId l.paymentId = q →
      o.revision ≤ l.revision ∧ (o.revision = l.revision → l.outcome ≠ .ALLOW) := by
  intro xs
  induction xs with
  | nil => intro s0 s h k q o ho j y hy; simp at hy
  | cons x rest ih =>
    intro s0 s h k q o ho j y hy hk l hl hq
    simp only [List.foldlM] at h
    obtain ⟨s1, hs1, hr⟩ := Option.bind_eq_some_iff.mp h
    subst hq
    cases j with
    | zero =>
      simp at hy; subst hy; subst hk
      exact leaves_gate _ _ _ (push_pays P s0 s1 _ hs1) l hl o ho
    | succ j =>
      simp at hy
      obtain ⟨o1, ho1, hle⟩ := push_mono P s0 s1 x hs1 k _ o ho
      obtain ⟨g1, g2⟩ := ih s1 s hr k _ o1 ho1 j y hy hk l hl rfl
      exact ⟨Nat.le_trans hle g1, fun he => g2 (by omega)⟩

private theorem fold_mono (P : Pins) : ∀ (xs : List Entry) (s0 s : LogState),
    xs.foldlM (push P) s0 = some s →
    ∀ (i j : Nat), i < j → ∀ (e e' : Entry), xs[i]? = some e → xs[j]? = some e' → e.shard = e'.shard →
    ∀ l ∈ e.body.leaves, ∀ l' ∈ e'.body.leaves,
      payNat l.programId l.paymentId = payNat l'.programId l'.paymentId →
      l.revision ≤ l'.revision ∧ (l.revision = l'.revision → l'.outcome ≠ .ALLOW) := by
  intro xs
  induction xs with
  | nil => intro s0 s h i j hij e e' hi; simp at hi
  | cons x rest ih =>
    intro s0 s h i j hij e e' hi hj hk l hl l' hl' hp
    simp only [List.foldlM] at h
    obtain ⟨s1, hs1, hr⟩ := Option.bind_eq_some_iff.mp h
    cases i with
    | zero =>
      simp at hi; subst hi
      cases j with
      | zero => omega
      | succ j =>
        simp at hj
        obtain ⟨o1, ho1, hle⟩ := leaves_born _ _ _ (push_pays P s0 s1 _ hs1) l hl
        obtain ⟨g1, g2⟩ := fold_gate P rest s1 s hr _ _ o1 ho1 j e' hj hk.symm l' hl' hp.symm
        exact ⟨Nat.le_trans hle g1, fun he => g2 (by omega)⟩
    | succ i =>
      cases j with
      | zero => omega
      | succ j =>
        simp at hi hj
        exact ih s1 s hr i j (by omega) e e' hi hj hk l hl l' hl' hp

private theorem fold_redec (P : Pins) : ∀ (xs : List Entry) (s0 s : LogState),
    xs.foldlM (push P) s0 = some s →
    ∀ (j : Nat) (y : Entry), xs[j]? = some y → ∀ l' ∈ y.body.leaves, l'.outcome = .ALLOW → 0 < l'.revision →
    ∃ o, (o ∈ (s0.shard y.shard).pays.map (·.2) ∨
        ∃ i e, i ≤ j ∧ xs[i]? = some e ∧ e.shard = y.shard ∧ o ∈ e.body.leaves) ∧
      redecides o.revision o l' = true := by
  intro xs
  induction xs with
  | nil => intro s0 s h j y hy; simp at hy
  | cons x rest ih =>
    intro s0 s h j y hy l' hl' ha hr
    simp only [List.foldlM] at h
    obtain ⟨s1, hs1, hr1⟩ := Option.bind_eq_some_iff.mp h
    cases j with
    | zero =>
      simp at hy; subst hy
      obtain ⟨o, ho, hrd⟩ := leaves_step _ _ _ (push_pays P s0 s1 _ hs1) l' hl' ha hr
      rcases ho with ho | ho
      · exact ⟨o, Or.inl ho, hrd⟩
      · exact ⟨o, Or.inr ⟨0, _, Nat.le_refl _, rfl, rfl, ho⟩, hrd⟩
    | succ j =>
      simp at hy
      obtain ⟨o, ho, hrd⟩ := ih s1 s hr1 j y hy l' hl' ha hr
      refine ⟨o, ?_, hrd⟩
      rcases ho with ho | ⟨i, e, hij, hi, hs, ho⟩
      · rcases push_mem P s0 s1 x hs1 y.shard o ho with h0 | ⟨hxk, h0⟩
        · exact Or.inl h0
        · exact Or.inr ⟨0, x, by omega, rfl, hxk, h0⟩
      · exact Or.inr ⟨i + 1, e, by omega, by simpa using hi, hs, ho⟩

private theorem push_live (P : Pins) (s0 s1 : LogState) (x : Entry) (h : push P s0 x = some s1)
    (hl : (s0.shard x.shard).live = true) : ∃ a, x.body.signed? = some a := by
  obtain ⟨_, _, sh', hsh, hc⟩ := push_shape P s0 s1 x h
  rcases hc with ⟨t, hb, _, hv, _⟩ | ⟨p, hb, hv, _⟩ | ⟨cert, new, tokens, fresh, n, hb, _⟩
  · rw [hl] at hv; exact absurd hv (by decide)
  · rw [hl] at hv; exact absurd hv (by decide)
  · exact ⟨new, by rw [hb]; rfl⟩

private theorem push_sign (P : Pins) (s0 s1 : LogState) (x : Entry) (a : Bytes) (h : push P s0 x = some s1)
    (ha : x.body.signed? = some a) :
    ∃ cert n, (s0.shard x.shard).live = true ∧ storedOfAny sha3 a = some n ∧
      (∀ q y c, (s0.shard x.shard).last = some (y, c) → storedOfAny sha3 y = some q →
        q.checkpoint.createdAt < n.checkpoint.createdAt) ∧
      (s1.shard x.shard).last = some (a, cert) ∧ (s1.shard x.shard).live = true := by
  obtain ⟨_, _, sh', hsh, hc⟩ := push_shape P s0 s1 x h
  have hs : s1.shard x.shard = sh' := by rw [hsh]; simp [upd]
  rcases hc with ⟨t, hb, _⟩ | ⟨p, hb, _⟩ | ⟨cert, new, tokens, fresh, n, hb, hlive, hn, hlt, hlast, hl', _⟩
  · rw [hb] at ha; simp [Body.signed?] at ha
  · rw [hb] at ha; simp [Body.signed?] at ha
  · rw [hb] at ha
    simp only [Body.signed?, Option.some.injEq] at ha
    subst ha
    exact ⟨cert, n, hlive, hn, hlt, by rw [hs]; exact hlast, by rw [hs]; exact hl'⟩

private theorem fold_last (P : Pins) : ∀ (xs : List Entry) (s0 s : LogState),
    xs.foldlM (push P) s0 = some s →
    ∀ (k c : Nat), (s0.shard k).live = true →
    (∃ y cert q, (s0.shard k).last = some (y, cert) ∧ storedOfAny sha3 y = some q ∧
      c ≤ q.checkpoint.createdAt) →
    ∀ (j : Nat) (y : Entry), xs[j]? = some y → y.shard = k →
    ∀ b n', y.body.signed? = some b → storedOfAny sha3 b = some n' → c < n'.checkpoint.createdAt := by
  intro xs
  induction xs with
  | nil => intro s0 s h k c hlive hex j y hy; simp at hy
  | cons x rest ih =>
    intro s0 s h k c hlive hex j y hy hk b n' hb hn'
    obtain ⟨y0, cert0, q, hlast0, hq, hc⟩ := hex
    simp only [List.foldlM] at h
    obtain ⟨s1, hs1, hr⟩ := Option.bind_eq_some_iff.mp h
    by_cases hxk : x.shard = k
    · subst hxk
      obtain ⟨a, ha⟩ := push_live P s0 s1 x hs1 hlive
      obtain ⟨cert, n, _, hn, hlt, hlast, hlive'⟩ := push_sign P s0 s1 x a hs1 ha
      have hlt' := hlt q y0 cert0 hlast0 hq
      cases j with
      | zero =>
        simp at hy; subst hy
        rw [ha] at hb; obtain rfl := Option.some.inj hb
        rw [hn] at hn'; obtain rfl := Option.some.inj hn'
        omega
      | succ j =>
        simp at hy
        have := ih s1 s hr _ n.checkpoint.createdAt hlive'
          ⟨a, cert, n, hlast, hn, Nat.le_refl _⟩ j y hy hk b n' hb hn'
        omega
    · rw [← push_other P s0 s1 x hs1 k (fun e => hxk e.symm)] at hlive hlast0
      cases j with
      | zero => simp at hy; subst hy; exact absurd hk hxk
      | succ j =>
        simp at hy
        exact ih s1 s hr k c hlive ⟨y0, cert0, q, hlast0, hq, hc⟩ j y hy hk b n' hb hn'

private theorem fold_created (P : Pins) : ∀ (xs : List Entry) (s0 s : LogState),
    xs.foldlM (push P) s0 = some s →
    ∀ (i j : Nat), i < j → ∀ (e e' : Entry), xs[i]? = some e → xs[j]? = some e' → e.shard = e'.shard →
    ∀ a b, e.body.signed? = some a → e'.body.signed? = some b → ∀ n n' : Stored,
      storedOfAny sha3 a = some n → storedOfAny sha3 b = some n' →
      n.checkpoint.createdAt < n'.checkpoint.createdAt := by
  intro xs
  induction xs with
  | nil => intro s0 s h i j hij e e' hi; simp at hi
  | cons x rest ih =>
    intro s0 s h i j hij e e' hi hj hk a b ha hb n n' hn hn'
    simp only [List.foldlM] at h
    obtain ⟨s1, hs1, hr⟩ := Option.bind_eq_some_iff.mp h
    cases i with
    | zero =>
      simp at hi; subst hi
      cases j with
      | zero => omega
      | succ j =>
        simp at hj
        obtain ⟨cert, n0, _, hn0, _, hlast, hlive⟩ := push_sign P s0 s1 _ a hs1 ha
        rw [hn] at hn0; obtain rfl := Option.some.inj hn0
        exact fold_last P rest s1 s hr _ n.checkpoint.createdAt hlive
          ⟨a, cert, n, hlast, hn, Nat.le_refl _⟩ j e' hj hk.symm b n' hb hn'
    | succ i =>
      cases j with
      | zero => omega
      | succ j =>
        simp at hi hj
        exact ih s1 s hr i j (by omega) e e' hi hj hk a b ha hb n n' hn hn'

/-- Per shard and payment, revisions never go down, and an equal revision later is never ALLOW. -/
theorem revision_mono (P : Pins) (log : List Entry) (hf : (fold P log).isSome) (i j : Nat) (hij : i < j)
    (e e' : Entry) (hi : log[i]? = some e) (hj : log[j]? = some e') (hk : e.shard = e'.shard)
    (l l' : Leaf) (hl : l ∈ e.body.leaves) (hl' : l' ∈ e'.body.leaves)
    (hp : payNat l.programId l.paymentId = payNat l'.programId l'.paymentId) :
    l.revision ≤ l'.revision ∧ (l.revision = l'.revision → l'.outcome ≠ .ALLOW) := by
  obtain ⟨st, hst⟩ := Option.isSome_iff_exists.mp hf
  exact fold_mono P log LogState.init st hst i j hij e e' hi hj hk l hl l' hl' hp

/-- An ALLOW past revision 0 re-decides an earlier ALLOW of the same shard by trunk `redecides`. -/
theorem revision_step (P : Pins) (log : List Entry) (hf : (fold P log).isSome) (j : Nat) (e' : Entry)
    (hj : log[j]? = some e') (l' : Leaf) (hl' : l' ∈ e'.body.leaves) (ha : l'.outcome = .ALLOW)
    (hr : 0 < l'.revision) :
    ∃ (i : Nat) (e : Entry) (l : Leaf), i ≤ j ∧ log[i]? = some e ∧ e.shard = e'.shard ∧ l ∈ e.body.leaves ∧
      redecides l.revision l l' = true := by
  obtain ⟨st, hst⟩ := Option.isSome_iff_exists.mp hf
  obtain ⟨o, ho, hrd⟩ := fold_redec P log LogState.init st hst j e' hj l' hl' ha hr
  rcases ho with ho | ⟨i, e, hij, hi, hs, ho⟩
  · simp [LogState.init, Shard.init] at ho
  · exact ⟨i, e, o, hij, hi, hs, ho, hrd⟩

/-- F8: signed checkpoints of one shard have strictly increasing createdAt. -/
theorem createdAt_strict (P : Pins) (log : List Entry) (hf : (fold P log).isSome) (i j : Nat) (hij : i < j)
    (e e' : Entry) (hi : log[i]? = some e) (hj : log[j]? = some e') (hk : e.shard = e'.shard)
    (a b : Bytes) (ha : e.body.signed? = some a) (hb : e'.body.signed? = some b) (n n' : Stored)
    (hn : storedOfAny sha3 a = some n) (hn' : storedOfAny sha3 b = some n') :
    n.checkpoint.createdAt < n'.checkpoint.createdAt := by
  obtain ⟨st, hst⟩ := Option.isSome_iff_exists.mp hf
  exact fold_created P log LogState.init st hst i j hij e e' hi hj hk a b ha hb n n' hn hn'

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

/-- Two leaves of one pushed sign entry with one payment id are one leaf (publishOkAny: ids strictly ascending). -/
private theorem cust_leaf_eq (P : Pins) (st st' : LogState) (e : Entry) (h : push P st e = some st')
    (l l' : Leaf) (hl : l ∈ e.body.leaves) (hl' : l' ∈ e.body.leaves) (hp : l.paymentId = l'.paymentId) :
    l = l' := by
  have inj : ∀ (L : List Leaf), (L.map (·.paymentId)).Nodup →
      ∀ a ∈ L, ∀ b ∈ L, a.paymentId = b.paymentId → a = b := by
    intro L
    induction L with
    | nil => intro _ a ha; simp at ha
    | cons x xs ih =>
      intro hn a ha b hb hab
      simp only [List.map_cons, List.nodup_cons, List.mem_map, not_exists, not_and] at hn
      rcases List.mem_cons.mp ha with rfl | ha' <;> rcases List.mem_cons.mp hb with rfl | hb'
      · rfl
      · exact absurd hab.symm (hn.1 b hb')
      · exact absurd hab (hn.1 a ha')
      · exact ih hn.2 a ha' b hb' hab
  unfold push at h
  cases hb : e.body with
  | sign cert new tokens fresh =>
    rw [hb] at hl hl'
    simp [hb, Option.bind_eq_some_iff, cust_guard] at h
    obtain ⟨_, _, _, _, _, _, _, _, n, hn, c, hc, _, hpub, -⟩ := h
    simp only [publishOkAny, hc, hn, Bool.and_eq_true] at hpub
    have hnd := ascending_nodup _ hpub.1.2
    have hL : (Body.sign cert new tokens fresh).leaves = (tokens.filterMap decodeToken).map (·.leaf) := by
      simp [Body.leaves, List.map_filterMap]
    rw [hL] at hl hl'
    exact inj _ (by rw [List.map_map]; exact hnd) l hl l' hl' hp
  | resume _ => rw [hb] at hl; simp [Body.leaves] at hl
  | «seal» _ => rw [hb] at hl; simp [Body.leaves] at hl

/-- A prefix of a folding log folds. -/
private theorem cust_fold_pre (P : Pins) (l r : List Entry) (h : (fold P (l ++ r)).isSome) :
    (fold P l).isSome := by
  simp only [fold, List.foldlM_append] at h
  cases hx : l.foldlM (push P) LogState.init with
  | none => rw [hx] at h; simp at h
  | some _ => simp [fold, hx]

/-- An entry at position m of a folding log: the prefix before it folds, it pushes, its index is m. -/
private theorem cust_fold_at (P : Pins) (l : List Entry) (h : (fold P l).isSome) (m : Nat) (e : Entry)
    (hm : l[m]? = some e) :
    ∃ st st', fold P (l.take m) = some st ∧ push P st e = some st' ∧ e.idx = m ∧
      (fold P (l.take (m + 1))).isSome := by
  have hlt : m < l.length := (List.getElem?_eq_some_iff.mp hm).1
  have ht : l.take (m + 1) = l.take m ++ [e] := by simp [List.take_add_one, hm]
  have hp : (fold P (l.take (m + 1))).isSome :=
    cust_fold_pre P _ (l.drop (m + 1)) (by rw [List.take_append_drop]; exact h)
  have hp' := hp
  rw [ht] at hp'
  obtain ⟨st', hst'⟩ := Option.isSome_iff_exists.mp hp'
  obtain ⟨st, h1, h2⟩ := (cust_fold_snoc P _ e st').mp hst'
  refine ⟨st, st', h1, h2, ?_, hp⟩
  rw [(cust_push P st st' e h2).1, cust_fold_len P _ st h1, List.length_take]
  omega

/-- A pushed signed checkpoint is stored and names the entry's shard. -/
private theorem cust_push_signed (P : Pins) (st st' : LogState) (e : Entry) (h : push P st e = some st')
    (x : Bytes) (hx : e.body.signed? = some x) :
    ∃ n, storedOfAny sha3 x = some n ∧ n.checkpoint.shardId = e.shard := by
  cases hb : e.body with
  | sign cert new tokens f =>
    rw [hb] at hx
    simp only [Body.signed?, Option.some.injEq] at hx
    subst hx
    obtain ⟨c, n, -, hn, hs, -⟩ := (cust_push P st st' e h).2.2.2.2 cert new tokens f hb
    exact ⟨n, hn, hs⟩
  | resume _ => rw [hb] at hx; simp [Body.signed?] at hx
  | «seal» _ => rw [hb] at hx; simp [Body.signed?] at hx

/-- In a folding log one signed checkpoint sits at one position (F8: createdAt strictly increasing). -/
private theorem cust_signed_uniq (P : Pins) (l : List Entry) (h : (fold P l).isSome) (m m' : Nat)
    (e e' : Entry) (hm : l[m]? = some e) (hm' : l[m']? = some e') (x : Bytes)
    (hx : e.body.signed? = some x) (hx' : e'.body.signed? = some x) : m = m' := by
  have stored : ∀ (j : Nat) (y : Entry), l[j]? = some y → y.body.signed? = some x →
      ∃ n, storedOfAny sha3 x = some n ∧ n.checkpoint.shardId = y.shard := by
    intro j y hj hy
    obtain ⟨st, st', -, hp, -, -⟩ := cust_fold_at P l h j y hj
    exact cust_push_signed P st st' y hp x hy
  obtain ⟨n, hn, hs⟩ := stored m e hm hx
  obtain ⟨n', hn', hs'⟩ := stored m' e' hm' hx'
  have hnn : n = n' := Option.some.inj (hn.symm.trans hn')
  subst hnn
  have hk : e.shard = e'.shard := hs.symm.trans hs'
  rcases Nat.lt_trichotomy m m' with hlt | heq | hgt
  · exact absurd (createdAt_strict P l h m m' hlt e e' hm hm' hk x x hx hx' n n hn hn) (Nat.lt_irrefl _)
  · exact heq
  · exact absurd (createdAt_strict P l h m' m hgt e' e hm' hm hk.symm x x hx' hx n n hn hn) (Nat.lt_irrefl _)

/-- Unless a released signed was lost, every released entry sits at its own index under a folding prefix:
    a rollback past it would need another copy of its signed below it in that prefix (F8 forbids). -/
private theorem cust_out_inv (P : Pins) (cert₀ : Bytes) (s : Cust) (hr : Reach P cert₀ s) :
    (∀ e ∈ s.made, ∃ x, e.body.signed? = some x) ∧ (∀ e ∈ s.out, e ∈ s.made) ∧
    (¬ s.lost → ∀ e ∈ s.out, s.off[e.idx]? = some e ∧ (fold P (s.off.take (e.idx + 1))).isSome) := by
  have keep : ∀ (off : List Entry) (y x : Entry), off[x.idx]? = some x →
      (fold P (off.take (x.idx + 1))).isSome →
      (off ++ [y])[x.idx]? = some x ∧ (fold P ((off ++ [y]).take (x.idx + 1))).isSome := by
    intro off y x h1 h2
    have hlt : x.idx < off.length := (List.getElem?_eq_some_iff.mp h1).1
    rw [List.getElem?_append_left hlt, List.take_append_of_le_length (by omega)]
    exact ⟨h1, h2⟩
  induction hr with
  | init => simp [Cust.init]
  | honest s s' _ hs ih =>
    obtain ⟨hA, hB, hC⟩ := ih
    cases hs with
    | sign k0 st0 b0 v0 i new tokens e hf0 hb hc hi he =>
      obtain ⟨-, ⟨f, hbody⟩, -⟩ := cust_custodyOk P st0 k0 (s.cert k0) i new tokens e he
      refine ⟨fun x hx => ?_, fun x hx => List.mem_append_left _ (hB x hx),
        fun hl x hx => keep _ e x (hC hl x hx).1 (hC hl x hx).2⟩
      rcases List.mem_append.mp hx with hx | hx
      · exact hA x hx
      · rw [List.mem_singleton.mp hx, hbody]; exact ⟨new, rfl⟩
    | bump k0 b0 v0 hb hc => exact ⟨hA, hB, hC⟩
    | activate e hs hfo => exact ⟨hA, hB, fun hl x hx => keep _ e x (hC hl x hx).1 (hC hl x hx).2⟩
    | define k0 c0 hc => exact ⟨hA, hB, hC⟩
    | ceremony k0 cert hc hdc => exact ⟨hA, hB, hC⟩
    | release e hm ho hb =>
      refine ⟨hA, fun x hx => ?_, fun hl x hx => ?_⟩
      · rcases List.mem_append.mp hx with hx | hx
        · exact hB x hx
        · rw [List.mem_singleton.mp hx]; exact hm
      · rcases List.mem_append.mp hx with hx | hx
        · exact hC hl x hx
        · rw [List.mem_singleton.mp hx]
          have hfs : (fold P s.off).isSome := by
            revert hb; unfold boot; cases fold P s.off <;> simp
          obtain ⟨m, hm'⟩ := List.mem_iff_getElem?.mp ho
          obtain ⟨-, -, -, -, hidx, hpre⟩ := cust_fold_at P s.off hfs m e hm'
          rw [hidx]; exact ⟨hm', hpre⟩
  | adv s s' _ ha ih =>
    obtain ⟨hA, hB, hC⟩ := ih
    cases ha with
    | offRollback j =>
      refine ⟨hA, hB, fun hn x hx => ?_⟩
      have hl : ¬ s.lost := fun h => hn (Or.inl h)
      obtain ⟨h1, h2⟩ := hC hl x hx
      by_cases hj : x.idx < j
      · refine ⟨by rw [List.getElem?_take_of_lt hj]; exact h1, ?_⟩
        have ht : (s.off.take j).take (x.idx + 1) = s.off.take (x.idx + 1) := by
          rw [List.take_take]; congr 1; omega
        rw [ht]; exact h2
      · exfalso
        obtain ⟨y, hy, hys⟩ : ∃ y ∈ s.off.take j, y.body.signed? = x.body.signed? :=
          Classical.byContradiction fun hc => hn (Or.inr ⟨x, hx, fun y hy h => hc ⟨y, hy, h⟩⟩)
        obtain ⟨m, hm⟩ := List.mem_iff_getElem?.mp hy
        have hmj : m < j := by
          have := (List.getElem?_eq_some_iff.mp hm).1
          simp only [List.length_take] at this; omega
        rw [List.getElem?_take_of_lt hmj] at hm
        obtain ⟨z, hz⟩ := hA x (hB x hx)
        have := cust_signed_uniq P _ h2 m x.idx y x
          (by rw [List.getElem?_take_of_lt (by omega)]; exact hm)
          (by rw [List.getElem?_take_of_lt (by omega)]; exact h1) z (hys.trans hz) hz
        omega
    | foreignWrite e hr => exact ⟨hA, hB, fun hl x hx => keep _ e x (hC hl x hx).1 (hC hl x hx).2⟩
    | tpmClear k => exact ⟨hA, hB, hC⟩

/-- H2: unless a released signed was ever lost, one shard never releases two ALLOWs for one payment and
    revision, except as the same leaf of the same signed checkpoint. -/
theorem never_twice (P : Pins) (cert₀ : Bytes) (s : Cust) (hr : Reach P cert₀ s) (hl : ¬ s.lost)
    (e e' : Entry) (he : e ∈ s.out) (he' : e' ∈ s.out) (hk : e.shard = e'.shard) (l l' : Leaf)
    (hl1 : l ∈ e.body.leaves) (hl2 : l' ∈ e'.body.leaves) (ha : l.outcome = .ALLOW) (ha' : l'.outcome = .ALLOW)
    (hp : l.programId = l'.programId ∧ l.paymentId = l'.paymentId ∧ l.revision = l'.revision) :
    (e.body.signed? = e'.body.signed? ∧ l = l') ∨ ChainCollision s := by
  obtain ⟨-, -, hC⟩ := cust_out_inv P cert₀ s hr
  obtain ⟨h1, f1⟩ := hC hl e he
  obtain ⟨h2, f2⟩ := hC hl e' he'
  have hpn : payNat l.programId l.paymentId = payNat l'.programId l'.paymentId := by rw [hp.1, hp.2.1]
  left
  rcases Nat.lt_trichotomy e.idx e'.idx with hlt | heq | hgt
  · exact absurd ha' ((revision_mono P _ f2 e.idx e'.idx hlt e e'
      (by rw [List.getElem?_take_of_lt (by omega)]; exact h1)
      (by rw [List.getElem?_take_of_lt (by omega)]; exact h2) hk l l' hl1 hl2 hpn).2 hp.2.2)
  · rw [heq] at h1
    have hee : e = e' := Option.some.inj (h1.symm.trans h2)
    subst hee
    obtain ⟨st, st', -, hpush, -, -⟩ := cust_fold_at P _ f2 e.idx e
      (by rw [List.getElem?_take_of_lt (by omega)]; exact h2)
    exact ⟨rfl, cust_leaf_eq P st st' e hpush l l' hl1 hl2 hp.2.1⟩
  · exact absurd ha ((revision_mono P _ f1 e'.idx e.idx hgt e' e
      (by rw [List.getElem?_take_of_lt (by omega)]; exact h2)
      (by rw [List.getElem?_take_of_lt (by omega)]; exact h1) hk.symm l' l hl2 hl1 hpn.symm).2 hp.2.2.symm)

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

/-- The signed checkpoint an entry counts on shard k at cert epoch E, if any. -/
private def cust_sig (k E : Nat) (x : Entry) : Option Bytes :=
  match x.body with
  | .sign cert new _ _ => if x.shard = k ∧ (decodeKeyCert cert).map (·.epoch) = some E then some new else none
  | _ => none

private theorem cust_sig_some {k E : Nat} {x : Entry} {y : Bytes} (h : cust_sig k E x = some y) :
    x.shard = k ∧ x.body.signed? = some y := by
  cases hb : x.body with
  | sign cert new tokens f =>
    simp only [cust_sig, hb] at h
    split at h
    · rename_i hc; cases h; exact ⟨hc.1, by simp [Body.signed?]⟩
    · cases h
  | resume _ => simp [cust_sig, hb] at h
  | «seal» _ => simp [cust_sig, hb] at h

private theorem cust_sig_none {k E : Nat} {x : Entry} (h : x.body.signed? = none) : cust_sig k E x = none := by
  cases hs : cust_sig k E x with
  | none => rfl
  | some y => rw [(cust_sig_some hs).2] at h; cases h

/-- A folded shard's count at epoch E is the number of signeds the log counts there. -/
private theorem cust_own (P : Pins) (k E : Nat) (p : List Entry) (st : LogState) (h : fold P p = some st) :
    (st.shard k).own E = (p.filterMap (cust_sig k E)).length := by
  suffices ∀ (l : List Entry) s0 st, l.foldlM (push P) s0 = some st →
      (st.shard k).own E = (s0.shard k).own E + (l.filterMap (cust_sig k E)).length by
    simpa [LogState.init, Shard.init] using this p LogState.init st h
  intro l
  induction l with
  | nil => intro s0 st h; simp at h; subst h; simp
  | cons e l ih =>
    intro s0 st h
    simp only [List.foldlM] at h
    obtain ⟨s1, hs1, hr⟩ := Option.bind_eq_some_iff.mp h
    rw [ih s1 st hr, show e :: l = [e] ++ l from rfl, List.filterMap_append, List.length_append]
    suffices (s1.shard k).own E = (s0.shard k).own E + ([e].filterMap (cust_sig k E)).length by omega
    obtain ⟨-, -, hoth, hns, hsg⟩ := cust_push P s0 s1 e hs1
    by_cases hk : e.shard = k
    · subst hk
      cases hb : e.body with
      | sign cert new tokens f =>
        obtain ⟨c, n, hc, -, -, hown⟩ := hsg cert new tokens f hb
        rw [hown]
        by_cases hE : c.epoch = E
        · subst hE; simp [cust_sig, hb, hc, upd]
        · simp [cust_sig, hb, hc, upd, hE, Ne.symm hE]
      | resume _ => rw [hns (by simp [Body.signed?, hb])]; simp [cust_sig, hb]
      | «seal» _ => rw [hns (by simp [Body.signed?, hb])]; simp [cust_sig, hb]
    · rw [hoth k (Ne.symm hk)]
      cases hb : e.body <;> simp [cust_sig, hb, hk]

/-- A folding log counts each signed once. -/
private theorem cust_sigs_nodup (P : Pins) (k E : Nat) (p : List Entry) (h : (fold P p).isSome) :
    (p.filterMap (cust_sig k E)).Nodup := by
  unfold List.Nodup
  rw [List.pairwise_filterMap, List.pairwise_iff_getElem]
  intro i j hi hj hij y hy y' hy' hyy
  subst hyy
  have := cust_signed_uniq P p h i j p[i] p[j] (List.getElem?_eq_some_iff.mpr ⟨hi, rfl⟩)
    (List.getElem?_eq_some_iff.mpr ⟨hj, rfl⟩) y (cust_sig_some hy).2 (cust_sig_some hy').2
  omega

/-- Counted signeds S fit a set T for counter span N: inside T, or N of T plus one fresh signed on top. -/
private def cust_fits (T : List Bytes) (N : Nat) (S : List Bytes) : Prop :=
  S ⊆ T ∨ ∃ S0 y, S = S0 ++ [y] ∧ S0 ⊆ T ∧ S0.length = N

/-- Until a TPM clear: each made entry is a stored signed under its shard's live cert; a shard with no counter
    counts no signed in a folding prefix; a counted shard's signeds at its cert epoch fit a set T of at most
    v - b signeds holding every released one. -/
private theorem cust_lost_inv (P : Pins) (cert₀ : Bytes) (s : Cust) (hr : Reach P cert₀ s) :
    s.cleared = false →
    (∀ e ∈ s.made, s.ctr e.shard ≠ none ∧ ∃ new tokens f n, e.body = .sign (s.cert e.shard) new tokens f ∧
      storedOfAny sha3 new = some n ∧ n.checkpoint.shardId = e.shard) ∧
    (∀ k p, s.ctr k = none → p <+: s.off → (fold P p).isSome → ∀ x ∈ p, x.shard = k →
      x.body.signed? = none) ∧
    (∀ k b v c, s.ctr k = some (b, v) → decodeKeyCert (s.cert k) = some c → b ≤ v ∧
      ∃ T : List Bytes, T.length ≤ v - b ∧ (∀ e ∈ s.out, e.shard = k → ∃ x, e.body.signed? = some x ∧ x ∈ T) ∧
      ∀ p, p <+: s.off → (fold P p).isSome → cust_fits T (v - b) (p.filterMap (cust_sig k c.epoch))) := by
  induction hr with
  | init =>
    intro _
    refine ⟨fun e he => by simp [Cust.init] at he, fun k p _ hp _ x hx _ => ?_,
      fun k b v c hk => by simp [Cust.init] at hk⟩
    simp [Cust.init] at hp; subst hp; simp at hx
  | honest s s' hrs hs ih =>
    intro hcl
    have hB := (cust_out_inv P cert₀ s hrs).2.1
    cases hs with
    | sign k0 st0 b0 v0 i new tokens e hf0 hb hc hi he =>
      obtain ⟨hM, hZ, hF⟩ := ih hcl
      obtain ⟨hsh, ⟨f, hbody⟩, st1, hp⟩ := cust_custodyOk P st0 k0 _ i new tokens e he
      subst hsh
      obtain ⟨c, n, hc', hn, hns, -⟩ := (cust_push P st0 st1 e hp).2.2.2.2 _ _ _ _ hbody
      have hok : v0 - b0 = (st0.shard e.shard).own c.epoch := by
        rw [cust_boot P s _ st0 b0 v0 c hf0 hc hc'] at hb
        split at hb
        · assumption
        · split at hb <;> cases hb
      have hf0' : (fold P s.off).isSome := by rw [hf0]; rfl
      dsimp only
      refine ⟨fun x hx => ?_, fun k p hk hpp hfp x hx hxk => ?_, fun k b v c0 hk hdk => ?_⟩
      · rcases List.mem_append.mp hx with hx | hx
        · exact hM x hx
        · rw [List.mem_singleton.mp hx]
          exact ⟨by rw [hc]; simp, new, tokens, f, n, hbody, hn, hns⟩
      · rcases List.prefix_concat_iff.mp hpp with rfl | hpp
        · rcases List.mem_append.mp hx with hx | hx
          · exact hZ k s.off hk (List.prefix_refl _) hf0' x hx hxk
          · rw [List.mem_singleton.mp hx] at hxk; rw [← hxk, hc] at hk; cases hk
        · exact hZ k p hk hpp hfp x hx hxk
      · obtain ⟨hbv, T, hT, hout, hfit⟩ := hF k b v c0 hk hdk
        refine ⟨hbv, T, hT, hout, fun p hpp hfp => ?_⟩
        rcases List.prefix_concat_iff.mp hpp with rfl | hpp
        · have hfit0 := hfit s.off (List.prefix_refl _) hf0'
          rw [List.filterMap_append]
          by_cases hke : k = e.shard
          · subst hke
            rw [hc] at hk; rw [hc'] at hdk
            simp only [Option.some.injEq, Prod.mk.injEq] at hk hdk
            obtain ⟨rfl, rfl⟩ := hk
            subst hdk
            have hS := cust_own P e.shard c.epoch s.off st0 hf0
            rcases hfit0 with hsub | ⟨S0, y, hS0, -, hl⟩
            · exact Or.inr ⟨s.off.filterMap (cust_sig e.shard c.epoch), new,
                by simp [cust_sig, hbody, hc'], hsub, by omega⟩
            · simp [hS0] at hS; omega
          · have hn0 : cust_sig k c0.epoch e = none := by simp [cust_sig, hbody, Ne.symm hke]
            rw [List.filterMap_cons_none hn0, List.filterMap_nil, List.append_nil]
            exact hfit0
        · exact hfit p hpp hfp
    | bump k0 b0 v0 hb hc =>
      obtain ⟨hM, hZ, hF⟩ := ih hcl
      dsimp only
      refine ⟨fun x hx => ?_, fun k p hk => ?_, fun k b v c hk hdk => ?_⟩
      · obtain ⟨h1, h2⟩ := hM x hx
        refine ⟨?_, h2⟩
        by_cases hke : x.shard = k0
        · rw [hke]; simp [upd]
        · simp only [upd, if_neg hke]; exact h1
      · by_cases hke : k = k0
        · subst hke; simp [upd] at hk
        · simp only [upd, if_neg hke] at hk; exact hZ k p hk
      · by_cases hke : k = k0
        · subst hke
          simp [upd] at hk
          obtain ⟨rfl, rfl⟩ := hk
          cases hf : fold P s.off with
          | none => simp [boot, hf] at hb
          | some st =>
            have hfin : v0 - b0 + 1 = (st.shard k).own c.epoch := by
              rw [cust_boot P s _ st b0 v0 c hf hc hdk] at hb
              split at hb
              · cases hb
              · split at hb
                · assumption
                · cases hb
            obtain ⟨hbv, T, hT, hout, hfit⟩ := hF k b0 v0 c hc hdk
            have hS := cust_own P k c.epoch s.off st hf
            have hf' : (fold P s.off).isSome := by rw [hf]; rfl
            rcases hfit s.off (List.prefix_refl _) hf' with hsub | ⟨S0, y, hS0, hsub, hl⟩
            · have := (cust_sigs_nodup P k c.epoch s.off hf').length_le_of_subset hsub; omega
            · refine ⟨by omega, T ++ [y], by simp; omega, fun x hx hxk => ?_, fun p hpp _ => Or.inl ?_⟩
              · obtain ⟨z, hz, hzT⟩ := hout x hx hxk; exact ⟨z, hz, List.mem_append_left _ hzT⟩
              · intro z hz
                have hz' := (hpp.filterMap (cust_sig k c.epoch)).subset hz
                rw [hS0] at hz'
                rcases List.mem_append.mp hz' with hz' | hz'
                · exact List.mem_append_left _ (hsub hz')
                · exact List.mem_append_right _ hz'
        · simp only [upd, if_neg hke] at hk; exact hF k b v c hk hdk
    | activate e hs hfo =>
      obtain ⟨hM, hZ, hF⟩ := ih hcl
      have hf0 := cust_fold_pre P s.off [e] hfo
      dsimp only
      refine ⟨hM, fun k p hk hpp hfp x hx hxk => ?_, fun k b v c hk hdk => ?_⟩
      · rcases List.prefix_concat_iff.mp hpp with rfl | hpp
        · rcases List.mem_append.mp hx with hx | hx
          · exact hZ k s.off hk (List.prefix_refl _) hf0 x hx hxk
          · rw [List.mem_singleton.mp hx]; exact hs
        · exact hZ k p hk hpp hfp x hx hxk
      · obtain ⟨hbv, T, hT, hout, hfit⟩ := hF k b v c hk hdk
        refine ⟨hbv, T, hT, hout, fun p hpp hfp => ?_⟩
        rcases List.prefix_concat_iff.mp hpp with rfl | hpp
        · rw [List.filterMap_append, List.filterMap_cons_none (cust_sig_none hs), List.filterMap_nil,
            List.append_nil]
          exact hfit s.off (List.prefix_refl _) hf0
        · exact hfit p hpp hfp
    | define k0 c0 hc =>
      obtain ⟨hM, hZ, hF⟩ := ih hcl
      dsimp only
      refine ⟨fun x hx => ?_, fun k p hk => ?_, fun k b v c hk hdk => ?_⟩
      · obtain ⟨h1, h2⟩ := hM x hx
        refine ⟨?_, h2⟩
        by_cases hke : x.shard = k0
        · rw [hke]; simp [upd]
        · simp only [upd, if_neg hke]; exact h1
      · by_cases hke : k = k0
        · subst hke; simp [upd] at hk
        · simp only [upd, if_neg hke] at hk; exact hZ k p hk
      · by_cases hke : k = k0
        · subst hke
          simp [upd] at hk
          obtain ⟨rfl, rfl⟩ := hk
          refine ⟨Nat.le_refl _, [], Nat.zero_le _, fun x hx hxk => ?_, fun p hpp hfp => Or.inl ?_⟩
          · exact ((hM x (hB x hx)).1 (by rw [hxk]; exact hc)).elim
          · intro y hy
            obtain ⟨x, hx, hxy⟩ := List.mem_filterMap.mp hy
            obtain ⟨hxk, hxs⟩ := cust_sig_some hxy
            rw [hZ _ p hc hpp hfp x hx hxk] at hxs; cases hxs
        · simp only [upd, if_neg hke] at hk; exact hF k b v c hk hdk
    | ceremony k0 cert hc hdc =>
      obtain ⟨hM, hZ, hF⟩ := ih hcl
      dsimp only
      refine ⟨fun x hx => ?_, hZ, fun k b v c hk hdk => ?_⟩
      · obtain ⟨h1, h2⟩ := hM x hx
        have hne : x.shard ≠ k0 := fun h => h1 (by rw [h]; exact hc)
        simp only [upd, if_neg hne]; exact ⟨h1, h2⟩
      · have hne : k ≠ k0 := fun h => by rw [h, hc] at hk; cases hk
        simp only [upd, if_neg hne] at hdk; exact hF k b v c hk hdk
    | release e hm ho hb =>
      obtain ⟨hM, hZ, hF⟩ := ih hcl
      dsimp only
      refine ⟨hM, hZ, fun k b v c hk hdk => ?_⟩
      obtain ⟨hbv, T, hT, hout, hfit⟩ := hF k b v c hk hdk
      refine ⟨hbv, T, hT, fun x hx hxk => ?_, hfit⟩
      rcases List.mem_append.mp hx with hx | hx
      · exact hout x hx hxk
      · rw [List.mem_singleton.mp hx] at hxk ⊢
        subst hxk
        obtain ⟨-, new, tokens, f, -, hbody, -⟩ := hM e hm
        cases hf : fold P s.off with
        | none => simp [boot, hf] at hb
        | some st =>
          rw [cust_boot P s e.shard st b v c hf hk hdk] at hb
          have hok : v - b = (st.shard e.shard).own c.epoch := by
            split at hb
            · assumption
            · split at hb <;> cases hb
          have hS := cust_own P e.shard c.epoch s.off st hf
          rcases hfit s.off (List.prefix_refl _) (by rw [hf]; rfl) with hsub | ⟨S0, y, hS0, -, hl⟩
          · refine ⟨new, by rw [hbody]; rfl, hsub (List.mem_filterMap.mpr ⟨e, ho, ?_⟩)⟩
            simp [cust_sig, hbody, hdk]
          · simp [hS0] at hS; omega
  | adv s s' hrs ha ih =>
    intro hcl
    have hB := (cust_out_inv P cert₀ s hrs).2.1
    cases ha with
    | offRollback j =>
      obtain ⟨hM, hZ, hF⟩ := ih hcl
      dsimp only
      refine ⟨hM, fun k p hk hpp => hZ k p hk (hpp.trans (List.take_prefix j s.off)), fun k b v c hk hdk => ?_⟩
      obtain ⟨hbv, T, hT, hout, hfit⟩ := hF k b v c hk hdk
      exact ⟨hbv, T, hT, hout, fun p hpp => hfit p (hpp.trans (List.take_prefix j s.off))⟩
    | foreignWrite e hrw =>
      obtain ⟨hM, hZ, hF⟩ := ih hcl
      dsimp only
      -- a signed the foreign entry pushes is a released signed of the same shard (stored shardId)
      have hrel : (fold P (s.off ++ [e])).isSome → ∀ y, e.body.signed? = some y →
          ∃ e' ∈ s.out, e'.shard = e.shard ∧ e'.body.signed? = some y := by
        intro hfo y hy
        obtain ⟨st1, hf1⟩ := Option.isSome_iff_exists.mp hfo
        obtain ⟨st0, -, hp⟩ := (cust_fold_snoc P s.off e st1).mp hf1
        obtain ⟨n, hn, hsh⟩ := cust_push_signed P st0 st1 e hp y hy
        obtain ⟨e', he', hy'⟩ := hrw y hy
        obtain ⟨-, new, tokens, f, n', hb', hn', hsh'⟩ := hM e' (hB e' he')
        rw [hb'] at hy'
        simp only [Body.signed?, Option.some.injEq] at hy'
        rw [← hy', hn'] at hn
        cases hn
        exact ⟨e', he', hsh'.symm.trans hsh, by rw [hb', ← hy']; rfl⟩
      refine ⟨hM, fun k p hk hpp hfp x hx hxk => ?_, fun k b v c hk hdk => ?_⟩
      · rcases List.prefix_concat_iff.mp hpp with rfl | hpp
        · rcases List.mem_append.mp hx with hx | hx
          · exact hZ k s.off hk (List.prefix_refl _) (cust_fold_pre P s.off [e] hfp) x hx hxk
          · rw [List.mem_singleton.mp hx] at hxk ⊢
            cases hy : e.body.signed? with
            | none => rfl
            | some y =>
              obtain ⟨e', he', hsh, -⟩ := hrel hfp y hy
              exact ((hM e' (hB e' he')).1 (by rw [hsh, hxk]; exact hk)).elim
        · exact hZ k p hk hpp hfp x hx hxk
      · obtain ⟨hbv, T, hT, hout, hfit⟩ := hF k b v c hk hdk
        refine ⟨hbv, T, hT, hout, fun p hpp hfp => ?_⟩
        rcases List.prefix_concat_iff.mp hpp with rfl | hpp
        · have hfit0 := hfit s.off (List.prefix_refl _) (cust_fold_pre P s.off [e] hfp)
          have hnd := cust_sigs_nodup P k c.epoch _ hfp
          rw [List.filterMap_append] at hnd ⊢
          cases hy : cust_sig k c.epoch e with
          | none =>
            rw [List.filterMap_cons_none hy, List.filterMap_nil, List.append_nil]; exact hfit0
          | some y =>
            rw [List.filterMap_cons_some hy, List.filterMap_nil] at hnd ⊢
            obtain ⟨hek, hsy⟩ := cust_sig_some hy
            obtain ⟨e', he', hsh, hy'⟩ := hrel hfp y hsy
            obtain ⟨z, hz, hzT⟩ := hout e' he' (hsh.trans hek)
            rw [hy', Option.some.injEq] at hz
            rw [← hz] at hzT
            rcases hfit0 with hsub | ⟨S0, y0, hS0, hsub, hl⟩
            · exact Or.inl (List.append_subset.mpr ⟨hsub, List.cons_subset.mpr ⟨hzT, List.nil_subset _⟩⟩)
            · exfalso
              rw [hS0, List.append_assoc] at hnd
              have h1 := (hnd.sublist ((List.sublist_append_right [y0] [y]).append_left S0)).length_le_of_subset
                (List.append_subset.mpr ⟨hsub, List.cons_subset.mpr ⟨hzT, List.nil_subset _⟩⟩)
              simp at h1; omega
        · exact hfit p hpp hfp
    | tpmClear k => simp at hcl

/-- H2 + H1: a released signed missing from the store stops its shard at boot, unless the TPM was cleared. -/
theorem lost_detected (P : Pins) (cert₀ : Bytes) (s : Cust) (hr : Reach P cert₀ s) (e : Entry)
    (he : e ∈ s.out) (hg : Gone s e) : s.cleared = true ∨ boot P s e.shard = .stop ∨ ChainCollision s := by
  cases hcl : s.cleared
  · obtain ⟨hM, -, hF⟩ := cust_lost_inv P cert₀ s hr hcl
    right; left
    obtain ⟨hne, new, tokens, f, -, hbody, -⟩ := hM e ((cust_out_inv P cert₀ s hr).2.1 e he)
    cases hc : s.ctr e.shard with
    | none => exact absurd hc hne
    | some bv =>
      obtain ⟨b, v⟩ := bv
      cases hf : fold P s.off with
      | none => simp [boot, hf]
      | some st =>
        cases hd : decodeKeyCert (s.cert e.shard) with
        | none => simp [boot, hf, hc, hd]
        | some c =>
          obtain ⟨-, T, hT, hout, hfit⟩ := hF e.shard b v c hc hd
          obtain ⟨x, hx, hxT⟩ := hout e he rfl
          rw [hbody] at hx; simp only [Body.signed?, Option.some.injEq] at hx
          rw [← hx] at hxT
          have hS := cust_own P e.shard c.epoch s.off st hf
          have hnd := cust_sigs_nodup P e.shard c.epoch s.off (by rw [hf]; rfl)
          have hnot : new ∉ s.off.filterMap (cust_sig e.shard c.epoch) := fun hm => by
            obtain ⟨y, hy, hyx⟩ := List.mem_filterMap.mp hm
            exact hg y hy (by rw [(cust_sig_some hyx).2, hbody]; rfl)
          rw [cust_boot P s e.shard st b v c hf hc hd]
          rcases hfit s.off (List.prefix_refl _) (by rw [hf]; rfl) with hsub | ⟨S0, y, hS0, hsub, hl⟩
          · have := (List.nodup_cons.mpr ⟨hnot, hnd⟩).length_le_of_subset (List.cons_subset.mpr ⟨hxT, hsub⟩)
            simp only [List.length_cons] at this
            split
            · omega
            · split
              · omega
              · rfl
          · exfalso
            rw [hS0] at hnot hnd
            have := (List.nodup_cons.mpr ⟨fun h => hnot (List.mem_append_left _ h),
              hnd.sublist (List.sublist_append_left _ _)⟩).length_le_of_subset (List.cons_subset.mpr ⟨hxT, hsub⟩)
            simp only [List.length_cons] at this
            omega
  · exact Or.inl rfl

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
