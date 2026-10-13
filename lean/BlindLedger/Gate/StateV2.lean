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
  witness (refusal), never a decision; evidenceRoot stays unchecked (trunk writes zero) until MAN-0 S2 binds it to the read manifest; never_twice is per shard,
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
import BlindLedger.Gate.AnchorTheorems
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

private theorem emptyIn_ne_leafIn (p v : Bytes) : emptyIn ≠ leafIn p v := by
  intro h; unfold emptyIn leafIn at h
  have := List.append_cancel_left h; simp at this

private theorem emptyIn_ne_nodeIn (l r : Bytes) : emptyIn ≠ nodeIn l r := by
  intro h; unfold emptyIn nodeIn at h
  have := List.append_cancel_left h; simp at this

private theorem leafIn_ne_nodeIn (p v l r : Bytes) : leafIn p v ≠ nodeIn l r := by
  intro h; unfold leafIn nodeIn at h
  have := List.append_cancel_left h; simp at this

private theorem hashPf_len (H : Bytes → Bytes) (hH : HashLen H) (d : Nat) (pf : Proof) (ks : List Bytes)
    (h : minimal d pf ks = true) : (hashPf H pf).length = digestBytes := by
  cases pf with
  | «opaque» x => simpa [minimal, hashPf] using h
  | empty => exact hH _
  | leaf p v =>
    by_cases hl : leafOk p v = true
    · simp only [hashPf, hl, ↓reduceIte]; exact hH _
    · simp [minimal, hl] at h
  | node l r => exact hH _

private theorem rootAt_nil (H : Bytes → Bytes) (f d : Nat) : rootAt H f d [] = H emptyIn := by
  cases f <;> first | rfl | simp [rootAt]
private theorem rootAt_one (H : Bytes → Bytes) (f d : Nat) (p v : Bytes) : rootAt H f d [(p, v)] = H (leafIn p v) := by
  cases f <;> first | rfl | simp [rootAt]
private theorem rootAt_zero2 (H : Bytes → Bytes) (d : Nat) (a b : Bytes × Bytes) (t : Map) : rootAt H 0 d (a :: b :: t) = [] := by
  first | rfl | simp [rootAt]
private theorem rootAt_succ2 (H : Bytes → Bytes) (f d : Nat) (a b : Bytes × Bytes) (t : Map) :
    rootAt H (f + 1) d (a :: b :: t) = H (nodeIn (rootAt H f (d + 1) ((a :: b :: t).filter fun e => !bit e.1 d))
      (rootAt H f (d + 1) ((a :: b :: t).filter fun e => bit e.1 d))) := by
  first | rfl | simp [rootAt]
private theorem treeInputs_nil (H : Bytes → Bytes) (f d : Nat) : treeInputs H f d [] = [emptyIn] := by
  cases f <;> first | rfl | simp [treeInputs]
private theorem treeInputs_one (H : Bytes → Bytes) (f d : Nat) (p v : Bytes) : treeInputs H f d [(p, v)] = [leafIn p v] := by
  cases f <;> first | rfl | simp [treeInputs]
private theorem treeInputs_succ2 (H : Bytes → Bytes) (f d : Nat) (a b : Bytes × Bytes) (t : Map) :
    treeInputs H (f + 1) d (a :: b :: t) =
      nodeIn (rootAt H f (d + 1) ((a :: b :: t).filter fun e => !bit e.1 d))
        (rootAt H f (d + 1) ((a :: b :: t).filter fun e => bit e.1 d)) ::
      (treeInputs H f (d + 1) ((a :: b :: t).filter fun e => !bit e.1 d) ++
        treeInputs H f (d + 1) ((a :: b :: t).filter fun e => bit e.1 d)) := by
  first | rfl | simp [treeInputs]

private theorem rootAt_len (H : Bytes → Bytes) (hH : HashLen H) (f d : Nat) (m : Map) :
    (rootAt H f d m).length = 0 ∨ (rootAt H f d m).length = digestBytes := by
  rcases m with _ | ⟨a, _ | ⟨b, t⟩⟩
  · right; rw [rootAt_nil]; exact hH _
  · obtain ⟨p, v⟩ := a
    right; rw [rootAt_one]; exact hH _
  · cases f with
    | zero => left; rw [rootAt_zero2]; rfl
    | succ f => right; rw [rootAt_succ2]; exact hH _

private theorem find_filter (k : Bytes) (p : Bytes × Bytes → Bool) (hp : ∀ e : Bytes × Bytes, e.1 = k → p e = true) :
    ∀ m : Map, (m.filter p).find? (·.1 == k) = m.find? (·.1 == k) := by
  intro m
  induction m with
  | nil => rfl
  | cons e t ih =>
    by_cases he : e.1 = k
    · simp [List.filter_cons, hp e he, List.find?_cons, he]
    · cases hpe : p e <;> simp [List.filter_cons, hpe, List.find?_cons, he, ih]

private theorem lookup_filter (m : Map) (k : Bytes) (p : Bytes × Bytes → Bool)
    (hp : ∀ e : Bytes × Bytes, e.1 = k → p e = true) : lookup (m.filter p) k = lookup m k := by
  unfold lookup; rw [find_filter k p hp m]

private theorem match_root (H : Bytes → Bytes) (hH : HashLen H) (X : Bytes) (f d : Nat) (m : Map)
    (hh : H X = rootAt H f d m) :
    ∃ Y ∈ treeInputs H f d m, H X = H Y ∧
      ((m = [] ∧ Y = emptyIn) ∨ (∃ p v, m = [(p, v)] ∧ Y = leafIn p v) ∨
       (∃ f' a b t, f = f' + 1 ∧ m = a :: b :: t ∧
         Y = nodeIn (rootAt H f' (d + 1) ((a :: b :: t).filter fun e => !bit e.1 d))
               (rootAt H f' (d + 1) ((a :: b :: t).filter fun e => bit e.1 d)))) := by
  rcases m with _ | ⟨a, _ | ⟨b, t⟩⟩
  · exact ⟨emptyIn, by simp [treeInputs_nil], by rw [hh, rootAt_nil], Or.inl ⟨rfl, rfl⟩⟩
  · obtain ⟨p, v⟩ := a
    exact ⟨leafIn p v, by simp [treeInputs_one], by rw [hh, rootAt_one], Or.inr (Or.inl ⟨p, v, rfl, rfl⟩)⟩
  · cases f with
    | zero =>
      exfalso
      have := hH X
      rw [hh, rootAt_zero2] at this
      simp [digestBytes] at this
    | succ f =>
      refine ⟨nodeIn (rootAt H f (d + 1) ((a :: b :: t).filter fun e => !bit e.1 d))
        (rootAt H f (d + 1) ((a :: b :: t).filter fun e => bit e.1 d)), ?_, ?_, ?_⟩
      · rw [treeInputs_succ2]; simp
      · rw [hh, rootAt_succ2]
      · exact Or.inr (Or.inr ⟨f, a, b, t, rfl, rfl, rfl⟩)

private theorem col_mono {H : Bytes → Bytes} {A A' B B' : List Bytes} (hA : ∀ x ∈ A, x ∈ A')
    (hB : ∀ x ∈ B, x ∈ B') : Collision H A B → Collision H A' B' :=
  fun ⟨x, hx, y, hy, h1, h2⟩ => ⟨x, hA x hx, y, hB y hy, h1, h2⟩

private theorem smt_aux (H : Bytes → Bytes) (hH : HashLen H) (k : Bytes) :
    ∀ (pf : Proof) (d f : Nat) (m : Map) (ks : List Bytes), k ∈ ks → minimal d pf ks = true →
      (∀ e ∈ m, e.1.length = digestBytes) → hashPf H pf = rootAt H f d m →
      ∀ r, lookupPf d pf k = some r →
        r = lookup m k ∨ Collision H (pfInputs H pf) (treeInputs H f d m) := by
  intro pf
  induction pf with
  | «opaque» h => intro d f m ks hk hmin hm hh r hr; simp [lookupPf] at hr
  | empty =>
    intro d f m ks hk hmin hm hh r hr
    simp only [lookupPf, Option.some.injEq] at hr
    subst hr
    obtain ⟨Y, hY, hXY, hs⟩ := match_root H hH emptyIn f d m hh
    have col : emptyIn ≠ Y → Collision H (pfInputs H .empty) (treeInputs H f d m) :=
      fun hne => ⟨emptyIn, by simp [pfInputs], Y, hY, hne, hXY⟩
    rcases hs with ⟨rfl, rfl⟩ | ⟨p, v, rfl, rfl⟩ | ⟨f', a, b, t, rfl, rfl, rfl⟩
    · left; rfl
    · right; exact col (emptyIn_ne_leafIn _ _)
    · right; exact col (emptyIn_ne_nodeIn _ _)
  | leaf p v =>
    intro d f m ks hk hmin hm hh r hr
    have hok : leafOk p v = true := by
      by_cases hc : leafOk p v = true
      · exact hc
      · simp [lookupPf, hc] at hr
    simp only [lookupPf, hok, ↓reduceIte, Option.some.injEq] at hr
    subst hr
    have hp : p.length = digestBytes := by simp [leafOk] at hok; exact hok.1
    have hXin : leafIn p v ∈ pfInputs H (.leaf p v) := by simp [pfInputs, hok]
    have hh' : H (leafIn p v) = rootAt H f d m := by
      simp only [hashPf, hok, ↓reduceIte] at hh; exact hh
    obtain ⟨Y, hY, hXY, hs⟩ := match_root H hH (leafIn p v) f d m hh'
    have col : leafIn p v ≠ Y → Collision H (pfInputs H (.leaf p v)) (treeInputs H f d m) :=
      fun hne => ⟨leafIn p v, hXin, Y, hY, hne, hXY⟩
    rcases hs with ⟨rfl, rfl⟩ | ⟨p', v', rfl, rfl⟩ | ⟨f', a, b, t, rfl, rfl, rfl⟩
    · right; exact col (fun h => emptyIn_ne_leafIn _ _ h.symm)
    · by_cases hne : leafIn p v = leafIn p' v'
      · have hp' : p'.length = digestBytes := hm (p', v') (by simp)
        obtain ⟨rfl, rfl⟩ := leafIn_inj hp hp' hne
        left
        by_cases hpk : (p == k) = true <;> simp [lookup, List.find?_cons, hpk]
      · right; exact col hne
    · right; exact col (leafIn_ne_nodeIn _ _ _ _)
  | node l r ihl ihr =>
    intro d f m ks hk hmin hm hh r' hr
    have hd : d < 512 := by
      by_cases hc : d < 512
      · exact hc
      · simp [lookupPf, hc] at hr
    simp only [lookupPf, hd, ↓reduceIte] at hr
    simp only [minimal, Bool.and_eq_true] at hmin
    obtain ⟨⟨⟨_, _⟩, hml⟩, hmr⟩ := hmin
    have hll := hashPf_len H hH (d + 1) l _ hml
    have hlr := hashPf_len H hH (d + 1) r _ hmr
    have hXin : nodeIn (hashPf H l) (hashPf H r) ∈ pfInputs H (.node l r) := by simp [pfInputs]
    have hh' : H (nodeIn (hashPf H l) (hashPf H r)) = rootAt H f d m := hh
    obtain ⟨Y, hY, hXY, hs⟩ := match_root H hH _ f d m hh'
    have col : nodeIn (hashPf H l) (hashPf H r) ≠ Y → Collision H (pfInputs H (.node l r)) (treeInputs H f d m) :=
      fun hne => ⟨_, hXin, Y, hY, hne, hXY⟩
    rcases hs with ⟨rfl, rfl⟩ | ⟨p', v', rfl, rfl⟩ | ⟨f', a, b, t, rfl, rfl, rfl⟩
    · right; exact col (fun h => emptyIn_ne_nodeIn _ _ h.symm)
    · right; exact col (fun h => leafIn_ne_nodeIn _ _ _ _ h.symm)
    · by_cases hne : nodeIn (hashPf H l) (hashPf H r) =
          nodeIn (rootAt H f' (d + 1) ((a :: b :: t).filter fun e => !bit e.1 d))
            (rootAt H f' (d + 1) ((a :: b :: t).filter fun e => bit e.1 d))
      case neg => exact Or.inr (col hne)
      unfold nodeIn at hne
      have h1 := (List.cons.inj (List.append_cancel_left hne)).2
      have hlen := congrArg List.length h1
      have e1 := rootAt_len H hH f' (d + 1) ((a :: b :: t).filter fun e => !bit e.1 d)
      have e2 := rootAt_len H hH f' (d + 1) ((a :: b :: t).filter fun e => bit e.1 d)
      simp only [List.length_append] at hlen
      obtain ⟨q1, q2⟩ := List.append_inj h1 (by omega)
      by_cases hb : bit k d = true
      · rw [if_pos hb] at hr
        have hk' : k ∈ ks.filter (bit · d) := by simp [hk, hb]
        have hm' : ∀ e ∈ (a :: b :: t).filter (fun e => bit e.1 d), e.1.length = digestBytes :=
          fun e he => hm e ((List.mem_filter.mp he).1)
        rcases ihr (d + 1) f' _ _ hk' hmr hm' q2 r' hr with h | h
        · left
          rw [h]
          exact lookup_filter _ k _ (fun e he => by rw [he]; exact hb)
        · right
          refine col_mono (fun x hx => ?_) (fun x hx => ?_) h
          · simp [pfInputs, hx]
          · rw [treeInputs_succ2]; simp [hx]
      · have hb' : bit k d = false := by simpa using hb
        rw [if_neg hb] at hr
        have hk' : k ∈ ks.filter (!bit · d) := by simp [hk, hb']
        have hm' : ∀ e ∈ (a :: b :: t).filter (fun e => !bit e.1 d), e.1.length = digestBytes :=
          fun e he => hm e ((List.mem_filter.mp he).1)
        rcases ihl (d + 1) f' _ _ hk' hml hm' q1 r' hr with h | h
        · left
          rw [h]
          exact lookup_filter _ k _ (fun e he => by rw [he, hb']; rfl)
        · right
          refine col_mono (fun x hx => ?_) (fun x hx => ?_) h
          · simp [pfInputs, hx]
          · rw [treeInputs_succ2]; simp [hx]

/-- C1: presence and absence both sound. True as stated: a forged leaf must have a 64-byte path
    (`leafOk`), so equal leaf bytes give equal path and value (`leafIn_inj`); leaf, node and empty
    preimages differ in their tag byte; every child hash is 64 bytes, so `nodeIn` splits one way. -/
theorem smt_sound (H : Bytes → Bytes) (hH : HashLen H) (m : Map) (hm : MapOk m) (ks : List Bytes)
    (pf : Proof) (hv : verifyMulti H (root H m) ks pf = true) (k : Bytes) (hk : k ∈ ks) :
    lookupPf 0 pf k = some (lookup m k) ∨ Collision H (pfInputs H pf) (treeInputs H 513 0 m) := by
  simp only [verifyMulti, Bool.and_eq_true, beq_iff_eq] at hv
  obtain ⟨⟨⟨⟨_, _⟩, hh⟩, hs⟩, hmin⟩ := hv
  have hsome := List.all_eq_true.mp hs k hk
  obtain ⟨r, hr⟩ := Option.isSome_iff_exists.mp hsome
  have hm2 : ∀ e ∈ m, e.1.length = digestBytes := fun e he => (hm.2 e he).1
  rcases smt_aux H hH k pf 0 513 m ks hk hmin hm2 hh r hr with h | h
  · left; rw [hr, h]
  · right; exact h

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

/-- Elements of `L` share their first `d` bits. -/
private def Agree (d : Nat) (L : Map) : Prop := ∀ e ∈ L, ∀ e' ∈ L, ∀ j < d, bit e.1 j = bit e'.1 j

private theorem bit_ext (p q : Bytes) (hp : p.length = digestBytes) (hq : q.length = digestBytes)
    (h : ∀ j < 512, bit p j = bit q j) : p = q := by
  have h64 : digestBytes = 64 := rfl
  refine List.ext_getElem (hp.trans hq.symm) fun i hi hi' => ?_
  have hi64 : i < 64 := by omega
  have gp : p.getD i 0 = p[i] := by rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi]; rfl
  have gq : q.getD i 0 = q[i] := by rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi']; rfl
  have key : ∀ r < 8, (p[i]).toNat / 2 ^ (7 - r) % 2 = (q[i]).toNat / 2 ^ (7 - r) % 2 := by
    intro r hr
    have := h (8 * i + r) (by omega)
    rw [bit, bit, show (8 * i + r) / 8 = i by omega, show (8 * i + r) % 8 = r by omega, gp, gq] at this
    have la : (p[i]).toNat / 2 ^ (7 - r) % 2 < 2 := Nat.mod_lt _ (by omega)
    have lb : (q[i]).toNat / 2 ^ (7 - r) % 2 < 2 := Nat.mod_lt _ (by omega)
    generalize (p[i]).toNat / 2 ^ (7 - r) % 2 = a at this la ⊢
    generalize (q[i]).toNat / 2 ^ (7 - r) % 2 = b at this lb ⊢
    obtain rfl | rfl : a = 0 ∨ a = 1 := by omega
    all_goals obtain rfl | rfl : b = 0 ∨ b = 1 := by omega
    all_goals first | rfl | exact absurd this (by decide)
  have k0 := key 0 (by omega)
  have k1 := key 1 (by omega)
  have k2 := key 2 (by omega)
  have k3 := key 3 (by omega)
  have k4 := key 4 (by omega)
  have k5 := key 5 (by omega)
  have k6 := key 6 (by omega)
  have k7 := key 7 (by omega)
  simp only [Nat.reduceSub, Nat.reducePow] at k0 k1 k2 k3 k4 k5 k6 k7
  have lp : (p[i]).toNat < 256 := p[i].toNat_lt
  have lq : (q[i]).toNat < 256 := q[i].toNat_lt
  have : (p[i]).toNat = (q[i]).toNat := by omega
  exact UInt8.toNat_inj.mp this

private theorem agree_small {d : Nat} (hd : 512 ≤ d) {L : Map} (ha : Agree d L)
    (hl : ∀ e ∈ L, e.1.length = digestBytes) (hn : (L.map (·.1)).Nodup) : L.length ≤ 1 := by
  rcases L with _ | ⟨a, _ | ⟨b, t⟩⟩
  · simp
  · simp
  · exfalso
    have hab : a.1 = b.1 := bit_ext _ _ (hl a (by simp)) (hl b (by simp))
      (fun j hj => ha a (by simp) b (by simp) j (by omega))
    simp [List.nodup_cons, hab] at hn

private theorem agree_filter {d : Nat} {L : Map} (ha : Agree d L) (p : Bytes × Bytes → Bool)
    (hp : ∀ e ∈ L, ∀ e' ∈ L, p e = true → p e' = true → bit e.1 d = bit e'.1 d) : Agree (d + 1) (L.filter p) := by
  intro e he e' he' j hj
  obtain ⟨he1, he2⟩ := List.mem_filter.mp he
  obtain ⟨he1', he2'⟩ := List.mem_filter.mp he'
  by_cases hjd : j < d
  · exact ha e he1 e' he1' j hjd
  · have : j = d := by omega
    subst this
    exact hp e he1 e' he1' he2 he2'

private theorem rootAt_len64 (H : Bytes → Bytes) (hH : HashLen H) (f d : Nat) (m : Map)
    (h : f = 0 → m.length ≤ 1) : (rootAt H f d m).length = digestBytes := by
  rcases m with _ | ⟨a, _ | ⟨b, t⟩⟩
  · rw [rootAt_nil]; exact hH _
  · obtain ⟨p, v⟩ := a
    rw [rootAt_one]; exact hH _
  · cases f with
    | zero => simp at h
    | succ f => rw [rootAt_succ2]; exact hH _

private theorem mapOk_filter {m : Map} (hm : MapOk m) (p : Bytes × Bytes → Bool) : MapOk (m.filter p) :=
  ⟨List.Nodup.sublist (List.filter_sublist.map _) hm.1, fun e he => hm.2 e (List.mem_filter.mp he).1⟩

private theorem rootAt_node (H : Bytes → Bytes) (f d : Nat) (L : Map) (h : 2 ≤ L.length) :
    rootAt H (f + 1) d L = H (nodeIn (rootAt H f (d + 1) (L.filter fun e => !bit e.1 d))
      (rootAt H f (d + 1) (L.filter fun e => bit e.1 d))) := by
  rcases L with _ | ⟨a, _ | ⟨b, t⟩⟩
  · simp at h
  · simp at h
  · exact rootAt_succ2 H f d a b t

private theorem agree_mono {d : Nat} {L L' : Map} (h : ∀ e ∈ L', e ∈ L) (ha : Agree d L) : Agree d L' :=
  fun e he e' he' j hj => ha e (h e he) e' (h e' he') j hj

private theorem build_hash (H : Bytes → Bytes) (hH : HashLen H) : ∀ (f d : Nat) (L : Map),
    f + d = 513 → Agree d L → MapOk L → hashPf H (build f d L) = rootAt H f d L := by
  intro f
  induction f with
  | zero =>
    intro d L hf ha hm
    have hs := agree_small (by omega) ha (fun e he => (hm.2 e he).1) hm.1
    rcases L with _ | ⟨⟨p, v⟩, _ | ⟨b, t⟩⟩
    · simp [build, hashPf, rootAt_nil]
    · have hok : leafOk p v = true := by
        have := hm.2 (p, v) (by simp)
        simp [leafOk, this.1, this.2]
      simp [build, hashPf, hok, rootAt_one]
    · simp at hs
  | succ f ih =>
    intro d L hf ha hm
    rcases L with _ | ⟨⟨p, v⟩, _ | ⟨b, t⟩⟩
    · simp [build, hashPf, rootAt_nil]
    · have hok : leafOk p v = true := by
        have := hm.2 (p, v) (by simp)
        simp [leafOk, this.1, this.2]
      simp [build, hashPf, hok, rootAt_one]
    · have hag0 := agree_filter ha (fun e => !bit e.1 d) (fun e _ e' _ h h' => by simp at h h'; rw [h, h'])
      have hag1 := agree_filter ha (fun e => bit e.1 d) (fun e _ e' _ h h' => by
        have h1 : bit e.1 d = true := h
        have h2 : bit e'.1 d = true := h'
        rw [h1, h2])
      rw [rootAt_succ2]
      show H (nodeIn (hashPf H (build f (d + 1) _)) (hashPf H (build f (d + 1) _))) = _
      rw [ih (d + 1) _ (by omega) hag0 (mapOk_filter hm _), ih (d + 1) _ (by omega) hag1 (mapOk_filter hm _)]

/-- The top hash input of `rootAt` and its shape (fuel 0 only for at most one key). -/
private theorem c12_top (H : Bytes → Bytes) (f d : Nat) (m : Map) (h : f = 0 → m.length ≤ 1) :
    ∃ Y ∈ treeInputs H f d m, rootAt H f d m = H Y ∧
      ((m = [] ∧ Y = emptyIn) ∨ (∃ p v, m = [(p, v)] ∧ Y = leafIn p v) ∨
       (∃ f' a b t, f = f' + 1 ∧ m = a :: b :: t ∧
         Y = nodeIn (rootAt H f' (d + 1) ((a :: b :: t).filter fun e => !bit e.1 d))
               (rootAt H f' (d + 1) ((a :: b :: t).filter fun e => bit e.1 d)))) := by
  rcases m with _ | ⟨a, _ | ⟨b, t⟩⟩
  · exact ⟨emptyIn, by simp [treeInputs_nil], rootAt_nil H f d, Or.inl ⟨rfl, rfl⟩⟩
  · obtain ⟨p, v⟩ := a
    exact ⟨leafIn p v, by simp [treeInputs_one], rootAt_one H f d p v, Or.inr (Or.inl ⟨p, v, rfl, rfl⟩)⟩
  · cases f with
    | zero => simp at h
    | succ f =>
      refine ⟨nodeIn (rootAt H f (d + 1) ((a :: b :: t).filter fun e => !bit e.1 d))
        (rootAt H f (d + 1) ((a :: b :: t).filter fun e => bit e.1 d)), ?_, rootAt_succ2 H f d a b t,
        Or.inr (Or.inr ⟨f, a, b, t, rfl, rfl, rfl⟩)⟩
      rw [treeInputs_succ2]; simp

/-- Root binding at fuel `f`: equal roots give the same entries up to order, or a collision. -/
private def C12P (H : Bytes → Bytes) (f : Nat) : Prop :=
  ∀ (d : Nat) (m m' : Map), f + d = 513 → Agree d m → Agree d m' → MapOk m → MapOk m' →
    rootAt H f d m = rootAt H f d m' → m.Perm m' ∨ Collision H (treeInputs H f d m) (treeInputs H f d m')

private theorem c12_step (H : Bytes → Bytes) (hH : HashLen H) (f : Nat)
    (ih : ∀ f', f = f' + 1 → C12P H f') : C12P H f := by
  intro d m m' hf ha ha' hm hm' hr
  obtain ⟨Y, hY, hrY, hs⟩ := c12_top H f d m
    (fun _ => agree_small (by omega) ha (fun e he => (hm.2 e he).1) hm.1)
  obtain ⟨Y', hY', hrY', hs'⟩ := c12_top H f d m'
    (fun _ => agree_small (by omega) ha' (fun e he => (hm'.2 e he).1) hm'.1)
  by_cases hne : Y = Y'
  case neg => exact Or.inr ⟨Y, hY, Y', hY', hne, by rw [← hrY, ← hrY', hr]⟩
  subst hne
  rcases hs with ⟨rfl, rfl⟩ | ⟨p, v, rfl, rfl⟩ | ⟨f1, a, b, t, rfl, rfl, rfl⟩ <;>
    rcases hs' with ⟨rfl, he⟩ | ⟨p', v', rfl, he⟩ | ⟨f2, a', b', t', hf2, rfl, he⟩
  · exact Or.inl (List.Perm.refl _)
  · exact absurd he (emptyIn_ne_leafIn _ _)
  · exact absurd he (emptyIn_ne_nodeIn _ _)
  · exact absurd he.symm (emptyIn_ne_leafIn _ _)
  · obtain ⟨rfl, rfl⟩ := leafIn_inj (hm.2 (p, v) (by simp)).1 (hm'.2 (p', v') (by simp)).1 he
    exact Or.inl (List.Perm.refl _)
  · exact absurd he (leafIn_ne_nodeIn _ _ _ _)
  · exact absurd he.symm (emptyIn_ne_nodeIn _ _)
  · exact absurd he.symm (leafIn_ne_nodeIn _ _ _ _)
  · have hf12 : f2 = f1 := by omega
    subst f2
    have p0 : ∀ (L : Map), ∀ e ∈ L, ∀ e' ∈ L, (fun e : Bytes × Bytes => !bit e.1 d) e = true →
        (fun e : Bytes × Bytes => !bit e.1 d) e' = true → bit e.1 d = bit e'.1 d :=
      fun _ e _ e' _ h h' => by simp at h h'; rw [h, h']
    have p1 : ∀ (L : Map), ∀ e ∈ L, ∀ e' ∈ L, (fun e : Bytes × Bytes => bit e.1 d) e = true →
        (fun e : Bytes × Bytes => bit e.1 d) e' = true → bit e.1 d = bit e'.1 d := by
      intro _ e _ e' _ h h'
      have h1 : bit e.1 d = true := h
      have h2 : bit e'.1 d = true := h'
      rw [h1, h2]
    have hl : ∀ (L : Map) (q : Bytes × Bytes → Bool), Agree d L → MapOk L →
        (∀ e ∈ L, ∀ e' ∈ L, q e = true → q e' = true → bit e.1 d = bit e'.1 d) →
        (rootAt H f1 (d + 1) (L.filter q)).length = digestBytes := fun L q hL hmL hq =>
      rootAt_len64 H hH f1 (d + 1) _ (fun _ => agree_small (by omega) (agree_filter hL q hq)
        (fun e he => ((mapOk_filter hmL q).2 e he).1) (mapOk_filter hmL q).1)
    unfold nodeIn at he
    have h1 := (List.cons.inj (List.append_cancel_left he)).2
    obtain ⟨q1, q2⟩ := List.append_inj h1 ((hl _ _ ha hm (p0 _)).trans (hl _ _ ha' hm' (p0 _)).symm)
    have r0 := ih f1 rfl (d + 1) _ _ (by omega) (agree_filter ha _ (p0 _)) (agree_filter ha' _ (p0 _))
      (mapOk_filter hm _) (mapOk_filter hm' _) q1
    have r1 := ih f1 rfl (d + 1) _ _ (by omega) (agree_filter ha _ (p1 _)) (agree_filter ha' _ (p1 _))
      (mapOk_filter hm _) (mapOk_filter hm' _) q2
    rcases r0 with e0 | c0
    · rcases r1 with e1 | c1
      · left
        exact ((List.filter_append_perm (fun e => bit e.1 d) _).symm.trans (e1.append e0)).trans
          (List.filter_append_perm (fun e => bit e.1 d) _)
      · right
        refine col_mono (fun x hx => ?_) (fun x hx => ?_) c1
        · rw [treeInputs_succ2]; simp [hx]
        · rw [treeInputs_succ2]; simp [hx]
    · right
      refine col_mono (fun x hx => ?_) (fun x hx => ?_) c0
      · rw [treeInputs_succ2]; simp [hx]
      · rw [treeInputs_succ2]; simp [hx]

/-- Root binding (c11 plan step 2): two well-formed maps with equal roots hold the same entries up to
    order, or their tree inputs contain an explicit collision. -/
private theorem c12_root_bind (H : Bytes → Bytes) (hH : HashLen H) (m m' : Map) (hm : MapOk m)
    (hm' : MapOk m') (hr : root H m = root H m') :
    m.Perm m' ∨ Collision H (treeInputs H 513 0 m) (treeInputs H 513 0 m') := by
  have hall : ∀ f, C12P H f := by
    intro f
    induction f with
    | zero => exact c12_step H hH 0 (fun _ h => absurd h (by omega))
    | succ f ih =>
      refine c12_step H hH (f + 1) (fun f' h => ?_)
      have hf : f' = f := by omega
      subst f'
      exact ih
  have a0 : ∀ L : Map, Agree 0 L := fun _ _ _ _ _ j hj => absurd hj (Nat.not_lt_zero j)
  exact hall 513 0 m m' rfl (a0 m) (a0 m') hm hm' hr

/-- Upsert result as a list: the writes, then the old rows whose key is not overwritten. -/
private def upM (m ws : Map) : Map := ws ++ m.filter fun e => !ws.any (·.1 == e.1)

private theorem upM_nil (m : Map) : upM m [] = m := by simp [upM]

private theorem upsert_perm : ∀ (ws m : Map), (ws.map (·.1)).Nodup → (upsert m ws).Perm (upM m ws) := by
  intro ws
  induction ws with
  | nil => intro m _; show m.Perm (upM m []); rw [upM_nil]
  | cons w ws ih =>
    intro m hn
    obtain ⟨k, v⟩ := w
    rw [List.map_cons, List.nodup_cons] at hn
    have e1 : upsert m ((k, v) :: ws) = upsert ((k, v) :: m.filter (·.1 != k)) ws := rfl
    rw [e1]
    refine (ih _ hn.2).trans ?_
    have hk : ws.any (·.1 == k) = false := by
      simp only [List.any_eq_false, beq_iff_eq]
      intro x hx hxk
      exact hn.1 (List.mem_map.mpr ⟨x, hx, hxk⟩)
    have e2 : upM ((k, v) :: m.filter (·.1 != k)) ws =
        ws ++ (k, v) :: (m.filter fun e => !((k, v) :: ws).any (·.1 == e.1)) := by
      have hf : (m.filter (·.1 != k)).filter (fun e => !ws.any (·.1 == e.1)) =
          m.filter fun e => !((k, v) :: ws).any (·.1 == e.1) := by
        rw [List.filter_filter]
        apply List.filter_congr
        intro e _
        by_cases h1 : e.1 = k
        · simp [h1]
        · have h2 : k ≠ e.1 := fun h => h1 h.symm
          have h3 : (k == e.1) = false := beq_eq_false_iff_ne.mpr h2
          have h4 : (e.1 != k) = true := bne_iff_ne.mpr h1
          simp [h3, h4]
      unfold upM
      rw [List.filter_cons_of_pos (by simp [hk]), hf]
    rw [e2]
    exact List.perm_middle

private theorem upM_filter (m ws : Map) (p : Bytes × Bytes → Bool) (hp : ∀ e e' : Bytes × Bytes, e.1 = e'.1 → p e = p e') :
    (upM m ws).filter p = upM (m.filter p) (ws.filter p) := by
  unfold upM
  rw [List.filter_append, List.filter_filter, List.filter_filter]
  congr 1
  apply List.filter_congr
  intro e he
  have key : ws.any (·.1 == e.1) = (ws.filter p).any (·.1 == e.1) ∨ p e = false := by
    by_cases hpe : p e = true
    · left
      by_cases h : ws.any (·.1 == e.1) = true
      · obtain ⟨w, hw, hwe⟩ := List.any_eq_true.mp h
        have hwe' : w.1 = e.1 := by simpa using hwe
        have : (ws.filter p).any (·.1 == e.1) = true :=
          List.any_eq_true.mpr ⟨w, List.mem_filter.mpr ⟨hw, by rw [hp w e hwe']; exact hpe⟩, hwe⟩
        rw [h, this]
      · have h' : ws.any (·.1 == e.1) = false := Bool.eq_false_iff.mpr h
        have : (ws.filter p).any (·.1 == e.1) = false := by
          simp only [List.any_eq_false] at h' ⊢
          intro x hx; exact h' x (List.mem_filter.mp hx).1
        rw [h', this]
    · right; simpa using hpe
  rcases key with h | h
  · simp only [h]; exact Bool.and_comm _ _
  · simp [h]

private theorem upM_two {m : Map} (hm : MapOk m) (h2 : 2 ≤ m.length) (ws : Map) : 2 ≤ (upM m ws).length := by
  have hmem : ∀ e ∈ m, ∃ e' ∈ upM m ws, e'.1 = e.1 := by
    intro e he
    by_cases h : ws.any (·.1 == e.1) = true
    · obtain ⟨w, hw, hwe⟩ := List.any_eq_true.mp h
      exact ⟨w, by simp [upM, hw], by simpa using hwe⟩
    · exact ⟨e, by simp [upM, he, h], rfl⟩
  rcases m with _ | ⟨a, _ | ⟨b, t⟩⟩
  · simp at h2
  · simp at h2
  · obtain ⟨x, hx, hxa⟩ := hmem a (by simp)
    obtain ⟨y, hy, hyb⟩ := hmem b (by simp)
    have hab : a.1 ≠ b.1 := by
      have := hm.1
      simp only [List.map_cons, List.nodup_cons, List.mem_cons, List.mem_map, not_or] at this
      intro h; exact this.1.1 h
    rcases hL : upM (a :: b :: t) ws with _ | ⟨z, _ | ⟨z', u⟩⟩
    · rw [hL] at hx; simp at hx
    · rw [hL] at hx hy
      simp at hx hy
      subst hx; subst hy
      exact absurd (hxa.symm.trans hyb) hab
    · simp

private theorem upsertPf_empty (f d : Nat) (ws : Map) (h : ws ≠ []) : upsertPf f d .empty ws = build f d ws := by
  cases ws with
  | nil => exact absurd rfl h
  | cons w ws => first | rfl | simp [upsertPf]

private theorem upsertPf_leaf (f d : Nat) (p v : Bytes) (ws : Map) (h : ws ≠ []) :
    upsertPf f d (.leaf p v) ws = build f d (if ws.any (·.1 == p) then ws else (p, v) :: ws) := by
  cases ws with
  | nil => exact absurd rfl h
  | cons w ws => first | rfl | simp [upsertPf]

private theorem upsertPf_node (f d : Nat) (l r : Proof) (ws : Map) (h : ws ≠ []) :
    upsertPf (f + 1) d (.node l r) ws = .node (upsertPf f (d + 1) l (ws.filter fun e => !bit e.1 d))
      (upsertPf f (d + 1) r (ws.filter fun e => bit e.1 d)) := by
  cases ws with
  | nil => exact absurd rfl h
  | cons w ws => first | rfl | simp [upsertPf]

private theorem upsertPf_nil (f d : Nat) (pf : Proof) : upsertPf f d pf [] = pf := by
  first | rfl | simp [upsertPf]

private theorem mu_aux (H : Bytes → Bytes) (hH : HashLen H) : ∀ (pf : Proof) (f d : Nat) (m ws : Map) (ks : List Bytes),
    f + d = 513 → Agree d (m ++ ws) → MapOk m → MapOk ws → (∀ e ∈ ws, e.1 ∈ ks) → minimal d pf ks = true →
    (∀ e ∈ ws, (lookupPf d pf e.1).isSome = true) → hashPf H pf = rootAt H f d m →
    hashPf H (upsertPf f d pf ws) = rootAt H f d (upM m ws) ∨ Collision H (pfInputs H pf) (treeInputs H f d m) := by
  intro pf
  induction pf with
  | «opaque» h =>
    intro f d m ws ks hf ha hm hw hs hmin hl hh
    by_cases h0 : ws = []
    · subst h0; left; rw [upsertPf_nil, upM_nil]; exact hh
    · obtain ⟨w, hwm⟩ := List.exists_mem_of_ne_nil ws h0
      have := hl w hwm
      simp [lookupPf] at this
  | empty =>
    intro f d m ws ks hf ha hm hw hs hmin hl hh
    by_cases h0 : ws = []
    · subst h0; left; rw [upsertPf_nil, upM_nil]; exact hh
    · rw [upsertPf_empty f d ws h0]
      obtain ⟨Y, hY, hXY, hsh⟩ := match_root H hH emptyIn f d m hh
      have col : emptyIn ≠ Y → Collision H (pfInputs H .empty) (treeInputs H f d m) :=
        fun hne => ⟨emptyIn, by simp [pfInputs], Y, hY, hne, hXY⟩
      rcases hsh with ⟨rfl, rfl⟩ | ⟨p, v, rfl, rfl⟩ | ⟨f', a, b, t, rfl, rfl, rfl⟩
      · left
        have e : upM [] ws = ws := by simp [upM]
        rw [e]
        exact build_hash H hH f d ws hf (by simpa using ha) hw
      · right; exact col (emptyIn_ne_leafIn _ _)
      · right; exact col (emptyIn_ne_nodeIn _ _)
  | leaf p v =>
    intro f d m ws ks hf ha hm hw hs hmin hl hh
    by_cases h0 : ws = []
    · subst h0; left; rw [upsertPf_nil, upM_nil]; exact hh
    · obtain ⟨w, hwm⟩ := List.exists_mem_of_ne_nil ws h0
      have hok : leafOk p v = true := by
        by_cases hc : leafOk p v = true
        · exact hc
        · have := hl w hwm
          simp [lookupPf, hc] at this
      have hp : p.length = digestBytes := by simp [leafOk] at hok; exact hok.1
      have hh' : H (leafIn p v) = rootAt H f d m := by
        simp only [hashPf, hok, ↓reduceIte] at hh; exact hh
      obtain ⟨Y, hY, hXY, hsh⟩ := match_root H hH (leafIn p v) f d m hh'
      have col : leafIn p v ≠ Y → Collision H (pfInputs H (.leaf p v)) (treeInputs H f d m) :=
        fun hne => ⟨leafIn p v, by simp [pfInputs, hok], Y, hY, hne, hXY⟩
      rcases hsh with ⟨rfl, rfl⟩ | ⟨p', v', rfl, rfl⟩ | ⟨f', a, b, t, rfl, rfl, rfl⟩
      · right; exact col (fun h => emptyIn_ne_leafIn _ _ h.symm)
      · by_cases hne : leafIn p v = leafIn p' v'
        · have hp' : p'.length = digestBytes := (hm.2 (p', v') (by simp)).1
          obtain ⟨rfl, rfl⟩ := leafIn_inj hp hp' hne
          left
          rw [upsertPf_leaf f d p v ws h0]
          have hcase : (if ws.any (·.1 == p) then ws else (p, v) :: ws).Perm (upM [(p, v)] ws) := by
            by_cases hany : ws.any (·.1 == p) = true
            · simp [upM, hany]
            · have h' : ws.any (·.1 == p) = false := Bool.eq_false_iff.mpr hany
              simp [upM, h']
              exact (List.perm_append_singleton _ _).symm
          have hL : MapOk (if ws.any (·.1 == p) then ws else (p, v) :: ws) := by
            by_cases hany : ws.any (·.1 == p) = true
            · simpa [hany] using hw
            · have h' : ws.any (·.1 == p) = false := Bool.eq_false_iff.mpr hany
              rw [if_neg hany]
              refine ⟨?_, ?_⟩
              · rw [List.map_cons, List.nodup_cons]
                refine ⟨?_, hw.1⟩
                intro hmem
                obtain ⟨x, hx, hxp⟩ := List.mem_map.mp hmem
                have : ws.any (·.1 == p) = true := List.any_eq_true.mpr ⟨x, hx, by simpa using hxp⟩
                rw [h'] at this; exact Bool.false_ne_true this
              · intro e he
                rcases List.mem_cons.mp he with rfl | he
                · exact hm.2 _ (by simp)
                · exact hw.2 e he
          have hAg : Agree d (if ws.any (·.1 == p) then ws else (p, v) :: ws) := by
            refine agree_mono (L := [(p, v)] ++ ws) (fun e he => ?_) ha
            by_cases hany : ws.any (·.1 == p) = true
            · rw [if_pos hany] at he; simp [he]
            · rw [if_neg hany] at he; simpa using he
          rw [build_hash H hH f d _ hf hAg hL]
          exact rootAt_perm' H f d _ _ hcase
        · right; exact col hne
      · right; exact col (leafIn_ne_nodeIn _ _ _ _)
  | node l r ihl ihr =>
    intro f d m ws ks hf ha hm hw hs hmin hl hh
    by_cases h0 : ws = []
    · subst h0; left; rw [upsertPf_nil, upM_nil]; exact hh
    · obtain ⟨w, hwm⟩ := List.exists_mem_of_ne_nil ws h0
      have hd : d < 512 := by
        by_cases hc : d < 512
        · exact hc
        · have := hl w hwm
          simp [lookupPf, hc] at this
      obtain ⟨f', rfl⟩ : ∃ f', f = f' + 1 := ⟨f - 1, by omega⟩
      rw [upsertPf_node f' d l r ws h0]
      simp only [minimal, Bool.and_eq_true] at hmin
      obtain ⟨⟨⟨_, _⟩, hml⟩, hmr⟩ := hmin
      have hll := hashPf_len H hH (d + 1) l _ hml
      have hlr := hashPf_len H hH (d + 1) r _ hmr
      have hXin : nodeIn (hashPf H l) (hashPf H r) ∈ pfInputs H (.node l r) := by simp [pfInputs]
      have hh' : H (nodeIn (hashPf H l) (hashPf H r)) = rootAt H (f' + 1) d m := hh
      obtain ⟨Y, hY, hXY, hsh⟩ := match_root H hH _ (f' + 1) d m hh'
      have col : nodeIn (hashPf H l) (hashPf H r) ≠ Y →
          Collision H (pfInputs H (.node l r)) (treeInputs H (f' + 1) d m) :=
        fun hne => ⟨_, hXin, Y, hY, hne, hXY⟩
      rcases hsh with ⟨rfl, rfl⟩ | ⟨p', v', rfl, rfl⟩ | ⟨f'', a, b, t, hf', rfl, rfl⟩
      · right; exact col (fun h => emptyIn_ne_nodeIn _ _ h.symm)
      · right; exact col (fun h => leafIn_ne_nodeIn _ _ _ _ h.symm)
      · have hf'' : f'' = f' := by omega
        subst hf''
        by_cases hne : nodeIn (hashPf H l) (hashPf H r) =
            nodeIn (rootAt H f'' (d + 1) ((a :: b :: t).filter fun e => !bit e.1 d))
              (rootAt H f'' (d + 1) ((a :: b :: t).filter fun e => bit e.1 d))
        case neg => exact Or.inr (col hne)
        unfold nodeIn at hne
        have h1 := (List.cons.inj (List.append_cancel_left hne)).2
        have hlen := congrArg List.length h1
        have e1 := rootAt_len H hH f'' (d + 1) ((a :: b :: t).filter fun e => !bit e.1 d)
        have e2 := rootAt_len H hH f'' (d + 1) ((a :: b :: t).filter fun e => bit e.1 d)
        simp only [List.length_append] at hlen
        obtain ⟨q1, q2⟩ := List.append_inj h1 (by omega)
        have hag0 := agree_filter ha (fun e => !bit e.1 d) (fun e _ e' _ h h' => by simp at h h'; rw [h, h'])
        have hag1 := agree_filter ha (fun e => bit e.1 d) (fun e _ e' _ h h' => by
          have h1 : bit e.1 d = true := h
          have h2 : bit e'.1 d = true := h'
          rw [h1, h2])
        have hsub : ∀ (p : Bytes × Bytes → Bool) (x : Bytes × Bytes), x ∈ (a :: b :: t).filter p ++ ws.filter p →
            x ∈ ((a :: b :: t) ++ ws).filter p := by
          intro p x hx; rw [List.filter_append]; exact hx
        have hagl : Agree (d + 1) ((a :: b :: t).filter (fun e => !bit e.1 d) ++ ws.filter (fun e => !bit e.1 d)) := by
          have := hag0; rw [List.filter_append] at this; exact this
        have hagr : Agree (d + 1) ((a :: b :: t).filter (fun e => bit e.1 d) ++ ws.filter (fun e => bit e.1 d)) := by
          have := hag1; rw [List.filter_append] at this; exact this
        have hsl : ∀ e ∈ ws.filter (fun e => !bit e.1 d), e.1 ∈ ks.filter (!bit · d) := by
          intro e he
          obtain ⟨he1, he2⟩ := List.mem_filter.mp he
          exact List.mem_filter.mpr ⟨hs e he1, he2⟩
        have hsr : ∀ e ∈ ws.filter (fun e => bit e.1 d), e.1 ∈ ks.filter (bit · d) := by
          intro e he
          obtain ⟨he1, he2⟩ := List.mem_filter.mp he
          exact List.mem_filter.mpr ⟨hs e he1, he2⟩
        have hll' : ∀ e ∈ ws.filter (fun e => !bit e.1 d), (lookupPf (d + 1) l e.1).isSome = true := by
          intro e he
          obtain ⟨he1, he2⟩ := List.mem_filter.mp he
          have := hl e he1
          have hb : bit e.1 d = false := by simpa using he2
          simpa [lookupPf, hd, hb] using this
        have hlr' : ∀ e ∈ ws.filter (fun e => bit e.1 d), (lookupPf (d + 1) r e.1).isSome = true := by
          intro e he
          obtain ⟨he1, he2⟩ := List.mem_filter.mp he
          have := hl e he1
          simpa [lookupPf, hd, he2] using this
        have hfin : ∀ p : Bytes × Bytes → Bool, (∀ e e' : Bytes × Bytes, e.1 = e'.1 → p e = p e') →
            (upM (a :: b :: t) ws).filter p = upM ((a :: b :: t).filter p) (ws.filter p) :=
          fun p hp => upM_filter _ _ p hp
        have hu0 := hfin (fun e => !bit e.1 d) (fun e e' h => by simp [h])
        have hu1 := hfin (fun e => bit e.1 d) (fun e e' h => by simp [h])
        have h2 := upM_two hm (by simp) ws
        rw [rootAt_node H f'' d _ h2, hu0, hu1]
        rcases ihl f'' (d + 1) _ _ _ (by omega) hagl (mapOk_filter hm _) (mapOk_filter hw _) hsl hml hll' q1 with c1 | c1
        · rcases ihr f'' (d + 1) _ _ _ (by omega) hagr (mapOk_filter hm _) (mapOk_filter hw _) hsr hmr hlr' q2 with c2 | c2
          · left
            show H (nodeIn (hashPf H _) (hashPf H _)) = _
            rw [c1, c2]
          · right
            refine col_mono (fun x hx => ?_) (fun x hx => ?_) c2
            · simp [pfInputs, hx]
            · rw [treeInputs_succ2]; simp [hx]
        · right
          refine col_mono (fun x hx => ?_) (fun x hx => ?_) c1
          · simp [pfInputs, hx]
          · rw [treeInputs_succ2]; simp [hx]

theorem multi_update_sound (H : Bytes → Bytes) (hH : HashLen H) (m ws : Map) (hm : MapOk m) (hw : MapOk ws)
    (ks : List Bytes) (pf : Proof) (hv : verifyMulti H (root H m) ks pf = true) (hs : ∀ e ∈ ws, e.1 ∈ ks) :
    hashPf H (upsertPf 513 0 pf ws) = root H (upsert m ws) ∨
      Collision H (pfInputs H pf) (treeInputs H 513 0 m) := by
  simp only [verifyMulti, Bool.and_eq_true, beq_iff_eq] at hv
  obtain ⟨⟨⟨⟨_, _⟩, hh⟩, hsm⟩, hmin⟩ := hv
  have hl : ∀ e ∈ ws, (lookupPf 0 pf e.1).isSome = true := fun e he => List.all_eq_true.mp hsm e.1 (hs e he)
  rcases mu_aux H hH pf 513 0 m ws ks rfl (fun _ _ _ _ j hj => absurd hj (Nat.not_lt_zero _)) hm hw hs hmin hl hh with h | h
  · left
    rw [h]
    exact rootAt_perm' H _ _ _ _ (upsert_perm ws m hw.1).symm
  · right; exact h

/-- The honest multiproof: `m`'s canonical tree cut to the paths `ks`. -/
def prune (H : Bytes → Bytes) : Nat → Nat → Map → List Bytes → Proof
  | f, d, m, [] => .opaque (rootAt H f d m)
  | _, _, [], _ :: _ => .empty
  | _, _, [(p, v)], _ :: _ => .leaf p v
  | 0, _, _, _ => .opaque []
  | f + 1, d, m, ks => .node (prune H f (d + 1) (m.filter fun e => !bit e.1 d) (ks.filter (!bit · d)))
      (prune H f (d + 1) (m.filter fun e => bit e.1 d) (ks.filter (bit · d)))

private theorem prune_base (H : Bytes → Bytes) (hH : HashLen H) (f d : Nat) (m : Map) (ks : List Bytes)
    (hm : MapOk m) (hsm : f = 0 → m.length ≤ 1) (hb : ks = [] ∨ m.length ≤ 1) :
    hashPf H (prune H f d m ks) = rootAt H f d m ∧
      (∀ k ∈ ks, (lookupPf d (prune H f d m ks) k).isSome = true) ∧
      minimal d (prune H f d m ks) ks = true := by
  rcases ks with _ | ⟨k0, ks'⟩
  · simp [prune, hashPf, lookupPf, minimal, rootAt_len64 H hH f d m hsm]
  · have hl : m.length ≤ 1 := hb.resolve_left (by simp)
    rcases m with _ | ⟨⟨p, v⟩, _ | ⟨b, t⟩⟩
    · simp [prune, hashPf, lookupPf, minimal, rootAt_nil]
    · have hok : leafOk p v = true := by
        have := hm.2 (p, v) (by simp)
        simp [leafOk, this.1, this.2]
      simp [prune, hashPf, lookupPf, minimal, hok, rootAt_one]
    · simp at hl

private theorem prune_node (H : Bytes → Bytes) (f d : Nat) (a b : Bytes × Bytes) (t : Map) (k : Bytes) (ks : List Bytes) :
    prune H (f + 1) d (a :: b :: t) (k :: ks) =
      .node (prune H f (d + 1) ((a :: b :: t).filter fun e => !bit e.1 d) ((k :: ks).filter (!bit · d)))
        (prune H f (d + 1) ((a :: b :: t).filter fun e => bit e.1 d) ((k :: ks).filter (bit · d))) := by
  first | rfl | simp [prune]

private theorem prune_aux (H : Bytes → Bytes) (hH : HashLen H) : ∀ (f d : Nat) (m : Map) (ks : List Bytes),
    f + d = 513 → Agree d m → MapOk m → (∀ k ∈ ks, k.length = digestBytes) →
    hashPf H (prune H f d m ks) = rootAt H f d m ∧
      (∀ k ∈ ks, (lookupPf d (prune H f d m ks) k).isSome = true) ∧
      minimal d (prune H f d m ks) ks = true := by
  intro f
  induction f with
  | zero =>
    intro d m ks hf ha hm hk
    exact prune_base H hH 0 d m ks hm (fun _ => agree_small (by omega) ha (fun e he => (hm.2 e he).1) hm.1)
      (Or.inr (agree_small (by omega) ha (fun e he => (hm.2 e he).1) hm.1))
  | succ f ih =>
    intro d m ks hf ha hm hk
    rcases ks with _ | ⟨k0, ks'⟩
    · exact prune_base H hH _ d m _ hm (fun h => by omega) (Or.inl rfl)
    rcases m with _ | ⟨a, _ | ⟨b, t⟩⟩
    · exact prune_base H hH _ d _ _ hm (fun h => by omega) (Or.inr (by simp))
    · exact prune_base H hH _ d _ _ hm (fun h => by omega) (Or.inr (by simp))
    have hd : d < 512 := by
      by_cases hc : d < 512
      · exact hc
      · have := agree_small (by omega) ha (fun e he => (hm.2 e he).1) hm.1
        simp at this
    have hag0 := agree_filter ha (fun e => !bit e.1 d) (fun e _ e' _ h h' => by simp at h h'; rw [h, h'])
    have hag1 := agree_filter ha (fun e => bit e.1 d) (fun e _ e' _ h h' => by
      have h1 : bit e.1 d = true := h
      have h2 : bit e'.1 d = true := h'
      rw [h1, h2])
    obtain ⟨l1, l2, l3⟩ := ih (d + 1) _ ((k0 :: ks').filter (!bit · d)) (by omega) hag0
      (mapOk_filter hm _) (fun k hk' => hk k (List.mem_filter.mp hk').1)
    obtain ⟨r1, r2, r3⟩ := ih (d + 1) _ ((k0 :: ks').filter (bit · d)) (by omega) hag1
      (mapOk_filter hm _) (fun k hk' => hk k (List.mem_filter.mp hk').1)
    rw [prune_node]
    refine ⟨?_, ?_, ?_⟩
    · rw [rootAt_succ2]; simp only [hashPf, l1, r1]
    · intro k hk'
      simp only [lookupPf, hd, ↓reduceIte]
      by_cases hb : bit k d = true
      · rw [if_pos hb]; exact r2 k (by simp [hk', hb])
      · rw [if_neg hb]; exact l2 k (by simp [hk', show bit k d = false by simpa using hb])
    · simp [minimal, hd, l3, r3]

theorem prune_complete (H : Bytes → Bytes) (hH : HashLen H) (m : Map) (hm : MapOk m) (ks : List Bytes)
    (hk : ∀ k ∈ ks, k.length = digestBytes) : verifyMulti H (root H m) ks (prune H 513 0 m ks) = true := by
  obtain ⟨ha, hl, hmin⟩ := prune_aux H hH 513 0 m ks rfl
    (fun _ _ _ _ j hj => absurd hj (Nat.not_lt_zero _)) hm hk
  unfold verifyMulti
  simp only [Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨⟨⟨rootAt_len64 H hH 513 0 m (fun h => by omega), List.all_eq_true.mpr fun k hk' => by simpa using hk k hk'⟩, ha⟩,
    List.all_eq_true.mpr hl⟩, hmin⟩


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

private theorem tr_succ (H : Bytes → Bytes) (d : Bytes) (f : Nat) (T : List Bytes) (h : 1 < T.length) :
    treeRoot H d (f + 1) T = treeRoot H d f (pairUp H d T) := by
  rcases T with _ | ⟨x, _ | ⟨y, t⟩⟩
  · simp at h
  · simp at h
  · simp [treeRoot]

/-- Split-point tree root over a leaf list of length at most `2^a` (fuel `a`). -/
private def Mt (H : Bytes → Bytes) (d : Bytes) : Nat → List Bytes → Bytes
  | 0, L => L.headD []
  | a + 1, L => if L.length ≤ 2 ^ a then Mt H d a L
      else nodeHash H d (Mt H d a (L.take (2 ^ a))) (Mt H d a (L.drop (2 ^ a)))

private theorem Mt_succ (H : Bytes → Bytes) (d : Bytes) (a : Nat) (L : List Bytes) : Mt H d (a + 1) L =
    if L.length ≤ 2 ^ a then Mt H d a L
      else nodeHash H d (Mt H d a (L.take (2 ^ a))) (Mt H d a (L.drop (2 ^ a))) := by rw [Mt]

private theorem pu_drop_even (H : Bytes → Bytes) (d : Bytes) : ∀ (lv : List Bytes) (j : Nat), j % 2 = 0 →
    pairUp H d (lv.drop j) = (pairUp H d lv).drop (j / 2)
  | [], j, _ => by simp [pairUp]
  | [a], j, h => by
    rcases j with _ | j
    · simp [pairUp]
    · have : 1 ≤ (j + 1) / 2 := by omega
      simp [pairUp, List.drop_of_length_le, this]
  | a :: b :: rest, j, h => by
    rcases j with _ | _ | j
    · simp [pairUp]
    · omega
    · have := pu_drop_even H d rest j (by omega)
      have e : (j + 1 + 1) / 2 = j / 2 + 1 := by omega
      simp [pairUp, this, e]

private theorem Mt_one (H : Bytes → Bytes) (d : Bytes) : ∀ (a : Nat) (x : Bytes), Mt H d a [x] = x
  | 0, x => rfl
  | a + 1, x => by
    have h1 : 1 ≤ 2 ^ a := Nat.one_le_two_pow
    rw [Mt_succ H d a [x], if_pos (by simpa using h1)]
    exact Mt_one H d a x

private theorem Mt_indep (H : Bytes → Bytes) (d : Bytes) : ∀ (b a : Nat) (L : List Bytes), L.length ≤ 2 ^ a → a ≤ b →
    Mt H d a L = Mt H d b L
  | 0, a, L, hl, hab => by
    have : a = 0 := by omega
    subst this; rfl
  | b + 1, a, L, hl, hab => by
    by_cases h : a = b + 1
    · subst h; rfl
    · have hab' : a ≤ b := by omega
      have hl' : L.length ≤ 2 ^ b := Nat.le_trans hl (Nat.pow_le_pow_right (by omega) hab')
      rw [Mt_succ H d b L, if_pos hl']
      exact Mt_indep H d b a L hl hab'

private theorem Mt_pair (H : Bytes → Bytes) (d : Bytes) : ∀ (a : Nat) (L : List Bytes), L ≠ [] → L.length ≤ 2 ^ (a + 1) →
    Mt H d a (pairUp H d L) = Mt H d (a + 1) L
  | 0, L, hne, hl => by
    rcases L with _ | ⟨x, _ | ⟨y, t⟩⟩
    · exact absurd rfl hne
    · simp [Mt, pairUp]
    · rcases t with _ | ⟨z, t'⟩
      · simp [Mt, pairUp, nodeHash]
      · simp at hl
  | a + 1, L, hne, hl => by
    have pp : ∀ k, 0 < 2 ^ k := fun k => Nat.two_pow_pos k
    have p2 : 2 ^ (a + 1) = 2 * 2 ^ a := by rw [Nat.pow_succ]; omega
    have p3 : 2 ^ (a + 1 + 1) = 2 * 2 ^ (a + 1) := by rw [Nat.pow_succ]; omega
    have hlen := pu_len H d L
    have pa := pp a
    have pa1 := pp (a + 1)
    by_cases h : L.length ≤ 2 ^ (a + 1)
    · rw [Mt_succ H d a (pairUp H d L), if_pos (by omega), Mt_succ H d (a + 1) L, if_pos h]
      exact Mt_pair H d a L hne h
    · rw [Mt_succ H d a (pairUp H d L), if_neg (by omega), Mt_succ H d (a + 1) L, if_neg h]
      have e1 : (pairUp H d L).take (2 ^ a) = pairUp H d (L.take (2 ^ (a + 1))) := by
        rw [pu_take_even H d L (2 ^ (a + 1)) (by omega), show 2 ^ (a + 1) / 2 = 2 ^ a by omega]
      have e2 : (pairUp H d L).drop (2 ^ a) = pairUp H d (L.drop (2 ^ (a + 1))) := by
        rw [pu_drop_even H d L (2 ^ (a + 1)) (by omega), show 2 ^ (a + 1) / 2 = 2 ^ a by omega]
      have hk : (L.take (2 ^ (a + 1))).length = 2 ^ (a + 1) := by simp; omega
      have hd : (L.drop (2 ^ (a + 1))).length = L.length - 2 ^ (a + 1) := by simp
      have hne1 : L.take (2 ^ (a + 1)) ≠ [] := by
        intro h0; rw [h0] at hk; simp at hk; omega
      have hne2 : L.drop (2 ^ (a + 1)) ≠ [] := by
        intro h0; rw [h0] at hd; simp at hd; omega
      rw [e1, e2, Mt_pair H d a _ hne1 (by omega), Mt_pair H d a _ hne2 (by omega)]

private theorem tr_nil (H : Bytes → Bytes) (d : Bytes) : ∀ f : Nat, treeRoot H d f [] = []
  | 0 => rfl
  | f + 1 => by simp only [treeRoot, pairUp]; exact tr_nil H d f

private theorem tr_Mt (H : Bytes → Bytes) (d : Bytes) : ∀ (f : Nat) (L : List Bytes), L ≠ [] → L.length ≤ 2 ^ f →
    treeRoot H d f L = Mt H d f L
  | 0, L, hne, hl => by
    rcases L with _ | ⟨x, _ | ⟨y, t⟩⟩
    · exact absurd rfl hne
    · simp [treeRoot, Mt]
    · simp at hl
  | f + 1, L, hne, hl => by
    have p2 : 2 ^ (f + 1) = 2 * 2 ^ f := by rw [Nat.pow_succ]; omega
    rcases L with _ | ⟨x, _ | ⟨y, t⟩⟩
    · exact absurd rfl hne
    · simp [treeRoot, Mt_one]
    · have h1 : 1 < (x :: y :: t).length := by simp
      have hlen := pu_len H d (x :: y :: t)
      rw [tr_succ H d f _ h1, tr_Mt H d f _ (by simp [pairUp]) (by omega), Mt_pair H d f _ hne hl]

private def Fr (H : Bytes → Bytes) (d : Bytes) : List (Nat × Bytes) → List Bytes → Prop
  | [], T => T = []
  | (h, r) :: rest, T => ∃ P B, T = P ++ B ∧ B.length = 2 ^ h ∧ r = Mt H d h B ∧ (∀ e ∈ rest, h < e.1) ∧ Fr H d rest P

private theorem carry_fr (H : Bytes → Bytes) : ∀ (f h : Nat) (r : Bytes) (fs : List (Nat × Bytes)) (P B : List Bytes),
    fs.length ≤ f → (∀ e ∈ fs, h ≤ e.1) → Fr H PD fs P → B.length = 2 ^ h → r = Mt H PD h B →
    Fr H PD (carry H f h r fs) (P ++ B) := by
  intro f
  induction f with
  | zero =>
    intro h r fs P B hl _ hF hB hr
    have : fs = [] := List.eq_nil_of_length_eq_zero (by omega)
    subst this
    simp only [Fr] at hF; subst hF
    simp only [carry, Fr]
    exact ⟨[], B, by simp, hB, hr, by simp, by simp [Fr]⟩
  | succ f ih =>
    intro h r fs P B hl hmin hF hB hr
    rcases fs with _ | ⟨⟨h', l⟩, rest⟩
    · simp only [Fr] at hF; subst hF
      simp only [carry, Fr]
      exact ⟨[], B, by simp, hB, hr, by simp, by simp [Fr]⟩
    · simp only [Fr] at hF
      obtain ⟨P', Bl, rfl, hBl, hl', hlt, hF'⟩ := hF
      simp only [carry]
      by_cases hh : h = h'
      · subst hh
        simp only [beq_self_eq_true, if_true]
        have hne : ¬ (Bl ++ B).length ≤ 2 ^ h := by
          rw [List.length_append, hBl, hB]; have := Nat.two_pow_pos h; omega
        have := ih (h + 1) (nodeHash H PD l r) rest P' (Bl ++ B) (by simp at hl; omega)
          (fun e he => Nat.succ_le_of_lt (hlt e he)) hF'
          (by rw [List.length_append, hBl, hB, Nat.pow_succ]; omega)
          (by rw [Mt_succ H PD h (Bl ++ B), if_neg hne, List.take_left' hBl, List.drop_left' hBl, hl', hr])
        rw [List.append_assoc]; exact this
      · have hlt' : h < h' := by
          have := hmin ⟨h', l⟩ (by simp); omega
        have hne : (h == h') = false := by simp [hh]
        rw [hne]; simp only [Bool.false_eq_true, if_false]
        simp only [Fr]
        refine ⟨P' ++ Bl, B, rfl, hB, hr, ?_, ⟨P', Bl, rfl, hBl, hl', hlt, hF'⟩⟩
        intro e he
        simp only [List.mem_cons] at he
        rcases he with rfl | he
        · exact hlt'
        · exact Nat.lt_trans hlt' (hlt e he)

private theorem fr_fold (H : Bytes → Bytes) :
    ∀ xs : List Bytes, xs.length < 2 ^ 64 → Fr H PD (xs.foldl (frontierPush H) []) (xs.map (leafHash H PD)) := by
  intro xs
  induction xs using snoc_ind with
  | h0 => intro _; simp [Fr]
  | hs ys x ih =>
    intro hn
    have hn' : ys.length < 2 ^ 64 := by simp at hn; omega
    have hF := ih hn'
    have hlen : (ys.foldl (frontierPush H) []).length ≤ 64 := by
      have := congrArg List.length (svFp H ys hn')
      simp only [List.length_map] at this
      rw [this]; unfold peaksOf
      exact Nat.le_trans (List.length_filter_le _ _) (by simp)
    rw [List.foldl_append]
    simp only [List.foldl_cons, List.foldl_nil, frontierPush, List.map_append, List.map_cons, List.map_nil]
    exact carry_fr H 64 0 (leafHash H PD x) _ (ys.map (leafHash H PD)) [leafHash H PD x] hlen
      (fun e _ => Nat.zero_le _) hF (by simp) (by simp [Mt])

private theorem fr_fold_root (H : Bytes → Bytes) : ∀ (rest : List (Nat × Bytes)) (P S : List Bytes) (acc : Bytes) (a : Nat),
    Fr H PD rest P → (∀ e ∈ rest, a ≤ e.1 ∧ e.1 < 64) → S.length ≤ 2 ^ a → S ≠ [] → a ≤ 64 →
    acc = Mt H PD a S →
    ∃ b ≤ 64, (P ++ S).length ≤ 2 ^ b ∧
      rest.foldl (fun acc e => nodeHash H PD e.2 acc) acc = Mt H PD b (P ++ S) := by
  intro rest
  induction rest with
  | nil =>
    intro P S acc a hF _ hS _ ha hacc
    simp only [Fr] at hF; subst hF
    exact ⟨a, ha, by simpa using hS, by simp [hacc]⟩
  | cons e rest ih =>
    obtain ⟨h1, r1⟩ := e
    intro P S acc a hF hb hS hSne ha hacc
    simp only [Fr] at hF
    obtain ⟨P', B, rfl, hB, hr, hlt, hF'⟩ := hF
    obtain ⟨hah, h64⟩ := hb (h1, r1) (by simp)
    have hSpos := List.length_pos_iff.mpr hSne
    have hne : ¬ (B ++ S).length ≤ 2 ^ h1 := by
      rw [List.length_append, hB]; omega
    have hSle : S.length ≤ 2 ^ h1 := Nat.le_trans hS (Nat.pow_le_pow_right (by omega) hah)
    have hMt : nodeHash H PD r1 acc = Mt H PD (h1 + 1) (B ++ S) := by
      rw [Mt_succ H PD h1 (B ++ S), if_neg hne, List.take_left' hB, List.drop_left' hB, ← hr, hacc]
      simp only [Mt_indep H PD h1 a S hS hah]
    obtain ⟨b, hb64, hlen, hfold⟩ := ih P' (B ++ S) (nodeHash H PD r1 acc) (h1 + 1) hF'
      (fun e he => ⟨Nat.succ_le_of_lt (hlt e he), (hb e (List.mem_cons_of_mem _ he)).2⟩)
      (by rw [List.length_append, hB, Nat.pow_succ]; omega)
      (by intro h0; exact hSne (List.append_eq_nil_iff.mp h0).2) (by omega) hMt
    exact ⟨b, hb64, by simpa [List.append_assoc] using hlen, by simpa [List.foldl_cons, List.append_assoc] using hfold⟩

theorem listRoot_frontier (H : Bytes → Bytes) (xs : List Bytes) (hn : xs.length < 2 ^ 64) :
    frontierRoot H (xs.foldl (frontierPush H) []) = listRoot H xs := by

  by_cases hx : xs = []
  · subst hx; simp [frontierRoot, listRoot, tr_nil]
  · have hF := fr_fold H xs hn
    have hpks := svFp H xs hn
    generalize xs.foldl (frontierPush H) [] = fs at hF hpks
    have hlt64 : ∀ e ∈ fs, e.1 < 64 := by
      intro e he
      have : e.1 ∈ fs.map (·.1) := List.mem_map_of_mem he
      rw [hpks] at this
      unfold peaksOf at this
      simp at this
      exact this.1
    rcases fs with _ | ⟨⟨h0, r0⟩, rest⟩
    · simp only [Fr] at hF
      exact absurd (List.map_eq_nil_iff.mp hF) hx
    · simp only [Fr] at hF
      obtain ⟨P, B, hTe, hB, hr, hlt, hF'⟩ := hF
      have hpos := Nat.two_pow_pos h0
      have h064 := hlt64 (h0, r0) (by simp)
      obtain ⟨b, hb64, hlen, hfold⟩ := fr_fold_root H rest P B r0 h0 hF'
        (fun e he => ⟨Nat.le_of_lt (hlt e he), hlt64 e (List.mem_cons_of_mem _ he)⟩)
        (by omega) (by intro h0'; rw [h0'] at hB; simp at hB; omega) (by omega) hr
      have hTlen : (xs.map (leafHash H PD)).length ≤ 2 ^ 64 := by simp; omega
      have hTne : xs.map (leafHash H PD) ≠ [] := by simpa using hx
      simp only [frontierRoot]
      rw [hfold, listRoot, tr_Mt H PD 64 _ hTne hTlen, hTe,
        Mt_indep H PD 64 b _ hlen hb64]

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

/-- One unresolved row of the carried context claims `[0, m, mo]` exactly when its near key is that key and
    enrollment is unusable, its date invalid, or its member enrolled. -/
private theorem c9_near_claim (c₀ : Ctx) (rel unr : Snapshot Line) (hi : Inv rel unr) (m mo : Nat) (x : Line)
    (hx : x ∈ unr.entries) : ([0, m, mo] ∈ claim (carried c₀ rel unr) x) ↔
      ((nearKey x == [0, m, mo] &&
        (!usable c₀.today 7 okSpan c₀.enrollment || !validDate x.date || enrolled c₀ x)) = true) := by
  have hd : x ∉ rel.entries := by
    intro hr
    have h := hi.1
    rw [List.map_append, List.nodup_append] at h
    exact h.2.2 x.id (List.mem_map.mpr ⟨x, hr, rfl⟩) x.id (List.mem_map.mpr ⟨x, hx, rfl⟩) rfl
  have ho : own (carried c₀ rel unr) x = false := by
    simp only [own, sv_released_carried]
    simp [hd]
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

/-- The CAP near claim is local: day keys of today's covering spans, invalid dates, or the aggregate key
    when enrollment is unusable. Exact and id keys are always claimed. -/
theorem pending_near_cap (c₀ : Ctx) (rel unr : Snapshot Line) (hi : Inv rel unr) (m mo : Nat) :
    (pending (carried c₀ rel unr)).contains [0, m, mo] =
      unr.entries.any fun x => nearKey x == [0, m, mo] &&
        (!usable c₀.today 7 okSpan c₀.enrollment || !validDate x.date || enrolled c₀ x) := by
  have hk := fun x hx => c9_near_claim c₀ rel unr hi m mo x hx
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

/-- `ids_disjoint` (Rules/Theorems.lean:516) with the registry's foreign ids. -/
private theorem sv_ids_disjoint_in {c : Ctx} {f : List Nat} {b : List Line}
    (h : ∀ x ∈ releasedSet c, ∀ y ∈ unresolvedSet c, x.id ≠ y.id) :
    ∀ x ∈ (decideBatchIn c f b).released.entries, ∀ y ∈ (decideBatchIn c f b).unresolved.entries,
      x.id ≠ y.id := by
  intro x hx y hy hxy
  rcases List.mem_append.mp hx with hx | hx <;> rcases List.mem_append.mp hy with hy | hy
  · exact h x hx y hy hxy
  · obtain ⟨dy, hdy, rfl⟩ := List.mem_map.mp hy
    obtain ⟨hdy, hay⟩ := List.mem_filter.mp hdy
    have fy : dy.outcome ≠ .ALLOW ∧ Reason.ALREADY_DECIDED ∉ dy.reasons ∧ own c dy.line = false := by
      simp at hay; exact and_assoc.mp hay
    obtain ⟨seen, he, hs⟩ := seen_all_in (c := c) (f := f) (b := b) hdy fy.2.2
    apply fy.2.1
    rw [he]
    exact mem_decideLine.mpr (Or.inl (hs x hx _ (by
      rw [show idKey dy.line = idKey x by simp [idKey, hxy]]; exact idKey_mem)))
  · obtain ⟨dx, hdx, rfl⟩ := List.mem_map.mp (List.mem_filter.mp hx).1
    obtain ⟨hdx, hax⟩ := List.mem_filter.mp hdx
    have hdx' : dx ∈ decideAll c (idSeen f ++ seen0 c b) (order c b) := hdx
    obtain ⟨pre, l, rfl⟩ := mem_decideAll hdx'
    have hk := ((allow_facts (by simpa using hax)).2 (idKey l) idKey_mem).2
    have hxy : l.id = y.id := hxy
    exact hk (List.mem_flatMap.mpr ⟨y, hy, by
      rw [show idKey l = idKey y by simp [idKey, hxy]]; exact idKey_claim⟩)
  · obtain ⟨dx, hdx, rfl⟩ := List.mem_map.mp (List.mem_filter.mp hx).1
    obtain ⟨hdx, hax⟩ := List.mem_filter.mp hdx
    obtain ⟨dy, hdy, rfl⟩ := List.mem_map.mp hy
    obtain ⟨hdy, hay⟩ := List.mem_filter.mp hdy
    have hdx' : dx ∈ decideAll c (idSeen f ++ seen0 c b) (order c b) := hdx
    have hdy' : dy ∈ decideAll c (idSeen f ++ seen0 c b) (order c b) := hdy
    have hax : dx.outcome = .ALLOW := by simpa using hax
    have hay : dy.outcome ≠ .ALLOW ∧ Reason.ALREADY_DECIDED ∉ dy.reasons ∧ own c dy.line = false := by
      simp at hay; exact and_assoc.mp hay
    exact fresh_ids c hdx' hdy' (fun e => hay.1 (e ▸ hax)) (by rw [allow_nil hdx' hax]; simp) hay.2.1 hxy

/-- Two decisions of one run, neither `ALREADY_DECIDED`, have distinct line ids (positions, not values). -/
private theorem sv_fresh_pairwise (c : Ctx) : ∀ (seen : List Key) (ls : List Line),
    (decideAll c seen ls).Pairwise fun a d =>
      Reason.ALREADY_DECIDED ∉ a.reasons → Reason.ALREADY_DECIDED ∉ d.reasons → a.line.id ≠ d.line.id
  | _, [] => List.Pairwise.nil
  | seen, l :: ls => by
    refine List.Pairwise.cons (fun e he _ fe hid => ?_) (sv_fresh_pairwise c (claim c l ++ seen) ls)
    have hid' : l.id = e.line.id := hid
    exact (fresh_unseen he fe).1 (List.mem_append_left _ (by
      rw [show idKey e.line = idKey l by simp [idKey, hid']]; exact idKey_claim))

private theorem sv_unr_fresh {c : Ctx} {d : Decision}
    (hq : (d.outcome != .ALLOW && !d.reasons.contains .ALREADY_DECIDED && !own c d.line) = true) :
    Reason.ALREADY_DECIDED ∉ d.reasons := fun hm => by
  simp only [Bool.and_eq_true, Bool.not_eq_true'] at hq
  rw [List.contains_iff_mem.mpr hm] at hq
  cases hq.1.2

/-- `released_nodup` (Rules/Shards.lean:131) for the unresolved set. -/
private theorem sv_unresolved_nodup_in {c : Ctx} {f : List Nat} {b : List Line}
    (hn : ((unresolvedSet c).map (·.id)).Nodup) :
    (((decideBatchIn c f b).unresolved.entries).map (·.id)).Nodup := by
  change ((unresolvedSet c ++ unresolvedLines c (decideAll c (idSeen f ++ seen0 c b) (order c b))).map
    (·.id)).Nodup
  rw [List.map_append, List.nodup_append]
  refine ⟨hn, ?_, ?_⟩
  · unfold unresolvedLines List.Nodup
    rw [List.map_map, List.pairwise_map, List.pairwise_filter]
    exact (sv_fresh_pairwise c (idSeen f ++ seen0 c b) (order c b)).imp
      fun {_ _} h ha hd => h (sv_unr_fresh ha) (sv_unr_fresh hd)
  · intro i hi j hj hij
    obtain ⟨y, hy, rfl⟩ := List.mem_map.mp hi
    obtain ⟨z, hz, rfl⟩ := List.mem_map.mp hj
    obtain ⟨d, hd, rfl⟩ := List.mem_map.mp hz
    obtain ⟨hd, hq⟩ := List.mem_filter.mp hd
    exact (fresh_unseen hd (sv_unr_fresh hq)).2 (List.mem_flatMap.mpr ⟨y, hy, by
      rw [show idKey d.line = idKey y by simp [idKey, hij]]; exact idKey_claim⟩)

/-- `Inv` survives one `decideReg` batch on the carried sets (dates aside). -/
private theorem sv_inv_reg (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (rel unr : Snapshot Line)
    (hi : Inv rel unr) :
    Inv (decideReg (carried c₀ rel unr) k os b).released (decideReg (carried c₀ rel unr) k os b).unresolved := by
  obtain ⟨-, -, n1, n2⟩ := decideReg_carried_asOf c₀ k os b rel unr
  have h := hi.1
  rw [List.map_append, List.nodup_append] at h
  obtain ⟨hr, hu, hd⟩ := h
  refine ⟨?_, n1, n2⟩
  rw [List.map_append, List.nodup_append]
  refine ⟨released_nodup (f := foreignOf k os (ready k os b)) (b := ready k os b)
      (by rw [sv_released_carried]; exact hr),
    sv_unresolved_nodup_in (by rw [sv_unresolved_carried]; exact hu), ?_⟩
  intro i hi' j hj hij
  obtain ⟨x, hx, rfl⟩ := List.mem_map.mp hi'
  obtain ⟨y, hy, rfl⟩ := List.mem_map.mp hj
  refine sv_ids_disjoint_in (f := foreignOf k os (ready k os b)) (b := ready k os b) ?_ x hx y hy hij
  rw [sv_released_carried, sv_unresolved_carried]
  exact fun x hx y hy => hd _ (List.mem_map_of_mem hx) _ (List.mem_map_of_mem hy)

theorem inv_step (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (rel unr : Snapshot Line)
    (hi : Inv rel unr) :
    let r := decideRegT (carried c₀ rel unr) k os b
    Inv r.released r.unresolved := sv_inv_reg c₀ k os b rel unr hi


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

-- `stateV2_binds` is stated and proved after `c3_setMap_mem` (§7), whose lemmas it uses.

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

private theorem c3_headIn_some {h : Head} {x : Bytes} (hx : headIn h = some x) :
    ∃ a b c d, be 4 h.relAsOf = some a ∧ be 4 h.unrAsOf = some b ∧ be 8 h.relCount = some c ∧
      be 8 h.unrCount = some d ∧ h.relRoot.length = digestBytes ∧ h.unrRoot.length = digestBytes ∧
      x = dom2 "STATE" ++ a ++ b ++ c ++ d ++ h.relRoot ++ h.unrRoot := by
  unfold headIn at hx
  cases h1 : be 4 h.relAsOf with
  | none => simp [h1] at hx
  | some a =>
  cases h2 : be 4 h.unrAsOf with
  | none => simp [h1, h2] at hx
  | some b =>
  cases h3 : be 8 h.relCount with
  | none => simp [h1, h2, h3] at hx
  | some c =>
  cases h4 : be 8 h.unrCount with
  | none => simp [h1, h2, h3, h4] at hx
  | some d =>
  by_cases hg : h.relRoot.length = digestBytes ∧ h.unrRoot.length = digestBytes
  · simp [h1, h2, h3, h4, hg, guard] at hx
    exact ⟨a, b, c, d, rfl, rfl, rfl, rfl, hg.1, hg.2, by rw [← hx]; simp [List.append_assoc]⟩
  · simp [h1, h2, h3, h4, hg, guard] at hx
    first | exact Option.noConfusion hx | cases hx | simp [failure] at hx

private theorem c3_headIn_inj {g h : Head} {x : Bytes} (hg : headIn g = some x) (hh : headIn h = some x) : g = h := by
  obtain ⟨a, b, c, d, h1, h2, h3, h4, h5, h6, rfl⟩ := c3_headIn_some hg
  obtain ⟨a', b', c', d', h1', h2', h3', h4', h5', h6', he⟩ := c3_headIn_some hh
  have e6 := List.append_inj' he (by rw [h6, h6'])
  have e5 := List.append_inj' e6.1 (by rw [h5, h5'])
  have e4 := List.append_inj' e5.1 (by rw [be_len h4, be_len h4'])
  have e3 := List.append_inj' e4.1 (by rw [be_len h3, be_len h3'])
  have e2 := List.append_inj' e3.1 (by rw [be_len h2, be_len h2'])
  have e1 := List.append_inj' e2.1 (by rw [be_len h1, be_len h1'])
  cases g; cases h
  simp only at *
  rw [← e1.2] at h1'; rw [← e2.2] at h2'; rw [← e3.2] at h3'; rw [← e4.2] at h4'
  rw [be_inj h1 h1', be_inj h2 h2', be_inj h3 h3', be_inj h4 h4', e5.2, e6.2]

private theorem c3_mapM_all {α β : Type} (f : α → Option β) :
    ∀ (xs : List α) (ys : List β), xs.mapM f = some ys → ∀ x ∈ xs, ∃ y ∈ ys, f x = some y
  | [], _, _, x, hx => by simp at hx
  | a :: xs, ys, h, x, hx => by
    simp only [List.mapM_cons] at h
    cases ha : f a with
    | none => simp [ha] at h
    | some b =>
      cases hm : xs.mapM f with
      | none => simp [ha, hm] at h
      | some bs =>
        simp [ha, hm] at h
        subst h
        rcases List.mem_cons.mp hx with rfl | hx
        · exact ⟨b, by simp, ha⟩
        · obtain ⟨y, hy, e⟩ := c3_mapM_all f xs bs hm x hx
          exact ⟨y, by simp [hy], e⟩

private theorem c3_mem_zipIdx {α : Type} {s : List α} {x : α} {i : Nat} (h : (x, i) ∈ s.zipIdx) : x ∈ s := by
  rw [List.mem_zipIdx_iff_getElem?] at h
  exact List.mem_of_getElem? h

private theorem c3_zipIdx_of_mem {α : Type} {s : List α} {x : α} (h : x ∈ s) : ∃ i, (x, i) ∈ s.zipIdx := by
  obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp h
  exact ⟨i, List.mem_zipIdx_iff_getElem?.mpr hi⟩

private theorem c3_setMap_mem {H : Bytes → Bytes} {u : Bool} {s : List Line} {m : Map} (hm : setMap H u s = some m) :
    (∀ e ∈ m, (∃ x i, (x, i) ∈ s.zipIdx ∧ ∃ kb, keyBytes (rowKey x) = some kb ∧ be 8 i = some e.2 ∧
        e.1 = pathOf H kb) ∨
      (∃ q ∈ (s.flatMap (rowKeys u)).eraseDups, ∃ kb es, keyBytes q = some kb ∧ postings u s q = some es ∧
        keyVal es.length (es.foldl (frontierPush H) []) = some e.2 ∧ e.1 = pathOf H kb)) ∧
    (∀ x ∈ s, ∃ kb, keyBytes (rowKey x) = some kb ∧ ∃ v, (pathOf H kb, v) ∈ m) ∧
    (∀ q ∈ s.flatMap (rowKeys u), ∃ kb es, keyBytes q = some kb ∧ postings u s q = some es ∧
        ∃ v, keyVal es.length (es.foldl (frontierPush H) []) = some v ∧ (pathOf H kb, v) ∈ m) ∧
    (m.map (·.1)).Nodup := by
  unfold setMap at hm
  simp only [bind, Option.bind] at hm
  split at hm
  · simp at hm
  rename_i rows hrows
  dsimp only at hm
  split at hm
  · simp at hm
  rename_i ks hks
  dsimp only at hm
  by_cases hg : (rows.map (·.1) ++ ks.map (·.1)).Nodup
  · simp [guard, hg] at hm
    subst hm
    refine ⟨?_, ?_, ?_, by simpa [List.map_append] using hg⟩
    · intro e he
      rcases List.mem_append.mp he with he | he
      · left
        obtain ⟨⟨x, i⟩, hx, hf⟩ := g1_mapM_mem _ _ _ hrows e he
        cases hk : keyBytes (rowKey x) with
        | none => simp [hk] at hf
        | some kb =>
          cases hb : be 8 i with
          | none => simp [hk, hb] at hf
          | some v =>
            simp [hk, hb] at hf
            subst hf
            exact ⟨x, i, hx, kb, hk, hb, rfl⟩
      · right
        obtain ⟨q, hq, hf⟩ := g1_mapM_mem _ _ _ hks e he
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
              exact ⟨q, hq, kb, es, hk, hp, hv, rfl⟩
    · intro x hx
      obtain ⟨i, hi⟩ := c3_zipIdx_of_mem hx
      obtain ⟨e, he, hf⟩ := c3_mapM_all _ _ _ hrows _ hi
      cases hk : keyBytes (rowKey x) with
      | none => simp [hk] at hf
      | some kb =>
        cases hb : be 8 i with
        | none => simp [hk, hb] at hf
        | some v =>
          simp [hk, hb] at hf
          subst hf
          exact ⟨kb, rfl, v, List.mem_append_left _ he⟩
    · intro q hq
      have hq' : q ∈ (s.flatMap (rowKeys u)).eraseDups := List.mem_eraseDups.mpr hq
      obtain ⟨e, he, hf⟩ := c3_mapM_all _ _ _ hks _ hq'
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
            exact ⟨kb, es, rfl, rfl, v, by first | exact hv | rfl, List.mem_append_right _ he⟩
  · simp [guard, hg] at hm

/-- The ROW leaf of row `i` is in the map, with value `be 8 i`. -/
private theorem c12_setMap_row {H : Bytes → Bytes} {u : Bool} {s : List Line} {m : Map}
    (hm : setMap H u s = some m) {x : Line} {i : Nat} (hxi : (x, i) ∈ s.zipIdx) :
    ∃ kb v, keyBytes (rowKey x) = some kb ∧ be 8 i = some v ∧ (pathOf H kb, v) ∈ m := by
  unfold setMap at hm
  simp only [bind, Option.bind] at hm
  split at hm
  · simp at hm
  rename_i rows hrows
  dsimp only at hm
  split at hm
  · simp at hm
  rename_i ks hks
  dsimp only at hm
  by_cases hg : (rows.map (·.1) ++ ks.map (·.1)).Nodup
  · simp [guard, hg] at hm
    subst hm
    obtain ⟨e, he, hf⟩ := c3_mapM_all _ _ _ hrows _ hxi
    cases hk : keyBytes (rowKey x) with
    | none => simp [hk] at hf
    | some kb =>
      cases hb : be 8 i with
      | none => simp [hk, hb] at hf
      | some v =>
        simp [hk, hb] at hf
        subst hf
        exact ⟨kb, v, rfl, rfl, List.mem_append_left _ he⟩
  · simp [guard, hg] at hm

/-- Tag 7: a row key is never one of the keys a row is stored under. -/
private theorem c12_rowKey_ne (u : Bool) (x y : Line) : rowKey x ∉ rowKeys u y := by
  intro h
  by_cases hc : isCap y = true <;> by_cases hv : validDate y.date = true <;>
    simp [rowKeys, keys, exactKey, nearKey, idKey, dayKey, badDayKey, rowKey, hc, hv] at h

private theorem c12_kd_mem {H : Bytes → Bytes} {u : Bool} {s : List Line} {q : Key} {kb : Bytes}
    (hq : q ∈ s.map rowKey ++ (s.flatMap (rowKeys u)).eraseDups) (hk : keyBytes q = some kb) :
    KD ++ kb ∈ setInputs H u s := by
  simp only [setInputs]
  exact List.mem_append_left _ (List.mem_append_left _ (List.mem_filterMap.mpr ⟨q, hq, by simp [hk]⟩))

private theorem c12_tree_mem {H : Bytes → Bytes} {u : Bool} {s : List Line} {m : Map}
    (hm : setMap H u s = some m) {z : Bytes} (hz : z ∈ treeInputs H 513 0 m) : z ∈ setInputs H u s := by
  simp only [setInputs, hm]
  exact List.mem_append_right _ hz

/-- Map to set: if every entry of `s`'s map is in `s'`'s map and the lengths agree, the row lists are
    equal, or two key paths collide. -/
private theorem c12_set_bind {H : Bytes → Bytes} {u : Bool} {s s' : List Line} {m m' : Map}
    (hs : setMap H u s = some m) (hs' : setMap H u s' = some m') (hsub : ∀ e ∈ m, e ∈ m')
    (hl : s.length = s'.length) : s = s' ∨ Collision H (setInputs H u s) (setInputs H u s') := by
  by_cases hc : Collision H (setInputs H u s) (setInputs H u s')
  · exact Or.inr hc
  left
  have hkd : ∀ {kb kb' : Bytes}, KD ++ kb ∈ setInputs H u s → KD ++ kb' ∈ setInputs H u s' →
      pathOf H kb = pathOf H kb' → kb = kb' := by
    intro kb kb' h1 h2 hp
    by_cases he : KD ++ kb = KD ++ kb'
    · exact List.append_cancel_left he
    · exact (hc (by unfold Collision; exact ⟨_, h1, _, h2, he, hp⟩)).elim
  have key : ∀ x i, (x, i) ∈ s.zipIdx → s'[i]? = some x := by
    intro x i hxi
    obtain ⟨kb, v, hk, hb, hmem⟩ := c12_setMap_row hs hxi
    have h1 : KD ++ kb ∈ setInputs H u s :=
      c12_kd_mem (List.mem_append_left _ (List.mem_map_of_mem (c3_mem_zipIdx hxi))) hk
    rcases (c3_setMap_mem hs').1 _ (hsub _ hmem) with
      ⟨y, j, hyj, kb', hk', hb', hp⟩ | ⟨q, hq, kb', es, hk', _, _, hp⟩
    · have hkb : kb = kb' :=
        hkd h1 (c12_kd_mem (List.mem_append_left _ (List.mem_map_of_mem (c3_mem_zipIdx hyj))) hk') hp
      subst hkb
      have hxy : x = y := rowKey_inj hk hk'
      have hij : i = j := be_inj hb hb'
      subst hxy
      subst hij
      exact List.mem_zipIdx_iff_getElem?.mp hyj
    · have hkb : kb = kb' := hkd h1 (c12_kd_mem (List.mem_append_right _ hq) hk') hp
      subst hkb
      have hq' := keyBytes_inj hk hk'
      subst hq'
      obtain ⟨y, _, hy⟩ := List.mem_flatMap.mp (List.mem_eraseDups.mp hq)
      exact (c12_rowKey_ne u x y hy).elim
  apply List.ext_getElem?
  intro i
  cases h : s[i]? with
  | some x => exact (key x i (List.mem_zipIdx_iff_getElem?.mpr h)).symm
  | none =>
    have h1 : s.length ≤ i := by simpa using h
    have h2 : s'[i]? = none := by simpa using (show s'.length ≤ i by omega)
    exact h2.symm

theorem stateV2_binds (H : Bytes → Bytes) (hH : HashLen H) (rel unr rel' unr' : Snapshot Line)
    (hi : Inv rel unr) (hi' : Inv rel' unr') (h h' : Head) (d : Bytes)
    (ha : headOf H rel unr = some h) (ha' : headOf H rel' unr' = some h')
    (he : digestV2 H h = some d) (he' : digestV2 H h' = some d) :
    (rel = rel' ∧ unr = unr') ∨ Collision H (stateInputs H rel unr) (stateInputs H rel' unr') := by
  unfold digestV2 at he he'
  obtain ⟨x, hx, rfl⟩ := Option.map_eq_some_iff.mp he
  obtain ⟨x', hx', hxx⟩ := Option.map_eq_some_iff.mp he'
  by_cases hne : x = x'
  case neg =>
    right
    have h1 : x ∈ stateInputs H rel unr := by unfold stateInputs; rw [ha]; simp [hx]
    have h2 : x' ∈ stateInputs H rel' unr' := by unfold stateInputs; rw [ha']; simp [hx']
    unfold Collision
    exact ⟨x, h1, x', h2, hne, hxx.symm⟩
  subst hne
  have hhh := c3_headIn_inj hx hx'
  subst hhh
  cases hs1 : setMap H false rel.entries with
  | none => simp [headOf, hs1] at ha
  | some a =>
  cases hs2 : setMap H true unr.entries with
  | none => simp [headOf, hs1, hs2] at ha
  | some b =>
  cases hs3 : setMap H false rel'.entries with
  | none => simp [headOf, hs3] at ha'
  | some a' =>
  cases hs4 : setMap H true unr'.entries with
  | none => simp [headOf, hs3, hs4] at ha'
  | some b' =>
  have e1 : headOf H rel unr = some ⟨rel.asOf, unr.asOf, rel.count, unr.count, root H a, root H b⟩ := by
    unfold headOf; rw [hs1, hs2]; first | rfl | simp
  have e2 : headOf H rel' unr' =
      some ⟨rel'.asOf, unr'.asOf, rel'.count, unr'.count, root H a', root H b'⟩ := by
    unfold headOf; rw [hs3, hs4]; first | rfl | simp
  have heq := Option.some.inj ((e1.symm.trans ha).trans (ha'.symm.trans e2))
  injection heq with q1 q2 q3 q4 q5 q6
  obtain ⟨_, c1, c2⟩ := hi
  obtain ⟨_, c1', c2'⟩ := hi'
  rcases c12_root_bind H hH a a' (setMap_ok H hH _ _ _ hs1) (setMap_ok H hH _ _ _ hs3) q5 with hA | hA
  · rcases c12_root_bind H hH b b' (setMap_ok H hH _ _ _ hs2) (setMap_ok H hH _ _ _ hs4) q6 with hB | hB
    · rcases c12_set_bind hs1 hs3 (fun e he => hA.mem_iff.mp he) (by omega) with r1 | r1
      · rcases c12_set_bind hs2 hs4 (fun e he => hB.mem_iff.mp he) (by omega) with r2 | r2
        · left
          have ext : ∀ p q : Snapshot Line, p.asOf = q.asOf → p.count = q.count → p.entries = q.entries →
              p = q := by
            intro p q f1 f2 f3
            cases p
            cases q
            simp only at f1 f2 f3
            subst f1 f2 f3
            rfl
          exact ⟨ext _ _ q1 q3 r1, ext _ _ q2 q4 r2⟩
        · right
          refine coll_mono H ?_ ?_ r2 <;> intro z hz <;> unfold stateInputs <;>
            exact List.mem_append_right _ hz
      · right
        refine coll_mono H ?_ ?_ r1 <;> intro z hz <;> unfold stateInputs <;>
          exact List.mem_append_left _ (List.mem_append_right _ hz)
    · right
      refine coll_mono H ?_ ?_ hB
      · intro z hz; unfold stateInputs; exact List.mem_append_right _ (c12_tree_mem hs2 hz)
      · intro z hz; unfold stateInputs; exact List.mem_append_right _ (c12_tree_mem hs4 hz)
  · right
    refine coll_mono H ?_ ?_ hA
    · intro z hz; unfold stateInputs
      exact List.mem_append_left _ (List.mem_append_right _ (c12_tree_mem hs1 hz))
    · intro z hz; unfold stateInputs
      exact List.mem_append_left _ (List.mem_append_right _ (c12_tree_mem hs3 hz))

private theorem c3_lookup_some {m : Map} {p v : Bytes} (h : lookup m p = some v) : (p, v) ∈ m := by
  unfold lookup at h
  cases hf : m.find? (·.1 == p) with
  | none => simp [hf] at h
  | some e =>
    simp [hf] at h
    have hm := List.mem_of_find?_eq_some hf
    have he := List.find?_some hf
    simp at he
    obtain ⟨a, b⟩ := e
    simp at he h
    subst he; subst h; exact hm

private theorem c3_lookup_none {m : Map} {p : Bytes} (h : lookup m p = none) : ∀ e ∈ m, e.1 ≠ p := by
  unfold lookup at h
  simp at h
  intro e he hep
  exact h e.1 e.2 he hep

private theorem c3_rowKeys_head (u : Bool) (x : Line) : ∀ q ∈ rowKeys u x, q.head? ≠ some 7 := by
  simp only [rowKeys, keys, exactKey, nearKey, idKey, dayKey, badDayKey]
  repeat' split
  all_goals simp

/-- The true hit of key `q` in set `s` at path `p`. -/
private def c3T (H : Bytes → Bytes) (u : Bool) (s : List Line) (q : Key) (p : Bytes) : Hit :=
  if q.head? = some 7 then ⟨u, q, p, if s.any (fun x => rowKey x == q) then 1 else 0, [], []⟩ else
    let es := (postings u s q).getD []
    ⟨u, q, p, es.length, es.foldl (frontierPush H) [], es.take K⟩

private theorem c3_probe (H : Bytes → Bytes) (hH : HashLen H) (u : Bool) (s : List Line) (m : Map)
    (hm : setMap H u s = some m) (pf : Proof) (w : Witness) (ps : List Bytes)
    (hv : verifyMulti H (root H m) ps pf = true) (q : Key) (kb : Bytes) (hk : keyBytes q = some kb)
    (hp : pathOf H kb ∈ ps) (A B : List Bytes) (hA1 : KD ++ kb ∈ A) (hA2 : ∀ y ∈ pfInputs H pf, y ∈ A)
    (hA3 : ∀ y ∈ w.lists.flatMap (fun (_, _, n, ys, fp) => firstKInputs H n ys fp), y ∈ A)
    (hB : ∀ y ∈ setInputs H u s, y ∈ B) (nc : ¬ Collision H A B) (r : Option Hit)
    (hr : probe H pf w u q = some r) : r = some (c3T H u s q (pathOf H kb)) := by
  obtain ⟨hmem, hrow, hkey, -⟩ := c3_setMap_mem hm
  have hlk : lookupPf 0 pf (pathOf H kb) = some (lookup m (pathOf H kb)) := by
    rcases smt_sound H hH m (setMap_ok H hH u s m hm) ps pf hv _ hp with h | h
    · exact h
    · exact absurd (coll_mono H hA2 (fun y hy => hB y (by simp [setInputs, hm, hy])) h) nc
  have hkb : ∀ q' kb', keyBytes q' = some kb' → q' ∈ s.map rowKey ++ (s.flatMap (rowKeys u)).eraseDups →
      pathOf H kb' = pathOf H kb → q' = q := by
    intro q' kb' hk' hq' he
    by_cases hne : KD ++ kb = KD ++ kb'
    · have : kb = kb' := List.append_cancel_left hne
      subst this
      exact keyBytes_inj hk' hk
    · refine absurd ⟨KD ++ kb, hA1, KD ++ kb', hB _ ?_, hne, he.symm⟩ nc
      unfold setInputs
      simp only [List.mem_append, List.mem_filterMap]
      exact Or.inl (Or.inl ⟨q', by simpa using hq', by simp [hk']⟩)
  unfold probe at hr
  rw [hk] at hr
  simp only [hlk] at hr
  cases hl : lookup m (pathOf H kb) with
  | none =>
    simp [hl] at hr
    subst hr
    have hn := c3_lookup_none hl
    unfold c3T
    split
    · have : s.any (fun x => rowKey x == q) = false := by
        rw [Bool.eq_false_iff]
        intro ha
        obtain ⟨x, hx, hxq⟩ := List.any_eq_true.mp ha
        have hxq : rowKey x = q := by simpa using hxq
        obtain ⟨kb', hk', v, hv'⟩ := hrow x hx
        rw [hxq, hk] at hk'
        cases hk'
        exact hn _ hv' rfl
      simp [this]
    · have hnil : (s.zipIdx.filter fun (x, _) => (rowKeys u x).contains q) = [] := by
        rw [List.filter_eq_nil_iff]
        rintro ⟨x, i⟩ hxi hc
        have hq : q ∈ s.flatMap (rowKeys u) := List.mem_flatMap.mpr ⟨x, c3_mem_zipIdx hxi, by simpa using hc⟩
        obtain ⟨kb', es, hk', -, v, -, hv'⟩ := hkey q hq
        rw [hk] at hk'
        cases hk'
        exact hn _ hv' rfl
      have : postings u s q = some [] := by unfold postings; rw [hnil]; rfl
      simp [this]
  | some v =>
    simp [hl] at hr
    rcases hmem _ (c3_lookup_some hl) with ⟨x, i, hxi, kb', hk', hb, he⟩ | ⟨q', hq', kb', es, hk', hes, hkv, he⟩
    · have hxq := hkb _ _ hk' (List.mem_append_left _ (List.mem_map_of_mem (c3_mem_zipIdx hxi))) he.symm
      subst hxq
      have h7 : (rowKey x).head? = some 7 := rfl
      have hv8 : v.length = 8 := be_len hb
      simp [h7, hv8] at hr
      subst hr
      unfold c3T
      rw [if_pos h7]
      have : s.any (fun y => rowKey y == rowKey x) = true := List.any_eq_true.mpr ⟨x, c3_mem_zipIdx hxi, by simp⟩
      simp [this]
    · have hqq := hkb _ _ hk' (List.mem_append_right _ hq') he.symm
      subst hqq
      rw [hk] at hk'; cases hk'
      obtain ⟨y, -, hqy⟩ := List.mem_flatMap.mp (List.mem_eraseDups.mp hq')
      have h7 := c3_rowKeys_head u y _ hqy
      have hlt : es.length < 2 ^ 64 := by
        unfold keyVal at hkv
        cases hb : be 8 es.length with
        | none => simp [hb] at hkv
        | some c =>
          have h1 := be_lt hb
          have : (256 : Nat) ^ 8 = 2 ^ 64 := by decide
          omega
      have hpk := keyVal_parse H hH es v hkv
      rw [if_neg h7, hpk] at hr
      cases hf : w.lists.find? (fun e => e.fst == u && e.snd.fst == pathOf H kb) with
      | none => simp [hf] at hr
      | some e =>
        obtain ⟨a1, a2, n', ys, fp⟩ := e
        simp only [hf] at hr
        split at hr
        · rename_i hc
          obtain ⟨⟨-, rfl⟩, hvf⟩ := hc
          rw [listRoot_frontier H es hlt] at hvf
          have hmemL : (a1, a2, es.length, ys, fp) ∈ w.lists := List.mem_of_find?_eq_some hf
          rcases firstK_sound H hH es ys fp hlt hvf with hys | hc
          · simp at hr; subst hr; subst hys
            unfold c3T; rw [if_neg h7]; simp [hes]
          · refine absurd (coll_mono H (fun y hy => hA3 y ?_) (fun y hy => hB y ?_) hc) nc
            · exact List.mem_flatMap.mpr ⟨_, hmemL, hy⟩
            · unfold setInputs
              simp only [List.mem_append, List.mem_flatMap]
              exact Or.inl (Or.inr ⟨_, hq', by simpa [hes] using hy⟩)
        · simp at hr

private theorem c3T_key (H : Bytes → Bytes) (u : Bool) (s : List Line) (q : Key) (p : Bytes) :
    (c3T H u s q p).key = q := by unfold c3T; split <;> rfl
private theorem c3T_unr (H : Bytes → Bytes) (u : Bool) (s : List Line) (q : Key) (p : Bytes) :
    (c3T H u s q p).unr = u := by unfold c3T; split <;> rfl

private theorem c3_mapM_len {α β : Type} (f : α → Option β) :
    ∀ (xs : List α) (ys : List β), xs.mapM f = some ys → ys.length = xs.length
  | [], ys, h => by simp at h; subst h; rfl
  | a :: xs, ys, h => by
    simp only [List.mapM_cons] at h
    cases ha : f a with
    | none => simp [ha] at h
    | some b =>
      cases hm : xs.mapM f with
      | none => simp [ha, hm] at h
      | some bs =>
        simp [ha, hm] at h
        subst h
        simp [c3_mapM_len f xs bs hm]

private theorem c3_postings_len {u : Bool} {s : List Line} {q : Key} {es : List Bytes} (h : postings u s q = some es) :
    es.length = (s.filter fun x => (rowKeys u x).contains q).length := by
  unfold postings at h
  rw [c3_mapM_len _ _ _ h]
  have e : s.filter (fun x => (rowKeys u x).contains q) =
      (s.zipIdx.filter fun (x, _) => (rowKeys u x).contains q).map Prod.fst := by
    conv => lhs; rw [← List.zipIdx_map_fst 0 s]
    rw [List.filter_map]
    first | rfl | (congr 1; apply List.filter_congr; intro p _; cases p; rfl)
  rw [e, List.length_map]

private theorem c3T_n {H : Bytes → Bytes} {u : Bool} {s : List Line} {m : Map} (hm : setMap H u s = some m)
    {q : Key} (h7 : q.head? ≠ some 7) (p : Bytes) :
    (c3T H u s q p).n = (s.filter fun x => (rowKeys u x).contains q).length := by
  unfold c3T
  rw [if_neg h7]
  show ((postings u s q).getD []).length = _
  cases hp : postings u s q with
  | some es => exact c3_postings_len hp
  | none =>
    show 0 = _
    symm
    rw [List.length_eq_zero_iff, List.filter_eq_nil_iff]
    intro x hx hq
    obtain ⟨kb, es, -, hes, -⟩ :=
      (c3_setMap_mem hm).2.2.1 q (List.mem_flatMap.mpr ⟨x, hx, by simpa using hq⟩)
    rw [hp] at hes; cases hes

private theorem c3_postings_lt {H : Bytes → Bytes} {u : Bool} {s : List Line} {m : Map} (hm : setMap H u s = some m)
    (q : Key) : ((postings u s q).getD []).length < 2 ^ 64 := by
  by_cases hq : q ∈ s.flatMap (rowKeys u)
  · obtain ⟨kb, es, -, hes, v, hv, -⟩ := (c3_setMap_mem hm).2.2.1 q hq
    rw [hes]
    unfold keyVal at hv
    cases hb : be 8 es.length with
    | none => simp [hb] at hv
    | some c =>
      have h1 := be_lt hb
      have e : (256:Nat) ^ 8 = 2 ^ 64 := by decide
      rw [e] at h1
      exact h1
  · have : (s.zipIdx.filter fun (x, _) => (rowKeys u x).contains q) = [] := by
      rw [List.filter_eq_nil_iff]
      intro ⟨x, i⟩ hx hc
      exact hq (List.mem_flatMap.mpr ⟨x, c3_mem_zipIdx hx, by simpa using hc⟩)
    unfold postings; rw [this]; simp

private theorem c3_find {hs : List Hit} {P : Hit → Bool} {t : Hit} (ht : t ∈ hs) (hp : P t = true)
    (hu : ∀ h ∈ hs, P h = true → h = t) : hs.find? P = some t := by
  cases hf : hs.find? P with
  | none => exact absurd hp (by simpa using List.find?_eq_none.mp hf t ht)
  | some h => rw [hu h (List.mem_of_find?_eq_some hf) (List.find?_some hf)]

private theorem c3_probes (H : Bytes → Bytes) (hH : HashLen H) (u : Bool) (s : List Line) (m : Map)
    (hm : setMap H u s = some m) (pf : Proof) (w : Witness) (qs : List Key)
    (hv : verifyMulti H (root H m) (qs.filterMap fun q => (keyBytes q).map (pathOf H)) pf = true)
    (A B : List Bytes) (hA1 : ∀ q ∈ qs, ∀ kb, keyBytes q = some kb → KD ++ kb ∈ A)
    (hA2 : ∀ y ∈ pfInputs H pf, y ∈ A)
    (hA3 : ∀ y ∈ w.lists.flatMap (fun (_, _, n, ys, fp) => firstKInputs H n ys fp), y ∈ A)
    (hB : ∀ y ∈ setInputs H u s, y ∈ B) (nc : ¬ Collision H A B) (hs : List (Option Hit))
    (hh : qs.mapM (probe H pf w u) = some hs) :
    (∀ h ∈ hs.filterMap id, ∃ kb, keyBytes h.key = some kb ∧ h = c3T H u s h.key (pathOf H kb)) ∧
    (∀ q ∈ qs, ∀ kb, keyBytes q = some kb → c3T H u s q (pathOf H kb) ∈ hs.filterMap id) := by
  have hpr : ∀ q ∈ qs, ∀ kb, keyBytes q = some kb → ∀ r, probe H pf w u q = some r →
      r = some (c3T H u s q (pathOf H kb)) := fun q hq kb hk r hr =>
    c3_probe H hH u s m hm pf w _ hv q kb hk
      (List.mem_filterMap.mpr ⟨q, hq, by simp [hk]⟩) A B (hA1 q hq kb hk) hA2 hA3 hB nc r hr
  refine ⟨?_, ?_⟩
  · intro h hh'
    obtain ⟨r, hr, hrh⟩ := List.mem_filterMap.mp hh'
    obtain ⟨q, hq, hpq⟩ := g1_mapM_mem _ _ _ hh r hr
    cases hk : keyBytes q with
    | none =>
      simp [probe, hk] at hpq; subst hpq; simp at hrh
    | some kb =>
      have e := hpr q hq kb hk r hpq
      subst e
      obtain rfl : c3T H u s q (pathOf H kb) = h := Option.some.inj hrh
      exact ⟨kb, by rw [c3T_key]; exact hk, by rw [c3T_key]⟩
  · intro q hq kb hk
    obtain ⟨r, hr, hpq⟩ := c3_mapM_all _ _ _ hh q hq
    have e := hpr q hq kb hk r hpq
    subst e
    exact List.mem_filterMap.mpr ⟨_, hr, rfl⟩

private theorem c3_findHit {H : Bytes → Bytes} {rs us : List Line} {hr hu : List Hit}
    (hr1 : ∀ h ∈ hr, ∃ kb, keyBytes h.key = some kb ∧ h = c3T H false rs h.key (pathOf H kb))
    (hu1 : ∀ h ∈ hu, ∃ kb, keyBytes h.key = some kb ∧ h = c3T H true us h.key (pathOf H kb))
    (u : Bool) (q : Key) :
    (keyBytes q = none → findHit (hr ++ hu) u q = none) ∧
    (∀ kb, keyBytes q = some kb → c3T H u (if u then us else rs) q (pathOf H kb) ∈ hr ++ hu →
      findHit (hr ++ hu) u q = some (c3T H u (if u then us else rs) q (pathOf H kb))) := by
  have hall : ∀ h ∈ hr ++ hu, ∃ kb, keyBytes h.key = some kb ∧
      h = c3T H h.unr (if h.unr then us else rs) h.key (pathOf H kb) := by
    intro h hh
    rcases List.mem_append.mp hh with hh | hh
    · obtain ⟨kb, hk, e⟩ := hr1 h hh
      have hu' : h.unr = false := by rw [e, c3T_unr]
      exact ⟨kb, hk, by rw [hu', if_neg (by decide)]; exact e⟩
    · obtain ⟨kb, hk, e⟩ := hu1 h hh
      have hu' : h.unr = true := by rw [e, c3T_unr]
      exact ⟨kb, hk, by rw [hu', if_pos rfl]; exact e⟩
  constructor
  · intro hk
    unfold findHit
    rw [List.find?_eq_none]
    intro h hh hp
    obtain ⟨kb, hk', -⟩ := hall h hh
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    rw [hp.2, hk] at hk'
    cases hk'
  · intro kb hk ht
    unfold findHit
    refine c3_find ht (by simp [c3T_unr, c3T_key]) ?_
    intro h hh hp
    obtain ⟨kb', hk', e⟩ := hall h hh
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    rw [hp.2, hk] at hk'
    cases hk'
    rw [e, hp.1, hp.2]

private theorem c3_flatMap_congr {α β : Type} {l : List α} {f g : α → List β} (h : ∀ x ∈ l, f x = g x) :
    l.flatMap f = l.flatMap g := by
  induction l with
  | nil => rfl
  | cons a l ih =>
    simp only [List.flatMap_cons]
    rw [h a (by simp), ih (fun x hx => h x (by simp [hx]))]

private theorem c3_hitsQ (H : Bytes → Bytes) (x : Ix) (rel unr : Snapshot Line) {mr mu : Map}
    (hmr : setMap H false rel.entries = some mr) (hmu : setMap H true unr.entries = some mu) (l : Line)
    (hF : ∀ u, ∀ q ∈ keys l, ∀ kb, keyBytes q = some kb →
      findHit x.hs u q = some (c3T H u (if u then unr.entries else rel.entries) q (pathOf H kb)))
    (hN : ∀ u q, keyBytes q = none → findHit x.hs u q = none) :
    x.hitsQ H l = trueHits H rel unr l := by
  unfold Ix.hitsQ trueHits
  apply c3_flatMap_congr
  intro q hq
  have h7 : q.head? ≠ some 7 := c3_rowKeys_head false l q (by simp [rowKeys, hq])
  have hf : ∀ u, ((findHit x.hs u q).map fun h => (u, h.path, h.n, frontierRoot H h.peaks)) =
      (keyBytes q).map fun kb => (u, pathOf H kb,
        ((postings u (if u then unr.entries else rel.entries) q).getD []).length,
        listRoot H ((postings u (if u then unr.entries else rel.entries) q).getD [])) := by
    intro u
    cases hk : keyBytes q with
    | none => rw [hN u q hk]; rfl
    | some kb =>
      rw [hF u q hq kb hk]
      have hlt : ((postings u (if u then unr.entries else rel.entries) q).getD []).length < 2 ^ 64 := by
        cases u
        · exact c3_postings_lt hmr q
        · exact c3_postings_lt hmu q
      unfold c3T
      rw [if_neg h7]
      dsimp only [Option.map]
      rw [listRoot_frontier H _ hlt]
  exact congrArg (fun F => List.filterMap F [false, true]) (funext hf)

private theorem c3_anchor (H : Bytes → Bytes) {g h : Head} {d : Bytes} (hg : digestV2 H g = some d)
    (hh : digestV2 H h = some d) (A B : List Bytes) (hA : ∀ y, headIn g = some y → y ∈ A)
    (hB : ∀ y, headIn h = some y → y ∈ B) (nc : ¬ Collision H A B) : g = h := by
  unfold digestV2 at hg hh
  cases hx : headIn g with
  | none => rw [hx] at hg; cases hg
  | some x =>
    cases hy : headIn h with
    | none => rw [hy] at hh; cases hh
    | some y =>
      rw [hx] at hg; rw [hy] at hh
      simp at hg hh
      by_cases e : x = y
      · subst e; exact c3_headIn_inj hx hy
      · exact absurd ⟨x, hA x hx, y, hB y hy, e, by rw [hg, hh]⟩ nc

private theorem c4_nodup_eraseDups {α : Type} [BEq α] [LawfulBEq α] :
    ∀ (n : Nat) (l : List α), l.length ≤ n → l.eraseDups.Nodup
  | _, [], _ => by simp
  | 0, _ :: _, h => by simp at h
  | n + 1, a :: as, h => by
    rw [List.eraseDups_cons, List.nodup_cons]
    refine ⟨?_, c4_nodup_eraseDups n _ (Nat.le_trans (List.length_filter_le _ _) (by simp at h; omega))⟩
    intro hm
    rw [List.mem_eraseDups, List.mem_filter] at hm
    simp at hm

private theorem c4_len_eq {α : Type} {A B : List α} (hA : A.Nodup) (hB : B.Nodup) (h : ∀ y, y ∈ A ↔ y ∈ B) :
    A.length = B.length :=
  ((List.perm_ext_iff_of_nodup hA hB).mpr h).length_eq

private theorem c4_rel_nodup {rel unr : Snapshot Line} (hi : Inv rel unr) : rel.entries.Nodup := by
  have h := hi.1
  rw [List.map_append, List.nodup_append] at h
  exact List.Pairwise.of_map (·.id) (fun a b hab e => hab (by rw [e])) h.1

private theorem c4_ownQ (x : Ix) (c₀ : Ctx) (rel unr : Snapshot Line) (hx : x.c₀ = c₀)
    (hR : ∀ l ∈ x.bb, x.inRel l = rel.entries.contains l) (l : Line) (hl : l ∈ x.bb) :
    x.ownQ l = own (carried c₀ rel unr) l := by
  unfold Ix.ownQ own
  rw [sv_released_carried, hR l hl, hx]
  rfl

private theorem c4_seen0Has (x : Ix) (c₀ : Ctx) (rel unr : Snapshot Line) (hi : Inv rel unr) (hx : x.c₀ = c₀)
    (hR : ∀ l ∈ x.bb, x.inRel l = rel.entries.contains l) (q : Key)
    (hq : x.cnt false q = (rel.entries.filter fun y => (rowKeys false y).contains q).length) :
    x.seen0Has q = (seen0 (carried c₀ rel unr) x.bb).contains q := by
  have hlen : ((x.bb.filter x.ownQ).eraseDups.filter fun y => (keys y).contains q).length =
      (rel.entries.filter fun y => c₀.redo.contains y.pay && x.bb.contains y && (keys y).contains q).length := by
    apply c4_len_eq (List.Pairwise.filter _ (c4_nodup_eraseDups _ _ (Nat.le_refl _)))
      (List.Pairwise.filter _ (c4_rel_nodup hi))
    intro y
    simp only [List.mem_filter, List.mem_eraseDups, Bool.and_eq_true]
    constructor
    · rintro ⟨⟨hb, ho⟩, hk⟩
      have ho' := ho
      unfold Ix.ownQ at ho'
      rw [hR y hb, hx, Bool.and_eq_true] at ho'
      exact ⟨List.contains_iff_mem.mp ho'.2, ⟨ho'.1, List.contains_iff_mem.mpr hb⟩, hk⟩
    · rintro ⟨hr, ⟨hp, hb⟩, hk⟩
      have hb' := List.contains_iff_mem.mp hb
      refine ⟨⟨hb', ?_⟩, hk⟩
      unfold Ix.ownQ
      rw [hR y hb', hx, hp, List.contains_iff_mem.mpr hr]
      rfl
  have hk : ∀ y : Line, rowKeys false y = keys y := by intro y; simp [rowKeys]
  rw [seen0_count, Ix.seen0Has, hq, hlen]
  simp only [hk]

private theorem c4_claim_mem (c : Ctx) (y : Line) (q : Key)
    (hq : q.head? = some 1 ∨ q.head? = some 2 ∨ q.head? = some 3 ∨ q.head? = some 4) :
    q ∈ claim c y ↔ q ∈ rowKeys true y := by
  cases q with
  | nil => simp at hq
  | cons a t =>
    simp only [List.head?_cons, Option.some.injEq] at hq
    by_cases hc : isCap y = true <;> by_cases hv : validDate y.date = true <;>
      simp only [claim, rowKeys, keys, exactKey, nearKey, idKey, dayKey, badDayKey, hc, hv] <;>
      (try split) <;> rcases hq with rfl | rfl | rfl | rfl <;> simp_all

private theorem c4_pend (c₀ : Ctx) (rel unr : Snapshot Line) (q : Key)
    (hq : q.head? = some 1 ∨ q.head? = some 2 ∨ q.head? = some 3 ∨ q.head? = some 4) :
    (pending (carried c₀ rel unr)).contains q =
      decide (0 < (unr.entries.filter fun y => (rowKeys true y).contains q).length) := by
  unfold pending
  rw [sv_unresolved_carried]
  apply Bool.eq_iff_iff.mpr
  rw [List.contains_iff_mem, decide_eq_true_iff, List.length_pos_iff_exists_mem, List.mem_flatMap]
  simp only [List.mem_filter, List.contains_iff_mem]
  constructor
  · rintro ⟨y, hy, hm⟩; exact ⟨y, hy, (c4_claim_mem _ y q hq).mp hm⟩
  · rintro ⟨y, hy, hm⟩; exact ⟨y, hy, (c4_claim_mem _ y q hq).mpr hm⟩

private theorem c4_monthDays_le (y m : Nat) : monthDays y m ≤ 31 := by
  unfold monthDays; split
  · split <;> omega
  · split <;> omega

private theorem c4_daysIn (d : Nat) (hv : validDate d = true) : d ∈ daysIn (d / 100) := by
  unfold daysIn
  rw [List.mem_filter, List.mem_map]
  refine ⟨⟨d % 100 - 1, ?_, ?_⟩, hv⟩
  · have := c4_monthDays_le (d / 10000) (d / 100 % 100)
    unfold validDate at hv
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hv
    rw [List.mem_range]; omega
  · unfold validDate at hv
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hv
    omega

private theorem c4_capProbe_mem (c₀ : Ctx) (m mo : Nat) (y : Line) :
    (∃ q ∈ capProbes c₀ m mo, q ∈ rowKeys true y) ↔
      (nearKey y = [0, m, mo] ∧
        (!usable c₀.today 7 okSpan c₀.enrollment || !validDate y.date || enrolled c₀ y) = true) := by
  by_cases hu : usable c₀.today 7 okSpan c₀.enrollment = true
  · have hp : capProbes c₀ m mo = [6, m, mo] :: ((entries c₀.enrollment).filter (·.member == m)).flatMap fun s =>
        ((daysIn mo).filter fun d => decide (s.start ≤ d) && decide (d ≤ s.stop)).map fun d => [5, m, mo, s.plan, d] := by
      simp [capProbes, hu]
    rw [hp, hu]
    constructor
    · rintro ⟨q, hq, hm⟩
      rw [List.mem_cons, List.mem_flatMap] at hq
      rcases hq with rfl | ⟨s, hs, hq⟩
      · by_cases hc : isCap y = true <;> by_cases hv : validDate y.date = true <;>
          simp [rowKeys, keys, exactKey, nearKey, idKey, dayKey, badDayKey, hc, hv] at hm ⊢
        exact ⟨hm.1.symm, hm.2.symm⟩
      · rw [List.mem_map] at hq
        obtain ⟨d, hd, rfl⟩ := hq
        rw [List.mem_filter] at hs hd
        by_cases hc : isCap y = true <;> by_cases hv : validDate y.date = true <;>
          simp [rowKeys, keys, exactKey, nearKey, idKey, dayKey, badDayKey, hc, hv] at hm ⊢
        obtain ⟨h1, h2, h3, h4⟩ := hm
        refine ⟨⟨h1.symm, h2.symm⟩, ?_⟩
        unfold enrolled
        rw [List.any_eq_true]
        refine ⟨s, hs.1, ?_⟩
        simp only [covers, hc, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq, Bool.not_true, Bool.false_or]
          at hs hd ⊢
        refine ⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩ <;> omega
    · rintro ⟨hn, ho⟩
      have hc : isCap y = true := by
        by_cases hc : isCap y = true
        · exact hc
        · simp [nearKey, hc] at hn
      simp only [nearKey, hc, if_true, List.cons.injEq] at hn
      obtain ⟨-, hm1, hm2, -⟩ := hn
      by_cases hv : validDate y.date = true
      · simp only [hv, Bool.not_true, Bool.false_or] at ho
        unfold enrolled at ho
        rw [List.any_eq_true] at ho
        obtain ⟨s, hs, hcov⟩ := ho
        simp only [covers, hc, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq, Bool.not_true,
          Bool.false_or] at hcov
        refine ⟨[5, m, mo, s.plan, y.date], ?_, ?_⟩
        · rw [List.mem_cons, List.mem_flatMap]
          refine Or.inr ⟨s, List.mem_filter.mpr ⟨hs, by simp [hcov.1.1.1, hm1]⟩, ?_⟩
          rw [List.mem_map]
          refine ⟨y.date, List.mem_filter.mpr ⟨by rw [← hm2]; exact c4_daysIn _ hv, ?_⟩, rfl⟩
          simp [hcov.1.1.2, hcov.1.2]
        · simp [rowKeys, keys, dayKey, hc, hv, hm1, hm2, hcov.2]
      · refine ⟨[6, m, mo], List.mem_cons_self, ?_⟩
        simp [rowKeys, keys, badDayKey, hc, hv, hm1, hm2]
  · have hp : capProbes c₀ m mo = [[0, m, mo]] := by simp [capProbes, hu]
    rw [hp]
    have hu' : usable c₀.today 7 okSpan c₀.enrollment = false := by simpa using hu
    rw [hu']
    simp only [List.mem_singleton, exists_eq_left, Bool.not_false, Bool.true_or, and_true]
    by_cases hc : isCap y = true <;> by_cases hv : validDate y.date = true <;>
      simp [rowKeys, keys, exactKey, nearKey, idKey, dayKey, badDayKey, hc, hv] <;>
      first | exact ⟨fun ⟨a, b⟩ => ⟨a.symm, b.symm⟩, fun ⟨a, b⟩ => ⟨a.symm, b.symm⟩⟩ | omega

private theorem c4_pend_cap (c₀ : Ctx) (rel unr : Snapshot Line) (hi : Inv rel unr) (m mo : Nat) :
    (pending (carried c₀ rel unr)).contains [0, m, mo] =
      (capProbes c₀ m mo).any fun q => decide (0 < (unr.entries.filter fun y => (rowKeys true y).contains q).length) := by
  rw [pending_near_cap c₀ rel unr hi]
  apply Bool.eq_iff_iff.mpr
  simp only [List.any_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq, List.length_pos_iff_exists_mem,
    List.mem_filter, List.contains_iff_mem]
  constructor
  · rintro ⟨y, hy, hn, ho⟩
    obtain ⟨q, hq, hm⟩ := (c4_capProbe_mem c₀ m mo y).mpr ⟨hn, ho⟩
    exact ⟨q, hq, y, hy, hm⟩
  · rintro ⟨q, hq, y, hy, hm⟩
    exact ⟨y, hy, (c4_capProbe_mem c₀ m mo y).mp ⟨q, hq, hm⟩⟩

private theorem c4_fires (x : Ix) (c₀ : Ctx) (rel unr : Snapshot Line) (hi : Inv rel unr) (hx : x.c₀ = c₀)
    (hrel : x.relOk = (validDate rel.asOf && decide (rel.asOf ≤ c₀.today)))
    (hunr : x.unrOk = (validDate unr.asOf && decide (unr.asOf ≤ c₀.today)))
    (seen : List Key) (l : Line)
    (hS : ∀ q ∈ keys l, x.seen0Has q = (seen0 (carried c₀ rel unr) x.bb).contains q)
    (hP : ∀ q ∈ keys l, x.pendQ q = (pending (carried c₀ rel unr)).contains q) (r : Reason) :
    x.firesQ seen l r = fires (carried c₀ rel unr) (seen ++ seen0 (carried c₀ rel unr) x.bb) l r := by
  have e1 := hS (idKey l) (by simp [keys])
  have e2 := hS (exactKey l) (by simp [keys])
  have e3 := hS (nearKey l) (by simp [keys])
  have p1 := hP (idKey l) (by simp [keys])
  have p2 := hP (exactKey l) (by simp [keys])
  have p3 := hP (nearKey l) (by simp [keys])
  have hl : looseKeys (carried c₀ rel unr) = [] := by simp [looseKeys, carried, carried_loose]
  have hcr : chained (carried c₀ rel unr).today (carried c₀ rel unr).releasedPrior
      (carried c₀ rel unr).released = (validDate rel.asOf && decide (rel.asOf ≤ c₀.today)) :=
    carried_chained c₀.today rel hi.2.1
  have hcu : chained (carried c₀ rel unr).today (carried c₀ rel unr).unresolvedPrior
      (carried c₀ rel unr).unresolved = (validDate unr.asOf && decide (unr.asOf ≤ c₀.today)) :=
    carried_chained c₀.today unr hi.2.2
  cases r <;> simp only [Ix.firesQ, fires, List.contains_append, e1, e2, e3, p1, p2, p3, hx, hl, hrel, hunr,
    hcr, hcu, List.contains_nil, Bool.and_false] <;> rfl

private theorem c4_claimQ (x : Ix) (c₀ : Ctx) (rel unr : Snapshot Line) (hx : x.c₀ = c₀)
    (hR : ∀ l ∈ x.bb, x.inRel l = rel.entries.contains l) (l : Line) (hl : l ∈ x.bb) :
    x.claimQ l = claim (carried c₀ rel unr) l := by
  unfold Ix.claimQ claim
  rw [c4_ownQ x c₀ rel unr hx hR l hl, hx]
  rfl

private theorem c4_decideAllQ (H : Bytes → Bytes) (x : Ix) (c₀ : Ctx) (rel unr : Snapshot Line) (hi : Inv rel unr)
    (hx : x.c₀ = c₀) (hrel : x.relOk = (validDate rel.asOf && decide (rel.asOf ≤ c₀.today)))
    (hunr : x.unrOk = (validDate unr.asOf && decide (unr.asOf ≤ c₀.today)))
    (hR : ∀ l ∈ x.bb, x.inRel l = rel.entries.contains l)
    (hS : ∀ l ∈ x.bb, ∀ q ∈ keys l, x.seen0Has q = (seen0 (carried c₀ rel unr) x.bb).contains q)
    (hP : ∀ l ∈ x.bb, ∀ q ∈ keys l, x.pendQ q = (pending (carried c₀ rel unr)).contains q) :
    ∀ (seen : List Key) (ls : List Line), (∀ l ∈ ls, l ∈ x.bb) →
      (Ix.decideAllQ H x seen ls).map (fun d => (d.line, d.outcome, d.reasons)) =
        (decideAll (carried c₀ rel unr) (seen ++ seen0 (carried c₀ rel unr) x.bb) ls).map
          (fun d => (d.line, d.outcome, d.reasons))
  | _, [], _ => rfl
  | seen, l :: ls, h => by
    have hl := h l (by simp)
    have hf : x.firesQ seen l = fires (carried c₀ rel unr) (seen ++ seen0 (carried c₀ rel unr) x.bb) l :=
      funext (c4_fires x c₀ rel unr hi hx hrel hunr seen l (hS l hl) (hP l hl))
    have hcq := c4_claimQ x c₀ rel unr hx hR l hl
    have ih := c4_decideAllQ H x c₀ rel unr hi hx hrel hunr hR hS hP (x.claimQ l ++ seen) ls
      (fun l' hl' => h l' (by simp [hl']))
    rw [hcq, List.append_assoc] at ih
    simp only [Ix.decideAllQ, decideAll, decideLine, List.map_cons, hf, hcq, ih]

private theorem c4_orderQ (x : Ix) (c₀ : Ctx) (rel unr : Snapshot Line) (hx : x.c₀ = c₀)
    (hR : ∀ l ∈ x.bb, x.inRel l = rel.entries.contains l) :
    x.orderQ x.bb = order (carried c₀ rel unr) x.bb := by
  unfold Ix.orderQ order
  have h1 : x.bb.filter x.ownQ = x.bb.filter (own (carried c₀ rel unr)) :=
    List.filter_congr (fun y hy => c4_ownQ x c₀ rel unr hx hR y hy)
  have h2 : (x.bb.filter fun y => !x.ownQ y) = x.bb.filter (fun y => !own (carried c₀ rel unr) y) :=
    List.filter_congr (fun y hy => by rw [c4_ownQ x c₀ rel unr hx hR y hy])
  rw [h1, h2]

private theorem c4_decisions (H : Bytes → Bytes) (x : Ix) (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line)
    (rel unr : Snapshot Line) (hi : Inv rel unr) (hx : x.c₀ = c₀) (hbb : x.bb = ready k os b)
    (hrel : x.relOk = (validDate rel.asOf && decide (rel.asOf ≤ c₀.today)))
    (hunr : x.unrOk = (validDate unr.asOf && decide (unr.asOf ≤ c₀.today)))
    (hR : ∀ l ∈ x.bb, x.inRel l = rel.entries.contains l)
    (hS : ∀ l ∈ x.bb, ∀ q ∈ keys l, x.seen0Has q = (seen0 (carried c₀ rel unr) x.bb).contains q)
    (hP : ∀ l ∈ x.bb, ∀ q ∈ keys l, x.pendQ q = (pending (carried c₀ rel unr)).contains q) :
    (Ix.decideAllQ H x (idSeen (foreignOf k os x.bb)) (x.orderQ x.bb)).map (fun d => (d.line, d.outcome, d.reasons)) =
      (decideRegT (carried c₀ rel unr) k os b).decisions.map (fun d => (d.line, d.outcome, d.reasons)) := by
  show _ = (decideAll (carried c₀ rel unr) (idSeen (foreignOf k os (ready k os b)) ++
    seen0 (carried c₀ rel unr) (ready k os b)) (order (carried c₀ rel unr) (ready k os b))).map _
  rw [← hbb, c4_orderQ x c₀ rel unr hx hR]
  refine c4_decideAllQ H x c₀ rel unr hi hx hrel hunr hR hS hP _ _ ?_
  intro l hl
  unfold order canonical at hl
  rcases List.mem_append.mp hl with h | h
  · exact (List.mem_filter.mp ((List.mergeSort_perm _ _).mem_iff.mp h)).1
  · exact (List.mem_filter.mp ((List.mergeSort_perm _ _).mem_iff.mp h)).1

private theorem c4_cnt {H : Bytes → Bytes} {x : Ix} {u : Bool} {s : List Line} {m : Map}
    (hm : setMap H u s = some m) {q : Key} (h7 : q.head? ≠ some 7)
    (hF : ∀ kb, keyBytes q = some kb → findHit x.hs u q = some (c3T H u s q (pathOf H kb)))
    (hN : keyBytes q = none → findHit x.hs u q = none) :
    x.cnt u q = (s.filter fun y => (rowKeys u y).contains q).length := by
  unfold Ix.cnt
  cases hk : keyBytes q with
  | none =>
    rw [hN hk]
    have e : s.filter (fun y => (rowKeys u y).contains q) = [] := List.filter_eq_nil_iff.mpr fun y hy hc => by
      obtain ⟨kb, -, hkb, -⟩ := (c3_setMap_mem hm).2.2.1 q (List.mem_flatMap.mpr ⟨y, hy, List.contains_iff_mem.mp hc⟩)
      rw [hk] at hkb; cases hkb
    rw [e]; rfl
  | some kb =>
    rw [hF kb hk]
    exact c3T_n hm h7 _

private theorem c4_inRel {H : Bytes → Bytes} {x : Ix} {s : List Line} (l : Line) (kb : Bytes)
    (hk : keyBytes (rowKey l) = some kb)
    (hF : findHit x.hs false (rowKey l) = some (c3T H false s (rowKey l) (pathOf H kb))) :
    x.inRel l = s.contains l := by
  have e : (s.any fun y => rowKey y == rowKey l) = s.contains l := by
    apply Bool.eq_iff_iff.mpr
    rw [List.any_eq_true, List.contains_iff_mem]
    constructor
    · rintro ⟨y, hy, he⟩
      have e' : rowKey y = rowKey l := beq_iff_eq.mp he
      have hyl : y = l := rowKey_inj (by rw [e']; exact hk) hk
      rw [hyl] at hy
      exact hy
    · intro hl; exact ⟨l, hl, beq_self_eq_true _⟩
  unfold Ix.inRel Ix.cnt
  rw [hF]
  have h7 : (rowKey l).head? = some 7 := rfl
  unfold c3T
  rw [if_pos h7]
  dsimp only [Option.map, Option.getD]
  rw [e]
  cases s.contains l <;> rfl

private theorem c4_pendQ (x : Ix) (q : Key) (h0 : q.head? ≠ some 0) : x.pendQ q = decide (0 < x.cnt true q) := by
  unfold Ix.pendQ
  split
  · simp at h0
  · rfl

private theorem c4_capProbes_head {c₀ : Ctx} {m mo : Nat} {q : Key} (h : q ∈ capProbes c₀ m mo) :
    q.head? ≠ some 7 := by
  unfold capProbes at h
  split at h
  · simp at h; subst h; simp
  · simp only [List.mem_cons, List.mem_flatMap, List.mem_map] at h
    rcases h with rfl | ⟨_, _, _, _, rfl⟩ <;> simp

/-- The index reads of `decideIdx` agree with the spec once every probed key's hit is the true hit. -/
private theorem c4_hyps {H : Bytes → Bytes} (x : Ix) (c₀ : Ctx) (rel unr : Snapshot Line) (hi : Inv rel unr)
    {mr mu : Map} (hmr : setMap H false rel.entries = some mr) (hmu : setMap H true unr.entries = some mu)
    (hx : x.c₀ = c₀)
    (hF : ∀ (u : Bool) (q : Key) kb, keyBytes q = some kb → (∃ l ∈ x.bb, q ∈ keys l ∨ q = rowKey l ∨
        (u = true ∧ isCap l = true ∧ q ∈ capProbes c₀ l.member (l.date / 100))) →
      findHit x.hs u q = some (c3T H u (if u then unr.entries else rel.entries) q (pathOf H kb)))
    (hN : ∀ u q, keyBytes q = none → findHit x.hs u q = none)
    (hK : ∀ l ∈ x.bb, (keyBytes (rowKey l)).isSome = true) :
    (∀ l ∈ x.bb, x.inRel l = rel.entries.contains l) ∧
    (∀ l ∈ x.bb, ∀ q ∈ keys l, x.seen0Has q = (seen0 (carried c₀ rel unr) x.bb).contains q) ∧
    (∀ l ∈ x.bb, ∀ q ∈ keys l, x.pendQ q = (pending (carried c₀ rel unr)).contains q) := by
  have hR : ∀ l ∈ x.bb, x.inRel l = rel.entries.contains l := by
    intro l hl
    obtain ⟨kb, hk⟩ := Option.isSome_iff_exists.mp (hK l hl)
    exact c4_inRel (s := rel.entries) l kb hk (hF false _ kb hk ⟨l, hl, Or.inr (Or.inl rfl)⟩)
  have h7 : ∀ l (q : Key), q ∈ keys l → q.head? ≠ some 7 := by
    intro l q hq
    simp only [keys, List.mem_cons, List.mem_nil_iff, or_false] at hq
    rcases hq with rfl | rfl | rfl <;> by_cases hc : isCap l = true <;> simp [exactKey, nearKey, idKey, hc]
  have cntU : ∀ l ∈ x.bb, ∀ q : Key, q.head? ≠ some 7 →
      (q ∈ keys l ∨ (isCap l = true ∧ q ∈ capProbes c₀ l.member (l.date / 100))) →
      x.cnt true q = (unr.entries.filter fun y => (rowKeys true y).contains q).length := by
    intro l hl q hq7 hq
    refine c4_cnt hmu hq7 (fun kb hk => hF true q kb hk ⟨l, hl, ?_⟩) (hN true q)
    rcases hq with hq | hq
    · exact Or.inl hq
    · exact Or.inr (Or.inr ⟨rfl, hq⟩)
  refine ⟨hR, ?_, ?_⟩
  · intro l hl q hq
    exact c4_seen0Has x c₀ rel unr hi hx hR q
      (c4_cnt hmr (h7 l q hq) (fun kb hk => hF false q kb hk ⟨l, hl, Or.inl hq⟩) (hN false q))
  · intro l hl q hq
    have e14 : (q.head? = some 1 ∨ q.head? = some 2 ∨ q.head? = some 3 ∨ q.head? = some 4) →
        x.pendQ q = (pending (carried c₀ rel unr)).contains q := fun h => by
      rw [c4_pendQ x q (by rcases h with h | h | h | h <;> simp [h]), c4_pend c₀ rel unr q h,
        cntU l hl q (h7 l q hq) (Or.inl hq)]
    simp only [keys, List.mem_cons, List.mem_nil_iff, or_false] at hq
    rcases hq with rfl | rfl | rfl
    · apply e14; by_cases hc : isCap l = true <;> simp [exactKey, hc]
    · by_cases hc : isCap l = true
      · have hn : nearKey l = [0, l.member, l.date / 100] := by simp [nearKey, hc]
        have ec : ∀ q' ∈ capProbes c₀ l.member (l.date / 100),
            x.cnt true q' = (unr.entries.filter fun y => (rowKeys true y).contains q').length :=
          fun q' hq' => cntU l hl q' (c4_capProbes_head hq') (Or.inr ⟨hc, hq'⟩)
        rw [hn, c4_pend_cap c₀ rel unr hi]
        show ((capProbes x.c₀ _ _).any fun q => decide (0 < x.cnt true q)) = _
        rw [hx]
        apply Bool.eq_iff_iff.mpr
        simp only [List.any_eq_true]
        constructor
        · rintro ⟨q', hq', h'⟩; exact ⟨q', hq', by rw [← ec q' hq']; exact h'⟩
        · rintro ⟨q', hq', h'⟩; exact ⟨q', hq', by rw [ec q' hq']; exact h'⟩
      · apply e14; simp [nearKey, hc]
    · apply e14; simp [idKey]

private theorem c5_guard {p : Prop} [Decidable p] {u : Unit} (h : (guard p : Option Unit) = some u) : p := by
  by_cases hp : p
  · exact hp
  rw [guard, if_neg hp] at h
  cases h

private theorem c5_headOf {H : Bytes → Bytes} {rel unr : Snapshot Line} {h : Head} (ha : headOf H rel unr = some h) :
    ∃ mr mu, setMap H false rel.entries = some mr ∧ setMap H true unr.entries = some mu ∧
      h = ⟨rel.asOf, unr.asOf, rel.count, unr.count, root H mr, root H mu⟩ := by
  unfold headOf at ha
  cases hmr : setMap H false rel.entries with
  | none => simp only [hmr, bind, Option.bind] at ha; cases ha
  | some mr =>
    cases hmu : setMap H true unr.entries with
    | none => simp only [hmr, hmu, bind, Option.bind] at ha; cases ha
    | some mu =>
      simp only [hmr, hmu, bind, Option.bind, pure] at ha
      exact ⟨mr, mu, rfl, rfl, (Option.some.inj ha).symm⟩

private theorem c5_wIn (H : Bytes → Bytes) (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (w : Witness) :
    witnessInputs H c₀ k os b w = (headIn w.anchor).toList ++
      ((probeKeys c₀ k os (ready k os b)).1 ++ (probeKeys c₀ k os (ready k os b)).2).filterMap
        (fun q => (keyBytes q).map (KD ++ ·)) ++ pfInputs H w.relPf ++ pfInputs H w.unrPf ++
      w.lists.flatMap fun (_, _, n, ys, fp) => firstKInputs H n ys fp := rfl

/-- `batchFresh` of a carried-style result is the batch's released and unresolved lines. -/
private theorem c5_fresh_spec (c : Ctx) (k : Nat) (os : List Owner) (b : List Line) :
    batchFresh c (decideRegT c k os b) =
      (releasedLines c (decideRegT c k os b).decisions, unresolvedLines c (decideRegT c k os b).decisions) := by
  simp [batchFresh, decideRegT, bumpRes, decideReg, decideBatchIn, advance, releasedSet, unresolvedSet]

/-- `decideIdx` peeled: every guard it passed and every value it bound. -/
private theorem c5_peel (H : Bytes → Bytes) (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (d : Bytes)
    (w : Witness) (o : OutV2) (hr : decideIdx H c₀ k os b d w = some o) :
    ∃ (hr' hu' : List (Option Hit)) (wr wu : Map) (x : Ix),
      digestV2 H w.anchor = some d ∧ (∀ l ∈ ready k os b, (keyBytes (rowKey l)).isSome = true) ∧
      verifyMulti H w.anchor.relRoot
        ((probeKeys c₀ k os (ready k os b)).1.filterMap fun q => (keyBytes q).map (pathOf H)) w.relPf = true ∧
      verifyMulti H w.anchor.unrRoot
        ((probeKeys c₀ k os (ready k os b)).2.filterMap fun q => (keyBytes q).map (pathOf H)) w.unrPf = true ∧
      (probeKeys c₀ k os (ready k os b)).1.mapM (probe H w.relPf w false) = some hr' ∧
      (probeKeys c₀ k os (ready k os b)).2.mapM (probe H w.unrPf w true) = some hu' ∧
      x.c₀ = c₀ ∧ x.hs = hr'.filterMap id ++ hu'.filterMap id ∧
      x.relOk = (validDate w.anchor.relAsOf && decide (w.anchor.relAsOf ≤ c₀.today)) ∧
      x.unrOk = (validDate w.anchor.unrAsOf && decide (w.anchor.unrAsOf ≤ c₀.today)) ∧
      x.bb = ready k os b ∧
      o.decisions = Ix.decideAllQ H x (idSeen (foreignOf k os x.bb)) (x.orderQ x.bb) ∧
      o.fresh = (x.releasedQ o.decisions, x.unresolvedQ o.decisions) ∧
      writes H false x.hs w.anchor.relCount o.fresh.1 = some wr ∧
      writes H true x.hs w.anchor.unrCount o.fresh.2 = some wu ∧
      o.head = ⟨bumpIf x.relOk c₀.today w.anchor.relAsOf, bumpIf x.unrOk c₀.today w.anchor.unrAsOf,
        w.anchor.relCount + o.fresh.1.length, w.anchor.unrCount + o.fresh.2.length,
        hashPf H (upsertPf 513 0 w.relPf wr), hashPf H (upsertPf 513 0 w.unrPf wu)⟩ ∧
      digestV2 H o.head = some o.digest ∧
      o.free = (pendingOf k os).filter (fun i => !((o.fresh.1 ++ o.fresh.2).map (·.id)).contains i &&
        x.cnt false [4, i] == 0 && x.cnt true [4, i] == 0) ∧
      o.pays = (o.decisions.map (·.line.pay)).eraseDups.map fun p =>
        (p, x.payOutcomeQ o.decisions p, ((o.decisions.filter (·.line.pay == p)).map (·.line.cents)).sum) := by
  unfold decideIdx at hr
  simp only [bind, Option.bind] at hr
  split at hr
  · cases hr
  rename_i _ g1
  replace g1 := c5_guard g1
  split at hr
  · cases hr
  rename_i _ g2
  replace g2 := c5_guard g2
  rw [List.all_eq_true] at g2
  generalize hq : probeKeys c₀ k os (ready k os b) = qq at hr ⊢
  obtain ⟨qr, qu⟩ := qq
  dsimp only at hr ⊢
  split at hr
  · cases hr
  rename_i _ g3
  replace g3 := c5_guard g3
  rw [Bool.and_eq_true] at g3
  dsimp only at hr
  split at hr
  · cases hr
  rename_i hr' ghr
  dsimp only at hr
  split at hr
  · cases hr
  rename_i hu' ghu
  dsimp only at hr
  split at hr
  · cases hr
  rename_i wr gwr
  dsimp only at hr
  split at hr
  · cases hr
  rename_i wu gwu
  dsimp only at hr
  split at hr
  · cases hr
  rename_i dg gdg
  cases hr
  exact ⟨hr', hu', wr, wu, _, g1, g2, g3.1, g3.2, ghr, ghu, rfl, rfl, rfl, rfl, rfl, rfl, rfl, gwr, gwu, rfl, gdg,
    rfl, rfl⟩

/-- Without a collision every probed key's hit is the true hit, and unencodable keys have none. -/
private theorem c5_hits (H : Bytes → Bytes) (hH : HashLen H) (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line)
    (rel unr : Snapshot Line) {mr mu : Map} (hmr : setMap H false rel.entries = some mr)
    (hmu : setMap H true unr.entries = some mu) (w : Witness)
    (hv1 : verifyMulti H (root H mr)
      ((probeKeys c₀ k os (ready k os b)).1.filterMap fun q => (keyBytes q).map (pathOf H)) w.relPf = true)
    (hv2 : verifyMulti H (root H mu)
      ((probeKeys c₀ k os (ready k os b)).2.filterMap fun q => (keyBytes q).map (pathOf H)) w.unrPf = true)
    {hr' hu' : List (Option Hit)}
    (ghr : (probeKeys c₀ k os (ready k os b)).1.mapM (probe H w.relPf w false) = some hr')
    (ghu : (probeKeys c₀ k os (ready k os b)).2.mapM (probe H w.unrPf w true) = some hu')
    (nc : ¬ Collision H (witnessInputs H c₀ k os b w) (stateInputs H rel unr)) :
    (∀ (u : Bool) (q : Key) kb, keyBytes q = some kb →
      q ∈ (if u then (probeKeys c₀ k os (ready k os b)).2 else (probeKeys c₀ k os (ready k os b)).1) →
      findHit (hr'.filterMap id ++ hu'.filterMap id) u q =
        some (c3T H u (if u then unr.entries else rel.entries) q (pathOf H kb))) ∧
    (∀ u q, keyBytes q = none → findHit (hr'.filterMap id ++ hu'.filterMap id) u q = none) := by
  have hA1 : ∀ q ∈ (probeKeys c₀ k os (ready k os b)).1 ++ (probeKeys c₀ k os (ready k os b)).2, ∀ kb,
      keyBytes q = some kb → KD ++ kb ∈ witnessInputs H c₀ k os b w := fun q hq kb hk => by
    rw [c5_wIn, List.mem_append, List.mem_append, List.mem_append, List.mem_append]
    exact Or.inl (Or.inl (Or.inl (Or.inr (List.mem_filterMap.mpr ⟨q, hq, by rw [hk]; rfl⟩))))
  have hA2r : ∀ y ∈ pfInputs H w.relPf, y ∈ witnessInputs H c₀ k os b w := fun y hy => by
    rw [c5_wIn, List.mem_append, List.mem_append, List.mem_append]
    exact Or.inl (Or.inl (Or.inr hy))
  have hA2u : ∀ y ∈ pfInputs H w.unrPf, y ∈ witnessInputs H c₀ k os b w := fun y hy => by
    rw [c5_wIn, List.mem_append, List.mem_append]
    exact Or.inl (Or.inr hy)
  have hA3 : ∀ y ∈ w.lists.flatMap (fun (_, _, n, ys, fp) => firstKInputs H n ys fp),
      y ∈ witnessInputs H c₀ k os b w := fun y hy => by
    rw [c5_wIn, List.mem_append]
    exact Or.inr hy
  have hBr : ∀ y ∈ setInputs H false rel.entries, y ∈ stateInputs H rel unr := fun y hy => by
    unfold stateInputs
    rw [List.mem_append, List.mem_append]
    exact Or.inl (Or.inr hy)
  have hBu : ∀ y ∈ setInputs H true unr.entries, y ∈ stateInputs H rel unr := fun y hy => by
    unfold stateInputs
    rw [List.mem_append]
    exact Or.inr hy
  have P1 := c3_probes H hH false rel.entries mr hmr w.relPf w _ hv1 _ _
    (fun q hq => hA1 q (List.mem_append_left _ hq)) hA2r hA3 hBr nc hr' ghr
  have P2 := c3_probes H hH true unr.entries mu hmu w.unrPf w _ hv2 _ _
    (fun q hq => hA1 q (List.mem_append_right _ hq)) hA2u hA3 hBu nc hu' ghu
  have F := c3_findHit P1.1 P2.1
  refine ⟨fun u q kb hk hq => ?_, fun u q hk => (F u q).1 hk⟩
  cases u
  · exact (F false q).2 kb hk (List.mem_append_left _ (P1.2 q hq kb hk))
  · exact (F true q).2 kb hk (List.mem_append_right _ (P2.2 q hq kb hk))

private theorem c7_probe_mem (c₀ : Ctx) (k : Nat) (os : List Owner) (bb : List Line) (u : Bool) (q : Key)
    (h : (∃ l ∈ bb, q ∈ keys l ∨ q = rowKey l ∨
      (u = true ∧ isCap l = true ∧ q ∈ capProbes c₀ l.member (l.date / 100))) ∨ ∃ i ∈ pendingOf k os, q = [4, i]) :
    q ∈ (if u then (probeKeys c₀ k os bb).2 else (probeKeys c₀ k os bb).1) := by
  rcases h with ⟨l, hl, hq⟩ | ⟨i, hi, rfl⟩
  · cases u
    · refine List.mem_eraseDups.mpr (List.mem_append_left _ (List.mem_flatMap.mpr ⟨l, hl, ?_⟩))
      rcases hq with hq | rfl | ⟨h, -⟩
      · exact List.mem_append_left _ hq
      · exact List.mem_append_right _ (List.mem_singleton_self _)
      · cases h
    · refine List.mem_eraseDups.mpr (List.mem_append_left _ (List.mem_flatMap.mpr ⟨l, hl, ?_⟩))
      rcases hq with hq | rfl | ⟨-, hc, hq⟩
      · exact List.mem_append_left _ (List.mem_append_left _ (List.mem_append_left _ hq))
      · exact List.mem_append_left _ (List.mem_append_right _ (List.mem_singleton_self _))
      · exact List.mem_append_right _ (by simpa [hc] using hq)
  · cases u <;> exact List.mem_eraseDups.mpr (List.mem_append_right _ (List.mem_map.mpr ⟨i, hi, rfl⟩))

private theorem c7_lines (H : Bytes → Bytes) (x : Ix) : ∀ (seen : List Key) (ls : List Line),
    (Ix.decideAllQ H x seen ls).map (·.line) = ls ∧ (Ix.decideAllQ H x seen ls).map (·.hits) = ls.map (x.hitsQ H)
  | _, [] => ⟨rfl, rfl⟩
  | _, l :: ls => ⟨congrArg (l :: ·) (c7_lines H x _ ls).1, congrArg (x.hitsQ H l :: ·) (c7_lines H x _ ls).2⟩

private theorem c7_ord (x : Ix) {bb : List Line} {l : Line} (h : l ∈ x.orderQ bb) : l ∈ bb := by
  unfold Ix.orderQ canonical at h
  rcases List.mem_append.mp h with h | h <;> exact (List.mem_filter.mp ((List.mergeSort_perm _ _).mem_iff.mp h)).1

private theorem c7_all {α : Type} : ∀ {L : List α} {p q : α → Bool}, (∀ a ∈ L, p a = q a) → L.all p = L.all q
  | [], _, _, _ => rfl
  | a :: L, _, _, h => by
    rw [List.all_cons, List.all_cons, h a (by simp), c7_all fun b hb => h b (by simp [hb])]

/-- Payment outcomes, released and unresolved lines read only line, outcome, reasons and `own` of the lines. -/
private theorem c7_sel (x : Ix) (c : Ctx) (dsI : List DecisionV2) (dsS : List Decision)
    (hT : dsI.map (fun d => (d.line, d.outcome, d.reasons)) = dsS.map (fun d => (d.line, d.outcome, d.reasons)))
    (hO : ∀ d ∈ dsI, x.ownQ d.line = own c d.line) (hr : x.c₀.redo = c.redo) :
    (∀ p, x.payOutcomeQ dsI p = payOutcome c dsS p) ∧ x.releasedQ dsI = releasedLines c dsS ∧
      x.unresolvedQ dsI = unresolvedLines c dsS := by
  have hM : dsI.map (fun d => ({ line := d.line, outcome := d.outcome, reasons := d.reasons, counterparts := [] } : Decision)) =
      dsS.map (fun d => ({ line := d.line, outcome := d.outcome, reasons := d.reasons, counterparts := [] } : Decision)) := by
    have := congrArg (List.map fun t : Line × Outcome × List Reason =>
      ({ line := t.1, outcome := t.2.1, reasons := t.2.2, counterparts := [] } : Decision)) hT
    simpa only [List.map_map, Function.comp_def] using this
  have hPS : ∀ (L : List Decision) p, payOutcome c (L.map fun d =>
      ({ line := d.line, outcome := d.outcome, reasons := d.reasons, counterparts := [] } : Decision)) p = payOutcome c L p := by
    intro L p
    simp only [payOutcome, List.filter_map, List.any_map, List.isEmpty_map, List.all_map, Function.comp_def]
  have hP : ∀ p, x.payOutcomeQ dsI p = payOutcome c dsS p := by
    intro p
    have ha : ((dsI.filter (·.line.pay == p)).all fun d => d.outcome == .ALLOW && (!x.c₀.redo.contains p || x.ownQ d.line)) =
        ((dsI.filter (·.line.pay == p)).all fun d => d.outcome == .ALLOW && (!c.redo.contains p || own c d.line)) :=
      c7_all fun d hd => by rw [hr, hO d (List.mem_filter.mp hd).1]
    rw [← hPS, ← hM]
    dsimp only [Ix.payOutcomeQ, payOutcome]
    rw [ha]
    simp only [List.filter_map, List.any_map, List.isEmpty_map, List.all_map, Function.comp_def]
  refine ⟨hP, ?_, ?_⟩
  · have hal : (dsI.filter (·.outcome == .ALLOW)).map (·.line) = allowedLines dsS := by
      have := congrArg allowedLines hM
      simpa only [allowedLines, List.filter_map, List.map_map, Function.comp_def] using this
    simp only [Ix.releasedQ, releasedLines, hP, hr, hal]
  · have e := List.filter_congr (l := dsI)
      (p := fun d : DecisionV2 => d.outcome != .ALLOW && !d.reasons.contains .ALREADY_DECIDED && !x.ownQ d.line)
      (q := fun d => d.outcome != .ALLOW && !d.reasons.contains .ALREADY_DECIDED && !own c d.line)
      fun d hd => by rw [hO d hd]
    unfold Ix.unresolvedQ unresolvedLines
    rw [e]
    have := congrArg (fun L : List Decision =>
      (L.filter fun d => d.outcome != .ALLOW && !d.reasons.contains .ALREADY_DECIDED && !own c d.line).map (·.line)) hM
    simpa only [List.filter_map, List.map_map, Function.comp_def] using this

/-- Without a collision: the anchor is the state's head, every probed hit is the true hit, and the decisions,
    payment outcomes and fresh rows are the spec's. -/
private theorem c7_core (H : Bytes → Bytes) (hH : HashLen H) (c₀ : Ctx) (k : Nat) (os : List Owner)
    (b : List Line) (rel unr : Snapshot Line) (hi : Inv rel unr) (h : Head) (ha : headOf H rel unr = some h)
    (d : Bytes) (hd : digestV2 H h = some d) (w : Witness) (o : OutV2) (hr : decideIdx H c₀ k os b d w = some o)
    (nc : ¬ Collision H (witnessInputs H c₀ k os b w) (stateInputs H rel unr)) :
    ∃ (x : Ix) (mr mu wr wu : Map), setMap H false rel.entries = some mr ∧ setMap H true unr.entries = some mu ∧
      verifyMulti H (root H mr)
        ((probeKeys c₀ k os (ready k os b)).1.filterMap fun q => (keyBytes q).map (pathOf H)) w.relPf = true ∧
      verifyMulti H (root H mu)
        ((probeKeys c₀ k os (ready k os b)).2.filterMap fun q => (keyBytes q).map (pathOf H)) w.unrPf = true ∧
      w.anchor = ⟨rel.asOf, unr.asOf, rel.count, unr.count, root H mr, root H mu⟩ ∧ x.c₀ = c₀ ∧ x.bb = ready k os b ∧
      (∀ (u : Bool) (q : Key) kb, keyBytes q = some kb →
        ((∃ l ∈ x.bb, q ∈ keys l ∨ q = rowKey l ∨
          (u = true ∧ isCap l = true ∧ q ∈ capProbes c₀ l.member (l.date / 100))) ∨ ∃ i ∈ pendingOf k os, q = [4, i]) →
        findHit x.hs u q = some (c3T H u (if u then unr.entries else rel.entries) q (pathOf H kb))) ∧
      (∀ u q, keyBytes q = none → findHit x.hs u q = none) ∧
      o.decisions = Ix.decideAllQ H x (idSeen (foreignOf k os x.bb)) (x.orderQ x.bb) ∧
      o.decisions.map (fun d => (d.line, d.outcome, d.reasons)) =
        (decideRegT (carried c₀ rel unr) k os b).decisions.map (fun d => (d.line, d.outcome, d.reasons)) ∧
      o.pays = paysOf (carried c₀ rel unr) (decideRegT (carried c₀ rel unr) k os b).decisions ∧
      o.fresh = batchFresh (carried c₀ rel unr) (decideRegT (carried c₀ rel unr) k os b) ∧
      writes H false x.hs rel.count o.fresh.1 = some wr ∧ writes H true x.hs unr.count o.fresh.2 = some wu ∧
      o.head = ⟨bumpIf x.relOk c₀.today rel.asOf, bumpIf x.unrOk c₀.today unr.asOf,
        rel.count + o.fresh.1.length, unr.count + o.fresh.2.length,
        hashPf H (upsertPf 513 0 w.relPf wr), hashPf H (upsertPf 513 0 w.unrPf wu)⟩ ∧
      x.relOk = (validDate rel.asOf && decide (rel.asOf ≤ c₀.today)) ∧
      x.unrOk = (validDate unr.asOf && decide (unr.asOf ≤ c₀.today)) ∧
      digestV2 H o.head = some o.digest ∧
      o.free = (pendingOf k os).filter (fun i => !((o.fresh.1 ++ o.fresh.2).map (·.id)).contains i &&
        x.cnt false [4, i] == 0 && x.cnt true [4, i] == 0) ∧
      o.decisions.map (·.hits) = (decideRegT (carried c₀ rel unr) k os b).decisions.map (trueHits H rel unr ·.line) ∧
      (∀ (u : Bool) (q : Key) kb, keyBytes q = some kb →
        q ∈ (if u then (probeKeys c₀ k os (ready k os b)).2 else (probeKeys c₀ k os (ready k os b)).1) →
        findHit x.hs u q = some (c3T H u (if u then unr.entries else rel.entries) q (pathOf H kb))) := by
  obtain ⟨hr', hu', wr, wu, x, g1, gK, gv1, gv2, ghr, ghu, hxc, hxs, hxr, hxu, hxb, hD, hFr, hW1, hW2, hHd, hDg,
    hFree, hPays⟩ := c5_peel H c₀ k os b d w o hr
  obtain ⟨mr, mu, hmr, hmu, rfl⟩ := c5_headOf ha
  have hA : w.anchor = ⟨rel.asOf, unr.asOf, rel.count, unr.count, root H mr, root H mu⟩ :=
    c3_anchor H g1 hd (witnessInputs H c₀ k os b w) (stateInputs H rel unr)
      (fun y hy => by rw [c5_wIn]; simp [hy]) (fun y hy => by unfold stateInputs; simp [ha, hy]) nc
  simp only [hA] at gv1 gv2 hW1 hW2 hHd hxr hxu
  obtain ⟨hT, hN⟩ := c5_hits H hH c₀ k os b rel unr hmr hmu w gv1 gv2 ghr ghu nc
  rw [← hxs] at hT hN
  have hF : ∀ (u : Bool) (q : Key) kb, keyBytes q = some kb →
      ((∃ l ∈ x.bb, q ∈ keys l ∨ q = rowKey l ∨
        (u = true ∧ isCap l = true ∧ q ∈ capProbes c₀ l.member (l.date / 100))) ∨ ∃ i ∈ pendingOf k os, q = [4, i]) →
      findHit x.hs u q = some (c3T H u (if u then unr.entries else rel.entries) q (pathOf H kb)) :=
    fun u q kb hk hm => hT u q kb hk (c7_probe_mem c₀ k os _ u q (hxb ▸ hm))
  obtain ⟨hR, hS, hP⟩ := c4_hyps x c₀ rel unr hi hmr hmu hxc (fun u q kb hk hm => hF u q kb hk (Or.inl hm)) hN
    (fun l hl => gK l (hxb ▸ hl))
  have hDec : o.decisions.map (fun d => (d.line, d.outcome, d.reasons)) =
      (decideRegT (carried c₀ rel unr) k os b).decisions.map (fun d => (d.line, d.outcome, d.reasons)) := by
    rw [hD]; exact c4_decisions H x c₀ k os b rel unr hi hxc hxb hxr hxu hR hS hP
  have hQ := c7_lines H x (idSeen (foreignOf k os x.bb)) (x.orderQ x.bb)
  rw [← hD] at hQ
  have hO : ∀ d ∈ o.decisions, x.ownQ d.line = own (carried c₀ rel unr) d.line := fun d hd' =>
    c4_ownQ x c₀ rel unr hxc hR d.line (by
      have hm : d.line ∈ o.decisions.map (·.line) := List.mem_map_of_mem hd'
      rw [hQ.1] at hm
      exact c7_ord x hm)
  obtain ⟨hPay, hRel, hUnr⟩ := c7_sel x (carried c₀ rel unr) o.decisions _ hDec hO (by rw [hxc]; rfl)
  have hFresh : o.fresh = batchFresh (carried c₀ rel unr) (decideRegT (carried c₀ rel unr) k os b) := by
    rw [hFr, c5_fresh_spec, hRel, hUnr]
  have hL : o.decisions.map (·.line) = (decideRegT (carried c₀ rel unr) k os b).decisions.map (·.line) := by
    simpa only [List.map_map, Function.comp_def] using congrArg (List.map Prod.fst) hDec
  have hPs : o.pays = paysOf (carried c₀ rel unr) (decideRegT (carried c₀ rel unr) k os b).decisions := by
    have e1 : o.decisions.map (·.line.pay) = (decideRegT (carried c₀ rel unr) k os b).decisions.map (·.line.pay) := by
      simpa only [List.map_map, Function.comp_def] using congrArg (List.map (·.pay)) hL
    have e2 : ∀ p, (o.decisions.filter (·.line.pay == p)).map (·.line.cents) =
        ((decideRegT (carried c₀ rel unr) k os b).decisions.filter (·.line.pay == p)).map (·.line.cents) := fun p => by
      simpa only [List.filter_map, List.map_map, Function.comp_def] using
        congrArg (fun L : List Line => (L.filter (·.pay == p)).map (·.cents)) hL
    rw [hPays]; unfold paysOf; rw [e1]; simp only [hPay, e2]
  have hHit : o.decisions.map (·.hits) =
      (decideRegT (carried c₀ rel unr) k os b).decisions.map (trueHits H rel unr ·.line) := by
    have e : (decideRegT (carried c₀ rel unr) k os b).decisions.map (trueHits H rel unr ·.line) =
        (x.orderQ x.bb).map (trueHits H rel unr) := by
      simp only [← hQ.1, hL, List.map_map, Function.comp_def]
    rw [hQ.2, e]
    exact List.map_congr_left fun l hl => c3_hitsQ H x rel unr hmr hmu l
      (fun u q hq kb hk => hF u q kb hk (Or.inl ⟨l, c7_ord x hl, Or.inl hq⟩)) hN
  exact ⟨x, mr, mu, wr, wu, hmr, hmu, gv1, gv2, hA, hxc, hxb, hF, hN, hD, hDec, hPs, hFresh, hW1, hW2, hHd, hxr,
    hxu, hDg, hFree, hHit, hT⟩

/-- A write map is well formed when every hit it extends is a frontier fold from `[]` (as `c3T` gives). -/
private theorem c7_wok (H : Bytes → Bytes) (hH : HashLen H) (u : Bool) (hs : List Hit) (c0 : Nat) (xs : List Line)
    (wm : Map) (hP : ∀ q ∈ (xs.flatMap (rowKeys u)).eraseDups, ∀ h, findHit hs u q = some h →
      ∃ L : List Bytes, h.n = L.length ∧ h.peaks = L.foldl (frontierPush H) [])
    (h : writes H u hs c0 xs = some wm) : MapOk wm := by
  unfold writes at h
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
        cases hb : be 8 (c0 + i) with
        | none => simp [hk, hb] at hf
        | some v =>
          simp [hk, hb] at hf
          subst hf
          exact ⟨hH _, by simp [be_len hb]⟩
    · obtain ⟨q, hq, hf⟩ := g1_mapM_mem _ _ _ hks e he
      split at hf
      · simp at hf
      dsimp only at hf
      split at hf
      · simp at hf
      rename_i ht hh
      dsimp only at hf
      split at hf
      · simp at hf
      rename_i es _
      dsimp only at hf
      split at hf
      · simp at hf
      rename_i v hv
      simp at hf
      subst hf
      obtain ⟨L, hn, hpk⟩ := hP q hq ht hh
      rw [hn, hpk, ← List.foldl_append, ← List.length_append] at hv
      exact ⟨hH _, keyVal_len H hH (L ++ es) v hv⟩
  · simp [guard, hg] at h

/-- Every leaf a batch writes sits at the path of a new row's ROW key or of one of its index keys. -/
private theorem c8_writes_keys {H : Bytes → Bytes} {u : Bool} {hs : List Hit} {c0 : Nat} {xs : List Line}
    {wm : Map} (h : writes H u hs c0 xs = some wm) :
    ∀ e ∈ wm, ∃ q kb, ((∃ x ∈ xs, q = rowKey x) ∨ q ∈ xs.flatMap (rowKeys u)) ∧ keyBytes q = some kb ∧
      e.1 = pathOf H kb := by
  unfold writes at h
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
    intro e he
    rcases List.mem_append.mp he with he | he
    · obtain ⟨⟨x, i⟩, hx, hf⟩ := g1_mapM_mem _ _ _ hrows e he
      cases hk : keyBytes (rowKey x) with
      | none => simp [hk] at hf
      | some kb =>
        cases hb : be 8 (c0 + i) with
        | none => simp [hk, hb] at hf
        | some v =>
          simp [hk, hb] at hf
          subst hf
          exact ⟨rowKey x, kb, Or.inl ⟨x, c3_mem_zipIdx hx, rfl⟩, hk, rfl⟩
    · obtain ⟨q, hq, hf⟩ := g1_mapM_mem _ _ _ hks e he
      split at hf
      · simp at hf
      rename_i kb hk
      dsimp only at hf
      split at hf
      · simp at hf
      dsimp only at hf
      split at hf
      · simp at hf
      dsimp only at hf
      split at hf
      · simp at hf
      simp at hf
      subst hf
      exact ⟨q, kb, Or.inr (List.mem_eraseDups.mp hq), hk, rfl⟩
  · simp [guard, hg] at h

/-- H1: writes over verified probe paths update the old root, unless the proof collides with the tree. -/
private theorem c8_root (H : Bytes → Bytes) (hH : HashLen H) (u : Bool) (s : List Line) (m : Map)
    (hm : setMap H u s = some m) (hs : List Hit) (c0 : Nat) (f : List Line) (wm : Map)
    (hw : writes H u hs c0 f = some wm) (qs : List Key) (pf : Proof)
    (hv : verifyMulti H (root H m) (qs.filterMap fun q => (keyBytes q).map (pathOf H)) pf = true)
    (hq : ∀ x ∈ f, rowKey x ∈ qs ∧ ∀ q ∈ rowKeys u x, q ∈ qs)
    (hT : ∀ q kb, keyBytes q = some kb → q ∈ qs → findHit hs u q = some (c3T H u s q (pathOf H kb)))
    (hN : ∀ q, keyBytes q = none → findHit hs u q = none) :
    hashPf H (upsertPf 513 0 pf wm) = root H (upsert m wm) ∨
      Collision H (pfInputs H pf) (treeInputs H 513 0 m) := by
  have hP : ∀ q ∈ (f.flatMap (rowKeys u)).eraseDups, ∀ h, findHit hs u q = some h →
      ∃ L : List Bytes, h.n = L.length ∧ h.peaks = L.foldl (frontierPush H) [] := by
    intro q hq0 h hh
    obtain ⟨x, hx, hqx⟩ := List.mem_flatMap.mp (List.mem_eraseDups.mp hq0)
    cases hk : keyBytes q with
    | none => rw [hN q hk] at hh; cases hh
    | some kb =>
      rw [hT q kb hk ((hq x hx).2 q hqx)] at hh
      obtain rfl := Option.some.inj hh
      exact ⟨(postings u s q).getD [], by simp [c3T, c3_rowKeys_head u x q hqx],
        by simp [c3T, c3_rowKeys_head u x q hqx]⟩
  refine multi_update_sound H hH m wm (setMap_ok H hH u s m hm) (c7_wok H hH u hs c0 f wm hP hw) _ pf hv ?_
  intro e he
  obtain ⟨q, kb, hq', hk, he1⟩ := c8_writes_keys hw e he
  rw [he1]
  refine List.mem_filterMap.mpr ⟨q, ?_, by simp [hk]⟩
  rcases hq' with ⟨x, hx, rfl⟩ | hq'
  · exact (hq x hx).1
  · obtain ⟨x, hx, hqx⟩ := List.mem_flatMap.mp hq'
    exact (hq x hx).2 q hqx

private theorem c8_mapM_some {α β : Type} (F : α → Option β) :
    ∀ xs : List α, (∀ x ∈ xs, ∃ y, F x = some y) → ∃ ys, xs.mapM F = some ys
  | [], _ => ⟨[], by simp⟩
  | x :: xs, h => by
    obtain ⟨y, hy⟩ := h x (by simp)
    obtain ⟨ys, hys⟩ := c8_mapM_some F xs fun z hz => h z (by simp [hz])
    exact ⟨y :: ys, by simp [List.mapM_cons, hy, hys]⟩

/-- Index-blind filters commute with shifting `zipIdx` positions into the mapped function. -/
private theorem c8_shift {α β : Type} (Q Q' : α × Nat → Bool) (hQ : ∀ x i j, Q (x, i) = Q' (x, j))
    (F G : α × Nat → Option β) (n : Nat) (hFG : ∀ x j, G (x, j) = F (x, n + j)) :
    ∀ (l : List α) (k : Nat), ((l.zipIdx (n + k)).filter Q).mapM F = ((l.zipIdx k).filter Q').mapM G
  | [], _ => by simp
  | x :: l, k => by
    rw [List.zipIdx_cons, List.zipIdx_cons, List.filter_cons, List.filter_cons, hQ x (n + k) k,
      show n + k + 1 = n + (k + 1) by omega]
    have ih := c8_shift Q Q' hQ F G n hFG l (k + 1)
    split
    · simp only [List.mapM_cons, ih, hFG]
    · exact ih

/-- Postings over an appended set: the old postings, then the new rows' postings at shifted positions. -/
private theorem c8_postings_append (u : Bool) (s f : List Line) (q : Key) (P : Line × Nat → Bool)
    (hP : ∀ x j, P (x, j) = (rowKeys u x).contains q) (G : Line × Nat → Option Bytes)
    (hG : ∀ x j, G (x, j) = postEntry (s.length + j) x.id) :
    postings u (s ++ f) q = (do
      let a ← postings u s q
      let b ← (f.zipIdx.filter P).mapM G
      pure (a ++ b)) := by
  have e := c8_shift (fun (x, _) => (rowKeys u x).contains q) P (fun x i j => (hP x j).symm)
    (fun (x, i) => postEntry i x.id) G s.length hG f 0
  rw [Nat.add_zero] at e
  unfold postings
  rw [List.zipIdx_append, List.filter_append, List.mapM_append, Nat.zero_add]
  rw [← e]

/-- Row leaves over an appended set: the old rows, then the new rows at shifted positions. -/
private theorem c8_rows_append {α β : Type} (F G : α × Nat → Option β) (s f : List α)
    (hG : ∀ x j, G (x, j) = F (x, s.length + j)) :
    (s ++ f).zipIdx.mapM F = (do
      let a ← s.zipIdx.mapM F
      let b ← f.zipIdx.mapM G
      pure (a ++ b)) := by
  have e := c8_shift (fun _ => true) (fun _ => true) (fun _ _ _ => rfl) F G s.length hG f 0
  have ft : ∀ l : List (α × Nat), l.filter (fun _ => true) = l := fun l => by
    induction l <;> simp_all
  simp only [ft, Nat.add_zero] at e
  rw [List.zipIdx_append, List.mapM_append, Nat.zero_add, e]

private theorem c8_nodup_of_map {α β : Type} (g : α → β) {l : List α} (h : (l.map g).Nodup) : l.Nodup :=
  (List.pairwise_map.1 h).imp fun hne e => hne (congrArg g e)

private theorem c8_inj_of_nodup_map {α β : Type} (g : α → β) :
    ∀ (l : List α), (l.map g).Nodup → ∀ a b, a ∈ l → b ∈ l → g a = g b → a = b
  | [], _, _, _, ha, _, _ => by simp at ha
  | x :: l, h, a, b, ha, hb, e => by
    rw [List.map_cons, List.nodup_cons] at h
    rcases List.mem_cons.mp ha with rfl | ha' <;> rcases List.mem_cons.mp hb with rfl | hb'
    · rfl
    · exact (h.1 (by rw [e]; exact List.mem_map_of_mem hb')).elim
    · exact (h.1 (by rw [← e]; exact List.mem_map_of_mem ha')).elim
    · exact c8_inj_of_nodup_map g l h.2 a b ha' hb' e

private theorem c8_nodup_map_of_inj {α β : Type} (g : α → β) :
    ∀ (l : List α), l.Nodup → (∀ a ∈ l, ∀ b ∈ l, g a = g b → a = b) → (l.map g).Nodup
  | [], _, _ => by simp
  | x :: l, h, hi => by
    rw [List.nodup_cons] at h
    rw [List.map_cons, List.nodup_cons]
    refine ⟨fun hm => ?_, c8_nodup_map_of_inj g l h.2 fun a ha b hb => hi a (by simp [ha]) b (by simp [hb])⟩
    obtain ⟨y, hy, e⟩ := List.mem_map.mp hm
    exact h.1 (by rw [← hi y (by simp [hy]) x (by simp) e]; exact hy)

/-- The first components of a `mapM` result, when each image's first component is a function of its source. -/
private theorem c8_mapM_fst {α β γ : Type} (F : α → Option (β × γ)) (g : α → β) :
    ∀ (xs : List α) (ys : List (β × γ)), xs.mapM F = some ys → (∀ x ∈ xs, ∀ y, F x = some y → y.1 = g x) →
      ys.map (·.1) = xs.map g
  | [], ys, h, _ => by simp [List.mapM_nil] at h; subst h; rfl
  | x :: xs, ys, h, hg => by
    simp only [List.mapM_cons] at h
    cases hx : F x with
    | none => simp [hx] at h
    | some a =>
      cases hm : xs.mapM F with
      | none => simp [hx, hm] at h
      | some bs =>
        simp [hx, hm] at h
        subst h
        simp only [List.map_cons, hg x (by simp) a hx,
          c8_mapM_fst F g xs bs hm fun z hz => hg z (by simp [hz])]

private theorem c8_mapM_mem {α β : Type} {F : α → Option β} {xs : List α} {ys : List β}
    (h : xs.mapM F = some ys) {x : α} {y : β} (hx : x ∈ xs) (hy : F x = some y) : y ∈ ys := by
  obtain ⟨y', hy', e⟩ := c3_mapM_all F xs ys h x hx
  rw [hy] at e
  obtain rfl := Option.some.inj e
  exact hy'

/-- H0: with `count = entries.length`, the spec's date bump is the index's. -/
private theorem c8_bumpSet (t : Nat) (s : Snapshot Line) (hc : s.count = s.entries.length) :
    bumpSet t s = bumpIf (validDate s.asOf && decide (s.asOf ≤ t)) t s.asOf := by
  simp only [bumpSet, hc, beq_self_eq_true, Bool.true_and]

/-- The shape shared by `setMap` and `writes`: two `mapM` blocks under a Nodup guard. -/
private theorem c9_dec {A B : Option Map} {m : Map}
    (h : (do let a ← A; let b ← B; let m := a ++ b; guard (m.map (·.1)).Nodup; pure m) = some m) :
    ∃ a b, A = some a ∧ B = some b ∧ (a.map (·.1) ++ b.map (·.1)).Nodup ∧ m = a ++ b := by
  cases A with
  | none => simp at h
  | some a =>
    cases B with
    | none => simp at h
    | some b =>
      by_cases g : (a.map (·.1) ++ b.map (·.1)).Nodup
      · simp [guard, g] at h
        exact ⟨a, b, rfl, rfl, g, h.symm⟩
      · simp [guard, g] at h <;> exact nomatch h

private theorem c9_enc {A B : Option Map} {a b : Map} (hA : A = some a) (hB : B = some b)
    (g : (a.map (·.1) ++ b.map (·.1)).Nodup) :
    (do let a ← A; let b ← B; let m := a ++ b; guard (m.map (·.1)).Nodup; pure m) = some (a ++ b) := by
  subst hA hB
  simp [guard, g]

/-- The path a key's leaf sits at (its bytes, when it has them). -/
private def c9PK (H : Bytes → Bytes) (q : Key) : Bytes := pathOf H ((keyBytes q).getD [])

private theorem c9_row {H : Bytes → Bytes} (pos : Nat → Nat) {x : Line} {i : Nat} {y : Bytes × Bytes}
    (h : (fun ((x, i) : Line × Nat) => do
      let kb ← keyBytes (rowKey x)
      let v ← be 8 (pos i)
      pure (pathOf H kb, v)) (x, i) = some y) :
    ∃ kb, keyBytes (rowKey x) = some kb ∧ y.1 = pathOf H kb := by
  cases hk : keyBytes (rowKey x) with
  | none => simp [hk] at h
  | some kb =>
    cases hb : be 8 (pos i) with
    | none => simp [hk, hb] at h
    | some v =>
      simp [hk, hb] at h
      subst h
      exact ⟨kb, rfl, rfl⟩

private theorem c9_rows_fst {H : Bytes → Bytes} (pos : Nat → Nat) {t : List Line} {rows : Map}
    (h : t.zipIdx.mapM (fun ((x, i) : Line × Nat) => do
      let kb ← keyBytes (rowKey x)
      let v ← be 8 (pos i)
      pure (pathOf H kb, v)) = some rows) :
    rows.map (·.1) = (t.map rowKey).map (c9PK H) ∧ ∀ x ∈ t, ∃ kb, keyBytes (rowKey x) = some kb := by
  refine ⟨?_, fun x hx => ?_⟩
  · calc rows.map (·.1) = (t.zipIdx.map Prod.fst).map (c9PK H ∘ rowKey) := by
          rw [List.map_map]
          refine c8_mapM_fst _ (fun p : Line × Nat => c9PK H (rowKey p.1)) _ _ h ?_
          rintro ⟨x, i⟩ - y hy
          obtain ⟨kb, hk, h1⟩ := c9_row pos hy
          simp [c9PK, hk, h1]
      _ = _ := by rw [List.zipIdx_map_fst, List.map_map]
  · obtain ⟨i, hi⟩ := c3_zipIdx_of_mem hx
    obtain ⟨y, -, hy⟩ := c3_mapM_all _ _ _ h _ hi
    obtain ⟨kb, hk, -⟩ := c9_row pos hy
    exact ⟨kb, hk⟩

private theorem c9_kS {H : Bytes → Bytes} {u : Bool} {t : List Line} {q : Key} {y : Bytes × Bytes}
    (h : (do
      let kb ← keyBytes q
      let es ← postings u t q
      let v ← keyVal es.length (es.foldl (frontierPush H) [])
      pure (pathOf H kb, v)) = some y) :
    ∃ kb, keyBytes q = some kb ∧ y.1 = pathOf H kb := by
  cases hk : keyBytes q with
  | none => simp [hk] at h
  | some kb =>
    cases hp : postings u t q with
    | none => simp [hk, hp] at h
    | some es =>
      cases hv : keyVal es.length (es.foldl (frontierPush H) []) with
      | none => simp [hk, hp, hv] at h
      | some v =>
        simp [hk, hp, hv] at h
        subst h
        exact ⟨kb, rfl, rfl⟩

private theorem c9_ks_fst {H : Bytes → Bytes} {u : Bool} {t : List Line} {Q : List Key} {ks : Map}
    (h : Q.mapM (fun (q : Key) => do
      let kb ← keyBytes q
      let es ← postings u t q
      let v ← keyVal es.length (es.foldl (frontierPush H) [])
      pure (pathOf H kb, v)) = some ks) :
    ks.map (·.1) = Q.map (c9PK H) ∧ ∀ q ∈ Q, ∃ kb, keyBytes q = some kb := by
  refine ⟨c8_mapM_fst _ _ _ _ h fun q _ y hy => ?_, fun q hq => ?_⟩
  · obtain ⟨kb, hk, h1⟩ := c9_kS hy
    simp [c9PK, hk, h1]
  · obtain ⟨y, -, hy⟩ := c3_mapM_all _ _ _ h q hq
    obtain ⟨kb, hk, -⟩ := c9_kS hy
    exact ⟨kb, hk⟩

private theorem c9_kW {H : Bytes → Bytes} {u : Bool} {hs : List Hit} {c0 : Nat} {f : List Line} {q : Key}
    {y : Bytes × Bytes}
    (hy : (do
      let kb ← keyBytes q
      let h ← findHit hs u q
      let es ← (f.zipIdx.filter fun ((x, _) : Line × Nat) => (rowKeys u x).contains q).mapM
        fun ((x, j) : Line × Nat) => postEntry (c0 + j) x.id
      let v ← keyVal (h.n + es.length) (es.foldl (frontierPush H) h.peaks)
      pure (pathOf H kb, v)) = some y) :
    ∃ kb hit es v, keyBytes q = some kb ∧ findHit hs u q = some hit ∧
      (f.zipIdx.filter fun ((x, _) : Line × Nat) => (rowKeys u x).contains q).mapM
        (fun ((x, j) : Line × Nat) => postEntry (c0 + j) x.id) = some es ∧
      keyVal (hit.n + es.length) (es.foldl (frontierPush H) hit.peaks) = some v ∧ y = (pathOf H kb, v) := by
  cases hk : keyBytes q with
  | none => rw [hk] at hy; simp at hy
  | some kb =>
    rw [hk] at hy
    cases hh : findHit hs u q with
    | none => rw [hh] at hy; simp at hy
    | some hit =>
      rw [hh] at hy
      cases he : (f.zipIdx.filter fun ((x, _) : Line × Nat) => (rowKeys u x).contains q).mapM
          (fun ((x, j) : Line × Nat) => postEntry (c0 + j) x.id) with
      | none => rw [he] at hy; simp at hy
      | some es =>
        rw [he] at hy
        cases hv : keyVal (hit.n + es.length) (es.foldl (frontierPush H) hit.peaks) with
        | none => simp [hv] at hy
        | some v =>
          simp [hv] at hy
          exact ⟨kb, hit, es, v, rfl, rfl, rfl, hv, hy.symm⟩

private theorem c9_kw_fst {H : Bytes → Bytes} {u : Bool} {hs : List Hit} {c0 : Nat} {f : List Line}
    {Q : List Key} {ks : Map}
    (h : Q.mapM (fun (q : Key) => do
      let kb ← keyBytes q
      let h ← findHit hs u q
      let es ← (f.zipIdx.filter fun ((x, _) : Line × Nat) => (rowKeys u x).contains q).mapM
        fun ((x, j) : Line × Nat) => postEntry (c0 + j) x.id
      let v ← keyVal (h.n + es.length) (es.foldl (frontierPush H) h.peaks)
      pure (pathOf H kb, v)) = some ks) :
    ks.map (·.1) = Q.map (c9PK H) ∧ ∀ q ∈ Q, ∃ kb, keyBytes q = some kb := by
  refine ⟨c8_mapM_fst _ _ _ _ h fun q _ y hy => ?_, fun q hq => ?_⟩
  · obtain ⟨kb, _, _, _, hk, _, _, _, rfl⟩ := c9_kW hy
    simp [c9PK, hk]
  · obtain ⟨y, -, hy⟩ := c3_mapM_all _ _ _ h q hq
    obtain ⟨kb, _, _, _, hk, _⟩ := c9_kW hy
    exact ⟨kb, hk⟩

/-- No row of `t` sits under a key none of its rows uses. -/
private theorem c9_postings_nil (u : Bool) (t : List Line) (q : Key) (hq : q ∉ t.flatMap (rowKeys u)) (k : Nat) :
    (t.zipIdx k).filter (fun ((x, _) : Line × Nat) => (rowKeys u x).contains q) = [] := by
  rw [List.filter_eq_nil_iff]
  rintro ⟨x, j⟩ hp hc
  have hx : x ∈ t := by
    have := List.mem_map_of_mem (f := Prod.fst) hp
    rwa [List.zipIdx_map_fst] at this
  exact hq (List.mem_flatMap.mpr ⟨x, hx, by simpa using hc⟩)

private theorem c9_postings_out (u : Bool) (s f : List Line) (q : Key) (hq : q ∉ f.flatMap (rowKeys u)) :
    postings u (s ++ f) q = postings u s q := by
  unfold postings
  rw [List.zipIdx_append, List.filter_append, c9_postings_nil u f q hq, List.append_nil]

/-- H2: appending `f` (true hits for its keys, fresh rows, path-separated keys) to `s` turns `s`'s map into
    `upsert m (writes ..)`, up to order. -/
private theorem c8_setMap_append (H : Bytes → Bytes) (u : Bool) (s f : List Line) (hs : List Hit) (m wm : Map)
    (hm : setMap H u s = some m) (hw : writes H u hs s.length f = some wm)
    (hT : ∀ q ∈ f.flatMap (rowKeys u), ∀ h, findHit hs u q = some h →
      h.n = ((postings u s q).getD []).length ∧ h.peaks = ((postings u s q).getD []).foldl (frontierPush H) [])
    (hR : ∀ x ∈ f, ∀ y ∈ s, rowKey x ≠ rowKey y)
    (hP : ∀ a b ka kb, a ∈ f.map rowKey ++ f.flatMap (rowKeys u) → b ∈ s.map rowKey ++ s.flatMap (rowKeys u) →
      keyBytes a = some ka → keyBytes b = some kb → pathOf H ka = pathOf H kb → a = b) :
    ∃ m', setMap H u (s ++ f) = some m' ∧ (upsert m wm).Perm m' := by
  have hwk := c8_writes_keys hw
  obtain ⟨rS, kS, hrS, hkS, gS, rfl⟩ := c9_dec hm
  obtain ⟨rF, kF, hrF, hkF, gF, rfl⟩ := c9_dec hw
  have hQ : ∀ q, q ∈ ((s ++ f).flatMap (rowKeys u)).eraseDups ↔
      q ∈ s.flatMap (rowKeys u) ∨ q ∈ f.flatMap (rowKeys u) := fun q => by
    rw [List.mem_eraseDups, List.flatMap_append, List.mem_append]
  have hps : ∀ q, ∃ ps, postings u s q = some ps := by
    intro q
    by_cases hq : q ∈ s.flatMap (rowKeys u)
    · obtain ⟨y, -, hy⟩ := c3_mapM_all _ _ _ hkS q (List.mem_eraseDups.mpr hq)
      cases hp : postings u s q with
      | none =>
        cases hk : keyBytes q with
        | none => simp [hk] at hy
        | some kb => simp [hk, hp] at hy
      | some ps => exact ⟨ps, rfl⟩
    · exact ⟨[], by unfold postings; rw [c9_postings_nil u s q hq]; rfl⟩
  -- a batch key's leaf is the appended set's leaf
  have hKW : ∀ q ∈ f.flatMap (rowKeys u), ∀ y, (do
      let kb ← keyBytes q
      let h ← findHit hs u q
      let es ← (f.zipIdx.filter fun ((x, _) : Line × Nat) => (rowKeys u x).contains q).mapM
        fun ((x, j) : Line × Nat) => postEntry (s.length + j) x.id
      let v ← keyVal (h.n + es.length) (es.foldl (frontierPush H) h.peaks)
      pure (pathOf H kb, v)) = some y →
      (do
        let kb ← keyBytes q
        let es ← postings u (s ++ f) q
        let v ← keyVal es.length (es.foldl (frontierPush H) [])
        pure (pathOf H kb, v)) = some y := by
    intro q hq y hy
    obtain ⟨kb, hit, es, v, hk, hh, he, hv, rfl⟩ := c9_kW hy
    obtain ⟨ps, hp⟩ := hps q
    obtain ⟨hn, hpk⟩ := hT q hq hit hh
    simp only [hp, Option.getD_some] at hn hpk
    rw [c8_postings_append u s f q (fun ((x, _) : Line × Nat) => (rowKeys u x).contains q) (fun _ _ => rfl)
      (fun ((x, j) : Line × Nat) => postEntry (s.length + j) x.id) (fun _ _ => rfl), hp, he]
    simp [hk, List.foldl_append, ← hn, ← hpk, hv]
  obtain ⟨kN, hkN⟩ := c8_mapM_some (fun (q : Key) => do
      let kb ← keyBytes q
      let es ← postings u (s ++ f) q
      let v ← keyVal es.length (es.foldl (frontierPush H) [])
      pure (pathOf H kb, v)) ((s ++ f).flatMap (rowKeys u)).eraseDups (by
    intro q hq
    by_cases hqf : q ∈ f.flatMap (rowKeys u)
    · obtain ⟨y, -, hy⟩ := c3_mapM_all _ _ _ hkF q (List.mem_eraseDups.mpr hqf)
      exact ⟨y, hKW q hqf y hy⟩
    · have hqs : q ∈ s.flatMap (rowKeys u) := ((hQ q).mp hq).resolve_right hqf
      obtain ⟨y, -, hy⟩ := c3_mapM_all _ _ _ hkS q (List.mem_eraseDups.mpr hqs)
      refine ⟨y, ?_⟩
      simp only [c9_postings_out u s f q hqf]
      exact hy)
  have hrN : (s ++ f).zipIdx.mapM (fun ((x, i) : Line × Nat) => do
      let kb ← keyBytes (rowKey x)
      let v ← be 8 i
      pure (pathOf H kb, v)) = some (rS ++ rF) := by
    rw [c8_rows_append (fun ((x, i) : Line × Nat) => do
      let kb ← keyBytes (rowKey x)
      let v ← be 8 i
      pure (pathOf H kb, v)) (fun ((x, j) : Line × Nat) => do
      let kb ← keyBytes (rowKey x)
      let v ← be 8 (s.length + j)
      pure (pathOf H kb, v)) s f (fun _ _ => rfl), hrS, hrF] <;> rfl
  -- keys: encodable, path-injective on each side, and across sides by hP
  have cv : ∀ (t : List Line) a, a ∈ t.map rowKey ++ t.flatMap (rowKeys u) ↔
      a ∈ t.map rowKey ++ (t.flatMap (rowKeys u)).eraseDups := fun t a => by
    simp only [List.mem_append, List.mem_eraseDups]
  have eS : ∀ a ∈ s.map rowKey ++ (s.flatMap (rowKeys u)).eraseDups, ∃ ka, keyBytes a = some ka := by
    intro a ha
    rcases List.mem_append.mp ha with ha | ha
    · obtain ⟨x, hx, rfl⟩ := List.mem_map.mp ha
      exact (c9_rows_fst (fun i => i) hrS).2 x hx
    · exact (c9_ks_fst hkS).2 a ha
  have eF : ∀ a ∈ f.map rowKey ++ (f.flatMap (rowKeys u)).eraseDups, ∃ ka, keyBytes a = some ka := by
    intro a ha
    rcases List.mem_append.mp ha with ha | ha
    · obtain ⟨x, hx, rfl⟩ := List.mem_map.mp ha
      exact (c9_rows_fst (fun j => s.length + j) hrF).2 x hx
    · exact (c9_kw_fst hkF).2 a ha
  have gS' : ((s.map rowKey ++ (s.flatMap (rowKeys u)).eraseDups).map (c9PK H)).Nodup := by
    rw [List.map_append, ← (c9_rows_fst (fun i => i) hrS).1, ← (c9_ks_fst hkS).1]
    exact gS
  have gF' : ((f.map rowKey ++ (f.flatMap (rowKeys u)).eraseDups).map (c9PK H)).Nodup := by
    rw [List.map_append, ← (c9_rows_fst (fun j => s.length + j) hrF).1, ← (c9_kw_fst hkF).1]
    exact gF
  have side : ∀ a ∈ (s ++ f).map rowKey ++ ((s ++ f).flatMap (rowKeys u)).eraseDups,
      a ∈ s.map rowKey ++ (s.flatMap (rowKeys u)).eraseDups ∨
        a ∈ f.map rowKey ++ (f.flatMap (rowKeys u)).eraseDups := by
    intro a ha
    simp only [List.map_append, List.flatMap_append, List.mem_append, List.mem_eraseDups] at ha ⊢
    rcases ha with (h | h) | h | h
    · exact Or.inl (Or.inl h)
    · exact Or.inr (Or.inl h)
    · exact Or.inl (Or.inr h)
    · exact Or.inr (Or.inr h)
  have hI : ∀ a ∈ (s ++ f).map rowKey ++ ((s ++ f).flatMap (rowKeys u)).eraseDups,
      ∀ b ∈ (s ++ f).map rowKey ++ ((s ++ f).flatMap (rowKeys u)).eraseDups, c9PK H a = c9PK H b → a = b := by
    intro a ha b hb e
    rcases side a ha with ha | ha <;> rcases side b hb with hb | hb
    · exact c8_inj_of_nodup_map _ _ gS' a b ha hb e
    · obtain ⟨ka, hka⟩ := eS a ha
      obtain ⟨kb, hkb⟩ := eF b hb
      exact (hP b a kb ka ((cv f b).mpr hb) ((cv s a).mpr ha) hkb hka
        (by simpa [c9PK, hka, hkb] using e.symm)).symm
    · obtain ⟨ka, hka⟩ := eF a ha
      obtain ⟨kb, hkb⟩ := eS b hb
      exact hP a b ka kb ((cv f a).mpr ha) ((cv s b).mpr hb) hka hkb (by simpa [c9PK, hka, hkb] using e)
    · exact c8_inj_of_nodup_map _ _ gF' a b ha hb e
  have hL : ((s ++ f).map rowKey ++ ((s ++ f).flatMap (rowKeys u)).eraseDups).Nodup := by
    have ndS : (s.map rowKey).Nodup := by
      rw [List.map_append] at gS'
      exact c8_nodup_of_map _ (List.nodup_append.mp gS').1
    have ndF : (f.map rowKey).Nodup := by
      rw [List.map_append] at gF'
      exact c8_nodup_of_map _ (List.nodup_append.mp gF').1
    rw [List.map_append]
    refine List.nodup_append.mpr ⟨List.nodup_append.mpr ⟨ndS, ndF, ?_⟩,
      c4_nodup_eraseDups _ _ (Nat.le_refl _), ?_⟩
    · intro a ha b hb hab
      obtain ⟨y, hy, rfl⟩ := List.mem_map.mp ha
      obtain ⟨x, hx, rfl⟩ := List.mem_map.mp hb
      exact hR x hx y hy hab.symm
    · intro a ha b hb hab
      obtain ⟨z', -, hb'⟩ := List.mem_flatMap.mp (List.mem_eraseDups.mp hb)
      rcases List.mem_append.mp ha with ha | ha <;> obtain ⟨z, -, hz⟩ := List.mem_map.mp ha <;>
        exact c3_rowKeys_head u z' b hb' (by rw [← hab, ← hz] <;> rfl)
  have gN : ((rS ++ rF).map (·.1) ++ kN.map (·.1)).Nodup := by
    rw [(c9_rows_fst (fun i => i) hrN).1, (c9_ks_fst hkN).1, ← List.map_append]
    exact c8_nodup_map_of_inj _ _ hL hI
  -- no new leaf shadows an old ROW leaf, or an old key leaf the batch does not touch
  have noShadow : ∀ b kb, keyBytes b = some kb →
      (b ∈ s.map rowKey ∨ (b ∈ s.flatMap (rowKeys u) ∧ b ∉ f.flatMap (rowKeys u))) →
      (rF ++ kF).any (fun x => x.1 == pathOf H kb) = false := by
    intro b kb hk hb
    refine List.any_eq_false.mpr fun e' he' hc => ?_
    obtain ⟨a, ka, hsrc, hka, he1⟩ := hwk e' he'
    have hab : a = b := hP a b ka kb
      (by
        rcases hsrc with ⟨x, hx, rfl⟩ | h
        · exact List.mem_append_left _ (List.mem_map_of_mem hx)
        · exact List.mem_append_right _ h)
      (by
        rcases hb with h | h
        · exact List.mem_append_left _ h
        · exact List.mem_append_right _ h.1)
      hka hk (he1.symm.trans (beq_iff_eq.mp hc))
    rcases hsrc with ⟨x, hx, hax⟩ | haf <;> rcases hb with hbs | ⟨hbs, hbf⟩
    · obtain ⟨y, hy, hyb⟩ := List.mem_map.mp hbs
      exact hR x hx y hy (hax.symm.trans (hab.trans hyb.symm))
    · obtain ⟨y, -, hq⟩ := List.mem_flatMap.mp hbs
      exact c3_rowKeys_head u y b hq (by rw [← hab, hax] <;> rfl)
    · obtain ⟨y, -, hyb⟩ := List.mem_map.mp hbs
      obtain ⟨x, -, hq⟩ := List.mem_flatMap.mp haf
      exact c3_rowKeys_head u x a hq (by rw [hab, ← hyb] <;> rfl)
    · exact hbf (hab ▸ haf)
  refine ⟨rS ++ rF ++ kN, c9_enc hrN hkN gN, ?_⟩
  have wNd : ((rF ++ kF).map (·.1)).Nodup := by rw [List.map_append]; exact gF
  have mNd : (rS ++ kS).Nodup := by
    have g : ((rS ++ kS).map (·.1)).Nodup := by rw [List.map_append]; exact gS
    exact c8_nodup_of_map _ g
  have nNd : (rS ++ rF ++ kN).Nodup := by
    have g : ((rS ++ rF ++ kN).map (·.1)).Nodup := by rw [List.map_append]; exact gN
    exact c8_nodup_of_map _ g
  refine (upsert_perm _ _ wNd).trans ((List.perm_ext_iff_of_nodup ?_ nNd).mpr ?_)
  · unfold upM
    refine List.nodup_append.mpr ⟨c8_nodup_of_map _ wNd, mNd.sublist List.filter_sublist, ?_⟩
    intro a ha b hb hab
    rw [List.mem_filter] at hb
    have : (rF ++ kF).any (·.1 == b.1) = true := List.any_eq_true.mpr ⟨a, ha, by simp [hab]⟩
    simp [this] at hb
  intro e
  constructor
  · intro he
    unfold upM at he
    rcases List.mem_append.mp he with he | he
    · rcases List.mem_append.mp he with he | he
      · simp [he]
      · obtain ⟨q, hq, hy⟩ := g1_mapM_mem _ _ _ hkF e he
        have hqf := List.mem_eraseDups.mp hq
        exact List.mem_append_right _ (c8_mapM_mem hkN ((hQ q).mpr (Or.inr hqf)) (hKW q hqf e hy))
    · rw [List.mem_filter] at he
      obtain ⟨he, hns⟩ := he
      rcases List.mem_append.mp he with he | he
      · simp [he]
      · obtain ⟨q, hq, hy⟩ := g1_mapM_mem _ _ _ hkS e he
        have hqs := List.mem_eraseDups.mp hq
        by_cases hqf : q ∈ f.flatMap (rowKeys u)
        · obtain ⟨y, hy', hyW⟩ := c3_mapM_all _ _ _ hkF q (List.mem_eraseDups.mpr hqf)
          obtain ⟨kb, hk, h1⟩ := c9_kS hy
          obtain ⟨kb', _, _, _, hk', _, _, _, rfl⟩ := c9_kW hyW
          rw [hk] at hk'
          obtain rfl := Option.some.inj hk'
          have : (rF ++ kF).any (·.1 == e.1) = true :=
            List.any_eq_true.mpr ⟨_, List.mem_append_right _ hy', by simp [h1]⟩
          simp [this] at hns
        · refine List.mem_append_right _ (c8_mapM_mem hkN ((hQ q).mpr (Or.inl hqs)) ?_)
          simp only [c9_postings_out u s f q hqf]
          exact hy
  · intro he
    unfold upM
    rcases List.mem_append.mp he with he | he
    · rcases List.mem_append.mp he with he | he
      · obtain ⟨⟨x, i⟩, hx, hy⟩ := g1_mapM_mem _ _ _ hrS e he
        obtain ⟨kb, hk, h1⟩ := c9_row (fun i => i) hy
        refine List.mem_append_right _ (List.mem_filter.mpr ⟨List.mem_append_left _ he, ?_⟩)
        rw [h1, noShadow (rowKey x) kb hk (Or.inl (List.mem_map_of_mem (c3_mem_zipIdx hx)))] <;> rfl
      · exact List.mem_append_left _ (List.mem_append_left _ he)
    · obtain ⟨q, hq, hy⟩ := g1_mapM_mem _ _ _ hkN e he
      by_cases hqf : q ∈ f.flatMap (rowKeys u)
      · obtain ⟨y, hy', hyW⟩ := c3_mapM_all _ _ _ hkF q (List.mem_eraseDups.mpr hqf)
        have e1 : e = y := Option.some.inj (hy.symm.trans (hKW q hqf y hyW))
        rw [e1]
        exact List.mem_append_left _ (List.mem_append_right _ hy')
      · have hqs : q ∈ s.flatMap (rowKeys u) := ((hQ q).mp hq).resolve_right hqf
        simp only [c9_postings_out u s f q hqf] at hy
        obtain ⟨kb, hk, h1⟩ := c9_kS hy
        refine List.mem_append_right _ (List.mem_filter.mpr
          ⟨List.mem_append_right _ (c8_mapM_mem hkS (List.mem_eraseDups.mpr hqs) hy), ?_⟩)
        rw [h1, noShadow q kb hk (Or.inr ⟨hqs, hqf⟩)] <;> rfl

/-- Every fresh row of a carried-style result is the line of one of its decisions. -/
private theorem c9_fresh_sub (c : Ctx) (k : Nat) (os : List Owner) (b : List Line) {l : Line}
    (h : l ∈ (batchFresh c (decideRegT c k os b)).1 ∨ l ∈ (batchFresh c (decideRegT c k os b)).2) :
    l ∈ (decideRegT c k os b).decisions.map (·.line) := by
  rw [c5_fresh_spec] at h
  rcases h with h | h
  · obtain ⟨h, -⟩ := List.mem_filter.mp h
    obtain ⟨d, hd, rfl⟩ := List.mem_map.mp h
    exact List.mem_map_of_mem (List.mem_filter.mp hd).1
  · obtain ⟨d, hd, rfl⟩ := List.mem_map.mp h
    exact List.mem_map_of_mem (List.mem_filter.mp hd).1

/-- A ready line's ROW key and stored keys are probed in its set. -/
private theorem c9_probeQ (c₀ : Ctx) (k : Nat) (os : List Owner) {bb : List Line} {l : Line} (hl : l ∈ bb) :
    (rowKey l ∈ (probeKeys c₀ k os bb).1 ∧ ∀ q ∈ rowKeys false l, q ∈ (probeKeys c₀ k os bb).1) ∧
      (rowKey l ∈ (probeKeys c₀ k os bb).2 ∧ ∀ q ∈ rowKeys true l, q ∈ (probeKeys c₀ k os bb).2) := by
  have e1 : ∀ q, (q ∈ keys l ∨ q = rowKey l) → q ∈ (probeKeys c₀ k os bb).1 := fun q hq =>
    List.mem_eraseDups.mpr (List.mem_append_left _ (List.mem_flatMap.mpr ⟨l, hl, by
      rcases hq with hq | rfl
      · exact List.mem_append_left _ hq
      · exact List.mem_append_right _ (List.mem_singleton.mpr rfl)⟩))
  have e2 : ∀ q, (q ∈ rowKeys true l ∨ q = rowKey l) → q ∈ (probeKeys c₀ k os bb).2 := fun q hq =>
    List.mem_eraseDups.mpr (List.mem_append_left _ (List.mem_flatMap.mpr ⟨l, hl, by
      rcases hq with hq | rfl
      · exact List.mem_append_left _ (List.mem_append_left _ hq)
      · exact List.mem_append_left _ (List.mem_append_right _ (List.mem_singleton.mpr rfl))⟩))
  exact ⟨⟨e1 _ (Or.inr rfl), fun q hq => e1 q (Or.inl (by simpa [rowKeys] using hq))⟩,
    ⟨e2 _ (Or.inr rfl), fun q hq => e2 q (Or.inl hq)⟩⟩

/-- One set's step: the appended set's map exists and the courier's updated root is its root, unless the proof
    or a probed key path collides with the set's inputs. -/
private theorem c9_set (H : Bytes → Bytes) (hH : HashLen H) (u : Bool) (s f : List Line) (m : Map)
    (hm : setMap H u s = some m) (hs : List Hit) (wm : Map) (hw : writes H u hs s.length f = some wm)
    (qs : List Key) (pf : Proof)
    (hv : verifyMulti H (root H m) (qs.filterMap fun q => (keyBytes q).map (pathOf H)) pf = true)
    (hq : ∀ x ∈ f, rowKey x ∈ qs ∧ ∀ q ∈ rowKeys u x, q ∈ qs)
    (hT : ∀ q kb, keyBytes q = some kb → q ∈ qs → findHit hs u q = some (c3T H u s q (pathOf H kb)))
    (hN : ∀ q, keyBytes q = none → findHit hs u q = none)
    (hR : ∀ x ∈ f, ∀ y ∈ s, rowKey x ≠ rowKey y) :
    (∃ m', setMap H u (s ++ f) = some m' ∧ hashPf H (upsertPf 513 0 pf wm) = root H m') ∨
      Collision H (pfInputs H pf ++ qs.filterMap fun q => (keyBytes q).map (KD ++ ·)) (setInputs H u s) := by
  by_cases nc : Collision H (pfInputs H pf ++ qs.filterMap fun q => (keyBytes q).map (KD ++ ·)) (setInputs H u s)
  · exact Or.inr nc
  left
  have hT' : ∀ q ∈ f.flatMap (rowKeys u), ∀ h, findHit hs u q = some h →
      h.n = ((postings u s q).getD []).length ∧ h.peaks = ((postings u s q).getD []).foldl (frontierPush H) [] := by
    intro q hq0 h hh
    obtain ⟨x, hx, hqx⟩ := List.mem_flatMap.mp hq0
    cases hk : keyBytes q with
    | none => rw [hN q hk] at hh; cases hh
    | some kb =>
      rw [hT q kb hk ((hq x hx).2 q hqx)] at hh
      obtain rfl := Option.some.inj hh
      exact ⟨by simp [c3T, c3_rowKeys_head u x q hqx], by simp [c3T, c3_rowKeys_head u x q hqx]⟩
  have hP : ∀ a b ka kb, a ∈ f.map rowKey ++ f.flatMap (rowKeys u) → b ∈ s.map rowKey ++ s.flatMap (rowKeys u) →
      keyBytes a = some ka → keyBytes b = some kb → pathOf H ka = pathOf H kb → a = b := by
    intro a b ka kb ha hb hka hkb he
    refine Classical.byContradiction fun hne => nc ⟨KD ++ ka, ?_, KD ++ kb, ?_, ?_, he⟩
    · have haq : a ∈ qs := by
        rcases List.mem_append.mp ha with ha | ha
        · obtain ⟨x, hx, rfl⟩ := List.mem_map.mp ha
          exact (hq x hx).1
        · obtain ⟨x, hx, hax⟩ := List.mem_flatMap.mp ha
          exact (hq x hx).2 a hax
      exact List.mem_append_right _ (List.mem_filterMap.mpr ⟨a, haq, by rw [hka]; rfl⟩)
    · unfold setInputs
      dsimp only
      refine List.mem_append_left _ (List.mem_append_left _ (List.mem_filterMap.mpr ⟨b, ?_, by rw [hkb]; rfl⟩))
      rcases List.mem_append.mp hb with hb | hb
      · exact List.mem_append_left _ hb
      · exact List.mem_append_right _ (List.mem_eraseDups.mpr hb)
    · intro e
      exact hne (keyBytes_inj hka (by rw [hkb, List.append_cancel_left e]))
  obtain ⟨m', hm', hp⟩ := c8_setMap_append H u s f hs m wm hm hw hT' hR hP
  refine ⟨m', hm', ?_⟩
  rcases c8_root H hH u s m hm hs s.length f wm hw qs pf hv hq hT hN with e | e
  · rw [e]
    exact (root_perm H m' _ (setMap_ok H hH u _ m' hm') hp.symm).symm
  · refine absurd (coll_mono H (fun y hy => List.mem_append_left _ hy) (fun y hy => ?_) e) nc
    unfold setInputs
    simp [hm, hy]

private theorem c9_eraseDups_sub {α : Type} [BEq α] [LawfulBEq α] :
    ∀ (n : Nat) (l : List α), l.length ≤ n → l.eraseDups.Sublist l
  | _, [], _ => by simp
  | 0, _ :: _, h => by simp at h
  | n + 1, a :: as, h => by
    rw [List.eraseDups_cons]
    exact ((c9_eraseDups_sub n _ (Nat.le_trans (List.length_filter_le _ _) (by simp at h; omega))).trans
      (List.filter_sublist ..)).cons_cons a

private theorem c9_sub : ∀ (S T : List (Nat × Nat)), S.Pairwise (fun a b => a.1 < b.1) →
    T.Pairwise (fun a b => a.1 ≤ b.1) → T.Nodup → (∀ e ∈ T, e ∈ S) → T.Sublist S
  | [], [], _, _, _, _ => List.Sublist.slnil
  | [], t :: _, _, _, _, hm => absurd (hm t (List.mem_cons_self ..)) (by simp)
  | _ :: _, [], _, _, _, _ => List.nil_sublist _
  | s :: S, t :: T, hS, hT, hN, hm => by
    rw [List.pairwise_cons] at hS hT
    rw [List.nodup_cons] at hN
    by_cases e : t = s
    · subst e
      refine (c9_sub S T hS.2 hT.2 hN.2 fun a ha => ?_).cons_cons t
      rcases List.mem_cons.mp (hm a (List.mem_cons_of_mem _ ha)) with h | h
      · exact absurd (h ▸ ha) hN.1
      · exact h
    · have ht : t ∈ S := (List.mem_cons.mp (hm t (List.mem_cons_self ..))).resolve_left e
      refine (c9_sub S (t :: T) hS.2 (List.pairwise_cons.mpr hT) (List.nodup_cons.mpr hN) fun a ha => ?_).cons s
      rcases List.mem_cons.mp (hm a ha) with h | h
      · exfalso
        have h1 := hS.1 t ht
        rcases List.mem_cons.mp ha with h2 | h2
        · exact e (h2.symm.trans h)
        · have h3 := hT.1 a h2; rw [h] at h3; omega
      · exact h

private theorem c9_take_mem {e : Nat × Nat} : ∀ (S L : List (Nat × Nat)) (k : Nat), S.Nodup → L.Sublist S →
    e ∈ L → e ∈ S.take k → e ∈ L.take k
  | [], L, _, _, hL, he, _ => by rw [List.sublist_nil.mp hL] at he; simp at he
  | _ :: _, _, 0, _, _, _, hk => by simp at hk
  | s :: S, L, k + 1, hN, hL, he, hk => by
    rw [List.nodup_cons] at hN
    rw [List.take_succ_cons, List.mem_cons] at hk
    rcases List.sublist_cons_iff.mp hL with hL' | ⟨r, rfl, hr⟩
    · rcases hk with rfl | hk
      · exact absurd (hL'.subset he) hN.1
      · rw [List.take_add]; exact List.mem_append_left _ (c9_take_mem S L k hN.2 hL' he hk)
    · rw [List.take_succ_cons, List.mem_cons]
      rcases List.mem_cons.mp he with h | h
      · exact Or.inl h
      · rcases hk with rfl | hk
        · exact Or.inl rfl
        · exact Or.inr (c9_take_mem S r k hN.2 hr h hk)

private theorem c9_take_eq : ∀ (S T : List (Nat × Nat)) (k : Nat), S.Nodup → T.Sublist S →
    (∀ e ∈ S.take k, e ∈ T) → T.take k = S.take k
  | [], T, _, _, hT, _ => by rw [List.sublist_nil.mp hT]
  | _ :: _, _, 0, _, _, _ => by simp
  | s :: S, T, k + 1, hN, hT, hm => by
    rw [List.nodup_cons] at hN
    have hs : s ∈ T := hm s (by simp)
    rcases List.sublist_cons_iff.mp hT with hT | ⟨r, rfl, hr⟩
    · exact absurd (hT.subset hs) hN.1
    · have ih : r.take k = S.take k := c9_take_eq S r k hN.2 hr fun e he => by
        have := hm e (by rw [List.take_succ_cons]; exact List.mem_cons_of_mem _ he)
        rcases List.mem_cons.mp this with h | h
        · exact absurd (by rw [← h]; exact List.mem_of_mem_take he) hN.1
        · exact h
      rw [List.take_succ_cons, List.take_succ_cons, ih]

/-- Merging per-key first-K lists of a position-sorted union gives the union's first K. -/
private theorem c9_merge {ι : Type} (S : List (Nat × Nat)) (F : List ι) (f : ι → List (Nat × Nat))
    (hS : S.Pairwise (fun a b => a.1 < b.1)) (hsub : ∀ i ∈ F, (f i).Sublist S) (hcov : ∀ e ∈ S, ∃ i ∈ F, e ∈ f i) :
    (((F.map fun i => (f i).take K).flatten.mergeSort fun a b => decide (a.1 ≤ b.1)).eraseDups.take K) =
      S.take K := by
  have hN : S.Nodup := hS.imp fun {a b} (h : a.1 < b.1) (e : a = b) => by subst e; exact Nat.lt_irrefl _ h
  have hM : ∀ e, e ∈ (F.map fun i => (f i).take K).flatten.mergeSort (fun a b => decide (a.1 ≤ b.1)) ↔
      ∃ i ∈ F, e ∈ (f i).take K := fun e => by
    rw [(List.mergeSort_perm _ _).mem_iff]
    constructor
    · intro h
      obtain ⟨l, hl, he⟩ := List.mem_flatten.mp h
      obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hl
      exact ⟨i, hi, he⟩
    · rintro ⟨i, hi, he⟩
      exact List.mem_flatten.mpr ⟨_, List.mem_map_of_mem hi, he⟩
  have hP := List.pairwise_mergeSort (le := fun a b : Nat × Nat => decide (a.1 ≤ b.1))
    (fun a b c h1 h2 => by simp only [decide_eq_true_eq] at *; omega)
    (fun a b => by simp only [Bool.or_eq_true, decide_eq_true_eq]; omega)
    ((F.map fun i => (f i).take K).flatten)
  refine c9_take_eq S _ K hN (c9_sub S _ hS ((hP.sublist (c9_eraseDups_sub _ _ (Nat.le_refl _))).imp
    fun h => of_decide_eq_true h) (c4_nodup_eraseDups _ _ (Nat.le_refl _)) fun e he => ?_) fun e he => ?_
  · obtain ⟨i, hi, h⟩ := (hM e).mp (List.mem_eraseDups.mp he)
    exact (hsub i hi).subset (List.mem_of_mem_take h)
  · obtain ⟨i, hi, h⟩ := hcov e (List.mem_of_mem_take he)
    exact List.mem_eraseDups.mpr ((hM e).mpr ⟨i, hi, c9_take_mem S (f i) K hN (hsub i hi) h he⟩)

private theorem c9_zipIdx_lt {α : Type} : ∀ (s : List α) (n : Nat), (s.zipIdx n).Pairwise (fun a b => a.2 < b.2)
  | [], _ => List.Pairwise.nil
  | a :: s, n => by
    rw [List.zipIdx_cons, List.pairwise_cons]
    exact ⟨fun p hp => by have := List.le_snd_of_mem_zipIdx hp; show n < p.2; omega, c9_zipIdx_lt s (n + 1)⟩

/-- The merge over per-key position lists of a set is the first K ids of the rows the keys cover. -/
private theorem c9_mergeZ (s : List Line) (P : Line → Bool) (Qs : List Key) (M : Key → Line → Bool)
    (hsub : ∀ x ∈ s, ∀ q ∈ Qs, M q x = true → P x = true) (hcov : ∀ x ∈ s, P x = true → ∃ q ∈ Qs, M q x = true) :
    (((Qs.map fun q => ((s.zipIdx.filter fun p => M q p.1).map fun p => (p.2, p.1.id)).take K).flatten.mergeSort
      fun a b => decide (a.1 ≤ b.1)).eraseDups.take K).map (·.2) = ((s.filter P).map (·.id)).take K := by
  rw [c9_merge ((s.zipIdx.filter fun p => P p.1).map fun p => (p.2, p.1.id)) Qs
    (fun q => (s.zipIdx.filter fun p => M q p.1).map fun p => (p.2, p.1.id))
    (List.pairwise_map.mpr ((c9_zipIdx_lt s 0).sublist (List.filter_sublist ..)))
    (fun q hq => by
      have e : s.zipIdx.filter (fun p => M q p.1) = (s.zipIdx.filter fun p => P p.1).filter fun p => M q p.1 := by
        rw [List.filter_filter]
        refine List.filter_congr fun p hp => ?_
        cases h : M q p.1
        · simp
        · simp [hsub _ (List.fst_mem_of_mem_zipIdx hp) q hq h]
      rw [e]
      exact (List.filter_sublist ..).map _)
    (fun e he => by
      obtain ⟨p, hp, rfl⟩ := List.mem_map.mp he
      have hp' := List.mem_filter.mp hp
      obtain ⟨q, hq, hm⟩ := hcov p.1 (List.fst_mem_of_mem_zipIdx hp'.1) hp'.2
      exact ⟨q, hq, List.mem_map_of_mem (List.mem_filter.mpr ⟨hp'.1, hm⟩)⟩)]
  rw [← List.map_take]
  congr 1
  conv => rhs; rw [← List.zipIdx_map_fst 0 s]
  rw [List.filter_map, List.map_map, List.map_map]
  rw [List.map_take]
  rfl

private theorem c9_take_app (A B : List Nat) : (A.take K ++ B.take K).take K = (A ++ B).take K := by
  rw [List.take_append, List.take_append, List.take_take, List.take_take, List.length_take, Nat.min_self]
  congr 2
  omega

/-- A posting decodes to its (position, id). -/
private theorem c9_postEntry {i n : Nat} {e : Bytes} (h : postEntry i n = some e) :
    (beNat (e.take 8), beNat (e.drop 8)) = (i, n) := by
  have hdec : ∀ {w v : Nat} {a : Bytes}, be w v = some a → beNat a = v := fun {w v a} hb => by
    by_cases hl : v < 256 ^ w
    · rw [be_eq_natBE hl] at hb; cases hb; exact beNat_natBE w v hl
    · unfold be at hb; rw [if_neg hl] at hb; cases hb
  unfold postEntry at h
  cases ha : be 8 i with
  | none => simp [ha] at h
  | some a =>
    cases hb : be idWidth n with
    | none => simp [ha, hb] at h
    | some c =>
      simp [ha, hb] at h
      subst h
      rw [List.take_left' (be_len ha), List.drop_left' (be_len ha), hdec ha, hdec hb]

private theorem c9_mapM {α β γ : Type} (F : α → Option β) (h : β → γ) (g : α → γ) :
    ∀ (xs : List α) (ys : List β), xs.mapM F = some ys → (∀ x ∈ xs, ∀ y, F x = some y → h y = g x) →
      ys.map h = xs.map g
  | [], ys, hm, _ => by simp [List.mapM_nil] at hm; subst hm; rfl
  | x :: xs, ys, hm, hg => by
    simp only [List.mapM_cons] at hm
    cases hx : F x with
    | none => simp [hx] at hm
    | some a =>
      cases hr : xs.mapM F with
      | none => simp [hx, hr] at hm
      | some bs =>
        simp [hx, hr] at hm
        subst hm
        simp only [List.map_cons, hg x (by simp) a hx,
          c9_mapM F h g xs bs hr fun z hz => hg z (by simp [hz])]

/-- A probed key's first-K list decodes to the first K (position, id) of the rows stored under it. -/
private theorem c9_firstOf (H : Bytes → Bytes) (x : Ix) (u : Bool) (s : List Line) (m : Map)
    (hm : setMap H u s = some m) (q : Key)
    (hF : ∀ kb, keyBytes q = some kb → findHit x.hs u q = some (c3T H u s q (pathOf H kb)))
    (hN : keyBytes q = none → findHit x.hs u q = none) :
    (x.firstOf u q).map (fun e => (beNat (e.take 8), beNat (e.drop 8))) =
      ((s.zipIdx.filter fun p => (rowKeys u p.1).contains q).map fun p => (p.2, p.1.id)).take K := by
  have hP : postings u s q = (s.zipIdx.filter fun p => (rowKeys u p.1).contains q).mapM
      fun p => postEntry p.2 p.1.id := by
    first
      | rfl
      | (unfold postings; congr 1 <;> first | rfl | (funext ⟨y, i⟩; rfl) | (congr 1; funext ⟨y, i⟩; rfl))
  by_cases hL : (s.zipIdx.filter fun p => (rowKeys u p.1).contains q) = []
  · have h0 : x.firstOf u q = [] := by
      unfold Ix.firstOf
      cases hk : keyBytes q with
      | none => rw [hN hk] <;> rfl
      | some kb =>
        rw [hF kb hk]
        unfold c3T
        split
        · rfl
        · rw [hP, hL] <;> rfl
    rw [h0, hL] <;> rfl
  · obtain ⟨p, hp⟩ := List.exists_mem_of_ne_nil _ hL
    have hp' := List.mem_filter.mp hp
    have hpq : q ∈ rowKeys u p.1 := List.contains_iff_mem.mp hp'.2
    obtain ⟨kb, es, hk, hes, -⟩ := (c3_setMap_mem hm).2.2.1 q
      (List.mem_flatMap.mpr ⟨p.1, List.fst_mem_of_mem_zipIdx hp'.1, hpq⟩)
    have hfo : x.firstOf u q = es.take K := by
      unfold Ix.firstOf
      rw [hF kb hk]
      unfold c3T
      rw [if_neg (c3_rowKeys_head u p.1 q hpq), hes] <;> rfl
    rw [hfo, List.map_take]
    congr 1
    exact c9_mapM _ _ _ _ es (hP.symm.trans hes) fun y _ e he => c9_postEntry he

/-- `mergeFirst` over keys `Qs` whose rows are exactly those with `P` is the first K ids of `s.filter P`. -/
private theorem c9_mergeFirst (s : List Line) (u : Bool) (P : Line → Bool) (Qs : List Key) (f : Key → List Bytes)
    (hf : ∀ q ∈ Qs, (f q).map (fun e => (beNat (e.take 8), beNat (e.drop 8))) =
      ((s.zipIdx.filter fun p => (rowKeys u p.1).contains q).map fun p => (p.2, p.1.id)).take K)
    (hsub : ∀ x ∈ s, ∀ q ∈ Qs, (rowKeys u x).contains q = true → P x = true)
    (hcov : ∀ x ∈ s, P x = true → ∃ q ∈ Qs, (rowKeys u x).contains q = true) :
    Ix.mergeFirst (Qs.map f) = ((s.filter P).map (·.id)).take K := by
  have e : (Qs.map f).flatten.map (fun e => (beNat (e.take 8), beNat (e.drop 8))) =
      (Qs.map fun q => ((s.zipIdx.filter fun p => (rowKeys u p.1).contains q).map
        fun p => (p.2, p.1.id)).take K).flatten := by
    rw [List.map_flatten, List.map_map]
    congr 1
    exact List.map_congr_left hf
  unfold Ix.mergeFirst
  rw [e]
  exact c9_mergeZ s P Qs (fun q y => (rowKeys u y).contains q) hsub hcov

/-- The unresolved probe keys of `firstKQ` hit exactly the unresolved rows whose claim shares a key with `l`. -/
private theorem c9_unrQ (c₀ : Ctx) (rel unr : Snapshot Line) (hi : Inv rel unr) (l y : Line) (hy : y ∈ unr.entries) :
    (∃ q ∈ keys l, q ∈ claim (carried c₀ rel unr) y) ↔
      ∃ q ∈ [exactKey l, idKey l] ++ (if isCap l then capProbes c₀ l.member (l.date / 100) else [nearKey l]),
        q ∈ rowKeys true y := by
  have hEx : exactKey l ∈ claim (carried c₀ rel unr) y ↔ exactKey l ∈ rowKeys true y :=
    c4_claim_mem _ y _ (by unfold exactKey; split <;> simp)
  have hId : idKey l ∈ claim (carried c₀ rel unr) y ↔ idKey l ∈ rowKeys true y :=
    c4_claim_mem _ y _ (by simp [idKey])
  have hK : ∀ P : Key → Prop, (∃ q ∈ keys l, P q) ↔ (P (exactKey l) ∨ P (nearKey l) ∨ P (idKey l)) :=
    fun P => by simp [keys]
  rw [hK]
  by_cases hcap : isCap l = true
  · rw [if_pos hcap]
    have hNc : nearKey l = [0, l.member, l.date / 100] := by simp [nearKey, hcap]
    rw [hNc, c9_near_claim c₀ rel unr hi _ _ y hy, hEx, hId]
    constructor
    · rintro (h | h | h)
      · exact ⟨_, List.mem_append_left _ (by simp), h⟩
      · simp only [Bool.and_eq_true, beq_iff_eq] at h
        obtain ⟨q, hq, hr⟩ := (c4_capProbe_mem c₀ _ _ y).mpr h
        exact ⟨q, List.mem_append_right _ hq, hr⟩
      · exact ⟨_, List.mem_append_left _ (by simp), h⟩
    · rintro ⟨q, hq, hr⟩
      rcases List.mem_append.mp hq with h | h
      · simp only [List.mem_cons, List.mem_nil_iff, or_false] at h
        rcases h with rfl | rfl
        · exact Or.inl hr
        · exact Or.inr (Or.inr hr)
      · have hc := (c4_capProbe_mem c₀ _ _ y).mp ⟨q, h, hr⟩
        exact Or.inr (Or.inl (by simp [hc.1, hc.2]))
  · rw [if_neg hcap]
    have hNe : nearKey l ∈ claim (carried c₀ rel unr) y ↔ nearKey l ∈ rowKeys true y :=
      c4_claim_mem _ y _ (by simp [nearKey, hcap])
    rw [hEx, hId, hNe]
    constructor
    · rintro (h | h | h)
      · exact ⟨_, List.mem_append_left _ (by simp), h⟩
      · exact ⟨_, List.mem_append_right _ (by simp), h⟩
      · exact ⟨_, List.mem_append_left _ (by simp), h⟩
    · rintro ⟨q, hq, hr⟩
      simp only [List.mem_append, List.mem_cons, List.mem_nil_iff, or_false] at hq
      rcases hq with (rfl | rfl) | rfl
      · exact Or.inl hr
      · exact Or.inr (Or.inr hr)
      · exact Or.inr (Or.inl hr)

/-- Per line: the indexed first-K equals the spec's `counterparts.take K` on the carried context. -/
private theorem c9_firstKQ (H : Bytes → Bytes) (x : Ix) (c₀ : Ctx) (rel unr : Snapshot Line) (hi : Inv rel unr)
    (mr mu : Map) (hmr : setMap H false rel.entries = some mr) (hmu : setMap H true unr.entries = some mu)
    (hxc : x.c₀ = c₀) (l : Line)
    (hF : ∀ (u : Bool) (q : Key) kb, keyBytes q = some kb →
      (q ∈ keys l ∨ (u = true ∧ isCap l = true ∧ q ∈ capProbes c₀ l.member (l.date / 100))) →
      findHit x.hs u q = some (c3T H u (if u then unr.entries else rel.entries) q (pathOf H kb)))
    (hN : ∀ u q, keyBytes q = none → findHit x.hs u q = none) :
    x.firstKQ l = (decideLine (carried c₀ rel unr) [] l).counterparts.take K := by
  have hl1 : loose (carried c₀ rel unr).today (carried c₀ rel unr).releasedPrior (carried c₀ rel unr).released = [] :=
    carried_loose _ _
  have hl2 : loose (carried c₀ rel unr).today (carried c₀ rel unr).unresolvedPrior
      (carried c₀ rel unr).unresolved = [] := carried_loose _ _
  have hc : (decideLine (carried c₀ rel unr) [] l).counterparts =
      (rel.entries.filter fun y => (keys l).any (keys y).contains).map (·.id) ++
      (unr.entries.filter fun y => (keys l).any (claim (carried c₀ rel unr) y).contains).map (·.id) := by
    show ((releasedSet _ ++ loose _ _ _).filter _ ++ (unresolvedSet _ ++ loose _ _ _).filter _).map _ = _
    rw [hl1, hl2, sv_released_carried, sv_unresolved_carried, List.append_nil, List.append_nil, List.map_append]
  have rk0 : ∀ y, rowKeys false y = keys y := fun y => by simp [rowKeys]
  have h1 : Ix.mergeFirst ((keys l).map (x.firstOf false)) =
      ((rel.entries.filter fun y => (keys l).any (keys y).contains).map (·.id)).take K :=
    c9_mergeFirst rel.entries false (fun y => (keys l).any (keys y).contains) (keys l) (x.firstOf false)
      (fun q hq => c9_firstOf H x false rel.entries mr hmr q (fun kb hk => hF false q kb hk (Or.inl hq))
        (hN false q))
      (fun y _ q hq hm => List.any_eq_true.mpr ⟨q, hq, by rw [← rk0 y]; exact hm⟩)
      (fun y _ hp => by
        obtain ⟨q, hq, hm⟩ := List.any_eq_true.mp hp
        exact ⟨q, hq, by rw [rk0 y]; exact hm⟩)
  have hQ : ∀ q ∈ [exactKey l, idKey l] ++ (if isCap l then capProbes c₀ l.member (l.date / 100) else [nearKey l]),
      q ∈ keys l ∨ (true = true ∧ isCap l = true ∧ q ∈ capProbes c₀ l.member (l.date / 100)) := by
    intro q hq
    rcases List.mem_append.mp hq with h | h
    · simp only [List.mem_cons, List.mem_nil_iff, or_false] at h
      left; rcases h with rfl | rfl <;> simp [keys]
    · by_cases hcap : isCap l = true
      · rw [if_pos hcap] at h; exact Or.inr ⟨rfl, hcap, h⟩
      · rw [if_neg hcap, List.mem_singleton] at h; left; rw [h]; simp [keys]
  have h2 : Ix.mergeFirst (([exactKey l, idKey l] ++
      (if isCap l then capProbes c₀ l.member (l.date / 100) else [nearKey l])).map (x.firstOf true)) =
      ((unr.entries.filter fun y => (keys l).any (claim (carried c₀ rel unr) y).contains).map (·.id)).take K :=
    c9_mergeFirst unr.entries true (fun y => (keys l).any (claim (carried c₀ rel unr) y).contains)
      ([exactKey l, idKey l] ++ (if isCap l then capProbes c₀ l.member (l.date / 100) else [nearKey l]))
      (x.firstOf true)
      (fun q hq => c9_firstOf H x true unr.entries mu hmu q (fun kb hk => hF true q kb hk (hQ q hq)) (hN true q))
      (fun y hy q hq hm => by
        obtain ⟨q', hq', h'⟩ := (c9_unrQ c₀ rel unr hi l y hy).mpr ⟨q, hq, List.contains_iff_mem.mp hm⟩
        exact List.any_eq_true.mpr ⟨q', hq', List.contains_iff_mem.mpr h'⟩)
      (fun y hy hp => by
        obtain ⟨q, hq, h⟩ := List.any_eq_true.mp hp
        obtain ⟨q', hq', h'⟩ := (c9_unrQ c₀ rel unr hi l y hy).mp ⟨q, hq, List.contains_iff_mem.mp h⟩
        exact ⟨q', hq', List.contains_iff_mem.mpr h'⟩)
  rw [hc]
  show (Ix.mergeFirst ((keys l).map (x.firstOf false)) ++ Ix.mergeFirst (([exactKey l, idKey l] ++
    (if isCap l then capProbes x.c₀ l.member (l.date / 100) else [nearKey l])).map (x.firstOf true))).take K = _
  rw [hxc, h1, h2, c9_take_app]

private theorem c9_firstKs (H : Bytes → Bytes) (x : Ix) : ∀ (seen : List Key) (ls : List Line),
    (Ix.decideAllQ H x seen ls).map (·.firstK) = ls.map x.firstKQ
  | _, [] => rfl
  | _, l :: ls => congrArg (x.firstKQ l :: ·) (c9_firstKs H x _ ls)

/-- The spec's counterparts do not depend on `seen`. -/
private theorem c9_cps (c : Ctx) : ∀ (seen : List Key) (ls : List Line),
    (decideAll c seen ls).map (·.counterparts.take K) =
      (decideAll c seen ls).map fun d => (decideLine c [] d.line).counterparts.take K
  | _, [] => rfl
  | _, l :: ls => congrArg ((decideLine c [] l).counterparts.take K :: ·) (c9_cps c _ ls)

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
    Collision H (witnessInputs H c₀ k os b w) (stateInputs H rel unr) := by
  by_cases nc : Collision H (witnessInputs H c₀ k os b w) (stateInputs H rel unr)
  · exact Or.inr nc
  left
  obtain ⟨x, mr, mu, wr, wu, hmr, hmu, gv1, gv2, -, hxc, hxb, hF, hN, hD, hDec, hPs, hFresh, hW1, hW2, hHd, hxr, hxu,
    hDg, -, hHit, hT⟩ := c7_core H hH c₀ k os b rel unr hi h ha d hd w o hr nc
  obtain ⟨f1, f2, hRel, hUnr, hBF⟩ := decideRegT_sets c₀ k os b rel unr
  have hI : Inv (decideRegT (carried c₀ rel unr) k os b).released (decideRegT (carried c₀ rel unr) k os b).unresolved :=
    inv_step c₀ k os b rel unr hi
  rw [hRel, hUnr] at hI
  have hId : ((rel.entries ++ f1 ++ (unr.entries ++ f2)).map (·.id)).Nodup := hI.1
  simp only [List.map_append] at hId
  obtain ⟨n1, n2, -⟩ := List.nodup_append.mp hId
  have rk : ∀ x y : Line, rowKey x = rowKey y → x.id = y.id := fun x y e => by
    have := congrArg (fun q : Key => q[1]?) e
    simpa [rowKey, Line.fields] using this
  have hof : o.fresh = (f1, f2) := hFresh.trans hBF
  simp only [hof, hi.2.1, hi.2.2] at hW1 hW2 hHd
  have hL : o.decisions.map (·.line) = (decideRegT (carried c₀ rel unr) k os b).decisions.map (·.line) := by
    simpa only [List.map_map, Function.comp_def] using congrArg (List.map Prod.fst) hDec
  have hsub : ∀ l, l ∈ f1 ∨ l ∈ f2 → l ∈ ready k os b := fun l hl => by
    have h1 := c9_fresh_sub (carried c₀ rel unr) k os b (l := l) (by rw [hBF]; exact hl)
    rw [← hL, hD, (c7_lines H x _ _).1] at h1
    exact hxb ▸ c7_ord x h1
  obtain ⟨m1, hm1, r1⟩ : ∃ m1, setMap H false (rel.entries ++ f1) = some m1 ∧
      hashPf H (upsertPf 513 0 w.relPf wr) = root H m1 := by
    refine (c9_set H hH false rel.entries f1 mr hmr x.hs wr hW1 _ w.relPf gv1
      (fun y hy => (c9_probeQ c₀ k os (hsub y (Or.inl hy))).1) (fun q kb hk hq => hT false q kb hk hq) (hN false)
      (fun y hy z hz e => (List.nodup_append.mp n1).2.2 _ (List.mem_map_of_mem hz) _ (List.mem_map_of_mem hy)
        (rk y z e).symm)).resolve_right fun e => nc (coll_mono H ?_ ?_ e)
    · intro y hy
      rw [c5_wIn]
      rcases List.mem_append.mp hy with hy | hy
      · exact List.mem_append_left _ (List.mem_append_left _ (List.mem_append_right _ hy))
      · refine List.mem_append_left _ (List.mem_append_left _ (List.mem_append_left _ (List.mem_append_right _ ?_)))
        rw [List.filterMap_append]
        exact List.mem_append_left _ hy
    · intro y hy
      exact List.mem_append_left _ (List.mem_append_right _ hy)
  obtain ⟨m2, hm2, r2⟩ : ∃ m2, setMap H true (unr.entries ++ f2) = some m2 ∧
      hashPf H (upsertPf 513 0 w.unrPf wu) = root H m2 := by
    refine (c9_set H hH true unr.entries f2 mu hmu x.hs wu hW2 _ w.unrPf gv2
      (fun y hy => (c9_probeQ c₀ k os (hsub y (Or.inr hy))).2) (fun q kb hk hq => hT true q kb hk hq) (hN true)
      (fun y hy z hz e => (List.nodup_append.mp n2).2.2 _ (List.mem_map_of_mem hz) _ (List.mem_map_of_mem hy)
        (rk y z e).symm)).resolve_right fun e => nc (coll_mono H ?_ ?_ e)
    · intro y hy
      rw [c5_wIn]
      rcases List.mem_append.mp hy with hy | hy
      · exact List.mem_append_left _ (List.mem_append_right _ hy)
      · refine List.mem_append_left _ (List.mem_append_left _ (List.mem_append_left _ (List.mem_append_right _ ?_)))
        rw [List.filterMap_append]
        exact List.mem_append_right _ hy
    · intro y hy
      exact List.mem_append_right _ hy
  have e1 : bumpSet c₀.today rel = bumpIf x.relOk c₀.today rel.asOf := by rw [hxr]; exact c8_bumpSet _ _ hi.2.1
  have e2 : bumpSet c₀.today unr = bumpIf x.unrOk c₀.today unr.asOf := by rw [hxu]; exact c8_bumpSet _ _ hi.2.2
  have hHead : headOf H (decideRegT (carried c₀ rel unr) k os b).released
      (decideRegT (carried c₀ rel unr) k os b).unresolved = some o.head := by
    rw [hRel, hUnr, hHd, r1, r2, ← e1, ← e2]
    show (do
      let a ← setMap H false (rel.entries ++ f1)
      let b' ← setMap H true (unr.entries ++ f2)
      pure (⟨bumpSet c₀.today rel, bumpSet c₀.today unr, rel.entries.length + f1.length,
        unr.entries.length + f2.length, root H a, root H b'⟩ : Head)) = _
    rw [hm1, hm2] <;> rfl
  have hFK : o.decisions.map (·.firstK) =
      (decideRegT (carried c₀ rel unr) k os b).decisions.map (·.counterparts.take K) := by
    have e1 : o.decisions.map (·.firstK) = (o.decisions.map (·.line)).map x.firstKQ := by
      rw [hD, c9_firstKs, (c7_lines H x _ _).1]
    have e2 : (decideRegT (carried c₀ rel unr) k os b).decisions.map (·.counterparts.take K) =
        ((decideRegT (carried c₀ rel unr) k os b).decisions.map (·.line)).map
          fun l => (decideLine (carried c₀ rel unr) [] l).counterparts.take K := by
      rw [List.map_map]
      exact c9_cps (carried c₀ rel unr) (idSeen (foreignOf k os (ready k os b)) ++
        seen0 (carried c₀ rel unr) (ready k os b)) (order (carried c₀ rel unr) (ready k os b))
    rw [e1, e2, ← hL]
    apply List.map_congr_left
    intro l hl
    have hlb : l ∈ x.bb := by
      rw [hD, (c7_lines H x _ _).1] at hl
      exact c7_ord x hl
    exact c9_firstKQ H x c₀ rel unr hi mr mu hmr hmu hxc l
      (fun u q kb hk hq => hF u q kb hk (Or.inl ⟨l, hlb, hq.elim Or.inl fun h => Or.inr (Or.inr h)⟩)) hN
  exact ⟨hDec, hFK, hHit, hFresh, hPs, hHead, hDg⟩

/-- A set has no row under id key [4, i] iff no row has id i (kinds 5, 6 never equal [4, i]). -/
private theorem c7_cnt0 (u : Bool) (s : List Line) (i : Nat) :
    ((s.filter fun y => (rowKeys u y).contains [4, i]).length == 0) = !((s.map (·.id)).contains i) := by
  have e : ∀ y : Line, (rowKeys u y).contains [4, i] = (y.id == i) := fun y => by
    apply Bool.eq_iff_iff.mpr
    unfold rowKeys keys exactKey nearKey idKey dayKey badDayKey
    cases isCap y <;> cases validDate y.date <;> cases u <;> simp <;> exact eq_comm
  simp only [e]
  apply Bool.eq_iff_iff.mpr
  simp [List.filter_eq_nil_iff]

/-- H5: WAIT ids are probed as id keys in both trees; does not reuse `hp` (DecideLayer.lean:111). -/
theorem freeIdx_refines (H : Bytes → Bytes) (hH : HashLen H) (c₀ : Ctx) (k : Nat) (os : List Owner)
    (b : List Line) (rel unr : Snapshot Line) (hi : Inv rel unr) (h : Head) (ha : headOf H rel unr = some h)
    (d : Bytes) (hd : digestV2 H h = some d) (w : Witness) (o : OutV2) (hr : decideIdx H c₀ k os b d w = some o) :
    (let r := decideRegT (carried c₀ rel unr) k os b
     o.free = settleFree r.released.entries r.unresolved.entries (pendingOf k os)) ∨
    Collision H (witnessInputs H c₀ k os b w) (stateInputs H rel unr) := by
  by_cases nc : Collision H (witnessInputs H c₀ k os b w) (stateInputs H rel unr)
  · exact Or.inr nc
  left
  obtain ⟨x, mr, mu, -, -, hmr, hmu, -, -, -, -, -, hF, hN, -, -, -, hFresh, -, -, -, -, -, -, hFree, -, -⟩ :=
    c7_core H hH c₀ k os b rel unr hi h ha d hd w o hr nc
  obtain ⟨f1, f2, e1, e2, e3⟩ := decideRegT_sets c₀ k os b rel unr
  simp only [hFree, hFresh, e1, e2, e3, settleFree]
  apply List.filter_congr
  intro i hi'
  have h0 : x.cnt false [4, i] = (rel.entries.filter fun y => (rowKeys false y).contains [4, i]).length :=
    c4_cnt hmr (by simp) (fun kb hk => hF false _ kb hk (Or.inr ⟨i, hi', rfl⟩)) (hN false _)
  have h1 : x.cnt true [4, i] = (unr.entries.filter fun y => (rowKeys true y).contains [4, i]).length :=
    c4_cnt hmu (by simp) (fun kb hk => hF true _ kb hk (Or.inr ⟨i, hi', rfl⟩)) (hN true _)
  rw [h0, h1, c7_cnt0, c7_cnt0]
  simp only [List.map_append, List.contains_append]
  cases (rel.entries.map (·.id)).contains i <;> cases (unr.entries.map (·.id)).contains i <;>
    cases (f1.map (·.id)).contains i <;> cases (f2.map (·.id)).contains i <;> rfl

private theorem c13_bind2 {α : Type} {A B : Option (List α)} {r : List α}
    (h : (do let a ← A; let b ← B; pure (a ++ b)) = some r) : ∃ a b, A = some a ∧ B = some b ∧ r = a ++ b := by
  cases A with
  | none => cases h
  | some a =>
    cases B with
    | none => cases h
    | some b => exact ⟨a, b, rfl, rfl, (Option.some.inj h).symm⟩

/-- Writes completeness: if the appended set has a map and the hits are true, the batch's writes exist. -/
private theorem c13_writes (H : Bytes → Bytes) (u : Bool) (s f : List Line) (hs : List Hit) (m' : Map)
    (hm' : setMap H u (s ++ f) = some m')
    (hT : ∀ q ∈ f.flatMap (rowKeys u), ∃ h, findHit hs u q = some h ∧
      h.n = ((postings u s q).getD []).length ∧ h.peaks = ((postings u s q).getD []).foldl (frontierPush H) []) :
    ∃ wm, writes H u hs s.length f = some wm := by
  obtain ⟨rA, kA, hrA, hkA, gA, -⟩ := c9_dec hm'
  have hrA0 := hrA
  rw [c8_rows_append (fun ((x, i) : Line × Nat) => do
      let kb ← keyBytes (rowKey x)
      let v ← be 8 i
      pure (pathOf H kb, v)) (fun ((x, j) : Line × Nat) => do
      let kb ← keyBytes (rowKey x)
      let v ← be 8 (s.length + j)
      pure (pathOf H kb, v)) s f (fun _ _ => rfl)] at hrA
  obtain ⟨-, rF, -, hrF, -⟩ := c13_bind2 hrA
  obtain ⟨kF, hkF⟩ := c8_mapM_some (fun (q : Key) => do
      let kb ← keyBytes q
      let h ← findHit hs u q
      let es ← (f.zipIdx.filter fun ((x, _) : Line × Nat) => (rowKeys u x).contains q).mapM
        fun ((x, j) : Line × Nat) => postEntry (s.length + j) x.id
      let v ← keyVal (h.n + es.length) (es.foldl (frontierPush H) h.peaks)
      pure (pathOf H kb, v)) (f.flatMap (rowKeys u)).eraseDups (by
    intro q hq
    have hqf := List.mem_eraseDups.mp hq
    obtain ⟨y, -, hy⟩ := c3_mapM_all _ _ _ hkA q (by
      rw [List.mem_eraseDups, List.flatMap_append, List.mem_append]; exact Or.inr hqf)
    obtain ⟨hit, hh, hn, hpk⟩ := hT q hqf
    rw [c8_postings_append u s f q (fun ((x, _) : Line × Nat) => (rowKeys u x).contains q) (fun _ _ => rfl)
      (fun ((x, j) : Line × Nat) => postEntry (s.length + j) x.id) (fun _ _ => rfl)] at hy
    cases hk : keyBytes q with
    | none => simp [hk] at hy
    | some kb =>
      cases hp : postings u s q with
      | none => simp [hk, hp] at hy
      | some a =>
        cases he : (f.zipIdx.filter fun ((x, _) : Line × Nat) => (rowKeys u x).contains q).mapM
            (fun ((x, j) : Line × Nat) => postEntry (s.length + j) x.id) with
        | none => rw [hk, hp, he] at hy; simp at hy
        | some bs =>
          simp only [hp, Option.getD_some] at hn hpk
          cases hv : keyVal (hit.n + bs.length) (bs.foldl (frontierPush H) hit.peaks) with
          | none =>
            rw [hk, hp, he] at hy
            simp [List.foldl_append, ← hn, ← hpk, hv] at hy
          | some v => exact ⟨(pathOf H kb, v), by simp [hh, hv]⟩)
  have gA' : (((s ++ f).map rowKey ++ ((s ++ f).flatMap (rowKeys u)).eraseDups).map (c9PK H)).Nodup := by
    rw [List.map_append, ← (c9_rows_fst (fun i => i) hrA0).1, ← (c9_ks_fst hkA).1]
    exact gA
  have sub : ∀ a ∈ f.map rowKey ++ (f.flatMap (rowKeys u)).eraseDups,
      a ∈ (s ++ f).map rowKey ++ ((s ++ f).flatMap (rowKeys u)).eraseDups := by
    intro a ha
    simp only [List.map_append, List.flatMap_append, List.mem_append, List.mem_eraseDups] at ha ⊢
    rcases ha with h | h
    · exact Or.inl (Or.inr h)
    · exact Or.inr (Or.inr h)
  have ndF : (f.map rowKey).Nodup := by
    have g2 := c8_nodup_of_map _ gA'
    rw [List.map_append] at g2
    exact (List.nodup_append.mp (List.nodup_append.mp g2).1).2.1
  have hLF : (f.map rowKey ++ (f.flatMap (rowKeys u)).eraseDups).Nodup := by
    refine List.nodup_append.mpr ⟨ndF, c4_nodup_eraseDups _ _ (Nat.le_refl _), ?_⟩
    intro a ha b hb hab
    obtain ⟨z', -, hb'⟩ := List.mem_flatMap.mp (List.mem_eraseDups.mp hb)
    obtain ⟨z, -, hz⟩ := List.mem_map.mp ha
    exact c3_rowKeys_head u z' b hb' (by rw [← hab, ← hz] <;> rfl)
  have gF : (rF.map (·.1) ++ kF.map (·.1)).Nodup := by
    rw [(c9_rows_fst (fun j => s.length + j) hrF).1, (c9_kw_fst hkF).1, ← List.map_append]
    exact c8_nodup_map_of_inj _ _ hLF fun a ha b hb e =>
      c8_inj_of_nodup_map _ _ gA' a b (sub a ha) (sub b hb) e
  exact ⟨rF ++ kF, c9_enc hrF hkF gF⟩

private theorem c13_postings_mem {u : Bool} {s : List Line} {q : Key} {es : List Bytes}
    (h : postings u s q = some es) (hne : es ≠ []) : q ∈ s.flatMap (rowKeys u) := by
  refine Classical.byContradiction fun hq => hne ?_
  unfold postings at h
  rw [c9_postings_nil u s q hq] at h
  cases h
  rfl

private theorem c13_postings_ne {u : Bool} {s : List Line} {q : Key} {es : List Bytes}
    (hq : q ∈ s.flatMap (rowKeys u)) (h : postings u s q = some es) : es ≠ [] := by
  rintro rfl
  obtain ⟨x, hx, hqx⟩ := List.mem_flatMap.mp hq
  obtain ⟨i, hi⟩ := c3_zipIdx_of_mem hx
  unfold postings at h
  obtain ⟨y, hy, -⟩ := c3_mapM_all _ _ _ h (x, i) (List.mem_filter.mpr ⟨hi, by simpa using hqx⟩)
  cases hy

private theorem c13_postings_len {u : Bool} {s : List Line} {q : Key} {es : List Bytes}
    (h : postings u s q = some es) : ∀ x ∈ es, x.length = 8 + idWidth := by
  intro x hx
  unfold postings at h
  obtain ⟨⟨y, i⟩, -, hy⟩ := g1_mapM_mem _ _ _ h x hx
  dsimp only at hy
  unfold postEntry at hy
  cases ha : be 8 i with
  | none => simp [ha] at hy
  | some a =>
    cases hb : be idWidth y.id with
    | none => simp [ha, hb] at hy
    | some b =>
      simp [ha, hb] at hy
      subst hy
      rw [List.length_append, be_len ha, be_len hb]

/-- Probe completeness (mirror of `c3_probe`): on a verified proof of the set's map, with the honest list of
    every listed key present and every listed entry honest, a probe is never refused. -/
private theorem c13_probe (H : Bytes → Bytes) (hH : HashLen H) (u : Bool) (s : List Line) (m : Map)
    (hm : setMap H u s = some m) (pf : Proof) (w : Witness) (ps : List Bytes)
    (hv : verifyMulti H (root H m) ps pf = true) (q : Key) (kb : Bytes) (hk : keyBytes q = some kb)
    (hp : pathOf H kb ∈ ps) (A B : List Bytes) (hA1 : KD ++ kb ∈ A) (hA2 : ∀ y ∈ pfInputs H pf, y ∈ A)
    (hB : ∀ y ∈ setInputs H u s, y ∈ B) (nc : ¬ Collision H A B)
    (hL1 : ∀ es, postings u s q = some es → es ≠ [] → q.head? ≠ some 7 →
      (u, pathOf H kb, es.length, es.take K, firstKPf H PD 64 (min K es.length) (es.map (leafHash H PD))) ∈ w.lists)
    (hL2 : ∀ e ∈ w.lists, e.1 = u → ∃ q' kb' es', keyBytes q' = some kb' ∧ postings u s q' = some es' ∧ es' ≠ [] ∧
      e = (u, pathOf H kb', es'.length, es'.take K, firstKPf H PD 64 (min K es'.length) (es'.map (leafHash H PD)))) :
    ∃ r, probe H pf w u q = some r := by
  cases hr : probe H pf w u q with
  | some r => exact ⟨r, rfl⟩
  | none =>
  exfalso
  obtain ⟨hmem, -, -, -⟩ := c3_setMap_mem hm
  have hlk : lookupPf 0 pf (pathOf H kb) = some (lookup m (pathOf H kb)) := by
    rcases smt_sound H hH m (setMap_ok H hH u s m hm) ps pf hv _ hp with h | h
    · exact h
    · exact absurd (coll_mono H hA2 (fun y hy => hB y (by simp [setInputs, hm, hy])) h) nc
  have hkb : ∀ q' kb', keyBytes q' = some kb' → q' ∈ s.map rowKey ++ (s.flatMap (rowKeys u)).eraseDups →
      pathOf H kb' = pathOf H kb → q' = q := by
    intro q' kb' hk' hq' he
    by_cases hne : KD ++ kb = KD ++ kb'
    · have : kb = kb' := List.append_cancel_left hne
      subst this
      exact keyBytes_inj hk' hk
    · refine absurd ⟨KD ++ kb, hA1, KD ++ kb', hB _ ?_, hne, he.symm⟩ nc
      unfold setInputs
      simp only [List.mem_append, List.mem_filterMap]
      exact Or.inl (Or.inl ⟨q', by simpa using hq', by simp [hk']⟩)
  unfold probe at hr
  rw [hk] at hr
  simp only [hlk] at hr
  cases hl : lookup m (pathOf H kb) with
  | none => simp [hl] at hr
  | some v =>
    simp [hl] at hr
    rcases hmem _ (c3_lookup_some hl) with ⟨x, i, hxi, kb', hk', hb, he⟩ | ⟨q', hq', kb', es, hk', hes, hkv, he⟩
    · have hxq := hkb _ _ hk' (List.mem_append_left _ (List.mem_map_of_mem (c3_mem_zipIdx hxi))) he.symm
      subst hxq
      have h7 : (rowKey x).head? = some 7 := rfl
      have hv8 : v.length = 8 := be_len hb
      simp [h7, hv8] at hr
    · have hqq := hkb _ _ hk' (List.mem_append_right _ hq') he.symm
      subst hqq
      rw [hk] at hk'; cases hk'
      obtain ⟨y, -, hqy⟩ := List.mem_flatMap.mp (List.mem_eraseDups.mp hq')
      have h7 := c3_rowKeys_head u y _ hqy
      have hne := c13_postings_ne (List.mem_eraseDups.mp hq') hes
      have h1 : 1 ≤ es.length := by
        cases es with
        | nil => exact absurd rfl hne
        | cons _ _ => exact Nat.succ_le_succ (Nat.zero_le _)
      have hlt : es.length < 2 ^ 64 := by
        unfold keyVal at hkv
        cases hb : be 8 es.length with
        | none => simp [hb] at hkv
        | some c =>
          have h1 := be_lt hb
          have : (256 : Nat) ^ 8 = 2 ^ 64 := by decide
          omega
      have hpk := keyVal_parse H hH es v hkv
      have hvf : verifyFirstK H (frontierRoot H (es.foldl (frontierPush H) [])) es.length (es.take K)
          (firstKPf H PD 64 (min K es.length) (es.map (leafHash H PD))) = true := by
        rw [listRoot_frontier H es hlt]
        exact firstK_complete H hH es h1 hlt (c13_postings_len hes)
      rw [if_neg h7, hpk] at hr
      cases hf : w.lists.find? (fun e => e.fst == u && e.snd.fst == pathOf H kb) with
      | none =>
        have := List.find?_eq_none.mp hf _ (hL1 es hes hne h7)
        simp at this
      | some e =>
        obtain ⟨a1, a2, n', ys, fp⟩ := e
        have hpe := List.find?_some hf
        simp only [Bool.and_eq_true, beq_iff_eq] at hpe
        obtain ⟨q', kb', es', hk', hes', hne', he'⟩ := hL2 _ (List.mem_of_find?_eq_some hf) hpe.1
        simp only [Prod.mk.injEq] at he'
        obtain ⟨-, rfl, rfl, rfl, rfl⟩ := he'
        have hqq := hkb _ _ hk' (List.mem_append_right _ (List.mem_eraseDups.mpr (c13_postings_mem hes' hne')))
          hpe.2
        subst hqq
        rw [hk] at hk'; cases hk'
        rw [hes] at hes'; cases hes'
        simp only [hf] at hr
        split at hr
        · cases hr
        · rename_i hc
          exact hc (by simp [h1, hvf])

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

/-- One entry of `witnessOf`'s lists, read back. -/
private theorem c13_entry (H : Bytes → Bytes) (u : Bool) (s : List Line) (q : Key)
    (e : Bool × Bytes × Nat × List Bytes × List Bytes)
    (h : (do
      let kb ← keyBytes q
      guard (q.head? ≠ some 7)
      let es ← postings u s q
      guard (es ≠ [])
      pure (u, pathOf H kb, es.length, es.take K, firstKPf H PD 64 (min K es.length) (es.map (leafHash H PD)))) =
      some e) :
    ∃ kb es, keyBytes q = some kb ∧ postings u s q = some es ∧ es ≠ [] ∧
      e = (u, pathOf H kb, es.length, es.take K, firstKPf H PD 64 (min K es.length) (es.map (leafHash H PD))) := by
  cases hk : keyBytes q with
  | none => simp [hk] at h
  | some kb =>
    by_cases h7 : q.head? = some 7
    · first | simp [hk, h7, guard, failure] at h | (simp [hk, h7, guard] at h; cases h)
    cases hp : postings u s q with
    | none => simp [hk, hp, h7, guard] at h
    | some es =>
      by_cases he : es = []
      · first | simp [hk, hp, h7, he, guard, failure] at h | (simp [hk, hp, h7, he, guard] at h; cases h)
      simp [hk, hp, h7, he, guard] at h
      exact ⟨kb, es, rfl, rfl, he, h.symm⟩

/-- `witnessOf`'s lists, as `c13_probe` needs them: every nonempty probed posting is listed, every entry is one. -/
private theorem c13_lists (H : Bytes → Bytes) (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line)
    (rel unr : Snapshot Line) (h : Head) (u : Bool) :
    (∀ q ∈ (if u then (probeKeys c₀ k os (ready k os b)).2 else (probeKeys c₀ k os (ready k os b)).1),
      ∀ kb es, keyBytes q = some kb → postings u (if u then unr.entries else rel.entries) q = some es → es ≠ [] →
      q.head? ≠ some 7 →
      (u, pathOf H kb, es.length, es.take K, firstKPf H PD 64 (min K es.length) (es.map (leafHash H PD))) ∈
        (witnessOf H c₀ k os b rel unr h).lists) ∧
    (∀ e ∈ (witnessOf H c₀ k os b rel unr h).lists, e.1 = u → ∃ q' kb' es', keyBytes q' = some kb' ∧
      postings u (if u then unr.entries else rel.entries) q' = some es' ∧ es' ≠ [] ∧
      e = (u, pathOf H kb', es'.length, es'.take K, firstKPf H PD 64 (min K es'.length) (es'.map (leafHash H PD)))) := by
  generalize hpk : probeKeys c₀ k os (ready k os b) = p
  obtain ⟨qr, qu⟩ := p
  have hw : (witnessOf H c₀ k os b rel unr h).lists =
      qr.filterMap (fun q => do
        let kb ← keyBytes q
        guard (q.head? ≠ some 7)
        let es ← postings false rel.entries q
        guard (es ≠ [])
        pure (false, pathOf H kb, es.length, es.take K, firstKPf H PD 64 (min K es.length) (es.map (leafHash H PD)))) ++
      qu.filterMap (fun q => do
        let kb ← keyBytes q
        guard (q.head? ≠ some 7)
        let es ← postings true unr.entries q
        guard (es ≠ [])
        pure (true, pathOf H kb, es.length, es.take K, firstKPf H PD 64 (min K es.length) (es.map (leafHash H PD)))) := by
    unfold witnessOf
    rw [hpk]
    try rfl
  rw [hw]
  constructor
  · intro q hq kb es hk hp hne h7
    cases u
    · have hq : q ∈ qr := hq
      have hp : postings false rel.entries q = some es := hp
      exact List.mem_append_left _ (List.mem_filterMap.mpr ⟨q, hq, by simp [hk, hp, hne, h7, guard]⟩)
    · have hq : q ∈ qu := hq
      have hp : postings true unr.entries q = some es := hp
      exact List.mem_append_right _ (List.mem_filterMap.mpr ⟨q, hq, by simp [hk, hp, hne, h7, guard]⟩)
  · intro e he hu
    rcases List.mem_append.mp he with he | he
    · obtain ⟨q, -, hq⟩ := List.mem_filterMap.mp he
      obtain ⟨kb, es, hk, hp, hne, rfl⟩ := c13_entry H false rel.entries q e hq
      cases u
      · exact ⟨q, kb, es, hk, hp, hne, rfl⟩
      · simp at hu
    · obtain ⟨q, -, hq⟩ := List.mem_filterMap.mp he
      obtain ⟨kb, es, hk, hp, hne, rfl⟩ := c13_entry H true unr.entries q e hq
      cases u
      · simp at hu
      · exact ⟨q, kb, es, hk, hp, hne, rfl⟩

private theorem c14_guard {p : Prop} [Decidable p] (hp : p) : (guard p : Option Unit) = some () := by
  unfold guard; exact if_pos hp

/-- Every key of a set with a map has a key encoding. -/
private theorem c14_kb {H : Bytes → Bytes} {u : Bool} {s : List Line} {m : Map} {q : Key}
    (hm : setMap H u s = some m) (hq : q ∈ s.flatMap (rowKeys u)) : ∃ kb, keyBytes q = some kb := by
  obtain ⟨-, kA, -, hkA, -, -⟩ := c9_dec hm
  obtain ⟨y, -, hy⟩ := c3_mapM_all _ _ _ hkA q (List.mem_eraseDups.mpr hq)
  cases hk : keyBytes q with
  | none => simp [hk] at hy
  | some kb => exact ⟨kb, rfl⟩

/-- `witnessOf`'s anchor and proofs, read back. -/
private theorem c14_wit (H : Bytes → Bytes) (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line)
    (rel unr : Snapshot Line) (h : Head) :
    (witnessOf H c₀ k os b rel unr h).anchor = h ∧
    (witnessOf H c₀ k os b rel unr h).relPf = prune H 513 0 ((setMap H false rel.entries).getD [])
      ((probeKeys c₀ k os (ready k os b)).1.filterMap fun q => (keyBytes q).map (pathOf H)) ∧
    (witnessOf H c₀ k os b rel unr h).unrPf = prune H 513 0 ((setMap H true unr.entries).getD [])
      ((probeKeys c₀ k os (ready k os b)).2.filterMap fun q => (keyBytes q).map (pathOf H)) := by
  unfold witnessOf
  generalize probeKeys c₀ k os (ready k os b) = p
  obtain ⟨qr, qu⟩ := p
  exact ⟨rfl, rfl, rfl⟩

/-- `decideIdx` built back up (converse of `c5_peel`): every guard holds, both probe runs return, and for the
    resulting index the writes and the next head's digest exist. -/
private theorem c14_some (H : Bytes → Bytes) (c₀ : Ctx) (k : Nat) (os : List Owner) (b : List Line) (d : Bytes)
    (w : Witness) (g1 : digestV2 H w.anchor = some d)
    (g2 : (ready k os b).all (fun l => (keyBytes (rowKey l)).isSome) = true)
    (g3 : verifyMulti H w.anchor.relRoot
      ((probeKeys c₀ k os (ready k os b)).1.filterMap fun q => (keyBytes q).map (pathOf H)) w.relPf = true)
    (g4 : verifyMulti H w.anchor.unrRoot
      ((probeKeys c₀ k os (ready k os b)).2.filterMap fun q => (keyBytes q).map (pathOf H)) w.unrPf = true)
    (P1 : ∃ hr', (probeKeys c₀ k os (ready k os b)).1.mapM (probe H w.relPf w false) = some hr')
    (P2 : ∃ hu', (probeKeys c₀ k os (ready k os b)).2.mapM (probe H w.unrPf w true) = some hu')
    (hW : ∀ hr' hu', (probeKeys c₀ k os (ready k os b)).1.mapM (probe H w.relPf w false) = some hr' →
      (probeKeys c₀ k os (ready k os b)).2.mapM (probe H w.unrPf w true) = some hu' →
      ∀ x : Ix, x.c₀ = c₀ → x.hs = hr'.filterMap id ++ hu'.filterMap id →
      x.relOk = (validDate w.anchor.relAsOf && decide (w.anchor.relAsOf ≤ c₀.today)) →
      x.unrOk = (validDate w.anchor.unrAsOf && decide (w.anchor.unrAsOf ≤ c₀.today)) → x.bb = ready k os b →
      ∃ wr wu, writes H false x.hs w.anchor.relCount
          (x.releasedQ (Ix.decideAllQ H x (idSeen (foreignOf k os x.bb)) (x.orderQ x.bb))) = some wr ∧
        writes H true x.hs w.anchor.unrCount
          (x.unresolvedQ (Ix.decideAllQ H x (idSeen (foreignOf k os x.bb)) (x.orderQ x.bb))) = some wu ∧
        ∃ dg, digestV2 H ⟨bumpIf x.relOk c₀.today w.anchor.relAsOf, bumpIf x.unrOk c₀.today w.anchor.unrAsOf,
          w.anchor.relCount + (x.releasedQ (Ix.decideAllQ H x (idSeen (foreignOf k os x.bb)) (x.orderQ x.bb))).length,
          w.anchor.unrCount +
            (x.unresolvedQ (Ix.decideAllQ H x (idSeen (foreignOf k os x.bb)) (x.orderQ x.bb))).length,
          hashPf H (upsertPf 513 0 w.relPf wr), hashPf H (upsertPf 513 0 w.unrPf wu)⟩ = some dg) :
    (decideIdx H c₀ k os b d w).isSome = true := by
  cases hX : decideIdx H c₀ k os b d w with
  | some _ => rfl
  | none =>
  exfalso
  unfold decideIdx at hX
  simp only [bind, Option.bind] at hX
  split at hX
  · rename_i e; exact Option.some_ne_none _ ((c14_guard g1).symm.trans e)
  split at hX
  · rename_i e; exact Option.some_ne_none _ ((c14_guard g2).symm.trans e)
  generalize hq : probeKeys c₀ k os (ready k os b) = qq at hX g3 g4 P1 P2 hW
  obtain ⟨qr, qu⟩ := qq
  dsimp only at hX
  have g34 : (verifyMulti H w.anchor.relRoot (qr.filterMap fun q => (keyBytes q).map (pathOf H)) w.relPf &&
      verifyMulti H w.anchor.unrRoot (qu.filterMap fun q => (keyBytes q).map (pathOf H)) w.unrPf) = true := by
    simp only [Bool.and_eq_true]; exact ⟨g3, g4⟩
  split at hX
  · rename_i e; exact Option.some_ne_none _ ((c14_guard g34).symm.trans e)
  dsimp only at hX
  split at hX
  · rename_i e; obtain ⟨_, h⟩ := P1; exact Option.some_ne_none _ (h.symm.trans e)
  rename_i hr' ghr
  dsimp only at hX
  split at hX
  · rename_i e; obtain ⟨_, h⟩ := P2; exact Option.some_ne_none _ (h.symm.trans e)
  rename_i hu' ghu
  dsimp only at hX
  obtain ⟨wr0, wu0, h1, h2, dg0, h3⟩ := hW hr' hu' ghr ghu ⟨c₀, hr'.filterMap id ++ hu'.filterMap id,
    validDate w.anchor.relAsOf && decide (w.anchor.relAsOf ≤ c₀.today),
    validDate w.anchor.unrAsOf && decide (w.anchor.unrAsOf ≤ c₀.today), ready k os b⟩ rfl rfl rfl rfl rfl
  split at hX
  · rename_i e; exact Option.some_ne_none _ (h1.symm.trans e)
  rename_i wr gwr
  obtain rfl := Option.some.inj (h1.symm.trans gwr)
  dsimp only at hX
  split at hX
  · rename_i e; exact Option.some_ne_none _ (h2.symm.trans e)
  rename_i wu gwu
  obtain rfl := Option.some.inj (h2.symm.trans gwu)
  dsimp only at hX
  split at hX
  · rename_i e; exact Option.some_ne_none _ (h3.symm.trans e)
  cases hX

/-- Liveness: an honest witness is refused only on a named collision or an unrepresentable next state. -/
theorem decideIdx_complete (H : Bytes → Bytes) (hH : HashLen H) (c₀ : Ctx) (k : Nat) (os : List Owner)
    (b : List Line) (rel unr : Snapshot Line) (hi : Inv rel unr) (h : Head) (ha : headOf H rel unr = some h)
    (d : Bytes) (hd : digestV2 H h = some d)
    (hb : (ready k os b).all (fun l => (keyBytes (rowKey l)).isSome) = true)
    (hn : (let r := decideRegT (carried c₀ rel unr) k os b; (headOf H r.released r.unresolved).bind headIn).isSome) :
    (decideIdx H c₀ k os b d (witnessOf H c₀ k os b rel unr h)).isSome ∨
      Collision H (witnessInputs H c₀ k os b (witnessOf H c₀ k os b rel unr h)) (stateInputs H rel unr) := by
  by_cases nc : Collision H (witnessInputs H c₀ k os b (witnessOf H c₀ k os b rel unr h)) (stateInputs H rel unr)
  · exact Or.inr nc
  left
  obtain ⟨mr, mu, hmr, hmu, hh⟩ := c5_headOf ha
  have L0 := c13_lists H c₀ k os b rel unr h false
  have L1 := c13_lists H c₀ k os b rel unr h true
  obtain ⟨wA, wR, wU⟩ := c14_wit H c₀ k os b rel unr h
  generalize witnessOf H c₀ k os b rel unr h = w at nc L0 L1 wA wR wU ⊢
  subst hh
  have hpl : ∀ (qs : List Key), ∀ p ∈ qs.filterMap (fun q => (keyBytes q).map (pathOf H)), p.length = digestBytes := by
    intro qs p hp
    obtain ⟨q, -, hq⟩ := List.mem_filterMap.mp hp
    cases hk : keyBytes q with
    | none => rw [hk] at hq; cases hq
    | some kb => rw [hk] at hq; cases hq; exact hH _
  have gv1 : verifyMulti H (root H mr)
      ((probeKeys c₀ k os (ready k os b)).1.filterMap fun q => (keyBytes q).map (pathOf H)) w.relPf = true := by
    rw [wR, hmr]; exact prune_complete H hH mr (setMap_ok H hH false _ mr hmr) _ (hpl _)
  have gv2 : verifyMulti H (root H mu)
      ((probeKeys c₀ k os (ready k os b)).2.filterMap fun q => (keyBytes q).map (pathOf H)) w.unrPf = true := by
    rw [wU, hmu]; exact prune_complete H hH mu (setMap_ok H hH true _ mu hmu) _ (hpl _)
  have hA1 : ∀ q ∈ (probeKeys c₀ k os (ready k os b)).1 ++ (probeKeys c₀ k os (ready k os b)).2, ∀ kb,
      keyBytes q = some kb → KD ++ kb ∈ witnessInputs H c₀ k os b w := fun q hq kb hk => by
    rw [c5_wIn, List.mem_append, List.mem_append, List.mem_append, List.mem_append]
    exact Or.inl (Or.inl (Or.inl (Or.inr (List.mem_filterMap.mpr ⟨q, hq, by rw [hk]; rfl⟩))))
  have hA2r : ∀ y ∈ pfInputs H w.relPf, y ∈ witnessInputs H c₀ k os b w := fun y hy => by
    rw [c5_wIn, List.mem_append, List.mem_append, List.mem_append]
    exact Or.inl (Or.inl (Or.inr hy))
  have hA2u : ∀ y ∈ pfInputs H w.unrPf, y ∈ witnessInputs H c₀ k os b w := fun y hy => by
    rw [c5_wIn, List.mem_append, List.mem_append]
    exact Or.inl (Or.inr hy)
  have hBr : ∀ y ∈ setInputs H false rel.entries, y ∈ stateInputs H rel unr := fun y hy => by
    unfold stateInputs
    rw [List.mem_append, List.mem_append]
    exact Or.inl (Or.inr hy)
  have hBu : ∀ y ∈ setInputs H true unr.entries, y ∈ stateInputs H rel unr := fun y hy => by
    unfold stateInputs
    rw [List.mem_append]
    exact Or.inr hy
  refine c14_some H c₀ k os b d w (by rw [wA]; exact hd) hb (by rw [wA]; exact gv1) (by rw [wA]; exact gv2)
    (c8_mapM_some _ _ fun q hq => ?_) (c8_mapM_some _ _ fun q hq => ?_) ?_
  · cases hk : keyBytes q with
    | none => exact ⟨none, by simp only [probe, hk]⟩
    | some kb =>
      exact c13_probe H hH false rel.entries mr hmr w.relPf w _ gv1 q kb hk
        (List.mem_filterMap.mpr ⟨q, hq, by rw [hk]; rfl⟩) _ _ (hA1 q (List.mem_append_left _ hq) kb hk) hA2r hBr nc
        (fun es he hne h7 => L0.1 q hq kb es hk he hne h7) L0.2
  · cases hk : keyBytes q with
    | none => exact ⟨none, by simp only [probe, hk]⟩
    | some kb =>
      exact c13_probe H hH true unr.entries mu hmu w.unrPf w _ gv2 q kb hk
        (List.mem_filterMap.mpr ⟨q, hq, by rw [hk]; rfl⟩) _ _ (hA1 q (List.mem_append_right _ hq) kb hk) hA2u hBu nc
        (fun es he hne h7 => L1.1 q hq kb es hk he hne h7) L1.2
  intro hr' hu' ghr ghu x hxc hxs hxr hxu hxb
  simp only [wA] at hxr hxu ⊢
  have gK : ∀ l ∈ ready k os b, (keyBytes (rowKey l)).isSome = true := List.all_eq_true.mp hb
  obtain ⟨hT, hN⟩ := c5_hits H hH c₀ k os b rel unr hmr hmu w gv1 gv2 ghr ghu nc
  rw [← hxs] at hT hN
  have hF : ∀ (u : Bool) (q : Key) kb, keyBytes q = some kb →
      ((∃ l ∈ x.bb, q ∈ keys l ∨ q = rowKey l ∨
        (u = true ∧ isCap l = true ∧ q ∈ capProbes c₀ l.member (l.date / 100))) ∨ ∃ i ∈ pendingOf k os, q = [4, i]) →
      findHit x.hs u q = some (c3T H u (if u then unr.entries else rel.entries) q (pathOf H kb)) :=
    fun u q kb hk hm => hT u q kb hk (c7_probe_mem c₀ k os _ u q (hxb ▸ hm))
  obtain ⟨hR, hS, hP⟩ := c4_hyps x c₀ rel unr hi hmr hmu hxc (fun u q kb hk hm => hF u q kb hk (Or.inl hm)) hN
    (fun l hl => gK l (hxb ▸ hl))
  generalize hD : Ix.decideAllQ H x (idSeen (foreignOf k os x.bb)) (x.orderQ x.bb) = ds
  have hDec : ds.map (fun d => (d.line, d.outcome, d.reasons)) =
      (decideRegT (carried c₀ rel unr) k os b).decisions.map (fun d => (d.line, d.outcome, d.reasons)) := by
    rw [← hD]; exact c4_decisions H x c₀ k os b rel unr hi hxc hxb hxr hxu hR hS hP
  have hQ := c7_lines H x (idSeen (foreignOf k os x.bb)) (x.orderQ x.bb)
  rw [hD] at hQ
  have hO : ∀ d ∈ ds, x.ownQ d.line = own (carried c₀ rel unr) d.line := fun d hd' =>
    c4_ownQ x c₀ rel unr hxc hR d.line (by
      have hm : d.line ∈ ds.map (·.line) := List.mem_map_of_mem hd'
      rw [hQ.1] at hm
      exact c7_ord x hm)
  obtain ⟨-, hRel, hUnr⟩ := c7_sel x (carried c₀ rel unr) ds _ hDec hO (by rw [hxc]; rfl)
  obtain ⟨f1, f2, hS1, hS2, hBF⟩ := decideRegT_sets c₀ k os b rel unr
  have hBF' := hBF
  rw [c5_fresh_spec] at hBF'
  obtain ⟨hf1, hf2⟩ := Prod.mk.inj hBF'
  rw [hRel, hUnr, hf1, hf2, hi.2.1, hi.2.2]
  have hL : ds.map (·.line) = (decideRegT (carried c₀ rel unr) k os b).decisions.map (·.line) := by
    simpa only [List.map_map, Function.comp_def] using congrArg (List.map Prod.fst) hDec
  have hsub : ∀ l, l ∈ f1 ∨ l ∈ f2 → l ∈ ready k os b := fun l hl => by
    have h1 := c9_fresh_sub (carried c₀ rel unr) k os b (l := l) (by rw [hBF]; exact hl)
    rw [← hL, hQ.1] at h1
    exact hxb ▸ c7_ord x h1
  have hn' : ((headOf H (decideRegT (carried c₀ rel unr) k os b).released
      (decideRegT (carried c₀ rel unr) k os b).unresolved).bind headIn).isSome = true := hn
  rw [hS1, hS2] at hn'
  cases hh0 : headOf H ⟨bumpSet c₀.today rel, rel.entries.length + f1.length, rel.entries ++ f1⟩
      ⟨bumpSet c₀.today unr, unr.entries.length + f2.length, unr.entries ++ f2⟩ with
  | none => rw [hh0] at hn'; cases hn'
  | some hd0 =>
  rw [hh0] at hn'
  obtain ⟨m1, m2, hm1, hm2, hd0e⟩ := c5_headOf hh0
  have hTw : ∀ (u : Bool) (s f : List Line) (m : Map), (if u then unr.entries else rel.entries) = s →
      (∀ l ∈ f, l ∈ ready k os b) → setMap H u (s ++ f) = some m → ∀ q ∈ f.flatMap (rowKeys u), ∃ h,
        findHit x.hs u q = some h ∧ h.n = ((postings u s q).getD []).length ∧
          h.peaks = ((postings u s q).getD []).foldl (frontierPush H) [] := by
    intro u s f m hs hf hm q hq
    obtain ⟨l, hl, hql⟩ := List.mem_flatMap.mp hq
    obtain ⟨kb, hk⟩ := c14_kb hm (List.mem_flatMap.mpr ⟨l, List.mem_append_right _ hl, hql⟩)
    have hqp : q ∈ (if u then (probeKeys c₀ k os (ready k os b)).2 else (probeKeys c₀ k os (ready k os b)).1) := by
      cases u
      · exact (c9_probeQ c₀ k os (hf l hl)).1.2 q hql
      · exact (c9_probeQ c₀ k os (hf l hl)).2.2 q hql
    have e := hT u q kb hk hqp
    rw [hs] at e
    exact ⟨_, e, by simp [c3T, c3_rowKeys_head u l q hql], by simp [c3T, c3_rowKeys_head u l q hql]⟩
  obtain ⟨wr, hwr⟩ := c13_writes H false rel.entries f1 x.hs m1 hm1
    (hTw false rel.entries f1 m1 rfl (fun l hl => hsub l (Or.inl hl)) hm1)
  obtain ⟨wu, hwu⟩ := c13_writes H true unr.entries f2 x.hs m2 hm2
    (hTw true unr.entries f2 m2 rfl (fun l hl => hsub l (Or.inr hl)) hm2)
  refine ⟨wr, wu, hwr, hwu, ?_⟩
  have hI : Inv (decideRegT (carried c₀ rel unr) k os b).released (decideRegT (carried c₀ rel unr) k os b).unresolved :=
    inv_step c₀ k os b rel unr hi
  rw [hS1, hS2] at hI
  have hId : ((rel.entries ++ f1 ++ (unr.entries ++ f2)).map (·.id)).Nodup := hI.1
  simp only [List.map_append] at hId
  obtain ⟨n1, n2, -⟩ := List.nodup_append.mp hId
  have rk : ∀ x y : Line, rowKey x = rowKey y → x.id = y.id := fun x y e => by
    have := congrArg (fun q : Key => q[1]?) e
    simpa [rowKey, Line.fields] using this
  obtain ⟨m1', hm1', r1⟩ : ∃ m1', setMap H false (rel.entries ++ f1) = some m1' ∧
      hashPf H (upsertPf 513 0 w.relPf wr) = root H m1' := by
    refine (c9_set H hH false rel.entries f1 mr hmr x.hs wr hwr _ w.relPf gv1
      (fun y hy => (c9_probeQ c₀ k os (hsub y (Or.inl hy))).1) (fun q kb hk hq => hT false q kb hk hq) (hN false)
      (fun y hy z hz e => (List.nodup_append.mp n1).2.2 _ (List.mem_map_of_mem hz) _ (List.mem_map_of_mem hy)
        (rk y z e).symm)).resolve_right fun e => nc (coll_mono H ?_ ?_ e)
    · intro y hy
      rw [c5_wIn]
      rcases List.mem_append.mp hy with hy | hy
      · exact List.mem_append_left _ (List.mem_append_left _ (List.mem_append_right _ hy))
      · refine List.mem_append_left _ (List.mem_append_left _ (List.mem_append_left _ (List.mem_append_right _ ?_)))
        rw [List.filterMap_append]
        exact List.mem_append_left _ hy
    · intro y hy
      exact List.mem_append_left _ (List.mem_append_right _ hy)
  obtain ⟨m2', hm2', r2⟩ : ∃ m2', setMap H true (unr.entries ++ f2) = some m2' ∧
      hashPf H (upsertPf 513 0 w.unrPf wu) = root H m2' := by
    refine (c9_set H hH true unr.entries f2 mu hmu x.hs wu hwu _ w.unrPf gv2
      (fun y hy => (c9_probeQ c₀ k os (hsub y (Or.inr hy))).2) (fun q kb hk hq => hT true q kb hk hq) (hN true)
      (fun y hy z hz e => (List.nodup_append.mp n2).2.2 _ (List.mem_map_of_mem hz) _ (List.mem_map_of_mem hy)
        (rk y z e).symm)).resolve_right fun e => nc (coll_mono H ?_ ?_ e)
    · intro y hy
      rw [c5_wIn]
      rcases List.mem_append.mp hy with hy | hy
      · exact List.mem_append_left _ (List.mem_append_right _ hy)
      · refine List.mem_append_left _ (List.mem_append_left _ (List.mem_append_left _ (List.mem_append_right _ ?_)))
        rw [List.filterMap_append]
        exact List.mem_append_right _ hy
    · intro y hy
      exact List.mem_append_right _ hy
  obtain rfl := Option.some.inj (hm1'.symm.trans hm1)
  obtain rfl := Option.some.inj (hm2'.symm.trans hm2)
  have e1 : bumpSet c₀.today rel = bumpIf x.relOk c₀.today rel.asOf := by rw [hxr]; exact c8_bumpSet _ _ hi.2.1
  have e2 : bumpSet c₀.today unr = bumpIf x.unrOk c₀.today unr.asOf := by rw [hxu]; exact c8_bumpSet _ _ hi.2.2
  obtain ⟨y, hy⟩ := Option.isSome_iff_exists.mp hn'
  have hy' : headIn hd0 = some y := hy
  rw [r1, r2, ← e1, ← e2]
  refine ⟨H y, ?_⟩
  have e3 : (⟨bumpSet c₀.today rel, bumpSet c₀.today unr, rel.entries.length + f1.length,
      unr.entries.length + f2.length, root H m1', root H m2'⟩ : Head) = hd0 := hd0e.symm
  rw [e3]
  unfold digestV2
  rw [hy']
  rfl

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

/-- Month step of `civilOf`: month index and day bounds from the day of the March-based year. -/
private theorem c10_month (doy mp d : Nat) (h : doy ≤ 365) (hmp : mp = (5 * doy + 2) / 153)
    (hd : d = doy - (153 * mp + 2) / 5 + 1) :
    mp ≤ 11 ∧ 1 ≤ d ∧ d ≤ 31 ∧ ((mp = 1 ∨ mp = 3 ∨ mp = 6 ∨ mp = 8) → d ≤ 30) ∧ (mp = 11 → d ≤ 29) ∧
      (mp = 11 → d = 29 → doy = 365) := by
  omega

/-- Year-of-era step of `civilOf`: bounds and the leap condition at day-of-year 365. -/
private theorem c10_yoe (doe : Nat) (h : doe ≤ 146096) :
    ∃ yoe, (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365 = yoe ∧ yoe ≤ 399 ∧
      365 * yoe + yoe / 4 - yoe / 100 ≤ doe ∧ doe - (365 * yoe + yoe / 4 - yoe / 100) ≤ 365 ∧
      (doe - (365 * yoe + yoe / 4 - yoe / 100) = 365 →
        (yoe + 1) % 4 = 0 ∧ ((yoe + 1) % 100 ≠ 0 ∨ (yoe + 1) % 400 = 0)) := by
  by_cases he : doe = 146096
  · subst he; exact ⟨399, by decide, by decide, by decide, by decide, fun _ => by decide⟩
  have e0 : doe / 146096 = 0 := Nat.div_eq_of_lt (by omega)
  obtain ⟨c, r, hr, hdoe⟩ : ∃ c r, r < 36524 ∧ doe = 36524 * c + r :=
    ⟨_, _, Nat.mod_lt _ (by decide), (Nat.div_add_mod doe 36524).symm⟩
  obtain ⟨f, g, hg, hrr⟩ : ∃ f g, g < 1461 ∧ r = 1461 * f + g :=
    ⟨_, _, Nat.mod_lt _ (by decide), (Nat.div_add_mod r 1461).symm⟩
  have hc : doe / 36524 = c := Nat.div_eq_of_lt_le (by omega) (by omega)
  by_cases hd : 1460 ≤ 24 * c + f + g
  · have ha : doe / 1460 = 25 * c + f + 1 := Nat.div_eq_of_lt_le (by omega) (by omega)
    obtain ⟨y, k, hk, hgk⟩ : ∃ y k, k < 365 ∧ g - 1 = 365 * y + k :=
      ⟨_, _, Nat.mod_lt _ (by decide), (Nat.div_add_mod (g - 1) 365).symm⟩
    have q4 : (100 * c + 4 * f + y) / 4 = 25 * c + f := Nat.div_eq_of_lt_le (by omega) (by omega)
    have q100 : (100 * c + 4 * f + y) / 100 = c := Nat.div_eq_of_lt_le (by omega) (by omega)
    refine ⟨100 * c + 4 * f + y, ?_, ?_⟩
    · rw [ha, hc, e0]; exact Nat.div_eq_of_lt_le (by omega) (by omega)
    · have hs : 365 * (100 * c + 4 * f + y) + (25 * c + f) - c = 36524 * c + 1461 * f + 365 * y := by omega
      rw [q4, q100, hs]
      refine ⟨by omega, by omega, by omega, fun h3 => ?_⟩
      have hy3 : y = 3 := by omega
      have hf : f ≤ 23 := by omega
      subst hy3
      exact ⟨by omega, Or.inl (by omega)⟩
  · have ha : doe / 1460 = 25 * c + f := Nat.div_eq_of_lt_le (by omega) (by omega)
    obtain ⟨y, k, hk, hgk⟩ : ∃ y k, k < 365 ∧ g = 365 * y + k :=
      ⟨_, _, Nat.mod_lt _ (by decide), (Nat.div_add_mod g 365).symm⟩
    have q4 : (100 * c + 4 * f + y) / 4 = 25 * c + f := Nat.div_eq_of_lt_le (by omega) (by omega)
    have q100 : (100 * c + 4 * f + y) / 100 = c := Nat.div_eq_of_lt_le (by omega) (by omega)
    refine ⟨100 * c + 4 * f + y, ?_, ?_⟩
    · rw [ha, hc, e0]; exact Nat.div_eq_of_lt_le (by omega) (by omega)
    · rw [q4, q100]; exact ⟨by omega, by omega, by omega, fun h3 => by omega⟩

/-- A CCYYMMDD built from in-range parts is a valid date. -/
private theorem c11_vd (Y m d : Nat) (hY : 0 < Y) (hY' : Y ≤ 9999) (hm : 0 < m) (hm' : m ≤ 12) (hd : 0 < d)
    (hd' : d ≤ monthDays Y m) : validDate (Y * 10000 + m * 100 + d) = true := by
  have h31 := c4_monthDays_le Y m
  have e1 : (Y * 10000 + m * 100 + d) / 10000 = Y := by omega
  have e2 : (Y * 10000 + m * 100 + d) / 100 % 100 = m := by omega
  have e3 : (Y * 10000 + m * 100 + d) % 100 = d := by omega
  simp only [validDate, e1, e2, e3]
  simp [hY, hY', hm, hm', hd, hd']

/-- `civilOf` names a valid date for every second before 10000-01-01T00:00:00Z. -/
private theorem c11_civ_valid (secs : Nat) (h : secs < 253402300800) : validDate (civilOf secs) = true := by
  simp only [civilOf]
  generalize hz : secs / 86400 + 719468 = z
  generalize he : z / 146097 = era
  generalize hdoe : z - era * 146097 = doe
  have hb : 4 ≤ era ∧ era ≤ 24 ∧ doe ≤ 146096 ∧ (era < 24 ∨ doe ≤ 146036) := by omega
  clear hz he hdoe h
  obtain ⟨yoe, hy, hy1, hy2, hy3, hy4⟩ := c10_yoe doe hb.2.2.1
  rw [hy]
  clear hy
  generalize hdoy : doe - (365 * yoe + yoe / 4 - yoe / 100) = doy at hy3 hy4 ⊢
  generalize hmp : (5 * doy + 2) / 153 = mp
  generalize hd : doy - (153 * mp + 2) / 5 + 1 = d
  obtain ⟨t1, t2, t3, t4, t5, t6⟩ := c10_month doy mp d hy3 hmp.symm hd.symm
  have edge : era < 24 ∨ yoe < 399 ∨ mp < 10 := by omega
  clear hmp hd hdoy hy2
  by_cases hlt : mp < 10
  · rw [if_pos hlt, if_neg (show ¬ mp + 3 ≤ 2 by omega)]
    refine c11_vd _ _ _ (by omega) (by omega) (by omega) (by omega) (by omega) ?_
    have t4' : d ≤ 30 ∨ ¬(mp = 1 ∨ mp = 3 ∨ mp = 6 ∨ mp = 8) := by
      by_cases hq : mp = 1 ∨ mp = 3 ∨ mp = 6 ∨ mp = 8
      · exact Or.inl (t4 hq)
      · exact Or.inr hq
    have h10 : mp = 0 ∨ mp = 1 ∨ mp = 2 ∨ mp = 3 ∨ mp = 4 ∨ mp = 5 ∨ mp = 6 ∨ mp = 7 ∨ mp = 8 ∨ mp = 9 := by
      omega
    rcases h10 with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> simp [monthDays] <;> omega
  · rw [if_neg hlt, if_pos (show mp - 9 ≤ 2 by omega)]
    refine c11_vd _ _ _ (by omega) (by omega) (by omega) (by omega) (by omega) ?_
    rcases (show mp = 10 ∨ mp = 11 by omega) with rfl | rfl
    · simp [monthDays] <;> omega
    · have t5' := t5 rfl
      by_cases h29 : d = 29
      · obtain ⟨l4, l100⟩ := hy4 (t6 rfl h29)
        have hl : leap (yoe + era * 400 + 1) = true := by
          have a4 : (yoe + era * 400 + 1) % 4 = 0 := by omega
          have a1 : ((yoe + era * 400 + 1) % 100 != 0 || (yoe + era * 400 + 1) % 400 == 0) = true := by
            rcases l100 with l | l
            · have : (yoe + era * 400 + 1) % 100 ≠ 0 := by omega
              simp [this]
            · have : (yoe + era * 400 + 1) % 400 = 0 := by omega
              simp [this]
          unfold leap; rw [a4, a1]; rfl
        simp [monthDays, hl] <;> omega
      · have h28 : 28 ≤ monthDays (yoe + era * 400 + 1) (11 - 9) := by
          unfold monthDays; split <;> split <;> omega
        omega

/-- The UTC offset in force at any instant is within `maxOff` on a `tableOk` table. -/
private theorem c11_off (tbl : OffsetTable) (hT : tableOk tbl = true) (s : Nat) :
    -maxOff ≤ offsetAt tbl s ∧ offsetAt tbl s ≤ maxOff := by
  simp only [tableOk, Bool.and_eq_true, List.all_eq_true, decide_eq_true_eq] at hT
  unfold offsetAt
  cases hl : (tbl.filter (·.1 ≤ s)).getLast? with
  | none => unfold maxOff; simp
  | some e => exact hT.1.2 e (List.mem_filter.mp (List.mem_of_getLast? hl)).1

theorem localDay_valid (tbl : OffsetTable) (hT : tableOk tbl = true) (s : Nat) (hs : s + 50400 < 253402300800) :
    validDate (localDay tbl s) = true := by
  have ho := c11_off tbl hT s
  unfold maxOff at ho
  unfold localDay
  apply c11_civ_valid
  omega

/-- Order of `civilOf` keys: an earlier (year, day-of-year) gives a smaller CCYYMMDD. -/
private theorem c11_keyle (y y' doy doy' : Nat) (h3 : doy ≤ 365) (h3' : doy' ≤ 365)
    (hlex : y < y' ∨ (y = y' ∧ doy ≤ doy')) :
    (if (if (5 * doy + 2) / 153 < 10 then (5 * doy + 2) / 153 + 3 else (5 * doy + 2) / 153 - 9) ≤ 2
        then y + 1 else y) * 10000 +
      (if (5 * doy + 2) / 153 < 10 then (5 * doy + 2) / 153 + 3 else (5 * doy + 2) / 153 - 9) * 100 +
      (doy - (153 * ((5 * doy + 2) / 153) + 2) / 5 + 1) ≤
    (if (if (5 * doy' + 2) / 153 < 10 then (5 * doy' + 2) / 153 + 3 else (5 * doy' + 2) / 153 - 9) ≤ 2
        then y' + 1 else y') * 10000 +
      (if (5 * doy' + 2) / 153 < 10 then (5 * doy' + 2) / 153 + 3 else (5 * doy' + 2) / 153 - 9) * 100 +
      (doy' - (153 * ((5 * doy' + 2) / 153) + 2) / 5 + 1) := by
  generalize hmp : (5 * doy + 2) / 153 = mp
  generalize hmp' : (5 * doy' + 2) / 153 = mp'
  generalize hd : doy - (153 * mp + 2) / 5 + 1 = d
  generalize hd' : doy' - (153 * mp' + 2) / 5 + 1 = d'
  obtain ⟨t1, t2, t3, -, -, -⟩ := c10_month doy mp d h3 hmp.symm hd.symm
  obtain ⟨u1, u2, u3, -, -, -⟩ := c10_month doy' mp' d' h3' hmp'.symm hd'.symm
  have hsame : y = y' ∧ doy ≤ doy' → mp ≤ mp' ∧ (mp = mp' → d ≤ d') := by
    rintro ⟨-, hle⟩
    have hmm : mp ≤ mp' := by
      rw [← hmp, ← hmp']
      exact Nat.div_le_div_right (by omega)
    refine ⟨hmm, fun he => ?_⟩
    subst he
    omega
  clear hmp hmp' hd hd'
  generalize hm : (if mp < 10 then mp + 3 else mp - 9) = m
  generalize hm' : (if mp' < 10 then mp' + 3 else mp' - 9) = m'
  have em : (mp < 10 ∧ m = mp + 3) ∨ (10 ≤ mp ∧ m = mp - 9) := by rw [← hm]; split <;> omega
  have em' : (mp' < 10 ∧ m' = mp' + 3) ∨ (10 ≤ mp' ∧ m' = mp' - 9) := by rw [← hm']; split <;> omega
  split <;> split <;> omega

/-- Day count before year of era `y` grows by at least a year per year. -/
private theorem c11_F (y : Nat) :
    365 * y + y / 4 - y / 100 + 365 ≤ 365 * (y + 1) + (y + 1) / 4 - (y + 1) / 100 := by
  omega

private theorem c11_Fmono (a b : Nat) (h : a ≤ b) :
    365 * a + a / 4 - a / 100 ≤ 365 * b + b / 4 - b / 100 := by
  induction b with
  | zero =>
    have : a = 0 := by omega
    subst this; exact Nat.le_refl _
  | succ n ih =>
    rcases Nat.lt_or_ge a (n + 1) with h' | h'
    · have := ih (by omega)
      have := c11_F n
      omega
    · have : a = n + 1 := by omega
      subst this; exact Nat.le_refl _

/-- Within one 400-year era an earlier day of era never has a later year of era. -/
private theorem c11_yoe_le (doe doe' yoe yoe' : Nat) (h : doe ≤ doe') (hy : yoe ≤ 399)
    (h1 : 365 * yoe + yoe / 4 - yoe / 100 ≤ doe) (h1' : 365 * yoe' + yoe' / 4 - yoe' / 100 ≤ doe')
    (h3' : doe' - (365 * yoe' + yoe' / 4 - yoe' / 100) ≤ 365)
    (h4' : doe' - (365 * yoe' + yoe' / 4 - yoe' / 100) = 365 →
      (yoe' + 1) % 4 = 0 ∧ ((yoe' + 1) % 100 ≠ 0 ∨ (yoe' + 1) % 400 = 0)) :
    yoe ≤ yoe' := by
  apply Nat.le_of_not_lt
  intro hc
  have m1 := c11_Fmono (yoe' + 1) yoe hc
  have m2 := c11_F yoe'
  have e : doe' - (365 * yoe' + yoe' / 4 - yoe' / 100) = 365 := by omega
  obtain ⟨l4, l100⟩ := h4' e
  have m3 : 365 * yoe' + yoe' / 4 - yoe' / 100 + 366 ≤ 365 * (yoe' + 1) + (yoe' + 1) / 4 - (yoe' + 1) / 100 := by
    omega
  omega

/-- `civilOf` is monotone in the second count. -/
private theorem c11_civ_mono (a b : Nat) (h : a ≤ b) : civilOf a ≤ civilOf b := by
  simp only [civilOf]
  generalize hz : a / 86400 + 719468 = z
  generalize hz' : b / 86400 + 719468 = z'
  generalize he : z / 146097 = era
  generalize he' : z' / 146097 = era'
  generalize hdoe : z - era * 146097 = doe
  generalize hdoe' : z' - era' * 146097 = doe'
  have hb : doe ≤ 146096 ∧ doe' ≤ 146096 ∧ (era < era' ∨ (era = era' ∧ doe ≤ doe')) := by omega
  clear hz hz' he he' hdoe hdoe' h
  obtain ⟨yoe, hy, hy1, hy2, hy3, hy4⟩ := c10_yoe doe hb.1
  obtain ⟨yoe', hy', hy1', hy2', hy3', hy4'⟩ := c10_yoe doe' hb.2.1
  rw [hy, hy']
  clear hy hy'
  apply c11_keyle _ _ _ _ hy3 hy3'
  rcases hb.2.2 with hlt | ⟨rfl, hle⟩
  · left; omega
  · rcases Nat.lt_or_eq_of_le (c11_yoe_le doe doe' yoe yoe' hle hy1 hy2 hy2' hy3' hy4') with hlt | rfl
    · left; omega
    · right; exact ⟨rfl, by omega⟩

private theorem c11_civI (x y : Int) (h : x ≤ y) : civilOf x.toNat ≤ civilOf y.toNat :=
  c11_civ_mono _ _ (by omega)

/-- The entry in force before every later change start. -/
private theorem c11_offHead (a : Nat × Int) (l : OffsetTable) (s : Nat) (ha : a.1 ≤ s) (hl : ∀ e ∈ l, s < e.1) :
    offsetAt (a :: l) s = a.2 := by
  have hn : l.filter (·.1 ≤ s) = [] := List.filter_eq_nil_iff.mpr fun e he => by
    have := hl e he
    simp only [decide_eq_true_eq, Nat.not_le]
    exact this
  have hg : (a :: l).filter (·.1 ≤ s) = a :: l.filter (·.1 ≤ s) := List.filter_cons_of_pos (by simpa using ha)
  unfold offsetAt
  rw [hg, hn]
  rfl

/-- From the second entry's start on, the first entry no longer matters. -/
private theorem c11_offTail (a b : Nat × Int) (rest : OffsetTable) (s : Nat) (hb : b.1 ≤ s) :
    offsetAt (a :: b :: rest) s = offsetAt (b :: rest) s := by
  have hf : (b :: rest).filter (·.1 ≤ s) = b :: rest.filter (·.1 ≤ s) :=
    List.filter_cons_of_pos (by simpa using hb)
  unfold offsetAt
  by_cases ha : a.1 ≤ s
  · have hg : (a :: b :: rest).filter (·.1 ≤ s) = a :: (b :: rest).filter (·.1 ≤ s) :=
      List.filter_cons_of_pos (by simpa using ha)
    rw [hg, hf]
    simp
  · have hg : (a :: b :: rest).filter (·.1 ≤ s) = (b :: rest).filter (·.1 ≤ s) :=
      List.filter_cons_of_neg (by simpa using ha)
    rw [hg]

/-- Consecutive ascending starts give every later start above the head's. -/
private theorem c11_lt (l : OffsetTable) (b : Nat × Int) (h : ∀ p ∈ (b :: l).zip l, p.1.1 < p.2.1) :
    ∀ e ∈ l, b.1 < e.1 := by
  induction l generalizing b with
  | nil => simp
  | cons c l ih =>
    have hbc : b.1 < c.1 := h (b, c) (by simp)
    have hc := ih c fun p hp => h p (List.mem_cons_of_mem _ hp)
    intro e he
    rcases List.mem_cons.mp he with he | he
    · rw [he]; exact hbc
    · have := hc e he; omega

/-- Local day is monotone from the head entry's start on, given each change's clause. -/
private theorem c11_seg (l : OffsetTable) (a : Nat × Int)
    (hC : ∀ p ∈ (a :: l).zip l, p.1.1 < p.2.1 ∧
      civilOf ((p.2.1 : Int) - 1 + p.1.2).toNat ≤ civilOf ((p.2.1 : Int) + p.2.2).toNat)
    (s s' : Nat) (ha : a.1 ≤ s) (h : s ≤ s') :
    civilOf ((s : Int) + offsetAt (a :: l) s).toNat ≤ civilOf ((s' : Int) + offsetAt (a :: l) s').toNat := by
  induction l generalizing a s with
  | nil =>
    rw [c11_offHead a [] s ha (by simp), c11_offHead a [] s' (by omega) (by simp)]
    exact c11_civI _ _ (by omega)
  | cons b rest ih =>
    have hab := hC (a, b) (by simp)
    have hC' : ∀ p ∈ (b :: rest).zip rest, p.1.1 < p.2.1 ∧
        civilOf ((p.2.1 : Int) - 1 + p.1.2).toNat ≤ civilOf ((p.2.1 : Int) + p.2.2).toNat :=
      fun p hp => hC p (List.mem_cons_of_mem _ hp)
    have hr := c11_lt rest b fun p hp => (hC' p hp).1
    by_cases h1 : b.1 ≤ s
    · rw [c11_offTail a b rest s h1, c11_offTail a b rest s' (by omega)]
      exact ih b hC' s h1 h
    · have hl : ∀ e ∈ b :: rest, s < e.1 := by
        intro e he
        rcases List.mem_cons.mp he with he | he
        · rw [he]; omega
        · have := hr e he; omega
      by_cases h2 : b.1 ≤ s'
      · have hb0 : offsetAt (b :: rest) b.1 = b.2 := c11_offHead b rest b.1 (Nat.le_refl _) hr
        rw [c11_offHead a (b :: rest) s ha hl, c11_offTail a b rest s' h2]
        calc civilOf ((s : Int) + a.2).toNat ≤ civilOf ((b.1 : Int) - 1 + a.2).toNat := c11_civI _ _ (by omega)
          _ ≤ civilOf ((b.1 : Int) + b.2).toNat := hab.2
          _ = civilOf ((b.1 : Int) + offsetAt (b :: rest) b.1).toNat := by rw [hb0]
          _ ≤ civilOf ((s' : Int) + offsetAt (b :: rest) s').toNat := ih b hC' b.1 (Nat.le_refl _) h2
      · have hl' : ∀ e ∈ b :: rest, s' < e.1 := by
          intro e he
          rcases List.mem_cons.mp he with he | he
          · rw [he]; omega
          · have := hr e he; omega
        rw [c11_offHead a (b :: rest) s ha hl, c11_offHead a (b :: rest) s' (by omega) hl']
        exact c11_civI _ _ (by omega)

theorem localDay_mono (tbl : OffsetTable) (hT : tableOk tbl = true) (s s' : Nat) (h : s ≤ s') :
    localDay tbl s ≤ localDay tbl s' := by
  simp only [tableOk, Bool.and_eq_true, List.all_eq_true] at hT
  obtain ⟨⟨h0, -⟩, hC⟩ := hT
  have hC' : ∀ p ∈ tbl.zip tbl.tail, p.1.1 < p.2.1 ∧
      civilOf ((p.2.1 : Int) - 1 + p.1.2).toNat ≤ civilOf ((p.2.1 : Int) + p.2.2).toNat := by
    rintro ⟨p1, p2⟩ hp
    have hp' := hC _ hp
    simp only [decide_eq_true_eq] at hp'
    exact hp'
  cases tbl with
  | nil => simp at h0
  | cons a l =>
    have ha : a.1 = 0 := by simpa using h0
    unfold localDay
    exact c11_seg l a hC' s s' (by omega) h

/-- Custody signs only within `eps` seconds of its own clock reading `secs`; Lean decides on `localDay tbl secs`. -/
def eps : Nat := 120

/-! ### 8b. Order independence (fix 6) -/

private theorem pm_view (t : Nat) (s : Snapshot Line) : view t s (some s) = s := by
  unfold view; split <;> rfl

private theorem pm_all_self (l : List Line) : l.all l.contains = true := by simp

private theorem pm_chained (t : Nat) (s s' : Snapshot Line) (h1 : s.entries.Perm s'.entries)
    (h2 : s.count = s'.count) (h3 : s.asOf = s'.asOf) :
    chained t s (some s) = chained t s' (some s') := by
  simp only [chained, pm_all_self, h1.length_eq, h2, h3]

private theorem pm_loose (t : Nat) (s : Snapshot Line) : loose t s (some s) = [] := by
  unfold loose; split
  · rfl
  · simp [entries]

private theorem pm_relSet (c₀ : Ctx) (rel unr : Snapshot Line) :
    releasedSet (carried c₀ rel unr) = rel.entries := by
  simp [releasedSet, carried, pm_view]

private theorem pm_unrSet (c₀ : Ctx) (rel unr : Snapshot Line) :
    unresolvedSet (carried c₀ rel unr) = unr.entries := by
  simp [unresolvedSet, carried, pm_view]

private theorem pm_own (c₀ : Ctx) (rel unr rel' unr' : Snapshot Line) (hr : rel.entries.Perm rel'.entries)
    (l : Line) : own (carried c₀ rel unr) l = own (carried c₀ rel' unr') l := by
  simp only [own, pm_relSet, hr.contains_eq]
  rfl

private theorem pm_claim_gen (c c' : Ctx) (h1 : c.today = c'.today) (h5 : c.enrollment = c'.enrollment)
    (l : Line) (ho : own c l = own c' l) : claim c l = claim c' l := by
  have hne : notEnrolled c l = notEnrolled c' l := by
    clear ho
    cases c; cases c'
    simp only at h1 h5
    subst h1 h5
    simp only [notEnrolled, certain, enrolled]
  unfold claim
  by_cases hcnd : (isCap l && notEnrolled c l && !own c l) = true
  · have h2 : (isCap l && notEnrolled c' l && !own c' l) = true := by rw [← hne, ← ho]; exact hcnd
    rw [if_pos hcnd, if_pos h2]
  · have h2 : ¬ (isCap l && notEnrolled c' l && !own c' l) = true := by rw [← hne, ← ho]; exact hcnd
    rw [if_neg hcnd, if_neg h2]

private theorem pm_fires (c c' : Ctx) (h1 : c.today = c'.today) (h2 : c.dmf = c'.dmf)
    (h3 : c.providerDeaths = c'.providerDeaths) (h4 : c.exclusions = c'.exclusions)
    (h5 : c.enrollment = c'.enrollment)
    (h6 : chained c.today c.releasedPrior c.released = chained c'.today c'.releasedPrior c'.released)
    (h7 : chained c.today c.unresolvedPrior c.unresolved = chained c'.today c'.unresolvedPrior c'.unresolved)
    (hp : ∀ x, (pending c).contains x = (pending c').contains x) (hl : looseKeys c = looseKeys c')
    (seen seen' : List Key) (hs : ∀ x, seen.contains x = seen'.contains x) (l : Line) (r : Reason) :
    fires c seen l r = fires c' seen' l r := by
  cases c; cases c'
  simp only at h1 h2 h3 h4 h5 h6 h7
  subst h1 h2 h3 h4 h5
  cases r <;> simp only [fires, certain, unverified, notEnrolled, enrolled, overlap, memberDead,
    providerDead, excluded, h6, h7, hp, hl, hs]

private def pmP (d : Decision) : Line × Outcome × List Reason := (d.line, d.outcome, d.reasons)

private abbrev pmS (d : Decision) : Decision := { d with counterparts := [] }

private theorem pm_decideAll (c c' : Ctx)
    (hf : ∀ seen seen', (∀ x, seen.contains x = seen'.contains x) → ∀ l r, fires c seen l r = fires c' seen' l r)
    (hcl : ∀ l, claim c l = claim c' l) :
    ∀ (ls : List Line) (seen seen' : List Key), (∀ x, seen.contains x = seen'.contains x) →
      (decideAll c seen ls).map pmP = (decideAll c' seen' ls).map pmP := by
  intro ls
  induction ls with
  | nil => intros; rfl
  | cons l ls ih =>
    intro seen seen' hs
    have hfl : fires c seen l = fires c' seen' l := funext (hf seen seen' hs l)
    have := ih (claim c l ++ seen) (claim c' l ++ seen') (by intro x; rw [List.contains_append, List.contains_append, hs x, hcl])
    simp only [decideAll, List.map_cons, decideLine, pmP, hfl]
    rw [this]

private theorem pm_strip : ∀ ds ds' : List Decision, ds.map pmP = ds'.map pmP → ds.map pmS = ds'.map pmS := by
  intro ds
  induction ds with
  | nil => intro ds' h; cases ds' with
    | nil => rfl
    | cons _ _ => simp at h
  | cons d ds ih => intro ds' h; cases ds' with
    | nil => simp at h
    | cons d' ds' =>
      simp only [List.map_cons, List.cons.injEq] at h ⊢
      refine ⟨?_, ih _ h.2⟩
      obtain ⟨h1, _⟩ := h
      cases d; cases d'
      simp only [pmP, pmS, Prod.mk.injEq] at h1 ⊢
      obtain ⟨a, b, c⟩ := h1
      subst a b c
      rfl


private theorem pm_payOutcome_strip (c : Ctx) (ds : List Decision) (p : Nat) :
    payOutcome c (ds.map pmS) p = payOutcome c ds p := by
  simp [payOutcome, pmS, List.filter_map, Function.comp_def]

private theorem pm_pays_strip (c : Ctx) (ds : List Decision) : paysOf c (ds.map pmS) = paysOf c ds := by
  simp [paysOf, pm_payOutcome_strip, pmS, List.filter_map, Function.comp_def, List.map_map]

private theorem pm_rl_strip (c : Ctx) (ds : List Decision) : releasedLines c (ds.map pmS) = releasedLines c ds := by
  simp [releasedLines, allowedLines, pm_payOutcome_strip, pmS, List.filter_map, Function.comp_def, List.map_map]

private theorem pm_ul_strip (c : Ctx) (ds : List Decision) : unresolvedLines c (ds.map pmS) = unresolvedLines c ds := by
  simp [unresolvedLines, pmS, List.filter_map, Function.comp_def, List.map_map]

private theorem pm_payOutcome_c (c c' : Ctx) (hr : c.redo = c'.redo) (ho : ∀ l, own c l = own c' l)
    (ds : List Decision) (p : Nat) : payOutcome c ds p = payOutcome c' ds p := by
  simp only [payOutcome, hr, ho]

private theorem pm_three (c c' : Ctx) (ds ds' : List Decision) (hr : c.redo = c'.redo)
    (ho : ∀ l, own c l = own c' l) (h : ds.map pmP = ds'.map pmP) :
    releasedLines c ds = releasedLines c' ds' ∧ unresolvedLines c ds = unresolvedLines c' ds' ∧
      paysOf c ds = paysOf c' ds' := by
  have hs := pm_strip _ _ h
  refine ⟨?_, ?_, ?_⟩
  · rw [← pm_rl_strip c ds, hs, pm_rl_strip]
    simp only [releasedLines, hr, pm_payOutcome_c c c' hr ho]
  · rw [← pm_ul_strip c ds, hs, pm_ul_strip]
    simp only [unresolvedLines, ho]
  · rw [← pm_pays_strip c ds, hs, pm_pays_strip]
    simp only [paysOf, pm_payOutcome_c c c' hr ho]

private theorem pm_viewc (c₀ : Ctx) (rel unr : Snapshot Line) :
    view (carried c₀ rel unr).today (carried c₀ rel unr).releasedPrior (carried c₀ rel unr).released = rel :=
  pm_view _ _

private theorem pm_viewu (c₀ : Ctx) (rel unr : Snapshot Line) :
    view (carried c₀ rel unr).today (carried c₀ rel unr).unresolvedPrior (carried c₀ rel unr).unresolved = unr :=
  pm_view _ _

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
    paysOf (carried c₀ rel unr) r.decisions = paysOf (carried c₀ rel' unr') r'.decisions := by
  obtain ⟨hcr, hcu, har, hau⟩ := hc
  have ho : ∀ l, own (carried c₀ rel unr) l = own (carried c₀ rel' unr') l := pm_own c₀ rel unr rel' unr' hr
  have hcl : ∀ l, claim (carried c₀ rel unr) l = claim (carried c₀ rel' unr') l :=
    fun l => pm_claim_gen (carried c₀ rel unr) (carried c₀ rel' unr') rfl rfl l (ho l)
  have hpend : ∀ x, (pending (carried c₀ rel unr)).contains x = (pending (carried c₀ rel' unr')).contains x := by
    intro x
    have hc2 : claim (carried c₀ rel' unr') = claim (carried c₀ rel unr) := funext fun l => (hcl l).symm
    simp only [pending, pm_unrSet, hc2]
    exact (List.Perm.flatMap_right _ hu).contains_eq
  have hloose : ∀ (a b : Snapshot Line), looseKeys (carried c₀ a b) = [] := by
    intro a b; simp [looseKeys, carried, pm_loose]
  have hchR : chained (carried c₀ rel unr).today (carried c₀ rel unr).releasedPrior (carried c₀ rel unr).released =
      chained (carried c₀ rel' unr').today (carried c₀ rel' unr').releasedPrior (carried c₀ rel' unr').released :=
    pm_chained c₀.today rel rel' hr hcr har
  have hchU : chained (carried c₀ rel unr).today (carried c₀ rel unr).unresolvedPrior (carried c₀ rel unr).unresolved =
      chained (carried c₀ rel' unr').today (carried c₀ rel' unr').unresolvedPrior (carried c₀ rel' unr').unresolved :=
    pm_chained c₀.today unr unr' hu hcu hau
  have hf : ∀ seen seen', (∀ x, seen.contains x = seen'.contains x) → ∀ l r,
      fires (carried c₀ rel unr) seen l r = fires (carried c₀ rel' unr') seen' l r :=
    fun seen seen' hs l r => pm_fires (carried c₀ rel unr) (carried c₀ rel' unr') rfl rfl rfl rfl rfl hchR hchU hpend
      ((hloose _ _).trans (hloose _ _).symm) seen seen' hs l r
  have hdec := pm_decideAll _ _ hf hcl
  have hord : order (carried c₀ rel unr) (ready k os b) = order (carried c₀ rel' unr') (ready k os b) := by
    have hown : own (carried c₀ rel unr) = own (carried c₀ rel' unr') := funext ho
    simp only [order, hown]
  have hseen0 : ∀ x, (idSeen (foreignOf k os (ready k os b)) ++ seen0 (carried c₀ rel unr) (ready k os b)).contains x =
      (idSeen (foreignOf k os (ready k os b)) ++ seen0 (carried c₀ rel' unr') (ready k os b)).contains x := by
    intro x
    rw [List.contains_append, List.contains_append]
    congr 1
    have : (seen0 (carried c₀ rel unr) (ready k os b)).Perm (seen0 (carried c₀ rel' unr') (ready k os b)) := by
      simp only [seen0, pm_relSet, ho]
      exact List.Perm.flatMap_right _ (hr.filter _)
    exact this.contains_eq
  have hD := hdec (order (carried c₀ rel unr) (ready k os b)) _ _ hseen0
  dsimp only
  simp only [decideRegT, bumpRes, decideReg, decideBatchIn]
  rw [← hord]
  generalize decideAll (carried c₀ rel unr) _ (order (carried c₀ rel unr) (ready k os b)) = ds at hD ⊢
  generalize decideAll (carried c₀ rel' unr') _ (order (carried c₀ rel unr) (ready k os b)) = ds' at hD ⊢
  obtain ⟨hRL, hUL, hP⟩ := pm_three (carried c₀ rel unr) (carried c₀ rel' unr') ds ds' rfl ho hD
  refine ⟨hD, ?_, ?_, ?_, ?_, ?_, ?_, hP⟩
  · simp only [advance, pm_viewc, hRL]; exact List.Perm.append_right _ hr
  · simp only [advance, pm_viewu, hUL]; exact List.Perm.append_right _ hu
  · simp only [advance, pm_viewc, hRL, hr.length_eq]
  · simp only [advance, pm_viewu, hUL, hu.length_eq]
  · simp only [advance, pm_viewc, bumpIf, hchR, har]; try rfl
  · simp only [advance, pm_viewu, bumpIf, hchU, hau]; try rfl

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
    (ts : List Batch) : runT k g ts = runT k g' ts := by
  induction ts generalizing g g' with
  | nil => rfl
  | cons t ts ih =>
    have h := decideRegT_perm t.ctx k t.owners t.lines g.1 g.2 g'.1 g'.2 hr hu hc
    dsimp only at h
    obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩ := h
    have hih := ih ((decideRegT (carried t.ctx g.1 g.2) k t.owners t.lines).released,
      (decideRegT (carried t.ctx g.1 g.2) k t.owners t.lines).unresolved)
      ((decideRegT (carried t.ctx g'.1 g'.2) k t.owners t.lines).released,
      (decideRegT (carried t.ctx g'.1 g'.2) k t.owners t.lines).unresolved) h2 h3 ⟨h4, h5, h6, h7⟩
    simp only [runT]
    rw [h1, h8, hih]

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
private theorem sv_shardSets_inv (k : Nat) :
    ∀ (g : Snapshot Line × Snapshot Line) (ts : List Batch), Inv g.1 g.2 →
      Inv (shardSets k g ts).1 (shardSets k g ts).2
  | _, [], h => h
  | g, t :: ts, h => sv_shardSets_inv k _ ts (sv_inv_reg t.ctx k t.owners t.lines g.1 g.2 h)

theorem v1_reach_inv (k : Nat) (ts : List Batch) :
    Inv (shardSets k (genesisSets 0) ts).1 (shardSets k (genesisSets 0) ts).2 :=
  sv_shardSets_inv k _ ts ⟨List.nodup_nil, rfl, rfl⟩


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

/-- Equal set digests: the same pin inputs, or a hash collision among them (`anchored_binding_witness`). -/
private theorem sv_digest_pins (hH : HashLen sha3) {a b r u : Snapshot Line} {D : Bytes}
    (h : setsDigest sha3 a b = some D) (h' : setsDigest sha3 r u = some D) :
    (∃ A B, pinInput "RR/GATE/RELEASED/v1" 5 Line.fields a = some A ∧
        pinInput "RR/GATE/RELEASED/v1" 5 Line.fields r = some A ∧
        pinInput "RR/GATE/UNRESOLVED/v1" 6 Line.fields b = some B ∧
        pinInput "RR/GATE/UNRESOLVED/v1" 6 Line.fields u = some B) ∨
      V1Collision sha3 a b r u := by
  unfold setsDigest setPins at h h'
  cases hA : pinInput "RR/GATE/RELEASED/v1" 5 Line.fields a <;>
    cases hB : pinInput "RR/GATE/UNRESOLVED/v1" 6 Line.fields b <;>
    cases hA' : pinInput "RR/GATE/RELEASED/v1" 5 Line.fields r <;>
    cases hB' : pinInput "RR/GATE/UNRESOLVED/v1" 6 Line.fields u <;>
    simp [hA, hB, hA', hB'] at h h'
  rename_i A B A' B'
  have e : stateDigest sha3 (sha3 A) (sha3 B) = stateDigest sha3 (sha3 A') (sha3 B') := h.trans h'.symm
  unfold stateDigest at e
  by_cases hq : domain "STATE" ++ sha3 A ++ sha3 B = domain "STATE" ++ sha3 A' ++ sha3 B'
  · obtain ⟨hq1, hq2⟩ := List.append_inj' hq (by rw [hH, hH])
    have hq3 := List.append_cancel_left hq1
    by_cases hAA : A = A'
    · by_cases hBB : B = B'
      · subst hAA hBB; exact Or.inl ⟨A, B, rfl, rfl, rfl, rfl⟩
      · exact Or.inr ⟨A, B, A', B', hA, hB, hA', hB', B, B', hBB, hq2, Or.inr (Or.inl rfl)⟩
    · exact Or.inr ⟨A, B, A', B', hA, hB, hA', hB', A, A', hAA, hq3, Or.inl rfl⟩
  · exact Or.inr ⟨A, B, A', B', hA, hB, hA', hB', _, _, hq, e, Or.inr (Or.inr rfl)⟩

/-- `canon` keeps the count and permutes the entries (stated through `canon.eq_1` so the kernel never unfolds
`List.mergeSort`). -/
private theorem sv_canon (s : Snapshot Line) : (canon s).count = s.count ∧ (canon s).entries.Perm s.entries :=
  have e : ∀ (a c : Nat) (E : List Line), (Snapshot.mk a c E).count = c ∧ (Snapshot.mk a c E).entries = E :=
    fun _ _ _ => ⟨rfl, rfl⟩
  ⟨(congrArg Snapshot.count (canon.eq_1 s)).trans (e _ _ _).1,
    Eq.mpr (congrArg (List.Perm · s.entries) ((congrArg Snapshot.entries (canon.eq_1 s)).trans (e _ _ _).2))
      (List.mergeSort_perm _ _)⟩

/-- Redating sets that permute `(r, u)` with equal counts keeps `Inv` and the run. -/
private theorem sv_redate_bind (k m : Nat) {a b r u : Snapshot Line} (ha : a.entries.Perm r.entries)
    (hb : b.entries.Perm u.entries) (hc : a.count = r.count) (hd : b.count = u.count) (hi : Inv r u)
    (ts : List Batch) :
    (redate m (a, b)).1.entries.Perm r.entries ∧ (redate m (a, b)).2.entries.Perm u.entries ∧
      Inv (redate m (a, b)).1 (redate m (a, b)).2 ∧ runT k (redate m (a, b)) ts = runT k (redate m (r, u)) ts :=
  ⟨ha, hb, ⟨((ha.append hb).map _).nodup_iff.mpr hi.1, hc.trans (hi.2.1.trans ha.length_eq.symm),
    hd.trans (hi.2.2.trans hb.length_eq.symm)⟩, runT_perm k (redate m (a, b)) (redate m (r, u)) ha hb ⟨hc, hd, rfl, rfl⟩ ts⟩

/-- RESTATED (review: m pinned): the activation sets are the true v1 sets up to order, dated by the tip's
    createdAt, and every later batch decides and pays as on the true sets; else a v1 collision. -/
theorem migrate_binds (hH : HashLen sha3) (P : Pins) (k : Nat) (p : Permit) (b cert : Bytes)
    (hp : p.tip = some (b, cert)) (g : Snapshot Line × Snapshot Line) (hg : activation P k p = some g)
    (r u : Snapshot Line) (hi : Inv r u) (n : Stored) (hn : storedOfAny sha3 b = some n)
    (hd : setsDigest sha3 r u = some n.checkpoint.stateDigest) (ts : List Batch) :
    (g.1.entries.Perm r.entries ∧ g.2.entries.Perm u.entries ∧ Inv g.1 g.2 ∧
       runT k g ts = runT k (redate (localDay P.tbl n.checkpoint.createdAt) (r, u)) ts) ∨
      V1Collision sha3 p.rel p.unr r u := by
  obtain ⟨⟨hS, -⟩, rfl⟩ :
      (setsDigest sha3 p.rel p.unr = some n.checkpoint.stateDigest ∧ invB p.rel p.unr = true) ∧
        redate (localDay P.tbl n.checkpoint.createdAt) (canon p.rel, canon p.unr) = g := by
    simp only [activation, hp, hn, Option.bind_eq_bind, Option.bind_some, guard] at hg
    repeat' split at hg
    all_goals first | (cases hg; done) | exact ⟨‹_›, Option.some.inj hg⟩
  rcases sv_digest_pins hH hS hd with ⟨A, B, hA, hA', hB, hB'⟩ | hc
  · obtain ⟨-, rc, rp⟩ := pinInput_lines hA hA'
    obtain ⟨-, uc, up⟩ := pinInput_lines hB hB'
    exact Or.inl (sv_redate_bind k _ ((sv_canon _).2.trans rp) ((sv_canon _).2.trans up)
      ((sv_canon _).1.trans rc) ((sv_canon _).1.trans uc) hi ts)
  · exact Or.inr hc

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

theorem guard_some (c : Prop) [Decidable c] (x : Unit) : (guard c : Option Unit) = some x ↔ c := by
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

/-- custodyOk's binds: the batch, Lean's output on the shard base, the read set, the stored checkpoint carrying
    Lean's digest, the token check on the rows custody built, and the sign body with Lean's fresh rows. -/
theorem c15_peel (P : Pins) (st : LogState) (k : Nat) (cert : Bytes) (i : SignIn) (new : Bytes)
    (tokens : List Bytes) (e : Entry) (h : custodyOk P st k cert i new tokens = some e) :
    ∃ (rs : List Request) (bt : Batch) (o : OutV2) (rset : Bytes) (n : Stored), batchAt P st k i = some (rs, bt) ∧
      decideIdx sha3 bt.ctx k bt.owners bt.lines (st.shard k).base i.witness = some o ∧
      readSetOf i.ctx (st.shard k).base = some rset ∧ storedOfAny sha3 new = some n ∧
      n.checkpoint.stateDigest = o.digest ∧
      tokensOk P.c i.secs ((i.reqs.zip rs).filterMap (rowOf (revAt (st.shard k) i.ctx.redo) o.pays
        (o.decisions.map fun x => (x.line, x.outcome, x.reasons)) rset)) tokens = true ∧
      e.body = .sign cert new tokens o.fresh := by
  unfold custodyOk at h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨⟨rs, bt⟩, hbt, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨o, ho, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨rset, hrs, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨n, hn, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, g1, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, g3, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  have he := Option.some.inj h
  subst he
  exact ⟨rs, bt, o, rset, n, hbt, ho, hrs, hn, ((guard_some _ _).mp g1).2.2, (guard_some _ _).mp g3, rfl⟩

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
       Collision sha3 (witnessInputs sha3 bt.ctx k bt.owners bt.lines i.witness) (stateInputs sha3 rel unr)) := by
  obtain ⟨rs, bt, o, rset, n, hbt, ho, hrs, hn, hdg, htk, hbody⟩ := c15_peel P st k cert i new tokens e h
  obtain ⟨hh, ha, hd⟩ := Option.bind_eq_some_iff.mp hb.symm
  refine ⟨rs, bt, rset, n, hbt, hrs, hn, ?_⟩
  rcases decideIdx_refines sha3 hH bt.ctx k bt.owners bt.lines rel unr hi hh ha _ hd i.witness o ho with
    ⟨hdec, -, -, hfr, hpays, hhd, hdo⟩ | hc
  · left
    intro cc r rows
    rw [hpays, hdec] at htk
    unfold tokensOk at htk
    simp only [Bool.and_eq_true, beq_iff_eq, List.isPerm_iff] at htk
    refine ⟨⟨o.head, hhd, by rw [hdg]; exact hdo⟩, htk.2, htk.1, ?_⟩
    rw [hbody, hfr]
  · exact Or.inr hc


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
    simp [hb, Option.bind_eq_some_iff, guard_some] at h
    obtain ⟨hg, a, _, _, rfl⟩ := h
    exact ⟨hg.1, rfl, fun j hj => by simp [upd, hj], fun _ => by simp [upd], fun _ _ _ _ h => by cases h⟩
  | resume p =>
    simp [hb, Option.bind_eq_some_iff, guard_some] at h
    obtain ⟨hg, a, _, _, _, _, _, _, _, _, _, _, _, rfl⟩ := h
    exact ⟨hg.1, rfl, fun j hj => by simp [upd, hj], fun _ => by simp [upd], fun _ _ _ _ h => by cases h⟩
  | sign cert new tokens fresh =>
    simp [hb, Option.bind_eq_some_iff, guard_some] at h
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
  exact ⟨rfl, ⟨_, rfl⟩, Option.isSome_iff_exists.mp ((guard_some _ _).mp hp)⟩

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
    simp [hb, Option.bind_eq_some_iff, guard_some] at h
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

private theorem c15_mapM_idx {α β : Type} (F : α → Option β) :
    ∀ (xs : List α) (ys : List β) (i : Nat) (x : α), xs.mapM F = some ys → xs[i]? = some x →
      ∃ y, F x = some y ∧ ys[i]? = some y
  | [], _, _, _, _, hx => by simp at hx
  | a :: xs, ys, i, x, h, hx => by
    rw [List.mapM_cons] at h
    obtain ⟨y, hy, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨ys', hys', h⟩ := Option.bind_eq_some_iff.mp h
    have he := Option.some.inj h
    subst he
    cases i with
    | zero =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at hx
      subst hx
      exact ⟨y, hy, by simp⟩
    | succ i =>
      simp only [List.getElem?_cons_succ] at hx
      obtain ⟨z, hz, hz'⟩ := c15_mapM_idx F xs ys' i x hys' hx
      exact ⟨z, hz, by simpa using hz'⟩

/-- chain (a): the i-th batch is batchAt on the fold of the log before the i-th signed. -/
private theorem c15_hb_idx (P : Pins) (log : List Entry) (k : Nat) (hist : List (Bytes × SignIn × Entry))
    (bs : List Batch) (h : histBatches P log k hist = some bs) (i : Nat) (x : Bytes × SignIn × Entry)
    (hx : hist[i]? = some x) :
    ∃ (st : LogState) (rs : List Request) (b : Batch), fold P (log.take x.2.2.idx) = some st ∧
      batchAt P st k x.2.1 = some (rs, b) ∧ bs[i]? = some b := by
  unfold histBatches at h
  obtain ⟨b, hF, hb⟩ := c15_mapM_idx _ hist bs i x h hx
  obtain ⟨st, hst, hF⟩ := Option.bind_eq_some_iff.mp hF
  obtain ⟨⟨rs, b'⟩, hbt, hF⟩ := Option.bind_eq_some_iff.mp hF
  have he := Option.some.inj hF
  subst he
  exact ⟨st, rs, b', hst, hbt, hb⟩

/-- chain (a): MadeBy makes histBatches defined (each custodyOk ran batchAt on its prefix fold). -/
private theorem c15_hb_some (P : Pins) (log : List Entry) (k : Nat) (hist : List (Bytes × SignIn × Entry))
    (hm : MadeBy P log k hist) : ∃ bs, histBatches P log k hist = some bs := by
  unfold histBatches
  exact c8_mapM_some _ hist fun x hx => by
    obtain ⟨st, new, tokens, hst, hc⟩ := hm.2 x hx
    obtain ⟨rs, bt, _, _, _, hbt, _⟩ := c15_peel P st k x.1 x.2.1 new tokens x.2.2 hc
    exact ⟨bt, by simp [hst, hbt]⟩

/-- push on its own shard: seal and resume need it not live; resume makes it live on the activation base; sign
    needs it live, keeps it live and sets the base to the checkpoint's state digest. -/
private theorem c16_push_k (P : Pins) (s s' : LogState) (e : Entry) (h : push P s e = some s') :
    (∀ t, e.body = .seal t → (s.shard e.shard).live = false) ∧
    (∀ p, e.body = .resume p → (s.shard e.shard).live = false ∧ (s'.shard e.shard).live = true ∧
      ∃ g, activation P e.shard p = some g ∧
        some (s'.shard e.shard).base = (headOf sha3 g.1 g.2).bind (digestV2 sha3)) ∧
    (∀ cert new tokens f, e.body = .sign cert new tokens f → (s.shard e.shard).live = true ∧
      (s'.shard e.shard).live = true ∧
      ∃ n, storedOfAny sha3 new = some n ∧ (s'.shard e.shard).base = n.checkpoint.stateDigest) := by
  unfold push at h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  refine ⟨fun t hb => ?_, fun p hb => ?_, fun cert new tokens f hb => ?_⟩
  · rw [hb] at h
    obtain ⟨_, hg, -⟩ := Option.bind_eq_some_iff.mp h
    exact ((guard_some _ _).mp hg).2.2.2.2
  · rw [hb] at h
    obtain ⟨_, hg, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨g, hact, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨hd, hhd, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨base, hbase, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨sh', hsh, h⟩ := Option.bind_eq_some_iff.mp h
    have hs : s'.shard e.shard = sh' := by rw [← Option.some.inj h]; simp [upd]
    rw [← Option.some.inj hsh] at hs
    refine ⟨((guard_some _ _).mp hg).1, by simp only [hs], g, hact, ?_⟩
    rw [hs, hhd]
    exact hbase.symm
  · rw [hb] at h
    obtain ⟨_, hg, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨⟨_, _⟩, -, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨n, hn, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨sh', hsh, h⟩ := Option.bind_eq_some_iff.mp h
    have hs : s'.shard e.shard = sh' := by rw [← Option.some.inj h]; simp [upd]
    rw [← Option.some.inj hsh] at hs
    exact ⟨(guard_some _ _).mp hg, by simp only [hs]; exact (guard_some _ _).mp hg, n, hn, by simp only [hs]⟩

/-- A live shard stays live: no push sets live to false. -/
private theorem c16_live (P : Pins) (s s' : LogState) (e : Entry) (h : push P s e = some s') (j : Nat)
    (hl : (s.shard j).live = true) : (s'.shard j).live = true := by
  by_cases hj : j = e.shard
  · subst hj
    obtain ⟨h1, h2, h3⟩ := c16_push_k P s s' e h
    cases hb : e.body with
    | «seal» t => rw [h1 t hb] at hl; cases hl
    | resume p => exact (h2 p hb).2.1
    | sign cert new tokens f => exact (h3 cert new tokens f hb).2.1
  · rw [(cust_push P s s' e h).2.2.1 j hj]; exact hl

/-- The entry at position m of a log: the prefix before it folds and pushes it, and its index is m. -/
private theorem c16_step (P : Pins) (log : List Entry) (m : Nat) (e : Entry) (hm : log[m]? = some e)
    (s' : LogState) (h : fold P (log.take (m + 1)) = some s') :
    ∃ s, fold P (log.take m) = some s ∧ push P s e = some s' ∧ e.idx = m := by
  have hlt : m < log.length := (List.getElem?_eq_some_iff.mp hm).1
  have ht : log.take (m + 1) = log.take m ++ [e] := by simp [List.take_add_one, hm]
  rw [ht] at h
  obtain ⟨s, h1, h2⟩ := (cust_fold_snoc P _ e s').mp h
  refine ⟨s, h1, h2, ?_⟩
  rw [(cust_push P s s' e h2).1, cust_fold_len P _ s h1, List.length_take]
  omega

private theorem c16_live_mono (P : Pins) (log : List Entry) (k m : Nat) (s : LogState)
    (hs : fold P (log.take m) = some s) (hl : (s.shard k).live = true) :
    ∀ (d : Nat) (s' : LogState), fold P (log.take (m + d)) = some s' → (s'.shard k).live = true
  | 0, s', h => by
    rw [Nat.add_zero, hs] at h
    rw [← Option.some.inj h]; exact hl
  | d + 1, s', h => by
    cases hm : log[m + d]? with
    | none =>
      have hle := List.getElem?_eq_none_iff.mp hm
      have e1 : log.take (m + (d + 1)) = log.take (m + d) := by
        rw [List.take_of_length_le hle]; exact List.take_of_length_le (by omega)
      rw [e1] at h
      exact c16_live_mono P log k m s hs hl d s' h
    | some e =>
      obtain ⟨s0, h0, hp, -⟩ := c16_step P log (m + d) e hm s' (by rw [← Nat.add_assoc] at h; exact h)
      exact c16_live P s0 s' e hp k (c16_live_mono P log k m s hs hl d s0 h0)

private theorem c16_filter_take {α : Type} (f : α → Bool) (l : List α) (m : Nat) :
    (l.take m).filter f = (l.filter f).take ((l.take m).filter f).length := by
  have h : l.filter f = (l.take m).filter f ++ (l.drop m).filter f := by
    rw [← List.filter_append, List.take_append_drop]
  rw [h, List.take_append_length]

private theorem c16_cnt0 {α : Type} (f : α → Bool) (l : List α) (m : Nat) (e : α) (hm : l[m]? = some e)
    (hf : f e = false) : ((l.take (m + 1)).filter f).length = ((l.take m).filter f).length := by
  have ht : l.take (m + 1) = l.take m ++ [e] := by simp [List.take_add_one, hm]
  rw [ht, List.filter_append]; simp [hf]

private theorem c16_cnt1 {α : Type} (f : α → Bool) (l : List α) (m : Nat) (e : α) (hm : l[m]? = some e)
    (hf : f e = true) : ((l.take (m + 1)).filter f).length = ((l.take m).filter f).length + 1 := by
  have ht : l.take (m + 1) = l.take m ++ [e] := by simp [List.take_add_one, hm]
  rw [ht, List.filter_append]; simp [hf]

/-- A kept entry at position m sits in the filter at the count kept before m. -/
private theorem c16_pos {α : Type} (f : α → Bool) (l : List α) (m : Nat) (e : α) (hm : l[m]? = some e)
    (hf : f e = true) : (l.filter f)[((l.take m).filter f).length]? = some e := by
  have h1 := c16_filter_take f l (m + 1)
  have ht : l.take (m + 1) = l.take m ++ [e] := by simp [List.take_add_one, hm]
  rw [ht, List.filter_append, List.filter_cons_of_pos hf, List.filter_nil] at h1
  rw [← List.getElem?_take_of_lt (i := ((l.take m).filter f).length)
    (j := ((l.take m).filter f ++ [e]).length) (by simp), ← h1]
  exact List.getElem?_concat_length

/-- chain (d): Inv holds along shardSetsT. -/
private theorem c16_inv (k : Nat) : ∀ (ts : List Batch) (g : Snapshot Line × Snapshot Line),
    Inv g.1 g.2 → Inv (shardSetsT k g ts).1 (shardSetsT k g ts).2
  | [], _, h => h
  | t :: ts, g, h => c16_inv k ts ((decideRegT (carried t.ctx g.1 g.2) k t.owners t.lines).released,
      (decideRegT (carried t.ctx g.1 g.2) k t.owners t.lines).unresolved)
      (inv_step t.ctx k t.owners t.lines g.1 g.2 h)

/-- Shard-k signed entries among the first m log entries. -/
private def c16cnt (log : List Entry) (k m : Nat) : Nat :=
  ((log.take m).filter (fun e => e.shard == k && e.body.signed?.isSome)).length

/-- custodyOk dates the batch by the checkpoint it stores. -/
private theorem c16_today (P : Pins) (st : LogState) (k : Nat) (cert : Bytes) (i : SignIn) (new : Bytes)
    (tokens : List Bytes) (e : Entry) (h : custodyOk P st k cert i new tokens = some e) (rs : List Request)
    (bt : Batch) (hbt : batchAt P st k i = some (rs, bt)) (n : Stored) (hn : storedOfAny sha3 new = some n) :
    localDay P.tbl n.checkpoint.createdAt = bt.ctx.today := by
  unfold custodyOk at h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨⟨_, _⟩, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨n', hn', h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨_, g2, -⟩ := Option.bind_eq_some_iff.mp h
  rw [hn] at hn'
  rw [Option.some.inj hn', ((guard_some _ _).mp g2).1]
  unfold batchAt at hbt
  obtain ⟨_, -, hbt⟩ := Option.bind_eq_some_iff.mp hbt
  obtain ⟨_, -, hbt⟩ := Option.bind_eq_some_iff.mp hbt
  exact congrArg (fun b : Batch => b.ctx.today) (Prod.mk.inj (Option.some.inj hbt)).2

/-- chain_sound's left disjunct at step i, with the fresh rows and the date rebuild_sound replays. -/
private abbrev c16G (P : Pins) (k : Nat) (g : Snapshot Line × Snapshot Line)
    (hist : List (Bytes × SignIn × Entry)) (bs : List Batch) (i : Nat) : Prop :=
  (∀ (x : Bytes × SignIn × Entry) (new : Bytes), hist[i]? = some x → x.2.2.body.signed? = some new →
    ∃ (n : Stored) (hd : Head), storedOfAny sha3 new = some n ∧
      headOf sha3 (shardSetsT k g (bs.take (i + 1))).1 (shardSetsT k g (bs.take (i + 1))).2 = some hd ∧
      digestV2 sha3 hd = some n.checkpoint.stateDigest) ∧
  ∀ (x : Bytes × SignIn × Entry) cert new tokens f (b : Batch), hist[i]? = some x →
    x.2.2.body = .sign cert new tokens f → bs[i]? = some b →
    f = batchFresh (carried b.ctx (shardSetsT k g (bs.take i)).1 (shardSetsT k g (bs.take i)).2)
      (decideRegT (carried b.ctx (shardSetsT k g (bs.take i)).1 (shardSetsT k g (bs.take i)).2) k b.owners
        b.lines) ∧
    ∃ n, storedOfAny sha3 new = some n ∧ localDay P.tbl n.checkpoint.createdAt = b.ctx.today

/-- chain_sound's collision at step i. -/
private abbrev c16C (k : Nat) (g : Snapshot Line × Snapshot Line) (hist : List (Bytes × SignIn × Entry))
    (bs : List Batch) (i : Nat) : Prop :=
  ∃ (x : Bytes × SignIn × Entry) (b : Batch), hist[i]? = some x ∧ bs[i]? = some b ∧
    Collision sha3 (witnessInputs sha3 b.ctx k b.owners b.lines x.2.1.witness)
      (stateInputs sha3 (shardSetsT k g (bs.take i)).1 (shardSetsT k g (bs.take i)).2)

/-- chain (b, c, e) by induction on the log prefix: before the resume no shard-k signed; after it the shard is
    live and every signed so far is good with the base the digest of the true sets so far, or a collision. -/
private theorem c16_chain (hH : HashLen sha3) (P : Pins) (log : List Entry) (k : Nat)
    (hist : List (Bytes × SignIn × Entry)) (hm : MadeBy P log k hist) (er : Entry) (p : Permit)
    (her : log[er.idx]? = some er) (hk : er.shard = k) (hp : er.body = .resume p)
    (g : Snapshot Line × Snapshot Line) (hg : activation P k p = some g) (hi : Inv g.1 g.2) (bs : List Batch)
    (hbs : histBatches P log k hist = some bs)
    (hpre : ∀ m s, m ≤ er.idx → fold P (log.take m) = some s → (s.shard k).live = false) :
    ∀ m s, fold P (log.take m) = some s → (m ≤ er.idx → c16cnt log k m = 0) ∧
      (er.idx < m → (s.shard k).live = true ∧
        (((∀ i < c16cnt log k m, c16G P k g hist bs i) ∧
          some (s.shard k).base = (headOf sha3 (shardSetsT k g (bs.take (c16cnt log k m))).1
            (shardSetsT k g (bs.take (c16cnt log k m))).2).bind (digestV2 sha3)) ∨
         ∃ i < c16cnt log k m, c16C k g hist bs i)) := by
  intro m
  induction m with
  | zero =>
    intro s _
    exact ⟨fun _ => rfl, fun h => absurd h (Nat.not_lt_zero _)⟩
  | succ m ih =>
    intro s' hs'
    cases hme : log[m]? with
    | none =>
      have hle := List.getElem?_eq_none_iff.mp hme
      have hlt : er.idx < log.length := (List.getElem?_eq_some_iff.mp her).1
      have e1 : log.take (m + 1) = log.take m := by
        rw [List.take_of_length_le hle]; exact List.take_of_length_le (by omega)
      have hc : c16cnt log k (m + 1) = c16cnt log k m := by unfold c16cnt; rw [e1]
      rw [e1] at hs'
      rw [hc]
      exact ⟨fun h => absurd h (by omega), fun _ => (ih s' hs').2 (by omega)⟩
    | some e =>
      obtain ⟨s, hs, hpu, hei⟩ := c16_step P log m e hme s' hs'
      obtain ⟨ih1, ih2⟩ := ih s hs
      obtain ⟨hseal, hres, hsign⟩ := c16_push_k P s s' e hpu
      have hee : er.idx = m → e = er := fun h => by
        rw [h, hme] at her; exact Option.some.inj her
      by_cases hek : e.shard = k
      · cases hb : e.body with
        | «seal» t =>
          have hl := hseal t hb
          rw [hek] at hl
          have hc : c16cnt log k (m + 1) = c16cnt log k m :=
            c16_cnt0 (fun e : Entry => e.shard == k && e.body.signed?.isSome) log m e hme
              (by simp [hb, Body.signed?])
          rw [hc]
          refine ⟨fun h => ih1 (by omega), fun h => ?_⟩
          have hne : er.idx ≠ m := fun h' => by rw [hee h', hp] at hb; cases hb
          rw [(ih2 (by omega)).1] at hl; cases hl
        | resume p' =>
          obtain ⟨hl, hl', g', hact, hbase⟩ := hres p' hb
          rw [hek] at hl hl' hact hbase
          have hc : c16cnt log k (m + 1) = c16cnt log k m :=
            c16_cnt0 (fun e : Entry => e.shard == k && e.body.signed?.isSome) log m e hme
              (by simp [hb, Body.signed?])
          rw [hc]
          have hge : m ≤ er.idx := by
            cases Nat.lt_or_ge er.idx m with
            | inl h => rw [(ih2 h).1] at hl; cases hl
            | inr h => exact h
          have hle : er.idx ≤ m := by
            cases Nat.lt_or_ge m er.idx with
            | inl h => rw [hpre (m + 1) s' h hs'] at hl'; cases hl'
            | inr h => exact h
          rw [hee (Nat.le_antisymm hle hge), hp] at hb
          rw [← Body.resume.inj hb, hg] at hact
          rw [← Option.some.inj hact] at hbase
          have h0 : c16cnt log k m = 0 := ih1 hge
          refine ⟨fun _ => h0, fun _ => ⟨hl', Or.inl ⟨fun i hi' => absurd hi' (by omega), ?_⟩⟩⟩
          rw [h0]
          exact hbase
        | sign cert new tokens f =>
          obtain ⟨hl, hl', n', hn', hbase'⟩ := hsign cert new tokens f hb
          rw [hek] at hl hl' hbase'
          have hfe : (e.shard == k && e.body.signed?.isSome) = true := by simp [hek, hb, Body.signed?]
          have hc : c16cnt log k (m + 1) = c16cnt log k m + 1 :=
            c16_cnt1 (fun e : Entry => e.shard == k && e.body.signed?.isSome) log m e hme hfe
          rw [hc]
          have hlt : er.idx < m := by
            cases Nat.lt_or_ge er.idx m with
            | inl h => exact h
            | inr h => rw [hpre m s h hs] at hl; cases hl
          refine ⟨fun h => absurd h (by omega), fun _ => ⟨hl', ?_⟩⟩
          have hpos := c16_pos (fun e : Entry => e.shard == k && e.body.signed?.isSome) log m e hme hfe
          rw [← hm.1, List.getElem?_map] at hpos
          obtain ⟨x, hxj, hxe⟩ := Option.map_eq_some_iff.mp hpos
          have hxj : hist[c16cnt log k m]? = some x := hxj
          have hxe : x.2.2 = e := hxe
          obtain ⟨st0, new0, tokens0, hst0, hc0⟩ := hm.2 x (List.mem_of_getElem? hxj)
          rw [hxe, hei, hs] at hst0
          rw [← Option.some.inj hst0] at hc0
          obtain ⟨st1, rs, b, hst1, hbt, hbj⟩ := c15_hb_idx P log k hist bs hbs _ x hxj
          rw [hxe, hei, hs] at hst1
          rw [← Option.some.inj hst1] at hbt
          rcases (ih2 hlt).2 with ⟨hG, hbase⟩ | ⟨i, hi', hC⟩
          · rcases custody_binds hH P s k x.1 x.2.1 new0 tokens0 x.2.2 hc0 _ _
                (c16_inv k (bs.take (c16cnt log k m)) g hi) hbase with
              ⟨rs', bt, rset, n0, hbt', -, hn0, ⟨⟨hd, hhd, hdd⟩, -, -, hbody⟩ | hcol⟩
            · have hbb : bt = b := by
                rw [hbt] at hbt'
                exact (Prod.mk.inj (Option.some.inj hbt')).2.symm
              rw [hbb] at hhd
              have hs1 : shardSetsT k g (bs.take (c16cnt log k m + 1)) =
                  shardSetsT k (shardSetsT k g (bs.take (c16cnt log k m))) [b] := by
                unfold shardSetsT; rw [List.take_add_one, hbj]; exact List.foldl_append
              have hh : headOf sha3 (shardSetsT k g (bs.take (c16cnt log k m + 1))).1
                  (shardSetsT k g (bs.take (c16cnt log k m + 1))).2 = some hd := by
                rw [hs1]; exact hhd
              rw [hxe, hb] at hbody
              have hnn : new = new0 := (Body.sign.inj hbody).2.1
              rw [hnn, hn0] at hn'
              rw [← Option.some.inj hn'] at hbase'
              refine Or.inl ⟨fun i hi' => ?_, ?_⟩
              · cases Nat.lt_or_ge i (c16cnt log k m) with
                | inl h => exact hG i h
                | inr h =>
                  have hij : i = c16cnt log k m := by omega
                  rw [hij]
                  refine ⟨fun x' new' hx' hsg => ?_, fun x' cert' new' tokens' f' b' hx' hb' hbi => ?_⟩
                  · rw [hxj] at hx'
                    rw [← Option.some.inj hx', hxe, hb] at hsg
                    simp only [Body.signed?, Option.some.injEq] at hsg
                    exact ⟨n0, hd, by rw [← hsg, hnn]; exact hn0, hh, hdd⟩
                  · rw [hxj] at hx'
                    rw [← Option.some.inj hx', hxe, hb] at hb'
                    rw [hbj] at hbi
                    rw [← Option.some.inj hbi]
                    obtain ⟨-, hn2, -, hf2⟩ := Body.sign.inj hb'
                    obtain ⟨-, -, -, hf3⟩ := Body.sign.inj hbody
                    rw [← hf2, hf3, hbb]
                    refine ⟨rfl, n0, by rw [← hn2, hnn]; exact hn0, ?_⟩
                    rw [← hbb]
                    exact c16_today P s k x.1 x.2.1 new0 tokens0 x.2.2 hc0 rs' bt hbt' n0 hn0
              · rw [hh, hbase']
                exact hdd.symm
            · have hbb : bt = b := by
                rw [hbt] at hbt'
                exact (Prod.mk.inj (Option.some.inj hbt')).2.symm
              rw [hbb] at hcol
              exact Or.inr ⟨c16cnt log k m, Nat.lt_succ_self _, x, b, hxj, hbj, hcol⟩
          · exact Or.inr ⟨i, by omega, hC⟩
      · have hfe : (e.shard == k && e.body.signed?.isSome) = false := by simp [hek]
        have hc : c16cnt log k (m + 1) = c16cnt log k m :=
          c16_cnt0 (fun e : Entry => e.shard == k && e.body.signed?.isSome) log m e hme hfe
        rw [hc, (cust_push P s s' e hpu).2.2.1 k (fun h => hek h.symm)]
        have hne : er.idx ≠ m := fun h => hek (by rw [hee h]; exact hk)
        exact ⟨fun h => ih1 (by omega), fun h => ih2 (by omega)⟩

/-- c16_chain on the whole log: every step good, or a collision at some step. -/
private theorem c16_run (hH : HashLen sha3) (P : Pins) (log : List Entry) (st : LogState)
    (hf : fold P log = some st) (k : Nat) (hist : List (Bytes × SignIn × Entry)) (hm : MadeBy P log k hist)
    (er : Entry) (p : Permit) (her : er ∈ log) (hk : er.shard = k) (hp : er.body = .resume p)
    (g : Snapshot Line × Snapshot Line) (hg : activation P k p = some g) (hi : Inv g.1 g.2) (bs : List Batch)
    (hbs : histBatches P log k hist = some bs) :
    (∀ i < hist.length, c16G P k g hist bs i) ∨ ∃ i, c16C k g hist bs i := by
  obtain ⟨i0, hi0⟩ := List.mem_iff_getElem?.mp her
  obtain ⟨s0, s1, hs0, hp0, hix, -⟩ := cust_fold_at P log (by simp [hf]) i0 er hi0
  have her' : log[er.idx]? = some er := by rw [hix]; exact hi0
  have hpre : ∀ m s, m ≤ er.idx → fold P (log.take m) = some s → (s.shard k).live = false := by
    intro m s hle hs
    have hl0 := ((c16_push_k P s0 s1 er hp0).2.1 p hp).1
    rw [hk] at hl0
    cases hl : (s.shard k).live with
    | false => rfl
    | true =>
      have h2 := c16_live_mono P log k m s hs hl (er.idx - m) s0
        (by rw [Nat.add_sub_of_le hle, hix]; exact hs0)
      rw [hl0] at h2; cases h2
  have hlen : er.idx < log.length := (List.getElem?_eq_some_iff.mp her').1
  have hc : c16cnt log k log.length = hist.length := by
    unfold c16cnt; rw [List.take_length, ← hm.1, List.length_map]
  obtain ⟨-, h2⟩ := c16_chain hH P log k hist hm er p her' hk hp g hg hi bs hbs hpre log.length st
    (by rw [List.take_length]; exact hf)
  rw [hc] at h2
  rcases (h2 hlen).2 with ⟨hG, -⟩ | ⟨i, -, hC⟩
  · exact Or.inl hG
  · exact Or.inr ⟨i, hC⟩

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
           (stateInputs sha3 (shardSetsT k g (bs.take i)).1 (shardSetsT k g (bs.take i)).2)) := by
  obtain ⟨bs, hbs⟩ := c15_hb_some P log k hist hm
  refine ⟨bs, hbs, ?_⟩
  rcases c16_run hH P log st hf k hist hm er p her hk hp g hg hi bs hbs with hG | ⟨i, hC⟩
  · exact Or.inl fun i x new hx hs => (hG i (List.getElem?_eq_some_iff.mp hx).1).1 x new hx hs
  · exact Or.inr ⟨i, hC⟩

private theorem c16_mapM_len {α β : Type} (F : α → Option β) :
    ∀ (xs : List α) (ys : List β), xs.mapM F = some ys → ys.length = xs.length
  | [], ys, h => by
    rw [← Option.some.inj h]; rfl
  | a :: xs, ys, h => by
    rw [List.mapM_cons] at h
    obtain ⟨_, -, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨ys', hys, h⟩ := Option.bind_eq_some_iff.mp h
    rw [← Option.some.inj h, List.length_cons, List.length_cons, c16_mapM_len F xs ys' hys]

/-- addsOfT's i-th rows: the fresh rows of batch i on the true sets before it. -/
private theorem c16_adds (k : Nat) : ∀ (ts : List Batch) (g : Snapshot Line × Snapshot Line) (i : Nat) (b : Batch),
    ts[i]? = some b → (addsOfT k g ts)[i]? = some (batchFresh
      (carried b.ctx (shardSetsT k g (ts.take i)).1 (shardSetsT k g (ts.take i)).2)
      (decideRegT (carried b.ctx (shardSetsT k g (ts.take i)).1 (shardSetsT k g (ts.take i)).2) k b.owners
        b.lines))
  | [], _, _, _, h => by simp at h
  | t :: _, g, 0, b, h => by
    rw [List.getElem?_cons_zero, Option.some.injEq] at h
    subst h
    rfl
  | t :: ts, g, i + 1, b, h => by
    rw [List.getElem?_cons_succ] at h
    exact c16_adds k ts ((decideRegT (carried t.ctx g.1 g.2) k t.owners t.lines).released,
      (decideRegT (carried t.ctx g.1 g.2) k t.owners t.lines).unresolved) i b h

/-- filterMap meets a list it agrees with index by index. -/
private theorem c16_fm {α β : Type} (H : α → Option β) : ∀ (l : List α) (L : List β),
    (∀ (i : Nat) x, l[i]? = some x → H x = L[i]?) → (∀ i : Nat, l[i]? = none → L[i]? = none) →
      l.filterMap H = L
  | [], [], _, _ => rfl
  | [], y :: L, _, h0 => by simpa using h0 0 rfl
  | x :: l, L, h1, h0 => by
    have hx := h1 0 x rfl
    have t1 : ∀ (i : Nat) x', l[i]? = some x' → H x' = L.tail[i]? := fun i x' h => by
      rw [h1 (i + 1) x' h]; cases L <;> simp
    have t0 : ∀ i : Nat, l[i]? = none → L.tail[i]? = none := fun i h => by
      have := h0 (i + 1) h; cases L <;> simp_all
    cases L with
    | nil => rw [List.filterMap_cons_none (by simpa using hx)]; exact c16_fm H l [] t1 t0
    | cons y L =>
      rw [List.filterMap_cons_some (by simpa using hx)]
      exact congrArg (y :: ·) (c16_fm H l L t1 t0)

/-- The log alone (activation base + fresh rows) rebuilds the chain's true sets; else the same collision. -/
theorem rebuild_sound (hH : HashLen sha3) (P : Pins) (log : List Entry) (st : LogState)
    (hf : fold P log = some st) (k : Nat) (hist : List (Bytes × SignIn × Entry)) (hm : MadeBy P log k hist)
    (er : Entry) (p : Permit) (her : er ∈ log) (hk : er.shard = k) (hp : er.body = .resume p)
    (g : Snapshot Line × Snapshot Line) (hg : activation P k p = some g) (hi : Inv g.1 g.2) (bs : List Batch)
    (hb : histBatches P log k hist = some bs) :
    rebuild P k g log = shardSetsT k g bs ∨
      ∃ (i : Nat) (x : Bytes × SignIn × Entry) (b : Batch), hist[i]? = some x ∧ bs[i]? = some b ∧
        Collision sha3 (witnessInputs sha3 b.ctx k b.owners b.lines x.2.1.witness)
          (stateInputs sha3 (shardSetsT k g (bs.take i)).1 (shardSetsT k g (bs.take i)).2) := by
  rcases c16_run hH P log st hf k hist hm er p her hk hp g hg hi bs hb with hG | ⟨i, hC⟩
  · refine Or.inl ?_
    rw [← replayT_addsOfT k g bs]
    unfold rebuild
    congr 1
    refine Eq.trans (b := (log.filter fun e => e.shard == k && e.body.signed?.isSome).filterMap fun e =>
      match e.body with
      | .sign _ new _ f => (storedOfAny sha3 new).map fun n => (localDay P.tbl n.checkpoint.createdAt, f)
      | _ => none) ?_ ?_
    · rw [List.filterMap_filter]
      congr 1
      funext e
      cases e.body <;> simp [Body.signed?]
    rw [← hm.1, List.filterMap_map]
    apply c16_fm
    · intro i x hx
      have hmem : x.2.2 ∈ log.filter (fun e => e.shard == k && e.body.signed?.isSome) := by
        rw [← hm.1]; exact List.mem_map_of_mem (List.mem_of_getElem? hx)
      obtain ⟨-, hpx⟩ := List.mem_filter.mp hmem
      obtain ⟨-, -, b, -, -, hbi⟩ := c15_hb_idx P log k hist bs hb i x hx
      cases hbx : x.2.2.body with
      | sign cert new tokens f =>
        obtain ⟨hf', n, hn, hday⟩ :=
          (hG i (List.getElem?_eq_some_iff.mp hx).1).2 x cert new tokens f b hx hbx hbi
        simp only [Function.comp_apply, hbx, hn, Option.map_some]
        rw [hday, hf', eq_comm, List.getElem?_zip_eq_some]
        exact ⟨by rw [List.getElem?_map, hbi]; rfl, c16_adds k bs g i b hbi⟩
      | _ => simp [hbx, Body.signed?] at hpx
    · intro i hx
      have hb' := hb
      unfold histBatches at hb'
      have hl := c16_mapM_len _ hist bs hb'
      rw [List.getElem?_eq_none_iff] at hx ⊢
      simp only [List.length_zip, List.length_map]
      omega
  · exact Or.inr ⟨i, hC⟩

end BlindLedger.Gate.StateV2
