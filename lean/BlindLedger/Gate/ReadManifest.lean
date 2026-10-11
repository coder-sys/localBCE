import BlindLedger.Gate.StateV2
import BlindLedger.Gate.BatchTheorems
import BlindLedger.Gate.Rules.Run
import BlindLedger.Gate.Rules.FastEq

/-! The per-batch read manifest `RR/GATE/READ-MANIFEST/v1` (MAN-0 S1): the exe constants, the four SNAPSHOT/v1 pins
    of what `readSetOf` read (zero for a kind it did not read), and the bytes `P` it hashes, length-prefixed:
    `tag ‖ grant ‖ rule ‖ engine ‖ pin₁..₄ ‖ u32 |P| ‖ P`, each const and pin 64 bytes. The header's `evidenceRoot`
    signs `sha3` of it (`manifestOk`). `reads_exact`: a stored record hashing to that root decodes to exact pins
    and to the `P` every token's input commitment binds, or names a SHA3 collision. `run_reads_eq`: the runner's
    `RULES_READS` is `readsOf`. Not imported by the runner. -/

namespace BlindLedger.Gate.ReadManifest

open BlindLedger.Gate BlindLedger.Gate.Rules BlindLedger.Gate.StateV2

def manifestTag : Bytes := "RR/GATE/READ-MANIFEST/v1".toUTF8.toList ++ [0]

/-- One kind: its SNAPSHOT/v1 pin (zero when Lean read none; a snapshot pinning to zero is refused) and its
    `readSetOf` slot (`optPin`). -/
def kindOf {α : Type} (d : String) (k : Nat) (f : α → List (Nat × Nat)) :
    Option (Snapshot α) → Option (Bytes × Bytes)
  | none => some (zeroDigest, [0])
  | some s => do
    let p := sha3 (← pinInput "RR/GATE/SNAPSHOT/v1" k f s)
    guard (p ≠ zeroDigest)
    let q ← pinInput d k f s
    pure (p, 1 :: sha3 q)

def kindPins (c : Ctx) : Option (List (Bytes × Bytes)) := do
  pure [← kindOf "RR/GATE/READ-DMF/v2" 1 Death.fields c.dmf, ← kindOf "RR/GATE/READ-PROVIDER-DEATH/v2" 2 Death.fields c.providerDeaths,
    ← kindOf "RR/GATE/READ-EXCLUSION/v2" 3 Exclusion.fields c.exclusions, ← kindOf "RR/GATE/READ-ENROLLMENT/v2" 4 Span.fields c.enrollment]

/-- The bytes `readSetOf` hashes (`readSetOf_pre`). -/
def readSetPre (c₀ : Ctx) (base : Bytes) : Option Bytes := do
  let a ← optPin "RR/GATE/READ-DMF/v2" 1 Death.fields c₀.dmf
  let b ← optPin "RR/GATE/READ-PROVIDER-DEATH/v2" 2 Death.fields c₀.providerDeaths
  let e ← optPin "RR/GATE/READ-EXCLUSION/v2" 3 Exclusion.fields c₀.exclusions
  let n ← optPin "RR/GATE/READ-ENROLLMENT/v2" 4 Span.fields c₀.enrollment
  let r ← be 4 c₀.redo.length
  let rs ← c₀.redo.mapM (be payWidth)
  pure (dom2 "READ-SET" ++ a ++ b ++ e ++ n ++ r ++ rs.flatten ++ base)

/-- pins ‖ u32 |P| ‖ P: what Lean emits (`RULES_READS`); the producer prefixes the tag and constants. -/
def readsOf (c : Ctx) (base : Bytes) : Option Bytes := do
  let ks ← kindPins c
  let pre ← readSetPre c base
  pure ((ks.map (·.1)).flatten ++ (← be 4 pre.length) ++ pre)

def encodeReads (k : Consts) (c : Ctx) (base : Bytes) : Option Bytes := do
  guard (k.grant.length = digestBytes ∧ k.rule.length = digestBytes ∧ k.engine.length = digestBytes)
  pure (manifestTag ++ k.grant ++ k.rule ++ k.engine ++ (← readsOf c base))

def cut (n : Nat) (x : Bytes) : Option (Bytes × Bytes) := if n ≤ x.length then some (x.take n, x.drop n) else none

/-- A pin's slot in `P`: `0` iff the pin is zero, else `1` and a digest. -/
def slot (p : Bytes) : Bytes → Option Bytes
  | b :: y => if b = 0 ∧ p = zeroDigest then some y
    else if b = 1 ∧ p ≠ zeroDigest ∧ digestBytes ≤ y.length then some (y.drop digestBytes) else none
  | [] => none

structure Manifest where
  grant : Bytes
  rule : Bytes
  engine : Bytes
  pins : List Bytes
  pre : Bytes

def decodeReads (x : Bytes) : Option Manifest := do
  let t ← cut manifestTag.length x
  guard (t.1 = manifestTag)
  let g ← cut digestBytes t.2
  let r ← cut digestBytes g.2
  let e ← cut digestBytes r.2
  let p1 ← cut digestBytes e.2
  let p2 ← cut digestBytes p1.2
  let p3 ← cut digestBytes p2.2
  let p4 ← cut digestBytes p3.2
  let l ← cut 4 p4.2
  guard (beNat l.1 = l.2.length)
  let h ← cut (dom2 "READ-SET").length l.2
  guard (h.1 = dom2 "READ-SET")
  let y ← slot p1.1 h.2
  let y ← slot p2.1 y
  let y ← slot p3.1 y
  let _ ← slot p4.1 y
  pure ⟨g.1, r.1, e.1, [p1.1, p2.1, p3.1, p4.1], l.2⟩

/-- Pin `p` is exactly what Lean read of one kind: zero iff none, else the SNAPSHOT/v1 digest of that snapshot. -/
def Exact {α : Type} (k : Nat) (f : α → List (Nat × Nat)) (o : Option (Snapshot α)) (p : Bytes) : Prop :=
  (p = zeroDigest ↔ o = none) ∧
    ∀ d, d ≠ zeroDigest → (p = d ↔ ∃ s x, o = some s ∧ pinInput "RR/GATE/SNAPSHOT/v1" k f s = some x ∧ sha3 x = d)

/-- The checkpoint custody signs carries `sha3` of the manifest in `evidenceRoot`. -/
def manifestOk (P : Pins) (st : LogState) (k : Nat) (i : SignIn) (new : Bytes) : Prop :=
  ∃ n m, storedOfAny sha3 new = some n ∧ encodeReads P.c i.ctx (st.shard k).base = some m ∧
    n.checkpoint.evidenceRoot = sha3 m

theorem hB_mk (bs : Bytes) : Run.hB ⟨bs.toArray⟩ = sha3 bs := by
  have h : (⟨bs.toArray⟩ : ByteArray) = bs.toByteArray := ByteArray.ext (by simp [List.data_toByteArray])
  unfold Run.hB sha3
  rw [h]

theorem dom2_eq : dom2 "READ-SET" = "RR/GATE/READ-SET/v2".toUTF8.toList ++ [0] := by
  simp [dom2]

theorem readPin_eq {α : Type} (d : String) (k : Nat) (f : α → List (Nat × Nat)) (o : Option (Snapshot α)) :
    Run.readPin d k f o = kindOf d k f o := by
  cases o with
  | none => rfl
  | some s =>
    simp only [Run.readPin, kindOf, ← Fast.pin_run_eq]
    cases pinInput "RR/GATE/SNAPSHOT/v1" k f s <;> cases pinInput d k f s <;> simp [hB_mk]

theorem cut_app {n : Nat} {l y : Bytes} (h : l.length = n) : cut n (l ++ y) = some (l, y) := by
  subst h; simp [cut]

theorem kindOf_some {α : Type} {d : String} {k : Nat} {f : α → List (Nat × Nat)} {o : Option (Snapshot α)}
    {p a : Bytes} (h : kindOf d k f o = some (p, a)) :
    p.length = digestBytes ∧ optPin d k f o = some a ∧ (∀ rest, slot p (a ++ rest) = some rest) ∧ Exact k f o p := by
  cases o with
  | none =>
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj h).symm
    refine ⟨by simp [zeroDigest], rfl, fun rest => by simp [slot], by simp, fun d hd => ?_⟩
    simp only [reduceCtorEq, false_and, exists_false, iff_false]
    exact fun e => hd e.symm
  | some s =>
    obtain ⟨x, hx, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨_, hg, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨q, hq, h⟩ := Option.bind_eq_some_iff.mp h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj h).symm
    have hz := (guard_some _ _).mp hg
    refine ⟨sha3_length x, by simp [optPin, hq], fun rest => ?_, ⟨fun e => absurd e hz, fun e => by cases e⟩,
      fun d _ => ⟨fun e => ⟨s, x, rfl, hx, e⟩, fun ⟨s', x', e1, e2, e3⟩ => ?_⟩⟩
    · simp only [List.cons_append, slot]
      rw [if_neg (by simp), if_pos (by simp [hz, sha3_length]), List.drop_left' (sha3_length q)]
    · cases e1
      rw [hx] at e2
      cases e2
      exact e3

theorem kindPins_some {c : Ctx} {ks : List (Bytes × Bytes)} (h : kindPins c = some ks) :
    ∃ p1 a1 p2 a2 p3 a3 p4 a4, ks = [(p1, a1), (p2, a2), (p3, a3), (p4, a4)] ∧
      kindOf "RR/GATE/READ-DMF/v2" 1 Death.fields c.dmf = some (p1, a1) ∧
      kindOf "RR/GATE/READ-PROVIDER-DEATH/v2" 2 Death.fields c.providerDeaths = some (p2, a2) ∧
      kindOf "RR/GATE/READ-EXCLUSION/v2" 3 Exclusion.fields c.exclusions = some (p3, a3) ∧
      kindOf "RR/GATE/READ-ENROLLMENT/v2" 4 Span.fields c.enrollment = some (p4, a4) := by
  unfold kindPins at h
  obtain ⟨⟨p1, a1⟩, h1, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨⟨p2, a2⟩, h2, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨⟨p3, a3⟩, h3, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨⟨p4, a4⟩, h4, h⟩ := Option.bind_eq_some_iff.mp h
  exact ⟨p1, a1, p2, a2, p3, a3, p4, a4, (Option.some.inj h).symm, h1, h2, h3, h4⟩

theorem kindPins_pre {c : Ctx} {ks : List (Bytes × Bytes)} (h : kindPins c = some ks) (base : Bytes) :
    readSetPre c base = (do
      let r ← be 4 c.redo.length
      let rs ← c.redo.mapM (be payWidth)
      pure (dom2 "READ-SET" ++ (ks.map (·.2)).flatten ++ r ++ rs.flatten ++ base)) := by
  obtain ⟨p1, a1, p2, a2, p3, a3, p4, a4, rfl, h1, h2, h3, h4⟩ := kindPins_some h
  unfold readSetPre
  rw [(kindOf_some h1).2.1, (kindOf_some h2).2.1, (kindOf_some h3).2.1, (kindOf_some h4).2.1]
  cases be 4 c.redo.length <;> cases c.redo.mapM (be payWidth) <;> simp [List.append_assoc]

theorem readSetOf_pre (c : Ctx) (base : Bytes) : readSetOf c base = (readSetPre c base).map sha3 := by
  unfold readSetOf readSetPre
  cases optPin "RR/GATE/READ-DMF/v2" 1 Death.fields c.dmf <;>
    cases optPin "RR/GATE/READ-PROVIDER-DEATH/v2" 2 Death.fields c.providerDeaths <;>
    cases optPin "RR/GATE/READ-EXCLUSION/v2" 3 Exclusion.fields c.exclusions <;>
    cases optPin "RR/GATE/READ-ENROLLMENT/v2" 4 Span.fields c.enrollment <;>
    cases be 4 c.redo.length <;> cases c.redo.mapM (be payWidth) <;> rfl

/-- The runner's `RULES_READS` bytes are `readsOf` of its context. -/
theorem run_reads_eq (c : Ctx) (base : Bytes) : Run.reads c base = readsOf c base := by
  have hk : Run.readPins c = kindPins c := by simp only [Run.readPins, kindPins, readPin_eq]
  unfold Run.reads readsOf
  rw [hk]
  cases h : kindPins c with
  | none => rfl
  | some ks =>
    simp only [kindPins_pre h, dom2_eq]
    cases be 4 c.redo.length <;> cases c.redo.mapM (be payWidth) <;> simp [List.append_assoc]

theorem decodeReads_encode {k : Consts} {c : Ctx} {base x : Bytes} (h : encodeReads k c base = some x) :
    ∃ ks P, kindPins c = some ks ∧ readSetPre c base = some P ∧
      decodeReads x = some ⟨k.grant, k.rule, k.engine, ks.map (·.1), P⟩ := by
  unfold encodeReads at h
  obtain ⟨_, hg, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨hg1, hg2, hg3⟩ := (guard_some _ _).mp hg
  obtain ⟨R, hR, h⟩ := Option.bind_eq_some_iff.mp h
  obtain rfl := (Option.some.inj h).symm
  unfold readsOf at hR
  obtain ⟨ks, hks, hR⟩ := Option.bind_eq_some_iff.mp hR
  obtain ⟨P, hP, hR⟩ := Option.bind_eq_some_iff.mp hR
  obtain ⟨L, hL, hR⟩ := Option.bind_eq_some_iff.mp hR
  obtain rfl := (Option.some.inj hR).symm
  refine ⟨ks, P, hks, hP, ?_⟩
  have hPk := hP
  rw [kindPins_pre hks] at hPk
  obtain ⟨r, -, hPk⟩ := Option.bind_eq_some_iff.mp hPk
  obtain ⟨rs, -, hPk⟩ := Option.bind_eq_some_iff.mp hPk
  obtain rfl := (Option.some.inj hPk).symm
  obtain ⟨p1, a1, p2, a2, p3, a3, p4, a4, rfl, h1, h2, h3, h4⟩ := kindPins_some hks
  obtain ⟨l1, -, s1, -⟩ := kindOf_some h1
  obtain ⟨l2, -, s2, -⟩ := kindOf_some h2
  obtain ⟨l3, -, s3, -⟩ := kindOf_some h3
  obtain ⟨l4, -, s4, -⟩ := kindOf_some h4
  obtain ⟨hLe, hLt⟩ := be_eq hL
  have hb := beNat_natBE 4 _ hLt
  rw [← hLe] at hb
  simp only [List.map_cons, List.map_nil, List.flatten_cons, List.flatten_nil, List.append_nil, List.append_assoc] at hb
  simp only [decodeReads, List.map_cons, List.map_nil, List.flatten_cons, List.flatten_nil, List.append_nil,
    List.append_assoc, cut_app rfl, cut_app hg1, cut_app hg2, cut_app hg3, cut_app l1, cut_app l2, cut_app l3,
    cut_app l4, cut_app (be_length hL), s1, s2, s3, s4, guard, hb, Option.bind_eq_bind,
    Option.bind_some, Option.pure_def, ↓reduceIte]

/-- Fixed widths: one record is one (constants, pins, `P`). -/
theorem encodeReads_inj {k k' : Consts} {c c' : Ctx} {base base' x : Bytes} (h : encodeReads k c base = some x)
    (h' : encodeReads k' c' base' = some x) :
    k.grant = k'.grant ∧ k.rule = k'.rule ∧ k.engine = k'.engine ∧
      (kindPins c).map (·.map (·.1)) = (kindPins c').map (·.map (·.1)) ∧ readSetPre c base = readSetPre c' base' := by
  obtain ⟨ks, P, hk, hP, hd⟩ := decodeReads_encode h
  obtain ⟨ks', P', hk', hP', hd'⟩ := decodeReads_encode h'
  rw [hd] at hd'
  simp only [Option.some.injEq, Manifest.mk.injEq] at hd'
  obtain ⟨e1, e2, e3, e4, e5⟩ := hd'
  rw [hk, hk', hP, hP', e5]
  exact ⟨e1, e2, e3, by simp [e4], rfl⟩

private theorem rowOf_commit {rev : Nat → Nat} {pays : List (Nat × Outcome × Nat)}
    {ds : List (Line × Outcome × List Reason)} {rset : Bytes} {raw : Bytes} {r : Request} {w : PayRow}
    (h : StateV2.rowOf rev pays ds rset (raw, r) = some w) : w.commit = inputCommitment sha3 raw rset := by
  unfold StateV2.rowOf at h
  cases hr : r.flow.ruled <;>
    simp only [hr, Bool.not_false, Bool.not_true, Bool.false_eq_true, ↓reduceIte, Option.some.injEq] at h
  · subst h; rfl
  · obtain ⟨⟨_, o, cents⟩, _, h⟩ := Option.bind_eq_some_iff.mp h
    simp only [Option.pure_def, Option.some.injEq] at h
    subst h; rfl

/-- A stored record hashing to the signed `evidenceRoot` of a checkpoint custody accepted decodes to custody's
    constants, four pins each `Exact` for what Lean read, and the `P` whose hash every token's input
    commitment binds to its raw request; or it names a SHA3 collision with the true manifest. -/
theorem reads_exact {P : Pins} {st : LogState} {k : Nat} {cert : Bytes} {i : SignIn} {new : Bytes}
    {tokens : List Bytes} {e : Entry} {n : Stored} {row : Bytes} (h : custodyOk P st k cert i new tokens = some e)
    (hm : manifestOk P st k i new) (hn : storedOfAny sha3 new = some n) (hroot : n.checkpoint.evidenceRoot = sha3 row) :
    (∃ p1 p2 p3 p4 Pre, decodeReads row = some ⟨P.c.grant, P.c.rule, P.c.engine, [p1, p2, p3, p4], Pre⟩ ∧
      Exact 1 Death.fields i.ctx.dmf p1 ∧ Exact 2 Death.fields i.ctx.providerDeaths p2 ∧
      Exact 3 Exclusion.fields i.ctx.exclusions p3 ∧ Exact 4 Span.fields i.ctx.enrollment p4 ∧
      readSetPre i.ctx (st.shard k).base = some Pre ∧
      ∀ t ∈ tokens, ∀ w, tokRow P.c i.secs t = some w → ∃ raw ∈ i.reqs, w.commit = inputCommitment sha3 raw (sha3 Pre)) ∨
    ∃ m, encodeReads P.c i.ctx (st.shard k).base = some m ∧ Collision sha3 [row] [m] := by
  obtain ⟨n', m, hn', hm, hr⟩ := hm
  rw [hn] at hn'
  obtain rfl := Option.some.inj hn'
  by_cases hrm : row = m
  · subst hrm
    left
    obtain ⟨ks, Pre, hks, hP, hd⟩ := decodeReads_encode hm
    obtain ⟨p1, a1, p2, a2, p3, a3, p4, a4, rfl, h1, h2, h3, h4⟩ := kindPins_some hks
    refine ⟨p1, p2, p3, p4, Pre, hd, (kindOf_some h1).2.2.2, (kindOf_some h2).2.2.2, (kindOf_some h3).2.2.2,
      (kindOf_some h4).2.2.2, hP, ?_⟩
    obtain ⟨rs, _, _, rset, _, -, -, hrs, -, -, htk, -⟩ := c15_peel P st k cert i new tokens e h
    rw [readSetOf_pre, hP] at hrs
    obtain rfl := (Option.some.inj hrs)
    unfold tokensOk at htk
    simp only [Bool.and_eq_true, beq_iff_eq, List.isPerm_iff] at htk
    intro t ht w hw
    obtain ⟨⟨raw, r⟩, hx, hxw⟩ := List.mem_filterMap.mp (htk.2.mem_iff.mp (List.mem_filterMap.mpr ⟨t, ht, hw⟩))
    exact ⟨raw, (List.of_mem_zip hx).1, rowOf_commit hxw⟩
  · exact Or.inr ⟨m, hm, row, List.mem_singleton_self _, m, List.mem_singleton_self _, hrm, hroot.symm.trans hr⟩

end BlindLedger.Gate.ReadManifest
