import BlindLedger.Gate.Rules.ShardRun

/-! The decide layer (rrb/designs/decide-layer-v1.md §3): a shard decides with its own checkpoints as the sets
    read and the priors (`carried`), so what the store persists and reloads is exactly the spec's fold.  Proofs
    only; the definitions are in `Rules/Spec.lean` and `Anchor.lean`.  Synthetic, nonpayment, activation=false. -/

namespace BlindLedger.Gate

/-- Spec only: `decide` threaded through a shard's batches. Each frame's anchor is the batch's own
    (`t.ctx.anchor`, read from the producer's last sealed header), so a run that is `some` is one whose every
    anchor named the previous state's digest. -/
def ShardState.runDecide (H : Bytes → Bytes) (k : Nat) :
    ShardState → List Rules.Batch → Option (List Rules.Result × ShardState)
  | st, [] => some ([], st)
  | st, t :: ts =>
    match st.decide H t.ctx k t.owners t.lines with
    | none => none
    | some (r, st') => (ShardState.runDecide H k st' ts).map fun (rs, s) => (r :: rs, s)

end BlindLedger.Gate

namespace BlindLedger.Gate.Rules

private theorem view_self (t : Nat) (p : Snapshot Line) : view t p (some p) = p := by
  unfold view; split <;> rfl

/-- The view of a carried context is the state itself, chained or not (`view` returns `o.getD prior` = prior). -/
theorem carried_sets (c₀ : Ctx) (rel unr : Snapshot Line) :
    releasedSet (carried c₀ rel unr) = rel.entries ∧ unresolvedSet (carried c₀ rel unr) = unr.entries := by
  simp [releasedSet, unresolvedSet, carried, view_self]

/-- A carried batch only appends (`advance`; §C's `decideReg_sets` specialised; no `loose` rows). -/
theorem carried_append (c₀ : Ctx) (rel unr : Snapshot Line) (k : Nat) (os : List Owner) (b : List Line) :
    let c := carried c₀ rel unr; let r := decideReg c k os b
    r.released.entries = rel.entries ++ (batchFresh c r).1 ∧ r.unresolved.entries = unr.entries ++ (batchFresh c r).2 := by
  obtain ⟨h1, h2⟩ := carried_sets c₀ rel unr
  simp only [batchFresh, h1, h2]
  simp [decideReg, decideBatchIn, advance, carried, view_self]

private theorem replay_aux (k : Nat) (ts : List Batch) : ∀ (g g' : Snapshot Line × Snapshot Line),
    g.1.entries = g'.1.entries → g.2.entries = g'.2.entries →
    ((replay g (addsOf k g' ts)).1.entries, (replay g (addsOf k g' ts)).2.entries) =
      ((shardSets k g' ts).1.entries, (shardSets k g' ts).2.entries) := by
  induction ts with
  | nil => intro g g' h1 h2; simp [addsOf, replay, shardSets, h1, h2]
  | cons t ts ih =>
    intro g g' h1 h2
    obtain ⟨a1, a2⟩ := carried_append t.ctx g'.1 g'.2 k t.owners t.lines
    exact ih _ _ (by simp [h1, a1]) (by simp [h2, a2])

/-- REFINEMENT (load): replaying the stored rows gives the spec fold (entries; asOf kept). -/
theorem replay_addsOf (k : Nat) (g : Snapshot Line × Snapshot Line) (ts : List Batch) :
    ((replay g (addsOf k g ts)).1.entries, (replay g (addsOf k g ts)).2.entries) =
      ((shardSets k g ts).1.entries, (shardSets k g ts).2.entries) :=
  replay_aux k ts g g rfl rfl

/-- COMPOSITION with the World model: a carried decide is a seal World accepts (the guard's set conjuncts hold by
    `carried_sets`), and it moves World exactly as the runtime state moves. With `run_one_payment_per_line`
    (ShardRun.lean, unchanged) this is the headline for the mshist-1 case (lead ruling L1). -/
theorem carried_sealB {w : World} {k : Nat} {c₀ : Ctx} {rel unr : Snapshot Line} {os : List Owner} {b : List Line}
    (hr : w.rel k = rel.entries) (hu : w.unr k = unr.entries) (hos : ∀ o ∈ os, o.shard = k → w.reg o.id = some k) :
    ∃ w', w.step (.sealB k (carried c₀ rel unr) os b) = some w' ∧
      w'.rel k = (decideReg (carried c₀ rel unr) k os b).released.entries ∧
      w'.unr k = (decideReg (carried c₀ rel unr) k os b).unresolved.entries := by
  obtain ⟨h1, h2⟩ := carried_sets c₀ rel unr
  have hg : releasedSet (carried c₀ rel unr) = w.rel k ∧ unresolvedSet (carried c₀ rel unr) = w.unr k ∧
      ∀ o ∈ os, o.shard = k → w.reg o.id = some k := ⟨h1.trans hr.symm, h2.trans hu.symm, hos⟩
  exact ⟨_, if_pos hg, by simp, by simp⟩

/-- The acceptance test as a theorem: a ready line whose id is already in the carried released set (and whose
    payment is not a re-decision, `hnr`: `seen0` drops own lines) is decided, and every decision of it is HOLD
    ALREADY_DECIDED. -/
theorem carried_resend_held (c₀ : Ctx) (rel unr : Snapshot Line) (k : Nat) (os : List Owner) (b : List Line)
    (l : Line) (hl : l ∈ ready k os b) (hin : ∃ x ∈ rel.entries, x.id = l.id)
    (hnr : ¬ c₀.redo.contains l.pay) :
    (∃ d ∈ (decideReg (carried c₀ rel unr) k os b).decisions, d.line = l) ∧
      ∀ d ∈ (decideReg (carried c₀ rel unr) k os b).decisions, d.line = l →
        Reason.ALREADY_DECIDED ∈ d.reasons ∧ d.outcome = .HOLD := by
  have hm : l ∈ (decideReg (carried c₀ rel unr) k os b).decisions.map (·.line) := by
    show l ∈ (decideAll _ _ (order _ (ready k os b))).map (·.line)
    rw [lines_decideAll]; exact (order_perm _ _).mem_iff.mpr hl
  refine ⟨List.mem_map.mp hm, fun d hd hdl => ?_⟩
  have hown : own (carried c₀ rel unr) l = false := by
    have : c₀.redo.contains l.pay = false := by simpa using hnr
    show (c₀.redo.contains l.pay && (releasedSet (carried c₀ rel unr)).contains l) = false
    rw [this]; rfl
  obtain ⟨seen, hseen, hall⟩ := seen_all_in (c := carried c₀ rel unr) (f := foreignOf k os (ready k os b))
    (b := ready k os b) (e := d) hd (by rw [hdl]; exact hown)
  obtain ⟨x, hx, hxid⟩ := hin
  have hmem : idKey x ∈ seen :=
    hall x (by rw [(carried_sets c₀ rel unr).1]; exact hx) _ idKey_mem
  have hk : idKey l ∈ seen := by
    have : idKey x = idKey l := by simp [idKey, hxid]
    rwa [this] at hmem
  have hf : fires (carried c₀ rel unr) seen l .ALREADY_DECIDED = true := by
    simp [fires, hk]
  have hr : Reason.ALREADY_DECIDED ∈ d.reasons := by
    rw [hseen, hdl]
    exact List.mem_filter.mpr ⟨mem_all _, hf⟩
  have ho : d.outcome = outcomeOf d.reasons := by rw [hseen]; rfl
  exact ⟨hr, ho.trans (outcomeOf_certain hr rfl)⟩

/-- Settle from the batch (§C, restated against carried): the frees computed at decide time are the spec's. -/
theorem settleFreeInc_carried (c₀ : Ctx) (rel unr : Snapshot Line) (k : Nat) (os : List Owner) (b : List Line)
    (hp : ∀ i ∈ pendingOf k os, ∀ x ∈ rel.entries ++ unr.entries, x.id ≠ i) :
    let c := carried c₀ rel unr; let r := decideReg c k os b
    settleFreeInc ((batchFresh c r).1 ++ (batchFresh c r).2) (pendingOf k os) =
      settleFree r.released.entries r.unresolved.entries (pendingOf k os) := by
  obtain ⟨ha, hb⟩ := carried_append c₀ rel unr k os b
  dsimp only
  rw [ha, hb]
  unfold settleFreeInc settleFree
  apply List.filter_congr
  intro i hi
  have hr : i ∉ rel.entries.map (·.id) := fun h =>
    let ⟨x, hx, e⟩ := List.mem_map.mp h; hp i hi x (List.mem_append_left _ hx) e
  have hu : i ∉ unr.entries.map (·.id) := fun h =>
    let ⟨x, hx, e⟩ := List.mem_map.mp h; hp i hi x (List.mem_append_right _ hx) e
  simp [List.map_append, hr, hu, or_comm, or_left_comm]

end BlindLedger.Gate.Rules

namespace BlindLedger.Gate

open Rules

/-- REFINEMENT (step): a decide step is decideReg on the carried sets and keeps the cache sound (from
    `stepReg_some` and `load_ok`). Axioms: three; no H hypothesis. -/
theorem decide_ok {H : Bytes → Bytes} {st st' : ShardState} {c₀ : Rules.Ctx} {k : Nat} {os : List Rules.Owner}
    {b : List Rules.Line} {r : Rules.Result} (hs : st.Ok H) (h : st.decide H c₀ k os b = some (r, st')) :
    r = decideReg (carried c₀ st.released st.unresolved) k os b ∧ st'.Ok H ∧
      st'.released = r.released ∧ st'.unresolved = r.unresolved := by
  unfold ShardState.decide at h
  obtain ⟨hr, h1, h2⟩ := stepReg_some h
  refine ⟨hr, ?_, h1, h2⟩
  unfold ShardState.stepReg at h
  split at h
  · simp only [Option.map_eq_some_iff, Prod.mk.injEq] at h
    obtain ⟨s0, hl, rfl, rfl⟩ := h
    exact (load_ok hl).1
  · cases h

/-- REFINEMENT (run): any accepted sequence of decide steps carries exactly `shardSets` of all prior batches. -/
theorem decide_run_fold {H : Bytes → Bytes} {k : Nat} :
    ∀ (ts : List Batch) (st st' : ShardState) (rs : List Result), st.Ok H →
      ShardState.runDecide H k st ts = some (rs, st') →
      (st'.released.entries, st'.unresolved.entries) =
        ((shardSets k (st.released, st.unresolved) ts).1.entries,
         (shardSets k (st.released, st.unresolved) ts).2.entries) := by
  intro ts
  induction ts with
  | nil => intro st st' rs _ h; simp [ShardState.runDecide] at h; obtain ⟨-, rfl⟩ := h; rfl
  | cons t ts ih =>
    intro st st' rs hs h
    unfold ShardState.runDecide at h
    split at h
    · cases h
    · rename_i r1 st1 hd
      obtain ⟨hr, hok, h1, h2⟩ := decide_ok hs hd
      simp only [Option.map_eq_some_iff] at h
      obtain ⟨⟨rs0, s0⟩, hrun, he⟩ := h
      simp only [Prod.mk.injEq] at he
      obtain ⟨-, rfl⟩ := he
      have := ih st1 s0 rs0 hok hrun
      rw [h1, h2] at this
      rw [this, hr]
      rfl

private theorem setsDigest_pins {H : Bytes → Bytes} {r u : Snapshot Line} {d : Bytes}
    (h : setsDigest H r u = some d) :
    ∃ A B, pinInput "RR/GATE/RELEASED/v1" 5 Line.fields r = some A ∧
      pinInput "RR/GATE/UNRESOLVED/v1" 6 Line.fields u = some B := by
  unfold setsDigest setPins at h
  cases hA : pinInput "RR/GATE/RELEASED/v1" 5 Line.fields r with
  | none => simp [hA] at h
  | some A =>
  cases hB : pinInput "RR/GATE/UNRESOLVED/v1" 6 Line.fields u with
  | none => simp [hA, hB] at h
  | some B => exact ⟨A, B, rfl, rfl⟩

/-- LOAD BINDS: a load that passed equals, up to row order, the sets whose digest the header signed, or H has an
    explicit collision (as `anchored_binding`, AnchorTheorems, with `pinInput_lines`). Axioms: three; hypothesis
    `hl` only. -/
theorem loadAdds_binds {H : Bytes → Bytes} (hl : ∀ x, (H x).length = digestBytes)
    {g : Snapshot Line × Snapshot Line} {as : List (List Line × List Line)} {a : Nat} {st : ShardState}
    {r u : Snapshot Line} (h : ShardState.loadAdds H g as a = some st)
    (hd : setsDigest H r u = some (natBE digestBytes a)) :
    (st.released.entries.Perm r.entries ∧ st.unresolved.entries.Perm u.entries ∧ st.released.count = r.count ∧
      st.unresolved.count = u.count) ∨ ∃ x y, x ≠ y ∧ H x = H y := by
  unfold ShardState.loadAdds at h
  rw [Option.filter_eq_some_iff] at h
  obtain ⟨hld, hdg⟩ := h
  have hok := (load_ok hld).1
  have hdg' : st.digest = natBE digestBytes a := by simpa using hdg
  have hs : setsDigest H st.released st.unresolved = some (natBE digestBytes a) := by
    have := hok; unfold ShardState.Ok at this; rw [this, hdg']
  let mk : Snapshot Line → Snapshot Line → Rules.Ctx := fun r u =>
    { today := 0, dmf := none, providerDeaths := none, exclusions := none, enrollment := none, released := none,
      unresolved := none, releasedPrior := r, unresolvedPrior := u, anchor := a, redo := [] }
  have h1 : anchored H (mk st.released st.unresolved) = true := by unfold anchored; simp [mk, hs]
  have h2 : anchored H (mk r u) = true := by unfold anchored; simp [mk, hd]
  obtain ⟨A, B, hA, hB⟩ := setsDigest_pins hs
  obtain ⟨A', B', hA', hB'⟩ := setsDigest_pins hd
  rcases anchored_binding hl h1 h2 rfl with ⟨e1, e2⟩ | hc
  · refine .inl ?_
    have eA : some A = some A' := by rw [← hA, ← hA']; exact e1
    have eB : some B = some B' := by rw [← hB, ← hB']; exact e2
    obtain rfl := Option.some.inj eA
    obtain rfl := Option.some.inj eB
    obtain ⟨-, c1, p1⟩ := pinInput_lines hA hA'
    obtain ⟨-, c2, p2⟩ := pinInput_lines hB hB'
    exact ⟨p1, p2, c1, c2⟩
  · exact .inr hc

end BlindLedger.Gate
