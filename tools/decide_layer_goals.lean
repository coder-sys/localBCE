import BlindLedger.Gate.Anchor
import BlindLedger.Gate.AnchorTheorems
import BlindLedger.Gate.Rules.ShardRun

/-! Decide layer: goals (S0, 2026-10-03). Design: `C:\Users\neers\rrb\designs\decide-layer-v1.md` §3.
    Definitions are final text for the S1 builder; every `sorry` is a proof the builder owes.
    Homes in the product tree: the `Rules` definitions go to `Gate/Rules/Spec.lean`; `ShardState.decide` and
    `loadAdds` to `Gate/Anchor.lean`; `runDecide` and every theorem to the new `Gate/Rules/DecideLayer.lean`
    (proofs only). This file is outside `lean/`, so no executable, library target, TCB report or pin
    manifest sees it. Check: `lake -d lean env lean tools/decide_layer_goals.lean` over a warm build.
    `decide_one_payment_per_line` is dropped by lead ruling L1 (`carried_sealB` + `run_one_payment_per_line`). -/

namespace BlindLedger.Gate.Rules

/-- A shard decides with its own checkpoints as both the sets read and the priors; this is gate-rules-resident's
    `next c₀ r` (= `carried c₀ r.released r.unresolved`; one def, not two). -/
def carried (c₀ : Ctx) (rel unr : Snapshot Line) : Ctx :=
  { c₀ with released := some rel, releasedPrior := rel, unresolved := some unr, unresolvedPrior := unr }

/-- One batch of a shard, as the decide layer receives it: snapshots, today, redo and the frame's anchor (in
    `ctx`; its set fields are ignored), the registry's answers, the lines. -/
structure Batch where
  ctx : Ctx
  owners : List Owner
  lines : List Line

/-- The rows a batch appends to each set (multi-shard §C, unchanged text). -/
def batchFresh (c : Ctx) (r : Result) : List Line × List Line :=
  (r.released.entries.drop (releasedSet c).length, r.unresolved.entries.drop (unresolvedSet c).length)

/-- Spec of the carried state: the fold of `decideReg` over all of shard k's prior batches. -/
def shardSets (k : Nat) (g : Snapshot Line × Snapshot Line) (ts : List Batch) : Snapshot Line × Snapshot Line :=
  ts.foldl (fun s t => let r := decideReg (carried t.ctx s.1 s.2) k t.owners t.lines; (r.released, r.unresolved)) g

/-- What the store persists: each batch's appended rows. -/
def addsOf (k : Nat) (g : Snapshot Line × Snapshot Line) : List Batch → List (List Line × List Line)
  | [] => []
  | t :: ts => let c := carried t.ctx g.1 g.2; let r := decideReg c k t.owners t.lines
               batchFresh c r :: addsOf k (r.released, r.unresolved) ts

/-- Replay of stored rows onto genesis (the load path's spec). -/
def replay (g : Snapshot Line × Snapshot Line) (as : List (List Line × List Line)) : Snapshot Line × Snapshot Line :=
  as.foldl (fun s a => (⟨s.1.asOf, s.1.entries.length + a.1.length, s.1.entries ++ a.1⟩,
                        ⟨s.2.asOf, s.2.entries.length + a.2.length, s.2.entries ++ a.2⟩)) g

def settleFreeInc (fresh : List Line) (p : List Nat) : List Nat := p.filter fun i => !(fresh.map (·.id)).contains i

end BlindLedger.Gate.Rules

namespace BlindLedger.Gate

/-- The decide layer's step: `stepReg` on the state's own sets as the sets read. -/
def ShardState.decide (H : Bytes → Bytes) (st : ShardState) (c₀ : Rules.Ctx) (k : Nat) (os : List Rules.Owner)
    (b : List Rules.Line) : Option (Rules.Result × ShardState) :=
  st.stepReg H (Rules.carried c₀ st.released st.unresolved) k os b

/-- Load: replay stored rows, refuse unless they hash to the signed anchor. -/
def ShardState.loadAdds (H : Bytes → Bytes) (g : Rules.Snapshot Rules.Line × Rules.Snapshot Rules.Line)
    (as : List (List Rules.Line × List Rules.Line)) (anchor : Nat) : Option ShardState :=
  let s := Rules.replay g as
  (ShardState.load H s.1 s.2).filter (·.digest == natBE digestBytes anchor)

/-- Spec only (DecideLayer.lean): `decide` threaded through a shard's batches. Each frame's anchor is the
    batch's own (`t.ctx.anchor`, read from the producer's last sealed header), so a run that is `some` is one
    whose every anchor named the previous state's digest. -/
def ShardState.runDecide (H : Bytes → Bytes) (k : Nat) :
    ShardState → List Rules.Batch → Option (List Rules.Result × ShardState)
  | st, [] => some ([], st)
  | st, t :: ts =>
    match st.decide H t.ctx k t.owners t.lines with
    | none => none
    | some (r, st') => (ShardState.runDecide H k st' ts).map fun (rs, s) => (r :: rs, s)

end BlindLedger.Gate

namespace BlindLedger.Gate.Rules

/-- The view of a carried context is the state itself, chained or not (`view` returns `o.getD prior` = prior). -/
theorem carried_sets (c₀ : Ctx) (rel unr : Snapshot Line) :
    releasedSet (carried c₀ rel unr) = rel.entries ∧ unresolvedSet (carried c₀ rel unr) = unr.entries := by
  sorry

/-- A carried batch only appends (`advance`; §C's `decideReg_sets` specialised; no `loose` rows). -/
theorem carried_append (c₀ : Ctx) (rel unr : Snapshot Line) (k : Nat) (os : List Owner) (b : List Line) :
    let c := carried c₀ rel unr; let r := decideReg c k os b
    r.released.entries = rel.entries ++ (batchFresh c r).1 ∧ r.unresolved.entries = unr.entries ++ (batchFresh c r).2 := by
  sorry

/-- REFINEMENT (load): replaying the stored rows gives the spec fold (entries; asOf kept). -/
theorem replay_addsOf (k : Nat) (g : Snapshot Line × Snapshot Line) (ts : List Batch) :
    ((replay g (addsOf k g ts)).1.entries, (replay g (addsOf k g ts)).2.entries) =
      ((shardSets k g ts).1.entries, (shardSets k g ts).2.entries) := by
  sorry

/-- COMPOSITION with the World model: a carried decide is a seal World accepts (the guard's set conjuncts hold by
    `carried_sets`), and it moves World exactly as the runtime state moves. With `run_one_payment_per_line`
    (ShardRun.lean, unchanged) this is the headline for the mshist-1 case (lead ruling L1). -/
theorem carried_sealB {w : World} {k : Nat} {c₀ : Ctx} {rel unr : Snapshot Line} {os : List Owner} {b : List Line}
    (hr : w.rel k = rel.entries) (hu : w.unr k = unr.entries) (hos : ∀ o ∈ os, o.shard = k → w.reg o.id = some k) :
    ∃ w', w.step (.sealB k (carried c₀ rel unr) os b) = some w' ∧
      w'.rel k = (decideReg (carried c₀ rel unr) k os b).released.entries ∧
      w'.unr k = (decideReg (carried c₀ rel unr) k os b).unresolved.entries := by
  sorry

/-- The acceptance test as a theorem: a line id already in the carried released set is ALREADY_DECIDED. If the
    proof needs a stronger hypothesis than `hnr` (`seen0` drops own lines the batch carries), state the minimal one
    and report it. -/
theorem carried_resend_held (c₀ : Ctx) (rel unr : Snapshot Line) (k : Nat) (os : List Owner) (b : List Line)
    (l : Line) (hl : l ∈ ready k os b) (hin : ∃ x ∈ rel.entries, x.id = l.id)
    (hnr : ¬ c₀.redo.contains l.pay) :
    ∀ d ∈ (decideReg (carried c₀ rel unr) k os b).decisions, d.line = l → Reason.ALREADY_DECIDED ∈ d.reasons := by
  sorry

/-- Settle from the batch (§C, restated against carried): the frees computed at decide time are the spec's. -/
theorem settleFreeInc_carried (c₀ : Ctx) (rel unr : Snapshot Line) (k : Nat) (os : List Owner) (b : List Line)
    (hp : ∀ i ∈ pendingOf k os, ∀ x ∈ rel.entries ++ unr.entries, x.id ≠ i) :
    let c := carried c₀ rel unr; let r := decideReg c k os b
    settleFreeInc ((batchFresh c r).1 ++ (batchFresh c r).2) (pendingOf k os) =
      settleFree r.released.entries r.unresolved.entries (pendingOf k os) := by
  sorry

end BlindLedger.Gate.Rules

namespace BlindLedger.Gate

open Rules

/-- REFINEMENT (step): a decide step is decideReg on the carried sets and keeps the cache sound (from
    `stepReg_some` and `load_ok`). Axioms: three; no H hypothesis. -/
theorem decide_ok {H : Bytes → Bytes} {st st' : ShardState} {c₀ : Ctx} {k : Nat} {os : List Owner}
    {b : List Line} {r : Result} (hs : st.Ok H) (h : st.decide H c₀ k os b = some (r, st')) :
    r = decideReg (carried c₀ st.released st.unresolved) k os b ∧ st'.Ok H ∧
      st'.released = r.released ∧ st'.unresolved = r.unresolved := by
  sorry

/-- REFINEMENT (run): any accepted sequence of decide steps carries exactly `shardSets` of all prior batches. -/
theorem decide_run_fold {H : Bytes → Bytes} {k : Nat} :
    ∀ (ts : List Batch) (st st' : ShardState) (rs : List Result), st.Ok H →
      ShardState.runDecide H k st ts = some (rs, st') →
      (st'.released.entries, st'.unresolved.entries) =
        ((shardSets k (st.released, st.unresolved) ts).1.entries,
         (shardSets k (st.released, st.unresolved) ts).2.entries) := by
  sorry

/-- LOAD BINDS: a load that passed equals, up to row order, the sets whose digest the header signed. From
    `anchored_binding` and `pinInput_lines` (both proved, AnchorTheorems). Axioms: three; hypotheses `hl` and
    H injective. -/
theorem loadAdds_binds {H : Bytes → Bytes} (hl : ∀ x, (H x).length = digestBytes) (hinj : Function.Injective H)
    {g : Snapshot Line × Snapshot Line} {as : List (List Line × List Line)} {a : Nat} {st : ShardState}
    {r u : Snapshot Line} (h : ShardState.loadAdds H g as a = some st)
    (hd : setsDigest H r u = some (natBE digestBytes a)) :
    st.released.entries.Perm r.entries ∧ st.unresolved.entries.Perm u.entries ∧ st.released.count = r.count ∧
      st.unresolved.count = u.count := by
  sorry

end BlindLedger.Gate
