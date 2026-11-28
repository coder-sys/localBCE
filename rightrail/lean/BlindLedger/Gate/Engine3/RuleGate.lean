import BlindLedger.Gate.RuleSet.Spec
import BlindLedger.Gate.Flat.Worker

/-! The signed rule set on the rows-file engine (conformance/RULESET_V1.md section 9).  A batch with requests takes
    `RuleSet.gateStep` on the shard's authority record and the rule-set records the frame presents, then the frame's
    asserted rule-set floor against the head after the step.  A batch that passes writes the head and its version into
    the record after it; any other is held whole and writes nothing.
    Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.RuleGate

open BlindLedger.Gate BlindLedger.Gate.Flat.Worker

/-- The hold word of a step that does not decide. -/
def word : RuleSet.Why → String
  | .refused _ => "RULESET_REFUSED"
  | .unsupported => "RULESET_NOT_RUN"
  | .missing => "RULESET_MISSING"
  | .other => "RULESET_OTHER"

/-- A shard behind the tenant (one-store design §16.1 rule 10): the frame asserts a rule-set version above the shard's.
    Then a first record is admitted after its signing window has ended, and only when it is the asserted one. -/
def lateOf (r : AuthRec) (a : Frame.Auth) : Option Bytes := if r.rsv < a.rsv then some a.rs else none

/-- A pending frame decided under the authority record `p` that the frame's floors `a` have passed
    (`right_rail_gate_chain.behind`, as `Flat.Worker.commitBin`): a grant floor or the key-set epoch below the frame's, a
    rule-set version below, or the same version with another rule set.  It can never be signed, so it is cut. -/
def passedBy (p : AuthRec) (a : Frame.Auth) : Bool :=
  !(a.floor.all (· ≤ p.floor)) || p.rat.epoch < a.kfloor || p.rsv < a.rsv || (p.rsv == a.rsv && p.rs != a.rs)

/-- The rows-file engine's cut test on a pending frame's stored record `pau` is the pinned engine's
    (`Flat.Worker.commitBin`, its `passed`), written out here as there, for every record and every frame. -/
theorem passedBy_worker (pau : Bytes) (au : Frame.Auth) :
    (decAuth pau).any (passedBy · au) =
      (match decAuth pau with
        | some p => !(au.floor.all (· ≤ p.floor)) || p.rat.epoch < au.kfloor || p.rsv < au.rsv ||
            (p.rsv == au.rsv && p.rs != au.rs)
        | none => false) := by
  cases decAuth pau <;> rfl

/-- The rule-set head and version after a batch with requests, on a shard whose record is `r`, for the frame's authority
    section `a`: the step on the records the frame presents (`a.rsets`), then the asserted floor against its result.  The
    key-set head is needed only to admit a first record; `headOf` gives it (none: held `HEAD`) and is called only then,
    because it verifies the key set again. -/
def after (verify : Bytes → Bytes → Bytes → Bool) (headOf : Unit → Option SnapshotV2.Head) (tenant : Bytes) (B : Nat)
    (r : AuthRec) (a : Frame.Auth) : Except String (Bytes × Nat) := do
  let g ← match a.rsets with
    | [x] =>
      if r.rs == zeroDigest then
        match headOf () with
        | some H => (RuleSet.startStep verify H tenant B (lateOf r a) x).mapError word
        | none => .error "HEAD"
      else (RuleSet.heldStep r.rs a.rsets).mapError word
    | _ => (RuleSet.heldStep r.rs a.rsets).mapError word
  match floorHold g.head g.ver a with
  | some w => .error w
  | none => pure (g.head, g.ver)

/-- Whenever the key-set head is `H`, the engine's step is `RuleSet.gateStep` from the shard's head, then the floor. -/
theorem after_eq {verify headOf tenant B r a H} (hH : headOf () = some H) :
    after verify headOf tenant B r a =
      ((RuleSet.gateStep verify H tenant B r.rs (lateOf r a) a.rsets).mapError word >>= fun g =>
        match floorHold g.head g.ver a with
        | some w => .error w
        | none => pure (g.head, g.ver)) := by
  unfold after RuleSet.gateStep
  rcases a with ⟨pin, floor, kfloor, rsv, rs, grant, keyset, release, ksteps, byps, rsets, reqs⟩
  dsimp only
  rcases rsets with _ | ⟨x, _ | ⟨y, t⟩⟩
  · rfl
  · by_cases hz : (r.rs == zeroDigest) = true
    · simp only [hz, if_true, hH]
    · simp only [hz, Bool.false_eq_true, if_false]
  · rfl

/-- What a batch that passes went through: the shard's head kept (with every record in force presented again), or a first
    record admitted under the key-set head on a shard with none; and the frame's asserted floor met by the result. -/
theorem after_ok {verify headOf tenant B r a d v} (h : after verify headOf tenant B r a = .ok (d, v)) :
    ∃ g : RuleSet.GateStep, (RuleSet.heldStep r.rs a.rsets = .ok g ∨
      ∃ H x, headOf () = some H ∧ a.rsets = [x] ∧ r.rs = zeroDigest ∧
        RuleSet.startStep verify H tenant B (lateOf r a) x = .ok g) ∧
      floorHold g.head g.ver a = none ∧ d = g.head ∧ v = g.ver := by
  have fin : ∀ (g : RuleSet.GateStep), (match floorHold g.head g.ver a with
      | some w => (.error w : Except String (Bytes × Nat))
      | none => pure (g.head, g.ver)) = .ok (d, v) → floorHold g.head g.ver a = none ∧ d = g.head ∧ v = g.ver := by
    intro g hg
    split at hg
    · cases hg
    · rename_i hf
      simp only [pure, Except.pure, Except.ok.injEq, Prod.mk.injEq] at hg
      exact ⟨hf, hg.1.symm, hg.2.symm⟩
  have held : ∀ (e : Except RuleSet.Why RuleSet.GateStep), e = RuleSet.heldStep r.rs a.rsets →
      (e.mapError word >>= fun g => match floorHold g.head g.ver a with
        | some w => (.error w : Except String (Bytes × Nat))
        | none => pure (g.head, g.ver)) = .ok (d, v) →
      ∃ g : RuleSet.GateStep, (RuleSet.heldStep r.rs a.rsets = .ok g ∨
        ∃ H x, headOf () = some H ∧ a.rsets = [x] ∧ r.rs = zeroDigest ∧
          RuleSet.startStep verify H tenant B (lateOf r a) x = .ok g) ∧
        floorHold g.head g.ver a = none ∧ d = g.head ∧ v = g.ver := by
    intro e he hg
    rcases e with w | g
    · cases hg
    · exact ⟨g, Or.inl he.symm, fin g hg⟩
  unfold after at h
  split at h
  · rename_i x hx
    split at h
    · rename_i hz
      split at h
      · rename_i H hH
        cases hs : RuleSet.startStep verify H tenant B (lateOf r a) x with
        | error w => rw [hs] at h; cases h
        | ok g =>
          rw [hs] at h
          exact ⟨g, Or.inr ⟨H, x, hH, hx, by simpa using hz, hs⟩, fin g h⟩
      · cases h
    · exact held _ rfl h
  · exact held _ rfl h

/-- A shard behind the tenant moves its rule-set head only to the record the tenant asserts (rule 10). -/
theorem after_late {verify headOf tenant B r a d v} (hl : r.rsv < a.rsv)
    (h : after verify headOf tenant B r a = .ok (d, v)) : d = r.rs ∨ d = a.rs := by
  obtain ⟨g, hg, -, rfl, -⟩ := after_ok h
  rcases hg with hg | ⟨H, x, -, -, hz, hs⟩
  · rcases RuleSet.heldStep_ok hg with ⟨-, hz, rfl⟩ | ⟨-, -, -, -, rfl⟩
    · exact Or.inl hz.symm
    · exact Or.inl rfl
  · obtain ⟨A, -, -, hla, rfl⟩ := RuleSet.startStep_ok hs
    simp only [lateOf, hl, if_true] at hla
    rcases hla with hla | hla
    · cases hla
    · simp only [Option.some.injEq] at hla
      exact Or.inr hla.symm

/-- While a rule set is in force on the shard, a batch passes only when the frame presents exactly the record in force
    again (it decodes, has that digest and is runnable), and the head stays. -/
theorem after_held {verify headOf tenant B r a d v} (hz : r.rs ≠ zeroDigest)
    (h : after verify headOf tenant B r a = .ok (d, v)) :
    ∃ x A, a.rsets = [x] ∧ RuleSet.reload r.rs x = some A ∧ d = r.rs ∧ v = A.doc.version := by
  obtain ⟨g, hg, -, rfl, rfl⟩ := after_ok h
  rcases hg with hg | ⟨-, -, -, -, hz', -⟩
  · rcases RuleSet.heldStep_ok hg with ⟨-, hz', -⟩ | ⟨x, A, hx, hA, rfl⟩
    · exact absurd hz' hz
    · exact ⟨x, A, hx, hA, rfl, rfl⟩
  · exact absurd hz' hz

/-- A batch that passes meets the frame's asserted rule-set floor: its version is at least the asserted one, and at the
    asserted version it has the asserted digest. -/
theorem after_floor {verify headOf tenant B r a d v} (h : after verify headOf tenant B r a = .ok (d, v)) :
    a.rsv ≤ v ∧ (v = a.rsv → d = a.rs) := by
  obtain ⟨g, -, hf, rfl, rfl⟩ := after_ok h
  exact floorHold_none hf

end BlindLedger.Gate.Engine3.RuleGate
