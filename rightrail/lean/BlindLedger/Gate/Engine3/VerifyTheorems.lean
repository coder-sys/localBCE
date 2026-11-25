import BlindLedger.Gate.Engine3.Verify

/-! What the checker's recovery path guarantees of the facts it carries (`VC.Good`: `sb` is the bytes of the store, and a
    held digest is `factsTag` of the facts).

    - A fact frame `checkF` accepts appends records to the store (`FactFrame.admit_st`), so the bytes it extends stay
      the store's, and it drops the held digest (`checkF_good`).
    - A decision frame `checkFrame` accepts leaves the facts, their bytes and the held digest as they were
      (`checkFrame_dec_facts`); so every frame `checkFrame` accepts keeps `VC.Good` (`checkFrame_good`).
    - `saveLast` returns its state holding the digest it computed (`saveLast_ret`); on a good state that digest is
      `factsTag` of the store flattened afresh (`saveLast_good`).  The bytes written are not modelled.
    - A state `resume` returns is good, and the digest it holds is both `factsTag` of its facts and the facts digest of a
      last state that `Last.dec` authenticates under the returned key, whose batch, position, lines, heads, head and
      authority record it also returns (`resume_good`): from `vfacts` only when its size is whole bodies (`loadFacts`),
      so its bodies flatten back to it, and its digest equals the last state's; from the replay only when the replayed
      facts' digest equals it.

    The world of an `IO` action is explicit: `x s = .ok a s'` says `x`, run from world `s`, returns `a`.  Whatever the
    files, clocks and other cores give, these hold.  Not stated here: the loops that chain them (`pump`, `follow`,
    `followC`, `factsBefore`), which are `partial`; the state `rebuild` starts from (`VerifyMain.lean`, which defines the
    checker's `main` and so cannot be imported beside the other checkers); and that the facts `resume` keeps from
    `vfacts` are those the replay of the log would give (their digests are equal; the facts are equal only as far as the
    digest is collision free).
    Synthetic, nonpayment, non-PHI. -/

namespace BlindLedger.Gate.Engine3.Verify

open BlindLedger.Gate BlindLedger.Gate.Flat

/-! ## Small cases: a store's bytes extended by each admitted vector frame are the bytes of the store after it; a
    `vfacts` of whole bodies is cut into bodies that flatten back to it, and one that is not whole bodies is not. -/

open BlindLedger.Gate.FactFrame in
#guard [({} : Facts), vS1, vS2, vS3].zip [vS1, vS2, vS3, vS4] |>.all fun (a, b) =>
  extendSb (storeBytes a.st) a.st.size b.st == storeBytes b.st

/-- `vfacts` cut into bodies, as `resume` cuts it. -/
private abbrev cutBodies (sb : ByteArray) : FactFrame.Store :=
  (Array.range (sb.size / FactCodec.bodyBytes)).map fun i =>
    (sb.extract (FactCodec.bodyBytes * i) (FactCodec.bodyBytes * (i + 1))).toList

#guard [0, 1, 2, 3].all fun k =>
  let sb : ByteArray := ⟨(List.range (FactCodec.bodyBytes * k)).toArray.map (·.toUInt8)⟩
  storeBytes (cutBodies sb) == sb
#guard
  let sb : ByteArray := ⟨(List.range (FactCodec.bodyBytes + 7)).toArray.map (·.toUInt8)⟩
  storeBytes (cutBodies sb) != sb

/-! ## Results of `IO` actions -/

/-- Every value `x` returns, from any world, satisfies `P`. -/
private def Post {α : Type} (x : IO α) (P : α → Prop) : Prop := ∀ s a s', x s = .ok a s' → P a

private theorem Post.bind {α β : Type} {x : IO α} {f : α → IO β} {Q : α → Prop} {P : β → Prop} (hx : Post x Q)
    (hf : ∀ a, Q a → Post (f a) P) : Post (x >>= f) P := by
  intro s b s' h
  change EST.bind x f s = _ at h
  simp only [EST.bind] at h
  split at h
  · exact hf _ (hx _ _ _ (by assumption)) _ _ _ h
  · cases h

private theorem Post.any {α : Type} (x : IO α) : Post x fun _ => True := fun _ _ _ _ => trivial

private theorem Post.pure {α : Type} {a : α} {P : α → Prop} (h : P a) : Post (pure a) P := by
  intro s b s' e
  cases e
  exact h

private theorem Post.throw {α : Type} {e : IO.Error} {P : α → Prop} : Post (throw e) P := by
  intro s b s' h
  cases h

private theorem Post.pure_bind {α β : Type} {a : α} {f : α → IO β} {P : β → Prop} (h : Post (f a) P) :
    Post (Pure.pure a >>= f) P :=
  fun s b s' e => h s b s' e

/-- One step of a `Post` goal: a return, a throw, a bind of a return (its value kept), a bind (any value of the action),
    or a branch. -/
local macro "post_step" : tactic => `(tactic| first
  | (with_reducible apply Post.pure)
  | (with_reducible apply Post.throw)
  | (with_reducible apply Post.pure_bind; try dsimp only)
  | (with_reducible apply Post.bind (Post.any _); intro _ _)
  | split
  | (dsimp only))

/-! ## Pure facts -/

private theorem checkFact_st {H : List UInt8 → List UInt8} {fx : FactFrame.Facts} {rf : FactFrame.Refs}
    {shard batch : Nat} {prev pin rq rqb anb an : List UInt8} {x : FactFrame.Facts × FactFrame.Refs}
    (h : FactFrame.checkFact H fx rf shard batch prev pin rq rqb anb an = .ok x) : ∃ xs, x.1.st = fx.st ++ xs := by
  unfold FactFrame.checkFact at h
  split at h
  · cases h
  · rename_i q ents fx0 hr
    dsimp only at h
    split at h
    · cases h
      exact FactFrame.admit_st (FactFrame.replay_ok hr).2.2.2.2.2
    · split at h <;> cases h

private theorem replay_st {H : List UInt8 → List UInt8} {fx : FactFrame.Facts} {shard batch : Nat}
    {prev pin rq rqb : List UInt8} {F : FactFrame.Req × List FactFrame.Entry × FactFrame.Facts → FactFrame.Refs}
    {x : FactFrame.Facts × FactFrame.Refs}
    (h : Except.map (fun y => (y.2.2, F y)) (FactFrame.replay H fx shard batch prev pin rq rqb) = .ok x) :
    ∃ xs, x.1.st = fx.st ++ xs := by
  cases e : FactFrame.replay H fx shard batch prev pin rq rqb with
  | error f => rw [e] at h; cases h
  | ok y =>
    rw [e] at h
    cases h
    obtain ⟨q, ents, fx'⟩ := y
    exact FactFrame.admit_st (FactFrame.replay_ok e).2.2.2.2.2

/-- The facts `checkF` takes from a frame, checked with or without its answer, extend the store. -/
private theorem answer_st {b : Bool} {H : List UInt8 → List UInt8} {fx : FactFrame.Facts} {rf : FactFrame.Refs}
    {shard batch : Nat} {prev pin rq rqb anb an : List UInt8}
    {F : FactFrame.Req × List FactFrame.Entry × FactFrame.Facts → FactFrame.Refs} {x : FactFrame.Facts × FactFrame.Refs}
    (h : (if b = true then Except.map (fun y => (y.2.2, F y)) (FactFrame.replay H fx shard batch prev pin rq rqb)
      else FactFrame.checkFact H fx rf shard batch prev pin rq rqb anb an) = .ok x) : ∃ xs, x.1.st = fx.st ++ xs := by
  split at h
  · exact replay_st h
  · exact checkFact_st h

private theorem extend_good {sb : ByteArray} {st st' : FactFrame.Store} (hsb : sb = storeBytes st)
    (h : ∃ xs, st' = st ++ xs) : extendSb sb st.size st' = storeBytes st' := by
  obtain ⟨xs, rfl⟩ := h
  exact extendSb_eq hsb

private theorem ba_beq {a b : ByteArray} (h : (a == b) = true) : a = b :=
  ByteArray.ext (beq_iff_eq.mp (show (a.data == b.data) = true from h))

private theorem ba_bne {a b : ByteArray} (h : ¬(a != b) = true) : a = b := by
  apply ba_beq
  cases e : (a == b)
  · exact absurd (by simp [bne, e]) h
  · rfl

/-- A state holding digest `fd` of its facts, whose bytes are its store's, is good. -/
private theorem held_good {v : VC} {fd : ByteArray} (hsb : v.sb = storeBytes v.fs.st) (ht : v.tg = some fd)
    (hfd : fd = factsTag v.sb v.rf v.ft) : v.Good ∧ v.tg = some (factsTag v.sb v.rf v.ft) :=
  And.intro (And.intro hsb fun t e => by rw [ht] at e; cases e; exact hfd) (ht.trans (congrArg some hfd))

private theorem chunks_flat (B : Nat) (sb : ByteArray) : ∀ k, B * k ≤ sb.size →
    ((Array.range k).map fun i => (sb.extract (B * i) (B * (i + 1))).toList).toList.flatten =
      (sb.extract 0 (B * k)).data.toList
  | 0, _ => by simp
  | k + 1, hk => by
    have h1 : B * k ≤ B * (k + 1) := Nat.mul_le_mul_left B (Nat.le_succ k)
    rw [Array.range_succ, Array.map_append, Array.toList_append, List.flatten_append,
      chunks_flat B sb k (Nat.le_trans h1 hk), ByteArray.extract_eq_extract_append_extract (B * k) (Nat.zero_le _) h1,
      ByteArray.toList_data_append]
    simp [Bin.toList_eq']

/-- A `vfacts` of whole bodies, cut into bodies as `resume` cuts it, flattens back to itself. -/
private theorem cut_bytes {sb : ByteArray} (h : sb.size % FactCodec.bodyBytes = 0) : storeBytes (cutBodies sb) = sb := by
  have hm : FactCodec.bodyBytes * (sb.size / FactCodec.bodyBytes) = sb.size :=
    Nat.mul_div_cancel' (Nat.dvd_of_mod_eq_zero h)
  apply ByteArray.ext
  simp only [storeBytes, cutBodies]
  rw [chunks_flat _ _ _ (Nat.le_of_eq hm), hm, ByteArray.extract_zero_size]

/-- Facts `resume` keeps from a `vfacts` of whole bodies: their bytes are the store's, and the digest they were checked
    against is theirs. -/
private theorem kept_good {sb ft0 fd : ByteArray} {fs : FactFrame.Facts} {rf : FactFrame.Refs} {ft sb' : ByteArray}
    (hw : sb.size % FactCodec.bodyBytes = 0)
    (h : (if (factsTag sb (FactFrame.Refs.ofStore FactFrame.sha (cutBodies sb)) ft0 == fd) = true then
        some ((⟨cutBodies sb, FactFrame.Ix.ofStore (cutBodies sb)⟩ : FactFrame.Facts),
          FactFrame.Refs.ofStore FactFrame.sha (cutBodies sb), ft0, sb)
      else none) = some (fs, rf, ft, sb')) :
    sb' = storeBytes fs.st ∧ fd = factsTag sb' rf ft := by
  split at h
  · rename_i hc
    cases h
    exact And.intro (cut_bytes hw).symm (ba_beq hc).symm
  · cases h

/-! ## The recovery path -/

private theorem loadFacts_whole (d : String) :
    Post (loadFacts d) fun r => ∀ sb, r = some sb → sb.size % FactCodec.bodyBytes = 0 := by
  unfold loadFacts
  repeat' post_step
  all_goals intro sb e
  all_goals first
    | (cases e; done)
    | (cases e; exact beq_iff_eq.mp (by assumption))
    | (split at e
       · cases e; exact beq_iff_eq.mp (by assumption)
       · cases e)

private theorem checkF_post {c : Ctx} {v : VC} {n : Nat} {rqb anb : ByteArray} {t : Trailer} (hv : v.Good) :
    Post (checkF c v n rqb anb t) fun r => ∀ v' k, r = .ok (v', k) → v'.Good ∧ v'.tg = none := by
  have hsb : v.sb = storeBytes v.fs.st := hv.1
  unfold checkF
  repeat' post_step
  all_goals intro v' k e
  all_goals first
    | (cases e; done)
    | (cases e
       refine And.intro (And.intro ?_ fun _ e => nomatch e) rfl
       try dsimp only
       first
        | exact extend_good hsb (checkFact_st (by with_reducible assumption))
        | exact extend_good hsb (replay_st (by with_reducible assumption))
        | exact extend_good hsb (answer_st (by with_reducible assumption)))

/-- A fact frame `checkF` accepts keeps the bytes the store's (its records are appended to them) and holds no digest. -/
theorem checkF_good {c : Ctx} {v v' : VC} {n : Nat} {rqb anb : ByteArray} {t : Trailer}
    {k : Task (Except Mismatch Nat)} {s s' : Void IO.RealWorld} (hv : v.Good)
    (h : checkF c v n rqb anb t s = .ok (.ok (v', k)) s') : v'.Good ∧ v'.tg = none :=
  checkF_post hv s _ s' h v' k rfl

private theorem checkFrame_dec_post {c : Ctx} {v : VC} {p : PreD} :
    Post (checkFrame c (some v) (.ok (.dec p))) fun r => ∀ v' k, r = .ok (v', k) →
      v'.fs = v.fs ∧ v'.rf = v.rf ∧ v'.ft = v.ft ∧ v'.sb = v.sb ∧ v'.tg = v.tg := by
  unfold checkFrame
  repeat' post_step
  all_goals intro v' k e
  all_goals first
    | (cases e; done)
    | (cases e; exact ⟨rfl, rfl, rfl, rfl, rfl⟩)
    | (cases e; split <;> exact ⟨rfl, rfl, rfl, rfl, rfl⟩)

/-- A decision frame `checkFrame` accepts leaves the facts, the reference entries, the fact frames' digest, the bytes and
    the held digest as they were. -/
theorem checkFrame_dec_facts {c : Ctx} {v v' : VC} {p : PreD} {k : Task (Except Mismatch Nat)}
    {s s' : Void IO.RealWorld} (h : checkFrame c (some v) (.ok (.dec p)) s = .ok (.ok (v', k)) s') :
    v'.fs = v.fs ∧ v'.rf = v.rf ∧ v'.ft = v.ft ∧ v'.sb = v.sb ∧ v'.tg = v.tg :=
  checkFrame_dec_post s _ s' h v' k rfl

/-- Every frame `checkFrame` accepts, on a good state, gives a good state. -/
theorem checkFrame_good {c : Ctx} {v : Option VC} {p : Except String Pre} {v' : VC} {k : Task (Except Mismatch Nat)}
    {s s' : Void IO.RealWorld} (hv : ∀ x, v = some x → x.Good) (h : checkFrame c v p s = .ok (.ok (v', k)) s') :
    v'.Good := by
  cases v with
  | none =>
    have hp : Post (checkFrame c none p) fun r => ∀ v' k, r = .ok (v', k) → v'.Good := by
      unfold checkFrame
      repeat' post_step
      all_goals intro v' k e
      all_goals cases e
    exact hp s _ s' h v' k rfl
  | some x =>
    have hx : x.Good := hv x rfl
    have hsb : x.sb = storeBytes x.fs.st := hx.1
    match p, h with
    | .ok (.dec q), h =>
      obtain ⟨e1, e2, e3, e4, e5⟩ := checkFrame_dec_facts h
      refine And.intro ?_ ?_
      · rw [e4, e1]; exact hsb
      · intro t ht; rw [e5] at ht; rw [e4, e2, e3]; exact hx.2 t ht
    | .ok (.fact rqb anb t), h =>
      have hp : Post (checkFrame c (some x) (.ok (.fact rqb anb t)))
          fun r => ∀ v' k, r = .ok (v', k) → v'.Good ∧ v'.tg = none := by
        unfold checkFrame
        repeat' (first
          | (with_reducible apply checkF_post; first | exact hx | exact hv _ (by assumption))
          | (with_reducible apply Post.bind (checkF_post hx); intro _ _)
          | post_step)
        all_goals first
          | assumption
          | (intro v' k e; cases e; done)
      exact (hp s _ s' h v' k rfl).1
    | .error w, h =>
      have hp : Post (checkFrame c (some x) (.error w)) fun r => ∀ v' k, r = .ok (v', k) → v'.Good := by
        unfold checkFrame
        repeat' post_step
        all_goals intro v' k e
        all_goals cases e
      exact hp s _ s' h v' k rfl

private theorem saveLast_post {c : Ctx} {k : ByteArray} {v : VC} {pos lines : Nat} :
    Post (saveLast c k v pos lines) fun v' => v' = { v with tg := some v.tag } := by
  unfold saveLast
  repeat' post_step
  all_goals rfl

/-- `saveLast` returns its state holding the digest it computed. -/
theorem saveLast_ret {c : Ctx} {k : ByteArray} {v v' : VC} {pos lines : Nat} {s s' : Void IO.RealWorld}
    (h : saveLast c k v pos lines s = .ok v' s') : v' = { v with tg := some v.tag } :=
  saveLast_post s _ s' h

/-- On a good state `saveLast` returns a good state, whose held digest is `factsTag` of the store flattened afresh. -/
theorem saveLast_good {c : Ctx} {k : ByteArray} {v v' : VC} {pos lines : Nat} {s s' : Void IO.RealWorld} (hv : v.Good)
    (h : saveLast c k v pos lines s = .ok v' s') :
    v'.Good ∧ v'.tg = some (factsTag (storeBytes v.fs.st) v.rf v.ft) := by
  have e := saveLast_ret h
  subst e
  have hsb : v.sb = storeBytes v.fs.st := hv.1
  have ht := VC.tag_eq hv
  refine And.intro (And.intro hsb ?_) (congrArg some ht)
  intro t e
  cases e
  show v.tag = factsTag v.sb v.rf v.ft
  rw [ht, hsb]

private theorem resume_post {c : Ctx} {log : UInt32} {size : Nat} :
    Post (resume c log size) fun r => ∀ v k pos lines, r = .ok (v, k, pos, lines) →
      (v.Good ∧ v.tg = some (factsTag v.sb v.rf v.ft)) ∧ ∃ raw l, Last.dec k c.shard raw = some l ∧
        v.tg = some l.fd ∧ v.n = l.n ∧ pos = l.pos ∧ lines = l.lines ∧ v.hr = l.hr ∧ v.hu = l.hu ∧ v.prev = l.prev ∧
        v.au = l.au := by
  unfold resume
  repeat' (first
    | (with_reducible apply Post.bind (loadFacts_whole _); intro _ whole)
    | post_step)
  all_goals intro v k pos lines e
  all_goals first
    | (cases e; done)
    | (cases e
       refine And.intro (held_good ?_ rfl ?_) ⟨_, _, ‹_›, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
       · try dsimp only
         all_goals with_reducible rfl
       · try dsimp only
         all_goals exact (ba_bne (by with_reducible assumption)).symm)
    | (cases e
       exact And.intro
         ((kept_good (whole _ rfl) (by with_reducible assumption)).elim fun h1 h2 => held_good h1 rfl h2)
         ⟨_, _, ‹_›, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩)

/-- A state `resume` returns is good and holds the digest of its facts, which is the facts digest of a last state that
    `Last.dec` authenticates under the returned key; the batch, position, lines, heads, head and authority record it
    returns are that last state's. -/
theorem resume_good {c : Ctx} {log : UInt32} {size : Nat} {v : VC} {k : ByteArray} {pos lines : Nat}
    {s s' : Void IO.RealWorld} (h : resume c log size s = .ok (.ok (v, k, pos, lines)) s') :
    v.Good ∧ v.tg = some (factsTag v.sb v.rf v.ft) ∧ ∃ raw l, Last.dec k c.shard raw = some l ∧
      v.tg = some l.fd ∧ v.n = l.n ∧ pos = l.pos ∧ lines = l.lines ∧ v.hr = l.hr ∧ v.hu = l.hu ∧ v.prev = l.prev ∧
      v.au = l.au :=
  match resume_post s _ s' h v k pos lines rfl with
  | ⟨⟨hg, ht⟩, hl⟩ => ⟨hg, ht, hl⟩

/-! ## Their statements and what they rest on

    Their statements reach the checker's file and clock primitives (`extern`), which the statement digest refuses, so
    they are not in `AxiomCheck.lean`'s pinned list.  Each statement and its axioms are pinned here instead (changing a
    theorem must change its pin in the same commit), and `AxiomCheck` imports this file so the `gate_axioms` build
    checks them. -/

/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example (v : VC) :
    v.Good ↔ (v.sb = storeBytes v.fs.st ∧ ∀ t, v.tg = some t → t = factsTag v.sb v.rf v.ft) := Iff.rfl
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {c : Ctx} {v v' : VC} {n : Nat} {rqb anb : ByteArray} {t : Trailer} {k : Task (Except Mismatch Nat)}
    {s s' : Void IO.RealWorld}, v.Good → checkF c v n rqb anb t s = .ok (.ok (v', k)) s' → v'.Good ∧ v'.tg = none :=
  @BlindLedger.Gate.Engine3.Verify.checkF_good
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {c : Ctx} {v v' : VC} {p : PreD} {k : Task (Except Mismatch Nat)} {s s' : Void IO.RealWorld},
    checkFrame c (some v) (.ok (.dec p)) s = .ok (.ok (v', k)) s' →
    v'.fs = v.fs ∧ v'.rf = v.rf ∧ v'.ft = v.ft ∧ v'.sb = v.sb ∧ v'.tg = v.tg :=
  @BlindLedger.Gate.Engine3.Verify.checkFrame_dec_facts
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {c : Ctx} {v : Option VC} {p : Except String Pre} {v' : VC} {k : Task (Except Mismatch Nat)}
    {s s' : Void IO.RealWorld}, (∀ x, v = some x → x.Good) → checkFrame c v p s = .ok (.ok (v', k)) s' → v'.Good :=
  @BlindLedger.Gate.Engine3.Verify.checkFrame_good
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {c : Ctx} {k : ByteArray} {v v' : VC} {pos lines : Nat} {s s' : Void IO.RealWorld},
    saveLast c k v pos lines s = .ok v' s' → v' = { v with tg := some v.tag } :=
  @BlindLedger.Gate.Engine3.Verify.saveLast_ret
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {c : Ctx} {k : ByteArray} {v v' : VC} {pos lines : Nat} {s s' : Void IO.RealWorld}, v.Good →
    saveLast c k v pos lines s = .ok v' s' → v'.Good ∧ v'.tg = some (factsTag (storeBytes v.fs.st) v.rf v.ft) :=
  @BlindLedger.Gate.Engine3.Verify.saveLast_good
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {c : Ctx} {log : UInt32} {size : Nat} {v : VC} {k : ByteArray} {pos lines : Nat} {s s' : Void IO.RealWorld},
    resume c log size s = .ok (.ok (v, k, pos, lines)) s' →
    v.Good ∧ v.tg = some (factsTag v.sb v.rf v.ft) ∧ ∃ raw l, Last.dec k c.shard raw = some l ∧
      v.tg = some l.fd ∧ v.n = l.n ∧ pos = l.pos ∧ lines = l.lines ∧ v.hr = l.hr ∧ v.hu = l.hu ∧ v.prev = l.prev ∧
      v.au = l.au :=
  @BlindLedger.Gate.Engine3.Verify.resume_good

/-- info: 'BlindLedger.Gate.Engine3.Verify.checkF_good' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms checkF_good
/-- info: 'BlindLedger.Gate.Engine3.Verify.checkFrame_dec_facts' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms checkFrame_dec_facts
/-- info: 'BlindLedger.Gate.Engine3.Verify.checkFrame_good' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms checkFrame_good
/-- info: 'BlindLedger.Gate.Engine3.Verify.saveLast_ret' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms saveLast_ret
/-- info: 'BlindLedger.Gate.Engine3.Verify.saveLast_good' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms saveLast_good
/-- info: 'BlindLedger.Gate.Engine3.Verify.resume_good' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms resume_good

end BlindLedger.Gate.Engine3.Verify
