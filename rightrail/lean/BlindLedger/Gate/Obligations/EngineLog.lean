import BlindLedger.Gate.Obligations.Check

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec
open BlindLedger.Financial (FinancialInput FinancialResult evaluate rawEncodeFinancialInput)
open BlindLedger.Financial.Payment (Ledger Call Command encodeCommand)

/-! The logs the engine writes.

    `logOf` is the log of a list of commands applied in order from an empty shard.  Proved here:
    - in every such log a state row that names a row before it names a state row of its own obligation
      (`engine_log_chain`, `ChainOk`), which is what makes the obligation table of a scan sound
      (`unknown_obligation_has_no_row`);
    - an obligation a decided command leaves in its plan is the one rebuilt from the records the command wrote
      (`written_loads`), so the next command of that obligation is decided on what this one decided.

    Nothing the program runs imports this module. -/

/-! ## Which records are state rows -/

theorem enc_tag {α : Type} {c : RecCodec α} {v : Nat} {fs : List Fld} (hL : c.L = .lit 1 v :: fs) (hv : v < 256)
    (x : α) : tagOf (c.enc x) = v := by
  unfold tagOf RecCodec.enc
  rw [hL, encF_head hv]
  rfl

theorem stateC_dec_tag {b : Bytes} {row : StateRow} (h : stateC.dec b = some row) : tagOf b = 0x60 := by
  rw [← RecCodec.enc_dec h]
  exact enc_tag (v := 0x60) rfl (by decide) row

theorem stateOf_state {x : StateRow} {l : Link} {b : Bytes} (h : encFull (full stateC x l) = some b) :
    stateOf b = some (x, l) := by
  obtain ⟨hu, hwf⟩ := unwrap_full stateC_ok.2 h
  simp [stateOf, hu, enc_tag (c := stateC) (v := 0x60) rfl (by decide) x, RecCodec.dec_enc stateC_ok.1 hwf]

theorem stateOf_other {α : Type} {c : RecCodec α} {v : Nat} {fs : List Fld} (hL : c.L = .lit 1 v :: fs)
    (hv : v < 256) (hne : v ≠ 0x60) (hw : width c.L = bodyBytes) {x : α} {l : Link} {b : Bytes}
    (h : encFull (full c x l) = some b) : stateOf b = none := by
  obtain ⟨hu, -⟩ := unwrap_full hw h
  simp [stateOf, hu, enc_tag hL hv x, hne]

/-- Among the records a command writes after its command record, the state rows are exactly the `state` ones. -/
theorem Body.state_of_enc {b : Body} {r : Bytes} {row : StateRow} {l : Link} (h : b.encOk = some r)
    (hs : stateOf r = some (row, l)) : b = .state row l := by
  cases b with
  | state x l' => rw [stateOf_state h] at hs; cases hs; rfl
  | text x l' =>
    rw [stateOf_other (c := textC) (v := 0xF5) rfl (by decide) (by decide) textC_ok.2 h] at hs; cases hs
  | caseR x l' =>
    rw [stateOf_other (c := caseC) (v := 0x72) rfl (by decide) (by decide) caseC_ok.2 h] at hs; cases hs
  | oblig x l' =>
    rw [stateOf_other (c := obligC) (v := 0x8E) rfl (by decide) (by decide) obligC_ok.2 h] at hs; cases hs
  | cash x l' =>
    rw [stateOf_other (c := cashC) (v := 15) rfl (by decide) (by decide) cashC_ok.2 h] at hs; cases hs
  | mark x l' =>
    rw [stateOf_other (c := markC) (v := 0x50) rfl (by decide) (by decide) markC_ok.2 h] at hs; cases hs

theorem encAll_mem : ∀ {l : List Body} {bs : List Bytes}, encAll l = some bs → ∀ r ∈ bs, ∃ b ∈ l, b.encOk = some r
  | [], bs, h => by simp [encAll] at h; subst h; simp
  | b :: l, bs, h => by
    simp only [encAll] at h
    split at h
    · rename_i x xs hx hxs
      cases h
      intro r hr
      rcases List.mem_cons.mp hr with rfl | hr
      · exact ⟨b, by simp, hx⟩
      · obtain ⟨b', hb', he⟩ := encAll_mem hxs r hr
        exact ⟨b', List.mem_cons_of_mem _ hb', he⟩
    · cases h

/-- A state row among the records of a decided command is a `state` record of its plan. -/
theorem Plan.state_of_bytes {p : Plan} {c : Cmd} {bs : List Bytes} (h : p.bytes c = some bs) {r : Bytes}
    (hr : r ∈ bs) {row : StateRow} {l : Link} (hs : stateOf r = some (row, l)) : Body.state row l ∈ p.body := by
  unfold Plan.bytes at h
  split at h
  · rename_i b rest hb hrest
    cases h
    rcases List.mem_cons.mp hr with rfl | hr
    · rw [stateOf_other (c := cmdC) (v := 0x74) rfl (by decide) (by decide) cmdC_ok.2 hb] at hs; cases hs
    · obtain ⟨b', hb', he⟩ := encAll_mem hrest r hr
      have hb := Body.state_of_enc he hs
      subst hb
      exact hb'
  · cases h

/-! ## The obligation a result is of -/

theorem evaluate_context {i : FinancialInput} {res : FinancialResult} (h : evaluate i = some res) :
    res.context = i.context := by
  unfold evaluate at h
  split at h
  · unfold BlindLedger.Financial.evaluateWellFormed at h
    cases ht : BlindLedger.Financial.evaluateTotals i with
    | none => simp [ht] at h
    | some t =>
      simp [ht] at h
      rw [← h]
      rfl
  · cases h

/-- The result Lean gives for a payment, a reversal or an evaluation is of the obligation it was decided on. -/
theorem leanResult_context {v : View} {c : Cmd} {o : Obl} {res : FinancialResult} (ho : v.obl = some o)
    (hp : ∀ i, c.act ≠ .population i) (h : leanResult v c = some res) : res.context = o.led.input.context := by
  unfold leanResult at h
  rw [ho] at h
  cases hc : c.act with
  | population i => exact absurd hc (hp i)
  | pack p cls => simp [hc] at h
  | other k => simp [hc] at h
  | evaluate item r =>
    simp only [hc] at h
    exact (evaluate_context h).trans rfl
  | payment item pc =>
    simp only [hc] at h
    cases hout : o.led.outcome ⟨c.atMs, c.exprev, pc⟩ with
    | mutated k w post res' =>
      simp only [hout, Option.some.injEq] at h
      subst h
      obtain ⟨hpost, -, hev, -⟩ := BlindLedger.Financial.Payment.paymentTransition_mutated_post hout
      rw [evaluate_context hev, hpost]
      rfl
    | alias pid e post =>
      simp only [hout] at h
      rw [evaluate_context h, (BlindLedger.Financial.Payment.alias_shape hout).1]
      rfl
    | refused r => simp [hout] at h
    | duplicate r => simp [hout] at h
    | conflictUnchanged r => simp [hout] at h

/-! ## The row an obligation is loaded from is its newest -/

theorem replay1_head {o : Option Obl} {s : Seg} {o' : Obl} (h : replay1 o s = some o') : o'.head = s.at_ := by
  unfold replay1 at h
  dsimp only at h
  repeat' split at h
  all_goals first
    | (cases h; done)
    | (simp only [Option.some.injEq] at h; subst h; rfl)

theorem replay_head : ∀ (ss : List Seg) (o : Option Obl) (s : Seg) (o' : Obl), replay o (ss ++ [s]) = some o' →
    o'.head = s.at_
  | [], o, s, o', h => by
    cases h1 : replay1 o s with
    | none => simp [replay, h1] at h
    | some o'' =>
      simp [replay, h1] at h
      subst h
      exact replay1_head h1
  | t :: ss, o, s, o', h => by
    cases h1 : replay1 o t with
    | none => simp [replay, h1] at h
    | some o'' =>
      simp only [List.cons_append, replay, h1] at h
      exact replay_head ss (some o'') s o' h

theorem readSegs_at {fetch : Nat → Option Bytes} : ∀ (rows : List (Nat × StateRow × Link)) (acc segs : List Seg),
    ((readSegs rows acc).run fetch).1 = some segs →
      segs.map (·.at_) = acc.reverse.map (·.at_) ++ rows.map (·.1)
  | [], acc, segs, h => by
    simp [readSegs, Rd.run] at h
    subst h
    simp
  | (i, row, l) :: rest, acc, segs, h => by
    rw [readSegs] at h
    split at h
    · simp [Rd.run] at h
    · rw [Rd.run_bind] at h
      split at h
      · split at h
        · have ih := readSegs_at rest _ segs h
          simp [ih]
        · simp [Rd.run] at h
      · simp [Rd.run] at h

/-- A chain read from row `i` ends at row `i`, which is a state row of the obligation. -/
theorem readChain_last {fetch : Nat → Option Bytes} {ob : Bytes} : ∀ (fuel i : Nat)
    (acc rows : List (Nat × StateRow × Link)), ((readChain ob fuel i acc).run fetch).1 = some rows →
      ∃ pre r row l, rows = pre ++ (i, row, l) :: acc ∧ fetch i = some r ∧ stateOf r = some (row, l) ∧ row.ob = ob
  | 0, _, _, _, h => by simp [readChain, Rd.run] at h
  | fuel + 1, i, acc, rows, h => by
    cases hf : fetch i with
    | none => simp [readChain, Rd.run, hf] at h
    | some r =>
      cases hu : unwrap r with
      | none => simp [readChain, Rd.run, hf, hu] at h
      | some q =>
        obtain ⟨body, l⟩ := q
        cases hd : stateC.dec body with
        | none => simp [readChain, Rd.run, hf, hu, hd] at h
        | some row =>
          have hst : stateOf r = some (row, l) := by simp [stateOf, hu, hd, stateC_dec_tag hd]
          by_cases hob : row.ob = ob
          · by_cases hp : l.prev = 0
            · simp [readChain, Rd.run, hf, hu, hd, hob, hp] at h
              exact ⟨[], r, row, l, by simp [h], rfl, hst, hob⟩
            · by_cases hlt : l.prev - 1 < i
              · have h' : ((readChain ob fuel (l.prev - 1) ((i, row, l) :: acc)).run fetch).1 = some rows := by
                  simpa [readChain, Rd.run, hf, hu, hd, hob, hp, hlt] using h
                obtain ⟨pre, r', row', l', he, -⟩ := readChain_last fuel (l.prev - 1) ((i, row, l) :: acc) rows h'
                exact ⟨pre ++ [(l.prev - 1, row', l')], r, row, l, by simp [he], rfl, hst, hob⟩
              · simp [readChain, Rd.run, hf, hu, hd, hob, hp, hlt] at h
          · simp [readChain, Rd.run, hf, hu, hd, hob] at h

/-- What a load that gives an obligation read: its chain of state rows, the records of each row's command, and the
    replay of those. -/
theorem loadObl_parts {fetch : Nat → Option Bytes} {ob : Bytes} {h : Nat} {o : Obl}
    (hl : ((loadObl ob h).run fetch).1 = some o) : ∃ rows segs,
      ((readChain ob (h + 1) h []).run fetch).1 = some rows ∧ ((readSegs rows []).run fetch).1 = some segs ∧
        replay none segs = some o := by
  unfold loadObl at hl
  rw [Rd.run_bind] at hl
  cases hc : ((readChain ob (h + 1) h []).run fetch).1 with
  | none => simp [hc, Rd.run] at hl
  | some rows =>
    rw [hc] at hl
    dsimp only at hl
    rw [Rd.run_bind] at hl
    cases hs : ((readSegs rows []).run fetch).1 with
    | none => simp [hs, Rd.run] at hl
    | some segs =>
      rw [hs] at hl
      exact ⟨rows, segs, rfl, hs, by simpa [Rd.run] using hl⟩

theorem loadObl_of {fetch : Nat → Option Bytes} {ob : Bytes} {h : Nat} {rows : List (Nat × StateRow × Link)}
    {segs : List Seg} (hc : ((readChain ob (h + 1) h []).run fetch).1 = some rows)
    (hs : ((readSegs rows []).run fetch).1 = some segs) : ((loadObl ob h).run fetch).1 = replay none segs := by
  unfold loadObl
  rw [Rd.run_bind, hc]
  dsimp only
  rw [Rd.run_bind, hs]
  rfl

/-- An obligation loaded from row `h` has `h` as its newest row, and `h` is a state row of it. -/
theorem loadObl_head {fetch : Nat → Option Bytes} {ob : Bytes} {h : Nat} {o : Obl}
    (hl : ((loadObl ob h).run fetch).1 = some o) :
    o.head = h ∧ ∃ r row l, fetch h = some r ∧ stateOf r = some (row, l) ∧ row.ob = ob := by
  obtain ⟨rows, segs, hc, hs, hrep⟩ := loadObl_parts hl
  obtain ⟨pre, r, row, l, he, hf, hst, hob⟩ := readChain_last _ _ _ _ hc
  have hat := readSegs_at rows [] segs hs
  rw [he] at hat
  simp only [List.reverse_nil, List.map_nil, List.nil_append, List.map_append, List.map_cons] at hat
  obtain ⟨ss, t, rfl, -, ht⟩ := List.map_eq_append_iff.mp hat
  obtain ⟨s, t', rfl, hs1, ht'⟩ := List.map_eq_cons_iff.mp ht
  have : t' = [] := by simpa using ht'
  subst this
  exact ⟨(replay_head ss none s o hrep).trans hs1, r, row, l, hf, hst, hob⟩

/-! ## The links of the state rows a command writes -/

@[simp] theorem state_not_mem_textsAt (x : StateRow) (l : Link) (e : Bytes) (a c : Nat) :
    Body.state x l ∉ textsAt e a c := by
  intro h
  obtain ⟨t, l', he⟩ := mem_textsAt h
  cases he

/-- A state row a command writes starts the chain of the obligation an opening opens, or follows the newest row of
    the obligation the command was decided on; it is a row of the obligation of Lean's result. -/
theorem core_state_link {v : View} {c : Cmd} {f : Nat → Plan} (h : core v c = .ok f) (n : Nat) {x : StateRow}
    {l : Link} (hm : Body.state x l ∈ (f n).body) :
    (l.prev = 0 ∧ ∃ i, c.act = .population i ∧ scopeOfCtx i.context = c.scope ∧
        ∃ res, evaluate i = some res ∧ x.ob = obOfCtx res.context) ∨
      ∃ o res, v.obl = some o ∧ leanResult v c = some res ∧ l.prev = o.head + 1 ∧
      x.ob = obOfCtx res.context ∧
      ((∃ item pc, c.act = .payment item pc ∧ o.names c.scope item = true) ∨
        (∃ item r, c.act = .evaluate item r ∧ o.names c.scope item = true)) := by
  unfold core at h
  dsimp only at h
  repeat' split at h
  all_goals try (cases h; done)
  all_goals
    simp only [Except.ok.injEq] at h
    subst h
    simp_all [leanResult, rowOf]

/-! ## Every log the engine writes chains its state rows within their obligations -/

theorem RowAt.mono {log : List Bytes} {ob : Bytes} {j : Nat} (h : RowAt log ob j) (bs : List Bytes) :
    RowAt (log ++ bs) ob j := by
  obtain ⟨r, row, l, h1, h2, h3⟩ := h
  obtain ⟨hj, -⟩ := List.getElem?_eq_some_iff.1 h1
  exact ⟨r, row, l, by rw [List.getElem?_append_left hj]; exact h1, h2, h3⟩

theorem loadRd_obl (s : Store) (fetch : Nat → Option Bytes) (c : Cmd) :
    ((loadRd s c).run fetch).1.obl = ((loadOb s c).run fetch).1.2.2 := by
  simp [loadRd, Rd.run_bind, Rd.run]

/-- The obligation a payment, a reversal or an evaluation is decided on is the load of the obligation the command
    names, from its newest row. -/
theorem view_obl_load {s : Store} {fetch : Nat → Option Bytes} {c : Cmd} {k : Bytes} {o : Obl}
    (hk : obKey c = some k) (ho : (viewOf s fetch c).obl = some o) : ((loadObl k o.head).run fetch).1 = some o := by
  have h : ((loadOb s c).run fetch).1.2.2 = some o := by rw [← loadRd_obl]; exact ho
  simp only [loadOb, hk] at h
  rw [Rd.run_bind] at h
  cases hfnd : ((findRec (rowIs k) (Slots.of s.obl k)).run fetch).1 with
  | absent => rw [hfnd] at h; simp [Rd.run] at h
  | unread => rw [hfnd] at h; simp [Rd.run] at h
  | hit i a =>
    rw [hfnd] at h
    by_cases hro : readsObl c
    · simp only [hro, ↓reduceIte] at h
      rw [Rd.run_bind] at h
      cases hl : ((loadObl k i).run fetch).1 with
      | none => rw [hl] at h; simp [Rd.run] at h
      | some o' =>
        rw [hl] at h
        have ho' : o' = o := by simpa [Rd.run] using h
        subst ho'
        rw [(loadObl_head hl).1]
        exact hl
    · simp [hro, Rd.run] at h

/-- One command keeps the chains: the state rows it writes follow rows of their own obligation. -/
theorem apply_chain {s : Store} {log : List Bytes} {c : Cmd} (hc : ChainOk log) :
    ChainOk (log ++ (apply s (fun i => log[i]?) c).2.1) := by
  unfold apply applyView
  rcases hd : decideView (viewOf s (fun i => log[i]?) c) c s.n with ⟨d, _ | p, bs⟩
  · simpa using hc
  · show ChainOk (log ++ bs)
    obtain ⟨-, -, hbs, f, hf, rfl⟩ := decideView_some hd
    intro i r row l hr hst hp
    by_cases hlt : i < log.length
    · rw [List.getElem?_append_left hlt] at hr
      exact (hc i r row l hr hst hp).mono bs
    · rw [List.getElem?_append_right (Nat.le_of_not_lt hlt)] at hr
      have hmem : r ∈ bs := List.mem_of_getElem? hr
      rcases core_state_link hf s.n (Plan.state_of_bytes hbs hmem hst) with h0 | ⟨o, res, ho, hres, hprev, hob, hact⟩
      · exact absurd h0.1 hp
      · have hctx : res.context = o.led.input.context :=
          leanResult_context ho (by rcases hact with ⟨_, _, ha, -⟩ | ⟨_, _, ha, -⟩ <;> simp [ha]) hres
        have hk : obKey c = some row.ob := by
          rw [hob, hctx]
          rcases hact with ⟨item, pc, ha, hn⟩ | ⟨item, q, ha, hn⟩ <;>
            (simp only [Obl.names, Bool.and_eq_true, beq_iff_eq] at hn
             simp [obKey, ha, obOfCtx, hn.1, hn.2])
        obtain ⟨r', row', l', h1, h2, h3⟩ := (loadObl_head (view_obl_load hk ho)).2
        rw [hprev, Nat.add_sub_cancel]
        exact RowAt.mono ⟨r', row', l', h1, h2, h3⟩ bs

/-- `ChainOk` for every log of commands applied in order from an empty shard. -/
theorem engine_log_chain (card : Card) (reg : Array Nat) (cmds : List Cmd) : ChainOk (logOf card reg cmds).2 := by
  have key : ∀ (cmds : List Cmd) (p : Store × List Bytes), ChainOk p.2 →
      ChainOk (cmds.foldl (fun (s, log) c =>
        let r := apply s (fun i => log[i]?) c
        (r.2.2, log ++ r.2.1)) p).2 := by
    intro cmds
    induction cmds with
    | nil => intro p h; exact h
    | cons c cs ih =>
      rintro ⟨s, log⟩ h
      exact ih ((apply s (fun i => log[i]?) c).2.2, log ++ (apply s (fun i => log[i]?) c).2.1) (apply_chain h)
  exact key cmds (Store.empty card reg, []) (by intro i r row l h; simp at h)

/-! ## An obligation loads from its records as the command left it

    A decided command leaves an obligation in its plan, which nothing reads, and writes records.  The next command
    of that obligation rebuilds it from the records (`loadObl`).  Proved here: the two are the same obligation
    (`written_loads`). -/

/-- A record after the command record as a reader has it: its body and its link. -/
def Body.pair : Body → Bytes × Link
  | .text x l => (textC.enc x, l)
  | .state x l => (stateC.enc x, l)
  | .caseR x l => (caseC.enc x, l)
  | .oblig x l => (obligC.enc x, l)
  | .cash x l => (cashC.enc x, l)
  | .mark x l => (markC.enc x, l)

def Body.textOf : Body → Option TextRec
  | .text x _ => some x
  | _ => none

/-- A written record reads back as its body and link, and as a text record exactly when it is one. -/
theorem Body.unwrap_enc {b : Body} {r : Bytes} (h : b.encOk = some r) :
    unwrap r = some b.pair ∧ (if tagOf b.pair.1 = 0xF5 then textC.dec b.pair.1 else none) = b.textOf := by
  cases b with
  | text x l =>
    obtain ⟨hu, hwf⟩ := unwrap_full textC_ok.2 h
    exact ⟨hu, by
      simp [Body.pair, Body.textOf, enc_tag (c := textC) (v := 0xF5) rfl (by decide) x,
        RecCodec.dec_enc textC_ok.1 hwf]⟩
  | state x l =>
    exact ⟨(unwrap_full stateC_ok.2 h).1, by
      simp [Body.pair, Body.textOf, enc_tag (c := stateC) (v := 0x60) rfl (by decide) x]⟩
  | caseR x l =>
    exact ⟨(unwrap_full caseC_ok.2 h).1, by
      simp [Body.pair, Body.textOf, enc_tag (c := caseC) (v := 0x72) rfl (by decide) x]⟩
  | oblig x l =>
    exact ⟨(unwrap_full obligC_ok.2 h).1, by
      simp [Body.pair, Body.textOf, enc_tag (c := obligC) (v := 0x8E) rfl (by decide) x]⟩
  | cash x l =>
    exact ⟨(unwrap_full cashC_ok.2 h).1, by
      simp [Body.pair, Body.textOf, enc_tag (c := cashC) (v := 15) rfl (by decide) x]⟩
  | mark x l =>
    exact ⟨(unwrap_full markC_ok.2 h).1, by
      simp [Body.pair, Body.textOf, enc_tag (c := markC) (v := 0x50) rfl (by decide) x]⟩

theorem encAll_read : ∀ {l : List Body} {bs : List Bytes}, encAll l = some bs →
    bs.map unwrap = (l.map Body.pair).map some ∧
      (l.map Body.pair).filterMap (fun q => if tagOf q.1 = 0xF5 then textC.dec q.1 else none) =
        l.filterMap Body.textOf
  | [], bs, h => by simp [encAll] at h; subst h; simp
  | b :: l, bs, h => by
    simp only [encAll] at h
    split at h
    · rename_i x xs hx hxs
      cases h
      obtain ⟨hu, ht⟩ := Body.unwrap_enc hx
      obtain ⟨h1, h2⟩ := encAll_read hxs
      refine ⟨by simp [hu, h1], ?_⟩
      simp only [List.map_cons, List.filterMap_cons, ht, h2]
    · cases h

theorem encAll_append : ∀ {xs ys : List Body} {bs : List Bytes}, encAll (xs ++ ys) = some bs →
    ∃ b1 b2, encAll xs = some b1 ∧ encAll ys = some b2 ∧ bs = b1 ++ b2
  | [], _, bs, h => ⟨[], bs, rfl, h, rfl⟩
  | x :: xs, ys, bs, h => by
    simp only [List.cons_append, encAll] at h
    split at h
    · rename_i r rs hr hrs
      cases h
      obtain ⟨b1, b2, h1, h2, rfl⟩ := encAll_append hrs
      exact ⟨r :: b1, b2, by simp [encAll, hr, h1], h2, rfl⟩
    · cases h

theorem midElement_eq (mid : List (Bytes × Link)) :
    midElement mid = joinFrom 0 (mid.filterMap fun q => if tagOf q.1 = 0xF5 then textC.dec q.1 else none) :=
  congrArg (fun f => joinFrom 0 (mid.filterMap f)) (funext fun ⟨_, _⟩ => rfl)

/-! ### Reading the records of a command, and reading an older chain in a longer log -/

theorem readRun_enc {g : Nat → Option Bytes} : ∀ (rs : List Bytes) (us : List (Bytes × Link)) (a : Nat)
    (acc : List (Bytes × Link)), (∀ j r, rs[j]? = some r → g (a + j) = some r) → rs.map unwrap = us.map some →
      ((readRun a rs.length acc).run g).1 = some (acc.reverse ++ us)
  | [], us, a, acc, _, hu => by
    cases us with
    | nil => simp [readRun, Rd.run]
    | cons u us => simp at hu
  | r :: rs, us, a, acc, hg, hu => by
    cases us with
    | nil => simp at hu
    | cons u us =>
      simp only [List.map_cons, List.cons.injEq] at hu
      have h0 : g a = some r := by simpa using hg 0 r (by simp)
      have ih := readRun_enc rs us (a + 1) (u :: acc) (fun j q hq => by
        have h1 := hg (j + 1) q (by simpa using hq)
        have e : a + 1 + j = a + (j + 1) := by omega
        rw [e]
        exact h1) hu.2
      simp [readRun, Rd.run, h0, hu.1, ih]

theorem readRun_ext {f g : Nat → Option Bytes} (hfg : ∀ j r, f j = some r → g j = some r) : ∀ (k a : Nat)
    (acc rs : List (Bytes × Link)), ((readRun a k acc).run f).1 = some rs → ((readRun a k acc).run g).1 = some rs
  | 0, a, acc, rs, h => by simpa [readRun, Rd.run] using h
  | k + 1, a, acc, rs, h => by
    cases hf : f a with
    | none => simp [readRun, Rd.run, hf] at h
    | some r =>
      cases hu : unwrap r with
      | none => simp [readRun, Rd.run, hf, hu] at h
      | some q =>
        have h' : ((readRun (a + 1) k (q :: acc)).run f).1 = some rs := by simpa [readRun, Rd.run, hf, hu] using h
        simpa [readRun, Rd.run, hfg a r hf, hu] using readRun_ext hfg k (a + 1) (q :: acc) rs h'

/-- A chain read in a log reads the same in a log that holds the same records and more, with any more fuel, before
    any rows already gathered. -/
theorem readChain_ext {f g : Nat → Option Bytes} (hfg : ∀ j r, f j = some r → g j = some r) {ob : Bytes} :
    ∀ (fuel i : Nat) (acc rows : List (Nat × StateRow × Link)), ((readChain ob fuel i acc).run f).1 = some rows →
      ∃ pre, rows = pre ++ acc ∧ ∀ (fuel' : Nat) (acc' : List (Nat × StateRow × Link)), fuel ≤ fuel' →
        ((readChain ob fuel' i acc').run g).1 = some (pre ++ acc')
  | 0, _, _, _, h => by simp [readChain, Rd.run] at h
  | fuel + 1, i, acc, rows, h => by
    cases hf : f i with
    | none => simp [readChain, Rd.run, hf] at h
    | some r =>
      have hg := hfg i r hf
      cases hu : unwrap r with
      | none => simp [readChain, Rd.run, hf, hu] at h
      | some q =>
        obtain ⟨body, l⟩ := q
        cases hd : stateC.dec body with
        | none => simp [readChain, Rd.run, hf, hu, hd] at h
        | some row =>
          by_cases hob : row.ob = ob
          · by_cases hp : l.prev = 0
            · simp [readChain, Rd.run, hf, hu, hd, hob, hp] at h
              refine ⟨[(i, row, l)], by simp [h], fun fuel' acc' hle => ?_⟩
              obtain ⟨m, rfl⟩ : ∃ m, fuel' = m + 1 := ⟨fuel' - 1, by omega⟩
              simp [readChain, Rd.run, hg, hu, hd, hob, hp]
            · by_cases hlt : l.prev - 1 < i
              · have h' : ((readChain ob fuel (l.prev - 1) ((i, row, l) :: acc)).run f).1 = some rows := by
                  simpa [readChain, Rd.run, hf, hu, hd, hob, hp, hlt] using h
                obtain ⟨pre, he, hall⟩ := readChain_ext hfg fuel (l.prev - 1) ((i, row, l) :: acc) rows h'
                refine ⟨pre ++ [(i, row, l)], by simp [he], fun fuel' acc' hle => ?_⟩
                obtain ⟨m, rfl⟩ : ∃ m, fuel' = m + 1 := ⟨fuel' - 1, by omega⟩
                have hm := hall m ((i, row, l) :: acc') (by omega)
                simpa [readChain, Rd.run, hg, hu, hd, hob, hp, hlt] using hm
              · simp [readChain, Rd.run, hf, hu, hd, hob, hp, hlt] at h
          · simp [readChain, Rd.run, hf, hu, hd, hob] at h

theorem readSegs_ext {f g : Nat → Option Bytes} (hfg : ∀ j r, f j = some r → g j = some r) :
    ∀ (rows : List (Nat × StateRow × Link)) (acc segs : List Seg), ((readSegs rows acc).run f).1 = some segs →
      ∀ rest, ((readSegs (rows ++ rest) acc).run g).1 = ((readSegs rest segs.reverse).run g).1
  | [], acc, segs, h, rest => by
    simp [readSegs, Rd.run] at h
    subst h
    simp
  | (i, row, l) :: rows, acc, segs, h, rest => by
    rw [readSegs] at h
    split at h
    · simp [Rd.run] at h
    · rename_i hc
      rw [Rd.run_bind] at h
      split at h
      · rename_i cb lk mid hrun
        split at h
        · rename_i x hx
          rw [List.cons_append, readSegs, if_neg hc, Rd.run_bind, readRun_ext hfg _ _ _ _ hrun]
          simp only [hx]
          exact readSegs_ext hfg rows _ segs h rest
        · simp [Rd.run] at h
      · simp [Rd.run] at h

theorem replay_one (o : Option Obl) (s : Seg) : replay o [s] = replay1 o s := by
  cases h : replay1 o s <;> simp [replay, h]

theorem replay_append_some : ∀ (xs ys : List Seg) (o : Option Obl) (o' : Obl), replay o xs = some o' →
    replay o (xs ++ ys) = replay (some o') ys
  | [], _, o, o', h => by
    simp only [replay] at h
    subst h
    rfl
  | x :: xs, ys, o, o', h => by
    cases h1 : replay1 o x with
    | none => simp [replay, h1] at h
    | some o1 =>
      simp only [replay, h1] at h
      simp only [List.cons_append, replay, h1]
      exact replay_append_some xs ys (some o1) o' h

/-- The load from a state row just written: the chain read before it, then the records of its own command, replayed
    after the obligation that chain gave. -/
theorem loadObl_new {g : Nat → Option Bytes} {k : Bytes} {n : Nat} {x : CmdRec} {cl : Link} {cb sb : Bytes}
    {pre : List Body} {preB : List Bytes} {row : StateRow} {l : Link}
    (hcb : encFull (full cmdC x cl) = some cb) (hpre : encAll pre = some preB)
    (hsb : encFull (full stateC row l) = some sb)
    (hg0 : g n = some cb) (hg1 : ∀ j r, preB[j]? = some r → g (n + 1 + j) = some r)
    (hg2 : g (n + 1 + pre.length) = some sb) (hob : row.ob = k) (hcmd : row.cmd = n + 1)
    {rows : List (Nat × StateRow × Link)} {segs : List Seg} {prev : Option Obl}
    (hchain : if l.prev = 0 then rows = [] else l.prev - 1 < n + 1 + pre.length ∧
      ∀ (fuel : Nat) (acc : List (Nat × StateRow × Link)), l.prev ≤ fuel →
        ((readChain k fuel (l.prev - 1) acc).run g).1 = some (rows ++ acc))
    (hsegs : ∀ rest, ((readSegs (rows ++ rest) []).run g).1 = ((readSegs rest segs.reverse).run g).1)
    (hrep : segs = [] ∧ prev = none ∨ ∃ o, replay none segs = some o ∧ prev = some o) :
    ((loadObl k (n + 1 + pre.length)).run g).1 =
      replay1 prev ⟨x, pre.map Body.pair, n + 1 + pre.length, row, l⟩ := by
  obtain ⟨hux, hwx⟩ := unwrap_full cmdC_ok.2 hcb
  obtain ⟨hus, hws⟩ := unwrap_full stateC_ok.2 hsb
  obtain ⟨hup, -⟩ := encAll_read hpre
  have hlen := encAll_length hpre
  have hc : ((readChain k (n + 1 + pre.length + 1) (n + 1 + pre.length) []).run g).1 =
      some (rows ++ [(n + 1 + pre.length, row, l)]) := by
    by_cases hp : l.prev = 0
    · rw [if_pos hp] at hchain
      simp [readChain, Rd.run, hg2, hus, RecCodec.dec_enc stateC_ok.1 hws, hob, hp, hchain]
    · rw [if_neg hp] at hchain
      obtain ⟨hlt, hall⟩ := hchain
      simpa [readChain, Rd.run, hg2, hus, RecCodec.dec_enc stateC_ok.1 hws, hob, hp, hlt] using
        hall (n + 1 + pre.length) [(n + 1 + pre.length, row, l)] (by omega)
  have hrun : ((readRun n (pre.length + 1) []).run g).1 = some ((cmdC.enc x, cl) :: pre.map Body.pair) := by
    have h := readRun_enc (g := g) (cb :: preB) ((cmdC.enc x, cl) :: pre.map Body.pair) n [] (fun j r hj => by
      cases j with
      | zero =>
        simp only [List.getElem?_cons_zero, Option.some.injEq] at hj
        subst hj
        exact hg0
      | succ j =>
        have h1 := hg1 j r (by simpa using hj)
        have e : n + (j + 1) = n + 1 + j := by omega
        rw [e]
        exact h1) (by simp [hux, hup])
    simpa [hlen] using h
  have hs : ((readSegs (rows ++ [(n + 1 + pre.length, row, l)]) []).run g).1 =
      some (segs ++ [⟨x, pre.map Body.pair, n + 1 + pre.length, row, l⟩]) := by
    have hcond : ¬(row.cmd = 0 ∨ n + 1 + pre.length < row.cmd) := by rw [hcmd]; omega
    have e1 : row.cmd - 1 = n := by omega
    have e2 : n + 1 + pre.length - n = pre.length + 1 := by omega
    rw [hsegs, readSegs, if_neg hcond, Rd.run_bind, e1, e2, hrun]
    simp [RecCodec.dec_enc cmdC_ok.1 hwx, readSegs, Rd.run]
  rw [loadObl_of hc hs]
  rcases hrep with ⟨rfl, rfl⟩ | ⟨o, ho, rfl⟩
  · exact replay_one _ _
  · rw [replay_append_some _ _ _ _ ho]
    exact replay_one _ _

/-! ### The shape of what a decided command writes -/

/-- The records before the first state row, and that row. -/
def stateSplit : List Body → Option (List Body × StateRow × Link)
  | [] => none
  | .state x l :: _ => some ([], x, l)
  | b :: rest => (stateSplit rest).map fun q => (b :: q.1, q.2)

theorem stateSplit_spec : ∀ {bs pre : List Body} {x : StateRow} {l : Link}, stateSplit bs = some (pre, x, l) →
    ∃ post, bs = pre ++ .state x l :: post
  | [], _, _, _, h => by simp [stateSplit] at h
  | b :: rest, pre, x, l, h => by
    cases b
    case state y m =>
      simp only [stateSplit, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      exact ⟨rest, rfl⟩
    all_goals
      simp only [stateSplit] at h
      cases hr : stateSplit rest with
      | none => simp [hr] at h
      | some q =>
        obtain ⟨p, y', l'⟩ := q
        simp only [hr, Option.map_some, Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl, rfl⟩ := h
        obtain ⟨post, rfl⟩ := stateSplit_spec hr
        exact ⟨post, rfl⟩

theorem stateSplit_append : ∀ (xs rest : List Body), (∀ x l, Body.state x l ∉ xs) →
    stateSplit (xs ++ rest) = (stateSplit rest).map fun q => (xs ++ q.1, q.2)
  | [], rest, _ => by
    rw [List.nil_append]
    cases stateSplit rest <;> rfl
  | b :: xs, rest, h => by
    have ih := stateSplit_append xs rest fun x l hm => h x l (List.mem_cons_of_mem _ hm)
    cases b
    case state y m => exact (h y m (by simp)).elim
    all_goals
      simp only [List.cons_append, stateSplit, ih]
      cases stateSplit rest <;> rfl

theorem stateSplit_texts (e : Bytes) (a c : Nat) (rest : List Body) :
    stateSplit (textsAt e a c ++ rest) = (stateSplit rest).map fun q => (textsAt e a c ++ q.1, q.2) :=
  stateSplit_append _ _ (by simp)

theorem stateSplit_textsAt (e : Bytes) (a c : Nat) : stateSplit (textsAt e a c) = none := by
  have h := stateSplit_texts e a c []
  simpa [stateSplit] using h

theorem stateSplit_cases {α : Type} (g : α → CaseRec) (lk : Link) (ks : List α) (rest : List Body) :
    stateSplit (ks.map (fun k => Body.caseR (g k) lk) ++ rest) =
      (stateSplit rest).map fun q => (ks.map (fun k => Body.caseR (g k) lk) ++ q.1, q.2) :=
  stateSplit_append _ _ (by simp)

theorem textOf_linkTexts : ∀ (ts : List TextRec) (a c : Nat), (linkTexts ts a c).filterMap Body.textOf = ts
  | [], _, _ => rfl
  | t :: ts, a, c => by simp [linkTexts, Body.textOf, textOf_linkTexts ts]

/-- The text records of an element join back to it. -/
theorem join_textsAt (e : Bytes) (a c : Nat) :
    joinFrom 0 ((textsAt e a c).filterMap Body.textOf) = if e.isEmpty then none else some e := by
  unfold textsAt
  cases e with
  | nil => simp [joinFrom]
  | cons b e => simp [textOf_linkTexts, join_parts 0 (b :: e) (by simp)]

theorem textOf_cases {α : Type} (g : α → CaseRec) (lk : Link) (ks : List α) :
    (ks.map fun k => Body.caseR (g k) lk).filterMap Body.textOf = [] := by
  induction ks with
  | nil => rfl
  | cons k ks ih => simp [Body.textOf]

theorem encodeCommand_isEmpty (pc : Command) : (encodeCommand pc).isEmpty = false := by cases pc <;> rfl

theorem rawEncode_isEmpty (i : FinancialInput) : (rawEncodeFinancialInput i).isEmpty = false := by
  have hm : BlindLedger.Financial.financialCodecMagic ≠ [] := by decide +kernel
  rw [BlindLedger.Financial.rawEncodeFinancialInput_eq_magic_append]
  simp [hm]

theorem lgOf_testBit1 (b : Bool) : (lgOf b).testBit 1 = b := (lgOf_bits b).1

/-- The expected revision a command record holds reads back as the command's. -/
theorem exprev_round (e : Option Nat) :
    (if (e.map (· + 1)).getD 0 = 0 then none else some ((e.map (· + 1)).getD 0 - 1)) = e := by
  cases e <;> simp

attribute [local simp high] lgOf_testBit1 exprev_round stateSplit_texts stateSplit_textsAt stateSplit_cases
  join_textsAt textOf_cases encodeCommand_isEmpty rawEncode_isEmpty

/-- Where a decided command puts its state row: it names the command record, the obligation the plan leaves has it
    as its newest row, and that obligation is the one the command names. -/
theorem core_shape {v : View} {c : Cmd} {f : Nat → Plan} (h : core v c = .ok f) (n : Nat) :
    (stateSplit (f n).body).map (fun q => q.2.1.cmd) = (f n).obl.map (fun _ => n + 1) ∧
      (f n).obl.map (·.2.head) = (stateSplit (f n).body).map (fun q => n + 1 + q.1.length) ∧
      (f n).obl.map (·.1) = obKey c := by
  unfold core at h
  dsimp only at h
  repeat' split at h
  all_goals try (cases h; done)
  all_goals
    simp only [Except.ok.injEq] at h
    subst h
    simp_all [stateSplit, rowOf, obKey, obOfCtx]
  all_goals omega

/-- Replaying the records a decided command writes, after the obligation it was decided on, gives the obligation
    its plan leaves.  `mid` stands for the records between the command record and the state row, which hold the
    command's element as text. -/
theorem core_replay {v : View} {c : Cmd} {f : Nat → Plan} (h : core v c = .ok f) (n : Nat)
    {mid : List (Bytes × Link)}
    (hm : midElement mid =
      joinFrom 0 ((((stateSplit (f n).body).map (·.1)).getD []).filterMap Body.textOf)) :
    (stateSplit (f n).body).bind (fun q => replay1 (if q.2.2.prev = 0 then none else v.obl)
      ⟨(f n).cmd c, mid, ((f n).obl.map (·.2.head)).getD 0, q.2.1, q.2.2⟩) = (f n).obl.map (·.2) := by
  unfold core at h
  dsimp only at h
  repeat' split at h
  all_goals try (cases h; done)
  all_goals
    simp only [Except.ok.injEq] at h
    subst h
    simp_all [stateSplit, Body.textOf, List.filterMap_cons, Plan.cmd, replay1, rowOf, stepOut, ← stepOut_eq,
      command_rebuild, opening_rebuild, decodeInput_eq]

/-! ### The theorem -/

theorem written_at (log : List Bytes) (cb sb : Bytes) (preB postB : List Bytes) :
    (log ++ cb :: (preB ++ sb :: postB))[log.length]? = some cb ∧
      (∀ (j : Nat) (r : Bytes), preB[j]? = some r →
        (log ++ cb :: (preB ++ sb :: postB))[log.length + 1 + j]? = some r) ∧
      (log ++ cb :: (preB ++ sb :: postB))[log.length + 1 + preB.length]? = some sb ∧
      ∀ (j : Nat) (r : Bytes), log[j]? = some r → (log ++ cb :: (preB ++ sb :: postB))[j]? = some r := by
  refine ⟨?_, fun j r hj => ?_, ?_, fun j r hj => ?_⟩
  · rw [List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]
    rfl
  · have hjl : j < preB.length := (List.getElem?_eq_some_iff.1 hj).1
    have h1 : log.length ≤ log.length + 1 + j := by omega
    have e : log.length + 1 + j - log.length = j + 1 := by omega
    rw [List.getElem?_append_right h1, e, List.getElem?_cons_succ, List.getElem?_append_left hjl]
    exact hj
  · have h1 : log.length ≤ log.length + 1 + preB.length := by omega
    have e : log.length + 1 + preB.length - log.length = preB.length + 1 := by omega
    rw [List.getElem?_append_right h1, e, List.getElem?_cons_succ, List.getElem?_append_right (Nat.le_refl _),
      Nat.sub_self]
    rfl
  · have hjl : j < log.length := (List.getElem?_eq_some_iff.1 hj).1
    rw [List.getElem?_append_left hjl]
    exact hj

/-- After a decided command, the obligation its plan leaves is the one the log gives: loading it from the state row
    the command wrote, on the log with the command's records, gives exactly that obligation.  So the next command
    is decided on what this one decided, read from the records alone. -/
theorem written_loads {s : Store} {log : List Bytes} {c : Cmd} {d : Disp} {p : Plan} {bs : List Bytes}
    (hn : s.n = log.length) (hd : decideView (viewOf s (fun i => log[i]?) c) c s.n = (d, some p, bs))
    {k : Bytes} {o' : Obl} (ho : p.obl = some (k, o')) :
    ((loadObl k o'.head).run fun i => (log ++ bs)[i]?).1 = some o' := by
  obtain ⟨-, -, hbs, f, hf, rfl⟩ := decideView_some hd
  obtain ⟨hcmd, hhead, hkey⟩ := core_shape hf s.n
  cases hq : stateSplit (f s.n).body with
  | none =>
    rw [hq, ho] at hhead
    simp at hhead
  | some q =>
    obtain ⟨pre, row, l⟩ := q
    have hcmd' : row.cmd = log.length + 1 := by
      rw [hq, ho, hn] at hcmd
      simpa using hcmd
    have hhead' : o'.head = log.length + 1 + pre.length := by
      rw [hq, ho, hn] at hhead
      simpa using hhead
    have hk : obKey c = some k := by
      rw [ho] at hkey
      simpa using hkey.symm
    obtain ⟨post, hbody⟩ := stateSplit_spec hq
    unfold Plan.bytes at hbs
    split at hbs
    · rename_i cb rest hcb hrest
      cases hbs
      rw [hbody] at hrest
      obtain ⟨preB, b2, hpre, h2, rfl⟩ := encAll_append hrest
      simp only [encAll] at h2
      split at h2
      · rename_i sb postB hsb hpost
        cases h2
        have hlen := encAll_length hpre
        obtain ⟨hg0, hg1, hg2, hext⟩ := written_at log cb sb preB postB
        rw [hlen] at hg2
        -- Replaying the command's own records gives the plan's obligation.
        have hrp : replay1 (if l.prev = 0 then none else (viewOf s (fun i => log[i]?) c).obl)
            ⟨(f s.n).cmd c, pre.map Body.pair, log.length + 1 + pre.length, row, l⟩ = some o' := by
          have h := core_replay hf s.n (mid := pre.map Body.pair) (by
            rw [hq, midElement_eq, (encAll_read hpre).2]
            rfl)
          rw [hq, ho] at h
          rw [← hhead']
          exact h
        have hmem : Body.state row l ∈ (f s.n).body := by rw [hbody]; simp
        rw [hhead']
        rcases core_state_link hf s.n hmem with ⟨h0, i, hact, hscope, res, hev, hob⟩ |
          ⟨o, res, hvo, hres, hprev, hob, hact⟩
        · -- An opening: the row starts the chain.
          have hrowk : row.ob = k := by
            have h := hk
            simp only [obKey, hact, Option.some.injEq] at h
            rw [hob, evaluate_context hev, ← h, obOfCtx, hscope]
          rw [if_pos h0] at hrp
          rw [← hrp]
          exact loadObl_new (rows := []) (segs := []) hcb hpre hsb hg0 hg1 hg2 hrowk hcmd' (by rw [if_pos h0])
            (fun _ => rfl) (Or.inl ⟨rfl, rfl⟩)
        · -- A payment, a reversal or an evaluation: the row follows the newest row of the obligation loaded.
          have hctx : res.context = o.led.input.context :=
            leanResult_context hvo (by rcases hact with ⟨_, _, ha, -⟩ | ⟨_, _, ha, -⟩ <;> simp [ha]) hres
          have hk' : obKey c = some row.ob := by
            rw [hob, hctx]
            rcases hact with ⟨item, pc, ha, hnm⟩ | ⟨item, q, ha, hnm⟩ <;>
              (simp only [Obl.names, Bool.and_eq_true, beq_iff_eq] at hnm
               simp [obKey, ha, obOfCtx, hnm.1, hnm.2])
          have hrowk : row.ob = k := by
            rw [hk] at hk'
            exact (Option.some.inj hk').symm
          have hold := view_obl_load hk hvo
          obtain ⟨rows, segs, hc, hs, hrep⟩ := loadObl_parts hold
          obtain ⟨r0, -, -, hr0, -⟩ := (loadObl_head hold).2
          have hlt : o.head < log.length := (List.getElem?_eq_some_iff.1 hr0).1
          obtain ⟨pre', he, hall⟩ := readChain_ext hext _ _ _ _ hc
          have hpre' : pre' = rows := by simpa using he.symm
          subst hpre'
          have hne : ¬l.prev = 0 := by omega
          have hsub : l.prev - 1 = o.head := by omega
          rw [if_neg hne, hvo] at hrp
          rw [← hrp]
          refine loadObl_new (rows := pre') (segs := segs) hcb hpre hsb hg0 hg1 hg2 hrowk hcmd' ?_
            (readSegs_ext hext _ _ _ hs) (Or.inr ⟨o, hrep, rfl⟩)
          rw [if_neg hne, hsub]
          exact ⟨by omega, fun fuel acc hle => hall fuel acc (by omega)⟩
      · cases h2
    · cases hbs

end BlindLedger.Gate.Obligations
