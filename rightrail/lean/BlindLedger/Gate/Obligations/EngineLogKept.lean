import BlindLedger.Gate.Obligations.EngineLogForward

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec
open BlindLedger.Financial (FinancialInput FinancialResult ControlPack evaluate decodeFinancialInput decodeControlPack
  encodeControlPack rawEncodeFinancialInput rawEncodeFinancialResult)
open BlindLedger.Financial.Payment (Ledger Call Command ReverseCommand readCommand encodeCommand commitInput)

/-! Part 3 of `EngineLogChecks`: after a decided command the checker's tables stand in the same relation to the
    engine's store and log, now with the records the command wrote (`Kept`).

    Nothing the program runs imports this module. -/

/-! ## The newest command record after a scan -/

theorem scan_cmd {s : Store} {r b : Bytes} {l : Link} {x : CmdRec} (hu : unwrap r = some (b, l))
    (ht : tagOf b = 0x74) (hx : cmdC.dec b = some x) :
    (s.scan r).cmdPrev = s.n + 1 ∧ (s.scan r).cmdCount = l.count ∧ (s.scan r).lastMs = x.atMs := by
  obtain ⟨card, reg, n, ident, obl, cp, cc, lm⟩ := s
  simp [Store.scan, hu, ht, hx]

theorem scan_other {s : Store} {r : Bytes} {q : Bytes × Link} (hu : unwrap r = some q) (ht : tagOf q.1 ≠ 0x74) :
    (s.scan r).cmdPrev = s.cmdPrev ∧ (s.scan r).cmdCount = s.cmdCount ∧ (s.scan r).lastMs = s.lastMs := by
  obtain ⟨card, reg, n, ident, obl, cp, cc, lm⟩ := s
  obtain ⟨b, l⟩ := q
  have ht' : ¬tagOf b = 0x74 := ht
  by_cases h2 : tagOf b = 0x60
  · cases hx : stateC.dec b <;> simp [Store.scan, hu, h2, hx]
  · simp [Store.scan, hu, ht', h2]

theorem Body.pair_tag (b : Body) : tagOf b.pair.1 ≠ 0x74 := by
  cases b with
  | text x l => simp [Body.pair, enc_tag (c := textC) (v := 0xF5) rfl (by decide) x]
  | state x l => simp [Body.pair, enc_tag (c := stateC) (v := 0x60) rfl (by decide) x]
  | caseR x l => simp [Body.pair, enc_tag (c := caseC) (v := 0x72) rfl (by decide) x]
  | oblig x l => simp [Body.pair, enc_tag (c := obligC) (v := 0x8E) rfl (by decide) x]
  | cash x l => simp [Body.pair, enc_tag (c := cashC) (v := 15) rfl (by decide) x]
  | mark x l => simp [Body.pair, enc_tag (c := markC) (v := 0x50) rfl (by decide) x]

/-- The records after a command record leave the newest command record as it is. -/
theorem foldl_scan_body : ∀ {body : List Body} {rs : List Bytes} (s : Store), encAll body = some rs →
    (rs.foldl Store.scan s).cmdPrev = s.cmdPrev ∧ (rs.foldl Store.scan s).cmdCount = s.cmdCount ∧
      (rs.foldl Store.scan s).lastMs = s.lastMs
  | [], rs, s, h => by simp [encAll] at h; subst h; exact ⟨rfl, rfl, rfl⟩
  | b :: body, rs, s, h => by
    simp only [encAll] at h
    split at h
    · rename_i x xs hx hxs
      cases h
      obtain ⟨h1, h2, h3⟩ := foldl_scan_body (s.scan x) hxs
      obtain ⟨g1, g2, g3⟩ := scan_other (s := s) (Body.unwrap_enc hx).1 (Body.pair_tag b)
      simp only [List.foldl_cons]
      exact ⟨h1.trans g1, h2.trans g2, h3.trans g3⟩
    · cases h

/-- After the records of a decided command, the newest command record is the command's own. -/
theorem written_cmd {s : Store} {p : Plan} {c : Cmd} {bs : List Bytes} (h : p.bytes c = some bs) :
    (bs.foldl Store.scan s).cmdPrev = s.n + 1 ∧ (bs.foldl Store.scan s).cmdCount = p.link.count ∧
      (bs.foldl Store.scan s).lastMs = c.atMs := by
  obtain ⟨cb, rest, rfl, hcb, hrest⟩ := Plan.bytes_cons h
  obtain ⟨hu, hwf⟩ := unwrap_full cmdC_ok.2 hcb
  obtain ⟨g1, g2, g3⟩ := scan_cmd (s := s) hu (enc_tag (c := cmdC) (v := 0x74) rfl (by decide) _)
    (RecCodec.dec_enc cmdC_ok.1 hwf)
  obtain ⟨h1, h2, h3⟩ := foldl_scan_body (s.scan cb) hrest
  simp only [List.foldl_cons]
  exact ⟨h1.trans g1, h2.trans g2, h3.trans g3⟩

/-! ## The obligation table after the records of a decided command -/

theorem rows_textsAt (e : Bytes) (a c : Nat) : (textsAt e a c).filterMap Body.row? = [] := by
  rw [List.filterMap_eq_nil_iff]
  intro b hb
  obtain ⟨t, l, rfl⟩ := mem_textsAt hb
  rfl

theorem rows_cases {α : Type} (g : α → CaseRec) (lk : Link) (ks : List α) :
    (ks.map fun k => Body.caseR (g k) lk).filterMap Body.row? = [] := by
  rw [List.filterMap_eq_nil_iff]
  intro b hb
  obtain ⟨k, -, rfl⟩ := List.mem_map.1 hb
  rfl

attribute [local simp high] rows_textsAt rows_cases

/-- A decided command writes at most one state row. -/
theorem core_one_row {v : View} {c : Cmd} {f : Nat → Plan} (h : core v c = .ok f) (n : Nat) :
    ((f n).body.filterMap Body.row?).length ≤ 1 := by
  unfold core at h
  dsimp only at h
  repeat' split at h
  all_goals try (cases h; done)
  all_goals
    simp only [Except.ok.injEq] at h
    subst h
    simp_all [List.filterMap_append, List.filterMap_cons, Body.row?]

theorem stateSplit_none : ∀ {bs : List Body}, stateSplit bs = none → bs.filterMap Body.row? = []
  | [], _ => rfl
  | b :: rest, h => by
    cases b
    case state y m => simp [stateSplit] at h
    all_goals
      simp only [stateSplit] at h
      cases hr : stateSplit rest with
      | some q => simp [hr] at h
      | none => simp [List.filterMap_cons, Body.row?, stateSplit_none hr]

/-- Records that are not state rows leave the obligation table as it is. -/
theorem foldl_scan_rows : ∀ {body : List Body} {rs : List Bytes} (s : Store), encAll body = some rs →
    body.filterMap Body.row? = [] → (rs.foldl Store.scan s).obl = s.obl
  | [], rs, s, h, _ => by simp [encAll] at h; subst h; rfl
  | b :: body, rs, s, h, h0 => by
    simp only [encAll] at h
    split at h
    · rename_i x xs hx hxs
      cases h
      rw [List.filterMap_cons] at h0
      split at h0
      · rename_i hb
        have hno : stateOf x = none := by
          cases hs : stateOf x with
          | none => rfl
          | some q =>
            obtain ⟨row, l⟩ := q
            rw [Body.state_of_enc hx hs] at hb
            exact absurd hb (by simp [Body.row?])
        have h1 := Store.scan_obl s x
        rw [hno] at h1
        simp only [List.foldl_cons]
        exact (foldl_scan_rows (s.scan x) hxs h0).trans h1
      · cases h0
    · cases h

theorem scan_cmd_obl {s : Store} {x : CmdRec} {l : Link} {cb : Bytes} (hcb : encFull (full cmdC x l) = some cb) :
    (s.scan cb).obl = s.obl := by
  have h1 := Store.scan_obl s cb
  rw [stateOf_other (c := cmdC) (v := 0x74) rfl (by decide) (by decide) cmdC_ok.2 hcb] at h1
  exact h1

/-- A command that writes no state row leaves the obligation table as it is. -/
theorem written_table_none {s : Store} {p : Plan} {c : Cmd} {bs : List Bytes} (hbs : p.bytes c = some bs)
    (hq : stateSplit p.body = none) : (bs.foldl Store.scan s).obl = s.obl := by
  obtain ⟨cb, rest, rfl, hcb, hrest⟩ := Plan.bytes_cons hbs
  simp only [List.foldl_cons]
  exact (foldl_scan_rows (s.scan cb) hrest (stateSplit_none hq)).trans (scan_cmd_obl hcb)

/-- A command that writes one state row puts that row's number in the obligation table, in place of the row it
    follows. -/
theorem written_table_some {s : Store} {p : Plan} {c : Cmd} {bs : List Bytes} (hbs : p.bytes c = some bs)
    {pre : List Body} {row : StateRow} {l : Link} (hq : stateSplit p.body = some (pre, row, l))
    (hone : (p.body.filterMap Body.row?).length ≤ 1) :
    (bs.foldl Store.scan s).obl = Slots.put s.obl row.ob l.prev (s.n + 1 + pre.length) := by
  obtain ⟨cb, rest, rfl, hcb, hrest⟩ := Plan.bytes_cons hbs
  obtain ⟨post, hbody⟩ := stateSplit_spec hq
  rw [hbody] at hrest hone
  simp only [List.filterMap_append, List.filterMap_cons, Body.row?, List.length_append, List.length_cons] at hone
  have hpre0 : pre.filterMap Body.row? = [] := List.eq_nil_of_length_eq_zero (by omega)
  have hpost0 : post.filterMap Body.row? = [] := List.eq_nil_of_length_eq_zero (by omega)
  obtain ⟨preB, b2, hpre, h2, rfl⟩ := encAll_append hrest
  simp only [encAll] at h2
  split at h2
  · rename_i sb postB hsb hpost
    cases h2
    have hrow : ((preB.foldl Store.scan (s.scan cb)).scan sb).obl =
        Slots.put (preB.foldl Store.scan (s.scan cb)).obl row.ob l.prev (preB.foldl Store.scan (s.scan cb)).n := by
      have h1 := Store.scan_obl (preB.foldl Store.scan (s.scan cb)) sb
      rw [stateOf_state hsb] at h1
      exact h1
    simp only [List.foldl_cons, List.foldl_append]
    rw [foldl_scan_rows _ hpost hpost0, hrow, foldl_scan_rows _ hpre hpre0, scan_cmd_obl hcb,
      (foldl_scan_fixed preB (s.scan cb)).1, (Store.scan_fixed s cb).1, encAll_length hpre]
  · cases h2

/-- The state row a decided command writes stands where the table says. -/
theorem written_row {p : Plan} {c : Cmd} {bs : List Bytes} (hbs : p.bytes c = some bs) {pre : List Body}
    {row : StateRow} {l : Link} (hq : stateSplit p.body = some (pre, row, l)) (log : List Bytes) :
    ∃ sb, (log ++ bs)[log.length + 1 + pre.length]? = some sb ∧ stateOf sb = some (row, l) := by
  obtain ⟨cb, rest, rfl, hcb, hrest⟩ := Plan.bytes_cons hbs
  obtain ⟨post, hbody⟩ := stateSplit_spec hq
  rw [hbody] at hrest
  obtain ⟨preB, b2, hpre, h2, rfl⟩ := encAll_append hrest
  simp only [encAll] at h2
  split at h2
  · rename_i sb postB hsb hpost
    cases h2
    obtain ⟨-, -, hg2, -⟩ := written_at log cb sb preB postB
    rw [encAll_length hpre] at hg2
    exact ⟨sb, hg2, stateOf_state hsb⟩
  · cases h2

/-- The state row of a decided command is of the obligation the command names.  It starts the chain of an
    obligation the engine did not know, or follows the newest row of the obligation the command was decided on. -/
theorem row_of_core {v : View} {c : Cmd} {f : Nat → Plan} (hf : core v c = .ok f) (n : Nat) {row : StateRow}
    {l : Link} (hm : Body.state row l ∈ (f n).body) {k : Bytes} (hk : obKey c = some k) :
    row.ob = k ∧ ((l.prev = 0 ∧ v.oblKnown = false) ∨ ∃ o, v.obl = some o ∧ l.prev = o.head + 1) := by
  rcases core_state_link hf n hm with ⟨h0, i, hact, hscope, res, hev, hob⟩ |
    ⟨o, res, hvo, hres, hprev, hob, hact⟩
  · refine ⟨?_, Or.inl ⟨h0, ?_⟩⟩
    · have h := hk
      simp only [obKey, hact, Option.some.injEq] at h
      rw [hob, evaluate_context hev, ← h, obOfCtx, hscope]
    · obtain ⟨_, _, _, _, _, _, hun, _⟩ := core_open hf hact
      exact hun
  · have hctx : res.context = o.led.input.context :=
      leanResult_context hvo (by rcases hact with ⟨_, _, ha, -⟩ | ⟨_, _, ha, -⟩ <;> simp [ha]) hres
    have hk' : obKey c = some row.ob := by
      rw [hob, hctx]
      rcases hact with ⟨item, pc, ha, hnm⟩ | ⟨item, q, ha, hnm⟩ <;>
        (simp only [Obl.names, Bool.and_eq_true, beq_iff_eq] at hnm
         simp [obKey, ha, obOfCtx, hnm.1, hnm.2])
    rw [hk] at hk'
    exact ⟨(Option.some.inj hk').symm, Or.inr ⟨o, hvo, hprev⟩⟩

theorem RowAt.old {log bs : List Bytes} {ob : Bytes} {j : Nat} (h : RowAt (log ++ bs) ob j) (hj : j < log.length) :
    RowAt log ob j := by
  obtain ⟨r, row, l, h1, h2, h3⟩ := h
  rw [List.getElem?_append_left hj] at h1
  exact ⟨r, row, l, h1, h2, h3⟩

/-! ## One slot of the table after a row is put -/

theorem slots_put_getD (m : Slots) (k : Bytes) (p i : Nat) (u : UInt64) :
    (Slots.put m k p i).getD u [] =
      if slotOf k = u then i :: (if p = 0 then m.getD (slotOf k) [] else (m.getD (slotOf k) []).erase (p - 1))
      else m.getD u [] := by
  simp [Slots.put, Std.HashMap.getD_insert]

theorem slots_put_mem {m : Slots} {k : Bytes} {p i j : Nat} {u : UInt64} (hnd : (m.getD u []).Nodup)
    (h : j ∈ (Slots.put m k p i).getD u []) :
    (slotOf k = u ∧ j = i) ∨ (j ∈ m.getD u [] ∧ (slotOf k = u → p ≠ 0 → j ≠ p - 1)) := by
  rw [slots_put_getD] at h
  by_cases hu : slotOf k = u
  · subst hu
    rw [if_pos rfl] at h
    rcases List.mem_cons.1 h with hji | h
    · exact Or.inl ⟨rfl, hji⟩
    · by_cases hp : p = 0
      · rw [if_pos hp] at h
        exact Or.inr ⟨h, fun _ hp' => absurd hp hp'⟩
      · rw [if_neg hp] at h
        exact Or.inr ⟨List.mem_of_mem_erase h, fun _ _ => (hnd.mem_erase_iff.1 h).1⟩
  · rw [if_neg hu] at h
    exact Or.inr ⟨h, fun h' => absurd h' hu⟩

theorem slots_put_nodup {m : Slots} {k : Bytes} {p i : Nat} {u : UInt64} (hnd : (m.getD u []).Nodup)
    (hi : i ∉ m.getD u []) : ((Slots.put m k p i).getD u []).Nodup := by
  rw [slots_put_getD]
  by_cases hu : slotOf k = u
  · subst hu
    rw [if_pos rfl]
    by_cases hp : p = 0
    · rw [if_pos hp]
      exact List.nodup_cons.2 ⟨hi, hnd⟩
    · rw [if_neg hp]
      exact List.nodup_cons.2 ⟨fun h => hi (List.mem_of_mem_erase h), List.Nodup.erase _ hnd⟩
  · rw [if_neg hu]
    exact hnd

/-! ## Reading a pack back from the records of its command -/

theorem packOf_kind {g : Nat → Option Bytes} {n : Nat} {x : CmdRec} {cl : Link} {cb : Bytes}
    (hcb : encFull (full cmdC x cl) = some cb) (hk : x.ckind ≠ 1) : ((packOf n cb).run g).1 = none := by
  obtain ⟨hu, hwf⟩ := unwrap_full cmdC_ok.2 hcb
  have hx : (bodyOf cb).bind cmdC.dec = some x := by simp [bodyOf, hu, RecCodec.dec_enc cmdC_ok.1 hwf]
  unfold packOf
  rw [hx]
  simp [hk, Rd.run]

/-- A pack read from a command record and the text records after it is the pack those records hold. -/
theorem packOf_written {g : Nat → Option Bytes} {n : Nat} {x : CmdRec} {cl : Link} {cb : Bytes}
    {body : List Body} {rest : List Bytes} {e tail : Bytes} {pk : ControlPack}
    (hcb : encFull (full cmdC x cl) = some cb) (hrest : encAll body = some rest)
    (hg : ∀ j r, rest[j]? = some r → g (n + 1 + j) = some r) (hnt : x.nt = body.length)
    (hjoin : joinFrom 0 (body.filterMap Body.textOf) = some e) (hdec : decodeControlPack e = some (pk, tail))
    {pc : ControlPack × PackClass} (h : ((packOf n cb).run g).1 = some pc) : pc.1 = pk := by
  obtain ⟨hu, hwf⟩ := unwrap_full cmdC_ok.2 hcb
  have hx : (bodyOf cb).bind cmdC.dec = some x := by simp [bodyOf, hu, RecCodec.dec_enc cmdC_ok.1 hwf]
  have hrun : ((readRun (n + 1) x.nt []).run g).1 = some (body.map Body.pair) := by
    have h1 := readRun_enc (g := g) rest (body.map Body.pair) (n + 1) [] hg (encAll_read hrest).1
    rw [encAll_length hrest, ← hnt] at h1
    simpa using h1
  have hmid : midElement (body.map Body.pair) = some e := by
    rw [midElement_eq, (encAll_read hrest).2]
    exact hjoin
  unfold packOf at h
  rw [hx] at h
  dsimp only at h
  split at h
  · simp [Rd.run] at h
  · rw [Rd.run_bind, hrun] at h
    simp [Rd.run, hmid, hdec] at h
    split at h
    · cases h
      rfl
    · cases h

/-- Only a pack command writes a command record of kind 1. -/
theorem core_kind {v : View} {c : Cmd} {f : Nat → Plan} (h : core v c = .ok f) (hk : kindOf c.act = 1) :
    ∃ pk cls, c.act = .pack pk cls := by
  cases ha : c.act with
  | pack pk cls => exact ⟨pk, cls, rfl⟩
  | population i => simp [ha, kindOf] at hk
  | payment item pc =>
    rw [ha] at hk
    cases pc <;> simp [kindOf] at hk
  | evaluate item r => simp [ha, kindOf] at hk
  | other k =>
    unfold core at h
    simp only [ha] at h
    split at h <;> cases h

/-! ## An older obligation in a longer log -/

theorem loadObl_ext {f g : Nat → Option Bytes} (hfg : ∀ j r, f j = some r → g j = some r) {ob : Bytes} {h : Nat}
    {o : Obl} (hl : ((loadObl ob h).run f).1 = some o) : ((loadObl ob h).run g).1 = some o := by
  obtain ⟨rows, segs, hc, hs, hrep⟩ := loadObl_parts hl
  obtain ⟨pre, he, hall⟩ := readChain_ext hfg _ _ _ _ hc
  have hpre : pre = rows := by simpa using he.symm
  subst hpre
  have hc' := hall (h + 1) [] (Nat.le_refl _)
  rw [List.append_nil] at hc'
  have hs' := readSegs_ext hfg _ _ _ hs []
  rw [List.append_nil] at hs'
  have hs'' : ((readSegs pre []).run g).1 = some segs := by
    rw [hs']
    simp [readSegs, Rd.run]
  rw [loadObl_of hc' hs'']
  exact hrep

/-! ## The theorem -/

theorem core_pack_body {v : View} {c : Cmd} {f : Nat → Plan} {pk : ControlPack} {cls : PackClass}
    (h : core v c = .ok f) (ha : c.act = .pack pk cls) (n : Nat) :
    (f n).body = textsAt (packElement pk cls) (n + 1) (nextCount v.cmdCount) ∧
      (f n).nt = nParts (packElement pk cls) := by
  obtain ⟨-, -, -, rfl⟩ := core_pack h ha
  exact ⟨rfl, by dsimp only⟩

/-- The pack table: the checker holds the pack the engine reads from each pack command, the new one included. -/
theorem kept_packs {s : Store} {log : List Bytes} {st st' : Chk} {c : Cmd} {f : Nat → Plan} {bs : List Bytes}
    (hsim : Sim s log st) (hhit : (viewOf s (fun i => log[i]?) c).hit = none)
    (hf : core (viewOf s (fun i => log[i]?) c) c = .ok f) (hbs : (f s.n).bytes c = some bs)
    (hpost : Post st st' c (f s.n) log.length) :
    ∀ (i : Nat) (r k : Bytes), (log ++ bs)[i]? = some r → identKey r = some (0x74, k) →
      ∀ (ext : List Bytes) (pc : ControlPack × PackClass),
        ((packOf i r).run fun j => (log ++ bs ++ ext)[j]?).1 = some pc → st'.packs[k]? = some pc.1 := by
  intro i r k hi hk ext pc hpc
  have hc5 := hpost.2.2.2.2.1
  have hfresh := no_hit_no_record (fetch := fun i => log[i]?) (c := c) hsim.inv (fun _ => rfl) hhit
  by_cases hlt : i < log.length
  · rw [List.getElem?_append_left hlt] at hi
    have h1 := hsim.packs i r k hi hk (bs ++ ext) pc (by rw [← List.append_assoc]; exact hpc)
    have hne : cidOfCmd c ≠ k := by
      intro heq
      subst heq
      exact hfresh r (List.mem_of_getElem? hi) hk
    rw [hc5]
    split
    · simpa [Std.HashMap.getElem?_insert, hne] using h1
    · exact h1
  · obtain ⟨-, b, rest', he, hcbk, hrestk⟩ := Plan.bytes_spec hbs
    obtain ⟨cb, rest, rfl, hcb, hrest⟩ := Plan.bytes_cons hbs
    have hcbk : identKey cb = some (0x74, cidOfCmd c) := by
      cases he
      exact hcbk
    have hrestk : ∀ r ∈ rest, ∀ k, identKey r ≠ some (0x74, k) := by
      cases he
      exact hrestk
    rw [List.getElem?_append_right (Nat.le_of_not_lt hlt)] at hi
    cases hidx : i - log.length with
    | succ m =>
      rw [hidx, List.getElem?_cons_succ] at hi
      exact absurd hk (hrestk r (List.mem_of_getElem? hi) k)
    | zero =>
      rw [hidx, List.getElem?_cons_zero] at hi
      have hr : r = cb := (Option.some.inj hi).symm
      have hik : i = log.length := by omega
      rw [hr, hik] at hpc
      rw [hr, hcbk] at hk
      have hkk : cidOfCmd c = k := (Prod.mk.inj (Option.some.inj hk)).2
      rw [← hkk]
      by_cases hkind : kindOf c.act = 1
      · obtain ⟨pk, cls, ha⟩ := core_kind hf hkind
        obtain ⟨-, hwf, -⟩ := core_pack hf ha
        obtain ⟨hbody, hnt⟩ := core_pack_body hf ha s.n
        rw [hbody] at hrest
        have hlen1 : 1 ≤ (packElement pk cls).length := by
          unfold packElement
          rw [List.length_append, leBytes_length]
          omega
        have hne : (packElement pk cls).isEmpty = false := by
          cases hpe : packElement pk cls with
          | nil => rw [hpe] at hlen1; simp at hlen1
          | cons _ _ => rfl
        have hdec : decodeControlPack (packElement pk cls) =
            some (pk, leBytes 1 cls.offsetMin ++ leBytes 1 cls.dispatchMin) := by
          unfold packElement
          rw [List.append_assoc]
          exact BlindLedger.Financial.decodeControlPack_encodeControlPack_append pk _ (pack_wire hwf)
        have hg : ∀ (j : Nat) (q : Bytes), rest[j]? = some q →
            (log ++ cb :: rest ++ ext)[log.length + 1 + j]? = some q := by
          intro j q hj
          have hjl : j < rest.length := (List.getElem?_eq_some_iff.1 hj).1
          have e : log.length + 1 + j - log.length = j + 1 := by omega
          rw [List.getElem?_append_left (by rw [List.length_append, List.length_cons]; omega),
            List.getElem?_append_right (by omega), e, List.getElem?_cons_succ]
          exact hj
        have hnt' : ((f s.n).cmd c).nt = (textsAt (packElement pk cls) (s.n + 1)
            (nextCount (viewOf s (fun i => log[i]?) c).cmdCount)).length := by
          rw [textsAt_length]
          exact hnt
        have hjoin : joinFrom 0 ((textsAt (packElement pk cls) (s.n + 1)
            (nextCount (viewOf s (fun i => log[i]?) c).cmdCount)).filterMap Body.textOf) =
              some (packElement pk cls) := by
          simp [join_textsAt, hne]
        have hpk := packOf_written (g := fun j => (log ++ cb :: rest ++ ext)[j]?) (n := log.length) hcb hrest hg
          hnt' hjoin hdec hpc
        rw [hpk, hc5]
        simp only [ha]
        exact Std.HashMap.getElem?_insert_self
      · have hnone := packOf_kind (g := fun j => (log ++ cb :: rest ++ ext)[j]?) (n := log.length) hcb
          (show ((f s.n).cmd c).ckind ≠ 1 from hkind)
        rw [hnone] at hpc
        cases hpc

/-- The obligation table: each entry is what the engine loads from the entry's row in the longer log, and that row
    is the only one of the obligation the engine's table holds. -/
theorem kept_obl {s : Store} {log : List Bytes} {st st' : Chk} {c : Cmd} {d : Disp} {p : Plan} {bs : List Bytes}
    (hsim : Sim s log st) (hd : decideView (viewOf s (fun i => log[i]?) c) c s.n = (d, some p, bs))
    (hpost : Post st st' c p log.length) :
    (∀ (ob : Bytes) (E : Entry), st'.obl[ob]? = some E →
        ∃ o, ((loadObl ob E.head).run fun j => (log ++ bs)[j]?).1 = some o ∧ E.same o) ∧
      (∀ (ob : Bytes) (j : Nat), j ∈ Slots.of (bs.foldl Store.scan s).obl ob → RowAt (log ++ bs) ob j →
        ∃ E, st'.obl[ob]? = some E ∧ E.head = j) ∧
      ∀ (u : UInt64), ((bs.foldl Store.scan s).obl.getD u []).Nodup ∧
        ∀ j ∈ (bs.foldl Store.scan s).obl.getD u [], j < (log ++ bs).length := by
  obtain ⟨-, hhit, hbs, f, hf, rfl⟩ := decideView_some hd
  have hc6 := hpost.2.2.2.2.2
  have hpre := sim_pre hsim hhit
  have hold : ∀ (j : Nat) (r : Bytes), log[j]? = some r → (log ++ bs)[j]? = some r := by
    intro j r hj
    rw [List.getElem?_append_left (List.getElem?_eq_some_iff.1 hj).1]
    exact hj
  obtain ⟨-, hhead, hkey⟩ := core_shape hf s.n
  cases hq : stateSplit (f s.n).body with
  | none =>
    have htab := written_table_none (s := s) hbs hq
    have ho : (f s.n).obl = none := by
      cases ho : (f s.n).obl with
      | none => rfl
      | some q =>
        rw [hq, ho] at hhead
        simp at hhead
    simp only [ho] at hc6
    refine ⟨?_, ?_, ?_⟩
    · intro ob E hE
      rw [hc6] at hE
      obtain ⟨o, hl, hs⟩ := hsim.obl ob E hE
      exact ⟨o, loadObl_ext (f := fun j => log[j]?) (g := fun j => (log ++ bs)[j]?) hold hl, hs⟩
    · intro ob j hj hrow
      rw [htab] at hj
      have hjl := (hsim.slots (slotOf ob)).2 j hj
      obtain ⟨E, hE, hh⟩ := hsim.heads ob j hj (hrow.old hjl)
      exact ⟨E, by rw [hc6]; exact hE, hh⟩
    · intro u
      rw [htab]
      obtain ⟨h1, h2⟩ := hsim.slots u
      refine ⟨h1, fun j hj => ?_⟩
      have := h2 j hj
      rw [List.length_append]
      omega
  | some q =>
    obtain ⟨pre, row, l⟩ := q
    have htab := written_table_some (s := s) hbs hq (core_one_row hf s.n)
    rw [hsim.n] at htab
    cases ho : (f s.n).obl with
    | none =>
      rw [hq, ho] at hhead
      simp at hhead
    | some ko =>
      obtain ⟨k, o'⟩ := ko
      have hhead' : o'.head = log.length + 1 + pre.length := by
        rw [hq, ho, hsim.n] at hhead
        simpa using hhead
      have hk : obKey c = some k := by
        rw [ho] at hkey
        simpa using hkey.symm
      simp only [ho] at hc6
      obtain ⟨E0, hE0, hsame⟩ := hc6
      obtain ⟨post, hbody⟩ := stateSplit_spec hq
      obtain ⟨hrowk, hlink⟩ :=
        row_of_core hf s.n (show Body.state row l ∈ (f s.n).body by rw [hbody]; simp) hk
      obtain ⟨sb, hsb1, hsb2⟩ := written_row hbs hq log
      have hnew : log.length + 1 + pre.length < (log ++ bs).length := (List.getElem?_eq_some_iff.1 hsb1).1
      refine ⟨?_, ?_, ?_⟩
      · intro ob E hE
        rw [hE0] at hE
        by_cases hob : k = ob
        · rw [← hob] at hE ⊢
          rw [Std.HashMap.getElem?_insert_self] at hE
          have hEE : E0 = E := Option.some.inj hE
          rw [← hEE]
          exact ⟨o', by rw [hsame.2.1]; exact written_loads hsim.n hd ho, hsame⟩
        · have hE' : st.obl[ob]? = some E := by simpa [Std.HashMap.getElem?_insert, hob] using hE
          obtain ⟨o, hl, hs⟩ := hsim.obl ob E hE'
          exact ⟨o, loadObl_ext (f := fun j => log[j]?) (g := fun j => (log ++ bs)[j]?) hold hl, hs⟩
      · intro ob j hj hrow
        rw [htab] at hj
        rcases slots_put_mem (hsim.slots (slotOf ob)).1 hj with ⟨-, hji⟩ | ⟨hjo, hne⟩
        · obtain ⟨r, row', l', h1, h2, h3⟩ := hrow
          rw [hji, hsb1] at h1
          rw [← Option.some.inj h1, hsb2] at h2
          have hrr : row = row' := congrArg Prod.fst (Option.some.inj h2)
          refine ⟨E0, ?_, by rw [hsame.2.1, hhead', hji]⟩
          rw [hE0, ← h3, ← hrr, hrowk]
          exact Std.HashMap.getElem?_insert_self
        · have hjl : j < log.length := (hsim.slots (slotOf ob)).2 j hjo
          have hrow0 := hrow.old hjl
          obtain ⟨E, hE, hh⟩ := hsim.heads ob j hjo hrow0
          by_cases hob : k = ob
          · exfalso
            rw [← hob] at hrow0 hE hne
            rcases hlink with ⟨-, hun⟩ | ⟨o, hvo, hprev'⟩
            · exact unknown_obligation_has_no_row hsim.inv (fun _ => rfl) hsim.chain hk hun j hrow0
            · obtain ⟨E1, hE1, hs1⟩ := hpre.obl k o hk hvo
              rw [hE] at hE1
              have hEE : E = E1 := Option.some.inj hE1
              have hj1 := hne (by rw [hrowk]) (by omega)
              have hh1 := hs1.2.1
              rw [← hEE, hh] at hh1
              omega
          · exact ⟨E, by simpa [hE0, Std.HashMap.getElem?_insert, hob] using hE, hh⟩
      · intro u
        rw [htab]
        obtain ⟨h1, h2⟩ := hsim.slots u
        have hout : log.length + 1 + pre.length ∉ s.obl.getD u [] := by
          intro hm
          have := h2 _ hm
          omega
        refine ⟨slots_put_nodup h1 hout, fun j hj => ?_⟩
        rcases slots_put_mem h1 hj with ⟨-, hji⟩ | ⟨hjo, -⟩
        · rw [hji]
          exact hnew
        · have := h2 j hjo
          rw [List.length_append]
          omega

/-- Part 3: the changes of `Post` keep the relation over the records the command wrote. -/
theorem kept : Kept := by
  intro s log st st' c d p bs hsim hd hpost
  obtain ⟨hobl, hheads, hslots⟩ := kept_obl hsim hd hpost
  obtain ⟨-, hhit, hbs, f, hf, rfl⟩ := decideView_some hd
  have hpacks := kept_packs hsim hhit hf hbs hpost
  obtain ⟨hc1, hc2, hc3, hc4, -, -⟩ := hpost
  obtain ⟨hw1, hw2, hw3⟩ := written_cmd (s := s) hbs
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, hpacks, hobl, hheads, hslots⟩
  · have h := apply_inv (fetch := fun i => log[i]?) (c := c) hsim.inv
    rw [apply_some hd] at h
    exact h
  · rw [(foldl_scan_fixed bs s).1, hsim.n, List.length_append]
  · have h := apply_chain (s := s) (c := c) hsim.chain
    rw [apply_some hd] at h
    exact h
  · rw [hc2, hw1, hsim.n]
  · rw [hc3, hw2]
  · rw [hc4, hw3]
  · intro k hk
    rw [hc1, Std.HashSet.contains_insert] at hk
    simp only [Bool.or_eq_true, beq_iff_eq] at hk
    rcases hk with hk | hk
    · obtain ⟨-, b, rest, hb, hbk, -⟩ := Plan.bytes_spec hbs
      exact ⟨b, by rw [hb]; simp, by rw [← hk]; exact hbk⟩
    · obtain ⟨r, hm, hr⟩ := hsim.cids k hk
      exact ⟨r, List.mem_append_left _ hm, hr⟩

end BlindLedger.Gate.Obligations
