import BlindLedger.Gate.Obligations.EngineLog

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec
open BlindLedger.Financial (FinancialInput FinancialResult evaluate decodeFinancialInput)
open BlindLedger.Financial.Payment (Command readCommand commitInput)

/-! The logs the checker accepts.

    Proved here: in a log the checker accepts, the engine rebuilds an obligation from every state row
    (`accepted_log_loads`).  The checker reads every record of a command by one layout, so a state row stands only
    where the checker read one.  There it has checked the row's link, the command record the row names and Lean's
    rule on the obligation it keeps, and those are what the engine reads back (`loadObl`).

    Nothing the program runs imports this module. -/

/-! ## What a step that passed says -/

theorem bind_ok {α β : Type} {x : Except String α} {f : α → Except String β} {r : β} (h : (x >>= f) = .ok r) :
    ∃ a, x = .ok a ∧ f a = .ok r := by
  cases x with
  | error e =>
    have h' : (Except.error e : Except String β) = .ok r := h
    cases h'
  | ok a => exact ⟨a, rfl, h⟩

theorem pure_ok {α : Type} {a b : α} (h : (pure a : Except String α) = .ok b) : a = b := Except.ok.inj h

theorem throw_ok {α : Type} {e : String} {a : α} (h : (throw e : Except String α) = .ok a) : False := by
  have h' : (Except.error e : Except String α) = .ok a := h
  cases h'

theorem need_ok {b : Bool} {i : Nat} {m : String} {u : Unit} (h : need b i m = .ok u) : b = true := by
  cases b with
  | true => rfl
  | false =>
    have h' : (Except.error _ : Except String Unit) = .ok u := h
    cases h'

theorem get_ok {α : Type} {o : Option α} {i : Nat} {m : String} {a : α} (h : get o i m = .ok a) : o = some a := by
  cases o with
  | none =>
    have h' : (Except.error _ : Except String α) = .ok a := h
    cases h'
  | some b =>
    have h' : (Except.ok b : Except String α) = .ok a := h
    cases h'
    rfl

theorem read_ok {α : Type} {rec : Nat → Option Bytes} {i : Nat} {d : Bytes → Option α} {m : String} {x : α}
    {l : Link} (h : read rec i d m = .ok (x, l)) : ∃ b, rd rec i = some (b, l) ∧ d b = some x := by
  unfold read at h
  obtain ⟨⟨b, l'⟩, h1, h⟩ := bind_ok h
  try dsimp only at h
  obtain ⟨y, h2, h⟩ := bind_ok h
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj (pure_ok h)
  exact ⟨b, get_ok h1, get_ok h2⟩

/-- `read_ok`, with a name for the record's number. -/
theorem read_ok_at {α : Type} {rec : Nat → Option Bytes} {i : Nat} {d : Bytes → Option α} {m : String} {x : α}
    {l : Link} (h : read rec i d m = .ok (x, l)) : ∃ r b, r = i ∧ rd rec r = some (b, l) ∧ d b = some x := by
  obtain ⟨b, h1, h2⟩ := read_ok h
  exact ⟨i, b, rfl, h1, h2⟩

/-- Record `p` is whole and its body starts with the byte `t`. -/
def TagAt (rec : Nat → Option Bytes) (p t : Nat) : Prop := ∃ b l, rd rec p = some (b, l) ∧ tagOf b = t

theorem TagAt.not_row {rec : Nat → Option Bytes} {p t : Nat} (h : TagAt rec p t) (ht : t ≠ 0x60) (row : StateRow)
    (l : Link) : rd rec p ≠ some (stateC.enc row, l) := by
  obtain ⟨b, l', hb, rfl⟩ := h
  intro hr
  rw [hb] at hr
  obtain ⟨rfl, -⟩ := Prod.mk.inj (Option.some.inj hr)
  exact ht (enc_tag (c := stateC) (v := 0x60) rfl (by decide) row)

theorem tagAt_dec {α : Type} {c : RecCodec α} {v : Nat} {fs : List Fld} (hL : c.L = .lit 1 v :: fs) (hv : v < 256)
    {rec : Nat → Option Bytes} {p : Nat} {b : Bytes} {l : Link} {x : α} (hb : rd rec p = some (b, l))
    (hd : c.dec b = some x) : TagAt rec p v :=
  ⟨b, l, hb, by rw [← RecCodec.enc_dec hd]; exact enc_tag hL hv x⟩

theorem peek_some {α : Type} {rec : Nat → Option Bytes} {i t : Nat} {d : Bytes → Option α} {q : α × Link}
    (h : peek rec i t d = some q) : ∃ b, rd rec i = some (b, q.2) ∧ tagOf b = t ∧ d b = some q.1 := by
  unfold peek at h
  cases hr : rd rec i with
  | none => rw [hr] at h; cases h
  | some v =>
    obtain ⟨b, l⟩ := v
    rw [hr] at h
    have h' : (if tagOf b = t then (d b).map (·, l) else none) = some q := h
    split at h'
    · rename_i ht
      cases hd : d b with
      | none => rw [hd] at h'; cases h'
      | some y =>
        rw [hd] at h'
        have h'' : some (y, l) = some q := h'
        obtain rfl := Option.some.inj h''
        exact ⟨b, rfl, ht, hd⟩
    · cases h'

/-- The record after an optional record of tag `t` at `q`: one further when that record is there. -/
theorem peek_span {α : Type} {rec : Nat → Option Bytes} {q t : Nat} {d : Bytes → Option α} {s : Nat}
    (hs : s = if (peek rec q t d).isSome = true then q + 1 else q) :
    q ≤ s ∧ s ≤ q + 1 ∧ ∀ p, q ≤ p → p < s → TagAt rec p t := by
  cases hp : peek rec q t d with
  | none =>
    rw [hp] at hs
    have hs' : s = q := hs
    exact ⟨by omega, by omega, fun p h1 h2 => by omega⟩
  | some v =>
    rw [hp] at hs
    have hs' : s = q + 1 := hs
    obtain ⟨b, hb, ht, -⟩ := peek_some hp
    exact ⟨by omega, by omega, fun p h1 h2 => by
      have e : p = q := by omega
      rw [e]
      exact ⟨b, _, hb, ht⟩⟩

/-- Record `p` as a text record, if it is one. -/
def textAt (rec : Nat → Option Bytes) (p : Nat) : Option TextRec :=
  (rd rec p).bind fun q => if tagOf q.1 = 0xF5 then textC.dec q.1 else none

/-- What `texts` read: text records from `i` up to where it stopped, in order. -/
theorem texts_ok {rec : Nat → Option Bytes} {n : Nat} : ∀ (k i c : Nat) (acc ts : Array TextRec) (j : Nat),
    n - i = k → texts rec n i c acc = .ok (ts, j) →
      i ≤ j ∧ ts.toList = acc.toList ++ (List.range' i (j - i)).filterMap (textAt rec) ∧
        ∀ p, i ≤ p → p < j → TagAt rec p 0xF5 := by
  intro k
  induction k using Nat.strongRecOn with
  | _ k ih =>
    intro i c acc ts j hk h
    unfold texts at h
    split at h
    · rename_i hi
      split at h
      · rename_i b l hr
        split at h
        · rename_i htag
          obtain ⟨t, ht, h⟩ := bind_ok h
          obtain ⟨-, -, h⟩ := bind_ok h
          obtain ⟨h1, h3, h4⟩ := ih (n - (i + 1)) (by omega) (i + 1) (c + 1) (acc.push t) ts j rfl h
          have hT : textAt rec i = some t := by simp [textAt, hr, htag, get_ok ht]
          refine ⟨by omega, ?_, fun p hp1 hp2 => ?_⟩
          · rw [h3, show j - i = (j - (i + 1)) + 1 by omega, List.range'_succ]
            simp [hT]
          · by_cases hp : p = i
            · rw [hp]
              exact ⟨b, l, hr, htag⟩
            · exact h4 p (by omega) hp2
        · obtain ⟨rfl, rfl⟩ := Prod.mk.inj (pure_ok h)
          exact ⟨Nat.le_refl _, by simp, fun p h1 h2 => by omega⟩
      · obtain ⟨rfl, rfl⟩ := Prod.mk.inj (pure_ok h)
        exact ⟨Nat.le_refl _, by simp, fun p h1 h2 => by omega⟩
    · obtain ⟨rfl, rfl⟩ := Prod.mk.inj (pure_ok h)
      exact ⟨Nat.le_refl _, by simp, fun p h1 h2 => by omega⟩

/-- What `element` read: the text records from `i` up to `j`, which join to the element. -/
theorem element_ok {rec : Nat → Option Bytes} {n i c : Nat} {e : Bytes} {j : Nat}
    (h : element rec n i c = .ok (e, j)) :
    i ≤ j ∧ joinFrom 0 ((List.range' i (j - i)).filterMap (textAt rec)) = some e ∧
      ∀ p, i ≤ p → p < j → TagAt rec p 0xF5 := by
  unfold element at h
  obtain ⟨⟨ts, j'⟩, h1, h⟩ := bind_ok h
  try dsimp only at h
  obtain ⟨e', h2, h⟩ := bind_ok h
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj (pure_ok h)
  obtain ⟨ha, hb, hc⟩ := texts_ok _ _ _ _ _ _ rfl h1
  refine ⟨ha, ?_, hc⟩
  have h3 := get_ok h2
  rw [hb] at h3
  first
    | exact h3
    | simpa using h3

/-- `element_ok`, with a name for the first record's number. -/
theorem element_ok_at {rec : Nat → Option Bytes} {n i c : Nat} {e : Bytes} {j : Nat}
    (h : element rec n i c = .ok (e, j)) :
    ∃ s, s = i ∧ s ≤ j ∧ joinFrom 0 ((List.range' s (j - s)).filterMap (textAt rec)) = some e ∧
      ∀ p, s ≤ p → p < j → TagAt rec p 0xF5 :=
  ⟨i, rfl, element_ok h⟩

theorem afterRef_ok {rec : Nat → Option Bytes} {n r c : Nat} {res : FinancialResult} {k : Nat}
    (h : afterRef rec n r c res = .ok k) : r + 1 ≤ k ∧ ∀ p, r < p → p < k → TagAt rec p 0xF5 := by
  unfold afterRef at h
  obtain ⟨⟨e, k'⟩, he, h⟩ := bind_ok h
  try dsimp only at h
  obtain ⟨-, -, h⟩ := bind_ok h
  obtain rfl := pure_ok h
  obtain ⟨h1, -, h3⟩ := element_ok he
  exact ⟨h1, fun p p1 p2 => h3 p (by omega) p2⟩

/-- A loop that passed kept what every round keeps. -/
theorem forIn_ok {α β : Type} {f : α → β → Except String (ForInStep β)} (P : β → Prop)
    (hstep : ∀ a b r, P b → f a b = .ok r → ∃ b2, r = .yield b2 ∧ P b2) :
    ∀ (l : List α) (b b' : β), forIn l b f = .ok b' → P b → P b'
  | [], b, b', h, hp => by
    rw [List.forIn_nil] at h
    exact pure_ok h ▸ hp
  | a :: l, b, b', h, hp => by
    rw [List.forIn_cons] at h
    obtain ⟨r, hr, h⟩ := bind_ok h
    obtain ⟨b2, rfl, hp2⟩ := hstep a b r hp hr
    exact forIn_ok P hstep l b2 b' h hp2

theorem stateAgree_ob {r : FinancialResult} {c : Nat} {x : StateRow} (h : stateAgree r c x = true) :
    x.ob = obOfCtx r.context := by
  simp only [stateAgree, Bool.and_eq_true] at h
  exact eq_of_beq h.1.1.1.1.1.1.1.1.1.1.1.1

theorem rowLinks_cmd {x : CmdRec} {row : StateRow} {i cause fact caseRef : Nat} {after : FinancialInput}
    (h : rowLinks x row i cause fact caseRef after = true) : row.cmd = i + 1 := by
  simp only [rowLinks, Bool.and_eq_true] at h
  exact eq_of_beq h.1.1.1.1.1.1.1.1

/-! ## A state row is of the obligation it names -/

theorem stateC_enc_ob {a b : StateRow} (h : stateC.enc a = stateC.enc b) : a.ob = b.ob := by
  have key : ∀ x : StateRow, ∃ post : Bytes, post.length = 210 ∧
      stateC.enc x = leBytes 1 0x60 ++ (leBytes 1 5 ++ (leBytes 1 x.mkind ++ (x.ob ++ post))) := fun x =>
    ⟨_, by simp [z, encF, leBytes_length], rfl⟩
  obtain ⟨pa, ha, ea⟩ := key a
  obtain ⟨pb, hb, eb⟩ := key b
  rw [ea, eb] at h
  have h1 := (List.append_inj h rfl).2
  have h2 := (List.append_inj h1 rfl).2
  have h3 := (List.append_inj h2 (by rw [leBytes_length, leBytes_length])).2
  exact (List.append_inj' h3 (by rw [ha, hb])).1

/-- A state row at a record where a state row was decoded is of that row's obligation. -/
theorem row_ob {rec : Nat → Option Bytes} {p : Nat} {sb : Bytes} {rl : Link} {row : StateRow}
    (hrd : rd rec p = some (sb, rl)) (hdec : stateC.dec sb = some row) (row' : StateRow) (l' : Link)
    (h : rd rec p = some (stateC.enc row', l')) : row'.ob = row.ob := by
  rw [hrd] at h
  obtain ⟨hb, -⟩ := Prod.mk.inj (Option.some.inj h)
  exact (stateC_enc_ob ((RecCodec.enc_dec hdec).trans hb)).symm

/-! ## The engine's reading of the records the checker read -/

theorem readRun_rd {g : Nat → Option Bytes} : ∀ (k a : Nat) (acc : List (Bytes × Link)),
    (∀ p, a ≤ p → p < a + k → (rd g p).isSome = true) →
      ((readRun a k acc).run g).1 = some (acc.reverse ++ (List.range' a k).filterMap (rd g))
  | 0, a, acc, _ => by simp [readRun, Rd.run]
  | k + 1, a, acc, h => by
    have h0 := h a (Nat.le_refl _) (by omega)
    cases hr : rd g a with
    | none => simp [hr] at h0
    | some q =>
      have hr' : (g a).bind unwrap = some q := hr
      have ih := readRun_rd k (a + 1) (q :: acc) fun p h1 h2 => h p (by omega) (by omega)
      simp [readRun, Rd.run, hr', ih, List.range'_succ, hr]

/-- The records from a command record to its state row, as the engine reads them. -/
theorem readRun_cmd {g : Nat → Option Bytes} {i ri : Nat} {cb : Bytes} {cl : Link} (hlt : i < ri)
    (hc : rd g i = some (cb, cl)) (hall : ∀ p, i < p → p < ri → (rd g p).isSome = true) :
    ((readRun i (ri - i) []).run g).1 =
      some ((cb, cl) :: (List.range' (i + 1) (ri - (i + 1))).filterMap (rd g)) := by
  rw [readRun_rd (ri - i) i [] (fun p h1 h2 => by
    by_cases hp : p = i
    · rw [hp, hc]
      rfl
    · exact hall p (by omega) (by omega)),
    show ri - i = (ri - (i + 1)) + 1 by omega, List.range'_succ]
  simp [hc]

theorem filterMap_window {β : Type} (f : Nat → Option β) {a s j e : Nat} (h1 : a ≤ s) (h2 : s ≤ j) (h3 : j ≤ e)
    (hlo : ∀ p, a ≤ p → p < s → f p = none) (hhi : ∀ p, j ≤ p → p < e → f p = none) :
    (List.range' a (e - a)).filterMap f = (List.range' s (j - s)).filterMap f := by
  have e1 : e - a = (s - a) + ((j - s) + (e - j)) := by omega
  have n1 : (List.range' a (s - a)).filterMap f = [] := List.filterMap_eq_nil_iff.mpr fun p hp => by
    rw [List.mem_range'_1] at hp
    exact hlo p hp.1 (by omega)
  have n2 : (List.range' j (e - j)).filterMap f = [] := List.filterMap_eq_nil_iff.mpr fun p hp => by
    rw [List.mem_range'_1] at hp
    exact hhi p hp.1 (by omega)
  rw [e1, ← List.range'_append_1, ← List.range'_append_1, List.filterMap_append, List.filterMap_append, n1,
    show a + (s - a) = s by omega, show s + (j - s) = j by omega, n2]
  simp

/-- The element the engine joins from a command's records is the one the checker joined from its text records,
    when the records around them are not text records. -/
theorem mid_element {rec : Nat → Option Bytes} {a s j e : Nat} {el : Bytes} (h1 : a ≤ s) (h2 : s ≤ j) (h3 : j ≤ e)
    (hlo : ∀ p, a ≤ p → p < s → ∃ t, TagAt rec p t ∧ t ≠ 0xF5)
    (hhi : ∀ p, j ≤ p → p < e → ∃ t, TagAt rec p t ∧ t ≠ 0xF5)
    (hj : joinFrom 0 ((List.range' s (j - s)).filterMap (textAt rec)) = some el) :
    midElement ((List.range' a (e - a)).filterMap (rd rec)) = some el := by
  have hT : ∀ p, (∃ t, TagAt rec p t ∧ t ≠ 0xF5) → textAt rec p = none := by
    intro p hp
    obtain ⟨t, ⟨b, l, hb, rfl⟩, ht⟩ := hp
    simp [textAt, hb, ht]
  rw [midElement_eq, List.filterMap_filterMap, ← hj]
  exact congrArg (joinFrom 0) (filterMap_window (textAt rec) h1 h2 h3 (fun p p1 p2 => hT p (hlo p p1 p2))
    (fun p p1 p2 => hT p (hhi p p1 p2)))

/-- The records of one command, from its command record at `i` to its state row at `ri`, with its text records
    from `s` up to `j`: the engine reads them whole and joins the same element. -/
theorem cmd_records {rec : Nat → Option Bytes} {i s j ri : Nat} {cb : Bytes} {cl : Link} {el : Bytes}
    (hc : rd rec i = some (cb, cl)) (h1 : i < s) (h2 : s ≤ j) (h3 : j ≤ ri)
    (hlo : ∀ p, i < p → p < s → ∃ t, TagAt rec p t ∧ t ≠ 0xF5) (hmid : ∀ p, s ≤ p → p < j → TagAt rec p 0xF5)
    (hhi : ∀ p, j ≤ p → p < ri → ∃ t, TagAt rec p t ∧ t ≠ 0xF5)
    (hj : joinFrom 0 ((List.range' s (j - s)).filterMap (textAt rec)) = some el) :
    ∃ mid, ((readRun i (ri - i) []).run rec).1 = some ((cb, cl) :: mid) ∧ midElement mid = some el := by
  refine ⟨_, readRun_cmd (by omega) hc fun p p1 p2 => ?_, ?_⟩
  · have ht : ∃ t, TagAt rec p t := by
      by_cases q1 : p < s
      · obtain ⟨t, ht, -⟩ := hlo p p1 q1
        exact ⟨t, ht⟩
      · by_cases q2 : p < j
        · exact ⟨_, hmid p (by omega) q2⟩
        · obtain ⟨t, ht, -⟩ := hhi p (by omega) p2
          exact ⟨t, ht⟩
    obtain ⟨t, b, l, hb, -⟩ := ht
    rw [hb]
    rfl
  · exact mid_element (by omega) h2 h3 (fun p p1 p2 => hlo p (by omega) p2) hhi hj

/-- The load from a state row whose command's records read whole: the chain before it, then its own command,
    replayed after the obligation that chain gave. -/
theorem loadObl_step {g : Nat → Option Bytes} {k : Bytes} {i ri : Nat} {x : CmdRec} {cb sb : Bytes} {cl l : Link}
    {mid : List (Bytes × Link)} {row : StateRow} (hrow : rd g ri = some (sb, l))
    (hdec : stateC.dec sb = some row) (hob : row.ob = k) (hcmd : row.cmd = i + 1) (hle : i < ri)
    (hrun : ((readRun i (ri - i) []).run g).1 = some ((cb, cl) :: mid)) (hx : cmdC.dec cb = some x)
    {prev : Option Obl}
    (hprev : prev = none ∧ l.prev = 0 ∨
      ∃ o hd, prev = some o ∧ l.prev = hd + 1 ∧ hd < ri ∧ ((loadObl k hd).run g).1 = some o) :
    ((loadObl k ri).run g).1 = replay1 prev ⟨x, mid, ri, row, l⟩ := by
  have hrd : (g ri).bind unwrap = some (sb, l) := hrow
  have hcond : ¬(row.cmd = 0 ∨ ri < row.cmd) := by rw [hcmd]; omega
  have hseg : ∀ acc : List Seg,
      ((readSegs [(ri, row, l)] acc).run g).1 = some (acc.reverse ++ [⟨x, mid, ri, row, l⟩]) := by
    intro acc
    have e1 : row.cmd - 1 = i := by omega
    rw [readSegs, if_neg hcond, Rd.run_bind, e1, hrun]
    simp [hx, readSegs, Rd.run]
  cases hf : g ri with
  | none => rw [hf] at hrd; cases hrd
  | some r0 =>
    rw [hf] at hrd
    have hu : unwrap r0 = some (sb, l) := hrd
    rcases hprev with ⟨rfl, hp⟩ | ⟨o, hd, rfl, hp, hlt, hl⟩
    · have hc : ((readChain k (ri + 1) ri []).run g).1 = some [(ri, row, l)] := by
        simp [readChain, Rd.run, hf, hu, hdec, hob, hp]
      have hs := hseg []
      simp only [List.reverse_nil, List.nil_append] at hs
      rw [loadObl_of hc hs]
      exact replay_one _ _
    · obtain ⟨rows, segs, hc0, hs0, hrep⟩ := loadObl_parts hl
      obtain ⟨pre, hpre, hall⟩ := readChain_ext (f := g) (g := g) (fun _ _ hh => hh) _ _ _ _ hc0
      simp only [List.append_nil] at hpre
      subst hpre
      have hc : ((readChain k (ri + 1) ri []).run g).1 = some (rows ++ [(ri, row, l)]) := by
        have hm := hall ri [(ri, row, l)] (by omega)
        simpa [readChain, Rd.run, hf, hu, hdec, hob, hp, hlt] using hm
      have hs : ((readSegs (rows ++ [(ri, row, l)]) []).run g).1 = some (segs ++ [⟨x, mid, ri, row, l⟩]) := by
        rw [readSegs_ext (f := g) (g := g) (fun _ _ hh => hh) rows [] segs hs0, hseg]
        simp
      rw [loadObl_of hc hs, replay_append_some _ _ _ _ hrep]
      exact replay_one _ _

/-! ## One more command of an obligation, replayed -/

theorem replay1_open {s : Seg} {e : Bytes} {i : FinancialInput} {res : FinancialResult} (hm : s.row.mkind = 13)
    (he : midElement s.mid = some e) (hi : decodeFinancialInput e = some i) (hr : evaluate i = some res) :
    replay1 none s = some {
      led := { input := commitInput i res, receipts := [] }, noClass := s.row.lg.testBit 1, head := s.at_,
      headCount := s.link.count, caseRef := s.row.caseRef, fact := s.row.fact - 1, factCount := 1, cash := [] } := by
  simp [replay1, hm, he, decodeInput_eq, hi, hr]

theorem replay1_eval {o : Obl} {s : Seg} {res : FinancialResult} (hm : s.row.mkind = 25)
    (he : evaluate { o.led.input with evaluatedAt := s.row.atMs } = some res) :
    replay1 (some o) s = some { o with
      led := { o.led with input := commitInput { o.led.input with evaluatedAt := s.row.atMs } res },
      head := s.at_, headCount := s.link.count } := by
  simp [replay1, hm, he]

theorem replay1_pay {o : Obl} {s : Seg} {e : Bytes} {pc : Command} (hm : 14 ≤ s.row.mkind ∧ s.row.mkind ≤ 17)
    (he : midElement s.mid = some e) (hc : readCommand e = some (pc, [])) :
    (replay1 (some o) s).map (·.led) =
      some (BlindLedger.Financial.Payment.step o.led
        ⟨s.row.atMs, if s.x.exprev = 0 then none else some (s.x.exprev - 1), pc⟩) := by
  have h25 : s.row.mkind ≠ 25 := by omega
  simp [replay1, h25, hm.1, hm.2, he, hc, stepOut_eq]

/-! ## A load reads only its row and records before it -/

theorem Rd.run_bind_reads {α β : Type} (fetch : Nat → Option Bytes) (f : α → Rd β) :
    ∀ (m : Rd α), ((m.bind f).run fetch).2 = (m.run fetch).2 ++ ((f (m.run fetch).1).run fetch).2
  | .done _ => rfl
  | .need i k => congrArg (i :: ·) (Rd.run_bind_reads fetch f (k (fetch i)))

theorem readRun_reads {f : Nat → Option Bytes} : ∀ (k a : Nat) (acc : List (Bytes × Link)),
    ∀ j ∈ ((readRun a k acc).run f).2, a ≤ j ∧ j < a + k
  | 0, a, acc, j, hj => by simp [readRun, Rd.run] at hj
  | k + 1, a, acc, j, hj => by
    simp only [readRun, Rd.run, List.mem_cons] at hj
    rcases hj with rfl | hj
    · omega
    · split at hj
      · simp [Rd.run] at hj
      · have := readRun_reads k (a + 1) _ j hj
        omega

theorem readChain_reads {f : Nat → Option Bytes} {ob : Bytes} : ∀ (fuel i : Nat)
    (acc : List (Nat × StateRow × Link)), ∀ j ∈ ((readChain ob fuel i acc).run f).2, j ≤ i
  | 0, i, acc, j, hj => by simp [readChain, Rd.run] at hj
  | fuel + 1, i, acc, j, hj => by
    simp only [readChain, Rd.run, List.mem_cons] at hj
    rcases hj with rfl | hj
    · exact Nat.le_refl _
    · revert hj
      split
      · simp [Rd.run]
      · split
        · simp [Rd.run]
        · split
          · simp [Rd.run]
          · split
            · intro hj
              have := readChain_reads fuel _ _ j hj
              omega
            · simp [Rd.run]

theorem readChain_rows {f : Nat → Option Bytes} {ob : Bytes} : ∀ (fuel i : Nat)
    (acc rows : List (Nat × StateRow × Link)), ((readChain ob fuel i acc).run f).1 = some rows →
      ∀ q ∈ rows, q.1 ≤ i ∨ q ∈ acc
  | 0, i, acc, rows, h => by simp [readChain, Rd.run] at h
  | fuel + 1, i, acc, rows, h => by
    simp only [readChain, Rd.run] at h
    revert h
    split
    · simp [Rd.run]
    · split
      · simp [Rd.run]
      · split
        · intro h q hq
          simp only [Rd.run, Option.some.injEq] at h
          subst h
          rcases List.mem_cons.mp hq with rfl | hq
          · exact Or.inl (Nat.le_refl _)
          · exact Or.inr hq
        · split
          · intro h q hq
            rcases readChain_rows fuel _ _ rows h q hq with h1 | h1
            · exact Or.inl (by omega)
            · rcases List.mem_cons.mp h1 with rfl | h1
              · exact Or.inl (Nat.le_refl _)
              · exact Or.inr h1
          · simp [Rd.run]

theorem readSegs_reads {f : Nat → Option Bytes} {h : Nat} : ∀ (rows : List (Nat × StateRow × Link))
    (acc : List Seg), (∀ q ∈ rows, q.1 ≤ h) → ∀ j ∈ ((readSegs rows acc).run f).2, j ≤ h
  | [], acc, _, j, hj => by simp [readSegs, Rd.run] at hj
  | (i, row, l) :: rest, acc, hr, j, hj => by
    have hi : i ≤ h := hr (i, row, l) (List.mem_cons_self ..)
    rw [readSegs] at hj
    split at hj
    · simp [Rd.run] at hj
    · rename_i hc
      rw [Rd.run_bind_reads, List.mem_append] at hj
      rcases hj with hj | hj
      · have := readRun_reads _ _ _ j hj
        omega
      · revert hj
        split
        · split
          · exact readSegs_reads rest _ (fun q hq => hr q (List.mem_cons_of_mem _ hq)) j
          · simp [Rd.run]
        · simp [Rd.run]

theorem loadObl_reads {f : Nat → Option Bytes} {ob : Bytes} {h : Nat} : ∀ j ∈ ((loadObl ob h).run f).2, j ≤ h := by
  intro j hj
  unfold loadObl at hj
  rw [Rd.run_bind_reads, List.mem_append] at hj
  rcases hj with hj | hj
  · exact readChain_reads _ _ _ j hj
  · revert hj
    cases hc : ((readChain ob (h + 1) h []).run f).1 with
    | none => simp [Rd.run]
    | some rows =>
      intro hj
      dsimp only at hj
      rw [Rd.run_bind_reads, List.mem_append] at hj
      rcases hj with hj | hj
      · refine readSegs_reads rows [] (fun q hq => ?_) j hj
        rcases readChain_rows _ _ _ _ hc q hq with h1 | h1
        · exact h1
        · simp at h1
      · revert hj
        split <;> simp [Rd.run]

/-! ## What the checker's table says of the log -/

/-- After the checker has read the records below `m`: the engine loads an obligation from every state row below
    `m`, and for every obligation the checker keeps, from the row the checker holds as its newest, with the ledger
    the checker holds. -/
structure Loads (rec : Nat → Option Bytes) (st : Chk) (m : Nat) : Prop where
  rows : ∀ p, p < m → ∀ (row : StateRow) (l : Link), rd rec p = some (stateC.enc row, l) →
    ((loadObl row.ob p).run rec).1.isSome = true
  obl : ∀ (ob : Bytes) (E : Entry), st.obl[ob]? = some E →
    E.head < m ∧ ∃ o, ((loadObl ob E.head).run rec).1 = some o ∧ o.led = E.led

/-- A command whose only state row is at `ri`, of obligation `ob`, which loads with the ledger of the entry the
    checker then keeps for `ob`. -/
theorem Loads.step {rec : Nat → Option Bytes} {st st' : Chk} {i ri k : Nat} {ob : Bytes} {E' : Entry}
    (hg : Loads rec st i) (hst : st'.obl = st.obl.insert ob E') (hik : i ≤ ri) (hrk : ri < k)
    (hnot : ∀ p, i ≤ p → p < k → p ≠ ri → ∀ (row : StateRow) (l : Link), rd rec p ≠ some (stateC.enc row, l))
    (hrow : ∀ (row : StateRow) (l : Link), rd rec ri = some (stateC.enc row, l) → row.ob = ob)
    (hhead : E'.head = ri) (hload : ∃ o, ((loadObl ob ri).run rec).1 = some o ∧ o.led = E'.led) :
    Loads rec st' k := by
  refine ⟨fun p hp row l hr => ?_, fun ob' E hE => ?_⟩
  · by_cases h1 : p < i
    · exact hg.rows p h1 row l hr
    · by_cases h2 : p = ri
      · rw [h2] at hr ⊢
        rw [hrow row l hr]
        obtain ⟨o, h3, -⟩ := hload
        rw [h3]
        rfl
      · exact (hnot p (by omega) hp h2 row l hr).elim
  · rw [hst, Std.HashMap.getElem?_insert] at hE
    split at hE
    · rename_i heq
      have e1 : ob = ob' := eq_of_beq heq
      have e2 : E' = E := Option.some.inj hE
      rw [← e1, ← e2, hhead]
      exact ⟨hrk, hload⟩
    · obtain ⟨h1, h2⟩ := hg.obl ob' E hE
      exact ⟨by omega, h2⟩

/-- A command with no state row leaves the table's obligations as they were. -/
theorem Loads.skip {rec : Nat → Option Bytes} {st st' : Chk} {i k : Nat} (hg : Loads rec st i)
    (hst : st'.obl = st.obl) (hik : i ≤ k)
    (hnot : ∀ p, i ≤ p → p < k → ∀ (row : StateRow) (l : Link), rd rec p ≠ some (stateC.enc row, l)) :
    Loads rec st' k := by
  refine ⟨fun p hp row l hr => ?_, fun ob E hE => ?_⟩
  · by_cases h1 : p < i
    · exact hg.rows p h1 row l hr
    · exact (hnot p (by omega) hp row l hr).elim
  · rw [hst] at hE
    obtain ⟨h1, h2⟩ := hg.obl ob E hE
    exact ⟨by omega, h2⟩

/-- `Loads` holds of any log with the same records below `m`: a load reads only its row and records before it. -/
theorem Loads.local {f g : Nat → Option Bytes} {st : Chk} {m : Nat} (hfg : ∀ k, k < m → g k = f k)
    (h : Loads f st m) : Loads g st m := by
  have hrun : ∀ ob p, p < m → (loadObl ob p).run g = (loadObl ob p).run f := fun ob p hp =>
    Rd.run_local _ fun j hj => (hfg j (by have := loadObl_reads j hj; omega)).symm
  refine ⟨fun p hp row l hr => ?_, fun ob E hE => ?_⟩
  · have hr' : rd f p = some (stateC.enc row, l) := by
      unfold rd at hr ⊢
      rwa [hfg p hp] at hr
    rw [hrun _ _ hp]
    exact h.rows p hp row l hr'
  · obtain ⟨h1, h2⟩ := h.obl ob E hE
    rw [hrun _ _ h1]
    exact ⟨h1, h2⟩

/-- A command the checker passed keeps `Loads`, up to the record after the command's last. -/
theorem checkOne_loads {rec : Nat → Option Bytes} {n i j : Nat} {st st' : Chk}
    (h : checkOne st rec n i = .ok (st', j)) (hg : Loads rec st i) : Loads rec st' j := by
  unfold checkOne at h
  obtain ⟨⟨x, xl⟩, hx, h⟩ := bind_ok h
  try dsimp only at h
  obtain ⟨-, -, h⟩ := bind_ok h
  obtain ⟨-, -, h⟩ := bind_ok h
  obtain ⟨-, -, h⟩ := bind_ok h
  obtain ⟨-, -, h⟩ := bind_ok h
  try dsimp only at h
  obtain ⟨cb, hcb, hxd⟩ := read_ok hx
  have hcmdrec : TagAt rec i 0x74 := tagAt_dec (c := cmdC) (v := 0x74) rfl (by decide) hcb hxd
  split at h
  · -- A pack: the command record and its text.
    obtain ⟨⟨e, j1⟩, he, h⟩ := bind_ok h
    try dsimp only at h
    obtain ⟨⟨p, cls⟩, -, h⟩ := bind_ok h
    try dsimp only at h
    obtain ⟨-, -, h⟩ := bind_ok h
    obtain ⟨-, -, h⟩ := bind_ok h
    obtain ⟨rfl, hj⟩ := Prod.mk.inj (pure_ok h)
    rw [← hj]
    obtain ⟨he1, -, htxt⟩ := element_ok he
    refine hg.skip rfl (by omega) fun q q1 q2 => ?_
    by_cases q0 : q = i
    · rw [q0]
      exact hcmdrec.not_row (by decide)
    · exact (htxt q (by omega) q2).not_row (by decide)
  · -- An opening: the OBLIG fact, the input's text, a case record for each case, the row, its reference.
    obtain ⟨⟨f, fl⟩, hf, h⟩ := bind_ok h
    try dsimp only at h
    obtain ⟨⟨e, j1⟩, he, h⟩ := bind_ok h
    try dsimp only at h
    obtain ⟨inp, hinp, h⟩ := bind_ok h
    obtain ⟨res, hres, h⟩ := bind_ok h
    try dsimp only at h
    obtain ⟨q, hfor, h⟩ := bind_ok h
    try dsimp only at h
    obtain ⟨⟨row, rl⟩, hrow, h⟩ := bind_ok h
    try dsimp only at h
    obtain ⟨-, -, h⟩ := bind_ok h
    obtain ⟨-, -, h⟩ := bind_ok h
    obtain ⟨-, -, h⟩ := bind_ok h
    obtain ⟨_, hrowok, h⟩ := bind_ok h
    obtain ⟨-, -, h⟩ := bind_ok h
    obtain ⟨-, -, h⟩ := bind_ok h
    obtain ⟨k, hk, h⟩ := bind_ok h
    obtain ⟨rfl, hj⟩ := Prod.mk.inj (pure_ok h)
    rw [← hj]
    obtain ⟨fb, hfb, hfd⟩ := read_ok hf
    have hfact : TagAt rec (i + 1) 0x8E := tagAt_dec (c := obligC) (v := 0x8E) rfl (by decide) hfb hfd
    obtain ⟨he1, hjoin, htxt⟩ := element_ok he
    have hq : j1 ≤ q ∧ ∀ p, j1 ≤ p → p < q → TagAt rec p 0x72 := by
      refine forIn_ok (P := fun q => j1 ≤ q ∧ ∀ p, j1 ≤ p → p < q → TagAt rec p 0x72) ?_ _ _ _ hfor
        ⟨Nat.le_refl _, fun p h1 h2 => by omega⟩
      intro a b r hp hr
      obtain ⟨hp1, hp2⟩ := hp
      try dsimp only at hr
      obtain ⟨⟨kase, kl⟩, hkr, hr⟩ := bind_ok hr
      try dsimp only at hr
      obtain ⟨-, -, hr⟩ := bind_ok hr
      have hr' : (Except.ok (ForInStep.yield (b + 1)) : Except String (ForInStep Nat)) = .ok r := hr
      obtain rfl := Except.ok.inj hr'
      obtain ⟨kb, hkb, hkd⟩ := read_ok hkr
      refine ⟨b + 1, rfl, by omega, fun p h1 h2 => ?_⟩
      by_cases h3 : p < b
      · exact hp2 p h1 h3
      · have e : p = b := by omega
        rw [e]
        exact tagAt_dec (c := caseC) (v := 0x72) rfl (by decide) hkb hkd
    obtain ⟨hq1, hq2⟩ := hq
    obtain ⟨sb, hrd, hdec⟩ := read_ok hrow
    have hrowok' := need_ok hrowok
    simp only [Bool.and_eq_true] at hrowok'
    obtain ⟨⟨⟨hmk, hagree⟩, hlinks⟩, hrl⟩ := hrowok'
    obtain ⟨hk1, hk2⟩ := afterRef_ok hk
    have hob : row.ob = obOfCtx inp.context := by
      rw [stateAgree_ob hagree, evaluate_context (get_ok hres)]
    have hrl' : rl.prev = 0 := by rw [eq_of_beq hrl]
    obtain ⟨mid, hrun, hmid⟩ := cmd_records (i := i) (s := i + 2) (j := j1) (ri := q) hcb (by omega) he1 hq1
      (fun p p1 p2 => ⟨0x8E, by
        have e : p = i + 1 := by omega
        rw [e]
        exact hfact, by decide⟩)
      htxt (fun p p1 p2 => ⟨0x72, hq2 p p1 p2, by decide⟩) hjoin
    have hload := loadObl_step hrd hdec hob (rowLinks_cmd hlinks) (by omega) hrun hxd (prev := none)
      (Or.inl ⟨rfl, hrl'⟩)
    refine hg.step (ri := q) (ob := obOfCtx inp.context) (by rfl) (by omega) (by omega) ?_ ?_ ?_ ?_
    · intro p p1 p2 p3
      have ht : ∃ t, TagAt rec p t ∧ t ≠ 0x60 := by
        by_cases q0 : p = i
        · rw [q0]
          exact ⟨0x74, hcmdrec, by decide⟩
        · by_cases q1 : p = i + 1
          · rw [q1]
            exact ⟨0x8E, hfact, by decide⟩
          · by_cases q2 : p < j1
            · exact ⟨0xF5, htxt p (by omega) q2, by decide⟩
            · by_cases q3 : p < q
              · exact ⟨0x72, hq2 p (by omega) q3, by decide⟩
              · exact ⟨0xF5, hk2 p (by omega) p2, by decide⟩
      obtain ⟨t, ht1, ht2⟩ := ht
      exact ht1.not_row ht2
    · intro row' l' hr'
      rw [row_ob hrd hdec row' l' hr', hob]
    · rfl
    · rw [hload, replay1_open (s := ⟨x, mid, q, row, rl⟩) (eq_of_beq hmk) hmid (get_ok hinp) (get_ok hres)]
      exact ⟨_, rfl, rfl⟩
  iterate 2
    · -- A payment or reversal: an optional CASH fact, the command's text, an optional marker, the row, and its
      -- reference unless the row is an alias.
      obtain ⟨⟨e, j1⟩, he, h⟩ := bind_ok h
      try dsimp only at h
      obtain ⟨-, -, h⟩ := bind_ok h
      obtain ⟨⟨cmd, rest⟩, hcmd, h⟩ := bind_ok h
      try dsimp only at h
      obtain ⟨_, hrest, h⟩ := bind_ok h
      obtain ⟨⟨row, rl⟩, hrow, h⟩ := bind_ok h
      try dsimp only at h
      obtain ⟨o, ho, h⟩ := bind_ok h
      try dsimp only at h
      obtain ⟨_, hlink, h⟩ := bind_ok h
      obtain ⟨s, hs, hs1, hjoin, htxt⟩ := element_ok_at he
      obtain ⟨hsa, hsb, hcashrec⟩ := peek_span (q := i + 1) hs
      obtain ⟨r, sb, hr, hrd, hdec⟩ := read_ok_at hrow
      obtain ⟨hra, hrb, hmarkrec⟩ := peek_span (q := j1) hr
      rw [← hr] at h
      have hrest' : rest = [] := by
        cases rest with
        | nil => rfl
        | cons a t => exact absurd (need_ok hrest : false = true) (by decide)
      rw [hrest'] at hcmd
      have hlink' := need_ok hlink
      simp only [Bool.and_eq_true] at hlink'
      have hrl : rl.prev = o.head + 1 := by rw [eq_of_beq hlink'.1.1.1]
      obtain ⟨hoh, o0, hl0, hled0⟩ := hg.obl row.ob o (get_ok ho)
      obtain ⟨mid, hrun, hmid⟩ := cmd_records (i := i) (s := s) (j := j1) (ri := r) hcb (by omega) hs1 hra
        (fun p p1 p2 => ⟨15, hcashrec p (by omega) p2, by decide⟩) htxt
        (fun p p1 p2 => ⟨0x50, hmarkrec p p1 p2, by decide⟩) hjoin
      -- The outcome Lean's rule gives, by the kind of row it is checked against.
      split at h
      all_goals
        first
          | (obtain ⟨_, hbad, _⟩ := bind_ok h
             exact (throw_ok hbad).elim)
          | skip
      all_goals
        have hmk : 14 ≤ row.mkind ∧ row.mkind ≤ 17 := by omega
        have hpay := replay1_pay (o := o0) (s := ⟨x, mid, r, row, rl⟩) hmk hmid (get_ok hcmd)
        first
          | (obtain ⟨tup, hp, h⟩ := bind_ok h
             have _ := pure_ok hp)
          | (obtain ⟨_, -, h⟩ := bind_ok h
             obtain ⟨_, -, h⟩ := bind_ok h
             obtain ⟨tup, hp, h⟩ := bind_ok h)
        obtain ⟨_, hok, h⟩ := bind_ok h
        have hok' := need_ok hok
        simp only [Bool.and_eq_true] at hok'
        have hload := loadObl_step hrd hdec rfl (rowLinks_cmd hok'.2) (by omega) hrun hxd (prev := some o0)
          (Or.inr ⟨o0, o.head, rfl, hrl, by omega, hl0⟩)
        split at h
        all_goals
          obtain ⟨k, hk, h⟩ := bind_ok h
          obtain ⟨rfl, hj⟩ := Prod.mk.inj (pure_ok h)
          rw [← hj]
          have hkk : r + 1 ≤ k ∧ ∀ p, r < p → p < k → TagAt rec p 0xF5 := by
            first
              | exact afterRef_ok hk
              | (have e1 : r + 1 = k := pure_ok hk
                 exact ⟨by omega, fun p p1 p2 => by omega⟩)
          obtain ⟨hk1, hk2⟩ := hkk
          refine hg.step (ri := r) (ob := row.ob) (by rfl) (by omega) (by omega) ?_ (row_ob hrd hdec) ?_ ?_
          · intro p p1 p2 p3
            have ht : ∃ t, TagAt rec p t ∧ t ≠ 0x60 := by
              by_cases q0 : p = i
              · rw [q0]
                exact ⟨0x74, hcmdrec, by decide⟩
              · by_cases q1 : p < s
                · exact ⟨15, hcashrec p (by omega) q1, by decide⟩
                · by_cases q2 : p < j1
                  · exact ⟨0xF5, htxt p (by omega) q2, by decide⟩
                  · by_cases q3 : p < r
                    · exact ⟨0x50, hmarkrec p (by omega) q3, by decide⟩
                    · exact ⟨0xF5, hk2 p (by omega) p2, by decide⟩
            obtain ⟨t, ht1, ht2⟩ := ht
            exact ht1.not_row ht2
          · rfl
          · rw [hload]
            cases hrep : replay1 (some o0) ⟨x, mid, r, row, rl⟩ with
            | none => rw [hrep] at hpay; cases hpay
            | some o1 =>
              rw [hrep, hled0] at hpay
              exact ⟨o1, rfl, Option.some.inj hpay⟩
  · -- An evaluation: the request id's text, the row, its reference.
    split at h
    all_goals
      obtain ⟨⟨rid, j1⟩, hel, h⟩ := bind_ok h
      try dsimp only at h
      obtain ⟨-, -, h⟩ := bind_ok h
      obtain ⟨⟨row, rl⟩, hrow, h⟩ := bind_ok h
      try dsimp only at h
      obtain ⟨o, ho, h⟩ := bind_ok h
      try dsimp only at h
      obtain ⟨-, -, h⟩ := bind_ok h
      obtain ⟨res, hres, h⟩ := bind_ok h
      try dsimp only at h
      obtain ⟨-, -, h⟩ := bind_ok h
      obtain ⟨_, hrowok, h⟩ := bind_ok h
      obtain ⟨k, hk, h⟩ := bind_ok h
      try dsimp only at h
      obtain ⟨rfl, hj⟩ := Prod.mk.inj (pure_ok h)
      rw [← hj]
      have hmid : i + 1 ≤ j1 ∧ ∀ p, i + 1 ≤ p → p < j1 → TagAt rec p 0xF5 := by
        first
          | (have e : i + 1 = j1 := (Prod.mk.inj (pure_ok hel)).2
             exact ⟨by omega, fun p h1 h2 => by omega⟩)
          | (have h0 := element_ok hel
             exact ⟨h0.1, h0.2.2⟩)
      obtain ⟨hm1, hm2⟩ := hmid
      obtain ⟨sb, hrd, hdec⟩ := read_ok hrow
      have hrowok' := need_ok hrowok
      simp only [Bool.and_eq_true] at hrowok'
      obtain ⟨⟨⟨⟨hmk, -⟩, hlinks⟩, -⟩, hrl⟩ := hrowok'
      have hrl' : rl.prev = o.head + 1 := by rw [eq_of_beq hrl]
      obtain ⟨hoh, o0, hl0, hled0⟩ := hg.obl row.ob o (get_ok ho)
      obtain ⟨hk1, hk2⟩ := afterRef_ok hk
      obtain ⟨mid, hrun⟩ : ∃ mid, ((readRun i (j1 - i) []).run rec).1 = some ((cb, xl) :: mid) :=
        ⟨_, readRun_cmd (by omega) hcb fun p p1 p2 => by
          obtain ⟨b, l, hb, -⟩ := hm2 p (by omega) p2
          rw [hb]
          rfl⟩
      have hload := loadObl_step hrd hdec rfl (rowLinks_cmd hlinks) (by omega) hrun hxd (prev := some o0)
        (Or.inr ⟨o0, o.head, rfl, hrl', by omega, hl0⟩)
      have hres' : evaluate { o0.led.input with evaluatedAt := row.atMs } = some res := by
        rw [hled0]
        exact get_ok hres
      refine hg.step (ri := j1) (ob := row.ob) (by rfl) (by omega) (by omega) ?_ (row_ob hrd hdec) ?_ ?_
      · intro p p1 p2 p3
        have ht : ∃ t, TagAt rec p t ∧ t ≠ 0x60 := by
          by_cases q0 : p = i
          · rw [q0]
            exact ⟨0x74, hcmdrec, by decide⟩
          · by_cases q2 : p < j1
            · exact ⟨0xF5, hm2 p (by omega) q2, by decide⟩
            · exact ⟨0xF5, hk2 p (by omega) p2, by decide⟩
        obtain ⟨t, ht1, ht2⟩ := ht
        exact ht1.not_row ht2
      · rfl
      · rw [hload, replay1_eval (o := o0) (s := ⟨x, mid, j1, row, rl⟩) (eq_of_beq hmk) hres']
        exact ⟨_, rfl, by rw [hled0]⟩
  · exact (throw_ok h).elim

/-! ## The whole log -/

theorem checkLog_loads {rec : Nat → Option Bytes} {dig : Nat → Bytes → Nat → Bytes} {n : Nat} :
    ∀ (k : Nat) (st : Chk) (i c : Nat), n - i = k → i ≤ n → Loads rec st i → (checkLog rec dig n st i c).err = none →
      ∀ p, p < n → ∀ (row : StateRow) (l : Link), rd rec p = some (stateC.enc row, l) →
        ((loadObl row.ob p).run rec).1.isSome = true := by
  intro k
  induction k using Nat.strongRecOn with
  | _ k ih =>
    intro st i c hk hi hg herr
    unfold checkLog at herr
    split at herr
    · rename_i hlt
      split at herr
      · rename_i xr lr hpeek
        split at herr
        · rename_i st' hpass
          obtain ⟨b, lb, hb, ht⟩ := point_some hpeek
          have hrep : TagAt rec i (tagOf b) := ⟨b, lb, hb, rfl⟩
          refine ih (n - (i + 1)) (by omega) st' (i + 1) c rfl (by omega) (hg.skip (pass_obl hpass) (by omega) ?_) herr
          intro p p1 p2
          have e : p = i := by omega
          rw [e]
          exact hrep.not_row (by rcases ht with ht | ht <;> rw [ht] <;> decide)
        · cases herr
      · split at herr
        · split at herr
          · rename_i st' j hone
            split at herr
            · rename_i hj
              have := ownEnd_gt rec i
              have hcut : ∀ k, k < ownEnd rec i → cutAt rec (ownEnd rec i) k = rec k := fun k hk => by
                simp [cutAt, hk]
              have h2 := checkOne_loads hone (hg.local fun k hk => hcut k (by omega))
              exact ih (n - j) (by omega) st' j (c + 1) rfl (by omega)
                (h2.local fun k hk => (hcut k (by omega)).symm) herr
            · cases herr
          · cases herr
        · cases herr
    · intro p hp row l hr
      exact hg.rows p (by omega) row l hr

/-- In a log the checker accepts, the engine rebuilds an obligation from every state row (`loadObl`), so no command
    on an accepted log is answered `STORE_READ` for its obligation. -/
theorem accepted_log_loads : AcceptedLogLoads := by
  intro log herr i row l hr _
  have hi : i < log.length := by
    rcases Nat.lt_or_ge i log.length with h | h
    · exact h
    · have hn : log[i]? = none := List.getElem?_eq_none h
      simp [rd, hn] at hr
  exact checkLog_loads (rec := fun i => log[i]?) (dig := spanDig fun i => log[i]?) (n := log.length) _ {} 0 0 rfl
    (Nat.zero_le _)
    ⟨fun p hp => absurd hp (Nat.not_lt_zero _), fun ob E hE => by simp at hE⟩ herr i hi row l hr

end BlindLedger.Gate.Obligations
