import BlindLedger.Gate.Obligations.CheckedLog

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec
open BlindLedger.Financial (FinancialInput FinancialResult ControlPack evaluate decodeFinancialInput decodeControlPack
  encodeControlPack rawEncodeFinancialInput rawEncodeFinancialResult)
open BlindLedger.Financial.Payment (Ledger Call Command ReverseCommand readCommand encodeCommand commitInput)

/-! The checker accepts every log the engine writes (`EngineLogChecks`), in three parts.

    1. The checker's tables stand in a fixed relation to the engine's store and log (`Sim`).  Before a command it
       gives what the checker needs to know of the engine's view (`Pre`, by `sim_pre`).
    2. For a command the engine decides, the checker passes its records and changes its tables as the plan says
       (`Forward`, with `Post`).
    3. Those changes keep the relation over the records the command wrote (`Kept`).

    Proved here: part 1 and the theorem from parts 2 and 3 (`engine_log_checks_of`).  Parts 2 and 3 are stated here
    as `Forward` and `Kept`; they are proved in `EngineLogForward.lean` and `EngineLogKept.lean`, and the theorem
    itself (`engine_log_checks`) is in `EngineLogProof.lean`.

    Nothing the program runs imports this module. -/

/-! ## Steps of the checker that pass -/

theorem bind_intro {α β : Type} {x : Except String α} {f : α → Except String β} {a : α} {r : β}
    (hx : x = .ok a) (h : f a = .ok r) : (x >>= f) = .ok r := by
  subst hx
  exact h

theorem need_intro {β : Type} {b : Bool} {i : Nat} {m : String} {f : Unit → Except String β} {r : β}
    (hb : b = true) (h : f () = .ok r) : (need b i m >>= f) = .ok r := by
  subst hb
  exact h

theorem get_intro {α β : Type} {o : Option α} {i : Nat} {m : String} {f : α → Except String β} {a : α} {r : β}
    (ho : o = some a) (h : f a = .ok r) : (get o i m >>= f) = .ok r := by
  subst ho
  exact h

theorem read_intro {α : Type} {rec : Nat → Option Bytes} {i : Nat} {d : Bytes → Option α} {m : String} {b : Bytes}
    {l : Link} {x : α} (hr : rd rec i = some (b, l)) (hd : d b = some x) : read rec i d m = .ok (x, l) := by
  unfold read
  exact get_intro hr (get_intro hd rfl)

theorem peek_hit {α : Type} {rec : Nat → Option Bytes} {i t : Nat} {d : Bytes → Option α} {b : Bytes} {l : Link}
    {x : α} (hr : rd rec i = some (b, l)) (ht : tagOf b = t) (hd : d b = some x) : peek rec i t d = some (x, l) := by
  simp [peek, hr, ht, hd]

theorem peek_miss {α : Type} {rec : Nat → Option Bytes} {i t : Nat} {d : Bytes → Option α} {b : Bytes} {l : Link}
    (hr : rd rec i = some (b, l)) (ht : tagOf b ≠ t) : peek rec i t d = none := by
  simp [peek, hr, ht]

/-- A record the engine wrote reads back as its body and link, and its body decodes. -/
theorem rd_full {α : Type} {c : RecCodec α} (hc : c.Lawful ∧ width c.L = bodyBytes) {rec : Nat → Option Bytes}
    {a : Nat} {x : α} {l : Link} {r : Bytes} (he : encFull (full c x l) = some r) (hr : rec a = some r) :
    rd rec a = some (c.enc x, l) ∧ c.dec (c.enc x) = some x := by
  obtain ⟨hu, hwf⟩ := unwrap_full hc.2 he
  exact ⟨by simp [rd, hr, hu], RecCodec.dec_enc hc.1 hwf⟩

/-! ## Records placed in the log -/

/-- The records of `body` stand in the log from record `a` on. -/
def Placed (rec : Nat → Option Bytes) (a : Nat) (body : List Body) : Prop :=
  ∃ rs, encAll body = some rs ∧ ∀ j r, rs[j]? = some r → rec (a + j) = some r

theorem Placed.split {rec : Nat → Option Bytes} {a : Nat} {xs ys : List Body} (h : Placed rec a (xs ++ ys)) :
    Placed rec a xs ∧ Placed rec (a + xs.length) ys := by
  obtain ⟨rs, he, hr⟩ := h
  obtain ⟨b1, b2, h1, h2, rfl⟩ := encAll_append he
  have hl := encAll_length h1
  refine ⟨⟨b1, h1, fun j r hj => hr j r ?_⟩, ⟨b2, h2, fun j r hj => ?_⟩⟩
  · have hlt : j < b1.length := (List.getElem?_eq_some_iff.1 hj).1
    rw [List.getElem?_append_left hlt]
    exact hj
  · have h3 := hr (b1.length + j) r (by
      rw [List.getElem?_append_right (Nat.le_add_right _ _), Nat.add_sub_cancel_left]
      exact hj)
    rw [← hl, Nat.add_assoc]
    exact h3

theorem Placed.head {rec : Nat → Option Bytes} {a : Nat} {b : Body} {ys : List Body} (h : Placed rec a (b :: ys)) :
    (∃ r, b.encOk = some r ∧ rec a = some r) ∧ Placed rec (a + 1) ys := by
  obtain ⟨rs, he, hr⟩ := h
  simp only [encAll] at he
  split at he
  · rename_i x xs hx hxs
    cases he
    refine ⟨⟨x, hx, by simpa using hr 0 x (by simp)⟩, xs, hxs, fun j r hj => ?_⟩
    have h3 := hr (j + 1) r (by simpa using hj)
    rw [Nat.add_assoc, Nat.add_comm 1 j]
    exact h3
  · cases he

theorem nParts_pos {e : Bytes} (h : 1 ≤ e.length) : 1 ≤ nParts e := by
  have hne : e.isEmpty = false := by
    cases e with
    | nil => simp at h
    | cons _ _ => rfl
  have hp := partsFrom_ne 0 e
  unfold nParts
  rw [hne]
  cases hq : partsFrom 0 e with
  | nil => exact absurd hq hp
  | cons _ _ => simp

/-- The text records of an element, placed where they were numbered, read back as the element. -/
theorem Placed.element {rec : Nat → Option Bytes} {n a c : Nat} {e : Bytes} (h : Placed rec a (textsAt e a c))
    (he : 1 ≤ e.length) (hn : a + nParts e ≤ n)
    (hend : a + nParts e < n → ∀ b l, rd rec (a + nParts e) = some (b, l) → tagOf b ≠ 0xF5) :
    element rec n a c = .ok (e, a + nParts e) := by
  obtain ⟨rs, hrs, hr⟩ := h
  have hl : rs.length = nParts e := by rw [encAll_length hrs, textsAt_length]
  rw [← hl] at hn hend ⊢
  exact element_rebuild he hrs (fun j hj => hr j rs[j] (List.getElem?_eq_getElem hj)) hn hend

theorem refOf_eq (res : FinancialResult) : refOf res = evalRef res := rfl

theorem evalRef_length (res : FinancialResult) : 1 ≤ (evalRef res).length := by
  simp only [evalRef, zeros, List.length_append, List.length_replicate]
  omega

/-- The evaluation reference the engine wrote after a state row is the one the checker asks for. -/
theorem Placed.afterRef {rec : Nat → Option Bytes} {n r c : Nat} {res : FinancialResult}
    (h : Placed rec (r + 1) (textsAt (evalRef res) (r + 1) c)) (hn : r + 1 + nParts (evalRef res) ≤ n)
    (hend : r + 1 + nParts (evalRef res) < n → ∀ b l, rd rec (r + 1 + nParts (evalRef res)) = some (b, l) →
      tagOf b ≠ 0xF5) :
    afterRef rec n r c res = .ok (r + 1 + nParts (evalRef res)) := by
  unfold BlindLedger.Gate.Obligations.afterRef
  refine bind_intro (h.element (evalRef_length res) hn hend) ?_
  exact need_intro (by simp [refOf_eq]) rfl

/-! ## The relation between the checker's tables and the engine's store -/

/-- The checker's entry of an obligation holds what the engine's obligation holds. -/
def Entry.same (E : Entry) (o : Obl) : Prop :=
  E.led = o.led ∧ E.head = o.head ∧ E.headCount = o.headCount ∧ E.caseRef = o.caseRef ∧ E.fact = o.fact ∧
    E.factCount = o.factCount ∧ E.cash = o.cash ∧ E.noClass = o.noClass

/-- The checker's tables after it has passed the log, against the engine's store of that log.  Every command id
    the checker holds is of a command record of the log.  The checker holds the pack the engine reads from each
    pack command.  The entry of an obligation is what the engine loads from the entry's row, and that row is the
    only one of the obligation the engine's table holds. -/
structure Sim (s : Store) (log : List Bytes) (st : Chk) : Prop where
  inv : s.Inv log
  n : s.n = log.length
  chain : ChainOk log
  prev : st.cmdPrev = s.cmdPrev
  count : st.cmdCount = s.cmdCount
  last : st.lastMs = s.lastMs
  cids : ∀ k, st.cids.contains k = true → ∃ r ∈ log, identKey r = some (0x74, k)
  packs : ∀ (i : Nat) (r k : Bytes), log[i]? = some r → identKey r = some (0x74, k) →
    ∀ (ext : List Bytes) (pc : ControlPack × PackClass),
      ((packOf i r).run fun j => (log ++ ext)[j]?).1 = some pc → st.packs[k]? = some pc.1
  obl : ∀ (ob : Bytes) (E : Entry), st.obl[ob]? = some E →
    ∃ o, ((loadObl ob E.head).run fun j => log[j]?).1 = some o ∧ E.same o
  heads : ∀ (ob : Bytes) (j : Nat), j ∈ Slots.of s.obl ob → RowAt log ob j → ∃ E, st.obl[ob]? = some E ∧ E.head = j
  slots : ∀ (u : UInt64), (s.obl.getD u []).Nodup ∧ ∀ j ∈ s.obl.getD u [], j < log.length

/-- What the checker's tables say of the engine's view of a command it has no record of. -/
structure Pre (st : Chk) (v : View) (c : Cmd) : Prop where
  prev : st.cmdPrev = v.cmdPrev
  count : st.cmdCount = v.cmdCount
  last : st.lastMs = v.lastMs
  fresh : st.cids.contains (cidOfCmd c) = false
  pack : ∀ (k : Bytes) (pk : ControlPack) (cls : PackClass), packCid c = some k → v.pack = some (pk, cls) →
    st.packs[k]? = some pk
  unknown : ∀ (k : Bytes), obKey c = some k → v.oblKnown = false → st.obl.contains k = false
  obl : ∀ (k : Bytes) (o : Obl), obKey c = some k → v.obl = some o → ∃ E, st.obl[k]? = some E ∧ E.same o

/-- The checker's tables after a command whose command record is record `i`, against the plan the engine decided:
    the command's id, the chain of command records, the pack of a pack command, and the obligation the plan
    leaves. -/
def Post (st st' : Chk) (c : Cmd) (p : Plan) (i : Nat) : Prop :=
  st'.cids = st.cids.insert (cidOfCmd c) ∧ st'.cmdPrev = i + 1 ∧ st'.cmdCount = p.link.count ∧
    st'.lastMs = c.atMs ∧
    st'.packs = (match c.act with
      | .pack pk _ => st.packs.insert (cidOfCmd c) pk
      | _ => st.packs) ∧
    match p.obl with
    | some (ob, o') => ∃ E, st'.obl = st.obl.insert ob E ∧ E.same o'
    | none => st'.obl = st.obl

/-- What every command of this step states: no actor, role 0, attribution 2, source 1. -/
def Cmd.plain (c : Cmd) : Prop := c.actor = zeros 32 ∧ c.role = 0 ∧ c.attr = 2 ∧ c.src = stepSource

/-- Part 2: the records of a decided command, placed from record `i`, end where the command's own counts say they
    end (`ownEnd`); the checker passes them in a log that ends there, and changes its tables as the plan says. -/
def Forward : Prop :=
  ∀ (st : Chk) (v : View) (c : Cmd) (f : Nat → Plan) (i : Nat) (bs : List Bytes) (rec : Nat → Option Bytes),
    Pre st v c → c.plain → core v c = .ok f → (f i).bytes c = some bs →
    (∀ j r, bs[j]? = some r → rec (i + j) = some r) →
    ownEnd rec i = i + bs.length ∧
      ∃ st', checkOne st rec (i + bs.length) i = .ok (st', i + bs.length) ∧ Post st st' c (f i) i

/-- Part 3: the changes of `Post` keep the relation over the records the command wrote. -/
def Kept : Prop :=
  ∀ (s : Store) (log : List Bytes) (st st' : Chk) (c : Cmd) (d : Disp) (p : Plan) (bs : List Bytes),
    Sim s log st → decideView (viewOf s (fun i => log[i]?) c) c s.n = (d, some p, bs) →
    Post st st' c p log.length → Sim (bs.foldl Store.scan s) (log ++ bs) st'

theorem sim_empty (card : Card) (reg : Array Nat) : Sim (Store.empty card reg) [] {} where
  inv := rfl
  n := rfl
  chain := by intro i r row l h; simp at h
  prev := rfl
  count := rfl
  last := rfl
  cids := by intro k h; simp at h
  packs := by intro i r k h; simp at h
  obl := by intro ob E h; simp at h
  heads := by intro ob j h; simp [Slots.of, Store.empty] at h
  slots := by intro u; simp [Store.empty]

/-! ## What the relation says of a command's view -/

theorem loadRd_pack (s : Store) (fetch : Nat → Option Bytes) (c : Cmd) :
    ((loadRd s c).run fetch).1.pack = ((loadPk s c).run fetch).1.2 := by
  simp [loadRd, Rd.run_bind, Rd.run]

/-- The pack a command's view holds was read from a command record of the pack's id. -/
theorem view_pack_read {s : Store} {fetch : Nat → Option Bytes} {c : Cmd} {k : Bytes}
    {pc : ControlPack × PackClass} (hk : packCid c = some k) (hp : (viewOf s fetch c).pack = some pc) :
    ∃ i r, fetch i = some r ∧ identKey r = some (0x74, k) ∧ ((packOf i r).run fetch).1 = some pc := by
  have h : ((loadPk s c).run fetch).1.2 = some pc := by rw [← loadRd_pack]; exact hp
  simp only [loadPk, hk] at h
  rw [Rd.run_bind] at h
  cases hfnd : ((findRec (keyIs (0x74, k)) (Slots.of s.ident k)).run fetch).1 with
  | absent => rw [hfnd] at h; simp [Rd.run] at h
  | unread => rw [hfnd] at h; simp [Rd.run] at h
  | hit i r =>
    rw [hfnd] at h
    obtain ⟨-, r', h1, h2⟩ := findRec_hit hfnd
    have hr : identKey r' = some (0x74, k) ∧ r' = r := by
      cases hk' : identKey r' with
      | none => simp [keyIs, hk'] at h2
      | some k' =>
        by_cases he : k' = (0x74, k)
        · subst he
          simp [keyIs, hk'] at h2
          exact ⟨rfl, h2⟩
        · simp [keyIs, hk', he] at h2
    obtain ⟨hr1, rfl⟩ := hr
    refine ⟨i, r', h1, hr1, ?_⟩
    dsimp only at h
    rw [Rd.run_bind] at h
    cases hpk : ((packOf i r').run fetch).1 with
    | none => rw [hpk] at h; simp [Rd.run] at h
    | some pc' => rw [hpk] at h; simpa [Rd.run] using h

/-- The obligation a command's view holds was loaded from a row the engine's table holds. -/
theorem view_obl_slot {s : Store} {fetch : Nat → Option Bytes} {c : Cmd} {k : Bytes} {o : Obl}
    (hk : obKey c = some k) (ho : (viewOf s fetch c).obl = some o) : o.head ∈ Slots.of s.obl k := by
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
        exact (findRec_hit hfnd).1
    · simp [hro, Rd.run] at h

/-- Part 1: the relation gives what the checker needs to know of the view of a command the log does not hold. -/
theorem sim_pre {s : Store} {log : List Bytes} {st : Chk} {c : Cmd} (hsim : Sim s log st)
    (hhit : (viewOf s (fun i => log[i]?) c).hit = none) : Pre st (viewOf s (fun i => log[i]?) c) c where
  prev := hsim.prev
  count := hsim.count
  last := hsim.last
  fresh := by
    cases h : st.cids.contains (cidOfCmd c) with
    | false => rfl
    | true =>
      obtain ⟨r, hm, hr⟩ := hsim.cids _ h
      exact absurd hr (no_hit_no_record hsim.inv (fun _ => rfl) hhit r hm)
  pack := by
    intro k pk cls hk hp
    obtain ⟨i, r, h1, h2, h3⟩ := view_pack_read hk hp
    exact hsim.packs i r k h1 h2 [] (pk, cls) (by simpa using h3)
  unknown := by
    intro k hk hv
    have hno := unknown_obligation_has_no_row hsim.inv (fun _ => rfl) hsim.chain hk hv
    cases hE : st.obl[k]? with
    | none => simp [Std.HashMap.contains_eq_isSome_getElem?, hE]
    | some E =>
      obtain ⟨o, hl, -⟩ := hsim.obl k E hE
      exact absurd (loadObl_head hl).2 (hno E.head)
  obl := by
    intro k o hk ho
    have hl := view_obl_load hk ho
    obtain ⟨E, hE, hh⟩ := hsim.heads k o.head (view_obl_slot hk ho) (loadObl_head hl).2
    obtain ⟨o', hl', hs⟩ := hsim.obl k E hE
    rw [hh, hl] at hl'
    cases hl'
    exact ⟨E, hE, hs⟩

/-! ## The whole log -/

theorem apply_some {s : Store} {fetch : Nat → Option Bytes} {c : Cmd} {d : Disp} {p : Plan} {bs : List Bytes}
    (hd : decideView (viewOf s fetch c) c s.n = (d, some p, bs)) :
    apply s fetch c = (d, bs, bs.foldl Store.scan s) := by
  simp only [apply, applyView, hd]

theorem apply_none {s : Store} {fetch : Nat → Option Bytes} {c : Cmd} {d : Disp} {bs : List Bytes}
    (hd : decideView (viewOf s fetch c) c s.n = (d, none, bs)) : apply s fetch c = (d, [], s) := by
  simp only [apply, applyView, hd]

/-- The command record and the records after it. -/
theorem Plan.bytes_cons {p : Plan} {c : Cmd} {bs : List Bytes} (h : p.bytes c = some bs) :
    ∃ cb rest, bs = cb :: rest ∧ encFull (full cmdC (p.cmd c) p.link) = some cb ∧ encAll p.body = some rest := by
  unfold Plan.bytes at h
  split at h
  · rename_i b rest hb hr
    cases h
    exact ⟨b, rest, rfl, hb, hr⟩
  · cases h

/-- The fold of `logOf`, from any store and log. -/
def run (cmds : List Cmd) (p : Store × List Bytes) : Store × List Bytes :=
  cmds.foldl (fun (s, log) c =>
    let r := apply s (fun i => log[i]?) c
    (r.2.2, log ++ r.2.1)) p

theorem run_cons (c : Cmd) (cs : List Cmd) (s : Store) (log : List Bytes) :
    run (c :: cs) (s, log) =
      run cs ((apply s (fun i => log[i]?) c).2.2, log ++ (apply s (fun i => log[i]?) c).2.1) := rfl

/-- Commands only add records. -/
theorem run_grows : ∀ (cmds : List Cmd) (s : Store) (log : List Bytes), ∃ ext, (run cmds (s, log)).2 = log ++ ext
  | [], s, log => ⟨[], by simp [run]⟩
  | c :: cs, s, log => by
    rw [run_cons]
    cases hd : decideView (viewOf s (fun i => log[i]?) c) c s.n with
    | mk d q =>
      obtain ⟨_ | p, bs⟩ := q
      · rw [apply_none hd]
        simpa using run_grows cs s log
      · rw [apply_some hd]
        obtain ⟨ext, he⟩ := run_grows cs (bs.foldl Store.scan s) (log ++ bs)
        exact ⟨bs ++ ext, he.trans (List.append_assoc _ _ _)⟩

/-- One command of the whole check: its own records end at `e`, inside the log, and the checker passes it on
    the log cut there. -/
theorem checkLog_step {rec : Nat → Option Bytes} {dig : Nat → Bytes → Nat → Bytes} {n i e k : Nat}
    {st st' : Chk} (hi : i < n) (hp : point rec i = none) (hown : ownEnd rec i = e) (he : e ≤ n)
    (h1 : checkOne st (cutAt rec e) e i = .ok (st', e)) :
    checkLog rec dig n st i k = checkLog rec dig n st' e (k + 1) := by
  subst hown
  rw [checkLog.eq_1 rec dig n st i k]
  simp [hi, hp, he, h1]

/-- A command record is not a commit point. -/
theorem point_cmd {rec : Nat → Option Bytes} {i : Nat} {b : Bytes} {l : Link} (h : rd rec i = some (b, l))
    (ht : tagOf b = 0x74) : point rec i = none := by
  cases hq : point rec i with
  | none => rfl
  | some q =>
    obtain ⟨b', l', h', ht'⟩ := point_some hq
    rw [h] at h'
    cases h'
    rcases ht' with ht' | ht' <;> rw [ht] at ht' <;> exact absurd ht' (by decide)

theorem run_checks (hF : Forward) (hK : Kept) : ∀ (cmds : List Cmd) (s : Store) (log : List Bytes) (st : Chk)
    (k : Nat), Sim s log st → (∀ c ∈ cmds, c.plain) →
      (checkLog (fun i => (run cmds (s, log)).2[i]?) (spanDig fun i => (run cmds (s, log)).2[i]?)
        (run cmds (s, log)).2.length st log.length k).err = none
  | [], s, log, st, k, _, _ => by
    show (checkLog (fun i => log[i]?) (spanDig fun i => log[i]?) log.length st log.length k).err = none
    rw [checkLog.eq_1, dif_neg (Nat.lt_irrefl _)]
  | c :: cs, s, log, st, k, hsim, hpl => by
    have hcs : ∀ c' ∈ cs, c'.plain := fun c' hc => hpl c' (List.mem_cons_of_mem _ hc)
    rw [run_cons]
    cases hd : decideView (viewOf s (fun i => log[i]?) c) c s.n with
    | mk d q =>
      obtain ⟨_ | p, bs⟩ := q
      · rw [apply_none hd]
        have ih := run_checks hF hK cs s log st k hsim hcs
        rw [← List.append_nil log] at ih
        simpa using ih
      · rw [apply_some hd]
        show (checkLog (fun i => (run cs (bs.foldl Store.scan s, log ++ bs)).2[i]?)
          (spanDig fun i => (run cs (bs.foldl Store.scan s, log ++ bs)).2[i]?)
          (run cs (bs.foldl Store.scan s, log ++ bs)).2.length st log.length k).err = none
        obtain ⟨-, hhit, hb, f, hf, hp⟩ := decideView_some hd
        obtain ⟨ext, he⟩ := run_grows cs (bs.foldl Store.scan s) (log ++ bs)
        have hn := hsim.n
        obtain ⟨cb, rest, hbs, hcb, -⟩ := Plan.bytes_cons hb
        have hpos : 0 < bs.length := by rw [hbs]; simp
        obtain ⟨fin, hfin⟩ : ∃ fin, fin = (run cs (bs.foldl Store.scan s, log ++ bs)).2 := ⟨_, rfl⟩
        rw [← hfin] at he ⊢
        have hrec : ∀ j r, bs[j]? = some r → fin[log.length + j]? = some r := by
          intro j r hj
          have hjl : j < bs.length := (List.getElem?_eq_some_iff.1 hj).1
          rw [he, List.getElem?_append_left (by rw [List.length_append]; omega),
            List.getElem?_append_right (Nat.le_add_right _ _), Nat.add_sub_cancel_left]
          exact hj
        have hlen : log.length + bs.length ≤ fin.length := by
          rw [he, List.length_append, List.length_append]
          omega
        have hb' : (f log.length).bytes c = some bs := by rw [← hn, ← hp]; exact hb
        -- The command's records are all in the log cut at their end.
        have hcut : ∀ j r, bs[j]? = some r →
            cutAt (fun i => fin[i]?) (log.length + bs.length) (log.length + j) = some r := by
          intro j r hj
          have hjl : j < bs.length := (List.getElem?_eq_some_iff.1 hj).1
          show (if log.length + j < log.length + bs.length then fin[log.length + j]? else none) = some r
          rw [if_pos (Nat.add_lt_add_left hjl _)]
          exact hrec j r hj
        obtain ⟨hown, st', hone, hpost⟩ := hF st _ c f log.length bs
          (cutAt (fun i => fin[i]?) (log.length + bs.length)) (sim_pre hsim hhit) (hpl c (by simp)) hf hb' hcut
        -- The whole log names the same end: a command's own end depends on its own records alone.
        have hown' : ownEnd (fun i => fin[i]?) log.length = log.length + bs.length :=
          (ownEnd_local fun a ha => by
            rw [hown] at ha
            show fin[a]? = if a < log.length + bs.length then fin[a]? else none
            rw [if_pos ha]).trans hown
        have hpost' : Post st st' c p log.length := by rw [hp, hn]; exact hpost
        have hpeek : point (fun i => fin[i]?) log.length = none := by
          have h0 := hrec 0 cb (by simp [hbs])
          rw [Nat.add_zero] at h0
          have hu := (unwrap_full cmdC_ok.2 hcb).1
          exact point_cmd (b := cmdC.enc (p.cmd c)) (l := p.link) (by simp [rd, h0, hu])
            (by rw [enc_tag (c := cmdC) (v := 0x74) rfl (by decide)])
        have ih := run_checks hF hK cs (bs.foldl Store.scan s) (log ++ bs) st' (k + 1)
          (hK s log st st' c d p bs hsim hd hpost') hcs
        rw [← hfin, List.length_append] at ih
        rw [checkLog_step (by omega) hpeek hown' hlen hone]
        exact ih

/-- `EngineLogChecks`, from parts 2 and 3. -/
theorem engine_log_checks_of (hF : Forward) (hK : Kept) : EngineLogChecks := by
  intro card reg cmds hpl
  exact run_checks hF hK cmds (Store.empty card reg) [] {} 0 (sim_empty card reg) hpl

end BlindLedger.Gate.Obligations
