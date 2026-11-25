import BlindLedger.Gate.Obligations.EngineLogSim

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec
open BlindLedger.Financial (FinancialInput FinancialResult ControlPack evaluate decodeFinancialInput decodeControlPack
  encodeControlPack rawEncodeFinancialInput rawEncodeFinancialResult)
open BlindLedger.Financial.Payment (Ledger Call Command ReverseCommand readCommand encodeCommand commitInput)

/-! The checker passes one command, given what its records hold: one statement for each kind of command.  Each
    asks for exactly what `checkOne` asks, in its order, and says which tables the checker leaves.

    Nothing the program runs imports this module. -/

theorem band_intro {a b : Bool} (ha : a = true) (hb : b = true) : (a && b) = true := by
  subst ha
  subst hb
  rfl

/-- What the checker asks of every command record before it looks at the command's kind. -/
structure Start (st : Chk) (rec : Nat → Option Bytes) (i : Nat) (x : CmdRec) (xl : Link) : Prop where
  cmd : read rec i cmdC.dec "not a command record" = .ok (x, xl)
  fresh : st.cids.contains x.cid = false
  link : xl = ⟨st.cmdPrev, nextCount st.cmdCount⟩
  fixed : cmdFixed x = true
  time : st.lastMs ≤ x.atMs ∧ x.atMs < 2 ^ 63

/-- Pass the checks every command record meets, down to the choice by kind. -/
local macro "start_cmd " h:ident : tactic => `(tactic| (
  unfold checkOne
  refine bind_intro (Start.cmd $h) ?_
  try dsimp only
  refine need_intro (by simp [Start.fresh $h]) ?_
  refine need_intro (beq_iff_eq.2 (Start.link $h)) ?_
  refine need_intro (Start.fixed $h) ?_
  refine need_intro (by simp only [Bool.and_eq_true, decide_eq_true_eq]; exact Start.time $h) ?_
  try dsimp only))

/-- A pack command: its text is the pack and two class bytes, and its id and request are the pack's own. -/
theorem checkOne_pack {st : Chk} {rec : Nat → Option Bytes} {n i j : Nat} {x : CmdRec} {xl : Link} {e cls : Bytes}
    {p : ControlPack} (h : Start st rec i x xl) (hk : x.ckind = 1)
    (hel : element rec n (i + 1) xl.count = .ok (e, j)) (hdec : decodeControlPack e = some (p, cls))
    (h1 : (x.result == 0 && x.lg == 0 && x.exprev == 0 && cls.length == 2 &&
      e == encodeControlPack p ++ cls) = true)
    (h2 : (x.cid == cidFor (scopeOf p.stateId.toUTF8.toList p.deploymentId.toUTF8.toList p.programId.toUTF8.toList
        p.periodId.toUTF8.toList p.currency.toUTF8.toList) 1 p.packId.toUTF8.toList &&
      x.rqd == rqdOf (canon ⟨1, p.packId.toUTF8.toList, scopeOf p.stateId.toUTF8.toList
        p.deploymentId.toUTF8.toList p.programId.toUTF8.toList p.periodId.toUTF8.toList p.currency.toUTF8.toList,
        [.d (H e)]⟩)) = true) :
    checkOne st rec n i = .ok
      ({ st with
          cids := st.cids.insert x.cid, cmdPrev := i + 1, cmdCount := xl.count, lastMs := x.atMs,
          packs := st.packs.insert x.cid p }, j) := by
  start_cmd h
  simp only [hk]
  refine bind_intro hel ?_
  try dsimp only
  refine get_intro hdec ?_
  try dsimp only
  refine need_intro h1 ?_
  refine need_intro h2 ?_
  rfl

/-- An evaluation: its request id is its text, its row continues the obligation's rows, and the row is Lean's
    evaluation of the obligation's input at the row's time. -/
theorem checkOne_eval {st : Chk} {rec : Nat → Option Bytes} {n i j k : Nat} {x : CmdRec} {xl rl : Link} {rid : Bytes}
    {row : StateRow} {o : Entry} {res : FinancialResult} (h : Start st rec i x xl) (hk : x.ckind = 12)
    (hel : (if (x.nt == 0) = true then (pure ([], i + 1) : Except String (Bytes × Nat))
      else element rec n (i + 1) xl.count) = .ok (rid, j))
    (hnt : (x.nt == j - (i + 1)) = true)
    (hrow : read rec j stateC.dec "state row" = .ok (row, rl)) (ho : st.obl[row.ob]? = some o)
    (hex : ((if x.exprev = 0 then none else some (x.exprev - 1)).all (· == o.led.input.beforeRevision)) = true)
    (hres : evaluate { o.led.input with evaluatedAt := row.atMs } = some res)
    (h1 : (x.cid == cidFor (scopeOfCtx o.led.input.context) 12 rid &&
      x.rqd == rqdOf (canon ⟨12, rid, scopeOfCtx o.led.input.context, [.s o.led.input.context.itemId]⟩) &&
      (x.lg == 2) == o.noClass) = true)
    (h2 : (row.mkind == 25 && stateAgree res 0 row &&
      rowLinks x row i o.fact o.fact o.caseRef (commitInput { o.led.input with evaluatedAt := row.atMs } res) &&
      x.result == j + 1 && rl == ⟨o.head + 1, nextCount o.headCount⟩) = true)
    (href : afterRef rec n j rl.count res = .ok k) :
    checkOne st rec n i = .ok
      ({ st with
          cids := st.cids.insert x.cid, cmdPrev := i + 1, cmdCount := xl.count, lastMs := x.atMs,
          obl := st.obl.insert row.ob
            { o with
              led := { o.led with input := commitInput { o.led.input with evaluatedAt := row.atMs } res },
              head := j, headCount := rl.count } }, k) := by
  start_cmd h
  simp only [hk]
  -- The checker goes on the same way whether or not the command has text.
  by_cases hc : (x.nt == 0) = true
  all_goals
    first
      | rw [if_pos hc] at hel ⊢
      | rw [if_neg hc] at hel ⊢
    refine bind_intro hel ?_
    try dsimp only
    refine need_intro hnt ?_
    refine bind_intro hrow ?_
    try dsimp only
    refine get_intro ho ?_
    try dsimp only
    refine need_intro hex ?_
    refine get_intro hres ?_
    try dsimp only
    refine need_intro h1 ?_
    refine need_intro h2 ?_
    refine bind_intro href ?_
    rfl

/-! ## An opening -/

/-- A loop whose every round passes and counts one ends at the count of its rounds. -/
theorem forIn_count {α : Type} {f : α → Nat → Except String (ForInStep Nat)} : ∀ (l : List α) (q : Nat),
    (∀ (t : Nat) (ht : t < l.length), f l[t] (q + t) = .ok (.yield (q + t + 1))) →
      forIn l q f = .ok (q + l.length)
  | [], q, _ => by
    rw [List.forIn_nil]
    rfl
  | a :: l, q, h => by
    rw [List.forIn_cons]
    refine bind_intro (h 0 (Nat.succ_pos _)) ?_
    have ih := forIn_count l (q + 1) fun t ht => by
      have h1 := h (t + 1) (Nat.succ_lt_succ ht)
      rw [List.getElem_cons_succ, show q + (t + 1) = q + 1 + t by omega] at h1
      exact h1
    rw [show q + (a :: l).length = q + 1 + l.length by rw [List.length_cons]; omega]
    exact ih

/-- An opening: an OBLIG fact that starts its own chain, the input's text, one OPEN record for each case of the
    input after its evaluation, the row, which stands on the fact, and its evaluation reference. -/
theorem checkOne_open {st : Chk} {rec : Nat → Option Bytes} {n i j q k : Nat} {x : CmdRec} {xl fl rl : Link}
    {e : Bytes} {f : ObligF} {inp : FinancialInput} {res : FinancialResult} {row : StateRow}
    (h : Start st rec i x xl) (hk : x.ckind = 2)
    (hf : read rec (i + 1) obligC.dec "OBLIG fact" = .ok (f, fl))
    (hel : element rec n (i + 2) fl.count = .ok (e, j)) (hinp : decodeFinancialInput e = some inp)
    (hres : evaluate inp = some res) (hq : q = j + (commitInput inp res).cases.length)
    (hcases : ∀ (t : Nat) (ht : t < (commitInput inp res).cases.length), ∃ kase kl,
      read rec (j + t) caseC.dec "case record" = .ok (kase, kl) ∧
        (kase.op == 1 && caseAgree (scopeOfCtx inp.context) (obOfCtx inp.context) (commitInput inp res).cases[t] kase &&
          caseFixed kase && kase.cmd == i + 1 && kase.lg == x.lg && kl == ⟨0, 1⟩) = true)
    (hrow : read rec q stateC.dec "state row" = .ok (row, rl))
    (h1 : (st.packs[cidFor (scopeOfCtx inp.context) 1 (utf8 inp.pack.packId)]? == some inp.pack) = true)
    (h2 : (inp.payments.isEmpty && inp.claims.isEmpty && inp.determinations.isEmpty && inp.conflicts.isEmpty &&
      inp.actions.isEmpty && (inp.evidence.isEmpty || x.lg == 2)) = true)
    (h3 : (x.cid == cidFor (scopeOfCtx inp.context) 2 (utf8 (inp.context.populationId ++ "/" ++ inp.context.itemId)) &&
      x.rqd == rqdOf (canon ⟨2, utf8 (inp.context.populationId ++ "/" ++ inp.context.itemId), scopeOfCtx inp.context,
        [.d (H (rawEncodeFinancialInput { inp with evaluatedAt := 0 }))]⟩) &&
      x.nt == 0 && x.exprev == 0 && x.atMs == inp.evaluatedAt && x.result == q + 1) = true)
    (h4 : (row.mkind == 13 && stateAgree res 0 row &&
      rowLinks x row i (i + 1) (i + 1) (if q = j then 0 else q) (commitInput inp res) && rl == ⟨0, 1⟩) = true)
    (h5 : (f.h.op == 0 && f.h.subject == obOfCtx inp.context && hdrFixed f.h &&
      f.h.sid == obligSidOf (scopeOfCtx inp.context) (utf8 inp.context.populationId) (utf8 inp.context.itemId) &&
      f.h.vstart == utcDate x.atMs && f.h.vstop == utcDate x.atMs && f.owed == inp.obligation.owedCents &&
      f.dueMs == inp.obligation.dueAt && f.rule == inp.obligation.ruleVersion &&
      f.pop == popOf (scopeOfCtx inp.context) (utf8 inp.context.populationId) &&
      f.item == display 51 inp.context.itemId && f.period == display 21 inp.context.periodId && f.ecls == 0 &&
      fl == ⟨0, 1⟩) = true)
    (h6 : st.obl.contains (obOfCtx inp.context) = false)
    (href : afterRef rec n q rl.count res = .ok k) :
    checkOne st rec n i = .ok
      ({ st with
          cids := st.cids.insert x.cid, cmdPrev := i + 1, cmdCount := xl.count, lastMs := x.atMs,
          obl := st.obl.insert (obOfCtx inp.context)
            ⟨{ input := commitInput inp res, receipts := [] }, q, 1, if q = j then 0 else q, i + 1, 1, [],
              x.lg == 2⟩ }, k) := by
  subst hq
  start_cmd h
  simp only [hk]
  refine bind_intro hf ?_
  try dsimp only
  refine bind_intro hel ?_
  try dsimp only
  refine get_intro hinp ?_
  refine get_intro hres ?_
  try dsimp only
  refine bind_intro (forIn_count _ _ fun t ht => ?_) ?_
  · obtain ⟨kase, kl, hrd, hok⟩ := hcases t ht
    try dsimp only
    refine bind_intro hrd ?_
    try dsimp only
    refine need_intro hok ?_
    rfl
  try dsimp only
  refine bind_intro hrow ?_
  try dsimp only
  refine need_intro h1 ?_
  refine need_intro h2 ?_
  refine need_intro h3 ?_
  refine need_intro h4 ?_
  refine need_intro h5 ?_
  refine need_intro (by simp [h6]) ?_
  refine bind_intro href ?_
  rfl

/-! ## A payment

    One statement for each of the four things Lean's rule can do with a payment the engine decided: answer it as
    another id of a payment already recorded (an alias), record a conflict, record the payment, or reverse one. -/

/-- The key of the request a recorded payment pays: zeros when its receipt names none. -/
def paysOf (scope : Bytes) (k : BlindLedger.Financial.Payment.Receipt) : Bytes :=
  match k.paysActionId with
  | some a => akOf scope (utf8 a)
  | none => zeros 32

/-- The call Lean's rule is asked: at the row's time, at the revision the command record expects. -/
local macro "call_of% " x:ident row:ident cmd:term:max : term =>
  `((⟨StateRow.atMs $row, if CmdRec.exprev $x = 0 then none else some (CmdRec.exprev $x - 1), $cmd⟩ : Call))

section Payment

variable {st : Chk} {rec : Nat → Option Bytes} {n i j k : Nat} {x : CmdRec} {xl rl : Link} {e : Bytes}
  {row : StateRow} {o : Entry} {post : FinancialInput} {res : FinancialResult}

/-- An alias: no fact; the row stands on the fact of the payment Lean names and keeps the revision. -/
theorem checkOne_alias {r : BlindLedger.Financial.Payment.RecordCommand} {pid : String}
    {w : BlindLedger.Financial.EvidenceRecord} (h : Start st rec i x xl) (hk : x.ckind = 5)
    (hcash : peek rec (i + 1) 15 cashC.dec = none)
    (hel : element rec n (i + 1) xl.count = .ok (e, j)) (hnt : (x.nt == j - (i + 1)) = true)
    (hcmd : readCommand e = some (.record r, [])) (hmark : peek rec j 0x50 markC.dec = none)
    (hrow : read rec j stateC.dec "state row" = .ok (row, rl)) (ho : st.obl[row.ob]? = some o)
    (hl : rl = ⟨o.head + 1, nextCount o.headCount⟩)
    (hout : o.led.outcome (call_of% x row (.record r)) = .alias pid w post) (hmk : row.mkind = 17)
    (hres : evaluate post = some res) (hfact : o.cash.lookup pid = some k)
    (hok : (stateAgree res 0 { row with rev := res.afterRevision } && row.rev == post.beforeRevision) = true)
    (hlg : (!o.noClass || x.lg == 2) = true)
    (hcid : (x.cid == cidFor (scopeOfCtx o.led.input.context) 5 r.paymentId.toUTF8.toList) = true)
    (hrq : (x.rqd == rqdOf (canon (aliasIdentityReq (scopeOfCtx o.led.input.context) o.led.input.context.itemId r
      (paidBy o.led r.commonOriginId)))) = true)
    (hresult : (x.result == j + 1) = true)
    (hlinks : rowLinks x row i k o.fact o.caseRef
      (BlindLedger.Financial.Payment.step o.led (call_of% x row (.record r))).input = true) :
    checkOne st rec n i = .ok
      ({ st with
          cids := st.cids.insert x.cid, cmdPrev := i + 1, cmdCount := xl.count, lastMs := x.atMs,
          obl := st.obl.insert row.ob
            { o with
              led := BlindLedger.Financial.Payment.step o.led (call_of% x row (.record r)),
              head := j, headCount := rl.count, noClass := x.lg == 2 } }, j + 1) := by
  start_cmd h
  simp only [hk, hcash, Option.isSome_none, Bool.false_eq_true, ↓reduceIte]
  refine bind_intro hel ?_
  try dsimp only
  refine need_intro hnt ?_
  refine get_intro hcmd ?_
  try dsimp only
  refine need_intro rfl ?_
  simp only [hmark, Option.isSome_none, Bool.false_eq_true, ↓reduceIte]
  refine bind_intro hrow ?_
  try dsimp only
  refine get_intro ho ?_
  try dsimp only
  refine need_intro (by simp [hl]) ?_
  simp only [hout, hmk]
  refine get_intro hres ?_
  refine get_intro hfact ?_
  refine bind_intro (x := pure _) rfl ?_
  try dsimp only
  refine need_intro
    (band_intro (band_intro (band_intro (band_intro (band_intro (band_intro hok hlg) rfl) hcid) hrq) hresult)
      hlinks) ?_
  rfl

/-- A conflict: the command's text, a quarantine marker that continues the obligation's facts, then the row, which
    stands on the marker. -/
theorem checkOne_conflict {r : BlindLedger.Financial.Payment.RecordCommand} {m : MarkRec} {ml : Link}
    {w : BlindLedger.Financial.Payment.Writes} (h : Start st rec i x xl) (hk : x.ckind = 5)
    (hcash : peek rec (i + 1) 15 cashC.dec = none)
    (hel : element rec n (i + 1) xl.count = .ok (e, j)) (hnt : (x.nt == j - (i + 1)) = true)
    (hcmd : readCommand e = some (.record r, [])) (hmark : peek rec j 0x50 markC.dec = some (m, ml))
    (hrow : read rec (j + 1) stateC.dec "state row" = .ok (row, rl)) (ho : st.obl[row.ob]? = some o)
    (hl : rl = ⟨o.head + 1, nextCount o.headCount⟩) (hml : ml = ⟨o.fact + 1, nextCount o.factCount⟩)
    (hout : o.led.outcome (call_of% x row (.record r)) = .mutated .CONFLICT_RECORDED w post res)
    (hmk : row.mkind = 16)
    (hok : (stateAgree res 0 row && m.src == stepSource && m.fkind == 15 &&
      m.subject == obOf (scopeOfCtx o.led.input.context) (utf8 o.led.input.context.itemId) && m.receipt == 0 &&
      m.roff == 0 && m.cause == originConflict && m.sidk == 1 &&
      m.sid == sidOf 15 [obOf (scopeOfCtx o.led.input.context) (utf8 o.led.input.context.itemId),
        utf8 r.commonOriginId]) = true)
    (hlg : (!o.noClass || x.lg == 2) = true)
    (hcid : (x.cid == cidFor (scopeOfCtx o.led.input.context) 5 r.paymentId.toUTF8.toList) = true)
    (hrq : (x.rqd == rqdOf (canon (paymentReq (scopeOfCtx o.led.input.context) o.led.input.context.itemId r none
      none))) = true)
    (hresult : (x.result == j + 1 + 1) = true)
    (hlinks : rowLinks x row i j j o.caseRef
      (BlindLedger.Financial.Payment.step o.led (call_of% x row (.record r))).input = true)
    (href : afterRef rec n (j + 1) rl.count res = .ok k) :
    checkOne st rec n i = .ok
      ({ st with
          cids := st.cids.insert x.cid, cmdPrev := i + 1, cmdCount := xl.count, lastMs := x.atMs,
          obl := st.obl.insert row.ob
            { o with
              led := BlindLedger.Financial.Payment.step o.led (call_of% x row (.record r)),
              head := j + 1, headCount := rl.count, fact := j, factCount := nextCount o.factCount,
              noClass := x.lg == 2 } }, k) := by
  start_cmd h
  simp only [hk, hcash, Option.isSome_none, Bool.false_eq_true, ↓reduceIte]
  refine bind_intro hel ?_
  try dsimp only
  refine need_intro hnt ?_
  refine get_intro hcmd ?_
  try dsimp only
  refine need_intro rfl ?_
  simp only [hmark, Option.isSome_some, ↓reduceIte]
  refine bind_intro hrow ?_
  try dsimp only
  refine get_intro ho ?_
  try dsimp only
  refine need_intro (by simp [hl, hml]) ?_
  simp only [hout, hmk]
  refine bind_intro rfl ?_
  try dsimp only
  refine need_intro
    (band_intro (band_intro (band_intro (band_intro (band_intro (band_intro hok hlg) rfl) hcid) hrq) hresult)
      hlinks) ?_
  refine bind_intro href ?_
  rfl

/-- A recorded payment: a CASH fact that continues the obligation's facts, the command's text, then the row, which
    stands on the fact. -/
theorem checkOne_recorded {r : BlindLedger.Financial.Payment.RecordCommand} {f : CashF} {cl : Link}
    {w : BlindLedger.Financial.Payment.Writes} {p : BlindLedger.Financial.Payment}
    {rc : BlindLedger.Financial.Payment.Receipt} (h : Start st rec i x xl) (hk : x.ckind = 5)
    (hcash : peek rec (i + 1) 15 cashC.dec = some (f, cl))
    (hel : element rec n (i + 2) cl.count = .ok (e, j)) (hnt : (x.nt == 0) = true)
    (hcmd : readCommand e = some (.record r, [])) (hmark : peek rec j 0x50 markC.dec = none)
    (hrow : read rec j stateC.dec "state row" = .ok (row, rl)) (ho : st.obl[row.ob]? = some o)
    (hl : rl = ⟨o.head + 1, nextCount o.headCount⟩) (hcl : cl = ⟨o.fact + 1, nextCount o.factCount⟩)
    (hfix : hdrFixed f.h = true)
    (hout : o.led.outcome (call_of% x row (.record r)) = .mutated .RECORDED w post res) (hmk : row.mkind = 14)
    (hp : w.payment = some p) (hrc : w.receipt = some rc)
    (hok : (cashAgree post.context p f && f.pays == paysOf (scopeOfCtx o.led.input.context) rc && f.ecls == 0 &&
      stateAgree res p.amountCents row) = true)
    (hlg : (!o.noClass || x.lg == 2) = true)
    (hcid : (x.cid == cidFor (scopeOfCtx o.led.input.context) 5 r.paymentId.toUTF8.toList) = true)
    (hrq : (x.rqd == rqdOf (canon (paymentIdentityReq (scopeOfCtx o.led.input.context)
      o.led.input.context.itemId r rc))) = true)
    (hresult : (x.result == j + 1) = true)
    (hlinks : rowLinks x row i (i + 1) (i + 1) o.caseRef
      (BlindLedger.Financial.Payment.step o.led (call_of% x row (.record r))).input = true)
    (href : afterRef rec n j rl.count res = .ok k) :
    checkOne st rec n i = .ok
      ({ st with
          cids := st.cids.insert x.cid, cmdPrev := i + 1, cmdCount := xl.count, lastMs := x.atMs,
          obl := st.obl.insert row.ob
            { o with
              led := BlindLedger.Financial.Payment.step o.led (call_of% x row (.record r)),
              head := j, headCount := rl.count, fact := i + 1, factCount := nextCount o.factCount,
              cash := (p.paymentId, i + 1) :: o.cash, noClass := x.lg == 2 } }, k) := by
  start_cmd h
  simp only [hk, hcash, Option.isSome_some, ↓reduceIte]
  refine bind_intro hel ?_
  try dsimp only
  refine need_intro hnt ?_
  refine get_intro hcmd ?_
  try dsimp only
  refine need_intro rfl ?_
  simp only [hmark, Option.isSome_none, Bool.false_eq_true, ↓reduceIte]
  refine bind_intro hrow ?_
  try dsimp only
  refine get_intro ho ?_
  try dsimp only
  refine need_intro (by simp [hl, hcl, hfix]) ?_
  simp only [hout, hmk]
  refine get_intro hp ?_
  refine get_intro hrc ?_
  refine bind_intro (x := pure _) rfl ?_
  try dsimp only
  refine need_intro
    (band_intro (band_intro (band_intro (band_intro (band_intro (band_intro hok hlg) rfl) hcid) hrq) hresult)
      hlinks) ?_
  refine bind_intro href ?_
  rfl

/-- A reversal: a void row that continues the obligation's facts, the command's text, then the row, which stands
    on the void row. -/
theorem checkOne_reversed {r : ReverseCommand} {f : CashF} {cl : Link} {w : BlindLedger.Financial.Payment.Writes}
    {p : BlindLedger.Financial.Payment} {ev : BlindLedger.Financial.EvidenceRecord} (h : Start st rec i x xl)
    (hk : x.ckind = 6) (hcash : peek rec (i + 1) 15 cashC.dec = some (f, cl))
    (hel : element rec n (i + 2) cl.count = .ok (e, j)) (hnt : (x.nt == 0) = true)
    (hcmd : readCommand e = some (.reverse r, [])) (hmark : peek rec j 0x50 markC.dec = none)
    (hrow : read rec j stateC.dec "state row" = .ok (row, rl)) (ho : st.obl[row.ob]? = some o)
    (hl : rl = ⟨o.head + 1, nextCount o.headCount⟩) (hcl : cl = ⟨o.fact + 1, nextCount o.factCount⟩)
    (hfix : hdrFixed f.h = true)
    (hout : o.led.outcome (call_of% x row (.reverse r)) = .mutated .REVERSED w post res) (hmk : row.mkind = 15)
    (hp : w.payment = some p) (hev : w.evidence = some ev)
    (hok : (cashVoidAgree post.context p ev f && f.pays == zeros 32 && f.ecls == 0 &&
      stateAgree res p.amountCents row) = true)
    (hlg : (!o.noClass || x.lg == 2) = true)
    (hcid : (x.cid == cidFor (scopeOfCtx o.led.input.context) 6 r.evidenceId.toUTF8.toList) = true)
    (hrq : (x.rqd == rqdOf (canon (reversalReq (scopeOfCtx o.led.input.context) o.led.input.context.itemId o.led r
      row.atMs))) = true)
    (hresult : (x.result == j + 1) = true)
    (hlinks : rowLinks x row i (i + 1) (i + 1) o.caseRef
      (BlindLedger.Financial.Payment.step o.led (call_of% x row (.reverse r))).input = true)
    (href : afterRef rec n j rl.count res = .ok k) :
    checkOne st rec n i = .ok
      ({ st with
          cids := st.cids.insert x.cid, cmdPrev := i + 1, cmdCount := xl.count, lastMs := x.atMs,
          obl := st.obl.insert row.ob
            { o with
              led := BlindLedger.Financial.Payment.step o.led (call_of% x row (.reverse r)),
              head := j, headCount := rl.count, fact := i + 1, factCount := nextCount o.factCount,
              cash := (p.paymentId, i + 1) :: o.cash, noClass := x.lg == 2 } }, k) := by
  start_cmd h
  simp only [hk, hcash, Option.isSome_some, ↓reduceIte]
  refine bind_intro hel ?_
  try dsimp only
  refine need_intro hnt ?_
  refine get_intro hcmd ?_
  try dsimp only
  refine need_intro rfl ?_
  simp only [hmark, Option.isSome_none, Bool.false_eq_true, ↓reduceIte]
  refine bind_intro hrow ?_
  try dsimp only
  refine get_intro ho ?_
  try dsimp only
  refine need_intro (by simp [hl, hcl, hfix]) ?_
  simp only [hout, hmk]
  refine get_intro hp ?_
  refine get_intro hev ?_
  refine bind_intro (x := pure _) rfl ?_
  try dsimp only
  refine need_intro
    (band_intro (band_intro (band_intro (band_intro (band_intro (band_intro hok hlg) rfl) hcid) hrq) hresult)
      hlinks) ?_
  refine bind_intro href ?_
  rfl

end Payment

end BlindLedger.Gate.Obligations
