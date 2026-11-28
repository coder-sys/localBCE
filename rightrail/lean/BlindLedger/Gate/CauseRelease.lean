import BlindLedger.Gate.Authority
import BlindLedger.Gate.Rules.Bypass
import BlindLedger.Gate.AuthorityLaws

namespace BlindLedger.Gate.CauseRelease

open BlindLedger.Gate

/-! Release by cause (Constitution I.2; docs/RIGHTRAIL_FULL_STACK_TARGET.md §6, "Release by cause").  The engine reads
    records with these definitions: `Rules.Run.admit` admits them (`admit`), and `Rules.Run.approvals` judges their listed
    payments (`listed`, `judge`, `pairs`) and merges their pairs with the bypasses' (`merge`).

    The record is `APPROVAL/v2` kind 3, under the grant's and bypass's domain and signature tag; kinds 1 and 2 keep
    their bytes, and each decoder reads only its own kinds (`kinds_disjoint`).  It names one cause, a scope that only
    narrows, and the exact list of held payments it releases: each by payment id, the digest of the request bytes it
    was held under, and its amount.  Two approvers of distinct employees and distinct identity-provider subjects sign
    it, the bypass's quorum.

    At the rules, an admitted record is what a bypass is: a (payment number, override mask) pair in `Rules.Ctx.byp`,
    here with the single bit of its cause.  So `Rules.bypassed` decides the release, and what is proved of it holds of
    cause releases too: `Rules.fail_closed_unless_bypass`, `Rules.bypass_no_window`, `Rules.bypass_once`.  A payment
    named by two approvals of one batch is in no pair (`merge`), so it stays held. -/

def kindByte : Nat := 3

/-- Entries a record may list.  A record rides every batch that carries one of its payments, so its size is bounded. -/
def maxEntries : Nat := 4096

structure Entry where
  payment : Bytes
  /-- SHA3-512 of the exact `DECIDE-REQUEST` bytes the payment was held under. -/
  request : Bytes
  amount : Nat
  deriving DecidableEq

structure Doc where
  state : Bytes
  tenantId : Bytes
  notBefore : Nat
  notAfter : Nat
  cause : Rules.Reason
  program : Bytes
  flows : Nat
  dateFrom : Nat
  dateTo : Nat
  /-- The sum of the entries' amounts, exactly. -/
  total : Nat
  entries : List Entry
  deriving DecidableEq

structure Frame where
  a : Doc
  sigs : List Keyset.SigRec
  deriving DecidableEq

/-! ### Bytes -/

def encEntry (e : Entry) : Bytes := identField e.payment ++ e.request ++ natBE 8 e.amount

def encDoc (a : Doc) : Bytes :=
  Authority.tag ++ natBE 1 kindByte ++ a.state ++ identField a.tenantId ++ natBE 4 a.notBefore ++ natBE 4 a.notAfter ++
    natBE 1 a.cause.idx ++ identField a.program ++ natBE 1 a.flows ++ natBE 4 a.dateFrom ++ natBE 4 a.dateTo ++
    natBE 8 a.total ++ natBE 2 a.entries.length ++ a.entries.flatMap encEntry

def Frame.unsigned (f : Frame) : Bytes := encDoc f.a
def encode (f : Frame) : Bytes := f.unsigned ++ Keyset.encodeSigs f.sigs
/-- What the signers sign: the grant's and bypass's signature tag over the unsigned bytes. -/
def msgOf (f : Frame) : Bytes := sha3 (Authority.sigTag ++ f.unsigned)

/-- The reason with this fixed bit number (`Rules.Reason.idx`, dense from 0). -/
def reasonOf (i : Nat) : Option Rules.Reason := Rules.reasons.find? (·.idx == i)

/-- Payment ids strictly ascending in byte order: each payment once, one encoding per list. -/
def ascendingPay : List Entry → Bool
  | a :: b :: rest => lexLt a.payment b.payment && ascendingPay (b :: rest)
  | _ => true

def pEntry : P Entry := do
  let payment ← ident
  let request ← digest
  let amount ← nat 8
  pure ⟨payment, request, amount⟩

def pDoc : P Doc := do
  expect Authority.tag
  let _ ← nat 1 kindByte kindByte
  let state ← digest
  let tenantId ← ident
  let notBefore ← nat 4
  let notAfter ← nat 4
  need (Authority.spanOk notBefore notAfter)
  let ci ← nat 1
  let some cause := reasonOf ci | fail
  let program ← ident
  let flows ← nat 1 1 31
  let dateFrom ← nat 4
  let dateTo ← nat 4
  need (Rules.validDate dateFrom && Rules.validDate dateTo && dateFrom ≤ dateTo)
  let total ← nat 8
  let n ← nat 2 1 maxEntries
  let entries ← many pEntry n
  need (ascendingPay entries && total == (entries.map (·.amount)).sum)
  pure { state, tenantId, notBefore, notAfter, cause, program, flows, dateFrom, dateTo, total, entries }

/-- Canonical: the document, then a signature block of 1..16 records, nothing after. -/
def decode (x : Bytes) : Option Frame :=
  match pDoc.run x with
  | some (a, rest) => (Keyset.decodeSigBlock rest).map fun ss => ⟨a, ss⟩
  | none => none

/-! ### Admission -/

/-- An admitted record: only `admit` builds one. -/
structure Release where
  private mk ::
  id : Bytes
  doc : Doc

inductive Refusal | MALFORMED | SCOPE | EXPIRED | REASONS | UNSIGNED deriving DecidableEq, Repr

/-- The record of the batch's state and tenant on the batch's day: in its window, its cause one a bypass may override,
    signed by two approvers of distinct employees and distinct subjects under the batch head's key set. -/
def admit (verify : Bytes → Bytes → Bytes → Bool) (H : SnapshotV2.Head) (tenant : Bytes) (x : Bytes) :
    Except Refusal Release :=
  match decode x with
  | none => .error .MALFORMED
  | some f =>
    if f.a.state != H.ks.state || f.a.tenantId != tenant then .error .SCOPE
    else if !Authority.windowOk f.a.notBefore f.a.notAfter H.day then .error .EXPIRED
    else if !Rules.bypassable f.a.cause then .error .REASONS
    else if !(Keyset.quorum verify (Authority.approverOk H.day) (·.employee) H.ks 2 (msgOf f) f.sigs &&
        Keyset.quorum verify (Authority.approverOk H.day) (·.idp) H.ks 2 (msgOf f) f.sigs) then .error .UNSIGNED
    else .ok ⟨sha3 f.unsigned, f.a⟩

/-- One request of the batch as admission sees it: its payment number (`Rules.payNat`), program and payment ids, the
    digest of its bytes, its flow, amount and its lines' service dates, whether the grant entry covering it has TRANSFER
    authority, and whether the batch decides it again. -/
structure Seen where
  q : Nat
  program : Bytes
  payment : Bytes
  digest : Bytes
  flow : WireFlow
  amount : Nat
  dates : List Nat
  transfer : Bool
  redo : Bool

/-- The entry listing this request's payment, if the record lists it.  Another program's payment is never listed. -/
def listed (a : Doc) (s : Seen) : Option Entry :=
  if a.program == s.program then a.entries.find? (·.payment == s.payment) else none

inductive EntryRefusal | WRONG_REQUEST | AMOUNT | SCOPE | REDO deriving DecidableEq, Repr

/-- A listed payment of the batch: its request is the one listed, for the listed amount, within the scope, under a
    TRANSFER entry, and not decided again.  `DUPLICATE` is `merge`'s; `NOT_HELD` is the rules' (`Rules.bypassed`). -/
def judge (a : Doc) (s : Seen) (e : Entry) : Except EntryRefusal Unit :=
  if e.request != s.digest then .error .WRONG_REQUEST
  else if e.amount != s.amount then .error .AMOUNT
  else if !(Keyset.bit a.flows (s.flow.tag.toNat - 1) && s.dates.all (fun d => a.dateFrom ≤ d && d ≤ a.dateTo) &&
      s.transfer) then .error .SCOPE
  else if s.redo then .error .REDO
  else .ok ()

def fits (a : Doc) (s : Seen) : Bool :=
  match listed a s with
  | some e => match judge a s e with
    | .ok _ => true
    | .error _ => false
  | none => false

/-- The (payment number, override mask) pairs one admitted record gives the batch: one per request it lists that
    `judge` accepts, each with the record's single cause bit. -/
def pairs (r : Release) (ss : List Seen) : List (Nat × Nat) :=
  (ss.filter (fits r.doc)).map fun s => (s.q, 2 ^ r.doc.cause.idx)

/-- `Rules.Ctx.byp` of a batch: the admitted bypasses' pairs and every admitted record's, less every payment named more
    than once (each such naming is refused `DUPLICATE`). -/
def merge (named : List (Nat × Nat)) : List (Nat × Nat) :=
  named.filter fun x => named.countP (·.1 == x.1) == 1

/-- A shard's history with cause releases: each batch's lines, its admitted bypasses' pairs, the records admitted for
    it and its requests as seen. -/
def stepsWith (c : Rules.Ctx) (h : List (List Rules.Line × List (Nat × Nat) × List Release × List Seen)) :
    List Rules.Step :=
  Rules.steps c (h.map fun (b, bp, rs, ss) => (b, merge (bp ++ rs.flatMap (pairs · ss))))

/-! ### Statements: the record -/

theorem maxNat_lt : maxNat < 256 ^ 8 := by unfold maxNat; omega

theorem reasonOf_idx {i : Nat} {r : Rules.Reason} (h : reasonOf i = some r) : r.idx = i := by
  unfold reasonOf at h
  simpa using List.find?_some h

theorem ascendingPay_eq : ∀ es : List Entry, ascendingPay es = ascending (es.map (·.payment))
  | [] => rfl
  | [_] => rfl
  | a :: b :: rest => by
    simp only [ascendingPay, ascending, List.map_cons]
    have := ascendingPay_eq (b :: rest)
    simp only [List.map_cons] at this
    rw [this]

theorem ascendingPay_nodup {es : List Entry} (h : ascendingPay es = true) : (es.map (·.payment)).Nodup := by
  rw [ascendingPay_eq] at h
  exact ascending_nodup _ h

def EntryWf (e : Entry) : Prop :=
  identOk e.payment = true ∧ e.request.length = digestBytes ∧ e.amount < 256 ^ 8

def DocWf (a : Doc) : Prop :=
  a.state.length = digestBytes ∧ identOk a.tenantId = true ∧ Authority.spanOk a.notBefore a.notAfter = true ∧
    reasonOf a.cause.idx = some a.cause ∧ identOk a.program = true ∧ 1 ≤ a.flows ∧ a.flows ≤ 31 ∧
    Rules.validDate a.dateFrom = true ∧ Rules.validDate a.dateTo = true ∧ a.dateFrom ≤ a.dateTo ∧ a.total < 256 ^ 8 ∧
    1 ≤ a.entries.length ∧ a.entries.length ≤ maxEntries ∧ (∀ e ∈ a.entries, EntryWf e) ∧
    ascendingPay a.entries = true ∧ a.total = (a.entries.map (·.amount)).sum

theorem pEntry_inv {b r : Bytes} {e : Entry} (h : pEntry.run b = some (e, r)) : b = encEntry e ++ r ∧ EntryWf e := by
  simp only [pEntry, StateT.run_bind] at h
  obtain ⟨⟨p, m1⟩, h1, h⟩ := bind_some h
  obtain ⟨⟨q, m2⟩, h2, h⟩ := bind_some h
  obtain ⟨⟨am, m3⟩, h3, h⟩ := bind_some h
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  dsimp only at *
  obtain ⟨e1, i1⟩ := ident_inv h1
  obtain ⟨e2, l2⟩ := take_inv h2
  obtain ⟨e3, -, a2⟩ := nat_inv h3
  subst e1 e2 e3
  refine ⟨by simp [encEntry, Authority.identField_eq, List.append_assoc], i1, l2, ?_⟩
  have := maxNat_lt
  show am < 256 ^ 8
  omega

theorem pDoc_inv {b r : Bytes} {a : Doc} (h : pDoc.run b = some (a, r)) : b = encDoc a ++ r ∧ DocWf a := by
  simp only [pDoc, StateT.run_bind] at h
  obtain ⟨⟨u0, m0⟩, h0, h⟩ := bind_some h
  obtain ⟨⟨k, m1⟩, h1, h⟩ := bind_some h
  obtain ⟨⟨st, m2⟩, h2, h⟩ := bind_some h
  obtain ⟨⟨tn, m3⟩, h3, h⟩ := bind_some h
  obtain ⟨⟨nb, m4⟩, h4, h⟩ := bind_some h
  obtain ⟨⟨na, m5⟩, h5, h⟩ := bind_some h
  obtain ⟨⟨u6, m6⟩, h6, h⟩ := bind_some h
  obtain ⟨⟨ci, m7⟩, h7, h⟩ := bind_some h
  rcases hc : reasonOf ci with _ | cause
  · simp only [hc] at h
    change (none : Option (Doc × Bytes)) = some (a, r) at h
    cases h
  · simp only [hc, StateT.run_bind] at h
    obtain ⟨⟨pg, m8⟩, h8, h⟩ := bind_some h
    obtain ⟨⟨fl, m9⟩, h9, h⟩ := bind_some h
    obtain ⟨⟨df, m10⟩, h10, h⟩ := bind_some h
    obtain ⟨⟨dt, m11⟩, h11, h⟩ := bind_some h
    obtain ⟨⟨u12, m12⟩, h12, h⟩ := bind_some h
    obtain ⟨⟨tot, m13⟩, h13, h⟩ := bind_some h
    obtain ⟨⟨n, m14⟩, h14, h⟩ := bind_some h
    obtain ⟨⟨es, m15⟩, h15, h⟩ := bind_some h
    obtain ⟨⟨u16, m16⟩, h16, h⟩ := bind_some h
    simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    dsimp only at *
    have e0 := expect_run h0
    obtain ⟨e1, k1, k2⟩ := nat_inv h1
    obtain ⟨e2, l2⟩ := take_inv h2
    obtain ⟨e3, i3⟩ := ident_inv h3
    obtain ⟨e4, -⟩ := nat_inv h4
    obtain ⟨e5, -⟩ := nat_inv h5
    have e6 := need_rest h6
    have ok6 := need_ok h6
    obtain ⟨e7, -⟩ := nat_inv h7
    obtain ⟨e8, i8⟩ := ident_inv h8
    obtain ⟨e9, f1, f2⟩ := nat_inv h9
    obtain ⟨e10, -⟩ := nat_inv h10
    obtain ⟨e11, -⟩ := nat_inv h11
    have e12 := need_rest h12
    have ok12 := need_ok h12
    obtain ⟨e13, -, t2⟩ := nat_inv h13
    obtain ⟨e14, n1, n2⟩ := nat_inv h14
    obtain ⟨e15, hl, hq⟩ := ParseLaws.many_run (e := encEntry) (Q := EntryWf)
      (fun h => ⟨((pEntry_inv h).1).symm, (pEntry_inv h).2⟩) n h15
    have e16 := need_rest h16
    have ok16 := need_ok h16
    have hci := reasonOf_idx hc
    have hk : k = kindByte := Nat.le_antisymm k2 k1
    subst e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 e10 e11 e12 e13 e14 e16 hl hci hk
    have hm := maxNat_lt
    simp only [Bool.and_eq_true, decide_eq_true_eq] at ok12 ok16
    obtain ⟨⟨ok12a, ok12b⟩, ok12c⟩ := ok12
    refine ⟨?_, l2, i3, ok6, hc, i8, f1, f2, ok12a, ok12b, ok12c, (by show tot < 256 ^ 8; omega), n1, n2, hq, ok16.1, ?_⟩
    · rw [← e15]; simp [encDoc, kindByte, Authority.identField_eq, List.append_assoc]
    · simpa using ok16.2

theorem authDecode_pDoc {x : Bytes} {g : Authority.Frame} (h : Authority.decode x = some g) :
    ∃ rest, Authority.pDoc.run x = some (g.a, rest) := by
  unfold Authority.decode at h
  rcases hp : Authority.pDoc.run x with _ | ⟨a, rest⟩
  · simp [hp] at h
  · simp only [hp] at h
    rcases hs : Keyset.decodeSigBlock rest with _ | ss
    · simp [hs] at h
    · simp only [hs, Option.map_some, Option.some.injEq] at h
      subst h
      exact ⟨rest, rfl⟩

theorem decode_spec {x : Bytes} {f : Frame} (h : decode x = some f) :
    ∃ rest, pDoc.run x = some (f.a, rest) ∧ Keyset.decodeSigBlock rest = some f.sigs := by
  unfold decode at h
  rcases hp : pDoc.run x with _ | ⟨a, rest⟩
  · simp [hp] at h
  · simp only [hp] at h
    rcases hs : Keyset.decodeSigBlock rest with _ | ss
    · simp [hs] at h
    · simp only [hs, Option.map_some, Option.some.injEq] at h
      subst h
      exact ⟨rest, rfl, hs⟩

/-- Canonical bytes: a decoded record re-encodes to exactly its input, so its id names one byte string. -/
theorem encode_decode {x : Bytes} {f : Frame} (h : decode x = some f) : encode f = x := by
  obtain ⟨rest, hp, hs⟩ := decode_spec h
  have e := (pDoc_inv hp).1
  rw [(Keyset.decodeSigBlock_spec hs).1] at e
  simpa [encode, Frame.unsigned] using e.symm

/-- A cause record is never read as a grant or a bypass, and a grant or bypass is never read as a cause record. -/
theorem kinds_disjoint (x : Bytes) : decode x = none ∨ Authority.decode x = none := by
  by_cases h1 : decode x = none
  · exact Or.inl h1
  · right
    rcases hg : Authority.decode x with _ | g
    · rfl
    exfalso
    obtain ⟨f, hf⟩ := Option.ne_none_iff_exists'.mp h1
    obtain ⟨r1, hp1, -⟩ := decode_spec hf
    obtain ⟨r2, hp2⟩ := authDecode_pDoc hg
    have e := (pDoc_inv hp1).1.symm.trans (Authority.pDoc_inv hp2).1
    obtain ⟨⟨st, tn, nb, na, body⟩, sg⟩ := g
    cases body <;>
      simp [encDoc, Authority.encDoc, Authority.kindByte, kindByte, List.append_assoc, natBE] at e

/-- A decoded record lists 1 to `maxEntries` payments, each once, and its total is their sum. -/
theorem decode_list {x : Bytes} {f : Frame} (h : decode x = some f) :
    1 ≤ f.a.entries.length ∧ f.a.entries.length ≤ maxEntries ∧ (f.a.entries.map (·.payment)).Nodup ∧
      f.a.total = (f.a.entries.map (·.amount)).sum := by
  obtain ⟨rest, hp, -⟩ := decode_spec h
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, h1, h2, -, h3, h4⟩ := (pDoc_inv hp).2
  exact ⟨h1, h2, ascendingPay_nodup h3, h4⟩

/-- Admission reads back its checks: the bytes decode, the record is of the batch's state and tenant and in its window,
    its cause is one a bypass may override, and two approvers of distinct employees and two of distinct
    identity-provider subjects signed it. -/
theorem admit_sound {verify : Bytes → Bytes → Bytes → Bool} {H : SnapshotV2.Head} {tenant x : Bytes} {r : Release}
    (h : admit verify H tenant x = .ok r) :
    ∃ f, decode x = some f ∧ r.doc = f.a ∧ r.id = sha3 f.unsigned ∧ f.a.state = H.ks.state ∧ f.a.tenantId = tenant ∧
      Authority.windowOk f.a.notBefore f.a.notAfter H.day = true ∧ Rules.bypassable f.a.cause = true ∧
      Keyset.quorum verify (Authority.approverOk H.day) (·.employee) H.ks 2 (msgOf f) f.sigs = true ∧
      Keyset.quorum verify (Authority.approverOk H.day) (·.idp) H.ks 2 (msgOf f) f.sigs = true := by
  unfold admit at h
  rcases hd : decode x with _ | f
  · simp [hd] at h
  · simp only [hd] at h
    split at h
    · cases h
    rename_i h1
    split at h
    · cases h
    rename_i h2
    split at h
    · cases h
    rename_i h3
    split at h
    · cases h
    rename_i h4
    cases h
    have h1' : f.a.state = H.ks.state ∧ f.a.tenantId = tenant := by simpa using h1
    have h2' : Authority.windowOk f.a.notBefore f.a.notAfter H.day = true := by simpa using h2
    have h3' : Rules.bypassable f.a.cause = true := by simpa using h3
    have h4' : (Keyset.quorum verify (Authority.approverOk H.day) (·.employee) H.ks 2 (msgOf f) f.sigs &&
        Keyset.quorum verify (Authority.approverOk H.day) (·.idp) H.ks 2 (msgOf f) f.sigs) = true := by
      simpa using h4
    exact ⟨f, rfl, rfl, rfl, h1'.1, h1'.2, h2', h3', (Bool.and_eq_true _ _).mp h4' |>.1, (Bool.and_eq_true _ _).mp h4' |>.2⟩

theorem fits_spec {a : Doc} {s : Seen} (h : fits a s = true) :
    ∃ e ∈ a.entries, a.program = s.program ∧ e.payment = s.payment ∧ e.request = s.digest ∧ e.amount = s.amount ∧
      Keyset.bit a.flows (s.flow.tag.toNat - 1) = true ∧ (∀ d ∈ s.dates, a.dateFrom ≤ d ∧ d ≤ a.dateTo) ∧
      s.transfer = true ∧ s.redo = false := by
  unfold fits at h
  rcases hl : listed a s with _ | e
  · simp [hl] at h
  · simp only [hl] at h
    rcases hj : judge a s e with _ | u
    · simp [hj] at h
    · unfold listed at hl
      split at hl
      · rename_i hp
        have he := List.find?_some hl
        have hm := List.mem_of_find?_eq_some hl
        unfold judge at hj
        split at hj
        · cases hj
        rename_i h1
        split at hj
        · cases hj
        rename_i h2
        split at hj
        · cases hj
        rename_i h3
        split at hj
        · cases hj
        rename_i h4
        have h1' : e.request = s.digest := by simpa using h1
        have h2' : e.amount = s.amount := by simpa using h2
        have h3' : (Keyset.bit a.flows (s.flow.tag.toNat - 1) && s.dates.all (fun d => a.dateFrom ≤ d && d ≤ a.dateTo) &&
            s.transfer) = true := by simpa using h3
        have h4' : s.redo = false := by simpa using h4
        simp only [Bool.and_eq_true, List.all_eq_true, decide_eq_true_eq] at h3'
        simp only [beq_iff_eq] at hp he
        exact ⟨e, hm, hp, he, h1', h2', h3'.1.1, h3'.1.2, h3'.2, h4'⟩
      · simp at hl

/-- Every pair a record gives is a payment of the batch that it lists, whose request bytes hash to the listed digest,
    for the listed amount, in scope, under a TRANSFER entry, not decided again; and its mask is the cause bit alone. -/
theorem pairs_listed {r : Release} {ss : List Seen} {p m : Nat} (h : (p, m) ∈ pairs r ss) :
    m = 2 ^ r.doc.cause.idx ∧ ∃ s ∈ ss, s.q = p ∧ s.program = r.doc.program ∧
      ∃ e ∈ r.doc.entries, e.payment = s.payment ∧ e.request = s.digest ∧ e.amount = s.amount ∧
        Keyset.bit r.doc.flows (s.flow.tag.toNat - 1) = true ∧ (∀ d ∈ s.dates, r.doc.dateFrom ≤ d ∧ d ≤ r.doc.dateTo) ∧
        s.transfer = true ∧ s.redo = false := by
  unfold pairs at h
  obtain ⟨s, hs, he⟩ := List.mem_map.mp h
  obtain ⟨hs1, hs2⟩ := List.mem_filter.mp hs
  simp only [Prod.mk.injEq] at he
  obtain ⟨e, he1, hp, ep, er, ea, b, ds, t, rd⟩ := fits_spec hs2
  exact ⟨he.2.symm, s, hs1, he.1, hp.symm, e, he1, ep, er, ea, b, ds, t, rd⟩

theorem nodup_of_map {α β : Type} (f : α → β) : ∀ {l : List α}, (l.map f).Nodup → l.Nodup
  | [], _ => List.nodup_nil
  | a :: l, h => by
    rw [List.map_cons, List.nodup_cons] at h
    exact List.nodup_cons.mpr ⟨fun ha => h.1 (List.mem_map_of_mem ha), nodup_of_map f h.2⟩

theorem sum_le_entries : ∀ (L : List Seen) (E : List Entry), (L.map (·.payment)).Nodup → (E.map (·.payment)).Nodup →
    (∀ s ∈ L, ∃ e ∈ E, e.payment = s.payment ∧ e.amount = s.amount) →
    (L.map (·.amount)).sum ≤ (E.map (·.amount)).sum
  | [], E, _, _, _ => by simp
  | s :: L, E, hL, hE, hsub => by
    obtain ⟨e, he, hep, hea⟩ := hsub s (List.mem_cons_self ..)
    have hEnd : E.Nodup := nodup_of_map _ hE
    have hL' : (L.map (·.payment)).Nodup := (List.nodup_cons.mp (by simpa using hL)).2
    have hsn : s.payment ∉ L.map (·.payment) := (List.nodup_cons.mp (by simpa using hL)).1
    have hE' : ((E.erase e).map (·.payment)).Nodup :=
      List.Nodup.sublist ((List.erase_sublist).map _) hE
    have ih := sum_le_entries L (E.erase e) hL' hE' (fun s' hs' => by
      obtain ⟨e', he', hep', hea'⟩ := hsub s' (List.mem_cons_of_mem _ hs')
      refine ⟨e', (List.Nodup.mem_erase_iff hEnd).mpr ⟨?_, he'⟩, hep', hea'⟩
      intro hee
      subst hee
      exact hsn (hep ▸ hep' ▸ List.mem_map_of_mem hs'))
    have hperm := ((List.perm_cons_erase he).map (·.amount)).sum_nat
    simp only [List.map_cons, List.sum_cons] at hperm ⊢
    omega

/-- The cap: in a batch carrying each payment once, the amounts a record releases sum to at most its total.  Across
    batches each payment is released at most once (`release_once`), so the bound holds for the record's whole life. -/
theorem fits_within_total {verify : Bytes → Bytes → Bytes → Bool} {H : SnapshotV2.Head} {tenant x : Bytes}
    {r : Release} (h : admit verify H tenant x = .ok r) (ss : List Seen)
    (hnd : (ss.map fun s => (s.program, s.payment)).Nodup) :
    ((ss.filter (fits r.doc)).map (·.amount)).sum ≤ r.doc.total := by
  obtain ⟨f, hd, hr, -⟩ := admit_sound h
  obtain ⟨-, -, hnodup, htot⟩ := decode_list hd
  rw [hr, htot]
  have hmem : ∀ s ∈ ss.filter (fits f.a), ∃ e ∈ f.a.entries, e.payment = s.payment ∧ e.amount = s.amount ∧
      f.a.program = s.program := by
    intro s hs
    obtain ⟨e, he, hp, ep, -, ea, -⟩ := fits_spec (List.mem_filter.mp hs).2
    exact ⟨e, he, ep, ea, hp⟩
  have hLnd : ((ss.filter (fits f.a)).map (·.payment)).Nodup := by
    have h1 : ((ss.filter (fits f.a)).map fun s => (s.program, s.payment)).Nodup :=
      List.Nodup.sublist ((List.filter_sublist).map _) hnd
    have h2 : ((ss.filter (fits f.a)).map fun s => (s.program, s.payment)) =
        ((ss.filter (fits f.a)).map (·.payment)).map (fun p => (f.a.program, p)) := by
      rw [List.map_map]
      apply List.map_congr_left
      intro s hs
      obtain ⟨-, -, -, -, hp⟩ := hmem s hs
      simp [Function.comp, hp]
    rw [h2] at h1
    exact nodup_of_map _ h1
  exact sum_le_entries _ _ hLnd hnodup (fun s hs => let ⟨e, he, a, b, _⟩ := hmem s hs; ⟨e, he, a, b⟩)

/-- After `merge` a payment has at most one pair, so the rules never pick between two approvals. -/
theorem mem_merge {named : List (Nat × Nat)} {p m : Nat} :
    (p, m) ∈ merge named ↔ (p, m) ∈ named ∧ named.countP (·.1 == p) = 1 := by
  simp [merge, List.mem_filter]

/-! ### Statements: what the rules release -/

theorem mem_of_lookup : ∀ {L : List (Nat × Nat)} {p m : Nat}, L.lookup p = some m → (p, m) ∈ L
  | [], _, _, h => by simp [List.lookup] at h
  | (a, b) :: L, p, m, h => by
    simp only [List.lookup] at h
    split at h
    · rename_i hh
      cases h
      have : p = a := by simpa using hh
      subst this
      simp
    · exact List.mem_cons_of_mem _ (mem_of_lookup h)

theorem lookup_of_unique : ∀ {L : List (Nat × Nat)} {p m : Nat}, (p, m) ∈ L → L.countP (·.1 == p) = 1 →
    L.lookup p = some m
  | [], _, _, h, _ => by simp at h
  | (a, b) :: L, p, m, h, hc => by
    by_cases hap : a = p
    · subst hap
      rcases List.mem_cons.mp h with h | h
      · cases h; simp [List.lookup]
      · exfalso
        have h1 : 0 < L.countP (·.1 == a) := List.countP_pos_iff.mpr ⟨(a, m), h, by simp⟩
        rw [List.countP_cons_of_pos (by simp)] at hc
        omega
    · have hm : (p, m) ∈ L := by
        rcases List.mem_cons.mp h with h | h
        · cases h; exact absurd rfl hap
        · exact h
      have hc' : L.countP (·.1 == p) = 1 := by
        simpa [List.countP_cons, hap] using hc
      have := lookup_of_unique hm hc'
      simp only [List.lookup, beq_false_of_ne (Ne.symm hap)]
      exact this

theorem bit_pow {i j : Nat} (h : Keyset.bit (2 ^ i) j = true) : i = j := by
  unfold Keyset.bit at h
  simp only [beq_iff_eq] at h
  rw [Nat.shiftRight_eq_div_pow] at h
  by_cases hij : i < j
  · have : 2 ^ i / 2 ^ j = 0 := Nat.div_eq_of_lt (Nat.pow_lt_pow_right (by omega) hij)
    omega
  · have h2 : 2 ^ i = 2 ^ j * 2 ^ (i - j) := by rw [← Nat.pow_add]; congr 1; omega
    rw [h2, Nat.mul_div_cancel_left _ (Nat.two_pow_pos j)] at h
    by_cases h' : i = j
    · exact h'
    · obtain ⟨k, hk⟩ : ∃ k, i - j = k + 1 := ⟨i - j - 1, by omega⟩
      rw [hk, Nat.pow_succ] at h
      omega

theorem bit_self (i : Nat) : Keyset.bit (2 ^ i) i = true := by
  unfold Keyset.bit
  simp [Nat.shiftRight_eq_div_pow, Nat.div_self (Nat.two_pow_pos i)]

/-- Only the listed payments, only when held here, and only for the one cause: with the batch's pairs all from one
    record, a released line of a payment the rules did not allow, and not lifted at HOLD authority, is of a payment the
    record lists, a line of the batch, of a payment with a line in the unresolved set, and every reason on every line
    of its payment is the record's cause. -/
theorem releases_only_listed (c : Rules.Ctx) (batch : List Rules.Line) (named : List (Nat × Nat))
    (cause : Rules.Reason) (listedPays : List Nat) (hbyp : c.byp = merge named)
    (hnamed : ∀ p m, (p, m) ∈ named → p ∈ listedPays ∧ m = 2 ^ cause.idx) (l : Rules.Line)
    (hl : l ∈ Rules.releasedLines c (Rules.decideAll c (Rules.seen0 c batch) (Rules.order c batch)))
    (hn : Rules.payOutcome c (Rules.decideAll c (Rules.seen0 c batch) (Rules.order c batch)) l.pay ≠ .ALLOW)
    (hlim : c.lim.lookup l.pay = none) :
    l.pay ∈ listedPays ∧ l ∈ batch ∧ (∃ l' ∈ batch, l'.pay = l.pay ∧ l' ∈ Rules.unresolvedSet c) ∧
      ∀ d ∈ Rules.decideAll c (Rules.seen0 c batch) (Rules.order c batch), d.line.pay = l.pay →
        ∀ x ∈ d.reasons, x = cause := by
  have hb := (Rules.bypass_no_window c batch l hl hn).2
  rcases Rules.fail_closed_unless_bypass c batch l hl with h1 | ⟨m, hm, hheld, hall⟩ | ⟨m, hm, -⟩
  · exact absurd h1 hn
  · have hmem : (l.pay, m) ∈ merge named := by rw [← hbyp]; exact mem_of_lookup hm
    obtain ⟨hnm, -⟩ := mem_merge.mp hmem
    obtain ⟨hlp, hmc⟩ := hnamed _ _ hnm
    refine ⟨hlp, hb, hheld, fun d hd hdp x hx => ?_⟩
    have := (hall d hd hdp x hx).2
    rw [hmc] at this
    exact Rules.Reason.idx_inj (bit_pow this).symm
  · rw [hlim] at hm; cases hm

/-- Never a payment held for another cause as well, whatever other approvals the batch carries: a payment with a line
    carrying any reason other than the cause of the pair naming it has no released line (unless lifted at HOLD
    authority, which a cause release never is). -/
theorem never_other_cause (c : Rules.Ctx) (batch : List Rules.Line) (cause : Rules.Reason) (d : Rules.Decision)
    (hd : d ∈ Rules.decideAll c (Rules.seen0 c batch) (Rules.order c batch))
    (hm : c.byp.lookup d.line.pay = some (2 ^ cause.idx)) (hlim : c.lim.lookup d.line.pay = none)
    (x : Rules.Reason) (hx : x ∈ d.reasons) (hne : x ≠ cause) :
    ∀ l ∈ Rules.releasedLines c (Rules.decideAll c (Rules.seen0 c batch) (Rules.order c batch)), l.pay ≠ d.line.pay := by
  have hm0 := hm
  intro l hl hlp
  rcases Rules.fail_closed_unless_bypass c batch l hl with h1 | ⟨m, hm, -, hall⟩ | ⟨m, hm, -⟩
  · have ha := (Rules.payOutcome_allow h1 hd hlp.symm).1
    obtain ⟨pre, l0, rfl⟩ := Rules.mem_decideAll hd
    have : (Rules.decideLine c (pre ++ Rules.seen0 c batch) l0).reasons = [] := Rules.outcomeOf_allow.mp ha
    rw [this] at hx
    cases hx
  · rw [hlp] at hm
    have hmm : m = 2 ^ cause.idx := Option.some.inj (hm.symm.trans hm0)
    have := (hall d hd hlp.symm x hx).2
    rw [hmm] at this
    exact hne (Rules.Reason.idx_inj (bit_pow this).symm)
  · rw [hlp, hlim] at hm; cases hm

/-- Every listed payment held for the cause alone is released: a payment named once, with the cause bit, not decided
    again, with a line held here, and every reason on every line of it the cause (a bypassable one), has every line
    of the batch released. -/
theorem releases_every_listed_held (c : Rules.Ctx) (batch : List Rules.Line) (named : List (Nat × Nat))
    (cause : Rules.Reason) (hbyp : c.byp = merge named) (p : Nat) (hp : (p, 2 ^ cause.idx) ∈ named)
    (hone : named.countP (·.1 == p) = 1) (hcause : Rules.bypassable cause = true) (hredo : c.redo.contains p = false)
    (hheld : ∃ l ∈ batch, l.pay = p ∧ l ∈ Rules.unresolvedSet c)
    (honly : ∀ d ∈ Rules.decideAll c (Rules.seen0 c batch) (Rules.order c batch), d.line.pay = p →
      ∀ x ∈ d.reasons, x = cause) :
    ∀ l ∈ batch, l.pay = p →
      l ∈ Rules.releasedLines c (Rules.decideAll c (Rules.seen0 c batch) (Rules.order c batch)) := by
  have hmem : (p, 2 ^ cause.idx) ∈ merge named := mem_merge.mpr ⟨hp, hone⟩
  have hcm : (merge named).countP (·.1 == p) = 1 := by
    unfold merge
    rw [List.countP_filter, ← hone]
    apply List.countP_congr
    intro x hx
    by_cases h : x.1 = p
    · simp [h, hone]
    · simp [h]
  have hlk : c.byp.lookup p = some (2 ^ cause.idx) := by rw [hbyp]; exact lookup_of_unique hmem hcm
  have hbp : Rules.bypassed c (Rules.decideAll c (Rules.seen0 c batch) (Rules.order c batch)) p = true := by
    obtain ⟨l0, hl0, hl0p, hl0u⟩ := hheld
    obtain ⟨d0, hd0, hd0l⟩ := Rules.lines_mem_decideAll (c := c) hl0
    unfold Rules.bypassed
    rw [hlk]
    refine (Bool.and_eq_true _ _).mpr ⟨(Bool.and_eq_true _ _).mpr ⟨by rw [hredo]; rfl, ?_⟩, ?_⟩
    · exact List.any_eq_true.mpr ⟨d0, hd0, by simp [hd0l, hl0p, hl0u, List.contains_iff_mem]⟩
    · refine List.all_eq_true.mpr fun d hd => ?_
      by_cases hdp : d.line.pay = p
      · simp only [Bool.or_eq_true]
        right
        refine List.all_eq_true.mpr fun r hr => ?_
        have hrc := honly d hd hdp r hr
        subst hrc
        exact (Bool.and_eq_true _ _).mpr ⟨hcause, bit_self _⟩
      · simp [hdp]
  intro l hl hlp
  obtain ⟨d, hd, hdl⟩ := Rules.lines_mem_decideAll (c := c) hl
  have hdp : d.line.pay = p := by rw [hdl]; exact hlp
  unfold Rules.releasedLines
  refine List.mem_map.mpr ⟨d, List.mem_filter.mpr ⟨hd, ?_⟩, hdl⟩
  have : Rules.bypassed c (Rules.decideAll c (Rules.seen0 c batch) (Rules.order c batch)) d.line.pay = true := by
    rw [hdp]; exact hbp
  simp [this]

open Classical in
/-- Once: over a shard's history of batches with bypasses and cause records, the same lines are released by an approval
    in at most one batch; a record read again after its payments went releases nothing of them. -/
theorem release_once (c0 : Rules.Ctx) (h : List (List Rules.Line × List (Nat × Nat) × List Release × List Seen))
    (ls : List Rules.Line) (hne : ls ≠ []) :
    ((stepsWith c0 h).filter fun s => ∃ p, Rules.bypassed s.ctx s.ds p = true ∧ s.lines p = ls).length ≤ 1 :=
  Rules.bypass_once c0 _ ls hne

end BlindLedger.Gate.CauseRelease
