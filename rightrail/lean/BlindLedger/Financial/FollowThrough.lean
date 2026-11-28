/-
Follow-through and the correction follow-up status, as total functions of stored records.

`followThrough` derives one obligation's follow-through item: who found it, who owns it, each clock (anchor, end,
due time, status), the federal share and the gaps. `correctionFollowUpStatus` derives whether an accepted correction is
CURRENT, REOPENED or REVIEW_REQUIRED. They replace two Python derivations, `_build` in
`app/right_rail_financial_followthrough.py` and `_correction_followup_status` in `app/right_rail_financial_owner.py`,
and must give the same outputs (tests/test_follow_through_lean.py runs both on the same records). Neither the engine
nor the pinned financial worker imports this module; it imports nothing but `Init`.

Times are UTC milliseconds since 1970. Records arrive in the order the store holds them; each carries the record
number (`seq`, `recorded`) that orders it against the decisions.

Domain: the Lean functions answer on every input, Python refuses some. Python refuses an obligation marked satisfied
that has no satisfying evaluation, and any date or quarter outside the years 1971 to 9998. Lean computes an answer
for those anyway. The caller that switches to Lean must check both before calling, so the two agree only on inputs
Python accepts.
-/
namespace BlindLedger.Financial.FollowThrough

/-! ## Calendar -/

def dayMs : Nat := 86400000

/-- Days since 1 January 1970 of a Gregorian date (0 for a date before it). -/
def daysFromCivil (y m d : Nat) : Nat :=
  let y := if m ≤ 2 then y - 1 else y
  let era := y / 400
  let yoe := y - era * 400
  let doy := (153 * (if m > 2 then m - 3 else m + 9) + 2) / 5 + d - 1
  era * 146097 + (yoe * 365 + yoe / 4 - yoe / 100 + doy) - 719468

/-- The date (year, month, day) of a day count since 1 January 1970. -/
def civilFromDays (days : Nat) : Nat × Nat × Nat :=
  let z := days + 719468
  let era := z / 146097
  let doe := z - era * 146097
  let yoe := (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
  let doy := doe - (365 * yoe + yoe / 4 - yoe / 100)
  let mp := (5 * doy + 2) / 153
  let m := if mp < 10 then mp + 3 else mp - 9
  (yoe + era * 400 + (if m ≤ 2 then 1 else 0), m, doy - (153 * mp + 2) / 5 + 1)

def leapYear (y : Nat) : Bool := y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)

/-- A clock's length: a number of days or of calendar years. -/
inductive Period where
  | days (count : Nat)
  | years (count : Nat)

/-- `t` plus a clock's length; a 29 February anniversary in a common year is 28 February. -/
def addPeriod (t : Nat) : Period → Nat
  | .days n => t + n * dayMs
  | .years n =>
    let (y, m, d) := civilFromDays (t / dayMs)
    let d := if m == 2 && d == 29 && !leapYear (y + n) then 28 else d
    daysFromCivil (y + n) m d * dayMs + t % dayMs

/-- A federal fiscal quarter: (fiscal year, 1 to 4); quarter 1 starts on 1 October of the year before. -/
abbrev Quarter := Nat × Nat

def quarterOf (t : Nat) : Quarter :=
  let (y, m, _) := civilFromDays (t / dayMs)
  (if m ≥ 10 then y + 1 else y, (m + 2) % 12 / 3 + 1)

/-- The first millisecond after a quarter. -/
def quarterEnd (q : Quarter) : Nat := daysFromCivil q.1 (3 * q.2 - 2) 1 * dayMs

/-- The CMS-64 quarter that carries a credit (the recovery's, if it came before the clock's end; else the end's), its
due time, and whether it is the recovery's. -/
def cms64Due (ends : Nat) (recovered : Option Nat) (dueDays : Nat) : Quarter × Nat × Bool :=
  let collected := match recovered with
    | some r => decide (r < ends)
    | none => false
  let q := quarterOf (match recovered with
    | some r => if r < ends then r else ends - 1
    | none => ends - 1)
  (q, quarterEnd q + dueDays * dayMs, collected)

/-! ## The pack's follow-through rules -/

structure ReportLine where
  form : String
  line : Option String
  summaryLine : String

inductive Report where
  | atEnd
  | cms64Quarter (dueDays : Nat) (collected uncollected : ReportLine)

structure Clock where
  clockId : String
  citation : String
  /-- `EVIDENCE:<purpose>` or `EVENT:<event kind>`. -/
  anchors : List String
  period : Period
  report : Report
  /-- `EVIDENCE:<purpose>` or `SATISFIED`. -/
  satisfiedBy : List String

structure Reason where
  code : String
  requires : List String
  stops : List String

structure Party where
  partyId : String
  party : String
  kind : String
  purposes : List String

structure Rules where
  parties : List Party
  defaultOwner : String
  clocks : List Clock
  reasons : List Reason
  /-- Federal share rate in basis points by period, when the pack states rates. -/
  fmap : Option (List (String × Nat))

/-! ## One obligation's records -/

/-- Who found the obligation: its population manifest. -/
structure Finder where
  sourceOwnerId : String
  sourceId : String
  manifestId : String
  registeredAt : Nat
  approvedBy : String
  approvalRef : String

structure Support where
  evidenceId : String
  sourceId : String
  origin : String
  contentDigest : String
  recordDigest : String
  eventAt : Nat
  receivedAt : Nat
  /-- The record number of the record that stored this document. -/
  recorded : Nat

/-- A payment in force: when the money moved, when its evidence was received, and how many cents it paid. An authorized
offset is one too: a recovery at its decision time, on record from the later of that and its action's record. -/
structure Payment where
  eventAt : Nat
  receivedAt : Nat
  amount : Nat

structure Evaluation where
  evaluationId : String
  revision : Nat
  satisfied : Bool
  evaluatedAt : Nat

structure Suggestion where
  sourceId : String
  sourceRef : String
  sourceSha256 : String
  suggestedAt : Nat
  act : String
  reasonCode : Option String
  ownerId : Option String

structure Decision where
  decisionId : String
  act : String
  reasonCode : Option String
  ownerId : Option String
  suggestion : Option Suggestion
  actorId : String
  actorRole : String

/-- An event on the obligation; a follow-through decision carries its decision. -/
structure Event where
  kind : String
  seq : Nat
  committedAt : Nat
  decision : Option Decision

structure Obligation where
  itemId : String
  obligationId : String
  periodId : String
  owedCents : Nat
  shortfallCents : Nat
  amountSatisfied : Bool
  finder : Finder
  evaluations : List Evaluation
  payments : List Payment
  support : List Support
  events : List Event

/-! ## The item -/

structure AnchorFact where
  source : String
  atMs : Nat
  evidenceId : Option String
  recordDigest : Option String
  recordedAt : Nat
  eventSeq : Option Nat

structure MetFact where
  source : String
  atMs : Nat
  evidenceId : Option String
  recordDigest : Option String
  evaluationId : Option String

inductive ClockStatus where
  | notAnchored | running | missed | met | metLate | stopped
  deriving BEq, DecidableEq

structure ClockView where
  clockId : String
  citation : String
  anchor : Option AnchorFact
  endsMs : Option Nat
  dueMs : Option Nat
  report : Option (Quarter × ReportLine)
  satisfied : Option MetFact
  stoppedBy : Option String
  status : ClockStatus

structure Share where
  periodId : String
  basisPoints : Nat
  cents : Nat

inductive PartStatus where
  | due | missed | met | metLate
  deriving BEq

/-- One part of the federal share, owed on one CMS-64 quarter's report. -/
structure SharePart where
  clockId : String
  /-- The cents of the debt this part covers. -/
  principalCents : Nat
  cents : Nat
  quarter : Quarter
  dueMs : Nat
  report : ReportLine
  status : PartStatus

structure DecisionView where
  decision : Decision
  agrees : Option Bool
  decidedAt : Nat
  seq : Nat

inductive ItemStatus where
  | open | satisfied | closed

structure Item where
  itemId : String
  obligationId : String
  finder : Finder
  finderParty : Option Party
  owner : Option String
  ownerDecision : Option String
  status : ItemStatus
  principalCents : Nat
  openCents : Nat
  clocks : List ClockView
  federalShare : Option Share
  shareParts : List SharePart
  decisions : List DecisionView
  gaps : List String

/-! ## Follow-through -/

def purposeOf (name : String) : Option String :=
  if name.startsWith "EVIDENCE:" then some (String.ofList (name.toList.drop 9)) else none

def holds (r : Rules) (purpose source : String) : Bool :=
  r.parties.any fun p => p.partyId == source && p.purposes.contains purpose

def partyOf (r : Rules) (id : String) : Option Party := r.parties.find? (·.partyId == id)

def reasonOf (r : Rules) (code : String) : Option Reason := r.reasons.find? (·.code == code)

/-- The first least element under `lt`. -/
def firstMin (lt : α → α → Bool) : List α → Option α
  | [] => none
  | x :: xs => some (xs.foldl (fun b y => if lt y b then y else b) x)

def anchorLt (a b : (Nat × Nat × String × Nat) × AnchorFact) : Bool :=
  let ((t1, k1, e1, s1), _) := a
  let ((t2, k2, e2, s2), _) := b
  t1 < t2 || t1 == t2 && (k1 < k2 || k1 == k2 && (e1 < e2 || e1 == e2 && s1 < s2))

def metLt (a b : (Nat × String × String) × MetFact) : Bool :=
  let ((t1, n1, e1), _) := a
  let ((t2, n2, e2), _) := b
  t1 < t2 || t1 == t2 && (n1 < n2 || n1 == n2 && e1 < e2)

/-- The facts that can start a clock: a document from a party that holds a listed purpose, or a listed event. -/
def anchorFacts (r : Rules) (o : Obligation) (k : Clock) : List ((Nat × Nat × String × Nat) × AnchorFact) :=
  k.anchors.flatMap fun name =>
    match purposeOf name with
    | some p => (o.support.filter (holds r p ·.sourceId)).map fun s =>
        ((s.eventAt, 0, s.evidenceId, 0), ⟨name, s.eventAt, some s.evidenceId, some s.recordDigest, s.receivedAt, none⟩)
    | none => (o.events.filter (·.kind == String.ofList (name.toList.drop 6))).map fun e =>
        ((e.committedAt, 1, "", e.seq), ⟨name, e.committedAt, none, none, e.committedAt, some e.seq⟩)

/-- The first evaluation after the last unsatisfied one, in revision order, when the obligation is satisfied. -/
def satisfiedEvaluation (o : Obligation) : Option Evaluation :=
  if o.amountSatisfied then
    let history := o.evaluations.mergeSort fun a b => a.revision ≤ b.revision
    (history.drop (history.length - (history.reverse.takeWhile (·.satisfied)).length)).head?
  else none

/-- The collection date: the latest payment whose evidence came in by the satisfying evaluation, else that
evaluation's time (42 CFR 433.320(a)(2)(i)). -/
def recoveredAt (o : Obligation) (s : Evaluation) : Nat :=
  match (o.payments.filter (·.receivedAt ≤ s.evaluatedAt)).map (·.eventAt) with
  | [] => s.evaluatedAt
  | x :: xs => xs.foldl max x

/-- The facts that can meet a clock: a document from a party that holds a listed purpose, or the satisfaction. -/
def metFacts (r : Rules) (o : Obligation) (sat : Option Evaluation) (k : Clock) :
    List ((Nat × String × String) × MetFact) :=
  (k.satisfiedBy.flatMap fun name =>
    match purposeOf name with
    | some p => (o.support.filter (holds r p ·.sourceId)).map fun s =>
        ((s.receivedAt, name, s.evidenceId), ⟨name, s.receivedAt, some s.evidenceId, some s.recordDigest, none⟩)
    | none => []) ++
  match sat with
  | some e => if k.satisfiedBy.contains "SATISFIED" then
      [((recoveredAt o e, "SATISFIED", ""), ⟨"SATISFIED", recoveredAt o e, none, none, some e.evaluationId⟩)] else []
  | none => []

def federalShare (r : Rules) (o : Obligation) : Option Share := do
  let bp ← (← r.fmap).lookup o.periodId
  pure ⟨o.periodId, bp, (o.owedCents * bp + 5000) / 10000⟩

/-- One document per origin and per content digest: a repeat is the same document. -/
def documents (rows : List Support) : List Support :=
  (rows.foldl (fun (acc : List Support × List String × List String) s =>
      ((if acc.2.1.contains s.origin || acc.2.2.contains s.contentDigest then acc.1 else s :: acc.1),
        s.origin :: acc.2.1, s.contentDigest :: acc.2.2)) ([], [], [])).1.reverse

/-- One step of the search that gives each required purpose its own document: try the sources in order, moving a
document's earlier purpose elsewhere when it can be. Returns success, the purpose each document meets, and the
documents tried. -/
def scan (fits : String → Bool) (purpose : String)
    (move : String → List (Nat × String) → List Nat → Bool × List (Nat × String) × List Nat) :
    List (String × Nat) → List (Nat × String) → List Nat → Bool × List (Nat × String) × List Nat
  | [], taken, tried => (false, taken, tried)
  | (source, n) :: rest, taken, tried =>
    if fits source && !tried.contains n then
      match taken.lookup n with
      | none => (true, (n, purpose) :: taken, n :: tried)
      | some other =>
        match move other taken (n :: tried) with
        | (true, taken', tried') => (true, (n, purpose) :: taken', tried')
        | (false, taken', tried') => scan fits purpose move rest taken' tried'
    else scan fits purpose move rest taken tried

/-- Place one purpose; `fuel` bounds the chain of moves (one more than the number of documents is enough, since each
move tries a new document). -/
def place (r : Rules) (sources : List (String × Nat)) : Nat → String → List (Nat × String) → List Nat →
    Bool × List (Nat × String) × List Nat
  | 0, _, taken, tried => (false, taken, tried)
  | fuel + 1, purpose, taken, tried => scan (holds r purpose) purpose (place r sources fuel) sources taken tried

/-- Each required purpose (42 CFR 433.318) has its own document, from a source that holds that purpose. -/
def covered (r : Rules) (needs sources : List String) : Bool :=
  let numbered := sources.zipIdx
  (needs.foldl (fun (acc : Bool × List (Nat × String)) p =>
      if acc.1 then
        let (ok, taken, _) := place r numbered (sources.length + 1) p acc.2 []
        (ok, taken)
      else acc) (true, [])).1

def notActivity (kind : String) : Bool :=
  ["FOLLOWTHROUGH_DECIDED", "ACTION_ACKNOWLEDGED", "EVALUATION_RECORDED"].contains kind

def decisionsOf (o : Obligation) : List DecisionView :=
  (o.events.mergeSort fun a b => a.seq ≤ b.seq).filterMap fun e =>
    if e.kind == "FOLLOWTHROUGH_DECIDED" then
      e.decision.map fun d => ⟨d, d.suggestion.map fun s =>
        d.act == s.act && d.reasonCode == s.reasonCode && d.ownerId == s.ownerId, e.committedAt, e.seq⟩
    else none

/-- A decision the rules know: a close names a reason in the rules, an assignment names a party that is not a model. -/
def listed (r : Rules) (d : Decision) : Bool :=
  if d.act == "CLOSE" then (d.reasonCode.bind (reasonOf r)).isSome
  else match d.ownerId.bind (partyOf r) with
    | some p => p.kind != "MODEL"
    | none => false

/-- A close whose every required purpose has its own document recorded before the close. -/
def closeCovered (r : Rules) (o : Obligation) (d : DecisionView) : Bool :=
  d.decision.act == "CLOSE" && listed r d.decision &&
  match d.decision.reasonCode.bind (reasonOf r) with
  | some reason => covered r reason.requires ((documents (o.support.filter (·.recorded < d.seq))).map (·.sourceId))
  | none => false

def decisionGaps (r : Rules) (o : Obligation) (d : DecisionView) : List String :=
  let id := d.decision.decisionId
  (if !listed r d.decision then [s!"gap:decision-not-in-rules:{id}"]
   else if d.decision.act == "CLOSE" && !closeCovered r o d then [s!"gap:closure-evidence-missing:{id}"]
   else []) ++
  match d.decision.suggestion with
  | some s => if (partyOf r s.sourceId).isNone then [s!"gap:suggestion-source-not-typed:{id}"] else []
  | none => []

/-- What every clock of one obligation reads. -/
structure Basis where
  satisfied : Option Evaluation
  recovered : Option Nat
  share : Option Share
  /-- The item's close, with what its reason stops, when it is the last decision and its evidence covers it. -/
  stopping : Option (DecisionView × List String)

/-- `cents × basis points / 10000`, rounded half up. -/
def shareOf (cents bp : Nat) : Nat := (cents * bp + 5000) / 10000

/-- A collection, or the rest of the debt, on its way to a part: its CMS-64 (quarter, due time, collected line), the
debt it covers, the earliest time a credit can report it (its quarter's end, and the collection on record), its share,
and the filing that met it. -/
structure Cell where
  key : Quarter × Nat × Bool
  principal : Nat
  ready : Nat
  cents : Nat
  met : Option Nat

/-- In order, each (key, cents, ready) owes the rounded share of the running total (at most `owed`) less the rounded
share before it, so the shares add up to the rounded share of what they cover. -/
def cut (owed bp : Nat) : Nat → List ((Quarter × Nat × Bool) × Nat × Nat) → List Cell
  | _, [] => []
  | before, (key, cents, ready) :: rest =>
    let total := min owed (before + cents)
    ⟨key, total - before, ready, shareOf total bp - shareOf before bp, none⟩ :: cut owed bp total rest

/-- A credit filed at `f` meets the earliest cell not yet met that owes cents and that it can report, with every other
cell of that quarter and line not yet met that it can report. -/
def meetOne (f : Nat) (cells : List Cell) : List Cell :=
  match cells.find? fun c => c.met.isNone && decide (0 < c.cents) && decide (c.ready ≤ f) with
  | none => cells
  | some e => cells.map fun c =>
    if c.met.isNone && c.key == e.key && decide (c.ready ≤ f) then { c with met := some f } else c

/-- Joins neighbouring cells of one quarter, line and filing. -/
def joinCells : List Cell → List Cell
  | [] => []
  | c :: rest =>
    match joinCells rest with
    | d :: more => if c.key == d.key && c.met == d.met then
        { c with principal := c.principal + d.principal, cents := c.cents + d.cents } :: more else c :: d :: more
    | [] => [c]

/-- A part, met on time before its due time, else late; not met, missed from its due time. -/
def partOf (k : String) (now : Nat) (col unc : ReportLine) (c : Cell) : SharePart :=
  ⟨k, c.principal, c.cents, c.key.1, c.key.2.1, if c.key.2.2 then col else unc, match c.met with
    | some f => if f < c.key.2.1 then .met else .metLate
    | none => if now ≥ c.key.2.1 then .missed else .due⟩

/-- The collections (payments and authorized offsets), each on its own quarter, and before a stop the rest of the debt
on `rest`: (key, cents, ready). Before a stop, collections at or after the year end `ends` add nothing. -/
def entriesOf (o : Obligation) (ends days : Nat) (rest : Quarter × Nat × Bool) (stopped : Bool) :
    List ((Quarter × Nat × Bool) × Nat × Nat) :=
  let listed := o.payments.filter fun p => stopped || decide (p.eventAt < ends)
  (if stopped then [] else [(rest, o.owedCents - (listed.map (·.amount)).sum, quarterEnd rest.1)]) ++
    listed.map fun p => let key := cms64Due (p.eventAt + 1) (some p.eventAt) days
      (key, p.amount, max (quarterEnd key.1) p.receivedAt)

/-- Quarter order, then the order on record. -/
def byQuarter (x y : (Quarter × Nat × Bool) × Nat × Nat) : Bool :=
  decide (quarterEnd x.1.1 < quarterEnd y.1.1) || quarterEnd x.1.1 == quarterEnd y.1.1 && decide (x.2.2 ≤ y.2.2)

/-- The federal share by the CMS-64 quarter that carries each part (42 CFR 433.320(a)(2)). Each collection owes on its
own quarter. Before a stop, collections at or after the year end add nothing (433.320(b)(2)) and the rest of the debt
owes on `rest`, the clock's own quarter (433.316(h): a part payment does not move the year). Once a covered close stops
the clock, only collected money owes, whenever it is collected. In quarter order, then the order on record, the shares
are cut from the running total (`cut`); each credit `filed`, in filing order, meets the collections it can report
(`meetOne`); neighbouring cells of one quarter, line and filing make one part, and a part that owes no cents is left
out (the debt it covers is not listed). -/
def shareParts (o : Obligation) (now ends : Nat) (filed : List Nat) (k : Clock) (rest : Quarter × Nat × Bool) (stopped : Bool)
    (s : Share) : List SharePart :=
  match k.report with
  | .atEnd => []
  | .cms64Quarter days col unc =>
    (joinCells (filed.foldl (fun cs f => meetOne f cs)
      (cut o.owedCents s.basisPoints 0 ((entriesOf o ends days rest stopped).mergeSort byQuarter)))).filterMap fun c =>
        if c.cents = 0 then none else some (partOf k.clockId now col unc c)

/-- The cents a clock's parts cover: the whole debt, or once a close stops the clock the money collected, at most the
debt. -/
def coveredBy (o : Obligation) (stopped : Bool) : Nat :=
  if stopped then min o.owedCents (o.payments.map (·.amount)).sum else o.owedCents

/-- The close that stops a clock ending at `ends` (42 CFR 433.320(d)): the item's covered close, when its reason stops
the clock and it came before the end. -/
def stopFor (stopping : Option (DecisionView × List String)) (clockId : String) (ends : Nat) : Option String :=
  match stopping with
  | some (close, stops) => if stops.contains clockId && decide (close.decidedAt < ends) then some close.decision.decisionId else none
  | none => none

/-- The CMS-64 quarter, due time and line of a clock that reports on the CMS-64. -/
def owesOf (b : Basis) (k : Clock) (ends : Nat) : Option (Quarter × Nat × Bool) :=
  match k.report with
  | .atEnd => none
  | .cms64Quarter days _ _ => some (cms64Due ends b.recovered days)

def clockStep (o : Obligation) (now : Nat) (b : Basis) (k : Clock) (anchor : Option AnchorFact)
    (met : Option MetFact) (filed : List Nat) : ClockView × List SharePart :=
  match anchor with
  | none => (⟨k.clockId, k.citation, none, none, none, none, met, none, .notAnchored⟩, [])
  | some a =>
    let ends := addPeriod a.atMs k.period
    let owes := owesOf b k ends
    let due := match owes with
      | some x => x.2.1
      | none => ends
    let report : Option (Quarter × ReportLine) := match k.report, owes with
      | .cms64Quarter _ col unc, some (q, _, c) => some (q, if c then col else unc)
      | _, _ => none
    -- 433.320(d): a covered close stops only the uncollected part, whether or not a credit was filed
    let stop := stopFor b.stopping k.clockId ends
    let stoppedBy := if met.isSome then none else stop
    let status := match met with
      | some m => if m.atMs < due then .met else .metLate
      | none => if stop.isSome then .stopped else if now ≥ due then .missed else .running
    (⟨k.clockId, k.citation, anchor, some ends, some due, if stoppedBy.isSome then none else report, met, stoppedBy,
      status⟩,
     match owes, b.share with
     | some rest, some s => shareParts o now ends filed k rest stop.isSome s
     | _, _ => [])

/-- The credits filed for a clock: the times of the documents that meet it, one per document, in filing order (a
recovery meets a clock but is not a filing). -/
def credits (r : Rules) (o : Obligation) (k : Clock) : List Nat :=
  (documents ((o.support.filter fun s => k.satisfiedBy.any fun name => match purposeOf name with
      | some p => holds r p s.sourceId
      | none => false).mergeSort fun a b =>
        a.receivedAt < b.receivedAt || a.receivedAt == b.receivedAt && !decide (b.evidenceId < a.evidenceId))).map (·.receivedAt)

def clockOf (r : Rules) (o : Obligation) (now : Nat) (b : Basis) (k : Clock) : ClockView × List SharePart :=
  clockStep o now b k ((firstMin anchorLt (anchorFacts r o k)).map (·.2)) ((firstMin metLt (metFacts r o b.satisfied k)).map (·.2))
    (credits r o k)

/-- The item's close: its last decision, when that is a close (an assignment after a close reopens the item). -/
def closeOf (o : Obligation) : Option DecisionView :=
  match (decisionsOf o).getLast? with
  | some d => if d.decision.act == "CLOSE" then some d else none
  | none => none

/-- The item's close with what its reason stops, when its evidence covers it. -/
def stoppingOf (r : Rules) (o : Obligation) : Option (DecisionView × List String) :=
  match closeOf o with
  | some c => if closeCovered r o c then (c.decision.reasonCode.bind (reasonOf r)).map fun x => (c, x.stops) else none
  | none => none

/-- One obligation's follow-through item, from the pack's rules, the obligation's records and the time. -/
def followThrough (r : Rules) (o : Obligation) (now : Nat) : Item :=
  let sat := satisfiedEvaluation o
  let share := federalShare r o
  let decisions := decisionsOf o
  let close := closeOf o
  let assigned := (decisions.filter (·.decision.act == "ASSIGN")).getLast?
  let b : Basis := ⟨sat, sat.map (recoveredAt o), share, stoppingOf r o⟩
  let steps := r.clocks.map (clockOf r o now b)
  let clocks := steps.map (·.1)
  let party := partyOf r o.finder.sourceOwnerId
  let gaps :=
    (if party.isNone then [s!"gap:finder-not-typed:{o.finder.sourceOwnerId}"] else []) ++
    (if r.fmap.isSome && share.isNone then [s!"gap:fmap-period-missing:{o.periodId}"] else []) ++
    decisions.flatMap (decisionGaps r o) ++
    (match close with
     | some c => if o.events.any fun e => e.seq > c.seq && !notActivity e.kind
         then [s!"gap:activity-after-close:{o.itemId}"] else []
     | none => []) ++
    (if clocks.any (·.status == .stopped) then [s!"gap:write-off-line-unknown:{o.itemId}"] else [])
  { itemId := o.itemId, obligationId := o.obligationId, finder := o.finder, finderParty := party,
    owner := match assigned with
      | some d => d.decision.ownerId
      | none => some r.defaultOwner,
    ownerDecision := assigned.map (·.decision.decisionId),
    status := if sat.isSome then .satisfied else if close.isSome then .closed else .open,
    principalCents := o.owedCents, openCents := o.shortfallCents, clocks := clocks, federalShare := share,
    shareParts := (steps.map (·.2)).flatten, decisions := decisions, gaps := gaps.eraseDups }

/-! ## Correction follow-up status -/

inductive FollowUpStatus where
  | current | reopened | reviewRequired
  deriving BEq, DecidableEq

/-- Which dependency families of an accepted correction a later event of each kind can move. A kind not listed gives
`none`, and the status is then REVIEW_REQUIRED, never CURRENT. -/
def touches : String → Option (List String)
  | "CONTROL_PACK_PUBLISHED" => some ["RULE"]
  | "EVALUATION_RECORDED" => some ["AUTHORITY"]
  | "SUPPORT_EVIDENCE_RECORDED" => some ["AUTHORITY", "SUPPORT_EVIDENCE"]
  | "PAYMENT_RECEIVED" | "PAYMENT_REVERSED" | "PAYMENT_CONFLICT_VISIBLE" => some ["AUTHORITY", "PAYMENT_EVIDENCE"]
  | "OFFSET_CLAIMED" => some ["AUTHORITY", "OFFSET_EVIDENCE"]
  | "OFFSET_AUTHORIZED" | "OFFSET_REJECTED_CORRECTION_AUTHORIZED" => some ["AUTHORITY", "DETERMINATION"]
  | "ACTION_ACKNOWLEDGED" => some ["AUTHORITY"]
  | "REPORTING_EVIDENCE_RECORDED" | "REPORTING_CORRECTION_RECORDED" => some ["AUTHORITY", "REPORT_EVIDENCE"]
  | "PAYMENT_DUPLICATE_EVIDENCE" | "INTAKE_RECEIVED" | "FOLLOWTHROUGH_DECIDED"
  | "POPULATION_MANIFEST_REGISTERED" | "POPULATION_MANIFEST_SUPERSEDED" | "POPULATION_STAGED"
  | "POPULATION_IMPORT_OPENED" | "POPULATION_SOURCE_COMPLETED" | "POPULATION_VALIDATED"
  | "POPULATION_PUBLISHED" | "FUNDING_RECEIPT_RECORDED" | "FUNDING_RECEIPT_SUPERSEDED" => some []
  | _ => none

def evidenceFamily : String → Option String
  | "SUPPORT" => some "SUPPORT_EVIDENCE"
  | "PAYMENT_CONFIRMATION" | "PAYMENT_REVERSAL" => some "PAYMENT_EVIDENCE"
  | "OFFSET_CLAIM" => some "OFFSET_EVIDENCE"
  | "REPORT" | "REPORT_CORRECTION" => some "REPORT_EVIDENCE"
  | _ => none

/-- The basis a correction was accepted on, as stored with it. Field values are canonical JSON text. -/
structure AcceptedBasis where
  workId : String
  packId : String
  pack : List (String × String)
  authorityId : String
  authority : String
  determinationId : String
  determinationDigest : String
  boundEvidence : List String

/-- The same inputs now. -/
structure CurrentBasis where
  pack : List (String × String)
  authority : String
  determination : Option (String × String)
  /-- The action's status and its outbox status. -/
  delivery : Option (String × String)

/-- A document on the item: the work ids of the requests its cash pays, and whether it only repeats a confirmation. -/
structure ItemEvidence where
  evidenceId : String
  kind : String
  paysWork : List String
  repeatsConfirmation : Bool

structure LaterEvent where
  kind : String
  /-- An event on another obligation moves nothing of this one. -/
  otherObligation : Bool

def evidenceMoves (itemId : String) (b : AcceptedBasis) (e : ItemEvidence) : Option (List (String × String)) :=
  if e.kind == "PAYMENT_CONFIRMATION" && (e.paysWork.contains b.workId || e.repeatsConfirmation) then some []
  else if b.boundEvidence.contains e.evidenceId then some []
  else (evidenceFamily e.kind).map fun f => [(f, s!"COLLECTION({f}, {itemId})")]

/-- REVIEW_REQUIRED when a moved family is one no later event can move; else REOPENED with the moved keys, sorted,
or CURRENT when none moved. -/
def verdict (moved : List (String × String)) (touched : List String) : FollowUpStatus × List String :=
  if moved.any fun (f, _) => !touched.contains f then (.reviewRequired, [])
  else match (moved.map (·.2)).eraseDups.mergeSort fun x y => decide (x ≤ y) with
    | [] => (.current, [])
    | changed => (.reopened, changed)

/-- CURRENT, REOPENED (naming the keys that moved) or REVIEW_REQUIRED, for one accepted correction. -/
def correctionFollowUpStatus (itemId obligationId : String) (basis : Option AcceptedBasis) (now : CurrentBasis)
    (evidence : List ItemEvidence) (later : List LaterEvent) : FollowUpStatus × List String :=
  match basis, now.determination,
      basis.bind fun b => b.pack.mapM fun (k, v) => (now.pack.lookup k).map (· != v),
      basis.bind fun b => evidence.mapM (evidenceMoves itemId b),
      later.mapM fun e => (touches e.kind).map fun fs => if e.otherObligation then [] else fs with
  | some b, some (detId, detDigest), some packMoves, some evidenceMoved, some touched =>
    let moved :=
      (if packMoves.any id then [("RULE", s!"RULE({b.packId})")] else []) ++
      (if now.authority != b.authority then [("AUTHORITY", s!"AUTHORITY({b.authorityId})")] else []) ++
      (if (detId, detDigest) != (b.determinationId, b.determinationDigest)
       then [("DETERMINATION", s!"COLLECTION(DETERMINATION, {obligationId})")] else []) ++
      (match now.delivery with
       | some (a, o) => if ["READY", "ACKNOWLEDGED"].contains a && ["READY", "ACKNOWLEDGED"].contains o then []
                        else [("DELIVERY_REJECTED", s!"COLLECTION(DELIVERY_REJECTED, {b.workId})")]
       | none => [("DELIVERY_REJECTED", s!"COLLECTION(DELIVERY_REJECTED, {b.workId})")]) ++
      evidenceMoved.flatten
    verdict moved touched.flatten
  | _, _, _, _, _ => (.reviewRequired, [])

/-! ## Laws -/

/-- The times the obligation's records store. -/
def storedTimes (o : Obligation) : List Nat := o.support.map (·.eventAt) ++ o.events.map (·.committedAt)

theorem firstMin_mem {lt : α → α → Bool} : ∀ {l : List α} {x : α}, firstMin lt l = some x → x ∈ l
  | [], _, h => by simp [firstMin] at h
  | y :: ys, x, h => by
    simp only [firstMin, Option.some.injEq] at h
    subst h
    suffices ∀ z, z ∈ y :: ys → ∀ zs : List α, (∀ w ∈ zs, w ∈ y :: ys) →
        zs.foldl (fun b w => if lt w b then w else b) z ∈ y :: ys from
      this y (List.mem_cons_self ..) ys fun w hw => List.mem_cons_of_mem _ hw
    intro z hz zs hzs
    induction zs generalizing z with
    | nil => exact hz
    | cons w ws ih =>
      simp only [List.foldl_cons]
      apply ih
      · split
        · exact hzs w (List.mem_cons_self ..)
        · exact hz
      · exact fun v hv => hzs v (List.mem_cons_of_mem _ hv)

theorem anchorFacts_stored (r : Rules) (o : Obligation) (k : Clock) :
    ∀ x ∈ anchorFacts r o k, x.2.atMs ∈ storedTimes o := by
  intro x hx
  simp only [anchorFacts, List.mem_flatMap] at hx
  obtain ⟨name, -, hx⟩ := hx
  split at hx <;> simp only [List.mem_map, List.mem_filter] at hx <;> obtain ⟨y, ⟨hy, -⟩, rfl⟩ := hx <;>
    simp [storedTimes] <;> first | exact Or.inl ⟨y, hy, rfl⟩ | exact Or.inr ⟨y, hy, rfl⟩

theorem cms64Due_due (ends : Nat) (recovered : Option Nat) (days : Nat) :
    ∃ t, (cms64Due ends recovered days).2.1 = quarterEnd (quarterOf t) + days * dayMs := ⟨_, rfl⟩

theorem owesOf_due {b : Basis} {k : Clock} {ends : Nat} {x : Quarter × Nat × Bool} (h : owesOf b k ends = some x) :
    ∃ days col unc t, k.report = .cms64Quarter days col unc ∧ x.2.1 = quarterEnd (quarterOf t) + days * dayMs := by
  unfold owesOf at h
  split at h
  · cases h
  · rename_i days col unc hk
    cases h
    obtain ⟨t, ht⟩ := cms64Due_due ends b.recovered days
    exact ⟨days, col, unc, t, hk, ht⟩

theorem clockStep_times (o : Obligation) (now : Nat) (b : Basis) (k : Clock) (anchor : Option AnchorFact)
    (met : Option MetFact) (filed : List Nat) :
    let v := (clockStep o now b k anchor met filed).1
    v.clockId = k.clockId ∧ v.anchor = anchor ∧
    (∀ e, v.endsMs = some e → ∃ a, anchor = some a ∧ e = addPeriod a.atMs k.period) ∧
    (∀ d, v.dueMs = some d → ∃ e, v.endsMs = some e ∧
      (d = e ∨ ∃ days col unc t, k.report = .cms64Quarter days col unc ∧ d = quarterEnd (quarterOf t) + days * dayMs)) := by
  intro v
  cases anchor with
  | none => simp [v, clockStep]
  | some a =>
    refine ⟨rfl, rfl, fun e he => ⟨a, rfl, (Option.some.inj he).symm⟩, fun d hd => ⟨_, rfl, ?_⟩⟩
    have hd : (match owesOf b k (addPeriod a.atMs k.period) with
      | some x => x.2.1
      | none => addPeriod a.atMs k.period) = d := Option.some.inj hd
    cases ho : owesOf b k (addPeriod a.atMs k.period) with
    | none => rw [ho] at hd; exact Or.inl hd.symm
    | some x =>
      rw [ho] at hd
      obtain ⟨days, col, unc, t, hk, hx⟩ := owesOf_due ho
      exact Or.inr ⟨days, col, unc, t, hk, hd ▸ hx⟩

theorem shareOf_mono {a c : Nat} (bp : Nat) (h : a ≤ c) : shareOf a bp ≤ shareOf c bp :=
  Nat.div_le_div_right (Nat.add_le_add_right (Nat.mul_le_mul_right bp h) 5000)

theorem shareOf_zero (bp : Nat) : shareOf 0 bp = 0 := by simp [shareOf]

/-- The cells' shares add up to the rounded share of the running total, and their principal to that total. -/
theorem cut_sums (owed bp : Nat) : ∀ (xs : List ((Quarter × Nat × Bool) × Nat × Nat)) (before : Nat), before ≤ owed →
    ((cut owed bp before xs).map (·.cents)).sum + shareOf before bp = shareOf (min owed (before + (xs.map (·.2.1)).sum)) bp ∧
    ((cut owed bp before xs).map (·.principal)).sum + before = min owed (before + (xs.map (·.2.1)).sum)
  | [], before, h => by constructor <;> simp [cut, Nat.min_eq_right h]
  | (key, cents, ready) :: rest, before, h => by
    have hT : min owed (before + cents) ≤ owed := by omega
    have hle : before ≤ min owed (before + cents) := by omega
    have hmono := shareOf_mono bp hle
    obtain ⟨hc, hp⟩ := cut_sums owed bp rest (min owed (before + cents)) hT
    have hm : min owed (min owed (before + cents) + (rest.map (·.2.1)).sum) =
        min owed (before + (cents + (rest.map (·.2.1)).sum)) := by omega
    rw [hm] at hc hp
    simp only [cut, List.map_cons, List.sum_cons]
    generalize ((cut owed bp (min owed (before + cents)) rest).map (·.cents)).sum = C at *
    generalize ((cut owed bp (min owed (before + cents)) rest).map (·.principal)).sum = P at *
    generalize min owed (before + (cents + (rest.map (·.2.1)).sum)) = T at *
    generalize min owed (before + cents) = M at *
    generalize shareOf M bp = SM at *
    generalize shareOf before bp = SB at *
    constructor <;> omega

/-- A credit changes which filing met a cell, never its cents or principal. -/
theorem meetOne_amounts (f : Nat) (cs : List Cell) :
    (meetOne f cs).map (·.cents) = cs.map (·.cents) ∧ (meetOne f cs).map (·.principal) = cs.map (·.principal) := by
  unfold meetOne
  split
  · exact ⟨rfl, rfl⟩
  · constructor <;> (rw [List.map_map]; exact List.map_congr_left fun c _ => by simp only [Function.comp_apply]; split <;> rfl)

theorem meet_amounts : ∀ (fs : List Nat) (cs : List Cell),
    (fs.foldl (fun cs f => meetOne f cs) cs).map (·.cents) = cs.map (·.cents) ∧
    (fs.foldl (fun cs f => meetOne f cs) cs).map (·.principal) = cs.map (·.principal)
  | [], _ => ⟨rfl, rfl⟩
  | f :: fs, cs => by
    obtain ⟨a, b⟩ := meet_amounts fs (meetOne f cs)
    obtain ⟨c, d⟩ := meetOne_amounts f cs
    exact ⟨a.trans c, b.trans d⟩

theorem joinCells_sums : ∀ cs : List Cell,
    ((joinCells cs).map (·.cents)).sum = (cs.map (·.cents)).sum ∧
    ((joinCells cs).map (·.principal)).sum = (cs.map (·.principal)).sum
  | [] => ⟨rfl, rfl⟩
  | c :: rest => by
    obtain ⟨h1, h2⟩ := joinCells_sums rest
    simp only [joinCells]
    split
    · rename_i d more heq
      rw [heq] at h1 h2
      simp only [List.map_cons, List.sum_cons] at h1 h2 ⊢
      split <;> simp only [List.map_cons, List.sum_cons] <;> omega
    · rename_i heq
      rw [heq] at h1 h2
      simp only [List.map_cons, List.sum_cons, List.map_nil, List.sum_nil] at h1 h2 ⊢
      omega

/-- Leaving out the parts that owe no cents keeps the cents and lists at most the principal. -/
theorem kept_sums (k : String) (now : Nat) (col unc : ReportLine) : ∀ cs : List Cell,
    ((cs.filterMap fun c => if c.cents = 0 then none else some (partOf k now col unc c)).map (·.cents)).sum = (cs.map (·.cents)).sum ∧
    ((cs.filterMap fun c => if c.cents = 0 then none else some (partOf k now col unc c)).map (·.principalCents)).sum ≤
      (cs.map (·.principal)).sum
  | [] => ⟨rfl, Nat.le_refl _⟩
  | c :: rest => by
    obtain ⟨h1, h2⟩ := kept_sums k now col unc rest
    have hc : (partOf k now col unc c).cents = c.cents := rfl
    have hp : (partOf k now col unc c).principalCents = c.principal := rfl
    by_cases h0 : c.cents = 0 <;> simp only [List.filterMap_cons, h0, ↓reduceIte, List.map_cons, List.sum_cons, hc, hp] <;> omega

/-- The entries cover the whole debt, or after a stop the money collected (at most the debt). -/
theorem entries_cover (o : Obligation) (ends days : Nat) (rest : Quarter × Nat × Bool) (stopped : Bool) :
    min o.owedCents ((entriesOf o ends days rest stopped).map (·.2.1)).sum = coveredBy o stopped := by
  cases stopped
  · simp [entriesOf, coveredBy, List.map_map, Function.comp_def] <;> omega
  · have h : o.payments.filter (fun _ => true) = o.payments := List.filter_eq_self.2 fun _ _ => rfl
    simp [entriesOf, coveredBy, List.map_map, Function.comp_def, h]

/-- A clock's parts are none, or add up to the rounded share of exactly what they cover (`coveredBy`), with that at
least their listed principal. -/
theorem shareParts_sum (o : Obligation) (now ends : Nat) (filed : List Nat) (k : Clock) (rest : Quarter × Nat × Bool)
    (stopped : Bool) (s : Share) :
    shareParts o now ends filed k rest stopped s = [] ∨
      ((shareParts o now ends filed k rest stopped s).map (·.cents)).sum = shareOf (coveredBy o stopped) s.basisPoints ∧
      ((shareParts o now ends filed k rest stopped s).map (·.principalCents)).sum ≤ coveredBy o stopped := by
  unfold shareParts
  split
  · exact Or.inl rfl
  · rename_i days col unc _
    right
    have hperm : (((entriesOf o ends days rest stopped).mergeSort byQuarter).map (·.2.1)).sum =
        ((entriesOf o ends days rest stopped).map (·.2.1)).sum := ((List.mergeSort_perm _ _).map _).sum_nat
    obtain ⟨hc, hp⟩ := cut_sums o.owedCents s.basisPoints ((entriesOf o ends days rest stopped).mergeSort byQuarter) 0 (Nat.zero_le _)
    rw [hperm, Nat.zero_add, entries_cover, shareOf_zero, Nat.add_zero] at hc
    rw [hperm, Nat.zero_add, entries_cover, Nat.add_zero] at hp
    obtain ⟨ma, mb⟩ := meet_amounts filed (cut o.owedCents s.basisPoints 0 ((entriesOf o ends days rest stopped).mergeSort byQuarter))
    obtain ⟨ja, jb⟩ := joinCells_sums (filed.foldl (fun cs f => meetOne f cs)
      (cut o.owedCents s.basisPoints 0 ((entriesOf o ends days rest stopped).mergeSort byQuarter)))
    obtain ⟨ka, kb⟩ := kept_sums k.clockId now col unc (joinCells (filed.foldl (fun cs f => meetOne f cs)
      (cut o.owedCents s.basisPoints 0 ((entriesOf o ends days rest stopped).mergeSort byQuarter))))
    rw [ma] at ja
    rw [mb] at jb
    exact ⟨ka.trans (ja.trans hc), Nat.le_trans kb (Nat.le_of_eq (jb.trans hp))⟩

theorem clockStep_parts (o : Obligation) (now : Nat) (b : Basis) (k : Clock) (anchor : Option AnchorFact)
    (met : Option MetFact) (filed : List Nat) :
    (clockStep o now b k anchor met filed).2 = [] ∨ ∃ s e, b.share = some s ∧ (clockStep o now b k anchor met filed).1.endsMs = some e ∧
      ((clockStep o now b k anchor met filed).2.map (·.cents)).sum =
        shareOf (coveredBy o (stopFor b.stopping (clockStep o now b k anchor met filed).1.clockId e).isSome) s.basisPoints ∧
      ((clockStep o now b k anchor met filed).2.map (·.principalCents)).sum ≤
        coveredBy o (stopFor b.stopping (clockStep o now b k anchor met filed).1.clockId e).isSome := by
  cases anchor with
  | none => exact Or.inl rfl
  | some a =>
    simp only [clockStep]
    split
    · rename_i rest s _ hs
      exact (shareParts_sum o now _ filed k rest _ s).imp_right fun h => ⟨s, _, hs, rfl, h⟩
    · exact Or.inl rfl

theorem verdict_current (moved : List (String × String)) (touched : List String) :
    (verdict moved touched).1 = .current → (verdict moved touched).2 = [] := by
  unfold verdict
  split
  · simp
  · split <;> simp

/-- Laws of the outputs. Every clock's end is the pack's length added to a stored time (the anchor's), and its due time
is that end or some federal quarter end plus the pack's days; each federal share is
`(owed cents × basis points + 5000) div 10000`; the share parts are one block per clock, and each block is empty or its
shares add up to that rounding, at the federal share's rate, of exactly the cents it covers: the whole debt, or once the
item's covered close stops the clock (whether or not a credit was filed) the money collected, at most the debt (so
rounding each part never adds or loses a cent); those cents are at least the block's listed principal (a part whose
share rounds to 0 cents is left out, and its principal is not listed); an accepted correction with no readable basis, or with a later event of
a kind the table does not list, is REVIEW_REQUIRED, and a CURRENT status carries no changed families. It does not say
which quarter end a due time uses (any will do), that the share's rate is the one the pack's fmap table lists for the
period, which quarter each part falls in or its status, what the clock count or the item status is. The equality tests against Python cover those. -/
theorem follow_through_laws (r : Rules) (o : Obligation) (now : Nat) (itemId obligationId : String)
    (basis : Option AcceptedBasis) (current : CurrentBasis) (evidence : List ItemEvidence) (later : List LaterEvent) :
    let item := followThrough r o now
    let status := correctionFollowUpStatus itemId obligationId basis current evidence later
    (∀ v ∈ item.clocks, ∃ k ∈ r.clocks, v.clockId = k.clockId ∧
      (∀ e, v.endsMs = some e → ∃ a, v.anchor = some a ∧ a.atMs ∈ storedTimes o ∧ e = addPeriod a.atMs k.period) ∧
      (∀ d, v.dueMs = some d → ∃ e, v.endsMs = some e ∧
        (d = e ∨ ∃ days col unc t, k.report = .cms64Quarter days col unc ∧ d = quarterEnd (quarterOf t) + days * dayMs))) ∧
    (∀ s, item.federalShare = some s → s.cents = (o.owedCents * s.basisPoints + 5000) / 10000) ∧
    (∃ blocks : List (ClockView × List SharePart), blocks.map (·.1) = item.clocks ∧ item.shareParts = (blocks.map (·.2)).flatten ∧
      ∀ vp ∈ blocks, vp.2 = [] ∨ ∃ s e, item.federalShare = some s ∧ vp.1.endsMs = some e ∧
        (vp.2.map (·.cents)).sum = shareOf (coveredBy o (stopFor (stoppingOf r o) vp.1.clockId e).isSome) s.basisPoints ∧
        (vp.2.map (·.principalCents)).sum ≤ coveredBy o (stopFor (stoppingOf r o) vp.1.clockId e).isSome) ∧
    (basis = none → status = (.reviewRequired, [])) ∧
    ((∃ e ∈ later, touches e.kind = none) → status = (.reviewRequired, [])) ∧
    (status.1 = .current → status.2 = []) := by
  intro item status
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro v hv
    simp only [item, followThrough, List.map_map, List.mem_map] at hv
    obtain ⟨k, hk, rfl⟩ := hv
    refine ⟨k, hk, ?_⟩
    obtain ⟨hid, hanchor, hends, hdue⟩ := clockStep_times o now _ k _ _ _
    refine ⟨hid, fun e he => ?_, hdue⟩
    obtain ⟨a, ha, rfl⟩ := hends e he
    refine ⟨a, hanchor.trans ha, ?_, rfl⟩
    simp only [Option.map_eq_some_iff] at ha
    obtain ⟨x, hx, rfl⟩ := ha
    exact anchorFacts_stored r o k x (firstMin_mem hx)
  · intro s hs
    simp only [item, followThrough, federalShare] at hs
    cases hf : r.fmap <;> simp [hf] at hs
    rename_i table
    cases hl : table.lookup o.periodId <;> simp [hl] at hs
    subst hs
    rfl
  · refine ⟨_, rfl, rfl, fun vp hvp => ?_⟩
    simp only [List.mem_map] at hvp
    obtain ⟨k, -, rfl⟩ := hvp
    exact clockStep_parts o now _ k _ _ _
  · intro h
    simp [status, correctionFollowUpStatus, h]
  · rintro ⟨e, he, hk⟩
    have : (later.mapM fun e => (touches e.kind).map fun fs => if e.otherObligation then [] else fs) = none := by
      induction later with
      | nil => simp at he
      | cons x xs ih =>
        simp only [List.mem_cons] at he
        rcases he with rfl | he
        · simp [List.mapM_cons, hk]
        · simp [List.mapM_cons, ih he]
    simp only [status, correctionFollowUpStatus, this]
    split <;> simp_all
  · simp only [status, correctionFollowUpStatus]
    split
    · exact verdict_current _ _
    · simp

end BlindLedger.Financial.FollowThrough
