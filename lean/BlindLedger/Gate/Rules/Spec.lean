namespace BlindLedger.Gate.Rules

/-! Payment gate decision rules v1: whether a payment line is ALLOW or HOLD on
    the merits.  Five checks run over pinned reference snapshots and the gate's
    released set; each check that fires adds its reason code.

    - R1 `MEMBER_DECEASED`: the member's Death Master File date of death is
      before the service date (FFS) or the service-period start (CAP_820).
    - R2 `CAP_MEMBER_MONTH_DUPLICATE`: a CAP_820 line's (member, month) is
      already released, or belongs to an earlier line of the batch in canonical
      order, whatever that line's plan or outcome.
    - R3 `PROVIDER_EXCLUDED` / `PROVIDER_DECEASED`: the payee or rendering
      party is on the exclusion snapshot (LEIE, SAM or state list) on the
      service date, or on the provider death list with a date of death before it.
    - R4 `FFS_DUPLICATE_LINE`: an FFS line's (member, billing provider, date,
      procedure, units, cents) is already released or belongs to an earlier line.
    - R5 `MEMBER_NOT_ENROLLED`: no enrollment span covers the date; for
      CAP_820 the span must also be with the paying plan.

    Any reason makes the line HOLD.  A missing or stale snapshot adds its
    `STALE_*` code and makes the line HUMAN_REVIEW.  No rule yields BLOCK:
    blocking stays a human or state action, so `Outcome` has no BLOCK.

    Mapping onto the token (`BlindLedger.Gate.Spec`, gate-v1; not imported):
    `Flow.tag` and the outcome names equal the token's; `reasons` lists the
    codes in ascending byte order, as the leaf's `reasonCodes` requires.  One
    `Line` becomes one canonical line leaf of `Request.lines` (flow tag, then
    each field; identifiers are the u16-length identifiers read as big-endian
    naturals after a 0x01 byte, which is injective), so `lines_root` commits
    to exactly the lines decided here.  The payment is ALLOW when every line
    is; a held line leaves the cycle.  Snapshot pins join the token's read-set
    digest.  Dates are CCYYMMDD naturals (X12 D8), so `<` is calendar order.
    Synthetic, nonpayment, activation=false. -/

inductive Flow | FFS_CYCLE | FFS_CLAIM | CAP_820 deriving DecidableEq, Repr

def Flow.tag : Flow → Nat
  | .FFS_CYCLE => 1 | .FFS_CLAIM => 2 | .CAP_820 => 3

inductive Outcome | ALLOW | HOLD | HUMAN_REVIEW deriving DecidableEq, Repr

inductive Reason
  | CAP_MEMBER_MONTH_DUPLICATE | FFS_DUPLICATE_LINE | MEMBER_DECEASED | MEMBER_NOT_ENROLLED
  | PROVIDER_DECEASED | PROVIDER_EXCLUDED
  | STALE_DMF | STALE_ENROLLMENT | STALE_EXCLUSION | STALE_PROVIDER_DEATH
  deriving DecidableEq, Repr

/-- Every code once, in ascending byte order of its name (the runner's `#guard` checks the order). -/
def reasons : List Reason :=
  [.CAP_MEMBER_MONTH_DUPLICATE, .FFS_DUPLICATE_LINE, .MEMBER_DECEASED, .MEMBER_NOT_ENROLLED,
   .PROVIDER_DECEASED, .PROVIDER_EXCLUDED,
   .STALE_DMF, .STALE_ENROLLMENT, .STALE_EXCLUSION, .STALE_PROVIDER_DEATH]

/-- For CAP_820, `payee` and `rendering` are the plan and `date` is the first
    day of the service period. -/
structure Line where
  flow : Flow
  member : Nat
  payee : Nat
  rendering : Nat
  date : Nat
  proc : Nat
  units : Nat
  cents : Nat
  deriving DecidableEq, Repr

/-- A death list entry: member or provider, and the date of death. -/
structure Death where
  id : Nat
  date : Nat

/-- An exclusion in force from `start` to `stop`, both inclusive (99991231 when open). -/
structure Exclusion where
  id : Nat
  start : Nat
  stop : Nat

/-- An enrollment span, inclusive; `plan` is the paying plan. -/
structure Span where
  member : Nat
  plan : Nat
  start : Nat
  stop : Nat

structure Snapshot (α : Type) where
  asOf : Nat
  entries : List α

/-- The read set: `none` is a missing snapshot. -/
structure Ctx where
  today : Nat
  dmf : Option (Snapshot Death)
  providerDeaths : Option (Snapshot Death)
  exclusions : Option (Snapshot Exclusion)
  enrollment : Option (Snapshot Span)

def entries {α : Type} (o : Option (Snapshot α)) : List α := (o.map (·.entries)).getD []

/-- Days from 0000-03-01 to a CCYYMMDD date (proleptic Gregorian). -/
def dayNum (d : Nat) : Nat :=
  let m := d / 100 % 100
  let y := d / 10000 - (if m ≤ 2 then 1 else 0)
  let mp := if m > 2 then m - 3 else m + 9
  y * 365 + y / 4 - y / 100 + y / 400 + (153 * mp + 2) / 5 + d % 100 - 1

/-- Present, not dated after today, and at most `maxAge` days old. -/
def fresh {α : Type} (today maxAge : Nat) : Option (Snapshot α) → Bool
  | none => false
  | some s => s.asOf ≤ today && dayNum today ≤ dayNum s.asOf + maxAge

/-- A line's duplicate key: member-month for CAP_820 (any plan); the exact
    billed line for FFS (either FFS flow, any rendering party). -/
abbrev Key := List Nat

def key (l : Line) : Key :=
  if l.flow = .CAP_820 then [0, l.member, l.date / 100]
  else [1, l.member, l.payee, l.date, l.proc, l.units, l.cents]

def isCap (l : Line) : Bool := l.flow == .CAP_820

def covers (l : Line) (s : Span) : Bool :=
  s.member == l.member && s.start ≤ l.date && l.date ≤ s.stop && (!isCap l || s.plan == l.payee)

def party (l : Line) (id : Nat) : Bool := id == l.payee || id == l.rendering

/-- The rule table.  Maximum ages: DMF and provider deaths 90 days (H.R.1
    §§71104-71105 quarterly minimum); exclusions 31 days (42 CFR 455.436
    monthly checks); enrollment 7 days, a placeholder for the state's own. -/
def fires (c : Ctx) (seen : List Key) (l : Line) : Reason → Bool
  | .CAP_MEMBER_MONTH_DUPLICATE => isCap l && seen.contains (key l)
  | .FFS_DUPLICATE_LINE => !isCap l && seen.contains (key l)
  | .MEMBER_DECEASED => (entries c.dmf).any fun d => d.id == l.member && d.date < l.date
  | .MEMBER_NOT_ENROLLED => !(entries c.enrollment).any (covers l)
  | .PROVIDER_DECEASED => (entries c.providerDeaths).any fun d => party l d.id && d.date < l.date
  | .PROVIDER_EXCLUDED => (entries c.exclusions).any fun e =>
      party l e.id && e.start ≤ l.date && l.date ≤ e.stop
  | .STALE_DMF => !fresh c.today 90 c.dmf
  | .STALE_ENROLLMENT => !fresh c.today 7 c.enrollment
  | .STALE_EXCLUSION => !fresh c.today 31 c.exclusions
  | .STALE_PROVIDER_DEATH => !fresh c.today 90 c.providerDeaths

def stale : Reason → Bool
  | .STALE_DMF | .STALE_ENROLLMENT | .STALE_EXCLUSION | .STALE_PROVIDER_DEATH => true
  | _ => false

def outcomeOf (rs : List Reason) : Outcome :=
  if rs.isEmpty then .ALLOW else if rs.any stale then .HUMAN_REVIEW else .HOLD

structure Decision where
  line : Line
  outcome : Outcome
  reasons : List Reason
  deriving DecidableEq, Repr

def decideLine (c : Ctx) (seen : List Key) (l : Line) : Decision :=
  let rs := reasons.filter (fires c seen l)
  { line := l, outcome := outcomeOf rs, reasons := rs }

/-- Lines in order; each line's key is seen by every later line, whatever its outcome. -/
def decideAll (c : Ctx) : List Key → List Line → List Decision
  | _, [] => []
  | seen, l :: ls => decideLine c seen l :: decideAll c (key l :: seen) ls

def enc (l : Line) : List Nat :=
  [l.flow.tag, l.member, l.payee, l.rendering, l.date, l.proc, l.units, l.cents]

def lineLe (x y : Line) : Bool := decide (enc x ≤ enc y)

/-- Canonical order: lexicographic on `enc`; arrival order is forgotten. -/
def canonical (batch : List Line) : List Line := batch.mergeSort lineLe

def allowedKeys (ds : List Decision) : List Key :=
  (ds.filter (·.outcome == .ALLOW)).map (key ·.line)

structure Result where
  decisions : List Decision
  released : List Key
  deriving DecidableEq

/-- One batch against the released set; only ALLOW lines join it. -/
def decideBatch (c : Ctx) (released : List Key) (batch : List Line) : Result :=
  let ds := decideAll c released (canonical batch)
  { decisions := ds, released := released ++ allowedKeys ds }

end BlindLedger.Gate.Rules
