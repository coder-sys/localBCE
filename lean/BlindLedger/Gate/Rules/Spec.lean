namespace BlindLedger.Gate.Rules

/-! Payment gate decision rules v1: whether a payment line is ALLOW, HOLD or
    HUMAN_REVIEW on the merits.  Checks run over pinned reference snapshots and
    the pinned released set; each check that fires adds its reason code.

    - R1 `MEMBER_DECEASED`: the member's Death Master File date of death is
      before the service date (FFS) or the service-period start (CAP_820).
    - R2 `CAP_MEMBER_MONTH_DUPLICATE`: a CAP_820 line's (member, month) is
      already released or claimed by an earlier line of the batch in canonical
      order, or the member has spans with two plans that overlap in that month
      (then every capitation line for it holds: the gate never picks a plan).
    - R3 `PROVIDER_EXCLUDED` / `PROVIDER_DECEASED`: the payee or rendering
      party is on the exclusion snapshot (LEIE, SAM or
      state list) on the service date, or on the provider death list with a
      date of death before it.
    - R4 `FFS_DUPLICATE_LINE`: an FFS line's (member, billing provider, date,
      procedure, units, cents) is already released or claimed earlier.
      `FFS_NEAR_DUPLICATE`: not that, but its (member, rendering party, date,
      procedure) is, whoever bills and whatever the units or amount; a person
      decides, since legitimate repeats exist.
    - R5 `MEMBER_NOT_ENROLLED`: no enrollment span covers the date; for
      CAP_820 the span must also be with the paying plan.  Such a line claims
      no key, so a line for a plan the member is not in never blocks the real one.

    Bad or unusable data never becomes ALLOW.  `SERVICE_DATE_INVALID` (not a
    calendar date) and `SERVICE_DATE_FUTURE` (after today) review the line.
    `STALE_*` marks a reference snapshot that is not usable: missing, failing
    its pin, dated on an invalid day or after an invalid or valid today, older
    than its maximum age, empty, not holding exactly its declared row count, or
    with a row whose dates are invalid or reversed.  `STALE_RELEASED` marks a
    released set that is missing or short of its declared count.  Any of these,
    or a near duplicate, makes the line HUMAN_REVIEW; any other reason, HOLD.
    No rule yields BLOCK: blocking stays a human or state action.

    The released set is every line already paid by any path, including lines
    a person released from HUMAN_REVIEW; the uniqueness theorem assumes it is
    complete.  Only ALLOW lines join it here.

    Mapping onto the token (`BlindLedger.Gate.Spec`, gate-v1; not imported):
    `Flow.tag` and the outcome names equal the token's; `reasons` lists the
    codes in ascending byte order, as the leaf's `reasonCodes` requires.  One
    `Line` becomes one canonical line leaf of `Request.lines` (flow tag, then
    each field; identifiers are the u16-length identifiers read as big-endian
    naturals after a 0x01 byte, which is injective), so `lines_root` commits
    to exactly the lines decided here.  The payment is ALLOW when every line
    is; a held line leaves the cycle.  Snapshot and released-set pins
    (SHA3-512 under `RR/GATE/SNAPSHOT/v1` and `RR/GATE/RELEASED/v1` over kind,
    date, declared count and rows) join the token's read-set digest.  Dates
    are CCYYMMDD naturals (X12 D8), so on valid dates `<` is calendar order.
    Synthetic, nonpayment, activation=false. -/

inductive Flow | FFS_CYCLE | FFS_CLAIM | CAP_820 deriving DecidableEq, Repr

def Flow.tag : Flow → Nat
  | .FFS_CYCLE => 1 | .FFS_CLAIM => 2 | .CAP_820 => 3

inductive Outcome | ALLOW | HOLD | HUMAN_REVIEW deriving DecidableEq, Repr

inductive Reason
  | CAP_MEMBER_MONTH_DUPLICATE | FFS_DUPLICATE_LINE | FFS_NEAR_DUPLICATE | MEMBER_DECEASED
  | MEMBER_NOT_ENROLLED | PROVIDER_DECEASED | PROVIDER_EXCLUDED | SERVICE_DATE_FUTURE
  | SERVICE_DATE_INVALID | STALE_DMF | STALE_ENROLLMENT | STALE_EXCLUSION | STALE_PROVIDER_DEATH
  | STALE_RELEASED
  deriving DecidableEq, Repr

/-- Every code once, in ascending byte order of its name (the runner's `#guard` checks the order). -/
def reasons : List Reason :=
  [.CAP_MEMBER_MONTH_DUPLICATE, .FFS_DUPLICATE_LINE, .FFS_NEAR_DUPLICATE, .MEMBER_DECEASED,
   .MEMBER_NOT_ENROLLED, .PROVIDER_DECEASED, .PROVIDER_EXCLUDED, .SERVICE_DATE_FUTURE,
   .SERVICE_DATE_INVALID, .STALE_DMF, .STALE_ENROLLMENT, .STALE_EXCLUSION, .STALE_PROVIDER_DEATH,
   .STALE_RELEASED]

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

/-- A pinned input: its date, its declared row count, and the rows read. -/
structure Snapshot (α : Type) where
  asOf : Nat
  count : Nat
  entries : List α

/-- The read set: `none` is missing (or failed its pin). -/
structure Ctx where
  today : Nat
  dmf : Option (Snapshot Death)
  providerDeaths : Option (Snapshot Death)
  exclusions : Option (Snapshot Exclusion)
  enrollment : Option (Snapshot Span)
  released : Option (Snapshot Line)

def entries {α : Type} (o : Option (Snapshot α)) : List α := (o.map (·.entries)).getD []

def leap (y : Nat) : Bool := y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)

def monthDays (y m : Nat) : Nat :=
  if m == 2 then (if leap y then 29 else 28) else if m == 4 || m == 6 || m == 9 || m == 11 then 30 else 31

/-- A calendar date CCYYMMDD, years 0001-9999 (proleptic Gregorian). -/
def validDate (d : Nat) : Bool :=
  let y := d / 10000
  let m := d / 100 % 100
  0 < y && y ≤ 9999 && 0 < m && m ≤ 12 && 0 < d % 100 && d % 100 ≤ monthDays y m

/-- Days from 0000-03-01 to a valid CCYYMMDD date. -/
def dayNum (d : Nat) : Nat :=
  let m := d / 100 % 100
  let y := d / 10000 - (if m ≤ 2 then 1 else 0)
  let mp := if m > 2 then m - 3 else m + 9
  y * 365 + y / 4 - y / 100 + y / 400 + (153 * mp + 2) / 5 + d % 100 - 1

def okDeath (d : Death) : Bool := validDate d.date

def okExclusion (e : Exclusion) : Bool := validDate e.start && validDate e.stop && e.start ≤ e.stop

def okSpan (s : Span) : Bool := validDate s.start && validDate s.stop && s.start ≤ s.stop

/-- Present, dated on a valid day not after a valid today, at most `maxAge`
    days old, holding exactly its declared, nonzero count of well-formed rows
    (a real death, exclusion or enrollment list is never empty). -/
def usable {α : Type} (today maxAge : Nat) (ok : α → Bool) : Option (Snapshot α) → Bool
  | none => false
  | some s => validDate today && validDate s.asOf && s.asOf ≤ today &&
      dayNum today ≤ dayNum s.asOf + maxAge && s.entries.length == s.count && 0 < s.count &&
      s.entries.all ok

/-- The released set is present with exactly its declared count (it may be empty). -/
def whole : Option (Snapshot Line) → Bool
  | none => false
  | some s => s.entries.length == s.count

/-- Duplicate keys: member-month for CAP_820 (any plan); the exact billed line
    for FFS (either FFS flow), and its near key (member, rendering party, date,
    procedure). -/
abbrev Key := List Nat

def key (l : Line) : Key :=
  if l.flow = .CAP_820 then [0, l.member, l.date / 100]
  else [1, l.member, l.payee, l.date, l.proc, l.units, l.cents]

def nearKey (l : Line) : Key := [2, l.member, l.rendering, l.date, l.proc]

def keys (l : Line) : List Key := if l.flow = .CAP_820 then [key l] else [key l, nearKey l]

def isCap (l : Line) : Bool := l.flow == .CAP_820

def covers (l : Line) (s : Span) : Bool :=
  s.member == l.member && s.start ≤ l.date && l.date ≤ s.stop && (!isCap l || s.plan == l.payee)

def enrolled (c : Ctx) (l : Line) : Bool := (entries c.enrollment).any (covers l)

/-- The member has spans with two plans that share a day of the line's month. -/
def overlap (c : Ctx) (l : Line) : Bool :=
  let first := l.date / 100 * 100 + 1
  let last := l.date / 100 * 100 + monthDays (l.date / 10000) (l.date / 100 % 100)
  let ss := (entries c.enrollment).filter (·.member == l.member)
  ss.any fun s => ss.any fun t =>
    s.plan != t.plan && max first (max s.start t.start) ≤ min last (min s.stop t.stop)

def party (l : Line) (id : Nat) : Bool := id == l.payee || id == l.rendering

/-- The rule table.  Maximum ages: DMF and provider deaths 90 days (H.R.1
    §§71104-71105 quarterly minimum); exclusions 31 days (42 CFR 455.436
    monthly checks); enrollment 7 days, a placeholder for the state's own. -/
def fires (c : Ctx) (seen : List Key) (l : Line) : Reason → Bool
  | .CAP_MEMBER_MONTH_DUPLICATE => isCap l && (seen.contains (key l) || overlap c l)
  | .FFS_DUPLICATE_LINE => !isCap l && seen.contains (key l)
  | .FFS_NEAR_DUPLICATE => !isCap l && seen.contains (nearKey l) && !seen.contains (key l)
  | .MEMBER_DECEASED => (entries c.dmf).any fun d => d.id == l.member && d.date < l.date
  | .MEMBER_NOT_ENROLLED => !enrolled c l
  | .PROVIDER_DECEASED => (entries c.providerDeaths).any fun d => party l d.id && d.date < l.date
  | .PROVIDER_EXCLUDED => (entries c.exclusions).any fun e =>
      party l e.id && e.start ≤ l.date && l.date ≤ e.stop
  | .SERVICE_DATE_FUTURE => c.today < l.date
  | .SERVICE_DATE_INVALID => !validDate l.date
  | .STALE_DMF => !usable c.today 90 okDeath c.dmf
  | .STALE_ENROLLMENT => !usable c.today 7 okSpan c.enrollment
  | .STALE_EXCLUSION => !usable c.today 31 okExclusion c.exclusions
  | .STALE_PROVIDER_DEATH => !usable c.today 90 okDeath c.providerDeaths
  | .STALE_RELEASED => !whole c.released

/-- Reasons a person must look at: bad or unusable data, or a near duplicate. -/
def review : Reason → Bool
  | .FFS_NEAR_DUPLICATE | .SERVICE_DATE_FUTURE | .SERVICE_DATE_INVALID | .STALE_DMF
  | .STALE_ENROLLMENT | .STALE_EXCLUSION | .STALE_PROVIDER_DEATH | .STALE_RELEASED => true
  | _ => false

def outcomeOf (rs : List Reason) : Outcome :=
  if rs.isEmpty then .ALLOW else if rs.any review then .HUMAN_REVIEW else .HOLD

structure Decision where
  line : Line
  outcome : Outcome
  reasons : List Reason
  deriving DecidableEq, Repr

def decideLine (c : Ctx) (seen : List Key) (l : Line) : Decision :=
  let rs := reasons.filter (fires c seen l)
  { line := l, outcome := outcomeOf rs, reasons := rs }

/-- The keys a line claims for the lines after it, whatever its outcome;
    none when no span covers it (R5). -/
def claim (c : Ctx) (l : Line) : List Key := if enrolled c l then keys l else []

def decideAll (c : Ctx) : List Key → List Line → List Decision
  | _, [] => []
  | seen, l :: ls => decideLine c seen l :: decideAll c (claim c l ++ seen) ls

def enc (l : Line) : List Nat :=
  [l.flow.tag, l.member, l.payee, l.rendering, l.date, l.proc, l.units, l.cents]

def lineLe (x y : Line) : Bool := decide (enc x ≤ enc y)

/-- Canonical order: lexicographic on `enc`; arrival order is forgotten. -/
def canonical (batch : List Line) : List Line := batch.mergeSort lineLe

def allowedLines (ds : List Decision) : List Line :=
  (ds.filter (·.outcome == .ALLOW)).map (·.line)

structure Result where
  decisions : List Decision
  released : List Line
  deriving DecidableEq

/-- One batch against the read set; only ALLOW lines join the released set. -/
def decideBatch (c : Ctx) (batch : List Line) : Result :=
  let ds := decideAll c ((entries c.released).flatMap keys) (canonical batch)
  { decisions := ds, released := entries c.released ++ allowedLines ds }

end BlindLedger.Gate.Rules
