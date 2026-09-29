namespace BlindLedger.Gate.Rules

/-! Payment gate decision rules v1: whether a payment line is ALLOW, HOLD or
    HUMAN_REVIEW on the merits.  Checks run over pinned reference snapshots and
    the pinned released and unresolved sets; each check that fires adds its
    reason code.

    Keys.  Every line has an identity (`id`, unique per line as submitted), an
    exact key (member, billing party or plan, date, procedure, units, cents)
    and a near key: (member, rendering party, date, procedure) for FFS, the
    member-month for CAP_820.  A line claims all three for the lines after it,
    whatever its outcome, except that a CAP_820 line whose member is known not
    to be enrolled with that plan claims no member-month, so a line for the
    wrong plan never blocks the real one.

    - R1 `MEMBER_DECEASED`: the member's Death Master File date of death is
      before the service date (FFS) or the service-period start (CAP_820).
    - R2 `CAP_MEMBER_MONTH_DUPLICATE`: a CAP_820 line's exact key or
      member-month is already released or claimed by an earlier line of the
      batch in canonical order, or the member has spans with two plans that
      overlap in that month (then every capitation line for it holds: the gate
      never picks a plan).
    - R3 `PROVIDER_EXCLUDED` / `PROVIDER_DECEASED`: the payee or rendering
      party is on the exclusion snapshot (LEIE, SAM or state list) on the
      service date, or on the provider death list with a date of death before it.
    - R4 `FFS_DUPLICATE_LINE`: an FFS line's exact key is already released or
      claimed earlier.  `FFS_NEAR_DUPLICATE`: not that, but its near key is,
      whoever bills and whatever the units or amount; a person decides, since
      legitimate repeats exist.
    - R5 `MEMBER_NOT_ENROLLED`: no enrollment span covers the date; for
      CAP_820 the span must also be with the paying plan.
    - `ALREADY_DECIDED`: the line's identity is already released, unresolved
      or used earlier in the batch.  Such a line joins neither set.
    - `DUPLICATE_OF_UNRESOLVED`: the exact key (or, for CAP_820, the
      member-month) is claimed by a line of the unresolved set.
      `COLLIDES_WITH_UNRESOLVED_NEAR`: not that, but an FFS near key is.  The
      decision lists the identities of the released and unresolved lines it
      shares a key with (`counterparts`); an earlier line of the same batch is
      not listed.
    - `FFS_DUPLICATE_UNVERIFIED`: an FFS line's exact key is that of a row an
      unchained set shows outside the gate's view (`loose`).  Review only; the
      row is listed in `counterparts`, as is any loose row sharing a key.

    The certain reasons (R1 to R5, the duplicates, `ALREADY_DECIDED`) make the
    line HOLD, whatever else it carries.  R1, R3, R5 and R2's plan overlap
    fire only on a usable snapshot and a valid service date.  The duplicates
    and `ALREADY_DECIDED` read the gate's view of each set: the set read when
    it is chained, else the gate's own checkpoint of it, never an unchained
    set's rows.  So no HOLD rests on unusable data.  The rest make it
    HUMAN_REVIEW: a near duplicate, a near collision, what an unchained set's
    own rows show, `SERVICE_DATE_INVALID`
    (not a calendar date), `SERVICE_DATE_FUTURE` (after today), `STALE_*`: a
    reference snapshot that is missing, failing its pin, dated on an invalid
    day or after an invalid or valid today, older than its maximum age, empty,
    not holding exactly its declared row count, or with a row whose dates are
    invalid or reversed or a death dated after the snapshot; `STALE_RELEASED` /
    `STALE_UNRESOLVED`: that set is missing, not exactly its declared count,
    dated on an invalid day, after today or before the gate's checkpoint, or
    not extending the checkpoint's lines; and `*_UNVERIFIED`: a present but
    unusable snapshot still shows R1, R3 or R5's fact for a valid service
    date, so the reviewer sees it.
    No rule yields BLOCK: blocking stays a human or state action.

    The released set is every line already paid by any path, including lines
    a person released from HUMAN_REVIEW.  The unresolved set holds the gate's
    HOLD and HUMAN_REVIEW lines, enrolled or not, until a person releases or
    rejects them; the gate adds each identity to at most one of the two.  Both
    are append-only in v1: each extends the gate's own checkpoint of it
    (`releasedPrior`, `unresolvedPrior`), a REQUIRED trusted input that no
    component supplies yet (see STATUS).  After each batch the
    next checkpoint is the view plus the batch's own additions (`advance`),
    whether or not the set read was chained, so a store that rolls back or
    drops those additions no longer chains.  Moving a line out of the
    unresolved set is the release path's (see STATUS).

    Mapping onto the token (`BlindLedger.Gate.Spec`, gate-v1; not imported):
    `Flow.tag` and the outcome names equal the wire's `WireFlow` and
    `WireOutcome`; `reasons` lists the codes in ascending byte order, as the
    leaf's `reasonCodes` requires.  One `Line` is one canonical line of
    `Request.lines` (`pLine`: flow tag, line id, 32-byte member key, payee,
    rendering party, u32 date, procedure, u32 units, u64 cents); `id`,
    `member`, `payee`, `rendering` and `proc` are those identifiers and the
    member key read as big-endian naturals after a 0x01 byte, which is
    injective.  The request decoder binds every line to the payment's flow,
    member and payee and their sum to its amount, an FFS_CLAIM carries its
    lines, and `lines_root` commits to exactly the lines decided here.  The
    payment is ALLOW when every line is; a held line leaves the cycle.
    Snapshot and set pins (SHA3-512 of `RR/GATE/SNAPSHOT/v1`,
    `RR/GATE/RELEASED/v1` or `RR/GATE/UNRESOLVED/v1` and a NUL, then kind,
    date, declared count and rows) join the token's read-set digest; the
    released and unresolved pins after a batch are the checkpoint's state
    digest (`RR/GATE/STATE/v1`), whose producer is not built.  Dates
    are CCYYMMDD naturals (X12 D8), so on valid dates `<` is calendar order.
    Synthetic, nonpayment, activation=false. -/

inductive Flow | FFS_CYCLE | FFS_CLAIM | CAP_820 deriving DecidableEq, Repr

def Flow.tag : Flow → Nat
  | .FFS_CYCLE => 1 | .FFS_CLAIM => 2 | .CAP_820 => 3

inductive Outcome | ALLOW | HOLD | HUMAN_REVIEW deriving DecidableEq, Repr

inductive Reason
  | ALREADY_DECIDED | CAP_MEMBER_MONTH_DUPLICATE | COLLIDES_WITH_UNRESOLVED_NEAR | DUPLICATE_OF_UNRESOLVED
  | FFS_DUPLICATE_LINE | FFS_DUPLICATE_UNVERIFIED | FFS_NEAR_DUPLICATE | MEMBER_DECEASED | MEMBER_DECEASED_UNVERIFIED
  | MEMBER_NOT_ENROLLED | MEMBER_NOT_ENROLLED_UNVERIFIED | PROVIDER_DECEASED | PROVIDER_DECEASED_UNVERIFIED
  | PROVIDER_EXCLUDED | PROVIDER_EXCLUDED_UNVERIFIED | SERVICE_DATE_FUTURE | SERVICE_DATE_INVALID | STALE_DMF
  | STALE_ENROLLMENT | STALE_EXCLUSION | STALE_PROVIDER_DEATH | STALE_RELEASED | STALE_UNRESOLVED
  deriving DecidableEq, Repr

/-- Every code once, in ascending byte order of its name (the runner's `#guard` checks the order). -/
def reasons : List Reason :=
  [.ALREADY_DECIDED, .CAP_MEMBER_MONTH_DUPLICATE, .COLLIDES_WITH_UNRESOLVED_NEAR, .DUPLICATE_OF_UNRESOLVED,
   .FFS_DUPLICATE_LINE, .FFS_DUPLICATE_UNVERIFIED, .FFS_NEAR_DUPLICATE, .MEMBER_DECEASED, .MEMBER_DECEASED_UNVERIFIED,
   .MEMBER_NOT_ENROLLED, .MEMBER_NOT_ENROLLED_UNVERIFIED, .PROVIDER_DECEASED, .PROVIDER_DECEASED_UNVERIFIED,
   .PROVIDER_EXCLUDED, .PROVIDER_EXCLUDED_UNVERIFIED, .SERVICE_DATE_FUTURE, .SERVICE_DATE_INVALID, .STALE_DMF,
   .STALE_ENROLLMENT, .STALE_EXCLUSION, .STALE_PROVIDER_DEATH, .STALE_RELEASED, .STALE_UNRESOLVED]

/-- For CAP_820, `payee` and `rendering` are the plan and `date` is the first
    day of the service period. -/
structure Line where
  id : Nat
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
  deriving DecidableEq

/-- The read set: `none` is missing (or failed its pin).  The priors are the
    gate's checkpoints of the two sets (genesis: date 0, no lines). -/
structure Ctx where
  today : Nat
  dmf : Option (Snapshot Death)
  providerDeaths : Option (Snapshot Death)
  exclusions : Option (Snapshot Exclusion)
  enrollment : Option (Snapshot Span)
  released : Option (Snapshot Line)
  unresolved : Option (Snapshot Line)
  releasedPrior : Snapshot Line
  unresolvedPrior : Snapshot Line

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

/-- A row is well formed on a snapshot dated `asOf`: a death is dated on a valid day not after it. -/
def okDeath (asOf : Nat) (d : Death) : Bool := validDate d.date && d.date ≤ asOf

def okExclusion (_ : Nat) (e : Exclusion) : Bool := validDate e.start && validDate e.stop && e.start ≤ e.stop

def okSpan (_ : Nat) (s : Span) : Bool := validDate s.start && validDate s.stop && s.start ≤ s.stop

/-- Present, dated on a valid day not after a valid today, at most `maxAge`
    days old, holding exactly its declared, nonzero count of well-formed rows
    (a real death, exclusion or enrollment list is never empty). -/
def usable {α : Type} (today maxAge : Nat) (ok : Nat → α → Bool) : Option (Snapshot α) → Bool
  | none => false
  | some s => validDate today && validDate s.asOf && s.asOf ≤ today &&
      dayNum today ≤ dayNum s.asOf + maxAge && s.entries.length == s.count && 0 < s.count &&
      s.entries.all (ok s.asOf)

/-- The released or unresolved set: present with exactly its declared count
    (it may be empty), dated on a valid day not after today nor before the
    checkpoint `prior`, and extending the checkpoint's lines. -/
def chained (today : Nat) (prior : Snapshot Line) : Option (Snapshot Line) → Bool
  | none => false
  | some s => s.entries.length == s.count && validDate s.asOf && s.asOf ≤ today && prior.asOf ≤ s.asOf &&
      prior.entries.isPrefixOf s.entries

/-- The gate's view of a set: the set read when it is chained, else the gate's checkpoint of it. -/
def view (today : Nat) (prior : Snapshot Line) (o : Option (Snapshot Line)) : Snapshot Line :=
  if chained today prior o then o.getD prior else prior

/-- The gate's next checkpoint of a set: its view, then the batch's own additions, whether or not
    the set read was chained. -/
def advance (today : Nat) (prior : Snapshot Line) (o : Option (Snapshot Line)) (adds : List Line) :
    Snapshot Line :=
  let v := view today prior o
  ⟨v.asOf, v.entries.length + adds.length, v.entries ++ adds⟩

/-- The rows a set read shows outside the gate's view: none when it is chained (the view is the set
    read), else those not in the checkpoint (the view). -/
def loose (today : Nat) (prior : Snapshot Line) (o : Option (Snapshot Line)) : List Line :=
  if chained today prior o then [] else (entries o).filter fun x => !prior.entries.contains x

def releasedSet (c : Ctx) : List Line := (view c.today c.releasedPrior c.released).entries

def unresolvedSet (c : Ctx) : List Line := (view c.today c.unresolvedPrior c.unresolved).entries

abbrev Key := List Nat

def isCap (l : Line) : Bool := l.flow == .CAP_820

def exactKey (l : Line) : Key := [if isCap l then 3 else 1, l.member, l.payee, l.date, l.proc, l.units, l.cents]

def nearKey (l : Line) : Key := if isCap l then [0, l.member, l.date / 100] else [2, l.member, l.rendering, l.date, l.proc]

def idKey (l : Line) : Key := [4, l.id]

def keys (l : Line) : List Key := [exactKey l, nearKey l, idKey l]

def covers (l : Line) (s : Span) : Bool :=
  s.member == l.member && s.start ≤ l.date && l.date ≤ s.stop && (!isCap l || s.plan == l.payee)

def enrolled (c : Ctx) (l : Line) : Bool := (entries c.enrollment).any (covers l)

/-- A check on this snapshot is certain for the line: the snapshot is usable and the date valid. -/
def certain {α : Type} (c : Ctx) (maxAge : Nat) (ok : Nat → α → Bool) (o : Option (Snapshot α)) (l : Line) :
    Bool :=
  usable c.today maxAge ok o && validDate l.date

/-- A check on this snapshot is not certain, but the snapshot is present and the date valid. -/
def unverified {α : Type} (c : Ctx) (maxAge : Nat) (ok : Nat → α → Bool) (o : Option (Snapshot α))
    (l : Line) : Bool :=
  o.isSome && !usable c.today maxAge ok o && validDate l.date

def party (l : Line) (id : Nat) : Bool := id == l.payee || id == l.rendering

/-- The facts of R1 and R3 as the rows show them. -/
def memberDead (c : Ctx) (l : Line) : Bool := (entries c.dmf).any fun d => d.id == l.member && d.date < l.date

def providerDead (c : Ctx) (l : Line) : Bool :=
  (entries c.providerDeaths).any fun d => party l d.id && d.date < l.date

def excluded (c : Ctx) (l : Line) : Bool :=
  (entries c.exclusions).any fun e => party l e.id && e.start ≤ l.date && l.date ≤ e.stop

def notEnrolled (c : Ctx) (l : Line) : Bool := certain c 7 okSpan c.enrollment l && !enrolled c l

/-- The member has spans with two plans that share a day of the line's month. -/
def overlap (c : Ctx) (l : Line) : Bool :=
  let first := l.date / 100 * 100 + 1
  let last := l.date / 100 * 100 + monthDays (l.date / 10000) (l.date / 100 % 100)
  let ss := (entries c.enrollment).filter (·.member == l.member)
  ss.any fun s => ss.any fun t =>
    s.plan != t.plan && max first (max s.start t.start) ≤ min last (min s.stop t.stop)

/-- The keys a line claims for the lines after it, whatever its outcome. -/
def claim (c : Ctx) (l : Line) : List Key := if isCap l && notEnrolled c l then [exactKey l, idKey l] else keys l

/-- The keys claimed by the unresolved set. -/
def pending (c : Ctx) : List Key := (unresolvedSet c).flatMap (claim c)

/-- The exact keys of both sets' `loose` rows. -/
def looseKeys (c : Ctx) : List Key :=
  (loose c.today c.releasedPrior c.released ++ loose c.today c.unresolvedPrior c.unresolved).map exactKey

/-- The rule table.  Maximum ages: DMF and provider deaths 90 days (H.R.1
    §§71104-71105 quarterly minimum); exclusions 31 days (42 CFR 455.436
    monthly checks); enrollment 7 days, a placeholder for the state's own. -/
def fires (c : Ctx) (seen : List Key) (l : Line) : Reason → Bool
  | .ALREADY_DECIDED => seen.contains (idKey l) || (pending c).contains (idKey l)
  | .CAP_MEMBER_MONTH_DUPLICATE => isCap l &&
      (seen.contains (exactKey l) || seen.contains (nearKey l) || certain c 7 okSpan c.enrollment l && overlap c l)
  | .COLLIDES_WITH_UNRESOLVED_NEAR =>
      !isCap l && (pending c).contains (nearKey l) && !(pending c).contains (exactKey l)
  | .DUPLICATE_OF_UNRESOLVED => (pending c).contains (exactKey l) || isCap l && (pending c).contains (nearKey l)
  | .FFS_DUPLICATE_LINE => !isCap l && seen.contains (exactKey l)
  | .FFS_DUPLICATE_UNVERIFIED => !isCap l && (looseKeys c).contains (exactKey l)
  | .FFS_NEAR_DUPLICATE => !isCap l && seen.contains (nearKey l) && !seen.contains (exactKey l)
  | .MEMBER_DECEASED => certain c 90 okDeath c.dmf l && memberDead c l
  | .MEMBER_DECEASED_UNVERIFIED => unverified c 90 okDeath c.dmf l && memberDead c l
  | .MEMBER_NOT_ENROLLED => notEnrolled c l
  | .MEMBER_NOT_ENROLLED_UNVERIFIED => unverified c 7 okSpan c.enrollment l && !enrolled c l
  | .PROVIDER_DECEASED => certain c 90 okDeath c.providerDeaths l && providerDead c l
  | .PROVIDER_DECEASED_UNVERIFIED => unverified c 90 okDeath c.providerDeaths l && providerDead c l
  | .PROVIDER_EXCLUDED => certain c 31 okExclusion c.exclusions l && excluded c l
  | .PROVIDER_EXCLUDED_UNVERIFIED => unverified c 31 okExclusion c.exclusions l && excluded c l
  | .SERVICE_DATE_FUTURE => c.today < l.date
  | .SERVICE_DATE_INVALID => !validDate l.date
  | .STALE_DMF => !usable c.today 90 okDeath c.dmf
  | .STALE_ENROLLMENT => !usable c.today 7 okSpan c.enrollment
  | .STALE_EXCLUSION => !usable c.today 31 okExclusion c.exclusions
  | .STALE_PROVIDER_DEATH => !usable c.today 90 okDeath c.providerDeaths
  | .STALE_RELEASED => !chained c.today c.releasedPrior c.released
  | .STALE_UNRESOLVED => !chained c.today c.unresolvedPrior c.unresolved

/-- Reasons a person must look at: bad or unusable data, what it still shows, or a near duplicate or
    collision. -/
def review : Reason → Bool
  | .COLLIDES_WITH_UNRESOLVED_NEAR | .FFS_NEAR_DUPLICATE | .SERVICE_DATE_FUTURE | .SERVICE_DATE_INVALID
  | .STALE_DMF | .STALE_ENROLLMENT | .STALE_EXCLUSION | .STALE_PROVIDER_DEATH | .STALE_RELEASED
  | .STALE_UNRESOLVED | .MEMBER_DECEASED_UNVERIFIED | .MEMBER_NOT_ENROLLED_UNVERIFIED
  | .PROVIDER_DECEASED_UNVERIFIED | .PROVIDER_EXCLUDED_UNVERIFIED | .FFS_DUPLICATE_UNVERIFIED => true
  | _ => false

/-- A certain reason outranks every review reason. -/
def outcomeOf (rs : List Reason) : Outcome :=
  if rs.isEmpty then .ALLOW else if rs.any (!review ·) then .HOLD else .HUMAN_REVIEW

structure Decision where
  line : Line
  outcome : Outcome
  reasons : List Reason
  /-- Identities of the released lines sharing a key with the line, then the unresolved lines whose
      claim does; each set's view first, then its `loose` rows. -/
  counterparts : List Nat
  deriving DecidableEq, Repr

def decideLine (c : Ctx) (seen : List Key) (l : Line) : Decision :=
  let rs := reasons.filter (fires c seen l)
  { line := l, outcome := outcomeOf rs, reasons := rs,
    counterparts := ((releasedSet c ++ loose c.today c.releasedPrior c.released).filter
      (fun x => (keys l).any (keys x).contains) ++ (unresolvedSet c ++ loose c.today c.unresolvedPrior
      c.unresolved).filter fun x => (keys l).any (claim c x).contains).map (·.id) }

def decideAll (c : Ctx) : List Key → List Line → List Decision
  | _, [] => []
  | seen, l :: ls => decideLine c seen l :: decideAll c (claim c l ++ seen) ls

def enc (l : Line) : List Nat :=
  [l.flow.tag, l.member, l.payee, l.rendering, l.date, l.proc, l.units, l.cents, l.id]

def lineLe (x y : Line) : Bool := decide (enc x ≤ enc y)

/-- Canonical order: lexicographic on `enc`; arrival order is forgotten. -/
def canonical (batch : List Line) : List Line := batch.mergeSort lineLe

def allowedLines (ds : List Decision) : List Line :=
  (ds.filter (·.outcome == .ALLOW)).map (·.line)

/-- HOLD and HUMAN_REVIEW lines with a new identity: they stay open until a person acts. -/
def unresolvedLines (ds : List Decision) : List Line :=
  (ds.filter fun d => d.outcome != .ALLOW && !d.reasons.contains .ALREADY_DECIDED).map (·.line)

/-- The decisions and the gate's next checkpoints of the two sets. -/
structure Result where
  decisions : List Decision
  released : Snapshot Line
  unresolved : Snapshot Line
  deriving DecidableEq

/-- One batch against the read set: ALLOW lines join the released set, the
    other lines with a new identity join the unresolved set. -/
def decideBatch (c : Ctx) (batch : List Line) : Result :=
  let ds := decideAll c ((releasedSet c).flatMap keys) (canonical batch)
  { decisions := ds, released := advance c.today c.releasedPrior c.released (allowedLines ds),
    unresolved := advance c.today c.unresolvedPrior c.unresolved (unresolvedLines ds) }

end BlindLedger.Gate.Rules
