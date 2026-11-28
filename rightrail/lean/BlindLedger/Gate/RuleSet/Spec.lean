import BlindLedger.Gate.Authority
import BlindLedger.Gate.Scoped
import BlindLedger.Gate.CheckpointTheorems
import BlindLedger.Gate.ParseLaws
import BlindLedger.Gate.Rules.Theorems
import BlindLedger.Gate.FactBelief

namespace BlindLedger.Gate.RuleSet

open BlindLedger.Gate
open BlindLedger.Gate.Rules

/-! RULESET/v1: the decision rules as state-signed data under one interpreter (`conformance/RULESET_V1.md`,
    `docs/STATE_EVIDENCE_ARCHITECTURE.md` §6.3).

    A rule set is a signed record: a header (state, tenant, version chained to the previous version's digest, a
    signing window, an effective range of service dates, the earlier versions it ends), a table of legal sources, the
    maximum age of each reference source it reads, and up to 64 rules.  A rule names one reason code and a condition, a
    small boolean expression over fixed reads of the line and the reference snapshots.  The interpreter (`eval`) is
    structurally recursive, so it is total, and its cost per line (`costOf`) is computed from the record alone and
    bounded (`maxCost`).

    What stays fixed Lean, never data: the release-once and identity checks (`coreFires`: already decided, the exact
    and near duplicates against the released and unresolved sets, the line's own date checks, the staleness of the two
    sets), the outcome class of every reason (`Rules.review`), which reasons a bypass may override, the batch
    structure (`order`, `seen0`, release and unresolved sets), and the enrollment guard (`dataFires`): a feed older
    than the rule set's enrollment age (1 to `ceilEnrollment` days, `enrollDefault` if it declares none) sends the
    line to review, never to an allow and never, by itself, to a hold.  A rule set may fire only the thirteen fact reasons
    (`dataReason`); a rule for any other reason is refused when decoded, and `dataFires` ignores it in any case.

    Admission (`admit`): a POLICY quorum of the head's key set signed it (at least `kPolicy` distinct employees, each
    with a POLICY key live on the head's day; roster keys admit POLICY keys but never sign a rule set), inside its
    signing window, as the next version of the tenant's series, with an effective range that overlaps no range still in
    force.  Selection (`select`): a line runs under the one admitted rule set, known at the batch's known time, whose
    effective range holds the line's date.

    RULESET/v2 (`conformance/RULESET_V2.md`) is version 1 under its own tags plus the eligibility read: source 7, the
    member's eligibility facts (`FactBelief`, kind 1), with a maximum age; a table of aid codes, each listed as eligible
    for the program or as not eligible; a condition node that tests the read (`Expr.elig`); and the five eligibility
    reasons (`eligReason`), which only a version 2 record may fire.  Version 1 records decode and decide as before.
    Fixed for every version 2 record (`elGuard`): every rule for not eligible for the program, and a rule for another
    hold reason whose value depends on the eligibility read, holds a line only on a present answer read within the
    record's maximum age (`elig_guard_hold`); on any other read such a rule sends the line to review unless its
    condition is false whatever the read (`eval3`, `eval3_sound`, `evalAt_read`, `elig_guard_review`,
    `elig_guard_narrow`).  A rule for another hold reason whose condition is true whatever the read holds the line on
    any read.  The guard is about the read's freshness and presence only; which aid codes and statuses hold a line is
    the rule set's own content.
    The two benefit level reasons decode but are refused at admission (`NOSOURCE`) until a fact field carries a benefit
    level.  The read itself (`elRead`) is checked on a small fact corpus and is not yet carried by the engine.

    Every theorem here is proved, with no `sorry`.  Nothing in a pinned executable imports this module, so the live
    gate does not yet decide under a rule set.  Synthetic, nonpayment, activation=false. -/

/-! ## Bounds -/

def tag : Bytes := Authority.dom "RR/GATE/RULESET/v1"
def sigTag : Bytes := Authority.dom "RR/GATE/RULESET/v1/SIG"
def tag2 : Bytes := Authority.dom "RR/GATE/RULESET/v2"
def sigTag2 : Bytes := Authority.dom "RR/GATE/RULESET/v2/SIG"

/-- Aid codes in a version 2 record's table, and the bytes of one code (an eligibility fact's 21-byte block holds a
    length byte and up to 20 bytes). -/
def maxAids : Nat := 1024
def maxAidLen : Nat := 20

/-- The whole record, body and signature block, before any field is read. -/
def maxRecord : Nat := 131072
def maxEnds : Nat := 8
def maxCites : Nat := 32
def maxRules : Nat := 64
/-- Operands of one AND or OR. -/
def maxArity : Nat := 8
/-- Nesting of a condition, its root at depth 1. -/
def maxDepth : Nat := 8
/-- Cost units per line, all rules together (`costOf`). -/
def maxCost : Nat := 1024
/-- The open end of an effective range. -/
def openEnd : Nat := 99991231

/-! ## Reads -/

/-- The reference sources a condition reads; the bytes 1 to 4 are `SnapshotV2.Kind.byte`, and 7 is the member's
    eligibility facts (version 2 only). -/
inductive Src | DMF | PDEATH | EXCL | SPAN | ELIG deriving DecidableEq, Repr

def Src.byte : Src → Nat | .DMF => 1 | .PDEATH => 2 | .EXCL => 3 | .SPAN => 4 | .ELIG => 7

def Src.ofByte : Nat → Option Src
  | 1 => some .DMF | 2 => some .PDEATH | 3 => some .EXCL | 4 => some .SPAN | 7 => some .ELIG | _ => none

/-- The product's ceiling on the enrollment feed's maximum age, in days: a state sets 1 to 10 in its rule set (an
    agency gives notice at least 10 days before a termination, 42 CFR 431.211, so a feed that new already shows most
    coming terminations). -/
def ceilEnrollment : Nat := 10

/-- The enrollment feed's maximum age when a rule set declares none (`Doc.enrollAge`). -/
def enrollDefault : Nat := 4

/-- The ceiling on a source's maximum age: deaths and exclusions at `Scoped.CEIL`, enrollment and eligibility at
    `ceilEnrollment`.  A rule set may tighten it, never raise it. -/
def Src.ceil : Src → Nat
  | .DMF => Scoped.ceilDmf | .PDEATH => Scoped.ceilProviderDeath | .EXCL => Scoped.ceilExclusion
  | .SPAN | .ELIG => ceilEnrollment

/-- Whose identifier a row must carry: the line's member, or its payee or rendering party. -/
inductive Subj | member | party deriving DecidableEq, Repr

/-- How a row's dates meet the line's date: a death before it, an interval holding it, or an interval holding it with
    the row's plan equal to the line's payee (capitation). -/
inductive Test | before | within | withinPlan deriving DecidableEq, Repr

/-- The (source, subject, test) triples a HIT may name; the row shape of each source decides. -/
def hitOk : Src → Subj → Test → Bool
  | .DMF, .member, .before | .PDEATH, .party, .before | .EXCL, .party, .within
  | .SPAN, .member, .within | .SPAN, .member, .withinPlan => true
  | _, _, _ => false

/-- A condition. -/
inductive Expr
  | and (es : List Expr)
  | or (es : List Expr)
  | not (e : Expr)
  /-- The line's flow is in the mask (bit `Flow.tag - 1`). -/
  | flow (mask : Nat)
  /-- The line's date is a calendar date. -/
  | dateOk
  /-- The source's snapshot was read (present, its pin matched). -/
  | present (s : Src)
  /-- The source's snapshot is usable at the rule set's maximum age for it (`Rules.usable`). -/
  | fresh (s : Src)
  /-- Some row of the source carries the subject and passes the test. -/
  | hit (s : Src) (subj : Subj) (t : Test)
  /-- The member has rows with two plans that share a day of the line's month (`Rules.overlap`). -/
  | overlap (s : Src)
  /-- The eligibility read (version 2): query 1, the answer is in the mask `a` (bit 0 present, 1 absent, 2 unknown,
      3 conflict); query 2, the answer is present and its status is in the mask (bit `status - 1`: 1 eligible, 2 not
      eligible, 3 pending, 4 presumptive); query 3, the answer is present and some cited aid code has class `a`
      (`aidClass`). -/
  | elig (q a : Nat)

/-- The member's eligibility as of one line (`elRead`): the belief's answer (0 present, 1 absent, 2 unknown,
    3 conflict), the status when present (else 0), the 21-byte aid-code blocks of the facts it cites, and the oldest
    as-of among the facts it cites (`none`: it cites none).  The default is the cautious one: unknown, nothing cited, no
    as-of. -/
structure ElRead where
  ans : Nat := 2
  status : Nat := 0
  aids : List Bytes := []
  asof : Option Nat := none

/-- The eligibility read of the member whose fact subject is `key`, for a line dated `D`, from the fact store as known
    at batch `K`: `FactBelief.belief` on kind 1 at minimum class `minCls` gives the answer and, when present, the status
    and the facts cited (their aid-code blocks); the as-of is the oldest receipt as-of among the cited facts, so a newer
    fact the answer does not rest on never makes it fresh (none when a cited fact's receipt is not known). -/
def elRead (fc : FactBelief.Ctx) (S : FactBelief.Store) (K minCls : Nat) (key : Bytes) (D : Nat) : ElRead :=
  let res := FactBelief.belief fc S K minCls 1 key D
  let known := S.upTo K
  let cited := known.rows.filter fun r => res.cites.contains r.seq
  { ans := match res with | .present .. => 0 | .absent => 1 | .unknown _ => 2 | .conflict => 3
    status := match res with | .present (st :: _) _ => st | _ => 0
    aids := cited.filterMap fun r => match r.fact.value with | .elig v => some v.aid | _ => none
    asof := (cited.mapM fun r => (known.recs.lookup r.fact.receipt).map (·.asof)).bind List.min? }

/-- What one line's conditions read: the batch's read set, the line, the rule set's maximum age per source, its aid
    table, and the line's eligibility read. -/
structure Env where
  c : Ctx
  l : Line
  age : Src → Nat
  aids : List (Bytes × Nat)
  el : ElRead

/-- The class of an aid-code block under the table: 1 listed eligible, 2 listed not eligible, 3 not listed or not a
    well-formed code (a length byte of at most 20, the code an identifier, zeros after it). -/
def aidClass (table : List (Bytes × Nat)) : Bytes → Nat
  | n :: t => if n.toNat ≤ maxAidLen && t.length == maxAidLen && (t.drop n.toNat).all (· == 0) &&
      identOk (t.take n.toNat) then (table.lookup (t.take n.toNat)).getD 3 else 3
  | [] => 3

def Env.present (v : Env) : Src → Bool
  | .DMF => v.c.dmf.isSome | .PDEATH => v.c.providerDeaths.isSome | .EXCL => v.c.exclusions.isSome
  | .SPAN => v.c.enrollment.isSome
  | .ELIG => v.el.asof.isSome

/-- Eligibility is fresh when the answer is present, its as-of is a date not after the batch's own date and the as-of
    plus the maximum age is not before the line's date (an as-of after the line's date is fresh; one after the batch's
    date is not).  An absent, unknown or conflicting answer is never fresh. -/
def Env.fresh (v : Env) : Src → Bool
  | .DMF => usable v.c.today (v.age .DMF) okDeath v.c.dmf
  | .PDEATH => usable v.c.today (v.age .PDEATH) okDeath v.c.providerDeaths
  | .EXCL => usable v.c.today (v.age .EXCL) okExclusion v.c.exclusions
  | .SPAN => usable v.c.today (v.age .SPAN) okSpan v.c.enrollment
  | .ELIG => match v.el.asof with
    | some a => v.el.ans == 0 && validDate a && validDate v.l.date && validDate v.c.today && a ≤ v.c.today &&
        dayNum v.l.date ≤ dayNum a + v.age .ELIG
    | none => false

def Env.elig (v : Env) (q a : Nat) : Bool :=
  if q = 1 then Keyset.bit a v.el.ans
  else if q = 2 then v.el.ans == 0 && 1 ≤ v.el.status && Keyset.bit a (v.el.status - 1)
  else v.el.ans == 0 && v.el.aids.any fun b => aidClass v.aids b == a

def subjOk (l : Line) : Subj → Nat → Bool
  | .member, id => id == l.member
  | .party, id => party l id

def Env.hit (v : Env) : Src → Subj → Test → Bool
  | .DMF, j, .before => (entries v.c.dmf).any fun d => subjOk v.l j d.id && d.date < v.l.date
  | .PDEATH, j, .before => (entries v.c.providerDeaths).any fun d => subjOk v.l j d.id && d.date < v.l.date
  | .EXCL, j, .within =>
      (entries v.c.exclusions).any fun e => subjOk v.l j e.id && e.start ≤ v.l.date && v.l.date ≤ e.stop
  | .SPAN, j, .within =>
      (entries v.c.enrollment).any fun s => subjOk v.l j s.member && s.start ≤ v.l.date && v.l.date ≤ s.stop
  | .SPAN, j, .withinPlan =>
      (entries v.c.enrollment).any fun s =>
        subjOk v.l j s.member && s.start ≤ v.l.date && v.l.date ≤ s.stop && s.plan == v.l.payee
  | _, _, _ => false

def Env.overlap (v : Env) : Src → Bool
  | .SPAN => Rules.overlap v.c v.l
  | _ => false

/-! ## The interpreter and its cost -/

mutual
def eval (v : Env) : Expr → Bool
  | .and es => evalAll v es
  | .or es => evalAny v es
  | .not e => !eval v e
  | .flow m => Keyset.bit m (v.l.flow.tag - 1)
  | .dateOk => validDate v.l.date
  | .present s => v.present s
  | .fresh s => v.fresh s
  | .hit s j t => v.hit s j t
  | .overlap s => v.overlap s
  | .elig q a => v.elig q a

def evalAll (v : Env) : List Expr → Bool
  | [] => true
  | e :: es => eval v e && evalAll v es

def evalAny (v : Env) : List Expr → Bool
  | [] => false
  | e :: es => eval v e || evalAny v es
end

mutual
/-- One unit per node, plus one per index probe: a member HIT or an OVERLAP probes once, a party HIT twice (payee and
    rendering party).  Independent of the input. -/
def cost : Expr → Nat
  | .and es => 1 + costAll es
  | .or es => 1 + costAll es
  | .not e => 1 + cost e
  | .hit _ .party _ => 3
  | .hit _ .member _ => 2
  | .overlap _ => 2
  | .flow _ => 1
  | .dateOk => 1
  | .present _ => 1
  | .fresh _ => 1
  | .elig _ _ => 2

def costAll : List Expr → Nat
  | [] => 0
  | e :: es => cost e + costAll es
end

mutual
/-- Whether a condition reads source `s` (PRESENT, FRESH, HIT or OVERLAP of it). -/
def reads (s : Src) : Expr → Bool
  | .and es => readsAny s es
  | .or es => readsAny s es
  | .not e => reads s e
  | .present t | .fresh t | .hit t _ _ | .overlap t => t == s
  | .elig _ _ => s == .ELIG
  | .flow _ | .dateOk => false

def readsAny (s : Src) : List Expr → Bool
  | [] => false
  | e :: es => reads s e || readsAny s es
end

mutual
/-- `eval` in three values (`none` unknown) with the eligibility read unknown: an atom that reads the eligibility source
    is unknown and every other atom has its value; AND is false when an operand is false, else unknown when one is
    unknown; OR is true when an operand is true, else unknown when one is unknown; NOT swaps true and false. -/
def eval3 (v : Env) : Expr → Option Bool
  | .and es => all3 v es
  | .or es => any3 v es
  | .not e => (eval3 v e).map (!·)
  | x@(.flow _) | x@.dateOk | x@(.present _) | x@(.fresh _) | x@(.hit ..) | x@(.overlap _) | x@(.elig ..) =>
    if reads .ELIG x then none else some (eval v x)

def all3 (v : Env) : List Expr → Option Bool
  | [] => some true
  | e :: es => match eval3 v e, all3 v es with
    | some false, _ | _, some false => some false
    | some true, r => r
    | none, _ => none

def any3 (v : Env) : List Expr → Option Bool
  | [] => some false
  | e :: es => match eval3 v e, any3 v es with
    | some true, _ | _, some true => some true
    | some false, r => r
    | none, _ => none
end

mutual
/-- `eval` with each atom that reads the eligibility source given the value `f` assigns it. -/
def evalAt (v : Env) (f : Expr → Bool) : Expr → Bool
  | .and es => allAt v f es
  | .or es => anyAt v f es
  | .not e => !evalAt v f e
  | x@(.flow _) | x@.dateOk | x@(.present _) | x@(.fresh _) | x@(.hit ..) | x@(.overlap _) | x@(.elig ..) =>
    if reads .ELIG x then f x else eval v x

def allAt (v : Env) (f : Expr → Bool) : List Expr → Bool
  | [] => true
  | e :: es => evalAt v f e && allAt v f es

def anyAt (v : Env) (f : Expr → Bool) : List Expr → Bool
  | [] => false
  | e :: es => evalAt v f e || anyAt v f es
end

mutual
/-- `eval`, counting the units it spends (AND and OR stop at the first operand that decides them). -/
def evalC (v : Env) : Expr → Bool × Nat
  | .and es => let r := allC v es; (r.1, r.2 + 1)
  | .or es => let r := anyC v es; (r.1, r.2 + 1)
  | .not e => let r := evalC v e; (!r.1, r.2 + 1)
  | .hit s .party t => (v.hit s .party t, 3)
  | .hit s .member t => (v.hit s .member t, 2)
  | .overlap s => (v.overlap s, 2)
  | .flow m => (Keyset.bit m (v.l.flow.tag - 1), 1)
  | .dateOk => (validDate v.l.date, 1)
  | .present s => (v.present s, 1)
  | .fresh s => (v.fresh s, 1)
  | .elig q a => (v.elig q a, 2)

def allC (v : Env) : List Expr → Bool × Nat
  | [] => (true, 0)
  | e :: es => let r := evalC v e; if r.1 then let q := allC v es; (q.1, r.2 + q.2) else (false, r.2)

def anyC (v : Env) : List Expr → Bool × Nat
  | [] => (false, 0)
  | e :: es => let r := evalC v e; if r.1 then (true, r.2) else let q := anyC v es; (q.1, r.2 + q.2)
end

/-! ## The record -/

/-- A legal source: kind (1 statute, 2 regulation, 3 state plan amendment, 4 waiver or demonstration, 5 contract,
    6 state policy, 7 court order), its reference, its date, and the SHA3-512 of the document. -/
structure Cite where
  kind : Nat
  ref : Bytes
  date : Nat
  doc : Bytes

structure Rule where
  reason : Reason
  /-- Index into the record's legal sources. -/
  cite : Nat
  cond : Expr

/-- An earlier version's effective range, cut to end on `to` (0: withdrawn for every date). -/
structure End where
  version : Nat
  to : Nat

structure Doc where
  state : Bytes
  tenantId : Bytes
  version : Nat
  /-- The digest of the previous version's body; zeros for version 1. -/
  prev : Bytes
  notBefore : Nat
  notAfter : Nat
  effFrom : Nat
  effTo : Nat
  ends : List End
  cites : List Cite
  ages : List (Src × Nat)
  rules : List Rule
  /-- Version 2 (`tag2`): it may read eligibility and fire the eligibility reasons. -/
  v2 : Bool
  /-- Version 2's aid table, ascending by code: each code with its class, 1 eligible for the program or 2 not. -/
  aids : List (Bytes × Nat)

structure Frame where
  d : Doc
  sigs : List Keyset.SigRec

/-- The fact reasons a rule set may fire.  Every other reason belongs to the fixed core. -/
def dataReason : Reason → Bool
  | .CAP_MEMBER_MONTH_DUPLICATE | .MEMBER_DECEASED | .MEMBER_DECEASED_UNVERIFIED | .MEMBER_NOT_ENROLLED
  | .MEMBER_NOT_ENROLLED_UNVERIFIED | .PROVIDER_DECEASED | .PROVIDER_DECEASED_UNVERIFIED | .PROVIDER_EXCLUDED
  | .PROVIDER_EXCLUDED_UNVERIFIED | .STALE_DMF | .STALE_ENROLLMENT | .STALE_EXCLUSION | .STALE_PROVIDER_DEATH => true
  | _ => false

/-- The eligibility reasons, which only a version 2 rule set may fire. -/
def eligReason : Reason → Bool
  | .BENEFIT_LEVEL_MISSING | .BENEFIT_LEVEL_MISSING_UNVERIFIED | .PROGRAM_NOT_ELIGIBLE
  | .PROGRAM_NOT_ELIGIBLE_UNVERIFIED | .STALE_ELIGIBILITY => true
  | _ => false

/-- The reasons a record may fire: the fact reasons, and under version 2 the eligibility reasons too. -/
def Doc.fires (d : Doc) (r : Reason) : Bool := dataReason r || d.v2 && eligReason r

/-- A source's maximum age in the record; 0 for a source it does not declare (the decoder refuses any read of one). -/
def Doc.age (d : Doc) (s : Src) : Nat := ((d.ages.find? (·.1 == s)).map (·.2)).getD 0

def Doc.env (d : Doc) (e : ElRead) (c : Ctx) (l : Line) : Env := ⟨c, l, d.age, d.aids, e⟩

/-- Cost units per line of the whole record. -/
def costOf (d : Doc) : Nat := (d.rules.map fun r => cost r.cond).sum

/-! ## Bytes -/

def subjByte : Subj → Nat | .member => 1 | .party => 2
def testByte : Test → Nat | .before => 1 | .within => 2 | .withinPlan => 3

def encSrc (s : Src) : Bytes := natBE 1 s.byte

mutual
def encExpr : Expr → Bytes
  | .and es => natBE 1 0x01 ++ natBE 1 es.length ++ encAll es
  | .or es => natBE 1 0x02 ++ natBE 1 es.length ++ encAll es
  | .not e => natBE 1 0x03 ++ encExpr e
  | .flow m => natBE 1 0x10 ++ natBE 1 m
  | .dateOk => natBE 1 0x11
  | .present s => natBE 1 0x20 ++ encSrc s
  | .fresh s => natBE 1 0x21 ++ encSrc s
  | .hit s j t => natBE 1 0x30 ++ encSrc s ++ natBE 1 (subjByte j) ++ natBE 1 (testByte t)
  | .overlap s => natBE 1 0x31 ++ encSrc s
  | .elig q a => natBE 1 0x22 ++ natBE 1 q ++ natBE 1 a

def encAll : List Expr → Bytes
  | [] => []
  | e :: es => encExpr e ++ encAll es
end

/-- Version 2's aid table, between the ages and the rules; nothing in version 1. -/
def encAids (v2 : Bool) (as : List (Bytes × Nat)) : Bytes :=
  if v2 then natBE 2 as.length ++ as.flatMap (fun a => identField a.1 ++ natBE 1 a.2) else []

def encDoc (d : Doc) : Bytes :=
  (if d.v2 then tag2 else tag) ++ d.state ++ identField d.tenantId ++ natBE 4 d.version ++ d.prev ++ natBE 4 d.notBefore ++
    natBE 4 d.notAfter ++ natBE 4 d.effFrom ++ natBE 4 d.effTo ++
    natBE 1 d.ends.length ++ d.ends.flatMap (fun e => natBE 4 e.version ++ natBE 4 e.to) ++
    natBE 1 d.cites.length ++ d.cites.flatMap (fun c => natBE 1 c.kind ++ identField c.ref ++ natBE 4 c.date ++ c.doc) ++
    natBE 1 d.ages.length ++ d.ages.flatMap (fun a => encSrc a.1 ++ natBE 2 a.2) ++ encAids d.v2 d.aids ++
    natBE 1 d.rules.length ++ d.rules.flatMap (fun r => natBE 1 r.reason.idx ++ natBE 1 r.cite ++ encExpr r.cond)

def encode (f : Frame) : Bytes := encDoc f.d ++ Keyset.encodeSigs f.sigs

/-- The rule set's identity: the next version's `prev`, the token leaf's `ruleVersion`, and what a decision record
    cites. -/
def digestOf (d : Doc) : Bytes := sha3 (encDoc d)

/-- What the signers sign. -/
def msgOf (f : Frame) : Bytes := sha3 ((if f.d.v2 then sigTag2 else sigTag) ++ encDoc f.d)

def pSrc : P Src := do
  match Src.ofByte (← nat 1 1 7) with
  | some s => pure s
  | none => fail

/-- A source the record's age table declares. -/
def pSrcIn (ok : List Src) : P Src := do
  let s ← pSrc
  need (ok.contains s)
  pure s

def pSubj : P Subj := do pure (if (← nat 1 1 2) = 1 then .member else .party)

def pTest : P Test := do
  let b ← nat 1 1 3
  pure (if b = 1 then .before else if b = 2 then .within else .withinPlan)

/-- A condition at most `n` levels deep, reading only the declared sources `ok`. -/
def pExpr (ok : List Src) : Nat → P Expr
  | 0 => fail
  | n + 1 => do
    let op ← nat 1
    if op = 0x01 then do let k ← nat 1 2 maxArity; pure (.and (← many (pExpr ok n) k))
    else if op = 0x02 then do let k ← nat 1 2 maxArity; pure (.or (← many (pExpr ok n) k))
    else if op = 0x03 then do pure (.not (← pExpr ok n))
    else if op = 0x10 then do pure (.flow (← nat 1 1 7))
    else if op = 0x11 then pure .dateOk
    else if op = 0x20 then do pure (.present (← pSrcIn ok))
    else if op = 0x21 then do pure (.fresh (← pSrcIn ok))
    else if op = 0x30 then do
      let s ← pSrcIn ok
      let j ← pSubj
      let t ← pTest
      need (hitOk s j t)
      pure (.hit s j t)
    else if op = 0x31 then do
      let s ← pSrcIn ok
      need (s == .SPAN)
      pure (.overlap s)
    else if op = 0x22 then do
      need (ok.contains .ELIG)
      let q ← nat 1 1 3
      let a ← nat 1 1 (if q = 3 then 3 else 15)
      pure (.elig q a)
    else fail

def pEnd : P End := do
  let v ← nat 4 1
  let t ← nat 4
  need (t == 0 || validDate t)
  pure ⟨v, t⟩

def pCite : P Cite := do
  let k ← nat 1 1 7
  let r ← ident
  let dt ← nat 4
  need (validDate dt)
  let h ← digest
  need (h != zeroDigest)
  pure ⟨k, r, dt, h⟩

/-- A maximum age; eligibility only in version 2. -/
def pAge (v2 : Bool) : P (Src × Nat) := do
  let s ← pSrc
  need (v2 || s != .ELIG)
  let a ← nat 2 1 s.ceil
  pure (s, a)

def pAid : P (Bytes × Nat) := do
  let c ← ident
  need (c.length ≤ maxAidLen)
  let k ← nat 1 1 2
  pure (c, k)

/-- Version 2's aid table: at most `maxAids` codes, strictly ascending. -/
def pAids (v2 : Bool) : P (List (Bytes × Nat)) :=
  if v2 then do
    let as ← many pAid (← nat 2 0 maxAids)
    need (ascending (as.map (·.1)))
    pure as
  else pure []

def reasonOf (b : Nat) : Option Reason := reasons.find? (·.idx == b)

def pRule (v2 : Bool) (ok : List Src) (nCites : Nat) : P Rule := do
  let b ← nat 1 0 (reasons.length - 1)
  match reasonOf b with
  | none => fail
  | some r =>
    need (dataReason r || v2 && eligReason r)
    let ci ← nat 1 0 (nCites - 1)
    let e ← pExpr ok maxDepth
    pure ⟨r, ci, e⟩

def ascBy {α : Type} (key : α → Nat) : List α → Bool
  | a :: b :: rest => key a < key b && ascBy key (b :: rest)
  | _ => true

def pDoc : P Doc := do
  let t ← take tag.length
  need (t == tag || t == tag2)
  let state ← digest
  let tenant ← ident
  let version ← nat 4 1
  let prev ← digest
  need ((version == 1) == (prev == zeroDigest))
  let nb ← nat 4
  let na ← nat 4
  need (Authority.spanOk nb na)
  let ef ← nat 4
  let et ← nat 4
  need (validDate ef && validDate et && ef ≤ et)
  let ends ← many pEnd (← nat 1 0 maxEnds)
  need (ascBy (fun e : End => e.version) ends && ends.all fun e => e.version < version)
  let cites ← many pCite (← nat 1 1 maxCites)
  let ages ← many (pAge (t == tag2)) (← nat 1 1 (if t == tag2 then 5 else 4))
  need (ascBy (fun a : Src × Nat => a.1.byte) ages)
  let aids ← pAids (t == tag2)
  let rules ← many (pRule (t == tag2) (ages.map (·.1)) cites.length) (← nat 1 1 maxRules)
  need (ascBy (fun r : Rule => r.reason.idx) rules)
  let d : Doc := ⟨state, tenant, version, prev, nb, na, ef, et, ends, cites, ages, rules, t == tag2, aids⟩
  need (costOf d ≤ maxCost)
  pure d

/-- Canonical: the body, then a KEYSET/v2 signature block of 1..16 records, nothing after. -/
def decode (x : Bytes) : Option Frame :=
  if x.length > maxRecord then none else
  match pDoc.run x with
  | some (d, rest) => (Keyset.decodeSigBlock rest).map fun ss => ⟨d, ss⟩
  | none => none

/-! ## Deciding under a rule set -/

/-- The enrollment feed's maximum age under `d`: the age it declares, else `enrollDefault`. -/
def Doc.enrollAge (d : Doc) : Nat := ((d.ages.find? (·.1 == .SPAN)).map (·.2)).getD enrollDefault

/-- The enrollment feed is not usable at the rule set's maximum age for it: older, absent, or dated past today. -/
def enrollStale (d : Doc) (c : Ctx) : Bool := !usable c.today d.enrollAge okSpan c.enrollment

/-- The rules the fixed eligibility guard covers on the line `v`: every rule for `PROGRAM_NOT_ELIGIBLE`, and a rule for
    another hold reason whose condition reads the eligibility source and is not true with every atom that reads it
    unknown (`eval3`), so whose value depends on the read (`eval3_sound`).  Such a rule holds a line only on a fresh read
    (`Env.fresh`). -/
def elGuard (v : Env) (r : Reason) (x : Expr) : Bool :=
  !review r && (r == .PROGRAM_NOT_ELIGIBLE || reads .ELIG x && eval3 v x != some true)

/-- Some rule of the record for reason `r` holds, except that while the enrollment feed is stale at the rule set's limit
    no rule that reads enrollment fires a hold reason, and on a read that is not fresh no rule the eligibility guard
    covers fires. -/
def ruleAny (d : Doc) (e : ElRead) (c : Ctx) (l : Line) (r : Reason) : Bool :=
  d.rules.any fun x => x.reason == r && eval (d.env e c l) x.cond &&
    !(enrollStale d c && !review r && reads .SPAN x.cond) &&
    !(elGuard (d.env e c l) r x.cond && !(d.env e c l).fresh .ELIG)

/-- The read is not fresh and the record has a rule the eligibility guard covers that could hold the line under some
    read: its condition is not false with every atom that reads the eligibility source unknown (`eval3`), and so, for a
    reason other than `PROGRAM_NOT_ELIGIBLE`, unknown.  A rule whose other atoms already rule the line out (another flow,
    a bad date) leaves it alone (`eval3_sound`); otherwise a rule cannot screen a read it may not act on out. -/
def elHeld (d : Doc) (e : ElRead) (c : Ctx) (l : Line) : Bool :=
  !(d.env e c l).fresh .ELIG && d.rules.any fun x =>
    elGuard (d.env e c l) x.reason x.cond && eval3 (d.env e c l) x.cond != some false

/-- The rule set's own conditions for reason `r`, under two fixed guards.  Enrollment: when the feed is stale at the rule
    set's limit, `STALE_ENROLLMENT` fires (the line is never allowed) and no rule that reads enrollment fires a hold
    reason (a late feed never holds), so the line goes to review unless a fact from another source holds it.
    Eligibility (`elGuard`): a stale, missing, absent, unknown or conflicting read never holds a line through a rule whose
    value depends on it, nor as not eligible for the program; a record with such a rule that could hold the line under
    some read sends it to review as `PROGRAM_NOT_ELIGIBLE_UNVERIFIED`.  Nothing without a rule set, and nothing for a core reason.  `e` is the line's
    eligibility read; only a version 2 rule reads it. -/
def dataFires (o : Option Doc) (e : ElRead) (c : Ctx) (l : Line) (r : Reason) : Bool :=
  match o with
  | none => false
  | some d => d.fires r && (r == .STALE_ENROLLMENT && enrollStale d c || ruleAny d e c l r ||
      r == .PROGRAM_NOT_ELIGIBLE_UNVERIFIED && elHeld d e c l)

/-- `Rules.claim` with the rule set's enrollment rule: a capitation line its rule set finds not enrolled claims no
    member-month.  A line with no rule set claims every key (the stricter side).  `el` gives each line its
    eligibility read. -/
def claimP (pick : Line → Option Doc) (el : Line → ElRead) (c : Ctx) (l : Line) : List Key :=
  if isCap l && dataFires (pick l) (el l) c l .MEMBER_NOT_ENROLLED && !own c l then [exactKey l, idKey l] else keys l

def pendingP (pick : Line → Option Doc) (el : Line → ElRead) (c : Ctx) (l : Line) : List Key :=
  ((unresolvedSet c).filter fun u => !(u == l && (c.byp.lookup l.pay).isSome)).flatMap (claimP pick el c)

/-- The fixed core of `Rules.fires`: identity, duplicates, the line's own dates and the two sets' staleness. -/
def coreFires (pick : Line → Option Doc) (el : Line → ElRead) (c : Ctx) (seen : List Key) (l : Line) : Reason → Bool
  | .ALREADY_DECIDED => seen.contains (idKey l) || (pendingP pick el c l).contains (idKey l)
  | .CAP_MEMBER_MONTH_DUPLICATE => isCap l && (seen.contains (exactKey l) || seen.contains (nearKey l))
  | .COLLIDES_WITH_UNRESOLVED_NEAR =>
      !isCap l && (pendingP pick el c l).contains (nearKey l) && !(pendingP pick el c l).contains (exactKey l)
  | .DUPLICATE_OF_UNRESOLVED =>
      (pendingP pick el c l).contains (exactKey l) || isCap l && (pendingP pick el c l).contains (nearKey l)
  | .FFS_DUPLICATE_LINE => !isCap l && seen.contains (exactKey l)
  | .FFS_DUPLICATE_UNVERIFIED => !isCap l && (looseKeys c).contains (exactKey l)
  | .FFS_NEAR_DUPLICATE => !isCap l && seen.contains (nearKey l) && !seen.contains (exactKey l)
  | .SERVICE_DATE_FUTURE => c.today < l.date
  | .SERVICE_DATE_INVALID => !validDate l.date
  | .STALE_RELEASED => !chained c.today c.releasedPrior c.released
  | .STALE_UNRESOLVED => !chained c.today c.unresolvedPrior c.unresolved
  | _ => false

def firesP (pick : Line → Option Doc) (el : Line → ElRead) (c : Ctx) (seen : List Key) (l : Line) (r : Reason) : Bool :=
  coreFires pick el c seen l r || dataFires (pick l) (el l) c l r

def decideLineP (pick : Line → Option Doc) (el : Line → ElRead) (c : Ctx) (seen : List Key) (l : Line) : Decision :=
  let rs := reasons.filter (firesP pick el c seen l)
  { line := l, outcome := outcomeOf rs, reasons := rs,
    counterparts := ((releasedSet c ++ loose c.today c.releasedPrior c.released).filter
      (fun x => (keys l).any (keys x).contains) ++ (unresolvedSet c ++ loose c.today c.unresolvedPrior
      c.unresolved).filter fun x => (keys l).any (claimP pick el c x).contains).map (·.id) }

def decideAllP (pick : Line → Option Doc) (el : Line → ElRead) (c : Ctx) : List Key → List Line → List Decision
  | _, [] => []
  | seen, l :: ls => decideLineP pick el c seen l :: decideAllP pick el c (claimP pick el c l ++ seen) ls

/-- `Rules.decideBatch`, each line under the rule set `pick` gives it. -/
def decideBatchS (pick : Line → Option Doc) (el : Line → ElRead) (c : Ctx) (batch : List Line) : Result :=
  let ds := decideAllP pick el c (seen0 c batch) (order c batch)
  { decisions := ds, released := advance c.today c.releasedPrior c.released (releasedLines c ds),
    unresolved := advance c.today c.unresolvedPrior c.unresolved (unresolvedLines c ds) }

/-! ## Pack 1: today's R1-R5 as data -/

def capOnly : Expr := .flow 4
def ffsOnly : Expr := .flow 3

def enrolledE : Expr :=
  .or [.and [ffsOnly, .hit .SPAN .member .within], .and [capOnly, .hit .SPAN .member .withinPlan]]

def certainE (s : Src) (e : Expr) : Expr := .and [.fresh s, .dateOk, e]
def unverifiedE (s : Src) (e : Expr) : Expr := .and [.present s, .not (.fresh s), .dateOk, e]

/-- Today's maximum ages (`Rules.fires`): deaths 90 days, exclusions 31, enrollment 7. -/
def pack1Ages : List (Src × Nat) := [(.DMF, 90), (.PDEATH, 90), (.EXCL, 31), (.SPAN, 7)]

/-- Today's fact rules, ascending by reason bit. -/
def pack1Conds : List (Reason × Expr) :=
  [(.CAP_MEMBER_MONTH_DUPLICATE, .and [capOnly, .fresh .SPAN, .dateOk, .overlap .SPAN]),
   (.MEMBER_DECEASED, certainE .DMF (.hit .DMF .member .before)),
   (.MEMBER_DECEASED_UNVERIFIED, unverifiedE .DMF (.hit .DMF .member .before)),
   (.MEMBER_NOT_ENROLLED, certainE .SPAN (.not enrolledE)),
   (.MEMBER_NOT_ENROLLED_UNVERIFIED, unverifiedE .SPAN (.not enrolledE)),
   (.PROVIDER_DECEASED, certainE .PDEATH (.hit .PDEATH .party .before)),
   (.PROVIDER_DECEASED_UNVERIFIED, unverifiedE .PDEATH (.hit .PDEATH .party .before)),
   (.PROVIDER_EXCLUDED, certainE .EXCL (.hit .EXCL .party .within)),
   (.PROVIDER_EXCLUDED_UNVERIFIED, unverifiedE .EXCL (.hit .EXCL .party .within)),
   (.STALE_DMF, .not (.fresh .DMF)),
   (.STALE_ENROLLMENT, .not (.fresh .SPAN)),
   (.STALE_EXCLUSION, .not (.fresh .EXCL)),
   (.STALE_PROVIDER_DEATH, .not (.fresh .PDEATH))]

/-- A rule set whose ages and conditions are pack 1's; header, legal sources and citation indexes are the state's. -/
def IsPack1 (d : Doc) : Prop := d.ages = pack1Ages ∧ d.rules.map (fun r => (r.reason, r.cond)) = pack1Conds

#guard (pack1Conds.map fun x => cost x.2).sum == 82
#guard ascBy (fun x : Reason × Expr => x.1.idx) pack1Conds
#guard pack1Conds.all (dataReason ·.1)
#guard (reasons.filter dataReason).length == pack1Conds.length

/-! ## Admission, the series, selection and replay -/

/-- A rule set the gate may run: only `admit` builds one. -/
structure Admitted where
  private mk ::
  /-- `digestOf doc`. -/
  id : Bytes
  /-- The batch of the shard's chain that admitted it; decisions read it from batch `kb + 1` (known time `K ≥ kb`). -/
  kb : Nat
  doc : Doc

inductive Refusal | MALFORMED | NOSOURCE | SCOPE | EXPIRED | CHAIN | ENDS | OVERLAP | UNSIGNED deriving DecidableEq, Repr

/-- The benefit level reasons: no fact field carries a benefit level yet. -/
def noSource : Reason → Bool
  | .BENEFIT_LEVEL_MISSING | .BENEFIT_LEVEL_MISSING_UNVERIFIED => true
  | _ => false

/-- A rule names a reason no data source backs: admission refuses the record (`NOSOURCE`). -/
def unbacked (d : Doc) : Bool := d.rules.any fun r => noSource r.reason

/-- The effective end of `a` once every end in `s` is applied (an end only shortens a range). -/
def endOf (s : List Admitted) (a : Admitted) : Nat :=
  s.foldl (fun t b => match b.doc.ends.find? (·.version == a.doc.version) with
    | some e => min t e.to
    | none => t) a.doc.effTo

/-- `endOf`, with the ends of a record not yet admitted applied too. -/
def endWith (s : List Admitted) (d : Doc) (a : Admitted) : Nat :=
  match d.ends.find? (·.version == a.doc.version) with
  | some e => min (endOf s a) e.to
  | none => endOf s a

def inForce (s : List Admitted) (a : Admitted) (D : Nat) : Bool := a.doc.effFrom ≤ D && D ≤ endOf s a

/-- Next version, chained to the last admitted one's digest, admitted no earlier in the chain than it. -/
def chainOk (s : List Admitted) (d : Doc) (kb : Nat) : Bool :=
  match s.getLast? with
  | none => d.version == 1 && d.prev == zeroDigest
  | some a => d.version == a.doc.version + 1 && d.prev == a.id && a.kb ≤ kb

/-- Each end names an admitted version still in force on some date and only shortens it; 0 withdraws it. -/
def endsOk (s : List Admitted) (d : Doc) : Bool :=
  d.ends.all fun e => s.any fun a => a.doc.version == e.version && a.doc.effFrom ≤ endOf s a &&
    (e.to == 0 || a.doc.effFrom ≤ e.to && e.to < endOf s a)

/-- After its ends, the new range meets no range still in force. -/
def disjoint (s : List Admitted) (d : Doc) : Bool :=
  s.all fun a => endWith s d a < a.doc.effFrom || endWith s d a < d.effFrom || d.effTo < a.doc.effFrom

/-- `admit`, with the end of the signing window checked only when `win`: a shard that starts after the window admits the
    tenant's record without it (`gateStep`), and every other check stays, its start included (`admitW_notBefore`). -/
def admitW (win : Bool) (verify : Bytes → Bytes → Bytes → Bool) (H : SnapshotV2.Head) (tenant : Bytes) (kb : Nat)
    (s : List Admitted) (x : Bytes) : Except Refusal Admitted :=
  match decode x with
  | none => .error .MALFORMED
  | some f =>
    if unbacked f.d then .error .NOSOURCE
    else if f.d.state != H.ks.state || f.d.tenantId != tenant then .error .SCOPE
    else if !Authority.windowOk f.d.notBefore (bif win then f.d.notAfter else H.day) H.day then .error .EXPIRED
    else if !chainOk s f.d kb then .error .CHAIN
    else if !endsOk s f.d then .error .ENDS
    else if !disjoint s f.d then .error .OVERLAP
    else if !Keyset.quorum verify (Keyset.policyOk H.day) (·.employee) H.ks H.ks.kPolicy (msgOf f) f.sigs then
      .error .UNSIGNED
    else .ok ⟨digestOf f.d, kb, f.d⟩

/-- Admit the record `x` in batch `kb` of a shard whose admitted head is `H`, after the tenant's series `s`. -/
def admit (verify : Bytes → Bytes → Bytes → Bool) (H : SnapshotV2.Head) (tenant : Bytes) (kb : Nat)
    (s : List Admitted) (x : Bytes) : Except Refusal Admitted :=
  admitW true verify H tenant kb s x

/-- A series built by admissions alone, in order, under the signature check `verify`. -/
inductive Reachable (verify : Bytes → Bytes → Bytes → Bool) : List Admitted → Prop
  | nil : Reachable verify []
  | step {s : List Admitted} {a : Admitted} (H : SnapshotV2.Head) (tenant : Bytes) (kb : Nat) (x : Bytes) :
      Reachable verify s → admit verify H tenant kb s x = .ok a → Reachable verify (s ++ [a])

/-- The admissions known at known time `K`. -/
def known (s : List Admitted) (K : Nat) : List Admitted := s.filter (·.kb ≤ K)

/-- The rule set in force for date `D` as known at `K`. -/
def select (s : List Admitted) (K D : Nat) : Option Admitted :=
  (known s K).find? fun a => inForce (known s K) a D

/-- A batch as known at `K`: each line under the rule set in force on its date then.  The lines with none are
    returned apart, undecided (their payments are not released); the rest are decided. -/
def replayAt (s : List Admitted) (K : Nat) (el : Line → ElRead) (c : Ctx) (b : List Line) : List Line × Result :=
  let pick := fun l : Line => (select s K l.date).map (·.doc)
  (b.filter fun l => (pick l).isNone, decideBatchS pick el c (b.filter fun l => (pick l).isSome))

/-- Signed as the gate admits, under the signature check `verify`: some record decodes to it and a POLICY quorum of an
    admitted head's key set signed it (a head is built only by admission). -/
def Signed (verify : Bytes → Bytes → Bytes → Bool) (a : Admitted) : Prop :=
  ∃ (H : SnapshotV2.Head) (x : Bytes) (f : Frame),
    decode x = some f ∧ f.d = a.doc ∧ a.id = digestOf f.d ∧
    Keyset.quorum verify (Keyset.policyOk H.day) (·.employee) H.ks H.ks.kPolicy (msgOf f) f.sigs = true

/-! ## Golden records

    `tests/test_ruleset_v1_codec.py` builds the same two records (the pack-1 record and one at every bound) in Python and
    compares its SHA3-512 of each with this table.  Here the build decodes each record again and checks that it re-encodes
    to the same bytes (canonical) and to the table's digest.  Signatures are filler bytes: the codec checks only shape. -/

def pat (n s : Nat) : Bytes := (List.range n).map fun i => UInt8.ofNat (s + i)

def text (s : String) : Bytes := s.toUTF8.toList

/-- A condition of cost exactly `c ≥ 1` with at most 8 operands per node, reading deaths and exclusions. -/
def sized : Nat → Nat → Expr
  | 0, _ => .dateOk
  | f + 1, c =>
    if c ≤ 1 then .dateOk
    else if c = 2 then .hit .DMF .member .before
    else if c = 3 then .hit .EXCL .party .within
    else
      let n := min 8 (c - 1)
      .and ((List.range n).map fun i => sized f ((c - 1) / n + if i < (c - 1) % n then 1 else 0))

def goldenPack1 : Frame :=
  ⟨⟨pat 64 0x40, text "TENANT-A", 1, zeroDigest, 20261101, 20261130, 20270101, openEnd, [],
    [⟨2, text "TEST-CITE-1", 20260701, pat 64 9⟩], pack1Ages, pack1Conds.map (fun x => ⟨x.1, 0, x.2⟩), false, []⟩,
   [⟨pat 64 1, pat 4627 1⟩, ⟨pat 64 2, pat 4627 2⟩]⟩

/-- Every bound at its edge: version 9 ending the eight earlier ones, a 31-day window, the widest range, a 128-byte
    tenant, 32 legal sources, every age at its ceiling, one rule of cost exactly `maxCost`, sixteen signatures. -/
def goldenEdge : Frame :=
  ⟨⟨pat 64 0xC0, text ("A" ++ String.join (List.replicate 21 "z9._:-") ++ "b"), 9, pat 64 0x77, 20261101, 20261202,
    10101, openEnd, ⟨1, 0⟩ :: (List.range 7).map (fun i => ⟨i + 2, 20261202 + i⟩),
    (List.range 32).map (fun i => ⟨1 + i % 7, text s!"REF-{i}", 20000101 + i % 28, pat 64 (i + 1)⟩),
    [Src.DMF, .PDEATH, .EXCL, .SPAN].map (fun s => (s, s.ceil)),
    [⟨.STALE_PROVIDER_DEATH, 31, sized 8 maxCost⟩], false, []⟩,
   (List.range 16).map fun j => ⟨pat 64 (15 * (j + 1)), pat 4627 (j + 1)⟩⟩

def golden : List (String × String) :=
  [("pack1", "717ae28ec7507114c0d3ff4188c16e823e9e3e6539ca58192717123b76303541d3c0aca2dfaa1d193db1997d1fc1315e84f9fb660b9e98cf1ef2b8918d06256f"),
   ("edge", "c8c98a83461f132cf68ef90f52f8428cb46c6d80ad4485dd488377e0fe474d1593ffad0530758e53fcfb7a76fa394845978f40ff096d77e18aec644593384968")]

def goldenOk : Bool :=
  [("pack1", goldenPack1), ("edge", goldenEdge)].all fun (n, f) =>
    (golden.lookup n) == some (Keyset.vecHex (sha3 (encode f))) && ((decode (encode f)).map encode) == some (encode f)

#guard goldenOk
#guard costOf goldenEdge.d == maxCost && costOf goldenPack1.d == 82

/-- Pack 1's record with enrollment age `n`. -/
def withSpanAge (n : Nat) : Frame :=
  { goldenPack1 with d := { goldenPack1.d with ages := [(.DMF, 90), (.PDEATH, 90), (.EXCL, 31), (.SPAN, n)] } }

-- The state sets the enrollment age from 1 to 10 days; 0 and 11 do not decode, so they are refused (MALFORMED).
#guard [1, 4, 10].all fun n => (decode (encode (withSpanAge n))).isSome
#guard [0, 11, 65535].all fun n => (decode (encode (withSpanAge n))).isNone
#guard goldenPack1.d.enrollAge == 7 && (withSpanAge 4).d.enrollAge == 4 &&
  { goldenPack1.d with ages := [(.DMF, 90)] }.enrollAge == enrollDefault

/-! ## Version 2: the test pack and its golden records

    `tests/test_ruleset_v2.py` builds the same two records in Python and compares its SHA3-512 of each with `golden2`.
    The test pack is a state's eligibility rules as the product reads them, as data (`conformance/RULESET_V2.md` §6):
    aid codes A1 and A2 are on the program's list, R7 is a recognised code that is not, and anything else, or a malformed
    code, is unrecognised. -/

def pack2Aids : List (Bytes × Nat) := [(text "A1", 1), (text "A2", 1), (text "R7", 2)]

/-- The test pack's rules, ascending by reason bit. -/
def pack2Conds : List (Reason × Expr) :=
  [-- the segment's status is "not eligible" (an absent answer is never fresh: it goes to review)
   (.MEMBER_NOT_ENROLLED, .and [.fresh .ELIG, .dateOk, .elig 2 2]),
   -- a recognised aid code that is not on the program's list
   (.PROGRAM_NOT_ELIGIBLE, .and [.fresh .ELIG, .dateOk, .elig 3 2]),
   -- no as-of at all, an unknown or conflicting answer, an unrecognised or malformed aid code, or a listed
   -- not-eligible code read from facts too old to act on
   (.PROGRAM_NOT_ELIGIBLE_UNVERIFIED,
     .or [.not (.present .ELIG), .elig 1 12, .elig 3 3, .and [.not (.fresh .ELIG), .elig 3 2]]),
   -- the read's as-of (the oldest fact it cites) is older than the maximum age before the service date
   (.STALE_ELIGIBILITY, .and [.present .ELIG, .not (.fresh .ELIG)])]

def goldenPack2 : Frame :=
  ⟨{ goldenPack1.d with
      v2 := true, ages := [(.ELIG, 4)], aids := pack2Aids, rules := pack2Conds.map fun x => ⟨x.1, 0, x.2⟩ },
   goldenPack1.sigs⟩

def zeroPad (w i : Nat) : String := String.ofList (List.replicate (w - (toString i).length) '0') ++ toString i

/-- Every version 2 bound at its edge: five ages at their ceilings, `maxAids` codes of `maxAidLen` bytes, version 1's
    other edges. -/
def goldenEdge2 : Frame :=
  ⟨{ goldenEdge.d with
      v2 := true
      ages := [Src.DMF, .PDEATH, .EXCL, .SPAN, .ELIG].map (fun s => (s, s.ceil))
      aids := (List.range maxAids).map (fun i => (text ("C" ++ zeroPad 19 i), 1 + i % 2))
      rules := [⟨.STALE_ELIGIBILITY, 31, sized 8 maxCost⟩] },
   goldenEdge.sigs⟩

def golden2 : List (String × String) :=
  [("pack2", "f6fdea534c8bcd94babf83077d2369f79d41f1618bc7f71e511e61058d1b7985d38c8b1fb402ccf92d686f5ea9b50392da0f57133951aac47f4b7e84ac195336"),
   ("edge2", "e28791426c2eaed4be808b8a4166e5434ba404cc5ece3316217f93e1b9e3a7785e531d61bcfe9b756ce5445ec0680c079950539a3e203e6401a6e4208aef90c3")]

def golden2Ok : Bool :=
  [("pack2", goldenPack2), ("edge2", goldenEdge2)].all fun (n, f) =>
    (golden2.lookup n) == some (Keyset.vecHex (sha3 (encode f))) && ((decode (encode f)).map encode) == some (encode f)

#guard golden2Ok
#guard costOf goldenEdge2.d == maxCost && costOf goldenPack2.d == 26 && (encode goldenEdge2).length ≤ maxRecord
-- A version 1 record keeps its bytes, and the same body under the other tag is another record.
#guard (encDoc goldenPack1.d).take tag.length == tag && (encDoc goldenPack2.d).take tag2.length == tag2 &&
  digestOf goldenPack2.d != digestOf { goldenPack2.d with v2 := false, aids := [] }
-- Version 1 refuses the eligibility source and reasons; version 2 refuses an aid table out of order or too long.
#guard (decode (encode { goldenPack2 with d := { goldenPack2.d with v2 := false, aids := [] } })).isNone
#guard (decode (encode { goldenPack2 with d := { goldenPack2.d with aids := pack2Aids.reverse } })).isNone
#guard (decode (encode { goldenPack2 with d := { goldenPack2.d with aids := [(text "A1", 1), (text "A1", 2)] } })).isNone
#guard (decode (encode { goldenEdge2 with d := { goldenEdge2.d with aids := goldenEdge2.d.aids ++ [(text "D", 1)] } })).isNone

/-! ### The eligibility read and the gate on a small fact corpus (`tests/test_ruleset_v2.py`, against
    `conformance/ruleset_v2_ref.py`) -/

/-- The empty context for a batch dated `today`: no reference snapshot and no prior lines, so the enrollment feed is
    stale and `STALE_ENROLLMENT` fires on every line. -/
def emptyCtx (today : Nat) : Ctx :=
  { today := today, dmf := none, providerDeaths := none, exclusions := none, enrollment := none, released := none,
    unresolved := none, releasedPrior := ⟨0, 0, []⟩, unresolvedPrior := ⟨0, 0, []⟩, anchor := 0, redo := [] }

/-- A line of flow `w` dated `D`, every other field 0. -/
def bareLine (w : Flow) (D : Nat) : Line := ⟨0, 0, w, 0, 0, 0, D, 0, 0, 0⟩

/-- The reason bits record `d` fires on one line (`dataFires`). -/
def dataMask (d : Doc) (e : ElRead) (c : Ctx) (l : Line) : Nat :=
  reasons.foldl (fun m r => if dataFires (some d) e c l r then m ||| 2 ^ r.idx else m) 0

/-- The read of member `pat 32 7` for a line dated `D` (also the reading day), from one clean full file per source:
    `(source, class, as-of, the member's rows as (status, aid code))`, the source its own origin with a 400-day registry
    age, each row holding from 20260101 with no end, read at minimum class 1. -/
def elCase (D : Nat) (files : List (Nat × Nat × Nat × List (Nat × String))) : ElRead :=
  let m := FactCodec.pat 32 7
  let ix := (List.range files.length).zip files
  let reg : FactRegistry.Registry := files.map fun (src, cls, _, _) =>
    { src := src, cls := cls, origin := 6 + src, kinds := 2, gapless := 0, maxage := 400, drop := 50, oneper := 0,
      scope := FactCodec.ident 21 "MEDICAID", name := FactCodec.ident 31 "N", fseqRule := 2, full := 1, cfromRule := 0,
      ids := [(1, [1])] }
  let recs := ix.map fun (i, src, _, asof, _) =>
    (i, { FactRegistry.mkRcpt src 1 asof 20260101 10 (i + 1) 0 0 with kb := i + 1 })
  let rows := ix.flatMap fun (i, src, _, _, rs) => ((List.range rs.length).zip rs).map fun (j, st, code) =>
    ({ seq := 10 * i + j + 1, src := src, fseq := 10, reader := 1,
       fact := { op := 0, subject := m, sid := FactCodec.pat 32 3, vstart := 20260101, vstop := 99991231,
                 lineUntil := 99991231, receipt := i, roff := 0,
                 value := .elig { status := st, basis := 1, program := FactCodec.ident 21 "P",
                                  aid := FactCodec.ident 21 code, determined := 0, notice := 0 } } } : FactBelief.Row)
  elRead { reg := reg, today := some D, refhi := [], inScope := fun _ _ => true } { recs := recs, rows := rows } 100 1 m D

def elText (r : ElRead) : String :=
  s!"{r.ans} {r.status} {r.asof.getD 0} {",".intercalate (r.aids.map Keyset.vecHex)}"

def elCases : List (String × Nat × List (Nat × Nat × Nat × List (Nat × String))) :=
  [("fresh", 20260303, [(1, 1, 20260301, [(1, "A1")])]),
   ("stale", 20260303, [(1, 1, 20260210, [(1, "A1")])]),
   ("stale_not_eligible", 20260303, [(1, 1, 20260210, [(1, "R7")])]),
   ("no_as_of", 20260303, [(1, 1, 20260301, [])]),
   ("conflict", 20260303, [(1, 1, 20260301, [(1, "A1")]), (2, 1, 20260302, [(2, "R7")])]),
   ("agree", 20260303, [(1, 1, 20260301, [(1, "A1")]), (2, 1, 20260302, [(1, "R7")])]),
   ("unknown_code", 20260303, [(1, 1, 20260301, [(1, "ZZ9")])]),
   -- a newer fact the answer does not rest on (a weaker source's) does not freshen the stale one it does
   ("newer_weak_row", 20260303, [(1, 1, 20260210, [(1, "R7")]), (2, 2, 20260302, [(1, "A1")])])]

/-- Each case's read, then the reason bits the test pack fires on it for a claim line on the batch's own date. -/
def elGolden : List (String × String) :=
  [("fresh", "0 1 20260301 024131000000000000000000000000000000000000 524288"),
   ("stale", "0 1 20260210 024131000000000000000000000000000000000000 403177472"),
   ("stale_not_eligible", "0 1 20260210 025237000000000000000000000000000000000000 403177472"),
   ("no_as_of", "1 0 0  134742016"),
   ("conflict", "3 0 0  134742016"),
   ("agree", "0 1 20260301 024131000000000000000000000000000000000000,025237000000000000000000000000000000000000 67633152"),
   ("unknown_code", "0 1 20260301 035a5a390000000000000000000000000000000000 134742016"),
   ("newer_weak_row", "0 1 20260210 025237000000000000000000000000000000000000 403177472")]

#guard elCases.map (fun (n, D, fs) => let r := elCase D fs
  (n, elText r ++ " " ++ toString (dataMask goldenPack2.d r (emptyCtx D) (bareLine .FFS_CLAIM D)))) == elGolden

/-! ### The eligibility guard on a rule that reads enrollment too (`tests/test_ruleset_v2.py` has the same cases without
    enrollment, against `conformance/ruleset_v2_ref.py`) -/

/-- Not enrolled: a fresh enrollment feed has no span of the member on the line's date, or a fresh read says the
    member is not eligible. -/
def guardCond : Expr := .or [.and [.fresh .SPAN, .not (.hit .SPAN .member .within)], .and [.fresh .ELIG, .elig 2 2]]

def guardDoc (r : Reason) : Doc :=
  { goldenPack2.d with ages := [(.SPAN, 7), (.ELIG, 4)], rules := [⟨r, 0, guardCond⟩] }

/-- A batch dated `D` whose enrollment feed, read that day, holds one span, of member `m`, around `D`. -/
def guardCtx (m D : Nat) : Ctx := { emptyCtx D with enrollment := some ⟨D, 1, [⟨m, 0, 20270101, 20271231⟩]⟩ }

-- On a stale read (as-of five days before the line, maximum age 4): with no span of the line's member (0) the rule is
-- true whatever the read and holds the line (`MEMBER_NOT_ENROLLED`); with one its value is the read's, so the line goes
-- to review (`PROGRAM_NOT_ELIGIBLE_UNVERIFIED`); the same rule for not eligible for the program never holds on it.
#guard ([(1, .MEMBER_NOT_ENROLLED, 2 ^ 9), (0, .MEMBER_NOT_ENROLLED, 2 ^ 27), (1, .PROGRAM_NOT_ELIGIBLE, 2 ^ 27)] :
    List (Nat × Reason × Nat)).all fun (m, r, want) =>
  dataMask (guardDoc r) { ans := 0, status := 2, asof := some 20270308 } (guardCtx m 20270313)
    (bareLine .FFS_CLAIM 20270313) == want

/-! ## Proof helpers: the interpreter -/

mutual
theorem evalC_fst (v : Env) : (e : Expr) → (evalC v e).1 = eval v e
  | .and es => by
    have h := allC_fst v es
    simp only [evalC, eval]
    exact h
  | .or es => by
    have h := anyC_fst v es
    simp only [evalC, eval]
    exact h
  | .not e => by
    have h := evalC_fst v e
    simp only [evalC, eval, h]
  | .hit s .party t => by simp [evalC, eval]
  | .hit s .member t => by simp [evalC, eval]
  | .overlap s => by simp [evalC, eval]
  | .flow m => by simp [evalC, eval]
  | .dateOk => by simp [evalC, eval]
  | .present s => by simp [evalC, eval]
  | .fresh s => by simp [evalC, eval]
  | .elig q a => by simp [evalC, eval]

theorem allC_fst (v : Env) : (es : List Expr) → (allC v es).1 = evalAll v es
  | [] => by simp [allC, evalAll]
  | e :: es => by
    have h1 := evalC_fst v e
    have h2 := allC_fst v es
    simp only [allC, evalAll, ← h1]
    cases hb : (evalC v e).1 <;> simp [hb, h2]

theorem anyC_fst (v : Env) : (es : List Expr) → (anyC v es).1 = evalAny v es
  | [] => by simp [anyC, evalAny]
  | e :: es => by
    have h1 := evalC_fst v e
    have h2 := anyC_fst v es
    simp only [anyC, evalAny, ← h1]
    cases hb : (evalC v e).1 <;> simp [hb, h2]
end

mutual
theorem evalC_snd (v : Env) : (e : Expr) → (evalC v e).2 ≤ cost e
  | .and es => by
    have h := allC_snd v es
    simp only [evalC, cost]
    omega
  | .or es => by
    have h := anyC_snd v es
    simp only [evalC, cost]
    omega
  | .not e => by
    have h := evalC_snd v e
    simp only [evalC, cost]
    omega
  | .hit s .party t => by simp [evalC, cost]
  | .hit s .member t => by simp [evalC, cost]
  | .overlap s => by simp [evalC, cost]
  | .flow m => by simp [evalC, cost]
  | .dateOk => by simp [evalC, cost]
  | .present s => by simp [evalC, cost]
  | .fresh s => by simp [evalC, cost]
  | .elig q a => by simp [evalC, cost]

theorem allC_snd (v : Env) : (es : List Expr) → (allC v es).2 ≤ costAll es
  | [] => by simp [allC, costAll]
  | e :: es => by
    have h1 := evalC_snd v e
    have h2 := allC_snd v es
    simp only [allC, costAll]
    cases hb : (evalC v e).1 <;> simp [hb] <;> omega

theorem anyC_snd (v : Env) : (es : List Expr) → (anyC v es).2 ≤ costAll es
  | [] => by simp [anyC, costAll]
  | e :: es => by
    have h1 := evalC_snd v e
    have h2 := anyC_snd v es
    simp only [anyC, costAll]
    cases hb : (evalC v e).1 <;> simp [hb] <;> omega
end

theorem sum_evalC_le (v : Env) : ∀ rs : List Rule,
    (rs.map fun r => (evalC v r.cond).2).sum ≤ (rs.map fun r => cost r.cond).sum
  | [] => by simp
  | r :: rs => by
    have h1 := evalC_snd v r.cond
    have h2 := sum_evalC_le v rs
    simp only [List.map_cons, List.sum_cons]
    omega

/-! ## Proof helpers: the reader inverts the writer -/

theorem encAll_eq : ∀ es : List Expr, encAll es = es.flatMap encExpr
  | [] => by simp [encAll]
  | e :: es => by simp [encAll, encAll_eq es]

theorem ofByte_byte {v : Nat} {s : Src} (h : Src.ofByte v = some s) : s.byte = v := by
  unfold Src.ofByte at h
  split at h
  all_goals (try cases h) <;> simp_all [Src.byte]

theorem pSrc_inv {b : Bytes} {s : Src} {r : Bytes} (h : pSrc.run b = some (s, r)) : b = encSrc s ++ r := by
  unfold pSrc at h
  obtain ⟨v, r1, h1, h⟩ := ParseLaws.bind_run h
  obtain ⟨e1, -, -⟩ := nat_inv h1
  rcases hv : Src.ofByte v with _ | s'
  · rw [hv] at h
    simp [fail, StateT.run] at h
  · rw [hv] at h
    change (pure s' : P Src).run r1 = some (s, r) at h
    obtain ⟨he, hr⟩ := ParseLaws.pure_run h
    subst he hr
    rw [e1, encSrc, ofByte_byte hv]

theorem pSrcIn_inv {ok : List Src} {b : Bytes} {s : Src} {r : Bytes} (h : (pSrcIn ok).run b = some (s, r)) :
    b = encSrc s ++ r := by
  unfold pSrcIn at h
  obtain ⟨s', r1, h1, h⟩ := ParseLaws.bind_run h
  obtain ⟨u, r2, h2, h⟩ := ParseLaws.bind_run h
  obtain ⟨he, hr⟩ := ParseLaws.pure_run h
  have e1 := pSrc_inv h1
  have e2 := need_rest h2
  subst he hr e2
  exact e1

theorem pSubj_inv {b : Bytes} {j : Subj} {r : Bytes} (h : pSubj.run b = some (j, r)) :
    b = natBE 1 (subjByte j) ++ r := by
  unfold pSubj at h
  obtain ⟨v, r1, h1, h⟩ := ParseLaws.bind_run h
  obtain ⟨e1, hlo, hhi⟩ := nat_inv h1
  obtain ⟨he, hr⟩ := ParseLaws.pure_run h
  subst hr
  rw [e1]
  by_cases hv : v = 1
  · subst hv
    simp at he
    subst he
    rfl
  · have hv2 : v = 2 := by omega
    subst hv2
    simp at he
    subst he
    rfl

theorem pTest_inv {b : Bytes} {t : Test} {r : Bytes} (h : pTest.run b = some (t, r)) :
    b = natBE 1 (testByte t) ++ r := by
  unfold pTest at h
  obtain ⟨v, r1, h1, h⟩ := ParseLaws.bind_run h
  obtain ⟨e1, hlo, hhi⟩ := nat_inv h1
  obtain ⟨he, hr⟩ := ParseLaws.pure_run h
  subst hr
  rw [e1]
  by_cases hv : v = 1
  · subst hv
    simp at he
    subst he
    rfl
  · by_cases hv2 : v = 2
    · subst hv2
      simp at he
      subst he
      rfl
    · have hv3 : v = 3 := by omega
      subst hv3
      simp at he
      subst he
      rfl

theorem pExpr_inv (ok : List Src) : ∀ (n : Nat) {b : Bytes} {e : Expr} {r : Bytes},
    (pExpr ok n).run b = some (e, r) → b = encExpr e ++ r
  | 0, b, e, r, h => by simp [pExpr, fail, StateT.run] at h
  | n + 1, b, e, r, h0 => by
    have ih : ∀ {b : Bytes} {e : Expr} {r : Bytes}, (pExpr ok n).run b = some (e, r) → b = encExpr e ++ r :=
      fun h => pExpr_inv ok n h
    simp only [pExpr] at h0
    obtain ⟨op, r1, h1, h⟩ := ParseLaws.bind_run h0
    clear h0
    obtain ⟨e1, -, -⟩ := nat_inv h1
    subst e1
    by_cases h01 : op = 0x01
    · subst h01
      simp only [↓reduceIte] at h
      obtain ⟨k, r2, h2, h⟩ := ParseLaws.bind_run h
      obtain ⟨xs, r3, h3, h⟩ := ParseLaws.bind_run h
      obtain ⟨he, hr⟩ := ParseLaws.pure_run h
      obtain ⟨e2, -, -⟩ := nat_inv h2
      obtain ⟨e3, hl, -⟩ := ParseLaws.many_run (p := pExpr ok n) (e := encExpr) (Q := fun _ => True)
        (fun h => ⟨(ih h).symm, trivial⟩) k h3
      subst e2 e3 hr he hl
      simp [encExpr, encAll_eq]
    rw [if_neg h01] at h
    by_cases h02 : op = 0x02
    · subst h02
      simp only [↓reduceIte] at h
      obtain ⟨k, r2, h2, h⟩ := ParseLaws.bind_run h
      obtain ⟨xs, r3, h3, h⟩ := ParseLaws.bind_run h
      obtain ⟨he, hr⟩ := ParseLaws.pure_run h
      obtain ⟨e2, -, -⟩ := nat_inv h2
      obtain ⟨e3, hl, -⟩ := ParseLaws.many_run (p := pExpr ok n) (e := encExpr) (Q := fun _ => True)
        (fun h => ⟨(ih h).symm, trivial⟩) k h3
      subst e2 e3 hr he hl
      simp [encExpr, encAll_eq]
    rw [if_neg h02] at h
    by_cases h03 : op = 0x03
    · subst h03
      simp only [↓reduceIte] at h
      obtain ⟨x, r2, h2, h⟩ := ParseLaws.bind_run h
      obtain ⟨he, hr⟩ := ParseLaws.pure_run h
      have e2 := ih h2
      subst e2 hr he
      simp [encExpr]
    rw [if_neg h03] at h
    by_cases h10 : op = 0x10
    · subst h10
      simp only [↓reduceIte] at h
      obtain ⟨m, r2, h2, h⟩ := ParseLaws.bind_run h
      obtain ⟨he, hr⟩ := ParseLaws.pure_run h
      obtain ⟨e2, -, -⟩ := nat_inv h2
      subst e2 hr he
      simp [encExpr]
    rw [if_neg h10] at h
    by_cases h11 : op = 0x11
    · subst h11
      simp only [↓reduceIte] at h
      obtain ⟨he, hr⟩ := ParseLaws.pure_run h
      subst hr he
      simp [encExpr]
    rw [if_neg h11] at h
    by_cases h20 : op = 0x20
    · subst h20
      simp only [↓reduceIte] at h
      obtain ⟨s, r2, h2, h⟩ := ParseLaws.bind_run h
      obtain ⟨he, hr⟩ := ParseLaws.pure_run h
      have e2 := pSrcIn_inv h2
      subst e2 hr he
      simp [encExpr]
    rw [if_neg h20] at h
    by_cases h21 : op = 0x21
    · subst h21
      simp only [↓reduceIte] at h
      obtain ⟨s, r2, h2, h⟩ := ParseLaws.bind_run h
      obtain ⟨he, hr⟩ := ParseLaws.pure_run h
      have e2 := pSrcIn_inv h2
      subst e2 hr he
      simp [encExpr]
    rw [if_neg h21] at h
    by_cases h30 : op = 0x30
    · subst h30
      simp only [↓reduceIte] at h
      obtain ⟨s, r2, h2, h⟩ := ParseLaws.bind_run h
      obtain ⟨j, r3, h3, h⟩ := ParseLaws.bind_run h
      obtain ⟨t, r4, h4, h⟩ := ParseLaws.bind_run h
      obtain ⟨u, r5, h5, h⟩ := ParseLaws.bind_run h
      obtain ⟨he, hr⟩ := ParseLaws.pure_run h
      have e2 := pSrcIn_inv h2
      have e3 := pSubj_inv h3
      have e4 := pTest_inv h4
      have e5 := need_rest h5
      subst e2 e3 e4 e5 hr he
      simp [encExpr, List.append_assoc]
    rw [if_neg h30] at h
    by_cases h31 : op = 0x31
    · subst h31
      simp only [↓reduceIte] at h
      obtain ⟨s, r2, h2, h⟩ := ParseLaws.bind_run h
      obtain ⟨u, r3, h3, h⟩ := ParseLaws.bind_run h
      obtain ⟨he, hr⟩ := ParseLaws.pure_run h
      have e2 := pSrcIn_inv h2
      have e3 := need_rest h3
      subst e2 e3 hr he
      simp [encExpr]
    rw [if_neg h31] at h
    by_cases h22 : op = 0x22
    · subst h22
      simp only [↓reduceIte] at h
      obtain ⟨u, r2, h2, h⟩ := ParseLaws.bind_run h
      obtain ⟨q, r3, h3, h⟩ := ParseLaws.bind_run h
      obtain ⟨a, r4, h4, h⟩ := ParseLaws.bind_run h
      obtain ⟨he, hr⟩ := ParseLaws.pure_run h
      have e2 := need_rest h2
      obtain ⟨e3, -, -⟩ := nat_inv h3
      obtain ⟨e4, -, -⟩ := nat_inv h4
      subst e2 e3 e4 hr he
      simp [encExpr, List.append_assoc]
    rw [if_neg h22] at h
    simp [fail, StateT.run] at h

theorem pEnd_inv {b : Bytes} {e : End} {r : Bytes} (h : pEnd.run b = some (e, r)) :
    b = natBE 4 e.version ++ natBE 4 e.to ++ r := by
  unfold pEnd at h
  obtain ⟨v, r1, h1, h⟩ := ParseLaws.bind_run h
  obtain ⟨t, r2, h2, h⟩ := ParseLaws.bind_run h
  obtain ⟨u, r3, h3, h⟩ := ParseLaws.bind_run h
  obtain ⟨he, hr⟩ := ParseLaws.pure_run h
  obtain ⟨e1, -, -⟩ := nat_inv h1
  obtain ⟨e2, -, -⟩ := nat_inv h2
  have e3 := need_rest h3
  subst e1 e2 e3 hr he
  simp [List.append_assoc]

theorem pCite_inv {b : Bytes} {c : Cite} {r : Bytes} (h : pCite.run b = some (c, r)) :
    b = natBE 1 c.kind ++ identField c.ref ++ natBE 4 c.date ++ c.doc ++ r := by
  unfold pCite at h
  obtain ⟨k, r1, h1, h⟩ := ParseLaws.bind_run h
  obtain ⟨rf, r2, h2, h⟩ := ParseLaws.bind_run h
  obtain ⟨dt, r3, h3, h⟩ := ParseLaws.bind_run h
  obtain ⟨u4, r4, h4, h⟩ := ParseLaws.bind_run h
  obtain ⟨dg, r5, h5, h⟩ := ParseLaws.bind_run h
  obtain ⟨u6, r6, h6, h⟩ := ParseLaws.bind_run h
  obtain ⟨he, hr⟩ := ParseLaws.pure_run h
  obtain ⟨e1, -, -⟩ := nat_inv h1
  obtain ⟨e2, -⟩ := ident_inv h2
  obtain ⟨e3, -, -⟩ := nat_inv h3
  have e4 := need_rest h4
  obtain ⟨e5, -⟩ := take_inv h5
  have e6 := need_rest h6
  subst e1 e2 e3 e4 e5 e6 hr he
  simp [identBytes, identField, List.append_assoc]

theorem pAge_inv {v2 : Bool} {b : Bytes} {a : Src × Nat} {r : Bytes} (h : (pAge v2).run b = some (a, r)) :
    b = encSrc a.1 ++ natBE 2 a.2 ++ r := by
  unfold pAge at h
  obtain ⟨s, r1, h1, h⟩ := ParseLaws.bind_run h
  obtain ⟨u, r2, h2, h⟩ := ParseLaws.bind_run h
  obtain ⟨n, r3, h3, h⟩ := ParseLaws.bind_run h
  obtain ⟨he, hr⟩ := ParseLaws.pure_run h
  have e1 := pSrc_inv h1
  have e2 := need_rest h2
  obtain ⟨e3, -, -⟩ := nat_inv h3
  subst e1 e2 e3 hr he
  simp [List.append_assoc]

theorem pAge_bound {v2 : Bool} {b : Bytes} {a : Src × Nat} {r : Bytes} (h : (pAge v2).run b = some (a, r)) :
    1 ≤ a.2 ∧ a.2 ≤ a.1.ceil := by
  unfold pAge at h
  obtain ⟨s, r1, -, h⟩ := ParseLaws.bind_run h
  obtain ⟨u, r2, -, h⟩ := ParseLaws.bind_run h
  obtain ⟨n, r3, h2, h⟩ := ParseLaws.bind_run h
  obtain ⟨he, -⟩ := ParseLaws.pure_run h
  obtain ⟨-, hlo, hhi⟩ := nat_inv h2
  subst he
  exact ⟨hlo, hhi⟩

theorem pAid_inv {b : Bytes} {a : Bytes × Nat} {r : Bytes} (h : pAid.run b = some (a, r)) :
    b = identField a.1 ++ natBE 1 a.2 ++ r := by
  unfold pAid at h
  obtain ⟨c, r1, h1, h⟩ := ParseLaws.bind_run h
  obtain ⟨u, r2, h2, h⟩ := ParseLaws.bind_run h
  obtain ⟨k, r3, h3, h⟩ := ParseLaws.bind_run h
  obtain ⟨he, hr⟩ := ParseLaws.pure_run h
  obtain ⟨e1, -⟩ := ident_inv h1
  have e2 := need_rest h2
  obtain ⟨e3, -, -⟩ := nat_inv h3
  subst e1 e2 e3 hr he
  simp [identBytes, identField, List.append_assoc]

theorem pAids_inv {v2 : Bool} {b : Bytes} {as : List (Bytes × Nat)} {r : Bytes}
    (h : (pAids v2).run b = some (as, r)) : b = encAids v2 as ++ r := by
  cases v2
  · simp only [pAids, Bool.false_eq_true, ↓reduceIte] at h
    obtain ⟨he, hr⟩ := ParseLaws.pure_run h
    subst he hr
    simp [encAids]
  · simp only [pAids, ↓reduceIte] at h
    obtain ⟨k, r1, h1, h⟩ := ParseLaws.bind_run h
    obtain ⟨xs, r2, h2, h⟩ := ParseLaws.bind_run h
    obtain ⟨u, r3, h3, h⟩ := ParseLaws.bind_run h
    obtain ⟨he, hr⟩ := ParseLaws.pure_run h
    obtain ⟨e1, -, -⟩ := nat_inv h1
    obtain ⟨e2, l2, -⟩ := ParseLaws.many_run (p := pAid) (e := fun a : Bytes × Nat => identField a.1 ++ natBE 1 a.2)
      (Q := fun _ => True) (fun h => ⟨(pAid_inv h).symm, trivial⟩) k h2
    have e3 := need_rest h3
    subst e1 e2 e3 hr he l2
    simp [encAids, List.append_assoc]

theorem reasonOf_idx {v : Nat} {r : Reason} (h : reasonOf v = some r) : r.idx = v := by
  have := List.find?_some h
  simpa using this

theorem pRule_inv {v2 : Bool} {ok : List Src} {nC : Nat} {b : Bytes} {ru : Rule} {r : Bytes}
    (h : (pRule v2 ok nC).run b = some (ru, r)) :
    b = natBE 1 ru.reason.idx ++ natBE 1 ru.cite ++ encExpr ru.cond ++ r := by
  unfold pRule at h
  obtain ⟨v, r1, h1, h⟩ := ParseLaws.bind_run h
  obtain ⟨e1, -, -⟩ := nat_inv h1
  rcases hv : reasonOf v with _ | rs
  · rw [hv] at h
    simp [fail, StateT.run] at h
  · rw [hv] at h
    obtain ⟨u, r2, h2, h⟩ := ParseLaws.bind_run h
    obtain ⟨ci, r3, h3, h⟩ := ParseLaws.bind_run h
    obtain ⟨ex, r4, h4, h⟩ := ParseLaws.bind_run h
    obtain ⟨he, hr⟩ := ParseLaws.pure_run h
    have e2 := need_rest h2
    obtain ⟨e3, -, -⟩ := nat_inv h3
    have e4 := pExpr_inv ok maxDepth h4
    have hi := reasonOf_idx hv
    subst e1 e2 e3 e4 hr he hi
    simp [List.append_assoc]

theorem tag_of {t : Bytes} (h : (t == tag || t == tag2) = true) : (if (t == tag2) = true then tag2 else tag) = t := by
  by_cases h2 : t = tag2
  · subst h2
    simp
  · have h1 : t = tag := by simpa [h2] using h
    rw [if_neg (by simpa using h2)]
    exact h1.symm

theorem pDoc_inv {b : Bytes} {d : Doc} {r : Bytes} (h : pDoc.run b = some (d, r)) :
    b = encDoc d ++ r ∧ costOf d ≤ maxCost ∧ ∀ a ∈ d.ages, 1 ≤ a.2 ∧ a.2 ≤ a.1.ceil := by
  unfold pDoc at h
  obtain ⟨t, r0, h0, h⟩ := ParseLaws.bind_run h
  obtain ⟨u1, r1, h1, h⟩ := ParseLaws.bind_run h
  obtain ⟨st, r2, h2, h⟩ := ParseLaws.bind_run h
  obtain ⟨te, r3, h3, h⟩ := ParseLaws.bind_run h
  obtain ⟨ve, r4, h4, h⟩ := ParseLaws.bind_run h
  obtain ⟨pv, r5, h5, h⟩ := ParseLaws.bind_run h
  obtain ⟨u6, r6, h6, h⟩ := ParseLaws.bind_run h
  obtain ⟨nb, r7, h7, h⟩ := ParseLaws.bind_run h
  obtain ⟨na, r8, h8, h⟩ := ParseLaws.bind_run h
  obtain ⟨u9, r9, h9, h⟩ := ParseLaws.bind_run h
  obtain ⟨ef, r10, h10, h⟩ := ParseLaws.bind_run h
  obtain ⟨et, r11, h11, h⟩ := ParseLaws.bind_run h
  obtain ⟨u12, r12, h12, h⟩ := ParseLaws.bind_run h
  obtain ⟨ke, r13, h13, h⟩ := ParseLaws.bind_run h
  obtain ⟨en, r14, h14, h⟩ := ParseLaws.bind_run h
  obtain ⟨u15, r15, h15, h⟩ := ParseLaws.bind_run h
  obtain ⟨kc, r16, h16, h⟩ := ParseLaws.bind_run h
  obtain ⟨ci, r17, h17, h⟩ := ParseLaws.bind_run h
  obtain ⟨ka, r18, h18, h⟩ := ParseLaws.bind_run h
  obtain ⟨ag, r19, h19, h⟩ := ParseLaws.bind_run h
  obtain ⟨u20, r20, h20, h⟩ := ParseLaws.bind_run h
  obtain ⟨ai, r21, h21, h⟩ := ParseLaws.bind_run h
  obtain ⟨kr, r22, h22, h⟩ := ParseLaws.bind_run h
  obtain ⟨ru, r23, h23, h⟩ := ParseLaws.bind_run h
  obtain ⟨u24, r24, h24, h⟩ := ParseLaws.bind_run h
  try dsimp only at h
  obtain ⟨u25, r25, h25, h⟩ := ParseLaws.bind_run h
  obtain ⟨he, hr⟩ := ParseLaws.pure_run h
  have hcost := of_decide_eq_true (need_ok h25)
  have htag := tag_of (need_ok h1)
  obtain ⟨e0, -⟩ := take_inv h0
  have e1 := need_rest h1
  obtain ⟨e2, -⟩ := take_inv h2
  obtain ⟨e3, -⟩ := ident_inv h3
  obtain ⟨e4, -, -⟩ := nat_inv h4
  obtain ⟨e5, -⟩ := take_inv h5
  have e6 := need_rest h6
  obtain ⟨e7, -, -⟩ := nat_inv h7
  obtain ⟨e8, -, -⟩ := nat_inv h8
  have e9 := need_rest h9
  obtain ⟨e10, -, -⟩ := nat_inv h10
  obtain ⟨e11, -, -⟩ := nat_inv h11
  have e12 := need_rest h12
  obtain ⟨e13, -, -⟩ := nat_inv h13
  obtain ⟨e14, l14, -⟩ := ParseLaws.many_run (p := pEnd) (e := fun e : End => natBE 4 e.version ++ natBE 4 e.to)
    (Q := fun _ => True) (fun h => ⟨by rw [(pEnd_inv h)], trivial⟩) ke h14
  have e15 := need_rest h15
  obtain ⟨e16, -, -⟩ := nat_inv h16
  obtain ⟨e17, l17, -⟩ := ParseLaws.many_run (p := pCite)
    (e := fun c : Cite => natBE 1 c.kind ++ identField c.ref ++ natBE 4 c.date ++ c.doc)
    (Q := fun _ => True) (fun h => ⟨(pCite_inv h).symm, trivial⟩) kc h17
  obtain ⟨e18, -, -⟩ := nat_inv h18
  obtain ⟨e19, l19, q19⟩ := ParseLaws.many_run (p := pAge (t == tag2))
    (e := fun a : Src × Nat => encSrc a.1 ++ natBE 2 a.2)
    (Q := fun a => 1 ≤ a.2 ∧ a.2 ≤ a.1.ceil) (fun h => ⟨by rw [(pAge_inv h)], pAge_bound h⟩) ka h19
  have e20 := need_rest h20
  have e21 := pAids_inv h21
  obtain ⟨e22, -, -⟩ := nat_inv h22
  obtain ⟨e23, l23, -⟩ := ParseLaws.many_run (p := pRule (t == tag2) (ag.map (·.1)) ci.length)
    (e := fun r : Rule => natBE 1 r.reason.idx ++ natBE 1 r.cite ++ encExpr r.cond)
    (Q := fun _ => True) (fun h => ⟨(pRule_inv h).symm, trivial⟩) kr h23
  have e24 := need_rest h24
  have e25 := need_rest h25
  subst he
  refine ⟨?_, hcost, q19⟩
  subst e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 e10 e11 e12 e13 e14 e15 e16 e17 e18 e19 e20 e21 e22 e23 e24 e25 hr l14 l17 l19 l23
  simp only [encDoc]
  rw [htag]
  simp [identBytes, identField, List.append_assoc]

theorem decode_parts {x : Bytes} {f : Frame} (h : decode x = some f) :
    ∃ rest, pDoc.run x = some (f.d, rest) ∧ Keyset.decodeSigBlock rest = some f.sigs := by
  unfold decode at h
  by_cases hl : x.length > maxRecord
  · simp [hl] at h
  · rw [if_neg hl] at h
    rcases hp : pDoc.run x with _ | ⟨d, rest⟩
    · simp [hp] at h
    · rcases hs : Keyset.decodeSigBlock rest with _ | ss
      · simp [hp, hs] at h
      · simp [hp, hs] at h
        subst h
        exact ⟨rest, rfl, hs⟩

/-! ## Proof helpers: the eligibility read unknown -/

mutual
/-- From assignments to reads: giving each atom that reads the eligibility source its value under another read `w`
    (every other atom keeps its own, which does not depend on the read) is evaluating under `w`. -/
theorem evalAt_read (v : Env) (w : ElRead) : (x : Expr) → evalAt v (eval { v with el := w }) x = eval { v with el := w } x
  | .and es => by
    simp only [evalAt, eval]
    exact allAt_read v w es
  | .or es => by
    simp only [evalAt, eval]
    exact anyAt_read v w es
  | .not e => by simp only [evalAt, eval, evalAt_read v w e]
  | .flow _ | .dateOk | .elig .. => by
    simp only [evalAt]
    split <;> first | rfl | simp_all [reads]
  | .present s | .fresh s | .overlap s => by
    cases s <;> simp only [evalAt] <;> split <;> first | rfl | simp_all [reads]
  | .hit s j t => by
    cases s <;> cases j <;> cases t <;> simp only [evalAt] <;> split <;> first | rfl | simp_all [reads]

theorem allAt_read (v : Env) (w : ElRead) : (es : List Expr) → allAt v (eval { v with el := w }) es = evalAll { v with el := w } es
  | [] => rfl
  | e :: es => by simp only [allAt, evalAll, evalAt_read v w e, allAt_read v w es]

theorem anyAt_read (v : Env) (w : ElRead) : (es : List Expr) → anyAt v (eval { v with el := w }) es = evalAny { v with el := w } es
  | [] => rfl
  | e :: es => by simp only [anyAt, evalAny, evalAt_read v w e, anyAt_read v w es]
end

mutual
theorem eval3_sound_aux (v : Env) (f : Expr → Bool) : (x : Expr) → (b : Bool) → eval3 v x = some b → evalAt v f x = b
  | .and es, b, h => by
    simp only [eval3] at h
    simp only [evalAt]
    exact all3_sound v f es b h
  | .or es, b, h => by
    simp only [eval3] at h
    simp only [evalAt]
    exact any3_sound v f es b h
  | .not e, b, h => by
    simp only [eval3] at h
    simp only [evalAt]
    have s := eval3_sound_aux v f e
    generalize eval3 v e = o at h s
    rcases o with _ | _ | _ <;> simp_all
  | .flow _, b, h | .dateOk, b, h | .present _, b, h | .fresh _, b, h | .hit .., b, h | .overlap _, b, h
  | .elig .., b, h => by
    simp only [eval3] at h
    simp only [evalAt]
    split at h <;> simp_all

theorem all3_sound (v : Env) (f : Expr → Bool) : (es : List Expr) → (b : Bool) → all3 v es = some b → allAt v f es = b
  | [], b, h => by
    simp only [all3, Option.some.injEq] at h
    simp only [allAt, h]
  | e :: es, b, h => by
    simp only [all3] at h
    simp only [allAt]
    have s1 := eval3_sound_aux v f e
    have s2 := all3_sound v f es
    generalize eval3 v e = o1 at h s1
    generalize all3 v es = o2 at h s2
    rcases o1 with _ | _ | _ <;> rcases o2 with _ | _ | _ <;> simp_all

theorem any3_sound (v : Env) (f : Expr → Bool) : (es : List Expr) → (b : Bool) → any3 v es = some b → anyAt v f es = b
  | [], b, h => by
    simp only [any3, Option.some.injEq] at h
    simp only [anyAt, h]
  | e :: es, b, h => by
    simp only [any3] at h
    simp only [anyAt]
    have s1 := eval3_sound_aux v f e
    have s2 := any3_sound v f es
    generalize eval3 v e = o1 at h s1
    generalize any3 v es = o2 at h s2
    rcases o1 with _ | _ | _ <;> rcases o2 with _ | _ | _ <;> simp_all
end

/-! ## Statements -/

/-- Agreement: the counting interpreter's answer is the interpreter's answer. -/
theorem evalC_eq (v : Env) (e : Expr) : (evalC v e).1 = eval v e := evalC_fst v e

/-- Cost: it never spends more than the condition's static cost. -/
theorem evalC_le (v : Env) (e : Expr) : (evalC v e).2 ≤ cost e := evalC_snd v e

/-- Per line, one pass: a decoded rule set's rules together spend at most `maxCost` units on any line, on any read set.
    (Per batch the claim set grows with the batch, so `claimP` is quadratic in it; this bounds a line, not a batch.) -/
theorem run_bounded {x : Bytes} {f : Frame} (h : decode x = some f) (e : ElRead) (c : Ctx) (l : Line) :
    (f.d.rules.map fun r => (evalC (f.d.env e c l) r.cond).2).sum ≤ maxCost := by
  obtain ⟨rest, hp, -⟩ := decode_parts h
  have hc := (pDoc_inv hp).2.1
  exact Nat.le_trans (sum_evalC_le _ _) hc

/-- No rule set fires a core reason. -/
theorem dataFires_core {o : Option Doc} {e : ElRead} {c : Ctx} {l : Line} {r : Reason} (h : dataReason r = false)
    (h' : eligReason r = false) : dataFires o e c l r = false := by
  cases o <;> simp [dataFires, Doc.fires, h, h']

/-! ## Proof helpers: pack 1 -/

theorem pack1_age {d : Doc} (hd : IsPack1 d) :
    d.age .DMF = 90 ∧ d.age .PDEATH = 90 ∧ d.age .EXCL = 31 ∧ d.age .SPAN = 7 := by
  obtain ⟨h1, -⟩ := hd
  unfold Doc.age
  rw [h1]
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem reason_beq (a b : Reason) : (a == b) = decide (a = b) := rfl

theorem src_beq (a b : Src) : (a == b) = decide (a = b) := rfl

theorem pack1_enrollAge {d : Doc} (hd : IsPack1 d) : d.enrollAge = 7 := by
  obtain ⟨h1, -⟩ := hd
  unfold Doc.enrollAge
  rw [h1]
  rfl

/-- Pack 1 already guards every enrollment read by freshness, so the fixed enrollment guard changes none of its answers. -/
theorem dataFires_pack1 {d : Doc} (hd : IsPack1 d) (e : ElRead) (c : Ctx) (l : Line) (r : Reason) :
    dataFires (some d) e c l r =
      (dataReason r && pack1Conds.any fun p => p.1 == r && eval (d.env e c l) p.2) := by
  have hA := pack1_age hd
  have hE := pack1_enrollAge hd
  obtain ⟨-, h2⟩ := hd
  have hm : ∀ r, ruleAny d e c l r =
      pack1Conds.any fun p => p.1 == r && eval (d.env e c l) p.2 &&
        !(enrollStale d c && !review r && reads .SPAN p.2) &&
        !(elGuard (d.env e c l) r p.2 && !(d.env e c l).fresh .ELIG) := by
    intro r
    unfold ruleAny
    rw [← h2, List.any_map]
    rfl
  have hh : elHeld d e c l = (!(d.env e c l).fresh .ELIG &&
      pack1Conds.any fun p => elGuard (d.env e c l) p.1 p.2 && eval3 (d.env e c l) p.2 != some false) := by
    unfold elHeld
    rw [← h2, List.any_map]
    rfl
  have he : reads .ELIG enrolledE = false := by simp [enrolledE, reads, readsAny, src_beq, capOnly, ffsOnly]
  simp only [dataFires, hm, hh]
  unfold enrollStale
  rw [hE]
  cases hu : usable c.today 7 okSpan c.enrollment <;> cases r <;>
    simp [pack1Conds, reason_beq, src_beq, dataReason, eligReason, Doc.fires, review, reads, readsAny, certainE,
      unverifiedE, capOnly, eval, evalAll, Doc.env, Env.fresh, elGuard, he, hA, hu]

theorem bit_cap (l : Line) : Keyset.bit 4 (l.flow.tag - 1) = isCap l := by
  cases h : l.flow <;> simp [isCap, Flow.tag, Keyset.bit, h]

theorem covers_fun (l : Line) : Rules.covers l = fun s =>
    (s.member == l.member && decide (s.start ≤ l.date) && decide (l.date ≤ s.stop) && (!isCap l || s.plan == l.payee)) := by
  funext s
  rfl

theorem flow_beq (a b : Flow) : (a == b) = decide (a = b) := rfl

theorem enrolledE_eval (v : Env) : eval v enrolledE = enrolled v.c v.l := by
  unfold enrolledE enrolled
  cases hf : v.l.flow <;>
    simp [eval, evalAll, evalAny, capOnly, ffsOnly, Keyset.bit, Flow.tag, hf, Env.hit, covers_fun, isCap, subjOk, flow_beq]

theorem dfNE_pack1 {d : Doc} (hd : IsPack1 d) (e : ElRead) (c : Ctx) (l : Line) :
    dataFires (some d) e c l .MEMBER_NOT_ENROLLED = Rules.notEnrolled c l := by
  have hA := pack1_age hd
  rw [dataFires_pack1 hd]
  simp [reason_beq, pack1Conds, certainE, eval, evalAll, Doc.env, Env.fresh, enrolledE_eval, hA, Rules.notEnrolled,
    Rules.certain, dataReason, Bool.and_assoc]

theorem claimP_pack1 {d : Doc} {el : Line → ElRead} (hd : IsPack1 d) (c : Ctx) (l : Line) :
    claimP (fun _ => some d) el c l = Rules.claim c l := by
  simp only [claimP, Rules.claim, dfNE_pack1 hd]

theorem claimP_pack1' {d : Doc} {el : Line → ElRead} (hd : IsPack1 d) (c : Ctx) :
    claimP (fun _ => some d) el c = Rules.claim c := funext (claimP_pack1 hd c)

theorem pendingP_pack1 {d : Doc} {el : Line → ElRead} (hd : IsPack1 d) (c : Ctx) (l : Line) :
    pendingP (fun _ => some d) el c l = Rules.pending c l := by
  simp only [pendingP, Rules.pending, claimP_pack1' hd]

theorem pack1_fires_aux {d : Doc} {el : Line → ElRead} (hd : IsPack1 d) (c : Ctx) (seen : List Key) (l : Line) (r : Reason) :
    firesP (fun _ => some d) el c seen l r = Rules.fires c seen l r := by
  have hA := pack1_age hd
  have hP := pendingP_pack1 (el := el) hd c l
  have hb := bit_cap l
  have hE : eval ⟨c, l, d.age, d.aids, el l⟩ enrolledE = enrolled c l := enrolledE_eval ⟨c, l, d.age, d.aids, el l⟩
  unfold firesP
  rw [dataFires_pack1 hd]
  cases r <;>
    simp [reason_beq, capOnly, Bool.and_or_distrib_left, coreFires, Rules.fires, hP, pack1Conds, dataReason, certainE, unverifiedE, eval, evalAll, evalAny,
      Doc.env, Env.fresh, Env.present, Env.hit, Env.overlap, subjOk, hA, hb, hE, Rules.certain, Rules.unverified,
      Rules.notEnrolled, Rules.memberDead, Rules.providerDead, Rules.excluded, Bool.and_assoc]

theorem firesP_pack1' {d : Doc} {el : Line → ElRead} (hd : IsPack1 d) (c : Ctx) (seen : List Key) (l : Line) :
    firesP (fun _ => some d) el c seen l = Rules.fires c seen l := funext (pack1_fires_aux hd c seen l)

theorem decideLineP_pack1 {d : Doc} {el : Line → ElRead} (hd : IsPack1 d) (c : Ctx) (seen : List Key) (l : Line) :
    decideLineP (fun _ => some d) el c seen l = Rules.decideLine c seen l := by
  simp only [decideLineP, Rules.decideLine, firesP_pack1' hd, claimP_pack1' hd]

theorem decideAllP_pack1 {d : Doc} {el : Line → ElRead} (hd : IsPack1 d) (c : Ctx) :
    ∀ (seen : List Key) (ls : List Line), decideAllP (fun _ => some d) el c seen ls = Rules.decideAll c seen ls
  | _, [] => by simp [decideAllP, Rules.decideAll]
  | seen, l :: ls => by
    simp only [decideAllP, Rules.decideAll, decideLineP_pack1 hd, claimP_pack1 hd, decideAllP_pack1 hd c _ ls]

/-- Pack 1 fires exactly today's reasons, on every read set, key list, line and reason. -/
theorem pack1_fires {d : Doc} {el : Line → ElRead} (hd : IsPack1 d) (c : Ctx) (seen : List Key) (l : Line) (r : Reason) :
    firesP (fun _ => some d) el c seen l r = Rules.fires c seen l r := pack1_fires_aux hd c seen l r

/-- Pack 1 decides every batch exactly as today's rules, so every theorem about `Rules.decideBatch` carries over. -/
theorem pack1_decideBatch {d : Doc} {el : Line → ElRead} (hd : IsPack1 d) (c : Ctx) (b : List Line) :
    decideBatchS (fun _ => some d) el c b = Rules.decideBatch c b := by
  simp only [decideBatchS, Rules.decideBatch, decideAllP_pack1 hd]

/-! ## Proof helpers: release once under any rule sets -/

theorem mem_pendingP {pick : Line → Option Doc} {el : Line → ElRead} {c : Ctx} {l : Line} {k : Key} :
    k ∈ pendingP pick el c l ↔
      ∃ u ∈ unresolvedSet c, ¬(u = l ∧ (c.byp.lookup l.pay).isSome = true) ∧ k ∈ claimP pick el c u := by
  unfold pendingP
  rw [List.mem_flatMap]
  constructor
  · rintro ⟨u, hu, hk⟩
    obtain ⟨hu, hp⟩ := List.mem_filter.mp hu
    exact ⟨u, hu, fun ⟨e, s⟩ => by simp [e, s] at hp, hk⟩
  · rintro ⟨u, hu, hn, hk⟩
    exact ⟨u, List.mem_filter.mpr ⟨hu, Rules.keep_row hn⟩, hk⟩

theorem claimP_keys {pick : Line → Option Doc} {el : Line → ElRead} {c : Ctx} {x : Line} {k : Key} (hk : k ∈ keys x)
    (hc : k ∉ claimP pick el c x) :
    x.flow = .CAP_820 ∧ k = nearKey x ∧ dataFires (pick x) (el x) c x .MEMBER_NOT_ENROLLED = true := by
  unfold claimP at hc
  split at hc
  · rename_i h
    simp only [Bool.and_eq_true, isCap, beq_iff_eq] at h
    simp only [keys, List.mem_cons, List.not_mem_nil, or_false] at hk hc
    rcases hk with rfl | rfl | rfl
    · simp at hc
    · exact ⟨h.1.1, rfl, h.1.2⟩
    · simp at hc
  · exact absurd hk hc

theorem mem_decideAllP {pick : Line → Option Doc} {el : Line → ElRead} {c : Ctx} :
    ∀ {seen : List Key} {ls : List Line} {d : Decision},
      d ∈ decideAllP pick el c seen ls → ∃ pre l, d = decideLineP pick el c (pre ++ seen) l
  | _, [], _, h => by simp [decideAllP] at h
  | seen, l :: ls, d, h => by
    simp only [decideAllP, List.mem_cons] at h
    rcases h with rfl | h
    · exact ⟨[], l, rfl⟩
    · obtain ⟨pre, l', rfl⟩ := mem_decideAllP h
      exact ⟨pre ++ claimP pick el c l, l', by rw [List.append_assoc]⟩

theorem allowP_facts {pick : Line → Option Doc} {el : Line → ElRead} {c : Ctx} {seen : List Key} {l : Line}
    (h : (decideLineP pick el c seen l).outcome = .ALLOW) :
    claimP pick el c l = keys l ∧ ∀ k ∈ keys l, k ∉ seen ∧ k ∉ pendingP pick el c l := by
  have hr : reasons.filter (firesP pick el c seen l) = [] :=
    Rules.outcomeOf_allow.mp h
  have no : ∀ r, firesP pick el c seen l r = false := fun r => by
    cases hf : firesP pick el c seen l r
    · rfl
    · have hm : r ∈ reasons.filter (firesP pick el c seen l) := List.mem_filter.mpr ⟨Rules.mem_all r, hf⟩
      rw [hr] at hm
      cases hm
  have hn : dataFires (pick l) (el l) c l .MEMBER_NOT_ENROLLED = false := by
    have := no .MEMBER_NOT_ENROLLED
    simpa [firesP, coreFires] using this
  refine ⟨by simp [claimP, hn], fun k hk => ?_⟩
  have h1 := no .ALREADY_DECIDED
  have h2 := no .CAP_MEMBER_MONTH_DUPLICATE
  have h3 := no .COLLIDES_WITH_UNRESOLVED_NEAR
  have h4 := no .DUPLICATE_OF_UNRESOLVED
  have h5 := no .FFS_DUPLICATE_LINE
  have h6 := no .FFS_NEAR_DUPLICATE
  simp only [firesP, coreFires, Bool.or_eq_false_iff] at h2
  replace h2 := h2.1
  simp only [firesP, dataFires_core (r := .ALREADY_DECIDED) rfl rfl, Bool.or_false, coreFires] at h1
  simp only [firesP, dataFires_core (r := .COLLIDES_WITH_UNRESOLVED_NEAR) rfl rfl, Bool.or_false, coreFires] at h3
  simp only [firesP, dataFires_core (r := .DUPLICATE_OF_UNRESOLVED) rfl rfl, Bool.or_false, coreFires] at h4
  simp only [firesP, dataFires_core (r := .FFS_DUPLICATE_LINE) rfl rfl, Bool.or_false, coreFires] at h5
  simp only [firesP, dataFires_core (r := .FFS_NEAR_DUPLICATE) rfl rfl, Bool.or_false, coreFires] at h6
  simp only [keys, List.mem_cons, List.not_mem_nil, or_false] at hk
  rcases hk with rfl | rfl | rfl
  · cases hc : isCap l
    · refine ⟨fun hs => by simp [hc, hs] at h5, fun hp => by simp [hp] at h4⟩
    · exact ⟨fun hs => by simp [hc, hs] at h2, fun hp => by simp [hc, hp] at h4⟩
  · cases hc : isCap l
    · refine ⟨fun hs => ?_, fun hp => ?_⟩
      · by_cases he : exactKey l ∈ seen
        · simp [hc, he] at h5
        · simp [hc, hs, he] at h6
      · by_cases he : exactKey l ∈ pendingP pick el c l
        · simp [he] at h4
        · simp [hc, hp, he] at h3
    · exact ⟨fun hs => by simp [hc, hs] at h2, fun hp => by simp [hc, hp] at h4⟩
  · exact ⟨fun hs => by simp [hs] at h1, fun hp => by simp [hp] at h1⟩

/-- Release once, under any rule sets: `Rules.allow_clear` with each unresolved row's own rule set in place of the
    fixed enrollment rule. -/
theorem allow_clear_any {pick : Line → Option Doc} {el : Line → ElRead} {c : Ctx} {b : List Line} {d : Decision}
    (hd : d ∈ (decideBatchS pick el c b).decisions) (ha : d.outcome = .ALLOW) :
    ∀ x ∈ releasedSet c ++ unresolvedSet c, ∀ k ∈ keys d.line, k ∈ keys x →
      (own c x = true ∧ x ∈ b) ∨ (ownU c x = true ∧ x = d.line) ∨
        (x.flow = .CAP_820 ∧ k = nearKey x ∧ dataFires (pick x) (el x) c x .MEMBER_NOT_ENROLLED = true) := by
  obtain ⟨pre, l, rfl⟩ := mem_decideAllP (pick := pick) (el := el) (c := c) (seen := seen0 c b) (ls := order c b) hd
  intro x hx k hk hkx
  change k ∈ keys l at hk
  have hf := (allowP_facts ha).2 k hk
  rcases List.mem_append.mp hx with hx | hx
  · by_cases ho : own c x = true ∧ x ∈ b
    · exact Or.inl ho
    · exact (hf.1 (List.mem_append.mpr (Or.inr (List.mem_flatMap.mpr
        ⟨x, List.mem_filter.mpr ⟨hx, Rules.not_own_mem ho⟩, hkx⟩)))).elim
  · by_cases hu : x = l ∧ (c.byp.lookup l.pay).isSome = true
    · obtain ⟨rfl, hs⟩ := hu
      exact Or.inr (Or.inl ⟨by simp only [ownU, hs, List.contains_iff_mem.mpr hx, Bool.and_self], rfl⟩)
    · exact Or.inr (Or.inr (claimP_keys hkx (fun hc => hf.2 (mem_pendingP.mpr ⟨x, hx, hu, hc⟩))))

/-- One byte string per record: a decoded record encodes back to exactly its input. -/
theorem decode_canonical {x : Bytes} {f : Frame} (h : decode x = some f) : encode f = x := by
  obtain ⟨rest, hp, hs⟩ := decode_parts h
  have e1 := (pDoc_inv hp).1
  have e2 := Keyset.encodeSigs_decode hs
  unfold encode
  rw [e2, e1]

/-- Admission, with or without the signing window, implies a POLICY quorum signed exactly the admitted record, for this
    state and tenant. -/
theorem admitW_signed {win verify H tenant kb s x a} (h : admitW win verify H tenant kb s x = .ok a) :
    ∃ f, decode x = some f ∧ a.doc = f.d ∧ a.id = digestOf f.d ∧ a.kb = kb ∧
      f.d.state = H.ks.state ∧ f.d.tenantId = tenant ∧
      Keyset.quorum verify (Keyset.policyOk H.day) (·.employee) H.ks H.ks.kPolicy (msgOf f) f.sigs = true := by
  unfold admitW at h
  rcases hx : decode x with _ | f
  · simp [hx] at h
  · simp only [hx] at h
    refine ⟨f, rfl, ?_⟩
    iterate 7 (split at h <;> try cases h)
    simp_all

/-- Admission, with or without the end of the signing window, never takes a record before its window opens. -/
theorem admitW_notBefore {win verify H tenant kb s x a} (h : admitW win verify H tenant kb s x = .ok a) :
    Rules.dayNum a.doc.notBefore ≤ Rules.dayNum H.day := by
  unfold admitW at h
  rcases hx : decode x with _ | f
  · simp [hx] at h
  · simp only [hx] at h
    iterate 7 (split at h <;> try cases h)
    simp_all [Authority.windowOk]

/-- Admission never takes a record with a rule for a reason no data source backs. -/
theorem admitW_backed {win verify H tenant kb s x a} (h : admitW win verify H tenant kb s x = .ok a) :
    unbacked a.doc = false := by
  unfold admitW at h
  rcases hx : decode x with _ | f
  · simp [hx] at h
  · simp only [hx] at h
    iterate 7 (split at h <;> try cases h)
    simp_all

/-- Admission implies a POLICY quorum signed exactly the admitted record, for this state and tenant. -/
theorem admit_signed {verify H tenant kb s x a} (h : admit verify H tenant kb s x = .ok a) :
    ∃ f, decode x = some f ∧ a.doc = f.d ∧ a.id = digestOf f.d ∧ a.kb = kb ∧
      f.d.state = H.ks.state ∧ f.d.tenantId = tenant ∧
      Keyset.quorum verify (Keyset.policyOk H.day) (·.employee) H.ks H.ks.kPolicy (msgOf f) f.sigs = true :=
  admitW_signed h

/-- A record without a POLICY quorum is never admitted. -/
theorem admit_unsigned {verify H tenant kb s x f} (hx : decode x = some f)
    (hq : Keyset.quorum verify (Keyset.policyOk H.day) (·.employee) H.ks H.ks.kPolicy (msgOf f) f.sigs = false) :
    ∀ a, admit verify H tenant kb s x ≠ .ok a := by
  intro a h
  obtain ⟨f', hx', -, -, -, -, -, hq'⟩ := admit_signed h
  rw [hx, Option.some.injEq] at hx'
  subst hx'
  rw [hq] at hq'
  cases hq'

/-- POLICY quorum needed: an admitted rule set under a well-formed head was signed by at least `kPolicy ≥ 2` people,
    pairwise distinct in employee and in identity-provider subject, each with a POLICY key of the head live on its day. -/
theorem admit_policy {verify H tenant kb s x a} (hw : Keyset.Wf H.ks) (h : admit verify H tenant kb s x = .ok a) :
    ∃ f, decode x = some f ∧ a.doc = f.d ∧ Keyset.minPolicy ≤ H.ks.kPolicy ∧
      ∃ es : List Keyset.Entry, es.Sublist H.ks.entries ∧ H.ks.kPolicy ≤ es.length ∧
        (es.map (·.employee)).Nodup ∧ (es.map (·.idp)).Nodup ∧
        ∀ e ∈ es, Keyset.policyOk H.day e = true ∧ ∃ r ∈ f.sigs, r.keyId = e.keyId ∧ verify e.pk (msgOf f) r.sig = true := by
  obtain ⟨f, hx, hd, -, -, -, -, hq⟩ := admit_signed h
  exact ⟨f, hx, hd, Keyset.policy_signers hw hq⟩

/-- Roster keys alone never admit a rule set: when every key with a verifying record is a ROSTER key, it is refused. -/
theorem admit_roster_only {verify H tenant kb s x f} (hx : decode x = some f)
    (hr : ∀ e ∈ H.ks.entries, Keyset.signedBy verify (msgOf f) f.sigs e = true → e.role = Keyset.roster) :
    ∀ a, admit verify H tenant kb s x ≠ .ok a :=
  admit_unsigned hx (Keyset.policy_not_roster hr)

/-- Every rule set of a series was signed. -/
theorem reachable_signed {verify} {s : List Admitted} (hs : Reachable verify s) : ∀ a ∈ s, Signed verify a := by
  induction hs with
  | nil => intro a ha; cases ha
  | @step s a' H tenant kb x _ hadm ih =>
    intro a ha
    rcases List.mem_append.1 ha with ha | ha
    · exact ih a ha
    · rw [List.mem_singleton] at ha
      subst ha
      obtain ⟨f, hx, hd, hid, -, -, -, hq⟩ := admit_signed hadm
      exact ⟨H, x, f, hx, hd.symm, hid, hq⟩

/-! ## Enrollment age -/

/-- Every admitted rule set runs the enrollment feed at 1 to `ceilEnrollment` days: a record declaring an age outside
    that does not decode, so `admit` refuses it (MALFORMED); one that declares none runs at `enrollDefault`. -/
theorem admit_enrollAge {verify H tenant kb s x a} (h : admit verify H tenant kb s x = .ok a) :
    1 ≤ a.doc.enrollAge ∧ a.doc.enrollAge ≤ ceilEnrollment := by
  obtain ⟨f, hx, hd, -⟩ := admit_signed h
  obtain ⟨rest, hp, -⟩ := decode_parts hx
  have hq := (pDoc_inv hp).2.2
  rw [hd]
  unfold Doc.enrollAge
  rcases hf : f.d.ages.find? (·.1 == .SPAN) with _ | ⟨src, n⟩
  · rw [hf]; decide
  · have hs : src = .SPAN := by simpa [src_beq] using List.find?_some hf
    obtain ⟨h1, h2⟩ := hq _ (List.mem_of_find?_eq_some hf)
    subst hs
    rw [hf]
    exact ⟨h1, h2⟩

/-- A late enrollment feed never lets a line through: `STALE_ENROLLMENT` fires, so the line is not allowed. -/
theorem enroll_stale_allow {pick : Line → Option Doc} {el : Line → ElRead} {c : Ctx} {seen : List Key} {l : Line} {d : Doc}
    (hp : pick l = some d) (hs : enrollStale d c = true) :
    Reason.STALE_ENROLLMENT ∈ (decideLineP pick el c seen l).reasons ∧ (decideLineP pick el c seen l).outcome ≠ .ALLOW := by
  have hf : firesP pick el c seen l .STALE_ENROLLMENT = true := by
    simp [firesP, coreFires, dataFires, Doc.fires, hp, hs, dataReason]
  have hm : Reason.STALE_ENROLLMENT ∈ reasons.filter (firesP pick el c seen l) :=
    List.mem_filter.mpr ⟨Rules.mem_all _, hf⟩
  refine ⟨hm, fun ha => ?_⟩
  have h0 : reasons.filter (firesP pick el c seen l) = [] := Rules.outcomeOf_allow.mp ha
  rw [h0] at hm
  cases hm

mutual
theorem eval_noSpan (c : Ctx) (l : Line) (a : Src → Nat) (t : List (Bytes × Nat)) (w : ElRead) : (e : Expr) → reads .SPAN e = false →
    eval ⟨c, l, a, t, w⟩ e = eval ⟨{ c with enrollment := none }, l, a, t, w⟩ e
  | .and es, h => by
    simp only [eval]
    exact evalAll_noSpan c l a t w es (by simpa [reads] using h)
  | .or es, h => by
    simp only [eval]
    exact evalAny_noSpan c l a t w es (by simpa [reads] using h)
  | .not e, h => by
    simp only [eval]
    rw [eval_noSpan c l a t w e (by simpa [reads] using h)]
  | .flow _, _ => rfl
  | .dateOk, _ => rfl
  | .present s, h => by cases s <;> simp_all [reads, src_beq, eval, Env.present]
  | .fresh s, h => by cases s <;> simp_all [reads, src_beq, eval, Env.fresh]
  | .hit s j t, h => by cases s <;> cases j <;> cases t <;> simp_all [reads, src_beq, eval, Env.hit]
  | .overlap s, h => by cases s <;> simp_all [reads, src_beq, eval, Env.overlap]
  | .elig _ _, _ => rfl

theorem evalAll_noSpan (c : Ctx) (l : Line) (a : Src → Nat) (t : List (Bytes × Nat)) (w : ElRead) : (es : List Expr) → readsAny .SPAN es = false →
    evalAll ⟨c, l, a, t, w⟩ es = evalAll ⟨{ c with enrollment := none }, l, a, t, w⟩ es
  | [], _ => rfl
  | e :: es, h => by
    simp only [readsAny, Bool.or_eq_false_iff] at h
    simp only [evalAll, eval_noSpan c l a t w e h.1, evalAll_noSpan c l a t w es h.2]

theorem evalAny_noSpan (c : Ctx) (l : Line) (a : Src → Nat) (t : List (Bytes × Nat)) (w : ElRead) : (es : List Expr) → readsAny .SPAN es = false →
    evalAny ⟨c, l, a, t, w⟩ es = evalAny ⟨{ c with enrollment := none }, l, a, t, w⟩ es
  | [], _ => rfl
  | e :: es, h => by
    simp only [readsAny, Bool.or_eq_false_iff] at h
    simp only [evalAny, eval_noSpan c l a t w e h.1, evalAny_noSpan c l a t w es h.2]
end

mutual
theorem eval3_noSpan (c : Ctx) (l : Line) (a : Src → Nat) (t : List (Bytes × Nat)) (w : ElRead) : (e : Expr) → reads .SPAN e = false →
    eval3 ⟨c, l, a, t, w⟩ e = eval3 ⟨{ c with enrollment := none }, l, a, t, w⟩ e
  | .and es, h => by
    simp only [eval3]
    exact all3_noSpan c l a t w es (by simpa [reads] using h)
  | .or es, h => by
    simp only [eval3]
    exact any3_noSpan c l a t w es (by simpa [reads] using h)
  | .not e, h => by
    simp only [eval3]
    rw [eval3_noSpan c l a t w e (by simpa [reads] using h)]
  | .flow _, h | .dateOk, h | .present _, h | .fresh _, h | .hit .., h | .overlap _, h | .elig .., h => by
    simp only [eval3]
    rw [eval_noSpan c l a t w _ h]

theorem all3_noSpan (c : Ctx) (l : Line) (a : Src → Nat) (t : List (Bytes × Nat)) (w : ElRead) : (es : List Expr) → readsAny .SPAN es = false →
    all3 ⟨c, l, a, t, w⟩ es = all3 ⟨{ c with enrollment := none }, l, a, t, w⟩ es
  | [], _ => rfl
  | e :: es, h => by
    simp only [readsAny, Bool.or_eq_false_iff] at h
    simp only [all3]
    rw [eval3_noSpan c l a t w e h.1, all3_noSpan c l a t w es h.2]

theorem any3_noSpan (c : Ctx) (l : Line) (a : Src → Nat) (t : List (Bytes × Nat)) (w : ElRead) : (es : List Expr) → readsAny .SPAN es = false →
    any3 ⟨c, l, a, t, w⟩ es = any3 ⟨{ c with enrollment := none }, l, a, t, w⟩ es
  | [], _ => rfl
  | e :: es, h => by
    simp only [readsAny, Bool.or_eq_false_iff] at h
    simp only [any3]
    rw [eval3_noSpan c l a t w e h.1, any3_noSpan c l a t w es h.2]
end

theorem any_noSpan (c : Ctx) (l : Line) (a : Src → Nat) (t : List (Bytes × Nat)) (w : ElRead) (r : Reason)
    (g : Env → Rule → Bool)
    (hg : ∀ x : Rule, reads .SPAN x.cond = false →
      g ⟨c, l, a, t, w⟩ x = g ⟨{ c with enrollment := none }, l, a, t, w⟩ x) : ∀ rs : List Rule,
    (rs.any fun x => x.reason == r && eval ⟨c, l, a, t, w⟩ x.cond && !reads .SPAN x.cond && g ⟨c, l, a, t, w⟩ x) =
      (rs.any fun x => x.reason == r && eval ⟨{ c with enrollment := none }, l, a, t, w⟩ x.cond && !reads .SPAN x.cond &&
        g ⟨{ c with enrollment := none }, l, a, t, w⟩ x)
  | [] => rfl
  | x :: rs => by
    simp only [List.any_cons, any_noSpan c l a t w r g hg rs]
    cases hx : reads .SPAN x.cond
    · rw [eval_noSpan c l a t w x.cond hx, hg x hx]
    · simp

theorem enrollStale_none (d : Doc) (c : Ctx) : enrollStale d { c with enrollment := none } = true := rfl

theorem dataFires_noSpan {d : Doc} {e : ElRead} {c : Ctx} (hs : enrollStale d c = true) (l : Line) {r : Reason}
    (hr : review r = false) :
    dataFires (some d) e c l r = dataFires (some d) e { c with enrollment := none } l r := by
  have ha : ∀ {r : Reason}, review r = false → ruleAny d e c l r = ruleAny d e { c with enrollment := none } l r := by
    intro r hr
    simp only [ruleAny, Doc.env, hs, enrollStale_none, hr, Bool.not_false, Bool.true_and, Bool.and_true]
    exact any_noSpan c l d.age d.aids e r (fun v x => !(elGuard v r x.cond && !v.fresh .ELIG))
      (fun x hx => by simp only [elGuard, eval3_noSpan c l d.age d.aids e x.cond hx] <;> rfl) d.rules
  have h27 : (r == .PROGRAM_NOT_ELIGIBLE_UNVERIFIED) = false := by
    cases r <;> first | rfl | exact absurd hr (by decide)
  simp only [dataFires, h27, Bool.false_and, Bool.or_false, hs, enrollStale_none]
  rw [ha hr]

theorem claimP_noSpan {pick : Line → Option Doc} {el : Line → ElRead} {c : Ctx} (hs : ∀ x d, pick x = some d → enrollStale d c = true)
    (x : Line) : claimP pick el c x = claimP pick el { c with enrollment := none } x := by
  have h : dataFires (pick x) (el x) c x .MEMBER_NOT_ENROLLED =
      dataFires (pick x) (el x) { c with enrollment := none } x .MEMBER_NOT_ENROLLED := by
    rcases hp : pick x with _ | d
    · rfl
    · exact dataFires_noSpan (hs x d hp) x rfl
  unfold claimP
  rw [h] <;> rfl

theorem pendingP_noSpan {pick : Line → Option Doc} {el : Line → ElRead} {c : Ctx} (hs : ∀ x d, pick x = some d → enrollStale d c = true)
    (l : Line) : pendingP pick el c l = pendingP pick el { c with enrollment := none } l := by
  have h : claimP pick el c = claimP pick el { c with enrollment := none } := funext (claimP_noSpan hs)
  unfold pendingP
  rw [h] <;> rfl

theorem firesP_noSpan {pick : Line → Option Doc} {el : Line → ElRead} {c : Ctx} (hs : ∀ x d, pick x = some d → enrollStale d c = true)
    (seen : List Key) (l : Line) {r : Reason} (hr : review r = false) :
    firesP pick el c seen l r = firesP pick el { c with enrollment := none } seen l r := by
  have hp := pendingP_noSpan (el := el) hs l
  have hc : coreFires pick el c seen l r = coreFires pick el { c with enrollment := none } seen l r := by
    cases r <;> simp only [coreFires, hp] <;> rfl
  unfold firesP
  rw [hc]
  rcases hq : pick l with _ | d
  · rfl
  · rw [dataFires_noSpan (hs l d hq) l hr]

/-- Under a stale enrollment feed a line's hold reasons are exactly those it has with no enrollment feed at all: when
    every rule set in use finds the feed stale, the guard itself adds no hold reason (with `enroll_stale_allow`: review,
    unless a fact from another source holds it).  One indirect effect remains: a `MEMBER_NOT_ENROLLED` the guard
    suppresses no longer drops the near-key relaxation in the claim, so a later line of the same member and month may
    hold on `CAP_MEMBER_MONTH_DUPLICATE`.  That fails closed, as `Rules.claim` does. -/
theorem enroll_stale_hold {pick : Line → Option Doc} {el : Line → ElRead} {c : Ctx} (seen : List Key) (l : Line)
    (hs : ∀ x d, pick x = some d → enrollStale d c = true) :
    (decideLineP pick el c seen l).reasons.filter (!review ·) =
      (decideLineP pick el { c with enrollment := none } seen l).reasons.filter (!review ·) := by
  show (reasons.filter (firesP pick el c seen l)).filter (!review ·) =
    (reasons.filter (firesP pick el { c with enrollment := none } seen l)).filter (!review ·)
  simp only [List.filter_filter]
  apply List.filter_congr
  intro r _
  cases hr : review r
  · simp only [Bool.not_false, Bool.true_and]
    exact firesP_noSpan hs seen l hr
  · rfl

theorem endOf_le_effTo (s : List Admitted) (a : Admitted) : endOf s a ≤ a.doc.effTo := by
  unfold endOf
  have : ∀ (l : List Admitted) (t : Nat), l.foldl (fun t b => match b.doc.ends.find? (·.version == a.doc.version) with
      | some e => min t e.to
      | none => t) t ≤ t := by
    intro l
    induction l with
    | nil => intro t; exact Nat.le_refl _
    | cons x l ih =>
      intro t
      simp only [List.foldl_cons]
      refine Nat.le_trans (ih _) ?_
      split
      · exact Nat.min_le_left _ _
      · exact Nat.le_refl _
  exact this s _

theorem endOf_append_le (s r : List Admitted) (a : Admitted) : endOf (s ++ r) a ≤ endOf s a := by
  unfold endOf
  rw [List.foldl_append]
  generalize (s.foldl (fun t b => match b.doc.ends.find? (·.version == a.doc.version) with
      | some e => min t e.to
      | none => t) a.doc.effTo) = t
  have : ∀ (l : List Admitted) (t : Nat), l.foldl (fun t b => match b.doc.ends.find? (·.version == a.doc.version) with
      | some e => min t e.to
      | none => t) t ≤ t := by
    intro l
    induction l with
    | nil => intro t; exact Nat.le_refl _
    | cons x l ih =>
      intro t
      simp only [List.foldl_cons]
      refine Nat.le_trans (ih _) ?_
      split
      · exact Nat.min_le_left _ _
      · exact Nat.le_refl _
  exact this r t

theorem endOf_snoc (s : List Admitted) (x a : Admitted) : endOf (s ++ [x]) a = endWith s x.doc a := by
  unfold endOf endWith
  rw [List.foldl_append]
  simp only [List.foldl_cons, List.foldl_nil, endOf]

theorem inForce_mono {s r : List Admitted} {a : Admitted} {D : Nat} (h : inForce (s ++ r) a D = true) :
    inForce s a D = true := by
  have := endOf_append_le s r a
  simp only [inForce, Bool.and_eq_true, decide_eq_true_eq] at h ⊢
  exact ⟨h.1, Nat.le_trans h.2 this⟩

/-- The facts a successful admission gives. -/
theorem admit_ok {verify H tenant kb s x} {a : Admitted} (h : admit verify H tenant kb s x = .ok a) :
    a.kb = kb ∧ chainOk s a.doc kb = true ∧ disjoint s a.doc = true := by
  unfold admit admitW at h
  split at h
  · cases h
  · rename_i f hf
    split at h
    · cases h
    split at h
    · cases h
    split at h
    · cases h
    split at h
    · cases h
    split at h
    · cases h
    split at h
    · cases h
    split at h
    · cases h
    · cases h
      simp_all

theorem reachable_sorted {verify} {s : List Admitted} (hs : Reachable verify s) :
    s.Pairwise (fun a b => a.kb ≤ b.kb) := by
  induction hs with
  | nil => exact List.Pairwise.nil
  | @step s a H tenant kb x _ hadm ih =>
    obtain ⟨hkb, hch, _⟩ := admit_ok hadm
    rw [List.pairwise_append]
    refine ⟨ih, List.pairwise_singleton _ _, ?_⟩
    intro y hy z hz
    rw [List.mem_singleton] at hz
    subst hz
    rw [hkb]
    unfold chainOk at hch
    rcases List.eq_nil_or_concat s with hnil | ⟨L, l, hl⟩
    · subst hnil; cases hy
    · subst hl
      simp only [List.concat_eq_append] at ih hch
      rw [List.getLast?_concat] at hch
      simp only [Bool.and_eq_true, decide_eq_true_eq] at hch
      have hlk := hch.2
      rw [List.pairwise_append] at ih
      simp only [List.concat_eq_append] at hy
      rcases List.mem_append.mp hy with hy | hy
      · exact Nat.le_trans (ih.2.2 y hy l (by simp)) hlk
      · rw [List.mem_singleton] at hy; subst hy; exact hlk

/-- Each admitted record was disjoint from every earlier one. -/
def DisjInv (s : List Admitted) : Prop :=
  ∀ p b r, s = p ++ b :: r → disjoint p b.doc = true

theorem reachable_disj {verify} {s : List Admitted} (hs : Reachable verify s) : DisjInv s := by
  induction hs with
  | nil => intro p b r h; simp at h
  | @step s a H tenant kb x _ hadm ih =>
    obtain ⟨_, _, hd⟩ := admit_ok hadm
    intro p b r h
    rcases List.eq_nil_or_concat r with hr | ⟨L, y, hr⟩
    · subst hr
      have h' : s ++ [a] = p ++ [b] := by simpa using h
      obtain ⟨h1, h2⟩ := List.append_inj' h' (by simp)
      have hab : a = b := by simpa using h2
      subst h1; subst hab; exact hd
    · subst hr
      have h' : s ++ [a] = (p ++ b :: L) ++ [y] := by simpa using h
      obtain ⟨h1, _⟩ := List.append_inj' h' (by simp)
      exact ih p b L h1

theorem DisjInv.init {s : List Admitted} {x : Admitted} (h : DisjInv (s ++ [x])) : DisjInv s := by
  intro p b r hpb
  exact h p b (r ++ [x]) (by rw [hpb]; simp)

theorem DisjInv.prefix {s r : List Admitted} (h : DisjInv (s ++ r)) : DisjInv s := by
  intro p b q hpb
  exact h p b (q ++ r) (by rw [hpb]; simp)

theorem unique_of_disj {P : List Admitted} (hP : DisjInv P) {D : Nat} {a b : Admitted}
    (ha : a ∈ P) (hb : b ∈ P) (hfa : inForce P a D = true) (hfb : inForce P b D = true) : a = b := by
  have main : ∀ (n : Nat) (P : List Admitted), P.length ≤ n → DisjInv P → ∀ a b : Admitted, a ∈ P → b ∈ P →
      inForce P a D = true → inForce P b D = true → a = b := by
    intro n
    induction n with
    | zero =>
      intro P hl _ a b ha
      have : P = [] := List.eq_nil_of_length_eq_zero (Nat.le_zero.mp hl)
      subst this; cases ha
    | succ n ih =>
      intro P hl hP a b ha hb hfa hfb
      rcases List.eq_nil_or_concat P with hnil | ⟨P0, x, hP0⟩
      · subst hnil; cases ha
      · simp only [List.concat_eq_append] at hP0
        subst hP0
        have hl0 : P0.length ≤ n := by simp at hl; omega
        have hd : disjoint P0 x.doc = true := hP P0 x [] (by simp)
        have key : ∀ c, c ∈ P0 → inForce (P0 ++ [x]) c D = true → inForce (P0 ++ [x]) x D = true → False := by
          intro c hc hfc hfx
          have hdc := (List.all_eq_true.mp hd) c hc
          have e := endOf_snoc P0 x c
          have hcle := endOf_le_effTo (P0 ++ [x]) x
          simp only [inForce, Bool.and_eq_true, decide_eq_true_eq] at hfc hfx
          simp only [Bool.or_eq_true, decide_eq_true_eq] at hdc
          rw [e] at hfc
          rcases hdc with (h1 | h1) | h1
          · omega
          · omega
          · omega
        rcases List.mem_append.mp ha with ha' | ha' <;> rcases List.mem_append.mp hb with hb' | hb'
        · exact ih P0 hl0 hP.init a b ha' hb' (inForce_mono hfa) (inForce_mono hfb)
        · rw [List.mem_singleton] at hb'; subst hb'; exact (key a ha' hfa hfb).elim
        · rw [List.mem_singleton] at ha'; subst ha'; exact (key b hb' hfb hfa).elim
        · rw [List.mem_singleton] at ha' hb'; rw [ha', hb']
  exact main P.length P (Nat.le_refl _) hP a b ha hb hfa hfb

theorem known_prefix {s : List Admitted} (K : Nat) (hs : s.Pairwise (fun a b => a.kb ≤ b.kb)) :
    ∃ R, s = known s K ++ R := by
  induction s with
  | nil => exact ⟨[], rfl⟩
  | cons x t ih =>
    rw [List.pairwise_cons] at hs
    by_cases hx : x.kb ≤ K
    · obtain ⟨R, hR⟩ := ih hs.2
      refine ⟨R, ?_⟩
      simp only [known, List.filter_cons, hx, decide_true] at hR ⊢
      simp only [if_true, List.cons_append]
      rw [← hR]
    · refine ⟨x :: t, ?_⟩
      have : known t K = [] := by
        unfold known
        rw [List.filter_eq_nil_iff]
        intro y hy
        have := hs.1 y hy
        simp only [decide_eq_true_eq]; omega
      simp only [known, List.filter_cons, hx, decide_false] at this ⊢
      simp [this]

/-- Only an admitted rule set is ever selected, so only a signed one ever runs. -/
theorem select_mem {s : List Admitted} {K D : Nat} {a : Admitted} (h : select s K D = some a) : a ∈ s := by
  unfold select at h
  have := List.mem_of_find?_eq_some h
  exact (List.mem_filter.mp this).1

/-- At most one rule set is in force for a date, at every known time. -/
theorem select_unique {verify} {s : List Admitted} (hs : Reachable verify s) {K D : Nat} {a b : Admitted}
    (ha : a ∈ known s K) (hb : b ∈ known s K)
    (hfa : inForce (known s K) a D = true) (hfb : inForce (known s K) b D = true) : a = b := by
  obtain ⟨R, hR⟩ := known_prefix K (reachable_sorted hs)
  have hd : DisjInv (known s K ++ R) := hR ▸ reachable_disj hs
  exact unique_of_disj hd.prefix ha hb hfa hfb

/-- Selection finds that one. -/
theorem select_iff {verify} {s : List Admitted} (hs : Reachable verify s) {K D : Nat} {a : Admitted} :
    select s K D = some a ↔ a ∈ known s K ∧ inForce (known s K) a D = true := by
  constructor
  · intro h
    unfold select at h
    have h2 := List.find?_some h
    exact ⟨List.mem_of_find?_eq_some h, h2⟩
  · rintro ⟨hm, hf⟩
    unfold select
    have hsome : ((known s K).find? fun a => inForce (known s K) a D).isSome = true :=
      List.find?_isSome.mpr ⟨a, hm, hf⟩
    obtain ⟨b, hb⟩ := Option.isSome_iff_exists.mp hsome
    rw [hb]
    have h1 := List.mem_of_find?_eq_some hb
    have h2 := List.find?_some hb
    rw [select_unique hs hm h1 hf h2]

/-- Replay depends on the series only through what was known at `K`. -/
theorem replay_congr {s s' : List Admitted} {K : Nat} (h : known s K = known s' K) (el : Line → ElRead) (c : Ctx)
    (b : List Line) :
    replayAt s K el c b = replayAt s' K el c b := by
  have : select s K = select s' K := by
    funext D
    unfold select
    rw [h]
  simp only [replayAt, this]

/-- A rule set admitted after `K` never changes a replay as of `K`. -/
theorem replay_later {s₁ s₂ : List Admitted} {K : Nat} (h : ∀ a ∈ s₂, K < a.kb) (el : Line → ElRead) (c : Ctx)
    (b : List Line) :
    replayAt (s₁ ++ s₂) K el c b = replayAt s₁ K el c b := by
  apply replay_congr
  have : known s₂ K = [] := by
    unfold known
    rw [List.filter_eq_nil_iff]
    intro y hy
    have := h y hy
    simp only [decide_eq_true_eq]; omega
  have e : known (s₁ ++ s₂) K = known s₁ K ++ known s₂ K := by
    unfold known; exact List.filter_append _ _
  rw [e, this, List.append_nil]

/-! ## The gate's step: pack 1 as the state's signed data

    The gate's fast deciders are proved equal to `Rules.decideBatch`, and pack 1 decides exactly as it does
    (`pack1_decideBatch`).  So until the fast deciders run the interpreter itself, the gate can run a signed rule set
    that is pack 1 in force for every calendar date: version 1, no ends, effective from `firstDate` to `openEnd`
    (`runnable`).  The shard keeps the series head (the digest of the admitted record, `zeroDigest` for none) and its
    version in its authority record, and each frame carries the record again.  `gateStep` is what the rows-file engine
    does with a frame's rule-set records (`Engine3.RuleGate`).  `live_pack1` ties the decision to the interpreter: under
    the shard's rule set, a batch whose every line is covered replays to exactly today's decisions.  A record that is
    not runnable holds the frame (`unsupported`): a second version, an end or another pack waits for the fast deciders
    to run the interpreter. -/

mutual
/-- Structural equality of conditions. -/
def Expr.beq : Expr → Expr → Bool
  | .and a, .and b => Expr.beqs a b
  | .or a, .or b => Expr.beqs a b
  | .not a, .not b => Expr.beq a b
  | .flow m, .flow n => m == n
  | .dateOk, .dateOk => true
  | .present s, .present t => s == t
  | .fresh s, .fresh t => s == t
  | .hit s j u, .hit t k v => s == t && j == k && u == v
  | .overlap s, .overlap t => s == t
  | .elig q a, .elig r b => q == r && a == b
  | _, _ => false

def Expr.beqs : List Expr → List Expr → Bool
  | [], [] => true
  | a :: as, b :: bs => Expr.beq a b && Expr.beqs as bs
  | _, _ => false
end

mutual
theorem Expr.beq_sound : (a b : Expr) → Expr.beq a b = true → a = b
  | .and as, b, h => by
    cases b <;> simp only [Expr.beq, Bool.false_eq_true] at h
    exact congrArg Expr.and (Expr.beqs_sound as _ h)
  | .or as, b, h => by
    cases b <;> simp only [Expr.beq, Bool.false_eq_true] at h
    exact congrArg Expr.or (Expr.beqs_sound as _ h)
  | .not a, b, h => by
    cases b <;> simp only [Expr.beq, Bool.false_eq_true] at h
    exact congrArg Expr.not (Expr.beq_sound a _ h)
  | .flow _, b, h | .dateOk, b, h | .present _, b, h | .fresh _, b, h | .hit .., b, h | .overlap _, b, h
  | .elig .., b, h => by
    cases b <;> simp_all [Expr.beq]

theorem Expr.beqs_sound : (a b : List Expr) → Expr.beqs a b = true → a = b
  | [], b, h => by cases b <;> simp_all [Expr.beqs]
  | x :: xs, b, h => by
    cases b with
    | nil => simp [Expr.beqs] at h
    | cons y ys =>
      simp only [Expr.beqs, Bool.and_eq_true] at h
      rw [Expr.beq_sound x y h.1, Expr.beqs_sound xs ys h.2]
end

/-- The record's ages and rules are pack 1's (`IsPack1`, decided). -/
def isPack1 (d : Doc) : Bool :=
  d.ages == pack1Ages && Expr.beqs (d.rules.map (·.cond)) (pack1Conds.map (·.2)) &&
    d.rules.map (·.reason) == pack1Conds.map (·.1)

theorem map_pairs : ∀ (rs : List Rule) (ps : List (Reason × Expr)), rs.map (·.cond) = ps.map (·.2) →
    rs.map (·.reason) = ps.map (·.1) → rs.map (fun r => (r.reason, r.cond)) = ps
  | [], [], _, _ => rfl
  | r :: rs, p :: ps, h1, h2 => by
    simp only [List.map_cons, List.cons.injEq] at h1 h2 ⊢
    exact ⟨Prod.ext h2.1 h1.1, map_pairs rs ps h1.2 h2.2⟩
  | [], _ :: _, h1, _ | _ :: _, [], h1, _ => by simp at h1

theorem isPack1_sound {d : Doc} (h : isPack1 d = true) : IsPack1 d := by
  simp only [isPack1, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨ha, hc⟩, hr⟩ := h
  exact ⟨ha, map_pairs _ _ (Expr.beqs_sound _ _ hc) hr⟩

/-- The first calendar date (0001-01-01): `validDate` holds for no earlier number. -/
def firstDate : Nat := 10101

/-- A rule set the gate runs: version 1 with no ends, in force from `firstDate` to `openEnd`, pack 1, in format 1 (the
    gate has no eligibility read yet). -/
def runnable (d : Doc) : Bool :=
  d.version == 1 && d.ends.isEmpty && d.effFrom == firstDate && d.effTo == openEnd && isPack1 d && !d.v2

#guard runnable { goldenPack1.d with effFrom := firstDate }
#guard !runnable goldenPack1.d && !runnable goldenEdge.d &&
  !runnable { goldenPack1.d with effFrom := firstDate, ages := [(.DMF, 90)] } &&
  !runnable { goldenPack1.d with effFrom := firstDate, rules := goldenPack1.d.rules.reverse } &&
  !runnable { goldenPack1.d with effFrom := firstDate, version := 2 } &&
  !runnable { goldenPack1.d with effFrom := firstDate, v2 := true }

/-- The line's date is in the rule set's effective range. -/
def covered (a : Admitted) (l : Line) : Bool := inForce [a] a l.date

/-- The stored rule set as the frame carries it again: `x` decodes, is runnable, and its digest is the shard's stored
    series head.  It was admitted in an earlier batch; `kb` 0 stands for it, as selection compares `kb` only with the
    known time.  The head binds the bytes by their SHA3-512 digest, as the key-set ratchet binds its head. -/
def reload (head x : Bytes) : Option Admitted :=
  match decode x with
  | some f => if digestOf f.d == head && runnable f.d then some ⟨head, 0, f.d⟩ else none
  | none => none

/-- Why a frame is held for its rule-set records: a record §6 refuses; a record admitted but not runnable, or a second
    record; no record while the shard has a rule set in force; a record that is not the one the frame must present. -/
inductive Why | refused (r : Refusal) | unsupported | missing | other deriving DecidableEq, Repr

/-- One batch's rule set: the one its lines run under (none before the shard has one), and the series head and its
    version after the batch (`zeroDigest` and 0 for none). -/
structure GateStep where
  cur : Option Admitted
  head : Bytes
  ver : Nat

/-- A shard with no rule set given the frame's one record `x`: it is admitted in batch `B` on the empty series and must
    be runnable.  A shard that starts behind the tenant (`late`, the digest the tenant asserts) admits that record
    without the signing window, which has closed for good, and no other record. -/
def startStep (verify : Bytes → Bytes → Bytes → Bool) (H : SnapshotV2.Head) (tenant : Bytes) (B : Nat)
    (late : Option Bytes) (x : Bytes) : Except Why GateStep :=
  match admitW late.isNone verify H tenant B [] x with
  | .error r => .error (.refused r)
  | .ok a =>
    if late.any (· != a.id) then .error .other
    else if runnable a.doc then .ok ⟨none, a.id, a.doc.version⟩ else .error .unsupported

/-- Every other case, which reads no key-set head: no record and no rule set; the stored rule set presented again
    (`reload`); otherwise held. -/
def heldStep (head : Bytes) (xs : List Bytes) : Except Why GateStep :=
  match xs with
  | [] => if head == zeroDigest then .ok ⟨none, zeroDigest, 0⟩ else .error .missing
  | [x] =>
    match reload head x with
    | some a => .ok ⟨some a, head, a.doc.version⟩
    | none => .error .other
  | _ :: _ :: _ => .error .unsupported

/-- The gate's step for batch `B` of a shard of `tenant` whose admitted key-set head is `H` and whose authority record
    holds series head `head`, given the frame's rule-set records `xs` in order (one-store design §16.1 rules 3, 4, 10).
    - No stored head and no record: the batch runs under none, as today.
    - No stored head and one record: `startStep`.  The record governs from batch `B + 1` (known time `K = B`), so this
      batch runs under none.
    - A stored head: the frame must present the stored record again (`reload`), and this batch runs under it.
    Any other frame is held (`.error`) and decides nothing; the head never changes once set. -/
def gateStep (verify : Bytes → Bytes → Bytes → Bool) (H : SnapshotV2.Head) (tenant : Bytes) (B : Nat) (head : Bytes)
    (late : Option Bytes) (xs : List Bytes) : Except Why GateStep :=
  match xs with
  | [x] => if head == zeroDigest then startStep verify H tenant B late x else heldStep head xs
  | _ => heldStep head xs

/-! ### Proofs -/

theorem runnable_spec {d : Doc} (h : runnable d = true) :
    d.version = 1 ∧ d.ends = [] ∧ d.effFrom = firstDate ∧ d.effTo = openEnd ∧ IsPack1 d := by
  simp only [runnable, Bool.and_eq_true, beq_iff_eq, List.isEmpty_iff] at h
  exact ⟨h.1.1.1.1.1, h.1.1.1.1.2, h.1.1.1.2, h.1.1.2, isPack1_sound h.1.2⟩

/-- A calendar date lies between `firstDate` and `openEnd`. -/
theorem validDate_range {D : Nat} (h : validDate D = true) : firstDate ≤ D ∧ D ≤ openEnd := by
  unfold validDate at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩ := h
  have hm : monthDays (D / 10000) (D / 100 % 100) ≤ 31 := by
    unfold monthDays; split <;> (try split) <;> omega
  unfold firstDate openEnd
  omega

theorem endOf_single {a : Admitted} (h : a.doc.ends = []) : endOf [a] a = a.doc.effTo := by
  simp [endOf, h]

theorem covered_iff {a : Admitted} (h : runnable a.doc = true) (l : Line) :
    covered a l = true ↔ firstDate ≤ l.date ∧ l.date ≤ openEnd := by
  obtain ⟨_, he, hf, ht, _⟩ := runnable_spec h
  simp [covered, inForce, endOf_single he, hf, ht]

theorem select_single {a : Admitted} {K : Nat} (hk : a.kb ≤ K) (D : Nat) :
    select [a] K D = if inForce [a] a D then some a else none := by
  have : known [a] K = [a] := by simp [known, hk]
  simp only [select, this, List.find?_cons, List.find?_nil]
  split <;> simp_all

/-- The pick a single runnable rule set gives: its record for a covered line, none for a line whose date is not a
    calendar date. -/
theorem pick_single {a : Admitted} (h : runnable a.doc = true) {K : Nat} (hk : a.kb ≤ K) (l : Line) :
    (select [a] K l.date).map (·.doc) = some a.doc ∨
      ((select [a] K l.date).map (·.doc) = none ∧ validDate l.date = false) := by
  rw [select_single hk]
  by_cases hc : inForce [a] a l.date = true
  · left; simp [hc]
  · right
    refine ⟨by simp [hc], ?_⟩
    cases hv : validDate l.date
    · rfl
    · exact absurd ((covered_iff h l).mpr (validDate_range hv)) hc

section
variable {pick : Line → Option Doc} {el : Line → ElRead} {d : Doc} (hd : IsPack1 d)
  (hp : ∀ l, pick l = some d ∨ (pick l = none ∧ validDate l.date = false))
include hd hp

theorem claimP_pick (c : Ctx) (l : Line) : claimP pick el c l = Rules.claim c l := by
  rcases hp l with h | ⟨h, hv⟩
  · simp only [claimP, Rules.claim, h, dfNE_pack1 hd]
  · simp [claimP, Rules.claim, h, dataFires, Rules.notEnrolled, Rules.certain, hv]

theorem pendingP_pick (c : Ctx) (l : Line) : pendingP pick el c l = Rules.pending c l := by
  simp only [pendingP, Rules.pending, funext (claimP_pick hd hp c)]

theorem firesP_pick (c : Ctx) (seen : List Key) {l : Line} (hl : pick l = some d) (r : Reason) :
    firesP pick el c seen l r = Rules.fires c seen l r := by
  rw [← pack1_fires (el := el) hd c seen l r]
  have e1 : pendingP pick el c = pendingP (fun _ => some d) el c := by
    funext x; rw [pendingP_pick hd hp, pendingP_pack1 (el := el) hd]
  have e2 : coreFires pick el c seen l r = coreFires (fun _ => some d) el c seen l r := by
    cases r <;> simp only [coreFires, e1]
  simp only [firesP, e2, hl]

theorem decideAllP_pick (c : Ctx) :
    ∀ (seen : List Key) (ls : List Line), (∀ l ∈ ls, pick l = some d) →
      decideAllP pick el c seen ls = Rules.decideAll c seen ls
  | _, [], _ => by simp [decideAllP, Rules.decideAll]
  | seen, l :: ls, h => by
    have hl := h l (List.mem_cons_self ..)
    have ef : firesP pick el c seen l = Rules.fires c seen l := funext (firesP_pick hd hp c seen hl)
    have ec : claimP pick el c = Rules.claim c := funext (claimP_pick hd hp c)
    simp only [decideAllP, Rules.decideAll, decideLineP, Rules.decideLine, ef, ec,
      decideAllP_pick c _ ls fun x hx => h x (List.mem_cons_of_mem _ hx)]

theorem decideBatchS_pick (c : Ctx) (b : List Line) (hb : ∀ l ∈ b, pick l = some d) :
    decideBatchS pick el c b = Rules.decideBatch c b := by
  have ho : ∀ l ∈ order c b, pick l = some d := fun l hl => hb l ((Rules.order_perm c b).mem_iff.mp hl)
  simp only [decideBatchS, Rules.decideBatch, decideAllP_pick hd hp c _ _ ho]

end

/-- The live decision is the interpreter's: under a runnable rule set admitted by known time `K`, a batch whose every
    line is covered replays with no line left undecided and exactly today's decisions (`Rules.decideBatch`, which the
    gate's fast deciders are proved to compute). -/
theorem live_pack1 {a : Admitted} (h : runnable a.doc = true) {K : Nat} (hk : a.kb ≤ K) (el : Line → ElRead) (c : Ctx)
    (b : List Line) (hb : ∀ l ∈ b, covered a l = true) :
    replayAt [a] K el c b = ([], Rules.decideBatch c b) := by
  have hd := (runnable_spec h).2.2.2.2
  have hs : ∀ l ∈ b, (select [a] K l.date).map (·.doc) = some a.doc := fun l hl => by
    rw [select_single hk]; simp [show inForce [a] a l.date = true from hb l hl]
  have e1 : b.filter (fun l => ((select [a] K l.date).map (·.doc)).isNone) = [] :=
    List.filter_eq_nil_iff.mpr fun l hl => by simp [hs l hl]
  have e2 : b.filter (fun l => ((select [a] K l.date).map (·.doc)).isSome) = b :=
    List.filter_eq_self.mpr fun l hl => by simp [hs l hl]
  simp only [replayAt, e1, e2,
    decideBatchS_pick (el := el) hd (pick_single h hk) c b hs]

theorem reload_some {head x : Bytes} {a : Admitted} (h : reload head x = some a) :
    a.id = head ∧ a.id = digestOf a.doc ∧ runnable a.doc = true := by
  unfold reload at h
  split at h
  · rename_i f _
    split at h
    · rename_i hc
      simp only [Option.some.injEq] at h
      subst h
      simp only [Bool.and_eq_true, beq_iff_eq] at hc
      exact ⟨rfl, hc.1.symm, hc.2⟩
    · cases h
  · cases h

theorem startStep_ok {verify H tenant B late x g} (h : startStep verify H tenant B late x = .ok g) :
    ∃ a, admitW late.isNone verify H tenant B [] x = .ok a ∧ runnable a.doc = true ∧
      (late = none ∨ late = some a.id) ∧ g = ⟨none, a.id, a.doc.version⟩ := by
  unfold startStep at h
  split at h
  · cases h
  · rename_i a ha
    split at h
    · cases h
    · rename_i hl
      split at h
      · rename_i hr
        cases h
        refine ⟨a, ha, hr, ?_, rfl⟩
        cases late with
        | none => exact Or.inl rfl
        | some d =>
          simp only [Option.any_some, bne_iff_ne, ne_eq, Decidable.not_not] at hl
          exact Or.inr (by rw [hl])
      · cases h

theorem heldStep_ok {head xs g} (h : heldStep head xs = .ok g) :
    (xs = [] ∧ head = zeroDigest ∧ g = ⟨none, zeroDigest, 0⟩) ∨
      (∃ x a, xs = [x] ∧ reload head x = some a ∧ g = ⟨some a, head, a.doc.version⟩) := by
  unfold heldStep at h
  split at h
  · split at h
    · rename_i hz
      cases h
      exact Or.inl ⟨rfl, by simpa using hz, rfl⟩
    · cases h
  · rename_i x
    split at h
    · rename_i a ha
      cases h
      exact Or.inr ⟨x, a, rfl, ha, rfl⟩
    · cases h
  · cases h

/-- The step decides exactly in three cases: no record and no rule set; the stored record presented again alone; or, with
    no rule set, one record admitted (without the signing window only on a shard behind the tenant, and then only the
    asserted record) that is runnable, which becomes the head.  Every other frame is held. -/
theorem gateStep_ok {verify H tenant B head late xs g} (h : gateStep verify H tenant B head late xs = .ok g) :
    (xs = [] ∧ head = zeroDigest ∧ g = ⟨none, zeroDigest, 0⟩) ∨
      (∃ x a, xs = [x] ∧ head ≠ zeroDigest ∧ reload head x = some a ∧ g = ⟨some a, head, a.doc.version⟩) ∨
      (∃ x a, xs = [x] ∧ head = zeroDigest ∧ admitW late.isNone verify H tenant B [] x = .ok a ∧
        runnable a.doc = true ∧ (late = none ∨ late = some a.id) ∧ g = ⟨none, a.id, a.doc.version⟩) := by
  unfold gateStep at h
  split at h
  · rename_i x
    split at h
    · rename_i hz
      obtain ⟨a, ha, hr, hl, rfl⟩ := startStep_ok h
      exact Or.inr (Or.inr ⟨x, a, rfl, by simpa using hz, ha, hr, hl, rfl⟩)
    · rename_i hz
      rcases heldStep_ok h with ⟨hx, -, -⟩ | ⟨y, a, hy, ha, rfl⟩
      · cases hx
      · simp only [List.cons.injEq, and_true] at hy
        subst hy
        exact Or.inr (Or.inl ⟨x, a, rfl, fun e => hz (by simp [e]), ha, rfl⟩)
  · rename_i hne
    rcases heldStep_ok h with ⟨rfl, hz, rfl⟩ | ⟨y, a, rfl, -, -⟩
    · exact Or.inl ⟨rfl, hz, rfl⟩
    · exact (hne y rfl).elim

/-- A rule set governs a batch only when the shard already held it: a record admitted in this batch is not used before
    the next one, and the one used is the stored head, runnable, with that digest. -/
theorem gateStep_cur {verify H tenant B head late xs g a} (h : gateStep verify H tenant B head late xs = .ok g)
    (ha : g.cur = some a) :
    head ≠ zeroDigest ∧ a.id = head ∧ a.id = digestOf a.doc ∧ runnable a.doc = true := by
  rcases gateStep_ok h with ⟨-, -, rfl⟩ | ⟨x, a', -, hz, hr, rfl⟩ | ⟨_, _, _, _, _, _, _, rfl⟩
  · simp at ha
  · simp only [Option.some.injEq] at ha
    subst ha
    exact ⟨hz, reload_some hr⟩
  · simp at ha

/-- The series head moves only from none to a record the gate admitted (a POLICY quorum signed it under the batch head)
    that is runnable, and on a shard behind the tenant only to the asserted record; once set it never changes. -/
theorem gateStep_head {verify H tenant B head late xs g} (h : gateStep verify H tenant B head late xs = .ok g) :
    g.head = head ∨ (head = zeroDigest ∧ ∃ x ∈ xs, ∃ a, admitW late.isNone verify H tenant B [] x = .ok a ∧
      runnable a.doc = true ∧ (late = none ∨ late = some a.id) ∧ g.head = a.id ∧ g.ver = a.doc.version) := by
  rcases gateStep_ok h with ⟨_, hz, rfl⟩ | ⟨_, _, _, _, _, rfl⟩ | ⟨x, a, rfl, hz, ha, hr, hl, rfl⟩
  · exact Or.inl hz.symm
  · exact Or.inl rfl
  · exact Or.inr ⟨hz, x, List.mem_cons_self .., a, ha, hr, hl, rfl, rfl⟩

/-- No silent downgrade (one-store design §16.1 rule 3): while a rule set is in force, a frame decides only when it
    presents exactly the stored record again, and then the head and its version stay and the batch runs under it. -/
theorem gateStep_held {verify H tenant B head late xs g} (hz : head ≠ zeroDigest)
    (h : gateStep verify H tenant B head late xs = .ok g) :
    ∃ x a, xs = [x] ∧ reload head x = some a ∧ g = ⟨some a, head, a.doc.version⟩ := by
  rcases gateStep_ok h with ⟨_, hz', _⟩ | ⟨x, a, hx, _, ha, rfl⟩ | ⟨_, _, _, hz', _⟩
  · exact absurd hz' hz
  · exact ⟨x, a, hx, ha, rfl⟩
  · exact absurd hz' hz

/-- A shard behind the tenant (rule 10) moves its head only to the record the tenant asserts. -/
theorem gateStep_late {verify H tenant B head d xs g} (h : gateStep verify H tenant B head (some d) xs = .ok g) :
    g.head = head ∨ g.head = d := by
  rcases gateStep_head h with e | ⟨_, _, _, _, _, _, hl, e, _⟩
  · exact Or.inl e
  · rcases hl with hl | hl
    · cases hl
    · simp only [Option.some.injEq] at hl
      exact Or.inr (e.trans hl.symm)

/-! ## Version 2: statements -/

/-- A version 1 record fires no eligibility reason, whatever the read. -/
theorem dataFires_v1 {d : Doc} (hv : d.v2 = false) (e : ElRead) (c : Ctx) (l : Line) {r : Reason}
    (hr : eligReason r = true) : dataFires (some d) e c l r = false := by
  cases r <;> simp_all [dataFires, Doc.fires, eligReason, dataReason]

/-- A rule set whose ages, aid table and rules are the test pack's (header and citations the state's). -/
def IsPack2 (d : Doc) : Prop :=
  d.v2 = true ∧ d.ages = [(.ELIG, 4)] ∧ d.aids = pack2Aids ∧ d.rules.map (fun r => (r.reason, r.cond)) = pack2Conds

/-- A hold reason fires exactly when a rule for it holds and the guards let it. -/
theorem dataFires_hold (d : Doc) (e : ElRead) (c : Ctx) (l : Line) {r : Reason} (hr : review r = false) :
    dataFires (some d) e c l r = (d.fires r && ruleAny d e c l r) := by
  have h19 : (r == .STALE_ENROLLMENT) = false := by cases r <;> first | rfl | exact absurd hr (by decide)
  have h27 : (r == .PROGRAM_NOT_ELIGIBLE_UNVERIFIED) = false := by cases r <;> first | rfl | exact absurd hr (by decide)
  simp only [dataFires, h19, h27, Bool.false_and, Bool.false_or, Bool.or_false]

theorem fresh_elig {v : Env} (h : v.fresh .ELIG = true) : v.el.ans = 0 ∧ ∃ a, v.el.asof = some a ∧
    validDate a = true ∧ validDate v.l.date = true ∧ validDate v.c.today = true ∧ a ≤ v.c.today ∧
    dayNum v.l.date ≤ dayNum a + v.age .ELIG := by
  simp only [Env.fresh] at h
  split at h
  · rename_i a ha
    simp only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at h
    obtain ⟨⟨⟨⟨⟨h0, h1⟩, h2⟩, h3⟩, h4⟩, h5⟩ := h
    exact ⟨h0, a, ha, h1, h2, h3, h4, h5⟩
  · cases h

/-- The fixed eligibility guard, under every rule set (so every admitted version 2 record): a hold reason fires only
    through a rule for it whose condition holds, and when the reason is `PROGRAM_NOT_ELIGIBLE`, or the rule reads the
    eligibility source and its condition is not true with every atom that reads it unknown (`eval3`; one that is, is
    true whatever the read, `eval3_sound`), only on a present answer whose as-of is a valid date not after the batch's
    own date and whose as-of plus the rule set's maximum age for eligibility is not before the line's valid service
    date.  Stale, missing, absent, unknown or conflicting eligibility never holds a line through a value that depends
    on it. -/
theorem elig_guard_hold {o : Option Doc} {e : ElRead} {c : Ctx} {l : Line} {r : Reason} (hr : review r = false)
    (h : dataFires o e c l r = true) :
    ∃ d, o = some d ∧ ∃ x ∈ d.rules, x.reason = r ∧ eval (d.env e c l) x.cond = true ∧
      ((r = .PROGRAM_NOT_ELIGIBLE ∨ reads .ELIG x.cond = true ∧ eval3 (d.env e c l) x.cond ≠ some true) →
        e.ans = 0 ∧ ∃ a, e.asof = some a ∧ validDate a = true ∧ validDate l.date = true ∧ validDate c.today = true ∧
        a ≤ c.today ∧ dayNum l.date ≤ dayNum a + d.age .ELIG) := by
  rcases o with _ | d
  · simp [dataFires] at h
  · rw [dataFires_hold d e c l hr, Bool.and_eq_true] at h
    obtain ⟨x, hx, hp⟩ := List.any_eq_true.mp h.2
    simp only [Bool.and_eq_true, Bool.not_eq_true', beq_iff_eq] at hp
    obtain ⟨⟨⟨hxr, hev⟩, -⟩, hb⟩ := hp
    refine ⟨d, rfl, x, hx, hxr, hev, fun h' => ?_⟩
    have hf : (d.env e c l).fresh .ELIG = true := by
      cases hfr : (d.env e c l).fresh .ELIG
      · have hg : elGuard (d.env e c l) r x.cond = true := by
          rcases h' with h' | ⟨h1, h2⟩
          · subst h'
            simp [elGuard, hr]
          · simp [elGuard, hr, h1, h2]
        simp [hg, hfr] at hb
      · rfl
    exact fresh_elig hf

/-- The three-valued reading is sound: a condition that is true or false with every atom that reads the eligibility
    source unknown (`eval3`) has that value whatever values those atoms take (`f`), and so under every eligibility read
    (`w`, through `evalAt_read`), the line's own among them. -/
theorem eval3_sound {v : Env} {x : Expr} {b : Bool} (h : eval3 v x = some b) :
    (∀ f, evalAt v f x = b) ∧ ∀ w, eval { v with el := w } x = b :=
  ⟨fun f => eval3_sound_aux v f x b h, fun w => by rw [← evalAt_read v w x]; exact eval3_sound_aux v _ x b h⟩

/-- What the guard does instead: when a version 2 rule set has a rule the guard covers (`PROGRAM_NOT_ELIGIBLE`, or a
    hold reason whose condition reads the eligibility source and is not true with the read unknown) that is not false
    with the read unknown (`eval3`), and the line's read is not fresh, the line goes to review
    (`PROGRAM_NOT_ELIGIBLE_UNVERIFIED`). -/
theorem elig_guard_review {d : Doc} (hv : d.v2 = true) {e : ElRead} {c : Ctx} {l : Line} {x : Rule} (hx : x ∈ d.rules)
    (hr : review x.reason = false)
    (hg : x.reason = .PROGRAM_NOT_ELIGIBLE ∨ reads .ELIG x.cond = true ∧ eval3 (d.env e c l) x.cond ≠ some true)
    (h3 : eval3 (d.env e c l) x.cond ≠ some false) (hf : (d.env e c l).fresh .ELIG = false) :
    dataFires (some d) e c l .PROGRAM_NOT_ELIGIBLE_UNVERIFIED = true := by
  have hh : elHeld d e c l = true := by
    simp only [elHeld, hf, Bool.not_false, Bool.true_and]
    refine List.any_eq_true.mpr ⟨x, hx, ?_⟩
    rcases hg with hg | ⟨hg, ht⟩
    · rw [hg] at hr ⊢
      simp [elGuard, hr, h3]
    · simp [elGuard, hr, hg, ht, h3]
  simp [dataFires, Doc.fires, hv, eligReason, hh]

/-- The guard is narrow: when every rule it covers is false with the read unknown (`eval3`), so false whatever the read
    (`eval3_sound`: another flow, a date that is not a calendar date), it sends nothing to review. -/
theorem elig_guard_narrow {d : Doc} {e : ElRead} {c : Ctx} {l : Line}
    (h : ∀ x ∈ d.rules, elGuard (d.env e c l) x.reason x.cond = true → eval3 (d.env e c l) x.cond = some false) :
    elHeld d e c l = false := by
  unfold elHeld
  cases (d.env e c l).fresh .ELIG
  · simp only [Bool.not_false, Bool.true_and, List.any_eq_false]
    intro x hx
    cases hg : elGuard (d.env e c l) x.reason x.cond
    · simp
    · simp [h x hx hg]
  · simp

/-- The test pack reads no enrollment, so its rules hold exactly when their conditions do and the eligibility guard
    lets them. -/
theorem pack2_rule {d : Doc} (hd : IsPack2 d) (e : ElRead) (c : Ctx) (l : Line) (r : Reason) :
    ruleAny d e c l r = pack2Conds.any fun p => p.1 == r && eval (d.env e c l) p.2 &&
      !(elGuard (d.env e c l) r p.2 && !(d.env e c l).fresh .ELIG) := by
  obtain ⟨-, -, -, h4⟩ := hd
  have hm : ruleAny d e c l r = pack2Conds.any fun p => p.1 == r && eval (d.env e c l) p.2 &&
      !(enrollStale d c && !review r && reads .SPAN p.2) &&
      !(elGuard (d.env e c l) r p.2 && !(d.env e c l).fresh .ELIG) := by
    unfold ruleAny
    rw [← h4, List.any_map]
    rfl
  rw [hm]
  simp [pack2Conds, reads, readsAny, src_beq]

theorem pack2_age {d : Doc} (hd : IsPack2 d) : d.age .ELIG = 4 := by
  obtain ⟨-, h2, -⟩ := hd
  unfold Doc.age
  rw [h2]
  rfl

/-- The held side: a recognised aid code that is not on the program's list holds the line (`PROGRAM_NOT_ELIGIBLE`, a
    hold reason) only on a fresh, present answer and a valid date. -/
theorem pack2_pne {d : Doc} (hd : IsPack2 d) (e : ElRead) (c : Ctx) (l : Line) :
    dataFires (some d) e c l .PROGRAM_NOT_ELIGIBLE =
      ((d.env e c l).fresh .ELIG && validDate l.date && e.ans == 0 && e.aids.any fun b => aidClass d.aids b == 2) := by
  have hv := hd.1
  rw [dataFires_hold d e c l rfl, pack2_rule hd]
  have he : (d.env e c l).el = e := rfl
  have ha : (d.env e c l).aids = d.aids := rfl
  have hl : (d.env e c l).l = l := rfl
  cases hf : (d.env e c l).fresh .ELIG <;> cases h0 : e.ans == 0 <;>
    simp [Doc.fires, hv, eligReason, pack2Conds, reason_beq, eval, evalAll, Env.elig, elGuard, review, he, ha, hl, hf, h0]

/-- With an as-of on a present answer, `STALE_ELIGIBILITY` fires exactly when the as-of plus the maximum age (4 days in
    the test pack) is before the service date, the as-of is after the batch's own date, or a date is not a calendar
    date. -/
theorem pack2_stale {d : Doc} (hd : IsPack2 d) (e : ElRead) (c : Ctx) (l : Line) {a : Nat} (ha : e.asof = some a)
    (h0 : e.ans = 0) :
    dataFires (some d) e c l .STALE_ELIGIBILITY =
      !(validDate a && validDate l.date && validDate c.today && decide (a ≤ c.today) && dayNum l.date ≤ dayNum a + 4) := by
  have hv := hd.1
  have hA := pack2_age hd
  have h0' : (e.ans == 0) = true := by rw [h0]; rfl
  simp only [dataFires, pack2_rule hd]
  simp [Doc.fires, hv, eligReason, pack2Conds, reason_beq, eval, evalAll, Env.present, Env.fresh, Doc.env, elGuard,
    review, ha, hA, h0']

/-- The unverified side: with no as-of at all the line is never allowed on eligibility
    (`PROGRAM_NOT_ELIGIBLE_UNVERIFIED`, review), and `STALE_ELIGIBILITY` does not fire. -/
theorem pack2_no_asof {d : Doc} (hd : IsPack2 d) (e : ElRead) (c : Ctx) (l : Line) (ha : e.asof = none) :
    dataFires (some d) e c l .PROGRAM_NOT_ELIGIBLE_UNVERIFIED = true ∧
      dataFires (some d) e c l .STALE_ELIGIBILITY = false ∧ dataFires (some d) e c l .PROGRAM_NOT_ELIGIBLE = false := by
  have hv := hd.1
  refine ⟨?_, ?_, ?_⟩
  · simp only [dataFires, pack2_rule hd]
    simp [Doc.fires, hv, eligReason, pack2Conds, reason_beq, eval, evalAny, Env.present, Doc.env, elGuard, review, ha]
  · simp only [dataFires, pack2_rule hd]
    simp [Doc.fires, hv, eligReason, pack2Conds, reason_beq, eval, evalAll, Env.present, Doc.env, ha]
  · rw [pack2_pne hd]
    simp [Env.fresh, Doc.env, ha]

/-- The unverified side of the aid table: an aid code that is not on the list or not well formed, on a present answer,
    sends the line to review (`PROGRAM_NOT_ELIGIBLE_UNVERIFIED`). -/
theorem pack2_unlisted {d : Doc} (hd : IsPack2 d) (e : ElRead) (c : Ctx) (l : Line) (h0 : e.ans = 0)
    (hu : (e.aids.any fun b => aidClass d.aids b == 3) = true) :
    dataFires (some d) e c l .PROGRAM_NOT_ELIGIBLE_UNVERIFIED = true := by
  have hv := hd.1
  simp only [dataFires, pack2_rule hd, Doc.fires, hv, eligReason, Bool.or_true, Bool.true_and]
  simp [pack2Conds, reason_beq, eval, evalAny, Env.elig, Doc.env, elGuard, review, h0, hu]

/-- How the eligibility reasons resolve: `PROGRAM_NOT_ELIGIBLE` holds the line, the other two send it to review, and a
    signed staff override may clear each of them. -/
theorem elig_reason_class : review .PROGRAM_NOT_ELIGIBLE = false ∧ review .PROGRAM_NOT_ELIGIBLE_UNVERIFIED = true ∧
    review .STALE_ELIGIBILITY = true ∧ bypassable .PROGRAM_NOT_ELIGIBLE = true ∧
    bypassable .PROGRAM_NOT_ELIGIBLE_UNVERIFIED = true ∧ bypassable .STALE_ELIGIBILITY = true :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

end BlindLedger.Gate.RuleSet
