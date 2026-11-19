import BlindLedger.Gate.Rules.Fast

/-! G2 mutants (docs/integration/TRUNK_STEP3_G2_DESIGN.md 7.1; TRUNK_MIGRATION_PLAN decision 7).  Each `Mutant:`
    definition is one of October's G2 mutants (f16a61f4:rightrail/tools/gate_rules_mutants.py, `G2_SPEC` and
    `G2_FAST`) applied to a copy of the trunk definition it changes; the `#guard` pair after it kills it: the real
    definition gives the expected answer on a small context and the mutant does not.  A Fast mutant changes one arm of
    `Ix.fires`, one query, or one field of `Ix.build`; every other arm is the real `Ix.fires`.

    Not here: "G2 any member" (`eligCovers` without its member test).  Fast reads rows by member (`Ix.elig.getD
    l.member`), so the runner's output cannot tell it apart; October killed it by proof (FastEq), and the trunk kills it
    by a one-off scratch-copy build (design 7.1, decision 12).  The allowed aid list and `review`'s G2 entries are
    `#guard`-checked in `Run.lean`.

    Outside the `gate_engine` closure (nothing it builds imports this module); built by the default `lake build`
    through `BlindLedger.lean`.  Synthetic, not legally verified. -/

namespace BlindLedger.Gate.Rules.G2Mutants

open BlindLedger.Gate.Rules
open BlindLedger.Gate.Rules.Fast
open Std (HashMap HashSet)

/-- The five G2 reasons, in name order. -/
def g2 : List Reason :=
  [.BENEFIT_LEVEL_MISSING, .BENEFIT_LEVEL_MISSING_UNVERIFIED, .PROGRAM_NOT_ELIGIBLE, .PROGRAM_NOT_ELIGIBLE_UNVERIFIED,
   .STALE_ELIGIBILITY]

def today0 : Nat := 20270315

/-- A fee-for-service line of member `m` on `d`. -/
def mkLine (m d : Nat) : Line :=
  { id := 1, pay := 1, flow := .FFS_CLAIM, member := m, payee := 7001, rendering := 7001, date := d, proc := 99213,
    units := 1, cents := 100 }

def l1 : Line := mkLine 1001 20270305

/-- An eligibility snapshot dated `asOf` holding `rs`, its count `n` (default: the row count). -/
def eligSnap (asOf : Nat) (rs : List Elig) (n : Nat := rs.length) : Option (Snapshot Elig) := some ⟨asOf, n, rs⟩

/-- A context reading only eligibility (every other reference snapshot missing). -/
def eligCtx (e : Option (Snapshot Elig)) : Ctx :=
  { today := today0, dmf := none, providerDeaths := none, exclusions := none, enrollment := none, eligibility := e,
    released := none, unresolved := none, releasedPrior := ⟨0, 0, []⟩, unresolvedPrior := ⟨0, 0, []⟩, anchor := 0,
    redo := [] }

/-- Aid codes: 78131 is "13" (allowed), 20527417 is "999" (not allowed). -/
def ok13 : Elig := ⟨1001, 78131, 1, 20260101, 20271231⟩
def lvl0 : Elig := ⟨1001, 78131, 0, 20260101, 20271231⟩
def lvl2 : Elig := ⟨1001, 78131, 2, 20260101, 20271231⟩
def bad999 : Elig := ⟨1001, 20527417, 1, 20260101, 20271231⟩

/-- Usable: aid eligible and level eligible. -/
def cOk : Ctx := eligCtx (eligSnap 20270314 [ok13])
/-- Usable, no allowed aid: `PROGRAM_NOT_ELIGIBLE`. -/
def cNE : Ctx := eligCtx (eligSnap 20270314 [bad999])
/-- Usable, allowed aid with no level: `BENEFIT_LEVEL_MISSING`. -/
def cBL : Ctx := eligCtx (eligSnap 20270314 [lvl0])
/-- Usable, the pairing case: an allowed aid with level 0 beside a leveled row of another aid. -/
def cPair : Ctx := eligCtx (eligSnap 20270314 [lvl0, bad999])
/-- Present and unusable (count mismatch), no allowed aid. -/
def cNEu : Ctx := eligCtx (eligSnap 20270314 [bad999] 2)
/-- Present and unusable (count mismatch), allowed aid with no level. -/
def cBLu : Ctx := eligCtx (eligSnap 20270314 [lvl0] 2)
/-- Present and unusable only because of a level of 2. -/
def cLvl2 : Ctx := eligCtx (eligSnap 20270314 [lvl2])
/-- Usable at the 7-day limit; unusable at 8 days. -/
def c7 : Ctx := eligCtx (eligSnap 20270308 [ok13])
def c8 : Ctx := eligCtx (eligSnap 20270307 [ok13])

/-- The G2 reasons the Spec fires (`fires`, real). -/
def spec (c : Ctx) (l : Line := l1) : List Reason := g2.filter (fires c [] l)

/-- The G2 reasons the Fast twin fires (`Ix.fires` over `Ix.build`, real). -/
def fast (c : Ctx) (l : Line := l1) : List Reason := g2.filter ((Ix.build c [l]).fires ∅ l)

-- The contexts give the answers the mutants are tested against (Spec and Fast agree).
#guard spec cOk == [] && fast cOk == []
#guard spec cNE == [.PROGRAM_NOT_ELIGIBLE] && fast cNE == [.PROGRAM_NOT_ELIGIBLE]
#guard spec cBL == [.BENEFIT_LEVEL_MISSING] && fast cBL == [.BENEFIT_LEVEL_MISSING]
#guard spec cPair == [.BENEFIT_LEVEL_MISSING] && fast cPair == [.BENEFIT_LEVEL_MISSING]
#guard spec cNEu == [.PROGRAM_NOT_ELIGIBLE_UNVERIFIED, .STALE_ELIGIBILITY] && fast cNEu == spec cNEu
#guard spec cBLu == [.BENEFIT_LEVEL_MISSING_UNVERIFIED, .STALE_ELIGIBILITY] && fast cBLu == spec cBLu
#guard spec cLvl2 == [.BENEFIT_LEVEL_MISSING_UNVERIFIED, .STALE_ELIGIBILITY] && fast cLvl2 == spec cLvl2
#guard spec c7 == [] && fast c7 == [] && spec c8 == [.STALE_ELIGIBILITY] && fast c8 == [.STALE_ELIGIBILITY]
#guard spec (eligCtx none) == [.STALE_ELIGIBILITY] && fast (eligCtx none) == [.STALE_ELIGIBILITY]

/-! ## G2_SPEC: `eligCovers` and `okElig` (Spec.lean), killed on the definition and on the Spec's five G2 arms. -/

/-- The Spec's five G2 arms over a covering test `cov` and a row check `ok` (a copy of `fires`' G2 rows, with
    `aidEligible`/`levelEligible` inlined); with `eligCovers` and `okElig` it is the real `fires` (first `#guard`). -/
def firesG2 (cov : Line → Elig → Bool) (ok : Nat → Elig → Bool) (c : Ctx) (l : Line) : Reason → Bool :=
  let aid := (entries c.eligibility).any fun e => cov l e && allowedAid.contains e.aid
  let lvl := (entries c.eligibility).any fun e => cov l e && allowedAid.contains e.aid && e.level == 1
  fun
  | .BENEFIT_LEVEL_MISSING => certain c 7 ok c.eligibility l && aid && !lvl
  | .BENEFIT_LEVEL_MISSING_UNVERIFIED => unverified c 7 ok c.eligibility l && aid && !lvl
  | .PROGRAM_NOT_ELIGIBLE => certain c 7 ok c.eligibility l && !aid
  | .PROGRAM_NOT_ELIGIBLE_UNVERIFIED => unverified c 7 ok c.eligibility l && !aid
  | .STALE_ELIGIBILITY => !usable c.today 7 ok c.eligibility
  | r => fires c [] l r

def specG2 (cov : Line → Elig → Bool) (ok : Nat → Elig → Bool) (c : Ctx) (l : Line := l1) : List Reason :=
  g2.filter (firesG2 cov ok c l)

-- The copy is the real `fires` on every context used below.
#guard [cOk, cNE, cBL, cPair, cNEu, cBLu, cLvl2, c7, c8, eligCtx none].all fun c => specG2 eligCovers okElig c == spec c

/-- Mutant: G2 row start exclusive (`e.start < l.date`). -/
def eligCoversM1 (l : Line) (e : Elig) : Bool := e.member == l.member && e.start < l.date && l.date ≤ e.stop

def cStart : Ctx := eligCtx (eligSnap 20270314 [⟨1001, 78131, 1, 20270305, 20271231⟩])
#guard eligCovers l1 ⟨1001, 78131, 1, 20270305, 20271231⟩ && !eligCoversM1 l1 ⟨1001, 78131, 1, 20270305, 20271231⟩
#guard spec cStart == [] && specG2 eligCovers okElig cStart == spec cStart &&
  specG2 eligCoversM1 okElig cStart == [.PROGRAM_NOT_ELIGIBLE]

/-- Mutant: G2 row stop exclusive (`l.date < e.stop`). -/
def eligCoversM2 (l : Line) (e : Elig) : Bool := e.member == l.member && e.start ≤ l.date && l.date < e.stop

def cStop : Ctx := eligCtx (eligSnap 20270314 [⟨1001, 78131, 1, 20260101, 20270305⟩])
#guard eligCovers l1 ⟨1001, 78131, 1, 20260101, 20270305⟩ && !eligCoversM2 l1 ⟨1001, 78131, 1, 20260101, 20270305⟩
#guard spec cStop == [] && specG2 eligCovers okElig cStop == spec cStop &&
  specG2 eligCoversM2 okElig cStop == [.PROGRAM_NOT_ELIGIBLE]

/-- Mutant: eligibility level unchecked (`okElig` without `e.level ≤ 1`). -/
def okEligM3 (_ : Nat) (e : Elig) : Bool := validDate e.start && validDate e.stop && e.start ≤ e.stop

#guard !okElig 0 lvl2 && okEligM3 0 lvl2
#guard specG2 eligCovers okElig cLvl2 == [.BENEFIT_LEVEL_MISSING_UNVERIFIED, .STALE_ELIGIBILITY] &&
  specG2 eligCovers okEligM3 cLvl2 == [.BENEFIT_LEVEL_MISSING]

/-- Mutant: eligibility row order unchecked (`okElig` without `e.start ≤ e.stop`). -/
def okEligM4 (_ : Nat) (e : Elig) : Bool := validDate e.start && validDate e.stop && e.level ≤ 1

def revRow : Elig := ⟨1008, 78131, 1, 20271231, 20260101⟩
def cRev : Ctx := eligCtx (eligSnap 20270314 [ok13, revRow])
#guard !okElig 0 revRow && okEligM4 0 revRow
#guard spec cRev == [.STALE_ELIGIBILITY] && specG2 eligCovers okElig cRev == spec cRev &&
  specG2 eligCovers okEligM4 cRev == []

/-! ## G2_FAST: `Ix.fires`, its queries and `Ix.build` (Fast.lean), killed on `Ix.fires` over `Ix.build`. -/

/-- The G2 reasons a mutant `f` of `(Ix.build c [l]).fires ∅ l` fires. -/
def fastM (f : Ix → Line → Reason → Bool) (c : Ctx) (l : Line := l1) : List Reason := g2.filter (f (Ix.build c [l]) l)

/-- The G2 reasons the real `Ix.fires` fires over a mutant `b` of `Ix.build`. -/
def fastB (b : Ctx → List Line → Ix) (c : Ctx) (l : Line := l1) : List Reason := g2.filter ((b c [l]).fires ∅ l)

#guard [cOk, cNE, cBL, cNEu, cBLu, eligCtx none].all fun c => fastM (fun x l => x.fires ∅ l) c == fast c &&
  fastB Ix.build c == fast c

/-- Mutant: G2 program off. -/
def firesM5 (x : Ix) (l : Line) : Reason → Bool
  | .PROGRAM_NOT_ELIGIBLE => false
  | r => x.fires ∅ l r

#guard fast cNE == [.PROGRAM_NOT_ELIGIBLE] && fastM firesM5 cNE == []

/-- Mutant: G2 benefit level off. -/
def firesM6 (x : Ix) (l : Line) : Reason → Bool
  | .BENEFIT_LEVEL_MISSING => false
  | r => x.fires ∅ l r

#guard fast cBL == [.BENEFIT_LEVEL_MISSING] && fastM firesM6 cBL == []

/-- Mutant: G2 program on an unusable snapshot (`PROGRAM_NOT_ELIGIBLE => !x.aidEligible l`). -/
def firesM7 (x : Ix) (l : Line) : Reason → Bool
  | .PROGRAM_NOT_ELIGIBLE => !x.aidEligible l
  | r => x.fires ∅ l r

#guard fast cNEu == [.PROGRAM_NOT_ELIGIBLE_UNVERIFIED, .STALE_ELIGIBILITY] &&
  fastM firesM7 cNEu == [.PROGRAM_NOT_ELIGIBLE, .PROGRAM_NOT_ELIGIBLE_UNVERIFIED, .STALE_ELIGIBILITY]

/-- Mutant: G2 benefit level on an unusable snapshot (`BENEFIT_LEVEL_MISSING => x.aidEligible l && !x.levelEligible l`). -/
def firesM8 (x : Ix) (l : Line) : Reason → Bool
  | .BENEFIT_LEVEL_MISSING => x.aidEligible l && !x.levelEligible l
  | r => x.fires ∅ l r

#guard fast cBLu == [.BENEFIT_LEVEL_MISSING_UNVERIFIED, .STALE_ELIGIBILITY] &&
  fastM firesM8 cBLu == [.BENEFIT_LEVEL_MISSING, .BENEFIT_LEVEL_MISSING_UNVERIFIED, .STALE_ELIGIBILITY]

/-- Mutant: G2 program unverified off. -/
def firesM9 (x : Ix) (l : Line) : Reason → Bool
  | .PROGRAM_NOT_ELIGIBLE_UNVERIFIED => false
  | r => x.fires ∅ l r

#guard fast cNEu == [.PROGRAM_NOT_ELIGIBLE_UNVERIFIED, .STALE_ELIGIBILITY] && fastM firesM9 cNEu == [.STALE_ELIGIBILITY]

/-- Mutant: G2 benefit level unverified off. -/
def firesM10 (x : Ix) (l : Line) : Reason → Bool
  | .BENEFIT_LEVEL_MISSING_UNVERIFIED => false
  | r => x.fires ∅ l r

#guard fast cBLu == [.BENEFIT_LEVEL_MISSING_UNVERIFIED, .STALE_ELIGIBILITY] && fastM firesM10 cBLu == [.STALE_ELIGIBILITY]

/-- Mutant: eligibility staleness off. -/
def firesM11 (x : Ix) (l : Line) : Reason → Bool
  | .STALE_ELIGIBILITY => false
  | r => x.fires ∅ l r

#guard fast (eligCtx none) == [.STALE_ELIGIBILITY] && fastM firesM11 (eligCtx none) == []
#guard fast c8 == [.STALE_ELIGIBILITY] && fastM firesM11 c8 == []

/-- The two benefit-level arms of `Ix.fires` over a replacement `lvl` of `Ix.levelEligible`. -/
def firesLvl (lvl : Ix → Line → Bool) (x : Ix) (l : Line) : Reason → Bool
  | .BENEFIT_LEVEL_MISSING => x.eligOk && validDate l.date && x.aidEligible l && !lvl x l
  | .BENEFIT_LEVEL_MISSING_UNVERIFIED => x.eligSome && !x.eligOk && validDate l.date && x.aidEligible l && !lvl x l
  | r => x.fires ∅ l r

#guard [cOk, cBL, cPair, cBLu, cLvl2].all fun c => fastM (firesLvl Ix.levelEligible) c == fast c

/-- Mutant: G2 pairing broken (`Ix.levelEligible` without the allowed-aid test on the leveled row). -/
def levelEligibleM12 (x : Ix) (l : Line) : Bool := (x.elig.getD l.member []).any fun e => eligCovers l e && e.level == 1

#guard fast cPair == [.BENEFIT_LEVEL_MISSING] && fastM (firesLvl levelEligibleM12) cPair == []

/-- Mutant: G2 any nonzero level (`e.level != 0` for `e.level == 1`). -/
def levelEligibleM13 (x : Ix) (l : Line) : Bool :=
  (x.elig.getD l.member []).any fun e => eligCovers l e && allowedAid.contains e.aid && e.level != 0

#guard fast cLvl2 == [.BENEFIT_LEVEL_MISSING_UNVERIFIED, .STALE_ELIGIBILITY] &&
  fastM (firesLvl levelEligibleM13) cLvl2 == [.STALE_ELIGIBILITY]

/-- Mutant: G2 benefit level also without an allowed aid (`x.aidEligible l` dropped from the certain arm). -/
def firesM14 (x : Ix) (l : Line) : Reason → Bool
  | .BENEFIT_LEVEL_MISSING => x.eligOk && validDate l.date && !x.levelEligible l
  | r => x.fires ∅ l r

#guard fast cNE == [.PROGRAM_NOT_ELIGIBLE] && fastM firesM14 cNE == [.BENEFIT_LEVEL_MISSING, .PROGRAM_NOT_ELIGIBLE]

/-- Mutant: eligibility 6 days. -/
def buildM15 (c : Ctx) (b : List Line) : Ix := { Ix.build c b with eligOk := usable c.today 6 okElig c.eligibility }

#guard fast c7 == [] && fastB buildM15 c7 == [.STALE_ELIGIBILITY]

/-- Mutant: eligibility 8 days. -/
def buildM16 (c : Ctx) (b : List Line) : Ix := { Ix.build c b with eligOk := usable c.today 8 okElig c.eligibility }

#guard fast c8 == [.STALE_ELIGIBILITY] && fastB buildM16 c8 == []

/-- Mutant: eligibility usability read from enrollment. -/
def buildM17 (c : Ctx) (b : List Line) : Ix := { Ix.build c b with eligOk := usable c.today 7 okSpan c.enrollment }

#guard fast cOk == [] && fastB buildM17 cOk == [.STALE_ELIGIBILITY]

/-- Mutant: eligibility rows unread (`elig := ∅`). -/
def buildM18 (c : Ctx) (b : List Line) : Ix := { Ix.build c b with elig := ∅ }

#guard fast cOk == [] && fastB buildM18 cOk == [.PROGRAM_NOT_ELIGIBLE]

end BlindLedger.Gate.Rules.G2Mutants
