import Std

namespace RightRail.ProviderApp

/-- The synthetic core's only aggregate outcomes. -/
inductive Outcome where
  | pass
  | missing
  | humanCheck
  deriving DecidableEq, Repr

inductive RunMode where
  | syntheticTest
  | realUse
  deriving DecidableEq, Repr

inductive Scope where
  | providerA
  | providerB
  deriving DecidableEq, Repr

inductive ServiceCategory where
  | categoryA
  | categoryB
  deriving DecidableEq, Repr

inductive ReferenceState where
  | present
  | absent
  deriving DecidableEq, Repr

inductive SourceStatus where
  | completeFixture
  | partialFixture
  | stale
  | conflict
  | replayed
  | unknown
  deriving DecidableEq, Repr

inductive Provenance where
  | unapprovedSyntheticFixture
  | other
  deriving DecidableEq, Repr

inductive RuleId where
  | serviceDate
  | serviceCategory
  | supportReference
  | chargeRange
  | sourceCurrency
  deriving DecidableEq, Repr

inductive RuleSemantic where
  | serviceDateInEffectiveWindow
  | serviceCategoryEquals
  | supportReferencePresent
  | chargeCentsBetween
  | sourceCompleteAndFresh
  | other
  deriving DecidableEq, Repr

inductive FactName where
  | serviceDate
  | serviceCategory
  | supportReference
  | chargeCents
  | sourceBinding
  | sourceEffectiveAt
  | sourceReceivedAt
  deriving DecidableEq, Repr

structure SourceFacts where
  status : SourceStatus
  effectiveDay : Option Nat
  receivedDay : Option Nat
  receivedAt : Option Nat
  deriving DecidableEq, Repr

structure ClaimFacts where
  serviceDay : Option Nat
  serviceCategory : Option ServiceCategory
  supportReference : Option ReferenceState
  chargeCents : Option Nat
  source : Option SourceFacts
  deriving DecidableEq, Repr

structure RuleSpec where
  ruleId : RuleId
  version : Nat
  semantic : RuleSemantic
  effectiveFrom : Nat
  effectiveUntil : Nat
  expectedCategory : Option ServiceCategory
  minimumCents : Option Nat
  maximumCents : Option Nat
  maxSourceAgeDays : Option Nat
  deriving DecidableEq, Repr

structure RuleBundle where
  bundleId : String
  version : Nat
  scope : Scope
  provenance : Provenance
  issuerIsLocalFixture : Bool
  publishedAt : Nat
  effectiveFrom : Nat
  effectiveUntil : Nat
  expiresAt : Nat
  withdrawnAt : Option Nat
  digestMatchesCanonicalContent : Bool
  rules : Option (List RuleSpec)
  deriving DecidableEq, Repr

structure Input where
  mode : RunMode
  scope : Scope
  evaluatedAt : Nat
  evaluatedDay : Nat
  facts : ClaimFacts
  bundle : RuleBundle
  deriving DecidableEq, Repr

structure RuleResult where
  ruleId : RuleId
  citation : String
  outcome : Outcome
  missingFacts : List FactName
  reasonCodes : List String
  factsUsed : List FactName
  deriving DecidableEq, Repr

structure Result where
  outcome : Outcome
  bundleIssues : List String
  rules : List RuleResult
  missingFacts : List FactName
  deriving DecidableEq, Repr

end RightRail.ProviderApp
