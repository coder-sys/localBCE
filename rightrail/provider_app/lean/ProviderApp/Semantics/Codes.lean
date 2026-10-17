import Semantics.Model

namespace RightRail.ProviderApp

def ruleOrder : List RuleId :=
  [.serviceDate, .serviceCategory, .supportReference, .chargeRange, .sourceCurrency]

def factOrder : List FactName :=
  [.serviceDate, .serviceCategory, .supportReference, .chargeCents,
   .sourceBinding, .sourceEffectiveAt, .sourceReceivedAt]

def ruleIdCode : RuleId → String
  | .serviceDate => "SYN-PRE-001"
  | .serviceCategory => "SYN-PRE-002"
  | .supportReference => "SYN-PRE-003"
  | .chargeRange => "SYN-PRE-004"
  | .sourceCurrency => "SYN-PRE-005"

def factCode : FactName → String
  | .serviceDate => "service_date"
  | .serviceCategory => "service_category"
  | .supportReference => "support_reference"
  | .chargeCents => "charge_cents"
  | .sourceBinding => "source_binding"
  | .sourceEffectiveAt => "source_effective_at"
  | .sourceReceivedAt => "source_received_at"

def outcomeCode : Outcome → String
  | .pass => "PASS"
  | .missing => "MISSING"
  | .humanCheck => "HUMAN_CHECK"

end RightRail.ProviderApp
