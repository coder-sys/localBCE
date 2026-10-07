import BlindLedger.Financial.Payment.Batch
import BlindLedger.Financial.Payment.ChainLaws

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial

/-- `erase` drops nothing section 11 stores: whenever today's projection (ChainLaws.lean:14) has a
    stored image, its stored part is the erased outcome. -/
theorem project_factors_erase (r : PaymentRequest) (o : PaymentOutcome) :
    (project r o).map Erased.ofStep = (project r o).map fun _ => erase o := by
  cases o <;> simp [project, erase, Erased.ofStep, Option.map_map, Function.comp_def]

end BlindLedger.Financial.Payment
