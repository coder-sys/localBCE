import BlindLedger.Gate.Obligations.EngineLogKept

namespace BlindLedger.Gate.Obligations

/-- The checker accepts every log the engine writes from commands that state what every command of this step
    states. -/
theorem engine_log_checks : EngineLogChecks := engine_log_checks_of forward kept

end BlindLedger.Gate.Obligations
