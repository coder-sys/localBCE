import BlindLedger.Arithmetic
import BlindLedger.RowBounds
import BlindLedger.WidthBounds

set_option maxRecDepth 100000

namespace BlindLedger.SecurityArithmetic

open ExactFrac

/-!
  The executable imports this module so the emitted record is tied to named
  theorem terms, rather than to an unproved collection of calculations.
  These theorems cover only finite arithmetic and counter invariants.  The
  cryptographic, primitive, custody, and operational claims remain external
  premises and are named in `externalPremises` below.
-/

def externalPremises : List String :=
  [ "crypto_reduction=EXTERNAL_PREMISE"
  , "primitive_security=EXTERNAL_PREMISE"
  , "source_custody_and_independence=EXTERNAL_PREMISE"
  , "operations_and_rng=EXTERNAL_PREMISE" ]

theorem cap_theorem_bundle :
    Counters.WellFormed capCounters ∧
    qAlg capCounters = pow2 128 + 4264009 * pow2 32 ∧
    qEff capCounters = pow2 128 + 4264009 * pow2 32 + 38 ∧
    qHist capCounters = pow2 128 + 4264016 * pow2 32 ∧
    pUpper capCounters = 4198401 * pow2 32 ∧
    nonnegative (adaptiveRemaining capCounters) ∧
    (qromUncapped capCounters).lt (ofNat 1 4 (by decide)) ∧
    (adaptiveSquare capCounters).lt
      ((adaptiveRemaining capCounters).mul (adaptiveRemaining capCounters)) := by
  exact ⟨cap_counters_well_formed, q_alg_cap_exact, q_eff_cap_exact, q_hist_cap_exact,
    p_cap_exact, cap_remaining_nonnegative, cap_qrom_bound_lt_quarter,
    cap_adaptive_square_lt_remaining_square⟩

theorem width_partition_bundle :
    width384.widthBytes = 48 ∧ width384.r = 1056 ∧ width384.nuBits = 1439 ∧
    width384.nuSerializedBytes = 180 ∧ width384.streamBlocksPerRow = 330 ∧
    width384.m4Bytes = 15348 ∧ width384.frameBytes = 539306 ∧
    width512.widthBytes = 64 ∧ width512.r = 1312 ∧ width512.nuBits = 1823 ∧
    width512.nuSerializedBytes = 228 ∧ width512.streamBlocksPerRow = 248 ∧
    width512.m4Bytes = 20068 ∧ width512.frameBytes = 544074 := by
  exact ⟨width384_partition.1, width384_partition.2.1, width384_partition.2.2.1,
    width384_partition.2.2.2.1, width384_partition.2.2.2.2.1,
    width384_partition.2.2.2.2.2.1, width384_partition.2.2.2.2.2.2,
    width512_partition.1, width512_partition.2.1, width512_partition.2.2.1,
    width512_partition.2.2.2.1, width512_partition.2.2.2.2.1,
    width512_partition.2.2.2.2.2.1, width512_partition.2.2.2.2.2.2⟩

theorem row_bounds_certificate_bundle :
    (rowEval 0).maximum.eq e3 ∧
    (rowEval 1).maximum.eq e3 ∧
    (rowEval 0).maximum.le (rowEval 0).simplified ∧
    (rowEval 1).maximum.le (rowEval 1).simplified ∧
    (∀ j, (rowEval j).maximum.le (rowEval j).simplified) := by
  exact ⟨row_bounds_zero_max_e3, row_bounds_one_max_e3,
    row_bounds_zero_simplified, row_bounds_one_simplified, row_bounds_simplified⟩

theorem width_delta_all_k_bundle :
    (∀ k, k ≤ width384.qEffV3 →
      (widthRowMaximum width384 k).eq e3) ∧
    (∀ k, k ≤ width512.qEffV3 →
      (widthRowMaximum width512 k).eq e3) := by
  exact ⟨fun k hk => width384_delta_cap_all_k hk,
    fun k hk => width512_delta_cap_all_k hk⟩

end BlindLedger.SecurityArithmetic
