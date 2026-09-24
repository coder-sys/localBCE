import BlindLedger.Theorems

namespace BlindLedger.SecurityArithmetic

open ExactFrac

def boolText (value : Bool) : String := if value then "true" else "false"

def propText (value : Prop) [Decidable value] : String := boolText (decide value)

def theoremStatus {value : Prop} (_proof : value) : String := "PROVED_THEOREM_TERM"

def boolFromProof {value : Prop} (_proof : value) : Bool := true

def fracText (value : ExactFrac) : String :=
  toString value.num ++ "/" ++ toString value.den

def render (tag : String) (fields : List (String × String)) : String :=
  fields.foldl (fun output field => output ++ ";" ++ field.1 ++ "=" ++ field.2) tag

def counterFields (c : Counters) : List (String × String) :=
  [ ("Q", toString c.q)
  , ("A", toString c.a)
  , ("V", toString c.v)
  , ("M", toString c.m)
  , ("E_U", toString c.eu)
  , ("S", toString c.s)
  , ("R0", toString c.r0)
  , ("R2", toString c.r2)
  , ("R3", toString c.r3)
  , ("h0_first", toString c.h0First)
  , ("h0_accepted", toString c.h0Accepted)
  , ("h0_rejected", toString c.h0Rejected)
  , ("h0_aborted", toString c.h0Aborted)
  , ("h0_oracle_evaluations", toString c.h0Oracle)
  , ("fs2_first", toString c.fs2First)
  , ("fs2_accepted", toString c.fs2Accepted)
  , ("fs2_rejected", toString c.fs2Rejected)
  , ("fs2_aborted", toString c.fs2Aborted)
  , ("fs2_oracle_evaluations", toString c.fs2Oracle)
  , ("fs3_first", toString c.fs3First)
  , ("fs3_accepted", toString c.fs3Accepted)
  , ("fs3_rejected", toString c.fs3Rejected)
  , ("fs3_aborted", toString c.fs3Aborted)
  , ("fs3_oracle_evaluations", toString c.fs3Oracle)
  , ("one_commitment_per_attempt", boolText c.oneCommitmentPerAttempt)
  , ("source_generation_admitted", boolText c.sourceGenerationAdmitted)
  , ("U96_nonzero", boolText c.u96Nonzero)
  , ("source_coins_independent", boolText c.sourceCoinsIndependent)
  , ("source_cap_enforced", boolText c.sourceCapEnforced) ]

def qromFields (c : Counters) : List (String × String) :=
  let raw := qromUncapped c
  [ ("q_alg", toString (qAlg c))
  , ("q_eff", toString (qEff c))
  , ("q", toString (qEff c))
  , ("uncapped", fracText raw)
  , ("bound", fracText raw) ]

def capQromFields : List (String × String) :=
  let c := capCounters
  let raw := qromUncapped c
  [ ("q_alg", toString (qAlg c))
  , ("q_eff", toString (qEff c))
  , ("q", toString (qEff c))
  , ("q_alg_overhead", toString (qAlg c - pow2 128))
  , ("q_overhead", toString (qEff c - pow2 128))
  , ("uncapped", fracText raw)
  , ("bound", fracText raw)
  , ("q_overhead_lt_2^55", propText (qEff c - pow2 128 < pow2 55))
  , ("bound_lt_one_quarter", propText ((qromUncapped c).lt (ofNat 1 4 (by decide))))
  , ("half_success_probe_q", toString qProbe)
  , ("half_success_probe_q_eff", toString qProbe)
  , ("half_success_probe_bound", fracText qromProbeBound)
  , ("half_success_probe_lt_one_half", propText (qromProbeBound.lt (ofNat 1 2 (by decide)))) ]

def privacyFields (c : Counters) : List (String × String) :=
  let linear := adaptiveLinear c
  let remaining := adaptiveRemaining c
  let square := adaptiveSquare c
  [ ("P_upper_bound", toString (pUpper c))
  , ("q_hist", toString (qHist c))
  , ("q_hist_overhead", toString (qHist c - c.q))
  , ("q_star_without_overlay", toString (2 * qHist c))
  , ("q_hist_lt_cap_ratio", propText (qHist c < pow2 128 + pow2 55))
  , ("linear_term", fracText linear)
  , ("remaining", fracText remaining)
  , ("remaining_nonnegative", propText remaining.nonnegative)
  , ("sqrt_radicand", toString (pUpper c ^ 2 * qHist c))
  , ("sqrt_term", fracText square)
  , ("sqrt_square_lt_remaining_square", propText (square.lt (remaining.mul remaining)))
  , ("target", fracText (pow2Frac 1 137))
  , ("bit_switching", fracText (bitSwitching c))
  , ("source_switching", fracText (sourceSwitching c))
  , ("combined_switching_at_caps", fracText combinedSwitchingAtCaps)
  , ("combined_switching_available", boolText c.sourceCapEnforced)
  , ("source_binding", fracText (sourceBinding c)) ]

def constantFields : List (String × String) :=
  [ ("e0", fracText e0)
  , ("eKOS", fracText eKOS)
  , ("e2", fracText e2)
  , ("e3", fracText e3)
  , ("max_constant", fracText e3)
  , ("max_is_e3", propText (e0.le e3 ∧ eKOS.le e3 ∧ e2.le e3))
  , ("e3_ge_e0", propText (e0.le e3))
  , ("e3_ge_eKOS", propText (eKOS.le e3))
  , ("e3_ge_e2", propText (e2.le e3))
  , ("density_a_lt_2^17", propText (125049 < pow2 17))
  , ("density_m_minus_1_lt_2^18", propText (172231 < pow2 18)) ]

def widthFields (w : WidthEval)
    (deltaProof : ∀ k, k ≤ w.qEffV3 → (widthRowMaximum w k).eq e3) : List (String × String) :=
  [ ("width", toString w.width)
  , ("seed_width_bits", toString w.width)
  , ("seed_width_bytes", toString w.widthBytes)
  , ("r", toString w.r)
  , ("nu_bits", toString w.nuBits)
  , ("active_h0_bits", toString w.activeH0Bits)
  , ("h0_squeeze_bytes", toString w.h0SqueezeBytes)
  , ("nu_serialized_bytes", toString w.nuSerializedBytes)
  , ("commitment_bytes", toString w.commitmentBytes)
  , ("leaf_output_bits", toString w.leafOutputBits)
  , ("leaf_output_bytes", toString w.leafOutputBytes)
  , ("stream_blocks_per_row", toString w.streamBlocksPerRow)
  , ("frontier_seed_bytes", toString w.widthBytes)
  , ("m4_bytes", toString w.m4Bytes)
  , ("frame_bytes", toString w.frameBytes)
  , ("frame_delta", toString w.frameDelta)
  , ("h0_input_bytes", "51")
  , ("h1_vector_128_input_bytes", toString w.h1Vector128Bytes)
  , ("h1_vector_256_input_bytes", toString w.h1Vector256Bytes)
  , ("h1_outer_input_bytes", "2140")
  , ("fs_uhash_bytes", toString w.nuSerializedBytes)
  , ("tree_child_queries_per_commitment", "12798")
  , ("generator_H_queries_per_commitment", toString w.generatorPerCommitment)
  , ("generator_H_queries_at_caps", toString w.generatorAtCaps)
  , ("verifier_generator_H_queries_per_verification", toString w.verifierPerVerification)
  , ("verifier_generator_H_queries_at_caps", toString w.verifierAtCaps)
  , ("candidate_q_hist_at_caps", toString w.qHistV3)
  , ("candidate_q_alg_at_caps", toString w.qAlgV3)
  , ("candidate_qP", toString w.qP)
  , ("candidate_q_eff_at_caps", toString w.qEffV3)
  , ("candidate_q_H_at_caps", toString w.qH)
  , ("candidate_total_public_RO_queries_at_caps", toString w.qTotal)
  , ("secret_seed_count_at_caps", toString w.secretSeedCount)
  , ("hybrid_count_at_caps", toString w.hybridCount)
  , ("h0_completion", fracText w.h0Completion)
  , ("e_leaf_v3", fracText w.eLeaf)
  , ("eKOS", fracText eKOS)
  , ("e2", fracText e2)
  , ("e3", fracText e3)
  , ("direct_max", fracText w.directMax)
  , ("e3_ge_e_leaf_v3", propText (w.eLeaf.le e3))
  , ("e3_ge_eKOS", propText (eKOS.le e3))
  , ("e3_ge_e2", propText (e2.le e3))
  , ("direct_constant_max_name", "e3")
  , ("h0_bound", fracText w.h0Bound)
  , ("h1_vector_bound", fracText w.h1VectorBound)
  , ("h1_outer_bound", fracText w.h1OuterBound)
  , ("fs1_bound", fracText w.fs1Bound)
  , ("fs2_bound", fracText w.fs2Bound)
  , ("fs3_bound", fracText w.fs3Bound)
  , ("delta_cap_name", "FS3")
  , ("delta_cap_is_constant_for_all_k", boolText (boolFromProof deltaProof))
  , ("delta_cap", fracText w.fs3Bound)
  , ("delta_linear_weight", fracText w.deltaLinearWeight)
  , ("delta_sum_upper", fracText w.deltaSumUpper)
  , ("soundness_bound", fracText w.soundnessBound)
  , ("generator_privacy_bound", fracText w.generatorPrivacyBound)
  , ("seed_collision_term", fracText w.seedCollisionTerm)
  , ("epsilon_ar_upper_bound", fracText (pow2Frac 1 137))
  , ("source_alpha_ceiling", fracText w.sourceAlphaCeiling)
  , ("source_switching", fracText w.sourceSwitching)
  , ("fs1_bytes", toString w.fs1Bytes)
  , ("fs2_bytes", toString w.fs2Bytes)
  , ("fs3_bytes", toString w.fs3Bytes)
  , ("fs1_bits", toString w.fs1Bits)
  , ("fs2_bits", toString w.fs2Bits)
  , ("fs3_bits", toString w.fs3Bits)
  , ("program_points", toString w.programPoints)
  , ("table_entry_bits", toString w.tableEntryBits)
  , ("table_memory_bits", toString w.tableMemoryBits)
  , ("table_memory_bytes", toString w.tableMemoryBytes)
  , ("scan_units_per_forward", toString w.scanUnitsPerForward)
  , ("scan_history_units", toString w.scanHistoryUnits)
  , ("scan_forward_reverse_units", toString w.scanForwardReverseUnits) ]

def rowFields (row : RowEval) : List (String × String) :=
  [ ("j", toString row.j)
  , ("H0_leaf_bad_or_completion", fracText row.h0)
  , ("H1_vector", fracText row.h1Vector)
  , ("H1_outer", fracText row.h1Outer)
  , ("FS1", fracText row.fs1)
  , ("FS2", fracText row.fs2)
  , ("FS3", fracText row.fs3)
  , ("other_typed_input", fracText row.otherTyped)
  , ("maximum_row_bound", fracText row.maximum)
  , ("simplified_replacement_bound", fracText row.simplified)
  , ("simplified_bound_holds", propText (row.maximum.le row.simplified)) ]

def header (mode : String) : String :=
  render "BL-SECURITY-ARITHMETIC/2"
    [ ("schema", schemaId)
    , ("result", "PASS")
    , ("mode", mode)
    , ("build_id", buildId)
    , ("toolchain", "leanprover/lean4:v4.33.1") ]

def rejectLine (mode error : String) : String :=
  render "BL-SECURITY-ARITHMETIC/2"
    [ ("schema", schemaId)
    , ("result", "REJECT")
    , ("mode", mode)
    , ("build_id", buildId)
    , ("toolchain", "leanprover/lean4:v4.33.1")
    , ("error", error) ]

def theoremLine : String :=
  render "THEOREMS"
    [ ("manifest_count", toString theoremManifest.length)
    , ("manifest_names", theoremManifestEncoded)
    , ("manifest_count_proof", theoremStatus theoremManifest_count)
    , ("cap_bundle", theoremStatus cap_theorem_bundle)
     , ("width_bundle", theoremStatus width_partition_bundle)
     , ("completion_accounting", theoremStatus (fun c => q_eff_completion_accounting c))
     , ("row_bounds_bundle", theoremStatus row_bounds_certificate_bundle)
     , ("row_bounds_simplified", theoremStatus row_bounds_simplified)
     , ("width384_delta_cap_all_k", theoremStatus (fun k hk =>
          width384_delta_cap_all_k (k := k) hk))
     , ("width512_delta_cap_all_k", theoremStatus (fun k hk =>
          width512_delta_cap_all_k (k := k) hk))
     , ("width_delta_all_k_bundle", theoremStatus width_delta_all_k_bundle)
     , ("crypto_primitives_custody_operations", "EXTERNAL_PREMISES") ]

def capLines : List String :=
  [ header "cap"
  , theoremLine
  , render "COUNTERS" (counterFields capCounters)
  , render "CONSTANTS" constantFields
  , render "QROM" capQromFields
  , render "PRIVACY" (privacyFields capCounters)
  , render "WIDTH" (widthFields width384 (fun k hk =>
      width384_delta_cap_all_k (k := k) hk))
  , render "WIDTH" (widthFields width512 (fun k hk =>
      width512_delta_cap_all_k (k := k) hk)) ]

def runtimeLines (c : Counters) : List String :=
  [ header "runtime"
  , theoremLine
  , render "COUNTERS" (counterFields c)
  , render "QROM" (qromFields c)
  , render "PRIVACY" (privacyFields c) ]

def parseNatToken (token : String) : Except String Nat :=
  match token.toNat? with
  | some value => .ok value
  | none => .error "natural-number-parse"

def parseBoolToken (token : String) : Except String Bool :=
  if token = "true" then .ok true
  else if token = "false" then .ok false
  else .error "boolean-parse"

def parseRuntime (tokens : List String) : Except String Counters := do
  if tokens.length ≠ 29 then
    throw "runtime-arity"
  let numbers ← tokens.take 24 |>.mapM parseNatToken
  let flags ← tokens.drop 24 |>.mapM parseBoolToken
  match numbers, flags with
  | [q, a, v, m, eu, s, r0, r2, r3, h0First, h0Accepted, h0Rejected, h0Aborted,
      h0Oracle, fs2First, fs2Accepted, fs2Rejected, fs2Aborted, fs2Oracle,
      fs3First, fs3Accepted, fs3Rejected, fs3Aborted, fs3Oracle],
      [oneCommitmentPerAttempt, sourceGenerationAdmitted, u96Nonzero,
        sourceCoinsIndependent, sourceCapEnforced] =>
    pure
      { q := q, a := a, v := v, m := m, eu := eu, s := s
        r0 := r0, r2 := r2, r3 := r3
        h0First := h0First, h0Accepted := h0Accepted, h0Rejected := h0Rejected
        h0Aborted := h0Aborted, h0Oracle := h0Oracle
        fs2First := fs2First, fs2Accepted := fs2Accepted, fs2Rejected := fs2Rejected
        fs2Aborted := fs2Aborted, fs2Oracle := fs2Oracle
        fs3First := fs3First, fs3Accepted := fs3Accepted, fs3Rejected := fs3Rejected
        fs3Aborted := fs3Aborted, fs3Oracle := fs3Oracle
        oneCommitmentPerAttempt := oneCommitmentPerAttempt
        sourceGenerationAdmitted := sourceGenerationAdmitted
        u96Nonzero := u96Nonzero
        sourceCoinsIndependent := sourceCoinsIndependent
        sourceCapEnforced := sourceCapEnforced }
  | _, _ => throw "runtime-arity"

def runtimeResult (c : Counters) : List String :=
  if c.WellFormed then runtimeLines c
  else [rejectLine "runtime" "counters-not-well-formed"]

def runArgs (args : List String) : List String :=
  match args with
  | ["cap"] => capLines
  | ["row", token] =>
    match parseNatToken token with
    | .ok j => [ header "row", theoremLine, render "ROW" (rowFields (rowEval j)) ]
    | .error error => [rejectLine "row" error]
  | "row" :: _ => [rejectLine "row" "row-arity"]
  | "runtime" :: tokens =>
    match parseRuntime tokens with
    | .ok counters => runtimeResult counters
    | .error error => [rejectLine "runtime" error]
  | _ => [rejectLine "unknown" "argument-shape"]

def main (args : List String) : IO Unit := do
  for line in runArgs args do
    IO.println line

end BlindLedger.SecurityArithmetic

def main (args : List String) : IO Unit := BlindLedger.SecurityArithmetic.main args
