import Std
import Lean.Elab.Tactic.Omega

set_option exponentiation.threshold 4096

namespace BlindLedger.SecurityArithmetic

/-!
  This module is deliberately independent of the product implementation.  It is
  the small arithmetic kernel for the finite counter, query, switching, and
  width-budget ledgers.  Crypto reductions, primitive bounds, custody, and
  operational assumptions are not definitions in this module.
-/

def buildId : String := "BL-SECURITY-ARITHMETIC-20260922-V2"
def schemaId : String := "BLSECAR02/v2"

def pow2 (exponent : Nat) : Nat := 2 ^ exponent

def choose2 (n : Nat) : Nat := n * (n - 1) / 2
def choose3 (n : Nat) : Nat := n * (n - 1) * (n - 2) / 6

structure ExactFrac where
  num : Int
  den : Nat
  den_pos : 0 < den

namespace ExactFrac

def ofNat (n d : Nat) (hd : 0 < d) : ExactFrac :=
  { num := n, den := d, den_pos := hd }

def add (a b : ExactFrac) : ExactFrac :=
  { num := a.num * (b.den : Int) + b.num * (a.den : Int)
    den := a.den * b.den
    den_pos := Nat.mul_pos a.den_pos b.den_pos }

def sub (a b : ExactFrac) : ExactFrac :=
  { num := a.num * (b.den : Int) - b.num * (a.den : Int)
    den := a.den * b.den
    den_pos := Nat.mul_pos a.den_pos b.den_pos }

def mul (a b : ExactFrac) : ExactFrac :=
  { num := a.num * b.num
    den := a.den * b.den
    den_pos := Nat.mul_pos a.den_pos b.den_pos }

def divNat (a : ExactFrac) (n : Nat) (hn : 0 < n) : ExactFrac :=
  { num := a.num
    den := a.den * n
    den_pos := Nat.mul_pos a.den_pos hn }

def lt (a b : ExactFrac) : Prop :=
  a.num * (b.den : Int) < b.num * (a.den : Int)

def le (a b : ExactFrac) : Prop :=
  a.num * (b.den : Int) ≤ b.num * (a.den : Int)

def eq (a b : ExactFrac) : Prop :=
  a.num * (b.den : Int) = b.num * (a.den : Int)

def nonnegative (a : ExactFrac) : Prop := 0 ≤ a.num

instance (a b : ExactFrac) : Decidable (lt a b) := by
  unfold lt
  infer_instance

instance (a b : ExactFrac) : Decidable (le a b) := by
  unfold le
  infer_instance

instance (a b : ExactFrac) : Decidable (eq a b) := by
  unfold eq
  infer_instance

instance (a : ExactFrac) : Decidable (nonnegative a) := by
  unfold nonnegative
  infer_instance

def pow2Frac (n exponent : Nat) : ExactFrac :=
  ofNat n (pow2 exponent) (Nat.pow_pos (by decide))

def one : ExactFrac := ofNat 1 1 (by decide)

end ExactFrac

open ExactFrac

structure Counters where
  q : Nat
  a : Nat
  v : Nat
  m : Nat
  eu : Nat
  s : Nat
  r0 : Nat
  r2 : Nat
  r3 : Nat
  h0First : Nat
  h0Accepted : Nat
  h0Rejected : Nat
  h0Aborted : Nat
  h0Oracle : Nat
  fs2First : Nat
  fs2Accepted : Nat
  fs2Rejected : Nat
  fs2Aborted : Nat
  fs2Oracle : Nat
  fs3First : Nat
  fs3Accepted : Nat
  fs3Rejected : Nat
  fs3Aborted : Nat
  fs3Oracle : Nat
  oneCommitmentPerAttempt : Bool
  sourceGenerationAdmitted : Bool
  u96Nonzero : Bool
  sourceCoinsIndependent : Bool
  sourceCapEnforced : Bool

def stageWellFormed (first accepted rejected aborted oracle total : Nat) : Prop :=
  accepted + rejected + aborted = total ∧
  first ≤ total ∧
  accepted ≤ first ∧
  oracle ≤ total ∧
  (first = 0 → total = 0)

def Counters.WellFormed (c : Counters) : Prop :=
  c.q ≤ pow2 128 ∧
  c.a ≤ pow2 32 ∧
  c.v ≤ pow2 32 ∧
  c.eu ≤ pow2 32 ∧
  (c.sourceCapEnforced = true → c.s ≤ pow2 32) ∧
  c.h0First = c.a ∧
  stageWellFormed c.h0First c.h0Accepted c.h0Rejected c.h0Aborted c.h0Oracle c.r0 ∧
  stageWellFormed c.fs2First c.fs2Accepted c.fs2Rejected c.fs2Aborted c.fs2Oracle c.r2 ∧
  stageWellFormed c.fs3First c.fs3Accepted c.fs3Rejected c.fs3Aborted c.fs3Oracle c.r3 ∧
  c.r0 ≤ pow2 16 * c.a ∧
  c.r2 ≤ pow2 12 * c.a ∧
  c.r3 ≤ pow2 22 * c.a ∧
  c.m ≤ c.a ∧
  c.fs2First ≤ c.a ∧
  c.fs3First ≤ c.a ∧
  c.oneCommitmentPerAttempt = true ∧
  c.sourceGenerationAdmitted = true ∧
  c.u96Nonzero = true ∧
  c.sourceCoinsIndependent = true

instance (c : Counters) : Decidable c.WellFormed := by
  unfold Counters.WellFormed stageWellFormed
  infer_instance

def Counters.BoundedBy (a b : Counters) : Prop :=
  a.q ≤ b.q ∧ a.a ≤ b.a ∧ a.v ≤ b.v ∧ a.r0 ≤ b.r0 ∧ a.r2 ≤ b.r2 ∧ a.r3 ≤ b.r3

def capCounters : Counters :=
  { q := pow2 128
    a := pow2 32
    v := pow2 32
    m := pow2 32
    eu := pow2 32
    s := pow2 32
    r0 := pow2 16 * pow2 32
    r2 := pow2 12 * pow2 32
    r3 := pow2 22 * pow2 32
    h0First := pow2 32
    h0Accepted := pow2 32
    h0Rejected := pow2 16 * pow2 32 - pow2 32
    h0Aborted := 0
    h0Oracle := pow2 16 * pow2 32
    fs2First := pow2 32
    fs2Accepted := pow2 32
    fs2Rejected := pow2 12 * pow2 32 - pow2 32
    fs2Aborted := 0
    fs2Oracle := pow2 12 * pow2 32
    fs3First := pow2 32
    fs3Accepted := pow2 32
    fs3Rejected := pow2 22 * pow2 32 - pow2 32
    fs3Aborted := 0
    fs3Oracle := pow2 22 * pow2 32
    oneCommitmentPerAttempt := true
    sourceGenerationAdmitted := true
    u96Nonzero := true
    sourceCoinsIndependent := true
    sourceCapEnforced := true }

def qAlg (c : Counters) : Nat :=
  c.q + 35 * c.a + 38 * c.v + c.r0 + c.r2 + c.r3

def qEff (c : Counters) : Nat := qAlg c + 38

def qHist (c : Counters) : Nat :=
  c.q + 39 * c.a + 41 * c.v + c.r0 + c.r2 + c.r3

def pUpper (c : Counters) : Nat := c.a + c.r2 + c.r3

def qromUncapped (c : Counters) : ExactFrac :=
  add (pow2Frac (1020 * (qEff c) ^ 3) 512)
    (pow2Frac (30 * (qEff c) ^ 2) 263)

def qProbe : Nat := Nat.sqrt (pow2 257) + 1

def qromProbeBound : ExactFrac :=
  add (pow2Frac (1020 * qProbe ^ 3) 512)
    (pow2Frac (30 * qProbe ^ 2) 263)

def adaptiveLinear (c : Counters) : ExactFrac :=
  ofNat (pUpper c * qHist c) (2 * pow2 512)
    (Nat.mul_pos (by decide) (Nat.pow_pos (by decide)))

/- The common-denominator form is intentional: it exposes the exact remaining
   numerator and makes its sign a kernel-checked natural-number comparison. -/
def adaptiveRemaining (c : Counters) : ExactFrac :=
  { num := (pow2 376 : Int) - (pUpper c * qHist c : Int)
    den := pow2 513
    den_pos := Nat.pow_pos (by decide) }

def adaptiveSquare (c : Counters) : ExactFrac :=
  ofNat ((pUpper c) ^ 2 * qHist c) (pow2 512) (Nat.pow_pos (by decide))

def bitSwitching (c : Counters) : ExactFrac :=
  ofNat (c.m * 85297284) (pow2 128) (Nat.pow_pos (by decide))

def sourceSwitching (c : Counters) : ExactFrac :=
  ofNat (c.s * 1253) (pow2 128) (Nat.pow_pos (by decide))

def combinedSwitchingAtCaps : ExactFrac := pow2Frac 85298537 96

def sourceBinding (c : Counters) : ExactFrac := pow2Frac c.eu 257

def e0 : ExactFrac := pow2Frac (33 * choose2 (pow2 256)) 778

def eKOS : ExactFrac :=
  mul (pow2Frac (choose3 (pow2 248)) 1024)
    (add one (pow2Frac (125049 ^ 5) 64))

def e2 : ExactFrac :=
  divNat (add one (pow2Frac (172231 ^ 2) 64)) (pow2 262)
    (Nat.pow_pos (by decide))

def e3 : ExactFrac := pow2Frac 3 263

def zeroFrac : ExactFrac := ofNat 0 1 (by decide)

def maxFrac (a b : ExactFrac) : ExactFrac :=
  if le a b then b else a

structure RowEval where
  j : Nat
  h0 : ExactFrac
  h1Vector : ExactFrac
  h1Outer : ExactFrac
  fs1 : ExactFrac
  fs2 : ExactFrac
  fs3 : ExactFrac
  otherTyped : ExactFrac
  maximum : ExactFrac
  simplified : ExactFrac

def rowEval (j : Nat) : RowEval :=
  let h0 := add (pow2Frac j 768) e0
  let h1Vector := pow2Frac (34 * j) 512
  let h1Outer := pow2Frac (2 * j) 512
  let fs1 := add (pow2Frac (2 * j) 2112) eKOS
  let fs2 := add (pow2Frac (2 * j) 832) e2
  let fs3 := e3
  let otherTyped := zeroFrac
  let maximum :=
    maxFrac (maxFrac (maxFrac (maxFrac (maxFrac (maxFrac h0 h1Vector) h1Outer) fs1) fs2) fs3)
      otherTyped
  let simplified := add (pow2Frac (102 * j) 512) e3
  { j := j
    h0 := h0
    h1Vector := h1Vector
    h1Outer := h1Outer
    fs1 := fs1
    fs2 := fs2
    fs3 := fs3
    otherTyped := otherTyped
    maximum := maximum
    simplified := simplified }

def baseDeltaLinearWeight : ExactFrac :=
  add (pow2Frac 36 512)
    (add (pow2Frac 2 2112) (pow2Frac 2 832))

def baseFrameWithoutNuOrM4 : Nat := 534370 - 96 - 10496

structure WidthEval where
  width : Nat
  widthBytes : Nat
  r : Nat
  nuBits : Nat
  activeH0Bits : Nat
  h0SqueezeBytes : Nat
  nuSerializedBytes : Nat
  commitmentBytes : Nat
  leafOutputBits : Nat
  leafOutputBytes : Nat
  streamBlocksPerRow : Nat
  m4Bytes : Nat
  frameBytes : Nat
  frameDelta : Nat
  h1Vector128Bytes : Nat
  h1Vector256Bytes : Nat
  generatorPerCommitment : Nat
  generatorAtCaps : Nat
  verifierPerVerification : Nat
  verifierAtCaps : Nat
  qHistV3 : Nat
  qAlgV3 : Nat
  qP : Nat
  qEffV3 : Nat
  qH : Nat
  qTotal : Nat
  secretSeedCount : Nat
  hybridCount : Nat
  h0Completion : ExactFrac
  eLeaf : ExactFrac
  directMax : ExactFrac
  h0Bound : ExactFrac
  h1VectorBound : ExactFrac
  h1OuterBound : ExactFrac
  fs1Bound : ExactFrac
  fs2Bound : ExactFrac
  fs3Bound : ExactFrac
  deltaLinearWeight : ExactFrac
  deltaSumUpper : ExactFrac
  soundnessBound : ExactFrac
  generatorPrivacyBound : ExactFrac
  seedCollisionTerm : ExactFrac
  sourceAlphaCeiling : ExactFrac
  sourceSwitching : ExactFrac
  fs1Bytes : Nat
  fs2Bytes : Nat
  fs3Bytes : Nat
  fs1Bits : Nat
  fs2Bits : Nat
  fs3Bits : Nat
  programPoints : Nat
  tableEntryBits : Nat
  tableMemoryBits : Nat
  tableMemoryBytes : Nat
  scanUnitsPerForward : Nat
  scanHistoryUnits : Nat
  scanForwardReverseUnits : Nat

def lpTotal (payloads : List Nat) : Nat :=
  payloads.foldl (fun total payload => total + payload) 0 + 4 * payloads.length

def widthEval (width : Nat) : WidthEval :=
  let widthBytes := width / 8
  let r := 2 * width + 288
  let nuBits := r + width - 1
  let activeH0Bits := nuBits + 10
  let h0SqueezeBytes := (activeH0Bits + 7) / 8
  let nuSerializedBytes := (nuBits + 7) / 8
  let commitmentBytes := r / 8
  let leafOutputBits := width + r
  let leafOutputBytes := leafOutputBits / 8
  let streamBlocksPerRow := (15823 + widthBytes - 1) / widthBytes
  let m4Bytes := 33 * commitmentBytes + 229 * widthBytes
  let frameBytes := baseFrameWithoutNuOrM4 + nuSerializedBytes + m4Bytes
  let h1Vector128Bytes := 28 + 128 * commitmentBytes
  let h1Vector256Bytes := 28 + 256 * commitmentBytes
  let generatorPerCommitment := 2 * 6399 + 6400 * (1 + streamBlocksPerRow)
  let verifierPerVerification := 2 * (6400 - 1) + (1 + streamBlocksPerRow) * (6400 - 33)
  let generatorAtCaps := generatorPerCommitment * pow2 32
  let verifierAtCaps := verifierPerVerification * pow2 32
  let qHistV3 := qHist capCounters + generatorAtCaps + verifierAtCaps
  let programPoints := 4198401 * pow2 32
  let qAlgV3 := qAlg capCounters + generatorAtCaps + verifierAtCaps
  let qP := 38
  let qEffV3 := qAlgV3 + qP
  let qH := 2 * qHistV3 + programPoints
  let qTotal := qH
  let secretSeedCount := 19199 * pow2 32
  let hybridCount := 463 * pow2 32
  let h0Completion := pow2Frac 1 nuBits
  let leaf := pow2Frac (6400 * choose2 (pow2 width)) (r + 10)
  let h0Bound := add leaf (mul h0Completion (ofNat qEffV3 1 (by decide)))
  let h1VectorBound := pow2Frac (34 * qEffV3) 512
  let h1OuterBound := pow2Frac (2 * qEffV3) 512
  let fs1Bound := add (pow2Frac (2 * qEffV3) 2112) eKOS
  let fs2Bound := add (pow2Frac (2 * qEffV3) 832) e2
  let fs3Bound := e3
  let deltaLinearWeight := add h0Completion baseDeltaLinearWeight
  let deltaSumUpper := mul e3 (ofNat qEffV3 1 (by decide))
  let soundnessBound := mul (ofNat (10 * qEffV3) 1 (by decide)) deltaSumUpper
  let generatorPrivacyBound := pow2Frac (2 * hybridCount * qH) (width / 2)
  let sourceSwitching := pow2Frac (1253 * pow2 32) 128
  let sourceAlphaCeiling :=
    divNat (sub (sub (sub (ofNat 1 4 (by decide)) (pow2Frac 1 137)) generatorPrivacyBound)
      sourceSwitching) (pow2 32) (Nat.pow_pos (by decide))
  let fs1Bytes := 20 + 3 + lpTotal [1147, nuSerializedBytes, 506416, 64]
  let fs2Bytes := 20 + 3 + lpTotal [1147, nuSerializedBytes, 506416, 64, 264, 15887, 64]
  let fs3Bytes := 20 + 3 + lpTotal [1147, nuSerializedBytes, 506416, 64, 264, 15887, 64, 104, 96, 64]
  let fs1Bits := 8 * fs1Bytes
  let fs2Bits := 8 * fs2Bytes
  let fs3Bits := 8 * fs3Bytes
  let tableEntryBits := fs3Bits + 2112
  let tableMemoryBits := programPoints * tableEntryBits
  let scanUnitsPerForward := programPoints * fs3Bits
  { width := width
    widthBytes := widthBytes
    r := r
    nuBits := nuBits
    activeH0Bits := activeH0Bits
    h0SqueezeBytes := h0SqueezeBytes
    nuSerializedBytes := nuSerializedBytes
    commitmentBytes := commitmentBytes
    leafOutputBits := leafOutputBits
    leafOutputBytes := leafOutputBytes
    streamBlocksPerRow := streamBlocksPerRow
    m4Bytes := m4Bytes
    frameBytes := frameBytes
    frameDelta := frameBytes - 534370
    h1Vector128Bytes := h1Vector128Bytes
    h1Vector256Bytes := h1Vector256Bytes
    generatorPerCommitment := generatorPerCommitment
    generatorAtCaps := generatorAtCaps
    verifierPerVerification := verifierPerVerification
    verifierAtCaps := verifierAtCaps
    qHistV3 := qHistV3
    qAlgV3 := qAlgV3
    qP := qP
    qEffV3 := qEffV3
    qH := qH
    qTotal := qTotal
    secretSeedCount := secretSeedCount
    hybridCount := hybridCount
    h0Completion := h0Completion
    eLeaf := leaf
    directMax := e3
    h0Bound := h0Bound
    h1VectorBound := h1VectorBound
    h1OuterBound := h1OuterBound
    fs1Bound := fs1Bound
    fs2Bound := fs2Bound
    fs3Bound := fs3Bound
    deltaLinearWeight := deltaLinearWeight
    deltaSumUpper := deltaSumUpper
    soundnessBound := soundnessBound
    generatorPrivacyBound := generatorPrivacyBound
    seedCollisionTerm := ofNat 0 1 (by decide)
    sourceAlphaCeiling := sourceAlphaCeiling
    sourceSwitching := sourceSwitching
    fs1Bytes := fs1Bytes
    fs2Bytes := fs2Bytes
    fs3Bytes := fs3Bytes
    fs1Bits := fs1Bits
    fs2Bits := fs2Bits
    fs3Bits := fs3Bits
    programPoints := programPoints
    tableEntryBits := tableEntryBits
    tableMemoryBits := tableMemoryBits
    tableMemoryBytes := tableMemoryBits / 8
    scanUnitsPerForward := scanUnitsPerForward
    scanHistoryUnits := qHistV3 * scanUnitsPerForward
    scanForwardReverseUnits := qH * scanUnitsPerForward }

def width384 : WidthEval := widthEval 384
def width512 : WidthEval := widthEval 512

/-! Theorems used as the executable's trust-critical gates. -/

theorem cap_counters_well_formed : Counters.WellFormed capCounters := by
  unfold Counters.WellFormed stageWellFormed
  decide

theorem q_eff_completion_accounting (c : Counters) : qEff c = qAlg c + 38 := by
  rfl

theorem q_alg_cap_exact : qAlg capCounters = pow2 128 + 4264009 * pow2 32 := by
  decide

theorem q_eff_cap_exact : qEff capCounters = pow2 128 + 4264009 * pow2 32 + 38 := by
  decide

theorem q_hist_cap_exact : qHist capCounters = pow2 128 + 4264016 * pow2 32 := by
  decide

theorem p_cap_exact : pUpper capCounters = 4198401 * pow2 32 := by
  decide

theorem switching_counted_once_at_caps :
    (bitSwitching capCounters).num + (sourceSwitching capCounters).num =
      85298537 * pow2 32 := by
  decide

theorem q_alg_mono {a b : Counters} (h : a.BoundedBy b) : qAlg a ≤ qAlg b := by
  unfold Counters.BoundedBy at h
  unfold qAlg
  rcases h with ⟨hq, ha, hv, hr0, hr2, hr3⟩
  omega

theorem q_eff_mono {a b : Counters} (h : a.BoundedBy b) : qEff a ≤ qEff b := by
  exact Nat.add_le_add_right (q_alg_mono h) 38

theorem q_hist_mono {a b : Counters} (h : a.BoundedBy b) : qHist a ≤ qHist b := by
  unfold Counters.BoundedBy at h
  unfold qHist
  rcases h with ⟨hq, ha, hv, hr0, hr2, hr3⟩
  omega

theorem p_mono {a b : Counters} (h : a.BoundedBy b) : pUpper a ≤ pUpper b := by
  unfold Counters.BoundedBy at h
  unfold pUpper
  rcases h with ⟨hq, ha, hv, hr0, hr2, hr3⟩
  omega

theorem cap_remaining_nonnegative : nonnegative (adaptiveRemaining capCounters) := by
  unfold nonnegative adaptiveRemaining
  decide

theorem remaining_nonnegative_on_admissible (c : Counters) (h : c.WellFormed) :
    nonnegative (adaptiveRemaining c) := by
  have hb : c.BoundedBy capCounters := by
    unfold Counters.BoundedBy
    rcases h with ⟨hq, ha, hv, heu, hs, hfirst, hh0, hfs2, hfs3, hr0, hr2, hr3, hm, h2a, h3a,
      hone, hgen, hu, hind⟩
    have haCap : c.a ≤ capCounters.a := by simpa [capCounters] using ha
    have hr0Cap : c.r0 ≤ capCounters.r0 := by
      calc
        c.r0 ≤ pow2 16 * c.a := hr0
        _ ≤ pow2 16 * pow2 32 := Nat.mul_le_mul_left _ ha
        _ = capCounters.r0 := by rfl
    have hr2Cap : c.r2 ≤ capCounters.r2 := by
      calc
        c.r2 ≤ pow2 12 * c.a := hr2
        _ ≤ pow2 12 * pow2 32 := Nat.mul_le_mul_left _ ha
        _ = capCounters.r2 := by rfl
    have hr3Cap : c.r3 ≤ capCounters.r3 := by
      calc
        c.r3 ≤ pow2 22 * c.a := hr3
        _ ≤ pow2 22 * pow2 32 := Nat.mul_le_mul_left _ ha
        _ = capCounters.r3 := by rfl
    exact ⟨hq, haCap, hv, hr0Cap, hr2Cap, hr3Cap⟩
  have hp : pUpper c ≤ pUpper capCounters := p_mono hb
  have hq : qHist c ≤ qHist capCounters := q_hist_mono hb
  have hprod : pUpper c * qHist c ≤ pUpper capCounters * qHist capCounters :=
    Nat.mul_le_mul hp hq
  have hcap : pUpper capCounters * qHist capCounters ≤ pow2 376 := by decide
  have hsmall : pUpper c * qHist c ≤ pow2 376 := Nat.le_trans hprod hcap
  have hsmallInt : (pUpper c * qHist c : Int) ≤ (pow2 376 : Int) := by
    exact_mod_cast hsmall
  change 0 ≤ (pow2 376 : Int) - (pUpper c * qHist c : Int)
  omega

theorem cap_qrom_bound_lt_quarter :
    qromUncapped capCounters |>.lt (ofNat 1 4 (by decide)) := by
  unfold ExactFrac.lt qromUncapped
  decide

theorem cap_adaptive_square_lt_remaining_square :
    (adaptiveSquare capCounters).lt
      ((adaptiveRemaining capCounters).mul (adaptiveRemaining capCounters)) := by
  unfold ExactFrac.lt adaptiveSquare adaptiveRemaining ExactFrac.mul
  decide

theorem width384_partition :
    width384.widthBytes = 48 ∧ width384.r = 1056 ∧ width384.nuBits = 1439 ∧
    width384.nuSerializedBytes = 180 ∧ width384.streamBlocksPerRow = 330 ∧
    width384.m4Bytes = 15348 ∧ width384.frameBytes = 539306 := by
  decide

theorem width512_partition :
    width512.widthBytes = 64 ∧ width512.r = 1312 ∧ width512.nuBits = 1823 ∧
    width512.nuSerializedBytes = 228 ∧ width512.streamBlocksPerRow = 248 ∧
    width512.m4Bytes = 20068 ∧ width512.frameBytes = 544074 := by
  decide

theorem width384_direct_constant_gate :
    ¬((e3).le width384.eLeaf ∨ (e3).le eKOS ∨ (e3).le e2) := by
  unfold ExactFrac.le
  decide

theorem width512_direct_constant_gate :
    ¬((e3).le width512.eLeaf ∨ (e3).le eKOS ∨ (e3).le e2) := by
  unfold ExactFrac.le
  decide

theorem row_bounds_zero_max_e3 : (rowEval 0).maximum.eq e3 := by
  decide

theorem row_bounds_one_max_e3 : (rowEval 1).maximum.eq e3 := by
  decide

theorem row_bounds_zero_simplified :
    (rowEval 0).maximum.le (rowEval 0).simplified := by
  decide

theorem row_bounds_one_simplified :
    (rowEval 1).maximum.le (rowEval 1).simplified := by
  decide

/- The generalized row and width proof terms are compiled in the separately
   guarded RowBounds and WidthBounds modules.  This keeps the arithmetic kernel
   compilation unit bounded while preserving the same named propositions. -/

def theoremManifest : List String :=
  [ "cap_adaptive_square_lt_remaining_square"
  , "cap_counters_well_formed"
  , "cap_qrom_bound_lt_quarter"
  , "cap_theorem_bundle"
  , "p_cap_exact"
  , "p_mono"
  , "q_alg_cap_exact"
  , "q_alg_mono"
  , "q_eff_cap_exact"
  , "q_eff_completion_accounting"
  , "q_eff_mono"
  , "q_hist_cap_exact"
  , "q_hist_mono"
  , "remaining_nonnegative_on_admissible"
  , "row_bounds_certificate_bundle"
  , "row_bounds_one_max_e3"
  , "row_bounds_one_simplified"
  , "row_bounds_simplified"
  , "row_bounds_zero_max_e3"
  , "row_bounds_zero_simplified"
  , "switching_counted_once_at_caps"
  , "theoremManifest_count"
  , "width384_cap_row_terms_le_e3"
  , "width384_delta_cap_all_k"
  , "width384_direct_constant_gate"
  , "width384_partition"
  , "width512_cap_row_terms_le_e3"
  , "width512_delta_cap_all_k"
  , "width512_direct_constant_gate"
  , "width512_partition"
  , "width_delta_all_k_bundle"
  , "width_partition_bundle" ]

def encodeTheoremManifest : List String → String
  | [] => ""
  | [name] => name
  | name :: rest => name ++ "," ++ encodeTheoremManifest rest

def theoremManifestEncoded : String := encodeTheoremManifest theoremManifest

theorem theoremManifest_count : theoremManifest.length = 32 := by decide

end BlindLedger.SecurityArithmetic
