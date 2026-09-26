import BlindLedger.Gate.Theorems

/-! Pins what the gate theorems rest on.  `#guard_msgs` fails this build if
    any theorem's dependency set changes, so `lake build gate_axioms` is the
    reproducible check. -/

/-- info: 'BlindLedger.Gate.verifyToken_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_iff
/-- info: 'BlindLedger.Gate.verifyToken_epoch_ge_fence' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_epoch_ge_fence
/-- info: 'BlindLedger.Gate.raiseFence_ge' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.raiseFence_ge
/-- info: 'BlindLedger.Gate.raiseFence_self' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.raiseFence_self
/-- info: 'BlindLedger.Gate.installCert_raises_fence' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.installCert_raises_fence
/-- info: 'BlindLedger.Gate.coherent_empty' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.coherent_empty
/-- info: 'BlindLedger.Gate.installCert_coherent' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.installCert_coherent
/-- info: 'BlindLedger.Gate.storeCheckpoint_coherent' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpoint_coherent
/-- info: 'BlindLedger.Gate.release_coherent' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.release_coherent
/-- info: 'BlindLedger.Gate.verifyToken_fence_eq_epoch' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_fence_eq_epoch
/-- info: 'BlindLedger.Gate.verifyToken_pinned' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_pinned
/-- info: 'BlindLedger.Gate.verifyToken_route' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_route
/-- info: 'BlindLedger.Gate.installCert_shardCount' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.installCert_shardCount
/-- info: 'BlindLedger.Gate.storeCheckpoint_keeps' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpoint_keeps
/-- info: 'BlindLedger.Gate.release_keeps' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.release_keeps
/-- info: 'BlindLedger.Gate.pinPayment_keeps' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.pinPayment_keeps
/-- info: 'BlindLedger.Gate.Step.keeps' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Step.keeps
/-- info: 'BlindLedger.Gate.Steps.keeps' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Steps.keeps
/-- info: 'BlindLedger.Gate.verifyToken_one_route' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_one_route
/-- info: 'BlindLedger.Gate.verifyToken_unforked' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_unforked
/-- info: 'BlindLedger.Gate.release_isSome' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.release_isSome
/-- info: 'BlindLedger.Gate.release_at_most_once' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.release_at_most_once
/-- info: 'BlindLedger.Gate.pathCollision_sound' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.pathCollision_sound
/-- info: 'BlindLedger.Gate.pathCollision_complete' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.pathCollision_complete
/-- info: 'BlindLedger.Gate.verifyPath_collision' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyPath_collision

def main : IO Unit := IO.println "GATE_AXIOM_CHECK=PASS"
