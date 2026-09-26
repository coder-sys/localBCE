import BlindLedger.Gate.Theorems

/-! Pins what the gate theorems rest on.  `#guard_msgs` fails this build if
    any theorem's dependency set changes, so `lake build gate_axioms` is the
    reproducible check. -/

#print axioms BlindLedger.Gate.verifyToken_iff
#print axioms BlindLedger.Gate.verifyToken_epoch_ge_fence
#print axioms BlindLedger.Gate.raiseFence_ge
#print axioms BlindLedger.Gate.raiseFence_self
#print axioms BlindLedger.Gate.installCert_raises_fence
#print axioms BlindLedger.Gate.coherent_empty
#print axioms BlindLedger.Gate.installCert_coherent
#print axioms BlindLedger.Gate.storeCheckpoint_coherent
#print axioms BlindLedger.Gate.release_coherent
#print axioms BlindLedger.Gate.verifyToken_fence_eq_epoch
#print axioms BlindLedger.Gate.release_isSome
#print axioms BlindLedger.Gate.release_at_most_once
#print axioms BlindLedger.Gate.pathCollision_sound
#print axioms BlindLedger.Gate.pathCollision_complete
#print axioms BlindLedger.Gate.verifyPath_collision

def main : IO Unit := IO.println "GATE_AXIOM_CHECK=PASS"
