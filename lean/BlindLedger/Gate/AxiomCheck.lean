import BlindLedger.Gate.Theorems
import BlindLedger.Gate.MlDsa87Laws

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
/-- info: 'BlindLedger.Gate.send_keeps' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.send_keeps
/-- info: 'BlindLedger.Gate.Step.keeps' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Step.keeps
/-- info: 'BlindLedger.Gate.Steps.keeps' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Steps.keeps
/-- info: 'BlindLedger.Gate.verifyToken_one_route' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_one_route
/-- info: 'BlindLedger.Gate.send_pins' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.send_pins
/-- info: 'BlindLedger.Gate.send_new' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.send_new
/-- info: 'BlindLedger.Gate.Step.new_pin' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Step.new_pin
/-- info: 'BlindLedger.Gate.Steps.first_send' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Steps.first_send
/-- info: 'BlindLedger.Gate.verifyToken_first_send' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_first_send
/-- info: 'BlindLedger.Gate.verifyToken_after_send' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_after_send
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
/-- info: 'BlindLedger.Gate.Step.released_grows' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Step.released_grows
/-- info: 'BlindLedger.Gate.Steps.released_grows' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Steps.released_grows
/-- info: 'BlindLedger.Gate.Steps.at_most_once' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Steps.at_most_once
/-- info: 'BlindLedger.Gate.installCert_equivocation' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.installCert_equivocation
/-- info: 'BlindLedger.Gate.Steps.coherent' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Steps.coherent
/-- info: 'BlindLedger.Gate.MlDsa87.rejNttFrom_size' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.rejNttFrom_size
/-- info: 'BlindLedger.Gate.MlDsa87.rejNttFrom_append' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.rejNttFrom_append
/-- info: 'BlindLedger.Gate.MlDsa87.sampleInBallFrom_size' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.sampleInBallFrom_size
/-- info: 'BlindLedger.Gate.MlDsa87.sampleInBallFrom_append' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.sampleInBallFrom_append
/-- info: 'BlindLedger.Gate.MlDsa87.verify_rejects_sampleInBall_none' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.verify_rejects_sampleInBall_none
/-- info: 'BlindLedger.Gate.MlDsa87.verify_rejects_rejNtt_none' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.verify_rejects_rejNtt_none
