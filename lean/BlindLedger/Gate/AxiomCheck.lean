import BlindLedger.Gate.Theorems
import BlindLedger.Gate.MlDsa87Laws
import BlindLedger.Gate.ProducerTheorems
import BlindLedger.Gate.AnchorTheorems
import BlindLedger.Gate.CheckpointV2Theorems
import BlindLedger.Gate.StateV2
import BlindLedger.Gate.Rules.DecideLayer
import BlindLedger.Gate.ApprovalLaws
import BlindLedger.Gate.BatchTheorems
import BlindLedger.Sha3FastEq

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
/-- info: 'BlindLedger.Gate.verifyToken_grant_tenant' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_grant_tenant
open BlindLedger.Gate in
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {c : Crypto} {s : PayerState} {p : Payment} {bytes : Bytes} {t : Token},
    verifyToken c s p bytes = true → decodeToken bytes = some t →
    ∃ g ∈ s.grants, g.tenantId = t.leaf.tenantId ∧ g.tenantId = p.tenantId ∧ g.grantId = t.leaf.grantId ∧
      t.leaf.ruleVersion ∈ g.ruleVersions ∧ t.leaf.engineRelease ∈ g.engineReleases :=
  @BlindLedger.Gate.verifyToken_grant_tenant
/-- info: 'BlindLedger.Gate.verifyToken_foreign_grant' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_foreign_grant
open BlindLedger.Gate in
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {c : Crypto} {s : PayerState} {p : Payment} {bytes : Bytes} {t : Token},
    decodeToken bytes = some t →
    (∀ g ∈ s.grants, g.grantId = t.leaf.grantId → g.tenantId ≠ t.leaf.tenantId) →
    verifyToken c s p bytes = false :=
  @BlindLedger.Gate.verifyToken_foreign_grant
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
/-- info: 'BlindLedger.Gate.storedOf_wf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storedOf_wf
/-- info: 'BlindLedger.Gate.forks_comm' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.forks_comm
/-- info: 'BlindLedger.Gate.chain_no_fork' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.chain_no_fork
/-- info: 'BlindLedger.Gate.follows_twice_forks' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.follows_twice_forks
/-- info: 'BlindLedger.Gate.publishOk_sound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.publishOk_sound
/-- info: 'BlindLedger.Gate.publish_payer_local' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.publish_payer_local
/-- info: 'BlindLedger.Gate.verifyToken_slice' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_slice
/-- info: 'BlindLedger.Gate.storeCheckpoint_slice' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpoint_slice
/-- info: 'BlindLedger.Gate.firstFailure_none' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.firstFailure_none
/-- info: 'BlindLedger.Gate.anchored_binding' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.anchored_binding
/-- info: 'BlindLedger.Gate.anchored_binding_witness' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.anchored_binding_witness
/-- info: 'BlindLedger.Gate.pinInput_lines' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.pinInput_lines
/-- info: 'BlindLedger.Gate.decideAnchored_some' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decideAnchored_some
/-- info: 'BlindLedger.Gate.load_ok' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.load_ok
/-- info: 'BlindLedger.Gate.step_ok' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.step_ok
/-- info: 'BlindLedger.Gate.natBE_beNat' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.natBE_beNat
/-- info: 'BlindLedger.Gate.realCrypto_cert_not_root' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.realCrypto_cert_not_root
/-- info: 'BlindLedger.Gate.accepts_cert_not_root' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.accepts_cert_not_root
/-- info: 'BlindLedger.Gate.checkpoint_header_ne_keycert_body' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.checkpoint_header_ne_keycert_body
/-- info: 'BlindLedger.Gate.installCert_fence' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.installCert_fence
/-- info: 'BlindLedger.Gate.installCert_equivocation_signed' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.installCert_equivocation_signed
/-- info: 'BlindLedger.Gate.installCert_certs' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.installCert_certs
/-- info: 'BlindLedger.Gate.storeCheckpoint_signed' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpoint_signed
/-- info: 'BlindLedger.Gate.storeCheckpoint_not_root' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpoint_not_root
/-- info: 'BlindLedger.Gate.pCheckpointFields_wf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.pCheckpointFields_wf
/-- info: 'BlindLedger.Gate.pCheckpoint_wf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.pCheckpoint_wf
/-- info: 'BlindLedger.Gate.parse_run' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.parse_run
/-- info: 'BlindLedger.Gate.decodeAnyCheckpoint_cases' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.decodeAnyCheckpoint_cases
/-- info: 'BlindLedger.Gate.decodeCheckpoint2_wf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decodeCheckpoint2_wf
/-- info: 'BlindLedger.Gate.storedOfAny_wf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storedOfAny_wf
/-- info: 'BlindLedger.Gate.publishOkAny_sound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.publishOkAny_sound
/-- info: 'BlindLedger.Gate.publishOkAny_no_downgrade' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.publishOkAny_no_downgrade
/-- info: 'BlindLedger.Gate.storeCheckpointAny_slice' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpointAny_slice
/-- info: 'BlindLedger.Gate.storeCheckpointAny_signed' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpointAny_signed
/-- info: 'BlindLedger.Gate.storeCheckpointAny_not_root' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpointAny_not_root
/-- info: 'BlindLedger.Gate.acceptsAny_cert_not_root' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.acceptsAny_cert_not_root
/-- info: 'BlindLedger.Gate.checkpoint2_header_domain' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.checkpoint2_header_domain
/-- info: 'BlindLedger.Gate.idx_append' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.idx_append
/-- info: 'BlindLedger.Gate.checkpoint_header_ne_keycert_body_any' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.checkpoint_header_ne_keycert_body_any
/-- info: 'BlindLedger.Gate.decodeCheckpoint2_magic' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decodeCheckpoint2_magic
/-- info: 'BlindLedger.Gate.storeCheckpointAny_v1' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpointAny_v1
/-- info: 'BlindLedger.Gate.storeCheckpointAny_keeps' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpointAny_keeps
/-- info: 'BlindLedger.Gate.storeCheckpointAny_released' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpointAny_released
/-- info: 'BlindLedger.Gate.storeCheckpointAny_coherent' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpointAny_coherent
/-- info: 'BlindLedger.Gate.storeCheckpoint_any' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpoint_any
/-- info: 'BlindLedger.Gate.Step.any' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Step.any
/-- info: 'BlindLedger.Gate.Steps.any' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Steps.any
/-- info: 'BlindLedger.Gate.StepAny.keeps' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.StepAny.keeps
/-- info: 'BlindLedger.Gate.StepsAny.keeps' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.StepsAny.keeps
/-- info: 'BlindLedger.Gate.verifyToken_one_route_any' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_one_route_any
/-- info: 'BlindLedger.Gate.StepAny.new_pin' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.StepAny.new_pin
/-- info: 'BlindLedger.Gate.StepsAny.first_send' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.StepsAny.first_send
/-- info: 'BlindLedger.Gate.verifyToken_first_send_any' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_first_send_any
/-- info: 'BlindLedger.Gate.verifyToken_after_send_any' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_after_send_any
/-- info: 'BlindLedger.Gate.StepAny.released_grows' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.StepAny.released_grows
/-- info: 'BlindLedger.Gate.StepsAny.released_grows' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.StepsAny.released_grows
/-- info: 'BlindLedger.Gate.StepsAny.at_most_once' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.StepsAny.at_most_once
/-- info: 'BlindLedger.Gate.StepsAny.coherent' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.StepsAny.coherent
/-- info: 'BlindLedger.Gate.stepReg_some' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.stepReg_some
/-- info: 'BlindLedger.Gate.decodeCheckpoint_disjoint' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decodeCheckpoint_disjoint
/-- info: 'BlindLedger.Gate.decodeCheckpoint2_head' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decodeCheckpoint2_head
/-- info: 'BlindLedger.Gate.decodeCheckpoint2_encode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decodeCheckpoint2_encode
/-- info: 'BlindLedger.Gate.decodeCheckpoint2_canonical' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decodeCheckpoint2_canonical
/-- info: 'BlindLedger.Semantic.sha3_512_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.sha3_512_eq
/-- info: 'BlindLedger.Semantic.shake128_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.shake128_eq
/-- info: 'BlindLedger.Semantic.shake256_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.shake256_eq
/-- info: 'BlindLedger.Gate.Rules.carried_sets' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.carried_sets
/-- info: 'BlindLedger.Gate.Rules.carried_append' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.carried_append
/-- info: 'BlindLedger.Gate.Rules.replay_addsOf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.replay_addsOf
/-- info: 'BlindLedger.Gate.Rules.carried_sealB' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.carried_sealB
/-- info: 'BlindLedger.Gate.Rules.carried_resend_held' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.carried_resend_held
/-- info: 'BlindLedger.Gate.Rules.settleFreeInc_carried' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.settleFreeInc_carried
/-- info: 'BlindLedger.Gate.decide_ok' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decide_ok
/-- info: 'BlindLedger.Gate.decide_run_fold' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decide_run_fold
/-- info: 'BlindLedger.Gate.loadAdds_binds' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.loadAdds_binds
/-- info: 'BlindLedger.Gate.Approval.decodeMoves_canonical' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Approval.decodeMoves_canonical
/-- info: 'BlindLedger.Gate.Approval.decodeMoves_lineDigest' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Approval.decodeMoves_lineDigest
/-- info: 'BlindLedger.Gate.Approval.decodeMoves_ascending' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Approval.decodeMoves_ascending
/-- info: 'BlindLedger.Gate.Approval.decodeApproval_canonical' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Approval.decodeApproval_canonical
/-- info: 'BlindLedger.Gate.certsInstalled_mem' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.certsInstalled_mem
/-- info: 'BlindLedger.Gate.frameOrdered_nodup' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.frameOrdered_nodup
/-- info: 'BlindLedger.Gate.releaseBatch_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.releaseBatch_eq
/-- info: 'BlindLedger.Gate.releaseBatch_spec' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.releaseBatch_spec
/-- info: 'BlindLedger.Gate.releaseBatch_isolation' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.releaseBatch_isolation
/-- info: 'BlindLedger.Gate.releaseBatch_cp_isolation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.releaseBatch_cp_isolation
/-- info: 'BlindLedger.Gate.releaseBatch_accept_verified' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.releaseBatch_accept_verified
/-- info: 'BlindLedger.Gate.releaseBatch_once' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.releaseBatch_once
/-- info: 'BlindLedger.Gate.releaseBatch_grant_tenant' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.releaseBatch_grant_tenant
open BlindLedger.Gate in
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {c : Crypto} {r : ReleaseRun} {items : List Item} {i : Nat} {it : Item},
    items[i]? = some it → (releaseBatch c r items)[i]? = some none →
    ∃ t, decodeToken it.token = some t ∧ ∃ g ∈ r.grants,
      g.tenantId = it.payment.tenantId ∧ g.tenantId = t.leaf.tenantId ∧ g.grantId = t.leaf.grantId :=
  @BlindLedger.Gate.releaseBatch_grant_tenant
/-- info: 'BlindLedger.Gate.pathOf_verifies' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.pathOf_verifies
/-- info: 'BlindLedger.Gate.publishOkTree_sound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.publishOkTree_sound
/-- info: 'BlindLedger.Gate.publishOkTree_complete' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.publishOkTree_complete
/-- info: 'BlindLedger.Gate.publishOkTree_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.publishOkTree_eq
/-- info: 'BlindLedger.Gate.publishOkTree_no_downgrade' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.publishOkTree_no_downgrade
open BlindLedger.Gate in
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {rootPk cert new : Bytes} {last : Option Bytes} {tokens : List Bytes},
    publishOkTree rootPk cert last new tokens = true → publishOkAny rootPk cert last new tokens = true :=
  @BlindLedger.Gate.publishOkTree_sound
open BlindLedger.Gate in
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {rootPk cert new : Bytes} {last : Option Bytes} {tokens : List Bytes},
    publishOkAny rootPk cert last new tokens = true →
    publishOkTree rootPk cert last new tokens = true ∨
      ∃ x y, publishCollision tokens = some (x, y) ∧ x ≠ y ∧ sha3 x = sha3 y :=
  @BlindLedger.Gate.publishOkTree_complete
open BlindLedger.Gate in
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {rootPk cert new : Bytes} {last : Option Bytes} {tokens : List Bytes},
    publishCollision tokens = none →
    publishOkTree rootPk cert last new tokens = publishOkAny rootPk cert last new tokens :=
  @BlindLedger.Gate.publishOkTree_eq
open BlindLedger.Gate in
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {rootPk cert new : Bytes} {last : Option Bytes} {tokens : List Bytes} {b : Bytes},
    publishOkTree rootPk cert last new tokens = true → last = some b → isV2 b = true → isV2 new = true :=
  @BlindLedger.Gate.publishOkTree_no_downgrade

