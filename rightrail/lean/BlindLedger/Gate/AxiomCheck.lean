import BlindLedger.Gate.Rules.Run
import BlindLedger.Gate.Theorems
import BlindLedger.Gate.MlDsa87Laws
import BlindLedger.Gate.ProducerTheorems
import BlindLedger.Gate.AnchorTheorems
import BlindLedger.Gate.CheckpointTheorems
import BlindLedger.Gate.Rules.DecideLayer
import BlindLedger.Gate.ParseLaws
import BlindLedger.Gate.BatchTheorems
import BlindLedger.Sha3FastEq
import BlindLedger.Gate.Engine.FrameLaws
import BlindLedger.Gate.Keyset
import BlindLedger.Gate.AuthorityLaws
import BlindLedger.Gate.Rules.Bypass
import BlindLedger.Gate.SnapshotV2
import BlindLedger.Gate.Scoped
import BlindLedger.Gate.Consume
import BlindLedger.Gate.PublishFastEq
import BlindLedger.Gate.Flat.Theorems
import BlindLedger.Gate.Flat.ChunkTheorems
import BlindLedger.Gate.Flat.StoreTheorems
import BlindLedger.Gate.Flat.StoreTombs
import BlindLedger.Gate.Flat.StoreIndex
import BlindLedger.Gate.Flat.ChunkIoWin
import BlindLedger.Gate.Flat.Signed
import BlindLedger.Gate.Flat.PayTheorems
import BlindLedger.Gate.Flat.RowsBudget
import BlindLedger.Gate.Custody
import BlindLedger.Gate.Rules.EmitLaws
import BlindLedger.Gate.Engine3.Frame3
import BlindLedger.Gate.Engine3.AdmitB
import BlindLedger.Gate.FactCodec
import BlindLedger.Gate.WitnessTheorems
import BlindLedger.Gate.FactRegistry
import BlindLedger.Gate.Obligations.Agree
import BlindLedger.Gate.Obligations.RequestMap
import BlindLedger.Gate.Cosign.CodecLaws
import BlindLedger.Gate.Cosign.Theorems

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
/-- info: 'BlindLedger.Gate.verifyToken_transfer' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_transfer
open BlindLedger.Gate in
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {c : Crypto} {s : PayerState} {p : Payment} {bytes : Bytes},
    verifyToken c s p bytes = true →
    ∃ t, decodeToken bytes = some t ∧ t.leaf.outcome = .ALLOW ∧ t.leaf.authority = .TRANSFER :=
  @BlindLedger.Gate.verifyToken_transfer
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
/-- info: 'BlindLedger.Gate.verifyToken_unforked' depends on axioms: [propext, Classical.choice, Quot.sound] -/
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
/-- info: 'BlindLedger.Gate.MlDsa87.unpackF_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.unpackF_eq
/-- info: 'BlindLedger.Gate.storedOf_wf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storedOf_wf
/-- info: 'BlindLedger.Gate.forks_comm' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.forks_comm
/-- info: 'BlindLedger.Gate.chain_no_fork' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.chain_no_fork
/-- info: 'BlindLedger.Gate.follows_twice_forks' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.follows_twice_forks
/-- info: 'BlindLedger.Gate.follows_counter' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.follows_counter
/-- info: 'BlindLedger.Gate.follows_none_counter' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.follows_none_counter
/-- info: 'BlindLedger.Gate.chainOk_counter' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.chainOk_counter
/-- info: 'BlindLedger.Gate.publishOk_counter' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.publishOk_counter
/-- info: 'BlindLedger.Gate.storeCheckpoint_counter_fork' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpoint_counter_fork
/-- info: 'BlindLedger.Gate.publishOk_sound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.publishOk_sound
/-- info: 'BlindLedger.Gate.publish_payer_local' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.publish_payer_local
/-- info: 'BlindLedger.Gate.verifyToken_slice' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.verifyToken_slice
/-- info: 'BlindLedger.Gate.storeCheckpoint_slice' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpoint_slice
/-- info: 'BlindLedger.Gate.blocked_shard' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.blocked_shard
/-- info: 'BlindLedger.Gate.forks_candidate' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.forks_candidate
/-- info: 'BlindLedger.Gate.storeCheckpoint_candidates' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpoint_candidates
/-- info: 'BlindLedger.Gate.storeCheckpoint_pinned' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.storeCheckpoint_pinned
/-- info: 'BlindLedger.Gate.release_after_fork' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.release_after_fork
/-- info: 'BlindLedger.Gate.firstFailure_none' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.firstFailure_none
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
/-- info: 'BlindLedger.Gate.idx_append' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.idx_append
/-- info: 'BlindLedger.Gate.stepReg_some' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.stepReg_some
/-- info: 'BlindLedger.Gate.decodeCheckpoint_tail' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decodeCheckpoint_tail
/-- info: 'BlindLedger.Gate.decodeCheckpoint_encode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decodeCheckpoint_encode
/-- info: 'BlindLedger.Gate.decodeCheckpoint_canonical' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decodeCheckpoint_canonical
/-- info: 'BlindLedger.Semantic.sha3_512_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.sha3_512_eq
/-- info: 'BlindLedger.Semantic.shake128_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.shake128_eq
/-- info: 'BlindLedger.Semantic.shake256_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.shake256_eq
/-- info: 'BlindLedger.Semantic.Quick.keccakF_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.Quick.keccakF_eq
/-- info: 'BlindLedger.Semantic.sha3_256Quick_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.sha3_256Quick_eq
/-- info: 'BlindLedger.Semantic.sha3_512Quick_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.sha3_512Quick_eq
/-- info: 'BlindLedger.Semantic.shake128Quick_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.shake128Quick_eq
/-- info: 'BlindLedger.Semantic.shake256Quick_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.shake256Quick_eq
/-- info: 'BlindLedger.Gate.Engine3.sha3_512Into_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Engine3.sha3_512Into_eq
/-- info: 'BlindLedger.Gate.Engine3.sha3_512Into_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Engine3.sha3_512Into_spec
/-- info: 'BlindLedger.Gate.Engine3.hD_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Engine3.hD_eq
/-- info: 'BlindLedger.Gate.Engine3.Run.admitB_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Engine3.Run.admitB_eq
/-- info: 'BlindLedger.Gate.Engine3.Run.admitB_eq_needs_ra' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Engine3.Run.admitB_eq_needs_ra
/-- info: 'BlindLedger.Gate.Rules.carried_sets' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.carried_sets
/-- info: 'BlindLedger.Gate.Rules.carried_append' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.carried_append
/-- info: 'BlindLedger.Gate.Rules.replay_addsOf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.replay_addsOf
/-- info: 'BlindLedger.Gate.Rules.carried_resend_held' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.carried_resend_held
/-- info: 'BlindLedger.Gate.decide_ok' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decide_ok
/-- info: 'BlindLedger.Gate.decide_run_fold' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decide_run_fold
/-- info: 'BlindLedger.Gate.loadAdds_binds' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.loadAdds_binds
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
open BlindLedger.Gate in
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {rootPk cert new : Bytes} {last : Option Bytes} {tokens : List Bytes} {tpm : Nat},
    publishOkTree rootPk cert last new tokens tpm = true → publishOk rootPk cert last new tokens tpm = true :=
  @BlindLedger.Gate.publishOkTree_sound
open BlindLedger.Gate in
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {rootPk cert new : Bytes} {last : Option Bytes} {tokens : List Bytes} {tpm : Nat},
    publishOk rootPk cert last new tokens tpm = true →
    publishOkTree rootPk cert last new tokens tpm = true ∨
      ∃ x y, publishCollision tokens = some (x, y) ∧ x ≠ y ∧ sha3 x = sha3 y :=
  @BlindLedger.Gate.publishOkTree_complete
open BlindLedger.Gate in
/-- The statement is pinned: changing the theorem must change this pin in the same commit. -/
example : ∀ {rootPk cert new : Bytes} {last : Option Bytes} {tokens : List Bytes} {tpm : Nat},
    publishCollision tokens = none →
    publishOkTree rootPk cert last new tokens tpm = publishOk rootPk cert last new tokens tpm :=
  @BlindLedger.Gate.publishOkTree_eq

-- The resident theorems and the S0-S3 statements (all proved; no sorryAx).
/-- info: 'BlindLedger.Gate.Engine.OneProc.splitFrames_join' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Engine.OneProc.splitFrames_join
/-- info: 'BlindLedger.Gate.Engine.OneProc.splitFrames_sound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Engine.OneProc.splitFrames_sound















/-- info: 'BlindLedger.Gate.Keyset.decode_encode' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.decode_encode
/-- info: 'BlindLedger.Gate.Keyset.admitSucc_rejects_old' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitSucc_rejects_old
/-- info: 'BlindLedger.Gate.Keyset.succ_revoked_dead' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.succ_revoked_dead
/-- info: 'BlindLedger.Gate.Keyset.admitSucc_quorum' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitSucc_quorum
/-- info: 'BlindLedger.Gate.Keyset.admitSucc_possession' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitSucc_possession
/-- info: 'BlindLedger.Gate.Keyset.admitSucc_expired' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitSucc_expired
/-- info: 'BlindLedger.Gate.Keyset.admitChain_pinned' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitChain_pinned
/-- info: 'BlindLedger.Gate.Keyset.admitFold_pinned' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitFold_pinned
/-- info: 'BlindLedger.Gate.Keyset.admitFold_persists' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitFold_persists
/-- info: 'BlindLedger.Gate.Keyset.admitFold_revoked_dead' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitFold_revoked_dead
/-- info: 'BlindLedger.Gate.Keyset.admitHead_sound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitHead_sound
/-- info: 'BlindLedger.Gate.Keyset.admitHead_refuses' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitHead_refuses
/-- info: 'BlindLedger.Gate.Keyset.admitHead_expired' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitHead_expired
/-- info: 'BlindLedger.Gate.Keyset.admitHead_init' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitHead_init
/-- info: 'BlindLedger.Gate.Keyset.admitHead_extend' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitHead_extend
/-- info: 'BlindLedger.Gate.Keyset.admitHead_live' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.admitHead_live
/-- info: 'BlindLedger.Gate.Keyset.succOk_overlap' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.succOk_overlap
/-- info: 'BlindLedger.Gate.Keyset.chain_crosses_year_end' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.chain_crosses_year_end
/-- info: 'BlindLedger.Gate.Keyset.reinit_some' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.reinit_some
/-- info: 'BlindLedger.Gate.Keyset.reinit_sound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.reinit_sound
/-- info: 'BlindLedger.Gate.Keyset.reinit_from' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.reinit_from
/-- info: 'BlindLedger.Gate.Keyset.reinit_no_replay' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.reinit_no_replay
/-- info: 'BlindLedger.Gate.Keyset.inband_reinit_same_epoch' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.inband_reinit_same_epoch
/-- info: 'BlindLedger.Gate.Keyset.inband_reinit_keys_live' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.inband_reinit_keys_live
/-- info: 'BlindLedger.Gate.Keyset.reinit_never_unrevokes' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.reinit_never_unrevokes
/-- info: 'BlindLedger.Gate.Keyset.refused_run_persists_nothing' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Keyset.refused_run_persists_nothing
/-- info: 'BlindLedger.Gate.SnapshotV2.decode_encode' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.decode_encode
/-- info: 'BlindLedger.Gate.SnapshotV2.decodeMan_encode' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.decodeMan_encode
/-- info: 'BlindLedger.Gate.SnapshotV2.sigMsg_pre_inj' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.sigMsg_pre_inj
/-- info: 'BlindLedger.Gate.SnapshotV2.attach_sound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.attach_sound
/-- info: 'BlindLedger.Gate.SnapshotV2.attach_expired' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.attach_expired
/-- info: 'BlindLedger.Gate.SnapshotV2.attachChain_sound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.attachChain_sound
/-- info: 'BlindLedger.Gate.SnapshotV2.attachChain_rollback' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.attachChain_rollback
/-- info: 'BlindLedger.Gate.SnapshotV2.attachChain_refuses' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.attachChain_refuses
/-- info: 'BlindLedger.Gate.SnapshotV2.attachChain_live' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.attachChain_live
/-- info: 'BlindLedger.Gate.publishFrameB_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.publishFrameB_eq
/-- info: 'BlindLedger.Gate.decodeKeyCert_signed' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.decodeKeyCert_signed
/-- info: 'BlindLedger.Gate.accepts_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.accepts_eq
/-- info: 'BlindLedger.Gate.publishOkTreeB_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.publishOkTreeB_eq
/-- info: 'BlindLedger.Gate.SnapshotV2.attachChain_binds' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.attachChain_binds
/-- info: 'BlindLedger.Gate.Scoped.self_never_satisfies' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.self_never_satisfies
/-- info: 'BlindLedger.Gate.Scoped.other_kind_not_counts' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.other_kind_not_counts
/-- info: 'BlindLedger.Gate.Scoped.le_expDay_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.le_expDay_iff
/-- info: 'BlindLedger.Gate.Scoped.live_iff_counts' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.live_iff_counts
/-- info: 'BlindLedger.Gate.Scoped.rules_eq' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.rules_eq
/-- info: 'BlindLedger.Gate.Scoped.counts_lengthen' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.counts_lengthen
/-- info: 'BlindLedger.Gate.Scoped.usable_tightens' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.usable_tightens
/-- info: 'BlindLedger.Gate.Scoped.allow_live' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.allow_live
/-- info: 'BlindLedger.Gate.Scoped.allow_tightens' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.allow_tightens
/-- info: 'BlindLedger.Gate.Scoped.uncounted_reviews' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.uncounted_reviews
/-- info: 'BlindLedger.Gate.Scoped.uncounted_not_certain' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.uncounted_not_certain
/-- info: 'BlindLedger.Gate.Scoped.self_reviews_not_holds' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.self_reviews_not_holds
/-- info: 'BlindLedger.Gate.Scoped.window_no_resurrect' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.window_no_resurrect
/-- info: 'BlindLedger.Gate.Scoped.allow_attached' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Scoped.allow_attached
-- History index: the model's statements, then the fast code's equality with the model.
/-- info: 'BlindLedger.Gate.Flat.decideBatchIdx_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.decideBatchIdx_eq
/-- info: 'BlindLedger.Gate.Flat.cap_hold' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.cap_hold
/-- info: 'BlindLedger.Gate.Flat.decide_perCore' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.decide_perCore
/-- info: 'BlindLedger.Gate.Flat.core_hold' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.core_hold
/-- info: 'BlindLedger.Gate.Flat.released_perCore' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.released_perCore
/-- info: 'BlindLedger.Gate.Flat.Store.decideFast_perCore' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.decideFast_perCore
/-- info: 'BlindLedger.Gate.Flat.cappedWith_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.cappedWith_eq
/-- info: 'BlindLedger.Gate.Flat.feed_cap_hold' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.feed_cap_hold
/-- info: 'BlindLedger.Gate.Flat.apply_inv' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.apply_inv
/-- info: 'BlindLedger.Gate.Flat.EntryA.push_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.EntryA.push_eq
/-- info: 'BlindLedger.Gate.Flat.Chunk.decChunk_encChunk' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Chunk.decChunk_encChunk
/-- info: 'BlindLedger.Gate.Flat.Chunk.decChunk_canon' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Chunk.decChunk_canon
/-- info: 'BlindLedger.Gate.Flat.Chunk.decChunk_wf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Chunk.decChunk_wf
/-- info: 'BlindLedger.Gate.Flat.Chunk.empty_inv' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Chunk.empty_inv
/-- info: 'BlindLedger.Gate.Flat.Chunk.set_inv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Chunk.set_inv
/-- info: 'BlindLedger.Gate.Flat.Chunk.root_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Chunk.root_eq
/-- info: 'BlindLedger.Gate.Flat.Chunk.root_binds' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Chunk.root_binds
/-- info: 'BlindLedger.Gate.Flat.Store.Dir.sound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.Dir.sound
/-- info: 'BlindLedger.Gate.Flat.Store.alt_alt' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.alt_alt
/-- info: 'BlindLedger.Gate.Flat.Store.cls_alt' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.cls_alt
/-- info: 'BlindLedger.Gate.Flat.Store.cls_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.cls_eq
/-- info: 'BlindLedger.Gate.Flat.Store.put_count' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.put_count
/-- info: 'BlindLedger.Gate.Flat.Store.erase_count' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.erase_count
/-- info: 'BlindLedger.Gate.Flat.Store.drop_count' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.drop_count
/-- info: 'BlindLedger.Gate.Flat.Store.ins_count' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.ins_count
/-- info: 'BlindLedger.Gate.Flat.Store.rebuild_inv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.rebuild_inv
/-- info: 'BlindLedger.Gate.Flat.Store.lookup_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.lookup_eq
/-- info: 'BlindLedger.Gate.Flat.Store.view_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.view_eq
/-- info: 'BlindLedger.Gate.Flat.Store.hits_one' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.hits_one
/-- info: 'BlindLedger.Gate.Flat.Store.read_bound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.read_bound
/-- info: 'BlindLedger.Gate.Flat.Store.inWin_of' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.inWin_of
/-- info: 'BlindLedger.Gate.Flat.Store.hits_win' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.hits_win
/-- info: 'BlindLedger.Gate.Flat.Store.hits_win_inv' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.hits_win_inv
/-- info: 'BlindLedger.Gate.Flat.Store.pagesIn_le' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.pagesIn_le
/-- info: 'BlindLedger.Gate.Flat.Store.lookup_pages' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.lookup_pages
/-- info: 'BlindLedger.Gate.Flat.Store.marks_index' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.marks_index
/-- info: 'BlindLedger.Gate.Flat.Store.pages_slice' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.pages_slice
/-- info: 'BlindLedger.Gate.Flat.Store.rows_mid' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.rows_mid
/-- info: 'BlindLedger.Gate.Flat.Store.fetchFast_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.fetchFast_eq
/-- info: 'BlindLedger.Gate.Flat.Store.fetchFast_bad' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.fetchFast_bad
/-- info: 'BlindLedger.Gate.Flat.Store.decideFast_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.decideFast_eq
/-- info: 'BlindLedger.Gate.Flat.Store.pagesRead_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.pagesRead_le
/-- info: 'BlindLedger.Gate.Flat.Store.apply_inv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.apply_inv
/-- info: 'BlindLedger.Gate.Flat.Store.seal_inv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.seal_inv
/-- info: 'BlindLedger.Gate.Flat.Store.reclaim_inv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.reclaim_inv
/-- info: 'BlindLedger.Gate.Flat.Store.install_inv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.install_inv
/-- info: 'BlindLedger.Gate.Flat.Store.regrow_inv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.regrow_inv
/-- info: 'BlindLedger.Gate.Flat.Store.regrow_lookup' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.regrow_lookup
/-- info: 'BlindLedger.Gate.Flat.Store.regrow_view' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.regrow_view
/-- info: 'BlindLedger.Gate.Flat.Store.load_inv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.load_inv
/-- info: 'BlindLedger.Gate.Flat.Store.decMeta2_enc' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.decMeta2_enc
/-- info: 'BlindLedger.Gate.Flat.Store.chainStepR_binds' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.chainStepR_binds
/-- info: 'BlindLedger.Gate.Flat.Store.batchDigest_binds' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.batchDigest_binds
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.authFollows_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.authFollows_iff
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.authFollows_trans' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.authFollows_trans
/-- info: 'BlindLedger.Gate.Flat.Store.decM_encM' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.decM_encM
/-- info: 'BlindLedger.Gate.Flat.Store.isDead_deadOf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.isDead_deadOf
/-- info: 'BlindLedger.Gate.Flat.Store.book_init' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.book_init
/-- info: 'BlindLedger.Gate.Flat.Store.book_congr' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.book_congr
/-- info: 'BlindLedger.Gate.Flat.Store.apply_book' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.apply_book
/-- info: 'BlindLedger.Gate.Flat.Store.place_book' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.place_book
/-- info: 'BlindLedger.Gate.Flat.Store.reclaim_book' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.reclaim_book
/-- info: 'BlindLedger.Gate.Flat.Store.install_book' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.install_book
/-- info: 'BlindLedger.Gate.Flat.Store.finv_congr' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.finv_congr
/-- info: 'BlindLedger.Gate.Flat.Store.load_book' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.load_book
/-- info: 'BlindLedger.Gate.Flat.Store.sortRows_sorted' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.sortRows_sorted
/-- info: 'BlindLedger.Gate.Flat.Store.entryOf_wf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Store.entryOf_wf
/-- info: 'BlindLedger.Gate.Flat.work_le' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.work_le
/-- info: 'BlindLedger.Gate.Flat.entry_codec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.entry_codec
/-- info: 'BlindLedger.Gate.SnapshotV2.admitBatchHead_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.admitBatchHead_eq
/-- info: 'BlindLedger.Gate.SnapshotV2.attachAt_chain' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.attachAt_chain
/-- info: 'BlindLedger.Gate.SnapshotV2.chain_attachAt' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.chain_attachAt
/-- info: 'BlindLedger.Gate.SnapshotV2.attachAt_sound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.SnapshotV2.attachAt_sound
/-- info: 'BlindLedger.Gate.Consume.allow_signed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Consume.allow_signed
/-- info: 'BlindLedger.Gate.Consume.cause_counted_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Consume.cause_counted_iff
/-- info: 'BlindLedger.Gate.Consume.uncounted_signed' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Consume.uncounted_signed
/-- info: 'BlindLedger.Gate.Consume.uncounted_not_certain_signed' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Consume.uncounted_not_certain_signed
/-- info: 'BlindLedger.Gate.Consume.decideSigned_total' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Consume.decideSigned_total
/-- info: 'BlindLedger.Gate.Consume.counted_good' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Consume.counted_good
/-- info: 'BlindLedger.Gate.Consume.readAll_ratchet' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Consume.readAll_ratchet
/-- info: 'BlindLedger.Gate.Rules.Fast.Ix.allow_ok' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Fast.Ix.allow_ok
/-- info: 'BlindLedger.Gate.Flat.rules_carried' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.rules_carried
/-- info: 'BlindLedger.Gate.Flat.readIdx_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.readIdx_eq
/-- info: 'BlindLedger.Gate.Flat.fetched_feeds' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.fetched_feeds
/-- info: 'BlindLedger.Gate.Flat.decideSignedIdx_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.decideSignedIdx_eq
/-- info: 'BlindLedger.Gate.Flat.allow_signed_idx' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.allow_signed_idx
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.lebS_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.lebS_eq
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.lebK_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.lebK_eq
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.lebPush_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.lebPush_eq
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.skeyB_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.skeyB_eq
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.encBodyB_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.encBodyB_eq
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.encRowB_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.encRowB_eq
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.candsA_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.candsA_eq
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.killFast_get' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.killFast_get
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.killFast_isDead' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.killFast_isDead
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.pushBE8_eq' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.pushBE8_eq
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.pagesN_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.pagesN_eq
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.rows_fold' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.rows_fold
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.encFast_eq_P' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.encFast_eq_P
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.fm_fold' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.fm_fold
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.mk_fold' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.mk_fold
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.pg_flatten' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.pg_flatten
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.pgAt_pad' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.pgAt_pad
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.Q_data' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.Q_data
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.Q_phash' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.Q_phash
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.Q_md' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.Q_md
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.encFast_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.encFast_spec
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.partPoint_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.partPoint_eq
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.Q_ix' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.Q_ix
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.window_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.window_spec
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.scan_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.scan_spec
/-- info: 'BlindLedger.Gate.Flat.ChunkIo.readHits_pure' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ChunkIo.readHits_pure
/-- info: 'BlindLedger.Gate.Rules.Run.leafOutcome_allow' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.leafOutcome_allow
/-- info: 'BlindLedger.Gate.Rules.Run.natStr_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.natStr_eq
/-- info: 'BlindLedger.Gate.Flat.pay_line' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.pay_line
/-- info: 'BlindLedger.Gate.Flat.leafReasons_codes' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.leafReasons_codes
/-- info: 'BlindLedger.Gate.Flat.pay_capped' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.pay_capped
/-- info: 'BlindLedger.Gate.Flat.pay_line_part' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.pay_line_part
/-- info: 'BlindLedger.Gate.Flat.leafReasons_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.leafReasons_le
/-- info: 'BlindLedger.Gate.Flat.pay_codes_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.pay_codes_le
/-- info: 'BlindLedger.Gate.Flat.pay_codes_le_part' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.pay_codes_le_part
/-- info: 'BlindLedger.Gate.Flat.feedBits_inv' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.feedBits_inv
/-- info: 'BlindLedger.Gate.Flat.ix_may_sound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.ix_may_sound
/-- info: 'BlindLedger.Gate.Flat.decideFetched_may' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.decideFetched_may
/-- info: 'BlindLedger.Gate.Flat.pay_codes_le_all' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.pay_codes_le_all
/-- info: 'BlindLedger.Gate.Flat.leafReasons_filter' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.leafReasons_filter
/-- info: 'BlindLedger.Gate.Flat.leafReasons_group' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.leafReasons_group
/-- info: 'BlindLedger.Gate.Flat.Rows.layout_mask_may' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.layout_mask_may
/-- info: 'BlindLedger.Gate.Flat.Rows.cut_mask_may' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.cut_mask_may
/-- info: 'BlindLedger.Gate.Flat.Rows.rows_leaf_may' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.rows_leaf_may
/-- info: 'BlindLedger.Gate.Flat.Rows.rows_leaf_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.rows_leaf_le
/-- info: 'BlindLedger.Gate.Flat.Rows.leafBits_testBit' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.leafBits_testBit
/-- info: 'BlindLedger.Gate.Flat.Rows.leafBits_lt' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.leafBits_lt
/-- info: 'BlindLedger.Gate.Flat.Rows.leafIn_reasons' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.leafIn_reasons
/-- info: 'BlindLedger.Gate.Flat.Rows.leafIn_bits_may' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.leafIn_bits_may
/-- info: 'BlindLedger.Gate.Flat.Rows.has_fold_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.has_fold_iff
/-- info: 'BlindLedger.Gate.Flat.Rows.payFlags_snd' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.payFlags_snd
/-- info: 'BlindLedger.Gate.Flat.Rows.payFlagsC_snd' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.payFlagsC_snd
/-- info: 'BlindLedger.Gate.Flat.Rows.payFlags_msk' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.payFlags_msk
/-- info: 'BlindLedger.Gate.Flat.Rows.payFlagsC_msk' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.payFlagsC_msk
/-- info: 'BlindLedger.Gate.Flat.Rows.payFlags_leaf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.Rows.payFlags_leaf
/-- info: 'BlindLedger.Gate.Flat.feedsOf_inv' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.feedsOf_inv
/-- info: 'BlindLedger.Gate.Flat.allow_fresh' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.allow_fresh
/-- info: 'BlindLedger.Gate.Flat.decideAll_allow_fresh' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.decideAll_allow_fresh
/-- info: 'BlindLedger.Gate.Flat.leaf_allow_fresh' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.leaf_allow_fresh
/-- info: 'BlindLedger.Gate.Flat.reqsOk_empty' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.reqsOk_empty
/-- info: 'BlindLedger.Gate.Flat.addReq_ok' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.addReq_ok
/-- info: 'BlindLedger.Gate.Flat.linesOf_pay' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.linesOf_pay
/-- info: 'BlindLedger.Gate.Flat.lines_req' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.lines_req
/-- info: 'BlindLedger.Gate.Flat.pay_req' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.pay_req
/-- info: 'BlindLedger.Gate.custodyStep_behind' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.custodyStep_behind
/-- info: 'BlindLedger.Gate.custodyStep_proceeds' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.custodyStep_proceeds
/-- info: 'BlindLedger.Gate.seal_crash_resumes' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.seal_crash_resumes
/-- info: 'BlindLedger.Gate.Flat.contextPre_inj' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.contextPre_inj
/-- info: 'BlindLedger.Gate.Flat.paymentPre_inj' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.paymentPre_inj
/-- info: 'BlindLedger.Gate.Flat.inputV6Pre_inj' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.inputV6Pre_inj
/-- info: 'BlindLedger.Gate.Flat.batchInputPre_inj' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.batchInputPre_inj
/-- info: 'BlindLedger.Gate.custodyStep_unwritten' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.custodyStep_unwritten
/-- info: 'BlindLedger.Gate.custodyStep_catchUp_unwritten' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.custodyStep_catchUp_unwritten
/-- info: 'BlindLedger.Gate.custodyOf_unreadable' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.custodyOf_unreadable
/-- info: 'BlindLedger.Gate.first_seal_crash_heals' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.first_seal_crash_heals
/-- info: 'BlindLedger.Gate.counter_one_once' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.counter_one_once
/-- info: 'BlindLedger.Gate.Rules.Run.emit_shape' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.emit_shape
/-- info: 'BlindLedger.Gate.Rules.Run.emit_authority' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.emit_authority
/-- info: 'BlindLedger.Gate.Rules.Run.emit_authority_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.emit_authority_le
/-- info: 'BlindLedger.Gate.Rules.Run.no_transfer_without_grant' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.no_transfer_without_grant
/-- info: 'BlindLedger.Gate.Rules.Run.observe_never_transfer' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.observe_never_transfer
/-- info: 'BlindLedger.Gate.Rules.Run.hold_within_grant' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.hold_within_grant
/-- info: 'BlindLedger.Gate.Rules.Run.no_lines_not_allow' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.no_lines_not_allow
/-- info: 'BlindLedger.Gate.Rules.Run.transfer_allow_is_rules' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.transfer_allow_is_rules
/-- info: 'BlindLedger.Gate.Rules.Run.hold_allow_limited' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.hold_allow_limited
/-- info: 'BlindLedger.Gate.Rules.Run.lookup_limOf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.lookup_limOf
/-- info: 'BlindLedger.Gate.Rules.Run.limitedPay_redo' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.limitedPay_redo
/-- info: 'BlindLedger.Gate.Rules.Run.redo_never_lifted' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.redo_never_lifted
/-- info: 'BlindLedger.Gate.Rules.Run.limOf_sound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.limOf_sound
/-- info: 'BlindLedger.Gate.Rules.Run.bypass_attributed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.bypass_attributed
/-- info: 'BlindLedger.Gate.Rules.Run.effFloor_ge' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.effFloor_ge
/-- info: 'BlindLedger.Gate.Rules.Run.floor_monotone' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.floor_monotone
/-- info: 'BlindLedger.Gate.Rules.Run.admit_keyset_floor' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.Run.admit_keyset_floor
/-- info: 'BlindLedger.Gate.Engine3.Run.limB_sound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Engine3.Run.limB_sound
/-- info: 'BlindLedger.Gate.Flat.addReq_bytes' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.addReq_bytes
/-- info: 'BlindLedger.Gate.Authority.decode_encode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Authority.decode_encode
/-- info: 'BlindLedger.Gate.Authority.encode_decode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Authority.encode_decode
/-- info: 'BlindLedger.Gate.Authority.admitGrant_sound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Authority.admitGrant_sound
/-- info: 'BlindLedger.Gate.Authority.admitGrant_superseded' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Authority.admitGrant_superseded
/-- info: 'BlindLedger.Gate.Authority.admitBypass_sound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Authority.admitBypass_sound
/-- info: 'BlindLedger.Gate.Authority.admitBypassR_ok_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Authority.admitBypassR_ok_iff
/-- info: 'BlindLedger.Gate.Authority.admitBypass_pair' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Authority.admitBypass_pair
/-- info: 'BlindLedger.Gate.Rules.bypass_no_window' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.bypass_no_window
/-- info: 'BlindLedger.Gate.Rules.bypass_once' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.bypass_once
/-- info: 'BlindLedger.Gate.Rules.fail_closed_unless_bypass' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.fail_closed_unless_bypass
/-- info: 'BlindLedger.Gate.Rules.never_bypassable' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.never_bypassable
/-- info: 'BlindLedger.Gate.Rules.ids_disjoint' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.ids_disjoint
/-- info: 'BlindLedger.Gate.Frame.decodeAns_encodeAns' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.decodeAns_encodeAns
/-- info: 'BlindLedger.Gate.Frame.encodeAns_decodeAns' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.encodeAns_decodeAns
/-- info: 'BlindLedger.Gate.Rules.one_payment_per_line' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.one_payment_per_line
/-- info: 'BlindLedger.Gate.Rules.released_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.released_iff
/-- info: 'BlindLedger.Gate.select_decides' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.select_decides
/-- info: 'BlindLedger.Gate.install_classifies' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.install_classifies
/-- info: 'BlindLedger.Gate.resign_noop' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.resign_noop
/-- info: 'BlindLedger.Gate.forks_witness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.forks_witness
/-- info: 'BlindLedger.Gate.Frame.decodeReq_encodeReq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.decodeReq_encodeReq
/-- info: 'BlindLedger.Gate.Frame.encodeReq_decodeReq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.encodeReq_decodeReq
/-- info: 'BlindLedger.Gate.Frame.decodeReq_wf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.decodeReq_wf
/-- info: 'BlindLedger.Gate.Frame.decodeReq_length' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.decodeReq_length
/-- info: 'BlindLedger.Gate.Frame.wide_local' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.wide_local
/-- info: 'BlindLedger.Gate.Frame.records_perm' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.records_perm
/-- info: 'BlindLedger.Gate.Frame.record_binds' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.record_binds
/-- info: 'BlindLedger.Gate.Frame.rows_of_records' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.rows_of_records
/-- info: 'BlindLedger.Gate.Frame.answer_encodes' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.answer_encodes
/-- info: 'BlindLedger.Gate.Rules.idx_dense' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.idx_dense
/-- info: 'BlindLedger.Gate.Rules.reasons_len_le' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.reasons_len_le
/-- info: 'BlindLedger.Gate.Rules.idx_len' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.idx_len
/-- info: 'BlindLedger.Gate.Rules.reasons_list_nodup' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Rules.reasons_list_nodup
/-- info: 'BlindLedger.Gate.Frame.maskOf_testBit_idx' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.maskOf_testBit_idx
/-- info: 'BlindLedger.Gate.Frame.unmask_maskOf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.unmask_maskOf
/-- info: 'BlindLedger.Gate.Frame.maskOf_lt' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Frame.maskOf_lt
/-- info: 'BlindLedger.Gate.Flat.StoreLog.load_binds' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.StoreLog.load_binds
/-- info: 'BlindLedger.Gate.Flat.StoreLog.crash_repair' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.StoreLog.crash_repair
/-- info: 'BlindLedger.Gate.Flat.StoreLog.crash_old_loads' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.StoreLog.crash_old_loads
/-- info: 'BlindLedger.Gate.Flat.StoreLog.crash_new_loads' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.StoreLog.crash_new_loads
/-- info: 'BlindLedger.Gate.Flat.StoreLog.crash_prefix_loads' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.StoreLog.crash_prefix_loads
/-- info: 'BlindLedger.Gate.Flat.StoreLog.load_reach' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Flat.StoreLog.load_reach
/-- info: 'BlindLedger.Gate.FactRegistry.RegEntry.dec_enc' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.RegEntry.dec_enc
/-- info: 'BlindLedger.Gate.FactRegistry.fseqDateIsa_lt' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.fseqDateIsa_lt
/-- info: 'BlindLedger.Gate.FactRegistry.fseqDateIsa_u64' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.fseqDateIsa_u64
/-- info: 'BlindLedger.Gate.FactRegistry.dayNum_mono' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.dayNum_mono
/-- info: 'BlindLedger.Gate.FactRegistry.pickMax_spec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.pickMax_spec
/-- info: 'BlindLedger.Gate.FactRegistry.pickMin_spec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.pickMin_spec
/-- info: 'BlindLedger.Gate.FactRegistry.admit_total' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.admit_total
/-- info: 'BlindLedger.Gate.FactRegistry.admit_already_file' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.admit_already_file
/-- info: 'BlindLedger.Gate.FactRegistry.admit_reused' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.admit_reused
/-- info: 'BlindLedger.Gate.FactRegistry.admit_late_ok' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.admit_late_ok
/-- info: 'BlindLedger.Gate.FactRegistry.admit_shape' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.admit_shape
/-- info: 'BlindLedger.Gate.FactRegistry.shapeOk_cfrom' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.shapeOk_cfrom
/-- info: 'BlindLedger.Gate.FactRegistry.admit_names1' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.admit_names1
/-- info: 'BlindLedger.Gate.FactRegistry.rank_strict' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.rank_strict
/-- info: 'BlindLedger.Gate.FactRegistry.admit_day' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.admit_day
/-- info: 'BlindLedger.Gate.FactRegistry.drop_bound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.drop_bound
/-- info: 'BlindLedger.Gate.FactRegistry.store_drop' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.store_drop
/-- info: 'BlindLedger.Gate.FactRegistry.dropCheck_full' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.dropCheck_full
/-- info: 'BlindLedger.Gate.FactRegistry.gapAt_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.gapAt_iff
/-- info: 'BlindLedger.Gate.FactRegistry.gap_filled' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.gap_filled
/-- info: 'BlindLedger.Gate.FactRegistry.gap_full_newest' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.gap_full_newest
/-- info: 'BlindLedger.Gate.FactRegistry.stale_of_drop' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.stale_of_drop
/-- info: 'BlindLedger.Gate.FactRegistry.stale_of_reused' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.stale_of_reused
/-- info: 'BlindLedger.Gate.FactRegistry.stale_of_none' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.stale_of_none
/-- info: 'BlindLedger.Gate.FactRegistry.age_persists' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.age_persists
/-- info: 'BlindLedger.Gate.FactRegistry.idle_never_fresher' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.idle_never_fresher
/-- info: 'BlindLedger.Gate.FactRegistry.lateUntil_open' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.lateUntil_open
/-- info: 'BlindLedger.Gate.FactRegistry.lateUntil_cut' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.lateUntil_cut
/-- info: 'BlindLedger.Gate.FactRegistry.no_ends_when_stale' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.no_ends_when_stale
/-- info: 'BlindLedger.Gate.FactCodec.Fact.dec_enc' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Fact.dec_enc
/-- info: 'BlindLedger.Gate.FactCodec.Fact.enc_length' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Fact.enc_length
/-- info: 'BlindLedger.Gate.FactCodec.Fact.dec_wrong_length' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Fact.dec_wrong_length
/-- info: 'BlindLedger.Gate.FactCodec.Receipt.dec_enc' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Receipt.dec_enc
/-- info: 'BlindLedger.Gate.FactCodec.Receipt.enc_length' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Receipt.enc_length
/-- info: 'BlindLedger.Gate.FactCodec.Receipt.dec_wrong_length' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Receipt.dec_wrong_length
/-- info: 'BlindLedger.Gate.FactCodec.Value.dec_enc' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Value.dec_enc
/-- info: 'BlindLedger.Gate.FactCodec.Value.dec_unknown' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Value.dec_unknown
/-- info: 'BlindLedger.Gate.FactCodec.rankLt_irrefl' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.rankLt_irrefl
/-- info: 'BlindLedger.Gate.FactCodec.rankLt_trans' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.rankLt_trans
/-- info: 'BlindLedger.Gate.FactCodec.rankLt_total' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.rankLt_total
/-- info: 'BlindLedger.Gate.FactCodec.rank_names_row' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.rank_names_row
/-- info: 'BlindLedger.Gate.FactCodec.Elig.enc_dec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Elig.enc_dec
/-- info: 'BlindLedger.Gate.FactCodec.Death.enc_dec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Death.enc_dec
/-- info: 'BlindLedger.Gate.FactCodec.Excl.enc_dec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Excl.enc_dec
/-- info: 'BlindLedger.Gate.FactCodec.Pdeath.enc_dec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Pdeath.enc_dec
/-- info: 'BlindLedger.Gate.FactCodec.Ack.enc_dec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Ack.enc_dec
/-- info: 'BlindLedger.Gate.FactCodec.Disc.enc_dec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Disc.enc_dec
/-- info: 'BlindLedger.Gate.FactCodec.Recov.enc_dec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Recov.enc_dec
/-- info: 'BlindLedger.Gate.FactCodec.Value.enc_dec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Value.enc_dec
/-- info: 'BlindLedger.Gate.FactCodec.Fact.enc_dec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Fact.enc_dec
/-- info: 'BlindLedger.Gate.FactCodec.Receipt.enc_dec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Receipt.enc_dec
/-- info: 'BlindLedger.Gate.FactRegistry.dayBefore_lt' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.dayBefore_lt
/-- info: 'BlindLedger.Gate.FactRegistry.stale_age_persists' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.stale_age_persists
/-- info: 'BlindLedger.Gate.FactRegistry.stale_gap_persists' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.stale_gap_persists
/-- info: 'BlindLedger.Gate.FactRegistry.dayBefore_valid' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.dayBefore_valid
/-- info: 'BlindLedger.Gate.FactRegistry.lookup_of_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.lookup_of_mem
/-- info: 'BlindLedger.Gate.FactCodec.Elig.dec_wf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Elig.dec_wf
/-- info: 'BlindLedger.Gate.FactCodec.Death.dec_wf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Death.dec_wf
/-- info: 'BlindLedger.Gate.FactCodec.Excl.dec_wf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Excl.dec_wf
/-- info: 'BlindLedger.Gate.FactCodec.Pdeath.dec_wf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Pdeath.dec_wf
/-- info: 'BlindLedger.Gate.FactCodec.Ack.dec_wf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Ack.dec_wf
/-- info: 'BlindLedger.Gate.FactCodec.Disc.dec_wf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Disc.dec_wf
/-- info: 'BlindLedger.Gate.FactCodec.Recov.dec_wf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Recov.dec_wf
/-- info: 'BlindLedger.Gate.FactCodec.Value.dec_wf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Value.dec_wf
/-- info: 'BlindLedger.Gate.FactCodec.Fact.dec_wf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Fact.dec_wf
/-- info: 'BlindLedger.Gate.FactCodec.Receipt.dec_wf' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactCodec.Receipt.dec_wf
/-- info: 'BlindLedger.Gate.FactRegistry.admit_registry' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.admit_registry
/-- info: 'BlindLedger.Gate.FactRegistry.admit_future' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.admit_future
/-- info: 'BlindLedger.Gate.FactRegistry.admit_fseq_date' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.admit_fseq_date
/-- info: 'BlindLedger.Gate.FactRegistry.admitFrame_fseq_date' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.admitFrame_fseq_date
/-- info: 'BlindLedger.Gate.FactRegistry.gapFrom_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.FactRegistry.gapFrom_iff
/-- info: 'BlindLedger.Gate.Obligations.RecCodec.dec_enc' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.RecCodec.dec_enc
/-- info: 'BlindLedger.Gate.Obligations.RecCodec.enc_dec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.RecCodec.enc_dec
/-- info: 'BlindLedger.Gate.Obligations.RecCodec.enc_inj' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.RecCodec.enc_inj
/-- info: 'BlindLedger.Gate.Obligations.RecCodec.dec_wrong_length' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.RecCodec.dec_wrong_length
/-- info: 'BlindLedger.Gate.Obligations.decF_encF' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.decF_encF
/-- info: 'BlindLedger.Gate.Obligations.encF_decF' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.encF_decF
/-- info: 'BlindLedger.Gate.Obligations.stateC_ok' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.stateC_ok
/-- info: 'BlindLedger.Gate.Obligations.caseC_ok' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.caseC_ok
/-- info: 'BlindLedger.Gate.Obligations.actionC_ok' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.actionC_ok
/-- info: 'BlindLedger.Gate.Obligations.cmdC_ok' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.cmdC_ok
/-- info: 'BlindLedger.Gate.Obligations.textC_ok' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.textC_ok
/-- info: 'BlindLedger.Gate.Obligations.join_parts' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.join_parts
/-- info: 'BlindLedger.Gate.Obligations.parts_join' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.parts_join
/-- info: 'BlindLedger.Gate.Obligations.parts_wf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.parts_wf
/-- info: 'BlindLedger.Gate.Obligations.obligC_ok' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.obligC_ok
/-- info: 'BlindLedger.Gate.Obligations.cashC_ok' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.cashC_ok
/-- info: 'BlindLedger.Gate.Obligations.claimC_ok' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.claimC_ok
/-- info: 'BlindLedger.Gate.Obligations.supportC_ok' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.supportC_ok
/-- info: 'BlindLedger.Gate.Obligations.reportC_ok' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.reportC_ok
/-- info: 'BlindLedger.Gate.Obligations.fundC_ok' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.fundC_ok
/-- info: 'BlindLedger.Gate.Obligations.ackC_ok' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.ackC_ok
/-- info: 'BlindLedger.Gate.Obligations.source_free_identity' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.source_free_identity
/-- info: 'BlindLedger.Gate.Obligations.in_force_latest' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.in_force_latest
/-- info: 'BlindLedger.Gate.Obligations.ident_spec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.ident_spec
/-- info: 'BlindLedger.Gate.Obligations.ident_append' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.ident_append
/-- info: 'BlindLedger.Gate.Obligations.case_key' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.case_key
/-- info: 'BlindLedger.Gate.Obligations.action_key' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.action_key
/-- info: 'BlindLedger.Gate.Obligations.cmd_key' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.cmd_key
/-- info: 'BlindLedger.Gate.Obligations.bounds_fit' does not depend on any axioms -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.bounds_fit
/-- info: 'BlindLedger.Gate.Obligations.wdec_wenc' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.wdec_wenc
/-- info: 'BlindLedger.Gate.Obligations.request_map_faithful' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.request_map_faithful
/-- info: 'BlindLedger.Gate.Obligations.offset_request_faithful' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.offset_request_faithful
/-- info: 'BlindLedger.Gate.Obligations.display_ok' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.display_ok
/-- info: 'BlindLedger.Gate.Obligations.element_fixed_agree' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.element_fixed_agree
/-- info: 'BlindLedger.Gate.Obligations.payment_request_faithful' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.payment_request_faithful
/-- info: 'BlindLedger.Gate.Obligations.state_row_roundtrip' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Obligations.state_row_roundtrip
/-- info: 'BlindLedger.Gate.Cosign.decode_too_long' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.decode_too_long
/-- info: 'BlindLedger.Gate.Cosign.encode_decode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.encode_decode
/-- info: 'BlindLedger.Gate.Cosign.decode_encode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.decode_encode
/-- info: 'BlindLedger.Gate.Cosign.decode_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.decode_iff
/-- info: 'BlindLedger.Gate.Cosign.decode_total' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.decode_total
/-- info: 'BlindLedger.Gate.Cosign.decode_schemes' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.decode_schemes
/-- info: 'BlindLedger.Gate.Cosign.encode_injective' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.encode_injective
/-- info: 'BlindLedger.Gate.Cosign.mlDsa87_length' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.mlDsa87_length
/-- info: 'BlindLedger.Gate.Cosign.mlDsa87_decodes' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.mlDsa87_decodes
/-- info: 'BlindLedger.Gate.Cosign.verify_ok' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_ok
/-- info: 'BlindLedger.Gate.Cosign.verify_malformed' depends on axioms: [propext] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_malformed
/-- info: 'BlindLedger.Gate.Cosign.verify_wrong_tenant' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_wrong_tenant
/-- info: 'BlindLedger.Gate.Cosign.verify_stale' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_stale
/-- info: 'BlindLedger.Gate.Cosign.verify_ahead' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_ahead
/-- info: 'BlindLedger.Gate.Cosign.verify_wrong_link' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_wrong_link
/-- info: 'BlindLedger.Gate.Cosign.verify_key_reuse' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_key_reuse
/-- info: 'BlindLedger.Gate.Cosign.verify_after_rotation' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_after_rotation
/-- info: 'BlindLedger.Gate.Cosign.verify_bad_root' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_bad_root
/-- info: 'BlindLedger.Gate.Cosign.verify_bad_witness' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_bad_witness
/-- info: 'BlindLedger.Gate.Cosign.keysApart_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.keysApart_iff
/-- info: 'BlindLedger.Gate.Cosign.verify_ok_keys' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_ok_keys
/-- info: 'BlindLedger.Gate.Cosign.linkAt_spec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.linkAt_spec
/-- info: 'BlindLedger.Gate.Cosign.linkAt_of_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.linkAt_of_mem
/-- info: 'BlindLedger.Gate.Cosign.linkAt_between' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.linkAt_between
/-- info: 'BlindLedger.Gate.Cosign.verify_ok_epoch' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_ok_epoch
/-- info: 'BlindLedger.Gate.Cosign.verify_own_generation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_own_generation
/-- info: 'BlindLedger.Gate.Cosign.verify_ok_closed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.verify_ok_closed
/-- info: 'BlindLedger.Gate.Cosign.inTime_head' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.inTime_head
/-- info: 'BlindLedger.Gate.Cosign.stale_any_crypto' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.stale_any_crypto
/-- info: 'BlindLedger.Gate.Cosign.body_ne_checkpoint_header' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Cosign.body_ne_checkpoint_header
