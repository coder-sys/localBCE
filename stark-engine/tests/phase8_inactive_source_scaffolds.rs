use stark_engine::{
    Phase8ImplementationEvidenceSlots, Phase8ImplementationSourceRegistry, local_verifier,
    proof_artifact, proof_commitment, public_inputs, real_prover, root_semantics, source_roots,
};

struct InactiveScaffold {
    transformation_id: &'static str,
    module_path: &'static str,
    implementation_status: &'static str,
    runtime_wiring_allowed: bool,
    real_proof_generation_allowed: bool,
    required_evidence: &'static [&'static str],
}

fn inactive_scaffolds() -> Vec<InactiveScaffold> {
    vec![
        InactiveScaffold {
            transformation_id: real_prover::TRANSFORMATION_ID,
            module_path: real_prover::MODULE_PATH,
            implementation_status: real_prover::IMPLEMENTATION_STATUS,
            runtime_wiring_allowed: real_prover::RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: real_prover::REAL_PROOF_GENERATION_ALLOWED,
            required_evidence: &real_prover::REQUIRED_EVIDENCE,
        },
        InactiveScaffold {
            transformation_id: root_semantics::TRANSFORMATION_ID,
            module_path: root_semantics::MODULE_PATH,
            implementation_status: root_semantics::IMPLEMENTATION_STATUS,
            runtime_wiring_allowed: root_semantics::RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: root_semantics::REAL_PROOF_GENERATION_ALLOWED,
            required_evidence: &root_semantics::REQUIRED_EVIDENCE,
        },
        InactiveScaffold {
            transformation_id: public_inputs::TRANSFORMATION_ID,
            module_path: public_inputs::MODULE_PATH,
            implementation_status: public_inputs::IMPLEMENTATION_STATUS,
            runtime_wiring_allowed: public_inputs::RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: public_inputs::REAL_PROOF_GENERATION_ALLOWED,
            required_evidence: &public_inputs::REQUIRED_EVIDENCE,
        },
        InactiveScaffold {
            transformation_id: source_roots::TRANSFORMATION_ID,
            module_path: source_roots::MODULE_PATH,
            implementation_status: source_roots::IMPLEMENTATION_STATUS,
            runtime_wiring_allowed: source_roots::RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: source_roots::REAL_PROOF_GENERATION_ALLOWED,
            required_evidence: &source_roots::REQUIRED_EVIDENCE,
        },
        InactiveScaffold {
            transformation_id: proof_commitment::TRANSFORMATION_ID,
            module_path: proof_commitment::MODULE_PATH,
            implementation_status: proof_commitment::IMPLEMENTATION_STATUS,
            runtime_wiring_allowed: proof_commitment::RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: proof_commitment::REAL_PROOF_GENERATION_ALLOWED,
            required_evidence: &proof_commitment::REQUIRED_EVIDENCE,
        },
        InactiveScaffold {
            transformation_id: local_verifier::TRANSFORMATION_ID,
            module_path: local_verifier::MODULE_PATH,
            implementation_status: local_verifier::IMPLEMENTATION_STATUS,
            runtime_wiring_allowed: local_verifier::RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: local_verifier::REAL_PROOF_GENERATION_ALLOWED,
            required_evidence: &local_verifier::REQUIRED_EVIDENCE,
        },
        InactiveScaffold {
            transformation_id: proof_artifact::TRANSFORMATION_ID,
            module_path: proof_artifact::MODULE_PATH,
            implementation_status: proof_artifact::IMPLEMENTATION_STATUS,
            runtime_wiring_allowed: proof_artifact::RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: proof_artifact::REAL_PROOF_GENERATION_ALLOWED,
            required_evidence: &proof_artifact::REQUIRED_EVIDENCE,
        },
    ]
}

#[test]
fn inactive_scaffolds_match_phase8_source_registry() {
    let scaffolds = inactive_scaffolds();

    assert_eq!(
        scaffolds.len(),
        Phase8ImplementationSourceRegistry::PLANNED_SOURCES.len()
    );

    for (scaffold, (expected_id, expected_path, expected_owner)) in scaffolds
        .iter()
        .zip(Phase8ImplementationSourceRegistry::PLANNED_SOURCES.iter())
    {
        assert_eq!(scaffold.transformation_id, *expected_id);
        assert_eq!(scaffold.module_path, *expected_path);
        assert_eq!(*expected_owner, "stark-engine");
    }
}

#[test]
fn inactive_scaffolds_match_phase8_required_evidence_slots() {
    let scaffolds = inactive_scaffolds();

    assert_eq!(
        scaffolds.len(),
        Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE.len()
    );

    for (scaffold, (expected_id, expected_evidence)) in scaffolds
        .iter()
        .zip(Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE.iter())
    {
        assert_eq!(scaffold.transformation_id, *expected_id);
        assert_eq!(scaffold.required_evidence, expected_evidence);
    }
}

#[test]
fn inactive_scaffolds_do_not_enable_runtime_or_real_proofs() {
    for scaffold in inactive_scaffolds() {
        assert_eq!(
            scaffold.implementation_status,
            "scaffold_only_not_implemented"
        );
        assert!(!scaffold.runtime_wiring_allowed);
        assert!(!scaffold.real_proof_generation_allowed);
    }
}
