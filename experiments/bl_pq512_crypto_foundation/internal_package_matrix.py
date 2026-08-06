"""Exact source/test ownership for the remaining internal package ledger.

The matrix is evidence metadata, not a closure shortcut.  A package remains
open until its listed acceptance boundary is implemented and its containing
gate passes.  Keeping this list explicit prevents a broad wave receipt from
silently reusing one group's files for unrelated packages.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Final


class PackageMatrixError(RuntimeError):
    """Raised when package ownership or evidence is incomplete."""


@dataclass(frozen=True, slots=True)
class PackageDefinition:
    package_id: str
    acceptance: str
    sources: tuple[str, ...]
    tests: tuple[str, ...]


def _definition(
    package_id: str,
    acceptance: str,
    sources: tuple[str, ...],
    tests: tuple[str, ...],
) -> PackageDefinition:
    return PackageDefinition(package_id, acceptance, sources, tests)


# The 48 currently open packages have deliberately non-overlapping primary
# acceptance anchors.  Shared regression files are included only where they
# exercise a cross-boundary invariant as well.
OPEN_PACKAGE_DEFINITIONS: Final[dict[str, PackageDefinition]] = {
    "S02": _definition(
        "S02",
        "pin the candidate runtime/profile configuration without selecting a suite",
        ("docs/bl_pq512_suite_candidate_v1.json", "app/wave2_internal.py", "ops/wave2_internal_release_profile.json"),
        ("tests/test_wave2_internal_conformance.py", "tests/test_s07_s12_preimplementation_freeze.py"),
    ),
    "S04": _definition(
        "S04",
        "freeze and reject the canonical 744-byte authenticated sidecar",
        ("experiments/bl_pq512_crypto_foundation/h6_receipt_grammar.py", "experiments/bl_pq512_crypto_foundation/wave3_verifier_state_custody.py"),
        ("tests/test_bl_pq512_h6_receipt_grammar_cross_language.py", "tests/test_bl_pq512_wave3_verifier_state_custody.py", "tests/attacks/test_bl_pq512_s09_proof_body_reference_attacks.py"),
    ),
    "S07": _definition(
        "S07",
        "close the composed security/error/retry/multi-target ledger without activation",
        ("experiments/bl_pq512_crypto_foundation/h6_security_ledger.py", "docs/PQ_ZK_SECURITY_ARCHITECTURE.md"),
        ("tests/test_bl_pq512_h6_security_ledger.py", "tests/attacks/test_s07_s12_candidate_attacks.py"),
    ),
    "S08": _definition(
        "S08",
        "pin the reviewed field, challenge, PCS, query, and no-grinding parameter envelope",
        ("experiments/bl_pq512_crypto_foundation/field16_reference.py", "experiments/bl_pq512_crypto_foundation/native_hiding_parameters.py", "experiments/bl_pq512_crypto_core/src/proof_parameters.rs"),
        ("tests/test_bl_pq512_native_hiding_parameters.py", "tests/test_bl_pq512_unique_decoding_parameters.py", "tests/attacks/test_bl_pq512_native_hiding_parameters_attacks.py"),
    ),
    "S09": _definition(
        "S09",
        "pin the candidate proof grammar/transcript domains while retaining proofSuiteId=null",
        ("experiments/bl_pq512_crypto_foundation/proof_body_reference.py", "experiments/bl_pq512_crypto_foundation/selected_public_coin.py", "docs/bl_pq512_suite_candidate_v1.json"),
        ("tests/test_bl_pq512_s09_proof_body_reference.py", "tests/test_bl_pq512_selected_public_coin_schedule.py", "tests/attacks/test_bl_pq512_s09_proof_body_reference_attacks.py"),
    ),
    "S10": _definition(
        "S10",
        "bind migration, rollback, rotation, mixed-version, and activation-failure semantics",
        ("experiments/bl_pq512_crypto_foundation/state_migration_recovery.py", "experiments/bl_pq512_crypto_foundation/wave3_verifier_state_custody.py"),
        ("tests/test_bl_pq512_state_migration_recovery.py", "tests/test_bl_pq512_wave3_verifier_state_custody.py", "tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py"),
    ),
    "S11": _definition(
        "S11",
        "pin the offline locked toolchain, dependency, license, SBOM, and source inputs",
        ("experiments/bl_pq512_crypto_foundation/h6_supply_chain.py", "experiments/bl_pq512_crypto_foundation/internal_completion.py", "experiments/bl_pq512_crypto_core/Cargo.toml", "experiments/bl_pq512_crypto_core/Cargo.lock"),
        ("tests/test_bl_pq512_h6_supply_chain.py", "tests/test_build_release_archive.py"),
    ),
    "S12": _definition(
        "S12",
        "freeze the complete statement, invariant, error, and acceptance contract",
        ("docs/BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md", "experiments/bl_pq512_crypto_foundation/gate_2e_terminal_ledger.py"),
        ("tests/test_s07_s12_preimplementation_freeze.py", "tests/test_bl_pq512_gate_2e_terminal_ledger.py", "tests/attacks/test_s07_s12_candidate_attacks.py"),
    ),
    "A01": _definition(
        "A01",
        "freeze fixed K128/K256/K512 profile dimensions and capacity labels",
        ("experiments/fixed_shape_claim_air/profile.py", "experiments/fixed_shape_claim_air/physical_air_reference.py", "experiments/bl_pq512_crypto_core/src/wave1a_dimensions.rs"),
        ("tests/test_r25_fixed_shape_semantics.py", "tests/test_wave1a_physical_air_reference.py", "tests/test_wave1a_executable_air.py"),
    ),
    "A02": _definition(
        "A02",
        "freeze bounded canonical witness and private-slot serialization",
        ("experiments/fixed_shape_claim_air/witness_schema_reference.py", "experiments/fixed_shape_claim_air/semantics.py", "app/canonical_encoding.py"),
        ("tests/test_r25_witness_schema_reference.py", "tests/test_fixed_k_privacy_reference.py", "tests/attacks/test_r25_payment_attacks.py"),
    ),
    "A03": _definition(
        "A03",
        "freeze ordering, duplicate handling, ranges, and canonical encoding across the boundary",
        ("app/canonical_order.py", "app/service_line_canonical.py", "experiments/fixed_shape_claim_air/ordered_map_reference.py"),
        ("tests/test_wave1a_ordered_map_reference.py", "tests/test_r25_vector_corpus.py", "tests/attacks/test_wave1a_ordered_map_reference_attacks.py"),
    ),
    "A04": _definition(
        "A04",
        "freeze real/dummy/cover composition and collision rejection",
        ("experiments/fixed_shape_claim_air/a12_nullifier_executable_air.py", "experiments/fixed_shape_claim_air/salt_use_tag_executable_air.py", "app/batch/nullifier.py"),
        ("tests/test_wave1a_a12_nullifier_executable_air.py", "tests/test_wave1a_salt_use_tag_executable_air.py", "tests/attacks/test_wave1a_a12_nullifier_executable_air_attacks.py"),
    ),
    "A05": _definition(
        "A05",
        "prove witness-class-independent trace, query, proof, and operation shape",
        ("experiments/fixed_shape_claim_air/physical_air_reference.py", "experiments/bl_pq512_crypto_foundation/h6_complete_simulator.py", "app/privacy_v2.py"),
        ("tests/test_wave1a_physical_air_reference.py", "tests/test_bl_pq512_h6_complete_simulator.py", "tests/test_privacy_v2_abi.py", "tests/attacks/test_privacy_v2_bundle_attacks.py"),
    ),
    "A06": _definition(
        "A06",
        "bind every adjudication gate and exact first-failure priority into the relation",
        ("experiments/fixed_shape_claim_air/claim_gate_executable_air.py", "experiments/fixed_shape_claim_air/claim_result_executable_air.py", "rules-engine-rust/src/lib.rs"),
        ("tests/test_wave1a_claim_gate_executable_air.py", "tests/test_wave1a_claim_result_executable_air.py", "tests/test_rules_engine_coverage.py", "tests/attacks/test_wave1a_claim_gate_executable_air_attacks.py"),
    ),
    "A07": _definition(
        "A07",
        "bind canonical claim-source membership, encoding, authority, and absence",
        ("experiments/bl_pq512_crypto_foundation/claim_source_commitment.py", "experiments/fixed_shape_claim_air/claim_source_commitment_executable_air.py", "app/batch/claim_source_root.py"),
        ("tests/test_bl_pq512_claim_source_commitment.py", "tests/test_wave1a_claim_source_commitment_executable_air.py", "tests/attacks/test_bl_pq512_claim_batch_access_manifest_attacks.py"),
    ),
    "A08": _definition(
        "A08",
        "bind oracle facts, authorization, signer, epoch, membership, and absence",
        ("experiments/bl_pq512_crypto_foundation/claim_truth_pq_authority.py", "experiments/fixed_shape_claim_air/claim_truth_authority_executable_air.py", "app/oracle_attestation.py"),
        ("tests/test_bl_pq512_claim_truth_pq_authority.py", "tests/test_wave1a_claim_truth_authority_executable_air.py", "tests/attacks/test_bl_pq512_oracle_bundle_commitment_attacks.py"),
    ),
    "A09": _definition(
        "A09",
        "bind policy, fee rows, ruleset versions, and their authorities",
        ("experiments/bl_pq512_crypto_foundation/policy_bundle_commitment.py", "experiments/bl_pq512_crypto_foundation/ruleset_commitment.py", "experiments/fixed_shape_claim_air/policy_bundle_encoding_executable_air.py"),
        ("tests/test_bl_pq512_policy_bundle_commitment.py", "tests/test_bl_pq512_ruleset_commitment.py", "tests/test_wave1a_policy_bundle_encoding_executable_air.py", "tests/attacks/test_proving_evidence_policy_attacks.py"),
    ),
    "A10": _definition(
        "A10",
        "bind adjudication and exact first-failure ordering",
        ("experiments/fixed_shape_claim_air/claim_result_executable_air.py", "experiments/fixed_shape_claim_air/claim_semantics_executable_air.py", "rules-engine-rust/src/lib.rs"),
        ("tests/test_wave1a_claim_result_executable_air.py", "tests/test_wave1a_claim_semantics_executable_air.py", "tests/test_rules_engine_coverage.py", "tests/attacks/test_wave1a_claim_result_executable_air_attacks.py"),
    ),
    "A11": _definition(
        "A11",
        "bind checked money, conservation, payment maps, and state transitions",
        ("experiments/fixed_shape_claim_air/fee_arithmetic_executable_air.py", "experiments/fixed_shape_claim_air/claim_payment_maps_executable_air.py", "experiments/fixed_shape_claim_air/payment_state.py"),
        ("tests/test_wave1a_fee_arithmetic_executable_air.py", "tests/test_wave1a_authenticated_payment_maps_executable_air.py", "tests/test_r25_payment_state_reference.py", "tests/attacks/test_r25_payment_attacks.py"),
    ),
    "A13": _definition(
        "A13",
        "bind identical authenticated state-operation shape for every slot",
        ("experiments/fixed_shape_claim_air/state_relation_executable_air.py", "experiments/fixed_shape_claim_air/typed_state_relation_executable_air.py", "experiments/bl_pq512_crypto_foundation/state_interface.py"),
        ("tests/test_bl_pq512_state_relation_executable_air.py", "tests/test_bl_pq512_typed_state_relation_executable_air.py", "tests/attacks/test_bl_pq512_state_interface_attacks.py"),
    ),
    "A14": _definition(
        "A14",
        "project wide authoritative values onto the exact ordered twelve fields",
        ("experiments/fixed_shape_claim_air/wide_public_executable_air.py", "app/privacy_v2.py", "app/public_inputs.py"),
        ("tests/test_wave1a_wide_public_executable_air.py", "tests/test_privacy_v2_abi.py", "tests/attacks/test_privacy_v2_bundle_attacks.py"),
    ),
    "A15": _definition(
        "A15",
        "bind SHA3-512 roots and master commitments over canonical records",
        ("experiments/fixed_shape_claim_air/master_commitments_executable_air.py", "experiments/fixed_shape_claim_air/master_public_composition.py", "experiments/fixed_shape_claim_air/sha3_512_executable_air.py"),
        ("tests/test_wave1a_master_commitments_executable_air.py", "tests/test_wave1a_master_public_composition.py", "tests/attacks/test_wave1a_sha3_512_executable_air_attacks.py"),
    ),
    "A16": _definition(
        "A16",
        "complete the trace/AIR/composition/prover/verifier and adversarial closure",
        ("experiments/fixed_shape_claim_air/executable_air.py", "experiments/fixed_shape_claim_air/wave1a_global_executable_air.py", "experiments/bl_pq512_crypto_core/src/bin/k512_atomic_semantic_prototype.rs"),
        ("tests/test_wave1a_executable_air.py", "tests/test_wave1a_global_executable_air.py", "tests/test_bl_pq512_wave3_full_internal.py", "tests/attacks/test_wave1a_executable_air_attacks.py"),
    ),
    "Z02": _definition(
        "Z02",
        "separate OS entropy from deterministic tests and zeroize owned secrets",
        ("app/wave2_internal.py", "app/wave4_operations.py", "experiments/bl_pq512_crypto_foundation/wave3_verifier_state_custody.py"),
        ("tests/test_wave2_internal_completion.py", "tests/test_wave4_adapters_operations.py", "tests/attacks/test_wave2_internal_completion_attacks.py"),
    ),
    "Z03": _definition(
        "Z03",
        "mask private semantic, bus, GKR, and terminal messages",
        ("experiments/bl_pq512_crypto_core/src/gkr_zk_mask.rs", "experiments/bl_pq512_crypto_foundation/native_hiding_parameters.py", "experiments/bl_pq512_crypto_foundation/h6_complete_simulator.py"),
        ("tests/test_bl_pq512_native_hiding_parameters.py", "tests/test_bl_pq512_fp16_hiding_simulator.py", "tests/attacks/test_bl_pq512_native_hiding_parameters_attacks.py"),
    ),
    "Z04": _definition(
        "Z04",
        "inventory and mask auxiliary, lookup, permutation, and interaction columns",
        ("experiments/bl_pq512_crypto_core/src/claim_source.rs", "experiments/bl_pq512_crypto_core/src/ordered_map_schedule.rs", "experiments/bl_pq512_crypto_foundation/claim_batch_access_manifest.py"),
        ("tests/test_bl_pq512_claim_batch_access_manifest.py", "tests/test_bl_pq512_oracle_bundle_commitment.py", "tests/attacks/test_bl_pq512_claim_batch_access_manifest_attacks.py"),
    ),
    "Z05": _definition(
        "Z05",
        "randomize quotient/composition polynomials and split factors",
        ("experiments/bl_pq512_crypto_core/src/quotient_mask.rs", "experiments/bl_pq512_crypto_core/src/composition_mask.rs", "experiments/bl_pq512_crypto_foundation/circle_quotient_masking.py"),
        ("tests/test_bl_pq512_circle_quotient_masking.py", "tests/attacks/test_bl_pq512_circle_quotient_masking_attacks.py"),
    ),
    "Z06": _definition(
        "Z06",
        "enforce disjoint trace/commitment/evaluation domains and reject raw openings",
        ("experiments/bl_pq512_crypto_core/src/cross_domain.rs", "experiments/bl_pq512_crypto_core/src/multilinear_pcs.rs", "experiments/bl_pq512_crypto_foundation/cross_domain_pcs_reference.py"),
        ("tests/test_bl_pq512_cross_domain_pcs.py", "tests/attacks/test_bl_pq512_cross_domain_pcs_attacks.py"),
    ),
    "Z07": _definition(
        "Z07",
        "inventory DEEP/FRI/bus/GKR/bridge and implicit query exposure",
        ("experiments/bl_pq512_crypto_core/src/fri_layer_multiproof.rs", "experiments/bl_pq512_crypto_core/src/fp16_zk_rs_gkr_binding.rs", "experiments/bl_pq512_crypto_foundation/h6_complete_simulator.py"),
        ("tests/test_bl_pq512_h6_complete_simulator.py", "tests/test_bl_pq512_h6_proof_body_cross_language.py", "tests/attacks/test_bl_pq512_h6_closure_attacks.py"),
    ),
    "Z08": _definition(
        "Z08",
        "commit independent PCS masks before batching and preserve folding entropy",
        ("experiments/bl_pq512_crypto_core/src/multilinear_pcs_query.rs", "experiments/bl_pq512_crypto_core/src/multilinear_pcs_transcript.rs", "experiments/bl_pq512_crypto_foundation/circle_hiding_simulator.py"),
        ("tests/test_bl_pq512_circle_hiding_simulator.py", "tests/test_bl_pq512_selected_public_coin_transcript.py", "tests/attacks/test_bl_pq512_circle_hiding_simulator_attacks.py"),
    ),
    "Z09": _definition(
        "Z09",
        "version and bind dual-PQ interactive transcript and complete statement",
        ("experiments/bl_pq512_crypto_foundation/public_coin_governance.py", "experiments/bl_pq512_crypto_foundation/selected_public_coin.py", "experiments/bl_pq512_crypto_core/src/chained_public_coin.rs"),
        ("tests/test_bl_pq512_selected_public_coin_schedule.py", "tests/test_bl_pq512_selected_public_coin_transcript.py", "tests/attacks/test_bl_pq512_h6_closure_attacks.py"),
    ),
    "Z10": _definition(
        "Z10",
        "qualify SHA3-512, Fp16, PCS, GKR, hiding, and query parameters",
        ("experiments/bl_pq512_crypto_foundation/h6_security_ledger.py", "experiments/bl_pq512_crypto_foundation/field16_reference.py", "experiments/bl_pq512_crypto_core/src/proof_parameters.rs"),
        ("tests/test_bl_pq512_h6_security_ledger.py", "tests/test_bl_pq512_native_hiding_parameters.py", "tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py"),
    ),
    "Z11": _definition(
        "Z11",
        "prove the complete simulator across abort, retry, crash, and artifact paths",
        ("experiments/bl_pq512_crypto_foundation/h6_complete_simulator.py", "experiments/bl_pq512_crypto_foundation/native_hiding_simulator.py", "experiments/bl_pq512_crypto_foundation/h6_privacy_boundary.py"),
        ("tests/test_bl_pq512_h6_complete_simulator.py", "tests/test_bl_pq512_native_hiding_simulator.py", "tests/test_bl_pq512_h6_privacy_boundary.py", "tests/attacks/test_bl_pq512_native_hiding_simulator_attacks.py", "tests/attacks/test_bl_pq512_h6_closure_attacks.py"),
    ),
    "Z12": _definition(
        "Z12",
        "qualify serialization, fail-closed parsing, fuzz/mutation, and unlinkability",
        ("experiments/bl_pq512_crypto_foundation/h6_receipt_grammar.py", "experiments/bl_pq512_crypto_foundation/proof_body_reference.py", "tools/privacy_artifact_scan.py"),
        ("tests/test_bl_pq512_h6_receipt_grammar_cross_language.py", "tests/test_privacy_artifact_scan.py", "tests/attacks/test_privacy_v2_bundle_attacks.py"),
    ),
    "T01": _definition("T01", "freeze one whole-product vector schema", ("experiments/fixed_shape_claim_air/vector_corpus.py", "experiments/fixed_shape_claim_air/whole_product_vector_corpus.py", "test_data/bl_pq512_whole_product_vectors.json", "tools/whole_product_kat.py", "tests/proving_policy_fixtures.py"), ("tests/test_foundation_vector_schema.py", "tests/test_whole_product_vector_corpus.py")),
    "T02": _definition("T02", "KAT approved claims across authoritative implementations", ("experiments/fixed_shape_claim_air/vector_corpus.py", "experiments/fixed_shape_claim_air/claim_semantics_executable_air.py", "experiments/fixed_shape_claim_air/whole_product_vector_corpus.py"), ("tests/test_r25_vector_corpus.py", "tests/test_wave1a_claim_semantics_executable_air.py", "tests/test_whole_product_vector_corpus.py")),
    "T03": _definition("T03", "KAT all denial and first-failure priority", ("experiments/fixed_shape_claim_air/claim_gate_executable_air.py", "rules-engine-rust/src/lib.rs", "experiments/fixed_shape_claim_air/whole_product_vector_corpus.py"), ("tests/test_wave1a_claim_gate_executable_air.py", "tests/test_rules_engine_coverage.py", "tests/test_whole_product_vector_corpus.py")),
    "T04": _definition("T04", "KAT dummy, padding, mixed, and all-denied shapes", ("experiments/fixed_shape_claim_air/physical_air_reference.py", "app/privacy_v2.py", "experiments/fixed_shape_claim_air/whole_product_vector_corpus.py"), ("tests/test_wave1a_physical_air_reference.py", "tests/test_privacy_v2_abi.py", "tests/test_whole_product_vector_corpus.py")),
    "T05": _definition("T05", "KAT zero/minimum/maximum capacity and boundaries", ("experiments/fixed_shape_claim_air/profile.py", "app/money.py", "experiments/fixed_shape_claim_air/whole_product_vector_corpus.py"), ("tests/test_r25_fixed_shape_semantics.py", "tests/test_money_cross_lane_hardening.py", "tests/test_whole_product_vector_corpus.py")),
    "T06": _definition("T06", "KAT duplicate/replay/retry/correction/revision/nullifier cases", ("experiments/fixed_shape_claim_air/a12_replay_composition_executable_air.py", "experiments/bl_pq512_crypto_foundation/state_migration_recovery.py", "experiments/fixed_shape_claim_air/whole_product_vector_corpus.py"), ("tests/test_wave1a_a12_replay_composition_executable_air.py", "tests/test_bl_pq512_state_migration_recovery.py", "tests/attacks/test_wave1a_replay_header_executable_air_attacks.py", "tests/test_whole_product_vector_corpus.py")),
    "T07": _definition("T07", "attack fabricated/stale policy/oracle/source/signer/epoch inputs", ("experiments/bl_pq512_crypto_foundation/claim_truth_pq_authority.py", "experiments/bl_pq512_crypto_foundation/claim_source_commitment.py", "experiments/bl_pq512_crypto_foundation/state_migration_recovery.py"), ("tests/test_bl_pq512_claim_truth_pq_authority.py", "tests/test_bl_pq512_claim_source_commitment.py", "tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py")),
    "T08": _definition("T08", "attack money, canonical-field, serialization, and length inputs", ("app/money.py", "app/canonical_encoding.py", "experiments/bl_pq512_crypto_foundation/h6_receipt_grammar.py"), ("tests/test_money_cross_lane_hardening.py", "tests/test_bl_pq512_h6_receipt_grammar_cross_language.py", "tests/attacks/test_privacy_v2_bundle_attacks.py")),
    "T09": _definition("T09", "attack proof/profile/schema/artifact/domain/root rebinding", ("experiments/bl_pq512_crypto_foundation/proof_body_reference.py", "experiments/bl_pq512_crypto_foundation/wave3_verifier_state_custody.py", "app/wave5_rollup.py"), ("tests/attacks/test_bl_pq512_s09_proof_body_reference_attacks.py", "tests/attacks/test_bl_pq512_state_plane_attacks.py", "tests/attacks/test_wave5_rollup_attacks.py")),
    "T10": _definition("T10", "property/fuzz coverage for AIR, parsers, verifiers, and projections", ("experiments/fixed_shape_claim_air/executable_air.py", "experiments/bl_pq512_crypto_foundation/proof_body_reference.py", "app/privacy_v2.py"), ("tests/test_r25_vector_properties.py", "tests/test_verifier_receipt.py", "tests/attacks/test_privacy_v2_bundle_attacks.py")),
    "T11": _definition("T11", "scan proofs/logs/errors/crashes/artifacts and unlinkability", ("tools/privacy_artifact_scan.py", "experiments/bl_pq512_crypto_foundation/h6_privacy_boundary.py", "app/wave4_operations.py"), ("tests/test_privacy_artifact_scan.py", "tests/test_bl_pq512_h6_privacy_boundary.py", "tests/test_wave4_adapters_operations.py")),
    "T12": _definition("T12", "test shape/cadence/timing/root/query/failure leakage", ("experiments/bl_pq512_crypto_foundation/h6_complete_simulator.py", "app/wave4_operations.py", "experiments/bl_pq512_crypto_foundation/benchmark_evidence.py"), ("tests/test_bl_pq512_h6_complete_simulator.py", "tests/test_wave4_adapters_operations.py", "tests/test_bl_pq512_benchmark_evidence.py")),
    "T13": _definition("T13", "measure complete stage time/dimensions/memory/bytes and attribution", ("experiments/bl_pq512_crypto_foundation/benchmark_evidence.py", "experiments/bl_pq512_crypto_foundation/k512_parallel_campaign_evidence.py", "tools/wave5_conformance.py"), ("tests/test_bl_pq512_benchmark_evidence.py", "tests/test_bl_pq512_k512_parallel_campaign_evidence.py")),
    "T14": _definition("T14", "run all applicable language/proof/attack/integrity/artifact gates", ("experiments/bl_pq512_crypto_foundation/internal_completion.py", "tools/internal_completion.py", "ops/launch_blockers.json"), ("tests/test_internal_completion.py", "tests/attacks/test_internal_completion_attacks.py")),
}


def _regular(root: Path, relative: str) -> Path:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise PackageMatrixError(f"package_matrix_missing:{relative}")
    return path


def validate_open_package_matrix(repo_root: Path) -> tuple[PackageDefinition, ...]:
    expected = {
        package_id
        for package_id in (
            "S02",
            "S04",
            *(f"S{index:02d}" for index in range(7, 13)),
            *(f"A{index:02d}" for index in range(1, 17) if index != 12),
            *(f"Z{index:02d}" for index in range(2, 13)),
            *(f"T{index:02d}" for index in range(1, 15)),
        )
    }
    if set(OPEN_PACKAGE_DEFINITIONS) != expected:
        missing = sorted(expected - set(OPEN_PACKAGE_DEFINITIONS))
        extra = sorted(set(OPEN_PACKAGE_DEFINITIONS) - expected)
        raise PackageMatrixError(f"package_matrix_ids_invalid:missing={missing}:extra={extra}")
    records = tuple(OPEN_PACKAGE_DEFINITIONS[package_id] for package_id in sorted(expected))
    for record in records:
        if not record.acceptance or not record.sources or not record.tests:
            raise PackageMatrixError(f"package_matrix_record_incomplete:{record.package_id}")
        for relative in (*record.sources, *record.tests):
            _regular(repo_root, relative)
    return records


def package_evidence(repo_root: Path, package_id: str) -> dict[str, object]:
    validate_open_package_matrix(repo_root)
    try:
        record = OPEN_PACKAGE_DEFINITIONS[package_id]
    except KeyError as exc:
        raise PackageMatrixError(f"package_matrix_unknown:{package_id}") from exc
    records = tuple(
        {
            "path": relative,
            "bytes": _regular(repo_root, relative).stat().st_size,
            "sha3_512": hashlib.sha3_512(_regular(repo_root, relative).read_bytes()).hexdigest(),
        }
        for relative in (*record.sources, *record.tests)
    )
    payload = {
        "package_id": record.package_id,
        "acceptance": record.acceptance,
        "sources": record.sources,
        "tests": record.tests,
        "records": records,
    }
    return {
        "package_id": record.package_id,
        "acceptance": record.acceptance,
        "sources": record.sources,
        "tests": record.tests,
        "evidence_sha3_512": hashlib.sha3_512(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest(),
    }


__all__: tuple[str, ...] = (
    "OPEN_PACKAGE_DEFINITIONS",
    "PackageDefinition",
    "PackageMatrixError",
    "package_evidence",
    "validate_open_package_matrix",
)
