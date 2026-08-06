"""Bounded conformance receipt for the remaining internal package boundary.

This receipt closes the local/synthetic engineering packages only.  It does
not promote the candidate proof grammar, the reference field implementation,
or the local Rust state verifier into a production suite.  The production
native prover/verifier, HSM/FIPS custody, and independent audit remain explicit
launch blockers.
"""

from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha3_512
import os
from pathlib import Path
from typing import Final, Iterator, Mapping

from app.privacy_v2 import PRIVACY_V2_PUBLIC_OUTPUT_NAMES
from app.public_inputs import (
    PUBLIC_INPUT_FIELD_NAMES_V2,
    manifest_fields_v2,
)
from experiments.bl_pq512_crypto_foundation.h6_complete_simulator import (
    run_complete_simulator_suite,
)
from experiments.bl_pq512_crypto_foundation.active_gkr_hiding import (
    build_active_gkr_hiding_certificate,
    validate_active_gkr_hiding_certificate,
)
from experiments.bl_pq512_crypto_foundation.h6_security_ledger import (
    require_h6_security_ledger,
)
from experiments.bl_pq512_crypto_foundation.native_hiding_parameters import (
    HidingTableDimensions,
    build_native_hiding_interface_plan,
)
from experiments.bl_pq512_crypto_foundation.unique_decoding_parameters import (
    InterfaceTableDimensions,
    InterfaceTheoremEnvelope,
    build_unique_decoding_candidate,
)
from experiments.bl_pq512_crypto_foundation.circle_quotient_masking import (
    build_canonical_circle_quotient_mask_plan,
)
from experiments.bl_pq512_crypto_foundation.cross_domain_pcs_reference import (
    CommitmentStage,
    CrossDomainLayout,
    CrossDomainTree,
    DomainEvaluationBatch,
    DomainSpec,
    EvaluationField,
)
from experiments.fixed_shape_claim_air.physical_air_reference import (
    build_wave1a_physical_air_program,
)
from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.bl_pq512_crypto_foundation.internal_package_matrix import (
    OPEN_PACKAGE_DEFINITIONS,
)
from tools.privacy_v2_conformance import build_receipt as build_privacy_v2_receipt
from tools.wave2_spec_conformance import build_receipt as build_wave2_spec_receipt
from tools.whole_product_kat import build_receipt as build_whole_product_kat_receipt


ROOT: Final[Path] = Path(__file__).resolve().parents[1]
STATUS: Final[str] = "REMAINING_INTERNAL_CONFORMANCE_VERIFIED_NONACTIVATING"
PACKAGE_STATUS: Final[str] = "COMPLETE_INTERNAL_NONACTIVATING"
PROOF_SUITE_ID: None = None
ACTIVATION_ALLOWED: Final[bool] = False
PRODUCTION_USABLE: Final[bool] = False

PACKAGE_IDS: Final[tuple[str, ...]] = (
    *(f"A{index:02d}" for index in range(1, 12)),
    *(f"A{index:02d}" for index in range(13, 17)),
    *(f"Z{index:02d}" for index in range(3, 11)),
    *(f"T{index:02d}" for index in range(7, 15)),
)
SOURCE_DOMAIN: Final[bytes] = b"BL/PQ512/REMAINING-INTERNAL-CONFORMANCE/v1\x00"
FORBIDDEN_PUBLIC_TERMS: Final[tuple[str, ...]] = (
    "diagnosis",
    "patient",
    "member_id",
    "raw_edi",
    "serialized_arguments",
    "witness",
)


class RemainingInternalConformanceError(RuntimeError):
    """Raised when the bounded internal boundary cannot be established."""


@contextmanager
def _synthetic_environment() -> Iterator[None]:
    names = (
        "BL_ENV",
        "BL_DEV",
        "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE",
        "BL_DETERMINISTIC_TEST_ONLY",
    )
    previous = {name: os.environ.get(name) for name in names}
    os.environ.update(
        {
            "BL_ENV": "test",
            "BL_DEV": "1",
            "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
            "BL_DETERMINISTIC_TEST_ONLY": "1",
        }
    )
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _require_root(repo_root: Path | None) -> Path:
    root = ROOT if repo_root is None else repo_root.resolve()
    if root != ROOT:
        raise RemainingInternalConformanceError("remaining_internal_wrong_repository_root")
    return root


def _manifest(root: Path) -> tuple[int, int, str]:
    if set(PACKAGE_IDS) - set(OPEN_PACKAGE_DEFINITIONS):
        raise RemainingInternalConformanceError("remaining_internal_package_definition_missing")
    paths: set[str] = set()
    for package_id in PACKAGE_IDS:
        definition = OPEN_PACKAGE_DEFINITIONS[package_id]
        paths.update(definition.sources)
        paths.update(definition.tests)
    hasher = sha3_512(SOURCE_DOMAIN)
    source_count = 0
    test_count = 0
    for relative in sorted(paths):
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise RemainingInternalConformanceError(
                f"remaining_internal_manifest_path_missing:{relative}"
            )
        data = path.read_bytes()
        encoded = relative.encode("utf-8")
        hasher.update(len(encoded).to_bytes(4, "big"))
        hasher.update(encoded)
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(sha3_512(data).digest())
        if relative.startswith("tests/"):
            test_count += 1
        else:
            source_count += 1
    return source_count, test_count, hasher.hexdigest()


def _profile_and_boundary_check() -> dict[str, object]:
    expected = {
        "K128_CALIBRATION": (128, 7, 13),
        "K256_DESIGN_POINT": (256, 8, 14),
        "K512_CALIBRATION": (512, 9, 15),
    }
    observed = {
        profile_id: (
            profile.claim_slots,
            profile.claim_source_tree_depth,
            profile.oracle_tree_depth,
        )
        for profile_id, profile in PROFILES.items()
    }
    if observed != expected:
        raise RemainingInternalConformanceError("remaining_internal_profile_dimensions_mismatch")
    if tuple(PUBLIC_INPUT_FIELD_NAMES_V2) != tuple(PRIVACY_V2_PUBLIC_OUTPUT_NAMES):
        raise RemainingInternalConformanceError("remaining_internal_public_field_order_mismatch")
    manifest = manifest_fields_v2()
    if tuple(item["index"] for item in manifest) != tuple(range(12)):
        raise RemainingInternalConformanceError("remaining_internal_public_field_indices_mismatch")
    if any(
        term in " ".join(PUBLIC_INPUT_FIELD_NAMES_V2).casefold()
        for term in FORBIDDEN_PUBLIC_TERMS
    ):
        raise RemainingInternalConformanceError("remaining_internal_forbidden_public_term")
    return {
        "profile_count": len(observed),
        "claim_slots": {key: value[0] for key, value in observed.items()},
        "field_count": len(PUBLIC_INPUT_FIELD_NAMES_V2),
        "field_names": tuple(PUBLIC_INPUT_FIELD_NAMES_V2),
        "private_public_payload": False,
    }


def _native_hiding_check(simulator: Mapping[str, object]) -> dict[str, object]:
    profile = PROFILES["K512_CALIBRATION"]
    program = build_wave1a_physical_air_program(profile)
    envelope = InterfaceTheoremEnvelope(
        profile_id=program.profile_id,
        tables=tuple(
            InterfaceTableDimensions(
                table.name,
                table.padded_rows,
                table.trace_columns,
                table.constraint_count,
                table.maximum_degree,
                table.lookup_message_width,
            )
            for table in program.tables
        ),
        commitment_group_count=program.commitment_count,
    )
    candidate = build_unique_decoding_candidate(envelope, log_blowup=1)
    tables = tuple(
        HidingTableDimensions(
            table.name,
            table.padded_rows,
            table.trace_columns,
            table.commitment_group != "public_statement",
        )
        for table in program.tables
    )
    plan = build_native_hiding_interface_plan(
        profile_id=profile.profile_id,
        tables=tables,
        log_blowup=1,
        fri_query_count=candidate.query_count,
        reduced_air_degree=program.maximum_constraint_degree - 1,
    )
    active_hiding = build_active_gkr_hiding_certificate()
    validate_active_gkr_hiding_certificate(active_hiding)
    native_simulator = simulator.get("native_hiding")
    if not isinstance(native_simulator, Mapping):
        raise RemainingInternalConformanceError("remaining_internal_native_hiding_simulator_missing")
    if not all(
        native_simulator.get(key) is True
        for key in (
            "fixed_shape_verified",
            "private_opening_verified",
            "simulator_shape_verified",
            "error_shape_verified",
        )
    ):
        raise RemainingInternalConformanceError("remaining_internal_native_hiding_simulator_invalid")
    if len(plan.table_plans) != 16 or active_hiding.coverage_gaps:
        raise RemainingInternalConformanceError("remaining_internal_hiding_boundary_invalid")
    quotient = build_canonical_circle_quotient_mask_plan(
        profile_id="K512_CALIBRATION",
        reduced_air_degree=2,
        oods_query_count=1,
        fri_query_count=926,
    )
    if quotient.proof_suite_id is not None or quotient.activation_allowed:
        raise RemainingInternalConformanceError("remaining_internal_quotient_activation_boundary")
    return {
        "table_count": len(plan.table_plans),
        "private_trace_columns": plan.private_trace_columns,
        "trace_mask_degree_freedom": plan.trace_mask_degree_freedom,
        "quotient_mask_degree_freedom": quotient.quotient_mask_degree_freedom,
        "active_certificate_status": active_hiding.status,
        "active_certificate_sha3_512": active_hiding.certificate_digest_sha3_512,
        "historical_circle_gaps": active_hiding.superseded_historical_gaps,
        "coverage_gaps": active_hiding.coverage_gaps,
        "simulator_complete": True,
        "proofSuiteId": None,
        "activationAllowed": False,
    }


def _cross_domain_check() -> dict[str, object]:
    def rows(log_size: int, columns: int, offset: int) -> tuple[bytes, ...]:
        return tuple(
            b"".join(
                (offset + row * 17 + column).to_bytes(4, "big")
                for column in range(columns)
            )
            for row in range(1 << log_size)
        )

    small = DomainSpec(2, EvaluationField.M31, 2)
    large = DomainSpec(4, EvaluationField.M31, 1)
    layout = CrossDomainLayout(
        CommitmentStage.MAIN_TRACE,
        bytes([0x5A]) * 64,
        (small, large),
    )
    tree = CrossDomainTree.build(
        layout,
        (
            DomainEvaluationBatch(small, rows(2, 2, 100)),
            DomainEvaluationBatch(large, rows(4, 1, 200)),
        ),
    )
    proof = tree.proof(3)
    if not proof.verify(tree.layout, tree.root):
        raise RemainingInternalConformanceError("remaining_internal_cross_domain_replay_failed")
    return {"layout_identity_sha3_512": layout.identity.hex(), "root_sha3_512": tree.root.hex()}


def _source_backend_check(root: Path) -> dict[str, object]:
    selected = (root / "experiments/bl_pq512_crypto_core/src/selected_proof_package.rs").read_text(
        encoding="utf-8"
    )
    native = (root / "experiments/bl_pq512_crypto_foundation/wave3_full_internal.py").read_text(
        encoding="utf-8"
    )
    coordinator = (root / "experiments/bl_pq512_crypto_core/src/bin/k512_atomic_semantic_prototype.rs").read_text(
        encoding="utf-8"
    )
    parallel = (root / "experiments/bl_pq512_crypto_foundation/k512_parallel_campaign_evidence.py").read_text(
        encoding="utf-8"
    )
    required = (
        "verify_selected_proof_package",
        "verify_selected_fri_pipeline_v2",
        "Wave3RustStateBindingVerifierV1",
        "verify_state_binding",
        "BL_SHARD_CONCURRENCY",
        "validate_k512_parallel_campaign",
    )
    combined = selected + native + coordinator + parallel
    if any(symbol not in combined for symbol in required):
        raise RemainingInternalConformanceError("remaining_internal_backend_symbol_missing")
    return {
        "rust_package_decoder_present": True,
        "rust_independent_verifier_present": True,
        "rust_state_binding_port_present": True,
        "k512_two_lane_validator_present": True,
        "production_native_stark_verifier": False,
    }


def build_receipt(repo_root: Path | None = None) -> dict[str, object]:
    root = _require_root(repo_root)
    source_count, test_count, manifest_digest = _manifest(root)
    profile = _profile_and_boundary_check()
    with _synthetic_environment():
        cross_domain = _cross_domain_check()
        simulator = run_complete_simulator_suite()
        hiding = _native_hiding_check(simulator)
        security = require_h6_security_ledger()
    whole_product = build_whole_product_kat_receipt(root)
    wave2_spec = build_wave2_spec_receipt(root)
    privacy_v2 = build_privacy_v2_receipt(root)
    backend = _source_backend_check(root)
    if not simulator["repeated_proof_shape_fixed"] or not security.qualifies:
        raise RemainingInternalConformanceError("remaining_internal_simulator_or_security_failed")
    if whole_product["private_material_in_manifest"] or privacy_v2["private_public_payload"]:
        raise RemainingInternalConformanceError("remaining_internal_private_material_boundary_failed")
    if wave2_spec["proofSuiteId"] is not None or privacy_v2["proofSuiteId"] is not None:
        raise RemainingInternalConformanceError("remaining_internal_suite_identity_set")
    package_status = {package_id: PACKAGE_STATUS for package_id in PACKAGE_IDS}
    return {
        "schema": "blind_ledger_remaining_internal_conformance_v1",
        "status": STATUS,
        "package_status": package_status,
        "package_count": len(package_status),
        "source_file_count": source_count,
        "test_file_count": test_count,
        "package_manifest_sha3_512": manifest_digest,
        "profile_and_boundary": profile,
        "native_hiding": hiding,
        "cross_domain": cross_domain,
        "simulator": {
            key: value
            for key, value in simulator.items()
            if key != "records"
        },
        "security_ledger_qualifies": security.qualifies,
        "whole_product_kat_status": whole_product["status"],
        "wave2_spec_status": wave2_spec["status"],
        "privacy_v2_status": privacy_v2["status"],
        "backend": backend,
        "proofSuiteId": PROOF_SUITE_ID,
        "activationAllowed": ACTIVATION_ALLOWED,
        "productionUsable": PRODUCTION_USABLE,
        "production_blockers_preserved": (
            "LB-001",
            "LB-002",
            "LB-003",
            "LB-004",
            "LB-005",
            "LB-006",
            "LB-007",
            "LB-008",
            "LB-009",
            "LB-010",
        ),
    }


if __name__ == "__main__":
    import json

    print(json.dumps(build_receipt(ROOT), sort_keys=True, separators=(",", ":")))


__all__: tuple[str, ...] = (
    "ACTIVATION_ALLOWED",
    "PACKAGE_IDS",
    "PACKAGE_STATUS",
    "PRODUCTION_USABLE",
    "PROOF_SUITE_ID",
    "STATUS",
    "build_receipt",
)
