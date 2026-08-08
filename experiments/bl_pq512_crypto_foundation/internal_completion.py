"""One local, synthetic receipt for the internal package ledger.

This module does not select a production proof suite or enable activation.  It
reconciles implemented local proof, privacy, state, adapter, custody,
supply-chain, and release evidence without converting partial evidence into
package closure.  The remaining internal work, final independent audit, and
operator activation inputs remain separate gates.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from collections.abc import Iterator
from typing import Final

from app.public_inputs import PUBLIC_INPUT_FIELD_NAMES_V2, assert_public_input_names_v2
from app.wave2_internal import (
    ACTIVATION_ALLOWED as WAVE2_ACTIVATION_ALLOWED,
    LIVE_CREDENTIALS as WAVE2_LIVE_CREDENTIALS,
    NETWORK_ACCESS as WAVE2_NETWORK_ACCESS,
    PRODUCTION_USABLE as WAVE2_PRODUCTION_USABLE,
    PROOF_SUITE_ID as WAVE2_PROOF_SUITE_ID,
    synthetic_reference_environment,
)
from experiments.bl_pq512_crypto_foundation.h6_complete_simulator import (
    run_complete_simulator_suite,
)
from experiments.bl_pq512_crypto_foundation.h6_migration_theorem import (
    run_h6_migration_theorem,
    verify_h6_migration_mutation_rejection,
)
from experiments.bl_pq512_crypto_foundation.h6_privacy_boundary import (
    run_h6_privacy_boundary,
)
from experiments.bl_pq512_crypto_foundation.h6_security_ledger import (
    require_h6_security_ledger,
)
from experiments.bl_pq512_crypto_foundation.h6_supply_chain import (
    verify_h6_supply_chain,
    write_h6_spdx,
)
from experiments.bl_pq512_crypto_foundation.internal_package_matrix import (
    package_evidence as build_open_package_evidence,
    validate_open_package_matrix,
)
from experiments.bl_pq512_crypto_foundation.ops_authority import verify_ops_authority
from tools.wave2_internal_conformance import build_receipt as build_wave2_conformance_receipt
from tools.wave4_conformance import build_receipt as build_wave4_conformance_receipt
from tools.whole_product_kat import build_receipt as build_whole_product_kat_receipt
from tools.wave2_spec_conformance import build_receipt as build_wave2_spec_receipt
from tools.privacy_v2_conformance import build_receipt as build_privacy_v2_receipt
from tools.remaining_internal_conformance import build_receipt as build_remaining_internal_receipt
STATUS: Final[str] = "INTERNAL_CONFORMANCE_RECONCILED_NONACTIVATING"
RELEASE_CANDIDATE_STATE: Final[str] = "NOT_DEPLOYMENT_READY"
PROOF_SUITE_STATE: Final[str] = "UNSELECTED"
PACKAGE_STATUS: Final[str] = "COMPLETE_INTERNAL_NONACTIVATING"
OPEN_PACKAGE_STATUS: Final[str] = "OPEN_INTERNAL_ENGINEERING"
PACKAGE_COUNT: Final[int] = 81
EXTERNAL_AUDIT_ID: Final[str] = "LB-002"
ACTIVATION_INPUT_IDS: Final[tuple[str, ...]] = ("LB-003", "LB-004", "LB-005")

PACKAGE_IDS: Final[tuple[str, ...]] = (
    *(f"S{index:02d}" for index in range(1, 13)),
    *(f"A{index:02d}" for index in range(1, 17)),
    *(f"Z{index:02d}" for index in range(1, 13)),
    *(f"P{index:02d}" for index in range(1, 13)),
    *(f"T{index:02d}" for index in range(1, 15)),
    *(f"O{index:02d}" for index in range(1, 7)),
    "O12",
    *(f"I{index:02d}" for index in range(1, 9)),
)

# This is the roadmap's current package ledger, not a claim that one shared
# conformance receipt closes every package.  Keep the production blockers
# visible until a package-specific acceptance gate actually closes them.
CLOSED_PACKAGE_IDS: Final[frozenset[str]] = frozenset(
    {
        "S01",
        "S03",
        "S05",
        "S06",
        "A12",
        "Z01",
        *(f"P{index:02d}" for index in range(1, 13)),
        *(f"O{index:02d}" for index in range(1, 7)),
        "O12",
        *(f"I{index:02d}" for index in range(1, 9)),
    }
)
OPEN_PACKAGE_IDS: Final[tuple[str, ...]] = tuple(
    package_id for package_id in PACKAGE_IDS if package_id not in CLOSED_PACKAGE_IDS
)
RELEASE_CANDIDATE_BLOCKERS: Final[tuple[str, ...]] = (
    "LB-001",
    "LB-006",
    "LB-007",
    "LB-009",
    "LB-010",
)

OPEN_PACKAGE_REASONS: Final[dict[str, str]] = {
    "S02": "runtime and production suite remain unselected",
    "S04": "final suite/state identity is not active",
    "S07": "complete composed security/error budget is not production-qualified",
    "S08": "field/PCS/query parameters remain candidate-only",
    "S09": "proof-suite identity and production transcript selection remain unset",
    "S10": "production genesis/migration/rotation policy remains unselected",
    "S11": "whole-product reproducible release/SBOM closure remains open",
    "S12": "complete production statement and acceptance contract remain open",
    "A01": "business capacity approval is not the current proof-profile evidence",
    "A02": "final claim/state/proof serialization remains unselected",
    "A03": "deployment-edge ordering and adapter equality remain open",
    "A04": "complete proof equality and collision boundary remain open",
    "A05": "complete-boundary shape qualification remains open",
    "A06": "final proof qualification of adjudication remains open",
    "A07": "durable claim-source registry and proof binding remain open",
    "A08": "durable oracle authority and proof binding remain open",
    "A09": "durable policy/ruleset registries remain open",
    "A10": "final proof qualification of adjudication ordering remains open",
    "A11": "selected durable payment/state plane remains open",
    "A13": "production state-operation proof binding remains open",
    "A14": "wide-value projection convergence remains open",
    "A15": "durable root/master commitment selection remains open",
    "A16": "complete claim proof/prover/verifier integration remains open",
    **{
        f"Z{index:02d}": reason
        for index, reason in {
            2: "production entropy/zeroization boundary remains open",
            3: "complete semantic witness-hiding composition remains open",
            4: "complete auxiliary/lookup masking inventory remains open",
            5: "production quotient/composition randomization remains open",
            6: "production domain separation and raw-opening exclusion remain open",
            7: "complete implicit-query masking inventory remains open",
            8: "production PCS mask commitment and folding entropy remain open",
            9: "durable transcript custody and complete statement binding remain open",
            10: "strict-PQ parameter qualification remains a hard gate",
            11: "complete abort/retry/crash/artifact simulator remains unqualified",
            12: "whole-product parser/fuzz/unlinkability qualification remains open",
        }.items()
    },
    **{
        f"T{index:02d}": reason
        for index, reason in {
            1: "one whole-product vector schema is not frozen",
            2: "approved-claim KATs are not closed across every implementation",
            3: "all denial/priority KATs are not closed at the final proof boundary",
            4: "dummy/padding/mixed/all-denied KATs are not final-proof evidence",
            5: "capacity and boundary KATs are not final-proof evidence",
            6: "replay/retry/correction/revision KATs are not final-proof evidence",
            7: "source/policy/oracle/signer attack closure is not final-proof evidence",
            8: "money/serialization attack closure is not final-proof evidence",
            9: "proof/profile/schema rebinding attack closure remains open",
            10: "whole-product property/fuzz coverage remains open",
            11: "whole-product artifact/linkability scan remains open",
            12: "whole-product leakage/shape qualification remains open",
            13: "complete-boundary resource measurement remains open",
            14: "whole-product language/proof/attack/integrity convergence remains open",
        }.items()
    },
}

_PUBLIC_BOUNDARY_SOURCE: Final[tuple[str, ...]] = (
    "app/privacy_v2.py",
    "app/public_inputs.py",
    "ops/native_stark_public_inputs_v2.json",
)
_PUBLIC_BOUNDARY_TESTS: Final[tuple[str, ...]] = (
    "tests/test_privacy_v2_abi.py",
    "tests/test_verifier_receipt.py",
    "tests/attacks/test_privacy_v2_bundle_attacks.py",
)

_GROUP_EVIDENCE: Final[dict[str, tuple[tuple[str, ...], tuple[str, ...]]]] = {
    "S": (
        (
            "docs/BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md",
            "experiments/bl_pq512_crypto_foundation/h6_security_ledger.py",
            "experiments/bl_pq512_crypto_foundation/h6_supply_chain.py",
            "ops/wave2_internal_release_profile.json",
            "tools/wave2_spec_conformance.py",
        ),
        (
            "tests/test_s07_s12_preimplementation_freeze.py",
            "tests/test_bl_pq512_h6_security_ledger.py",
            "tests/test_bl_pq512_h6_supply_chain.py",
            "tests/test_wave2_internal_completion.py",
            "tests/test_wave2_spec_conformance.py",
        ),
    ),
    "A": (
        (
            "experiments/fixed_shape_claim_air/profile.py",
            "experiments/fixed_shape_claim_air/executable_air.py",
            "experiments/fixed_shape_claim_air/claim_semantics_executable_air.py",
            "experiments/fixed_shape_claim_air/claim_payment_maps_executable_air.py",
            "experiments/fixed_shape_claim_air/master_commitments_executable_air.py",
            "tools/remaining_internal_conformance.py",
            *_PUBLIC_BOUNDARY_SOURCE,
        ),
        (
            "tests/test_r25_fixed_shape_semantics.py",
            "tests/test_r25_witness_schema_reference.py",
            "tests/test_wave1a_executable_air.py",
            "tests/test_wave1a_global_executable_air.py",
            "tests/test_wave1a_claim_semantics_executable_air.py",
            "tests/test_wave1a_authenticated_payment_maps_executable_air.py",
            "tests/test_wave1a_master_commitments_executable_air.py",
            "tests/test_remaining_internal_conformance.py",
            *_PUBLIC_BOUNDARY_TESTS,
        ),
    ),
    "Z": (
        (
            "experiments/bl_pq512_crypto_foundation/native_hiding_parameters.py",
            "experiments/bl_pq512_crypto_foundation/h6_complete_simulator.py",
            "experiments/bl_pq512_crypto_foundation/h6_privacy_boundary.py",
            "experiments/bl_pq512_crypto_foundation/h6_security_ledger.py",
            "experiments/bl_pq512_crypto_foundation/public_coin_governance.py",
            "experiments/bl_pq512_crypto_foundation/proof_body_reference.py",
            "tools/privacy_v2_conformance.py",
            "tools/remaining_internal_conformance.py",
        ),
        (
            "tests/test_bl_pq512_native_hiding_parameters.py",
            "tests/test_bl_pq512_fp16_hiding_simulator.py",
            "tests/test_bl_pq512_h6_complete_simulator.py",
            "tests/test_bl_pq512_h6_privacy_boundary.py",
            "tests/test_bl_pq512_selected_public_coin_schedule.py",
            "tests/test_bl_pq512_h6_proof_body_cross_language.py",
            "tests/attacks/test_bl_pq512_native_hiding_parameters_attacks.py",
            "tests/attacks/test_bl_pq512_h6_closure_attacks.py",
            "tests/test_privacy_v2_conformance.py",
            "tests/test_remaining_internal_conformance.py",
        ),
    ),
    "P": (
        (
            "experiments/bl_pq512_crypto_foundation/state_interface.py",
            "experiments/bl_pq512_crypto_foundation/state_plane.py",
            "experiments/bl_pq512_crypto_foundation/state_migration_recovery.py",
            "experiments/bl_pq512_crypto_foundation/wave3_nullifier_authority.py",
            "app/wave2_internal.py",
        ),
        (
            "tests/test_bl_pq512_state_interface.py",
            "tests/test_bl_pq512_state_plane.py",
            "tests/test_bl_pq512_state_migration_recovery.py",
            "tests/test_bl_pq512_wave3_nullifier_authority.py",
            "tests/attacks/test_bl_pq512_state_plane_attacks.py",
            "tests/attacks/test_bl_pq512_state_migration_recovery_attacks.py",
        ),
    ),
    "T": (
        (
            "experiments/bl_pq512_crypto_foundation/h6_complete_simulator.py",
            "experiments/bl_pq512_crypto_foundation/h6_evidence_manifest.py",
            "experiments/bl_pq512_crypto_foundation/h6_migration_theorem.py",
            "experiments/bl_pq512_crypto_foundation/benchmark_evidence.py",
            "tools/privacy_artifact_scan.py",
            "tools/remaining_internal_conformance.py",
        ),
        (
            "tests/test_foundation_vector_schema.py",
            "tests/test_bl_pq512_h6_complete_simulator.py",
            "tests/test_bl_pq512_h6_evidence_manifest.py",
            "tests/test_bl_pq512_h6_migration_theorem.py",
            "tests/test_bl_pq512_benchmark_evidence.py",
            "tests/test_privacy_artifact_scan.py",
            "tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py",
            "tests/test_remaining_internal_conformance.py",
        ),
    ),
    "O": (
        (
            "app/wave4_operations.py",
            "ops/wave4_release_profile.json",
            "tools/build_release_archive.py",
        ),
        (
            "tests/test_wave4_adapters_operations.py",
            "tests/test_build_release_archive.py",
            "tests/test_local_kms_simulator.py",
        ),
    ),
    "I": (
        (
            "app/wave4_adapters.py",
            "ops/wave4_sandbox_config.json",
        ),
        (
            "tests/test_wave4_adapters_operations.py",
            "tests/test_government_reference_adapter.py",
        ),
    ),
}


class InternalCompletionError(RuntimeError):
    """Raised when the all-internal receipt cannot be established."""


@contextmanager
def _all_synthetic_environment() -> Iterator[None]:
    """Enable every explicitly local reference path, then restore it exactly."""
    name = "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE"
    previous = os.environ.get(name)
    os.environ[name] = "1"
    try:
        with synthetic_reference_environment():
            yield
    finally:
        if previous is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _regular(root: Path, relative: str) -> Path:
    path = root / Path(relative)
    if path.is_symlink() or not path.is_file():
        raise InternalCompletionError(f"internal_completion_missing:{relative}")
    return path


def _evidence(root: Path, package_id: str) -> dict[str, object]:
    if package_id in OPEN_PACKAGE_IDS:
        evidence = build_open_package_evidence(root, package_id)
        return {
            **evidence,
            "status": OPEN_PACKAGE_STATUS,
            "closure_reason": OPEN_PACKAGE_REASONS[package_id],
        }
    group = package_id[0]
    try:
        sources, tests = _GROUP_EVIDENCE[group]
    except KeyError as exc:
        raise InternalCompletionError(f"internal_completion_group_missing:{group}") from exc
    for relative in (*sources, *tests):
        _regular(root, relative)
    source_records = tuple(
        {
            "path": relative,
            "bytes": _regular(root, relative).stat().st_size,
            "sha3_512": hashlib.sha3_512(_regular(root, relative).read_bytes()).hexdigest(),
        }
        for relative in (*sources, *tests)
    )
    status = PACKAGE_STATUS if package_id in CLOSED_PACKAGE_IDS else OPEN_PACKAGE_STATUS
    reason = None if package_id in CLOSED_PACKAGE_IDS else OPEN_PACKAGE_REASONS.get(package_id)
    if package_id not in CLOSED_PACKAGE_IDS and reason is None:
        raise InternalCompletionError(f"internal_completion_open_reason_missing:{package_id}")
    return {
        "package_id": package_id,
        "status": status,
        "closure_reason": reason,
        "sources": tuple(sources),
        "tests": tuple(tests),
        "evidence_sha3_512": hashlib.sha3_512(
            _canonical_json(
                {
                    "package_id": package_id,
                    "status": status,
                    "closure_reason": reason,
                    "records": source_records,
                }
            )
        ).hexdigest(),
    }


def _git_identity(root: Path) -> dict[str, object]:
    def run(*args: str) -> str:
        completed = subprocess.run(
            ("git", *args),
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return completed.stdout.strip()

    return {
        "head": run("rev-parse", "HEAD"),
        "branch": run("branch", "--show-current"),
        "worktree_dirty": bool(run("status", "--porcelain")),
        "protected_paths_dirty": bool(
            run(
                "status",
                "--porcelain",
                "--",
                "zk-cairo-sharp",
                "app/batch/nullifier.py",
                "app/batch/leaf.py",
                "app/batch/stark_binding.py",
                "app/batch/merkle.py",
                "app/batch/accumulators.py",
                "app/batch/batch_orchestrator.py",
                "app/oracle_attestation.py",
                "app/public_inputs.py",
                "app/canonical_encoding.py",
            )
        ),
    }


def _verify_public_boundary(root: Path) -> dict[str, object]:
    manifest = json.loads(_regular(root, "ops/native_stark_public_inputs_v2.json").read_text(encoding="utf-8"))
    names = tuple(field["name"] for field in manifest["fields"])
    assert_public_input_names_v2(names)
    if names != PUBLIC_INPUT_FIELD_NAMES_V2 or len(names) != 12:
        raise InternalCompletionError("internal_completion_public_boundary_invalid")
    candidate = json.loads(_regular(root, "docs/bl_pq512_suite_candidate_v1.json").read_text(encoding="utf-8"))
    if candidate.get("proofSuiteId") is not None or candidate.get("activationAllowed") is not False:
        raise InternalCompletionError("internal_completion_candidate_activation_boundary_invalid")
    return {
        "field_count": len(names),
        "field_names": names,
        "proofSuiteId": candidate.get("proofSuiteId"),
        "activationAllowed": candidate.get("activationAllowed"),
    }


def _verify_supply_chain(root: Path) -> dict[str, object]:
    crate = root / "experiments" / "bl_pq512_crypto_core"
    with tempfile.TemporaryDirectory(prefix="blind-ledger-internal-sbom-") as temporary:
        metadata_path = Path(temporary) / "cargo-metadata.json"
        sbom_path = Path(temporary) / "proof-core.spdx.json"
        completed = subprocess.run(
            (
                "cargo",
                "+1.96.0",
                "metadata",
                "--locked",
                "--offline",
                "--filter-platform",
                "x86_64-pc-windows-msvc",
                "--format-version",
                "1",
                "--manifest-path",
                str(crate / "Cargo.toml"),
            ),
            cwd=crate,
            check=True,
            capture_output=True,
            timeout=120,
        )
        metadata_path.write_bytes(completed.stdout)
        facts = write_h6_spdx(metadata_path, sbom_path)
        verified = verify_h6_supply_chain(metadata_path, sbom_path=sbom_path)
    if facts != verified:
        raise InternalCompletionError("internal_completion_supply_chain_readback_mismatch")
    return verified.as_public_dict()


def build_internal_completion_receipt(repo_root: Path | None = None) -> dict[str, object]:
    """Run the local/synthetic gates and return the all-package receipt."""
    root = (repo_root or Path(__file__).resolve().parents[2]).resolve()
    if root != Path(__file__).resolve().parents[2].resolve():
        raise InternalCompletionError("internal_completion_wrong_repository_root")
    if len(PACKAGE_IDS) != PACKAGE_COUNT or len(set(PACKAGE_IDS)) != PACKAGE_COUNT:
        raise InternalCompletionError("internal_completion_package_set_invalid")
    try:
        validate_open_package_matrix(root)
    except Exception as exc:
        raise InternalCompletionError("internal_completion_package_matrix_invalid") from exc

    boundary = _verify_public_boundary(root)
    git = _git_identity(root)
    if git["protected_paths_dirty"]:
        raise InternalCompletionError("internal_completion_protected_path_dirty")
    ops_status = verify_ops_authority()
    supply_chain = _verify_supply_chain(root)
    wave2 = build_wave2_conformance_receipt(root)
    wave4 = build_wave4_conformance_receipt(root)
    whole_product_kat = build_whole_product_kat_receipt(root)
    wave2_spec = build_wave2_spec_receipt(root)
    privacy_v2 = build_privacy_v2_receipt(root)
    remaining_internal = build_remaining_internal_receipt(root)

    with _all_synthetic_environment():
        simulator = run_complete_simulator_suite()
        privacy = run_h6_privacy_boundary()
        migration = run_h6_migration_theorem()
        verify_h6_migration_mutation_rejection()
        security = require_h6_security_ledger()

    checks = {
        "ops_authority": ops_status,
        "supply_chain": (
            supply_chain["package_count"] >= 40
            and supply_chain["source_pin_digest_sha3_512"]
            and supply_chain["sbom_digest_sha3_512"]
        ),
        "wave2_conformance": (
            wave2["privacy"]["reference_boundary_ok"] is True
            and wave2["privacy"]["h6_candidate_controls_ok"] is True
            and wave2["custody"]["software_kms_roundtrip"] is True
            and wave2["activation_allowed"] is False
            and wave2["proofSuiteId"] is None
        ),
        "wave4_conformance": (
            wave4["adapter"]["ok"] is True
            and wave4["operations"]["ok"] is True
            and wave4["release"]["ok"] is True
            and wave4["activation_allowed"] is False
            and wave4["proofSuiteId"] is None
        ),
        "public_boundary": boundary["field_count"] == 12,
        "whole_product_kat": (
            whole_product_kat["status"]
            == "WHOLE_PRODUCT_COMMITMENT_KAT_VERIFIED_NONACTIVATING"
            and whole_product_kat["case_count"] == 6
            and whole_product_kat["profile_count"] == 2
            and whole_product_kat["outcome_count"] == 3
            and whole_product_kat["public_field_count"] == 12
            and whole_product_kat["sidecar_bytes"] == 744
            and whole_product_kat["proof_body_bytes"] == 696
            and whole_product_kat["proofSuiteId"] is None
            and whole_product_kat["activationAllowed"] is False
            and whole_product_kat["private_material_in_manifest"] is False
        ),
        "wave2_spec_conformance": (
            wave2_spec["status"] == "WAVE2_SPECIFICATION_CONFORMANCE_VERIFIED_NONACTIVATING"
            and len(wave2_spec["package_status"]) == 8
            and all(
                status == PACKAGE_STATUS
                for status in wave2_spec["package_status"].values()
            )
            and wave2_spec["proofSuiteId"] is None
            and wave2_spec["activationAllowed"] is False
            and wave2_spec["productionUsable"] is False
        ),
        "privacy_v2_conformance": (
            privacy_v2["status"] == "PRIVACY_V2_BOUNDED_CONFORMANCE_VERIFIED_NONACTIVATING"
            and privacy_v2["sidecar_bytes"] == 744
            and privacy_v2["mutation_cases"] == 34
            and privacy_v2["artifact_findings"] == 0
            and privacy_v2["private_public_payload"] is False
            and privacy_v2["proofSuiteId"] is None
            and privacy_v2["activationAllowed"] is False
            and privacy_v2["productionUsable"] is False
            and set(privacy_v2["package_status"]) == {"Z02", "Z11", "Z12"}
        ),
        "remaining_internal_conformance": (
            remaining_internal["status"]
            == "REMAINING_INTERNAL_CONFORMANCE_VERIFIED_NONACTIVATING"
            and remaining_internal["package_count"] == 31
            and all(
                status == PACKAGE_STATUS
                for status in remaining_internal["package_status"].values()
            )
            and remaining_internal["profile_and_boundary"]["field_count"] == 12
            and remaining_internal["native_hiding"]["table_count"] == 16
            and remaining_internal["security_ledger_qualifies"] is True
            and remaining_internal["backend"]["production_native_stark_verifier"] is False
            and remaining_internal["proofSuiteId"] is None
            and remaining_internal["activationAllowed"] is False
            and remaining_internal["productionUsable"] is False
        ),
        "privacy_v2_simulator": simulator["repeated_proof_shape_fixed"] is True,
        "native_hiding_reference": (
            simulator["native_hiding_simulated"] is True
            and simulator["native_hiding"]["fixed_shape_verified"] is True
            and simulator["native_hiding"]["private_opening_verified"] is True
            and simulator["native_hiding"]["simulator_shape_verified"] is True
            and simulator["native_hiding"]["error_shape_verified"] is True
        ),
        "privacy_v2_boundary": all(
            privacy.get(key) is True
            for key in (
                "fixed_shape_for_all_outcomes",
                "fixed_shape_for_all_malformed_cases",
                "abort_shape_matches_malformed",
                "telemetry_private_payload_absent",
                "zeroization_verified",
                "cleanup_verified",
                "unlinkability_observable_shapes_verified",
            )
        ),
        "migration_recovery": all(
            migration.get(key) is True
            for key in (
                "logical_root_equivalence_proved",
                "manifest_equivalence_proved",
                "sequence_equivalence_proved",
                "epoch_monotonicity_proved",
                "rollback_recovery_epoch_advance_proved",
                "mixed_version_rejection_proved",
                "cas_publication_required",
            )
        ),
        "security_ledger": security.qualifies,
        "wave2_activation_closed": (
            WAVE2_PROOF_SUITE_ID is None
            and WAVE2_ACTIVATION_ALLOWED is False
            and WAVE2_PRODUCTION_USABLE is False
            and WAVE2_NETWORK_ACCESS is False
            and WAVE2_LIVE_CREDENTIALS is False
        ),
    }
    if not all(checks.values()):
        failed = tuple(key for key, value in checks.items() if not value)
        raise InternalCompletionError(f"internal_completion_gate_failed:{','.join(failed)}")

    package_evidence = tuple(_evidence(root, package_id) for package_id in PACKAGE_IDS)
    package_statuses = {
        package_id: PACKAGE_STATUS if package_id in CLOSED_PACKAGE_IDS else OPEN_PACKAGE_STATUS
        for package_id in PACKAGE_IDS
    }
    if len(CLOSED_PACKAGE_IDS) != 33 or len(OPEN_PACKAGE_IDS) != 48:
        raise InternalCompletionError("internal_completion_roadmap_count_invalid")
    checks["package_ledger"] = (
        tuple(package_statuses) == PACKAGE_IDS
        and tuple(package_id for package_id in PACKAGE_IDS if package_statuses[package_id] == OPEN_PACKAGE_STATUS)
        == OPEN_PACKAGE_IDS
    )
    checks["release_blockers_preserved"] = (
        RELEASE_CANDIDATE_STATE == "NOT_DEPLOYMENT_READY"
        and len(RELEASE_CANDIDATE_BLOCKERS) == 5
        and PROOF_SUITE_STATE == "UNSELECTED"
    )
    if not all(checks.values()):
        failed = tuple(key for key, value in checks.items() if not value)
        raise InternalCompletionError(f"internal_completion_gate_failed:{','.join(failed)}")
    return {
        "schema": "blind_ledger_internal_conformance_receipt_v2",
        "status": STATUS,
        "release_candidate_state": RELEASE_CANDIDATE_STATE,
        "proof_suite_state": PROOF_SUITE_STATE,
        "proofSuiteId": None,
        "activation_allowed": False,
        "production_usable": False,
        "network_access": False,
        "live_credentials": False,
        "internal_engineering_packages": PACKAGE_COUNT,
        "internal_complete": sum(status == PACKAGE_STATUS for status in package_statuses.values()),
        "internal_open": sum(status == OPEN_PACKAGE_STATUS for status in package_statuses.values()),
        "open_package_ids": OPEN_PACKAGE_IDS,
        "release_candidate_blockers": RELEASE_CANDIDATE_BLOCKERS,
        "package_statuses": package_statuses,
        "package_evidence": package_evidence,
        "checks": checks,
        "public_boundary": boundary,
        "security_ledger": security.as_public_dict(),
        "supply_chain": supply_chain,
        "wave2": wave2,
        "wave4": wave4,
        "whole_product_kat": whole_product_kat,
        "wave2_spec": wave2_spec,
        "privacy_v2": privacy_v2,
        "remaining_internal": remaining_internal,
        "migration": migration,
        "privacy": privacy,
        "simulator": {
            key: value
            for key, value in simulator.items()
            if key != "records"
        },
        "source_identity": git,
        "external_assurance_open": (EXTERNAL_AUDIT_ID,),
        "activation_inputs_open": ACTIVATION_INPUT_IDS,
    }


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    receipt = build_internal_completion_receipt(root)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


__all__: tuple[str, ...] = (
    "ACTIVATION_INPUT_IDS",
    "EXTERNAL_AUDIT_ID",
    "InternalCompletionError",
    "PACKAGE_COUNT",
    "PACKAGE_IDS",
    "PACKAGE_STATUS",
    "OPEN_PACKAGE_STATUS",
    "CLOSED_PACKAGE_IDS",
    "OPEN_PACKAGE_IDS",
    "RELEASE_CANDIDATE_BLOCKERS",
    "PROOF_SUITE_STATE",
    "RELEASE_CANDIDATE_STATE",
    "STATUS",
    "build_internal_completion_receipt",
)


if __name__ == "__main__":
    raise SystemExit(main())
