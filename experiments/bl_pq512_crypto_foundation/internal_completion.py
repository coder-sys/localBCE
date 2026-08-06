"""One local, synthetic receipt for all internally finishable packages.

This module does not select a production proof suite or enable activation.  It
reconciles the already implemented local proof, privacy, state, adapter,
rollup, custody, supply-chain, and release boundaries into one fail-closed
engineering receipt.  The final independent audit and operator activation
inputs remain separate gates.
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
from experiments.bl_pq512_crypto_foundation.ops_authority import verify_ops_authority
from tools.wave2_internal_conformance import build_receipt as build_wave2_conformance_receipt
from tools.wave4_conformance import build_receipt as build_wave4_conformance_receipt
from app.wave4_adapters import (
    DualPqAuthenticator,
    ML_DSA_87,
    PqcryptoSoftwareSigner,
    SLH_DSA_SHAKE_256F,
)
from app.wave5_rollup import PqGovernance, run_wave5_conformance


STATUS: Final[str] = "INTERNAL_ENGINEERING_COMPLETE_NONACTIVATING"
RELEASE_CANDIDATE_STATE: Final[str] = "DEPLOYMENT_READY_AUDIT_PENDING"
PROOF_SUITE_STATE: Final[str] = "UNSELECTED"
PACKAGE_STATUS: Final[str] = "COMPLETE_INTERNAL_NONACTIVATING"
PACKAGE_COUNT: Final[int] = 93
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
    *(f"R{index:02d}" for index in range(1, 13)),
)

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
        ),
        (
            "tests/test_s07_s12_preimplementation_freeze.py",
            "tests/test_bl_pq512_h6_security_ledger.py",
            "tests/test_bl_pq512_h6_supply_chain.py",
            "tests/test_wave2_internal_completion.py",
        ),
    ),
    "A": (
        (
            "experiments/fixed_shape_claim_air/profile.py",
            "experiments/fixed_shape_claim_air/executable_air.py",
            "experiments/fixed_shape_claim_air/claim_semantics_executable_air.py",
            "experiments/fixed_shape_claim_air/claim_payment_maps_executable_air.py",
            "experiments/fixed_shape_claim_air/master_commitments_executable_air.py",
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
        ),
        (
            "tests/test_foundation_vector_schema.py",
            "tests/test_bl_pq512_h6_complete_simulator.py",
            "tests/test_bl_pq512_h6_evidence_manifest.py",
            "tests/test_bl_pq512_h6_migration_theorem.py",
            "tests/test_bl_pq512_benchmark_evidence.py",
            "tests/test_privacy_artifact_scan.py",
            "tests/attacks/test_bl_pq512_h6_qualification_preflight_attacks.py",
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
    "R": (
        (
            "app/wave5_rollup.py",
            "ops/wave5_release_profile.json",
            "docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md",
        ),
        (
            "tests/test_wave5_rollup.py",
            "tests/attacks/test_wave5_rollup_attacks.py",
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
    return {
        "package_id": package_id,
        "status": PACKAGE_STATUS,
        "sources": tuple(sources),
        "tests": tuple(tests),
        "evidence_sha3_512": hashlib.sha3_512(_canonical_json(source_records)).hexdigest(),
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
                "contracts",
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


def _verify_wave5_conformance() -> dict[str, object]:
    ml = PqcryptoSoftwareSigner.generate(ML_DSA_87)
    slh = PqcryptoSoftwareSigner.generate(SLH_DSA_SHAKE_256F)
    try:
        return run_wave5_conformance(PqGovernance(DualPqAuthenticator((ml, slh)))).as_dict()
    finally:
        ml.destroy()
        slh.destroy()


def build_internal_completion_receipt(repo_root: Path | None = None) -> dict[str, object]:
    """Run the local/synthetic gates and return the all-package receipt."""
    root = (repo_root or Path(__file__).resolve().parents[2]).resolve()
    if root != Path(__file__).resolve().parents[2].resolve():
        raise InternalCompletionError("internal_completion_wrong_repository_root")
    if len(PACKAGE_IDS) != PACKAGE_COUNT or len(set(PACKAGE_IDS)) != PACKAGE_COUNT:
        raise InternalCompletionError("internal_completion_package_set_invalid")

    boundary = _verify_public_boundary(root)
    git = _git_identity(root)
    if git["protected_paths_dirty"]:
        raise InternalCompletionError("internal_completion_protected_path_dirty")
    ops_status = verify_ops_authority()
    supply_chain = _verify_supply_chain(root)
    wave2 = build_wave2_conformance_receipt(root)
    wave4 = build_wave4_conformance_receipt(root)
    wave5 = _verify_wave5_conformance()

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
        "wave5_conformance": (
            wave5["rollback_ok"] is True
            and wave5["network_access"] is False
            and wave5["live_credentials"] is False
            and wave5["production_usable"] is False
            and wave5["activation_allowed"] is False
            and wave5["proofSuiteId"] is None
        ),
        "public_boundary": boundary["field_count"] == 12,
        "privacy_v2_simulator": simulator["repeated_proof_shape_fixed"] is True,
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
    package_statuses = {package_id: PACKAGE_STATUS for package_id in PACKAGE_IDS}
    return {
        "schema": "blind_ledger_internal_completion_receipt_v1",
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
        "internal_open": 0,
        "package_statuses": package_statuses,
        "package_evidence": package_evidence,
        "checks": checks,
        "public_boundary": boundary,
        "security_ledger": security.as_public_dict(),
        "supply_chain": supply_chain,
        "wave2": wave2,
        "wave4": wave4,
        "wave5": wave5,
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
    "PROOF_SUITE_STATE",
    "RELEASE_CANDIDATE_STATE",
    "STATUS",
    "build_internal_completion_receipt",
)


if __name__ == "__main__":
    raise SystemExit(main())
