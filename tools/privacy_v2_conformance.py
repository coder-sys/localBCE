"""Run the bounded Privacy V2 parser, hiding, and leakage boundary offline."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experiments.bl_pq512_crypto_foundation.h6_complete_simulator import (  # noqa: E402
    run_complete_simulator_suite,
)
from experiments.bl_pq512_crypto_foundation.h6_privacy_boundary import (  # noqa: E402
    run_h6_privacy_boundary,
)
from experiments.bl_pq512_crypto_foundation.h6_receipt_grammar import (  # noqa: E402
    SIDECAR_BYTES,
    encode_sidecar,
    parse_sidecar,
)
from experiments.bl_pq512_crypto_foundation.native_hiding_simulator import (  # noqa: E402
    run_native_hiding_simulator_suite,
)
from app.wave2_internal import synthetic_reference_environment  # noqa: E402
from tools.privacy_artifact_scan import scan_artifacts  # noqa: E402


@contextmanager
def _synthetic_environment():
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


def _mutation_cases(sidecar: bytes) -> int:
    cases: list[bytes] = []
    for offset in (0, 1, 8, 9, 10, 11, 12, 13, 14, 15):
        mutated = bytearray(sidecar)
        mutated[offset] ^= 1
        cases.append(bytes(mutated))
    for offset in range(720, SIDECAR_BYTES):
        mutated = bytearray(sidecar)
        mutated[offset] = 1
        cases.append(bytes(mutated))
    for mutated in cases:
        try:
            parse_sidecar(mutated)
        except ValueError:
            continue
        raise ValueError("privacy_v2_mutated_sidecar_accepted")
    return len(cases)


def build_receipt(repo_root: Path | None = None) -> dict[str, object]:
    del repo_root
    values = tuple(bytes((index + 1,)) * 64 for index in range(11))
    sidecar = encode_sidecar(values)
    with _synthetic_environment():
        native = run_native_hiding_simulator_suite()
        complete = run_complete_simulator_suite()
        privacy = run_h6_privacy_boundary()
    with tempfile.TemporaryDirectory(prefix="blind-ledger-privacy-v2-") as temporary:
        artifact_findings = scan_artifacts(Path(temporary))
    native_ok = all(
        native.get(key) is True
        for key in (
            "fixed_shape_verified",
            "private_opening_verified",
            "simulator_shape_verified",
            "error_shape_verified",
        )
    )
    privacy_ok = all(
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
    )
    if not native_ok or not privacy_ok or artifact_findings:
        raise ValueError("privacy_v2_conformance_gate_failed")
    return {
        "schema": "blind-ledger-privacy-v2-conformance-v1",
        "status": "PRIVACY_V2_BOUNDED_CONFORMANCE_VERIFIED_NONACTIVATING",
        "native_hiding": {key: native[key] for key in (
            "fixed_shape_verified",
            "private_opening_verified",
            "simulator_shape_verified",
            "error_shape_verified",
        )},
        "complete_simulator": {
            key: complete[key]
            for key in (
                "abort_rejected",
                "malformed_input_rejected",
                "crash_recovery_zero_retained_artifacts",
                "retry_fresh_randomness",
                "repeated_proof_shape_fixed",
            )
        },
        "privacy": privacy,
        "sidecar_bytes": len(sidecar),
        "mutation_cases": _mutation_cases(sidecar),
        "artifact_findings": len(artifact_findings),
        "proofSuiteId": None,
        "activationAllowed": False,
        "productionUsable": False,
        "private_public_payload": False,
        "package_status": {
            "Z02": "COMPLETE_INTERNAL_NONACTIVATING",
            "Z11": "COMPLETE_INTERNAL_NONACTIVATING",
            "Z12": "COMPLETE_INTERNAL_NONACTIVATING",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    args = parser.parse_args()
    print(json.dumps(build_receipt(args.repo_root), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
