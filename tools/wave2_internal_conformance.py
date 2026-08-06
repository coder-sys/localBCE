"""Run the local/synthetic Wave 2 internal reference boundary.

This runner exercises fixed-K Privacy V2 shape, the exact 12-field public
projection, the 744-byte sidecar, the bounded proof-body grammar, the
nonactivating reference verifier, H6 privacy controls, and the software PQ
KMS reference.  It never opens a network socket, consumes live credentials,
or emits a production proof-suite identity.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.wave2_internal import (  # noqa: E402
    ACTIVATION_ALLOWED,
    LIVE_CREDENTIALS,
    MODULE_STATUS,
    NETWORK_ACCESS,
    PRODUCTION_USABLE,
    PUBLIC_FIELD_COUNT,
    SIDECAR_BYTES,
    build_reference_artifact,
    build_synthetic_schedule,
    synthetic_reference_environment,
    verify_reference_artifact,
)
from app.wave4_operations import SoftwarePqKmsReference  # noqa: E402
from experiments.bl_pq512_crypto_foundation.h6_privacy_boundary import (  # noqa: E402
    run_h6_privacy_boundary,
)


def _profile_receipt(fixed_k: int) -> dict[str, object]:
    cases = (
        build_reference_artifact(
            build_synthetic_schedule(fixed_k, label=f"conformance-k{fixed_k}-cover")
        ),
        build_reference_artifact(
            build_synthetic_schedule(
                fixed_k,
                real_slot_indices=(0,),
                label=f"conformance-k{fixed_k}-one",
            )
        ),
        build_reference_artifact(
            build_synthetic_schedule(
                fixed_k,
                real_slot_indices=tuple(range(fixed_k)),
                label=f"conformance-k{fixed_k}-full",
            )
        ),
    )
    verification_digests = [verify_reference_artifact(artifact).hex() for artifact in cases]
    receipts = [artifact.public_receipt() for artifact in cases]
    public_encodings = [json.dumps(receipt, sort_keys=True, separators=(",", ":")) for receipt in receipts]
    forbidden = (
        "approvedAmountCents",
        "paymentAmountCents",
        "claimCount",
        "approvedCount",
        "deniedCount",
        "encryptedPayload",
        '"witness":',
        "12500",
    )
    shape_equal = len({receipt["proof_body_bytes"] for receipt in receipts}) == 1 and len(
        {receipt["private_wire_bytes"] for receipt in receipts}
    ) == 1
    privacy_clean = all(not any(token in encoded for token in forbidden) for encoded in public_encodings)
    if not shape_equal or not privacy_clean or any(len(digest) != 128 for digest in verification_digests):
        raise RuntimeError("wave2_internal_conformance_profile_failed")
    return {
        "profile": f"K{fixed_k}_LOCAL_SYNTHETIC",
        "case_count": len(cases),
        "verified_case_count": len(verification_digests),
        "fixed_shape": shape_equal,
        "public_field_count": PUBLIC_FIELD_COUNT,
        "sidecar_bytes": SIDECAR_BYTES,
        "proof_body_bytes": receipts[0]["proof_body_bytes"],
        "private_wire_bytes": receipts[0]["private_wire_bytes"],
        "privacy_clean": privacy_clean,
        "verification_digests_sha3_512": verification_digests,
    }


def build_receipt(repo_root: Path) -> dict[str, object]:
    del repo_root  # The runner is source-local and does not write or package files.
    with synthetic_reference_environment():
        profiles = [_profile_receipt(128), _profile_receipt(512)]
        h6 = run_h6_privacy_boundary()
        kms = SoftwarePqKmsReference()
        try:
            envelope = kms.seal(
                plaintext=b"synthetic-private-witness-fixture",
                associated_data=b"wave2-internal-conformance",
            )
            opened = kms.open(
                envelope=envelope,
                associated_data=b"wave2-internal-conformance",
            )
            kms_roundtrip = opened == b"synthetic-private-witness-fixture"
        finally:
            kms.destroy()
    privacy_ok = all(profile["fixed_shape"] and profile["privacy_clean"] for profile in profiles)
    h6_ok = all(
        h6.get(key) is True
        for key in (
            "fixed_shape_for_all_outcomes",
            "fixed_shape_for_all_malformed_cases",
            "abort_shape_matches_malformed",
            "telemetry_private_payload_absent",
            "zeroization_verified",
            "cleanup_verified",
            "unlinkability_observable_shapes_verified",
        )
    ) and h6.get("proofSuiteId") is None and h6.get("activationAllowed") is False
    return {
        "schema": "blind_ledger_wave2_internal_conformance_receipt_v1",
        "module_status": MODULE_STATUS,
        "profiles": profiles,
        "privacy": {
            "reference_boundary_ok": privacy_ok,
            "h6_candidate_controls_ok": h6_ok,
            "proof_backend": "REFERENCE_GRAMMAR_AND_PUBLIC_BINDING_ONLY",
            "zero_knowledge_proof_verified": False,
        },
        "custody": {
            "software_kms_roundtrip": kms_roundtrip,
            "software_only": True,
            "hsm_backed": False,
            "fips_validated": False,
            "production_usable": False,
        },
        "network_access": NETWORK_ACCESS,
        "live_credentials": LIVE_CREDENTIALS,
        "activation_allowed": ACTIVATION_ALLOWED,
        "production_usable": PRODUCTION_USABLE,
        "proofSuiteId": None,
        "internal_only": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    receipt = build_receipt(args.repo_root.resolve())
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["privacy"]["reference_boundary_ok"] and receipt["custody"]["software_kms_roundtrip"] else 1  # type: ignore[index]


if __name__ == "__main__":
    raise SystemExit(main())
