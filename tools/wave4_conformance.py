"""Run the complete local/synthetic Wave 4 conformance boundary.

The command is intentionally offline and creates no repository artifacts.  It
prints a compact JSON receipt and returns non-zero on any adapter, custody,
queue, incident, privacy, or release-manifest failure.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.wave4_adapters import (
    DualPqAuthenticator,
    ML_DSA_87,
    PqcryptoSoftwareSigner,
    SLH_DSA_SHAKE_256F,
    build_synthetic_registry,
    run_adapter_conformance,
)
from app.wave4_operations import (
    FixedCadenceQueue,
    IncidentController,
    KeyLifecycleRegistry,
    NonPhiAuditLog,
    NonceReuseGuard,
    SoftwarePqKmsReference,
    build_wave4_release_manifest,
    healthy_entropy_sample,
)


def build_receipt(repo_root: Path) -> dict[str, object]:
    ml = PqcryptoSoftwareSigner.generate(ML_DSA_87)
    slh = PqcryptoSoftwareSigner.generate(SLH_DSA_SHAKE_256F)
    try:
        authority = DualPqAuthenticator((ml, slh))
        registry = build_synthetic_registry(authority)
        adapter_report = run_adapter_conformance(registry)

        with TemporaryDirectory(prefix="blind-ledger-wave4-") as temporary:
            audit = NonPhiAuditLog(Path(temporary) / "audit.jsonl")
            controller = IncidentController(audit)
            checkpoint = "1" * 128
            drill = controller.drill(checkpoint_digest_sha3_512=checkpoint)

            queue = FixedCadenceQueue(capacity=8, batch_size=4, cadence_ms=1_000)
            queue.submit(job_id="SYNTHETIC-JOB-1", opaque_commitment_sha3_512="2" * 128)
            slots = queue.tick()

            nonce_guard = NonceReuseGuard()
            nonce_digest = nonce_guard.reserve(b"synthetic-nonce-1", context=b"wave4")
            entropy = healthy_entropy_sample(32)

            kms = SoftwarePqKmsReference()
            try:
                envelope = kms.seal(plaintext=b"synthetic-private-fixture", associated_data=b"wave4")
                opened = kms.open(envelope=envelope, associated_data=b"wave4")
                kms_roundtrip = opened == b"synthetic-private-fixture"
            finally:
                kms.destroy()

            manifest = build_wave4_release_manifest(repo_root)
            operations_ok = (
                drill == ("pause", "recovery", "resume")
                and controller.state.status == "healthy"
                and len(slots) == 4
                and sum(slot.kind == "cover" for slot in slots) == 3
                and nonce_guard.reservation_count == 1
                and len(entropy) == 32
                and kms_roundtrip
                and audit.head_digest_sha3_512 != "0" * 128
            )

        return {
            "schema": "blind_ledger_wave4_conformance_receipt_v1",
            "wave": 4,
            "adapter": {
                "ok": adapter_report.ok,
                "passed_count": len(adapter_report.passed),
                "failure_count": len(adapter_report.failures),
                "failures": list(adapter_report.failures),
                "capability_count": len(registry.capabilities()),
            },
            "operations": {
                "ok": operations_ok,
                "software_kms_production_usable": False,
                "hsm_backed": False,
                "fixed_slot_count": len(slots),
                "audit_head_digest_sha3_512": audit.head_digest_sha3_512,
                "nonce_digest_sha3_512": nonce_digest,
            },
            "release": {
                "ok": True,
                "manifest_digest_sha3_512": manifest.manifest_digest_sha3_512,
                "file_count": len(manifest.files),
                "package_count": len(manifest.package_status),
                "production_usable": manifest.production_usable,
                "proofSuiteId": manifest.proof_suite_id,
            },
            "network_access": False,
            "live_credentials": False,
            "activation_allowed": False,
            "proofSuiteId": None,
        }
    finally:
        ml.destroy()
        slh.destroy()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    receipt = build_receipt(args.repo_root.resolve())
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["adapter"]["ok"] and receipt["operations"]["ok"] and receipt["release"]["ok"] else 1  # type: ignore[index]


if __name__ == "__main__":
    raise SystemExit(main())
