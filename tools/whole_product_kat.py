"""Run the commitment-only whole-product KAT manifest offline."""

from __future__ import annotations

import argparse
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experiments.fixed_shape_claim_air.whole_product_vector_corpus import (
    manifest_sha3_512,
    parse_manifest,
)


def build_receipt(repo_root: Path | None = None) -> dict[str, object]:
    root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
    manifest = root / "test_data" / "bl_pq512_whole_product_vectors.json"
    encoded = manifest.read_bytes()
    parsed = parse_manifest(encoded)
    cases = parsed["cases"]
    return {
        "schema": "blind-ledger-whole-product-kat-receipt-v1",
        "status": "WHOLE_PRODUCT_COMMITMENT_KAT_VERIFIED_NONACTIVATING",
        "manifest": str(manifest.relative_to(root)).replace("\\", "/"),
        "manifest_sha3_512": manifest_sha3_512(encoded),
        "case_count": len(cases),
        "profile_count": len({case["profile"] for case in cases}),
        "outcome_count": len({case["outcome"] for case in cases}),
        "public_field_count": len(parsed["fieldNames"]),
        "sidecar_bytes": {case["sidecar"]["byteLength"] for case in cases}.pop(),
        "proof_body_bytes": {case["proof"]["bodyByteLength"] for case in cases}.pop(),
        "proofSuiteId": None,
        "activationAllowed": False,
        "productionUsable": False,
        "private_material_in_manifest": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    args = parser.parse_args()
    print(json.dumps(build_receipt(args.repo_root), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
