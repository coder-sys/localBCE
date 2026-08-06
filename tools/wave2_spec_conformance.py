"""Reconcile the Wave 2 specification packages at a local nonactivating boundary."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.wave2_internal import synthetic_reference_environment  # noqa: E402
from experiments.bl_pq512_crypto_foundation.h6_migration_theorem import (  # noqa: E402
    run_h6_migration_theorem,
    verify_h6_migration_mutation_rejection,
)
from experiments.bl_pq512_crypto_foundation.h6_receipt_grammar import (  # noqa: E402
    encode_receipt,
    encode_sidecar,
    parse_receipt,
    parse_sidecar,
)
from experiments.bl_pq512_crypto_foundation.h6_security_ledger import (  # noqa: E402
    require_h6_security_ledger,
)
from experiments.bl_pq512_crypto_foundation.native_hiding_simulator import (  # noqa: E402
    run_native_hiding_simulator_suite,
)
from experiments.bl_pq512_crypto_foundation.proof_body_reference import (  # noqa: E402
    ProofGrammar,
    UNSELECTED_GRAMMAR_STATUS,
)
from tools.wave2_internal_conformance import build_receipt as build_wave2_receipt  # noqa: E402


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


def _load(root: Path, relative: str) -> dict[str, object]:
    value = json.loads((root / relative).read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError(f"wave2_spec_{relative}_object_required")
    return value


def build_receipt(repo_root: Path | None = None) -> dict[str, object]:
    root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
    candidate = _load(root, "docs/bl_pq512_suite_candidate_v1.json")
    profile = _load(root, "ops/wave2_internal_release_profile.json")
    if (
        candidate["status"] != "CANDIDATE_UNQUALIFIED"
        or candidate["activationAllowed"] is not False
        or candidate["proofSuiteId"] is not None
        or candidate["syntheticOnly"] is not True
        or candidate["externalAbi"]["fieldCount"] != 12
        or profile["public_boundary"]
        != {"field_count": 12, "sidecar_bytes": 744, "proof_body_grammar": "BLPQPF01_REFERENCE_ONLY"}
        or profile["proofSuiteId"] is not None
        or profile["activation_allowed"] is not False
        or profile["production_usable"] is not False
    ):
        raise ValueError("wave2_spec_candidate_boundary_invalid")

    values = tuple(bytes((index + 1,)) * 64 for index in range(11))
    sidecar = encode_sidecar(values)
    receipt = encode_receipt(values[:7])
    if parse_sidecar(sidecar) != values or parse_receipt(receipt) != values[:7]:
        raise ValueError("wave2_spec_grammar_readback_failed")
    malformed = bytearray(sidecar)
    malformed[-1] = 1
    try:
        parse_sidecar(bytes(malformed))
    except ValueError:
        pass
    else:
        raise ValueError("wave2_spec_reserved_byte_accepted")

    grammar = ProofGrammar.unselected()
    if grammar.status != UNSELECTED_GRAMMAR_STATUS or grammar.identity is not None:
        raise ValueError("wave2_spec_unselected_grammar_invalid")

    with _synthetic_environment():
        migration = run_h6_migration_theorem()
        verify_h6_migration_mutation_rejection()
        hiding = run_native_hiding_simulator_suite()
        wave2 = build_wave2_receipt(root)
    security = require_h6_security_ledger()
    migration_ok = all(
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
    )
    hiding_ok = all(
        hiding.get(key) is True
        for key in (
            "fixed_shape_verified",
            "private_opening_verified",
            "simulator_shape_verified",
            "error_shape_verified",
        )
    )
    if not migration_ok or not hiding_ok or not security.qualifies:
        raise ValueError("wave2_spec_conformance_gate_failed")
    package_status = {
        package_id: "COMPLETE_INTERNAL_NONACTIVATING"
        for package_id in ("S02", "S04", *(f"S{index:02d}" for index in range(7, 13)))
    }
    return {
        "schema": "blind-ledger-wave2-spec-conformance-v1",
        "status": "WAVE2_SPECIFICATION_CONFORMANCE_VERIFIED_NONACTIVATING",
        "package_status": package_status,
        "sidecar_bytes": len(sidecar),
        "receipt_bytes": len(receipt),
        "unselected_grammar": True,
        "security_ledger_qualifies": security.qualifies,
        "migration": migration,
        "native_hiding": {
            key: hiding[key]
            for key in (
                "fixed_shape_verified",
                "private_opening_verified",
                "simulator_shape_verified",
                "error_shape_verified",
            )
        },
        "wave2_reference": {
            "proofSuiteId": wave2["proofSuiteId"],
            "activation_allowed": wave2["activation_allowed"],
            "production_usable": wave2["production_usable"],
        },
        "proofSuiteId": None,
        "activationAllowed": False,
        "productionUsable": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    args = parser.parse_args()
    print(json.dumps(build_receipt(args.repo_root), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
