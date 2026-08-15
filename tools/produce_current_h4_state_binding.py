"""Produce one synthetic, independently checked state component for H4.

This is the smallest executable state-side producer for the current H4
calibration lane.  It deliberately uses the repository's real state AIR,
selected streaming prover, dual-PQ contributor path, and v3 binding grammar.
It never selects a proof suite or enables activation.  The resulting binding
is private run input and must not be copied into a source archive.
"""

from __future__ import annotations

import argparse
from hashlib import sha3_512
import json
import os
from pathlib import Path
import sys

from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    NativeSlhDsaAdapter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import Contributor
from experiments.bl_pq512_crypto_foundation.state_air_proof import (
    build_state_air_binding_bytes,
    prove_state_air,
)
from experiments.bl_pq512_crypto_foundation.state_plane import (
    StateEntry,
    StateOperation,
    StateSnapshot,
    build_state_transition,
    independently_verify_state_transition,
)
from experiments.fixed_shape_claim_air.profile import get_profile


def _wide(label: str) -> bytes:
    return sha3_512(b"BL/PQ512/WAVE2/CURRENT-H4/" + label.encode("ascii")).digest()


def _write_once(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"output_exists:{path}")
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _build_state(profile_id: str):
    profile = get_profile(profile_id)
    before = StateSnapshot.empty(profile_id, capacity=profile.claim_slots, epoch=7)
    operations = []
    for index in range(profile.claim_slots):
        old = StateEntry.empty(index)
        new = (
            StateEntry(index, True, _wide(f"state-key-{profile_id}"), _wide(f"state-value-{profile_id}"))
            if index == 0
            else old
        )
        operations.append(StateOperation(index, old, new))
    projection = tuple(
        sha3_512(
            b"BL/PQ512/WAVE2/CURRENT-H4/PUBLIC-PROJECTION/v1\0"
            + profile_id.encode("ascii")
            + bytes((index,))
        ).digest()[:32]
        for index in range(12)
    )
    public_coin = _wide(f"state-public-coin-{profile_id}")
    mask = _wide(f"state-mask-{profile_id}")
    proof = build_state_transition(
        before,
        operations,
        projection,
        public_coin,
        mask,
        commitment_backend="HASH_PAD",
    )
    independently_verify_state_transition(proof)
    return proof


def _contributors(slh_service: Path):
    ml = MlDsa87PqcryptoAdapter()
    slh = NativeSlhDsaAdapter(slh_service)
    material = []
    for index, adapter in enumerate((ml, slh), 1):
        public_key, secret_key = adapter.generate_keypair()
        contributor_id = _wide(f"contributor-{index}")
        key_id = _wide(f"key-{index}")
        material.append(
            (
                Contributor(contributor_id, key_id, adapter.suite_id, public_key),
                secret_key,
            )
        )
    material.sort(key=lambda item: item[0].contributor_id)
    return (
        tuple(item[0] for item in material),
        {item[0].contributor_id: item[1] for item in material},
        {ml.suite_id: ml, slh.suite_id: slh},
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", choices=("K128_CALIBRATION", "K512_CALIBRATION"))
    parser.add_argument("worker", type=Path)
    parser.add_argument("slh_service", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    for label, path in (("worker", args.worker), ("slh_service", args.slh_service)):
        if not path.is_absolute() or not path.is_file() or path.is_symlink():
            raise RuntimeError(f"{label}_invalid:{path}")
    if not args.output_dir.is_absolute() or args.output_dir.is_symlink():
        raise RuntimeError("output_dir_invalid")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if any(args.output_dir.iterdir()):
        raise RuntimeError("output_dir_not_empty")
    scratch = args.output_dir / "scratch"
    scratch.mkdir()

    # The state producer is synthetic by construction.  These flags only
    # select the repository's local/reference adapters; they do not alter
    # verifier bytes or activation state.
    os.environ.setdefault("BL_ENV", "test")
    os.environ.setdefault("BL_DEV", "1")
    os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")

    proof = _build_state(args.profile)
    contributors, secret_keys, adapters = _contributors(args.slh_service)
    session_id = _wide(f"state-session-{args.profile}")
    evidence = prove_state_air(
        proof,
        worker_executable=args.worker,
        secret_mask_seed=_wide(f"state-proof-mask-{args.profile}"),
        session_id=session_id,
        contributors=contributors,
        adapters=adapters,
        secret_keys=secret_keys,
        scratch_parent=scratch,
    )
    binding = build_state_air_binding_bytes(proof, evidence)
    binding_path = args.output_dir / "state-binding.bin"
    _write_once(binding_path, binding)
    _write_once(args.output_dir / "before-snapshot.bin", proof.before.encoded)
    _write_once(args.output_dir / "after-snapshot.bin", proof.after.encoded)
    metadata = {
        "profile": args.profile,
        "synthetic": True,
        "activation": False,
        "proofSuiteId": None,
        "production_usable": False,
        "state_capacity": proof.before.capacity,
        "statement_sha3_512": proof.statement_digest_512.hex(),
        "binding_sha3_512": proof.binding_digest_512.hex(),
        "state_relation_source_required": True,
        "state_air_program_sha3_512": evidence.program_commitment_512.hex(),
        "state_air_execution_sha3_512": evidence.execution_commitment_512.hex(),
        "selected_proof_suite_id": evidence.proof_suite_id_512.hex(),
        "selected_transcript_root": evidence.transcript_root_512.hex(),
        "binding_bytes": len(binding),
    }
    _write_once(
        args.output_dir / "state-metadata.json",
        (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode("ascii"),
    )
    print("status=verified")
    print(f"profile={args.profile}")
    print("synthetic=true")
    print("activation=false")
    print("proofSuiteId=null")
    print(f"state_binding={binding_path}")
    print(f"state_binding_bytes={len(binding)}")
    print(f"state_statement_sha3_512={proof.statement_digest_512.hex()}")
    print(f"state_binding_sha3_512={proof.binding_digest_512.hex()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # pragma: no cover - CLI boundary
        print(f"ERR:{error}", file=sys.stderr)
        raise SystemExit(2)
