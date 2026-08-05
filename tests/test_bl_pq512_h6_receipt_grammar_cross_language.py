from __future__ import annotations

from hashlib import sha3_512
from pathlib import Path
import subprocess

from experiments.bl_pq512_crypto_foundation.h6_receipt_grammar import (
    RECEIPT_FIELD_COUNT,
    SIDECAR_FIELD_COUNT,
    encode_receipt,
    encode_sidecar,
    grammar_identity,
    parse_receipt,
    parse_sidecar,
)


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "experiments" / "bl_pq512_crypto_core"
TARGET = Path(r"C:\blpq-target")


def _fields(count: int) -> tuple[bytes, ...]:
    return tuple(bytes((index + 1,)) * 64 for index in range(count))


def test_rust_and_python_h6_receipt_grammar_match_exactly() -> None:
    sidecar_fields = _fields(SIDECAR_FIELD_COUNT)
    receipt_fields = _fields(RECEIPT_FIELD_COUNT)
    sidecar = encode_sidecar(sidecar_fields)
    receipt = encode_receipt(receipt_fields)
    assert parse_sidecar(sidecar) == sidecar_fields
    assert parse_receipt(receipt) == receipt_fields

    completed = subprocess.run(
        (
            "cargo",
            "+1.96.0",
            "run",
            "--quiet",
            "--locked",
            "--offline",
            "--features",
            "std",
            "--target-dir",
            str(TARGET),
            "--bin",
            "h6_receipt_grammar_kat",
        ),
        cwd=CRATE,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    observed = dict(
        line.split("=", 1)
        for line in completed.stdout.splitlines()
        if "=" in line
    )
    assert observed == {
        "h6_receipt_grammar_kat": "PASS",
        "sidecar_bytes": str(len(sidecar)),
        "receipt_bytes": str(len(receipt)),
        "sidecar_sha3_512": sha3_512(sidecar).hexdigest(),
        "receipt_sha3_512": sha3_512(receipt).hexdigest(),
        "grammar_sha3_512": grammar_identity().hex(),
        "sidecar_parser": "PASS",
        "receipt_parser": "PASS",
        "mutation_rejections": "3",
    }
