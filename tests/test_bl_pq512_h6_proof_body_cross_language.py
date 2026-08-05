from __future__ import annotations

from hashlib import sha3_512
from pathlib import Path
import subprocess

import pytest

from experiments.bl_pq512_crypto_foundation.h6_complete_simulator import _grammar
from experiments.bl_pq512_crypto_foundation.proof_body_reference import (
    SectionPayload,
    encode_reference_proof_body,
)


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "experiments" / "bl_pq512_crypto_core"
TARGET = Path(r"C:\blpq-target")


@pytest.mark.parametrize("capacity", (128, 512))
def test_rust_and_python_h6_proof_body_grammar_match(capacity: int) -> None:
    grammar, identity = _grammar(capacity)
    payloads = (
        SectionPayload(1, b"a" * 64),
        SectionPayload(2, b"b" * 128),
        SectionPayload(3, b"c" * 192),
    )
    encoded = encode_reference_proof_body(
        payloads,
        grammar=grammar,
        active_identity=identity,
    )
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
            "h6_proof_body_kat",
            "--",
            str(capacity),
        ),
        cwd=CRATE,
        input=encoded,
        check=True,
        capture_output=True,
        timeout=180,
    )
    observed = dict(
        line.split("=", 1)
        for line in completed.stdout.decode("ascii").splitlines()
        if "=" in line
    )
    assert observed == {
        "h6_proof_body_kat": "PASS",
        "capacity": str(capacity),
        "proof_bytes": str(len(encoded)),
        "grammar_sha3_512": grammar.digest.hex(),
        "section_0_sha3_512": sha3_512(payloads[0].data).hexdigest(),
        "section_1_sha3_512": sha3_512(payloads[1].data).hexdigest(),
        "section_2_sha3_512": sha3_512(payloads[2].data).hexdigest(),
        "mutation_rejections": "4",
    }
