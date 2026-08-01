from __future__ import annotations

from hashlib import sha3_512
import os
from pathlib import Path
import subprocess

import pytest

from experiments.fixed_shape_claim_air.sha3_512_boolean_executable_air import (
    Sha3BooleanCall,
    build_sha3_boolean_executable_air,
)


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "experiments" / "bl_pq512_crypto_core"
TARGET = Path(r"C:\blpq-target")
DOMAIN = b"BL/PQ512/WAVE1A/SHA3-BOOLEAN-TRACE/v1\x00"


@pytest.fixture(scope="module")
def validator() -> Path:
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(TARGET)
    subprocess.run(
        (
            "cargo",
            "+1.96.0",
            "build",
            "--offline",
            "--quiet",
            "--bin",
            "sha3_boolean_trace_commitment",
        ),
        cwd=CRATE,
        env=environment,
        check=True,
    )
    executable = TARGET / "debug" / "sha3_boolean_trace_commitment.exe"
    assert executable.is_file()
    return executable


def _commitment(table, trace, table_id: int) -> str:
    fixed = set(table.fixed_columns)
    private_columns = tuple(name for name in table.columns if name not in fixed)
    digest = sha3_512(DOMAIN + bytes((table_id,)))
    for row in range(table.rows):
        digest.update(len(private_columns).to_bytes(4, "big"))
        for name in private_columns:
            digest.update(trace.columns[name][row].to_bytes(4, "big"))
    digest.update(table.rows.to_bytes(8, "big"))
    return digest.hexdigest()


def test_rust_boolean_sha3_trace_is_exactly_python_equivalent(validator: Path) -> None:
    calls = (
        Sha3BooleanCall("empty", b"", 0),
        Sha3BooleanCall("partial", b"A", 73),
        Sha3BooleanCall("full", b"B" * 72, 73),
        Sha3BooleanCall("over_block", b"C" * 73, 73),
    )
    instance = build_sha3_boolean_executable_air(calls)
    completed = subprocess.run(
        (
            str(validator),
            *(f"{call.capacity}:{call.message.hex()}" for call in calls),
        ),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    observed = dict(line.split("=", 1) for line in completed.stdout.splitlines())
    tables = {table.name: table for table in instance.program.tables}

    assert observed["calls"] == "4"
    assert observed["permutations"] == "7"
    assert observed["round_rows"] == "175"
    assert observed["absorb_rows"] == "7"
    assert observed["digest_rows"] == "4"
    assert observed["round_commitment"] == _commitment(
        tables["sha3_boolean_round"],
        instance.traces["sha3_boolean_round"],
        0,
    )
    assert observed["absorb_commitment"] == _commitment(
        tables["sha3_boolean_absorb"],
        instance.traces["sha3_boolean_absorb"],
        1,
    )
    assert observed["digest_commitment"] == _commitment(
        tables["sha3_boolean_digest"],
        instance.traces["sha3_boolean_digest"],
        2,
    )


def test_rust_boolean_sha3_rejects_over_capacity(validator: Path) -> None:
    completed = subprocess.run(
        (str(validator), "1:4142"),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "trace_Capacity" in completed.stderr
