from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import mock

from experiments.fixed_shape_claim_air.physical_air_reference import (
    build_wave1a_physical_air_program,
)
from experiments.fixed_shape_claim_air.profile import get_profile


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "bl_pq512_crypto_core" / "Cargo.toml"
FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


def test_python_and_no_std_rust_dimension_ledgers_match_exactly() -> None:
    cargo = shutil.which("cargo")
    assert cargo is not None, "wave1a_cross_language_cargo_missing"
    with tempfile.TemporaryDirectory(prefix="bl-wave1a-rust-target-") as target:
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = target
        completed = subprocess.run(
            (
                cargo,
                "+1.96.0",
                "run",
                "--quiet",
                "--offline",
                "--locked",
                "--manifest-path",
                str(MANIFEST),
                "--bin",
                "wave1a-dimensions",
            ),
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    lines = completed.stdout.splitlines()
    assert len(lines) == 4
    assert lines[0].split("\t") == [
        "profile_id",
        "tables",
        "commitments",
        "logical_rows",
        "padded_rows",
        "trace_columns",
        "constraints",
        "maximum_degree",
        "lookup_width",
        "padded_cells",
        "d_eff_upper_bound",
        "program_commitment_sha3_512",
    ]
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        for line in lines[1:]:
            fields = line.split("\t")
            assert len(fields) == 12
            program = build_wave1a_physical_air_program(get_profile(fields[0]))
            assert tuple(map(int, fields[1:11])) == (
                program.table_count,
                program.commitment_count,
                program.total_logical_rows,
                program.total_padded_rows,
                program.total_trace_columns,
                program.total_constraints,
                program.maximum_constraint_degree,
                program.total_lookup_message_width,
                program.total_padded_cells,
                program.d_eff_upper_bound,
            )
            assert fields[11] == program.program_commitment_sha3_512.hex()
