from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile

import pytest

from experiments.fixed_shape_claim_air.air_binary_ir import (
    encode_air_execution,
    encode_air_program,
)
from experiments.fixed_shape_claim_air.air_streaming_ir import (
    StreamingAirManifest,
    StreamingColumnManifest,
    StreamingTableManifest,
    build_streaming_air_manifest,
    encode_streaming_value_chunk,
    iter_streaming_air_chunks,
    streaming_column_commitment,
)
from experiments.fixed_shape_claim_air.executable_air import (
    AirProgram,
    AirTable,
    PublicInputBinding,
    TraceTable,
    freeze_columns,
)
from tests.test_wave1a_executable_air import _fixture


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "bl_pq512_crypto_core" / "Cargo.toml"
TARGET = Path(r"C:\blpq-target")


@pytest.fixture(scope="module")
def validator() -> Path:
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(TARGET)
    subprocess.run(
        [
            "cargo",
            "+1.96.0",
            "build",
            "--offline",
            "--manifest-path",
            str(MANIFEST),
            "--bin",
            "air_streaming_manifest_validate",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    executable = TARGET / "debug" / "air_streaming_manifest_validate.exe"
    assert executable.is_file()
    return executable


def _framed(program: bytes, manifest: bytes) -> bytes:
    return (
        len(program).to_bytes(4, "big")
        + program
        + len(manifest).to_bytes(4, "big")
        + manifest
    )


def _run(
    validator: Path, program: bytes, manifest: bytes
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(validator)],
        input=_framed(program, manifest),
        cwd=ROOT,
        check=False,
        capture_output=True,
    )


def _report(stdout: bytes) -> dict[str, str]:
    lines = stdout.decode("ascii").splitlines()
    assert lines[0] == "OK"
    return dict(line.split("=", 1) for line in lines[1:])


def test_rust_accepts_exact_python_streaming_manifest(validator: Path) -> None:
    program, traces = _fixture()
    program_encoded = encode_air_program(program)
    manifest = build_streaming_air_manifest(program, traces)
    result = _run(validator, program_encoded, manifest.encoded)
    assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
    assert _report(result.stdout) == {
        "program_binary_commitment": manifest.program_binary_commitment_512.hex(),
        "manifest_commitment": manifest.commitment_512.hex(),
        "tables": str(len(program.tables)),
        "columns": str(sum(len(table.columns) for table in program.tables)),
    }


def test_one_value_changes_only_its_column_and_manifest_commitments() -> None:
    program, traces = _fixture()
    original = build_streaming_air_manifest(program, traces)
    table = original.tables[0]
    column = table.columns[0]
    values = list(traces[program.tables[0].name].columns[program.tables[0].columns[0]])
    values[0] = (values[0] + 1) % ((1 << 31) - 1)
    changed_column = StreamingColumnManifest(
        column.table_index,
        column.column_index,
        column.value_count,
        streaming_column_commitment(
            original.program_binary_commitment_512,
            column.table_index,
            column.column_index,
            values,
        ),
    )
    changed_table = StreamingTableManifest(
        table.table_index,
        table.row_count,
        (changed_column,) + table.columns[1:],
    )
    changed = StreamingAirManifest(
        original.program_binary_commitment_512,
        original.public_inputs,
        (changed_table,) + original.tables[1:],
    )
    assert changed_column.commitment_512 != column.commitment_512
    assert changed.commitment_512 != original.commitment_512
    assert changed.tables[0].columns[1:] == original.tables[0].columns[1:]
    assert changed.tables[1:] == original.tables[1:]


def test_fixed_columns_are_reconstructed_not_streamed(validator: Path) -> None:
    program = AirProgram(
        "STREAMING-FIXED-OMISSION-v1",
        (
            AirTable(
                "mixed",
                ("fixed", "witness"),
                4,
                (),
                {"fixed": (0, 1, 2, 3)},
            ),
            AirTable("all_fixed", ("fixed",), 4, (), {"fixed": (3, 2, 1, 0)}),
        ),
    )
    traces = {
        "mixed": TraceTable(
            "mixed", freeze_columns({"fixed": (0, 1, 2, 3), "witness": (4, 5, 6, 7)})
        ),
        "all_fixed": TraceTable(
            "all_fixed", freeze_columns({"fixed": (3, 2, 1, 0)})
        ),
    }
    manifest = build_streaming_air_manifest(program, traces)
    assert [column.column_index for column in manifest.tables[0].columns] == [1]
    assert manifest.tables[1].columns == ()
    result = _run(validator, encode_air_program(program), manifest.encoded)
    assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
    assert _report(result.stdout)["columns"] == "1"


def test_public_input_values_are_bound_and_checked_during_streaming(
    execution_validator: Path,
) -> None:
    program = AirProgram(
        "STREAMING-PUBLIC-INPUT-v1",
        (AirTable("table", ("value",), 4, ()),),
        (),
        (PublicInputBinding("declared", "table", "value", 1),),
    )
    traces = {
        "table": TraceTable(
            "table", freeze_columns({"value": (4, 5, 6, 7)})
        )
    }
    manifest = build_streaming_air_manifest(program, traces, (5,))
    valid_chunks = list(
        iter_streaming_air_chunks(program, traces, manifest, chunk_values=2)
    )
    valid = _run_execution(
        execution_validator,
        encode_air_program(program),
        manifest.encoded,
        valid_chunks,
    )
    assert valid.returncode == 0, valid.stderr.decode("ascii", errors="replace")

    wrong = StreamingAirManifest(
        manifest.program_binary_commitment_512,
        (6,),
        manifest.tables,
    )
    values = traces["table"].columns["value"]
    wrong_chunks = [
        encode_streaming_value_chunk(wrong, 0, 0, 0, values[:2]),
        encode_streaming_value_chunk(wrong, 0, 0, 2, values[2:]),
    ]
    rejected = _run_execution(
        execution_validator,
        encode_air_program(program),
        wrong.encoded,
        wrong_chunks,
    )
    assert rejected.returncode == 2
    assert b"ProgramMismatch" in rejected.stderr


@pytest.mark.parametrize("mutation", ["wrong_program", "reordered", "duplicate"])
def test_rust_rejects_program_and_column_identity_mutations(
    validator: Path, mutation: str
) -> None:
    program, traces = _fixture()
    program_encoded = encode_air_program(program)
    manifest = build_streaming_air_manifest(program, traces)
    encoded = bytearray(manifest.encoded)
    first_column_index_offset = 8 + 2 + 64 + 4 + 4 + 4 + 8 + 4
    if mutation == "wrong_program":
        program_encoded = program_encoded[:-1] + bytes([program_encoded[-1] ^ 1])
    elif mutation == "reordered":
        encoded[first_column_index_offset : first_column_index_offset + 4] = (1).to_bytes(
            4, "big"
        )
    else:
        second_column_index_offset = first_column_index_offset + 4 + 8 + 64
        encoded[second_column_index_offset : second_column_index_offset + 4] = (0).to_bytes(
            4, "big"
        )
    result = _run(validator, program_encoded, bytes(encoded))
    assert result.returncode == 2


@pytest.mark.parametrize("mutation", ["truncated", "trailing"])
def test_rust_rejects_manifest_transport_mutations(
    validator: Path, mutation: str
) -> None:
    program, traces = _fixture()
    program_encoded = encode_air_program(program)
    manifest = build_streaming_air_manifest(program, traces).encoded
    manifest = manifest[:-1] if mutation == "truncated" else manifest + b"\x00"
    result = _run(validator, program_encoded, manifest)
    assert result.returncode == 2


@pytest.fixture(scope="module")
def execution_validator() -> Path:
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(TARGET)
    subprocess.run(
        [
            "cargo",
            "+1.96.0",
            "build",
            "--offline",
            "--manifest-path",
            str(MANIFEST),
            "--bin",
            "air_streaming_execution_validate",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    executable = TARGET / "debug" / "air_streaming_execution_validate.exe"
    assert executable.is_file()
    return executable


def _execution_framed(program: bytes, manifest: bytes, chunks: list[bytes]) -> bytes:
    return _framed(program, manifest) + b"".join(
        len(chunk).to_bytes(4, "big") + chunk for chunk in chunks
    )


def _run_execution(
    execution_validator: Path,
    program: bytes,
    manifest: bytes,
    chunks: list[bytes],
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(execution_validator)],
        input=_execution_framed(program, manifest, chunks),
        cwd=ROOT,
        check=False,
        capture_output=True,
    )


@pytest.mark.parametrize("chunk_values", [1, 3, 1 << 20])
def test_stream_chunk_size_does_not_change_execution_identity(
    execution_validator: Path, chunk_values: int
) -> None:
    program, traces = _fixture()
    program_encoded = encode_air_program(program)
    manifest = build_streaming_air_manifest(program, traces)
    chunks = list(
        iter_streaming_air_chunks(
            program, traces, manifest, chunk_values=chunk_values
        )
    )
    result = _run_execution(
        execution_validator, program_encoded, manifest.encoded, chunks
    )
    assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
    assert result.stdout.startswith(b"OK chunks=")
    assert f"values={sum(table.rows * len(table.columns) for table in program.tables)}".encode() in result.stdout


@pytest.mark.parametrize(
    "mutation", ["reorder", "skip", "duplicate", "value", "noncanonical", "trailing"]
)
def test_stream_rejects_order_content_and_transport_mutations(
    execution_validator: Path, mutation: str
) -> None:
    program, traces = _fixture()
    program_encoded = encode_air_program(program)
    manifest = build_streaming_air_manifest(program, traces)
    chunks = list(iter_streaming_air_chunks(program, traces, manifest, chunk_values=2))
    if mutation == "reorder":
        chunks[0], chunks[1] = chunks[1], chunks[0]
    elif mutation == "skip":
        del chunks[0]
    elif mutation == "duplicate":
        chunks.insert(1, chunks[0])
    elif mutation == "value":
        changed = bytearray(chunks[0])
        changed[-1] ^= 1
        chunks[0] = bytes(changed)
    elif mutation == "noncanonical":
        changed = bytearray(chunks[0])
        changed[-4:] = ((1 << 31) - 1).to_bytes(4, "big")
        chunks[0] = bytes(changed)
    else:
        chunks[0] += b"\x00"
    result = _run_execution(
        execution_validator, program_encoded, manifest.encoded, chunks
    )
    assert result.returncode == 2


def test_disk_main_commitment_is_byte_exact_to_memory_engine() -> None:
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(TARGET)
    subprocess.run(
        [
            "cargo",
            "+1.96.0",
            "build",
            "--release",
            "--offline",
            "--features",
            "std",
            "--manifest-path",
            str(MANIFEST),
            "--bin",
            "air_disk_main_compare",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    comparator = TARGET / "release" / "air_disk_main_compare.exe"
    program, traces = _fixture()
    program = AirProgram(
        program.program_id,
        tuple(
            AirTable(
                table.name,
                table.columns,
                table.rows,
                table.identities,
                {"live": traces[table.name].columns["live"]},
            )
            for table in program.tables
        ),
        program.lookups,
        program.public_inputs,
    )
    program_encoded = encode_air_program(program)
    execution_encoded = encode_air_execution(program, traces)
    manifest = build_streaming_air_manifest(program, traces)
    chunks = list(iter_streaming_air_chunks(program, traces, manifest, chunk_values=2))
    framed = b"".join(
        len(value).to_bytes(4, "big") + value
        for value in (
            program_encoded,
            execution_encoded,
            manifest.encoded,
            bytes([0x11]) * 64,
            bytes([0x22]) * 64,
            *chunks,
        )
    )
    with tempfile.TemporaryDirectory(prefix="blpq-disk-main-test-") as scratch:
        result = subprocess.run(
            [str(comparator), scratch],
            input=framed,
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
        assert result.stdout.startswith(b"OK root=")
        assert list(Path(scratch).iterdir()) == []
