from __future__ import annotations

import os
from hashlib import sha3_512
from pathlib import Path
import subprocess

import pytest

from experiments.fixed_shape_claim_air.air_binary_ir import (
    air_binary_commitment,
    air_program_commitment,
    encode_air_execution,
    encode_air_program,
)
from experiments.fixed_shape_claim_air.a12_nullifier_executable_air import (
    AttemptNullifierAirRequest,
    CoverNullifierAirRequest,
    build_a12_nullifier_executable_air,
)
from experiments.fixed_shape_claim_air.sha3_512_boolean_executable_air import (
    build_sha3_boolean_permutation_air,
)
from experiments.fixed_shape_claim_air.executable_air import (
    AirProgram,
    AirTable,
    FixedColumnPeriodic,
    FixedColumnRuns,
    TraceTable,
    evaluate_program,
    evaluate_serialized,
    freeze_columns,
)
from tests.test_wave1a_executable_air import _fixture
from tests.test_a12_nullifier_derivation import _authority, _cover_context_v2, _identity


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "bl_pq512_crypto_core" / "Cargo.toml"
TARGET = Path(r"C:\blpq-target")


@pytest.fixture(scope="module")
def evaluator() -> Path:
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
            "air_ir_evaluate",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    executable = TARGET / "debug" / "air_ir_evaluate.exe"
    assert executable.is_file()
    return executable


def _run(evaluator: Path, encoded: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(evaluator)],
        input=encoded,
        cwd=ROOT,
        check=False,
        capture_output=True,
    )


def _report(stdout: bytes) -> dict[str, str]:
    lines = stdout.decode("ascii").splitlines()
    assert lines[0] == "OK"
    return dict(line.split("=", 1) for line in lines[1:])


def _compact_fixed_fixture() -> tuple[AirProgram, dict[str, TraceTable]]:
    rows = 8
    program = AirProgram(
        "BL-COMPACT-FIXED-KAT-v1",
        (
            AirTable(
                "compact",
                ("rle", "periodic", "witness"),
                rows,
                (),
                {
                    "rle": FixedColumnRuns(((0, 3), (7, 2), (1, 3))),
                    "periodic": FixedColumnPeriodic((2, 4), rows),
                },
            ),
        ),
        (),
    )
    traces = {
        "compact": TraceTable(
            "compact",
            freeze_columns(
                {
                    "rle": (0, 0, 0, 7, 7, 1, 1, 1),
                    "periodic": (2, 4, 2, 4, 2, 4, 2, 4),
                    "witness": tuple(range(rows)),
                }
            ),
        )
    }
    return program, traces


def _build_binary(name: str) -> Path:
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
            name,
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    executable = TARGET / "debug" / f"{name}.exe"
    assert executable.is_file()
    return executable


def test_rust_independently_evaluates_exact_python_air_ir(evaluator: Path) -> None:
    program, traces = _fixture()
    encoded = encode_air_execution(program, traces)
    result = _run(evaluator, encoded)
    assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
    report = _report(result.stdout)
    assert report == {
        "source_program_commitment": program.commitment().hex(),
        "binary_commitment": air_binary_commitment(encoded).hex(),
        "identities_evaluated": "13",
        "lookup_messages_evaluated": "4",
        "maximum_degree": "2",
    }


def test_compact_fixed_columns_are_cross_language_and_fail_closed(evaluator: Path) -> None:
    program, traces = _compact_fixed_fixture()
    encoded = encode_air_execution(program, traces)
    assert int.from_bytes(encoded[8:10], "big") == 2
    assert len(encode_air_program(program)) < 400
    assert evaluate_program(program, traces).identities_evaluated == 0
    assert evaluate_serialized(program.canonical_bytes(), traces).identities_evaluated == 0

    result = _run(evaluator, encoded)
    assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
    assert _report(result.stdout)["source_program_commitment"] == program.commitment().hex()

    bad = dict(traces)
    bad["compact"] = TraceTable(
        "compact",
        freeze_columns(
            {
                "rle": (0, 0, 0, 7, 6, 1, 1, 1),
                "periodic": (2, 4, 2, 4, 2, 4, 2, 4),
                "witness": tuple(range(8)),
            }
        ),
    )
    rejected = _run(evaluator, encode_air_execution(program, bad))
    assert rejected.returncode == 2
    assert b"ERR:FixedColumnMismatch" in rejected.stderr


def test_rust_independently_evaluates_direct_boolean_keccak(evaluator: Path) -> None:
    instance = build_sha3_boolean_permutation_air((bytes(200),))
    expected = evaluate_program(instance.program, instance.traces)
    encoded = encode_air_execution(instance.program, instance.traces)
    result = _run(evaluator, encoded)

    assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
    report = _report(result.stdout)
    assert report == {
        "source_program_commitment": expected.program_commitment.hex(),
        "binary_commitment": air_binary_commitment(encoded).hex(),
        "identities_evaluated": "86573",
        "lookup_messages_evaluated": "0",
        "maximum_degree": "11",
    }


def test_rust_evaluates_real_a12_sha3_projection_component(evaluator: Path) -> None:
    instance = build_a12_nullifier_executable_air(
        (
            AttemptNullifierAirRequest("attempt", _identity()),
            CoverNullifierAirRequest(
                "cover",
                _cover_context_v2(),
                sha3_512(b"BL-A12-COVER-NONCE").digest(),
            ),
        ),
        _authority(),
    )
    expected = evaluate_program(instance.program, instance.traces)
    encoded = encode_air_execution(instance.program, instance.traces)
    result = _run(evaluator, encoded)
    assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
    report = _report(result.stdout)
    assert report == {
        "source_program_commitment": expected.program_commitment.hex(),
        "binary_commitment": air_binary_commitment(encoded).hex(),
        "identities_evaluated": str(expected.identities_evaluated),
        "lookup_messages_evaluated": str(expected.lookup_messages_evaluated),
        "maximum_degree": str(expected.maximum_degree),
    }


def test_rust_rejects_identity_and_lookup_mutations(evaluator: Path) -> None:
    program, traces = _fixture()
    bad_identity = dict(traces)
    bad_identity["source"] = TraceTable(
        "source",
        freeze_columns(
            {
                "live": (1, 1, 0, 0),
                "value": (0, 1, 2, 3),
                "acc": (0, 0, 0, 1),
            }
        ),
    )
    result = _run(evaluator, encode_air_execution(program, bad_identity))
    assert result.returncode == 2
    assert b"ERR:IdentityFailed" in result.stderr

    bad_lookup = dict(traces)
    bad_lookup["destination"] = TraceTable(
        "destination",
        freeze_columns({"live": (1, 1, 0, 0), "value": (0, 0, 2, 3)}),
    )
    result = _run(evaluator, encode_air_execution(program, bad_lookup))
    assert result.returncode == 2
    assert b"ERR:LookupMultisetMismatch" in result.stderr


def test_rust_rejects_noncanonical_field_and_transport_mutations(
    evaluator: Path,
) -> None:
    program, traces = _fixture()
    encoded = encode_air_execution(program, traces)

    noncanonical = bytearray(encoded)
    # The final word is the zero public-input count; the preceding word is the
    # final trace cell in canonical table/column order.
    noncanonical[-8:-4] = ((1 << 31) - 1).to_bytes(4, "big")
    result = _run(evaluator, bytes(noncanonical))
    assert result.returncode == 2
    assert b"ERR:NonCanonicalField" in result.stderr

    zero_commitment = bytearray(encoded)
    zero_commitment[10:74] = bytes(64)
    result = _run(evaluator, bytes(zero_commitment))
    assert result.returncode == 2
    assert b"ERR:ZeroProgramCommitment" in result.stderr

    result = _run(evaluator, encoded + b"\x00")
    assert result.returncode == 2
    assert b"ERR:TrailingBytes" in result.stderr

    bad_magic = bytearray(encoded)
    bad_magic[0] ^= 1
    result = _run(evaluator, bytes(bad_magic))
    assert result.returncode == 2
    assert b"ERR:Magic" in result.stderr


def test_program_only_ir_and_masked_identity_composition_are_rust_executable() -> None:
    program, traces = _fixture()
    program_encoded = encode_air_program(program)
    execution_encoded = encode_air_execution(program, traces)

    validator = _build_binary("air_program_validate")
    validated = subprocess.run(
        [str(validator)],
        input=program_encoded,
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    assert validated.returncode == 0, validated.stderr.decode("ascii", errors="replace")
    fields = dict(item.split("=", 1) for item in validated.stdout.decode("ascii").split())
    assert fields == {
        "source": program.commitment().hex(),
        "binary": air_program_commitment(program_encoded).hex(),
        "tables": "2",
        "columns": "5",
        "identities": "5",
        "lookups": "1",
        "public_inputs": "0",
    }

    composition = _build_binary("air_composition_evaluate")
    alpha = (7).to_bytes(4, "big") + bytes(60)
    payload = b"".join(
        (
            len(program_encoded).to_bytes(4, "big"),
            program_encoded,
            len(execution_encoded).to_bytes(4, "big"),
            execution_encoded,
            alpha,
            bytes(range(64)),
            bytes(range(64, 128)),
            (4).to_bytes(4, "big"),
            b"\x02",
        )
    )
    result = subprocess.run(
        [str(composition)],
        input=payload,
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
    report = _report(result.stdout)
    assert report["source"] == program.commitment().hex()
    assert report["program"] == air_program_commitment(program_encoded).hex()
    assert report["tables"] == "2"
    assert report["identities"] == "5"
    assert report["fixed"] == "0"
    assert report["public"] == "0"
    assert report["lookups_pending"] == "1"
    assert len(bytes.fromhex(report["composition_digest"])) == 64

    logup = _build_binary("air_logup_evaluate")
    beta = (11).to_bytes(4, "big") + bytes(60)
    gamma = (13).to_bytes(4, "big") + bytes(60)
    logup_payload = b"".join(
        (
            len(program_encoded).to_bytes(4, "big"),
            program_encoded,
            len(execution_encoded).to_bytes(4, "big"),
            execution_encoded,
            beta,
            gamma,
            bytes(range(64)),
            bytes(range(64, 128)),
            (4).to_bytes(4, "big"),
            b"\x02",
        )
    )
    result = subprocess.run(
        [str(logup)],
        input=logup_payload,
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
    report = _report(result.stdout)
    assert report["lookups"] == "1"
    assert report["interactions"] == "2"
    assert report["sides"] == "2"
    assert report["denominators"] == "4"
    assert len(bytes.fromhex(report["digest"])) == 64

    complete = _build_binary("air_complete_composition_evaluate")
    complete_payload = b"".join(
        (
            len(program_encoded).to_bytes(4, "big"),
            program_encoded,
            len(execution_encoded).to_bytes(4, "big"),
            execution_encoded,
            alpha,
            beta,
            gamma,
            bytes(range(64)),
            bytes(range(64, 128)),
            (4).to_bytes(4, "big"),
            b"\x02",
        )
    )
    result = subprocess.run(
        [str(complete)],
        input=complete_payload,
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
    report = _report(result.stdout)
    assert report["pending"] == "0"
    assert report["logup_terms"] == "8"
    assert report["interactions"] == "2"
    assert len(bytes.fromhex(report["main_root"])) == 64
    assert len(bytes.fromhex(report["interaction_root"])) == 64
    assert len(bytes.fromhex(report["composition_root"])) == 64
    assert len(bytes.fromhex(report["deep_claims_commitment"])) == 64
    assert int(report["deep_domains"]) > 0
    assert int(report["oods_claims"]) > 0
    assert len(bytes.fromhex(report["fri_mask_root"])) == 64
    assert int(report["fri_layers"]) > 0
    assert len(bytes.fromhex(report["fri_final"])) == 64
    assert report["fri_proof_verified"] == "true"
    assert report["fri_attack_rejections"] == "4"
    assert int(report["proof_bytes"]) > 0
    assert report["parser_rejections"] == "3"
    assert all(int(value) > 0 for value in report["composition_coefficients"].split(","))
    assert len(bytes.fromhex(report["digest"])) == 64
