from __future__ import annotations

from hashlib import sha3_512
import os
from pathlib import Path
import subprocess

import pytest

from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import Contributor
from experiments.bl_pq512_crypto_foundation.selected_prover_orchestrator import (
    prove_selected_air,
    prove_selected_air_streaming,
)
from experiments.bl_pq512_crypto_foundation.selected_public_coin import (
    decode_selected_challenge_bundle,
    encode_selected_challenge_bundle,
)
from experiments.fixed_shape_claim_air.air_binary_ir import encode_air_execution
from experiments.fixed_shape_claim_air.executable_air import AirProgram, AirTable
from tests.test_wave1a_executable_air import _fixture


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "bl_pq512_crypto_core" / "Cargo.toml"
TARGET = Path(r"C:\tmp\blpq-target-wave2")


@pytest.fixture(scope="module")
def selected_worker() -> Path:
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
            "parallel",
            "--manifest-path",
            str(MANIFEST),
            "--bin",
            "selected_prover_worker",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    executable = TARGET / "release" / "selected_prover_worker.exe"
    assert executable.is_file()
    return executable


@pytest.fixture(scope="module")
def selected_streaming_worker() -> Path:
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
            "parallel",
            "--manifest-path",
            str(MANIFEST),
            "--bin",
            "selected_streaming_prover_worker",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    executable = TARGET / "release" / "selected_streaming_prover_worker.exe"
    assert executable.is_file()
    return executable


def test_real_dual_pq_selected_proof_roundtrip(selected_worker: Path) -> None:
    program, traces = _fixture()
    program = AirProgram(
        program.program_id,
        tuple(
            AirTable(
                table.name,
                table.columns,
                table.rows,
                table.identities,
                {
                    **dict(table.fixed_columns or {}),
                    "live": traces[table.name].columns["live"],
                },
            )
            for table in program.tables
        ),
        program.lookups,
        program.public_inputs,
    )
    execution = encode_air_execution(program, traces)
    ml_dsa = MlDsa87PqcryptoAdapter()
    slh_dsa = SphincsShake256fSimplePqcryptoAdapter()
    adapters = {ml_dsa.suite_id: ml_dsa, slh_dsa.suite_id: slh_dsa}
    material = []
    for ordinal, adapter in enumerate((ml_dsa, slh_dsa), 1):
        public_key, secret_key = adapter.generate_keypair()
        material.append(
            (
                Contributor(
                    sha3_512(f"selected-prover-contributor-{ordinal}".encode()).digest(),
                    sha3_512(f"selected-prover-key-{ordinal}".encode()).digest(),
                    adapter.suite_id,
                    public_key,
                ),
                secret_key,
            )
        )
    material.sort(key=lambda item: item[0].contributor_id)
    contributors = tuple(item[0] for item in material)
    secret_keys = {item[0].contributor_id: item[1] for item in material}

    result = prove_selected_air(
        worker_executable=selected_worker,
        program=program,
        execution_encoded=execution,
        secret_mask_seed=sha3_512(b"selected-prover-mask-seed").digest(),
        session_id=sha3_512(b"selected-prover-session").digest(),
        public_outputs=bytes(384),
        sidecar=bytes(744),
        contributors=contributors,
        adapters=adapters,
        secret_keys=secret_keys,
    )

    assert len(result.transcript.evidence) == 20
    assert len(result.challenge_bundle.query_positions) == 945
    assert len(result.challenge_bundle.fri_layer_roots) == 15
    assert result.grammar_version == 2
    assert 28_643_096 - result.proof_bytes > 21_000_000
    assert result.proof_bytes < 7_500_000
    assert result.proof_attribution.header_bytes == 146
    assert result.proof_attribution.initial_index_bytes == 0
    assert result.proof_attribution.fri_layer_count == 15
    assert result.proof_attribution.fri_opened_value_count % 2 == 0
    assert result.proof_attribution.fri_path_digest_count > 0
    assert result.proof_attribution.total_bytes == result.proof_bytes
    assert result.proof_bytes < 1 << 29
    assert "query_count=945" in result.worker_report
    assert "trace_masks=4789" in result.worker_report
    assert "quotient_masks=946" in result.worker_report
    assert "folds=15" in result.worker_report
    encoded = encode_selected_challenge_bundle(result.challenge_bundle)
    assert decode_selected_challenge_bundle(encoded) == result.challenge_bundle


def test_real_dual_pq_streaming_proof_is_exact_and_cleans_scratch(
    selected_streaming_worker: Path, tmp_path: Path
) -> None:
    program, traces = _fixture()
    program = AirProgram(
        program.program_id,
        tuple(
            AirTable(
                table.name,
                table.columns,
                table.rows,
                table.identities,
                {
                    **dict(table.fixed_columns or {}),
                    "live": traces[table.name].columns["live"],
                },
            )
            for table in program.tables
        ),
        program.lookups,
        program.public_inputs,
    )
    ml_dsa = MlDsa87PqcryptoAdapter()
    slh_dsa = SphincsShake256fSimplePqcryptoAdapter()
    adapters = {ml_dsa.suite_id: ml_dsa, slh_dsa.suite_id: slh_dsa}
    material = []
    for ordinal, adapter in enumerate((ml_dsa, slh_dsa), 1):
        public_key, secret_key = adapter.generate_keypair()
        material.append(
            (
                Contributor(
                    sha3_512(f"selected-stream-contributor-{ordinal}".encode()).digest(),
                    sha3_512(f"selected-stream-key-{ordinal}".encode()).digest(),
                    adapter.suite_id,
                    public_key,
                ),
                secret_key,
            )
        )
    material.sort(key=lambda item: item[0].contributor_id)
    contributors = tuple(item[0] for item in material)
    secret_keys = {item[0].contributor_id: item[1] for item in material}
    result = prove_selected_air_streaming(
        worker_executable=selected_streaming_worker,
        scratch_parent=tmp_path,
        program=program,
        traces=traces,
        chunk_values=2,
        secret_mask_seed=sha3_512(b"selected-stream-mask-seed").digest(),
        session_id=sha3_512(b"selected-stream-session").digest(),
        public_outputs=bytes(384),
        sidecar=bytes(744),
        contributors=contributors,
        adapters=adapters,
        secret_keys=secret_keys,
    )
    assert len(result.transcript.evidence) == 20
    assert len(result.challenge_bundle.query_positions) == 945
    assert result.grammar_version == 2
    assert 28_643_096 - result.proof_bytes > 21_000_000
    assert result.proof_bytes < 7_500_000
    assert result.proof_attribution.header_bytes == 146
    assert result.proof_attribution.initial_index_bytes == 0
    assert result.proof_attribution.fri_layer_count == 15
    assert result.proof_attribution.fri_opened_value_count % 2 == 0
    assert result.proof_attribution.fri_path_digest_count > 0
    assert result.proof_attribution.total_bytes == result.proof_bytes
    assert "query_count=945" in result.worker_report
    assert list(tmp_path.iterdir()) == []
