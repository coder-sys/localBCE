from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from tests.test_bl_pq512_state_plane import _proof


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "bl_pq512_crypto_core" / "Cargo.toml"
TARGET = Path(r"C:\blpq-target")


@pytest.fixture(scope="module")
def native_state_verifier() -> Path:
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(TARGET)
    subprocess.run(
        [
            "cargo",
            "+1.96.0",
            "build",
            "--offline",
            "--locked",
            "--features",
            "std",
            "--manifest-path",
            str(MANIFEST),
            "--bin",
            "k512_atomic_semantic_prototype",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    executable = TARGET / "debug" / "k512_atomic_semantic_prototype.exe"
    assert executable.is_file()
    return executable


@pytest.fixture(scope="module")
def state_proof():
    return _proof()


@pytest.fixture(scope="module")
def state_binding_bytes(state_proof) -> bytes:
    return state_proof.binding_bytes


def _verify(executable: Path, path: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(executable), "--verify-state-binding", str(path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )


def test_native_state_verifier_consumes_and_evaluates_air_fragment(
    native_state_verifier: Path,
    state_binding_bytes: bytes,
    state_proof,
    tmp_path: Path,
) -> None:
    path = tmp_path / "state-binding.bin"
    path.write_bytes(state_binding_bytes)
    result = _verify(native_state_verifier, path)
    assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
    output = result.stdout.decode("ascii").splitlines()
    assert "state_plane_binding_verified=true" in output
    assert (
        f"state_plane_statement_sha3_512={state_proof.statement_digest_512.hex()}"
        in output
    )
    assert (
        f"state_plane_binding_digest_sha3_512={state_proof.binding_digest_512.hex()}"
        in output
    )


def test_native_state_verifier_rejects_mutated_air_execution(
    native_state_verifier: Path,
    state_binding_bytes: bytes,
    tmp_path: Path,
) -> None:
    mutated = bytearray(state_binding_bytes)
    mutated[-1] ^= 1
    path = tmp_path / "mutated-state-binding.bin"
    path.write_bytes(mutated)
    result = _verify(native_state_verifier, path)
    assert result.returncode == 2
    assert b"ERR:state_binding_air_" in result.stderr


def test_native_state_verifier_rejects_mutated_public_abi(
    native_state_verifier: Path,
    state_binding_bytes: bytes,
    state_proof,
    tmp_path: Path,
) -> None:
    mutated = bytearray(state_binding_bytes)
    cursor = 7
    before_length = int.from_bytes(mutated[cursor : cursor + 4], "big")
    cursor += 4 + before_length
    after_length = int.from_bytes(mutated[cursor : cursor + 4], "big")
    cursor += 4 + after_length
    cursor += 8 + state_proof.before.capacity * 274
    mutated[cursor] ^= 1
    path = tmp_path / "mutated-public-abi-state-binding.bin"
    path.write_bytes(mutated)
    result = _verify(native_state_verifier, path)
    assert result.returncode == 2
    assert b"ERR:state_binding_statement" in result.stderr
