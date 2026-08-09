from __future__ import annotations

from io import BytesIO
from pathlib import Path
import subprocess

import pytest

from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import Contributor
from experiments.bl_pq512_crypto_foundation.selected_prover_orchestrator import (
    WORKER_MAGIC,
    prove_selected_air,
)
from tests.test_wave1a_executable_air import _fixture


class _CaptureInput(BytesIO):
    def __init__(self) -> None:
        super().__init__()
        self.snapshot = b""

    def close(self) -> None:
        self.snapshot = super().getvalue()
        super().close()


class _FailingWorker:
    def __init__(self) -> None:
        self.stdin = _CaptureInput()
        self.stdout = BytesIO()
        self.stderr = BytesIO(b"ERR:synthetic_failure\n")
        self.waited = False
        self.killed = False
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: int | None = None) -> int:
        del timeout
        self.waited = True
        self.returncode = 2
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


def _authority() -> tuple[tuple[Contributor, ...], dict[str, object], dict[bytes, bytes]]:
    ml_dsa = MlDsa87PqcryptoAdapter()
    slh_dsa = SphincsShake256fSimplePqcryptoAdapter()
    contributors = (
        Contributor(
            bytes([1]) * 64,
            bytes([3]) * 64,
            "FIPS204-ML-DSA-87",
            b"key-a",
        ),
        Contributor(
            bytes([2]) * 64,
            bytes([4]) * 64,
            "FIPS205-SLH-DSA-SHAKE-256F",
            b"key-b",
        ),
    )
    return contributors, {
        ml_dsa.suite_id: ml_dsa,
        slh_dsa.suite_id: slh_dsa,
    }, {
        contributors[0].contributor_id: b"secret-a",
        contributors[1].contributor_id: b"secret-b",
    }


def test_legacy_caller_seed_cannot_cross_worker_boundary_or_survive_cancellation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    program, _ = _fixture()
    executable = tmp_path / "worker.exe"
    executable.write_bytes(b"placeholder")
    worker = _FailingWorker()
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: worker)
    contributors, adapters, secret_keys = _authority()
    legacy_seed = bytes(range(64))
    public_session = bytes(range(64, 128))

    with pytest.raises(RuntimeError, match="worker_response_missing") as failure:
        prove_selected_air(
            worker_executable=executable,
            program=program,
            execution_encoded=b"execution",
            session_id=public_session,
            public_outputs=bytes(384),
            sidecar=bytes(744),
            contributors=contributors,
            adapters=adapters,
            secret_keys=secret_keys,
            secret_mask_seed=legacy_seed,
        )

    frame = worker.stdin.snapshot
    assert frame.startswith(WORKER_MAGIC)
    assert frame.endswith(public_session)
    assert legacy_seed not in frame
    assert legacy_seed.hex() not in str(failure.value)
    assert worker.stdin.closed
    assert worker.waited is True
    assert worker.killed is False


def test_unrecognized_entropy_injection_keyword_fails_closed_before_worker_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    program, _ = _fixture()
    executable = tmp_path / "worker.exe"
    executable.write_bytes(b"placeholder")
    started = False

    def _popen(*args: object, **kwargs: object) -> object:
        nonlocal started
        del args, kwargs
        started = True
        raise AssertionError("worker must not start")

    monkeypatch.setattr(subprocess, "Popen", _popen)
    contributors, adapters, secret_keys = _authority()
    with pytest.raises(TypeError, match="unexpected_entropy_keyword"):
        prove_selected_air(
            worker_executable=executable,
            program=program,
            execution_encoded=b"execution",
            session_id=bytes([7]) * 64,
            public_outputs=bytes(384),
            sidecar=bytes(744),
            contributors=contributors,
            adapters=adapters,
            secret_keys=secret_keys,
            attacker_seed=bytes([9]) * 64,
        )
    assert started is False


def test_default_cargo_feature_set_cannot_enable_deterministic_entropy() -> None:
    manifest = (
        Path(__file__).resolve().parents[2]
        / "experiments"
        / "bl_pq512_crypto_core"
        / "Cargo.toml"
    ).read_text(encoding="utf-8")
    assert "default = []" in manifest
    assert "test_entropy_injection = []" in manifest
    default_line = next(line for line in manifest.splitlines() if line.startswith("default ="))
    assert "test_entropy_injection" not in default_line
