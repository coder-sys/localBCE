from __future__ import annotations

import inspect
import os
from pathlib import Path
import subprocess

import pytest

from experiments.bl_pq512_crypto_foundation.selected_prover_orchestrator import (
    prove_selected_air,
    prove_selected_air_streaming,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "bl_pq512_crypto_core" / "Cargo.toml"
CORE = ROOT / "experiments" / "bl_pq512_crypto_core"
TARGET = Path(r"C:\tmp\blpq-target-z02")
WORKERS = (
    ("selected_prover_worker", b"BLPQSPW2", b"BLPQSPT2"),
    ("selected_streaming_prover_worker", b"BLPQSDW3", b"BLPQSDT3"),
)


def _cargo(*arguments: str, target: Path) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(target)
    return subprocess.run(
        (
            "cargo",
            "+1.96.0",
            *arguments,
            "--locked",
            "--offline",
            "--manifest-path",
            str(MANIFEST),
        ),
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )


@pytest.fixture(scope="module")
def z02_workers() -> dict[str, tuple[Path, Path]]:
    default_target = TARGET / "default"
    test_target = TARGET / "test-only"
    binary_arguments = tuple(
        argument
        for name, _, _ in WORKERS
        for argument in ("--bin", name)
    )
    _cargo(
        "build",
        "--features",
        "parallel",
        *binary_arguments,
        target=default_target,
    )
    _cargo(
        "build",
        "--features",
        "parallel,test_entropy_injection",
        *binary_arguments,
        target=test_target,
    )
    suffix = ".exe" if os.name == "nt" else ""
    return {
        name: (
            default_target / "debug" / f"{name}{suffix}",
            test_target / "debug" / f"{name}{suffix}",
        )
        for name, _, _ in WORKERS
    }


def _initial_frame(
    magic: bytes,
    *,
    session_id: bytes,
    injected: tuple[bytes, bytes] | None = None,
) -> bytes:
    # A nonempty but invalid program/execution pair reaches entropy ownership
    # and then fails before any proof or artifact can be produced.
    body = b"".join((magic, (1).to_bytes(4, "big"), b"p", (1).to_bytes(4, "big"), b"e", session_id))
    if injected is not None:
        body += b"".join(injected)
    return body


def test_non_test_api_has_no_named_caller_mask_seed() -> None:
    for function in (prove_selected_air, prove_selected_air_streaming):
        parameters = inspect.signature(function).parameters
        assert "secret_mask_seed" not in parameters
        assert parameters["session_id"].kind is inspect.Parameter.KEYWORD_ONLY
        assert any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        )


@pytest.mark.parametrize("name,default_magic,test_magic", WORKERS)
def test_default_worker_rejects_test_only_entropy_injection(
    name: str,
    default_magic: bytes,
    test_magic: bytes,
    z02_workers: dict[str, tuple[Path, Path]],
    tmp_path: Path,
) -> None:
    default_worker, _ = z02_workers[name]
    session = bytes([0x31]) * 64
    seed = bytes([0x52]) * 64
    nonce = bytes([0x73]) * 64
    completed = subprocess.run(
        (str(default_worker), str(tmp_path))
        if name == "selected_streaming_prover_worker"
        else (str(default_worker),),
        input=_initial_frame(test_magic, session_id=session, injected=(seed, nonce)),
        cwd=tmp_path,
        check=False,
        capture_output=True,
    )
    assert completed.returncode == 2
    assert completed.stdout == b""
    assert completed.stderr == b"ERR:initial_magic\n"
    assert seed not in completed.stdout + completed.stderr
    assert nonce not in completed.stdout + completed.stderr
    assert list(tmp_path.iterdir()) == []
    assert default_magic not in completed.stdout + completed.stderr


@pytest.mark.parametrize("name,default_magic,test_magic", WORKERS)
def test_test_only_entropy_is_zeroized_on_error_without_output_or_artifacts(
    name: str,
    default_magic: bytes,
    test_magic: bytes,
    z02_workers: dict[str, tuple[Path, Path]],
    tmp_path: Path,
) -> None:
    _, test_worker = z02_workers[name]
    session = bytes([0x14]) * 64
    seed = bytes([0x25]) * 64
    nonce = bytes([0x36]) * 64
    completed = subprocess.run(
        (str(test_worker), str(tmp_path))
        if name == "selected_streaming_prover_worker"
        else (str(test_worker),),
        input=_initial_frame(test_magic, session_id=session, injected=(seed, nonce)),
        cwd=tmp_path,
        check=False,
        capture_output=True,
    )
    combined = completed.stdout + completed.stderr
    assert completed.returncode == 2
    assert completed.stdout == b""
    assert completed.stderr.startswith(b"ERR:")
    assert seed not in combined and seed.hex().encode("ascii") not in combined
    assert nonce not in combined and nonce.hex().encode("ascii") not in combined
    assert default_magic not in combined and test_magic not in combined
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("name,_,__", WORKERS)
def test_real_worker_unit_lifecycle_proves_retry_freshness_and_zeroization(
    name: str,
    _: bytes,
    __: bytes,
) -> None:
    completed = _cargo(
        "test",
        "--features",
        "parallel",
        "--bin",
        name,
        "worker_entropy_",
        target=TARGET / "default",
    )
    output = completed.stdout + completed.stderr
    assert b"3 passed" in output
    assert b"worker_entropy_is_fresh_across_attempts" in output
    assert b"worker_entropy_zeroizes_both_owned_buffers" in output
    assert b"worker_entropy_drop_runs_during_panic_unwind" in output
    assert b"mask_seed=" not in output
    assert b"attempt_nonce=" not in output


def test_worker_sources_keep_entropy_owned_noncloneable_and_drop_zeroized() -> None:
    for relative in (
        "src/bin/selected_prover_worker.rs",
        "src/bin/selected_streaming_prover_worker.rs",
    ):
        source = (CORE / relative).read_text(encoding="utf-8")
        assert "struct WorkerEntropy" in source
        assert "impl Drop for WorkerEntropy" in source
        assert "self.mask_seed.zeroize();" in source
        assert "self.attempt_nonce.zeroize();" in source
        assert "getrandom::fill(destination)" in source
        assert "derive(Clone" not in source
        assert "read_exact(&mut secret_seed)" not in source
        assert '#[cfg(any(test, feature = "test_entropy_injection"))]' in source
