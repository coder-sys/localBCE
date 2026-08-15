from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import inspect
import os
from pathlib import Path
import re
import subprocess
from typing import Any
from unittest import mock

import pytest

from experiments.bl_pq512_crypto_foundation import selected_prover_orchestrator
from experiments.bl_pq512_crypto_foundation.c0_control_fixture import (
    build_c0_typed_state_witness,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    NativeSlhDsaAdapter,
)
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    TRANSCRIPT_COMMITMENT_DOMAIN,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import Contributor
from experiments.bl_pq512_crypto_foundation.selected_public_coin import (
    MAX_SELECTED_TRANSCRIPT_BYTES,
    SELECTED_TRANSCRIPT_MAGIC,
    SELECTED_TRANSCRIPT_VERSION,
)
from experiments.bl_pq512_crypto_foundation.typed_state_air_proof import (
    PORTABLE_PACKAGE_BYTES,
    PORTABLE_PACKAGE_PREFIX_BYTES,
    PORTABLE_SIDECAR_MAGIC,
    PUBLIC_OUTPUT_BYTES,
    SIDECAR_BYTES,
    _sidecar,
    _validate_transcript_binding,
    build_typed_state_proof_package_v1,
    prove_typed_state_air,
)
from experiments.fixed_shape_claim_air.air_binary_ir import AIR_BINARY_MAGIC
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.semantics import StructuralError


ROOT = Path(__file__).resolve().parents[1]
CORE_MANIFEST = ROOT / "experiments" / "bl_pq512_crypto_core" / "Cargo.toml"
TARGET_DIR = Path(r"C:\tmp\blpq-target-typed-state-package-v1")
PROFILE_ID = "K128_CALIBRATION"
TEST_FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}
RECEIPT_KEYS = (
    "profile_code",
    "profile_label",
    "profile_identity",
    "program_identity",
    "program_commitment",
    "proof_suite_id",
    "schedule_commitment",
    "session_id",
    "proof_package_commitment",
    "transcript_commitment",
    "public_input_digest",
    "projection_digest",
    "public_outputs",
    "epoch",
    "sequence_before",
    "sequence_after",
    "settlement_root_before",
    "settlement_root_after",
    "asset_registry_root_before",
    "asset_registry_root_after",
    "scope_root_before",
    "scope_root_after",
    "benefit_root_before",
    "benefit_root_after",
    "obligation_root_before",
    "obligation_root_after",
    "ledger_root_before",
    "ledger_root_after",
    "operation_log_root_before",
    "operation_log_root_after",
    "payment_root_before",
    "payment_root_after",
    "replay_root_before",
    "replay_root_after",
    "state_root_before",
    "state_root_after",
    "transition_commitment",
)


def _wide(label: str) -> bytes:
    return sha3_512(f"typed-state-package-v1/{label}".encode("ascii")).digest()


@dataclass(slots=True)
class _RealTypedStateCase:
    scratch: Path
    verifier: Path
    package_path: Path
    portable: bytes
    evidence: Any
    witness: Any
    session_id: bytes
    witness_canary: bytes


def _prove_with_worker_diagnostics(worker: Path, witness: Any, **kwargs: Any) -> Any:
    worker_processes: list[subprocess.Popen[bytes]] = []
    chunk_progress: dict[str, object] = {}
    original_popen = subprocess.Popen
    original_chunks = selected_prover_orchestrator.iter_streaming_air_chunks

    def observed_popen(*args: Any, **popen_kwargs: Any) -> subprocess.Popen[bytes]:
        process = original_popen(*args, **popen_kwargs)
        command = args[0] if args else popen_kwargs.get("args")
        if (
            isinstance(command, (list, tuple))
            and command
            and Path(command[0]).resolve() == worker.resolve()
        ):
            worker_processes.append(process)
        return process

    def observed_chunks(
        program: Any,
        traces: Any,
        manifest: Any,
        *,
        chunk_values: int,
    ) -> Any:
        chunks = original_chunks(
            program,
            traces,
            manifest,
            chunk_values=chunk_values,
        )
        for chunk_index, chunk in enumerate(chunks):
            table_index = int.from_bytes(chunk[138:142], "big")
            column_index = int.from_bytes(chunk[142:146], "big")
            row_start = int.from_bytes(chunk[146:154], "big")
            value_count = int.from_bytes(chunk[154:158], "big")
            table = program.tables[table_index]
            chunk_progress.clear()
            chunk_progress.update(
                chunk_index=chunk_index,
                table_index=table_index,
                table_name=table.name,
                column_index=column_index,
                column_name=table.columns[column_index],
                row_start=row_start,
                value_count=value_count,
                chunk_bytes=len(chunk),
            )
            yield chunk

    try:
        with (
            mock.patch.object(subprocess, "Popen", new=observed_popen),
            mock.patch.object(
                selected_prover_orchestrator,
                "iter_streaming_air_chunks",
                new=observed_chunks,
            ),
        ):
            return prove_typed_state_air(witness, worker_executable=worker, **kwargs)
    except BaseException as error:
        if not worker_processes:
            raise RuntimeError(
                "typed_state_selected_worker_not_launched:"
                f"chunk_progress={chunk_progress!r}"
            ) from error
        process = worker_processes[-1]
        return_code = process.poll()
        worker_stderr = b""
        if process.stderr is not None:
            worker_stderr = process.stderr.read()
        raise RuntimeError(
            "typed_state_selected_worker_failed:"
            f"returncode={return_code};"
            f"chunk_progress={chunk_progress!r};"
            f"stderr={worker_stderr.decode('ascii', errors='replace')!r}"
        ) from error


@pytest.fixture(scope="module")
def typed_state_package_binaries() -> tuple[Path, Path, Path]:
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(TARGET_DIR)
    completed = subprocess.run(
        [
            "cargo",
            "+1.96.0",
            "build",
            "--release",
            "--offline",
            "--locked",
            "--features",
            "parallel",
            "--manifest-path",
            str(CORE_MANIFEST),
            "--bin",
            "selected_streaming_prover_worker",
            "--bin",
            "typed_state_proof_package_verify",
            "--bin",
            "selected_slh_dsa_service",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    paths = tuple(
        TARGET_DIR / "release" / name
        for name in (
            "selected_streaming_prover_worker.exe",
            "typed_state_proof_package_verify.exe",
            "selected_slh_dsa_service.exe",
        )
    )
    assert all(path.is_file() for path in paths)
    return paths


@pytest.fixture(scope="module")
def real_typed_state_package(
    typed_state_package_binaries: tuple[Path, Path, Path],
    tmp_path_factory: pytest.TempPathFactory,
) -> _RealTypedStateCase:
    worker, verifier, slh_service = typed_state_package_binaries
    scratch = tmp_path_factory.mktemp("typed-state-package-v1")
    session_id = _wide("session")
    with mock.patch.dict(os.environ, TEST_FLAGS, clear=False):
        witness = build_c0_typed_state_witness(get_profile(PROFILE_ID))
        ml_dsa = MlDsa87PqcryptoAdapter()
        slh_dsa = NativeSlhDsaAdapter(slh_service)
        adapters = {ml_dsa.suite_id: ml_dsa, slh_dsa.suite_id: slh_dsa}
        material = []
        for ordinal, adapter in enumerate((ml_dsa, slh_dsa), 1):
            public_key, secret_key = adapter.generate_keypair()
            material.append(
                (
                    Contributor(
                        _wide(f"contributor-{ordinal}"),
                        _wide(f"key-{ordinal}"),
                        adapter.suite_id,
                        public_key,
                    ),
                    secret_key,
                )
            )
        material.sort(key=lambda item: item[0].contributor_id)
        contributors = tuple(item[0] for item in material)
        secret_keys = {item[0].contributor_id: item[1] for item in material}
        evidence = _prove_with_worker_diagnostics(
            worker,
            witness,
            secret_mask_seed=_wide("legacy-transparent-mask-seed"),
            session_id=session_id,
            contributors=contributors,
            adapters=adapters,
            secret_keys=secret_keys,
            scratch_parent=scratch,
        )
    portable = build_typed_state_proof_package_v1(evidence)
    package_path = scratch / "typed-state-package-v1.bin"
    package_path.write_bytes(portable)
    return _RealTypedStateCase(
        scratch,
        verifier,
        package_path,
        portable,
        evidence,
        witness,
        session_id,
        witness.replay_batch.operations[0].key_512,
    )


def test_typed_state_proof_package_v1_has_exact_fixed_shape() -> None:
    assert PORTABLE_PACKAGE_PREFIX_BYTES == 1_156
    assert PORTABLE_PACKAGE_BYTES == 83_887_236
    assert PORTABLE_PACKAGE_BYTES == (
        PORTABLE_PACKAGE_PREFIX_BYTES + 64 * 1024 * 1024 + MAX_SELECTED_TRANSCRIPT_BYTES
    )


def test_typed_state_proof_package_v1_sidecar_is_fixed_and_ordered() -> None:
    fields = tuple(bytes((index,)) * 64 for index in range(1, 12))
    encoded = _sidecar(fields)
    assert len(encoded) == SIDECAR_BYTES
    assert encoded[:8] == PORTABLE_SIDECAR_MAGIC
    assert encoded[8:10] == (1).to_bytes(2, "big")
    assert encoded[10:12] == bytes(2)
    assert encoded[12:16] == SIDECAR_BYTES.to_bytes(4, "big")
    for index, field in enumerate(fields):
        assert encoded[16 + index * 64 : 16 + (index + 1) * 64] == field
    assert encoded[16 + 11 * 64 :] == bytes(24)


def test_typed_state_proof_package_v1_retains_exact_transcript_statement() -> None:
    public_outputs = bytes((index % 251) + 1 for index in range(PUBLIC_OUTPUT_BYTES))
    sidecar = _sidecar(tuple(bytes((index,)) * 64 for index in range(1, 12)))
    proof_suite = bytes((21,)) * 64
    schedule = bytes((22,)) * 64
    final_root = bytes((23,)) * 64
    transcript = b"".join(
        (
            SELECTED_TRANSCRIPT_MAGIC,
            SELECTED_TRANSCRIPT_VERSION.to_bytes(2, "big"),
            bytes((20,)) * 64,
            public_outputs,
            sidecar,
            proof_suite,
            schedule,
            final_root,
        )
    )
    _validate_transcript_binding(
        transcript,
        public_outputs,
        sidecar,
        proof_suite,
        schedule,
        final_root,
    )
    mutated = bytearray(transcript)
    mutated[8 + 2 + 64] ^= 1
    with pytest.raises(StructuralError, match="transcript_binding_mismatch"):
        _validate_transcript_binding(
            bytes(mutated),
            public_outputs,
            sidecar,
            proof_suite,
            schedule,
            final_root,
        )


def test_typed_state_proof_package_v1_serializer_has_no_private_field_dependency() -> None:
    source = inspect.getsource(build_typed_state_proof_package_v1)
    assert "state_commitment_mask" not in source
    assert "execution_commitment" not in source
    assert "state_witness" not in source
    with pytest.raises(StructuralError, match="portable_evidence_required"):
        build_typed_state_proof_package_v1(object())  # type: ignore[arg-type]


def _sidecar_fields(encoded: bytes) -> tuple[bytes, ...]:
    assert len(encoded) == SIDECAR_BYTES
    return tuple(encoded[16 + index * 64 : 16 + (index + 1) * 64] for index in range(11))


def _invoke(
    case: _RealTypedStateCase,
    path: Path,
    *,
    program_commitment: bytes | None = None,
) -> subprocess.CompletedProcess[str]:
    commitment = case.evidence.program_commitment_512 if program_commitment is None else program_commitment
    return subprocess.run(
        [str(case.verifier), str(path), PROFILE_ID, commitment.hex()],
        cwd=case.verifier.parent,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )


def _parse_strict_receipt(encoded: str) -> dict[str, str]:
    assert encoded.endswith("\n") and encoded.count("\n") == 1
    tokens = encoded[:-1].split(" ")
    assert tokens[0] == "OK"
    assert len(tokens) == len(RECEIPT_KEYS) + 1
    fields = []
    for token in tokens[1:]:
        key, separator, value = token.partition("=")
        assert separator == "=" and key and value
        fields.append((key, value))
    assert tuple(key for key, _ in fields) == RECEIPT_KEYS
    assert len({key for key, _ in fields}) == len(fields)
    receipt = dict(fields)
    assert receipt["profile_code"] in {"1", "3"}
    assert receipt["profile_label"] in {"K128_CALIBRATION", "K512_CALIBRATION"}
    assert (receipt["profile_code"], receipt["profile_label"]) in {
        ("1", "K128_CALIBRATION"),
        ("3", "K512_CALIBRATION"),
    }
    for key in ("profile_code", "epoch", "sequence_before", "sequence_after"):
        assert re.fullmatch(r"0|[1-9][0-9]*", receipt[key])
    for key in set(RECEIPT_KEYS) - {
        "profile_code",
        "profile_label",
        "public_outputs",
        "epoch",
        "sequence_before",
        "sequence_after",
    }:
        assert re.fullmatch(r"[0-9a-f]{128}", receipt[key])
    assert re.fullmatch(r"[0-9a-f]{768}", receipt["public_outputs"])
    return receipt


def _private_needles(case: _RealTypedStateCase) -> tuple[bytes, ...]:
    mask = case.evidence.state_commitment_mask
    return (
        AIR_BINARY_MAGIC,
        case.witness_canary,
        mask,
        *(mask[offset : offset + 64] for offset in range(0, len(mask), 64)),
    )


def _assert_text_excludes_private(text: str, needles: tuple[bytes, ...]) -> None:
    lowered = text.lower()
    for needle in needles:
        assert needle.hex() not in lowered
        if all(32 <= value < 127 for value in needle):
            assert needle.decode("ascii") not in text


def _assert_file_excludes_private(path: Path, needles: tuple[bytes, ...]) -> None:
    overlap = max(len(needle) for needle in needles) - 1
    tail = b""
    with path.open("rb") as source:
        while chunk := source.read(1 << 20):
            block = tail + chunk
            assert all(needle not in block for needle in needles), path
            tail = block[-overlap:] if overlap else b""


def test_typed_state_proof_package_v1_real_k128_cross_language_receipt(
    real_typed_state_package: _RealTypedStateCase,
) -> None:
    case = real_typed_state_package
    assert len(case.portable) == PORTABLE_PACKAGE_BYTES == 83_887_236
    completed = _invoke(case, case.package_path)
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert completed.stderr == ""
    receipt = _parse_strict_receipt(completed.stdout)

    fields = _sidecar_fields(case.evidence.public_sidecar)
    before = case.witness.payment_before
    after = case.witness.payment_after
    expected = {
        "profile_code": "1",
        "profile_label": PROFILE_ID,
        "profile_identity": fields[0].hex(),
        "program_identity": fields[1].hex(),
        "program_commitment": case.evidence.program_commitment_512.hex(),
        "proof_suite_id": case.evidence.proof_suite_id_512.hex(),
        "schedule_commitment": case.evidence.schedule_commitment_512.hex(),
        "session_id": case.session_id.hex(),
        "proof_package_commitment": case.evidence.proof_package_commitment_512.hex(),
        "transcript_commitment": sha3_512(
            TRANSCRIPT_COMMITMENT_DOMAIN + case.evidence.transcript_evidence_bytes
        ).hexdigest(),
        "public_input_digest": case.evidence.public_input_digest_512.hex(),
        "projection_digest": fields[10].hex(),
        "public_outputs": case.evidence.public_outputs.hex(),
        "epoch": str(case.witness.payment_before.epoch),
        "sequence_before": str(case.witness.payment_before.sequence),
        "sequence_after": str(case.witness.payment_after.sequence),
        "settlement_root_before": before.strong_settlement_domain_id_512.hex(),
        "settlement_root_after": after.strong_settlement_domain_id_512.hex(),
        "asset_registry_root_before": before.asset_registry_root_512.hex(),
        "asset_registry_root_after": after.asset_registry_root_512.hex(),
        "scope_root_before": before.benefit_scope.commitment_512().hex(),
        "scope_root_after": after.benefit_scope.commitment_512().hex(),
        "benefit_root_before": before.benefit_root_512.hex(),
        "benefit_root_after": after.benefit_root_512.hex(),
        "obligation_root_before": before.obligation_root_512.hex(),
        "obligation_root_after": after.obligation_root_512.hex(),
        "ledger_root_before": before.private_asset_ledger_root_512.hex(),
        "ledger_root_after": after.private_asset_ledger_root_512.hex(),
        "operation_log_root_before": before.operation_log_root_512.hex(),
        "operation_log_root_after": after.operation_log_root_512.hex(),
        "payment_root_before": fields[5].hex(),
        "payment_root_after": fields[6].hex(),
        "replay_root_before": fields[7].hex(),
        "replay_root_after": fields[8].hex(),
        "state_root_before": fields[3].hex(),
        "state_root_after": fields[4].hex(),
        "transition_commitment": fields[9].hex(),
    }
    assert receipt == expected

    needles = _private_needles(case)
    assert all(needle not in case.portable for needle in needles)
    _assert_text_excludes_private(completed.stdout + completed.stderr, needles)


def test_typed_state_proof_package_v1_real_mutations_and_private_scan(
    real_typed_state_package: _RealTypedStateCase,
) -> None:
    case = real_typed_state_package
    attack_path = case.scratch / "typed-state-package-v1-attack.bin"
    needles = _private_needles(case)
    completions: list[subprocess.CompletedProcess[str]] = []

    def reject(label: str, encoded: bytes | bytearray, *, pin: bytes | None = None) -> None:
        attack_path.write_bytes(encoded)
        completed = _invoke(case, attack_path, program_commitment=pin)
        completions.append(completed)
        assert completed.returncode != 0, label
        assert completed.stdout == "", label
        assert re.fullmatch(r"ERR:[a-z_]+\n", completed.stderr), (label, completed.stderr)

    reject("truncate", case.portable[:-1])
    reject("extend", case.portable + b"\x00")

    transcript_length = int.from_bytes(
        case.portable[PORTABLE_PACKAGE_PREFIX_BYTES - 8 : PORTABLE_PACKAGE_PREFIX_BYTES],
        "big",
    )
    transcript_start = PORTABLE_PACKAGE_PREFIX_BYTES + 64 * 1024 * 1024
    padding_start = transcript_start + transcript_length
    assert transcript_start < padding_start < len(case.portable)

    mutated = bytearray(case.portable)
    assert mutated[padding_start] == 0
    mutated[padding_start] = 1
    reject("nonzero_transcript_padding", mutated)

    mutated = bytearray(case.portable)
    sidecar_start = 8 + 2 + 2 + PUBLIC_OUTPUT_BYTES
    mutated[sidecar_start] ^= 1
    reject("public_sidecar", mutated)

    mutated = bytearray(case.portable)
    mutated[padding_start - 1] ^= 1
    reject("authenticated_transcript", mutated)

    mutated = bytearray(case.portable)
    state_root_before = sidecar_start + 16 + 3 * 64
    mutated[state_root_before] ^= 1
    reject("public_root", mutated)

    reject(
        "program_pin",
        case.portable,
        pin=_wide("wrong-governed-program-commitment"),
    )

    for completed in completions:
        _assert_text_excludes_private(completed.stdout + completed.stderr, needles)
    for path in case.scratch.rglob("*"):
        path_text = str(path)
        _assert_text_excludes_private(path_text, needles)
        if path.is_file():
            _assert_file_excludes_private(path, needles)
