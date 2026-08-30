"""Nonactivating Queue adapter shell for the signed Native Profile 9 source boundary.

The adapter owns only volatile frame assembly and the narrow process call.  It
does not parse proof material, select a disposition, or persist source,
signature, key, frame, IPC, or process-output bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import shutil
import tempfile
from typing import Final, NoReturn

from app.minimal_clearance_resource_limits import (
    ACTIVE_PROCESS_LIMIT,
    ADMISSION_CAP_BYTES,
)
from app.minimal_clearance_verification_queue import (
    BatchVerifierResult,
    IssuedVerificationBatch,
    PROOF_STATEMENT_BYTES,
    QueueConfig,
    QueueHeldError,
    QueueIntegrityError,
    VolatileProofHandoff,
)
from app.minimal_clearance_verifier_process import (
    ContainedVerifierResult,
    VerifierProcessError,
    run_contained_verifier_stream,
)


SOURCE_AUTH_FRAME_BYTES: Final[int] = 24_853_179
ML_DSA_87_PUBLIC_KEY_BYTES: Final[int] = 2_592
SOURCE_AUTH_IPC_BYTES: Final[int] = 24_859_347
SOURCE_AUTH_PROCESS_ARGUMENTS: Final[tuple[str, ...]] = ()
SOURCE_AUTH_TIMEOUT_SECONDS: Final[float] = 30.0
SOURCE_AUTH_EXECUTABLE_SIZE_BYTES: Final[int] = 58_880
SOURCE_AUTH_EXECUTABLE_SHA256: Final[bytes] = bytes.fromhex(
    "855C089EF8E4B23FF4D63B453215FBA2DA31E6B377B49A90DABA08C18F3A1107"
)


def _raise_fixed(error: QueueHeldError | QueueIntegrityError) -> NoReturn:
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


def _hold(code: str) -> NoReturn:
    _raise_fixed(QueueHeldError(code))


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0
    value.clear()


def _new_disposable_workspace(parent: Path) -> Path:
    if not parent.is_dir() or parent.is_symlink():
        _hold("verifier_workspace")
    try:
        return Path(tempfile.mkdtemp(prefix=".blind-verifier-", dir=str(parent)))
    except (OSError, ValueError):
        _hold("verifier_workspace")


def _remove_disposable_workspace(workspace: Path) -> None:
    try:
        if workspace.is_symlink():
            workspace.unlink()
        elif workspace.is_dir():
            shutil.rmtree(workspace)
        elif workspace.exists():
            workspace.unlink()
    except FileNotFoundError:
        return
    except BaseException:
        _hold("verifier_workspace_cleanup")


@dataclass(frozen=True, slots=True)
class SourceAuthVerifierConfig:
    """Volatile adapter configuration; the public key is deliberately not repr-able."""

    queue_config: QueueConfig
    executable_path: Path
    executable_size_bytes: int
    executable_sha256: bytes = field(repr=False)
    workspace: Path
    ml_dsa_87_public_key: bytes = field(repr=False, compare=False, hash=False)
    timeout_seconds: float = SOURCE_AUTH_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if type(self.queue_config) is not QueueConfig:
            raise ValueError("source_auth_queue_config") from None
        if not isinstance(self.executable_path, Path) or not self.executable_path.is_absolute():
            raise ValueError("source_auth_executable_path") from None
        if self.executable_size_bytes != SOURCE_AUTH_EXECUTABLE_SIZE_BYTES:
            raise ValueError("source_auth_executable_identity") from None
        if self.executable_sha256 != SOURCE_AUTH_EXECUTABLE_SHA256:
            raise ValueError("source_auth_executable_identity") from None
        if not isinstance(self.workspace, Path) or not self.workspace.is_absolute():
            raise ValueError("source_auth_workspace") from None
        if type(self.ml_dsa_87_public_key) is not bytes or len(self.ml_dsa_87_public_key) != ML_DSA_87_PUBLIC_KEY_BYTES:
            raise ValueError("source_auth_public_key") from None
        if type(self.timeout_seconds) is not float or not 0 < self.timeout_seconds <= SOURCE_AUTH_TIMEOUT_SECONDS:
            raise ValueError("source_auth_timeout") from None


def _read_exact_frame(handoff: VolatileProofHandoff) -> bytearray:
    if handoff.used:
        _hold("proof_handoff_closed")
    frame = bytearray()
    complete = False
    try:
        while len(frame) < SOURCE_AUTH_FRAME_BYTES:
            needed = SOURCE_AUTH_FRAME_BYTES - len(frame)
            chunk = handoff.read(needed)
            if type(chunk) is not bytes or not chunk or len(chunk) > needed:
                _hold("proof_handoff_length")
            frame.extend(chunk)
        trailing = handoff.read(1)
        if type(trailing) is not bytes or trailing or not handoff.exhausted:
            _hold("proof_handoff_length")
        complete = True
        return frame
    except (QueueHeldError, QueueIntegrityError):
        raise
    except BaseException:
        _hold("verifier_transport")
    finally:
        if not complete:
            _wipe(frame)


def _build_ipc_input(*, batch: IssuedVerificationBatch, source_key_epoch: int, public_key: bytes, frame: bytearray) -> bytearray:
    if type(source_key_epoch) is not int or not 1 <= source_key_epoch <= 2**64 - 1:
        _raise_fixed(QueueIntegrityError("verifier_key_epoch"))
    if type(public_key) is not bytes or len(public_key) != ML_DSA_87_PUBLIC_KEY_BYTES:
        _raise_fixed(QueueIntegrityError("verifier_result_shape"))
    if len(frame) != SOURCE_AUTH_FRAME_BYTES:
        _raise_fixed(QueueIntegrityError("proof_handoff_length"))
    try:
        if type(batch) is not IssuedVerificationBatch:
            _raise_fixed(QueueIntegrityError("batch_required"))
        batch.__post_init__()
    except (QueueHeldError, QueueIntegrityError):
        raise
    except BaseException:
        _hold("batch_binding")
    ipc = bytearray(SOURCE_AUTH_IPC_BYTES)
    offset = 0
    ipc[offset : offset + 8] = source_key_epoch.to_bytes(8, "little")
    offset += 8
    ipc[offset : offset + 64] = batch.batch_root
    offset += 64
    refs = b"".join(batch.operation_refs)
    if len(refs) != 3_200:
        _hold("batch_binding")
    ipc[offset : offset + 3_200] = refs
    offset += 3_200
    ipc[offset : offset + PROOF_STATEMENT_BYTES] = batch.proof_statement
    offset += PROOF_STATEMENT_BYTES
    ipc[offset : offset + ML_DSA_87_PUBLIC_KEY_BYTES] = public_key
    offset += ML_DSA_87_PUBLIC_KEY_BYTES
    ipc[offset:] = frame
    if offset + len(frame) != SOURCE_AUTH_IPC_BYTES:
        _raise_fixed(QueueIntegrityError("verifier_result_shape"))
    return ipc


def _validate_contained_result(result: object) -> ContainedVerifierResult:
    if type(result) is not ContainedVerifierResult:
        _hold("verifier_transport")
    if (
        type(result.exit_code) is not int
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or result.stdout
        or result.stderr
        or result.timed_out is not False
        or result.cap_enforced is not True
        or type(result.cap_bytes) is not int
        or result.cap_bytes != ADMISSION_CAP_BYTES
        or type(result.active_process_limit) is not int
        or result.active_process_limit != ACTIVE_PROCESS_LIMIT
        or type(result.peak_job_commit_bytes) is not int
        or not 0 <= result.peak_job_commit_bytes <= result.cap_bytes
        or type(result.child_process_count) is not int
        or result.child_process_count < 1
        or result.process_tree_complete is not True
        or result.measurement_complete is not True
        or result.cleanup_complete is not True
    ):
        if getattr(result, "timed_out", False) is True:
            _hold("verifier_timeout")
        _hold("verifier_transport")
    return result


class MinimalClearanceSourceAuthVerifierAdapter:
    """Direct Queue VerifierPort adapter for the future signed C process."""

    __slots__ = ("_config",)

    def __init__(self, config: SourceAuthVerifierConfig) -> None:
        if type(config) is not SourceAuthVerifierConfig:
            raise ValueError("source_auth_config") from None
        self._config = config

    @property
    def config(self) -> SourceAuthVerifierConfig:
        return self._config

    def verify(self, stream: VolatileProofHandoff, issued_batch: IssuedVerificationBatch) -> BatchVerifierResult:
        if type(stream) is not VolatileProofHandoff:
            _hold("proof_handoff_stream")
        frame: bytearray | None = None
        ipc: bytearray | None = None
        workspace: Path | None = None
        try:
            frame = _read_exact_frame(stream)
            ipc = _build_ipc_input(
                batch=issued_batch,
                source_key_epoch=self._config.queue_config.source_key_epoch,
                public_key=self._config.ml_dsa_87_public_key,
                frame=frame,
            )
            workspace = _new_disposable_workspace(self._config.workspace)
            try:
                contained = run_contained_verifier_stream(
                    self._config.executable_path,
                    SOURCE_AUTH_PROCESS_ARGUMENTS,
                    ipc,
                    workspace=workspace,
                    timeout_seconds=self._config.timeout_seconds,
                    expected_executable_size_bytes=self._config.executable_size_bytes,
                    expected_executable_sha256=self._config.executable_sha256,
                )
            except VerifierProcessError as error:
                if str(error).startswith("verifier_timeout"):
                    _hold("verifier_timeout")
                _hold("verifier_transport")
            except BaseException:
                _hold("verifier_transport")
            result = _validate_contained_result(contained)
            if result.exit_code == 0:
                return BatchVerifierResult(
                    True,
                    True,
                    issued_batch.proof_statement,
                    issued_batch.batch_root,
                    self._config.queue_config.source_auth_profile,
                    self._config.queue_config.source_key_epoch,
                    "accepted",
                    self._config.queue_config.qualification_flags,
                )
            if result.exit_code == 1:
                return BatchVerifierResult(
                    False,
                    False,
                    issued_batch.proof_statement,
                    issued_batch.batch_root,
                    self._config.queue_config.source_auth_profile,
                    self._config.queue_config.source_key_epoch,
                    "rejected",
                    self._config.queue_config.qualification_flags,
                )
            _hold("verifier_transport")
        finally:
            for value in (frame, ipc):
                if value is not None:
                    _wipe(value)
            stream.wipe()
            if workspace is not None:
                _remove_disposable_workspace(workspace)


SourceAuthVerifierAdapterConfig = SourceAuthVerifierConfig
SourceAuthVerifierAdapter = MinimalClearanceSourceAuthVerifierAdapter


__all__ = (
    "ML_DSA_87_PUBLIC_KEY_BYTES",
    "MinimalClearanceSourceAuthVerifierAdapter",
    "SOURCE_AUTH_FRAME_BYTES",
    "SOURCE_AUTH_EXECUTABLE_SHA256",
    "SOURCE_AUTH_EXECUTABLE_SIZE_BYTES",
    "SOURCE_AUTH_IPC_BYTES",
    "SOURCE_AUTH_PROCESS_ARGUMENTS",
    "SOURCE_AUTH_TIMEOUT_SECONDS",
    "SourceAuthVerifierAdapter",
    "SourceAuthVerifierAdapterConfig",
    "SourceAuthVerifierConfig",
)
