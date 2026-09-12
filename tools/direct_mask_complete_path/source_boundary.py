"""Nonactivating public Profile12 caller for the direct-mask source appliance.

The State owner supplies one immutable public context and public coin.  This
module serializes those fields into the exact appliance request and forwards
one request through the existing contained-process boundary.  It owns no
witness, secret key, proof, signature, or persistent source state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, NoReturn

from app.minimal_clearance_resource_limits import ACTIVE_PROCESS_LIMIT, ADMISSION_CAP_BYTES
from app.minimal_clearance_source_auth_verifier_adapter import SOURCE_AUTH_FRAME_BYTES
from app.minimal_clearance_verification_queue import IssuedVerificationBatch
from app.minimal_clearance_verifier_process import (
    ContainedVerifierResult,
    VerifierProcessError,
    run_contained_verifier_stream,
)


SOURCE_APPLIANCE_REQUEST_MAGIC: Final[bytes] = b"DMSR0001"
SOURCE_APPLIANCE_KEY_EPOCH: Final[int] = 1
SOURCE_APPLIANCE_MAX_FINAL_RETRIES: Final[int] = 4_096
SOURCE_APPLIANCE_REQUEST_BYTES: Final[int] = 180
SOURCE_APPLIANCE_REQUEST_EPOCH_OFFSET: Final[int] = 8
SOURCE_APPLIANCE_REQUEST_RETRIES_OFFSET: Final[int] = 16
SOURCE_APPLIANCE_REQUEST_CONTEXT_OFFSET: Final[int] = 20
SOURCE_APPLIANCE_REQUEST_U_OFFSET: Final[int] = 84
SOURCE_APPLIANCE_CONTEXT_BYTES: Final[int] = 64
SOURCE_APPLIANCE_U_BYTES: Final[int] = 96
SOURCE_APPLIANCE_CAPSULE_BYTES: Final[int] = SOURCE_AUTH_FRAME_BYTES
SOURCE_APPLIANCE_STDOUT_CAP_BYTES: Final[int] = SOURCE_APPLIANCE_CAPSULE_BYTES + 1
SOURCE_APPLIANCE_STDERR_CAP_BYTES: Final[int] = 1
SOURCE_APPLIANCE_TIMEOUT_SECONDS: Final[float] = 180.0
SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES: Final[int] = 275_968
SOURCE_APPLIANCE_EXECUTABLE_SHA256: Final[bytes] = bytes.fromhex(
    "D3A36CFAADBB1B6A3455DA44C4DC0E941C00906EC7E281199876F851C503FCA8"
)
CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE: Final[Path] = (
    Path(__file__).resolve().parents[2]
    / "build-performance/fixture-candidate/Release/direct_mask_fixture_source_performance.exe"
)
CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES: Final[int] = 276_480
CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE_SHA256: Final[bytes] = bytes.fromhex(
    "176B237D8277A1CF09EECE1DC58DBB9B012C9B6700C6FB8C04FEF46011FDD626"
)
SOURCE_APPLIANCE_PROCESS_ARGUMENTS: Final[tuple[str, ...]] = ()


class SourceBoundaryError(RuntimeError):
    """Sanitized source-boundary failure; process details never cross this seam."""


def _fail(code: str) -> NoReturn:
    error = SourceBoundaryError(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0
    value.clear()


def _validate_batch(batch: IssuedVerificationBatch) -> None:
    if type(batch) is not IssuedVerificationBatch:
        _fail("source_batch_shape")
    try:
        batch.__post_init__()
    except BaseException:
        _fail("source_batch_binding")
    if type(batch.proof_context) is not bytes or len(batch.proof_context) != SOURCE_APPLIANCE_CONTEXT_BYTES:
        _fail("source_context")
    if type(batch.public_coin) is not bytes or len(batch.public_coin) != SOURCE_APPLIANCE_U_BYTES:
        _fail("source_public_coin")
    if batch.public_coin == bytes(SOURCE_APPLIANCE_U_BYTES):
        _fail("source_public_coin")
    if type(batch.operation_refs) is not tuple or len(batch.operation_refs) != 100:
        _fail("source_operation_count")


def build_source_request(*, batch: IssuedVerificationBatch, source_key_epoch: int) -> bytearray:
    """Build exactly the public 180-byte request accepted by the appliance."""

    _validate_batch(batch)
    if type(source_key_epoch) is not int or source_key_epoch != SOURCE_APPLIANCE_KEY_EPOCH:
        _fail("source_key_epoch")
    request = bytearray(SOURCE_APPLIANCE_REQUEST_BYTES)
    request[: len(SOURCE_APPLIANCE_REQUEST_MAGIC)] = SOURCE_APPLIANCE_REQUEST_MAGIC
    request[
        SOURCE_APPLIANCE_REQUEST_EPOCH_OFFSET :
        SOURCE_APPLIANCE_REQUEST_EPOCH_OFFSET + 8
    ] = SOURCE_APPLIANCE_KEY_EPOCH.to_bytes(8, "little")
    request[
        SOURCE_APPLIANCE_REQUEST_RETRIES_OFFSET :
        SOURCE_APPLIANCE_REQUEST_RETRIES_OFFSET + 4
    ] = SOURCE_APPLIANCE_MAX_FINAL_RETRIES.to_bytes(4, "little")
    request[
        SOURCE_APPLIANCE_REQUEST_CONTEXT_OFFSET :
        SOURCE_APPLIANCE_REQUEST_CONTEXT_OFFSET + SOURCE_APPLIANCE_CONTEXT_BYTES
    ] = batch.proof_context
    request[
        SOURCE_APPLIANCE_REQUEST_U_OFFSET :
        SOURCE_APPLIANCE_REQUEST_U_OFFSET + SOURCE_APPLIANCE_U_BYTES
    ] = batch.public_coin
    if len(request) != SOURCE_APPLIANCE_REQUEST_BYTES:
        _fail("source_request_shape")
    return request


@dataclass(frozen=True, slots=True)
class SourceApplianceConfig:
    """Pinned executable/workspace configuration for one source call."""

    executable_path: Path
    workspace: Path
    executable_size_bytes: int
    executable_sha256: bytes = field(repr=False)
    timeout_seconds: float = SOURCE_APPLIANCE_TIMEOUT_SECONDS
    identity_profile: str = "accepted"

    def __post_init__(self) -> None:
        if not isinstance(self.executable_path, Path) or not self.executable_path.is_absolute():
            _fail("source_executable_path")
        if not isinstance(self.workspace, Path) or not self.workspace.is_absolute() or not self.workspace.is_dir():
            _fail("source_workspace")
        if self.identity_profile == "accepted":
            expected_size = SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES
            expected_sha256 = SOURCE_APPLIANCE_EXECUTABLE_SHA256
        elif self.identity_profile == "child-performance":
            if self.executable_path.resolve() != CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE:
                _fail("source_executable_identity")
            expected_size = CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES
            expected_sha256 = CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE_SHA256
        else:
            _fail("source_executable_identity")
        if self.executable_size_bytes != expected_size:
            _fail("source_executable_identity")
        if type(self.executable_sha256) is not bytes or self.executable_sha256 != expected_sha256:
            _fail("source_executable_identity")
        if type(self.timeout_seconds) is not float or not 0 < self.timeout_seconds <= SOURCE_APPLIANCE_TIMEOUT_SECONDS:
            _fail("source_timeout")


def _validate_contained_result(result: object) -> bytearray:
    if type(result) is not ContainedVerifierResult:
        _fail("source_process")
    numeric_fields = (
        result.peak_job_commit_bytes,
        result.peak_working_set_bytes,
        result.peak_private_commit_bytes,
        result.parent_peak_working_set_bytes,
        result.parent_peak_private_commit_bytes,
        result.private_commit_delta_bytes,
        result.scratch_peak_bytes,
    )
    if (
        type(result.exit_code) is not int
        or result.exit_code != 0
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or result.timed_out is not False
        or result.cap_enforced is not True
        or type(result.cap_bytes) is not int
        or result.cap_bytes != ADMISSION_CAP_BYTES
        or type(result.active_process_limit) is not int
        or result.active_process_limit != ACTIVE_PROCESS_LIMIT
        or type(result.child_process_count) is not int
        or result.child_process_count < 1
        or result.process_tree_complete is not True
        or result.measurement_complete is not True
        or result.cleanup_complete is not True
        or result.pagefile_growth_evidence != "unavailable"
        or any(type(value) is not int or value < 0 for value in numeric_fields)
        or result.peak_job_commit_bytes > result.cap_bytes
    ):
        if result.timed_out is True:
            _fail("source_timeout")
        _fail("source_process")
    if result.stderr:
        _fail("source_stderr")
    if len(result.stdout) != SOURCE_APPLIANCE_CAPSULE_BYTES:
        _fail("source_capsule_shape")
    return bytearray(result.stdout)


class Profile12SourceBoundaryCaller:
    """One public State request to the unqualified source appliance."""

    __slots__ = ("_config",)

    def __init__(self, config: SourceApplianceConfig) -> None:
        if type(config) is not SourceApplianceConfig:
            _fail("source_config")
        self._config = config

    @property
    def config(self) -> SourceApplianceConfig:
        return self._config

    def prove_one(self, *, batch: IssuedVerificationBatch, source_key_epoch: int) -> bytearray:
        request = build_source_request(batch=batch, source_key_epoch=source_key_epoch)
        try:
            return self._run_one_request(request)
        finally:
            try:
                _wipe(request)
            except BaseException:
                _fail("source_cleanup")

    def _run_one_request(self, request: bytearray) -> bytearray:
        try:
            contained = run_contained_verifier_stream(
                self._config.executable_path,
                SOURCE_APPLIANCE_PROCESS_ARGUMENTS,
                request,
                workspace=self._config.workspace,
                timeout_seconds=self._config.timeout_seconds,
                expected_executable_size_bytes=self._config.executable_size_bytes,
                expected_executable_sha256=self._config.executable_sha256,
                stdout_cap_bytes=SOURCE_APPLIANCE_STDOUT_CAP_BYTES,
                stderr_cap_bytes=SOURCE_APPLIANCE_STDERR_CAP_BYTES,
                stdout_ascii=False,
                expected_input_bytes=SOURCE_APPLIANCE_REQUEST_BYTES,
            )
            return _validate_contained_result(contained)
        except SourceBoundaryError:
            raise
        except VerifierProcessError as error:
            if str(error).startswith("verifier_timeout"):
                _fail("source_timeout")
            if str(error).startswith("verifier_workspace"):
                _fail("source_workspace")
            _fail("source_process")
        except BaseException:
            _fail("source_process")


__all__ = (
    "Profile12SourceBoundaryCaller",
    "SourceApplianceConfig",
    "SourceBoundaryError",
    "SOURCE_APPLIANCE_CAPSULE_BYTES",
    "SOURCE_APPLIANCE_CONTEXT_BYTES",
    "SOURCE_APPLIANCE_EXECUTABLE_SHA256",
    "SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES",
    "CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE",
    "CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE_SHA256",
    "CHILD_PERFORMANCE_SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES",
    "SOURCE_APPLIANCE_KEY_EPOCH",
    "SOURCE_APPLIANCE_MAX_FINAL_RETRIES",
    "SOURCE_APPLIANCE_PROCESS_ARGUMENTS",
    "SOURCE_APPLIANCE_REQUEST_BYTES",
    "SOURCE_APPLIANCE_REQUEST_CONTEXT_OFFSET",
    "SOURCE_APPLIANCE_REQUEST_EPOCH_OFFSET",
    "SOURCE_APPLIANCE_REQUEST_MAGIC",
    "SOURCE_APPLIANCE_REQUEST_RETRIES_OFFSET",
    "SOURCE_APPLIANCE_REQUEST_U_OFFSET",
    "SOURCE_APPLIANCE_STDERR_CAP_BYTES",
    "SOURCE_APPLIANCE_STDOUT_CAP_BYTES",
    "SOURCE_APPLIANCE_TIMEOUT_SECONDS",
    "SOURCE_APPLIANCE_U_BYTES",
    "build_source_request",
)
