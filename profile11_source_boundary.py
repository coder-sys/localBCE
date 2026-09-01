"""E2E-only Profile 11 public source-request boundary.

The Queue sends one exact V2 request containing only the expected source epoch,
batch root, ordered opaque references, and the canonical 304-byte statement.
The test-only Rust host owns one synthetic SourceTransactionAuthority lifecycle,
the fixed test witness/seed, ML-DSA secret key, randomizer, proof, signature, and
complete frame. None of those private values crosses this Python boundary or is
written to disk. The host returns exactly one 16,302,267-byte frame; launch,
receipt, and status remain source-owned opaque state, and the independently pinned
C process then verifies the frame. This module makes no production,
qualification, or filesystem-observation claim.
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


SOURCE_APPLIANCE_REQUEST_MAGIC: Final[bytes] = b"BL-SRC-REQ-V2\0\0\0"
SOURCE_APPLIANCE_PROTOCOL_VERSION: Final[int] = 2
SOURCE_AUTH_REQUEST_BYTES: Final[int] = 3_596
SOURCE_AUTH_INPUT_BYTES: Final[int] = SOURCE_AUTH_REQUEST_BYTES
SOURCE_AUTH_ORDERED_REFS_BYTES: Final[int] = 3_200
SOURCE_AUTH_STATEMENT_BYTES: Final[int] = 304
SOURCE_AUTH_OPERATION_COUNT: Final[int] = 100
SOURCE_AUTH_REQUEST_VERSION_OFFSET: Final[int] = 16
SOURCE_AUTH_REQUEST_RESERVED_OFFSET: Final[int] = 18
SOURCE_AUTH_REQUEST_EPOCH_OFFSET: Final[int] = 20
SOURCE_AUTH_REQUEST_ROOT_OFFSET: Final[int] = 28
SOURCE_AUTH_REQUEST_REFS_OFFSET: Final[int] = 92
SOURCE_AUTH_REQUEST_STATEMENT_OFFSET: Final[int] = 3_292
SOURCE_AUTH_STDOUT_CAP_BYTES: Final[int] = SOURCE_AUTH_FRAME_BYTES + 1
SOURCE_AUTH_STDERR_CAP_BYTES: Final[int] = 1

# This is the measured test-only host release built from the source below
# against the accepted C libraries. It is not a production artifact.
SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES: Final[int] = 480_768
SOURCE_APPLIANCE_EXECUTABLE_SHA256: Final[bytes] = bytes.fromhex(
    "3D2C0A468303E68AA63B2A6A52BA922422231695D589ED1562E4F1CA3A8F5562"
)


class SourceBoundaryError(RuntimeError):
    """Fixed source-boundary failure; raw process output never crosses the seam."""


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
    if len(batch.operation_refs) != SOURCE_AUTH_OPERATION_COUNT:
        _fail("source_operation_count")


def build_request_record(*, batch: IssuedVerificationBatch, source_key_epoch: int) -> bytearray:
    """Serialize only the exact public V2 request; private material is impossible here."""

    _validate_batch(batch)
    if type(source_key_epoch) is not int or not 1 <= source_key_epoch <= 2**64 - 1:
        _fail("source_key_epoch")
    ordered_refs = b"".join(batch.operation_refs)
    if len(ordered_refs) != SOURCE_AUTH_ORDERED_REFS_BYTES:
        _fail("source_batch_binding")
    statement = batch.proof_statement
    if type(statement) is not bytes or len(statement) != SOURCE_AUTH_STATEMENT_BYTES:
        _fail("source_statement")
    request = bytearray(SOURCE_AUTH_REQUEST_BYTES)
    request[:16] = SOURCE_APPLIANCE_REQUEST_MAGIC
    request[SOURCE_AUTH_REQUEST_VERSION_OFFSET:SOURCE_AUTH_REQUEST_VERSION_OFFSET + 2] = SOURCE_APPLIANCE_PROTOCOL_VERSION.to_bytes(2, "little")
    request[SOURCE_AUTH_REQUEST_RESERVED_OFFSET:SOURCE_AUTH_REQUEST_RESERVED_OFFSET + 2] = b"\0\0"
    request[SOURCE_AUTH_REQUEST_EPOCH_OFFSET:SOURCE_AUTH_REQUEST_EPOCH_OFFSET + 8] = source_key_epoch.to_bytes(8, "little")
    request[SOURCE_AUTH_REQUEST_ROOT_OFFSET:SOURCE_AUTH_REQUEST_ROOT_OFFSET + 64] = batch.batch_root
    request[SOURCE_AUTH_REQUEST_REFS_OFFSET:SOURCE_AUTH_REQUEST_REFS_OFFSET + SOURCE_AUTH_ORDERED_REFS_BYTES] = ordered_refs
    request[SOURCE_AUTH_REQUEST_STATEMENT_OFFSET:] = statement
    if len(request) != SOURCE_AUTH_REQUEST_BYTES:
        _fail("source_request_shape")
    return request


@dataclass(frozen=True, slots=True)
class SourceApplianceConfig:
    executable_path: Path
    workspace: Path
    executable_size_bytes: int
    executable_sha256: bytes = field(repr=False)
    timeout_seconds: float = 180.0

    def __post_init__(self) -> None:
        if not isinstance(self.executable_path, Path) or not self.executable_path.is_absolute():
            _fail("source_executable_path")
        if not isinstance(self.workspace, Path) or not self.workspace.is_absolute() or not self.workspace.is_dir():
            _fail("source_workspace")
        if self.executable_size_bytes != SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES:
            _fail("source_executable_identity")
        if self.executable_sha256 != SOURCE_APPLIANCE_EXECUTABLE_SHA256:
            _fail("source_executable_identity")
        if type(self.timeout_seconds) is not float or not 0 < self.timeout_seconds <= 180.0:
            _fail("source_timeout")


def _validate_contained_result(result: object) -> bytearray:
    if type(result) is not ContainedVerifierResult:
        _fail("source_process")
    if result.timed_out is True:
        _fail("source_timeout")
    if result.timed_out is not False:
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
        or result.cap_enforced is not True
        or result.cap_bytes != ADMISSION_CAP_BYTES
        or result.active_process_limit != ACTIVE_PROCESS_LIMIT
        or result.child_process_count < 1
        or result.process_tree_complete is not True
        or result.measurement_complete is not True
        or result.cleanup_complete is not True
        or result.pagefile_growth_evidence != "unavailable"
        or any(type(value) is not int or value < 0 for value in numeric_fields)
        or result.peak_job_commit_bytes > result.cap_bytes
    ):
        _fail("source_process")
    if result.stderr:
        _fail("source_stderr")
    if len(result.stdout) < SOURCE_AUTH_FRAME_BYTES:
        _fail("source_frame_truncated")
    if len(result.stdout) > SOURCE_AUTH_FRAME_BYTES:
        _fail("source_frame_trailing")
    return bytearray(result.stdout)


class Profile11SourceBoundaryCaller:
    """One public V2 request to the source-owned test host."""

    __slots__ = ("_config",)

    def __init__(self, config: SourceApplianceConfig) -> None:
        if type(config) is not SourceApplianceConfig:
            _fail("source_config")
        self._config = config

    @property
    def config(self) -> SourceApplianceConfig:
        return self._config

    def prove_one(self, *, batch: IssuedVerificationBatch, source_key_epoch: int) -> bytearray:
        request = build_request_record(batch=batch, source_key_epoch=source_key_epoch)
        try:
            return self._run_one_request(request)
        finally:
            _wipe(request)

    def _run_one_request(self, request: bytearray) -> bytearray:
        contained: ContainedVerifierResult | None = None
        try:
            contained = run_contained_verifier_stream(
                self._config.executable_path,
                (),
                request,
                workspace=self._config.workspace,
                timeout_seconds=self._config.timeout_seconds,
                expected_executable_size_bytes=self._config.executable_size_bytes,
                expected_executable_sha256=self._config.executable_sha256,
                stdout_cap_bytes=SOURCE_AUTH_STDOUT_CAP_BYTES,
                stderr_cap_bytes=SOURCE_AUTH_STDERR_CAP_BYTES,
                stdout_ascii=False,
                expected_input_bytes=SOURCE_AUTH_INPUT_BYTES,
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
        finally:
            del contained


__all__ = (
    "Profile11SourceBoundaryCaller",
    "SourceApplianceConfig",
    "SourceBoundaryError",
    "SOURCE_APPLIANCE_EXECUTABLE_SHA256",
    "SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES",
    "SOURCE_APPLIANCE_PROTOCOL_VERSION",
    "SOURCE_APPLIANCE_REQUEST_MAGIC",
    "SOURCE_AUTH_FRAME_BYTES",
    "SOURCE_AUTH_INPUT_BYTES",
    "SOURCE_AUTH_OPERATION_COUNT",
    "SOURCE_AUTH_ORDERED_REFS_BYTES",
    "SOURCE_AUTH_REQUEST_BYTES",
    "SOURCE_AUTH_REQUEST_EPOCH_OFFSET",
    "SOURCE_AUTH_REQUEST_REFS_OFFSET",
    "SOURCE_AUTH_REQUEST_ROOT_OFFSET",
    "SOURCE_AUTH_REQUEST_STATEMENT_OFFSET",
    "SOURCE_AUTH_REQUEST_VERSION_OFFSET",
    "SOURCE_AUTH_REQUEST_RESERVED_OFFSET",
    "SOURCE_AUTH_STATEMENT_BYTES",
    "SOURCE_AUTH_STDERR_CAP_BYTES",
    "SOURCE_AUTH_STDOUT_CAP_BYTES",
    "build_request_record",
)
