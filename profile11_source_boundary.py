"""E2E-only Profile 11 source-boundary caller.

This module is evidence plumbing, not Queue production code.  The caller owns
the appliance provision record and source-only witness/seed/randomizer bytes.
For this E2E exercise it serializes the 4,896-byte secret and source inputs to
the accepted appliance's stdin, does not expose them to Queue or intentionally
persist/log them, and is not the production no-serialization/custody boundary.
It transfers one complete frame to Queue.  OS-level process-tree and
filesystem tracing remain external gates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import subprocess
from typing import Final, NoReturn

from app.minimal_clearance_source_auth_verifier_adapter import SOURCE_AUTH_FRAME_BYTES
from app.minimal_clearance_verification_queue import IssuedVerificationBatch


SOURCE_APPLIANCE_PROVISION_MAGIC: Final[bytes] = b"BL-SRC-HOST-V1\0\0"
SOURCE_APPLIANCE_REQUEST_MAGIC: Final[bytes] = b"BL-SRC-REQ-V1\0\0\0"
SOURCE_APPLIANCE_PROTOCOL_VERSION: Final[int] = 1
SOURCE_AUTH_ORDERED_REFS_BYTES: Final[int] = 3_200
SOURCE_AUTH_SECRET_KEY_BYTES: Final[int] = 4_896
SOURCE_AUTH_RANDOMIZER_BYTES: Final[int] = 32
SOURCE_AUTH_PROVISION_BYTES: Final[int] = 4_924
SOURCE_AUTH_REQUEST_BYTES: Final[int] = 4_544
SOURCE_AUTH_WITNESS_COUNT: Final[int] = 100
SOURCE_AUTH_WITNESS_BYTES: Final[int] = 800
SOURCE_AUTH_SEED_BYTES: Final[int] = 128
SOURCE_AUTH_LOWER: Final[int] = 0x1122_3344_5566_7788
SOURCE_AUTH_UPPER: Final[int] = 0xDD_EE_FF_00_1122_3344
SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES: Final[int] = 458_240
SOURCE_APPLIANCE_EXECUTABLE_SHA256: Final[bytes] = bytes.fromhex(
    "CC367F04BB2E9519DED8AA393C05ACE209C4952A4AE4BD8E433D8CB0619B90B8"
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


def _validate_source_values(
    *,
    witness: tuple[int, ...],
    seed: bytes,
    randomizer: bytes,
) -> None:
    if type(witness) is not tuple or len(witness) != SOURCE_AUTH_WITNESS_COUNT:
        _fail("source_witness")
    if any(type(value) is not int or not SOURCE_AUTH_LOWER <= value <= SOURCE_AUTH_UPPER for value in witness):
        _fail("source_witness")
    if type(seed) is not bytes or len(seed) != SOURCE_AUTH_SEED_BYTES:
        _fail("source_seed")
    if type(randomizer) is not bytes or len(randomizer) != SOURCE_AUTH_RANDOMIZER_BYTES:
        _fail("source_randomizer")


def _validate_material(
    *,
    secret_key: bytes,
    witness: tuple[int, ...],
    seed: bytes,
    randomizer: bytes,
) -> None:
    if type(secret_key) is not bytes or len(secret_key) != SOURCE_AUTH_SECRET_KEY_BYTES:
        _fail("source_secret_key")
    _validate_source_values(witness=witness, seed=seed, randomizer=randomizer)


def build_provision_record(*, source_key_epoch: int, secret_key: bytes) -> bytearray:
    if type(source_key_epoch) is not int or not 1 <= source_key_epoch <= 2**64 - 1:
        _fail("source_key_epoch")
    if type(secret_key) is not bytes or len(secret_key) != SOURCE_AUTH_SECRET_KEY_BYTES:
        _fail("source_secret_key")
    record = bytearray(SOURCE_AUTH_PROVISION_BYTES)
    record[:16] = SOURCE_APPLIANCE_PROVISION_MAGIC
    record[16:18] = SOURCE_APPLIANCE_PROTOCOL_VERSION.to_bytes(2, "little")
    record[20:28] = source_key_epoch.to_bytes(8, "little")
    record[28:] = secret_key
    return record


def build_request_record(
    *,
    batch: IssuedVerificationBatch,
    witness: tuple[int, ...],
    seed: bytes,
    randomizer: bytes,
) -> bytearray:
    _validate_batch(batch)
    _validate_source_values(witness=witness, seed=seed, randomizer=randomizer)
    record = bytearray(SOURCE_AUTH_REQUEST_BYTES)
    cursor = 0
    record[cursor:cursor + 16] = SOURCE_APPLIANCE_REQUEST_MAGIC
    cursor += 16
    record[cursor:cursor + 64] = batch.batch_root
    cursor += 64
    ordered_refs = b"".join(batch.operation_refs)
    if len(ordered_refs) != SOURCE_AUTH_ORDERED_REFS_BYTES:
        _fail("source_batch_binding")
    record[cursor:cursor + SOURCE_AUTH_ORDERED_REFS_BYTES] = ordered_refs
    cursor += SOURCE_AUTH_ORDERED_REFS_BYTES
    record[cursor:cursor + len(batch.proof_statement)] = batch.proof_statement
    cursor += len(batch.proof_statement)
    for value in witness:
        record[cursor:cursor + 8] = value.to_bytes(8, "little")
        cursor += 8
    record[cursor:cursor + SOURCE_AUTH_SEED_BYTES] = seed
    cursor += SOURCE_AUTH_SEED_BYTES
    record[cursor:cursor + SOURCE_AUTH_RANDOMIZER_BYTES] = randomizer
    cursor += SOURCE_AUTH_RANDOMIZER_BYTES
    if cursor != SOURCE_AUTH_REQUEST_BYTES:
        _fail("source_request_shape")
    return record


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


class Profile11SourceBoundaryCaller:
    """Source-owned one-request caller for the accepted persistent appliance."""

    __slots__ = ("_config",)

    def __init__(self, config: SourceApplianceConfig) -> None:
        if type(config) is not SourceApplianceConfig:
            _fail("source_config")
        self._config = config

    @property
    def config(self) -> SourceApplianceConfig:
        return self._config

    def prove_one(
        self,
        *,
        batch: IssuedVerificationBatch,
        source_key_epoch: int,
        secret_key: bytes,
        witness: tuple[int, ...],
        seed: bytes,
        randomizer: bytes,
    ) -> bytearray:
        _validate_batch(batch)
        _validate_material(
            secret_key=secret_key,
            witness=witness,
            seed=seed,
            randomizer=randomizer,
        )
        provision = build_provision_record(source_key_epoch=source_key_epoch, secret_key=secret_key)
        request = build_request_record(batch=batch, witness=witness, seed=seed, randomizer=randomizer)
        payload = bytearray(provision)
        payload.extend(request)
        _wipe(provision)
        _wipe(request)
        try:
            return self._run_one_request(payload)
        finally:
            _wipe(payload)

    def _run_one_request(self, payload: bytearray) -> bytearray:
        try:
            if (
                not self._config.executable_path.is_file()
                or self._config.executable_path.stat().st_size != self._config.executable_size_bytes
            ):
                _fail("source_executable_identity")
            actual_sha256 = hashlib.sha256(self._config.executable_path.read_bytes()).digest()
        except SourceBoundaryError:
            raise
        except BaseException:
            _fail("source_executable_identity")
        if actual_sha256 != self._config.executable_sha256:
            _fail("source_executable_identity")
        try:
            if any(self._config.workspace.iterdir()):
                _fail("source_workspace_not_empty")
        except SourceBoundaryError:
            raise
        except BaseException:
            _fail("source_workspace")

        process: subprocess.Popen[bytes] | None = None
        frame = bytearray()
        try:
            process = subprocess.Popen(
                [str(self._config.executable_path)],
                cwd=self._config.workspace,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if process.stdin is None or process.stdout is None or process.stderr is None:
                _fail("source_process")
            process.stdin.write(payload)
            process.stdin.flush()
            process.stdin.close()
            while len(frame) < SOURCE_AUTH_FRAME_BYTES:
                chunk = process.stdout.read(min(64 * 1024, SOURCE_AUTH_FRAME_BYTES - len(frame)))
                if not chunk:
                    break
                frame.extend(chunk)
            if process.poll() is None:
                try:
                    process.wait(timeout=self._config.timeout_seconds)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                    _fail("source_timeout")
            trailing = process.stdout.read(1)
            stderr = process.stderr.read()
            if process.returncode != 0:
                _fail("source_process")
            if stderr:
                _fail("source_stderr")
            if len(frame) != SOURCE_AUTH_FRAME_BYTES:
                _fail("source_frame_truncated")
            if trailing:
                _fail("source_frame_trailing")
            return frame
        except SourceBoundaryError:
            _wipe(frame)
            raise
        except (BrokenPipeError, OSError):
            _wipe(frame)
            _fail("source_process")
        except BaseException:
            _wipe(frame)
            _fail("source_process")
        finally:
            if process is not None:
                if process.poll() is None:
                    try:
                        process.kill()
                        process.wait(timeout=10)
                    except BaseException:
                        pass
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except BaseException:
                            pass


__all__ = (
    "Profile11SourceBoundaryCaller",
    "SourceApplianceConfig",
    "SourceBoundaryError",
    "SOURCE_APPLIANCE_PROVISION_MAGIC",
    "SOURCE_APPLIANCE_PROTOCOL_VERSION",
    "SOURCE_APPLIANCE_REQUEST_MAGIC",
    "SOURCE_APPLIANCE_EXECUTABLE_SHA256",
    "SOURCE_APPLIANCE_EXECUTABLE_SIZE_BYTES",
    "SOURCE_AUTH_FRAME_BYTES",
    "SOURCE_AUTH_LOWER",
    "SOURCE_AUTH_PROVISION_BYTES",
    "SOURCE_AUTH_RANDOMIZER_BYTES",
    "SOURCE_AUTH_REQUEST_BYTES",
    "SOURCE_AUTH_SECRET_KEY_BYTES",
    "SOURCE_AUTH_SEED_BYTES",
    "SOURCE_AUTH_UPPER",
    "SOURCE_AUTH_WITNESS_BYTES",
    "SOURCE_AUTH_WITNESS_COUNT",
    "build_provision_record",
    "build_request_record",
)
