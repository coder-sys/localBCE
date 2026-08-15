"""Bounded client for one native selected-v3 strict public-coin transaction."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
import subprocess
from threading import Thread
from typing import Final

from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.selected_public_coin_v3 import (
    SemanticV3GovernedContext,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


SEMANTIC_CONTEXT_FILE: Final[str] = "semantic-context.bin"
SEMANTIC_KEY_FILE: Final[str] = "semantic-key.bin"
SEMANTIC_STRICT_BUNDLE_FILE: Final[str] = "semantic-strict-bundle.bin"
MAX_STRICT_MESSAGE_BYTES: Final[int] = 1 << 20
MAX_STRICT_RESPONSE_BYTES: Final[int] = 64 << 10
MAX_STRICT_ARTIFACT_BYTES: Final[int] = 16 << 20
DEFAULT_STRICT_TIMEOUT_SECONDS: Final[float] = 6 * 60 * 60


@dataclass(frozen=True, slots=True)
class SemanticV3StrictRoundChallenge:
    ordinal: int
    field_elements: tuple[Fp16, ...]
    transcript_root: bytes


@dataclass(frozen=True, slots=True)
class FinishedSemanticV3StrictCoin:
    context_path: Path
    key_path: Path
    bundle_path: Path
    pre_final_transcript_root: bytes
    final_transcript_root: bytes


def _bounded_line(
    process: subprocess.Popen[bytes], timeout_seconds: float
) -> tuple[str, ...]:
    if process.stdout is None:
        raise RuntimeError("semantic_v3_strict_stdout_missing")
    result: Queue[tuple[bytes | None, BaseException | None]] = Queue(maxsize=1)

    def read_line() -> None:
        try:
            result.put(
                (process.stdout.readline(MAX_STRICT_RESPONSE_BYTES + 1), None),
                block=False,
            )
        except BaseException as error:
            result.put((None, error), block=False)

    reader = Thread(target=read_line, name="semantic-v3-strict-read", daemon=True)
    reader.start()
    try:
        encoded, error = result.get(timeout=timeout_seconds)
    except Empty as error:
        raise TimeoutError("semantic_v3_strict_response_timeout") from error
    if error is not None:
        raise RuntimeError("semantic_v3_strict_response_read_failed") from error
    if (
        encoded is None
        or not encoded
        or len(encoded) > MAX_STRICT_RESPONSE_BYTES
        or not encoded.endswith(b"\n")
    ):
        raise RuntimeError("semantic_v3_strict_response_missing")
    try:
        return tuple(encoded.decode("ascii").split())
    except UnicodeDecodeError as error:
        raise RuntimeError("semantic_v3_strict_response_non_ascii") from error


def _bounded_write(
    process: subprocess.Popen[bytes], encoded: bytes, timeout_seconds: float
) -> None:
    if process.stdin is None:
        raise RuntimeError("semantic_v3_strict_stdin_missing")
    result: Queue[BaseException | None] = Queue(maxsize=1)

    def write() -> None:
        try:
            written = process.stdin.write(encoded)
            if written != len(encoded):
                raise OSError("semantic_v3_strict_short_write")
            process.stdin.flush()
            result.put(None, block=False)
        except BaseException as error:
            result.put(error, block=False)

    writer = Thread(target=write, name="semantic-v3-strict-write", daemon=True)
    writer.start()
    try:
        error = result.get(timeout=timeout_seconds)
    except Empty as error:
        raise TimeoutError("semantic_v3_strict_write_timeout") from error
    if error is not None:
        raise RuntimeError("semantic_v3_strict_write_failed") from error


def _lower_hex(
    value: str, length: int, label: str, *, nonzero: bool = False
) -> bytes:
    if (
        type(value) is not str
        or len(value) != 2 * length
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RuntimeError(f"semantic_v3_strict_{label}_invalid")
    decoded = bytes.fromhex(value)
    if nonzero and not any(decoded):
        raise RuntimeError(f"semantic_v3_strict_{label}_zero")
    return decoded


class SemanticV3StrictCoinClient:
    """Own one native service from READY through verified FINISHED output."""

    __slots__ = (
        "_process",
        "_timeout_seconds",
        "_output_directory",
        "_context_path",
        "_next_ordinal",
        "_finished",
    )

    def __init__(
        self,
        *,
        service_executable: Path,
        context: SemanticV3GovernedContext,
        session_id: bytes,
        attempt: int,
        output_directory: Path,
        timeout_seconds: float = DEFAULT_STRICT_TIMEOUT_SECONDS,
    ) -> None:
        if (
            not isinstance(service_executable, Path)
            or not service_executable.is_absolute()
            or not service_executable.is_file()
            or type(context) is not SemanticV3GovernedContext
            or type(session_id) is not bytes
            or len(session_id) != 64
            or not any(session_id)
            or type(attempt) is not int
            or not 0 <= attempt < 4
            or not isinstance(output_directory, Path)
            or not output_directory.is_absolute()
            or not output_directory.is_dir()
            or type(timeout_seconds) not in (int, float)
            or not 0 < float(timeout_seconds) <= DEFAULT_STRICT_TIMEOUT_SECONDS
        ):
            raise StructuralError("semantic_v3_strict_client_input_invalid")
        context_path = output_directory / SEMANTIC_CONTEXT_FILE
        key_path = output_directory / SEMANTIC_KEY_FILE
        bundle_path = output_directory / SEMANTIC_STRICT_BUNDLE_FILE
        if context_path.exists() or key_path.exists() or bundle_path.exists():
            raise StructuralError("semantic_v3_strict_client_artifact_collision")
        with context_path.open("xb") as output:
            output.write(context.encode())
            output.flush()
        try:
            process = subprocess.Popen(
                [
                    str(service_executable),
                    str(context_path),
                    session_id.hex(),
                    str(attempt),
                    str(output_directory),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=service_executable.parent,
            )
        except BaseException:
            context_path.unlink(missing_ok=False)
            raise
        self._process = process
        self._timeout_seconds = float(timeout_seconds)
        self._output_directory = output_directory
        self._context_path = context_path
        self._next_ordinal = 0
        self._finished = False
        try:
            if _bounded_line(process, self._timeout_seconds) != ("READY",):
                raise RuntimeError("semantic_v3_strict_ready_invalid")
        except BaseException:
            self.abort()
            raise

    def absorb_message(self, message: bytes) -> SemanticV3StrictRoundChallenge:
        if (
            self._finished
            or type(message) is not bytes
            or not 0 < len(message) <= MAX_STRICT_MESSAGE_BYTES
        ):
            raise StructuralError("semantic_v3_strict_message_invalid")
        _bounded_write(
            self._process,
            b"ROUND " + message.hex().encode("ascii") + b"\n",
            self._timeout_seconds,
        )
        fields = _bounded_line(self._process, self._timeout_seconds)
        if len(fields) < 5 or fields[0] != "CHALLENGE":
            raise RuntimeError("semantic_v3_strict_challenge_shape")
        try:
            ordinal = int(fields[1])
            count = int(fields[2])
        except ValueError as error:
            raise RuntimeError("semantic_v3_strict_challenge_integer") from error
        if (
            ordinal != self._next_ordinal
            or count <= 0
            or len(fields) != count + 4
        ):
            raise RuntimeError("semantic_v3_strict_challenge_sequence")
        elements = tuple(
            Fp16.decode(_lower_hex(value, 64, "field"))
            for value in fields[3 : 3 + count]
        )
        root = _lower_hex(
            fields[-1], 128, "transcript_root", nonzero=True
        )
        self._next_ordinal += 1
        return SemanticV3StrictRoundChallenge(ordinal, elements, root)

    def finish(self) -> FinishedSemanticV3StrictCoin:
        if self._finished:
            raise StructuralError("semantic_v3_strict_already_finished")
        _bounded_write(self._process, b"FINISH\n", self._timeout_seconds)
        fields = _bounded_line(self._process, self._timeout_seconds)
        if len(fields) != 3 or fields[0] != "FINISHED":
            raise RuntimeError("semantic_v3_strict_finish_shape")
        pre_final = _lower_hex(
            fields[1], 128, "pre_final_root", nonzero=True
        )
        final = _lower_hex(fields[2], 128, "final_root", nonzero=True)
        if self._process.stdin is not None and not self._process.stdin.closed:
            self._process.stdin.close()
        return_code = self._process.wait(timeout=min(30.0, self._timeout_seconds))
        if return_code != 0:
            raise RuntimeError(f"semantic_v3_strict_exit_{return_code}")
        key_path = self._output_directory / SEMANTIC_KEY_FILE
        bundle_path = self._output_directory / SEMANTIC_STRICT_BUNDLE_FILE
        for label, path in (("key", key_path), ("bundle", bundle_path)):
            if (
                not path.is_file()
                or path.is_symlink()
                or not 0 < path.stat().st_size <= MAX_STRICT_ARTIFACT_BYTES
            ):
                raise RuntimeError(f"semantic_v3_strict_{label}_artifact_invalid")
        self._finished = True
        return FinishedSemanticV3StrictCoin(
            self._context_path,
            key_path,
            bundle_path,
            pre_final,
            final,
        )

    def abort(self) -> None:
        if self._process.poll() is not None:
            self._process.wait()
            return
        if self._process.stdin is not None and not self._process.stdin.closed:
            try:
                self._process.stdin.close()
            except OSError:
                pass
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()


__all__ = (
    "FinishedSemanticV3StrictCoin",
    "SemanticV3StrictCoinClient",
    "SemanticV3StrictRoundChallenge",
)
