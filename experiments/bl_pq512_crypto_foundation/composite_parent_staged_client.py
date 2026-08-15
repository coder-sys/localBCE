"""Bounded client/provider for one exact composite-parent 900/901/902 transaction."""

from __future__ import annotations

from hashlib import sha3_512
from pathlib import Path
from queue import Empty, Queue
import subprocess
from threading import Thread
from typing import Callable, Final

from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.oods_reference import CirclePoint
from experiments.bl_pq512_crypto_foundation.selected_prover_orchestrator import (
    SemanticV3ParentRound900Production,
    SemanticV3ParentRound901Production,
    SemanticV3ParentRound902Production,
)
from experiments.bl_pq512_crypto_foundation.selected_public_coin_v3 import (
    SemanticV3ContinuationEvidence,
    SemanticV3ParentAnchorState,
    SemanticV3ParentProducerState,
    SemanticV3PrefixEvidence,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


PARENT_BUNDLE_FILE: Final[str] = "parent-bundle.bin"
PARENT_PRE_ALPHA_BYTES: Final[int] = 1_436
PARENT_QUOTIENT_BYTES: Final[int] = 613_220
PARENT_FINAL_BYTES: Final[int] = 844
MAX_PARENT_RESPONSE_BYTES: Final[int] = 2 * PARENT_QUOTIENT_BYTES + 1_024
MAX_PARENT_ARTIFACT_BYTES: Final[int] = 16 << 20
DEFAULT_PARENT_TIMEOUT_SECONDS: Final[float] = 6 * 60 * 60
PARENT_BRIDGE_PROGRAMS: Final[dict[int, bytes]] = {
    1: bytes.fromhex("2b6c174d9ce183e1f6e5e2bc51e4c411f55ba5997aa2f87b81ca062c8473e33be60406d97d2dbd17958bf8fdbe89ab92b44cdb8acf48a09ca879310a635cd29f"),
    3: bytes.fromhex("b1962cd2423238664861bc6f2551c0da9b362febcfc9b48e5ac8b2dda613973d7ec080dd3ad4e5ffcc9978d3bd8b395a9677c9b7be0fefdfb9fdeed4b4d1c966"),
}


def _digest(value: bytes, label: str, *, zero_allowed: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != 64 or (not zero_allowed and not any(value)):
        raise StructuralError(f"composite_parent_{label}_invalid")
    return value


def _semantic_program_from_prefix(prefix: SemanticV3PrefixEvidence) -> bytes:
    # BLV3PF03 | version | flags | session | schedule | semantic program.
    if (
        type(prefix.encoded) is not bytes
        or len(prefix.encoded) < 204
        or prefix.encoded[:8] != b"BLV3SP01"
        or prefix.encoded[8:12] != b"\x00\x01\x00\x00"
    ):
        raise StructuralError("composite_parent_semantic_prefix_encoding_invalid")
    return _digest(prefix.encoded[140:204], "semantic_program")


def encode_parent_pre_alpha_template(
    *, profile_code: int, composite_session_id: bytes, attempt: int,
    schedule_commitment: bytes, parent_program_commitment: bytes,
    candidate_descriptor_commitment: bytes, statement_commitment: bytes,
    prefix: SemanticV3PrefixEvidence, semantic_composition_root: bytes,
    h4_child_final_root: bytes, h4_ordered_shard_root_receipt: bytes,
    h4_source_root: bytes, h4_b_tensor_root: bytes, h4_n_tensor_root: bytes,
    h4_a_tensor_root: bytes, bridge_mask_base_aggregate_root: bytes,
    bridge_mask_pad_aggregate_root: bytes,
) -> bytes:
    """Encode canonical round 900 solely from child-owned commitments."""
    if profile_code not in PARENT_BRIDGE_PROGRAMS or type(attempt) is not int or not 0 <= attempt < 4 or type(prefix) is not SemanticV3PrefixEvidence:
        raise StructuralError("composite_parent_pre_alpha_identity_invalid")
    ordered = (
        parent_program_commitment, candidate_descriptor_commitment, statement_commitment,
        _semantic_program_from_prefix(prefix), prefix.semantic_session_id,
        prefix.semantic_schedule_commitment, prefix.contributor_set_commitment,
        prefix.receipt_commitment, prefix.round_1_transcript_root,
        prefix.main_trace_root, prefix.interaction_trace_root,
        semantic_composition_root, h4_child_final_root,
        h4_ordered_shard_root_receipt, h4_source_root, h4_b_tensor_root,
        h4_n_tensor_root, h4_a_tensor_root, bridge_mask_base_aggregate_root,
        bridge_mask_pad_aggregate_root,
    )
    checked = tuple(_digest(value, f"pre_alpha_digest_{index}") for index, value in enumerate(ordered))
    encoded = b"".join((
        b"BLV3PA03", (3).to_bytes(2, "big"), bytes(2), bytes((profile_code,)), bytes(7),
        _digest(composite_session_id, "session"), attempt.to_bytes(2, "big"), bytes(6),
        _digest(schedule_commitment, "schedule"), *checked,
    ))
    if len(encoded) != PARENT_PRE_ALPHA_BYTES:
        raise RuntimeError("composite_parent_pre_alpha_length")
    return encoded


def encode_parent_quotient_template(
    *, profile_code: int, answer_aggregate_root: bytes,
    message_coefficients: tuple[Fp16, ...], digest_coefficients: tuple[Fp16, ...],
) -> bytes:
    """Encode canonical round 901 with the predecessor left for native ownership."""
    if profile_code not in PARENT_BRIDGE_PROGRAMS or len(message_coefficients) != 4_789 or len(digest_coefficients) != 4_789 or any(type(value) is not Fp16 for value in (*message_coefficients, *digest_coefficients)):
        raise StructuralError("composite_parent_quotient_shape_invalid")
    groups = []
    for group, coefficients in enumerate((message_coefficients, digest_coefficients)):
        groups.append(bytes((group, 1)) + (4_789).to_bytes(2, "big") + bytes(4) + b"".join(value.encode() for value in coefficients))
    encoded = b"".join((
        b"BLV3QR03", (3).to_bytes(2, "big"), bytes(2), bytes((profile_code,)), bytes(7),
        bytes(64), PARENT_BRIDGE_PROGRAMS[profile_code],
        _digest(answer_aggregate_root, "answer_aggregate"), *groups,
    ))
    if len(encoded) != PARENT_QUOTIENT_BYTES:
        raise RuntimeError("composite_parent_quotient_length")
    return encoded


def encode_parent_final_template(
    *, continuation: SemanticV3ContinuationEvidence,
    post_z_response_oracle_root: bytes, post_z_claim_vector_commitment: bytes,
    semantic_component_package_commitment: bytes, h4_component_package_commitment: bytes,
    typed_component_package_commitment: bytes, typed_verified_receipt_commitment: bytes,
    h4_booleanity_receipt_commitment: bytes, h4_global_padding_receipt_commitment: bytes,
    bridge_privacy_ledger_commitment: bytes, semantic_exposure_ledger_commitment: bytes,
    h4_exposure_ledger_commitment: bytes,
) -> bytes:
    """Encode canonical round 902 from already-materialized component evidence."""
    if type(continuation) is not SemanticV3ContinuationEvidence:
        raise StructuralError("composite_parent_continuation_invalid")
    ordered = (
        bytes(64), post_z_response_oracle_root, post_z_claim_vector_commitment,
        continuation.final_transcript_root, semantic_component_package_commitment,
        h4_component_package_commitment, typed_component_package_commitment,
        typed_verified_receipt_commitment, h4_booleanity_receipt_commitment,
        h4_global_padding_receipt_commitment, bridge_privacy_ledger_commitment,
        semantic_exposure_ledger_commitment, h4_exposure_ledger_commitment,
    )
    checked = tuple(_digest(value, f"final_digest_{index}", zero_allowed=index == 0) for index, value in enumerate(ordered))
    encoded = b"BLV3FR03" + (3).to_bytes(2, "big") + bytes(2) + b"".join(checked)
    if len(encoded) != PARENT_FINAL_BYTES:
        raise RuntimeError("composite_parent_final_length")
    return encoded


def _read_line(process: subprocess.Popen[bytes], timeout: float) -> tuple[str, ...]:
    if process.stdout is None:
        raise RuntimeError("composite_parent_stdout_missing")
    result: Queue[tuple[bytes | None, BaseException | None]] = Queue(maxsize=1)

    def read() -> None:
        try:
            result.put((process.stdout.readline(MAX_PARENT_RESPONSE_BYTES + 1), None))
        except BaseException as error:
            result.put((None, error))

    Thread(target=read, name="composite-parent-read", daemon=True).start()
    try:
        encoded, error = result.get(timeout=timeout)
    except Empty as error:
        raise TimeoutError("composite_parent_response_timeout") from error
    if error is not None:
        raise RuntimeError("composite_parent_response_read_failed") from error
    if (
        encoded is None
        or not encoded
        or len(encoded) > MAX_PARENT_RESPONSE_BYTES
        or not encoded.endswith(b"\n")
    ):
        raise RuntimeError("composite_parent_response_missing")
    try:
        return tuple(encoded.decode("ascii").split())
    except UnicodeDecodeError as error:
        raise RuntimeError("composite_parent_response_non_ascii") from error


def _write(process: subprocess.Popen[bytes], encoded: bytes, timeout: float) -> None:
    if process.stdin is None:
        raise RuntimeError("composite_parent_stdin_missing")
    result: Queue[BaseException | None] = Queue(maxsize=1)

    def write() -> None:
        try:
            if process.stdin.write(encoded) != len(encoded):
                raise OSError("composite_parent_short_write")
            process.stdin.flush()
            result.put(None)
        except BaseException as error:
            result.put(error)

    Thread(target=write, name="composite-parent-write", daemon=True).start()
    try:
        error = result.get(timeout=timeout)
    except Empty as error:
        raise TimeoutError("composite_parent_write_timeout") from error
    if error is not None:
        raise RuntimeError("composite_parent_write_failed") from error


def _hex(value: str, length: int, label: str, *, nonzero: bool = False) -> bytes:
    if (
        type(value) is not str
        or len(value) != 2 * length
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RuntimeError(f"composite_parent_{label}_invalid")
    decoded = bytes.fromhex(value)
    if nonzero and not any(decoded):
        raise RuntimeError(f"composite_parent_{label}_zero")
    return decoded


class StagedCompositeParentProvider:
    """Callable selected-prover provider owning one fail-closed native process."""

    __slots__ = (
        "_service", "_coin_service", "_output", "_timeout", "_pre_alpha",
        "_quotient", "_anchor_observer", "_final", "_process", "_used", "_round_900_root",
        "_round_901_root", "_metadata", "_z", "_prepared",
    )

    def __init__(
        self,
        *,
        service_executable: Path,
        chained_coin_service: Path,
        output_directory: Path,
        pre_alpha_builder: Callable[[SemanticV3PrefixEvidence, bytes], bytes],
        quotient_builder: Callable[[Fp16], bytes],
        final_builder: Callable[[SemanticV3ContinuationEvidence, bytes], bytes],
        anchor_observer: Callable[[CirclePoint], None] | None = None,
        timeout_seconds: float = DEFAULT_PARENT_TIMEOUT_SECONDS,
    ) -> None:
        if (
            not isinstance(service_executable, Path)
            or not service_executable.is_absolute()
            or not service_executable.is_file()
            or not isinstance(chained_coin_service, Path)
            or not chained_coin_service.is_absolute()
            or not chained_coin_service.is_file()
            or not isinstance(output_directory, Path)
            or not output_directory.is_absolute()
            or not output_directory.is_dir()
            or (output_directory / PARENT_BUNDLE_FILE).exists()
            or not callable(pre_alpha_builder)
            or not callable(quotient_builder)
            or (anchor_observer is not None and not callable(anchor_observer))
            or not callable(final_builder)
            or type(timeout_seconds) not in (int, float)
            or not 0 < float(timeout_seconds) <= DEFAULT_PARENT_TIMEOUT_SECONDS
        ):
            raise StructuralError("composite_parent_client_input_invalid")
        self._service = service_executable
        self._coin_service = chained_coin_service
        self._output = output_directory
        self._timeout = float(timeout_seconds)
        self._pre_alpha = pre_alpha_builder
        self._quotient = quotient_builder
        self._anchor_observer = anchor_observer
        self._final = final_builder
        self._process: subprocess.Popen[bytes] | None = None
        self._used = False
        self._round_900_root: bytes | None = None
        self._round_901_root: bytes | None = None
        self._metadata: tuple[bytes, ...] | None = None
        self._z: CirclePoint | None = None
        self._prepared: bytes | None = None

    def __call__(
        self, prefix: SemanticV3PrefixEvidence, composition_root: bytes
    ) -> SemanticV3ParentRound900Production:
        if self._used or type(prefix) is not SemanticV3PrefixEvidence:
            raise StructuralError("composite_parent_provider_reused")
        if type(composition_root) is not bytes or len(composition_root) != 64:
            raise StructuralError("composite_parent_composition_root_invalid")
        pre_alpha = self._pre_alpha(prefix, composition_root)
        if type(pre_alpha) is not bytes or len(pre_alpha) != PARENT_PRE_ALPHA_BYTES:
            raise StructuralError("composite_parent_pre_alpha_invalid")
        self._used = True
        try:
            self._process = subprocess.Popen(
                [str(self._service), str(self._coin_service), str(self._output)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self._service.parent,
            )
            if _read_line(self._process, self._timeout) != ("READY",):
                raise RuntimeError("composite_parent_ready_invalid")
            fields = self._command(b"ROUND900 ", pre_alpha)
            if len(fields) != 3 or fields[0] != "ROUND900_ACCEPTED":
                raise RuntimeError("composite_parent_round900_shape")
            accepted = _hex(fields[1], PARENT_PRE_ALPHA_BYTES, "round900")
            if accepted != pre_alpha:
                raise RuntimeError("composite_parent_round900_substitution")
            self._round_900_root = _hex(fields[2], 64, "round900_root", nonzero=True)
            return SemanticV3ParentRound900Production(accepted, self._advance)
        except BaseException:
            self.abort()
            raise

    def _command(self, command: bytes, message: bytes) -> tuple[str, ...]:
        assert self._process is not None
        _write(self._process, command + message.hex().encode("ascii") + b"\n", self._timeout)
        return _read_line(self._process, self._timeout)

    def _advance(self, bridge_alpha: Fp16) -> SemanticV3ParentRound901Production:
        if type(bridge_alpha) is not Fp16 or self._round_900_root is None:
            raise StructuralError("composite_parent_bridge_alpha_invalid")
        template = self._quotient(bridge_alpha)
        if type(template) is not bytes or len(template) != PARENT_QUOTIENT_BYTES:
            raise StructuralError("composite_parent_quotient_invalid")
        fields = self._command(b"ROUND901 ", template)
        if len(fields) != 9 or fields[0] != "ROUND901_ACCEPTED":
            raise RuntimeError("composite_parent_round901_shape")
        accepted = _hex(fields[1], PARENT_QUOTIENT_BYTES, "round901")
        if accepted[:20] != template[:20] or accepted[84:] != template[84:]:
            raise RuntimeError("composite_parent_round901_substitution")
        if accepted[20:84] != self._round_900_root:
            raise RuntimeError("composite_parent_round901_predecessor")
        metadata = tuple(_hex(value, 64, "round901_metadata", nonzero=True) for value in fields[2:])
        self._round_901_root = metadata[1]
        self._metadata = metadata
        return SemanticV3ParentRound901Production(accepted, self._anchor, self._prepare_final)

    def _anchor(self, z: CirclePoint) -> SemanticV3ParentAnchorState:
        if type(z) is not CirclePoint or self._metadata is None:
            raise StructuralError("composite_parent_oods_invalid")
        if self._anchor_observer is not None:
            self._anchor_observer(z)
        self._z = z
        parent_session, round_root, composition, program, answer, message_q, digest_q = self._metadata
        return SemanticV3ParentAnchorState(
            parent_session, round_root, composition, z, program, answer, message_q, digest_q
        )

    def _prepare_final(
        self, continuation: SemanticV3ContinuationEvidence, pre_final_root: bytes
    ) -> SemanticV3ParentRound902Production:
        if self._z is None or self._round_901_root is None or self._prepared is not None:
            raise StructuralError("composite_parent_final_sequence")
        template = self._final(continuation, pre_final_root)
        if type(template) is not bytes or len(template) != PARENT_FINAL_BYTES:
            raise StructuralError("composite_parent_final_invalid")
        fields = self._command(b"PREPARE902 ", template)
        if len(fields) != 2 or fields[0] != "ROUND902_PREPARED":
            raise RuntimeError("composite_parent_round902_shape")
        accepted = _hex(fields[1], PARENT_FINAL_BYTES, "round902")
        if accepted[:12] != template[:12] or accepted[76:] != template[76:]:
            raise RuntimeError("composite_parent_round902_substitution")
        if accepted[12:76] != self._round_901_root:
            raise RuntimeError("composite_parent_round902_predecessor")
        self._prepared = accepted
        return SemanticV3ParentRound902Production(accepted, self._commit)

    def _commit(self, completion_challenge: Fp16) -> SemanticV3ParentProducerState:
        if type(completion_challenge) is not Fp16 or self._prepared is None or self._metadata is None or self._z is None:
            raise StructuralError("composite_parent_commit_sequence")
        fields = self._command(b"COMMIT902 ", self._prepared)
        if len(fields) != 3 or fields[0] != "FINISHED":
            raise RuntimeError("composite_parent_finish_shape")
        try:
            expected_size = int(fields[1])
        except ValueError as error:
            raise RuntimeError("composite_parent_finish_size") from error
        expected_digest = _hex(fields[2], 64, "bundle_digest", nonzero=True)
        assert self._process is not None
        if self._process.stdin is not None:
            self._process.stdin.close()
        if self._process.wait(timeout=min(30.0, self._timeout)) != 0:
            raise RuntimeError("composite_parent_service_failed")
        bundle_path = self._output / PARENT_BUNDLE_FILE
        if not bundle_path.is_file() or bundle_path.is_symlink():
            raise RuntimeError("composite_parent_bundle_missing")
        bundle = bundle_path.read_bytes()
        if not 0 < len(bundle) <= MAX_PARENT_ARTIFACT_BYTES or len(bundle) != expected_size or sha3_512(bundle).digest() != expected_digest:
            raise RuntimeError("composite_parent_bundle_mismatch")
        parent_session, round_root, composition, program, answer, message_q, digest_q = self._metadata
        return SemanticV3ParentProducerState(
            bundle, parent_session, round_root, composition, self._z, program, answer, message_q, digest_q
        )

    def abort(self) -> None:
        process = self._process
        if process is None or process.poll() is not None:
            return
        if process.stdin is not None and not process.stdin.closed:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


__all__ = (
    "StagedCompositeParentProvider",
    "encode_parent_final_template",
    "encode_parent_pre_alpha_template",
    "encode_parent_quotient_template",
)
