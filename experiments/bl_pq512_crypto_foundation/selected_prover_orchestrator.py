"""Production-shaped selected-suite prover orchestration.

The Rust worker retains large private proof state.  This module owns the
authenticated public-coin state machine and will only emit a proof result after
an independent replay of both standardized post-quantum signature suites.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from pathlib import Path
from queue import Empty, Queue
import os
import shutil
import subprocess
from threading import Thread
from typing import Callable, Final, Mapping

from experiments.bl_pq512_crypto_foundation.durable_public_coin_custody import (
    DurablePublicCoinCustody,
)
from experiments.bl_pq512_crypto_foundation.durable_selected_public_coin import (
    DurableSelectedPublicCoinSession,
)
from experiments.bl_pq512_crypto_foundation.oods_reference import (
    CirclePoint,
    OodsParameter,
    stereographic_circle_point,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    Contributor,
    EnvelopeKind,
    ProverMessageKind,
    PublicCoinSession,
    SignedEnvelope,
    TheoremProverMessage,
    build_selected_theorem_round_schedule,
    sample_query_positions,
)
from experiments.bl_pq512_crypto_foundation.selected_proof_parameters import (
    LOG_BLOWUP,
    derive_selected_proof_geometry,
)
from experiments.bl_pq512_crypto_foundation.selected_public_coin import (
    SelectedChallengeBundle,
    SelectedPublicCoinTranscript,
    capture_selected_transcript,
    encode_selected_challenge_bundle,
    verify_selected_transcript,
)
from experiments.bl_pq512_crypto_foundation.selected_public_coin_v3 import (
    SemanticV3GovernedContext,
    SemanticV3ParentAnchorState,
    SemanticV3ParentProducerState,
    SemanticV3ContinuationEvidence,
    SemanticV3PrefixEvidence,
    SemanticV3TranscriptEvidence,
    SemanticV3TranscriptProducer,
)
from experiments.bl_pq512_crypto_foundation.semantic_v3_strict_coin_client import (
    FinishedSemanticV3StrictCoin,
    SemanticV3StrictCoinClient,
)
from experiments.fixed_shape_claim_air.air_binary_ir import (
    AirProgram,
    encode_air_program,
)
from experiments.fixed_shape_claim_air.air_streaming_ir import (
    MAX_STREAMING_CHUNK_VALUES,
    StreamingAirManifest,
    build_streaming_air_manifest,
    iter_streaming_air_chunks,
)
from experiments.fixed_shape_claim_air.executable_air import TraceTable
from experiments.fixed_shape_claim_air.semantics import StructuralError


WORKER_MAGIC: Final[bytes] = b"BLPQSPW2"
STREAMING_WORKER_MAGIC: Final[bytes] = b"BLPQSDW3"
MAX_WORKER_LINE_BYTES: Final[int] = 1 << 20
WORKER_RESPONSE_TIMEOUT_SECONDS: Final[float] = 6 * 60 * 60
_H4_COMPLETION_ENVIRONMENT: Final[tuple[str, ...]] = (
    "BL_H4_AGGREGATE_PATH",
    "BL_H4_VERIFICATION_KEY_PATH",
    "BL_H4_MASK_COEFFICIENTS_PATH",
)
_STREAMING_STAGE_DOMAIN: Final[bytes] = (
    b"BL/PQ512/WAVE1B/STREAMING-WORKER-STAGE/v1\x00"
)
_STREAMING_SCRATCH_MARKER: Final[bytes] = b"BLPQSCR1"
_STREAMING_SCRATCH_MARKER_BYTES: Final[int] = 73

_ATTRIBUTION_BYTE_FIELDS: Final[tuple[str, ...]] = (
    "header_bytes",
    "initial_index_bytes",
    "mask_opening_bytes",
    "main_opening_bytes",
    "interaction_opening_bytes",
    "composition_opening_bytes",
    "next_main_opening_bytes",
    "next_interaction_opening_bytes",
    "fri_layer_count_bytes",
    "fri_opened_value_bytes",
    "fri_log_size_bytes",
    "fri_merkle_metadata_bytes",
    "fri_path_digest_bytes",
)
_ATTRIBUTION_COUNT_FIELDS: Final[tuple[str, ...]] = (
    "query_count",
    "fri_layer_count",
    "fri_opened_value_count",
    "fri_path_digest_count",
)
_WORKER_REPORT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "grammar_version",
        "proof_bytes",
        "attribution_total",
        "query_count",
        "trace_masks",
        "quotient_masks",
        "folds",
        "main_ms",
        "interaction_ms",
        "composition_ms",
        "deep_ms",
        "fri_start_ms",
        "fold_compute_ms",
        "openings_ms",
        "verify_ms",
        "worker_wall_ms",
    }
)


def _strict_unsigned_fields(
    fields: tuple[str, ...], expected: frozenset[str]
) -> dict[str, int]:
    observed: dict[str, int] = {}
    for field in fields:
        name, separator, encoded = field.partition("=")
        if (
            separator != "="
            or name not in expected
            or name in observed
            or not encoded
            or not encoded.isascii()
            or not encoded.isdecimal()
        ):
            raise StructuralError("selected_proof_worker_report_field_invalid")
        observed[name] = int(encoded)
    if frozenset(observed) != expected:
        raise StructuralError("selected_proof_worker_report_fields_missing")
    return observed


@dataclass(frozen=True, slots=True)
class SelectedProofByteAttribution:
    header_bytes: int
    initial_index_bytes: int
    mask_opening_bytes: int
    main_opening_bytes: int
    interaction_opening_bytes: int
    composition_opening_bytes: int
    next_main_opening_bytes: int
    next_interaction_opening_bytes: int
    fri_layer_count_bytes: int
    fri_opened_value_bytes: int
    fri_log_size_bytes: int
    fri_merkle_metadata_bytes: int
    fri_path_digest_bytes: int
    query_count: int
    fri_layer_count: int
    fri_opened_value_count: int
    fri_path_digest_count: int

    def __post_init__(self) -> None:
        values = tuple(getattr(self, name) for name in (*_ATTRIBUTION_BYTE_FIELDS, *_ATTRIBUTION_COUNT_FIELDS))
        if any(type(value) is not int or value < 0 for value in values):
            raise StructuralError("selected_proof_attribution_value_invalid")
        if (
            self.query_count == 0
            or self.fri_layer_count == 0
            or self.fri_opened_value_count < 2 * self.fri_layer_count
            or self.fri_opened_value_count % 2 != 0
            or self.fri_path_digest_count == 0
        ):
            raise StructuralError("selected_proof_attribution_count_invalid")

    @classmethod
    def from_worker_fields(
        cls, fields: tuple[str, ...]
    ) -> "SelectedProofByteAttribution":
        expected = frozenset((*_ATTRIBUTION_BYTE_FIELDS, *_ATTRIBUTION_COUNT_FIELDS))
        return cls(**_strict_unsigned_fields(fields, expected))

    @property
    def total_bytes(self) -> int:
        return sum(getattr(self, name) for name in _ATTRIBUTION_BYTE_FIELDS)


@dataclass(frozen=True, slots=True)
class SelectedProofResult:
    transcript: SelectedPublicCoinTranscript
    challenge_bundle: SelectedChallengeBundle
    proof_bytes: int
    proof_attribution: SelectedProofByteAttribution
    worker_report: str

    def __post_init__(self) -> None:
        if (
            type(self.proof_bytes) is not int
            or self.proof_bytes < 1
            or type(self.proof_attribution) is not SelectedProofByteAttribution
            or self.proof_attribution.total_bytes != self.proof_bytes
            or type(self.worker_report) is not str
            or not self.worker_report.startswith("OK ")
        ):
            raise StructuralError("selected_proof_worker_report_invalid")
        report = _strict_unsigned_fields(
            tuple(self.worker_report.split()[1:]), _WORKER_REPORT_FIELDS
        )
        if (
            report["grammar_version"] != 2
            or report["proof_bytes"] != self.proof_bytes
            or report["attribution_total"] != self.proof_bytes
            or report["query_count"] != self.proof_attribution.query_count
            or report["folds"] != self.proof_attribution.fri_layer_count
            or any(
                report[name] > report["worker_wall_ms"]
                for name in _WORKER_REPORT_FIELDS
                if name.endswith("_ms") and name != "worker_wall_ms"
            )
        ):
            raise StructuralError("selected_proof_worker_report_mismatch")

    @property
    def grammar_version(self) -> int:
        return _strict_unsigned_fields(
            tuple(self.worker_report.split()[1:]), _WORKER_REPORT_FIELDS
        )["grammar_version"]


@dataclass(frozen=True, slots=True)
class SemanticV3ParentRound902Production:
    prover_message: bytes
    commit: Callable[[Fp16], SemanticV3ParentProducerState]

    def __post_init__(self) -> None:
        if (
            type(self.prover_message) is not bytes
            or not 0 < len(self.prover_message) <= 1 << 20
            or not callable(self.commit)
        ):
            raise StructuralError("selected_v3_parent_round_902_invalid")


@dataclass(frozen=True, slots=True)
class SemanticV3ParentRound901Production:
    prover_message: bytes
    anchor: Callable[[CirclePoint], SemanticV3ParentAnchorState]
    prepare_final: Callable[
        [SemanticV3ContinuationEvidence, bytes],
        SemanticV3ParentRound902Production,
    ]

    def __post_init__(self) -> None:
        if (
            type(self.prover_message) is not bytes
            or not 0 < len(self.prover_message) <= 1 << 20
            or not callable(self.anchor)
            or not callable(self.prepare_final)
        ):
            raise StructuralError("selected_v3_parent_round_901_invalid")


@dataclass(frozen=True, slots=True)
class SemanticV3ParentRound900Production:
    prover_message: bytes
    advance: Callable[[Fp16], SemanticV3ParentRound901Production]

    def __post_init__(self) -> None:
        if (
            type(self.prover_message) is not bytes
            or not 0 < len(self.prover_message) <= 1 << 20
            or not callable(self.advance)
        ):
            raise StructuralError("selected_v3_parent_round_900_invalid")


@dataclass(frozen=True, slots=True)
class SemanticV3StrictProducerRecord:
    finished: FinishedSemanticV3StrictCoin
    logup_beta: Fp16
    logup_gamma: Fp16
    composition_alpha: Fp16
    bridge_alpha: Fp16
    oods_point: CirclePoint
    completion_challenge: Fp16
    fri_batch_coefficient: Fp16
    fri_fold_coefficients: tuple[Fp16, ...]
    query_seed: bytes
    query_positions: tuple[int, ...]

    def __post_init__(self) -> None:
        fields = (
            self.logup_beta,
            self.logup_gamma,
            self.composition_alpha,
            self.bridge_alpha,
            self.completion_challenge,
            self.fri_batch_coefficient,
            *self.fri_fold_coefficients,
        )
        if (
            type(self.finished) is not FinishedSemanticV3StrictCoin
            or any(type(value) is not Fp16 for value in fields)
            or type(self.oods_point) is not CirclePoint
            or not self.fri_fold_coefficients
            or type(self.query_seed) is not bytes
            or len(self.query_seed) != 64
            or type(self.query_positions) is not tuple
            or not self.query_positions
            or any(type(value) is not int or value < 0 for value in self.query_positions)
        ):
            raise StructuralError("selected_v3_strict_producer_record_invalid")


@dataclass(frozen=True, slots=True)
class SelectedV3ProofResult:
    """Nonactivating v3 producer evidence plus a worker-local proof check.

    ``worker_challenge_bundle`` is sent only to the current worker's numerical
    proof verifier.  It is not semantic transcript authority and its legacy
    suite identifier is never exported as a v3 ``proofSuiteId``.
    """

    evidence: SemanticV3TranscriptEvidence
    worker_challenge_bundle: SelectedChallengeBundle
    strict_record: SemanticV3StrictProducerRecord
    parent_anchor_commitment: bytes
    proof_bytes: int
    proof_attribution: SelectedProofByteAttribution
    worker_report: str

    def __post_init__(self) -> None:
        if (
            type(self.evidence) is not SemanticV3TranscriptEvidence
            or type(self.worker_challenge_bundle) is not SelectedChallengeBundle
            or type(self.strict_record) is not SemanticV3StrictProducerRecord
            or self.parent_anchor_commitment != self.evidence.parent_anchor.commitment
            or type(self.proof_bytes) is not int
            or self.proof_bytes < 1
            or type(self.proof_attribution) is not SelectedProofByteAttribution
            or self.proof_attribution.total_bytes != self.proof_bytes
            or type(self.worker_report) is not str
            or not self.worker_report.startswith("OK ")
        ):
            raise StructuralError("selected_v3_proof_worker_report_invalid")
        continuation = self.evidence.continuation
        bundle = self.worker_challenge_bundle
        prefix = self.evidence.prefix
        frame = self.evidence.parent_anchor
        strict = self.strict_record
        if (
            bundle.session_id != prefix.semantic_session_id
            or bundle.final_transcript_root != continuation.final_transcript_root
            or bundle.evidence_commitment != self.evidence.evidence_commitment
            or bundle.logup_beta != strict.logup_beta
            or bundle.logup_gamma != strict.logup_gamma
            or bundle.composition_alpha != strict.composition_alpha
            or bundle.oods_point != strict.oods_point
            or bundle.oods_point != frame.z
            or bundle.fri_batch_coefficient != strict.fri_batch_coefficient
            or bundle.fri_fold_coefficients != strict.fri_fold_coefficients
            or bundle.query_seed != strict.query_seed
            or bundle.query_positions != strict.query_positions
        ):
            raise StructuralError("selected_v3_proof_worker_bundle_mismatch")
        report = _strict_unsigned_fields(
            tuple(self.worker_report.split()[1:]), _WORKER_REPORT_FIELDS
        )
        if (
            report["grammar_version"] != 2
            or report["proof_bytes"] != self.proof_bytes
            or report["attribution_total"] != self.proof_bytes
            or report["query_count"] != self.proof_attribution.query_count
            or report["folds"] != self.proof_attribution.fri_layer_count
            or any(
                report[name] > report["worker_wall_ms"]
                for name in _WORKER_REPORT_FIELDS
                if name.endswith("_ms") and name != "worker_wall_ms"
            )
        ):
            raise StructuralError("selected_v3_proof_worker_report_mismatch")

    @property
    def proof_suite_id(self) -> None:
        """The semantic-v3 path remains deliberately nonactivating."""

        return None

    @property
    def grammar_version(self) -> int:
        return _strict_unsigned_fields(
            tuple(self.worker_report.split()[1:]), _WORKER_REPORT_FIELDS
        )["grammar_version"]


def _exact_bytes(name: str, value: bytes, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length or (nonzero and not any(value)):
        raise StructuralError(f"selected_prover_{name}_invalid")
    return value


def _discard_obsolete_entropy(values: dict[str, object]) -> None:
    """Accept, but never consume, the scoped migration's former seed keyword.

    Higher-level callers live outside this change's exact edit scope. Keeping
    their obsolete keyword in a variadic compatibility sink avoids breaking
    them while ensuring it cannot control, enter, or be logged by the worker.
    This is not the deterministic test-injection boundary; that boundary is a
    non-default Rust feature with a distinct worker magic.
    """

    unexpected = frozenset(values).difference({"secret_mask_seed"})
    if unexpected:
        raise TypeError("selected_prover_unexpected_entropy_keyword")
    values.clear()


def _cancel_worker(process: subprocess.Popen[bytes]) -> None:
    """Prefer EOF-driven unwind so the worker drops and zeroizes its secrets."""

    if process.poll() is not None:
        process.wait()
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


def _streaming_store_nonce(session_id: bytes, program_commitment: bytes) -> bytes:
    stage = b"store"
    return sha3_512(
        _STREAMING_STAGE_DOMAIN
        + session_id
        + program_commitment
        + len(stage).to_bytes(8, "big")
        + stage
    ).digest()[:32]


def _owned_streaming_scratch_path(
    scratch_parent: Path, session_id: bytes, program_commitment: bytes
) -> Path:
    nonce = _streaming_store_nonce(session_id, program_commitment)
    return scratch_parent / ("blpq-stream-" + nonce.hex())


def _cleanup_owned_streaming_scratch(
    scratch_parent: Path,
    session_path: Path,
    manifest_commitment: bytes,
) -> None:
    parent = scratch_parent.resolve(strict=True)
    candidate = session_path.resolve(strict=False)
    if candidate.parent != parent or candidate == parent:
        raise RuntimeError("selected_prover_scratch_cleanup_path_invalid")
    if not candidate.exists():
        return
    if not candidate.is_dir() or candidate.is_symlink():
        raise RuntimeError("selected_prover_scratch_cleanup_target_invalid")
    marker_path = candidate / "OWNER"
    entries = tuple(candidate.iterdir())
    if not marker_path.exists():
        if entries:
            raise RuntimeError("selected_prover_scratch_cleanup_marker_missing")
        candidate.rmdir()
        return
    if not marker_path.is_file() or marker_path.is_symlink():
        raise RuntimeError("selected_prover_scratch_cleanup_marker_invalid")
    marker = marker_path.read_bytes()
    expected_prefix = _STREAMING_SCRATCH_MARKER + manifest_commitment
    if len(marker) < _STREAMING_SCRATCH_MARKER_BYTES:
        if entries != (marker_path,) or not expected_prefix.startswith(marker):
            raise RuntimeError("selected_prover_scratch_cleanup_partial_marker_invalid")
        marker_path.unlink()
        candidate.rmdir()
        return
    if (
        len(marker) != _STREAMING_SCRATCH_MARKER_BYTES
        or marker[:8] != _STREAMING_SCRATCH_MARKER
        or marker[8:72] != manifest_commitment
        or marker[72] not in (0, 1)
    ):
        raise RuntimeError("selected_prover_scratch_cleanup_ownership_mismatch")
    if any(path.is_symlink() for path in candidate.rglob("*")):
        raise RuntimeError("selected_prover_scratch_cleanup_symlink_forbidden")
    shutil.rmtree(candidate)


def _worker_line(process: subprocess.Popen[bytes], expected: str) -> tuple[str, ...]:
    assert process.stdout is not None
    results: Queue[tuple[bytes | None, BaseException | None]] = Queue(maxsize=1)

    def read_one_line() -> None:
        try:
            results.put(
                (process.stdout.readline(MAX_WORKER_LINE_BYTES + 1), None),
                block=False,
            )
        except BaseException as exc:
            results.put((None, exc), block=False)

    reader = Thread(target=read_one_line, name="selected-worker-line", daemon=True)
    reader.start()
    try:
        encoded, read_error = results.get(timeout=WORKER_RESPONSE_TIMEOUT_SECONDS)
    except Empty as exc:
        raise TimeoutError("selected_prover_worker_response_timeout") from exc
    if read_error is not None:
        raise RuntimeError("selected_prover_worker_read_failed") from read_error
    assert encoded is not None
    if not encoded or len(encoded) > MAX_WORKER_LINE_BYTES or not encoded.endswith(b"\n"):
        remaining_stdout = b""
        stderr = b""
        if process.poll() is not None and process.stderr is not None:
            remaining_stdout = process.stdout.read(MAX_WORKER_LINE_BYTES)
            stderr = process.stderr.read(MAX_WORKER_LINE_BYTES)
        raise RuntimeError(
            "selected_prover_worker_response_missing:"
            + "stdout="
            + (encoded + remaining_stdout).decode("ascii", errors="replace")
            + ";stderr="
            + stderr.decode("ascii", errors="replace")
        )
    try:
        fields = tuple(encoded.decode("ascii").split())
    except UnicodeDecodeError as error:
        raise RuntimeError("selected_prover_worker_response_non_ascii") from error
    if not fields or fields[0] != expected:
        raise RuntimeError(f"selected_prover_worker_expected_{expected}")
    return fields


def _worker_write(
    process: subprocess.Popen[bytes], encoded: bytes, *, flush: bool
) -> None:
    assert process.stdin is not None
    results: Queue[BaseException | None] = Queue(maxsize=1)

    def write_bytes() -> None:
        try:
            written = process.stdin.write(encoded)
            if written != len(encoded):
                raise OSError("selected_prover_worker_short_write")
            if flush:
                process.stdin.flush()
            results.put(None, block=False)
        except BaseException as exc:
            results.put(exc, block=False)

    writer = Thread(target=write_bytes, name="selected-worker-write", daemon=True)
    writer.start()
    try:
        write_error = results.get(timeout=WORKER_RESPONSE_TIMEOUT_SECONDS)
    except Empty as exc:
        raise TimeoutError("selected_prover_worker_write_timeout") from exc
    if write_error is not None:
        raise RuntimeError("selected_prover_worker_write_failed") from write_error


def _worker_command(process: subprocess.Popen[bytes], *fields: object) -> None:
    encoded = " ".join(str(value) for value in fields).encode("ascii") + b"\n"
    if len(encoded) > MAX_WORKER_LINE_BYTES:
        raise StructuralError("selected_prover_worker_command_too_large")
    _worker_write(process, encoded, flush=True)


def _signed_round(
    session: PublicCoinSession,
    descriptor: object,
    prover_message: TheoremProverMessage,
    *,
    contributors: tuple[Contributor, ...],
    adapters: Mapping[str, object],
    secret_keys: Mapping[bytes, bytes],
    custody_binding: DurableSelectedPublicCoinSession | None = None,
):
    session.begin_round(descriptor, prover_message.encode())
    reveals = {
        contributor.contributor_id: sha3_512(
            b"BL/PQ512/WAVE1B/SELECTED-PROVER-REVEAL/v1\x00"
            + session.session_id
            + descriptor.encode()
            + contributor.contributor_id
            + session.transcript_root
        ).digest()
        for contributor in contributors
    }
    for contributor in contributors:
        adapter = adapters[contributor.suite_id]
        secret_key = secret_keys[contributor.contributor_id]
        payload = session.commitment_for(
            contributor.contributor_id, reveals[contributor.contributor_id]
        )
        message = session.signature_message(
            EnvelopeKind.RANDOMNESS_COMMITMENT,
            contributor.contributor_id,
            payload,
        )
        session.submit_commitment(
            SignedEnvelope(
                contributor.contributor_id,
                payload,
                adapter.sign(secret_key=secret_key, message=message),
            )
        )
    for contributor in contributors:
        adapter = adapters[contributor.suite_id]
        secret_key = secret_keys[contributor.contributor_id]
        payload = reveals[contributor.contributor_id]
        message = session.signature_message(
            EnvelopeKind.RANDOMNESS_REVEAL,
            contributor.contributor_id,
            payload,
        )
        session.submit_reveal(
            SignedEnvelope(
                contributor.contributor_id,
                payload,
                adapter.sign(secret_key=secret_key, message=message),
            )
        )
    challenge = session.finalize_round()
    if custody_binding is not None:
        custody_binding.record_latest_verified_round()
    return challenge


def prove_selected_air(
    *,
    worker_executable: Path,
    program: AirProgram,
    execution_encoded: bytes,
    session_id: bytes | None,
    public_outputs: bytes,
    sidecar: bytes,
    contributors: tuple[Contributor, ...],
    adapters: Mapping[str, object],
    secret_keys: Mapping[bytes, bytes],
    _streaming_manifest: StreamingAirManifest | None = None,
    _streaming_traces: Mapping[str, TraceTable] | None = None,
    _streaming_chunk_values: int = MAX_STREAMING_CHUNK_VALUES,
    _scratch_parent: Path | None = None,
    _proof_export_path: Path | None = None,
    _native_v3_export_directory: Path | None = None,
    durable_custody: DurablePublicCoinCustody | None = None,
    _semantic_v3_context: SemanticV3GovernedContext | None = None,
    _semantic_v3_parent_provider: Callable[
        [SemanticV3PrefixEvidence, bytes], SemanticV3ParentRound900Production
    ]
    | None = None,
    _semantic_v3_strict_service: Path | None = None,
    _semantic_v3_authority_output_directory: Path | None = None,
    _semantic_v3_attempt: int | None = None,
    _semantic_v3_reveal_source: Callable[[int, Contributor], bytes] | None = None,
    _semantic_v3_post_z_builder: Callable[[bytes], Callable[[], None]] | None = None,
    _semantic_v3_post_z_exchange_directory: Path | None = None,
    _semantic_v3_h4_completion_paths: Mapping[str, Path] | None = None,
    **_obsolete_entropy: object,
) -> SelectedProofResult | SelectedV3ProofResult:
    """Build and independently verify one exact selected-suite proof.

    Key generation and custody stay outside this function. The caller supplies
    one contributor per locked PQ suite and the matching signing adapters. The
    session identifier is authenticated public transcript context; the worker
    owns all private masking entropy and its private retry/attempt nonce.
    """

    if not isinstance(worker_executable, Path) or not worker_executable.is_file():
        raise StructuralError("selected_prover_worker_executable_missing")
    program_encoded = encode_air_program(program)
    geometry = derive_selected_proof_geometry(program)
    schedule = build_selected_theorem_round_schedule(geometry)
    _discard_obsolete_entropy(_obsolete_entropy)
    streaming = _streaming_manifest is not None
    semantic_v3 = (
        _semantic_v3_context is not None
        or _semantic_v3_parent_provider is not None
        or _semantic_v3_strict_service is not None
        or _semantic_v3_authority_output_directory is not None
        or _semantic_v3_attempt is not None
        or _semantic_v3_reveal_source is not None
        or _semantic_v3_post_z_builder is not None
        or _semantic_v3_post_z_exchange_directory is not None
        or _semantic_v3_h4_completion_paths is not None
    )
    if _native_v3_export_directory is not None and (
        not semantic_v3
        or not isinstance(_native_v3_export_directory, Path)
        or not _native_v3_export_directory.is_absolute()
        or not _native_v3_export_directory.is_dir()
        or (_native_v3_export_directory / "semantic-fri-proof.bin").exists()
        or (_native_v3_export_directory / "semantic-fri-parameters.bin").exists()
        or any(
            (_native_v3_export_directory / name).exists()
            for name in (
                "semantic-prefix.bin",
                "semantic-continuation.bin",
                "semantic-parent-anchor.bin",
                "semantic-program.bin",
            )
        )
    ):
        raise StructuralError("selected_prover_native_v3_export_invalid")
    if semantic_v3 and (
        type(_semantic_v3_context) is not SemanticV3GovernedContext
        or not callable(_semantic_v3_parent_provider)
        or not isinstance(_semantic_v3_strict_service, Path)
        or not _semantic_v3_strict_service.is_absolute()
        or not _semantic_v3_strict_service.is_file()
        or not isinstance(_semantic_v3_authority_output_directory, Path)
        or not _semantic_v3_authority_output_directory.is_absolute()
        or not _semantic_v3_authority_output_directory.is_dir()
        or _semantic_v3_authority_output_directory
        != _native_v3_export_directory
        or type(_semantic_v3_attempt) is not int
        or not 0 <= _semantic_v3_attempt < 4
        or durable_custody is not None
        or (
            _semantic_v3_post_z_builder is not None
            and not callable(_semantic_v3_post_z_builder)
        )
        or ((_semantic_v3_post_z_builder is None) != (_semantic_v3_post_z_exchange_directory is None))
        or (
            _semantic_v3_h4_completion_paths is not None
            and (
                frozenset(_semantic_v3_h4_completion_paths)
                != frozenset(_H4_COMPLETION_ENVIRONMENT)
                or any(
                    not isinstance(path, Path) or not path.is_absolute()
                    for path in _semantic_v3_h4_completion_paths.values()
                )
                or not _semantic_v3_h4_completion_paths[
                    "BL_H4_MASK_COEFFICIENTS_PATH"
                ].is_file()
                or _semantic_v3_h4_completion_paths[
                    "BL_H4_MASK_COEFFICIENTS_PATH"
                ].is_symlink()
                or any(
                    path.exists()
                    or path.parent is None
                    or not path.parent.is_dir()
                    for variable, path in _semantic_v3_h4_completion_paths.items()
                    if variable != "BL_H4_MASK_COEFFICIENTS_PATH"
                )
            )
        )
        or ((_semantic_v3_post_z_builder is None) != (_semantic_v3_h4_completion_paths is None))
        or (
            _semantic_v3_post_z_exchange_directory is not None
            and (
                not _semantic_v3_post_z_exchange_directory.is_absolute()
                or not _semantic_v3_post_z_exchange_directory.is_dir()
                or any(_semantic_v3_post_z_exchange_directory.iterdir())
            )
        )
        or public_outputs != b""
        or sidecar != b""
    ):
        raise StructuralError("selected_prover_semantic_v3_authority_invalid")
    if durable_custody is None:
        _exact_bytes("session_id", session_id, 64, nonzero=True)
    elif type(durable_custody) is not DurablePublicCoinCustody or session_id is not None:
        raise StructuralError("selected_prover_durable_custody_owns_session_id")
    if (
        (not streaming and (type(execution_encoded) is not bytes or not execution_encoded))
        or (
            streaming
            and (
                type(_streaming_manifest) is not StreamingAirManifest
                or not isinstance(_streaming_traces, Mapping)
                or type(_streaming_chunk_values) is not int
                or not 0 < _streaming_chunk_values <= MAX_STREAMING_CHUNK_VALUES
                or not isinstance(_scratch_parent, Path)
                or not _scratch_parent.is_absolute()
                or not _scratch_parent.is_dir()
            )
        )
        or (
            _proof_export_path is not None
            and (
                not streaming
                or not isinstance(_proof_export_path, Path)
                or not _proof_export_path.is_absolute()
                or _proof_export_path.parent != _scratch_parent
                or _proof_export_path.exists()
            )
        )
        or type(contributors) is not tuple
        or len(contributors) < 2
        or tuple(sorted(contributors, key=lambda item: item.contributor_id)) != contributors
        or set(adapters) != {item.suite_id for item in contributors}
        or set(secret_keys) != {item.contributor_id for item in contributors}
    ):
        raise StructuralError("selected_prover_authority_shape_invalid")
    custody_binding: DurableSelectedPublicCoinSession | None = None
    semantic_producer: SemanticV3TranscriptProducer | None = None
    session: PublicCoinSession | None = None
    if semantic_v3:
        assert _semantic_v3_context is not None
        assert session_id is not None
        if (
            _semantic_v3_context.semantic_program_commitment
            != geometry.program_binary_commitment
            or _semantic_v3_context.parameter_commitment
            != schedule.parameter_commitment
            or _semantic_v3_context.geometry.fold_round_count
            != geometry.fold_round_count
            or _semantic_v3_context.geometry.query_domain_log_size
            != geometry.query_domain_size.bit_length() - 1
            or _semantic_v3_context.geometry.log_blowup != LOG_BLOWUP
        ):
            raise StructuralError("selected_prover_semantic_v3_geometry_mismatch")
        semantic_producer = SemanticV3TranscriptProducer(
            context=_semantic_v3_context,
            session_id=session_id,
            contributors=contributors,
            adapters=adapters,
            secret_keys=secret_keys,
            reveal_source=_semantic_v3_reveal_source,
        )
    elif durable_custody is None:
        assert session_id is not None
        session = PublicCoinSession(
            session_id=session_id,
            public_outputs=public_outputs,
            sidecar=sidecar,
            candidate_descriptor_sha3_512=schedule.proof_suite_id,
            schedule=schedule.descriptors,
            contributors=contributors,
            verifiers=adapters,
            production_mode=True,
            theorem_schedule=schedule,
        )
    else:
        custody_binding = DurableSelectedPublicCoinSession(
            custody=durable_custody,
            public_outputs=public_outputs,
            sidecar=sidecar,
            schedule=schedule,
            contributors=contributors,
            adapters=adapters,
        )
        session = custody_binding.session
        session_id = session.session_id

    owned_scratch_path: Path | None = None
    if streaming:
        assert _streaming_manifest is not None
        assert _scratch_parent is not None
        owned_scratch_path = _owned_streaming_scratch_path(
            _scratch_parent,
            session_id,
            _streaming_manifest.program_binary_commitment_512,
        )

    process: subprocess.Popen[bytes] | None = None
    strict_client: SemanticV3StrictCoinClient | None = None
    try:
        if owned_scratch_path is not None and owned_scratch_path.exists():
            raise RuntimeError("selected_prover_owned_scratch_residue_present")
        if semantic_v3:
            assert _semantic_v3_context is not None
            assert session_id is not None
            assert _semantic_v3_strict_service is not None
            assert _semantic_v3_authority_output_directory is not None
            assert _semantic_v3_attempt is not None
            strict_client = SemanticV3StrictCoinClient(
                service_executable=_semantic_v3_strict_service,
                context=_semantic_v3_context,
                session_id=session_id,
                attempt=_semantic_v3_attempt,
                output_directory=_semantic_v3_authority_output_directory,
                timeout_seconds=WORKER_RESPONSE_TIMEOUT_SECONDS,
            )
        worker_environment = None
        if _semantic_v3_post_z_exchange_directory is not None:
            worker_environment = os.environ.copy()
            for variable, name in (
                ("BL_H4_POST_Z_PROJECTION_REQUEST_PATH", "projection-request.bin"),
                ("BL_H4_POST_Z_PROJECTION_RESPONSE_PATH", "projection-response.bin"),
                ("BL_H4_POST_Z_OPENING_REQUEST_PATH", "opening-request.bin"),
                ("BL_H4_POST_Z_OPENING_RESPONSE_PATH", "opening-response.bin"),
            ):
                worker_environment[variable] = str(
                    _semantic_v3_post_z_exchange_directory / name
                )
            assert _semantic_v3_h4_completion_paths is not None
            for variable in _H4_COMPLETION_ENVIRONMENT:
                worker_environment[variable] = str(
                    _semantic_v3_h4_completion_paths[variable]
                )
        process = subprocess.Popen(
            (
                [str(worker_executable)]
                + ([str(_scratch_parent)] if streaming else [])
                + ([str(_proof_export_path)] if _proof_export_path is not None else [])
                + (
                    ["--native-v3-export", str(_native_v3_export_directory)]
                    if _native_v3_export_directory is not None
                    else []
                )
            ),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=worker_executable.parent,
            env=worker_environment,
        )
        assert process.stdin is not None
        if streaming:
            assert _streaming_manifest is not None
            assert _streaming_traces is not None
            chunks = iter_streaming_air_chunks(
                program,
                _streaming_traces,
                _streaming_manifest,
                chunk_values=_streaming_chunk_values,
            )
            chunk_count = sum(
                (table.row_count + _streaming_chunk_values - 1)
                // _streaming_chunk_values
                for table in _streaming_manifest.tables
                for _ in table.columns
            )
            if not 0 < chunk_count <= 0xFFFF_FFFF:
                raise StructuralError("selected_prover_stream_chunk_count_invalid")
            available_scratch_bytes = shutil.disk_usage(_scratch_parent).free
            if not 0 < available_scratch_bytes <= 0xFFFF_FFFF_FFFF_FFFF:
                raise StructuralError("selected_prover_stream_scratch_capacity_invalid")
            _worker_write(
                process,
                b"".join(
                    (
                        STREAMING_WORKER_MAGIC,
                        len(program_encoded).to_bytes(4, "big"),
                        program_encoded,
                        len(_streaming_manifest.encoded).to_bytes(4, "big"),
                        _streaming_manifest.encoded,
                        session_id,
                        available_scratch_bytes.to_bytes(8, "big"),
                        chunk_count.to_bytes(4, "big"),
                    )
                ),
                flush=False,
            )
            observed_chunks = 0
            for chunk in chunks:
                _worker_write(
                    process,
                    len(chunk).to_bytes(4, "big") + chunk,
                    flush=False,
                )
                observed_chunks += 1
            if observed_chunks != chunk_count:
                raise RuntimeError("selected_prover_stream_chunk_count_mismatch")
        else:
            _worker_write(
                process,
                b"".join(
                    (
                        WORKER_MAGIC,
                        len(program_encoded).to_bytes(4, "big"),
                        program_encoded,
                        len(execution_encoded).to_bytes(4, "big"),
                        execution_encoded,
                        session_id,
                    )
                ),
                flush=False,
            )
        _worker_write(process, b"", flush=True)

        native_v3 = _native_v3_export_directory is not None
        main = _worker_line(process, "MAIN")
        if len(main) != (3 if native_v3 else 2):
            raise RuntimeError("selected_prover_main_shape")
        main_root = bytes.fromhex(main[1])
        compatibility_main_root = bytes.fromhex(main[2]) if native_v3 else main_root
        if semantic_v3:
            assert semantic_producer is not None
            assert strict_client is not None
            semantic_producer.record_main_root(main_root)
            strict_main = strict_client.absorb_message(main_root)
            if len(strict_main.field_elements) != 2:
                raise RuntimeError("selected_prover_strict_main_shape")
            logup_beta, logup_gamma = strict_main.field_elements
        else:
            assert session is not None
            challenge = _signed_round(
                session,
                schedule.descriptors[0],
                TheoremProverMessage(
                    ProverMessageKind.MAIN_TRACE_ROOT, 0, main_root, bytes(64)
                ),
                contributors=contributors,
                adapters=adapters,
                secret_keys=secret_keys,
                custody_binding=custody_binding,
            )
            logup_beta, logup_gamma = challenge.field_elements[:2]
        _worker_command(
            process,
            "INTERACTION",
            logup_beta.encode().hex(),
            logup_gamma.encode().hex(),
        )

        interaction = _worker_line(process, "INTERACTION_ROOT")
        if len(interaction) != (3 if native_v3 else 2):
            raise RuntimeError("selected_prover_interaction_shape")
        interaction_root = bytes.fromhex(interaction[1])
        compatibility_interaction_root = (
            bytes.fromhex(interaction[2]) if native_v3 else interaction_root
        )
        if semantic_v3:
            assert semantic_producer is not None
            assert strict_client is not None
            semantic_producer.record_interaction_root(interaction_root)
            strict_interaction = strict_client.absorb_message(interaction_root)
            if len(strict_interaction.field_elements) != 1:
                raise RuntimeError("selected_prover_strict_interaction_shape")
            composition_alpha = strict_interaction.field_elements[0]
        else:
            assert session is not None
            challenge = _signed_round(
                session,
                schedule.descriptors[1],
                TheoremProverMessage(
                    ProverMessageKind.INTERACTION_TRACE_ROOT,
                    0,
                    interaction_root,
                    bytes(64),
                ),
                contributors=contributors,
                adapters=adapters,
                secret_keys=secret_keys,
                custody_binding=custody_binding,
            )
            composition_alpha = challenge.field_elements[0]
        _worker_command(process, "COMPOSITION", composition_alpha.encode().hex())

        composition = _worker_line(process, "COMPOSITION_ROOT")
        if len(composition) != (3 if native_v3 else 2):
            raise RuntimeError("selected_prover_composition_shape")
        composition_root = bytes.fromhex(composition[1])
        compatibility_composition_root = (
            bytes.fromhex(composition[2]) if native_v3 else composition_root
        )
        semantic_frame = None
        if semantic_v3:
            assert semantic_producer is not None
            assert strict_client is not None
            assert _semantic_v3_parent_provider is not None
            prefix = semantic_producer.finish_prefix()
            parent_round_900 = _semantic_v3_parent_provider(prefix, composition_root)
            if type(parent_round_900) is not SemanticV3ParentRound900Production:
                raise RuntimeError("selected_prover_parent_round_900_missing")
            strict_parent_900 = strict_client.absorb_message(
                parent_round_900.prover_message
            )
            if len(strict_parent_900.field_elements) != 1:
                raise RuntimeError("selected_prover_strict_parent_900_shape")
            strict_bridge_alpha = strict_parent_900.field_elements[0]
            parent_round_901 = parent_round_900.advance(strict_bridge_alpha)
            if type(parent_round_901) is not SemanticV3ParentRound901Production:
                raise RuntimeError("selected_prover_parent_round_901_missing")
            strict_parent_901 = strict_client.absorb_message(
                parent_round_901.prover_message
            )
            if len(strict_parent_901.field_elements) != 1:
                raise RuntimeError("selected_prover_strict_parent_901_shape")
            point = stereographic_circle_point(
                OodsParameter(strict_parent_901.field_elements[0])
            )
            parent_anchor = parent_round_901.anchor(point)
            if type(parent_anchor) is not SemanticV3ParentAnchorState:
                raise RuntimeError("selected_prover_parent_anchor_missing")
            semantic_frame = semantic_producer.bind_parent_anchor(
                parent_anchor,
                worker_composition_root=composition_root,
            )
            _worker_command(process, *semantic_frame.command_fields)
        else:
            assert session is not None
            challenge = _signed_round(
                session,
                schedule.descriptors[2],
                TheoremProverMessage(
                    ProverMessageKind.COMPOSITION_ROOT,
                    0,
                    composition_root,
                    bytes(64),
                ),
                contributors=contributors,
                adapters=adapters,
                secret_keys=secret_keys,
                custody_binding=custody_binding,
            )
            if challenge.oods_sample is None:
                raise RuntimeError("selected_prover_oods_sample_missing")
            point = stereographic_circle_point(challenge.oods_sample.parameter)
            _worker_command(
                process, "OODS", point.x.encode().hex(), point.y.encode().hex()
            )

        oods_roots = _worker_line(process, "OODS_ROOTS")
        expected_oods_fields = 6 if native_v3 else (4 if semantic_v3 else 3)
        if len(oods_roots) != expected_oods_fields:
            raise RuntimeError("selected_prover_oods_shape")
        claims_commitment = bytes.fromhex(oods_roots[1])
        fri_mask_root = bytes.fromhex(oods_roots[2])
        compatibility_claims_commitment = (
            bytes.fromhex(oods_roots[4]) if native_v3 else claims_commitment
        )
        compatibility_fri_mask_root = (
            bytes.fromhex(oods_roots[5]) if native_v3 else fri_mask_root
        )
        if semantic_v3:
            assert semantic_producer is not None
            assert strict_client is not None
            assert semantic_frame is not None
            if (
                len(oods_roots[3]) != 128
                or oods_roots[3] != oods_roots[3].lower()
                or bytes.fromhex(oods_roots[3]) != semantic_frame.commitment
            ):
                raise RuntimeError("selected_prover_v3_parent_anchor_echo_mismatch")
            oods_message = claims_commitment + fri_mask_root
            semantic_producer.record_continuation_message(oods_message)
            strict_batch = strict_client.absorb_message(oods_message)
            if len(strict_batch.field_elements) != 1:
                raise RuntimeError("selected_prover_strict_batch_shape")
            fri_batch_coefficient = strict_batch.field_elements[0]
        else:
            assert session is not None
            challenge = _signed_round(
                session,
                schedule.descriptors[3],
                TheoremProverMessage(
                    ProverMessageKind.OODS_CLAIMS_AND_FRI_MASK_ROOT,
                    0,
                    claims_commitment,
                    fri_mask_root,
                ),
                contributors=contributors,
                adapters=adapters,
                secret_keys=secret_keys,
                custody_binding=custody_binding,
            )
        _worker_command(
            process,
            "BATCH",
            (
                fri_batch_coefficient
                if semantic_v3
                else challenge.field_elements[0]
            ).encode().hex(),
        )

        batch = _worker_line(process, "BATCH_DERIVATION")
        if len(batch) != (3 if native_v3 else 2):
            raise RuntimeError("selected_prover_batch_shape")
        batch_derivation = bytes.fromhex(batch[1])
        compatibility_batch_derivation = (
            bytes.fromhex(batch[2]) if native_v3 else batch_derivation
        )
        if semantic_v3:
            assert semantic_producer is not None
            assert strict_client is not None
            semantic_producer.record_continuation_message(batch_derivation)
            strict_fold = strict_client.absorb_message(batch_derivation)
            if len(strict_fold.field_elements) != 1:
                raise RuntimeError("selected_prover_strict_fold_shape")
            fri_fold_coefficients = [strict_fold.field_elements[0]]
        else:
            assert session is not None
            challenge = _signed_round(
                session,
                schedule.descriptors[4],
                TheoremProverMessage(
                    ProverMessageKind.FRI_BATCH_DERIVATION,
                    0,
                    batch_derivation,
                    bytes(64),
                ),
                contributors=contributors,
                adapters=adapters,
                secret_keys=secret_keys,
                custody_binding=custody_binding,
            )
        _worker_command(
            process,
            "FOLD",
            (
                fri_fold_coefficients[-1]
                if semantic_v3
                else challenge.field_elements[0]
            ).encode().hex(),
        )

        layer_roots: list[bytes] = []
        compatibility_layer_roots: list[bytes] = []
        for ordinal in range(geometry.fold_round_count):
            layer = _worker_line(process, "LAYER")
            if len(layer) != (4 if native_v3 else 3) or int(layer[1]) != ordinal:
                raise RuntimeError("selected_prover_layer_shape")
            layer_roots.append(bytes.fromhex(layer[2]))
            compatibility_layer_root = (
                bytes.fromhex(layer[3]) if native_v3 else layer_roots[-1]
            )
            compatibility_layer_roots.append(compatibility_layer_root)
            if ordinal + 1 < geometry.fold_round_count:
                if semantic_v3:
                    assert semantic_producer is not None
                    assert strict_client is not None
                    semantic_producer.record_continuation_message(layer_roots[-1])
                    strict_fold = strict_client.absorb_message(layer_roots[-1])
                    if len(strict_fold.field_elements) != 1:
                        raise RuntimeError("selected_prover_strict_fold_shape")
                    fri_fold_coefficients.append(strict_fold.field_elements[0])
                else:
                    assert session is not None
                    challenge = _signed_round(
                        session,
                        schedule.descriptors[5 + ordinal],
                        TheoremProverMessage(
                            ProverMessageKind.FRI_LAYER_ROOT,
                            ordinal,
                            layer_roots[-1],
                            bytes(64),
                        ),
                        contributors=contributors,
                        adapters=adapters,
                        secret_keys=secret_keys,
                        custody_binding=custody_binding,
                    )
                _worker_command(
                    process,
                    "FOLD",
                    (
                        fri_fold_coefficients[-1]
                        if semantic_v3
                        else challenge.field_elements[0]
                    ).encode().hex(),
                )

        if semantic_v3:
            assert semantic_producer is not None
            assert strict_client is not None
            semantic_producer.record_continuation_message(layer_roots[-1])
            strict_query = strict_client.absorb_message(layer_roots[-1])
            if len(strict_query.field_elements) != 1:
                raise RuntimeError("selected_prover_strict_query_shape")
            query_seed = strict_query.field_elements[0].encode()
        else:
            assert session is not None
            final_challenge = _signed_round(
                session,
                schedule.descriptors[-1],
                TheoremProverMessage(
                    ProverMessageKind.FRI_LAYER_ROOT,
                    geometry.fold_round_count - 1,
                    layer_roots[-1],
                    bytes(64),
                ),
                contributors=contributors,
                adapters=adapters,
                secret_keys=secret_keys,
                custody_binding=custody_binding,
            )
        query_positions = sample_query_positions(
            query_seed if semantic_v3 else final_challenge.seed,
            session_id=session_id,
            domain_size=geometry.query_domain_size,
            query_count=schedule.query_count,
            with_replacement=True,
            maximum_attempts_per_position=1,
        )
        _worker_command(process, "QUERIES", len(query_positions), *query_positions)
        proof_ready = _worker_line(process, "PROOF_READY")
        if len(proof_ready) != 20:
            raise RuntimeError("selected_prover_proof_report_shape")
        proof_bytes = int(proof_ready[1])
        proof_metadata = _strict_unsigned_fields(
            proof_ready[2:3],
            frozenset({"grammar_version"}),
        )
        if proof_metadata["grammar_version"] != 2:
            raise RuntimeError("selected_prover_proof_metadata_mismatch")
        proof_attribution = SelectedProofByteAttribution.from_worker_fields(
            proof_ready[3:]
        )
        if proof_attribution.total_bytes != proof_bytes:
            raise RuntimeError("selected_prover_proof_attribution_mismatch")

        semantic_evidence = None
        strict_record = None
        if semantic_v3:
            assert semantic_producer is not None
            assert semantic_frame is not None
            assert strict_client is not None
            assert type(parent_round_901) is SemanticV3ParentRound901Production
            continuation = semantic_producer.finish_continuation()
            if _semantic_v3_post_z_builder is not None:
                _worker_command(
                    process, "POST_Z_CONTEXT", strict_query.transcript_root.hex()
                )
                post_z_context = _worker_line(process, "POST_Z_CONTEXT_READY")
                if len(post_z_context) != 2:
                    raise RuntimeError("selected_prover_post_z_context_shape")
                try:
                    post_z_context_bytes = bytes.fromhex(post_z_context[1])
                except ValueError as error:
                    raise RuntimeError("selected_prover_post_z_context_invalid") from error
                if len(post_z_context_bytes) != 64 or not any(post_z_context_bytes):
                    raise RuntimeError("selected_prover_post_z_context_invalid")
                # The H4 child must overlap the paused semantic worker: it waits
                # for projection/opening requests that FUNCTIONALS emits below.
                # Returning a finisher makes that lifetime explicit and avoids
                # a start-to-completion callback deadlock.
                post_z_finisher = _semantic_v3_post_z_builder(post_z_context_bytes)
                if not callable(post_z_finisher):
                    raise RuntimeError("selected_prover_post_z_finisher_missing")
                assert _semantic_v3_attempt is not None
                _worker_command(
                    process, "FUNCTIONALS", post_z_context[1], _semantic_v3_attempt
                )
                functional_ready = _worker_line(process, "FUNCTIONALS_READY")
                if len(functional_ready) != 2:
                    raise RuntimeError("selected_prover_functionals_shape")
                try:
                    functional_bytes = int(functional_ready[1])
                except ValueError as error:
                    raise RuntimeError("selected_prover_functionals_shape") from error
                if functional_bytes <= 0:
                    raise RuntimeError("selected_prover_functionals_shape")
                post_z_ready = _worker_line(process, "POST_Z_READY")
                if len(post_z_ready) != 3:
                    raise RuntimeError("selected_prover_post_z_shape")
                try:
                    response_bytes = int(post_z_ready[1])
                    strict_bytes = int(post_z_ready[2])
                except ValueError as error:
                    raise RuntimeError("selected_prover_post_z_shape") from error
                if response_bytes <= 0 or strict_bytes <= 0:
                    raise RuntimeError("selected_prover_post_z_shape")
                post_z_finisher()
                _worker_command(process, "H4_COMPLETE")
                h4_complete = _worker_line(process, "H4_COMPLETE_READY")
                if len(h4_complete) != 2:
                    raise RuntimeError("selected_prover_h4_complete_shape")
                try:
                    h4_mask_bytes = int(h4_complete[1])
                except ValueError as error:
                    raise RuntimeError("selected_prover_h4_complete_shape") from error
                if h4_mask_bytes <= 0:
                    raise RuntimeError("selected_prover_h4_complete_shape")
            parent_round_902 = parent_round_901.prepare_final(
                continuation,
                strict_query.transcript_root,
            )
            if type(parent_round_902) is not SemanticV3ParentRound902Production:
                raise RuntimeError("selected_prover_parent_round_902_missing")
            strict_parent_902 = strict_client.absorb_message(
                parent_round_902.prover_message
            )
            if len(strict_parent_902.field_elements) != 1:
                raise RuntimeError("selected_prover_strict_parent_902_shape")
            completion_challenge = strict_parent_902.field_elements[0]
            parent = parent_round_902.commit(completion_challenge)
            if type(parent) is not SemanticV3ParentProducerState:
                raise RuntimeError("selected_prover_parent_bundle_missing")
            semantic_producer.finalize_parent(parent)
            strict_finished = strict_client.finish()
            if (
                strict_finished.pre_final_transcript_root
                != strict_query.transcript_root
                or len(fri_fold_coefficients) != geometry.fold_round_count
            ):
                raise RuntimeError("selected_prover_strict_completion_mismatch")
            strict_record = SemanticV3StrictProducerRecord(
                finished=strict_finished,
                logup_beta=logup_beta,
                logup_gamma=logup_gamma,
                composition_alpha=composition_alpha,
                bridge_alpha=strict_bridge_alpha,
                oods_point=point,
                completion_challenge=completion_challenge,
                fri_batch_coefficient=fri_batch_coefficient,
                fri_fold_coefficients=tuple(fri_fold_coefficients),
                query_seed=query_seed,
                query_positions=query_positions,
            )
            semantic_evidence = semantic_producer.finish_evidence()
            # These transcript bytes are complete producer outputs required by
            # the native closed-witness replay.  Publish them only after both
            # strict coins and parent 902 have finished successfully; the
            # caller owns the enclosing unpublished transaction directory.
            for name, payload in (
                ("semantic-prefix.bin", semantic_evidence.prefix.encoded),
                ("semantic-continuation.bin", semantic_evidence.continuation.encoded),
                ("semantic-parent-anchor.bin", semantic_evidence.parent_anchor.encoded),
                ("semantic-program.bin", program_encoded),
            ):
                path = _semantic_v3_authority_output_directory / name
                if path.exists() or path.is_symlink():
                    raise RuntimeError(f"selected_prover_semantic_artifact_collision:{name}")
                with path.open("xb") as output:
                    output.write(payload)
                    output.flush()
            bundle = SelectedChallengeBundle(
                # Compatibility input to the current proof-byte verifier only.
                # Semantic verifier authority is the complete evidence above.
                proof_suite_id=schedule.proof_suite_id,
                parameter_commitment=schedule.parameter_commitment,
                program_binary_commitment=schedule.program_binary_commitment,
                schedule_commitment=schedule.schedule_commitment,
                session_id=semantic_evidence.prefix.semantic_session_id,
                final_transcript_root=semantic_evidence.continuation.final_transcript_root,
                evidence_commitment=semantic_evidence.evidence_commitment,
                main_trace_root=compatibility_main_root,
                interaction_trace_root=compatibility_interaction_root,
                composition_root=compatibility_composition_root,
                oods_claims_commitment=compatibility_claims_commitment,
                fri_mask_root=compatibility_fri_mask_root,
                fri_batch_derivation_commitment=compatibility_batch_derivation,
                fri_layer_roots=tuple(compatibility_layer_roots),
                logup_beta=logup_beta,
                logup_gamma=logup_gamma,
                composition_alpha=composition_alpha,
                oods_point=semantic_frame.z,
                fri_batch_coefficient=fri_batch_coefficient,
                fri_fold_coefficients=tuple(fri_fold_coefficients),
                query_seed=query_seed,
                query_positions=query_positions,
            )
        elif custody_binding is None:
            assert session is not None
            transcript = capture_selected_transcript(session)
            bundle = verify_selected_transcript(transcript, adapters)
        else:
            transcript, bundle = custody_binding.prepare_completion()
        if bundle.query_positions != query_positions:
            raise RuntimeError("selected_prover_replayed_queries_mismatch")
        _worker_command(process, "BUNDLE", encode_selected_challenge_bundle(bundle).hex())
        worker_report = " ".join(_worker_line(process, "OK"))
        worker_metadata = _strict_unsigned_fields(
            tuple(
                field
                for field in worker_report.split()[1:]
                if field.partition("=")[0]
                in {
                    "grammar_version",
                    "proof_bytes",
                }
            ),
            frozenset(
                {
                    "grammar_version",
                    "proof_bytes",
                }
            ),
        )
        if worker_metadata != {"proof_bytes": proof_bytes, **proof_metadata}:
            raise RuntimeError("selected_prover_proof_metadata_report_mismatch")
        process.stdin.close()
        return_code = process.wait(timeout=30)
        if return_code != 0:
            raise RuntimeError(f"selected_prover_worker_exit_{return_code}")
        if owned_scratch_path is not None:
            assert _streaming_manifest is not None
            assert _scratch_parent is not None
            _cleanup_owned_streaming_scratch(
                _scratch_parent,
                owned_scratch_path,
                _streaming_manifest.commitment_512,
            )
        if custody_binding is not None:
            completion = custody_binding.commit_completion()
            transcript = completion.transcript
            bundle = completion.challenge_bundle
        if semantic_v3:
            assert semantic_evidence is not None
            assert semantic_frame is not None
            assert strict_record is not None
            return SelectedV3ProofResult(
                evidence=semantic_evidence,
                worker_challenge_bundle=bundle,
                strict_record=strict_record,
                parent_anchor_commitment=semantic_frame.commitment,
                proof_bytes=proof_bytes,
                proof_attribution=proof_attribution,
                worker_report=worker_report,
            )
        return SelectedProofResult(
            transcript, bundle, proof_bytes, proof_attribution, worker_report
        )
    except BaseException as original_error:
        failures: list[BaseException] = [original_error]
        if process is not None:
            try:
                _cancel_worker(process)
            except BaseException as cancel_error:
                failures.append(cancel_error)
        if strict_client is not None:
            try:
                strict_client.abort()
            except BaseException as strict_error:
                failures.append(strict_error)
        if owned_scratch_path is not None:
            assert _streaming_manifest is not None
            assert _scratch_parent is not None
            try:
                _cleanup_owned_streaming_scratch(
                    _scratch_parent,
                    owned_scratch_path,
                    _streaming_manifest.commitment_512,
                )
            except BaseException as cleanup_error:
                failures.append(cleanup_error)
        if custody_binding is not None and not custody_binding.closed:
            assert session is not None
            try:
                custody_binding.abort_worker(
                    round_index=len(session.evidence),
                    failure_code="selected_prover_failure",
                )
            except BaseException as custody_error:
                failures.append(custody_error)
        if len(failures) > 1:
            raise BaseExceptionGroup(
                "selected_prover_cleanup_or_custody_failed", tuple(failures)
            ) from None
        raise


def prove_selected_air_streaming(
    *,
    worker_executable: Path,
    scratch_parent: Path,
    program: AirProgram,
    traces: Mapping[str, TraceTable],
    public_inputs: tuple[int, ...] = (),
    chunk_values: int = MAX_STREAMING_CHUNK_VALUES,
    session_id: bytes | None,
    public_outputs: bytes,
    sidecar: bytes,
    contributors: tuple[Contributor, ...],
    adapters: Mapping[str, object],
    secret_keys: Mapping[bytes, bytes],
    proof_export_path: Path | None = None,
    durable_custody: DurablePublicCoinCustody | None = None,
    **_obsolete_entropy: object,
) -> SelectedProofResult:
    """Build and independently verify the same proof through bounded storage."""

    if type(public_inputs) is not tuple:
        raise StructuralError("selected_prover_stream_public_inputs_invalid")
    manifest = build_streaming_air_manifest(program, traces, public_inputs)
    return prove_selected_air(
        worker_executable=worker_executable,
        program=program,
        execution_encoded=b"streaming-execution",
        session_id=session_id,
        public_outputs=public_outputs,
        sidecar=sidecar,
        contributors=contributors,
        adapters=adapters,
        secret_keys=secret_keys,
        _streaming_manifest=manifest,
        _streaming_traces=traces,
        _streaming_chunk_values=chunk_values,
        _scratch_parent=scratch_parent,
        _proof_export_path=proof_export_path,
        durable_custody=durable_custody,
        **_obsolete_entropy,
    )


def prove_selected_air_v3(
    *,
    worker_executable: Path,
    program: AirProgram,
    execution_encoded: bytes,
    session_id: bytes,
    semantic_context: SemanticV3GovernedContext,
    parent_provider: Callable[
        [SemanticV3PrefixEvidence, bytes], SemanticV3ParentRound900Production
    ],
    strict_coin_service: Path,
    authority_output_directory: Path,
    attempt: int,
    contributors: tuple[Contributor, ...],
    adapters: Mapping[str, object],
    secret_keys: Mapping[bytes, bytes],
    reveal_source: Callable[[int, Contributor], bytes] | None = None,
    post_z_builder: Callable[[bytes], Callable[[], None]] | None = None,
    post_z_exchange_directory: Path | None = None,
    h4_completion_paths: Mapping[str, Path] | None = None,
) -> SelectedV3ProofResult:
    """Pause after composition, bind parent-produced v3 state, and resume.

    The callback executes while the worker is paused.  Its caller-shaped
    ``SemanticV3ParentProducerState`` supplies producer guidance only; the
    eventual Rust verifier must replay ``result.evidence.parent_bundle`` and
    reconstruct the opaque parent anchor before accepting the continuation.
    """

    result = prove_selected_air(
        worker_executable=worker_executable,
        program=program,
        execution_encoded=execution_encoded,
        session_id=session_id,
        public_outputs=b"",
        sidecar=b"",
        contributors=contributors,
        adapters=adapters,
        secret_keys=secret_keys,
        _semantic_v3_context=semantic_context,
        _semantic_v3_parent_provider=parent_provider,
        _semantic_v3_strict_service=strict_coin_service,
        _semantic_v3_authority_output_directory=authority_output_directory,
        _semantic_v3_attempt=attempt,
        _semantic_v3_reveal_source=reveal_source,
        _semantic_v3_post_z_builder=post_z_builder,
        _semantic_v3_post_z_exchange_directory=post_z_exchange_directory,
        _semantic_v3_h4_completion_paths=h4_completion_paths,
        _native_v3_export_directory=authority_output_directory,
    )
    if type(result) is not SelectedV3ProofResult:
        raise RuntimeError("selected_prover_semantic_v3_result_missing")
    return result


def prove_selected_air_v3_streaming(
    *,
    worker_executable: Path,
    scratch_parent: Path,
    program: AirProgram,
    traces: Mapping[str, TraceTable],
    session_id: bytes,
    semantic_context: SemanticV3GovernedContext,
    parent_provider: Callable[
        [SemanticV3PrefixEvidence, bytes], SemanticV3ParentRound900Production
    ],
    strict_coin_service: Path,
    authority_output_directory: Path,
    attempt: int,
    contributors: tuple[Contributor, ...],
    adapters: Mapping[str, object],
    secret_keys: Mapping[bytes, bytes],
    public_inputs: tuple[int, ...] = (),
    chunk_values: int = MAX_STREAMING_CHUNK_VALUES,
    proof_export_path: Path | None = None,
    reveal_source: Callable[[int, Contributor], bytes] | None = None,
    post_z_builder: Callable[[bytes], Callable[[], None]] | None = None,
    post_z_exchange_directory: Path | None = None,
    h4_completion_paths: Mapping[str, Path] | None = None,
) -> SelectedV3ProofResult:
    """Run the same nonactivating v3 producer flow through bounded storage."""

    if type(public_inputs) is not tuple:
        raise StructuralError("selected_prover_stream_public_inputs_invalid")
    manifest = build_streaming_air_manifest(program, traces, public_inputs)
    result = prove_selected_air(
        worker_executable=worker_executable,
        program=program,
        execution_encoded=b"streaming-execution",
        session_id=session_id,
        public_outputs=b"",
        sidecar=b"",
        contributors=contributors,
        adapters=adapters,
        secret_keys=secret_keys,
        _streaming_manifest=manifest,
        _streaming_traces=traces,
        _streaming_chunk_values=chunk_values,
        _scratch_parent=scratch_parent,
        _proof_export_path=proof_export_path,
        _semantic_v3_context=semantic_context,
        _semantic_v3_parent_provider=parent_provider,
        _semantic_v3_strict_service=strict_coin_service,
        _semantic_v3_authority_output_directory=authority_output_directory,
        _semantic_v3_attempt=attempt,
        _semantic_v3_reveal_source=reveal_source,
        _semantic_v3_post_z_builder=post_z_builder,
        _semantic_v3_post_z_exchange_directory=post_z_exchange_directory,
        _semantic_v3_h4_completion_paths=h4_completion_paths,
        _native_v3_export_directory=authority_output_directory,
    )
    if type(result) is not SelectedV3ProofResult:
        raise RuntimeError("selected_prover_semantic_v3_result_missing")
    return result


__all__ = (
    "SelectedProofByteAttribution",
    "SelectedProofResult",
    "SelectedV3ProofResult",
    "SemanticV3ParentRound900Production",
    "SemanticV3ParentRound901Production",
    "SemanticV3ParentRound902Production",
    "SemanticV3StrictProducerRecord",
    "prove_selected_air",
    "prove_selected_air_streaming",
    "prove_selected_air_v3",
    "prove_selected_air_v3_streaming",
)
