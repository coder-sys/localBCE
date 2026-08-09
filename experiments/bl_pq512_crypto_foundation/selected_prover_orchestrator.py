"""Production-shaped selected-suite prover orchestration.

The Rust worker retains large private proof state.  This module owns the
authenticated public-coin state machine and will only emit a proof result after
an independent replay of both standardized post-quantum signature suites.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from pathlib import Path
import shutil
import subprocess
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.oods_reference import (
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
    derive_selected_proof_geometry,
)
from experiments.bl_pq512_crypto_foundation.selected_public_coin import (
    SelectedChallengeBundle,
    SelectedPublicCoinTranscript,
    capture_selected_transcript,
    encode_selected_challenge_bundle,
    verify_selected_transcript,
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


def _worker_line(process: subprocess.Popen[bytes], expected: str) -> tuple[str, ...]:
    assert process.stdout is not None
    encoded = process.stdout.readline(MAX_WORKER_LINE_BYTES + 1)
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


def _worker_command(process: subprocess.Popen[bytes], *fields: object) -> None:
    assert process.stdin is not None
    encoded = " ".join(str(value) for value in fields).encode("ascii") + b"\n"
    if len(encoded) > MAX_WORKER_LINE_BYTES:
        raise StructuralError("selected_prover_worker_command_too_large")
    process.stdin.write(encoded)
    process.stdin.flush()


def _signed_round(
    session: PublicCoinSession,
    descriptor: object,
    prover_message: TheoremProverMessage,
    *,
    contributors: tuple[Contributor, ...],
    adapters: Mapping[str, object],
    secret_keys: Mapping[bytes, bytes],
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
    return session.finalize_round()


def prove_selected_air(
    *,
    worker_executable: Path,
    program: AirProgram,
    execution_encoded: bytes,
    session_id: bytes,
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
    **_obsolete_entropy: object,
) -> SelectedProofResult:
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
    _exact_bytes("session_id", session_id, 64, nonzero=True)
    streaming = _streaming_manifest is not None
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

    process = subprocess.Popen(
        [str(worker_executable)]
        + ([str(_scratch_parent)] if streaming else [])
        + ([str(_proof_export_path)] if _proof_export_path is not None else []),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=worker_executable.parent,
    )
    try:
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
            process.stdin.write(
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
                )
            )
            observed_chunks = 0
            for chunk in chunks:
                process.stdin.write(len(chunk).to_bytes(4, "big"))
                process.stdin.write(chunk)
                observed_chunks += 1
            if observed_chunks != chunk_count:
                raise RuntimeError("selected_prover_stream_chunk_count_mismatch")
        else:
            process.stdin.write(
                b"".join(
                    (
                        WORKER_MAGIC,
                        len(program_encoded).to_bytes(4, "big"),
                        program_encoded,
                        len(execution_encoded).to_bytes(4, "big"),
                        execution_encoded,
                        session_id,
                    )
                )
            )
        process.stdin.flush()

        main = _worker_line(process, "MAIN")
        if len(main) != 2:
            raise RuntimeError("selected_prover_main_shape")
        challenge = _signed_round(
            session,
            schedule.descriptors[0],
            TheoremProverMessage(
                ProverMessageKind.MAIN_TRACE_ROOT, 0, bytes.fromhex(main[1]), bytes(64)
            ),
            contributors=contributors,
            adapters=adapters,
            secret_keys=secret_keys,
        )
        _worker_command(
            process,
            "INTERACTION",
            challenge.field_elements[0].encode().hex(),
            challenge.field_elements[1].encode().hex(),
        )

        interaction = _worker_line(process, "INTERACTION_ROOT")
        if len(interaction) != 2:
            raise RuntimeError("selected_prover_interaction_shape")
        challenge = _signed_round(
            session,
            schedule.descriptors[1],
            TheoremProverMessage(
                ProverMessageKind.INTERACTION_TRACE_ROOT,
                0,
                bytes.fromhex(interaction[1]),
                bytes(64),
            ),
            contributors=contributors,
            adapters=adapters,
            secret_keys=secret_keys,
        )
        _worker_command(
            process, "COMPOSITION", challenge.field_elements[0].encode().hex()
        )

        composition = _worker_line(process, "COMPOSITION_ROOT")
        if len(composition) != 2:
            raise RuntimeError("selected_prover_composition_shape")
        challenge = _signed_round(
            session,
            schedule.descriptors[2],
            TheoremProverMessage(
                ProverMessageKind.COMPOSITION_ROOT,
                0,
                bytes.fromhex(composition[1]),
                bytes(64),
            ),
            contributors=contributors,
            adapters=adapters,
            secret_keys=secret_keys,
        )
        if challenge.oods_sample is None:
            raise RuntimeError("selected_prover_oods_sample_missing")
        point = stereographic_circle_point(challenge.oods_sample.parameter)
        _worker_command(process, "OODS", point.x.encode().hex(), point.y.encode().hex())

        oods_roots = _worker_line(process, "OODS_ROOTS")
        if len(oods_roots) != 3:
            raise RuntimeError("selected_prover_oods_shape")
        challenge = _signed_round(
            session,
            schedule.descriptors[3],
            TheoremProverMessage(
                ProverMessageKind.OODS_CLAIMS_AND_FRI_MASK_ROOT,
                0,
                bytes.fromhex(oods_roots[1]),
                bytes.fromhex(oods_roots[2]),
            ),
            contributors=contributors,
            adapters=adapters,
            secret_keys=secret_keys,
        )
        _worker_command(process, "BATCH", challenge.field_elements[0].encode().hex())

        batch = _worker_line(process, "BATCH_DERIVATION")
        if len(batch) != 2:
            raise RuntimeError("selected_prover_batch_shape")
        challenge = _signed_round(
            session,
            schedule.descriptors[4],
            TheoremProverMessage(
                ProverMessageKind.FRI_BATCH_DERIVATION,
                0,
                bytes.fromhex(batch[1]),
                bytes(64),
            ),
            contributors=contributors,
            adapters=adapters,
            secret_keys=secret_keys,
        )
        _worker_command(process, "FOLD", challenge.field_elements[0].encode().hex())

        layer_roots: list[bytes] = []
        for ordinal in range(geometry.fold_round_count):
            layer = _worker_line(process, "LAYER")
            if len(layer) != 3 or int(layer[1]) != ordinal:
                raise RuntimeError("selected_prover_layer_shape")
            layer_roots.append(bytes.fromhex(layer[2]))
            if ordinal + 1 < geometry.fold_round_count:
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
                )
                _worker_command(
                    process, "FOLD", challenge.field_elements[0].encode().hex()
                )

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
        )
        query_positions = sample_query_positions(
            final_challenge.seed,
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

        transcript = capture_selected_transcript(session)
        bundle = verify_selected_transcript(transcript, adapters)
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
        return SelectedProofResult(
            transcript, bundle, proof_bytes, proof_attribution, worker_report
        )
    except BaseException:
        _cancel_worker(process)
        raise


def prove_selected_air_streaming(
    *,
    worker_executable: Path,
    scratch_parent: Path,
    program: AirProgram,
    traces: Mapping[str, TraceTable],
    public_inputs: tuple[int, ...] = (),
    chunk_values: int = MAX_STREAMING_CHUNK_VALUES,
    session_id: bytes,
    public_outputs: bytes,
    sidecar: bytes,
    contributors: tuple[Contributor, ...],
    adapters: Mapping[str, object],
    secret_keys: Mapping[bytes, bytes],
    proof_export_path: Path | None = None,
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
        **_obsolete_entropy,
    )


__all__ = (
    "SelectedProofByteAttribution",
    "SelectedProofResult",
    "prove_selected_air",
    "prove_selected_air_streaming",
)
