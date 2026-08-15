from __future__ import annotations

from hashlib import sha3_512
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from experiments.bl_pq512_crypto_foundation.durable_public_coin_custody import (
    CustodyContributor,
    CustodyError,
    DurablePublicCoinCustody,
)
from experiments.bl_pq512_crypto_foundation.durable_selected_public_coin import (
    ACTIVATION_ALLOWED,
    GLOBAL_PROOF_SUITE_ID,
    PRODUCTION_USABLE,
    DurableSelectedPublicCoinSession,
    selected_custody_statement_root,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    Contributor,
    ProverMessageKind,
    RoundKind,
    TheoremProverMessage,
    build_selected_theorem_round_schedule,
)
from experiments.bl_pq512_crypto_foundation.selected_proof_parameters import (
    derive_selected_proof_geometry,
)
from experiments.bl_pq512_crypto_foundation.selected_prover_orchestrator import (
    _signed_round,
    prove_selected_air,
)
from experiments.bl_pq512_crypto_foundation import selected_prover_orchestrator as orchestrator
from tests.test_wave1a_executable_air import _fixture


def _field(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def _material():
    program, _ = _fixture()
    schedule = build_selected_theorem_round_schedule(
        derive_selected_proof_geometry(program)
    )
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    adapters = {ml.suite_id: ml, slh.suite_id: slh}
    material = []
    for ordinal, adapter in enumerate((ml, slh), 1):
        public, secret = adapter.generate_keypair()
        contributor = Contributor(
            _field(f"durable-selected-contributor-{ordinal}"),
            _field(f"durable-selected-key-{ordinal}"),
            adapter.suite_id,
            public,
        )
        material.append((contributor, secret))
    material.sort(key=lambda item: item[0].contributor_id)
    contributors = tuple(item[0] for item in material)
    secrets = {item[0].contributor_id: item[1] for item in material}
    return schedule, contributors, adapters, secrets


def _message(descriptor, fold_round_count: int) -> TheoremProverMessage:
    if descriptor.kind is RoundKind.INTERACTION_CHALLENGE:
        kind, ordinal = ProverMessageKind.MAIN_TRACE_ROOT, 0
    elif descriptor.kind is RoundKind.COMPOSITION_COEFFICIENT:
        kind, ordinal = ProverMessageKind.INTERACTION_TRACE_ROOT, 0
    elif descriptor.kind is RoundKind.OODS_POINT_PARAMETER:
        kind, ordinal = ProverMessageKind.COMPOSITION_ROOT, 0
    elif descriptor.kind is RoundKind.FRI_BATCH_COEFFICIENT:
        kind, ordinal = ProverMessageKind.OODS_CLAIMS_AND_FRI_MASK_ROOT, 0
    elif descriptor.kind is RoundKind.FRI_FOLD_COEFFICIENT:
        kind = (
            ProverMessageKind.FRI_BATCH_DERIVATION
            if descriptor.ordinal == 0
            else ProverMessageKind.FRI_LAYER_ROOT
        )
        ordinal = 0 if descriptor.ordinal == 0 else descriptor.ordinal - 1
    else:
        kind, ordinal = ProverMessageKind.FRI_LAYER_ROOT, fold_round_count - 1
    primary = _field(f"durable-selected-message-{int(kind)}-{ordinal}")
    secondary = (
        _field("durable-selected-fri-mask")
        if kind is ProverMessageKind.OODS_CLAIMS_AND_FRI_MASK_ROOT
        else bytes(64)
    )
    return TheoremProverMessage(kind, ordinal, primary, secondary)


def _store(
    path: Path, *, schedule, contributors, public_outputs: bytes, sidecar: bytes
) -> DurablePublicCoinCustody:
    statement = selected_custody_statement_root(
        public_outputs=public_outputs,
        sidecar=sidecar,
        schedule=schedule,
        contributors=contributors,
    )
    return DurablePublicCoinCustody(
        path,
        epoch_id=_field("durable-selected-epoch"),
        registry_root=_field("durable-selected-registry"),
        statement_root=statement,
        contributors=tuple(
            CustodyContributor(item.contributor_id, item.suite_id)
            for item in contributors
        ),
    )


def _signed(binding, descriptor, contributors, adapters, secrets):
    return _signed_round(
        binding.session,
        descriptor,
        _message(descriptor, binding.session.theorem_schedule.fold_round_count),
        contributors=contributors,
        adapters=adapters,
        secret_keys=secrets,
    )


def test_complete_selected_transcript_is_durably_recorded_before_terminal_receipt(
    tmp_path: Path,
) -> None:
    schedule, contributors, adapters, secrets = _material()
    public_outputs, sidecar = bytes(384), bytes(744)
    path = tmp_path / "custody.sqlite3"
    store = _store(
        path,
        schedule=schedule,
        contributors=contributors,
        public_outputs=public_outputs,
        sidecar=sidecar,
    )
    binding = DurableSelectedPublicCoinSession(
        custody=store,
        public_outputs=public_outputs,
        sidecar=sidecar,
        schedule=schedule,
        contributors=contributors,
        adapters=adapters,
    )
    with pytest.raises(CustodyError, match="exactly_one_new_round"):
        binding.record_latest_verified_round()
    for index, descriptor in enumerate(schedule.descriptors):
        _signed(binding, descriptor, contributors, adapters, secrets)
        binding.record_latest_verified_round()
        if index == 0:
            with pytest.raises(CustodyError, match="exactly_one_new_round"):
                binding.record_latest_verified_round()
    completed = binding.complete()
    assert completed.transcript.final_transcript_root == binding.session.transcript_root
    assert completed.challenge_bundle.final_transcript_root == binding.session.transcript_root
    assert _store(
        path,
        schedule=schedule,
        contributors=contributors,
        public_outputs=public_outputs,
        sidecar=sidecar,
    ).verify_receipt(completed.custody_receipt).encode() == completed.custody_receipt.encode()
    assert GLOBAL_PROOF_SUITE_ID is None
    assert PRODUCTION_USABLE is ACTIVATION_ALLOWED is False


def test_statement_or_contributor_substitution_rejects_before_attempt_burn(
    tmp_path: Path,
) -> None:
    schedule, contributors, adapters, _ = _material()
    public_outputs, sidecar = bytes(384), bytes(744)
    path = tmp_path / "custody.sqlite3"
    store = _store(
        path,
        schedule=schedule,
        contributors=contributors,
        public_outputs=public_outputs,
        sidecar=sidecar,
    )
    with pytest.raises(CustodyError, match="statement_root_mismatch"):
        DurableSelectedPublicCoinSession(
            custody=store,
            public_outputs=b"X" + public_outputs[1:],
            sidecar=sidecar,
            schedule=schedule,
            contributors=contributors,
            adapters=adapters,
        )
    with pytest.raises(CustodyError, match="no_committed_receipt"):
        store.recover_latest_receipt()


def test_worker_abort_is_durable_and_unrecorded_verified_round_fails_closed(
    tmp_path: Path,
) -> None:
    schedule, contributors, adapters, secrets = _material()
    public_outputs, sidecar = bytes(384), bytes(744)
    path = tmp_path / "custody.sqlite3"
    store = _store(
        path,
        schedule=schedule,
        contributors=contributors,
        public_outputs=public_outputs,
        sidecar=sidecar,
    )
    first = DurableSelectedPublicCoinSession(
        custody=store,
        public_outputs=public_outputs,
        sidecar=sidecar,
        schedule=schedule,
        contributors=contributors,
        adapters=adapters,
    )
    _signed(first, schedule.descriptors[0], contributors, adapters, secrets)
    with pytest.raises(CustodyError, match="verified_round_not_recorded"):
        first.abort_worker(round_index=1, failure_code="worker_crash")
    first.record_latest_verified_round()
    aborted = first.abort_worker(round_index=1, failure_code="worker_crash")
    assert store.verify_receipt(aborted).encode() == aborted.encode()
    second = DurableSelectedPublicCoinSession(
        custody=store,
        public_outputs=public_outputs,
        sidecar=sidecar,
        schedule=schedule,
        contributors=contributors,
        adapters=adapters,
    )
    assert second.session.session_id != first.session.session_id
    second.abort_worker(round_index=0, failure_code="cancelled")


def test_orchestrator_spawn_failure_durably_aborts_burned_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    schedule, contributors, adapters, secrets = _material()
    public_outputs, sidecar = bytes(384), bytes(744)
    path = tmp_path / "custody.sqlite3"
    store = _store(
        path,
        schedule=schedule,
        contributors=contributors,
        public_outputs=public_outputs,
        sidecar=sidecar,
    )
    executable = tmp_path / "selected-worker.exe"
    executable.write_bytes(b"test-only-placeholder")

    def fail_spawn(*_args, **_kwargs):
        raise OSError("test-only-spawn-failure")

    monkeypatch.setattr(
        "experiments.bl_pq512_crypto_foundation.selected_prover_orchestrator.subprocess.Popen",
        fail_spawn,
    )
    program, _ = _fixture()
    with pytest.raises(OSError, match="test-only-spawn-failure"):
        prove_selected_air(
            worker_executable=executable,
            program=program,
            execution_encoded=b"test-only-execution",
            session_id=None,
            public_outputs=public_outputs,
            sidecar=sidecar,
            contributors=contributors,
            adapters=adapters,
            secret_keys=secrets,
            durable_custody=store,
        )
    with pytest.raises(CustodyError, match="no_open_attempt"):
        store.recover_open_attempt()
    assert store.burn_attempt().ordinal == 1


def test_worker_readline_has_a_hard_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    release = Event()

    class BlockingStdout:
        def readline(self, _limit: int) -> bytes:
            release.wait()
            return b""

    process = SimpleNamespace(stdout=BlockingStdout())
    monkeypatch.setattr(orchestrator, "WORKER_RESPONSE_TIMEOUT_SECONDS", 0.02)
    try:
        with pytest.raises(TimeoutError, match="worker_response_timeout"):
            orchestrator._worker_line(process, "NEVER")
    finally:
        release.set()


def test_worker_write_has_a_hard_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    release = Event()

    class BlockingStdin:
        def write(self, encoded: bytes) -> int:
            release.wait()
            return len(encoded)

        def flush(self) -> None:
            return None

    process = SimpleNamespace(stdin=BlockingStdin())
    monkeypatch.setattr(orchestrator, "WORKER_RESPONSE_TIMEOUT_SECONDS", 0.02)
    try:
        with pytest.raises(TimeoutError, match="worker_write_timeout"):
            orchestrator._worker_write(process, b"blocked", flush=True)
    finally:
        release.set()


def test_forced_kill_cleanup_removes_only_exact_owned_streaming_directory(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "scratch"
    parent.mkdir()
    session_id = _field("cleanup-session")
    program = _field("cleanup-program")
    manifest = _field("cleanup-manifest")
    owned = orchestrator._owned_streaming_scratch_path(parent, session_id, program)
    owned.mkdir()
    (owned / "OWNER").write_bytes(b"BLPQSCR1" + manifest + b"\x00")
    (owned / "private-column.bin").write_bytes(b"private-test-data")
    orchestrator._cleanup_owned_streaming_scratch(parent, owned, manifest)
    assert not owned.exists()

    unowned = orchestrator._owned_streaming_scratch_path(
        parent, _field("other-session"), program
    )
    unowned.mkdir()
    (unowned / "OWNER").write_bytes(b"BLPQSCR1" + _field("wrong") + b"\x00")
    with pytest.raises(RuntimeError, match="ownership_mismatch"):
        orchestrator._cleanup_owned_streaming_scratch(parent, unowned, manifest)
    assert unowned.is_dir()


def test_forced_kill_cleanup_removes_only_empty_or_authentic_partial_creation(
    tmp_path: Path,
) -> None:
    parent = tmp_path.resolve()
    manifest = _field("partial-scratch-manifest")

    empty = parent / "blpq-stream-empty"
    empty.mkdir()
    orchestrator._cleanup_owned_streaming_scratch(parent, empty, manifest)
    assert not empty.exists()

    partial = parent / "blpq-stream-partial"
    partial.mkdir()
    expected = b"BLPQSCR1" + manifest
    (partial / "OWNER").write_bytes(expected[:37])
    orchestrator._cleanup_owned_streaming_scratch(parent, partial, manifest)
    assert not partial.exists()

    hostile = parent / "blpq-stream-hostile"
    hostile.mkdir()
    (hostile / "OWNER").write_bytes(b"wrong")
    with pytest.raises(RuntimeError, match="partial_marker_invalid"):
        orchestrator._cleanup_owned_streaming_scratch(parent, hostile, manifest)
    assert hostile.is_dir()
