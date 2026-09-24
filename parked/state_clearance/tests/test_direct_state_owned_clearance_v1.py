from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import fields, replace
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
from threading import Lock
from types import SimpleNamespace

import pytest

import parked.state_clearance.app.direct_state_owned_clearance_v1 as direct_clearance_module
import parked.state_clearance.app.transactional_database_boundary as database_boundary_module
from parked.state_clearance.app.direct_state_owned_clearance_v1 import (
    DIRECT_INITIAL_CLEARANCE_ROOT,
    DIRECT_INITIAL_PAYMENT_ROOT,
    DirectStateOwnedAtomicClearanceV1,
    DirectStateOwnedClearanceError,
)
from parked.state_clearance.app.semantic_kernel_binding import (
    DIRECTIVE_NAMES,
    POLICY_NAMES,
    PinnedSemanticKernelBinding,
    SEMANTIC_ADAPTER_PROTOCOL,
    SEMANTIC_KERNEL_PACKAGE_PROTOCOL,
    SemanticKernelBindingError,
    SemanticKernelPackageFile,
    SemanticKernelPin,
    SemanticKernelResult,
    StateKernelRequest,
    StateKernelResult,
    STATE_ADAPTER_PROTOCOL,
    STATE_KERNEL_BUILD_ID,
    STATE_KERNEL_SCHEMA,
    build_production_semantic_kernel_binding,
    parse_semantic_adapter_output,
    parse_state_kernel_adapter_output,
    parse_state_kernel_request,
    semantic_result_from_details,
)
from parked.state_clearance.app.transactional_database_boundary import (
    AntiRollbackAnchorSnapshot,
    InMemoryAntiRollbackReference,
    ProductionBoundaryError,
)
from parked.state_clearance.experiments.native_v3_phase0.native_v3_fixture import (
    DIRECTIVE_BLOCK,
    DIRECTIVE_CLEAR,
    DIRECTIVE_EXCEPTION_APPROVED,
    DIRECTIVE_HOLD,
    DIRECTIVE_HUMAN_REVIEW,
    NO_EXCEPTION_SENTINEL,
)
from parked.state_clearance.experiments.native_v3_plaintext_continuity.continuity import (
    ACCESS_READ,
    ACCESS_WRITE,
    DEMO_CASES,
    ContinuityReceipt,
    ContinuityStore,
    build_demo_case,
    bundle_bytes,
    make_completeness,
)
from parked.state_clearance.experiments.native_v3_plaintext_continuity.independent import (
    CONTROL_SET_ID,
    EVALUATOR_ID,
    IndependentParseError,
    MODE_ID,
    RULE_ID,
    parse_bundle,
    parse_bundle_details,
)
from parked.state_clearance.experiments.native_v3_trust_boundary.profile import build_profile_bindings


def _digest(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _case(name: str) -> tuple[bytes, object, object, object, object]:
    request, facts, completeness, exception = build_demo_case(name)
    receipt = ContinuityStore().apply(request, facts, completeness, exception)
    return (
        bundle_bytes(receipt, facts, completeness),
        request,
        facts,
        completeness,
        receipt,
    )


def _encode_state_kernel_result(result: StateKernelResult) -> bytes:
    values: list[str] = []
    for field in fields(result):
        if field.name == "protocol":
            continue
        value = getattr(result, field.name)
        if field.name == "policy":
            encoded = POLICY_NAMES[value]
        elif field.name == "directive":
            encoded = DIRECTIVE_NAMES[value]
        elif type(value) is bytes:
            encoded = value.hex()
        elif type(value) is bool:
            encoded = str(value).lower()
        else:
            encoded = str(value)
        values.append(f"{field.name}={encoded}")
    return (result.protocol + ";" + ";".join(values) + "\n").encode("ascii")


def _legacy_pinned_semantic_kernel_binding(root: Path) -> PinnedSemanticKernelBinding:
    package_root = root / "legacy-semantic-kernel"
    digest = b"\xA1" * 32
    package_file = SemanticKernelPackageFile(
        path=package_root / "adapter.exe",
        size_bytes=1,
        sha256=digest,
        role="adapter_executable",
    )
    return PinnedSemanticKernelBinding(
        SemanticKernelPin(
            package_protocol=SEMANTIC_KERNEL_PACKAGE_PROTOCOL,
            package_root=package_root,
            adapter_executable=package_file.path,
            kernel_artifact=package_root / "kernel.bin",
            source_manifest=package_root / "source.json",
            build_receipt=package_root / "build-receipt.json",
            workspace=package_root.parent,
            adapter_size_bytes=1,
            adapter_sha256=digest,
            kernel_artifact_size_bytes=1,
            kernel_artifact_sha256=digest,
            source_manifest_size_bytes=1,
            source_manifest_sha256=digest,
            build_receipt_size_bytes=1,
            build_receipt_sha256=digest,
            source_binding_sha256=digest,
            kernel_build_id="BLSK-BLCBND02-EXACT-V2",
            handoff_commit="a" * 40,
            handoff_tree="b" * 40,
            package_files=(package_file,),
            adapter_protocol=SEMANTIC_ADAPTER_PROTOCOL,
        )
    )


class _TestSemanticKernel:
    """Explicit test-only provider; its synthetic pin is not bridge evidence."""

    kernel_artifact_sha256 = b"\xA1" * 32
    source_binding_sha256 = b"\xB2" * 32

    @property
    def pin(self) -> "_TestSemanticKernel":
        return self

    def evaluate(self, bundle: bytes) -> SemanticKernelResult:
        details = parse_bundle_details(bundle)
        profile = build_profile_bindings()
        return semantic_result_from_details(
            details,
            profile_id=profile.profile_id,
            schema_id=direct_clearance_module.DIRECT_DATABASE_SCHEMA_ID,
            program_id=direct_clearance_module.DIRECT_DATABASE_PROGRAM_ID,
            mode_id=MODE_ID,
            evaluator_id=EVALUATOR_ID,
            rule_id=RULE_ID,
        )

    def evaluate_state_request(self, request: StateKernelRequest) -> StateKernelResult:
        details = parse_bundle_details(request.bundle)
        evidence = self.evaluate(request.bundle)
        bundle_id = _digest(
            b"BL/NATIVE-V3/CONTINUITY/BUNDLE/v2\x00",
            request.bundle,
        )
        if request.prior_operation is not None:
            prior = request.prior_operation
            values = {
                "receipt_id": prior.receipt_id,
                "request_id": prior.request_id,
                "decision_id": prior.decision_id,
                "join_id": prior.join_id,
                "profile_id": prior.profile_id,
                "schema_id": prior.schema_id,
                "program_id": prior.program_id,
                "mode_id": prior.mode_id,
                "evaluator_id": prior.evaluator_id,
                "control_set_id": prior.control_set_id,
                "rule_id": prior.rule_id,
                "phase0_receipt_binding": prior.phase0_receipt_binding,
                "source_root": prior.source_root,
                "completeness_id": details.completeness["id"],
                "exception_id": prior.exception_id,
                "before_state_id": prior.continuity_before_state_id,
                "after_state_id": prior.continuity_after_state_id,
                "receipt_id": prior.receipt_id,
                "chronology_id": details.decision["chronology_id"],
                "replay_id": (
                    details.decision["replay_id"]
                    if prior.operation_version == 0
                    else _digest(
                        b"BL/DIRECT-STATE-OWNED/STATE-REPLAY/v1\x00",
                        prior.request_id,
                        prior.continuity_before_state_id,
                        prior.bundle_id,
                        prior.control_set_id,
                    )
                ),
                "decision_path_id": (
                    details.decision["decision_path_id"]
                    if prior.operation_version == 0
                    else _digest(
                        b"BL/DIRECT-STATE-OWNED/STATE-DECISION-PATH/v1\x00",
                        details.decision["decision_path_id"],
                        prior.decision_id,
                    )
                ),
                "before_audit_head": prior.continuity_before_audit_head,
                "before_continuity_root": prior.continuity_before_root,
                "after_audit_head": prior.continuity_after_audit_head,
                "after_continuity_root": prior.continuity_after_root,
                "audit_head_after": prior.continuity_after_audit_head,
                "continuity_root_after": prior.continuity_after_root,
                "policy": prior.policy_result,
                "directive": prior.effective_directive,
                "event_time": prior.event_time,
                "observation_time": prior.observation_time,
                "rule_effective_time": prior.rule_effective_time,
                "decision_time": prior.decision_time,
                "continuity_epoch": prior.continuity_epoch,
                "sequence_before": prior.continuity_sequence_before,
                "sequence_after": prior.continuity_sequence_after,
                "economic_mutation": prior.clearance_advanced,
                "disposition": "REPLAY",
                "prior_operation_digest": prior.operation_digest,
            }
        else:
            before_state = request.continuity_state_id
            before_audit = request.continuity_audit_head
            before_root = request.continuity_root
            before_sequence = request.global_sequence
            before_row_count = request.continuity_row_count
            new_request_id = _digest(
                b"BL/DIRECT-STATE-OWNED/STATE-REQUEST/v1\x00",
                request.command_id,
                bundle_id,
                request.expected_revision.to_bytes(8, "big"),
                before_state,
                request.governance_commitment,
                request.control_set_id,
                request.mode_id,
            )
            new_decision_id = _digest(
                b"BL/DIRECT-STATE-OWNED/STATE-DECISION/v1\x00",
                new_request_id,
                evidence.decision_id,
                before_state,
                details.facts["source_root"],
                bytes((evidence.policy, evidence.directive)),
                details.decision["exception_id"],
            )
            after_audit = _digest(
                b"BL/NATIVE-V3/CONTINUITY/AUDIT-HEAD/v2\x00",
                before_audit,
                new_decision_id,
                bytes((evidence.directive,)),
            )
            after_root = _digest(
                b"BL/NATIVE-V3/CONTINUITY/ROOT/v2\x00",
                before_root,
                details.facts["source_root"],
                new_decision_id,
            )
            context_id = _digest(
                b"BL/NATIVE-V3/CONTINUITY/STATE-CONTEXT/v2\x00",
                request.profile_id,
                request.mode_id,
            )
            raw_state = b"".join(
                (
                    b"BLCSTA02",
                    (2).to_bytes(2, "big"),
                    b"\x00\x00",
                    context_id,
                    (before_sequence + 1).to_bytes(8, "big"),
                    (before_row_count + 1).to_bytes(4, "big"),
                    b"\x00" * 4,
                    after_audit,
                    after_root,
                )
            )
            after_state = _digest(
                b"BL/NATIVE-V3/CONTINUITY/STATE-ID/v2\x00",
                raw_state,
            )
            values = {
                "receipt_id": _digest(
                    b"BL/DIRECT-STATE-OWNED/STATE-RECEIPT/v1\x00",
                    new_decision_id,
                    after_state,
                    evidence.receipt_id,
                ),
                "request_id": new_request_id,
                "decision_id": new_decision_id,
                "join_id": _digest(
                    b"BL/DIRECT-STATE-OWNED/STATE-JOIN/v1\x00",
                    new_decision_id,
                    evidence.join_id,
                ),
                "profile_id": request.profile_id,
                "schema_id": request.schema_id,
                "program_id": request.program_id,
                "mode_id": request.mode_id,
                "evaluator_id": request.evaluator_id,
                "control_set_id": request.control_set_id,
                "rule_id": request.rule_id,
                "phase0_receipt_binding": request.phase0_receipt_binding,
                "source_root": details.facts["source_root"],
                "completeness_id": details.completeness["id"],
                "exception_id": details.decision["exception_id"],
                "before_state_id": before_state,
                "after_state_id": after_state,
                "chronology_id": evidence.chronology_id,
                "replay_id": _digest(
                    b"BL/DIRECT-STATE-OWNED/STATE-REPLAY/v1\x00",
                    new_request_id,
                    before_state,
                    bundle_id,
                    request.control_set_id,
                ),
                "decision_path_id": _digest(
                    b"BL/DIRECT-STATE-OWNED/STATE-DECISION-PATH/v1\x00",
                    evidence.decision_path_id,
                    new_decision_id,
                ),
                "before_audit_head": before_audit,
                "before_continuity_root": before_root,
                "after_audit_head": after_audit,
                "after_continuity_root": after_root,
                "audit_head_after": after_audit,
                "continuity_root_after": after_root,
                "evidence_request_id": details.request["id"],
                "evidence_decision_id": details.decision["decision_id"],
                "evidence_join_id": details.join_id,
                "evidence_receipt_id": details.receipt_id,
                "evidence_decision_path_id": details.decision["decision_path_id"],
                "policy": evidence.policy,
                "directive": evidence.directive,
                "event_time": evidence.event_time,
                "observation_time": evidence.observation_time,
                "rule_effective_time": evidence.rule_effective_time,
                "decision_time": evidence.decision_time,
                "continuity_epoch": request.continuity_epoch,
                "sequence_before": before_sequence,
                "sequence_after": before_sequence + 1,
                "economic_mutation": evidence.directive in (1, 5),
                "disposition": "ACCEPT",
                "prior_operation_digest": b"\x00" * 64,
            }
        if "evidence_request_id" not in values:
            values.update(
                {
                    "evidence_request_id": details.request["id"],
                    "evidence_decision_id": details.decision["decision_id"],
                    "evidence_join_id": details.join_id,
                    "evidence_receipt_id": details.receipt_id,
                    "evidence_decision_path_id": details.decision["decision_path_id"],
                }
            )
        return StateKernelResult(
            protocol=STATE_ADAPTER_PROTOCOL,
            schema=STATE_KERNEL_SCHEMA,
            result="PASS",
            kernel_build_id=STATE_KERNEL_BUILD_ID,
            artifact_sha256=b"\xA1" * 32,
            source_binding_sha256=b"\xB2" * 32,
            input_sha3_512=request.input_sha3_512,
            command_id=request.command_id,
            expected_revision=request.expected_revision,
            current_sequence=request.global_sequence,
            bundle_id=bundle_id,
            bundle_bytes=len(request.bundle),
            reason=evidence.reason,
            reason_id=evidence.reason_id,
            attempt_id=request.command_id,
            proof_suite_id="NONE",
            proof_session_accepted=False,
            replay_stateful=True,
            **values,
        )


class _StateRequestCaptureKernel(_TestSemanticKernel):
    def __init__(self) -> None:
        self.request: StateKernelRequest | None = None
        self.result: StateKernelResult | None = None

    def evaluate_state_request(self, request: StateKernelRequest) -> StateKernelResult:
        self.request = request
        self.result = super().evaluate_state_request(request)
        return self.result


class _UnavailableSemanticKernel(_TestSemanticKernel):
    def evaluate(self, bundle: bytes) -> SemanticKernelResult:
        raise SemanticKernelBindingError("kernel-artifact-binding-mismatch")

    def evaluate_state_request(self, request: StateKernelRequest) -> StateKernelResult:
        raise SemanticKernelBindingError("kernel-artifact-binding-mismatch")


class _MalformedSemanticKernel(_TestSemanticKernel):
    def evaluate(self, bundle: bytes) -> SemanticKernelResult:
        parse_semantic_adapter_output(b"BL-SEMANTIC-ADAPTER/2;result=PASS\n")
        raise AssertionError("unreachable")

    def evaluate_state_request(self, request: StateKernelRequest) -> StateKernelResult:
        parse_state_kernel_adapter_output(b"BL-STATE-SEMANTIC-ADAPTER/1;result=PASS\n")
        raise AssertionError("unreachable")


class _MismatchingKernelIdentitySemanticKernel(_TestSemanticKernel):
    def __init__(self, field: str) -> None:
        if field not in {"artifact_sha256", "source_binding_sha256"}:
            raise ValueError("test_kernel_identity_field")
        self._field = field

    def evaluate_state_request(self, request: StateKernelRequest) -> StateKernelResult:
        result = super().evaluate_state_request(request)
        return replace(result, **{self._field: b"\xC3" * 32})


class _MismatchingSemanticKernel(_TestSemanticKernel):
    def evaluate(self, bundle: bytes) -> SemanticKernelResult:
        return replace(super().evaluate(bundle), decision_id=b"\x01" * 64)

    def evaluate_state_request(self, request: StateKernelRequest) -> StateKernelResult:
        return replace(
            super().evaluate_state_request(request),
            decision_id=b"\x01" * 64,
        )


class _MalformedAfterNativeSemanticKernel:
    """Run the real adapter, then inject a malformed response at the typed seam."""

    def __init__(self, binding: object) -> None:
        self._binding = binding

    def evaluate_state_request(self, request: StateKernelRequest) -> StateKernelResult:
        self._binding.evaluate_state_request(request)  # type: ignore[attr-defined]
        parse_state_kernel_adapter_output(b"BL-STATE-SEMANTIC-ADAPTER/1;result=PASS\n")
        raise AssertionError("unreachable")


class _MismatchingAfterNativeSemanticKernel:
    """Run the real adapter, then corrupt one semantic field before State sees it."""

    def __init__(self, binding: object) -> None:
        self._binding = binding

    def evaluate_state_request(self, request: StateKernelRequest) -> StateKernelResult:
        result = self._binding.evaluate_state_request(request)  # type: ignore[attr-defined]
        return replace(result, decision_id=b"\x01" * 64)


def _install_test_semantic_kernel(
    monkeypatch: pytest.MonkeyPatch,
    semantic_kernel: object,
) -> None:
    """Replace the production loader only inside this test module."""

    monkeypatch.setattr(
        direct_clearance_module,
        "build_production_semantic_kernel_binding",
        lambda: semantic_kernel,
    )


@pytest.fixture(autouse=True)
def _inject_test_semantic_kernel(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install a synthetic provider; this is not real Lean acceptance."""

    if os.environ.get("BLIND_LEDGER_RUN_NATIVE_STATE") == "1":
        return

    _install_test_semantic_kernel(monkeypatch, _TestSemanticKernel())


def test_semantic_adapter_rejects_legacy_or_incomplete_output() -> None:
    with pytest.raises(SemanticKernelBindingError, match="semantic_kernel_output"):
        parse_semantic_adapter_output(b"BL-SEMANTIC-ADAPTER/2;result=PASS\n")


def test_semantic_adapter_parser_accepts_the_complete_result_surface() -> None:
    raw, _, _, _, _ = _case("valid-continuity")
    result = _TestSemanticKernel().evaluate(raw)
    values: list[str] = []
    for field in fields(result):
        if field.name == "protocol":
            continue
        value = getattr(result, field.name)
        if field.name == "policy":
            encoded = POLICY_NAMES[value]
        elif field.name == "directive":
            encoded = DIRECTIVE_NAMES[value]
        elif type(value) is bytes:
            encoded = value.hex()
        elif type(value) is bool:
            encoded = str(value).lower()
        else:
            encoded = str(value)
        values.append(f"{field.name}={encoded}")
    encoded_line = (result.protocol + ";" + ";".join(values) + "\n").encode("ascii")
    assert parse_semantic_adapter_output(encoded_line) == result


@pytest.mark.parametrize(
    "semantic_kernel",
    (
        _UnavailableSemanticKernel(),
        _MalformedSemanticKernel(),
        _MismatchingSemanticKernel(),
        _MismatchingKernelIdentitySemanticKernel("artifact_sha256"),
        _MismatchingKernelIdentitySemanticKernel("source_binding_sha256"),
    ),
    ids=(
        "unavailable-or-tampered",
        "malformed-response",
        "semantic-mismatch",
        "artifact-identity-mismatch",
        "source-binding-identity-mismatch",
    ),
)
def test_native_faults_leave_database_untouched(
    tmp_path: Path,
    semantic_kernel: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw, _, _, _, _ = _case("valid-continuity")
    _install_test_semantic_kernel(monkeypatch, semantic_kernel)
    service = DirectStateOwnedAtomicClearanceV1(
        path=tmp_path / "native-fault.sqlite3",
    )
    before = service.snapshot()
    with pytest.raises(DirectStateOwnedClearanceError, match="direct_semantic_kernel_reject"):
        service.submit(raw)
    assert service.snapshot() == before
    assert _direct_count(service.path) == 0
    service.verify_integrity()
    service.close()


def test_synthetic_legacy_protocol_binding_stays_fail_closed_for_state_operations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw, _, _, _, _ = _case("valid-continuity")
    legacy_binding = _legacy_pinned_semantic_kernel_binding(tmp_path)
    _install_test_semantic_kernel(monkeypatch, legacy_binding)
    service = DirectStateOwnedAtomicClearanceV1(
        path=tmp_path / "production-native.sqlite3",
    )
    try:
        before = service.snapshot()
        with pytest.raises(
            DirectStateOwnedClearanceError,
            match="direct_semantic_kernel_reject:state_kernel_release_not_pinned",
        ):
            service.submit(raw)
        assert service.snapshot() == before
        assert _direct_count(service.path) == 0
        service.verify_integrity()
    finally:
        service.close()


@pytest.mark.parametrize("case_name", DEMO_CASES)
def test_typed_state_kernel_seam_handles_every_direct_case(
    tmp_path: Path,
    case_name: str,
) -> None:
    raw, _, _, _, _ = _case(case_name)
    service = DirectStateOwnedAtomicClearanceV1(path=tmp_path / f"state-{case_name}.sqlite3")
    try:
        receipt = service.submit(raw)
        details = parse_bundle_details(raw)
        assert receipt.effective_directive == details.effective_directive
        assert receipt.policy_result == details.policy_result
        assert _direct_count(service.path) == 1
        service.verify_integrity()
    finally:
        service.close()


def test_pending_production_pin_prevents_state_service_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "pending-production-pin.sqlite3"
    monkeypatch.setattr(
        direct_clearance_module,
        "build_production_semantic_kernel_binding",
        build_production_semantic_kernel_binding,
    )
    with pytest.raises(
        DirectStateOwnedClearanceError,
        match="direct_semantic_kernel_unavailable:semantic_kernel_artifact_pin_fields",
    ):
        DirectStateOwnedAtomicClearanceV1(path=path)
    assert not path.exists()


def test_production_native_stale_before_state_leaves_database_untouched(
    tmp_path: Path,
) -> None:
    first_raw, _, _, _, _ = _case("valid-continuity")
    stale_raw, _, _, _, _ = _case("expired-credential")
    path = tmp_path / "production-native-stale.sqlite3"
    first = DirectStateOwnedAtomicClearanceV1(
        path=path,
    )
    try:
        first.submit(first_raw)
    finally:
        first.close()

    stale = DirectStateOwnedAtomicClearanceV1(
        path=path,
    )
    try:
        before = stale.snapshot()
        count_before = _direct_count(stale.path)
        with pytest.raises(DirectStateOwnedClearanceError, match="state_kernel_stale_revision"):
            stale.submit(stale_raw)
        assert stale.snapshot() == before
        assert _direct_count(stale.path) == count_before == 1
        stale.verify_integrity()
    finally:
        stale.close()


def _split_bundle(raw: bytes) -> list[bytes]:
    assert raw[:8] == b"BLCBND02"
    offset = 12
    parts: list[bytes] = []
    for _ in range(7):
        length = int.from_bytes(raw[offset : offset + 4], "big")
        offset += 4
        parts.append(raw[offset : offset + length])
        offset += length
    assert offset == len(raw)
    return parts


def _join_bundle(parts: list[bytes]) -> bytes:
    return b"".join(
        (
            b"BLCBND02",
            (2).to_bytes(2, "big"),
            b"\0\0",
            *(len(part).to_bytes(4, "big") + part for part in parts),
        )
    )


def _rebind_receipt(receipt_raw: bytes) -> bytes:
    body = bytearray(receipt_raw[:-64])
    decision_length_offset = 532
    decision_length = int.from_bytes(
        body[decision_length_offset : decision_length_offset + 4], "big"
    )
    access_count_offset = decision_length_offset + 4 + decision_length
    assert int.from_bytes(body[access_count_offset : access_count_offset + 4], "big") == 2
    cursor = access_count_offset + 4
    access_raws: list[bytes] = []
    for _ in range(2):
        length = int.from_bytes(body[cursor : cursor + 4], "big")
        cursor += 4
        access_raws.append(bytes(body[cursor : cursor + length]))
        cursor += length
    decision_raw = bytes(body[536 : 536 + decision_length])
    join_raw = b"".join(
        (
            b"BLCJON02",
            (2).to_bytes(2, "big"),
            b"\0\0",
            (1).to_bytes(4, "big"),
            (2).to_bytes(4, "big"),
            len(decision_raw).to_bytes(4, "big"),
            decision_raw,
            *(len(raw).to_bytes(4, "big") + raw for raw in access_raws),
        )
    )
    body[276:340] = _digest(
        b"BL/NATIVE-V3/CONTINUITY/DECISION-ACCESS-JOIN/v2\0",
        join_raw,
    )
    return bytes(body) + _digest(
        b"BL/NATIVE-V3/CONTINUITY/RECEIPT-ID/v2\0",
        bytes(body),
    )


def _access_rows(receipt_raw: bytes) -> tuple[bytes, bytes]:
    body = receipt_raw[:-64]
    decision_length = int.from_bytes(body[532:536], "big")
    cursor = 532 + 4 + decision_length + 4
    rows: list[bytes] = []
    for _ in range(2):
        length = int.from_bytes(body[cursor : cursor + 4], "big")
        cursor += 4
        rows.append(bytes(body[cursor : cursor + length]))
        cursor += length
    return rows[0], rows[1]


def _replace_access_rows(raw: bytes, rows: tuple[bytes, bytes]) -> bytes:
    parts = _split_bundle(raw)
    body = bytearray(parts[0][:-64])
    decision_length = int.from_bytes(body[532:536], "big")
    cursor = 532 + 4 + decision_length + 4
    for row in rows:
        length = int.from_bytes(body[cursor : cursor + 4], "big")
        cursor += 4
        assert len(row) == length
        body[cursor : cursor + length] = row
        cursor += length
    parts[0] = _rebind_receipt(bytes(body) + b"\0" * 64)
    return _join_bundle(parts)


def _replace_decision(raw: bytes, decision: bytes) -> bytes:
    parts = _split_bundle(raw)
    body = bytearray(parts[0][:-64])
    decision_length = int.from_bytes(body[532:536], "big")
    assert len(decision) == decision_length
    body[536 : 536 + decision_length] = decision
    parts[0] = _rebind_receipt(bytes(body) + b"\0" * 64)
    return _join_bundle(parts)


def _mutate_access(
    raw: bytes,
    access_index: int,
    field_offset: int,
    value: bytes | int,
) -> bytes:
    rows = list(_access_rows(_split_bundle(raw)[0]))
    row = bytearray(rows[access_index])
    if isinstance(value, int):
        row[field_offset] = value
    else:
        row[field_offset : field_offset + len(value)] = value
    rows[access_index] = bytes(row)
    return _replace_access_rows(raw, (rows[0], rows[1]))


def _set_access_field(row: bytes, offset: int, value: bytes) -> bytes:
    mutated = bytearray(row)
    mutated[offset : offset + len(value)] = value
    return bytes(mutated)


def _role_write(row: bytes) -> bytes:
    return _set_access_field(
        _set_access_field(
            row,
            352,
            bytes((ACCESS_WRITE,)),
        ),
        288,
        b"\xA5" * 64,
    )


def _role_read(row: bytes) -> bytes:
    return _set_access_field(
        _set_access_field(
            row,
            352,
            bytes((ACCESS_READ,)),
        ),
        288,
        row[224:288],
    )


def _direct_count(path: Path) -> int:
    with sqlite3.connect(path) as connection:
        return int(
            connection.execute(
                "SELECT COUNT(*) FROM direct_clearance_requests"
            ).fetchone()[0]
        )


def _direct_state_values(path: Path) -> tuple[bytes, int, bytes, int, int, str]:
    with sqlite3.connect(path) as connection:
        state = connection.execute(
            "SELECT strong_payment_state_root, settled_batch_count, sequence "
            "FROM state WHERE id=1"
        ).fetchone()
        direct = connection.execute(
            "SELECT clearance_root, direct_clearance_count, payment_root, "
            "settled_batch_count, sequence FROM direct_clearance_state WHERE id=1"
        ).fetchone()
        transition = connection.execute(
            "SELECT transition_kind FROM transition_records WHERE sequence_after=1"
        ).fetchone()
    assert state is not None and direct is not None and transition is not None
    return (
        bytes(state[0]),
        int(state[1]),
        bytes(direct[0]),
        int(direct[1]),
        int(direct[3]),
        str(transition[0]),
    )


def _make_v3_direct_only_fixture(path: Path) -> bytes:
    """Build a direct-only schema-3 image for the intentional clean-break gate."""

    current = DirectStateOwnedAtomicClearanceV1(path=path)
    current.close()
    with closing(sqlite3.connect(path)) as connection:
        metadata_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='metadata'"
        ).fetchone()
        assert metadata_sql is not None
        sql = str(metadata_sql[0])
        old_clause = "schema_version INTEGER NOT NULL CHECK (schema_version = 4)"
        new_clause = "schema_version INTEGER NOT NULL CHECK (schema_version = 3)"
        assert sql.count(old_clause) == 1
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "UPDATE sqlite_master SET sql=? WHERE type='table' AND name='metadata'",
            (sql.replace(old_clause, new_clause),),
        )
        connection.execute("PRAGMA writable_schema=OFF")
        connection.commit()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("UPDATE metadata SET schema_version=3 WHERE id=1")
        connection.commit()
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
    with closing(sqlite3.connect(path, isolation_level=None)) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        assert connection.execute("PRAGMA journal_mode=DELETE").fetchone() == ("delete",)
    assert tables == {
        "audit_events",
        "configuration",
        "database_genesis",
        "direct_clearance_requests",
        "direct_clearance_state",
        "governance_authorities",
        "metadata",
        "state",
        "transition_records",
    }
    assert not any(
        Path(f"{path}{suffix}").exists()
        for suffix in ("-wal", "-shm", "-journal")
    )
    return path.read_bytes()


def test_schema_v3_clean_break_rejects_without_mutation(tmp_path: Path) -> None:
    v3_path = tmp_path / "schema-v3.sqlite3"
    v3_before = _make_v3_direct_only_fixture(v3_path)

    with pytest.raises(ProductionBoundaryError, match="database_schema_version_mismatch"):
        DirectStateOwnedAtomicClearanceV1(path=v3_path)
    assert v3_path.read_bytes() == v3_before
    assert not any(
        Path(f"{v3_path}{suffix}").exists()
        for suffix in ("-wal", "-shm", "-journal")
    )

    backup_path = tmp_path / "schema-v3-backup.sqlite3"
    shutil.copyfile(v3_path, backup_path)
    backup_before = backup_path.read_bytes()
    recovered_path = tmp_path / "schema-v3-recovered.sqlite3"
    current_v4 = DirectStateOwnedAtomicClearanceV1(
        path=tmp_path / "schema-v4-source.sqlite3"
    )
    with pytest.raises(ProductionBoundaryError, match="database_schema_version_mismatch"):
        current_v4.recover_from_backup(
            backup_path=backup_path,
            recovered_path=recovered_path,
        )
    current_v4.close()
    assert backup_path.read_bytes() == backup_before
    assert not recovered_path.exists()
    assert not any(
        Path(f"{recovered_path}{suffix}").exists()
        for suffix in ("-wal", "-shm", "-journal")
    )


def _tamper_direct_state(path: Path, field: str) -> None:
    assert field in {"clearance_root", "direct_clearance_count"}
    with sqlite3.connect(path) as connection:
        if field == "clearance_root":
            connection.execute(
                "UPDATE direct_clearance_state SET clearance_root=? WHERE id=1",
                (sqlite3.Binary(b"\xA5" * 64),),
            )
        else:
            connection.execute(
                "UPDATE direct_clearance_state SET direct_clearance_count=9 WHERE id=1"
            )


def _tamper_direct_continuity_before(path: Path) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "DROP TRIGGER direct_clearance_requests_no_update"
            )
            record = connection.execute(
                "SELECT * FROM direct_clearance_requests WHERE sequence_after=2"
            ).fetchone()
            assert record is not None
            operation = database_boundary_module._direct_operation_from_record(
                tuple(record[:41])
            )
            before_audit_head = b"\xA9" * 64
            before_root = b"\xB8" * 64
            before_state_id = database_boundary_module._direct_continuity_state_id(
                profile_id=operation.profile_id,
                mode_id=operation.mode_id,
                sequence=operation.continuity_sequence_before,
                row_count=operation.continuity_sequence_before,
                audit_head=before_audit_head,
                continuity_root=before_root,
            )
            after_audit_head = database_boundary_module._direct_continuity_sha(
                database_boundary_module._DIRECT_CONTINUITY_AUDIT_HEAD_DOMAIN,
                before_audit_head,
                operation.decision_id,
                bytes((operation.effective_directive,)),
            )
            after_root = database_boundary_module._direct_continuity_sha(
                database_boundary_module._DIRECT_CONTINUITY_ROOT_DOMAIN,
                before_root,
                operation.source_root,
                operation.decision_id,
            )
            after_state_id = database_boundary_module._direct_continuity_state_id(
                profile_id=operation.profile_id,
                mode_id=operation.mode_id,
                sequence=operation.continuity_sequence_after,
                row_count=operation.continuity_sequence_after,
                audit_head=after_audit_head,
                continuity_root=after_root,
            )
            tampered_operation = replace(
                operation,
                continuity_before_state_id=before_state_id,
                continuity_after_state_id=after_state_id,
                continuity_before_audit_head=before_audit_head,
                continuity_after_audit_head=after_audit_head,
                continuity_before_root=before_root,
                continuity_after_root=after_root,
            )
            operation_digest = database_boundary_module._direct_operation_digest(
                tampered_operation
            )
            cursor = connection.execute(
                "UPDATE direct_clearance_requests SET operation_digest=?, "
                "continuity_before_state_id=?, continuity_after_state_id=?, "
                "continuity_before_audit_head=?, continuity_after_audit_head=?, "
                "continuity_before_root=?, continuity_after_root=? "
                "WHERE sequence_after=2",
                (
                    operation_digest,
                    before_state_id,
                    after_state_id,
                    before_audit_head,
                    after_audit_head,
                    before_root,
                    after_root,
                ),
            )
            assert cursor.rowcount == 1
            tampered_record = connection.execute(
                "SELECT * FROM direct_clearance_requests WHERE sequence_after=2"
            ).fetchone()
            assert tampered_record is not None
            assert database_boundary_module._direct_operation_from_record(
                tuple(tampered_record[:41])
            ) == tampered_operation
        finally:
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS direct_clearance_requests_no_update "
                "BEFORE UPDATE ON direct_clearance_requests "
                "BEGIN SELECT RAISE(ABORT, "
                "'direct_clearance_requests_append_only'); END"
            )
        connection.commit()


def _operation_namespace_with_changes(
    operation: object,
    **changes: object,
) -> SimpleNamespace:
    values = {item.name: getattr(operation, item.name) for item in fields(operation)}
    values.update(changes)
    return SimpleNamespace(**values)


def _direct_continuity_after(
    operation: object,
    *,
    before_audit_head: bytes,
    before_root: bytes,
) -> tuple[bytes, bytes, bytes]:
    after_audit_head = database_boundary_module._direct_continuity_sha(
        database_boundary_module._DIRECT_CONTINUITY_AUDIT_HEAD_DOMAIN,
        before_audit_head,
        operation.decision_id,
        bytes((operation.effective_directive,)),
    )
    after_root = database_boundary_module._direct_continuity_sha(
        database_boundary_module._DIRECT_CONTINUITY_ROOT_DOMAIN,
        before_root,
        operation.source_root,
        operation.decision_id,
    )
    after_state_id = database_boundary_module._direct_continuity_state_id(
        profile_id=operation.profile_id,
        mode_id=operation.mode_id,
        sequence=operation.continuity_sequence_after,
        row_count=operation.continuity_sequence_after,
        audit_head=after_audit_head,
        continuity_root=after_root,
    )
    return after_state_id, after_audit_head, after_root


def _tamper_direct_continuity_transition_edge_and_relink_successor(
    path: Path,
) -> None:
    with closing(sqlite3.connect(path, isolation_level=None)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "DROP TRIGGER direct_clearance_requests_no_update"
            )
            records = connection.execute(
                "SELECT * FROM direct_clearance_requests "
                "WHERE sequence_after IN (1, 2) ORDER BY sequence_after"
            ).fetchall()
            assert len(records) == 2
            first = database_boundary_module._direct_operation_from_record(
                tuple(records[0][:41])
            )
            second = database_boundary_module._direct_operation_from_record(
                tuple(records[1][:41])
            )

            tampered_after_state_id = b"\xC3" * 64
            tampered_after_audit_head = b"\xC4" * 64
            tampered_after_root = b"\xC5" * 64
            first_changed = _operation_namespace_with_changes(
                first,
                continuity_after_state_id=tampered_after_state_id,
                continuity_after_audit_head=tampered_after_audit_head,
                continuity_after_root=tampered_after_root,
            )
            first_digest = database_boundary_module._direct_operation_digest(
                first_changed
            )
            first_update = connection.execute(
                "UPDATE direct_clearance_requests SET operation_digest=?, "
                "continuity_after_state_id=?, continuity_after_audit_head=?, "
                "continuity_after_root=? WHERE sequence_after=1",
                (
                    first_digest,
                    tampered_after_state_id,
                    tampered_after_audit_head,
                    tampered_after_root,
                ),
            )
            assert first_update.rowcount == 1

            (
                successor_after_state_id,
                successor_after_audit_head,
                successor_after_root,
            ) = _direct_continuity_after(
                second,
                before_audit_head=tampered_after_audit_head,
                before_root=tampered_after_root,
            )
            second_changed = _operation_namespace_with_changes(
                second,
                continuity_before_state_id=tampered_after_state_id,
                continuity_before_audit_head=tampered_after_audit_head,
                continuity_before_root=tampered_after_root,
                continuity_after_state_id=successor_after_state_id,
                continuity_after_audit_head=successor_after_audit_head,
                continuity_after_root=successor_after_root,
            )
            second_digest = database_boundary_module._direct_operation_digest(
                second_changed
            )
            second_update = connection.execute(
                "UPDATE direct_clearance_requests SET operation_digest=?, "
                "continuity_before_state_id=?, continuity_after_state_id=?, "
                "continuity_before_audit_head=?, continuity_after_audit_head=?, "
                "continuity_before_root=?, continuity_after_root=? "
                "WHERE sequence_after=2",
                (
                    second_digest,
                    tampered_after_state_id,
                    successor_after_state_id,
                    tampered_after_audit_head,
                    successor_after_audit_head,
                    tampered_after_root,
                    successor_after_root,
                ),
            )
            assert second_update.rowcount == 1
            successor = connection.execute(
                "SELECT continuity_before_state_id, continuity_before_audit_head, "
                "continuity_before_root, continuity_after_state_id, "
                "continuity_after_audit_head, continuity_after_root "
                "FROM direct_clearance_requests WHERE sequence_after=2"
            ).fetchone()
            assert successor == (
                tampered_after_state_id,
                tampered_after_audit_head,
                tampered_after_root,
                successor_after_state_id,
                successor_after_audit_head,
                successor_after_root,
            )
        finally:
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS direct_clearance_requests_no_update "
                "BEFORE UPDATE ON direct_clearance_requests "
                "BEGIN SELECT RAISE(ABORT, "
                "'direct_clearance_requests_append_only'); END"
            )
        connection.commit()


def _tamper_transition_kind(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER transition_records_no_update")
        connection.execute("PRAGMA ignore_check_constraints=ON")
        try:
            connection.execute(
                "UPDATE transition_records SET transition_kind='SETTLEMENT' "
                "WHERE sequence_after=1"
            )
        finally:
            connection.execute("PRAGMA ignore_check_constraints=OFF")


class _FinalizeFailureAnchor:
    def __init__(self) -> None:
        self.delegate = InMemoryAntiRollbackReference()
        self.fail_finalize = True
        self.lock = Lock()

    def snapshot(self) -> AntiRollbackAnchorSnapshot | None:
        return self.delegate.snapshot()

    def initialize(self, epoch: int, state_binding: bytes) -> None:
        self.delegate.initialize(epoch, state_binding)

    def prepare(
        self,
        *,
        expected_epoch: int,
        expected_state_binding: bytes,
        next_epoch: int,
        next_state_binding: bytes,
        transition_commitment: bytes,
    ) -> None:
        self.delegate.prepare(
            expected_epoch=expected_epoch,
            expected_state_binding=expected_state_binding,
            next_epoch=next_epoch,
            next_state_binding=next_state_binding,
            transition_commitment=transition_commitment,
        )

    def finalize(
        self,
        *,
        next_epoch: int,
        next_state_binding: bytes,
        transition_commitment: bytes,
    ) -> None:
        with self.lock:
            if self.fail_finalize:
                raise RuntimeError("injected_direct_finalize_failure")
        self.delegate.finalize(
            next_epoch=next_epoch,
            next_state_binding=next_state_binding,
            transition_commitment=transition_commitment,
        )


def test_all_five_directives_and_exception_sentinel(tmp_path: Path) -> None:
    observed: set[int] = set()
    for index, name in enumerate(DEMO_CASES):
        raw, request, _, _, producer_receipt = _case(name)
        service = DirectStateOwnedAtomicClearanceV1(
            path=tmp_path / f"case-{index}.sqlite3"
        )
        result = service.submit(raw)
        details = parse_bundle_details(raw)
        payment_root, settled_count, clearance_root, clearance_count, direct_settled_count, transition_kind = _direct_state_values(service.path)
        observed.add(result.effective_directive)
        assert result.bundle_id == details.bundle_id
        assert result.receipt_id != b"\x00" * 64
        assert result.request_id != b"\x00" * 64
        assert result.proof_suite_id is None
        assert result.proof_session_accepted is False
        assert result.economic_mutation is False
        assert payment_root == DIRECT_INITIAL_PAYMENT_ROOT
        assert result.payment_root_before == DIRECT_INITIAL_PAYMENT_ROOT
        assert result.payment_root_after == DIRECT_INITIAL_PAYMENT_ROOT
        assert result.clearance_root_before == DIRECT_INITIAL_CLEARANCE_ROOT
        assert settled_count == 0
        assert direct_settled_count == 0
        assert result.settled_batch_count_before == 0
        assert result.settled_batch_count_after == 0
        assert clearance_count == 1
        assert result.clearance_count_before == 0
        assert result.clearance_count_after == 1
        assert result.clearance_root_after == clearance_root
        assert transition_kind == "DIRECT_CLEARANCE"
        assert result.clearance_advanced == (
            result.effective_directive in (DIRECTIVE_CLEAR, DIRECTIVE_EXCEPTION_APPROVED)
        )
        if result.clearance_advanced:
            assert result.clearance_root_after != result.clearance_root_before
        else:
            assert result.clearance_root_after == result.clearance_root_before
        if name == "governed-exception":
            assert details.decision["exception_id"] != NO_EXCEPTION_SENTINEL
        else:
            assert details.decision["exception_id"] == NO_EXCEPTION_SENTINEL
        service.verify_integrity()
        service.close()
    assert observed == {
        DIRECTIVE_CLEAR,
        DIRECTIVE_HOLD,
        DIRECTIVE_HUMAN_REVIEW,
        DIRECTIVE_BLOCK,
        DIRECTIVE_EXCEPTION_APPROVED,
    }


def test_deterministic_parse_serialize_and_exact_retry(tmp_path: Path) -> None:
    raw_one, request, facts, completeness, receipt_one = _case("valid-continuity")
    raw_two, _, facts_two, completeness_two, receipt_two = _case("valid-continuity")
    assert receipt_one.canonical_bytes() == receipt_two.canonical_bytes()
    assert receipt_one.join_id == receipt_two.join_id
    assert raw_one == raw_two
    parsed_receipt = ContinuityReceipt.parse(
        receipt_one.canonical_bytes(),
        before_state=receipt_one.before_state,
        after_state=receipt_one.after_state,
        request=request,
        exception_authorization=None,
    )
    assert parsed_receipt.canonical_bytes() == receipt_one.canonical_bytes()
    assert bundle_bytes(parsed_receipt, facts, completeness) == bundle_bytes(
        receipt_two,
        facts_two,
        completeness_two,
    )
    details = parse_bundle_details(raw_one)
    assert parse_bundle(raw_one)["receipt_id"] == details.receipt_id.hex()

    service = DirectStateOwnedAtomicClearanceV1(path=tmp_path / "retry.sqlite3")
    first = service.submit(raw_one)
    second = service.submit(raw_two)
    assert second == first
    payment_root, settled_count, _, clearance_count, direct_settled_count, transition_kind = _direct_state_values(service.path)
    assert payment_root == DIRECT_INITIAL_PAYMENT_ROOT
    assert settled_count == 0
    assert direct_settled_count == 0
    assert clearance_count == 1
    assert transition_kind == "DIRECT_CLEARANCE"
    assert service.snapshot().sequence == 1
    service.verify_integrity()

    fresh_service = DirectStateOwnedAtomicClearanceV1(
        path=tmp_path / "fresh-rebuild.sqlite3"
    )
    fresh = fresh_service.submit(raw_two)
    assert fresh == first
    assert fresh_service.snapshot() == service.snapshot()
    assert fresh_service.clearance_snapshot() == service.clearance_snapshot()
    fresh_service.verify_integrity()
    fresh_service.close()
    service.close()


def test_state_kernel_advances_revision_and_replays_historical_receipt(
    tmp_path: Path,
) -> None:
    first_raw, _, _, _, _ = _case("valid-continuity")
    second_raw, _, _, _, _ = _case("expired-credential")
    service = DirectStateOwnedAtomicClearanceV1(path=tmp_path / "stateful-revision.sqlite3")

    first = service.submit(first_raw)
    second = service.submit(second_raw, expected_revision=1)
    assert first.sequence_before == 0 and first.sequence_after == 1
    assert second.sequence_before == 1 and second.sequence_after == 2
    assert second.effective_directive == DIRECTIVE_BLOCK
    assert service.snapshot().sequence == 2
    assert service.clearance_snapshot().sequence == 2

    historical_retry = service.submit(first_raw, expected_revision=0)
    assert historical_retry == first
    assert service.snapshot().sequence == 2
    service.verify_integrity()
    service.close()


def test_state_kernel_request_wire_is_exact_and_command_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw, _, _, _, _ = _case("valid-continuity")
    semantic_kernel = _StateRequestCaptureKernel()
    _install_test_semantic_kernel(monkeypatch, semantic_kernel)
    service = DirectStateOwnedAtomicClearanceV1(
        path=tmp_path / "state-request-wire.sqlite3",
    )
    first_receipt = service.submit(raw)
    details = parse_bundle_details(raw)
    request = semantic_kernel.request
    assert request is not None
    state_result = semantic_kernel.result
    assert state_result is not None
    adapter_output = _encode_state_kernel_result(state_result)
    assert parse_state_kernel_adapter_output(adapter_output) == state_result
    malformed_result = adapter_output.replace(
        b";attempt_id=" + state_result.attempt_id.hex().encode("ascii"),
        b";attempt_id=00",
        1,
    )
    with pytest.raises(
        SemanticKernelBindingError,
        match="semantic_kernel_field:attempt_id",
    ):
        parse_state_kernel_adapter_output(malformed_result)
    encoded = request.encode()
    expected_length = (
        16
        + len(raw)
        + 64
        + 8
        + 9 * 64
        + 3 * 8
        + 4 * 64
        + 3 * 8
        + 6 * 64
        + 2 * 8
        + 3 * 64
        + 4
    )
    assert len(encoded) == expected_length
    assert encoded[:12] == b"BLSDRQ01\x00\x01\x00\x00"
    assert int.from_bytes(encoded[12:16], "big") == len(raw)
    assert encoded[16 : 16 + len(raw)] == raw
    assert parse_state_kernel_request(encoded) == request
    assert request.input_sha3_512 == hashlib.sha3_512(
        b"BL/DIRECT-STATE-OWNED/STATE-INPUT/v1\x00" + encoded
    ).digest()
    assert (
        details.request["rule_effective_time"]
        < details.request["event_time"]
        < details.request["observation_time"]
        < details.request["decision_time"]
    )

    replay_receipt = service.submit(raw, expected_revision=0)
    assert replay_receipt == first_receipt
    replay_request = semantic_kernel.request
    assert replay_request is not None and replay_request.prior_operation is not None
    replay_encoded = replay_request.encode()
    assert len(replay_encoded) == expected_length + 1 + 1 + 64 + 16 * 64 + 9 * 8 + 6 * 64
    assert int.from_bytes(replay_encoded[-1550:-1546], "big") == 1546
    assert parse_state_kernel_request(replay_encoded) == replay_request

    malformed_magic = bytearray(encoded)
    malformed_magic[0] ^= 1
    with pytest.raises(SemanticKernelBindingError, match="state_kernel_request_magic"):
        parse_state_kernel_request(bytes(malformed_magic))
    malformed_version = bytearray(encoded)
    malformed_version[9] = 2
    with pytest.raises(SemanticKernelBindingError, match="state_kernel_request_version"):
        parse_state_kernel_request(bytes(malformed_version))
    with pytest.raises(
        SemanticKernelBindingError,
        match="state_kernel_request_trailing_bytes",
    ):
        parse_state_kernel_request(encoded + b"\x00")
    service.close()


def test_state_kernel_command_must_match_authenticated_attempt(tmp_path: Path) -> None:
    raw, _, _, _, _ = _case("valid-continuity")
    service = DirectStateOwnedAtomicClearanceV1(
        path=tmp_path / "state-command-attempt.sqlite3",
    )
    before = service.snapshot()
    with pytest.raises(
        DirectStateOwnedClearanceError,
        match="state_kernel_evidence_binding:attempt_id",
    ):
        service.submit(raw, expected_revision=0, command_id=b"\xA7" * 64)
    assert service.snapshot() == before
    assert _direct_count(service.path) == 0
    service.verify_integrity()
    service.close()


def test_changed_command_identity_conflicts_with_exact_retry_record(
    tmp_path: Path,
) -> None:
    raw, _, _, _, _ = _case("valid-continuity")
    service = DirectStateOwnedAtomicClearanceV1(path=tmp_path / "command-conflict.sqlite3")
    service.submit(raw)
    before = service.snapshot()
    with pytest.raises(
        ProductionBoundaryError,
        match="database_direct_conflicting_retry",
    ):
        service.submit(raw, expected_revision=0, command_id=b"\xA7" * 64)
    assert service.snapshot() == before
    assert _direct_count(service.path) == 1
    service.verify_integrity()
    service.close()


def _mutated_access_cases(raw: bytes) -> tuple[tuple[str, bytes, str], ...]:
    read, write = _access_rows(_split_bundle(raw)[0])
    coherent_swap = (
        _set_access_field(write, 80, (0).to_bytes(4, "big")),
        _set_access_field(read, 80, (1).to_bytes(4, "big")),
    )
    return (
        ("coherent-access-row-swap", _replace_access_rows(raw, coherent_swap), "access:read"),
        ("write-write-role-confusion", _replace_access_rows(raw, (_role_write(read), write)), "access:read"),
        ("read-read-role-confusion", _replace_access_rows(raw, (read, _role_read(write))), "access:write"),
        ("unknown-role", _mutate_access(raw, 0, 352, 9), "access:mode"),
        ("wrong-access-index", _mutate_access(raw, 0, 80, (1).to_bytes(4, "big")), "join:order-or-decision"),
        ("wrong-access-count", _mutate_access(raw, 0, 84, (3).to_bytes(4, "big")), "access:shape"),
        ("wrong-decision-index", _mutate_access(raw, 0, 76, (1).to_bytes(4, "big")), "access:shape"),
        ("wrong-access-decision-id", _mutate_access(raw, 0, 12, b"\xA5" * 64), "join:order-or-decision"),
        ("wrong-write-before", _mutate_access(raw, 1, 224, b"\xA5" * 64), "access:write"),
        ("wrong-write-after", _mutate_access(raw, 1, 288, b"\xA5" * 64), "access:write"),
        ("read-at-decision", _mutate_access(raw, 0, 88, (7002).to_bytes(8, "big")), "access:read"),
        ("write-at-observation", _mutate_access(raw, 1, 88, (7001).to_bytes(8, "big")), "access:write"),
    )


@pytest.mark.parametrize("label,mutated,error", _mutated_access_cases(_case("valid-continuity")[0]))
def test_rebound_raw_semantic_mutations_fail_before_database_mutation(
    tmp_path: Path,
    label: str,
    mutated: bytes,
    error: str,
) -> None:
    with pytest.raises(IndependentParseError, match=error):
        parse_bundle_details(mutated)
    service = DirectStateOwnedAtomicClearanceV1(path=tmp_path / f"{label}.sqlite3")
    before = service.snapshot()
    with pytest.raises(DirectStateOwnedClearanceError, match="direct_independent_reject"):
        service.submit(mutated)
    assert service.snapshot() == before
    assert _direct_count(service.path) == 0
    service.verify_integrity()


def _mutated_authority_cases(raw: bytes) -> tuple[tuple[str, bytes, str], ...]:
    parts = _split_bundle(raw)
    body = parts[0][:-64]

    def receipt_byte(offset: int, value: bytes) -> bytes:
        mutated = bytearray(body)
        mutated[offset : offset + len(value)] = value
        return _join_bundle([_rebind_receipt(bytes(mutated) + b"\0" * 64)] + parts[1:])

    facts = bytearray(parts[2])
    facts[12] ^= 1
    return (
        ("mode-downgrade", receipt_byte(15, b"\x02"), "receipt:profile-or-mutation"),
        ("proof-suite-substitution", receipt_byte(20, b"\xA5"), "receipt:profile-or-mutation"),
        ("cross-profile-adapter", receipt_byte(84, b"\xA5"), "adapter:binding"),
        ("control-substitution", receipt_byte(148, b"\xA5"), "receipt:decision-binding"),
        ("source-substitution", _join_bundle(parts[:2] + [bytes(facts)] + parts[3:]), "fact-set:synthetic-feed"),
    )


@pytest.mark.parametrize("label,mutated,error", _mutated_authority_cases(_case("valid-continuity")[0]))
def test_rebound_authority_and_downgrade_mutations_are_rejected(
    tmp_path: Path,
    label: str,
    mutated: bytes,
    error: str,
) -> None:
    with pytest.raises(IndependentParseError, match=error):
        parse_bundle_details(mutated)
    service = DirectStateOwnedAtomicClearanceV1(path=tmp_path / f"{label}.sqlite3")
    with pytest.raises(DirectStateOwnedClearanceError, match="direct_independent_reject"):
        service.submit(mutated)
    assert service.snapshot().sequence == 0
    assert _direct_count(service.path) == 0


def test_conflicting_retry_stale_state_and_unsealed_operation_are_fail_closed(
    tmp_path: Path,
) -> None:
    raw, request, _, _, _ = _case("valid-continuity")
    expired_raw, expired_request, expired_facts, _, _ = _case("expired-credential")
    conflict_request = replace(expired_request, attempt_id=request.attempt_id)
    conflict_completeness = make_completeness(conflict_request, expired_facts, complete=True)
    conflict_receipt = ContinuityStore().apply(
        conflict_request,
        expired_facts,
        conflict_completeness,
    )
    conflicting_raw = bundle_bytes(conflict_receipt, expired_facts, conflict_completeness)
    service = DirectStateOwnedAtomicClearanceV1(path=tmp_path / "retry-conflict.sqlite3")
    first = service.submit(raw)
    before = service.snapshot()
    with pytest.raises(ProductionBoundaryError, match="database_direct_conflicting_retry"):
        service.submit(conflicting_raw)
    assert service.snapshot() == before
    with pytest.raises(DirectStateOwnedClearanceError, match="state_kernel_stale_revision"):
        service.submit(expired_raw)
    assert service.snapshot() == before
    with pytest.raises(ProductionBoundaryError, match="database_direct_prepare_result_invalid"):
        details = parse_bundle_details(expired_raw)
        service.database._commit_direct_state_owned(
            lambda context: object(),
            retry_lookup_ids=(
                ("bundle_id", details.bundle_id),
                ("attempt_id", details.request["attempt_id"]),
            ),
        )
    assert service.snapshot() == before
    assert service.submit(raw) == first


def test_concurrent_exact_retry_converges_and_competing_transition_loses(
    tmp_path: Path,
) -> None:
    raw, _, _, _, _ = _case("valid-continuity")
    same_path = tmp_path / "same-concurrent.sqlite3"
    services = [DirectStateOwnedAtomicClearanceV1(path=same_path) for _ in range(2)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda service: service.submit(raw), services))
    assert results[0] == results[1]
    assert services[0].snapshot().sequence == 1
    for service in services:
        service.verify_integrity()

    competing_raw, _, _, _, _ = _case("expired-credential")
    compete_path = tmp_path / "competing.sqlite3"
    competing_services = [
        DirectStateOwnedAtomicClearanceV1(path=compete_path) for _ in range(2)
    ]

    def submit_competing(index: int):
        try:
            return ("ok", competing_services[index].submit((raw, competing_raw)[index]))
        except Exception as exc:
            return ("error", exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(submit_competing, (0, 1)))
    assert sum(kind == "ok" for kind, _ in outcomes) == 1
    errors = [value for kind, value in outcomes if kind == "error"]
    assert len(errors) == 1
    assert isinstance(errors[0], DirectStateOwnedClearanceError)
    assert "state_kernel_stale_revision" in str(errors[0])
    assert competing_services[0].snapshot().sequence == 1
    competing_services[0].verify_integrity()


def test_before_commit_failure_rolls_back_and_restart_retries(
    tmp_path: Path,
) -> None:
    raw, _, _, _, _ = _case("valid-continuity")

    def fail_before_commit() -> None:
        raise RuntimeError("injected_direct_before_commit_failure")

    path = tmp_path / "rollback.sqlite3"
    failing = DirectStateOwnedAtomicClearanceV1(
        path=path,
        before_commit_hook=fail_before_commit,
    )
    with pytest.raises(RuntimeError, match="injected_direct_before_commit_failure"):
        failing.submit(raw)
    assert failing.snapshot().sequence == 0
    assert _direct_count(path) == 0
    failing.close()

    restarted = DirectStateOwnedAtomicClearanceV1(path=path)
    result = restarted.submit(raw)
    assert result.sequence_after == 1
    restarted.verify_integrity()


def test_after_commit_indeterminate_resolves_by_exact_retry(tmp_path: Path) -> None:
    raw, _, _, _, _ = _case("valid-continuity")
    anchor = _FinalizeFailureAnchor()
    path = tmp_path / "indeterminate.sqlite3"
    service = DirectStateOwnedAtomicClearanceV1(path=path, anti_rollback=anchor)
    with pytest.raises(
        ProductionBoundaryError,
        match="database_direct_transition_committed_anchor_pending",
    ):
        service.submit(raw)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT sequence FROM state WHERE id=1").fetchone() == (1,)
    assert anchor.snapshot() is not None and anchor.snapshot().pending is not None
    service.close()

    anchor.fail_finalize = False
    restarted = DirectStateOwnedAtomicClearanceV1(path=path, anti_rollback=anchor)
    result = restarted.submit(raw)
    assert result.sequence_after == 1
    assert anchor.snapshot() is not None
    assert anchor.snapshot().pending is None
    restarted.verify_integrity()


def test_backup_restore_preserves_direct_identity_and_retry(tmp_path: Path) -> None:
    raw, _, _, _, _ = _case("governed-exception")
    path = tmp_path / "source.sqlite3"
    backup = tmp_path / "backup.sqlite3"
    restored_path = tmp_path / "restored.sqlite3"
    service = DirectStateOwnedAtomicClearanceV1(path=path)
    committed = service.submit(raw)
    service.create_backup(backup)
    service.close()

    recovery_source = DirectStateOwnedAtomicClearanceV1(path=path)
    recovered = recovery_source.recover_from_backup(
        backup_path=backup,
        recovered_path=restored_path,
    )
    retry = recovered.submit(raw)
    assert retry == committed
    assert recovered.snapshot().sequence == 1
    recovered.verify_integrity()


@pytest.mark.parametrize("field", ("clearance_root", "direct_clearance_count"))
def test_direct_clearance_state_corruption_fails_verify_restart_and_backup(
    tmp_path: Path,
    field: str,
) -> None:
    raw, _, _, _, _ = _case("valid-continuity")

    verify_path = tmp_path / f"verify-{field}.sqlite3"
    verifying = DirectStateOwnedAtomicClearanceV1(path=verify_path)
    verifying.submit(raw)
    _tamper_direct_state(verify_path, field)
    with pytest.raises(ProductionBoundaryError):
        verifying.verify_integrity()
    verifying.close()

    restart_path = tmp_path / f"restart-{field}.sqlite3"
    restarting = DirectStateOwnedAtomicClearanceV1(path=restart_path)
    restarting.submit(raw)
    restarting.close()
    _tamper_direct_state(restart_path, field)
    with pytest.raises(ProductionBoundaryError):
        DirectStateOwnedAtomicClearanceV1(path=restart_path)

    source_path = tmp_path / f"backup-source-{field}.sqlite3"
    backup_path = tmp_path / f"backup-{field}.sqlite3"
    restored_path = tmp_path / f"restored-{field}.sqlite3"
    source = DirectStateOwnedAtomicClearanceV1(path=source_path)
    source.submit(raw)
    source.create_backup(backup_path)
    source.close()
    _tamper_direct_state(backup_path, field)
    recovery_source = DirectStateOwnedAtomicClearanceV1(path=source_path)
    with pytest.raises(ProductionBoundaryError):
        recovery_source.recover_from_backup(
            backup_path=backup_path,
            recovered_path=restored_path,
        )
    recovery_source.close()


@pytest.mark.parametrize("surface", ("verify", "reopen", "backup"))
def test_direct_continuity_before_chain_corruption_fails_closed(
    tmp_path: Path,
    surface: str,
) -> None:
    first_raw, _, _, _, _ = _case("valid-continuity")
    second_raw, _, _, _, _ = _case("expired-credential")

    if surface == "verify":
        path = tmp_path / "verify-continuity-chain.sqlite3"
        service = DirectStateOwnedAtomicClearanceV1(path=path)
        service.submit(first_raw)
        service.submit(second_raw, expected_revision=1)
        _tamper_direct_continuity_before(path)
        with pytest.raises(
            ProductionBoundaryError,
            match="database_direct_continuity_chain_broken",
        ):
            service.verify_integrity()
        service.close()
    elif surface == "reopen":
        path = tmp_path / "reopen-continuity-chain.sqlite3"
        service = DirectStateOwnedAtomicClearanceV1(path=path)
        service.submit(first_raw)
        service.submit(second_raw, expected_revision=1)
        service.close()
        _tamper_direct_continuity_before(path)
        with pytest.raises(
            ProductionBoundaryError,
            match="database_direct_continuity_chain_broken",
        ):
            DirectStateOwnedAtomicClearanceV1(path=path)
    else:
        source_path = tmp_path / "backup-source-continuity-chain.sqlite3"
        backup_path = tmp_path / "backup-continuity-chain.sqlite3"
        recovered_path = tmp_path / "recovered-continuity-chain.sqlite3"
        source = DirectStateOwnedAtomicClearanceV1(path=source_path)
        source.submit(first_raw)
        source.submit(second_raw, expected_revision=1)
        source.create_backup(backup_path)
        source.close()
        _tamper_direct_continuity_before(backup_path)
        recovery_source = DirectStateOwnedAtomicClearanceV1(path=source_path)
        with pytest.raises(
            ProductionBoundaryError,
            match="database_direct_continuity_chain_broken",
        ):
            recovery_source.recover_from_backup(
                backup_path=backup_path,
                recovered_path=recovered_path,
            )
        recovery_source.close()
        assert not recovered_path.exists()


def test_direct_continuity_transition_corruption_rejected_with_relinked_successor(
    tmp_path: Path,
) -> None:
    """Reject a bad older transition after rehashing and relinking its successor."""

    first_raw, _, _, _, _ = _case("valid-continuity")
    second_raw, _, _, _, _ = _case("expired-credential")
    path = tmp_path / "continuity-transition-relinked-successor.sqlite3"
    service = DirectStateOwnedAtomicClearanceV1(path=path)
    try:
        service.submit(first_raw)
        service.submit(second_raw, expected_revision=1)
        _tamper_direct_continuity_transition_edge_and_relink_successor(path)
        with pytest.raises(
            ProductionBoundaryError,
            match="database_direct_continuity_transition_mismatch",
        ):
            service.verify_integrity()
    finally:
        service.close()


def test_direct_transition_kind_substitution_fails_closed(tmp_path: Path) -> None:
    raw, _, _, _, _ = _case("valid-continuity")
    path = tmp_path / "transition-kind.sqlite3"
    service = DirectStateOwnedAtomicClearanceV1(path=path)
    service.submit(raw)
    service.close()
    with sqlite3.connect(path) as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO transition_records ("
            "sequence_after, transition_kind, record_commitment, "
            "state_binding_before, state_binding_after, nullifier_root_before, "
            "nullifier_root_after, payment_root_before, payment_root_after, "
            "governance_before, governance_after, profile_before, profile_after, "
            "suite_before, suite_after, schema_before, schema_after, verifier_before, "
            "verifier_after, epoch_before, epoch_after, checkpoint_commitment_after"
            ") SELECT sequence_after + 1, 'SETTLEMENT', ?, state_binding_before, "
            "state_binding_after, nullifier_root_before, nullifier_root_after, "
            "payment_root_before, payment_root_after, governance_before, "
            "governance_after, profile_before, profile_after, suite_before, "
            "suite_after, schema_before, schema_after, verifier_before, verifier_after, "
            "epoch_before, epoch_after, ? FROM transition_records "
            "WHERE sequence_after=1",
            (sqlite3.Binary(b"\xC3" * 64), sqlite3.Binary(b"\xC4" * 64)),
        )
    _tamper_transition_kind(path)
    with pytest.raises(ProductionBoundaryError, match="database_direct_transition_kind_invalid"):
        DirectStateOwnedAtomicClearanceV1(path=path)
