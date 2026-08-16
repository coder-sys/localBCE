from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
from pathlib import Path
import sqlite3
from threading import Lock

import pytest

from app.direct_state_owned_clearance_v1 import (
    DIRECT_INITIAL_CLEARANCE_ROOT,
    DIRECT_INITIAL_PAYMENT_ROOT,
    DirectStateOwnedAtomicClearanceV1,
    DirectStateOwnedClearanceError,
)
from app.production_boundary import ProductionBoundaryError
from app.transactional_database_boundary import (
    AntiRollbackAnchorSnapshot,
    InMemoryAntiRollbackReference,
)
from experiments.native_v3_phase0.native_v3_fixture import (
    DIRECTIVE_BLOCK,
    DIRECTIVE_CLEAR,
    DIRECTIVE_EXCEPTION_APPROVED,
    DIRECTIVE_HOLD,
    DIRECTIVE_HUMAN_REVIEW,
    NO_EXCEPTION_SENTINEL,
)
from experiments.native_v3_plaintext_continuity.continuity import (
    ACCESS_READ,
    ACCESS_WRITE,
    DEMO_CASES,
    ContinuityReceipt,
    ContinuityStore,
    build_demo_case,
    bundle_bytes,
    make_completeness,
)
from experiments.native_v3_plaintext_continuity.independent import (
    IndependentParseError,
    parse_bundle,
    parse_bundle_details,
)


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


def _tamper_transition_kind(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER transition_records_no_update")
        connection.execute(
            "UPDATE transition_records SET transition_kind='SETTLEMENT' "
            "WHERE sequence_after=1"
        )


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
        assert result.receipt_id == producer_receipt.receipt_id
        assert result.bundle_id == details.bundle_id
        assert result.request_id == request.request_id
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
    with pytest.raises(ProductionBoundaryError, match="database_direct_sequence_stale"):
        service.submit(expired_raw)
    assert service.snapshot() == before
    with pytest.raises(ProductionBoundaryError, match="database_direct_operation_not_authorized"):
        details = parse_bundle_details(expired_raw)
        operation = service._operation_from_details(details)
        service.database._commit_direct_state_owned(operation)
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
    assert isinstance(errors[0], ProductionBoundaryError)
    assert str(errors[0]) == "database_direct_sequence_stale"
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


def test_direct_transition_kind_substitution_fails_closed(tmp_path: Path) -> None:
    raw, _, _, _, _ = _case("valid-continuity")
    path = tmp_path / "transition-kind.sqlite3"
    service = DirectStateOwnedAtomicClearanceV1(path=path)
    service.submit(raw)
    service.close()
    _tamper_transition_kind(path)
    with pytest.raises(ProductionBoundaryError, match="database_direct_transition_kind_invalid"):
        DirectStateOwnedAtomicClearanceV1(path=path)
