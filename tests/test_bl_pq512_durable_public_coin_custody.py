from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha3_512
from pathlib import Path
import sqlite3
from threading import Barrier

import pytest

from experiments.bl_pq512_crypto_foundation import durable_public_coin_custody as custody_module
from experiments.bl_pq512_crypto_foundation.durable_public_coin_custody import (
    ACTIVATION_ALLOWED,
    GLOBAL_PROOF_SUITE_ID,
    MAX_ATTEMPTS_PER_STATEMENT,
    ML_DSA_87_SUITE_ID,
    PRODUCTION_USABLE,
    RECEIPT_LENGTH,
    RECORD_LENGTH,
    SLH_DSA_SHAKE_256F_SUITE_ID,
    STATUS,
    CustodyContributor,
    CustodyError,
    DurablePublicCoinCustody,
    OpaqueCustodyReceipt,
)


def _field(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def _contributors(count: int = 2) -> tuple[CustodyContributor, ...]:
    values = []
    for index in range(count):
        contributor_id = index.to_bytes(63, "big") + bytes((index + 1,))
        suite = ML_DSA_87_SUITE_ID if index % 2 == 0 else SLH_DSA_SHAKE_256F_SUITE_ID
        values.append(CustodyContributor(contributor_id, suite))
    return tuple(values)


def _store(path: Path, *, contributors: tuple[CustodyContributor, ...] | None = None, statement: bytes | None = None) -> DurablePublicCoinCustody:
    return DurablePublicCoinCustody(
        path,
        epoch_id=_field("epoch"),
        registry_root=_field("registry"),
        statement_root=statement or _field("statement"),
        contributors=contributors or _contributors(),
    )


def _append_one_round(store: DurablePublicCoinCustody, receipt: OpaqueCustodyReceipt, *, sequence: int = 0) -> tuple[OpaqueCustodyReceipt, bytes]:
    prior = _field(f"prior-{sequence}")
    resulting = _field(f"result-{sequence}")
    return (
        store.append_round(
            receipt,
            expected_record_sequence=sequence,
            round_index=sequence,
            prior_transcript_root=prior,
            resulting_transcript_root=resulting,
            authenticated_record_sha3_512=_field(f"authenticated-round-{sequence}"),
        ),
        resulting,
    )


def _counts(path: Path) -> tuple[int, int, int, bytes]:
    with sqlite3.connect(path) as connection:
        attempts = connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        events = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        receipts = connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
        head = bytes(connection.execute("SELECT audit_head FROM custody_state WHERE id=1").fetchone()[0])
    return attempts, events, receipts, head


def test_nonactivating_identity_and_fixed_grammars(tmp_path: Path) -> None:
    assert STATUS == "Z09_DURABLE_CUSTODY_REFERENCE_NONACTIVATING"
    assert PRODUCTION_USABLE is False
    assert ACTIVATION_ALLOWED is False
    assert GLOBAL_PROOF_SUITE_ID is None
    assert MAX_ATTEMPTS_PER_STATEMENT == 4
    assert RECORD_LENGTH == 316
    assert RECEIPT_LENGTH == 308

    store = _store(tmp_path / "custody.sqlite3")
    release = store.burn_attempt()
    assert len(release.session_id) == 64
    assert len(release.custody_receipt.encode()) == RECEIPT_LENGTH
    assert repr(release.custody_receipt) == "OpaqueCustodyReceipt(<redacted>)"
    assert store.verify_receipt(release.custody_receipt) is release.custody_receipt


def test_burn_is_committed_before_session_release_and_pragmas_are_durable(tmp_path: Path) -> None:
    path = tmp_path / "custody.sqlite3"
    release = _store(path).burn_attempt()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        attempt = connection.execute(
            "SELECT ordinal,session_id,status FROM attempts WHERE ordinal=0"
        ).fetchone()
        event = connection.execute(
            "SELECT kind,record,length(record) FROM audit_events WHERE sequence=0"
        ).fetchone()
        state = connection.execute(
            "SELECT next_attempt,next_audit_sequence FROM custody_state WHERE id=1"
        ).fetchone()
    assert attempt == (0, release.session_id, "OPEN")
    assert event[0] == 1
    assert len(event[1]) == RECORD_LENGTH
    assert event[2] == RECORD_LENGTH
    assert state == (1, 1)


def test_round_final_receipts_survive_restart_and_no_raw_transcript_is_stored(tmp_path: Path) -> None:
    path = tmp_path / "custody.sqlite3"
    store = _store(path)
    release = store.burn_attempt()
    round_receipt, final_root = _append_one_round(store, release.custody_receipt)
    restarted = _store(path)
    assert restarted.verify_receipt(round_receipt) is round_receipt
    final_receipt = restarted.append_final(
        round_receipt,
        expected_record_sequence=1,
        final_transcript_root=final_root,
        authenticated_final_sha3_512=_field("authenticated-final"),
    )
    assert _store(path).verify_receipt(final_receipt) is final_receipt
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT status,next_record_sequence,transcript_root FROM attempts"
        ).fetchone() == ("SUCCEEDED", 2, final_root)
        records = b"".join(bytes(row[0]) for row in connection.execute("SELECT record FROM audit_events"))
    assert b"private-transcript-material" not in records
    with pytest.raises(CustodyError, match="statement_already_completed"):
        restarted.burn_attempt()


def test_latest_receipt_is_recoverable_after_process_restart_and_uncertain_response(
    tmp_path: Path,
) -> None:
    path = tmp_path / "custody.sqlite3"
    first = _store(path).burn_attempt().custody_receipt.encode()
    recovered = _store(path).recover_latest_receipt()
    assert recovered.encode() == first
    round_receipt, _ = _append_one_round(_store(path), recovered)
    assert _store(path).recover_latest_receipt().encode() == round_receipt.encode()
    open_attempt = _store(path).recover_open_attempt()
    assert open_attempt.ordinal == 0
    assert open_attempt.next_record_sequence == 1
    assert open_attempt.transcript_root == _field("result-0")
    assert open_attempt.custody_receipt.encode() == round_receipt.encode()


def test_recover_latest_receipt_rejects_empty_ledger(tmp_path: Path) -> None:
    with pytest.raises(CustodyError, match="no_committed_receipt"):
        _store(tmp_path / "custody.sqlite3").recover_latest_receipt()


def test_worker_abort_burns_attempt_without_quarantining_signers_and_survives_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "custody.sqlite3"
    store = _store(path)
    first = store.burn_attempt()
    aborted = store.append_worker_abort(
        first.custody_receipt,
        expected_record_sequence=0,
        round_index=0,
        prior_transcript_root=bytes(64),
        authenticated_abort_sha3_512=_field("worker-crash"),
    )
    assert _store(path).verify_receipt(aborted).encode() == aborted.encode()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM quarantines").fetchone()[0] == 0
    second = _store(path).burn_attempt()
    assert second.ordinal == 1
    assert second.session_id != first.session_id


def test_recover_open_attempt_rejects_terminal_or_empty_state(tmp_path: Path) -> None:
    path = tmp_path / "custody.sqlite3"
    store = _store(path)
    with pytest.raises(CustodyError, match="no_open_attempt"):
        store.recover_open_attempt()
    release = store.burn_attempt()
    store.append_worker_abort(
        release.custody_receipt,
        expected_record_sequence=0,
        round_index=0,
        prior_transcript_root=bytes(64),
        authenticated_abort_sha3_512=_field("worker-crash"),
    )
    with pytest.raises(CustodyError, match="no_open_attempt"):
        _store(path).recover_open_attempt()


def test_replay_stale_sequence_and_stale_root_fail_without_partial_write(tmp_path: Path) -> None:
    path = tmp_path / "custody.sqlite3"
    store = _store(path)
    release = store.burn_attempt()
    before = _counts(path)
    with pytest.raises(CustodyError, match="record_sequence_stale"):
        store.append_round(
            release.custody_receipt,
            expected_record_sequence=1,
            round_index=0,
            prior_transcript_root=_field("prior"),
            resulting_transcript_root=_field("result"),
            authenticated_record_sha3_512=_field("round"),
        )
    assert _counts(path) == before
    round_receipt, first_root = _append_one_round(store, release.custody_receipt)
    after_round = _counts(path)
    with pytest.raises(CustodyError, match="receipt_stale"):
        _append_one_round(store, release.custody_receipt, sequence=1)
    assert _counts(path) == after_round
    with pytest.raises(CustodyError, match="prior_transcript_root_stale"):
        store.append_round(
            round_receipt,
            expected_record_sequence=1,
            round_index=1,
            prior_transcript_root=_field("wrong-root"),
            resulting_transcript_root=_field("next-root"),
            authenticated_record_sha3_512=_field("next-round"),
        )
    assert _counts(path) == after_round
    assert first_root != _field("wrong-root")


def test_concurrent_same_receipt_has_exactly_one_committed_winner(tmp_path: Path) -> None:
    path = tmp_path / "custody.sqlite3"
    release = _store(path).burn_attempt()
    barrier = Barrier(2)

    def append(label: str) -> str:
        store = _store(path)
        barrier.wait()
        try:
            store.append_round(
                release.custody_receipt,
                expected_record_sequence=0,
                round_index=0,
                prior_transcript_root=_field("shared-prior"),
                resulting_transcript_root=_field(label),
                authenticated_record_sha3_512=_field(f"record-{label}"),
            )
            return "committed"
        except CustodyError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(append, ("candidate-a", "candidate-b")))
    assert outcomes.count("committed") == 1
    assert sum("receipt_stale" in item for item in outcomes) == 1
    assert _counts(path)[:3] == (1, 2, 2)


def test_missing_reveal_abort_quarantines_and_requires_suite_diversity(tmp_path: Path) -> None:
    path = tmp_path / "custody.sqlite3"
    contributors = _contributors()
    store = _store(path, contributors=contributors)
    release = store.burn_attempt()
    abort_receipt = store.append_abort(
        release.custody_receipt,
        expected_record_sequence=0,
        round_index=0,
        prior_transcript_root=bytes(64),
        authenticated_abort_sha3_512=_field("signed-missing-reveal-evidence"),
        missing_contributor_ids=(contributors[0].contributor_id,),
    )
    assert store.verify_receipt(abort_receipt) is abort_receipt
    with sqlite3.connect(path) as connection:
        assert tuple(bytes(row[0]) for row in connection.execute("SELECT contributor_id FROM quarantines")) == (
            contributors[0].contributor_id,
        )
    with pytest.raises(CustodyError, match="two_suite_diverse_services"):
        store.burn_attempt()


def test_four_ordinals_are_burned_then_cap_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "custody.sqlite3"
    contributors = _contributors(10)
    store = _store(path, contributors=contributors)
    released = []
    for ordinal in range(MAX_ATTEMPTS_PER_STATEMENT):
        release = store.burn_attempt()
        released.append(release.ordinal)
        store.append_abort(
            release.custody_receipt,
            expected_record_sequence=0,
            round_index=0,
            prior_transcript_root=bytes(64),
            authenticated_abort_sha3_512=_field(f"abort-{ordinal}"),
            missing_contributor_ids=(contributors[ordinal].contributor_id,),
        )
    assert released == [0, 1, 2, 3]
    before = _counts(path)
    with pytest.raises(CustodyError, match="attempt_cap_exhausted"):
        store.burn_attempt()
    assert _counts(path) == before


@pytest.mark.parametrize("mutator", ["statement", "registry", "contributors"])
def test_restart_rejects_configuration_swap(tmp_path: Path, mutator: str) -> None:
    path = tmp_path / "custody.sqlite3"
    contributors = _contributors(4)
    _store(path, contributors=contributors).burn_attempt()
    kwargs = {
        "epoch_id": _field("epoch"),
        "registry_root": _field("registry-swap") if mutator == "registry" else _field("registry"),
        "statement_root": _field("statement-swap") if mutator == "statement" else _field("statement"),
        "contributors": _contributors(6) if mutator == "contributors" else contributors,
    }
    with pytest.raises(CustodyError, match="configuration_mismatch"):
        DurablePublicCoinCustody(path, **kwargs)


def test_truncated_extended_and_mutated_receipts_are_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path / "custody.sqlite3")
    encoded = store.burn_attempt().custody_receipt.encode()
    with pytest.raises(CustodyError, match="must_be_308_bytes"):
        OpaqueCustodyReceipt(encoded[:-1])
    with pytest.raises(CustodyError, match="must_be_308_bytes"):
        OpaqueCustodyReceipt(encoded + b"\x00")
    mutated = bytearray(encoded)
    mutated[100] ^= 1
    with pytest.raises(CustodyError, match="receipt_commitment_invalid"):
        store.verify_receipt(OpaqueCustodyReceipt(bytes(mutated)))


def test_restart_rejects_mutated_record_and_incomplete_atomic_tail(tmp_path: Path) -> None:
    path = tmp_path / "custody.sqlite3"
    store = _store(path)
    store.burn_attempt()
    with sqlite3.connect(path) as connection:
        record = bytearray(connection.execute("SELECT record FROM audit_events WHERE sequence=0").fetchone()[0])
        record[-1] ^= 1
        connection.execute("UPDATE audit_events SET record=? WHERE sequence=0", (bytes(record),))
    with pytest.raises(CustodyError, match="record_reserved_nonzero"):
        _store(path)

    path2 = tmp_path / "partial.sqlite3"
    store2 = _store(path2)
    store2.burn_attempt()
    with sqlite3.connect(path2) as connection:
        connection.execute("DELETE FROM receipts WHERE event_sequence=0")
    with pytest.raises(CustodyError, match="receipt_ledger_incomplete"):
        _store(path2)


@pytest.mark.parametrize("rewrite_audit_event", [False, True])
def test_restart_rejects_self_consistent_receipt_token_substitution(
    tmp_path: Path, rewrite_audit_event: bool
) -> None:
    path = tmp_path / "custody.sqlite3"
    encoded = _store(path).burn_attempt().custody_receipt.encode()
    prefix_values = list(custody_module._RECEIPT_PREFIX.unpack(encoded[:-64]))
    forged_token = _field("attacker-chosen-receipt-token")[:32]
    prefix_values[6] = forged_token
    forged_prefix = custody_module._RECEIPT_PREFIX.pack(*prefix_values)
    forged_commitment = custody_module._digest(
        custody_module._RECEIPT_DOMAIN, forged_prefix
    )
    forged = OpaqueCustodyReceipt(forged_prefix + forged_commitment)
    forged_token_hash = custody_module._digest(
        custody_module._TOKEN_DOMAIN, forged_token
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE receipts SET token_hash=? WHERE event_sequence=0",
            (forged_token_hash,),
        )
        if rewrite_audit_event:
            connection.execute(
                "UPDATE audit_events SET receipt_token_hash=? WHERE sequence=0",
                (forged_token_hash,),
            )
    expected = "audit_result_mismatch" if rewrite_audit_event else "receipt_ledger_incomplete"
    with pytest.raises(CustodyError, match=expected):
        _store(path)
    with pytest.raises(CustodyError):
        _store(path).verify_receipt(forged)


def test_abort_rejects_duplicate_unknown_and_noncanonical_missing_sets(tmp_path: Path) -> None:
    contributors = _contributors(4)
    store = _store(tmp_path / "custody.sqlite3", contributors=contributors)
    release = store.burn_attempt()
    common = dict(
        receipt=release.custody_receipt,
        expected_record_sequence=0,
        round_index=0,
        prior_transcript_root=bytes(64),
        authenticated_abort_sha3_512=_field("abort"),
    )
    with pytest.raises(CustodyError, match="not_unique_sorted"):
        store.append_abort(
            **common,
            missing_contributor_ids=(contributors[0].contributor_id, contributors[0].contributor_id),
        )
    with pytest.raises(CustodyError, match="not_active"):
        store.append_abort(**common, missing_contributor_ids=(_field("unknown-contributor"),))
    assert _counts(tmp_path / "custody.sqlite3")[:3] == (1, 1, 1)
