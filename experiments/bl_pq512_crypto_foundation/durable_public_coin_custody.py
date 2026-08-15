"""Durable, nonactivating custody for bounded public-coin attempts.

This SQLite reference owns attempt burning and append-only custody, not public-
coin signature or transcript verification.  Callers provide only authenticated
SHA3-512 commitments and transcript roots; selected transcript bytes, witness
material, and private bus values are never serialized here.  The fixed custody
record below is therefore a separate storage grammar and does not modify the
selected public-coin transcript grammar.

Every mutation uses ``BEGIN IMMEDIATE``.  Every connection requests WAL mode,
``synchronous=FULL``, foreign keys, and a bounded busy timeout.  A session is
returned only after the burn transaction commits.  This is local durability
evidence, not an HSM, trusted-clock, external anti-rollback, production, or
activation claim.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from hashlib import sha3_512
from pathlib import Path
import secrets
import sqlite3
import struct
from typing import Final


STATUS: Final[str] = "Z09_DURABLE_CUSTODY_REFERENCE_NONACTIVATING"
PRODUCTION_USABLE: Final[bool] = False
ACTIVATION_ALLOWED: Final[bool] = False
GLOBAL_PROOF_SUITE_ID: Final[None] = None

MAX_ATTEMPTS_PER_STATEMENT: Final[int] = 4
MAX_CONTRIBUTORS: Final[int] = 32
ML_DSA_87_SUITE_ID: Final[str] = "FIPS204-ML-DSA-87"
SLH_DSA_SHAKE_256F_SUITE_ID: Final[str] = "FIPS205-SLH-DSA-SHAKE-256F"
APPROVED_SUITES: Final[frozenset[str]] = frozenset(
    (ML_DSA_87_SUITE_ID, SLH_DSA_SHAKE_256F_SUITE_ID)
)

_SCHEMA_VERSION: Final[int] = 3
_RECORD_MAGIC: Final[bytes] = b"BLPQCST1"
_RECEIPT_MAGIC: Final[bytes] = b"BLPQCRP1"
_RECORD_VERSION: Final[int] = 1
_RECEIPT_VERSION: Final[int] = 1
_KIND_BURN: Final[int] = 1
_KIND_ROUND: Final[int] = 2
_KIND_FINAL: Final[int] = 3
_KIND_ABORT: Final[int] = 4
_NO_RECORD_SEQUENCE: Final[int] = 0xFFFFFFFF
_NO_ROUND_INDEX: Final[int] = 0xFFFFFFFF

# magic, version, kind, attempt, record sequence, round index, flags,
# session, prior root, resulting root, authenticated payload commitment,
# quarantine bitmap, reserved zeros.
_RECORD_STRUCT: Final[struct.Struct] = struct.Struct(">8sHHIIII64s64s64s64sI28s")
RECORD_LENGTH: Final[int] = _RECORD_STRUCT.size  # 316 bytes

# magic, version, event kind, attempt, record sequence, session, random token,
# event audit root, immutable configuration root, receipt commitment.
_RECEIPT_PREFIX: Final[struct.Struct] = struct.Struct(">8sHHII64s32s64s64s")
RECEIPT_LENGTH: Final[int] = _RECEIPT_PREFIX.size + 64  # 308 bytes

_CONFIG_DOMAIN: Final[bytes] = b"BL/PQ512/Z09/CUSTODY-CONFIG/v1\x00"
_AUDIT_INIT_DOMAIN: Final[bytes] = b"BL/PQ512/Z09/CUSTODY-AUDIT-INIT/v1\x00"
_AUDIT_APPEND_DOMAIN: Final[bytes] = b"BL/PQ512/Z09/CUSTODY-AUDIT-APPEND/v1\x00"
_ATTEMPT_BURN_DOMAIN: Final[bytes] = b"S09/ATTEMPT-BURN"
_RECEIPT_DOMAIN: Final[bytes] = b"BL/PQ512/Z09/CUSTODY-RECEIPT/v1\x00"
_TOKEN_DOMAIN: Final[bytes] = b"BL/PQ512/Z09/CUSTODY-TOKEN/v1\x00"


class CustodyError(RuntimeError):
    """Stable fail-closed error for the custody boundary."""


def _exact_bytes(label: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise CustodyError(f"durable_custody_{label}_must_be_{length}_bytes")
    if nonzero and not any(value):
        raise CustodyError(f"durable_custody_{label}_must_be_nonzero")
    return value


def _u32(label: str, value: object) -> int:
    if type(value) is not int or value < 0 or value > 0xFFFFFFFF:
        raise CustodyError(f"durable_custody_{label}_must_be_u32")
    return value


def _frame(domain: bytes, *parts: bytes) -> bytes:
    out = bytearray(len(domain).to_bytes(2, "big"))
    out.extend(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise CustodyError("durable_custody_digest_part_invalid")
        out.extend(len(part).to_bytes(4, "big"))
        out.extend(part)
    return bytes(out)


def _digest(domain: bytes, *parts: bytes) -> bytes:
    return sha3_512(_frame(domain, *parts)).digest()


@dataclass(frozen=True, slots=True)
class CustodyContributor:
    contributor_id: bytes
    suite_id: str

    def __post_init__(self) -> None:
        _exact_bytes("contributor_id", self.contributor_id, 64, nonzero=True)
        if type(self.suite_id) is not str or self.suite_id not in APPROVED_SUITES:
            raise CustodyError("durable_custody_contributor_suite_not_approved")

    def encode(self) -> bytes:
        suite = self.suite_id.encode("ascii")
        return self.contributor_id + len(suite).to_bytes(2, "big") + suite


class OpaqueCustodyReceipt:
    """Opaque capability whose bytes are meaningful only to this custody store."""

    __slots__ = ("__encoded",)

    def __init__(self, encoded: bytes) -> None:
        self.__encoded = _exact_bytes("receipt", encoded, RECEIPT_LENGTH)

    def encode(self) -> bytes:
        return self.__encoded

    def __repr__(self) -> str:
        return "OpaqueCustodyReceipt(<redacted>)"


@dataclass(frozen=True, slots=True)
class AttemptRelease:
    ordinal: int
    session_id: bytes
    custody_receipt: OpaqueCustodyReceipt


@dataclass(frozen=True, slots=True)
class RecoveredOpenAttempt:
    ordinal: int
    session_id: bytes
    next_record_sequence: int
    transcript_root: bytes | None
    custody_receipt: OpaqueCustodyReceipt


def _record(
    *,
    kind: int,
    attempt: int,
    record_sequence: int,
    round_index: int,
    session_id: bytes,
    prior_root: bytes,
    resulting_root: bytes,
    payload_commitment: bytes,
    quarantine_bitmap: int = 0,
) -> bytes:
    return _RECORD_STRUCT.pack(
        _RECORD_MAGIC,
        _RECORD_VERSION,
        kind,
        attempt,
        record_sequence,
        round_index,
        0,
        session_id,
        prior_root,
        resulting_root,
        payload_commitment,
        quarantine_bitmap,
        bytes(28),
    )


def _decode_record(encoded: bytes) -> tuple[object, ...]:
    _exact_bytes("record", encoded, RECORD_LENGTH)
    values = _RECORD_STRUCT.unpack(encoded)
    if values[0] != _RECORD_MAGIC or values[1] != _RECORD_VERSION:
        raise CustodyError("durable_custody_record_header_invalid")
    if values[2] not in {_KIND_BURN, _KIND_ROUND, _KIND_FINAL, _KIND_ABORT}:
        raise CustodyError("durable_custody_record_kind_invalid")
    if values[6] != 0 or values[12] != bytes(28):
        raise CustodyError("durable_custody_record_reserved_nonzero")
    return values


class DurablePublicCoinCustody:
    """One immutable epoch/registry/statement custody ledger."""

    def __init__(
        self,
        path: str | Path,
        *,
        epoch_id: bytes,
        registry_root: bytes,
        statement_root: bytes,
        contributors: tuple[CustodyContributor, ...],
    ) -> None:
        self._path = Path(path)
        if self._path.exists() and (not self._path.is_file() or self._path.is_symlink()):
            raise CustodyError("durable_custody_database_path_invalid")
        if not self._path.parent.exists() or not self._path.parent.is_dir():
            raise CustodyError("durable_custody_database_parent_missing")
        self._epoch_id = _exact_bytes("epoch_id", epoch_id, 64, nonzero=True)
        self._registry_root = _exact_bytes("registry_root", registry_root, 64, nonzero=True)
        self._statement_root = _exact_bytes("statement_root", statement_root, 64, nonzero=True)
        if type(contributors) is not tuple or not (2 <= len(contributors) <= MAX_CONTRIBUTORS):
            raise CustodyError("durable_custody_contributor_count_invalid")
        if any(not isinstance(item, CustodyContributor) for item in contributors):
            raise CustodyError("durable_custody_contributor_invalid")
        ids = tuple(item.contributor_id for item in contributors)
        if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids):
            raise CustodyError("durable_custody_contributors_not_unique_sorted")
        if {item.suite_id for item in contributors} != APPROVED_SUITES:
            raise CustodyError("durable_custody_both_pq_suites_required")
        self._contributors = contributors
        self._config_root = _digest(
            _CONFIG_DOMAIN,
            self._epoch_id,
            self._registry_root,
            self._statement_root,
            MAX_ATTEMPTS_PER_STATEMENT.to_bytes(4, "big"),
            *(item.encode() for item in contributors),
        )
        self._initialize()

    @property
    def statement_root(self) -> bytes:
        return self._statement_root

    @property
    def contributor_configuration(self) -> tuple[CustodyContributor, ...]:
        return self._contributors

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self._path), timeout=10.0, isolation_level=None, check_same_thread=False
        )
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            "CREATE TABLE IF NOT EXISTS metadata ("
            "id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL, "
            "status TEXT NOT NULL, epoch_id BLOB NOT NULL, registry_root BLOB NOT NULL, "
            "statement_root BLOB NOT NULL, config_root BLOB NOT NULL, retry_cap INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS contributors ("
            "position INTEGER PRIMARY KEY, contributor_id BLOB NOT NULL UNIQUE, suite_id TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS custody_state ("
            "id INTEGER PRIMARY KEY CHECK(id=1), next_attempt INTEGER NOT NULL, "
            "next_audit_sequence INTEGER NOT NULL, audit_head BLOB NOT NULL, completed INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS attempts ("
            "ordinal INTEGER PRIMARY KEY, session_id BLOB NOT NULL UNIQUE, status TEXT NOT NULL, "
            "next_record_sequence INTEGER NOT NULL, transcript_root BLOB, last_audit_root BLOB NOT NULL);"
            "CREATE TABLE IF NOT EXISTS audit_events ("
            "sequence INTEGER PRIMARY KEY, kind INTEGER NOT NULL, attempt_ordinal INTEGER NOT NULL, "
            "record_sequence INTEGER NOT NULL, record BLOB NOT NULL, record_digest BLOB NOT NULL, "
            "prior_root BLOB NOT NULL, resulting_root BLOB NOT NULL, receipt_token_hash BLOB NOT NULL, "
            "FOREIGN KEY(attempt_ordinal) REFERENCES attempts(ordinal));"
            "CREATE TABLE IF NOT EXISTS quarantines ("
            "contributor_id BLOB PRIMARY KEY, attempt_ordinal INTEGER NOT NULL, audit_sequence INTEGER NOT NULL, "
            "FOREIGN KEY(attempt_ordinal) REFERENCES attempts(ordinal), "
            "FOREIGN KEY(audit_sequence) REFERENCES audit_events(sequence));"
            "CREATE TABLE IF NOT EXISTS receipts ("
            "event_sequence INTEGER PRIMARY KEY, token BLOB NOT NULL UNIQUE, token_hash BLOB NOT NULL UNIQUE, "
            "FOREIGN KEY(event_sequence) REFERENCES audit_events(sequence));"
        )

    def _initialize(self) -> None:
        created = not self._path.exists()
        try:
            with closing(self._connect()) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                self._schema(connection)
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT * FROM metadata WHERE id=1").fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO metadata VALUES(1,?,?,?,?,?,?,?)",
                        (
                            _SCHEMA_VERSION,
                            STATUS,
                            sqlite3.Binary(self._epoch_id),
                            sqlite3.Binary(self._registry_root),
                            sqlite3.Binary(self._statement_root),
                            sqlite3.Binary(self._config_root),
                            MAX_ATTEMPTS_PER_STATEMENT,
                        ),
                    )
                    connection.executemany(
                        "INSERT INTO contributors VALUES(?,?,?)",
                        tuple(
                            (index, sqlite3.Binary(item.contributor_id), item.suite_id)
                            for index, item in enumerate(self._contributors)
                        ),
                    )
                    init = _digest(_AUDIT_INIT_DOMAIN, self._config_root)
                    connection.execute(
                        "INSERT INTO custody_state VALUES(1,0,0,?,0)",
                        (sqlite3.Binary(init),),
                    )
                self._validate_locked(connection)
                connection.execute("COMMIT")
        except Exception as exc:
            if created:
                for candidate in (self._path, Path(str(self._path) + "-wal"), Path(str(self._path) + "-shm")):
                    if candidate.exists() and candidate.is_file() and not candidate.is_symlink():
                        candidate.unlink()
            if isinstance(exc, CustodyError):
                raise
            raise CustodyError("durable_custody_initialization_failed") from exc

    def _validate_locked(self, connection: sqlite3.Connection) -> None:
        metadata = connection.execute(
            "SELECT schema_version,status,epoch_id,registry_root,statement_root,config_root,retry_cap "
            "FROM metadata WHERE id=1"
        ).fetchone()
        expected_metadata = (
            _SCHEMA_VERSION,
            STATUS,
            self._epoch_id,
            self._registry_root,
            self._statement_root,
            self._config_root,
            MAX_ATTEMPTS_PER_STATEMENT,
        )
        if metadata is None or tuple(bytes(x) if isinstance(x, bytes) else x for x in metadata) != expected_metadata:
            raise CustodyError("durable_custody_configuration_mismatch")
        contributors = connection.execute(
            "SELECT position,contributor_id,suite_id FROM contributors ORDER BY position"
        ).fetchall()
        expected_contributors = tuple(
            (index, item.contributor_id, item.suite_id) for index, item in enumerate(self._contributors)
        )
        normalized = tuple((row[0], bytes(row[1]), row[2]) for row in contributors)
        if normalized != expected_contributors:
            raise CustodyError("durable_custody_contributor_registry_mismatch")
        state = connection.execute(
            "SELECT next_attempt,next_audit_sequence,audit_head,completed FROM custody_state WHERE id=1"
        ).fetchone()
        if state is None or type(state[0]) is not int or type(state[1]) is not int or state[3] not in (0, 1):
            raise CustodyError("durable_custody_state_invalid")
        attempts = connection.execute(
            "SELECT ordinal,session_id,status,next_record_sequence,transcript_root,last_audit_root "
            "FROM attempts ORDER BY ordinal"
        ).fetchall()
        if tuple(row[0] for row in attempts) != tuple(range(len(attempts))) or state[0] != len(attempts):
            raise CustodyError("durable_custody_attempt_ledger_not_contiguous")
        if len(attempts) > MAX_ATTEMPTS_PER_STATEMENT:
            raise CustodyError("durable_custody_attempt_cap_corrupt")
        events = connection.execute(
            "SELECT sequence,kind,attempt_ordinal,record_sequence,record,record_digest,prior_root,resulting_root,receipt_token_hash "
            "FROM audit_events ORDER BY sequence"
        ).fetchall()
        root = _digest(_AUDIT_INIT_DOMAIN, self._config_root)
        per_attempt: dict[int, list[tuple[int, int, tuple[object, ...], bytes]]] = {}
        quarantined: dict[bytes, tuple[int, int]] = {}
        for expected_sequence, row in enumerate(events):
            if row[0] != expected_sequence or bytes(row[6]) != root:
                raise CustodyError("durable_custody_audit_chain_invalid")
            encoded = bytes(row[4])
            decoded = _decode_record(encoded)
            record_digest = sha3_512(encoded).digest()
            if bytes(row[5]) != record_digest or decoded[2] != row[1] or decoded[3] != row[2] or decoded[4] != row[3]:
                raise CustodyError("durable_custody_audit_record_mismatch")
            receipt_token_hash = bytes(row[8])
            if len(receipt_token_hash) != 64 or not any(receipt_token_hash):
                raise CustodyError("durable_custody_audit_receipt_token_invalid")
            resulting = _digest(
                _AUDIT_APPEND_DOMAIN,
                root,
                expected_sequence.to_bytes(8, "big"),
                record_digest,
                receipt_token_hash,
            )
            if bytes(row[7]) != resulting:
                raise CustodyError("durable_custody_audit_result_mismatch")
            root = resulting
            per_attempt.setdefault(row[2], []).append((row[1], row[3], decoded, root))
            if row[1] == _KIND_ABORT:
                bitmap = decoded[11]
                for position, contributor in enumerate(self._contributors):
                    if bitmap & (1 << position):
                        quarantined[contributor.contributor_id] = (row[2], row[0])
        if state[1] != len(events) or bytes(state[2]) != root:
            raise CustodyError("durable_custody_state_audit_mismatch")
        open_count = 0
        succeeded_count = 0
        for ordinal, session, status, next_record, transcript_root, last_root in attempts:
            attempt_events = per_attempt.get(ordinal, [])
            if not attempt_events or attempt_events[0][0] != _KIND_BURN:
                raise CustodyError("durable_custody_attempt_burn_missing")
            burn = attempt_events[0][2]
            if burn[3] != ordinal or burn[4] != _NO_RECORD_SEQUENCE or bytes(burn[7]) != bytes(session):
                raise CustodyError("durable_custody_attempt_burn_invalid")
            previously_quarantined = {
                contributor_id
                for contributor_id, (abort_attempt, _) in quarantined.items()
                if abort_attempt < ordinal
            }
            active = tuple(
                item for item in self._contributors if item.contributor_id not in previously_quarantined
            )
            expected_session = _digest(
                _ATTEMPT_BURN_DOMAIN,
                self._epoch_id,
                self._registry_root,
                self._statement_root,
                ordinal.to_bytes(1, "big"),
                *(item.contributor_id for item in active),
            )
            expected_burn_payload = _digest(
                _ATTEMPT_BURN_DOMAIN,
                self._statement_root,
                ordinal.to_bytes(1, "big"),
                expected_session,
                *(item.contributor_id for item in active),
            )
            if (
                bytes(session) != expected_session
                or burn[5] != _NO_ROUND_INDEX
                or any(bytes(burn[8]))
                or any(bytes(burn[9]))
                or bytes(burn[10]) != expected_burn_payload
                or burn[11] != 0
            ):
                raise CustodyError("durable_custody_attempt_burn_noncanonical")
            transcript_events = attempt_events[1:]
            if tuple(item[1] for item in transcript_events) != tuple(range(len(transcript_events))):
                raise CustodyError("durable_custody_record_sequence_not_contiguous")
            derived_root: bytes | None = None
            terminal: str | None = None
            for kind, _, decoded, _ in transcript_events:
                if terminal is not None:
                    raise CustodyError("durable_custody_record_after_terminal")
                if bytes(decoded[7]) != bytes(session) or not any(bytes(decoded[10])):
                    raise CustodyError("durable_custody_transcript_record_noncanonical")
                prior = bytes(decoded[8])
                resulting = bytes(decoded[9])
                if kind == _KIND_ROUND:
                    if decoded[5] == _NO_ROUND_INDEX or decoded[11] != 0 or not any(prior) or not any(resulting) or prior == resulting:
                        raise CustodyError("durable_custody_round_record_noncanonical")
                    if derived_root is not None and prior != derived_root:
                        raise CustodyError("durable_custody_transcript_root_chain_invalid")
                    derived_root = resulting
                elif kind == _KIND_FINAL:
                    if decoded[5] != _NO_ROUND_INDEX or decoded[11] != 0:
                        raise CustodyError("durable_custody_final_record_noncanonical")
                    if derived_root is None or prior != derived_root or resulting != derived_root:
                        raise CustodyError("durable_custody_final_root_invalid")
                    terminal = "SUCCEEDED"
                elif kind == _KIND_ABORT:
                    if decoded[5] == _NO_ROUND_INDEX or decoded[11] >= (1 << len(self._contributors)):
                        raise CustodyError("durable_custody_abort_record_noncanonical")
                    if derived_root is None:
                        if any(prior):
                            raise CustodyError("durable_custody_abort_root_invalid")
                    elif prior != derived_root:
                        raise CustodyError("durable_custody_abort_root_invalid")
                    if any(resulting):
                        raise CustodyError("durable_custody_abort_result_nonzero")
                    terminal = "ABORTED"
            expected_status = terminal or "OPEN"
            if status != expected_status or next_record != len(transcript_events):
                raise CustodyError("durable_custody_attempt_state_mismatch")
            normalized_root = None if transcript_root is None else bytes(transcript_root)
            if normalized_root != derived_root or bytes(last_root) != attempt_events[-1][3]:
                raise CustodyError("durable_custody_attempt_root_mismatch")
            open_count += status == "OPEN"
            succeeded_count += status == "SUCCEEDED"
        if open_count > 1 or succeeded_count > 1 or state[3] != (1 if succeeded_count else 0):
            raise CustodyError("durable_custody_terminal_state_invalid")
        observed_quarantine = {
            bytes(row[0]): (row[1], row[2])
            for row in connection.execute(
                "SELECT contributor_id,attempt_ordinal,audit_sequence FROM quarantines"
            )
        }
        if observed_quarantine != quarantined:
            raise CustodyError("durable_custody_quarantine_ledger_mismatch")
        receipts = connection.execute(
            "SELECT event_sequence,token,token_hash FROM receipts ORDER BY event_sequence"
        ).fetchall()
        expected_receipts = tuple((row[0], bytes(row[8])) for row in events)
        observed_receipts = tuple((row[0], bytes(row[2])) for row in receipts)
        if observed_receipts != expected_receipts:
            raise CustodyError("durable_custody_receipt_ledger_incomplete")
        if any(
            len(bytes(row[1])) != 32
            or not any(bytes(row[1]))
            or _digest(_TOKEN_DOMAIN, bytes(row[1])) != bytes(row[2])
            for row in receipts
        ):
            raise CustodyError("durable_custody_receipt_token_mismatch")

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        kind: int,
        attempt: int,
        record_sequence: int,
        encoded: bytes,
        receipt_token_hash: bytes,
    ) -> tuple[int, bytes]:
        state = connection.execute(
            "SELECT next_audit_sequence,audit_head FROM custody_state WHERE id=1"
        ).fetchone()
        if state is None:
            raise CustodyError("durable_custody_state_missing")
        sequence, prior = state[0], bytes(state[1])
        record_digest = sha3_512(encoded).digest()
        token_hash = _exact_bytes(
            "receipt_token_hash", receipt_token_hash, 64, nonzero=True
        )
        resulting = _digest(
            _AUDIT_APPEND_DOMAIN,
            prior,
            sequence.to_bytes(8, "big"),
            record_digest,
            token_hash,
        )
        connection.execute(
            "INSERT INTO audit_events VALUES(?,?,?,?,?,?,?,?,?)",
            (
                sequence,
                kind,
                attempt,
                record_sequence,
                sqlite3.Binary(encoded),
                sqlite3.Binary(record_digest),
                sqlite3.Binary(prior),
                sqlite3.Binary(resulting),
                sqlite3.Binary(token_hash),
            ),
        )
        connection.execute(
            "UPDATE custody_state SET next_audit_sequence=?,audit_head=? WHERE id=1",
            (sequence + 1, sqlite3.Binary(resulting)),
        )
        return sequence, resulting

    def _issue_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        event_sequence: int,
        kind: int,
        attempt: int,
        record_sequence: int,
        session_id: bytes,
        audit_root: bytes,
        token: bytes,
    ) -> OpaqueCustodyReceipt:
        token = _exact_bytes("receipt_token", token, 32, nonzero=True)
        prefix = _RECEIPT_PREFIX.pack(
            _RECEIPT_MAGIC,
            _RECEIPT_VERSION,
            kind,
            attempt,
            record_sequence,
            session_id,
            token,
            audit_root,
            self._config_root,
        )
        commitment = _digest(_RECEIPT_DOMAIN, prefix)
        encoded = prefix + commitment
        connection.execute(
            "INSERT INTO receipts VALUES(?,?,?)",
            (
                event_sequence,
                sqlite3.Binary(token),
                sqlite3.Binary(_digest(_TOKEN_DOMAIN, token)),
            ),
        )
        return OpaqueCustodyReceipt(encoded)

    def _verify_receipt_locked(
        self, connection: sqlite3.Connection, receipt: OpaqueCustodyReceipt, *, current: bool
    ) -> tuple[int, int, int, bytes, bytes]:
        if not isinstance(receipt, OpaqueCustodyReceipt):
            raise CustodyError("durable_custody_opaque_receipt_required")
        encoded = receipt.encode()
        prefix, commitment = encoded[:-64], encoded[-64:]
        values = _RECEIPT_PREFIX.unpack(prefix)
        if values[0] != _RECEIPT_MAGIC or values[1] != _RECEIPT_VERSION or values[2] not in {_KIND_BURN, _KIND_ROUND, _KIND_FINAL, _KIND_ABORT}:
            raise CustodyError("durable_custody_receipt_header_invalid")
        if bytes(values[8]) != self._config_root or commitment != _digest(_RECEIPT_DOMAIN, prefix):
            raise CustodyError("durable_custody_receipt_commitment_invalid")
        token_hash = _digest(_TOKEN_DOMAIN, bytes(values[6]))
        row = connection.execute(
            "SELECT r.event_sequence,e.kind,e.attempt_ordinal,e.record_sequence,e.resulting_root,a.session_id,a.last_audit_root,e.receipt_token_hash "
            "FROM receipts r JOIN audit_events e ON e.sequence=r.event_sequence "
            "JOIN attempts a ON a.ordinal=e.attempt_ordinal WHERE r.token_hash=?",
            (sqlite3.Binary(token_hash),),
        ).fetchone()
        if row is None or bytes(row[7]) != token_hash:
            raise CustodyError("durable_custody_receipt_unknown")
        if (row[1], row[2], row[3], bytes(row[5]), bytes(row[4])) != (
            values[2], values[3], values[4], bytes(values[5]), bytes(values[7])
        ):
            raise CustodyError("durable_custody_receipt_database_mismatch")
        if current and bytes(row[6]) != bytes(values[7]):
            raise CustodyError("durable_custody_receipt_stale")
        return values[2], values[3], values[4], bytes(values[5]), bytes(values[7])

    def verify_receipt(self, receipt: OpaqueCustodyReceipt) -> OpaqueCustodyReceipt:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            self._validate_locked(connection)
            self._verify_receipt_locked(connection, receipt, current=False)
            connection.execute("COMMIT")
        return receipt

    def recover_latest_receipt(self) -> OpaqueCustodyReceipt:
        """Reconstruct the newest committed capability after restart/uncertain response."""

        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            self._validate_locked(connection)
            receipt, _ = self._recover_latest_receipt_locked(connection)
            connection.execute("COMMIT")
        return receipt

    def _recover_latest_receipt_locked(
        self, connection: sqlite3.Connection
    ) -> tuple[OpaqueCustodyReceipt, tuple[object, ...]]:
        row = connection.execute(
            "SELECT e.kind,e.attempt_ordinal,e.record_sequence,a.session_id,e.resulting_root,r.token "
            "FROM audit_events e JOIN attempts a ON a.ordinal=e.attempt_ordinal "
            "JOIN receipts r ON r.event_sequence=e.sequence "
            "ORDER BY e.sequence DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise CustodyError("durable_custody_no_committed_receipt")
        prefix = _RECEIPT_PREFIX.pack(
            _RECEIPT_MAGIC,
            _RECEIPT_VERSION,
            row[0],
            row[1],
            row[2],
            bytes(row[3]),
            bytes(row[5]),
            bytes(row[4]),
            self._config_root,
        )
        receipt = OpaqueCustodyReceipt(prefix + _digest(_RECEIPT_DOMAIN, prefix))
        self._verify_receipt_locked(connection, receipt, current=True)
        return receipt, row

    def recover_open_attempt(self) -> RecoveredOpenAttempt:
        """Recover the one open attempt and its exact transcript cursor."""

        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            self._validate_locked(connection)
            row = connection.execute(
                "SELECT ordinal,session_id,next_record_sequence,transcript_root "
                "FROM attempts WHERE status='OPEN'"
            ).fetchone()
            if row is None:
                raise CustodyError("durable_custody_no_open_attempt")
            receipt, receipt_row = self._recover_latest_receipt_locked(connection)
            if receipt_row[1] != row[0]:
                raise CustodyError("durable_custody_open_attempt_not_latest")
            recovered = RecoveredOpenAttempt(
                ordinal=row[0],
                session_id=bytes(row[1]),
                next_record_sequence=row[2],
                transcript_root=None if row[3] is None else bytes(row[3]),
                custody_receipt=receipt,
            )
            connection.execute("COMMIT")
        return recovered

    def burn_attempt(self) -> AttemptRelease:
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_locked(connection)
                state = connection.execute(
                    "SELECT next_attempt,completed FROM custody_state WHERE id=1"
                ).fetchone()
                if state is None or state[1] != 0:
                    raise CustodyError("durable_custody_statement_already_completed")
                if connection.execute("SELECT 1 FROM attempts WHERE status='OPEN'").fetchone():
                    raise CustodyError("durable_custody_attempt_already_open")
                ordinal = state[0]
                if ordinal >= MAX_ATTEMPTS_PER_STATEMENT:
                    raise CustodyError("durable_custody_attempt_cap_exhausted")
                quarantined = {
                    bytes(row[0]) for row in connection.execute("SELECT contributor_id FROM quarantines")
                }
                active = tuple(item for item in self._contributors if item.contributor_id not in quarantined)
                if len(active) < 2 or {item.suite_id for item in active} != APPROVED_SUITES:
                    raise CustodyError("durable_custody_retry_requires_two_suite_diverse_services")
                session_id = _digest(
                    _ATTEMPT_BURN_DOMAIN,
                    self._epoch_id,
                    self._registry_root,
                    self._statement_root,
                    ordinal.to_bytes(1, "big"),
                    *(item.contributor_id for item in active),
                )
                active_commitment = _digest(
                    _ATTEMPT_BURN_DOMAIN,
                    self._statement_root,
                    ordinal.to_bytes(1, "big"),
                    session_id,
                    *(item.contributor_id for item in active),
                )
                encoded = _record(
                    kind=_KIND_BURN,
                    attempt=ordinal,
                    record_sequence=_NO_RECORD_SEQUENCE,
                    round_index=_NO_ROUND_INDEX,
                    session_id=session_id,
                    prior_root=bytes(64),
                    resulting_root=bytes(64),
                    payload_commitment=active_commitment,
                )
                # The attempts row must exist before its FK-bound audit event.
                init_root = _digest(_AUDIT_INIT_DOMAIN, self._config_root)
                connection.execute(
                    "INSERT INTO attempts VALUES(?,?, 'OPEN',0,NULL,?)",
                    (ordinal, sqlite3.Binary(session_id), sqlite3.Binary(init_root)),
                )
                receipt_token = secrets.token_bytes(32)
                event_sequence, audit_root = self._append_event(
                    connection,
                    kind=_KIND_BURN,
                    attempt=ordinal,
                    record_sequence=_NO_RECORD_SEQUENCE,
                    encoded=encoded,
                    receipt_token_hash=_digest(_TOKEN_DOMAIN, receipt_token),
                )
                connection.execute(
                    "UPDATE attempts SET last_audit_root=? WHERE ordinal=?",
                    (sqlite3.Binary(audit_root), ordinal),
                )
                connection.execute(
                    "UPDATE custody_state SET next_attempt=? WHERE id=1", (ordinal + 1,)
                )
                receipt = self._issue_receipt(
                    connection,
                    event_sequence=event_sequence,
                    kind=_KIND_BURN,
                    attempt=ordinal,
                    record_sequence=_NO_RECORD_SEQUENCE,
                    session_id=session_id,
                    audit_root=audit_root,
                    token=receipt_token,
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return AttemptRelease(ordinal, session_id, receipt)

    def append_round(
        self,
        receipt: OpaqueCustodyReceipt,
        *,
        expected_record_sequence: int,
        round_index: int,
        prior_transcript_root: bytes,
        resulting_transcript_root: bytes,
        authenticated_record_sha3_512: bytes,
    ) -> OpaqueCustodyReceipt:
        sequence = _u32("expected_record_sequence", expected_record_sequence)
        round_number = _u32("round_index", round_index)
        prior = _exact_bytes("prior_transcript_root", prior_transcript_root, 64, nonzero=True)
        resulting = _exact_bytes("resulting_transcript_root", resulting_transcript_root, 64, nonzero=True)
        payload = _exact_bytes("authenticated_record_sha3_512", authenticated_record_sha3_512, 64, nonzero=True)
        if prior == resulting:
            raise CustodyError("durable_custody_round_root_did_not_advance")
        return self._append_terminal_or_round(
            receipt,
            kind=_KIND_ROUND,
            expected_record_sequence=sequence,
            round_index=round_number,
            prior_root=prior,
            resulting_root=resulting,
            payload=payload,
            missing=(),
        )

    def append_final(
        self,
        receipt: OpaqueCustodyReceipt,
        *,
        expected_record_sequence: int,
        final_transcript_root: bytes,
        authenticated_final_sha3_512: bytes,
    ) -> OpaqueCustodyReceipt:
        root = _exact_bytes("final_transcript_root", final_transcript_root, 64, nonzero=True)
        payload = _exact_bytes("authenticated_final_sha3_512", authenticated_final_sha3_512, 64, nonzero=True)
        return self._append_terminal_or_round(
            receipt,
            kind=_KIND_FINAL,
            expected_record_sequence=_u32("expected_record_sequence", expected_record_sequence),
            round_index=_NO_ROUND_INDEX,
            prior_root=root,
            resulting_root=root,
            payload=payload,
            missing=(),
        )

    def append_abort(
        self,
        receipt: OpaqueCustodyReceipt,
        *,
        expected_record_sequence: int,
        round_index: int,
        prior_transcript_root: bytes,
        authenticated_abort_sha3_512: bytes,
        missing_contributor_ids: tuple[bytes, ...],
    ) -> OpaqueCustodyReceipt:
        prior = _exact_bytes("prior_transcript_root", prior_transcript_root, 64)
        payload = _exact_bytes("authenticated_abort_sha3_512", authenticated_abort_sha3_512, 64, nonzero=True)
        if type(missing_contributor_ids) is not tuple or not missing_contributor_ids:
            raise CustodyError("durable_custody_abort_requires_missing_contributors")
        for contributor_id in missing_contributor_ids:
            _exact_bytes("missing_contributor_id", contributor_id, 64, nonzero=True)
        if missing_contributor_ids != tuple(sorted(missing_contributor_ids)) or len(set(missing_contributor_ids)) != len(missing_contributor_ids):
            raise CustodyError("durable_custody_missing_contributors_not_unique_sorted")
        return self._append_terminal_or_round(
            receipt,
            kind=_KIND_ABORT,
            expected_record_sequence=_u32("expected_record_sequence", expected_record_sequence),
            round_index=_u32("round_index", round_index),
            prior_root=prior,
            resulting_root=bytes(64),
            payload=payload,
            missing=missing_contributor_ids,
        )

    def append_worker_abort(
        self,
        receipt: OpaqueCustodyReceipt,
        *,
        expected_record_sequence: int,
        round_index: int,
        prior_transcript_root: bytes,
        authenticated_abort_sha3_512: bytes,
    ) -> OpaqueCustodyReceipt:
        """Burn an attempt after a prover/worker failure without blaming a signer."""

        return self._append_terminal_or_round(
            receipt,
            kind=_KIND_ABORT,
            expected_record_sequence=_u32(
                "expected_record_sequence", expected_record_sequence
            ),
            round_index=_u32("round_index", round_index),
            prior_root=_exact_bytes(
                "prior_transcript_root", prior_transcript_root, 64
            ),
            resulting_root=bytes(64),
            payload=_exact_bytes(
                "authenticated_abort_sha3_512",
                authenticated_abort_sha3_512,
                64,
                nonzero=True,
            ),
            missing=(),
        )

    def _append_terminal_or_round(
        self,
        receipt: OpaqueCustodyReceipt,
        *,
        kind: int,
        expected_record_sequence: int,
        round_index: int,
        prior_root: bytes,
        resulting_root: bytes,
        payload: bytes,
        missing: tuple[bytes, ...],
    ) -> OpaqueCustodyReceipt:
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_locked(connection)
                _, attempt, _, session_id, _ = self._verify_receipt_locked(
                    connection, receipt, current=True
                )
                row = connection.execute(
                    "SELECT status,next_record_sequence,transcript_root FROM attempts WHERE ordinal=?",
                    (attempt,),
                ).fetchone()
                if row is None or row[0] != "OPEN":
                    raise CustodyError("durable_custody_attempt_not_open")
                if row[1] != expected_record_sequence:
                    raise CustodyError("durable_custody_record_sequence_stale")
                current_root = None if row[2] is None else bytes(row[2])
                if kind == _KIND_ROUND:
                    if current_root is not None and prior_root != current_root:
                        raise CustodyError("durable_custody_prior_transcript_root_stale")
                elif kind == _KIND_FINAL:
                    if current_root is None or prior_root != current_root:
                        raise CustodyError("durable_custody_final_transcript_root_stale")
                elif kind == _KIND_ABORT:
                    if (current_root is None and any(prior_root)) or (
                        current_root is not None and prior_root != current_root
                    ):
                        raise CustodyError("durable_custody_abort_transcript_root_stale")
                positions = {item.contributor_id: index for index, item in enumerate(self._contributors)}
                quarantined = {
                    bytes(item[0]) for item in connection.execute("SELECT contributor_id FROM quarantines")
                }
                if any(item not in positions or item in quarantined for item in missing):
                    raise CustodyError("durable_custody_abort_contributor_not_active")
                bitmap = sum(1 << positions[item] for item in missing)
                encoded = _record(
                    kind=kind,
                    attempt=attempt,
                    record_sequence=expected_record_sequence,
                    round_index=round_index,
                    session_id=session_id,
                    prior_root=prior_root,
                    resulting_root=resulting_root,
                    payload_commitment=payload,
                    quarantine_bitmap=bitmap,
                )
                receipt_token = secrets.token_bytes(32)
                event_sequence, audit_root = self._append_event(
                    connection,
                    kind=kind,
                    attempt=attempt,
                    record_sequence=expected_record_sequence,
                    encoded=encoded,
                    receipt_token_hash=_digest(_TOKEN_DOMAIN, receipt_token),
                )
                next_root = resulting_root if kind == _KIND_ROUND else current_root
                status = "OPEN" if kind == _KIND_ROUND else ("SUCCEEDED" if kind == _KIND_FINAL else "ABORTED")
                connection.execute(
                    "UPDATE attempts SET status=?,next_record_sequence=?,transcript_root=?,last_audit_root=? WHERE ordinal=?",
                    (
                        status,
                        expected_record_sequence + 1,
                        None if next_root is None else sqlite3.Binary(next_root),
                        sqlite3.Binary(audit_root),
                        attempt,
                    ),
                )
                if kind == _KIND_FINAL:
                    connection.execute("UPDATE custody_state SET completed=1 WHERE id=1")
                for contributor_id in missing:
                    connection.execute(
                        "INSERT INTO quarantines VALUES(?,?,?)",
                        (sqlite3.Binary(contributor_id), attempt, event_sequence),
                    )
                next_receipt = self._issue_receipt(
                    connection,
                    event_sequence=event_sequence,
                    kind=kind,
                    attempt=attempt,
                    record_sequence=expected_record_sequence,
                    session_id=session_id,
                    audit_root=audit_root,
                    token=receipt_token,
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return next_receipt


__all__ = [
    "ACTIVATION_ALLOWED",
    "AttemptRelease",
    "CustodyContributor",
    "CustodyError",
    "DurablePublicCoinCustody",
    "GLOBAL_PROOF_SUITE_ID",
    "MAX_ATTEMPTS_PER_STATEMENT",
    "ML_DSA_87_SUITE_ID",
    "OpaqueCustodyReceipt",
    "RecoveredOpenAttempt",
    "PRODUCTION_USABLE",
    "RECEIPT_LENGTH",
    "RECORD_LENGTH",
    "SLH_DSA_SHAKE_256F_SUITE_ID",
    "STATUS",
]
