"""Read-only owner-to-Lean adapter for the synthetic v5 workflow.

The adapter is deliberately a transaction-boundary producer, not another owner.
It accepts an already-open ``sqlite3.Connection`` from the financial owner,
reconstructs and authenticates the bounded facts needed by the semantic
engine, and returns an immutable canonical snapshot.  It never opens a
database, writes a row, advances a revision, creates a receipt, or creates a
reservation/lease table.

The owner-side snapshot envelope and the handed-off BLFIN02/BLFRES02 binary
seam are frozen here from the Engine packet.  The binary codec is deliberately
small and strict: fixed-width big-endian naturals, raw digests, bounded UTF-8
strings/lists, explicit enum tags, and no trailing bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
import sqlite3
from typing import Any, Final, Mapping

from app import right_rail_financial_owner as owner
from app import right_rail_financial_owner_independent as independent


class SemanticAdapterError(owner.FinancialError):
    """Base error for the fail-closed adapter boundary."""


class SemanticAdapterInputError(SemanticAdapterError):
    pass


class SemanticAdapterIntegrityError(SemanticAdapterError):
    pass


class SemanticAdapterAuthorityError(SemanticAdapterError):
    pass


class SemanticAdapterCodecError(SemanticAdapterError):
    pass


SEMANTIC_INPUT_SCHEMA: Final[str] = "RR/FINANCIAL/SEMANTIC-INPUT/v1"
SEMANTIC_INPUT_VERSION: Final[int] = 1
MAX_FACT_ROWS: Final[int] = 256
MAX_SNAPSHOT_BYTES: Final[int] = 4 * 1024 * 1024
MAX_RESULT_BYTES: Final[int] = 1 * 1024 * 1024
MAX_JSON_COLUMN_BYTES: Final[int] = independent.MAX_JSON_BYTES
_SNAPSHOT_DOMAIN: Final[bytes] = b"RR/FINANCIAL/SEMANTIC-INPUT/v1\x00"
_HEX_DIGEST = re.compile(r"[0-9A-F]{128}\Z")
_SCHEMA_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9./:_-]{0,127}\Z")
_RESULT_STATUSES: Final[frozenset[str]] = frozenset(
    {"CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED"}
)


def _fail(error_type: type[SemanticAdapterError], code: str) -> None:
    error = error_type(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


def _text(value: object, label: str, *, max_bytes: int = 4096) -> str:
    if type(value) is not str or not value or "\x00" in value or len(value.encode("utf-8")) > max_bytes:
        _fail(SemanticAdapterInputError, label)
    return value


def _schema_text(value: object, label: str) -> str:
    if type(value) is not str or _SCHEMA_TEXT.fullmatch(value) is None:
        _fail(SemanticAdapterInputError, label)
    return value


def _id(value: object, label: str) -> str:
    if type(value) is not str or owner._ID.fullmatch(value) is None:
        _fail(SemanticAdapterInputError, label)
    return value


def _role(value: object, label: str) -> str:
    if type(value) is not str or owner._ROLE.fullmatch(value) is None:
        _fail(SemanticAdapterInputError, label)
    return value


def _time(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 2**63:
        _fail(SemanticAdapterInputError, label)
    return value


def _cents(value: object, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or abs(value) > owner._MAX_CENTS or (positive and value <= 0):
        _fail(SemanticAdapterIntegrityError, label)
    return value


def _add(left: int, right: int, label: str = "cents_overflow") -> int:
    if type(left) is not int or type(right) is not int:
        _fail(SemanticAdapterIntegrityError, label)
    value = left + right
    if value < -owner._MAX_CENTS or value > owner._MAX_CENTS:
        _fail(SemanticAdapterIntegrityError, label)
    return value


def _blob(value: object, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        _fail(SemanticAdapterIntegrityError, label)
    return bytes(value)


def _hex(value: bytes, label: str = "digest") -> str:
    _blob(value, label)
    return value.hex().upper()


def _digest(value: str, label: str) -> bytes:
    if type(value) is not str or _HEX_DIGEST.fullmatch(value) is None:
        _fail(SemanticAdapterIntegrityError, label)
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        _fail(SemanticAdapterIntegrityError, label)
    return _blob(raw, label)


def _canonical(value: Mapping[str, Any]) -> bytes:
    try:
        return owner._canonical(value)
    except (TypeError, ValueError, OverflowError):
        _fail(SemanticAdapterIntegrityError, "canonical_value")


def _validate_json_tree(value: object, *, depth: int = 0) -> None:
    if depth > 32:
        _fail(SemanticAdapterIntegrityError, "json_depth")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > owner._MAX_CENTS:
            _fail(SemanticAdapterIntegrityError, "json_integer_range")
        return
    if type(value) is str:
        if "\x00" in value or len(value.encode("utf-8")) > 16 * 1024:
            _fail(SemanticAdapterIntegrityError, "json_text")
        return
    if type(value) is list:
        if len(value) > MAX_FACT_ROWS:
            _fail(SemanticAdapterIntegrityError, "json_list_bound")
        for item in value:
            _validate_json_tree(item, depth=depth + 1)
        return
    if type(value) is dict:
        if len(value) > 128:
            _fail(SemanticAdapterIntegrityError, "json_map_bound")
        for key, item in value.items():
            if type(key) is not str:
                _fail(SemanticAdapterIntegrityError, "json_key")
            _validate_json_tree(item, depth=depth + 1)
        return
    _fail(SemanticAdapterIntegrityError, "json_value")


def _parse_json_column(value: object, label: str, *, expected_type: type[Any] | None = None) -> Any:
    if type(value) is not str:
        _fail(SemanticAdapterIntegrityError, label)
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        _fail(SemanticAdapterIntegrityError, label)
    if not encoded or len(encoded) > MAX_JSON_COLUMN_BYTES:
        _fail(SemanticAdapterIntegrityError, label)
    try:
        parsed = json.loads(encoded.decode("ascii"))
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError):
        _fail(SemanticAdapterIntegrityError, label)
    try:
        _validate_json_tree(parsed)
        canonical = _canonical(parsed)
    except SemanticAdapterError:
        raise
    except (RecursionError, TypeError, ValueError, OverflowError):
        _fail(SemanticAdapterIntegrityError, label)
    if canonical != encoded:
        _fail(SemanticAdapterIntegrityError, label)
    if expected_type is not None and type(parsed) is not expected_type:
        _fail(SemanticAdapterIntegrityError, label)
    return parsed


def _wrapped_values(value: object, label: str) -> list[Any]:
    parsed = _parse_json_column(value, label, expected_type=dict)
    if set(parsed) != {"values"} or type(parsed["values"]) is not list or not parsed["values"]:
        _fail(SemanticAdapterIntegrityError, label)
    return list(parsed["values"])


def _row_map(row: sqlite3.Row, columns: tuple[str, ...]) -> dict[str, Any]:
    return {column: row[column] for column in columns}


def _bounded_rows(
    connection: sqlite3.Connection,
    query: str,
    args: tuple[Any, ...],
    *,
    label: str,
    limit: int,
) -> list[sqlite3.Row]:
    rows = connection.execute(f"{query} LIMIT ?", (*args, limit + 1)).fetchall()
    if len(rows) > limit:
        _fail(SemanticAdapterIntegrityError, f"{label}_bound")
    return rows


def _require_connection(connection: object) -> sqlite3.Connection:
    if type(connection) is not sqlite3.Connection:
        _fail(SemanticAdapterInputError, "connection_type")
    if not connection.in_transaction:
        _fail(SemanticAdapterInputError, "transaction_required")
    if connection.row_factory is not sqlite3.Row:
        _fail(SemanticAdapterInputError, "row_factory_required")
    return connection


@dataclass(frozen=True, slots=True)
class TrustedAuthorityContext:
    """Authenticated authority material supplied for this semantic read.

    ``source`` is explicit so a historical row is never silently rebound to
    the current ``financial_meta`` authority.  The digest is recomputed from
    the supplied actors; callers cannot provide a synthetic ``verified`` bit
    or make a copied digest authoritative.
    """

    authority_id: str
    epoch: int
    actors: tuple[owner.AuthorityActor, ...]
    digest: bytes
    source: str = "CURRENT"

    def __post_init__(self) -> None:
        _id(self.authority_id, "authority_context_id")
        if type(self.epoch) is not int or self.epoch < 1:
            _fail(SemanticAdapterInputError, "authority_context_epoch")
        if type(self.actors) is not tuple or not self.actors:
            _fail(SemanticAdapterInputError, "authority_context_actors")
        if any(type(actor) is not owner.AuthorityActor for actor in self.actors):
            _fail(SemanticAdapterInputError, "authority_context_actor_type")
        if len({actor.actor_id for actor in self.actors}) != len(self.actors):
            _fail(SemanticAdapterInputError, "authority_context_actor_duplicate")
        if self.source not in {"CURRENT", "HISTORICAL"}:
            _fail(SemanticAdapterInputError, "authority_context_source")
        supplied = _blob(self.digest, "authority_context_digest")
        try:
            reconstructed = owner.SyntheticTrustedAuthority(
                authority_id=self.authority_id,
                epoch=self.epoch,
                actors=self.actors,
            ).digest
        except owner.FinancialError:
            _fail(SemanticAdapterInputError, "authority_context_actors")
        if supplied != reconstructed:
            _fail(SemanticAdapterAuthorityError, "authority_context_digest")

    @classmethod
    def from_authority(
        cls,
        authority: owner.SyntheticTrustedAuthority,
        *,
        source: str = "CURRENT",
    ) -> "TrustedAuthorityContext":
        if type(authority) is not owner.SyntheticTrustedAuthority:
            _fail(SemanticAdapterInputError, "authority_context_type")
        return cls(
            authority_id=authority.authority_id,
            epoch=authority.epoch,
            actors=authority.actors,
            digest=authority.digest,
            source=source,
        )

    def has_role(self, actor_id: str, actor_role: str) -> bool:
        return any(actor.actor_id == actor_id and actor_role in actor.roles for actor in self.actors)

    @property
    def actor_roles(self) -> list[dict[str, Any]]:
        return [
            {"actor_id": actor.actor_id, "roles": list(actor.roles)}
            for actor in self.actors
        ]


    @property
    def authority(self) -> owner.SyntheticTrustedAuthority:
        """Return a freshly reconstructed authority for the checker seam."""

        try:
            return owner.SyntheticTrustedAuthority(
                authority_id=self.authority_id,
                epoch=self.epoch,
                actors=self.actors,
            )
        except owner.FinancialError:
            _fail(SemanticAdapterAuthorityError, "authority_context_reconstruction")


_SNAPSHOT_VALIDATION_TOKEN: Final[object] = object()


@dataclass(frozen=True, slots=True, init=False)
class LockedSemanticSnapshot:
    """Immutable canonical owner-side snapshot handed to the Engine."""

    canonical_bytes: bytes
    snapshot_digest: bytes
    obligation_id: str
    pre_evaluation_revision: int
    evaluation_time_ms: int
    _validation_token: object = field(default=None, repr=False, compare=False)

    def __init__(
        self,
        canonical_bytes: bytes,
        snapshot_digest: bytes,
        obligation_id: str,
        pre_evaluation_revision: int,
        evaluation_time_ms: int,
        *,
        _validation_token: object | None = None,
    ) -> None:
        if _validation_token is not _SNAPSHOT_VALIDATION_TOKEN:
            _fail(SemanticAdapterAuthorityError, "snapshot_unverified")
        object.__setattr__(self, "canonical_bytes", canonical_bytes)
        object.__setattr__(self, "snapshot_digest", snapshot_digest)
        object.__setattr__(self, "obligation_id", obligation_id)
        object.__setattr__(self, "pre_evaluation_revision", pre_evaluation_revision)
        object.__setattr__(self, "evaluation_time_ms", evaluation_time_ms)
        object.__setattr__(self, "_validation_token", _SNAPSHOT_VALIDATION_TOKEN)
        if type(self.canonical_bytes) is not bytes or not self.canonical_bytes:
            _fail(SemanticAdapterCodecError, "snapshot_bytes")
        if len(self.canonical_bytes) > MAX_SNAPSHOT_BYTES:
            _fail(SemanticAdapterCodecError, "snapshot_size")
        _blob(self.snapshot_digest, "snapshot_digest")
        _id(self.obligation_id, "snapshot_obligation")
        if type(self.pre_evaluation_revision) is not int or not 0 <= self.pre_evaluation_revision <= owner._MAX_ROWS:
            _fail(SemanticAdapterCodecError, "snapshot_revision")
        _time(self.evaluation_time_ms, "snapshot_time")
        body, digest, obligation_id, revision, evaluation_time = _decode_snapshot_body(self.canonical_bytes)
        del body
        if digest != self.snapshot_digest:
            _fail(SemanticAdapterCodecError, "snapshot_digest")
        if obligation_id != self.obligation_id or revision != self.pre_evaluation_revision or evaluation_time != self.evaluation_time_ms:
            _fail(SemanticAdapterCodecError, "snapshot_binding")

    @property
    def data(self) -> dict[str, Any]:
        return json.loads(self.canonical_bytes.decode("ascii"))


def _require_validated_snapshot(snapshot: object, label: str = "snapshot_type") -> LockedSemanticSnapshot:
    if type(snapshot) is not LockedSemanticSnapshot:
        _fail(SemanticAdapterInputError, label)
    if snapshot._validation_token is not _SNAPSHOT_VALIDATION_TOKEN:
        _fail(SemanticAdapterAuthorityError, "snapshot_unverified")
    return snapshot


def _decode_canonical_object(payload: bytes, *, max_bytes: int, error_type: type[SemanticAdapterError], prefix: str) -> dict[str, Any]:
    if type(payload) is not bytes or not payload or len(payload) > max_bytes:
        _fail(error_type, f"{prefix}_size")
    try:
        text = payload.decode("ascii")
        value = json.loads(text)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError):
        _fail(error_type, f"{prefix}_json")
    if type(value) is not dict:
        _fail(error_type, f"{prefix}_shape")
    try:
        _validate_json_tree(value)
        if _canonical(value) != payload:
            _fail(error_type, f"{prefix}_canonical")
    except SemanticAdapterError:
        raise
    except (RecursionError, UnicodeEncodeError, TypeError, ValueError, OverflowError):
        _fail(error_type, f"{prefix}_canonical")
    return value


def _decode_snapshot_body(payload: bytes) -> tuple[dict[str, Any], bytes, str, int, int]:
    body = _decode_canonical_object(
        payload,
        max_bytes=MAX_SNAPSHOT_BYTES,
        error_type=SemanticAdapterCodecError,
        prefix="snapshot",
    )
    required = {
        "schema",
        "version",
        "scope",
        "owner",
        "authority",
        "evaluation_time_ms",
        "pre_evaluation",
        "population",
        "population_item",
        "control_pack",
        "obligation",
        "evidence",
        "payments",
        "claims",
        "determinations",
        "cases",
        "actions",
        "action_outbox",
        "conflicts",
        "evaluations",
        "current_evaluation",
        "snapshot_digest",
    }
    if set(body) != required or body["schema"] != SEMANTIC_INPUT_SCHEMA or body["version"] != SEMANTIC_INPUT_VERSION:
        _fail(SemanticAdapterCodecError, "snapshot_contract")
    snapshot_digest = _digest(body["snapshot_digest"], "snapshot_digest")
    unsigned = dict(body)
    del unsigned["snapshot_digest"]
    expected = owner._digest(_SNAPSHOT_DOMAIN, _canonical(unsigned))
    if snapshot_digest != expected or body["snapshot_digest"] != _hex(expected):
        _fail(SemanticAdapterCodecError, "snapshot_digest")
    pre = body["pre_evaluation"]
    if type(pre) is not dict or set(pre) != {"obligation_id", "item_id", "revision"}:
        _fail(SemanticAdapterCodecError, "snapshot_pre_evaluation")
    obligation_id = _id(pre["obligation_id"], "snapshot_obligation")
    if type(pre["revision"]) is not int or not 0 <= pre["revision"] <= owner._MAX_ROWS:
        _fail(SemanticAdapterCodecError, "snapshot_revision")
    evaluation_time = _time(body["evaluation_time_ms"], "snapshot_time")
    if type(pre["item_id"]) is not str:
        _fail(SemanticAdapterCodecError, "snapshot_item")
    return body, snapshot_digest, obligation_id, pre["revision"], evaluation_time


def decode_locked_snapshot(
    payload: bytes,
    *,
    connection: sqlite3.Connection,
    obligation_id: str,
    authority_context: TrustedAuthorityContext,
    evaluation_time_ms: int,
    expected_config: object,
    expected_scope: object,
    expected_mode: str,
    expected_owner_id: str,
    expected_continuity_epoch: int | None = None,
    max_fact_rows: int = MAX_FACT_ROWS,
) -> LockedSemanticSnapshot:
    """Rebuild a snapshot from the owner transaction before accepting bytes."""

    _decode_snapshot_body(payload)
    rebuilt = build_locked_semantic_snapshot(
        connection,
        obligation_id=obligation_id,
        authority_context=authority_context,
        evaluation_time_ms=evaluation_time_ms,
        expected_config=expected_config,
        expected_scope=expected_scope,
        expected_mode=expected_mode,
        expected_owner_id=expected_owner_id,
        expected_continuity_epoch=expected_continuity_epoch,
        max_fact_rows=max_fact_rows,
    )
    if rebuilt.canonical_bytes != payload:
        _fail(SemanticAdapterCodecError, "snapshot_owner_binding")
    return rebuilt


def encode_locked_snapshot(snapshot: LockedSemanticSnapshot) -> bytes:
    """Return the already-authenticated immutable canonical snapshot bytes."""

    return bytes(_require_validated_snapshot(snapshot).canonical_bytes)


BLFIN02_MAGIC: Final[bytes] = b"BLFIN02"
BLFRES02_MAGIC: Final[bytes] = b"BLFRES02"
MAX_WIRE_BYTES: Final[int] = 8 * 1024 * 1024
MAX_WIRE_LIST: Final[int] = 10_000
_U64_MAX: Final[int] = (1 << 64) - 1

_MODE_TAGS: Final[dict[str, int]] = {"LIVE": 1, "SHADOW": 2, "TEST": 3}
_PROVENANCE_TAGS: Final[dict[str, int]] = {"ROOT": 1, "CONTINUITY_RESTORE": 2}
_PACK_STATUS_TAGS: Final[dict[str, int]] = {"APPROVED": 1, "REVOKED": 2}
_PAYMENT_STATUS_TAGS: Final[dict[str, int]] = {"ACTIVE": 1, "REVERSED": 2}
_CLAIM_STATUS_TAGS: Final[dict[str, int]] = {"CLAIMED": 1, "AUTHORIZED": 2, "REJECTED": 3}
_DECISION_TAGS: Final[dict[str, int]] = {
    "OFFSET_AUTHORIZED": 1,
    "OFFSET_REJECTED_CORRECTION_AUTHORIZED": 2,
}
_CASE_STATUS_TAGS: Final[dict[str, int]] = {
    "OPEN": 1,
    "AUTHORIZED": 2,
    "CORRECTION_REQUIRED": 3,
    "ACTIONED": 4,
    "RESOLVED": 5,
}
_ACTION_STATUS_TAGS: Final[dict[str, int]] = {"READY": 1, "ACKNOWLEDGED": 2, "CANCELLED": 3}
_VERIFICATION_STATUS_TAGS: Final[dict[str, int]] = {
    "MISSING_EVIDENCE": 1,
    "SUPPORTED": 2,
    "CONFLICT_VISIBLE": 3,
}
_DELIVERY_STATUS_TAGS: Final[dict[str, int]] = {
    "NONE": 1,
    "READY": 2,
    "ACKNOWLEDGED": 3,
    "CANCELLED": 4,
}


def _wire_id(value: object, label: str) -> str:
    if type(value) is not str or owner._ID.fullmatch(value) is None or len(value.encode("utf-8")) > 128:
        _fail(SemanticAdapterCodecError, label)
    return value


def _wire_role(value: object, label: str) -> str:
    if type(value) is not str or owner._ROLE.fullmatch(value) is None or len(value.encode("utf-8")) > 128:
        _fail(SemanticAdapterCodecError, label)
    return value


def _wire_text(value: object, label: str, *, max_bytes: int = 512) -> str:
    if type(value) is not str or not value or "\x00" in value:
        _fail(SemanticAdapterCodecError, label)
    encoded = value.encode("utf-8")
    if len(encoded) > max_bytes or len(encoded) > 0xFFFF:
        _fail(SemanticAdapterCodecError, label)
    return value


def _wire_nat(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value > _U64_MAX:
        _fail(SemanticAdapterCodecError, label)
    return value


def _wire_digest(value: object, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        _fail(SemanticAdapterCodecError, label)
    return bytes(value)


def _wire_hex_digest(value: object, label: str) -> bytes:
    if type(value) is not str or _HEX_DIGEST.fullmatch(value) is None:
        _fail(SemanticAdapterCodecError, label)
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        _fail(SemanticAdapterCodecError, label)
    return _wire_digest(raw, label)


def _wire_tag(tags: Mapping[str, int], value: object, label: str) -> int:
    if type(value) is not str or value not in tags:
        _fail(SemanticAdapterCodecError, label)
    return tags[value]


def _wire_mapping(value: object, label: str, keys: set[str] | None = None) -> dict[str, Any]:
    if type(value) is not dict or (keys is not None and set(value) != keys):
        _fail(SemanticAdapterCodecError, label)
    return value


class _WireWriter:
    def __init__(self) -> None:
        self._buffer = bytearray()

    def raw(self, value: bytes, label: str) -> None:
        if type(value) is not bytes:
            _fail(SemanticAdapterCodecError, label)
        self._buffer.extend(value)

    def byte(self, value: int, label: str) -> None:
        if type(value) is not int or not 0 <= value <= 0xFF:
            _fail(SemanticAdapterCodecError, label)
        self._buffer.append(value)

    def nat(self, value: object, label: str) -> None:
        self._buffer.extend(_wire_nat(value, label).to_bytes(8, "big"))

    def count(self, value: object, label: str) -> None:
        if type(value) is not int or not 0 <= value <= MAX_WIRE_LIST or value > 0xFFFF:
            _fail(SemanticAdapterCodecError, label)
        self._buffer.extend(value.to_bytes(2, "big"))

    def string(self, value: object, label: str, *, max_bytes: int = 512) -> None:
        text = _wire_text(value, label, max_bytes=max_bytes)
        encoded = text.encode("utf-8")
        self.count(len(encoded), f"{label}_length")
        self.raw(encoded, label)

    def identifier(self, value: object, label: str) -> None:
        self.string(_wire_id(value, label), label, max_bytes=128)

    def role(self, value: object, label: str) -> None:
        self.string(_wire_role(value, label), label, max_bytes=128)

    def digest(self, value: object, label: str) -> None:
        self.raw(_wire_digest(value, label), label)

    def boolean(self, value: object, label: str) -> None:
        if type(value) is not bool:
            _fail(SemanticAdapterCodecError, label)
        self.byte(1 if value else 0, label)

    def option_nat(self, value: object, label: str) -> None:
        if value is None:
            self.byte(0, label)
            return
        self.byte(1, label)
        self.nat(value, label)

    def option_identifier(self, value: object, label: str) -> None:
        if value is None:
            self.byte(0, label)
            return
        self.byte(1, label)
        self.identifier(value, label)

    def list(self, values: object, label: str, encode_item: Any) -> None:
        if type(values) is not list or len(values) > MAX_WIRE_LIST:
            _fail(SemanticAdapterCodecError, label)
        self.count(len(values), label)
        for index, value in enumerate(values):
            encode_item(value, f"{label}_{index}")

    def finish(self, *, label: str) -> bytes:
        if len(self._buffer) > MAX_WIRE_BYTES:
            _fail(SemanticAdapterCodecError, label)
        return bytes(self._buffer)


class _WireReader:
    def __init__(self, payload: bytes, *, max_bytes: int) -> None:
        if type(payload) is not bytes or not payload or len(payload) > max_bytes:
            _fail(SemanticAdapterCodecError, "wire_size")
        self._payload = payload
        self._offset = 0

    def take(self, size: int, label: str) -> bytes:
        if type(size) is not int or size < 0 or self._offset + size > len(self._payload):
            _fail(SemanticAdapterCodecError, label)
        value = self._payload[self._offset : self._offset + size]
        self._offset += size
        return value

    def byte(self, label: str) -> int:
        return self.take(1, label)[0]

    def nat(self, label: str) -> int:
        return int.from_bytes(self.take(8, label), "big")

    def count(self, label: str) -> int:
        value = int.from_bytes(self.take(2, label), "big")
        if value > MAX_WIRE_LIST:
            _fail(SemanticAdapterCodecError, label)
        return value

    def string(self, label: str, *, max_bytes: int = 512) -> str:
        size = int.from_bytes(self.take(2, f"{label}_length"), "big")
        if size > max_bytes:
            _fail(SemanticAdapterCodecError, label)
        raw = self.take(size, label)
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            _fail(SemanticAdapterCodecError, label)
        if value.encode("utf-8") != raw:
            _fail(SemanticAdapterCodecError, label)
        return _wire_text(value, label, max_bytes=max_bytes)

    def identifier(self, label: str) -> str:
        return _wire_id(self.string(label, max_bytes=128), label)

    def role(self, label: str) -> str:
        return _wire_role(self.string(label, max_bytes=128), label)

    def digest(self, label: str) -> bytes:
        return _wire_digest(self.take(64, label), label)

    def boolean(self, label: str) -> bool:
        value = self.byte(label)
        if value not in (0, 1):
            _fail(SemanticAdapterCodecError, label)
        return bool(value)

    def option_nat(self, label: str) -> int | None:
        tag = self.byte(label)
        if tag == 0:
            return None
        if tag != 1:
            _fail(SemanticAdapterCodecError, label)
        return self.nat(label)

    def option_identifier(self, label: str) -> str | None:
        tag = self.byte(label)
        if tag == 0:
            return None
        if tag != 1:
            _fail(SemanticAdapterCodecError, label)
        return self.identifier(label)

    def list(self, label: str, decode_item: Any) -> list[Any]:
        count = self.count(label)
        return [decode_item(f"{label}_{index}") for index in range(count)]

    def finish(self) -> None:
        if self._offset != len(self._payload):
            _fail(SemanticAdapterCodecError, "wire_trailing_bytes")


def _write_tag(writer: _WireWriter, tags: Mapping[str, int], value: object, label: str) -> None:
    writer.byte(_wire_tag(tags, value, label), label)


def _read_tag(reader: _WireReader, tags: Mapping[str, int], label: str) -> str:
    tag = reader.byte(label)
    inverse = {number: name for name, number in tags.items()}
    if tag not in inverse:
        _fail(SemanticAdapterCodecError, label)
    return inverse[tag]


def _write_id_list(writer: _WireWriter, values: object, label: str) -> None:
    writer.list(values, label, lambda value, item_label: writer.identifier(value, item_label))


def _write_text_list(writer: _WireWriter, values: object, label: str) -> None:
    writer.list(values, label, lambda value, item_label: writer.string(value, item_label))


def _write_context(
    writer: _WireWriter,
    *,
    owner_id: object,
    mode: object,
    provenance: object,
    state_id: object,
    deployment_id: object,
    program_id: object,
    period_id: object,
    population_id: object,
    item_id: object,
    obligation_id: object,
    currency: object,
) -> None:
    writer.identifier(owner_id, "owner_id")
    _write_tag(writer, _MODE_TAGS, mode, "mode")
    _write_tag(writer, _PROVENANCE_TAGS, provenance, "provenance")
    writer.identifier(state_id, "state_id")
    writer.identifier(deployment_id, "deployment_id")
    writer.identifier(program_id, "program_id")
    writer.identifier(period_id, "period_id")
    writer.identifier(population_id, "population_id")
    writer.identifier(item_id, "item_id")
    writer.identifier(obligation_id, "obligation_id")
    writer.string(currency, "currency", max_bytes=128)


def _write_authority(writer: _WireWriter, authority: Mapping[str, Any]) -> None:
    writer.identifier(authority["authority_id"], "authority_id")
    writer.nat(authority["epoch"], "authority_epoch")
    writer.digest(_wire_hex_digest(authority["digest"], "authority_digest"), "authority_digest")
    writer.boolean(True, "synthetic_only")
    actors = authority["actors"]

    def encode_actor(value: object, label: str) -> None:
        actor = _wire_mapping(value, label, {"actor_id", "roles"})
        writer.identifier(actor["actor_id"], f"{label}_id")
        _write_id_list(writer, actor["roles"], f"{label}_roles")

    writer.list(actors, "authority_actors", encode_actor)


def _write_control_pack(writer: _WireWriter, pack: Mapping[str, Any], currency: object) -> None:
    wrapper = _wire_mapping(pack, "control_pack", {"status", "canonical_fields", "digest"})
    fields = _wire_mapping(
        wrapper["canonical_fields"],
        "control_pack_fields",
        {
            "pack_id", "state_id", "deployment_id", "program_id", "period_id", "version",
            "source_refs", "effective_start_ms", "effective_end_ms", "recorded_at_ms", "approved_at_ms",
            "calculation_rule_id", "adjustment_rule_id", "authorized_roles", "expected_tests",
        },
    )
    writer.identifier(fields["pack_id"], "pack_id")
    writer.identifier(fields["state_id"], "pack_state_id")
    writer.identifier(fields["deployment_id"], "pack_deployment_id")
    writer.identifier(fields["program_id"], "pack_program_id")
    writer.identifier(fields["period_id"], "pack_period_id")
    writer.string(currency, "pack_currency", max_bytes=128)
    writer.nat(fields["version"], "pack_version")
    _write_text_list(writer, fields["source_refs"], "pack_source_refs")
    writer.nat(fields["effective_start_ms"], "pack_effective_start")
    writer.nat(fields["effective_end_ms"], "pack_effective_end")
    writer.nat(fields["recorded_at_ms"], "pack_recorded_at")
    writer.nat(fields["approved_at_ms"], "pack_approved_at")
    writer.identifier(fields["calculation_rule_id"], "pack_calculation_rule")
    writer.identifier(fields["adjustment_rule_id"], "pack_adjustment_rule")
    writer.list(fields["authorized_roles"], "pack_authorized_roles", lambda value, label: writer.role(value, label))
    _write_text_list(writer, fields["expected_tests"], "pack_expected_tests")
    expected_digest = owner._digest(owner._EVIDENCE_DOMAIN, _canonical(fields))
    stored_digest = _wire_hex_digest(wrapper["digest"], "pack_digest")
    if stored_digest != expected_digest:
        _fail(SemanticAdapterIntegrityError, "pack_digest")
    writer.digest(stored_digest, "pack_digest")
    _write_tag(writer, _PACK_STATUS_TAGS, wrapper["status"], "pack_status")


def _write_obligation(writer: _WireWriter, obligation: Mapping[str, Any]) -> None:
    writer.identifier(obligation["population_id"], "obligation_population_id")
    writer.identifier(obligation["item_id"], "obligation_item_id")
    writer.identifier(obligation["obligation_id"], "obligation_id")
    writer.nat(obligation["owed_cents"], "obligation_owed_cents")
    writer.nat(obligation["due_at_ms"], "obligation_due_at")
    writer.nat(obligation["rule_version"], "obligation_rule_version")
    writer.boolean(obligation["reporting_complete"], "obligation_reporting_complete")


def _write_payments(writer: _WireWriter, payments: object) -> None:
    def encode_payment(value: object, label: str) -> None:
        payment = _wire_mapping(value, label)
        for key, field_label in (
            ("payment_id", "payment_id"), ("obligation_id", "payment_obligation_id"),
            ("item_id", "payment_item_id"), ("evidence_id", "payment_evidence_id"),
            ("common_origin_id", "payment_origin"),
        ):
            writer.identifier(payment[key], f"{label}_{field_label}")
        writer.nat(payment["amount_cents"], f"{label}_amount")
        writer.nat(payment["event_at_ms"], f"{label}_event_at")
        writer.option_identifier(payment["reversed_by_evidence_id"], f"{label}_reversed_by")
        active = payment["active"]
        status = "ACTIVE" if active == 1 else "REVERSED" if active == 0 else None
        _write_tag(writer, _PAYMENT_STATUS_TAGS, status, f"{label}_status")

    writer.list(payments, "payments", encode_payment)


def _write_claims(writer: _WireWriter, claims: object) -> None:
    def encode_claim(value: object, label: str) -> None:
        claim = _wire_mapping(value, label)
        for key, field_label in (
            ("claim_id", "claim_id"), ("obligation_id", "claim_obligation_id"),
            ("evidence_id", "claim_evidence_id"),
        ):
            writer.identifier(claim[key], f"{label}_{field_label}")
        writer.nat(claim["amount_cents"], f"{label}_amount")
        writer.role(claim["owner_role"], f"{label}_owner_role")
        writer.nat(claim["deadline_ms"], f"{label}_deadline")
        _write_tag(writer, _CLAIM_STATUS_TAGS, claim["status"], f"{label}_status")

    writer.list(claims, "claims", encode_claim)


def _write_determinations(writer: _WireWriter, determinations: object) -> None:
    def encode_determination(value: object, label: str) -> None:
        determination = _wire_mapping(value, label)
        for key, field_label in (
            ("determination_id", "determination_id"), ("obligation_id", "determination_obligation_id"),
            ("claim_id", "determination_claim_id"), ("actor_id", "determination_actor_id"),
        ):
            writer.identifier(determination[key], f"{label}_{field_label}")
        writer.role(determination["actor_role"], f"{label}_actor_role")
        writer.identifier(determination["authority_id"], f"{label}_authority_id")
        writer.nat(determination["authority_epoch"], f"{label}_authority_epoch")
        writer.digest(_wire_hex_digest(determination["authority_digest"], f"{label}_authority_digest"), f"{label}_authority_digest")
        _write_tag(writer, _DECISION_TAGS, determination["decision"], f"{label}_decision")
        writer.nat(determination["amount_cents"], f"{label}_amount")
        bindings = determination["supporting_evidence"]
        if type(bindings) is not list:
            _fail(SemanticAdapterCodecError, f"{label}_supporting_evidence")
        writer.list(
            bindings,
            f"{label}_supporting_evidence",
            lambda binding, binding_label: writer.identifier(
                _wire_mapping(binding, binding_label, {"evidence_id", "record_digest"})["evidence_id"],
                binding_label,
            ),
        )
        writer.nat(determination["expected_revision"], f"{label}_expected_revision")
        writer.nat(determination["resulting_revision"], f"{label}_resulting_revision")
        writer.nat(determination["decided_at_ms"], f"{label}_decided_at")

    writer.list(determinations, "determinations", encode_determination)


def _write_evidence(writer: _WireWriter, evidence: object, *, obligation_id: object) -> None:
    def encode_evidence(value: object, label: str) -> None:
        record = _wire_mapping(value, label)
        writer.identifier(record["evidence_id"], f"{label}_evidence_id")
        writer.identifier(obligation_id, f"{label}_obligation_id")
        writer.identifier(record["item_id"], f"{label}_item_id")
        writer.string(record["kind"], f"{label}_kind")
        writer.identifier(record["common_origin_id"], f"{label}_common_origin_id")
        writer.string(record["source_id"], f"{label}_source_id")
        writer.string(record["source_version"], f"{label}_source_version")
        writer.string(record["local_ref"], f"{label}_local_ref")
        writer.nat(record["applicable_at_ms"], f"{label}_applicable_at")
        writer.nat(record["event_at_ms"], f"{label}_event_at")
        writer.nat(record["received_at_ms"], f"{label}_received_at")
        writer.option_nat(record["amount_cents"], f"{label}_amount")
        writer.option_identifier(record["reversal_of"], f"{label}_reversal_of")
        writer.option_identifier(record["supersedes"], f"{label}_supersedes")

    writer.list(evidence, "evidence", encode_evidence)


def _write_conflicts(writer: _WireWriter, conflicts: object) -> None:
    def encode_conflict(value: object, label: str) -> None:
        conflict = _wire_mapping(value, label)
        for key, field_label in (
            ("conflict_id", "conflict_id"), ("obligation_id", "conflict_obligation_id"),
            ("common_origin_id", "conflict_origin"), ("existing_payment_id", "conflict_payment_id"),
            ("candidate_evidence_id", "conflict_evidence_id"),
        ):
            writer.identifier(conflict[key], f"{label}_{field_label}")
        writer.nat(conflict["existing_amount_cents"], f"{label}_existing_amount")
        writer.nat(conflict["candidate_amount_cents"], f"{label}_candidate_amount")
        writer.string(conflict["reason"], f"{label}_reason")
        writer.nat(conflict["visible_at_ms"], f"{label}_visible_at")


    writer.list(conflicts, "conflicts", encode_conflict)


def _write_cases(writer: _WireWriter, cases: object) -> None:
    def encode_case(value: object, label: str) -> None:
        case = _wire_mapping(value, label)
        writer.identifier(case["case_id"], f"{label}_case_id")
        writer.identifier(case["obligation_id"], f"{label}_obligation_id")
        writer.string(case["reason"], f"{label}_reason")
        writer.role(case["next_action_owner"], f"{label}_next_action_owner")
        writer.nat(case["due_at_ms"], f"{label}_due_at")
        _write_tag(writer, _CASE_STATUS_TAGS, case["status"], f"{label}_status")
        writer.nat(case["updated_at_ms"], f"{label}_updated_at")

    writer.list(cases, "cases", encode_case)


def _write_actions(writer: _WireWriter, actions: object, *, currency: object) -> None:
    def encode_action(value: object, label: str) -> None:
        action = _wire_mapping(value, label)
        writer.identifier(action["action_id"], f"{label}_action_id")
        writer.identifier(action["obligation_id"], f"{label}_obligation_id")
        writer.option_identifier(action["determination_id"], f"{label}_determination_id")
        writer.identifier(action["kind"], f"{label}_kind")
        payload = _wire_mapping(action["payload"], f"{label}_payload")
        writer.nat(payload["amount_cents"], f"{label}_amount")
        writer.string(payload["currency"], f"{label}_currency", max_bytes=128)
        if payload["currency"] != currency:
            _fail(SemanticAdapterIntegrityError, f"{label}_currency")
        writer.nat(action["revision"], f"{label}_revision")
        _write_tag(writer, _ACTION_STATUS_TAGS, action["status"], f"{label}_status")
        writer.digest(_wire_hex_digest(action["payload_digest"], f"{label}_payload_digest"), f"{label}_payload_digest")
        writer.nat(action["created_at_ms"], f"{label}_created_at")

    writer.list(actions, "actions", encode_action)


def encode_blfin02_input(snapshot: LockedSemanticSnapshot) -> bytes:
    """Encode one authenticated owner snapshot using the Engine BLFIN02 wire contract."""

    snapshot = _require_validated_snapshot(snapshot)
    data = snapshot.data
    try:
        scope = _wire_mapping(data["scope"], "scope", {"state_id", "deployment_id", "program_id", "period_id", "currency"})
        owner_body = _wire_mapping(data["owner"], "owner")
        pre = _wire_mapping(data["pre_evaluation"], "pre_evaluation", {"obligation_id", "item_id", "revision"})
        authority = _wire_mapping(data["authority"], "authority")
        obligation = _wire_mapping(data["obligation"], "obligation")
        population = _wire_mapping(data["population"], "population")
        writer = _WireWriter()
        writer.raw(BLFIN02_MAGIC, "input_magic")
        _write_context(
            writer,
            owner_id=owner_body["owner_id"],
            mode=owner_body["mode"],
            provenance=owner_body["provenance"],
            state_id=scope["state_id"],
            deployment_id=scope["deployment_id"],
            program_id=scope["program_id"],
            period_id=scope["period_id"],
            population_id=population["population_id"],
            item_id=pre["item_id"],
            obligation_id=pre["obligation_id"],
            currency=scope["currency"],
        )
        _write_authority(writer, authority)
        _write_control_pack(writer, data["control_pack"], scope["currency"])
        _write_obligation(writer, obligation)
        writer.nat(pre["revision"], "before_revision")
        writer.nat(data["evaluation_time_ms"], "evaluated_at")
        _write_payments(writer, data["payments"])
        _write_claims(writer, data["claims"])
        _write_determinations(writer, data["determinations"])
        _write_evidence(writer, data["evidence"], obligation_id=pre["obligation_id"])
        _write_conflicts(writer, data["conflicts"])
        _write_cases(writer, data["cases"])
        _write_actions(writer, data["actions"], currency=scope["currency"])
        return writer.finish(label="input_size")
    except SemanticAdapterError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, OverflowError):
        _fail(SemanticAdapterCodecError, "input_record_shape")


@dataclass(frozen=True, slots=True)
class DecodedLeanResult:
    owner_id: str
    mode: str
    provenance: str
    state_id: str
    deployment_id: str
    program_id: str
    period_id: str
    population_id: str
    item_id: str
    obligation_id: str
    currency: str
    authority_id: str
    authority_epoch: int
    authority_digest: bytes
    pack_id: str
    pack_digest: bytes
    before_revision: int
    after_revision: int
    evaluated_at_ms: int
    rule_version: int
    evidence_ids: tuple[str, ...]
    completion_at_ms: int | None
    owed_cents: int
    claimed_adjustment_cents: int
    lawful_adjustment_cents: int
    received_cash_cents: int
    shortfall_cents: int
    overage_cents: int
    cash_satisfied: bool
    amount_satisfied: bool
    timely: bool
    reporting_complete: bool
    verification_status: str
    case_status: str
    delivery_status: str


def _encode_blfres02_result(result: DecodedLeanResult) -> bytes:
    writer = _WireWriter()
    writer.raw(BLFRES02_MAGIC, "result_magic")
    _write_context(
        writer,
        owner_id=result.owner_id,
        mode=result.mode,
        provenance=result.provenance,
        state_id=result.state_id,
        deployment_id=result.deployment_id,
        program_id=result.program_id,
        period_id=result.period_id,
        population_id=result.population_id,
        item_id=result.item_id,
        obligation_id=result.obligation_id,
        currency=result.currency,
    )
    writer.identifier(result.authority_id, "authority_id")
    writer.nat(result.authority_epoch, "authority_epoch")
    writer.digest(result.authority_digest, "authority_digest")
    writer.identifier(result.pack_id, "pack_id")
    writer.digest(result.pack_digest, "pack_digest")
    writer.nat(result.before_revision, "before_revision")
    writer.nat(result.after_revision, "after_revision")
    writer.nat(result.evaluated_at_ms, "evaluated_at")
    writer.nat(result.rule_version, "rule_version")
    _write_id_list(writer, list(result.evidence_ids), "evidence_ids")
    writer.option_nat(result.completion_at_ms, "completion_at")
    for field in (
        "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents",
        "received_cash_cents", "shortfall_cents", "overage_cents",
    ):
        writer.nat(getattr(result, field), field)
    for field in ("cash_satisfied", "amount_satisfied", "timely", "reporting_complete"):
        writer.boolean(getattr(result, field), field)
    _write_tag(writer, _VERIFICATION_STATUS_TAGS, result.verification_status, "verification_status")
    _write_tag(writer, _CASE_STATUS_TAGS, result.case_status, "case_status")
    _write_tag(writer, _DELIVERY_STATUS_TAGS, result.delivery_status, "delivery_status")
    return writer.finish(label="result_size")


def _completion_time_from_snapshot(data: Mapping[str, Any]) -> int | None:
    obligation = _wire_mapping(data["obligation"], "obligation")
    entries: list[tuple[int, int]] = []
    for determination in data["determinations"]:
        if determination["decision"] == "OFFSET_AUTHORIZED":
            entries.append((determination["decided_at_ms"], determination["amount_cents"]))
    for payment in data["payments"]:
        if payment["active"] == 1:
            entries.append((payment["event_at_ms"], payment["amount_cents"]))
    total = 0
    for at_ms, amount in sorted(entries, key=lambda value: (value[0], value[1])):
        total = _add(total, amount)
        if total >= obligation["owed_cents"]:
            return at_ms
    active_cash = 0
    for payment in data["payments"]:
        if payment["active"] == 1:
            active_cash = _add(active_cash, payment["amount_cents"])
    if _add(obligation["lawful_adjustment_cents"], active_cash) >= obligation["owed_cents"] and entries:
        return max(value[0] for value in entries)
    return None


def _validate_decoded_result(result: DecodedLeanResult, snapshot: LockedSemanticSnapshot) -> None:
    data = snapshot.data
    scope = _wire_mapping(data["scope"], "scope")
    owner_body = _wire_mapping(data["owner"], "owner")
    authority = _wire_mapping(data["authority"], "authority")
    pre = _wire_mapping(data["pre_evaluation"], "pre_evaluation")
    population = _wire_mapping(data["population"], "population")
    pack = _wire_mapping(data["control_pack"], "control_pack")
    pack_fields = _wire_mapping(pack["canonical_fields"], "control_pack_fields")
    obligation = _wire_mapping(data["obligation"], "obligation")
    current = _wire_mapping(data["current_evaluation"], "current_evaluation")
    receipt = _wire_mapping(current["receipt"], "current_receipt")
    expected_context = (
        owner_body["owner_id"], owner_body["mode"], owner_body["provenance"],
        scope["state_id"], scope["deployment_id"], scope["program_id"], scope["period_id"],
        population["population_id"], pre["item_id"], pre["obligation_id"], scope["currency"],
    )
    actual_context = (
        result.owner_id, result.mode, result.provenance, result.state_id, result.deployment_id,
        result.program_id, result.period_id, result.population_id, result.item_id,
        result.obligation_id, result.currency,
    )
    if actual_context != expected_context:
        _fail(SemanticAdapterCodecError, "result_context_binding")
    if (result.authority_id, result.authority_epoch, result.authority_digest) != (
        authority["authority_id"], authority["epoch"], _wire_hex_digest(authority["digest"], "authority_digest"),
    ):
        _fail(SemanticAdapterAuthorityError, "result_authority_binding")
    if (result.pack_id, result.pack_digest) != (pack_fields["pack_id"], _wire_hex_digest(pack["digest"], "pack_digest")):
        _fail(SemanticAdapterIntegrityError, "result_pack_binding")
    if result.before_revision != pre["revision"] or result.after_revision != pre["revision"] + 1:
        _fail(SemanticAdapterCodecError, "result_revision_binding")
    if result.evaluated_at_ms != data["evaluation_time_ms"]:
        _fail(SemanticAdapterCodecError, "result_time_binding")
    if result.rule_version != obligation["rule_version"] or result.rule_version != pack_fields["version"]:
        _fail(SemanticAdapterIntegrityError, "result_rule_version")
    expected_evidence_ids = tuple(receipt["evidence_ids"])
    if result.evidence_ids != expected_evidence_ids:
        _fail(SemanticAdapterIntegrityError, "result_evidence_ids")
    if result.completion_at_ms != _completion_time_from_snapshot(data):
        _fail(SemanticAdapterIntegrityError, "result_completion")
    expected_values = {
        "owed_cents": obligation["owed_cents"],
        "claimed_adjustment_cents": obligation["claimed_adjustment_cents"],
        "lawful_adjustment_cents": obligation["lawful_adjustment_cents"],
        "received_cash_cents": obligation["received_cash_cents"],
        "shortfall_cents": obligation["shortfall_cents"],
        "overage_cents": obligation["overage_cents"],
        "cash_satisfied": obligation["cash_satisfied"],
        "amount_satisfied": obligation["amount_satisfied"],
        "timely": obligation["timely"],
        "reporting_complete": obligation["reporting_complete"],
        "verification_status": obligation["verification_status"],
        "case_status": obligation["case_status"],
        "delivery_status": obligation["delivery_status"],
    }
    for field, expected_value in expected_values.items():
        if getattr(result, field) != expected_value:
            _fail(SemanticAdapterIntegrityError, f"result_{field}")


def decode_blfres02_result(
    payload: bytes,
    *,
    expected_snapshot: LockedSemanticSnapshot,
) -> DecodedLeanResult:
    """Decode, canonically re-encode, and bind one Engine BLFRES02 result."""

    expected_snapshot = _require_validated_snapshot(expected_snapshot, "result_snapshot_type")
    reader = _WireReader(payload, max_bytes=MAX_RESULT_BYTES)
    if reader.take(len(BLFRES02_MAGIC), "result_magic") != BLFRES02_MAGIC:
        _fail(SemanticAdapterCodecError, "result_magic")
    try:
        context = {
            "owner_id": reader.identifier("owner_id"),
            "mode": _read_tag(reader, _MODE_TAGS, "mode"),
            "provenance": _read_tag(reader, _PROVENANCE_TAGS, "provenance"),
            "state_id": reader.identifier("state_id"),
            "deployment_id": reader.identifier("deployment_id"),
            "program_id": reader.identifier("program_id"),
            "period_id": reader.identifier("period_id"),
            "population_id": reader.identifier("population_id"),
            "item_id": reader.identifier("item_id"),
            "obligation_id": reader.identifier("obligation_id"),
            "currency": reader.string("currency", max_bytes=128),
        }
        result = DecodedLeanResult(
            **context,
            authority_id=reader.identifier("authority_id"),
            authority_epoch=reader.nat("authority_epoch"),
            authority_digest=reader.digest("authority_digest"),
            pack_id=reader.identifier("pack_id"),
            pack_digest=reader.digest("pack_digest"),
            before_revision=reader.nat("before_revision"),
            after_revision=reader.nat("after_revision"),
            evaluated_at_ms=reader.nat("evaluated_at"),
            rule_version=reader.nat("rule_version"),
            evidence_ids=tuple(reader.list("evidence_ids", lambda label: reader.identifier(label))),
            completion_at_ms=reader.option_nat("completion_at"),
            owed_cents=reader.nat("owed_cents"),
            claimed_adjustment_cents=reader.nat("claimed_adjustment_cents"),
            lawful_adjustment_cents=reader.nat("lawful_adjustment_cents"),
            received_cash_cents=reader.nat("received_cash_cents"),
            shortfall_cents=reader.nat("shortfall_cents"),
            overage_cents=reader.nat("overage_cents"),
            cash_satisfied=reader.boolean("cash_satisfied"),
            amount_satisfied=reader.boolean("amount_satisfied"),
            timely=reader.boolean("timely"),
            reporting_complete=reader.boolean("reporting_complete"),
            verification_status=_read_tag(reader, _VERIFICATION_STATUS_TAGS, "verification_status"),
            case_status=_read_tag(reader, _CASE_STATUS_TAGS, "case_status"),
            delivery_status=_read_tag(reader, _DELIVERY_STATUS_TAGS, "delivery_status"),
        )
        reader.finish()
        _validate_decoded_result(result, expected_snapshot)
        if _encode_blfres02_result(result) != payload:
            _fail(SemanticAdapterCodecError, "result_canonical")
        return result
    except SemanticAdapterError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, OverflowError):
        _fail(SemanticAdapterCodecError, "result_record_shape")


def encode_blfres02_result(result: DecodedLeanResult) -> bytes:
    """Encode a fully typed result for deterministic vectors and round trips."""

    if type(result) is not DecodedLeanResult:
        _fail(SemanticAdapterInputError, "result_type")
    return _encode_blfres02_result(result)


encode_lean_input = encode_blfin02_input
decode_engine_result = decode_blfres02_result


def _verify_owner_connection(
    connection: sqlite3.Connection,
    *,
    expected_config: object,
    expected_scope: object,
    authority_context: TrustedAuthorityContext,
    expected_mode: str,
    expected_owner_id: str,
    expected_continuity_epoch: int | None,
) -> dict[str, object]:
    """Use the existing independent verifier as the database trust boundary."""

    try:
        return independent.verify_database_connection(
            connection,
            expected_config=expected_config,
            expected_scope=expected_scope,
            expected_authority=authority_context.authority,
            expected_mode=expected_mode,
            expected_owner_id=expected_owner_id,
            expected_continuity_epoch=expected_continuity_epoch,
        )
    except independent.IndependentFinancialError as error:
        code = str(error)
        if code in {
            "meta:authority-binding",
            "meta:mode-binding",
            "meta:owner-binding",
            "identity:meta-binding",
        }:
            _fail(SemanticAdapterAuthorityError, f"owner_verifier:{code}")
        _fail(SemanticAdapterIntegrityError, f"owner_verifier:{code}")


def _read_verified_identity(connection: sqlite3.Connection) -> dict[str, Any]:
    """Materialize identity fields after the independent checker has passed."""

    rows = connection.execute("SELECT * FROM financial_identity WHERE id=1").fetchall()
    if len(rows) != 1:
        _fail(SemanticAdapterIntegrityError, "identity_cardinality")
    row = rows[0]
    identity = _row_map(row, owner._TABLE_COLUMNS["financial_identity"])
    anchor_head = _blob(identity["anchor_head"], "identity_anchor_head")
    genesis_head = _blob(identity["genesis_head"], "identity_genesis_head")
    source_digest = _blob(identity["source_package_digest"], "identity_source_digest")
    identity_digest = _blob(identity["identity_digest"], "identity_digest")
    return {
        "id": 1,
        "schema_version": int(identity["schema_version"]),
        "provenance": str(identity["provenance"]),
        "bound_mode": str(identity["bound_mode"]),
        "bound_owner_id": str(identity["bound_owner_id"]),
        "anchor_sequence": int(identity["anchor_sequence"]),
        "anchor_head": _hex(anchor_head),
        "genesis_head": _hex(genesis_head),
        "source_package_digest": _hex(source_digest),
        "identity_digest": _hex(identity_digest),
    }


def _read_verified_meta(
    connection: sqlite3.Connection,
    verification: Mapping[str, object],
) -> tuple[dict[str, str], dict[str, Any]]:
    """Read only material needed for the snapshot after independent verification."""

    raw_scope = verification.get("scope")
    if not isinstance(raw_scope, Mapping):
        _fail(SemanticAdapterIntegrityError, "owner_verifier:scope-shape")
    scope = {
        "state_id": _id(raw_scope.get("state_id"), "scope_state"),
        "deployment_id": _id(raw_scope.get("deployment_id"), "scope_deployment"),
        "program_id": _id(raw_scope.get("program_id"), "scope_program"),
        "period_id": _id(raw_scope.get("period_id"), "scope_period"),
        "currency": str(raw_scope.get("currency")),
    }
    owner_id = _id(verification.get("owner_id"), "meta_owner")
    mode = str(verification.get("mode"))
    return scope, {"owner_id": owner_id, "mode": mode, **_read_verified_identity(connection)}


def _load_population_and_pack(
    connection: sqlite3.Connection,
    obligation: sqlite3.Row,
    scope: Mapping[str, str],
) -> tuple[dict[str, Any], dict[str, Any], owner.ControlPack]:
    population_id = _id(obligation["population_id"], "population_id")
    population_rows = connection.execute(
        "SELECT * FROM population_imports WHERE population_id=?",
        (population_id,),
    ).fetchall()
    if len(population_rows) != 1:
        _fail(SemanticAdapterIntegrityError, "population_missing")
    population = population_rows[0]
    if population["status"] != "PUBLISHED" or population["source_complete"] != 1:
        _fail(SemanticAdapterIntegrityError, "population_status")
    expected_count = population["expected_count"]
    imported_count = population["imported_count"]
    validated_count = population["validated_count"]
    if type(expected_count) is not int or not 1 <= expected_count <= owner._MAX_ROWS or imported_count != expected_count or validated_count != expected_count:
        _fail(SemanticAdapterIntegrityError, "population_counts")
    inclusion_rules = _wrapped_values(population["inclusion_rules_json"], "population_rules")
    if any(type(value) is not str for value in inclusion_rules):
        _fail(SemanticAdapterIntegrityError, "population_rules")
    validation_digest = _blob(population["validation_digest"], "population_validation_digest")
    item_rows = connection.execute(
        "SELECT * FROM population_items WHERE population_id=? AND item_id=?",
        (population_id, obligation["item_id"]),
    ).fetchall()
    if len(item_rows) != 1:
        _fail(SemanticAdapterIntegrityError, "population_item_missing")
    item = item_rows[0]
    if tuple(item[column] for column in ("currency", "owed_cents", "due_at_ms")) != tuple(obligation[column] for column in ("currency", "owed_cents", "due_at_ms")):
        _fail(SemanticAdapterIntegrityError, "population_item_binding")
    pack_rows = connection.execute(
        "SELECT * FROM control_packs WHERE pack_id=? AND status='APPROVED'",
        (population["pack_id"],),
    ).fetchall()
    if len(pack_rows) != 1:
        _fail(SemanticAdapterIntegrityError, "control_pack_missing")
    row = pack_rows[0]
    source_refs = _wrapped_values(row["source_refs_json"], "control_pack_source_refs")
    authorized_roles = _wrapped_values(row["authorized_roles_json"], "control_pack_roles")
    expected_tests = _wrapped_values(row["expected_tests_json"], "control_pack_tests")
    if any(type(value) is not str for value in (*source_refs, *authorized_roles, *expected_tests)):
        _fail(SemanticAdapterIntegrityError, "control_pack_values")
    try:
        pack = owner.ControlPack(
            pack_id=str(row["pack_id"]),
            state_id=str(row["state_id"]),
            deployment_id=str(row["deployment_id"]),
            program_id=str(row["program_id"]),
            period_id=str(row["period_id"]),
            version=int(row["version"]),
            source_refs=tuple(source_refs),
            effective_start_ms=int(row["effective_start_ms"]),
            effective_end_ms=int(row["effective_end_ms"]),
            recorded_at_ms=int(row["recorded_at_ms"]),
            approved_at_ms=int(row["approved_at_ms"]),
            calculation_rule_id=str(row["calculation_rule_id"]),
            adjustment_rule_id=str(row["adjustment_rule_id"]),
            authorized_roles=tuple(authorized_roles),
            expected_tests=tuple(expected_tests),
        )
        owner._control_pack_policy(
            calculation_rule_id=pack.calculation_rule_id,
            adjustment_rule_id=pack.adjustment_rule_id,
            authorized_roles=pack.authorized_roles,
            expected_tests=pack.expected_tests,
        )
    except owner.FinancialError:
        _fail(SemanticAdapterIntegrityError, "control_pack_contract")
    stored_pack_digest = _blob(row["pack_digest"], "control_pack_digest")
    if stored_pack_digest != pack.digest or pack.state_id != scope["state_id"] or pack.deployment_id != scope["deployment_id"] or pack.program_id != scope["program_id"] or pack.period_id != scope["period_id"]:
        _fail(SemanticAdapterIntegrityError, "control_pack_binding")
    if int(obligation["rule_version"]) != pack.version:
        _fail(SemanticAdapterIntegrityError, "control_pack_rule_version")
    population_body = {
        "population_id": population_id,
        "pack_id": str(population["pack_id"]),
        "cutoff_ms": _time(population["cutoff_ms"], "population_cutoff"),
        "inclusion_rules": inclusion_rules,
        "expected_count": expected_count,
        "source_complete": True,
        "imported_count": imported_count,
        "validated_count": validated_count,
        "validation_digest": _hex(validation_digest),
        "status": "PUBLISHED",
    }
    item_body = {
        "population_id": population_id,
        "item_id": _id(item["item_id"], "population_item_id"),
        "display_label": _text(item["display_label"], "population_item_label", max_bytes=128),
        "owed_cents": _cents(item["owed_cents"], "population_item_owed", positive=True),
        "due_at_ms": _time(item["due_at_ms"], "population_item_due"),
        "currency": str(item["currency"]),
    }
    pack_body = json.loads(pack.canonical_bytes.decode("ascii"))
    return population_body, {
        "status": "APPROVED",
        "canonical_fields": pack_body,
        "digest": _hex(stored_pack_digest),
    }, pack


def _load_obligation(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    scope: Mapping[str, str],
    evaluation_time_ms: int,
) -> tuple[sqlite3.Row, dict[str, Any]]:
    _id(obligation_id, "obligation_id")
    rows = connection.execute("SELECT * FROM obligations WHERE obligation_id=?", (obligation_id,)).fetchall()
    if len(rows) != 1:
        _fail(SemanticAdapterIntegrityError, "obligation_missing")
    row = rows[0]
    if str(row["period_id"]) != scope["period_id"] or str(row["currency"]) != scope["currency"]:
        _fail(SemanticAdapterIntegrityError, "obligation_scope")
    if _id(row["item_id"], "obligation_item") is None:
        _fail(SemanticAdapterIntegrityError, "obligation_item")
    if type(row["revision"]) is not int or not 0 <= row["revision"] <= owner._MAX_ROWS:
        _fail(SemanticAdapterIntegrityError, "obligation_revision")
    _time(row["updated_at_ms"], "obligation_updated")
    if int(row["updated_at_ms"]) > evaluation_time_ms:
        _fail(SemanticAdapterIntegrityError, "obligation_after_evaluation")
    for field in ("owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents"):
        _cents(row[field], f"obligation_{field}")
    for field in ("cash_satisfied", "amount_satisfied", "timely", "reporting_complete"):
        if row[field] not in (0, 1):
            _fail(SemanticAdapterIntegrityError, f"obligation_{field}")
    body = {
        "obligation_id": str(row["obligation_id"]),
        "population_id": str(row["population_id"]),
        "item_id": str(row["item_id"]),
        "period_id": str(row["period_id"]),
        "currency": str(row["currency"]),
        "owed_cents": int(row["owed_cents"]),
        "due_at_ms": _time(row["due_at_ms"], "obligation_due"),
        "rule_version": int(row["rule_version"]),
        "revision": int(row["revision"]),
        "claimed_adjustment_cents": int(row["claimed_adjustment_cents"]),
        "lawful_adjustment_cents": int(row["lawful_adjustment_cents"]),
        "received_cash_cents": int(row["received_cash_cents"]),
        "shortfall_cents": int(row["shortfall_cents"]),
        "overage_cents": int(row["overage_cents"]),
        "cash_satisfied": bool(row["cash_satisfied"]),
        "amount_satisfied": bool(row["amount_satisfied"]),
        "timely": bool(row["timely"]),
        "reporting_complete": bool(row["reporting_complete"]),
        "verification_status": str(row["verification_status"]),
        "case_status": str(row["case_status"]),
        "delivery_status": str(row["delivery_status"]),
        "current_evaluation_id": None if row["current_evaluation_id"] is None else str(row["current_evaluation_id"]),
        "updated_at_ms": int(row["updated_at_ms"]),
    }
    return row, body


def _load_evidence(
    connection: sqlite3.Connection,
    *,
    item_id: str,
    evaluation_time_ms: int,
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    rows = _bounded_rows(
        connection,
        "SELECT evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,content_digest,record_digest,amount_cents,reversal_of,supersedes FROM evidence WHERE item_id=? ORDER BY evidence_id",
        (item_id,),
        label="evidence",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        content_digest = _blob(row["content_digest"], "evidence_content_digest")
        record_digest = _blob(row["record_digest"], "evidence_record_digest")
        amount = None if row["amount_cents"] is None else _cents(row["amount_cents"], "evidence_amount", positive=True)
        try:
            record = owner.EvidenceRecord(
                evidence_id=str(row["evidence_id"]),
                item_id=str(row["item_id"]),
                kind=str(row["kind"]),
                common_origin_id=str(row["common_origin_id"]),
                source_id=str(row["source_id"]),
                source_version=str(row["source_version"]),
                local_ref=str(row["local_ref"]),
                applicable_at_ms=int(row["applicable_at_ms"]),
                event_at_ms=int(row["event_at_ms"]),
                received_at_ms=int(row["received_at_ms"]),
                content_digest=content_digest,
                amount_cents=amount,
                reversal_of=None if row["reversal_of"] is None else str(row["reversal_of"]),
                supersedes=None if row["supersedes"] is None else str(row["supersedes"]),
            )
        except owner.FinancialError:
            _fail(SemanticAdapterIntegrityError, "evidence_contract")
        expected_content = owner._digest(
            owner._EVIDENCE_DOMAIN,
            _canonical(
                {
                    "source_id": record.source_id,
                    "source_version": record.source_version,
                    "local_ref": record.local_ref,
                    "common_origin_id": record.common_origin_id,
                    "kind": record.kind,
                }
            ),
        )
        if content_digest != expected_content or record_digest != record.record_digest:
            _fail(SemanticAdapterIntegrityError, "evidence_digest")
        if record.item_id != item_id or record.applicable_at_ms > evaluation_time_ms or record.received_at_ms > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "evidence_time_binding")
        body = {
            "evidence_id": record.evidence_id,
            "item_id": record.item_id,
            "kind": record.kind,
            "common_origin_id": record.common_origin_id,
            "source_id": record.source_id,
            "source_version": record.source_version,
            "local_ref": record.local_ref,
            "applicable_at_ms": record.applicable_at_ms,
            "event_at_ms": record.event_at_ms,
            "received_at_ms": record.received_at_ms,
            "content_digest": _hex(content_digest),
            "record_digest": _hex(record_digest),
            "amount_cents": amount,
            "reversal_of": record.reversal_of,
            "supersedes": record.supersedes,
        }
        by_id[record.evidence_id] = body
        result.append(body)
    return result, by_id


def _load_payments(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    item_id: str,
    evidence: Mapping[str, Mapping[str, Any]],
    evaluation_time_ms: int,
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    rows = _bounded_rows(
        connection,
        "SELECT payment_id,obligation_id,item_id,evidence_id,common_origin_id,amount_cents,event_at_ms,active,reversed_by_evidence_id FROM payments WHERE obligation_id=? ORDER BY payment_id",
        (obligation_id,),
        label="payments",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    origins: set[str] = set()
    for row in rows:
        payment_id = _id(row["payment_id"], "payment_id")
        if str(row["item_id"]) != item_id or str(row["obligation_id"]) != obligation_id:
            _fail(SemanticAdapterIntegrityError, "payment_scope")
        amount = _cents(row["amount_cents"], "payment_amount", positive=True)
        event_at = _time(row["event_at_ms"], "payment_event")
        if event_at > evaluation_time_ms or row["active"] not in (0, 1):
            _fail(SemanticAdapterIntegrityError, "payment_time_status")
        origin = _id(row["common_origin_id"], "payment_origin")
        if origin in origins:
            _fail(SemanticAdapterIntegrityError, "payment_origin_duplicate")
        origins.add(origin)
        evidence_id = _id(row["evidence_id"], "payment_evidence")
        evidence_row = evidence.get(evidence_id)
        if evidence_row is None or evidence_row["item_id"] != item_id or evidence_row["common_origin_id"] != origin or evidence_row["amount_cents"] != amount:
            _fail(SemanticAdapterIntegrityError, "payment_evidence_binding")
        reversed_by = None if row["reversed_by_evidence_id"] is None else _id(row["reversed_by_evidence_id"], "payment_reversal")
        if row["active"] == 1 and reversed_by is not None:
            _fail(SemanticAdapterIntegrityError, "payment_active_reversal")
        if row["active"] == 0:
            if reversed_by is None or reversed_by not in evidence or evidence[reversed_by]["kind"] != "PAYMENT_REVERSAL" or evidence[reversed_by]["reversal_of"] != payment_id:
                _fail(SemanticAdapterIntegrityError, "payment_reversal_binding")
        body = {
            "payment_id": payment_id,
            "obligation_id": obligation_id,
            "item_id": item_id,
            "evidence_id": evidence_id,
            "common_origin_id": origin,
            "amount_cents": amount,
            "event_at_ms": event_at,
            "active": int(row["active"]),
            "reversed_by_evidence_id": reversed_by,
        }
        by_id[payment_id] = body
        result.append(body)
    for evidence_row in evidence.values():
        if evidence_row["kind"] != "PAYMENT_REVERSAL":
            continue
        target_id = evidence_row["reversal_of"]
        target = by_id.get(target_id)
        if target is None or target["item_id"] != item_id or evidence_row["amount_cents"] != target["amount_cents"] or target["active"] != 0:
            _fail(SemanticAdapterIntegrityError, "payment_reversal_evidence")
    return result, by_id


def _load_claims(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    evidence: Mapping[str, Mapping[str, Any]],
    evaluation_time_ms: int,
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    rows = _bounded_rows(
        connection,
        "SELECT claim_id,obligation_id,evidence_id,amount_cents,owner_role,deadline_ms,status,created_at_ms,updated_at_ms FROM claimed_adjustments WHERE obligation_id=? ORDER BY claim_id",
        (obligation_id,),
        label="claims",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        claim_id = _id(row["claim_id"], "claim_id")
        if str(row["obligation_id"]) != obligation_id:
            _fail(SemanticAdapterIntegrityError, "claim_scope")
        evidence_id = _id(row["evidence_id"], "claim_evidence")
        evidence_row = evidence.get(evidence_id)
        amount = _cents(row["amount_cents"], "claim_amount", positive=True)
        if evidence_row is None or evidence_row["kind"] != "OFFSET_CLAIM" or evidence_row["amount_cents"] != amount:
            _fail(SemanticAdapterIntegrityError, "claim_evidence_binding")
        role = _role(row["owner_role"], "claim_owner_role")
        status = str(row["status"])
        if status not in {"CLAIMED", "AUTHORIZED", "REJECTED"}:
            _fail(SemanticAdapterIntegrityError, "claim_status")
        deadline = _time(row["deadline_ms"], "claim_deadline")
        created = _time(row["created_at_ms"], "claim_created")
        updated = _time(row["updated_at_ms"], "claim_updated")
        if created > evaluation_time_ms or updated > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "claim_time_binding")
        body = {
            "claim_id": claim_id,
            "obligation_id": obligation_id,
            "evidence_id": evidence_id,
            "amount_cents": amount,
            "owner_role": role,
            "deadline_ms": deadline,
            "status": status,
            "created_at_ms": created,
            "updated_at_ms": updated,
        }
        by_id[claim_id] = body
        result.append(body)
    return result, by_id


def _load_cases(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    pack: owner.ControlPack,
    evaluation_time_ms: int,
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    rows = _bounded_rows(
        connection,
        "SELECT case_id,obligation_id,reason,contractual_accountability,next_action_owner,due_at_ms,completion_conditions_json,status,updated_at_ms FROM cases WHERE obligation_id=? ORDER BY case_id",
        (obligation_id,),
        label="cases",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        case_id = _id(row["case_id"], "case_id")
        owner_role = _role(row["next_action_owner"], "case_owner_role")
        if owner_role not in pack.authorized_roles or str(row["obligation_id"]) != obligation_id:
            _fail(SemanticAdapterAuthorityError, "case_owner_role")
        conditions = _parse_json_column(row["completion_conditions_json"], "case_conditions", expected_type=dict)
        status = str(row["status"])
        if status not in {"OPEN", "AUTHORIZED", "ACTIONED", "CORRECTION_REQUIRED", "RESOLVED"}:
            _fail(SemanticAdapterIntegrityError, "case_status")
        updated = _time(row["updated_at_ms"], "case_updated")
        if updated > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "case_time_binding")
        body = {
            "case_id": case_id,
            "obligation_id": obligation_id,
            "reason": _id(row["reason"], "case_reason"),
            "contractual_accountability": _id(row["contractual_accountability"], "case_accountability"),
            "next_action_owner": owner_role,
            "due_at_ms": _time(row["due_at_ms"], "case_due"),
            "completion_conditions": conditions,
            "status": status,
            "updated_at_ms": updated,
        }
        by_id[case_id] = body
        result.append(body)
    if not result:
        _fail(SemanticAdapterIntegrityError, "case_missing")
    return result, by_id


def _load_actions(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    evaluation_time_ms: int,
    limit: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    rows = _bounded_rows(
        connection,
        "SELECT action_id,obligation_id,determination_id,kind,status,revision,payload_json,payload_digest,idempotency_key,created_at_ms FROM actions WHERE obligation_id=? ORDER BY action_id",
        (obligation_id,),
        label="actions",
        limit=limit,
    )
    outbox_rows = _bounded_rows(
        connection,
        "SELECT action_id,status,attempt,payload_digest,acknowledgment_ref,updated_at_ms FROM action_outbox WHERE action_id IN (SELECT action_id FROM actions WHERE obligation_id=?) ORDER BY action_id",
        (obligation_id,),
        label="action_outbox",
        limit=limit,
    )
    outbox_by_id: dict[str, dict[str, Any]] = {}
    for row in outbox_rows:
        action_id = _id(row["action_id"], "outbox_action")
        if action_id in outbox_by_id:
            _fail(SemanticAdapterIntegrityError, "outbox_duplicate")
        if row["status"] not in {"READY", "ACKNOWLEDGED"} or type(row["attempt"]) is not int or row["attempt"] < 0 or row["attempt"] > owner._MAX_ROWS:
            _fail(SemanticAdapterIntegrityError, "outbox_status")
        payload_digest = _blob(row["payload_digest"], "outbox_payload_digest")
        updated = _time(row["updated_at_ms"], "outbox_updated")
        if updated > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "outbox_time_binding")
        acknowledgment = None if row["acknowledgment_ref"] is None else _id(row["acknowledgment_ref"], "acknowledgment_ref")
        outbox_by_id[action_id] = {
            "action_id": action_id,
            "status": str(row["status"]),
            "attempt": int(row["attempt"]),
            "payload_digest": _hex(payload_digest),
            "acknowledgment_ref": acknowledgment,
            "updated_at_ms": updated,
        }
    result: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        action_id = _id(row["action_id"], "action_id")
        status = str(row["status"])
        if str(row["obligation_id"]) != obligation_id or status not in {"READY", "ACKNOWLEDGED"}:
            _fail(SemanticAdapterIntegrityError, "action_status")
        revision = row["revision"]
        if type(revision) is not int or not 0 <= revision <= owner._MAX_ROWS:
            _fail(SemanticAdapterIntegrityError, "action_revision")
        payload = _parse_json_column(row["payload_json"], "action_payload", expected_type=dict)
        payload_digest = _blob(row["payload_digest"], "action_payload_digest")
        if payload_digest != owner._digest(owner._ACTION_DOMAIN, row["payload_json"].encode("ascii")):
            _fail(SemanticAdapterIntegrityError, "action_payload_digest")
        idempotency = _blob(row["idempotency_key"], "action_idempotency")
        if idempotency != owner._digest(owner._IDEMPOTENCY_DOMAIN, action_id.encode("ascii")):
            _fail(SemanticAdapterIntegrityError, "action_idempotency")
        created = _time(row["created_at_ms"], "action_created")
        if created > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "action_time_binding")
        if action_id not in outbox_by_id or outbox_by_id[action_id]["payload_digest"] != _hex(payload_digest) or outbox_by_id[action_id]["status"] != status:
            _fail(SemanticAdapterIntegrityError, "action_outbox_binding")
        body = {
            "action_id": action_id,
            "obligation_id": obligation_id,
            "determination_id": _id(row["determination_id"], "action_determination"),
            "kind": _id(row["kind"], "action_kind"),
            "status": status,
            "revision": int(revision),
            "payload": payload,
            "payload_digest": _hex(payload_digest),
            "idempotency_key": _hex(idempotency),
            "created_at_ms": created,
        }
        by_id[action_id] = body
        result.append(body)
    for action_id, outbox in outbox_by_id.items():
        if outbox["status"] == "ACKNOWLEDGED" and outbox["acknowledgment_ref"] is None:
            _fail(SemanticAdapterIntegrityError, "outbox_acknowledgment")
        if outbox["status"] == "READY" and outbox["acknowledgment_ref"] is not None:
            _fail(SemanticAdapterIntegrityError, "outbox_acknowledgment")
    return result, list(outbox_by_id.values()), by_id


def _load_conflicts(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    item_id: str,
    evidence: Mapping[str, Mapping[str, Any]],
    payments: Mapping[str, Mapping[str, Any]],
    evaluation_time_ms: int,
    limit: int,
) -> list[dict[str, Any]]:
    rows = _bounded_rows(
        connection,
        "SELECT conflict_id,obligation_id,common_origin_id,existing_payment_id,candidate_evidence_id,existing_amount_cents,candidate_amount_cents,reason,visible_at_ms FROM financial_conflicts WHERE obligation_id=? ORDER BY conflict_id",
        (obligation_id,),
        label="conflicts",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    for row in rows:
        conflict_id = _id(row["conflict_id"], "conflict_id")
        common_origin = _id(row["common_origin_id"], "conflict_origin")
        existing_payment_id = _id(row["existing_payment_id"], "conflict_payment")
        candidate_evidence_id = _id(row["candidate_evidence_id"], "conflict_evidence")
        existing = payments.get(existing_payment_id)
        candidate = evidence.get(candidate_evidence_id)
        if str(row["obligation_id"]) != obligation_id or existing is None or candidate is None:
            _fail(SemanticAdapterIntegrityError, "conflict_binding")
        existing_amount = _cents(row["existing_amount_cents"], "conflict_existing_amount", positive=True)
        candidate_amount = _cents(row["candidate_amount_cents"], "conflict_candidate_amount", positive=True)
        if existing["common_origin_id"] != common_origin or candidate["item_id"] != item_id or candidate["common_origin_id"] != common_origin or existing_amount != existing["amount_cents"] or candidate_amount != candidate["amount_cents"] or existing_amount == candidate_amount or row["reason"] != "CONFLICTING_COMMON_ORIGIN_AMOUNT":
            _fail(SemanticAdapterIntegrityError, "conflict_binding")
        visible = _time(row["visible_at_ms"], "conflict_visible")
        if visible > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "conflict_time_binding")
        result.append(
            {
                "conflict_id": conflict_id,
                "obligation_id": obligation_id,
                "common_origin_id": common_origin,
                "existing_payment_id": existing_payment_id,
                "candidate_evidence_id": candidate_evidence_id,
                "existing_amount_cents": existing_amount,
                "candidate_amount_cents": candidate_amount,
                "reason": "CONFLICTING_COMMON_ORIGIN_AMOUNT",
                "visible_at_ms": visible,
            }
        )
    return result


def _load_evaluations(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    obligation: sqlite3.Row,
    scope: Mapping[str, str],
    pack: owner.ControlPack,
    authority_context: TrustedAuthorityContext,
    evidence: Mapping[str, Mapping[str, Any]],
    evaluation_time_ms: int,
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, Any]]:
    rows = _bounded_rows(
        connection,
        "SELECT evaluation_id,obligation_id,revision,rule_version,evidence_ids_json,authority_id,evaluated_at_ms,owed_cents,claimed_adjustment_cents,lawful_adjustment_cents,received_cash_cents,shortfall_cents,overage_cents,cash_satisfied,amount_satisfied,timely,reporting_complete,verification_status,case_status,delivery_status,result_digest,contract_version,scope_json,control_pack_id,control_pack_version,control_pack_digest,authority_epoch,authority_digest,evidence_bindings_json,input_snapshot_json,input_snapshot_digest,receipt_digest FROM evaluations WHERE obligation_id=? ORDER BY revision",
        (obligation_id,),
        label="evaluations",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    revisions: list[int] = []
    for row in rows:
        if str(row["obligation_id"]) != obligation_id or str(row["contract_version"]) != owner._EVALUATION_RECEIPT_CONTRACT:
            _fail(SemanticAdapterIntegrityError, "evaluation_contract")
        evaluation_id = _id(row["evaluation_id"], "evaluation_id")
        revision = row["revision"]
        if type(revision) is not int or not 0 <= revision <= owner._MAX_ROWS:
            _fail(SemanticAdapterIntegrityError, "evaluation_revision")
        evaluated_at = _time(row["evaluated_at_ms"], "evaluation_time")
        if evaluated_at > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "evaluation_time_binding")
        authority_id = _id(row["authority_id"], "evaluation_authority_id")
        authority_epoch = row["authority_epoch"]
        if type(authority_epoch) is not int or authority_epoch < 1:
            _fail(SemanticAdapterIntegrityError, "evaluation_authority_epoch")
        authority_digest = _blob(row["authority_digest"], "evaluation_authority_digest")
        if (authority_id, authority_epoch, authority_digest) != (authority_context.authority_id, authority_context.epoch, authority_context.digest):
            _fail(SemanticAdapterAuthorityError, "evaluation_authority_stale")
        evidence_ids_value = _parse_json_column(row["evidence_ids_json"], "evaluation_evidence_ids", expected_type=dict)
        bindings_value = _parse_json_column(row["evidence_bindings_json"], "evaluation_bindings", expected_type=dict)
        scope_value = _parse_json_column(row["scope_json"], "evaluation_scope", expected_type=dict)
        input_snapshot = _parse_json_column(row["input_snapshot_json"], "evaluation_input", expected_type=dict)
        if set(evidence_ids_value) != {"evidence_ids"} or type(evidence_ids_value["evidence_ids"]) is not list:
            _fail(SemanticAdapterIntegrityError, "evaluation_evidence_ids")
        evidence_ids = evidence_ids_value["evidence_ids"]
        if any(type(value) is not str for value in evidence_ids) or evidence_ids != sorted(evidence_ids) or len(set(evidence_ids)) != len(evidence_ids):
            _fail(SemanticAdapterIntegrityError, "evaluation_evidence_ids")
        if set(bindings_value) != {"bindings"} or type(bindings_value["bindings"]) is not list:
            _fail(SemanticAdapterIntegrityError, "evaluation_bindings")
        bindings = bindings_value["bindings"]
        if [binding.get("evidence_id") for binding in bindings if type(binding) is dict] != evidence_ids or any(type(binding) is not dict or set(binding) != {"evidence_id", "record_digest"} for binding in bindings):
            _fail(SemanticAdapterIntegrityError, "evaluation_bindings")
        for binding in bindings:
            evidence_row = evidence.get(binding["evidence_id"])
            if evidence_row is None or binding["record_digest"] != evidence_row["record_digest"]:
                _fail(SemanticAdapterIntegrityError, "evaluation_bindings")
            _digest(binding["record_digest"], "evaluation_binding_digest")
        if scope_value != dict(scope):
            _fail(SemanticAdapterIntegrityError, "evaluation_scope")
        if type(input_snapshot.get("pre_revision")) is not int or input_snapshot["pre_revision"] != (revision if revision == 0 else revision - 1):
            _fail(SemanticAdapterIntegrityError, "evaluation_input_revision")
        input_digest = _blob(row["input_snapshot_digest"], "evaluation_input_digest")
        if input_digest != owner._digest(owner._EVALUATION_INPUT_DOMAIN, _canonical(input_snapshot)):
            _fail(SemanticAdapterIntegrityError, "evaluation_input_digest")
        stored_pack_digest = _blob(row["control_pack_digest"], "evaluation_pack_digest")
        if str(row["control_pack_id"]) != pack.pack_id or row["control_pack_version"] != pack.version or stored_pack_digest != pack.digest:
            _fail(SemanticAdapterIntegrityError, "evaluation_pack_binding")
        result_body = {
            "evaluation_id": evaluation_id,
            "obligation_id": obligation_id,
            "revision": int(revision),
            "rule_version": int(row["rule_version"]),
            "evidence_ids": evidence_ids,
            "authority_id": authority_id,
            "evaluated_at_ms": evaluated_at,
            "owed_cents": _cents(row["owed_cents"], "evaluation_owed"),
            "claimed_adjustment_cents": _cents(row["claimed_adjustment_cents"], "evaluation_claimed"),
            "lawful_adjustment_cents": _cents(row["lawful_adjustment_cents"], "evaluation_lawful"),
            "received_cash_cents": _cents(row["received_cash_cents"], "evaluation_cash"),
            "shortfall_cents": _cents(row["shortfall_cents"], "evaluation_shortfall"),
            "overage_cents": _cents(row["overage_cents"], "evaluation_overage"),
            "cash_satisfied": int(row["cash_satisfied"]),
            "amount_satisfied": int(row["amount_satisfied"]),
            "timely": int(row["timely"]),
            "reporting_complete": int(row["reporting_complete"]),
            "verification_status": str(row["verification_status"]),
            "case_status": str(row["case_status"]),
            "delivery_status": str(row["delivery_status"]),
        }
        for field in ("cash_satisfied", "amount_satisfied", "timely", "reporting_complete"):
            if result_body[field] not in (0, 1):
                _fail(SemanticAdapterIntegrityError, "evaluation_boolean")
        result_digest = _blob(row["result_digest"], "evaluation_result_digest")
        expected_result_digest = owner._digest(owner._EVALUATION_RESULT_DOMAIN, _canonical(result_body))
        if result_digest != expected_result_digest:
            _fail(SemanticAdapterIntegrityError, "evaluation_result_digest")
        receipt_body = owner._evaluation_receipt_body(
            result={**result_body, "result_digest": _hex(result_digest)},
            scope=scope,
            control_pack_id=pack.pack_id,
            control_pack_version=pack.version,
            control_pack_digest=pack.digest,
            evidence_bindings=bindings,
            authority_id=authority_id,
            authority_epoch=authority_epoch,
            authority_digest=authority_digest,
            input_snapshot_digest=input_digest,
            result_digest=result_digest,
        )
        receipt_digest = owner._digest(owner._EVALUATION_RECEIPT_DOMAIN, _canonical(receipt_body))
        stored_receipt_digest = _blob(row["receipt_digest"], "evaluation_receipt_digest")
        if stored_receipt_digest != receipt_digest:
            _fail(SemanticAdapterIntegrityError, "evaluation_receipt_digest")
        receipt = {
            **receipt_body,
            "receipt_digest": _hex(receipt_digest),
            "evaluation_result_digest": _hex(result_digest),
        }
        full = {"receipt": receipt, "input_snapshot": input_snapshot}
        result.append(full)
        by_id[evaluation_id] = full
        revisions.append(int(revision))
    current_revision = int(obligation["revision"])
    if revisions != list(range(current_revision + 1)) or not result:
        _fail(SemanticAdapterIntegrityError, "evaluation_history")
    current_id = obligation["current_evaluation_id"]
    if current_id is None or str(current_id) != result[-1]["receipt"]["evaluation_id"] or int(result[-1]["receipt"]["revision"]) != current_revision:
        _fail(SemanticAdapterIntegrityError, "evaluation_current_binding")
    # The latest persisted receipt must still agree with the current projection.
    latest = result[-1]["receipt"]
    for field in (
        "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents",
        "shortfall_cents", "overage_cents", "cash_satisfied", "amount_satisfied", "timely",
        "reporting_complete", "verification_status", "case_status", "delivery_status",
    ):
        expected_value = int(obligation[field]) if field in {"cash_satisfied", "amount_satisfied", "timely", "reporting_complete"} else obligation[field]
        if latest[field] != expected_value:
            _fail(SemanticAdapterIntegrityError, "evaluation_projection_binding")
    return result, by_id, latest


def _validate_determinations(
    *,
    determinations: list[dict[str, Any]],
    claims: Mapping[str, Mapping[str, Any]],
    actions: Mapping[str, Mapping[str, Any]],
    evaluations: Mapping[str, Mapping[str, Any]],
    evidence: Mapping[str, Mapping[str, Any]],
    pack: owner.ControlPack,
    authority_context: TrustedAuthorityContext,
    obligation_id: str,
    pre_evaluation_revision: int,
    evaluation_time_ms: int,
) -> None:
    seen_claims: set[str] = set()
    for determination in determinations:
        claim_id = determination["claim_id"]
        claim = claims.get(claim_id)
        action = next((value for value in actions.values() if value["determination_id"] == determination["determination_id"]), None)
        if claim is None or action is None or determination["obligation_id"] != obligation_id:
            _fail(SemanticAdapterIntegrityError, "determination_relation")
        if claim_id in seen_claims:
            _fail(SemanticAdapterIntegrityError, "determination_claim_duplicate")
        seen_claims.add(claim_id)
        mapping = {
            "OFFSET_AUTHORIZED": ("OFFSET_AUTHORIZED", "OFFSET_AUTHORIZATION", "AUTHORIZED"),
            "OFFSET_REJECTED_CORRECTION_AUTHORIZED": ("OFFSET_REJECTED_CORRECTION_AUTHORIZED", "CORRECTION_PAYMENT_REQUEST", "REJECTED"),
        }
        expected = mapping.get(determination["decision"])
        if expected is None or (determination["decision"], action["kind"], claim["status"]) != expected:
            _fail(SemanticAdapterIntegrityError, "determination_status")
        if action["action_id"] != determination["action_id"] or action["revision"] != determination["resulting_revision"] or action["obligation_id"] != obligation_id:
            _fail(SemanticAdapterIntegrityError, "determination_action_binding")
        evaluation = evaluations.get(determination["input_evaluation_id"])
        if evaluation is None:
            _fail(SemanticAdapterIntegrityError, "determination_evaluation")
        receipt = evaluation["receipt"]
        if receipt["result_digest"] != determination["input_evaluation_result_digest"] or receipt["revision"] != determination["expected_revision"] or claim["evidence_id"] not in receipt["evidence_ids"]:
            _fail(SemanticAdapterIntegrityError, "determination_evaluation_binding")
        if determination["decided_at_ms"] < receipt["evaluated_at_ms"] or determination["decided_at_ms"] > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "determination_chronology")
        if (
            determination["expected_revision"] > pre_evaluation_revision
            or determination["resulting_revision"] > pre_evaluation_revision + 1
            or determination["resulting_revision"] != determination["expected_revision"] + 1
            or determination["amount_cents"] != claim["amount_cents"]
        ):
            _fail(SemanticAdapterIntegrityError, "determination_revision")
        if not authority_context.has_role(determination["actor_id"], determination["actor_role"]):
            _fail(SemanticAdapterAuthorityError, "determination_actor_role")
        if determination["actor_role"] not in pack.authorized_roles:
            _fail(SemanticAdapterAuthorityError, "determination_pack_role")
        bindings = determination["supporting_evidence"]
        for binding in bindings:
            if binding["evidence_id"] not in evidence or evidence[binding["evidence_id"]]["record_digest"] != binding["record_digest"]:
                _fail(SemanticAdapterIntegrityError, "determination_evidence")
        payload = owner._determination_digest_payload(
            action_id=determination["action_id"],
            determination_id=determination["determination_id"],
            obligation_id=obligation_id,
            kind=action["kind"],
            claim_id=claim_id,
            decision=determination["decision"],
            amount_cents=determination["amount_cents"],
            input_evaluation_id=determination["input_evaluation_id"],
            input_evaluation_result_digest=_digest(determination["input_evaluation_result_digest"], "determination_eval_digest"),
            actor_id=determination["actor_id"],
            actor_role=determination["actor_role"],
            authority_id=determination["authority_id"],
            authority_epoch=determination["authority_epoch"],
            authority_digest=_digest(determination["authority_digest"], "determination_authority_digest"),
            supporting_evidence=bindings,
            expected_revision=determination["expected_revision"],
            resulting_revision=determination["resulting_revision"],
            decided_at_ms=determination["decided_at_ms"],
        )
        if _hex(owner._digest(owner._ACTION_DOMAIN, _canonical(payload))) != determination["determination_digest"]:
            _fail(SemanticAdapterIntegrityError, "determination_digest")
        action_payload = action["payload"]
        if action_payload.get("action_id") != action["action_id"] or action_payload.get("obligation_id") != obligation_id or action_payload.get("determination_id") != determination["determination_id"] or action_payload.get("kind") != action["kind"] or action_payload.get("claim_id") != claim_id or action_payload.get("amount_cents") != claim["amount_cents"] or action_payload.get("revision") != action["revision"] or action_payload.get("input_evaluation_id") != determination["input_evaluation_id"] or action_payload.get("input_evaluation_result_digest") != determination["input_evaluation_result_digest"] or action_payload.get("dispatch") != "SYNTHETIC_RECORD_ONLY":
            _fail(SemanticAdapterIntegrityError, "action_payload_binding")

    for claim in claims.values():
        if claim["status"] in {"AUTHORIZED", "REJECTED"} and claim["claim_id"] not in seen_claims:
            _fail(SemanticAdapterIntegrityError, "claim_without_determination")


def _load_determinations(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    evidence: Mapping[str, Mapping[str, Any]],
    authority_context: TrustedAuthorityContext,
    evaluation_time_ms: int,
    limit: int,
) -> list[dict[str, Any]]:
    rows = _bounded_rows(
        connection,
        "SELECT determination_id,obligation_id,claim_id,actor_id,actor_role,authority_id,authority_epoch,authority_digest,decision,amount_cents,supporting_evidence_json,expected_revision,resulting_revision,decided_at_ms,determination_digest,input_evaluation_id,input_evaluation_result_digest FROM determinations WHERE obligation_id=? ORDER BY determination_id",
        (obligation_id,),
        label="determinations",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    for row in rows:
        determination_id = _id(row["determination_id"], "determination_id")
        if str(row["obligation_id"]) != obligation_id:
            _fail(SemanticAdapterIntegrityError, "determination_scope")
        actor_id = _id(row["actor_id"], "determination_actor")
        actor_role = _role(row["actor_role"], "determination_role")
        authority_id = _id(row["authority_id"], "determination_authority")
        authority_epoch = row["authority_epoch"]
        if type(authority_epoch) is not int or authority_epoch < 1:
            _fail(SemanticAdapterIntegrityError, "determination_authority_epoch")
        authority_digest = _blob(row["authority_digest"], "determination_authority_digest")
        if (authority_id, authority_epoch, authority_digest) != (authority_context.authority_id, authority_context.epoch, authority_context.digest):
            _fail(SemanticAdapterAuthorityError, "determination_authority_stale")
        supporting = _parse_json_column(row["supporting_evidence_json"], "determination_evidence", expected_type=dict)
        if set(supporting) != {"bindings"} or type(supporting["bindings"]) is not list:
            _fail(SemanticAdapterIntegrityError, "determination_evidence")
        bindings = supporting["bindings"]
        if any(type(binding) is not dict or set(binding) != {"evidence_id", "record_digest"} for binding in bindings):
            _fail(SemanticAdapterIntegrityError, "determination_evidence")
        if [binding["evidence_id"] for binding in bindings] != sorted(binding["evidence_id"] for binding in bindings) or len({binding["evidence_id"] for binding in bindings}) != len(bindings):
            _fail(SemanticAdapterIntegrityError, "determination_evidence")
        expected_revision = row["expected_revision"]
        resulting_revision = row["resulting_revision"]
        if type(expected_revision) is not int or type(resulting_revision) is not int or not 0 <= expected_revision <= owner._MAX_ROWS or not 0 <= resulting_revision <= owner._MAX_ROWS:
            _fail(SemanticAdapterIntegrityError, "determination_revision")
        body = {
            "determination_id": determination_id,
            "obligation_id": obligation_id,
            "claim_id": _id(row["claim_id"], "determination_claim"),
            "actor_id": actor_id,
            "actor_role": actor_role,
            "authority_id": authority_id,
            "authority_epoch": authority_epoch,
            "authority_digest": _hex(authority_digest),
            "decision": _id(row["decision"], "determination_decision"),
            "amount_cents": _cents(row["amount_cents"], "determination_amount", positive=True),
            "supporting_evidence": bindings,
            "expected_revision": expected_revision,
            "resulting_revision": resulting_revision,
            "decided_at_ms": _time(row["decided_at_ms"], "determination_time"),
            "determination_digest": _hex(_blob(row["determination_digest"], "determination_digest")),
            "input_evaluation_id": _id(row["input_evaluation_id"], "determination_evaluation_id"),
            "input_evaluation_result_digest": _hex(_blob(row["input_evaluation_result_digest"], "determination_eval_digest")),
            "action_id": "",
        }
        if body["decided_at_ms"] > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "determination_time_binding")
        result.append(body)
    return result


def _validate_projection(
    *,
    obligation: sqlite3.Row,
    payments: Mapping[str, Mapping[str, Any]],
    claims: Mapping[str, Mapping[str, Any]],
    evidence: Mapping[str, Mapping[str, Any]],
    conflicts: list[Mapping[str, Any]],
    cases: list[Mapping[str, Any]],
    actions: Mapping[str, Mapping[str, Any]],
) -> None:
    cash = 0
    for payment in payments.values():
        if payment["active"] == 1:
            cash = _add(cash, payment["amount_cents"])
    claimed = 0
    lawful = 0
    for claim in claims.values():
        if claim["status"] in {"CLAIMED", "AUTHORIZED"}:
            claimed = _add(claimed, claim["amount_cents"])
        if claim["status"] == "AUTHORIZED":
            lawful = _add(lawful, claim["amount_cents"])
    owed = int(obligation["owed_cents"])
    total = _add(cash, lawful)
    expected = {
        "claimed_adjustment_cents": claimed,
        "lawful_adjustment_cents": lawful,
        "received_cash_cents": cash,
        "shortfall_cents": max(owed - total, 0),
        "overage_cents": max(total - owed, 0),
        "cash_satisfied": int(cash >= owed),
        "amount_satisfied": int(total >= owed),
    }
    for field, value in expected.items():
        if int(obligation[field]) != value:
            _fail(SemanticAdapterIntegrityError, "obligation_projection")
    evidence_status = "CONFLICT_VISIBLE" if conflicts else ("SUPPORTED" if evidence else "MISSING_EVIDENCE")
    if str(obligation["verification_status"]) != evidence_status:
        _fail(SemanticAdapterIntegrityError, "obligation_verification")
    if not cases:
        _fail(SemanticAdapterIntegrityError, "obligation_case")
    if cases[-1]["status"] != str(obligation["case_status"]):
        _fail(SemanticAdapterIntegrityError, "obligation_case_status")
    latest_action = max(actions.values(), key=lambda action: (action["created_at_ms"], action["action_id"])) if actions else None
    delivery = "NONE" if latest_action is None else latest_action["status"]
    if str(obligation["delivery_status"]) != delivery:
        _fail(SemanticAdapterIntegrityError, "obligation_delivery")


def _make_snapshot(body: dict[str, Any]) -> LockedSemanticSnapshot:
    unsigned = dict(body)
    unsigned_bytes = _canonical(unsigned)
    digest = owner._digest(_SNAPSHOT_DOMAIN, unsigned_bytes)
    body["snapshot_digest"] = _hex(digest)
    encoded = _canonical(body)
    return LockedSemanticSnapshot(
        encoded,
        digest,
        str(body["pre_evaluation"]["obligation_id"]),
        int(body["pre_evaluation"]["revision"]),
        int(body["evaluation_time_ms"]),
        _validation_token=_SNAPSHOT_VALIDATION_TOKEN,
    )


def build_locked_semantic_snapshot(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    authority_context: TrustedAuthorityContext,
    evaluation_time_ms: int,
    expected_config: object,
    expected_scope: object,
    expected_mode: str,
    expected_owner_id: str,
    expected_continuity_epoch: int | None = None,
    max_fact_rows: int = MAX_FACT_ROWS,
) -> LockedSemanticSnapshot:
    """Produce a bounded authenticated snapshot from one owner transaction.

    This function performs SELECT/PRAGMA work only.  It intentionally does not
    call ``sqlite3.connect`` or any owner command, and it never commits or
    rolls back the caller's transaction.
    """

    connection = _require_connection(connection)
    if type(authority_context) is not TrustedAuthorityContext:
        _fail(SemanticAdapterInputError, "authority_context_type")
    _time(evaluation_time_ms, "evaluation_time")
    _id(expected_owner_id, "expected_owner_id")
    if expected_mode not in owner._MODES:
        _fail(SemanticAdapterInputError, "expected_mode")
    if type(max_fact_rows) is not int or not 1 <= max_fact_rows <= MAX_FACT_ROWS:
        _fail(SemanticAdapterInputError, "fact_row_bound")
    try:
        verification = _verify_owner_connection(
            connection,
            expected_config=expected_config,
            expected_scope=expected_scope,
            authority_context=authority_context,
            expected_mode=expected_mode,
            expected_owner_id=expected_owner_id,
            expected_continuity_epoch=expected_continuity_epoch,
        )
        scope, identity = _read_verified_meta(connection, verification)
        obligation_row, obligation_body = _load_obligation(
            connection,
            obligation_id=obligation_id,
            scope=scope,
            evaluation_time_ms=evaluation_time_ms,
        )
        population_body, pack_body, pack = _load_population_and_pack(connection, obligation_row, scope)
        evidence_body, evidence_by_id = _load_evidence(
            connection,
            item_id=str(obligation_row["item_id"]),
            evaluation_time_ms=evaluation_time_ms,
            limit=max_fact_rows,
        )
        payments_body, payments_by_id = _load_payments(
            connection,
            obligation_id=obligation_id,
            item_id=str(obligation_row["item_id"]),
            evidence=evidence_by_id,
            evaluation_time_ms=evaluation_time_ms,
            limit=max_fact_rows,
        )
        claims_body, claims_by_id = _load_claims(
            connection,
            obligation_id=obligation_id,
            evidence=evidence_by_id,
            evaluation_time_ms=evaluation_time_ms,
            limit=max_fact_rows,
        )
        cases_body, cases_by_id = _load_cases(
            connection,
            obligation_id=obligation_id,
            pack=pack,
            evaluation_time_ms=evaluation_time_ms,
            limit=max_fact_rows,
        )
        actions_body, outbox_body, actions_by_id = _load_actions(
            connection,
            obligation_id=obligation_id,
            evaluation_time_ms=evaluation_time_ms,
            limit=max_fact_rows,
        )
        conflicts_body = _load_conflicts(
            connection,
            obligation_id=obligation_id,
            item_id=str(obligation_row["item_id"]),
            evidence=evidence_by_id,
            payments=payments_by_id,
            evaluation_time_ms=evaluation_time_ms,
            limit=max_fact_rows,
        )
        evaluations_body, evaluations_by_id, current_evaluation = _load_evaluations(
            connection,
            obligation_id=obligation_id,
            obligation=obligation_row,
            scope=scope,
            pack=pack,
            authority_context=authority_context,
            evidence=evidence_by_id,
            evaluation_time_ms=evaluation_time_ms,
            limit=max_fact_rows,
        )
        determinations_raw = _load_determinations(
            connection,
            obligation_id=obligation_id,
            evidence=evidence_by_id,
            authority_context=authority_context,
            evaluation_time_ms=evaluation_time_ms,
            limit=max_fact_rows,
        )
        determination_by_id: dict[str, dict[str, Any]] = {}
        for determination in determinations_raw:
            action = next((value for value in actions_by_id.values() if value["determination_id"] == determination["determination_id"]), None)
            if action is None:
                _fail(SemanticAdapterIntegrityError, "determination_action_missing")
            determination["action_id"] = action["action_id"]
            determination_by_id[determination["determination_id"]] = determination
        _validate_determinations(
            determinations=determinations_raw,
            claims=claims_by_id,
            actions=actions_by_id,
            evaluations=evaluations_by_id,
            evidence=evidence_by_id,
            pack=pack,
            authority_context=authority_context,
            obligation_id=obligation_id,
            pre_evaluation_revision=int(obligation_row["revision"]),
            evaluation_time_ms=evaluation_time_ms,
        )
        _validate_projection(
            obligation=obligation_row,
            payments=payments_by_id,
            claims=claims_by_id,
            evidence=evidence_by_id,
            conflicts=conflicts_body,
            cases=cases_body,
            actions=actions_by_id,
        )
        body = {
            "schema": SEMANTIC_INPUT_SCHEMA,
            "version": SEMANTIC_INPUT_VERSION,
            "scope": dict(scope),
            "owner": identity,
            "authority": {
                "context": authority_context.source,
                "authority_id": authority_context.authority_id,
                "epoch": authority_context.epoch,
                "digest": _hex(authority_context.digest),
                "actors": authority_context.actor_roles,
            },
            "evaluation_time_ms": evaluation_time_ms,
            "pre_evaluation": {
                "obligation_id": obligation_id,
                "item_id": str(obligation_row["item_id"]),
                "revision": int(obligation_row["revision"]),
            },
            "population": population_body,
            "population_item": {
                "population_id": population_body["population_id"],
                "item_id": str(obligation_row["item_id"]),
                "display_label": _text(
                    connection.execute(
                        "SELECT display_label FROM population_items WHERE population_id=? AND item_id=?",
                        (obligation_row["population_id"], obligation_row["item_id"]),
                    ).fetchone()[0],
                    "population_item_label",
                    max_bytes=128,
                ),
                "owed_cents": int(obligation_row["owed_cents"]),
                "due_at_ms": int(obligation_row["due_at_ms"]),
                "currency": str(obligation_row["currency"]),
            },
            "control_pack": pack_body,
            "obligation": obligation_body,
            "evidence": evidence_body,
            "payments": payments_body,
            "claims": claims_body,
            "determinations": determinations_raw,
            "cases": cases_body,
            "actions": actions_body,
            "action_outbox": outbox_body,
            "conflicts": conflicts_body,
            "evaluations": evaluations_body,
            "current_evaluation": {
                "receipt": current_evaluation,
                "input_snapshot": evaluations_by_id[current_evaluation["evaluation_id"]]["input_snapshot"],
            },
        }
        encoded = _canonical(body)
        if len(encoded) > MAX_SNAPSHOT_BYTES:
            _fail(SemanticAdapterIntegrityError, "snapshot_size")
        return _make_snapshot(body)
    except SemanticAdapterError:
        raise
    except sqlite3.Error:
        _fail(SemanticAdapterIntegrityError, "database_read")
    except (TypeError, ValueError, KeyError, IndexError):
        _fail(SemanticAdapterIntegrityError, "record_shape")


__all__ = [
    "BLFIN02_MAGIC",
    "BLFRES02_MAGIC",
    "DecodedLeanResult",
    "LockedSemanticSnapshot",
    "MAX_FACT_ROWS",
    "MAX_WIRE_BYTES",
    "MAX_WIRE_LIST",
    "SEMANTIC_INPUT_SCHEMA",
    "SEMANTIC_INPUT_VERSION",
    "SemanticAdapterAuthorityError",
    "SemanticAdapterCodecError",
    "SemanticAdapterError",
    "SemanticAdapterInputError",
    "SemanticAdapterIntegrityError",
    "TrustedAuthorityContext",
    "build_locked_semantic_snapshot",
    "decode_blfres02_result",
    "decode_engine_result",
    "decode_locked_snapshot",
    "encode_blfin02_input",
    "encode_blfres02_result",
    "encode_lean_input",
    "encode_locked_snapshot",
]
