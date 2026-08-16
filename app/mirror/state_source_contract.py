"""Synthetic-only Mirror state-source admission contract.

The contract is deliberately narrower than a production source adapter.  It
accepts one bounded, canonical synthetic adapter envelope, validates it
against the state-controlled V1 profile, and emits the exact source-coverage
input consumed by the read-only Provider Trust Graph.  It does not authenticate
an external source, select credentials, authorize a decision, or mutate state.

The independent verifier in ``state_source_contract_independent`` duplicates
the wire grammar and root checks.  Keeping this module free of the graph
producer makes the admission boundary explicit and prevents a caller-supplied
boolean or status string from becoming authentication authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Mapping, Sequence


class StateSourceContractError(ValueError):
    """Raised for malformed, substituted, stale, or conflicting source input."""


ADAPTER_SCHEMA = "mirror-state-source-adapter-v1"
GRAPH_INPUT_SCHEMA = "mirror-provider-trust-graph-input-v1"
RECEIPT_SCHEMA = "mirror-state-source-admission-receipt-v1"
CONTRACT_VERSION = 1
PROFILE_ID = "SYNTH_PROVIDER_CONTINUITY_SOURCE_PROFILE_V1"
VERIFIER_ID = "SYNTHETIC_STATE_SOURCE_VERIFIER_V1"
VERIFIER_EPOCH = 1

PROVIDER_GRAPH_SUBJECT = "SYNTH_PROVIDER_001"
SUBJECT_KEY = "SYNTH_PROVIDER_001|SYNTH_CREDENTIAL_001|SYNTH_ENROLLMENT_001"
SCOPE = "provider-credential-enrollment-continuity-v1"
CREDENTIAL_ID = "SYNTH_CREDENTIAL_001"
ENROLLMENT_ID = "SYNTH_ENROLLMENT_001"

SOURCE_CREDENTIAL_ID = "SYNTH_SOURCE_CREDENTIAL_001"
SOURCE_ENROLLMENT_ID = "SYNTH_SOURCE_ENROLLMENT_001"
SOURCE_CREDENTIAL_KIND = "CREDENTIAL_REGISTRY"
SOURCE_ENROLLMENT_KIND = "ENROLLMENT_REGISTRY"
AUTH_CREDENTIAL_ID = "SYNTH_AUTHORITY_CREDENTIAL_001"
AUTH_ENROLLMENT_ID = "SYNTH_AUTHORITY_ENROLLMENT_001"
PROVENANCE_CREDENTIAL_ID = "SYNTH_PROVENANCE_CREDENTIAL_001"
PROVENANCE_ENROLLMENT_ID = "SYNTH_PROVENANCE_ENROLLMENT_001"

OBSERVATION_TIME = 7_000
EFFECTIVE_START = 6_000
EFFECTIVE_END = 9_000

STATUS_ACTIVE = "ACTIVE"
STATUS_EXPIRED = "EXPIRED"
STATUS_TERMINATED = "TERMINATED"
STATUSES = (STATUS_ACTIVE, STATUS_EXPIRED, STATUS_TERMINATED)

MAX_ADAPTER_BYTES = 262_144
MAX_GRAPH_INPUT_BYTES = 262_144
MAX_RECEIPT_BYTES = 16_384
MAX_SOURCES = 2
MAX_RECORDS_PER_SOURCE = 8
MAX_NONMEMBERSHIP_PER_SOURCE = 1
MAX_STRING_BYTES = 128
MAX_NODES = 4_096
MAX_DEPTH = 16
MAX_TIMESTAMP = 2_147_483_647

FORBIDDEN_EXTERNAL_TOKENS = (
    "policyResult",
    "policy_result",
    "effectiveDirective",
    "effective_directive",
    "ClearanceDecisionRow",
    "StateAccessRow",
    "proofSuiteId",
    "proof_suite_id",
    "CLEAR",
    "HOLD",
    "HUMAN_REVIEW",
    "BLOCK",
    "EXCEPTION_APPROVED",
    "directive",
    "clearance",
    "payment",
    "economic",
    "private-proof",
    "private_proof",
)

ADAPTER_KEYS = {
    "schema",
    "profile_id",
    "contract_version",
    "verifier_id",
    "verifier_epoch",
    "provider_graph_subject",
    "scope",
    "observation_time",
    "sources",
}
SOURCE_KEYS = {
    "source_id",
    "source_kind",
    "coverage_scope",
    "coverage_observation_time",
    "coverage_effective_start",
    "coverage_effective_end",
    "coverage_complete",
    "coverage_authority_id",
    "nonmembership_keys",
    "records",
    "provenance",
    "source_root",
}
PROVENANCE_KEYS = {"provenance_id", "integrity_digest"}
RECORD_KEYS = {
    "record_id",
    "record_kind",
    "provider_id",
    "credential_id",
    "enrollment_id",
    "subject_key",
    "observed_at",
    "issued_at",
    "valid_from",
    "valid_until",
    "terminated_at",
    "status",
}

_HEX = re.compile(r"^[0-9a-f]{128}$")
_RECORD = re.compile(r"^SYNTH_(CREDENTIAL|ENROLLMENT)_RECORD_00[1-8]$")


@dataclass(frozen=True)
class SourceBinding:
    """One state-controlled source role in the fixed V1 source order."""

    source_id: str
    source_kind: str
    coverage_authority_id: str
    provenance_id: str
    record_kind: str

    def material(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "coverage_authority_id": self.coverage_authority_id,
            "provenance_id": self.provenance_id,
            "record_kind": self.record_kind,
        }


@dataclass(frozen=True)
class StateSourceContractV1:
    """State-owned profile; adapter bytes cannot replace these values."""

    schema: str
    profile_id: str
    version: int
    provider_graph_subject: str
    subject_key: str
    scope: str
    observation_time: int
    effective_start: int
    effective_end: int
    require_complete: bool
    allow_nonmembership: bool
    nonmembership_policy: str
    source_order_rule: str
    record_order_rule: str
    observation_rule: str
    validity_rule: str
    integrity_rule: str
    root_rule: str
    authentication_verifier_id: str
    authentication_verifier_epoch: int
    bindings: tuple[SourceBinding, ...]

    def material(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "profile_id": self.profile_id,
            "version": self.version,
            "provider_graph_subject": self.provider_graph_subject,
            "subject_key": self.subject_key,
            "scope": self.scope,
            "observation_time": self.observation_time,
            "effective_start": self.effective_start,
            "effective_end": self.effective_end,
            "require_complete": self.require_complete,
            "allow_nonmembership": self.allow_nonmembership,
            "nonmembership_policy": self.nonmembership_policy,
            "source_order_rule": self.source_order_rule,
            "record_order_rule": self.record_order_rule,
            "observation_rule": self.observation_rule,
            "validity_rule": self.validity_rule,
            "integrity_rule": self.integrity_rule,
            "root_rule": self.root_rule,
            "authentication_verifier_id": self.authentication_verifier_id,
            "authentication_verifier_epoch": self.authentication_verifier_epoch,
            "bindings": [binding.material() for binding in self.bindings],
        }

    @property
    def profile_root(self) -> str:
        return _contract_digest("profile-root", self.material())

    @property
    def contract_id(self) -> str:
        return _contract_digest("contract-id", self.material())


STATE_SOURCE_CONTRACT = StateSourceContractV1(
    schema=ADAPTER_SCHEMA,
    profile_id=PROFILE_ID,
    version=CONTRACT_VERSION,
    provider_graph_subject=PROVIDER_GRAPH_SUBJECT,
    subject_key=SUBJECT_KEY,
    scope=SCOPE,
    observation_time=OBSERVATION_TIME,
    effective_start=EFFECTIVE_START,
    effective_end=EFFECTIVE_END,
    require_complete=True,
    allow_nonmembership=True,
    nonmembership_policy="EXACT_SUBJECT_KEY_SORTED_UNIQUE_NO_FACT_CONFLICT_V1",
    source_order_rule="SOURCE_ID_PROFILE_ORDER_V1",
    record_order_rule="RECORD_ID_ASC_SORTED_UNIQUE_V1",
    observation_rule="OBSERVED_AT_EQUALS_PROFILE_TIME_V1",
    validity_rule="ISSUED_EQUALS_VALID_FROM_AND_STATUS_AT_OBSERVATION_V1",
    integrity_rule="SHA3_512_PROVIDER_GRAPH_SOURCE_INTEGRITY_V1",
    root_rule="SHA3_512_PROVIDER_GRAPH_SOURCE_ROOT_V1",
    authentication_verifier_id=VERIFIER_ID,
    authentication_verifier_epoch=VERIFIER_EPOCH,
    bindings=(
        SourceBinding(
            source_id=SOURCE_CREDENTIAL_ID,
            source_kind=SOURCE_CREDENTIAL_KIND,
            coverage_authority_id=AUTH_CREDENTIAL_ID,
            provenance_id=PROVENANCE_CREDENTIAL_ID,
            record_kind="CREDENTIAL",
        ),
        SourceBinding(
            source_id=SOURCE_ENROLLMENT_ID,
            source_kind=SOURCE_ENROLLMENT_KIND,
            coverage_authority_id=AUTH_ENROLLMENT_ID,
            provenance_id=PROVENANCE_ENROLLMENT_ID,
            record_kind="ENROLLMENT",
        ),
    ),
)


@dataclass(frozen=True)
class StateSourceAdmission:
    """Immutable result of one synthetic source admission."""

    graph_input: bytes
    receipt: bytes
    source_roots: tuple[str, ...]
    record_count: int
    nonmembership_count: int

    def telemetry(self) -> dict[str, object]:
        """Return bounded telemetry with no source identifiers or raw records."""

        return {
            "adapter_schema": ADAPTER_SCHEMA,
            "contract_version": CONTRACT_VERSION,
            "verifier_epoch": VERIFIER_EPOCH,
            "synthetic_only": True,
            "production_source_authentication": False,
            "source_count": len(self.source_roots),
            "record_count": self.record_count,
            "nonmembership_count": self.nonmembership_count,
            "graph_input_bytes": len(self.graph_input),
            "receipt_bytes": len(self.receipt),
        }


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise StateSourceContractError("json:noncanonical-value") from exc


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StateSourceContractError("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if count[0] > MAX_NODES:
        raise StateSourceContractError("json:node-cap")
    if depth > MAX_DEPTH:
        raise StateSourceContractError("json:depth-cap")
    if isinstance(value, float):
        raise StateSourceContractError("json:float-forbidden")
    if isinstance(value, str):
        try:
            raw = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise StateSourceContractError("json:non-ascii") from exc
        if len(raw) > MAX_STRING_BYTES:
            raise StateSourceContractError("json:string-cap")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise StateSourceContractError("json:key-type")
            _walk(key, depth + 1, count)
            _walk(item, depth + 1, count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, count)


def _reject_forbidden(value: object) -> None:
    if isinstance(value, str):
        if any(token in value for token in FORBIDDEN_EXTERNAL_TOKENS):
            raise StateSourceContractError("payload:forbidden-token")
    elif isinstance(value, dict):
        for key, item in value.items():
            if any(token in key for token in FORBIDDEN_EXTERNAL_TOKENS):
                raise StateSourceContractError("payload:forbidden-token")
            _reject_forbidden(item)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden(item)


def canonical_adapter(value: Mapping[str, object]) -> bytes:
    """Encode a test/adapter value; admission still performs full validation."""

    if not isinstance(value, dict):
        raise StateSourceContractError("json:top-level")
    _walk(value)
    _reject_forbidden(value)
    raw = _canonical(value)
    if len(raw) > MAX_ADAPTER_BYTES:
        raise StateSourceContractError("json:byte-cap")
    return raw


def parse_adapter(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw:
        raise StateSourceContractError("json:empty-or-type")
    if len(raw) > MAX_ADAPTER_BYTES:
        raise StateSourceContractError("json:byte-cap")
    try:
        text = raw.decode("utf-8", errors="strict")
        if text.startswith("\ufeff"):
            raise StateSourceContractError("json:bom")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                StateSourceContractError("json:constant-forbidden")
            ),
        )
    except StateSourceContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateSourceContractError("json:parse") from exc
    if not isinstance(value, dict):
        raise StateSourceContractError("json:top-level")
    _walk(value)
    _reject_forbidden(value)
    if _canonical(value) != raw:
        raise StateSourceContractError("json:not-canonical")
    return value


def _contract_digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/STATE-SOURCE-CONTRACT/" + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _graph_digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/PROVIDER-TRUST-GRAPH/" + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise StateSourceContractError(f"{label}:schema")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise StateSourceContractError(f"{label}:text")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise StateSourceContractError(f"{label}:ascii") from exc
    if len(raw) > MAX_STRING_BYTES:
        raise StateSourceContractError(f"{label}:length")
    return value


def _int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StateSourceContractError(f"{label}:integer")
    if not 0 <= value <= MAX_TIMESTAMP:
        raise StateSourceContractError(f"{label}:range")
    return value


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StateSourceContractError(f"{label}:boolean")
    return value


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise StateSourceContractError(f"{label}:hex")
    return value


def _sorted_unique(values: object, label: str, *, maximum: int) -> list[str]:
    if not isinstance(values, list) or len(values) > maximum:
        raise StateSourceContractError(f"{label}:list-cap")
    result = [_text(item, label) for item in values]
    if result != sorted(result) or len(set(result)) != len(result):
        raise StateSourceContractError(f"{label}:order-or-duplicate")
    return result


def _record_expected_status(record: Mapping[str, object], observation_time: int) -> str:
    issued = record["issued_at"]
    valid_until = record["valid_until"]
    terminated = record["terminated_at"]
    assert isinstance(issued, int) and isinstance(valid_until, int) and isinstance(terminated, int)
    if record["record_kind"] == "CREDENTIAL":
        if terminated != 0:
            raise StateSourceContractError("record:credential-termination")
        return STATUS_ACTIVE if observation_time < valid_until else STATUS_EXPIRED
    if terminated:
        if not issued <= terminated <= observation_time:
            raise StateSourceContractError("record:termination-time")
        return STATUS_TERMINATED
    return STATUS_ACTIVE if observation_time < valid_until else STATUS_EXPIRED


def _validate_record(record: object, binding: SourceBinding, profile: StateSourceContractV1) -> dict[str, object]:
    item = _expect_keys(record, RECORD_KEYS, "record")
    record_id = _text(item["record_id"], "record:id")
    if _RECORD.fullmatch(record_id) is None:
        raise StateSourceContractError("record:id:not-synthetic")
    expected_prefix = "SYNTH_" + binding.record_kind
    if not record_id.startswith(expected_prefix):
        raise StateSourceContractError("record:id:source-mismatch")
    if item["record_kind"] != binding.record_kind or item["record_kind"] not in ("CREDENTIAL", "ENROLLMENT"):
        raise StateSourceContractError("record:kind:source-mismatch")
    for field, expected in (
        ("provider_id", profile.provider_graph_subject),
        ("credential_id", CREDENTIAL_ID),
        ("enrollment_id", ENROLLMENT_ID),
        ("subject_key", profile.subject_key),
    ):
        if _text(item[field], "record:" + field) != expected:
            raise StateSourceContractError("record:identity-mismatch")
    observed = _int(item["observed_at"], "record:observed_at")
    if observed != profile.observation_time:
        raise StateSourceContractError("record:observation-mismatch")
    issued = _int(item["issued_at"], "record:issued_at")
    valid_from = _int(item["valid_from"], "record:valid_from")
    valid_until = _int(item["valid_until"], "record:valid_until")
    terminated = _int(item["terminated_at"], "record:terminated_at")
    if issued != valid_from or valid_until <= issued:
        raise StateSourceContractError("record:interval-contradiction")
    status = _text(item["status"], "record:status")
    if status not in STATUSES:
        raise StateSourceContractError("record:status:enum")
    if status != _record_expected_status(item, profile.observation_time):
        raise StateSourceContractError("record:status-time-mismatch")
    if binding.record_kind == "CREDENTIAL" and status == STATUS_TERMINATED:
        raise StateSourceContractError("record:credential-status")
    if binding.record_kind == "ENROLLMENT" and status == STATUS_EXPIRED:
        raise StateSourceContractError("record:enrollment-status")
    return item


def _source_integrity_material(source: Mapping[str, object]) -> dict[str, object]:
    material = dict(source)
    provenance = dict(material["provenance"])  # type: ignore[arg-type]
    provenance.pop("integrity_digest", None)
    material["provenance"] = provenance
    material.pop("source_root", None)
    return material


def source_integrity_digest(source: Mapping[str, object]) -> str:
    """Return the graph-compatible source integrity digest."""

    return _graph_digest("source-integrity", _source_integrity_material(source))


def source_root(source: Mapping[str, object]) -> str:
    """Return the graph-compatible source root."""

    return _graph_digest("source-root", {"source": dict(source)})


def _validate_source(
    source: object,
    binding: SourceBinding,
    profile: StateSourceContractV1,
) -> tuple[dict[str, object], int, int]:
    item = _expect_keys(source, SOURCE_KEYS, "source")
    if _text(item["source_id"], "source:id") != binding.source_id:
        raise StateSourceContractError("source:identity")
    if _text(item["source_kind"], "source:kind") != binding.source_kind:
        raise StateSourceContractError("source:kind-id-mismatch")
    provenance = _expect_keys(item["provenance"], PROVENANCE_KEYS, "source:provenance")
    if _text(provenance["provenance_id"], "source:provenance-id") != binding.provenance_id:
        raise StateSourceContractError("source:authority-or-provenance")
    if _text(item["coverage_scope"], "source:scope") != profile.scope:
        raise StateSourceContractError("source:scope")
    coverage_observation = _int(item["coverage_observation_time"], "source:coverage-observation")
    if coverage_observation != profile.observation_time:
        raise StateSourceContractError("source:coverage-observation-mismatch")
    start = _int(item["coverage_effective_start"], "source:coverage-start")
    end = _int(item["coverage_effective_end"], "source:coverage-end")
    if start >= end or not start <= profile.observation_time < end:
        raise StateSourceContractError("source:stale-coverage")
    if (start, end) != (profile.effective_start, profile.effective_end):
        raise StateSourceContractError("source:coverage-contract-mismatch")
    complete = _bool(item["coverage_complete"], "source:complete")
    if profile.require_complete and not complete:
        raise StateSourceContractError("source:partial-coverage")
    if _text(item["coverage_authority_id"], "source:authority") != binding.coverage_authority_id:
        raise StateSourceContractError("source:authority-or-provenance")
    nonmembership = _sorted_unique(
        item["nonmembership_keys"],
        "source:nonmembership",
        maximum=MAX_NONMEMBERSHIP_PER_SOURCE,
    )
    if not profile.allow_nonmembership and nonmembership:
        raise StateSourceContractError("source:nonmembership-policy")
    if any(key != profile.subject_key for key in nonmembership):
        raise StateSourceContractError("source:nonmembership-identity")
    records = item["records"]
    if not isinstance(records, list) or len(records) > MAX_RECORDS_PER_SOURCE:
        raise StateSourceContractError("source:record-cap")
    record_items = [_validate_record(record, binding, profile) for record in records]
    record_ids = [record["record_id"] for record in record_items]
    if record_ids != sorted(record_ids) or len(set(record_ids)) != len(record_ids):
        raise StateSourceContractError("source:record-order-or-duplicate")
    facts = {record["subject_key"] for record in record_items}
    if facts & set(nonmembership):
        raise StateSourceContractError("completeness:fact-nonmembership-conflict")
    _hex(provenance["integrity_digest"], "source:integrity")
    expected_integrity = source_integrity_digest(item)
    if provenance["integrity_digest"] != expected_integrity:
        raise StateSourceContractError("source:integrity-mismatch")
    expected_root = source_root({key: value for key, value in item.items() if key != "source_root"})
    if _hex(item["source_root"], "source:root") != expected_root:
        raise StateSourceContractError("source:root-mismatch")
    return item, len(record_items), len(nonmembership)


def _receipt_value(
    adapter: Mapping[str, object],
    graph_input: Mapping[str, object],
    roots: Sequence[str],
    record_count: int,
    nonmembership_count: int,
) -> dict[str, object]:
    profile = STATE_SOURCE_CONTRACT
    body: dict[str, object] = {
        "schema": RECEIPT_SCHEMA,
        "contract_id": profile.contract_id,
        "contract_version": profile.version,
        "profile_id": profile.profile_id,
        "profile_root": profile.profile_root,
        "adapter_digest": _contract_digest("adapter", adapter),
        "graph_input_digest": _contract_digest("graph-input", graph_input),
        "source_roots": list(roots),
        "provider_graph_subject": profile.provider_graph_subject,
        "scope": profile.scope,
        "observation_time": profile.observation_time,
        "record_count": record_count,
        "nonmembership_count": nonmembership_count,
        "authentication": {
            "verifier_id": profile.authentication_verifier_id,
            "verifier_epoch": profile.authentication_verifier_epoch,
            "status": "SYNTHETIC_TEST_RECEIPT",
            "production_qualified": False,
        },
        "synthetic_only": True,
        "production_source_authentication": False,
    }
    return {"receipt_id": _contract_digest("receipt-id", body), **body}


def _validate_adapter(value: Mapping[str, object]) -> StateSourceAdmission:
    profile = STATE_SOURCE_CONTRACT
    item = _expect_keys(value, ADAPTER_KEYS, "adapter")
    if _text(item["schema"], "adapter:schema") != profile.schema:
        raise StateSourceContractError("adapter:unknown-profile")
    if item["profile_id"] != profile.profile_id:
        raise StateSourceContractError("adapter:unknown-profile")
    if _int(item["contract_version"], "adapter:version") != profile.version:
        raise StateSourceContractError("adapter:downgrade-or-version")
    if _text(item["verifier_id"], "adapter:verifier") != profile.authentication_verifier_id:
        raise StateSourceContractError("adapter:verifier")
    if _int(item["verifier_epoch"], "adapter:verifier-epoch") != profile.authentication_verifier_epoch:
        raise StateSourceContractError("adapter:verifier-epoch")
    if _text(item["provider_graph_subject"], "adapter:subject") != profile.provider_graph_subject:
        raise StateSourceContractError("adapter:subject")
    if _text(item["scope"], "adapter:scope") != profile.scope:
        raise StateSourceContractError("adapter:scope")
    if _int(item["observation_time"], "adapter:observation-time") != profile.observation_time:
        raise StateSourceContractError("adapter:observation-time")
    sources = item["sources"]
    if not isinstance(sources, list) or len(sources) != len(profile.bindings):
        raise StateSourceContractError("sources:exact-count")
    validated: list[dict[str, object]] = []
    record_count = 0
    nonmembership_count = 0
    for source, binding in zip(sources, profile.bindings):
        validated_source, source_records, source_nonmembership = _validate_source(source, binding, profile)
        validated.append(validated_source)
        record_count += source_records
        nonmembership_count += source_nonmembership
    ids = [item["source_id"] for item in validated]
    expected_ids = [binding.source_id for binding in profile.bindings]
    if ids != expected_ids:
        raise StateSourceContractError("sources:identity-or-order")
    graph_input: dict[str, object] = {
        "schema": GRAPH_INPUT_SCHEMA,
        "provider_graph_subject": profile.provider_graph_subject,
        "scope": profile.scope,
        "observation_time": profile.observation_time,
        "sources": [{key: value for key, value in source.items() if key != "source_root"} for source in validated],
        "prior_artifact": None,
        "remediation": None,
        "parity_cases": [],
    }
    graph_input_raw = _canonical(graph_input)
    if len(graph_input_raw) > MAX_GRAPH_INPUT_BYTES:
        raise StateSourceContractError("graph-input:byte-cap")
    receipt_value = _receipt_value(item, graph_input, [source["source_root"] for source in validated], record_count, nonmembership_count)
    receipt_raw = _canonical(receipt_value)
    if len(receipt_raw) > MAX_RECEIPT_BYTES:
        raise StateSourceContractError("receipt:byte-cap")
    return StateSourceAdmission(
        graph_input=graph_input_raw,
        receipt=receipt_raw,
        source_roots=tuple(str(source["source_root"]) for source in validated),
        record_count=record_count,
        nonmembership_count=nonmembership_count,
    )


def admit(adapter_raw: bytes, *, expected_receipt: bytes | None = None) -> StateSourceAdmission:
    """Admit canonical adapter bytes through the verifier-owned V1 port.

    The operation is stateless and deterministic.  Supplying a prior receipt
    is an exact-retry check: a different adapter cannot silently reuse a prior
    source admission.
    """

    value = parse_adapter(adapter_raw)
    admission = _validate_adapter(value)
    if expected_receipt is not None:
        if type(expected_receipt) is not bytes or expected_receipt != admission.receipt:
            raise StateSourceContractError("retry:conflict")
    return admission


def _demo_record(kind: str, *, record_number: int = 1, valid_until: int = EFFECTIVE_END, status: str = STATUS_ACTIVE, terminated_at: int = 0) -> dict[str, object]:
    prefix = "CREDENTIAL" if kind == "CREDENTIAL" else "ENROLLMENT"
    return {
        "record_id": f"SYNTH_{prefix}_RECORD_{record_number:03d}",
        "record_kind": kind,
        "provider_id": PROVIDER_GRAPH_SUBJECT,
        "credential_id": CREDENTIAL_ID,
        "enrollment_id": ENROLLMENT_ID,
        "subject_key": SUBJECT_KEY,
        "observed_at": OBSERVATION_TIME,
        "issued_at": EFFECTIVE_START,
        "valid_from": EFFECTIVE_START,
        "valid_until": valid_until,
        "terminated_at": terminated_at,
        "status": status,
    }


def _demo_source(binding: SourceBinding, records: list[dict[str, object]], *, complete: bool = True, nonmembership: list[str] | None = None, end: int = EFFECTIVE_END) -> dict[str, object]:
    source: dict[str, object] = {
        "source_id": binding.source_id,
        "source_kind": binding.source_kind,
        "coverage_scope": SCOPE,
        "coverage_observation_time": OBSERVATION_TIME,
        "coverage_effective_start": EFFECTIVE_START,
        "coverage_effective_end": end,
        "coverage_complete": complete,
        "coverage_authority_id": binding.coverage_authority_id,
        "nonmembership_keys": [] if nonmembership is None else nonmembership,
        "records": records,
        "provenance": {"provenance_id": binding.provenance_id, "integrity_digest": "0" * 128},
        "source_root": "0" * 128,
    }
    source["provenance"]["integrity_digest"] = source_integrity_digest(source)  # type: ignore[index]
    source["source_root"] = source_root({key: value for key, value in source.items() if key != "source_root"})
    return source


def synthetic_test_adapter(case: str = "confirmed") -> bytes:
    """Return a bounded synthetic adapter fixture for tests and local KATs."""

    credential_record = _demo_record("CREDENTIAL")
    enrollment_record = _demo_record("ENROLLMENT")
    credential_records = [credential_record]
    enrollment_records = [enrollment_record]
    credential_complete = True
    enrollment_complete = True
    credential_nonmembership: list[str] = []
    enrollment_nonmembership: list[str] = []
    credential_end = EFFECTIVE_END
    enrollment_end = EFFECTIVE_END
    if case == "expired":
        credential_record["valid_until"] = 6_500
        credential_record["status"] = STATUS_EXPIRED
    elif case == "terminated":
        enrollment_record["terminated_at"] = 6_500
        enrollment_record["status"] = STATUS_TERMINATED
    elif case == "absent":
        credential_records = []
        enrollment_records = []
        credential_nonmembership = [SUBJECT_KEY]
        enrollment_nonmembership = [SUBJECT_KEY]
    elif case == "conflict":
        credential_records = [credential_record, _demo_record("CREDENTIAL", record_number=2)]
    elif case == "stale":
        credential_end = 6_999
    elif case == "incomplete":
        enrollment_complete = False
    elif case != "confirmed":
        raise StateSourceContractError("test:unknown-case")
    profile = STATE_SOURCE_CONTRACT
    value = {
        "schema": ADAPTER_SCHEMA,
        "profile_id": PROFILE_ID,
        "contract_version": CONTRACT_VERSION,
        "verifier_id": VERIFIER_ID,
        "verifier_epoch": VERIFIER_EPOCH,
        "provider_graph_subject": PROVIDER_GRAPH_SUBJECT,
        "scope": SCOPE,
        "observation_time": OBSERVATION_TIME,
        "sources": [
            _demo_source(profile.bindings[0], credential_records, complete=credential_complete, nonmembership=credential_nonmembership, end=credential_end),
            _demo_source(profile.bindings[1], enrollment_records, complete=enrollment_complete, nonmembership=enrollment_nonmembership, end=enrollment_end),
        ],
    }
    return canonical_adapter(value)


__all__ = [
    "ADAPTER_SCHEMA",
    "CONTRACT_VERSION",
    "GRAPH_INPUT_SCHEMA",
    "PROFILE_ID",
    "RECEIPT_SCHEMA",
    "StateSourceAdmission",
    "StateSourceContractError",
    "StateSourceContractV1",
    "STATE_SOURCE_CONTRACT",
    "admit",
    "canonical_adapter",
    "parse_adapter",
    "source_integrity_digest",
    "source_root",
    "synthetic_test_adapter",
]
