"""Independent verifier for the synthetic Mirror state-source contract.

This module intentionally duplicates the small adapter grammar, profile
constants, record checks, and Provider Trust Graph source roots.  It does not
import ``state_source_contract`` or any producer validation.  A successful
result means only that one synthetic adapter envelope is canonical and
internally coherent; it is not authenticated-source qualification.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Mapping, Sequence


class IndependentStateSourceContractError(ValueError):
    """Raised when an adapter envelope fails independent verification."""


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
BINDINGS = (
    {
        "source_id": SOURCE_CREDENTIAL_ID,
        "source_kind": SOURCE_CREDENTIAL_KIND,
        "coverage_authority_id": AUTH_CREDENTIAL_ID,
        "provenance_id": PROVENANCE_CREDENTIAL_ID,
        "record_kind": "CREDENTIAL",
    },
    {
        "source_id": SOURCE_ENROLLMENT_ID,
        "source_kind": SOURCE_ENROLLMENT_KIND,
        "coverage_authority_id": AUTH_ENROLLMENT_ID,
        "provenance_id": PROVENANCE_ENROLLMENT_ID,
        "record_kind": "ENROLLMENT",
    },
)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentStateSourceContractError("json:noncanonical-value") from exc


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentStateSourceContractError("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if count[0] > MAX_NODES:
        raise IndependentStateSourceContractError("json:node-cap")
    if depth > MAX_DEPTH:
        raise IndependentStateSourceContractError("json:depth-cap")
    if isinstance(value, float):
        raise IndependentStateSourceContractError("json:float-forbidden")
    if isinstance(value, str):
        try:
            raw = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise IndependentStateSourceContractError("json:non-ascii") from exc
        if len(raw) > MAX_STRING_BYTES:
            raise IndependentStateSourceContractError("json:string-cap")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentStateSourceContractError("json:key-type")
            _walk(key, depth + 1, count)
            _walk(item, depth + 1, count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, count)


def _reject_forbidden(value: object) -> None:
    if isinstance(value, str):
        if any(token in value for token in FORBIDDEN_EXTERNAL_TOKENS):
            raise IndependentStateSourceContractError("payload:forbidden-token")
    elif isinstance(value, dict):
        for key, item in value.items():
            if any(token in key for token in FORBIDDEN_EXTERNAL_TOKENS):
                raise IndependentStateSourceContractError("payload:forbidden-token")
            _reject_forbidden(item)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden(item)


def parse_adapter(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw:
        raise IndependentStateSourceContractError("json:empty-or-type")
    if len(raw) > MAX_ADAPTER_BYTES:
        raise IndependentStateSourceContractError("json:byte-cap")
    try:
        text = raw.decode("utf-8", errors="strict")
        if text.startswith("\ufeff"):
            raise IndependentStateSourceContractError("json:bom")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                IndependentStateSourceContractError("json:constant-forbidden")
            ),
        )
    except IndependentStateSourceContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentStateSourceContractError("json:parse") from exc
    if not isinstance(value, dict):
        raise IndependentStateSourceContractError("json:top-level")
    _walk(value)
    _reject_forbidden(value)
    if _canonical(value) != raw:
        raise IndependentStateSourceContractError("json:not-canonical")
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


def _profile_material() -> dict[str, object]:
    return {
        "schema": ADAPTER_SCHEMA,
        "profile_id": PROFILE_ID,
        "version": CONTRACT_VERSION,
        "provider_graph_subject": PROVIDER_GRAPH_SUBJECT,
        "subject_key": SUBJECT_KEY,
        "scope": SCOPE,
        "observation_time": OBSERVATION_TIME,
        "effective_start": EFFECTIVE_START,
        "effective_end": EFFECTIVE_END,
        "require_complete": True,
        "allow_nonmembership": True,
        "nonmembership_policy": "EXACT_SUBJECT_KEY_SORTED_UNIQUE_NO_FACT_CONFLICT_V1",
        "source_order_rule": "SOURCE_ID_PROFILE_ORDER_V1",
        "record_order_rule": "RECORD_ID_ASC_SORTED_UNIQUE_V1",
        "observation_rule": "OBSERVED_AT_EQUALS_PROFILE_TIME_V1",
        "validity_rule": "ISSUED_EQUALS_VALID_FROM_AND_STATUS_AT_OBSERVATION_V1",
        "integrity_rule": "SHA3_512_PROVIDER_GRAPH_SOURCE_INTEGRITY_V1",
        "root_rule": "SHA3_512_PROVIDER_GRAPH_SOURCE_ROOT_V1",
        "authentication_verifier_id": VERIFIER_ID,
        "authentication_verifier_epoch": VERIFIER_EPOCH,
        "bindings": [dict(binding) for binding in BINDINGS],
    }


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise IndependentStateSourceContractError(f"{label}:schema")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentStateSourceContractError(f"{label}:text")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise IndependentStateSourceContractError(f"{label}:ascii") from exc
    if len(raw) > MAX_STRING_BYTES:
        raise IndependentStateSourceContractError(f"{label}:length")
    return value


def _int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise IndependentStateSourceContractError(f"{label}:integer")
    if not 0 <= value <= MAX_TIMESTAMP:
        raise IndependentStateSourceContractError(f"{label}:range")
    return value


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise IndependentStateSourceContractError(f"{label}:boolean")
    return value


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise IndependentStateSourceContractError(f"{label}:hex")
    return value


def _sorted_unique(values: object, label: str, *, maximum: int) -> list[str]:
    if not isinstance(values, list) or len(values) > maximum:
        raise IndependentStateSourceContractError(f"{label}:list-cap")
    result = [_text(item, label) for item in values]
    if result != sorted(result) or len(set(result)) != len(result):
        raise IndependentStateSourceContractError(f"{label}:order-or-duplicate")
    return result


def _record_expected_status(record: Mapping[str, object], observation_time: int) -> str:
    issued = record["issued_at"]
    valid_until = record["valid_until"]
    terminated = record["terminated_at"]
    assert isinstance(issued, int) and isinstance(valid_until, int) and isinstance(terminated, int)
    if record["record_kind"] == "CREDENTIAL":
        if terminated != 0:
            raise IndependentStateSourceContractError("record:credential-termination")
        return STATUS_ACTIVE if observation_time < valid_until else STATUS_EXPIRED
    if terminated:
        if not issued <= terminated <= observation_time:
            raise IndependentStateSourceContractError("record:termination-time")
        return STATUS_TERMINATED
    return STATUS_ACTIVE if observation_time < valid_until else STATUS_EXPIRED


def _validate_record(record: object, binding: Mapping[str, str]) -> dict[str, object]:
    item = _expect_keys(record, RECORD_KEYS, "record")
    record_id = _text(item["record_id"], "record:id")
    if _RECORD.fullmatch(record_id) is None:
        raise IndependentStateSourceContractError("record:id:not-synthetic")
    if not record_id.startswith("SYNTH_" + binding["record_kind"]):
        raise IndependentStateSourceContractError("record:id:source-mismatch")
    if item["record_kind"] != binding["record_kind"]:
        raise IndependentStateSourceContractError("record:kind:source-mismatch")
    for field, expected in (
        ("provider_id", PROVIDER_GRAPH_SUBJECT),
        ("credential_id", CREDENTIAL_ID),
        ("enrollment_id", ENROLLMENT_ID),
        ("subject_key", SUBJECT_KEY),
    ):
        if _text(item[field], "record:" + field) != expected:
            raise IndependentStateSourceContractError("record:identity-mismatch")
    if _int(item["observed_at"], "record:observed_at") != OBSERVATION_TIME:
        raise IndependentStateSourceContractError("record:observation-mismatch")
    issued = _int(item["issued_at"], "record:issued_at")
    valid_from = _int(item["valid_from"], "record:valid_from")
    valid_until = _int(item["valid_until"], "record:valid_until")
    terminated = _int(item["terminated_at"], "record:terminated_at")
    if issued != valid_from or valid_until <= issued:
        raise IndependentStateSourceContractError("record:interval-contradiction")
    status = _text(item["status"], "record:status")
    if status not in STATUSES:
        raise IndependentStateSourceContractError("record:status:enum")
    if status != _record_expected_status(item, OBSERVATION_TIME):
        raise IndependentStateSourceContractError("record:status-time-mismatch")
    if binding["record_kind"] == "CREDENTIAL" and status == STATUS_TERMINATED:
        raise IndependentStateSourceContractError("record:credential-status")
    if binding["record_kind"] == "ENROLLMENT" and status == STATUS_EXPIRED:
        raise IndependentStateSourceContractError("record:enrollment-status")
    return item


def _source_integrity_material(source: Mapping[str, object]) -> dict[str, object]:
    material = dict(source)
    provenance = dict(material["provenance"])  # type: ignore[arg-type]
    provenance.pop("integrity_digest", None)
    material["provenance"] = provenance
    material.pop("source_root", None)
    return material


def _source_integrity_digest(source: Mapping[str, object]) -> str:
    return _graph_digest("source-integrity", _source_integrity_material(source))


def _source_root(source: Mapping[str, object]) -> str:
    return _graph_digest("source-root", {"source": dict(source)})


def _validate_source(source: object, binding: Mapping[str, str]) -> tuple[dict[str, object], int, int]:
    item = _expect_keys(source, SOURCE_KEYS, "source")
    if _text(item["source_id"], "source:id") != binding["source_id"]:
        raise IndependentStateSourceContractError("source:identity")
    if _text(item["source_kind"], "source:kind") != binding["source_kind"]:
        raise IndependentStateSourceContractError("source:kind-id-mismatch")
    provenance = _expect_keys(item["provenance"], PROVENANCE_KEYS, "source:provenance")
    if _text(provenance["provenance_id"], "source:provenance-id") != binding["provenance_id"]:
        raise IndependentStateSourceContractError("source:authority-or-provenance")
    if _text(item["coverage_scope"], "source:scope") != SCOPE:
        raise IndependentStateSourceContractError("source:scope")
    if _int(item["coverage_observation_time"], "source:coverage-observation") != OBSERVATION_TIME:
        raise IndependentStateSourceContractError("source:coverage-observation-mismatch")
    start = _int(item["coverage_effective_start"], "source:coverage-start")
    end = _int(item["coverage_effective_end"], "source:coverage-end")
    if start >= end or not start <= OBSERVATION_TIME < end:
        raise IndependentStateSourceContractError("source:stale-coverage")
    if (start, end) != (EFFECTIVE_START, EFFECTIVE_END):
        raise IndependentStateSourceContractError("source:coverage-contract-mismatch")
    if not _bool(item["coverage_complete"], "source:complete"):
        raise IndependentStateSourceContractError("source:partial-coverage")
    if _text(item["coverage_authority_id"], "source:authority") != binding["coverage_authority_id"]:
        raise IndependentStateSourceContractError("source:authority-or-provenance")
    nonmembership = _sorted_unique(item["nonmembership_keys"], "source:nonmembership", maximum=MAX_NONMEMBERSHIP_PER_SOURCE)
    if any(key != SUBJECT_KEY for key in nonmembership):
        raise IndependentStateSourceContractError("source:nonmembership-identity")
    records = item["records"]
    if not isinstance(records, list) or len(records) > MAX_RECORDS_PER_SOURCE:
        raise IndependentStateSourceContractError("source:record-cap")
    record_items = [_validate_record(record, binding) for record in records]
    record_ids = [record["record_id"] for record in record_items]
    if record_ids != sorted(record_ids) or len(set(record_ids)) != len(record_ids):
        raise IndependentStateSourceContractError("source:record-order-or-duplicate")
    if {record["subject_key"] for record in record_items} & set(nonmembership):
        raise IndependentStateSourceContractError("completeness:fact-nonmembership-conflict")
    _hex(provenance["integrity_digest"], "source:integrity")
    if provenance["integrity_digest"] != _source_integrity_digest(item):
        raise IndependentStateSourceContractError("source:integrity-mismatch")
    expected_root = _source_root({key: value for key, value in item.items() if key != "source_root"})
    if _hex(item["source_root"], "source:root") != expected_root:
        raise IndependentStateSourceContractError("source:root-mismatch")
    return item, len(record_items), len(nonmembership)


def _receipt_value(adapter: Mapping[str, object], graph_input: Mapping[str, object], roots: Sequence[str], record_count: int, nonmembership_count: int) -> dict[str, object]:
    profile = _profile_material()
    profile_root = _contract_digest("profile-root", profile)
    contract_id = _contract_digest("contract-id", profile)
    body: dict[str, object] = {
        "schema": RECEIPT_SCHEMA,
        "contract_id": contract_id,
        "contract_version": CONTRACT_VERSION,
        "profile_id": PROFILE_ID,
        "profile_root": profile_root,
        "adapter_digest": _contract_digest("adapter", adapter),
        "graph_input_digest": _contract_digest("graph-input", graph_input),
        "source_roots": list(roots),
        "provider_graph_subject": PROVIDER_GRAPH_SUBJECT,
        "scope": SCOPE,
        "observation_time": OBSERVATION_TIME,
        "record_count": record_count,
        "nonmembership_count": nonmembership_count,
        "authentication": {
            "verifier_id": VERIFIER_ID,
            "verifier_epoch": VERIFIER_EPOCH,
            "status": "SYNTHETIC_TEST_RECEIPT",
            "production_qualified": False,
        },
        "synthetic_only": True,
        "production_source_authentication": False,
    }
    return {"receipt_id": _contract_digest("receipt-id", body), **body}


def _validate_adapter(value: Mapping[str, object]) -> tuple[bytes, bytes, tuple[str, ...], int, int]:
    item = _expect_keys(value, ADAPTER_KEYS, "adapter")
    if _text(item["schema"], "adapter:schema") != ADAPTER_SCHEMA or item["profile_id"] != PROFILE_ID:
        raise IndependentStateSourceContractError("adapter:unknown-profile")
    if _int(item["contract_version"], "adapter:version") != CONTRACT_VERSION:
        raise IndependentStateSourceContractError("adapter:downgrade-or-version")
    if _text(item["verifier_id"], "adapter:verifier") != VERIFIER_ID:
        raise IndependentStateSourceContractError("adapter:verifier")
    if _int(item["verifier_epoch"], "adapter:verifier-epoch") != VERIFIER_EPOCH:
        raise IndependentStateSourceContractError("adapter:verifier-epoch")
    if _text(item["provider_graph_subject"], "adapter:subject") != PROVIDER_GRAPH_SUBJECT:
        raise IndependentStateSourceContractError("adapter:subject")
    if _text(item["scope"], "adapter:scope") != SCOPE:
        raise IndependentStateSourceContractError("adapter:scope")
    if _int(item["observation_time"], "adapter:observation-time") != OBSERVATION_TIME:
        raise IndependentStateSourceContractError("adapter:observation-time")
    sources = item["sources"]
    if not isinstance(sources, list) or len(sources) != MAX_SOURCES:
        raise IndependentStateSourceContractError("sources:exact-count")
    validated: list[dict[str, object]] = []
    record_count = 0
    nonmembership_count = 0
    for source, binding in zip(sources, BINDINGS):
        validated_source, source_records, source_nonmembership = _validate_source(source, binding)
        validated.append(validated_source)
        record_count += source_records
        nonmembership_count += source_nonmembership
    if [source["source_id"] for source in validated] != [binding["source_id"] for binding in BINDINGS]:
        raise IndependentStateSourceContractError("sources:identity-or-order")
    graph_input: dict[str, object] = {
        "schema": GRAPH_INPUT_SCHEMA,
        "provider_graph_subject": PROVIDER_GRAPH_SUBJECT,
        "scope": SCOPE,
        "observation_time": OBSERVATION_TIME,
        "sources": [{key: value for key, value in source.items() if key != "source_root"} for source in validated],
        "prior_artifact": None,
        "remediation": None,
        "parity_cases": [],
    }
    graph_input_raw = _canonical(graph_input)
    if len(graph_input_raw) > MAX_GRAPH_INPUT_BYTES:
        raise IndependentStateSourceContractError("graph-input:byte-cap")
    roots = tuple(str(source["source_root"]) for source in validated)
    receipt_raw = _canonical(_receipt_value(item, graph_input, roots, record_count, nonmembership_count))
    if len(receipt_raw) > MAX_RECEIPT_BYTES:
        raise IndependentStateSourceContractError("receipt:byte-cap")
    return graph_input_raw, receipt_raw, roots, record_count, nonmembership_count


def verify_bytes(raw: bytes, *, expected_receipt: bytes | None = None) -> dict[str, object]:
    """Independently verify adapter bytes and return bounded evidence."""

    value = parse_adapter(raw)
    graph_input, receipt, roots, record_count, nonmembership_count = _validate_adapter(value)
    if expected_receipt is not None and (type(expected_receipt) is not bytes or expected_receipt != receipt):
        raise IndependentStateSourceContractError("retry:conflict")
    return {
        "accepted": True,
        "contract_id": _contract_digest("contract-id", _profile_material()),
        "profile_root": _contract_digest("profile-root", _profile_material()),
        "adapter_digest": _contract_digest("adapter", value),
        "graph_input": graph_input,
        "receipt": receipt,
        "source_count": len(roots),
        "record_count": record_count,
        "nonmembership_count": nonmembership_count,
        "synthetic_only": True,
        "production_source_authentication": False,
    }


def verify_file(path: str | Path) -> dict[str, object]:
    target = Path(path)
    try:
        if not target.is_file() or target.stat().st_size > MAX_ADAPTER_BYTES:
            raise IndependentStateSourceContractError("file:byte-cap-or-type")
        raw = target.read_bytes()
    except IndependentStateSourceContractError:
        raise
    except OSError as exc:
        raise IndependentStateSourceContractError("file:read") from exc
    return verify_bytes(raw)


def _main(argv: Sequence[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m app.mirror.state_source_contract_independent ADAPTER.json", file=sys.stderr)
        return 2
    try:
        result = verify_file(argv[0])
        output = {key: value for key, value in result.items() if key not in {"graph_input", "receipt"}}
        print(json.dumps(output, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(f"REJECT {type(exc).__name__}:{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - exercised through subprocess tests.
    raise SystemExit(_main(sys.argv[1:]))


__all__ = [
    "IndependentStateSourceContractError",
    "parse_adapter",
    "verify_bytes",
    "verify_file",
]
