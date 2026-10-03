"""Read-only Switch replay and comparison for caller-classified synthetic input.

This module consumes only independently verified Continuity SHADOW bytes. It
never receives an incumbent Owner, Mirror, SQLite connection, or write API.
Every entry point needs caller-supplied trusted authority (with its
digest-bound roster) and scope; a snapshot never certifies its own authority.
Reference and candidate evaluators receive the same immutable canonical input
bytes and must be run by their caller inside an independently enforced,
no-egress environment. This module does not provide that OS boundary and does
not claim transfer, cutover, or approval authority.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
import hashlib
import json
import re
from time import monotonic_ns

from app.right_rail_financial_owner_independent import (
    IndependentFinancialError,
    MAX_CENTS,
    MAX_PACKAGE_BYTES,
    MAX_ROWS,
    CONTINUITY_SCHEMA,
    SCHEMA,
    SCHEMA_VERSION,
    verify_continuity_package,
)


REPLAY_INPUT_CONTRACT = "RR/SWITCH/REPLAY-INPUT/v1"
COHORT_APPROVAL_CONTRACT = "RR/SWITCH/COHORT-APPROVAL/v1"
COHORT_BINDING_CONTRACT = "RR/SWITCH/COHORT-BINDING/v1"
RESULT_CONTRACT = "RR/SWITCH/FINANCIAL-POPULATION-RESULT/v1"
RUN_REPORT_CONTRACT = "RR/SWITCH/RUN-REPORT/v1"
CURRENT_OWNER_SCHEMA_VERSION = SCHEMA_VERSION
MAX_REPLAY_INPUT_BYTES = 2 * MAX_PACKAGE_BYTES
MAX_RESULT_BYTES = 8 * 1024 * 1024
_EVALUATOR = Callable[[bytes], object]


class FinancialSwitchError(RuntimeError):
    """Raised for malformed Switch inputs or replay contracts."""


def _fail(code: str) -> None:
    raise FinancialSwitchError(code)


def _canonical_json(value: object, *, maximum: int) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("switch:canonical-json")
    if not encoded or len(encoded) > maximum:
        _fail("switch:canonical-size")
    return encoded


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("switch:duplicate-json-key")
        result[key] = value
    return result


def _decode_canonical_json(raw: bytes, *, maximum: int, label: str) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        _fail(f"{label}:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: _fail(f"{label}:constant"),
        )
    except FinancialSwitchError:
        raise
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError, RecursionError):
        _fail(f"{label}:json")
    if type(value) is not dict or _canonical_json(value, maximum=maximum) != raw:
        _fail(f"{label}:canonical")
    return value


def _matching(pattern: str) -> Callable[[object, str], str]:
    compiled = re.compile(pattern)

    def check(value: object, label: str) -> str:
        if type(value) is not str or compiled.fullmatch(value) is None:
            _fail(f"switch:{label}")
        return value

    return check


_id = _matching(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_sha256 = _matching(r"[0-9A-F]{64}\Z")
_sha3 = _matching(r"[0-9A-F]{128}\Z")


def _text(value: object, label: str, *, maximum: int = 1024) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or not value.isascii()
        or any(ord(character) < 0x20 for character in value)
    ):
        _fail(f"switch:{label}")
    return value


def _expect_keys(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        _fail(f"switch:{label}-fields")
    return value


# Wire record name -> ((wire key, field name), ...); one table drives records and replay-input keys.
_RECORDS = {
    "owner": (("owner_id", "owner_id"), ("schema", "owner_schema"), ("schema_version", "schema_version"),
              ("continuity_epoch", "continuity_epoch"), ("sequence", "sequence"), ("history_head", "history_head")),
    "authority": (("authority_id", "authority_id"), ("epoch", "authority_epoch"), ("digest", "authority_digest")),
    "scope": tuple((key, key) for key in ("state_id", "deployment_id", "program_id", "period_id", "currency")),
    "control_pack": (("pack_id", "control_pack_id"), ("version", "control_pack_version"), ("digest", "control_pack_digest"),
                     ("effective_start_ms", "control_pack_start_ms"), ("effective_end_ms", "control_pack_end_ms"),
                     ("calculation_rule_id", "calculation_rule_id"), ("adjustment_rule_id", "adjustment_rule_id")),
    "population": (("population_id", "population_id"), ("manifest_id", "manifest_id"), ("manifest_version", "manifest_version"),
                   ("manifest_digest", "manifest_digest"), ("member_digest", "member_digest"), ("member_ids", "member_ids")),
    "source": (("source_id", "source_id"), ("version", "source_version"), ("digest", "source_digest"),
               ("watermark_ms", "source_watermark_ms")),
}
_COHORT_TEXTS = ("test_identity", "source_class", "receiver_boundary_ref", "custody_ref", "permissions_ref", "pending_boundary_ref")


@dataclass(frozen=True, slots=True)
class _SnapshotRecords:
    """Wire-record fields shared by verified snapshot facts and decoded replay input."""

    owner_id: str
    owner_schema: str
    schema_version: int
    continuity_epoch: int
    sequence: int
    history_head: str
    authority_id: str
    authority_epoch: int
    authority_digest: str
    state_id: str
    deployment_id: str
    program_id: str
    period_id: str
    currency: str
    population_id: str
    manifest_id: str
    manifest_version: int
    manifest_digest: str
    member_ids: tuple[str, ...]
    member_digest: str
    control_pack_id: str
    control_pack_version: int
    control_pack_digest: str
    control_pack_start_ms: int
    control_pack_end_ms: int
    calculation_rule_id: str
    adjustment_rule_id: str
    source_id: str
    source_version: str
    source_digest: str
    source_watermark_ms: int

    def record(self, name: str) -> dict[str, object]:
        return {
            key: list(value) if type(value) is tuple else value
            for key, value in ((key, getattr(self, field)) for key, field in _RECORDS[name])
        }

    def binding_records(self) -> dict[str, object]:
        return {name: self.record(name) for name in _RECORDS}


@dataclass(frozen=True, slots=True)
class SnapshotFacts(_SnapshotRecords):
    """Identity and exact cohort facts derived from verified current-version SHADOW bytes."""

    snapshot_sha256: str
    package_digest: str

    def cohort_binding_bytes(self, *, cohort_id: str, **texts: str) -> bytes:
        """Return the canonical bytes an external cohort approval must bind."""

        if set(texts) != set(_COHORT_TEXTS):
            _fail("switch:cohort-binding-fields")
        payload = {
            "contract": COHORT_BINDING_CONTRACT,
            "cohort_id": _id(cohort_id, "cohort-id"),
            **{key: _text(texts[key], key.replace("_", "-")) for key in _COHORT_TEXTS},
            "snapshot_sha256": self.snapshot_sha256,
            **self.binding_records(),
        }
        return _canonical_json(payload, maximum=MAX_PACKAGE_BYTES)


def inspect_shadow_snapshot(
    snapshot_bytes: bytes,
    *,
    trusted_authority: object,
    expected_scope: Mapping[str, object],
) -> SnapshotFacts:
    """Independently verify and inspect one exact, complete current-version SHADOW package.

    ``trusted_authority`` (authority id, epoch, digest and roster) and
    ``expected_scope`` come from the caller; absent either, this fails closed.
    """

    if type(snapshot_bytes) is not bytes or not snapshot_bytes or len(snapshot_bytes) > MAX_PACKAGE_BYTES:
        _fail("switch:snapshot-byte-cap")
    if trusted_authority is None:
        _fail("switch:trusted-authority-required")
    if not isinstance(expected_scope, Mapping):
        _fail("switch:expected-scope-required")
    try:
        verified = verify_continuity_package(
            snapshot_bytes,
            expected_scope=expected_scope,
            expected_authority=trusted_authority,
            expected_schema_version=CURRENT_OWNER_SCHEMA_VERSION,
            _include_rows=True,
        )
    except IndependentFinancialError as error:
        raise FinancialSwitchError(f"switch:snapshot-integrity:{error}") from None
    raw_rows = verified.get("_decoded_rows")
    if type(raw_rows) is not dict:
        _fail("switch:snapshot-rows-missing")
    meta_rows = raw_rows.get("financial_meta")
    manifest_rows = raw_rows.get("population_manifests")
    member_rows = raw_rows.get("population_manifest_members")
    binding_rows = raw_rows.get("population_manifest_bindings")
    head_rows = raw_rows.get("population_manifest_heads")
    population_rows = raw_rows.get("population_imports")
    item_rows = raw_rows.get("population_items")
    pack_rows = raw_rows.get("control_packs")
    if any(type(rows) is not list for rows in (
        meta_rows,
        manifest_rows,
        member_rows,
        binding_rows,
        head_rows,
        population_rows,
        item_rows,
        pack_rows,
    )):
        _fail("switch:snapshot-table-shape")
    if len(meta_rows) != 1:
        _fail("switch:snapshot-meta-cardinality")
    meta = meta_rows[0]
    if type(meta) is not dict:
        _fail("switch:snapshot-meta-shape")
    if (
        verified.get("version") != CURRENT_OWNER_SCHEMA_VERSION
        or verified.get("schema") != CONTINUITY_SCHEMA
        or meta.get("schema_version") != CURRENT_OWNER_SCHEMA_VERSION
        or meta.get("mode") != "SHADOW"
    ):
        _fail("switch:snapshot-must-be-current-shadow")
    published = [
        row for row in population_rows
        if row.get("status") == "PUBLISHED" and row.get("source_complete") == 1
    ]
    if len(published) != 1:
        _fail("switch:snapshot-published-population-cardinality")
    population = published[0]
    population_id = _id(population.get("population_id"), "population-id")
    matching_bindings = [row for row in binding_rows if row.get("population_id") == population_id]
    if len(matching_bindings) != 1:
        _fail("switch:snapshot-population-binding")
    binding = matching_bindings[0]
    manifest_id = _id(binding.get("manifest_id"), "manifest-id")
    manifests = [row for row in manifest_rows if row.get("manifest_id") == manifest_id]
    if len(manifests) != 1:
        _fail("switch:snapshot-manifest-cardinality")
    manifest = manifests[0]
    heads = [row for row in head_rows if row.get("manifest_id") == manifest_id]
    if len(heads) != 1:
        _fail("switch:snapshot-manifest-not-current-head")
    member_ids = tuple(
        _id(row.get("member_id"), "manifest-member-id")
        for row in sorted(
            (row for row in member_rows if row.get("manifest_id") == manifest_id),
            key=lambda row: row.get("position", -1),
        )
    )
    if not member_ids or len(member_ids) > MAX_ROWS or tuple(sorted(set(member_ids))) != member_ids:
        _fail("switch:snapshot-manifest-members")
    imported_ids = tuple(sorted(
        _id(row.get("item_id"), "population-item-id")
        for row in item_rows
        if row.get("population_id") == population_id
    ))
    if imported_ids != member_ids:
        _fail("switch:snapshot-population-members-incomplete")
    pack_id = _id(manifest.get("pack_id"), "control-pack-id")
    packs = [row for row in pack_rows if row.get("pack_id") == pack_id]
    if len(packs) != 1:
        _fail("switch:snapshot-control-pack-cardinality")
    pack = packs[0]
    if pack.get("status") != "APPROVED":
        _fail("switch:snapshot-control-pack-not-approved")
    try:
        scope = verified["scope"]
        authority = verified["authority"]
        if type(scope) is not dict or type(authority) is not dict:
            _fail("switch:snapshot-scope-shape")
        result = SnapshotFacts(
            snapshot_sha256=hashlib.sha256(snapshot_bytes).hexdigest().upper(),
            package_digest=_sha3(verified.get("package_digest"), "package-digest"),
            owner_id=_id(meta.get("owner_id"), "owner-id"),
            owner_schema=SCHEMA,
            schema_version=CURRENT_OWNER_SCHEMA_VERSION,
            continuity_epoch=_checked_integer(verified.get("continuity_epoch"), "continuity-epoch", minimum=1),
            sequence=_checked_integer(verified.get("sequence"), "owner-sequence", minimum=0),
            history_head=_sha3(verified.get("history_head"), "history-head"),
            authority_id=_id(authority.get("authority_id"), "authority-id"),
            authority_epoch=_checked_integer(authority.get("epoch"), "authority-epoch", minimum=1),
            authority_digest=_sha3(authority.get("digest"), "authority-digest"),
            state_id=_id(scope.get("state_id"), "state-id"),
            deployment_id=_id(scope.get("deployment_id"), "deployment-id"),
            program_id=_id(scope.get("program_id"), "program-id"),
            period_id=_id(scope.get("period_id"), "period-id"),
            currency=_text(scope.get("currency"), "currency", maximum=3),
            population_id=population_id,
            manifest_id=manifest_id,
            manifest_version=_checked_integer(manifest.get("manifest_version"), "manifest-version", minimum=1),
            manifest_digest=bytes(manifest["manifest_digest"]).hex().upper(),
            member_ids=member_ids,
            member_digest=bytes(manifest["member_digest"]).hex().upper(),
            control_pack_id=pack_id,
            control_pack_version=_checked_integer(pack.get("version"), "control-pack-version", minimum=1),
            control_pack_digest=bytes(pack["pack_digest"]).hex().upper(),
            control_pack_start_ms=_checked_integer(pack.get("effective_start_ms"), "control-pack-start", minimum=0),
            control_pack_end_ms=_checked_integer(pack.get("effective_end_ms"), "control-pack-end", minimum=1),
            calculation_rule_id=_id(pack.get("calculation_rule_id"), "calculation-rule-id"),
            adjustment_rule_id=_id(pack.get("adjustment_rule_id"), "adjustment-rule-id"),
            source_id=_id(manifest.get("source_id"), "source-id"),
            source_version=_text(manifest.get("source_version"), "source-version"),
            source_digest=bytes(manifest["source_digest"]).hex().upper(),
            source_watermark_ms=_checked_integer(manifest.get("cutoff_ms"), "source-watermark", minimum=0),
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        _fail("switch:snapshot-identity-shape")
    if result.control_pack_end_ms <= result.control_pack_start_ms:
        _fail("switch:snapshot-control-pack-interval")
    if (
        population.get("pack_id") != result.control_pack_id
        or manifest.get("period_id") != result.period_id
        or population.get("cutoff_ms") != result.source_watermark_ms
    ):
        _fail("switch:snapshot-population-binding")
    return result


def _checked_integer(value: object, label: str, *, minimum: int = 0, maximum: int = MAX_CENTS) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        _fail(f"switch:{label}")
    return value


@dataclass(frozen=True, slots=True)
class CohortApproval:
    """Caller-supplied State approval record; not cryptographically verified here."""

    approval_id: str
    cohort_id: str
    test_identity: str
    approved_by: str
    approval_ref: str
    source_class: str
    receiver_boundary_ref: str
    custody_ref: str
    permissions_ref: str
    pending_boundary_ref: str
    binding_sha256: str
    contract: str = COHORT_APPROVAL_CONTRACT


@dataclass(frozen=True, slots=True)
class DifferencePolicy:
    """One explicitly referenced expected or forbidden difference path."""

    path: str
    classification: str
    rationale: str
    approval_ref: str


@dataclass(frozen=True, slots=True)
class ReferenceSpec:
    """Caller-supplied independent reference identity and evaluator."""

    reference_id: str
    version: str
    authority_id: str
    reviewer_id: str
    source_ref: str
    source_sha256: str
    tool_version: str
    evaluate: _EVALUATOR
    expected_differences: tuple[DifferencePolicy, ...] = ()
    forbidden_differences: tuple[DifferencePolicy, ...] = ()


@dataclass(frozen=True, slots=True)
class CandidateSpec:
    """One caller-supplied candidate release and evaluator."""

    operator_id: str
    version: str
    tool_version: str
    release_sha256: str
    evaluate: _EVALUATOR


@dataclass(frozen=True, slots=True)
class DecodedReplayInput(_SnapshotRecords):
    """Immutable, validated view of RR/SWITCH/REPLAY-INPUT/v1 bytes."""

    canonical_bytes: bytes
    input_sha256: str
    snapshot_package_bytes: bytes
    cohort_id: str
    reference_id: str
    reference_version: str
    reference_tool_version: str
    reference_source_sha256: str
    candidate_id: str
    candidate_version: str
    candidate_tool_version: str
    candidate_release_sha256: str

    def output_binding(
        self,
        *,
        producer_kind: str,
        producer_id: str,
        version: str,
        tool_version: str,
        artifact_sha256: str,
    ) -> dict[str, object]:
        return {
            "contract": RESULT_CONTRACT,
            "input_sha256": self.input_sha256,
            "producer": {
                "kind": producer_kind,
                "id": producer_id,
                "version": version,
                "tool_version": tool_version,
                "artifact_sha256": artifact_sha256,
            },
            **self.binding_records(),
        }

    def reference_output_binding(self) -> dict[str, object]:
        return self.output_binding(
            producer_kind="REFERENCE",
            producer_id=self.reference_id,
            version=self.reference_version,
            tool_version=self.reference_tool_version,
            artifact_sha256=self.reference_source_sha256,
        )


def decode_replay_input(
    raw: bytes,
    *,
    trusted_authority: object,
    expected_scope: Mapping[str, object],
) -> DecodedReplayInput:
    """Strictly decode one canonical replay input for evaluator implementations."""

    value = _decode_canonical_json(raw, maximum=MAX_REPLAY_INPUT_BYTES, label="switch:replay-input")
    _expect_keys(
        value,
        {"contract", "cohort", "owner", "authority", "scope", "control_pack", "population", "source", "reference", "candidate", "snapshot"},
        "replay-input",
    )
    if value["contract"] != REPLAY_INPUT_CONTRACT:
        _fail("switch:replay-input-version")
    cohort = _expect_keys(
        value["cohort"],
        {"cohort_id", "test_identity", "approval_id", "approved_by", "approval_ref", "source_class", "receiver_boundary_ref", "custody_ref", "permissions_ref", "pending_boundary_ref", "binding_sha256"},
        "replay-cohort",
    )
    records = {
        name: _expect_keys(value[name], {key for key, _ in fields}, f"replay-{name.replace('_', '-')}")
        for name, fields in _RECORDS.items()
    }
    population = records["population"]
    reference = _expect_keys(value["reference"], {"reference_id", "version", "authority_id", "reviewer_id", "source_ref", "source_sha256", "tool_version", "expected_differences", "forbidden_differences"}, "replay-reference")
    candidate = _expect_keys(value["candidate"], {"operator_id", "version", "tool_version", "release_sha256"}, "replay-candidate")
    snapshot = _expect_keys(value["snapshot"], {"mode", "package_digest", "sha256", "package_base64"}, "replay-snapshot")
    if snapshot.get("mode") != "SHADOW":
        _fail("switch:replay-snapshot-mode")
    try:
        package_bytes = base64.b64decode(snapshot["package_base64"], validate=True)
    except (ValueError, TypeError):
        _fail("switch:replay-snapshot-base64")
    if len(package_bytes) > MAX_PACKAGE_BYTES or hashlib.sha256(package_bytes).hexdigest().upper() != snapshot.get("sha256"):
        _fail("switch:replay-snapshot-digest")
    facts = inspect_shadow_snapshot(
        package_bytes,
        trusted_authority=trusted_authority,
        expected_scope=expected_scope,
    )
    if records != facts.binding_records():
        _fail("switch:replay-binding")
    if snapshot.get("package_digest") != facts.package_digest:
        _fail("switch:replay-package-digest")
    if cohort.get("source_class") != "SYNTHETIC":
        _fail("switch:replay-source-class")
    cohort_binding = facts.cohort_binding_bytes(
        cohort_id=_id(cohort.get("cohort_id"), "replay-cohort-id"),
        **{key: _text(cohort.get(key), "replay-" + key.replace("_", "-")) for key in _COHORT_TEXTS},
    )
    if hashlib.sha256(cohort_binding).hexdigest().upper() != _sha256(cohort.get("binding_sha256"), "replay-cohort-binding"):
        _fail("switch:replay-cohort-binding")
    _id(cohort.get("approval_id"), "replay-approval-id")
    _id(cohort.get("approved_by"), "replay-approver-id")
    _text(cohort.get("approval_ref"), "replay-approval-ref")
    _id(reference.get("authority_id"), "replay-reference-authority")
    _id(reference.get("reviewer_id"), "replay-reference-reviewer")
    _text(reference.get("source_ref"), "replay-reference-source-ref")
    _id(reference.get("reference_id"), "replay-reference-id")
    _text(reference.get("version"), "replay-reference-version")
    _text(reference.get("tool_version"), "replay-reference-tool-version")
    _sha256(reference.get("source_sha256"), "replay-reference-source-digest")
    _id(candidate.get("operator_id"), "replay-candidate-id")
    _text(candidate.get("version"), "replay-candidate-version")
    _text(candidate.get("tool_version"), "replay-candidate-tool-version")
    _sha256(candidate.get("release_sha256"), "replay-candidate-release-digest")
    member_ids = population.get("member_ids")
    if type(member_ids) is not list or not member_ids or len(member_ids) > MAX_ROWS:
        _fail("switch:replay-member-list")
    _validate_policy_wire(reference.get("expected_differences"), "EXPECTED", tuple(member_ids))
    _validate_policy_wire(reference.get("forbidden_differences"), "FORBIDDEN", tuple(member_ids))
    return DecodedReplayInput(
        canonical_bytes=raw,
        input_sha256=hashlib.sha256(raw).hexdigest().upper(),
        snapshot_package_bytes=package_bytes,
        cohort_id=_id(cohort.get("cohort_id"), "replay-cohort-id"),
        **{field.name: getattr(facts, field.name) for field in fields(_SnapshotRecords)},
        reference_id=_id(reference.get("reference_id"), "replay-reference-id"),
        reference_version=_text(reference.get("version"), "replay-reference-version"),
        reference_tool_version=_text(reference.get("tool_version"), "replay-reference-tool-version"),
        reference_source_sha256=_sha256(reference.get("source_sha256"), "replay-reference-source-digest"),
        candidate_id=_id(candidate.get("operator_id"), "replay-candidate-id"),
        candidate_version=_text(candidate.get("version"), "replay-candidate-version"),
        candidate_tool_version=_text(candidate.get("tool_version"), "replay-candidate-tool-version"),
        candidate_release_sha256=_sha256(candidate.get("release_sha256"), "replay-candidate-release-digest"),
    )


def _policy_path(path: object, member_ids: tuple[str, ...]) -> str:
    if type(path) is not str:
        _fail("switch:difference-path")
    if path == "aggregate.total_owed_cents":
        return path
    parts = path.split(".")
    if len(parts) == 3 and parts[0] == "members" and parts[1] in member_ids and parts[2] == "owed_cents":
        return path
    _fail("switch:difference-path")


def _validate_policy_wire(value: object, expected_class: str, member_ids: tuple[str, ...]) -> None:
    if type(value) is not list or len(value) > MAX_ROWS:
        _fail("switch:difference-policy-list")
    seen: set[str] = set()
    for rule in value:
        rule = _expect_keys(rule, {"path", "classification", "rationale", "approval_ref"}, "difference-policy")
        path = _policy_path(rule.get("path"), member_ids)
        if path in seen or rule.get("classification") != expected_class:
            _fail("switch:difference-policy-binding")
        seen.add(path)
        _text(rule.get("rationale"), "difference-rationale")
        _text(rule.get("approval_ref"), "difference-approval-ref")


def _policy_records(
    policies: tuple[DifferencePolicy, ...],
    expected_class: str,
    member_ids: tuple[str, ...],
) -> list[dict[str, str]]:
    if type(policies) is not tuple or len(policies) > MAX_ROWS:
        _fail("switch:difference-policy-type")
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for policy in policies:
        if type(policy) is not DifferencePolicy or policy.classification != expected_class:
            _fail("switch:difference-policy-class")
        path = _policy_path(policy.path, member_ids)
        if path in seen:
            _fail("switch:difference-policy-duplicate")
        seen.add(path)
        records.append({
            "path": path,
            "classification": expected_class,
            "rationale": _text(policy.rationale, "difference-rationale"),
            "approval_ref": _text(policy.approval_ref, "difference-approval-ref"),
        })
    return records


def _validate_approval(approval: CohortApproval | None, facts: SnapshotFacts) -> tuple[dict[str, object] | None, str | None]:
    if approval is None:
        return None, "cohort_approval_missing"
    if type(approval) is not CohortApproval or approval.contract != COHORT_APPROVAL_CONTRACT:
        return None, "cohort_approval_schema"
    try:
        record = {
            "cohort_id": _id(approval.cohort_id, "cohort-id"),
            "approval_id": _id(approval.approval_id, "approval-id"),
            "approved_by": _id(approval.approved_by, "approver-id"),
            "approval_ref": _text(approval.approval_ref, "approval-ref"),
            **{key: _text(getattr(approval, key), key.replace("_", "-")) for key in _COHORT_TEXTS},
            "binding_sha256": _sha256(approval.binding_sha256, "cohort-binding-digest"),
        }
        binding_bytes = facts.cohort_binding_bytes(
            **{key: record[key] for key in ("cohort_id", *_COHORT_TEXTS)}
        )
    except FinancialSwitchError:
        return None, "cohort_approval_fields"
    if record["source_class"] != "SYNTHETIC":
        return None, "snapshot_source_not_approved_synthetic"
    if hashlib.sha256(binding_bytes).hexdigest().upper() != record["binding_sha256"]:
        return None, "cohort_approval_binding_mismatch"
    return record, None


def _reference_identity(reference: ReferenceSpec) -> dict[str, str]:
    return {
        "reference_id": _id(reference.reference_id, "reference-id"),
        "version": _text(reference.version, "reference-version"),
        "authority_id": _id(reference.authority_id, "reference-authority-id"),
        "reviewer_id": _id(reference.reviewer_id, "reference-reviewer-id"),
        "source_ref": _text(reference.source_ref, "reference-source-ref"),
        "source_sha256": _sha256(reference.source_sha256, "reference-source-digest"),
        "tool_version": _text(reference.tool_version, "reference-tool-version"),
    }


def _candidate_identity(candidate: CandidateSpec) -> dict[str, str]:
    return {
        "operator_id": _id(candidate.operator_id, "candidate-id"),
        "version": _text(candidate.version, "candidate-version"),
        "tool_version": _text(candidate.tool_version, "candidate-tool-version"),
        "release_sha256": _sha256(candidate.release_sha256, "candidate-release-digest"),
    }


def _build_replay_input(
    snapshot_bytes: bytes,
    facts: SnapshotFacts,
    approval_record: dict[str, object],
    reference: ReferenceSpec,
    candidate: CandidateSpec,
) -> tuple[bytes, dict[str, str], dict[str, str], list[dict[str, str]], list[dict[str, str]]]:
    reference_record = _reference_identity(reference)
    candidate_record = _candidate_identity(candidate)
    expected_policies = _policy_records(reference.expected_differences, "EXPECTED", facts.member_ids)
    forbidden_policies = _policy_records(reference.forbidden_differences, "FORBIDDEN", facts.member_ids)
    if approval_record.get("approved_by") == candidate_record["operator_id"]:
        _fail("switch:candidate-self-approval")
    if candidate_record["operator_id"] in {reference_record["authority_id"], reference_record["reviewer_id"]}:
        _fail("switch:reference-candidate-identity-overlap")
    expected_paths = {policy["path"] for policy in expected_policies}
    if expected_paths & {policy["path"] for policy in forbidden_policies}:
        _fail("switch:difference-policy-conflict")
    payload = {
        "contract": REPLAY_INPUT_CONTRACT,
        "cohort": approval_record,
        **facts.binding_records(),
        "reference": {
            **reference_record,
            "expected_differences": expected_policies,
            "forbidden_differences": forbidden_policies,
        },
        "candidate": candidate_record,
        "snapshot": {
            "mode": "SHADOW",
            "package_digest": facts.package_digest,
            "sha256": facts.snapshot_sha256,
            "package_base64": base64.b64encode(snapshot_bytes).decode("ascii"),
        },
    }
    replay_input = _canonical_json(payload, maximum=MAX_REPLAY_INPUT_BYTES)
    return replay_input, reference_record, candidate_record, expected_policies, forbidden_policies


def prepare_shadow_replay_input(
    snapshot_bytes: bytes,
    *,
    trusted_authority: object,
    expected_scope: Mapping[str, object],
    cohort_approval: CohortApproval,
    reference: ReferenceSpec,
    candidate: CandidateSpec,
) -> bytes:
    """Build the exact canonical input that both independent evaluators consume.

    This preparation function never invokes either evaluator. The caller can
    hand the returned bytes to separately controlled reference and candidate
    runners, then submit their input-bound results to ``run_shadow_replay``.
    """

    facts = inspect_shadow_snapshot(
        snapshot_bytes,
        trusted_authority=trusted_authority,
        expected_scope=expected_scope,
    )
    if type(reference) is not ReferenceSpec or type(candidate) is not CandidateSpec:
        _fail("switch:operator-spec-schema")
    approval_record, approval_error = _validate_approval(cohort_approval, facts)
    if approval_error is not None or approval_record is None:
        _fail(approval_error or "switch:cohort-approval-invalid")
    return _build_replay_input(snapshot_bytes, facts, approval_record, reference, candidate)[0]


def _result_binding(
    facts: SnapshotFacts,
    input_sha256: str,
    producer: Mapping[str, str],
) -> dict[str, object]:
    return {
        "contract": RESULT_CONTRACT,
        "input_sha256": input_sha256,
        "producer": dict(producer),
        **facts.binding_records(),
    }


def _validate_output(
    output: object,
    *,
    facts: SnapshotFacts,
    input_sha256: str,
    producer: Mapping[str, str],
    label: str,
) -> tuple[dict[str, object] | None, list[str]]:
    errors: list[str] = []
    if type(output) is not dict:
        return None, [f"{label}:result-not-object"]
    try:
        canonical_output = _canonical_json(output, maximum=MAX_RESULT_BYTES)
    except FinancialSwitchError:
        return None, [f"{label}:result-byte-cap-or-type"]
    expected_top = {
        "contract", "input_sha256", "producer", "owner", "authority", "scope",
        "control_pack", "population", "source", "member_results", "aggregate",
    }
    actual_top = set(output)
    if actual_top != expected_top:
        extras = sorted(str(key) for key in actual_top - expected_top)
        missing = sorted(expected_top - actual_top)
        if extras:
            errors.append(f"{label}:unknown-result-fields:{','.join(extras)}")
        if missing:
            errors.append(f"{label}:missing-result-fields:{','.join(missing)}")
    if output.get("contract") != RESULT_CONTRACT:
        errors.append(f"{label}:result-contract")
    if output.get("input_sha256") != input_sha256:
        errors.append(f"{label}:input-binding")
    expected_binding = _result_binding(facts, input_sha256, producer)
    for key, expected in expected_binding.items():
        if key == "contract" or key == "input_sha256":
            continue
        if output.get(key) != expected:
            errors.append(f"{label}:{key}-binding")
    member_results = output.get("member_results")
    if type(member_results) is not list or len(member_results) > MAX_ROWS:
        errors.append(f"{label}:member-results-shape")
        member_results = []
    seen: set[str] = set()
    total = 0
    for index, record in enumerate(member_results):
        if type(record) is not dict or set(record) != {"member_id", "currency", "owed_cents"}:
            errors.append(f"{label}:member-result-fields:{index}")
            continue
        member_id = record.get("member_id")
        if type(member_id) is not str or member_id not in facts.member_ids or member_id in seen:
            errors.append(f"{label}:member-result-identity:{index}")
            continue
        seen.add(member_id)
        amount = record.get("owed_cents")
        if record.get("currency") != facts.currency or type(amount) is not int or not 0 <= amount <= MAX_CENTS:
            errors.append(f"{label}:member-result-type:{member_id}")
            continue
        total += amount
    if tuple(record.get("member_id") for record in member_results if type(record) is dict and type(record.get("member_id")) is str) != facts.member_ids:
        errors.append(f"{label}:member-results-order-or-membership")
    aggregate = output.get("aggregate")
    if type(aggregate) is not dict or set(aggregate) != {"member_count", "total_owed_cents", "currency"}:
        errors.append(f"{label}:aggregate-fields")
    elif (
        type(aggregate.get("member_count")) is not int
        or aggregate.get("member_count") != len(facts.member_ids)
        or type(aggregate.get("total_owed_cents")) is not int
        or aggregate.get("total_owed_cents") != total
        or aggregate.get("currency") != facts.currency
    ):
        errors.append(f"{label}:aggregate-reconciliation")
    elif total > MAX_CENTS:
        errors.append(f"{label}:aggregate-total-bound")
    if errors:
        return None, errors
    normalized = json.loads(canonical_output.decode("ascii"))
    return normalized, []


def _comparable_values(output: Mapping[str, object], facts: SnapshotFacts) -> dict[str, object]:
    values: dict[str, object] = {}
    aggregate = output["aggregate"]
    assert type(aggregate) is dict
    values["aggregate.member_count"] = aggregate["member_count"]
    values["aggregate.total_owed_cents"] = aggregate["total_owed_cents"]
    values["aggregate.currency"] = aggregate["currency"]
    rows = output["member_results"]
    assert type(rows) is list
    for row in rows:
        assert type(row) is dict
        member_id = row["member_id"]
        values[f"members.{member_id}.currency"] = row["currency"]
        values[f"members.{member_id}.owed_cents"] = row["owed_cents"]
    return values


def _member_audit(output: object, facts: SnapshotFacts) -> dict[str, object]:
    rows = output.get("member_results") if type(output) is dict else None
    if type(rows) is not list:
        return {
            "status": "NO_MEMBER_RESULTS",
            "received_member_count": 0,
            "unique_received_member_count": 0,
            "omitted_member_ids": [],
            "extra_member_ids": [],
            "duplicate_member_ids": [],
            "rejected_member_record_count": 0,
        }
    if len(rows) > MAX_ROWS:
        return {
            "status": "OUTPUT_MEMBER_COUNT_EXCEEDED",
            "received_member_count": len(rows),
            "unique_received_member_count": None,
            "omitted_member_ids": [],
            "extra_member_ids": [],
            "duplicate_member_ids": [],
            "rejected_member_record_count": None,
        }
    received_ids: list[str] = []
    rejected = 0
    for row in rows:
        if type(row) is not dict or type(row.get("member_id")) is not str:
            rejected += 1
            continue
        if set(row) != {"member_id", "currency", "owed_cents"}:
            rejected += 1
        received_ids.append(row["member_id"])
    expected = set(facts.member_ids)
    received = set(received_ids)
    seen: set[str] = set()
    duplicate_ids: set[str] = set()
    for member_id in received_ids:
        if member_id in seen:
            duplicate_ids.add(member_id)
        seen.add(member_id)
    return {
        "status": "OUTPUT_RETURNED",
        "received_member_count": len(rows),
        "unique_received_member_count": len(received),
        "omitted_member_ids": sorted(expected - received),
        "extra_member_ids": sorted(received - expected),
        "duplicate_member_ids": sorted(duplicate_ids),
        "rejected_member_record_count": rejected,
    }


def _unknown(report: dict[str, object], reasons: list[str], unknowns: list[str]) -> dict[str, object]:
    report["reasons"] = reasons
    report["unknowns"] = [{"class": "UNKNOWN", "reason": reason} for reason in unknowns]
    return report


def _run_evaluator(evaluator: _EVALUATOR, replay_input: bytes, *, label: str) -> tuple[object | None, int | None, str | None]:
    if not callable(evaluator):
        return None, None, f"{label}:evaluator-missing"
    started = monotonic_ns()
    try:
        result = evaluator(replay_input)
    except Exception as error:
        return None, monotonic_ns() - started, f"{label}:evaluator-raised:{type(error).__name__}"
    return result, monotonic_ns() - started, None


def _base_report(
    *,
    status: str,
    reasons: list[str],
    facts: SnapshotFacts | None = None,
    input_sha256: str | None = None,
) -> dict[str, object]:
    return {
        "contract": RUN_REPORT_CONTRACT,
        "status": status,
        "comparison_status": "INCOMPLETE",
        "reasons": reasons,
        "replay_input_sha256": input_sha256,
        "snapshot": None if facts is None else {
            "sha256": facts.snapshot_sha256,
            "package_digest": facts.package_digest,
            "mode": "SHADOW",
            "independent_verification": "PASS",
            "restore_status": "NOT_PERFORMED_BY_SWITCH",
            "owner_id": facts.owner_id,
            "schema": facts.owner_schema,
            "schema_version": facts.schema_version,
            "continuity_epoch": facts.continuity_epoch,
            "sequence": facts.sequence,
            "history_head": facts.history_head,
            "authority": facts.record("authority"),
            "scope": facts.record("scope"),
            "population": facts.record("population"),
            "control_pack": facts.record("control_pack"),
            "source": facts.record("source"),
        },
        "expected_member_count": 0 if facts is None else len(facts.member_ids),
        "reference_received_member_count": 0,
        "candidate_received_member_count": 0,
        "member_audit": {
            "reference": {"status": "NOT_RUN", "omitted_member_ids": [], "extra_member_ids": [], "duplicate_member_ids": [], "rejected_member_record_count": 0},
            "candidate": {"status": "NOT_RUN", "omitted_member_ids": [], "extra_member_ids": [], "duplicate_member_ids": [], "rejected_member_record_count": 0},
        },
        "matched_field_count": 0,
        "differences": [],
        "unknowns": [],
        "unused_difference_rules": [],
        "resources": {
            "replay_input_bytes": None,
            "reference_output_bytes": None,
            "candidate_output_bytes": None,
            "reference_elapsed_ns": None,
            "candidate_elapsed_ns": None,
            "peak_memory_bytes": None,
            "profile": "PARTIAL_LOCAL",
            "evaluation_timeout_enforced_by_module": False,
        },
        "isolation": {
            "evaluator_input": "CANONICAL_REPLAY_BYTES_ONLY",
            "incumbent_owner_or_database_passed_as_input": False,
            "evaluator_closure_isolation": "UNVERIFIED",
            "dispatch_api_called_by_switch": False,
            "egress_api_called_by_switch": False,
            "network_egress_enforced_by_module": False,
            "status": "CALLER_BOUNDARY_UNVERIFIED",
        },
        "candidate_authority": "NONE",
        "transfer_authorized": False,
        "source_class_verification": "CALLER_ASSERTED",
        "reference_independence": "CALLER_ASSERTED",
        "cohort_approval_authentication": "CALLER_ASSERTED",
        "difference_policy_approval": "CALLER_ASSERTED",
    }


def run_shadow_replay(
    snapshot_bytes: bytes,
    *,
    trusted_authority: object,
    expected_scope: Mapping[str, object],
    cohort_approval: CohortApproval | None = None,
    reference: ReferenceSpec | None = None,
    candidate: CandidateSpec | None = None,
) -> dict[str, object]:
    """Compare one independent reference and candidate over the same bytes.

    Missing approval or operator facts produce an INCOMPLETE report and no
    evaluator call. The report is comparison evidence only; this function has
    no cutover, transfer, routing, Owner, database, or dispatch API.
    """

    try:
        facts = inspect_shadow_snapshot(
            snapshot_bytes,
            trusted_authority=trusted_authority,
            expected_scope=expected_scope,
        )
    except FinancialSwitchError as error:
        return _unknown(_base_report(status="INVALID_SNAPSHOT", reasons=[str(error)]), [str(error)], [str(error)])
    missing: list[str] = []
    if cohort_approval is None:
        missing.append("cohort_approval_missing")
    if reference is None:
        missing.append("independent_reference_missing")
    if candidate is None:
        missing.append("candidate_missing")
    if missing:
        return _base_report(status="INCOMPLETE", reasons=missing, facts=facts)
    assert cohort_approval is not None and reference is not None and candidate is not None
    if type(reference) is not ReferenceSpec or type(candidate) is not CandidateSpec:
        return _unknown(_base_report(status="INCOMPLETE", reasons=[], facts=facts), ["operator_spec_schema"], ["operator_spec_schema"])
    approval_record, approval_error = _validate_approval(cohort_approval, facts)
    if approval_error is not None or approval_record is None:
        reason = approval_error or "cohort_approval_invalid"
        return _unknown(_base_report(status="INCOMPLETE", reasons=[], facts=facts), [reason], [reason])
    try:
        if not callable(reference.evaluate) or not callable(candidate.evaluate):
            _fail("switch:evaluator-missing")
        (
            replay_input,
            reference_record,
            candidate_record,
            expected_policies,
            forbidden_policies,
        ) = _build_replay_input(snapshot_bytes, facts, approval_record, reference, candidate)
    except FinancialSwitchError as error:
        return _unknown(_base_report(status="INCOMPLETE", reasons=[], facts=facts), [str(error)], [str(error)])
    assert approval_record is not None
    input_sha256 = hashlib.sha256(replay_input).hexdigest().upper()
    report = _base_report(status="INCOMPLETE", reasons=[], facts=facts, input_sha256=input_sha256)
    report["reference_identity"] = reference_record
    report["candidate_identity"] = candidate_record
    report["cohort_approval"] = approval_record
    report["resources"]["replay_input_bytes"] = len(replay_input)  # type: ignore[index]

    valid: dict[str, dict[str, object]] = {}
    for label, spec, record, id_key, digest_key, invalid_reason in (
        ("reference", reference, reference_record, "reference_id", "source_sha256", "independent_reference_result_invalid"),
        ("candidate", candidate, candidate_record, "operator_id", "release_sha256", "candidate_result_invalid"),
    ):
        raw, elapsed, error = _run_evaluator(spec.evaluate, replay_input, label=label)
        report["resources"][f"{label}_elapsed_ns"] = elapsed  # type: ignore[index]
        if error is not None:
            report["member_audit"][label] = {"status": "EVALUATOR_FAILED", "reason": error}  # type: ignore[index]
            return _unknown(report, [error], [error])
        checked, errors = _validate_output(
            raw,
            facts=facts,
            input_sha256=input_sha256,
            producer={
                "kind": label.upper(),
                "id": record[id_key],
                "version": record["version"],
                "tool_version": record["tool_version"],
                "artifact_sha256": record[digest_key],
            },
            label=label,
        )
        report["member_audit"][label] = _member_audit(raw, facts)  # type: ignore[index]
        report[f"{label}_received_member_count"] = report["member_audit"][label]["received_member_count"]  # type: ignore[index]
        if checked is None:
            return _unknown(report, [invalid_reason], errors)
        report["resources"][f"{label}_output_bytes"] = len(_canonical_json(checked, maximum=MAX_RESULT_BYTES))  # type: ignore[index]
        valid[label] = checked
    reference_valid, candidate_valid = valid["reference"], valid["candidate"]

    expected_by_path = {policy["path"]: policy for policy in expected_policies}
    forbidden_by_path = {policy["path"]: policy for policy in forbidden_policies}
    reference_values = _comparable_values(reference_valid, facts)
    candidate_values = _comparable_values(candidate_valid, facts)
    differences: list[dict[str, object]] = []
    unknowns: list[dict[str, str]] = []
    matched = 0
    used_rules: set[str] = set()
    for path in sorted(set(reference_values) | set(candidate_values)):
        if path not in reference_values or path not in candidate_values:
            unknowns.append({"class": "UNKNOWN", "path": path, "reason": "comparison_value_missing"})
            continue
        expected_value = reference_values[path]
        candidate_value = candidate_values[path]
        if type(expected_value) is type(candidate_value) and expected_value == candidate_value:
            matched += 1
            continue
        rule = expected_by_path.get(path) or forbidden_by_path.get(path)
        if rule is not None:
            used_rules.add(path)
        differences.append({
            "path": path,
            "classification": "UNEXPLAINED" if rule is None else str(rule["classification"]),
            "reference_value": expected_value,
            "candidate_value": candidate_value,
            "rationale": None if rule is None else rule["rationale"],
            "approval_ref": None if rule is None else rule["approval_ref"],
        })
    all_rules = expected_policies + forbidden_policies
    report["unused_difference_rules"] = [
        {"path": policy["path"], "classification": policy["classification"], "reason": "no_difference_at_path"}
        for policy in all_rules
        if policy["path"] not in used_rules
    ]
    report["differences"] = differences
    report["unknowns"] = unknowns
    report["matched_field_count"] = matched
    report["reference_result_sha256"] = hashlib.sha256(_canonical_json(reference_valid, maximum=MAX_RESULT_BYTES)).hexdigest().upper()
    report["candidate_result_sha256"] = hashlib.sha256(_canonical_json(candidate_valid, maximum=MAX_RESULT_BYTES)).hexdigest().upper()
    report["run_id"] = hashlib.sha256(
        bytes.fromhex(input_sha256)
        + bytes.fromhex(report["reference_result_sha256"])
        + bytes.fromhex(report["candidate_result_sha256"])
    ).hexdigest().upper()
    classes = {item["classification"] for item in differences}
    report["status"], report["comparison_status"] = (
        ("INCOMPLETE", "INCOMPLETE") if unknowns
        else ("BLOCKED", "FORBIDDEN_DIFFERENCES") if "FORBIDDEN" in classes
        else ("BLOCKED", "UNEXPLAINED_DIFFERENCES") if "UNEXPLAINED" in classes
        else ("COMPARISON_ONLY", "EXPECTED_DIFFERENCES_ONLY") if differences
        else ("COMPARISON_ONLY", "MATCHED")
    )
    report["reasons"] = []
    return report
