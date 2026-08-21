"""Independent verifier for the nonactivating Mirror qualification artifact.

This module is intentionally independent of the producer, custody facade, and
ContinuityStore.  It owns the bounded manifest grammar, fixed dependency and
component registry, synthetic evidence bindings, custody-envelope check, and
rehearsal lifecycle transition rules, and the unavailable external-port
registry.  It never upgrades a fixture result into source authentication,
state approval, production custody, HA, a controlled shadow, or activation.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping


ARTIFACT_KIND = "MIRROR_QUALIFICATION_V2"
SCHEMA = "mirror-qualification-manifest-v2"
SCHEMA_VERSION = 2
DOMAIN = "BL/MIRROR/QUALIFICATION/"
PROFILE_ID = "mirror.qualification.synthetic-rehearsal.v2"
PROFILE_VERSION = 2
SUBJECT = "SYNTH_MIRROR_QUALIFICATION_REHEARSAL_SCOPE_V2"
SCOPE = "MIRROR_QUALIFICATION_REHEARSAL_V2"
CUSTODY_PURPOSE = "MIRROR_SYNTHETIC_REHEARSAL_MANIFEST_V2"
MAX_ARTIFACT_BYTES = 524_288
MAX_STRING_BYTES = 8_192
MAX_NODES = 16_384
MAX_DEPTH = 24
HEX128 = re.compile(r"^[0-9a-f]{128}$")

READINESS_NOT_READY = "NOT_READY"
SYNTHETIC_REHEARSAL_READY = "SYNTHETIC_REHEARSAL_READY"
CONTROLLED_SHADOW_READY = "CONTROLLED_SHADOW_READY"
PRODUCTION_READY = "PRODUCTION_READY"
READINESS_LEVELS = (
    READINESS_NOT_READY,
    SYNTHETIC_REHEARSAL_READY,
    CONTROLLED_SHADOW_READY,
    PRODUCTION_READY,
)

REHEARSAL_NOT_READY = "REHEARSAL_NOT_READY"
REHEARSAL_READY = "REHEARSAL_READY"
REHEARSAL_RUNNING = "REHEARSAL_RUNNING"
REHEARSAL_PAUSED = "REHEARSAL_PAUSED"
REHEARSAL_ROLLED_BACK = "REHEARSAL_ROLLED_BACK"
REHEARSAL_COMPLETED = "REHEARSAL_COMPLETED"
REHEARSAL_STATES = (
    REHEARSAL_NOT_READY,
    REHEARSAL_READY,
    REHEARSAL_RUNNING,
    REHEARSAL_PAUSED,
    REHEARSAL_ROLLED_BACK,
    REHEARSAL_COMPLETED,
)
LEGAL_TRANSITIONS = {
    REHEARSAL_NOT_READY: {REHEARSAL_READY},
    REHEARSAL_READY: {REHEARSAL_RUNNING},
    REHEARSAL_RUNNING: {REHEARSAL_PAUSED, REHEARSAL_ROLLED_BACK, REHEARSAL_COMPLETED},
    REHEARSAL_PAUSED: {REHEARSAL_RUNNING, REHEARSAL_ROLLED_BACK, REHEARSAL_COMPLETED},
    REHEARSAL_ROLLED_BACK: set(),
    REHEARSAL_COMPLETED: set(),
}

DEPENDENCY_STATES = {"MISSING", "PRESENT_UNVERIFIED", "REHEARSAL_VERIFIED", "VERIFIED", "EXPIRED", "REVOKED"}
OPERATION_STATES = {"PRESENT_UNVERIFIED", "REHEARSAL_VERIFIED", "VERIFIED", "EXPIRED", "REVOKED"}
REHEARSAL_EVIDENCE_CLASS = "SYNTHETIC_REHEARSAL"
REHEARSAL_PAYLOAD_KIND = "FIXTURE_REHEARSAL"
REHEARSAL_VERIFIED_STATE = "REHEARSAL_VERIFIED"
DEPENDENCY_IDS = (
    "SOURCE_AUTHORIZATION",
    "LEGAL_TERMS",
    "SOURCE_SCOPE",
    "COMPLETENESS",
    "CADENCE",
    "FAILURE_BEHAVIOR",
    "STATE_APPROVAL",
    "PRIVACY",
    "SUPPORT",
    "CUSTODY",
    "HA",
    "BACKUP_DR",
    "MONITORING",
    "ROLLBACK",
)
OWNER_REGISTRY = {
    "source_authorization": "STATE_SOURCE_AUTHORITY",
    "legal_terms": "STATE_LEGAL_AUTHORITY",
    "source_scope": "STATE_SOURCE_AUTHORITY",
    "completeness": "STATE_SOURCE_AUTHORITY",
    "cadence": "STATE_SOURCE_AUTHORITY",
    "failure_behavior": "STATE_SOURCE_AUTHORITY",
    "state_approval": "STATE_GOVERNANCE_AUTHORITY",
    "privacy": "STATE_PRIVACY_AUTHORITY",
    "support": "STATE_SUPPORT_AUTHORITY",
    "custody": "STATE_CUSTODY_AUTHORITY",
    "ha": "STATE_OPERATIONS_AUTHORITY",
    "backup_dr": "STATE_OPERATIONS_AUTHORITY",
    "monitoring": "STATE_OPERATIONS_AUTHORITY",
    "rollback": "STATE_OPERATIONS_AUTHORITY",
}
DEPENDENCY_OWNERS = {
    dependency_id: OWNER_REGISTRY[owner_key]
    for dependency_id, owner_key in zip(
        DEPENDENCY_IDS,
        (
            "source_authorization", "legal_terms", "source_scope", "completeness",
            "cadence", "failure_behavior", "state_approval", "privacy", "support",
            "custody", "ha", "backup_dr", "monitoring", "rollback",
        ),
    )
}

COMPONENT_CONTRACTS = [
    {"component_id": "SOURCE_ADMISSION", "owner": "MIRROR_SOURCE_ADMISSION", "contract_version": 1, "verification_boundary": "INDEPENDENT_SOURCE_VERIFIER"},
    {"component_id": "SOURCE_CUSTODY", "owner": "MIRROR_SOURCE_CUSTODY", "contract_version": 1, "verification_boundary": "INDEPENDENT_CUSTODY_VERIFIER"},
    {"component_id": "SOURCE_RECONCILIATION", "owner": "MIRROR_SOURCE_RECONCILIATION", "contract_version": 1, "verification_boundary": "INDEPENDENT_RECONCILIATION_VERIFIER"},
    {"component_id": "PROVIDER_TRUST_GRAPH", "owner": "MIRROR_PROVIDER_TRUST_GRAPH", "contract_version": 2, "verification_boundary": "INDEPENDENT_GRAPH_VERIFIER"},
    {"component_id": "DISCREPANCY_RESPONSIBILITY_REMEDIATION", "owner": "MIRROR_CASE_LIFECYCLE", "contract_version": 1, "verification_boundary": "INDEPENDENT_CASE_VERIFIER"},
    {"component_id": "DENOMINATOR_LEDGER", "owner": "MIRROR_DENOMINATOR_LEDGER", "contract_version": 1, "verification_boundary": "INDEPENDENT_DENOMINATOR_VERIFIER"},
    {"component_id": "CONTRACT_MIRROR", "owner": "MIRROR_CONTRACT", "contract_version": 1, "verification_boundary": "INDEPENDENT_CONTRACT_VERIFIER"},
    {"component_id": "TRANSACTION_MIRROR", "owner": "MIRROR_TRANSACTION", "contract_version": 1, "verification_boundary": "INDEPENDENT_TRANSACTION_VERIFIER"},
    {"component_id": "MONEY_MIRROR", "owner": "MIRROR_MONEY", "contract_version": 1, "verification_boundary": "INDEPENDENT_MONEY_VERIFIER"},
    {"component_id": "TRANSITION_MIRROR", "owner": "MIRROR_TRANSITION", "contract_version": 1, "verification_boundary": "INDEPENDENT_TRANSITION_VERIFIER"},
    {"component_id": "STATE_VALUE_LEDGER", "owner": "MIRROR_STATE_VALUE", "contract_version": 1, "verification_boundary": "INDEPENDENT_STATE_VALUE_VERIFIER"},
    {"component_id": "CONTINUITY_STORE", "owner": "MIRROR_CONTINUITY_STORE", "contract_version": 2, "verification_boundary": "INDEPENDENT_DATABASE_VERIFIER"},
    {"component_id": "EXPORT_RESTORE_SUPPORT", "owner": "MIRROR_OPERATIONS", "contract_version": 2, "verification_boundary": "INDEPENDENT_EXPORT_SUPPORT_VERIFIER"},
    {"component_id": "MIRROR_QUALIFICATION", "owner": "MIRROR_QUALIFICATION_SERVICE", "contract_version": 2, "verification_boundary": "INDEPENDENT_QUALIFICATION_VERIFIER"},
]
OPERATION_IDS = (
    "ATOMIC_PERSISTENCE",
    "SINGLE_WRITER_CONCURRENCY",
    "BACKUP_RESTORE",
    "RESTART_RECOVERY",
    "ROLLBACK_FAULT_INJECTION",
    "INTEGRITY_CORRUPTION_REJECTION",
    "SUPPORT_SANITIZATION",
    "RESOURCE_BOUNDARY",
)

# These are verifier-owned substitution seams, not caller-selectable trust
# roots.  No production implementation is registered in this repository.
EXTERNAL_PORT_CONTRACTS = [
    {
        "port_id": "STATE_SOURCE_AUTHORIZATION_TERMS_PORT_V1",
        "authority": "STATE_SOURCE_AUTHORITY",
        "verification_method": "AUTHENTICATED_EXTERNAL_EVIDENCE_V1",
        "trust_root_id": "UNCONFIGURED",
        "implemented": False,
        "dependencies": ["SOURCE_AUTHORIZATION", "LEGAL_TERMS", "SOURCE_SCOPE", "COMPLETENESS", "CADENCE", "FAILURE_BEHAVIOR"],
    },
    {
        "port_id": "STATE_GOVERNANCE_APPROVAL_PORT_V1",
        "authority": "STATE_GOVERNANCE_AUTHORITY",
        "verification_method": "AUTHENTICATED_EXTERNAL_EVIDENCE_V1",
        "trust_root_id": "UNCONFIGURED",
        "implemented": False,
        "dependencies": ["STATE_APPROVAL"],
    },
    {
        "port_id": "STATE_PRIVACY_SUPPORT_APPROVAL_PORT_V1",
        "authority": "STATE_PRIVACY_AUTHORITY",
        "verification_method": "AUTHENTICATED_EXTERNAL_EVIDENCE_V1",
        "trust_root_id": "UNCONFIGURED",
        "implemented": False,
        "dependencies": ["PRIVACY", "SUPPORT"],
    },
    {
        "port_id": "PRODUCTION_CUSTODY_PORT_V1",
        "authority": "STATE_CUSTODY_AUTHORITY",
        "verification_method": "AUTHENTICATED_CUSTODY_EVIDENCE_V1",
        "trust_root_id": "UNCONFIGURED",
        "implemented": False,
        "dependencies": ["CUSTODY"],
    },
    {
        "port_id": "STATE_OPERATIONS_QUALIFICATION_PORT_V1",
        "authority": "STATE_OPERATIONS_AUTHORITY",
        "verification_method": "AUTHENTICATED_OPERATIONS_EVIDENCE_V1",
        "trust_root_id": "UNCONFIGURED",
        "implemented": False,
        "dependencies": ["HA", "BACKUP_DR", "MONITORING", "ROLLBACK"],
    },
]

AUTHORITY_FLAGS = {
    "automaticControlSetId": None,
    "automatic_enforcement_eligible": False,
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "production_usable": False,
    "synthetic_only": True,
    "rehearsal_only": True,
    "controlled_shadow_authority": False,
    "production_authority": False,
    "production_source_authentication": False,
    "proofSuiteId": None,
}
FIXED_FLAGS = {
    "read_only": True,
    "observation_only": True,
    "payment_movement": False,
    "settlement_authority": False,
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "state_approval": False,
    "controlled_shadow_pilot": False,
    "rehearsal_only": True,
    "automatic_decision_authority": False,
    "production_usable": False,
    "synthetic_only": True,
    "activation": False,
    "encryption_at_rest_qualified": False,
    "hsm_fips_qualified": False,
    "proofSuiteId": None,
}

GAP_LEDGER = {
    "schema": "mirror-qualification-gap-ledger-v2",
    "implemented_software_seams": [
        {"gap_id": item["component_id"], "status": "REHEARSAL_SOFTWARE_ONLY", "claim": "bounded local contract and independent checks; no external authority"}
        for item in COMPONENT_CONTRACTS
    ] + [
        {
            "gap_id": "EXTERNAL_SOURCE_QUARANTINE",
            "status": "SOFTWARE_ONLY",
            "claim": "durable state-owned quarantine and independent recovery checks only; no approval, downstream bridge, source truth, or production qualification",
        },
    ],
    "software_gaps": [
        {"gap_id": "EXTERNAL_SOURCE_EVIDENCE_ADAPTER", "status": "SOFTWARE_CONTRACT_ONLY", "claim": "bounded transport-neutral contract and independent checks only; live authorization/authentication, legal terms, completeness/cadence qualification, and operational failure evidence remain external"},
        {"gap_id": "EXTERNAL_GOVERNANCE_APPROVAL_ADAPTER", "status": "UNIMPLEMENTED", "claim": "state approval evidence"},
        {"gap_id": "EXTERNAL_PRIVACY_SUPPORT_ADAPTER", "status": "UNIMPLEMENTED", "claim": "state privacy and support approval evidence"},
        {"gap_id": "PRODUCTION_CUSTODY_ADAPTER", "status": "UNIMPLEMENTED", "claim": "production envelope custody and HSM/FIPS evidence"},
        {"gap_id": "PRODUCTION_HA_BACKUP_DR_ADAPTER", "status": "UNIMPLEMENTED", "claim": "production HA, backup, restore, DR, monitoring, and rollback evidence"},
        {"gap_id": "CONTROLLED_SHADOW_PILOT_RUNTIME", "status": "UNIMPLEMENTED", "claim": "externally authorized read-only shadow operations"},
        {"gap_id": "PRODUCTION_QUALIFICATION", "status": "UNIMPLEMENTED", "claim": "production claim level"},
    ],
    "external_blockers": [
        {"gap_id": "STATE_SOURCE_AUTHORIZATION", "status": "EXTERNAL_REQUIRED", "claim": "legal access and source authority"},
        {"gap_id": "STATE_TERMS_AND_RETENTION", "status": "EXTERNAL_REQUIRED", "claim": "terms, cadence, retention, redistribution"},
        {"gap_id": "STATE_PRIVACY_APPROVAL", "status": "EXTERNAL_REQUIRED", "claim": "production privacy and PHI review"},
        {"gap_id": "STATE_CUSTODY_HA_APPROVAL", "status": "EXTERNAL_REQUIRED", "claim": "production custody, HA, backup, DR"},
    ],
    "nonclaims": [
        "real_source_authentication",
        "legal_access",
        "record_truth",
        "completeness_or_nonmembership",
        "state_approval",
        "hsm_or_fips_qualification",
        "production_privacy",
        "production_ha_or_dr",
        "controlled_shadow_pilot",
        "payment_or_clearance_authority",
    ],
}

TOP_KEYS = {
    "schema", "schema_version", "profile_binding", "subject", "scope", "as_of",
    "owners", "components", "external_ports", "dependencies", "operations", "custody", "readiness",
    "pilot_state", "gap_ledger", "flags", "authority", "manifest_id", "prior_artifact_id",
    "prior_stage_id", "artifact_id", "current_stage_id", "transition_id",
}
PROFILE_KEYS = {"profile_id", "version", "profile_digest"}
EVIDENCE_KEYS = {"evidence_id", "dependency_id", "owner", "state", "evidence_class", "issued_at", "valid_until", "revoked", "payload_kind", "proof"}
DEPENDENCY_KEYS = {"dependency_id", "owner", "required", "state", "evidence"}
OPERATION_KEYS = {"operation_id", "owner", "required", "state", "evidence_class", "observed_rpo_seconds", "observed_rto_ms", "fault_codes", "proof"}
CUSTODY_KEYS = {"mode", "key_id", "key_epoch", "key_state", "envelope", "audit", "audit_root", "envelope_digest", "encryption_at_rest_qualified", "production_key_custody"}
ENVELOPE_KEYS = {"schema", "key_id", "key_epoch", "ciphertext", "tag", "plaintext_digest"}
AUDIT_KEYS = {"action", "key_id", "key_epoch", "status"}
READINESS_KEYS = {
    "software_contract_verified",
    "synthetic_rehearsal_evidence_verified",
    "external_evidence_authenticated_current",
    "operational_qualification_verified",
    "unresolved_blockers",
    "final_claim",
}


class IndependentQualificationError(ValueError):
    """Stable fail-closed rejection from the qualification boundary."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentQualificationError("qualification:noncanonical") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentQualificationError("qualification:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > MAX_NODES:
        raise IndependentQualificationError("qualification:node-cap")
    if depth > MAX_DEPTH:
        raise IndependentQualificationError("qualification:depth-cap")
    if isinstance(value, float):
        raise IndependentQualificationError("qualification:float")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                raise IndependentQualificationError("qualification:string-cap")
        except UnicodeEncodeError as exc:
            raise IndependentQualificationError("qualification:ascii") from exc
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentQualificationError("qualification:key-type")
            _walk(key, depth=depth + 1, count=count)
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentQualificationError("qualification:byte-cap")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys, parse_constant=lambda _value: (_ for _ in ()).throw(IndependentQualificationError("qualification:constant")))
    except IndependentQualificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentQualificationError("qualification:parse") from exc
    if not isinstance(value, dict):
        raise IndependentQualificationError("qualification:top-level")
    _walk(value)
    if set(value) != TOP_KEYS or _canonical(value) != raw:
        raise IndependentQualificationError("qualification:keys-or-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _synthetic_key(key_id: str, epoch: int) -> bytes:
    return hashlib.sha3_512((DOMAIN + "synthetic-key/v1\0" + key_id + "|" + str(epoch)).encode("ascii")).digest()


def _crypt(raw: bytes, key: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < len(raw):
        block = hashlib.sha3_512(key + counter.to_bytes(8, "big")).digest()
        output.extend(block)
        counter += 1
    return bytes(left ^ right for left, right in zip(raw, output))


def _tag(key: bytes, header: Mapping[str, object], ciphertext: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update(key)
    digest.update(_canonical(header))
    digest.update(ciphertext)
    return digest.hexdigest()


def _expect_text(value: object, label: str, *, maximum: int = MAX_STRING_BYTES) -> str:
    if not isinstance(value, str) or not value or len(value.encode("ascii")) > maximum:
        raise IndependentQualificationError(f"qualification:{label}")
    return value


def _expect_int(value: object, label: str, *, minimum: int = 0, maximum: int = 10_000_000_000) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise IndependentQualificationError(f"qualification:{label}")
    return value


def _profile_material() -> dict[str, object]:
    return {
        "profile_id": PROFILE_ID,
        "version": PROFILE_VERSION,
        "subject": SUBJECT,
        "scope": SCOPE,
        "owners": dict(OWNER_REGISTRY),
        "component_ids": [item["component_id"] for item in COMPONENT_CONTRACTS],
        "dependency_ids": list(DEPENDENCY_IDS),
        "operation_ids": list(OPERATION_IDS),
        "rehearsal_states": list(REHEARSAL_STATES),
        "readiness_levels": list(READINESS_LEVELS),
        "external_port_contracts": EXTERNAL_PORT_CONTRACTS,
        "semantics": "SYNTHETIC_REHEARSAL_ONLY_EXTERNAL_AUTHORITY_UNIMPLEMENTED",
    }


PROFILE_DIGEST = _digest("profile", _profile_material())


def _evidence_material(value: Mapping[str, object]) -> dict[str, object]:
    return {key: value[key] for key in ("dependency_id", "owner", "state", "evidence_class", "issued_at", "valid_until", "revoked", "payload_kind")}


def _operation_material(value: Mapping[str, object]) -> dict[str, object]:
    return {key: value[key] for key in ("operation_id", "owner", "required", "state", "evidence_class", "observed_rpo_seconds", "observed_rto_ms", "fault_codes")}


def _core_without_custody(value: Mapping[str, object]) -> dict[str, object]:
    return {key: value[key] for key in value if key not in {"custody", "manifest_id", "artifact_id", "current_stage_id", "transition_id"}}


def _validate_external_ports(value: object) -> list[dict[str, object]]:
    if value != EXTERNAL_PORT_CONTRACTS:
        raise IndependentQualificationError("qualification:external-port-registry")
    return value


def _validate_evidence(value: object, dependency_id: str, owner: str) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != EVIDENCE_KEYS:
        raise IndependentQualificationError("qualification:evidence-keys")
    if value["dependency_id"] != dependency_id or value["owner"] != owner:
        raise IndependentQualificationError("qualification:evidence-binding")
    state = value["state"]
    if state not in DEPENDENCY_STATES:
        raise IndependentQualificationError("qualification:evidence-state")
    if value["evidence_class"] != REHEARSAL_EVIDENCE_CLASS or value["payload_kind"] != REHEARSAL_PAYLOAD_KIND:
        raise IndependentQualificationError("qualification:evidence-class")
    if state == "VERIFIED":
        # No external verifier/trust root is registered.  A fixture proof may
        # establish rehearsal evidence only and cannot be relabelled as
        # authenticated external evidence.
        raise IndependentQualificationError("qualification:external-evidence-unavailable")
    issued = _expect_int(value["issued_at"], "evidence-issued")
    valid_until = _expect_int(value["valid_until"], "evidence-expiry", minimum=issued + 1)
    if type(value["revoked"]) is not bool:
        raise IndependentQualificationError("qualification:evidence-revoked")
    if value["revoked"] is True and state != "REVOKED":
        raise IndependentQualificationError("qualification:evidence-revocation-binding")
    if value["revoked"] is False and state == "REVOKED":
        raise IndependentQualificationError("qualification:evidence-revocation-binding")
    proof = _expect_text(value["proof"], "evidence-proof")
    if not HEX128.fullmatch(proof) or proof != _digest("evidence-proof", _evidence_material(value)):
        raise IndependentQualificationError("qualification:evidence-proof")
    evidence_id = _expect_text(value["evidence_id"], "evidence-id")
    if not HEX128.fullmatch(evidence_id) or evidence_id != _digest("evidence-id", _evidence_material(value)):
        raise IndependentQualificationError("qualification:evidence-id")
    _expect_text(value["dependency_id"], "evidence-dependency")
    return value


def _validate_dependencies(value: object, as_of: int) -> tuple[list[dict[str, object]], int]:
    if not isinstance(value, list) or len(value) != len(DEPENDENCY_IDS):
        raise IndependentQualificationError("qualification:dependency-count")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != DEPENDENCY_KEYS:
            raise IndependentQualificationError("qualification:dependency-keys")
        dependency_id = _expect_text(item["dependency_id"], "dependency-id")
        if dependency_id not in DEPENDENCY_OWNERS or dependency_id in seen:
            raise IndependentQualificationError("qualification:dependency-order")
        seen.add(dependency_id)
        owner = _expect_text(item["owner"], "dependency-owner")
        if owner != DEPENDENCY_OWNERS[dependency_id] or item["required"] is not True:
            raise IndependentQualificationError("qualification:dependency-owner")
        state = item["state"]
        if state not in DEPENDENCY_STATES:
            raise IndependentQualificationError("qualification:dependency-state")
        evidence = _validate_evidence(item["evidence"], dependency_id, owner)
        if state == "MISSING" and evidence is not None:
            raise IndependentQualificationError("qualification:missing-evidence")
        if state == "PRESENT_UNVERIFIED" and evidence is None:
            raise IndependentQualificationError("qualification:evidence-required")
        if state in {"VERIFIED", "REHEARSAL_VERIFIED", "EXPIRED", "REVOKED"} and evidence is None:
            raise IndependentQualificationError("qualification:evidence-required")
        if evidence is not None and evidence["state"] != state:
            raise IndependentQualificationError("qualification:evidence-state-binding")
        if state == REHEARSAL_VERIFIED_STATE and evidence is not None and (as_of < evidence["issued_at"] or as_of >= evidence["valid_until"] or evidence["revoked"]):
            raise IndependentQualificationError("qualification:rehearsal-not-current")
        result.append(item)
    if [item["dependency_id"] for item in result] != sorted(DEPENDENCY_IDS):
        raise IndependentQualificationError("qualification:dependency-order")
    return result, sum(1 for item in result if item["state"] == REHEARSAL_VERIFIED_STATE)


def _validate_operations(value: object) -> tuple[list[dict[str, object]], int]:
    if not isinstance(value, list) or len(value) != len(OPERATION_IDS):
        raise IndependentQualificationError("qualification:operation-count")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != OPERATION_KEYS:
            raise IndependentQualificationError("qualification:operation-keys")
        operation_id = _expect_text(item["operation_id"], "operation-id")
        if operation_id not in OPERATION_IDS or operation_id in seen:
            raise IndependentQualificationError("qualification:operation-order")
        seen.add(operation_id)
        if item["owner"] != "STATE_OPERATIONS_AUTHORITY" or item["required"] is not True:
            raise IndependentQualificationError("qualification:operation-owner")
        state = item["state"]
        if state not in OPERATION_STATES:
            raise IndependentQualificationError("qualification:operation-state")
        if state == "VERIFIED":
            raise IndependentQualificationError("qualification:external-operations-unavailable")
        for key in ("observed_rpo_seconds", "observed_rto_ms"):
            if item[key] is not None:
                _expect_int(item[key], f"operation:{key}", maximum=86_400_000)
        fault_codes = item["fault_codes"]
        if not isinstance(fault_codes, list) or any(not isinstance(code, str) for code in fault_codes) or fault_codes != sorted(set(fault_codes)) or len(fault_codes) > 16:
            raise IndependentQualificationError("qualification:operation-fault-codes")
        if item["evidence_class"] != REHEARSAL_EVIDENCE_CLASS:
            raise IndependentQualificationError("qualification:operation-evidence-class")
        proof = item["proof"]
        if state == "PRESENT_UNVERIFIED":
            if proof is not None:
                raise IndependentQualificationError("qualification:operation-unverified-proof")
        else:
            if not isinstance(proof, str) or not HEX128.fullmatch(proof) or proof != _digest("operation-proof", _operation_material(item)):
                raise IndependentQualificationError("qualification:operation-proof")
        result.append(item)
    if [item["operation_id"] for item in result] != sorted(OPERATION_IDS):
        raise IndependentQualificationError("qualification:operation-order")
    return result, sum(1 for item in result if item["state"] == REHEARSAL_VERIFIED_STATE)


def _validate_custody(value: object, core: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != CUSTODY_KEYS:
        raise IndependentQualificationError("qualification:custody-keys")
    if value["mode"] != "SYNTHETIC_DETERMINISTIC_ENVELOPE" or value["encryption_at_rest_qualified"] is not False or value["production_key_custody"] is not False:
        raise IndependentQualificationError("qualification:custody-policy")
    key_id = _expect_text(value["key_id"], "custody-key-id")
    if not re.fullmatch(r"SYNTHETIC_QUALIFICATION_KEY_V[0-9]+", key_id):
        raise IndependentQualificationError("qualification:custody-key-id")
    epoch = _expect_int(value["key_epoch"], "custody-key-epoch", minimum=1, maximum=1024)
    key_state = value["key_state"]
    if key_state not in {"ACTIVE", "REVOKED"}:
        raise IndependentQualificationError("qualification:custody-key-state")
    envelope = value["envelope"]
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_KEYS:
        raise IndependentQualificationError("qualification:envelope-keys")
    if envelope["schema"] != "synthetic-envelope-encryption-v1" or envelope["key_id"] != key_id or envelope["key_epoch"] != epoch:
        raise IndependentQualificationError("qualification:envelope-binding")
    ciphertext_hex = envelope["ciphertext"]
    if not isinstance(ciphertext_hex, str) or len(ciphertext_hex) % 2 or ciphertext_hex.lower() != ciphertext_hex:
        raise IndependentQualificationError("qualification:envelope-ciphertext")
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError as exc:
        raise IndependentQualificationError("qualification:envelope-ciphertext") from exc
    if len(ciphertext) > 32_768:
        raise IndependentQualificationError("qualification:envelope-byte-cap")
    key = _synthetic_key(key_id, epoch)
    header = {"schema": envelope["schema"], "key_id": key_id, "key_epoch": epoch}
    tag = _expect_text(envelope["tag"], "envelope-tag")
    if not HEX128.fullmatch(tag) or tag != _tag(key, header, ciphertext):
        raise IndependentQualificationError("qualification:envelope-tag")
    plaintext = _crypt(ciphertext, key)
    plaintext_digest = _expect_text(envelope["plaintext_digest"], "envelope-plaintext-digest")
    if not HEX128.fullmatch(plaintext_digest) or plaintext_digest != _raw_digest("envelope-plaintext", plaintext):
        raise IndependentQualificationError("qualification:envelope-plaintext")
    try:
        seed = json.loads(plaintext.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentQualificationError("qualification:envelope-seed") from exc
    if _canonical(seed) != plaintext:
        raise IndependentQualificationError("qualification:envelope-seed")
    if not isinstance(seed, dict) or set(seed) != {"profile_id", "manifest_core_digest", "purpose"} or seed["profile_id"] != PROFILE_ID or seed["purpose"] != CUSTODY_PURPOSE:
        raise IndependentQualificationError("qualification:envelope-seed")
    if seed["manifest_core_digest"] != _digest("manifest-core", dict(core)):
        raise IndependentQualificationError("qualification:envelope-core-binding")
    audit = value["audit"]
    if not isinstance(audit, list) or not audit or len(audit) > 16 or any(not isinstance(item, dict) or set(item) != AUDIT_KEYS for item in audit):
        raise IndependentQualificationError("qualification:custody-audit")
    for item in audit:
        if item["key_id"] != key_id or item["key_epoch"] != epoch or item["status"] != "OBSERVED" or item["action"] not in {"SEAL", "ROTATE", "REVOKE"}:
            raise IndependentQualificationError("qualification:custody-audit")
    audit_root = _expect_text(value["audit_root"], "custody-audit-root")
    if not HEX128.fullmatch(audit_root) or audit_root != _digest("custody-audit", audit):
        raise IndependentQualificationError("qualification:custody-audit-root")
    envelope_digest = _expect_text(value["envelope_digest"], "custody-envelope-digest")
    if not HEX128.fullmatch(envelope_digest) or envelope_digest != _digest("custody-envelope", envelope):
        raise IndependentQualificationError("qualification:custody-envelope-digest")
    return value


def _identity_body(value: Mapping[str, object]) -> dict[str, object]:
    return {key: value[key] for key in value if key not in {"artifact_id", "current_stage_id", "transition_id"}}


def _validate_value(
    value: Mapping[str, object],
    *,
    prior_value: Mapping[str, object] | None = None,
    check_prior: bool = True,
) -> dict[str, object]:
    profile = value["profile_binding"]
    if not isinstance(profile, dict) or set(profile) != PROFILE_KEYS or profile != {"profile_id": PROFILE_ID, "version": PROFILE_VERSION, "profile_digest": PROFILE_DIGEST}:
        raise IndependentQualificationError("qualification:profile")
    if value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION or value["subject"] != SUBJECT or value["scope"] != SCOPE:
        raise IndependentQualificationError("qualification:profile-binding")
    as_of = _expect_int(value["as_of"], "as-of")
    if value["owners"] != OWNER_REGISTRY or value["components"] != COMPONENT_CONTRACTS or value["gap_ledger"] != GAP_LEDGER:
        raise IndependentQualificationError("qualification:fixed-registry")
    _validate_external_ports(value["external_ports"])
    dependencies, rehearsal_dependencies = _validate_dependencies(value["dependencies"], as_of)
    operations, rehearsal_operations = _validate_operations(value["operations"])
    core = _core_without_custody(value)
    _validate_custody(value["custody"], core)
    readiness = value["readiness"]
    if not isinstance(readiness, dict) or set(readiness) != READINESS_KEYS:
        raise IndependentQualificationError("qualification:readiness-keys")
    software_contract_verified = True
    synthetic_rehearsal_verified = (
        rehearsal_dependencies == len(DEPENDENCY_IDS)
        and rehearsal_operations == len(OPERATION_IDS)
    )
    # This profile has no external adapters or trust roots.  These values are
    # verifier-owned constants, never evidence fields supplied by a caller.
    external_evidence_authenticated_current = False
    operational_qualification_verified = False
    blockers = [
        "EXTERNAL_AUTHENTICATED_EVIDENCE_UNAVAILABLE",
        "PRODUCTION_CUSTODY_UNQUALIFIED",
        "PRODUCTION_OPERATIONS_UNQUALIFIED",
        "CONTROLLED_SHADOW_NOT_AUTHORIZED",
        "PRODUCTION_QUALIFICATION_UNIMPLEMENTED",
    ]
    if not synthetic_rehearsal_verified:
        blockers.insert(0, "SYNTHETIC_REHEARSAL_EVIDENCE_INCOMPLETE")
    expected_state = SYNTHETIC_REHEARSAL_READY if software_contract_verified and synthetic_rehearsal_verified else READINESS_NOT_READY
    expected_readiness = {
        "software_contract_verified": software_contract_verified,
        "synthetic_rehearsal_evidence_verified": synthetic_rehearsal_verified,
        "external_evidence_authenticated_current": external_evidence_authenticated_current,
        "operational_qualification_verified": operational_qualification_verified,
        "unresolved_blockers": blockers,
        "final_claim": expected_state,
    }
    if readiness != expected_readiness:
        raise IndependentQualificationError("qualification:readiness")
    pilot_state = value["pilot_state"]
    if pilot_state not in REHEARSAL_STATES:
        raise IndependentQualificationError("qualification:pilot-state")
    flags = value["flags"]
    if flags != FIXED_FLAGS or value["authority"] != AUTHORITY_FLAGS:
        raise IndependentQualificationError("qualification:authority-flags")
    prior_id = value["prior_artifact_id"]
    prior_stage = value["prior_stage_id"]
    if check_prior:
        if prior_value is None:
            if prior_id is not None or prior_stage is not None or pilot_state != REHEARSAL_NOT_READY:
                raise IndependentQualificationError("qualification:initial-state")
        else:
            if prior_id != prior_value["artifact_id"] or prior_stage != prior_value["current_stage_id"]:
                raise IndependentQualificationError("qualification:prior-binding")
            prior_state = prior_value["pilot_state"]
            if pilot_state not in LEGAL_TRANSITIONS[prior_state]:
                raise IndependentQualificationError("qualification:illegal-transition")
            if pilot_state in {REHEARSAL_READY, REHEARSAL_RUNNING, REHEARSAL_COMPLETED} and not synthetic_rehearsal_verified:
                raise IndependentQualificationError("qualification:readiness-required")
    manifest_id = _expect_text(value["manifest_id"], "manifest-id")
    if not HEX128.fullmatch(manifest_id) or manifest_id != _digest("manifest-id", core):
        raise IndependentQualificationError("qualification:manifest-id")
    artifact_id = _expect_text(value["artifact_id"], "artifact-id")
    if not HEX128.fullmatch(artifact_id) or artifact_id != _digest("artifact-id", _identity_body(value)):
        raise IndependentQualificationError("qualification:artifact-id")
    current_stage_id = _expect_text(value["current_stage_id"], "stage-id")
    if not HEX128.fullmatch(current_stage_id) or current_stage_id != _digest("stage-id", {"manifest_id": manifest_id, "pilot_state": pilot_state, "readiness": expected_state, "prior_artifact_id": prior_id, "prior_stage_id": prior_stage}):
        raise IndependentQualificationError("qualification:stage-id")
    transition_id = _expect_text(value["transition_id"], "transition-id")
    if not HEX128.fullmatch(transition_id) or transition_id != _digest("transition-id", {"artifact_id": artifact_id, "prior_artifact_id": prior_id, "prior_stage_id": prior_stage, "current_stage_id": current_stage_id}):
        raise IndependentQualificationError("qualification:transition-id")
    return {
        "accepted": True,
        "schema": SCHEMA,
        "artifact_id": artifact_id,
        "manifest_id": manifest_id,
        "current_stage_id": current_stage_id,
        "transition_id": transition_id,
        "stage_kind": pilot_state,
        "prior_artifact_id": prior_id,
        "prior_stage_id": prior_stage,
        "subject": SUBJECT,
        "scope": SCOPE,
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "readiness_state": expected_state,
        "claim_level": expected_state,
        "external_evidence_authenticated_current": external_evidence_authenticated_current,
        "dependency_states": {item["dependency_id"]: item["state"] for item in dependencies},
    }


def verify_artifact(raw: bytes, *, prior_raw: bytes | None = None) -> dict[str, object]:
    value = _parse(raw)
    prior_value = None
    if prior_raw is not None:
        prior_value = _parse(prior_raw)
        _validate_value(prior_value, check_prior=False)
    return _validate_value(value, prior_value=prior_value)


def inspect_artifact(raw: bytes) -> dict[str, object]:
    """Normalize one candidate without deciding its predecessor transition.

    ContinuityStore uses this only before BEGIN IMMEDIATE.  It validates the
    complete manifest grammar, identities, custody envelope, and fixed flags;
    the store then reloads the predecessor and calls ``verify_artifact`` under
    its transaction owner to enforce lifecycle legality and head binding.
    """

    value = _parse(raw)
    return _validate_value(value, check_prior=False)


def verify_bytes(raw: bytes, *, prior_raw: bytes | None = None) -> dict[str, object]:
    return verify_artifact(raw, prior_raw=prior_raw)


__all__ = [
    "ARTIFACT_KIND", "SCHEMA", "SCHEMA_VERSION", "PROFILE_ID", "PROFILE_VERSION", "SUBJECT", "SCOPE", "CUSTODY_PURPOSE",
    "READINESS_NOT_READY", "SYNTHETIC_REHEARSAL_READY", "CONTROLLED_SHADOW_READY", "PRODUCTION_READY", "READINESS_LEVELS",
    "REHEARSAL_NOT_READY", "REHEARSAL_READY", "REHEARSAL_RUNNING", "REHEARSAL_PAUSED", "REHEARSAL_ROLLED_BACK", "REHEARSAL_COMPLETED",
    "REHEARSAL_STATES", "DEPENDENCY_IDS", "DEPENDENCY_STATES", "OPERATION_STATES", "OWNER_REGISTRY", "COMPONENT_CONTRACTS",
    "OPERATION_IDS", "EXTERNAL_PORT_CONTRACTS", "AUTHORITY_FLAGS", "FIXED_FLAGS", "GAP_LEDGER", "PROFILE_DIGEST",
    "IndependentQualificationError", "verify_artifact", "verify_bytes",
    "inspect_artifact",
]
