"""Producer-side synthetic Mirror Qualification V1 composition boundary.

The qualification manifest is a bounded readiness record for the existing
Mirror seams.  It records synthetic evidence and explicit nonclaims; it does
not authenticate a live source, grant state approval, or activate a pilot.
The independent grammar and identity owner is
``qualification_independent``.  This module only assembles candidates and
delegates final lifecycle authority to ContinuityStore.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import time
from typing import Mapping, Protocol, Sequence

from app.mirror import qualification_independent as independent


class QualificationError(ValueError):
    """Candidate construction or qualification-port failure."""


class EnvelopeCustodyPort(Protocol):
    """Narrow state-owned custody seam used by the synthetic candidate."""

    def seal(self, seed: Mapping[str, object]) -> dict[str, object]: ...

    def rotate(self) -> dict[str, object]: ...

    def revoke(self) -> dict[str, object]: ...

    def open(self, envelope: Mapping[str, object]) -> bytes: ...


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise QualificationError("qualification:noncanonical") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((independent.DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update((independent.DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _synthetic_key(key_id: str, epoch: int) -> bytes:
    return hashlib.sha3_512((independent.DOMAIN + "synthetic-key/v1\0" + key_id + "|" + str(epoch)).encode("ascii")).digest()


def _crypt(raw: bytes, key: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < len(raw):
        output.extend(hashlib.sha3_512(key + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(left ^ right for left, right in zip(raw, output))


def _tag(key: bytes, header: Mapping[str, object], ciphertext: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update(key)
    digest.update(_canonical(header))
    digest.update(ciphertext)
    return digest.hexdigest()


def _restate_evidence(evidence: Mapping[str, object], state: str, revoked: bool) -> dict[str, object]:
    material = {
        "dependency_id": evidence["dependency_id"],
        "owner": evidence["owner"],
        "state": state,
        "evidence_class": evidence["evidence_class"],
        "issued_at": evidence["issued_at"],
        "valid_until": evidence["valid_until"],
        "revoked": revoked,
        "payload_kind": evidence["payload_kind"],
    }
    return {
        **material,
        "proof": _digest("evidence-proof", material),
        "evidence_id": _digest("evidence-id", material),
    }


class SyntheticEvidenceAuthority:
    """Deterministic fixture-only issuer; not a real state authority."""

    @staticmethod
    def issue(
        dependency_id: str,
        *,
        state: str = "VERIFIED",
        issued_at: int = 1_000,
        valid_until: int = 9_000,
        revoked: bool = False,
    ) -> dict[str, object]:
        if dependency_id not in independent.DEPENDENCY_IDS:
            raise QualificationError("qualification:dependency")
        if state not in independent.DEPENDENCY_STATES or state == "MISSING":
            raise QualificationError("qualification:evidence-state")
        if type(issued_at) is not int or type(valid_until) is not int or valid_until <= issued_at:
            raise QualificationError("qualification:evidence-time")
        if type(revoked) is not bool or (revoked and state != "REVOKED") or (state == "REVOKED" and not revoked):
            raise QualificationError("qualification:evidence-revocation")
        owner = independent.DEPENDENCY_OWNERS[dependency_id]
        material = {
            "dependency_id": dependency_id,
            "owner": owner,
            "state": state,
            "evidence_class": "SYNTHETIC",
            "issued_at": issued_at,
            "valid_until": valid_until,
            "revoked": revoked,
            "payload_kind": "FIXTURE_ATTESTATION",
        }
        return {
            **material,
            "proof": _digest("evidence-proof", material),
            "evidence_id": _digest("evidence-id", material),
        }


class SyntheticOperationsEvidence:
    """Deterministic local observations for the operational harness."""

    @staticmethod
    def issue(
        operation_id: str,
        *,
        state: str = "VERIFIED",
        observed_rpo_seconds: int | None = 0,
        observed_rto_ms: int | None = 1,
        fault_codes: Sequence[str] = (),
    ) -> dict[str, object]:
        if operation_id not in independent.OPERATION_IDS:
            raise QualificationError("qualification:operation")
        if state not in {"PRESENT_UNVERIFIED", "VERIFIED", "EXPIRED", "REVOKED"}:
            raise QualificationError("qualification:operation-state")
        codes = sorted(set(fault_codes))
        if any(type(code) is not str for code in codes):
            raise QualificationError("qualification:fault-code")
        material = {
            "operation_id": operation_id,
            "owner": "STATE_OPERATIONS_AUTHORITY",
            "required": True,
            "state": state,
            "evidence_class": "SYNTHETIC",
            "observed_rpo_seconds": observed_rpo_seconds,
            "observed_rto_ms": observed_rto_ms,
            "fault_codes": codes,
        }
        return {**material, "proof": None if state == "PRESENT_UNVERIFIED" else _digest("operation-proof", material)}


class SyntheticEnvelopeCustody:
    """Deterministic test custody, explicitly not encryption-at-rest qualification."""

    def __init__(self, *, key_id: str = "SYNTHETIC_QUALIFICATION_KEY_V1", epoch: int = 1) -> None:
        if not key_id.startswith("SYNTHETIC_QUALIFICATION_KEY_V") or epoch < 1:
            raise QualificationError("qualification:custody-key")
        self.key_id = key_id
        self.epoch = epoch
        self.key_state = "ACTIVE"
        self._audit: list[dict[str, object]] = []

    def _audit_entry(self, action: str) -> dict[str, object]:
        return {"action": action, "key_id": self.key_id, "key_epoch": self.epoch, "status": "OBSERVED"}

    def rotate(self) -> dict[str, object]:
        version = int(self.key_id.rsplit("V", 1)[1]) + 1
        self.key_id = f"SYNTHETIC_QUALIFICATION_KEY_V{version}"
        self.epoch += 1
        self.key_state = "ACTIVE"
        self._audit = [self._audit_entry("ROTATE")]
        return {"key_id": self.key_id, "key_epoch": self.epoch, "key_state": self.key_state}

    def revoke(self) -> dict[str, object]:
        self.key_state = "REVOKED"
        self._audit = [self._audit_entry("REVOKE")]
        return {"key_id": self.key_id, "key_epoch": self.epoch, "key_state": self.key_state}

    def seal(self, seed: Mapping[str, object]) -> dict[str, object]:
        if self.key_state != "ACTIVE":
            raise QualificationError("qualification:custody-key-revoked")
        plaintext = _canonical(dict(seed))
        if len(plaintext) > 32_768:
            raise QualificationError("qualification:custody-byte-cap")
        key = _synthetic_key(self.key_id, self.epoch)
        header = {"schema": "synthetic-envelope-encryption-v1", "key_id": self.key_id, "key_epoch": self.epoch}
        ciphertext = _crypt(plaintext, key)
        envelope = {
            **header,
            "ciphertext": ciphertext.hex(),
            "tag": _tag(key, header, ciphertext),
            "plaintext_digest": _raw_digest("envelope-plaintext", plaintext),
        }
        prior = [item for item in self._audit if item["action"] != "SEAL"]
        self._audit = [*prior, self._audit_entry("SEAL")]
        return {
            "mode": "SYNTHETIC_DETERMINISTIC_ENVELOPE",
            "key_id": self.key_id,
            "key_epoch": self.epoch,
            "key_state": self.key_state,
            "envelope": envelope,
            "audit": deepcopy(self._audit),
            "audit_root": _digest("custody-audit", self._audit),
            "envelope_digest": _digest("custody-envelope", envelope),
            "encryption_at_rest_qualified": False,
            "production_key_custody": False,
        }

    def open(self, envelope: Mapping[str, object]) -> bytes:
        if not isinstance(envelope, Mapping):
            raise QualificationError("qualification:custody-envelope")
        key_id = envelope.get("key_id")
        epoch = envelope.get("key_epoch")
        body = envelope.get("envelope")
        if not isinstance(key_id, str) or type(epoch) is not int or not isinstance(body, Mapping):
            raise QualificationError("qualification:custody-envelope")
        if body.get("key_id") != key_id or body.get("key_epoch") != epoch:
            raise QualificationError("qualification:custody-binding")
        try:
            ciphertext = bytes.fromhex(str(body["ciphertext"]))
        except (KeyError, ValueError) as exc:
            raise QualificationError("qualification:custody-ciphertext") from exc
        key = _synthetic_key(key_id, epoch)
        header = {"schema": body["schema"], "key_id": key_id, "key_epoch": epoch}
        if body.get("tag") != _tag(key, header, ciphertext):
            raise QualificationError("qualification:custody-tag")
        plaintext = _crypt(ciphertext, key)
        if body.get("plaintext_digest") != _raw_digest("envelope-plaintext", plaintext):
            raise QualificationError("qualification:custody-digest")
        return plaintext


def _dependency_rows(evidence: Mapping[str, Mapping[str, object]] | None, as_of: int) -> list[dict[str, object]]:
    supplied = evidence or {}
    if any(key not in independent.DEPENDENCY_IDS for key in supplied):
        raise QualificationError("qualification:dependency-set")
    rows: list[dict[str, object]] = []
    for dependency_id in sorted(independent.DEPENDENCY_IDS):
        item = supplied.get(dependency_id)
        if item is None:
            state = "MISSING"
            evidence_value = None
        else:
            if not isinstance(item, Mapping):
                raise QualificationError("qualification:evidence-shape")
            state = str(item["state"])
            revoked = bool(item["revoked"])
            if revoked:
                state = "REVOKED"
            elif state == "VERIFIED" and as_of >= int(item["valid_until"]):
                state = "EXPIRED"
            evidence_value = dict(item) if state == item["state"] else _restate_evidence(item, state, False)
        rows.append({
            "dependency_id": dependency_id,
            "owner": independent.DEPENDENCY_OWNERS[dependency_id],
            "required": True,
            "state": state,
            "evidence": evidence_value,
        })
    return rows


def _operation_rows(operations: Mapping[str, Mapping[str, object]] | None) -> list[dict[str, object]]:
    supplied = operations or {}
    if any(key not in independent.OPERATION_IDS for key in supplied):
        raise QualificationError("qualification:operation-set")
    rows: list[dict[str, object]] = []
    for operation_id in sorted(independent.OPERATION_IDS):
        item = supplied.get(operation_id)
        rows.append(dict(item) if item is not None else SyntheticOperationsEvidence.issue(operation_id, state="PRESENT_UNVERIFIED", observed_rpo_seconds=None, observed_rto_ms=None))
    return rows


def _readiness(dependencies: Sequence[Mapping[str, object]], operations: Sequence[Mapping[str, object]]) -> dict[str, object]:
    verified = sum(1 for item in dependencies if item["state"] == "VERIFIED") + sum(1 for item in operations if item["state"] == "VERIFIED")
    required = len(independent.DEPENDENCY_IDS) + len(independent.OPERATION_IDS)
    ready = verified == required
    return {
        "state": independent.PILOT_READY if ready else independent.PILOT_NOT_READY,
        "required_checks": required,
        "verified_checks": verified,
        "current": ready,
        "claim_level": "SYNTHETIC_CANDIDATE",
    }


def build_manifest(
    *,
    evidence: Mapping[str, Mapping[str, object]] | None = None,
    operations: Mapping[str, Mapping[str, object]] | None = None,
    as_of: int = 1_000,
    custody: EnvelopeCustodyPort | None = None,
    prior_raw: bytes | None = None,
    pilot_state: str = independent.PILOT_NOT_READY,
) -> bytes:
    """Build one deterministic synthetic manifest candidate."""

    if type(as_of) is not int or as_of < 0:
        raise QualificationError("qualification:as-of")
    prior_value = independent._parse(prior_raw) if prior_raw is not None else None
    dependencies = _dependency_rows(evidence, as_of)
    operation_rows = _operation_rows(operations)
    readiness = _readiness(dependencies, operation_rows)
    prior_id = prior_value["artifact_id"] if prior_value is not None else None
    prior_stage = prior_value["current_stage_id"] if prior_value is not None else None
    core: dict[str, object] = {
        "schema": independent.SCHEMA,
        "schema_version": independent.SCHEMA_VERSION,
        "profile_binding": {"profile_id": independent.PROFILE_ID, "version": independent.PROFILE_VERSION, "profile_digest": independent.PROFILE_DIGEST},
        "subject": independent.SUBJECT,
        "scope": independent.SCOPE,
        "as_of": as_of,
        "owners": deepcopy(independent.OWNER_REGISTRY),
        "components": deepcopy(independent.COMPONENT_CONTRACTS),
        "dependencies": dependencies,
        "operations": operation_rows,
        "readiness": readiness,
        "pilot_state": pilot_state,
        "gap_ledger": deepcopy(independent.GAP_LEDGER),
        "flags": deepcopy(independent.FIXED_FLAGS),
        "authority": deepcopy(independent.AUTHORITY_FLAGS),
        "prior_artifact_id": prior_id,
        "prior_stage_id": prior_stage,
    }
    manifest_id = _digest("manifest-id", core)
    seed = {"profile_id": independent.PROFILE_ID, "manifest_core_digest": _digest("manifest-core", core), "purpose": "MIRROR_QUALIFICATION_MANIFEST"}
    custody_value = (custody or SyntheticEnvelopeCustody()).seal(seed)
    value: dict[str, object] = {**core, "custody": custody_value, "manifest_id": manifest_id}
    artifact_id = _digest("artifact-id", {key: value[key] for key in value if key not in {"artifact_id", "current_stage_id", "transition_id"}})
    stage_id = _digest("stage-id", {"manifest_id": manifest_id, "pilot_state": pilot_state, "readiness": readiness["state"], "prior_artifact_id": prior_id, "prior_stage_id": prior_stage})
    transition_id = _digest("transition-id", {"artifact_id": artifact_id, "prior_artifact_id": prior_id, "prior_stage_id": prior_stage, "current_stage_id": stage_id})
    value.update({"artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id})
    return _canonical(value)


class QualificationService:
    """Composition root for qualification admission and pilot transitions."""

    def __init__(self, store_or_path: object) -> None:
        from app.mirror import continuity_store as store

        self.store = store_or_path if isinstance(store_or_path, store.ContinuityStore) else store.ContinuityStore(str(store_or_path))
        self._key_id = "SYNTHETIC_QUALIFICATION_KEY_V1"
        self._key_epoch = 1

    def _head_raw(self) -> bytes | None:
        from app.mirror import continuity_store as store

        chain_id = store._chain_id(independent.ARTIFACT_KIND, independent.SUBJECT, independent.SCOPE, independent.PROFILE_ID)
        connection = self.store._connect()
        try:
            row = connection.execute(
                "SELECT a.payload FROM heads h JOIN artifacts a ON a.kind=h.artifact_kind AND a.artifact_id=h.artifact_id WHERE h.chain_id=?",
                (chain_id,),
            ).fetchone()
            return bytes(row[0]) if row is not None else None
        finally:
            connection.close()

    @staticmethod
    def _maps(raw: bytes) -> tuple[dict[str, dict[str, object]], dict[str, dict[str, object]]]:
        value = independent._parse(raw)
        evidence = {
            item["dependency_id"]: item["evidence"]
            for item in value["dependencies"]
            if item["evidence"] is not None
        }
        operations = {item["operation_id"]: item for item in value["operations"] if item["state"] != "PRESENT_UNVERIFIED"}
        return evidence, operations

    def _candidate(
        self,
        *,
        prior_raw: bytes | None,
        target_state: str,
        evidence: Mapping[str, Mapping[str, object]] | None,
        operations: Mapping[str, Mapping[str, object]] | None,
        as_of: int,
    ) -> bytes:
        if prior_raw is not None and evidence is None and operations is None:
            evidence, operations = self._maps(prior_raw)
        return build_manifest(
            evidence=evidence,
            operations=operations,
            as_of=as_of,
            custody=SyntheticEnvelopeCustody(key_id=self._key_id, epoch=self._key_epoch),
            prior_raw=prior_raw,
            pilot_state=target_state,
        )

    def _admit(self, raw: bytes):
        from app.mirror import continuity_store as store

        return store.run_with_busy_recovery(lambda: self.store.admit(store.ARTIFACT_QUALIFICATION, raw))

    def initialize(
        self,
        *,
        evidence: Mapping[str, Mapping[str, object]] | None = None,
        operations: Mapping[str, Mapping[str, object]] | None = None,
        as_of: int = 1_000,
    ):
        return self._admit(self._candidate(prior_raw=None, target_state=independent.PILOT_NOT_READY, evidence=evidence, operations=operations, as_of=as_of))

    def advance(
        self,
        target_state: str,
        *,
        evidence: Mapping[str, Mapping[str, object]] | None = None,
        operations: Mapping[str, Mapping[str, object]] | None = None,
        as_of: int | None = None,
    ):
        if target_state not in independent.PILOT_STATES or target_state == independent.PILOT_NOT_READY:
            raise QualificationError("qualification:target-state")
        prior_raw = self._head_raw()
        if prior_raw is None:
            raise QualificationError("qualification:head-missing")
        prior = independent._parse(prior_raw)
        effective_as_of = int(prior["as_of"]) if as_of is None else as_of
        raw = self._candidate(
            prior_raw=prior_raw,
            target_state=target_state,
            evidence=evidence,
            operations=operations,
            as_of=effective_as_of,
        )
        return self._admit(raw)

    def refresh(
        self,
        *,
        evidence: Mapping[str, Mapping[str, object]],
        as_of: int,
        target_state: str = independent.PILOT_PAUSED,
        operations: Mapping[str, Mapping[str, object]] | None = None,
    ):
        return self.advance(target_state, evidence=evidence, operations=operations, as_of=as_of)

    def current_raw(self) -> bytes | None:
        return self._head_raw()


class QualificationOperationsHarness:
    """Local persistence/backup/restart observation; never production HA/DR."""

    @staticmethod
    def observe(path: str | Path) -> dict[str, object]:
        from app.mirror import continuity_export as export
        from app.mirror import continuity_store_independent as db_independent

        started = time.monotonic()
        try:
            database = db_independent.verify_database(path)
            exported = export.export_database(path)
            export.verify_export_bytes(exported)
            with tempfile.TemporaryDirectory() as temporary:
                restored = Path(temporary) / "qualification-restore.db"
                export.import_export(exported, restored)
                db_independent.verify_database(restored)
            elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
            return {
                "schema": "mirror-qualification-operations-observation-v1",
                "synthetic_only": True,
                "production_usable": False,
                "database_integrity": "VERIFIED",
                "export_restore_integrity": "VERIFIED",
                "restart_recovery": "PRESENT_UNVERIFIED",
                "fault_injection": "SUPPORTED",
                "single_writer": "PRESENT_UNVERIFIED",
                "ha": "PRESENT_UNVERIFIED",
                "backup_dr": "PRESENT_UNVERIFIED",
                "rpo_seconds_observed": 0,
                "rto_ms_observed": elapsed_ms,
                "artifact_count": int(database["artifact_count"]),
                "event_count": int(database["event_count"]),
                "export_bytes": len(exported),
            }
        except Exception:
            return {
                "schema": "mirror-qualification-operations-observation-v1",
                "synthetic_only": True,
                "production_usable": False,
                "database_integrity": "FAILED",
                "export_restore_integrity": "FAILED",
                "restart_recovery": "UNKNOWN",
                "fault_injection": "SUPPORTED",
                "single_writer": "UNKNOWN",
                "ha": "PRESENT_UNVERIFIED",
                "backup_dr": "PRESENT_UNVERIFIED",
                "rpo_seconds_observed": None,
                "rto_ms_observed": None,
                "artifact_count": 0,
                "event_count": 0,
                "export_bytes": 0,
            }


SUPPORT_SCHEMA = "mirror-qualification-support-v1"
SUPPORT_KEYS = {
    "schema", "schema_version", "pilot_state", "readiness_state", "dependency_counts",
    "operation_counts", "custody_state", "support_safe", "zero_phi_boundary",
    "synthetic_only", "production_usable", "no_external_transmission_performed",
}


def build_support_bundle(raw: bytes) -> bytes:
    """Return aggregate-only qualification support evidence."""

    value = independent.inspect_artifact(raw)
    parsed = independent._parse(raw)
    dependency_counts = {state: 0 for state in sorted(independent.DEPENDENCY_STATES)}
    for item in parsed["dependencies"]:
        dependency_counts[item["state"]] += 1
    operation_counts = {state: 0 for state in ("PRESENT_UNVERIFIED", "VERIFIED", "EXPIRED", "REVOKED")}
    for item in parsed["operations"]:
        operation_counts[item["state"]] += 1
    support = {
        "schema": SUPPORT_SCHEMA,
        "schema_version": independent.SCHEMA_VERSION,
        "pilot_state": parsed["pilot_state"],
        "readiness_state": parsed["readiness"]["state"],
        "dependency_counts": dependency_counts,
        "operation_counts": operation_counts,
        "custody_state": {
            "key_state": parsed["custody"]["key_state"],
            "encryption_at_rest_qualified": False,
            "production_key_custody": False,
        },
        "support_safe": True,
        "zero_phi_boundary": True,
        "synthetic_only": True,
        "production_usable": False,
        "no_external_transmission_performed": True,
    }
    result = _canonical(support)
    if len(result) > 16_384:
        raise QualificationError("qualification:support-byte-cap")
    if not value["accepted"]:
        raise QualificationError("qualification:support-input")
    return result


def verify_support_bytes(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > 16_384:
        raise QualificationError("qualification:support-byte-cap")
    try:
        parsed = json.loads(raw.decode("ascii"), object_pairs_hook=lambda pairs: _reject_unique(pairs), parse_constant=lambda _: (_ for _ in ()).throw(QualificationError("qualification:support-constant")))
    except QualificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError("qualification:support-parse") from exc
    if not isinstance(parsed, dict) or set(parsed) != SUPPORT_KEYS or _canonical(parsed) != raw:
        raise QualificationError("qualification:support-keys")
    if parsed["schema"] != SUPPORT_SCHEMA or parsed["schema_version"] != independent.SCHEMA_VERSION:
        raise QualificationError("qualification:support-schema")
    if parsed["pilot_state"] not in independent.PILOT_STATES or parsed["readiness_state"] not in {independent.PILOT_NOT_READY, independent.PILOT_READY}:
        raise QualificationError("qualification:support-state")
    expected_dependencies = {state: 0 for state in sorted(independent.DEPENDENCY_STATES)}
    if parsed["dependency_counts"] != expected_dependencies and not (
        isinstance(parsed["dependency_counts"], dict)
        and set(parsed["dependency_counts"]) == set(expected_dependencies)
        and all(type(value) is int and 0 <= value <= len(independent.DEPENDENCY_IDS) for value in parsed["dependency_counts"].values())
        and sum(parsed["dependency_counts"].values()) == len(independent.DEPENDENCY_IDS)
    ):
        raise QualificationError("qualification:support-dependencies")
    if not isinstance(parsed["operation_counts"], dict) or set(parsed["operation_counts"]) != {"PRESENT_UNVERIFIED", "VERIFIED", "EXPIRED", "REVOKED"} or any(type(value) is not int or value < 0 or value > len(independent.OPERATION_IDS) for value in parsed["operation_counts"].values()) or sum(parsed["operation_counts"].values()) != len(independent.OPERATION_IDS):
        raise QualificationError("qualification:support-operations")
    custody = parsed["custody_state"]
    if custody != {"key_state": custody.get("key_state") if isinstance(custody, dict) else None, "encryption_at_rest_qualified": False, "production_key_custody": False} or custody["key_state"] not in {"ACTIVE", "REVOKED"}:
        raise QualificationError("qualification:support-custody")
    if parsed["support_safe"] is not True or parsed["zero_phi_boundary"] is not True or parsed["synthetic_only"] is not True or parsed["production_usable"] is not False or parsed["no_external_transmission_performed"] is not True:
        raise QualificationError("qualification:support-boundary")
    def reject_fingerprint(item: object) -> None:
        if isinstance(item, str) and independent.HEX128.fullmatch(item):
            raise QualificationError("qualification:support-fingerprint")
        if isinstance(item, dict):
            for nested in item.values():
                reject_fingerprint(nested)
        elif isinstance(item, list):
            for nested in item:
                reject_fingerprint(nested)
    reject_fingerprint(parsed)
    return {"accepted": True, "support_bytes": len(raw)}


def _reject_unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise QualificationError("qualification:support-duplicate-key")
        result[key] = value
    return result


__all__ = [
    "QualificationError", "EnvelopeCustodyPort", "SyntheticEvidenceAuthority", "SyntheticOperationsEvidence",
    "SyntheticEnvelopeCustody", "build_manifest", "QualificationService", "QualificationOperationsHarness",
    "build_support_bundle", "verify_support_bytes",
]
