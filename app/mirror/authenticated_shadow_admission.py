"""Durable authenticated shadow admission and local authority supervision.

The service owns only the orchestration ledger and the outbox ordering around
the already-owned acquisition, quarantine, approval, and runtime services.
Every runtime side effect is preceded by a durable pending state.  Synthetic
fixtures remain observation-only and never become controlled-shadow or
production authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Callable, Mapping

from app.mirror import authenticated_source_acquisition as acquisition
from app.mirror import authenticated_source_acquisition_independent as acquisition_independent
from app.mirror import controlled_shadow_runtime as runtime
from app.mirror import controlled_shadow_runtime_independent as runtime_independent
from app.mirror import external_governance_approval as governance
from app.mirror import external_governance_approval_independent as governance_independent
from app.mirror import external_privacy_support_approval as privacy
from app.mirror import external_privacy_support_approval_independent as privacy_independent
from app.mirror import authenticated_shadow_admission_independent as independent
from app.mirror import restore_publication
from app.mirror.error_boundary import raise_redacted


SCHEMA = independent.SCHEMA
SCHEMA_VERSION = independent.SCHEMA_VERSION
EXPORT_SCHEMA = independent.EXPORT_SCHEMA
EXPORT_VERSION = independent.EXPORT_VERSION
STATES = independent.STATES
FIXED_FLAGS = independent.FIXED_FLAGS
DDL = (
    "CREATE TABLE admission_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
    "CREATE TABLE admission_candidates(admission_id TEXT PRIMARY KEY,config_digest TEXT NOT NULL,state TEXT NOT NULL,slot_id TEXT NOT NULL,acquisition_id TEXT NOT NULL,acquisition_config_digest TEXT NOT NULL,acquisition_database_id TEXT NOT NULL,acquisition_profile_digest TEXT NOT NULL,source_policy_digest TEXT NOT NULL,scheduled_at INTEGER NOT NULL,observed_at INTEGER NOT NULL,fetched_at INTEGER NOT NULL,envelope_id TEXT NOT NULL,envelope_digest TEXT NOT NULL,capture_id TEXT NOT NULL,artifact_id TEXT NOT NULL,artifact_digest TEXT NOT NULL,quarantine_database_id TEXT NOT NULL,quarantine_policy_digest TEXT NOT NULL,quarantine_chain_id TEXT NOT NULL,quarantine_operation_id TEXT NOT NULL,quarantine_transition_id TEXT NOT NULL,quarantine_request_digest TEXT NOT NULL,quarantine_receipt_digest TEXT NOT NULL,quarantine_head_root TEXT NOT NULL,quarantine_sequence INTEGER NOT NULL,governance_policy_digest TEXT NOT NULL,governance_artifact_id TEXT NOT NULL,governance_evidence_digest TEXT NOT NULL,governance_verifier_id TEXT NOT NULL,governance_verifier_epoch INTEGER NOT NULL,privacy_policy_digest TEXT NOT NULL,privacy_artifact_id TEXT NOT NULL,privacy_evidence_digest TEXT NOT NULL,privacy_verifier_id TEXT NOT NULL,privacy_verifier_epoch INTEGER NOT NULL,runtime_profile_digest TEXT NOT NULL,runtime_database_id TEXT NOT NULL,qualification_digest TEXT NOT NULL,bundle_digest TEXT NOT NULL,session_id TEXT,runtime_open_operation_id TEXT,runtime_start_operation_id TEXT,runtime_pause_operation_id TEXT,runtime_head_root TEXT,attempt INTEGER NOT NULL,lease_id TEXT,lease_until INTEGER,failure_code TEXT,last_operation_id TEXT)",
    "CREATE TABLE admission_operations(operation_id TEXT PRIMARY KEY,admission_id TEXT NOT NULL,action TEXT NOT NULL,attempt INTEGER NOT NULL,request_digest TEXT NOT NULL,material_digest TEXT NOT NULL,material_raw BLOB NOT NULL,transition_id TEXT NOT NULL,receipt_digest TEXT NOT NULL,sequence INTEGER NOT NULL,receipt_raw BLOB NOT NULL,FOREIGN KEY(admission_id) REFERENCES admission_candidates(admission_id))",
    "CREATE TABLE admission_transitions(transition_id TEXT PRIMARY KEY,sequence INTEGER NOT NULL,admission_id TEXT NOT NULL,operation_id TEXT NOT NULL,action TEXT NOT NULL,attempt INTEGER NOT NULL,request_digest TEXT NOT NULL,prior_state TEXT NOT NULL,next_state TEXT NOT NULL,before_root TEXT NOT NULL,after_root TEXT NOT NULL,material_digest TEXT NOT NULL,observed_at INTEGER NOT NULL,transition_raw BLOB NOT NULL,FOREIGN KEY(admission_id) REFERENCES admission_candidates(admission_id),FOREIGN KEY(operation_id) REFERENCES admission_operations(operation_id))",
)
BUSY_TIMEOUT_MS = 250
MAX_EXPORT_BYTES = independent.MAX_EXPORT_BYTES


class AuthenticatedShadowAdmissionError(ValueError):
    """Base class for bounded public admission failures."""


class ShadowAdmissionConflictError(AuthenticatedShadowAdmissionError):
    pass


class ShadowAdmissionBusyError(AuthenticatedShadowAdmissionError):
    pass


class ShadowAdmissionResponseLost(AuthenticatedShadowAdmissionError):
    pass


class ShadowAdmissionInjectedFault(AuthenticatedShadowAdmissionError):
    pass


class ShadowAdmissionAuthorityError(AuthenticatedShadowAdmissionError):
    def __init__(self, reason: str = "AUTHORITY_INDETERMINATE") -> None:
        self.reason = reason if reason in independent.REASONS else "AUTHORITY_INDETERMINATE"
        super().__init__("admission:authority")


def _canonical(value: object) -> bytes:
    try:
        return independent._canonical(value)
    except independent.IndependentAuthenticatedShadowAdmissionError:
        raise_redacted(AuthenticatedShadowAdmissionError, "admission:noncanonical")


def _digest(label: str, value: object) -> str:
    return independent._digest(label, value)


def _raw_digest(raw: bytes) -> str:
    return independent._raw_digest(raw)


def _token(value: object, label: str) -> str:
    try:
        return independent._safe_value(value, label)
    except independent.IndependentAuthenticatedShadowAdmissionError:
        raise_redacted(AuthenticatedShadowAdmissionError, "admission:" + label)


def _hex(value: object, label: str) -> str:
    try:
        return independent._hex(value, label)
    except independent.IndependentAuthenticatedShadowAdmissionError:
        raise_redacted(AuthenticatedShadowAdmissionError, "admission:" + label)


def _policy_material(value: Mapping[str, object] | object) -> dict[str, object]:
    material = getattr(value, "material", None)
    if callable(material):
        return dict(material())
    if isinstance(value, Mapping):
        return dict(value)
    raise_redacted(AuthenticatedShadowAdmissionError, "admission:policy")


def _resolve_database(path: str | Path) -> Path:
    try:
        target = Path(os.path.abspath(os.fspath(path)))
    except (TypeError, ValueError):
        raise_redacted(AuthenticatedShadowAdmissionError, "admission:database-path")
    if not target.name or not target.parent.is_dir() or target.is_symlink() or target.parent.is_symlink():
        raise_redacted(AuthenticatedShadowAdmissionError, "admission:database-path")
    return target


@dataclass(frozen=True)
class AuthenticatedShadowAdmissionConfigV1:
    admission_ledger_id: str
    version: int
    acquisition_id: str
    acquisition_config_digest: str
    acquisition_database_id: str
    acquisition_profile_digest: str
    source_policy_digest: str
    quarantine_database_id: str
    quarantine_policy_digest: str
    quarantine_chain_id: str
    governance_policy_digest: str
    governance_verifier_id: str
    governance_verifier_epoch: int
    privacy_policy_digest: str
    privacy_verifier_id: str
    privacy_verifier_epoch: int
    runtime_profile_digest: str
    runtime_database_id: str
    cadence_seconds: int = 600
    freshness_grace_seconds: int = 60
    lease_seconds: int = 60
    max_admissions: int = 16
    max_attempts: int = 3
    busy_timeout_ms: int = BUSY_TIMEOUT_MS
    zero_phi: bool = True
    state_owned: bool = True
    read_only: bool = True
    observation_only: bool = True
    quarantine_only: bool = True
    synthetic_only: bool = True
    production_source_authentication: bool = False
    production_usable: bool = False
    activation: bool = False
    payment_authority: bool = False
    clearance_authority: bool = False
    settlement_authority: bool = False
    adjudication_authority: bool = False
    controlled_shadow_ready: bool = False
    proofSuiteId: None = None

    def __post_init__(self) -> None:
        try:
            independent._config_view(self)
        except independent.IndependentAuthenticatedShadowAdmissionError:
            raise AuthenticatedShadowAdmissionError("admission:config") from None

    def material(self) -> dict[str, object]:
        return {
            "admission_ledger_id": self.admission_ledger_id, "version": self.version,
            "acquisition_id": self.acquisition_id, "acquisition_config_digest": self.acquisition_config_digest,
            "acquisition_database_id": self.acquisition_database_id, "acquisition_profile_digest": self.acquisition_profile_digest,
            "source_policy_digest": self.source_policy_digest, "quarantine_database_id": self.quarantine_database_id,
            "quarantine_policy_digest": self.quarantine_policy_digest, "quarantine_chain_id": self.quarantine_chain_id,
            "governance_policy_digest": self.governance_policy_digest, "governance_verifier_id": self.governance_verifier_id,
            "governance_verifier_epoch": self.governance_verifier_epoch, "privacy_policy_digest": self.privacy_policy_digest,
            "privacy_verifier_id": self.privacy_verifier_id, "privacy_verifier_epoch": self.privacy_verifier_epoch,
            "runtime_profile_digest": self.runtime_profile_digest, "runtime_database_id": self.runtime_database_id,
            "cadence_seconds": self.cadence_seconds, "freshness_grace_seconds": self.freshness_grace_seconds,
            "lease_seconds": self.lease_seconds, "max_admissions": self.max_admissions,
            "max_attempts": self.max_attempts, "busy_timeout_ms": self.busy_timeout_ms,
            "zero_phi": self.zero_phi, "state_owned": self.state_owned,
            "read_only": self.read_only, "observation_only": self.observation_only,
            "quarantine_only": self.quarantine_only, "synthetic_only": self.synthetic_only,
            "production_source_authentication": self.production_source_authentication,
            "production_usable": self.production_usable, "activation": self.activation,
            "payment_authority": self.payment_authority, "clearance_authority": self.clearance_authority,
            "settlement_authority": self.settlement_authority, "adjudication_authority": self.adjudication_authority,
            "controlled_shadow_ready": self.controlled_shadow_ready, "proofSuiteId": self.proofSuiteId,
        }

    @property
    def digest(self) -> str:
        return independent.config_digest(self.material())


@dataclass(frozen=True)
class _VerifiedInputs:
    view: acquisition_independent.VerifiedAcquisitionQualificationV1
    source_policy: dict[str, object]
    governance_policy: dict[str, object]
    governance_raw: bytes
    governance_evidence_raw: bytes
    privacy_policy: dict[str, object]
    privacy_raw: bytes
    privacy_evidence_raw: bytes
    bundle: runtime.RuntimeUpstreamBundleV1
    governance_result: dict[str, object]
    privacy_result: dict[str, object]
    candidate: dict[str, object]


class AuthenticatedShadowAdmissionService:
    """One orchestration ledger around existing independent owners."""

    def __init__(
        self,
        database: str | Path,
        *,
        config: AuthenticatedShadowAdmissionConfigV1,
        acquisition_service: acquisition.AuthenticatedSourceAcquisitionService,
        runtime_service: runtime.ControlledShadowRuntimeService,
        runtime_database_id: str,
        authorization_verifier: runtime.ControlledShadowAuthorizationVerifier,
        clock: Callable[[], int],
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.database = _resolve_database(database)
        self.config = config
        self.acquisition_service = acquisition_service
        self.runtime_service = runtime_service
        self.runtime_database_id = _token(runtime_database_id, "runtime-database")
        self.authorization_verifier = authorization_verifier
        self.clock = clock
        self.fault_injector = fault_injector
        if not callable(clock):
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:clock")
        if acquisition_service.config.acquisition_id != config.acquisition_id or acquisition_service.config.digest != config.acquisition_config_digest or acquisition_service.config.nc_profile_digest != config.acquisition_profile_digest or acquisition_service.config.external_policy_digest != config.source_policy_digest:
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:acquisition-binding")
        if acquisition_service.quarantine_service.database_id != config.quarantine_database_id or acquisition_service.quarantine_service.policy_digest != config.quarantine_policy_digest or acquisition_service.quarantine_service.chain_id != config.quarantine_chain_id:
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:quarantine-binding")
        try:
            runtime_independent.verify_profile(runtime_service.profile_material)
        except runtime_independent.IndependentControlledShadowError:
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:runtime-profile")
        if runtime_service.profile_digest != config.runtime_profile_digest or self.runtime_database_id != config.runtime_database_id:
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:runtime-binding")
        try:
            verifier_id = authorization_verifier.verifier_id
            verifier_epoch = authorization_verifier.verifier_epoch
        except AttributeError:
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:runtime-verifier")
        if verifier_id != runtime_service.profile.authorization_verifier_id or verifier_epoch != runtime_service.profile.authorization_verifier_epoch:
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:runtime-verifier")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.database, timeout=self.config.busy_timeout_ms / 1000.0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute(f"PRAGMA busy_timeout={self.config.busy_timeout_ms}")
            journal = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(journal).lower() != "wal":
                connection.close()
                raise_redacted(AuthenticatedShadowAdmissionError, "admission:journal-mode")
            connection.execute("PRAGMA synchronous=FULL")
            return connection
        except AuthenticatedShadowAdmissionError:
            raise
        except sqlite3.OperationalError:
            raise_redacted(ShadowAdmissionBusyError, "admission:busy")
        except (sqlite3.Error, OSError):
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:database-open")

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if not tables:
                connection.execute("BEGIN IMMEDIATE")
                for statement in DDL:
                    connection.execute(statement)
                chain = independent._chain_id(self.config.digest)
                values = {
                    "schema": SCHEMA, "schema_version": str(SCHEMA_VERSION), "admission_ledger_id": self.config.admission_ledger_id,
                    "config_digest": self.config.digest, "chain_id": chain, "sequence": "0",
                    "state_root": independent._state_root(chain, 0, independent._genesis_root(chain), None),
                    "head_transition_id": independent.GENESIS_TRANSITION, **independent.FIXED_FLAG_STORAGE,
                }
                for key in sorted(values):
                    connection.execute("INSERT INTO admission_meta(key,value) VALUES(?,?)", (key, values[key]))
                connection.commit()
            elif tables != set(independent.TABLE_COLUMNS):
                raise_redacted(AuthenticatedShadowAdmissionError, "admission:database-schema")
        except AuthenticatedShadowAdmissionError:
            if connection.in_transaction:
                connection.rollback()
            raise
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:database-initialize")
        finally:
            connection.close()
        self.integrity()

    def _fault(self, point: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(point)

    @staticmethod
    def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
        return {str(row["key"]): str(row["value"]) for row in connection.execute("SELECT key,value FROM admission_meta ORDER BY key")}

    @staticmethod
    def _candidate(connection: sqlite3.Connection, admission_id: str) -> dict[str, object] | None:
        row = connection.execute("SELECT * FROM admission_candidates WHERE admission_id=?", (admission_id,)).fetchone()
        return None if row is None else dict(row)

    @staticmethod
    def _operation(connection: sqlite3.Connection, operation_id: str) -> dict[str, object] | None:
        row = connection.execute("SELECT * FROM admission_operations WHERE operation_id=?", (operation_id,)).fetchone()
        return None if row is None else dict(row)

    @staticmethod
    def _find_request(connection: sqlite3.Connection, admission_id: str, action: str, request_digest: str) -> dict[str, object] | None:
        row = connection.execute("SELECT * FROM admission_operations WHERE admission_id=? AND action=? AND request_digest=? ORDER BY sequence DESC LIMIT 1", (admission_id, action, request_digest)).fetchone()
        return None if row is None else dict(row)

    def _transition_locked(
        self,
        connection: sqlite3.Connection,
        *,
        candidate_after: Mapping[str, object],
        action: str,
        request_digest: str,
        attempt: int,
        observed_at: int,
    ) -> dict[str, object]:
        admission_id = str(candidate_after["admission_id"])
        current = self._candidate(connection, admission_id)
        prior_state = "" if current is None else str(current["state"])
        next_state = str(candidate_after["state"])
        after = {key: candidate_after[key] for key in independent.MATERIAL_COLUMNS}
        material = {"action": action, "attempt": attempt, "request_digest": request_digest, "prior_state": prior_state, "next_state": next_state, "candidate_after": after}
        material_raw = _canonical(material)
        material_digest = _digest("material", material)
        operation_id = independent._operation_id(admission_id, action, request_digest, material_digest)
        existing = self._operation(connection, operation_id)
        if existing is not None:
            if existing["material_digest"] != material_digest or bytes(existing["material_raw"]) != material_raw:
                raise_redacted(ShadowAdmissionConflictError, "admission:operation-conflict")
            return {"accepted": True, "operation_id": operation_id, "admission_id": admission_id, "state": next_state, "receipt_raw": bytes(existing["receipt_raw"]), "receipt_digest": existing["receipt_digest"], "head_root": self._metadata(connection)["state_root"], "replayed": True}
        metadata = self._metadata(connection)
        sequence = int(metadata["sequence"]) + 1
        before_root = metadata["state_root"]
        transition_id = independent._transition_id(sequence, admission_id, action, material_digest, before_root)
        after_root = independent._state_root(independent._chain_id(self.config.digest), sequence, before_root, transition_id)
        transition_value = {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "transition_id": transition_id,
            "sequence": sequence, "admission_id": admission_id, "operation_id": operation_id,
            "action": action, "attempt": attempt, "request_digest": request_digest,
            "prior_state": prior_state, "next_state": next_state, "before_root": before_root,
            "after_root": after_root, "material_digest": material_digest, "observed_at": observed_at,
        }
        transition_raw = _canonical(transition_value)
        receipt_value = {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "admission_id": admission_id,
            "operation_id": operation_id, "action": action, "attempt": attempt,
            "request_digest": request_digest, "prior_state": prior_state, "next_state": next_state,
            "sequence": sequence, "before_root": before_root, "after_root": after_root,
            "transition_id": transition_id, "material_digest": material_digest,
            "candidate_digest": after["qualification_digest"], "flags": FIXED_FLAGS,
        }
        receipt_raw = _canonical(receipt_value)
        stored = dict(after)
        stored["state"] = next_state
        stored["last_operation_id"] = None
        if current is None:
            connection.execute("INSERT INTO admission_candidates(" + ",".join(independent.CANDIDATE_COLUMNS) + ") VALUES(" + ",".join("?" for _ in independent.CANDIDATE_COLUMNS) + ")", tuple(stored[key] for key in independent.CANDIDATE_COLUMNS))
        connection.execute(
            "INSERT INTO admission_operations(operation_id,admission_id,action,attempt,request_digest,material_digest,material_raw,transition_id,receipt_digest,sequence,receipt_raw) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (operation_id, admission_id, action, attempt, request_digest, material_digest, material_raw, transition_id, _raw_digest(receipt_raw), sequence, receipt_raw),
        )
        connection.execute(
            "INSERT INTO admission_transitions(transition_id,sequence,admission_id,operation_id,action,attempt,request_digest,prior_state,next_state,before_root,after_root,material_digest,observed_at,transition_raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (transition_id, sequence, admission_id, operation_id, action, attempt, request_digest, prior_state, next_state, before_root, after_root, material_digest, observed_at, transition_raw),
        )
        stored["state"] = next_state
        stored["last_operation_id"] = operation_id
        assignments = ",".join(f"{key}=?" for key in independent.CANDIDATE_COLUMNS if key != "admission_id")
        connection.execute("UPDATE admission_candidates SET " + assignments + " WHERE admission_id=?", tuple(stored[key] for key in independent.CANDIDATE_COLUMNS if key != "admission_id") + (admission_id,))
        connection.execute("UPDATE admission_meta SET value=? WHERE key='sequence'", (str(sequence),))
        connection.execute("UPDATE admission_meta SET value=? WHERE key='state_root'", (after_root,))
        connection.execute("UPDATE admission_meta SET value=? WHERE key='head_transition_id'", (transition_id,))
        self._fault("after_transition_insert")
        return {"accepted": True, "operation_id": operation_id, "admission_id": admission_id, "state": next_state, "receipt_raw": receipt_raw, "receipt_digest": _raw_digest(receipt_raw), "head_root": after_root, "replayed": False}

    def _run_transaction(self, callback: Callable[[sqlite3.Connection], dict[str, object]]) -> dict[str, object]:
        self._fault("before_transaction")
        connection = self._connect()
        committed = False
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError:
                raise_redacted(ShadowAdmissionBusyError, "admission:busy")
            self._fault("after_begin")
            result = callback(connection)
            self._fault("before_commit")
            connection.commit()
            committed = True
            try:
                self._fault("after_commit_before_response")
            except ShadowAdmissionInjectedFault:
                raise ShadowAdmissionResponseLost("admission:response-loss")
            return result
        except ShadowAdmissionResponseLost:
            raise
        except (ShadowAdmissionInjectedFault, ShadowAdmissionConflictError, ShadowAdmissionBusyError, AuthenticatedShadowAdmissionError):
            if not committed and connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.IntegrityError:
            if not committed and connection.in_transaction:
                connection.rollback()
            raise_redacted(ShadowAdmissionConflictError, "admission:integrity")
        except sqlite3.OperationalError:
            if not committed and connection.in_transaction:
                connection.rollback()
            raise_redacted(ShadowAdmissionBusyError, "admission:busy")
        except Exception:
            if not committed and connection.in_transaction:
                connection.rollback()
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:database")
        finally:
            connection.close()

    def _profile(self) -> dict[str, object]:
        try:
            return runtime_independent.verify_profile(self.runtime_service.profile_material)
        except runtime_independent.IndependentControlledShadowError:
            raise ShadowAdmissionAuthorityError("AUTHORITY_INDETERMINATE")

    @staticmethod
    def _artifact_assertion(raw: bytes, parser: Callable[[bytes], dict[str, object]]) -> Mapping[str, object]:
        try:
            value = parser(raw)
            assertion = value.get("assertion")
        except Exception:
            raise ShadowAdmissionAuthorityError("AUTHORITY_INDETERMINATE")
        if not isinstance(assertion, Mapping):
            raise ShadowAdmissionAuthorityError("AUTHORITY_INDETERMINATE")
        return assertion

    def _verify_current(
        self,
        slot_id: str,
        *,
        governance_policy: Mapping[str, object] | object,
        governance_raw: bytes,
        governance_evidence_raw: bytes,
        privacy_policy: Mapping[str, object] | object,
        privacy_raw: bytes,
        privacy_evidence_raw: bytes,
    ) -> _VerifiedInputs:
        try:
            view = self.acquisition_service.qualification_view(slot_id)
        except acquisition.AcquisitionQualificationError as exc:
            raise ShadowAdmissionAuthorityError(exc.reason)
        except acquisition.AuthenticatedSourceAcquisitionError:
            raise ShadowAdmissionAuthorityError("AUTHORITY_INDETERMINATE")
        source_policy = self.acquisition_service.external_policy.material()
        g_policy = _policy_material(governance_policy)
        p_policy = _policy_material(privacy_policy)
        if g_policy.get("source_policy_digest") != self.config.source_policy_digest or g_policy.get("quarantine_artifact_id") != view.artifact_id or g_policy.get("quarantine_head_artifact_id") != view.quarantine_head_artifact_id or g_policy.get("quarantine_head_root") != view.quarantine_head_root or g_policy.get("verifier_id") != self.config.governance_verifier_id or g_policy.get("verifier_epoch") != self.config.governance_verifier_epoch or governance_independent._digest("policy", governance_independent._policy_material(g_policy)) != self.config.governance_policy_digest:
            raise ShadowAdmissionAuthorityError("AUTHORITY_INDETERMINATE")
        if p_policy.get("source_policy_digest") != self.config.source_policy_digest or p_policy.get("quarantine_artifact_id") != view.artifact_id or p_policy.get("quarantine_head_artifact_id") != view.quarantine_head_artifact_id or p_policy.get("quarantine_head_root") != view.quarantine_head_root or p_policy.get("verifier_id") != self.config.privacy_verifier_id or p_policy.get("verifier_epoch") != self.config.privacy_verifier_epoch or privacy_independent._digest("policy", privacy_independent._policy_material(p_policy)) != self.config.privacy_policy_digest:
            raise ShadowAdmissionAuthorityError("AUTHORITY_INDETERMINATE")
        try:
            g_result = governance_independent.verify_artifact(governance_raw, policy=g_policy, evidence_raw=governance_evidence_raw)
        except governance_independent.IndependentExternalGovernanceError:
            raise ShadowAdmissionAuthorityError("AUTHORITY_INDETERMINATE")
        if g_result["decision"] != "GRANTED":
            raise ShadowAdmissionAuthorityError("GOVERNANCE_WITHDRAWN")
        try:
            p_result = privacy_independent.verify_artifact(privacy_raw, policy=p_policy, evidence_raw=privacy_evidence_raw)
        except privacy_independent.IndependentExternalPrivacySupportError:
            raise ShadowAdmissionAuthorityError("AUTHORITY_INDETERMINATE")
        if p_result["privacy_decision"] != "GRANTED":
            raise ShadowAdmissionAuthorityError("PRIVACY_WITHDRAWN")
        if p_result["support_decision"] != "GRANTED":
            raise ShadowAdmissionAuthorityError("PRIVACY_WITHDRAWN")
        g_assertion = self._artifact_assertion(governance_raw, governance_independent._parse)
        p_assertion = self._artifact_assertion(privacy_raw, privacy_independent._parse)
        now = self.clock()
        if type(now) is not int or now < 1:
            raise ShadowAdmissionAuthorityError("AUTHORITY_INDETERMINATE")
        if now < int(g_assertion["valid_from"]) or now > int(g_assertion["valid_until"]):
            raise ShadowAdmissionAuthorityError("GOVERNANCE_EXPIRED")
        if now < int(p_assertion["valid_from"]) or now > int(p_assertion["valid_until"]):
            raise ShadowAdmissionAuthorityError("PRIVACY_EXPIRED")
        profile = self._profile()
        if runtime_independent.profile_digest(profile) != self.config.runtime_profile_digest:
            raise ShadowAdmissionAuthorityError("AUTHORITY_INDETERMINATE")
        if profile["source_policy_digest"] != view.source_policy_digest or profile["quarantine_artifact_id"] != view.artifact_id or profile["quarantine_head_artifact_id"] != view.quarantine_head_artifact_id or profile["quarantine_head_root"] != view.quarantine_head_root or profile["governance_policy_digest"] != self.config.governance_policy_digest or profile["governance_artifact_id"] != g_result["artifact_id"] or profile["governance_evidence_digest"] != _raw_digest(governance_evidence_raw) or profile["privacy_policy_digest"] != self.config.privacy_policy_digest or profile["privacy_artifact_id"] != p_result["artifact_id"] or profile["privacy_evidence_digest"] != _raw_digest(privacy_evidence_raw) or profile["governance_decision"] != "GRANTED" or profile["privacy_decision"] != "GRANTED" or profile["support_decision"] != "GRANTED":
            raise ShadowAdmissionAuthorityError("AUTHORITY_INDETERMINATE")
        q_head = {
            "policy_digest": view.quarantine_policy_digest,
            "head_artifact_id": view.quarantine_head_artifact_id,
            "head_root": view.quarantine_head_root,
            "state": "QUARANTINED",
            "sequence": view.quarantine_sequence,
        }
        bundle = runtime.RuntimeUpstreamBundleV1(
            source_policy=source_policy,
            quarantine_raw=bytes(view.artifact_raw),
            quarantine_head=q_head,
            governance_policy=g_policy,
            governance_raw=bytes(governance_raw),
            governance_evidence_raw=bytes(governance_evidence_raw),
            privacy_policy=p_policy,
            privacy_raw=bytes(privacy_raw),
            privacy_evidence_raw=bytes(privacy_evidence_raw),
        )
        try:
            runtime_independent.verify_upstream_bundle(bundle.snapshot(), profile=profile)
        except runtime_independent.IndependentControlledShadowError:
            raise ShadowAdmissionAuthorityError("AUTHORITY_INDETERMINATE")
        bundle_material = {
            "qualification_digest": view.qualification_digest,
            "governance_artifact_id": g_result["artifact_id"],
            "governance_evidence_digest": _raw_digest(governance_evidence_raw),
            "privacy_artifact_id": p_result["artifact_id"],
            "privacy_evidence_digest": _raw_digest(privacy_evidence_raw),
            "runtime_profile_digest": self.config.runtime_profile_digest,
            "runtime_database_id": self.config.runtime_database_id,
        }
        candidate: dict[str, object] = {key: None for key in independent.MATERIAL_COLUMNS}
        candidate.update({
            "admission_id": _digest("admission", bundle_material), "config_digest": self.config.digest,
            "state": "DISCOVERED", "slot_id": view.slot_id, "acquisition_id": view.acquisition_id,
            "acquisition_config_digest": view.config_digest, "acquisition_database_id": view.acquisition_database_id,
            "acquisition_profile_digest": self.config.acquisition_profile_digest, "source_policy_digest": view.source_policy_digest,
            "scheduled_at": view.scheduled_at, "observed_at": view.observed_at, "fetched_at": view.fetched_at,
            "envelope_id": view.envelope_id, "envelope_digest": view.envelope_digest,
            "capture_id": view.capture_id, "artifact_id": view.artifact_id, "artifact_digest": view.artifact_digest,
            "quarantine_database_id": view.quarantine_database_id, "quarantine_policy_digest": view.quarantine_policy_digest,
            "quarantine_chain_id": view.quarantine_chain_id, "quarantine_operation_id": view.quarantine_operation_id,
            "quarantine_transition_id": view.quarantine_transition_id, "quarantine_request_digest": view.quarantine_request_digest,
            "quarantine_receipt_digest": view.quarantine_receipt_digest,
            "quarantine_head_root": view.quarantine_head_root, "quarantine_sequence": view.quarantine_sequence,
            "governance_policy_digest": self.config.governance_policy_digest, "governance_artifact_id": g_result["artifact_id"],
            "governance_evidence_digest": _raw_digest(governance_evidence_raw), "governance_verifier_id": self.config.governance_verifier_id,
            "governance_verifier_epoch": self.config.governance_verifier_epoch, "privacy_policy_digest": self.config.privacy_policy_digest,
            "privacy_artifact_id": p_result["artifact_id"], "privacy_evidence_digest": _raw_digest(privacy_evidence_raw),
            "privacy_verifier_id": self.config.privacy_verifier_id, "privacy_verifier_epoch": self.config.privacy_verifier_epoch,
            "runtime_profile_digest": self.config.runtime_profile_digest, "runtime_database_id": self.config.runtime_database_id,
            "qualification_digest": view.qualification_digest, "bundle_digest": _digest("bundle", bundle_material),
            "attempt": 0,
        })
        return _VerifiedInputs(view, source_policy, g_policy, bytes(governance_raw), bytes(governance_evidence_raw), p_policy, bytes(privacy_raw), bytes(privacy_evidence_raw), bundle, g_result, p_result, candidate)

    def _current_for_row(self, row: Mapping[str, object], **kwargs: object) -> _VerifiedInputs:
        verified = self._verify_current(str(row["slot_id"]), **kwargs)  # type: ignore[arg-type]
        candidate = verified.candidate
        if candidate["admission_id"] != row["admission_id"] or candidate["qualification_digest"] != row["qualification_digest"] or candidate["bundle_digest"] != row["bundle_digest"]:
            raise ShadowAdmissionAuthorityError("AUTHORITY_INDETERMINATE")
        return verified

    @staticmethod
    def _request_digest(request_key: str) -> str:
        _token(request_key, "request-key")
        return _digest("request", {"request_key": request_key})

    def qualify(
        self,
        request_key: str,
        slot_id: str,
        *,
        governance_policy: Mapping[str, object] | object,
        governance_raw: bytes,
        governance_evidence_raw: bytes,
        privacy_policy: Mapping[str, object] | object,
        privacy_raw: bytes,
        privacy_evidence_raw: bytes,
    ) -> dict[str, object]:
        verified = self._verify_current(slot_id, governance_policy=governance_policy, governance_raw=governance_raw, governance_evidence_raw=governance_evidence_raw, privacy_policy=privacy_policy, privacy_raw=privacy_raw, privacy_evidence_raw=privacy_evidence_raw)
        request_digest = self._request_digest(request_key)
        candidate = dict(verified.candidate)
        admission_id = str(candidate["admission_id"])
        candidate["admission_id"] = admission_id
        candidate["config_digest"] = self.config.digest
        def mutate(connection: sqlite3.Connection) -> dict[str, object]:
            existing = self._candidate(connection, admission_id)
            if existing is not None:
                if existing["qualification_digest"] != candidate["qualification_digest"] or existing["bundle_digest"] != candidate["bundle_digest"]:
                    raise_redacted(ShadowAdmissionConflictError, "admission:candidate-conflict")
                found = self._find_request(connection, admission_id, "QUALIFY", request_digest)
                if found is not None:
                    return {"accepted": True, "admission_id": admission_id, "state": existing["state"], "receipt_raw": bytes(found["receipt_raw"]), "receipt_digest": found["receipt_digest"], "operation_id": found["operation_id"], "head_root": self._metadata(connection)["state_root"], "replayed": True}
                if existing["state"] != "DISCOVERED":
                    raise_redacted(ShadowAdmissionConflictError, "admission:qualification-retry")
                return self._transition_locked(connection, candidate_after={**candidate, "state": "QUALIFIED"}, action="QUALIFY", request_digest=request_digest, attempt=0, observed_at=int(self.clock()))
            count = int(connection.execute("SELECT COUNT(*) FROM admission_candidates").fetchone()[0])
            if count >= self.config.max_admissions:
                raise_redacted(ShadowAdmissionConflictError, "admission:capacity")
            discovered = self._transition_locked(connection, candidate_after={**candidate, "state": "DISCOVERED"}, action="DISCOVER", request_digest=request_digest, attempt=0, observed_at=int(self.clock()))
            if not discovered["accepted"]:
                raise_redacted(ShadowAdmissionConflictError, "admission:discover")
            return self._transition_locked(connection, candidate_after={**candidate, "state": "QUALIFIED"}, action="QUALIFY", request_digest=request_digest, attempt=0, observed_at=int(self.clock()))
        return self._run_transaction(mutate)

    def _runtime_snapshot_operation(self, operation_id: str, action: str) -> dict[str, object] | None:
        try:
            snapshot_result = runtime_independent.snapshot_database(self.runtime_service.database, profile=self.runtime_service.profile_material)
        except runtime_independent.IndependentControlledShadowError:
            raise ShadowAdmissionResponseLost("admission:runtime-indeterminate")
        rows = snapshot_result["snapshot"]["runtime_operations"]
        matches = [row for row in rows if row["operation_id"] == operation_id and row["action"] == action]
        if len(matches) > 1:
            raise_redacted(ShadowAdmissionConflictError, "admission:runtime-operation")
        if not matches:
            return None
        operation = dict(matches[0])
        transitions = snapshot_result["snapshot"]["runtime_transitions"]
        transition_matches = [row for row in transitions if row["operation_id"] == operation_id and row["transition_id"] == operation["transition_id"]]
        if len(transition_matches) != 1:
            raise_redacted(ShadowAdmissionConflictError, "admission:runtime-operation")
        operation["after_session_root"] = transition_matches[0]["after_session_root"]
        return operation

    def _lease_candidate(self, row: Mapping[str, object], *, state: str, request_digest: str, action: str, failure_code: str | None = None) -> dict[str, object]:
        attempt = int(row["attempt"]) + 1
        if attempt > self.config.max_attempts:
            raise_redacted(ShadowAdmissionConflictError, "admission:attempt-cap")
        updated = dict(row)
        updated["state"] = state
        updated["attempt"] = attempt
        updated["lease_id"] = _digest("lease", {"admission_id": row["admission_id"], "action": action, "request_digest": request_digest, "attempt": attempt})
        updated["lease_until"] = int(self.clock()) + self.config.lease_seconds
        updated["failure_code"] = failure_code
        return updated

    def _pending_or_requeue(self, connection: sqlite3.Connection, row: Mapping[str, object], *, pending_state: str, action: str, request_digest: str, failure_code: str | None = None) -> dict[str, object]:
        if row["state"] == pending_state and row["lease_until"] is not None and int(row["lease_until"]) > int(self.clock()):
            last = self._operation(connection, str(row["last_operation_id"]))
            if last is None or last["action"] != action or last["request_digest"] != request_digest:
                raise_redacted(ShadowAdmissionConflictError, "admission:lease-owned")
            return dict(row)
        if row["state"] == pending_state:
            updated = self._lease_candidate(row, state=pending_state, request_digest=request_digest, action="REQUEUE", failure_code=failure_code)
            self._transition_locked(connection, candidate_after=updated, action="REQUEUE", request_digest=request_digest, attempt=int(updated["attempt"]), observed_at=int(self.clock()))
            return updated
        updated = self._lease_candidate(row, state=pending_state, request_digest=request_digest, action=action, failure_code=failure_code)
        self._transition_locked(connection, candidate_after=updated, action=action, request_digest=request_digest, attempt=int(updated["attempt"]), observed_at=int(self.clock()))
        return updated

    def _confirm_runtime(
        self,
        admission_id: str,
        *,
        pending_state: str,
        final_state: str,
        action: str,
        request_digest: str,
        runtime_operation_id: str,
        runtime_row: Mapping[str, object],
    ) -> dict[str, object]:
        def mutate(connection: sqlite3.Connection) -> dict[str, object]:
            row = self._candidate(connection, admission_id)
            if row is None:
                raise_redacted(ShadowAdmissionConflictError, "admission:missing")
            found = self._find_request(connection, admission_id, action, request_digest)
            if found is not None:
                return {"accepted": True, "admission_id": admission_id, "state": row["state"], "receipt_raw": bytes(found["receipt_raw"]), "receipt_digest": found["receipt_digest"], "operation_id": found["operation_id"], "head_root": self._metadata(connection)["state_root"], "replayed": True}
            if row["state"] != pending_state:
                raise_redacted(ShadowAdmissionConflictError, "admission:state")
            updated = dict(row)
            updated["state"] = final_state
            updated["lease_id"] = None
            updated["lease_until"] = None
            if action != "PAUSE":
                updated["failure_code"] = None
            if action == "OPEN":
                updated["session_id"] = str(runtime_row["session_id"])
                updated["runtime_open_operation_id"] = runtime_operation_id
            elif action == "START":
                updated["runtime_start_operation_id"] = runtime_operation_id
            elif action == "PAUSE":
                updated["runtime_pause_operation_id"] = runtime_operation_id
            updated["runtime_head_root"] = str(runtime_row["after_session_root"])
            return self._transition_locked(connection, candidate_after=updated, action=action, request_digest=request_digest, attempt=int(row["attempt"]), observed_at=int(self.clock()))
        return self._run_transaction(mutate)

    def open(
        self,
        request_key: str,
        admission_id: str,
        *,
        governance_policy: Mapping[str, object] | object,
        governance_raw: bytes,
        governance_evidence_raw: bytes,
        privacy_policy: Mapping[str, object] | object,
        privacy_raw: bytes,
        privacy_evidence_raw: bytes,
    ) -> dict[str, object]:
        _hex(admission_id, "admission-id")
        request_digest = self._request_digest(request_key)
        def load() -> dict[str, object]:
            connection = self._connect()
            try:
                row = self._candidate(connection, admission_id)
                if row is None:
                    raise_redacted(ShadowAdmissionConflictError, "admission:missing")
                return row
            finally:
                connection.close()
        current_row = load()
        verified = self._current_for_row(current_row, governance_policy=governance_policy, governance_raw=governance_raw, governance_evidence_raw=governance_evidence_raw, privacy_policy=privacy_policy, privacy_raw=privacy_raw, privacy_evidence_raw=privacy_evidence_raw)
        runtime_operation_id = _digest("runtime-open", {"admission_id": admission_id, "qualification_digest": current_row["qualification_digest"]})
        def reserve(connection: sqlite3.Connection) -> dict[str, object]:
            row = self._candidate(connection, admission_id)
            if row is None:
                raise_redacted(ShadowAdmissionConflictError, "admission:missing")
            found = self._find_request(connection, admission_id, "OPEN", request_digest)
            if found is not None:
                return {"accepted": True, "admission_id": admission_id, "state": row["state"], "runtime_operation_id": runtime_operation_id, "final": True, "receipt_raw": bytes(found["receipt_raw"]), "receipt_digest": found["receipt_digest"], "operation_id": found["operation_id"], "head_root": self._metadata(connection)["state_root"]}
            if row["state"] == "OPENED":
                raise_redacted(ShadowAdmissionConflictError, "admission:open-retry")
            if row["state"] not in {"QUALIFIED", "OPEN_PENDING"}:
                raise_redacted(ShadowAdmissionConflictError, "admission:state")
            updated = self._pending_or_requeue(connection, row, pending_state="OPEN_PENDING", action="OPEN_PENDING", request_digest=request_digest)
            return {"accepted": True, "admission_id": admission_id, "state": updated["state"], "runtime_operation_id": runtime_operation_id, "final": False, "head_root": self._metadata(connection)["state_root"]}
        reserved = self._run_transaction(reserve)
        if reserved.get("final"):
            return reserved
        verified = self._current_for_row(current_row, governance_policy=governance_policy, governance_raw=governance_raw, governance_evidence_raw=governance_evidence_raw, privacy_policy=privacy_policy, privacy_raw=privacy_raw, privacy_evidence_raw=privacy_evidence_raw)
        runtime_row: dict[str, object] | None = None
        try:
            # The runtime owner is itself idempotent on this exact operation.
            # Calling it for every pending retry avoids a read-then-call race
            # in which two identical admission writers both observe absence.
            self.runtime_service.create_session(runtime_operation_id, "ADMISSION_" + admission_id[:24], verified.bundle, self.authorization_verifier)
            runtime_row = self._runtime_snapshot_operation(runtime_operation_id, "OPEN")
            if runtime_row is None:
                raise ShadowAdmissionResponseLost("admission:runtime-indeterminate")
        except runtime.RuntimeResponseLost:
            runtime_row = self._runtime_snapshot_operation(runtime_operation_id, "OPEN")
            if runtime_row is None:
                raise ShadowAdmissionResponseLost("admission:response-loss")
        except runtime.RuntimeBusyError:
            raise_redacted(ShadowAdmissionBusyError, "admission:runtime-busy")
        except runtime.RuntimeConflictError:
            runtime_row = self._runtime_snapshot_operation(runtime_operation_id, "OPEN")
            if runtime_row is None:
                raise_redacted(ShadowAdmissionConflictError, "admission:runtime-conflict")
        except runtime.ControlledShadowRuntimeError:
            raise_redacted(ShadowAdmissionConflictError, "admission:runtime")
        return self._confirm_runtime(admission_id, pending_state="OPEN_PENDING", final_state="OPENED", action="OPEN", request_digest=request_digest, runtime_operation_id=runtime_operation_id, runtime_row=runtime_row)

    def start(
        self,
        request_key: str,
        admission_id: str,
        *,
        governance_policy: Mapping[str, object] | object,
        governance_raw: bytes,
        governance_evidence_raw: bytes,
        privacy_policy: Mapping[str, object] | object,
        privacy_raw: bytes,
        privacy_evidence_raw: bytes,
    ) -> dict[str, object]:
        _hex(admission_id, "admission-id")
        request_digest = self._request_digest(request_key)
        connection = self._connect()
        try:
            row = self._candidate(connection, admission_id)
            if row is None:
                raise_redacted(ShadowAdmissionConflictError, "admission:missing")
            current_row = row
        finally:
            connection.close()
        verified = self._current_for_row(current_row, governance_policy=governance_policy, governance_raw=governance_raw, governance_evidence_raw=governance_evidence_raw, privacy_policy=privacy_policy, privacy_raw=privacy_raw, privacy_evidence_raw=privacy_evidence_raw)
        runtime_operation_id = _digest("runtime-start", {"admission_id": admission_id, "qualification_digest": current_row["qualification_digest"]})
        def reserve(connection: sqlite3.Connection) -> dict[str, object]:
            row = self._candidate(connection, admission_id)
            if row is None:
                raise_redacted(ShadowAdmissionConflictError, "admission:missing")
            found = self._find_request(connection, admission_id, "START", request_digest)
            if found is not None:
                return {"accepted": True, "admission_id": admission_id, "state": row["state"], "runtime_operation_id": runtime_operation_id, "final": True, "receipt_raw": bytes(found["receipt_raw"]), "receipt_digest": found["receipt_digest"], "operation_id": found["operation_id"], "head_root": self._metadata(connection)["state_root"]}
            if row["state"] == "STARTED":
                raise_redacted(ShadowAdmissionConflictError, "admission:start-retry")
            if row["state"] not in {"OPENED", "START_PENDING"}:
                raise_redacted(ShadowAdmissionConflictError, "admission:state")
            updated = self._pending_or_requeue(connection, row, pending_state="START_PENDING", action="START_PENDING", request_digest=request_digest)
            return {"accepted": True, "admission_id": admission_id, "state": updated["state"], "runtime_operation_id": runtime_operation_id, "final": False, "head_root": self._metadata(connection)["state_root"]}
        reserved = self._run_transaction(reserve)
        if reserved.get("final"):
            return reserved
        _ = self._current_for_row(current_row, governance_policy=governance_policy, governance_raw=governance_raw, governance_evidence_raw=governance_evidence_raw, privacy_policy=privacy_policy, privacy_raw=privacy_raw, privacy_evidence_raw=privacy_evidence_raw)
        runtime_row: dict[str, object] | None = None
        try:
            current_head = str(current_row["runtime_head_root"])
            self.runtime_service.start_session(runtime_operation_id, str(current_row["session_id"]), expected_head=current_head)
            runtime_row = self._runtime_snapshot_operation(runtime_operation_id, "START")
            if runtime_row is None:
                raise ShadowAdmissionResponseLost("admission:runtime-indeterminate")
        except runtime.RuntimeResponseLost:
            runtime_row = self._runtime_snapshot_operation(runtime_operation_id, "START")
            if runtime_row is None:
                raise ShadowAdmissionResponseLost("admission:response-loss")
        except runtime.RuntimeBusyError:
            raise_redacted(ShadowAdmissionBusyError, "admission:runtime-busy")
        except runtime.RuntimeConflictError:
            runtime_row = self._runtime_snapshot_operation(runtime_operation_id, "START")
            if runtime_row is None:
                raise_redacted(ShadowAdmissionConflictError, "admission:runtime-conflict")
        except runtime.ControlledShadowRuntimeError:
            raise_redacted(ShadowAdmissionConflictError, "admission:runtime")
        return self._confirm_runtime(admission_id, pending_state="START_PENDING", final_state="STARTED", action="START", request_digest=request_digest, runtime_operation_id=runtime_operation_id, runtime_row=runtime_row)

    def supervise(
        self,
        request_key: str,
        admission_id: str,
        *,
        governance_policy: Mapping[str, object] | object,
        governance_raw: bytes,
        governance_evidence_raw: bytes,
        privacy_policy: Mapping[str, object] | object,
        privacy_raw: bytes,
        privacy_evidence_raw: bytes,
    ) -> dict[str, object]:
        _hex(admission_id, "admission-id")
        request_digest = self._request_digest(request_key)
        connection = self._connect()
        try:
            row = self._candidate(connection, admission_id)
            if row is None or row["state"] not in {"STARTED", "PAUSE_PENDING", "PAUSED"}:
                raise_redacted(ShadowAdmissionConflictError, "admission:state")
            current_row = row
        finally:
            connection.close()
        reason = None
        try:
            self._current_for_row(current_row, governance_policy=governance_policy, governance_raw=governance_raw, governance_evidence_raw=governance_evidence_raw, privacy_policy=privacy_policy, privacy_raw=privacy_raw, privacy_evidence_raw=privacy_evidence_raw)
        except ShadowAdmissionAuthorityError as exc:
            reason = exc.reason
        if reason is None:
            if current_row["state"] == "PAUSED":
                return {"accepted": True, "admission_id": admission_id, "state": "PAUSED", "supervision": "UNCHANGED"}
            return {"accepted": True, "admission_id": admission_id, "state": current_row["state"], "supervision": "CURRENT"}
        runtime_operation_id = _digest("runtime-pause", {"admission_id": admission_id, "qualification_digest": current_row["qualification_digest"], "reason": reason})
        def reserve(connection: sqlite3.Connection) -> dict[str, object]:
            row = self._candidate(connection, admission_id)
            if row is None:
                raise_redacted(ShadowAdmissionConflictError, "admission:missing")
            found = self._find_request(connection, admission_id, "PAUSE", request_digest)
            if found is not None:
                return {"accepted": True, "final": True, "state": row["state"], "receipt_raw": bytes(found["receipt_raw"]), "receipt_digest": found["receipt_digest"], "operation_id": found["operation_id"], "head_root": self._metadata(connection)["state_root"]}
            if row["state"] == "PAUSED":
                raise_redacted(ShadowAdmissionConflictError, "admission:pause-retry")
            updated = self._pending_or_requeue(
                connection,
                row,
                pending_state="PAUSE_PENDING",
                action="PAUSE_PENDING",
                request_digest=request_digest,
                failure_code=reason,
            )
            return {**updated, "final": False}
        reserved = self._run_transaction(reserve)
        if reserved.get("final"):
            return reserved
        runtime_row: dict[str, object] | None = None
        try:
            self.runtime_service.pause_session(runtime_operation_id, str(current_row["session_id"]), expected_head=str(current_row["runtime_head_root"]), reason="AUTHORITY_EXPIRED")
            runtime_row = self._runtime_snapshot_operation(runtime_operation_id, "PAUSE")
            if runtime_row is None:
                raise ShadowAdmissionResponseLost("admission:runtime-indeterminate")
        except runtime.RuntimeResponseLost:
            runtime_row = self._runtime_snapshot_operation(runtime_operation_id, "PAUSE")
            if runtime_row is None:
                raise ShadowAdmissionResponseLost("admission:response-loss")
        except runtime.RuntimeBusyError:
            raise_redacted(ShadowAdmissionBusyError, "admission:runtime-busy")
        except runtime.RuntimeConflictError:
            runtime_row = self._runtime_snapshot_operation(runtime_operation_id, "PAUSE")
            if runtime_row is None:
                raise_redacted(ShadowAdmissionConflictError, "admission:runtime-conflict")
        except runtime.ControlledShadowRuntimeError:
            raise_redacted(ShadowAdmissionConflictError, "admission:runtime")
        confirmed = self._confirm_runtime(admission_id, pending_state="PAUSE_PENDING", final_state="PAUSED", action="PAUSE", request_digest=request_digest, runtime_operation_id=runtime_operation_id, runtime_row=runtime_row)
        return {**confirmed, "reason": reason}

    def integrity(self) -> dict[str, object]:
        try:
            return independent.verify_database(self.database, config=self.config.material())
        except independent.IndependentAuthenticatedShadowAdmissionError:
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:integrity")

    def export_bytes(self) -> bytes:
        try:
            snapshot_result = independent.snapshot_database(self.database, config=self.config.material())
            rows = snapshot_result["snapshot"]
            body: dict[str, object] = {
                "schema": EXPORT_SCHEMA, "schema_version": EXPORT_VERSION, "config": self.config.material(),
                "config_digest": self.config.digest, "chain_id": independent._chain_id(self.config.digest),
                "meta": rows["admission_meta"], "candidates": rows["admission_candidates"], "operations": [], "transitions": [],
                **FIXED_FLAGS,
            }
            body["operations"] = [{**{key: row[key] for key in independent.TABLE_COLUMNS["admission_operations"] if key not in {"material_raw", "receipt_raw"}}, "material_hex": bytes(row["material_raw"]).hex(), "receipt_hex": bytes(row["receipt_raw"]).hex()} for row in rows["admission_operations"]]
            body["transitions"] = [{**{key: row[key] for key in independent.TABLE_COLUMNS["admission_transitions"] if key != "transition_raw"}, "transition_hex": bytes(row["transition_raw"]).hex()} for row in rows["admission_transitions"]]
            body["export_root"] = _digest("export-root", body)
            raw = _canonical(body)
            if len(raw) > MAX_EXPORT_BYTES:
                raise_redacted(AuthenticatedShadowAdmissionError, "admission:export-cap")
            independent.verify_export_bytes(raw, config=self.config.material())
            return raw
        except independent.IndependentAuthenticatedShadowAdmissionError:
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:export")

    @classmethod
    def restore_export(
        cls,
        destination: str | Path,
        raw: bytes,
        *,
        config: AuthenticatedShadowAdmissionConfigV1,
        acquisition_service: acquisition.AuthenticatedSourceAcquisitionService,
        runtime_service: runtime.ControlledShadowRuntimeService,
        runtime_database_id: str,
        authorization_verifier: runtime.ControlledShadowAuthorizationVerifier,
        clock: Callable[[], int],
        governance_policy: Mapping[str, object] | object,
        governance_raw: bytes,
        governance_evidence_raw: bytes,
        privacy_policy: Mapping[str, object] | object,
        privacy_raw: bytes,
        privacy_evidence_raw: bytes,
        fault_injector: Callable[[str], None] | None = None,
    ) -> "AuthenticatedShadowAdmissionService":
        try:
            verified = independent.verify_export_bytes(raw, config=config.material())
        except independent.IndependentAuthenticatedShadowAdmissionError:
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:restore-export")
        def build_stage(stage: Path) -> None:
            service = cls(stage, config=config, acquisition_service=acquisition_service, runtime_service=runtime_service, runtime_database_id=runtime_database_id, authorization_verifier=authorization_verifier, clock=clock, fault_injector=fault_injector)
            connection = service._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                for table in reversed(tuple(independent.TABLE_COLUMNS)):
                    connection.execute(f"DELETE FROM {table}")
                rows = verified["snapshot"]
                for table in independent.TABLE_COLUMNS:
                    for row in rows[table]:
                        columns = independent.TABLE_COLUMNS[table]
                        connection.execute(f"INSERT INTO {table}({','.join(columns)}) VALUES({','.join('?' for _ in columns)})", tuple(row[column] for column in columns))
                connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()
        def verify_database(path: Path) -> object:
            try:
                return independent.verify_database(path, config=config.material())
            except independent.IndependentAuthenticatedShadowAdmissionError:
                raise_redacted(AuthenticatedShadowAdmissionError, "admission:restore-database")
        def open_service(path: Path) -> "AuthenticatedShadowAdmissionService":
            service = cls(path, config=config, acquisition_service=acquisition_service, runtime_service=runtime_service, runtime_database_id=runtime_database_id, authorization_verifier=authorization_verifier, clock=clock)
            for candidate in verified["snapshot"]["admission_candidates"]:
                if candidate["state"] in {"QUALIFIED", "OPEN_PENDING", "OPENED", "START_PENDING", "STARTED", "PAUSE_PENDING"}:
                    service._current_for_row(candidate, governance_policy=governance_policy, governance_raw=governance_raw, governance_evidence_raw=governance_evidence_raw, privacy_policy=privacy_policy, privacy_raw=privacy_raw, privacy_evidence_raw=privacy_evidence_raw)
            return service
        try:
            return restore_publication.publish_create_only(destination, export_root=str(verified["export_root"]), expected_evidence=verified, build_stage=build_stage, verify_database=verify_database, open_service=open_service)
        except restore_publication.RestorePublicationConflict:
            raise_redacted(ShadowAdmissionConflictError, "admission:restore-conflict")
        except (restore_publication.RestorePublicationError, AuthenticatedShadowAdmissionError):
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:restore")
        except Exception:
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:restore")

    def support_snapshot(self) -> dict[str, object]:
        try:
            return independent.support_snapshot(self.database, config=self.config.material())
        except independent.IndependentAuthenticatedShadowAdmissionError:
            raise_redacted(AuthenticatedShadowAdmissionError, "admission:support")


def restore_export(*args: object, **kwargs: object) -> AuthenticatedShadowAdmissionService:
    return AuthenticatedShadowAdmissionService.restore_export(*args, **kwargs)  # type: ignore[arg-type]


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "EXPORT_SCHEMA", "EXPORT_VERSION", "STATES", "FIXED_FLAGS",
    "AuthenticatedShadowAdmissionError", "ShadowAdmissionConflictError", "ShadowAdmissionBusyError",
    "ShadowAdmissionResponseLost", "ShadowAdmissionInjectedFault", "ShadowAdmissionAuthorityError",
    "AuthenticatedShadowAdmissionConfigV1", "AuthenticatedShadowAdmissionService", "restore_export",
]
