"""Small configured source-admission port for the read-only Mirror wedge.

This module owns only composition and cross-boundary binding.  It deliberately
does not contain an adapter grammar, source semantics, synthetic fixtures, or
a default verifier.  A state composition root supplies an immutable profile
and a verifier implementation; the verifier returns a typed source result,
which is then checked by the existing Provider Trust Graph producer and its
independent artifact verifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping, Protocol

from app.mirror import provider_trust_graph as graph
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror import external_source_adapter_independent as external_independent
from app.mirror.error_boundary import raise_redacted


class SourceAdmissionError(ValueError):
    """Raised when configured source admission cannot produce one safe result."""


class EvidenceMode(str, Enum):
    """Evidence modes currently admitted by this nonproduction boundary."""

    SYNTHETIC_TEST_ONLY = "synthetic_test_only"
    OBSERVATION_ONLY = "observation_only"


@dataclass(frozen=True)
class SourceRole:
    """State-owned description of one ordered synthetic source role."""

    source_id: str
    source_kind: str
    record_kind: str
    authority_id: str
    provenance_id: str

    def __post_init__(self) -> None:
        if any(type(value) is not str or not value for value in (
            self.source_id,
            self.source_kind,
            self.record_kind,
            self.authority_id,
            self.provenance_id,
        )):
            raise ValueError("profile:source-role")
        if self.record_kind not in ("CREDENTIAL", "ENROLLMENT"):
            raise ValueError("profile:source-role-kind")

    def material(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "record_kind": self.record_kind,
            "authority_id": self.authority_id,
            "provenance_id": self.provenance_id,
        }


@dataclass(frozen=True)
class SourceProfile:
    """Immutable composition-root configuration for one source contract."""

    profile_id: str
    version: int
    subject: str
    scope: str
    observation_time: int | None
    effective_start: int
    effective_end: int
    source_roles: tuple[str, ...]
    require_complete: bool
    verifier_id: str
    verifier_epoch: int
    evidence_mode: EvidenceMode
    source_role_details: tuple[SourceRole, ...] | None = None
    credential_id: str | None = None
    enrollment_id: str | None = None
    observation_start: int | None = None
    observation_end: int | None = None
    allow_nonmembership: bool = True
    canonical_order: str = "lexicographic-v1"
    root_rule: str = "source-root-v1"
    source_contract_digest: str | None = None

    def __post_init__(self) -> None:
        if any(
            type(value) is not str or not value
            for value in (self.profile_id, self.subject, self.scope, self.verifier_id)
        ):
            raise ValueError("profile:identity")
        if type(self.version) is not int or self.version <= 0:
            raise ValueError("profile:version")
        if self.observation_time is not None and (type(self.observation_time) is not int or self.observation_time < 0):
            raise ValueError("profile:observation-time")
        if (
            type(self.effective_start) is not int
            or type(self.effective_end) is not int
            or self.effective_start >= self.effective_end
        ):
            raise ValueError("profile:interval")
        if (
            type(self.source_roles) is not tuple
            or not self.source_roles
            or any(type(role) is not str or not role for role in self.source_roles)
            or len(set(self.source_roles)) != len(self.source_roles)
        ):
            raise ValueError("profile:source-roles")
        if type(self.require_complete) is not bool:
            raise ValueError("profile:completeness")
        if type(self.verifier_epoch) is not int or self.verifier_epoch < 0:
            raise ValueError("profile:verifier")
        if self.evidence_mode not in (EvidenceMode.SYNTHETIC_TEST_ONLY, EvidenceMode.OBSERVATION_ONLY):
            raise ValueError("profile:evidence-mode-not-qualified")
        if type(self.allow_nonmembership) is not bool:
            raise ValueError("profile:nonmembership-policy")
        if self.canonical_order != "lexicographic-v1" or self.root_rule != "source-root-v1":
            raise ValueError("profile:canonical-rules")
        if self.source_contract_digest is not None:
            if (
                self.source_role_details is None
                or type(self.source_contract_digest) is not str
                or len(self.source_contract_digest) != 128
                or any(character not in "0123456789abcdef" for character in self.source_contract_digest)
            ):
                raise ValueError("profile:source-contract")
        if self.source_role_details is None:
            if self.observation_time is None:
                raise ValueError("profile:observation-window")
            if any(value is not None for value in (self.credential_id, self.enrollment_id, self.observation_start, self.observation_end)) or not self.allow_nonmembership:
                raise ValueError("profile:v1-extra")
            return
        if type(self.source_role_details) is not tuple or len(self.source_role_details) != 2:
            raise ValueError("profile:source-role-details")
        if self.version not in (2, 3):
            raise ValueError("profile:v2-version")
        if any(not isinstance(role, SourceRole) for role in self.source_role_details):
            raise ValueError("profile:source-role-details")
        role_ids = tuple(role.source_id for role in self.source_role_details)
        if role_ids != self.source_roles or role_ids != tuple(sorted(role_ids)) or len(set(role_ids)) != len(role_ids):
            raise ValueError("profile:source-role-order")
        if self.observation_time is not None:
            raise ValueError("profile:v2-snapshot-time")
        if any(type(value) is not str or not value for value in (self.credential_id, self.enrollment_id)):
            raise ValueError("profile:subject-identities")
        if (
            type(self.observation_start) is not int
            or type(self.observation_end) is not int
            or self.observation_start < 1
            or self.observation_start >= self.observation_end
        ):
            raise ValueError("profile:observation-window")
        if self.observation_start < self.effective_start or self.observation_end > self.effective_end:
            raise ValueError("profile:observation-window-interval")

    def material(self) -> dict[str, object]:
        if self.source_role_details is None:
            return {
                "profile_id": self.profile_id,
                "version": self.version,
                "subject": self.subject,
                "scope": self.scope,
                "observation_time": self.observation_time,
                "effective_start": self.effective_start,
                "effective_end": self.effective_end,
                "source_roles": list(self.source_roles),
                "require_complete": self.require_complete,
                "verifier_id": self.verifier_id,
                "verifier_epoch": self.verifier_epoch,
                "evidence_mode": self.evidence_mode.value,
            }
        material = {
            "profile_id": self.profile_id,
            "version": self.version,
            "subject": self.subject,
            "scope": self.scope,
            "observation_window": {"start": self.observation_start, "end": self.observation_end},
            "effective_start": self.effective_start,
            "effective_end": self.effective_end,
            "source_roles": [role.material() for role in self.source_role_details],
            "require_complete": self.require_complete,
            "credential_id": self.credential_id,
            "enrollment_id": self.enrollment_id,
            "verifier_id": self.verifier_id,
            "verifier_epoch": self.verifier_epoch,
            "evidence_mode": self.evidence_mode.value,
            "allow_nonmembership": self.allow_nonmembership,
            "canonical_order": self.canonical_order,
            "root_rule": self.root_rule,
        }
        if self.source_contract_digest is not None:
            material["source_contract_digest"] = self.source_contract_digest
        return material

    @property
    def profile_digest(self) -> str:
        return _digest("profile", self.material())


@dataclass(frozen=True)
class VerifiedSourceCoverage:
    """Typed output of the configured verifier, never a caller assertion."""

    profile_id: str
    subject: str
    scope: str
    observation_time: int
    effective_start: int
    effective_end: int
    complete: bool
    source_roles: tuple[str, ...]
    evidence_mode: EvidenceMode
    graph_input: bytes
    credential_id: str | None = None
    enrollment_id: str | None = None
    subject_locator_digest: str | None = None
    source_contract_digest: str | None = None
    fetched_at: int | None = None
    envelope_id: str | None = None
    snapshot_id: str | None = None
    snapshot_root: str | None = None
    page_digests: tuple[str, ...] = ()
    page_evidence: tuple[dict[str, object], ...] = ()
    graph_profile: SourceProfile | None = None
    source_status: str = "COMPLETE"
    freshness: str = "UNKNOWN"
    page_complete: bool = True
    page_count: int = 1
    resource_count: int = 0


class SourceVerifier(Protocol):
    """Narrow verifier port selected by the state composition root."""

    @property
    def identity(self) -> str:
        ...

    @property
    def epoch(self) -> int:
        ...

    def verify(self, adapter_bytes: bytes) -> VerifiedSourceCoverage:
        ...


@dataclass(frozen=True)
class SourceAdmission:
    """The one bound result passed to downstream Mirror consumers."""

    profile_id: str
    profile_digest: str
    verifier_id: str
    verifier_epoch: int
    graph_input: bytes
    graph_artifact: bytes
    receipt: bytes
    report_id: str
    production_source_authentication: bool
    telemetry: tuple[tuple[str, int | bool | str | None], ...]
    profile_version: int = 1
    source_contract_digest: str | None = None
    external_artifact_id: str | None = None
    external_artifact_digest: str | None = None
    capture_id: str | None = None
    capture_context_digest: str | None = None
    envelope_digest: str | None = None
    page_digests: tuple[str, ...] = ()
    observation: bytes = b""
    verification_receipt: bytes = b""


MAX_ADAPTER_BYTES = 262_144
MAX_RECEIPT_BYTES = 32_768
RECEIPT_SCHEMA = "mirror-source-admission-receipt-v1"
RECEIPT_SCHEMA_V2 = "mirror-source-admission-receipt-v2"
SANITIZED_OBSERVATION_SCHEMA = "mirror-source-observation-v1"
SANITIZED_OBSERVATION_VERSION = 1
SANITIZED_RECEIPT_SCHEMA = "mirror-source-verification-receipt-v1"
SANITIZED_OUTCOMES = (
    "CONTINUITY_CONFIRMED",
    "CREDENTIAL_EXPIRED",
    "ENROLLMENT_TERMINATED",
    "EVIDENCE_INCOMPLETE",
    "SOURCE_CONFLICT",
    "COVERAGE_STALE",
)


def _canonical(value: object) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise_redacted(SourceAdmissionError, "receipt:noncanonical")
    if len(raw) > MAX_RECEIPT_BYTES:
        raise SourceAdmissionError("receipt:byte-cap")
    return raw


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/SOURCE-ADMISSION/" + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/SOURCE-ADMISSION/" + label + "/v1\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _scoped_observation_digest(raw: bytes) -> str:
    """Bind the receipt to sanitized bytes without exposing source identity."""

    digest = hashlib.sha3_512()
    digest.update(b"BL/MIRROR/INGRESS/V5/sanitized-observation\0")
    digest.update(raw)
    return digest.hexdigest()


def _v2_profile(profile: SourceProfile) -> bool:
    return profile.source_role_details is not None


def _sanitized_values(
    artifact: Mapping[str, object],
    result: VerifiedSourceCoverage,
    profile: SourceProfile,
) -> tuple[dict[str, object], dict[str, object]]:
    """Derive the only bytes permitted to cross the acquisition port.

    This projection is intentionally aggregate-only.  It is built from the
    already independently verified graph artifact and never copies a source,
    record, subject, URL, capture, or digest field.
    """
    sources = artifact.get("source_coverage")
    findings = artifact.get("findings")
    discrepancies = artifact.get("discrepancies")
    if not isinstance(sources, list) or not isinstance(findings, list) or not isinstance(discrepancies, list):
        raise SourceAdmissionError("observation:shape")
    if len(findings) != 1 or not isinstance(findings[0], Mapping):
        raise SourceAdmissionError("observation:shape")
    outcome = findings[0].get("kind")
    if outcome not in SANITIZED_OUTCOMES:
        raise SourceAdmissionError("observation:outcome")
    complete_source_count = 0
    record_count = 0
    for source in sources:
        if not isinstance(source, Mapping):
            raise SourceAdmissionError("observation:shape")
        if source.get("coverage_complete") is True:
            complete_source_count += 1
        records = source.get("records")
        if not isinstance(records, list):
            raise SourceAdmissionError("observation:shape")
        record_count += len(records)
    if len(sources) != 2:
        raise SourceAdmissionError("observation:source-count")
    if len(discrepancies) > 1:
        raise SourceAdmissionError("observation:discrepancy-count")
    observation_time = result.observation_time
    if type(observation_time) is not int or observation_time < 1:
        raise SourceAdmissionError("observation:time")
    source_status = result.source_status
    freshness = result.freshness
    page_complete = result.page_complete
    page_count = result.page_count
    resource_count = result.resource_count
    if source_status not in ("COMPLETE", "FAILED") or freshness not in ("FRESH", "UNKNOWN", "STALE"):
        raise SourceAdmissionError("observation:source-status")
    if type(page_complete) is not bool or type(page_count) is not int or not 1 <= page_count <= 4:
        raise SourceAdmissionError("observation:pages")
    if type(resource_count) is not int or not 0 <= resource_count <= 4096:
        raise SourceAdmissionError("observation:resources")
    if outcome == "SOURCE_CONFLICT" and len(discrepancies) != 1:
        raise SourceAdmissionError("observation:discrepancy-count")
    if outcome != "SOURCE_CONFLICT" and discrepancies:
        raise SourceAdmissionError("observation:discrepancy-count")
    observation = {
        "schema": SANITIZED_OBSERVATION_SCHEMA,
        "schema_version": SANITIZED_OBSERVATION_VERSION,
        "profile_id": profile.profile_id,
        "profile_version": profile.version,
        "observation_time": observation_time,
        "effective_start": profile.effective_start,
        "effective_end": profile.effective_end,
        "source_count": len(sources),
        "complete_source_count": complete_source_count,
        "record_count": record_count,
        "finding_count": len(findings),
        "discrepancy_count": len(discrepancies),
        "outcome": outcome,
        "source_status": source_status,
        "freshness": freshness,
        "page_complete": page_complete,
        "page_count": page_count,
        "resource_count": resource_count,
        "synthetic_only": True,
        "production_usable": False,
        "activation": False,
        "proofSuiteId": None,
    }
    observation_raw = _canonical(observation)
    receipt = {
        "schema": SANITIZED_RECEIPT_SCHEMA,
        "schema_version": 1,
        "profile_id": profile.profile_id,
        "profile_version": profile.version,
        "verifier_id": profile.verifier_id,
        "verifier_epoch": profile.verifier_epoch,
        "evidence_mode": profile.evidence_mode.value,
        "verification_status": "VERIFIED_AT_TIME",
        "outcome": outcome,
        "observation_digest": _scoped_observation_digest(observation_raw),
        "issued_at": result.fetched_at if type(result.fetched_at) is int else observation_time,
        "synthetic_only": True,
        "production_usable": False,
        "activation": False,
        "proofSuiteId": None,
    }
    return observation, receipt


class SourceAdmissionService:
    """Compose one immutable profile with one configured verifier."""

    def __init__(self, profile: SourceProfile, verifier: SourceVerifier) -> None:
        if not isinstance(profile, SourceProfile):
            raise SourceAdmissionError("composition:profile")
        try:
            identity = verifier.identity
            epoch = verifier.epoch
        except Exception:
            raise_redacted(SourceAdmissionError, "composition:verifier")
        if identity != profile.verifier_id or epoch != profile.verifier_epoch:
            raise SourceAdmissionError("composition:verifier-mismatch")
        if profile.evidence_mode not in (EvidenceMode.SYNTHETIC_TEST_ONLY, EvidenceMode.OBSERVATION_ONLY):
            raise SourceAdmissionError("composition:production-mode-unavailable")
        self.profile = profile
        self._verifier = verifier
        self._identity = identity
        self._epoch = epoch

    def _verify(self, adapter_bytes: bytes) -> VerifiedSourceCoverage:
        try:
            identity = self._verifier.identity
            epoch = self._verifier.epoch
        except Exception:
            raise_redacted(SourceAdmissionError, "verifier:configuration-changed")
        if identity != self._identity or epoch != self._epoch:
            raise SourceAdmissionError("verifier:configuration-changed")
        try:
            result = self._verifier.verify(adapter_bytes)
        except Exception:
            raise_redacted(SourceAdmissionError, "verifier:reject")
        if not isinstance(result, VerifiedSourceCoverage):
            raise SourceAdmissionError("verifier:malformed-result")
        return result

    def _validate_result(self, result: VerifiedSourceCoverage) -> None:
        if _v2_profile(self.profile):
            if not isinstance(result.graph_profile, SourceProfile) or result.graph_profile != self.profile:
                raise_redacted(SourceAdmissionError, "result:profile-mismatch")
            profile = result.graph_profile
        else:
            if result.graph_profile is not None and result.graph_profile != self.profile:
                raise_redacted(SourceAdmissionError, "result:profile-mismatch")
            profile = result.graph_profile or self.profile
        if not isinstance(profile, SourceProfile) or profile.source_contract_digest != self.profile.source_contract_digest:
            raise_redacted(SourceAdmissionError, "result:profile-mismatch")
        if type(result.profile_id) is not str or result.profile_id != profile.profile_id:
            raise SourceAdmissionError("result:profile-mismatch")
        if (
            type(result.subject) is not str
            or result.subject != profile.subject
            or type(result.scope) is not str
            or result.scope != profile.scope
        ):
            raise SourceAdmissionError("result:subject-or-scope-mismatch")
        if type(result.observation_time) is not int:
            raise SourceAdmissionError("result:observation-mismatch")
        if _v2_profile(profile):
            assert profile.observation_start is not None and profile.observation_end is not None
            # A V2 dynamic capture owns its own observation context. The
            # configured profile only supplies the source contract interval.
            if result.source_contract_digest is None and not profile.observation_start <= result.observation_time < profile.observation_end:
                raise SourceAdmissionError("result:observation-mismatch")
        elif result.observation_time != profile.observation_time:
            raise SourceAdmissionError("result:observation-mismatch")
        if (
            type(result.effective_start) is not int
            or type(result.effective_end) is not int
            or (result.effective_start, result.effective_end) != (profile.effective_start, profile.effective_end)
        ):
            raise SourceAdmissionError("result:interval-mismatch")
        if type(result.complete) is not bool:
            raise SourceAdmissionError("result:completeness")
        if profile.require_complete and result.complete is not True:
            raise SourceAdmissionError("result:partial-coverage")
        if type(result.source_roles) is not tuple or result.source_roles != profile.source_roles:
            raise SourceAdmissionError("result:source-roles-mismatch")
        if type(result.evidence_mode) is not EvidenceMode or result.evidence_mode is not profile.evidence_mode:
            raise SourceAdmissionError("result:evidence-mode-mismatch")
        if type(result.graph_input) is not bytes or not result.graph_input or len(result.graph_input) > graph.MAX_INPUT_BYTES:
            raise SourceAdmissionError("result:graph-input")
        if result.source_contract_digest is not None and result.source_contract_digest != profile.source_contract_digest:
            raise SourceAdmissionError("result:source-contract-mismatch")

    def _validate_graph_coverage(self, artifact: dict[str, object], profile: SourceProfile) -> None:
        subject = artifact.get("subject")
        if subject != {"provider_graph_subject": profile.subject, "scope": profile.scope}:
            raise SourceAdmissionError("graph:profile-mismatch")
        sources = artifact.get("source_coverage")
        if not isinstance(sources, list) or [source.get("source_id") for source in sources if isinstance(source, dict)] != list(profile.source_roles):
            raise SourceAdmissionError("graph:source-roles-mismatch")
        for source in sources:
            if not isinstance(source, dict):
                raise SourceAdmissionError("graph:source-shape")
            if profile.require_complete and source.get("coverage_complete") is not True:
                raise SourceAdmissionError("graph:partial-coverage")
            if not isinstance(source.get("coverage_observation_time"), int):
                raise SourceAdmissionError("graph:observation-mismatch")
            if _v2_profile(profile):
                assert profile.observation_start is not None and profile.observation_end is not None
                if not profile.observation_start <= source["coverage_observation_time"] < profile.observation_end:
                    raise SourceAdmissionError("graph:observation-mismatch")
            elif source.get("coverage_observation_time") != profile.observation_time:
                raise SourceAdmissionError("graph:observation-mismatch")
            start = source.get("coverage_effective_start")
            end = source.get("coverage_effective_end")
            observation = source["coverage_observation_time"]
            if not isinstance(start, int) or not isinstance(end, int) or not start <= observation < end:
                raise SourceAdmissionError("graph:stale-coverage")
            if (start, end) != (profile.effective_start, profile.effective_end):
                raise SourceAdmissionError("graph:interval-mismatch")

    def admit(self, adapter_bytes: bytes, *, external_evidence_raw: bytes | None = None, external_policy: Mapping[str, object] | None = None, expected_receipt: bytes | None = None) -> SourceAdmission:
        """Verify one exact envelope/evidence pair and bind one graph receipt."""

        if type(adapter_bytes) is not bytes or not adapter_bytes:
            raise SourceAdmissionError("adapter:bytes")
        if len(adapter_bytes) > MAX_ADAPTER_BYTES:
            raise SourceAdmissionError("adapter:byte-cap")
        result = self._verify(adapter_bytes)
        self._validate_result(result)
        if external_evidence_raw is not None or external_policy is not None:
            if type(external_evidence_raw) is not bytes or not external_evidence_raw or not isinstance(external_policy, Mapping):
                raise SourceAdmissionError("external:evidence")
            try:
                external = external_independent.verify_bytes(external_evidence_raw, policy=external_policy, capture_raw=adapter_bytes)
            except Exception:
                raise_redacted(SourceAdmissionError, "external:evidence-reject")
            if external.get("derived_status") != "OBSERVATION_ADMITTED":
                raise SourceAdmissionError("external:not-admitted")
            if external.get("source_contract_digest") != result.source_contract_digest:
                raise SourceAdmissionError("external:contract-binding")
            context = result
            for key in ("subject_id", "credential_id", "enrollment_id", "subject_locator_digest"):
                actual = context.subject if key == "subject_id" else getattr(context, key, None)
                if actual != external.get(key):
                    raise SourceAdmissionError("external:context-binding")
            if result.observation_time != external.get("observed_at") or result.fetched_at != external.get("fetched_at") or tuple(result.page_digests) != tuple(digest for _, digest in external.get("page_bindings", ())):
                raise SourceAdmissionError("external:capture-binding")
        else:
            external = None
        effective_profile = result.graph_profile or self.profile
        try:
            if _v2_profile(effective_profile):
                graph_artifact, graph_telemetry = graph.build_report(result.graph_input, profile=effective_profile)
            else:
                graph_artifact, graph_telemetry = graph.build_report(result.graph_input)
        except Exception:
            raise_redacted(SourceAdmissionError, "graph:producer-reject")
        try:
            if _v2_profile(effective_profile):
                independent = graph_independent.verify_bytes_v2(
                    graph_artifact,
                    {effective_profile.profile_id: effective_profile},
                )
            else:
                independent = graph_independent.verify_bytes(graph_artifact)
        except Exception:
            raise_redacted(SourceAdmissionError, "graph:independent-reject")
        if independent.get("accepted") is not True:
            raise SourceAdmissionError("graph:independent-reject")
        try:
            artifact = graph.parse_canonical(graph_artifact, artifact=True)
        except Exception:
            raise_redacted(SourceAdmissionError, "graph:artifact-shape")
        self._validate_graph_coverage(artifact, effective_profile)
        report_id = independent.get("report_id")
        if not isinstance(report_id, str):
            raise SourceAdmissionError("graph:report-id")
        graph_input_digest = _raw_digest("graph-input", result.graph_input)
        graph_artifact_digest = _raw_digest("graph-artifact", graph_artifact)
        source_result_digest = _digest(
            "source-result",
            {
                "profile_id": result.profile_id,
                "subject": result.subject,
                "scope": result.scope,
                "observation_time": result.observation_time,
                "effective_start": result.effective_start,
                "effective_end": result.effective_end,
                "complete": result.complete,
                "source_roles": list(result.source_roles),
                "evidence_mode": result.evidence_mode.value,
                "graph_input_digest": graph_input_digest,
                "source_contract_digest": result.source_contract_digest,
                "envelope_id": result.envelope_id,
                "page_digests": list(result.page_digests),
            },
        )
        body: dict[str, object] = {
            "schema": RECEIPT_SCHEMA_V2 if _v2_profile(effective_profile) else RECEIPT_SCHEMA,
            "profile_id": effective_profile.profile_id,
            "profile_version": effective_profile.version,
            "profile_digest": effective_profile.profile_digest,
            "verifier_id": effective_profile.verifier_id,
            "verifier_epoch": effective_profile.verifier_epoch,
            "evidence_mode": effective_profile.evidence_mode.value,
            "adapter_digest": _raw_digest("adapter", adapter_bytes),
            "source_result_digest": source_result_digest,
            "graph_input_digest": graph_input_digest,
            "graph_artifact_digest": graph_artifact_digest,
            "graph_report_id": report_id,
            "production_source_authentication": False,
        }
        if external is not None:
            body.update({
                "external_artifact_id": external["artifact_id"],
                "external_artifact_digest": _raw_digest("external-artifact", external_evidence_raw),
                "capture_id": external["capture_id"],
                "capture_context_digest": _digest("capture-context", {key: external[key] for key in ("subject_id", "credential_id", "enrollment_id", "subject_locator_digest", "observed_at", "fetched_at")} ),
                "external_policy_digest": external["policy_digest"],
            })
        source_receipt_value = {"receipt_id": _digest("receipt-id", body), **body}
        source_receipt = _canonical(source_receipt_value)
        observation_value, verification_receipt_value = _sanitized_values(artifact, result, effective_profile)
        observation = _canonical(observation_value)
        verification_receipt = _canonical(verification_receipt_value)
        if expected_receipt is not None and (type(expected_receipt) is not bytes or expected_receipt != source_receipt):
            raise SourceAdmissionError("retry:conflict")
        telemetry = tuple(
            (key, graph_telemetry[key])
            for key in (
                "artifact_bytes",
                "wall_time_ns",
                "process_tree_peak_bytes",
                "process_tree_scope",
                "proof_performance_claim",
            )
        )
        return SourceAdmission(
            profile_id=effective_profile.profile_id,
            profile_digest=effective_profile.profile_digest,
            verifier_id=effective_profile.verifier_id,
            verifier_epoch=effective_profile.verifier_epoch,
            graph_input=result.graph_input,
            graph_artifact=graph_artifact,
            receipt=source_receipt,
            report_id=report_id,
            production_source_authentication=False,
            telemetry=telemetry,
            profile_version=effective_profile.version,
            source_contract_digest=result.source_contract_digest,
            external_artifact_id=external.get("artifact_id") if external is not None else None,
            external_artifact_digest=_raw_digest("external-artifact", external_evidence_raw) if external is not None and isinstance(external_evidence_raw, bytes) else None,
            capture_id=external.get("capture_id") if external is not None else None,
            capture_context_digest=body.get("capture_context_digest"),
            envelope_digest=_raw_digest("envelope", adapter_bytes),
            page_digests=tuple(result.page_digests),
            observation=observation,
            verification_receipt=verification_receipt,
        )

__all__ = [
    "EvidenceMode",
    "SourceAdmission",
    "SourceAdmissionError",
    "SourceAdmissionService",
    "SourceProfile",
    "SourceRole",
    "SourceVerifier",
    "VerifiedSourceCoverage",
]
