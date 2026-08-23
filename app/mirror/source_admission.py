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
from typing import Protocol

from app.mirror import provider_trust_graph as graph
from app.mirror import provider_trust_graph_independent as graph_independent
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
        if self.version != 2:
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


MAX_ADAPTER_BYTES = 262_144
MAX_RECEIPT_BYTES = 32_768
RECEIPT_SCHEMA = "mirror-source-admission-receipt-v1"
RECEIPT_SCHEMA_V2 = "mirror-source-admission-receipt-v2"


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


def _v2_profile(profile: SourceProfile) -> bool:
    return profile.source_role_details is not None


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
        profile = self.profile
        if type(result.profile_id) is not str or result.profile_id != profile.profile_id:
            raise SourceAdmissionError("result:profile-mismatch")
        if (
            type(result.subject) is not str
            or type(result.scope) is not str
            or result.subject != profile.subject
            or result.scope != profile.scope
        ):
            raise SourceAdmissionError("result:subject-or-scope-mismatch")
        if type(result.observation_time) is not int:
            raise SourceAdmissionError("result:observation-mismatch")
        if _v2_profile(profile):
            assert profile.observation_start is not None and profile.observation_end is not None
            if not profile.observation_start <= result.observation_time < profile.observation_end:
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

    def _validate_graph_coverage(self, artifact: dict[str, object]) -> None:
        profile = self.profile
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

    def admit(self, adapter_bytes: bytes, *, expected_receipt: bytes | None = None) -> SourceAdmission:
        """Verify one adapter payload, build one graph, and bind its receipt."""

        if type(adapter_bytes) is not bytes or not adapter_bytes:
            raise SourceAdmissionError("adapter:bytes")
        if len(adapter_bytes) > MAX_ADAPTER_BYTES:
            raise SourceAdmissionError("adapter:byte-cap")
        result = self._verify(adapter_bytes)
        self._validate_result(result)
        try:
            if _v2_profile(self.profile):
                graph_artifact, graph_telemetry = graph.build_report(result.graph_input, profile=self.profile)
            else:
                graph_artifact, graph_telemetry = graph.build_report(result.graph_input)
        except Exception:
            raise_redacted(SourceAdmissionError, "graph:producer-reject")
        try:
            if _v2_profile(self.profile):
                independent = graph_independent.verify_bytes_v2(
                    graph_artifact,
                    {self.profile.profile_id: self.profile},
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
        self._validate_graph_coverage(artifact)
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
            },
        )
        body: dict[str, object] = {
            "schema": RECEIPT_SCHEMA_V2 if _v2_profile(self.profile) else RECEIPT_SCHEMA,
            "profile_id": self.profile.profile_id,
            "profile_version": self.profile.version,
            "profile_digest": self.profile.profile_digest,
            "verifier_id": self._identity,
            "verifier_epoch": self._epoch,
            "evidence_mode": self.profile.evidence_mode.value,
            "adapter_digest": _raw_digest("adapter", adapter_bytes),
            "source_result_digest": source_result_digest,
            "graph_input_digest": graph_input_digest,
            "graph_artifact_digest": graph_artifact_digest,
            "graph_report_id": report_id,
            "production_source_authentication": False,
        }
        receipt_value = {"receipt_id": _digest("receipt-id", body), **body}
        receipt = _canonical(receipt_value)
        if expected_receipt is not None and (type(expected_receipt) is not bytes or expected_receipt != receipt):
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
            profile_id=self.profile.profile_id,
            profile_digest=self.profile.profile_digest,
            verifier_id=self._identity,
            verifier_epoch=self._epoch,
            graph_input=result.graph_input,
            graph_artifact=graph_artifact,
            receipt=receipt,
            report_id=report_id,
            production_source_authentication=False,
            telemetry=telemetry,
            profile_version=self.profile.version,
        )


@dataclass(frozen=True)
class SourceAdmissionBinding:
    """One immutable profile/verifier pair owned by a composition root."""

    profile: SourceProfile
    verifier: SourceVerifier


class MultiSubjectSourceAdmissionService:
    """Select exactly one configured synthetic profile by verifier acceptance."""

    def __init__(self, bindings: tuple[SourceAdmissionBinding, ...]) -> None:
        if type(bindings) is not tuple or not bindings:
            raise SourceAdmissionError("composition:bindings")
        services: list[SourceAdmissionService] = []
        profile_ids: set[str] = set()
        for binding in bindings:
            if not isinstance(binding, SourceAdmissionBinding) or binding.profile.source_role_details is None:
                raise SourceAdmissionError("composition:v2-profile-required")
            if binding.profile.profile_id in profile_ids:
                raise SourceAdmissionError("composition:duplicate-profile")
            profile_ids.add(binding.profile.profile_id)
            services.append(SourceAdmissionService(binding.profile, binding.verifier))
        self._services = tuple(services)
        self.profiles = tuple(service.profile for service in services)

    def admit(self, adapter_bytes: bytes, *, expected_receipt: bytes | None = None) -> SourceAdmission:
        accepted: list[SourceAdmission] = []
        for service in self._services:
            try:
                accepted.append(service.admit(adapter_bytes))
            except SourceAdmissionError:
                continue
        if len(accepted) != 1:
            if len(accepted) > 1:
                raise SourceAdmissionError("admission:ambiguous-profile")
            raise SourceAdmissionError("admission:no-profile")
        result = accepted[0]
        if expected_receipt is not None and expected_receipt != result.receipt:
            raise SourceAdmissionError("retry:conflict")
        return result


__all__ = [
    "EvidenceMode",
    "SourceAdmission",
    "SourceAdmissionError",
    "SourceAdmissionService",
    "SourceAdmissionBinding",
    "MultiSubjectSourceAdmissionService",
    "SourceProfile",
    "SourceRole",
    "SourceVerifier",
    "VerifiedSourceCoverage",
]
