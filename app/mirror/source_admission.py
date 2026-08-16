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


class SourceAdmissionError(ValueError):
    """Raised when configured source admission cannot produce one safe result."""


class EvidenceMode(str, Enum):
    """Evidence modes currently admitted by this nonproduction boundary."""

    SYNTHETIC_TEST_ONLY = "synthetic_test_only"


@dataclass(frozen=True)
class SourceProfile:
    """Immutable composition-root configuration for one source contract."""

    profile_id: str
    version: int
    subject: str
    scope: str
    observation_time: int
    effective_start: int
    effective_end: int
    source_roles: tuple[str, ...]
    require_complete: bool
    verifier_id: str
    verifier_epoch: int
    evidence_mode: EvidenceMode

    def __post_init__(self) -> None:
        if any(
            type(value) is not str or not value
            for value in (self.profile_id, self.subject, self.scope, self.verifier_id)
        ):
            raise ValueError("profile:identity")
        if type(self.version) is not int or self.version <= 0:
            raise ValueError("profile:version")
        if type(self.observation_time) is not int or self.observation_time < 0:
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
        if self.evidence_mode is not EvidenceMode.SYNTHETIC_TEST_ONLY:
            raise ValueError("profile:evidence-mode-not-qualified")

    def material(self) -> dict[str, object]:
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


MAX_ADAPTER_BYTES = 262_144
MAX_RECEIPT_BYTES = 32_768
RECEIPT_SCHEMA = "mirror-source-admission-receipt-v1"


def _canonical(value: object) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SourceAdmissionError("receipt:noncanonical") from exc
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


class SourceAdmissionService:
    """Compose one immutable profile with one configured verifier."""

    def __init__(self, profile: SourceProfile, verifier: SourceVerifier) -> None:
        if not isinstance(profile, SourceProfile):
            raise SourceAdmissionError("composition:profile")
        try:
            identity = verifier.identity
            epoch = verifier.epoch
        except Exception as exc:
            raise SourceAdmissionError("composition:verifier") from exc
        if identity != profile.verifier_id or epoch != profile.verifier_epoch:
            raise SourceAdmissionError("composition:verifier-mismatch")
        if profile.evidence_mode is not EvidenceMode.SYNTHETIC_TEST_ONLY:
            raise SourceAdmissionError("composition:production-mode-unavailable")
        self.profile = profile
        self._verifier = verifier
        self._identity = identity
        self._epoch = epoch

    def _verify(self, adapter_bytes: bytes) -> VerifiedSourceCoverage:
        try:
            if self._verifier.identity != self._identity or self._verifier.epoch != self._epoch:
                raise SourceAdmissionError("verifier:configuration-changed")
            result = self._verifier.verify(adapter_bytes)
        except SourceAdmissionError:
            raise
        except Exception as exc:
            raise SourceAdmissionError("verifier:reject") from exc
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
        if type(result.observation_time) is not int or result.observation_time != profile.observation_time:
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
            if source.get("coverage_observation_time") != profile.observation_time:
                raise SourceAdmissionError("graph:observation-mismatch")
            start = source.get("coverage_effective_start")
            end = source.get("coverage_effective_end")
            if not isinstance(start, int) or not isinstance(end, int) or not start <= profile.observation_time < end:
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
            graph_artifact, graph_telemetry = graph.build_report(result.graph_input)
        except Exception as exc:
            raise SourceAdmissionError("graph:producer-reject") from exc
        try:
            independent = graph_independent.verify_bytes(graph_artifact)
        except Exception as exc:
            raise SourceAdmissionError("graph:independent-reject") from exc
        if independent.get("accepted") is not True:
            raise SourceAdmissionError("graph:independent-reject")
        try:
            artifact = graph.parse_canonical(graph_artifact, artifact=True)
        except Exception as exc:
            raise SourceAdmissionError("graph:artifact-shape") from exc
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
            "schema": RECEIPT_SCHEMA,
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
        )


__all__ = [
    "EvidenceMode",
    "SourceAdmission",
    "SourceAdmissionError",
    "SourceAdmissionService",
    "SourceProfile",
    "SourceVerifier",
    "VerifiedSourceCoverage",
]
