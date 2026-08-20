"""State-side custody composition for the synthetic NC Medicaid FHIR boundary.

This is a composition root, not another source parser.  The existing
independent FHIR verifier owns envelope admissibility; the existing graph
admission service owns graph construction; ContinuityStore owns the atomic
durable write.  The raw canonical envelope is retained as a state-owned,
content-bearing custody artifact so retry and restore can be checked without a
second database.  Support output never serializes this artifact.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Mapping

from app.mirror import continuity_store as store
from app.mirror import nc_medicaid_fhir_independent as fhir
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import source_evidence_custody_independent as independent
from app.mirror.source_admission import SourceAdmissionError, SourceAdmissionService


class SourceEvidenceCustodyError(ValueError):
    """A bounded source-custody composition or admission failure."""


@dataclass(frozen=True)
class SourceCustodyBuild:
    raw: bytes
    envelope_digest: str
    source_status: str
    graph_linked: bool


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SourceEvidenceCustodyError("custody:noncanonical") from exc


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


def _profile_binding() -> dict[str, object]:
    source = profile.NC_MEDICAID_PROFILE
    graph_profile = source.graph_profile
    return {
        **source.binding(),
        "graph_profile_id": graph_profile.profile_id,
        "graph_profile_version": graph_profile.version,
        "evidence_mode": graph_profile.evidence_mode.value,
        "source_completeness": source.completeness,
        "allow_nonmembership": source.allow_nonmembership,
        "live_transport_authorized": source.live_transport_authorized,
        "synthetic_only": source.synthetic_only,
        "production_usable": source.production_usable,
    }


def _flags() -> dict[str, object]:
    return dict(independent.FIXED_FLAGS)


def build_artifact(
    envelope_raw: bytes,
    result: Mapping[str, object],
    *,
    prior_artifact_id: str | None = None,
    prior_stage_id: str | None = None,
    admission: object | None = None,
) -> SourceCustodyBuild:
    """Build one canonical custody artifact from an independently checked result.

    The result is intentionally treated as a candidate here.  The store calls
    the independent verifier again before any durable mutation.
    """

    if type(envelope_raw) is not bytes or not envelope_raw or len(envelope_raw) > independent.MAX_ENVELOPE_BYTES:
        raise SourceEvidenceCustodyError("custody:envelope-byte-cap")
    if not isinstance(result, Mapping) or result.get("accepted") is not True:
        raise SourceEvidenceCustodyError("custody:verification-required")
    source = profile.NC_MEDICAID_PROFILE
    graph_profile = source.graph_profile
    verification = independent.build_verification_receipt(envelope_raw, result)
    graph_link: dict[str, object] | None = None
    if admission is not None:
        try:
            graph_raw = admission.graph_artifact
            admission_raw = admission.receipt
            report_id = admission.report_id
        except AttributeError as exc:
            raise SourceEvidenceCustodyError("custody:admission-shape") from exc
        if type(graph_raw) is not bytes or not graph_raw or type(admission_raw) is not bytes or not admission_raw or type(report_id) is not str or not report_id:
            raise SourceEvidenceCustodyError("custody:admission-shape")
        graph_link = {
            "artifact_id": report_id,
            "payload_hash": independent.storage_payload_hash(graph_raw),
            "graph_artifact_digest": independent.admission_raw_digest("graph-artifact", graph_raw),
            "report_id": report_id,
            "admission_receipt_hex": admission_raw.hex(),
        }
    body: dict[str, object] = {
        "schema": independent.SCHEMA,
        "schema_version": independent.SCHEMA_VERSION,
        "profile_binding": _profile_binding(),
        "subject": graph_profile.subject,
        "scope": graph_profile.scope,
        "prior_artifact_id": prior_artifact_id,
        "prior_stage_id": prior_stage_id,
        "stage_kind": independent.STAGE_KIND,
        "source_status": result["source_status"],
        "failure_code": result["failure_code"],
        "freshness": result["freshness"],
        "observation_time": result["observation_time"],
        "fetched_at": result["fetched_at"],
        "page_complete": result["page_complete"],
        "server_markers": {"total": result["server_total"], "last_updated": result["server_last_updated"]},
        "snapshot_id": result["snapshot_id"],
        "snapshot_root": result["snapshot_root"],
        "page_count": result["page_count"],
        "resource_count": result["resource_count"],
        "source_completeness": source.completeness,
        "allow_nonmembership": source.allow_nonmembership,
        "verification_receipt": verification,
        "envelope": {
            "encoding": "canonical-json-ascii-hex",
            "byte_length": len(envelope_raw),
            "bytes_hex": envelope_raw.hex(),
        },
        "envelope_digest": _raw_digest("envelope", envelope_raw),
        "graph_link": graph_link,
        "flags": _flags(),
        "authority": dict(independent.AUTHORITY_FLAGS),
        "custody_policy": dict(independent.CUSTODY_POLICY),
    }
    artifact_id = _digest("artifact-id", body)
    stage_id = _digest(
        "stage-id",
        {
            "artifact_id": artifact_id,
            "envelope_digest": body["envelope_digest"],
            "source_status": body["source_status"],
            "prior_artifact_id": prior_artifact_id,
            "prior_stage_id": prior_stage_id,
        },
    )
    transition_id = _digest(
        "transition-id",
        {
            "artifact_id": artifact_id,
            "current_stage_id": stage_id,
            "prior_artifact_id": prior_artifact_id,
            "prior_stage_id": prior_stage_id,
        },
    )
    value = {
        **body,
        "artifact_id": artifact_id,
        "current_stage_id": stage_id,
        "transition_id": transition_id,
    }
    raw = _canonical(value)
    if len(raw) > independent.MAX_ARTIFACT_BYTES:
        raise SourceEvidenceCustodyError("custody:artifact-byte-cap")
    return SourceCustodyBuild(
        raw=raw,
        envelope_digest=str(body["envelope_digest"]),
        source_status=str(body["source_status"]),
        graph_linked=graph_link is not None,
    )


class SourceEvidenceCustodyService:
    """Configured NC fixture custody service with no live transport path."""

    def __init__(
        self,
        continuity_store: store.ContinuityStore,
        *,
        source_profile: profile.NcMedicaidFhirSourceProfile = profile.NC_MEDICAID_PROFILE,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> None:
        if not isinstance(continuity_store, store.ContinuityStore):
            raise SourceEvidenceCustodyError("composition:store")
        if source_profile != profile.NC_MEDICAID_PROFILE:
            raise SourceEvidenceCustodyError("composition:profile")
        registry = dict(graph_profile_registry or profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
        if registry != dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY):
            raise SourceEvidenceCustodyError("composition:registry")
        self.store = continuity_store
        self.profile = source_profile
        self.graph_profile_registry = registry

    def ingest(self, envelope_raw: bytes, *, fixed_envelope_digest: str | None = None):
        """Verify, compose, and atomically custody one synthetic envelope."""

        if type(envelope_raw) is not bytes or not envelope_raw:
            raise SourceEvidenceCustodyError("custody:envelope-bytes")
        if len(envelope_raw) > independent.MAX_ENVELOPE_BYTES:
            raise SourceEvidenceCustodyError("custody:envelope-byte-cap")
        if fixed_envelope_digest is None:
            existing = self.store.find_source_evidence(envelope_raw, self.graph_profile_registry)
            if existing is not None:
                return existing
        elif type(fixed_envelope_digest) is not str or fixed_envelope_digest != _raw_digest("envelope", envelope_raw):
            raise SourceEvidenceCustodyError("custody:fixed-envelope-binding")
        try:
            result = fhir.verify_bytes(envelope_raw, profile=self.profile)
        except Exception as exc:
            raise SourceEvidenceCustodyError("custody:envelope-reject") from exc
        admission = None
        if result["source_status"] == "COMPLETE" and result["freshness"] in {"FRESH", "UNKNOWN"}:
            try:
                admission = SourceAdmissionService(
                    self.profile.graph_profile,
                    fhir.NcMedicaidFhirVerifier(self.profile),
                ).admit(envelope_raw)
            except SourceAdmissionError as exc:
                raise SourceEvidenceCustodyError(f"custody:graph-admission:{exc}") from exc
        prior = None
        if fixed_envelope_digest is None:
            prior = self.store.source_evidence_head(
                self.profile.graph_profile.subject,
                self.profile.graph_profile.scope,
                self.profile.graph_profile.profile_id,
                self.graph_profile_registry,
            )
        candidate = build_artifact(
            envelope_raw,
            result,
            prior_artifact_id=prior[0] if prior else None,
            prior_stage_id=prior[1] if prior else None,
            admission=admission,
        )
        if admission is None:
            return self.store.admit_source_evidence(
                candidate.raw,
                None,
                self.graph_profile_registry,
                fixed_envelope_digest=fixed_envelope_digest,
            )
        # The store performs the governance check and any observation-only
        # retention in one transaction.  Only its typed, independently
        # reconstructable not-approved/withdrawn outcome can select fallback.
        fallback = build_artifact(
            envelope_raw,
            result,
            prior_artifact_id=prior[0] if prior else None,
            prior_stage_id=prior[1] if prior else None,
            admission=None,
        )
        return self.store.admit_source_evidence_with_governance_observation(
            candidate.raw,
            admission.graph_artifact,
            fallback.raw,
            self.graph_profile_registry,
            fixed_envelope_digest=fixed_envelope_digest,
        )


__all__ = [
    "SourceCustodyBuild",
    "SourceEvidenceCustodyError",
    "SourceEvidenceCustodyService",
    "build_artifact",
]
