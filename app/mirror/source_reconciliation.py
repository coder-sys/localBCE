"""Composition root for the synthetic state-side temporal reconciliation seam."""

from __future__ import annotations

from typing import Mapping

from app.mirror import continuity_store as store
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import source_reconciliation_independent as independent


class SourceReconciliationError(ValueError):
    """Stable producer/composition failure."""


def _prior_identity(raw: bytes | None) -> tuple[str | None, str | None]:
    if raw is None:
        return None, None
    try:
        value = independent._parse(raw)
        artifact_id = value["artifact_id"]
        stage_id = value["current_stage_id"]
        if not isinstance(artifact_id, str) or not isinstance(stage_id, str):
            raise SourceReconciliationError("reconciliation:prior-identity")
        return artifact_id, stage_id
    except SourceReconciliationError:
        raise
    except Exception as exc:
        raise SourceReconciliationError("reconciliation:prior-identity") from exc


class SourceReconciliationService:
    """Configured service; the store owns predecessor and head selection."""

    def __init__(
        self,
        continuity_store: store.ContinuityStore,
        *,
        source_profile: profile.NcMedicaidFhirSourceProfile = profile.NC_MEDICAID_PROFILE,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> None:
        if not isinstance(continuity_store, store.ContinuityStore):
            raise SourceReconciliationError("composition:store")
        if source_profile != profile.NC_MEDICAID_PROFILE:
            raise SourceReconciliationError("composition:profile")
        registry = dict(graph_profile_registry or profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
        if registry != dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY):
            raise SourceReconciliationError("composition:registry")
        self.store = continuity_store
        self.profile = source_profile
        self.graph_profile_registry = registry

    def reconcile(self, custody_raw: bytes) -> store.AdmissionReceipt:
        """Reconcile one already-stored custody head, or return its exact retry."""

        if type(custody_raw) is not bytes or not custody_raw:
            raise SourceReconciliationError("reconciliation:custody-bytes")
        try:
            existing = self.store.find_source_reconciliation(custody_raw, self.graph_profile_registry)
            if existing is not None:
                return existing
            context = self.store.source_reconciliation_context(custody_raw, self.graph_profile_registry)
            prior_id, prior_stage = _prior_identity(context.get("prior_reconciliation_raw"))
            candidate = independent.build_artifact(
                context["current_custody_raw"],
                context.get("prior_custody_raw"),
                current_graph_raw=context.get("current_graph_raw"),
                prior_graph_raw=context.get("prior_graph_raw"),
                prior_artifact_id=prior_id,
                prior_stage_id=prior_stage,
                graph_profile_registry=self.graph_profile_registry,
            )
            return self.store.admit_source_reconciliation(
                custody_raw,
                candidate,
                self.graph_profile_registry,
            )
        except SourceReconciliationError:
            raise
        except Exception as exc:
            raise SourceReconciliationError(f"reconciliation:admission:{exc}") from exc

    def reconcile_current(self, custody_raw: bytes) -> store.AdmissionReceipt:
        """Explicit alias used by callers that process the current source head."""

        return self.reconcile(custody_raw)


__all__ = [
    "SourceReconciliationError",
    "SourceReconciliationService",
]
