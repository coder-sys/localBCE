"""Composition root for the synthetic Mirror discrepancy lifecycle.

Callers can select an existing finding/evidence identity or a case head and
request a named lifecycle operation.  The store selects all payload bytes and
the independent verifier derives every responsibility, remediation, retest,
parity, and resolution value.
"""

from __future__ import annotations

import time
from typing import Mapping

from app.mirror import continuity_store as store
from app.mirror import discrepancy_case_independent as independent


class DiscrepancyCaseError(ValueError):
    """Stable composition-layer failure."""


class DiscrepancyCaseService:
    """Configured read-only case lifecycle over the existing ContinuityStore."""

    def __init__(
        self,
        continuity_store: store.ContinuityStore,
        *,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> None:
        if not isinstance(continuity_store, store.ContinuityStore):
            raise DiscrepancyCaseError("composition:store")
        registry = dict(graph_profile_registry or continuity_store.graph_profile_registry)
        if registry != dict(continuity_store.graph_profile_registry):
            raise DiscrepancyCaseError("composition:registry")
        self.store = continuity_store
        self.graph_profile_registry = registry

    @staticmethod
    def _selector(value: object, label: str) -> str:
        if not isinstance(value, str) or not value:
            raise DiscrepancyCaseError(f"case:{label}")
        return value

    def _admit(self, action: str, **selectors: str) -> store.AdmissionReceipt:
        for attempt in range(3):
            try:
                return self.store.admit_discrepancy_case(
                    action,
                    graph_profile_registry=self.graph_profile_registry,
                    **selectors,
                )
            except store.StoreBusyError as exc:
                if attempt == 2:
                    raise DiscrepancyCaseError(f"case:admission:{exc}") from exc
                time.sleep(0.05 * (attempt + 1))
            except (store.StoreConflictError, store.StoreSchemaError, store.ArtifactAdmissionError) as exc:
                raise DiscrepancyCaseError(f"case:admission:{exc}") from exc
            except Exception as exc:
                raise DiscrepancyCaseError(f"case:admission:{exc}") from exc
        raise DiscrepancyCaseError("case:busy-retry-exhausted")

    def open_case(self, graph_artifact_id: str, finding_id: str, reconciliation_artifact_id: str) -> store.AdmissionReceipt:
        """Open from store-selected governed graph and reconciliation artifacts."""

        return self._admit(
            independent.STAGE_OPEN,
            graph_artifact_id=self._selector(graph_artifact_id, "graph-artifact"),
            finding_id=self._selector(finding_id, "finding"),
            reconciliation_artifact_id=self._selector(reconciliation_artifact_id, "reconciliation-artifact"),
        )

    def record_responsibility(self, case_id: str) -> store.AdmissionReceipt:
        return self._admit(independent.STAGE_RESPONSIBILITY, case_id=self._selector(case_id, "case-id"))

    def propose_remediation(self, case_id: str) -> store.AdmissionReceipt:
        return self._admit(independent.STAGE_REMEDIATION_PROPOSED, case_id=self._selector(case_id, "case-id"))

    def attach_remediation_evidence(self, case_id: str) -> store.AdmissionReceipt:
        return self._admit(independent.STAGE_REMEDIATION_EVIDENCE, case_id=self._selector(case_id, "case-id"))

    def execute_retest(self, case_id: str) -> store.AdmissionReceipt:
        """Retest against the current store-selected reconciliation head."""

        return self._admit(independent.STAGE_RETEST, case_id=self._selector(case_id, "case-id"))

    def observe_parity_or_persistence(self, case_id: str) -> store.AdmissionReceipt:
        """Derive parity/persistence from the stored retest; no pass bit is accepted."""

        return self._admit("ADVANCE_RETEST", case_id=self._selector(case_id, "case-id"))

    def observe_resolution(self, case_id: str) -> store.AdmissionReceipt:
        return self._admit(independent.STAGE_RESOLVED, case_id=self._selector(case_id, "case-id"))

    def supersede_with_new_evidence(self, case_id: str) -> store.AdmissionReceipt:
        """Supersede only when the store has a newer reconciliation artifact."""

        return self._admit(independent.STAGE_SUPERSEDED, case_id=self._selector(case_id, "case-id"))


__all__ = ["DiscrepancyCaseError", "DiscrepancyCaseService"]
