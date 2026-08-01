from __future__ import annotations

from app.connectors.base import SourceRecord, service_date_window
from app.connectors.synthetic_state.sources import SyntheticOfficialSources
from app.models import SharedContext


class DocumentsConnector:
    source_system = "CA-MEDI-CAL-DOCUMENTS-SYNTHETIC"

    def __init__(self, sources: SyntheticOfficialSources) -> None:
        self.sources = sources

    def fetch(self, ctx: SharedContext) -> list[SourceRecord]:
        integrity_hold = bool(self.sources.documents.get("program_integrity_hold", False))
        return [
            SourceRecord(
                source_system=self.source_system,
                source_record_id=f"documents:{ctx.claim_id}",
                source_type="synthetic_official_document_completeness_record",
                facts={
                    "program_integrity_hold": integrity_hold,
                    "documents_complete": not integrity_hold,
                },
                valid_from=ctx.service_date,
                valid_until=ctx.service_date,
                service_date_coverage=service_date_window(ctx.service_date),
                attestation="synthetic_documents_signed_snapshot_v1",
                verification_status="synthetic_verified",
            )
        ]
