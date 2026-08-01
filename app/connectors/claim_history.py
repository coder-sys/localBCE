from __future__ import annotations

from app.connectors.base import SourceRecord, service_date_window
from app.connectors.synthetic_state.sources import SyntheticOfficialSources
from app.models import SharedContext


class ClaimHistoryConnector:
    source_system = "CA-MMIS-CLAIM-HISTORY-SYNTHETIC"

    def __init__(self, sources: SyntheticOfficialSources) -> None:
        self.sources = sources

    def fetch(self, ctx: SharedContext) -> list[SourceRecord]:
        duplicate = bool(self.sources.claim_history.get("duplicate_claim", False))
        return [
            SourceRecord(
                source_system=self.source_system,
                source_record_id=f"claim-history:{ctx.member_id}:{ctx.provider.npi}:{ctx.service_date}",
                source_type="synthetic_official_claim_history_record",
                facts={"duplicate_claim": duplicate},
                valid_from=ctx.service_date,
                valid_until=ctx.service_date,
                service_date_coverage=service_date_window(ctx.service_date),
                attestation="synthetic_claim_history_signed_snapshot_v1",
            )
        ]
