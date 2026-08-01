from __future__ import annotations

from app.connectors.base import SourceRecord, service_date_window
from app.connectors.synthetic_state.sources import SyntheticOfficialSources
from app.models import SharedContext


class EligibilityConnector:
    source_system = "CA-MMIS-ELIGIBILITY-SYNTHETIC"

    def __init__(self, sources: SyntheticOfficialSources) -> None:
        self.sources = sources

    def fetch(self, ctx: SharedContext) -> list[SourceRecord]:
        return [
            SourceRecord(
                source_system=self.source_system,
                source_record_id=f"eligibility:{ctx.member_id}:{ctx.service_date}",
                source_type="synthetic_official_eligibility_record",
                facts={
                    "eligibility_active": bool(self.sources.eligibility.get("eligibility_active", False)),
                    "not_deceased": bool(self.sources.eligibility.get("not_deceased", False)),
                },
                valid_from=ctx.service_date,
                valid_until=ctx.service_date,
                service_date_coverage=service_date_window(ctx.service_date),
                attestation="synthetic_mm_is_signed_snapshot_v1",
            )
        ]
