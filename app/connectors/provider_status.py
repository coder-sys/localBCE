from __future__ import annotations

from app.connectors.base import SourceRecord, service_date_window
from app.connectors.synthetic_state.sources import SyntheticOfficialSources
from app.models import SharedContext


class ProviderStatusConnector:
    source_system = "CA-PAVE-PROVIDER-STATUS-SYNTHETIC"

    def __init__(self, sources: SyntheticOfficialSources) -> None:
        self.sources = sources

    def fetch(self, ctx: SharedContext) -> list[SourceRecord]:
        return [
            SourceRecord(
                source_system=self.source_system,
                source_record_id=f"provider:{ctx.provider.npi}:{ctx.service_date}",
                source_type="synthetic_official_provider_status_record",
                facts={
                    "provider_enrolled": bool(self.sources.provider_status.get("provider_enrolled", False)),
                    "provider_not_suspended": bool(self.sources.provider_status.get("provider_not_suspended", False)),
                },
                valid_from=ctx.service_date,
                valid_until=ctx.service_date,
                service_date_coverage=service_date_window(ctx.service_date),
                attestation="synthetic_pave_signed_snapshot_v1",
            )
        ]
