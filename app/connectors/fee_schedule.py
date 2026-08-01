from __future__ import annotations

from app.connectors.base import SourceRecord, service_date_window
from app.connectors.synthetic_state.sources import SyntheticOfficialSources
from app.models import SharedContext


class FeeScheduleConnector:
    source_system = "CA-MEDI-CAL-FEE-SCHEDULE-SYNTHETIC"

    def __init__(self, sources: SyntheticOfficialSources) -> None:
        self.sources = sources

    def fetch(self, ctx: SharedContext) -> list[SourceRecord]:
        records: list[SourceRecord] = []
        for line in ctx.service_lines:
            allowed = self.sources.fee_schedule_cents.get(line.procedure_code)
            missing = allowed is None
            records.append(
                SourceRecord(
                    source_system=self.source_system,
                    source_record_id=f"fee:{line.procedure_code}:{ctx.service_date}",
                    source_type="synthetic_official_fee_schedule_row",
                    facts={
                        f"fee_allowed_cents:{line.line_id}:{line.procedure_code}": allowed,
                    },
                    valid_from="20260101",
                    valid_until="20261231",
                    service_date_coverage=service_date_window(ctx.service_date),
                    attestation="synthetic_fee_schedule_signed_snapshot_v1",
                    verification_status="missing" if missing else "synthetic_verified",
                    reason_if_missing=f"fee_schedule_missing:{line.procedure_code}" if missing else "",
                )
            )
        return records
