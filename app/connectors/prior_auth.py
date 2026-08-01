from __future__ import annotations

from app.connectors.base import SourceRecord, service_date_window
from app.models import SharedContext
from app.rules_engine_fallback import procedure_requires_prior_authorization
from app.service_line_canonical import canonical_service_line_identities


class PriorAuthConnector:
    source_system = "CA-MEDI-CAL-PRIOR-AUTH-SYNTHETIC"

    def fetch(self, ctx: SharedContext) -> list[SourceRecord]:
        records: list[SourceRecord] = []
        ordered = canonical_service_line_identities(ctx.service_lines)
        for line_index, (procedure_code, _charge_cents, _units_cents, prior_authorization) in enumerate(ordered):
            required = procedure_requires_prior_authorization(procedure_code)
            present = bool(prior_authorization)
            records.append(
                SourceRecord(
                    source_system=self.source_system,
                    source_record_id=f"prior-auth:{ctx.claim_id}:{line_index}:{procedure_code}:{ctx.service_date}",
                    source_type="synthetic_official_prior_authorization_record",
                    facts={
                        f"prior_authorization_required:{line_index}": required,
                        f"authorization_present:{line_index}": present,
                        f"authorization_procedure_code:{line_index}": procedure_code,
                    },
                    valid_from=ctx.service_date,
                    valid_until=ctx.service_date,
                    service_date_coverage=service_date_window(ctx.service_date),
                    attestation="synthetic_prior_auth_signed_snapshot_v1",
                    verification_status="synthetic_verified" if not required or present else "missing",
                    reason_if_missing="" if not required or present else "prior_authorization_required",
                )
            )
        return records
