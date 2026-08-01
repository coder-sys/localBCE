from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.connectors.base import Connector, SourceRecord
from app.connectors.claim_history import ClaimHistoryConnector
from app.connectors.documents import DocumentsConnector
from app.connectors.eligibility import EligibilityConnector
from app.connectors.fee_schedule import FeeScheduleConnector
from app.connectors.prior_auth import PriorAuthConnector
from app.connectors.provider_status import ProviderStatusConnector
from app.connectors.synthetic_state.sources import SyntheticOfficialSources, build_synthetic_official_sources
from app.evidence import EvidenceItem, EvidencePacket
from app.models import SharedContext
from app.rules_engine_fallback import DEFAULT_FEE_SCHEDULE_CENTS


@dataclass(frozen=True)
class ResolvedFacts:
    flags: dict[str, bool]
    fact_verification: dict[str, str]
    evidence_packet: EvidencePacket
    facts: dict[str, Any]


def _records_to_evidence(claim_id: str, records: list[SourceRecord]) -> EvidencePacket:
    items: list[EvidenceItem] = []
    for record in records:
        for fact_name, fact_value in sorted(record.facts.items()):
            items.append(
                EvidenceItem.create(
                    fact_name=fact_name,
                    fact_value=fact_value,
                    source_system=record.source_system,
                    source_record_id=record.source_record_id,
                    source_type=record.source_type,
                    fetched_at=record.fetched_at,
                    valid_from=record.valid_from,
                    valid_until=record.valid_until,
                    service_date_coverage=record.service_date_coverage,
                    signature=record.signature,
                    attestation=record.attestation,
                    verification_status=record.verification_status,
                    reason_if_missing=record.reason_if_missing,
                )
            )
    return EvidencePacket(claim_id=claim_id, items=tuple(items))


def default_connectors(sources: SyntheticOfficialSources) -> list[Connector]:
    return [
        EligibilityConnector(sources),
        ProviderStatusConnector(sources),
        PriorAuthConnector(),
        FeeScheduleConnector(sources),
        ClaimHistoryConnector(sources),
        DocumentsConnector(sources),
    ]


def resolve_claim_facts(
    ctx: SharedContext,
    *,
    flags: dict[str, object] | None = None,
    fee_schedule_cents: dict[str, int] | None = None,
    sources: SyntheticOfficialSources | None = None,
    connectors: list[Connector] | None = None,
) -> ResolvedFacts:
    source_state = sources or build_synthetic_official_sources(
        flags if flags is not None else ctx.flags,
        fee_schedule_cents=fee_schedule_cents or DEFAULT_FEE_SCHEDULE_CENTS,
    )
    active_connectors = connectors or default_connectors(source_state)
    records: list[SourceRecord] = []
    for connector in active_connectors:
        records.extend(connector.fetch(ctx))
    evidence_packet = _records_to_evidence(ctx.claim_id, records)
    resolved_flags = evidence_packet.to_flags()
    resolved_flags.setdefault("duplicate_claim", False)
    resolved_flags.setdefault("program_integrity_hold", False)
    facts = evidence_packet.fact_map()
    return ResolvedFacts(
        flags=resolved_flags,
        fact_verification=evidence_packet.fact_verification(),
        evidence_packet=evidence_packet,
        facts=facts,
    )
