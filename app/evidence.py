from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

from app.batch.leaf import stable_private_hash


EVIDENCE_PACKET_SCHEMA = "blind_ledger_evidence_packet_v1"
VERIFIED_STATUSES = {"verified", "synthetic_verified", "attested", "ratified"}


def _clean_dict(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return dict(value or {})


@dataclass(frozen=True)
class EvidenceItem:
    fact_name: str
    fact_value: Any
    source_system: str
    source_record_id: str
    source_type: str
    fetched_at: str
    valid_from: str
    valid_until: str
    service_date_coverage: dict[str, str] = field(default_factory=dict)
    hash: str = ""
    signature: str = ""
    attestation: str = ""
    verification_status: str = "missing"
    reason_if_missing: str = ""

    @classmethod
    def create(
        cls,
        *,
        fact_name: str,
        fact_value: Any,
        source_system: str,
        source_record_id: str,
        source_type: str,
        fetched_at: str,
        valid_from: str = "",
        valid_until: str = "",
        service_date_coverage: Mapping[str, str] | None = None,
        signature: str = "",
        attestation: str = "",
        verification_status: str = "synthetic_verified",
        reason_if_missing: str = "",
    ) -> "EvidenceItem":
        record = {
            "fact_name": fact_name,
            "fact_value": fact_value,
            "source_system": source_system,
            "source_record_id": source_record_id,
            "source_type": source_type,
            "fetched_at": fetched_at,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "service_date_coverage": _clean_dict(service_date_coverage),
            "signature": signature,
            "attestation": attestation,
            "verification_status": verification_status,
            "reason_if_missing": reason_if_missing,
        }
        return cls(hash=stable_private_hash(record), **record)

    def is_verified(self) -> bool:
        return self.verification_status in VERIFIED_STATUSES and not self.reason_if_missing

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvidencePacket:
    claim_id: str
    items: tuple[EvidenceItem, ...]
    schema_version: str = EVIDENCE_PACKET_SCHEMA

    @property
    def evidence_root(self) -> str:
        return stable_private_hash(
            {
                "schema_version": self.schema_version,
                "claim_id": self.claim_id,
                "items": [item.to_dict() for item in self.items],
            }
        )

    def fact_map(self) -> dict[str, Any]:
        facts: dict[str, Any] = {}
        for item in self.items:
            if item.is_verified():
                facts[item.fact_name] = item.fact_value
        return facts

    def fact_verification(self) -> dict[str, str]:
        verification = {
            item.fact_name: item.verification_status if item.is_verified() else f"missing:{item.reason_if_missing or item.verification_status}"
            for item in self.items
        }
        verification["evidence_root"] = self.evidence_root
        return verification

    def missing_reasons(self) -> dict[str, str]:
        return {
            item.fact_name: item.reason_if_missing or item.verification_status
            for item in self.items
            if not item.is_verified()
        }

    def to_flags(self) -> dict[str, bool]:
        facts = self.fact_map()
        return {
            "eligibility_active": bool(facts.get("eligibility_active", False)),
            "provider_enrolled": bool(facts.get("provider_enrolled", False)),
            "provider_not_suspended": bool(facts.get("provider_not_suspended", False)),
            "not_deceased": bool(facts.get("not_deceased", False)),
            "duplicate_claim": bool(facts.get("duplicate_claim", False)),
            "program_integrity_hold": bool(facts.get("program_integrity_hold", False)),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "claim_id": self.claim_id,
            "evidence_root": self.evidence_root,
            "items": [item.to_dict() for item in self.items],
        }
