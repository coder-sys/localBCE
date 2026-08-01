from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from app.models import SharedContext


SYNTHETIC_FETCHED_AT = "2026-06-18T00:00:00Z"


@dataclass(frozen=True)
class SourceRecord:
    source_system: str
    source_record_id: str
    source_type: str
    facts: dict[str, Any]
    fetched_at: str = SYNTHETIC_FETCHED_AT
    valid_from: str = ""
    valid_until: str = ""
    service_date_coverage: dict[str, str] = field(default_factory=dict)
    signature: str = ""
    attestation: str = ""
    verification_status: str = "synthetic_verified"
    reason_if_missing: str = ""


class Connector(Protocol):
    source_system: str

    def fetch(self, ctx: SharedContext) -> list[SourceRecord]:
        ...


def service_date_window(service_date: str) -> dict[str, str]:
    return {"service_date": service_date}
