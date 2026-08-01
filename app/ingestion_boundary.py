from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.ingestion import Parsed837, parse_837


PROTOTYPE_X12_BOUNDARY = "prototype_837_parser_narrow_policy_wedge_only"


class ClaimIngestionPort(Protocol):
    boundary_status: str

    def parse(self, raw_edi: str) -> Parsed837:
        ...


@dataclass(frozen=True)
class Prototype837Ingestion:
    boundary_status: str = PROTOTYPE_X12_BOUNDARY

    def parse(self, raw_edi: str) -> Parsed837:
        return parse_837(raw_edi)
