from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Patient:
    name: str
    id: str


@dataclass
class Provider:
    npi: str
    name: str = ""


@dataclass
class ServiceLine:
    line_id: str
    procedure_code: str
    charge_amount: float
    units: float
    prior_authorization: Optional[str] = None


@dataclass
class SharedContext:
    claim_id: str
    transaction_set: str
    payer_id: str
    member_id: str
    patient: Patient
    provider: Provider
    service_date: str
    diagnoses: List[str]
    service_lines: List[ServiceLine]
    total_charge: float
    flags: Dict[str, bool] = field(default_factory=dict)
    fact_verification: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GateResult:
    gate: str
    passed: bool
    reason: str = ""


@dataclass
class AdjudicationResult:
    claim_id: str
    approved: bool
    denial_reason: str
    gates: List[GateResult]
    carc: str
    rarc: str
    total_charge: float
    payable_amount: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
