"""Closed, bounded data types for the synthetic Provider App core.

Every token and source status in this module is fictional fixture vocabulary.
The types do not encode a real payer, state, program, clinical catalog, or
provider identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from enum import Enum


REQUEST_CONTRACT = "RR/PROVIDER-APP/CHECK-REQUEST/v1"
BUNDLE_CONTRACT = "RR/PROVIDER-APP/RULE-BUNDLE/v1"
RESULT_CONTRACT = "RR/PROVIDER-APP/CHECK-RESULT/v1"
BUNDLE_ID = "RR-SYNTHETIC-PREFLIGHT"
MAX_JSON_BYTES = 16_384
MAX_JSON_DEPTH = 8
MAX_RESULT_BYTES = 16_384
MAX_RULES = 8
MAX_AMOUNT_CENTS = 100_000_000
MAX_VERSION = 65_535
RESULT_LIMITATION = (
    "Synthetic pre-submission result only; it is not claim acceptance, "
    "coverage, authorization, clinical judgment, or payment."
)


class InputError(ValueError):
    """A stable, non-sensitive input rejection code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __str__(self) -> str:
        return self.code


class Outcome(str, Enum):
    PASS = "PASS"
    MISSING = "MISSING"
    HUMAN_CHECK = "HUMAN_CHECK"


class RunMode(str, Enum):
    SYNTHETIC_TEST = "SYNTHETIC_TEST"
    REAL_USE = "REAL_USE"


class Scope(str, Enum):
    SYNTHETIC_PROVIDER_A = "RR-SYNTHETIC-PROVIDER-A"
    SYNTHETIC_PROVIDER_B = "RR-SYNTHETIC-PROVIDER-B"


class ServiceCategory(str, Enum):
    CATEGORY_A = "SYNTH-CATEGORY-A"
    CATEGORY_B = "SYNTH-CATEGORY-B"


class ReferenceState(str, Enum):
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"


class SyntheticSource(str, Enum):
    SOURCE_ALPHA = "SYNTHETIC-SOURCE-ALPHA"
    SOURCE_BETA = "SYNTHETIC-SOURCE-BETA"


class SourceStatus(str, Enum):
    COMPLETE_FIXTURE = "COMPLETE_FIXTURE"
    PARTIAL = "PARTIAL"
    STALE = "STALE"
    CONFLICT = "CONFLICT"
    REPLAYED = "REPLAYED"
    UNKNOWN = "UNKNOWN"


class BundleProvenance(str, Enum):
    UNAPPROVED_SYNTHETIC_FIXTURE = "UNAPPROVED_SYNTHETIC_FIXTURE"


class RuleId(str, Enum):
    SERVICE_DATE = "SYN-PRE-001"
    SERVICE_CATEGORY = "SYN-PRE-002"
    SUPPORT_REFERENCE = "SYN-PRE-003"
    CHARGE_RANGE = "SYN-PRE-004"
    SOURCE_CURRENCY = "SYN-PRE-005"


class RuleSemantic(str, Enum):
    SERVICE_DATE_IN_EFFECTIVE_WINDOW = "SERVICE_DATE_IN_EFFECTIVE_WINDOW"
    SERVICE_CATEGORY_EQUALS = "SERVICE_CATEGORY_EQUALS"
    SUPPORT_REFERENCE_PRESENT = "SUPPORT_REFERENCE_PRESENT"
    CHARGE_CENTS_BETWEEN = "CHARGE_CENTS_BETWEEN"
    SOURCE_COMPLETE_AND_FRESH = "SOURCE_COMPLETE_AND_FRESH"


class FactName(str, Enum):
    SERVICE_DATE = "service_date"
    SERVICE_CATEGORY = "service_category"
    SUPPORT_REFERENCE = "support_reference"
    CHARGE_CENTS = "charge_cents"
    SOURCE_BINDING = "source_binding"
    SOURCE_EFFECTIVE_AT = "source_effective_at"
    SOURCE_RECEIVED_AT = "source_received_at"


@dataclass(frozen=True, slots=True)
class SourceBinding:
    source: SyntheticSource
    version: str
    status: SourceStatus
    effective_at: date | None
    received_at: datetime | None


@dataclass(frozen=True, slots=True)
class ClaimFacts:
    service_date: date | None
    service_category: ServiceCategory | None
    support_reference: ReferenceState | None
    charge_cents: int | None
    source_binding: SourceBinding | None


@dataclass(frozen=True, slots=True)
class CheckRequest:
    mode: RunMode
    scope: Scope
    evaluated_at: datetime
    facts: ClaimFacts


@dataclass(frozen=True, slots=True)
class RuleSpec:
    rule_id: RuleId
    version: int
    semantic: RuleSemantic
    effective_from: date
    effective_until: date
    expected_category: ServiceCategory | None = None
    minimum_cents: int | None = None
    maximum_cents: int | None = None
    max_source_age_days: int | None = None


@dataclass(frozen=True, slots=True)
class RuleBundle:
    bundle_id: str
    version: int
    scope: Scope
    provenance: BundleProvenance
    issuer_reference: str
    published_at: datetime
    effective_from: date
    effective_until: date
    expires_at: datetime
    withdrawn_at: datetime | None
    rules: tuple[RuleSpec, ...]
    content_digest: str


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    rule_id: RuleId
    citation: str
    outcome: Outcome
    missing_facts: tuple[FactName, ...]
    reason_codes: tuple[str, ...]
    facts_used: tuple[FactName, ...]


@dataclass(frozen=True, slots=True)
class BundleBinding:
    bundle_id: str
    version: int
    scope: Scope
    provenance: BundleProvenance
    issuer_reference: str
    content_digest: str
    effective_from: date
    effective_until: date
    expires_at: datetime
    withdrawn_at: datetime | None


@dataclass(frozen=True, slots=True)
class CheckResult:
    outcome: Outcome
    mode: RunMode
    scope: Scope
    evaluated_at: datetime
    bundle: BundleBinding
    source_binding: SourceBinding | None
    bundle_issues: tuple[str, ...]
    rules: tuple[RuleEvaluation, ...]
    missing_facts: tuple[FactName, ...]
    limitation: str = RESULT_LIMITATION


def is_utc_timestamp(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timezone.utc.utcoffset(value)
    )
