"""Fixed, synthetic expectations for RightRail financial acceptance tests.

This module deliberately has no application imports, calculations, persistence, or mock
success path.  Values below are fixture inputs and independently hand-derived outcomes for
the later real-owner tests.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScopeExpectation:
    state_id: str
    deployment_id: str
    program_id: str
    period_id: str
    currency: str


@dataclass(frozen=True, slots=True)
class ControlPackExpectation:
    pack_id: str
    scope: ScopeExpectation
    version: int
    source_refs: tuple[str, ...]
    effective_start_ms: int
    effective_end_ms: int
    recorded_at_ms: int
    approved_at_ms: int
    calculation_rule_id: str
    adjustment_rule_id: str
    authorized_roles: tuple[str, ...]
    expected_tests: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PopulationItemExpectation:
    population_id: str
    item_id: str
    display_label: str
    owed_cents: int
    due_at_ms: int
    currency: str = "USD"


@dataclass(frozen=True, slots=True)
class EvidenceExpectation:
    evidence_id: str
    item_id: str
    kind: str
    common_origin_id: str
    source_id: str
    source_version: str
    local_ref: str
    applicable_at_ms: int
    event_at_ms: int
    received_at_ms: int
    amount_cents: int | None = None
    reversal_of: str | None = None
    supersedes: str | None = None


@dataclass(frozen=True, slots=True)
class BalanceExpectation:
    stage: str
    owed_cents: int
    received_cash_cents: int
    claimed_adjustment_cents: int
    lawful_adjustment_cents: int
    shortfall_cents: int
    overage_cents: int
    cash_satisfied: bool
    amount_satisfied: bool
    timely: bool
    reporting_complete: bool
    verification_status: str
    case_status: str
    delivery_status: str


@dataclass(frozen=True, slots=True)
class ActionExpectation:
    action_id: str
    obligation_id: str
    kind: str
    amount_cents: int
    revision: int
    payload_fields: tuple[tuple[str, str], ...]
    expected_status: str
    retry_count: int
    duplicate_effect_count: int
    changed_payload_rejected: bool


@dataclass(frozen=True, slots=True)
class RejectionExpectation:
    operation: str
    reason: str
    expected_error: str
    mutation_committed: bool


@dataclass(frozen=True, slots=True)
class RevisionRaceExpectation:
    aggregate_id: str
    expected_revision: int
    winner_count: int
    loser_count: int
    loser_error: str
    committed_history_events: int
    committed_projection_updates: int
    committed_outbox_rows: int


@dataclass(frozen=True, slots=True)
class InterruptionExpectation:
    boundary: str
    expected_outcome: str
    prior_state_preserved: bool
    reservation_preserved: bool
    external_effect: str


@dataclass(frozen=True, slots=True)
class ContinuityExpectation:
    export_version: str
    source_case_id: str
    restore_mode: str
    dispatch_enabled: bool
    egress_enabled: bool
    included_records: tuple[str, ...]
    excluded_records: tuple[str, ...]
    evidence_available_after_restore: bool
    action_idempotency_preserved: bool
    duplicate_dispatches_after_restore: int


@dataclass(frozen=True, slots=True)
class BoundaryExpectation:
    scoped_fields: tuple[str, ...]
    foreign_scope_rejected: bool
    oversized_limit_bytes: int
    oversized_input_bytes: int
    oversized_rejected_without_mutation: bool
    synthetic_canary: str
    corporate_egress_enabled: bool
    canary_persisted_or_emitted: bool
    diagnostic_fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AcceptanceCase:
    number: int
    case_id: str
    scope: ScopeExpectation
    operations: tuple[str, ...]
    expected_population_count: int
    expected_population_total_cents: int
    expected_population_evidence_count: int
    missing_item_ids: tuple[str, ...]
    balance_snapshots: tuple[BalanceExpectation, ...]
    evidence_ids: tuple[str, ...]
    actions: tuple[ActionExpectation, ...]
    rejections: tuple[RejectionExpectation, ...]
    invariant_tags: tuple[str, ...]


# Fixed scope and dates.  Times are UTC milliseconds; these literals make rule and timeliness
# boundaries reproducible without consulting a clock or a production date helper.
STATE_ID = "fixture-state"
DEPLOYMENT_ID = "fixture-rightrail"
PROGRAM_ID = "fixture-provider-payment"
CURRENCY = "USD"
PERIOD_ONE_ID = "fixture-2026-period-01"
PERIOD_TWO_ID = "fixture-2026-period-02"
POPULATION_ONE_ID = "population:fixture-2026-01"
POPULATION_TWO_ID = "population:fixture-2026-02"

PERIOD_ONE_START_MS = 1_767_225_600_000       # 2026-01-01T00:00:00Z
PERIOD_ONE_END_MS = 1_775_001_600_000         # 2026-04-01T00:00:00Z
PERIOD_TWO_START_MS = 1_775_001_600_000         # 2026-04-01T00:00:00Z
PERIOD_TWO_END_MS = 1_782_864_000_000         # 2026-07-01T00:00:00Z
H_DUE_AT_MS = 1_774_915_200_000              # 2026-03-31T00:00:00Z
SUPPORT_EVENT_MS = 1_767_312_000_000          # 2026-01-02T00:00:00Z
CASH_EVENT_MS = 1_774_828_800_000             # 2026-03-30T00:00:00Z
OFFSET_DECISION_MS = 1_774_864_800_000        # 2026-03-30T10:00:00Z
CORRECTION_AUTH_MS = 1_774_922_400_000        # 2026-03-31T02:00:00Z
ACK_EVENT_MS = 1_774_926_000_000              # 2026-03-31T03:00:00Z
P2_EVENT_MS = 1_775_001_600_000               # 2026-04-01T00:00:00Z (late)
P2_CONFIRMATION_MS = 1_775_005_200_000        # 2026-04-01T01:00:00Z
P2_CONFLICT_MS = 1_775_008_800_000            # 2026-04-01T02:00:00Z
REPORT_CORRECTION_MS = 1_775_088_000_000      # 2026-04-02T00:00:00Z
P2_REVERSAL_MS = 1_775_174_400_000            # 2026-04-03T00:00:00Z
P3_EVENT_MS = 1_775_260_800_000               # 2026-04-04T00:00:00Z

H_ITEM_ID = "item-h"
OTHER_ITEM_IDS = (
    "item-01", "item-02", "item-03", "item-04", "item-05", "item-06", "item-07",
    "item-08", "item-09", "item-10", "item-11", "item-12", "item-13", "item-14",
    "item-15", "item-16", "item-17", "item-18", "item-19",
)
ITEM_IDS = (H_ITEM_ID,) + OTHER_ITEM_IDS
H_OWED_CENTS = 10_000_000
OTHER_ITEM_CENTS = 4_700_000
FINAL_OTHER_ITEM_CENTS = 5_400_000
OTHER_TOTAL_CENTS = 90_000_000
PROGRAM_TOTAL_CENTS = 100_000_000
H_CASH_CENTS = 9_700_000
UNAPPROVED_OFFSET_CENTS = 300_000
CORRECTION_PAYMENT_CENTS = 300_000
CONFLICTING_P2_CENTS = 300_001

H_OBLIGATION_ID = "obligation:item-h:period-01"
ACTION_OFFSET_ID = "action:obligation-item-h:offset-v1"
ACTION_CORRECTION_ID = "action:obligation-item-h:correction-v1"
P2_EVIDENCE_ID = "evidence:payment-h:p2"
P2_REVERSAL_EVIDENCE_ID = "evidence:payment-h:p2-reversal"

PERIOD_ONE_SCOPE = ScopeExpectation(STATE_ID, DEPLOYMENT_ID, PROGRAM_ID, PERIOD_ONE_ID, CURRENCY)
PERIOD_TWO_SCOPE = ScopeExpectation(STATE_ID, DEPLOYMENT_ID, PROGRAM_ID, PERIOD_TWO_ID, CURRENCY)

PROGRAM_ITEMS = (
    PopulationItemExpectation(POPULATION_ONE_ID, H_ITEM_ID, "Synthetic recipient H", H_OWED_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-01", "Synthetic recipient 01", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-02", "Synthetic recipient 02", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-03", "Synthetic recipient 03", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-04", "Synthetic recipient 04", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-05", "Synthetic recipient 05", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-06", "Synthetic recipient 06", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-07", "Synthetic recipient 07", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-08", "Synthetic recipient 08", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-09", "Synthetic recipient 09", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-10", "Synthetic recipient 10", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-11", "Synthetic recipient 11", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-12", "Synthetic recipient 12", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-13", "Synthetic recipient 13", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-14", "Synthetic recipient 14", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-15", "Synthetic recipient 15", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-16", "Synthetic recipient 16", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-17", "Synthetic recipient 17", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-18", "Synthetic recipient 18", OTHER_ITEM_CENTS, H_DUE_AT_MS),
    PopulationItemExpectation(POPULATION_ONE_ID, "item-19", "Synthetic recipient 19", FINAL_OTHER_ITEM_CENTS, H_DUE_AT_MS),
)

CONTROL_PACK_V1 = ControlPackExpectation(
    "control-pack:fixture-2026-01:v1", PERIOD_ONE_SCOPE, 1,
    ("fixture-source:approved-schedule:v1",), PERIOD_ONE_START_MS, PERIOD_ONE_END_MS,
    1_767_139_200_000, 1_767_182_400_000, "calculation:per-recipient:v1", "adjustment:offset:v1",
    ("FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR", "RECEIVER"),
    ("program-total=100000000", "H-owed=10000000", "other-total=90000000", "timeliness-separate"),
)
CONTROL_PACK_V2 = ControlPackExpectation(
    "control-pack:fixture-2026-02:v2", PERIOD_TWO_SCOPE, 2,
    ("fixture-source:approved-schedule:v2", "fixture-source:rule-change:2026-04-01"),
    PERIOD_TWO_START_MS, PERIOD_TWO_END_MS, 1_774_915_200_000, 1_774_958_400_000,
    "calculation:per-recipient:v2", "adjustment:offset:v2",
    ("FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR", "RECEIVER"),
    ("period-02-uses-rule-v2", "period-01-evaluation-preserved", "retrospective-authority-required"),
)
CONTROL_PACKS = (CONTROL_PACK_V1, CONTROL_PACK_V2)

OTHER_SUPPORT_EVIDENCE = (
    EvidenceExpectation("evidence:support:item-01", "item-01", "SUPPORT", "origin:support:01", "fixture-source", "support-v1", "ref:support:01", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-02", "item-02", "SUPPORT", "origin:support:02", "fixture-source", "support-v1", "ref:support:02", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-03", "item-03", "SUPPORT", "origin:support:03", "fixture-source", "support-v1", "ref:support:03", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-04", "item-04", "SUPPORT", "origin:support:04", "fixture-source", "support-v1", "ref:support:04", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-05", "item-05", "SUPPORT", "origin:support:05", "fixture-source", "support-v1", "ref:support:05", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-06", "item-06", "SUPPORT", "origin:support:06", "fixture-source", "support-v1", "ref:support:06", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-07", "item-07", "SUPPORT", "origin:support:07", "fixture-source", "support-v1", "ref:support:07", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-08", "item-08", "SUPPORT", "origin:support:08", "fixture-source", "support-v1", "ref:support:08", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-09", "item-09", "SUPPORT", "origin:support:09", "fixture-source", "support-v1", "ref:support:09", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-10", "item-10", "SUPPORT", "origin:support:10", "fixture-source", "support-v1", "ref:support:10", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-11", "item-11", "SUPPORT", "origin:support:11", "fixture-source", "support-v1", "ref:support:11", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-12", "item-12", "SUPPORT", "origin:support:12", "fixture-source", "support-v1", "ref:support:12", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-13", "item-13", "SUPPORT", "origin:support:13", "fixture-source", "support-v1", "ref:support:13", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-14", "item-14", "SUPPORT", "origin:support:14", "fixture-source", "support-v1", "ref:support:14", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-15", "item-15", "SUPPORT", "origin:support:15", "fixture-source", "support-v1", "ref:support:15", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-16", "item-16", "SUPPORT", "origin:support:16", "fixture-source", "support-v1", "ref:support:16", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-17", "item-17", "SUPPORT", "origin:support:17", "fixture-source", "support-v1", "ref:support:17", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-18", "item-18", "SUPPORT", "origin:support:18", "fixture-source", "support-v1", "ref:support:18", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
    EvidenceExpectation("evidence:support:item-19", "item-19", "SUPPORT", "origin:support:19", "fixture-source", "support-v1", "ref:support:19", SUPPORT_EVENT_MS, SUPPORT_EVENT_MS, SUPPORT_EVENT_MS),
)

H_CASH_EVIDENCE = EvidenceExpectation("evidence:cash-h:9700000", H_ITEM_ID, "CASH_CONFIRMATION", "origin:cash:h:v1", "fixture-payment-file", "cash-v1", "ref:cash:h:v1", CASH_EVENT_MS, CASH_EVENT_MS, CASH_EVENT_MS, H_CASH_CENTS)
OFFSET_CLAIM_EVIDENCE = EvidenceExpectation("evidence:offset-h:claim", H_ITEM_ID, "ADJUSTMENT_CLAIM", "origin:offset:h:v1", "fixture-report", "offset-v1", "ref:offset:h:claim", CASH_EVENT_MS, CASH_EVENT_MS, CASH_EVENT_MS, UNAPPROVED_OFFSET_CENTS)
OFFSET_SUPPORT_EVIDENCE = EvidenceExpectation("evidence:offset-h:support", H_ITEM_ID, "SUPPORT", "origin:offset-support:h:v1", "fixture-approval-file", "offset-support-v1", "ref:offset:h:support", CASH_EVENT_MS, CASH_EVENT_MS, CASH_EVENT_MS)
OFFSET_APPROVAL_EVIDENCE = EvidenceExpectation("evidence:offset-h:approval", H_ITEM_ID, "ADJUSTMENT_APPROVAL", "origin:offset:h:v1", "fixture-official", "authority-v1", "ref:offset:h:approval", OFFSET_DECISION_MS, OFFSET_DECISION_MS, OFFSET_DECISION_MS, UNAPPROVED_OFFSET_CENTS)
CORRECTION_AUTH_EVIDENCE = EvidenceExpectation("evidence:correction-h:authorization", H_ITEM_ID, "CORRECTION_AUTHORIZATION", "origin:correction:h:v1", "fixture-official", "authority-v1", "ref:correction:h:authorization", CORRECTION_AUTH_MS, CORRECTION_AUTH_MS, CORRECTION_AUTH_MS, CORRECTION_PAYMENT_CENTS)
ACTION_ACK_EVIDENCE = EvidenceExpectation("evidence:action-h:ack", H_ITEM_ID, "ACTION_ACKNOWLEDGMENT", "origin:action:h:ack:v1", "fixture-receiver", "ack-v1", "ref:action:h:ack", ACK_EVENT_MS, ACK_EVENT_MS, ACK_EVENT_MS)
P2_PAYMENT_EVIDENCE = EvidenceExpectation(P2_EVIDENCE_ID, H_ITEM_ID, "PAYMENT", "origin:payment:h:p2", "fixture-payment-file", "payment-v2", "ref:payment:h:p2", P2_EVENT_MS, P2_EVENT_MS, P2_EVENT_MS, CORRECTION_PAYMENT_CENTS)
P2_CONFIRMATION_EVIDENCE = EvidenceExpectation("evidence:cash-confirmation-h:p2", H_ITEM_ID, "CASH_CONFIRMATION", "origin:payment:h:p2", "fixture-bank-confirmation", "cash-v2", "ref:payment:h:p2:confirmation", P2_CONFIRMATION_MS, P2_CONFIRMATION_MS, P2_CONFIRMATION_MS, CORRECTION_PAYMENT_CENTS)
P2_CONFLICT_EVIDENCE = EvidenceExpectation("evidence:payment-h:p2-conflict", H_ITEM_ID, "PAYMENT", "origin:payment:h:p2", "fixture-payment-file", "payment-v2-conflict", "ref:payment:h:p2:conflict", P2_CONFLICT_MS, P2_CONFLICT_MS, P2_CONFLICT_MS, CONFLICTING_P2_CENTS)
REPORT_ORIGINAL_EVIDENCE = EvidenceExpectation("evidence:report-h:original", H_ITEM_ID, "REPORT", "origin:report:h:v1", "fixture-report", "report-v1", "ref:report:h:original", P2_EVENT_MS, P2_EVENT_MS, P2_EVENT_MS)
REPORT_CORRECTION_EVIDENCE = EvidenceExpectation("evidence:report-h:correction", H_ITEM_ID, "REPORT_CORRECTION", "origin:report:h:v2", "fixture-report", "report-v2", "ref:report:h:correction", REPORT_CORRECTION_MS, REPORT_CORRECTION_MS, REPORT_CORRECTION_MS, supersedes="evidence:report-h:original")
P2_REVERSAL_EVIDENCE = EvidenceExpectation(P2_REVERSAL_EVIDENCE_ID, H_ITEM_ID, "PAYMENT_REVERSAL", "origin:payment:h:p2-reversal", "fixture-payment-file", "payment-v2", "ref:payment:h:p2:reversal", P2_REVERSAL_MS, P2_REVERSAL_MS, P2_REVERSAL_MS, CORRECTION_PAYMENT_CENTS, reversal_of=P2_EVIDENCE_ID)
P3_REPLACEMENT_EVIDENCE = EvidenceExpectation("evidence:payment-h:p3", H_ITEM_ID, "PAYMENT", "origin:payment:h:p3", "fixture-payment-file", "payment-v3", "ref:payment:h:p3", P3_EVENT_MS, P3_EVENT_MS, P3_EVENT_MS, CORRECTION_PAYMENT_CENTS, supersedes=P2_REVERSAL_EVIDENCE_ID)
H_EVIDENCE = (H_CASH_EVIDENCE, OFFSET_CLAIM_EVIDENCE, OFFSET_SUPPORT_EVIDENCE, OFFSET_APPROVAL_EVIDENCE, CORRECTION_AUTH_EVIDENCE, ACTION_ACK_EVIDENCE, P2_PAYMENT_EVIDENCE, P2_CONFIRMATION_EVIDENCE, P2_CONFLICT_EVIDENCE, REPORT_ORIGINAL_EVIDENCE, REPORT_CORRECTION_EVIDENCE, P2_REVERSAL_EVIDENCE, P3_REPLACEMENT_EVIDENCE)
ALL_EVIDENCE = OTHER_SUPPORT_EVIDENCE + H_EVIDENCE

H_MISSING = BalanceExpectation("missing-H", H_OWED_CENTS, 0, 0, 0, H_OWED_CENTS, 0, False, False, False, False, "MISSING_EVIDENCE", "OPEN", "NONE")
H_CASH_AND_CLAIM = BalanceExpectation("cash-plus-claimed-offset", H_OWED_CENTS, H_CASH_CENTS, UNAPPROVED_OFFSET_CENTS, 0, UNAPPROVED_OFFSET_CENTS, 0, False, False, False, False, "SUPPORTED", "OPEN", "NONE")
H_AUTHORIZED_OFFSET = BalanceExpectation("lawful-offset", H_OWED_CENTS, H_CASH_CENTS, UNAPPROVED_OFFSET_CENTS, UNAPPROVED_OFFSET_CENTS, 0, 0, False, True, True, False, "SUPPORTED", "ACTIONED", "READY")
H_REJECTED_CORRECTION = BalanceExpectation("rejected-offset-correction-ready", H_OWED_CENTS, H_CASH_CENTS, 0, 0, UNAPPROVED_OFFSET_CENTS, 0, False, False, False, False, "SUPPORTED", "CORRECTION_REQUIRED", "READY")
H_ACKNOWLEDGED = BalanceExpectation("ack-without-cash", H_OWED_CENTS, H_CASH_CENTS, 0, 0, UNAPPROVED_OFFSET_CENTS, 0, False, False, False, False, "SUPPORTED", "CORRECTION_REQUIRED", "ACKNOWLEDGED")
H_P2_RECEIVED_LATE = BalanceExpectation("p2-received-late", H_OWED_CENTS, 10_000_000, 0, 0, 0, 0, True, True, False, False, "SUPPORTED", "ACTIONED", "ACKNOWLEDGED")
H_REPORT_CORRECTED_LATE = BalanceExpectation("report-corrected-late", H_OWED_CENTS, 10_000_000, 0, 0, 0, 0, True, True, False, True, "SUPPORTED", "RESOLVED", "ACKNOWLEDGED")
H_P2_DUPLICATE_UNCHANGED = BalanceExpectation("p2-duplicate-unchanged", H_OWED_CENTS, 10_000_000, 0, 0, 0, 0, True, True, False, True, "SUPPORTED", "RESOLVED", "ACKNOWLEDGED")
H_P2_CONFLICT_VISIBLE = BalanceExpectation("p2-conflict-visible", H_OWED_CENTS, 10_000_000, 0, 0, 0, 0, True, True, False, True, "CONFLICT_VISIBLE", "RESOLVED", "ACKNOWLEDGED")
H_P2_REVERSED = BalanceExpectation("p2-reversed", H_OWED_CENTS, H_CASH_CENTS, 0, 0, UNAPPROVED_OFFSET_CENTS, 0, False, False, False, True, "CONFLICT_VISIBLE", "OPEN", "ACKNOWLEDGED")
H_P3_REPLACED = BalanceExpectation("p3-replacement", H_OWED_CENTS, 10_000_000, 0, 0, 0, 0, True, True, False, True, "CONFLICT_VISIBLE", "RESOLVED", "ACKNOWLEDGED")

OFFSET_ACTION_READY = ActionExpectation(ACTION_OFFSET_ID, H_OBLIGATION_ID, "OFFSET_AUTHORIZATION", UNAPPROVED_OFFSET_CENTS, 1, (("action", "authorize-offset"), ("amount_cents", "300000"), ("currency", "USD"), ("item_id", H_ITEM_ID)), "READY", 2, 0, True)
CORRECTION_ACTION_READY = ActionExpectation(ACTION_CORRECTION_ID, H_OBLIGATION_ID, "CORRECTION_REQUEST", CORRECTION_PAYMENT_CENTS, 1, (("action", "request-correction"), ("amount_cents", "300000"), ("currency", "USD"), ("item_id", H_ITEM_ID)), "READY", 2, 0, True)
CORRECTION_ACTION_ACKNOWLEDGED = ActionExpectation(ACTION_CORRECTION_ID, H_OBLIGATION_ID, "CORRECTION_REQUEST", CORRECTION_PAYMENT_CENTS, 1, (("action", "request-correction"), ("amount_cents", "300000"), ("currency", "USD"), ("item_id", H_ITEM_ID)), "ACKNOWLEDGED", 2, 0, True)

UNAUTHORIZED_REJECTION = RejectionExpectation("authorize-offset", "UNAUTHORIZED_ACTOR", "authority_actor_not_authorized", False)
STALE_REJECTION = RejectionExpectation("authorize-offset", "STALE_OBLIGATION_REVISION", "obligation_revision_conflict", False)
ACTION_PAYLOAD_REJECTION = RejectionExpectation("retry-action-with-changed-payload", "IMMUTABLE_ACTION_PAYLOAD", "action_payload_immutable", False)

CASE_01 = AcceptanceCase(1, "case-01-publish-and-missing-H", PERIOD_ONE_SCOPE, ("publish-control-pack-v1", "publish-population-v1", "submit-19-support-records", "evaluate-H"), 20, PROGRAM_TOTAL_CENTS, 19, (H_ITEM_ID,), (H_MISSING,), ("evidence:support:item-01", "evidence:support:item-02", "evidence:support:item-03", "evidence:support:item-04", "evidence:support:item-05", "evidence:support:item-06", "evidence:support:item-07", "evidence:support:item-08", "evidence:support:item-09", "evidence:support:item-10", "evidence:support:item-11", "evidence:support:item-12", "evidence:support:item-13", "evidence:support:item-14", "evidence:support:item-15", "evidence:support:item-16", "evidence:support:item-17", "evidence:support:item-18", "evidence:support:item-19"), (), (), ("missing-obligation-visible", "population-accountability", "hand-derived-cents"))
CASE_02 = AcceptanceCase(2, "case-02-cash-and-offset-claim", PERIOD_ONE_SCOPE, ("record-cash-H-9700000", "record-offset-claim-300000", "open-case"), 20, PROGRAM_TOTAL_CENTS, 20, (), (H_CASH_AND_CLAIM,), (H_CASH_EVIDENCE.evidence_id, OFFSET_CLAIM_EVIDENCE.evidence_id), (), (), ("cash-separate-from-claim", "approval-owner-and-deadline-recorded"))
CASE_03 = AcceptanceCase(3, "case-03-authorized-offset", PERIOD_ONE_SCOPE, ("supply-offset-support", "authorize-offset", "evaluate-H"), 20, PROGRAM_TOTAL_CENTS, 20, (), (H_AUTHORIZED_OFFSET,), (OFFSET_SUPPORT_EVIDENCE.evidence_id, OFFSET_APPROVAL_EVIDENCE.evidence_id), (OFFSET_ACTION_READY,), (), ("lawful-adjustment-satisfies-amount", "cash-unchanged", "timeliness-separate", "reporting-separate"))
CASE_04 = AcceptanceCase(4, "case-04-reject-and-authorize-correction", PERIOD_ONE_SCOPE, ("reject-offset", "authorize-correction", "evaluate-H"), 20, PROGRAM_TOTAL_CENTS, 20, (), (H_REJECTED_CORRECTION,), (CORRECTION_AUTH_EVIDENCE.evidence_id,), (CORRECTION_ACTION_READY,), (UNAUTHORIZED_REJECTION, STALE_REJECTION), ("authority-required", "stale-decision-rejected", "cash-shortfall-remains"))
CASE_05 = AcceptanceCase(5, "case-05-ack-without-cash", PERIOD_ONE_SCOPE, ("acknowledge-correction-action", "evaluate-H"), 20, PROGRAM_TOTAL_CENTS, 20, (), (H_ACKNOWLEDGED,), (ACTION_ACK_EVIDENCE.evidence_id,), (CORRECTION_ACTION_ACKNOWLEDGED,), (ACTION_PAYLOAD_REJECTION,), ("ack-is-not-cash", "action-payload-immutable", "retry-reuses-action-id"))
CASE_06 = AcceptanceCase(6, "case-06-late-payment-and-report-correction", PERIOD_ONE_SCOPE, ("receive-P2", "evaluate-H", "correct-report", "evaluate-H-again"), 20, PROGRAM_TOTAL_CENTS, 20, (), (H_P2_RECEIVED_LATE, H_REPORT_CORRECTED_LATE), (P2_PAYMENT_EVIDENCE.evidence_id, REPORT_CORRECTION_EVIDENCE.evidence_id), (CORRECTION_ACTION_ACKNOWLEDGED,), (), ("P2-unique-payment", "late-satisfaction-preserves-missed-deadline", "reporting-independent"))
CASE_07 = AcceptanceCase(7, "case-07-duplicates-conflict-reversal-replacement", PERIOD_ONE_SCOPE, ("resubmit-P2", "record-second-confirmation", "record-conflicting-P2", "reverse-P2", "receive-P3"), 20, PROGRAM_TOTAL_CENTS, 20, (), (H_P2_DUPLICATE_UNCHANGED, H_P2_CONFLICT_VISIBLE, H_P2_REVERSED, H_P3_REPLACED), (P2_CONFIRMATION_EVIDENCE.evidence_id, P2_CONFLICT_EVIDENCE.evidence_id, P2_REVERSAL_EVIDENCE.evidence_id, P3_REPLACEMENT_EVIDENCE.evidence_id), (CORRECTION_ACTION_ACKNOWLEDGED,), (), ("common-origin-counts-once", "conflict-visible-without-mutation", "reversal-additive", "replacement-distinct"))
CASE_08 = AcceptanceCase(8, "case-08-revision-race", PERIOD_ONE_SCOPE, ("race-evaluations-on-same-revision", "race-corrections-on-same-revision"), 20, PROGRAM_TOTAL_CENTS, 20, (), (H_REJECTED_CORRECTION,), (), (CORRECTION_ACTION_READY,), (STALE_REJECTION,), ("one-winner", "one-stale-loser", "history-projection-outbox-atomic"))
CASE_09 = AcceptanceCase(9, "case-09-rule-change-and-second-period", PERIOD_TWO_SCOPE, ("publish-control-pack-v2", "publish-population-v2", "evaluate-period-02", "authorize-retrospective-correction"), 20, PROGRAM_TOTAL_CENTS, 20, (), (H_P3_REPLACED,), (), (), (STALE_REJECTION,), ("period-01-rule-v1-preserved", "period-02-rule-v2", "retrospective-explicitly-authorized"))
CASE_10 = AcceptanceCase(10, "case-10-interruption-restart-boundaries", PERIOD_ONE_SCOPE, ("interrupt-import", "interrupt-verification", "interrupt-commit", "interrupt-dispatch", "interrupt-recovery"), 20, PROGRAM_TOTAL_CENTS, 19, (H_ITEM_ID,), (H_REJECTED_CORRECTION,), (), (CORRECTION_ACTION_READY,), (), ("restart-coherent", "reservation-not-refunded", "no-receiver-guarantee"))
CASE_11 = AcceptanceCase(11, "case-11-shadow-export-restore", PERIOD_ONE_SCOPE, ("export-open-dispute", "restore-shadow", "continue-to-completion"), 20, PROGRAM_TOTAL_CENTS, 20, (), (H_ACKNOWLEDGED, H_P3_REPLACED), (ACTION_ACK_EVIDENCE.evidence_id,), (CORRECTION_ACTION_ACKNOWLEDGED,), (), ("evidence-reference-available", "shadow-dispatch-disabled", "no-second-live-writer", "deduplicated-action"))
CASE_12 = AcceptanceCase(12, "case-12-isolation-oversize-canary", PERIOD_ONE_SCOPE, ("cross-scope-command", "submit-oversized-package", "emit-safe-diagnostic"), 20, PROGRAM_TOTAL_CENTS, 20, (), (H_P3_REPLACED,), (), (), (RejectionExpectation("cross-scope-command", "FOREIGN_SCOPE", "period_scope", False),), ("corporate-egress-disabled", "oversize-no-mutation", "synthetic-canary-only"))

REVISION_RACE = RevisionRaceExpectation(H_OBLIGATION_ID, 1, 1, 1, "obligation_revision_conflict", 1, 1, 1)
INTERRUPTION_EXPECTATIONS = (
    InterruptionExpectation("IMPORT", "staged-partial-import-retained", True, False, "none"),
    InterruptionExpectation("VERIFICATION_HANDOFF", "restart-requires-fresh-evidence", True, True, "none"),
    InterruptionExpectation("COMMIT", "transaction-rolls-back-or-is-fully-visible", True, True, "none"),
    InterruptionExpectation("DISPATCH", "action-remains-state-owned", True, True, "disabled"),
    InterruptionExpectation("RECOVERY", "reopen-reads-last-committed-state", True, True, "none"),
)
CONTINUITY = ContinuityExpectation(
    "RR/FINANCIAL/CONTINUITY/v5", CASE_11.case_id, "SHADOW", False, False,
    ("control_packs", "populations", "obligations", "evidence_references", "evaluations", "cases", "determinations", "actions", "outbox_state"),
    ("raw_evidence_bytes", "secrets", "private_proof_material", "external_payment_credentials"), True, True, 0,
)
BOUNDARY_EXPECTATIONS = BoundaryExpectation(
    ("state_id", "deployment_id", "program_id", "period_id", "currency"), True,
    8_388_608, 8_388_609, True, "SYNTHETIC-SENSITIVE-CANARY", False, False,
    ("stage", "error_code", "scope", "record_count"),
)

ACCEPTANCE_CASES = (CASE_01, CASE_02, CASE_03, CASE_04, CASE_05, CASE_06, CASE_07, CASE_08, CASE_09, CASE_10, CASE_11, CASE_12)

__all__ = (
    "ScopeExpectation", "ControlPackExpectation", "PopulationItemExpectation", "EvidenceExpectation",
    "BalanceExpectation", "ActionExpectation", "RejectionExpectation", "RevisionRaceExpectation",
    "InterruptionExpectation", "ContinuityExpectation", "BoundaryExpectation", "AcceptanceCase",
    "STATE_ID", "DEPLOYMENT_ID", "PROGRAM_ID", "CURRENCY", "PERIOD_ONE_ID", "PERIOD_TWO_ID",
    "POPULATION_ONE_ID", "POPULATION_TWO_ID", "PERIOD_ONE_START_MS", "PERIOD_ONE_END_MS",
    "PERIOD_TWO_START_MS", "PERIOD_TWO_END_MS", "H_DUE_AT_MS", "H_ITEM_ID", "OTHER_ITEM_IDS",
    "ITEM_IDS", "H_OWED_CENTS", "OTHER_ITEM_CENTS", "FINAL_OTHER_ITEM_CENTS", "OTHER_TOTAL_CENTS",
    "PROGRAM_TOTAL_CENTS", "H_CASH_CENTS", "UNAPPROVED_OFFSET_CENTS", "CORRECTION_PAYMENT_CENTS",
    "CONFLICTING_P2_CENTS", "PERIOD_ONE_SCOPE", "PERIOD_TWO_SCOPE", "PROGRAM_ITEMS",
    "CONTROL_PACK_V1", "CONTROL_PACK_V2", "CONTROL_PACKS", "OTHER_SUPPORT_EVIDENCE", "H_EVIDENCE",
    "H_CASH_EVIDENCE", "OFFSET_CLAIM_EVIDENCE", "OFFSET_SUPPORT_EVIDENCE", "OFFSET_APPROVAL_EVIDENCE",
    "CORRECTION_AUTH_EVIDENCE", "ACTION_ACK_EVIDENCE", "P2_PAYMENT_EVIDENCE", "P2_CONFIRMATION_EVIDENCE",
    "P2_CONFLICT_EVIDENCE", "REPORT_ORIGINAL_EVIDENCE", "REPORT_CORRECTION_EVIDENCE",
    "P2_REVERSAL_EVIDENCE", "P3_REPLACEMENT_EVIDENCE", "P2_EVIDENCE_ID", "P2_REVERSAL_EVIDENCE_ID",
    "ALL_EVIDENCE", "H_MISSING", "H_CASH_AND_CLAIM", "H_AUTHORIZED_OFFSET", "H_REJECTED_CORRECTION",
    "H_ACKNOWLEDGED", "H_P2_RECEIVED_LATE", "H_REPORT_CORRECTED_LATE", "H_P2_DUPLICATE_UNCHANGED",
    "H_P2_CONFLICT_VISIBLE", "H_P2_REVERSED", "H_P3_REPLACED", "OFFSET_ACTION_READY",
    "CORRECTION_ACTION_READY", "CORRECTION_ACTION_ACKNOWLEDGED", "UNAUTHORIZED_REJECTION",
    "STALE_REJECTION", "ACTION_PAYLOAD_REJECTION", "REVISION_RACE", "INTERRUPTION_EXPECTATIONS",
    "CONTINUITY", "BOUNDARY_EXPECTATIONS", "CASE_01", "CASE_02", "CASE_03", "CASE_04", "CASE_05",
    "CASE_06", "CASE_07", "CASE_08", "CASE_09", "CASE_10", "CASE_11", "CASE_12", "ACCEPTANCE_CASES",
)
