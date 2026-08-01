from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / "operator_portal"
SHARED_STYLES = ROOT / "portal_shared" / "foundation.css"


def _read(name: str) -> str:
    return (PORTAL / name).read_text(encoding="utf-8")


def test_portal_uses_intended_claims_inbox_design_system() -> None:
    css = _read("styles.css")
    shared_css = SHARED_STYLES.read_text(encoding="utf-8")
    html = _read("index.html")

    assert '/shared-static/foundation.css' in css
    assert "Source Serif 4" in shared_css
    assert "Public Sans" in shared_css
    assert "IBM Plex Mono" in shared_css
    assert 'html[data-theme="dark"]' in shared_css
    assert ".receipt-card.receipt-hero" in css
    assert ".drawer-provenance" in css
    assert ".queue-row.selected" in css
    assert "--bg: #D8CDB9" in shared_css
    assert "letter-spacing: -" not in css, "negative letter spacing must stay out of the dashboard skin"

    assert "Medi-Cal Claims Inbox" in html
    assert 'class="app"' in html
    assert 'class="layout"' in html
    assert 'id="queueList"' in html
    assert 'id="decisionPane"' in html
    assert 'id="railPane"' in html
    assert 'id="drawer"' in html
    assert 'data-filter="missing_auth"' in html
    assert 'data-filter="ready_for_release"' in html


def test_static_markup_classes_are_backed_by_the_stylesheet() -> None:
    css = _read("styles.css")
    html = _read("index.html")

    css_classes = set(re.findall(r"\.([A-Za-z_][\w-]*)", css))
    html_classes: set[str] = set()
    for class_attr in re.findall(r'class="([^"]+)"', html):
        html_classes.update(class_attr.split())

    missing = sorted(name for name in html_classes if name not in css_classes)
    assert missing == []


def test_old_settlement_dashboard_shell_does_not_return() -> None:
    html = _read("index.html")
    js = _read("app.js")
    combined = html + "\n" + js

    stale_shell_markers = [
        "Medi-Cal Settlement Desk",
        "Claim Intake",
        "Batch Evidence",
        "Claims Waiting",
        "Decision History",
        "runDemoBatch",
        "submitBatch",
        "openIntakeDrawer",
        "openRootsDrawer",
        "data-command=\"new-claim\"",
    ]
    for marker in stale_shell_markers:
        assert marker not in combined


def test_header_does_not_show_fake_time_estimates() -> None:
    html = _read("index.html")
    js = _read("app.js")
    combined = html + "\n" + js

    fake_estimate_markers = [
        "28-39",
        "~25",
        "min remaining",
    ]
    for marker in fake_estimate_markers:
        assert marker not in combined


def test_claims_inbox_state_machine_is_explicit_and_receipt_centered() -> None:
    js = _read("app.js")

    required_symbols = [
        "const DECISION_MODEL",
        "const CLAIM_FACTS_BY_ID",
        "function transitionClaim(",
        "function workBuckets(",
        "function requiredDocsSummary(",
        "function renderActionLedger(",
        "function prepareRequest(",
        "function markDocsReceived(",
        "function verifyAuthorization(",
        "function primaryActionForClaim(",
        "function renderQueue()",
        "function renderDecision()",
        "function renderCaseFacts(",
        "function renderReceipt(",
        "function renderDocsReceived(",
        "function renderRail()",
        "function evidenceChecksForClaim(",
        "function queueSortLabel(",
        "function openRequestDrawer(",
        "function startHoldToSend(",
        "function openDecisionNoteDrawer(",
        "function confirmPendingDecision(",
        "function openDecisionDrawer()",
        "function openPredicatesDrawer()",
        "function openEvidenceDrawer()",
        "function openHistoryDrawer()",
        "function openSystemAuditDrawer()",
        "function loadAuditLog(",
        "function recordOperatorAuditEvent(",
        "function renderAuditAttachments(",
        "function providerPacketEventForClaim(",
        "function renderClaimPacketAttachments(",
        "function downloadAttachment(",
        "function moveSelection(",
        "function handleCommand(",
    ]
    for symbol in required_symbols:
        assert symbol in js

    for marker in (
        "Documentation request sent",
        "Provider documentation requested",
        "Waiting on provider packet",
        "Verify packet before release",
        "action-card",
        "action-ledger",
        "fact-wide",
        "docs_received",
        "verify_authorization",
        "Verify authorization",
        "Payment remains held",
        "G1_PRIOR_AUTH_REQUIRED",
        "DOC-REQ-",
        "AUD-OP-",
        "receipt-card receipt-hero",
        "Case record",
        "Provider NPI",
        "Auth window",
        "PA lookup",
        "System audit",
        "/api/audit-log",
        "/api/operator-events",
        "...(auditEvent.metadata || {})",
        "HOLD_TO_SEND_MS",
        "confirm_prepare_request",
        "Hold 1.6s to send",
        "Internal rationale",
        "policyCitation",
        "hasMoreDecisions",
    ):
        assert marker in js

    simple_outcome_source = js[js.index("function renderSimpleOutcome(") : js.index("function renderRail()")]
    assert "DECISION_MODEL[claim.workflowState]" in simple_outcome_source
    assert 'data-action="open_decisions"' in simple_outcome_source


def test_officer_workstation_facts_do_not_regress_to_generic_dashboard_copy() -> None:
    css = _read("styles.css")
    html = _read("index.html")
    js = _read("app.js")
    combined = html + "\n" + js

    for marker in (
        "case-facts",
        "PA.T1019.2026",
        "providerNpi",
        "serviceDate",
        "No active PA for T1019",
        "837 claim file readable and bound",
        "Primary action",
        "audit-stream",
        "System audit",
        "Sorted by SLA risk",
        "hold-send-button",
        "internal-note-textarea",
        "sortSelect",
        "Sort work queue",
        "Audit trail",
        "Latest system event",
        "Provider packet available",
        "download_attachment",
        "/api/provider-packets/",
    ):
        assert marker in combined + "\n" + css

    old_generic_markers = [
        "Evidence summary",
        "Request receipt preview",
        "Trust & Audit",
        "Trust and audit",
    ]
    for marker in old_generic_markers:
        assert marker not in combined


def test_other_decisions_are_state_transitions_not_read_only_utilities() -> None:
    js = _read("app.js")

    assert "Available decisions" in js
    assert "deny_claim" in js
    assert "route_clinical" in js
    assert "override_review" in js
    assert "mark_docs_received" in js
    assert "verify_authorization" in js
    assert "release_payment" in js

    drawer_source = js[js.index("function openDecisionDrawer()") : js.index("function renderDecisionButton")]
    forbidden_in_decision_drawer = ["open_evidence", "view_history", "view_predicates", "focus-search"]
    for marker in forbidden_in_decision_drawer:
        assert marker not in drawer_source
