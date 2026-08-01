from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / "provider_portal"
SHARED_STYLES = ROOT / "portal_shared" / "foundation.css"


def _read(name: str) -> str:
    return (PORTAL / name).read_text(encoding="utf-8")


def test_provider_portal_uses_same_desk_design_language() -> None:
    css = _read("styles.css")
    shared_css = SHARED_STYLES.read_text(encoding="utf-8")
    html = _read("index.html")

    assert '/shared-static/foundation.css' in css
    assert "Source Serif 4" in shared_css
    assert "Public Sans" in shared_css
    assert "IBM Plex Mono" in shared_css
    assert 'html[data-theme="dark"]' in shared_css
    assert "--bg: #D8CDB9" in shared_css
    assert "letter-spacing: -" not in css

    assert "Provider Packet Desk" in html
    assert 'class="app"' in html
    assert 'class="layout"' in html
    assert 'id="queueList"' in html
    assert 'id="workspacePane"' in html
    assert 'id="railPane"' in html
    assert 'id="drawer"' in html
    assert 'data-filter="action_needed"' in html
    assert 'data-filter="corrections"' in html
    assert 'data-filter="submitted"' in html
    assert 'data-filter="accepted"' in html
    assert 'data-filter="closed"' in html
    assert "/provider-static/styles.css" in html
    assert "/provider-static/app.js" in html


def test_static_provider_markup_classes_are_backed_by_stylesheet() -> None:
    css = _read("styles.css")
    html = _read("index.html")

    css_classes = set(re.findall(r"\.([A-Za-z_][\w-]*)", css))
    html_classes: set[str] = set()
    for class_attr in re.findall(r'class="([^"]+)"', html):
        html_classes.update(class_attr.split())

    missing = sorted(name for name in html_classes if name not in css_classes)
    assert missing == []


def test_provider_workflow_state_machine_is_explicit_and_narrow() -> None:
    js = _read("app.js")

    required_symbols = [
        "const INITIAL_REQUESTS",
        "const STATUS_META",
        "function primaryActionForRequest(",
        "function shortHash(",
        "function uniqueHistory(",
        "function uniqueNames(",
        "function attachmentName(",
        "function requestByClaimOrRequest(",
        "function selectedFileAttachments(",
        "function mergeAttachments(",
        "function attachmentCount(",
        "function renderHashField(",
        "function renderQueue()",
        "function renderWorkspace()",
        "function renderFacts(",
        "function renderPacketList(",
        "function renderActionPanel(",
        "function openPacketDrawer(",
        "function packetErrors(",
        "function saveDraft(",
        "function submitPacket(",
        "function openNoteDrawer(",
        "function submitNote(",
        "function openRequestDrawer(",
        "function openReceiptDrawer(",
        "function openHistoryDrawer(",
        "function sendProviderPacket(",
        "function sendProviderMessage(",
        "function mergeProviderWorkspace(",
        "function loadProviderWorkspace(",
        "function recordProviderEvent(",
        "function copyValue(",
        "function setActionBusy(",
        "function moveSelection(",
        "function handleCommand(",
    ]
    for symbol in required_symbols:
        assert symbol in js

    for marker in (
        "Prior authorization packet required",
        "Correction needed on authorization dates",
        "Packet submitted, awaiting payer review",
        "Authorization accepted, release pending",
        "Provider NPI",
        "Member / program",
        "Service date",
        "Procedure / units",
        "Auth window",
        "PA lookup",
        "Policy citation",
        "Packet checklist",
        "Prior authorization number",
        "Authorization effective date window",
        "Submit packet",
        "Submit correction",
        "Save draft",
        "Upload authorization documents",
        "packet attachment",
        "content_base64",
        "Staged files",
        "Attachments",
        "No request selected",
        "Latest activity",
        "copy_value",
        "Ask payer question",
        "Withdraw claim",
        "Closed",
        "View receipt",
        "Request log",
        "/api/provider-packets",
        "/api/provider-messages",
        "/api/provider-events",
        "/api/provider-workspace",
        "received by payer service",
        "Payer message received",
        "payer_document_request_sent",
        "local-provider-token",
    ):
        assert marker in js

    forbidden_operator_actions = [
        "release_payment",
        "verify_authorization",
        "mark_docs_received",
        "deny_claim",
        "route_clinical",
        "override_review",
        "/api/operator-events",
    ]
    for marker in forbidden_operator_actions:
        assert marker not in js


def test_provider_portal_does_not_reintroduce_fake_estimates_or_old_shell() -> None:
    combined = _read("index.html") + "\n" + _read("app.js")

    for marker in (
        "28-39",
        "~25",
        "min remaining",
        "Medi-Cal Claims Inbox",
        "Medi-Cal Settlement Desk",
        "Batch Evidence",
        "Trust & Audit",
        "Trust and audit",
    ):
        assert marker not in combined
