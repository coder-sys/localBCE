const PORTAL_TOKEN = localStorage.getItem("blProviderPortalToken") || "local-provider-token";

const INITIAL_REQUESTS = [
  {
    id: "req-042",
    claimId: "BL-CLAIM-AUTH-042",
    requestId: "DOC-REQ-042",
    title: "Prior authorization packet required",
    status: "needs_packet",
    provider: "North Valley Home Health",
    providerNpi: "1999999984",
    payer: "Medi-Cal",
    member: "M-CA-4821-042",
    program: "Managed care",
    serviceDate: "Jun 12, 2026",
    procedure: "T1019",
    units: "22 hours",
    amountCents: 125000,
    dueRank: 1,
    dueLabel: "Due today",
    paymentState: "Held by payer",
    policyCitation: "Medi-Cal PCS prior authorization rule",
    paLookup: "No active authorization on file for T1019",
    authWindow: "Must cover Jun 12, 2026",
    issue: "No matching prior authorization was attached to the claim.",
    requiredDocs: [
      { id: "pa_number", label: "Prior authorization number", state: "missing" },
      { id: "effective_dates", label: "Authorization effective date window", state: "missing" },
      { id: "procedure_match", label: "Procedure code T1019 match", state: "missing" },
      { id: "signed_packet", label: "Signed authorization document", state: "missing" },
    ],
    receipt: null,
    draft: null,
    history: [
      { at: "Jun 18, 09:42 AM", actor: "Medi-Cal", action: "Documentation request opened", detail: "Payment remains held pending provider packet." },
    ],
  },
  {
    id: "req-144",
    claimId: "BL-CLAIM-AUTH-144",
    requestId: "DOC-REQ-144",
    title: "Correction needed on authorization dates",
    status: "needs_correction",
    provider: "East Bay Home Care",
    providerNpi: "1666666650",
    payer: "Medi-Cal",
    member: "M-CA-1188-144",
    program: "Managed care",
    serviceDate: "Jun 9, 2026",
    procedure: "T1019",
    units: "12 hours",
    amountCents: 70500,
    dueRank: 2,
    dueLabel: "Due tomorrow",
    paymentState: "Held by payer",
    policyCitation: "Medi-Cal PCS prior authorization rule",
    paLookup: "PA found, date window mismatch",
    authWindow: "Submitted PA starts Jun 10, 2026",
    issue: "The payer found a PA number, but the effective dates do not cover the service date.",
    requiredDocs: [
      { id: "corrected_dates", label: "Corrected authorization date page", state: "blocked" },
      { id: "pa_number", label: "Prior authorization number", state: "complete" },
      { id: "procedure_match", label: "Procedure code T1019 match", state: "complete" },
    ],
    receipt: { id: "DOC-REC-144", sentAt: "Jun 18, 12:06 PM", auditId: "PROV-AUD-144", hash: "7879f58296a99aefafb7012d8f9a315af35bb999c10d6f80e403337d6f4402ec", attachmentCount: 1 },
    draft: null,
    history: [
      { at: "Jun 18, 12:06 PM", actor: "Provider office", action: "Packet submitted", detail: "Authorization packet sent to payer." },
      { at: "Jun 18, 03:18 PM", actor: "Medi-Cal", action: "Correction requested", detail: "Effective dates did not cover the service date." },
    ],
  },
  {
    id: "req-208",
    claimId: "BL-CLAIM-AUTH-208",
    requestId: "DOC-REQ-208",
    title: "Packet submitted, awaiting payer review",
    status: "submitted",
    provider: "Golden State Therapy",
    providerNpi: "1555555542",
    payer: "Medi-Cal",
    member: "M-CA-7720-208",
    program: "Fee for service",
    serviceDate: "Jun 7, 2026",
    procedure: "97110",
    units: "4 units",
    amountCents: 61000,
    dueRank: 5,
    dueLabel: "Waiting on payer",
    paymentState: "Held by payer",
    policyCitation: "Physical therapy authorization policy",
    paLookup: "Provider packet received by payer",
    authWindow: "May 30, 2026 to Jun 30, 2026",
    issue: "The packet was submitted and is waiting for payer review.",
    requiredDocs: [
      { id: "pa_number", label: "Prior authorization number", state: "complete" },
      { id: "effective_dates", label: "Authorization effective date window", state: "complete" },
      { id: "procedure_match", label: "Procedure code 97110 match", state: "complete" },
      { id: "signed_packet", label: "Signed authorization document", state: "complete" },
    ],
    receipt: { id: "DOC-REC-208", sentAt: "Jun 17, 02:21 PM", auditId: "PROV-AUD-208", hash: "e20015a104fc8083d6d146195fe9f68445714bd12484f0f25b5f1ffb0a316c80", attachmentCount: 2 },
    draft: null,
    history: [
      { at: "Jun 17, 02:21 PM", actor: "Provider office", action: "Packet submitted", detail: "Receipt DOC-REC-208 recorded." },
    ],
  },
  {
    id: "req-263",
    claimId: "BL-CLAIM-AUTH-263",
    requestId: "DOC-REQ-263",
    title: "Authorization accepted, release pending",
    status: "accepted",
    provider: "Capital Family Services",
    providerNpi: "1333333326",
    payer: "Medi-Cal",
    member: "M-CA-8041-263",
    program: "Managed care",
    serviceDate: "Jun 4, 2026",
    procedure: "T1020",
    units: "8 hours",
    amountCents: 89000,
    dueRank: 8,
    dueLabel: "Accepted",
    paymentState: "Release pending",
    policyCitation: "Home support prior authorization rule",
    paLookup: "Authorization accepted by payer",
    authWindow: "Jun 1, 2026 to Jun 30, 2026",
    issue: "The authorization matched. Payer release remains outside provider control.",
    requiredDocs: [
      { id: "pa_number", label: "Prior authorization number", state: "complete" },
      { id: "effective_dates", label: "Authorization effective date window", state: "complete" },
      { id: "procedure_match", label: "Procedure code T1020 match", state: "complete" },
      { id: "signed_packet", label: "Signed authorization document", state: "complete" },
    ],
    receipt: { id: "DOC-REC-263", sentAt: "Jun 16, 10:04 AM", auditId: "PROV-AUD-263", hash: "44b2596518390ac550b97cecad37a8e5e8709487d055888bdd5d48a387f69612", attachmentCount: 2 },
    draft: null,
    history: [
      { at: "Jun 16, 10:04 AM", actor: "Provider office", action: "Packet submitted", detail: "Receipt DOC-REC-263 recorded." },
      { at: "Jun 17, 08:31 AM", actor: "Medi-Cal", action: "Authorization accepted", detail: "Payment release remains pending payer batch." },
    ],
  },
];

const STATUS_META = {
  needs_packet: { label: "Action needed", className: "action", rank: 0, primary: "Prepare packet" },
  draft: { label: "Draft saved", className: "draft", rank: 1, primary: "Continue packet" },
  needs_correction: { label: "Correction", className: "correction", rank: 0, primary: "Prepare correction" },
  submitted: { label: "Submitted", className: "submitted", rank: 3, primary: "View receipt" },
  accepted: { label: "Accepted", className: "accepted", rank: 4, primary: "View receipt" },
  released: { label: "Released", className: "accepted", rank: 5, primary: "View receipt" },
  denied: { label: "Denied", className: "closed", rank: 5, primary: "View history" },
  withdrawn: { label: "Withdrawn", className: "closed", rank: 5, primary: "View history" },
};

let requests = structuredClone(INITIAL_REQUESTS);
let selectedId = requests[0].id;
let activeFilter = "action_needed";
let activeSort = "status_due";
let searchQuery = "";
let drawerMode = "";

const $ = (selector) => document.querySelector(selector);

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatCurrency(cents) {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(Number(cents || 0) / 100);
}

function uniqueNames(names) {
  return Array.from(new Set((names || []).map((name) => String(name || "").trim()).filter(Boolean)));
}

function attachmentName(attachment) {
  return typeof attachment === "string" ? attachment : attachment?.name || attachment?.filename || "";
}

function attachmentSize(attachment) {
  return typeof attachment === "object" && attachment ? Number(attachment.sizeBytes || attachment.size_bytes || 0) : 0;
}

function shortHash(hash) {
  const value = String(hash || "");
  return value.length > 24 ? `${value.slice(0, 12)}...${value.slice(-8)}` : value;
}

function uniqueHistory(request) {
  const seen = new Set();
  return (request?.history || []).filter((item) => {
    const key = `${item.actor}|${item.detail}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function attachmentCount(request) {
  return request.draft?.attachments?.length || request.receipt?.attachmentCount || request.receipt?.attachments?.length || 0;
}

function fileCountLabel(count) {
  return count === 1 ? "1 file" : `${count} files`;
}

function attachmentLabel(request) {
  return fileCountLabel(attachmentCount(request));
}

function nowStamp() {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date());
}

function requestById(id) {
  return requests.find((request) => request.id === id) || requests[0];
}

function requestByClaimOrRequest(claimId, requestId) {
  return requests.find((request) => request.claimId === claimId || request.requestId === requestId);
}

function selectedRequest() {
  return selectedId ? requestById(selectedId) : null;
}

function statusMeta(status) {
  return STATUS_META[status] || STATUS_META.needs_packet;
}

function matchesFilter(request) {
  if (activeFilter === "action_needed") return ["needs_packet", "draft", "needs_correction"].includes(request.status);
  if (activeFilter === "corrections") return request.status === "needs_correction";
  if (activeFilter === "submitted") return request.status === "submitted";
  if (activeFilter === "accepted") return ["accepted", "released"].includes(request.status);
  if (activeFilter === "closed") return ["withdrawn", "denied"].includes(request.status);
  return true;
}

function searchableText(request) {
  return [
    request.title,
    request.claimId,
    request.requestId,
    request.provider,
    request.providerNpi,
    request.member,
    request.procedure,
    request.issue,
    ...(request.draft?.attachments || []).map(attachmentName),
    ...(request.receipt?.attachments || []).map(attachmentName),
  ].join(" ").toLowerCase();
}

function sortedRequests(list) {
  return [...list].sort((a, b) => {
    if (activeSort === "amount") return b.amountCents - a.amountCents || a.dueRank - b.dueRank;
    if (activeSort === "due") return a.dueRank - b.dueRank || statusMeta(a.status).rank - statusMeta(b.status).rank;
    return statusMeta(a.status).rank - statusMeta(b.status).rank || a.dueRank - b.dueRank;
  });
}

function visibleRequests() {
  const query = searchQuery.trim().toLowerCase();
  return sortedRequests(requests.filter((request) => matchesFilter(request) && (!query || searchableText(request).includes(query))));
}

function ensureSelection() {
  const visible = visibleRequests();
  if (!visible.length) {
    selectedId = "";
    return;
  }
  if (!visible.some((request) => request.id === selectedId)) {
    selectedId = visible[0].id;
  }
}

function workBuckets() {
  return {
    action: requests.filter((request) => ["needs_packet", "draft", "needs_correction"].includes(request.status)).length,
    waiting: requests.filter((request) => request.status === "submitted").length,
    accepted: requests.filter((request) => request.status === "accepted").length,
    withdrawn: requests.filter((request) => ["withdrawn", "denied", "released"].includes(request.status)).length,
  };
}

function filterLabel() {
  return {
    action_needed: "Action needed",
    corrections: "Corrections",
    submitted: "Submitted",
    accepted: "Accepted",
    closed: "Closed",
  }[activeFilter] || "Packet queue";
}

function primaryActionForRequest(request) {
  if (!request) return "";
  if (request.status === "needs_packet" || request.status === "draft") return "prepare_packet";
  if (request.status === "needs_correction") return "prepare_correction";
  if (["submitted", "accepted", "released"].includes(request.status)) return "view_receipt";
  return "view_history";
}

function render() {
  ensureSelection();
  renderHeader();
  renderQueue();
  renderWorkspace();
  renderRail();
}

function scrollMainPanesToTop() {
  ["#workspacePane", "#railPane"].forEach((selector) => {
    const pane = $(selector);
    if (pane) {
      pane.scrollTop = 0;
      pane.scrollLeft = 0;
    }
  });
}

function renderNavigationChange() {
  render();
  scrollMainPanesToTop();
}

function renderHeader() {
  const buckets = workBuckets();
  $("#sessionSummary").textContent = `${buckets.action} action · ${buckets.waiting} waiting · ${buckets.accepted} accepted · ${buckets.withdrawn} closed`;
  $("#queueTitle").textContent = "Packet queue";
  $("#queueSort").textContent = activeSort === "amount" ? "Sorted by amount" : activeSort === "due" ? "Sorted by due date" : "Sorted by urgency, due date";
  $("#queueCount").textContent = String(visibleRequests().length);
  document.querySelectorAll(".filter").forEach((button) => {
    button.classList.toggle("active", button.dataset.filter === activeFilter);
  });
}

function renderQueue() {
  const list = visibleRequests();
  const target = $("#queueList");
  if (!list.length) {
    target.innerHTML = `
      <div class="empty-state">
        <h2>No requests here</h2>
        <p>Try another view or search term.</p>
      </div>
    `;
    return;
  }
  target.innerHTML = list.map((request) => {
    const meta = statusMeta(request.status);
    return `
      <button class="queue-row ${request.id === selectedId ? "selected" : ""}" type="button" role="option" aria-selected="${request.id === selectedId}" data-select="${escapeHtml(request.id)}">
        <span>
          <span class="row-title">${escapeHtml(request.title)}</span>
          <span class="row-id">${escapeHtml(request.claimId)}</span>
          <span class="row-meta">${escapeHtml(request.member)} · ${escapeHtml(request.procedure)} · ${escapeHtml(request.units)}</span>
        </span>
        <span class="row-side">
          <span class="row-amount">${escapeHtml(formatCurrency(request.amountCents))}</span>
          <span class="row-state"><span class="status-pill ${meta.className}">${escapeHtml(meta.label)}</span></span>
          <span class="row-due">${escapeHtml(request.dueLabel)}</span>
        </span>
      </button>
    `;
  }).join("");
}

function renderWorkspace() {
  const request = selectedRequest();
  if (!request) {
    $("#workspacePane").innerHTML = `
      <div class="empty-state empty-state-pane">
        <h2>No request selected</h2>
        <p>This view has no matching provider work. Choose another queue.</p>
      </div>
    `;
    return;
  }
  const meta = statusMeta(request.status);
  const primaryAction = primaryActionForRequest(request);
  $("#workspacePane").innerHTML = `
    <div class="workspace-head">
      <span class="status-pill ${meta.className}">${escapeHtml(meta.label)}</span>
      <h1>${escapeHtml(request.title)}</h1>
      <p class="request-identity mono">${escapeHtml(request.claimId)} · ${escapeHtml(formatCurrency(request.amountCents))} · ${escapeHtml(request.payer)}</p>
      <div class="rule-strip">
        <span class="rule-strip-id">${escapeHtml(requestReasonLabel(request))}</span>
        <p>${escapeHtml(request.issue)}</p>
      </div>
    </div>

    <div class="work-grid">
      <p class="section-label">Claim facts</p>
      ${renderFacts(request)}
      <div class="workspace-columns">
        <div class="primary-column">
          ${renderActionPanel(request, meta, primaryAction)}
          ${renderReceiptPanel(request)}
        </div>
        <div class="secondary-column">
          ${renderPacketList(request)}
        </div>
      </div>
    </div>
  `;
}

function renderFacts(request) {
  const facts = [
    ["Member / program", `${request.member} · ${request.program}`],
    ["Service date", request.serviceDate],
    ["Procedure / units", `${request.procedure} · ${request.units}`],
    ["Auth window", request.authWindow],
    ["PA lookup", request.paLookup],
    ["Policy citation", request.policyCitation],
  ];
  return `
    <dl class="fact-list">
      ${facts.map(([label, value]) => `
        <div>
          <dt>${escapeHtml(label)}</dt>
          <dd>${escapeHtml(value)}</dd>
        </div>
      `).join("")}
    </dl>
  `;
}

function requestReasonLabel(request) {
  if (request.status === "needs_packet" || request.status === "draft") return "PA required";
  if (request.status === "needs_correction") return "Date window";
  if (request.status === "submitted") return "Payer review";
  if (request.status === "accepted") return "Release pending";
  if (request.status === "released") return "Released";
  if (request.status === "denied") return "Denied";
  return "Closed";
}

function renderPacketList(request) {
  const openItems = request.requiredDocs.filter((item) => item.state !== "complete").length;
  return `
    <div class="packet-list">
      <h2>Packet checklist</h2>
      <p class="packet-summary">${escapeHtml(openItems ? `${openItems} item${openItems === 1 ? "" : "s"} required before submission` : "All packet items are present")}</p>
      <div class="packet-items">
        ${request.requiredDocs.map((item) => {
          const stateText = item.state === "complete" ? "Present" : item.state === "blocked" ? "Needs correction" : "";
          return `
          <div class="packet-item ${item.state === "complete" ? "complete" : item.state === "blocked" ? "blocked" : ""}">
            <span class="packet-dot" aria-hidden="true"></span>
            <span>
              <strong>${escapeHtml(item.label)}</strong>
              ${stateText ? `<p>${escapeHtml(stateText)}</p>` : ""}
            </span>
          </div>
        `;}).join("")}
      </div>
    </div>
  `;
}

function renderActionPanel(request, meta, primaryAction) {
  const secondary = secondaryActionsForRequest(request);
  return `
    <section class="action-panel">
      <p class="section-label">Next step</p>
      <h2>${escapeHtml(actionHeading(request))}</h2>
      <p>${escapeHtml(actionCopy(request))}</p>
      <div class="button-row">
        <button class="button primary" type="button" data-action="${escapeHtml(primaryAction)}">${escapeHtml(meta.primary)}</button>
        ${secondary.map((action) => `<button class="button" type="button" data-action="${escapeHtml(action.id)}">${escapeHtml(action.label)}</button>`).join("")}
      </div>
    </section>
  `;
}

function actionCopy(request) {
  if (request.status === "needs_packet") return "Attach the authorization packet, verify the date and procedure match, then submit it to the payer.";
  if (request.status === "draft") return "A draft is saved locally. Finish the missing packet checks before submitting.";
  if (request.status === "needs_correction") return "Correct only the item the payer returned, then resubmit the packet against the same request.";
  if (request.status === "submitted") return "The payer has the packet. Keep the receipt for reconciliation and wait for payer review.";
  if (request.status === "accepted") return "The authorization matched. Payment release is now a payer-side batch operation.";
  if (request.status === "released") return "The payer released payment. Keep this receipt for reconciliation.";
  if (request.status === "denied") return "The payer denied the claim. Review the payer note before resubmitting or appealing.";
  return "This request is closed for provider action.";
}

function actionHeading(request) {
  if (request.status === "needs_packet") return "Complete the packet";
  if (request.status === "draft") return "Finish the packet";
  if (request.status === "needs_correction") return "Fix the returned field";
  if (request.status === "submitted") return "Keep the receipt";
  if (request.status === "accepted") return "Reconcile release";
  if (request.status === "released") return "Payment released";
  if (request.status === "denied") return "Claim denied";
  return "Review the record";
}

function secondaryActionsForRequest(request) {
  if (["needs_packet", "draft", "needs_correction"].includes(request.status)) {
    return [
      { id: "request_clarification", label: "Ask payer question" },
      { id: "withdraw_claim", label: "Withdraw claim" },
      { id: "view_request", label: "View request" },
    ];
  }
  if (request.status === "submitted") {
    return [
      { id: "request_clarification", label: "Message payer" },
      { id: "view_request", label: "View request" },
    ];
  }
  return [
    { id: "view_request", label: "View request" },
    { id: "view_history", label: "View history" },
  ];
}

function renderHashField(label, hash) {
  if (!hash) return `<div><dt>${escapeHtml(label)}</dt><dd class="mono">Pending</dd></div>`;
  return `
    <div>
      <dt>${escapeHtml(label)}</dt>
      <dd class="mono hash-value" title="${escapeHtml(hash)}">
        <span>${escapeHtml(shortHash(hash))}</span>
        <button class="copy-button" type="button" data-action="copy_value" data-copy-value="${escapeHtml(hash)}">Copy</button>
      </dd>
    </div>
  `;
}

function renderReceiptPanel(request) {
  if (!request.receipt) {
    return `
      <section class="receipt-panel">
        <p class="section-label">Receipt</p>
        <h2>No packet sent yet</h2>
        <p>The payer will return a receipt after submission.</p>
      </section>
    `;
  }
  return `
    <section class="receipt-panel">
      <p class="section-label">Receipt</p>
      <h2>${escapeHtml(request.receipt.id)}</h2>
      <dl class="receipt-list">
        <div><dt>Sent</dt><dd>${escapeHtml(request.receipt.sentAt)}</dd></div>
        <div><dt>Audit ID</dt><dd class="mono">${escapeHtml(request.receipt.auditId)}</dd></div>
        ${renderHashField("Packet hash", request.receipt.hash)}
        <div><dt>Attachments</dt><dd>${escapeHtml(attachmentLabel(request))}</dd></div>
      </dl>
    </section>
  `;
}

function renderRail() {
  const request = selectedRequest();
  if (!request) {
    $("#railPane").innerHTML = `
      <section class="rail-section">
        <p class="rail-kicker">Provider record</p>
        <h2>No active item</h2>
        <p class="rail-muted">Queue filters can be changed from the top bar.</p>
      </section>
    `;
    return;
  }
  const activity = uniqueHistory(request).slice(0, 5);
  $("#railPane").innerHTML = `
    <section class="rail-section">
      <p class="rail-kicker">Provider record</p>
      <h2>${escapeHtml(request.provider)}</h2>
      <dl class="rail-list">
        <div><dt>Provider NPI</dt><dd class="mono">${escapeHtml(request.providerNpi)}</dd></div>
      </dl>
    </section>
    <section class="rail-section">
      <p class="rail-kicker">Request record</p>
      <dl class="rail-list">
        <div><dt>Request</dt><dd class="mono">${escapeHtml(request.requestId)}</dd></div>
        <div><dt>Due</dt><dd>${escapeHtml(request.dueLabel)}</dd></div>
        <div><dt>Receipt</dt><dd class="mono">${escapeHtml(request.receipt?.id || "Pending")}</dd></div>
        <div><dt>Files</dt><dd>${escapeHtml(attachmentLabel(request))}</dd></div>
      </dl>
    </section>
    <section class="rail-section">
      <p class="rail-kicker">Latest activity</p>
      <div class="log-list">
        ${activity.map((item) => `
          <div class="log-item">
            <strong>${escapeHtml(item.action)}</strong>
            <p>${escapeHtml(item.actor)} · <time>${escapeHtml(item.at)}</time></p>
            <p>${escapeHtml(item.detail)}</p>
          </div>
        `).join("")}
      </div>
      <div class="button-row">
        <button class="button" type="button" data-action="view_history">Full log</button>
      </div>
    </section>
  `;
}

function openDrawer(kicker, title, body) {
  $("#drawerKicker").textContent = kicker;
  $("#drawerTitle").textContent = title;
  $("#drawerBody").innerHTML = body;
  $("#drawerBackdrop").hidden = false;
  $("#drawer").hidden = false;
  const focusable = $("#drawerBody").querySelector("input, textarea, button");
  if (focusable) focusable.focus();
}

function closeDrawer() {
  drawerMode = "";
  $("#drawerBackdrop").hidden = true;
  $("#drawer").hidden = true;
  $("#drawerBody").innerHTML = "";
}

function openPacketDrawer(mode) {
  const request = selectedRequest();
  drawerMode = mode;
  const draft = request.draft || {};
  const correction = mode === "correction";
  openDrawer(
    request.requestId,
    correction ? "Prepare correction" : "Prepare packet",
    `
      <p class="drawer-note">${escapeHtml(correction ? "Correct the returned packet field and keep the original request attached." : "Submit only when the authorization number, date window, procedure match, and signed document are ready.")}</p>
      <div class="form-grid">
        <label class="field">
          <span>Prior authorization number</span>
          <input id="paNumber" autocomplete="off" value="${escapeHtml(draft.paNumber || "")}" placeholder="PA number" />
        </label>
        <label class="field">
          <span>Effective from</span>
          <input id="effectiveFrom" type="date" value="${escapeHtml(draft.effectiveFrom || "")}" />
        </label>
        <label class="field">
          <span>Effective through</span>
          <input id="effectiveThrough" type="date" value="${escapeHtml(draft.effectiveThrough || "")}" />
        </label>
        ${correction ? `
          <label class="field">
            <span>Correction note</span>
            <textarea id="correctionNote" placeholder="What changed in the packet">${escapeHtml(draft.correctionNote || "")}</textarea>
          </label>
        ` : ""}
        <label class="check-row">
          <input id="dateCovers" type="checkbox" ${draft.dateCovers ? "checked" : ""} />
          <span>Date window covers ${escapeHtml(request.serviceDate)}</span>
        </label>
        <label class="check-row">
          <input id="procedureMatch" type="checkbox" ${draft.procedureMatch ? "checked" : ""} />
          <span>Authorization explicitly covers ${escapeHtml(request.procedure)}</span>
        </label>
        <label class="check-row">
          <input id="signedDocument" type="checkbox" ${draft.signedDocument ? "checked" : ""} />
          <span>Signed authorization document is attached</span>
        </label>
        <label class="field file-field">
          <span>Upload authorization documents</span>
          <span class="file-control">
            <span class="file-button">Choose files</span>
            <span id="fileSummary" class="file-summary">${escapeHtml((draft.attachments || []).length ? fileCountLabel((draft.attachments || []).length) : "No files selected")}</span>
          </span>
          <input id="packetFiles" class="visually-hidden-file" type="file" multiple />
        </label>
        <ul class="attachment-list" aria-label="Staged packet attachments">
          ${(draft.attachments || []).map((attachment) => `
            <li>
              <span>${escapeHtml(attachmentName(attachment))}</span>
              <small>${escapeHtml(attachmentSize(attachment) ? `${Math.ceil(attachmentSize(attachment) / 1024)} KB` : "staged")}</small>
            </li>
          `).join("")}
        </ul>
        <div id="formError" class="form-error" role="alert"></div>
        <div class="button-row">
          <button class="button primary" type="button" data-action="submit_packet">${escapeHtml(correction ? "Submit correction" : "Submit packet")}</button>
          <button class="button" type="button" data-action="save_draft">Save draft</button>
        </div>
      </div>
    `,
  );
}

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

async function selectedFileAttachments() {
  const files = Array.from($("#packetFiles")?.files || []);
  return Promise.all(files.map(async (file) => ({
    name: file.name,
    filename: file.name,
    mimeType: file.type || "application/octet-stream",
    sizeBytes: file.size,
    contentBase64: arrayBufferToBase64(await file.arrayBuffer()),
  })));
}

function mergeAttachments(existing, incoming) {
  const merged = new Map();
  [...(existing || []), ...(incoming || [])].forEach((attachment) => {
    const name = attachmentName(attachment).trim();
    if (!name) return;
    merged.set(name, typeof attachment === "string" ? { name, filename: name } : { ...attachment, name, filename: attachment.filename || name });
  });
  return Array.from(merged.values());
}

async function readPacketForm() {
  const request = selectedRequest();
  const existingAttachments = request.draft?.attachments || [];
  const selectedFiles = await selectedFileAttachments();
  return {
    paNumber: $("#paNumber")?.value.trim() || "",
    effectiveFrom: $("#effectiveFrom")?.value || "",
    effectiveThrough: $("#effectiveThrough")?.value || "",
    correctionNote: $("#correctionNote")?.value.trim() || "",
    dateCovers: Boolean($("#dateCovers")?.checked),
    procedureMatch: Boolean($("#procedureMatch")?.checked),
    signedDocument: Boolean($("#signedDocument")?.checked),
    attachments: mergeAttachments(existingAttachments, selectedFiles),
  };
}

function packetErrors(packet, mode) {
  const errors = [];
  if (!packet.paNumber) errors.push("PA number");
  if (!packet.effectiveFrom || !packet.effectiveThrough) errors.push("effective dates");
  if (!packet.dateCovers) errors.push("date coverage check");
  if (!packet.procedureMatch) errors.push("procedure match check");
  if (!packet.signedDocument) errors.push("signed document check");
  if (!packet.attachments.length) errors.push("packet attachment");
  if (mode === "correction" && !packet.correctionNote) errors.push("correction note");
  return errors;
}

async function saveDraft() {
  const request = selectedRequest();
  const packet = await readPacketForm();
  request.draft = packet;
  if (request.status === "needs_packet") request.status = "draft";
  addHistory(request, "Provider office", "Draft saved", `Packet draft saved locally with ${fileCountLabel(packet.attachments.length)} staged; payer has not received it.`);
  recordProviderEvent(request, "save_draft", "draft_saved", "Packet draft saved.").catch(() => {
    addHistory(request, "Local desk", "Event queued locally", "Backend audit endpoint was not reachable.");
  });
  closeDrawer();
  renderNavigationChange();
}

async function submitPacket() {
  const request = selectedRequest();
  const packet = await readPacketForm();
  const errors = packetErrors(packet, drawerMode);
  if (errors.length) {
    $("#formError").textContent = `Missing: ${errors.join(", ")}.`;
    return;
  }
  const busyButton = setActionBusy("submit_packet", "Sending...");
  let response;
  try {
    response = await sendProviderPacket(request, packet, drawerMode);
  } catch (error) {
    $("#formError").textContent = error.message || "Packet could not be sent to the payer service.";
    clearActionBusy(busyButton);
    return;
  }
  const receipt = response.packet || {};
  const providerEvent = response.event || {};
  request.draft = packet;
  request.status = "submitted";
  request.paymentState = "Held by payer";
  request.paLookup = "Provider packet received by payer";
  request.authWindow = `${packet.effectiveFrom} to ${packet.effectiveThrough}`;
  request.receipt = {
    id: receipt.receipt_id || `DOC-REC-${request.claimId.split("-").at(-1)}`,
    sentAt: nowStamp(),
    auditId: providerEvent.id || receipt.packet_id || "",
    hash: receipt.packet_hash || "",
    attachmentCount: (receipt.attachments || []).length || packet.attachments.length,
    attachments: (receipt.attachments || []).map((attachment) => attachment.filename),
  };
  request.requiredDocs = request.requiredDocs.map((item) => ({ ...item, state: "complete" }));
  addHistory(request, "Provider office", drawerMode === "correction" ? "Correction submitted" : "Packet submitted", `Receipt ${request.receipt.id} received by payer service with ${fileCountLabel(request.receipt.attachmentCount)}.`);
  selectedId = request.id;
  activeFilter = "submitted";
  closeDrawer();
  renderNavigationChange();
}

function openNoteDrawer(kind) {
  const request = selectedRequest();
  drawerMode = kind;
  openDrawer(
    request.requestId,
    kind === "withdraw" ? "Withdraw claim" : "Message payer",
    `
      <p class="drawer-note">${escapeHtml(kind === "withdraw" ? "Withdrawal closes this provider-side request and leaves an auditable reason." : "Ask a focused question about this request. This does not release or deny payment.")}</p>
      <label class="field">
        <span>${escapeHtml(kind === "withdraw" ? "Withdrawal reason" : "Message")}</span>
        <textarea id="noteText" placeholder="${escapeHtml(kind === "withdraw" ? "Reason for withdrawal" : "Question for payer")}"></textarea>
      </label>
      <div id="formError" class="form-error" role="alert"></div>
      <div class="button-row">
        <button class="button primary" type="button" data-action="submit_note">${escapeHtml(kind === "withdraw" ? "Withdraw claim" : "Send message")}</button>
      </div>
    `,
  );
}

async function submitNote() {
  const request = selectedRequest();
  const note = $("#noteText")?.value.trim() || "";
  if (!note) {
    $("#formError").textContent = "A note is required.";
    return;
  }
  if (drawerMode === "withdraw") {
    const busyButton = setActionBusy("submit_note", "Recording...");
    try {
      await recordProviderEvent(request, "withdraw_claim", "withdrawn", note);
    } catch (error) {
      $("#formError").textContent = error.message || "Withdrawal could not be recorded.";
      clearActionBusy(busyButton);
      return;
    }
    request.status = "withdrawn";
    request.paymentState = "Closed by provider";
    addHistory(request, "Provider office", "Claim withdrawn", note);
    selectedId = request.id;
    activeFilter = "closed";
  } else {
    const busyButton = setActionBusy("submit_note", "Sending...");
    let response;
    try {
      response = await sendProviderMessage(request, note);
    } catch (error) {
      $("#formError").textContent = error.message || "Message could not be sent to the payer service.";
      clearActionBusy(busyButton);
      return;
    }
    addHistory(request, "Provider office", "Payer message sent", `${response.message?.message_id || "Message"} received by payer service.`);
  }
  closeDrawer();
  renderNavigationChange();
}

function openRequestDrawer() {
  const request = selectedRequest();
  openDrawer(
    request.requestId,
    "Payer request",
    `
      <dl class="receipt-list">
        <div><dt>Request ID</dt><dd class="mono">${escapeHtml(request.requestId)}</dd></div>
        <div><dt>Claim ID</dt><dd class="mono">${escapeHtml(request.claimId)}</dd></div>
        <div><dt>Needed</dt><dd>${escapeHtml(request.requiredDocs.map((item) => item.label).join(", "))}</dd></div>
        <div><dt>Staged files</dt><dd>${escapeHtml((request.draft?.attachments || request.receipt?.attachments || []).map(attachmentName).join(", ") || "None staged")}</dd></div>
        <div><dt>Policy</dt><dd>${escapeHtml(request.policyCitation)}</dd></div>
        <div><dt>PA lookup</dt><dd>${escapeHtml(request.paLookup)}</dd></div>
      </dl>
      <div class="button-row">
        <button class="button" type="button" data-action="view_history">View history</button>
      </div>
    `,
  );
}

function openReceiptDrawer() {
  const request = selectedRequest();
  if (!request.receipt) {
    openDrawer(request.requestId, "No receipt yet", `<p class="drawer-note">Submit the packet before a receipt exists.</p>`);
    return;
  }
  openDrawer(
    request.receipt.id,
    "Submission receipt",
    `
      <dl class="receipt-list">
        <div><dt>Receipt</dt><dd class="mono">${escapeHtml(request.receipt.id)}</dd></div>
        <div><dt>Sent</dt><dd>${escapeHtml(request.receipt.sentAt)}</dd></div>
        <div><dt>Audit ID</dt><dd class="mono">${escapeHtml(request.receipt.auditId)}</dd></div>
        ${renderHashField("Packet hash", request.receipt.hash)}
        <div><dt>Attachments</dt><dd>${escapeHtml(attachmentLabel(request))}</dd></div>
        <div><dt>Payment</dt><dd>${escapeHtml(request.paymentState)}</dd></div>
      </dl>
    `,
  );
}

function openHistoryDrawer() {
  const request = selectedRequest();
  openDrawer(
    request.requestId,
    "Request log",
    `
      <div class="log-list">
        ${uniqueHistory(request).map((item) => `
          <div class="log-item">
            <strong>${escapeHtml(item.action)}</strong>
            <p>${escapeHtml(item.actor)} · <time>${escapeHtml(item.at)}</time></p>
            <p>${escapeHtml(item.detail)}</p>
          </div>
        `).join("")}
      </div>
    `,
  );
}

function addHistory(request, actor, action, detail) {
  request.history.unshift({ at: nowStamp(), actor, action, detail });
}

async function copyValue(button) {
  const value = button?.dataset.copyValue || "";
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    button.textContent = "Copied";
  } catch (error) {
    const field = document.createElement("textarea");
    field.value = value;
    field.setAttribute("readonly", "");
    field.style.position = "fixed";
    field.style.inset = "0 auto auto 0";
    field.style.opacity = "0";
    document.body.appendChild(field);
    field.select();
    const copied = document.execCommand("copy");
    field.remove();
    button.textContent = copied ? "Copied" : "Select";
  }
}

function setActionBusy(action, label) {
  const button = document.querySelector(`[data-action="${action}"]`);
  if (!button) return null;
  button.dataset.originalText = button.textContent;
  button.disabled = true;
  button.textContent = label;
  return button;
}

function clearActionBusy(button) {
  if (!button) return;
  button.disabled = false;
  button.textContent = button.dataset.originalText || button.textContent;
  delete button.dataset.originalText;
}

function addHistoryOnce(request, actor, action, detail, syncKey) {
  if (syncKey && request.history.some((item) => item.syncKey === syncKey)) return;
  if (request.history.some((item) => item.actor === actor && item.detail === detail)) return;
  request.history.unshift({ at: nowStamp(), actor, action, detail, syncKey });
}

async function apiJson(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${PORTAL_TOKEN}`,
    },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.detail || `Request failed with ${response.status}`);
  }
  return payload;
}

async function apiGet(path) {
  const response = await fetch(path, {
    headers: {
      "Authorization": `Bearer ${PORTAL_TOKEN}`,
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.detail || `Request failed with ${response.status}`);
  }
  return payload;
}

function labelsToRequiredDocs(labels, status) {
  const complete = ["submitted", "accepted", "released"].includes(status);
  return (labels || []).map((label) => ({
    id: String(label).toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "") || "document",
    label,
    state: complete ? "complete" : status === "needs_correction" ? "blocked" : "missing",
  }));
}

function titleForProviderStatus(status) {
  return {
    needs_correction: "Correction needed on authorization packet",
    submitted: "Packet submitted, awaiting payer review",
    accepted: "Authorization accepted, release pending",
    released: "Payment released by payer",
    denied: "Claim denied by payer",
    withdrawn: "Claim withdrawn",
  }[status] || "Prior authorization packet required";
}

function paymentStateLabel(value, status) {
  if (value === "release_pending") return "Release pending";
  if (value === "released_by_payer" || status === "released") return "Released by payer";
  if (value === "denied_by_payer" || status === "denied") return "Denied by payer";
  if (value === "closed_by_provider" || status === "withdrawn") return "Closed by provider";
  return "Held by payer";
}

function dueLabelForStatus(status) {
  return {
    submitted: "Waiting on payer",
    accepted: "Accepted",
    released: "Released",
    denied: "Closed",
    withdrawn: "Closed",
  }[status] || "Due today";
}

function issueForProviderRecord(record) {
  if (record.message) return record.message;
  if (record.status === "released") return "The payer released payment for this request.";
  if (record.status === "denied") return "The payer denied this claim.";
  if (record.status === "accepted") return "The authorization matched. Payer release remains outside provider control.";
  if (record.status === "submitted") return "The packet was submitted and is waiting for payer review.";
  return "The payer requested authorization documentation for this claim.";
}

function providerRequestFromWorkspace(record) {
  const suffix = String(record.claim_id || record.request_id || "000").match(/(\d+)$/)?.[1] || "000";
  const procedure = record.procedure_code || "T1019";
  const labels = record.required_items || ["Prior authorization number", "Authorization effective date window", `Procedure code ${procedure} match`, "Signed authorization document"];
  return {
    id: `req-${suffix}`,
    claimId: record.claim_id || `BL-CLAIM-AUTH-${suffix}`,
    requestId: record.request_id || `DOC-REQ-${suffix}`,
    title: titleForProviderStatus(record.status || "needs_packet"),
    status: record.status || "needs_packet",
    provider: record.provider || "North Valley Home Health",
    providerNpi: record.provider_npi || "1999999984",
    payer: "Medi-Cal",
    member: `M-CA-${suffix}`,
    program: "Managed care",
    serviceDate: record.service_date || "Service date pending",
    procedure,
    units: "Units on claim",
    amountCents: Number(record.amount_cents || 0),
    dueRank: 1,
    dueLabel: dueLabelForStatus(record.status || "needs_packet"),
    paymentState: paymentStateLabel(record.payment_state, record.status),
    policyCitation: "Medi-Cal PCS prior authorization rule",
    paLookup: "No active authorization on file",
    authWindow: "Must cover service date",
    issue: issueForProviderRecord(record),
    requiredDocs: labelsToRequiredDocs(labels, record.status || "needs_packet"),
    receipt: null,
    draft: null,
    history: [
      {
        at: nowStamp(),
        actor: "Medi-Cal",
        action: "Documentation request opened",
        detail: record.message || "Payment remains held pending provider packet.",
        syncKey: `request:${record.request_id || suffix}`,
      },
    ],
  };
}

function mergeProviderRequest(record) {
  const claimId = record.claim_id || "";
  const requestId = record.request_id || "";
  let request = requestByClaimOrRequest(claimId, requestId);
  if (!request) {
    request = providerRequestFromWorkspace(record);
    requests.unshift(request);
  }
  request.requestId = requestId || request.requestId;
  if (record.status) {
    request.status = record.status;
    request.title = titleForProviderStatus(record.status);
    request.dueLabel = dueLabelForStatus(record.status);
  }
  if (record.provider) request.provider = record.provider;
  if (record.provider_npi) request.providerNpi = record.provider_npi;
  if (record.procedure_code) request.procedure = record.procedure_code;
  if (record.service_date) request.serviceDate = record.service_date;
  if (record.amount_cents) request.amountCents = Number(record.amount_cents);
  request.paymentState = paymentStateLabel(record.payment_state, request.status);
  request.issue = issueForProviderRecord(record);
  if (Array.isArray(record.required_items) && record.required_items.length) {
    request.requiredDocs = labelsToRequiredDocs(record.required_items, request.status);
  }
  if (record.message) {
    addHistoryOnce(request, "Medi-Cal", record.status === "needs_correction" ? "Correction requested" : "Documentation request opened", record.message, `request-message:${request.requestId}:${record.message}`);
  }
  return request;
}

function mergeWorkspacePacket(packet) {
  const request = requestByClaimOrRequest(packet.claim_id, packet.request_id);
  if (!request) return;
  request.status = "submitted";
  request.paymentState = "Held by payer";
  request.paLookup = "Provider packet received by payer";
  request.authWindow = `${packet.effective_from} to ${packet.effective_through}`;
  request.receipt = {
    id: packet.receipt_id,
    sentAt: nowStamp(),
    auditId: packet.packet_id,
    hash: packet.packet_hash,
    attachmentCount: (packet.attachments || []).length,
    attachments: (packet.attachments || []).map((attachment) => attachment.filename),
  };
  request.requiredDocs = request.requiredDocs.map((item) => ({ ...item, state: "complete" }));
  addHistoryOnce(request, "Provider office", "Packet submitted", `Receipt ${packet.receipt_id} received by payer service with ${fileCountLabel((packet.attachments || []).length)}.`, `packet:${packet.packet_id}`);
}

function mergeWorkspaceMessage(message) {
  const request = requestByClaimOrRequest(message.claim_id, message.request_id);
  if (!request) return;
  const fromPayer = message.direction === "payer_to_provider" || String(message.message_id || "").startsWith("PAYER-MSG");
  addHistoryOnce(
    request,
    fromPayer ? "Medi-Cal" : "Provider office",
    fromPayer ? "Payer message received" : "Payer message sent",
    message.message,
    `message:${message.message_id}`,
  );
}

function mergeProviderAuditEvent(event) {
  const requestId = event.metadata?.request_id || "";
  const request = requestByClaimOrRequest(event.claim_id, requestId);
  if (!request) return;
  const payerEvents = {
    payer_document_request_sent: "Documentation request opened",
    payer_followup_sent: "Payer follow-up received",
    payer_packet_marked_received: "Payer marked packet received",
    payer_authorization_accepted: "Authorization accepted",
    payer_payment_released: "Payment released",
    payer_claim_denied: "Claim denied",
  };
  if (payerEvents[event.event_type]) {
    addHistoryOnce(
      request,
      "Medi-Cal",
      payerEvents[event.event_type],
      event.metadata?.message || event.description,
      `provider-audit:${event.id}`,
    );
  }
}

function mergeProviderWorkspace(workspace) {
  (workspace.requests || []).forEach(mergeProviderRequest);
  [...(workspace.packets || [])].reverse().forEach(mergeWorkspacePacket);
  [...(workspace.messages || [])].reverse().forEach(mergeWorkspaceMessage);
  [...(workspace.audit_log || [])].reverse().forEach(mergeProviderAuditEvent);
  if (!requests.some((request) => request.id === selectedId)) selectedId = requests[0]?.id || "";
}

async function loadProviderWorkspace() {
  try {
    const workspace = await apiGet("/api/provider-workspace");
    mergeProviderWorkspace(workspace);
    render();
  } catch (error) {
    // Keep the local desk usable if the backend is offline.
  }
}

async function sendProviderPacket(request, packet, mode) {
  return apiJson("/api/provider-packets", {
    request_id: request.requestId,
    claim_id: request.claimId,
    action: mode === "correction" ? "submit_correction" : "submit_packet",
    pa_number: packet.paNumber,
    effective_from: packet.effectiveFrom,
    effective_through: packet.effectiveThrough,
    correction_note: packet.correctionNote,
    date_covers: packet.dateCovers,
    procedure_match: packet.procedureMatch,
    signed_document: packet.signedDocument,
    attachments: packet.attachments.map((attachment) => ({
      filename: attachmentName(attachment),
      content_base64: attachment.contentBase64 || "",
      mime_type: attachment.mimeType || "application/octet-stream",
      size_bytes: attachment.sizeBytes ?? null,
    })),
  });
}

async function sendProviderMessage(request, note) {
  return apiJson("/api/provider-messages", {
    request_id: request.requestId,
    claim_id: request.claimId,
    message: note,
  });
}

async function recordProviderEvent(request, action, status, description) {
  return apiJson("/api/provider-events", {
    request_id: request.requestId,
    claim_id: request.claimId,
    action,
    status,
    description,
    outcome: status,
  });
}

function handleAction(action, target) {
  if (action === "copy_value") {
    copyValue(target);
    return;
  }
  if (action === "prepare_packet") openPacketDrawer("packet");
  else if (action === "prepare_correction") openPacketDrawer("correction");
  else if (action === "save_draft") saveDraft();
  else if (action === "submit_packet") submitPacket();
  else if (action === "request_clarification") openNoteDrawer("message");
  else if (action === "withdraw_claim") openNoteDrawer("withdraw");
  else if (action === "submit_note") submitNote();
  else if (action === "view_request") openRequestDrawer();
  else if (action === "view_receipt") openReceiptDrawer();
  else if (action === "view_history") openHistoryDrawer();
}

function moveSelection(direction) {
  const list = visibleRequests();
  if (!list.length) return;
  const index = Math.max(0, list.findIndex((request) => request.id === selectedId));
  const next = (index + direction + list.length) % list.length;
  selectedId = list[next].id;
  renderNavigationChange();
}

function handleCommand(command) {
  if (command === "focus-search") $("#searchInput").focus();
  if (command === "next-request") moveSelection(1);
  if (command === "previous-request") moveSelection(-1);
  if (command === "primary-action") handleAction(primaryActionForRequest(selectedRequest()));
  if (command === "request-log") openHistoryDrawer();
  if (command === "toggle-theme") toggleTheme();
  if (command === "reset") resetDemo();
  $("#commandPalette").hidden = true;
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("blProviderTheme", next);
  $("#themeToggle").textContent = next === "dark" ? "Dark" : "Light";
}

function resetDemo() {
  requests = structuredClone(INITIAL_REQUESTS);
  selectedId = requests[0].id;
  activeFilter = "action_needed";
  activeSort = "status_due";
  searchQuery = "";
  $("#searchInput").value = "";
  $("#sortSelect").value = activeSort;
  closeDrawer();
  renderNavigationChange();
}

function bindEvents() {
  document.addEventListener("click", (event) => {
    const selectButton = event.target.closest("[data-select]");
    if (selectButton) {
      selectedId = selectButton.dataset.select;
      renderNavigationChange();
      return;
    }
    const filterButton = event.target.closest("[data-filter]");
    if (filterButton) {
      activeFilter = filterButton.dataset.filter;
      renderNavigationChange();
      return;
    }
    const actionButton = event.target.closest("[data-action]");
    if (actionButton) {
      handleAction(actionButton.dataset.action, actionButton);
      return;
    }
    const commandButton = event.target.closest("[data-command]");
    if (commandButton) {
      handleCommand(commandButton.dataset.command);
    }
  });

  $("#searchInput").addEventListener("input", (event) => {
    searchQuery = event.target.value;
    renderNavigationChange();
  });

  $("#sortSelect").addEventListener("change", (event) => {
    activeSort = event.target.value;
    renderNavigationChange();
  });

  document.addEventListener("change", (event) => {
    if (event.target?.id === "packetFiles") {
      const count = event.target.files?.length || 0;
      const summary = $("#fileSummary");
      if (summary) summary.textContent = count ? fileCountLabel(count) : "No files selected";
    }
  });

  $("#themeToggle").addEventListener("click", toggleTheme);
  $("#commandButton").addEventListener("click", () => {
    $("#commandPalette").hidden = false;
  });
  $("#drawerClose").addEventListener("click", closeDrawer);
  $("#drawerBackdrop").addEventListener("click", closeDrawer);

  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      $("#commandPalette").hidden = false;
    }
    if (event.key === "Escape") {
      closeDrawer();
      $("#commandPalette").hidden = true;
    }
  });
}

function initTheme() {
  const saved = localStorage.getItem("blProviderTheme") || document.documentElement.dataset.theme || "dark";
  document.documentElement.dataset.theme = saved;
  $("#themeToggle").textContent = saved === "dark" ? "Dark" : "Light";
}

initTheme();
bindEvents();
render();
loadProviderWorkspace();
window.addEventListener("focus", loadProviderWorkspace);
window.setInterval(loadProviderWorkspace, 15000);
