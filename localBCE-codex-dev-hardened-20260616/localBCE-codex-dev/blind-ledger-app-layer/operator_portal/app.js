const $ = (id) => document.getElementById(id);

const state = {
  sample: null,
  workspace: { batches: [], review_items: [], audit_log: [], readiness: null },
  selectedReviewId: "",
  activeView: "review",
  mode: localStorage.getItem("claimsDeskMode") || "operator",
  reviewFilter: "all",
  historyFilter: "all",
  auditSearch: "",
  busy: false,
};

const viewTitles = {
  operator: {
    review: "Claims Waiting for Review",
    intake: "Claim Package Intake",
    audit: "Decision History",
    batch: "Batch Evidence",
  },
  auditor: {
    review: "Review Queue Trace",
    intake: "Claim Package Intake",
    audit: "Claim Decision Trace",
    batch: "Settlement Evidence",
  },
};

const sampleLabels = {
  clean: "Ready to clear",
  priorAuth: "Missing authorization",
  eligibility: "Coverage issue",
  badFile: "Unreadable file",
};

const statusLabels = {
  open: "Open",
  waiting_on_documents: "Waiting on documents",
  ready_for_resubmission: "Ready for resubmission",
  assigned: "Assigned",
  payment_hold: "Payment hold",
  in_review: "In review",
};

function clearNode(node) {
  node.replaceChildren();
}

function textNode(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = String(value ?? "");
  return node;
}

function tableCell(value, className = "") {
  const td = document.createElement("td");
  if (className) td.className = className;
  td.textContent = String(value ?? "");
  return td;
}

function tableHead(labels) {
  const thead = document.createElement("thead");
  const row = document.createElement("tr");
  labels.forEach((label) => {
    const th = document.createElement("th");
    th.scope = "col";
    th.textContent = label;
    row.append(th);
  });
  thead.append(row);
  return thead;
}

function tableShell(className, labels) {
  const wrap = document.createElement("div");
  wrap.className = "table-scroll";
  const table = document.createElement("table");
  table.className = className;
  table.append(tableHead(labels), document.createElement("tbody"));
  wrap.append(table);
  return { wrap, table, tbody: table.querySelector("tbody") };
}

function statusKind(status) {
  if (["approved", "cleared", "payment_record_prepared", "claim_approved", "ready_for_resubmission"].includes(status)) return "ok";
  if (["open", "in_review", "waiting_on_documents", "claim_routed_to_review", "review_action", "assigned"].includes(status)) return "flag";
  if (["payment_hold", "program_integrity_hold"].includes(status)) return "bad";
  return "pending";
}

function statusChip(label, kind = "pending") {
  const chip = document.createElement("span");
  chip.className = `status-chip ${kind}`;
  chip.textContent = String(label || "Pending");
  return chip;
}

function actionButton(label, className = "text-button") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  return button;
}

function emptyState(title, reason) {
  const node = document.createElement("div");
  node.className = "empty-state";
  node.append(textNode("strong", "", title), textNode("span", "", reason));
  return node;
}

function setActiveRow(row, active) {
  row.classList.toggle("active-row", active);
  row.setAttribute("aria-selected", active ? "true" : "false");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.detail || "Request failed");
  }
  return payload;
}

function moneyFromCents(cents) {
  return (Number(cents || 0) / 100).toLocaleString(undefined, { style: "currency", currency: "USD" });
}

function shortText(value, head = 9, tail = 7) {
  const text = String(value || "");
  return text.length <= head + tail + 3 ? text : `${text.slice(0, head)}...${text.slice(-tail)}`;
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function formatStatus(status) {
  return statusLabels[status] || String(status || "open").replaceAll("_", " ");
}

function formatLabel(value) {
  return String(value || "").replaceAll("_", " ");
}

function routeLabel(route) {
  const labels = {
    cif_resubmission: "Corrected claim or CIF",
    formal_appeal: "Formal appeal",
    program_integrity: "Program integrity",
    manual_review: "Manual review",
  };
  return labels[route] || formatLabel(route || "manual_review");
}

function auditPresentation(event) {
  const amount = event.amount_cents == null ? "" : moneyFromCents(event.amount_cents);
  if (event.event_type === "claim_approved") {
    return {
      kind: "allowed",
      title: "Claim cleared by automated review",
      body: "The claim passed coverage, provider, duplicate, authorization, and integrity checks. It is ready for payment preparation.",
      meta: `${event.claim_id || "Claim"}${amount ? ` - ${amount}` : ""}`,
    };
  }
  if (event.event_type === "payment_record_prepared") {
    return {
      kind: "allowed",
      title: "Payment record prepared",
      body: "Payment paperwork was prepared for the cleared batch. Final release remains closed until settlement approval.",
      meta: amount || "Payment staged",
    };
  }
  if (event.event_type === "review_action") {
    return {
      kind: "review",
      title: "Staff action recorded",
      body: event.description || "A reviewer updated the claim file.",
      meta: `${event.claim_id || "Claim"} - ${formatStatus(event.outcome)}`,
    };
  }
  if (event.event_type === "claim_routed_to_review") {
    return {
      kind: "review",
      title: "Claim routed to staff review",
      body: event.description || "The claim needs staff review before it can continue.",
      meta: `${event.claim_id || "Claim"} - ${event.metadata?.owner_queue || "Review desk"}`,
    };
  }
  if (event.event_type === "batch_submitted") {
    return {
      kind: "batch",
      title: "Claim package received",
      body: "The package was received and checked for file format, rules coverage, and payment hold status.",
      meta: "Batch received",
    };
  }
  return {
    kind: "batch",
    title: formatLabel(event.event_type),
    body: event.description || "System record",
    meta: event.claim_id || shortText(event.batch_id || ""),
  };
}

function deriveClaimId(edi) {
  const claimMatch = String(edi || "").match(/(?:^|~)CLM\*([^*~]+)/);
  const bhtMatch = String(edi || "").match(/(?:^|~)BHT\*[^*~]*\*[^*~]*\*([^*~]+)/);
  return claimMatch?.[1] || bhtMatch?.[1] || "";
}

function replaceClaimId(claim, nextId) {
  const previous = claim.claim_id || deriveClaimId(claim.edi) || "BL-CLAIM-0001";
  claim.claim_id = nextId;
  claim.edi = String(claim.edi || "").replaceAll(previous, nextId).replaceAll("BL-CLAIM-0001", nextId);
}

function hasPriorAuthorization(edi) {
  return /~REF\*G1\*[^~]+/.test(String(edi || ""));
}

function setPriorAuthorization(edi, attached) {
  const source = String(edi || "");
  const cleaned = source.replace(/~REF\*G1\*[^~]*/g, "");
  if (!attached) return cleaned;
  if (hasPriorAuthorization(source)) return source;
  if (cleaned.includes("~SE*")) return cleaned.replace("~SE*", "~REF*G1*PA-OK-123~SE*");
  const separator = cleaned.endsWith("~") || !cleaned ? "" : "~";
  return `${cleaned}${separator}REF*G1*PA-OK-123~`;
}

function buildSample(kind) {
  const claim = clone(state.sample);
  if (kind === "clean") {
    replaceClaimId(claim, "BL-CLAIM-APPROVED");
    return claim;
  }
  if (kind === "priorAuth") {
    replaceClaimId(claim, "BL-CLAIM-MISSING-AUTH");
    claim.edi = claim.edi.replace("SV1*HC:99213", "SV1*HC:T1019").replace(/~REF\*G1\*[^~]*/g, "");
    return claim;
  }
  if (kind === "eligibility") {
    replaceClaimId(claim, "BL-CLAIM-ELIGIBILITY");
    claim.flags.eligibility_active = false;
    return claim;
  }
  return { claim_id: "BAD-FILE-0001", edi: "", flags: {} };
}

function setClaimForm(claim) {
  const flags = claim.flags || {};
  $("claimIdInput").value = claim.claim_id || deriveClaimId(claim.edi) || "";
  $("ediInput").value = claim.edi || "";
  $("eligibilityActive").checked = flags.eligibility_active !== false;
  $("providerEnrolled").checked = flags.provider_enrolled !== false;
  $("priorAuthAttached").checked = hasPriorAuthorization(claim.edi);
  $("duplicateClaim").checked = Boolean(flags.duplicate_claim);
  $("programIntegrityHold").checked = Boolean(flags.program_integrity_hold);
  renderPrecheck();
}

function buildClaimPacket() {
  const claim = clone(state.sample || { flags: {} });
  const claimId = $("claimIdInput").value.trim() || deriveClaimId($("ediInput").value) || "UNLABELED-CLAIM";
  claim.claim_id = claimId;
  claim.edi = setPriorAuthorization($("ediInput").value.trim(), $("priorAuthAttached").checked);
  claim.flags = {
    ...(claim.flags || {}),
    eligibility_active: $("eligibilityActive").checked,
    provider_enrolled: $("providerEnrolled").checked,
    duplicate_claim: $("duplicateClaim").checked,
    program_integrity_hold: $("programIntegrityHold").checked,
  };
  return [claim];
}

function setNotice(message, isError = false) {
  const notice = $("notice");
  notice.textContent = message || "";
  notice.classList.toggle("error", isError);
}

function setBusy(active, message = "") {
  state.busy = Boolean(active);
  document.body.classList.toggle("is-busy", state.busy);
  document.body.setAttribute("aria-busy", state.busy ? "true" : "false");
  document.querySelectorAll("button, input, textarea").forEach((control) => {
    control.disabled = state.busy;
  });
  if (message) setNotice(message);
}

async function runBusy(message, operation) {
  if (state.busy) return;
  setBusy(true, message);
  try {
    await operation();
  } catch (error) {
    setNotice(error.message, true);
  } finally {
    setBusy(false);
  }
}

function activeBatch() {
  const batches = state.workspace.batches || [];
  return batches[batches.length - 1] || null;
}

function openReviewItems() {
  return (state.workspace.review_items || []).filter((item) => item.status === "open");
}

function filterReviewItems(items) {
  if (state.reviewFilter === "documents") {
    return items.filter((item) => ["Documents", "Authorizations"].includes(item.owner_queue) || item.category.toLowerCase().includes("missing"));
  }
  if (state.reviewFilter === "eligibility") {
    return items.filter((item) => item.owner_queue === "Eligibility" || item.reason.includes("eligibility"));
  }
  if (state.reviewFilter === "policy") {
    return items.filter((item) => item.owner_queue === "Policy review" || item.category.toLowerCase().includes("rules"));
  }
  return items;
}

function filterAuditEvents(events) {
  let filtered = events;
  if (state.historyFilter === "cleared") {
    filtered = events.filter((event) => event.event_type === "claim_approved" || event.event_type === "payment_record_prepared");
  } else if (state.historyFilter === "routed") {
    filtered = events.filter((event) => event.event_type === "claim_routed_to_review");
  } else if (state.historyFilter === "staff") {
    filtered = events.filter((event) => event.event_type === "review_action");
  }
  const query = state.auditSearch.trim().toLowerCase();
  if (!query) {
    return filtered;
  }
  return filtered.filter((event) =>
    [event.claim_id, event.batch_id, event.event_type, event.description, event.outcome]
      .map((value) => String(value || "").toLowerCase())
      .some((value) => value.includes(query))
  );
}

function renderShell() {
  const readiness = state.workspace.readiness || {};
  const audit = state.workspace.audit_log || [];
  const reviews = openReviewItems();
  const approvedCount = audit.filter((event) => event.event_type === "claim_approved").length;
  const paymentCount = audit.filter((event) => event.event_type === "payment_record_prepared").length;
  const batch = activeBatch();
  const proofLane = String(readiness.proof_lane || "native_stark_binding").replaceAll("_", "-");
  $("modeLabel").textContent = state.mode === "auditor" ? "Auditor mode" : "Operator mode";
  $("proofLabel").textContent = readiness.production_ready ? "Production ready" : "STARK-native lane";
  $("modeEyebrow").textContent = state.mode === "auditor" ? "Traceability and settlement evidence" : "Claims operations";
  $("approvedMetric").textContent = approvedCount;
  $("reviewMetric").textContent = reviews.length;
  $("paymentMetric").textContent = paymentCount;
  $("blockerMetric").textContent = (readiness.open_launch_blockers || []).length;
  $("navReviewCount").textContent = reviews.length;
  $("navAuditCount").textContent = audit.length;
  $("stateNullifier").textContent = shortText(batch?.roots?.nullifier_after || readiness.onchain_anchor || "none", 12, 10);
  $("stateBatch").textContent = shortText(batch?.batch_id || "none", 12, 10);
  $("stateProof").textContent = proofLane.includes("stark") ? "STARK-native" : proofLane;
  $("stateVerifier").textContent = batch?.accepted_by_real_verifier ? "Real verifier accepted" : "Mock verifier / closed";
  document.querySelectorAll("[data-mode]").forEach((button) => {
    button.classList.toggle("active", button.dataset.mode === state.mode);
  });
  document.querySelector(".workspace")?.setAttribute("data-mode", state.mode);
}

function renderReviewList() {
  const allItems = state.workspace.review_items || [];
  const items = filterReviewItems(allItems);
  const open = openReviewItems();
  $("queueSubhead").textContent = `${open.length} open`;
  document.querySelectorAll("[data-review-filter]").forEach((button) => {
    button.classList.toggle("active", button.dataset.reviewFilter === state.reviewFilter);
  });
  const container = $("reviewList");
  clearNode(container);
  if (!items.length) {
    container.append(
      emptyState(
        state.reviewFilter === "all" ? "No cases in this session" : "No claims match this filter",
        state.reviewFilter === "all" ? "Submit a package to populate the operator queue." : "Clear the filter or route a matching claim."
      )
    );
    state.selectedReviewId = "";
    renderCaseDetail();
    return;
  }
  if (!state.selectedReviewId || !items.some((item) => item.id === state.selectedReviewId)) {
    state.selectedReviewId = items[0].id;
  }
  const { wrap, tbody } = tableShell("data-table queue-table", ["Claim", "Desk", "Priority", "Issue", "Status", ""]);
  items.forEach((item) => {
    const row = document.createElement("tr");
    row.tabIndex = 0;
    row.dataset.reviewId = item.id;
    setActiveRow(row, item.id === state.selectedReviewId);
    row.append(
      tableCell(item.claim_id, "mono"),
      tableCell(`${item.owner_queue} desk`),
      tableCell(item.priority),
      tableCell(item.category),
    );
    const status = document.createElement("td");
    status.append(statusChip(formatStatus(item.status), statusKind(item.status)));
    row.append(status);
    const action = document.createElement("td");
    const openButton = actionButton("Open", "text-button");
    openButton.addEventListener("click", (event) => {
      event.stopPropagation();
      state.selectedReviewId = item.id;
      renderReviewList();
      renderCaseDetail();
    });
    action.append(openButton);
    row.append(action);
    row.addEventListener("click", () => {
      state.selectedReviewId = item.id;
      renderReviewList();
      renderCaseDetail();
    });
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        state.selectedReviewId = item.id;
        renderReviewList();
        renderCaseDetail();
      }
    });
    tbody.append(row);
  });
  container.append(wrap);
}

function renderCaseDetail() {
  const item = (state.workspace.review_items || []).find((candidate) => candidate.id === state.selectedReviewId);
  const container = $("caseDetail");
  clearNode(container);
  if (!item) {
    container.className = "case-detail";
    container.append(emptyState("No claim selected", "Choose a row in the queue to inspect documents, routing, and next actions."));
    return;
  }
  container.className = "case-detail";
  const codes = [item.carc, item.rarc].filter(Boolean).join(" / ") || "-";
  const actions = item.next_actions || [];

  const cover = document.createElement("div");
  cover.className = "case-cover";
  const number = document.createElement("div");
  number.className = "claim-number";
  number.append(textNode("span", "", "Claim file"), textNode("strong", "", item.claim_id));
  cover.append(number, statusChip(formatStatus(item.status), statusKind(item.status)));

  const issue = document.createElement("div");
  issue.className = "issue-band";
  issue.append(textNode("span", "", "Blocking issue"), textNode("strong", "", item.category), textNode("p", "case-summary", item.summary));

  const { wrap: detailWrap, tbody: detailBody } = tableShell("data-table detail-table", ["Field", "Value"]);
  [
    ["Desk", item.owner_queue],
    ["Route", routeLabel(item.appeal_route)],
    ["Claim codes", codes],
    ["Batch", shortText(item.batch_id)],
    ["Documents or facts needed", (item.required_items || []).join("; ") || "None recorded"],
  ].forEach(([label, value]) => {
    const row = document.createElement("tr");
    row.append(tableCell(label), tableCell(value, label === "Batch" ? "mono" : ""));
    detailBody.append(row);
  });

  const actionsBlock = document.createElement("div");
  actionsBlock.className = "action-block";
  const actionTitle = document.createElement("div");
  actionTitle.className = "section-title compact";
  actionTitle.append(textNode("h2", "", "Next Steps"), textNode("span", "", `${actions.length} available`));
  const note = document.createElement("textarea");
  note.id = "actionNote";
  note.className = "action-note";
  note.placeholder = "Add a short case note";
  const actionGrid = document.createElement("div");
  actionGrid.className = "action-grid";
  actions.forEach((action) => {
    const button = actionButton(`${action.label} - ${action.detail}`, "action-button");
    button.dataset.actionId = action.id;
    button.addEventListener("click", () => recordAction(item.id, action.id));
    actionGrid.append(button);
  });
  actionsBlock.append(actionTitle, note, actionGrid);

  const { wrap: historyWrap, tbody: historyBody } = tableShell("data-table history-table", ["Time", "Actor", "Action", "Note"]);
  (item.history || []).forEach((entry) => {
    const row = document.createElement("tr");
    row.append(tableCell(entry.at, "mono"), tableCell(entry.actor), tableCell(formatLabel(entry.action)), tableCell(entry.note || ""));
    historyBody.append(row);
  });

  container.append(cover, issue, detailWrap, actionsBlock, historyWrap);
}

function renderAudit() {
  const allEvents = state.workspace.audit_log || [];
  const events = filterAuditEvents(allEvents);
  $("auditSubhead").textContent = `${events.length} entries`;
  if ($("auditSearchInput") && document.activeElement !== $("auditSearchInput")) $("auditSearchInput").value = state.auditSearch;
  document.querySelectorAll("[data-history-filter]").forEach((button) => {
    button.classList.toggle("active", button.dataset.historyFilter === state.historyFilter);
  });
  const timeline = $("auditTimeline");
  clearNode(timeline);
  if (!events.length) {
    timeline.append(emptyState(state.auditSearch ? "No records match that lookup" : "No decisions recorded", state.auditSearch ? "Clear lookup or use a different claim ID." : "Submit a package to create the audit trail."));
  } else {
    const { wrap, tbody } = tableShell("data-table audit-table", ["Time", "Event", "Claim", "Outcome", "Detail"]);
    events.forEach((event) => {
      const shown = auditPresentation(event);
      const row = document.createElement("tr");
      row.append(tableCell(event.created_at, "mono"), tableCell(shown.title), tableCell(event.claim_id || "-", "mono"));
      const outcome = document.createElement("td");
      outcome.append(statusChip(formatStatus(event.outcome || event.event_type), statusKind(event.event_type)));
      row.append(outcome, tableCell(shown.body));
      tbody.append(row);
    });
    timeline.append(wrap);
  }
  renderVerificationChecks();
}

function renderBatch() {
  const batch = activeBatch();
  const roots = $("batchRoots");
  clearNode(roots);
  if (!batch) {
    $("batchSubhead").textContent = "No batch";
    roots.append(emptyState("No batch submitted", "Submit a claim package to populate settlement roots and verifier evidence."));
    $("remitBox").textContent = "";
    return;
  }
  $("batchSubhead").textContent = shortText(batch.batch_id, 12, 10);
  const { wrap, tbody } = tableShell("data-table roots-table", ["Root", "Value", "Action"]);
  Object.entries(batch.roots || {}).forEach(([key, value]) => {
    const row = document.createElement("tr");
    row.append(tableCell(formatLabel(key)), tableCell(shortText(value, 20, 16), "mono"));
    row.children[1].title = value;
    const action = document.createElement("td");
    const copy = actionButton("Copy", "text-button");
    const verify = actionButton("Verify", "text-button");
    copy.addEventListener("click", () => copyText(value || ""));
    verify.addEventListener("click", () => verifyRootValue(value || ""));
    action.append(copy, verify);
    row.append(action);
    tbody.append(row);
  });
  roots.append(wrap);
  const first835 = (batch.claims || []).find((claim) => claim.remittance_835);
  $("remitBox").textContent = first835 ? first835.remittance_835 : "";
  renderVerificationChecks();
}

function renderVerificationChecks() {
  const target = $("allowedTrail");
  if (!target) return;
  clearNode(target);
  const batch = activeBatch();
  const readiness = state.workspace.readiness || {};
  const checks = [
    {
      name: "Ed25519 oracle attestations",
      status: batch?.roots?.oracle_signer_root ? "pass" : "pending",
      detail: batch?.roots?.oracle_signer_root ? `Signer root ${shortText(batch.roots.oracle_signer_root, 14, 10)}` : "No submitted batch yet",
    },
    {
      name: "Encrypted data access path",
      status: batch?.roots?.data_availability_root ? "pass" : "pending",
      detail: batch?.roots?.data_availability_root ? `DA root ${shortText(batch.roots.data_availability_root, 14, 10)}` : "Awaiting data availability root",
    },
    {
      name: "Rule ratification provenance",
      status: batch?.roots?.ruleset_root ? "pass" : "pending",
      detail: batch?.roots?.ruleset_root ? `Ruleset root ${shortText(batch.roots.ruleset_root, 14, 10)}` : "Awaiting batch ruleset root",
    },
    {
      name: "Native STARK settlement lane",
      status: String(readiness.proof_lane || "").includes("STARK") ? "pass" : "fail",
      detail: readiness.proof_lane || "Unknown proof lane",
    },
    {
      name: "Verifier release",
      status: batch?.accepted_by_real_verifier ? "pass" : "flag",
      detail: batch ? "Mock verifier / settlement closed" : "No verifier decision in this session",
    },
  ];
  const { wrap, tbody } = tableShell("data-table verify-table", ["Check", "Status", "Evidence"]);
  checks.forEach((check) => {
    const row = document.createElement("tr");
    row.append(tableCell(check.name));
    const status = document.createElement("td");
    status.append(statusChip(check.status === "pass" ? "Pass" : check.status === "fail" ? "Fail" : check.status === "flag" ? "Closed" : "Pending", check.status === "pass" ? "ok" : check.status === "fail" ? "bad" : check.status === "flag" ? "flag" : "pending"));
    row.append(status, tableCell(check.detail, "mono"));
    tbody.append(row);
  });
  target.append(wrap);
}

async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
    setNotice("Copied");
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "readonly");
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
    setNotice("Copied");
  }
}

function verifyRootValue(value) {
  const clean = String(value || "").replace(/^0x/, "");
  const ok = /^[0-9a-fA-F]{64}$/.test(clean) || clean.length >= 32;
  setNotice(ok ? "Root format verified in local batch record" : "Root value is missing or malformed", !ok);
}

function renderPrecheck() {
  let rows;
  try {
    const claim = buildClaimPacket()[0];
    const hasEdi = Boolean(String(claim.edi || "").trim());
    const hasClaimId = Boolean(String(claim.claim_id || "").trim()) && claim.claim_id !== "UNLABELED-CLAIM";
    rows = [
      { label: "Claim ID", value: hasClaimId ? claim.claim_id : "Missing claim ID", level: hasClaimId ? "" : "warning" },
      { label: "837 file", value: hasEdi ? "File text present" : "Needs corrected 837 file", level: hasEdi ? "" : "stop" },
      { label: "Eligibility", value: claim.flags.eligibility_active ? "Active" : "Needs eligibility review", level: claim.flags.eligibility_active ? "" : "warning" },
      { label: "Provider", value: claim.flags.provider_enrolled ? "Enrolled" : "Needs provider enrollment review", level: claim.flags.provider_enrolled ? "" : "warning" },
      { label: "Authorization", value: $("priorAuthAttached").checked ? "Attached when required" : "May need authorization", level: $("priorAuthAttached").checked ? "" : "warning" },
      { label: "Integrity", value: claim.flags.program_integrity_hold ? "Hold active" : "No hold selected", level: claim.flags.program_integrity_hold ? "stop" : "" },
      { label: "Settlement gate", value: $("proofGate").checked ? "Closed until verified" : "Gate disabled", level: $("proofGate").checked ? "" : "warning" },
    ];
    $("jsonPreview").textContent = JSON.stringify([claim], null, 2);
  } catch (error) {
    rows = [{ label: "Claim package", value: error.message, level: "stop" }];
  }
  const panel = $("precheckPanel");
  clearNode(panel);
  const { wrap, tbody } = tableShell("data-table precheck-table", ["Check", "Result", "Status"]);
  rows.forEach((item) => {
    const row = document.createElement("tr");
    row.append(tableCell(item.label), tableCell(item.value));
    const status = document.createElement("td");
    status.append(statusChip(item.level === "stop" ? "Stop" : item.level === "warning" ? "Review" : "Ready", item.level === "stop" ? "bad" : item.level === "warning" ? "flag" : "ok"));
    row.append(status);
    tbody.append(row);
  });
  panel.append(wrap);
}

function renderAll() {
  renderShell();
  renderReviewList();
  renderCaseDetail();
  renderAudit();
  renderBatch();
  renderPrecheck();
}

function setView(view) {
  state.activeView = view;
  document.querySelectorAll(".tab").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  document.querySelectorAll(".view").forEach((section) => section.classList.toggle("active", section.id === `${view}View`));
  $("viewTitle").textContent = viewTitles[state.mode]?.[view] || viewTitles.operator[view] || "Workspace";
}

function setMode(mode) {
  state.mode = mode === "auditor" ? "auditor" : "operator";
  localStorage.setItem("claimsDeskMode", state.mode);
  renderShell();
  setView(state.mode === "auditor" ? "audit" : "review");
}

async function loadWorkspace() {
  state.workspace = await api("/api/workspace");
  renderAll();
}

async function loadSample(kind = "clean") {
  if (!state.sample) {
    state.sample = await api("/api/sample-claim");
  }
  document.querySelectorAll(".sample-chip").forEach((button) => button.classList.toggle("active", button.dataset.sample === kind));
  setClaimForm(buildSample(kind));
  $("intakeStatus").textContent = sampleLabels[kind] || "Ready";
}

async function submitBatch() {
  setNotice("Submitting batch");
  const result = await api("/api/batches", {
    method: "POST",
    body: JSON.stringify({
      actor: $("actorInput").value.trim() || "operator@example.gov",
      claims: buildClaimPacket(),
      strict_oracle_attestations: $("strictOracle").checked,
      enforce_nullifier_proofs: $("proofGate").checked,
    }),
  });
  state.workspace = {
    ...state.workspace,
    readiness: result.readiness,
    batches: [...(state.workspace.batches || []), ...(result.batches || [])],
    review_items: result.review_items || [],
    audit_log: result.audit_log || [],
  };
  const open = openReviewItems();
  if (open.length) {
    state.selectedReviewId = open[0].id;
    setView("review");
  } else {
    setView("audit");
  }
  renderAll();
  setNotice("Batch submitted");
}

async function recordAction(itemId, actionId) {
  const note = $("actionNote")?.value || "";
  await api(`/api/review-items/${encodeURIComponent(itemId)}/actions`, {
    method: "POST",
    body: JSON.stringify({
      actor: $("actorInput").value.trim() || "operator@example.gov",
      action_id: actionId,
      note,
    }),
  });
  await loadWorkspace();
  state.selectedReviewId = itemId;
  renderReviewList();
  renderCaseDetail();
}

async function resetSession() {
  await api("/api/session/reset", { method: "POST", body: "{}" });
  state.workspace = await api("/api/workspace");
  state.selectedReviewId = "";
  state.reviewFilter = "all";
  state.historyFilter = "all";
  state.auditSearch = "";
  await loadSample("clean");
  setView("review");
  renderAll();
  setNotice("Session reset");
}

async function loadClaimFile(file) {
  if (!file) return;
  const text = await file.text();
  $("ediInput").value = text;
  const claimId = deriveClaimId(text);
  if (claimId) $("claimIdInput").value = claimId;
  $("priorAuthAttached").checked = hasPriorAuthorization(text);
  renderPrecheck();
}

function bindEvents() {
  document.querySelectorAll("[data-mode]").forEach((button) => {
    button.addEventListener("click", () => setMode(button.dataset.mode));
  });
  document.querySelectorAll(".tab").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.view));
  });
  document.querySelectorAll(".sample-chip").forEach((button) => {
    button.addEventListener("click", () => loadSample(button.dataset.sample).catch((error) => setNotice(error.message, true)));
  });
  document.querySelectorAll("[data-review-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.reviewFilter = button.dataset.reviewFilter;
      state.selectedReviewId = "";
      renderReviewList();
      renderCaseDetail();
    });
  });
  document.querySelectorAll("[data-history-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.auditSearch = $("auditSearchInput").value;
      state.historyFilter = button.dataset.historyFilter;
      renderAudit();
    });
  });
  $("auditSearchInput").addEventListener("input", () => {
    state.auditSearch = $("auditSearchInput").value;
    renderAudit();
  });
  $("auditSearchInput").addEventListener("change", () => {
    state.auditSearch = $("auditSearchInput").value;
    renderAudit();
  });
  $("auditSearchClear").addEventListener("click", () => {
    state.auditSearch = "";
    $("auditSearchInput").value = "";
    renderAudit();
  });
  $("submitBtn").addEventListener("click", () => runBusy("Submitting batch", submitBatch));
  $("resetBtn").addEventListener("click", () => runBusy("Resetting desk", resetSession));
  $("refreshBtn").addEventListener("click", () => runBusy("Refreshing desk", loadWorkspace));
  $("claimFileUpload").addEventListener("change", (event) => loadClaimFile(event.target.files?.[0]).catch((error) => setNotice(error.message, true)));
  ["claimIdInput", "ediInput", "strictOracle", "proofGate", "eligibilityActive", "providerEnrolled", "priorAuthAttached", "duplicateClaim", "programIntegrityHold"].forEach((id) => {
    $(id).addEventListener("input", renderPrecheck);
    $(id).addEventListener("change", renderPrecheck);
  });
}

async function boot() {
  bindEvents();
  setMode(state.mode);
  await loadWorkspace();
  await loadSample("clean");
  renderAll();
}

boot().catch((error) => setNotice(error.message, true));
