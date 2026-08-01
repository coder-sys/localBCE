"use strict";

const $ = (id) => document.getElementById(id);
const PORTAL_PRINCIPAL = localStorage.getItem("blPortalPrincipal") || "operator@example.gov";
const PORTAL_TOKEN = localStorage.getItem("blPortalToken") || "local-operator-token";
const HOLD_TO_SEND_MS = 1600;
const NOTE_REQUIRED_ACTIONS = new Set(["send_reminder", "verify_authorization", "deny_claim", "route_clinical", "override_review"]);
const SERVER_BLOCKED_ACTIONS = new Set(["release_payment"]);

const DECISION_MODEL = {
  release_blocked: ["prepare_request", "deny_claim", "route_clinical", "override_review"],
  documentation_requested: ["mark_docs_received", "send_reminder", "deny_claim", "reopen_review"],
  docs_received: ["verify_authorization", "send_reminder", "deny_claim", "reopen_review"],
  ready_for_release: ["reopen_review", "route_clinical"],
  released: ["reopen_review"],
  denied: ["reopen_review"],
  clinical_review: ["reopen_review", "deny_claim"],
  override_pending: ["deny_claim", "reopen_review"],
};

const ORIGINAL_CLAIMS = [
  {
    id: "claim-042",
    claimId: "BL-CLAIM-AUTH-042",
    provider: "North Valley Home Health",
    amountCents: 125000,
    procedureCode: "T1019",
    blocker: "Prior authorization missing",
    reasonCode: "G1_PRIOR_AUTH_REQUIRED",
    slaRisk: "high",
    slaText: "22h",
    assignedActor: "N. Patel",
    claimStatus: "release_blocked",
    workflowState: "release_blocked",
    paymentState: "Held",
    requestStatus: "Draft not sent",
    receiptStatus: "Pending send",
    auditStatus: "Draft not sent",
    rule: {
      id: "PA-REQUIRED",
      result: "failed",
      expected: "Approved authorization",
      found: "No matching authorization",
    },
    requiredDocs: ["PA number", "Effective dates", "T1019 match"],
    evidence: ["Eligibility verified", "Provider verified", "Duplicate clear", "Claim file readable"],
    blockerDetail: "No matching PA found",
    receipt: null,
    history: [
      {
        label: "Review opened",
        time: nowStamp(),
        detail: "Prior authorization predicate failed. Payment held pending operator action.",
      },
    ],
  },
  {
    id: "claim-087",
    claimId: "BL-CLAIM-AUTH-087",
    provider: "Marin Personal Care",
    amountCents: 98000,
    procedureCode: "T1020",
    blocker: "Prior authorization missing",
    reasonCode: "G1_PRIOR_AUTH_REQUIRED",
    slaRisk: "normal",
    slaText: "2d",
    assignedActor: "N. Patel",
    claimStatus: "release_blocked",
    workflowState: "release_blocked",
    paymentState: "Held",
    requestStatus: "Draft not sent",
    receiptStatus: "Pending send",
    auditStatus: "Draft not sent",
    rule: {
      id: "PA-REQUIRED",
      result: "failed",
      expected: "Approved authorization",
      found: "No matching authorization",
    },
    requiredDocs: ["PA number", "Effective dates", "T1020 match"],
    evidence: ["Eligibility verified", "Provider verified", "Duplicate clear", "Claim file readable"],
    blockerDetail: "No matching PA found",
    receipt: null,
    history: [
      {
        label: "Review opened",
        time: nowStamp(),
        detail: "Prior authorization predicate failed. Payment held pending operator action.",
      },
    ],
  },
  {
    id: "claim-113",
    claimId: "BL-CLAIM-AUTH-113",
    provider: "Sierra Valley Supportive Care",
    amountCents: 156000,
    procedureCode: "S5102",
    blocker: "Prior authorization missing",
    reasonCode: "G1_PRIOR_AUTH_REQUIRED",
    slaRisk: "high",
    slaText: "2d",
    assignedActor: "N. Patel",
    claimStatus: "release_blocked",
    workflowState: "release_blocked",
    paymentState: "Held",
    requestStatus: "Draft not sent",
    receiptStatus: "Pending send",
    auditStatus: "Draft not sent",
    rule: {
      id: "PA-REQUIRED",
      result: "failed",
      expected: "Approved authorization",
      found: "No matching authorization",
    },
    requiredDocs: ["PA number", "Effective dates", "S5102 match"],
    evidence: ["Eligibility verified", "Provider verified", "Duplicate clear", "Claim file readable"],
    blockerDetail: "No matching PA found",
    receipt: null,
    history: [
      {
        label: "Review opened",
        time: nowStamp(),
        detail: "Prior authorization predicate failed. Payment held pending operator action.",
      },
    ],
  },
  {
    id: "claim-144",
    claimId: "BL-CLAIM-AUTH-144",
    provider: "East Bay Home Care",
    amountCents: 70500,
    procedureCode: "T1019",
    blocker: "Prior authorization missing",
    reasonCode: "G1_PRIOR_AUTH_REQUIRED",
    slaRisk: "normal",
    slaText: "2d",
    assignedActor: "N. Patel",
    claimStatus: "release_blocked",
    workflowState: "release_blocked",
    paymentState: "Held",
    requestStatus: "Draft not sent",
    receiptStatus: "Pending send",
    auditStatus: "Draft not sent",
    rule: {
      id: "PA-REQUIRED",
      result: "failed",
      expected: "Approved authorization",
      found: "No matching authorization",
    },
    requiredDocs: ["PA number", "Effective dates", "T1019 match"],
    evidence: ["Eligibility verified", "Provider verified", "Duplicate clear", "Claim file readable"],
    blockerDetail: "No matching PA found",
    receipt: null,
    history: [
      {
        label: "Review opened",
        time: nowStamp(),
        detail: "Prior authorization predicate failed. Payment held pending operator action.",
      },
    ],
  },
  {
    id: "claim-208",
    claimId: "BL-CLAIM-AUTH-208",
    provider: "Golden State Therapy",
    amountCents: 61000,
    procedureCode: "97110",
    blocker: "Prior authorization missing",
    reasonCode: "G1_PRIOR_AUTH_REQUIRED",
    slaRisk: "normal",
    slaText: "3d",
    assignedActor: "N. Patel",
    claimStatus: "release_blocked",
    workflowState: "release_blocked",
    paymentState: "Held",
    requestStatus: "Draft not sent",
    receiptStatus: "Pending send",
    auditStatus: "Draft not sent",
    rule: {
      id: "PA-REQUIRED",
      result: "failed",
      expected: "Approved authorization",
      found: "No matching authorization",
    },
    requiredDocs: ["PA number", "Effective dates", "97110 match"],
    evidence: ["Eligibility verified", "Provider verified", "Duplicate clear", "Claim file readable"],
    blockerDetail: "No matching PA found",
    receipt: null,
    history: [
      {
        label: "Review opened",
        time: nowStamp(),
        detail: "Prior authorization predicate failed. Payment held pending operator action.",
      },
    ],
  },
  {
    id: "claim-220",
    claimId: "BL-CLAIM-AUTH-220",
    provider: "Central Coast Support",
    amountCents: 142000,
    procedureCode: "S5102",
    blocker: "Prior authorization missing",
    reasonCode: "G1_PRIOR_AUTH_REQUIRED",
    slaRisk: "normal",
    slaText: "3d",
    assignedActor: "N. Patel",
    claimStatus: "release_blocked",
    workflowState: "release_blocked",
    paymentState: "Held",
    requestStatus: "Draft not sent",
    receiptStatus: "Pending send",
    auditStatus: "Draft not sent",
    rule: {
      id: "PA-REQUIRED",
      result: "failed",
      expected: "Approved authorization",
      found: "No matching authorization",
    },
    requiredDocs: ["PA number", "Effective dates", "S5102 match"],
    evidence: ["Eligibility verified", "Provider verified", "Duplicate clear", "Claim file readable"],
    blockerDetail: "No matching PA found",
    receipt: null,
    history: [
      {
        label: "Review opened",
        time: nowStamp(),
        detail: "Prior authorization predicate failed. Payment held pending operator action.",
      },
    ],
  },
  {
    id: "claim-263",
    claimId: "BL-CLAIM-AUTH-263",
    provider: "Capital Family Services",
    amountCents: 89000,
    procedureCode: "T1020",
    blocker: "Prior authorization missing",
    reasonCode: "G1_PRIOR_AUTH_REQUIRED",
    slaRisk: "normal",
    slaText: "3d",
    assignedActor: "N. Patel",
    claimStatus: "release_blocked",
    workflowState: "release_blocked",
    paymentState: "Held",
    requestStatus: "Draft not sent",
    receiptStatus: "Pending send",
    auditStatus: "Draft not sent",
    rule: {
      id: "PA-REQUIRED",
      result: "failed",
      expected: "Approved authorization",
      found: "No matching authorization",
    },
    requiredDocs: ["PA number", "Effective dates", "T1020 match"],
    evidence: ["Eligibility verified", "Provider verified", "Duplicate clear", "Claim file readable"],
    blockerDetail: "No matching PA found",
    receipt: null,
    history: [
      {
        label: "Review opened",
        time: nowStamp(),
        detail: "Prior authorization predicate failed. Payment held pending operator action.",
      },
    ],
  },
  {
    id: "claim-305",
    claimId: "BL-CLAIM-AUTH-305",
    provider: "Valley Pediatric Care",
    amountCents: 39000,
    procedureCode: "99213",
    blocker: "Prior authorization missing",
    reasonCode: "G1_PRIOR_AUTH_REQUIRED",
    slaRisk: "normal",
    slaText: "4d",
    assignedActor: "N. Patel",
    claimStatus: "release_blocked",
    workflowState: "release_blocked",
    paymentState: "Held",
    requestStatus: "Draft not sent",
    receiptStatus: "Pending send",
    auditStatus: "Draft not sent",
    rule: {
      id: "PA-REQUIRED",
      result: "failed",
      expected: "Approved authorization",
      found: "No matching authorization",
    },
    requiredDocs: ["PA number", "Effective dates", "99213 match"],
    evidence: ["Eligibility verified", "Provider verified", "Duplicate clear", "Claim file readable"],
    blockerDetail: "No matching PA found",
    receipt: null,
    history: [
      {
        label: "Review opened",
        time: nowStamp(),
        detail: "Prior authorization predicate failed. Payment held pending operator action.",
      },
    ],
  },
  {
    id: "claim-338",
    claimId: "BL-CLAIM-AUTH-338",
    provider: "Delta Personal Care",
    amountCents: 117500,
    procedureCode: "T1020",
    blocker: "Prior authorization missing",
    reasonCode: "G1_PRIOR_AUTH_REQUIRED",
    slaRisk: "normal",
    slaText: "4d",
    assignedActor: "N. Patel",
    claimStatus: "release_blocked",
    workflowState: "release_blocked",
    paymentState: "Held",
    requestStatus: "Draft not sent",
    receiptStatus: "Pending send",
    auditStatus: "Draft not sent",
    rule: {
      id: "PA-REQUIRED",
      result: "failed",
      expected: "Approved authorization",
      found: "No matching authorization",
    },
    requiredDocs: ["PA number", "Effective dates", "T1020 match"],
    evidence: ["Eligibility verified", "Provider verified", "Duplicate clear", "Claim file readable"],
    blockerDetail: "No matching PA found",
    receipt: null,
    history: [
      {
        label: "Review opened",
        time: nowStamp(),
        detail: "Prior authorization predicate failed. Payment held pending operator action.",
      },
    ],
  },
];

const CLAIM_FACTS_BY_ID = {
  "claim-042": {
    member: "M-CA-4821-042",
    program: "HCBS waiver",
    serviceDate: "Jun 18, 2026",
    units: "18 units",
    providerNpi: "1999999984",
    authWindow: "Jun 1-Jul 31, 2026",
    policyCitation: "PA.T1019.2026",
    paLookup: "No active PA for T1019",
  },
  "claim-087": {
    member: "M-CA-6027-087",
    program: "Personal care",
    serviceDate: "Jun 17, 2026",
    units: "14 units",
    providerNpi: "1888888876",
    authWindow: "Jun 1-Jul 31, 2026",
    policyCitation: "PA.T1020.2026",
    paLookup: "No active PA for T1020",
  },
  "claim-113": {
    member: "M-CA-7104-113",
    program: "Adult day services",
    serviceDate: "Jun 18, 2026",
    units: "5 days",
    providerNpi: "1777777768",
    authWindow: "Jun 1-Aug 31, 2026",
    policyCitation: "TAR.S5102.2026",
    paLookup: "No active TAR for S5102",
  },
  "claim-144": {
    member: "M-CA-9442-144",
    program: "HCBS waiver",
    serviceDate: "Jun 16, 2026",
    units: "10 units",
    providerNpi: "1666666650",
    authWindow: "Jun 1-Jul 31, 2026",
    policyCitation: "PA.T1019.2026",
    paLookup: "No active PA for T1019",
  },
  "claim-208": {
    member: "M-CA-1835-208",
    program: "Outpatient therapy",
    serviceDate: "Jun 15, 2026",
    units: "6 units",
    providerNpi: "1555555542",
    authWindow: "Jun 1-Jul 15, 2026",
    policyCitation: "PA.97110.2026",
    paLookup: "No active PA for 97110",
  },
  "claim-220": {
    member: "M-CA-5378-220",
    program: "Adult day services",
    serviceDate: "Jun 14, 2026",
    units: "5 days",
    providerNpi: "1444444434",
    authWindow: "Jun 1-Aug 31, 2026",
    policyCitation: "TAR.S5102.2026",
    paLookup: "No active TAR for S5102",
  },
  "claim-263": {
    member: "M-CA-2609-263",
    program: "Personal care",
    serviceDate: "Jun 13, 2026",
    units: "12 units",
    providerNpi: "1333333326",
    authWindow: "Jun 1-Jul 31, 2026",
    policyCitation: "PA.T1020.2026",
    paLookup: "No active PA for T1020",
  },
  "claim-305": {
    member: "M-CA-8051-305",
    program: "Pediatric primary care",
    serviceDate: "Jun 12, 2026",
    units: "1 visit",
    providerNpi: "1222222218",
    authWindow: "Jun 1-Jun 30, 2026",
    policyCitation: "PA.99213.2026",
    paLookup: "No active PA for 99213",
  },
  "claim-338": {
    member: "M-CA-3916-338",
    program: "Personal care",
    serviceDate: "Jun 11, 2026",
    units: "16 units",
    providerNpi: "1111111100",
    authWindow: "Jun 1-Jul 31, 2026",
    policyCitation: "PA.T1020.2026",
    paLookup: "No active PA for T1020",
  },
};

const state = {
  claims: cloneClaims(),
  selectedId: "claim-042",
  filter: "my_queue",
  sort: "risk_oldest",
  search: "",
  theme: localStorage.getItem("blPortalTheme") || "dark",
  auditEvents: [],
  auditStatus: "idle",
  auditError: "",
  pendingDecisionAction: "",
  pendingDecisionClaimId: "",
  holdTimer: null,
  holdButton: null,
};

function cloneClaims() {
  return JSON.parse(JSON.stringify(ORIGINAL_CLAIMS)).map((claim) => ({
    ...claim,
    facts: {
      ...(CLAIM_FACTS_BY_ID[claim.id] || defaultFactsForClaim(claim)),
    },
  }));
}

function defaultFactsForClaim(claim) {
  return {
    member: "M-CA-0000-000",
    program: "Medi-Cal",
    serviceDate: "Jun 18, 2026",
    units: "1 unit",
    providerNpi: "0000000000",
    authWindow: "Current service window",
    policyCitation: `PA.${claim.procedureCode}.2026`,
    paLookup: `No active PA for ${claim.procedureCode}`,
  };
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[char]);
}

function formatCurrency(cents) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 2,
  }).format(Number(cents || 0) / 100);
}

function apiHeaders() {
  return {
    "Authorization": `Bearer ${PORTAL_TOKEN}`,
    "X-BL-Principal": PORTAL_PRINCIPAL,
    "Content-Type": "application/json",
  };
}

async function apiRequest(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...apiHeaders(),
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    throw new Error(`audit_api_${response.status}`);
  }
  return response.json();
}

function selectedClaim() {
  return state.claims.find((claim) => claim.id === state.selectedId) || null;
}

function isOperatorCompleted(claim) {
  return ["documentation_requested", "ready_for_release", "released", "denied", "clinical_review", "override_pending"].includes(
    claim.workflowState,
  );
}

function visibleClaims() {
  const query = state.search.trim().toLowerCase();
  return state.claims.filter((claim) => {
    if (state.filter === "missing_auth" && claim.reasonCode !== "G1_PRIOR_AUTH_REQUIRED") return false;
    if (state.filter === "sla_risk" && claim.slaRisk !== "high") return false;
    if (state.filter === "ready_for_release" && claim.workflowState !== "ready_for_release") return false;

    if (!query) return true;
    const haystack = [
      claim.claimId,
      claim.provider,
      claim.procedureCode,
      claim.blocker,
      claim.reasonCode,
      claim.paymentState,
      claim.requestStatus,
      claim.facts?.member,
      claim.facts?.program,
      claim.facts?.serviceDate,
      claim.facts?.providerNpi,
      claim.facts?.policyCitation,
    ].join(" ").toLowerCase();
    return haystack.includes(query);
  }).sort(compareClaimsForQueue);
}

function compareClaimsForQueue(a, b) {
  const riskRank = (claim) => (claim.slaRisk === "high" && !isOperatorCompleted(claim) ? 0 : 1);
  const dateRank = (claim) => Date.parse(claim.facts?.serviceDate || "") || Number.MAX_SAFE_INTEGER;
  const amountRank = (claim) => Number(claim.amountCents || 0);
  if (state.sort === "oldest") {
    return dateRank(a) - dateRank(b) || riskRank(a) - riskRank(b) || String(a.claimId).localeCompare(String(b.claimId));
  }
  if (state.sort === "amount") {
    return amountRank(b) - amountRank(a) || riskRank(a) - riskRank(b) || dateRank(a) - dateRank(b);
  }
  return riskRank(a) - riskRank(b) || dateRank(a) - dateRank(b) || String(a.claimId).localeCompare(String(b.claimId));
}

function queueSortLabel() {
  if (state.sort === "oldest") return "Sorted by oldest service date";
  if (state.sort === "amount") return "Sorted by billed amount";
  if (state.filter === "ready_for_release") return "Sorted by oldest ready item";
  if (state.filter === "sla_risk") return "Sorted by oldest high-SLA item";
  return "Sorted by high SLA, oldest service date";
}

function applyTheme() {
  document.documentElement.dataset.theme = state.theme;
  $("themeToggle").textContent = state.theme === "dark" ? "Dark" : "Light";
  localStorage.setItem("blPortalTheme", state.theme);
}

function render() {
  applyTheme();
  renderHeader();
  renderFilters();
  renderQueue();
  renderDecision();
  renderRail();
}

function scrollDecisionToTop() {
  $("decisionPane").scrollTop = 0;
}

function renderHeader() {
  const buckets = workBuckets();
  const highSla = state.claims.filter((claim) => claim.slaRisk === "high" && !isOperatorCompleted(claim)).length;
  const closedPct = Math.round((buckets.closed / state.claims.length) * 100);
  $("sessionSummary").innerHTML = `${buckets.active} active &middot; ${buckets.waiting} waiting &middot; ${buckets.ready} ready &middot; ${buckets.closed} closed &middot; ${highSla} high SLA`;
  $("sessionClock").textContent = "Closed";
  $("authState").textContent = `${buckets.closed}/${state.claims.length}`;
  $("dayArcFill").style.width = `${closedPct}%`;
}

function workBuckets() {
  return state.claims.reduce((buckets, claim) => {
    if (["released", "denied"].includes(claim.workflowState)) buckets.closed += 1;
    else if (claim.workflowState === "ready_for_release") buckets.ready += 1;
    else if (["documentation_requested", "clinical_review", "override_pending"].includes(claim.workflowState)) buckets.waiting += 1;
    else buckets.active += 1;
    return buckets;
  }, { active: 0, waiting: 0, ready: 0, closed: 0 });
}

function renderFilters() {
  document.querySelectorAll("[data-filter]").forEach((button) => {
    button.classList.toggle("active", button.dataset.filter === state.filter);
  });
}

function renderQueue() {
  const list = $("queueList");
  const claims = visibleClaims();
  $("queueCount").textContent = String(claims.length);
  $("queueSort").textContent = queueSortLabel();
  $("sortSelect").value = state.sort;

  if (claims.length === 0) {
    list.innerHTML = '<div class="empty-state">No claims match this view.</div>';
    return;
  }

  list.innerHTML = claims.map((claim) => renderQueueRow(claim)).join("");
}

function renderQueueRow(claim) {
  const selected = claim.id === state.selectedId;
  const risk = claim.slaRisk === "high"
    ? `<span class="risk-label">High SLA</span> / ${escapeHtml(claim.slaText)}`
    : `Normal SLA / ${escapeHtml(claim.slaText)}`;
  const facts = claim.facts || defaultFactsForClaim(claim);
  return `
    <button class="queue-row${selected ? " selected" : ""}" type="button" role="option" aria-selected="${selected}" data-claim-id="${escapeHtml(claim.id)}">
      <span class="line">
        <span class="row-blocker">${escapeHtml(claim.provider)}</span>
        <span class="row-amount">${escapeHtml(formatCurrency(claim.amountCents))}</span>
      </span>
      <span class="line">
        <span class="row-claim">${escapeHtml(claim.claimId)}</span>
        <span class="muted">${risk}</span>
      </span>
      <span class="line">
        <span class="row-provider">${escapeHtml(facts.member)} &middot; ${escapeHtml(facts.serviceDate)}</span>
        <span class="row-service">${escapeHtml(claim.procedureCode)} &middot; ${escapeHtml(facts.units)}</span>
      </span>
    </button>`;
}

function renderDecision() {
  const pane = $("decisionPane");
  const claim = selectedClaim();

  if (!claim || !visibleClaims().some((item) => item.id === claim.id)) {
    pane.innerHTML = `
      <div class="empty-state">
        <strong>No selected claim</strong>
        <p>Choose a claim from the work queue.</p>
      </div>`;
    return;
  }

  pane.innerHTML = `
    <div class="decision-inner">
    <div class="status-row">
      <span class="status-pill ${statusTone(claim)}">${escapeHtml(statusLabel(claim))}</span>
    </div>
    <h2>${escapeHtml(decisionTitle(claim))}</h2>
    <p class="claim-identity" data-mono="true">${escapeHtml(claim.claimId)} &middot; ${escapeHtml(formatCurrency(claim.amountCents))} &middot; ${escapeHtml(claim.provider)}</p>
    ${renderCaseFacts(claim)}
    ${renderRuleStrip(claim)}
    ${claim.workflowState === "documentation_requested" ? renderReceipt(claim) : renderDraftOrOutcome(claim)}
    </div>
  `;
}

function renderCaseFacts(claim) {
  const facts = claim.facts || defaultFactsForClaim(claim);
  const items = [
    { label: "Member", value: facts.member },
    { label: "Program", value: facts.program },
    { label: "Service date", value: facts.serviceDate },
    { label: "Procedure", value: `${claim.procedureCode} / ${facts.units}` },
    { label: "Provider NPI", value: facts.providerNpi },
    { label: "Auth window", value: facts.authWindow },
    { label: "Policy", value: facts.policyCitation },
    { label: "PA lookup", value: facts.paLookup, wide: true },
  ];

  return `
    <dl class="case-facts" aria-label="Claim facts">
      ${items.map((item) => `
        <div${item.wide ? ' class="fact-wide"' : ""}>
          <dt>${escapeHtml(item.label)}</dt>
          <dd>${escapeHtml(item.value)}</dd>
        </div>`).join("")}
    </dl>`;
}

function statusTone(claim) {
  if (claim.workflowState === "released" || claim.workflowState === "ready_for_release") return "ok";
  if (["documentation_requested", "docs_received", "clinical_review", "override_pending"].includes(claim.workflowState)) return "pending";
  return "blocked";
}

function statusLabel(claim) {
  const labels = {
    release_blocked: "Release blocked",
    documentation_requested: "Release blocked",
    docs_received: "Docs received",
    ready_for_release: "Ready for release",
    released: "Released",
    denied: "Denied",
    clinical_review: "Clinical review",
    override_pending: "Override review",
  };
  return labels[claim.workflowState] || "Release blocked";
}

function decisionTitle(claim) {
  const titles = {
    release_blocked: "Prior authorization required",
    documentation_requested: "Prior authorization required",
    docs_received: "Authorization packet received",
    ready_for_release: "Authorization received",
    released: "Payment released",
    denied: "Claim denied",
    clinical_review: "Clinical review requested",
    override_pending: "Override review pending",
  };
  return titles[claim.workflowState] || "Prior authorization required";
}

function renderRuleStrip(claim) {
  const result = claim.rule.result === "passed" ? "passed" : claim.rule.result === "needs_review" ? "needs_review" : "failed";
  return `
    <div class="rule-strip">
      <div class="rule-strip-label">Hold reason</div>
      <div class="rule-strip-main">
        <strong>${escapeHtml(claim.rule.id)}</strong>
        <span class="rule-result" data-result="${escapeHtml(result)}">${escapeHtml(result.replace("_", " "))}</span>
      </div>
      <div class="rule-strip-compare">
        <span><b>Expected</b> ${escapeHtml(claim.rule.expected)}</span>
        <span><b>Found</b> ${escapeHtml(claim.rule.found)}</span>
      </div>
      <button class="rule-strip-details" type="button" data-action="view_predicates">View predicates</button>
    </div>`;
}

function renderDraftOrOutcome(claim) {
  if (claim.workflowState === "release_blocked") return renderRequestDraft(claim);
  if (claim.workflowState === "docs_received") return renderDocsReceived(claim);
  if (claim.workflowState === "ready_for_release") return renderReadyForRelease(claim);
  if (claim.workflowState === "released") return renderSimpleOutcome(claim, "Payment released", `${formatCurrency(claim.amountCents)} payment instruction recorded after authorization match.`);
  if (claim.workflowState === "denied") return renderSimpleOutcome(claim, "Claim denied", "The denial decision is recorded. No payment instruction is prepared.");
  if (claim.workflowState === "clinical_review") return renderSimpleOutcome(claim, "Clinical review requested", "Payment remains held while the clinical queue reviews the authorization exception.");
  if (claim.workflowState === "override_pending") return renderSimpleOutcome(claim, "Override review pending", "Payment remains held. This operator cannot release from override review without a separate approval path.");
  return renderRequestDraft(claim);
}

function requiredDocsSummary(claim) {
  return claim.requiredDocs.join(" / ");
}

function renderActionLedger(rows) {
  return `
    <dl class="action-ledger">
      ${rows.map(([term, value]) => `
        <div>
          <dt>${escapeHtml(term)}</dt>
          <dd>${escapeHtml(value)}</dd>
        </div>`).join("")}
    </dl>`;
}

function renderRequestDraft(claim) {
  return `
    <div class="decision-surface action-card request-draft" data-state="draft">
      <div class="next-action-panel">
        <div class="next-action-copy">
          <h3>Next action</h3>
          <p>Ask the provider for the missing authorization packet. Keep payment held.</p>
          ${renderActionLedger([
            ["Request fields", requiredDocsSummary(claim)],
            ["Payment", "Held until authorization match"],
          ])}
        </div>
        <div class="major-actions">
          <button id="primaryAction" type="button" data-action="prepare_request">Prepare request</button>
          <button class="secondary-small" type="button" data-action="open_decisions">Other decisions</button>
        </div>
      </div>
    </div>`;
}

function defaultRequestMessage(claim) {
  return `Please send the prior authorization documentation for ${claim.claimId}: ${claim.requiredDocs.join(", ")}. Payment remains held until the authorization matches ${claim.procedureCode} for the service date.`;
}

function renderRequestDrawer(claim) {
  const facts = claim.facts || defaultFactsForClaim(claim);
  return `
    <div class="request-draft">
      <dl class="request-draft-list">
        <div>
          <dt>Recipient</dt>
          <dd>${escapeHtml(claim.provider)}</dd>
        </div>
        <div>
          <dt>Claim</dt>
          <dd data-mono="true">${escapeHtml(claim.claimId)}</dd>
        </div>
        <div>
          <dt>Requested docs</dt>
          <dd>${escapeHtml(claim.requiredDocs.join(", "))}</dd>
        </div>
        <div>
          <dt>Policy reason</dt>
          <dd>${escapeHtml(facts.policyCitation)} / ${escapeHtml(claim.rule.expected)}</dd>
        </div>
      </dl>
      <label class="textarea-label" for="requestMessage">
        Message
        <textarea id="requestMessage" class="request-message-textarea">${escapeHtml(defaultRequestMessage(claim))}</textarea>
      </label>
      <p class="hold-status" id="holdStatus">Review the request, then hold to send.</p>
      <div class="drawer-actions">
        <button class="hold-send-button" type="button" data-action="confirm_prepare_request" data-claim-id="${escapeHtml(claim.id)}">
          <span class="hold-fill" aria-hidden="true"></span>
          <span class="hold-label">Hold 1.6s to send</span>
        </button>
        <button class="drawer-secondary" type="button" data-action="open_decisions">Other decisions</button>
      </div>
    </div>`;
}

function openRequestDrawer(claim) {
  if (!claim) return;
  openDrawer("Documentation request", claim.claimId, renderRequestDrawer(claim));
}

function resetHoldButton(button) {
  if (!button) return;
  button.dataset.holding = "false";
  button.style.setProperty("--hold-progress", "0%");
  const label = button.querySelector(".hold-label");
  if (label) label.textContent = "Hold 1.6s to send";
  const status = $("holdStatus");
  if (status) status.textContent = "Review the request, then hold to send.";
}

function cancelHoldToSend() {
  if (state.holdTimer) {
    clearTimeout(state.holdTimer);
    state.holdTimer = null;
  }
  resetHoldButton(state.holdButton);
  state.holdButton = null;
}

function completeHoldToSend(button) {
  const claim = state.claims.find((item) => item.id === button.dataset.claimId);
  if (!claim) {
    cancelHoldToSend();
    return;
  }
  const message = $("requestMessage")?.value || defaultRequestMessage(claim);
  state.holdTimer = null;
  state.holdButton = null;
  state.selectedId = claim.id;
  closeDrawer();
  performDecision("prepare_request", message, { confirmedRequest: true });
}

function startHoldToSend(button) {
  if (button.dataset.action !== "confirm_prepare_request") return;
  cancelHoldToSend();
  state.holdButton = button;
  button.dataset.holding = "true";
  button.style.setProperty("--hold-progress", "0%");
  button.offsetWidth;
  button.style.setProperty("--hold-progress", "100%");
  const label = button.querySelector(".hold-label");
  if (label) label.textContent = "Keep holding...";
  const status = $("holdStatus");
  if (status) status.textContent = "Release before the bar fills to cancel.";
  state.holdTimer = setTimeout(() => completeHoldToSend(button), HOLD_TO_SEND_MS);
}

function renderReceipt(claim) {
  const receipt = claim.receipt;
  const packetEvent = providerPacketEventForClaim(claim);
  const withdrawalEvent = providerWithdrawalEventForClaim(claim);
  const packetMessage = withdrawalEvent
    ? "Provider withdrew the request. Payment remains held; record denial or reopen review."
    : packetEvent
    ? "Provider packet is in the payer audit stream. Open the attachment, then mark docs received."
    : `Sent ${receipt.sentAt} to ${claim.provider}. No packet is in the payer audit stream yet.`;
  const ledgerRows = [
    ["Requested", requiredDocsSummary(claim)],
    ["Payment", "Still held"],
  ];
  if (withdrawalEvent) ledgerRows.splice(1, 0, ["Provider", "Request withdrawn"]);
  else if (packetEvent) ledgerRows.splice(1, 0, ["Packet", "Available for review"]);
  else ledgerRows.splice(1, 0, ["Packet", "Awaiting provider"]);
  const receiptActions = packetEvent && !withdrawalEvent
    ? `
        <button id="primaryAction" type="button" data-action="mark_docs_received">Mark docs received</button>
        <button class="secondary-small" type="button" data-action="open_decisions">Other decisions</button>
      `
    : '<button class="secondary-small" type="button" data-action="open_decisions">Other decisions</button>';
  return `
    <div class="decision-surface action-card is-review" data-state="recorded">
      <div class="card-heading">
        <div>
          <p>Waiting on provider packet</p>
        </div>
        <span class="receipt-seal">Recorded</span>
      </div>
      <div class="next-action-copy">
        <p>${escapeHtml(packetMessage)}</p>
        ${renderActionLedger(ledgerRows)}
        ${renderClaimPacketAttachments(claim)}
      </div>
      <div class="receipt-actions">
        ${receiptActions}
      </div>
    </div>`;
}

function renderDocsReceived(claim) {
  return `
    <div class="decision-surface action-card is-review">
      <div class="card-heading">
        <div>
          <p>Verify packet before release</p>
        </div>
        <span class="receipt-seal">Needs match</span>
      </div>
      <div class="next-action-copy">
        <p>Payment stays held. Match the packet to the claim and policy window.</p>
        ${renderActionLedger([
          ["Fields", requiredDocsSummary(claim)],
          ["Rule", "Still failed"],
        ])}
        ${renderClaimPacketAttachments(claim)}
      </div>
      <div class="receipt-actions">
        <button id="primaryAction" type="button" data-action="verify_authorization">Verify authorization</button>
        <button class="secondary-small" type="button" data-action="open_decisions">Other decisions</button>
      </div>
    </div>`;
}

function renderReadyForRelease(claim) {
  return `
    <div class="decision-surface action-card is-approved">
      <div class="card-heading">
        <div>
          <p>Authorization match recorded</p>
        </div>
        <span class="receipt-seal">Ready</span>
      </div>
      <div class="next-action-copy">
        <p>The authorization hold is cleared. Payment remains held until verified proof and settlement are recorded by the trusted services.</p>
        ${renderActionLedger([
          ["Clearance", "Rule passed / authorization matched"],
          ["Next record", "Verified proof and settlement"],
        ])}
      </div>
      <div class="receipt-actions">
        <button id="primaryAction" type="button" disabled>Awaiting verified proof + settlement</button>
        <button class="secondary-small" type="button" data-action="open_decisions">Other decisions</button>
      </div>
    </div>`;
}

function renderSimpleOutcome(claim, title, copy) {
  const actions = DECISION_MODEL[claim.workflowState] || [];
  const hasMoreDecisions = actions.some((action) => action !== "reopen_review");

  return `
    <div class="receipt-card receipt-hero ${claim.workflowState === "denied" ? "is-denied" : "is-review"}">
      <div class="card-heading">
        <div>
          <p>${escapeHtml(title)}</p>
          <span>${escapeHtml(copy)}</span>
        </div>
        <span class="receipt-seal">${escapeHtml(claim.auditStatus)}</span>
      </div>
      <ul class="receipt-list">
        <li><strong>Claim ID</strong><span data-mono="true">${escapeHtml(claim.claimId)}</span></li>
        <li><strong>Payment state</strong><span>${escapeHtml(claim.paymentState)}</span></li>
        <li><strong>Last action</strong><span>${escapeHtml(claim.history[0]?.label || "Recorded")}</span></li>
      </ul>
      <div class="receipt-actions">
        <button class="secondary-small" type="button" data-action="reopen_review">Reopen review</button>
        ${hasMoreDecisions ? '<button class="secondary-small" type="button" data-action="open_decisions">Other decisions</button>' : ""}
      </div>
    </div>`;
}

function renderRail() {
  const rail = $("railPane");
  const claim = selectedClaim();
  if (!claim || !visibleClaims().some((item) => item.id === claim.id)) {
    rail.innerHTML = `
      <section class="rail-section trust-section">
        <div class="rail-head">
          <h2>Case record</h2>
        </div>
        <div class="rail-compact">
          <strong>No case selected</strong>
          <span>Choose a claim from this view.</span>
        </div>
      </section>
      <section class="rail-section">
        <div class="rail-head">
          <h2>Audit trail</h2>
          <button type="button" data-action="view_system_audit">Stream</button>
        </div>
        <div class="rail-activity">
          <strong>${escapeHtml(auditRailHeadline())}</strong>
          <span>${escapeHtml(auditRailDetail())}</span>
        </div>
      </section>`;
    return;
  }

  const auditFields = claim.workflowState === "documentation_requested"
    ? [
      ["Status", "Recorded"],
      ["Payment state", claim.paymentState],
      ["Request", "Provider packet requested"],
    ]
    : [
      ["Status", claim.auditStatus],
      ["Payment state", claim.paymentState],
      ["Reason code", claim.reasonCode],
    ];
  const latest = claim.history[0];
  const blockingEvidence = evidenceChecksForClaim(claim).find((item) => item.state === "blocked");

  rail.innerHTML = `
    <section class="rail-section trust-section">
      <div class="rail-head">
        <h2>Case record</h2>
      </div>
      ${renderAuditGrid(auditFields)}
    </section>
    <section class="rail-section">
      <div class="rail-head">
        <h2>Evidence</h2>
        <button type="button" data-action="open_evidence">Open evidence</button>
      </div>
      <div class="rail-compact">
        <strong>${escapeHtml(verifiedEvidenceCount(claim))} checks verified</strong>
        <span>${escapeHtml(railEvidenceSummary(claim, blockingEvidence))}</span>
      </div>
    </section>
    <section class="rail-section">
      <div class="rail-head">
        <h2>Last activity</h2>
        <button type="button" data-action="view_history">View log</button>
      </div>
      <div class="rail-activity">
        <strong>${escapeHtml(latest?.label || "Review opened")}</strong>
        <span>${escapeHtml(latest?.time || "")}</span>
      </div>
    </section>
    <section class="rail-section">
      <div class="rail-head">
        <h2>Audit trail</h2>
        <button type="button" data-action="view_system_audit">Stream</button>
      </div>
      <div class="rail-activity">
        <strong>${escapeHtml(auditRailHeadline())}</strong>
        <span>${escapeHtml(auditRailDetail())}</span>
      </div>
    </section>`;
}

function auditRailHeadline() {
  if (state.auditStatus === "error") return "Stream unavailable";
  if (state.auditStatus === "loading") return "Loading stream";
  return state.auditEvents.length > 0 ? "Latest system event" : "System stream";
}

function auditRailDetail() {
  if (state.auditStatus === "error") return "Claim log remains available";
  if (state.auditStatus === "loading") return "Protected endpoint";
  const latest = state.auditEvents[0];
  return latest ? `${formatEventType(latest.event_type)} / ${latest.claim_id || latest.batch_id || "system"}` : "Open for backend audit";
}

function railEvidenceSummary(claim, blockingEvidence) {
  if (blockingEvidence?.label === "PA lookup") return "Prior auth not matched";
  return claim.blockerDetail;
}

function evidenceChecksForClaim(claim) {
  const facts = claim.facts || defaultFactsForClaim(claim);
  const paState = claim.rule.result === "passed" ? "verified" : "blocked";
  const paValue = claim.rule.result === "passed"
    ? `Approved authorization matched ${claim.procedureCode} for ${facts.serviceDate}`
    : facts.paLookup;
  return [
    { label: "Eligibility", value: `${facts.member} active in ${facts.program}`, state: "verified" },
    { label: "Provider", value: `NPI ${facts.providerNpi} active for ${claim.provider}`, state: "verified" },
    { label: "Duplicate", value: "No matching paid claim found", state: "verified" },
    { label: "Claim file", value: "837 claim file readable and bound", state: "verified" },
    { label: "Policy", value: facts.policyCitation, state: "verified" },
    { label: "PA lookup", value: paValue, state: paState },
  ];
}

function verifiedEvidenceCount(claim) {
  return evidenceChecksForClaim(claim).filter((item) => item.state === "verified").length;
}

function renderAuditGrid(fields) {
  return `
    <dl class="audit-grid">
      ${fields.map(([term, value]) => `
        <div>
          <dt>${escapeHtml(term)}</dt>
          <dd>${escapeHtml(value)}</dd>
        </div>`).join("")}
    </dl>`;
}

function renderHistoryList(history) {
  return `
    <ol class="history-list">
      ${history.map((event) => `
        <li>
          <strong>${escapeHtml(event.label)}</strong>
          <span>${escapeHtml(event.time)}</span>
          <p>${escapeHtml(event.detail)}</p>
        </li>`).join("")}
    </ol>`;
}

function formatEventType(type) {
  return String(type || "event").replaceAll("_", " ");
}

function formatEventTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

function nowStamp() {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date());
}

function auditReference(event) {
  const metadata = event.metadata || {};
  if (metadata.receipt_id && metadata.packet_hash) return `${metadata.receipt_id} / ${shortReference(metadata.packet_hash)}`;
  if (metadata.message_id) return metadata.message_id;
  if (metadata.request_id) return metadata.request_id;
  return "";
}

function shortReference(value) {
  const text = String(value || "");
  return text.length > 24 ? `${text.slice(0, 12)}...${text.slice(-8)}` : text;
}

function providerPacketEventForClaim(claim) {
  if (!claim) return null;
  return state.auditEvents.find((event) => event.event_type === "provider_packet_received" && event.claim_id === claim.claimId) || null;
}

function providerWithdrawalEventForClaim(claim) {
  if (!claim) return null;
  return state.auditEvents.find((event) => event.event_type === "provider_claim_withdrawn" && event.claim_id === claim.claimId) || null;
}

function requestIdForClaim(claim) {
  return claim.receipt?.requestId || `DOC-REQ-${claim.claimId.match(/(\d+)$/)?.[1] || "000"}`;
}

function applyServerWorkflowState(claim, workflowState, paymentState = "", event = null) {
  if (!claim || !workflowState) return;
  const eventTime = formatEventTime(event?.created_at) || nowStamp();
  const eventLabel = event?.outcome || event?.metadata?.action || workflowState.replaceAll("_", " ");
  const historyEntry = {
    label: String(eventLabel).replaceAll("_", " "),
    time: eventTime,
    detail: event?.description || `Server state restored as ${workflowState.replaceAll("_", " ")}.`,
  };
  const patchByState = {
    documentation_requested: {
      claimStatus: "release_blocked",
      auditStatus: "Recorded",
      paymentState: paymentState || "Held",
      requestStatus: "Sent",
      receiptStatus: "Recorded",
    },
    docs_received: {
      claimStatus: "docs_received",
      auditStatus: "Recorded",
      paymentState: paymentState || "Held",
      requestStatus: "Documents received",
      receiptStatus: "Received",
      blockerDetail: "Authorization packet received; match not verified",
    },
    ready_for_release: {
      claimStatus: "ready_for_release",
      auditStatus: "Recorded",
      paymentState: paymentState || "Ready",
      requestStatus: "Authorization verified",
      receiptStatus: "Recorded",
      blockerDetail: "Authorization packet matched",
      rule: { ...claim.rule, result: "passed", found: "Approved authorization matched" },
      facts: {
        ...claim.facts,
        paLookup: `Approved authorization matched ${claim.procedureCode} for ${(claim.facts || defaultFactsForClaim(claim)).serviceDate}`,
      },
    },
    released: {
      claimStatus: "released",
      auditStatus: "Recorded",
      paymentState: paymentState || "Released",
      requestStatus: "Closed",
      receiptStatus: "Payment recorded",
    },
    denied: {
      claimStatus: "denied",
      auditStatus: "Recorded",
      paymentState: paymentState || "Denied",
      requestStatus: "Closed",
      receiptStatus: "No payment",
    },
    clinical_review: {
      claimStatus: "clinical_review",
      auditStatus: "Recorded",
      paymentState: paymentState || "Held",
      requestStatus: "Clinical review",
      receiptStatus: "Review recorded",
    },
    override_pending: {
      claimStatus: "override_pending",
      auditStatus: "Recorded",
      paymentState: paymentState || "Held",
      requestStatus: "Override review",
      receiptStatus: "Review recorded",
    },
  };
  const patch = patchByState[workflowState];
  if (!patch) return;
  Object.assign(claim, patch, { workflowState });
  if (workflowState === "documentation_requested" && !claim.receipt) {
    claim.receipt = {
      requestId: requestIdForClaim(claim),
      auditId: event?.id || "backend",
      hash: "backend-recorded",
      sentAt: eventTime,
      auditEvent: "Provider documentation requested",
      message: event?.metadata?.message || defaultRequestMessage(claim),
    };
  }
  if (!claim.history.some((item) => item.detail === historyEntry.detail && item.time === historyEntry.time)) {
    claim.history = [historyEntry, ...claim.history];
  }
}

function applyProviderRequestState(record) {
  const claim = state.claims.find((item) => item.claimId === record.claim_id);
  if (!claim) return;
  const latest = state.auditEvents.find((event) => event.claim_id === claim.claimId);
  const statusMap = {
    needs_packet: "documentation_requested",
    needs_correction: "documentation_requested",
    submitted: "docs_received",
    accepted: "ready_for_release",
    released: "released",
    denied: "denied",
    withdrawn: "denied",
  };
  const workflowState = statusMap[record.status];
  if (!workflowState) return;
  if (["released", "denied"].includes(claim.workflowState)) return;
  applyServerWorkflowState(claim, workflowState, record.payment_state || claim.paymentState, latest);
  if (record.request_id && !claim.receipt) {
    claim.receipt = {
      requestId: record.request_id,
      auditId: latest?.id || "backend",
      hash: "backend-recorded",
      sentAt: formatEventTime(record.updated_at) || nowStamp(),
      auditEvent: "Provider documentation requested",
      message: record.message || defaultRequestMessage(claim),
    };
  }
}

function applyWorkspaceState(payload) {
  const providerRequests = payload.provider_workspace?.requests || [];
  providerRequests.forEach(applyProviderRequestState);
  const serverStates = payload.operator_claim_states || {};
  Object.values(serverStates).forEach((record) => {
    const claim = state.claims.find((item) => item.claimId === record.claim_id);
    const event = state.auditEvents.find((candidate) => candidate.claim_id === record.claim_id && candidate.metadata?.action === record.last_action);
    applyServerWorkflowState(claim, record.workflow_state, record.payment_state, event);
  });
}

function renderClaimPacketAttachments(claim) {
  const packetEvent = providerPacketEventForClaim(claim);
  if (!packetEvent) return "";
  const metadata = packetEvent.metadata || {};
  const count = Number(metadata.attachment_count || (metadata.attachments || []).length || 0);
  return `
    <div class="packet-arrival">
      <div>
        <strong>Provider packet available</strong>
        <span>${escapeHtml(metadata.receipt_id || "Packet received")} / ${escapeHtml(count)} file(s)</span>
      </div>
      ${renderAuditAttachments(packetEvent)}
    </div>
  `;
}

function renderAuditAttachments(event) {
  const metadata = event.metadata || {};
  const attachments = Array.isArray(metadata.attachments) ? metadata.attachments : [];
  if (!attachments.length || !metadata.packet_id) return "";
  return `
    <div class="audit-attachments">
      ${attachments.map((attachment) => `
        <button
          type="button"
          data-action="download_attachment"
          data-packet-id="${escapeHtml(metadata.packet_id)}"
          data-filename="${escapeHtml(attachment.filename || "")}"
        >
          ${escapeHtml(attachment.filename || "Attachment")}
        </button>
      `).join("")}
    </div>
  `;
}

function renderAuditStream() {
  if (state.auditStatus === "loading") {
    return '<div class="empty-state">Loading protected audit stream.</div>';
  }
  if (state.auditStatus === "error") {
    return `
      <div class="empty-state">
        <strong>Backend audit stream unavailable</strong>
        <p>The claim log is still visible. Check the portal token before using this as the system record.</p>
      </div>`;
  }
  if (state.auditEvents.length === 0) {
    return `
      <div class="empty-state">
        <strong>No backend events yet</strong>
        <p>Operator decisions will appear here as they are recorded.</p>
      </div>`;
  }
  return `
    <ol class="audit-stream">
      ${state.auditEvents.slice(0, 30).map((event) => `
        <li>
          <div class="audit-stream-head">
            <strong>${escapeHtml(formatEventType(event.event_type))}</strong>
            <span>${escapeHtml(formatEventTime(event.created_at))}</span>
          </div>
          <p>${escapeHtml(event.description || event.outcome || "Audit event recorded.")}</p>
          ${renderAuditAttachments(event)}
          <dl>
            <div>
              <dt>Actor</dt>
              <dd>${escapeHtml(event.actor || "system")}</dd>
            </div>
            <div>
              <dt>Claim</dt>
              <dd data-mono="true">${escapeHtml(event.claim_id || "-")}</dd>
            </div>
            <div>
              <dt>Outcome</dt>
              <dd>${escapeHtml(event.outcome || "recorded")}</dd>
            </div>
            <div>
              <dt>Amount</dt>
              <dd>${event.amount_cents == null ? "-" : escapeHtml(formatCurrency(event.amount_cents))}</dd>
            </div>
            ${auditReference(event) ? `
              <div>
                <dt>Reference</dt>
                <dd data-mono="true">${escapeHtml(auditReference(event))}</dd>
              </div>
            ` : ""}
          </dl>
        </li>`).join("")}
    </ol>`;
}

async function loadAuditLog({ updateDrawer = false } = {}) {
  state.auditStatus = "loading";
  state.auditError = "";
  renderDecision();
  renderRail();
  if (updateDrawer) {
    openDrawer("System audit", "Audit stream", renderAuditStream());
  }
  try {
    const payload = await apiRequest("/api/workspace");
    state.auditEvents = Array.isArray(payload.audit_log) ? payload.audit_log : [];
    applyWorkspaceState(payload);
    state.auditStatus = "loaded";
  } catch (error) {
    try {
      const payload = await apiRequest("/api/audit-log");
      state.auditEvents = Array.isArray(payload.events) ? payload.events : [];
      state.auditStatus = "loaded";
    } catch (fallbackError) {
      state.auditStatus = "error";
      state.auditError = fallbackError.message || error.message;
    }
  }
  render();
  if (updateDrawer && !$("drawer").hidden && $("drawerKicker").textContent === "System audit") {
    $("drawerBody").innerHTML = renderAuditStream();
  }
}

function openSystemAuditDrawer() {
  openDrawer("System audit", "Audit stream", renderAuditStream());
  loadAuditLog({ updateDrawer: true });
}

function recordOperatorAuditEvent(claim, action, nextState, auditEvent) {
  return apiRequest("/api/operator-events", {
    method: "POST",
    body: JSON.stringify({
      claim_id: claim.claimId,
      action,
      description: auditEvent.detail,
      metadata: {
        request_id: requestIdForClaim(claim),
        ...(auditEvent.metadata || {}),
      },
    }),
  }).then((payload) => {
    state.auditEvents = Array.isArray(payload.audit_log) ? payload.audit_log : state.auditEvents;
    applyWorkspaceState(payload);
    state.auditStatus = "loaded";
    state.auditError = "";
    render();
    renderRail();
  });
}

async function downloadAttachment(button) {
  const packetId = button?.dataset.packetId || "";
  const filename = button?.dataset.filename || "";
  if (!packetId || !filename) return;
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Opening...";
  try {
    const response = await fetch(`/api/provider-packets/${encodeURIComponent(packetId)}/attachments/${encodeURIComponent(filename)}`, {
      headers: {
        "Authorization": `Bearer ${PORTAL_TOKEN}`,
        "X-BL-Principal": PORTAL_PRINCIPAL,
      },
    });
    if (!response.ok) throw new Error(`Download failed with ${response.status}`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    button.textContent = "Opened";
  } catch (error) {
    button.textContent = "Unavailable";
    state.auditError = error.message;
  } finally {
    window.setTimeout(() => {
      button.disabled = false;
      button.textContent = original;
    }, 1400);
  }
}

function transitionClaim(claim, action, nextState, _patch, auditEvent) {
  const previousWorkflowState = claim.workflowState;
  const allowed = DECISION_MODEL[claim.workflowState] || [];
  if (!allowed.includes(action)) {
    throw new Error(`Invalid transition ${action} from ${claim.workflowState}`);
  }

  state.auditStatus = "saving";
  state.auditError = "";
  renderRail();
  return recordOperatorAuditEvent(claim, action, nextState, {
    ...auditEvent,
    metadata: {
      previous_workflow_state: previousWorkflowState,
      ...(auditEvent.metadata || {}),
    },
  }).catch((error) => {
    state.auditStatus = "error";
    state.auditError = `${error.message}. No local claim state was changed.`;
    render();
    renderRail();
  });
}

function prepareRequest(claim, message = "") {
  const suffix = claim.claimId.match(/(\d+)$/)?.[1] || "000";
  const sentAt = nowStamp();
  const requestMessage = message.trim() || defaultRequestMessage(claim);
  const receipt = {
    requestId: `DOC-REQ-${suffix}`,
    auditId: `AUD-OP-${suffix}`,
    hash: `hash-${suffix}-${suffix}`,
    sentAt,
    auditEvent: "Provider documentation requested",
    message: requestMessage,
  };
  const facts = claim.facts || defaultFactsForClaim(claim);

  transitionClaim(
    claim,
    "prepare_request",
    "documentation_requested",
    {
      auditStatus: "Recorded",
      requestStatus: "Sent",
      receiptStatus: "Recorded",
      paymentState: "Held",
      receipt,
    },
    {
      label: "Documentation request sent",
      time: sentAt,
      detail: `${receipt.requestId} recorded. Payment remains held pending authorization documents.`,
      metadata: {
        request_id: receipt.requestId,
        audit_id: receipt.auditId,
        message: requestMessage,
        required_items: claim.requiredDocs,
        provider: claim.provider,
        provider_npi: facts.providerNpi,
        procedure_code: claim.procedureCode,
        service_date: facts.serviceDate,
        amount_cents: claim.amountCents,
      },
    },
  );
}

function markDocsReceived(claim) {
  const packetEvent = providerPacketEventForClaim(claim);
  if (!packetEvent) {
    throw new Error("No provider packet is in the audit stream yet. Wait for the packet or send a follow-up.");
  }
  const metadata = packetEvent.metadata || {};
  transitionClaim(
    claim,
    "mark_docs_received",
    "docs_received",
    {
      claimStatus: "docs_received",
      auditStatus: "Recorded",
      paymentState: "Held",
      requestStatus: "Documents received",
      receiptStatus: "Received",
      blockerDetail: "Authorization packet received; match not verified",
      facts: {
        ...claim.facts,
        paLookup: `Authorization packet received; not yet matched for ${claim.procedureCode}`,
      },
    },
    {
      label: "Documents received",
      time: nowStamp(),
      detail: `${metadata.receipt_id || "Provider packet"} was received. Payment remains held until the packet is matched against policy.`,
    },
  );
}

function verifyAuthorization(claim, note = "") {
  if (!providerPacketEventForClaim(claim)) {
    throw new Error("Authorization cannot be verified until a provider packet is available in the audit stream.");
  }
  const matchNote = note.trim();
  transitionClaim(
    claim,
    "verify_authorization",
    "ready_for_release",
    {
      claimStatus: "ready_for_release",
      auditStatus: "Recorded",
      paymentState: "Ready",
      requestStatus: "Authorization verified",
      receiptStatus: "Recorded",
      blockerDetail: "Authorization packet matched",
      facts: {
        ...claim.facts,
        paLookup: `Approved authorization matched ${claim.procedureCode} for ${claim.facts.serviceDate}`,
      },
      rule: {
        ...claim.rule,
        result: "passed",
        found: "Approved authorization matched",
      },
    },
    {
      label: "Authorization verified",
      time: nowStamp(),
      detail: detailWithRationale("Provider documentation matched the prior authorization predicate. Payment is ready for release.", matchNote),
    },
  );
}

function decisionActionCopy(action) {
  return {
    prepare_request: ["Send documentation request", "Send the provider documentation request and record the audit receipt.", ""],
    deny_claim: ["Deny claim", "Close this claim without a payment instruction.", "danger"],
    route_clinical: ["Route to clinical review", "Send the exception to clinical review while payment remains held.", "warning"],
    override_review: ["Open override review", "Request a formal release exception. Payment remains held.", "warning"],
    mark_docs_received: ["Mark docs received", "Record that the authorization packet arrived. Payment stays held.", ""],
    verify_authorization: ["Verify authorization", "Match the received packet against the policy window before release.", ""],
    send_reminder: ["Request follow-up", "Ask the provider to complete or correct the authorization packet.", ""],
    reopen_review: ["Reopen review", "Return the claim to the blocked prior-authorization state.", "warning"],
  }[action] || [action, "Record this decision.", ""];
}

function detailWithRationale(detail, note) {
  const clean = String(note || "").trim();
  return clean ? `${detail} Rationale: ${clean}` : detail;
}

function openDecisionNoteDrawer(action) {
  const claim = selectedClaim();
  if (!claim) return;
  const copy = decisionActionCopy(action);
  const noteLabel = action === "send_reminder" ? "Provider message" : action === "verify_authorization" ? "Match note" : "Internal rationale";
  const notePlaceholder = action === "send_reminder"
    ? "Write the follow-up message for the provider"
    : action === "verify_authorization"
      ? "Record the PA number/date/procedure match you verified"
      : "Short reason for the audit trail";
  const errorCopy = action === "send_reminder"
    ? "Enter the provider follow-up message before sending."
    : action === "verify_authorization"
      ? "Enter what matched before recording verification."
      : "Enter a short rationale before recording this decision.";
  state.pendingDecisionAction = action;
  state.pendingDecisionClaimId = claim.id;
  openDrawer("Decision note", copy[0], `
    <div class="request-draft">
      <p class="drawer-message">${escapeHtml(copy[1])}</p>
      <label class="textarea-label" for="decisionNote">
        ${escapeHtml(noteLabel)}
        <textarea id="decisionNote" class="internal-note-textarea" placeholder="${escapeHtml(notePlaceholder)}"></textarea>
      </label>
      <p class="form-error" id="decisionNoteError" hidden>${escapeHtml(errorCopy)}</p>
      <div class="drawer-actions">
        <button class="drawer-primary" type="button" data-action="confirm_decision_note">Record decision</button>
        <button class="drawer-secondary" type="button" data-action="open_decisions">Other decisions</button>
      </div>
    </div>`);
  $("decisionNote").focus();
}

function confirmPendingDecision() {
  const note = $("decisionNote")?.value.trim() || "";
  if (!note) {
    $("decisionNoteError").hidden = false;
    $("decisionNote").focus();
    return;
  }
  const action = state.pendingDecisionAction;
  const claimId = state.pendingDecisionClaimId;
  if (!action || !claimId) return;
  state.selectedId = claimId;
  state.pendingDecisionAction = "";
  state.pendingDecisionClaimId = "";
  performDecision(action, note, { confirmedNote: true });
}

function performDecision(action, note = "", options = {}) {
  const claim = selectedClaim();
  if (!claim) return;
  if (SERVER_BLOCKED_ACTIONS.has(action)) {
    state.auditStatus = "error";
    state.auditError = "Payment release is disabled until verified proof and settlement are recorded by trusted services.";
    renderRail();
    return;
  }

  try {
    if (NOTE_REQUIRED_ACTIONS.has(action) && !options.confirmedNote) {
      openDecisionNoteDrawer(action);
      return;
    }

    if (action === "prepare_request") {
      if (!options.confirmedRequest) {
        openRequestDrawer(claim);
        return;
      }
      prepareRequest(claim, note);
    } else if (action === "mark_docs_received") {
      markDocsReceived(claim);
    } else if (action === "verify_authorization") {
      verifyAuthorization(claim, note);
    } else if (action === "send_reminder") {
      const nextReminderState = claim.workflowState === "docs_received" ? "docs_received" : "documentation_requested";
      transitionClaim(
        claim,
        "send_reminder",
        nextReminderState,
        {
          auditStatus: "Recorded",
          paymentState: "Held",
          requestStatus: claim.workflowState === "docs_received" ? "Follow-up requested / docs retained" : "Follow-up requested",
          receiptStatus: claim.workflowState === "docs_received" ? "Received" : "Recorded",
        },
        {
          label: "Follow-up requested",
          time: nowStamp(),
          detail: "A provider follow-up was recorded for the authorization packet. Payment remains held.",
          metadata: {
            request_id: claim.receipt?.requestId || `DOC-REQ-${claim.claimId.match(/(\d+)$/)?.[1] || "000"}`,
            message: note || "Please complete or correct the authorization packet.",
            required_items: claim.requiredDocs,
            provider: claim.provider,
            provider_npi: (claim.facts || defaultFactsForClaim(claim)).providerNpi,
            procedure_code: claim.procedureCode,
            service_date: (claim.facts || defaultFactsForClaim(claim)).serviceDate,
            amount_cents: claim.amountCents,
          },
        },
      );
    } else if (action === "deny_claim") {
      transitionClaim(
        claim,
        "deny_claim",
        "denied",
        {
          claimStatus: "denied",
          auditStatus: "Recorded",
          paymentState: "Denied",
          requestStatus: "Closed",
          receiptStatus: "No payment",
        },
        {
          label: "Claim denied",
          time: nowStamp(),
          detail: detailWithRationale("Operator recorded denial because required authorization was not supplied.", note),
        },
      );
    } else if (action === "route_clinical") {
      transitionClaim(
        claim,
        "route_clinical",
        "clinical_review",
        {
          claimStatus: "clinical_review",
          auditStatus: "Recorded",
          paymentState: "Held",
          requestStatus: "Clinical review",
          receiptStatus: "Review recorded",
        },
        {
          label: "Clinical review requested",
          time: nowStamp(),
          detail: detailWithRationale("The claim was routed to clinical review. Payment remains held.", note),
        },
      );
    } else if (action === "override_review") {
      transitionClaim(
        claim,
        "override_review",
        "override_pending",
        {
          claimStatus: "override_pending",
          auditStatus: "Recorded",
          paymentState: "Held",
          requestStatus: "Override review",
          receiptStatus: "Review recorded",
        },
        {
          label: "Override review opened",
          time: nowStamp(),
          detail: detailWithRationale("A release override review was opened. No payment can release until review completes.", note),
        },
      );
    } else if (action === "reopen_review") {
      const currentState = claim.workflowState;
      transitionClaim(
        claim,
        "reopen_review",
        "release_blocked",
        {
          claimStatus: "release_blocked",
          auditStatus: "Draft not sent",
          paymentState: "Held",
          requestStatus: "Draft not sent",
          receiptStatus: "Pending send",
          receipt: null,
          blockerDetail: "No matching PA found",
          facts: {
            ...(CLAIM_FACTS_BY_ID[claim.id] || defaultFactsForClaim(claim)),
          },
          rule: {
            ...claim.rule,
            result: "failed",
            found: "No matching authorization",
          },
        },
        {
          label: "Review reopened",
          time: nowStamp(),
          detail: `Review reopened from ${currentState.replaceAll("_", " ")}. Payment is held.`,
        },
      );
    }
    closeDrawer();
    render();
    scrollDecisionToTop();
  } catch (error) {
    openDrawer("State guard", "Action unavailable", `<p class="drawer-message">${escapeHtml(error.message)}</p>`);
  }
}

function openDecisionDrawer() {
  const claim = selectedClaim();
  if (!claim) return;
  const actions = (DECISION_MODEL[claim.workflowState] || []).filter((action) => action !== "mark_docs_received" || providerPacketEventForClaim(claim));
  const body = `
    <div class="drawer-choice-list">
      <section class="decision-choice-group">
        <h3>Available decisions</h3>
        ${actions.map((action) => renderDecisionButton(action)).join("")}
      </section>
      <section class="drawer-provenance provenance-panel">
        <h3>Guardrail</h3>
        <p class="drawer-message">Every choice writes one audit event and keeps payment held unless the claim is explicitly ready for release.</p>
      </section>
    </div>`;
  openDrawer("Other decisions", claim.claimId, body);
}

function renderDecisionButton(action) {
  const copy = decisionActionCopy(action);

  return `
    <button type="button" data-action="${escapeHtml(action)}"${copy[2] ? ` data-tone="${escapeHtml(copy[2])}"` : ""}>
      <strong>${escapeHtml(copy[0])}</strong>
      <span>${escapeHtml(copy[1])}</span>
    </button>`;
}

function openPredicatesDrawer() {
  const claim = selectedClaim();
  if (!claim) return;
  const facts = claim.facts || defaultFactsForClaim(claim);
  const body = `
    <section class="drawer-provenance provenance-panel">
      <div class="provenance-headline">
        <h3>Predicate trace</h3>
        <span class="rule-result" data-result="${escapeHtml(claim.rule.result)}">${escapeHtml(claim.rule.result.replace("_", " "))}</span>
      </div>
      <div class="provenance-item">
        <div class="provenance-main">
          <div>
            <strong class="provenance-rule-name">${escapeHtml(claim.rule.id)}</strong>
            <span class="provenance-rule-id">${escapeHtml(claim.reasonCode)}</span>
          </div>
        </div>
        <p class="provenance-evidence">${escapeHtml(claim.blockerDetail)}</p>
        <dl class="provenance-compare">
          <div>
            <dt>Expected</dt>
            <dd>${escapeHtml(claim.rule.expected)}</dd>
          </div>
          <div>
            <dt>Found</dt>
            <dd>${escapeHtml(claim.rule.found)}</dd>
          </div>
          <div>
            <dt>Policy</dt>
            <dd>${escapeHtml(facts.policyCitation)}</dd>
          </div>
          <div>
            <dt>Authorization window</dt>
            <dd>${escapeHtml(facts.authWindow)}</dd>
          </div>
        </dl>
      </div>
    </section>`;
  openDrawer("Rule check", "Prior authorization", body);
}

function openEvidenceDrawer() {
  const claim = selectedClaim();
  if (!claim) return;
  const body = `
    <ul class="packet-list">
      ${evidenceChecksForClaim(claim).map((item) => `
        <li>
          <strong>${escapeHtml(item.label)}</strong>
          <span class="${item.state === "verified" ? "state-ok" : "state-bad"}">${escapeHtml(item.value)}</span>
        </li>`).join("")}
    </ul>`;
  openDrawer("Evidence", claim.claimId, body);
}

function openHistoryDrawer() {
  const claim = selectedClaim();
  if (!claim) return;
  openDrawer("Request log", claim.claimId, renderHistoryList(claim.history));
}

function openDrawer(kicker, title, body) {
  $("drawerKicker").textContent = kicker;
  $("drawerTitle").textContent = title;
  $("drawerBody").innerHTML = body;
  $("drawerBackdrop").hidden = false;
  $("drawer").hidden = false;
}

function closeDrawer() {
  cancelHoldToSend();
  state.pendingDecisionAction = "";
  state.pendingDecisionClaimId = "";
  $("drawerBackdrop").hidden = true;
  $("drawer").hidden = true;
}

function openCommandPalette() {
  $("commandPalette").hidden = false;
}

function closeCommandPalette() {
  $("commandPalette").hidden = true;
}

function moveSelection(direction) {
  const claims = visibleClaims();
  if (claims.length === 0) return;
  const currentIndex = Math.max(0, claims.findIndex((claim) => claim.id === state.selectedId));
  const nextIndex = (currentIndex + direction + claims.length) % claims.length;
  state.selectedId = claims[nextIndex].id;
  render();
  scrollDecisionToTop();
}

function setFilter(filter) {
  state.filter = filter;
  const claims = visibleClaims();
  if (claims.length > 0 && !claims.some((claim) => claim.id === state.selectedId)) {
    state.selectedId = claims[0].id;
  }
  render();
  scrollDecisionToTop();
}

function resetSession() {
  cancelHoldToSend();
  state.claims = cloneClaims();
  state.selectedId = "claim-042";
  state.filter = "my_queue";
  state.sort = "risk_oldest";
  state.search = "";
  state.pendingDecisionAction = "";
  state.pendingDecisionClaimId = "";
  $("searchInput").value = "";
  $("sortSelect").value = state.sort;
  closeDrawer();
  closeCommandPalette();
  render();
  scrollDecisionToTop();
}

function primaryActionForClaim(claim) {
  if (!claim) return null;
  if (claim.workflowState === "release_blocked") return "prepare_request";
  if (claim.workflowState === "documentation_requested") return providerPacketEventForClaim(claim) ? "mark_docs_received" : null;
  if (claim.workflowState === "docs_received") return "verify_authorization";
  return null;
}

function handleCommand(command) {
  closeCommandPalette();
  if (command === "focus-search") {
    $("searchInput").focus();
  } else if (command === "next-claim") {
    moveSelection(1);
  } else if (command === "previous-claim") {
    moveSelection(-1);
  } else if (command === "primary-action" || command === "prepare-request") {
    const primaryAction = primaryActionForClaim(selectedClaim());
    if (primaryAction) performDecision(primaryAction);
    else openDecisionDrawer();
  } else if (command === "system-audit") {
    openSystemAuditDrawer();
  } else if (command === "toggle-theme") {
    state.theme = state.theme === "dark" ? "light" : "dark";
    render();
  } else if (command === "reset") {
    resetSession();
  }
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("button");
  if (!button) return;

  if (button.dataset.claimId) {
    state.selectedId = button.dataset.claimId;
    render();
    scrollDecisionToTop();
    return;
  }

  if (button.dataset.filter) {
    setFilter(button.dataset.filter);
    return;
  }

  if (button.dataset.command) {
    handleCommand(button.dataset.command);
    return;
  }

  if (button.dataset.action) {
    const action = button.dataset.action;
    if (action === "open_decisions") openDecisionDrawer();
    else if (action === "view_predicates") openPredicatesDrawer();
    else if (action === "open_evidence") openEvidenceDrawer();
    else if (action === "view_history") openHistoryDrawer();
    else if (action === "view_system_audit") openSystemAuditDrawer();
    else if (action === "download_attachment") downloadAttachment(button);
    else if (action === "confirm_decision_note") confirmPendingDecision();
    else if (action === "confirm_prepare_request") return;
    else performDecision(action);
  }
});

document.addEventListener("pointerdown", (event) => {
  const button = event.target.closest(".hold-send-button");
  if (!button) return;
  event.preventDefault();
  startHoldToSend(button);
});

document.addEventListener("pointerup", cancelHoldToSend);
document.addEventListener("pointercancel", cancelHoldToSend);
document.addEventListener("pointerout", (event) => {
  const button = event.target.closest?.(".hold-send-button");
  if (!button) return;
  if (event.relatedTarget && button.contains(event.relatedTarget)) return;
  cancelHoldToSend();
});

$("searchInput").addEventListener("input", (event) => {
  state.search = event.target.value;
  const claims = visibleClaims();
  if (claims.length > 0 && !claims.some((claim) => claim.id === state.selectedId)) {
    state.selectedId = claims[0].id;
  }
  render();
  scrollDecisionToTop();
});

$("sortSelect").addEventListener("change", (event) => {
  state.sort = event.target.value;
  const claims = visibleClaims();
  if (claims.length > 0 && !claims.some((claim) => claim.id === state.selectedId)) {
    state.selectedId = claims[0].id;
  }
  render();
  scrollDecisionToTop();
});

$("themeToggle").addEventListener("click", () => {
  state.theme = state.theme === "dark" ? "light" : "dark";
  render();
});

$("commandButton").addEventListener("click", openCommandPalette);
$("drawerClose").addEventListener("click", closeDrawer);
$("drawerBackdrop").addEventListener("click", closeDrawer);

document.addEventListener("keydown", (event) => {
  const active = document.activeElement;
  const isTyping = active && ["INPUT", "TEXTAREA", "SELECT"].includes(active.tagName);

  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    openCommandPalette();
    return;
  }

  if (event.key === "Escape") {
    closeDrawer();
    closeCommandPalette();
    return;
  }

  if (!isTyping && event.key === "/") {
    event.preventDefault();
    $("searchInput").focus();
    return;
  }

  if (!isTyping && (event.key === "ArrowDown" || event.key.toLowerCase() === "j")) {
    event.preventDefault();
    moveSelection(1);
    return;
  }

  if (!isTyping && (event.key === "ArrowUp" || event.key.toLowerCase() === "k")) {
    event.preventDefault();
    moveSelection(-1);
    return;
  }

  if (!isTyping && event.key === "Enter") {
    const claim = selectedClaim();
    const primaryAction = primaryActionForClaim(claim);
    if (primaryAction) {
      event.preventDefault();
      performDecision(primaryAction);
    }
  }
});

render();
loadAuditLog();
window.addEventListener("focus", () => loadAuditLog());
window.setInterval(() => loadAuditLog(), 15000);
