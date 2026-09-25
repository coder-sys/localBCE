"use strict";

// Every Owner read is verified here (digests, exact keys, bindings) before it is shown.
// All page text is written with textContent; the server's CSP allows only same-origin
// script and style, and nothing here uses innerHTML, eval or inline handlers.
(() => {
  const money = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 2 });
  const byId = (id) => document.getElementById(id);
  let snapshot = null;
  let decisionView = null;
  let correctionFollowup = null;
  let unresolvedCorrectionBody = null;
  let unresolvedCashBody = null;
  let decisionOpen = false;
  let ownerAvailable = false;
  let packageAvailable = false;
  let packageStale = true;
  let lastSuccessfulRead = 0;
  let commandPending = false;
  let workspaceRequestGeneration = 0;
  let decisionRequestGeneration = 0;
  let correctionFollowupRequestGeneration = 0;
  const CASH_CORRECTION_COMMAND = Object.freeze({
    item_id: "item-h",
    payment_id: "payment:h:p2",
    common_origin_id: "origin:payment:h:p2",
    amount_cents: 300000,
    evidence_id: "evidence:payment-h:p2",
    event_at_ms: 1775001600000,
    source_id: "fixture-payment-file",
    source_version: "payment-v2",
    local_ref: "ref:payment:h:p2",
  });
  const READ_ENVELOPE = "RR/FINANCIAL/STAFF-READ-ENVELOPE/v1";
  const OWNER_DIGEST = /^[0-9A-F]{128}$/;
  const SHA256_DIGEST = /^[0-9A-F]{64}$/;
  // A command whose response was lost or unverifiable may have committed: keep the exact body for retry.
  const UNCERTAIN_OUTCOMES = [
    "owner_command_unavailable", "Failed to fetch", "NetworkError", "command_unavailable",
    "command_outcome_uncertain", "command_response_unverified",
  ];
  const ROUTES = {
    "reject-offset": "/api/decision/reject-offset",
    acknowledge: "/api/action/acknowledge",
    "record-cash": "/api/correction/record-cash",
    "record-report": "/api/reporting/record",
    "restore-test": "/api/continuity/restore-test",
  };
  const encoder = new TextEncoder();
  let model = null;
  let role = null;
  const allowedActions = new Set();

  // Art. XIII.4: role is resolved from the path (never a query string, which
  // the server rejects outright) so a disallowed control is absent from the
  // DOM for that role, not merely disabled.
  function resolveRole() {
    const match = /^\/role\/([a-z]+)$/.exec(location.pathname);
    return match ? match[1] : null;
  }

  function renderRolePicker() {
    const list = byId("role-links");
    list.replaceChildren();
    for (const [id, label] of Object.entries(model.roles)) {
      const item = document.createElement("li");
      const link = document.createElement("a");
      link.href = "/role/" + id;
      link.textContent = label;
      item.appendChild(link);
      list.appendChild(item);
    }
  }

  function applyRoleGating() {
    for (const button of document.querySelectorAll("[data-action]")) {
      const name = button.dataset.action;
      const control = model.controls[name];
      const allowed = Boolean(control && control.roles.includes(role));
      button.hidden = !allowed;
      if (allowed) allowedActions.add(name);
      else button.disabled = true;
    }
    const screens = model.role_screens[role] || [];
    byId("workflow-section").hidden = !screens.includes("decision");
    const status = byId("role-status");
    status.replaceChildren(Object.assign(document.createElement("span"), { textContent: "Role: " + model.roles[role] + " · " }));
    status.appendChild(Object.assign(document.createElement("a"), { href: "/", textContent: "Switch role" }));
  }

  function assert(condition, code) {
    if (!condition) throw new Error(code);
  }

  function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function exactKeys(value, keys) {
    return isRecord(value)
      && Object.keys(value).length === keys.length
      && keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
  }

  function nonEmpty(value) {
    return typeof value === "string" && value.length > 0;
  }

  function count(value) {
    return Number.isSafeInteger(value) && value >= 0;
  }

  function canonicalJson(value) {
    if (value === null) return "null";
    if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
    if (typeof value === "number") {
      assert(Number.isSafeInteger(value), "read_digest_number");
      return String(value);
    }
    if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
    assert(isRecord(value), "read_digest_value");
    return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonicalJson(value[key])).join(",") + "}";
  }

  async function digest(value) {
    assert(window.crypto && window.crypto.subtle, "read_digest_unavailable");
    const bytes = await window.crypto.subtle.digest("SHA-256", encoder.encode(canonicalJson(value)));
    return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
  }

  function sameJson(left, right) {
    return canonicalJson(left) === canonicalJson(right);
  }

  function sameFields(left, right, keys) {
    return keys.every((key) => left[key] === right[key]);
  }

  function ownerIdentity(envelope) {
    return {
      schema: envelope.schema,
      schema_version: envelope.schema_version,
      scope: envelope.scope,
      mode: envelope.mode,
      owner_id: envelope.owner_id,
      continuity_epoch: envelope.continuity_epoch,
    };
  }

  function snapshotFields(envelope) {
    return { ...ownerIdentity(envelope), sequence: envelope.sequence, history_head: envelope.history_head };
  }

  function sameSnapshot(left, right) {
    return sameJson(ownerIdentity(left), ownerIdentity(right))
      && sameFields(left, right, ["sequence", "history_head", "snapshot_id"]);
  }

  function checkBinding(binding) {
    assert(exactKeys(binding, [
      "item_id", "obligation_id", "revision", "evaluation_id", "evaluation_result_digest",
      "control_pack_id", "control_pack_version", "control_pack_digest",
    ])
      && nonEmpty(binding.item_id)
      && nonEmpty(binding.obligation_id)
      && count(binding.revision)
      && nonEmpty(binding.evaluation_id)
      && nonEmpty(binding.control_pack_id)
      && Number.isSafeInteger(binding.control_pack_version) && binding.control_pack_version > 0
      && OWNER_DIGEST.test(binding.evaluation_result_digest) && OWNER_DIGEST.test(binding.control_pack_digest),
    "read_item_binding");
  }

  function checkRowBinding(row, binding) {
    assert(isRecord(row)
      && sameFields(row, binding, ["item_id", "obligation_id", "revision", "control_pack_id", "control_pack_version", "control_pack_digest"])
      && row.current_evaluation_id === binding.evaluation_id
      && row.current_evaluation_result_digest === binding.evaluation_result_digest,
    "read_item_mismatch");
  }

  function checkPackageBinding(pkg, binding, scope) {
    assert(isRecord(pkg)
      && ["RR/FINANCIAL/DECISION-PACKAGE/v1", "RR/FINANCIAL/DECISION-PACKAGE/v2"].includes(pkg.contract)
      && sameJson(pkg.scope, scope)
      && isRecord(pkg.obligation)
      && isRecord(pkg.evaluation_receipt)
      && isRecord(pkg.control_pack),
    "read_package_contract");
    const obligation = pkg.obligation;
    const receipt = pkg.evaluation_receipt;
    const pack = pkg.control_pack;
    assert(sameFields(obligation, binding, ["item_id", "obligation_id", "revision"])
      && obligation.current_evaluation_id === binding.evaluation_id,
    "read_package_obligation_binding");
    assert(receipt.evaluation_id === binding.evaluation_id
      && receipt.revision === binding.revision
      && receipt.result_digest === binding.evaluation_result_digest
      && receipt.evaluation_result_digest === binding.evaluation_result_digest,
    "read_package_evaluation_binding");
    assert(pack.pack_id === binding.control_pack_id
      && pack.version === binding.control_pack_version
      && pack.digest === binding.control_pack_digest,
    "read_package_pack_binding");
  }

  function checkTimeline(events, total, truncated, limit, sequence) {
    assert(Array.isArray(events)
      && Number.isSafeInteger(total) && total >= events.length
      && typeof truncated === "boolean"
      && truncated === (total > limit)
      && events.length === Math.min(total, limit),
    "read_timeline_incomplete");
    let previous = 0;
    for (const event of events) {
      assert(isRecord(event)
        && Number.isSafeInteger(event.event_sequence)
        && event.event_sequence > previous
        && event.event_sequence <= sequence
        && typeof event.kind === "string"
        && Number.isSafeInteger(event.committed_at_ms),
      "read_timeline_binding");
      previous = event.event_sequence;
    }
  }

  async function validateStaffRead(value, expectedResource) {
    assert(isRecord(value) && isRecord(value.read_envelope), "read_envelope_missing");
    const envelope = value.read_envelope;
    assert(exactKeys(envelope, [
      "contract", "query", "query_digest", "scope", "schema", "schema_version", "mode", "owner_id",
      "continuity_epoch", "sequence", "history_head", "snapshot_id", "item_bindings", "verification",
      "read_cost", "resources_digest", "envelope_digest",
    ]) && envelope.contract === READ_ENVELOPE, "read_envelope_contract");
    assert(["query_digest", "snapshot_id", "resources_digest", "envelope_digest"].every((key) => SHA256_DIGEST.test(envelope[key]))
      && OWNER_DIGEST.test(envelope.history_head),
    "read_envelope_digest_format");

    const resources = { ...value };
    delete resources.read_envelope;
    assert(await digest(resources) === envelope.resources_digest, "read_resources_digest");
    const envelopeBase = { ...envelope };
    delete envelopeBase.envelope_digest;
    assert(await digest(envelopeBase) === envelope.envelope_digest, "read_envelope_digest");
    assert(await digest(envelope.query) === envelope.query_digest, "read_query_digest");

    const expectedQuery = expectedResource === "workspace"
      ? {
          resource: "workspace", item_id: "item-h", population_id: "population:fixture-2026-01",
          status: "ALL", limit: 100, offset: 0, detail_limit: 100, history_limit: 200,
        }
      : { resource: "decision_package", item_id: "item-h", limit: 100, offset: 0 };
    assert(expectedResource === envelope.query.resource && sameJson(envelope.query, expectedQuery), "read_query_identity");
    assert(exactKeys(envelope.scope, ["state_id", "deployment_id", "program_id", "period_id", "currency"])
      && Object.values(envelope.scope).every(nonEmpty),
    "read_scope");
    assert(nonEmpty(envelope.schema)
      && Number.isSafeInteger(envelope.schema_version) && envelope.schema_version > 0
      && nonEmpty(envelope.mode)
      && nonEmpty(envelope.owner_id)
      && count(envelope.continuity_epoch)
      && count(envelope.sequence),
    "read_identity");
    assert(await digest(snapshotFields(envelope)) === envelope.snapshot_id, "read_snapshot_digest");

    const identityKeys = ["schema", "schema_version", "mode", "owner_id", "continuity_epoch", "sequence", "history_head"];
    const verification = envelope.verification;
    assert(exactKeys(verification, [...identityKeys, "status", "scope", "counts", "result_digest"])
      && verification.status === "VERIFIED"
      && sameFields(verification, envelope, identityKeys)
      && sameJson(verification.scope, envelope.scope)
      && exactKeys(verification.counts, [
        "events", "packs", "populations", "items", "obligations", "evidence", "payments", "claims",
        "determinations", "actions", "conflicts", "evaluations",
      ])
      && Object.values(verification.counts).every(count)
      && SHA256_DIGEST.test(verification.result_digest),
    "read_verification_binding");
    assert(exactKeys(value.integrity, [...identityKeys, "status", "scope", "counts"])
      && sameFields(value.integrity, verification, [...identityKeys, "status"])
      && sameJson(value.integrity.scope, verification.scope)
      && sameJson(value.integrity.counts, verification.counts),
    "read_integrity_binding");

    const cost = envelope.read_cost;
    const costCounts = [
      "owner_read_statement_count", "independent_verifier_statement_count",
      "independent_verifier_microseconds", "snapshot_transaction_microseconds",
    ];
    assert(exactKeys(cost, ["owner_connection_acquisitions", "independent_verifier_connection_acquisitions", ...costCounts])
      && cost.owner_connection_acquisitions === 1
      && cost.independent_verifier_connection_acquisitions === 0
      && costCounts.every((key) => count(cost[key])),
    "read_cost_binding");

    assert(Array.isArray(envelope.item_bindings) && envelope.item_bindings.length > 0, "read_item_bindings");
    const bindings = new Map();
    let previousItemId = "";
    for (const binding of envelope.item_bindings) {
      checkBinding(binding);
      assert(binding.item_id > previousItemId && !bindings.has(binding.item_id), "read_item_bindings");
      previousItemId = binding.item_id;
      bindings.set(binding.item_id, binding);
    }
    const hBinding = bindings.get("item-h");

    if (expectedResource === "workspace") {
      const page = value.item_page;
      assert(value.schema === "RR/FINANCIAL/STAFF-DEMO/v2"
        && typeof value.read_at === "string"
        && isRecord(value.summary)
        && value.summary.sequence === envelope.sequence
        && sameFields(value.summary, envelope.scope, Object.keys(envelope.scope))
        && isRecord(value.population)
        && Array.isArray(value.items)
        && value.items.length <= expectedQuery.limit
        && exactKeys(page, ["resource", "status", "limit", "offset", "count", "total_count", "next_offset"])
        && page.resource === "obligations"
        && sameFields(page, expectedQuery, ["status", "limit", "offset"])
        && page.count === value.items.length
        && page.total_count === value.summary.obligation_count
        && page.next_offset === (page.offset + page.count < page.total_count ? page.offset + page.count : null)
        && exactKeys(value.h, ["obligation", "detail", "decision_package", "timeline", "timeline_total_count", "timeline_truncated"]),
      "read_workspace_contract");
      const visibleIds = value.items.map((item) => {
        assert(isRecord(item) && typeof item.item_id === "string", "read_workspace_item");
        const binding = bindings.get(item.item_id);
        assert(binding, "read_workspace_item_binding");
        checkRowBinding(item, binding);
        assert(count(item.support_evidence_count), "read_support_count");
        return item.item_id;
      });
      assert(new Set(visibleIds).size === visibleIds.length, "read_workspace_item_duplicate");
      assert(hBinding && bindings.size === new Set([...visibleIds, "item-h"]).size, "read_workspace_binding_set");
      checkRowBinding(value.h.obligation, hBinding);
      checkRowBinding(value.h.detail, hBinding);
      const support = value.h.obligation.support_evidence_count;
      assert(Array.isArray(value.h.detail.evidence_references)
        && value.h.detail.evidence_references.every(isRecord)
        && count(support)
        && support >= value.h.detail.evidence_references.filter((row) => row.kind === "SUPPORT").length,
      "read_support_count");
      assert(value.source_assessment.h_support_status === (support === 0 ? "MISSING" : "RECORDED_UNVERIFIED"), "read_support_status");
      checkPackageBinding(value.h.decision_package, hBinding, envelope.scope);
      checkTimeline(value.h.timeline, value.h.timeline_total_count, value.h.timeline_truncated, expectedQuery.history_limit, envelope.sequence);
      assert(value.freshness.status === "UNKNOWN" && value.source_assessment.status === "UNKNOWN", "read_workspace_status");
      assert(Array.isArray(value.gate_checks)
        && value.gate_checks.every((gate) => exactKeys(gate, ["name", "status", "code", "state_unchanged"])
          && typeof gate.name === "string" && typeof gate.status === "string"
          && typeof gate.code === "string" && typeof gate.state_unchanged === "boolean"),
      "read_gate_checks");
      const off = value.nonactivation;
      assert(isRecord(value.continuity)
        && isRecord(off)
        && [off.dispatch_enabled, off.egress_enabled, off.production_usable, off.activation, off.money_movement].every((flag) => flag === false)
        && off.proof_suite_id === null,
      "read_nonactivation");
    } else {
      assert(value.schema === "RR/FINANCIAL/STAFF-DECISION-VIEW/v1"
        && value.sequence === envelope.sequence
        && hBinding
        && bindings.size === 1
        && typeof value.read_at === "string"
        && isRecord(value.source_assessment)
        && isRecord(value.freshness),
      "read_decision_view_contract");
      checkPackageBinding(value.decision_package, hBinding, envelope.scope);
      checkTimeline(value.timeline, value.timeline_total_count, value.timeline_truncated, 200, envelope.sequence);
      assert(value.source_assessment.status === "UNKNOWN" && value.freshness.status === "UNKNOWN", "read_decision_view_status");
    }
    return value;
  }

  // ---- Rendering (textContent only) ----

  function asMoney(cents) {
    return Number.isSafeInteger(cents) ? money.format(cents / 100) : "Unknown";
  }

  function utc(ms) {
    return Number.isSafeInteger(ms) ? new Date(ms).toISOString().replace("T", " ").replace(".000Z", " UTC") : "Unknown";
  }

  // Owner codes in plain words (CASE_OWNER -> case owner); dates without the clock.
  function words(code) {
    return code === null || code === undefined ? "unknown" : String(code).toLowerCase().replaceAll("_", " ");
  }

  function day(ms) {
    return Number.isSafeInteger(ms) ? utc(ms).slice(0, 10) : "unknown";
  }

  // Answer first (Art. XIII.1): what is happening with H, who owns it, the gap, the next step.
  function attentionText(value) {
    const pkg = value.h.decision_package;
    const item = value.items.find((row) => row.item_id === "item-h");
    const kase = pkg.case;
    const resolution = (pkg.conclusions || {}).case_resolution;
    const missing = resolution && Array.isArray(resolution.missing_requirements) ? resolution.missing_requirements : [];
    const parts = [(item ? item.label : "H") + " (H): case " + (kase ? words(kase.status) : "not opened"),
      "shortfall " + asMoney(pkg.obligation.shortfall_cents)];
    if (kase) parts.push("next step owner: " + words(kase.next_action_owner) + ", due " + day(kase.due_at_ms));
    parts.push(missing.length
      ? "still needed: " + missing.map(words).join(", ")
      : "Owner assessment: " + words(resolution ? resolution.assessment : null) + ", nothing outstanding");
    return parts.join(" · ") + ".";
  }

  function shown(value) {
    return value === null || value === undefined ? "Unknown" : String(value);
  }

  function setText(id, value) {
    byId(id).textContent = value === "" ? "Unknown" : shown(value);
  }

  function banner(id, kind, text) {
    const node = byId(id);
    node.textContent = text;
    node.className = "status-banner " + kind;
  }

  function costText(cost) {
    return "Owner " + cost.owner_read_statement_count + " read statements"
      + " · independent verifier " + cost.independent_verifier_statement_count + " read statements / "
      + (cost.independent_verifier_microseconds / 1000).toFixed(3) + " ms"
      + " · snapshot transaction " + (cost.snapshot_transaction_microseconds / 1000).toFixed(3) + " ms";
  }

  function addRow(tbody, cells, className) {
    const row = document.createElement("tr");
    if (className) row.className = className;
    for (const [value, cellClass] of cells) {
      const cell = document.createElement("td");
      cell.textContent = shown(value);
      if (cellClass) cell.className = cellClass;
      row.appendChild(cell);
    }
    tbody.appendChild(row);
    return row;
  }

  function addNoteRow(tbody, text, span) {
    addRow(tbody, [[text]]).firstChild.colSpan = span;
  }

  function renderTable(id, rows, span, emptyText, render) {
    const tbody = byId(id);
    tbody.replaceChildren();
    if (!Array.isArray(rows) || rows.length === 0) addNoteRow(tbody, emptyText, span);
    else for (const row of rows) render(tbody, row);
    return tbody;
  }

  function currentH() {
    return snapshot && snapshot.h && snapshot.h.obligation ? snapshot.h.obligation : null;
  }

  function currentPackage() {
    return decisionView && decisionView.decision_package ? decisionView.decision_package : null;
  }

  function staffCommandBinding(envelope, pkg) {
    const itemBinding = envelope.item_bindings.find((binding) => binding.item_id === "item-h");
    const receipt = pkg && pkg.evaluation_receipt;
    assert(itemBinding && isRecord(receipt) && isRecord(receipt.authority), "staff_command_binding");
    return {
      contract: "RR/FINANCIAL/STAFF-COMMAND-BINDING/v2",
      snapshot: { ...snapshotFields(envelope), snapshot_id: envelope.snapshot_id },
      item_binding: itemBinding,
      authority: receipt.authority,
      input: {
        evaluation_id: receipt.evaluation_id,
        evaluation_result_digest: receipt.evaluation_result_digest,
        receipt_digest: receipt.receipt_digest,
      },
    };
  }

  function detectPackageStaleness() {
    try {
      packageStale = !decisionView || !snapshot || !sameJson(
        staffCommandBinding(snapshot.read_envelope, snapshot.h.decision_package),
        staffCommandBinding(decisionView.read_envelope, decisionView.decision_package),
      );
    } catch (_error) {
      packageStale = true;
    }
  }

  function applyWorkspaceSnapshot(value, requestGeneration) {
    if (requestGeneration !== null && requestGeneration !== workspaceRequestGeneration) return false;
    const incoming = value.read_envelope;
    if (snapshot) {
      const previous = snapshot.read_envelope;
      const identityChanged = !sameJson(ownerIdentity(previous), ownerIdentity(incoming));
      if (!identityChanged && incoming.sequence < previous.sequence) return false;
      if (!identityChanged && incoming.sequence === previous.sequence && !sameSnapshot(previous, incoming)) {
        // Same sequence, different history: the Owner forked. Stop trusting every read.
        workspaceRequestGeneration += 1;
        decisionRequestGeneration += 1;
        correctionFollowupRequestGeneration += 1;
        correctionFollowup = null;
        showOwnerUnavailable();
        return false;
      }
      if (!sameSnapshot(previous, incoming)) {
        decisionRequestGeneration += 1;
        correctionFollowupRequestGeneration += 1;
        correctionFollowup = null;
      }
      if (identityChanged) {
        decisionView = null;
        decisionOpen = false;
        packageAvailable = false;
        packageStale = true;
        unresolvedCorrectionBody = null;
        unresolvedCashBody = null;
      }
    }
    renderSnapshot(value);
    return true;
  }

  function renderSnapshot(value) {
    snapshot = value;
    ownerAvailable = true;
    lastSuccessfulRead = Date.now();
    setText("population-count", value.summary.obligation_count + " / " + value.population.expected_count);
    setText("program-total", asMoney(value.summary.owed_cents));
    setText("program-cash", asMoney(value.summary.received_cash_cents));
    setText("program-shortfall", asMoney(value.summary.shortfall_cents));
    setText("open-items", value.summary.open_count);
    setText("h-attention", attentionText(value));
    setText("roster-status", value.population.completeness + " · " + value.population.imported_count + "/" + value.population.expected_count);
    setText("source-status", value.source_assessment.status + " — " + value.source_assessment.reason);
    setText("freshness-status", value.freshness.status + " — " + value.freshness.reason);
    byId("read-as-of").textContent = "Verified as of " + new Date(value.read_at).toLocaleString() + ".";
    byId("read-detail").textContent = "Snapshot " + value.read_envelope.snapshot_id.slice(0, 16)
      + " · one SQLite connection · " + costText(value.read_envelope.read_cost)
      + " · local consistency digest only; external freshness checkpoint UNKNOWN.";
    renderTable("population-rows", value.items, 6, "No obligation rows returned.", (tbody, item) => {
      const isH = item.item_id === "item-h";
      addRow(tbody, [
        [item.label + (isH ? " (H)" : "")],
        [asMoney(item.owed_cents), "number"],
        [asMoney(item.received_cash_cents), "number"],
        [asMoney(item.shortfall_cents), "number"],
        [[
          "Verification " + words(item.verification_status),
          "Case " + words(item.case_status),
          "Delivery " + words(item.delivery_status),
          "Reporting " + (item.reporting_complete ? "complete" : "pending"),
        ].join(" · ")],
        [words(item.source_status), "state-label " + (item.source_status.includes("MISSING") ? "missing" : "unverified")],
      ], isH ? "highlight" : "");
    });
    const ownerMode = value.integrity.mode === "LIVE" ? "SYNTHETIC LOCAL (Owner native mode LIVE)" : value.integrity.mode;
    banner("connection-status", "disabled", "Owner snapshot VERIFIED · " + ownerMode + " · sequence " + value.summary.sequence
      + " · full independent reconstruction used this same SQLite snapshot.");
    detectPackageStaleness();
    renderDecision();
  }

  function markViewUnusable(connectionKind, connectionText, packageText) {
    ownerAvailable = false;
    packageAvailable = false;
    packageStale = true;
    banner("connection-status", connectionKind, connectionText);
    if (decisionOpen) banner("package-staleness", connectionKind, packageText);
    updateActions();
  }

  function showOwnerUnavailable() {
    byId("read-as-of").textContent = snapshot
      ? "Last successful read: " + new Date(snapshot.read_at).toLocaleString() + " (stale while service is unavailable)."
      : "No successful read yet.";
    markViewUnusable("unavailable", (snapshot
      ? "UNAVAILABLE — showing the last successful local view; it is stale and commands are disabled."
      : "UNAVAILABLE — no Owner snapshot loaded; commands are disabled.") + " Reload this page to check again.",
    "UNAVAILABLE — the displayed decision package is retained but stale; refresh the Owner read and reopen it before any command. Reload this page to check again.");
  }

  async function fetchJson(url) {
    const response = await fetch(url, { cache: "no-store", credentials: "omit" });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error && body.error.code ? body.error.code : "read_unavailable");
    return body;
  }

  async function refreshCorrectionFollowup(requestGeneration = null) {
    const followupRequest = ++correctionFollowupRequestGeneration;
    const snapshotId = snapshot && snapshot.read_envelope.snapshot_id;
    const superseded = () => (requestGeneration !== null && requestGeneration !== workspaceRequestGeneration)
      || followupRequest !== correctionFollowupRequestGeneration
      || !snapshot || snapshot.read_envelope.snapshot_id !== snapshotId;
    try {
      const value = await fetchJson("/api/correction-followup");
      if (superseded()) return;
      const followup = value.followup;
      assert(exactKeys(value, ["contract", "status", "followup"])
        && value.contract === "RR/FINANCIAL/STAFF-CORRECTION-FOLLOWUP/v1"
        && (value.status === "NOT_STARTED"
          ? followup === null
          : value.status === "AVAILABLE"
            && isRecord(followup)
            && followup.resource === "correction_followup"
            && ["CURRENT", "REOPENED", "REVIEW_REQUIRED"].includes(followup.followup_status)
            && isRecord(followup.state_report)
            && isRecord(followup.corporate_support)),
      "correction_followup_contract");
      correctionFollowup = value;
    } catch (error) {
      if (superseded()) return;
      correctionFollowup = { status: "UNAVAILABLE", reason: error.message };
    }
    renderDecision();
  }

  async function refreshOverview() {
    if (commandPending) return;
    const requestGeneration = ++workspaceRequestGeneration;
    try {
      const value = await validateStaffRead(await fetchJson("/api/workspace"), "workspace");
      if (!applyWorkspaceSnapshot(value, requestGeneration)) return;
      await refreshCorrectionFollowup(requestGeneration);
    } catch (_error) {
      if (requestGeneration === workspaceRequestGeneration) showOwnerUnavailable();
    }
  }

  function appendFact(list, label, value) {
    const wrapper = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = shown(value);
    wrapper.append(term, description);
    list.appendChild(wrapper);
  }

  function renderDecision() {
    byId("decision-panel").hidden = !decisionOpen;
    if (!decisionOpen || !decisionView) {
      updateActions();
      return;
    }
    const pkg = currentPackage();
    const h = pkg.obligation || {};
    const receipt = pkg.evaluation_receipt || {};
    const pack = pkg.control_pack || {};
    const conclusions = pkg.conclusions || {};
    const facts = byId("case-facts");
    const bindings = byId("binding-facts");
    facts.replaceChildren();
    bindings.replaceChildren();
    const plain = (label, value) => appendFact(facts, label, value);
    const fact = (label, value) => appendFact(bindings, label, value);
    const claimPage = pkg.references && pkg.references.claims;
    const claims = claimPage && Array.isArray(claimPage.items) ? claimPage.items : [];
    const support = decisionView.source_assessment.h_support_status === "MISSING" ? "no supporting evidence" : "support recorded, unverified";
    plain("Amount owed", asMoney(h.owed_cents));
    plain("Cash received", asMoney(h.received_cash_cents));
    plain("Offset claimed", claims.length
      ? claims.map((claim) => asMoney(claim.amount_cents) + " · claim " + words(claim.status) + " · " + support).join("; ")
      : "None");
    plain("Case", pkg.case
      ? words(pkg.case.status) + " · " + words(pkg.case.reason) + " · next step owner: " + words(pkg.case.next_action_owner)
        + " · due " + day(pkg.case.due_at_ms)
      : "No case opened");
    const determination = pkg.current_determination;
    plain("Current determination", determination
      ? words(determination.decision) + " · decided by " + words(determination.actor_role) + " · " + utc(determination.decided_at_ms)
        + " · evidence " + (determination.supporting_evidence || []).map((row) => (isRecord(row) ? row.evidence_id : row)).join(", ")
      : "None yet");
    plain("Rules", [pack.calculation_rule_id, pack.adjustment_rule_id].filter(Boolean).join(" · "));
    plain("Continuity", snapshot && snapshot.continuity ? snapshot.continuity.mode : "Unknown");
    fact("Decision package contract", pkg.contract);
    fact("Owner sequence reviewed", decisionView.sequence);
    fact("Read snapshot", decisionView.read_envelope.snapshot_id);
    fact("Same-snapshot verification", decisionView.integrity.status + " · " + decisionView.read_envelope.verification.result_digest);
    fact("Read cost", costText(decisionView.read_envelope.read_cost) + ".");
    fact("Obligation revision", h.revision);
    fact("Evaluation receipt", receipt.evaluation_id);
    fact("Evaluation result digest", receipt.result_digest);
    fact("Scope", JSON.stringify(pkg.scope));
    fact("Control Pack", [pack.pack_id, "v" + String(pack.version), pack.digest].filter(Boolean).join(" · "));
    fact("Trusted authority", receipt.authority
      ? [receipt.authority.authority_id, "epoch " + String(receipt.authority.epoch), receipt.authority.digest].join(" · ")
      : "Unknown");
    // The Mirror withholds input_snapshot_digest from staff; the receipt digest binds it.
    fact("Input state", "receipt " + String(receipt.receipt_digest));
    fact("Case reference", pkg.case ? pkg.case.case_id : "No case reference");
    fact("Source evidence", decisionView.source_assessment.status + " · H support " + decisionView.source_assessment.h_support_status);
    const durable = correctionFollowup && correctionFollowup.followup;
    const followupUnavailable = Boolean(correctionFollowup && correctionFollowup.status === "UNAVAILABLE");
    fact("Durable correction follow-up", correctionFollowup ? correctionFollowup.status : "UNAVAILABLE");
    byId("followup-json").textContent = durable
      ? JSON.stringify({ state_report: durable.state_report, allowlisted_support: durable.corporate_support }, null, 2)
      : followupUnavailable
        ? "Follow-up read unavailable: " + correctionFollowup.reason
        : "No accepted correction event has created durable follow-up.";
    if (durable) {
      const corporate = durable.corporate_support;
      const artifact = corporate.artifact;
      fact("Follow-up event", durable.source_event_sequence + " · " + durable.followup_status);
      fact("State report", durable.state_report.contract + " · " + durable.state_report.followup_status);
      fact("Allowlisted support", corporate.contract + " · " + corporate.status
        + " · " + corporate.failure_stage + " / " + corporate.error_class
        + (artifact ? " · artifact v" + artifact.version + " " + artifact.sha256 : ""));
    } else if (followupUnavailable) {
      fact("Follow-up read", correctionFollowup.reason);
    }

    const action = pkg.current_action;
    const delivery = conclusions.action_acknowledgment;
    setText("action-status", action
      ? action.status + " · " + (delivery ? delivery.result : "UNKNOWN") + " · cash effect " + asMoney(0)
      : "No action authorized · delivery UNKNOWN");
    const cash = conclusions.cash_satisfaction;
    setText("cash-status", cash
      ? cash.result + " · " + asMoney(cash.recorded_received_cash_cents) + " received · " + asMoney(cash.missing_cents) + " missing · evidence " + cash.evidence_status
      : "Cash status unavailable");
    const reporting = conclusions.reporting_completion;
    setText("reporting-status", reporting
      ? reporting.result + " · " + String(pkg.reporting.evidence_count) + " report evidence record(s)"
      : "Reporting status unavailable");

    const unresolved = [
      "Source authenticity is UNKNOWN: the manifest digest and evidence references are synthetic caller assertions.",
      "No feed watermark or source-specific freshness rule is available, so source freshness remains UNKNOWN.",
      "An action ACK records delivery only and contributes $0 to cash.",
    ];
    for (const claim of claims) {
      if (claim.status === "CLAIMED") {
        unresolved.push("H's " + asMoney(claim.amount_cents) + " offset claim has " + support + "; it is not an approved adjustment until decided.");
      }
    }
    if (cash && cash.missing_cents > 0) unresolved.push("Cash shortfall remains " + asMoney(cash.missing_cents) + ".");
    if (reporting && reporting.result !== "SUPPORTED") unresolved.push("Reporting completion remains " + reporting.result + ".");
    const resolution = conclusions.case_resolution;
    if (resolution) unresolved.push("Owner case assessment: " + resolution.assessment + "; missing requirements: " + (resolution.missing_requirements || []).join(", "));
    byId("unknowns").replaceChildren(...unresolved.map((text) => {
      const item = document.createElement("li");
      item.textContent = text;
      return item;
    }));

    const timeline = renderTable("timeline-rows", decisionView.timeline, 4, "No H chronology returned.", (tbody, event) => {
      addRow(tbody, [
        [event.event_sequence],
        [words(event.kind)],
        [event.after_revision === null || event.after_revision === undefined
          ? "—"
          : String(event.before_revision) + " → " + String(event.after_revision)],
        [utc(event.committed_at_ms)],
      ]);
    });
    if (decisionView.timeline.length > 0 && decisionView.timeline_truncated) {
      addNoteRow(timeline, "Showing " + decisionView.timeline.length + " recent events of " + decisionView.timeline_total_count + "; older history is omitted.", 4);
    }
    byId("package-json").textContent = JSON.stringify(pkg, null, 2);
    if (!ownerAvailable) {
      banner("package-staleness", "unavailable", "UNAVAILABLE — package contents are retained from the last successful Owner read; commands are disabled.");
    } else if (packageStale) {
      banner("package-staleness", "stale", "STALE REVIEW — the verified snapshot, scope, H revision, evaluation, Control Pack, authority, or input state changed. Reopen the package before a new command.");
    } else {
      banner("package-staleness", "pending", "The displayed scope, Owner snapshot, H revision, Control Pack, authority, and evaluation input match the current Owner view.");
    }
    setText("package-revision", "Sequence " + decisionView.sequence + " · revision " + h.revision);
    updateActions();
  }

  async function openPackage() {
    const requestGeneration = ++decisionRequestGeneration;
    try {
      const value = await validateStaffRead(await fetchJson("/api/decision-package"), "decision_package");
      if (requestGeneration !== decisionRequestGeneration) return;
      if (!snapshot || !sameSnapshot(snapshot.read_envelope, value.read_envelope)) {
        packageAvailable = false;
        packageStale = true;
        banner("package-staleness", "stale", "STALE READ — the package and overview do not describe the same Owner snapshot. Refresh and reopen the package.");
        if (!decisionOpen) commandMessage("The package changed while it was loading. The overview is refreshing; open the package again.", "error");
        updateActions();
        await refreshOverview();
        return;
      }
      decisionView = value;
      decisionOpen = true;
      packageAvailable = true;
      detectPackageStaleness();
      renderDecision();
      byId("decision-panel").scrollIntoView({ block: "start", behavior: "smooth" });
    } catch (error) {
      if (requestGeneration !== decisionRequestGeneration) return;
      packageAvailable = false;
      banner("package-staleness", "unavailable", "UNAVAILABLE — decision package read failed (" + error.message + ").");
      if (!decisionOpen) commandMessage("The decision package could not be loaded. Refresh the overview and try again.", "error");
      if (decisionView) packageStale = true;
      updateActions();
    }
  }

  function commandBody(name) {
    if (name === "reject-offset" && unresolvedCorrectionBody) return unresolvedCorrectionBody;
    if (name === "record-cash" && unresolvedCashBody) return unresolvedCashBody;
    const pkg = currentPackage();
    if (!pkg || !pkg.obligation) return null;
    const revision = { revision: pkg.obligation.revision };
    if (["acknowledge", "record-report"].includes(name)) return revision;
    if (name === "record-cash") return { ...revision, cash_command: { ...CASH_CORRECTION_COMMAND } };
    if (!pkg.evaluation_receipt) return null;
    return {
      ...revision,
      evaluation_id: pkg.evaluation_receipt.evaluation_id,
      evaluation_result_digest: pkg.evaluation_receipt.result_digest,
      read_binding: staffCommandBinding(decisionView.read_envelope, pkg),
    };
  }

  function applyCommandSnapshot(value, startedAt) {
    const incoming = value.read_envelope;
    const current = snapshot && snapshot.read_envelope;
    const identityMatches = Boolean(startedAt && current
      && sameJson(ownerIdentity(startedAt), ownerIdentity(incoming))
      && sameJson(ownerIdentity(startedAt), ownerIdentity(current)));
    const notOlderThanStart = Boolean(startedAt && incoming.sequence >= startedAt.sequence
      && (incoming.sequence !== startedAt.sequence || sameSnapshot(startedAt, incoming)));
    return identityMatches && notOlderThanStart && applyWorkspaceSnapshot(value, null);
  }

  function setButton(name, disabled, retryLabel) {
    if (!allowedActions.has(name)) return; // absent for this role: stays hidden and disabled
    const button = document.querySelector('[data-action="' + name + '"]');
    if (!button) return;
    if (!button.dataset.defaultLabel) button.dataset.defaultLabel = button.textContent;
    button.textContent = retryLabel || button.dataset.defaultLabel;
    button.disabled = disabled;
  }

  function updateActions() {
    const reviewed = Boolean(ownerAvailable && packageAvailable && decisionView && !packageStale && !commandPending);
    const pkg = currentPackage();
    const h = currentH();
    const action = pkg ? pkg.current_action : null;
    const decided = Boolean(pkg && pkg.current_determination);
    const testMode = Boolean(snapshot && snapshot.continuity && snapshot.continuity.mode === "TEST");
    const canRetry = ownerAvailable && !commandPending;
    byId("refresh-button").disabled = commandPending;
    const correctionRetry = Boolean(unresolvedCorrectionBody && canRetry);
    const cashRetry = Boolean(unresolvedCashBody && canRetry);
    setButton("reject-offset", correctionRetry ? false : !reviewed || decided, correctionRetry && "Retry exact correction command");
    setButton("acknowledge", !reviewed || !action || action.status !== "READY");
    setButton("record-cash", cashRetry ? false : !reviewed || !action || action.status !== "ACKNOWLEDGED" || !h || h.shortfall_cents <= 0,
      cashRetry && "Retry exact cash evidence command");
    setButton("record-report", !reviewed || !h || h.reporting_complete || h.shortfall_cents > 0);
    setButton("restore-test", !reviewed || testMode || !h);
  }

  function commandMessage(text, kind) {
    const node = byId("command-status");
    node.textContent = text;
    node.className = "command-status " + kind;
  }

  function describeError(code) {
    if (UNCERTAIN_OUTCOMES.includes(code)) {
      return "Command outcome is unavailable and may have committed. Refresh the overview, reopen the package, and inspect Owner state before retrying.";
    }
    return {
      authority_actor_not_authorized: "Owner denied the command because the fixed synthetic reporter role cannot make a financial decision.",
      obligation_revision_conflict: "Owner rejected the stale revision. Reopen the H package and review the current revision.",
      evaluation_revision_conflict: "Owner rejected the evaluation binding because it no longer matches the current package.",
      loopback_origin_required: "The service accepts this action only from its exact loopback browser origin.",
    }[code] || "Command result is unresolved (" + words(code) + "). Refresh the overview and reopen the package before any retry.";
  }

  async function postJson(url, body) {
    let response;
    let value;
    try {
      response = await fetch(url, {
        method: "POST",
        cache: "no-store",
        credentials: "omit",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      value = await response.json();
    } catch (_error) {
      throw new Error("command_outcome_uncertain");
    }
    if (!response.ok) {
      throw new Error(isRecord(value) && isRecord(value.error) && typeof value.error.code === "string"
        ? value.error.code
        : "command_unavailable");
    }
    try {
      assert(isRecord(value) && isRecord(value.workspace), "command_workspace_missing");
      await validateStaffRead(value.workspace, "workspace");
    } catch (_error) {
      throw new Error("command_response_unverified");
    }
    return value;
  }

  async function performAction(name) {
    if (commandPending) return;
    const envelope = snapshot && snapshot.read_envelope;
    const startedAt = envelope ? { ...ownerIdentity(envelope), ...snapshotFields(envelope), snapshot_id: envelope.snapshot_id } : null;
    const route = ROUTES[name];
    const body = commandBody(name);
    if (!route || !body) return;
    // Hold the exact body until the Owner answers: a lost response is retried byte for byte.
    if (name === "reject-offset") unresolvedCorrectionBody = body;
    if (name === "record-cash") unresolvedCashBody = body;
    commandPending = true;
    updateActions();
    let refreshAfter = false;
    let reopenAfter = false;
    try {
      const result = await postJson(route, body);
      if (name === "reject-offset") unresolvedCorrectionBody = null;
      if (name === "record-cash") unresolvedCashBody = null;
      let description = (result.command && result.command.status) || "Command recorded";
      if (name === "acknowledge") {
        description += ". Cash before: " + asMoney(result.cash_before_cents) + "; after: " + asMoney(result.cash_after_cents) + "; cash effect: " + asMoney(result.cash_effect_cents) + ".";
      }
      if (name === "record-cash") description += ". Synthetic evidence only; money movement: false.";
      if (name === "record-report") description += ". Reporting source: synthetic and unverified.";
      if (name === "restore-test") description = "Continuity TEST restore verified. H decision package equality: " + String(result.continuity.decision_package_equal) + ".";
      const applied = applyCommandSnapshot(result.workspace, startedAt);
      commandMessage(description + (applied ? " The package below now shows the result." : " Reopen the package to review the new Owner sequence."), "success");
      if (applied) {
        await refreshCorrectionFollowup(workspaceRequestGeneration);
        reopenAfter = decisionOpen;
      } else refreshAfter = true;
    } catch (error) {
      if (!UNCERTAIN_OUTCOMES.includes(error.message)) {
        if (name === "reject-offset") unresolvedCorrectionBody = null;
        if (name === "record-cash") unresolvedCashBody = null;
      }
      if (error.message === "owner_read_unavailable") {
        showOwnerUnavailable();
      } else {
        commandMessage(describeError(error.message), "error");
        if (error.message === "obligation_revision_conflict") {
          packageStale = true;
          banner("package-staleness", "stale", "STALE REVIEW — Owner rejected the package binding. Reload the overview and reopen H before continuing.");
        }
        refreshAfter = true;
      }
    } finally {
      commandPending = false;
      detectPackageStaleness();
      renderDecision();
      if (refreshAfter) await refreshOverview();
      else if (reopenAfter) await openPackage();
    }
  }

  byId("refresh-button").addEventListener("click", refreshOverview);
  byId("open-package").addEventListener("click", openPackage);
  document.querySelector(".action-grid").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action]");
    if (button && !button.disabled) performAction(button.dataset.action);
  });

  async function boot() {
    try {
      model = await fetchJson("/interaction-model.json");
    } catch (_error) {
      showOwnerUnavailable();
      return;
    }
    role = resolveRole();
    if (!role || !model.roles[role]) {
      byId("role-picker").hidden = false;
      renderRolePicker();
      return;
    }
    byId("workspace-root").hidden = false;
    applyRoleGating();
    refreshOverview();
    window.setInterval(refreshOverview, 15000);
    window.setInterval(() => {
      if (lastSuccessfulRead && Date.now() - lastSuccessfulRead > 30000 && ownerAvailable) {
        markViewUnusable("stale",
          "STALE LOCAL VIEW — no successful Owner read in 30 seconds; source freshness remains UNKNOWN and commands are disabled.",
          "STALE LOCAL VIEW — the open package is retained but cannot authorize a command.");
      }
    }, 5000);
  }

  boot();
})();
