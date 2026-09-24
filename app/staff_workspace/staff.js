"use strict";

(() => {
  const money = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 2 });
  const byId = (id) => document.getElementById(id);
  const overviewRows = byId("population-rows");
  const gateRows = byId("gate-rows");
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
  const encoder = new TextEncoder();

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

  function checkBinding(binding) {
    assert(exactKeys(binding, [
      "item_id", "obligation_id", "revision", "evaluation_id", "evaluation_result_digest",
      "control_pack_id", "control_pack_version", "control_pack_digest",
    ]), "read_item_binding");
    assert(typeof binding.item_id === "string" && binding.item_id.length > 0, "read_item_binding");
    assert(typeof binding.obligation_id === "string" && binding.obligation_id.length > 0, "read_item_binding");
    assert(Number.isSafeInteger(binding.revision) && binding.revision >= 0, "read_item_binding");
    assert(typeof binding.evaluation_id === "string" && binding.evaluation_id.length > 0, "read_item_binding");
    assert(typeof binding.control_pack_id === "string" && binding.control_pack_id.length > 0, "read_item_binding");
    assert(Number.isSafeInteger(binding.control_pack_version) && binding.control_pack_version > 0, "read_item_binding");
    assert(OWNER_DIGEST.test(binding.evaluation_result_digest) && OWNER_DIGEST.test(binding.control_pack_digest), "read_item_binding");
  }

  function checkRowBinding(row, binding) {
    assert(isRecord(row)
      && row.item_id === binding.item_id
      && row.obligation_id === binding.obligation_id
      && row.revision === binding.revision
      && row.current_evaluation_id === binding.evaluation_id
      && row.current_evaluation_result_digest === binding.evaluation_result_digest
      && row.control_pack_id === binding.control_pack_id
      && row.control_pack_version === binding.control_pack_version
      && row.control_pack_digest === binding.control_pack_digest,
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
    assert(obligation.item_id === binding.item_id
      && obligation.obligation_id === binding.obligation_id
      && obligation.revision === binding.revision
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
    const envelopeKeys = [
      "contract", "query", "query_digest", "scope", "schema", "schema_version", "mode", "owner_id",
      "continuity_epoch", "sequence", "history_head", "snapshot_id", "item_bindings", "verification",
      "read_cost", "resources_digest", "envelope_digest",
    ];
    assert(exactKeys(envelope, envelopeKeys) && envelope.contract === READ_ENVELOPE, "read_envelope_contract");
    assert(SHA256_DIGEST.test(envelope.query_digest)
      && SHA256_DIGEST.test(envelope.snapshot_id)
      && OWNER_DIGEST.test(envelope.history_head)
      && SHA256_DIGEST.test(envelope.resources_digest)
      && SHA256_DIGEST.test(envelope.envelope_digest),
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
      && Object.values(envelope.scope).every((part) => typeof part === "string" && part.length > 0),
    "read_scope");
    assert(typeof envelope.schema === "string" && envelope.schema.length > 0
      && Number.isSafeInteger(envelope.schema_version) && envelope.schema_version > 0
      && typeof envelope.mode === "string" && envelope.mode.length > 0
      && typeof envelope.owner_id === "string" && envelope.owner_id.length > 0
      && Number.isSafeInteger(envelope.continuity_epoch) && envelope.continuity_epoch >= 0
      && Number.isSafeInteger(envelope.sequence) && envelope.sequence >= 0,
    "read_identity");
    const snapshotBase = {
      schema: envelope.schema,
      schema_version: envelope.schema_version,
      scope: envelope.scope,
      mode: envelope.mode,
      owner_id: envelope.owner_id,
      continuity_epoch: envelope.continuity_epoch,
      sequence: envelope.sequence,
      history_head: envelope.history_head,
    };
    assert(await digest(snapshotBase) === envelope.snapshot_id, "read_snapshot_digest");

    const verification = envelope.verification;
    const verificationKeys = [
      "status", "schema", "schema_version", "scope", "mode", "owner_id", "continuity_epoch", "sequence", "history_head", "counts", "result_digest",
    ];
    const countKeys = ["events", "packs", "populations", "items", "obligations", "evidence", "payments", "claims", "determinations", "actions", "conflicts", "evaluations"];
    assert(exactKeys(verification, verificationKeys)
      && verification.status === "VERIFIED"
      && verification.schema === envelope.schema
      && verification.schema_version === envelope.schema_version
      && sameJson(verification.scope, envelope.scope)
      && verification.mode === envelope.mode
      && verification.owner_id === envelope.owner_id
      && verification.continuity_epoch === envelope.continuity_epoch
      && verification.sequence === envelope.sequence
      && verification.history_head === envelope.history_head
      && exactKeys(verification.counts, countKeys)
      && Object.values(verification.counts).every((count) => Number.isSafeInteger(count) && count >= 0)
      && SHA256_DIGEST.test(verification.result_digest),
    "read_verification_binding");
    assert(exactKeys(value.integrity, ["status", "schema", "schema_version", "mode", "owner_id", "continuity_epoch", "scope", "sequence", "history_head", "counts"])
      && value.integrity.status === verification.status
      && value.integrity.schema === verification.schema
      && value.integrity.schema_version === verification.schema_version
      && value.integrity.mode === verification.mode
      && value.integrity.owner_id === verification.owner_id
      && value.integrity.continuity_epoch === verification.continuity_epoch
      && sameJson(value.integrity.scope, verification.scope)
      && value.integrity.sequence === verification.sequence
      && value.integrity.history_head === verification.history_head
      && sameJson(value.integrity.counts, verification.counts),
    "read_integrity_binding");

    const cost = envelope.read_cost;
    assert(exactKeys(cost, [
      "owner_connection_acquisitions", "independent_verifier_connection_acquisitions",
      "owner_read_statement_count", "independent_verifier_statement_count",
      "independent_verifier_microseconds", "snapshot_transaction_microseconds",
    ])
      && cost.owner_connection_acquisitions === 1
      && cost.independent_verifier_connection_acquisitions === 0
      && [cost.owner_read_statement_count, cost.independent_verifier_statement_count,
        cost.independent_verifier_microseconds, cost.snapshot_transaction_microseconds]
        .every((count) => Number.isSafeInteger(count) && count >= 0),
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

    if (expectedResource === "workspace") {
      assert(value.schema === "RR/FINANCIAL/STAFF-DEMO/v2"
        && typeof value.read_at === "string"
        && isRecord(value.summary)
        && value.summary.sequence === envelope.sequence
        && value.summary.state_id === envelope.scope.state_id
        && value.summary.deployment_id === envelope.scope.deployment_id
        && value.summary.program_id === envelope.scope.program_id
        && value.summary.period_id === envelope.scope.period_id
        && value.summary.currency === envelope.scope.currency
        && isRecord(value.population)
        && Array.isArray(value.items)
        && value.items.length <= expectedQuery.limit
        && exactKeys(value.item_page, ["resource", "status", "limit", "offset", "count", "total_count", "next_offset"])
        && value.item_page.resource === "obligations"
        && value.item_page.status === expectedQuery.status
        && value.item_page.limit === expectedQuery.limit
        && value.item_page.offset === expectedQuery.offset
        && value.item_page.count === value.items.length
        && value.item_page.total_count === value.summary.obligation_count
        && value.item_page.next_offset === (value.item_page.offset + value.item_page.count < value.item_page.total_count
          ? value.item_page.offset + value.item_page.count
          : null)
        && isRecord(value.h)
        && exactKeys(value.h, ["obligation", "detail", "decision_package", "timeline", "timeline_total_count", "timeline_truncated"]),
      "read_workspace_contract");
      const visibleIds = value.items.map((item) => {
        assert(isRecord(item) && typeof item.item_id === "string", "read_workspace_item");
        const binding = bindings.get(item.item_id);
        assert(binding, "read_workspace_item_binding");
        checkRowBinding(item, binding);
        assert(Number.isSafeInteger(item.support_evidence_count) && item.support_evidence_count >= 0, "read_support_count");
        return item.item_id;
      });
      assert(new Set(visibleIds).size === visibleIds.length, "read_workspace_item_duplicate");
      const hBinding = bindings.get("item-h");
      assert(hBinding && bindings.size === new Set([...visibleIds, "item-h"]).size, "read_workspace_binding_set");
      checkRowBinding(value.h.obligation, hBinding);
      checkRowBinding(value.h.detail, hBinding);
      assert(Array.isArray(value.h.detail.evidence_references)
        && value.h.detail.evidence_references.every(isRecord)
        && Number.isSafeInteger(value.h.obligation.support_evidence_count)
        && value.h.obligation.support_evidence_count >= 0
        && value.h.obligation.support_evidence_count >= value.h.detail.evidence_references.filter((row) => row.kind === "SUPPORT").length,
      "read_support_count");
      assert(value.source_assessment.h_support_status === (value.h.obligation.support_evidence_count === 0 ? "MISSING" : "RECORDED_UNVERIFIED"), "read_support_status");
      checkPackageBinding(value.h.decision_package, hBinding, envelope.scope);
      checkTimeline(value.h.timeline, value.h.timeline_total_count, value.h.timeline_truncated, expectedQuery.history_limit, envelope.sequence);
      assert(value.freshness.status === "UNKNOWN"
        && value.source_assessment.status === "UNKNOWN"
        && Array.isArray(value.gate_checks),
      "read_workspace_status");
      assert(Array.isArray(value.gate_checks)
        && value.gate_checks.every((gate) => exactKeys(gate, ["name", "status", "code", "state_unchanged"])
          && typeof gate.name === "string" && typeof gate.status === "string"
          && typeof gate.code === "string" && typeof gate.state_unchanged === "boolean"),
      "read_gate_checks");
      assert(isRecord(value.continuity)
        && isRecord(value.nonactivation)
        && value.nonactivation.dispatch_enabled === false
        && value.nonactivation.egress_enabled === false
        && value.nonactivation.production_usable === false
        && value.nonactivation.activation === false
        && value.nonactivation.proof_suite_id === null
        && value.nonactivation.money_movement === false,
      "read_nonactivation");
    } else {
      const binding = bindings.get("item-h");
      assert(value.schema === "RR/FINANCIAL/STAFF-DECISION-VIEW/v1"
        && value.sequence === envelope.sequence
        && binding
        && bindings.size === 1
        && typeof value.read_at === "string"
        && isRecord(value.source_assessment)
        && isRecord(value.freshness),
      "read_decision_view_contract");
      checkPackageBinding(value.decision_package, binding, envelope.scope);
      checkTimeline(value.timeline, value.timeline_total_count, value.timeline_truncated, 200, envelope.sequence);
      assert(value.source_assessment.status === "UNKNOWN" && value.freshness.status === "UNKNOWN", "read_decision_view_status");
    }

    return value;
  }

  function asMoney(cents) {
    if (!Number.isSafeInteger(cents)) return "Unknown";
    return money.format(cents / 100);
  }

  function utc(ms) {
    if (!Number.isSafeInteger(ms)) return "Unknown";
    return new Date(ms).toISOString().replace("T", " ").replace(".000Z", " UTC");
  }

  function setText(id, value) {
    byId(id).textContent = value === null || value === undefined || value === "" ? "Unknown" : String(value);
  }

  function addCell(row, value, className) {
    const cell = document.createElement("td");
    cell.textContent = value === null || value === undefined ? "Unknown" : String(value);
    if (className) cell.className = className;
    row.appendChild(cell);
    return cell;
  }

  function renderItems(items) {
    overviewRows.replaceChildren();
    if (!Array.isArray(items) || items.length === 0) {
      const row = document.createElement("tr");
      addCell(row, "No obligation rows returned.");
      const cell = row.querySelector("td");
      cell.colSpan = 6;
      overviewRows.appendChild(row);
      return;
    }
    for (const item of items) {
      const row = document.createElement("tr");
      if (item.item_id === "item-h") row.className = "highlight";
      addCell(row, item.label + (item.item_id === "item-h" ? " (H)" : ""));
      addCell(row, asMoney(item.owed_cents), "number");
      addCell(row, asMoney(item.received_cash_cents), "number");
      addCell(row, asMoney(item.shortfall_cents), "number");
      addCell(row, [
        "Verification " + item.verification_status,
        "Case " + item.case_status,
        "Delivery " + item.delivery_status,
        "Reporting " + (item.reporting_complete ? "complete" : "pending"),
      ].join(" · "));
      const source = addCell(row, item.source_status.replaceAll("_", " "));
      source.className = "state-label " + (item.source_status.includes("MISSING") ? "missing" : "unverified");
      overviewRows.appendChild(row);
    }
  }

  function renderGateChecks(checks) {
    gateRows.replaceChildren();
    if (!Array.isArray(checks) || checks.length === 0) {
      const row = document.createElement("tr");
      addCell(row, "No gate attempts recorded.");
      row.firstChild.colSpan = 4;
      gateRows.appendChild(row);
      return;
    }
    for (const check of checks) {
      const row = document.createElement("tr");
      addCell(row, check.name);
      addCell(row, check.status);
      addCell(row, check.code);
      addCell(row, check.state_unchanged ? "No" : "Unknown");
      gateRows.appendChild(row);
    }
  }

  function currentH() {
    return snapshot && snapshot.h && snapshot.h.obligation ? snapshot.h.obligation : null;
  }

  function currentPackage() {
    return decisionView && decisionView.decision_package ? decisionView.decision_package : null;
  }

  function detectPackageStaleness() {
    if (!decisionView || !snapshot) {
      packageStale = true;
      return;
    }
    try {
      packageStale = !sameJson(
        staffCommandBinding(snapshot.read_envelope, snapshot.h.decision_package),
        staffCommandBinding(decisionView.read_envelope, decisionView.decision_package),
      );
    } catch (_error) {
      packageStale = true;
    }
  }

  function staffCommandBinding(envelope, pkg) {
    const itemBinding = envelope.item_bindings.find((binding) => binding.item_id === "item-h");
    const receipt = pkg && pkg.evaluation_receipt;
    assert(itemBinding && isRecord(receipt) && isRecord(receipt.authority), "staff_command_binding");
    return {
      contract: "RR/FINANCIAL/STAFF-COMMAND-BINDING/v1",
      snapshot: {
        schema: envelope.schema,
        schema_version: envelope.schema_version,
        scope: envelope.scope,
        mode: envelope.mode,
        owner_id: envelope.owner_id,
        continuity_epoch: envelope.continuity_epoch,
        sequence: envelope.sequence,
        history_head: envelope.history_head,
        snapshot_id: envelope.snapshot_id,
      },
      item_binding: itemBinding,
      authority: receipt.authority,
      input: {
        evaluation_id: receipt.evaluation_id,
        evaluation_result_digest: receipt.evaluation_result_digest,
        input_snapshot_digest: receipt.input_snapshot_digest,
        receipt_digest: receipt.receipt_digest,
      },
    };
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

  function applyWorkspaceSnapshot(value, requestGeneration) {
    if (requestGeneration !== null && requestGeneration !== workspaceRequestGeneration) return false;
    const incoming = value.read_envelope;
    if (snapshot) {
      const previous = snapshot.read_envelope;
      const identityChanged = !sameJson(ownerIdentity(previous), ownerIdentity(incoming));
      if (!identityChanged && incoming.sequence < previous.sequence) return false;
      if (!identityChanged && incoming.sequence === previous.sequence
        && (incoming.history_head !== previous.history_head || incoming.snapshot_id !== previous.snapshot_id)) {
        workspaceRequestGeneration += 1;
        decisionRequestGeneration += 1;
        correctionFollowupRequestGeneration += 1;
        correctionFollowup = null;
        showOwnerUnavailable();
        return false;
      }
      const snapshotChanged = identityChanged
        || incoming.sequence !== previous.sequence
        || incoming.history_head !== previous.history_head
        || incoming.snapshot_id !== previous.snapshot_id;
      if (snapshotChanged) {
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

  function decisionViewMatchesWorkspace(value) {
    return Boolean(snapshot
      && sameJson(ownerIdentity(snapshot.read_envelope), ownerIdentity(value.read_envelope))
      && snapshot.read_envelope.sequence === value.read_envelope.sequence
      && snapshot.read_envelope.history_head === value.read_envelope.history_head
      && snapshot.read_envelope.snapshot_id === value.read_envelope.snapshot_id);
  }

  function renderSnapshot(value) {
    if (!value || !value.read_envelope || value.read_envelope.contract !== READ_ENVELOPE) {
      throw new Error("read_envelope_missing");
    }
    snapshot = value;
    ownerAvailable = true;
    lastSuccessfulRead = Date.now();
    setText("population-count", String(value.summary.obligation_count) + " / " + String(value.population.expected_count));
    setText("program-total", asMoney(value.summary.owed_cents));
    setText("h-shortfall", asMoney(currentH() ? currentH().shortfall_cents : null));
    setText("roster-status", String(value.population.completeness) + " · " + String(value.population.imported_count) + "/" + String(value.population.expected_count));
    setText("source-status", value.source_assessment.status + " — " + value.source_assessment.reason);
    setText("freshness-status", value.freshness.status + " — " + value.freshness.reason);
    const cost = value.read_envelope.read_cost;
    const verifierMs = (cost.independent_verifier_microseconds / 1000).toFixed(3);
    const snapshotMs = (cost.snapshot_transaction_microseconds / 1000).toFixed(3);
    byId("read-as-of").textContent = "Verified local snapshot read at " + new Date(value.read_at).toLocaleString()
      + " · snapshot " + value.read_envelope.snapshot_id.slice(0, 16)
      + " · one SQLite connection"
      + " · Owner " + cost.owner_read_statement_count + " read statements"
      + " · independent verifier " + cost.independent_verifier_statement_count + " read statements / " + verifierMs + " ms"
      + " · snapshot transaction " + snapshotMs + " ms"
      + " · local consistency digest only; external freshness checkpoint UNKNOWN.";
    renderItems(value.items);
    renderGateChecks(value.gate_checks);
    const connection = byId("connection-status");
    const ownerMode = value.integrity.mode === "LIVE" ? "SYNTHETIC LOCAL (Owner native mode LIVE)" : value.integrity.mode;
    connection.textContent = "Owner snapshot VERIFIED · " + ownerMode + " · sequence " + value.summary.sequence
      + " · full independent reconstruction used this same SQLite snapshot.";
    connection.className = "status-banner disabled";
    detectPackageStaleness();
    renderDecision();
    updateActions();
  }

  function showOwnerUnavailable() {
    ownerAvailable = false;
    packageAvailable = false;
    packageStale = true;
    const connection = byId("connection-status");
    connection.textContent = snapshot
      ? "UNAVAILABLE — showing the last successful local view; it is stale and commands are disabled."
      : "UNAVAILABLE — no Owner snapshot loaded; commands are disabled.";
    connection.className = "status-banner unavailable";
    byId("read-as-of").textContent = snapshot
      ? "Last successful read: " + new Date(snapshot.read_at).toLocaleString() + " (stale while service is unavailable)."
      : "No successful read yet.";
    if (decisionOpen) {
      const status = byId("package-staleness");
      status.textContent = "UNAVAILABLE — the displayed decision package is retained but stale; refresh the Owner read and reopen it before any command.";
      status.className = "status-banner unavailable";
    }
    updateActions();
  }

  async function getJson(url) {
    const response = await fetch(url, { cache: "no-store", credentials: "omit" });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error && body.error.code ? body.error.code : "read_unavailable");
    const resource = url === "/api/workspace" ? "workspace" : "decision_package";
    return validateStaffRead(body, resource);
  }

  async function refreshCorrectionFollowup(requestGeneration = null) {
    const followupRequest = ++correctionFollowupRequestGeneration;
    const snapshotId = snapshot && snapshot.read_envelope.snapshot_id;
    try {
      const response = await fetch("/api/correction-followup", { cache: "no-store", credentials: "omit" });
      const value = await response.json();
      if (!response.ok) throw new Error(value.error && value.error.code ? value.error.code : "read_unavailable");
      if (requestGeneration !== null && requestGeneration !== workspaceRequestGeneration) return;
      if (followupRequest !== correctionFollowupRequestGeneration
        || !snapshot || snapshot.read_envelope.snapshot_id !== snapshotId) return;
      assert(exactKeys(value, ["contract", "status", "followup"])
        && value.contract === "RR/FINANCIAL/STAFF-CORRECTION-FOLLOWUP/v1"
        && ["NOT_STARTED", "AVAILABLE"].includes(value.status),
      "correction_followup_contract");
      if (value.status === "NOT_STARTED") {
        assert(value.followup === null, "correction_followup_contract");
      } else {
        const followup = value.followup;
        assert(isRecord(followup)
          && followup.resource === "correction_followup"
          && ["CURRENT", "REOPENED", "REVIEW_REQUIRED"].includes(followup.followup_status)
          && isRecord(followup.state_report)
          && isRecord(followup.corporate_support),
        "correction_followup_contract");
      }
      correctionFollowup = value;
    } catch (error) {
      if (requestGeneration !== null && requestGeneration !== workspaceRequestGeneration) return;
      if (followupRequest !== correctionFollowupRequestGeneration
        || !snapshot || snapshot.read_envelope.snapshot_id !== snapshotId) return;
      correctionFollowup = { status: "UNAVAILABLE", reason: error.message };
    }
    renderDecision();
  }

  async function refreshOverview() {
    if (commandPending) return;
    const requestGeneration = ++workspaceRequestGeneration;
    try {
      const value = await getJson("/api/workspace");
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
    description.textContent = value === null || value === undefined ? "Unknown" : String(value);
    wrapper.append(term, description);
    list.appendChild(wrapper);
  }

  function renderTimeline(events, totalCount, truncated) {
    const rows = byId("timeline-rows");
    rows.replaceChildren();
    if (!Array.isArray(events) || events.length === 0) {
      const row = document.createElement("tr");
      addCell(row, "No H chronology returned.");
      row.firstChild.colSpan = 4;
      rows.appendChild(row);
      return;
    }
    for (const event of events) {
      const row = document.createElement("tr");
      addCell(row, event.event_sequence);
      addCell(row, event.kind);
      const after = event.after_revision === null || event.after_revision === undefined
        ? "—"
        : String(event.before_revision) + " → " + String(event.after_revision);
      addCell(row, after);
      addCell(row, utc(event.committed_at_ms));
      rows.appendChild(row);
    }
    if (truncated) {
      const row = document.createElement("tr");
      addCell(row, "Showing " + String(events.length) + " recent events of " + String(totalCount) + "; older history is omitted.");
      row.firstChild.colSpan = 4;
      rows.appendChild(row);
    }
  }

  function renderDecision() {
    const panel = byId("decision-panel");
    panel.hidden = !decisionOpen;
    if (!decisionOpen || !decisionView) {
      updateActions();
      return;
    }
    const pkg = currentPackage();
    const h = pkg && pkg.obligation ? pkg.obligation : {};
    const receipt = pkg ? pkg.evaluation_receipt : {};
    const facts = byId("case-facts");
    facts.replaceChildren();
    appendFact(facts, "Decision package contract", pkg.contract);
    appendFact(facts, "Owner sequence reviewed", decisionView.sequence);
    appendFact(facts, "Read snapshot", decisionView.read_envelope.snapshot_id);
    appendFact(facts, "Same-snapshot verification", decisionView.integrity.status + " · " + decisionView.read_envelope.verification.result_digest);
    appendFact(facts, "Read cost", "Owner " + decisionView.read_envelope.read_cost.owner_read_statement_count
      + " statements; independent verifier " + decisionView.read_envelope.read_cost.independent_verifier_statement_count
      + " statements / " + (decisionView.read_envelope.read_cost.independent_verifier_microseconds / 1000).toFixed(3)
      + " ms; snapshot transaction " + (decisionView.read_envelope.read_cost.snapshot_transaction_microseconds / 1000).toFixed(3) + " ms.");
    appendFact(facts, "Obligation revision", h.revision);
    appendFact(facts, "Evaluation receipt", receipt.evaluation_id);
    appendFact(facts, "Evaluation result digest", receipt.result_digest);
    appendFact(facts, "Scope", JSON.stringify(pkg.scope));
    appendFact(facts, "Control Pack", [pkg.control_pack && pkg.control_pack.pack_id, "v" + String(pkg.control_pack && pkg.control_pack.version), pkg.control_pack && pkg.control_pack.digest].filter(Boolean).join(" · "));
    appendFact(facts, "Rules", [pkg.control_pack && pkg.control_pack.calculation_rule_id, pkg.control_pack && pkg.control_pack.adjustment_rule_id].filter(Boolean).join(" · "));
    appendFact(facts, "Trusted authority", receipt.authority
      ? [receipt.authority.authority_id, "epoch " + String(receipt.authority.epoch), receipt.authority.digest].join(" · ")
      : "Unknown");
    appendFact(facts, "Input state", [receipt.input_snapshot_digest, "receipt " + String(receipt.receipt_digest)].join(" · "));
    appendFact(facts, "Case", pkg.case ? pkg.case.case_id + " · " + pkg.case.status + " · " + pkg.case.reason : "No case reference");
    appendFact(facts, "Current determination", pkg.current_determination ? pkg.current_determination.decision : "None");
    appendFact(facts, "Source evidence", decisionView.source_assessment.status + " · H support " + decisionView.source_assessment.h_support_status);
    appendFact(facts, "Continuity", snapshot && snapshot.continuity ? snapshot.continuity.mode : "Unknown");
    const durable = correctionFollowup && correctionFollowup.followup;
    appendFact(facts, "Durable correction follow-up", correctionFollowup ? correctionFollowup.status : "UNAVAILABLE");
    byId("followup-json").textContent = durable
      ? JSON.stringify({ state_report: durable.state_report, allowlisted_support: durable.corporate_support }, null, 2)
      : correctionFollowup && correctionFollowup.status === "UNAVAILABLE"
        ? "Follow-up read unavailable: " + correctionFollowup.reason
        : "No accepted correction event has created durable follow-up.";
    if (durable) {
      const support = durable.corporate_support;
      const artifact = support.artifact;
      appendFact(facts, "Follow-up event", durable.source_event_sequence + " · " + durable.followup_status);
      appendFact(facts, "State report", durable.state_report.contract + " · " + durable.state_report.followup_status);
      appendFact(facts, "Allowlisted support", support.contract + " · " + support.status
        + " · " + support.failure_stage + " / " + support.error_class
        + (artifact ? " · artifact v" + artifact.version + " " + artifact.sha256 : ""));
    } else if (correctionFollowup && correctionFollowup.status === "UNAVAILABLE") {
      appendFact(facts, "Follow-up read", correctionFollowup.reason);
    }

    const action = pkg.current_action;
    const delivery = pkg.conclusions && pkg.conclusions.action_acknowledgment;
    setText("action-status", action
      ? action.status + " · " + (delivery ? delivery.result : "UNKNOWN") + " · cash effect " + asMoney(0)
      : "No action authorized · delivery UNKNOWN");
    const cash = pkg.conclusions && pkg.conclusions.cash_satisfaction;
    setText("cash-status", cash
      ? cash.result + " · " + asMoney(cash.recorded_received_cash_cents) + " received · " + asMoney(cash.missing_cents) + " missing · evidence " + cash.evidence_status
      : "Cash status unavailable");
    const reporting = pkg.conclusions && pkg.conclusions.reporting_completion;
    setText("reporting-status", reporting
      ? reporting.result + " · " + String(pkg.reporting.evidence_count) + " report evidence record(s)"
      : "Reporting status unavailable");

    const unknowns = byId("unknowns");
    unknowns.replaceChildren();
    const unresolved = [
      "Source authenticity is UNKNOWN: the manifest digest and evidence references are synthetic caller assertions.",
      "H has no supporting source evidence for its $3,000 offset claim; the claim is not an approved adjustment.",
      "No feed watermark or source-specific freshness rule is available, so source freshness remains UNKNOWN.",
      "An action ACK records delivery only and contributes $0 to cash.",
    ];
    if (cash && cash.missing_cents > 0) unresolved.push("Cash shortfall remains " + asMoney(cash.missing_cents) + ".");
    if (reporting && reporting.result !== "SUPPORTED") unresolved.push("Reporting completion remains " + reporting.result + ".");
    const resolution = pkg.conclusions && pkg.conclusions.case_resolution;
    if (resolution) unresolved.push("Owner case assessment: " + resolution.assessment + "; missing requirements: " + (resolution.missing_requirements || []).join(", "));
    for (const text of unresolved) {
      const item = document.createElement("li");
      item.textContent = text;
      unknowns.appendChild(item);
    }
    renderTimeline(decisionView.timeline, decisionView.timeline_total_count, decisionView.timeline_truncated);
    byId("package-json").textContent = JSON.stringify(pkg, null, 2);
    const status = byId("package-staleness");
    if (!ownerAvailable) {
      status.textContent = "UNAVAILABLE — package contents are retained from the last successful Owner read; commands are disabled.";
      status.className = "status-banner unavailable";
    } else if (packageStale) {
      status.textContent = "STALE REVIEW — the verified snapshot, scope, H revision, evaluation, Control Pack, authority, or input state changed. Reopen the package before a new command.";
      status.className = "status-banner stale";
    } else {
      status.textContent = "The displayed scope, Owner snapshot, H revision, Control Pack, authority, and evaluation input match the current Owner view.";
      status.className = "status-banner pending";
    }
    setText("package-revision", "Sequence " + decisionView.sequence + " · revision " + h.revision);
    updateActions();
  }

  async function openPackage() {
    const requestGeneration = ++decisionRequestGeneration;
    try {
      const value = await getJson("/api/decision-package");
      if (requestGeneration !== decisionRequestGeneration) return;
      if (!decisionViewMatchesWorkspace(value)) {
        packageAvailable = false;
        packageStale = true;
        const status = byId("package-staleness");
        status.textContent = "STALE READ — the package and overview do not describe the same Owner snapshot. Refresh and reopen the package.";
        status.className = "status-banner stale";
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
      const status = byId("package-staleness");
      status.textContent = "UNAVAILABLE — decision package read failed (" + error.message + ").";
      status.className = "status-banner unavailable";
      if (decisionView) packageStale = true;
      updateActions();
    }
  }

  function reviewedBody() {
    const pkg = currentPackage();
    if (!pkg || !pkg.obligation || !pkg.evaluation_receipt) return null;
    return {
      revision: pkg.obligation.revision,
      evaluation_id: pkg.evaluation_receipt.evaluation_id,
      evaluation_result_digest: pkg.evaluation_receipt.result_digest,
      read_binding: staffCommandBinding(decisionView.read_envelope, pkg),
    };
  }

  function revisionBody() {
    const pkg = currentPackage();
    if (!pkg || !pkg.obligation) return null;
    return { revision: pkg.obligation.revision };
  }

  function cashCorrectionBody() {
    const revision = revisionBody();
    if (!revision) return null;
    return { ...revision, cash_command: { ...CASH_CORRECTION_COMMAND } };
  }

  function commandStartSnapshot() {
    if (!snapshot) return null;
    const envelope = snapshot.read_envelope;
    return {
      owner: ownerIdentity(envelope),
      sequence: envelope.sequence,
      history_head: envelope.history_head,
      snapshot_id: envelope.snapshot_id,
    };
  }

  function applyCommandSnapshot(value, startedAt) {
    const incoming = value.read_envelope;
    const current = snapshot && snapshot.read_envelope;
    const identityMatches = Boolean(startedAt && current
      && sameJson(ownerIdentity(startedAt.owner), ownerIdentity(incoming))
      && sameJson(ownerIdentity(startedAt.owner), ownerIdentity(current)));
    const notOlderThanStart = Boolean(startedAt && incoming.sequence >= startedAt.sequence
      && (incoming.sequence !== startedAt.sequence
        || (incoming.history_head === startedAt.history_head && incoming.snapshot_id === startedAt.snapshot_id)));
    if (!identityMatches || !notOlderThanStart) return false;
    return applyWorkspaceSnapshot(value, null);
  }

  function updateActions() {
    const reviewed = Boolean(ownerAvailable && packageAvailable && decisionView && !packageStale && !commandPending);
    const pkg = currentPackage();
    const h = currentH();
    const action = pkg ? pkg.current_action : null;
    const determination = pkg ? pkg.current_determination : null;
    const testMode = Boolean(snapshot && snapshot.continuity && snapshot.continuity.mode === "TEST");
    const setDisabled = (name, disabled) => {
      const button = document.querySelector('[data-action="' + name + '"]');
      if (button) button.disabled = disabled;
    };
    const rejectButton = document.querySelector('[data-action="reject-offset"]');
    const correctionRetry = Boolean(unresolvedCorrectionBody && ownerAvailable && !commandPending);
    if (rejectButton) {
      if (!rejectButton.dataset.defaultLabel) rejectButton.dataset.defaultLabel = rejectButton.textContent;
      rejectButton.textContent = correctionRetry ? "Retry exact correction command" : rejectButton.dataset.defaultLabel;
    }
    setDisabled("wrong-role", !reviewed || Boolean(determination));
    setDisabled("stale-revision", !reviewed || Boolean(determination));
    setDisabled("reject-offset", correctionRetry ? false : !reviewed || Boolean(determination));
    setDisabled("acknowledge", !reviewed || !action || action.status !== "READY");
    const cashButton = document.querySelector('[data-action="record-cash"]');
    const cashRetry = Boolean(unresolvedCashBody && ownerAvailable && !commandPending);
    if (cashButton) {
      if (!cashButton.dataset.defaultLabel) cashButton.dataset.defaultLabel = cashButton.textContent;
      cashButton.textContent = cashRetry ? "Retry exact cash evidence command" : cashButton.dataset.defaultLabel;
    }
    setDisabled("record-cash", cashRetry ? false : !reviewed || !action || action.status !== "ACKNOWLEDGED" || !h || h.shortfall_cents <= 0);
    setDisabled("record-report", !reviewed || !h || h.reporting_complete);
    setDisabled("restore-test", !reviewed || testMode || !h || h.shortfall_cents > 0);
  }

  function commandMessage(text, kind) {
    const node = byId("command-status");
    node.textContent = text;
    node.className = "command-status" + (kind ? " " + kind : "");
  }

  function describeError(code) {
    const messages = {
      authority_actor_not_authorized: "Owner denied the command because the fixed synthetic reporter role cannot make a financial decision.",
      obligation_revision_conflict: "Owner rejected the stale revision. Reopen the H package and review the current revision.",
      evaluation_revision_conflict: "Owner rejected the evaluation binding because it no longer matches the current package.",
      loopback_origin_required: "The service accepts this action only from its exact loopback browser origin.",
      owner_read_unavailable: "Owner/Mirror read is unavailable. The last successful view is stale and commands are disabled.",
    };
    if (["owner_command_unavailable", "Failed to fetch", "NetworkError", "command_unavailable", "command_outcome_uncertain", "command_response_unverified"].includes(code)) {
      return "Command outcome is unavailable and may have committed. Refresh the overview, reopen the package, and inspect Owner state before retrying.";
    }
    return messages[code] || "Command result is unresolved (" + code + "). Refresh the overview and reopen the package before any retry.";
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
      const code = isRecord(value) && isRecord(value.error) && typeof value.error.code === "string"
        ? value.error.code
        : "command_unavailable";
      throw new Error(code);
    }
    try {
      assert(isRecord(value) && isRecord(value.workspace), "command_workspace_missing");
      await validateStaffRead(value.workspace, "workspace");
      if (url === "/api/attempt/wrong-role" || url === "/api/attempt/stale-revision") {
        assert(isRecord(value.gate) && Array.isArray(value.workspace.gate_checks)
          && value.workspace.gate_checks.some((gate) => sameJson(gate, value.gate)),
        "read_gate_result_binding");
      }
    } catch (_error) {
      throw new Error("command_response_unverified");
    }
    return value;
  }

  async function performAction(name) {
    if (commandPending) return;
    const startedAt = commandStartSnapshot();
    let route = "";
    let body = {};
    const packageBody = reviewedBody();
    const revBody = revisionBody();
    if (name === "wrong-role") { route = "/api/attempt/wrong-role"; body = packageBody; }
    if (name === "stale-revision") { route = "/api/attempt/stale-revision"; body = packageBody; }
    if (name === "reject-offset") {
      route = "/api/decision/reject-offset";
      body = unresolvedCorrectionBody || packageBody;
    }
    if (name === "acknowledge") { route = "/api/action/acknowledge"; body = revBody; }
    if (name === "record-cash") { route = "/api/correction/record-cash"; body = unresolvedCashBody || cashCorrectionBody(); }
    if (name === "record-report") { route = "/api/reporting/record"; body = revBody; }
    if (name === "restore-test") { route = "/api/continuity/restore-test"; body = packageBody; }
    if (!route || !body) return;
    if (name === "reject-offset" && !unresolvedCorrectionBody) unresolvedCorrectionBody = body;
    if (name === "record-cash" && !unresolvedCashBody) unresolvedCashBody = body;
    commandPending = true;
    updateActions();
    let refreshAfter = false;
    try {
      const result = await postJson(route, body);
      if (name === "reject-offset") unresolvedCorrectionBody = null;
      if (name === "record-cash") unresolvedCashBody = null;
      if (name === "wrong-role" || name === "stale-revision") {
        const gate = result.gate;
        commandMessage(gate.name + " rejected by Owner: " + gate.code + ". Owner state unchanged: " + String(gate.state_unchanged) + ".", "error");
        if (result.workspace && !applyCommandSnapshot(result.workspace, startedAt)) refreshAfter = true;
      } else {
        const command = result.command || {};
        let workspaceApplied = false;
        let description = command.status || "Command recorded";
        if (name === "acknowledge") {
          description += ". Cash before: " + asMoney(result.cash_before_cents) + "; after: " + asMoney(result.cash_after_cents) + "; cash effect: " + asMoney(result.cash_effect_cents) + ".";
        }
        if (name === "record-cash") description += ". Synthetic evidence only; money movement: false.";
        if (name === "record-report") description += ". Reporting source: synthetic and unverified.";
        if (name === "restore-test") description = "Continuity TEST restore verified. H decision package equality: " + String(result.continuity.decision_package_equal) + ".";
        commandMessage(description + " Reopen the package to review the new Owner sequence.", "success");
        if (result.workspace) workspaceApplied = applyCommandSnapshot(result.workspace, startedAt);
        else await refreshOverview();
        if (result.workspace && !workspaceApplied) refreshAfter = true;
        if (workspaceApplied) {
          await refreshCorrectionFollowup(workspaceRequestGeneration);
        }
      }
    } catch (error) {
      const uncertain = ["owner_command_unavailable", "Failed to fetch", "NetworkError", "command_unavailable", "command_outcome_uncertain", "command_response_unverified"]
        .includes(error.message);
      if (name === "reject-offset" && !uncertain) {
        unresolvedCorrectionBody = null;
      }
      if (name === "record-cash" && !uncertain) {
        unresolvedCashBody = null;
      }
      if (error.message === "owner_read_unavailable") {
        showOwnerUnavailable();
      } else {
        commandMessage(describeError(error.message), "error");
        if (error.message === "obligation_revision_conflict") {
          packageStale = true;
          const status = byId("package-staleness");
          status.textContent = "STALE REVIEW — Owner rejected the package binding. Reload the overview and reopen H before continuing.";
          status.className = "status-banner stale";
        }
        refreshAfter = true;
      }
    } finally {
      commandPending = false;
      detectPackageStaleness();
      renderDecision();
      updateActions();
      if (refreshAfter) await refreshOverview();
    }
  }

  byId("refresh-button").addEventListener("click", refreshOverview);
  byId("open-package").addEventListener("click", openPackage);
  document.querySelector(".action-grid").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action]");
    if (button && !button.disabled) performAction(button.dataset.action);
  });

  refreshOverview();
  window.setInterval(refreshOverview, 15000);
  window.setInterval(() => {
    if (lastSuccessfulRead && Date.now() - lastSuccessfulRead > 30000 && ownerAvailable) {
      ownerAvailable = false;
      const connection = byId("connection-status");
      connection.textContent = "STALE LOCAL VIEW — no successful Owner read in 30 seconds; source freshness remains UNKNOWN and commands are disabled.";
      connection.className = "status-banner stale";
      packageAvailable = false;
      packageStale = true;
      if (decisionOpen) {
        const status = byId("package-staleness");
        status.textContent = "STALE LOCAL VIEW — the open package is retained but cannot authorize a command.";
        status.className = "status-banner stale";
      }
      updateActions();
    }
  }, 5000);
})();
