"use strict";

// The Owner and the independent verifier check every read server-side before this
// loopback response exists; the browser is the same trust domain, so it echoes the
// read-to-command binding (snapshot, revision, evaluation id, digests) back on a
// command instead of recomputing digests the server already verified.
// All page text is written with textContent; the server's CSP allows only same-origin
// script and style, and nothing here uses innerHTML, eval or inline handlers.
// Every record is built once as data (recordOf) and drawn twice: as the screen and as
// the plain-text view, so the two cannot say different things.
(() => {
  const money = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 2 });
  const byId = (id) => document.getElementById(id);
  const REJECTED = "OFFSET_REJECTED_CORRECTION_AUTHORIZED";
  const MINUS = "−";
  let model = null;
  let role = null;
  let snapshot = null;
  let correctionFollowup = null;
  let unresolvedDecision = null; // {name, body}: a decision whose answer was lost, kept for an exact resend
  let unresolvedCashBody = null;
  let ownerAvailable = false;
  let lastSuccessfulRead = 0;
  let commandPending = false;
  let workspaceRequestGeneration = 0;
  let correctionFollowupRequestGeneration = 0;
  let picked = null; // the chosen decision command, before it is confirmed
  let confirming = null; // "decision" | "record-cash" while its confirm step shows
  let filterText = "";
  let lastId = null;
  let order = [];
  const CASH_CORRECTION_COMMAND = Object.freeze({
    item_id: "item-h",
    pays_action_id: "action:obligation-item-h:correction-v1",
    payment_id: "payment:h:p2",
    common_origin_id: "origin:payment:h:p2",
    amount_cents: 300000,
    evidence_id: "evidence:payment-h:p2",
    event_at_ms: 1775001600000,
    source_id: "fixture-payment-file",
    source_version: "payment-v2",
    local_ref: "ref:payment:h:p2",
  });
  // A command whose response was lost or unverifiable may have committed: keep the exact body for retry.
  const UNCERTAIN_OUTCOMES = [
    "owner_command_unavailable", "Failed to fetch", "NetworkError", "command_unavailable",
    "command_outcome_uncertain", "command_response_unverified", "store_busy", "store_busy_outcome_unknown", "transport_failure",
  ];
  const DECISIONS = { "reject-offset": true, "authorize-offset": true };
  const ROUTES = {
    "reject-offset": "/api/decision/reject-offset",
    "authorize-offset": "/api/decision/authorize-offset",
    acknowledge: "/api/action/acknowledge",
    "record-cash": "/api/correction/record-cash",
    "record-report": "/api/reporting/record",
    "restore-test": "/api/continuity/restore-test",
  };
  const can = (name) => model.controls[name].roles.includes(role);

  function resolveRole() { // from the path, never a query string, so a disallowed control is absent from the DOM
    const match = /^\/role\/([a-z]+)$/.exec(location.pathname);
    return match ? match[1] : null;
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

  function canonicalJson(value) {
    if (value === null) return "null";
    if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
    if (typeof value === "number") {
      assert(Number.isSafeInteger(value), "canonical_json_number");
      return String(value);
    }
    if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
    assert(isRecord(value), "canonical_json_value");
    return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonicalJson(value[key])).join(",") + "}";
  }

  function sameJson(left, right) {
    return canonicalJson(left) === canonicalJson(right);
  }

  function ownerIdentity(envelope) {
    const { schema, schema_version, scope, mode, owner_id, continuity_epoch } = envelope;
    return { schema, schema_version, scope, mode, owner_id, continuity_epoch };
  }

  function snapshotFields(envelope) {
    return { ...ownerIdentity(envelope), sequence: envelope.sequence, history_head: envelope.history_head };
  }

  function sameSnapshot(left, right) {
    return sameJson(ownerIdentity(left), ownerIdentity(right))
      && ["sequence", "history_head", "snapshot_id"].every((key) => left[key] === right[key]);
  }

  // ---- Words and numbers ----

  const asMoney = (cents) => (Number.isSafeInteger(cents) ? money.format(cents / 100) : "Unknown");
  const amt = (cents) => money.format(cents / 100).slice(1);
  const utc = (ms) => (Number.isSafeInteger(ms) ? new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC") : "Unknown");
  // One time convention: the screen shows an instant in the program's zone with its label; the record keeps UTC.
  // A record holds instants as at(ms) and each drawing writes them in its own convention; dates stay calendar dates.
  let zoned = null;
  const at = (ms) => ({ at: ms });
  const fill = (parts, onScreen) => [].concat(parts).map((part) => {
    if (part === null || typeof part !== "object") return part;
    if (!Number.isSafeInteger(part.at)) return "Unknown";
    if (!onScreen) return utc(part.at);
    zoned = zoned || new Intl.DateTimeFormat("en-US", { timeZone: model.time.zone, year: "numeric", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
    const when = (ms) => Object.fromEntries(zoned.formatToParts(ms).map(({ type, value }) => [type, value]));
    const p = when(part.at); // the year shows only when the instant is from another year than the snapshot's own as-of time
    return p.day + " " + p.month + (p.year === when(Date.parse(snapshot.read_at)).year ? "" : " " + p.year) + " " + p.hour + ":" + p.minute + " " + model.time.label;
  }).join("");
  // Owner codes in plain words (CASE_OWNER -> case owner).
  const words = (code) => (code === null || code === undefined ? "unknown" : String(code).toLowerCase().replaceAll("_", " "));
  const sentence = (text) => text.charAt(0).toUpperCase() + text.slice(1);
  const hId = () => snapshot.h.obligation.item_id; // the one obligation that carries a decision package
  const usd = (cents) => asMoney(cents);

  function el(tag, attrs, ...kids) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === false || value === null || value === undefined) continue;
      if (key === "text") node.textContent = value;
      else node.setAttribute(key, value === true ? "" : value);
    }
    node.append(...kids.flat(Infinity).filter((kid) => kid !== null && kid !== undefined && kid !== false));
    return node;
  }

  const dot = (kind) => el("span", { class: "dot " + kind });
  const section = (label, ...kids) => el("section", { "aria-label": label }, el("h2", { text: label }), ...kids);
  const table = (cls, rows) => el("table", { class: cls }, el("tbody", {}, rows.map(([cells, rowClass]) => el("tr", { class: rowClass },
    cells.map(([text, cellClass]) => el("td", { class: cellClass, text }))))));

  // ---- What the Owner says about each obligation ----

  function hView() {
    const pkg = snapshot.h.decision_package;
    const claims = ((pkg.references || {}).claims || {}).items || [];
    const resolution = (pkg.conclusions || {}).case_resolution || {};
    return {
      pkg,
      ob: pkg.obligation,
      kase: pkg.case,
      det: pkg.current_determination,
      act: pkg.current_action,
      claim: claims.find((row) => row.status === "CLAIMED") || claims[0] || null,
      missing: Array.isArray(resolution.missing_requirements) ? resolution.missing_requirements : [],
      assessment: resolution.assessment,
      support: snapshot.source_assessment.h_support_status === "MISSING" ? "no supporting evidence" : "support recorded, unverified",
    };
  }

  // kind: need (a person must decide), wait (money or follow-through is outstanding), ok (settled).
  function statusOf(item) {
    if (item.item_id !== hId()) {
      const state = item.shortfall_cents > 0 ? "Short " + usd(item.shortfall_cents) : "Paid in full";
      return { kind: item.shortfall_cents > 0 ? "wait" : "ok", state, sub: state };
    }
    const view = hView();
    if (view.kase && view.kase.status === "RESOLVED") {
      const state = view.ob.lawful_adjustment_cents > 0 ? "Settled with the offset" : "Settled in full";
      return { kind: "ok", state, sub: state };
    }
    if (!view.det && view.claim && view.claim.status === "CLAIMED") {
      return {
        kind: "need",
        state: role === "approver" ? "Needs your decision" : "Waiting for the finance approver's decision", plain: "Waiting for the finance approver's decision",
        sub: "Offset claim " + usd(view.claim.amount_cents) + " · " + view.support,
      };
    }
    const state = view.ob.shortfall_cents > 0 ? "Waiting on the payer for " + usd(view.ob.shortfall_cents) : "Paid. Follow-through is still open";
    return { kind: "wait", state, sub: state };
  }

  const STEPS = {
    acknowledge: { label: "Record action delivery ACK", note: "Delivery only. Cash effect: $0.00.", off: "Waits for a ready action that still asks for money." },
    "record-cash": { label: "Record synthetic " + money.format(CASH_CORRECTION_COMMAND.amount_cents / 100) + " cash evidence", note: "Records evidence only. No money moves.", off: "Waits for an acknowledged action whose open amount covers this payment." },
    "record-report": { label: "Record separate synthetic reporting evidence", note: "Reporting is separate from delivery and cash. The source is synthetic and unverified.", off: "Waits for nothing to be short and reporting to be pending." },
    "restore-test": { label: "Restore current case into Continuity TEST", note: "Copies the case into a separate test database.", off: "Already restored into Continuity TEST." },
  };

  function stepEnabled(name, view) {
    const reviewed = ownerAvailable && !commandPending && !unresolvedCashBody && !unresolvedDecision;
    const status = view.act ? view.act.status : null;
    if (name === "acknowledge") return reviewed && status === "READY" && view.act.open_cents !== 0;
    if (name === "record-cash") return unresolvedCashBody ? ownerAvailable && !commandPending : reviewed && status === "ACKNOWLEDGED" && view.act.open_cents >= CASH_CORRECTION_COMMAND.amount_cents;
    if (name === "record-report") return reviewed && !view.ob.reporting_complete && view.ob.shortfall_cents <= 0;
    return reviewed && !(snapshot.continuity && snapshot.continuity.mode === "TEST");
  }

  function followupRows() {
    const durable = correctionFollowup && correctionFollowup.followup;
    if (durable) {
      const support = durable.corporate_support;
      const artifact = support.artifact;
      return [
        ["Report to the State", durable.followup_status + " · event " + durable.source_event_sequence],
        ["Changed dependencies", durable.state_report.changed_dependencies.join(", ") || "None"],
        ["Allowlisted support", support.status + " · " + support.failure_stage + " / " + support.error_class + (artifact ? " · artifact v" + artifact.version + " " + artifact.sha256.slice(0, 16) + "…" : "")],
      ];
    }
    return correctionFollowup && correctionFollowup.status === "UNAVAILABLE" ? [["Report to the State", "Follow-up read unavailable: " + correctionFollowup.reason]] : [];
  }

  // The whole record as data: the screen and the plain-text view are both drawn from this.
  function recordOf(item) {
    const st = statusOf(item);
    const isH = item.item_id === hId();
    const name = item.label;
    const short = item.shortfall_cents;
    const env = snapshot.read_envelope;
    const R = {
      id: item.item_id, name, kind: st.kind, state: st.state, plain: st.plain || st.state, obligation: item.obligation_id,
      ledger: [], checks: [], decision: null, steps: [], sources: [], activity: [], followup: [], facts: [],
    };
    const rule = isH ? hView().pkg.control_pack : null;
    R.facts.push(["Payee", name]);
    R.facts.push(["Period", item.period_id], ["Due", at(item.due_at_ms)]);
    const source = snapshot.source_assessment;
    const sourceCheck = [false, "Source authenticity", "Not verified. " + sentence(words(source.status)) + ": " + source.reason];
    if (!isH) {
      R.claim = short > 0 ? name + " is short " + usd(short) + " for the period." : name + " was paid " + usd(item.received_cash_cents) + " in full.";
      R.more = short > 0 ? "" : "That matches the amount owed, so nothing is waiting on anyone.";
      R.ledger.push(["Owed to " + name, "", amt(item.owed_cents)], ["Cash recorded", "", MINUS + amt(item.received_cash_cents)], ["Shortfall", short > 0 ? "Still owed" : "Paid in full", amt(short), "total"]);
      R.checks.push([true, "Amount owed", usd(item.owed_cents)], [short === 0, "Cash received", usd(item.received_cash_cents) + " recorded of " + usd(item.owed_cents) + " owed; shortfall " + usd(short)], sourceCheck);
    } else {
      const v = hView();
      const claim = v.claim;
      const amount = claim ? usd(claim.amount_cents) : "Unknown";
      const payments = v.pkg.cash ? v.pkg.cash.active_payment_count : 0;
      R.claim = short > 0 && claim && claim.status === "CLAIMED"
        ? "The payer paid " + name + " " + usd(short) + " less than it owes and claims an offset of " + amount + " with " + v.support + "."
        : v.kase && v.kase.status === "RESOLVED" ? name + " is paid " + usd(item.received_cash_cents) + " of " + usd(item.owed_cents) + " owed."
          : short > 0 ? "The payer owes " + name + " " + usd(short) + " after the offset was " + (v.det && v.det.decision === REJECTED ? "rejected." : "decided.")
            : name + " is paid " + usd(item.received_cash_cents) + " of " + usd(item.owed_cents) + " owed. The case is not closed yet.";
      R.more = v.missing.length ? "Still needed: " + v.missing.map(words).join(", ") + "." : "Owner assessment: " + words(v.assessment) + ", nothing outstanding.";
      if (v.act && v.act.open_cents !== null && v.act.open_cents !== v.act.payload_fields.amount_cents) R.more += " Requested " + usd(v.act.payload_fields.amount_cents) + ", open " + usd(v.act.open_cents) + ".";
      R.ledger.push(["Owed to " + name, rule.source_refs[0], amt(item.owed_cents)],
        ["Cash recorded", payments + (payments === 1 ? " payment" : " payments") + " recorded", MINUS + amt(item.received_cash_cents)]);
      if (claim) R.ledger.push(["Offset claimed by the payer", "claim " + words(claim.status) + " · " + v.support, amt(claim.amount_cents)]);
      if (item.lawful_adjustment_cents > 0) R.ledger.push(["Offset accepted, counted as paid", "", MINUS + amt(item.lawful_adjustment_cents)]);
      R.ledger.push(["Shortfall", !v.det && short > 0 ? "Depends on the decision" : short > 0 ? "The payer must pay it" : "Nothing left to pay", amt(short), "total"]);
      R.checks.push([true, "Amount owed", usd(item.owed_cents) + " from " + rule.source_refs[0]],
        [short === 0, "Cash received", usd(item.received_cash_cents) + " recorded of " + usd(item.owed_cents) + " owed; shortfall " + usd(short)]);
      if (claim) R.checks.push([false, "Offset approval", "Rule " + rule.adjustment_rule_id + ": " + v.support]);
      R.checks.push(sourceCheck, [false, "Source freshness", sentence(words(snapshot.freshness.status)) + ": " + snapshot.freshness.reason]);
      R.caseLine = v.kase ? words(v.kase.status) + " · " + words(v.kase.reason) + " · owner: " + words(v.kase.next_action_owner) : "No case opened";
      R.facts.push(["Case", R.caseLine], ["Rule", rule.adjustment_rule_id]);
      if (claim && can("reject-offset") && (unresolvedDecision || (!v.det && st.kind === "need"))) {
        const left = short - claim.amount_cents; // what stays unpaid once the offset counts as paid
        R.decide = {
          options: [["authorize-offset", "1", "Accept the offset", "The " + usd(claim.amount_cents) + " offset counts toward " + name + "'s payment. "
            + (left > 0 ? name + " is still owed " + usd(left) + "." : name + " is owed nothing more.")],
          ["reject-offset", "2", "Reject the offset", "The payer must pay " + name + " " + usd(short) + ". A correction request is recorded."]],
          note: "This demo does not store decision reasons yet.",
        };
      }
      if (v.det) {
        const evidence = (v.det.supporting_evidence || []).map((row) => (isRecord(row) ? row.evidence_id : row));
        R.decision = {
          line: ["Decided: offset " + (v.det.decision === REJECTED ? "rejected" : "accepted") + " by " + words(v.det.actor_role) + " · ", at(v.det.decided_at_ms)],
          seal: "Determination " + v.det.decision + " · digest " + v.det.determination_digest.slice(0, 16) + "…",
          note: "Supporting evidence: " + (evidence.join(", ") || "none") + ". This demo does not store a reason.",
        };
      }
      for (const name of ["acknowledge", "record-cash", "record-report", "restore-test"]) {
        if (can(name)) R.steps.push({ name, ...STEPS[name], enabled: stepEnabled(name, v) });
      }
      for (const row of (v.pkg.references.evidence || {}).items || []) {
        R.sources.push([row.evidence_id, words(row.kind) + " · " + row.source_id, "digest " + row.record_digest.slice(0, 16) + "…"]);
      }
      const events = snapshot.h.timeline;
      for (const event of events.slice().reverse()) {
        R.activity.push([at(event.committed_at_ms), sentence(words(event.kind)), " · Owner event " + event.event_sequence
          + (event.after_revision === null || event.after_revision === undefined ? "" : ", revision " + event.before_revision + " → " + event.after_revision)]);
      }
      if (snapshot.h.timeline_truncated) R.activity.push(["", "Showing " + events.length + " recent events of " + snapshot.h.timeline_total_count + "; older history is omitted.", ""]);
      R.followup = followupRows();
    }
    R.facts.push(["Obligation", item.obligation_id], ["Read", "sequence " + env.sequence + " · snapshot " + env.snapshot_id.slice(0, 16)]);
    if (isH) R.facts.push(["Continuity", snapshot.continuity ? snapshot.continuity.mode : "Unknown"]);
    R.meta = [item.obligation_id, ["Due ", at(item.due_at_ms)], R.caseLine && "Case: " + R.caseLine];
    return R;
  }

  function textOf(R, forThisRole) { // the downloaded record is the same bytes for every role; only the on-page plain-text view adds this role's own status wording and sections
    const row = (label, ...cells) => label.padEnd(12) + cells.filter(Boolean).join("  ");
    const lines = [row("OBLIGATION", R.obligation), row("STATUS", forThisRole ? R.state : R.plain), row("SUMMARY", R.claim), row("", R.more), "", "AMOUNTS IN USD",
      ...R.ledger.map((entry) => row(entry[0], entry[1], entry[2]))];
    lines.push("", "WHAT WAS CHECKED", ...R.checks.map((entry) => row((entry[0] ? "ok" : "NOT OK") + " " + entry[1], entry[2])));
    if (R.decision) lines.push("", "DECISION", row("", fill(R.decision.line, false), R.decision.seal, R.decision.note));
    if (forThisRole && R.decide) lines.push("", "YOUR DECISION", ...R.decide.options.map(([, key, title, detail]) => row(key, title, detail)), row("", R.decide.note));
    if (forThisRole && R.steps.length) lines.push("", "NEXT STEPS", ...R.steps.map((step) => row(step.label, step.enabled ? step.note : step.off)));
    if (R.sources.length) lines.push("", "SOURCE RECORDS", ...R.sources.map((entry) => row(entry[0], entry[1], entry[2])));
    if (R.activity.length) lines.push("", "ACTIVITY", ...R.activity.map(([when, what, detail]) => row(fill(when, false), what + detail)));
    if (R.followup.length) lines.push("", "STATE REPORT", ...R.followup.map((entry) => row(entry[0], entry[1])));
    return [...lines, "", "FACTS", ...R.facts.map((entry) => row(entry[0], fill(entry[1], false)))].join("\n");
  }

  // ---- Screens ----

  function queueGroups() {
    const q = filterText.trim().toLowerCase();
    const rows = snapshot.items.map((item, index) => ({ item, index, st: statusOf(item) }))
      .filter(({ item, st }) => !q || [item.label, item.item_id, st.state].join(" ").toLowerCase().includes(q));
    rows.sort((a, b) => ["need", "wait", "ok"].indexOf(a.st.kind) - ["need", "wait", "ok"].indexOf(b.st.kind)
      || (b.item.item_id === hId()) - (a.item.item_id === hId()) || a.index - b.index);
    return rows;
  }

  function renderQueue() {
    const rows = queueGroups();
    order = rows.map(({ item }) => item.item_id);
    const open = rows.filter(({ st }) => st.kind !== "ok").length;
    const count = rows.filter(({ st }) => st.kind === "need").length;
    byId("qcount").textContent = role === "approver" ? (count ? count + " for you" : "Nothing for you") : (open ? open + " open" : "None open");
    byId("summary-link").setAttribute("aria-current", String(lastId === "summary"));
    const groups = [["need", "Needs a decision"], ["wait", "Waiting"], ["ok", "Settled"]].map(([kind, label]) => {
      const list = rows.filter(({ st }) => st.kind === kind);
      if (!list.length) return null;
      const sum = kind === "ok" ? 0 : list.reduce((total, { item }) => total + item.shortfall_cents, 0);
      return [el("div", { class: "group" }, el("span", { text: label }), el("span", { class: "num", text: String(list.length) }),
        sum ? el("span", { class: "sum num", text: amt(sum) }) : null),
      el("ul", { class: "rows" }, list.map(({ item, st }) => el("li", {}, el("a", {
        class: "row", id: "row-" + item.item_id, "data-id": item.item_id, href: "#" + item.item_id, "aria-current": String(item.item_id === lastId),
      }, dot(st.kind), el("span", { class: "name", text: item.label }), el("span", { class: "amt num", text: amt(item.owed_cents) }),
      el("span", { class: "sub", text: st.sub })))))];
    });
    byId("qlist").replaceChildren(...groups.flat().filter(Boolean),
      ...(rows.length ? [] : [el("p", { class: "empty", text: "No obligation matches “" + filterText.trim() + "”." })]));
  }

  const backLink = () => el("a", { class: "back", href: "#queue", text: "← Obligations" });
  const stateLine = (kind, text) => el("div", { class: "state " + kind }, dot(kind), text);

  function decisionForm(R, v) {
    const noChoice = commandPending || Boolean(unresolvedDecision) || !ownerAvailable;
    const amount = usd(v.claim.amount_cents);
    const { names, hints } = model.local_controls["record-decision"];
    const option = ([name, key, title, detail]) => el("label", { class: "opt" },
      el("input", { type: "radio", name: "kind", id: "kind-" + name, value: name, "aria-label": title, "aria-describedby": "detail-" + name,
        checked: picked === name, disabled: noChoice }),
      el("span", { class: "key", text: key }), el("span", {}, el("b", { text: title }), el("p", { id: "detail-" + name, text: detail })));
    const verb = picked === "reject-offset" ? "rejection" : "acceptance";
    const retry = Boolean(unresolvedDecision);
    const primary = (retry ? names.retry : names.confirm).replace("{verb}", verb).replace("{amount}", amount);
    return el("section", { class: "decide", "aria-label": "Your decision" }, el("h2", { text: "Your decision" }),
      el("div", { class: "opts", role: "radiogroup", "aria-label": "Should the offset stand?" },
        R.decide.options.map(option)),
      el("p", { class: "hint", text: R.decide.note }),
      confirming === "decision"
        ? confirmPanel("Confirm decision", "Record the " + verb + " of the payer's " + amount + " offset? It is recorded once written, and a later change needs a new decision.", primary, retry)
        : el("div", { class: "acts" }, el("button", { class: "btn primary", id: "record-btn", disabled: !picked || noChoice, text: names.idle }),
          el("span", { class: "hint", id: "why-off", text: picked ? "" : hints.no_choice })));
  }

  function confirmPanel(label, text, primary, retrying) {
    return el("div", { class: "confirm", role: "group", "aria-label": label }, el("p", { text }),
      el("div", { class: "acts" }, el("button", { class: "btn primary", id: "confirm", disabled: commandPending || !ownerAvailable, text: commandPending ? model.local_controls["record-decision"].names.pending : primary }),
        el("button", { class: "btn", id: "cancel", disabled: commandPending || retrying, text: "Back" })));
  }

  function stepList(R) {
    const cashAmount = money.format(CASH_CORRECTION_COMMAND.amount_cents / 100);
    return section("Next steps", el("ul", { class: "steps" }, R.steps.map((step) => el("li", {},
      el("button", { class: "btn small", type: "button", "data-action": step.name, disabled: !step.enabled, text: step.label }),
      el("span", { class: "hint", text: step.enabled ? step.note : step.off }),
      step.name === "record-cash" && confirming === "record-cash"
        ? confirmPanel("Confirm cash evidence", "Record synthetic payment evidence of " + cashAmount + " for " + R.name + "? This records evidence only. No money moves.",
          unresolvedCashBody ? model.local_controls["record-decision"].names.cash_retry : "Record " + cashAmount + " of cash evidence", Boolean(unresolvedCashBody))
        : null))));
  }

  function renderRecord(R, textMode) {
    const v = R.id === hId() ? hView() : null;
    const cash = R.steps.find((step) => step.name === "record-cash");
    // A read can remove the form or step a confirm belonged to (another actor decided, cash arrived); a command in flight settles it itself.
    if (!commandPending && ((confirming === "decision" && !R.decide) || (confirming === "record-cash" && !(cash && cash.enabled)))) confirming = null;
    const foot = el("div", { class: "foot" }, el("a", { id: "plain-text", href: "#" + R.id + (textMode ? "" : ".txt"), text: textMode ? "Back to the full view" : "View as plain text" }),
      el("a", { id: "download-record", href: "data:text/plain;charset=utf-8," + encodeURIComponent(textOf(R)), download: "record-" + R.id + ".txt", text: "Download record" }),
      el("span", { text: "The same record an auditor or an agent reads." }));
    const facts = el("dl", { class: "facts", "aria-label": "Facts" }, R.facts.map(([term, value]) => [el("dt", { text: term }), el("dd", { class: term === "Obligation" || term === "Read" ? "mono" : false, text: fill(value, true) })]));
    let main;
    if (textMode) {
      main = [el("header", {}, backLink()), el("pre", { class: "textview", id: "text-view", text: textOf(R, true) })];
    } else {
      main = [
        el("header", {}, backLink(), el("div", { class: "meta mono" }, R.meta.filter(Boolean).map((part) => el("span", { text: fill(part, true) }))), stateLine(R.kind, R.state),
          el("p", { class: "claim", text: R.claim }), R.more ? el("p", { class: "claim-more", text: R.more }) : null),
        section("Amounts in USD", table("ledger", R.ledger.map(([label, note, value, cls]) => [[[label], [note, "note"], [value, "num"]], cls]))),
        section("What was checked", table("checks", R.checks.map(([ok, what, result]) => [[[null, "mk"], [what, "what"], [result, "res2"]], ok ? "" : "bad"]))),
        R.decision && R.decision.line ? el("section", { class: "signed", "aria-label": "Decision" }, el("h2", { text: "Decision" }), el("div", { class: "line", text: fill(R.decision.line, true) }),
          el("div", { class: "seal mono", text: R.decision.seal }), el("p", { class: "hint", text: R.decision.note })) : null,
        R.decide ? decisionForm(R, v) : null,
        R.steps.length ? stepList(R) : null,
        R.sources.length ? section("Source records", table("src", R.sources.map((entry) => [[[entry[0]], [entry[1], "fp"], [entry[2], "fp mono"]]]))) : null,
        R.activity.length ? section("Activity", el("ol", { class: "log" }, R.activity.map(([when, text]) => el("li", {}, el("time", { class: "mono", text: fill(when, true) }), el("div", { text }))))) : null,
        R.followup.length ? section("State report", table("src", R.followup.map(([label, value]) => [[[label], [value]]]))) : null,
        foot,
      ];
    }
    const page = el("div", { class: "page", "data-record": R.id }, el("div", { class: "main" }, el("h1", { class: "sr", text: R.name }), main, textMode ? foot : null), facts);
    // A dot in the checks table marks each row; drawn here so the table helper stays plain.
    for (const [index, mark] of page.querySelectorAll(".checks td.mk").entries()) mark.append(dot(R.checks[index][0] ? "ok" : "need"));
    byId("page").replaceChildren(page);
  }

  function renderSummary() {
    const { summary, population, items } = snapshot;
    const open = items.filter((item) => statusOf(item).kind !== "ok");
    const totals = [["Population", summary.obligation_count + " / " + population.expected_count + " obligations · roster " + words(population.completeness)],
      ["Total owed", usd(summary.owed_cents)], ["Cash recorded", usd(summary.received_cash_cents)], ["Program shortfall", usd(summary.shortfall_cents)],
      ["Open items", open.length + (open.length === 1 ? " obligation" : " obligations") + " not paid in full"]];
    const claim = summary.shortfall_cents > 0 ? usd(summary.shortfall_cents) + " of " + usd(summary.owed_cents) + " is still short." : "Every obligation is paid in full.";
    byId("page").replaceChildren(el("div", { class: "page", "data-record": "summary" }, el("div", { class: "main" },
      el("h1", { class: "sr", text: "Program summary" }),
      el("header", {}, backLink(), stateLine(open.length ? "wait" : "ok", open.length ? "Program summary: " + open.length + " open" : "Program summary: nothing open"),
        el("p", { class: "claim", text: claim }),
        el("p", { class: "claim-more", text: "Source records: " + words(snapshot.source_assessment.status) + ". " + snapshot.source_assessment.reason })),
      section("Program totals", el("dl", { class: "totals" }, totals.map(([term, value]) => [el("dt", { text: term }), el("dd", { class: "num", text: value })]))),
      open.length ? section("Open obligations", table("sumtab", open.map((item) => [[
        [null, "d"], [statusOf(item).state, "next"], [amt(item.shortfall_cents), "num"]]]))) : null)));
    for (const [index, cell] of byId("page").querySelectorAll(".sumtab td.d").entries()) {
      const label = open[index].label;
      cell.append(el("a", { href: "#" + open[index].item_id, text: label }));
    }
  }

  function renderPage() {
    const page = byId("page");
    if (!snapshot) return page.replaceChildren(el("p", { class: "empty", text: "No verified read yet." }));
    const hash = decodeURIComponent(location.hash.slice(1));
    const item = snapshot.items.find((row) => row.item_id === hash.replace(/\.txt$/, ""));
    if (lastId === "summary" && !item) return renderSummary();
    return renderRecord(recordOf(snapshot.items.find((row) => row.item_id === lastId)), hash.endsWith(".txt") && Boolean(item));
  }

  function render() {
    if (!snapshot) return renderPage();
    const active = document.activeElement;
    const id = active && active.id;
    const range = active && typeof active.selectionStart === "number" ? [active.selectionStart, active.selectionEnd] : null;
    renderQueue();
    renderPage();
    const next = id && byId(id);
    if (next && next !== active) {
      next.focus({ preventScroll: true });
      if (range && next.setSelectionRange) next.setSelectionRange(...range);
    }
  }

  function defaultId() {
    if (role === "director") return "summary"; // the director's answer is the program's totals
    const all = queueGroups();
    return all.length ? all[0].item.item_id : "summary";
  }

  function route() {
    if (!model || !role) return;
    const hash = decodeURIComponent(location.hash.slice(1));
    const onList = hash === "queue";
    const wanted = hash.replace(/\.txt$/, "");
    const known = wanted === "summary" || Boolean(snapshot && snapshot.items.some((row) => row.item_id === wanted));
    let id = wanted;
    if (onList) id = lastId || defaultId();
    else if (!known) {
      id = defaultId();
      if (hash) history.replaceState(null, "", "#" + id);
    }
    const active = document.activeElement;
    const fromRow = Boolean(active && active.closest && active.closest("#qlist .row"));
    if (id !== lastId) {
      byId("record").scrollTop = 0;
      picked = unresolvedDecision ? unresolvedDecision.name : null; // a lost answer stays retryable wherever the person went
      confirming = unresolvedDecision ? "decision" : null;
      commandMessage("", "");
    }
    lastId = id;
    byId("work").classList.toggle("open", !onList && (Boolean(hash) || role === "director"));
    render();
    const current = byId("row-" + id);
    if (current && current.offsetParent) { // scrollIntoView would move the Tab starting point past the skip link
      const row = current.getBoundingClientRect(), list = byId("qlist"), box = list.getBoundingClientRect();
      list.scrollTop += row.top < box.top ? row.top - box.top : Math.max(0, row.bottom - box.bottom);
    }
    if (fromRow) (current && current.offsetParent ? current : byId("record")).focus({ preventScroll: true });
  }

  // ---- Reads ----

  function banner(kind, text) {
    const node = byId("connection-status");
    node.textContent = text;
    node.className = "conn " + kind;
  }

  function markViewUnusable(kind, text) {
    ownerAvailable = false;
    banner(kind, text);
    render();
  }

  function showOwnerUnavailable(message = "The Owner read failed. Reload this page to check again.") {
    markViewUnusable("unavailable", message);
  }

  function applyWorkspaceSnapshot(value, requestGeneration) {
    if (requestGeneration !== null && requestGeneration !== workspaceRequestGeneration) return false;
    const incoming = value.read_envelope;
    let changed = true;
    if (snapshot) {
      const previous = snapshot.read_envelope;
      const identityChanged = !sameJson(ownerIdentity(previous), ownerIdentity(incoming));
      if (!identityChanged && incoming.sequence < previous.sequence) return false;
      if (!identityChanged && incoming.sequence === previous.sequence && !sameSnapshot(previous, incoming)) {
        // Same sequence, different history: the Owner forked. Stop trusting every read.
        workspaceRequestGeneration += 1;
        correctionFollowupRequestGeneration += 1;
        correctionFollowup = null;
        showOwnerUnavailable(model.controls.read.responses.fork_detected.message);
        return false;
      }
      changed = !sameSnapshot(previous, incoming);
      if (changed) {
        correctionFollowupRequestGeneration += 1;
        correctionFollowup = null;
      }
      if (identityChanged) {
        unresolvedDecision = null;
        unresolvedCashBody = null;
      }
    }
    snapshot = value;
    ownerAvailable = true;
    lastSuccessfulRead = Date.now();
    byId("standing").textContent = "synthetic · not for payment · no PHI · " + (value.summary.production_usable ? "production" : "not production");
    banner("ok", model.controls.read.responses.success.message + " Sequence " + value.summary.sequence + " · synthetic local · dispatch and egress disabled.");
    if (changed || !byId("page").firstChild) route();
    return true;
  }

  async function fetchJson(url) {
    let response;
    try {
      response = await fetch(url, { cache: "no-store", credentials: "omit" });
    } catch (_error) {
      throw new Error("transport_failure");
    }
    const body = await response.json();
    if (!response.ok) throw new Error(body.error && body.error.code ? body.error.code : "read_unavailable");
    return body;
  }

  function readErrorMessage(error) {
    return model.controls.read.responses[error.message === "transport_failure" ? "transport_failure" : "owner_read_unavailable"].message;
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
      const message = readErrorMessage(error);
      correctionFollowup = { status: "UNAVAILABLE", reason: message };
      showOwnerUnavailable(message);
    }
    render();
  }

  async function refreshOverview() {
    if (commandPending) return;
    const requestGeneration = ++workspaceRequestGeneration;
    try {
      const value = await fetchJson("/api/workspace");
      if (!applyWorkspaceSnapshot(value, requestGeneration)) return;
      await refreshCorrectionFollowup(requestGeneration);
    } catch (error) {
      if (requestGeneration === workspaceRequestGeneration) showOwnerUnavailable(readErrorMessage(error));
    }
  }

  // ---- Commands ----

  function staffCommandBinding(envelope, pkg) {
    const itemBinding = envelope.item_bindings.find((binding) => binding.item_id === hId());
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

  function commandBody(name) {
    if (unresolvedDecision && unresolvedDecision.name === name) return unresolvedDecision.body;
    if (name === "record-cash" && unresolvedCashBody) return unresolvedCashBody;
    const pkg = snapshot && snapshot.h.decision_package;
    if (!pkg || !pkg.obligation) return null;
    const revision = { revision: pkg.obligation.revision };
    if (["acknowledge", "record-report"].includes(name)) return revision;
    if (name === "record-cash") return { ...revision, cash_command: { ...CASH_CORRECTION_COMMAND } };
    if (!pkg.evaluation_receipt) return null;
    return {
      ...revision,
      evaluation_id: pkg.evaluation_receipt.evaluation_id,
      evaluation_result_digest: pkg.evaluation_receipt.result_digest,
      read_binding: staffCommandBinding(snapshot.read_envelope, pkg),
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

  function commandMessage(text, kind) {
    const node = byId("command-status");
    node.textContent = text;
    node.className = "flash " + kind;
  }

  function describeError(code, name) {
    if (["Failed to fetch", "NetworkError", "command_outcome_uncertain"].includes(code)) code = "transport_failure";
    if (code === "command_unavailable") code = "owner_command_unavailable";
    const declared = name && model.controls[name] && model.controls[name].responses[code];
    if (declared && declared.message) return declared.message;
    return {
      authority_actor_not_authorized: "Owner denied the command because the fixed synthetic reporter role cannot make a financial decision.",
      obligation_revision_conflict: "This record changed while you were working. Review the new facts, then try again.",
      evaluation_revision_conflict: "This record changed while you were working. Review the new facts, then try again.",
      loopback_origin_required: "The service accepts this action only from its exact loopback browser origin.",
    }[code] || "Command result is unresolved. Reload this page and check the record before any retry.";
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
      const code = isRecord(value) && isRecord(value.error) && typeof value.error.code === "string" ? value.error.code : "command_unavailable";
      // Only a busy answer that says nothing changed is safe to retry blind; any other busy answer may have committed.
      throw new Error(code === "store_busy" && value.changed !== false ? "store_busy_outcome_unknown" : code);
    }
    try {
      assert(isRecord(value) && isRecord(value.workspace), "command_workspace_missing");
    } catch (_error) {
      throw new Error("command_response_unverified");
    }
    return value;
  }

  async function performAction(name) {
    if (commandPending || !ROUTES[name]) return;
    const envelope = snapshot && snapshot.read_envelope;
    const startedAt = envelope ? { ...snapshotFields(envelope), snapshot_id: envelope.snapshot_id } : null;
    const body = commandBody(name);
    if (!body) return commandMessage("Reload this page, then try again.", "error");
    const isDecision = name in DECISIONS;
    const amount = isDecision ? usd(hView().claim.amount_cents) : "";
    // Hold the exact body until the Owner answers: a lost response is retried byte for byte.
    if (isDecision) unresolvedDecision = { name, body };
    if (name === "record-cash") unresolvedCashBody = body;
    commandPending = true;
    render();
    let refreshAfter = false;
    let responseReceived = false;
    try {
      const result = await postJson(ROUTES[name], body);
      responseReceived = true;
      let description = model.controls[name].responses.success.message.replace("{amount}", amount);
      if (name === "acknowledge") {
        description += " Cash before: " + asMoney(result.cash_before_cents) + "; after: " + asMoney(result.cash_after_cents) + "; cash effect: " + asMoney(result.cash_effect_cents) + ".";
      }
      if (name === "record-cash") description += " Synthetic evidence only; money movement: false.";
      if (name === "record-report") description += " Reporting source: synthetic and unverified.";
      if (name === "restore-test") description += " H decision package equality: " + String(result.continuity.decision_package_equal) + ".";
      const applied = applyCommandSnapshot(result.workspace, startedAt);
      unresolvedDecision = null;
      if (name === "record-cash") unresolvedCashBody = null;
      picked = null;
      confirming = null;
      commandMessage(description + (applied ? "" : " Reload this page to review the new Owner sequence."), "success");
      if (applied) await refreshCorrectionFollowup(workspaceRequestGeneration);
      else refreshAfter = true;
    } catch (error) {
      const code = responseReceived ? "command_response_unverified" : error.message;
      if (!UNCERTAIN_OUTCOMES.includes(code)) {
        if (isDecision) unresolvedDecision = null;
        if (name === "record-cash") unresolvedCashBody = null;
        confirming = null; // nothing was recorded: back to the choice
      }
      const message = describeError(code, name);
      const response = model.controls[name].responses[code === "command_unavailable" ? "owner_command_unavailable" : code];
      commandMessage(message, "error");
      if (response && response.screen === "unavailable") showOwnerUnavailable(message);
      else refreshAfter = true;
    } finally {
      commandPending = false;
      render();
      (byId("confirm") || byId("command-status")).focus({ preventScroll: true });
      if (refreshAfter) await refreshOverview();
    }
  }

  // ---- Wiring ----

  function pick(name) {
    picked = name;
    confirming = null;
    render();
    byId("kind-" + name).focus({ preventScroll: true });
  }

  function onRecordClick(event) {
    const target = event.target.closest("button");
    if (!target || target.disabled) return;
    if (target.dataset.action) {
      if (target.dataset.action === "record-cash") {
        confirming = "record-cash";
        render();
        byId("confirm").focus({ preventScroll: true });
      } else performAction(target.dataset.action);
    } else if (target.id === "record-btn") {
      confirming = "decision";
      render();
      byId("confirm").focus({ preventScroll: true });
    } else if (target.id === "cancel") {
      const wasCash = confirming === "record-cash";
      confirming = null;
      render();
      (wasCash ? document.querySelector('[data-action="record-cash"]') : byId("record-btn")).focus({ preventScroll: true });
    } else if (target.id === "confirm") {
      performAction(confirming === "record-cash" ? "record-cash" : unresolvedDecision ? unresolvedDecision.name : picked);
    }
  }

  function onKey(event) {
    const record = document.querySelector("#page [data-record]");
    const button = byId("record-btn");
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      if (record && button && !button.disabled) {
        event.preventDefault();
        button.click();
      }
      return;
    }
    if (event.target.closest("input[type=search]") || event.metaKey || event.ctrlKey || event.altKey || !snapshot) return;
    if (event.key === "/") {
      event.preventDefault();
      byId("filter").focus();
    } else if ((event.key === "1" || event.key === "2") && !confirming && byId("kind-reject-offset") && !byId("kind-reject-offset").disabled) {
      event.preventDefault();
      pick(event.key === "1" ? "authorize-offset" : "reject-offset");
    } else if (event.key === "j" || event.key === "k") {
      const next = order[Math.max(0, Math.min(order.length - 1, order.indexOf(lastId) + (event.key === "j" ? 1 : -1)))];
      if (next) location.hash = next;
    } else if (event.key === "Escape" && byId("cancel") && !byId("cancel").disabled) byId("cancel").click();
  }

  async function boot() {
    document.querySelector(".sr-focus").addEventListener("click", (event) => { // keep the address: the hash names the record
      event.preventDefault();
      byId("record").focus();
    });
    try {
      model = await fetchJson("/interaction-model.json");
    } catch (_error) {
      showOwnerUnavailable();
      return;
    }
    role = resolveRole();
    if (!role || !model.roles[role]) {
      const list = byId("role-links");
      for (const [id, label] of Object.entries(model.roles)) list.append(el("li", {}, el("a", { href: "/role/" + id, text: label })));
      byId("role-picker").hidden = false;
      byId("work").classList.add("open");
      banner("ok", "Choose a role to begin.");
      return;
    }
    byId("role-status").replaceChildren("Role: " + model.roles[role] + " · ", el("a", { id: "switch-role", href: "/", text: "Switch role" }));
    byId("switch-role").addEventListener("click", (event) => {
      if (commandPending || unresolvedDecision || unresolvedCashBody) event.preventDefault();
    });
    byId("queue").hidden = false;
    byId("work").classList.add("has-queue");
    const decides = can("reject-offset"); // only the keys that do something for this role
    byId("keys").replaceChildren(...[[["j", "k"], "move"], ...(decides ? [[["1", "2"], "choose"], [["Ctrl", "Enter"], "record"]] : []), [["/"], "filter"]]
      .map(([caps, what]) => el("span", {}, caps.flatMap((cap) => [el("kbd", { text: cap }), " "]), what)));
    byId("filter").addEventListener("input", (event) => { filterText = event.target.value; renderQueue(); });
    byId("filter").addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.target.value = filterText = "";
        renderQueue();
        event.target.blur();
      } else if (event.key === "Enter") {
        const first = document.querySelector("#qlist a.row");
        if (first) {
          location.hash = first.dataset.id;
          event.target.blur();
        }
      }
    });
    byId("page").addEventListener("click", onRecordClick);
    byId("page").addEventListener("change", (event) => { if (event.target.name === "kind") pick(event.target.value); });
    document.addEventListener("keydown", onKey);
    window.addEventListener("hashchange", route);
    refreshOverview();
    window.setInterval(refreshOverview, 15000);
    window.setInterval(() => {
      if (lastSuccessfulRead && Date.now() - lastSuccessfulRead > 30000 && ownerAvailable) {
        markViewUnusable("stale", "STALE LOCAL VIEW — no successful Owner read in 30 seconds; commands are disabled.");
      }
    }, 5000);
  }

  boot();
})();
