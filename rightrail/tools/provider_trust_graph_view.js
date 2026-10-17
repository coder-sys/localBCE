"use strict";

const bundleSchema = "mirror-provider-trust-graph-local-view-v1";
const fields = {
  status: document.getElementById("status-grid"),
  error: document.getElementById("load-error"),
  observationTab: document.getElementById("observation-tab"),
  comparisonTab: document.getElementById("comparison-tab"),
  observationPanel: document.getElementById("observation-panel"),
  comparisonPanel: document.getElementById("comparison-panel"),
  sideLabel: document.getElementById("selection-label"),
  side: document.getElementById("selection-side"),
  collection: document.getElementById("collection"),
  summary: document.getElementById("collection-summary"),
  list: document.getElementById("item-list"),
  detail: document.getElementById("detail-fields"),
  detailHeading: document.getElementById("detail-heading"),
  position: document.getElementById("detail-position"),
  previous: document.getElementById("previous-item"),
  next: document.getElementById("next-item"),
  semantics: document.getElementById("comparison-semantics"),
  sourceChanges: document.getElementById("source-changes"),
  findingDeltas: document.getElementById("finding-deltas"),
  discrepancyDeltas: document.getElementById("discrepancy-deltas"),
  leftContext: document.getElementById("left-context"),
  rightContext: document.getElementById("right-context")
};

let viewBundle = null;
let detailIndex = 0;
let activeView = "observation";

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function displayValue(value) {
  if (value === null) return "null";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function addField(list, key, value) {
  const term = element("dt", "", key.replaceAll("_", " "));
  const description = element("dd", "", displayValue(value));
  list.append(term, description);
}

function renderFields(list, value) {
  list.replaceChildren();
  for (const [key, fieldValue] of Object.entries(value || {})) {
    addField(list, key, fieldValue);
  }
}

function selectedModel() {
  if (viewBundle.mode === "COMPARE" && fields.side.value === "right") return viewBundle.right;
  return viewBundle.left;
}

function currentItems() {
  const model = selectedModel();
  const observation = model && model.observation;
  const items = observation && observation[fields.collection.value];
  return Array.isArray(items) ? items : [];
}

function itemLabel(item, index) {
  const label = item.source_role || item.graph_finding_kind || item.graph_discrepancy_kind || "Projection item";
  const roles = Array.isArray(item.evidence_source_roles) ? item.evidence_source_roles.join(", ") : "";
  const references = Number.isInteger(item.evidence_reference_count) ? item.evidence_reference_count : 0;
  const parts = [`${index + 1}. ${String(label)}`];
  if (roles) parts.push(`roles: ${roles}`);
  parts.push(`evidence references: ${references}`);
  return parts.join(" · ");
}

function renderDetail(items) {
  fields.detail.replaceChildren();
  if (items.length === 0) {
    fields.detailHeading.textContent = "No projected item";
    fields.position.textContent = "0 items";
    fields.previous.disabled = true;
    fields.next.disabled = true;
    return;
  }
  detailIndex = Math.max(0, Math.min(detailIndex, items.length - 1));
  fields.detailHeading.textContent = `Ephemeral detail ${detailIndex + 1}`;
  fields.position.textContent = `${detailIndex + 1} of ${items.length}`;
  fields.previous.disabled = detailIndex === 0;
  fields.next.disabled = detailIndex >= items.length - 1;
  renderFields(fields.detail, items[detailIndex]);
}

function renderObservation() {
  const model = selectedModel();
  const items = currentItems();
  const name = fields.collection.options[fields.collection.selectedIndex].textContent;
  const summary = model.summary || {};
  const countKey = {
    sources: "source_count",
    findings: "finding_count",
    discrepancies: "discrepancy_count"
  }[fields.collection.value];
  const count = Number.isInteger(summary[countKey]) ? summary[countKey] : items.length;
  fields.summary.textContent = `${name}: ${count} item${count === 1 ? "" : "s"} in this verified projection. This count does not establish what the source contains.`;
  fields.list.replaceChildren();
  detailIndex = Math.max(0, Math.min(detailIndex, items.length - 1));

  if (items.length === 0) {
    const empty = element("li", "muted", "No items in this projection; this does not establish that the source has none.");
    fields.list.append(empty);
  } else {
    items.forEach((item, index) => {
      const row = element("li");
      const button = element("button", "", itemLabel(item, index));
      button.type = "button";
      button.setAttribute("aria-current", index === detailIndex ? "true" : "false");
      button.addEventListener("click", () => {
        detailIndex = index;
        renderObservation();
      });
      row.append(button);
      fields.list.append(row);
    });
  }
  renderDetail(items);
}

function renderDeltaList(container, rows, emptyText) {
  container.replaceChildren();
  if (!Array.isArray(rows) || rows.length === 0) {
    container.append(element("p", "muted", emptyText));
    return;
  }
  const list = element("div", "delta-list");
  rows.forEach((row, index) => {
    const item = element("section", "delta-item");
    const headingValue = row.graph_kind || row.source_role || row.graph_finding_kind || row.graph_discrepancy_kind || `Difference ${index + 1}`;
    item.append(element("h4", "", String(headingValue)));
    const details = element("dl", "field-list");
    renderFields(details, row);
    item.append(details);
    list.append(item);
  });
  container.append(list);
}

function renderComparison() {
  const comparison = viewBundle.comparison.comparison;
  fields.semantics.textContent = `${comparison.semantics}. Missing evidence semantics: ${comparison.missing_evidence_semantics}. Differences describe verified graph projections only.`;
  renderDeltaList(fields.sourceChanges, comparison.source_changes, "No source projection differences are listed.");
  renderDeltaList(fields.findingDeltas, comparison.finding_deltas, "No finding projection differences are listed.");
  renderDeltaList(fields.discrepancyDeltas, comparison.discrepancy_deltas, "No discrepancy projection differences are listed.");
  renderFields(fields.leftContext, comparison.left);
  renderFields(fields.rightContext, comparison.right);
}

function setActiveView(view) {
  activeView = view;
  const showObservation = activeView === "observation";
  fields.observationTab.setAttribute("aria-pressed", String(showObservation));
  fields.comparisonTab.setAttribute("aria-pressed", String(!showObservation));
  fields.observationPanel.hidden = !showObservation;
  fields.comparisonPanel.hidden = showObservation;
}

function showLoadError() {
  fields.error.textContent = "The local verified view could not be loaded. Close it and restart the command with valid synthetic inputs.";
  fields.error.hidden = false;
}

function initialize(bundle) {
  if (!bundle || bundle.schema !== bundleSchema || !["SINGLE", "COMPARE"].includes(bundle.mode) || !bundle.left) {
    throw new Error("invalid local view bundle");
  }
  if (bundle.mode === "COMPARE" && (!bundle.right || !bundle.comparison || !bundle.comparison.comparison)) {
    throw new Error("invalid comparison bundle");
  }
  viewBundle = bundle;
  renderFields(fields.status, bundle.left.status);
  fields.comparisonTab.hidden = bundle.mode !== "COMPARE";
  fields.sideLabel.hidden = bundle.mode !== "COMPARE";
  fields.side.hidden = bundle.mode !== "COMPARE";
  renderObservation();
  if (bundle.mode === "COMPARE") renderComparison();
}

fields.observationTab.addEventListener("click", () => setActiveView("observation"));
fields.comparisonTab.addEventListener("click", () => setActiveView("comparison"));
fields.collection.addEventListener("change", () => {
  detailIndex = 0;
  renderObservation();
});
fields.side.addEventListener("change", () => {
  detailIndex = 0;
  renderObservation();
});
fields.previous.addEventListener("click", () => {
  detailIndex -= 1;
  renderObservation();
});
fields.next.addEventListener("click", () => {
  detailIndex += 1;
  renderObservation();
});

fetch("/data.json", { cache: "no-store", credentials: "same-origin" })
  .then((response) => {
    if (!response.ok) throw new Error("local data route rejected");
    return response.json();
  })
  .then(initialize)
  .catch(showLoadError);
