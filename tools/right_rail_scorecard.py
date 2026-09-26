"""Felt-value scorecard for the Hospital H synthetic journey (Constitution Art. XII).

Runs the Hospital H journey end to end through what staff actually use: the real
loopback staff server (Owner, Mirror, pinned Lean correction release) over HTTP,
and the real served staff.js under Node against the served index.html. Each role
opens a fresh page, reads the overview, opens the H package only if the answer is
not there, expands raw JSON only as a last resort, and clicks the same buttons.

Counts are deterministic (server-side requests, clicks, screens, synthetic clock);
staff.js timers are recorded, not run. Evidence classes (Art. XI.11): "after" is
measured here; "demo_baseline" was measured by this harness before the friction
fixes; "manual_before" is an assumption with its source, or unknown.

Standing claims: synthetic, non-PHI, nonpayment, proofSuiteId=null,
production_usable=false, activation=false.

    python tools/right_rail_scorecard.py [--write]   # --write rewrites docs/scorecard/hospital_h.json
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app import right_rail_financial_engine as financial_engine  # noqa: E402
from app import right_rail_financial_staff_server as staff  # noqa: E402

SCHEMA = "RR/FINANCIAL/FELT-VALUE-SCORECARD/v1"
SCORECARD_PATH = _ROOT / "docs" / "scorecard" / "hospital_h.json"
ENGINE_PATH = _ROOT / "artifacts" / "engine-correction-e911" / "blind_financial_correction.exe"
_MODEL = json.loads((_ROOT / "app" / "staff_workspace" / "interaction-model.json").read_text(encoding="utf-8"))
HOUR_MS = 3_600_000
# Screens in the order a person reaches them; the overview is up on page load.
SCREEN_ORDER = ("overview", "decision_package", "raw:package-json", "raw:followup-json")

# Headless browser for the real staff.js: a stub DOM built from the served
# index.html ids and buttons, the browser's same-origin fetch (Origin on POST
# only), and a pending-work counter so every op returns once staff.js is idle.
DRIVER_JS = r"""
"use strict";
const http = require("http"), readline = require("readline"), vm = require("vm");
let port = 0, script = "", page = null, pending = 0, navPath = "/";
class El {
  constructor(tag, id = "") { Object.assign(this, { tagName: tag, id, children: [], parent: null, _text: "", className: "", hidden: false, disabled: false, dataset: {}, listeners: {}, colSpan: 1 }); }
  get textContent() { return this.children.length ? this.children.map((c) => c.textContent).join("\n") : this._text; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { c.parent = this; this.children.push(c); return c; }
  append(...cs) { cs.forEach((c) => this.appendChild(c)); }
  replaceChildren(...cs) { this.children = []; this._text = ""; this.append(...cs); }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  closest(sel) {
    if (sel !== "button[data-action]") throw new Error("unsupported_selector:" + sel);
    for (let n = this; n; n = n.parent) if (n.tagName === "button" && n.dataset.action) return n;
    return null;
  }
  scrollIntoView() {}
  focus() { this.focused = true; }
  setAttribute(k, v) { this.attrs = { ...this.attrs, [k]: String(v) }; }
}
const track = (p) => { pending += 1; return p.finally(() => { pending -= 1; }); };
function browserFetch(url, o = {}) {
  const method = o.method || "GET", body = o.body === undefined ? null : Buffer.from(String(o.body), "utf8");
  const headers = { Host: "127.0.0.1:" + port };
  if (method === "POST") headers.Origin = "http://127.0.0.1:" + port;
  if (o.headers && o.headers["Content-Type"]) headers["Content-Type"] = o.headers["Content-Type"];
  if (body) headers["Content-Length"] = String(body.length);
  return track(new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: url, method, headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve({ ok: res.statusCode < 300, status: res.statusCode, json: async () => JSON.parse(text), text: async () => text });
      });
      res.on("error", reject);
    });
    req.on("error", () => reject(new TypeError("Failed to fetch")));
    if (body) req.write(body);
    req.end();
  }));
}
function newPage(elements, actions) {
  const byId = new Map(), buttons = new Map(), grid = new El("div"), intervals = [];
  for (const [id, spec] of Object.entries(elements)) {
    const el = new El(spec.tag, id);
    el._text = spec.text; el.hidden = spec.hidden; byId.set(id, el);
  }
  for (const [name, label] of Object.entries(actions)) {
    const b = new El("button"); b.dataset.action = name; b._text = label; b.disabled = true;
    grid.appendChild(b); buttons.set(name, b);
  }
  const document = {
    getElementById: (id) => { if (!byId.has(id)) throw new Error("unknown_element:" + id); return byId.get(id); },
    createElement: (tag) => new El(tag),
    querySelector: (sel) => {
      if (sel === ".action-grid") return grid;
      const m = /^\[data-action="([a-z-]+)"\]$/.exec(sel);
      if (m) return buttons.get(m[1]) || null;
      throw new Error("unsupported_selector:" + sel);
    },
    querySelectorAll: (sel) => {
      if (sel === "[data-action]") return [...grid.children];
      throw new Error("unsupported_selector:" + sel);
    },
  };
  const context = { document, fetch: browserFetch, TextEncoder, console,
    location: { pathname: navPath },
    crypto: { subtle: { digest: (a, b) => track(globalThis.crypto.subtle.digest(a, b)) } },
    setInterval: (_f, ms) => intervals.push(ms), matchMedia: (q) => ({ matches: false, media: q, addEventListener() {}, addListener() {} }) };
  context.window = context;
  vm.createContext(context);
  return { byId, buttons, grid, intervals, context };
}
async function settle() {
  for (let quiet = 0; quiet < 5;) { await new Promise((r) => setImmediate(r)); quiet = pending ? 0 : quiet + 1; }
}
function view() {
  const texts = {}, tables = {}, hidden = {}, disabled = {}, buttons = {};
  for (const [id, el] of page.byId) {
    texts[id] = el.textContent;
    if (el.children.length) tables[id] = el.children.map((r) => (r.children.length ? r.children.map((c) => c.textContent) : [r.textContent]));
    if (el.hidden) hidden[id] = true;
    if (el.disabled) disabled[id] = true;
  }
  for (const [name, b] of page.buttons) buttons[name] = { disabled: b.disabled, hidden: Boolean(b.hidden) };
  return { texts, tables, hidden, disabled, buttons, intervals: page.intervals.slice() };
}
async function handle(m) {
  if (m.op === "navigate") {
    port = m.port; page = null; navPath = m.path || "/";
    const html = await (await browserFetch(navPath)).text();
    await browserFetch("/staff.css");
    script = await (await browserFetch("/staff.js")).text();
    return { html };
  }
  if (m.op === "post") {
    const res = await browserFetch(m.path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(m.body) });
    return { status: res.status, body: await res.json() };
  }
  if (m.op === "boot") {
    page = newPage(m.elements, m.actions);
    vm.runInContext(script, page.context, { filename: "staff.js" });
  } else if (m.op === "click") {
    const el = page.byId.get(m.id);
    if (!el || !el.listeners.click) throw new Error("not_clickable:" + m.id);
    el.listeners.click.forEach((f) => f({ target: el }));
  } else if (m.op === "action") {
    const b = page.buttons.get(m.name);
    if (!b) throw new Error("unknown_action:" + m.name);
    if (b.disabled) return { clicked: false };
    (page.grid.listeners.click || []).forEach((f) => f({ target: b }));
  } else if (m.op !== "view") throw new Error("unknown_op:" + m.op);
  await settle();
  return { clicked: true, view: view() };
}
let queue = Promise.resolve();
readline.createInterface({ input: process.stdin }).on("line", (line) => {
  queue = queue.then(async () => {
    let reply;
    try { reply = { ok: true, ...(await handle(JSON.parse(line))) }; } catch (e) { reply = { ok: false, error: String(e && e.message ? e.message : e) }; }
    process.stdout.write(JSON.stringify(reply) + "\n");
  });
});
"""

class HarnessUnavailable(RuntimeError):
    """A prerequisite (Node, the pinned engine artifact) is absent."""

class _PageMap(HTMLParser):
    """Served index.html -> element id: {tag, screen, label (last heading), columns, hidden, text}."""
    _VOID = {"meta", "link", "br", "input", "img", "hr"}
    def __init__(self, html: str) -> None:
        super().__init__(convert_charrefs=True)
        self._stack: list[dict[str, Any]] = []
        self._capture: dict[str, list[str]] = {}
        self._heading = ""
        self._headers: list[str] = []
        self._action = ""
        self.elements: dict[str, dict[str, Any]] = {}
        self.actions: dict[str, str] = {}
        self.feed(html)
        self.close()
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag in ("h1", "h2", "h3", "th", "button"):
            self._capture[tag] = []
        if tag == "table":
            self._headers = []
        if tag == "button":
            self._action = str(values.get("data-action") or "")
        if tag in self._VOID:
            return
        element_id = values.get("id") or ""
        self._stack.append({"tag": tag, "id": element_id, "text": []})
        if not element_id:
            return
        screen = "overview"
        for frame in self._stack:
            if frame["id"] == "decision-panel":
                screen = "decision_package"
            if frame["tag"] == "details":
                screen = "raw:"  # collapsed; named after its <pre> below
        if tag == "pre":
            screen = "raw:" + element_id
        self.elements[element_id] = {
            "tag": tag, "screen": screen, "label": self._heading,
            "columns": list(self._headers) if tag == "tbody" else [], "hidden": "hidden" in values, "text": "",
        }
    def handle_endtag(self, tag: str) -> None:
        if tag in self._capture:
            text = " ".join("".join(self._capture.pop(tag)).split())
            if tag == "th":
                self._headers.append(text)
            elif tag == "button":
                if self._action:
                    self.actions[self._action] = text
            else:
                self._heading = text
        if tag in self._VOID:
            return
        while self._stack:
            frame = self._stack.pop()
            if frame["id"] in self.elements:
                self.elements[frame["id"]]["text"] = " ".join("".join(frame["text"]).split())
            if frame["tag"] == tag:
                break
    def handle_data(self, data: str) -> None:
        for frame in self._stack:
            frame["text"].append(data)
        for parts in self._capture.values():
            parts.append(data)

class _Meter:
    """Server-side request log, tagged with the role task in progress."""
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.tag = "setup"
        self.requests: list[dict[str, Any]] = []
    def begin(self, method: str, path: str) -> dict[str, Any]:
        with self._lock:
            record = {"tag": self.tag, "method": method, "path": path, "status": None, "body": None}
            self.requests.append(record)
            return record
    def rows(self, tag: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self.requests if row["tag"] == tag]

def _metered_handler(workflow: staff.StaffWorkflow, meter: _Meter) -> type:
    """The staff server's own handler, with each request and its status recorded."""
    class Metered(staff._handler_for(workflow)):  # type: ignore[misc]
        def do_GET(self) -> None:
            self._record = meter.begin("GET", self.path)
            super().do_GET()
        def do_POST(self) -> None:
            self._record = meter.begin("POST", self.path)
            super().do_POST()
        def _json_request(self) -> dict[str, Any]:
            self._record["body"] = value = super()._json_request()
            return value
        def _respond(self, status: int, value: Any, content_type: str = "application/json; charset=utf-8") -> None:
            self._record["status"] = status
            super()._respond(status, value, content_type)
    return Metered

def _node_path() -> str:
    node = os.environ.get("RR_SCORECARD_NODE") or shutil.which("node")
    if not node:
        raise HarnessUnavailable("node_unavailable")
    return node

class _Browser:
    """One fresh browser tab for one role."""
    def __init__(self, port: int, driver: Path) -> None:
        self._process = subprocess.Popen(
            [_node_path(), str(driver)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8", cwd=str(_ROOT),
        )
        self.port = port
        self.page: _PageMap | None = None
        self.last_view: dict[str, Any] = {}
    def call(self, message: dict[str, Any]) -> dict[str, Any]:
        assert self._process.stdin and self._process.stdout
        self._process.stdin.write(json.dumps(message) + "\n")
        self._process.stdin.flush()
        line = self._process.stdout.readline()
        if not line:
            raise RuntimeError("browser_driver_exited:" + (self._process.stderr.read() if self._process.stderr else "")[-2000:])
        reply = json.loads(line)
        if not reply.pop("ok"):
            raise RuntimeError("browser_driver:" + str(reply.get("error")))
        if "view" in reply:
            self.last_view = reply["view"]
        return reply
    def open(self, path: str = "/") -> None:
        self.page = _PageMap(self.call({"op": "navigate", "port": self.port, "path": path})["html"])
        elements = {key: {"tag": spec["tag"], "text": spec["text"], "hidden": spec["hidden"]} for key, spec in self.page.elements.items()}
        self.call({"op": "boot", "elements": elements, "actions": self.page.actions})
    def click(self, element_id: str) -> None:
        self.call({"op": "click", "id": element_id})
    def action(self, name: str) -> bool:
        return bool(self.call({"op": "action", "name": name})["clicked"])
    def view(self) -> dict[str, Any]:
        return self.call({"op": "view"})["view"]
    def close(self) -> None:
        if self._process.stdin:
            self._process.stdin.close()
        try:
            self._process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()
        for stream in (self._process.stdout, self._process.stderr):
            if stream:
                stream.close()

# ---- What a person can read on each screen ----------------------------------

_NOT_CONTENT = frozenset({"button", "main", "section", "header", "footer", "body", "h1", "h2", "h3", "a"})

def _screen_lines(page: _PageMap, view: dict[str, Any], screen: str) -> list[tuple[str, str, bool]]:
    """Visible (scope "H"|"program", line, is_table_row) of one non-raw screen."""
    lines: list[tuple[str, str, bool]] = []
    for element_id, spec in page.elements.items():
        if spec["screen"] != screen or view["hidden"].get(element_id) or spec["tag"] in _NOT_CONTENT:
            continue
        label, columns = spec["label"], spec["columns"]
        rows = view["tables"].get(element_id)
        if rows is None:
            rendered = [f"{label}: {view['texts'].get(element_id, '')}" if label else view["texts"].get(element_id, "")]
        else:
            rendered = [
                " | ".join(f"{name}: {value}" for name, value in zip(columns, cells)) if columns and len(columns) == len(cells)
                else f"{cells[0]}: {cells[1]}" if len(cells) == 2 and not columns
                else (label + ": " if label else "") + " | ".join(cells)
                for cells in rows
            ]
        for line in rendered:
            in_h = screen == "decision_package" or element_id.startswith("h-") or "(H)" in line or label.startswith("H ")
            lines.append(("H" if in_h else "program", line, bool(columns)))
    return lines

def _dig(value: Any, path: tuple[Any, ...]) -> Any:
    for key in path:
        if isinstance(value, dict) and key in value:
            value = value[key]
        elif isinstance(value, list) and isinstance(key, int) and 0 <= key < len(value):
            value = value[key]
        else:
            return None
    return value

class Fact:
    """One thing a person must see: value and context regexes on one visible line,
    or (last resort) a path in the raw JSON screen."""
    def __init__(self, name: str, scope: str, value: str, context: str, json_path: tuple[Any, ...] | None = None,
                 *, rows_ok: bool = True) -> None:
        self.name, self.scope, self.json_path, self.rows_ok = name, scope, json_path, rows_ok
        self.value = re.compile(value)
        self.context = re.compile(context, re.IGNORECASE)
    def visible(self, screen: str, lines: list[tuple[str, str, bool]], raw: Any) -> bool:
        if screen.startswith("raw:"):
            return screen == "raw:package-json" and self.json_path is not None and _dig(raw, self.json_path) is not None
        for scope, line, is_row in lines:
            if scope == self.scope and (self.rows_ok or not is_row) and self.value.search(line) and self.context.search(line):
                if os.environ.get("RR_SCORECARD_DEBUG"):
                    print(f"FACT {self.name} on {screen}: {line}", file=sys.stderr)
                return True
        return False

def _money(cents: int) -> str:
    """Exact dollars and cents; whole-dollar amounts may drop ".00"."""
    text = re.escape(f"${cents // 100:,}") + (r"(?:\.00)?" if cents % 100 == 0 else re.escape(f".{cents % 100:02d}"))
    return r"(?<![\d,$.])" + text + r"(?![\d,]|\.\d)"

def _words(code: str) -> str:
    """An Owner code as shown raw (CASE_OWNER) or in plain words (case owner)."""
    return "(?i:" + "[_ ]".join(re.escape(part) for part in code.split("_")) + ")"

def _utc(ms: int, fmt: str = "%Y-%m-%d") -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime(fmt)

# ---- Fact sets per role (expected values come from the Owner, not the page) --

def _analyst_facts(truth: dict[str, Any]) -> list[Fact]:
    package = truth["decision_package"]
    case = package["case"]
    resolution = package["conclusions"]["case_resolution"]
    missing = list(resolution.get("missing_requirements") or [])
    if missing:
        next_value, next_context = "".join(f"(?=.*{_words(item)})" for item in missing), r"missing|next|requirement|needed"
    else:
        next_value, next_context = _words(str(resolution["assessment"])), r"assessment|next|resolution"
    return [
        Fact("status", "H", r"\b" + _words(str(case["status"])) + r"\b", r"case|status", ("case", "status")),
        Fact("owner", "H", _words(str(case["next_action_owner"])), r"owner", ("case", "next_action_owner")),
        Fact("amount_gap", "H", _money(int(package["obligation"]["shortfall_cents"])), r"shortfall|missing|gap|difference", ("obligation", "shortfall_cents")),
        Fact("next_action", "H", next_value, next_context, ("conclusions", "case_resolution", "missing_requirements")),
    ]

def _approver_facts(truth: dict[str, Any]) -> list[Fact]:
    package = truth["decision_package"]
    obligation = package["obligation"]
    claim = package["references"]["claims"]["items"][0]
    claim_path = ("references", "claims", "items", 0)
    return [
        Fact("amount_owed", "H", _money(int(obligation["owed_cents"])), r"owed", ("obligation", "owed_cents")),
        Fact("cash_received", "H", _money(int(obligation["received_cash_cents"])), r"cash|received", ("obligation", "received_cash_cents")),
        Fact("offset_claimed", "H", _money(int(claim["amount_cents"])), r"offset|claim|adjust", claim_path + ("amount_cents",)),
        # No support flag in the package JSON; support is a Mirror source assessment.
        Fact("offset_support", "H", r"MISSING|[Nn]o support", r"support"),
        Fact("claim_status", "H", r"\b" + _words(str(claim["status"])) + r"\b", r"claim|offset", claim_path + ("status",)),
        Fact("adjustment_rule", "H", re.escape(str(package["control_pack"]["adjustment_rule_id"])), r"rule", ("control_pack", "adjustment_rule_id")),
        Fact("deadline", "H", re.escape(_utc(int(package["case"]["due_at_ms"]))), r"due|deadline", ("case", "due_at_ms")),
    ]

def _director_facts(truth: dict[str, Any]) -> list[Fact]:
    summary, population = truth["workspace"]["summary"], truth["workspace"]["population"]
    return [
        Fact("population", "program", re.escape(f"{summary['obligation_count']} / {population['expected_count']}"), r"population", rows_ok=False),
        Fact("total_owed", "program", _money(int(summary["owed_cents"])), r"owed", rows_ok=False),
        Fact("cash_recorded", "program", _money(int(summary["received_cash_cents"])), r"cash|received", rows_ok=False),
        Fact("program_shortfall", "program", _money(int(summary["shortfall_cents"])), r"shortfall|missing|gap", rows_ok=False),
        Fact("open_items", "program", r"(?<![\d/$,.])" + str(int(summary["open_count"])) + r"(?![\d/,.])", r"open|attention|unresolved", rows_ok=False),
    ]

def _auditor_facts(truth: dict[str, Any]) -> list[Fact]:
    package = truth["decision_package"]
    determination = package["current_determination"]
    evidence = (determination.get("supporting_evidence") or [{"evidence_id": "none"}])[0]
    evidence_id = evidence.get("evidence_id", "none") if isinstance(evidence, dict) else evidence
    decision = str(determination["decision"])
    obligation = package["obligation"]
    return [
        Fact("decision", "H", _words(decision), r"determination|decision", ("current_determination", "decision")),
        Fact("decided_by_role", "H", _words(str(determination["actor_role"])), r"determination|decision|decided|role", ("current_determination", "actor_role")),
        # The chronology row of the decision event also shows when it was decided.
        Fact("decided_at", "H", re.escape(_utc(int(determination["decided_at_ms"]), "%Y-%m-%d %H:%M")), r"determination|decision|decided|" + re.escape(decision), ("current_determination", "decided_at_ms")),
        Fact("supporting_evidence", "H", re.escape(str(evidence_id)), r"evidence", ("current_determination", "supporting_evidence")),
        Fact("adjustment_rule", "H", re.escape(str(package["control_pack"]["adjustment_rule_id"])), r"rule", ("control_pack", "adjustment_rule_id")),
        Fact("chronology", "H", r"(?i:determin|offset[_ ]rejected|correction)", r"Chronology|event|sequence", ("current_determination", "determination_id")),
        Fact("cash_reconciles", "H", _money(int(obligation["received_cash_cents"])) + r".*" + _money(int(obligation["shortfall_cents"])), r"cash|received", ("obligation", "received_cash_cents")),
    ]

_CONTINUITY_FACTS = (
    Fact("continuity_test_mode", "H", r"\bTEST\b", r"continuity"),
    Fact("package_equal", "program", r"equality: true|equal: true|matches", r"restore|continuity", rows_ok=False),
)

# ---- The journey ------------------------------------------------------------

class _Journey:
    def __init__(self, port: int, workflow: staff.StaffWorkflow, meter: _Meter, driver: Path) -> None:
        self.port, self.workflow, self.meter, self.driver = port, workflow, meter, driver
        self.detail: dict[str, Any] = {}
        self.units: dict[str, int] = {}
        self._cash_body: Any = None
    def truth(self) -> dict[str, Any]:
        """Ground truth straight from the Owner through the Mirror (not counted)."""
        return {"workspace": self.workflow.workspace(), "decision_package": self.workflow.decision_view()["decision_package"]}
    def _task(self, tag: str) -> "_Task":
        self.meter.tag = tag
        return _Task(self, tag)
    def run(self) -> None:
        with self._task("director.weekly_review") as task:
            task.open()
            task.answer(_director_facts(self.truth()))
            task.record("rows_to_add_by_hand", len(task.browser.last_view["tables"].get("population-rows", [])) if task.unanswered else 0)
            task.record("rows_flagged_open", _open_rows(task.browser.last_view))
        with self._task("analyst.monday_reconciliation") as task:
            task.open()
            task.record("rows_flagged_open", _open_rows(task.browser.view()))
            task.answer(_analyst_facts(self.truth()))
        with self._task("approver.prepare_decision") as task:
            task.open()
            task.answer(_approver_facts(self.truth()), need_package=True)
            task.record("requests_to_prepare", task.request_count())
            task.command("reject-offset")
            task.record("requests_including_decision", task.request_count())
            if not self.truth()["decision_package"].get("current_determination"):
                raise RuntimeError("scorecard_decision_not_committed")
        with self._task("analyst.correction_followthrough") as task:
            task.open()
            task.ensure_package()
            reopens = 0
            for name in ("acknowledge", "record-cash", "record-report"):
                if task.browser.view()["buttons"][name]["disabled"]:
                    task.click("open-package", "reopen package (forced re-review)")
                    reopens += 1
                task.command(name)
            task.record("forced_package_reopens", reopens)
            posts = [row for row in self.meter.rows(task.tag) if row["method"] == "POST" and row["path"] in ("/api/correction/record-cash", "/api/reporting/record")]
            task.record("evidence_resubmissions", len(posts) - len({json.dumps([row["path"], row["body"]], sort_keys=True) for row in posts}))
            self._cash_body = next(row["body"] for row in posts if row["path"] == "/api/correction/record-cash")
        self._repeat_message()
        with self._task("auditor.answer_auditor") as task:
            task.open()
            task.answer(_auditor_facts(self.truth()))
        with self._task("replacement.continue_from_continuity") as task:
            task.open()
            task.ensure_package()
            task.command("restore-test")
            task.answer(list(_CONTINUITY_FACTS) + _analyst_facts(self.truth()), fresh_screens=True)
        self._case_units()
        self.meter.tag = "done"
    def _repeat_message(self) -> None:
        """The exact $3,000 cash message arrives again (as after a lost response)."""
        self.meter.tag = "harness.repeat_message"
        cash = lambda: int(self.truth()["decision_package"]["obligation"]["received_cash_cents"])  # noqa: E731
        before = cash()
        browser = _Browser(self.port, self.driver)
        try:
            browser.call({"op": "navigate", "port": self.port})
            reply = browser.call({"op": "post", "path": "/api/correction/record-cash", "body": self._cash_body})
        finally:
            browser.close()
        after = cash()
        status, body = reply["status"], reply["body"]
        self.detail["repeat_message"] = {"http_status": status, "outcome": _dig(body, ("command", "status") if status == 200 else ("error", "code"))}
        self.units["accuracy.repeat_message_double_count_cents"] = after - before
        self.units["evidence.repeat_message_absorbed"] = int(status == 200 and after == before)
    def _case_units(self) -> None:
        self.meter.tag = "harness.case_units"
        truth = self.truth()
        summary, items = truth["workspace"]["summary"], truth["workspace"]["items"]
        package = truth["decision_package"]
        obligation = package["obligation"]
        timeline = self.workflow.decision_view()["timeline"]
        if package["case"]["status"] != "RESOLVED":
            raise RuntimeError("scorecard_h_not_resolved")
        first_cash = min(event["committed_at_ms"] for event in timeline if event["kind"] == "PAYMENT_RECEIVED")
        resolved_at = max(event["committed_at_ms"] for event in timeline)
        due = int(package["case"]["due_at_ms"])
        hours = lambda ms: (ms + HOUR_MS // 2) // HOUR_MS  # noqa: E731  (whole synthetic hours, half up)
        self.units["case.h_unresolved_age_hours"] = hours(resolved_at - first_cash)
        self.units["case.h_hours_past_due_at_resolution"] = hours(max(0, resolved_at - due))
        self.units["program.unresolved_items_at_end"] = sum(1 for item in items if item["case_status"] != "RESOLVED")
        self.units["program.open_amount_items_at_end"] = int(summary["open_count"])
        self.units["accuracy.correction_error_cents"] = abs(
            int(obligation["received_cash_cents"]) + int(obligation["lawful_adjustment_cents"]) - int(obligation["owed_cents"])
        ) + int(obligation["shortfall_cents"])
        self.units["accuracy.reconciliation_error_cents"] = sum(
            abs(sum(int(item[key]) for item in items) - int(summary[key])) for key in ("owed_cents", "received_cash_cents", "shortfall_cents")
        ) + abs(int(summary["owed_cents"]) - staff.PROGRAM_TOTAL_CENTS)
        self.detail["case"] = {
            "h_first_cash_committed_utc": _utc(first_cash, "%Y-%m-%d %H:%M"),
            "h_due_utc": _utc(due, "%Y-%m-%d %H:%M"),
            "h_resolved_committed_utc": _utc(resolved_at, "%Y-%m-%d %H:%M"),
            "h_final": {key: obligation[key] for key in ("owed_cents", "received_cash_cents", "shortfall_cents", "timely")},
            "program_final": {key: summary[key] for key in ("owed_cents", "received_cash_cents", "shortfall_cents", "open_count")},
            "clock_note": "Synthetic demo clock; the fixture sets these times, so UI changes cannot move them.",
        }

def _open_rows(view: dict[str, Any]) -> int:
    rows = view["tables"].get("population-rows", [])
    return sum(1 for cells in rows if (m := re.search(r"Case ([A-Z_]+)", " ".join(cells))) and m.group(1) != "RESOLVED")

# Each task tag names the role it is performed as (Art. XIII.4: roles are
# real, so the journey now opens each task's page as that role would).
_TASK_ROLE = {"director": "director", "analyst": "analyst", "approver": "approver",
              "auditor": "auditor", "replacement": "operator"}

class _Task:
    """One role doing one task in a fresh browser tab."""
    def __init__(self, journey: _Journey, tag: str) -> None:
        self.journey, self.tag = journey, tag
        self.role = _TASK_ROLE[tag.split(".")[0]]
        self.browser = _Browser(journey.port, journey.driver)
        self.steps: list[str] = []
        self.ui_actions = 0
        self.screens: list[str] = []
        self.found_on: dict[str, str] = {}
        self.unanswered: list[str] = []
        self.values: dict[str, int] = {}
    def __enter__(self) -> "_Task":
        return self
    def __exit__(self, exc_type: object, _exc: object, _tb: object) -> None:
        try:
            if exc_type is None:
                view = self.browser.view()
                self.journey.detail[self.tag] = {
                    "steps": self.steps,
                    "enabled_commands_at_end": sorted(name for name, button in view["buttons"].items() if not button["disabled"]),
                    "screens": self.screens,
                    "facts_found_on": self.found_on,
                    "facts_unanswered": self.unanswered,
                    "requests": [f"{row['method']} {row['path']} -> {row['status']}" for row in self.journey.meter.rows(self.tag)],
                }
                self.values.update(requests=self.request_count(), ui_actions=self.ui_actions)
                self.journey.units.update({f"{self.tag}.{name}": value for name, value in self.values.items()})
        finally:
            self.browser.close()
    def request_count(self) -> int:
        return len(self.journey.meter.rows(self.tag))
    def step(self, text: str) -> None:
        self.steps.append(text)
        self.ui_actions += text.startswith(("click", "expand"))
    def record(self, name: str, value: int) -> None:
        self.values[name] = int(value)
    def open(self) -> None:
        self.browser.open(f"/role/{self.role}")
        self.steps.append("open workspace page")
        self.screens.append("overview")
    def click(self, element_id: str, why: str) -> None:
        self.browser.click(element_id)
        self.step(f"click: {why}")
    def command(self, name: str) -> None:
        if not self.browser.action(name):
            raise RuntimeError("scorecard_command_unavailable:" + name)
        self.step("click: " + name)
        status = self.browser.last_view["texts"].get("command-status", "")
        # The declared success text (Art. XIII.4) is checked first: a control's own
        # wording (e.g. reject-offset's "Offset rejected...") may legitimately use a
        # failure-shaped word, so only fall back to the denylist once it disagrees.
        expected = _MODEL["controls"][name]["responses"]["success"]["message"].split(".")[0]
        if not status or (expected not in status and any(word in status for word in ("rejected", "unresolved", "unavailable", "denied"))):
            raise RuntimeError(f"scorecard_command_failed:{name}:{status}")
    def ensure_package(self) -> None:
        if "decision_package" not in self.screens:
            self.click("open-package", "open H decision package")
            self.screens.append("decision_package")
    def answer(self, facts: list[Fact], *, need_package: bool = False, fresh_screens: bool = False) -> None:
        """Walk the screens in order until every fact is visible; record the cost."""
        if need_package:
            self.ensure_package()
        pending = list(facts)
        opened = ["overview"]
        package_up = not self.browser.view()["hidden"].get("decision-panel") if fresh_screens else "decision_package" in self.screens
        if package_up:
            opened.append("decision_package")
        for screen in SCREEN_ORDER:
            if not pending:
                break
            if screen not in opened:
                if screen == "decision_package":
                    self.click("open-package", "open H decision package")
                else:
                    self.step(f"expand: {screen[4:]}")
                opened.append(screen)
            if screen not in self.screens:
                self.screens.append(screen)
            view = self.browser.view()
            for seen in opened:
                lines = [] if seen.startswith("raw:") else _screen_lines(self.browser.page, view, seen)
                try:
                    raw = json.loads(view["texts"].get(seen[4:], "")) if seen.startswith("raw:") else None
                except ValueError:
                    raw = None
                for fact in list(pending):
                    if fact.visible(seen, lines, raw):
                        self.found_on[fact.name] = seen
                        pending.remove(fact)
        self.unanswered = [fact.name for fact in pending]
        self.record("requests_to_answer", self.request_count())
        self.record("ui_actions_to_answer", self.ui_actions)
        self.record("screens_to_answer", len(self.screens))
        self.record("facts_only_in_raw_json", sum(1 for screen in self.found_on.values() if screen.startswith("raw:")))
        self.record("facts_unanswered", len(self.unanswered))
        self.record("facts_total", len(facts))

# ---- Scorecard assembly -----------------------------------------------------

# Role task -> (role, moment, scored per-task units). Lower is better unless noted.
TASKS = {
    "analyst.monday_reconciliation": ("state analyst", "Monday: what is happening with H, who owns it, the gap, the next step",
                                      "requests_to_answer ui_actions_to_answer screens_to_answer facts_only_in_raw_json facts_unanswered rows_flagged_open"),
    "analyst.correction_followthrough": ("state analyst", "following the correction through: delivery ACK, $3,000 cash, report",
                                         "requests ui_actions forced_package_reopens evidence_resubmissions"),
    "approver.prepare_decision": ("finance approver", "deciding on the unsupported $3,000 offset",
                                  "requests_to_prepare ui_actions_to_answer screens_to_answer facts_only_in_raw_json facts_unanswered requests_including_decision"),
    "director.weekly_review": ("director", "weekly program review: population, owed, cash, shortfall, open items",
                               "requests_to_answer ui_actions_to_answer facts_unanswered rows_to_add_by_hand rows_flagged_open"),
    "auditor.answer_auditor": ("auditor", "who decided, when, on what evidence and rule",
                               "requests_to_answer ui_actions_to_answer screens_to_answer facts_only_in_raw_json facts_unanswered"),
    "replacement.continue_from_continuity": ("replacement operator", "taking over H from Continuity TEST",
                                             "requests_to_answer ui_actions_to_answer facts_only_in_raw_json facts_unanswered"),
}
UNIT_TEXT = {
    "requests_to_answer": "HTTP requests until every needed fact is on screen",
    "requests_to_prepare": "HTTP requests until every decision input is on screen",
    "requests_including_decision": "HTTP requests from opening the page through the recorded decision",
    "requests": "HTTP requests for the whole task",
    "ui_actions_to_answer": "clicks until every needed fact is on screen",
    "ui_actions": "clicks for the whole task",
    "screens_to_answer": "screens looked at",
    "facts_only_in_raw_json": "needed facts visible only in raw JSON",
    "facts_unanswered": "needed facts nowhere on screen",
    "rows_flagged_open": "hospital rows shown as open",
    "rows_to_add_by_hand": "rows to add up by hand for a missing total",
    "forced_package_reopens": "times the package had to be reopened before the next button worked",
    "evidence_resubmissions": "evidence entered twice",
}
CASE_UNITS = (
    ("case.h_unresolved_age_hours", "state analyst, director", "H's $3,000 gap stays open", "synthetic-clock hours from H's short payment to resolution"),
    ("case.h_hours_past_due_at_resolution", "director, auditor", "H is paid late", "synthetic-clock hours past H's due date at resolution (stays on record)"),
    ("program.unresolved_items_at_end", "director", "end of the journey", "hospitals still unresolved"),
    ("program.open_amount_items_at_end", "director", "end of the journey", "hospitals still short of their amount"),
    ("accuracy.correction_error_cents", "finance approver, auditor", "after the correction", "cents by which H's correction misses its $100,000"),
    ("accuracy.reconciliation_error_cents", "director, auditor", "after the correction", "cents by which the 20 rows miss the program totals"),
    ("accuracy.repeat_message_double_count_cents", "state analyst, auditor", "the $3,000 payment message arrives twice", "cents counted twice"),
    ("evidence.repeat_message_absorbed", "state analyst", "the $3,000 payment message arrives twice", "1 if the repeat was absorbed (higher is better)"),
)
HIGHER_IS_BETTER = {"evidence.repeat_message_absorbed"}

# Manual-process "before" (Art. XI.11): assumptions with their source, never measurements.
MANUAL_BEFORE: dict[str, dict[str, Any]] = {
    "analyst.monday_reconciliation.screens_to_answer": {"value": 4, "evidence": "assumption (source: plan §4: the analyst joins the approved schedule, the state payment record, Plan A's distribution file and the case correspondence by hand; one document each)"},
    "analyst.monday_reconciliation.rows_flagged_open": {"value": 20, "evidence": "assumption (source: plan §4: 20 hospitals; with no shared status each row is checked by hand)"},
    "approver.prepare_decision.screens_to_answer": {"value": 5, "evidence": "assumption (source: plan §4: approved amount, payment evidence, Plan A's offset claim, the missing approval and the method rule; one document each)"},
    "director.weekly_review.rows_to_add_by_hand": {"value": 20, "evidence": "assumption (source: plan §4: $1M across 20 hospitals, summed by hand)"},
    "case.h_hours_past_due_at_resolution": {"value": None, "evidence": "unknown (plan §2 cites NY Comptroller 2025-F-10: recoveries lost to passed deadlines; no per-case figure)"},
    "case.h_unresolved_age_hours": {"value": None, "evidence": "unknown (plan gives no manual resolution time; §14 says to measure it beside the current process)"},
    "accuracy.repeat_message_double_count_cents": {"value": None, "evidence": "unknown (plan §4 names the double-count risk; no rate given)"},
    "accuracy.correction_error_cents": {"value": None, "evidence": "unknown (plan §2 cites audit populations, e.g. NY 2021-S-24; no per-correction error rate)"},
}

# Measured by this harness on the staff workspace before the friction fixes
# (product code unchanged from e9b3727 through 1c7ed3b; guarded runs score-base-8
# and score-base-9 on a clean export of 1c7ed3b).
BASELINE_COMMIT = "1c7ed3b"
DEMO_BASELINE: dict[str, int] = {
    "analyst.monday_reconciliation.requests_to_answer": 6,
    "analyst.monday_reconciliation.ui_actions_to_answer": 2,
    "analyst.monday_reconciliation.screens_to_answer": 3,
    "analyst.monday_reconciliation.facts_only_in_raw_json": 1,
    "analyst.monday_reconciliation.facts_unanswered": 0,
    "analyst.monday_reconciliation.rows_flagged_open": 20,
    "analyst.correction_followthrough.requests": 14,
    "analyst.correction_followthrough.ui_actions": 6,
    "analyst.correction_followthrough.forced_package_reopens": 2,
    "analyst.correction_followthrough.evidence_resubmissions": 0,
    "approver.prepare_decision.requests_to_prepare": 6,
    "approver.prepare_decision.ui_actions_to_answer": 2,
    "approver.prepare_decision.screens_to_answer": 3,
    "approver.prepare_decision.facts_only_in_raw_json": 2,
    "approver.prepare_decision.facts_unanswered": 0,
    "approver.prepare_decision.requests_including_decision": 8,
    "director.weekly_review.requests_to_answer": 6,
    "director.weekly_review.ui_actions_to_answer": 3,
    "director.weekly_review.facts_unanswered": 3,
    "director.weekly_review.rows_to_add_by_hand": 20,
    "director.weekly_review.rows_flagged_open": 20,
    "auditor.answer_auditor.requests_to_answer": 6,
    "auditor.answer_auditor.ui_actions_to_answer": 2,
    "auditor.answer_auditor.screens_to_answer": 3,
    "auditor.answer_auditor.facts_only_in_raw_json": 2,
    "auditor.answer_auditor.facts_unanswered": 0,
    "replacement.continue_from_continuity.requests_to_answer": 8,
    "replacement.continue_from_continuity.ui_actions_to_answer": 3,
    "replacement.continue_from_continuity.facts_only_in_raw_json": 1,
    "replacement.continue_from_continuity.facts_unanswered": 0,
    "case.h_unresolved_age_hours": 48,
    "case.h_hours_past_due_at_resolution": 24,
    "program.unresolved_items_at_end": 19,
    "program.open_amount_items_at_end": 19,
    "accuracy.correction_error_cents": 0,
    "accuracy.reconciliation_error_cents": 0,
    "accuracy.repeat_message_double_count_cents": 0,
    "evidence.repeat_message_absorbed": 1,
}

def measure() -> dict[str, Any]:
    """Run the journey once on a fresh synthetic Owner; return units and journey detail."""
    if not ENGINE_PATH.is_file():
        raise HarnessUnavailable("correction_engine_artifact_absent")
    _node_path()
    with ExitStack() as stack:
        temp = lambda prefix: Path(stack.enter_context(tempfile.TemporaryDirectory(prefix=prefix))).resolve()  # noqa: E731
        owner_dir, engine_dir, driver_dir = temp("rr-scorecard-owner-"), temp("rr-scorecard-engine-"), temp("rr-scorecard-driver-")
        driver = driver_dir / "browser.js"
        driver.write_text(DRIVER_JS, encoding="utf-8")
        release = financial_engine.load_correction_transition_release(ENGINE_PATH.resolve(), engine_dir)
        workflow = staff.StaffWorkflow(owner_dir, correction_transition_release=release)
        stack.callback(workflow.close)
        meter = _Meter()
        server = staff._LoopbackServer(("127.0.0.1", 0), _metered_handler(workflow, meter))
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        stack.callback(thread.join, 30)
        stack.callback(server.server_close)
        stack.callback(server.shutdown)
        journey = _Journey(int(server.server_address[1]), workflow, meter, driver)
        journey.run()
        return {"units": dict(sorted(journey.units.items())), "journeys": journey.detail}

def catalog() -> list[tuple[str, str, str, str]]:
    """(unit id, role, moment, plain unit) for every scored unit."""
    rows = [(f"{task}.{unit}", role, moment, UNIT_TEXT[unit]) for task, (role, moment, units) in TASKS.items() for unit in units.split()]
    return rows + list(CASE_UNITS)

def build_scorecard(measured: dict[str, Any]) -> dict[str, Any]:
    units = []
    for unit_id, role, moment, text in catalog():
        baseline = DEMO_BASELINE.get(unit_id)
        units.append({
            "id": unit_id, "role": role, "moment": moment, "unit": text,
            "direction": "higher" if unit_id in HIGHER_IS_BETTER else "lower",
            "manual_before": MANUAL_BEFORE.get(unit_id, {"value": None, "evidence": "unknown (no manual figure in the plan)"}),
            "demo_baseline": {"value": baseline, "evidence": f"measured (this harness at {BASELINE_COMMIT}, before the friction fixes)"},
            "after": {"value": measured["units"][unit_id], "evidence": "measured (this harness)"},
        })
    return {
        "schema": SCHEMA,
        "scenario": "Hospital H: $1,000,000 across 20 synthetic hospitals; H is owed $100,000, $97,000 arrives, Plan A claims an unsupported $3,000 offset; the approver rejects it, a $3,000 correction arrives, reporting follows, and a replacement operator restores the case in Continuity TEST.",
        "claims": {"synthetic": True, "phi": False, "payment": False, "proofSuiteId": None, "production_usable": False, "activation": False},
        "method": {
            "path": "real loopback staff server over HTTP; real served staff.js under Node against the served index.html; Owner + Mirror + pinned Lean correction release",
            "counting": "deterministic: server-side requests, clicks and screens per role task; synthetic clock; timers recorded, not run",
            "screens": list(SCREEN_ORDER),
            "comparison": "tests/test_right_rail_scorecard.py fails if any 'after' value is worse than this file in its direction",
        },
        "units": units,
        "journeys": measured["journeys"],
    }

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--write", action="store_true", help="rewrite docs/scorecard/hospital_h.json")
    parser.add_argument("--out", type=Path, help="also write the full scorecard JSON here")
    args = parser.parse_args(argv)
    measured = measure()
    text = json.dumps(build_scorecard(measured), indent=2, sort_keys=True) + "\n"
    for path in filter(None, (args.out, SCORECARD_PATH if args.write else None)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        print("wrote", path)
    print(json.dumps(measured["units"], indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
