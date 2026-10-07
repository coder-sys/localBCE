"""Felt-value scorecard for the Hospital H synthetic journey (Constitution Art. XII).

Runs the Hospital H journey end to end through what staff actually use: the real
loopback staff server (Owner, Mirror, pinned Lean evaluator worker) over HTTP,
and the real served page in an isolated Edge browser driven by Playwright. Each role
opens a fresh page, reads what is on it, opens H's record only if the answer is not
there, and clicks the same buttons.

Counts include actual server requests, clicks, screens and normal polling; the
Owner clock is synthetic. Evidence classes (Art. XI.11): "after" is
measured here; "demo_baseline" was measured by this harness before the friction
fixes; "manual_before" is an assumption with its source, or unknown.

Standing claims: synthetic, non-PHI, nonpayment, proofSuiteId=null,
production_usable=false, activation=false.

    python tests/instruments/right_rail_scorecard.py [--write]   # --write rewrites docs/scorecard/hospital_h.json
"""

from __future__ import annotations

import argparse
import base64
import copy
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import itertools
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

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app import right_rail_financial_staff_server as staff  # noqa: E402

SCHEMA = "RR/FINANCIAL/FELT-VALUE-SCORECARD/v1"
SCORECARD_PATH = _ROOT / "docs" / "scorecard" / "hospital_h.json"
_MODEL = json.loads((_ROOT / "app" / "staff_workspace" / "interaction-model.json").read_text(encoding="utf-8"))
HOUR_MS = 3_600_000
# Screens in the order a person reaches them: the page as it opens, then H's record if H is not already up.
SCREEN_ORDER = ("landing", "record")

# The caller supplies the installed Edge executable and Playwright package.
# Browser contexts, DOM, same-origin fetch and polling are real; no fallback.
DRIVER_JS = r"""
"use strict";
const readline = require("readline");
const path = require("path");
const modulePath = process.env.RR_SCORECARD_PLAYWRIGHT;
const executablePath = process.env.RR_SCORECARD_BROWSER;
if (!modulePath || !executablePath) throw new Error("real_browser_runtime_unconfigured");
if (!path.isAbsolute(modulePath) || !path.isAbsolute(executablePath) || path.basename(executablePath).toLowerCase() !== "msedge.exe") {
  throw new Error("real_browser_runtime_not_explicit_edge");
}
if (require(path.join(modulePath, "package.json")).version !== "1.62.1") throw new Error("playwright_version_mismatch");
const { chromium } = require(modulePath);
let browser = null;  // the one browser, as a promise once launching: every session is a fresh context in it
const sessions = new Map();
const SHEET = { "reject-offset": "Reject the offset", "authorize-offset": "Accept the offset" };
async function settle(S) {
  const deadline = Date.now() + 30000;
  while (S.pending.size || Date.now() - S.changedAt < 150) {
    if (Date.now() >= deadline) throw new Error("browser_network_idle_timeout");
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  if (S.pageErrors.length) throw new Error("browser_page_error:" + S.pageErrors.join("\n"));
}
async function view(S) {
  const dom = await S.page.evaluate(() => {
    const texts = {}, hidden = {}, disabled = {}, buttons = {}, lines = [];
    const invisible = (el) => !el.getClientRects().length || getComputedStyle(el).visibility === "hidden";
    const text = (el) => (el.children.length && ![...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())
      ? [...el.children].map(text).filter(Boolean).join(" ") : el.textContent.replace(/\s+/g, " ").trim());
    for (const el of document.querySelectorAll("[id]")) {
      texts[el.id] = el.textContent;
      if (invisible(el)) hidden[el.id] = true;
      if (el.disabled) disabled[el.id] = true;
    }
    for (const button of document.querySelectorAll("[data-action]")) {
      buttons[button.dataset.action] = { disabled: button.disabled, hidden: invisible(button) };
    }
    // The two decisions have no button of their own: the choice is a radio, or, when a lost answer is retried, "Send the ... again".
    const role = location.pathname.split("/")[2] || null;
    const radio = document.getElementById("kind-reject-offset"), confirm = document.getElementById("confirm");
    const open = Boolean((radio && !radio.disabled) || (confirm && !confirm.disabled && /^Send the .* again$/.test(confirm.textContent)));
    for (const name of ["reject-offset", "authorize-offset"]) buttons[name] = { disabled: !open, hidden: role !== "approver" };
    // What a person reads: one line per table row, fact, paragraph and queue row, tagged H or program.
    const scope = (el) => ((el.closest("[data-record]") || {}).dataset?.record ?? (el.closest("#row-item-h") ? "item-h" : "")) === "item-h" ? "H" : "program";
    const add = (el, line) => { if (line && !invisible(el)) lines.push({ scope: scope(el), text: line, where: el.closest("#qlist") ? "queue" : el.closest("#page") ? "page" : "status" }); };
    for (const el of document.querySelectorAll("#page tr, #page p, #page .state, #page .line, #page .seal, #page .log li, #page dt, #page .steps li, #qlist .row, #qlist .group, #command-status")) {
      add(el, el.matches("dt") ? text(el) + ": " + text(el.nextElementSibling) : el.matches("tr") ? [...el.children].map(text).filter(Boolean).join(" | ") : text(el));
    }
    for (const pre of document.querySelectorAll("#page pre")) for (const line of pre.textContent.split("\n")) add(pre, line.trim());
    const named = (el) => Boolean(el.getAttribute("aria-label") || text(el) || (el.labels && el.labels.length));
    const unnamed = [...document.querySelectorAll("button, a[href], input, textarea, select")].filter((el) => !invisible(el) && !named(el)).map((el) => el.id || el.tagName);
    const unavailable = document.getElementById("connection-status").classList.contains("unavailable");
    const screens = { picker: !hidden["role-picker"], overview: !hidden["queue"] && !unavailable,
      decision: Boolean(document.querySelector('#page [data-record="item-h"]')) && !unavailable, unavailable };
    const queue = [...document.querySelectorAll("#qlist .row")].map((row) => row.querySelector(".dot").className.replace("dot ", ""));
    const active = document.activeElement;
    return { texts, hidden, disabled, buttons, screens, lines, queue, unnamed, path: location.pathname, hash: location.hash, focus: active.id || active.className || active.tagName };
  });
  return { ...dom, posts: S.posts };
}
async function handle(m, S) {
  const page = S.page;
  if (m.op === "navigate") {
    if (S.context) await S.context.close();
    browser ??= chromium.launch({ executablePath, headless: true, args: ["--disable-gpu", "--disable-extensions", "--disable-background-networking", "--disable-component-update", "--disable-features=site-per-process,IsolateOrigins,msEdgeCollections,EdgeCollections,msEntityExtraction,EdgeEntityExtraction,msEdgeEntityExtraction,msExtractor,EntityExtraction", "--renderer-process-limit=1", "--in-process-gpu", "--disable-breakpad", "--disable-software-rasterizer", "--disable-sync", "--disable-crash-reporter", "--noerrdialogs"] }).catch((error) => { browser = null; throw error; });  // fewer processes, same page; a failed launch is not cached
    S.context = await (await browser).newContext({ locale: "en-US", ...(m.width ? { viewport: { width: m.width, height: 800 } } : {}) });
    const page = S.page = await S.context.newPage();
    const t0 = Date.now(); await page.clock.install({ time: t0 }); await page.clock.pauseAt(t0 + 10000);  // page time is paused: only "tick" fires the 15 s read poll, never machine load
    S.pending = new Set();
    S.diagnostics = [];
    S.pageErrors = [];
    S.posts = [];
    page.on("request", (request) => {
      S.pending.add(request);
      S.changedAt = Date.now();
      if (request.method() === "POST") S.posts.push({ url: request.url(), body: request.postData() });
    });
    const finished = (request) => { S.pending.delete(request); S.changedAt = Date.now(); };
    page.on("requestfinished", finished);
    page.on("requestfailed", finished);
    page.on("pageerror", (error) => S.pageErrors.push(String(error)));
    page.on("console", (message) => {
      if (["warning", "error"].includes(message.type())) S.diagnostics.push({ type: message.type(), text: message.text() });
    });
    const response = await page.goto("http://127.0.0.1:" + m.port + (m.path || "/"));
    await settle(S);
    return { html: await response.text(), view: await view(S) };
  }
  if (m.op === "post") {
    return page.evaluate(async ({ path, body, role }) => {
      const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-Staff-Role": role }, body: JSON.stringify(body) });
      return { status: response.status, body: await response.json() };
    }, m);
  }
  if (m.op === "close") {
    if (browser) await (await browser).close();
    browser = null;
    return { closed: true };
  }
  if (m.op === "download") {  // a link found by role and name, clicked; the file the browser saved
    const [file] = await Promise.all([page.waitForEvent("download"), page.getByRole("link", { name: m.name, exact: true }).click()]);
    return { filename: file.suggestedFilename(), data: require("fs").readFileSync(await file.path()).toString("base64") };
  }
  if (m.op === "role") {  // a control found by its ARIA role and accessible name, or by a CSS selector
    const control = m.selector ? page.locator(m.selector) : page.getByRole(m.role, { name: m.name ?? undefined, exact: true });
    if (m.act === "find") {
      const found = await control.count();
      const text = found ? await control.first().textContent() : "";
      return { found, text, visible: found ? await control.first().isVisible() : false, disabled: found ? await control.first().isDisabled() : null, checked: found && m.role === "radio" ? await control.first().isChecked() : null, view: await view(S) };
    }
    await control.first()[m.act](...(m.text == null ? [] : [m.text]));
  } else if (m.op === "click") {
    await page.locator("#" + m.id).click();
  } else if (m.op === "key") {
    await page.keyboard.press(m.key);
  } else if (m.op === "tick") {
    await page.clock.fastForward(15000);
  } else if (["action", "begin-action"].includes(m.op)) {
    const ready = async (locator) => await locator.count() && await locator.first().isEnabled();
    const decision = Boolean(SHEET[m.name]);
    if (decision) {  // the decision form: choose, record, then confirm
      const radio = page.getByRole("radio", { name: SHEET[m.name], exact: true });
      if (await ready(radio)) {
        await radio.check();
        await page.locator("#record-btn").click();
      }
    } else {
      const button = page.locator('[data-action="' + m.name + '"]');
      if (await ready(button)) await button.click();
      else return { clicked: false };
    }
    if (decision || m.name === "record-cash") {  // the two money actions ask once more
      if (!await ready(page.locator("#confirm"))) return { clicked: false };
      await page.locator("#confirm").click();
    }
  } else if (m.op !== "view") throw new Error("unknown_op:" + m.op);
  if (m.op !== "begin-action" && m.wait !== false) await settle(S);
  return { clicked: true, view: await view(S) };
}
const queues = new Map();  // one queue per session: its steps stay in order, other sessions run beside it
const input = readline.createInterface({ input: process.stdin });
input.on("line", (line) => {
  const m = JSON.parse(line);
  if (!sessions.has(m.sid)) sessions.set(m.sid, { context: null, page: null, changedAt: 0, pending: new Set(), diagnostics: [], pageErrors: [], posts: [] });
  const S = sessions.get(m.sid);
  queues.set(m.sid, (queues.get(m.sid) || Promise.resolve()).then(async () => {
    let reply;
    try {
      reply = { ok: true, ...(await handle(m, S)) };
    } catch (e) {
      reply = { ok: false, error: String(e && e.message ? e.message : e) };
    }
    reply.rid = m.rid;
    reply.diagnostics = S.diagnostics.splice(0);
    process.stdout.write(JSON.stringify(reply) + "\n");
  }));
});
input.on("close", () => {
  Promise.all(queues.values()).then(async () => {
    if (browser) await (await browser).close();
  }).catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
});
"""

class HarnessUnavailable(RuntimeError):
    """A prerequisite (Node, the pinned engine artifact) is absent."""

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
        def _respond(self, status: int, value: Any, content_type: str = "application/json; charset=utf-8", *, retry_after: bool = False) -> None:
            self._record["status"] = status
            super()._respond(status, value, content_type, retry_after=retry_after)
    return Metered

def _node_path() -> str:
    node = os.environ.get("RR_SCORECARD_NODE") or shutil.which("node")
    if not node:
        raise HarnessUnavailable("node_unavailable")
    return node

class _Browser:
    """One fresh browser tab for one role; tab() gives more pages of the same browser, replies matched by id."""
    def __init__(self, port: int, driver: Path) -> None:
        self._process = subprocess.Popen(
            [_node_path(), str(driver)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8", cwd=str(_ROOT),
        )
        self.port = port
        self.last_view: dict[str, Any] = {}
        self.sid, self._sids, self._ids = 0, itertools.count(1), itertools.count(1)
        self._lock, self._replies, self._eof = threading.Condition(), {}, False
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
    def _read(self) -> None:
        try:
            for line in self._process.stdout:
                reply = json.loads(line)
                with self._lock:
                    self._replies[reply.pop("rid")] = reply
                    self._lock.notify_all()
        finally:
            with self._lock:
                self._eof = True
                self._lock.notify_all()
    def tab(self) -> "_Browser":
        """Another page of this browser process, its own fresh context at every open; close the parent, not the tab."""
        tab = copy.copy(self)
        tab.sid, tab.last_view = next(self._sids), {}
        return tab
    def call(self, message: dict[str, Any]) -> dict[str, Any]:
        assert self._process.stdin
        mid = next(self._ids)
        with self._lock:
            self._process.stdin.write(json.dumps({**message, "rid": mid, "sid": self.sid}) + "\n")
            self._process.stdin.flush()
            self._lock.wait_for(lambda: mid in self._replies or self._eof)
            reply = self._replies.pop(mid, None)
        if reply is None:
            raise RuntimeError("browser_driver_exited:" + (self._process.stderr.read() if self._process.stderr else "")[-2000:])
        for diagnostic in reply.pop("diagnostics", []):
            sys.stdout.write("BROWSER_DIAGNOSTIC=" + json.dumps(diagnostic, sort_keys=True) + "\n")  # one write per line: worker threads never splice lines
            sys.stdout.flush()
        if not reply.pop("ok"):
            raise RuntimeError("browser_driver:" + str(reply.get("error")))
        if "view" in reply:
            self.last_view = reply["view"]
        return reply
    def open(self, path: str = "/", width: int | None = None) -> None:
        self.call({"op": "navigate", "port": self.port, "path": path, "width": width})
    def click(self, element_id: str) -> None:
        self.call({"op": "click", "id": element_id})
    def action(self, name: str) -> bool:
        return bool(self.call({"op": "action", "name": name})["clicked"])
    def view(self) -> dict[str, Any]:
        return self.call({"op": "view"})["view"]
    def role(self, role: str | None, name: str | None = None, act: str = "find", text: str | None = None, selector: str | None = None) -> dict[str, Any]:
        """One control by ARIA role and accessible name, or by CSS selector: act is find, click, check or fill."""
        return self.call({"op": "role", "role": role, "name": name, "act": act, "text": text, "selector": selector})
    def download(self, name: str) -> tuple[str, bytes]:
        """Click the link with this accessible name; return the saved file's name and bytes."""
        reply = self.call({"op": "download", "name": name})
        return reply["filename"], base64.b64decode(reply["data"])
    def key(self, key: str) -> None:
        self.call({"op": "key", "key": key})
    def tick(self) -> None:
        """Let the page's 15-second read poll fire now."""
        self.call({"op": "tick"})
    def close(self) -> None:
        try:
            if self._process.poll() is None:
                self.call({"op": "close"})
        finally:
            if self._process.stdin:
                self._process.stdin.close()
            try:
                self._process.wait(timeout=30)
            except subprocess.TimeoutExpired as error:
                self._process.kill()
                self._process.wait()
                raise RuntimeError("browser_cleanup_timed_out") from error
            finally:
                self._reader.join(30)
                for stream in (self._process.stdout, self._process.stderr):
                    if stream:
                        stream.close()

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
    """One thing a person must see: a value and its context on one visible line of one scope (H or program)."""
    def __init__(self, name: str, scope: str, value: str, context: str) -> None:
        self.name, self.scope = name, scope
        self.value = re.compile(value)
        self.context = re.compile(context, re.IGNORECASE)
    def visible(self, lines: list[tuple[str, str]]) -> bool:
        return any(scope == self.scope and self.value.search(line) and self.context.search(line) for scope, line in lines)

def _money(cents: int) -> str:
    """Exact dollars and cents, with or without the "$" (the ledger is headed "in USD"); whole-dollar amounts may drop ".00"."""
    text = re.escape(f"{cents // 100:,}") + (r"(?:\.00)?" if cents % 100 == 0 else re.escape(f".{cents % 100:02d}"))
    return r"(?<![\d,.])\$?" + text + r"(?![\d,]|\.\d)"

def _words(code: str) -> str:
    """An Owner code as shown raw (CASE_OWNER) or in plain words (case owner)."""
    return "(?i:" + "[_ ]".join(re.escape(part) for part in code.split("_")) + ")"

def _utc(ms: int, fmt: str = "%Y-%m-%d") -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime(fmt)

def _program_time(ms: int, read_at: str) -> str:
    """An instant as the screen writes it: program zone and label, and the year only when it is not the snapshot's own as-of year. A fixed UTC-5 holds only in 2026 US daylight time, so any other instant fails by name."""
    if not 1772956800000 <= ms < 1793516400000:  # 2026-03-08 08:00 UTC to 2026-11-01 07:00 UTC
        raise RuntimeError(f"scorecard_program_time_outside_2026_us_daylight_time:{ms}")
    zone = timezone(timedelta(hours=-5))
    moment, as_of = datetime.fromtimestamp(ms / 1000, tz=zone), datetime.fromisoformat(read_at).astimezone(zone)
    return f"{moment.day} {moment:%b}{'' if moment.year == as_of.year else f' {moment.year}'} {moment:%H:%M} {_MODEL['time']['label']}"

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
        Fact("status", "H", r"\b" + _words(str(case["status"])) + r"\b", r"case|status"),
        Fact("owner", "H", _words(str(case["next_action_owner"])), r"owner"),
        Fact("amount_gap", "H", _money(int(package["obligation"]["shortfall_cents"])), r"shortfall|missing|gap|difference"),
        Fact("next_action", "H", next_value, next_context),
    ]

def _approver_facts(truth: dict[str, Any]) -> list[Fact]:
    package, read_at = truth["decision_package"], truth["workspace"]["read_at"]
    obligation = package["obligation"]
    claim = package["references"]["claims"]["items"][0]
    return [
        Fact("amount_owed", "H", _money(int(obligation["owed_cents"])), r"owed"),
        Fact("cash_received", "H", _money(int(obligation["received_cash_cents"])), r"cash|received"),
        Fact("offset_claimed", "H", _money(int(claim["amount_cents"])), r"offset|claim|adjust"),
        # No support flag in the package JSON; support is a Mirror source assessment.
        Fact("offset_support", "H", r"MISSING|[Nn]o support", r"support"),
        Fact("claim_status", "H", r"\b" + _words(str(claim["status"])) + r"\b", r"claim|offset"),
        Fact("adjustment_rule", "H", re.escape(str(package["control_pack"]["adjustment_rule_id"])), r"rule"),
        Fact("deadline", "H", re.escape(_program_time(int(package["case"]["due_at_ms"]), read_at)), r"due|deadline"),
    ]

def _director_facts(truth: dict[str, Any]) -> list[Fact]:
    summary, population = truth["workspace"]["summary"], truth["workspace"]["population"]
    return [
        Fact("population", "program", re.escape(f"{summary['obligation_count']} / {population['expected_count']}"), r"population"),
        Fact("total_owed", "program", _money(int(summary["owed_cents"])), r"owed"),
        Fact("cash_recorded", "program", _money(int(summary["received_cash_cents"])), r"cash|received"),
        Fact("program_shortfall", "program", _money(int(summary["shortfall_cents"])), r"shortfall|missing|gap"),
        Fact("open_items", "program", r"(?<![\d/$,.])" + str(int(summary["open_count"])) + r"(?![\d/,.])", r"open|attention|unresolved"),
    ]

def _auditor_facts(truth: dict[str, Any]) -> list[Fact]:
    package, read_at = truth["decision_package"], truth["workspace"]["read_at"]
    determination = package["current_determination"]
    evidence = (determination.get("supporting_evidence") or [{"evidence_id": "none"}])[0]
    evidence_id = evidence.get("evidence_id", "none") if isinstance(evidence, dict) else evidence
    decision = str(determination["decision"])
    obligation = package["obligation"]
    return [
        Fact("decision", "H", _words(decision), r"determination|decision"),
        Fact("decided_by_role", "H", _words(str(determination["actor_role"])), r"determination|decision|decided|role"),
        # The chronology row of the decision event also shows when it was decided.
        Fact("decided_at", "H", re.escape(_program_time(int(determination["decided_at_ms"]), read_at)), r"determination|decision|decided|" + re.escape(decision)),
        Fact("supporting_evidence", "H", re.escape(str(evidence_id)), r"evidence"),
        Fact("adjustment_rule", "H", re.escape(str(package["control_pack"]["adjustment_rule_id"])), r"rule"),
        Fact("chronology", "H", r"(?i:determin|offset[_ ]rejected|correction)", r"^\d+ \w+ (?:\d{4} )?\d\d:\d\d CT"),  # a row of the Activity list, which opens with its time; the Decision line, which ends with one, does not count
        Fact("cash_reconciles", "H", _money(int(obligation["received_cash_cents"])) + r".*" + _money(int(obligation["shortfall_cents"])), r"cash|received"),
    ]

_CONTINUITY_FACTS = (
    Fact("continuity_test_mode", "H", r"\bTEST\b", r"continuity"),
    Fact("package_equal", "program", r"equality: true|equal: true|matches", r"restore|continuity"),
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
    def _open_rows(self, view: dict[str, Any]) -> int:
        return _open_rows(view, int(self.truth()["workspace"]["summary"]["open_count"]))
    def _task(self, tag: str) -> "_Task":
        self.meter.tag = tag
        return _Task(self, tag)
    def run(self) -> None:
        with self._task("director.weekly_review") as task:
            task.open()
            task.answer(_director_facts(self.truth()))
            task.record("rows_to_add_by_hand", len(task.browser.last_view["queue"]) if task.unanswered else 0)
            task.record("rows_flagged_open", self._open_rows(task.browser.last_view))
        with self._task("analyst.monday_reconciliation") as task:
            task.open()
            task.record("rows_flagged_open", self._open_rows(task.browser.view()))
            task.answer(_analyst_facts(self.truth()))
        with self._task("approver.prepare_decision") as task:
            task.open()
            task.answer(_approver_facts(self.truth()))
            task.record("requests_to_prepare", task.request_count())
            task.command("reject-offset")
            task.record("requests_including_decision", task.request_count())
            if not self.truth()["decision_package"].get("current_determination"):
                raise RuntimeError("scorecard_decision_not_committed")
        with self._task("analyst.correction_followthrough") as task:
            task.open()
            task.ensure_record()
            for name in ("acknowledge", "record-cash", "record-report"):
                task.command(name)
            task.record("forced_package_reopens", 0)  # the record is already the package: nothing to reopen
            posts = [row for row in self.meter.rows(task.tag) if row["method"] == "POST" and row["path"] in ("/api/correction/record-cash", "/api/reporting/record")]
            task.record("evidence_resubmissions", len(posts) - len({json.dumps([row["path"], row["body"]], sort_keys=True) for row in posts}))
            self._cash_body = next(row["body"] for row in posts if row["path"] == "/api/correction/record-cash")
        self._repeat_message()
        with self._task("auditor.answer_auditor") as task:
            task.open()
            task.answer(_auditor_facts(self.truth()))
        with self._task("replacement.continue_from_continuity") as task:
            task.open()
            task.ensure_record()
            task.command("restore-test")
            task.answer(list(_CONTINUITY_FACTS) + _analyst_facts(self.truth()))
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
            reply = browser.call({"op": "post", "path": "/api/correction/record-cash", "role": "analyst", "body": self._cash_body})
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

def _open_rows(view: dict[str, Any], expected: int) -> int:
    """Queue rows not marked settled. The Owner's own open count must agree: a meter that cannot read, or disagrees with the ledger, fails the run instead of reporting a number."""
    rows = view["queue"]
    count = sum(1 for kind in rows if kind != "ok")
    if not rows or count != expected:
        raise RuntimeError(f"scorecard_open_rows_disagree:{count}!={expected}")
    return count

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
        self.screens.append("landing")
    def click(self, element_id: str, why: str) -> None:
        self.browser.click(element_id)
        self.step(f"click: {why}")
    def command(self, name: str) -> None:
        if not self.browser.action(name):
            raise RuntimeError("scorecard_command_unavailable:" + name)
        self.step("click: " + name)
        status = self.browser.last_view["texts"].get("command-status", "")
        # The declared success text (Art. XIII.4) is checked first: a control's own
        # wording (e.g. reject-offset's "You rejected the offset...") may legitimately use a
        # failure-shaped word, so only fall back to the denylist once it disagrees.
        expected = _MODEL["controls"][name]["responses"]["success"]["message"].replace("{amount}", "$3,000.00").split(".")[0]
        if not status or (expected not in status and any(word in status for word in ("rejected", "unresolved", "unavailable", "denied"))):
            raise RuntimeError(f"scorecard_command_failed:{name}:{status}")
    def ensure_record(self) -> None:
        """Open H's record from the queue unless it is already up."""
        if not self.browser.view()["screens"]["decision"]:
            self.click("row-item-h", "open H's record")
            self.screens.append("record")
    def answer(self, facts: list[Fact]) -> None:
        """Read the page as it opens; open H's record only if a fact is missing. Record the cost."""
        pending = list(facts)
        for screen in SCREEN_ORDER:
            if screen == "record" and (not pending or "record" in self.screens):
                continue
            if screen == "record":
                self.ensure_record()
            if screen not in self.screens:
                self.screens.append(screen)
            lines = [(line["scope"], line["text"]) for line in self.browser.view()["lines"]]
            for fact in list(pending):
                if fact.visible(lines):
                    self.found_on[fact.name] = screen
                    pending.remove(fact)
        self.unanswered = [fact.name for fact in pending]
        self.record("requests_to_answer", self.request_count())
        self.record("ui_actions_to_answer", self.ui_actions)
        self.record("screens_to_answer", len(self.screens))
        self.record("facts_only_in_raw_json", 0)  # the page has no raw-JSON screen: every fact is read on the page or is missing
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
    _node_path()
    with ExitStack() as stack:
        temp = lambda prefix: Path(stack.enter_context(tempfile.TemporaryDirectory(prefix=prefix))).resolve()  # noqa: E731
        owner_dir, driver_dir = temp("rr-scorecard-owner-"), temp("rr-scorecard-driver-")
        driver = driver_dir / "browser.js"
        driver.write_text(DRIVER_JS, encoding="utf-8")
        workflow = staff.StaffWorkflow(owner_dir)
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
            "path": "real loopback staff server over HTTP; real Edge DOM through Playwright; Owner + Mirror + pinned Lean correction release",
            "counting": "actual server-side requests, clicks and screens per role task; synthetic Owner clock; normal browser polling",
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
