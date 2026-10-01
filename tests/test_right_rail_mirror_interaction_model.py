"""Exhaustive check of interaction-model.json (Art. XIII.4): its structure (no dead control, orphan screen or trap), then the real page, role by role."""

import copy
import json
import re
import socket
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from app.right_rail_financial_owner import FinancialBusyError
from tools import right_rail_scorecard as scorecard

_WORKSPACE = Path(__file__).resolve().parents[1] / "app" / "staff_workspace"
_MODEL = json.loads((_WORKSPACE / "interaction-model.json").read_text(encoding="utf-8"))
_HTML = (_WORKSPACE / "index.html").read_text(encoding="utf-8")

class InteractionModelStructureTests(unittest.TestCase):
    def test_every_control_screen_role_and_response_target_is_declared(self) -> None:
        screens, roles = set(_MODEL["screens"]), set(_MODEL["roles"])
        for name, control in _MODEL["controls"].items():
            self.assertIn(control["screen"], screens, name)
            self.assertIn(control["leads_to"], screens, name)
            self.assertTrue(control["roles"], f"{name}: dead control, no role may use it")
            for role in control["roles"]:
                self.assertIn(role, roles, f"{name}/{role}")
            self.assertTrue(control["responses"], f"{name}: no declared response classes")
            for response, outcome in control["responses"].items():
                self.assertIn(outcome["screen"], screens, f"{name}/{response}")
                self.assertTrue(outcome["message"].strip(), f"{name}/{response}: no plain-language message")

    def test_every_role_screen_is_declared_and_not_a_trap(self) -> None:
        for role, screen_list in _MODEL["role_screens"].items():
            self.assertIn(role, _MODEL["roles"], role)
            for screen in screen_list:
                self.assertIn(screen, _MODEL["screens"], f"{role}/{screen}")
        reachable = {screen for screens in _MODEL["role_screens"].values() for screen in screens}
        for name, screen in _MODEL["screens"].items():
            if screen.get("entry"): continue
            self.assertIn(name, reachable, f"orphan screen: {name}")
            if not screen["home"]:
                self.assertIn(screen["back"], _MODEL["screens"], f"trap screen (no way back): {name}")

    def test_every_role_reaches_its_home_screen_with_some_control(self) -> None:
        for role, screens in _MODEL["role_screens"].items():
            homes = [s for s in screens if _MODEL["screens"][s]["home"]]
            self.assertEqual(homes, ["overview"], role)
            usable = [n for n, c in _MODEL["controls"].items() if role in c["roles"]]
            self.assertTrue(usable, f"{role}: no control reaches any screen (dead end)")

    def test_unavailable_responses_name_a_reload(self) -> None:
        for name, control in _MODEL["controls"].items():
            for response, outcome in control["responses"].items():
                if outcome["screen"] == "unavailable":
                    self.assertIn("reload", outcome["message"].lower(), f"{name}/{response}")

    def test_every_rejected_transition_code_is_named_in_the_model(self) -> None:
        """Every code the Lean correction-transition can reject with (Art. XIII.4.d)."""
        owner_src = (Path(__file__).resolve().parents[1] / "app" / "right_rail_financial_owner.py").read_text(encoding="utf-8")
        for method, control in (("reject_offset_and_authorize_correction", "reject-offset"), ("authorize_offset", "authorize-offset")):
            start = owner_src.index(f"def {method}")
            body = owner_src[start:owner_src.index("\n    def ", start + 40)]
            codes = set(re.findall(r'_fail\(\s*\w+\s*,\s*"([a-z_]+)"', body))
            codes |= set(re.findall(r'"[A-Z_]+":\s*\([A-Za-z]+,\s*"([a-z_]+)"\)', body))
            self.assertTrue(codes, "scanner found nothing: check the source has moved")
            missing = codes - set(_MODEL["controls"][control]["responses"])
            self.assertFalse(missing, f"{method} can emit {missing} but the model does not name it")

class InteractionModelPageTests(unittest.TestCase):
    def test_every_local_control_is_findable_and_every_decision_name_is_declared(self) -> None:
        for name, control in _MODEL["local_controls"].items():
            self.assertTrue(control["selector"] if "selector" in control else control["role"], name)
            self.assertTrue(control["visible_when"] and control["enabled_when"] and control["kind"], name)
        for radio in ("choose-accept", "choose-reject"):  # each outcome is one named radio leading to a declared control
            self.assertIn(_MODEL["local_controls"][radio]["target"], _MODEL["controls"])
        self.assertIn('href="#record"', _HTML)  # the skip link lands on the workspace region
        self.assertIn('id="record"', _HTML)

    def test_every_role_opens_a_record(self) -> None:
        for role, screens in _MODEL["role_screens"].items():
            self.assertIn("decision", screens, role)

class InteractionModelBrowserCrawlTests(unittest.TestCase):
    """Drive the real staff.js against the real server, one role at a time."""

    @classmethod
    def setUpClass(cls) -> None:
        if not scorecard.ENGINE_PATH.is_file():
            raise unittest.SkipTest("correction_engine_artifact_absent")
        scorecard._node_path()
        cls.temp = tempfile.TemporaryDirectory(prefix="rr-mirror-xiii-crawl-")
        cls.addClassCleanup(cls.temp.cleanup)
        (engine_dir := Path(cls.temp.name) / "engine-work").mkdir()
        cls.release = scorecard.financial_engine.load_correction_transition_release(scorecard.ENGINE_PATH.resolve(), engine_dir)
        cls.driver_path = Path(cls.temp.name) / "browser.js"
        cls.driver_path.write_text(scorecard.DRIVER_JS, encoding="utf-8")
        cls.browser = scorecard._Browser(0, cls.driver_path)
        cls.addClassCleanup(cls.browser.close)
        cls.workflow, cls.server, cls.thread = cls._start_workflow(Path(cls.temp.name) / "owner")
        cls.addClassCleanup(cls._stop_workflow, cls.workflow, cls.server, cls.thread)

    @classmethod
    def _start_workflow(cls, owner_dir: Path):
        owner_dir.mkdir()
        workflow = scorecard.staff.StaffWorkflow(owner_dir, correction_transition_release=cls.release)
        server = scorecard.staff._LoopbackServer(("127.0.0.1", 0), _response_handler(workflow))
        server.fault, server.fault_requests, server.rewrite = None, [], None
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        return workflow, server, thread

    @classmethod
    def _stop_workflow(cls, workflow, server, thread) -> None:
        server.shutdown()
        thread.join(30)
        server.server_close()
        workflow.close()

    def _open_path(self, path: str, server: Any = None) -> scorecard._Browser:
        self.browser.port = (server or self.server).server_address[1]
        self.browser.open(path)
        return self.browser

    def _open(self, role: str, server: Any = None) -> scorecard._Browser:
        """A fresh page on H's record: the address names the state, so it does not depend on the queue order."""
        return self._open_path(f"/role/{role}#item-h", server)

    def test_each_role_sees_exactly_its_declared_controls(self) -> None:
        for role in _MODEL["roles"]:
            view = self._open(role).view()
            visible = {name for name, button in view["buttons"].items() if not button["hidden"]}
            declared = {n for n, c in _MODEL["controls"].items() if role in c["roles"] and c["screen"] == "decision"}
            self.assertEqual(visible, declared, role)
            screens = view["screens"]
            self.assertEqual((screens["decision"], screens["overview"], screens["picker"]), (True, True, False), role)

    def test_no_role_in_the_path_shows_the_picker_not_the_workspace(self) -> None:
        view = self._open_path("/").view()
        self.assertTrue(view["screens"]["picker"] and not view["screens"]["overview"])

    def test_every_local_control_is_where_the_model_says_for_each_role(self) -> None:
        for role in (None, *_MODEL["roles"]):
            browser = self._open_path("/" if role is None else f"/role/{role}#item-h")
            ns = {"role": role, "phone": False, "decision_form": role == "approver", "confirming": False, "command_pending": False,
                  "unresolved_decision_body": False, "unresolved_cash_body": False, "picked": False}
            for name, control in _MODEL["local_controls"].items():
                with self.subTest(role=role, control=name):
                    found = browser.role(control.get("role"), control.get("name") or control.get("names", {}).get("idle"), selector=control.get("selector"))
                    self.assertEqual(bool(found["found"] and found["visible"]), eval(control["visible_when"], {"__builtins__": {}}, ns))
                    if found["found"] and found["visible"]:
                        self.assertEqual(not found["disabled"], eval(control["enabled_when"], {"__builtins__": {}}, ns))

    def test_a_phone_shows_one_pane_at_a_time_and_always_a_way_back(self) -> None:
        browser = self.browser
        browser.port = self.server.server_address[1]
        panes = lambda: [n for n in ("queue", "record") if not browser.view()["hidden"].get(n)]  # noqa: E731
        back = lambda: browser.role(None, selector="a.back", act="click")  # noqa: E731
        for role, first in (("approver", ["queue"]), ("director", ["record"])):  # the director lands on the program's totals
            with self.subTest(role=role):
                browser.open(f"/role/{role}", width=390)
                self.assertEqual(panes(), first)
                if first == ["record"]:
                    self.assertEqual(browser.role(None, selector="a.back")["visible"], True)
                    back()
                    self.assertEqual(panes(), ["queue"])
                browser.click("row-item-h")
                self.assertEqual(panes(), ["record"])
                self.assertEqual(browser.role(None, selector="a.back")["visible"], True)
                back()
                self.assertEqual(panes(), ["queue"])

    def test_the_keyboard_alone_reaches_and_records_a_decision(self) -> None:
        browser = self._open_path("/role/approver")  # no fragment: it would move the tab starting point past the skip link
        browser.key("Tab")
        self.assertIn("sr-focus", browser.view()["focus"])  # the skip link is the first stop
        browser.key("Enter")
        self.assertEqual(browser.view()["focus"], "record")
        browser.key("2")
        self.assertTrue(browser.role("radio", "Reject the offset")["checked"])
        self.assertEqual(browser.view()["focus"], "kind-reject-offset")
        browser.key("Control+Enter")
        self.assertTrue(browser.role("button", "Back")["found"])  # confirm step reached without the mouse
        browser.key("Escape")
        self.assertFalse(browser.role("button", "Back")["found"])
        self.assertEqual(browser.last_view["posts"], [])
        browser.key("j")
        self.assertNotEqual(browser.view()["hash"], "#item-h")  # moved to the next obligation

    def test_the_plain_text_view_says_what_the_screen_says(self) -> None:
        """At every stage of H's journey every line on the record also appears in its plain-text view."""
        workflow, server, thread = self._start_workflow(Path(self.temp.name) / "owner-plain-text")
        squash = lambda text: re.sub(r"[^0-9A-Za-z]", "", text)  # noqa: E731
        def compare(role: str) -> None:
            screen = [line["text"] for line in self._open(role, server).view()["lines"] if line["where"] == "page"]
            screen = [line for line in (_PROGRAM_TIME.sub("", line).strip() for line in screen) if line]  # an instant's two conventions are compared in their own test
            text = squash(" ".join(line["text"] for line in self._open_path(f"/role/{role}#item-h.txt", server).view()["lines"] if line["where"] == "page"))
            self.assertTrue(screen and len(screen) > 10, role)
            self.assertEqual([line for line in screen if squash(line) not in text], [], role)
        try:
            compare("approver")
            for role, step in _JOURNEY:
                self._run_step(workflow, server, role, step)
                compare(role)
            compare("auditor")
        finally:
            self._stop_workflow(workflow, server, thread)

    def test_every_role_downloads_the_record_byte_for_byte_at_every_stage(self) -> None:
        """M5, roles able to download the record: 0 of 5 before (no download existed), 5 of 5 now, at every stage of H's journey and for a settled item; the file is the plain-text record itself, the same bytes for every role (the on-page view adds only the role's own decision and next-step sections)."""
        workflow, server, thread = self._start_workflow(Path(self.temp.name) / "owner-download")
        link, able, same = _MODEL["local_controls"]["download-record"]["name"], set(), {}

        def check(stage: str) -> None:
            for role in _MODEL["roles"]:
                for item in ("item-h", "item-01"):
                    with self.subTest(stage=stage, role=role, item=item):
                        found = self._open_path(f"/role/{role}#{item}", server).role("link", link)
                        self.assertEqual((found["found"], found["visible"], found["disabled"]), (1, True, False))
                        name, data = self.browser.download(link)
                        shown = self._open_path(f"/role/{role}#{item}.txt", server).view()["texts"]["text-view"]
                        neutral = re.sub(r"\n\n(?:YOUR DECISION|NEXT STEPS)\n.*?(?=\n\n|\Z)", "", shown, flags=re.S)
                        self.assertEqual((name, data), (f"record-{item}.txt", neutral.encode("utf-8")))
                        self.assertEqual(same.setdefault((stage, item), data), data)  # role-neutral: one record, whoever downloads it
                        self.assertTrue(data.startswith(b"OBLIGATION") and "−".encode() in data)  # a real file, non-ASCII bytes intact
                        able.add(role)
        try:
            check("start")
            for role, step in _JOURNEY:
                self._run_step(workflow, server, role, step)
                check(step)
        finally:
            self._stop_workflow(workflow, server, thread)
        self.assertEqual(able, set(_MODEL["roles"]))

    def test_the_screen_writes_instants_in_program_time_and_the_record_in_utc(self) -> None:
        """M5, one time convention: every instant on the screen, the due date included, is the Owner's instant in the program's zone with its label and no calendar date is left; the record keeps the same instants in UTC, newest first; the engine's detail stays in the record."""
        self.assertEqual((_MODEL["time"]["zone"], _MODEL["time"]["label"]), ("America/Chicago", "CT"))
        workflow, server, thread = self._start_workflow(Path(self.temp.name) / "owner-time")
        try:
            for role, step in _JOURNEY:
                self._run_step(workflow, server, role, step)
            view = workflow.decision_view()  # the Owner's instants, not the page's text
            decided, due = (int(view["decision_package"]["current_determination"]["decided_at_ms"]), int(view["decision_package"]["case"]["due_at_ms"]))
            events = [int(event["committed_at_ms"]) for event in sorted(view["timeline"], key=lambda event: -event["event_sequence"])]
            self.assertGreater(len(events), 4)
            self.assertGreater(decided, due, "H is decided after it was due: the screen must not make it look early")
            utc = lambda ms: datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")  # noqa: E731
            for role in _MODEL["roles"]:
                with self.subTest(role=role):
                    page = " ".join(line["text"] for line in self._open(role, server).view()["lines"] if line["where"] == "page")
                    record = self._open_path(f"/role/{role}#item-h.txt", server).view()["texts"]["text-view"]
                    self.assertEqual(sorted(_PROGRAM_TIME.findall(page)), sorted(scorecard._program_time(ms) for ms in [due, decided, *events]))
                    self.assertIn("Due: " + scorecard._program_time(due), page)
                    self.assertIsNone(re.search(r"\d{4}-\d\d-\d\d", page), page)
                    self.assertEqual(_UTC_TIME.findall(record), [utc(ms) for ms in [decided, *events, due]])
                    self.assertFalse(any(word in page for word in ("UTC", "Owner event", "revision")), page)
                    self.assertTrue("Owner event" in record and "revision" in record)
        finally:
            self._stop_workflow(workflow, server, thread)

    def test_the_director_lands_on_the_totals_and_opens_any_record_from_the_queue(self) -> None:
        browser = self._open_path("/role/director")
        self.assertFalse(browser.view()["screens"]["decision"])
        self.assertTrue(any(line["text"].startswith("Total owed") for line in browser.last_view["lines"]))
        browser.click("row-item-h")
        self.assertTrue(browser.view()["screens"]["decision"])
        self.assertEqual(browser.role("link", "Download record")["found"], 1)
        self.assertEqual(browser.role("button", "Record decision")["found"], 0)  # a record to read, nothing to decide

    def test_clicking_each_navigation_control_leads_where_the_model_says(self) -> None:
        """The real-browser crawl of every declared navigation control, as every role; a control added to the model with no expectation here fails."""
        controls = _MODEL["local_controls"]
        elsewhere = {"choose-accept", "choose-reject", "record-decision", "back-from-confirm", "back-to-queue"}  # the decision tests and the phone test click these
        pickers = {name for name in controls if name.startswith("choose-") and "selector" in controls[name]}
        crawled = {"skip-workspace", "switch-role", "open-record", "summary-link", "filter", "plain-text", "download-record"}
        self.assertEqual(set(controls), pickers | crawled | elsewhere)

        def act(browser, name, how="click", text=None):
            control = controls[name]
            return browser.role(control.get("role"), control.get("name"), how, text, control.get("selector"))
        for name in sorted(pickers):
            with self.subTest(control=name):
                browser = self._open_path("/")
                act(browser, name)
                self.assertEqual(browser.view()["path"], controls[name]["target"])
        for role in _MODEL["roles"]:
            with self.subTest(role=role):
                browser = self._open_path(f"/role/{role}")
                act(browser, "skip-workspace")
                self.assertEqual(browser.view()["focus"], "record")
                act(browser, "summary-link")
                self.assertEqual(browser.view()["hash"], "#summary")
                self.assertTrue(any(line["text"].startswith("Total owed") for line in browser.last_view["lines"]))
                act(browser, "open-record")
                self.assertEqual((browser.view()["hash"], browser.last_view["screens"]["decision"]), ("#item-h", True))
                act(browser, "plain-text")
                self.assertEqual(browser.view()["hash"], "#item-h.txt")
                self.assertTrue(browser.last_view["texts"]["text-view"])
                act(browser, "plain-text")
                self.assertEqual(browser.view()["hash"], "#item-h")
                self.assertNotIn("text-view", browser.last_view["texts"])
                act(browser, "filter", "fill", "no such obligation")
                self.assertIn("No obligation matches", browser.view()["texts"]["qlist"])
                act(browser, "filter", "fill", "")
                self.assertNotIn("No obligation matches", browser.view()["texts"]["qlist"])
                act(browser, "switch-role")
                self.assertEqual((browser.view()["path"], browser.last_view["screens"]["picker"]), ("/", True))

    def _check_state(self, pkg: dict[str, Any], test_mode: bool, server: Any = None) -> None:
        ns = _state(pkg, test_mode)
        for role in _MODEL["roles"]:
            self._check_buttons(self._open(role, server).view(), role, ns)

    def _check_buttons(self, view, role, ns) -> None:
        for name, control in _MODEL["controls"].items():
            if control["screen"] != "decision":
                continue
            button = view["buttons"].get(name)
            if role not in control["roles"]:
                self.assertTrue(button is None or button["hidden"], f"{role}/{name}"); continue
            self.assertIsNotNone(button, f"{role}/{name}")
            self.assertFalse(button["hidden"], f"{role}/{name}")
            self.assertEqual(not button["disabled"], eval(control["enabled_when"], {"__builtins__": {}}, ns), f"{role}/{name}: state={ns}")

    def _run_step(self, workflow, server, role: str, name: str, response: str = "success", before_click=None) -> None:
        control = _MODEL["controls"][name]
        browser = self._open(role, server)
        if before_click is not None:
            before_click()
        self.assertTrue(browser.action(name), f"{name}: enabled but not clickable")
        status = browser.last_view["texts"].get("command-status", "")
        expected = _say(control["responses"][response]["message"])
        self.assertIn(expected.split(". ")[0].rstrip(".") if response == "success" else expected, status, f"{name}: {status}")

    def _walk(self, workflow, server, sequence, position=None) -> None:
        truth = lambda: workflow.decision_view()["decision_package"]  # noqa: E731
        test_mode = cash_recorded = False
        self._check_state(truth(), test_mode, server)
        for role, name in sequence:
            self._run_step(workflow, server, role, name)
            if name == "restore-test":
                if not cash_recorded:
                    self.assertGreater(truth()["obligation"]["shortfall_cents"], 0, f"position={position}: restore-test must be proven while H's shortfall is still open")
                test_mode = True
            cash_recorded = cash_recorded or name == "record-cash"
            self._check_state(truth(), test_mode, server)

    def test_walk_every_reachable_state_and_transition(self) -> None:
        self._walk(self.workflow, self.server, _JOURNEY)

    def test_restore_test_at_every_position_still_completes_the_journey(self) -> None:
        """restore-test is the only non-linear control (Art. XIII.4): at every position, every later step and state still matches the model."""
        for position in range(len(_JOURNEY) + 1):
            with self.subTest(restore_test_position=position):
                sequence = _JOURNEY[:position] + (("operator", "restore-test"),) + _JOURNEY[position:]
                workflow, server, thread = self._start_workflow(Path(self.temp.name) / f"owner-restore-at-{position}")
                try:
                    self._walk(workflow, server, sequence, position)
                finally:
                    self._stop_workflow(workflow, server, thread)

    def test_stale_revision_conflict_shows_the_declared_message_on_every_command(self) -> None:
        """A stale snapshot (Art. XIII.4.d) on every command shows the model's own per-control words, not a raw code."""
        owner_dir = Path(self.temp.name) / "owner-stale-probe"
        workflow, server, thread = self._start_workflow(owner_dir)
        probe = [0]

        def make_stale() -> None:
            probe[0] += 1
            workflow.mirror.owner.record_support_evidence(item_id=scorecard.staff.H_ITEM_ID, evidence_id=f"evidence:stale-probe:{probe[0]}", common_origin_id=f"origin:stale-probe:{probe[0]}")

        def check_stale(role: str, name: str) -> None:
            with self.subTest(control=name):
                self._run_step(workflow, server, role, name, "obligation_revision_conflict", make_stale)

        table = (("operator", "restore-test", False), ("approver", "reject-offset", True),
                 ("analyst", "acknowledge", True), ("analyst", "record-cash", True), ("analyst", "record-report", False))
        try:
            for role, name, advance in table:
                check_stale(role, name)
                if advance:
                    self._run_step(workflow, server, role, name)
        finally:
            self._stop_workflow(workflow, server, thread)

    def test_a_busy_store_keeps_the_exact_body_for_retry(self) -> None:
        """store_busy with changed:false recorded nothing; after a commit the answer is uncertain and the held body is retried."""
        workflow, server, thread = self._start_workflow(Path(self.temp.name) / "owner-busy")
        real = workflow.reject_offset_and_authorize_correction

        def busy_after(commit):
            def command(body):
                del workflow.reject_offset_and_authorize_correction  # busy once
                if commit:
                    real(body)
                raise FinancialBusyError("store_busy")
            return command
        try:
            browser = self._open("approver", server)
            for commit, words in ((False, "nothing was saved"), (True, "can't confirm")):
                workflow.reject_offset_and_authorize_correction = busy_after(commit)
                self.assertTrue(browser.action("reject-offset"))
                self.assertIn(words, browser.last_view["texts"]["command-status"])
                self.assertEqual(browser.role("button", _say(_MODEL["local_controls"]["record-decision"]["names"]["retry"].replace("{verb}", "rejection")))["disabled"], False)  # the held body, offered again
            self.assertTrue(browser.action("reject-offset"))
            self.assertIn(_say(_MODEL["controls"]["reject-offset"]["responses"]["success"]["message"]).split(". ")[0], browser.last_view["texts"]["command-status"])
            self.assertEqual(workflow.decision_view()["decision_package"]["current_action"]["status"], "READY")
        finally:
            self._stop_workflow(workflow, server, thread)

    def test_a_lost_decision_answer_stays_retryable_after_moving_away_and_back(self) -> None:
        workflow, server, thread = self._start_workflow(Path(self.temp.name) / "owner-lost-navigate")
        route = _MODEL["controls"]["reject-offset"]["route"]
        retry = _say(_MODEL["local_controls"]["record-decision"]["names"]["retry"].replace("{verb}", "rejection"))
        try:
            browser = self._open("approver", server)
            server.fault = {"route": route, "code": "transport_failure", "commit": True}
            self.assertTrue(browser.action("reject-offset"))
            server.fault = None
            self.assertEqual(browser.role("button", retry)["disabled"], False)
            browser.key("j")
            self.assertNotEqual(browser.view()["hash"], "#item-h")
            browser.key("k")
            self.assertEqual(browser.view()["hash"], "#item-h")
            self.assertEqual(browser.role("button", retry)["disabled"], False)  # the held answer is still offered on return
            server.fault = {"route": route, "code": "success", "commit": True}
            browser.role("button", retry, "click")
            self.assertEqual(server.fault_requests[-1]["body"], server.fault_requests[0]["body"])  # the same decision, byte for byte
            self.assertTrue(browser.last_view["texts"]["command-status"].startswith(_say(_MODEL["controls"]["reject-offset"]["responses"]["success"]["message"])))
        finally:
            server.fault = None
            self._stop_workflow(workflow, server, thread)

    def test_a_confirm_step_whose_form_or_step_a_read_removed_is_dropped(self) -> None:
        """Another actor decides, or cash arrives, while a confirm shows: the next read drops it, and Escape then does nothing."""
        workflow, server, thread = self._start_workflow(Path(self.temp.name) / "owner-stale-confirm")

        def held_body(role: str, name: str) -> Any:  # the exact body the page would send, stopped before the Owner sees it
            server.fault = {"route": _MODEL["controls"][name]["route"], "code": "transport_failure"}
            self.assertTrue(self._open(role, server).action(name))
            server.fault = None
            return server.fault_requests[-1]["body"]

        try:
            decision = held_body("approver", "reject-offset")
            browser = self._open("approver", server)
            browser.key("2")
            browser.key("Control+Enter")
            self.assertEqual(browser.role("button", "Back")["found"], 1)
            workflow.command("reject_offset_and_authorize_correction", decision)  # someone else decides
            browser.tick()
            self.assertEqual((browser.role("button", "Back")["found"], browser.role(None, selector="#confirm")["found"]), (0, 0))
            browser.key("Escape")  # the driver fails on any page error
            self.assertEqual(browser.last_view["posts"], [])
            self._run_step(workflow, server, "analyst", "acknowledge")
            cash = held_body("analyst", "record-cash")
            browser = self._open("analyst", server)
            browser.role(None, selector='[data-action="record-cash"]', act="click")
            self.assertEqual(browser.role("button", "Back")["found"], 1)
            workflow.command("record_cash_correction", cash)  # the cash arrives elsewhere: the step is no longer offered
            browser.tick()
            self.assertEqual((browser.role("button", "Back")["found"], browser.role(None, selector="#confirm")["found"]), (0, 0))
            browser.key("Escape")
            self.assertEqual(browser.last_view["posts"], [])
        finally:
            server.fault = None
            self._stop_workflow(workflow, server, thread)

    def test_the_choose_keys_do_nothing_while_a_decision_is_being_confirmed(self) -> None:
        workflow, server, thread = self._start_workflow(Path(self.temp.name) / "owner-keys-confirm")
        confirm = _say(_MODEL["local_controls"]["record-decision"]["names"]["confirm"].replace("{verb}", "rejection"))
        try:
            browser = self._open("approver", server)
            browser.key("2")
            browser.key("Control+Enter")
            self.assertEqual(browser.role("button", confirm)["found"], 1)
            browser.key("1")
            self.assertEqual(browser.role("button", confirm)["found"], 1)
            self.assertEqual([browser.role("radio", name)["checked"] for name in ("Reject the offset", "Accept the offset")], [True, False])
            self.assertEqual(browser.last_view["posts"], [])
        finally:
            self._stop_workflow(workflow, server, thread)

    def test_the_key_legend_lists_only_keys_that_do_something_for_the_role(self) -> None:
        for role in _MODEL["roles"]:
            view = self._open(role).view()
            legend = view["texts"]["keys"]
            self.assertFalse(view["hidden"].get("keys"), role)
            self.assertTrue("move" in legend and "filter" in legend, role)
            self.assertEqual(("choose" in legend, "record" in legend), (role == "approver",) * 2, role)

    def test_the_page_says_only_what_the_read_says(self) -> None:
        """No name, payer or claim is in the page: labels appear as the server gives them, consequences follow from the claim and the shortfall, and the standing tag follows the read."""
        workflow, server, thread = self._start_workflow(Path(self.temp.name) / "owner-read-says")

        def claim(cents: int):
            def rewrite(value):
                value["h"]["decision_package"]["references"]["claims"]["items"][0]["amount_cents"] = cents
                return value
            return rewrite
        try:
            view = self._open("approver", server).view()
            shown = " ".join(line["text"] for line in view["lines"])
            self.assertIn("Synthetic recipient H", " ".join(line["text"] for line in view["lines"] if line["where"] == "queue"))
            self.assertTrue("the payer" in shown and not any(word in shown for word in ("Plan A", "Hospital", "Payer:")), shown)
            self.assertTrue(all(word in view["texts"]["standing"] for word in ("synthetic", "not for payment", "no PHI", "not production")))
            for cents, left in ((200000, "is still owed $1,000.00."), (400000, "is owed nothing more.")):  # the shortfall is $3,000.00
                server.rewrite = claim(cents)
                texts = self._open("approver", server).view()["texts"]
                self.assertEqual(texts["detail-authorize-offset"], f"The {_money(cents)} offset counts toward Synthetic recipient H's payment. Synthetic recipient H {left}")
                self.assertEqual(texts["detail-reject-offset"], "The payer must pay Synthetic recipient H $3,000.00. A correction request is recorded.")
            server.rewrite = lambda value: {**value, "summary": {**value["summary"], "production_usable": True}}
            self.assertNotIn("not production", self._open("approver", server).view()["texts"]["standing"])
        finally:
            self._stop_workflow(workflow, server, thread)

    def test_record_cash_follows_the_open_amount_not_the_balance(self) -> None:
        """R2: an acknowledged request with money still owed but less open than the payment (a state the demo never reaches; H is still short $3,000.00) keeps the button off and says why."""
        workflow, server, thread = self._start_workflow(Path(self.temp.name) / "owner-open-amount")

        def action(open_cents: int):
            def rewrite(value):
                value["h"]["decision_package"]["current_action"] = {"status": "ACKNOWLEDGED", "open_cents": open_cents, "payload_fields": {"amount_cents": 300000}}
                return value
            return rewrite
        try:
            self.assertGreater(workflow.decision_view()["decision_package"]["obligation"]["shortfall_cents"], 0)  # money is owed in both states below
            for open_cents, enabled in ((100000, False), (300000, True)):
                server.rewrite = action(open_cents)
                view = self._open("analyst", server).view()
                self.assertEqual(not view["buttons"]["record-cash"]["disabled"], enabled, open_cents)
                self.assertEqual(any("Requested $3,000.00, open $1,000.00." in line["text"] for line in view["lines"]), open_cents < 300000, open_cents)
            server.rewrite = action(100000)
            self.assertIn("open amount covers this payment", " ".join(line["text"] for line in self._open("analyst", server).view()["lines"]))
        finally:
            self._stop_workflow(workflow, server, thread)

    def test_the_decision_form_starts_empty_and_asks_before_it_records(self) -> None:
        """Every decision control, in every state it can be in before a decision, found by role and name only."""
        controls = _MODEL["local_controls"]
        names, hints = controls["record-decision"]["names"], controls["record-decision"]["hints"]
        workflow, server, thread = self._start_workflow(Path(self.temp.name) / "form-states")
        try:
            for role in ("analyst", "auditor", "operator", "director"):  # only the approver decides
                self.assertEqual(self._open(role, server).role("button", names["idle"])["found"], 0, role)
            browser = self._open("approver", server)
            for radio in ("choose-accept", "choose-reject"):
                found = browser.role("radio", controls[radio]["name"])
                self.assertEqual((found["found"], found["checked"], found["disabled"]), (1, False, False), radio)
            before = workflow.mirror.owner.export_continuity()
            record = lambda: browser.role("button", names["idle"])  # noqa: E731
            self.assertEqual((record()["disabled"], browser.last_view["texts"]["why-off"]), (True, hints["no_choice"]))  # nothing chosen: it says why, it does not send
            self.assertEqual(browser.role("textbox")["found"], 0)  # no reason field: nothing here would be sent or stored
            self.assertIn("does not store decision reasons", " ".join(line["text"] for line in browser.view()["lines"]))
            browser.role("radio", controls["choose-reject"]["name"], "check")
            self.assertFalse(record()["disabled"])
            browser.role("button", names["idle"], "click")
            confirm = _say(names["confirm"].replace("{verb}", "rejection"))  # the button names verb and amount
            self.assertEqual(browser.role("button", confirm)["found"], 1)
            browser.role("button", controls["back-from-confirm"]["name"], "click")
            self.assertEqual(browser.role("button", confirm)["found"], 0)
            self.assertTrue(browser.role("radio", controls["choose-reject"]["name"])["checked"])  # Back keeps the choice
            self.assertEqual(browser.last_view["posts"], [])
            self.assertEqual(workflow.mirror.owner.export_continuity(), before)
        finally:
            self._stop_workflow(workflow, server, thread)

    def test_each_outcome_takes_three_steps_and_a_page_gone_stale_is_told_to_review(self) -> None:
        controls = _MODEL["local_controls"]
        for outcome, (radio, verb) in {"reject-offset": ("choose-reject", "rejection"), "authorize-offset": ("choose-accept", "acceptance")}.items():
            with self.subTest(outcome=outcome):
                workflow, server, thread = self._start_workflow(Path(self.temp.name) / f"form-{outcome}")
                declared = _MODEL["controls"][outcome]["responses"]
                names = controls["record-decision"]["names"]
                try:
                    browser = self._open("approver", server)
                    browser.role("radio", controls[radio]["name"], "check")  # step 1: choose
                    browser.role("button", names["idle"], "click")  # step 2: record; step 3 is the confirm
                    self.assertEqual(browser.last_view["posts"], [])  # nothing sends before the confirm
                    workflow.mirror.owner.record_support_evidence(item_id=scorecard.staff.H_ITEM_ID, evidence_id="evidence:stale-form", common_origin_id="origin:stale-form")
                    browser.role("button", _say(names["confirm"].replace("{verb}", verb)), "click")  # on facts that have moved
                    self.assertEqual(browser.last_view["texts"]["command-status"], declared["obligation_revision_conflict"]["message"])
                    self.assertIsNone(workflow.decision_view()["decision_package"]["current_determination"])
                    browser.role("button", names["idle"], "click")  # the choice is kept: record and confirm again on the new facts
                    browser.role("button", _say(names["confirm"].replace("{verb}", verb)), "click")
                    self.assertTrue(browser.last_view["texts"]["command-status"].startswith(_say(declared["success"]["message"])))
                    self.assertEqual(browser.role("radio", controls[radio]["name"])["found"], 0)  # a finished decision cannot repeat
                    self.assertIn("Decided: offset", " ".join(line["text"] for line in browser.view()["lines"]))
                    self.assertEqual(workflow.decision_view()["decision_package"]["current_determination"]["decision"], _DECISIONS[outcome])
                    self.assertEqual(len(browser.last_view["posts"]), 2)
                finally:
                    self._stop_workflow(workflow, server, thread)

    def test_accepting_the_offset_walks_a_shorter_journey(self) -> None:
        workflow, server, thread = self._start_workflow(Path(self.temp.name) / "owner-accept-walk")
        try:
            self._walk(workflow, server, (("approver", "authorize-offset"), ("analyst", "acknowledge"), ("analyst", "record-report")))
            view = workflow.decision_view()["decision_package"]  # the end state: nothing is left waiting, the case is closed
            self.assertEqual((view["case"]["status"], view["obligation"]["shortfall_cents"]), ("RESOLVED", 0))
        finally:
            self._stop_workflow(workflow, server, thread)

    def test_accessibility_regressions_are_caught(self) -> None:
        """WCAG 2.1 AA guard (Art. XIII.3): names, aria-live and token contrast in both themes; the keyboard test is above."""
        css = (_WORKSPACE / "staff.css").read_text(encoding="utf-8")
        def palette(anchor: str) -> dict[str, str]:
            block = css[css.index(anchor):]; return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", block[:block.index("}")]))
        linear = lambda c: c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
        luminance = lambda h: 0.2126 * linear(int(h[1:3], 16) / 255) + 0.7152 * linear(int(h[3:5], 16) / 255) + 0.0722 * linear(int(h[5:7], 16) / 255)
        contrast = lambda fg, bg: (max(luminance(fg), luminance(bg)) + 0.05) / (min(luminance(fg), luminance(bg)) + 0.05)
        themes = {"light": palette(":root {"), "dark": palette("prefers-color-scheme: dark")}
        for theme, tokens in themes.items():
            for fg, bg, minimum in _MODEL["accessibility"]["contrast_pairs"]:
                with self.subTest(check="contrast", theme=theme, pair=f"{fg}/{bg}"):
                    self.assertGreaterEqual(contrast(tokens[fg], tokens[bg]), minimum)
        for region in _MODEL["accessibility"]["live_regions"]:
            with self.subTest(check="aria_live", region=region):
                self.assertRegex(_HTML, rf'id="{region}"[^>]*role="status"[^>]*aria-live="(polite|assertive)"', region)
        for role in _MODEL["roles"]:  # every control the browser shows has a name
            self.assertEqual(self._open(role).view()["unnamed"], [], role)

    def test_every_declared_role_control_response_over_real_http(self) -> None:
        """Negative replies test rendering at the HTTP boundary, not Owner refusal causes."""
        expected = {(role, name, code) for name, control in _MODEL["controls"].items()
                    for role in control["roles"] for code in control["responses"]}
        observed = set()
        for name, control in _MODEL["controls"].items():
            workflow, server, thread = self._start_workflow(Path(self.temp.name) / f"responses-{name}")
            try:
                self._prepare_command(workflow, server, name)
                for role in control["roles"]:
                    codes = [code for code in control["responses"] if code != "success"] + ["success"]
                    for code in codes:
                        with self.subTest(role=role, control=name, response=code):
                            browser = self._open(role, server)
                            before = workflow.mirror.owner.export_continuity()
                            package = workflow.decision_view()["decision_package"]
                            server.fault_requests.clear()
                            server.fault = None if code == "success" else {"route": control["route"], "code": code}
                            try:
                                self.assertTrue(browser.action(name)) if control["route"].startswith("POST") else browser.tick()  # else the page's own next read
                                view = browser.view()
                            finally:
                                server.fault = None
                            self._check_response(view, name, code)
                            if code != "success":
                                self.assertTrue(server.fault_requests, "injection did not reach the real HTTP handler")
                                self.assertEqual(workflow.mirror.owner.export_continuity(), before)
                            elif control["route"].startswith("POST"):
                                self._check_success(workflow, name, package)
                            browser.tick()  # unavailable recovers on the next real read, with no reload
                            self.assertTrue(browser.view()["screens"]["overview"])
                            self.assertTrue(browser.last_view["screens"]["decision"], role)
                            observed.add((role, name, code))
                            print("BROWSER_RESPONSE_CASE=" + json.dumps([role, name, code]), flush=True)
            finally:
                self._stop_workflow(workflow, server, thread)
        self.assertEqual(observed, expected)

    def _prepare_command(self, workflow, server, name) -> None:
        for role, step in _JOURNEY:
            if name not in {action for _, action in _JOURNEY} or step == name:
                return
            self._run_step(workflow, server, role, step)

    def _check_response(self, view, name, code) -> None:
        outcome = _MODEL["controls"][name]["responses"][code]
        self.assertTrue(view["screens"][outcome["screen"]], (name, code, view["screens"]))
        region = "connection-status" if name == "read" or outcome["screen"] == "unavailable" else "command-status"
        if code == "success":
            self.assertTrue(view["texts"][region].startswith(_say(outcome["message"])), view["texts"][region])
        else:
            self.assertEqual(view["texts"][region], outcome["message"])
        if outcome["screen"] == "unavailable":
            self.assertTrue(all(button["disabled"] for button in view["buttons"].values()))

    def _check_success(self, workflow, name, before) -> None:
        after = workflow.decision_view()["decision_package"]
        if name in ("reject-offset", "acknowledge"):
            self.assertEqual(after["current_action"]["status"], "READY" if name == "reject-offset" else "ACKNOWLEDGED")
        if name in _DECISIONS:
            self.assertEqual(after["current_determination"]["decision"], _DECISIONS[name])
        if name == "record-cash":
            self.assertEqual(after["obligation"]["received_cash_cents"] - before["obligation"]["received_cash_cents"], 300000)
            self.assertEqual(after["obligation"]["shortfall_cents"], 0)
        else:
            self.assertEqual(after["obligation"]["received_cash_cents"], before["obligation"]["received_cash_cents"])
        if name == "record-report":
            self.assertTrue(after["obligation"]["reporting_complete"])
        if name == "restore-test":
            self.assertEqual(after, before)
            self.assertEqual(workflow.continuity["mode"], "TEST")
        workflow.mirror.owner.verify_integrity()

    def test_pending_and_lost_responses_retain_exact_correction_and_cash_bodies(self) -> None:
        for name, role in (("reject-offset", "approver"), ("authorize-offset", "approver"), ("record-cash", "analyst")):
            for code in ("transport_failure", "owner_command_unavailable", "command_response_unverified", "store_busy_outcome_unknown"):
                with self.subTest(control=name, response=code):
                    workflow, server, thread = self._start_workflow(Path(self.temp.name) / f"lost-{name}-{code}")
                    release = threading.Event()
                    entered = threading.Event()
                    try:
                        self._prepare_command(workflow, server, name)
                        browser = self._open(role, server)
                        before = workflow.decision_view()["decision_package"]
                        server.fault = {"route": _MODEL["controls"][name]["route"], "code": code,
                                        "commit": True, "entered": entered, "release": release}
                        self.assertTrue(browser.call({"op": "begin-action", "name": name})["clicked"])
                        self.assertTrue(entered.wait(5), "command did not reach the HTTP boundary")
                        pending = browser.call({"op": "view", "wait": False})["view"]
                        ns = _state(before, False)
                        retry_flag = "unresolved_cash_body" if name == "record-cash" else "unresolved_decision_body"
                        ns.update(reviewed=False, command_pending=True, **{retry_flag: True})
                        self._check_buttons(pending, role, ns)
                        self.assertTrue(pending["disabled"]["confirm"])
                        release.set()
                        self._check_response(browser.view(), name, code)
                        server.fault = None
                        self._check_success(workflow, name, before)
                        committed = workflow.mirror.owner.export_continuity()
                        original = server.fault_requests[0]["body"]
                        browser.tick()
                        ns = _state(workflow.decision_view()["decision_package"], False)
                        ns.update(reviewed=False, **{retry_flag: True})
                        self._check_buttons(browser.view(), role, ns)
                        server.fault = {"route": _MODEL["controls"][name]["route"], "code": "success", "commit": True}
                        self.assertTrue(browser.action(name))
                        server.fault = None
                        self.assertEqual(server.fault_requests[-1]["body"], original)
                        self.assertEqual(workflow.mirror.owner.export_continuity(), committed)
                        self._check_response(browser.view(), name, "success")
                        print("BROWSER_EXACT_RETRY=" + json.dumps([name, code]), flush=True)
                    finally:
                        release.set()
                        server.fault = None
                        self._stop_workflow(workflow, server, thread)

_JOURNEY = (("approver", "reject-offset"), ("analyst", "acknowledge"),
            ("analyst", "record-cash"), ("analyst", "record-report"))
_DECISIONS = {"reject-offset": "OFFSET_REJECTED_CORRECTION_AUTHORIZED", "authorize-offset": "OFFSET_AUTHORIZED"}

_PROGRAM_TIME = re.compile(r"\d{1,2} [A-Z][a-z]{2} \d\d:\d\d CT")
_UTC_TIME = re.compile(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC")

def _money(cents: int) -> str:
    return f"${cents // 100:,}.{cents % 100:02d}"

def _say(message: str) -> str:
    """A declared message with the amount its page fills in (H's claim is $3,000.00)."""
    return message.replace("{amount}", "$3,000.00")

def _state(pkg: dict[str, Any], test_mode: bool) -> dict[str, Any]:
    action = pkg.get("current_action") or {}
    return {
        "reviewed": True, "command_pending": False, "test_mode": test_mode,
        "owner_available": True, "unresolved_decision_body": False, "unresolved_cash_body": False,
        "decided": pkg.get("current_determination") is not None,
        "action": SimpleNamespace(status=action.get("status"), open_cents=action.get("open_cents")), "shortfall": pkg["obligation"]["shortfall_cents"],
        "reporting_complete": bool(pkg["obligation"]["reporting_complete"]),
    }

def _response_handler(workflow):
    """Inject HTTP replies only; genuine success/commit still uses the real command path."""
    class Responses(scorecard.staff._handler_for(workflow)):
        def _inject(self) -> bool:
            fault = self.server.fault
            if not fault or fault["route"] != f"{self.command} {self.path}":
                return False
            if not self._allowed(mutation=self.command == "POST"):
                return False
            body = self._json_request() if self.command == "POST" else None
            self.server.fault_requests.append({"route": fault["route"], "body": body})
            if "entered" in fault:
                fault["entered"].set()
                if not fault["release"].wait(30):
                    raise RuntimeError("browser_fault_release_timeout")
            result = workflow.command(scorecard.staff._COMMAND_ROUTES[self.path], body) if fault.get("commit") else None
            code = fault["code"]
            if code == "transport_failure":
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
            elif code in ("fork_detected", "stale_read"):
                result = getattr(workflow, scorecard.staff._READ_ROUTES[self.path])()
                result["read_envelope"]["snapshot_id"] = "0" * 64
                self._respond(200, result)
            elif code == "command_response_unverified":
                self._respond(200, {"workspace": {}})
            elif code == "success":
                self._respond(200, result)
            else:
                self._respond(503, {"error": {"code": code}, "changed": None if code == "store_busy_outcome_unknown" else False})
            return True

        def _respond(self, status, value, *args, **kwargs) -> None:
            if self.path == "/api/workspace" and self.server.rewrite:  # a read the Owner did not send, to test what the page says of it
                value = self.server.rewrite(copy.deepcopy(value))
            super()._respond(status, value, *args, **kwargs)

        def do_GET(self) -> None:
            if not self._inject():
                super().do_GET()

        def do_POST(self) -> None:
            if not self._inject():
                super().do_POST()
    return Responses

if __name__ == "__main__":
    unittest.main()
