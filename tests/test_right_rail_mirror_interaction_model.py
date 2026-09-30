"""Exhaustive check of interaction-model.json (Art. XIII.4): the one declared
source of truth for screens, controls, and every response class. Walks it for
structural integrity (no dead control, orphan screen, trap, or illogical
path), then drives the real served page, role by role, with the felt-value
scorecard's own headless browser, confirming the DOM matches exactly.
"""

import json
import re
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from app.right_rail_financial_owner import FinancialBusyError
from tools import right_rail_scorecard as scorecard

_WORKSPACE = Path(__file__).resolve().parents[1] / "app" / "staff_workspace"
_MODEL = json.loads((_WORKSPACE / "interaction-model.json").read_text(encoding="utf-8"))
_HTML = (_WORKSPACE / "index.html").read_text(encoding="utf-8")

class InteractionModelStructureTests(unittest.TestCase):
    """Static graph checks: every pathway the model declares is coherent."""

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
    """The served page must offer exactly what the model declares, nothing else."""

    def test_action_grid_controls_match_the_model_exactly(self) -> None:
        served = set(re.findall(r'data-action="([a-z-]+)"', _HTML))
        declared = {name for name, control in _MODEL["controls"].items() if control["screen"] == "decision"}
        self.assertEqual(served, declared)
        for radio in ("sheet-accept", "sheet-reject"):  # each outcome is one named radio leading to a declared control
            self.assertIn(_MODEL["local_controls"][radio]["target"], _MODEL["controls"])
            self.assertIn(_MODEL["local_controls"][radio]["name"], _HTML)

    def test_decision_screen_access_matches_the_open_package_gate(self) -> None:
        open_roles = set(_MODEL["controls"]["open-package"]["roles"])
        for role, screens in _MODEL["role_screens"].items():
            self.assertEqual("decision" in screens, role in open_roles, role)

class InteractionModelBrowserCrawlTests(unittest.TestCase):
    """Drive the real staff.js against the real server, one role at a time."""

    @classmethod
    def setUpClass(cls) -> None:
        if not scorecard.ENGINE_PATH.is_file():
            raise unittest.SkipTest("correction_engine_artifact_absent")
        scorecard._node_path()
        cls.temp = tempfile.TemporaryDirectory(prefix="rr-mirror-xiii-crawl-")
        cls.addClassCleanup(cls.temp.cleanup)
        engine_dir = Path(cls.temp.name) / "engine-work"
        engine_dir.mkdir()
        cls.release = scorecard.financial_engine.load_correction_transition_release(scorecard.ENGINE_PATH.resolve(), engine_dir)
        cls.driver_path = Path(cls.temp.name) / "browser.js"
        cls.driver_path.write_text(scorecard.DRIVER_JS, encoding="utf-8")
        cls.browser = scorecard._Browser(0, cls.driver_path)
        cls.addClassCleanup(cls.browser.close)
        cls.workflow, cls.server, cls.thread = cls._start_workflow(Path(cls.temp.name) / "owner")
        cls.addClassCleanup(cls._stop_workflow, cls.workflow, cls.server, cls.thread)

    @classmethod
    def _start_workflow(cls, owner_dir: Path):
        """A fresh workflow + server on the same real engine release."""
        owner_dir.mkdir()
        workflow = scorecard.staff.StaffWorkflow(owner_dir, correction_transition_release=cls.release)
        server = scorecard.staff._LoopbackServer(("127.0.0.1", 0), _response_handler(workflow))
        server.fault = None
        server.fault_requests = []
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
        return self._open_path(f"/role/{role}", server)

    @staticmethod
    def _cancel_sheet(browser: scorecard._Browser) -> None:
        """The sheet is modal: leave it by its own Cancel before touching the page behind."""
        if browser.last_view["screens"]["decide"]:
            browser.role("button", _MODEL["local_controls"]["sheet-cancel"]["name"], "click")

    def test_each_role_sees_exactly_its_declared_controls(self) -> None:
        for role in _MODEL["roles"]:
            view = self._open(role).view()
            visible = {name for name, button in view["buttons"].items() if not button["hidden"]}
            declared = {n for n, c in _MODEL["controls"].items() if role in c["roles"] and c["screen"] == "decision"}
            self.assertEqual(visible, declared, role)
            has_decision = "decision" in _MODEL["role_screens"][role]
            self.assertEqual(view["hidden"].get("workflow-section", False), not has_decision, role)
            self.assertTrue(view["hidden"].get("role-picker", False), role)
            self.assertFalse(view["hidden"].get("workspace-root", False), role)

    def test_no_role_in_the_path_shows_the_picker_not_the_workspace(self) -> None:
        view = self._open_path("/").view()
        self.assertFalse(view["hidden"].get("role-picker", False))
        self.assertTrue(view["hidden"].get("workspace-root", False))

    def _check_state(self, pkg: dict[str, Any], test_mode: bool, server: Any = None) -> None:
        ns = _state(pkg, test_mode)
        for role in _MODEL["roles"]:
            browser = self._open(role, server)
            browser.click("refresh-button")
            if role in _DECISION_ROLES:
                browser.click("open-package")
            self._check_buttons(browser.view(), role, ns)

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
        browser.click("open-package")
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
        """Linear journey, no restore-test: state must match the model throughout."""
        self._walk(self.workflow, self.server, _JOURNEY)

    def test_restore_test_at_every_position_still_completes_the_journey(self) -> None:
        """restore-test is the only non-linear control (Art. XIII.4): insert it at
        every position in a fresh journey and confirm every later step and
        enabled-state still matches the model, covering every reachable state."""
        for position in range(len(_JOURNEY) + 1):
            with self.subTest(restore_test_position=position):
                sequence = _JOURNEY[:position] + (("operator", "restore-test"),) + _JOURNEY[position:]
                workflow, server, thread = self._start_workflow(Path(self.temp.name) / f"owner-restore-at-{position}")
                try:
                    self._walk(workflow, server, sequence, position)
                finally:
                    self._stop_workflow(workflow, server, thread)

    def test_stale_revision_conflict_shows_the_declared_message_on_every_command(self) -> None:
        """One stale-snapshot failure (Art. XIII.4.d), every command: an
        unrelated support-evidence write moves the Owner behind the open
        page's back (it never mutates on conflict), then a click must show
        the model's own per-control words, not a raw code or another
        control's wording."""
        owner_dir = Path(self.temp.name) / "owner-stale-probe"
        workflow, server, thread = self._start_workflow(owner_dir)
        probe = [0]

        def make_stale() -> None:
            probe[0] += 1
            workflow.mirror.owner.record_support_evidence(
                item_id=scorecard.staff.H_ITEM_ID,
                evidence_id=f"evidence:stale-probe:{probe[0]}",
                common_origin_id=f"origin:stale-probe:{probe[0]}",
            )

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
        """store_busy with changed:false recorded nothing: say so and offer the same body again. A busy answer after
        the command committed is uncertain: the held body is retried and the Owner answers with what it recorded."""
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
            browser.click("open-package")
            for commit, words in ((False, "nothing was saved"), (True, "can't confirm")):
                workflow.reject_offset_and_authorize_correction = busy_after(commit)
                self.assertTrue(browser.action("reject-offset"))
                self.assertIn(words, browser.last_view["texts"]["command-status"])
                self.assertEqual(browser.role("button", "Check now")["disabled"], False)  # the held body, offered again
            self.assertTrue(browser.action("reject-offset"))
            self.assertIn(_say(_MODEL["controls"]["reject-offset"]["responses"]["success"]["message"]).split(". ")[0], browser.last_view["texts"]["command-status"])
            self.assertEqual(workflow.decision_view()["decision_package"]["current_action"]["status"], "READY")
        finally:
            self._stop_workflow(workflow, server, thread)

    def test_the_decide_sheet_starts_with_nothing_chosen_and_asks_before_it_records(self) -> None:
        """Every sheet control, in every state it can be in before a decision, found by role and name only."""
        controls = _MODEL["local_controls"]
        names, errors = controls["sheet-confirm"]["names"], controls["sheet-confirm"]["errors"]
        workflow, server, thread = self._start_workflow(Path(self.temp.name) / "sheet-states")
        try:
            for role in ("analyst", "auditor", "operator", "director"):  # only the approver decides
                self.assertEqual(self._open(role, server).role("button", "Decide Hospital H")["found"], 0, role)
            browser = self._open("approver", server)
            self.assertTrue(browser.role("button", "Decide Hospital H")["disabled"])  # nothing to decide on until the package is open
            browser.click("open-package")
            self.assertEqual(browser.role("dialog")["found"], 0)
            browser.role("button", "Decide Hospital H", "click")
            sheet = browser.role("dialog", "Decide Hospital H's $3,000.00 offset")
            self.assertEqual(sheet["found"], 1)
            for phrase in ("Evidence", "no supporting evidence", "Adjustment rule", "does not decide for you", "Your decision (required; nothing selected)"):
                self.assertIn(phrase, sheet["text"])
            for radio in ("sheet-accept", "sheet-reject"):
                found = browser.role("radio", controls[radio]["name"])
                self.assertEqual((found["found"], found["checked"], found["disabled"]), (1, False, False), radio)
            before = workflow.mirror.owner.export_continuity()
            self.assertEqual(browser.role("alert")["text"], "")
            browser.role("button", names["idle"], "click")  # nothing chosen: the button answers, it does not send
            self.assertEqual(browser.role("alert")["text"], errors["no_choice"])
            browser.role("radio", controls["sheet-accept"]["name"], "check")
            browser.role("button", _say(names["accept"]), "click")  # chosen, no reason
            self.assertEqual(browser.role("alert")["text"], errors["no_reason"])
            browser.role("radio", controls["sheet-reject"]["name"], "check")
            self.assertEqual(browser.role("button", _say(names["reject"]))["found"], 1)  # the button names verb and amount
            self.assertEqual(browser.last_view["posts"], [])
            self.assertEqual(workflow.mirror.owner.export_continuity(), before)
            browser.role("button", controls["sheet-cancel"]["name"], "click")
            self.assertEqual(browser.role("dialog")["found"], 0)
            browser.role("button", "Decide Hospital H", "click")
            self.assertFalse(browser.role("radio", controls["sheet-reject"]["name"])["checked"])  # a reopened sheet starts empty
        finally:
            self._stop_workflow(workflow, server, thread)

    def test_each_outcome_takes_three_steps_and_a_page_gone_stale_is_told_to_review(self) -> None:
        controls = _MODEL["local_controls"]
        for outcome, (radio, confirm) in {"reject-offset": ("sheet-reject", "reject"), "authorize-offset": ("sheet-accept", "accept")}.items():
            with self.subTest(outcome=outcome):
                workflow, server, thread = self._start_workflow(Path(self.temp.name) / f"sheet-{outcome}")
                declared = _MODEL["controls"][outcome]["responses"]
                button = _say(controls["sheet-confirm"]["names"][confirm])
                try:
                    browser = self._open("approver", server)
                    browser.click("open-package")
                    browser.role("button", "Decide Hospital H", "click")
                    browser.role("radio", controls[radio]["name"], "check")  # step 1: choose
                    browser.role("textbox", controls["sheet-reason"]["name"], "fill", "Plan A gave no approval reference.")  # step 2: reason
                    self.assertEqual(browser.last_view["posts"], [])  # neither step sends anything
                    workflow.mirror.owner.record_support_evidence(
                        item_id=scorecard.staff.H_ITEM_ID, evidence_id="evidence:stale-sheet", common_origin_id="origin:stale-sheet")
                    browser.role("button", button, "click")  # step 3 on facts that have moved
                    self.assertEqual(browser.role("alert")["text"], declared["obligation_revision_conflict"]["message"])
                    self.assertIn("(changed)", browser.role("dialog")["text"])
                    self.assertIsNone(workflow.decision_view()["decision_package"]["current_determination"])
                    browser.role("button", button, "click")  # the choice and reason are kept: confirm again on the new facts
                    self.assertTrue(browser.last_view["texts"]["command-status"].startswith(_say(declared["success"]["message"])))
                    self.assertEqual(browser.role("dialog")["found"], 0)
                    self.assertTrue(browser.role("button", "Decide Hospital H")["disabled"])  # a finished decision cannot repeat
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
        """WCAG 2.1 AA regression guard (Art. XIII.3): one table-driven test,
        no new framework, for names, aria-live, token contrast (both themes),
        and keyboard reachability in the real headless browser."""
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
        always_reachable = _MODEL["accessibility"]["always_reachable_controls"]
        markers = {n: (f'id="{n}"' if n in always_reachable else f'data-action="{n}"') for n, c in _MODEL["controls"].items() if c["screen"] != "decide"}
        self.assertRegex(_HTML, r'id="sheet-error"[^>]*role="alert"')  # sheet errors are announced
        for name, marker in markers.items():
            with self.subTest(check="accessible_name", control=name):
                start = _HTML.index(marker)
                self.assertRegex(_HTML[start:_HTML.index("</button>", start)], r">\s*\S", name)
        for region in _MODEL["accessibility"]["live_regions"]:
            with self.subTest(check="aria_live", region=region):
                self.assertRegex(_HTML, rf'id="{region}"[^>]*role="status"[^>]*aria-live="(polite|assertive)"', region)
        view = self._open("approver").view()
        for control_id in always_reachable:
            with self.subTest(check="keyboard_reachable", control=control_id):
                self.assertFalse(view["hidden"].get(control_id) or view["disabled"].get(control_id), control_id)

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
                            if control["screen"] in ("decision", "decide"):
                                browser.click("open-package")
                            before = workflow.mirror.owner.export_continuity()
                            package = workflow.decision_view()["decision_package"]
                            server.fault_requests.clear()
                            server.fault = None if code == "success" else {"route": control["route"], "code": code}
                            try:
                                if control["route"].startswith("POST"):
                                    self.assertTrue(browser.action(name))
                                else:
                                    browser.click(name)
                                view = browser.view()
                            finally:
                                server.fault = None
                            self._check_response(view, name, code)
                            if code != "success":
                                self.assertTrue(server.fault_requests, "injection did not reach the real HTTP handler")
                                self.assertEqual(workflow.mirror.owner.export_continuity(), before)
                            elif control["route"].startswith("POST"):
                                self._check_success(workflow, name, package)
                            self._cancel_sheet(browser)
                            browser.click("refresh-button")
                            self.assertTrue(browser.last_view["screens"]["overview"])
                            if role in _DECISION_ROLES:
                                browser.click("open-package")
                                self.assertTrue(browser.last_view["screens"]["decision"])
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
        region = ("connection-status" if name == "refresh-button" or outcome["screen"] == "unavailable"
                  else "package-staleness" if name == "open-package" and code == "success"
                  else "sheet-hint" if name == "decide" else "command-status")
        if code == "success":
            self.assertTrue(view["texts"][region].startswith(_say(outcome["message"])), view["texts"][region])
        else:
            self.assertEqual(view["texts"][region], outcome["message"])
        if outcome["screen"] == "unavailable":
            self.assertTrue(all(button["disabled"] for button in view["buttons"].values()))
            self.assertFalse(view["disabled"].get("refresh-button", False))

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
                        browser.click("open-package")
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
                        self.assertTrue(pending["disabled"]["refresh-button"])
                        release.set()
                        self._check_response(browser.view(), name, code)
                        server.fault = None
                        self._check_success(workflow, name, before)
                        committed = workflow.mirror.owner.export_continuity()
                        original = server.fault_requests[0]["body"]
                        self._cancel_sheet(browser)
                        browser.click("refresh-button")
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
_DECISION_ROLES = ("analyst", "approver", "auditor", "operator")

def _say(message: str) -> str:
    """A declared message with the amount its page fills in (H's claim is $3,000.00)."""
    return message.replace("{amount}", "$3,000.00")

def _state(pkg: dict[str, Any], test_mode: bool) -> dict[str, Any]:
    action = pkg.get("current_action") or {}
    return {
        "reviewed": True, "command_pending": False, "test_mode": test_mode,
        "owner_available": True, "unresolved_decision_body": False, "unresolved_cash_body": False,
        "decided": pkg.get("current_determination") is not None,
        "action": SimpleNamespace(status=action.get("status")), "shortfall": pkg["obligation"]["shortfall_cents"],
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

        def do_GET(self) -> None:
            if not self._inject():
                super().do_GET()

        def do_POST(self) -> None:
            if not self._inject():
                super().do_POST()
    return Responses

if __name__ == "__main__":
    unittest.main()
