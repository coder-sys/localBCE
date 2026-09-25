"""Exhaustive check of interaction-model.json (Art. XIII.4): the one declared
source of truth for screens, controls, and every response class. Walks it for
structural integrity (no dead control, orphan screen, trap, or illogical
path), then drives the real served page, role by role, with the felt-value
scorecard's own headless browser, confirming the DOM matches exactly.
"""

import json
import re
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

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
        start = owner_src.index("def reject_offset_and_authorize_correction")
        body = owner_src[start:owner_src.index("\n    def ", start + 40)]
        codes = set(re.findall(r'_fail\(\s*\w+\s*,\s*"([a-z_]+)"', body))
        codes |= set(re.findall(r'"[A-Z_]+":\s*\([A-Za-z]+,\s*"([a-z_]+)"\)', body))
        declared = set(_MODEL["controls"]["reject-offset"]["responses"])
        self.assertTrue(codes, "scanner found nothing: check the source has moved")
        missing = codes - declared
        self.assertFalse(missing, f"server can emit {missing} but the model does not name it")

class InteractionModelPageTests(unittest.TestCase):
    """The served page must offer exactly what the model declares, nothing else."""

    def test_action_grid_controls_match_the_model_exactly(self) -> None:
        served = set(re.findall(r'data-action="([a-z-]+)"', _HTML))
        declared = {name for name, control in _MODEL["controls"].items() if control["route"].startswith("POST")}
        self.assertEqual(served, declared)

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
        engine_dir = Path(cls.temp.name) / "engine-work"
        engine_dir.mkdir()
        cls.release = scorecard.financial_engine.load_correction_transition_release(scorecard.ENGINE_PATH.resolve(), engine_dir)
        cls.driver_path = Path(cls.temp.name) / "browser.js"
        cls.driver_path.write_text(scorecard.DRIVER_JS, encoding="utf-8")
        cls.browser = scorecard._Browser(0, cls.driver_path)
        cls.workflow, cls.server, cls.thread = cls._start_workflow(Path(cls.temp.name) / "owner")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._stop_workflow(cls.workflow, cls.server, cls.thread)
        cls.browser.close()
        cls.temp.cleanup()

    @classmethod
    def _start_workflow(cls, owner_dir: Path):
        """A fresh workflow + server on the same real engine release."""
        owner_dir.mkdir()
        workflow = scorecard.staff.StaffWorkflow(owner_dir, correction_transition_release=cls.release)
        server = scorecard.staff._LoopbackServer(("127.0.0.1", 0), scorecard.staff._handler_for(workflow))
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
        for role in _DECISION_ROLES:
            browser = self._open(role, server)
            browser.click("open-package")
            view = browser.view()
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
        expected = control["responses"][response]["message"]
        self.assertIn(expected.split(".")[0] if response == "success" else expected, status, f"{name}: {status}")

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
        markers = {n: (f'id="{n}"' if n in always_reachable else f'data-action="{n}"') for n in _MODEL["controls"]}
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

_JOURNEY = (("approver", "reject-offset"), ("analyst", "acknowledge"),
            ("analyst", "record-cash"), ("analyst", "record-report"))
_DECISION_ROLES = ("analyst", "approver", "auditor", "operator")

def _state(pkg: dict[str, Any], test_mode: bool) -> dict[str, Any]:
    action = pkg.get("current_action") or {}
    return {
        "reviewed": True, "command_pending": False, "test_mode": test_mode,
        "decided": pkg.get("current_determination") is not None,
        "action": SimpleNamespace(status=action.get("status")), "shortfall": pkg["obligation"]["shortfall_cents"],
        "reporting_complete": bool(pkg["obligation"]["reporting_complete"]),
    }

if __name__ == "__main__":
    unittest.main()
