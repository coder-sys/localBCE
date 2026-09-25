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

from tests.test_right_rail_financial_acceptance import _correction_transition_test_release
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
            if screen.get("entry"):
                continue
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
        owner_dir = Path(cls.temp.name) / "owner"
        owner_dir.mkdir()
        release = _correction_transition_test_release(workspace=Path(cls.temp.name) / "engine-work")
        cls.workflow = scorecard.staff.StaffWorkflow(owner_dir, correction_transition_release=release)
        cls.server = scorecard.staff._LoopbackServer(("127.0.0.1", 0), scorecard.staff._handler_for(cls.workflow))
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        cls.thread.start()
        cls.driver_path = Path(cls.temp.name) / "browser.js"
        cls.driver_path.write_text(scorecard.DRIVER_JS, encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.thread.join(30)
        cls.server.server_close()
        cls.workflow.close()
        cls.temp.cleanup()

    def _open_path(self, path: str) -> scorecard._Browser:
        browser = scorecard._Browser(self.server.server_address[1], self.driver_path)
        self.addCleanup(browser.close)
        browser.open(path)
        return browser

    def _open(self, role: str) -> scorecard._Browser:
        return self._open_path(f"/role/{role}")

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


if __name__ == "__main__":
    unittest.main()
