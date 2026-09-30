"""Felt-value scorecard ratchet (CONSTITUTION Art. XII, XIII.5).

Reruns the Hospital H journey through the real staff server and staff.js and
fails if any measured unit is worse than docs/scorecard/hospital_h.json in its
direction. An improvement passes but is printed so the file gets rewritten with
`python tools/right_rail_scorecard.py --write`.
"""

import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest

from tools import right_rail_scorecard as scorecard

_ROWS = "".join(f'<a class="row"><span class="dot {"need" if n == 20 else "ok"}"></span></a>' for n in range(1, 21))
_PAGE = f'<!doctype html><p id="connection-status"></p><div id="qlist">{_ROWS}</div>'.encode()


class _Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(_PAGE)
    def log_message(self, *args):
        pass


class FeltValueScorecardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.measured = scorecard.measure()
        except scorecard.HarnessUnavailable as missing:
            raise unittest.SkipTest(f"scorecard not executed: {missing}")
        cls.committed = json.loads(scorecard.SCORECARD_PATH.read_text(encoding="utf-8"))

    def test_committed_card_is_current_and_honest(self):
        card = scorecard.build_scorecard(self.measured)
        self.assertEqual(self.committed["claims"], card["claims"])
        self.assertEqual([unit["id"] for unit in self.committed["units"]], [unit["id"] for unit in card["units"]])
        for unit in self.committed["units"]:
            self.assertTrue(unit["manual_before"]["evidence"].startswith(("assumption (source:", "unknown")), unit["id"])

    def test_no_measured_unit_got_worse(self):
        worse, better = [], []
        for unit in self.committed["units"]:
            was, now = unit["after"]["value"], self.measured["units"][unit["id"]]
            sign = 1 if unit["direction"] == "lower" else -1
            if sign * (now - was) > 0:
                worse.append(f"{unit['id']}: {was} -> {now} ({unit['role']}, {unit['moment']})")
            elif now != was:
                better.append(f"{unit['id']}: {was} -> {now}")
        if better:
            print("\nScorecard improved; rewrite docs/scorecard/hospital_h.json:\n  " + "\n  ".join(better))
        self.assertEqual(worse, [], "felt-value regression (Art. XII)")


class OpenRowMeterTest(unittest.TestCase):
    def test_a_page_with_one_open_row_reads_one(self):
        """The meter once read 0 on a page with 1 open row because its pattern stopped matching."""
        try:
            scorecard._node_path()
        except scorecard.HarnessUnavailable as missing:
            raise unittest.SkipTest(str(missing))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Page)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory() as directory:
            driver = Path(directory) / "browser.js"
            driver.write_text(scorecard.DRIVER_JS, encoding="utf-8")
            browser = scorecard._Browser(server.server_address[1], driver)
            try:
                browser.open()
                self.assertEqual(scorecard._open_rows(browser.view(), 1), 1)
            finally:
                browser.close()

    def test_a_meter_that_cannot_read_or_disagrees_with_the_ledger_fails(self):
        for queue, expected in (([], 0), (["ok"], 1), (["wait"], 0), (["ok", "need"], 2)):
            with self.assertRaises(RuntimeError):
                scorecard._open_rows({"queue": queue}, expected)

if __name__ == "__main__":
    unittest.main()
