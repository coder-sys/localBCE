"""The provider screen: the server agrees with api + fix_list on every vector, refuses hostile requests with fixed codes,
and the declared interaction model (Art. XIII.4) matches the page and has no dead control, orphan screen or trap."""

import http.client
import itertools
import json
import re
import socket
import threading
import unittest
from unittest import mock
from pathlib import Path

from provider_app.api import preflight_bytes
from provider_app.fix_list import fix_list
from provider_app import screen
from provider_app.screen import MAX_BODY, make_server
from tests.helpers import VECTORS, bundle_bytes, canonical_bytes, request_bytes

_DIR = Path(__file__).resolve().parents[1] / "screen"
_MODEL = json.loads((_DIR / "interaction-model.json").read_text(encoding="utf-8"))
_HTML = (_DIR / "index.html").read_text(encoding="utf-8")
_JS = (_DIR / "screen.js").read_text(encoding="utf-8")
_CSS = (_DIR / "screen.css").read_text(encoding="utf-8")
_MARK = "HOSTILE-MARKER-7"
_ROUTES = _MODEL["assets"] + ["/cases", "/check"]
_J = {"Content-Type": "application/json"}


def _holds(expression: str, **state: bool) -> bool:
    return bool(eval(expression, {"__builtins__": {}}, state))


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = make_server(0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def call(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            reply = conn.getresponse()
            return reply.status, reply.read()
        finally:
            conn.close()

    def test_binds_loopback_only(self) -> None:
        self.assertEqual("127.0.0.1", self.server.server_address[0])

    def test_server_outcome_and_fix_list_match_api_for_every_vector(self) -> None:
        status, raw = self.call("GET", "/cases")
        self.assertEqual(200, status)
        cases = json.loads(raw)
        self.assertEqual([c["id"] for c in VECTORS["cases"]], [c["id"] for c in cases])
        for vector, case in zip(VECTORS["cases"], cases):
            with self.subTest(vector["id"]):
                self.assertEqual(request_bytes(vector), canonical_bytes(case["request"]))
                self.assertEqual(bundle_bytes(vector), canonical_bytes(case["bundle"]))
                result = preflight_bytes(request_bytes(vector), bundle_bytes(vector))
                status, raw = self.call("POST", "/check", json.dumps({"request": case["request"], "bundle": case["bundle"]}).encode())
                self.assertEqual(200, status)
                fixes = [dict(zip(("rule", "citation", "fact", "text"), fix)) for fix in fix_list(result)]
                self.assertEqual({"outcome": vector["outcome"], "fixes": fixes}, json.loads(raw))
                self.assertEqual(json.loads(result)["outcome"], vector["outcome"])

    def test_hostile_requests_get_a_fixed_code_without_echo_and_the_server_stays_up(self) -> None:
        good = json.loads(self.call("GET", "/cases")[1])[0]
        req, bun = json.dumps(good["request"]), json.dumps(good["bundle"])
        marked_request = req.replace('"mode"', '"%s"' % _MARK)
        padded = '{"request":{"pad":"%s"},"bundle":%s}' % ("x" * 17000 + _MARK, bun)
        hostile = [  # method, path, body, headers, status, code (None: any fixed codec code)
            ("POST", "/check", b"{" + _MARK.encode(), _J, 400, "BODY_INVALID"),
            ("POST", "/check", b'{"request":"\xff' + _MARK.encode() + b'"}', _J, 400, "BODY_INVALID"),
            ("POST", "/check", json.dumps([_MARK]).encode(), _J, 400, "BODY_FIELDS_INVALID"),
            ("POST", "/check", json.dumps({"request": {}, "bundle": {}, _MARK: 1}).encode(), _J, 400, "BODY_FIELDS_INVALID"),
            ("POST", "/check", json.dumps({"request": {}}).encode(), _J, 400, "BODY_FIELDS_INVALID"),
            ("POST", "/check", ('{"request":{"a":1,"a":2},"bundle":%s}' % bun).encode(), _J, 400, "JSON_DUPLICATE_KEY"),
            ("POST", "/check", ('{"request":%s,"bundle":%s}' % (marked_request, bun)).encode(), _J, 400, None),
            ("POST", "/check", padded.encode(), _J, 400, None),
            ("POST", "/check", b"[" * 5000 + b"]" * 5000, _J, 400, "BODY_INVALID"),
            ("POST", "/check", b"x" * (MAX_BODY + 1), _J, 413, "BODY_TOO_LARGE"),
            ("POST", "/check", b"", {"Content-Length": str(MAX_BODY + 1)}, 413, "BODY_TOO_LARGE"),
            ("POST", "/check", b"", {"Content-Length": "-1"}, 400, "BODY_INVALID"),
            ("POST", "/check", b"", {"Content-Length": "x" + _MARK}, 400, "BODY_INVALID"),
            ("GET", "/check", None, {}, 405, "METHOD_NOT_ALLOWED"),
            ("POST", "/", b"{}", _J, 405, "METHOD_NOT_ALLOWED"),
            ("POST", "/cases", b"{}", _J, 405, "METHOD_NOT_ALLOWED"),
            ("PUT", "/check", b"{}", _J, 405, "METHOD_NOT_ALLOWED"),
            ("DELETE", "/", None, {}, 405, "METHOD_NOT_ALLOWED"),
            ("FOO", "/", None, {}, 501, "REQUEST_REFUSED"),
            ("GET", "/" + _MARK, None, {}, 404, "NOT_FOUND"),
            ("POST", "/" + _MARK, b"{}", _J, 404, "NOT_FOUND"),
            ("GET", "/../README.md", None, {}, 404, "NOT_FOUND"),
            ("GET", "/screen.css?" + _MARK, None, {}, 404, "NOT_FOUND"),
            ("GET", "/", None, {"Host": "evil.example"}, 421, "HOST_REFUSED"),
            ("POST", "/check", b"{}", {**_J, "Host": "evil.example:%d" % self.port}, 421, "HOST_REFUSED"),
            ("GET", "/cases", None, {"Host": "127.0.0.1"}, 421, "HOST_REFUSED"),
        ]
        for method, path, body, headers, status, code in hostile:
            with self.subTest(method=method, path=path[:20], body=(body or b"")[:20]):
                got_status, raw = self.call(method, path, body, headers)
                self.assertEqual(status, got_status)
                self.assertNotIn(_MARK.encode(), raw)
                error = json.loads(raw)["error"]
                self.assertEqual(code or error, error)
                self.assertRegex(error, r"^[A-Z_]+$")
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:  # no Content-Length at all
            sock.sendall(b"POST /check HTTP/1.0\r\nHost: 127.0.0.1:%d\r\n\r\n" % self.port)
            self.assertIn(b"BODY_INVALID", sock.makefile("rb").read())
        self.assertEqual(200, self.call("GET", "/")[0])
        self.assertEqual(200, self.call("POST", "/check", ('{"request":%s,"bundle":%s}' % (req, bun)).encode(), _J)[0])
        self.assertEqual(200, self.call("GET", "/", headers={"Host": "localhost:%d" % self.port})[0])
        with mock.patch.object(screen, "preflight_bytes", side_effect=RuntimeError(_MARK)):  # an internal fault
            status, raw = self.call("POST", "/check", ('{"request":%s,"bundle":%s}' % (req, bun)).encode(), _J)
        self.assertEqual((500, b'{"error":"CHECK_FAILED"}'), (status, raw))

    def test_every_declared_route_exists_and_every_outcome_is_declared(self) -> None:
        for path in _MODEL["assets"] + ["/cases"]:
            self.assertEqual(200, self.call("GET", path)[0], path)
        for control in _MODEL["controls"].values():
            if control["route"]:
                self.assertIn(control["route"].split()[1], _ROUTES, control["route"])
        self.assertEqual({c["outcome"] for c in VECTORS["cases"]}, set(_MODEL["outcomes"]))


class InteractionModelTests(unittest.TestCase):
    def graph(self) -> dict[str, set[str]]:
        edges = {name: set() for name in _MODEL["screens"]}
        for control in _MODEL["controls"].values():
            for screen in control["screens"]:
                edges[screen] |= {r["screen"] for r in control["responses"].values()}
        return edges

    @staticmethod
    def reach(start: str, edges: dict[str, set[str]]) -> set[str]:
        seen, todo = set(), [start]
        while todo:
            node = todo.pop()
            if node not in seen:
                seen.add(node)
                todo.extend(edges[node])
        return seen

    def test_every_target_is_declared_and_every_control_has_a_place_and_a_response(self) -> None:
        for name, control in _MODEL["controls"].items():
            self.assertTrue(control["screens"] and control["responses"], f"{name}: dead control")
            for screen in control["screens"] + [r["screen"] for r in control["responses"].values()]:
                self.assertIn(screen, _MODEL["screens"], name)
        for name, screen in _MODEL["screens"].items():
            if name != "answer":  # the answer's words are the outcomes' own
                self.assertTrue(screen["message"].strip(), f"{name}: no plain-language message")
        for name, outcome in _MODEL["outcomes"].items():
            self.assertTrue(outcome["word"].strip() and outcome["says"].strip(), name)

    def test_no_orphan_screen_and_no_trap(self) -> None:
        edges = self.graph()
        entries = [n for n, s in _MODEL["screens"].items() if s.get("entry")]
        homes = [n for n, s in _MODEL["screens"].items() if s["home"]]
        self.assertEqual((1, 1), (len(entries), len(homes)))
        self.assertEqual(set(_MODEL["screens"]), self.reach(entries[0], edges), "orphan or unreachable screen")
        for name, screen in _MODEL["screens"].items():
            if screen.get("reload"):  # a reload starts over at the entry
                self.assertIn("reload", screen["message"].lower(), name)
            else:
                self.assertIn(homes[0], self.reach(name, edges), f"trap: {name}")
                if not screen["home"]:
                    self.assertIn(screen["back"], edges[name], f"trap: {name} has no control back")

    def test_no_dead_or_double_firing_control(self) -> None:
        names = list(_MODEL["state"])
        for name, control in _MODEL["controls"].items():
            states = (dict(zip(names, bits)) for bits in itertools.product([False, True], repeat=len(names)))
            self.assertTrue(any(_holds(control["enabled_when"], **s) for s in states), f"{name}: can never be used")
        check = _MODEL["controls"]["check"]["enabled_when"]
        self.assertFalse(_holds(check, cases_loaded=True, pending=True), "a second check could start")
        self.assertFalse(_holds(check, cases_loaded=False, pending=False), "a check with no case")

    def test_page_controls_and_model_controls_are_the_same_set(self) -> None:
        tags = re.findall(r"<(?:button|select|input|textarea|a)\b[^>]*>", _HTML)
        in_page = {re.search(r'\bid="([^"]+)"', tag).group(1) for tag in tags}  # a control without an id fails here
        self.assertEqual(in_page, {c["selector"][1:] for c in _MODEL["controls"].values() if c["selector"]})
        self.assertLess(_HTML.index('id="case"'), _HTML.index('id="check"'), "focus order: pick, then check")
        self.assertNotRegex(_HTML, r'tabindex="[1-9]')
        self.assertIn("if (pending) return", _JS)  # a second Check while one runs does nothing
        self.assertIn("mine !== generation", _JS)  # a stale answer never lands on a newly picked case
        self.assertIn(_MODEL["screens"]["loading"]["message"], _HTML)
        for path in re.findall(r'"(/[\w./-]+)"', _JS):
            self.assertIn(path, _ROUTES, path)
        for name, screen in _MODEL["screens"].items():
            if not screen.get("entry"):  # the page starts on the entry; the script shows every other screen by name
                self.assertIn(f'show("{name}"', _JS, name)

    def test_accessibility(self) -> None:
        """WCAG 2.1 AA (Art. XIII.3): names, aria-live and contrast in both palettes."""
        self.assertIn('<html lang="en">', _HTML)
        self.assertRegex(_HTML, r'<label for="case">\w')
        self.assertRegex(_HTML, r'<button id="check"[^>]*>Check</button>')

        def palette(anchor: str) -> dict[str, str]:
            block = _CSS[_CSS.index(anchor):]
            return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", block[:block.index("}")]))

        linear = lambda c: c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
        lum = lambda h: sum(w * linear(int(h[i:i + 2], 16) / 255) for w, i in ((0.2126, 1), (0.7152, 3), (0.0722, 5)))
        for theme, tokens in {"light": palette(":root {"), "dark": palette("prefers-color-scheme: dark")}.items():
            for fg, bg, minimum in _MODEL["accessibility"]["contrast_pairs"]:
                high, low = sorted((lum(tokens[fg]), lum(tokens[bg])), reverse=True)
                self.assertGreaterEqual((high + 0.05) / (low + 0.05), minimum, f"{theme} {fg}/{bg}")
        for region in _MODEL["accessibility"]["live_regions"]:
            self.assertRegex(_HTML, rf'id="{region}"[^>]*role="status"[^>]*aria-live="polite"')


if __name__ == "__main__":
    unittest.main()
