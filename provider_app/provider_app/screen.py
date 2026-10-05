"""One local screen over api.preflight_bytes and fix_list. Loopback only; stores, logs and sends nothing.

Run: python -m provider_app.screen [port]. Every refusal is a fixed code; no input is ever echoed.
"""

from __future__ import annotations

import copy
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .api import preflight_bytes
from .codec import _unique_pairs, bundle_content_digest
from .contracts import MAX_JSON_BYTES, InputError
from .fix_list import fix_list

_ROOT = Path(__file__).resolve().parents[1]
_PAGES = {"/": ("index.html", "text/html"), "/screen.css": ("screen.css", "text/css"),
          "/screen.js": ("screen.js", "text/javascript"), "/interaction-model.json": ("interaction-model.json", "application/json")}
MAX_BODY = 2 * MAX_JSON_BYTES + 64  # {"request":...,"bundle":...}: each part keeps the codec's own bound
_STATUS_CODES = {400: "BODY_INVALID", 404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 413: "BODY_TOO_LARGE", 421: "HOST_REFUSED", 500: "CHECK_FAILED"}
_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _cases() -> list[dict]:
    """The synthetic vectors as ready-to-send cases; expected outcomes stay in the file."""
    vectors = json.loads((_ROOT / "vectors" / "synthetic-vectors-v1.json").read_text(encoding="utf-8"))
    cases = []
    for case in vectors["cases"]:
        request, bundle = copy.deepcopy(vectors["requestTemplate"]), copy.deepcopy(vectors["bundleTemplate"])
        stack = [(request, case.get("requestChanges", {}))]
        while stack:
            target, changes = stack.pop()
            for key, value in changes.items():
                if isinstance(value, dict) and isinstance(target.get(key), dict):
                    stack.append((target[key], value))
                else:
                    target[key] = copy.deepcopy(value)
        for change in case.get("bundleChanges", []):
            node = bundle
            for part in change["path"][:-1]:
                node = node[part]
            node[change["path"][-1]] = copy.deepcopy(change["value"])
        bundle["contentDigest"] = bundle_content_digest(bundle)
        cases.append({"id": case["id"], "request": request, "bundle": bundle})
    return cases


def _check(raw: bytes) -> dict:
    try:
        body = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        if type(body) is not dict or set(body) != {"request", "bundle"}:
            raise InputError("BODY_FIELDS_INVALID")
        request, bundle = _canonical(body["request"]), _canonical(body["bundle"])
    except InputError:
        raise
    except (ValueError, RecursionError):
        raise InputError("BODY_INVALID") from None
    result = preflight_bytes(request, bundle)
    fixes = [dict(zip(("rule", "citation", "fact", "text"), fix)) for fix in fix_list(result)]
    return {"outcome": json.loads(result)["outcome"], "fixes": fixes}


class _Handler(BaseHTTPRequestHandler):
    timeout = 10

    def log_message(self, *_args) -> None:
        pass

    def _send(self, status: int, body: object, kind: str = "application/json") -> None:
        data = body if isinstance(body, bytes) else _canonical(body)
        self.send_response(status)
        for name, value in (("Content-Type", kind + "; charset=utf-8"), ("Content-Length", str(len(data))),
                            ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                            ("Content-Security-Policy", _CSP), ("Connection", "close")):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def send_error(self, code, message=None, explain=None) -> None:  # fixed JSON, never the request line
        self._send(code, {"error": _STATUS_CODES.get(code, "REQUEST_REFUSED")})

    def _foreign_host(self) -> bool:
        """A page another site points at 127.0.0.1 (DNS rebinding) carries its own Host; refuse it."""
        port = self.server.server_address[1]
        if self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}"):
            return False
        self.send_error(421)
        return True

    def do_GET(self) -> None:
        if self._foreign_host():
            return None
        if self.path == "/cases":
            return self._send(200, _cases())
        if self.path not in _PAGES:
            return self.send_error(405 if self.path == "/check" else 404)
        name, kind = _PAGES[self.path]
        self._send(200, (_ROOT / "screen" / name).read_bytes(), kind)

    def do_POST(self) -> None:
        if self._foreign_host():
            return None
        if self.path != "/check":
            return self.send_error(405 if self.path in _PAGES or self.path == "/cases" else 404)
        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.send_error(400)
        if not 0 <= size <= MAX_BODY:
            return self.send_error(413 if size > MAX_BODY else 400)
        try:
            result = _check(self.rfile.read(size))
        except InputError as refusal:
            return self._send(400, {"error": refusal.code})
        except Exception:  # a fault is a fixed code too, never a traceback or the input
            return self.send_error(500)
        self._send(200, result)

    do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = lambda self: self.send_error(405)


def make_server(port: int = 0) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), _Handler)


if __name__ == "__main__":
    server = make_server(int(sys.argv[1]) if len(sys.argv) > 1 else 8765)
    print(f"Provider check screen: http://127.0.0.1:{server.server_address[1]}/ (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
