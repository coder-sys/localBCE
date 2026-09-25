"""Focused source tests for the local, read-only PTG browser view."""

from __future__ import annotations

from http.client import HTTPConnection
import json
from pathlib import Path
import socket
import threading
import time
import unittest
from dataclasses import replace

from app.mirror import provider_trust_graph_read_model_v1 as read_model
from tests.test_mirror_provider_trust_graph_read_model_v1 import _admission, _selection
from tools import provider_trust_graph_view as local_view

class ProviderTrustGraphLocalViewTests(unittest.TestCase):
    def _bundle(self, *, compare: bool = False) -> bytes:
        admission = _admission()
        left = _selection(admission.graph_artifact, "a" * 64)
        right = _selection(admission.graph_artifact, "b" * 64) if compare else None
        return local_view._build_bundle(left, now=7_000, right=right)

    def test_single_bundle_contains_only_verified_read_model_projection(self) -> None:
        bundle_raw = self._bundle()
        bundle = json.loads(bundle_raw.decode("ascii"))
        self.assertEqual("SINGLE", bundle["mode"])
        self.assertEqual("mirror-provider-trust-graph-local-view-v1", bundle["schema"])
        self.assertEqual("UNKNOWN", bundle["left"]["status"]["freshness"])
        self.assertEqual("UNKNOWN", bundle["left"]["status"]["completeness"])
        self.assertEqual("NOT_ESTABLISHED", bundle["left"]["status"]["source_truth"])
        self.assertEqual("FORBIDDEN", bundle["left"]["status"]["absence_inference"])
        self.assertIsNone(bundle["left"]["status"]["proofSuiteId"])
        self.assertIs(bundle["left"]["status"]["production_usable"], False)
        self.assertIs(bundle["left"]["status"]["activation"], False)
        self.assertNotIn("operation_ref", bundle_raw.decode("ascii"))

    def test_compare_bundle_uses_existing_verified_comparison_contract(self) -> None:
        bundle = json.loads(self._bundle(compare=True).decode("ascii"))
        self.assertEqual("COMPARE", bundle["mode"])
        self.assertEqual("COMPARE", bundle["comparison"]["view"])
        self.assertEqual("UNKNOWN_NOT_ABSENT", bundle["comparison"]["comparison"]["missing_evidence_semantics"])
        self.assertEqual("UPSTREAM_REQUIRED", bundle["comparison"]["status"]["caller_authorization"])

    def test_tampered_selection_is_rejected_before_server_creation(self) -> None:
        admission = _admission()
        tampered = admission.graph_artifact.replace(b'"synthetic_only":true', b'"synthetic_only":false', 1)
        self.assertNotEqual(tampered, admission.graph_artifact)
        selection = replace(_selection(admission.graph_artifact), graph_artifact=tampered)
        with self.assertRaises(read_model.ProviderTrustGraphReadModelV1Error):
            local_view._build_bundle(selection, now=7_000)

    def test_server_is_loopback_only_and_serves_fixed_read_routes(self) -> None:
        server = local_view._make_server(self._bundle(compare=True), port=0)
        self.assertEqual("127.0.0.1", server.server_address[0])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
            connection.request("GET", "/data.json")
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(200, response.status)
            self.assertEqual("application/json; charset=utf-8", response.getheader("Content-Type"))
            self.assertEqual("no-store", response.getheader("Cache-Control"))
            self.assertEqual("nosniff", response.getheader("X-Content-Type-Options"))
            self.assertIn("frame-ancestors 'none'", response.getheader("Content-Security-Policy"))
            self.assertEqual("COMPARE", json.loads(body.decode("ascii"))["mode"])
            connection.close()

            for path, expected_type in (
                ("/", "text/html; charset=utf-8"),
                ("/style.css", "text/css; charset=utf-8"),
                ("/app.js", "text/javascript; charset=utf-8"),
            ):
                connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
                connection.request("GET", path)
                response = connection.getresponse()
                self.assertEqual(200, response.status)
                self.assertEqual(expected_type, response.getheader("Content-Type"))
                self.assertGreater(len(response.read()), 0)
                connection.close()

            connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
            connection.request("GET", "/data.json?artifact=C%3A%5Cprivate.json")
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(404, response.status)
            self.assertNotIn(b"private.json", body)
            connection.close()

            connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
            connection.request("POST", "/data.json", body=b"ignored")
            response = connection.getresponse()
            self.assertEqual(405, response.status)
            self.assertNotIn("Access-Control-Allow-Origin", response.headers)
            connection.close()

            connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
            connection.putrequest("GET", "/data.json", skip_host=True)
            connection.putheader("Host", "untrusted.example")
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(403, response.status)
            self.assertNotIn(b"untrusted.example", response.read())
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_idle_and_incomplete_connections_release_server_for_next_request(self) -> None:
        timeout_seconds = 0.25
        started = threading.Event()
        server = local_view._make_server(self._bundle(), port=0)
        server.client_socket_timeout_seconds = timeout_seconds
        original_handler = server.RequestHandlerClass

        class StartedHandler(original_handler):
            def handle(self) -> None:
                started.set()
                super().handle()

        server.RequestHandlerClass = StartedHandler
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            incomplete_request = (
                f"GET /data.json HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Pending:".encode("ascii")
            )
            for partial_request in (None, incomplete_request):
                with self.subTest(partial_request=partial_request is not None):
                    started.clear()
                    stalled = socket.create_connection(("127.0.0.1", port), timeout=2)
                    stalled.settimeout(2)
                    self.assertTrue(started.wait(timeout=1))
                    if partial_request is not None:
                        stalled.sendall(partial_request)

                    began = time.monotonic()
                    connection = HTTPConnection("127.0.0.1", port, timeout=2)
                    connection.request("GET", "/data.json")
                    response = connection.getresponse()
                    self.assertEqual(200, response.status)
                    self.assertEqual("SINGLE", json.loads(response.read().decode("ascii"))["mode"])
                    self.assertLessEqual(time.monotonic() - began, timeout_seconds + 1)
                    connection.close()
                    self.assertEqual(b"", stalled.recv(1))
                    stalled.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_browser_assets_use_text_rendering_without_persistence_or_remote_urls(self) -> None:
        script_path = Path(local_view.__file__).with_name("provider_trust_graph_view.js")
        script = script_path.read_text(encoding="utf-8")
        self.assertIn("textContent", script)
        self.assertNotIn("innerHTML", script)
        self.assertNotIn("insertAdjacentHTML", script)
        self.assertNotIn("localStorage", script)
        self.assertNotIn("https://", script)
        self.assertNotIn("http://", script)

if __name__ == "__main__":
    unittest.main()
