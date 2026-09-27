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
from contextlib import redirect_stderr, redirect_stdout
import io
import tempfile
from unittest.mock import patch

from app.mirror import nc_medicaid_fhir as fhir
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import provider_trust_graph_read_model_v1 as read_model
from tests.test_mirror_provider_trust_graph_read_model_v1 import _admission, _request, _selection
from tests.test_nc_medicaid_fhir_source import _bundle
from tools import provider_trust_graph_view as local_view


class ProviderTrustGraphLocalViewTests(unittest.TestCase):
    def test_source_cli_binds_full_context_before_serving_safe_projection(self) -> None:
        context = profile.DynamicCaptureContext("1" * 128, "2" * 128, "3" * 128, "4" * 128, 7001, 7011)
        url = profile.NC_MEDICAID_PROFILE.page_url(0, context)
        bundle = _bundle()
        bundle["link"][0]["url"] = url
        raw = fhir.build_fixture_envelope(fhir.SyntheticFhirTransport({(url, 0): fhir.fixture_response(bundle, url)}), context=context)
        with tempfile.TemporaryDirectory() as directory:
            source_path, request_path = Path(directory) / "source.json", Path(directory) / "request.json"
            source_path.write_bytes(raw)
            request_path.write_bytes(_request())
            args = ["--source-envelope", str(source_path), "--request", str(request_path), "--operation-ref", "a" * 64, "--now", "7011", "--port", "0", "--capture-context"]
            expected = list(map(str, context.material().values()))
            with patch.object(local_view, "_make_server") as factory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as stderr:
                factory.return_value.server_address = ("127.0.0.1", 12345)
                self.assertEqual(0, local_view.main(args + expected))
                self.assertEqual("", stderr.getvalue())
                projection = factory.call_args.args[0]
                self.assertEqual("UNKNOWN", json.loads(projection)["left"]["status"]["freshness"])
                self.assertEqual("NOT_ESTABLISHED", json.loads(projection)["left"]["status"]["source_truth"])
                for private in (*expected[:4], str(source_path), url, "NCPROV-001"):
                    self.assertNotIn(private.encode(), projection)
                factory.return_value.server_close.assert_called_once()
                comparison_args = ["--compare-source-envelope", str(source_path), "--compare-request", str(request_path),
                                   "--compare-operation-ref", "a" * 64, "--compare-capture-context", *expected]
                self.assertEqual(0, local_view.main(args + expected + comparison_args))
                self.assertEqual("COMPARE", json.loads(factory.call_args.args[0])["mode"])
                factory.reset_mock()
                for index in range(6):
                    changed = expected.copy()
                    changed[index] = "f" * 128 if index < 4 else str(int(changed[index]) + 1)
                    with self.subTest(context_field=index):
                        self.assertEqual(1, local_view.main(args + changed))
                for rejected in (raw.replace(b'"COMPLETE"', b'"FAILED"', 1), b"private-canary", b"x" * (profile.NC_MEDICAID_PROFILE.transport_caps["max_envelope_bytes"] + 1)):
                    source_path.write_bytes(rejected)
                    self.assertEqual(1, local_view.main(args + expected))
                self.assertEqual(1, local_view.main(args[:-1]))
                self.assertEqual("REJECT view:local-input\n" * 10, stderr.getvalue())
                source_path.write_bytes(raw)
                for option in ("--compare-artifact", "--compare-source-envelope"):
                    with self.subTest(option=option):
                        self.assertEqual(2, local_view.main(args + expected + [option, ""]))
                factory.assert_not_called()

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
        def exchange(method, path, *, body=None, host=None):
            connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
            try:
                connection.request(method, path, body=body, headers={"Host": host} if host else {})
                response = connection.getresponse()
                return response, response.read()
            finally:
                connection.close()
        try:
            response, body = exchange("GET", "/data.json")
            self.assertEqual(200, response.status)
            self.assertEqual("application/json; charset=utf-8", response.getheader("Content-Type"))
            self.assertEqual("no-store", response.getheader("Cache-Control"))
            self.assertEqual("nosniff", response.getheader("X-Content-Type-Options"))
            self.assertIn("frame-ancestors 'none'", response.getheader("Content-Security-Policy"))
            self.assertEqual("COMPARE", json.loads(body.decode("ascii"))["mode"])

            for path, expected_type in (
                ("/", "text/html; charset=utf-8"),
                ("/style.css", "text/css; charset=utf-8"),
                ("/app.js", "text/javascript; charset=utf-8"),
            ):
                response, body = exchange("GET", path)
                self.assertEqual(200, response.status)
                self.assertEqual(expected_type, response.getheader("Content-Type"))
                self.assertGreater(len(body), 0)

            response, body = exchange("GET", "/data.json?artifact=C%3A%5Cprivate.json")
            self.assertEqual(404, response.status)
            self.assertNotIn(b"private.json", body)

            response, _body = exchange("POST", "/data.json", body=b"ignored")
            self.assertEqual(405, response.status)
            self.assertNotIn("Access-Control-Allow-Origin", response.headers)

            response, body = exchange("GET", "/data.json", host="untrusted.example")
            self.assertEqual(403, response.status)
            self.assertNotIn(b"untrusted.example", body)
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
