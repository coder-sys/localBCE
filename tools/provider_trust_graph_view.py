"""Local, read-only browser view over verified synthetic Provider Trust Graph data."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import socket
import sys
from types import MappingProxyType

from app.mirror import provider_trust_graph as graph_producer
from app.mirror import provider_trust_graph_read_model_v1 as read_model


_BUNDLE_SCHEMA = "mirror-provider-trust-graph-local-view-v1"
_MAX_BUNDLE_BYTES = 65_536
# Each accepted connection has a 5-second read/write inactivity timeout. The
# synchronous server therefore releases silent or stalled I/O without creating
# a worker thread; this is an inactivity bound, not a total request deadline.
_CLIENT_SOCKET_TIMEOUT_SECONDS = 5.0
_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)
_ASSET_FILES = MappingProxyType(
    {
        "/": ("provider_trust_graph_view.html", "text/html; charset=utf-8", 16_384),
        "/style.css": ("provider_trust_graph_view.css", "text/css; charset=utf-8", 16_384),
        "/app.js": ("provider_trust_graph_view.js", "text/javascript; charset=utf-8", 32_768),
    }
)


class _LocalViewError(ValueError):
    """One fixed, path-free local view setup error."""


def _load_selection(
    artifact_path: str,
    request_path: str,
    operation_ref: str,
) -> read_model.ProviderTrustGraphReadSelectionV1:
    try:
        return read_model.load_selection(artifact_path, request_path, operation_ref)
    except read_model.ProviderTrustGraphReadModelV1Error:
        raise _LocalViewError("view:local-input") from None


def _base_view(selection: read_model.ProviderTrustGraphReadSelectionV1, *, now: int) -> dict[str, object]:
    # The read model returns its own canonical ASCII JSON object.
    return json.loads(read_model.build_read_model_v1(
        selection.graph_artifact,
        selection.profile_registry,
        expected_profile_id=selection.expected_profile_id,
        expected_profile_version=selection.expected_profile_version,
        export_request_raw=selection.export_request_raw,
        expected_operation_ref=selection.expected_operation_ref,
        now=now,
    ))


def _canonical_bundle(value: dict[str, object]) -> bytes:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (RecursionError, TypeError, ValueError, UnicodeEncodeError):
        raise _LocalViewError("view:bundle-encoding") from None
    if len(raw) > _MAX_BUNDLE_BYTES:
        raise _LocalViewError("view:bundle-byte-cap")
    return raw


def _build_bundle(
    left: read_model.ProviderTrustGraphReadSelectionV1,
    *,
    now: int,
    right: read_model.ProviderTrustGraphReadSelectionV1 | None = None,
) -> bytes:
    """Verify selections before creating the immutable response served by HTTP."""
    left_value = _base_view(left, now=now)
    if right is None:
        return _canonical_bundle(
            {
                "schema": _BUNDLE_SCHEMA,
                "mode": "SINGLE",
                "left": left_value,
            }
        )

    right_value = _base_view(right, now=now)
    comparison = json.loads(read_model.compare_read_models_v1(left, right, now=now))
    return _canonical_bundle(
        {
            "schema": _BUNDLE_SCHEMA,
            "mode": "COMPARE",
            "left": left_value,
            "right": right_value,
            "comparison": comparison,
        }
    )


def _load_static_assets() -> Mapping[str, tuple[str, bytes]]:
    routes: dict[str, tuple[str, bytes]] = {}
    for route, (filename, content_type, byte_limit) in _ASSET_FILES.items():
        try:
            raw = graph_producer._read_bounded(Path(__file__).with_name(filename), byte_limit)
        except Exception:
            raise _LocalViewError("view:local-assets") from None
        routes[route] = (content_type, raw)
    return MappingProxyType(routes)


def _make_handler(routes: Mapping[str, tuple[str, bytes]]) -> type[BaseHTTPRequestHandler]:
    class LocalViewHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "MirrorLocalPTG"
        sys_version = ""

        def log_message(self, format: str, *args: object) -> None:
            return

        def _respond(
            self,
            status: int,
            body: bytes,
            content_type: str = "text/plain; charset=utf-8",
        ) -> None:
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.send_header("Content-Security-Policy", _CONTENT_SECURITY_POLICY)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

        def _host_is_local(self) -> bool:
            values = self.headers.get_all("Host", [])
            return values == [f"127.0.0.1:{self.server.server_port}"]

        def do_GET(self) -> None:
            if not self._host_is_local():
                self._respond(403, b"Local host required.\n")
                return
            asset = routes.get(self.path)
            if asset is None:
                self._respond(404, b"Not found.\n")
                return
            content_type, body = asset
            self._respond(200, body, content_type)

        def _method_not_allowed(self) -> None:
            try:  # Read a small body first: closing with unread bytes sends RST on Windows.
                length = int(self.headers.get("Content-Length", "0"))
                if 0 < length <= _MAX_BUNDLE_BYTES:
                    self.rfile.read(length)
            except (ValueError, OSError):
                pass
            self._respond(405, b"Read-only GET routes only.\n")

        do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _method_not_allowed

        def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
            if code == 404:
                self._respond(404, b"Not found.\n")
            else:
                self._respond(400, b"Bad request.\n")

    return LocalViewHandler


class _LocalHTTPServer(HTTPServer):
    """Single-request loopback server with bounded accepted-socket I/O waits."""

    client_socket_timeout_seconds = _CLIENT_SOCKET_TIMEOUT_SECONDS

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        request, client_address = super().get_request()
        try:
            request.settimeout(self.client_socket_timeout_seconds)
        except OSError:
            self.shutdown_request(request)
            raise
        return request, client_address

    def handle_error(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        # A peer can disconnect or stop reading during a response. The request
        # lifecycle closes that accepted socket; do not emit a traceback.
        if isinstance(sys.exc_info()[1], OSError):
            return
        super().handle_error(request, client_address)


def _make_server(bundle: bytes, *, port: int) -> HTTPServer:
    routes = dict(_load_static_assets())
    routes["/data.json"] = ("application/json; charset=utf-8", bundle)
    return _LocalHTTPServer(
        ("127.0.0.1", port),
        _make_handler(MappingProxyType(routes)),
    )


def _parse_port(raw: str) -> int:
    try:
        port = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError("port must be an integer from 0 to 65535") from None
    if not 0 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be an integer from 0 to 65535")
    return port


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.provider_trust_graph_view",
        description="Serve an already verified synthetic PTG selection on loopback.",
    )
    parser.add_argument("--artifact", required=True, help="local graph artifact path")
    parser.add_argument("--request", required=True, help="local provider-evidence request path")
    parser.add_argument("--operation-ref", required=True, help="expected export operation reference")
    parser.add_argument("--now", required=True, type=int, help="verifier time used for export checks")
    parser.add_argument("--port", type=_parse_port, default=8765, help="loopback port; 0 selects an ephemeral port")
    parser.add_argument("--compare-artifact", help="second local graph artifact path")
    parser.add_argument("--compare-request", help="second local provider-evidence request path")
    parser.add_argument("--compare-operation-ref", help="second expected export operation reference")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    comparison_values = (args.compare_artifact, args.compare_request, args.compare_operation_ref)
    if any(value is not None for value in comparison_values) and not all(
        type(value) is str and value for value in comparison_values
    ):
        sys.stderr.write("REJECT view:compare-selection\n")
        return 2

    try:
        left = _load_selection(args.artifact, args.request, args.operation_ref)
        right = None
        if all(value is not None for value in comparison_values):
            right = _load_selection(
                args.compare_artifact,
                args.compare_request,
                args.compare_operation_ref,
            )
        bundle = _build_bundle(left, now=args.now, right=right)
        server = _make_server(bundle, port=args.port)
    except (read_model.ProviderTrustGraphReadModelV1Error, _LocalViewError) as error:
        sys.stderr.write(f"REJECT {error}\n")
        return 1
    except OSError:
        sys.stderr.write("REJECT view:loopback-server\n")
        return 1

    address = server.server_address
    actual_port = int(address[1])
    sys.stdout.write(f"Local synthetic Provider Trust Graph view: http://127.0.0.1:{actual_port}/\n")
    sys.stdout.write("Unauthenticated local preview; read-only, synthetic, and nonactivating. Press Ctrl+C to close.\n")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
