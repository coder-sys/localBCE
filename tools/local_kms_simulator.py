"""Local-only stand-in for a government KMS/HSM.

This module exists only to test the production trust boundary. The RSA private
key is generated and retained in a separate process. It is never returned to
the Blind Ledger application or proving queue.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from multiprocessing import Pipe, Process
from multiprocessing.connection import Client, Listener
import os
import re
import time
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tools.encrypted_witness_envelope import oaep_label_for_context


LOCAL_KMS_ENVIRONMENT = "BL_LOCAL_KMS_SIMULATOR"
_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _server(ready: Any, authkey: bytes, agency_id: str, key_id: str) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    listener = Listener(("127.0.0.1", 0), family="AF_INET", authkey=authkey)
    ready.send(
        {
            "host": listener.address[0],
            "port": listener.address[1],
            "public_key_pem_b64": base64.b64encode(public_pem).decode("ascii"),
        }
    )
    ready.close()
    active = True
    seen_request_ids: set[str] = set()
    audit: list[dict[str, Any]] = []
    while True:
        connection = listener.accept()
        try:
            request = connection.recv()
            operation = request.get("operation") if isinstance(request, dict) else None
            if operation == "stop":
                connection.send({"ok": True})
                break
            if operation == "public_key":
                connection.send(
                    {
                        "ok": True,
                        "key_id": key_id,
                        "agency_id": agency_id,
                        "public_key_pem_b64": base64.b64encode(public_pem).decode("ascii"),
                        "active": active,
                    }
                )
                continue
            if operation == "revoke":
                active = False
                audit.append({"event": "key_revoked", "key_id": key_id})
                connection.send({"ok": True})
                continue
            if operation == "audit":
                connection.send({"ok": True, "events": list(audit)})
                continue
            if operation != "unwrap":
                connection.send({"ok": False, "error": "unsupported KMS operation"})
                continue
            request_id = request.get("request_id")
            requested_agency = request.get("agency_id")
            requested_key = request.get("key_id")
            context_sha256 = request.get("context_sha256")
            failure = ""
            if not active:
                failure = "KMS wrapping key is revoked"
            elif requested_key != key_id:
                failure = "KMS wrapping key is unknown"
            elif requested_agency != agency_id:
                failure = "KMS agency authorization failed"
            elif not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
                failure = "invalid KMS request id"
            elif request_id in seen_request_ids:
                failure = "KMS unwrap replay rejected"
            elif not isinstance(context_sha256, str) or not re.fullmatch(
                r"[0-9a-f]{64}", context_sha256
            ):
                failure = "invalid KMS request context"
            if failure:
                audit.append(
                    {
                        "event": "unwrap_rejected",
                        "request_id": request_id,
                        "agency_id": requested_agency,
                        "key_id": requested_key,
                        "context_sha256": context_sha256,
                        "reason": failure,
                    }
                )
                connection.send({"ok": False, "error": failure})
                continue
            seen_request_ids.add(request_id)
            try:
                wrapped = base64.b64decode(request.get("wrapped_key_b64", ""), validate=True)
                unwrapped = private_key.decrypt(
                    wrapped,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=oaep_label_for_context(context_sha256),
                    ),
                )
            except Exception:
                audit.append(
                    {
                        "event": "unwrap_rejected",
                        "request_id": request_id,
                        "agency_id": requested_agency,
                        "key_id": requested_key,
                        "context_sha256": context_sha256,
                        "reason": "wrapped key authentication failed",
                    }
                )
                connection.send({"ok": False, "error": "wrapped key authentication failed"})
                continue
            audit.append(
                {
                    "event": "unwrap_succeeded",
                    "request_id": request_id,
                    "agency_id": requested_agency,
                    "key_id": requested_key,
                    "context_sha256": context_sha256,
                }
            )
            connection.send(
                {"ok": True, "unwrapped_key_b64": base64.b64encode(unwrapped).decode("ascii")}
            )
        finally:
            connection.close()
    listener.close()


@dataclass(frozen=True)
class LocalKmsEndpoint:
    host: str
    port: int
    authkey_b64: str

    def environment(self) -> dict[str, str]:
        return {
            LOCAL_KMS_ENVIRONMENT: "1",
            "BL_LOCAL_KMS_HOST": self.host,
            "BL_LOCAL_KMS_PORT": str(self.port),
            "BL_LOCAL_KMS_AUTHKEY_B64": self.authkey_b64,
        }


class LocalKmsClient:
    def __init__(self, endpoint: LocalKmsEndpoint) -> None:
        self.endpoint = endpoint

    @classmethod
    def from_environment(cls) -> "LocalKmsClient":
        if os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
            raise RuntimeError("local KMS simulator is forbidden in production")
        if os.environ.get(LOCAL_KMS_ENVIRONMENT) != "1":
            raise RuntimeError("local KMS simulator is not configured")
        try:
            endpoint = LocalKmsEndpoint(
                host=os.environ["BL_LOCAL_KMS_HOST"],
                port=int(os.environ["BL_LOCAL_KMS_PORT"]),
                authkey_b64=os.environ["BL_LOCAL_KMS_AUTHKEY_B64"],
            )
        except (KeyError, ValueError) as exc:
            raise RuntimeError("local KMS simulator configuration is invalid") from exc
        return cls(endpoint)

    def _request(self, request: dict[str, Any]) -> dict[str, Any]:
        try:
            authkey = base64.b64decode(self.endpoint.authkey_b64, validate=True)
            connection = Client(
                (self.endpoint.host, self.endpoint.port), family="AF_INET", authkey=authkey
            )
            try:
                connection.send(request)
                response = connection.recv()
            finally:
                connection.close()
        except (OSError, EOFError, ValueError) as exc:
            raise RuntimeError("local KMS simulator is unavailable") from exc
        if not isinstance(response, dict) or not response.get("ok"):
            message = (
                response.get("error", "local KMS request failed")
                if isinstance(response, dict)
                else "local KMS request failed"
            )
            raise RuntimeError(str(message))
        return response

    def public_key(self) -> dict[str, Any]:
        return self._request({"operation": "public_key"})

    def unwrap_key(
        self,
        wrapped_key: bytes,
        key_id: str,
        *,
        agency_id: str,
        request_id: str,
        context_sha256: str,
    ) -> bytes:
        response = self._request(
            {
                "operation": "unwrap",
                "wrapped_key_b64": base64.b64encode(wrapped_key).decode("ascii"),
                "key_id": key_id,
                "agency_id": agency_id,
                "request_id": request_id,
                "context_sha256": context_sha256,
            }
        )
        try:
            return base64.b64decode(response["unwrapped_key_b64"], validate=True)
        except (KeyError, ValueError) as exc:
            raise RuntimeError("local KMS returned an invalid unwrapped key") from exc

    def revoke(self) -> None:
        self._request({"operation": "revoke"})

    def audit_events(self) -> list[dict[str, Any]]:
        return list(self._request({"operation": "audit"})["events"])


class LocalKmsSimulator:
    """Context-managed local service. Never use it for production adjudication."""

    def __init__(self, *, agency_id: str, key_id: str) -> None:
        self.agency_id = agency_id
        self.key_id = key_id
        self._process: Process | None = None
        self.endpoint: LocalKmsEndpoint | None = None

    def start(self) -> LocalKmsClient:
        if self._process is not None:
            raise RuntimeError("local KMS simulator is already running")
        parent, child = Pipe(duplex=False)
        authkey = os.urandom(32)
        process = Process(
            target=_server,
            args=(child, authkey, self.agency_id, self.key_id),
            name="blind-ledger-local-kms-simulator",
            daemon=True,
        )
        process.start()
        child.close()
        if not parent.poll(30):
            process.terminate()
            process.join(5)
            raise RuntimeError("local KMS simulator failed to start")
        ready = parent.recv()
        parent.close()
        self._process = process
        self.endpoint = LocalKmsEndpoint(
            host=ready["host"],
            port=int(ready["port"]),
            authkey_b64=base64.b64encode(authkey).decode("ascii"),
        )
        client = LocalKmsClient(self.endpoint)
        deadline = time.monotonic() + 5
        while True:
            try:
                client.public_key()
                return client
            except RuntimeError:
                if time.monotonic() >= deadline:
                    self.stop()
                    raise
                time.sleep(0.05)

    def stop(self) -> None:
        process = self._process
        endpoint = self.endpoint
        self._process = None
        self.endpoint = None
        if process is None:
            return
        if process.is_alive() and endpoint is not None:
            try:
                LocalKmsClient(endpoint)._request({"operation": "stop"})
            except RuntimeError:
                pass
        process.join(5)
        if process.is_alive():
            process.terminate()
            process.join(5)

    def __enter__(self) -> LocalKmsClient:
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.stop()
