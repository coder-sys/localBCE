"""ContinuityStore export format and semantic import adapter.

ContinuityStore owns schema and semantic verification.  Filesystem staging,
locking, create-only publication, and recovery are owned exclusively by
``restore_publication``; this module contains no rename/replace publication
path and no second lock implementation.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Mapping

from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as independent
from app.mirror import restore_publication
from app.mirror import discrepancy_case, discrepancy_case_independent
from app.mirror import source_evidence_custody, source_evidence_custody_independent
from app.mirror import source_reconciliation, source_reconciliation_independent
from app.mirror import qualification, qualification_independent


EXPORT_SCHEMA = "mirror-continuity-state-export-v3"
EXPORT_DOMAIN = "BL/MIRROR/CONTINUITY-EXPORT-V3/"
MAX_EXPORT_BYTES = 20 * 1024 * 1024
MAX_EXPORT_ARTIFACTS = 32
MAX_EXPORT_EVENTS = 32
MAX_EXPORT_RECEIPTS = 32
MAX_HEX_BYTES = 2 * store.MAX_ARTIFACT_BYTES

EXPORT_KEYS = {
    "schema", "schema_version", "software", "meta", "artifacts", "operations", "receipts", "events", "heads",
    "state_root", "state_owned", "support_safe", "synthetic_only", "production_usable", "export_root",
}
ROW_KEYS = {
    "meta": {"key", "value"},
    "artifacts": set(independent.TABLE_COLUMNS["artifacts"]) - {"payload"} | {"payload_hex"},
    "operations": set(independent.TABLE_COLUMNS["operations"]),
    "receipts": set(independent.TABLE_COLUMNS["receipts"]) - {"receipt"} | {"receipt_hex"},
    "events": set(independent.TABLE_COLUMNS["events"]),
    "heads": set(independent.TABLE_COLUMNS["heads"]),
}


class ContinuityExportError(ValueError):
    pass


class InjectedRestoreFault(ContinuityExportError):
    """Private test-only restore interruption."""


RESTORE_FAULT_POINTS = (
    "before_staging_creation",
    "after_empty_staging_db_creation",
    "after_snapshot_transaction",
    "after_independent_verification_checkpoint",
    "before_stage_delete",
    "after_atomic_publication_before_response",
)
_restore_fault_point: str | None = None


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ContinuityExportError("export:noncanonical-value") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((EXPORT_DOMAIN + label + "/v3\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _module_identity(path: str | Path) -> str:
    digest = hashlib.sha3_512()
    digest.update((EXPORT_DOMAIN + "MODULE-SOURCE/v3\0").encode("ascii"))
    digest.update(Path(path).read_bytes())
    return digest.hexdigest()


SOFTWARE_IDENTITIES = {
    "store_module_identity": _module_identity(store.__file__),
    "independent_module_identity": _module_identity(independent.__file__),
    "source_custody_module_identity": _module_identity(source_evidence_custody.__file__),
    "source_custody_independent_identity": _module_identity(source_evidence_custody_independent.__file__),
    "source_reconciliation_module_identity": _module_identity(source_reconciliation.__file__),
    "source_reconciliation_independent_identity": _module_identity(source_reconciliation_independent.__file__),
    "discrepancy_case_module_identity": _module_identity(discrepancy_case.__file__),
    "discrepancy_case_independent_identity": _module_identity(discrepancy_case_independent.__file__),
    "qualification_module_identity": _module_identity(qualification.__file__),
    "qualification_independent_module_identity": _module_identity(qualification_independent.__file__),
    "export_module_identity": _module_identity(__file__),
}


def _decode_hex(value: object, label: str, *, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) % 2 or len(value) > maximum * 2:
        raise ContinuityExportError(f"export:{label}-hex")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ContinuityExportError(f"export:{label}-hex") from exc
    if raw.hex() != value:
        raise ContinuityExportError(f"export:{label}-canonical")
    return raw


def _encode_rows(rows: Mapping[str, list[Mapping[str, object]]]) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = {}
    for table in independent.SNAPSHOT_TABLES:
        output: list[dict[str, object]] = []
        for source in rows[table]:
            item = dict(source)
            if table == "artifacts":
                payload = item.pop("payload")
                if type(payload) is not bytes:
                    raise ContinuityExportError("export:artifact-bytes")
                item["payload_hex"] = payload.hex()
            elif table == "receipts":
                receipt = item.pop("receipt")
                if type(receipt) is not bytes:
                    raise ContinuityExportError("export:receipt-bytes")
                item["receipt_hex"] = receipt.hex()
            if set(item) != ROW_KEYS[table]:
                raise ContinuityExportError(f"export:{table}-keys")
            output.append(item)
        result[table] = output
    return result


def _decode_rows(value: Mapping[str, object]) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = {}
    caps = {"meta": 2, "artifacts": MAX_EXPORT_ARTIFACTS, "operations": MAX_EXPORT_EVENTS, "receipts": MAX_EXPORT_RECEIPTS, "events": MAX_EXPORT_EVENTS, "heads": MAX_EXPORT_ARTIFACTS}
    for table in independent.SNAPSHOT_TABLES:
        rows = value[table]
        if not isinstance(rows, list) or len(rows) > caps[table]:
            raise ContinuityExportError(f"export:{table}-count")
        decoded: list[dict[str, object]] = []
        for item in rows:
            if not isinstance(item, dict) or set(item) != ROW_KEYS[table]:
                raise ContinuityExportError(f"export:{table}-keys")
            row = dict(item)
            for key in ("event_sequence", "sequence"):
                if key in row and type(row[key]) is not int:
                    raise ContinuityExportError(f"export:{table}-integer")
            if table == "artifacts":
                row["payload"] = _decode_hex(row.pop("payload_hex"), "artifact", maximum=store.MAX_ARTIFACT_BYTES)
            elif table == "receipts":
                row["receipt"] = _decode_hex(row.pop("receipt_hex"), "receipt", maximum=store.MAX_RECEIPT_BYTES)
            decoded.append(row)
        result[table] = decoded
    orders = (
        ("meta", lambda item: str(item["key"])),
        ("artifacts", lambda item: (str(item["kind"]), str(item["artifact_id"]))),
        ("operations", lambda item: int(item["event_sequence"])),
        ("receipts", lambda item: str(item["operation_id"])),
        ("events", lambda item: int(item["sequence"])),
        ("heads", lambda item: str(item["chain_id"])),
    )
    for table, key in orders:
        if result[table] != sorted(result[table], key=key):
            raise ContinuityExportError(f"export:{table}-order")
    return result


def _decode_and_verify(raw: bytes, *, graph_profile_registry: Mapping[str, object] | None = None) -> tuple[dict[str, object], dict[str, list[dict[str, object]]], dict[str, object]]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_EXPORT_BYTES:
        raise ContinuityExportError("export:byte-cap")
    try:
        value = independent._parse_canonical(raw, maximum=MAX_EXPORT_BYTES, max_string_bytes=MAX_HEX_BYTES * 2)
    except independent.IndependentStoreError as exc:
        raise ContinuityExportError(str(exc)) from None
    if set(value) != EXPORT_KEYS or value["schema"] != EXPORT_SCHEMA or type(value["schema_version"]) is not int or value["schema_version"] != store.SCHEMA_VERSION:
        raise ContinuityExportError("export:schema")
    if value["software"] != SOFTWARE_IDENTITIES:
        raise ContinuityExportError("export:software")
    if value["state_owned"] is not True or value["support_safe"] is not False or value["synthetic_only"] is not True or value["production_usable"] is not False:
        raise ContinuityExportError("export:authority-flags")
    state_root = value["state_root"]
    if not isinstance(state_root, str) or not independent._HEX128.fullmatch(state_root):
        raise ContinuityExportError("export:state-root")
    snapshot = _decode_rows(value)
    try:
        result = independent.verify_snapshot(snapshot, graph_profile_registry=graph_profile_registry)
    except independent.IndependentStoreError as exc:
        raise ContinuityExportError("export:state") from None
    if result["state_root"] != state_root:
        raise ContinuityExportError("export:state-root-binding")
    body = dict(value)
    body.pop("export_root")
    if value["export_root"] != _digest("export-root", body):
        raise ContinuityExportError("export:root")
    return value, snapshot, result


def _restore_fault(point: str) -> None:
    global _restore_fault_point
    if _restore_fault_point == point:
        _restore_fault_point = None
        raise InjectedRestoreFault(f"restore:injected:{point}")


def _map_restore_error(exc: BaseException) -> ContinuityExportError:
    text = str(exc)
    if text.startswith("restore-publication:"):
        suffix = text.split(":", 1)[1]
        mapping = {
            "staging-foreign": "restore:staging-foreign",
            "staging-state": "restore:staging-state",
            "staging-marker": "restore:staging-marker",
            "staging-marker-binding": "restore:staging-marker",
            "lock-binding": "restore:lock-binding",
            "existing-object": "restore:target-object",
            "existing-invalid": "restore:target-conflict",
            "semantic-conflict": "restore:target-conflict",
            "target-sidecar-existing": "restore:target-sidecar-existing",
            "target-sidecar-nonempty": "restore:target-sidecar-nonempty",
            "database": "restore:staging-invalid",
            "checkpoint-busy": "restore:staging-sidecar-nonempty",
            "checkpoint-result": "restore:staging-sidecar-nonempty",
            "staging-sidecar-nonempty": "restore:staging-sidecar-nonempty",
        }
        return ContinuityExportError(mapping.get(suffix, "restore:" + suffix))
    if isinstance(exc, ContinuityExportError):
        return exc
    return ContinuityExportError("restore:publication")


def verify_export_bytes(raw: bytes, graph_profile_registry: Mapping[str, object] | None = None) -> dict[str, object]:
    _value, _snapshot, result = _decode_and_verify(raw, graph_profile_registry=graph_profile_registry)
    return {"accepted": True, "schema_version": store.SCHEMA_VERSION, "artifact_count": result["artifact_count"], "event_count": result["event_count"], "receipt_count": result["receipt_count"], "head_count": result["head_count"], "export_bytes": len(raw)}


def export_database(path: str | Path, graph_profile_registry: Mapping[str, object] | None = None) -> bytes:
    """Read, verify, and encode one explicit SQLite snapshot."""
    try:
        snap = independent.snapshot_database(path, graph_profile_registry=graph_profile_registry)
    except AttributeError:
        raise ContinuityExportError("export:snapshot-owner")
    verified = dict(snap["evidence"])
    rows = _encode_rows(snap["snapshot"])
    body: dict[str, object] = {
        "schema": EXPORT_SCHEMA, "schema_version": store.SCHEMA_VERSION, "software": dict(SOFTWARE_IDENTITIES),
        **rows, "state_root": verified["state_root"], "state_owned": True, "support_safe": False,
        "synthetic_only": True, "production_usable": False,
    }
    value = {**body, "export_root": _digest("export-root", body)}
    raw = _canonical(value)
    if len(raw) > MAX_EXPORT_BYTES:
        raise ContinuityExportError("export:byte-cap")
    verify_export_bytes(raw, graph_profile_registry=graph_profile_registry)
    return raw


def _restore_destination(destination: str | Path) -> Path:
    if not isinstance(destination, (str, Path)):
        raise ContinuityExportError("restore:destination")
    try:
        value = os.fspath(destination)
    except TypeError as exc:
        raise ContinuityExportError("restore:destination") from None
    if isinstance(value, bytes):
        raise ContinuityExportError("restore:destination")
    target = Path(os.path.abspath(value))
    if not target.name or len(target.name.encode("utf-8")) > 128:
        raise ContinuityExportError("restore:target-name")
    if not target.parent.exists():
        raise ContinuityExportError("restore:parent-missing")
    if target.parent.is_symlink() or not target.parent.is_dir():
        raise ContinuityExportError("restore:parent-object")
    return target


def import_export(raw: bytes, destination: str | Path, graph_profile_registry: Mapping[str, object] | None = None) -> dict[str, object]:
    value, snapshot, expected = _decode_and_verify(raw, graph_profile_registry=graph_profile_registry)
    target = _restore_destination(destination)

    def build_stage(stage: Path) -> None:
        service = store.ContinuityStore(stage, graph_profile_registry=graph_profile_registry)
        _restore_fault("after_empty_staging_db_creation")
        service._restore_snapshot(snapshot)
        _restore_fault("after_snapshot_transaction")

    def verify_database(path: Path) -> object:
        return independent.verify_database(path, graph_profile_registry=graph_profile_registry)

    def result_factory(_path: Path) -> dict[str, object]:
        return {"accepted": True, "restored": True, **expected}

    def fault(point: str) -> None:
        _restore_fault(point)

    try:
        result = restore_publication.publish_create_only(
            target, export_root=str(value["export_root"]), expected_evidence={**expected, "export_root": value["export_root"]}, build_stage=build_stage,
            verify_database=verify_database, result_factory=result_factory,
            fault_injector=fault,
        )
        return result if isinstance(result, dict) else result_factory(target)
    except InjectedRestoreFault:
        raise
    except (restore_publication.RestorePublicationError, OSError, ValueError) as exc:
        raise _map_restore_error(exc) from None


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("REJECT usage", file=sys.stderr)
        return 2
    try:
        raw = Path(args[0]).read_bytes()
        print(_canonical(verify_export_bytes(raw)).decode("ascii"))
        return 0
    except Exception:
        print("REJECT input", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
