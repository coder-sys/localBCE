"""A refused evaluator frame, kept for diagnosis beside the store."""

import hashlib
import os
import secrets
from pathlib import Path

_FOLDER_LIMIT = 256 * 1024 * 1024  # bytes: a full folder keeps no more frames


def keep(wire: bytes, connection, is_reparse) -> str:
    """Write the frame once as refused/<SHA3-512>.bin beside the store; return the hash for the refusal's cause.  Whatever goes
    wrong (no store folder, a link where the folder should be, a full folder, a failed write, a file of other bytes under the
    name) leaves the refusal standing, and the cause then says the bytes were not kept (or not kept: the folder is full)."""
    digest = hashlib.sha3_512(wire).hexdigest()
    try:
        store_file = connection.execute("PRAGMA database_list").fetchone()[2]
        if not store_file:
            return f"{digest}:not_kept"
        folder = Path(store_file).parent / "refused"
        if is_reparse(folder) or is_reparse(folder.parent):
            return f"{digest}:not_kept"
        folder.mkdir(exist_ok=True)
        target = folder / f"{digest}.bin"
        if is_reparse(target):
            return f"{digest}:not_kept"
        if target.exists():  # kept before: the same bytes, or the cause says not kept
            return digest if target.read_bytes() == wire else f"{digest}:not_kept"
        if sum(entry.stat().st_size for entry in folder.iterdir()) > _FOLDER_LIMIT:
            return f"{digest}:not_kept_full"
        temporary = folder / f"{digest}.{os.getpid()}.{secrets.token_hex(8)}.tmp"  # one name per call, never shared
        try:
            with open(temporary, "xb") as handle:
                handle.write(wire)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        except BaseException:
            temporary.unlink(missing_ok=True)  # a failed write leaves nothing that counts toward the folder limit
            raise
    except Exception:  # noqa: BLE001 - any error: the refusal is the same
        return f"{digest}:not_kept"
    return digest


def run(evaluate, wire: bytes, connection, error_type: type, cause: str, is_reparse):
    """``evaluate(wire)``; a refusal whose message is the decode cause also names the kept frame by its hash."""
    try:
        return evaluate(wire)
    except error_type as error:
        if str(error) != cause:
            raise
        raise error_type(f"{cause}:{keep(wire, connection, is_reparse)}") from None
