from __future__ import annotations

from pathlib import Path

import pytest

from experiments.bl_pq512_crypto_foundation.application_sha3_port_inventory import (
    SCANNED_PATHS,
    require_inventory_consistent,
)


def _copy_governed_inventory_sources(tmp_path: Path) -> Path:
    source_root = Path(__file__).resolve().parents[2]
    for relative in SCANNED_PATHS:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((source_root / relative).read_bytes())
    return source_root


def test_unclassified_sha3_callsite_is_rejected(tmp_path: Path) -> None:
    _copy_governed_inventory_sources(tmp_path)
    target = tmp_path / "app/batch/pq_sparse_tree_reference.py"
    target.write_text(
        target.read_text(encoding="utf-8")
        + "\n\ndef unreviewed_hash_port(data: bytes) -> bytes:\n"
        + "    return sha3_512(data).digest()\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="static_callsite_drift"):
        require_inventory_consistent(tmp_path)


def test_removed_sha3_callsite_is_rejected(tmp_path: Path) -> None:
    _copy_governed_inventory_sources(tmp_path)
    target = tmp_path / "app/batch/pq_sparse_tree_reference.py"
    target.write_text(
        target.read_text(encoding="utf-8").replace(
            "return sha3_512(preimage).digest()",
            "return bytes(64)",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="static_callsite_drift"):
        require_inventory_consistent(tmp_path)


def test_new_governed_file_sha3_callsite_is_rejected(tmp_path: Path) -> None:
    _copy_governed_inventory_sources(tmp_path)
    target = tmp_path / "app/batch/unreviewed_hash_port.py"
    target.write_text(
        "from hashlib import sha3_512\n\n"
        "def unreviewed_hash_port(data: bytes) -> bytes:\n"
        "    return sha3_512(data).digest()\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="static_callsite_drift"):
        require_inventory_consistent(tmp_path)


@pytest.mark.parametrize(
    "source,form",
    (
        (
            "from hashlib import sha3_512 as hidden_hash\n"
            "def hidden(data: bytes) -> bytes:\n"
            "    return hidden_hash(data).digest()\n",
            "aliased_sha3_512_import",
        ),
        (
            "import hashlib\n"
            "def hidden(data: bytes) -> bytes:\n"
            "    return hashlib.new('sha3_512', data).digest()\n",
            "hashlib_new_sha3_512_call",
        ),
        (
            "def hidden(data: bytes) -> bytes:\n"
            "    return __import__('hashlib').sha3_512(data).digest()\n",
            "dynamic_import_sha3_512_call",
        ),
    ),
)
def test_noncanonical_sha3_forms_are_rejected(
    tmp_path: Path, source: str, form: str
) -> None:
    _copy_governed_inventory_sources(tmp_path)
    target = tmp_path / "app/batch/unreviewed_hash_port.py"
    target.write_text(source, encoding="utf-8")
    with pytest.raises(ValueError, match=form):
        require_inventory_consistent(tmp_path)
