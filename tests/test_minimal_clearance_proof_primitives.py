from __future__ import annotations

import ctypes
import hashlib
from pathlib import Path
import os
import stat
from types import SimpleNamespace

import pytest

from app import minimal_clearance_proof_primitives as proof


def _metadata(*, inode: int = 7, size: int = 3, mtime: int = 11, mode: int | None = None):
    return SimpleNamespace(
        st_dev=2,
        st_ino=inode,
        st_size=size,
        st_mtime_ns=mtime,
        st_mode=stat.S_IFREG if mode is None else mode,
    )


def test_windows_by_handle_file_information_abi() -> None:
    information = proof._ByHandleFileInformation
    assert ctypes.sizeof(information) == 52
    assert information.dwFileAttributes.offset == 0
    assert information.ftCreationTime.offset == 4
    assert information.ftLastAccessTime.offset == 12
    assert information.ftLastWriteTime.offset == 20
    assert information.dwVolumeSerialNumber.offset == 28
    assert information.nFileSizeHigh.offset == 32
    assert information.nFileSizeLow.offset == 36
    assert information.nNumberOfLinks.offset == 40
    assert information.nFileIndexHigh.offset == 44
    assert information.nFileIndexLow.offset == 48


@pytest.mark.skipif(os.name != "nt", reason="requires the real Windows file-custody ABI")
def test_real_windows_held_file_custody(tmp_path: Path) -> None:
    path = tmp_path / "ordinary-executable-shaped.bin"
    payload = b"held-file-custody"
    path.write_bytes(payload)

    held = proof._open_held_file(path, maximum=4096, executable=True)
    try:
        assert held.path == path
        held._assert_path_and_chain()
        assert held._read_held() == payload
        size, digest = held.digest("sha256")
        assert size == len(payload)
        assert digest == hashlib.sha256(payload).digest()
        held.reset()
        held._assert_path_and_chain()
        assert held.descriptor >= 0
    finally:
        held.close()
    assert path.read_bytes() == payload


def test_stable_read_is_descriptor_owned_and_bounded(tmp_path: Path) -> None:
    source = tmp_path / "artifact.bin"
    source.write_bytes(b"stable")
    assert proof._read_bounded_regular_file(
        source, maximum=16, label="proof_artifact"
    ) == b"stable"


@pytest.mark.parametrize("mode", [stat.S_IFLNK, stat.S_IFDIR])
def test_symlink_or_nonregular_is_rejected_before_open(monkeypatch, mode: int) -> None:
    opened = False

    def fail_open(*_args, **_kwargs):
        nonlocal opened
        opened = True
        raise AssertionError("opened nonregular input")

    monkeypatch.setattr(proof.os, "lstat", lambda _path: _metadata(mode=mode))
    monkeypatch.setattr(proof.os, "open", fail_open)
    with pytest.raises(proof.MinimalClearanceProofStateError, match="artifact_not_regular_file"):
        proof._read_bounded_regular_file(Path("opaque"), maximum=16, label="artifact")
    assert not opened


def test_oversize_and_sparse_input_is_rejected_without_open(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "sparse.bin"
    with source.open("wb") as handle:
        handle.seek(64 * 1024)
        handle.write(b"x")
    opened = False

    def fail_open(*_args, **_kwargs):
        nonlocal opened
        opened = True
        raise AssertionError("oversize input was opened")

    monkeypatch.setattr(proof.os, "open", fail_open)
    with pytest.raises(proof.MinimalClearanceProofStateError, match="artifact_size"):
        proof._read_bounded_regular_file(source, maximum=1024, label="artifact")
    assert not opened


@pytest.mark.parametrize("kind", ["replacement", "growth", "truncation", "mtime"])
def test_post_read_identity_drift_is_rejected(monkeypatch, kind: str) -> None:
    before = _metadata()
    opened = _metadata()
    changed = {
        "replacement": _metadata(inode=8),
        "growth": _metadata(size=4),
        "truncation": _metadata(size=2),
        "mtime": _metadata(mtime=12),
    }[kind]
    path_stats = iter((before, changed))
    descriptor_stats = iter((opened, changed))
    monkeypatch.setattr(proof.os, "lstat", lambda _path: next(path_stats))
    monkeypatch.setattr(proof.os, "open", lambda *_args: 99)
    monkeypatch.setattr(proof.os, "fstat", lambda _fd: next(descriptor_stats))
    reads = iter((b"abc", b""))
    monkeypatch.setattr(proof.os, "read", lambda _fd, _size: next(reads))
    monkeypatch.setattr(proof.os, "close", lambda _fd: None)
    with pytest.raises(proof.MinimalClearanceProofStateError, match="artifact_identity"):
        proof._read_bounded_regular_file(Path("opaque"), maximum=16, label="artifact")


def test_read_failure_is_fixed_and_does_not_expose_input(monkeypatch) -> None:
    metadata = _metadata()
    monkeypatch.setattr(proof.os, "lstat", lambda _path: metadata)
    monkeypatch.setattr(proof.os, "open", lambda *_args: 99)
    monkeypatch.setattr(proof.os, "fstat", lambda _fd: metadata)
    monkeypatch.setattr(proof.os, "read", lambda *_args: (_ for _ in ()).throw(OSError("C:\\secret\\PHI")))
    monkeypatch.setattr(proof.os, "close", lambda _fd: None)
    with pytest.raises(proof.MinimalClearanceProofStateError) as raised:
        proof._read_bounded_regular_file(Path("C:\\secret\\PHI"), maximum=16, label="artifact")
    error = raised.value
    assert str(error) == "artifact_read"
    assert "PHI" not in repr(error)
    assert error.__cause__ is None
    assert error.__context__ is None


def test_snapshot_path_never_uses_unbounded_path_read_bytes(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"snapshot")
    destination = tmp_path / "private"
    destination.mkdir()
    monkeypatch.setattr(Path, "read_bytes", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Path.read_bytes")))
    target, raw = proof._snapshot_verified_file(
        source, destination, label="proof-artifact", maximum=32
    )
    assert target.is_file()
    assert raw == b"snapshot"
    with target.open("rb") as handle:
        assert handle.read() == raw


def test_snapshot_mismatch_is_rejected(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"snapshot")
    destination = tmp_path / "private"
    destination.mkdir()
    reads = iter((b"snapshot", b"tampered"))
    monkeypatch.setattr(
        proof, "_read_bounded_regular_file",
        lambda *_args, **_kwargs: next(reads),
    )
    with pytest.raises(
        proof.MinimalClearanceProofStateError, match="proof-artifact_snapshot_mismatch"
    ):
        proof._snapshot_verified_file(
            source, destination, label="proof-artifact", maximum=32
        )


def test_identity_recheck_uses_the_same_bounded_reader(monkeypatch, tmp_path: Path) -> None:
    verifier = object.__new__(proof.NativeMinimalClearanceVerifier)
    verifier.executable = tmp_path / "verifier.exe"
    expected = b"verifier"
    verifier._executable_sha256 = hashlib.sha256(expected).digest()
    calls: list[tuple[Path, int, str]] = []

    def bounded(path: Path, *, maximum: int, label: str) -> bytes:
        calls.append((path, maximum, label))
        return expected

    monkeypatch.setattr(proof, "_read_bounded_regular_file", bounded)
    assert verifier.identity_sha256() == verifier._executable_sha256
    assert calls == [(verifier.executable, proof._MAX_EXECUTABLE_BYTES, "verifier_executable")]


def test_source_has_no_unbounded_proof_snapshot_read_bytes() -> None:
    source = Path(proof.__file__).read_text(encoding="utf-8")
    assert "read_bytes(" not in source
