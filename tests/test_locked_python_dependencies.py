from __future__ import annotations

from hashlib import sha256, sha3_512
import json
from pathlib import Path
from unittest import mock
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from tools import locked_python_dependencies as locked


ROOT = Path(__file__).resolve().parents[1]


def _make_wheel(directory: Path, *, embedded_name: str = "demo", version: str = "1.0") -> Path:
    path = directory / "demo-1.0-py3-none-any.whl"
    with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(
            "demo-1.0.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: {embedded_name}\nVersion: {version}\n\n",
        )
        archive.writestr("demo/__init__.py", "")
    return path


def _artifact(path: Path, *, name: str = "demo", version: str = "1.0") -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "filename": path.name,
        "license_declared": "MIT",
        "name": name,
        "pypi_url": f"https://files.pythonhosted.org/packages/example/{path.name}",
        "sha256": sha256(raw).hexdigest(),
        "sha3_512": sha3_512(raw).hexdigest(),
        "size": len(raw),
        "version": version,
    }


def test_current_manifest_locks_profiles_and_dual_hashes_reconcile() -> None:
    manifest, digests = locked._validate_manifest()
    assert digests.size == len(locked._canonical_json(manifest))
    assert len(digests.sha256) == 64
    assert len(digests.sha3_512) == 128
    production = {"cffi", "pqcrypto", "pycparser"}
    development = production | {
        "colorama",
        "iniconfig",
        "packaging",
        "pluggy",
        "pygments",
        "pytest",
    }
    assert set(manifest["profiles"]["production"]) == production
    assert set(manifest["profiles"]["development"]) == development
    assert set(manifest["locks"]) == {
        "cp314-linux_x86_64-development",
        "cp314-linux_x86_64-production",
        "cp314-win_amd64-development",
        "cp314-win_amd64-production",
    }
    assert all({item["name"] for item in items} == development for items in manifest["artifacts"].values())


def test_python_sbom_reconciles_every_logical_package_and_declared_license() -> None:
    manifest, _ = locked._validate_manifest()
    sbom = json.loads((ROOT / "docs/SBOM.python.spdx.json").read_text(encoding="utf-8"))
    packages = {
        package["name"]: package
        for package in sbom["packages"]
        if package["name"] != "blind-ledger-python-environment"
    }
    windows = {item["name"]: item for item in manifest["artifacts"]["cp314-win_amd64"]}
    linux = {item["name"]: item for item in manifest["artifacts"]["cp314-linux_x86_64"]}
    assert set(packages) == set(windows) == set(linux)
    assert set(packages) == set(manifest["profiles"]["development"])
    for name, package in packages.items():
        assert package["versionInfo"] == windows[name]["version"] == linux[name]["version"]
        assert package["licenseDeclared"] == windows[name]["license_declared"]
        assert package["licenseDeclared"] == linux[name]["license_declared"]
        assert package["licenseDeclared"] != "NOASSERTION"


def test_exact_wheelhouse_passes_dual_hash_and_embedded_metadata_checks(tmp_path: Path) -> None:
    wheel = _make_wheel(tmp_path)
    artifact = _artifact(wheel)
    assert locked._verify_wheelhouse(tmp_path, [artifact]) == (artifact,)


@pytest.mark.parametrize("mutation", ["missing", "extra", "sdist", "renamed", "tampered"])
def test_wheelhouse_file_set_and_content_bypasses_fail_closed(tmp_path: Path, mutation: str) -> None:
    wheel = _make_wheel(tmp_path)
    artifact = _artifact(wheel)
    if mutation == "missing":
        wheel.unlink()
    elif mutation == "extra":
        (tmp_path / "extra.whl").write_bytes(b"not reviewed")
    elif mutation == "sdist":
        (tmp_path / "demo-1.0.tar.gz").write_bytes(b"sdist")
    elif mutation == "renamed":
        wheel.rename(tmp_path / "renamed.whl")
    else:
        wheel.write_bytes(wheel.read_bytes() + b"tampered")
    with pytest.raises(locked.SupplyChainError):
        locked._verify_wheelhouse(tmp_path, [artifact])


def test_symlinked_wheel_fails_closed_when_platform_can_create_symlink(tmp_path: Path) -> None:
    source_dir = tmp_path / "source"
    wheelhouse = tmp_path / "wheelhouse"
    source_dir.mkdir()
    wheelhouse.mkdir()
    source = _make_wheel(source_dir)
    target = wheelhouse / source.name
    try:
        target.symlink_to(source)
    except OSError:
        pytest.skip("platform account cannot create symlinks")
    with pytest.raises(locked.SupplyChainError, match="symlink"):
        locked._verify_wheelhouse(wheelhouse, [_artifact(source)])


def test_embedded_metadata_substitution_fails_even_when_outer_hash_is_reviewed(tmp_path: Path) -> None:
    wheel = _make_wheel(tmp_path, embedded_name="attacker-package")
    artifact = _artifact(wheel, name="demo")
    with pytest.raises(locked.SupplyChainError, match="embedded Name/Version"):
        locked._verify_wheelhouse(tmp_path, [artifact])


@pytest.mark.parametrize(
    "lines",
    [
        "demo==1.0\n",
        "demo>=1.0 --hash=sha256:" + "0" * 64 + "\n",
        "demo==1.0 --hash=sha256:" + "0" * 64 + " --index-url=https://evil.invalid\n",
        "demo==1.0 --hash=sha256:" + "0" * 64 + "\ndemo==1.0 --hash=sha256:" + "0" * 64 + "\n",
    ],
)
def test_unhashed_ranged_option_injected_and_duplicate_lock_lines_fail(
    tmp_path: Path, lines: str
) -> None:
    path = tmp_path / "bad.lock"
    path.write_text(lines, encoding="utf-8")
    with pytest.raises(locked.SupplyChainError):
        locked._parse_lock(path)


def test_pip_command_is_fixed_offline_binary_only_hash_enforced_and_no_deps(
    tmp_path: Path,
) -> None:
    manifest, digests = locked._validate_manifest()
    record = manifest["locks"]["cp314-win_amd64-development"]
    verified = locked.VerifiedInputs(
        artifacts=(),
        lock=record,
        manifest=manifest,
        manifest_digests=digests,
        platform_key="cp314-win_amd64",
        profile="development",
        wheelhouse=tmp_path,
    )
    command = locked._offline_pip_command(verified)
    for required in (
        "--isolated",
        "--require-virtualenv",
        "--no-index",
        "--require-hashes",
        "--only-binary=:all:",
        "--no-deps",
        "--no-cache-dir",
        "--no-compile",
    ):
        assert command.count(required) == 1
    assert not any("http://" in item or "https://" in item for item in command)
    assert command[command.index("--find-links") + 1] == str(tmp_path)


def test_attestation_is_canonical_create_only_and_never_overwritten(tmp_path: Path) -> None:
    value = {"schema": "test", "z": 1, "a": 2}
    path = tmp_path / "audit.json"
    digests = locked._write_new_attestation(path, value)
    assert path.read_bytes() == b'{"a":2,"schema":"test","z":1}\n'
    assert digests.sha256 == sha256(path.read_bytes()).hexdigest()
    assert digests.sha3_512 == sha3_512(path.read_bytes()).hexdigest()
    with pytest.raises(locked.SupplyChainError, match="refusing overwrite"):
        locked._write_new_attestation(path, value)


def test_runtime_rejects_wrong_python_platform_and_pip_without_relaxation() -> None:
    manifest, _ = locked._validate_manifest()
    with mock.patch.object(locked.platform, "python_implementation", return_value="PyPy"):
        with pytest.raises(locked.SupplyChainError, match="CPython"):
            locked._runtime_platform(manifest)
    with mock.patch.object(locked.platform, "system", return_value="Darwin"):
        with pytest.raises(locked.SupplyChainError, match="unsupported runtime target"):
            locked._runtime_platform(manifest)
    wrong = json.loads(json.dumps(manifest))
    key = "cp314-win_amd64" if locked.platform.system() == "Windows" else "cp314-linux_x86_64"
    wrong["python"]["platforms"][key]["installer_pip_version"] = "0.0"
    with pytest.raises(locked.SupplyChainError, match="pip version differs"):
        locked._runtime_platform(wrong)
