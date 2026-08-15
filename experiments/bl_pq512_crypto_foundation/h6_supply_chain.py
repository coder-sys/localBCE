"""Bounded proof-core supply-chain and deterministic SBOM verifier for H6.

The scope is the nonactivating BL-PQ512 proof candidate, not the unfinished
whole-product release.  It rejects an incomplete Cargo graph, an unpinned
toolchain, an unlicensed third-party package record, or missing module/CUDA/
schema/parameter/manifest inputs.  The local synthetic source package is
explicitly marked ``NOASSERTION_INTERNAL_SYNTHETIC_SCOPE`` rather than being
given an invented legal license.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import tomllib
from typing import Final


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
CRATE: Final[Path] = ROOT / "experiments" / "bl_pq512_crypto_core"
ROOT_PACKAGE: Final[str] = "bl_pq512_crypto_core"
EXPECTED_RUST_VERSION: Final[str] = "1.96.0"
EXPECTED_EDITION: Final[str] = "2024"
EXPECTED_PLATFORM: Final[str] = "x86_64-pc-windows-msvc"
ROOT_LICENSE_STATUS: Final[str] = "NOASSERTION_INTERNAL_SYNTHETIC_SCOPE"
STATUS: Final[str] = "H6_SUPPLY_CHAIN_V1_NONACTIVATING"

EXPECTED_DIRECT_REQUIREMENTS: Final[dict[str, str]] = {
    "getrandom": "=0.3.4",
    "ml-dsa": "=0.1.1",
    "sha3": "=0.10.9",
    "slh-dsa": "=0.2.0-rc.5",
    "zeroize": "=1.9.0",
}

PIN_GROUPS: Final[dict[str, tuple[str, ...]]] = {
    "source": (
        "experiments/bl_pq512_crypto_core/Cargo.toml",
        "experiments/bl_pq512_crypto_core/Cargo.lock",
        "experiments/bl_pq512_crypto_core/rust-toolchain.toml",
        "experiments/bl_pq512_crypto_core/.cargo/config.toml",
        "experiments/bl_pq512_crypto_core/src/lib.rs",
        "experiments/bl_pq512_crypto_core/src/h6_proof_body_format.rs",
        "experiments/bl_pq512_crypto_core/src/h6_receipt_format.rs",
        "experiments/bl_pq512_crypto_core/src/bin/h6_proof_body_kat.rs",
        "experiments/bl_pq512_crypto_core/src/bin/h6_receipt_grammar_kat.rs",
        "experiments/bl_pq512_crypto_foundation/proof_body_reference.py",
        "experiments/bl_pq512_crypto_foundation/h6_receipt_grammar.py",
        "experiments/bl_pq512_crypto_foundation/h6_complete_simulator.py",
        "experiments/bl_pq512_crypto_foundation/native_hiding_simulator.py",
        "experiments/bl_pq512_crypto_foundation/h6_security_ledger.py",
        "experiments/bl_pq512_crypto_foundation/h6_privacy_boundary.py",
    ),
    "cuda": (
        "experiments/bl_pq512_crypto_core/cuda/fp16_zk_rs_security_ledger.py",
        "experiments/bl_pq512_crypto_core/cuda/fp16_zk_rs_hiding_simulator_kat.py",
    ),
    "schema": (
        "schemas/bl_pq512_witness_v0.schema.json",
        "ops/native_stark_public_inputs_v2.json",
    ),
    "parameter": (
        "experiments/bl_pq512_crypto_core/src/proof_parameters.rs",
        "docs/bl_pq512_suite_candidate_v1.json",
    ),
    "manifest": (
        "experiments/bl_pq512_crypto_core/Cargo.lock",
        "ops/oracle_source_manifest.example.json",
    ),
}

_PURL_ID = re.compile(r"#([^@]+)@(.+)$")


class H6SupplyChainError(ValueError):
    """Stable fail-closed error for an incomplete proof-core supply chain."""


@dataclass(frozen=True, slots=True)
class H6SupplyChainFacts:
    package_count: int
    third_party_package_count: int
    source_pin_count: int
    source_pin_digest_512: bytes
    sbom_digest_512: bytes
    root_license_status: str
    platform: str
    rust_version: str
    cargo_version: str

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "package_count": self.package_count,
            "third_party_package_count": self.third_party_package_count,
            "source_pin_count": self.source_pin_count,
            "source_pin_digest_sha3_512": self.source_pin_digest_512.hex(),
            "sbom_digest_sha3_512": self.sbom_digest_512.hex(),
            "root_license_status": self.root_license_status,
            "platform": self.platform,
            "rust_version": self.rust_version,
            "cargo_version": self.cargo_version,
            "proofSuiteId": None,
            "activationAllowed": False,
        }


def _read_regular(relative: str) -> bytes:
    path = ROOT / Path(relative)
    if path.is_symlink() or not path.is_file():
        raise H6SupplyChainError(f"h6_supply_chain_missing:{relative}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise H6SupplyChainError(f"h6_supply_chain_read_failed:{relative}") from exc


def _pin_records() -> tuple[dict[str, object], ...]:
    records: list[dict[str, object]] = []
    for group, paths in PIN_GROUPS.items():
        for relative in paths:
            data = _read_regular(relative)
            records.append(
                {
                    "group": group,
                    "path": relative,
                    "size": len(data),
                    "sha3_512": hashlib.sha3_512(data).hexdigest(),
                }
            )
    return tuple(records)


def _load_json(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise H6SupplyChainError("h6_supply_chain_metadata_missing")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise H6SupplyChainError("h6_supply_chain_metadata_invalid") from exc
    if type(value) is not dict:
        raise H6SupplyChainError("h6_supply_chain_metadata_root_invalid")
    return value


def _package_key(package: dict[str, object]) -> tuple[str, str, str | None]:
    name = package.get("name")
    version = package.get("version")
    source = package.get("source")
    if type(name) is not str or not name or type(version) is not str or not version:
        raise H6SupplyChainError("h6_supply_chain_package_identity_invalid")
    if source is not None and type(source) is not str:
        raise H6SupplyChainError("h6_supply_chain_package_source_invalid")
    return name, version, source


def _verify_metadata(metadata: dict[str, object]) -> tuple[list[dict[str, object]], dict[str, object]]:
    if metadata.get("version") != 1:
        raise H6SupplyChainError("h6_supply_chain_metadata_version_invalid")
    packages = metadata.get("packages")
    if type(packages) is not list or not packages:
        raise H6SupplyChainError("h6_supply_chain_packages_invalid")
    records = [package for package in packages if type(package) is dict]
    if len(records) != len(packages):
        raise H6SupplyChainError("h6_supply_chain_package_record_invalid")
    keyed = [_package_key(package) for package in records]
    if len(set(keyed)) != len(keyed):
        raise H6SupplyChainError("h6_supply_chain_package_duplicate")
    roots = [package for package in records if package.get("name") == ROOT_PACKAGE]
    if len(roots) != 1:
        raise H6SupplyChainError("h6_supply_chain_root_package_invalid")
    root = roots[0]
    if root.get("version") != "0.1.0" or root.get("edition") != EXPECTED_EDITION:
        raise H6SupplyChainError("h6_supply_chain_root_version_invalid")
    if root.get("rust_version") not in {"1.96", EXPECTED_RUST_VERSION}:
        raise H6SupplyChainError("h6_supply_chain_root_rust_version_invalid")
    manifest_path = root.get("manifest_path")
    if type(manifest_path) is not str or Path(manifest_path).resolve() != (CRATE / "Cargo.toml").resolve():
        raise H6SupplyChainError("h6_supply_chain_root_manifest_invalid")
    if root.get("source") is not None or root.get("license") is not None:
        raise H6SupplyChainError("h6_supply_chain_root_scope_drift")
    dependencies = root.get("dependencies")
    if type(dependencies) is not list:
        raise H6SupplyChainError("h6_supply_chain_root_dependencies_invalid")
    observed_direct: dict[str, str] = {}
    for dependency in dependencies:
        if type(dependency) is not dict:
            raise H6SupplyChainError("h6_supply_chain_direct_dependency_invalid")
        name = dependency.get("name")
        requirement = dependency.get("req")
        source = dependency.get("source")
        if type(name) is not str or type(requirement) is not str or source != "registry+https://github.com/rust-lang/crates.io-index":
            raise H6SupplyChainError("h6_supply_chain_direct_dependency_source_invalid")
        observed_direct[name] = requirement
    if observed_direct != EXPECTED_DIRECT_REQUIREMENTS:
        raise H6SupplyChainError("h6_supply_chain_direct_dependency_pin_mismatch")
    for package in records:
        if package is root:
            continue
        source = package.get("source")
        license_value = package.get("license")
        if source != "registry+https://github.com/rust-lang/crates.io-index":
            raise H6SupplyChainError("h6_supply_chain_third_party_source_invalid")
        if type(license_value) is not str or not license_value.strip():
            raise H6SupplyChainError(
                f"h6_supply_chain_third_party_license_missing:{package['name']}@{package['version']}"
            )
    resolve = metadata.get("resolve")
    if type(resolve) is not dict or resolve.get("root") != root.get("id"):
        raise H6SupplyChainError("h6_supply_chain_resolve_root_invalid")
    return records, root


def _verify_lock(records: list[dict[str, object]]) -> None:
    try:
        lock = tomllib.loads(_read_regular("experiments/bl_pq512_crypto_core/Cargo.lock").decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise H6SupplyChainError("h6_supply_chain_lock_invalid") from exc
    if lock.get("version") != 4 or type(lock.get("package")) is not list:
        raise H6SupplyChainError("h6_supply_chain_lock_version_invalid")
    lock_records = [record for record in lock["package"] if type(record) is dict]
    lock_keys: dict[tuple[str, str, str | None], dict[str, object]] = {}
    for record in lock_records:
        key = _package_key(record)
        if key in lock_keys:
            raise H6SupplyChainError("h6_supply_chain_lock_duplicate")
        lock_keys[key] = record
    for package in records:
        key = _package_key(package)
        locked = lock_keys.get(key)
        if locked is None:
            raise H6SupplyChainError(
                f"h6_supply_chain_lock_missing:{package['name']}@{package['version']}"
            )
        if key[2] is not None and (
            type(locked.get("checksum")) is not str or not locked["checksum"]
        ):
            raise H6SupplyChainError(
                f"h6_supply_chain_checksum_missing:{package['name']}@{package['version']}"
            )


def _verify_toolchain() -> tuple[str, str]:
    toolchain = _read_regular("experiments/bl_pq512_crypto_core/rust-toolchain.toml").decode("utf-8")
    if 'channel = "1.96.0"' not in toolchain or EXPECTED_PLATFORM not in toolchain:
        raise H6SupplyChainError("h6_supply_chain_toolchain_pin_invalid")
    config = _read_regular("experiments/bl_pq512_crypto_core/.cargo/config.toml").decode("utf-8")
    for required in ("codegen-units = 1", "incremental = false", "/DEBUG:NONE", "/Brepro"):
        if required not in config:
            raise H6SupplyChainError("h6_supply_chain_build_flag_pin_invalid")
    return EXPECTED_RUST_VERSION, "cargo-1.96.0"


def _spdx_package(package: dict[str, object], root: dict[str, object]) -> dict[str, object]:
    name = str(package["name"])
    version = str(package["version"])
    source = package.get("source")
    identity = hashlib.sha3_512(f"{name}@{version}@{source}".encode("utf-8")).hexdigest()[:32]
    record: dict[str, object] = {
        "SPDXID": f"SPDXRef-Package-{identity}",
        "name": name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION" if source is None else str(source),
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": (
            ROOT_LICENSE_STATUS if package is root else str(package["license"])
        ),
        "copyrightText": "NOASSERTION",
    }
    if source is not None:
        match = _PURL_ID.search(str(package["id"]))
        if match is not None:
            record["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:cargo/{match.group(1)}@{match.group(2)}",
                }
            ]
    return record


def write_h6_spdx(metadata_path: Path, output_path: Path) -> H6SupplyChainFacts:
    verify_h6_supply_chain(metadata_path, sbom_path=None)
    metadata = _load_json(metadata_path)
    records, root = _verify_metadata(metadata)
    packages = [_spdx_package(package, root) for package in records]
    root_id = next(package["SPDXID"] for package in packages if package["name"] == ROOT_PACKAGE)
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "BL-PQ512 H6 proof-core candidate SBOM",
        "documentNamespace": "https://blind-ledger.invalid/spdx/h6-proof-core-v1",
        "creationInfo": {
            "created": "2026-08-04T00:00:00Z",
            "creators": ["Tool: BL-PQ512 H6 bounded supply-chain verifier"],
        },
        "documentDescribes": [root_id],
        "packages": packages,
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encoded)
    return verify_h6_supply_chain(metadata_path, sbom_path=output_path)


def verify_h6_supply_chain(metadata_path: Path, *, sbom_path: Path | None) -> H6SupplyChainFacts:
    metadata = _load_json(metadata_path)
    records, _ = _verify_metadata(metadata)
    _verify_lock(records)
    rust_version, cargo_version = _verify_toolchain()
    pins = _pin_records()
    pin_digest = hashlib.sha3_512(
        json.dumps(pins, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).digest()
    if sbom_path is None:
        sbom_digest = b"\x00" * 64
    else:
        if sbom_path.is_symlink() or not sbom_path.is_file():
            raise H6SupplyChainError("h6_supply_chain_sbom_missing")
        sbom_bytes = sbom_path.read_bytes()
        sbom_digest = hashlib.sha3_512(sbom_bytes).digest()
        sbom = _load_json(sbom_path)
        packages = sbom.get("packages")
        if type(packages) is not list or len(packages) != len(records):
            raise H6SupplyChainError("h6_supply_chain_sbom_package_count_invalid")
        observed = {(item.get("name"), item.get("versionInfo")) for item in packages if type(item) is dict}
        expected = {(item.get("name"), item.get("version")) for item in records}
        if observed != expected:
            raise H6SupplyChainError("h6_supply_chain_sbom_package_identity_invalid")
        root_items = [item for item in packages if item.get("name") == ROOT_PACKAGE]
        if len(root_items) != 1 or root_items[0].get("licenseDeclared") != ROOT_LICENSE_STATUS:
            raise H6SupplyChainError("h6_supply_chain_sbom_root_license_scope_invalid")
    return H6SupplyChainFacts(
        package_count=len(records),
        third_party_package_count=len(records) - 1,
        source_pin_count=len(pins),
        source_pin_digest_512=pin_digest,
        sbom_digest_512=sbom_digest,
        root_license_status=ROOT_LICENSE_STATUS,
        platform=EXPECTED_PLATFORM,
        rust_version=rust_version,
        cargo_version=cargo_version,
    )


__all__: tuple[str, ...] = (
    "EXPECTED_PLATFORM",
    "H6SupplyChainError",
    "H6SupplyChainFacts",
    "ROOT_LICENSE_STATUS",
    "STATUS",
    "verify_h6_supply_chain",
    "write_h6_spdx",
)
