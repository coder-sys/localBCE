from __future__ import annotations

from pathlib import Path
import subprocess

from experiments.bl_pq512_crypto_foundation.h6_supply_chain import (
    ROOT_LICENSE_STATUS,
    verify_h6_supply_chain,
    write_h6_spdx,
)


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "experiments" / "bl_pq512_crypto_core"


def test_h6_supply_chain_is_locked_licensed_and_spdx_reconciled(tmp_path: Path) -> None:
    metadata = tmp_path / "metadata.json"
    completed = subprocess.run(
        (
            "cargo",
            "+1.96.0",
            "metadata",
            "--locked",
            "--offline",
            "--filter-platform",
            "x86_64-pc-windows-msvc",
            "--format-version",
            "1",
            "--manifest-path",
            str(CRATE / "Cargo.toml"),
        ),
        cwd=CRATE,
        check=True,
        capture_output=True,
        timeout=120,
    )
    metadata.write_bytes(completed.stdout)
    sbom = tmp_path / "h6-proof-core.spdx.json"
    written = write_h6_spdx(metadata, sbom)
    observed = verify_h6_supply_chain(metadata, sbom_path=sbom)
    assert written == observed
    assert observed.package_count >= 40
    assert observed.third_party_package_count == observed.package_count - 1
    assert observed.source_pin_count >= 20
    assert observed.root_license_status == ROOT_LICENSE_STATUS
    assert observed.as_public_dict()["proofSuiteId"] is None
    assert observed.as_public_dict()["activationAllowed"] is False
