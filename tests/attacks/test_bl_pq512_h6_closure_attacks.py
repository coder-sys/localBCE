from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from experiments.bl_pq512_crypto_foundation.h6_complete_simulator import (
    H6SimulatorError,
    simulate_malformed,
    simulate_valid,
)
from experiments.bl_pq512_crypto_foundation.h6_migration_theorem import (
    verify_h6_migration_mutation_rejection,
)
from experiments.bl_pq512_crypto_foundation.h6_receipt_grammar import (
    H6ReceiptGrammarError,
    encode_receipt,
    parse_receipt,
)
from experiments.bl_pq512_crypto_foundation.h6_security_ledger import (
    TARGET_BITS,
    build_h6_security_ledger,
)
from experiments.bl_pq512_crypto_foundation.h6_supply_chain import (
    H6SupplyChainError,
    verify_h6_supply_chain,
)


os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_DEV", "1")
os.environ.setdefault("BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE", "1")


def _fields() -> tuple[bytes, ...]:
    return tuple(bytes((index + 1,)) * 64 for index in range(7))


def test_h6_receipt_zero_identity_and_header_mutations_reject() -> None:
    receipt = encode_receipt(_fields())
    with pytest.raises(H6ReceiptGrammarError, match="invalid"):
        encode_receipt((b"\x00" * 64,) + _fields()[1:])
    for offset, expected in ((0, "magic"), (10, "flags"), (12, "declared")):
        mutated = bytearray(receipt)
        mutated[offset] ^= 1
        with pytest.raises(H6ReceiptGrammarError, match=expected):
            parse_receipt(bytes(mutated))
    mutated = bytearray(receipt)
    mutated[-1] = 1
    with pytest.raises(H6ReceiptGrammarError, match="reserved"):
        parse_receipt(bytes(mutated))


def test_h6_simulator_rejects_malformed_profile_and_unknown_case() -> None:
    with pytest.raises(H6SimulatorError, match="profile|case"):
        simulate_malformed(256, "TRUNCATED_HEADER")
    with pytest.raises(H6SimulatorError, match="case"):
        simulate_malformed(128, "UNKNOWN")
    with pytest.raises(H6SimulatorError, match="input_invalid"):
        simulate_valid(
            128,
            "APPROVAL\x00",
            logical_attempt=b"attempt",
            proof_randomness=b"fresh",
        )


def test_h6_security_ledger_mutation_does_not_meet_floor() -> None:
    ledger = build_h6_security_ledger()
    assert ledger.qualifies
    assert ledger.target_bits == TARGET_BITS
    assert ledger.__class__(
        status=ledger.status,
        theorem_source=ledger.theorem_source,
        mca_assumption=ledger.mca_assumption,
        target_bits=TARGET_BITS + 1,
        target_count=ledger.target_count,
        max_retries=ledger.max_retries,
        terms=ledger.terms,
        composed_iopp_error=ledger.composed_iopp_error,
        composed_iopp_bits=ledger.composed_iopp_bits,
        multi_target_error=ledger.multi_target_error,
        multi_target_bits=ledger.multi_target_bits,
        retry_error=ledger.retry_error,
        retry_bits=ledger.retry_bits,
        abort_error=ledger.abort_error,
        abort_bits=ledger.abort_bits,
        source_manifest_sha3_512=ledger.source_manifest_sha3_512,
        ledger_digest_sha3_512=ledger.ledger_digest_sha3_512,
    ).qualifies is False


def test_h6_migration_root_mutation_rejects() -> None:
    verify_h6_migration_mutation_rejection()


def test_h6_supply_chain_missing_third_party_license_rejects(tmp_path: Path) -> None:
    crate = Path(__file__).resolve().parents[2] / "experiments" / "bl_pq512_crypto_core"
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
            str(crate / "Cargo.toml"),
        ),
        cwd=crate,
        check=True,
        capture_output=True,
        timeout=120,
    )
    value = json.loads(completed.stdout)
    for package in value["packages"]:
        if package["source"] is not None:
            package["license"] = None
            break
    metadata = tmp_path / "tampered-metadata.json"
    metadata.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(H6SupplyChainError, match="license_missing"):
        verify_h6_supply_chain(metadata, sbom_path=None)
