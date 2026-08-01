from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

from app.batch.batch_orchestrator import BatchConfig
from app.batch.claim_source_root import claim_source_diagnosis_commitment
from app.batch.nullifier import IndexedNullifierTree
from app.batch.poseidon import FIELD_MODULUS, domain_poseidon_hash
from app.batch.stark_binding import (
    build_monolithic_batch_input_witness,
    flatten_multi_line_decision_input_witness,
)
from app.models import Patient, Provider, ServiceLine, SharedContext
from app.service_line_canonical import cents
from app.privacy_v2 import build_privacy_v2_bundle
from app.rules_engine_fallback import adjudicate


ROOT = Path(__file__).resolve().parents[1]
CAIRO_ROOT = ROOT / "zk-cairo-sharp"
RISC0_ROOT = ROOT / "experiments" / "risc0_privacy_v2"
V2_OUTPUT_NAMES = (
    "protocol_version",
    "settlement_domain",
    "batch_nonce",
    "nullifier_root_before",
    "nullifier_root_after",
    "claim_source_root",
    "oracle_facts_root",
    "policy_root",
    "ruleset_root",
    "opaque_batch_commitment",
    "value_conservation_commitment",
    "settlement_commitment",
)


def _text_commitment(domain: str, value: str) -> int:
    raw = value.encode("utf-8")
    words = [int.from_bytes(raw[index : index + 16], "big") for index in range(0, len(raw), 16)] or [0]
    accumulator = domain_poseidon_hash(domain, [len(raw), len(words)])
    for index, word in enumerate(words):
        accumulator = domain_poseidon_hash(
            domain,
            [len(raw), len(words), index, accumulator, word],
        )
    return accumulator


def _private_claim_commitment(ctx: SharedContext, claim_source_leaf: int) -> int:
    lines = sorted(
        ctx.service_lines,
        key=lambda line: (
            line.procedure_code,
            cents(line.charge_amount),
            cents(line.units),
            line.prior_authorization or "",
        ),
    )
    line_commitment = domain_poseidon_hash("claim", [len(lines)])
    for index, line in enumerate(lines):
        line_commitment = domain_poseidon_hash(
            "claim",
            [
                len(lines),
                index,
                line_commitment,
                _text_commitment("claim", line.line_id),
                _text_commitment("claim", line.procedure_code),
                cents(line.charge_amount),
                cents(line.units),
                _text_commitment("claim", line.prior_authorization or ""),
            ],
        )
    return domain_poseidon_hash(
        "claim",
        [
            1,
            _text_commitment("claim", ctx.claim_id),
            _text_commitment("claim", ctx.transaction_set),
            _text_commitment("claim", ctx.payer_id),
            _text_commitment("claim", ctx.member_id),
            _text_commitment("claim", ctx.patient.name),
            _text_commitment("claim", ctx.patient.id),
            _text_commitment("claim", ctx.provider.npi),
            _text_commitment("claim", ctx.provider.name),
            _text_commitment("claim", ctx.service_date),
            claim_source_diagnosis_commitment(ctx.diagnoses),
            line_commitment,
            cents(ctx.total_charge),
            int(claim_source_leaf),
        ],
    )


def _synthetic_bundle() -> tuple[dict, dict]:
    os.environ.setdefault("BL_DEV", "1")
    os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")
    ctx = SharedContext(
        claim_id="BL-RISC0-CLAIM-0001",
        transaction_set="837",
        payer_id="PAYER",
        member_id="M123456789",
        patient=Patient(name="Synthetic Jane", id="M123456789"),
        provider=Provider(npi="1999999984", name="Synthetic Provider"),
        service_date="20260601",
        diagnoses=["F840"],
        service_lines=[
            ServiceLine(
                line_id="1",
                procedure_code="T1019",
                charge_amount=0.29,
                units=1.00,
                prior_authorization="PA-OK-123",
            )
        ],
        total_charge=0.29,
        flags={
            "eligibility_active": True,
            "provider_enrolled": True,
            "provider_not_suspended": True,
            "not_deceased": True,
            "duplicate_claim": False,
            "program_integrity_hold": False,
        },
        fact_verification={"tar_authorization": "VERIFIED"},
    )
    config = BatchConfig()
    result = adjudicate(ctx, config.tar_required_procedure_codes, config.fee_schedule_cents)
    if not result.approved or cents(result.payable_amount) != 29:
        raise AssertionError(result.to_dict())
    batch = build_monolithic_batch_input_witness(
        [(ctx, result, "synthetic-evidence", "python_reference")],
        nullifier_tree=IndexedNullifierTree(),
        config=config,
    )
    claim = batch["witness"]["claims"][0]
    private_commitment = _private_claim_commitment(ctx, claim.claim.claim_source_leaf)
    v2 = build_privacy_v2_bundle(
        batch,
        settlement_domain=7001,
        batch_nonce=9001,
        private_data_commitment=private_commitment,
        privacy_salt=222,
        value_salt=333,
    )
    return batch, v2


U128_LIMIT = 1 << 128


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_program_output(stdout: str, expected_count: int) -> list[int]:
    if "Program output:" not in stdout:
        raise AssertionError(f"missing Cairo program output:\n{stdout}")
    limbs = [
        int(line)
        for line in stdout.split("Program output:", 1)[1].splitlines()
        if re.fullmatch(r"-?\d+", line.strip())
    ]
    expected_limbs = expected_count * 2
    if len(limbs) != expected_limbs:
        raise AssertionError(f"expected {expected_limbs} Cairo limbs, got {limbs}\n{stdout}")
    for index, limb in enumerate(limbs):
        if not 0 <= limb < U128_LIMIT:
            raise AssertionError(f"Cairo output limb[{index}] is not a u128: {limb}")
    values = [limbs[index] | (limbs[index + 1] << 128) for index in range(0, len(limbs), 2)]
    for index, value in enumerate(values):
        if not 0 <= value < FIELD_MODULUS:
            raise AssertionError(
                f"Cairo output[{index}] is not a canonical field element: {value}"
            )
    return values


def _run_cairo(executable: str, arguments: list[int]) -> list[int]:
    with tempfile.TemporaryDirectory(prefix=f"blind-ledger-{executable}-") as temporary:
        argument_path = Path(temporary) / "synthetic_args.json"
        argument_path.write_text(json.dumps([hex(value) for value in arguments]), encoding="utf-8")
        process = subprocess.run(
            [
                "scarb",
                "execute",
                "--executable-name",
                executable,
                "--arguments-file",
                str(argument_path),
                "--print-program-output",
            ],
            cwd=CAIRO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
    if process.returncode != 0:
        raise AssertionError(
            f"Cairo {executable} failed ({process.returncode})\nstdout:\n{process.stdout}\nstderr:\n{process.stderr}"
        )
    return _canonical_program_output(process.stdout, 12)


def _resolve_run_owned_target(target_raw: str, root: Path = ROOT) -> Path:
    target = Path(target_raw).resolve()
    resolved_root = root.resolve()
    release_tree = resolved_root.parent
    execution_root = release_tree.parent
    cache_root = execution_root.parent

    if release_tree.name == "release-tree" and cache_root.name == "cache":
        allowed_root = execution_root
        forbidden_root = release_tree
    else:
        allowed_root = resolved_root
        forbidden_root = None

    try:
        target.relative_to(allowed_root)
    except ValueError as exc:
        raise AssertionError(
            "BL_RISC0_MODEL_TARGET_DIR must stay inside the run-owned execution root"
        ) from exc
    if forbidden_root is not None:
        try:
            target.relative_to(forbidden_root)
        except ValueError:
            pass
        else:
            raise AssertionError(
                "BL_RISC0_MODEL_TARGET_DIR must stay outside the frozen release tree"
            )
    return target


def _run_risc0_model() -> list[int]:
    target_raw = os.environ.get("BL_RISC0_MODEL_TARGET_DIR")
    if not target_raw:
        raise AssertionError("BL_RISC0_MODEL_TARGET_DIR must be set to a run-owned workspace path")
    target = _resolve_run_owned_target(target_raw)
    binary_raw = os.environ.get("BL_RISC0_MODEL_BINARY")
    expected_hash = os.environ.get("BL_RISC0_MODEL_BINARY_SHA256")
    if (binary_raw is None) != (expected_hash is None):
        raise AssertionError(
            "BL_RISC0_MODEL_BINARY and BL_RISC0_MODEL_BINARY_SHA256 must be set together"
        )

    if binary_raw is not None and expected_hash is not None:
        binary = _resolve_run_owned_target(binary_raw)
        expected_binary = (target / "release" / "host").resolve()
        if binary != expected_binary:
            raise AssertionError(
                f"BL_RISC0_MODEL_BINARY must equal the run-owned release host: {expected_binary}"
            )
        if not binary.is_file():
            raise AssertionError(f"BL_RISC0_MODEL_BINARY is not a file: {binary}")
        if re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None:
            raise AssertionError("BL_RISC0_MODEL_BINARY_SHA256 must be 64 lowercase hex characters")
        actual_hash = _sha256_file(binary)
        if not hmac.compare_digest(actual_hash, expected_hash):
            raise AssertionError(
                "BL_RISC0_MODEL_BINARY SHA-256 mismatch: "
                f"expected {expected_hash}, got {actual_hash}"
            )
        wsl_binary = subprocess.run(
            ["wsl", "wslpath", "-a", str(binary)],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        process = subprocess.run(
            ["wsl", "--exec", wsl_binary, "model"],
            text=True,
            capture_output=True,
            check=False,
        )
        post_execution_hash = _sha256_file(binary)
        if not hmac.compare_digest(post_execution_hash, expected_hash):
            raise AssertionError(
                "BL_RISC0_MODEL_BINARY changed during execution: "
                f"expected {expected_hash}, got {post_execution_hash}"
            )
        print("risc_model_execution_mode=prebuilt-hash-pinned")
    else:
        wsl_path = subprocess.run(
            ["wsl", "wslpath", "-a", str(RISC0_ROOT)],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        wsl_target = subprocess.run(
            ["wsl", "wslpath", "-a", str(target)],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        command = (
            f"cd {shlex.quote(wsl_path)} && "
            f"CARGO_TARGET_DIR={shlex.quote(wsl_target)} "
            "cargo run --release --quiet --offline --locked -p host -- model"
        )
        process = subprocess.run(
            ["wsl", "bash", "-lc", command],
            text=True,
            capture_output=True,
            check=False,
        )
        print("risc_model_execution_mode=cargo-run-offline-locked")
    if process.returncode != 0:
        raise AssertionError(
            f"RISC Zero model failed ({process.returncode})\nstdout:\n{process.stdout}\nstderr:\n{process.stderr}"
        )
    indexed_values = [
        (int(match.group(1)), int(match.group(2), 16))
        for line in process.stdout.splitlines()
        if (
            match := re.fullmatch(
                r"public_output\[(0|[1-9]\d*)\]=0x([0-9a-f]{64})",
                line.strip(),
            )
        )
    ]
    if len(indexed_values) != 12:
        raise AssertionError(
            f"expected 12 RISC Zero model fields, got {indexed_values}\n{process.stdout}"
        )
    indices = [index for index, _ in indexed_values]
    if indices != list(range(12)):
        raise AssertionError(f"RISC Zero model field indices are not exactly 0..11: {indices}")
    values = [value for _, value in indexed_values]
    for index, value in enumerate(values):
        if not 0 <= value < FIELD_MODULUS:
            raise AssertionError(
                f"RISC Zero model output[{index}] is not a canonical field element: {value}"
            )
    return values


class Risc0CompleteClaimDifferentialTests(unittest.TestCase):
    def test_python_rust_cairo_and_risc0_agree_on_complete_synthetic_claim(self) -> None:
        half_prime = FIELD_MODULUS // 2
        r16_regression_value = (
            2556804241959708214775924503969299168294989458702588455565708918393934598799
        )
        for value in (
            0,
            U128_LIMIT - 1,
            half_prime,
            half_prime + 1,
            r16_regression_value,
            FIELD_MODULUS - 1,
        ):
            with self.subTest(canonical_transport_value=value):
                low = value & (U128_LIMIT - 1)
                high = value >> 128
                self.assertEqual(
                    [value],
                    _canonical_program_output(f"Program output:\n{low}\n{high}\n", 1),
                )
        for invalid_limb in (-1, U128_LIMIT):
            with self.subTest(invalid_cairo_limb=invalid_limb):
                with self.assertRaisesRegex(AssertionError, "not a u128"):
                    _canonical_program_output(f"Program output:\n{invalid_limb}\n0\n", 1)
        modulus_low = FIELD_MODULUS & (U128_LIMIT - 1)
        modulus_high = FIELD_MODULUS >> 128
        with self.assertRaisesRegex(AssertionError, "not a canonical field element"):
            _canonical_program_output(
                f"Program output:\n{modulus_low}\n{modulus_high}\n",
                1,
            )
        with self.assertRaisesRegex(AssertionError, "expected 2 Cairo limbs"):
            _canonical_program_output("Program output:\n1\n", 1)

        batch, v2 = _synthetic_bundle()
        python_public = [int(v2["expected_output"][name]) for name in V2_OUTPUT_NAMES]
        rust_risc0_public = _run_risc0_model()
        cairo_v2_public = _run_cairo(
            "batch_main_v2_canonical_transport",
            [int(value) for value in v2["serialized_arguments"]],
        )
        claim = batch["witness"]["claims"][0]
        python_claim = batch["claim_outputs"][0]
        python_private_semantics = [
            int(python_claim["commitment"]),
            int(python_claim["decision"]),
            int(python_claim["failure_code"]),
            1,
            int(claim.sum_line_charge_cents),
            int(python_claim["allowed_cents"]),
            int(python_claim["payment_cents"]),
            int(python_claim["claim_source_root"]),
            int(python_claim["oracle_facts_root"]),
            int(python_claim["policy_root"]),
            int(python_claim["nullifier_root_before"]),
            int(python_claim["nullifier_root_after"]),
        ]
        cairo_private_semantics = _run_cairo(
            "claim_main_canonical_transport",
            flatten_multi_line_decision_input_witness(
                claim,
                batch_id=int(batch["witness"]["batch_id"]),
            ),
        )
        print("python_v2_public_fields=" + json.dumps(python_public))
        print("rust_risc0_v2_public_fields=" + json.dumps(rust_risc0_public))
        print("cairo_v2_public_fields=" + json.dumps(cairo_v2_public))
        print("python_synthetic_claim_semantics=" + json.dumps(python_private_semantics))
        print("cairo_synthetic_claim_semantics=" + json.dumps(cairo_private_semantics))
        self.assertEqual(python_public, rust_risc0_public)
        self.assertEqual(python_public, cairo_v2_public)
        self.assertEqual(python_private_semantics, cairo_private_semantics)
        self.assertEqual(12, len(python_public))


if __name__ == "__main__":
    unittest.main()
