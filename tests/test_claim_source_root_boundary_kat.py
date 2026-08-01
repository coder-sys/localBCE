from __future__ import annotations

import random
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from app.batch.attempt import ATTEMPT_RECORD_SCHEMA, REVISION_KIND_ORIGINAL
from app.batch.claim_source_root import CLAIM_SOURCE_SCHEMA, claim_source_service_lines_commitment
from app.batch.merkle import verify_inclusion
from app.batch.poseidon import FIELD_MODULUS, domain_poseidon_hash
from app.models import ServiceLine
from app.service_line_canonical import canonical_service_line_identities


ROOT = Path(__file__).resolve().parents[1]
CAIRO_PACKAGE = ROOT / "zk-cairo-sharp"
DEPTH = 7
SIZES = (1, 2, 8, 100)


def _random_felt(rng: random.Random) -> int:
    value = 0
    while value == 0:
        value = rng.randrange(1, FIELD_MODULUS)
    return value


def _path_indices(leaf_index: int, sibling_count: int) -> list[int]:
    return [(leaf_index >> level) & 1 for level in range(sibling_count)]


def _run_cairo(package_name: str, imports: str, body: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix=f"{package_name}-") as temp:
        temp_path = Path(temp)
        (temp_path / "src").mkdir()
        (temp_path / "Scarb.toml").write_text(
            textwrap.dedent(
                f"""
                [package]
                name = "{package_name}"
                version = "0.1.0"
                edition = "2024_07"

                [cairo]
                enable-gas = false

                [dependencies]
                blind_ledger_cairo_adjudication = {{ path = "{CAIRO_PACKAGE.as_posix()}" }}

                [dev-dependencies]
                cairo_test = "2.18.0"
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        (temp_path / "src" / "lib.cairo").write_text(
            textwrap.dedent(
                f"""
                {imports}

                #[cfg(test)]
                mod tests {{
                    use super::*;

                {textwrap.indent(body, "    ")}
                }}
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        return subprocess.run(["scarb", "test"], cwd=temp_path, text=True, capture_output=True, check=check)


def _claim_leaf(fields: dict[str, int]) -> int:
    attempt_identity_commitment = domain_poseidon_hash(
        "claim_source",
        [
            ATTEMPT_RECORD_SCHEMA,
            fields["source_authority_id"],
            fields["payer_id"],
            fields["provider_npi"],
            fields["claim_id"],
            fields["attempt_version"],
            fields["revision_kind"],
            fields["parent_attempt_version"],
        ],
    )
    attempt_snapshot_commitment = domain_poseidon_hash(
        "claim_source",
        [
            ATTEMPT_RECORD_SCHEMA,
            fields["member_id"],
            fields["service_date_day"],
            fields["service_lines_commitment"],
            fields["diagnosis_commitment"],
            fields["diagnosis_count"],
            fields["total_charge_cents"],
            fields["service_line_count"],
        ],
    )
    attempt_record_commitment = domain_poseidon_hash(
        "claim_source",
        [ATTEMPT_RECORD_SCHEMA, attempt_identity_commitment, attempt_snapshot_commitment],
    )
    return domain_poseidon_hash(
        "claim_source",
        [
            CLAIM_SOURCE_SCHEMA,
            fields["claim_id"],
            fields["member_id"],
            fields["provider_npi"],
            fields["service_date_day"],
            fields["service_lines_commitment"],
            fields["diagnosis_commitment"],
            fields["diagnosis_count"],
            fields["total_charge_cents"],
            fields["attempt_nullifier"],
            attempt_record_commitment,
            fields["ruleset_root"],
        ],
    )


def _case(rng: random.Random, size: int) -> tuple[dict[str, int], list[int], int]:
    fields = {
        "claim_id": _random_felt(rng),
        "member_id": _random_felt(rng),
        "provider_npi": rng.randrange(1_000_000_000, 9_999_999_999),
        "service_date_day": rng.randrange(1, 30_000),
        "service_lines_commitment": _random_felt(rng),
        "diagnosis_commitment": _random_felt(rng),
        "total_charge_cents": rng.randrange(1, 10_000_000),
        "source_authority_id": _random_felt(rng),
        "payer_id": _random_felt(rng),
        "attempt_version": 1,
        "revision_kind": REVISION_KIND_ORIGINAL,
        "parent_attempt_version": 0,
        "attempt_nullifier": _random_felt(rng),
        "ruleset_root": _random_felt(rng),
        "service_line_count": rng.randrange(1, 20),
        "diagnosis_count": rng.randrange(1, 12),
    }
    leaf = _claim_leaf(fields)
    leaves = {leaf}
    while len(leaves) < size:
        leaves.add(_random_felt(rng))
    return fields, sorted(leaves), leaf


def _proof_for(leaves: list[int], target_leaf: int):
    from app.batch.claim_source_root import claim_source_tree

    tree = claim_source_tree(leaves, DEPTH)
    leaf_hex = f"{target_leaf:064x}"
    leaf_index = tree.original_leaves.index(leaf_hex)
    proof = tree.prove(leaf_index)
    return tree, proof


def _array(name: str, suffix: str, values: list[int]) -> list[str]:
    lines = [f"    let mut {name} = ArrayTrait::new();"]
    for value in values:
        lines.append(f"    {name}.append({value}_{suffix});")
    return lines


def _cairo_claim_case(index: int, fields: dict[str, int], leaves: list[int], target_leaf: int, *, wrong_root: bool = False) -> str:
    tree, proof = _proof_for(leaves, target_leaf)
    assert verify_inclusion(
        proof.leaf,
        proof.leaf_index,
        proof.siblings,
        proof.root,
        hash_domain=proof.hash_domain,
        leaf_is_hashed=proof.leaf_is_hashed,
    )
    root = int(tree.root, 16)
    if wrong_root:
        root = (root + 1) % FIELD_MODULUS
    path_name = f"claim_path_{index}"
    lines = ["#[test]", f"fn claim_source_membership_kat_{index:03d}() {{"]
    lines.extend(_array(path_name, "felt252", [int(sibling, 16) for sibling in proof.siblings]))
    lines.extend(
        [
            "    let w = ClaimSourceWitness {",
            f"        claim_source_leaf: {target_leaf}_felt252,",
            f"        claim_id: {fields['claim_id']}_felt252,",
            f"        member_id: {fields['member_id']}_felt252,",
            f"        provider_npi: {fields['provider_npi']}_felt252,",
            f"        service_date_day: {fields['service_date_day']}_u128,",
            f"        service_lines_commitment: {fields['service_lines_commitment']}_felt252,",
            f"        diagnosis_commitment: {fields['diagnosis_commitment']}_felt252,",
            f"        total_charge_cents: {fields['total_charge_cents']}_u128,",
            f"        source_authority_id: {fields['source_authority_id']}_felt252,",
            f"        payer_id: {fields['payer_id']}_felt252,",
            f"        attempt_version: {fields['attempt_version']}_u128,",
            f"        revision_kind: {fields['revision_kind']}_u32,",
            f"        parent_attempt_version: {fields['parent_attempt_version']}_u128,",
            f"        attempt_nullifier: {fields['attempt_nullifier']}_felt252,",
            f"        service_line_count: {fields['service_line_count']}_u128,",
            f"        diagnosis_count: {fields['diagnosis_count']}_u128,",
            f"        claim_source_leaf_index: {proof.leaf_index}_u128,",
            f"        claim_source_path_elements: {path_name}.span(),",
            "    };",
            f"    assert_claim_source_membership(w, {root}_felt252, {fields['ruleset_root']}_felt252);",
            "}",
        ]
    )
    return "\n".join(lines)


@unittest.skipUnless(shutil.which("scarb"), "scarb unavailable")
class ClaimSourceRootBoundaryKatTests(unittest.TestCase):
    def test_python_poseidon_claim_source_membership_matches_cairo_for_n_1_2_8_100(self) -> None:
        rng = random.Random(0xBCE1A)
        cases = [_case(rng, size) for size in SIZES for _ in range(25)]
        output = _run_cairo(
            "claim_source_membership_kat",
            "use blind_ledger_cairo_adjudication::{ClaimSourceWitness, assert_claim_source_membership};",
            "\n\n".join(
                _cairo_claim_case(index, fields, leaves, target_leaf)
                for index, (fields, leaves, target_leaf) in enumerate(cases)
            ),
        ).stdout
        self.assertIn("100 passed", output)

    def test_claim_source_deliberate_root_divergence_rejects(self) -> None:
        rng = random.Random(0xBCE1B)
        fields, leaves, target_leaf = _case(rng, 8)
        proc = _run_cairo(
            "claim_source_membership_divergence_kat",
            "use blind_ledger_cairo_adjudication::{ClaimSourceWitness, assert_claim_source_membership};",
            _cairo_claim_case(0, fields, leaves, target_leaf, wrong_root=True),
            check=False,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("claim source membership", proc.stdout + proc.stderr)

    def test_identical_economic_lines_need_distinct_ids_and_preserve_quantity(self) -> None:
        line = ServiceLine("LINE-1", "99213", 125.00, 1.0, "PA-1")
        second = ServiceLine("LINE-2", "99213", 125.00, 1.0, "PA-1")
        one = [line]
        two = [line, second]
        identities = canonical_service_line_identities(two)
        self.assertEqual(len(identities), 2)
        self.assertEqual(identities[0], identities[1])
        self.assertNotEqual(
            claim_source_service_lines_commitment(one),
            claim_source_service_lines_commitment(two),
        )
        with self.assertRaisesRegex(ValueError, "service_line_id_duplicate"):
            claim_source_service_lines_commitment([line, line])

    def test_line_order_is_canonicalized_without_collapsing_quantity(self) -> None:
        first = ServiceLine("A", "99213", 125.00, 1.0, "PA-1")
        second = ServiceLine("B", "99214", 225.00, 1.0, "PA-2")
        self.assertEqual(
            claim_source_service_lines_commitment([first, second]),
            claim_source_service_lines_commitment([second, first]),
        )


if __name__ == "__main__":
    unittest.main()
