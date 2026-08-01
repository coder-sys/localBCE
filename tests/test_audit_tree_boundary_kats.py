from __future__ import annotations

import random
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from app.batch.merkle import PoseidonMerkleTree, verify_inclusion
from app.batch.poseidon import domain_poseidon_hash


ROOT = Path(__file__).resolve().parents[1]
CAIRO_PACKAGE = ROOT / "zk-cairo-sharp"
DEPTH = 5
CAPACITY = 2**DEPTH


def _random_hex32(rng: random.Random) -> str:
    value = 0
    while value == 0:
        value = rng.getrandbits(256)
    return f"{value:064x}"


def _record_words(record: str) -> tuple[int, int]:
    clean = record[2:] if record.startswith("0x") else record
    if len(clean) != 64:
        raise ValueError("expected 32-byte record")
    return int(clean[:32], 16), int(clean[32:], 16)


def _cases(seed: int) -> list[list[str]]:
    rng = random.Random(seed)
    cases: list[list[str]] = []
    for index in range(100):
        size = 2 + (index % 15)
        records: list[str] = []
        while len(records) < size:
            candidate = _random_hex32(rng)
            if candidate not in records:
                records.append(candidate)
        cases.append(records)
    return cases


def _occupancy_cases(seed: int) -> list[list[str]]:
    rng = random.Random(seed)
    cases: list[list[str]] = []
    for index in range(100):
        size = 1 + (index % CAPACITY)
        records: list[str] = []
        while len(records) < size:
            candidate = _random_hex32(rng)
            if candidate not in records:
                records.append(candidate)
        cases.append(records)
    return cases


def _full_padded_poseidon_root(records: list[str], domain: str) -> str:
    level: list[int] = []
    for record in records:
        high, low = _record_words(record)
        level.append(domain_poseidon_hash(domain, [high, low]))
    level.extend([0] * (CAPACITY - len(level)))
    while len(level) > 1:
        level = [
            domain_poseidon_hash(domain, [level[index], level[index + 1]])
            for index in range(0, len(level), 2)
        ]
    return f"{level[0]:064x}"


def _run_cairo_kat(package_name: str, imports: str, body: str) -> str:
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
        proc = subprocess.run(["scarb", "test"], cwd=temp_path, text=True, capture_output=True, check=True)
    return proc.stdout + proc.stderr


def _cairo_case(index: int, assertion_name: str, records: list[str], domain: str) -> str:
    expected = int(PoseidonMerkleTree(records, DEPTH, domain).root, 16)
    lines = ["#[test]", f"fn {domain}_audit_tree_kat_{index:03d}() {{", "    let mut words = ArrayTrait::new();"]
    for record in records:
        high, low = _record_words(record)
        lines.append(f"    words.append({high}_u128);")
        lines.append(f"    words.append({low}_u128);")
    lines.append(f"    {assertion_name}(words.span(), {DEPTH}_u32, {expected}_felt252, {expected}_felt252);")
    lines.append("}")
    return "\n".join(lines)


def _assert_audit_path_round_trips(testcase: unittest.TestCase, cases: list[list[str]], domain: str) -> int:
    count = 0
    for index, records in enumerate(cases):
        tree = PoseidonMerkleTree(records, DEPTH, domain)
        proof = tree.prove(index % len(records))
        testcase.assertTrue(
            verify_inclusion(
                proof.leaf,
                proof.leaf_index,
                proof.siblings,
                tree.root,
                leaf_count=len(records),
                hash_domain=proof.hash_domain,
            )
        )
        testcase.assertFalse(
            verify_inclusion(
                proof.leaf,
                proof.leaf_index,
                proof.siblings,
                tree.root,
                leaf_count=len(records),
            )
        )
        count += 1
    return count


def _assert_mutations_change_root(testcase: unittest.TestCase, cases: list[list[str]], domain: str, seed: int) -> int:
    rng = random.Random(seed)
    count = 0
    for records in cases:
        base = PoseidonMerkleTree(records, DEPTH, domain).root

        reordered = list(reversed(records))
        testcase.assertNotEqual(base, PoseidonMerkleTree(reordered, DEPTH, domain).root)
        count += 1

        substituted = list(records)
        replacement = _random_hex32(rng)
        while replacement in substituted:
            replacement = _random_hex32(rng)
        substituted[0] = replacement
        testcase.assertNotEqual(base, PoseidonMerkleTree(substituted, DEPTH, domain).root)
        count += 1

        omitted = records[:-1]
        testcase.assertNotEqual(base, PoseidonMerkleTree(omitted, DEPTH, domain).root)
        count += 1
    return count


@unittest.skipUnless(shutil.which("scarb"), "scarb unavailable")
class AuditTreeBoundaryKatTests(unittest.TestCase):
    def _assert_boundary(self, domain: str, assertion_name: str, seed: int) -> None:
        differential_cases = _occupancy_cases(seed + 0x1000)
        differential_count = 0
        for records in differential_cases:
            self.assertEqual(
                _full_padded_poseidon_root(records, domain),
                PoseidonMerkleTree(records, DEPTH, domain).root,
            )
            differential_count += 1
        differential_output = _run_cairo_kat(
            f"{domain}_audit_tree_sparse_differential_kat",
            f"use blind_ledger_cairo_adjudication::{assertion_name};",
            "\n\n".join(_cairo_case(index, assertion_name, records, domain) for index, records in enumerate(differential_cases)),
        )
        self.assertIn("100 passed", differential_output)
        self.assertEqual(differential_count, 100)

        cases = _cases(seed)
        output = _run_cairo_kat(
            f"{domain}_audit_tree_boundary_kat",
            f"use blind_ledger_cairo_adjudication::{assertion_name};",
            "\n\n".join(_cairo_case(index, assertion_name, records, domain) for index, records in enumerate(cases)),
        )
        self.assertIn("100 passed", output)
        self.assertEqual(_assert_audit_path_round_trips(self, cases, domain), 100)
        self.assertEqual(_assert_mutations_change_root(self, cases, domain, seed + 1), 300)

    def test_claim_root_python_to_cairo_and_audit_paths(self) -> None:
        self._assert_boundary("claim", "assert_claim_audit_tree_root", 0xBCE301)

    def test_result_root_python_to_cairo_and_audit_paths(self) -> None:
        self._assert_boundary("result", "assert_result_audit_tree_root", 0xBCE302)

    def test_payment_root_python_to_cairo_and_audit_paths(self) -> None:
        self._assert_boundary("payment", "assert_payment_audit_tree_root", 0xBCE303)


if __name__ == "__main__":
    unittest.main()
