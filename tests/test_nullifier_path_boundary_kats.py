from __future__ import annotations

import random
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from dataclasses import replace
from pathlib import Path

from app.batch.nullifier import DEPTH, MAX_NULLIFIER, IndexedLeaf, IndexedNullifierTree, NonMembershipWitness
from app.batch.poseidon import FIELD_MODULUS


ROOT = Path(__file__).resolve().parents[1]
CAIRO_PACKAGE = ROOT / "zk-cairo-sharp"
U128_MASK = (1 << 128) - 1


def _words(value: int) -> tuple[int, int]:
    value = int(value)
    return value >> 128, value & U128_MASK


def _array_lines(name: str, values: list[int], suffix: str) -> list[str]:
    lines = [f"    let mut {name} = ArrayTrait::new();"]
    for value in values:
        lines.append(f"    {name}.append({int(value)}_{suffix});")
    return lines


def _path_arrays(witness: NonMembershipWitness) -> list[str]:
    lines: list[str] = []
    lines.extend(_array_lines("pred_path_elements", witness.pathElements, "felt252"))
    lines.extend(_array_lines("inserted_path_elements", witness.insertedPathElements, "felt252"))
    return lines


def _witness_lines(
    name: str,
    witness: NonMembershipWitness,
    *,
    should_panic: bool = False,
    inserted_words_override: tuple[int, int] | None = None,
) -> str:
    inserted_high, inserted_low = inserted_words_override or _words(witness.nullifier)
    predecessor_high, predecessor_low = _words(witness.leafValue)
    successor_high, successor_low = _words(witness.nextValue)
    lines = ["#[test]"]
    if should_panic:
        lines.append("#[should_panic]")
    lines.append(f"fn {name}() {{")
    lines.extend(_path_arrays(witness))
    lines.append("    let witness = NullifierNonMembershipWitness {")
    lines.append(f"        live_root_before: {witness.root}_felt252,")
    lines.append(f"        onchain_root_before: {witness.root}_felt252,")
    lines.append(f"        root_after: {witness.rootAfter}_felt252,")
    lines.append(f"        onchain_root_after: {witness.rootAfter}_felt252,")
    lines.append(f"        inserted_nullifier_high: {inserted_high}_u128,")
    lines.append(f"        inserted_nullifier_low: {inserted_low}_u128,")
    lines.append(f"        predecessor_value_high: {predecessor_high}_u128,")
    lines.append(f"        predecessor_value_low: {predecessor_low}_u128,")
    lines.append(f"        successor_value_high: {successor_high}_u128,")
    lines.append(f"        successor_value_low: {successor_low}_u128,")
    lines.append(f"        predecessor_index: {witness.leafIndex}_u128,")
    lines.append(f"        successor_index: {witness.nextIndex}_u128,")
    lines.append(f"        inserted_index: {witness.insertedIndex}_u128,")
    lines.append("        predecessor_path_elements: pred_path_elements.span(),")
    lines.append("        inserted_path_elements: inserted_path_elements.span(),")
    lines.append("    };")
    lines.append("    assert_nullifier_nonmembership_transition(witness);")
    lines.append("}")
    return "\n".join(lines)


def _run_cairo_kat(package_name: str, body: str) -> str:
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
                use blind_ledger_cairo_adjudication::{{
                    assert_nullifier_nonmembership_transition, NullifierNonMembershipWitness,
                }};

                #[cfg(test)]
                mod tests {{
                    use super::{{
                        assert_nullifier_nonmembership_transition, NullifierNonMembershipWitness,
                    }};

                {textwrap.indent(body, "    ")}
                }}
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        proc = subprocess.run(["scarb", "test"], cwd=temp_path, text=True, capture_output=True, check=True)
    return proc.stdout + proc.stderr


def _valid_cases() -> list[NonMembershipWitness]:
    cases: list[NonMembershipWitness] = [
        IndexedNullifierTree().prove_nonmembership(1),
        IndexedNullifierTree().prove_nonmembership(MAX_NULLIFIER - 1),
        IndexedNullifierTree([10, 12, 20]).prove_nonmembership(11),
        IndexedNullifierTree([100, 200, 300, 400]).prove_nonmembership(250),
        IndexedNullifierTree([MAX_NULLIFIER - 10, MAX_NULLIFIER - 2]).prove_nonmembership(MAX_NULLIFIER - 5),
    ]
    rng = random.Random(0xBCE501)
    while len(cases) < 100:
        values = sorted(rng.sample(range(1, 250_000), 12))
        candidate = values[len(cases) % len(values)]
        existing = [value for value in values if value != candidate]
        cases.append(IndexedNullifierTree(existing).prove_nonmembership(candidate))
    return cases


def _remove_preserve_indices(tree: IndexedNullifierTree, victim: int) -> IndexedNullifierTree:
    removed = tree.clone()
    position = removed._sorted_values_list.index(victim)
    predecessor_value = removed._sorted_values_list[position - 1]
    successor_value = removed._sorted_values_list[position + 1]
    predecessor = removed._nodes[removed._value_to_index[predecessor_value]]
    successor = removed._nodes[removed._value_to_index[successor_value]]
    victim_index = removed._value_to_index[victim]
    removed._nodes[predecessor.index] = IndexedLeaf(
        predecessor.index,
        predecessor.value,
        successor.value,
        successor.index,
    )
    del removed._nodes[victim_index]
    del removed._value_to_index[victim]
    removed._sorted_values_list.remove(victim)
    removed._root_cache = None
    return removed


def _exploit_eviction_witness() -> NonMembershipWitness:
    real = IndexedNullifierTree([100, 200, 300, 400, 500, 600])
    base = real.prove_nonmembership(250)
    second = _remove_preserve_indices(real, 500)
    second.insert(250)
    root_after, inserted_path, inserted_indices = second._root_and_path(base.insertedIndex)
    return replace(
        base,
        rootAfter=root_after,
        insertedPathElements=inserted_path,
        insertedPathIndices=inserted_indices,
    )


def _exploit_occupied_slot_witness() -> NonMembershipWitness:
    real = IndexedNullifierTree([100, 200, 300, 400, 500, 600])
    base = real.prove_nonmembership(250)
    victim_index = real._value_to_index[500]
    second = real.clone()
    predecessor = second._nodes[base.leafIndex]
    second._nodes[predecessor.index] = IndexedLeaf(
        predecessor.index,
        predecessor.value,
        base.nullifier,
        victim_index,
    )
    second._nodes[victim_index] = IndexedLeaf(
        victim_index,
        base.nullifier,
        base.nextValue,
        base.nextIndex,
    )
    second._root_cache = None
    root_after, inserted_path, inserted_indices = second._root_and_path(victim_index)
    return replace(
        base,
        insertedIndex=victim_index,
        rootAfter=root_after,
        insertedPathElements=inserted_path,
        insertedPathIndices=inserted_indices,
    )


@unittest.skipUnless(shutil.which("scarb"), "scarb unavailable")
class NullifierPathBoundaryKatTests(unittest.TestCase):
    def test_nullifier_path_python_to_cairo_100_witnesses(self) -> None:
        body = "\n\n".join(
            _witness_lines(f"valid_nullifier_path_kat_{index:03d}", witness)
            for index, witness in enumerate(_valid_cases())
        )
        output = _run_cairo_kat("nullifier_path_boundary_kat", body)
        self.assertIn("100 passed", output)

    def test_nullifier_path_adversarial_rejects(self) -> None:
        base = IndexedNullifierTree([10, 20, 40, 80]).prove_nonmembership(30)
        bad_predecessor_path = replace(
            base,
            pathElements=[base.pathElements[0] + 1] + base.pathElements[1:],
        )
        bad_inserted_path = replace(
            base,
            insertedPathElements=[base.insertedPathElements[0] + 1] + base.insertedPathElements[1:],
        )
        omitted_after_root = replace(base, rootAfter=base.root)
        successor_as_inserted = replace(base, nullifier=base.nextValue)
        alias_inserted_words = _words(base.nullifier + FIELD_MODULUS)
        reject_cases = [
            ("reject_bad_predecessor_path", bad_predecessor_path, {}),
            ("reject_bad_inserted_path", bad_inserted_path, {}),
            ("reject_root_after_omits_insert", omitted_after_root, {}),
            ("reject_successor_as_inserted", successor_as_inserted, {}),
            ("reject_noncanonical_inserted_alias", base, {"inserted_words_override": alias_inserted_words}),
            ("reject_wrong_inserted_index", replace(base, insertedIndex=base.insertedIndex + 1), {}),
        ]
        body = "\n\n".join(
            _witness_lines(name, witness, should_panic=True, **kwargs)
            for name, witness, kwargs in reject_cases
        )
        output = _run_cairo_kat("nullifier_path_adversarial_kat", body)
        self.assertIn("6 passed", output)

    def test_phase15_eviction_and_occupied_slot_exploits_reject(self) -> None:
        body = "\n\n".join(
            [
                _witness_lines("reject_phase15_eviction", _exploit_eviction_witness(), should_panic=True),
                _witness_lines("reject_phase15_occupied_slot", _exploit_occupied_slot_witness(), should_panic=True),
            ]
        )
        output = _run_cairo_kat("nullifier_path_phase15_exploit_kat", body)
        self.assertIn("2 passed", output)


if __name__ == "__main__":
    unittest.main()
