from __future__ import annotations

import random
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from app.batch.epoch_nullifier import build_epoch_set_transition, epoch_nullifier_set_root, nullifier_words
from app.batch.leaf import batch_nullifier_commitment
from app.batch.nullifier import DEPTH, MAX_NULLIFIER
from app.batch.poseidon import FIELD_MODULUS


ROOT = Path(__file__).resolve().parents[1]
CAIRO_PACKAGE = ROOT / "zk-cairo-sharp"


def _words_lines(name: str, values: list[int]) -> list[str]:
    lines = [f"    let mut {name} = ArrayTrait::new();"]
    for value in values:
        high, low = nullifier_words(value)
        lines.append(f"    {name}.append({high}_u128);")
        lines.append(f"    {name}.append({low}_u128);")
    return lines


def _raw_words_lines(name: str, words: list[tuple[int, int]]) -> list[str]:
    lines = [f"    let mut {name} = ArrayTrait::new();"]
    for high, low in words:
        lines.append(f"    {name}.append({high}_u128);")
        lines.append(f"    {name}.append({low}_u128);")
    return lines


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
                use blind_ledger_cairo_adjudication::assert_epoch_nullifier_set_transition;

                #[cfg(test)]
                mod tests {{
                    use super::assert_epoch_nullifier_set_transition;

                {textwrap.indent(body, "    ")}
                }}
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        proc = subprocess.run(["scarb", "test"], cwd=temp_path, text=True, capture_output=True, check=True)
    return proc.stdout + proc.stderr


def _valid_case(index: int, existing: list[int], batch: list[int]) -> str:
    transition = build_epoch_set_transition(existing, batch)
    commitment = int(batch_nullifier_commitment(batch), 16)
    lines = ["#[test]", f"fn epoch_transition_kat_{index:03d}() {{"]
    lines.extend(_words_lines("existing", existing))
    lines.extend(_words_lines("batch", batch))
    lines.append(
        "    assert_epoch_nullifier_set_transition("
        f"existing.span(), batch.span(), {DEPTH}_u32, "
        f"{transition.root_before}_felt252, {transition.root_after}_felt252, {commitment}_felt252"
        ");"
    )
    lines.append("}")
    return "\n".join(lines)


def _reject_case(name: str, existing: list[int], batch_words: list[tuple[int, int]], root_after_values: list[int], commitment_values: list[int]) -> str:
    before = epoch_nullifier_set_root(existing).root
    after = build_epoch_set_transition(existing, root_after_values).root_after if root_after_values else 0
    commitment = int(batch_nullifier_commitment(commitment_values), 16)
    lines = ["#[test]", "#[should_panic]", f"fn reject_{name}() {{"]
    lines.extend(_words_lines("existing", existing))
    lines.extend(_raw_words_lines("batch", batch_words))
    lines.append(
        "    assert_epoch_nullifier_set_transition("
        f"existing.span(), batch.span(), {DEPTH}_u32, "
        f"{before}_felt252, {after}_felt252, {commitment}_felt252"
        ");"
    )
    lines.append("}")
    return "\n".join(lines)


def _boundary_cases() -> list[tuple[list[int], list[int]]]:
    cases: list[tuple[list[int], list[int]]] = [
        ([10, 20], [15]),
        ([100, 200, 300, 400], [50, 150, 250, 350, 450]),
        ([2, MAX_NULLIFIER - 2], [1, MAX_NULLIFIER - 3]),
        ([10, 12, 20], [11, 13]),
    ]
    rng = random.Random(0xBCE401)
    while len(cases) < 100:
        pool = sorted(rng.sample(range(1, 50_000), 16))
        existing = pool[::2]
        batch = pool[1::2][: 1 + (len(cases) % 6)]
        cases.append((existing, batch))
    return cases


@unittest.skipUnless(shutil.which("scarb"), "scarb unavailable")
class EpochNullifierBoundaryKatTests(unittest.TestCase):
    def test_epoch_transition_python_to_cairo_100_trees(self) -> None:
        cases = _boundary_cases()
        output = _run_cairo_kat(
            "epoch_nullifier_boundary_kat",
            "\n\n".join(_valid_case(index, existing, batch) for index, (existing, batch) in enumerate(cases)),
        )
        self.assertIn("100 passed", output)

    def test_epoch_transition_adversarial_rejects(self) -> None:
        existing = [10, 50, 90]
        alias = 20 + FIELD_MODULUS
        alias_words = [(alias >> 128, alias & ((1 << 128) - 1))]
        reject_bodies = [
            _reject_case("already_spent", existing, [nullifier_words(50), nullifier_words(60)], [20, 60], [50, 60]),
            _reject_case("internal_duplicate", existing, [nullifier_words(20), nullifier_words(20)], [20], [20, 20]),
            _reject_case("out_of_order", existing, [nullifier_words(60), nullifier_words(20)], [20, 60], [60, 20]),
            _reject_case("noncanonical_alias", existing, alias_words, [20], [20]),
            _reject_case("root_after_omits_batch_value", existing, [nullifier_words(20), nullifier_words(60)], [20], [20, 60]),
            _reject_case("witness_reordering", existing, [nullifier_words(60), nullifier_words(20)], [20, 60], [20, 60]),
        ]
        output = _run_cairo_kat("epoch_nullifier_adversarial_kat", "\n\n".join(reject_bodies))
        self.assertIn("6 passed", output)


if __name__ == "__main__":
    unittest.main()
