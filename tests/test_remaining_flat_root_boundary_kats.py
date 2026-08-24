from __future__ import annotations

import random
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from app.batch.leaf import batch_nullifier_commitment
from app.batch.poseidon import FIELD_MODULUS


ROOT = Path(__file__).resolve().parents[1]
CAIRO_PACKAGE = ROOT / "zk-cairo-sharp"


def _random_hex32(rng: random.Random) -> str:
    return f"{rng.getrandbits(256):064x}"


def _run_cairo_kat(package_name: str, imports: str, body: str, *, check: bool = True) -> str:
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
        proc = subprocess.run(["scarb", "test"], cwd=temp_path, text=True, capture_output=True, check=check)
    return proc.stdout + proc.stderr


def _batch_nullifier_case(index: int, nullifiers: list[int]) -> str:
    expected = int(batch_nullifier_commitment(nullifiers), 16)
    lines = ["#[test]", f"fn batch_nullifier_kat_{index:03d}() {{", "    let mut nullifiers = ArrayTrait::new();"]
    for value in nullifiers:
        lines.append(f"    nullifiers.append({value}_felt252);")
    lines.append(f"    assert_batch_nullifier_commitment(nullifiers.span(), {expected}_felt252);")
    lines.append("}")
    return "\n".join(lines)


@unittest.skipUnless(shutil.which("scarb"), "scarb unavailable")
class RemainingFlatRootBoundaryKatTests(unittest.TestCase):
    def test_batch_nullifier_commitment_python_to_cairo_102_lists(self) -> None:
        rng = random.Random(0xBCE201)
        ordered = [5, 10, 15]
        reordered = [15, 10, 5]
        self.assertNotEqual(batch_nullifier_commitment(ordered), batch_nullifier_commitment(reordered))
        cases = [
            [rng.randrange(1, FIELD_MODULUS) for _ in range(index % 17)]
            for index in range(100)
        ]
        cases.extend([ordered, reordered])
        output = _run_cairo_kat(
            "batch_nullifier_boundary_kat",
            "use blind_ledger_cairo_adjudication::assert_batch_nullifier_commitment;",
            "\n\n".join(_batch_nullifier_case(index, values) for index, values in enumerate(cases)),
        )
        self.assertIn("102 passed", output)

if __name__ == "__main__":
    unittest.main()
