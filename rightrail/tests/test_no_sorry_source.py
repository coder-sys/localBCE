"""No new `sorry` in lean/BlindLedger (S3d review r1 target 5): `lake build` stays green on a sorry and the semantic gate
scans only pinned files, so this counts `sorry` outside comments, strings and char literals in every .lean file and holds
the counts equal to tests/lean_sorry_allowlist.txt (`<path> <count>` lines).  A new sorry fails; a proof that removes one
fails until its line is lowered or dropped.  The allowlist only shrinks."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
ALLOW = ROOT / "tests" / "lean_sorry_allowlist.txt"
CODE = re.compile(r"""/-|--[^\n]*|"(?:\\.|[^"\\])*"|(?<![\w'.])'(?:\\.|[^\\'])'|(?<![\w'.!?])sorry(?![\w'!?])""")
BLOCK = re.compile(r"/-|-/")


def sorries(src: str) -> int:
    n, i = 0, 0
    while m := CODE.search(src, i):
        i = m.end()
        if m.group() == "sorry":
            n += 1
        elif m.group() == "/-":
            depth = 1
            while depth:
                c = BLOCK.search(src, i)
                if c is None:
                    return n
                depth, i = depth + (1 if c.group() == "/-" else -1), c.end()
    return n


class NoSorrySource(unittest.TestCase):
    def test_scanner(self) -> None:
        self.assertEqual(sorries('/- sorry /- sorry -/ -/ -- sorry\n"sorry" \'"\' sorryAx h.sorry x\n  sorry'), 1)

    def test_sorry_counts_match_allowlist(self) -> None:
        found = {p.relative_to(ROOT).as_posix(): n for p in sorted((ROOT / "lean" / "BlindLedger").rglob("*.lean"))
                 if (n := sorries(p.read_text("utf-8")))}
        allowed = {k: int(v) for k, v in (line.split() for line in ALLOW.read_text("utf-8").splitlines() if line.strip())}
        self.assertEqual(found, allowed)


if __name__ == "__main__":
    unittest.main()
