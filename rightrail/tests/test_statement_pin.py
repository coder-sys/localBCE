"""Statement pin: tools/stmt_hash.lean hashes the pinned theorem statements, every
non-core definition they reach, and the TCB file list; tools/STMT_PIN.txt is its committed output.  The pinned set is
generated here (`sources`) from the Gate and Financial AxiomCheck `#print axioms` lists (a line may start with `#guard_msgs ... in`), the Semantic ones in the gate
list, and the properties of lean/tools/semantic_assurance_manifest.json; tools/STATEMENTS is its committed copy.
Re-pin: `python tests/test_statement_pin.py regen` (rewrites both files).  Needs the built lean/.lake."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
VERSION = (ROOT / "lean" / "lean-toolchain").read_text("utf-8").strip().split(":v")[1]
TOOLCHAIN = Path.home() / ".elan" / "toolchains" / f"leanprover--lean4---v{VERSION}"
BUILT = ROOT / "lean" / ".lake" / "build" / "lib" / "lean"
CHECKS = [TOOLS / "gate_print_axioms.lean", ROOT / "lean" / "BlindLedger" / "Financial" / "AxiomCheck.lean"]
MANIFEST = ROOT / "lean" / "tools" / "semantic_assurance_manifest.json"
REGEN = "python tests/test_statement_pin.py regen"


def sources() -> tuple[list[str], list[str]]:
    """The pinned theorem names (sorted) and the modules that import them, from their single sources."""
    texts = [c.read_text("utf-8") for c in CHECKS]
    manifest = json.loads(MANIFEST.read_text("utf-8"))
    ns = manifest["candidate"]["namespace"]
    names = {n if n.startswith("BlindLedger.") else "BlindLedger.Financial." + n  # AxiomCheck opens that namespace
             for t in texts for n in re.findall(r"^(?:#guard_msgs[^\n]* in )?#print axioms (\S+)$", t, re.M)}
    names |= {f"{ns}.{p['id']}" for p in manifest["properties"]}
    mods = list(dict.fromkeys(m for t in texts for m in re.findall(r"^import (\S+)$", t, re.M)))
    return sorted(names), mods


FIXTURE = "def usable (n : Nat) : Bool := {body}\n{note}theorem fixt : usable 3 = true := by decide\n"


def _lean(args: list[str], *lean_path: Path, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, LEAN_PATH=os.pathsep.join(map(str, lean_path)), LEAN_SYSROOT=str(TOOLCHAIN))
    return subprocess.run([str(TOOLCHAIN / "bin" / "lean.exe"), *args], env=env, cwd=cwd, capture_output=True,
                          text=True, encoding="utf-8", timeout=1800)


def run_tool(root: Path, statements: Path, tcb: str, mods: list[str], *lean_path: Path) -> str:
    done = _lean(["--run", str(TOOLS / "stmt_hash.lean"), str(root), str(statements), tcb, *mods], BUILT, *lean_path)
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-2000:]
    return done.stdout


def _lines(text: str) -> dict[str, str]:
    return {l.split(" ", 1)[0]: l.split(" ", 1)[1] for l in text.splitlines()}


def _diff(got: str, want: str) -> str:
    g, w = _lines(got), _lines(want)
    added, removed = sorted(set(g) - set(w)), sorted(set(w) - set(g))
    changed = sorted(k for k in set(g) & set(w) if g[k] != w[k])
    cap = lambda xs: ", ".join(xs[:20]) + (f" (+{len(xs) - 20} more)" if len(xs) > 20 else "")
    moved = [k for k in ("tcb", "root") if g.get(k) != w.get(k)]
    out = [f"statement pin moved; regenerate with `{REGEN}` and review the diff"]
    if added: out.append(f"added: {cap(added)}")
    if removed: out.append(f"removed: {cap(removed)}")
    if changed: out.append(f"changed: {cap(changed)}")
    files = [k for k in changed if g[k].startswith("F ")]
    if "tcb" in moved: out.append("tcb moved; TCB files that moved: " + (cap(files) or "none (the file list changed)"))
    if moved == ["root"] and not (added or removed or changed): out.append("root moved with no listed difference (beyond the 16 hex shown)")
    return chr(10).join(out)


def _generated() -> str:
    names, mods = sources()
    return run_tool(ROOT, TOOLS / "STATEMENTS", "tools/STMT_TCB.txt", mods)


class StatementPinTests(unittest.TestCase):
    def test_statements_match_sources(self) -> None:
        names, _ = sources()
        self.assertEqual((TOOLS / "STATEMENTS").read_text("utf-8"), "".join(n + chr(10) for n in names),
                         f"tools/STATEMENTS drifted from its sources; regenerate with `{REGEN}`")

    def test_pin_matches_the_repository(self) -> None:
        got = _generated()
        want = (TOOLS / "STMT_PIN.txt").read_text("utf-8")
        if got != want:
            self.fail(_diff(got, want))

    def test_fixture_mutants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "STMT").write_text("fixt\n", "utf-8")
            (tmp_path / "TCB").write_text("a.txt\n", "utf-8")
            (tmp_path / "a.txt").write_text("one\r\ntwo\n", "utf-8", newline="")

            def hashed(body: str, note: str = "", stmt: str | None = None) -> str:
                src = FIXTURE.format(body=body, note=note)
                if stmt:
                    src = src.replace("usable 3 = true", stmt)
                (tmp_path / "Fix.lean").write_text(src, "utf-8")
                done = _lean(["Fix.lean", "-o", "Fix.olean"], tmp_path, cwd=tmp_path)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                return run_tool(tmp_path, tmp_path / "STMT", "TCB", ["Fix"], tmp_path)

            base = hashed("decide (n < 4)")
            self.assertEqual(sorted(re.findall(r"^(\S+) [TD] ", base, re.M)), ["fixt", "usable"])
            self.assertEqual(hashed("decide (n < 4)", note="/- note -/\n"), base, "a comment moved the hash")
            self.assertEqual(hashed("decide  (n  <  4)"), base, "whitespace moved the hash")
            self.assertNotEqual(hashed("decide (n < 6)"), base, "mutant (a): body changed under the same statement text")
            self.assertNotEqual(hashed("decide (n < 4)", stmt="usable 4 = false"), base, "mutant (b): statement changed")
            self.assertEqual(hashed("decide (n < 4)"), base)
            (tmp_path / "TCB").write_text("a.txt\nSTMT\n", "utf-8")
            self.assertNotEqual(run_tool(tmp_path, tmp_path / "STMT", "TCB", ["Fix"], tmp_path), base,
                                "mutant (c): a file added to the TCB list")
            (tmp_path / "TCB").write_text("a.txt\n", "utf-8")
            (tmp_path / "a.txt").write_text("one\ntwo\n", "utf-8", newline="")
            self.assertEqual(run_tool(tmp_path, tmp_path / "STMT", "TCB", ["Fix"], tmp_path), base, "CRLF moved the TCB hash")
            (tmp_path / "a.txt").write_text("one\ntwo!\n", "utf-8", newline="")
            self.assertNotEqual(run_tool(tmp_path, tmp_path / "STMT", "TCB", ["Fix"], tmp_path), base, "a TCB file edit")

    @staticmethod
    def _refused(builds: list[tuple[str, str]], root: str) -> str:
        """Compile each (module, source) in order, run the tool on `root`, require a non-zero exit, and return its output."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "STMT").write_text("fixt\n", "utf-8")
            (tmp_path / "TCB").write_text("", "utf-8")
            for name, src in builds:
                (tmp_path / f"{name}.lean").write_text(src, "utf-8")
                done = _lean([f"{name}.lean", "-o", f"{name}.olean"], tmp_path, cwd=tmp_path)
                assert done.returncode == 0, done.stdout + done.stderr
            done = _lean(["--run", str(TOOLS / "stmt_hash.lean"), str(tmp_path), str(tmp_path / "STMT"), "TCB", root], BUILT, tmp_path)
            assert done.returncode != 0, "the tool accepted a fixture it must refuse"
            return done.stderr + done.stdout

    def test_stub_constants_fail(self) -> None:
        thm = "theorem fixt : usable 3 = true := by decide\n"
        body = "(n : Nat) : Bool := decide (n < 4)\n"
        extern = '@[extern "nowhere"] def usable ' + body
        implby = "def other (n : Nat) : Bool := n == 0\n@[implemented_by other] def usable " + body
        private = '@[extern "nowhere"] private def hidden ' + body + "def usable (n : Nat) : Bool := hidden n\n"
        for mark, defn in (("extern", extern), ("implemented_by", implby)):
            out = self._refused([("Fix", defn + thm)], "Fix")
            self.assertTrue(mark in out and "usable" in out, out)
            out = self._refused([("Dep", defn), ("Fix", "import Dep\n" + thm)], "Fix")
            self.assertTrue(mark in out and "usable" in out, "a stub in another module than the theorem was hashed: " + out)
        out = self._refused([("Dep", private), ("Fix", "import Dep\n" + thm)], "Fix")
        self.assertTrue("extern" in out and "hidden" in out, "a private stub was hashed: " + out)

    def test_duplicate_constant_fails(self) -> None:
        """B is stale: it declares `usable` against an A that did not, and A was rebuilt to declare it too."""
        dup = "def usable (n : Nat) : Bool := decide (n < 4)\n"
        out = self._refused([("A", "def other : Nat := 1\n"),
                             ("B", "import A\n" + dup + "theorem fixt : usable 3 = true := by decide\n"),
                             ("A", dup)], "B")
        self.assertTrue("usable" in out and "A" in out and "B" in out, out)

if __name__ == "__main__":
    if sys.argv[1:] == ["regen"]:
        (TOOLS / "STATEMENTS").write_text("".join(n + chr(10) for n in sources()[0]), "utf-8", newline=chr(10))
        (TOOLS / "STMT_PIN.txt").write_text(_generated(), "utf-8", newline=chr(10))
    else:
        unittest.main()
