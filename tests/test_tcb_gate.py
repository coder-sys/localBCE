"""TCB gate (Constitution V.3, XI.2): what each pinned Lean executable runs is proof-backed and has no trusted escape hatch.

`tools/tcb_gate.lean` walks every constant reachable from each executable's `main` and fails on a non-standard axiom
(`sorryAx`, `Lean.ofReduceBool`) or a `partial`, `implemented_by`, `extern`, `opaque` or `unsafe` constant that its allowlist does
not name.  `tools/tcb_toolchain.txt` pins the toolchain that compiles, links and runs it.  The Lean tests skip when the toolchain or
`lean/.lake` build is absent; a violation fails."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

from lean.tools import semantic_assurance_gate as gate

ROOT = Path(__file__).resolve().parents[1]
LEAN = ROOT / "lean"
GATE = ROOT / "tools" / "tcb_gate.lean"
PIN = ROOT / "tools" / "tcb_toolchain.txt"
TCB_EXES = gate.PINNED_EXES + ("gate_verify",)
VERSION = (LEAN / "lean-toolchain").read_text("utf-8").strip().split(":v")[1]
TOOLCHAIN = Path.home() / ".elan" / "toolchains" / f"leanprover--lean4---v{VERSION}"
BUILT = LEAN / ".lake" / "build" / "lib" / "lean"
NEEDS_TOOLCHAIN = unittest.skipUnless(TOOLCHAIN.is_dir(), f"Lean toolchain v{VERSION} is not installed")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree(files: list[Path]) -> tuple[str, int]:
    """SHA-256 over `sha256  path` lines (paths relative to the toolchain, sorted), the shape of PROVENANCE manifests."""
    lines = "".join(f"{_sha256(p)}  {p.relative_to(TOOLCHAIN).as_posix()}\n" for p in sorted(files))
    return hashlib.sha256(lines.encode()).hexdigest(), len(files)


def _run_gate(args: list[str], lean_path: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, LEAN_PATH=str(lean_path), LEAN_SYSROOT=str(TOOLCHAIN))
    return subprocess.run([str(TOOLCHAIN / "bin" / "lean.exe"), "--run", str(GATE), *args], env=env,
                          capture_output=True, text=True, timeout=600)


class TcbGateTests(unittest.TestCase):
    def test_pinned_closures_hold_no_proof_module(self) -> None:
        """Item 4, measured: no KAT or `native_decide` module sits in any pinned executable's import closure, gate_verify included."""
        self.assertGreater(gate._check_pinned_exe_closure(LEAN, TCB_EXES), 20)

    @NEEDS_TOOLCHAIN
    def test_toolchain_pin_names_the_installed_toolchain(self) -> None:
        pinned = PIN.read_text("utf-8").splitlines()
        self.assertIn(f"lean-toolchain: {(LEAN / 'lean-toolchain').read_text('utf-8').strip()}", pinned)
        bin_files = sorted(p for p in (TOOLCHAIN / "bin").iterdir() if p.is_file())
        for path in bin_files:
            self.assertIn(f"{_sha256(path)}  {path.relative_to(TOOLCHAIN).as_posix()}", pinned)
        self.assertEqual(sum("  bin/" in line for line in pinned), len(bin_files))  # nothing pinned that is not installed
        libs = [p for p in (TOOLCHAIN / "lib").iterdir() if p.is_file()] + list((TOOLCHAIN / "lib" / "lean").glob("*.a"))
        digest, count = _tree(libs)
        self.assertIn(f"link inputs  {digest}  {count} files", pinned)

    @NEEDS_TOOLCHAIN
    def test_pinned_exes_have_no_escape_hatch(self) -> None:
        lake = tomllib.loads((LEAN / "lakefile.toml").read_text("utf-8"))
        roots = {e["name"]: e["root"] for e in lake["lean_exe"]}
        for exe in TCB_EXES:
            with self.subTest(exe):
                if not (BUILT / (roots[exe].replace(".", os.sep) + ".olean")).is_file():
                    self.skipTest(f"lean/.lake has no build of {roots[exe]}")
                done = _run_gate([f"{exe}={roots[exe]}"], BUILT)
                self.assertEqual((done.returncode, done.stderr), (0, ""), done.stdout)
                self.assertIn(" 0 violations", done.stdout)
                self.assertGreater(int(done.stdout.split(" constants walked")[0].split()[-1]), 1000)

    @NEEDS_TOOLCHAIN
    def test_gate_refuses_every_escape_hatch(self) -> None:
        """A module that reaches each hatch from `main` fails the gate once per hatch; the real exes above are the controls."""
        source = """axiom myAx : 1 = 2
partial def loopP (n : Nat) : Nat := if n > 5 then n else loopP (n + 1)
@[extern "ext_fn"] opaque externFn : Nat → Nat
opaque opaqueVal : Nat
def implTarget (n : Nat) : Nat := n
@[implemented_by implTarget] def implSpec (n : Nat) : Nat := n + 0
unsafe def unsafeFn (n : Nat) : Nat := n
@[implemented_by unsafeFn] def viaUnsafe (n : Nat) : Nat := n
def usesSorry : Nat := sorry
theorem nd : 2 + 2 = 4 := by native_decide
def usesNd : Nat := have _ := nd; 1
def usesAx : Nat := have _ := myAx; 1
def main : IO Unit := IO.println s!"{loopP 0} {externFn 1} {opaqueVal} {implSpec 1} {viaUnsafe 1} {usesSorry} {usesNd} {usesAx}"
"""
        with tempfile.TemporaryDirectory(prefix="tcb-gate-") as tmp:
            (Path(tmp) / "Bad.lean").write_text(source, encoding="utf-8")
            built = subprocess.run([str(TOOLCHAIN / "bin" / "lean.exe"), "Bad.lean", "-o", "Bad.olean"], cwd=tmp,
                                   env=dict(os.environ, LEAN_SYSROOT=str(TOOLCHAIN)), capture_output=True, text=True, timeout=600)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            done = _run_gate(["bad=Bad"], Path(tmp))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        for expected in ("axiom myAx", "axiom sorryAx", "axiom nd._native.native_decide.ax_1_1", "partial loopP", "extern externFn",
                         "opaque opaqueVal", "implemented_by implSpec", "unsafe unsafeFn"):
            self.assertIn(f"VIOLATION {expected}", done.stdout)


if __name__ == "__main__":
    unittest.main()
