"""TCB gate (Constitution V.3, XI.2): what each pinned Lean executable runs is proof-backed and has no trusted escape hatch.

`tools/tcb_gate.lean` walks every constant reachable from each executable's `main`, its startup initializers and the `@[csimp]`
theorems, and fails on a non-standard axiom (`sorryAx`, `Lean.ofReduceBool`) or a `partial`, `implemented_by`, `extern`, `opaque`,
`unsafe`, `partial_fixpoint`, `while`/`repeat`, `IO.iterate` or stream-`for` constant its allowlist does not name.  The live gate needs 3-5 GB, so the default run only checks the committed
`tools/tcb_report.txt`: it must be for the current `lean/` tree and gate file and the pinned exe bytes, hold no violation, and name
exactly the known VIOLATION-TODO set.  The pin procedure (`tools/tcb_pin.ps1`, RR_TCB_LIVE=1) builds nothing: it reruns the gate on the
built exes (whose bytes must equal the pins), pins the toolchain and rewrites the report."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest

from app import right_rail_financial_engine as engine
from app import right_rail_gate_signer as signer
from lean.tools import semantic_assurance_gate as gate

ROOT = Path(__file__).resolve().parents[1]
LEAN = ROOT / "lean"
GATE = ROOT / "tools" / "tcb_gate.lean"
PIN = ROOT / "tools" / "tcb_toolchain.txt"
REPORT = ROOT / "tools" / "tcb_report.txt"
TCB_EXES = gate.PINNED_EXES + ("gate_verify",)
VERSION = (LEAN / "lean-toolchain").read_text("utf-8").strip().split(":v")[1]
TOOLCHAIN = Path.home() / ".elan" / "toolchains" / f"leanprover--lean4---v{VERSION}"
BUILT = LEAN / ".lake" / "build" / "lib" / "lean"
LIVE = unittest.skipUnless(os.environ.get("RR_TCB_LIVE") == "1", "live TCB gate: run tools/tcb_pin.ps1 (RR_TCB_LIVE=1)")
# The committed pins of the three executables: the exes the report must be about.
EXE_PINS = {
    "blind_financial_worker": engine.EVALUATOR_ARTIFACT_SHA256.hex(),
    "blind_financial_correction": engine.CORRECTION_TRANSITION_ARTIFACT_SHA256.hex(),
    "gate_verify": signer.VERIFY_PIN.read_text("utf-8").strip(),
}
# The open items: a new one changes this set (and STATUS.md).  serve/readExact/readFinancialBounded, rejNtt and sampleInBall
# are closed by lean-partials-v1.
EXPECTED_TODO = {"blind_financial_worker": set(), "blind_financial_correction": set(), "gate_verify": set()}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _tree(files: list[Path]) -> str:
    """SHA-256 over `sha256  path` lines (paths relative to the toolchain, sorted), the shape of PROVENANCE manifests."""
    return hashlib.sha256("".join(f"{_sha256(p)}  {p.relative_to(TOOLCHAIN).as_posix()}\n" for p in sorted(files)).encode()).hexdigest()


def _lean_manifest() -> str:
    """The `lean/` source manifest hash of test_gate_verify_pin_names_the_current_lean_tree: tracked files, plain string order."""
    tracked = subprocess.run(["git", "ls-files", "-z", "lean"], cwd=ROOT, capture_output=True, check=True).stdout.decode().split("\0")
    files = sorted(name for name in tracked if name and ".lake" not in name.split("/"))
    lf = {name: hashlib.sha256((ROOT / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest() for name in files}  # LF = the git blob (eol=lf)
    return hashlib.sha256("".join(f"{lf[name]}  {name}\n" for name in files).encode()).hexdigest()


def _olean_line() -> str:
    """Every Init, Std and Lean module file the allowlist and the gate trust (oleans, IR, server data), less `.ilean` editor data."""
    lib = TOOLCHAIN / "lib" / "lean"
    files = [p for p in lib.rglob("*") if p.is_file() and not p.name.endswith(".ilean") and p.relative_to(lib).parts[0].split(".")[0] in ("Init", "Std", "Lean")]
    return f"toolchain oleans  {_tree(files)}  {len(files)} files"


def _bound(report: str) -> list[str]:
    """The report's binding lines: the gate file and each built exe, by SHA-256."""
    return [line for line in report.splitlines() if line.startswith(("gate  ", "exe "))]


def _blocks(report: str) -> dict[str, tuple[int, set[str]]]:
    """exe -> (violation count, VIOLATION-TODO set) from the gate's per-exe output."""
    found = {}
    for block in re.split(r"(?m)^(?=\S+: \d+ constants walked)", report)[1:]:
        todo = {line.strip().removeprefix("VIOLATION-TODO ") for line in block.splitlines() if line.strip().startswith("VIOLATION-TODO ")}
        found[block.split(":")[0]] = (int(re.search(r"(\d+) violations", block).group(1)), todo)
    return found


def _lean(args: list[str], lean_path: Path, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, LEAN_PATH=str(lean_path), LEAN_SYSROOT=str(TOOLCHAIN))
    return subprocess.run([str(TOOLCHAIN / "bin" / "lean.exe"), *args], env=env, cwd=cwd, capture_output=True, text=True, timeout=900)


class TcbReportTests(unittest.TestCase):
    """Cheap checks, always on."""

    def test_pinned_closures_hold_no_proof_module(self) -> None:
        """No KAT or `native_decide` module sits in any pinned executable's import closure, gate_verify included."""
        self.assertGreater(gate._check_pinned_exe_closure(LEAN, TCB_EXES), 20)

    def test_committed_report_is_current_and_clean(self) -> None:
        report = REPORT.read_text("utf-8")
        self.assertIn(f"manifest  {_lean_manifest()}", report.splitlines(), "lean/ changed since the report: rerun tools/tcb_pin.ps1")
        self.assertEqual(_blocks(report), {exe: (0, todo) for exe, todo in EXPECTED_TODO.items()})
        self.assertEqual(report.count("allowlist BlindLedger.Financial.serveWorker x1"), 1, "the worker's one partial_fixpoint")

    def test_committed_report_is_about_the_pinned_exes_and_this_gate(self) -> None:
        bound = [f"gate  {_sha256(GATE)}"] + [f"exe {exe}  {pin.lower()}" for exe, pin in ((e, EXE_PINS[e]) for e in TCB_EXES)]
        self.assertEqual(_bound(REPORT.read_text("utf-8")), bound, "the gate or a pinned exe changed since the report: rerun tools/tcb_pin.ps1")

    def test_toolchain_note_matches_the_report(self) -> None:
        pinned = PIN.read_text("utf-8").splitlines()
        self.assertIn(f"lean-toolchain: {(LEAN / 'lean-toolchain').read_text('utf-8').strip()}", pinned)
        line = next(l for l in pinned if l.startswith("toolchain oleans"))
        self.assertIn(line, REPORT.read_text("utf-8").splitlines())

    def test_no_project_csimp(self) -> None:
        """The gate reads the `@[csimp]` table from Init and Std only (it must not run project initializers); a project one needs the gate extended."""
        for source in (LEAN / "BlindLedger").rglob("*.lean"):
            self.assertNotIn("csimp", source.read_text("utf-8"), source.name)


@LIVE
class LiveTcbGateTests(unittest.TestCase):
    """The pin procedure: 3-5 GB, one Lean process at a time."""

    def test_toolchain_and_exes_pass_and_the_report_is_rewritten(self) -> None:
        self.assertTrue(TOOLCHAIN.is_dir(), f"pinned toolchain missing: {TOOLCHAIN}")
        pinned = PIN.read_text("utf-8").splitlines()
        for path in sorted(p for p in (TOOLCHAIN / "bin").iterdir() if p.is_file()):
            self.assertIn(f"{_sha256(path)}  {path.relative_to(TOOLCHAIN).as_posix()}", pinned)
        libs = [p for p in (TOOLCHAIN / "lib").iterdir() if p.is_file()] + list((TOOLCHAIN / "lib" / "lean").glob("*.a"))
        self.assertIn(f"link inputs  {_tree(libs)}  {len(libs)} files", pinned)
        oleans = _olean_line()
        self.assertIn(oleans, pinned)
        lake = tomllib.loads((LEAN / "lakefile.toml").read_text("utf-8"))
        roots = {e["name"]: e["root"] for e in lake["lean_exe"]}
        text = f"manifest  {_lean_manifest()}\ngate  {_sha256(GATE)}\n"
        for exe in TCB_EXES:
            built = _sha256(LEAN / ".lake" / "build" / "bin" / f"{exe}.exe")
            self.assertEqual(built, EXE_PINS[exe].lower(), f"the built {exe} is not the pinned one: build in-tree first")
            text += f"exe {exe}  {built}\n"
        text += f"{oleans}\n"
        for exe in TCB_EXES:
            done = _lean(["--run", str(GATE), f"{exe}={roots[exe]}"], BUILT)
            self.assertEqual((done.returncode, done.stderr), (0, ""), done.stdout)
            text += done.stdout
        self.assertEqual({exe: found[0] for exe, found in _blocks(text).items()}, {exe: 0 for exe in TCB_EXES})
        REPORT.write_text(text, encoding="utf-8", newline="\n")

    def test_gate_refuses_every_escape_hatch(self) -> None:
        """A module that reaches each hatch from `main`, from a startup initializer (bare `initialize do` too) or only through a partial body fails the gate once per hatch."""
        source = """axiom myAx : 1 = 2
partial def loopP (n : Nat) : Nat := if n > 5 then n else loopP (n + 1)
@[extern "ext_fn"] opaque externFn : Nat → Nat
@[extern "init_fn"] opaque initExt : Nat → Nat
opaque opaqueVal : Nat
def implTarget (n : Nat) : Nat := n
@[implemented_by implTarget] def implSpec (n : Nat) : Nat := n + 0
unsafe def unsafeFn (n : Nat) : Nat := n
@[implemented_by unsafeFn] def viaUnsafe (n : Nat) : Nat := n
def usesSorry : Nat := sorry
theorem nd : 2 + 2 = 4 := by native_decide
def usesNd : Nat := have _ := nd; 1
def usesAx : Nat := have _ := myAx; 1
axiom hidAx : 1 = 3
partial def viaBody (n : Nat) : Nat := have _ := hidAx; if n > 5 then n else viaBody (n + 1)
unsafe def usesLc : Nat := #[1][5]'lcProof
@[implemented_by usesLc] def viaLc : Nat := 0
@[extern "part_ext"] opaque partExt : Nat → Nat
partial def loopE (n : Nat) : Nat := if n > 5 then partExt n else loopE (n + 1)
@[extern "bare_init"] opaque bareExt : Nat → Nat
@[extern "bare_builtin_init"] opaque bareBuiltinExt : Nat → Nat
initialize do IO.println (bareExt 1)
builtin_initialize do IO.println (bareBuiltinExt 1)
initialize initRef : IO.Ref Nat ← IO.mkRef (initExt 1)
def spin (n : Nat) : Nat := Id.run do
  let mut i := n
  while i < 10 do i := i + 1
  return i
def spinFix (n : Nat) : Option Nat := if n > 5 then some n else spinFix (n + 1)
partial_fixpoint
def spinIter : IO Unit := IO.iterate (0 : Nat) fun n => pure (Sum.inl (n + 1) : Sum Nat Unit)
structure Forever where
instance : Stream Forever Nat where next? _ := some (0, {})
def spinStream : IO Unit := do for _ in ({} : Forever) do pure ()
def main : IO Unit := do
  IO.println s!"{spin 0} {spinFix 0} {loopP 0} {externFn 1} {opaqueVal} {implSpec 1} {viaUnsafe 1} {usesSorry} {usesNd} {usesAx} {viaBody 0} {viaLc} {loopE 0}"
  spinIter
  spinStream
"""
        with tempfile.TemporaryDirectory(prefix="tcb-gate-") as tmp:
            (Path(tmp) / "Bad.lean").write_text(source, encoding="utf-8")
            built = _lean(["Bad.lean", "-o", "Bad.olean"], Path(tmp), cwd=Path(tmp))
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            done = _lean(["--run", str(GATE), "bad=Bad"], Path(tmp))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        for expected in ("axiom myAx", "axiom sorryAx", "axiom nd._native.native_decide.ax_1_1", "partial loopP", "loop spin", "loop spinIter", "loop spinStream", "fixpoint spinFix", "extern externFn",
                         "extern initExt", "opaque opaqueVal", "implemented_by implSpec", "unsafe unsafeFn",
                         "axiom hidAx", "axiom lcProof", "unsafe usesLc", "extern partExt", "extern bareExt", "extern bareBuiltinExt"):
            self.assertIn(f"VIOLATION {expected}", done.stdout)


if __name__ == "__main__":
    unittest.main()
