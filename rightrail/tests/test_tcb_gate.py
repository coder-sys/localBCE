"""TCB gate (Constitution V.3, XI.2): what each pinned Lean executable runs is proof-backed and has no trusted escape hatch.

`tools/tcb_gate.lean` walks every constant reachable from each executable's `main`, its startup initializers and the `@[csimp]`
theorems, and fails on a non-standard axiom (`sorryAx`, `Lean.ofReduceBool`) or a `partial`, `implemented_by`, `extern`, `opaque`,
`unsafe`, `partial_fixpoint`, `while`/`repeat`, `IO.iterate` or stream-`for` constant its allowlist does not name (the one thing it accepts by structure,
not by name, is the compiler's own `I.ctorIdx` with its unsafe `I.ctorIdx._impl`, whose value and implementation it rebuilds and compares).  The live gate needs 3-5 GB, so the default run only checks the committed
`tools/tcb_report.txt`: it must be for the pinned exes' import closures (and lakefile.toml, lean-toolchain, lake-manifest.json), the gate file and the pinned exe bytes, hold no violation, and name
exactly the known VIOLATION-TODO set.  The pin procedure (`tools/tcb_pin.ps1`, RR_TCB_LIVE=1) builds nothing: it reruns the gate on the
built exes (whose bytes must equal the pins; the engine exes' the report's lines unless `-Regen` sets RR_TCB_REGEN=1), pins the toolchain and rewrites the report."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
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
PROVENANCE = ROOT / "artifacts" / "gate-verify" / "PROVENANCE.txt"
REPORT = ROOT / "tools" / "tcb_report.txt"
ENGINE_EXES = ("gate_engine",)  # the decision program, with fsync/rename C; pinned by the report line, not by a committed binary
TCB_EXES = gate.PINNED_EXES + ("gate_verify",) + ENGINE_EXES + ("obligations_shard",)
VERSION = (LEAN / "lean-toolchain").read_text("utf-8").strip().split(":v")[1]
TOOLCHAIN = Path.home() / ".elan" / "toolchains" / f"leanprover--lean4---v{VERSION}"
BUILT = LEAN / ".lake" / "build" / "lib" / "lean"
LIVE = unittest.skipUnless(os.environ.get("RR_TCB_LIVE") == "1", "live TCB gate: run tools/tcb_pin.ps1 (RR_TCB_LIVE=1)")
# The committed pins of the two executables: the exes the report must be about.
EXE_PINS = {
    "blind_financial_worker": engine.EVALUATOR_ARTIFACT_SHA256.hex(),
    "gate_verify": signer.VERIFY_PIN.read_text("utf-8").strip(),
    "obligations_shard": (ROOT / "artifacts" / "obligations-shard" / "obligations_shard.sha256").read_text("utf-8").split()[0],
}
# The open items: a new one changes this set (and STATUS.md).  serve/readExact/readFinancialBounded, rejNtt and sampleInBall
# are closed by lean-partials-v1.
EXPECTED_TODO = {exe: set() for exe in TCB_EXES}
# The only C the pinned closures call: (file, `@[extern` count), mirrored by `allowed` in tools/tcb_gate.lean.
EXTERN_FILES = {"Gate/Flat/Io.lean": 7, "Gate/Obligations/Main.lean": 1}  # 7: pgReadAt, which obligations_shard reads its log with


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _tree(files: list[Path]) -> str:
    """SHA-256 over `sha256  path` lines (paths relative to the toolchain, sorted), the shape of PROVENANCE manifests."""
    return hashlib.sha256("".join(f"{_sha256(p)}  {p.relative_to(TOOLCHAIN).as_posix()}\n" for p in sorted(files)).encode()).hexdigest()


def _olean_line() -> str:
    """Every Init, Std and Lean module file the allowlist and the gate trust (oleans, IR, server data), less `.ilean` editor data."""
    lib = TOOLCHAIN / "lib" / "lean"
    files = [p for p in lib.rglob("*") if p.is_file() and not p.name.endswith(".ilean") and p.relative_to(lib).parts[0].split(".")[0] in ("Init", "Std", "Lean")]
    return f"toolchain oleans  {_tree(files)}  {len(files)} files"


def _provenance_pin(text: str, exe: str) -> str:
    pins = re.findall(rf"^pin {exe} ([0-9a-f]{{64}})\s*$", text, re.M)
    assert len(pins) == 1, f"PROVENANCE.txt needs exactly one `pin {exe} <sha256>` line"
    return pins[0]


def _bound(report: str) -> list[str]:
    """The report's binding lines, literally: the gate file and each built exe, by SHA-256."""
    return [line for line in report.splitlines() if line.startswith(("gate  ", "exe "))]


def _blocks(report: str) -> dict[str, tuple[int, set[str]]]:
    """exe -> (violation count, VIOLATION-TODO set) from the gate's per-exe output."""
    found = {}
    for block in re.split(r"(?m)^(?=\S+: \d+ constants walked)", report)[1:]:
        todo = {line.strip().removeprefix("VIOLATION-TODO ") for line in block.splitlines() if line.strip().startswith("VIOLATION-TODO ")}
        found[block.split(":")[0]] = (int(re.search(r"(\d+) violations", block).group(1)), todo)
    return found


LEXEME_RE = re.compile(r"""--[^\n]*|/-|(?<![\w.'])r(?P<hash>#*)"|(?<![\w.'])\w+!"|"|«[^»]*»|(?<![\w'!?])'(?:\\(?:x[0-9a-fA-F]{2}|u\{?[0-9a-fA-F]+\}?|.)|[^\\'\n])'""")
COMMENT_EDGE_RE = re.compile(r"/-|-/")
SCAN_EVENT_RE = re.compile(
    r"(?m)^[ \t]*namespace[ \t]+(?P<ns>\S+)"
    r"|^[ \t]*(?:(?:public|noncomputable|meta|@\[[^\]]*\])[ \t]+)*(?P<block>section|mutual)\b"
    r"|^[ \t]*end\b"
    r"|@\[[^\]]*\bcsimp\b[^\]]*\]\s*(?:@\[[^\]]*\]\s*)*(?P<mods>(?:(?:private|protected)\s+)*)theorem\s+(?P<thm>[^\s:({\[]+)"
    r"|\battribute\s*\[(?P<body>[^\]]*)\](?P<rest>[^\n]*)")


def _string_end(text: str, at: int, interpolated: bool) -> int:
    """Index after the string whose body starts at `at`; an interpolated string's `{...}` holds code, with strings of its own."""
    while at < len(text):
        c = text[at]
        if c == '"':
            return at + 1
        if c == "{" and interpolated:
            depth, at = 1, at + 1
            while depth and at < len(text):
                if text[at] == '"':
                    at = _string_end(text, at + 1, text[at - 1] == "!")
                    continue
                depth += {"{": 1, "}": -1}.get(text[at], 0)
                at += 1
            continue
        at += 2 if c == "\\" else 1
    return len(text)


def _strip_lean(text: str) -> str:
    """The source with comments removed and string, char and guillemet literals emptied (newlines kept), lexed left to right as Lean does:
    a `/-` inside a line comment or a string opens nothing, and a block comment nests."""
    out, at = [], 0
    while m := LEXEME_RE.search(text, at):
        out.append(text[at:m.start()])
        token, at = m.group(), m.end()
        if token == "/-":
            depth = 1
            while depth and (edge := COMMENT_EDGE_RE.search(text, at)):
                depth += 1 if edge.group() == "/-" else -1
                at = edge.end()
            if depth:
                at = len(text)
            out.append(" ")
        elif token.startswith("--"):
            out.append(" ")
        elif token.endswith('"') and m.group("hash") is None:  # a string (`s!"`, `m!"`, `f!"`: interpolated), to its unescaped quote
            at = _string_end(text, at, token != '"')
            out.append('""')
        elif token.endswith('"'):  # a raw string: to the quote and its `#` run
            end = re.compile('"' + re.escape(m.group("hash"))).search(text, at)
            at = end.end() if end else len(text)
            out.append('""')
        else:
            out.append("«»" if token.startswith("«") else "''")
    return "".join(out) + text[at:]


def _unwalked_csimps(lean: Path, report: str) -> set[str]:
    """`exe path name` for each `@[csimp]` theorem (source scan, comments and strings removed) in a file of a pinned exe's import closure
    that the exe's report block does not list, by its full name, among the project csimp theorems it walked; `path` alone for a `csimp`
    anywhere under lean/BlindLedger that the scan cannot tie to a theorem name.  A declared name is its namespace plus its name
    (`private`: Lean's `_private.<module>.0.` form); a name in `attribute [csimp]` may be any enclosing namespace's."""
    walked = {block.split(":")[0]: set(re.findall(r"(?:«[^»]*»|[^\s,«\]])+", re.search(r"csimp: \d+ theorems walked, \d+ from project modules \[([^\]]*)\]", block).group(1)))
              for block in re.split(r"(?m)^(?=\S+: \d+ constants walked)", report)[1:]}
    found: dict[str, list[tuple[str, list[str]]]] = {}  # path -> (name as written, accepted full names)
    out = set()
    for source in sorted((lean / "BlindLedger").rglob("*.lean")):
        text = _strip_lean(source.read_text("utf-8"))
        path = source.relative_to(lean).as_posix()
        module = path.removesuffix(".lean").replace("/", ".")
        scopes: list[list[str]] = []  # one per open namespace (its parts), section or mutual block (none)
        names: list[tuple[str, list[str]]] = []
        tied = 0

        def accepted(name: str, nearest: bool, private: bool) -> list[str]:
            if name.startswith("_root_."):
                full = [name.removeprefix("_root_.")]
            else:
                prefix = [part for scope in scopes for part in scope]
                full = [".".join(prefix + [name])] if nearest else [".".join(prefix[:k] + [name]) for k in range(len(prefix), -1, -1)]
            return [f"_private.{module}.0.{n}" for n in full] if private else full

        for m in SCAN_EVENT_RE.finditer(text):
            if m.group("ns"):
                scopes.append(m.group("ns").split("."))
            elif m.group("block"):
                scopes.append([])
            elif m.group("thm"):
                names.append((m.group("thm"), accepted(m.group("thm"), True, "private" in m.group("mods"))))
                tied += 1
            elif m.group("body") is not None:
                if re.search(r"\bcsimp\b", m.group("body")):
                    listed = m.group("rest").split()
                    names += [(n, accepted(n, False, False)) for n in listed]
                    tied += bool(listed)
            elif scopes:
                scopes.pop()
        if len(re.findall(r"\bcsimp\b", text)) != tied:
            out.add(f"{path} csimp not tied to a theorem name")
        found[path] = names
    for exe in TCB_EXES:
        for path in sorted({m.replace(".", "/") + ".lean" for m in gate._pinned_exe_modules(lean, (exe,), True)} & found.keys()):
            out |= {f"{exe} {path} {name}" for name, full in found[path] if not walked.get(exe, set()).intersection(full)}
    return out


def _lean(args: list[str], lean_path: Path, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, LEAN_PATH=str(lean_path), LEAN_SYSROOT=str(TOOLCHAIN))
    return subprocess.run([str(TOOLCHAIN / "bin" / "lean.exe"), *args], env=env, cwd=cwd, capture_output=True, text=True, timeout=900)


class TcbReportTests(unittest.TestCase):
    """Cheap checks, always on."""

    def test_pinned_closures_hold_no_proof_module(self) -> None:
        """No KAT or `native_decide` module sits in the worker's or gate_verify's import closure (the engine exes share theorem files with their code; their manifest covers them)."""
        self.assertGreater(gate._check_pinned_exe_closure(LEAN, gate.PINNED_EXES + ("gate_verify",)), 20)

    def test_semantic_gate_pins_the_engine_worker(self) -> None:
        """The semantic gate's worker pin is the engine's: same bytes, same SHA-256, same file."""
        pin = gate.PINNED_EXE_IDENTITIES["blind_financial_worker"]
        self.assertEqual((pin.bytes, pin.sha256), (engine.EVALUATOR_ARTIFACT_SIZE_BYTES, EXE_PINS["blind_financial_worker"]))
        self.assertEqual(ROOT / pin.artifact, engine.EVALUATOR_PATH)

    def test_manifest_covers_the_pinned_closures_and_build_files_only(self) -> None:
        """An edit to a lean file no pinned exe imports leaves the manifest alone; one to a closure file or a build file moves it."""
        closure = {module.replace(".", "/") + ".lean" for module in gate._pinned_exe_modules(LEAN, TCB_EXES, True)}
        outside = next(p for p in sorted(LEAN.rglob("*.lean")) if ".lake" not in p.parts and p.relative_to(LEAN).as_posix() not in closure)
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "lean"
            shutil.copytree(LEAN, copy, ignore=shutil.ignore_patterns(".lake"))
            before = gate.pinned_source_manifest(copy, TCB_EXES, True)
            self.assertEqual(before, gate.pinned_source_manifest(LEAN, TCB_EXES, True))
            with (copy / outside.relative_to(LEAN)).open("a", encoding="utf-8") as handle:
                handle.write("-- edit\n")
            self.assertEqual(gate.pinned_source_manifest(copy, TCB_EXES, True), before, outside.name)
            for name in ("BlindLedger/Gate/VerifyCli.lean", "lakefile.toml", "lean-toolchain", "lake-manifest.json"):
                with self.subTest(name):
                    path = copy / name
                    original = path.read_bytes()
                    path.write_bytes(original + b"\n")
                    self.assertNotEqual(gate.pinned_source_manifest(copy, TCB_EXES, True), before)
                    path.write_bytes(original)
                    self.assertEqual(gate.pinned_source_manifest(copy, TCB_EXES, True), before)

    def test_committed_report_is_current_and_clean(self) -> None:
        report = REPORT.read_text("utf-8")
        self.assertIn(f"manifest  {gate.pinned_source_manifest(LEAN, TCB_EXES, True)}", report.splitlines(), "a pinned exe's sources changed since the report: rerun tools/tcb_pin.ps1")
        self.assertEqual(_blocks(report), {exe: (0, todo) for exe, todo in EXPECTED_TODO.items()})
        self.assertEqual(report.count("allowlist BlindLedger.Financial.serveWorker x1"), 1, "the worker's one partial_fixpoint")

    def test_committed_report_rooted_the_constant_equalities(self) -> None:
        """Without RR_TCB_LIVE: the report comes from a gate that roots every constant typed `@c1 = @c2` (a local csimp is stored nowhere), so each block
        states how many it rooted, as many as today's closures hold (a count moves only with a source change, which the manifest line also catches)."""
        report = REPORT.read_text("utf-8")
        self.assertIn(f"gate  {_sha256(GATE)}", report.splitlines())
        self.assertIn("eqConsts", GATE.read_text("utf-8"))
        rooted = {block.split(":")[0]: int(re.search(r"; (\d+) constant-equality constants also rooted;", block).group(1)) for block in re.split(r"(?m)^(?=\S+: \d+ constants walked)", report)[1:]}
        self.assertEqual(rooted, {"blind_financial_worker": 15, "gate_verify": 0, "gate_engine": 5, "obligations_shard": 16})
        pairs = {block.split(":")[0]: int(re.search(r"compiler-built ctorIdx pairs x(\d+)", block).group(1)) for block in re.split(r"(?m)^(?=\S+: \d+ constants walked)", report)[1:]}
        self.assertEqual(pairs, {"blind_financial_worker": 27, "gate_verify": 11, "gate_engine": 19, "obligations_shard": 20}, "the compiler-built ctorIdx pairs each closure accepts by structure")

    def test_committed_report_is_about_the_pinned_exes_and_this_gate(self) -> None:
        lines = _bound(REPORT.read_text("utf-8"))
        self.assertEqual(len(lines), 1 + len(TCB_EXES), lines)
        self.assertEqual(lines[0], f"gate  {_sha256(GATE)}", "the gate changed since the report: rerun tools/tcb_pin.ps1")
        for exe, line in zip(TCB_EXES, lines[1:]):
            with self.subTest(exe):
                if exe in EXE_PINS:
                    self.assertEqual(line, f"exe {exe}  {EXE_PINS[exe].lower()}", "a pinned exe changed since the report: rerun tools/tcb_pin.ps1")
                else:  # test-only exe, no committed binary: the line is checked against the built exe (next test) and PROVENANCE.txt
                    self.assertRegex(line, rf"^exe {exe}  [0-9a-f]{{64}}$")
                    self.assertEqual(_provenance_pin(PROVENANCE.read_text("utf-8"), exe), line.split()[-1], "PROVENANCE.txt's `pin` line is not the reported hash")

    def test_provenance_pin_refuses_a_retired_hash(self) -> None:
        """The `pin <exe> <hash>` line is the one current hash; a retired hash that the prose still names does not satisfy it."""
        text = PROVENANCE.read_text("utf-8")
        for exe, retired in (("gate_engine", "91c41e01"),):
            with self.subTest(exe):
                self.assertIn(retired, text)  # still named in the history prose
                self.assertNotEqual(_provenance_pin(text, exe), next(h for h in re.findall(r"[0-9a-f]{64}", text) if h.startswith(retired)))

    def test_built_engine_exes_match_the_report(self) -> None:
        """If the in-tree build exists, the engine exe's bytes are the report's line (a stale or edited report line fails here)."""
        lines = _bound(REPORT.read_text("utf-8"))
        built = {exe: LEAN / ".lake" / "build" / "bin" / f"{exe}.exe" for exe in ENGINE_EXES}
        if not any(path.is_file() for path in built.values()):
            self.skipTest("no in-tree gate_engine build (lake build gate_engine)")
        for exe, path in built.items():
            with self.subTest(exe):
                if path.is_file():
                    self.assertIn(f"exe {exe}  {_sha256(path)}", lines, f"the built {exe} is not the reported one: rebuild, or re-pin with tools/tcb_pin.ps1 -Regen")

    def test_externs_are_the_allowlisted_few(self) -> None:
        """A new `extern` attribute (any `@[...]` or `attribute [...]` list, any position, multi-line) in a pinned closure file fails until `allowed` in
        tools/tcb_gate.lean and EXTERN_FILES name it.  A text scan, so a cheap early alarm; the authority is the live gate (test_gate_refuses_every_escape_hatch)."""
        def found(lean: Path) -> dict[str, int]:
            out = {}
            for module in gate._pinned_exe_modules(lean, TCB_EXES, True):
                path = module.replace(".", "/") + ".lean"
                if (lean / path).is_file():
                    text = _strip_lean((lean / path).read_text("utf-8"))  # comments and strings name attributes too
                    if n := sum(bool(re.search(r"(?<![\w.])extern\b", body)) for body in re.findall(r"(?:@|\battribute\s*)\[([^\]]*)\]", text)):
                        out[path.removeprefix("BlindLedger/")] = n
            return out
        self.assertEqual(found(LEAN), EXTERN_FILES)
        allowed = GATE.read_text("utf-8")
        for name in ("Gate.Obligations.openExclusive", *(f"Gate.Flat.Io.{n}" for n in ("pgOpen", "pgRead", "pgReadAt", "pgWrite", "pgSync", "pgTrunc", "pgClose"))):
            self.assertIn(f'`BlindLedger.{name}, module := false, kinds := ["extern", "opaque"]', allowed)
        self.assertEqual(allowed.count('kinds := ["extern", "opaque"]'), 8)
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "lean"
            shutil.copytree(LEAN, copy, ignore=shutil.ignore_patterns(".lake"))
            path = copy / "BlindLedger/Gate/Engine/OneProc.lean"
            original = path.read_bytes()
            for plant in ('@[extern "evil"] opaque evil : IO UInt32', '@[inline, extern "evil"] opaque evil : IO UInt32', '@[inline] @[extern "evil"] opaque evil : IO UInt32',
                          '@[specialize,\n  extern "evil"]\nopaque evil : IO UInt32', 'attribute [extern "evil"] Nat.add'):
                with self.subTest(plant):
                    path.write_bytes(original + f"\n{plant}\n".encode())
                    self.assertNotEqual(found(copy), EXTERN_FILES)

    def test_toolchain_note_matches_the_report(self) -> None:
        pinned = PIN.read_text("utf-8").splitlines()
        self.assertIn(f"lean-toolchain: {(LEAN / 'lean-toolchain').read_text('utf-8').strip()}", pinned)
        line = next(l for l in pinned if l.startswith("toolchain oleans"))
        self.assertIn(line, REPORT.read_text("utf-8").splitlines())

    def test_project_csimp_theorems_are_walked(self) -> None:
        """Every `@[csimp]` theorem a pinned exe imports is a root the gate walked for that exe: its compiled code runs the
        replacement.  The live gate's own check is test_gate_refuses_every_escape_hatch (a project csimp proved by an axiom, global or `local`)."""
        report = REPORT.read_text("utf-8")
        self.assertEqual(_unwalked_csimps(LEAN, report), set())
        with tempfile.TemporaryDirectory() as tmp:  # a planted project csimp the report does not list fails
            copy = Path(tmp) / "lean"
            shutil.copytree(LEAN, copy, ignore=shutil.ignore_patterns(".lake"))
            with (copy / "BlindLedger/Gate/VerifyCli.lean").open("a", encoding="utf-8") as handle:
                handle.write("\n@[inline]\n@[csimp] theorem planted_eq : @f = @g := rfl\nattribute [csimp] planted_a\n")
            self.assertEqual(_unwalked_csimps(copy, report), {f"gate_verify BlindLedger/Gate/VerifyCli.lean {n}" for n in ("planted_eq", "planted_a")})

    def test_csimp_scan_is_lexically_correct(self) -> None:
        """A `/-` in a line comment or a string opens no comment (it once hid the next csimp theorem); a real comment hides one; names compare in full."""
        for text, want in (("a -- see /- here\nb", "a  \nb"), ('x "/-" y', 'x "" y'), ("/- a /- b -/ c -/ d", "  d"), (r'"a\"/-b" c', '"" c'), ('r#"/-"# d', '"" d'), ("'\"' /- x -/ y", "''   y"),
                           ("/-- doc -- /- x -/ -/ e", "  e"), ("f' /- x -/", "f'  "), ('s!"{"/-"}" /- c -/ d', '""   d'), ('m!"a{s!"{"}"}"}" e', '"" e')):
            with self.subTest(text):
                self.assertEqual(_strip_lean(text), want)
        report = REPORT.read_text("utf-8")
        planted = {"line comment": "-- see /- here\n@[csimp] theorem trick : @f = @g := rfl\n/- later -/\n",
                   "string": 'def s := "/-"\n@[csimp] theorem trick : @f = @g := rfl\n/- later -/\n',
                   "namespace": "namespace Planted\n@[csimp] theorem trick : @f = @g := rfl\nend Planted\n"}
        listing = lambda names: re.sub(r"(?ms)^(gate_verify: .*?from project modules )\[\]", lambda m: f"{m.group(1)}[{', '.join(names)}]", report, count=1)
        expected = {"gate_verify BlindLedger/Gate/VerifyCli.lean trick"}
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "lean"
            shutil.copytree(LEAN, copy, ignore=shutil.ignore_patterns(".lake"))
            path = copy / "BlindLedger/Gate/VerifyCli.lean"
            original = path.read_bytes()
            for name, plant in planted.items():
                with self.subTest(name):
                    path.write_bytes(original + b"\n" + plant.encode())
                    self.assertEqual(_unwalked_csimps(copy, report), expected)
                    self.assertEqual(_unwalked_csimps(copy, listing(["Other.Planted.trick", "BlindLedger.trick"])), expected, "a suffix or another namespace is not the name")
                    self.assertEqual(_unwalked_csimps(copy, listing(["Planted.trick" if name == "namespace" else "trick"])), set())
            path.write_bytes(original + b"\n/- @[csimp] theorem hidden : @f = @g := rfl -/\n")
            self.assertEqual(_unwalked_csimps(copy, report), set())


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
        text = f"manifest  {gate.pinned_source_manifest(LEAN, TCB_EXES, True)}\ngate  {_sha256(GATE)}\n"
        for exe in TCB_EXES:
            built = _sha256(LEAN / ".lake" / "build" / "bin" / f"{exe}.exe")
            if exe in EXE_PINS:
                self.assertEqual(built, EXE_PINS[exe].lower(), f"the built {exe} is not the pinned one: build in-tree first")
            elif os.environ.get("RR_TCB_REGEN") != "1":  # a check run: the committed hash is the pin; only -Regen records a new one
                self.assertIn(f"exe {exe}  {built}", REPORT.read_text("utf-8").splitlines(), f"the built {exe} is not the reported one: rebuild, or re-pin with tools/tcb_pin.ps1 -Regen")
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
@[noinline] def slowF (n : Nat) : Nat := n + 1
def usesSlow (n : Nat) : Nat := slowF n
def fastF (n : Nat) : Nat := n + 1
axiom csimpAx : @slowF = @fastF
@[csimp] theorem slowF_eq : @slowF = @fastF := csimpAx
@[noinline] def slowG (n : Nat) : Nat := n + 2
def usesSlowG (n : Nat) : Nat := slowG n
def fastG (n : Nat) : Nat := n + 2
axiom localCsimpAx : @slowG = @fastG
theorem slowG_eq : @slowG = @fastG := localCsimpAx
attribute [local csimp] slowG_eq
@[noinline] def slowH (n : Nat) : Nat := n + 3
def usesSlowH (n : Nat) : Nat := slowH n
def fastH (n : Nat) : Nat := n + 3
axiom directAx : @slowH = @fastH
attribute [local csimp] directAx
@[noinline] def slowK (n : Nat) : Nat := n + 4
def usesSlowK (n : Nat) : Nat := slowK n
def fastK (n : Nat) : Nat := n + 4
axiom directDefAx : @slowK = @fastK
def directDef : @slowK = @fastK := directDefAx
attribute [local csimp] directDef
def main : IO Unit := do
  IO.println s!"{spin 0} {spinFix 0} {loopP 0} {externFn 1} {opaqueVal} {implSpec 1} {viaUnsafe 1} {usesSorry} {usesNd} {usesAx} {viaBody 0} {viaLc} {loopE 0} {usesSlow 1} {usesSlowG 1} {usesSlowH 1} {usesSlowK 1}"
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
                         "axiom hidAx", "axiom lcProof", "unsafe usesLc", "extern partExt", "extern bareExt", "extern bareBuiltinExt", "axiom csimpAx", "axiom localCsimpAx", "axiom directAx", "axiom directDefAx"):
            self.assertIn(f"VIOLATION {expected}", done.stdout)
        # The module's own csimp is a root (its axiom is reached only through it) and, still called by usesSlow, is stale.  The `local csimp` is
        # stored nowhere, so only its equality shape roots it (any constant typed `@f = @g`, theorem or not: csimpAx, slowF_eq, localCsimpAx, slowG_eq, directAx, directDefAx, directDef: 7).
        self.assertRegex(done.stdout, r"csimp: \d+ theorems walked, 1 from project modules \[slowF_eq\]; 7 constant-equality constants also rooted; replaced constants still called by compiled code: \[[^\]]*\bslowF\]")

    def test_the_statement_hash_tool_carries_the_same_ctoridx_check(self) -> None:
        def block(path: Path) -> str:
            text = path.read_text("utf-8")
            return text[text.index("-- CTORIDX-PAIR-BEGIN"):text.index("-- CTORIDX-PAIR-END")]
        self.assertEqual(block(GATE), block(ROOT / "tools" / "stmt_hash.lean"))

    def test_ctoridx_pair_is_accepted_by_structure_only(self) -> None:
        """The compiler's `I.ctorIdx` with its unsafe `I.ctorIdx._impl` is accepted by structure (a pair written by hand to the same shape too);
        each look-alike that differs in one way is refused, and each case isolates one check of `ctorIdxPair`."""
        def enum(name: str, impl: str = "getObjTagNat x", alts: str = "(nat_lit 0) (nat_lit 1)", attr: str = "implemented_by {name}.ctorIdx._impl", extra: str = "") -> str:
            return (f"set_option genCtorIdx false in\ninductive {name} | a | b\n{extra}"
                    f"unsafe def {name}.ctorIdx._impl (x : {name}) : Nat := {impl}\n"
                    f"@[{attr.format(name=name)}] def {name}.ctorIdx (x : {name}) : Nat := {name}.casesOn (motive := fun _ => Nat) x {alts}\n")
        bad = "".join((
            enum("Foo", impl="7"),                                           # the tag read is another body
            enum("Swap", alts="(nat_lit 1) (nat_lit 0)"),                    # the alternatives are not the constructor indices
            enum("Lit", alts="(nat_lit 0) (nat_lit 2)"),                     # a wrong literal
            enum("Fake", attr="implemented_by fakeCtorIdx", extra="def fakeCtorIdx (x : Fake) : Nat := 0\n"),  # implemented by a safe function instead of `_impl`
            enum("Chain", extra="def fakeChain (x : Chain) : Nat := 0\n").replace("unsafe def Chain.ctorIdx._impl", "@[implemented_by fakeChain] unsafe def Chain.ctorIdx._impl"),
            enum("Ext").replace("unsafe def Ext.ctorIdx._impl", '@[extern "ext_tag"] unsafe def Ext.ctorIdx._impl'),
            "set_option genCtorIdx false in\nstructure Solo where (v : Nat)\n"
            "unsafe def Solo.ctorIdx._impl (x : Solo) : Nat := getObjTagNat x\n"
            "@[implemented_by Solo.ctorIdx._impl] def Solo.ctorIdx (x : Solo) : Nat := Solo.casesOn (motive := fun _ => Nat) x (fun _ => nat_lit 0)\n",  # one constructor
            'def main : IO Unit := do\n  IO.println s!"{Foo.a.ctorIdx} {Swap.a.ctorIdx} {Lit.a.ctorIdx} {Fake.a.ctorIdx} {Chain.a.ctorIdx} {Ext.a.ctorIdx} {(Solo.mk 1).ctorIdx}"\n'))
        good = """inductive Color | red | green | blue
inductive Pair (α : Type) : Nat → Type | one (a : α) : Pair α 0 | two (a b : α) : Pair α 1
def pick (n : Nat) : Color := if n = 0 then .red else .blue
def pickPair (n : Nat) : Pair Nat 0 := .one n
""" + enum("Hand") + """def main : IO Unit := IO.println s!"{(pick 1).ctorIdx} {(pickPair 1).ctorIdx} {Hand.a.ctorIdx}"
"""
        with tempfile.TemporaryDirectory(prefix="tcb-gate-") as tmp:
            for name, text in (("Bad", bad), ("Good", good)):
                (Path(tmp) / f"{name}.lean").write_text(text, encoding="utf-8")
                built = _lean([f"{name}.lean", "-o", f"{name}.olean"], Path(tmp), cwd=Path(tmp))
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            refused = _lean(["--run", str(GATE), "bad=Bad"], Path(tmp))
            ok = _lean(["--run", str(GATE), "--list", "good=Good"], Path(tmp))
        self.assertEqual((ok.returncode, ok.stderr), (0, ""), ok.stdout)
        self.assertIn("  0 violations", ok.stdout)
        listed = ok.stdout.replace("\r\n", "\n")
        for half in ("implemented_by Color.ctorIdx", "unsafe Color.ctorIdx._impl", "implemented_by Pair.ctorIdx", "unsafe Pair.ctorIdx._impl", "implemented_by Hand.ctorIdx", "unsafe Hand.ctorIdx._impl"):
            self.assertIn(f"    {half}\n", listed)
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        found = sorted(line.strip().removeprefix("VIOLATION ") for line in refused.stdout.replace("\r\n", "\n").splitlines() if line.strip().startswith("VIOLATION "))
        self.assertEqual(found, sorted([
            "implemented_by Foo.ctorIdx [Bad]", "unsafe Foo.ctorIdx._impl [Bad]",
            "implemented_by Swap.ctorIdx [Bad]", "unsafe Swap.ctorIdx._impl [Bad]",
            "implemented_by Lit.ctorIdx [Bad]", "unsafe Lit.ctorIdx._impl [Bad]",
            "implemented_by Fake.ctorIdx [Bad]",
            "implemented_by Chain.ctorIdx._impl [Bad]",
            "extern Ext.ctorIdx._impl [Bad]",
            "implemented_by Solo.ctorIdx [Bad]", "unsafe Solo.ctorIdx._impl [Bad]",
        ]), refused.stdout)
        self.assertIn("  11 violations", refused.stdout)

if __name__ == "__main__":
    unittest.main()
