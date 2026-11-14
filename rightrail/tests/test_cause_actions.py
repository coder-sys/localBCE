"""Every cause the gate, its host and the readers can give a person has one row in app/cause_actions.json, and no row
names a cause nothing gives.  The emitted set is read from the sources, never listed by hand."""

import ast
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
SPEC = ROOT / "lean/BlindLedger/Gate"
GATE_CALLS = {"GateDecideError", "MachineFault", "DataFault", "WorkerDied", "GateProducerError", "GatePayerError",
              "GateSignerError", "_hold", "_reread", "SetAside"}
GATE_FILES = ("decide", "producer", "payer", "signer", "ffs")
READER_CALLS = {"ReaderError", "_Bad", "Finding", "repair"}
UNITS = {"file", "set", "segment", "group", "interchange", "loop", "line", "payment"}
CODE = re.compile(r"[a-z][a-z0-9_]*\Z")


def _strings(node, skip=()):
    """The code-like words a cause expression can evaluate to: not comparands or subscripts, and not an f-string's holes."""
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str) and CODE.match(node.value) and node.value not in skip and node.value != "not_":
            yield node.value
    elif isinstance(node, ast.JoinedStr):
        head = re.match(r"[a-z][a-z0-9_]*", node.values[0].value) if node.values and isinstance(node.values[0], ast.Constant) else None
        if head and len(node.values) > 1:
            yield head.group(0)
    elif not isinstance(node, (ast.Compare, ast.Subscript)):
        for child in ast.iter_child_nodes(node):
            yield from _strings(child, skip)


def _name(call):
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


COVERED = {"why", "cause", "cause(r)", "step", "str(e)", "self._fault[prod.shard]"}  # read elsewhere: assignments, the custody tuple, a producer's own refusal


def _stems():
    """The names the signer builds its causes from: the stem of each pinned executable it runs."""
    tree = ast.parse((APP / "right_rail_gate_signer.py").read_text("utf-8"))
    return [Path(c.value).stem for n in tree.body if isinstance(n, ast.AnnAssign) and n.target.id in ("BINARY", "VERIFY")
            for c in ast.walk(n.value) if isinstance(c, ast.Constant) and str(c.value).endswith(".exe")]


def _custody():
    """The refusals Lean's custody check can give, which the producer raises under their own names."""
    tree = ast.parse((APP / "right_rail_gate_signer.py").read_text("utf-8"))
    names = next(n for n in ast.walk(tree) if isinstance(n, ast.Tuple) and "no_store" in [getattr(e, "value", 0) for e in n.elts])
    return {e.value for e in names.elts} - {"create", "ready", "catch_up"}


def _gate(path, unresolved):
    out = set()
    tree = ast.parse(path.read_text("utf-8"))
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _name(n) in GATE_CALLS and n.args:
            arg = n.args[{"_hold": -1, "_reread": 1, "SetAside": 1}.get(_name(n), 0)]
            if isinstance(arg, ast.JoinedStr) and isinstance(arg.values[0], ast.FormattedValue):  # f"{stem}_failed"
                out.update(stem + arg.values[1].value for stem in _stems())
            elif ast.unparse(arg) == "step":
                out.update(_custody())
            elif not set(_strings(arg)) and ast.unparse(arg) not in COVERED:
                unresolved.append(f"{path.name}:{n.lineno} {ast.unparse(arg)}")
            out.update(_strings(arg))
        elif isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ("why", "cause", "reason", "_DATA_FAULTS") for t in n.targets):
            out.update(_strings(n.value))
        elif isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_UNKNOWN" for t in n.targets):
            out.update(_strings(n.value))
        elif isinstance(n, ast.FunctionDef) and n.name == "_decide":  # the payer's release hold reasons
            for r in ast.walk(n):
                if isinstance(r, ast.Return) and r.value is not None:
                    out.update(_strings(r.value))
    if path.name.endswith("decide.py"):
        words = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and n.targets[0].id == "WORDS")
        out.update("flat_" + w.lower() for w in words[1:] if w != "IMAGE")  # IMAGE is reserved and never emitted
    return out


def _reader(path):
    out = set()
    tree = ast.parse(path.read_text("utf-8"))
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            name = _name(n)
            if name in ("Quarantine", "bad"):
                for a in n.args[2:3] if path.name.startswith("right_rail_reader") else n.args[1:2]:
                    out.update(_strings(a))
                out.update(s for k in n.keywords if k.arg == "cause" for s in _strings(k.value))
            elif name in READER_CALLS and n.args:
                out.update(_strings(n.args[0]))
            elif name == "read" and len(n.args) == 4:  # x12.read(data, sink, kind, ...): other kinds are set aside
                out.add("not_" + ast.literal_eval(n.args[2]))
        elif isinstance(n, ast.Assign) and any(isinstance(t, (ast.Name, ast.Attribute)) and
                                              getattr(t, "id", getattr(t, "attr", "")) in ("cause", "bad", "refused")
                                              for t in n.targets):
            out.update(s for s in _strings(n.value, UNITS))
        elif isinstance(n, ast.For) and isinstance(n.target, ast.Tuple) and getattr(n.target.elts[0], "id", "") in ("cause",):
            for t in ast.walk(n.iter):
                if isinstance(t, ast.Tuple) and t.elts and isinstance(t.elts[0], ast.Constant):
                    out.add(t.elts[0].value)
        elif isinstance(n, ast.Tuple) and len(n.elts) > 1 and getattr(n.elts[0], "value", None) in UNITS:
            out.update(s for s in _strings(n.elts[1]))
        elif isinstance(n, ast.JoinedStr) and len(n.values) == 2 and getattr(n.values[1], "value", "") == "_after_as_of":
            out.update(("reinstated_after_as_of", "waiver_after_as_of"))
    return out


def _lean():
    reasons = re.search(r"inductive Reason\n(.*?)deriving", (SPEC / "Rules/Spec.lean").read_text("utf-8"), re.S).group(1)
    out = set(re.findall(r"\b([A-Z][A-Z_]+)\b", re.sub(r"--[^\n]*", "", reasons)))
    auth = (SPEC / "Authority.lean").read_text("utf-8")
    refusals = re.search(r"inductive Refusal \|([^\n]*?) deriving", auth).group(1).split("|")
    run = (SPEC / "Rules/Run.lean").read_text("utf-8")
    admit = run[run.index("def admit"):run.index("let xfer")]
    out |= set(re.findall(r'HOLD ([A-Z_]+)"', (SPEC / "Frame/Spec.lean").read_text("utf-8")))  # a line too wide for the store
    out |= {re.search(r"def uncovered.*?\"([A-Z]+)\"", run, re.S).group(1)}  # a request no grant entry covers
    return out | {"grant_" + w.strip().lower() for w in refusals} | {"grant_" + w.lower() for w in re.findall(r'\.error "([A-Z_]+)"', admit)}


def _verify():
    """The payer's release holds and the custody refusals the checking program names."""
    text = (SPEC / "VerifyCli.lean").read_text("utf-8")
    names = re.search(r"def failureName.*?\n\n", text, re.S).group(0)
    steps = set(re.findall(r"GATE_VERIFY=CUSTODY ([a-z_]+)", text)) - {"create", "ready", "catch_up"}
    return set(re.findall(r'=> "([a-z]+)"', names)) | steps


def emitted(unresolved=None):
    """{code: {source file stem, ...}}; `unresolved` collects emitter arguments the parse cannot read."""
    found = {}
    unresolved = [] if unresolved is None else unresolved

    def add(codes, source):
        for c in codes:
            found.setdefault(c, set()).add(source)
    for stem in GATE_FILES:
        add(_gate(APP / f"right_rail_gate_{stem}.py", unresolved), f"gate_{stem}")
    for path in sorted(APP.glob("right_rail_reader_*.py")) + sorted(APP.glob("right_rail_x12*.py")):
        add(_reader(path), path.stem.replace("right_rail_", ""))
    add(_lean(), "gate_rules")
    add(_verify(), "gate_verify")
    return found


class CauseActionsTest(unittest.TestCase):
    def test_table_matches_what_is_emitted(self):
        rows = json.loads((APP / "cause_actions.json").read_text("utf-8"))
        table = {}
        for r in rows:
            self.assertEqual(set(r), {"code", "emitters", "kind", "meaning", "action"}, r)
            self.assertNotIn(r["code"], table, "one row per cause")
            self.assertIn(r["kind"], ("data", "machine", "configuration"), r["code"])
            self.assertTrue(r["meaning"].endswith(".") and r["action"].endswith("."), r["code"])
            self.assertGreater(len(r["meaning"]), 20, r["code"])
            for bad in (" or ", "investigate", "; ", "if it repeats"):
                self.assertNotIn(bad, r["action"], f"one action only: {r['code']}")
            table[r["code"]] = r
        lost = []
        seen = emitted(lost)
        self.assertEqual(lost, [], "an emitter argument the test cannot read")
        self.assertEqual(sorted(set(seen) - set(table)), [], "emitted with no row")
        self.assertEqual(sorted(set(table) - set(seen)), [], "row for a cause nothing emits")
        wrong = {c: (sorted(seen[c]), r["emitters"]) for c, r in table.items() if sorted(seen[c]) != r["emitters"]}
        self.assertEqual(wrong, {})


if __name__ == "__main__":
    unittest.main()
