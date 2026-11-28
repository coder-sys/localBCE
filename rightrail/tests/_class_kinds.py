"""Every kind of finding or set-aside the readers and the claim path can record, read from their source (ast), never listed by hand.

A kind is (module, name).  The readers record a fault in one of these shapes, and the walker finds each:
  - a call of ``Quarantine(...)`` or ``bad(...)`` whose cause is a string (a unit word first for the X12 readers),
  - a tuple ``(unit, "cause", ...)`` the X12 readers fill in before they report it,
  - a variable named ``cause`` or ``bad`` given a string (the X12 envelope),
  - ``Finding("kind", ...)`` and its f-string form over a loop's literal values (the exclusion list reader),
  - ``_Bad("cause")``, which the exclusion list reader files under the field it spoiled,
  - the causes of ``SetAside`` in ``right_rail_gate_ffs``: every string of a conditional expression and of a ``SetAside(...)`` call.
"""

from __future__ import annotations

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
UNITS = frozenset(("file", "interchange", "group", "set", "loop", "segment"))
# the readers whose records reach the claim path (right_rail_gate_ffs reads their results); every other reader module must be
# named in NOT_ON_CLAIM_PATH, and test_class_reader_findings fails when one of those is imported by another app module
ON_CLAIM_PATH = ("right_rail_x12", "right_rail_x12_834", "right_rail_x12_837", "right_rail_reader_leie", "right_rail_reader_lines", "right_rail_gate_ffs",
                 "right_rail_reader_provider_death")  # not imported by right_rail_gate_ffs: the replay opener reads it and hands the list to ffs.feeds as the provider-death feed
NOT_ON_CLAIM_PATH = ("right_rail_x12_820", "right_rail_x12_835", "right_rail_reader_death", "right_rail_reader_evv",
                     # the fact-record readers: whole-file layouts and their independent checkers, read only by their tests and
                     # vector generators; right_rail_gate_ffs imports none of them
                     "right_rail_reader_elig", "right_rail_reader_elig_independent", "right_rail_reader_fixed",
                     "right_rail_reader_fixed_independent", "right_rail_reader_state_death", "right_rail_reader_state_death_independent",
                     "right_rail_reader_provider_death_independent",
                     "right_rail_reader_state_exclusion", "right_rail_reader_state_exclusion_independent",
                     "right_rail_reader_federal_exclusion", "right_rail_reader_federal_exclusion_independent")


def _str(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _name(func: ast.AST) -> str:
    return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""


def _loop_values(tree: ast.AST, var: str) -> list[str]:
    """The literal first items of the tuples a ``for`` loop walks, where its target's first name is ``var``."""
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.For) and isinstance(node.target, ast.Tuple) and isinstance(node.target.elts[0], ast.Name) \
                and node.target.elts[0].id == var and isinstance(node.iter, ast.Tuple):
            out += [s for t in node.iter.elts if isinstance(t, ast.Tuple) and (s := _str(t.elts[0])) is not None]
    return out


def _fstring(node: ast.JoinedStr, tree: ast.AST) -> list[str]:
    names = [v.value.id for v in node.values if isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name)]
    if len(names) != 1:
        return []
    return ["".join(_str(p) if _str(p) is not None else v for p in node.values) for v in _loop_values(tree, names[0])]


def kinds_of(module: str) -> set[tuple[str, str]]:
    tree = ast.parse((APP / f"{module}.py").read_text("utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn, args = _name(node.func), node.args
            if fn in ("Quarantine", "bad"):
                if module in ("right_rail_reader_leie", "right_rail_reader_lines") and fn == "Quarantine":  # Quarantine(offset, field, cause)
                    cause = next((_str(k.value) for k in node.keywords if k.arg == "cause"), None) or (_str(args[2]) if len(args) > 2 else None)
                    if cause:
                        found.add(cause)
                elif len(args) > 1 and _str(args[0]) in UNITS and _str(args[1]):
                    found.add(_str(args[1]))
            elif fn == "Finding" and args:
                if _str(args[0]):
                    found.add(_str(args[0]))
                elif isinstance(args[0], ast.JoinedStr):
                    found.update(_fstring(args[0], tree))
            elif fn == "_Bad" and args and _str(args[0]):
                found.add(_str(args[0]))  # a spoiled field is filed under its column; the cause is what the reader names
            elif fn == "SetAside" and module == "right_rail_gate_ffs":
                found.update(s for a in args for n in ast.walk(a) if (s := _str(n)) and s.isidentifier() and s.islower())
        elif isinstance(node, ast.Tuple) and len(node.elts) >= 2 and _str(node.elts[0]) in UNITS and _str(node.elts[1]) and module != "right_rail_gate_ffs":
            found.add(_str(node.elts[1]))
        elif isinstance(node, ast.Assign) and module == "right_rail_x12" and any(isinstance(t, ast.Name) and t.id in ("cause", "bad") for t in node.targets):
            found.update(_str(n) for n in ast.walk(node.value) if _str(n))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and _str(node.left) == "not_" and module == "right_rail_x12":
            found.update(("not_834", "not_837"))  # ``"not_" + kind``: one for each reader on the claim path
        elif module == "right_rail_gate_ffs" and isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "cause" for t in node.targets):
            found.update(s for n in ast.walk(node.value) if isinstance(n, ast.IfExp) for b in (n.body, n.orelse) if (s := _str(b)))
    found.discard("")
    return {(module, k) for k in found if k.replace("_", "").isalnum()}


INDIRECT = ("cause", "cause(r)", "q.cause")  # built from strings elsewhere in the module (read as a ``cause`` assignment), or a cause the reader gave


def non_literal(module: str) -> list[str]:
    """The cause of each ``SetAside`` that is not a string or a conditional of strings, other than INDIRECT: such a cause is a kind this walker cannot see."""
    def leaves(node):
        yield from (x for b in (node.body, node.orelse) for x in leaves(b)) if isinstance(node, ast.IfExp) else [node]
    tree = ast.parse((APP / f"{module}.py").read_text("utf-8"))
    return [ast.unparse(x) for n in ast.walk(tree) if isinstance(n, ast.Call) and _name(n.func) == "SetAside" and len(n.args) > 1
            for x in leaves(n.args[1]) if _str(x) is None and ast.unparse(x) not in INDIRECT]


def all_kinds() -> set[tuple[str, str]]:
    return {k for m in ON_CLAIM_PATH for k in kinds_of(m)}


if __name__ == "__main__":
    for m, k in sorted(all_kinds()):
        print(m, k)
