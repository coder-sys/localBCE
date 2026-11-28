"""A second reader of the obligations records, written from conformance/OBLIGATIONS_V1.md alone.

It takes every layout from the specification's tables and every vector from its vectors block, applies each record's
rules as the specification words them, and shares no code with the implementation.  `python
conformance/obligations_v1_ref.py` reads every vector and prints one line per record, checks every `refuse` and
`accept` body, then computes each fold example's record from the section "The fold" and compares it with the vector.
"""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from typing import Callable

SPEC = Path(__file__).resolve().parent / "OBLIGATIONS_V1.md"
ROW = re.compile(r"^\| (\d+) \| (\d+) \| (num|blk|lit) \| (\w+) \| (\d*) \|$")
HEAD = re.compile(r"^### (\w+)(?: \(tag 0x([0-9A-F]{2})\))?$")
Table = list[tuple[int, int, str, str, "int | None"]]


def layouts(text: str) -> tuple[dict[str, Table], dict[str, int]]:
    """Every table of the specification by its heading, and every record's tag from its heading."""
    tables: dict[str, Table] = {}
    tags: dict[str, int] = {}
    name = None
    for line in text.splitlines():
        m = HEAD.match(line)
        if m:
            name = m.group(1)
            tables[name] = []
            if m.group(2):
                tags[name] = int(m.group(2), 16)
            continue
        if line.startswith("## "):
            name = None
        r = ROW.match(line)
        if r and name:
            o, w, kind, field, v = r.groups()
            tables[name].append((int(o), int(w), kind, field, int(v) if v else None))
    return tables, tags


def block_lines(text: str) -> list[str]:
    return text.split("## Vectors", 1)[1].split("```text\n", 1)[1].split("```", 1)[0].splitlines()


def vectors(text: str) -> list[tuple[str, bytes, list[tuple[str, str]]]]:
    """The valid bodies of the vectors block: each record's name, body and listed fields."""
    out: list[tuple[str, bytes, list[tuple[str, str]]]] = []
    for line in block_lines(text):
        word, _, rest = line.partition(" ")
        if word == "record":
            out.append((rest, b"", []))
        elif word == "hex":
            out[-1] = (out[-1][0], bytes.fromhex(rest), out[-1][2])
        elif word == "field":
            field, _, value = rest.partition(" ")
            out[-1][2].append((field, value))
    return out


def verdict_vectors(text: str) -> list[tuple[bool, str, str, bytes]]:
    """The `refuse` and `accept` lines: whether a reader accepts, the record, the field, the body."""
    out = []
    for line in block_lines(text):
        word, *rest = line.split(" ")
        if word in ("refuse", "accept"):
            out.append((word == "accept", rest[0], rest[1], bytes.fromhex(rest[2])))
    return out


class Refused(ValueError):
    """A body a reader refuses; `fields` names the fields of the broken rule (empty for the length)."""

    def __init__(self, why: str, fields: tuple[str, ...] = ()) -> None:
        super().__init__(why)
        self.fields = fields


def read(table: Table, body: bytes) -> list[tuple[str, str]]:
    """The number and block fields of a body, in layout order; a wrong length or literal is refused."""
    base = table[0][0]
    width = sum(w for _, w, _, _, _ in table)
    if len(body) != width:
        raise Refused(f"length {len(body)}, not {width}")
    out = []
    at = base
    for o, w, kind, field, v in table:
        if o != at:
            raise Refused(f"the table has a gap or an overlap at {field}")
        raw = body[o - base:o - base + w]
        at = o + w
        if kind == "blk":
            out.append((field, raw.hex()))
            continue
        n = int.from_bytes(raw, "little")
        if kind == "lit":
            if n != v:
                raise Refused(f"{field} at {o} holds {n}, not {v}", (field,))
        else:
            out.append((field, str(n)))
    return out


def values(table: Table, body: bytes) -> dict[str, int | bytes]:
    """The fields of a body that `read` accepts: numbers as integers, blocks as bytes."""
    base = table[0][0]
    return {field: body[o - base:o - base + w] if k == "blk" else int.from_bytes(body[o - base:o - base + w], "little")
            for o, w, k, field, _ in table if k != "lit"}


# The rules of "## Records", each as the specification words it: the fields it concerns and the test.
Rule = tuple[tuple[str, ...], Callable[[dict], bool]]


def display(x: bytes) -> bool:
    """A display field: an identifier (a length byte below the width, the text, zeros), or 0xFF and zeros from the
    field's offset 33 on."""
    n = x[0]
    if n < len(x) and not any(x[1 + n:]):
        return True
    return n == 0xFF and not any(x[33:])


def between(field: str, lo: int, hi: int) -> Rule:
    return (field,), lambda f: lo <= f[field] <= hi


def below(field: str, bound: int) -> Rule:
    return (field,), lambda f: f[field] < bound


def under_bound(field: str) -> Rule:
    """An amount or a time is below 2^63, the rules' bound."""
    return below(field, 2 ** 63)


def all_under_bound(*fields: str) -> list[Rule]:
    return [under_bound(f) for f in fields]


def is_display(field: str) -> Rule:
    return (field,), lambda f: display(f[field])


FACT: list[Rule] = [
    below("op", 3),
    (("op", "vstart", "vstop"), lambda f: f["op"] == 2 or f["vstart"] <= f["vstop"]),
    between("ecls", 0, 4),
]

RULES: dict[str, list[Rule]] = {
    "state": [between("mkind", 13, 25), below("flags", 16), between("verification", 1, 3),
              between("caseStatus", 1, 5), between("delivery", 1, 4), below("lg", 4),
              *all_under_bound("cents", "wbatch", "owed", "received", "claimed", "lawful", "shortfall", "overage",
                               "dueMs", "atMs")],
    "case": [between("op", 1, 4),
             (("op", "status"), lambda f: 1 <= f["status"] <= 5 if f["op"] <= 2 else f["status"] == 0),
             below("lg", 4), *all_under_bound("dueMs", "atMs")],
    "action": [between("op", 1, 4), between("akind", 1, 2), below("lg", 4),
               # the status is the operation's: CREATE and ATTEMPT 1, ACK 2, CANCEL 3 (op outside 1-4 is the op rule's)
               (("op", "status"), lambda f: f["op"] not in (1, 2, 3, 4) or f["status"] == {1: 1, 2: 2, 3: 3, 4: 1}[f["op"]]),
               (("decidedMs", "atMs"), lambda f: f["decidedMs"] <= f["atMs"]),
               (("ak",), lambda f: any(f["ak"])),  # an all-zero key names no request
               under_bound("amount"), under_bound("atMs")],
    "command": [between("ckind", 1, 12), between("attr", 0, 2), between("epoch", 1, 2 ** 63 - 1), below("lg", 4),
                *all_under_bound("atMs", "wbatch")],
    "marker": [(("cause",), lambda f: f["cause"] != 0), between("sidk", 0, 1),
               (("sidk", "sid"), lambda f: f["sidk"] != 0 or not any(f["sid"]))],
    "fold": [(("cmax", "cmaxMs", "cmaxCents"), lambda f: f["cmax"] != 0 or f["cmaxMs"] == f["cmaxCents"] == 0),
             (("done", "doneMs"), lambda f: f["done"] != 0 or f["doneMs"] == 0),
             (("amax", "amaxMs"), lambda f: f["amax"] != 0 or f["amaxMs"] == 0),
             under_bound("cmaxMs"), under_bound("cmaxCents"), under_bound("doneMs"), under_bound("reqsum"),
             under_bound("amaxMs")],
    "oblig": FACT + [is_display("item"), is_display("period"), *all_under_bound("owed", "dueMs")],
    "cash": [between("op", 0, 1), (("vstart", "vstop"), lambda f: f["vstart"] <= f["vstop"]), between("ecls", 0, 4),
             is_display("origin"), under_bound("amount"), under_bound("eventMs")],
    "claim": FACT + [is_display("claim"), *all_under_bound("amount", "deadlineMs", "eventMs")],
    "support": FACT + [is_display("ref"), *all_under_bound("applicableMs", "eventMs")],
    "report": FACT + [is_display("ref"), *all_under_bound("applicableMs", "eventMs")],
    "fund": FACT + [is_display("ref"), *all_under_bound("amount", "eventMs")],
    "ack": FACT + [is_display("ackref"), under_bound("eventMs")],
    "link": [],
}


def broken(f: dict, name: str) -> list[tuple[str, ...]]:
    """The fields of every rule of record `name` that the fields `f` break."""
    return [fields for fields, ok in RULES[name] if not ok(f)]


def check(tables: dict[str, Table], name: str, body: bytes) -> dict[str, int | bytes]:
    """The fields of a body its table and its rules accept; otherwise `Refused`, naming the first broken rule's
    fields."""
    read(tables[name], body)
    f = values(tables[name], body)
    for fields in broken(f, name):
        raise Refused(f"{name}: the rule on {', '.join(fields)} is broken", fields)
    return f


def verdict_ok(tables: dict[str, Table], want: bool, name: str, field: str, body: bytes) -> bool:
    """Whether a `refuse` or `accept` vector holds: a refused body breaks exactly the rule on its field, or, for the
    field `length` or a literal field, its table; an accepted body breaks nothing."""
    try:
        read(tables[name], body)
    except Refused as e:
        return not want and (field in e.fields or (field == "length" and not e.fields))
    rules = broken(values(tables[name], body), name)
    return rules == [] if want else len(rules) == 1 and field in rules[0]


def accepts(tables: dict[str, Table], name: str, body: bytes) -> bool:
    try:
        check(tables, name, body)
        return True
    except Refused:
        return False


def write(table: Table, vals: dict[str, int | bytes]) -> bytes:
    """A body from its number and block fields; literal fields hold their values."""
    out = b""
    for _, w, kind, field, v in table:
        x = v if kind == "lit" else vals[field]
        out += x if isinstance(x, bytes) else x.to_bytes(w, "little")
    return out


Input = tuple[int, bytes, list["bytes | None"]]


def fold_examples(text: str) -> list[tuple[str, list[bytes], list[Input], "bytes | None"]]:
    """The fold examples of the vectors block: each one's name, opening fields, input records and fold record (None
    when the total does not fit and there is no record)."""
    out: list = []
    for line in block_lines(text):
        word, *rest = line.split(" ")
        if word == "example":
            out.append((rest[0], [], [], b""))
        elif word == "opening":
            out[-1][1].append(bytes.fromhex(rest[1]))
        elif word == "input":
            ids = [None if x == "-" else bytes.fromhex(x) for x in rest[2:]]
            out[-1][2].append((int(rest[0]), bytes.fromhex(rest[1]), ids))
        elif word == "fold":
            out[-1] = (out[-1][0], out[-1][1], out[-1][2], None if rest[0] == "none" else bytes.fromhex(rest[0]))
    return out


def fold_of(text: str, opening: list[bytes], inputs: list[Input]) -> "bytes | None":
    """The fold record of the specification's section "The fold", from its words alone; None when there is none (a
    total at or above 2^63, an identifier of 65,536 bytes or more), never a wrapped or raised value."""
    if any(len(x) >= 65536 for x in [*opening, *(i for _, _, ids in inputs for i in ids if i is not None)]):
        return None
    tables, tags = layouts(text)
    kind_of = {t: n for n, t in tags.items()}

    def dom(name: str) -> bytes:
        return f"RR/GATE/{name}/v1".encode("ascii") + b"\0"

    def h(data: bytes) -> bytes:
        return hashlib.sha3_512(data).digest()

    def lp16(x: bytes) -> bytes:
        return len(x).to_bytes(2, "little") + x

    eacc, ecount, owed, latest = bytes(64), 0, 0, None
    asserted: set[bytes] = set()  # CASH statements that gave a payment or were voided: each is used once
    created: set[bytes] = set()  # action keys that have had a CREATE record, cancelled or not
    stated = False  # a readable state row has been read
    active: list[tuple[int, int, bytes, int, bytes, bytes]] = []  # time, amount, id, record, sid, pays
    requests: list[tuple[bytes, int]] = []
    for no, body, (evidence, contribution, action) in inputs:
        if evidence is not None:
            eacc, ecount = h(dom("EVIDACC") + eacc + lp16(evidence)), ecount + 1
        kind = kind_of.get(body[0]) if body else None
        if kind is None:
            continue
        try:
            f = check(tables, kind, body)
        except Refused:
            continue
        if kind == "state":
            owed, stated = f["owed"], True
        elif kind == "cash":
            if f["op"] == 1:
                active = [c for c in active if c[4] != f["sid"]]
                asserted.add(f["sid"])
            elif contribution is not None and f["sid"] not in asserted:
                asserted.add(f["sid"])
                active.append((f["eventMs"], f["amount"], contribution, no, f["sid"], f["pays"]))
        elif kind == "action" and f["op"] == 1 and f["ak"] not in created:
            created.add(f["ak"])
            if action is not None and (latest is None or (f["atMs"], action) >= latest[:2]):
                latest = (f["atMs"], action, no)
            if f["akind"] == 1 and contribution is not None:
                active.append((f["decidedMs"], f["amount"], contribution, no, b"", b""))
            elif f["akind"] == 2:
                requests.append((f["ak"], f["amount"]))
        elif kind == "action" and f["op"] == 3:
            requests = [r for r in requests if r[0] != f["ak"]]
    ordered = sorted(reversed(active), key=lambda c: (c[0], c[1], c[2]))  # equal keys: the later record first
    done, total = None, 0
    for c in ordered:
        total += c[1]
        if stated and total >= owed:
            done = c
            break
    if sum(c[1] for c in active) >= 2 ** 63:  # the rules add with a checked sum: no running sum is above this one
        return None
    last = ordered[-1] if ordered else None
    reqsum = sum(max(0, amount - sum(c[1] for c in active if c[5] == ak)) for ak, amount in requests)
    cref = h(dom("EVALFIX") + b"".join(lp16(x) for x in opening))
    fields = {
        "cref": cref, "eacc": eacc, "ecount": ecount, "ccount": len(active),
        "cmaxMs": last[0] if last else 0, "cmaxCents": last[1] if last else 0, "cmax": last[3] + 1 if last else 0,
        "doneMs": done[0] if done else 0, "done": done[3] + 1 if done else 0, "reqsum": reqsum,
        "amaxMs": latest[0] if latest else 0, "amax": latest[2] + 1 if latest else 0}
    widths = {field: w for _, w, kind, field, _ in tables["fold"] if kind != "lit"}
    if any(isinstance(v, int) and v >= 256 ** widths[k] for k, v in fields.items()):
        return None
    body = write(tables["fold"], fields)
    return body if accepts(tables, "fold", body) else None


def main() -> int:
    text = SPEC.read_text("utf-8")
    tables, tags = layouts(text)
    bad = 0
    for name, body, listed in vectors(text):
        got = read(tables[name], body)
        ok = got == listed and accepts(tables, name, body) and (name == "link" or body[0] == tags[name])
        bad += not ok
        print(f"{name} {'ok' if ok else 'DIFFERS'} fields={len(got)}")
    for want, name, field, body in verdict_vectors(text):
        ok = verdict_ok(tables, want, name, field, body)
        bad += not ok
        print(f"{'accept' if want else 'refuse'} {name} {field} {'ok' if ok else 'DIFFERS'}")
    for name, opening, inputs, fold in fold_examples(text):
        ok = fold_of(text, opening, inputs) == fold
        bad += not ok
        print(f"fold example {name} {'ok' if ok else 'DIFFERS'} inputs={len(inputs)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
