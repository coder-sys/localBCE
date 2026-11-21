"""Stage S0 of step 2's request side: the host's FRAME/v3 request builder (docs/integration/TRUNK_STEP2_FRAME_DESIGN.md
sections 2.1-2.5 and 5.1-5.2; conformance/ENGINE_V3.md sections 17 and 19).  Nothing in production calls the v3 path
yet: the built gate_engine speaks request version 1, so the v1 path must stay byte for byte as it was (``V1_DIGEST``).
Signer-free, no engine runs.  Synthetic, non-PHI."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import re
import unittest
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decide

# Every top-level name the S0 draft added, functions and constants alike.
V3_NAMES = {decide: ("REQUEST_VERSION_V3", "ELIG_KIND_V3", "SOC_KIND_V3", "FEED_KINDS", "PIN_WIDTHS", "_MEMBER_V3",
                     "_SNAPSHOT", "_nat", "feed_pin", "feed_v3", "_ABSENT", "request_frame_v3", "_check_feed_v3",
                     "_body_v3", "_requests_v3"),
            gate: ("FRAME_V3", "CONTEXT_V2", "DESC_AT_V3", "_SECTION19_V3", "ELIG_SLOT_V3", "SOC_SLOT_V3", "ELIG_ROW_V3",
                   "SOC_ROW_V3", "FEED_WIDTHS_V3", "ROWS_AT_V3", "PAY_WIDTH", "_Walk", "_walk_ctx", "frame_parts", "frame_walk",
                   "walk_prime", "body_prime", "frame_digest")}


def v3_uses(source: str) -> list[int]:
    """The lines of ``source`` that reference a v3 name (as a name or an attribute) outside a v3 definition: a top-level
    function or class named in ``V3_NAMES``, or a top-level assignment whose targets are all v3 names."""
    v3 = set().union(*V3_NAMES.values())
    found = []
    for top in ast.parse(source).body:
        if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            owners = {top.name}
        elif isinstance(top, (ast.Assign, ast.AnnAssign)):
            targets = top.targets if isinstance(top, ast.Assign) else [top.target]
            owners = {t.id if isinstance(t, ast.Name) else "" for t in targets}
        else:
            owners = set()
        if owners and owners <= v3:
            continue
        found += [n.lineno for n in ast.walk(top) if isinstance(n, ast.Name) and n.id in v3
                  or isinstance(n, ast.Attribute) and n.attr in v3]
    return found

ROOT = Path(__file__).resolve().parents[1]
RULES_SPEC = ROOT / "lean" / "BlindLedger" / "Gate" / "Rules" / "Spec.lean"
DESIGN = ROOT.parent / "docs" / "integration" / "TRUNK_STEP2_FRAME_DESIGN.md"
ENGINE_V3 = ROOT / "conformance" / "ENGINE_V3.md"
M = 1 << 256  # an n33 member's 0x01 top byte
MISSING = (b"\x02" + bytes(76), b"")
ABSENT = (bytes(77), b"")
LEAN_TYPE = {"dmf": "Death", "pdeath": "Death", "excl": "Exclusion", "span": "Span", "elig": "Elig", "soc": "Soc"}
FEED_NAME = {"DMF": "dmf", "Provider death": "pdeath", "Exclusion": "excl", "Enrollment span": "span",
             "Eligibility": "elig", "Share of cost": "soc"}

# SHA3-256 of ``v1_outputs()``, computed from the unmodified code at HEAD 2205b5cb before the S0 edits.
V1_DIGEST = "5ceb668faf4a5e12cd578cab1a660b64f2392512657e666b9dba053265b47a96"


def _le(n: int, w: int) -> bytes:
    return n.to_bytes(w, "little")


def v1_outputs() -> str:
    """Every v1 request-path output for fixed synthetic inputs: ``feed`` (present, misfit, small and n33 members),
    ``request_frame`` (batch 1 with redo, bypasses and requests; batch 2 empty; absent feeds), ``_requests`` of each
    frame and one ``payment_input``."""
    read = (decide.feed("dmf", 20261101, [(M + 5, 20260101), (M + 3, 20250101), (9001, 20270110)]),
            decide.feed("pdeath", 20261001, [(7, 20250101), (256**21, 1)]),
            decide.feed("excl", 20261002, [(9, 20250101, 99991231), (8, 20240101, 20241231)]),
            decide.feed("span", 20261101, [(M + 1, 11, 20250101, 20261231), (1001, 501, 20250101, 20261231)]))
    out = [d + r for d, r in read]
    keys = decide.Keys(b"keyset", ((4, b"step"), (5, b"step-two")))
    for feeds, batch, redo, bodies, byps in (((20261120, read), 1, (5, 2**200), [b"req-one", b"req-two"], [b"b1", b"bypass-2"]),
                                             ((20261121, read), 2, (), [], []),
                                             ((0, (ABSENT,) * 4), 1, (), [b"x"], [])):
        frame = decide.request_frame(feeds, 3, batch, 20261101, bytes(range(64)), b"\x11" * 64, (7, 2), keys, b"grant",
                                     bytes(64), byps, bodies, redo)
        context, sent, grant, bypasses = decide._requests(frame)
        out += [frame, context, *sent, grant, *bypasses]
    out.append(gate.payment_input(b"\x22" * 64, b"head", [b"l1", b"l2"], b"tail"))
    return hashlib.sha3_256(b"".join(_le(len(x), 4) + x for x in out)).hexdigest()


def _frame(read, bodies=(b"req-one", b"req-two"), byps=(b"b1",), redo=(5,), batch=1) -> bytes:
    return decide.request_frame_v3((20261120, read), 3, batch, 20261101, bytes(range(64)), b"\x11" * 64, (7, 2),
                                   decide.Keys(b"keyset", ((4, b"step"),)), b"grant", bytes(64), list(byps), list(bodies), redo)


def _six() -> tuple:
    return (decide.feed_v3("dmf", 20261101, [(M + 5, 20260101), (M + 3, 20250101)]),
            decide.feed_v3("pdeath", 20261001, [(7, 20250101)]),
            decide.feed_v3("excl", 20261002, [(9, 20250101, 99991231)]),
            decide.feed_v3("span", 20261101, [(M + 1, 11, 20250101, 20261231)]),
            decide.feed_v3("elig", 20261101, [(M + 2, 12, 1, 20250101, 20261231), (M + 1, 12, 0, 20250101, 20251231)]),
            decide.feed_v3("soc", 20261101, [(M + 1, 202611, 12_345, 1)]))


def _pin(kind: int, asof: int, rows, widths) -> bytes:
    """SNAPSHOT/v1 ``pinInput`` written out from Rules/Spec.lean: big-endian fields, rows in ascending byte order."""
    head = b"".join(v.to_bytes(4, "big") for v in (kind, asof, len(rows)))
    canon = sorted(b"".join(v.to_bytes(w, "big") for v, w in zip(r, widths)) for r in rows)
    return hashlib.sha3_512(b"RR/GATE/SNAPSHOT/v1\x00" + head + b"".join(canon)).digest()


class V1PathTests(unittest.TestCase):
    def test_the_v1_path_is_byte_identical_to_head(self) -> None:
        self.assertEqual(v1_outputs(), V1_DIGEST)
        self.assertEqual(decide.FEED_WIDTHS, {"dmf": (33, 4), "pdeath": (21, 4), "excl": (21, 4, 4), "span": (33, 21, 4, 4)})
        self.assertEqual(gate.CONTEXT, b"RR/GATE/CONTEXT/v1\x00")

    def test_nothing_in_production_calls_the_v3_path(self) -> None:
        # Every module under app/ (recursively), decide and codec included: a v3 name may be referenced only inside the
        # top-level definition of another v3 name (a v3 function's body, or the assignment of a v3 constant).
        for module, names in V3_NAMES.items():
            for name in names:
                self.assertTrue(hasattr(module, name), (module.__name__, name))  # the list follows renames
        paths = sorted((ROOT / "app").rglob("*.py"))
        self.assertIn(ROOT / "app" / "right_rail_gate_decide.py", paths)
        self.assertIn(ROOT / "app" / "right_rail_gate_codec.py", paths)
        self.assertTrue(any(p.parent != ROOT / "app" for p in paths))  # subpackages are scanned too
        for path in paths:
            self.assertEqual(v3_uses(path.read_text("utf-8")), [], path.relative_to(ROOT).as_posix())

    def test_the_guard_catches_a_production_call(self) -> None:
        # The guard above must fail on a decide() (or any v1 name) that switched to the v3 path.
        for src in ("def decide(x):\n    return request_frame_v3(x)\n", "def decide(f):\n    return _requests_v3(f)\n",
                    "def _requests(f):\n    return gate.frame_digest(f)\n", "def feed(k):\n    return feed_pin(k, 1, [])\n",
                    "X = gate.FEED_WIDTHS_V3\n", "def decide(b):\n    return _body_v3(b)\n",
                    "def request_frame(x):\n    return REQUEST_VERSION_V3\n"):
            self.assertNotEqual(v3_uses(src), [], src)
        self.assertEqual(v3_uses("def request_frame_v3(x):\n    return _body_v3(x) + gate.frame_digest(x)\n"), [])


class ConstantsTests(unittest.TestCase):
    def test_feed_kinds_and_pin_widths_are_the_lean_fields(self) -> None:
        spec = RULES_SPEC.read_text("utf-8")
        id_width = int(re.search(r"def idWidth : Nat := (\d+)", spec).group(1))
        fields = {}
        for name, items in re.findall(r"def (\w+)\.fields \(\w+ : \w+\) : List \(Nat × Nat\) :=\s*\[(.*?)\]\n", spec, re.S):
            fields[name] = tuple(id_width if w == "idWidth" else int(w) for w in re.findall(r"\((idWidth|\d+), \w+\.\w+\)", items))
        self.assertEqual(decide.PIN_WIDTHS, {k: fields[t] for k, t in LEAN_TYPE.items()})
        comment = " ".join(spec.split("the kind (", 1)[1].split(")", 1)[0].split())
        kinds = dict((n, int(k)) for k, n in re.findall(r"(\d) ([a-zA-Z ]+?)(?:,|$)", comment))
        lean = {"dmf": kinds["DMF"], "pdeath": kinds["provider deaths"], "excl": kinds["exclusions"],
                "span": kinds["enrollment"], "elig": kinds["eligibility"], "soc": kinds["share of cost"]}
        self.assertEqual(decide.FEED_KINDS, lean)
        self.assertEqual(decide.FEED_KINDS, {"dmf": 1, "pdeath": 2, "excl": 3, "span": 4, "elig": 7, "soc": 8})
        self.assertNotIn(5, decide.FEED_KINDS.values())  # RELEASED
        self.assertNotIn(6, decide.FEED_KINDS.values())  # UNRESOLVED
        self.assertEqual(list(decide.PIN_WIDTHS), list(gate.FEED_WIDTHS_V3))
        self.assertEqual(list(decide.FEED_KINDS), list(gate.FEED_WIDTHS_V3))

    def test_the_v3_constants_agree_with_one_another(self) -> None:
        # The draft's import-time asserts, moved here so a v1 caller's import never depends on the v3 constants.
        kinds = list(gate.FEED_WIDTHS_V3)
        self.assertEqual(list(decide.FEED_KINDS), kinds)
        self.assertEqual(list(decide.PIN_WIDTHS), kinds)
        for kind, widths in gate.FEED_WIDTHS_V3.items():
            self.assertEqual(len(decide.PIN_WIDTHS[kind]), len(widths), kind)
        slots = sorted([*gate._SECTION19_V3, gate.ELIG_SLOT_V3, gate.SOC_SLOT_V3])
        self.assertEqual(slots, list(range(1, len(kinds) + 1)))  # contiguous, no slot twice
        self.assertEqual(kinds.index("elig") + 1, gate.ELIG_SLOT_V3)
        self.assertEqual(kinds.index("soc") + 1, gate.SOC_SLOT_V3)
        self.assertEqual((gate.FEED_WIDTHS_V3["elig"], gate.FEED_WIDTHS_V3["soc"]), (gate.ELIG_ROW_V3, gate.SOC_ROW_V3))
        self.assertEqual(gate.ROWS_AT_V3, gate.DESC_AT_V3 + 77 * len(kinds))
        self.assertEqual((decide.FEED_KINDS["elig"], decide.FEED_KINDS["soc"]), (decide.ELIG_KIND_V3, decide.SOC_KIND_V3))
        self.assertEqual(decide._MEMBER_V3, {k for k, w in gate.FEED_WIDTHS_V3.items() if w[0] == 32})
        # Design decision 7: one version constant for request and answer.
        self.assertEqual(decide.REQUEST_VERSION_V3, decide.ANSWER_VERSION)
        spec = RULES_SPEC.read_text("utf-8")
        self.assertEqual(gate.PAY_WIDTH, int(re.search(r"def payWidth : Nat := (\d+)", spec).group(1)))

    def test_the_constants_match_the_design(self) -> None:
        design = DESIGN.read_text("utf-8")
        table = re.findall(r"^\| ([A-Za-z ]+) \| (\d) \| (.+?) \| (\d+) \|$", design.split("### 2.3", 1)[1].split("### 2.4", 1)[0], re.M)
        self.assertEqual([FEED_NAME[n] for n, *_ in table], list(gate.FEED_WIDTHS_V3))
        for name, kind, row, size in table:
            widths = tuple(int(n) // 8 if u else int(n) for u, n in re.findall(r"\w+ (u?)(\d+)", row))
            self.assertEqual(gate.FEED_WIDTHS_V3[FEED_NAME[name]], widths, name)
            self.assertEqual(sum(widths), int(size), name)
            self.assertEqual(decide.FEED_KINDS[FEED_NAME[name]], int(kind), name)
        offsets = design.split("### 2.2", 1)[1].split("### 2.3", 1)[0]
        slots = re.findall(r"\| \**(\d+)\** \| \**descriptor (\d), [^(]+\(kind (\d)\)", offsets)
        self.assertEqual([int(s) for _, s, _ in slots], list(range(1, len(gate.FEED_WIDTHS_V3) + 1)))
        for at, slot, kind in slots:
            self.assertEqual(76 + 77 * (int(slot) - 1), int(at))
            self.assertEqual(decide.FEED_KINDS[list(gate.FEED_WIDTHS_V3)[int(slot) - 1]], int(kind))
        self.assertIn(f"| **{gate.ROWS_AT_V3}** | feed rows, in feed order |", offsets)
        self.assertEqual(gate.ROWS_AT_V3, 538)
        self.assertIn(f"version u16 LE = **{decide.REQUEST_VERSION_V3}**", design)
        domains = design.split("### 2.8", 1)[1].split("## 3.", 1)[0]
        self.assertIn("`RR/GATE/FRAME/v3\\0`", domains)
        self.assertIn("`RR/GATE/CONTEXT/v2\\0`", domains)
        self.assertEqual((gate.FRAME_V3, gate.CONTEXT_V2), (b"RR/GATE/FRAME/v3\x00", b"RR/GATE/CONTEXT/v2\x00"))
        # ENGINE_V3 section 19's four rows are the first four.
        v19 = ENGINE_V3.read_text("utf-8").split("## 19.", 1)[1].split("## 20.", 1)[0]
        sizes = [int(n) for n in re.findall(r"^\| [^|]+ \| `[^`]+`[^|]* \| (\d+) \|$", v19, re.M)]
        self.assertEqual(sizes, [sum(w) for w in list(gate.FEED_WIDTHS_V3.values())[:4]])


class FeedTests(unittest.TestCase):
    def test_rows_are_sent_sorted_numerically(self) -> None:
        rows = [(9, 2), (256, 1), (7, 5), (1, 9), (7, 1)]
        desc, body = decide.feed_v3("pdeath", 20261001, rows)
        want = sorted(rows)
        self.assertEqual(body, b"".join(_le(i, 21) + _le(d, 4) for i, d in want))
        self.assertLess(body.index(_le(1, 21)), body.index(_le(256, 21)))  # by number, not by little-endian bytes
        self.assertEqual(decide.feed_v3("pdeath", 20261001, want), (desc, body))
        self.assertEqual(desc[:13], b"\x01" + _le(20261001, 4) + _le(5, 4) + _le(5, 4))
        span = [(M + 2, 1, 20250101, 20251231), (M + 1, 9, 20250101, 20251231), (M + 1, 3, 20260101, 20261231)]
        _, sent = decide.feed_v3("span", 20261101, span)
        self.assertEqual(sent, b"".join(_le(m - M, 32) + _le(p, 21) + _le(a, 4) + _le(b, 4) for m, p, a, b in sorted(span)))

    def test_pins_use_the_lean_field_widths(self) -> None:
        cases = {"dmf": [(M + 5, 20260101), (M + 3, 20250101)], "pdeath": [(7, 20250101)], "excl": [(9, 20250101, 99991231)],
                 "span": [(M + 1, 11, 20250101, 20261231)], "elig": [(M + 2, 12, 1, 20250101, 20261231)],
                 "soc": [(M + 1, 202611, 2**64 - 1, 1), (M + 1, 202610, 0, 0)]}
        widths = {"dmf": (129, 4), "pdeath": (129, 4), "excl": (129, 4, 4), "span": (129, 129, 4, 4),
                  "elig": (129, 129, 1, 4, 4), "soc": (129, 4, 8, 1)}
        kinds = {"dmf": 1, "pdeath": 2, "excl": 3, "span": 4, "elig": 7, "soc": 8}
        for kind, rows in cases.items():
            with self.subTest(kind):
                pin = _pin(kinds[kind], 20261101, rows, widths[kind])
                self.assertEqual(decide.feed_pin(kind, 20261101, rows), pin)
                self.assertEqual(decide.feed_v3(kind, 20261101, rows[::-1])[0][13:], pin)
                if kind in decide.FEED_WIDTHS:  # the pin format is unchanged: the v1 feed pins the same rows the same way
                    self.assertEqual(decide.feed(kind, 20261101, rows)[0][13:], pin)
        # v1's ``129 if w > 4 else 4`` would pin cents at 129 and met at 4; the Lean fields say 8 and 1.
        self.assertNotEqual(decide.feed_pin("soc", 1, cases["soc"]), _pin(8, 1, cases["soc"], (129, 4, 129, 4)))

    def test_a_row_that_does_not_fit_sends_the_feed_missing(self) -> None:
        bad = {"member without the top byte": ("dmf", [(M + 1, 1), (5, 1)]),
               "member at 2**257": ("dmf", [(2 * M, 1)]),
               "member below 2**256 in span": ("span", [(M - 1, 1, 1, 1)]),
               "member in elig": ("elig", [(7, 1, 1, 1, 1)]),
               "member in soc": ("soc", [(0, 1, 1, 1)]),
               "id of 256**21": ("pdeath", [(256**21, 1)]),
               "aid of 256**21": ("elig", [(M, 256**21, 1, 1, 1)]),
               "plan of 256**21": ("span", [(M, 256**21, 1, 1)]),
               "level of 256": ("elig", [(M, 1, 256, 1, 1)]),
               "met of 256": ("soc", [(M, 1, 1, 256)]),
               "cents of 2**64": ("soc", [(M, 1, 2**64, 1)]),
               "date of 2**32": ("excl", [(1, 2**32, 1)]),
               "negative": ("excl", [(1, -1, 1)]),
               "short row": ("excl", [(1, 1)]),
               "long row": ("pdeath", [(1, 1, 1)]),
               "not a number": ("pdeath", [(1, "1")]),
               "a bool": ("pdeath", [(1, True)]),
               "asof of 2**32": ("pdeath", [(1, 1)], 2**32)}
        for name, (kind, rows, *asof) in bad.items():
            with self.subTest(name):
                self.assertEqual(decide.feed_v3(kind, *(asof or [20261101]), rows), MISSING)
        self.assertEqual(decide.feed_v3("dmf", 20261101, [(M, 1), (2 * M - 1, 1)])[1], _le(0, 32) + _le(1, 4) + _le(M - 1, 32) + _le(1, 4))
        self.assertEqual(decide.feed_v3("soc", 1, [])[0][:13], b"\x01" + _le(1, 4) + bytes(8))  # no rows: present and empty

    def test_an_unknown_kind_is_feed_kind(self) -> None:
        for kind in ("bogus", "DMF", "", 1, None):
            for call in (decide.feed_v3, decide.feed_pin):
                with self.subTest((call.__name__, kind)), self.assertRaises(decide.GateDecideError) as caught:
                    call(kind, 20261101, [(1, 1)])
                self.assertEqual(str(caught.exception), "feed_kind")


class FrameTests(unittest.TestCase):
    def test_four_feeds_are_padded_six_are_sent_others_refused(self) -> None:
        six = _six()
        four = _frame(six[:4])
        self.assertEqual(four, _frame(six[:4] + (ABSENT, ABSENT)))
        frame = _frame(six)
        self.assertEqual(frame[:4] + frame[4:6], b"RRDQ" + _le(3, 2))
        self.assertEqual(frame[6:18], _le(3, 4) + _le(1, 8))
        self.assertEqual(frame[18:82], gate.frame_digest(frame[82:]))
        body = frame[82:]
        for slot, (d, _) in enumerate(six):
            self.assertEqual(body[76 + 77 * slot:76 + 77 * (slot + 1)], d)
        self.assertEqual(body[gate.ROWS_AT_V3:gate.ROWS_AT_V3 + sum(len(r) for _, r in six)], b"".join(r for _, r in six))
        self.assertEqual(four[82 + 384:82 + 538], ABSENT[0] * 2)
        for n in (0, 3, 5, 7):
            with self.subTest(n), self.assertRaises(decide.GateDecideError) as caught:
                _frame((six * 2)[:n])
            self.assertEqual(str(caught.exception), "feed_count")

    def test_feeds_the_v3_frame_cannot_carry_are_refused(self) -> None:
        six = _six()
        unsorted = decide.feed("pdeath", 20261001, [(9, 20250101), (7, 20250101)])  # v1 feed: rows in the caller's order
        self.assertEqual(unsorted[0][:13], decide.feed_v3("pdeath", 20261001, [(9, 20250101), (7, 20250101)])[0][:13])
        bad = {"v1 pdeath, unsorted": (1, unsorted),
               "v1 excl, unsorted": (2, decide.feed("excl", 20261002, [(9, 2, 3), (9, 1, 3)])),
               "v1 dmf, 33-byte members": (0, decide.feed("dmf", 20261101, [(M + 5, 20260101)])),
               "v1 span, 33-byte members": (3, decide.feed("span", 20261101, [(M + 1, 11, 20250101, 20261231)])),
               "short descriptor": (0, (six[0][0][:76], six[0][1])),
               "long descriptor": (0, (six[0][0] + b"\0", six[0][1])),
               "a row short": (4, (six[4][0], six[4][1][:-1])),
               "a row extra": (5, (six[5][0], six[5][1] * 2)),
               "elig unsorted": (4, (six[4][0], six[4][1][62:] + six[4][1][:62])),
               "state 3": (1, (b"\x03" + bytes(76), b"")),
               "state 2 with rows": (1, (MISSING[0], six[1][1])),
               "state 0 with a pin": (1, (b"\x00" + six[1][0][1:], b"")),
               "state 2 with an asOf": (1, (b"\x02" + _le(1, 4) + bytes(72), b"")),
               "not a pair": (1, (six[1][0],)),
               "rows not bytes": (1, (six[1][0], bytearray(six[1][1])))}
        for name, (slot, item) in bad.items():
            with self.subTest(name), self.assertRaises(decide.GateDecideError) as caught:
                _frame(six[:slot] + (item,) + six[slot + 1:])
            self.assertEqual(str(caught.exception), "feed_malformed")
        with self.assertRaises(decide.GateDecideError) as caught:  # the four-feed path checks too
            _frame((six[0], unsorted, six[2], six[3]))
        self.assertEqual(str(caught.exception), "feed_malformed")
        # What the v3 frame can carry: v1 output whose bytes are already the v3 bytes (sorted pdeath/excl, empty feeds),
        # missing, absent, equal rows.
        ok = (decide.feed("dmf", 20261101, []), decide.feed("pdeath", 20261001, [(7, 1), (9, 1)]), MISSING, ABSENT,
              decide.feed_v3("elig", 1, [(M + 1, 1, 1, 1, 1)] * 2), ABSENT)
        self.assertEqual(ok[1], decide.feed_v3("pdeath", 20261001, [(9, 1), (7, 1)]))
        self.assertEqual(_frame(ok)[18:82], gate.frame_digest(_frame(ok)[82:]))

    def test_a_body_that_does_not_walk_is_feed_malformed(self) -> None:
        with mock.patch.object(gate, "frame_digest", side_effect=gate.GateCodecError("frame_walk")), \
                self.assertRaises(decide.GateDecideError) as caught:
            _frame(_six())
        self.assertEqual(str(caught.exception), "feed_malformed")

    def test_requests_are_read_back_under_context_v2(self) -> None:
        frame = _frame(_six(), bodies=(b"req-one", b"req-two"), byps=(b"b1", b"bypass-2"))
        c, sent = gate.frame_walk(frame[82:])
        context, bodies, grant, byps = decide._requests_v3(frame)
        self.assertEqual((bodies, grant, byps), ([b"req-one", b"req-two"], b"grant", [b"b1", b"bypass-2"]))
        self.assertEqual(sent, bodies)
        self.assertEqual(context, hashlib.sha3_512(b"RR/GATE/CONTEXT/v2\x00" + frame[82:82 + c]).digest())
        self.assertEqual(frame[82 + c:82 + c + 4], _le(2, 4))
        for bad in (frame + b"\0", frame[:-1], frame[:4] + _le(1, 2) + frame[6:]):
            with self.subTest(len(bad)), self.assertRaises(decide.GateDecideError):
                decide._requests_v3(bad)


class DigestTests(unittest.TestCase):
    def test_the_digest_is_the_section_17_formula(self) -> None:
        for bodies in ((), (b"req-one",), (b"req-one", b"", b"x" * 300)):
            with self.subTest(len(bodies)):
                body = _frame(_six(), bodies=bodies)[82:]
                c, sent = gate.frame_walk(body)
                self.assertEqual(sent, list(bodies))
                prime = body[:c + 4] + b"".join(_le(len(x), 4) for x in bodies)
                self.assertEqual(gate.body_prime(body), (prime, list(bodies)))
                want = hashlib.sha3_512(b"RR/GATE/FRAME/v3\x00" + prime + b"".join(hashlib.sha3_512(x).digest() for x in bodies))
                self.assertEqual(gate.frame_digest(body), want.digest())
                self.assertEqual(gate.frame_digest(body), gate.frame_digest(bytes(body)))  # deterministic
                self.assertNotEqual(gate.frame_digest(body), hashlib.sha3_512(b"RR/GATE/FRAME/v1\x00" + body).digest())
                # walkPrime: body' parses to its own length, also with bytes after it (prefix-free), and not when cut.
                self.assertEqual(gate.walk_prime(prime), len(prime))
                self.assertEqual(gate.walk_prime(prime + b"tail"), len(prime))
                self.assertIsNone(gate.walk_prime(prime[:-1]))

    def test_changing_any_body_byte_changes_the_digest(self) -> None:
        six = _six()
        body = _frame(six, bodies=(b"req-one", b"q2"), byps=(b"b1",), redo=(5,))[82:]
        digest = gate.frame_digest(body)
        c, _ = gate.frame_walk(body)
        rows = sum(len(r) for _, r in six)
        # Bytes no walk reads, so every flip there must be compared: prev; each descriptor but its rows u32; the rows and
        # the redone payment; the key-set pin; the two request bodies (after nq and each length).
        must = {*range(8, 72), *(at for s in range(6) for at in range(76 + 77 * s, 76 + 77 * (s + 1)) if not 9 <= at - 76 - 77 * s < 13),
                *range(gate.ROWS_AT_V3, gate.ROWS_AT_V3 + rows + gate.PAY_WIDTH + 64),
                *range(c + 8, c + 8 + 7), *range(c + 8 + 7 + 4, c + 8 + 7 + 4 + 2)}
        self.assertEqual(body[c + 8:c + 15] + body[c + 19:c + 21], b"req-oneq2")
        compared, refused = set(), 0
        for at in range(len(body)):
            for flip in (0x01, 0x80):
                changed = body[:at] + bytes([body[at] ^ flip]) + body[at + 1:]
                try:
                    other = gate.frame_digest(changed)
                except gate.GateCodecError:
                    refused += 1  # a length that no longer walks: refused LENGTH before any digest
                    continue
                self.assertNotEqual(other, digest, (at, flip))
                compared.add(at)
        self.assertLessEqual(must, compared)
        self.assertGreater(refused, 0)  # the length bytes are walked
        self.assertGreater(len(compared), len(body) * 9 // 10)

    def test_a_body_that_does_not_walk_is_refused(self) -> None:
        body = _frame(_six())[82:]
        for name, bad in (("trailing byte", body + b"\0"), ("cut", body[:-1]), ("empty", b""), ("header only", body[:76]),
                          ("a row count too large", body[:76 + 9] + _le(2**32 - 1, 4) + body[76 + 13:])):
            with self.subTest(name), self.assertRaises(gate.GateCodecError) as caught:
                gate.frame_digest(bad)
            self.assertEqual(str(caught.exception), "frame_walk")


if __name__ == "__main__":
    unittest.main()
