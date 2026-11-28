"""The obligations record format (design one-store §16.3, §16.11, §16.12).

Runs the format package's programs, built by `lake build -d tools/obligations_format`; a missing program fails.

* The constants file `app/right_rail_obligations_constants.json` is the output of `obligations_constants`.
* `conformance/OBLIGATIONS_V1.md`: its tables equal the constants file, its vectors block is the output of
  `obligations_format_check vectors`, and the second reader `conformance/obligations_v1_ref.py`, which shares no code
  with the implementation, reads every vector to the fields it lists, refuses each `refuse` body for the one rule it
  names, accepts each `accept` body, and computes every fold example's record.
* Verdicts: for every record kind, `obligations_format_check verdicts SEED 2000` with a fresh seed gives bodies with
  fields set near the rules' bounds; the second reader gives the same verdict on each.
* Fuzzing: `obligations_format_check fuzz SEED 1000000` with a fresh seed, printed; every codec and the link, every
  length from 0 to twice the record's, every single-bit flip and 1,000,000 random and mutated inputs; no difference.
* Import test: the module table of §16.11 against the actual imports of every file of its rows.
* Constants test: outside the format module and the conformance text, no Lean or Python file of the table's modules
  holds 256, 276, 245, 208, a record tag (in hex, or in decimal on a line that says "tag") or a digest domain of the
  fold record, except the lines listed in `ALLOWED`.
"""
from __future__ import annotations

import importlib.util
import json
import random
import re
import secrets
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEAN = ROOT / "lean" / "BlindLedger"
BIN = ROOT / "tools" / "obligations_format" / ".lake" / "build" / "bin"
CONSTANTS = ROOT / "app" / "right_rail_obligations_constants.json"
SPEC = ROOT / "conformance" / "OBLIGATIONS_V1.md"
FUZZ_N = 1_000_000
VERDICTS_N = 2_000
EXAMPLES = ["main", "void", "refused", "cancel", "floor", "reqvoid", "dupsid", "reassert", "big", "overflow",
            "voidfirst", "createrepeat", "recreate", "zeroak", "nostate", "sumover"]
NO_FOLD = ("overflow", "sumover")  # the examples whose total does not fit: `fold none`
FOLD_CASES = 300


def run(program: str, *args: str, timeout: int = 60) -> str:
    exe = BIN / f"{program}.exe"
    if not exe.is_file():
        raise AssertionError(f"{exe} is not built: lake build -d tools/obligations_format")
    done = subprocess.run([str(exe), *args], capture_output=True, text=True, encoding="utf-8", timeout=timeout)
    if done.returncode != 0:
        raise AssertionError(f"{program} {' '.join(args)} exited {done.returncode}\n{done.stdout[-3000:]}{done.stderr[-2000:]}")
    return done.stdout


def ref_reader():
    spec = importlib.util.spec_from_file_location("obligations_v1_ref", ROOT / "conformance" / "obligations_v1_ref.py")
    mod = importlib.util.module_from_spec(spec)
    keep, sys.dont_write_bytecode = sys.dont_write_bytecode, True  # a cache file would be an unpinned file in conformance/
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = keep
    return mod


class FormatTests(unittest.TestCase):
    def test_constants_file_is_the_programs_output(self) -> None:
        self.assertEqual(run("obligations_constants"), CONSTANTS.read_text("utf-8"),
                         "regenerate app/right_rail_obligations_constants.json from obligations_constants")

    def test_spec_tables_match_the_constants(self) -> None:
        ref = ref_reader()
        tables, tags = ref.layouts(SPEC.read_text("utf-8"))
        data = json.loads(CONSTANTS.read_text("utf-8"))

        def rows(fields):
            return [(f["offset"], f["width"], f["kind"], f["name"], f.get("value")) for f in fields]

        self.assertEqual(tables["link"], rows(data["link"]))
        self.assertEqual(sorted(tags), sorted(r["name"] for r in data["records"]))
        for r in data["records"]:
            self.assertEqual(tables[r["name"]], rows(r["fields"]), r["name"])
            self.assertEqual(tags[r["name"]], r["tag"], r["name"])
            self.assertEqual(sum(f["width"] for f in r["fields"]), data["body_bytes"], r["name"])
            names = [f["name"] for f in r["fields"] if f["kind"] != "lit"]
            self.assertEqual(len(names), len(set(names)), f"{r['name']}: a cell name is used twice")
        self.assertEqual(data["body_bytes"] + sum(f["width"] for f in data["link"]), data["record_bytes"])

    def test_domains_are_the_specs(self) -> None:
        # The notation of "The fold": dom(name) is RR/GATE/<name>/v1.
        self.assertEqual(json.loads(CONSTANTS.read_text("utf-8"))["domains"],
                         {name: f"RR/GATE/{name}/v1" for name in ("EVALFIX", "EVIDACC")})

    def test_spec_vectors_are_the_programs_and_the_second_reader_reads_them(self) -> None:
        text = SPEC.read_text("utf-8")
        block = text.split("## Vectors", 1)[1].split("```text\n", 1)[1].split("```", 1)[0]
        self.assertEqual(block, run("obligations_format_check", "vectors"))
        ref = ref_reader()
        tables, tags = ref.layouts(text)
        vecs = ref.vectors(text)
        self.assertEqual([v[0] for v in vecs], list(tags) + ["link"])
        for name, body, listed in vecs:
            self.assertEqual(ref.read(tables[name], body), listed, name)
            self.assertTrue(ref.accepts(tables, name, body), name)
            if name != "link":
                self.assertEqual(body[0], tags[name], name)
            # one changed byte of any literal field, or one byte too many or too few, is refused
            lits = [o - tables[name][0][0] for o, _, kind, _, _ in tables[name] if kind == "lit"]
            self.assertTrue(lits, name)
            flips = [body[:o] + bytes([body[o] ^ 1]) + body[o + 1:] for o in lits]
            for bad in (*flips, body[:-1], body + b"\0"):
                with self.assertRaises(ref.Refused, msg=name):
                    ref.read(tables[name], bad)
        # every rule of every record has a body that breaks it and no other rule
        verdicts = ref.verdict_vectors(text)
        for want, name, field, body in verdicts:
            self.assertTrue(ref.verdict_ok(tables, want, name, field, body), f"{name} {field} {body.hex()}")
        for name, rules in ref.RULES.items():
            for fields, _ in rules:
                self.assertTrue(any(not want and n == name and f in fields for want, n, f, _ in verdicts),
                                f"no refuse vector for the rule on {name} {fields}")
        # the second reader computes every fold example's record from the text of "The fold"
        examples = ref.fold_examples(text)
        self.assertEqual([e[0] for e in examples], EXAMPLES)
        for name, opening, inputs, fold in examples:
            self.assertEqual(len(opening), 7, name)
            self.assertEqual(ref.fold_of(text, opening, inputs), fold, name)
            self.assertEqual(fold is None, name in NO_FOLD, name)
            if fold is not None:
                self.assertEqual(len(fold), json.loads(CONSTANTS.read_text("utf-8"))["body_bytes"], name)

    def _second_reader(self):
        text = SPEC.read_text("utf-8")
        ref = ref_reader()
        tables, _ = ref.layouts(text)
        vec = {n: b for n, b, _ in ref.vectors(text)}
        return text, ref, tables, vec

    def test_action_status_follows_op(self) -> None:
        _, ref, tables, vec = self._second_reader()
        status_of = {1: 1, 2: 2, 3: 3, 4: 1}  # CREATE and ATTEMPT READY, ACK ACKNOWLEDGED, CANCEL CANCELLED
        for op in range(0, 6):
            for status in range(0, 5):
                body = bytearray(vec["action"])
                body[1], body[67] = op, status
                want = status_of.get(op) == status
                self.assertEqual(ref.accepts(tables, "action", bytes(body)), want, f"op {op} status {status}")

    def test_amounts_and_times_stop_below_2_63(self) -> None:
        _, ref, tables, vec = self._second_reader()
        # every amount and time of every record kind, as the rules bound them (amountWellFormed, timeWellFormed)
        fields = [("state", f) for f in ("owed", "cents", "received", "claimed", "lawful", "shortfall", "overage",
                                         "dueMs", "atMs")]
        fields += [("case", "dueMs"), ("case", "atMs"), ("command", "atMs"), ("action", "amount"), ("action", "atMs"),
                   ("oblig", "owed"), ("oblig", "dueMs"), ("cash", "amount"), ("cash", "eventMs"),
                   ("claim", "amount"), ("claim", "deadlineMs"), ("claim", "eventMs"), ("support", "applicableMs"),
                   ("support", "eventMs"), ("report", "applicableMs"), ("report", "eventMs"), ("fund", "amount"),
                   ("fund", "eventMs"), ("ack", "eventMs")]
        fields += [("fold", f) for f in ("cmaxMs", "cmaxCents", "doneMs", "reqsum", "amaxMs")]
        fields += [("state", "wbatch"), ("command", "wbatch"), ("command", "epoch")]
        for name, field in fields:
            f = ref.values(tables[name], vec[name])
            f[field] = 2 ** 63 - 1
            self.assertTrue(ref.accepts(tables, name, ref.write(tables[name], f)), f"{name} {field} 2^63-1")
            f[field] = 2 ** 63
            self.assertFalse(ref.accepts(tables, name, ref.write(tables[name], f)), f"{name} {field} 2^63")

    def test_fold_of_repeated_statement_and_of_a_total_that_does_not_fit(self) -> None:
        text, ref, tables, vec = self._second_reader()
        _, opening, inputs, _ = next(e for e in ref.fold_examples(text) if e[0] == "void")
        state, pay = inputs[0], inputs[1]
        # the same CASH statement again, under another payment id and with no evidence id: nothing moves
        again = (9, pay[1], [None, b"pay-again", None])
        self.assertEqual(ref.fold_of(text, opening, [state, pay, again]), ref.fold_of(text, opening, [state, pay]))

        def request(no: int, ak: int, amount: int):
            f = ref.values(tables["action"], vec["action"])
            f.update(op=1, akind=2, status=1, amount=amount, ak=bytes([ak]) * 32)
            return (no, ref.write(tables["action"], f), [None, None, b"a%d" % no])

        # a statement asserted, voided and asserted again with a payment element: the second assertion adds nothing
        void = (8, ref.write(tables["cash"], {**ref.values(tables["cash"], pay[1]), "op": 1}), [None, None, None])
        again = (9, pay[1], [None, b"pay-again", None])
        self.assertEqual(ref.fold_of(text, opening, [state, pay, void, again]),
                         ref.fold_of(text, opening, [state, pay, void]))

        fits = [state, request(1, 1, 2 ** 63 - 1)]
        self.assertEqual(ref.values(tables["fold"], ref.fold_of(text, opening, fits))["reqsum"], 2 ** 63 - 1)
        # two requests make 2^64 - 2, three more than a field holds: no fold record, and no exception
        for n in (2, 3):
            self.assertIsNone(ref.fold_of(text, opening, [state] + [request(i, i, 2 ** 63 - 1) for i in range(1, n + 1)]))

    def test_command_epoch_is_at_least_1(self) -> None:
        _, ref, tables, vec = self._second_reader()
        for epoch, want in ((0, False), (1, True), (2 ** 63 - 1, True), (2 ** 63, False), (2 ** 64 - 1, False)):
            f = ref.values(tables["command"], vec["command"])
            f["epoch"] = epoch
            self.assertEqual(ref.accepts(tables, "command", ref.write(tables["command"], f)), want, f"epoch {epoch}")

    def test_action_key_is_not_all_zero(self) -> None:
        _, ref, tables, vec = self._second_reader()
        f = ref.values(tables["action"], vec["action"])
        f["ak"] = bytes(32)
        self.assertFalse(ref.accepts(tables, "action", ref.write(tables["action"], f)))
        f["ak"] = bytes(31) + b"\1"
        self.assertTrue(ref.accepts(tables, "action", ref.write(tables["action"], f)))

    def test_fold_rules_of_round_three(self) -> None:
        text, ref, tables, vec = self._second_reader()
        _, opening, inputs, _ = next(e for e in ref.fold_examples(text) if e[0] == "void")
        fold_of = lambda recs, op=opening: ref.fold_of(text, op, recs)
        field = lambda recs, name: ref.values(tables["fold"], fold_of(recs))[name]

        def state(owed: int, verification: int = 3):
            f = ref.values(tables["state"], vec["state"])
            f.update(owed=owed, verification=verification)
            return (0, ref.write(tables["state"], f), [None, None, None])

        def cash(no: int, sid: int, op: int, amount: int, pays: bytes = bytes(32), pid: "bytes | None" = b"p"):
            f = ref.values(tables["cash"], vec["cash"])
            f.update(op=op, sid=bytes([sid]) * 32, amount=amount, pays=pays)
            return (no, ref.write(tables["cash"], f), [None, pid if op == 0 else None, None])

        def action(no: int, op: int, akind: int, ak: int, amount: int, at: int = 1000, elems=(None, None, b"a")):
            f = ref.values(tables["action"], vec["action"])
            f.update(op=op, akind=akind, status={1: 1, 3: 3}[op], ak=bytes([ak]) * 32, amount=amount, atMs=at,
                     decidedMs=0)
            return (no, ref.write(tables["action"], f), list(elems))

        # a void counts as a use: void first, then assert with a payment element
        recs = [state(100), cash(1, 5, 1, 100), cash(2, 5, 0, 100)]
        self.assertEqual((field(recs, "ccount"), field(recs, "done")), (0, 0))
        self.assertEqual(field([state(100), cash(1, 5, 0, 100)], "done"), 2)  # no void: the payment counts
        # an action key creates once: an offset, a request, and create-cancel-create
        offset = lambda no, at, det: action(no, 1, 1, 7, 50, at, (None, det, b"o%d" % no))
        recs = [state(50), offset(1, 10, b"d1"), offset(2, 20, b"d2")]
        self.assertEqual((field(recs, "ccount"), field(recs, "amax")), (1, 2))
        request = lambda no, at: action(no, 1, 2, 8, 30, at)
        recs = [state(50), request(1, 10), request(2, 20)]
        self.assertEqual((field(recs, "reqsum"), field(recs, "amax")), (30, 2))
        recs = [state(50), request(1, 10), action(2, 3, 2, 8, 30), request(3, 30)]
        self.assertEqual((field(recs, "reqsum"), field(recs, "amax")), (0, 2))
        # an all-zero key is refused with its record: no request, no latest action
        zero = action(1, 1, 2, 0, 30)
        self.assertEqual((field([state(50), zero], "reqsum"), field([state(50), zero], "amax")), (0, 0))
        # no state row read: the first payment does not complete
        self.assertEqual(field([state(100, verification=0), cash(1, 5, 0, 1)], "done"), 0)
        self.assertEqual(field([state(1), cash(1, 5, 0, 1)], "done"), 2)
        # every payment fits and their sum does not: owed 2^63 - 1, then 5 and 2^63 - 1
        big = 2 ** 63 - 1
        self.assertIsNone(fold_of([state(big), cash(1, 5, 0, 5), cash(2, 6, 0, big)]))
        self.assertIsNotNone(fold_of([state(big), cash(1, 5, 0, 5), cash(2, 6, 0, big - 5)]))
        # an identifier or an opening field of 65,536 bytes does not fit lp16: no record, and no exception
        long = b"x" * 65536
        self.assertIsNone(fold_of([state(1)], [*opening[:5], long, opening[6]]))
        self.assertIsNone(fold_of([(0, state(1)[1], [long, None, None])]))
        self.assertIsNone(fold_of([(0, state(1)[1], [None, None, long])]))
        self.assertIsNone(fold_of([(0, state(1)[1], [None, long, None])]))
        self.assertIsNotNone(fold_of([(0, state(1)[1], [None, b"x" * 65535, None])]))
        self.assertIsNotNone(fold_of([(0, state(1)[1], [b"x" * 65535, None, None])]))

    def test_lean_and_second_reader_give_the_same_folds(self) -> None:
        seed = secrets.randbits(63)
        print(f"obligations format folds seed {seed}")
        text, ref, tables, vec = self._second_reader()
        tags = list(ref.layouts(text)[1].values())
        R = random.Random(seed)
        keys = [bytes([i]) * 32 for i in (60, 61, 62)] + [bytes(32)]
        ids = [b"p1", b"p10", b"p2", b"", b"id-7", b"\xff"]
        t0, edge = 1767225600000, [0, 1, 10, 100, 250, 1000, 2 ** 63 - 1, 2 ** 63]

        def mk(kind, **kw):
            f = ref.values(tables[kind], vec[kind])
            f.update(kw)
            return ref.write(tables[kind], f)

        def body():
            kind = R.choice(["state", "cash", "cash", "action", "action", "case", "junk"])
            if kind == "state":
                return mk("state", owed=R.choice(edge[:6] + [2 ** 63 - 1]), verification=R.choice([1, 2, 3, 3, 0]))
            if kind == "cash":
                return mk("cash", op=R.choice([0, 0, 0, 1, 1, 2]), sid=bytes([R.randint(1, 4)]) * 32,
                          amount=R.choice(edge), eventMs=t0 + R.choice([0, 1, 5]), pays=R.choice(keys))
            if kind == "action":
                op, at = R.choice([1, 1, 1, 3, 2, 4]), t0 + R.choice([0, 1, 5])
                status = {1: 1, 2: 2, 3: 3, 4: 1}[op] if R.random() < .9 else 2
                return mk("action", op=op, ak=R.choice(keys), akind=R.choice([1, 2, 2, 0, 3]), status=status,
                          amount=R.choice(edge), atMs=at, decidedMs=at - R.choice([0, 0, 1]))
            if kind == "case":
                return mk("case")
            return R.randbytes(245) if R.random() < .5 else bytes([R.choice(tags)]) + R.randbytes(244)

        lines, want = [], {}
        for k in range(FOLD_CASES):
            opening = [R.randbytes(R.randint(0, 6)) for _ in range(7)]
            recs = []
            for no in range(R.randint(0, 12)):
                b = body()
                if R.random() < .03:
                    b = b[:-1]
                recs.append((no, b, [R.choice(ids) if R.random() < p else None for p in (.4, .7, .7)]))
            lines.append(f"example e{k}")
            lines += [f"opening f{i} {o.hex()}" for i, o in enumerate(opening)]
            lines += ["input %d %s %s" % (no, b.hex(), " ".join("-" if x is None else x.hex() for x in e))
                      for no, b, e in recs]
            want[f"e{k}"] = ref.fold_of(text, opening, recs)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "folds.txt"
            path.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
            out = run("obligations_format_check", "folds", str(path), timeout=300)
        got = {l.split(" ")[1]: l.split(" ")[2] for l in out.splitlines() if l.startswith("R ")}
        self.assertEqual(len(got), FOLD_CASES)
        for name, fold in want.items():
            self.assertEqual(got[name], "none" if fold is None else fold.hex(), f"seed {seed} {name}")
        self.assertTrue(any(f is None for f in want.values()) and any(f is not None for f in want.values()))

    def test_second_reader_gives_the_programs_verdicts(self) -> None:
        seed = secrets.randbits(63)
        print(f"obligations format verdicts seed {seed}")
        text = SPEC.read_text("utf-8")
        ref = ref_reader()
        tables, _ = ref.layouts(text)
        counts: dict[str, list[int]] = {}
        for line in run("obligations_format_check", "verdicts", str(seed), str(VERDICTS_N), timeout=600).splitlines():
            _, name, lean, body = line.split(" ")
            ours = ref.accepts(tables, name, bytes.fromhex(body))
            self.assertEqual(ours, lean == "1", f"seed {seed} {name} {body}")
            counts.setdefault(name, [0, 0])[ours] += 1
        self.assertEqual(sorted(counts), sorted(ref.RULES.keys() - {"link"}))
        for name, (refused, accepted) in counts.items():
            self.assertEqual(refused + accepted, VERDICTS_N, name)
            self.assertTrue(refused and accepted, f"{name}: refused {refused}, accepted {accepted}")

    def test_fuzz_every_codec(self) -> None:
        seed = secrets.randbits(63)
        print(f"obligations format fuzz seed {seed}")
        out = run("obligations_format_check", "fuzz", str(seed), str(FUZZ_N), timeout=3600)
        lines = [l for l in out.splitlines() if l.startswith("FUZZ record=")]
        kinds = len(json.loads(CONSTANTS.read_text("utf-8"))["records"]) + 1  # every record kind and the link
        self.assertEqual(len(lines), kinds, out[-3000:])
        self.assertIn("FUZZ record=link ", out)
        for l in lines:
            self.assertIn(f" random={FUZZ_N} ", l)
            self.assertTrue(l.endswith(" failures=0"), l)
        self.assertIn(f"FUZZ_SUMMARY codecs={kinds} failures=0", out)


def lean_imports(path: Path) -> list[str]:
    return re.findall(r"^import (\S+)", path.read_text("utf-8"), re.M)


def row_files(*names: str) -> list[Path]:
    out: list[Path] = []
    for n in names:
        p = LEAN / n
        out += sorted(p.rglob("*.lean")) if p.is_dir() else []
        out += [p.with_suffix(".lean")] if p.with_suffix(".lean").is_file() else []
    return out


CORE = ("Init", "Std", "Lean")
HASH = ("BlindLedger.Sha3",)
FORMAT = ("BlindLedger.Gate.Obligations.Format",)
RULES = ("BlindLedger.Financial",)
TABLE = ("BlindLedger.Gate.Engine3.Index",)
STORE = ("BlindLedger.Gate.Obligations.Store",)
# What the format module imports beyond the hash library, one line each:
FORMAT_ALLOWED = (
    "BlindLedger.Gate.Obligations.Layout",  # the generic layout codec, no width of its own; moves into the format module when the first engine is removed
    "BlindLedger.Gate.FactCodec",  # the base fact codec: little-endian bytes, identifier fields, the 245-byte body
)

# Each row of the table: its files, and the module prefixes they may import (their own row always).
TABLE_ROWS = {
    "format": (row_files("Gate/Obligations/Format"), FORMAT + HASH + FORMAT_ALLOWED),
    "rules": (row_files("Financial"), RULES + HASH),
    "table": (row_files("Gate/Engine3/Index"), TABLE),
    "store": (row_files("Gate/Obligations/Store"), STORE + FORMAT + TABLE + ("BlindLedger.Gate.Engine3.Frame3",)),
    "engine": (row_files("Gate/Obligations/Engine"), ("BlindLedger.Gate.Obligations.Engine",) + FORMAT + RULES + STORE),
    "checker": (row_files("Gate/Obligations/Verify"),
                ("BlindLedger.Gate.Obligations.Verify",) + FORMAT + RULES + TABLE + HASH + ("BlindLedger.Gate.MlDsa87",)),
    "readers": (row_files("Gate/Obligations/View"), ("BlindLedger.Gate.Obligations.View",) + FORMAT + RULES),
}
HOST = sorted((ROOT / "app").glob("right_rail_obligations_*.py"))

# Lines of the table's modules that hold a guarded number and are not a width, offset or tag, one line each.
ARITH = re.compile(r"256 ?\^|[%/*<] 256(?![\w.])|256 \*")  # 256 as the byte base: a power, a digit split, a bound
ALLOWED = {
    ("Financial/Batch.lean", "def maxBatchItems : Nat := 256"),  # a count of items, not bytes
    ("Financial/CodecLaws/Primitives.lean", "simp [readByte, Nat.div_add_mod' value 256]"),  # the byte base
    ("Financial/CorrectionTransition/KAT.lean",
     "0x84, 0x97, 0x09, 0xa5, 0x88, 0x17, 0x47, 0xcf, 0xd9, 0x07, 0x5d, 0x49, 0xdb, 0x56, 0xdc, 0x12,"),  # a hash
    ("Financial/DecisionPackage/Decide.lean",
     "def packageRequestMagic : Bytes := [0x42, 0x4C, 0x46, 0x44, 0x50, 0x51, 0x30, 0x31]"),  # ASCII "BLFDPQ01"
    ("Financial/DecisionPackage/Wire.lean",
     "def packageItemMagic : Bytes := [0x42, 0x4C, 0x46, 0x44, 0x50, 0x4B, 0x30, 0x31]"),  # ASCII "BLFDPK01"
    ("Financial/DecisionPackage/Wire.lean",
     "def packageAnswerMagic : Bytes := [0x42, 0x4C, 0x46, 0x44, 0x50, 0x41, 0x30, 0x31]"),  # ASCII "BLFDPA01"
    ("Gate/Engine3/Index.lean", "rw [show (256 : UInt64).toNat = 2 ^ 8 from rfl, Nat.testBit_mod_two_pow]"),  # 2^8
}
WIDTH = re.compile(r"(?<![\w.])(256|276|245|208)(?![\w.])")
TAGS = sorted({r["tag"] for r in json.loads(CONSTANTS.read_text("utf-8"))["records"]})
TAG = re.compile(r"(?<!\w)0[xX](" + "|".join(f"{t:02x}" for t in TAGS) + r")(?!\w)", re.I)
TAG_DEC = re.compile(r"(?i)\btag.*?(?<![\w.])(" + "|".join(str(t) for t in TAGS) + r")(?![\w.])")
DOMAIN = re.compile(r"RR/GATE/(EVALFIX|EVIDACC)/")


class ModuleTests(unittest.TestCase):
    def test_imports_follow_the_module_table(self) -> None:
        self.assertTrue(TABLE_ROWS["format"][0] and TABLE_ROWS["rules"][0] and TABLE_ROWS["table"][0])
        bad = []
        for row, (files, allowed) in TABLE_ROWS.items():
            for f in files:
                for imp in lean_imports(f):
                    if imp.split(".")[0] in CORE or any(imp == a or imp.startswith(a + ".") or
                                                        (a in HASH and imp.startswith(a)) for a in allowed):
                        continue
                    bad.append(f"{row}: {f.relative_to(ROOT).as_posix()} imports {imp}")
        for f in HOST:
            for imp in re.findall(r"^\s*(?:from|import) (\S+)", f.read_text("utf-8"), re.M):
                if imp == "lean" or imp.startswith("lean."):
                    bad.append(f"host: {f.name} imports {imp}")
        self.assertEqual(bad, [])

    def test_no_layout_number_outside_the_format_module(self) -> None:
        files = [f for row, (fs, _) in TABLE_ROWS.items() if row != "format" for f in fs] + HOST
        seen, bad = set(), []
        for f in files:
            rel = f.relative_to(LEAN).as_posix() if f.is_relative_to(LEAN) else f.relative_to(ROOT).as_posix()
            for line in f.read_text("utf-8").splitlines():
                if WIDTH.search(ARITH.sub("", line)) or TAG.search(line) or TAG_DEC.search(line) or DOMAIN.search(line):
                    if (rel, line.strip()) in ALLOWED:
                        seen.add((rel, line.strip()))
                    else:
                        bad.append(f"{rel}: {line.strip()}")
        self.assertEqual(bad, [], "a width, offset, tag or domain outside the format module; name it there and read it")
        self.assertEqual(sorted(ALLOWED - seen), [], "an allowance no longer matches a line; remove it")


if __name__ == "__main__":
    unittest.main()
