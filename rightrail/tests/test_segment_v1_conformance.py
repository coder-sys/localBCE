"""RR/GATE/SEGMENT/v1 vectors (conformance/SEGMENT_V1.md): the owner and the independent checker accept every positive
vector with the published digests and refuse every negative one for its named reason; stdlib alone recomputes the digests
from the spec; the generator reproduces the files byte for byte. Synthetic, non-PHI, nonpayment."""

import ast
import hashlib
import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

VECTORS = Path(__file__).resolve().parent.parent / "conformance" / "vectors" / "segment_v1"
INDEX = json.loads((VECTORS / "index.json").read_bytes())
POSITIVE, NEGATIVE = 3, 37


def _product():  # the only place this file imports product code: the spec recompute below imports nothing
    from app.right_rail_financial_owner import FinancialContinuityError, FinancialOwner, SyntheticTrustedAuthority
    from app.right_rail_financial_owner_independent import IndependentFinancialError, verify_history_export
    from tools import gen_segment_v1_vectors
    return FinancialContinuityError, FinancialOwner, SyntheticTrustedAuthority, IndependentFinancialError, verify_history_export, gen_segment_v1_vectors


def _canonical(value):  # SEGMENT_V1.md section 2
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _d(*parts):  # SEGMENT_V1.md section 3
    state = hashlib.sha3_512(b"RR/GATE/SEGMENT/v1\x00")
    for part in parts:
        state.update(len(part).to_bytes(8, "big"))
        state.update(part)
    return state.hexdigest().upper()


def _json(path):
    return json.loads(path.read_bytes())


class SegmentV1Conformance(unittest.TestCase):
    def _overlay(self, case, root):
        source, target = VECTORS / "negative" / case["name"], root / case["name"]
        shutil.copytree(VECTORS / INDEX["negative_base"], target)
        if (source / "delete.json").exists():
            for name in _json(source / "delete.json"):
                (target / name).unlink()
        for path in source.iterdir():
            if path.name != "delete.json":
                shutil.copy(path, target / path.name)
        return target

    def test_the_vector_set_is_exactly_the_indexed_set(self):
        names = [case["name"] for case in INDEX["negative"]]
        self.assertEqual((len(names), len(set(names))), (NEGATIVE, NEGATIVE))
        self.assertEqual(sorted(path.name for path in (VECTORS / "negative").iterdir()), sorted(names))
        self.assertEqual(len(list((VECTORS / "positive").iterdir())), POSITIVE)
        (VECTORS.parents[1] / "SEGMENT_V1.md").read_bytes().decode("ascii")
        for path in [*(VECTORS / "negative").iterdir(), *(VECTORS / "positive").iterdir()]:
            self.assertTrue(any(path.iterdir()), f"{path.name} holds no file, so git would not track it")

    def test_positive_vectors_are_accepted_by_both_with_the_published_digests(self):
        _, FinancialOwner, SyntheticTrustedAuthority, _, verify_history_export, _ = _product()
        directories = sorted((VECTORS / "positive").iterdir())
        self.assertEqual(len(directories), POSITIVE)
        for directory in directories:
            with self.subTest(directory.name), tempfile.TemporaryDirectory() as tmp:
                expected = _json(directory / "expected.json")
                checked = verify_history_export(directory, expected_authority=INDEX["trusted_authority"])
                self.assertEqual((checked["sequence"], checked["segment_count"], checked["package_digest"]), (expected["sequence"], len(expected["segments"]), expected["manifest_digest"]))
                owner = FinancialOwner.restore_continuity(history=directory, recovered_path=Path(tmp) / "restored.sqlite3", trusted_authority=SyntheticTrustedAuthority())
                self.addCleanup(owner.close)
                with closing(sqlite3.connect(owner.path)) as connection:
                    resealed = [(row[0].hex().upper(), row[1].hex().upper()) for row in connection.execute("SELECT segment_digest,projection_root FROM history_segments ORDER BY segment_index")]
                self.assertEqual(resealed, [(s["segment_digest"], s["projection_root"]) for s in expected["segments"]])

    def test_spec_recompute_with_stdlib_only_matches_the_published_digests(self):
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        imported = {a.name.split(".")[0] for n in tree.body if isinstance(n, ast.Import) for a in n.names} | {n.module.split(".")[0] for n in tree.body if isinstance(n, ast.ImportFrom)}
        self.assertEqual(imported - set(sys.stdlib_module_names), set())
        recompute = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in ("_canonical", "_d", "test_spec_recompute_with_stdlib_only_matches_the_published_digests")]
        self.assertEqual((len(recompute), [n for f in recompute for n in ast.walk(f) if isinstance(n, (ast.Import, ast.ImportFrom))]), (3, []))
        for directory in sorted((VECTORS / "positive").iterdir()):
            with self.subTest(directory.name):
                expected, manifest, previous, last = _json(directory / "expected.json"), _json(directory / "manifest.json"), "0" * 128, 0
                self.assertEqual((directory / "manifest.json").read_bytes(), _canonical(manifest))
                self.assertEqual(manifest["segment_count"], len(expected["segments"]))
                for index, want in enumerate(expected["segments"]):
                    raw = (directory / f"segment-{index:08d}.json").read_bytes()
                    segment = json.loads(raw)
                    self.assertEqual((raw, segment["signature"], sorted(segment)), (_canonical(segment), None, ["events", "rows", "seal", "segment_digest", "signature"]))
                    sequences = [event["event_sequence"] for event in segment["events"]]
                    first, last = last + 1, last + len(sequences)
                    self.assertEqual(sequences, list(range(first, last + 1)))
                    seal = {"format": "RR/GATE/SEGMENT/v1", "segment_index": index, "first_sequence": first, "last_sequence": last, "event_count": len(sequences),
                            "previous_digest": previous, "event_head": segment["events"][-1]["head"]["hex"], "projection_root": _d(b"rows", _canonical(segment["rows"]))}
                    self.assertEqual(segment["rows"], sorted(segment["rows"], key=_canonical))
                    self.assertEqual((seal, _d(b"seal", _canonical(seal))), (segment["seal"], segment["segment_digest"]))
                    self.assertEqual((first, last, seal["projection_root"], seal["event_head"], segment["segment_digest"]), (want["first_sequence"], want["last_sequence"], want["projection_root"], want["event_head"], want["segment_digest"]))
                    previous = segment["segment_digest"]
                body = {key: value for key, value in manifest.items() if key != "manifest_digest"}
                self.assertEqual((manifest["last_segment_digest"], manifest["manifest_digest"], manifest["meta"]["sequence"]), (previous, expected["manifest_digest"], last))
                self.assertEqual(manifest["manifest_digest"], _d(b"manifest", _canonical(body)))

    def test_negative_vectors_are_refused_by_both_for_the_named_rule(self):
        FinancialContinuityError, FinancialOwner, SyntheticTrustedAuthority, IndependentFinancialError, verify_history_export, _ = _product()
        for case in INDEX["negative"]:
            with self.subTest(case["name"]), tempfile.TemporaryDirectory() as tmp:
                directory = self._overlay(case, Path(tmp))
                with self.assertRaisesRegex(IndependentFinancialError, f"^{case['refusal']}$"):
                    verify_history_export(directory, expected_authority=INDEX["trusted_authority"])
                with self.assertRaisesRegex(FinancialContinuityError, f"^history_export:{case['refusal']}$"):
                    FinancialOwner.restore_continuity(history=directory, recovered_path=Path(tmp) / "restored.sqlite3", trusted_authority=SyntheticTrustedAuthority())

    def test_the_signature_is_outside_every_digest(self):
        case = next(case for case in INDEX["negative"] if case["name"] == "signature_not_null")
        base, changed = _json(VECTORS / "positive" / "mid_chain" / "segment-00000001.json"), _json(VECTORS / "negative" / case["name"] / "segment-00000001.json")
        self.assertEqual({key: value for key, value in changed.items() if key != "signature"}, {key: value for key, value in base.items() if key != "signature"})
        self.assertEqual((base["signature"], changed["signature"]), (None, "00"))

    def test_the_generator_reproduces_every_vector_byte_for_byte(self):
        gen = _product()[-1]
        with tempfile.TemporaryDirectory() as tmp:
            gen.main(Path(tmp) / "again")
            listing = lambda root: {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}
            self.assertEqual(listing(Path(tmp) / "again"), listing(VECTORS))


if __name__ == "__main__":
    unittest.main()
