"""Provider pre-check contentDigest vectors (spec: conformance/PROVIDER_CONTENT_DIGEST_V1.md).

Three independent checks of the same published vectors: the stdlib-only recompute, the
product codec, and the deterministic generator. A missing vector directory fails.
"""

import ast
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VEC = ROOT / "conformance" / "vectors" / "provider_digest_v1"
GEN = ROOT / "tools" / "gen_provider_digest_v1_vectors.py"
POSITIVE, REJECT = 14, 32
SPEC = ROOT / "conformance" / "PROVIDER_CONTENT_DIGEST_V1.md"
BEGIN, END = "# ---" + " stdlib begin", "# ---" + " stdlib end"

# --- stdlib begin
_SHORT = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _str(text):
    out = ['"']
    for ch in text:
        c = ord(ch)
        if ch in _SHORT:
            out.append(_SHORT[ch])
        elif 0x20 <= c <= 0x7E:
            out.append(ch)
        elif c < 0x10000:
            out.append("\\u%04x" % c)
        else:
            c -= 0x10000
            out.append("\\u%04x\\u%04x" % (0xD800 + (c >> 10), 0xDC00 + (c & 0x3FF)))
    return "".join(out) + '"'


def serialize(v):
    if v is None:
        return "null"
    if v is True or v is False:
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return _str(v)
    if isinstance(v, list):
        return "[" + ",".join(serialize(x) for x in v) + "]"
    return "{" + ",".join(_str(k) + ":" + serialize(v[k]) for k in sorted(v)) + "}"


def recompute(raw):
    content = {k: v for k, v in json.loads(raw.decode("utf-8")).items() if k != "contentDigest"}
    text = serialize(content)
    return text, "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()
# --- stdlib end


def _index():
    return json.loads((VEC / "cases.json").read_text(encoding="ascii"))


def _raw(case):
    return (VEC / (case["id"] + ".json")).read_bytes()


class ProviderDigestVectors(unittest.TestCase):
    def test_vector_dir_present_and_counts_pinned(self):
        self.assertTrue(VEC.is_dir(), "vector directory missing")
        index = _index()
        self.assertEqual(POSITIVE, len(index["positive"]))
        self.assertEqual(REJECT, len(index["reject"]))
        names = {p.name for p in VEC.iterdir()}
        expected = {c["id"] + ".json" for c in index["positive"] + index["reject"]} | {"cases.json"}
        self.assertEqual(expected, names)
        self.assertLess(sum(p.stat().st_size for p in VEC.iterdir()), 150_000)
        SPEC.read_bytes().decode("ascii")

    def test_stdlib_recompute_matches_published(self):
        for case in _index()["positive"]:
            with self.subTest(case["id"]):
                text, digest = recompute(_raw(case))
                self.assertEqual(case["canonical"], text)
                self.assertEqual(case["digest"], digest)
        for case in _index()["reject"]:
            if case["error"] == "BUNDLE_DIGEST_MISMATCH":
                with self.subTest(case["id"]):
                    declared = json.loads(_raw(case))["contentDigest"]
                    self.assertNotEqual(declared, recompute(_raw(case))[1])

    def test_stdlib_section_imports_no_product_code(self):
        source = Path(__file__).read_text(encoding="utf-8")
        section = source[source.index(BEGIN):source.index(END)]
        for word in ("provider_app", "codec", "import ", "app."):
            self.assertNotIn(word, section)

    def test_generator_reproduces_every_byte(self):
        spec = importlib.util.spec_from_file_location("gen_provider_digest_v1_vectors", GEN)
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        roots = {a.name.split(".")[0] for n in ast.walk(ast.parse(GEN.read_text(encoding="utf-8")))
                 if isinstance(n, ast.Import) for a in n.names}
        self.assertEqual({"hashlib", "json", "re", "sys"}, roots)
        produced = gen.files()
        self.assertEqual(set(produced), {p.name for p in VEC.iterdir()})
        for name, data in produced.items():
            with self.subTest(name):
                self.assertEqual(data, (VEC / name).read_bytes())

    def test_product_codec_accepts_and_refuses_every_vector(self):
        sys.path.insert(0, str(ROOT / "provider_app"))
        try:
            from provider_app import codec
            from provider_app.contracts import InputError
        finally:
            sys.path.pop(0)
        for case in _index()["positive"]:
            with self.subTest(case["id"]):
                raw = _raw(case)
                self.assertEqual(case["digest"], codec.bundle_content_digest(codec._load(raw, "BUNDLE_TOO_LARGE")))
                if case["kind"] == "bundle":
                    self.assertEqual(case["digest"], codec.parse_bundle_bytes(raw).content_digest)
        for case in _index()["reject"]:
            with self.subTest(case["id"]):
                with self.assertRaises(InputError) as caught:
                    codec.parse_bundle_bytes(_raw(case))
                self.assertEqual(case["error"], caught.exception.code)
        with self.assertRaises(InputError) as caught:
            codec.parse_bundle_bytes("{}")
        self.assertEqual("JSON_BYTES_REQUIRED", caught.exception.code)


if __name__ == "__main__":
    unittest.main()
