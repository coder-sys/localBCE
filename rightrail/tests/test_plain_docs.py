"""Outside-facing docs stay plain English: no internal codenames or workflow talk."""
import glob, os, re, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODES = r"\b(hfb\d*|eflat|onep\d*|d1[chp]\d|IDREG|K6|TRAIN\d*)\b"
WORDS = r"\b(lead audit|helper|founder)\b"
STATUS_CODES = r"\b(hfb\d+|IDREG|K6|AGI|D7|S7a|M[134]|CFI-C1|BATCH-P\d|S\d[a-z]?\+?|trunk)\b"  # STATUS.md is read first: plain names only
read = lambda p: open(os.path.join(ROOT, p), encoding="utf-8").read()


class PlainDocsTest(unittest.TestCase):
    def test_docs_have_no_internal_talk(self):
        for p in ["README.md", "ARCHITECTURE.md", "AGENTS.md"] + [os.path.relpath(f, ROOT) for f in glob.glob(os.path.join(ROOT, "docs", "**", "*.md"), recursive=True) + glob.glob(os.path.join(ROOT, "conformance", "*.md"))]:
            self.assertIsNone(re.search(CODES, read(p)) or re.search(WORDS, read(p), re.I), p)

    def test_status_has_no_codenames(self):
        text = read("STATUS.md")
        self.assertIsNone(re.search(WORDS, text, re.I))
        self.assertEqual(re.findall(STATUS_CODES, text), [])

    def test_code_comments_name_no_workspace_paths(self):
        for tree in ("app", "tools", "tests", "provider_app"):
            for f in glob.glob(os.path.join(ROOT, tree, "**", "*.py"), recursive=True):
                if os.path.samefile(f, __file__):
                    continue
                self.assertIsNone(re.search(r"rrb/|rr-review", open(f, encoding="utf-8").read()), f)
