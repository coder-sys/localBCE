"""Hand-written Markdown stays few, each file owning one fact.

Rules (AGENTS.md "Documents"): every hand-written .md is listed below with the fact it owns, except one README.md per
directory for its module; conformance specs and generated provenance files are excluded by pattern; at most MAX_DOCS
hand-written files exist; "Continuity State" appears only in the Constitution's amendment log.
"""
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", ".lake", "__pycache__", "node_modules", "target", ".venv", "build", ".pytest_cache"}
MAX_DOCS = 22

OWNERS = {
    "CONSTITUTION.md": "the governing rules, standing claims and the amendment log",
    "AGENTS.md": "read order and working rules for contributors, including the Documents rule",
    "STATUS.md": "what runs now, open items, next steps and the speed bars",
    "ARCHITECTURE.md": "the six products, the code map and the built core rules",
    "docs/RIGHTRAIL_FULL_STACK_TARGET.md": "the end state, first jobs, rollout order and the authority ladder",
    "docs/STATE_EVIDENCE_ARCHITECTURE.md": "the evidence model, roles, build order and adoption",
}


def _rel(path):
    return os.path.relpath(path, ROOT).replace(os.sep, "/")


def _markdown():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.lower().endswith(".md"):
                yield _rel(os.path.join(dirpath, name))


def _excluded(rel):
    if rel.startswith("artifacts/") and os.path.basename(rel).startswith("PROVENANCE"):
        return True  # generated pin provenance
    return rel.startswith("conformance/") and rel.count("/") == 1 and rel != "conformance/README.md"  # wire specs


def _hand_written():
    return sorted(r for r in _markdown() if not _excluded(r))


def _module_readme(rel):
    return os.path.basename(rel) == "README.md"


class DocShapeTest(unittest.TestCase):
    def test_every_doc_is_listed_or_a_module_readme(self):
        unlisted = [r for r in _hand_written() if r not in OWNERS and not _module_readme(r)]
        self.assertEqual(unlisted, [], "add an OWNERS entry naming the fact it owns, or merge it into an owner")

    def test_every_listed_doc_exists(self):
        present = set(_markdown())
        self.assertEqual([r for r in OWNERS if r not in present], [])

    def test_at_most_the_cap(self):
        docs = _hand_written()
        self.assertLessEqual(len(docs), MAX_DOCS, "merge or delete a doc; raising the cap needs the owners' written approval")

    def test_continuity_state_only_in_the_amendment_log(self):
        offenders = []
        for rel in _markdown():
            with open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
                text = handle.read()
            if rel == "CONSTITUTION.md":
                text = text.split("### Amendment log", 1)[0]
            if "continuity state" in text.lower():
                offenders.append(rel)
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
