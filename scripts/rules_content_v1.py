"""RR/RULES/CONTENT/v1 (proposed): versioned, hash-pinned rule content exported as proposals.

RIGHTRAIL_BASE_PLAN.md Phase 2.  Exports the rules corpus promotion queue
(`gov-rules-kg-prototype/reports/claude_web_promotion_ready.json`) as a rule
content document that RightRail can review.  Every document this tool writes is
a PROPOSAL and `authoritative: false`: model output is a lead, never a
determination (CONST I.3).  Nothing here is read by any decision path.

The format name and digest domain are a localBCE proposal.  RightRail treats
wire formats and digest domains as protected (CONST XI.2), so RightRail accepts
this format only through an XI.2 record and an `rr-core` review.

Digest: SHA3-512 over the UTF-8 bytes of `RR/RULES/CONTENT/v1`, a NUL byte, then
the canonical JSON of the document without `content_digest` (keys sorted, no
insignificant whitespace, no floats).

Usage:
  python3 scripts/rules_content_v1.py export QUEUE.json OUT.json --content-id ID --version N
  python3 scripts/rules_content_v1.py verify DOC.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

FORMAT = "RR/RULES/CONTENT/v1"
DOMAIN = FORMAT.encode("utf-8") + b"\x00"
STATUS = "PROPOSAL"
PRODUCER = "gov-rules-kg-prototype"
RULE_FIELDS = ("rule_id", "program", "jurisdiction_level", "rule_unit_type", "statement", "citation",
               "model_confidence_bp", "verification_status", "corpus_promotion_status", "lean_rule", "test_vectors")
DOC_FIELDS = ("format", "content_id", "version", "status", "authoritative", "producer", "source_sha3_512",
              "rules", "content_digest")


class ContentError(ValueError):
    pass


def canonical(obj) -> bytes:
    def check(x):
        if isinstance(x, float):
            raise ContentError("floats are not allowed in rule content")
        if isinstance(x, dict):
            for v in x.values():
                check(v)
        elif isinstance(x, list):
            for v in x:
                check(v)
    check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(doc: dict) -> str:
    body = {k: v for k, v in doc.items() if k != "content_digest"}
    return hashlib.sha3_512(DOMAIN + canonical(body)).hexdigest()


def rule_from_candidate(c: dict) -> dict:
    for k in ("candidate_id", "statement", "source_url", "promotion_status"):
        if not c.get(k):
            raise ContentError(f"candidate is missing {k}")
    if c["promotion_status"] != "candidate_only_not_verified":
        raise ContentError(f"{c['candidate_id']}: unexpected promotion_status {c['promotion_status']!r}")
    conf = c.get("confidence_score")
    return {
        "rule_id": c["candidate_id"],
        "program": c.get("program"),
        "jurisdiction_level": c.get("jurisdiction_level"),
        "rule_unit_type": c.get("rule_unit_type"),
        "statement": c["statement"],
        "citation": {
            "url": c["source_url"],
            "title": c.get("source_title"),
            "text": c.get("citation_text"),
            "source_type": c.get("source_type"),
        },
        # Basis points, so the canonical form holds no float.
        "model_confidence_bp": None if conf is None else int(round(float(conf) * 10000)),
        "verification_status": c.get("verification_status"),
        "corpus_promotion_status": c["promotion_status"],
        # No Lean rule and no test vector exist for a corpus proposal; state review adds them (Phase 3).
        "lean_rule": None,
        "test_vectors": [],
    }


def export(queue: list, source_bytes: bytes, content_id: str, version: int) -> dict:
    if not isinstance(queue, list):
        raise ContentError("promotion queue must be a JSON list")
    if not content_id or version < 1:
        raise ContentError("content_id is required and version starts at 1")
    rules = sorted((rule_from_candidate(c) for c in queue), key=lambda r: r["rule_id"])
    ids = [r["rule_id"] for r in rules]
    if len(ids) != len(set(ids)):
        raise ContentError("duplicate rule_id in promotion queue")
    doc = {
        "format": FORMAT,
        "content_id": content_id,
        "version": version,
        "status": STATUS,
        "authoritative": False,
        "producer": PRODUCER,
        "source_sha3_512": hashlib.sha3_512(source_bytes).hexdigest(),
        "rules": rules,
    }
    doc["content_digest"] = digest(doc)
    return doc


def verify(doc: dict) -> dict:
    if set(doc) != set(DOC_FIELDS):
        raise ContentError(f"document fields {sorted(doc)} != {sorted(DOC_FIELDS)}")
    if doc["format"] != FORMAT:
        raise ContentError(f"format {doc['format']!r} is not {FORMAT}")
    if doc["status"] != STATUS or doc["authoritative"] is not False:
        raise ContentError("rule content from the corpus must be a non-authoritative PROPOSAL")
    if not isinstance(doc["version"], int) or isinstance(doc["version"], bool) or doc["version"] < 1:
        raise ContentError("version must be a positive integer")
    ids = [r.get("rule_id") for r in doc["rules"]]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ContentError("rules must be sorted by unique rule_id")
    for r in doc["rules"]:
        if set(r) != set(RULE_FIELDS):
            raise ContentError(f"rule {r.get('rule_id')} fields differ from {sorted(RULE_FIELDS)}")
        if r["lean_rule"] is not None or r["test_vectors"]:
            raise ContentError(f"rule {r['rule_id']}: a corpus proposal carries no Lean rule or vectors")
    if digest(doc) != doc["content_digest"]:
        raise ContentError("content_digest does not match the document")
    return {"format": FORMAT, "content_id": doc["content_id"], "version": doc["version"],
            "rules": len(doc["rules"]), "content_digest": doc["content_digest"], "authoritative": False}


def dumps(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description="RR/RULES/CONTENT/v1 proposals")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("queue")
    e.add_argument("out")
    e.add_argument("--content-id", required=True)
    e.add_argument("--version", type=int, required=True)
    v = sub.add_parser("verify")
    v.add_argument("doc")
    a = p.parse_args(argv)
    try:
        if a.cmd == "export":
            with open(a.queue, "rb") as f:
                raw = f.read()
            doc = export(json.loads(raw), raw, a.content_id, a.version)
            with open(a.out, "w", encoding="utf-8", newline="\n") as f:
                f.write(dumps(doc))
            print(json.dumps(verify(doc), sort_keys=True))
        else:
            with open(a.doc, encoding="utf-8") as f:
                print(json.dumps(verify(json.load(f)), sort_keys=True))
    except (ContentError, OSError, json.JSONDecodeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
