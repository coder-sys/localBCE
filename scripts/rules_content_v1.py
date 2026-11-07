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
import math
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
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError as err:  # e.g. a lone surrogate from a JSON \ud800 escape
        raise ContentError(f"text is not valid Unicode: {err}") from None


def digest(doc: dict) -> str:
    body = {k: v for k, v in doc.items() if k != "content_digest"}
    return hashlib.sha3_512(DOMAIN + canonical(body)).hexdigest()


CORPUS_STATUS = "candidate_only_not_verified"
CITATION_FIELDS = ("url", "title", "text", "source_type")
OPTIONAL_TEXT_RULE_FIELDS = ("program", "jurisdiction_level", "rule_unit_type", "verification_status")


def _text(value, name, required=True):
    if value is None and not required:
        return
    if not isinstance(value, str) or (required and not value):
        raise ContentError(f"{name} must be {'a non-empty' if required else 'a'} string{'' if required else ' or null'}")


def check_rule(r) -> None:
    """Every rule a corpus export can produce, and nothing else."""
    if not isinstance(r, dict) or set(r) != set(RULE_FIELDS):
        raise ContentError(f"rule fields must be exactly {sorted(RULE_FIELDS)}")
    rid = r["rule_id"]
    _text(rid, "rule_id")
    _text(r["statement"], f"rule {rid}: statement")
    for k in OPTIONAL_TEXT_RULE_FIELDS:
        _text(r[k], f"rule {rid}: {k}", required=False)
    c = r["citation"]
    if not isinstance(c, dict) or set(c) != set(CITATION_FIELDS):
        raise ContentError(f"rule {rid}: citation fields must be exactly {sorted(CITATION_FIELDS)}")
    _text(c["url"], f"rule {rid}: citation url")
    for k in ("title", "text", "source_type"):
        _text(c[k], f"rule {rid}: citation {k}", required=False)
    bp = r["model_confidence_bp"]
    if bp is not None and (not isinstance(bp, int) or isinstance(bp, bool) or not 0 <= bp <= 10000):
        raise ContentError(f"rule {rid}: model_confidence_bp must be null or an integer 0-10000")
    if r["corpus_promotion_status"] != CORPUS_STATUS:
        raise ContentError(f"rule {rid}: corpus_promotion_status must be {CORPUS_STATUS!r}")
    if r["lean_rule"] is not None or r["test_vectors"] != []:
        raise ContentError(f"rule {rid}: a corpus proposal carries no Lean rule or vectors")


def rule_from_candidate(c: dict) -> dict:
    if not isinstance(c, dict):
        raise ContentError("each promotion queue item must be a JSON object")
    for k in ("candidate_id", "statement", "source_url", "promotion_status"):
        if not c.get(k):
            raise ContentError(f"candidate is missing {k}")
    if c["promotion_status"] != CORPUS_STATUS:
        raise ContentError(f"{c['candidate_id']}: unexpected promotion_status {c['promotion_status']!r}")
    conf = c.get("confidence_score")
    if conf is not None and (not isinstance(conf, (int, float)) or isinstance(conf, bool)
                             or not math.isfinite(conf) or not 0 <= conf <= 1):
        raise ContentError(f"{c['candidate_id']}: confidence_score must be a number from 0 to 1")
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
    _text(content_id, "content_id")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ContentError("version must be a positive integer")
    rules = [rule_from_candidate(c) for c in queue]
    for r in rules:
        check_rule(r)
    rules.sort(key=lambda r: r["rule_id"])
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
    """Accept exactly the documents `export` can produce (then check the digest)."""
    if not isinstance(doc, dict) or set(doc) != set(DOC_FIELDS):
        raise ContentError(f"document fields must be exactly {sorted(DOC_FIELDS)}")
    if doc["format"] != FORMAT:
        raise ContentError(f"format {doc['format']!r} is not {FORMAT}")
    if doc["status"] != STATUS or doc["authoritative"] is not False:
        raise ContentError("rule content from the corpus must be a non-authoritative PROPOSAL")
    if not isinstance(doc["version"], int) or isinstance(doc["version"], bool) or doc["version"] < 1:
        raise ContentError("version must be a positive integer")
    _text(doc["content_id"], "content_id")
    if doc["producer"] != PRODUCER:
        raise ContentError(f"producer must be {PRODUCER!r}")
    for key in ("source_sha3_512", "content_digest"):
        v = doc[key]
        if not isinstance(v, str) or len(v) != 128 or any(ch not in "0123456789abcdef" for ch in v):
            raise ContentError(f"{key} must be 128 lowercase hex characters")
    if not isinstance(doc["rules"], list):
        raise ContentError("rules must be a list")
    for r in doc["rules"]:
        check_rule(r)
    ids = [r["rule_id"] for r in doc["rules"]]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ContentError("rules must be sorted by unique rule_id")
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
