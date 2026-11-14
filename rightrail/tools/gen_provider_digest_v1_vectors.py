"""Deterministic generator for conformance/vectors/provider_digest_v1 (stdlib only).

Spec: conformance/PROVIDER_CONTENT_DIGEST_V1.md. Usage: python gen_provider_digest_v1_vectors.py [OUTDIR]
"""

import hashlib
import json
import re
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "conformance" / "vectors" / "provider_digest_v1"
ZERO = "sha256:" + "0" * 64


def canon(value, **kw):
    return json.dumps(value, **{"sort_keys": True, "separators": (",", ":"), "ensure_ascii": True, **kw})


def hexdigest(value, **kw):
    content = {k: v for k, v in value.items() if k != "contentDigest"}
    return hashlib.sha256(canon(content, **kw).encode("ascii")).hexdigest()


def sealed(bundle, digest=None):
    return {**bundle, "contentDigest": digest or "sha256:" + hexdigest(bundle)}


def rule(n, semantic, version=1, cat=None, lo=None, hi=None, age=None):
    return {"ruleId": "SYN-PRE-00%d" % n, "version": version, "semantic": semantic, "effectiveFrom": "2026-01-01",
            "effectiveUntil": "2027-01-01", "expectedCategory": cat, "minimumCents": lo, "maximumCents": hi,
            "maxSourceAgeDays": age}


RULES = [rule(1, "SERVICE_DATE_IN_EFFECTIVE_WINDOW"), rule(2, "SERVICE_CATEGORY_EQUALS", cat="SYNTH-CATEGORY-A"),
         rule(3, "SUPPORT_REFERENCE_PRESENT"), rule(4, "CHARGE_CENTS_BETWEEN", lo=100, hi=100000),
         rule(5, "SOURCE_COMPLETE_AND_FRESH", age=30)]
BASE = {"contract": "RR/PROVIDER-APP/RULE-BUNDLE/v1", "bundleId": "RR-SYNTHETIC-PREFLIGHT", "version": 1,
        "scope": "RR-SYNTHETIC-PROVIDER-A",
        "provenance": {"status": "UNAPPROVED_SYNTHETIC_FIXTURE", "issuerReference": "LOCAL-SYNTHETIC-FIXTURE"},
        "issuerReference": "LOCAL-SYNTHETIC-FIXTURE", "publishedAt": "2026-01-01T00:00:00Z",
        "effectiveFrom": "2026-01-01", "effectiveUntil": "2027-01-01", "expiresAt": "2027-01-01T00:00:00Z",
        "withdrawnAt": None, "rules": RULES}


def wire(value):
    return canon(value).encode("ascii")


def upper_hex_escapes(text):
    return re.sub(r"\\u([0-9a-f]{4})", lambda m: "\\u" + m[1].upper(), text)


def files():
    pos, rej = [], []
    b = {**BASE}
    s = wire(sealed(b))

    def bundle(id_, raw, note):
        pos.append((id_, "bundle", raw, note))

    def mapping(id_, raw, note):
        pos.append((id_, "mapping", raw, note))

    bundle("pos-01-template", s, "Minimal accepted bundle in canonical form.")
    bundle("pos-02-pretty-reversed", (json.dumps(dict(reversed(list(sealed(b).items()))), indent=2) + "\n").encode(),
           "Indented, reverse key order, trailing newline: accepted, digest unchanged.")
    bundle("pos-03-escaped-value", s.replace(b'"scope":"R', b'"scope":"\\u0052'),
           "A value written with a \\u escape: same parsed string, same digest.")
    ext = {**b, "version": 65535, "scope": "RR-SYNTHETIC-PROVIDER-B", "withdrawnAt": "2026-06-01T00:00:00Z",
           "rules": [rule(5, "SOURCE_COMPLETE_AND_FRESH", 65535, age=365),
                     rule(4, "CHARGE_CENTS_BETWEEN", 65535, lo=0, hi=100000000),
                     rule(2, "SERVICE_CATEGORY_EQUALS", cat="SYNTH-CATEGORY-B")]}
    bundle("pos-04-upper-bounds", wire(sealed(ext)),
           "Largest version, cents, age; non-default rule order; withdrawnAt set.")
    low = {**b, "rules": [rule(4, "CHARGE_CENTS_BETWEEN", lo=100000000, hi=100000000),
                          rule(5, "SOURCE_COMPLETE_AND_FRESH", age=0)]}
    bundle("pos-05-lower-bounds", wire(sealed(low)), "Zero source age; minimum equals maximum at the cents ceiling.")
    allc = "".join(map(chr, range(0x21)))
    mapping("pos-06-nonascii-raw-utf8", json.dumps(
        {"\u00e9": "\u00e9\u20ac", "emoji": "\U0001f600", "nfc": "\u00e9", "nfd": "e\u0301", "cjk": "\u6f22"},
        ensure_ascii=False).encode("utf-8"), "Raw UTF-8 input; output is \\u escapes (surrogate pair); no NFC folding.")
    mapping("pos-07-escapes-upper-hex-input",
            upper_hex_escapes(json.dumps({"s": allc + '"\\/\x7f\x80\u2028'})).encode("ascii"),
            "Every control char, quote, backslash, solidus, DEL; input hex upper case, output lower case.")
    mapping("pos-08-nested-empty", b'{"a":{},"b":[],"c":[[],[{}]],"d":[[1,[2,[3]]]]}', "Empty containers and nested arrays.")
    mapping("pos-09-integers", b'{"zero":0,"negzero":-0,"neg":-1,"i53":9007199254740993,"u63":9223372036854775808,'
            b'"min":-9223372036854775808,"huge":1000000000000000000000000000000}', "Integers print in full; -0 is 0.")
    mapping("pos-10-key-order", json.dumps({k: 1 for k in ["b", "a", "B", "\U00010000", "_", "\uffff", "", "\u00e9", "10", "9"]}
            ).encode("ascii"), "Keys sort by code point: U+FFFF before U+10000 (UTF-16 order would differ).")
    mapping("pos-11-digest-field", b'{"contentDigest":"junk","a":{"contentDigest":"kept"},"b":1}',
            "Only the top-level contentDigest is dropped.")
    mapping("pos-12-surrogates", b'{"s":"\\ud800","t":"\\udc00\\ud800","u":"\\ud83d\\ude00"}',
            "Lone surrogates survive as lower-case escapes; a valid pair is one scalar, re-escaped as a pair.")
    mapping("pos-13-literals-whitespace", b'{\t"t" :true,\n"f":false , "n":null,"e":{} }', "Literals; JSON whitespace dropped.")
    mapping("pos-14-empty-object", b"{}", "Empty object.")

    def swap(old, new):
        return s.replace(old.encode(), new.encode(), 1)

    def with_digest(digest, **kw):
        return wire(sealed({**b, **kw}, digest))

    hx = hexdigest(b)
    rej += [
        ("rej-01-digest-wrong", with_digest(ZERO), "BUNDLE_DIGEST_MISMATCH", "Well-formed digest that is not the SHA-256."),
        ("rej-02-digest-upper-hex", with_digest("sha256:" + hx.upper()), "BUNDLE_DIGEST_INVALID", "Correct digest in upper-case hex."),
        ("rej-03-digest-no-prefix", with_digest(hx), "BUNDLE_DIGEST_INVALID", "Bare hex without the sha256: prefix."),
        ("rej-04-digest-upper-prefix", with_digest("SHA256:" + hx), "BUNDLE_DIGEST_INVALID", "Prefix in upper case."),
        ("rej-05-digest-null", wire({**b, "contentDigest": None}),
         "BUNDLE_DIGEST_INVALID", "contentDigest present but null."),
        ("rej-06-digest-trailing-newline", with_digest("sha256:" + hx + "\n"), "BUNDLE_DIGEST_INVALID", "72 characters: fails the pattern (the length cap is implied by it)."),
        ("rej-07-digest-missing", wire(b), "BUNDLE_SCHEMA", "contentDigest key absent."),
        ("rej-08-digest-unsorted-keys", with_digest("sha256:" + hexdigest(b, sort_keys=False)), "BUNDLE_DIGEST_MISMATCH",
         "Digest over insertion-order keys instead of sorted keys."),
        ("rej-09-digest-spaced-separators", with_digest("sha256:" + hexdigest(b, separators=(", ", ": "))),
         "BUNDLE_DIGEST_MISMATCH", "Digest over default json.dumps separators."),
        ("rej-10-digest-covers-self", wire({**b, "contentDigest": "sha256:" + hashlib.sha256(wire({**b, "contentDigest": ""})).hexdigest()}),
         "BUNDLE_DIGEST_MISMATCH", "Digest computed with the contentDigest key still in the content."),
        ("rej-11-digest-stale-after-edit", wire({**sealed(b), "version": 2}), "BUNDLE_DIGEST_MISMATCH",
         "A field changed after sealing."),
        ("rej-12-float-1.0", swap('"version":1,', '"version":1.0,'), "JSON_FLOAT_UNSUPPORTED", "1.0 is a float token, refused."),
        ("rej-13-float-exponent", swap('"minimumCents":100,', '"minimumCents":1e2,'), "JSON_FLOAT_UNSUPPORTED", "1e2 is a float token, refused."),
        ("rej-14-nan", swap('"version":1,', '"version":NaN,'), "JSON_CONSTANT_UNSUPPORTED", "NaN refused."),
        ("rej-15-duplicate-key", swap('"version":1,', '"version":1,"version":1,'), "JSON_DUPLICATE_KEY", "Same key twice, same value."),
        ("rej-16-duplicate-key-escaped", swap('"version":1,', '"version":1,"v\\u0065rsion":1,'), "JSON_DUPLICATE_KEY",
         "Duplicates are detected after unescaping."),
        ("rej-17-unknown-field", wire(sealed({**b, "extra": 1})), "BUNDLE_SCHEMA", "Field outside the schema, digest valid over it."),
        ("rej-18-unknown-rule-field", wire(sealed({**b, "rules": [{**RULES[0], "extra": 1}]})), "BUNDLE_RULE_SCHEMA",
         "Rule field outside the schema, digest valid over it."),
        ("rej-19-version-bool", wire(sealed({**b, "version": True})), "BUNDLE_VERSION_INVALID", "true is not an integer."),
        ("rej-20-version-65536", wire(sealed({**b, "version": 65536})), "BUNDLE_VERSION_INVALID", "One above the maximum."),
        ("rej-21-version-negative-zero", swap('"version":1,', '"version":-0,'), "BUNDLE_VERSION_INVALID", "-0 parses to 0, below the minimum."),
        ("rej-22-bom", b"\xef\xbb\xbf" + s, "JSON_INVALID", "UTF-8 byte order mark."),
        ("rej-23-invalid-utf8", s.replace(b"LOCAL-", b"LOCAL\xff", 1), "JSON_INVALID", "Byte 0xFF is not UTF-8."),
        ("rej-24-array-root", b"[" + s + b"]", "JSON_OBJECT_REQUIRED", "Top level is not an object."),
        ("rej-25-depth-9", b'{"x":[[[[[[[[0]]]]]]]]}', "JSON_DEPTH_EXCEEDED", "Nesting depth 9 > 8, before schema checks."),
        ("rej-26-too-large", s + b" " * (16385 - len(s)), "BUNDLE_TOO_LARGE", "16,385 bytes; limit 16,384."),
        ("rej-27-nonascii-scope", wire(sealed({**b, "scope": "RR-SYNTHETIC-PROVIDER-\u00c1"})), "BUNDLE_SCOPE_UNSUPPORTED",
         "Non-ASCII text never reaches a hashed accepted bundle."),
        ("rej-28-rule-error-beats-digest", wire({**b, "version": 65536, "contentDigest": "junk"}), "BUNDLE_VERSION_INVALID",
         "Bad version and bad digest: the rule error wins."),
        ("rej-29-duplicate-then-float", b'{"a":1,"a":2,"b":1.5}', "JSON_FLOAT_UNSUPPORTED",
         "Duplicate fires only when its object closes, after the float is read."),
        ("rej-30-constant-then-float", b'{"a":NaN,"b":1.5}', "JSON_CONSTANT_UNSUPPORTED", "First offending token by position wins."),
        ("rej-31-inner-duplicate-then-float", b'{"o":{"k":1,"k":2},"f":1.5}', "JSON_DUPLICATE_KEY",
         "The inner object closes before the float is read."),
        ("rej-32-integer-4301-digits", b'{"n":' + b"1" * 4301 + b"}", "JSON_INVALID",
         "Beyond the interpreter integer digit limit (4,300)."),
    ]
    out = {}
    index = {"contract": "RR/PROVIDER-DIGEST-VECTORS/v1", "positive": [], "reject": []}
    for id_, kind, raw, note in pos:
        value = json.loads(raw)
        digest = value["contentDigest"] if kind == "bundle" else "sha256:" + hexdigest(value)
        content = {k: v for k, v in value.items() if k != "contentDigest"}
        out[id_ + ".json"] = raw
        index["positive"].append({"id": id_, "kind": kind, "canonical": canon(content), "digest": digest, "note": note})
    for id_, raw, error, note in rej:
        out[id_ + ".json"] = raw
        index["reject"].append({"id": id_, "error": error, "note": note})
    out["cases.json"] = (json.dumps(index, indent=1) + "\n").encode("ascii")
    return out


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
    target.mkdir(parents=True, exist_ok=True)
    for name, data in files().items():
        (target / name).write_bytes(data)
