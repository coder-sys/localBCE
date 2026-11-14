"""Deterministic generator of the RR/GATE/SEGMENT/v1 conformance vectors (conformance/SEGMENT_V1.md).

python tools/gen_segment_v1_vectors.py [DEST]  (default conformance/vectors/segment_v1). Synthetic, non-PHI, nonpayment."""
import hashlib, json, random, shutil, sys, tempfile
from pathlib import Path
from unittest import mock


def authority():
    from app.right_rail_financial_owner import SyntheticTrustedAuthority, _checker_authority
    return _checker_authority(SyntheticTrustedAuthority())


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def D(*parts):
    h = hashlib.sha3_512(b"RR/GATE/SEGMENT/v1\x00")
    for p in parts:
        h.update(len(p).to_bytes(8, "big") + p)
    return h.hexdigest().upper()


class Clock:
    t = 1_700_000_000_000

    def now_ms(self):
        self.t += 1
        return self.t


def build(dest, commands, seal_events, size=1):
    """A real owner export: setup, then `commands` payments, evidence and evaluations; sealed every `seal_events` events."""
    import app.right_rail_financial_owner as owner_module
    from app.right_rail_financial_owner import FinancialOwner, FinancialOwnerConfig, SyntheticTrustedAuthority
    from tests.instruments.load_synthetic import _SCOPE, _setup

    authority = SyntheticTrustedAuthority()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp, mock.patch.object(owner_module, "_SEAL_SEGMENT_EVENTS", seal_events):
        with FinancialOwner(path=Path(tmp) / "o.sqlite3", config=FinancialOwnerConfig(**_SCOPE), trusted_authority=authority, clock=Clock()) as owner:
            items = [i.item_id for i in _setup(owner, random.Random(1), size, authority)] if commands else []
            for n in range(commands):
                item = items[n % size]
                (lambda: owner.record_payment_evidence(item_id=item, payment_id=f"payment:{n}", common_origin_id=f"origin:{n}", amount_cents=100 + n, evidence_id=f"evidence:payment:{n}", event_at_ms=1_000 + n),
                 lambda: owner.record_support_evidence(item_id=item, evidence_id=f"evidence:support:{n}", common_origin_id=f"origin:support:{n}"),
                 lambda: owner.evaluate_obligation(item))[n % 3]()
            owner.export_history(dest)


def load(directory):
    manifest = json.loads((directory / "manifest.json").read_bytes())
    return manifest, [json.loads((directory / f"segment-{i:08d}.json").read_bytes()) for i in range(manifest["segment_count"])]


def expected(directory):
    manifest, segs = load(directory)
    return {"sequence": manifest["meta"]["sequence"], "manifest_digest": manifest["manifest_digest"], "last_segment_digest": manifest["last_segment_digest"],
            "segments": [{"segment_digest": s["segment_digest"], "projection_root": s["seal"]["projection_root"], "event_head": s["seal"]["event_head"], "first_sequence": s["seal"]["first_sequence"], "last_sequence": s["seal"]["last_sequence"]} for s in segs]}


def flip(text):
    return text[:-1] + ("1" if text[-1] == "0" else "0")


def rehash(manifest, **changes):
    body = {k: v for k, v in {**manifest, **changes}.items() if k != "manifest_digest"}
    return {**body, "manifest_digest": D(b"manifest", canon(body))}


# (name, rule broken, refusal, mutation): the mutation edits (manifest, segments) in place, may return raw file bytes
# by name (None drops the file), and a manifest returned under "manifest.json" replaces the edited one.
def cases(manifest, segs):
    seal = segs[1]["seal"]

    def set_seal(key, value):
        return lambda: seal.__setitem__(key, value)

    def swap():
        segs[1]["rows"][0], segs[1]["rows"][1] = segs[1]["rows"][1], segs[1]["rows"][0]

    def file1(raw):
        return lambda: {"segment-00000001.json": raw}

    def manifest_file(raw):
        return lambda: {"manifest.json": raw}

    def bad_record(record):
        return lambda: segs[1]["rows"].__setitem__(0, record)

    signature = lambda raw: file1(canon(segs[1])[:-len(b"null}")] + raw + b"}")  # "signature" is the last key of a canonical segment
    swap_in = lambda old, new: file1(canon(segs[1]).replace(old, new, 1))

    return [
        ("flip_segment_digest", "segment_digest = D('seal', canonical seal), one hex digit flipped", "history:segment:1:digest", lambda: segs[1].__setitem__("segment_digest", flip(segs[1]["segment_digest"]))),
        ("flip_projection_root", "projection_root = D('rows', canonical rows), one hex digit flipped in the seal", "history:segment:1:seal", set_seal("projection_root", flip(seal["projection_root"]))),
        ("flip_event_head", "seal.event_head is the head of the segment's last event", "history:segment:1:seal", set_seal("event_head", flip(seal["event_head"]))),
        ("flip_manifest_digest", "manifest_digest = D('manifest', canonical body), one hex digit flipped", "history:manifest-digest", lambda: {"manifest.json": canon({**manifest, "manifest_digest": flip(manifest["manifest_digest"])})}),
        ("flip_last_segment_digest", "manifest.last_segment_digest is the last segment_digest (manifest re-hashed)", "history:manifest-binding", lambda: {"manifest.json": canon(rehash(manifest, last_segment_digest=flip(manifest["last_segment_digest"])))}),
        ("chain_break_previous_digest", "seal.previous_digest is the previous segment_digest", "history:segment:1:seal", set_seal("previous_digest", "0" * 128)),
        ("event_count_mismatch", "event_count = last_sequence - first_sequence + 1", "history:segment:1:seal", set_seal("event_count", seal["event_count"] + 1)),
        ("first_sequence_gap", "first_sequence = previous last_sequence + 1", "history:segment:1:seal", set_seal("first_sequence", seal["first_sequence"] + 1)),
        ("last_sequence_gap", "last_sequence = first_sequence + number of events - 1", "history:segment:1:seal", set_seal("last_sequence", seal["last_sequence"] + 1)),
        ("duplicate_segment_index", "each segment has its own events: segment 0 repeated as segment 1", "history:sequence", lambda: segs.__setitem__(1, segs[0])),
        ("segment_index_wrong", "seal.segment_index is the file's position", "history:segment:1:seal", set_seal("segment_index", 0)),
        ("unsorted_rows", "rows are sorted by their canonical JSON bytes", "history:segment:1:records", swap),
        ("duplicate_row", "one final image per row", "history:segment:1:records", lambda: segs[1]["rows"].append(segs[1]["rows"][-1])),
        ("signature_not_null", "signature is reserved and null in v1 (outside every digest)", "history:segment:1:shape", lambda: segs[1].__setitem__("signature", "00")),
        ("float_number", "no JSON float", "history:segment:1:float", file1(canon(segs[1]).replace(b'"event_count":%d' % seal["event_count"], b'"event_count":%d.0' % seal["event_count"]))),
        ("noncanonical_whitespace", "a file is exactly its canonical JSON bytes: no whitespace", "history:segment:1:noncanonical", file1(json.dumps(segs[1], sort_keys=True, separators=(", ", ": ")).encode())),
        ("noncanonical_key_order", "a file is exactly its canonical JSON bytes: keys sorted", "history:segment:1:noncanonical", file1(json.dumps(dict(reversed(segs[1].items())), separators=(",", ":")).encode())),
        ("duplicate_json_key", "no duplicate JSON object key", "json:duplicate-key", file1(canon(segs[1])[:-1] + b',"signature":null}')),
        ("over_bound_segment_count", "segment_count <= 10,000 (manifest re-hashed)", "history:segment-count", lambda: {"manifest.json": canon(rehash(manifest, segment_count=10_001))}),
        ("missing_segment_file", "every segment file 0..segment_count-1 exists", "history:segment:2:read", lambda: {"segment-00000002.json": None}),
        ("manifest_empty", "manifest size is 1..1,048,576 bytes", "history:manifest:bytes", manifest_file(b"")),
        ("manifest_non_ascii", "manifest bytes are ASCII", "history:manifest:ascii", manifest_file(canon(manifest)[:-1] + b',"x":"\xc3\xa9"}')),
        ("manifest_unparseable", "manifest is JSON", "history:manifest:parse", manifest_file(b"{")),
        ("manifest_integer_bounds", "integers are -2^63..2^63-1", "history:manifest:bounds", manifest_file(canon({**manifest, "segment_count": 1 << 63}))),
        ("manifest_extra_key", "manifest keys are exactly the six of section 5", "history:manifest", manifest_file(canon({**manifest, "extra": 0}))),
        ("meta_row_id", "meta.id is 1 (manifest re-hashed)", "history:meta", lambda: {"manifest.json": canon(rehash(manifest, meta={**manifest["meta"], "id": 2}))}),
        ("record_not_object", "a rows record is an object", "history:segment:1:record", bad_record(5)),
        ("record_unknown_table", "a rows record names a projection table", "history:segment:1:record", bad_record({"table": "nope", "row": {}})),
        ("rows_not_list", "rows is a list", "history:segment:1:shape", lambda: segs[1].__setitem__("rows", {})),
        ("events_not_list", "events is a list", "continuity:rows:financial_events", lambda: segs[1].__setitem__("events", {})),
        ("json_escaped_slash", "slash is written bare, never escaped", "history:segment:1:noncanonical", swap_in(b"RR/GATE", rb"RR\/GATE")),
        ("json_escaped_ascii_letter", "a printable ASCII character is never a unicode escape", "history:segment:1:noncanonical", swap_in(b"RR/GATE", rb"\u0052R/GATE")),
        ("json_uppercase_unicode_escape", "unicode escape hex digits are lowercase", "history:segment:1:noncanonical", signature(rb'"\u00E9"')),
        ("json_raw_non_ascii", "a file is ASCII: non-ASCII is escaped, never raw UTF-8", "history:segment:1:ascii", signature(b'"\xc3\xa9"')),
        ("json_non_ascii_value", "lowercase escapes and a surrogate pair parse as canonical, but no v1 field holds such text", "history:segment:1:shape", signature(rb'"\u00e9\ud83d\ude00"')),
        ("json_negative_zero", "-0 is not canonical (0)", "history:segment:1:noncanonical", swap_in(b'"segment_index":1', b'"segment_index":-0')),
        ("json_leading_zero", "no leading zeros", "history:segment:1:parse", swap_in(b'"segment_index":1', b'"segment_index":01')),
    ]


def negatives(base, out):
    index = []
    for position in range(len(cases(*load(base)))):
        manifest, segs = load(base)
        name, rule, refusal, mutate = cases(manifest, segs)[position]
        files = mutate() or {}
        target = out / name
        target.mkdir()
        files.setdefault("manifest.json", canon(manifest))
        for i, seg in enumerate(segs):
            files.setdefault(f"segment-{i:08d}.json", canon(seg))
        delete = sorted(file for file, raw in files.items() if raw is None)
        if delete:  # git tracks no empty directory, so a deletion is a tracked file
            (target / "delete.json").write_bytes(canon(delete))
        for file, raw in files.items():
            if raw is not None and raw != (base / file).read_bytes():  # an overlay: only the files that differ from the base chain
                (target / file).write_bytes(raw)
        index.append({"name": name, "rule": rule, "refusal": refusal})
    return index


def main(dest):
    dest = Path(dest)
    shutil.rmtree(dest, ignore_errors=True)
    for name, commands, seal in (("segment0_only", 3, 4096), ("mid_chain", 3, 2), ("empty_history", 0, 8)):
        build(dest / "positive" / name, commands, seal)
        (dest / "positive" / name / "expected.json").write_bytes(canon(expected(dest / "positive" / name)))
    (dest / "negative").mkdir()
    index = negatives(dest / "positive" / "mid_chain", dest / "negative")
    (dest / "index.json").write_bytes(canon({"format": "RR/GATE/SEGMENT/v1", "trusted_authority": authority(), "negative_base": "positive/mid_chain", "negative": index}))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "conformance" / "vectors" / "segment_v1")
