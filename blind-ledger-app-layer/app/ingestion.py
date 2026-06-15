from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass
class Parsed837:
    raw: str
    segments: List[List[str]]
    accepted: bool
    errors: List[str]


def parse_837(raw_edi: str) -> Parsed837:
    raw = (raw_edi or "").strip()
    errors: List[str] = []
    if not raw:
        return Parsed837(raw=raw, segments=[], accepted=False, errors=["empty_edi"])
    segments = []
    for segment in raw.split("~"):
        segment = segment.strip()
        if not segment:
            continue
        segments.append(segment.split("*"))
    tags = [seg[0] for seg in segments if seg]
    for required in ["ISA", "GS", "ST", "BHT", "CLM", "NM1", "SV1", "SE", "GE", "IEA"]:
        if required not in tags:
            errors.append(f"missing_{required}")
    tag_counts = Counter(tags)
    for unique_tag in ["ISA", "GS", "ST", "BHT", "CLM", "SE", "GE", "IEA"]:
        if tag_counts[unique_tag] > 1:
            errors.append(f"duplicate_{unique_tag}")
    if not any(seg[0] == "ST" and len(seg) > 1 and seg[1] == "837" for seg in segments):
        errors.append("not_837_transaction")
    clm_segments = [seg for seg in segments if seg and seg[0] == "CLM"]
    bht_segments = [seg for seg in segments if seg and seg[0] == "BHT"]
    if clm_segments and bht_segments and len(clm_segments[0]) > 1 and len(bht_segments[0]) > 3:
        if clm_segments[0][1] != bht_segments[0][3]:
            errors.append("claim_id_mismatch_BHT_CLM")
    if not any(seg[0] == "DTP" and len(seg) > 3 and seg[1] == "472" and seg[3].strip() for seg in segments):
        errors.append("missing_service_date")
    for seg in segments:
        if not seg:
            continue
        if seg[0] == "CLM" and len(seg) > 2 and not _finite_number(seg[2]):
            errors.append("invalid_CLM_amount")
        if seg[0] == "SV1":
            if len(seg) > 2 and not _finite_number(seg[2]):
                errors.append("invalid_SV1_amount")
            if len(seg) <= 4 or not _finite_number(seg[4]):
                errors.append("invalid_SV1_units")
            elif float(seg[4]) <= 0:
                errors.append("invalid_SV1_units")
    return Parsed837(raw=raw, segments=segments, accepted=not errors, errors=errors)


def _finite_number(value: str) -> bool:
    try:
        return math.isfinite(float(value))
    except (TypeError, ValueError):
        return False


def segment_map(parsed: Parsed837) -> Dict[str, List[List[str]]]:
    out: Dict[str, List[List[str]]] = {}
    for seg in parsed.segments:
        if seg:
            out.setdefault(seg[0], []).append(seg)
    return out


def validate_837(raw_edi: str) -> Tuple[bool, List[str]]:
    parsed = parse_837(raw_edi)
    return parsed.accepted, parsed.errors
