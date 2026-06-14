from __future__ import annotations

import json
from pathlib import Path


def evaluate_gold_set(gold_set_path: Path, extracted_path: Path, output_path: Path) -> dict:
    gold = json.loads(gold_set_path.read_text(encoding="utf-8"))
    extracted_payload = json.loads(extracted_path.read_text(encoding="utf-8")) if extracted_path.exists() else {}
    extracted_rules = flatten_extracted(extracted_payload)
    gold_by_text = {item.get("exact_source_text", "").strip().lower(): item for item in gold if item.get("exact_source_text")}
    extracted_by_text = {item.get("exact_source_text", "").strip().lower(): item for item in extracted_rules if item.get("exact_source_text")}
    matched = set(gold_by_text) & set(extracted_by_text)
    precision = len(matched) / max(1, len(extracted_by_text))
    recall = len(matched) / max(1, len(gold_by_text))
    missing_citation_rate = sum(1 for item in extracted_rules if not item.get("normalized_citation") and not item.get("citation")) / max(1, len(extracted_rules))
    report = {
        "overall_score": int(min(precision, recall) * 10),
        "precision": precision,
        "recall": recall,
        "citation_accuracy": 0.0,
        "state_classification_accuracy": 0.0,
        "federal_state_separation_accuracy": 0.0,
        "rule_family_accuracy": 0.0,
        "rule_type_accuracy": 0.0,
        "condition_action_accuracy": 0.0,
        "hallucination_rate": max(0.0, 1.0 - precision),
        "missing_citation_rate": missing_citation_rate,
        "production_ready": False,
        "blocking_issues": ["Gold-set metrics are present but not yet at production threshold."],
    }
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def flatten_extracted(payload: object) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        rules: list[dict] = []
        for value in payload.values():
            if isinstance(value, list):
                rules.extend(item for item in value if isinstance(item, dict))
        return rules
    return []

