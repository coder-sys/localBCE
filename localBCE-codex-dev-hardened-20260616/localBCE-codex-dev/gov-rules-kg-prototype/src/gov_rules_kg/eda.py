from __future__ import annotations

import json
from collections import Counter

from .store import Store


def build_eda_summary(store: Store) -> dict:
    entity_types = Counter(row["entity_type"] for row in store.rows("entities"))
    edge_types = Counter(row["edge_type"] for row in store.rows("edges"))
    docs_per_status = Counter(row["status"] for row in store.rows("fetch_log"))
    atomic_rule_types: Counter[str] = Counter()
    for row in store.rows("entities"):
        if row["entity_type"] != "atomic_rule":
            continue
        metadata = json.loads(row["metadata_json"])
        atomic_rule_types.update(metadata.get("rule_types") or ["uncategorized"])

    return {
        "entity_type_distribution": dict(entity_types),
        "edge_type_distribution": dict(edge_types),
        "fetch_status_distribution": dict(docs_per_status),
        "atomic_rule_type_distribution": dict(atomic_rule_types),
    }
