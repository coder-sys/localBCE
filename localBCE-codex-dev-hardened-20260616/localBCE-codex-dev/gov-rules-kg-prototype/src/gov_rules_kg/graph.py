from __future__ import annotations

import json
from pathlib import Path

import networkx as nx

from .store import Store


def export_graph(store: Store, path: Path) -> dict:
    graph = nx.MultiDiGraph()

    for row in store.rows("entities"):
        graph.add_node(
            row["canonical_key"],
            entity_type=row["entity_type"],
            title=row["title"],
            source_url=row["source_url"],
            fetch_timestamp=row["fetch_timestamp"],
        )

    for row in store.rows("edges"):
        graph.add_edge(
            row["from_key"],
            row["to_key"],
            edge_type=row["edge_type"],
            source_url=row["source_url"],
            evidence=row["evidence"],
            fetch_timestamp=row["fetch_timestamp"],
        )

    data = {
        "nodes": [
            {"id": node, **attrs}
            for node, attrs in graph.nodes(data=True)
        ],
        "edges": [
            {"from": source, "to": target, "key": key, **attrs}
            for source, target, key, attrs in graph.edges(keys=True, data=True)
        ],
        "stats": {"nodes": graph.number_of_nodes(), "edges": graph.number_of_edges()},
    }
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return data["stats"]
