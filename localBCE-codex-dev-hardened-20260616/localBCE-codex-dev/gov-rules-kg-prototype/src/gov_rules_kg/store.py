from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Entity:
    canonical_key: str
    entity_type: str
    title: str
    source_url: str
    text: str
    metadata: dict


class Store:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            create table if not exists documents (
                id integer primary key,
                canonical_url text unique not null,
                source_url text not null,
                status text not null,
                content_type text,
                content_hash text,
                fetched_at text not null,
                text text,
                metadata_json text not null
            );

            create table if not exists entities (
                id integer primary key,
                canonical_key text unique not null,
                entity_type text not null,
                title text not null,
                source_url text not null,
                fetch_timestamp text not null,
                text text not null,
                metadata_json text not null
            );

            create table if not exists edges (
                id integer primary key,
                from_key text not null,
                to_key text not null,
                edge_type text not null,
                source_url text not null,
                fetch_timestamp text not null,
                evidence text not null,
                unique(from_key, to_key, edge_type, source_url)
            );

            create table if not exists fetch_log (
                id integer primary key,
                url text not null,
                status text not null,
                detail text not null,
                fetched_at text not null
            );

            create table if not exists checkpoints (
                key text primary key,
                value_json text not null,
                updated_at text not null
            );

            create table if not exists merge_candidates (
                id integer primary key,
                left_key text not null,
                right_key text not null,
                confidence real not null,
                evidence_json text not null,
                status text not null default 'PROPOSED',
                created_at text not null
            );

            create table if not exists audit_log (
                id integer primary key,
                action text not null,
                target_key text not null,
                source_url text,
                detail_json text not null,
                created_at text not null
            );
            """
        )
        self.conn.commit()

    def upsert_document(
        self,
        canonical_url: str,
        source_url: str,
        status: str,
        content_type: str | None,
        content_hash: str | None,
        text: str,
        metadata: dict,
    ) -> None:
        self.conn.execute(
            """
            insert into documents
                (canonical_url, source_url, status, content_type, content_hash, fetched_at, text, metadata_json)
            values (?, ?, ?, ?, ?, ?, ?, ?)
            on conflict(canonical_url) do update set
                status=excluded.status,
                content_type=excluded.content_type,
                content_hash=excluded.content_hash,
                fetched_at=excluded.fetched_at,
                text=excluded.text,
                metadata_json=excluded.metadata_json
            """,
            (
                canonical_url,
                source_url,
                status,
                content_type,
                content_hash,
                utc_now(),
                text,
                json.dumps(metadata, sort_keys=True),
            ),
        )
        self.conn.commit()

    def upsert_entity(self, entity: Entity) -> None:
        self.conn.execute(
            """
            insert into entities
                (canonical_key, entity_type, title, source_url, fetch_timestamp, text, metadata_json)
            values (?, ?, ?, ?, ?, ?, ?)
            on conflict(canonical_key) do update set
                entity_type=excluded.entity_type,
                title=excluded.title,
                source_url=excluded.source_url,
                fetch_timestamp=excluded.fetch_timestamp,
                text=excluded.text,
                metadata_json=excluded.metadata_json
            """,
            (
                entity.canonical_key,
                entity.entity_type,
                entity.title,
                entity.source_url,
                utc_now(),
                entity.text,
                json.dumps(entity.metadata, sort_keys=True),
            ),
        )
        self.audit("upsert_entity", entity.canonical_key, entity.source_url, entity.metadata)
        self.conn.commit()

    def add_edge(self, from_key: str, to_key: str, edge_type: str, source_url: str, evidence: str) -> None:
        self.conn.execute(
            """
            insert or ignore into edges
                (from_key, to_key, edge_type, source_url, fetch_timestamp, evidence)
            values (?, ?, ?, ?, ?, ?)
            """,
            (from_key, to_key, edge_type, source_url, utc_now(), evidence),
        )
        self.conn.commit()

    def fetch_logged(self, url: str, status: str, detail: str) -> None:
        self.conn.execute(
            "insert into fetch_log (url, status, detail, fetched_at) values (?, ?, ?, ?)",
            (url, status, detail, utc_now()),
        )
        self.conn.commit()

    def checkpoint(self, key: str, value: dict) -> None:
        self.conn.execute(
            """
            insert into checkpoints (key, value_json, updated_at) values (?, ?, ?)
            on conflict(key) do update set value_json=excluded.value_json, updated_at=excluded.updated_at
            """,
            (key, json.dumps(value, sort_keys=True), utc_now()),
        )
        self.conn.commit()

    def audit(self, action: str, target_key: str, source_url: str | None, detail: dict) -> None:
        self.conn.execute(
            "insert into audit_log (action, target_key, source_url, detail_json, created_at) values (?, ?, ?, ?, ?)",
            (action, target_key, source_url, json.dumps(detail, sort_keys=True), utc_now()),
        )

    def stats(self) -> dict:
        return {
            "documents": self.conn.execute("select count(*) from documents").fetchone()[0],
            "entities": self.conn.execute("select count(*) from entities").fetchone()[0],
            "edges": self.conn.execute("select count(*) from edges").fetchone()[0],
            "needs_manual": self.conn.execute(
                "select count(*) from fetch_log where status = 'NEEDS_MANUAL'"
            ).fetchone()[0],
        }

    def rows(self, table: str) -> list[sqlite3.Row]:
        allowed = {"documents", "entities", "edges", "fetch_log"}
        if table not in allowed:
            raise ValueError(f"unsupported table: {table}")
        return list(self.conn.execute(f"select * from {table}"))
