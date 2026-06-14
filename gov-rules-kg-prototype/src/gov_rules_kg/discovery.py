from __future__ import annotations

import json
import hashlib
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .access import assert_core_dependencies, phase0_access_check
from .ai import AIOptions, AIProviderError, AIUsage, organize_atomic_rules, summarize_with_attribution
from .citations import parse_citations
from .compliance import extract_compliance_requirements
from .config import RunConfig
from .domain import build_state_space, classify_family_and_type, classify_government_hierarchy, federal_space, infer_jurisdiction, normalize_condition_action, stable_rule_id, valid_program, valid_vertical, vertical_for_program
from .eda import build_eda_summary
from .extract import extract_text, is_low_quality_document
from .fetcher import PoliteFetcher, canonicalize_url
from .graph import export_graph
from .merge_gate import propose_merge_candidates
from .ontology import classify_text, infer_entity_type, relevance_score
from .reports import write_production_reports
from .store import Entity, Store


@dataclass
class QueueItem:
    url: str
    depth: int
    parent_key: str | None = None


def canonical_entity_key(entity_type: str, url: str, title: str) -> str:
    safe_title = "-".join(title.lower().split())[:80]
    return f"{entity_type}:{canonicalize_url(url)}:{safe_title}"


class DiscoveryEngine:
    def __init__(self, config: RunConfig) -> None:
        self.config = config
        self.store = Store(config.db_path)
        self.fetcher = PoliteFetcher(config, self.log_progress)
        self.visited: set[str] = set()
        self.host_counts: Counter[str] = Counter()
        self.stop_condition = "not_started"
        self.ai_samples: list[dict] = []
        self.run_id = datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
        self.extracted_rule_sections = 0
        self.relevant_rule_sections = 0
        self.atomic_rule_units = 0
        self.skipped_low_quality_documents = 0
        self.rule_type_counts: Counter[str] = Counter()
        self.initial_atomic_rule_keys = {
            row["canonical_key"]
            for row in self.store.rows("entities")
            if row["entity_type"] == "atomic_rule"
        }
        self.current_run_atomic_rule_keys: set[str] = set()
        self.ai_options = AIOptions(
            provider=config.ai_provider,
            claude_model=config.claude_model,
            claude_max_sections=config.claude_max_sections,
            allow_local_stub=config.allow_local_stub,
            fail_on_ai_fallback=config.fail_on_ai_fallback,
        )
        self.ai_usage = AIUsage(provider_requested=config.ai_provider, model_requested=config.claude_model)

    def close(self) -> None:
        self.fetcher.close()

    def run(self) -> dict:
        phase0 = run_phase0_for_mode(self.config)
        if phase0["overall"] != "REACHABLE":
            report = {
                "verdict": "STOPPED_PHASE0_BLOCKED",
                "phase0": phase0,
                "message": "Core live sources are blocked; recursive discovery did not run.",
            }
            self.write_report(report)
            return report

        queue: deque[QueueItem] = deque(
            QueueItem(source.url, 0, None)
            for source in self.config.seeds
            if source.discovery_seed
            if source.name not in phase0["blocked_required_sources"]
        )

        processed = 0
        max_depth_reached = 0

        while queue:
            if processed >= self.config.global_doc_cap:
                self.stop_condition = "global_doc_cap"
                break

            item = queue.popleft()
            canonical_url = canonicalize_url(item.url)
            host = urlparse(canonical_url).netloc

            if canonical_url in self.visited:
                continue
            if item.depth > self.config.max_depth:
                self.stop_condition = "depth_cap"
                continue
            if self.host_counts[host] >= self.config.per_host_cap:
                self.stop_condition = "host_cap"
                self.store.fetch_logged(canonical_url, "SKIPPED_HOST_CAP", host)
                continue

            self.visited.add(canonical_url)
            self.host_counts[host] += 1
            processed += 1
            max_depth_reached = max(max_depth_reached, item.depth)

            self.log_progress(
                {
                    "event": "document_started",
                    "url": canonical_url,
                    "depth": item.depth,
                    "processed_documents": processed,
                    "queue_size": len(queue),
                    "visited_urls": len(self.visited),
                }
            )
            fetch = self.fetcher.fetch(canonical_url)
            self.store.fetch_logged(canonical_url, fetch.status, fetch.detail)
            self.log_progress(
                {
                    "event": "fetch_completed",
                    "url": fetch.canonical_url,
                    "status": fetch.status,
                    "status_code": fetch.status_code,
                    "content_type": fetch.content_type,
                    "bytes": len(fetch.body),
                    "detail": fetch.detail,
                    "attempts": fetch.attempts,
                }
            )

            if fetch.status != "FETCHED":
                self.store.upsert_document(
                    fetch.canonical_url,
                    fetch.url,
                    fetch.status,
                    fetch.content_type,
                    fetch.content_hash,
                    "",
                    {"detail": fetch.detail, "status_code": fetch.status_code},
                )
                continue

            extracted = extract_text(fetch.canonical_url, fetch.content_type, fetch.body, self.config.document_parser)
            if is_low_quality_document(extracted):
                self.skipped_low_quality_documents += 1
                self.store.fetch_logged(fetch.canonical_url, "SKIPPED_LOW_QUALITY", ",".join(extracted.extractor_notes))
                self.store.upsert_document(
                    fetch.canonical_url,
                    fetch.url,
                    "SKIPPED_LOW_QUALITY",
                    fetch.content_type,
                    fetch.content_hash,
                    extracted.text[:2000],
                    {
                        "extractor_notes": extracted.extractor_notes,
                        "rule_sections_extracted": len(extracted.rule_sections),
                    },
                )
                self.log_progress(
                    {
                        "event": "document_skipped",
                        "reason": "low_quality_document",
                        "url": fetch.canonical_url,
                        "depth": item.depth,
                        "notes": extracted.extractor_notes,
                    }
                )
                continue

            entity_type = infer_entity_type(extracted.title, fetch.canonical_url, extracted.text)
            jurisdiction_level, state_code = infer_jurisdiction(fetch.canonical_url, extracted.text, self.config.include_states)
            source_quality = source_quality_object(
                fetch.canonical_url,
                fetch.status,
                fetch.content_type,
                jurisdiction_level,
                state_code,
                extracted.extractor_notes,
                len(extracted.rule_sections),
                len(extracted.citations),
            )
            classification = classify_text(extracted.text)
            document_relevance = relevance_score(extracted.text)
            requirements = extract_compliance_requirements(extracted.text)
            key = canonical_entity_key(entity_type, fetch.canonical_url, extracted.title)

            metadata = {
                "classification": classification,
                "relevance": document_relevance,
                "citations": extracted.citations,
                "compliance_requirements": requirements,
                "extractor_notes": extracted.extractor_notes,
                "rule_sections_extracted": len(extracted.rule_sections),
                "source_quality": source_quality,
                        "domain": self.config.domain,
                        "vertical": self.config.vertical,
                        "program": self.config.program,
                        "run_id": self.run_id,
                        "jurisdiction_level": jurisdiction_level,
                        "state_code": state_code,
            }

            self.store.upsert_document(
                fetch.canonical_url,
                fetch.url,
                fetch.status,
                fetch.content_type,
                fetch.content_hash,
                extracted.text,
                metadata,
            )
            self.store.upsert_entity(
                Entity(
                    canonical_key=key,
                    entity_type=entity_type,
                    title=extracted.title,
                    source_url=fetch.canonical_url,
                    text=extracted.text,
                    metadata=metadata,
                )
            )

            if item.parent_key:
                self.store.add_edge(item.parent_key, key, "cites_or_discovers", fetch.canonical_url, "recursive link")

            for citation in extracted.citations:
                cited_key = f"citation:{citation.lower()}"
                self.store.upsert_entity(
                    Entity(
                        canonical_key=cited_key,
                        entity_type="citation",
                        title=citation,
                        source_url=fetch.canonical_url,
                        text=citation,
                        metadata={"source_document": key},
                    )
                )
                self.store.add_edge(key, cited_key, "cites", fetch.canonical_url, citation)

            sections_to_process = extracted.rule_sections[: self.config.max_rule_sections_per_document]
            self.log_progress(
                {
                    "event": "sections_detected",
                    "url": fetch.canonical_url,
                    "sections_detected": len(extracted.rule_sections),
                    "sections_to_process": len(sections_to_process),
                    "max_rule_sections_per_document": self.config.max_rule_sections_per_document,
                }
            )
            for section_index, section in enumerate(sections_to_process, start=1):
                self.extracted_rule_sections += 1
                if self.config.progress_every_sections > 0 and (
                    section_index == 1 or section_index % self.config.progress_every_sections == 0
                ):
                    self.log_progress(
                        {
                            "event": "section_progress",
                            "url": fetch.canonical_url,
                            "section_index": section_index,
                            "sections_to_process": len(sections_to_process),
                            "relevant_rule_sections_total": self.relevant_rule_sections,
                            "atomic_rule_units_total": self.atomic_rule_units,
                        }
                    )
                section_relevance = relevance_score(section.text)
                if not section_relevance["relevant"]:
                    continue

                self.relevant_rule_sections += 1
                section_key = canonical_rule_section_key(fetch.canonical_url, section.section_id, section.title)
                section_metadata = {
                    "section_id": section.section_id,
                    "source_kind": section.source_kind,
                    "classification": classify_text(section.text),
                    "relevance": section_relevance,
                    "citations": section.citations,
                    "parsed_citations": [citation.to_dict() for citation in parse_citations(section.text)],
                    "domain": self.config.domain,
                    "vertical": self.config.vertical,
                    "program": self.config.program,
                    "jurisdiction_level": jurisdiction_level,
                    "state_code": state_code,
                    "state_space_id": f"{self.config.program}:state:{state_code}" if state_code else None,
                    "federal_space_id": f"{self.config.program}:federal",
                }
                self.store.upsert_entity(
                    Entity(
                        canonical_key=section_key,
                        entity_type="rule_section",
                        title=section.title,
                        source_url=fetch.canonical_url,
                        text=section.text,
                        metadata=section_metadata,
                    )
                )
                self.store.add_edge(key, section_key, "contains_rule_section", fetch.canonical_url, section.title)

                for citation in section.citations:
                    cited_key = f"citation:{citation.lower()}"
                    self.store.upsert_entity(
                        Entity(
                            canonical_key=cited_key,
                            entity_type="citation",
                            title=citation,
                            source_url=fetch.canonical_url,
                            text=citation,
                            metadata={"source_rule_section": section_key},
                        )
                    )
                    self.store.add_edge(section_key, cited_key, "cites", fetch.canonical_url, citation)

                try:
                    rule_units = organize_atomic_rules(
                        section.title,
                        section.text,
                        fetch.canonical_url,
                        self.ai_options,
                        self.relevant_rule_sections - 1,
                    )
                except AIProviderError as exc:
                    self.ai_usage.sections_failed += 1
                    self.ai_usage.error_count += 1
                    self.ai_usage.errors.append(str(exc))
                    raise

                for rule_unit in rule_units:
                    self.atomic_rule_units += 1
                    enriched_rule = enrich_atomic_rule(
                        rule_unit,
                        section_key,
                        section.section_id,
                        section.title,
                        section.text,
                        fetch.canonical_url,
                        self.config.domain,
                        self.config.vertical,
                        self.config.program,
                        self.run_id,
                        jurisdiction_level,
                        state_code,
                    )
                    if enriched_rule["extraction_method"] == "llm":
                        self.ai_usage.sections_processed += 1
                        self.ai_usage.provider_used = "claude"
                        self.ai_usage.model_used = self.config.claude_model
                    self.rule_type_counts.update([enriched_rule["rule_type"], *enriched_rule.get("secondary_tags", [])])
                    unit_key = canonical_atomic_rule_key(section_key, enriched_rule["normalized_rule"])
                    self.current_run_atomic_rule_keys.add(unit_key)
                    self.store.upsert_entity(
                        Entity(
                            canonical_key=unit_key,
                            entity_type="atomic_rule",
                            title=enriched_rule["normalized_rule"][:160],
                            source_url=fetch.canonical_url,
                            text=enriched_rule["normalized_rule"],
                            metadata=enriched_rule,
                        )
                    )
                    self.store.add_edge(
                        section_key,
                        unit_key,
                        "has_atomic_rule",
                        fetch.canonical_url,
                        ",".join([enriched_rule["rule_family"], enriched_rule["rule_type"]]),
                    )

            for requirement in requirements[:10]:
                req_key = f"requirement:{key}:{abs(hash(requirement['statement']))}"
                self.store.upsert_entity(
                    Entity(
                        canonical_key=req_key,
                        entity_type="compliance_requirement",
                        title=requirement["statement"][:120],
                        source_url=fetch.canonical_url,
                        text=requirement["statement"],
                        metadata=requirement,
                    )
                )
                self.store.add_edge(key, req_key, "has_requirement", fetch.canonical_url, requirement["statement"])

            if len(self.ai_samples) < 5:
                self.ai_samples.append(summarize_with_attribution(extracted.title, extracted.text, fetch.canonical_url))

            if item.depth < self.config.max_depth:
                for link in extracted.links[:100]:
                    if should_enqueue(link):
                        queue.append(QueueItem(link, item.depth + 1, key))

            self.log_progress(
                {
                    "event": "document_processed",
                    "url": fetch.canonical_url,
                    "depth": item.depth,
                    "title": extracted.title[:120],
                    "rule_sections": len(extracted.rule_sections),
                    "relevant_rule_sections_total": self.relevant_rule_sections,
                    "atomic_rule_units_total": self.atomic_rule_units,
                    "queue_size": len(queue),
                }
            )
            self.store.checkpoint(
                "latest",
                {
                    "processed": processed,
                    "queue_size": len(queue),
                    "visited": len(self.visited),
                    "max_depth_reached": max_depth_reached,
                },
            )

        if self.stop_condition == "not_started":
            self.stop_condition = "no_new_entities" if not queue else "completed"

        rule_inventory = self.build_rule_inventory()
        if self.config.report_mode == "light":
            graph_stats = {"nodes": None, "edges": None, "skipped": "report_mode_light"}
            merge_candidates = []
            rules_by_type = {"skipped": "report_mode_light"}
            production_reports = self.write_light_reports(rule_inventory)
        else:
            graph_stats = export_graph(self.store, self.config.reports_dir / "graph.json")
            merge_candidates = propose_merge_candidates(self.store)
            rules_by_type = self.write_rules_by_type_reports()
            production_reports = write_production_reports(
                self.store,
                self.config.reports_dir,
                self.ai_usage.to_report(),
                {
                    "domain": self.config.domain,
                    "vertical": self.config.vertical,
                    "program": self.config.program,
                    "federal_space": federal_space(self.config.domain, self.config.vertical, self.config.program),
                    "state_spaces": [build_state_space(state, self.config.domain, self.config.vertical, self.config.program).to_dict() for state in self.config.include_states],
                },
                merge_candidates,
                rule_inventory,
            )
        report = {
            "verdict": "FUNCTIONS_END_TO_END",
            "working_dir": str(self.config.workdir),
            "recursion_stats": {
                "processed_documents": processed,
                "visited_urls": len(self.visited),
                "max_depth_reached": max_depth_reached,
                "stop_condition": self.stop_condition,
                "docs_per_source_host": dict(self.host_counts),
                "rule_sections_extracted": self.extracted_rule_sections,
                "relevant_rule_sections": self.relevant_rule_sections,
                "atomic_rule_units": self.atomic_rule_units,
                "rule_inventory": rule_inventory,
                "skipped_low_quality_documents": self.skipped_low_quality_documents,
                "atomic_rule_type_counts": dict(self.rule_type_counts),
                **self.store.stats(),
            },
            "classification_summary": build_eda_summary(self.store),
            "organized_rule_reports": rules_by_type,
            "production_reports": production_reports,
            "graph_size": graph_stats,
            "entity_merge_gate": {
                "status": "REVIEW_REQUIRED_BEFORE_MASS_MERGE",
                "sample_size": len(merge_candidates),
                "proposed_merges": merge_candidates,
            },
            "ai_layer": {**self.ai_usage.to_report(), "claude_max_sections": self.config.claude_max_sections, "samples": self.ai_samples},
        }
        self.write_report(report)
        return report

    def write_report(self, report: dict) -> None:
        self.config.reports_dir.mkdir(parents=True, exist_ok=True)
        (self.config.reports_dir / "run_report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (self.config.reports_dir / "demo_transcript.md").write_text(
            demo_transcript(report),
            encoding="utf-8",
        )

    def log_progress(self, event: dict) -> None:
        print(json.dumps(event, sort_keys=True), flush=True)

    def write_rules_by_type_reports(self) -> dict:
        grouped: dict[str, list[dict]] = {}
        for row in self.store.rows("entities"):
            if row["entity_type"] != "atomic_rule":
                continue
            metadata = json.loads(row["metadata_json"])
            rule_types = metadata.get("rule_types") or [metadata.get("rule_type") or "uncategorized"]
            for rule_type in rule_types:
                grouped.setdefault(rule_type, []).append(
                    {
                        "statement": row["text"],
                        "source_url": row["source_url"],
                        "citation": metadata.get("citation"),
                        "confidence": metadata.get("confidence"),
                        "extraction_method": metadata.get("extraction_method"),
                    }
                )

        self.config.reports_dir.mkdir(parents=True, exist_ok=True)
        json_path = self.config.reports_dir / "rules_by_type.json"
        json_path.write_text(json.dumps(grouped, indent=2, sort_keys=True), encoding="utf-8")

        md_lines = ["# Rules By Type", ""]
        for rule_type, rules in sorted(grouped.items()):
            md_lines.extend([f"## {rule_type}", ""])
            for rule in rules[:100]:
                md_lines.append(f"- {rule['statement']}")
                if rule.get("source_url"):
                    md_lines.append(f"  Source: {rule['source_url']}")
            if len(rules) > 100:
                md_lines.append(f"- ... {len(rules) - 100} more in rules_by_type.json")
            md_lines.append("")

        md_path = self.config.reports_dir / "rules_by_type.md"
        md_path.write_text("\n".join(md_lines), encoding="utf-8")
        return {
            "json": str(json_path),
            "markdown": str(md_path),
            "rule_types": {rule_type: len(rules) for rule_type, rules in sorted(grouped.items())},
        }

    def write_light_reports(self, rule_inventory: dict) -> dict:
        self.config.reports_dir.mkdir(parents=True, exist_ok=True)
        inventory_path = self.config.reports_dir / "rule_inventory.json"
        inventory_path.write_text(json.dumps(rule_inventory, indent=2, sort_keys=True), encoding="utf-8")
        return {
            "mode": "light",
            "rule_inventory": str(inventory_path),
            "message": "Heavy graph/type/audit reports skipped. Run `python -m gov_rules_kg.main proof-report` or rerun without --bulk-ingest to generate full reports.",
        }

    def build_rule_inventory(self) -> dict:
        all_atomic_rule_keys = {
            row["canonical_key"]
            for row in self.store.rows("entities")
            if row["entity_type"] == "atomic_rule"
        }
        new_keys = self.current_run_atomic_rule_keys - self.initial_atomic_rule_keys
        reseen_keys = self.current_run_atomic_rule_keys & self.initial_atomic_rule_keys
        out_of_scope_keys = all_atomic_rule_keys - self.current_run_atomic_rule_keys
        legacy_keys = {
            row["canonical_key"]
            for row in self.store.rows("entities")
            if row["entity_type"] == "atomic_rule"
            and not json.loads(row["metadata_json"]).get("run_id")
        }
        return {
            "run_id": self.run_id,
            "current_run_atomic_rules": len(self.current_run_atomic_rule_keys),
            "current_run_rule_units_attempted": self.atomic_rule_units,
            "new_atomic_rules_added": len(new_keys),
            "updated_or_reseen_atomic_rules": len(reseen_keys),
            "total_graph_atomic_rules": len(all_atomic_rule_keys),
            "rules_excluded_from_current_scope": len(out_of_scope_keys),
            "legacy_or_unversioned_atomic_rules": len(legacy_keys),
        }


def should_enqueue(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    blocked_extensions = (".jpg", ".jpeg", ".png", ".gif", ".zip", ".exe", ".css", ".js")
    return not parsed.path.lower().endswith(blocked_extensions)


def run_phase0_for_mode(config: RunConfig) -> dict:
    if config.phase0_mode == "skip":
        assert_core_dependencies()
        return {
            "working_dir": str(config.workdir),
            "overall": "REACHABLE",
            "blocked_required_sources": [],
            "source_verdicts": [],
            "egress_ip": None,
            "message": "Phase 0 source access checks skipped by --phase0-mode skip; core dependencies checked.",
        }
    if config.phase0_mode == "required":
        required_sources = [source for source in config.seeds if source.required]
        return phase0_access_check(config, sources=required_sources)
    return phase0_access_check(config)


def canonical_rule_section_key(source_url: str, section_id: str, title: str) -> str:
    digest = hashlib.sha256(f"{source_url}|{section_id}|{title}".encode("utf-8")).hexdigest()[:16]
    safe_section = "-".join(section_id.lower().split())[:40] or "section"
    return f"rule_section:{safe_section}:{digest}"


def canonical_atomic_rule_key(section_key: str, statement: str) -> str:
    digest = hashlib.sha256(f"{section_key}|{statement}".encode("utf-8")).hexdigest()[:20]
    return f"atomic_rule:{digest}"


def source_quality_object(
    url: str,
    fetch_status: str,
    content_type: str | None,
    jurisdiction_level: str,
    state_code: str | None,
    extractor_notes: list[str],
    sections_detected: int,
    citations_detected: int,
) -> dict:
    lowered_url = url.lower()
    source_type = "unknown"
    if "ecfr.gov" in lowered_url or "govinfo.gov" in lowered_url:
        source_type = "ecfr_xml"
    elif "medicaid.gov" in lowered_url:
        source_type = "medicaid_html"
    elif "dhcs.ca.gov" in lowered_url:
        source_type = "agency_guidance"
    elif "leginfo" in lowered_url:
        source_type = "state_code"
    elif "calregs" in lowered_url:
        source_type = "state_admin_code"
    elif "pdf" in (content_type or "").lower() or lowered_url.endswith(".pdf"):
        source_type = "pdf"

    problems = [note for note in extractor_notes if note.startswith("low_quality_")]
    text_quality_score = 0.95 if not problems and sections_detected else 0.65 if not problems else 0.35
    return {
        "url": url,
        "source_type": source_type,
        "jurisdiction_level": jurisdiction_level,
        "state_code": state_code,
        "program": "medicaid",
        "fetch_status": fetch_status,
        "text_quality_score": text_quality_score,
        "parser_used": ",".join(note for note in extractor_notes if note.endswith("_text") or note.endswith("_ok")),
        "sections_detected": sections_detected,
        "tables_detected": 0,
        "citations_detected": citations_detected,
        "rules_detected": 0,
        "problems": problems,
    }


def enrich_atomic_rule(
    rule_unit: dict,
    section_key: str,
    section_id: str,
    section_heading: str,
    section_text: str,
    source_url: str,
    domain: str,
    vertical: str,
    program: str,
    run_id: str,
    jurisdiction_level: str,
    state_code: str | None,
) -> dict:
    statement = rule_unit["statement"]
    hierarchy = classify_government_hierarchy(statement, source_url, domain, vertical, program)
    resolved_program = valid_program(rule_unit.get("program")) or hierarchy["program"]
    resolved_vertical = valid_vertical(rule_unit.get("vertical")) or vertical_for_program(resolved_program) or hierarchy["vertical"]
    resolved_source_type = rule_unit.get("source_type") or hierarchy["source_type"]
    resolved_rule_unit_type = rule_unit.get("rule_unit_type") or hierarchy["rule_unit_type"]
    citations = parse_citations(f"{section_heading} {statement}") or parse_citations(section_text)
    primary_citation = citations[0].normalized_citation if citations else None
    family, rule_type, tags = classify_family_and_type(statement)
    normalized = statement
    condition_action = normalize_condition_action(statement)
    confidence = float(rule_unit.get("confidence", 0.6))
    if not citations:
        confidence = min(confidence, 0.7)
    if condition_action["human_review_required"]:
        confidence = min(confidence, 0.74)
    human_review_required = confidence < 0.75 or not citations or condition_action["human_review_required"]
    review_reasons = []
    if confidence < 0.75:
        review_reasons.append("confidence_score below 0.75")
    if not citations:
        review_reasons.append("missing citation")
    if condition_action["human_review_required"]:
        review_reasons.append(condition_action["human_review_reason"])
    if rule_unit.get("human_review_required") and rule_unit.get("human_review_reason"):
        review_reasons.append(str(rule_unit["human_review_reason"]))
    human_review_required = human_review_required or bool(rule_unit.get("human_review_required"))
    extraction_method = "llm" if rule_unit.get("mode") == "claude" else "deterministic"
    verification_status = (
        "human_review_required"
        if human_review_required
        else "machine_validated_candidate"
        if confidence >= 0.85 and primary_citation
        else "candidate_extracted"
    )
    rule_id = stable_rule_id(source_url, section_id, primary_citation or "", statement)
    state_space_id = f"{resolved_program}:state:{state_code}" if jurisdiction_level == "state" and state_code else None
    return {
        "rule_id": rule_id,
        "domain": domain,
        "vertical": resolved_vertical,
        "program": resolved_program,
        "source_type": resolved_source_type,
        "rule_unit_type": resolved_rule_unit_type,
        "hierarchy_path": [
            domain,
            resolved_vertical,
            resolved_program,
            jurisdiction_level,
            resolved_source_type,
            resolved_rule_unit_type,
        ],
        "run_id": run_id,
        "jurisdiction_level": jurisdiction_level,
        "state_code": state_code if jurisdiction_level == "state" else None,
        "state_space_id": state_space_id,
        "federal_space_id": f"{resolved_program}:federal",
        "source_url": source_url,
        "source_document_id": source_url,
        "citation": primary_citation,
        "normalized_citation": primary_citation,
        "parsed_citations": [citation.to_dict() for citation in citations],
        "section_id": section_id,
        "section_heading": section_heading,
        "paragraph_path": None,
        "exact_source_text": rule_unit.get("attribution", {}).get("evidence") or statement,
        "normalized_rule": normalized,
        "statement": normalized,
        "rule_family": family,
        "rule_type": rule_type,
        "secondary_tags": tags,
        **condition_action,
        "cross_references": [],
        "related_federal_rules": [],
        "related_state_rules": [],
        "confidence_score": confidence,
        "confidence": confidence,
        "extraction_method": extraction_method,
        "verification_status": verification_status,
        "human_review_required": human_review_required,
        "human_review_reason": "; ".join(reason for reason in review_reasons if reason),
    }


def demo_transcript(report: dict) -> str:
    return "\n".join(
        [
            "# Demo Transcript",
            "",
            f"Verdict: {report.get('verdict')}",
            "",
            "## Recursion Stats",
            "",
            "```json",
            json.dumps(report.get("recursion_stats", {}), indent=2, sort_keys=True),
            "```",
            "",
            "## Graph",
            "",
            "```json",
            json.dumps(report.get("graph_size", {}), indent=2, sort_keys=True),
            "```",
            "",
            "## AI Layer",
            "",
            f"Mode: {report.get('ai_layer', {}).get('mode', 'not_run')}",
        ]
    )
