from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ai import AIOptions, AIProviderError, claude_api_key, extract_json_object
from .domain import GOVERNMENT_RULE_TAXONOMY, RULE_UNIT_TYPES, SOURCE_TYPES, taxonomy_for_prompt

try:
    import httpx
except ImportError:  # pragma: no cover - exercised only in minimal local runtimes
    httpx = None


RESEARCH_MODE = "claude_server_web_search_no_local_fetch_no_local_parse"
DEFAULT_ALLOWED_DOMAINS = [
    "cms.gov",
    "medicaid.gov",
    "medicare.gov",
    "ssa.gov",
    "irs.gov",
    "fns.usda.gov",
    "hud.gov",
    "acf.hhs.gov",
    "dol.gov",
    "uscis.gov",
    "travel.state.gov",
    "studentaid.gov",
    "ed.gov",
    "va.gov",
    "sam.gov",
    "grants.gov",
    "acquisition.gov",
    "ecfr.gov",
    "govinfo.gov",
    "federalregister.gov",
    "justice.gov",
    "hhs.gov",
    "epa.gov",
    "usa.gov",
    "e-verify.gov",
]


@dataclass(frozen=True)
class ClaudeWebResearchOptions:
    ai_options: AIOptions
    max_branches: int = 5
    max_uses: int = 10
    max_candidates_per_branch: int = 3
    allowed_domains: list[str] | None = None


def build_claude_web_research(options: ClaudeWebResearchOptions) -> dict:
    if options.ai_options.provider not in {"claude", "auto"}:
        if not options.ai_options.allow_local_stub:
            raise AIProviderError("Claude web research requires --ai-provider claude or --allow-local-stub true.")
        return deterministic_web_research_plan(options)
    if not claude_api_key():
        if options.ai_options.allow_local_stub:
            return deterministic_web_research_plan(options)
        raise AIProviderError("Claude web research selected, but no Claude API key is configured.")
    return call_claude_web_search(options)


def deterministic_web_research_plan(options: ClaudeWebResearchOptions) -> dict:
    branches = taxonomy_branches(options.max_branches)
    return {
        "mode": RESEARCH_MODE,
        "provider_used": "local_stub",
        "claim": "Planning preview only. No local fetching, local parsing, bs4, crawler, or scraper was used.",
        "branch_count": len(branches),
        "allowed_domains": options.allowed_domains or DEFAULT_ALLOWED_DOMAINS,
        "branches": branches,
        "candidate_rules": [],
        "verification_warning": "No candidate is verified until evidence, citation, and review gates pass.",
    }


def call_claude_web_search(options: ClaudeWebResearchOptions) -> dict:
    if httpx is None:
        raise AIProviderError("Claude web research selected, but httpx is not installed.")
    api_key = claude_api_key()
    if not api_key:
        raise AIProviderError("Claude web research selected, but no Claude API key is configured.")

    branches = taxonomy_branches(options.max_branches)
    allowed_domains = options.allowed_domains or DEFAULT_ALLOWED_DOMAINS
    prompt = {
        "task": "Use Claude server-side web search to research official government transaction rules and organize them into a hierarchy.",
        "strict_constraints": [
            "You must run at least one web_search before producing the final JSON.",
            "Use Claude web_search only. The local application must not fetch URLs, parse HTML, crawl links, or scrape pages.",
            "Prefer official government sources from the allowed domains.",
            f"Return at most {options.max_candidates_per_branch} high-confidence candidates per branch.",
            "Return compact JSON only. Do not use markdown fences.",
            "Return candidates, not verified rules.",
            "Every candidate must include source_url, source_title, citation_text if available, and a confidence score.",
            "If web search cannot support a candidate with a cited official source, do not output it.",
            "Do not rely on model memory as evidence.",
        ],
        "mode": RESEARCH_MODE,
        "branches_to_research": branches,
        "taxonomy": taxonomy_for_prompt(),
        "rule_unit_types": RULE_UNIT_TYPES,
        "source_types": SOURCE_TYPES,
        "output_schema": {
            "candidate_rules": [
                {
                    "domain": "government_transaction_rules",
                    "vertical": "taxonomy vertical",
                    "program": "taxonomy program",
                    "jurisdiction_level": "federal|state|county|city|agency_specific|unknown",
                    "source_type": "source type",
                    "rule_unit_type": "rule unit type",
                    "statement": "one atomic rule candidate",
                    "source_url": "official cited source URL",
                    "source_title": "official source title",
                    "citation_text": "short cited text from Claude web search citation",
                    "confidence_score": "0..1",
                    "verification_status": "claude_web_grounded_candidate",
                }
            ],
            "coverage_notes": ["gaps and next searches"],
        },
    }

    response = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": options.ai_options.claude_model,
            "max_tokens": 8192,
            "temperature": 0,
            "system": (
                "You are a government rules research agent. Use only the provided server-side web_search tool "
                "for current web research. Return strict JSON text after searching. Do not claim verification."
            ),
            "tools": [
                {
                    "type": "web_search_20250305",
                    "name": "web_search",
                    "max_uses": options.max_uses,
                    "allowed_domains": allowed_domains,
                },
            ],
            "messages": [
                {
                    "role": "user",
                    "content": (
                        json.dumps(prompt, ensure_ascii=False)
                        + "\n\nReturn only compact JSON with keys candidate_rules and coverage_notes. Do not wrap it in markdown fences."
                    ),
                }
            ],
        },
        timeout=120,
    )
    if response.status_code >= 400:
        raise AIProviderError(f"Claude web research error {response.status_code}: {response.text[:1000]}")

    content = response.json().get("content", [])
    payload = extract_web_research_payload(content)
    candidate_rules = normalize_candidate_rules(payload.get("candidate_rules", []))
    return {
        "mode": RESEARCH_MODE,
        "provider_used": "claude_web_search",
        "model_used": options.ai_options.claude_model,
        "branch_count": len(branches),
        "allowed_domains": allowed_domains,
        "candidate_rule_count": len(candidate_rules),
        "candidate_rules": candidate_rules,
        "coverage_notes": payload.get("coverage_notes", []),
        "raw_usage": response.json().get("usage", {}),
        "verification_warning": "These are web-grounded candidates, not verified rules.",
    }


def extract_web_research_payload(content: list[dict]) -> dict:
    for block in content:
        if block.get("type") == "tool_use" and block.get("name") == "emit_web_research":
            payload = block.get("input")
            if isinstance(payload, dict):
                return payload
    text = "\n".join(block.get("text", "") for block in content if block.get("type") == "text")
    if not text.strip():
        return {"candidate_rules": [], "coverage_notes": ["Claude returned no structured web research payload."]}
    try:
        return json.loads(extract_json_from_text(text))
    except Exception as exc:
        salvaged = salvage_candidate_rules_from_text(text)
        if salvaged:
            return {
                "candidate_rules": salvaged,
                "coverage_notes": [
                    f"Claude returned partial JSON; salvaged {len(salvaged)} complete candidate rule objects.",
                    f"Parse error: {exc}",
                ],
            }
        return {
            "candidate_rules": [],
            "coverage_notes": [
                "Claude web search completed but did not return parseable JSON.",
                text[:2000],
            ],
        }


def salvage_candidate_rules_from_text(text: str) -> list[dict]:
    marker = '"candidate_rules"'
    marker_index = text.find(marker)
    if marker_index == -1:
        return []
    array_start = text.find("[", marker_index)
    if array_start == -1:
        return []

    candidates: list[dict] = []
    index = array_start + 1
    while index < len(text):
        object_start = text.find("{", index)
        if object_start == -1:
            break
        try:
            object_text = extract_balanced_json_object(text[object_start:])
        except ValueError:
            break
        try:
            candidate = json.loads(object_text)
        except json.JSONDecodeError:
            break
        if isinstance(candidate, dict):
            candidates.append(candidate)
        index = object_start + len(object_text)
    return candidates


def extract_json_from_text(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```\s*$", "", stripped)
    try:
        return extract_json_object(stripped)
    except ValueError:
        return extract_balanced_json_object(stripped)


def extract_balanced_json_object(text: str) -> str:
    start = text.find("{")
    if start == -1:
        raise ValueError("Claude response did not contain a JSON object")
    depth = 0
    in_string = False
    escape = False
    for index in range(start, len(text)):
        char = text[index]
        if escape:
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise ValueError("Claude response JSON object was incomplete")


def normalize_candidate_rules(raw_rules: Any) -> list[dict]:
    if not isinstance(raw_rules, list):
        return []
    normalized: list[dict] = []
    for item in raw_rules:
        if not isinstance(item, dict):
            continue
        source_url = str(item.get("source_url") or "").strip()
        statement = str(item.get("statement") or "").strip()
        if not source_url or not statement:
            continue
        item = dict(item)
        item["verification_status"] = "claude_web_grounded_candidate"
        item["mode"] = RESEARCH_MODE
        normalized.append(item)
    return normalized


def taxonomy_branches(max_branches: int) -> list[dict]:
    branches: list[dict] = []
    for vertical, programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].items():
        for program in programs:
            branches.append(
                {
                    "domain": "government_transaction_rules",
                    "vertical": vertical,
                    "program": program,
                    "search_goal": f"Official government rules for {program.replace('_', ' ')}",
                }
            )
            if max_branches > 0 and len(branches) >= max_branches:
                return branches
    return branches


def write_claude_web_research(workdir: Path, options: ClaudeWebResearchOptions) -> dict:
    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report = build_claude_web_research(options)
    json_path = reports_dir / "claude_web_research.json"
    markdown_path = reports_dir / "claude_web_research.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(write_claude_web_research_markdown(report), encoding="utf-8")
    return {
        "claude_web_research": str(json_path),
        "markdown": str(markdown_path),
        "mode": report["mode"],
        "provider_used": report["provider_used"],
        "candidate_rule_count": report.get("candidate_rule_count", 0),
        "verdict": "CLAUDE_WEB_RESEARCH_READY",
    }


def write_claude_web_research_markdown(report: dict) -> str:
    lines = [
        "# Claude Web Research",
        "",
        f"- mode: {report.get('mode')}",
        f"- provider_used: {report.get('provider_used')}",
        f"- candidate_rule_count: {report.get('candidate_rule_count', len(report.get('candidate_rules', [])))}",
        "",
        "These are Claude web-search grounded candidates, not verified rules.",
        "The local app did not fetch URLs, parse HTML, crawl links, or use bs4 for this command.",
        "",
        "## Candidate Rules",
    ]
    for rule in report.get("candidate_rules", [])[:200]:
        lines.extend(
            [
                "",
                f"### {rule.get('program', 'unknown')} / {rule.get('rule_unit_type', 'unknown')}",
                "",
                f"- statement: {rule.get('statement', '')}",
                f"- source: {rule.get('source_url', '')}",
                f"- citation_text: {rule.get('citation_text', '')}",
                f"- status: {rule.get('verification_status', '')}",
            ]
        )
    notes = report.get("coverage_notes", [])
    if notes:
        lines.extend(["", "## Coverage Notes", ""])
        for note in notes:
            lines.append(f"- {note}")
    return "\n".join(lines)
