from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .ai import AIOptions, AIProviderError, claude_api_key, extract_json_object
from .domain import GOVERNMENT_RULE_TAXONOMY, RULE_UNIT_TYPES, SOURCE_TYPES, taxonomy_for_prompt

try:
    import httpx
except ImportError:  # pragma: no cover - exercised only in minimal local runtimes
    httpx = None


PLAN_MODE = "ai_hierarchy_planning_only_no_fetch_no_parse_no_crawl"


def build_ai_hierarchy_plan(options: AIOptions) -> dict:
    if options.provider in {"claude", "auto"} and claude_api_key():
        return build_claude_hierarchy_plan(options)
    if options.provider == "claude" and not options.allow_local_stub:
        raise AIProviderError("Claude hierarchy planning selected, but no Claude API key is configured.")
    if not options.allow_local_stub:
        raise AIProviderError("Hierarchy planning needs Claude or --allow-local-stub true for deterministic planning.")
    return build_deterministic_hierarchy_plan(provider_used="local_stub")


def build_deterministic_hierarchy_plan(provider_used: str = "deterministic") -> dict:
    branches = []
    for vertical, programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].items():
        for program in programs:
            branches.append(build_program_branch(vertical, program))
    return {
        "mode": PLAN_MODE,
        "provider_used": provider_used,
        "claim": (
            "This is a planning artifact only. It does not fetch documents, parse HTML, crawl websites, "
            "or create verified rules."
        ),
        "taxonomy": taxonomy_for_prompt(),
        "branch_count": len(branches),
        "branches": branches,
        "verification_contract": verification_contract(),
    }


def build_program_branch(vertical: str, program: str) -> dict:
    readable = program.replace("_", " ")
    return {
        "domain": "government_transaction_rules",
        "vertical": vertical,
        "program": program,
        "program_label": readable.title(),
        "rule_unit_types_to_extract": RULE_UNIT_TYPES,
        "source_types_to_prioritize": SOURCE_TYPES[:-1],
        "ai_extraction_prompt": (
            f"Identify atomic government transaction rules for {readable}. "
            "Organize each rule by rule_unit_type, source_type, jurisdiction, actor, condition, action, "
            "deadline, exception, and enforcement consequence. Do not invent rules. Require exact evidence "
            "from an official source before a rule can become verified."
        ),
        "source_research_prompt": (
            f"Find official statutes, regulations, agency manuals, guidance, forms, instructions, decisions, "
            f"and FAQs that govern {readable}. Prefer machine-readable official sources and stable public records."
        ),
        "verification_prompt": (
            f"For {readable}, mark a rule verified only when it has source_url, normalized_citation, exact_source_text, "
            "confidence_score >= 0.85, and human_review_required is false."
        ),
        "output_schema": {
            "rule_id": "stable id",
            "domain": "government_transaction_rules",
            "vertical": vertical,
            "program": program,
            "jurisdiction_level": "federal|state|county|city|agency_specific",
            "source_type": "one source type",
            "rule_unit_type": "one rule unit type",
            "statement": "one atomic rule",
            "actor": "agency/provider/applicant/recipient/etc.",
            "condition": "when the rule applies",
            "action": "required/permitted/prohibited action",
            "deadline": "deadline if present",
            "exception": "exception if present",
            "enforcement": "penalty/audit/appeal consequence if present",
            "source_url": "required for verified",
            "normalized_citation": "required for verified",
            "exact_source_text": "required for verified",
            "confidence_score": "0..1",
            "verification_status": "planning_only|candidate_extracted|human_review_required|machine_validated_candidate",
        },
    }


def verification_contract() -> dict:
    return {
        "not_verified_in_plan": True,
        "verified_rule_requirements": {
            "source_url": True,
            "normalized_citation": True,
            "exact_source_text": True,
            "human_review_required": False,
            "minimum_confidence_score": 0.85,
            "verification_status": "machine_validated_candidate",
        },
        "forbidden": [
            "Do not mark AI-memory output as verified.",
            "Do not use model memory as evidence.",
            "Do not create source_url or citation fields unless they came from a real official source.",
            "Do not imply every program has verified rules until evidence exists.",
        ],
    }


def build_claude_hierarchy_plan(options: AIOptions) -> dict:
    if httpx is None:
        raise AIProviderError("Claude hierarchy planning selected, but httpx is not installed.")
    api_key = claude_api_key()
    if not api_key:
        raise AIProviderError("Claude hierarchy planning selected, but no Claude API key is configured.")

    deterministic_plan = build_deterministic_hierarchy_plan(provider_used="deterministic_seed")
    prompt = {
        "task": "Create a planning-only government rules knowledge graph hierarchy plan.",
        "constraints": [
            "Do not browse the web.",
            "Do not fetch URLs.",
            "Do not parse HTML.",
            "Do not output verified rules.",
            "Do not claim evidence exists.",
            "Use the provided taxonomy as the coverage target.",
            "Improve prompts, schema guidance, and coverage strategy for every branch.",
        ],
        "mode": PLAN_MODE,
        "taxonomy": taxonomy_for_prompt(),
        "seed_plan": deterministic_plan,
    }
    response = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": options.claude_model,
            "max_tokens": 8192,
            "temperature": 0,
            "system": "You create planning-only structured knowledge graph specifications. You do not browse or claim verification.",
            "tools": [
                {
                    "name": "emit_hierarchy_plan",
                    "description": "Emit a planning-only hierarchy plan. No verified rules.",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "plan": {"type": "object"},
                        },
                        "required": ["plan"],
                    },
                }
            ],
            "tool_choice": {"type": "tool", "name": "emit_hierarchy_plan"},
            "messages": [{"role": "user", "content": json.dumps(prompt, ensure_ascii=False)}],
        },
        timeout=90,
    )
    if response.status_code >= 400:
        raise AIProviderError(f"Claude hierarchy planning error {response.status_code}: {response.text[:1000]}")
    payload = extract_hierarchy_plan_payload(response.json().get("content", []))
    plan = payload.get("plan") if isinstance(payload, dict) else None
    if not isinstance(plan, dict):
        plan = deterministic_plan
    return normalize_hierarchy_plan(plan, options.claude_model)


def extract_hierarchy_plan_payload(content: list[dict]) -> dict:
    for block in content:
        if block.get("type") == "tool_use" and block.get("name") == "emit_hierarchy_plan":
            payload = block.get("input")
            if isinstance(payload, dict):
                return payload
    text = "\n".join(block.get("text", "") for block in content if block.get("type") == "text")
    if not text.strip():
        return {}
    return json.loads(extract_json_object(text))


def normalize_hierarchy_plan(plan: dict[str, Any], model: str) -> dict:
    normalized = build_deterministic_hierarchy_plan(provider_used="claude")
    normalized["model_used"] = model
    if isinstance(plan.get("branches"), list) and len(plan["branches"]) >= normalized["branch_count"]:
        normalized["branches"] = plan["branches"]
        normalized["branch_count"] = len(plan["branches"])
    for key in ["claim", "verification_contract"]:
        if key in plan:
            normalized[key] = plan[key]
    normalized["mode"] = PLAN_MODE
    normalized["provider_used"] = "claude"
    return normalized


def write_ai_hierarchy_plan(workdir: Path, options: AIOptions) -> dict:
    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    plan = build_ai_hierarchy_plan(options)
    json_path = reports_dir / "ai_hierarchy_plan.json"
    markdown_path = reports_dir / "ai_hierarchy_plan.md"
    json_path.write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(write_ai_hierarchy_plan_markdown(plan), encoding="utf-8")
    return {
        "ai_hierarchy_plan": str(json_path),
        "markdown": str(markdown_path),
        "mode": plan["mode"],
        "provider_used": plan.get("provider_used"),
        "branch_count": plan.get("branch_count"),
        "verdict": "AI_HIERARCHY_PLAN_READY",
    }


def write_ai_hierarchy_plan_markdown(plan: dict) -> str:
    lines = [
        "# AI Hierarchy Plan",
        "",
        f"- mode: {plan.get('mode')}",
        f"- provider_used: {plan.get('provider_used')}",
        f"- branch_count: {plan.get('branch_count')}",
        "",
        "## Verification Contract",
        "",
        "This plan does not create verified rules. A rule is verified only after source URL, exact source text, normalized citation, confidence, and review checks pass.",
        "",
        "## Branches",
    ]
    for branch in plan.get("branches", [])[:200]:
        lines.append("")
        lines.append(f"### {branch.get('vertical')} / {branch.get('program')}")
        lines.append("")
        lines.append(f"- rule_unit_types: {', '.join(branch.get('rule_unit_types_to_extract', []))}")
        lines.append(f"- source_types: {', '.join(branch.get('source_types_to_prioritize', []))}")
        lines.append(f"- extraction_prompt: {branch.get('ai_extraction_prompt', '')}")
    return "\n".join(lines)
