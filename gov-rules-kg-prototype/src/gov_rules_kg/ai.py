from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .domain import SOURCE_TYPES, taxonomy_for_prompt

try:
    import httpx
except ImportError:  # pragma: no cover - exercised only in minimal local runtimes
    httpx = None


RULE_SENTENCE_PATTERN = re.compile(
    r"(?<=[.;:])\s+|(?<=\))\s+(?=[A-Z])"
)

RULE_MARKERS = {
    "obligation": ["shall", "must", "is required to", "are required to", "will"],
    "prohibition": ["shall not", "must not", "may not", "prohibited", "not permitted"],
    "permission": ["may", "is permitted", "are permitted", "authorized"],
    "definition": ["means", "defined as", "refers to"],
    "eligibility": ["eligible", "eligibility", "qualify", "beneficiary", "recipient"],
    "reporting": ["report", "submit", "notify", "notice", "statement"],
    "documentation": ["record", "documentation", "document", "maintain"],
    "enforcement": ["penalty", "sanction", "enforce", "violation", "civil money"],
}


@dataclass(frozen=True)
class AIOptions:
    provider: str = "local"
    claude_model: str = "claude-sonnet-4-6"
    claude_max_sections: int = 0
    allow_local_stub: bool = False
    fail_on_ai_fallback: bool = True


@dataclass
class AIUsage:
    provider_requested: str
    provider_used: str = "none"
    model_requested: str | None = None
    model_used: str | None = None
    fallback_used: bool = False
    sections_processed: int = 0
    sections_failed: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_estimate: float = 0.0
    error_count: int = 0
    errors: list[str] = field(default_factory=list)

    def to_report(self) -> dict:
        return {
            "ai_provider_requested": self.provider_requested,
            "ai_provider_used": self.provider_used,
            "model_requested": self.model_requested,
            "model_used": self.model_used,
            "ai_fallback_used": self.fallback_used,
            "ai_sections_processed": self.sections_processed,
            "ai_sections_failed": self.sections_failed,
            "ai_token_usage": {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
            },
            "ai_cost_estimate": self.cost_estimate,
            "ai_error_count": self.error_count,
            "ai_errors": self.errors,
        }


class AIProviderError(RuntimeError):
    pass


def summarize_with_attribution(title: str, text: str, source_url: str) -> dict:
    sentences = [s.strip() for s in text.replace("\n", " ").split(".") if s.strip()]
    summary = ". ".join(sentences[:3])
    if summary:
        summary += "."
    return {
        "mode": "deterministic_summary",
        "summary": summary or f"No summary text extracted for {title}.",
        "source_url": source_url,
        "note": "Deterministic extractive summary; not used for atomic rule generation.",
    }


def organize_atomic_rules(
    section_title: str,
    section_text: str,
    source_url: str,
    options: AIOptions | None = None,
    section_index: int = 0,
) -> list[dict]:
    """Extract AI-ready atomic rules from a legal section.

    Claude is opt-in because bulk extraction can become expensive. The local
    deterministic organizer remains the fallback so crawls stay resumable.
    """

    selected = options or AIOptions()
    if should_use_claude(selected, section_index):
        claude_rules = organize_atomic_rules_with_claude(section_title, section_text, source_url, selected)
        if claude_rules:
            return claude_rules

    if selected.provider == "claude" and not selected.allow_local_stub:
        return build_review_required_rule(
            section_title,
            section_text,
            source_url,
            "Claude was not used for this section because the configured Claude section cap was reached.",
            mode="claude_cap_review_required",
        )
    return organize_atomic_rules_locally(section_title, section_text, source_url)


def should_use_claude(options: AIOptions, section_index: int) -> bool:
    if options.provider not in {"claude", "auto"}:
        return False
    if not claude_api_key():
        return False
    if options.claude_max_sections > 0 and section_index >= options.claude_max_sections:
        return False
    return True


def organize_atomic_rules_locally(section_title: str, section_text: str, source_url: str) -> list[dict]:
    units: list[dict] = []
    seen: set[str] = set()
    for chunk in split_rule_sentences(section_text):
        labels = classify_rule_unit(chunk)
        if not labels:
            continue
        normalized = normalize_space(chunk)
        if len(normalized) < 40:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        units.append(
            {
                "mode": "local_ai_organizer",
                "statement": normalized,
                "rule_types": labels,
                "section_title": section_title,
                "source_url": source_url,
                "confidence": min(0.95, 0.45 + 0.1 * len(labels)),
                "attribution": {
                    "source_url": source_url,
                    "section_title": section_title,
                    "evidence": normalized[:500],
                },
            }
        )
    return units


def organize_atomic_rules_with_claude(
    section_title: str,
    section_text: str,
    source_url: str,
    options: AIOptions,
) -> list[dict]:
    api_key = claude_api_key()
    if not api_key:
        return []
    if httpx is None:
        raise AIProviderError("Claude provider selected, but httpx is not installed. Aborting extraction.")

    prompt = {
        "task": "Review the provided official source document section and extract grounded atomic government rule units.",
        "role": "You are a legal rules analyst. Treat the section_text as the only document you are allowed to read.",
        "instructions": [
            "Return only valid JSON.",
            "Do not browse, infer from the URL, use outside knowledge, or invent rules.",
            "Every rule must be directly supported by the provided section_text.",
            "If a rule is not visible in section_text, do not output it.",
            "If the section is mostly navigation, boilerplate, index text, or cross-reference-only text, return an empty rules array.",
            "Split compound legal text into atomic obligations, prohibitions, permissions, definitions, eligibility rules, reporting rules, documentation rules, and enforcement rules.",
            "Each atomic rule should contain one legal requirement, permission, prohibition, definition, exception, deadline, payment rule, appeal rule, or enforcement consequence.",
            "Classify each rule into the closest hierarchy path from the provided government_rule_taxonomy.",
            "Use null for vertical/program only when the section text is genuinely outside the taxonomy.",
            "Preserve attribution. Include a short exact evidence excerpt copied from section_text for every rule.",
            "Prefer precise legal actors and actions, such as agency, state, provider, applicant, recipient, plan, or CMS.",
            "Exclude navigation, boilerplate, copyright, menus, unrelated web page text, and generic summaries.",
            "Use confidence below 0.75 when evidence is indirect, incomplete, or requires human review.",
        ],
        "grounding_contract": {
            "allowed_inputs": ["section_title", "section_text", "source_url_as_metadata_only"],
            "forbidden_inputs": ["external web search", "model memory", "assumptions from source_url"],
            "evidence_requirement": "The evidence field must be an exact excerpt from section_text.",
        },
        "government_rule_taxonomy": taxonomy_for_prompt(),
        "json_schema": {
            "rules": [
                {
                    "statement": "string",
                    "vertical": "string|null",
                    "program": "string|null",
                    "source_type": "string",
                    "rule_unit_type": "string",
                    "rule_types": ["obligation|prohibition|permission|definition|eligibility|reporting|documentation|enforcement"],
                    "confidence": "number 0..1",
                    "evidence": "short exact excerpt from section text",
                }
            ]
        },
        "source_url": source_url,
        "section_title": section_title,
        "section_text": section_text[:120_000],
    }

    try:
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
                "system": (
                    "You extract structured legal and policy rules from provided document text. "
                    "You do not browse URLs or rely on outside knowledge. Return strict JSON through the tool only."
                ),
                "tools": [
                    {
                        "name": "emit_rules",
                        "description": "Emit grounded atomic legal rules extracted from the provided source section.",
                        "input_schema": {
                            "type": "object",
                            "properties": {
                                "rules": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "statement": {"type": "string"},
                                            "vertical": {"type": ["string", "null"]},
                                            "program": {"type": ["string", "null"]},
                                            "source_type": {
                                                "type": "string",
                                                "enum": SOURCE_TYPES,
                                            },
                                            "rule_unit_type": {"type": "string"},
                                            "rule_types": {
                                                "type": "array",
                                                "items": {
                                                    "type": "string",
                                                    "enum": [
                                                        "obligation",
                                                        "prohibition",
                                                        "permission",
                                                        "definition",
                                                        "eligibility",
                                                        "reporting",
                                                        "documentation",
                                                        "enforcement",
                                                        "payment",
                                                        "appeal",
                                                        "exception",
                                                        "cross_reference_only",
                                                    ],
                                                },
                                            },
                                            "confidence": {"type": "number"},
                                            "evidence": {"type": "string"},
                                        },
                                        "required": ["statement", "rule_types", "confidence", "evidence"],
                                    },
                                }
                            },
                            "required": ["rules"],
                        },
                    }
                ],
                "tool_choice": {"type": "tool", "name": "emit_rules"},
                "messages": [
                    {
                        "role": "user",
                        "content": json.dumps(prompt, ensure_ascii=False),
                    }
                ],
            },
            timeout=90,
        )
        if response.status_code >= 400:
            raise AIProviderError(f"Claude API error {response.status_code}: {response.text[:1000]}")
        content = response.json().get("content", [])
        payload = extract_payload_from_content(content)
    except AIProviderError:
        raise
    except Exception as exc:
        return build_review_required_rule(
            section_title,
            section_text,
            source_url,
            f"Claude response could not be parsed: {exc}",
            mode="claude_parse_review_required",
        )

    rules = normalize_claude_rules(payload, section_title, source_url, options.claude_model, section_text)
    if rules:
        return rules
    return build_review_required_rule(
        section_title,
        section_text,
        source_url,
        "Claude returned no usable atomic rules for this section.",
        mode="claude_empty_review_required",
    )


def extract_json_object(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.lower().startswith("json"):
            stripped = stripped[4:].strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("Claude response did not contain a JSON object")
    return stripped[start : end + 1]


def extract_payload_from_content(content: list[dict]) -> dict:
    payload = extract_tool_payload(content)
    if payload is not None:
        return payload
    text = "\n".join(block.get("text", "") for block in content if block.get("type") == "text")
    return json.loads(extract_json_object(text))


def extract_tool_payload(content: list[dict]) -> dict | None:
    for block in content:
        if block.get("type") == "tool_use" and block.get("name") == "emit_rules":
            payload = block.get("input")
            if isinstance(payload, dict):
                return payload
    return None


def normalize_claude_rules(
    payload: Any,
    section_title: str,
    source_url: str,
    model: str,
    source_text: str = "",
) -> list[dict]:
    raw_rules: Any
    if isinstance(payload, dict):
        raw_rules = payload.get("rules", [])
    elif isinstance(payload, list):
        raw_rules = payload
    elif isinstance(payload, str):
        raw_rules = [payload]
    else:
        raw_rules = []

    rules: list[dict] = []
    for item in raw_rules:
        if isinstance(item, str):
            item = {
                "statement": item,
                "rule_types": classify_rule_unit(item) or ["obligation"],
                "confidence": 0.6,
                "evidence": item,
            }
        if not isinstance(item, dict):
            continue

        statement = normalize_space(str(item.get("statement", "")))
        if len(statement) < 20:
            continue
        raw_types = item.get("rule_types", [])
        if isinstance(raw_types, str):
            raw_types = [raw_types]
        rule_types = [str(value) for value in raw_types if str(value)]
        confidence = item.get("confidence", 0.7)
        evidence = normalize_space(str(item.get("evidence", "")))[:500]
        evidence = evidence or statement[:500]
        evidence_grounded = evidence_matches_source(evidence, source_text) if source_text else True
        human_review_required = not evidence_grounded
        human_review_reason = "" if evidence_grounded else "Claude evidence excerpt was not found in the provided source text."
        if human_review_required:
            confidence = min(clamp_confidence(confidence, default=0.7), 0.65)
        rules.append(
            {
                "mode": "claude",
                "model": model,
                "statement": statement,
                "vertical": clean_optional_string(item.get("vertical")),
                "program": clean_optional_string(item.get("program")),
                "source_type": clean_optional_string(item.get("source_type")),
                "rule_unit_type": clean_optional_string(item.get("rule_unit_type")),
                "rule_types": rule_types or classify_rule_unit(statement) or ["obligation"],
                "section_title": section_title,
                "source_url": source_url,
                "confidence": clamp_confidence(confidence, default=0.7),
                "human_review_required": human_review_required,
                "human_review_reason": human_review_reason,
                "attribution": {
                    "source_url": source_url,
                    "section_title": section_title,
                    "evidence": evidence,
                },
            }
        )
    return rules


def clean_optional_string(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = normalize_space(str(value))
    return cleaned or None


def evidence_matches_source(evidence: str, source_text: str) -> bool:
    normalized_evidence = normalize_space(evidence).lower()
    normalized_source = normalize_space(source_text).lower()
    if not normalized_evidence:
        return False
    return normalized_evidence in normalized_source


def build_review_required_rule(
    section_title: str,
    section_text: str,
    source_url: str,
    reason: str,
    mode: str,
) -> list[dict]:
    evidence = first_rule_like_text(section_text)
    return [
        {
            "mode": mode,
            "statement": evidence,
            "rule_types": classify_rule_unit(evidence) or ["cross_reference_only"],
            "section_title": section_title,
            "source_url": source_url,
            "confidence": 0.35,
            "human_review_required": True,
            "human_review_reason": reason,
            "attribution": {
                "source_url": source_url,
                "section_title": section_title,
                "evidence": evidence[:500],
            },
        }
    ]


def first_rule_like_text(text: str) -> str:
    for chunk in split_rule_sentences(text):
        normalized = normalize_space(chunk)
        if len(normalized) >= 40 and classify_rule_unit(normalized):
            return normalized[:1000]
    fallback = normalize_space(text)
    return fallback[:1000] if fallback else "No usable rule text extracted; human review required."


def clamp_confidence(value: Any, default: float) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = default
    return min(1.0, max(0.0, numeric))


def split_rule_sentences(text: str) -> list[str]:
    # Keep semicolon-separated legal clauses because CFR sections often pack many
    # obligations into one long sentence.
    chunks: list[str] = []
    for paragraph in re.split(r"\s*(?:\n+|\([a-z0-9]+\))\s*", text):
        paragraph = normalize_space(paragraph)
        if not paragraph:
            continue
        chunks.extend(normalize_space(part) for part in RULE_SENTENCE_PATTERN.split(paragraph) if part.strip())
    return chunks


def classify_rule_unit(text: str) -> list[str]:
    lowered = text.lower()
    labels: list[str] = []
    for label, markers in RULE_MARKERS.items():
        if any(marker in lowered for marker in markers):
            labels.append(label)
    return labels


def normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def claude_api_key() -> str | None:
    return os.environ.get("CLAUDE_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")


def validate_ai_provider(options: AIOptions, client: Any | None = None) -> AIUsage:
    usage = AIUsage(
        provider_requested=options.provider,
        model_requested=options.claude_model if options.provider in {"claude", "auto"} else None,
    )
    if options.provider == "local":
        if not options.allow_local_stub:
            raise AIProviderError("Local stub selected, but --allow-local-stub is false. Use --allow-local-stub true for offline testing.")
        usage.provider_used = "local_stub"
        usage.fallback_used = True
        return usage

    key = claude_api_key()
    if not key:
        if options.provider == "auto" and options.allow_local_stub and not options.fail_on_ai_fallback:
            usage.provider_used = "local_stub"
            usage.fallback_used = True
            usage.errors.append("Claude key missing; auto mode fell back to local_stub.")
            return usage
        raise AIProviderError("Claude provider selected, but no valid Claude endpoint/API key was found. Aborting extraction.")

    if not options.claude_model.startswith("claude-"):
        raise AIProviderError(f"Claude model name is not valid for this prototype: {options.claude_model}")
    if httpx is None:
        raise AIProviderError("Claude provider selected, but httpx is not installed. Aborting extraction.")

    close_client = False
    if client is None:
        client = httpx.Client(timeout=30)
        close_client = True
    try:
        response = client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": options.claude_model,
                "max_tokens": 16,
                "temperature": 0,
                "messages": [{"role": "user", "content": "Return JSON: {\"ok\": true}"}],
            },
        )
        if response.status_code >= 400:
            raise AIProviderError(f"Claude API error {response.status_code}: {response.text[:1000]}")
        payload = response.json()
        usage_payload = payload.get("usage", {})
        usage.input_tokens += int(usage_payload.get("input_tokens", 0) or 0)
        usage.output_tokens += int(usage_payload.get("output_tokens", 0) or 0)
        usage.provider_used = "claude"
        usage.model_used = options.claude_model
        usage.cost_estimate = estimate_claude_cost(usage.input_tokens, usage.output_tokens)
        return usage
    except AIProviderError:
        raise
    except Exception as exc:
        raise AIProviderError("Claude provider selected, but no valid Claude endpoint/API key was found. Aborting extraction.") from exc
    finally:
        if close_client:
            client.close()


def estimate_claude_cost(input_tokens: int, output_tokens: int) -> float:
    # Conservative placeholder for scorecard/reporting; exact pricing should be
    # configured per model before production billing.
    return round((input_tokens / 1_000_000 * 3.0) + (output_tokens / 1_000_000 * 15.0), 6)
