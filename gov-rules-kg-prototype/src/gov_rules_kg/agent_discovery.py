from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote_plus, unquote, urldefrag, urlparse

try:
    import httpx
except ImportError:  # pragma: no cover - exercised only in minimal local runtimes
    httpx = None

from .ai import AIOptions, AIProviderError, claude_api_key, extract_json_object
from .config import RunConfig, Source
from .domain import GOVERNMENT_RULE_TAXONOMY, normalize_taxonomy_label, taxonomy_for_prompt


OFFICIAL_HOST_SUFFIXES = (
    ".gov",
    ".mil",
)

OFFICIAL_HOSTS = {
    "govinfo.gov",
    "www.govinfo.gov",
    "ecfr.gov",
    "www.ecfr.gov",
    "federalregister.gov",
    "www.federalregister.gov",
    "hudexchange.info",
    "www.hudexchange.info",
}

PREFERRED_OFFICIAL_HOSTS = [
    "govinfo.gov",
    "ecfr.gov",
    "federalregister.gov",
    "cms.gov",
    "medicaid.gov",
    "ssa.gov",
    "irs.gov",
    "fns.usda.gov",
    "hud.gov",
    "uscis.gov",
    "studentaid.gov",
    "ed.gov",
    "va.gov",
    "sam.gov",
    "grants.gov",
]

PROGRAM_OFFICIAL_ENTRYPOINTS = {
    "medicaid": [
        "https://www.medicaid.gov/medicaid/index.html",
        "https://www.medicaid.gov/medicaid/medicaid-state-plan-amendments/index.html",
        "https://www.ecfr.gov/current/title-42/chapter-IV/subchapter-C/part-430",
        "https://www.ecfr.gov/current/title-42/chapter-IV/subchapter-C/part-435",
    ],
    "medicare": [
        "https://www.medicare.gov/",
        "https://www.ecfr.gov/current/title-42/chapter-IV/subchapter-B/part-400",
        "https://www.ecfr.gov/current/title-42/chapter-IV/subchapter-B/part-422",
    ],
    "chip": [
        "https://www.medicaid.gov/chip/index.html",
        "https://www.medicaid.gov/chip/state-program-information/index.html",
        "https://www.ecfr.gov/current/title-42/chapter-IV/subchapter-D/part-457",
    ],
    "aca_marketplace": [
        "https://www.cms.gov/marketplace",
        "https://www.cms.gov/marketplace/resources/regulations-guidance",
        "https://www.healthcare.gov/",
    ],
    "veterans_health_benefits": [
        "https://www.va.gov/health-care/",
        "https://www.va.gov/resources/",
        "https://www.va.gov/vetapp/",
    ],
    "disability_ssi_health_eligibility": [
        "https://www.ssa.gov/ssi/",
        "https://secure.ssa.gov/apps10/poms.nsf/home",
        "https://www.ssa.gov/disability/",
    ],
    "social_security": [
        "https://www.ecfr.gov/current/title-20/chapter-III/part-404",
        "https://secure.ssa.gov/apps10/poms.nsf/home",
        "https://www.ssa.gov/benefits/",
    ],
    "ssi": [
        "https://www.ssa.gov/ssi/",
        "https://secure.ssa.gov/apps10/poms.nsf/home",
    ],
    "tanf": [
        "https://www.ecfr.gov/current/title-45/subtitle-B/chapter-II/part-260",
        "https://www.ecfr.gov/current/title-45/subtitle-B/chapter-II/part-261",
    ],
    "unemployment_insurance": [
        "https://oui.doleta.gov/unemploy/",
        "https://www.dol.gov/agencies/eta/advisories",
    ],
    "earned_income_tax_credit": [
        "https://www.irs.gov/credits-deductions/individuals/earned-income-tax-credit-eitc",
        "https://www.irs.gov/forms-pubs/about-publication-596",
    ],
    "snap": [
        "https://www.fns.usda.gov/snap/supplemental-nutrition-assistance-program",
        "https://www.ecfr.gov/current/title-7/subtitle-B/chapter-II/subchapter-C/part-271",
        "https://www.ecfr.gov/current/title-7/subtitle-B/chapter-II/subchapter-C/part-273",
    ],
    "wic": [
        "https://www.fns.usda.gov/wic",
        "https://www.ecfr.gov/current/title-7/subtitle-B/chapter-II/subchapter-A/part-246",
    ],
    "school_meals": [
        "https://www.fns.usda.gov/cn",
        "https://www.ecfr.gov/current/title-7/subtitle-B/chapter-II/subchapter-A/part-210",
    ],
    "emergency_food_assistance": [
        "https://www.fns.usda.gov/tefap/emergency-food-assistance-program",
        "https://www.ecfr.gov/current/title-7/subtitle-B/chapter-II/subchapter-B/part-251",
    ],
    "section_8_housing_choice_voucher": [
        "https://www.hud.gov/helping-americans/housing-choice-vouchers-guidance",
        "https://www.ecfr.gov/current/title-24/subtitle-B/chapter-IX/part-982",
    ],
    "public_housing": [
        "https://www.hud.gov/program_offices/public_indian_housing/programs/ph",
        "https://www.hud.gov/program_offices/public_indian_housing",
    ],
    "liheap": [
        "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-A/part-96/subpart-H",
        "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-A/part-96",
    ],
    "homelessness_assistance": [
        "https://www.ecfr.gov/current/title-24/subtitle-B/chapter-V/part-578",
        "https://www.hud.gov/program_offices/comm_planning/coc",
    ],
    "rental_assistance": [
        "https://www.hud.gov/topics/rental_assistance",
        "https://www.hud.gov/helping-americans/housing-choice-vouchers-guidance",
    ],
    "federal_income_tax": [
        "https://www.irs.gov/forms-instructions",
        "https://www.irs.gov/irm",
    ],
    "state_income_tax": [
        "https://www.irs.gov/government-entities/federal-state-local-governments",
        "https://www.usa.gov/state-taxes",
    ],
    "payroll_tax": [
        "https://www.irs.gov/businesses/small-businesses-self-employed/employment-taxes",
        "https://www.irs.gov/businesses/small-businesses-self-employed/depositing-and-reporting-employment-taxes",
    ],
    "sales_tax": [
        "https://www.usa.gov/state-taxes",
    ],
    "property_tax": [
        "https://www.usa.gov/state-taxes",
    ],
    "credits_refunds": [
        "https://www.irs.gov/credits-and-deductions",
        "https://www.irs.gov/refunds",
    ],
    "professional_licenses": [
        "https://www.dol.gov/sites/dolgov/files/VETS/files/CareerCredentials_PG_Interactive_Feb2026.pdf",
    ],
    "business_licenses": [
        "https://www.sba.gov/business-guide/launch-your-business/apply-licenses-permits",
    ],
    "driver_licenses": [
        "https://www.usa.gov/motor-vehicle-services",
    ],
    "building_permits": [
        "https://www.usa.gov/local-governments",
    ],
    "environmental_permits": [
        "https://www.epa.gov/permits",
        "https://www.epa.gov/laws-regulations",
    ],
    "federal_grants": [
        "https://www.grants.gov/learn-grants/grant-policies",
        "https://www.ecfr.gov/current/title-2/subtitle-A/chapter-II/part-200",
    ],
    "state_grants": [
        "https://www.grants.gov/learn-grants/grant-making-agencies/state-governments",
        "https://www.grants.gov/learn-grants/grant-policies",
    ],
    "contract_awards": [
        "https://www.acquisition.gov/browse/index/far",
        "https://sam.gov/content/home",
    ],
    "vendor_eligibility": [
        "https://sam.gov/content/entity-registration",
        "https://www.acquisition.gov/far/part-9",
    ],
    "reporting_compliance": [
        "https://www.ecfr.gov/current/title-2/subtitle-A/chapter-II/part-200",
        "https://www.grants.gov/learn-grants/grant-policies",
    ],
    "visas": [
        "https://www.uscis.gov/policy-manual",
        "https://www.ecfr.gov/current/title-22/chapter-I/subchapter-E/part-41",
    ],
    "work_authorization": [
        "https://www.uscis.gov/working-in-the-united-states",
        "https://www.uscis.gov/policy-manual",
    ],
    "naturalization": [
        "https://www.uscis.gov/citizenship",
        "https://www.uscis.gov/policy-manual",
    ],
    "asylum": [
        "https://www.uscis.gov/humanitarian/refugees-and-asylum/asylum",
        "https://www.uscis.gov/policy-manual",
    ],
    "identity_verification": [
        "https://www.uscis.gov/i-9",
        "https://www.e-verify.gov/",
    ],
    "fafsa": [
        "https://studentaid.gov/help-center/answers/topic/completing_the_fafsa",
        "https://fsapartners.ed.gov/knowledge-center/fsa-handbook",
    ],
    "pell_grants": [
        "https://studentaid.gov/understand-aid/types/grants/pell",
        "https://fsapartners.ed.gov/knowledge-center/fsa-handbook",
    ],
    "student_loans": [
        "https://studentaid.gov/understand-aid/types/loans",
        "https://fsapartners.ed.gov/knowledge-center/fsa-handbook",
    ],
    "veterans_education_benefits": [
        "https://www.va.gov/education/",
        "https://www.va.gov/education/about-gi-bill-benefits/",
    ],
    "state_aid": [
        "https://studentaid.gov/understand-aid/types/state-aid",
    ],
    "audits": [
        "https://www.ecfr.gov/current/title-2/subtitle-A/chapter-II/part-200",
        "https://www.oversight.gov/",
    ],
    "penalties": [
        "https://www.ecfr.gov/current/title-28/chapter-I/part-85",
        "https://www.govinfo.gov/app/collection/cfr",
    ],
    "appeals": [
        "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-A/part-16",
        "https://www.govinfo.gov/app/collection/cfr",
    ],
    "due_process": [
        "https://www.justice.gov/crt",
        "https://www.hhs.gov/civil-rights/for-individuals/index.html",
    ],
    "fraud_abuse": [
        "https://oig.hhs.gov/compliance/",
        "https://www.justice.gov/civil/false-claims-act",
    ],
}

# Append-only primary sources preserve the stable names of the original 104
# entrypoints while improving grounded coverage for programs with no accepted
# current-contract candidate.
PROGRAM_OFFICIAL_ENTRYPOINT_EXPANSIONS = {
    "veterans_health_benefits": [
        "https://www.ecfr.gov/current/title-38/chapter-I/part-17",
    ],
    "disability_ssi_health_eligibility": [
        "https://www.ecfr.gov/current/title-20/chapter-III/part-416",
    ],
    "ssi": [
        "https://www.ecfr.gov/current/title-20/chapter-III/part-416",
    ],
    "public_housing": [
        "https://www.ecfr.gov/current/title-24/subtitle-B/chapter-IX/part-960",
    ],
    "environmental_permits": [
        "https://www.ecfr.gov/current/title-40/chapter-I/subchapter-D/part-122",
    ],
    "contract_awards": [
        "https://www.ecfr.gov/current/title-48/chapter-1",
    ],
    "naturalization": [
        "https://www.ecfr.gov/current/title-8/chapter-I/subchapter-C/part-316",
    ],
    "fafsa": [
        "https://www.ecfr.gov/current/title-34/subtitle-B/chapter-VI/part-668",
    ],
    "pell_grants": [
        "https://www.ecfr.gov/current/title-34/subtitle-B/chapter-VI/part-690",
    ],
    "student_loans": [
        "https://www.ecfr.gov/current/title-34/subtitle-B/chapter-VI/part-685",
    ],
    "state_aid": [
        "https://studentaid.gov/sites/default/files/2026-27-fafsa-form.pdf",
    ],
    "fraud_abuse": [
        "https://www.ecfr.gov/current/title-42/chapter-V/subchapter-B/part-1001",
    ],
}

PROGRAM_OFFICIAL_STATE_ENTRYPOINTS = {
    # State and local programs cannot honestly reach balanced coverage from
    # federal material alone. These official California code tables of
    # contents are discovery seeds: linked code sections still require source
    # review before capture or inference.
    "building_permits": [
        "https://leginfo.legislature.ca.gov/faces/codesTOCSelected.xhtml?tocCode=HSC",
    ],
    "driver_licenses": [
        "https://leginfo.legislature.ca.gov/faces/codesTOCSelected.xhtml?tocCode=VEH",
    ],
    "professional_licenses": [
        "https://leginfo.legislature.ca.gov/faces/codesTOCSelected.xhtml?tocCode=BPC",
    ],
    "business_licenses": [
        "https://leginfo.legislature.ca.gov/faces/codesTOCSelected.xhtml?tocCode=BPC",
    ],
    "state_income_tax": [
        "https://leginfo.legislature.ca.gov/faces/codesTOCSelected.xhtml?tocCode=RTC",
    ],
    "sales_tax": [
        "https://leginfo.legislature.ca.gov/faces/codesTOCSelected.xhtml?tocCode=RTC",
    ],
    "property_tax": [
        "https://leginfo.legislature.ca.gov/faces/codesTOCSelected.xhtml?tocCode=RTC",
    ],
    "unemployment_insurance": [
        "https://leginfo.legislature.ca.gov/faces/codesTOCSelected.xhtml?tocCode=UIC",
    ],
    "state_grants": [
        "https://leginfo.legislature.ca.gov/faces/codesTOCSelected.xhtml?tocCode=EDC",
    ],
    "rental_assistance": [
        "https://leginfo.legislature.ca.gov/faces/codesTOCSelected.xhtml?tocCode=HSC",
    ],
    "appeals": [
        "https://leginfo.legislature.ca.gov/faces/codesTOCSelected.xhtml?tocCode=GOV",
    ],
    "due_process": [
        "https://leginfo.legislature.ca.gov/faces/codesTOCSelected.xhtml?tocCode=GOV",
    ],
}


@dataclass(frozen=True)
class DiscoveryBranch:
    vertical: str
    program: str
    queries: list[str]
    preferred_hosts: list[str]


@dataclass(frozen=True)
class DiscoveredSource:
    name: str
    url: str
    vertical: str
    program: str
    query: str
    official: bool
    reason: str


@dataclass(frozen=True)
class SourcePackItem:
    name: str
    url: str
    vertical: str
    program: str
    required: bool
    discovery_seed: bool
    jurisdiction_level: str
    state_code: str | None
    source_type: str
    official: bool
    reason: str


def build_agent_discovery_plan(
    options: AIOptions,
    max_branches: int,
    queries_per_branch: int,
    official_only: bool = True,
) -> list[DiscoveryBranch]:
    if options.provider in {"claude", "auto"} and claude_api_key():
        return build_claude_discovery_plan(options, max_branches, queries_per_branch, official_only)
    if options.provider == "claude" and not options.allow_local_stub:
        raise AIProviderError("Claude agent discovery selected, but no Claude API key is configured.")
    if not options.allow_local_stub:
        raise AIProviderError("Agent discovery needs Claude or --allow-local-stub true for deterministic planning.")
    return build_deterministic_discovery_plan(max_branches, queries_per_branch)


def build_claude_discovery_plan(
    options: AIOptions,
    max_branches: int,
    queries_per_branch: int,
    official_only: bool,
) -> list[DiscoveryBranch]:
    if httpx is None:
        raise AIProviderError("Claude agent discovery selected, but httpx is not installed.")
    api_key = claude_api_key()
    if not api_key:
        raise AIProviderError("Claude agent discovery selected, but no Claude API key is configured.")

    prompt = {
        "task": "Create an official-source web discovery plan for a government rules knowledge graph.",
        "role": "You are an AI research agent planning recursive discovery of government transaction rules.",
        "instructions": [
            "Cover the provided hierarchy broadly, not just Medicaid.",
            "Generate search queries that target official government sources and machine-readable/manual sources where possible.",
            "Prefer statutes, regulations, agency manuals, official guidance, forms/instructions, and policy manuals.",
            "Do not output rules. Output only discovery branches and search queries.",
            "Queries should be useful for a search tool, not prose.",
            "Use official sources only when official_only is true.",
        ],
        "official_only": official_only,
        "max_branches": max_branches,
        "queries_per_branch": queries_per_branch,
        "preferred_official_hosts": PREFERRED_OFFICIAL_HOSTS,
        "government_rule_taxonomy": taxonomy_for_prompt(),
        "json_schema": {
            "branches": [
                {
                    "vertical": "string",
                    "program": "string",
                    "queries": ["string"],
                    "preferred_hosts": ["string"],
                }
            ]
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
            "model": options.claude_model,
            "max_tokens": 8192,
            "temperature": 0,
            "system": (
                "You plan official-source legal research. You do not invent law. "
                "Return structured output through the tool only."
            ),
            "tools": [
                {
                    "name": "emit_discovery_plan",
                    "description": "Emit official-source discovery branches and search queries.",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "branches": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "vertical": {"type": "string"},
                                        "program": {"type": "string"},
                                        "queries": {"type": "array", "items": {"type": "string"}},
                                        "preferred_hosts": {"type": "array", "items": {"type": "string"}},
                                    },
                                    "required": ["vertical", "program", "queries", "preferred_hosts"],
                                },
                            }
                        },
                        "required": ["branches"],
                    },
                }
            ],
            "tool_choice": {"type": "tool", "name": "emit_discovery_plan"},
            "messages": [{"role": "user", "content": json.dumps(prompt, ensure_ascii=False)}],
        },
        timeout=90,
    )
    if response.status_code >= 400:
        raise AIProviderError(f"Claude discovery planning error {response.status_code}: {response.text[:1000]}")
    payload = extract_discovery_payload_from_content(response.json().get("content", []))
    branches = normalize_discovery_branches(payload.get("branches", []), queries_per_branch)
    if not branches:
        branches = build_deterministic_discovery_plan(max_branches, queries_per_branch)
    return branches[:max_branches] if max_branches > 0 else branches


def build_deterministic_discovery_plan(max_branches: int, queries_per_branch: int) -> list[DiscoveryBranch]:
    branches: list[DiscoveryBranch] = []
    for vertical, programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].items():
        for program in programs:
            title = program.replace("_", " ")
            queries = [
                f'{title} rules regulations official site:.gov',
                f'{title} eligibility payment reporting manual official site:.gov',
                f'{title} statute regulation guidance official',
            ][:queries_per_branch]
            branches.append(
                DiscoveryBranch(
                    vertical=vertical,
                    program=program,
                    queries=queries,
                    preferred_hosts=PREFERRED_OFFICIAL_HOSTS,
                )
            )
    return branches[:max_branches] if max_branches > 0 else branches


def normalize_discovery_branches(raw_branches: Any, queries_per_branch: int) -> list[DiscoveryBranch]:
    branches: list[DiscoveryBranch] = []
    if not isinstance(raw_branches, list):
        return branches
    valid_verticals = GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"]
    for item in raw_branches:
        if not isinstance(item, dict):
            continue
        vertical = normalize_taxonomy_key(item.get("vertical"))
        program = normalize_taxonomy_key(item.get("program"))
        if vertical not in valid_verticals:
            vertical = vertical_for_program_key(program) or vertical
        if vertical not in valid_verticals or program not in valid_verticals[vertical]:
            continue
        raw_queries = item.get("queries") or []
        if isinstance(raw_queries, str):
            raw_queries = [raw_queries]
        queries = [str(query).strip() for query in raw_queries if str(query).strip()][:queries_per_branch]
        if not queries:
            continue
        raw_hosts = item.get("preferred_hosts") or PREFERRED_OFFICIAL_HOSTS
        if isinstance(raw_hosts, str):
            raw_hosts = [raw_hosts]
        hosts = [normalize_host(str(host)) for host in raw_hosts if normalize_host(str(host))]
        branches.append(DiscoveryBranch(vertical, program, queries, hosts or PREFERRED_OFFICIAL_HOSTS))
    return branches


def normalize_taxonomy_key(value: Any) -> str:
    return normalize_taxonomy_label(value) or ""


def vertical_for_program_key(program: str) -> str | None:
    for vertical, programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].items():
        if program in programs:
            return vertical
    return None


def extract_discovery_payload_from_content(content: list[dict]) -> dict:
    for block in content:
        if block.get("type") == "tool_use" and block.get("name") == "emit_discovery_plan":
            payload = block.get("input")
            if isinstance(payload, dict):
                return payload
    text = "\n".join(block.get("text", "") for block in content if block.get("type") == "text")
    if not text.strip():
        return {"branches": []}
    return json.loads(extract_json_object(text))


def discover_sources_from_plan(
    config: RunConfig,
    branches: list[DiscoveryBranch],
    max_sources: int,
    results_per_query: int,
    official_only: bool = True,
) -> list[DiscoveredSource]:
    if httpx is None:
        raise RuntimeError("httpx is required for agent discovery search.")
    discovered: list[DiscoveredSource] = []
    seen: set[str] = set()
    for branch in branches:
        for url in PROGRAM_OFFICIAL_ENTRYPOINTS.get(branch.program, []):
            if len(discovered) >= max_sources:
                return discovered
            canonical = canonicalize_discovered_url(url)
            if canonical in seen:
                continue
            seen.add(canonical)
            official, reason = source_allowed(canonical, official_only)
            if not official:
                continue
            discovered.append(
                DiscoveredSource(
                    name=stable_source_name(branch.program, len(discovered) + 1),
                    url=canonical,
                    vertical=branch.vertical,
                    program=branch.program,
                    query="curated_official_entrypoint",
                    official=official,
                    reason=reason,
                )
            )
    with httpx.Client(headers={"user-agent": config.user_agent}, timeout=config.timeout_seconds, follow_redirects=True) as client:
        for branch in branches:
            for query in branch.queries:
                if len(discovered) >= max_sources:
                    return discovered
                search_query = strengthen_official_query(query, branch.preferred_hosts, official_only)
                for result_url in search_duckduckgo_html(client, search_query, results_per_query):
                    canonical = canonicalize_discovered_url(result_url)
                    if canonical in seen:
                        continue
                    seen.add(canonical)
                    official, reason = source_allowed(canonical, official_only)
                    if not official:
                        continue
                    discovered.append(
                        DiscoveredSource(
                            name=stable_source_name(branch.program, len(discovered) + 1),
                            url=canonical,
                            vertical=branch.vertical,
                            program=branch.program,
                            query=search_query,
                            official=official,
                            reason=reason,
                        )
                    )
                    if len(discovered) >= max_sources:
                        return discovered
                time.sleep(config.polite_delay_seconds)
    return discovered


def search_duckduckgo_html(client: Any, query: str, limit: int) -> list[str]:
    url = f"https://duckduckgo.com/html/?q={quote_plus(query)}"
    try:
        response = client.get(url)
    except Exception:
        return []
    if response.status_code >= 400:
        return []
    urls: list[str] = []
    for href in extract_href_values(response.text):
        cleaned = clean_search_result_url(href)
        if not cleaned:
            continue
        if cleaned not in urls:
            urls.append(cleaned)
        if len(urls) >= limit:
            break
    return urls


def extract_href_values(html: str) -> list[str]:
    href_pattern = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
    return [match.group(1) for match in href_pattern.finditer(html)]


def clean_search_result_url(href: str) -> str | None:
    if href.startswith("//duckduckgo.com/l/"):
        parsed = urlparse(f"https:{href}")
        uddg = parse_qs(parsed.query).get("uddg", [None])[0]
        return unquote(uddg) if uddg else None
    if href.startswith("/l/"):
        parsed = urlparse(f"https://duckduckgo.com{href}")
        uddg = parse_qs(parsed.query).get("uddg", [None])[0]
        return unquote(uddg) if uddg else None
    if href.startswith("http://") or href.startswith("https://"):
        return href
    return None


def strengthen_official_query(query: str, preferred_hosts: list[str], official_only: bool) -> str:
    cleaned = " ".join(query.split())
    if not official_only:
        return cleaned
    if "site:" in cleaned:
        return cleaned
    preferred = preferred_hosts[:3] or PREFERRED_OFFICIAL_HOSTS[:3]
    host_terms = " OR ".join(f"site:{host}" for host in preferred)
    return f"{cleaned} ({host_terms} OR site:.gov)"


def source_allowed(url: str, official_only: bool = True) -> tuple[bool, str]:
    parsed = urlparse(url)
    host = normalize_host(parsed.netloc)
    if parsed.scheme not in {"http", "https"}:
        return False, "unsupported_scheme"
    if not official_only:
        return True, "official_only_disabled"
    if host in OFFICIAL_HOSTS or any(host == preferred or host.endswith(f".{preferred}") for preferred in PREFERRED_OFFICIAL_HOSTS):
        return True, "preferred_official_host"
    if any(host.endswith(suffix) for suffix in OFFICIAL_HOST_SUFFIXES):
        return True, "official_domain_suffix"
    return False, "non_official_domain"


def discovered_sources_to_config_sources(sources: list[DiscoveredSource]) -> list[Source]:
    return [
        Source(
            name=source.name,
            url=source.url,
            required=False,
            discovery_seed=True,
            jurisdiction_level="unknown",
            source_type="ai_discovered_official",
        )
        for source in sources
    ]


def write_agent_discovery_reports(workdir: Path, branches: list[DiscoveryBranch], sources: list[DiscoveredSource]) -> dict:
    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    plan_path = reports_dir / "ai_discovery_plan.json"
    sources_path = reports_dir / "ai_discovered_sources.json"
    summary_path = reports_dir / "ai_discovery_summary.md"
    plan_path.write_text(json.dumps([asdict(branch) for branch in branches], indent=2, sort_keys=True), encoding="utf-8")
    sources_path.write_text(json.dumps([asdict(source) for source in sources], indent=2, sort_keys=True), encoding="utf-8")
    summary_path.write_text(write_agent_discovery_markdown(branches, sources), encoding="utf-8")
    return {
        "ai_discovery_plan": str(plan_path),
        "ai_discovered_sources": str(sources_path),
        "ai_discovery_summary": str(summary_path),
        "branches": len(branches),
        "sources": len(sources),
    }


def write_agent_discovery_markdown(branches: list[DiscoveryBranch], sources: list[DiscoveredSource]) -> str:
    lines = ["# AI Discovery Summary", ""]
    lines.append(f"- planned_branches: {len(branches)}")
    lines.append(f"- discovered_sources: {len(sources)}")
    lines.append("")
    lines.append("## Branches")
    for branch in branches[:100]:
        lines.append(f"- {branch.vertical} / {branch.program}: {len(branch.queries)} queries")
    lines.append("")
    lines.append("## Sources")
    for source in sources[:200]:
        lines.append(f"- {source.program}: {source.url}")
    return "\n".join(lines)


def build_official_source_pack(max_sources_per_program: int = 0) -> dict:
    items: list[SourcePackItem] = []
    covered_programs: set[str] = set()
    programs_without_sources: list[str] = []
    program_source_counts: dict[str, int] = {}
    source_index = 0

    for vertical, programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].items():
        for program in programs:
            urls = PROGRAM_OFFICIAL_ENTRYPOINTS.get(program, [])
            if max_sources_per_program > 0:
                urls = urls[:max_sources_per_program]
            if not urls:
                programs_without_sources.append(program)
                continue
            covered_programs.add(program)
            program_source_counts[program] = len(urls)
            for url in urls:
                source_index += 1
                official, reason = source_allowed(url, official_only=True)
                items.append(
                    SourcePackItem(
                        name=stable_source_name(program, source_index),
                        url=url,
                        vertical=vertical,
                        program=program,
                        required=False,
                        discovery_seed=True,
                        jurisdiction_level=infer_pack_jurisdiction(url),
                        state_code=infer_pack_state_code(url),
                        source_type=infer_pack_source_type(url),
                        official=official,
                        reason=reason,
                    )
                )

    for vertical, programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].items():
        for program in programs:
            urls = PROGRAM_OFFICIAL_ENTRYPOINT_EXPANSIONS.get(program, [])
            if max_sources_per_program > 0:
                remaining = max(
                    0,
                    max_sources_per_program - program_source_counts.get(program, 0),
                )
                urls = urls[:remaining]
            for url in urls:
                source_index += 1
                official, reason = source_allowed(url, official_only=True)
                items.append(
                    SourcePackItem(
                        name=stable_source_name(program, source_index),
                        url=url,
                        vertical=vertical,
                        program=program,
                        required=False,
                        discovery_seed=True,
                        jurisdiction_level=infer_pack_jurisdiction(url),
                        state_code=infer_pack_state_code(url),
                        source_type=infer_pack_source_type(url),
                        official=official,
                        reason=reason,
                    )
                )
                covered_programs.add(program)
                program_source_counts[program] = (
                    program_source_counts.get(program, 0) + 1
                )

    # Keep state expansion in a separate append-only pass so additions cannot
    # renumber the existing federal source IDs.
    for program, configured_urls in PROGRAM_OFFICIAL_STATE_ENTRYPOINTS.items():
        vertical = vertical_for_program_key(program)
        if vertical is None:
            raise ValueError(f"state source expansion has unknown program: {program}")
        urls = configured_urls
        if max_sources_per_program > 0:
            remaining = max(
                0,
                max_sources_per_program - program_source_counts.get(program, 0),
            )
            urls = urls[:remaining]
        for url in urls:
            source_index += 1
            official, reason = source_allowed(url, official_only=True)
            items.append(
                SourcePackItem(
                    name=stable_source_name(program, source_index),
                    url=url,
                    vertical=vertical,
                    program=program,
                    required=False,
                    discovery_seed=True,
                    jurisdiction_level=infer_pack_jurisdiction(url),
                    state_code=infer_pack_state_code(url),
                    source_type=infer_pack_source_type(url),
                    official=official,
                    reason=reason,
                )
            )
            covered_programs.add(program)
            program_source_counts[program] = (
                program_source_counts.get(program, 0) + 1
            )

    taxonomy_programs = [
        program
        for programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].values()
        for program in programs
    ]
    return {
        "mode": "official_source_pack",
        "discovery_method": "curated_official_entrypoints_no_recursive_crawl_no_search",
        "taxonomy_verticals_total": len(GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"]),
        "taxonomy_programs_total": len(taxonomy_programs),
        "programs_with_sources_count": len(covered_programs),
        "programs_without_sources_count": len(programs_without_sources),
        "programs_without_sources": programs_without_sources,
        "source_count": len(items),
        "sources": [asdict(item) for item in items],
    }


def write_official_source_pack(workdir: Path, output: Path, max_sources_per_program: int = 0) -> dict:
    manifest_path = output if output.is_absolute() else workdir / output
    reports_dir = workdir / "reports"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    payload = build_official_source_pack(max_sources_per_program)
    manifest_payload = {
        "mode": payload["mode"],
        "discovery_method": payload["discovery_method"],
        "source_count": payload["source_count"],
        "sources": payload["sources"],
    }
    manifest_path.write_text(json.dumps(manifest_payload, indent=2, sort_keys=True), encoding="utf-8")

    summary_path = reports_dir / "official_source_pack_summary.json"
    markdown_path = reports_dir / "official_source_pack_summary.md"
    commands_path = reports_dir / "official_source_pack_commands.md"
    summary_payload = {key: value for key, value in payload.items() if key != "sources"}
    summary_payload["manifest"] = str(manifest_path)
    summary_path.write_text(json.dumps(summary_payload, indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(write_official_source_pack_markdown(payload, manifest_path), encoding="utf-8")
    try:
        command_manifest_path = manifest_path.relative_to(workdir)
    except ValueError:
        command_manifest_path = manifest_path
    commands_path.write_text(write_official_source_pack_commands(command_manifest_path), encoding="utf-8")

    return {
        "manifest": str(manifest_path),
        "summary": str(summary_path),
        "markdown": str(markdown_path),
        "commands": str(commands_path),
        "taxonomy_programs_total": payload["taxonomy_programs_total"],
        "programs_with_sources_count": payload["programs_with_sources_count"],
        "programs_without_sources_count": payload["programs_without_sources_count"],
        "source_count": payload["source_count"],
        "verdict": "OFFICIAL_SOURCE_PACK_READY",
    }


def write_official_source_pack_markdown(payload: dict, manifest_path: Path) -> str:
    lines = [
        "# Official Source Pack",
        "",
        "This pack is a curated official-source manifest for the full government rules hierarchy.",
        "It is not an AI-memory rule dump and it does not perform recursive crawling or search discovery.",
        "",
        f"- manifest: `{manifest_path}`",
        f"- taxonomy_verticals_total: {payload['taxonomy_verticals_total']}",
        f"- taxonomy_programs_total: {payload['taxonomy_programs_total']}",
        f"- programs_with_sources_count: {payload['programs_with_sources_count']}",
        f"- programs_without_sources_count: {payload['programs_without_sources_count']}",
        f"- source_count: {payload['source_count']}",
        "",
        "## Coverage",
    ]
    by_program: dict[str, list[dict]] = {}
    for source in payload["sources"]:
        by_program.setdefault(source["program"], []).append(source)
    for vertical, programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].items():
        lines.append("")
        lines.append(f"### {vertical}")
        for program in programs:
            sources = by_program.get(program, [])
            status = "covered" if sources else "missing"
            lines.append(f"- {program}: {status} ({len(sources)} sources)")
            for source in sources[:3]:
                lines.append(f"  - {source['url']}")
    return "\n".join(lines)


def write_official_source_pack_commands(manifest_path: Path) -> str:
    return "\n".join(
        [
            "# Official Source Pack Commands",
            "",
            "Use this to view verified rules already in the graph:",
            "",
            "```bash",
            "python -m gov_rules_kg.main verified-hierarchy",
            "cat reports/verified_rules_summary.md",
            "cat reports/verified_rules_readable.md | head -160",
            "```",
            "",
            "Use this to ingest from the official source pack without recursive crawling:",
            "",
            "```bash",
            "python -m gov_rules_kg.main run \\",
            "  --source-manifest " + manifest_path.as_posix() + " \\",
            "  --manifest-only \\",
            "  --max-depth 0 \\",
            "  --global-doc-cap 25 \\",
            "  --per-host-cap 10 \\",
            "  --max-rule-sections-per-document 500 \\",
            "  --ai-provider claude \\",
            "  --claude-model claude-sonnet-4-6 \\",
            "  --claude-max-sections 50 \\",
            "  --fail-on-ai-fallback true \\",
            "  --allow-local-stub false \\",
            "  --phase0-mode skip \\",
            "  --progress-every-sections 25 \\",
            "  --document-parser no-bs4 \\",
            "  --timeout-seconds 90 \\",
            "  --polite-delay-seconds 2 \\",
            "  --fetch-retries 1 \\",
            "  --fetch-retry-backoff-seconds 10",
            "```",
        ]
    )


_PACK_STATE_HOST_CODES = {
    "leginfo.legislature.ca.gov": "CA",
}


def infer_pack_state_code(url: str) -> str | None:
    host = normalize_host(urlparse(url).netloc)
    return _PACK_STATE_HOST_CODES.get(host)


def infer_pack_jurisdiction(url: str) -> str:
    host = normalize_host(urlparse(url).netloc)
    if infer_pack_state_code(url) is not None:
        return "state"
    if host.endswith(".gov") or host.endswith(".mil") or host in {"hudexchange.info"}:
        return "federal"
    return "unknown"


def infer_pack_source_type(url: str) -> str:
    lowered = url.lower()
    if "leginfo.legislature.ca.gov" in lowered:
        return "statute"
    if "ecfr.gov" in lowered or "cfr" in lowered or "regulation" in lowered or "laws-regulations" in lowered:
        return "regulation"
    if "policy" in lowered or "guidance" in lowered or "manual" in lowered or "poms" in lowered or "handbook" in lowered or "irm" in lowered:
        return "manual"
    if "forms" in lowered or "instructions" in lowered or "form" in lowered:
        return "form_instruction"
    if "faq" in lowered or "help-center" in lowered or "resources" in lowered:
        return "faq_public_guidance"
    return "agency_guidance"


def stable_source_name(program: str, index: int) -> str:
    safe = re.sub(r"[^a-z0-9]+", "_", program.lower()).strip("_") or "source"
    return f"agent_{safe}_{index}"


def normalize_host(host: str) -> str:
    return host.lower().strip().removeprefix("www.")


def canonicalize_discovered_url(url: str) -> str:
    return urldefrag(url.strip())[0]
