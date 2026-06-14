from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from urllib.parse import urlparse


RULE_FAMILIES = [
    "eligibility",
    "enrollment",
    "claims",
    "payment",
    "reimbursement",
    "prior_authorization",
    "provider_enrollment",
    "managed_care",
    "reporting",
    "documentation",
    "appeals",
    "enforcement",
    "compliance",
    "definitions",
    "administration",
]

GOVERNMENT_RULE_TAXONOMY = {
    "government_transaction_rules": {
        "healthcare_benefits": [
            "medicaid",
            "medicare",
            "chip",
            "aca_marketplace",
            "veterans_health_benefits",
            "disability_ssi_health_eligibility",
        ],
        "cash_income_benefits": [
            "social_security",
            "ssi",
            "tanf",
            "unemployment_insurance",
            "earned_income_tax_credit",
        ],
        "food_nutrition_benefits": [
            "snap",
            "wic",
            "school_meals",
            "emergency_food_assistance",
        ],
        "housing_benefits": [
            "section_8_housing_choice_voucher",
            "public_housing",
            "liheap",
            "homelessness_assistance",
            "rental_assistance",
        ],
        "tax_revenue_transactions": [
            "federal_income_tax",
            "state_income_tax",
            "payroll_tax",
            "sales_tax",
            "property_tax",
            "credits_refunds",
        ],
        "licensing_permits": [
            "professional_licenses",
            "business_licenses",
            "driver_licenses",
            "building_permits",
            "environmental_permits",
        ],
        "procurement_grants": [
            "federal_grants",
            "state_grants",
            "contract_awards",
            "vendor_eligibility",
            "reporting_compliance",
        ],
        "immigration_identity": [
            "visas",
            "work_authorization",
            "naturalization",
            "asylum",
            "identity_verification",
        ],
        "education_benefits": [
            "fafsa",
            "pell_grants",
            "student_loans",
            "veterans_education_benefits",
            "state_aid",
        ],
        "compliance_enforcement": [
            "audits",
            "penalties",
            "appeals",
            "due_process",
            "fraud_abuse",
        ],
    }
}

SOURCE_TYPES = [
    "statute",
    "regulation",
    "agency_guidance",
    "manual",
    "bulletin_letter",
    "form_instruction",
    "court_administrative_decision",
    "faq_public_guidance",
    "unknown",
]

RULE_UNIT_TYPES = [
    "eligibility_rule",
    "claim_rule",
    "payment_rule",
    "provider_rule",
    "documentation_rule",
    "deadline_rule",
    "verification_rule",
    "exception_rule",
    "appeal_rule",
    "enforcement_rule",
    "reporting_rule",
    "definition_rule",
    "administration_rule",
]

PROGRAM_KEYWORDS = {
    "medicaid": ["medicaid", "medi-cal", "medical assistance", "chipra"],
    "medicare": ["medicare", "cms-1500", "medicare advantage", "part d"],
    "chip": ["children's health insurance", "chip"],
    "aca_marketplace": ["marketplace", "exchange", "qualified health plan", "aca"],
    "veterans_health_benefits": ["veterans health", "va health", "vha"],
    "disability_ssi_health_eligibility": ["ssi", "disability determination", "disabled individual"],
    "social_security": ["social security", "old-age", "survivors insurance"],
    "tanf": ["temporary assistance for needy families", "tanf"],
    "unemployment_insurance": ["unemployment insurance", "unemployment compensation"],
    "earned_income_tax_credit": ["earned income tax credit", "eitc"],
    "snap": ["supplemental nutrition assistance", "snap", "food stamp"],
    "wic": ["special supplemental nutrition", "wic"],
    "school_meals": ["school lunch", "school breakfast", "child nutrition"],
    "section_8_housing_choice_voucher": ["housing choice voucher", "section 8"],
    "public_housing": ["public housing"],
    "liheap": ["low income home energy", "liheap"],
    "federal_income_tax": ["internal revenue", "income tax"],
    "payroll_tax": ["payroll tax", "fica"],
    "professional_licenses": ["professional license", "licensure board"],
    "business_licenses": ["business license"],
    "driver_licenses": ["driver license", "motor vehicle"],
    "federal_grants": ["federal grant", "grant award", "uniform guidance"],
    "contract_awards": ["contract award", "procurement"],
    "visas": ["visa", "nonimmigrant"],
    "work_authorization": ["employment authorization", "work authorization"],
    "naturalization": ["naturalization", "citizenship"],
    "asylum": ["asylum"],
    "fafsa": ["fafsa", "student aid application"],
    "pell_grants": ["pell grant"],
    "student_loans": ["student loan"],
    "audits": ["audit"],
    "penalties": ["penalty", "civil money penalty"],
    "appeals": ["appeal", "fair hearing"],
    "fraud_abuse": ["fraud", "abuse"],
}

STATE_NAMES = {
    "AL": "Alabama",
    "AK": "Alaska",
    "AZ": "Arizona",
    "CA": "California",
    "FL": "Florida",
    "NY": "New York",
    "TX": "Texas",
}

STATE_PROGRAM_NAMES = {
    "CA": "California Medi-Cal",
    "TX": "Texas Medicaid",
    "NY": "New York Medicaid",
    "FL": "Florida Medicaid",
}

STATE_AGENCIES = {
    "CA": "California Department of Health Care Services",
    "TX": "Texas Health and Human Services Commission",
    "NY": "New York State Department of Health",
    "FL": "Florida Agency for Health Care Administration",
}


@dataclass(frozen=True)
class StateSpace:
    state_space_id: str
    domain: str
    vertical: str
    program: str
    state_code: str
    state_name: str
    state_program_name: str
    administering_agency: str
    jurisdiction_level: str
    federal_parent_space: str
    authority_sources: list[str]
    rule_families: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def federal_space(domain: str = "government_transaction_rules", vertical: str = "healthcare_benefits", program: str = "medicaid") -> dict:
    return {
        "federal_space_id": f"{program}:federal",
        "domain": domain,
        "vertical": vertical,
        "program": program,
        "jurisdiction_level": "federal",
        "state_code": None,
        "rule_families": RULE_FAMILIES,
    }


def taxonomy_for_prompt() -> dict:
    return {
        "domains": GOVERNMENT_RULE_TAXONOMY,
        "source_types": SOURCE_TYPES,
        "rule_unit_types": RULE_UNIT_TYPES,
    }


def normalize_taxonomy_label(value: object) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    text = text.replace("&", " and ")
    text = re.sub(r"[/\-]+", " ", text)
    text = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    prefixes = [
        "government_transaction_rules_",
        "government_rules_knowledge_graph_",
    ]
    for prefix in prefixes:
        if text.startswith(prefix):
            text = text[len(prefix) :]
    aliases = {
        "healthcare": "healthcare_benefits",
        "health_benefits": "healthcare_benefits",
        "cash_benefits": "cash_income_benefits",
        "income_benefits": "cash_income_benefits",
        "food_benefits": "food_nutrition_benefits",
        "nutrition_benefits": "food_nutrition_benefits",
        "housing": "housing_benefits",
        "tax": "tax_revenue_transactions",
        "tax_revenue": "tax_revenue_transactions",
        "licenses_permits": "licensing_permits",
        "licensing": "licensing_permits",
        "grants_procurement": "procurement_grants",
        "identity_immigration": "immigration_identity",
        "education": "education_benefits",
        "enforcement_compliance": "compliance_enforcement",
        "aca": "aca_marketplace",
        "aca_marketplace_exchange": "aca_marketplace",
        "earned_income_tax_credit_eitc": "earned_income_tax_credit",
        "section_8": "section_8_housing_choice_voucher",
        "housing_choice_voucher": "section_8_housing_choice_voucher",
        "drivers_licenses": "driver_licenses",
        "driver_license": "driver_licenses",
        "fafsa_student_aid": "fafsa",
        "va_health_benefits": "veterans_health_benefits",
    }
    return aliases.get(text, text)


def valid_vertical(value: object) -> str | None:
    normalized = normalize_taxonomy_label(value)
    if normalized in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"]:
        return normalized
    return None


def valid_program(value: object) -> str | None:
    normalized = normalize_taxonomy_label(value)
    if not normalized:
        return None
    for programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].values():
        if normalized in programs:
            return normalized
    return None


def classify_government_hierarchy(
    text: str,
    source_url: str = "",
    default_domain: str = "government_transaction_rules",
    default_vertical: str = "healthcare_benefits",
    default_program: str = "medicaid",
) -> dict:
    sample = f"{source_url} {text}".lower()
    program_scores = {
        program: sum(keyword in sample for keyword in keywords)
        for program, keywords in PROGRAM_KEYWORDS.items()
    }
    program = max(program_scores, key=program_scores.get) if program_scores else default_program
    if program_scores.get(program, 0) == 0:
        program = default_program
    vertical = vertical_for_program(program) or default_vertical
    _, rule_type, _ = classify_family_and_type(text)
    return {
        "domain": default_domain,
        "vertical": vertical,
        "program": program,
        "source_type": infer_source_type(source_url, text),
        "rule_unit_type": rule_unit_type_for_rule_type(rule_type, text),
    }


def vertical_for_program(program: str) -> str | None:
    for vertical, programs in GOVERNMENT_RULE_TAXONOMY["government_transaction_rules"].items():
        if program in programs:
            return vertical
    return None


def infer_source_type(source_url: str, text: str) -> str:
    sample = f"{source_url} {text[:1000]}".lower()
    if "ecfr.gov" in sample or "cfr-" in sample or "code of federal regulations" in sample:
        return "regulation"
    if "usc" in sample or "statute" in sample or "code section" in sample:
        return "statute"
    if "manual" in sample or "provider manual" in sample:
        return "manual"
    if "bulletin" in sample or "letter" in sample or "all plan letter" in sample:
        return "bulletin_letter"
    if "form" in sample or "instructions" in sample:
        return "form_instruction"
    if "decision" in sample or "court" in sample or "administrative law" in sample:
        return "court_administrative_decision"
    if "faq" in sample or "frequently asked" in sample:
        return "faq_public_guidance"
    if "guidance" in sample or ".gov" in sample:
        return "agency_guidance"
    return "unknown"


def rule_unit_type_for_rule_type(rule_type: str, text: str) -> str:
    lowered = text.lower()
    if rule_type == "eligibility":
        return "eligibility_rule"
    if rule_type == "payment":
        return "payment_rule"
    if rule_type == "documentation":
        return "documentation_rule"
    if rule_type == "appeal":
        return "appeal_rule"
    if rule_type == "enforcement":
        return "enforcement_rule"
    if rule_type == "prohibition":
        return "enforcement_rule"
    if rule_type == "exception":
        return "exception_rule"
    if rule_type == "definition":
        return "definition_rule"
    if "deadline" in lowered or re.search(r"\bwithin\s+\d+\s+(days|months|years)\b", lowered):
        return "deadline_rule"
    if "verify" in lowered or "verification" in lowered:
        return "verification_rule"
    if "provider" in lowered:
        return "provider_rule"
    if "claim" in lowered or "bill" in lowered:
        return "claim_rule"
    if "report" in lowered or "notify" in lowered or "submit" in lowered:
        return "reporting_rule"
    return "administration_rule"


def build_state_space(state_code: str, domain: str = "government_transaction_rules", vertical: str = "healthcare_benefits", program: str = "medicaid") -> StateSpace:
    code = state_code.upper()
    state_name = STATE_NAMES.get(code, code)
    return StateSpace(
        state_space_id=f"{program}:state:{code}",
        domain=domain,
        vertical=vertical,
        program=program,
        state_code=code,
        state_name=state_name,
        state_program_name=STATE_PROGRAM_NAMES.get(code, f"{state_name} Medicaid"),
        administering_agency=STATE_AGENCIES.get(code, f"{state_name} Medicaid agency"),
        jurisdiction_level="state",
        federal_parent_space=f"{program}:federal",
        authority_sources=[
            "state_admin_code",
            "state_statute",
            "state_plan_amendment",
            "provider_manual",
            "agency_guidance",
            "waiver_document",
            "fee_schedule",
            "billing_manual",
        ],
        rule_families=RULE_FAMILIES,
    )


def infer_jurisdiction(url: str, text: str, default_states: list[str] | None = None) -> tuple[str, str | None]:
    sample = f"{url} {text[:2000]}".lower()
    host = urlparse(url).netloc.lower()
    if "ecfr.gov" in host or "govinfo.gov" in host or "cms.gov" in host or "medicaid.gov" in host:
        return "federal", None
    if "dhcs.ca.gov" in host or "leginfo.legislature.ca.gov" in host or "calregs" in host or "medi-cal" in sample:
        return "state", "CA"
    if "texas" in sample or ".tx." in host:
        return "state", "TX"
    if "new york" in sample or ".ny." in host:
        return "state", "NY"
    if "florida" in sample or ".fl." in host:
        return "state", "FL"
    if default_states and len(default_states) == 1:
        return "state", default_states[0]
    return "unknown", None


def classify_family_and_type(text: str) -> tuple[str, str, list[str]]:
    lowered = text.lower()
    family_scores = {
        "eligibility": ["eligible", "eligibility", "qualifies", "covered group", "income standard", "resource standard"],
        "enrollment": ["enroll", "enrollment"],
        "claims": ["claim", "billing", "bill"],
        "payment": ["payment", "reimbursement", "rate", "fee schedule", "capitation", "matching funds"],
        "prior_authorization": ["prior authorization", "preauthorization"],
        "provider_enrollment": ["provider enrollment", "screening", "enrolled provider"],
        "managed_care": ["managed care", "mco", "plan"],
        "reporting": ["report", "submit", "notify", "file", "transmit", "notice"],
        "documentation": ["documentation", "verification", "evidence", "certify", "retain records", "maintain records"],
        "appeals": ["appeal", "hearing", "fair hearing", "grievance", "reconsideration"],
        "enforcement": ["penalty", "sanction", "terminate", "deny", "recover", "disallow", "suspend", "recoup"],
        "definitions": ["means", "defined as", "definition"],
        "compliance": ["shall", "must", "required", "prohibited"],
    }
    family = max(family_scores, key=lambda item: sum(term in lowered for term in family_scores[item]))
    if not any(term in lowered for term in family_scores[family]):
        family = "administration"

    definition_only = ("means" in lowered or "defined as" in lowered) and not re.search(r"\b(shall|must|required to|may not|shall not)\b", lowered)
    if definition_only:
        rule_type = "definition"
    elif "may not" in lowered or "shall not" in lowered or "must not" in lowered or "prohibited" in lowered:
        rule_type = "prohibition"
    elif "appeal" in lowered or "hearing" in lowered or "fair hearing" in lowered:
        rule_type = "appeal"
    elif "report" in lowered or "submit" in lowered or "notify" in lowered:
        rule_type = "obligation" if re.search(r"\b(shall|must|required to)\b", lowered) else "reporting"
        family = "reporting"
    elif "documentation" in lowered or "verification" in lowered or "maintain records" in lowered:
        rule_type = "documentation"
        family = "documentation"
    elif "penalty" in lowered or "sanction" in lowered or "terminate" in lowered:
        rule_type = "enforcement"
        family = "enforcement"
    elif "payment" in lowered or "reimbursement" in lowered or "rate" in lowered:
        rule_type = "payment"
        family = "payment"
    elif "except" in lowered or "unless" in lowered or "waiver" in lowered:
        rule_type = "exception"
    elif "may" in lowered:
        rule_type = "permission"
    elif "shall" in lowered or "must" in lowered or "required to" in lowered:
        rule_type = "obligation"
    elif "eligible" in lowered or "eligibility" in lowered:
        rule_type = "eligibility"
        family = "eligibility"
    else:
        rule_type = "cross_reference_only" if "see " in lowered or "refer to" in lowered else "obligation"

    tags = sorted({family, rule_type})
    return family, rule_type, tags


def normalize_condition_action(text: str) -> dict:
    normalized = re.sub(r"\s+", " ", text).strip()
    lowered = normalized.lower()
    actor = infer_actor(normalized)
    time_limit = infer_time_limit(normalized)
    exceptions = re.findall(r"\b(?:unless|except when|except that|except)\s+([^.;]+)", normalized, flags=re.IGNORECASE)
    condition = None
    if " if " in lowered:
        condition = normalized[lowered.find(" if ") + 4 :].split(".")[0].strip()
    elif " when " in lowered:
        condition = normalized[lowered.find(" when ") + 6 :].split(".")[0].strip()

    action = normalized
    for marker in [" shall ", " must ", " is required to ", " are required to ", " may not ", " may "]:
        index = lowered.find(marker)
        if index != -1:
            action = normalized[index + len(marker) :].split(".")[0].strip()
            break

    ambiguous = actor is None or len(action) < 8
    return {
        "actor": actor,
        "subject": None,
        "condition": condition,
        "action": action,
        "required_evidence": infer_required_evidence(normalized),
        "exception": [value.strip() for value in exceptions],
        "time_limit": time_limit,
        "human_review_required": ambiguous,
        "human_review_reason": "Ambiguous condition/action boundary" if ambiguous else "",
    }


def infer_actor(text: str) -> str | None:
    lowered = text.lower()
    for actor in ["state agency", "agency", "provider", "managed care plan", "applicant", "beneficiary", "recipient", "secretary"]:
        if lowered.startswith(actor) or f"the {actor}" in lowered:
            return actor
    return None


def infer_time_limit(text: str) -> str | None:
    match = re.search(r"\bwithin\s+(\d+\s+(?:days|months|years))\b", text, re.IGNORECASE)
    return match.group(1) if match else None


def infer_required_evidence(text: str) -> list[str]:
    lowered = text.lower()
    evidence = []
    for marker in ["documentation", "verification", "records", "certificate", "evidence"]:
        if marker in lowered:
            evidence.append(marker)
    return evidence


def stable_rule_id(*parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]
    return f"rule:{digest}"
