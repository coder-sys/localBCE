"""Pure deterministic preflight semantics for one unapproved synthetic bundle."""

from __future__ import annotations

from datetime import date

from .codec import bundle_to_mapping
from .contracts import (
    BUNDLE_ID,
    MAX_AMOUNT_CENTS,
    BundleBinding,
    BundleProvenance,
    CheckRequest,
    CheckResult,
    FactName,
    Outcome,
    ReferenceState,
    RuleBundle,
    RuleEvaluation,
    RuleId,
    RuleSemantic,
    RuleSpec,
    RunMode,
    Scope,
    ServiceCategory,
    SourceStatus,
)

RULE_ORDER = (
    RuleId.SERVICE_DATE,
    RuleId.SERVICE_CATEGORY,
    RuleId.SUPPORT_REFERENCE,
    RuleId.CHARGE_RANGE,
    RuleId.SOURCE_CURRENCY,
)

EXPECTED_SEMANTICS = {
    RuleId.SERVICE_DATE: RuleSemantic.SERVICE_DATE_IN_EFFECTIVE_WINDOW,
    RuleId.SERVICE_CATEGORY: RuleSemantic.SERVICE_CATEGORY_EQUALS,
    RuleId.SUPPORT_REFERENCE: RuleSemantic.SUPPORT_REFERENCE_PRESENT,
    RuleId.CHARGE_RANGE: RuleSemantic.CHARGE_CENTS_BETWEEN,
    RuleId.SOURCE_CURRENCY: RuleSemantic.SOURCE_COMPLETE_AND_FRESH,
}


def evaluate(request: CheckRequest, bundle: RuleBundle) -> CheckResult:
    """Return a stable, in-memory result; this function performs no I/O."""
    issues = _bundle_issues(request, bundle)
    binding = _bundle_binding(bundle)
    if issues:
        rules = tuple(
            _blocked_rule(rule_id, bundle)
            for rule_id in RULE_ORDER
        )
        return _result(request, binding, issues, rules)

    by_id = {rule.rule_id: rule for rule in bundle.rules}
    rules = tuple(
        _evaluate_rule(by_id[rule_id], request, bundle)
        for rule_id in RULE_ORDER
    )
    return _result(request, binding, (), rules)


def _result(
    request: CheckRequest,
    binding: BundleBinding,
    issues: tuple[str, ...],
    rules: tuple[RuleEvaluation, ...],
) -> CheckResult:
    if issues or any(rule.outcome is Outcome.HUMAN_CHECK for rule in rules):
        outcome = Outcome.HUMAN_CHECK
    elif any(rule.outcome is Outcome.MISSING for rule in rules):
        outcome = Outcome.MISSING
    else:
        outcome = Outcome.PASS
    missing_set = {
        fact for rule in rules for fact in rule.missing_facts
    }
    missing = tuple(fact for fact in FactName if fact in missing_set)
    return CheckResult(
        outcome=outcome,
        mode=request.mode,
        scope=request.scope,
        evaluated_at=request.evaluated_at,
        bundle=binding,
        source_binding=request.facts.source_binding,
        bundle_issues=issues,
        rules=rules,
        missing_facts=missing,
    )


def _bundle_binding(bundle: RuleBundle) -> BundleBinding:
    return BundleBinding(
        bundle_id=bundle.bundle_id,
        version=bundle.version,
        scope=bundle.scope,
        provenance=bundle.provenance,
        issuer_reference=bundle.issuer_reference,
        content_digest=bundle.content_digest,
        effective_from=bundle.effective_from,
        effective_until=bundle.effective_until,
        expires_at=bundle.expires_at,
        withdrawn_at=bundle.withdrawn_at,
    )


def _bundle_issues(request: CheckRequest, bundle: RuleBundle) -> tuple[str, ...]:
    issues: list[str] = []
    if request.mode is RunMode.REAL_USE:
        issues.append("REAL_USE_REQUIRES_APPROVED_ISSUER_BUNDLE")
    if bundle.bundle_id != BUNDLE_ID:
        issues.append("BUNDLE_ID_UNSUPPORTED")
    if bundle.version != 1:
        issues.append("BUNDLE_SEMANTIC_VERSION_UNSUPPORTED")
    if bundle.provenance is not BundleProvenance.UNAPPROVED_SYNTHETIC_FIXTURE:
        issues.append("BUNDLE_PROVENANCE_UNSUPPORTED")
    if bundle.issuer_reference != "LOCAL-SYNTHETIC-FIXTURE":
        issues.append("BUNDLE_ISSUER_UNSUPPORTED")
    if bundle.scope is not Scope.SYNTHETIC_PROVIDER_A or request.scope is not bundle.scope:
        issues.append("BUNDLE_SCOPE_MISMATCH")
    if bundle.effective_from >= bundle.effective_until:
        issues.append("BUNDLE_EFFECTIVE_INTERVAL_INVALID")
    if bundle.expires_at <= bundle.published_at:
        issues.append("BUNDLE_LIFETIME_INVALID")
    if bundle.withdrawn_at is not None and bundle.withdrawn_at <= bundle.published_at:
        issues.append("BUNDLE_WITHDRAWAL_INVALID")
    if bundle.published_at > request.evaluated_at:
        issues.append("BUNDLE_NOT_YET_PUBLISHED")
    if request.evaluated_at >= bundle.expires_at:
        issues.append("BUNDLE_EXPIRED")
    if (
        bundle.withdrawn_at is not None
        and request.evaluated_at >= bundle.withdrawn_at
    ):
        issues.append("BUNDLE_WITHDRAWN")
    try:
        calculated_digest = bundle_to_mapping(bundle)["contentDigest"]
    except (TypeError, ValueError):
        calculated_digest = ""
    if calculated_digest != bundle.content_digest:
        issues.append("BUNDLE_CONTENT_DIGEST_MISMATCH")
    if not _supported_rule_set(bundle):
        issues.append("BUNDLE_RULESET_UNSUPPORTED")
    return tuple(issues)


def _supported_rule_set(bundle: RuleBundle) -> bool:
    by_id: dict[RuleId, RuleSpec] = {}
    for rule in bundle.rules:
        if rule.rule_id in by_id:
            return False
        by_id[rule.rule_id] = rule
    if set(by_id) != set(RULE_ORDER):
        return False
    if len(bundle.rules) != len(RULE_ORDER):
        return False
    for rule_id in RULE_ORDER:
        rule = by_id[rule_id]
        if (
            rule.version != 1
            or rule.semantic is not EXPECTED_SEMANTICS[rule_id]
            or rule.effective_from != bundle.effective_from
            or rule.effective_until != bundle.effective_until
        ):
            return False
        if rule_id is RuleId.SERVICE_CATEGORY:
            if (
                rule.expected_category is not ServiceCategory.CATEGORY_A
                or rule.minimum_cents is not None
                or rule.maximum_cents is not None
                or rule.max_source_age_days is not None
            ):
                return False
        elif rule_id is RuleId.CHARGE_RANGE:
            if (
                rule.expected_category is not None
                or rule.minimum_cents != 100
                or rule.maximum_cents != min(100_000, MAX_AMOUNT_CENTS)
                or rule.max_source_age_days is not None
            ):
                return False
        elif rule_id is RuleId.SOURCE_CURRENCY:
            if (
                rule.expected_category is not None
                or rule.minimum_cents is not None
                or rule.maximum_cents is not None
                or rule.max_source_age_days != 30
            ):
                return False
        elif any(
            parameter is not None
            for parameter in (
                rule.expected_category,
                rule.minimum_cents,
                rule.maximum_cents,
                rule.max_source_age_days,
            )
        ):
            return False
    return True


def _blocked_rule(rule_id: RuleId, bundle: RuleBundle) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        citation=_citation(bundle, rule_id, 1),
        outcome=Outcome.HUMAN_CHECK,
        missing_facts=(),
        reason_codes=("BUNDLE_BLOCKED",),
        facts_used=(),
    )


def _evaluate_rule(
    rule: RuleSpec, request: CheckRequest, bundle: RuleBundle
) -> RuleEvaluation:
    facts = request.facts
    if rule.semantic is RuleSemantic.SERVICE_DATE_IN_EFFECTIVE_WINDOW:
        if facts.service_date is None:
            return _missing(rule, bundle, FactName.SERVICE_DATE)
        if not _in_interval(
            facts.service_date, rule.effective_from, rule.effective_until
        ):
            return _human(
                rule,
                bundle,
                ("SERVICE_DATE_OUTSIDE_RULE_INTERVAL",),
                (FactName.SERVICE_DATE,),
            )
        return _pass(rule, bundle, (FactName.SERVICE_DATE,))

    if rule.semantic is RuleSemantic.SERVICE_CATEGORY_EQUALS:
        if facts.service_category is None:
            return _missing(rule, bundle, FactName.SERVICE_CATEGORY)
        if facts.service_category is not rule.expected_category:
            return _human(
                rule,
                bundle,
                ("SERVICE_CATEGORY_REQUIRES_REVIEW",),
                (FactName.SERVICE_CATEGORY,),
            )
        return _pass(rule, bundle, (FactName.SERVICE_CATEGORY,))

    if rule.semantic is RuleSemantic.SUPPORT_REFERENCE_PRESENT:
        if facts.support_reference is None:
            return _missing(rule, bundle, FactName.SUPPORT_REFERENCE)
        if facts.support_reference is ReferenceState.ABSENT:
            return RuleEvaluation(
                rule_id=rule.rule_id,
                citation=_citation(bundle, rule.rule_id, rule.version),
                outcome=Outcome.MISSING,
                missing_facts=(FactName.SUPPORT_REFERENCE,),
                reason_codes=("SUPPORT_REFERENCE_MISSING",),
                facts_used=(FactName.SUPPORT_REFERENCE,),
            )
        return _pass(rule, bundle, (FactName.SUPPORT_REFERENCE,))

    if rule.semantic is RuleSemantic.CHARGE_CENTS_BETWEEN:
        if facts.charge_cents is None:
            return _missing(rule, bundle, FactName.CHARGE_CENTS)
        if (
            facts.charge_cents < (rule.minimum_cents or 0)
            or facts.charge_cents > (rule.maximum_cents or MAX_AMOUNT_CENTS)
        ):
            return _human(
                rule,
                bundle,
                ("CHARGE_OUTSIDE_SYNTHETIC_RANGE",),
                (FactName.CHARGE_CENTS,),
            )
        return _pass(rule, bundle, (FactName.CHARGE_CENTS,))

    if rule.semantic is RuleSemantic.SOURCE_COMPLETE_AND_FRESH:
        return _evaluate_source_rule(rule, request, bundle)

    return _human(rule, bundle, ("RULE_SEMANTIC_UNSUPPORTED",), ())


def _evaluate_source_rule(
    rule: RuleSpec, request: CheckRequest, bundle: RuleBundle
) -> RuleEvaluation:
    source = request.facts.source_binding
    if source is None:
        return _missing(rule, bundle, FactName.SOURCE_BINDING)

    missing: list[FactName] = []
    reasons: list[str] = []
    if source.effective_at is None:
        missing.append(FactName.SOURCE_EFFECTIVE_AT)
        reasons.append("SOURCE_EFFECTIVE_TIME_MISSING")
    if source.received_at is None:
        missing.append(FactName.SOURCE_RECEIVED_AT)
        reasons.append("SOURCE_RECEIVED_TIME_MISSING")
    if missing:
        return RuleEvaluation(
            rule_id=rule.rule_id,
            citation=_citation(bundle, rule.rule_id, rule.version),
            outcome=Outcome.MISSING,
            missing_facts=tuple(missing),
            reason_codes=tuple(reasons),
            facts_used=(FactName.SOURCE_BINDING,),
        )

    assert source.effective_at is not None
    assert source.received_at is not None
    if source.status is not SourceStatus.COMPLETE_FIXTURE:
        return _human(
            rule,
            bundle,
            ("SOURCE_STATUS_REQUIRES_REVIEW",),
            (FactName.SOURCE_BINDING,),
        )
    received_day = source.received_at.date()
    evaluated_day = request.evaluated_at.date()
    if received_day < source.effective_at:
        return _human(
            rule,
            bundle,
            ("SOURCE_RECEIVED_BEFORE_EFFECTIVE_DATE",),
            (FactName.SOURCE_BINDING, FactName.SOURCE_EFFECTIVE_AT, FactName.SOURCE_RECEIVED_AT),
        )
    if source.received_at > request.evaluated_at:
        return _human(
            rule,
            bundle,
            ("SOURCE_RECEIVED_AFTER_EVALUATION_TIME",),
            (FactName.SOURCE_BINDING, FactName.SOURCE_RECEIVED_AT),
        )
    age_days = (evaluated_day - received_day).days
    if rule.max_source_age_days is None or age_days > rule.max_source_age_days:
        return _human(
            rule,
            bundle,
            ("SOURCE_STALE_FOR_SYNTHETIC_WINDOW",),
            (FactName.SOURCE_BINDING, FactName.SOURCE_RECEIVED_AT),
        )
    return _pass(
        rule,
        bundle,
        (
            FactName.SOURCE_BINDING,
            FactName.SOURCE_EFFECTIVE_AT,
            FactName.SOURCE_RECEIVED_AT,
        ),
    )


def _pass(
    rule: RuleSpec, bundle: RuleBundle, facts_used: tuple[FactName, ...]
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule.rule_id,
        citation=_citation(bundle, rule.rule_id, rule.version),
        outcome=Outcome.PASS,
        missing_facts=(),
        reason_codes=(),
        facts_used=facts_used,
    )


def _missing(
    rule: RuleSpec, bundle: RuleBundle, fact: FactName
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule.rule_id,
        citation=_citation(bundle, rule.rule_id, rule.version),
        outcome=Outcome.MISSING,
        missing_facts=(fact,),
        reason_codes=("REQUIRED_FACT_MISSING",),
        facts_used=(),
    )


def _human(
    rule: RuleSpec,
    bundle: RuleBundle,
    reasons: tuple[str, ...],
    facts_used: tuple[FactName, ...],
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule.rule_id,
        citation=_citation(bundle, rule.rule_id, rule.version),
        outcome=Outcome.HUMAN_CHECK,
        missing_facts=(),
        reason_codes=reasons,
        facts_used=facts_used,
    )


def _citation(bundle: RuleBundle, rule_id: RuleId, version: int) -> str:
    return f"{bundle.bundle_id}/v{bundle.version}#{rule_id.value}/v{version}"


def _in_interval(value: date, start: date, end: date) -> bool:
    return start <= value < end
