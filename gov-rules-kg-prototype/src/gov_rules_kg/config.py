from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    required: bool = True
    discovery_seed: bool = True
    jurisdiction_level: str = "unknown"
    state_code: str | None = None
    source_type: str = "unknown"


@dataclass
class RunConfig:
    workdir: Path
    max_depth: int = 4
    global_doc_cap: int = 20_000
    per_host_cap: int = 500
    max_rule_sections_per_document: int = 2_500
    domain: str = "government_transaction_rules"
    vertical: str = "healthcare_benefits"
    program: str = "medicaid"
    jurisdiction: str = "all"
    include_federal: bool = True
    include_states: list[str] = field(default_factory=list)
    ai_provider: str = "local"
    claude_model: str = "claude-sonnet-4-6"
    claude_max_sections: int = 0
    allow_local_stub: bool = False
    fail_on_ai_fallback: bool = True
    polite_delay_seconds: float = 1.0
    timeout_seconds: float = 30.0
    fetch_retries: int = 2
    fetch_retry_backoff_seconds: float = 5.0
    seed_cache_path: Path | None = None
    phase0_mode: str = "full"
    report_mode: str = "full"
    progress_every_sections: int = 500
    document_parser: str = "default"
    user_agent: str = (
        "Mozilla/5.0 gov-rules-kg-prototype/0.1 "
        "(polite research prototype; contact: local)"
    )
    seeds: list[Source] = field(default_factory=list)

    @property
    def data_dir(self) -> Path:
        return self.workdir / "data"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def reports_dir(self) -> Path:
        return self.workdir / "reports"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "rules_kg.sqlite"


def default_seeds() -> list[Source]:
    return [
        Source("example", "https://example.com", required=True, discovery_seed=False),
        Source("httpbin_ip", "https://httpbin.org/ip", required=True, discovery_seed=False),
        Source("dhcs_apl", "https://www.dhcs.ca.gov/formsandpubs/Pages/AllPlanLetters.aspx", required=False),
        Source("dhcs_apl_pdf", "https://www.dhcs.ca.gov/formsandpubs/Documents/MMCDAPLsandPolicyLetters/APL2024/APL24-001.pdf", required=False),
        Source("ccr_title_22", "https://govt.westlaw.com/calregs/Browse/Home/California/CaliforniaCodeofRegulations?guid=I5F6E0E10D44E11DEA95CA4428EC25FA0"),
        Source(
            "ca_leginfo_wic",
            "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?lawCode=WIC",
            required=False,
        ),
        Source("ecfr_42", "https://www.ecfr.gov/api/versioner/v1/full/2026-06-10/title-42.xml"),
        Source(
            "govinfo_42_cfr",
            "https://www.govinfo.gov/bulkdata/CFR/2025/CFR-2025-title42-vol1.xml",
            required=False,
        ),
        Source("cms_medicaid", "https://www.medicaid.gov/medicaid/medicaid-state-plan-amendments/index.html"),
    ]


def ecfr_all_title_sources(date: str = "2026-06-10") -> list[Source]:
    return [
        Source(
            f"ecfr_title_{title_number}",
            f"https://www.ecfr.gov/api/versioner/v1/full/{date}/title-{title_number}.xml",
            required=False,
            jurisdiction_level="federal",
            source_type="ecfr_xml",
        )
        for title_number in range(1, 51)
    ]


def load_source_manifest(path: Path) -> list[Source]:
    if not path.exists():
        raise FileNotFoundError(f"source manifest not found: {path}")
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows = payload.get("sources", payload) if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            raise ValueError("JSON source manifest must be a list or an object with a 'sources' list")
        return [source_from_mapping(row) for row in rows]
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8") as handle:
            return [source_from_mapping(row) for row in csv.DictReader(handle)]
    raise ValueError("source manifest must be .json or .csv")


def source_from_mapping(row: dict) -> Source:
    return Source(
        name=str(row["name"]),
        url=str(row["url"]),
        required=parse_manifest_bool(row.get("required", False)),
        discovery_seed=parse_manifest_bool(row.get("discovery_seed", True)),
        jurisdiction_level=str(row.get("jurisdiction_level") or "unknown"),
        state_code=str(row["state_code"]).upper() if row.get("state_code") else None,
        source_type=str(row.get("source_type") or "unknown"),
    )


def parse_manifest_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def make_config(
    workdir: Path,
    max_depth: int = 4,
    global_doc_cap: int = 20_000,
    per_host_cap: int = 500,
    max_rule_sections_per_document: int = 2_500,
    domain: str = "government_transaction_rules",
    vertical: str = "healthcare_benefits",
    program: str = "medicaid",
    jurisdiction: str = "all",
    include_federal: bool = True,
    include_states: list[str] | None = None,
    ai_provider: str = "local",
    claude_model: str = "claude-sonnet-4-6",
    claude_max_sections: int = 0,
    allow_local_stub: bool = False,
    fail_on_ai_fallback: bool = True,
    include_ecfr_all_titles: bool = False,
    ecfr_date: str = "2026-06-10",
    seed_cache_path: Path | None = None,
    source_manifest_path: Path | None = None,
    source_manifest_only: bool = False,
    polite_delay_seconds: float = 1.0,
    timeout_seconds: float = 30.0,
    fetch_retries: int = 2,
    fetch_retry_backoff_seconds: float = 5.0,
    phase0_mode: str = "full",
    report_mode: str = "full",
    progress_every_sections: int = 500,
    document_parser: str = "default",
) -> RunConfig:
    seeds = default_seeds()
    access_only_seeds = [source for source in seeds if not source.discovery_seed]
    if source_manifest_path and source_manifest_only:
        seeds = access_only_seeds
    if include_ecfr_all_titles:
        seed_names = {source.name for source in seeds}
        seeds.extend(source for source in ecfr_all_title_sources(ecfr_date) if source.name not in seed_names)
    if source_manifest_path:
        seed_names = {source.name for source in seeds}
        seeds.extend(source for source in load_source_manifest(source_manifest_path) if source.name not in seed_names)

    config = RunConfig(
        workdir=workdir,
        max_depth=max_depth,
        global_doc_cap=global_doc_cap,
        per_host_cap=per_host_cap,
        max_rule_sections_per_document=max_rule_sections_per_document,
        domain=domain,
        vertical=vertical,
        program=program,
        jurisdiction=jurisdiction,
        include_federal=include_federal,
        include_states=include_states or [],
        ai_provider=ai_provider,
        claude_model=claude_model,
        claude_max_sections=claude_max_sections,
        allow_local_stub=allow_local_stub,
        fail_on_ai_fallback=fail_on_ai_fallback,
        polite_delay_seconds=polite_delay_seconds,
        timeout_seconds=timeout_seconds,
        fetch_retries=fetch_retries,
        fetch_retry_backoff_seconds=fetch_retry_backoff_seconds,
        seed_cache_path=seed_cache_path,
        phase0_mode=phase0_mode,
        report_mode=report_mode,
        progress_every_sections=progress_every_sections,
        document_parser=document_parser,
        seeds=seeds,
    )
    config.data_dir.mkdir(parents=True, exist_ok=True)
    config.cache_dir.mkdir(parents=True, exist_ok=True)
    config.reports_dir.mkdir(parents=True, exist_ok=True)
    return config
