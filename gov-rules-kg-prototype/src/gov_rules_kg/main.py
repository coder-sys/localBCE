from __future__ import annotations

import argparse
import json
from pathlib import Path

from .access import dependency_report, phase0_access_check
from .agent_discovery import build_agent_discovery_plan, discover_sources_from_plan, discovered_sources_to_config_sources, write_agent_discovery_reports, write_official_source_pack
from .ai import AIOptions, AIProviderError, validate_ai_provider
from .bulk_plan import build_bulk_plan
from .claude_web_audit import write_claude_web_audit
from .claude_web_coverage import write_claude_web_coverage
from .claude_web_executable import write_claude_web_executable_candidates, write_claude_web_proof_report
from .claude_web_mapping import write_claude_web_deterministic_mapping
from .claude_web_mapping_qa import write_claude_web_mapping_qa
from .claude_web_research import ClaudeWebResearchOptions, write_claude_web_research
from .claude_web_review import review_claude_web_candidates
from .claude_web_rust_shadow import write_claude_web_rust_shadow_bundle
from .claude_web_scale_plan import DEFAULT_JURISDICTIONS, DEFAULT_SOURCE_TYPES, allowed_source_types, parse_csv_or_default, write_claude_web_scale_plan
from .config import make_config
from .discovery import DiscoveryEngine
from .domain import valid_program
from .env import load_env_file
from .evaluation import evaluate_gold_set
from .hierarchy_plan import write_ai_hierarchy_plan
from .reports import build_programmatic_proof_report, build_rule_inventory_from_rules, load_atomic_rules, load_documents, write_json, write_markdown_programmatic_proof, write_verified_rules_by_hierarchy
from .rules_corpus_audit import write_rules_corpus_audit
from .scale import write_ecfr_manifest, write_scale_playbook
from .store import Store


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Government rules KG prototype")
    parser.add_argument(
        "--workdir",
        default=Path.cwd(),
        type=Path,
        help="Fresh working directory for data/reports/cache.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("deps", help="Print dependency versions")
    subparsers.add_parser("phase0", help="Run access verification gate")
    plan_parser = subparsers.add_parser("bulk-plan", help="Estimate bulk extraction scale from the last run")
    plan_parser.add_argument("--target-atomic-rules", type=int, default=1_000_000)
    scale_parser = subparsers.add_parser("scale-playbook", help="Write a concrete scale playbook toward a large rule target")
    scale_parser.add_argument("--target-atomic-rules", type=int, default=600_000)
    manifest_parser = subparsers.add_parser("generate-ecfr-manifest", help="Write a source manifest for all eCFR titles")
    manifest_parser.add_argument("--output", type=Path, default=Path("data/source_manifests/ecfr_all_titles.json"))
    manifest_parser.add_argument("--ecfr-date", default="2026-06-10")
    manifest_parser.add_argument("--summary-only", action="store_true")
    source_pack_parser = subparsers.add_parser("official-source-pack", help="Write a no-crawl official source pack for the full rules hierarchy")
    source_pack_parser.add_argument("--output", type=Path, default=Path("data/source_manifests/official_source_pack.json"))
    source_pack_parser.add_argument("--max-sources-per-program", type=int, default=0, help="0 means all curated official sources")
    hierarchy_plan_parser = subparsers.add_parser("ai-hierarchy-plan", help="Write an AI planning-only hierarchy plan without fetching or parsing documents")
    hierarchy_plan_parser.add_argument("--ai-provider", choices=["claude", "auto", "local"], default="claude")
    hierarchy_plan_parser.add_argument("--claude-model", default="claude-sonnet-4-6")
    hierarchy_plan_parser.add_argument("--allow-local-stub", default="false")
    hierarchy_plan_parser.add_argument("--fail-on-ai-fallback", default="true")
    claude_web_parser = subparsers.add_parser("claude-web-research", help="Use Claude server-side web search only; no local fetch, parse, crawl, or bs4")
    claude_web_parser.add_argument("--ai-provider", choices=["claude", "auto", "local"], default="claude")
    claude_web_parser.add_argument("--claude-model", default="claude-sonnet-4-6")
    claude_web_parser.add_argument("--allow-local-stub", default="false")
    claude_web_parser.add_argument("--fail-on-ai-fallback", default="true")
    claude_web_parser.add_argument("--max-branches", type=int, default=5, help="0 means all taxonomy branches")
    claude_web_parser.add_argument("--max-uses", type=int, default=10, help="Maximum Claude web_search uses")
    claude_web_parser.add_argument("--max-candidates-per-branch", type=int, default=3)
    claude_web_parser.add_argument("--batch-size", type=int, default=5)
    claude_web_parser.add_argument("--timeout-seconds", type=float, default=240.0)
    claude_web_parser.add_argument("--retries", type=int, default=1)
    claude_web_parser.add_argument("--allowed-domains", default="", help="Comma-separated official domains; default uses built-in government domains")
    claude_web_parser.add_argument("--programs", default="", help="Comma-separated taxonomy programs to research; overrides --max-branches when set")
    claude_web_parser.add_argument("--jurisdictions", default="", help="Comma-separated jurisdiction targets, e.g. federal,state_ca")
    claude_web_parser.add_argument("--source-types", default="", help="Comma-separated source-type targets, e.g. regulation,statute")
    claude_review_parser = subparsers.add_parser("claude-web-review", help="Review Claude web candidates and export promotion/human-review/hierarchy reports")
    claude_review_parser.add_argument("--min-confidence", type=float, default=0.85)
    claude_coverage_parser = subparsers.add_parser("claude-web-coverage", help="Report 51-program Claude web candidate coverage and next recommended batches")
    claude_coverage_parser.add_argument("--batch-size", type=int, default=5)
    claude_coverage_parser.add_argument("--min-confidence", type=float, default=0.85)
    subparsers.add_parser("claude-web-export-executable", help="Export Claude web promotion-ready candidates into deterministic executable candidate schema")
    claude_web_proof_parser = subparsers.add_parser("claude-web-proof-report", help="Generate a Claude-web-only proof report from executable candidates")
    claude_web_proof_parser.add_argument("--confidence-threshold", type=float, default=0.85)
    subparsers.add_parser("claude-web-audit", help="Run deterministic quality gates over Claude web executable candidates")
    subparsers.add_parser("claude-web-map-deterministic", help="Map Claude web executable candidates into deterministic rule-shape candidates")
    subparsers.add_parser("claude-web-mapping-qa", help="Report deterministic mapping weaknesses and next fix buckets")
    subparsers.add_parser("claude-web-export-rust-shadow", help="Export QA-passed Claude mappings into a deterministic non-runtime Rust shadow bundle")
    subparsers.add_parser("rules-corpus-audit", help="Write the Phase R1 JSON-only rules corpus inventory and runtime-boundary report")
    claude_scale_parser = subparsers.add_parser("claude-web-scale-plan", help="Plan structured Claude web expansion batches across programs, jurisdictions, and source types")
    claude_scale_parser.add_argument("--target-candidates-per-branch", type=int, default=10)
    claude_scale_parser.add_argument("--batch-size", type=int, default=5)
    claude_scale_parser.add_argument("--jurisdictions", default="")
    claude_scale_parser.add_argument("--source-types", default="")
    claude_scale_parser.add_argument("--max-batches", type=int, default=0, help="0 means all batches")
    subparsers.add_parser("validate-citations", help="Validate strict citation index from last run")
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate extraction against a gold set")
    eval_parser.add_argument("--gold-set", type=Path, required=True)
    eval_parser.add_argument("--extracted", type=Path, default=Path("reports/rules_by_type.json"))
    review_parser = subparsers.add_parser("review-queue", help="Print human review queue path/count")
    review_parser.add_argument("--confidence-threshold", type=float, default=0.75)
    executable_parser = subparsers.add_parser("export-executable", help="Print executable candidate path/count")
    executable_parser.add_argument("--only-high-confidence", default="true")
    executable_parser.add_argument("--min-confidence", type=float, default=0.85)
    subparsers.add_parser("proof-report", help="Generate programmatic proof report from the current SQLite graph")
    subparsers.add_parser("verified-hierarchy", help="Export only machine-validated rules organized by the full hierarchy")
    compare_fs = subparsers.add_parser("compare-federal-state", help="Print federal/state comparison report path")
    compare_fs.add_argument("--program", default="medicaid")
    compare_fs.add_argument("--state", required=True)
    compare_states = subparsers.add_parser("compare-states", help="Print state comparison report path")
    compare_states.add_argument("--program", default="medicaid")
    compare_states.add_argument("--states", required=True)

    agent_parser = subparsers.add_parser("agent-discover", help="Let AI plan official-source discovery, then extract rules into the hierarchy")
    agent_parser.add_argument("--ai-provider", choices=["claude", "auto", "local"], default="claude")
    agent_parser.add_argument("--claude-model", default="claude-sonnet-4-6")
    agent_parser.add_argument("--allow-local-stub", default="false")
    agent_parser.add_argument("--fail-on-ai-fallback", default="true")
    agent_parser.add_argument("--max-branches", type=int, default=10, help="0 means all taxonomy branches")
    agent_parser.add_argument("--queries-per-branch", type=int, default=3)
    agent_parser.add_argument("--max-sources", type=int, default=50)
    agent_parser.add_argument("--results-per-query", type=int, default=5)
    agent_parser.add_argument("--official-only", default="true")
    agent_parser.add_argument("--extract", default="true")
    agent_parser.add_argument("--max-depth", type=int, default=1)
    agent_parser.add_argument("--global-doc-cap", type=int, default=50)
    agent_parser.add_argument("--per-host-cap", type=int, default=5)
    agent_parser.add_argument("--max-rule-sections-per-document", type=int, default=300)
    agent_parser.add_argument("--claude-max-sections", type=int, default=100)
    agent_parser.add_argument("--phase0-mode", choices=["full", "required", "skip"], default="skip")
    agent_parser.add_argument("--report-mode", choices=["full", "light"], default="full")
    agent_parser.add_argument("--polite-delay-seconds", type=float, default=4.0)
    agent_parser.add_argument("--timeout-seconds", type=float, default=60.0)
    agent_parser.add_argument("--fetch-retries", type=int, default=2)
    agent_parser.add_argument("--fetch-retry-backoff-seconds", type=float, default=15.0)
    agent_parser.add_argument("--progress-every-sections", type=int, default=50)
    agent_parser.add_argument("--document-parser", choices=["default", "no-bs4"], default="default")

    run_parser = subparsers.add_parser("run", help="Run access-gated recursive discovery")
    run_parser.add_argument("--domain", default="government_transaction_rules")
    run_parser.add_argument("--vertical", default="healthcare_benefits")
    run_parser.add_argument("--program", default="medicaid")
    run_parser.add_argument("--jurisdiction", choices=["all", "federal", "state"], default="all")
    run_parser.add_argument("--include-federal", default="true")
    run_parser.add_argument("--include-states", default="")
    run_parser.add_argument("--max-depth", type=int, default=4)
    run_parser.add_argument("--global-doc-cap", type=int, default=20_000)
    run_parser.add_argument("--per-host-cap", type=int, default=500)
    run_parser.add_argument("--max-rule-sections-per-document", type=int, default=2_500)
    run_parser.add_argument("--ai-provider", choices=["local", "claude", "auto"], default="local")
    run_parser.add_argument("--claude-model", default="claude-sonnet-4-6")
    run_parser.add_argument("--claude-max-sections", type=int, default=0)
    run_parser.add_argument("--allow-local-stub", default="false")
    run_parser.add_argument("--fail-on-ai-fallback", default="true")
    run_parser.add_argument("--ecfr-all-titles", action="store_true")
    run_parser.add_argument("--ecfr-date", default="2026-06-10")
    run_parser.add_argument("--source-manifest", type=Path)
    run_parser.add_argument("--manifest-only", action="store_true")
    run_parser.add_argument("--fast", action="store_true")
    run_parser.add_argument("--bulk-ingest", action="store_true")
    run_parser.add_argument("--report-mode", choices=["full", "light"], default="full")
    run_parser.add_argument("--phase0-mode", choices=["full", "required", "skip"], default="full")
    run_parser.add_argument("--polite-delay-seconds", type=float)
    run_parser.add_argument("--timeout-seconds", type=float)
    run_parser.add_argument("--fetch-retries", type=int, default=2)
    run_parser.add_argument("--fetch-retry-backoff-seconds", type=float, default=5.0)
    run_parser.add_argument("--progress-every-sections", type=int, default=500)
    run_parser.add_argument("--document-parser", choices=["default", "no-bs4"], default="default")
    run_parser.add_argument("--seed-cache-path", type=Path)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    workdir = args.workdir.resolve()
    load_env_file(workdir)
    print(f"WORKING_DIR={workdir}")

    if args.command == "deps":
        print(json.dumps([item.__dict__ for item in dependency_report()], indent=2, sort_keys=True))
        return

    if args.command == "phase0":
        config = make_config(workdir)
        report = phase0_access_check(config)
        print(json.dumps(report, indent=2, sort_keys=True))
        if report["overall"] != "REACHABLE":
            raise SystemExit(2)
        return

    if args.command == "bulk-plan":
        print(json.dumps(build_bulk_plan(workdir, args.target_atomic_rules), indent=2, sort_keys=True))
        return

    if args.command == "scale-playbook":
        print(json.dumps(write_scale_playbook(workdir, args.target_atomic_rules), indent=2, sort_keys=True))
        return

    if args.command == "generate-ecfr-manifest":
        output = args.output if args.output.is_absolute() else workdir / args.output
        payload = write_ecfr_manifest(output, args.ecfr_date)
        if args.summary_only:
            payload = {
                "manifest": str(output),
                "date": payload["date"],
                "source_count": payload["source_count"],
                "first_source": payload["sources"][0]["url"],
                "last_source": payload["sources"][-1]["url"],
            }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "official-source-pack":
        payload = write_official_source_pack(workdir, args.output, args.max_sources_per_program)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "ai-hierarchy-plan":
        options = AIOptions(
            provider=args.ai_provider,
            claude_model=args.claude_model,
            allow_local_stub=parse_bool(args.allow_local_stub),
            fail_on_ai_fallback=parse_bool(args.fail_on_ai_fallback),
        )
        try:
            payload = write_ai_hierarchy_plan(workdir, options)
        except AIProviderError as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "claude-web-research":
        options = ClaudeWebResearchOptions(
            ai_options=AIOptions(
                provider=args.ai_provider,
                claude_model=args.claude_model,
                allow_local_stub=parse_bool(args.allow_local_stub),
                fail_on_ai_fallback=parse_bool(args.fail_on_ai_fallback),
            ),
            max_branches=args.max_branches,
            programs=parse_programs(args.programs),
            jurisdictions=parse_jurisdictions(args.jurisdictions),
            source_types=parse_source_types(args.source_types),
            max_uses=args.max_uses,
            max_candidates_per_branch=args.max_candidates_per_branch,
            batch_size=args.batch_size,
            timeout_seconds=args.timeout_seconds,
            retries=args.retries,
            allowed_domains=parse_domains(args.allowed_domains),
        )
        try:
            payload = write_claude_web_research(workdir, options)
        except AIProviderError as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "claude-web-review":
        try:
            payload = review_claude_web_candidates(workdir, args.min_confidence)
        except FileNotFoundError as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "claude-web-coverage":
        payload = write_claude_web_coverage(workdir, args.batch_size, args.min_confidence)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "claude-web-export-executable":
        try:
            payload = write_claude_web_executable_candidates(workdir)
        except FileNotFoundError as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "claude-web-proof-report":
        try:
            payload = write_claude_web_proof_report(workdir, args.confidence_threshold)
        except FileNotFoundError as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "claude-web-audit":
        try:
            payload = write_claude_web_audit(workdir)
        except FileNotFoundError as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "claude-web-map-deterministic":
        try:
            payload = write_claude_web_deterministic_mapping(workdir)
        except FileNotFoundError as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "claude-web-mapping-qa":
        try:
            payload = write_claude_web_mapping_qa(workdir)
        except FileNotFoundError as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "claude-web-export-rust-shadow":
        try:
            payload = write_claude_web_rust_shadow_bundle(workdir)
        except (FileNotFoundError, ValueError) as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "rules-corpus-audit":
        try:
            payload = write_rules_corpus_audit(workdir)
        except (FileNotFoundError, ValueError) as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "claude-web-scale-plan":
        try:
            payload = write_claude_web_scale_plan(
                workdir,
                target_candidates_per_branch=args.target_candidates_per_branch,
                batch_size=args.batch_size,
                jurisdictions=parse_jurisdictions(args.jurisdictions) or DEFAULT_JURISDICTIONS,
                source_types=parse_source_types(args.source_types) or DEFAULT_SOURCE_TYPES,
                max_batches=args.max_batches,
            )
        except ValueError as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.command == "validate-citations":
        path = workdir / "reports" / "citation_index.json"
        payload = read_json_if_exists(path, [])
        ambiguous = [item for item in payload if item.get("human_review_required")]
        print(json.dumps({"citation_index": str(path), "citations": len(payload), "human_review_required": len(ambiguous)}, indent=2, sort_keys=True))
        return

    if args.command == "evaluate":
        extracted = args.extracted if args.extracted.is_absolute() else workdir / args.extracted
        report = evaluate_gold_set(args.gold_set, extracted, workdir / "reports" / "evaluation_report.json")
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    if args.command == "review-queue":
        path = workdir / "reports" / "human_review_queue.json"
        queue = read_json_if_exists(path, [])
        print(json.dumps({"human_review_queue": str(path), "items": len(queue), "confidence_threshold": args.confidence_threshold}, indent=2, sort_keys=True))
        return

    if args.command == "export-executable":
        path = workdir / "reports" / "executable_rule_candidates.json"
        candidates = read_json_if_exists(path, [])
        print(json.dumps({"executable_rule_candidates": str(path), "items": len(candidates), "min_confidence": args.min_confidence}, indent=2, sort_keys=True))
        return

    if args.command == "proof-report":
        store = Store(workdir / "data" / "rules_kg.sqlite")
        try:
            rules = load_atomic_rules(store)
            documents = load_documents(store)
            inventory = read_json_if_exists(workdir / "reports" / "rule_inventory.json", build_rule_inventory_from_rules(rules))
            proof = build_programmatic_proof_report(rules, documents, inventory)
            json_path = workdir / "reports" / "programmatic_proof_report.json"
            md_path = workdir / "reports" / "programmatic_proof_report.md"
            write_json(json_path, proof)
            write_markdown_programmatic_proof(md_path, proof)
        finally:
            store.conn.close()
        print(json.dumps({"programmatic_proof_report": str(json_path), "markdown": str(md_path), "summary": proof["summary"]}, indent=2, sort_keys=True))
        return

    if args.command == "verified-hierarchy":
        store = Store(workdir / "data" / "rules_kg.sqlite")
        try:
            rules = load_atomic_rules(store)
            report = write_verified_rules_by_hierarchy(workdir / "reports", rules)
        finally:
            store.conn.close()
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    if args.command == "compare-federal-state":
        print(json.dumps({"program": args.program, "state": args.state.upper(), "reports": ["reports/federal_medicaid_rules.json", "reports/state_medicaid_rules.json", "reports/state_to_federal_mapping.json"]}, indent=2, sort_keys=True))
        return

    if args.command == "compare-states":
        print(json.dumps({"program": args.program, "states": parse_states(args.states), "report": "reports/rules_by_state.json"}, indent=2, sort_keys=True))
        return

    if args.command == "agent-discover":
        allow_local_stub = parse_bool(args.allow_local_stub)
        fail_on_ai_fallback = parse_bool(args.fail_on_ai_fallback)
        official_only = parse_bool(args.official_only)
        extract = parse_bool(args.extract)
        options = AIOptions(
            provider=args.ai_provider,
            claude_model=args.claude_model,
            claude_max_sections=args.claude_max_sections,
            allow_local_stub=allow_local_stub,
            fail_on_ai_fallback=fail_on_ai_fallback,
        )
        if args.ai_provider in {"claude", "auto"}:
            try:
                validate_ai_provider(options)
            except AIProviderError as exc:
                print(str(exc))
                raise SystemExit(2) from exc
        config = make_config(
            workdir,
            max_depth=args.max_depth,
            global_doc_cap=args.global_doc_cap,
            per_host_cap=args.per_host_cap,
            max_rule_sections_per_document=args.max_rule_sections_per_document,
            ai_provider=args.ai_provider,
            claude_model=args.claude_model,
            claude_max_sections=args.claude_max_sections,
            allow_local_stub=allow_local_stub,
            fail_on_ai_fallback=fail_on_ai_fallback,
            polite_delay_seconds=args.polite_delay_seconds,
            timeout_seconds=args.timeout_seconds,
            fetch_retries=args.fetch_retries,
            fetch_retry_backoff_seconds=args.fetch_retry_backoff_seconds,
            phase0_mode=args.phase0_mode,
            report_mode=args.report_mode,
            progress_every_sections=args.progress_every_sections,
            document_parser=args.document_parser,
        )
        try:
            branches = build_agent_discovery_plan(options, args.max_branches, args.queries_per_branch, official_only)
            discovered = discover_sources_from_plan(config, branches, args.max_sources, args.results_per_query, official_only)
        except (AIProviderError, RuntimeError) as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        discovery_report = write_agent_discovery_reports(workdir, branches, discovered)
        if not extract:
            print(json.dumps({"verdict": "AI_DISCOVERY_PLAN_READY", **discovery_report}, indent=2, sort_keys=True))
            return
        config.seeds = discovered_sources_to_config_sources(discovered)
        config.phase0_mode = args.phase0_mode
        engine = DiscoveryEngine(config)
        engine.ai_usage = validate_ai_provider(options) if args.ai_provider in {"claude", "auto"} else engine.ai_usage
        try:
            report = engine.run()
        except AIProviderError as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        finally:
            engine.close()
        print(json.dumps({"agent_discovery": discovery_report, "extraction": report}, indent=2, sort_keys=True))
        return

    if args.command == "run":
        polite_delay_seconds = args.polite_delay_seconds
        timeout_seconds = args.timeout_seconds
        phase0_mode = args.phase0_mode
        report_mode = args.report_mode
        ai_provider = args.ai_provider
        allow_local_stub = parse_bool(args.allow_local_stub)
        fail_on_ai_fallback = parse_bool(args.fail_on_ai_fallback)
        manifest_only = args.manifest_only
        if args.bulk_ingest:
            ai_provider = "local"
            allow_local_stub = True
            fail_on_ai_fallback = False
            report_mode = "light"
            manifest_only = True if args.source_manifest else manifest_only
        if args.fast or args.bulk_ingest:
            polite_delay_seconds = 0.05 if polite_delay_seconds is None else polite_delay_seconds
            timeout_seconds = 15.0 if timeout_seconds is None else timeout_seconds
            phase0_mode = "required" if phase0_mode == "full" else phase0_mode
        config = make_config(
            workdir,
            max_depth=args.max_depth,
            global_doc_cap=args.global_doc_cap,
            per_host_cap=args.per_host_cap,
            max_rule_sections_per_document=args.max_rule_sections_per_document,
            domain=args.domain,
            vertical=args.vertical,
            program=args.program,
            jurisdiction=args.jurisdiction,
            include_federal=parse_bool(args.include_federal),
            include_states=parse_states(args.include_states),
            ai_provider=ai_provider,
            claude_model=args.claude_model,
            claude_max_sections=args.claude_max_sections,
            allow_local_stub=allow_local_stub,
            fail_on_ai_fallback=fail_on_ai_fallback,
            include_ecfr_all_titles=args.ecfr_all_titles,
            ecfr_date=args.ecfr_date,
            source_manifest_path=args.source_manifest if args.source_manifest is None or args.source_manifest.is_absolute() else workdir / args.source_manifest,
            source_manifest_only=manifest_only,
            polite_delay_seconds=polite_delay_seconds if polite_delay_seconds is not None else 1.0,
            timeout_seconds=timeout_seconds if timeout_seconds is not None else 30.0,
            fetch_retries=args.fetch_retries,
            fetch_retry_backoff_seconds=args.fetch_retry_backoff_seconds,
            phase0_mode=phase0_mode,
            report_mode=report_mode,
            progress_every_sections=args.progress_every_sections,
            document_parser=args.document_parser,
            seed_cache_path=args.seed_cache_path,
        )
        try:
            ai_usage = validate_ai_provider(
                AIOptions(
                    provider=config.ai_provider,
                    claude_model=config.claude_model,
                    claude_max_sections=config.claude_max_sections,
                    allow_local_stub=config.allow_local_stub,
                    fail_on_ai_fallback=config.fail_on_ai_fallback,
                )
            )
        except AIProviderError as exc:
            print(str(exc))
            raise SystemExit(2) from exc
        engine = DiscoveryEngine(config)
        engine.ai_usage = ai_usage
        try:
            try:
                report = engine.run()
            except AIProviderError as exc:
                print(str(exc))
                raise SystemExit(2) from exc
            except Exception as exc:
                print(f"Extraction failed: {exc}")
                raise SystemExit(2) from exc
        finally:
            engine.close()
        print(json.dumps(report, indent=2, sort_keys=True))
        if report.get("verdict") == "STOPPED_PHASE0_BLOCKED":
            raise SystemExit(2)


def parse_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "y"}:
        return True
    if lowered in {"0", "false", "no", "n"}:
        return False
    raise argparse.ArgumentTypeError(f"expected true/false, got {value}")


def parse_states(value: str) -> list[str]:
    if not value or value.strip().lower() == "none":
        return []
    return [part.strip().upper() for part in value.split(",") if part.strip()]


def parse_domains(value: str) -> list[str] | None:
    domains = [part.strip().lower() for part in value.split(",") if part.strip()]
    return domains or None


def parse_programs(value: str) -> list[str] | None:
    programs: list[str] = []
    invalid: list[str] = []
    for part in value.split(","):
        if not part.strip():
            continue
        program = valid_program(part)
        if program:
            programs.append(program)
        else:
            invalid.append(part.strip())
    if invalid:
        raise argparse.ArgumentTypeError(f"unknown taxonomy program(s): {', '.join(invalid)}")
    return programs or None


def parse_jurisdictions(value: str) -> list[str] | None:
    return parse_csv_or_default(value, [], None) or None


def parse_source_types(value: str) -> list[str] | None:
    return parse_csv_or_default(value, [], allowed_source_types()) or None


def read_json_if_exists(path: Path, default: object) -> object:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
