# RightRail Integration Ledger

This directory tracks the controlled assimilation of the
`RightRail-Agent-20260919` evidence bundle into localBCE.

The source bundle is not an active runtime dependency. Archived instructions,
preserved binaries, generated builds, synthetic authorities, formal candidates,
and post-quantum research remain inactive until their individual reproduction
and qualification gates pass.

## Current Checkpoint

Phase 1 provides deterministic, byte-verified accounting for every package
manifest entry and every mapped workspace. Initial classification is deliberately
conservative:

- no archive entry is runtime eligible;
- no archive source is marked as an active port;
- preserved binaries are quarantined and never executed;
- exact duplicates identify one canonical path and retain all other paths as
  superseded evidence;
- build outputs must be reproduced from source;
- formal and cryptographic candidates remain inactive.

The current source bundle has a security quarantine recorded in
`SECURITY_REVIEW.md`. Two manifest paths containing the same executable bytes
were removed by Windows Defender. The catalog therefore accounts for every
manifest entry but intentionally fails the complete byte-integrity gate until a
trusted replacement bundle or independent malware review resolves that finding.

The reports do not claim that a workspace builds, passes tests, is secure, or is
production qualified. Those claims require later workspace-specific evidence.

## Reproduce

```text
python3 scripts/build_rightrail_integration_catalog.py \
  /path/to/RightRail-Agent-20260919

RIGHTRAIL_ARCHIVE_ROOT=/path/to/RightRail-Agent-20260919 \
  python3 scripts/validate_rightrail_integration.py

python3 -m unittest tests/test_rightrail_integration_catalog.py

python3 scripts/extract_rightrail_pdf_documents.py \
  /path/to/RightRail-Agent-20260919

python3 scripts/extract_rightrail_requirements.py \
  /path/to/RightRail-Agent-20260919

python3 scripts/build_rightrail_operating_plan_review_queue.py

python3 scripts/build_rightrail_safety_review_packet.py
```

The generated reports are intentional checkpoint artifacts:

- `reports/catalog_v1.jsonl`
- `reports/catalog_summary_v1.json`
- `reports/workspace_dispositions_v1.json`
- `reports/workspace_static_analysis_v1.json`
- `reports/workspace_static_analysis_summary_v1.json`
- `reports/pdf_document_inventory_v1.json`
- `reports/requirements_candidates_v1.jsonl`
- `reports/requirements_crosswalk_summary_v1.json`
- `reports/operating_plan_review_queue_v1.jsonl`
- `reports/operating_plan_review_queue_summary_v1.json`
- `reports/operating_plan_safety_review_packet_v1.json`

The static workspace analysis inventories build descriptors, tests, language
surfaces, preserved binaries, and review markers across all 73 workspaces. It
does not execute archive code. All workspaces remain blocked from execution
while the archive security quarantine is unresolved.

The requirements report extracts deterministic review candidates from canonical
plain-text documents and the RightRail operating-plan PDF. It marks archived
instructions as reference-only, records known localBCE conflicts, and never
promotes a statement automatically. The dedicated PDF inventory verifies all
four retained PDFs against the catalog and records page-level text hashes without
retaining full extracted text. The three cryptography papers remain documentary
references and are not treated as product requirements.

The operating-plan review queue prioritizes the four existing safety-boundary
candidates and leaves every human decision empty. Repository paths are only
cross-reference suggestions; they are not evidence of adoption or compatibility.

The safety review packet pins repository evidence for those four priority
candidates and records non-binding `adopt` or `adapt` recommendations. It does
not record human approval: all four remain pending named architecture, security,
privacy, rules, or settlement review as applicable, and none is executable,
runtime eligible, or proof bound.

## Safety Boundaries

This integration does not change adjudication, rules activation, Groth16,
Winterfell, Solidity settlement, claim schemas, or production configuration.
RightRail material can advance from this ledger only through an explicit port,
review, tests, and the existing localBCE activation gates.
