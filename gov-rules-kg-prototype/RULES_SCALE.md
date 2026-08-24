# Grounded Rules Corpus Scale Lane

This lane produces source-grounded, non-binding rule candidates in PostgreSQL 16.
It does not replace the hardcoded G1-G10 adjudicator, activate candidate rules, or
bind any candidate to Groth16 or STARK proofs.

## Local Database

Set a development-only password in the shell, start PostgreSQL, and expose a
standard `DATABASE_URL`:

```bash
export RULES_POSTGRES_PASSWORD='local-only-value'
docker compose -f docker-compose.rules.yml up -d
export DATABASE_URL='postgresql://localbce_rules:local-only-value@127.0.0.1:5432/localbce_rules'
python -m gov_rules_kg.main rules-db-migrate
```

Passwords, Claude credentials, OIDC tokens, and database dumps must not be
committed. PostgreSQL is the only active bulk corpus store. Existing SQLite
commands and `data/rules_kg.sqlite` remain reference-only.

## Pipeline

```bash
python -m gov_rules_kg.main sources-sync
python -m gov_rules_kg.main sources-sync --fetch --capture-id official-v2-20260818 --concurrency 4
python -m gov_rules_kg.main sources-discover
python -m gov_rules_kg.main sources-preflight --limit 0 --target 600000
python -m gov_rules_kg.main sources-preflight-validate \
  --report reports/rules_source_candidate_preflight_v1.json
python -m gov_rules_kg.main source-registry-release --release-id official-source-v2
python -m gov_rules_kg.main sources-sync --registry reports/source_registry_release_official-source-v2.json --fetch
python -m gov_rules_kg.main sections-extract --concurrency 4
# Explicit operator recovery after diagnosing terminal parser failures:
python -m gov_rules_kg.main sections-extract --concurrency 4 --retry-failed --retry-limit 8
# A PDF with a terminal no-text failure may receive separately reviewed OCR.
# The UTF-8 artifact must remain beneath the dedicated evidence root.
python -m gov_rules_kg.main ocr-artifact-ingest \
  --retrieval-id RETRIEVAL_ID \
  --artifact data/evidence/ocr/SOURCE.txt \
  --engine-name tesseract --engine-version 5.4.1 \
  --operator-id REVIEWER_ID --generated-at 2026-08-13T12:00:00Z
ANTHROPIC_API_KEY=... python -m gov_rules_kg.main claude-infer --limit 5100 --concurrency 8 --batch-size 256
# Resume a previously queued run without selecting more source sections:
ANTHROPIC_API_KEY=... python -m gov_rules_kg.main claude-infer --limit 5100 --concurrency 8 --batch-size 256 --drain-existing
# Credential-free crash recovery reclaims leases, enqueues missing critique
# work, and materializes completed critiques:
python -m gov_rules_kg.main inference-recover
# Returning failed current-contract jobs to pending requires an explicit retry:
python -m gov_rules_kg.main inference-recover --retry-failed --retry-limit 8
python -m gov_rules_kg.main corpus-progress --target 5100
# Explicit operator recovery after diagnosing terminal failures:
ANTHROPIC_API_KEY=... python -m gov_rules_kg.main claude-infer --concurrency 8 --retry-failed --retry-limit 8
python -m gov_rules_kg.main inference-usage-report
python -m gov_rules_kg.main quality-sample-plan --release-id official-5100-v1 --corpus-target 5100
python -m gov_rules_kg.main quality-evaluate --release-id official-5100-v1
python -m gov_rules_kg.main review-export
python -m gov_rules_kg.main corpus-release --release-id official-5100-v1 --target 5100 --source-registry reports/source_registry_release_official-source-v2.json
python -m gov_rules_kg.main corpus-release-validate --release-manifest reports/corpus_release_official-5100-v1.json --source-registry reports/source_registry_release_official-source-v2.json
python -m gov_rules_kg.main shadow-bundle-export --release-manifest reports/corpus_release_official-5100-v1.json
```

`sources-sync` registers the 128 explicitly configured entrypoints in
`official_source_registry_v2.json` across all 51 programs and imports the current
226 candidates as blocked baseline records. The registry contains 116 federal
entrypoints and 12 California legislative discovery seeds. State seeds remain
source-expansion inputs pending human source review: they do not activate
discovered links, create runtime rules, or change the federal-first rollout
policy.
`--fetch` creates a durable PostgreSQL fetch batch and captures exact response
bytes. Rerunning the same `--capture-id` resumes that batch idempotently; a new
identifier explicitly starts a fresh capture. Jobs use bounded attempts, delayed
retry, renewable leases, `SKIP LOCKED` claiming, and atomic snapshot completion,
so process interruption cannot silently duplicate or lose source work. Terminal
failures reopen only through `--retry-failed --retry-limit N`.
`sections-extract` uses a durable PostgreSQL queue with bounded attempts, delayed
retry, renewable leases, `SKIP LOCKED` claiming, and atomic completion. Section IDs
bind the immutable snapshot hash, extraction-pipeline version, parser identity,
ordinal, and normalized text hash. Completing a newer pipeline version deactivates
older sections for paid inference without deleting their lineage. Parser behavior
changes require a new extraction-pipeline version; terminal jobs reopen only through
`--retry-failed --retry-limit N`. Parser v2 preserves eCFR/GovInfo container
headings, HTML heading levels, list items, table rows, PDF page context, and
machine-readable node/page locators in each section. OCR is never silently invoked.

`ocr-artifact-ingest` is restricted to PDF retrievals whose native extraction
terminated with no usable text. It preserves the official response snapshot,
stores the exact OCR bytes and engine/version/operator metadata in a separate
immutable PostgreSQL artifact, and links every OCR section back to that artifact.
OCR candidates are always mandatory quality samples; OCR text is never represented
as official source bytes or made runtime eligible by ingestion.

`sources-discover` extracts only HTTPS links on official `.gov` hosts from the
captured bytes. It writes immutable discovery runs and `pending_review` source
candidates with parent snapshot and node lineage. It never fetches a discovered
link, edits the versioned source registry, or activates a source automatically.
A `rules_admin` may claim and decide these candidates through `/rules/sources/*`;
approval means only `approved_for_registry` and still requires a later, explicit
versioned registry release. A later retrieval with different parent bytes, an
inactive parent source, or mismatched discovery lineage marks the candidate
`superseded` and removes it from release eligibility while preserving its decision
and audit history. Re-fetching identical bytes does not invalidate review.
`source-candidate-preflight-v8` also flags Federal Register, eCFR, GovInfo, and
GPO links as primary temporal-authority review candidates. This raises only their
human-review priority so reviewers can address missing source-stated effective
dates; it does not assert an effective date, approve a source, or change runtime
eligibility. Candidate-level program evidence is required by default. Parent-page
program scope is inherited only for cross-host jurisdiction-directory entries,
primary temporal authorities, or an explicitly curated authority hierarchy. The
driver-license classifier additionally rejects generic motor-vehicle branches unless
they contain driver/license evidence or come from one of those scoped handoffs.
`source-registry-release` exports that reviewed,
hash-pinned release candidate without modifying a runtime registry. Passing that
artifact explicitly to `sources-sync --registry` selects it for corpus ingestion;
the sync deactivates older corpus source versions and never affects adjudication.
`corpus-release --source-registry` then rejects mixed source-registry lineage and
binds the exact selected registry ID and canonical hash into the release manifest.
`corpus-release-validate` independently recomputes the release hash, quotas,
quality verdict, safety flags, pinned model/prompts, and source-registry binding
before an artifact can feed a shadow export.
The release also pins the exact unique source-snapshot set, ordered section and
evidence digests, schema versions, and independent hashes of the quality and
reviewer-evidence payloads. This makes a release reproducible without embedding a
600,000-record candidate body in the compact manifest.

## Verified Bootstrap Checkpoint

The local PostgreSQL 16 audit corpus was revalidated on 2026-08-23 with the
following closed checkpoint. `corpus-progress` counts only the current source,
parser, model, prompt, schema, and response-contract lineage:

- 128 versioned source entrypoints: 116 federal entrypoints plus 12 California
  legislative discovery seeds pending human source review
- all 128 v2 sources captured successfully in the `official-v2-20260818` batch;
  the audit database retains 455 retrieval records and 298 unique immutable
  source snapshots across all historical captures
- 15,100 current-source physical sections and 16,230 active program-section
  contexts after the v2 extraction pass
- active source and section coverage for all 51 programs
- 7,577 discovered official-link lineage rows deterministically preflighted
- 1,029 links eligible for human source review and 6,548 blocked by preflight v8
- 1,697 duplicate program/URL candidates blocked from inflating source volume
- 112 eligible Federal Register, eCFR, GovInfo, or GPO links prioritized for
  temporal-authority review without automatic approval
- 14,927 current-contract grounded candidates, but only 2,884 of the balanced
  5,100 quota slots are filled
- 419 conflict-free deterministic candidates, filling only 335 balanced quota
  slots; 1 of 51 programs meets its deterministic quota
- 14,493 accepted candidates lack source-stated effective dates; 14,493 current
  drafts carry the corresponding missing-effective-date blocker
- 13 candidates remain blocked by conflicting duplicate clusters and 2 by
  semantic-duplicate clusters
- 20 of 51 programs meet the grounded-candidate quota
- 2 additional program-section contexts are still required before source
  capacity alone can support the balanced 5,100 milestone
- 5,769 inference jobs completed, 213 were deterministically rejected, and
  4,618 remain pending; the latest bounded extraction checkpoint completed
  111 jobs and rejected 11 malformed or over-limit responses, then the bounded
  critique checkpoint completed 124 jobs and rejected 4 evidence-mismatched
  repairs without adding a durable failure or leaving a stranded lease
- 204 historical failed jobs are retained for audit, with zero failures blocking
  the current active source and inference lineage
- 176 reviewer tasks are pending and no corpus release exists
- `fafsa` and `pell_grants` currently have no preflight-eligible discovered
  links; most programs still lack enough approved source capacity for the
  600,000 target
- `driver_licenses` and `building_permits` each have only 3 active program
  sections and remain the immediate balanced 5,100 capacity blockers. Their
  discovery queues contain 51 and 5 blocker-free pending source links,
  respectively, but none is approved. Human review must reject noisy links and
  approve only relevant official authority before either registry can expand
- the 56 immediate capacity candidates are exported through the preflight API as
  a canonical review packet with SHA-256
  `661790cf462592e2cf44372cedccea0fe050b743917d7f927a74a903c185db69`;
  each item is explicitly inactive, non-legal, and proof-unbound
- `sources-preflight-validate` verifies that packet without database access and
  fails closed on count, hash, ordering, official-URL, scope, review-state, or
  activation-boundary tampering
- all 1,029 eligible links have deterministic scope evidence: 885 carry direct
  candidate evidence, 110 are jurisdiction-directory handoffs, and 34 inherit
  scope from a primary temporal authority; no eligible candidate is unscoped
- no candidate is legally verified or runtime eligible
- the inference queue remains resumable and non-runtime
- quality accounting separates detected open conflict clusters from truly
  unclustered conflicting pairs; either condition blocks a corpus release

The current paid-inference contract pins `claude-sonnet-4-6`, extraction prompt
`grounded-atomic-extraction-v6`, critique prompt
`grounded-atomic-critique-v6`, and response contract
`grounded-inference-tool-contract-v13`. It requires forced structured tool output,
validates the typed condition/outcome schema locally, and recomputes exact evidence
spans from captured section bytes. Candidate-granular validation retains valid
siblings while recording invalid extraction candidates as explicit local rejections.
Critique no-op repairs and missing repaired candidates reject only the affected
candidate. Repaired lineage insertion is idempotent on the semantic
candidate/relation/predecessor tuple, including across inference-contract upgrades.
All of these paths retain `runtime_activation=false` and `proof_binding=false`.

Malformed structured model output is recorded as a terminal rejected response with
full token/request accounting. It does not become a grounded candidate and does not
masquerade as an infrastructure failure. HTTP/network exhaustion, lost leases, and
database failures remain blocking failed jobs. An end date without a source-stated
start date is preserved for discovery and blocked at draft validation rather than
discarding the entire section response.
Critique scheduling additionally requires the originating extraction job to match
that exact pinned contract, preventing candidates from crossing prompt or response
contract boundaries.
Stable candidate IDs may recur across inference versions, so each canonical candidate
row is an explicit current-contract projection with separate extraction and critique
contract keys. Historical observations remain immutable in inference jobs and
candidate lineage. Review, quality, progress, and release queries reject any
candidate that lacks both current pinned keys.
No-op critique repairs are rejected during response validation, before any database
mutation. Inference leases are 15 minutes with 30-second heartbeats so the lease
covers the provider call while still allowing deterministic crash recovery. Each
renewal and result commit locks the job row and requires the same recorded owner.
If a host pause crosses the timestamp but no recovery worker has taken ownership,
that owner may safely renew or commit; after recovery or reassignment changes the
status or owner, the stale worker fails closed.
Claude operation has one cumulative wall-clock deadline across connection, response,
internal retries, and retry delays; a response cannot extend the configured deadline
by continuing to emit data or by resetting an individual read timeout.

The hash-pinned 5,100 launch plan passes its operational preflight, but that means
only that a bounded inference run can start safely. It does not mean the 5,100
candidate milestone, quality gates, human source review, policy review, legal
verification, or any runtime release has passed. Superseded prompt failures remain
in usage and queue history; only failures matching the exact current model, prompt,
schema, and response contract block a new launch.

Rule, quality, and source-review claims use owner-bound 24-hour PostgreSQL leases.
The current owner may renew or release a claim through the corresponding
`/rules/*/renew` or `/rules/*/release` endpoint. Expired claims, including legacy
claimed rows without an expiry, return to their pending queue and emit an immutable
audit event before another reviewer can claim them. Decisions fail closed after a
lease expires, and claim attempts remain counted for recovery analysis.

The source preflight summary joins current-contract accepted counts to the 5,100
program quotas and exposes deficit-ranked review choices. Administrators may claim a
specific program through the existing source-review endpoint, while an omitted
program retains the balanced `SKIP LOCKED` queue. All 20 programs that had no
accepted candidate at the start of the source audit have active captured source
sections. Of the 29 programs still without a current-contract accepted candidate,
27 have preflight-eligible discovered links. `fafsa` and `pell_grants` remain
explicit source-review gaps and must not be filled with irrelevant material.
Direct primary sources were added for `public_housing`,
`state_aid`, and `veterans_health_benefits` without automatically promoting
discovered links.

`claude-infer` is pinned to the configured Claude model and performs extraction
and independent critique. There is no local model fallback. All evidence offsets,
types, operators, dates, hashes, and forbidden status fields are checked by local
code before candidates are accepted. Ready critique jobs are claimed before new
extraction jobs so each extraction page reaches its quality pass without starvation.
The model identifier returned by the provider must exactly match the configured
model. A persisted deterministic relevance gate filters obvious site boilerplate
before paid inference. Unique sections are
scheduled using the least-covered program among their valid source links, without
duplicating a section or counting cross-program links as additional volume. The model's
actual program assignment remains evidence-derived and may differ from that scheduling
focus. Programs without an accepted current-contract candidate still require
reviewed, program-specific official sources rather than
forced labels. Critique repairs must provide a complete corrected candidate; accepted
repairs receive a new stable ID and `repaired_from` lineage.
Every completed or failed request records attempts, model, request ID, and input and
output token counts; `inference-usage-report` exports aggregate accounting without
credentials or source text. Long-running Claude retries renew their PostgreSQL lease,
preventing another worker from claiming the same live request. Expired leases are
reclaimed until their durable attempt limit is exhausted, then fail closed. A
database-wide PostgreSQL advisory lock permits only one paid `claude-infer` command
at a time, so separate terminals cannot silently multiply the configured worker
concurrency. The lock is session-scoped and releases when the command exits or its
database connection closes.

A terminal failure can be resumed only with
the explicit `--retry-failed --retry-limit N` operator action; lifetime attempts and
retry rounds remain accounted instead of being reset. Candidate or critique writes
and inference-job completion occur in one transaction under a live worker-owned
lease. A parser upgrade blocks results for superseded sections, and inactive parser
output is excluded from critique, draft materialization, quality sampling, and new
release cohorts. Large runs page section scheduling and review-draft materialization
through `--batch-size`; exact request and token totals remain in the run report while
per-job details are bounded by `--result-detail-limit`. Remaining queue counts make a
partially drained run explicit and resumable. `corpus-progress` reports exact active
source, snapshot, section, accepted-candidate, deterministic-candidate, queue-failure,
current-draft blocker, accepted-candidate effective-date coverage, and per-program
quota deficits for a selected milestone. Effective-date and blocker totals are scoped
to active sections, active source-program contexts, and the current pinned inference
contract. It never treats an inactive
source version, a superseded parser section, or a raw total concentrated in a few
programs as milestone completion.

Grounded discovery volume and deterministic readiness are reported separately.
`milestone_grounded_candidate_ready` requires balanced accepted-candidate quotas;
`milestone_deterministic_candidate_ready` additionally requires validated typed
drafts. The legacy `milestone_candidate_ready` field remains a compatibility alias
for deterministic readiness and is the release gate.

The same progress report derives a hard global ceiling from active physical
sections and the pinned 25-candidate extraction cap. Per-program context counts
are optimistic upper bounds because one physical section can be linked to
several programs but each grounded candidate has exactly one primary program.
The report exposes physical-section and per-program-context lower bounds for
the additional reviewed source material required by the selected balanced
milestone. These capacity checks are necessary, not sufficient: candidates
still must pass grounding, critique, typing, conflict, review, and quality
gates.

In `--drain-existing` mode, `--limit` is the exact maximum number of database job
attempts claimed by that invocation. The worker pool replenishes each completed slot
immediately instead of waiting for the slowest request in a fixed batch, while never
claiming beyond that exact budget. Completed, rejected, and retryable failed
attempts all consume that budget, so a failed job cannot be reclaimed repeatedly
inside one bounded operator run.
Ready critique jobs are always claimed before new extraction work. Within pass 1,
the scheduler uses current accepted-candidate counts and a per-program row rank to
favor lower-coverage programs without sacrificing PostgreSQL `SKIP LOCKED`
concurrency.

`quality-sample-plan` creates a deterministic sample of at least 1,020 records,
including at least 20 per program and every OCR, low-confidence, conflict, or
provenance-warning record. A policy reviewer and a different legal verifier must
independently submit hash-bound measurements through `/rules/quality/*` before a
sample contributes to the release quality gate. The consensus uses the more
conservative result for every metric.

Planning also freezes the balanced candidate cohort for that release ID.
Quality measurements, reviewer summaries, corpus manifests, and shadow exports
are scoped to that immutable cohort, so records from another milestone cannot
satisfy its gates.
Only the latest draft version for each candidate can enter a cohort or shadow
export. A repaired or replaced draft therefore invalidates approvals attached
to an older version instead of silently falling back to them.
The cohort also pins each candidate's draft hash, source snapshot, parser section,
source-registry version, and extraction-pipeline version. If any current lineage
no longer matches those pins, pending or completed quality work is marked
`invalidated`, an immutable audit event is recorded, and release generation fails
closed. The same release ID cannot be silently rebuilt around replacement data.

## Release Boundary

Releases are allowed only at 5,100, 51,000, and 600,000 unique primary candidates.
Program quotas differ by at most one. Source scarcity is reported instead of being
filled with unofficial or unsupported material.

Every release remains:

- `runtime_activation: false`
- `proof_binding: false`
- `production_usable: false`

Policy approval and legal verification must be performed by different reviewers.
A source or draft hash change makes earlier decisions inapplicable. Even a fully
reviewed record is only `legally_verified_shadow`; R5 requires a separate release.

## Paused Checkpoint And Medicaid Core V1

Paid inference is paused at the current federal checkpoint. The durable PostgreSQL
queues remain resumable; pausing does not delete pending, failed, completed, or
leased work. Expired leases may be returned to `pending`, but checkpoint generation
does not enqueue, retry, materialize, or execute inference.

The NC/GA/CA Medicaid Core V1 registry is an additive source-only supplement. It
adds 15 deterministic official source roots without deactivating the federal source
registry or creating snapshots, fetch jobs, candidates, drafts, or reviewer tasks.
California anti-bot responses and SPA shells remain adapter-required discovery
roots and are not captured legal evidence.

```bash
python -m gov_rules_kg.main --workdir . state-medicaid-sources-sync
python -m gov_rules_kg.main --workdir . rules-checkpoint
```

`rules-checkpoint` writes `reports/rules_corpus_checkpoint_v1.json`. The report is
deterministic for a fixed database state and includes all 51 programs, queue states,
provenance coverage, conflicts, review and quality status, Medicaid state/family
coverage, source-registry hashes, and its own canonical SHA-256. It is not a corpus
release and never changes runtime or proof behavior.
