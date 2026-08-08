# Phase 1 first major hardening and convergence run — 2026-07-13

Historical-status note (2026-07-22): this log is preserved as execution chronology. Its
then-selected monolithic application-specific AIR direction has since become the semantic half of
the heterogeneous proof in `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`; the shared-bus
Boolean SHA3 coprocessor is now the active physical implementation path. Solidity, Foundry, and
on-chain settlement references below describe deleted historical work and are not current
requirements.

Status: **the first major run completed to an explicit RED/no-go; the complete private proof and
roadmap are not complete**.

This is the durable recovery record for the run. It uses synthetic data only. It does not authorize
real PHI, production settlement, a witness-hiding claim, a strict post-quantum claim, or a claim
that the approximately 11ms prototype is the final proof.

## Plain-English outcome

Nothing silently escaped the gates. The gates found that a formatter had changed
security-governed Rust bytes, seven synthetic identities were invalid under the strengthened NPI
rules, and the RISC semantic reference still used an older oracle-root construction. Execution
stopped, the governed source was restored from rollback, the synthetic fixtures were corrected,
the reference model was reconciled, and every affected gate was rerun.

The approximately 17-hour projection was not the unavoidable cost of proving one claim. It came
from asking a general-purpose RISC-V virtual machine to repeat an extremely expensive computation.
The selected production direction is a bounded, application-specific claim AIR. A narrow
six-column, 1024-row S-two prototype proves and verifies its limited decision/value statement in
about 11ms internally. That is the zero-to-one architecture result: the wrong abstraction was
removed and the narrow replacement is fast.

It is not yet the complete result. The prototype omits complete claim semantics, governed roots,
attempt and cover nullifiers, the exact 12-field statement, audited witness hiding, authoritative
SHA3-512 state, and the `BL-PQ512-v1` transcript/PCS. Native hiding and the complete constraints
will add cost that cannot honestly be estimated until they exist. Therefore no final proof-time or
proof-size target has been achieved or promised.

## Non-negotiable external ABI

The external Privacy V2 ABI remains exactly these 12 ordered fields:

1. `protocolVersion`
2. `settlementDomain`
3. `batchNonce`
4. `nullifierRootBefore`
5. `nullifierRootAfter`
6. `claimSourceRoot`
7. `oracleFactsRoot`
8. `policyRoot`
9. `rulesetRoot`
10. `opaqueBatchCommitment`
11. `valueConservationCommitment`
12. `settlementCommitment`

Focused ABI output was `8 passed in 0.23s`. Count, order, names, types, and the forbidden-public-
field boundary were preserved.

## Source recovery and security evidence

- At execution time, the pre-fix source recovery set reconciled `486` source files and
  `4,147,266` bytes with `0` SHA-256 mismatches. Its redundant local copy was removed on
  2026-07-22; it is not a current recovery path.
- Security snapshot:
  `codex-security-snapshot/v1:sha256:586d65b92d52fb67fb41c27903eef9811416dd6ee206186471e7873a88e4987b`.
- Security scan: `120/120` full-file receipts, `31` candidate IDs, `0` missing, duplicate, or
  skipped candidates.
- Validation: `16 reportable`, `14 suppressed`, `1 deferred`.
- Attack-path result: `10` final reportables (`4` medium/P2 and `6` low/P3) plus `6` ignored
  hardening paths.
- Current remediation state: `8/10` final reportables remediated, `R25-C01` partially hardened but
  still open, and `R23-C02` open. `R02-C03` remains deferred rather than guessed closed.
- Detailed post-scan evidence was originally written to a generated cache artifact that is not
  packaged; this log preserves only its recorded conclusions.

Important repairs include strict ASCII/check-digit NPI handling; bounded EDI, segment, service-line,
claim, envelope, and queue inputs; atomic portal attachments and state; server-owned claim/payment
transitions; globally unique fail-closed credentials; authorization before KMS/decryption;
authenticated replay reservation; canonical Base64 release scanning; fresh execution provenance;
synthetic-only aggregate profiling; real launch-blocker readiness checks; oracle-root convergence;
Merkle proof metadata repair; and complete Python nullifier-transition validation.

## The mismatch incident and repair

The first complete Python attempt after hardening reported:

```text
9 failed, 473 passed, 63 warnings, 128 subtests passed in 676.41s
```

The nine failures reconciled exactly:

- seven governed-attempt fixtures used the invalid synthetic NPI `1234567890`;
- WSL Rust 1.97 formatting changed governed rules-engine source bytes, changing the governed source
  hash and downstream ruleset/public-input pins;
- the RISC semantic model still used old signer/evidence-root semantics.

Repairs were narrow:

- the three governed rules-engine Rust files were restored byte-for-byte from the verified rollback;
- the synthetic fixture NPI became the valid `1999999984`;
- the RISC model was bound to the canonical signer root and encoded the full 256-bit evidence root
  as two `u128` limbs instead of attempting to force it into one field;
- independently derived oracle/public/claim/batch known-answer values and high-width regressions
  were added.

The decisive complete-claim Python/Cairo/RISC differential then reported:

```text
1 passed in 160.65s
```

All three implementations agreed on the 12 public fields and the checked private-claim semantics.
No modulo/truncation repair or ABI change was used.

## Final gate evidence

| Gate | Final result | Qualification |
| --- | --- | --- |
| Python non-attack lane | `483 passed`, `63 warnings`, `128 subtests passed in 602.04s`; wall `604.571s` | Passed |
| Separate attack lane | `94 passed`, `31 warnings`, `36 subtests passed in 39.02s`; wall `40.725s` | Passed |
| Unique Python top-level tests | `577` (`483 + 94`) | Attacks were not duplicated |
| Privacy V2 ABI | `8 passed in 0.23s` | Exact 12-field boundary preserved |
| Complete semantic differential | `1 passed in 160.65s` | Python/Cairo/RISC agreement |
| Rust rules engine | `44` tests on Windows and `44` on WSL | Check/tests passed; WSL Clippy passed |
| RISC semantic model | `43` tests on Windows and `43` on WSL | Check/tests passed; WSL format/Clippy passed |
| Custom S-two prototype | `4` tests on Windows and `4` on WSL | Package-only format/check/Clippy/test on WSL |
| Cairo | format/build/test; `9` declarations reported passed | Native bodies are empty; meaningful coverage is Python-driven executable KATs |
| Solidity | `26` files compiled with Solc `0.8.24`; `23 passed`, `0 failed`, `0 skipped` | Forge 1.7.1 clean build/test |
| Operations mirror | `14/14` files compared; `0` missing, `0` mismatched | Passed |
| Clean privacy target | `privacy_findings=0` | Empty controlled target only |
| Development-tree privacy scan | `privacy_findings=567`, exit `1` | Correct expected rejection; not a privacy pass |
| Release builder | `release_status=blocked reason=release manifest is missing`, exit `1` | Correct no-go; no archive created |
| Installed dependencies | `No broken requirements found.`, exit `0` | Current environment only |
| Offline/no-download dependency dry run | exit `0` | Direct pins resolve from installed environment |
| Python syntax | `PYTHON_SOURCE_FILES=133`, `PYTHON_COMPILE_FAILURES=0` | In-memory compilation; no bytecode created |
| Portal JavaScript syntax | `JS_FILES_CHECKED=2`, `JS_SYNTAX_FAILURES=0` | Node syntax check |

The release-builder result reconciled as:

```text
MANIFEST_EXISTS=False
release_status=blocked reason=release manifest is missing
EXIT_CODE=1
OUTPUT_EXISTS=False
```

The development-tree privacy findings reconciled exactly:

```text
development_tree_privacy_findings=567
encoded_container_not_privacy_scanned=1
forbidden_artifact_reference=7
forbidden_json_key=1
host_private_path=9
opaque_file_not_privacy_scanned=6
plaintext_x12_837=3
private_key_material=3
sensitive_plaintext_assignment=41
unapproved_json_artifact_schema=12
unapproved_text_artifact_present=455
unscanned_directory_present=29
```

The categories sum to `567`. The development tree intentionally held rollback, security evidence,
synthetic attack fixtures, and generated metadata; it was never release staging.

Warnings are not counted as passes. Python warnings were a framework deprecation plus explicit
local-only fallback warnings. Cairo emitted its current test-runner deprecation warning. Solidity
emitted its current `block.timestamp` timelock warning.

## Toolchain fingerprints and unresolved formatter gate

```text
Python 3.14.4
pip 26.0.1
Windows rustc/cargo 1.96.0
WSL rustc/cargo 1.97.0
WSL nightly rustc 1.90.0-nightly (2025-07-13)
Scarb/Cairo 2.18.0
Forge 1.7.1
Node 24.16.0
```

Rust rules formatting is not green under one governed toolchain. WSL Rust 1.97 would rewrite
governed source bytes; Windows Rust 1.96 lacks the required formatter/component set. The correct
response was to restore the governed bytes, not silently reformat or rebaseline their security
hash. Rust check/tests passed on both environments and WSL Clippy passed, but S11 toolchain and
reproducibility work remains open.

Direct Python dependencies are now version-pinned, and the installed/no-download gates pass. This
does not close `R25-C01`: a reviewed, platform-specific lock with hashes for every transitive
artifact is still missing.

## Exact performance and test-process audit

The stopped RISC Zero profile reported `191` segments, at least `199,229,440` guest cycles, and
`17` observed intervals totaling `5,464s`. Linear projection was `61,389.647059s`, or
`17.052680h`. This was an interrupted-run projection, not a completed proof.

The narrow S-two prototype's 20 warm measurements reported:

| Measurement | Result |
| --- | ---: |
| Proof-pipeline mean | `10.977ms` |
| Internal prove-plus-verify mean | `11.584ms` |
| Verification mean | `0.299ms` |
| Process wall mean including startup | `71.432ms` |
| Process wall median | `48.581ms` |
| Process wall p95 | `83.842ms` |

Internal pipeline attribution was `1.062%` twiddle preparation, `0.379%` trace construction,
`23.181%` commitment, `3.703%` interaction, and `71.675%` core proving. Verification was `2.585%`
of internal prove-plus-verify time. These numbers describe only the incomplete prototype.

For software qualification:

- the complete Python/Cairo/RISC differential took `160.65s`, which is `26.684273%` of the final
  `602.04s` non-attack wall time under a simple ratio;
- the historical `112.04s` 10,000-case Poseidon path-index check would be `18.610059%` of that
  final wall time if unchanged; because it was not independently re-timed in the final run, that
  percentage is conditional;
- together those two checks would conditionally represent `45.294333%`;
- readiness-test time fell from `97.21s` to `0.22s`, a `99.773686%` reduction and
  `441.863636x` speedup, while preserving the no-go decision;
- running a collection that already includes attacks and then rerunning attacks would duplicate
  `94` tests and `39.02s`, approximately `5.738%` of that double-run schedule. The final schedule
  avoided the duplication.

Tests do not make a proof slower. They make engineering feedback slower. Removing necessary tests
would reduce confidence without changing prover arithmetic. The efficient schedule is:

1. per edit: focused tests for the changed component and its negative cases;
2. per language boundary: that language's complete suite plus relevant KATs;
3. per commitment/root/encoding change: the slow RISC differential, 10,000-case property check,
   cross-language parity, and attack subset;
4. final candidate: every regression, attack, Rust, RISC, S-two, Cairo, Solidity, privacy, release,
   mirror, provenance, and toolchain gate sequentially;
5. proof campaign: only after the complete proof architecture and independent verifier exist.

The dirty development tree need not be rescanned after every edit because its expected 567 findings
do not move the release boundary. The exact clean staging tree and every generated artifact/log must
always be scanned. Clean builds on both supported platforms belong to convergence/final lanes, not
every edit. No acceptance criterion is weakened.

Coverage remains too weak in the places that matter most: the nine empty native Cairo test bodies;
no complete fixed-shape AIR; no audited hiding layer or unlinkability campaign; no strict-PQ
PCS/transcript/FRI parameters; no authoritative SHA3-512 sidecar/state; no real Solidity/native
proof verifier; no independently provisioned verifier or digest-pinned proof toolchain; no
production malformed-proof fuzzing; no 124-proof campaign; no independent cryptographic,
implementation, privacy, or side-channel audit; and no production PQ KMS/HSM, governed signer
registry, or real source/payment integration.

## Workspace cleanup and orphaned load

Before cleanup:

```text
files=49174
directories=8618
bytes=18447368219
```

An exact read-only audit classified 30 literal roots as generated output: 22 build/cache paths plus
eight non-rollback Python caches. Every path resolved beneath the workspace, no candidate or
descendant was a reparse point, and no build/proof process was active at deletion time. The exact
`R:` workspace mapping was verified and removed first.

Cleanup result:

```text
PREFLIGHT_PATHS=30
PREFLIGHT_STATUS=PASS
DELETED_LITERAL_PATHS=30
CLEANUP_STATUS=PASS
removed_files=47448
removed_directories=8088
removed_bytes=18430296049
after_files=1726
after_directories=530
after_bytes=17072170
```

A post-cleanup, pre-final-log-write measurement remained `1726` files and `530` directories and
measured `17084707` bytes (`16.293246MiB`). The byte increase from the immediate deletion
measurement is the durable documentation added afterward, not regenerated build output.

Vendor sources, provider packets, security scans, source, docs, tests, and the five new regression
files were preserved. The historical post-cleanup reconciliation was:

```text
cache/vendor_sources: files=1 dirs_including_root=1 bytes=496533
cache/provider_packets: files=1 dirs_including_root=3 bytes=38
cache/security-scans: files=596 dirs_including_root=174 bytes=4562702
R_SUBST_REMAINS=False
```

The redundant local rollback collection reported by the original log was removed on 2026-07-22;
Git identities and sealed manifests are the current audit boundary.

The audit also found an orphaned Python launcher, PID `68028`, started at `18:04:28` local with a
missing parent, command `python.exe -`, approximately `8310` accumulated CPU seconds, `63` read
operations, `0` write operations, no network connection, and an idle child PID `73132` at `0` CPU.
Both were stopped and verified absent. This one-core load could contaminate overlapping wall-clock
measurements, but it cannot explain the 17-hour RISC projection, which is independently grounded in
at least 199 million guest cycles. Future performance campaigns require an exclusive-host preflight.

## Release decision and remaining roadmap

Release qualification is **RED/no-go**:

- `APP_RELEASE_FILE_MANIFEST.json` is absent and no release archive was produced;
- all 10 entries in `ops/launch_blockers.json` remain open;
- the LB-010 progress narrative still describes RISC Zero as selected, although RISC Zero is now a
  semantic oracle and the selected direction is the custom S-two AIR. Correcting it requires a
  synchronized canonical/mirror update; the stale wording does not change its open status;
- `R23-C02` proof-tool digest pinning and independent verification remain open;
- `R25-C01` transitive hash-locked dependency provenance remains open;
- the governed SPHINCS+ signer registry/rotation commitment remains unspecified;
- there is no complete AIR, hiding layer, strict-PQ parameter set, production verifier, end-to-end
  settlement proof, production HSM/KMS, or independent audit.

Roadmap package `S01` is still the only closed package; `77` packages remain. Defensive application
limits and the fast prototype do not close `A01-A16`, `Z01-Z12`, or `P01-P12`.

The next large run should not be the 124-proof campaign. The safe sequence is:

1. complete review-ready internal specifications `S02-S06`;
2. prepare, but do not falsely close, dependent `S10-S11`, bounded-shape/semantics `A01-A06`, wide
   reference `P01-P02`, and vector `T01` material;
3. submit `S07-S09` together as one cryptographic feasibility/review packet covering the full
   quantum budget, M31 extension/FRI parameters, and wide PCS/transcript/tree primitives;
4. only after `S07-S12` pass, implement the separately reviewable AIR, hiding/PQ, verifier, and
   integration lanes;
5. run the 12-stage/16-gate qualification bundle and 124 fresh-randomness synthetic proofs only
   after the complete AIR, hiding layer, sidecar/state, strict-PQ parameters, and independent
   verifier exist.

## Final truth boundary

The first major hardening and baseline-convergence run is complete. Phase 1's complete private
claim proof is not. The architecture now has strong performance evidence at prototype scale and a
much safer application/evidence boundary, but final speed, witness hiding, strict post-quantum
security, production settlement, and release remain unproven. No real PHI or real payment release
is authorized.
