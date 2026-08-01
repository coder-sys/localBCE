# Proof provenance

Updated: 2026-07-22

This archive does not include generated Cairo build outputs, execution traces, or proof JSON files. Those outputs are intentionally excluded because they are large/generated artifacts and can become stale.

## Current Wave 2 proof topology

The release target is now the heterogeneous semantic-STARK/shared-bus/Boolean-GKR construction in
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. No complete K128 proof for that topology has yet
been generated. The independently verified 28,643,096-byte strict-parameter kernel remains genuine
regression evidence only; every Cairo, RISC Zero, and narrow S-two proof below remains historical or
differential evidence and is not the active release proof.

The CBAM, state-topology alternatives, conflict-DAG scheduler, WHIR/STIR bake-off, three-plane
Shout-like/Twist-like/GKR memory-proof candidate, VEIL hiding wrapper, Neo/SuperNeo or Hachi
post-K128 research, and rollup compatibility work have no proof artifact or completed K128
benchmark here. They are roadmap candidates and must not be cited as throughput, proof-size,
hiding, post-quantum qualification, or production evidence.

## Current Wave 1A host-reference boundary

The 2026-07-18 Wave 1A development convergence generated no proof. Its composed K128 relation is a
host-side reference over authenticated synthetic governed paths, internally derived A12 attempt/
cover keys, typed replay transitions,
aggregate payment state, the ordered 12 compatibility fields, and a SHA3-512 batch commitment. It
explicitly records `nullifier_derivations_authenticated=true`, `physical_air_constrained=false`,
and `production_usable=false`. The repository proof-artifact scan after convergence found zero
`*.proof`, `*.receipt`, `*.stark`, `*.trace`, or `*.wtns` files outside excluded historical scan/
release snapshots. `proofSuiteId` remains null and activation remains false.

## Sealed R25 and unsealed R26 synthetic calibration checkpoint

R25 is sealed narrow validity-calibration evidence. R26 was interrupted before terminal integrity
reconciliation: it has an initial manifest and seven stage JSON files but no terminal manifest or
terminal seal. R28 later requalified the applicable current source and gates under its own terminal
record; R26 itself remains unsealed. Neither run establishes complete-statement evidence, witness hiding, strict post-quantum
security, or production verification.

Unsealed R26 stage JSON reports 51 physical calibration proofs across K128/K256/K512. Every proof verified and was
discarded; no proof artifact was retained. Every profile used 267 trace columns, one interaction
column, and 476 constraints. Average proving time was `0.051942850s`, `0.070609592s`, and
`0.086222081s` respectively; maximum measured verification was `0.002575530s`, and maximum measured
RSS was 7,252 KiB. The kernel proves only 13-gate decision priority and limb payment conservation.
It omits the ordered 12-field complete statement, authenticated claim/oracle/policy/nullifier state,
SHA3-512 authoritative shadow state, native hiding, and the strict-PQ proof suite.

Unsealed R26 stage JSON also reports a repeat of the separate 1,024-claim custom S-two validity baseline at `0.115831s` proving,
`0.000197s` verification, and 4,084 KiB peak RSS. Its hiding-required control failed closed before
trace allocation. Both paths have `witness_hiding=false`, `proofSuiteId=null`, use synthetic data
only, and are forbidden from activation. The complete 124-proof campaign was not run. Never create
or backdate missing R26 terminal files; use the genuine R28 terminal record for the requalified
boundary.

## Historical 2026-07-09 external proof note

As of 2026-07-09, the latest local proof run recorded for this workspace was produced outside this archive with an external WSL CUDA prover build:

| Field | Value |
| --- | --- |
| External proof path at time of run | `<external-workspace>/proofs/safeopts_execution162_cuda_finalgroup_proof.json` (local username/path redacted; artifact was never packaged) |
| Proof SHA-256 | `2e6a0d5edbf8884a6da4f5476298f06a3c5e95b4a8bb9934b24c0f6b06c3ea3f` |
| Approximate proof file size | `14M` |
| Wall time recorded | `352.08s` |
| Prover source/binary packaged here | No |

This is a provenance note, not a production verifier certificate. If a current proof is required, regenerate it from this source tree and preserve the raw prover and verifier output.

## Isolated-workspace reproduction

On 2026-07-10, this isolated source workspace ran:

```powershell
python -m tools.measure_proving --claim-count 1
```

Scarb execution and proving both returned success. The generated artifact was transient and is not packaged.

| Field | Value |
| --- | --- |
| Generated execution | `execution19` |
| Witness time | `0.106396s` |
| Cairo execute time | `93.086414s` |
| Prove time | `140.681949s` |
| Proof size | `13,865,776` bytes |
| Proof SHA-256 | `2e6a0d5edbf8884a6da4f5476298f06a3c5e95b4a8bb9934b24c0f6b06c3ea3f` |
| Hash comparison | Matches the previously recorded external proof hash above. |
| Production verifier run | Not performed; this is proof-generation evidence only. |

## Historical doc note

Some protected circuit-folder notes may mention generated proof-output paths from a developer checkout. Those generated paths are not part of this source archive. The source-of-truth handoff statement is: proof/build outputs are excluded and must be regenerated locally.

## Verified serialized-runner checkpoint

On 2026-07-10, the isolated operations runner queued and completed one synthetic
one-claim proof through the supported simple bootloader. The immutable request used
eight Rayon threads, and the runner independently checked the generated manifest and
proof file before recording success.

| Field | Value |
| --- | --- |
| Job id | `first3-verified-1` |
| Queue request SHA-256 | `fd1d08aaf5b22f33614ca12773a8ba9bf10cd82b683a2abedf6c1077994e4f2b` |
| Runner state | `succeeded`, first attempt |
| Threads | `8` |
| Witness time | `0.120941s` |
| Cairo run time | `3.41s` |
| Prove/verify/serialize time | `115.0s` |
| Prover-command wall time | `120.166749s` |
| Verifier time | `0.046s` |
| Proof size | `5,591,878` bytes |
| Proof SHA-256 | `20801b8071e6fead23db5d6c3c2a2e239d33e1475756c104d3c76da9b61b0fb4` |
| Semantic output match | Yes |
| Protected Cairo source unchanged | Yes |
| Settlement-contract verification run | No |
| Generated artifact location | `../../proof-runs/first3-queue-20260710-2048/` |

The installed standalone `scarb verify` path remains unsuitable for this statement:
it panics with `ECDSA segment is not empty`. The successful evidence above comes from
the repository's official simple-bootloader runner, which invokes the upstream prover
with verification enabled. It is verifier-clean off-chain evidence, not proof that the
pinned Solidity settlement verifier accepts this proof encoding or output frame.
