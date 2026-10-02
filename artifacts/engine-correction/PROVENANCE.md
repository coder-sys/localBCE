# Provenance: blind_financial_correction.exe

`blind_financial_correction.exe` is the Lean/Lake executable of the integ2 re-pin below: two fresh `git archive ee97ca0 lean` stage builds
(lean tree `e0751fe4887d4e69e020479101e4b8b7df78a7b7`), byte-identical. The release producer has NOT run on this tree; its last receipts are on the partials tree, below.

- Size: 6,433,792 bytes
- SHA-256: `874E2A37123E3B3EA5AD6E96DEE9DD066C596029D5268EF9FE6F3AF6A278323F`
- Toolchain: `leanprover/lean4:v4.33.1` (Lake, no package dependencies).
- Retired (2026-09-30, rule `h1-v1`, in `RETIRED_PINS`): `1A5821FA...DDBE`, 6,298,112 bytes, recoverable at `3ff5c9e`; `D5A06E9F...0CBB`, 6,298,624 bytes, recoverable at `824280b`. `FB659DA3...A785`, 6,300,160 bytes, recoverable at `84f3044`; `2CD5822D...1E58B`, 6,298,624 bytes, recoverable at `6326b9d` (retired 2026-10-01). `441EB3E8...F4A8A`, 6,431,232 bytes, recoverable at `a62906f` (retired 2026-10-01). `C6177355...12DCC`, 6,433,792 bytes, recoverable at `06e0b21` (retired 2026-10-02).

## integ2 re-pin (2026-10-02, rule `h1-v1`, no money or format change)

Why it moved: `Sha3.lean` gained private fill/size lemmas and `sha3_512_toList_length` (proofs, no code) and `WorkerLaws.lean` changed theorems only; the correction closure imports `Sha3`; the exe has the same size and a different layout (not attributed further). The worker did not move (`36D3FE0C...1AEA`).
Evidence: two fresh `git archive ee97ca0 lean` stage builds (`C:\Users\neers\rrb\le\stage-i2-c` and `-d`; guard suffixes `i2-stagec`, `i2-staged`, five targets, exit 0) gave this exe byte for byte, equal to the in-tree build (`i2-full2`); an earlier pair at 99b8b06 (`i2-stagea`, `i2-stageb`) gave the same bytes. Differential `bench/correction_repin_diff.py` (suffix `i2-rdiff`), `C6177355...12DCC` against this exe on the 52 requests the acceptance and constitution suites send, each with a trailing byte, truncations, bit flips, 0xFF overwrites, insertions, deletions and 0xC0 in strings: `SUMMARY captured=52 runs=11646 mismatches=0`. The vectors below are unchanged. No release-producer receipt was made for this pin.

## m3-step2 re-pin (2026-10-01, rule `h1-v1`, no money or format change)

Why it moved: `Evaluation.lean` gained `caseStatusFrom` and `Financial/Types.lean` gained `envWellFormed` (m3-step2 C1, shared with the payment step); the transition is unchanged. The exe is 2,560 bytes larger.
Evidence: two fresh `git archive 1168909` stage builds (`m3s2-stagea-a1-L2`, `m3s2-stageb-a1-L2`; `lake build` of `blind_financial_worker blind_financial_correction gate_verify gate_axioms blind_financial_axioms`, 104 jobs, exit 0) gave this exe byte for byte; gate_verify (`9bd2602b...`) did not move and the worker moved (`36D3FE0C...1AEA`, `../engine-evaluator/PROVENANCE.md`). Differential `bench/correction_repin_diff.py` (log `m3s2-rdiff-dev-a1-L2`), `441EB3E8...F4A8A` against this exe on the 52 requests the acceptance and constitution suites send, each with a trailing byte, truncations, bit flips, 0xFF overwrites, insertions, deletions and 0xC0 in strings: `SUMMARY captured=52 runs=11646 mismatches=0`. The vectors below are unchanged. No release-producer receipt was made for this pin.

## Cursor-decoder re-pin (2026-10-01, rule `h1-v1`, no money or format change)

Why it moved: `CorrectionTransition/Runtime.lean` decodes the request with `Cursor.decodeCorrectionTransitionRequest` over the stdin byte array (one parse in place, plus one `List UInt8` and a list re-encode for the canonical check), proved equal to the list decoder (`decodeCorrectionTransitionRequest_eq`, pinned in `AxiomCheck.lean`); the exe is 132,608 bytes larger.
Evidence: two fresh `git archive 7b47660 lean` stage builds (logs `bf1m-stagea-a5-L2`, `bf1m-stageb-a1-L2`, five targets, 94 jobs, exit 0) gave this exe byte for byte, equal to the in-tree build (`bf1m-full2-a2-L3`); gate_verify (`9bd2602b...`) and the worker (`86299A0D...`) did not move. Differential `bench/correction_repin_diff.py` (log `bf1m-rdiff2-dev-a1-L1`), `2CD5822D...1E58B` against this exe on the 52 requests the acceptance and constitution suites send, each with a trailing byte, truncations, bit flips, 0xFF length overwrites, insertions, deletions and 0xC0 in strings: `SUMMARY captured=52 runs=11646 mismatches=0`. No release-producer receipt was made for this pin.

## Core-thm re-pin (2026-10-01, rule `h1-v1`, no money or format change)

Why it moved: `Transition.lean` gained eight `CorrectionMutationLinkFacts` fields (proofs, not code) and lost the unreachable
`pack.status != APPROVED` refusal (`controlPackWellFormed` already demands APPROVED); the exe is 1,536 bytes smaller (not attributed further).
Evidence: two fresh `git archive 7dde24e lean` stage builds (`C:\Users\neers\rrb\le\stage-ctm-a` and `-b`; guard logs `ctm-builda-a1-L3` and `ctm-buildb-a1-L3`,
`lake build -d` of `blind_financial_worker blind_financial_correction gate_verify gate_axioms blind_financial_axioms`, 87 jobs, exit 0) gave this exe byte for byte; gate_verify
(`9bd2602b...`) and the worker (`86299A0D...`) did not move. The re-pin differential (`bench/correction_repin_diff.py`, guard log `ctm-rdiff1-dev-a1-L1`, the trunk
`5e2e552` exe `FB659DA3...A785` against `bench/ct-new-2cd5822d.exe`) sent the 52 BLFCMD03 requests the acceptance and constitution suites send, each with a trailing byte,
eight truncations and 32 bit flips: `SUMMARY captured=52 runs=2184 mismatches=0`. The vectors below are unchanged. No release-producer receipt was made for this pin.

## One-Keccak re-pin (2026-09-30, rule `h1-v1`, no money or format change)

`BlindLedger.Keccak` is deleted; `Sha3.lean` is the one sponge, so the transition compiles a different `sha3_512` body. Stage builds `kd-stagea-a1-L3` and
`kd-stageb-a13-L1` (75 jobs, exit 0) are byte-identical and equal the in-tree build `kd-dev5-a1-L3`; the vector files below are unchanged.

## Partials re-pin (2026-09-30, rule `h1-v1`, no money or format change)

Why it moved: `lean-partials-v1` replaced the worker CLI's read loops with the total `readUpTo` (commit A, shared by the
correction CLI) and range loops in the gate and Keccak (commit B); ea42222 changed `FastEncode.lean`, which this exe does not import.
The transition and reuse vectors are byte-identical (`request.bin` `234FDF65...E666`, `result.expected.bin` `83BB53D1...E0D6`,
reuse request `9C203F6B...5B99`, reuse result `973B0CA0...8E4B`), so the amount rule and every digest are unchanged.
Evidence: two fresh `git archive` stage builds of `351cfa0` (`prtb2-stagea-a1-L3`, `prtb2-stageb-a1-L3`) and of `117ad71`
(`prtb-stagea`, `prtb-stageb`) gave this exe byte for byte; the release producer (SHA-256
`61AEB3A85B2DA8E0DBD3A5BC5BC03345B471B037C99C36FE94E4E9E6A31DC909`) then reproduced it on `98b22ce` (a merge of trunk `381767b` that
left `lean/` unchanged), guard log `prt-pin1-a1-L*` (v10 away mode, `-MinFree 4029372048`, inner start floor 4,190,433,321).
Receipt `C:/Users/neers/rrb/engine-release-partials-p1/provenance/engine-build-receipt.json` (SHA-256
`B51AC61815683236A7F28FDFF2A1F443A9AED724DE91E58DFED8B90CB28A087A`; schema `RR/LEAN-ENGINE/BUILD-RECEIPT/v2`, status PASS, git status
empty, all exits 0, cleanup PASS, mutex RELEASED, minimum free 4,725,374,976 bytes); source manifest `source-manifest.json` SHA-256
`B4CB694B5EBA48E512E40A63DF1FFAF402FBB87C3ECEAF4FF95D2DDB5C275ABC`. Direct-lane grant: `lead-2026-09-30-partials-task-message`.
Repeated twice more with the same exe bytes and source manifest SHA-256 `B4CB694B...5ABC` (git status empty, PASS, cleanup PASS, mutex RELEASED): on `57634db`
(guard log `prt-pin2`, output `C:/Users/neers/rrb/engine-release-partials-p2/`, receipt SHA-256 `822ACBEC...9437`, minimum free 4,618,555,392 bytes) and on the final tree
`c7f8615` (lean tree `000358bc...`; review added `ReadUpTo.lean` to the semantic manifest and pinned its hash): guard log `prt-pin3`, output
`C:/Users/neers/rrb/engine-release-partials-p3/`, receipt SHA-256 `5CE91D94AAC4B54BFE622961B9984810E2E73B16DFECA9ECFA127B9A9BDBB2F8`, minimum free 5,063,761,920 bytes.

## Paid-sum re-pin (2026-09-29, rule `h1-v1`)

Lean derives each correction request's paid-so-far from linked payment rows (BLFCMD03);
BLFCRES3 and every digest are unchanged (record: `docs/CORE_REDESIGN.md`). Two builds by
`tools/build_financial_correction_release.ps1` (SHA-256
`61AEB3A85B2DA8E0DBD3A5BC5BC03345B471B037C99C36FE94E4E9E6A31DC909`) through the v4 guard, in
`C:/Users/neers/rrb/engine-release-lpsb-a2/` and `-a3/`, gave byte-identical executables.
Their receipts record HEAD `40e802f`, a dirty tree (git status SHA-256 `AD016F0A...DEEF`) and one
53-file source manifest (SHA-256 `38EC61E74F5EB10CAD039E0188A6C202989B8F36BEA6E7EE00BF4E946B28C14A`)
whose every file equals the same path at `1e74852`. Both reproduced the unchanged result and reuse
vectors (empty link list); only `request.bin` changed. `1A7A1833...D3AF` is in `RETIRED_PINS`.
Those builds were not made from the current trunk `lean/` (51 files: the gate and quick-wins
changes since). Rebuild `lpsm-pin1` (2026-09-30) built nothing: v4's 4.19 GB start floor was unmet.

## Reproduction of the retired pin `1A7A1833...D3AF` (2026-09-26)

This section, with the r67-r88 records below it, concerns the RETIRED h1 executable, not the
current pin. That day's pinned bytes were reproduced from commit
`61a24519c2d52a963769f663beec476fd6b66c8a`, Lean tree
`29a06cbdc92fb40e0b7e0da01ef0c02d90629769`; no executable or retired-pin entry
changed. Protected change record: `docs/CORE_REDESIGN.md`.

`tools/build_financial_correction_release.ps1` (SHA-256
`BE4B0B295D057EF8C8B7C1C5AEFA8925A476C03AFEEFE39CBC7F86ED2A34F445`)
built `blind_financial_correction` in a new isolated stage. Release evidence is
at `C:/Users/neers/rrb/engine-release-cx-r67-a1/`:

- 46-file source manifest: SHA-256
  `0BDE4F74BD9A73D48E95B82FAD6AC809D0FEAEE9A5C3E9FC8DAF621682EBD901`.
- Build receipt: SHA-256
  `DDFAC66B5DE7D247ED9A2363726377CC32860993DBA4D4AB73A9877D526D4B3B`.
- Guard and child exited zero; cleanup PASS and mutex RELEASED. Start floor
  4,190,433,321 bytes; measured minimum free 3,365,908,480 bytes; the unchanged
  running floor was 2,190,433,321 bytes.
- Transition output: 5,099 bytes, SHA-256
  `83BB53D184B0B7D9268B565B844ECE9D6943C37DD022E2D361F735A4C835E0D6`.
- Reuse output: 53 bytes, SHA-256
  `973B0CA003384170C5031B0E32295E02D8F34D80BFE095B30DE6142DBD378E4F`.

Both outputs equal the expected files. Four vector inputs were used;
`result.actual.bin` and `run-vectors.cmd` were ignored (recomputed output and a
launcher are not input data).

The separate guarded r68 build in that same fresh stage compiled all six targets:
`BlindLedger blind_semantic_kernel blind_financial_axioms
blind_financial_correction blind_financial gate_rules` (87 jobs, exit zero,
cleanup PASS). It emitted 21 linter warnings and printed diagnostic native axioms;
compilation does not establish that all declarations have approved axiom closures.
Guarded r69 passed the 30 evaluator, 18 decision-package and 42 correction KATs,
plus the 210 and 3,616 gate-rule vectors, with no failed case and cleanup PASS.

Guarded r70 independently rebuilt the financial CLI from a clean checkout of
the exact commit above. The unchanged semantic manifest (SHA-256
`6606918908b28a5b8478d73719d8fcf6ddeb616c7c0151bd77a9c1c0912cec2c`)
passed all 18 selected correction declarations: source statements, fresh
`lean --trust=0` proof-body checks, axiom closures and the pinned `leanchecker`.
Its 28-file source scan found zero forbidden tokens; all 42 correction KATs
passed. The fresh 7,471,104-byte financial CLI has SHA-256
`942B1EBC0CB30CF3AEF5695C4B0C1530FD5A7B36EFADACB2F551D48797F07AD3`.
The complete receipt and checker outputs are in
`native/guard/guarded-command-cx-lean-assurance-r70-a1.stdout.log`.
This proof claim covers those 18 declarations, not the diagnostic native-axiom
theorems elsewhere in the library. Guard/child exits were zero, cleanup PASS.

### Canonical release and offline kit

r75 refused packaging r67 because the producer sorted Windows backslash paths
before converting them to portable paths. Independent inspection found all 46
path/size/hash tuples identical (730,014 source bytes); only 14 positions moved.
The r67 manifest and logs remain unchanged and are not a kit-compatible handoff.

The corrected producer normalizes before ordinal sorting. Its SHA-256 is
`A073CA149B65B8AD94991A398B507F1CC56FEF570F5B567447EB29D255D25BF5`.
A separate fresh build in `C:/Users/neers/rrb/engine-release-cx-r77-a1/`
reproduced the same pinned executable and both vector outputs (32 build jobs):

- Canonical 46-file source manifest, 7,399 bytes: SHA-256
  `6B4B8BDCAC316F8BD3149B2078F574765C212C0D7D8D0B9D9C52F9BEF6454ED0`.
- Build receipt: SHA-256
  `779BE63EC0D024169FB9B53F269646A13AC46CB2D482CD18CD050DB7D946D3CB`.
- Guard stdout: SHA-256
  `E8E5B45583E9F300D5F9F53ADA9D2C2E6EBA5C11606CA3EE5C61FF30DE45EEDD`.
- Guard/child exits zero; cleanup PASS, mutex RELEASED; minimum free
  3,271,634,944 bytes against the unchanged 2,190,433,321-byte running floor.

r78 refused the kit because its guard-log parser rejected CRLF record endings.
Only the three line-ending patterns changed; every policy, resource, exit,
cleanup, mutex and byte-hash binding remains. The regression covers two valid
line-ending forms and 33 adverse cases, the producer's binary I/O, empty streams
and an independently built canonical source manifest. r79 passed all 24 kit,
size-budget and protected-invariant tests (zero skips/errors); both changes had
independent read-only review.

Guarded r80 assembled, hashed, verified and extracted
`C:/Users/neers/rrb/service-kit-cx-r80.zip`: 65,753,878 bytes, 2,673 members,
SHA-256 `6D937707EBFF20592199271C2F589325BB5ECFF030646A17CD03493CAD57A622`.
Its bundled CPython ran the correction/lost-response/exact-retry/SHADOW
restore scenario: one correction commit, sequence 50 to 51, duplicate retry
with no second write, integrity VERIFIED, replacement refused.
1,625 third-party `Lib/site-packages` files were excluded; Queue remains
omitted because no source-bound Queue runtime handoff exists.

Guarded r84 ran the extracted kit's `serve` command twice: HTML and workspace
HTTP 200, integrity VERIFIED, owner/epoch/sequence/history head unchanged on
restart, engine workspace empty. Each owned server was deliberately terminated
for restart (exit -1 / unsigned 4294967295) and the wrapper's post-stop checks
completed; check and guard exited zero, cleanup PASS. Earlier r81-r83
smoke-harness failures are retained: missing exception property, startup
timeout classification, then a buffered diagnostic print used as a resume
signal. r84 checks the actual child resume argument. No product gate was relaxed.

The extracted runtime also passed the durable process-restart test in r85: a Lean
correction and linked cash commit survive reopening, same owner/epoch/sequence/
history head, exact received cash, zero shortfall, VERIFIED (1/1, zero
skips/errors); all six size gates passed. The enclosing r85 run then failed in an
auxiliary count-print command (unmatched parenthesis) and is not a pass. The
corrected count-only r87 run exited zero, cleanup PASS: 154 code files, 78,975
lines against the then 80,000-line total cap.

That test's child also wrote nine Python bytecode files under `app/__pycache__`
in the r80 extraction; r86 refused its changed membership before starting a
server (extraction and failure preserved; the archive is unchanged). Guarded r88
freshly extracted the same archive into `C:/Users/neers/rrb/service-kit-cx-r88/` and
repeated both serve cycles with the hardened harness (it keeps the verified child
identity before HTTP, rejects HTTP errors at once, and leaves the parent to guard
cleanup if child ownership or termination is unproven): zero readiness retries,
HTTP 200, VERIFIED, unchanged owner/history, empty engine workspace, post-stop tree
verified, exits zero, cleanup PASS. The r88 extraction is the clean handoff.

The kit binds the complete working-tree inventory at assembly, including frozen
connector/browser candidates. These Lean and service checks do not establish
exhaustive browser conformance or qualify those other tracks.

Source binding (2026-09-28, rr-review H1; XI.2 record in `docs/CORE_REDESIGN.md`).
r80 was assembled from an uncommitted tree, so r80/r84/r85/r88 are not evidence
for `86390ab`. Compared file by file (CRLF-normalised), the r80 archive equals
commit `707ba78`: all 46 `engine/source` Lean files and 26 of 27 `app`/`tools`/
`tests` files. The exception is `app/right_rail_financial_engine.py`, which is the
`86390ab` version; `707ba78` replaces its 21-line reject-requirement literal with
an equal map derived from the tag tables. No pin, digest or vector changes.

## Vectors

- `vectors/request.bin` (BLFCMD03; was BLFCMD02 `B658DCEE…D067`, only the magic and version differ) SHA-256 `234FDF65E630E41D38E1ECA1CC674845969ED35B409AEB12CB41E3116487E666`
- `vectors/result.expected.bin` (BLFCRES3) SHA-256 `83BB53D184B0B7D9268B565B844ECE9D6943C37DD022E2D361F735A4C835E0D6`, produced by
  the first build's executable from `request.bin` with
  `vectors/run-vectors.cmd <exe> <request> <output>` under the guard.
- `vectors/result.actual.bin`, produced the same way by the second build's
  executable, is byte-identical to `result.expected.bin`.

The BLFCMD02-era pin `349BED31…` was never released, so it is not in `RETIRED_PINS`.

## Reuse-v2 conformance fixture (2026-09-26)

Protected change record: `docs/CORE_REDESIGN.md`, current-engine service-kit
connection. This fixture's expected assessment was independently derived and
reviewed before running the engine. Guarded comparison passed in
`native/guard/guarded-command-cx-package-fixtures-r4-a1.stdout.log`
(`test_current_engine_matches_independent_reuse_vector`, within 19/19 tests).
This verifies the existing pin's baseline vector, not a new-source rebuild.

- Request: 9,204 bytes, SHA-256
  `9C203F6BF50DA69D9D77CAFC4ADBF7BD3628724DFABF87E69E141A319F185B99`.
- Expected: 53 bytes, SHA-256
  `973B0CA003384170C5031B0E32295E02D8F34D80BFE095B30DE6142DBD378E4F`.
- Complete expected hex:
  `424C4643525630320002002052522F46494E414E4349414C2F434F5252454354494F4E2D52455553452F7631010001000100020000`.

Let `old` be the 9,887-byte reuse request at main `6cccb84`, SHA-256
`DD7DDC27FEEDFDFD26540AB6B1F7D37E6BE49768583FB1EA3AB02F85C8390DC6`;
let `accepted` be the 5,099-byte current `result.expected.bin` pinned above.
Using zero-based, half-open byte slices, the new request is exactly:

```python
b'BLFCRU02' + b'\x00\x02' + old[10:44] + (5099).to_bytes(4, 'big') + accepted + old[5637:9117] + old[9182:9216] + old[9344:9887]
```

This preserves input, receipt, determination, outbox identity and all three
query observations, removing only the old determination digest and outbox
payload/idempotency digests removed by ReuseCodec v2. Queries bind sequence 11,
head `2B` repeated 64 times, and time `1774922400021`. The baseline assessment is
valid calculation, valid approval, allowed local execution, deadline reached,
no watermark advance and no dispatch. It makes no claim about changed paid
history or the known stale-shortfall reuse limitation.

## Retired pins

`RETIRED_PINS` lists engines a re-pin retired, one per line: SHA-256, retire
date, retiring commit, amount rule, reason (tab-separated, append-only). A
correction follow-up already committed under one of them stays valid history,
judged by that engine's amount rule (`correction-rule-v1`: the whole claim;
`b2-v1`: min(claim, shortfall)); only the pin above (rule `h1-v1`) decides new
work. Every correction must also stay within the unpaid shortfall no earlier
request still asks for, and an obligation's corrections never name an older
engine after a newer one. The
independent checker pins the file's SHA-256, so appending a line means
updating `RETIRED_PINS_SHA256` too.

## Status

Synthetic evidence only. Non-activating and non-payment:
`proofSuiteId=null`, `production_usable=false`, `activation=false`.

## Reproduction on the lean-leak tree (2026-09-30)

Superseded by the partials re-pin above: two fresh stage builds of `b6bc647` reproduced the then pin `1A5821FA...DDBE` (6,298,112 bytes, guard logs `leakint-stagea-a1-L1`, `leakint-stageb-a1-L1`). Its producer receipt was never made; that pin is retired.
