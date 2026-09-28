# Provenance: blind_financial_correction.exe

`blind_financial_correction.exe` is the Lean/Lake executable built from this
repository's `lean/` source at commit `79b6913` (tree `lean/` =
`git archive 79b6913 lean`, tree id `3dba470d`).

- Size: 6,279,168 bytes
- SHA-256: `1A7A18333726484A0737DA7B005EC699F73E99EA0CFACFB409B000F964BED3AF`
- Toolchain: `leanprover/lean4:v4.33.1` (Lake, no package dependencies).

## Current-source reproduction (2026-09-26)

The existing pinned bytes were reproduced from commit
`61a24519c2d52a963769f663beec476fd6b66c8a`, Lean tree
`29a06cbdc92fb40e0b7e0da01ef0c02d90629769`. This supplements the historical
origin above; no executable or retired-pin entry changed. The protected change
record is in `docs/CORE_REDESIGN.md`.

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

Both outputs equal the unchanged expected files. Four vector inputs were used;
two non-input files (`result.actual.bin`, `run-vectors.cmd`) were ignored because
actual output must be recomputed and the launcher is not input data.

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
Only the three line-ending patterns changed; all exact policy, resource, exit,
cleanup, mutex and byte-hash bindings remain. The regression covers two valid
line-ending forms and 33 adverse cases, plus the actual producer's binary I/O,
empty streams and independently constructed canonical source manifest. r79
passed all 24 kit, size-budget and protected-invariant tests, zero skips/errors.
Both producer/parser changes received independent read-only review.

Guarded r80 assembled, independently hashed, verified and extracted
`C:/Users/neers/rrb/service-kit-cx-r80.zip`: 65,753,878 bytes, 2,673 members,
SHA-256 `6D937707EBFF20592199271C2F589325BB5ECFF030646A17CD03493CAD57A622`.
Its pinned bundled CPython ran the correction/lost-response/exact-retry/SHADOW
restore scenario: one correction commit, sequence 50 to 51, duplicate retry
with no second write, independent integrity VERIFIED, replacement refused.
1,625 third-party `Lib/site-packages` files were explicitly excluded; Queue
remains omitted because no current source-bound Queue runtime handoff exists.

Guarded r84 exercised the extracted kit's actual `serve` command twice: HTML
and workspace HTTP 200, integrity VERIFIED, owner/epoch/sequence/history head
unchanged on restart, engine workspace empty. Each owned server was deliberately
terminated for restart (server and wrapper exit -1 / unsigned 4294967295);
the wrapper's post-stop checks completed. The enclosing check and guard exited
zero, cleanup PASS. Earlier r81-r83 smoke-harness failures are retained: missing
exception property, startup timeout classification, then a buffered diagnostic
print incorrectly used as a resume signal. r84 checks the actual child resume
argument instead. No product gate was relaxed for those harness corrections.

The extracted runtime also passed the existing durable process-restart test in
r85: a Lean correction and linked cash commit survive reopening, with the same
owner/epoch/sequence/history head, exact received cash, zero shortfall and
VERIFIED integrity (1/1, zero skips/errors). All six final size gates passed.
The enclosing r85 run then failed in an auxiliary count-print command with an
unmatched parenthesis; this does not turn that outer run into a pass.
The corrected count-only r87 run exited zero with cleanup PASS: 154 code files,
78,975 lines against the founder-approved 80,000-line total cap.

That extra restart test's direct child process also wrote nine Python bytecode
files under `app/__pycache__` in the r80 extraction. r86 correctly refused its
changed membership before starting a server; the extraction and failure remain
preserved. The archive itself is unchanged. Guarded r88 freshly extracted that
same pinned archive into `C:/Users/neers/rrb/service-kit-cx-r88/` and repeated both
actual serve cycles with the hardened harness: zero readiness retries, HTTP 200,
VERIFIED integrity, unchanged owner/history, empty engine workspace and successful
post-stop tree verification. Child/guard exits zero, cleanup PASS. The harness
now retains the verified child identity before HTTP, rejects HTTP error responses
immediately, and leaves the parent available to guard cleanup if ownership or
child termination cannot be established. The r88 extraction is the clean handoff.

The kit binds the complete working-tree inventory at assembly, including frozen
connector/browser candidates. These Lean and service checks do not establish
exhaustive browser conformance or qualify those other unfinished tracks.

Source binding (2026-09-28, rr-review H1; XI.2 record in `docs/CORE_REDESIGN.md`).
r80 was assembled from an uncommitted tree, so r80/r84/r85/r88 are not evidence
for `86390ab`. Compared file by file (CRLF-normalised), the r80 archive equals
commit `707ba78`: all 46 `engine/source` Lean files and 26 of 27 `app`/`tools`/
`tests` files. The exception is `app/right_rail_financial_engine.py`, which is the
`86390ab` version; `707ba78` replaces its 21-line reject-requirement literal with
an equal map derived from the tag tables. No pin, digest or vector changes.

## Reproduced twice

Two clean builds, each in a fresh export under its own `<BUILD_ROOT>`, each
run through `native/guard/run_guarded_v4.ps1` (SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`):

    lake --dir <BUILD_ROOT>/lean build BlindLedger blind_semantic_kernel blind_financial_axioms blind_financial_correction blind_financial

Both produced `<BUILD_ROOT>/lean/.lake/build/bin/blind_financial_correction.exe`
with the SHA-256 above. `blind_financial --correction-transition-kat` passed
42 of 42 gates on the first build's executable.

## Vectors

- `vectors/request.bin` (BLFCMD02) SHA-256 `B658DCEE04138FDCBA6C9D72F3D2D044E5F596AA5794B3562A8312FBB57AD067`
- `vectors/result.expected.bin` (BLFCRES3) SHA-256 `83BB53D184B0B7D9268B565B844ECE9D6943C37DD022E2D361F735A4C835E0D6`, produced by
  the first build's executable from `request.bin` with
  `vectors/run-vectors.cmd <exe> <request> <output>` under the guard.
- `vectors/result.actual.bin`, produced the same way by the second build's
  executable, is byte-identical to `result.expected.bin`.

The request is the previous BLFCMD01 vector (SHA-256 `13F832E8…`) re-framed as
BLFCMD02: new magic and version, and an empty correction-paid list (two zero
bytes) before the input length. Against the previous result the only changes
are BLFCRES3's magic and version and the same empty list in the dependency
facts. This pin replaces `349BED31…`, which was never released, so it is not
listed as retired.

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
