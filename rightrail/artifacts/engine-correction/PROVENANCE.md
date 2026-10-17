# Provenance: artifacts/engine-correction

The one-shot `blind_financial_correction.exe` is retired (M4 P1, 2026-10-02): corrections run on the evaluator
worker (`artifacts/engine-evaluator/PROVENANCE.md`). Its last pin, `874E2A37123E3B3EA5AD6E96DEE9DD066C596029D5268EF9FE6F3AF6A278323F`
(6,433,792 bytes, rule `h1-v1`), is in `RETIRED_PINS` and recoverable at git `99ec957`, with its reuse vectors and the
per-re-pin history of this file (full text there). The worker's answers over 1,558 and 1,566 inputs equal that exe's but 361 and 27
(`tests/fixtures/correction_exe_answers.json`).

`vectors/request.bin` and `vectors/result.expected.bin` stay as the worker's known answer (`conformance/MANIFEST.sha256`).
`request.bin` binds the authority digest (ACCEPTED); `request_unbound.bin`, the old zero-digest request, answers AUTHORITY_STALE.
The independent checker's correction-engine constant is now the worker's SHA-256.

## Retired pins

`RETIRED_PINS` lists engines a re-pin retired, one per line: SHA-256, retire
date, retiring commit, amount rule, reason (tab-separated, append-only). A
correction follow-up already committed under one of them stays valid history,
judged by that engine's amount rule (`correction-rule-v1`: the whole claim;
`b2-v1`: min(claim, shortfall)); only the current pin (rule `h1-v1`) decides new
work. Every correction must also stay within the unpaid shortfall no earlier
request still asks for, and an obligation's corrections never name an older
engine after a newer one. The independent checker pins the file's SHA-256, so
appending a line means updating `RETIRED_PINS_SHA256` too.

Synthetic evidence only. Non-activating and non-payment:
`proofSuiteId=null`, `production_usable=false`, `activation=false`.
