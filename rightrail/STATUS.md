# RightRail status

What is true now, replaced at each merge into the main code line; history is `git log` (protected Constitution changes:
`git log --grep '^XI.2:'`). Evidence is git state, raw test logs and the pinned executables' provenance; a pass on
one branch says nothing about another.

Terms: **Lean** is the proof language (code machine-checked against stated theorems). **HOLD** stops a payment; **ALLOW**
lets it go. A **shard** is one slice of the ledger with its own lock and chain; a **checkpoint** is a signed summary of one.
"Not yet called": written and proved, but no product code uses it yet.

## Product and standing claims

One state-controlled record connects approved rules, evidence, unresolved work, official decisions and follow-through.
The six products are listed in `ARCHITECTURE.md`; State Control Pack, Blind Ledger, Mirror and Switch share the payer
app's financial owner, and the Provider App is separate. Existing payment systems move money. Member, claim and payment data are synthetic (tests may also read public non-PHI reference data); state-local, non-PHI, nonpayment; `proofSuiteId=null`, `production_usable=false`,
`activation=false`. Guarded local runs are merge evidence, not release qualification.

## What runs and what is proved

The rollback checks (the store-rewound check at producer start, the counter rule), `audit_flat` and `newest_stored` run only in the
tests: nothing in `app/` or `tools/` builds a producer or calls `decide`, and a restored old store with its matching mark passes.

- **One fingerprint for every proved statement:** `tools/STMT_PIN.txt`, a SHA3-512 root over all pinned theorem statements.
- **Line identity is per shard; the id registry is gone.** Each shard's own history index finds a repeated line id, and
  nothing compares line ids across shards. At start-up a shard producer checks that its store holds the payer's newest
  checkpoint for that shard and refuses a store that went backwards (`store_rewound`), or an unreadable payer (`payer_unavailable`), by raising before it creates or writes anything. The store format
  changed, so an older store is refused (`store_version`) and never migrated. What it does with the shard's counter is
  the proved Lean custody step (`custodyStep`), asked through the verifier, refused under Lean's names. A crash between
  the shard's first seal and the counter's first increment is caught up at the next start, but only under that first
  checkpoint with a valid signature (`first_seal_crash_heals`); once the counter has moved, or on top of a published checkpoint,
  no counter-1 checkpoint is publishable (`counter_one_once`). A store deleted before the first increment (nothing of it
  released) still starts over at counter 1, as before. The catch-up cannot tell that case from a store wound back to its
  first sealed checkpoint while the counter file was redefined to unwritten: both reseal at counter 2 and fork, and only the
  payer's fork detection catches it. Lean reads the store's counter from the signed checkpoint itself (`custodyOf`), and a
  newest checkpoint that does not decode is refused (`store_rewound`).
- **Decide and commit:** a batch over 1,000 requests is refused at intake (`batch_too_large`). A batch the rules program
  fails the same way on every launch (a cap, a panic or out of memory) is refused once under its cause, with one action,
  split the batch (a single request, which cannot be split, is held for a person under that cause). A worker death or a launch past the deadline is a machine fault and is retried, at most three launches;
  if every launch is past the deadline, a batch of several requests is refused once as `timeout`, to be retried later (split it),
  and a single request is held for a person (`timeout`). A commit holds the tenant's floor lock for the floor check and the
  reservation, and again for the last floor check and the signature store, not while signing.
- **Payer batch release (Lean, not yet called):** equals one-at-a-time release (`releaseBatch_eq`); acceptance is the
  payer's twelve checks (`releaseBatch_spec`, `_accept_verified`); a bad item changes no other answer; a released item never
  accepts again (`releaseBatch_once`); a token pass implies a tree pass or a SHA3-512 collision (`publishOkTree_complete`).
- **Deployment settings:** an empty setting reads its strictest value, logs `DEPLOYMENT_SLOT_EMPTY`; `require_active` refuses while any setting is empty, but no product code calls it yet.
- **Payer release:** Lean decision and every write under one lock; append-only `closed` table; one hold row per refusal.
  Holds and member-key refusals are keyed by tenant, program and payment id, commands by tenant, program and command key;
  a payer store from before that, or from before `closed`, is refused (`store_version`) before any write, never migrated.
  A release counts the member-key pin only when the exact command bytes under its command key were marked sent. A
  command key of the same tenant and program reused with other bytes is refused (`command_conflict`) with no effect; another
  tenant's or program's command key is its own; a changed member key is still
  recorded as a refusal first. The newest checkpoint per shard is found by index, not by reading the shard's history.
- **Rules worker on a disk history index** (`conformance/FLAT_V1.md`): a signed chain head per
  checkpoint; a mismatched head or index HOLDs every line; one writer per index (`HOLD LOCK`); pinned. Cost per line is
  flat in history (300k -> 3M rows: pages per line 2.77 -> 2.85). Only `audit_flat` catches an edit to an
  older sealed batch. A batch is journaled once (`JOURNAL3`), applied at the open naming its signed head; no
  undo file (model and fast reader proved, crash-tested; format bounds tested only).
  The one decision program, `gate_engine`, runs contained (pin, a fixed 1 GB job memory cap, deadline); a worker that dies mid-batch is
  relaunched, at most 3 launches per batch; the batch's answer counts 1 plus the workers it lost and relaunched (one lost between
  batches counts for the batch that needed it). A wrong or missing program is refused before anything is decided, never retried.
- **Combined history engine** (`conformance/ENGINE_V3.md`, `lean/BlindLedger/Gate/Engine3/`): `gate_hist3`
  and `gate_verify3` are built and tested by `tests/test_engine3_*.py`. They are not pinned and no product code calls them;
  the chunk-store engine `gate_engine3` was retired (2026-11-06). Every theorem statement is proved (`tests/lean_sorry_allowlist.txt` is empty).
- **A decision's input names everything it was decided on (`INPUT/v5`).** Lean computes each token's input fingerprint over the
  payment request, the signed chain head, the four reference-snapshot pins (deaths, provider deaths, exclusions, enrollment),
  today's date, the grant id, the bypass id, the key-set digest and the engine release; each variable-length part
  carries its length, so two different sets of parts never share an encoding (`inputV5_inj`, up to the hash). The engine
  computes it and Python copies it; a frame with requests but no grant or release is refused. The producer store keeps
  the exact frame of each sealed batch (`record(batch_id)`), written in the same transaction as the batch. Replaying a batch
  from its record at publish time (`publishOk`) is not built yet: `publishOk` still checks signature, chain, token set and
  tree only. Fact signatures do not exist yet.
- **The grant and the bypass are signed and admitted in Lean (`APPROVAL/v2`, under the pinned key set).** A grant needs the
  roster quorum (distinct employees holding live ROSTER keys); a bypass needs two signers with distinct employees and
  distinct identity-provider subjects (stricter than the target, which allows one signer below the program threshold, TARGET §6), holding live APPROVER keys, and releases exactly one held payment. A grant or key set that is
  not admitted holds the frame in the open. A bypass that is not admitted (malformed, unsigned, expired, out of scope, a second
  one for the same payment and request, one signed for another request (`WRONG_REQUEST`), one for a payment not in the batch, or one for a redo payment) is refused alone with a
  `RULES_BYPASS` line naming the cause, and the rest of the batch is decided; only the first 64 bypasses of a batch are read; two bypasses for one payment and request are both refused (duplicates are detected only among the first 64 entries, `Rules.maxBypasses`) and
  the payment stays held; a stale bypass, signed for another request, never blocks the one for this request. An admitted bypass releases its held payment even if the payment's facts have since cleared, and the
  leaf then carries the bypass id. Token leaves (`TOKEN/v2`) carry the authority and the bypass id, and the payer pays only on ALLOW with TRANSFER
  authority (`verifyToken_transfer`). A request the grant does not cover is held alone, for SCOPE, and its lines are not decided
  (HUMAN_REVIEW if its flow has no rules); a flow with no lines keeps the rules' outcome under a HOLD grant; a bypass needs a
  grant entry with TRANSFER authority for its payment. The `APPROVAL/v1` format is deleted. Not covered: separation from the raiser and from the
  authors of the payment's lines (the decide request carries no author identity, so Lean cannot check it); the payer verifying a
  bypass while the gate is down; release or deny of a held payment as a determination (a later `APPROVAL/v2` kind); two
  different line sets under one payment id (the gate keys identity by line).
- **Each shard's signed chain binds its key-set pin and authority record; the grant and key-set floors are tenant-wide.** The
  key-set pin comes from the tenant's deployment setting (`GATE_KEYSET_PIN`); an empty setting reads 64 zero bytes, which no key
  set matches, so every frame holds (`keyset_pin`). A shard's chain starts from a hash over the pin, and each signed step hashes
  the 208-byte authority record (pin, key-set epoch and head, day, checkpoint, grant floor) with the batch's changes, so a
  replay of the chain checks the pin of every batch. The host keeps one file per tenant with the highest grant serial and
  key-set epoch any shard has admitted (it only rises) and sends both in every frame: a grant serial already passed on one
  shard is refused on all of them (`grant_superseded`), and so is an older key set (`grant_stale_keyset`). Proved: admission
  respects both floors (`floor_monotone`, `admit_keyset_floor`). Tested, not proved: the floor file and the read-back of the
  authority record.
- **The tenant floors are kept in one file and raised to every shard's sealed record; a re-decision is never lifted; the pin is
  checked at open.** The floor file is created once (`provision`); after that a missing, empty, corrupt or other-tenant file is
  refused (`tenant_floor`); a partial or all-zero last record reads as the previous one, but a whole last record that fails its
  check is refused, and `provision` never overwrites a non-empty file unless it is the start of a record naming these shards. Each record names the tenant's exact shard set (a different set is
  `tenant_shards`). The file is used by one process at a time, one thread at a time; a lock held longer than about a minute is
  refused (`tenant_floor_busy`). A failure before the signature may be stored voids the reservation and the producer stays open (if the void itself fails the producer closes, `reservation_not_voided`); a signing failure other than a refusal, an interrupt, or any failure once the signature may be stored closes the producer and needs a reopen (`signature_not_stored`, `mark_not_written`); a counter read error is raised unchanged. A producer's start takes the floors from the
  file alone (any shard can reopen first); at every seal, at a commit as at a start, the floors are read again before signing, and again
  under the floor lock just before the signature is stored (the lock is not held while signing); a reservation below the higher of those
  and its own sealed record is voided in one transaction and refused (`reservation_below_floor`), so the batch is decided again whether
  or not a crash came between the reservation and its seal. No floor rises between that last check and the stored signature; floors that
  cannot be read void the reservation too. Adding or removing a shard means
  provisioning a new file and raising it to the old file's floors (`raise_floors`)). Each read raises the file to the highest floors any of
  its shards has sealed, taking a shard's record only when its batch steps the signed chain (`authority_unchained`). A file
  from before the tenant name was in its domain (v1) is refused and must be replaced by hand. `commit` re-checks the floors under the
  file's lock and seals nothing if they rose since the decide (`grant_floor_risen`). At HOLD authority a re-decided payment
  is never lifted to ALLOW (`limitedPay_redo`, `redo_never_lifted`). `flat open` carries the key-set pin and holds the frame
  if the index holds another (`flat_pin`); `audit_flat` checks the pin of every batch and that the epoch and grant floor
  never fall, but only tests call it, and publishing (`publishOk`) does not replay the chain. Tested, not proved: the pin checks at open and
  per batch, the replay, and the floor file.
- **Signed payment-window facts (Lean decides, not yet called):** a check consumes k-of-n signed facts (`allow_signed`); on
  the history index no line is ALLOW without them, whatever the index holds (`allow_signed_idx`). The signed path reads
  no eligibility, so today every line on it is HUMAN_REVIEW on `STALE_ELIGIBILITY`; its ALLOW theorems hold vacuously and
  no signed-path vector exercises an ALLOW until the path is extended.
- **G2 eligibility is a gate rule (synthetic, not legally verified):** localBCE's aid code and benefit level gate reads a
  pinned eligibility snapshot (kind 7) and adds five reasons, `BENEFIT_LEVEL_MISSING`, `PROGRAM_NOT_ELIGIBLE` (HOLD) and
  their `_UNVERIFIED` twins and `STALE_ELIGIBILITY` (review, bypassable), at answer bits 24-28: 29 reasons, and no
  existing bit moved. A HOLD rests only on a usable snapshot (at most 7 days old, a placeholder) and a valid service
  date. No eligibility producer exists and the request frame does not carry the feed yet, so the engine reads none and
  every engine line, every former ALLOW included, is HUMAN_REVIEW on `STALE_ELIGIBILITY`.
- **Resident rules worker:** equals the `gate_rules` test program step for step until a lost or wrong store poisons it (HOLD); pinned.
- **Multi-key approval (Lean decides; the gate engine admits signed key-set steps, only re-initialisation is not yet called):** key-set changes (`KEYSET/v2`) and snapshot reads (`SNAPSHOT/v3`)
  need a quorum of distinct employees; revocation is permanent; a clock wound back cannot revive expired keys
  (`inband_reinit_keys_live`).
- **Conformance:** byte-level specs and must-reject vectors for gate rules v2 (v1 plus G2; v1 retired), `SEGMENT/v1`,
  provider `contentDigest` v1.
- **Bypass only per verified payment** (I.2): built in the rules worker only (see the grant and bypass entry above;
  `fail_closed_unless_bypass`, `bypass_attributed`, `bypass_no_window`). No product code outside the worker releases a
  payment the gate did not allow.
- **Receiver cash file:** plan on a copy, commit under the lock (quarter-end 1.44-1.65 s,
  limit 5 s).
- **Lean decides each gate payment's outcome:** the gate worker answers every token's outcome and reason codes, proved
  equal to the specification's for that payment on a batch no posting cap touches (a payment with a capped line is
  HOLD). The host sends each payment's request bytes; Lean decodes them, derives the rule lines and prints every leaf
  field (tenant, program, flow, payment, member, payee, amount, period, lines root). The signing path copies those fields
  and no caller supplies a leaf or payment field. The host checks the leaf's tenant against the shard's. The independent publish check does not re-run the
  decision, because the batch's facts and date are not committed. Byte frames, claim and offset rules proved; offsets
  capped.
- **Pins:** the worker, `gate_verify` and `gate_engine` hashes are in `tools/tcb_report.txt`, byte-matched by a fresh build.
- **Payer fork evidence:** a recorded fork (two different signed checkpoints at one position) keeps its tenant's evidence;
  `release_after_fork` proves no token of the forked shard in any epoch, and none in either side's epoch, is released. A payer store from before the counter column or the per-tenant fork table is refused
  (`store_version`), never migrated.
- **Payer key authority:** Lean INSTALL gives each certificate its role, and the store keeps every certificate that changes a
  decision (INSTALLED, EQUIVOCATES, FENCE_ONLY), with no count limit. A STORE or RELEASE frame carries at most four
  certificates and three forks, whatever the store's age: the witnesses of its tenant, shard and epoch, which decide as the
  whole history does (`select_decides`, `forks_witness`, `install_classifies`, `resign_noop`, `select_dedup`; the SQL mirrors
  `select` and `selectForks` clause for clause, checked on a 10,000-certificate, 5,000-fork store). A store from before roles
  is refused (`store_version`), as is one whose forks lack their shard; neither is migrated. A tenant's root key is pinned at its first kept certificate; another
  root is refused (`root_changed`, naming the tenant).
- **Rollback counter:** `CHECKPOINT/v3` carries the shard's counter, and the producer's counter rule (first seal arms it, a
  reopen resumes one lost increment, any other gap or a store deleted under a counter that has counted is refused) runs
  against a test counter only; no TPM adapter exists yet.

- **Key certificates (Lean, not yet called by the payer):** each epoch signing key is certified by the tenant's root and
  witness keys of its own generation; the chain of root generations has no gaps; a rotation records the last epoch
  certified under the old generation and refuses an old-generation certificate above it; a key used anywhere in the chain,
  or in a chain a later start replaced, is never accepted again. 84 test vectors are judged the same way by an independent Python checker.
- **Program-obligation records (Lean codecs, not yet called):** every record reads back as itself; obligation and funding
  identities include the program scope; a payment request repeats a stored payment exactly when the payment rules call it a
  duplicate; out-of-range status codes are refused. Follow-through and correction follow-up status are total Lean
  functions that the Python matches on every boundary date.
- **Fee-for-service claim lines:** `app/right_rail_gate_ffs.py` turns each 837 claim line into a decide request and the
  834, exclusion-list and provider-death rows into the frame's feeds; a claim that cannot be sent whole is set aside with
  its cause and cents; an exact resend returns the tokens already sealed.
- **Readers:** the four X12 readers (834, 820, 835, 837) and the exclusion-list reader keep names and ids as received, read
  as a stream, and set aside bad rows with a cause; 834 and 837 feed the claim path, the rest are not connected.
- **Federal share of a recovered overpayment** is owed per collection on the CMS-64 for the quarter collected (42 CFR
  433.320(a)(2), 433.316(h), 433.318); the independent checker refuses a store holding an authorized offset without its action.
- **Staff cause table:** every hold, refusal and set-aside the gate, its host and the file readers can give (285) has one
  row in `app/cause_actions.json` with its meaning, kind (data, machine or configuration) and one action; a test fails on
  a cause emitted without a row or a row nothing emits. No screen shows it yet.

## Speed bars

The bars: engine plus checker at most 40 µs CPU per line; 200,000 lines/s on 8 cores; per-line cost at 3M history at most
1.05x of 0.3M; at most 18 B per line plus 256 MB per process. This is the one place they are written. Measured whole path
on 2,000 lines, 2026-11-02: batch 2,000 at 688 lines/s synthetic and 618 realistic; batch 100 at 270 and 357 lines/s. No
300k-history figure is current. Speed work continues as its own lane.

## Standing design

- **Owner and checker (store format v8 only):** one verified writer; every commit flushed to disk; a checker re-verifies
  each obligation before COMMIT; table SQL pinned; at most 10,000 rows per table. Older stores fail unchanged. This is
  the store that runs today: one store for the gate and the ledger, without the row cap, is decided and in progress,
  not built.
- **Lean decides:** the pinned worker derives paid-so-far from linked payments; the checker re-checks it. Stray bytes fail closed.
- **Gate (Blind Ledger's end-state function):** its decision rules (R1-R5 and G2, 29 reason codes), `CHECKPOINT/v3`, `TOKEN/v2` and the payer's `verifyToken` in
  Lean; `gate_verify` checks every checkpoint's ML-DSA-87 (post-quantum) signature, tested against NIST vectors and AWS-LC.
- **Trusted-code check** (`tools/tcb_report.txt`, rerun `tools/tcb_pin.ps1`): every constant a pinned executable reaches
  is proof-backed except Lean's `Init` runtime, the arena reservations (`reserveArena`), the worker's frame loop (`serveWorker`),
  the six C file calls of the history store (`pgOpen`, `pgRead`, `pgWrite`, `pgSync`, `pgTrunc`, `pgClose`) and the placeholder `lcProof`.

## Open items

- **Gate restart:** the moved-file check misses an A->B->A swap; fork and POSIX in-place
  replace untested; network paths refused.
- **Correction size:** a result (`BLFCRES3`) embeds its input and the wire limit is 8 MiB, so a correction input over about 4 MiB is refused.
- **Cash file:** a foreign commit before the first write costs a full verify under the lock (21.5 s measured at 6,000 payments); the fallback batch grows with history (2.7 -> 4.6 s).
- **Real-world data:** the messy test corpus has cases not yet representable (advance payments, member crosswalk, PLB
  balances, death after release, upward retroactive rates).
- **Gate speed and gaps:** bars and measurements are under Speed bars; a stale journal under a torn trailer
  at an old head can replay. Live use needs a rules-source setting and a Lean length check on
  payment requests. Unbuilt: prior-digest check, integrated payer gate, durable token. The failover
  model check (TLC) is bounded. The rules program's pin is checked only if passed; a live worker's lock blocks copying
  its index on Windows.
- **Posting cap:** approved to count per core ((member, date, procedure) for FFS, (member, month) for capitation). The Lean rule and the rows-file
  engine (`gate_hist3`, `gate_verify3`) count per core; `gate_engine`, which the claim path runs, still counts per key and passes
  no core counts, until the decide path moves to the rows-file engine.
- **Held batches:** there is no queue of held batches with an owner and a deadline, and the gate does not learn when the payer
  releases a held payment.
- **Key set expiry and the clock:** a shard with no frames for more than 31 days has an expired key set, and its payments hold until the key set is re-provisioned, which is not yet built. The host supplies the `today` clock and the gate trusts it.
- **Built, not yet wired into decisions:** X12 820 and 835 readers (834 and 837 feed the claim path above). **Reference feeds are re-sent and re-hashed with every batch** (a speed gap). **Unbuilt:** MCO report and MMIS extract adapters, payee identity, a second synthetic state, a Lean seal codec.
- **Carried:** the staff role header is not a login; no cancel command for stale corrections; receipt `delivery_status`
  shows the newest action, not the verdict; core over size target (owner 6,687/~3,000, checker 4,511/~1,800 lines);
  test restore uses the system clock; published items cannot be re-stated.
- **Scorecard friction:** all 20 rows of the synthetic scorecard read "Case OPEN" and 19 stay open, though only one hospital
  has a problem; restore to the test copy is enabled only after the shortfall is 0, so a replacement operator cannot take
  over unfinished work; the reason for a decision is not stored yet.
- **Constitution amendments of 2026-11-14:** release by cause (I.2) and exact duplicates answered at once (I.4) are in the
  Constitution but not built; today the gate holds an exact duplicate and releases per payment (two signers, 64 per batch).
- **Acknowledger not stored:** `ACTION_ACKNOWLEDGED` has no actor, so "a decider may not acknowledge" is unchecked.

Next: speed and proofs as planned (the speed bars, the proved rules interpreter, custody and the agency cosign), then the staff
loop (a queue of held work with owner and deadline, re-decision when a fact arrives, release by cause, exact duplicates
answered at once, a screen per cause); alongside them, decision records with their read sets and a trusted known-time clock,
one store for the gate and the ledger with facts kept under two times, and rules as signed data under one proved interpreter.
