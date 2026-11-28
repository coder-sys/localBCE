# History index v1: chain, entries, chunk store (log v2)

Status: draft. Synthetic, nonpayment, non-PHI: `proofSuiteId=null`, `production_usable=false`,
`activation=false`. The Lean model is normative: `lean/BlindLedger/Gate/Flat/Model.lean` (chain, entries, caps),
`Flat/Chunk.lean` (chunk bytes, head step), `Flat/StoreLog.lean` (frames, state root, write order, load) and
`Flat/ChunkIo.lean` (their execution); statements in `Flat/Theorems.lean`, `Flat/ChunkTheorems.lean` and `Flat/StoreLog.lean`. No vectors are published yet.

## 1. Notation

- `leb n`: minimal unsigned LEB128. `be8 n`, `be2 n`: big-endian, 8 and 2 bytes.
- `dom X`: the UTF-8 bytes of `RR/GATE/X/v1` followed by one zero byte.
- `H`: SHA3-512 (64 bytes). `Z`: 64 zero bytes.
- A line encodes as `line = leb` of each of its ten fields in order: flow tag, member, payee,
  rendering, date, procedure, units, cents, id, payment.
- A key (exact, near or id key of a line, each a list of numbers) encodes as
  `leb (length) ‖ leb` of each number.

## 2. Chain (CHAIN/v1)

The history of a shard's two sets (released, unresolved) is bound by a hash chain. A set
encodes as `leb asOf ‖ leb count ‖ leb rows ‖ line*`.

    genesis = H(dom CHAIN ‖ 0x00 ‖ leb shard ‖ set(released) ‖ set(unresolved))
    delta   = leb r ‖ line*r ‖ leb u ‖ line*u
    digest  = H(dom CHAIN ‖ 0x03 ‖ delta)
    D'      = H(dom CHAIN ‖ 0x02 ‖ D ‖ digest ‖ Root_b)

`delta` holds only the rows the batch appends to each set (released first): a step costs the
batch, not the history. `Root_b` is the state root after the batch (section 5), so a head binds the whole store as well
as the batch. Equal heads mean the same shard, genesis, batch digests and roots, or two distinct inputs of the step share a
SHA3-512 digest. A head cannot be rebuilt from the rows alone: the roots are needed.

A checkpoint's state digest is the head after its batch. Each token of the batch commits to its input as INPUT/v7,
`H("RR/GATE/INPUT/v7" ‖ 0x00 ‖ ctx ‖ lp32 head ‖ lines root ‖ tail)`: `ctx` is the batch context, the request frame's
body before its request count (today, the pre-batch head, the feeds with their pins, the redone payments, the key set,
grant and bypasses and the engine release), and the rest is the request's bytes with its lines replaced by their root
(`conformance/ENGINE_V3.md` §18, `Gate.inputV7`, injective by `inputV7Pre_inj`). The batch's identity, logged as `rq`,
is `BATCH-INPUT` over `ctx` and each payment's input in frame order (`Frame.ident`). The worker puts the input in each
leaf of its answer; the producer stores the frame bytes with the batch.

### 2.1 Authority record

The shard's authority record (`AuthRec`, `encAuth`, `authLen` = 276 bytes) is

    auth = pin 64 ‖ be4 epoch ‖ head 64 ‖ be4 day ‖ cp 64 ‖ be8 floor ‖ rs 64 ‖ be4 rsv

the key-set genesis pin, the ratchet of the key-set head last admitted (epoch, head digest, day, checkpoint), the
highest grant serial admitted (`floor`), and the rule set in force: the digest of the newest rule-set record admitted and
its version (`rs`, `rsv`; the zero digest and 0 for none). This engine runs no rule set: it writes `rsv` 0 with the zero
digest, and a store whose record (in the trailer or a pending batch) has `rsv` above 0 is `CORRUPT`. A frame that
asserts a rule-set version above the record's holds as `RULESET_STALE`, and one that presents rule-set records as
`RULESET_NOT_RUN` (FRAME_V1 section 2). The record lives in the trailer (section 6) and every chain step covers it, so a trailer
of another head carries another record. `flat init` stores the pin with the ratchet at the genesis key set and floor 0.
A batch with no requests carries the record unchanged; a committed batch with requests stores the ratchet its key-set
head reached and the serial of the grant it admitted. Proved for admission only: `floor_monotone` shows that an admitted
grant's serial is not below the stored floor or the frame's. The commit step that stores the record and reads it back
is covered by tests, not by a theorem; the codec is proved: `decAuth` reads exactly `authLen` bytes (`decAuth_isSome`)
and returns the record `encAuth` wrote (`decAuth_encAuth`). The worker prints the record as `RULES_FLAT_AUTH hex` before
`RULES_FLAT_HEAD`. The pin is checked in three places, by tests and not by a theorem (the third only when a caller asks):

- Lean, at `flat open` (section 7): the host sends the tenant's pin, and once the open has brought the index to the
  signed head, the stored record must name that pin, else `RULES_FLAT_HOLD PIN` (`flat_pin`) and nothing is decided.
- The host, at each batch: it recomputes the step from `RULES_FLAT_AUTH ‖ RULES_ADDS`, and a record whose pin is not the
  tenant's is `keyset_pin` (every row HOLDs).
- The host, when asked to replay (`audit_flat`, `head_after`; only tests call it today): it rebuilds the chain from the shard's genesis under the tenant's pin,
  and fails when any batch's record names another pin, or has a lower key-set epoch or grant floor than the batch
  before it.

The publish check (`gate_verify` PUBLISH, `publishOk`) does not replay the chain and takes no key-set input, so publishing
does not check the pin; nothing outside tests calls `audit_flat` yet. Before the grant floor is read from a shard's newest
sealed record, the producer checks that the record's batch steps the previous signed head to its own state digest
(`authority_unchained` otherwise).

Grant floor. A frame may carry `floor N`: the host sends the tenant's floor, the highest grant serial any shard of the
tenant has admitted, kept in one mark file the host raises (never lowers) once a batch's head checks. A grant below
max(stored floor, N) is `SUPERSEDED`; an `N` below the stored floor is `FLOOR` (`RULES_GRANT_HOLD`), since a lowered floor
would re-admit a revoked grant. So a grant revoked by a higher serial on one shard is refused on every shard of the
tenant.

Key-set floor. A frame may carry `kfloor E`: the host sends the tenant's key-set epoch, the highest ratchet epoch any
shard of the tenant has admitted, kept in the same mark file and raised the same way. A batch head whose epoch is below
`E` is `STALE_KEYSET` (`RULES_GRANT_HOLD`; `admit_keyset_floor`), so a key set superseded on one shard is refused on every
shard of the tenant. Below a shard's own ratchet the chain is refused anyway (`HEAD`).

Refused frames. A frame whose key-set head is admitted but whose grant is refused (`RULES_GRANT_HOLD`) writes nothing,
so the shard does not keep the ratchet that head reached. This is harmless: every later frame is decided exactly as if
the refused one had never been sent, which a host can always arrange by withholding the key-set step, and the stored
ratchet never moves back.

## 3. Index entries

Each set keeps one entry per key that any of its rows carries. A posting is `(seq, row)`: the
row's position in its set, from 0, and the full row (the rules read row fields, so a posting
that held only an id would need a third read round).

    posting = leb seq ‖ line
    entry   = leb count ‖ leb n ‖ posting*n ‖ leb 64 ‖ tail

`count` is the number of rows carrying the key. The first `min(count, 1024)` postings are kept
in row order with strictly rising `seq` (`n` must equal `min(count, 1024)`). Past 1,024,
each further posting folds into `tail = H(dom INDEX/TAIL ‖ tail ‖ posting)`, starting from `Z`.
Any other bytes (trailing data, wrong `n`, falling `seq`, a short tail) are corruption: the
batch HOLDs. In the store, a key is stored as `ns ‖ key` with namespace 5 for released and 6 for
unresolved; 7-10 are reserved for the four reference feeds by id.

## 4. Caps (POSTING_CAP, FEED_CAP)

A batch reads per line: each of its three keys in both sets; for each fetched unresolved CAP_820
row of a redone payment, that row's id key in the released set; and the death, provider death,
exclusion and enrollment facts of the line's member, payee and rendering provider, at most 1,024
facts per id. No read depends on the history's length (`work_le`).

A line HOLDs with reason `POSTING_CAP` (`cap_hold`) when it reads anything cut short:

- its core holds more than 1,024 rows in either set (`core_hold`): member, date and procedure for a fee-for-service
  line, member and month for a CAP_820 line (`coreKey`; it agrees with the engine's core bytes for lines that pass
  `fitsLine2`, not yet proved), so every exact and near key of the line lies inside it; or its id key has more than
  1,024 postings. This replaced the per-key count (sign-off 2026-11-03, GATE_RULES_V1) and only adds holds:
  each decision is the per-key one, made HOLD with `POSTING_CAP` when the line's core is over the cap
  (`decide_perCore`), and the lines it releases are a sublist of the per-key rule's (`released_perCore`); both read the
  state's core counts as they stand, so they are the per-core rule only for a state whose core counts are exact
  (`CoreInv`, kept by `addRows_core`; `core_hold` states it for such a state). Each set's
  index counts rows per core (`SetIdx.core`, kept exact by `addRows_core`). The chunk stores keep no core counts yet:
  their reads decide per key (`view_eq`, `St.perKey`), so they agree with the per-core rule except on lines whose core
  is over the cap (`decideFast_perCore`);
- one of its keys is carried by a fetched unresolved CAP_820 row, or by a CAP_820 line of the
  batch, whose member has more than 1,024 enrollment spans;
- FEED_CAP: one of its own feed ids has more than 1,024 facts (`feed_cap_hold`). This reuses the
  `POSTING_CAP` reason, since the rule set's reason list is fixed.

A released id-key entry over the cap HOLDs the whole batch, because ownership sets the decision
order. Ids are unique within the sets, so this cannot happen after a sound genesis. On a batch
with no cap, decisions and appended rows equal the rule set's (`decideBatchIdx_eq`).

## 5. Chunk store

A shard's history is one append-only log of frames, one frame per batch. Nothing written is changed, and no image of the
in-memory state is written, so a batch costs its own frame and not the history. A load replays every frame from the first.
Version 1 of the store (one `.dat`/`.meta` pair per chunk and a commit record) and the store that wrote state images are
gone and not read: such a directory is refused (`FILES`). The store directory holds `log` and `lock` (the worker's lock
file) and nothing else.

- `log`: the frames in batch order. A frame is a 16-byte header (`RRF2`, then the page count `np`, the metadata length `ml`
  and the trailer length `tl`, each 32 bits little endian), the chunk's `np` pages, the metadata, and the trailer.
  A batch that appends nothing has `np = ml = 0`.
- The chunk's pages hold its rows sorted by the 64-bit key hash `kh` (FNV-1a over the key bytes, then two multiply-and-shift
  mixes: `ChunkIo.kh`; nothing but the order depends on it), then by key, each as
  `leb length ‖ body`, `body = leb |key| ‖ key ‖ leb count ‖ leb n ‖ posting*n ‖ tail` (`tail` is `00` for `Z`, else `01 ‖ 64
  bytes`), ended by `leb 0` and cut into 4,096-byte pages, the last padded with zeros. A row carries the newest entry of its
  key (section 3).
- The metadata (v3) is `leb |m| ‖ m ‖ leb seq ‖ leb t ‖ tomb*t ‖ leb t ‖ kh*t`. `m` holds the row count with each row's
  8-byte key hash, the length of the row data, one mark per page (fence hash, offset of the first row starting in it, that
  row's number, whether it starts a run of one key hash) and each page's SHA3-512 (`H(dom STORE/PAGE ‖ page)`). `seq` is
  the chunk's install number. A tombstone `leb c ‖ leb seq ‖ leb i` marks row `i` of chunk `c` (installed as `seq`) dead
  because a later batch replaced its key; a row dead at birth names its own chunk. The final list is the 8-byte key hash
  of each tombstone's row, so a replay frees the row's directory slot without reading its page.
- The trailer is `dom FLAT/FRAME ‖ leb shard ‖ leb nb0 ‖ leb batches ‖ leb (chunk + 1, or 0 for none) ‖ head(released) ‖
  head(unresolved) ‖ leb nx ‖ auth ‖ rq ‖ prev ‖ digest ‖ head`: the shard, the directory's bucket count when the store
  was created, the batch count, the chunk, the set heads, the next install number, the shard's authority record after the
  batch (`authLen` = 276 bytes: key-set genesis pin 64 ‖ ratchet epoch u32 ‖ ratchet head 64 ‖ day u32 ‖ checkpoint 64 ‖
  grant serial floor u64 ‖ rule-set digest 64 ‖ rule-set version u32, big endian), the request digest `rq`, the head before the batch, the batch digest and the head after it. `rq`
  is the request frame's own digest, `H(dom FRAME ‖ body)` (FRAME_V1), over the request bytes exactly as the host sent them. The batch is committed when
  its trailer is on disk. A load takes the authority record from the target's frame; the state root binds it, so a record
  swapped or rewound refuses the load.

The directory layout is part of the state: it starts at `nb0` buckets and grows (a rebuild at twice the size plus one) in
ascending chunk number, so a replay that runs the frames in order builds the very layout the first writer did.

The chunk roots form a Merkle tree of depth 18 over chunk numbers: leaf `H(dom STORE/LEAF ‖ 00)` for an empty number,
`H(dom STORE/LEAF ‖ 01 ‖ r)` for chunk root `r = H(dom STORE/CHUNK ‖ the metadata bytes)`, node
`H(dom STORE/NODE ‖ left ‖ right)`. The state root is
`H(dom STORE/STATE3 ‖ leb shard ‖ leb nb0 ‖ tree root ‖ head(released) ‖ head(unresolved) ‖ leb nx ‖ bs auth ‖ bs rq)`, where a
set's head is `leb asOf ‖ leb count ‖ leb rows`, `nx` is the next install number and `bs x = leb |x| ‖ x`. The head after a batch is
`H(dom CHAIN ‖ 02 ‖ prev ‖ digest ‖ root)`; at batch 0 it is `chainStart`.

Write order of a batch: (F1) the header, pages and metadata appended to `log`; (F2) the trailer appended; (F3) one sync,
which commits the batch. Nothing is released before F3. The three kill points `frame-torn` (body written, trailer not),
`frame-write` (trailer written, not synced) and `frame-sync` (synced, not answered) are read from `RR_FLAT_CRASH` by
`gate_rules_crashtest` only; `gate_rules` and the pinned `gate_engine` have no such variable.

## 6. Load

`flat open DIR HEAD BATCHES` loads the store from disk at the signed head and batch count. It refuses, printing
`RULES_FLAT_HOLD` and the word, unless:

- `BATCHES` is above 0 (`HEAD`: a store that never committed is created again by `flat init`);
- the directory holds no file other than `lock` and `log` (`FILES`), and `log` is there (`LOG`);
- the frames from the first replay in order: each one's shard and `nb0` equal the first frame's, its count follows, its
  `prev` is the head before it, its metadata decodes and gives the chunk and the tombstones, the page count equals the
  page-hash count, the install number and chunk number are the expected ones, and the head recomputed over the tree and
  the state root equals the trailer's (`REPLAY`, or `HEAD` where a frame is missing);
- frame `BATCHES` carries the signed head (`HEAD`);
- the files can be repaired (`IO`).

Load reads no page of row data. A page is read, and checked against the metadata's page hash, when a batch needs its rows; a
mismatch prints `RULES_FLAT_HOLD CORRUPT` and writes nothing.

Torn batches. A frame with no whole trailer is not a batch: load cuts the log after the signed head's frame. One whole
frame after the signed head (the batch was committed and the host never sealed it) is replayed too and kept; the batch is
then decided again, and it must be the same request bytes (`rq`) and come out as the same frame, else it is refused
(`PENDING`). Two whole frames past the signed head are `HEAD`. After a kill at any write step, load at the signed head gives
the last committed state, and the resent batch answers and commits as an uninterrupted run does, byte for byte.

Every decision reads state recomputed from the first frame to the signed head, and each page's hash, so an edited frame at
any age changes a state root or head and refuses the load. The cost of a load grows with the log.

Not claimed: the hashes are unkeyed, so they catch corruption and a mismatch with the signed head, not a writer who can also
forge the signature. Rolling the whole directory back to an older consistent copy is caught only by comparing the signed
head and count. The store shares the worker's trust domain, as its memory does. The fast codecs, scan and replay equal the
model by differential check (`RR_FLAT_CHECK`), not by proof.

## 7. Worker frames

The resident worker (`gate_engine`, frame tag 3) and the test-only runner (`gate_rules --flat FILE`) take a rules vector
text whose history is the store on disk. Two directives replace `load`, `resume` and the set snapshots (which a flat
frame refuses):

    flat init DIR SHARD ASOF SALTHEX PIN (the salt is parsed and unused) a new empty store in an empty directory, the sets dated ASOF, the authority record at the key-set genesis pin PIN (64 bytes hex, floor 0); prints RULES_FLAT_HEAD hex 0
    flat open DIR HEADHEX BATCHES        loads the store (section 6) at that head and batch count

A refusal prints `RULES_FLAT_HOLD word` and decides nothing (section 6; `LOCK` if another process or worker holds
`<dir>/lock`, `INIT` if the directory to initialise holds anything but a first batch that never completed). `commit` decides as the rules do, prints the usual
`RULES_LINE` and `RULES_ADDS` lines, installs the batch (section 5), then prints `RULES_FLAT_HEAD head batches
root digest` (the head after the batch, the count, the state root and the batch digest) and `RULES_FLAT_COUNTERS lines=N
work=W pages=P` (`work` is the model's count; `pages` the pages read from disk for the batch). A corrupt page prints
`RULES_FLAT_HOLD CORRUPT`, a failed install `TABLE`, an I/O error `IO`; none releases anything. A frame holds one `commit`: a
second prints `RULES_FLAT_HOLD NOT_OPEN`.

The worker appends the batch's frame when it decides; the host signs the printed head and names it at the next
`flat open`. A batch the host never seals is put back by the next open at the old head (section 6). The host takes the
worker's head only after it recomputes it: the digest from the `RULES_ADDS` rows, then the step over the signed head, the
digest and the printed root. A two-field head line, or a wrong digest, root or count, is `chain_mismatch`. `commit` on the
host seals only the answer of the last `decide` (store directory, head and batch count) and spends it before the seal is
written; any other answer is refused as `stale_answer`. Every `RULES_FLAT_HOLD word` reply HOLDs every row of the batch as
`flat_word` (lower case), and the host never accepts a head the signature does not cover.

A worker holds an exclusive lock on `<dir>/lock` for as long as it lives. A worker that already has the directory open
skips the reload if the `flat open` names the head and count it holds; otherwise it closes the store and loads from disk.

Proved and tested: the chunk bytes and the head step follow the model (`Chunk.lean`). The frame and load statements
are in `StoreLog.lean`, their proofs not yet done (8 `sorry` in `tests/lean_sorry_allowlist.txt`); the code is checked against the model's codecs by `RR_FLAT_CHECK`, and a
kill at each write step, tampered bytes, torn tails and missing, extra or swapped files are exercised against the test-only
`gate_rules_crashtest` program.
