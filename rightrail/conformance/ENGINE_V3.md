# Engine v3: fixed rows, keyed directory, hot tier, machine holds

Status: draft. The statements are unproved; the engine is built and tested but not pinned, and no product code calls it. Synthetic, state-local, nonpayment, non-PHI: `proofSuiteId=null`,
`production_usable=false`, `activation=false`. Moves no money. The Lean model is normative:
`lean/BlindLedger/Gate/Engine3/Layout.lean` (definitions); the executables `gate_hist3` and `gate_verify3`
and the tests `tests/test_engine3_*.py` run the engine; revision 2's exact rows are stated in `Engine3/ExactRows.lean`.
No vectors are published yet.

This replaces `FLAT_V1.md` §5-7 (chunk store, load, worker frames) and, for a pending frame, the retry of
`FRAME_V1.md` §6. `FLAT_V1.md` §1-4 (chain, entries, caps), the decision rules (`Flat/Model.lean` `decideBatchIdx`,
`Rules/Spec.lean`) and the request and record of `FRAME_V1.md` §2-4 are unchanged except where §8, §9 and §17-§19
say so.

Revision 2 (2026-10-31) is the text of this document: exact identifier widths (§1-§3), feed facts as row words (§19),
request and answer version 2 and the input commitment INPUT/v6 (§17-§18). The Python host and the pinned `gate_engine` (the `Flat` store) implement revision 1 (113-byte lines, 4,096-byte pages,
request and answer version 1, INPUT/v5) until the steps of §20 land; the engine in `Gate/Engine3` already uses
revision 2's 245-byte lines. Each step changes the code and its statements together. Revision 1 stores and logs are refused
at load, never converted.

## 1. Notation

- Numbers are unsigned little-endian of the stated width (`u8`, `u32`, `u40`, `u64`), as in `FRAME_V1.md`. A field of
  `w` bytes holds every number below `256^w`, exactly.
- `H` is SHA3-512 (64 bytes), `H256` is SHA3-256 (32 bytes). `dom X` is the UTF-8 bytes of `RR/GATE/X/v1` and one zero
  byte. `Z` is 64 zero bytes. No other primitive is used: every hash is SHA3, every signature ML-DSA-87.
- `HB` is the block and page hash and `hb` its length in bytes: `HB = H` (SHA3-512), `hb = 64`. It is one named constant: every
  size below that depends on it is written with `hb`, so changing the block hash changes this line only.
- A line's store widths (revision 2), 245 bytes, every field the rules' number (`Line`) stored exactly:

  | Offset | Field | Width | Holds | Real case |
  |---|---|---|---|---|
  | 0 | `id` | 51 | a line id of at most 50 bytes | X12 REF02 50; CLP01 38 |
  | 51 | `pay` | 72 | `payNat`: program and payment id with their u16 lengths, the two ids at most 67 bytes together | program `medicaid-ffs` 12 + TRN02 50 |
  | 123 | `flow` | u8 | the flow tag | |
  | 124 | `member` | 32 | the `n33` member key `0x01 ‖ 32 bytes`, `0x01` implied | |
  | 156 | `payee` | 21 | an identifier of at most 20 bytes | NPI 10, EIN 9 |
  | 177 | `rendering` | 21 | an identifier of at most 20 bytes | NPI 10 |
  | 198 | `date` | u32 | | |
  | 202 | `proc` | 31 | an identifier of at most 30 bytes | `HC:99213:25:59:GT:95` 20 |
  | 233 | `units` | u32 | | |
  | 237 | `cents` | u64 | | |

  The rules' number of a `k`-byte identifier is below `256^(k+1)`. A line with a value outside these widths, or a
  `member` that is not `n33`, takes `FRAME_V1.md` rule 3 and its payment rule 4, cause `FIELD_WIDTH(field)` (§8): it is
  held, never stored shortened (`fitsLine`, `wideField`). Equal store bytes are equal lines, so no two payments or line
  ids are ever treated as one (Constitution III.3).
- Inside a batch a payment is named by its request's position in the frame. The decoder refuses two requests of one
  payment, so position and payment number are one to one. No map on the decision path is keyed by a payment number.

## 2. Store secret and key digests

At `init` the engine takes 32 bytes `s` from the operating system's random generator, writes them to the file `key`
in the store directory and syncs the file and the directory before the first frame. The state root binds
`ks = H(dom STORE/KEY ‖ s)`. `s` itself is never in the log, an answer, a record or a root. The file is store data:
it is backed up with the store and lost with it.

A key's bytes `kb` are its kind (`u8`) and then its fields (`kbytes`). `member` (32), `date`, `units`, `month` (u32)
and `cents` (u64) are fixed. An identifier field (`payee`, `rendering`, `proc`, `id`) is `u8 n ‖ n bytes`, the
number's minimal big-endian bytes, `n` at most its store width. The lengths make the map one to one.

| Kind | Key | Fields | Bytes, typical | Bytes, at most |
|---|---|---|---|---|
| 1, 3 | exact | member, payee, date, proc, units, cents | 68 | 103 |
| 2 | FFS near | member, rendering, date, proc | 56 | 91 |
| 0 | CAP near | member, month (`date / 100`, u32) | 37 | 37 |
| 4 | id | id | 41-53 | 53 |

A key with a field outside its width (never stored: its line holds for width) encodes as `0xFF ‖ leb key`, so the map
from keys to bytes is one to one.

The key digest is `kd = H256(dom KEY2 ‖ s ‖ kb)`: 16 + 32 + `kb` bytes, one permutation while `kb` is at most 87
bytes (every typical key), two above. The new domain keeps revision 2 sort hashes apart from revision 1's. It is cut
into four 64-bit values:

| Bytes of `kd` | Name | Use |
|---|---|---|
| 0-7 | `kh` released | sort and fence hash on disk |
| 8-15 | `kh` unresolved | sort and fence hash on disk |
| 16-23 | `dh` released | directory hash, kept per entry in chunk metadata |
| 24-31 | `dh` unresolved | directory hash, kept per entry in chunk metadata |

Why a secret key. Only claim submitters choose ids and other key fields, and without `s` they cannot compute where a
key lands: not its directory bucket, its fingerprint, its page or its block. They cannot aim keys at one bucket pair to
fill a stash, or at one hash-map bucket. `kh` must be the same at every load, because chunks on disk are sorted by it,
so `s` is persisted rather than drawn per process. Every hash map on the decision path that is keyed by input data hashes
by `kd`, never by a default hash, so hash flooding cannot slow the decision thread. Key digests are computed on the read
tasks: about 2.5 distinct keys per line at about 1.2 µs each.

The directory does not use `dh` directly but `dh XOR salt`, where `salt` is a fresh 64-bit random value for each
segment (§4) each time that segment is built (load or growth) and is never written. The directory is not state (no
root binds it), so a growth that failed under one salt retries at fresh positions.

## 3. Rows and rows files

The chunk store (blocks, pages, chunk files and their metadata) is gone. Later sections that still speak of chunks,
windows, seals, installs or reclaims describe that older design; the engine now keeps each set of rows in one append-only
rows file (`Engine3/RowsFile.lean`).

A row is the 245-byte canonical line at the store widths of §1. Its record in the rows file is 256 bytes, at byte
`256 * seq` for row number `seq`:

| Bytes | Field |
|---|---|
| 0-244 | the canonical row |
| 245-249 | `prevCore`: the number of the previous row of the same core, plus one (0 for none), 40 bits, little endian |
| 250-251 | the number of rows of this core up to and including this one, 16 bits, saturating |
| 252 | flags: bit 0 claims its near key, bit 1 is a cap row |
| 253-255 | zero |

A set only grows, so a record never changes. The file is a projection of the log (§6): on open, a torn tail (a partial
record, or records the log does not confirm) is cut back and the log replays the rest.

## 4. Tables

Each of the two sets (released, unresolved) is a rows file plus two tables in memory (`Engine3/Hist.lean`):

- `ids`: one slot per row under its id key, holding the row's number;
- `cores`: one slot per core, holding the number of the core's newest row. Through `prevCore` a core's rows form a chain
  in the file.

A core is the member with the date and procedure of a fee-for-service row, or the member and the month of a cap row. The
exact key and the near key of a row are each a filter of its core. A key's entry is its core's chain filtered by the
key's equality, in ascending row number; its count is exact, and the decider reads its first cap rows. An id key's entry
is the rows that the id table's hints name and that have the id. A hint only suggests: every row is read from the file and
compared whole, so a wrong hint costs a read and nothing else.

A core of more than 32 rows is also summarised (`Engine3/CoreSum.lean`): each of its keys keeps its first row, its count and
its first row that is not identical to the first. That is all the decider reads of a key where no line of the batch can be
its own payment's released row, or where the key is a fee-for-service one (`Flat.DecideCut.decideRows_cut`).

The tables hold nothing the rows files do not. They are built again from the files at load. Only ids and cores are stored
under a digest; exact and near keys are not digested.

## 5. Writing a batch

A batch is read and put in one pass. `read` digests each distinct core and id of the batch once, probes the tables of both
sets, reads the rows the hints name, and keeps what the put needs. The batch is decided from those rows; its frame is
appended to the log and synced (§6); then its rows are appended to the rows files in one write per batch, and the tables
are updated. There are no windows, seals, installs or reclaims.

## 6. Root, frame, log, load

Files: `lock`, `key`, `log`, one rows file per set, and `clean` (one byte). Anything else refuses the load (`FILES`).

The log is the truth. The rows files are not synced per batch. A clean stop syncs them and then writes 1 to `clean`; a
start writes 0 there and syncs it before any other write. A load that finds 1 trusts the rows files: it cuts them to the
last signed batch and puts the rows they lack from the frames. Any other start, whose process did not itself write the
files, rebuilds both rows files from the log and swaps them in, so a power loss that left whole but hollow records cannot
reach a decision. Damage to the files while the marker says clean, behind a completed sync, is outside the threat model.

Frame, one per batch, appended to `log` and synced once:

    RRF4 ‖ u32 |request| ‖ u32 |answer| ‖ u32 |trailer| ‖ request ‖ answer ‖ trailer

The request and answer are the engine's frames (§17). `rq` is the batch identity (`Frame.ident`: BATCH-INPUT over the
batch context and each request's INPUT/v6, §18), not a frame digest (§24). Rows are not copied
into the frame: a batch's appended rows are the lines of its rule 1, 2 and 5 records, read from the request and answer
(`rows_of_records`).

Trailer: `dom STORE/FRAME4 ‖ u32 shard ‖ u64 batches ‖ head(released) ‖ head(unresolved) ‖ u64 nx ‖ u64 bOpen ‖
u64 bSeal ‖ events ‖ au 208 ‖ rq 64 ‖ an 64 ‖ replaced 64 ‖ prev 64 ‖ bd 64 ‖ root 64 ‖ head 64`, where a set's head is
`u32 asOf ‖ u64 count ‖ u64 rows`. The chunk fields (`nx`, `bOpen`, `bSeal`, `events`) are zero. `an = H(dom ANSWER2 ‖ the
answer's bytes with its head and root fields left out)`, so every other answer byte (notes, leaves, rows) is bound;
`replaced` is §9's digest or `Z`; `bd` is the CHAIN/v1 batch digest; `au` is the 208-byte authority record.

    Root4 = H(dom STORE/STATE4 ‖ u32 shard ‖ u64 batches ‖ tree root ‖ heads ‖ u64 nx ‖ ks ‖ u64 bOpen ‖ u64 bSeal ‖
              u32 sealing chunk (2^32 − 1 when none) ‖ au ‖ rq ‖ an ‖ replaced)
    head  = H(dom CHAIN ‖ 0x02 ‖ prev ‖ bd ‖ Root4)

With no chunk tree, the tree root is 64 zero bytes and there is no sealing chunk. No bucket count and no directory are in
the root. The answer is bound to the signed head through `an`.

Load at signed head `hd` and batch count `bt`:

1. Read `key`; refuse `KEY` when it is missing or not 32 bytes. Decode the frames of `log`; frame `bt` must carry `hd`
   and `bt` and be the last whole frame or the one before it (`HEAD`).
2. Check every frame without deciding it again. Its request must have the identity `rq` (the request's own digest first), its
   answer to its `an`, and the rows the answer adds to its `bd`; these checks need no state. Its `prev` is the head
   before it, its root is the state root of its own fields, and its head is the chain head of `prev`, `bd` and root
   (`REPLAY`). So every frame is chained by SHA3-512 digests to the signed head `hd`. The genesis is under the key-set pin
   of the first frame's authority record. The decisions themselves are checked by the verifier, which decides every
   frame again (§10).
3. Put the rows from the frames into the rows files and tables as the marker above says.

A whole frame after `bt` is the pending frame (§9). Torn bytes after the last whole frame are cut.

## 7. Threads and pure values

- Decision thread: decode, admission, probes, decision, apply, record.
- Up to 4 read tasks: key digests, block reads and their hash checks.
- Writer: frame, chain and fsync; chunk encoding, writing and sync; directory segment rebuilds.

Each hands the next a value: digests, verified blocks, a built segment, a synced chunk. The decision thread takes them
at fixed batch points only. A late value makes it wait, never changes a result. Anything that depends on the disk or on
timing (a bad block, an install still pending, a full segment) becomes a machine hold recorded in the answer, so a
replay of the log reproduces every decision without the disk's history.

## 8. Batch, machine holds, causes, staff view

A batch runs in this order (`run3`):

1. Decode and authority (`FRAME_V1.md` §2-3). A request over 16 MiB is refused `LENGTH`; the host splits batches.
2. Row numbers: if either set's row count plus the batch's lines would reach 2^40, every line holds `ROWS(shard)`.
3. Widths: rule 3 for a line with a wide field, rule 4 for the rest of its payment, cause `FIELD_WIDTH(field)` (the
   first wide field in field order of the payment's first wide line).
4. Reads: first rows, then whole entries. A line one of whose reads (round 1 or 2) meets a block whose hash check fails
   holds with cause `BLOCK(shard, chunk, page, block)`, the first such block in read order; the rest of its payment
   holds with the same cause.
5. Budgets (§5): lines past the admitted prefix, and the rest of their payments, hold with cause
   `WINDOW(shard, why)`, `why` one of: install pending, directory growing, `DIRECTORY_FULL`, no chunk number, disk
   write failed, budget (no install pending).
6. `decideBatchIdx` on the kept lines; apply; record.

Each step only removes lines. Removing lines never adds a read (`reads_mono`, `fetch_local`), so the steps run once and
never loop. A held line is removed as if absent: the kept lines are decided exactly as `decideBatchIdx` decides the
smaller batch (`decide3_kept`), which is a valid input, and a held line joins no set (`held_no_set`). A held line may not
keep its keys, because the rules' `own` and decision order read its fetched entries, which are the very reads that
failed. A held payment is resent whole, and a duplicate of a kept line is then caught against the set that line joined.

Record changes to `FRAME_V1.md` §4: rule 6 is a machine hold, rule 7 another line of its payment machine held. For rules
3, 4, 6 and 7, `reasons` is the index of the line's cause in the answer's cause table (replacing "zero reasons" for 3
and 4), and there is no counterpart reference. The answer adds, after the records, `u32 causes` and per cause
`id 64 ‖ u16 length ‖ encCause`. Record order: decided lines in decision order, then the rule 3 and 4 lines in input
order, then the rule 6 and 7 lines in input order (`records_perm3`).

    encCause = tag u8 ‖ leb of each field
    causeId  = H(dom CAUSE ‖ encCause)

| Tag | Cause | Fields |
|---|---|---|
| 1 | `BLOCK` | shard, chunk, page, block |
| 2 | `WINDOW` | shard, why (0 install pending, 1 growing, 2 full, 3 no number, 4 disk, 5 budget) |
| 3 | `ROWS` | shard |
| 4 | `FIELD_WIDTH` | field (0-9 in `Line` order; widths in §1) |

A cause has no line, batch, payment or time field, so the same cause in any batch or on any resend has the same id
(`causeId_inj`: equal ids are equal causes unless SHA3-512 collides). Store causes name the shard; feed causes do not.

What staff see (Article XIV). The host gathers held lines by cause id into one item per cause (`items_once`), never one
per line: the plain reason, the money at stake (cents summed by the host, off the decision path), the deadline, the
owner and one action. Machine holds are resent automatically with the payment whole, first in the next batch; an item
appears only when a cause outlives its automatic remedy:

| Cause | Engine remedy | Item, only if it persists | Action |
|---|---|---|---|
| `BLOCK` | re-read; rebuild the block from the log (§13) | "Store block unreadable, payments waiting" | restore chunk file from backup |
| `WINDOW` install pending, growing, budget | wait one install or rebuild | "Store catching up, payments waiting" | none needed; shown with expected time |
| `WINDOW` full, no number | none | "Store shard full" | split the shard |
| `WINDOW` disk | retry write | "Store disk full or failing" | free or replace the disk |
| `ROWS` | none | "Store shard full" | split the shard |
| `FIELD_WIDTH` | none (it is the data) | "Feed field too wide: field" (the field and its width, §1) | fix the feed field |

## 9. Retry

Let `bt` be the signed batch count at load, frame `bt` the last committed (signed) frame and frame `bt + 1`, when
whole, the pending frame. A pending frame was never signed and nothing was released from it.

| Request | Action |
|---|---|
| batch `bt`, the logged `rq` | return the committed frame's answer bytes, which the signed head binds through `an` |
| batch `bt`, another `rq` | `CONFLICT` |
| batch `bt + 1`, nothing pending | decide and append |
| batch `bt + 1`, pending with another `rq` | `HOLD RETRY` (`retry3_other`), the answer word `CONFLICT` |
| batch `bt + 1`, pending with the same `rq` | decide afresh on the loaded state; equal bytes: keep the pending frame and return it; different bytes: cut the log after frame `bt`, append the fresh frame with `replaced = H(dom STORE/REPLACED ‖ pending frame)`, and return it |
| any other batch | `NOT_NEXT` |

"The same `rq`" compares the pending trailer's `rq` with the digest the engine checked over the host's request bytes.
The pending frame's own request bytes are neither read nor compared: the fresh decision is made from the host's bytes,
so request bytes edited on disk make the fresh frame differ and it replaces the pending one. A pending trailer that
cannot be read is `CORRUPT`; one whose `rq` differs stays `HOLD RETRY`. A committed frame is never replaced.

With nothing committed (`bt = 0`) the store's start, the genesis head and the first authority record, is the request's
own: a pending first frame does not choose it, and since its `rq` binds the request's date, previous head and keys, a
request that would start the store differently is `HOLD RETRY` against it. A first request refused before anything is
written leaves no start behind: the engine opens the store again for the next one. A committed first frame owns the start: at
load its request must be batch 1 on the genesis head of its own shard and date, and its trailer's `prev`, `shard` and
`rq` must agree with that request (`HEAD` otherwise).

The bytes released for batch `bt + 1` are always the fresh decision's (`retry3_fresh`): a stored pending frame is never
released as it is. Its bytes can differ for good reasons (machine holds depend on disk and timing) or bad ones (an edited
file); either way the fresh decision is the one the state and the request give. Taking the pending frame's machine holds
as an input was rejected: whoever can write the disk could then choose whose lines are held and so who is paid first.
The replacement is fixed by the engine itself and noted (`replaced` in the frame and root, counted by the verifier); it
is not a staff item (Article XIV.1).

## 10. Checker

`gate_verify3 DIR SHARD rows-offline|rows-tail [VDIR [IDLE_MS [BATCHES]]]` checks a store of `gate_hist3` (rows files and
log) in a process that shares no memory with the engine. It reads `key`, builds its own history in `VDIR` (its own tagged
rows files, tables, chain walk and reads: none of the engine's `Hist` or `StepH`) from batch 1, and `rows-tail` follows
the log as the engine writes. Per frame it:

1. decodes the request (`decodeB`) and admits it (`admitC`, `admB`); the first frame and one in 64 are also decoded and
   admitted by the specification's code and must agree;
2. decides the kept lines with the proved `decideRows` over its own reads, POSTING_CAP counted per core;
3. compares the answer bytes, `an`, the request, batch and authority digests, the heads, `Root4` and the head with the
   frame's, and requires the trailer `freshH` writes (no chunk events, install number 1, no windows).

The checker resumes from its last state (`vlast`) when its tag, the rows files and the log agree; otherwise it prints
`VSTORE_REFUSED` with the cause and rebuilds from the log. A mismatch stops the shard's releases and raises one item,
`VERIFY_MISMATCH(shard)`, with the batch and both digests; `VERIFY_COUNT`, `TORN_TAIL` and an empty log are refused
too (exit 3, 3, 4). Any other mode word is exit 64. The chunk-store modes `offline` and `tail` were removed on
2026-11-06 with the chunk-store engine. `RR_V3_SKIP=answer` turns the answer check off for the tamper tests; the run
prints `DIAGNOSTIC_INCOMPLETE` and exits 2.

## 11. Memory account

Engine, per stored line, derived from the layout as built (2.5 live entries and 3 rows per stored line, estimated). The
bar is 18 B/line; the layout as built does not meet it:

| Term | Derivation | B/line |
|---|---|---|
| Directory | 2.5 entries × 4 B / 0.75 (a rebuilt segment is about 75 % full, grown at 90 %) | 13.3 |
| Entry list of each chunk's metadata (`Meta.ents`, for growth) | 2.5 entries × 12 B (`dh` u64, first row u32) | 30.0 |
| Page hashes | `hb` = 64 B per page / 9.33 lines per page (28 slots / 3 rows) | 6.9 |
| Page fences | an array of boxed 8-byte values, about 24 B per page / 9.33 | 2.6 |
| Dead bits | 1 bit per row slot × 3 | 0.4 |
| Growth | the crowded segments rebuilt at once, at most all 64: one directory more while it runs | up to 13.3 |
| **Total** | | **about 53, 66 during a growth** |

Reading the entry lists from the chunk files at growth instead of keeping them, and keeping fences unboxed, gives about
21.5 B/line; under 18 needs a smaller directory slot or fewer entries per line. Neither is done.

Engine, per shard:

| Term | MB |
|---|---|
| Open window: 32 MB of rows (pin budget) and its map | 40 |
| Sealing window: 32 MB of rows and its map | 40 |
| Clean tier, map included | 128 |
| Batch: request ≤ 16 MiB, fetched rows ≤ 16 MiB, answer and scratch ≤ 8 MB | 40 |
| Runtime (projected, to be measured) | 8 |
| **Total** | **256** |

Verifier: the same per-line terms (about 20.9 B/line) and about 160 MB per shard (two windows 80, batch 40, a 32 MB
clean tier, runtime 8). The earlier per-stage budget left the verifier's directory out; it is needed for step 3 of §10. At 300M lines
in 4 shards, engine and verifier together need about 2 × 20.9 × 300M + 4 × 416 MB ≈ 14.2 GB of the laptop's 15 GB.

Measured (tests/gate_bench.py --e3, mixed corpus, 2,000 lines a batch, engine and verifier together, 2026-11-02):

| Measured | 66,000 lines (hr-28) | 206,000 lines (hr-24) |
|---|---|---|
| Engine, CPU µs/line (median of 3 batches) | 547 | 562 |
| Engine, wall µs/line | 400 | 435 |
| Verifier, CPU µs/line | 578 | 602 |
| Engine working set, MB (B/line) | 681 (10,819) | 1,354 (6,893) |
| Engine private bytes, MB (B/line) | 2,684 (42,645) | 5,129 (26,109) |
| Verifier working set, MB (B/line) | 308 (4,895) | 1,056 (5,377) |
| Load of a copy, s (replay of the window's frames) | 12.1 (11.9, 16 frames) | 12.6 (12.4) |

The measured memory is far over the derived account and the cause is not attributed: no heap profile was taken, so how
much is live state and how much is memory the allocator keeps after frees is unknown. A 300,000-line run (hr-21)
stopped at the guard's memory floor after 198,000 lines with 5.6 GB free at its start, so 300k, 1M and 3M lines and
the 3M / 0.3M ratio are not measured.

Revision 2 rows (256 bytes) change none of these terms: a page still holds 28 slots, and the windows, the clean tier and
the batch are byte budgets. A window holds about 42,000 lines instead of 82,000, so chunks are about 31,800 lines and a
shard of 75M lines has about 2,400 chunks. The clean tier holds half as many rows; its hit rate is unmeasured.

## 12. CPU and disk accounts

CPU, µs per line, all threads of one shard, starting from the earlier per-stage budget's total of 35.6 (projected):

| Change | µs/line |
|---|---|
| Key digests on the read tasks: 2.5 keys × 1.2 µs | +3.0 |
| Cold reads hash 23 SHA3-512 permutations (27.6 µs) instead of 1 KB of SHA3-512 (15 permutations, 18 µs), × 0.15 reads/line | +1.4 |
| Seal hashing: about 11.5 SHA3-512 permutations per line (13.8 µs) instead of 256 B of SHA3-512 (3.6, 4.3 µs) | +9.5 |
| Verifier's own fetch: key digests 3.0, probes and reads 3.0 | +6.0 |
| **Total** | **55.5, over the 40 cap** |

The decision thread's span is unchanged (17.5 µs/line); the overrun is in hashing on other threads. Of about 16 µs/line
of SHA3, a Keccak at the Lean model's 0.72 µs per permutation instead of the measured 1.2 saves about 6, and with the 10-31 SHA3-512 block hashes (about 28 µs/line of SHA3) about 11, which would give
about 44.5. That proved faster Keccak is the lever; until it lands the honest figure is 55.5.

Neither of the other options meets the cap:

- More shards do not. The account is CPU per line, summed over a shard's threads and its share of the verifier, and
  splitting lines over more shards does not change the work per line. 200k lines/s at 55.5 µs/line is 11.1 cores with 4
  shards or with 8, against 40 × 200k = 8.0 cores on the 8 physical cores. What 8 shards change is the decision thread:
  each shard needs 25k lines/s, a span of at most 40 µs/line against the 17.5 projected (2.3x margin, against 1.14x for
  4 shards at 50k lines/s, 20 µs). They cost RAM: 2 × 20.9 × 300M + 8 × 416 MB ≈ 15.9 GB, over the laptop's 15 GB.
- Without faster Keccak, the cuts found are not enough. (a) Blocks a seal writes enter the clean tier as written:
  `TierOk` holds by construction, since the writer hashed those bytes for the page header. This saves at most the
  engine's cold-read hashing, 0.15 × 27.6 = 4.1 µs/line, and only for reads of recently sealed chunks; the fraction is
  unmeasured. (b) SHA3-256 instead of SHA3-512 for `rq` and `an` (the 2026-10-31 ruling keeps SHA3-512, so this cut is out): 128 B/line in 0.94 permutations of the 136-byte rate
  instead of 1.78 of the 72-byte rate, 1.0 µs/line saved in the engine and 1.0 in the verifier. That weakens the hash
  that binds released answers to the signed head, so it is the owner's choice, not an engineering one. Both together give
  at best 55.5 − 4.1 − 2.0 = 49.4, and only if every cold read is of a recent chunk.

So 40 is not met without the faster Keccak. Rule out (b) and the best figure is 51.4.

A batch on one member: its lines share their near keys, so each distinct key's entry is read once for the batch and
counted once against the fetch budget; reads per batch are at most the lines' sum of distinct keys × 258 blocks
(1,026 rows over 4-slot blocks, plus one crossed) and never depend on the history's length. The decision reads per key
a summary computed once per batch (rows, first counterpart, whether a CAP member-month duplicate exists), groups the
payment outcome by payment in one pass (`payOutcomeG_eq`) instead of once per line, and the record carries only the
first counterpart reference, not the full list. `POSTING_CAP` is counted per key, as in the per-key state `s.perKey`;
per core is the target (section 5).

Disk, per stored line (derived, revision 2): chunk slots 3 × 282 B = 846 (7,896-byte pages of 28 slots), metadata
about 37 (per entry `dh` and first row, per page hash and fence), log about 200 (request line with real-length ids,
record and leaf): about 1,080 B/line live, against 773 measured for the old store. Revision 2 seal hashing is about
11.5 `HB` permutations per line (3 rows × 264 B, plus the header share), and the verifier's chunk rebuild (§10 step 5)
the same. Superseded versions wait for reclaim; at the reclaim threshold a chunk is at most half dead, so chunk bytes are at
most twice the live ones. A hot key rewrites its whole entry at each seal; that write traffic is bounded per seal by the
32 MB window.

### Measured history run (2026-11-01, tip 7a653119, tests/gate_bench.py --e3, run hg-7)

One store, the mixed corpus, 2,000 lines per batch, the engine and the verifier running together; three batches back to
back at each size (best / median). The run was asked for 0.3M, 1M and 3M stored lines. It stopped growing at 374,000
lines because free memory fell below 900 MB, so there is no 1M or 3M row and no 3M / 0.3M ratio: those values are missing.
Stage times are CPU µs per line; "wall" is the round trip. A seal and install happen every 32,000 lines.

| Measured | 306,000 lines | 374,000 lines |
|---|---|---|
| Engine, CPU µs/line | 1,141 / 1,188 | 1,469 / 1,492 |
| Engine, wall µs/line | 1,190 / 1,206 | 1,506 / 1,520 |
| Verifier, CPU µs/line | 1,148 / 1,234 | 1,133 / 1,180 |
| Verifier stages: fetch / decide / decide again / whole frame | 529 / 46 / 65 / 1,183 | 504 / 44 / 50 / 1,128 |
| Host: request frame / answer parse / corpus and request encoding | 3 / 27 / 52 | 4 / 29 / 60 |
| Engine plus verifier CPU, lines/s on 8 cores | 3,303 | 2,994 |
| Engine memory (working set), B/line | 5,965 | 5,609 |
| Verifier memory (working set), B/line | 4,540 | 4,144 |
| Engine disk, B/line (log 1,670, chunks 837) | 2,506 | 2,506 |
| Verifier store on disk, B/line | 837 | 761 |
| Engine file bytes read per line (includes the 400-byte request pipe) | 778 / 854 | 515 / 538 |
| Load of a copy of the store | refused (flat_replay after 1.9 s) | refused (flat_replay after 1.8 s) |

The 374,000-line batches ran while free memory was under 1 GB, so their engine time is not comparable. Across the build
(not the three timed batches), the engine's median batch time per line was 1,075 (0 to 50k lines), then 1,180 to 1,200 up
to 300k lines. Every 32,000 lines the seal batch took 2,700 to 3,100 µs/line, with no trend across 11 seals; spread over
the batches that is about 110 µs/line, in the engine and in the verifier (verifier events stage over the whole run).
Engine working set was 495 MB at 48,000 lines, 1,096 MB at 192,000 and 2,031 MB at 366,000, against the bar of 18 B/line
plus 256 MB. No permutation counts exist: `RR_E3_PROF` prints only load-stage times. Reloading a store with installed
chunks (106,000 lines and up) fails; one with none (18,000 lines) loads.

## 13. Hostile cases

**Chosen ids.** Behaviour: positions, fingerprints, pages and hash-map buckets depend on `s`, which submitters cannot
read; a lookup examines at most 16 slots and a fingerprint match costs one block read, whatever the keys
(`probe_le`). Even with `s` known, a key costs at most 16 candidate reads and a full segment only holds lines (below).
Staff see nothing unless a segment fills.

**Full stash.** Behaviour: an insert takes at most 32 kicks and then the stash; a full stash refuses the insert, the
install is not applied, and the segment grows off the decision thread, at most 8 tries. Meanwhile the open window keeps
filling; once the pin budget has no room, the lines that would grow it hold with `WINDOW(shard, growing)`, then
`WINDOW(shard, DIRECTORY_FULL)` if all tries fail (`full_holds`). Lines that change no entry still decide. Every step is
bounded, so the engine never loops. Staff see one "Store catching up" item only if growth outlasts its expected time,
and one "Store shard full" item if it fails.

**Every line of a batch on one member.** Behaviour: shared keys are read once (§12); the reads and the pinned growth
are bounded per distinct key, so the batch stays inside the per-line budget; lines past the fetch or pin budget hold
`WINDOW(shard, budget)` and are resent first in the next batch, and a single line always fits. Staff see nothing; the
delay is in the record.

**Torn or bit-flipped block.** Behaviour: the block fails its hash check; exactly the lines whose reads touch it, and
the rest of their payments, hold `BLOCK(...)` (`badBlock_local`, `badBlock_clean`); every other line decides as if those
lines were absent. The read task re-reads it once bypassing the OS cache. If it still fails, a read task rebuilds the
block's bytes by replaying the log up to the chunk's seal and writes them back only if they hash to the header's value,
which restores the original bytes and changes no state. A block in the clean tier is trusted as RAM is; the verifier's
own reads catch a block flipped in the engine's RAM. Staff see one item per block, and only if the rebuild fails.

**Full disk or failed fsync.** Behaviour: the frame is not committed, the answer is `IO`, nothing is sealed and nothing
is released. After a failed fsync the engine drops its in-memory state (the OS may have lost the dirty pages) and loads
again from disk at the next open. The host resends the same request bytes; a torn tail is cut and a whole pending frame
goes through §9. A failed chunk write delays the install, and the pin budget then holds lines with `WINDOW(shard, disk)`.
Staff see one "disk full or failing" item if it persists.

**Widths overflow.** Behaviour: a line value over its store width takes rule 3 and its payment rule 4, cause
`FIELD_WIDTH(field)`; the other lines decide as if those were absent (`wide_local` in `FRAME_V1.md`). Store counters fail
closed too: row numbers (`ROWS`), chunk numbers (`WINDOW(shard, no number)`), and a frame field that does not fit
refuses the frame (`FRAME`) with nothing written. Staff see one item per field or per shard.

## 14. Protected change record (Constitution XI.2): retry of a pending frame

- Exact predicate: `StoreLog.retryOf` and `FRAME_V1.md` §6 row "batch n, with the logged digest: the logged answer,
  byte for byte, and no state change", with its rule "a batch that was decided but not sealed is sealed later or not at
  all; it is never replaced".
- Invariant and failure it protects: III.3 retry identity (one request, one answer) and no double decision.
- Evidence it is unsuitable: review of the first binary-frame step found that a pending frame is unsigned, so serving it as it is releases
  bytes no signature covers and that whoever writes the disk can choose; and machine holds make a fresh decision
  legitimately differ from the stored one.
- Disposition: replace, for a pending frame only. A committed frame is still served byte for byte.
- Replacement control: `retry3` with `retry3_fresh` (released bytes are the fresh decision's), `retry3_other` (another
  request is `HOLD RETRY`), `retry3_serve` (a committed frame is served unchanged), the `replaced` digest bound in
  `Root4`, and the verifier's check of every frame.
- Scope and duration: the engine store of this document, from the build branch that implements it; permanent.
- Claims withdrawn: "the logged answer, byte for byte" for a pending frame, and `serve_retry` for it.
- Amendment, 2026-11-01, the retry rule as built. Predicate: a repair of 2026-10-31 refused a same-`rq` pending frame
  whose stored request bytes differed from the host's (`CONFLICT` on every retry), and took the start of an empty store
  from a pending first frame's request (a damaged one failed the load). Failure: a shard locked by one edited disk
  byte, against this section's rule that a same-`rq` pending frame is decided again and replaced. Disposition: the
  `rq` comparison of §9 alone decides, as in `retry3`; the host's checked bytes are decided and the pending frame replaced, and with
  nothing committed the start is the request's own. Unchanged: another `rq` is `HOLD RETRY`, a committed frame is
  served unchanged, a committed first frame owns the start, and the verifier checks every frame. Claims withdrawn: none
  beyond the repair's own refusal of differing bytes; `retry3` and its statements are still unproved.

## 15. Lean statement map

Statements that exist in the sources are in the `Engine3` files. These names are planned
and have no theorem yet: `fitsLine_fitsLine2`, `decideRowsX_eq`, `payIdx_eq`, `putLine_getLine`, `kbytes_inj`,
`kbOfRow_key`, `feedOrder_decode`, `pinInputW_eq`, `feedW_eq`, `feedW_at_eq`, `frameV2Pre_inj`, `inputCtxPre_inj`,
`inputV6_bind`, `decodeAns_leafCount`, `bd_of_records`, `treeSet_root`, `install_leaf_eq`,
`install_leaf_sound`.

| Statement | Says |
|---|---|
| `probe_le` | a lookup's candidates are at most 8 + `stashCap`, under any keys |
| `dir_sound` | `DirInv` and a live entry put its chunk among the key's candidates |
| `view3_eq` | `PinInv` and `DirInv`: the store's lookups are the per-key decision state `s.perKey` (per core is the target) |
| `apply_inv`, `seal_inv`, `install_inv`, `reclaim_inv` | each step keeps `PinInv` and `DirInv` |
| `rebuild_inv`, `grow_inv` | a rebuilt or grown directory satisfies `DirInv` |
| `tier_same`, `tier_bad_sub` | a clean-tier block equals the verified disk block (or SHA3-512 collides); the tier never turns a good read bad |
| `hot_same`, `hot_holds_sub` | decisions are the same with and without the clean tier when no read fails; the tier only shrinks the block holds |
| `reads_mono`, `fetch_local` | removing lines never adds a read; a batch reads only its lines' own reads |
| `decide3_kept`, `held_no_set`, `records_perm3` | kept lines decided as the smaller batch; held lines join no set; records are a permutation |
| `full_holds` | with the directory full, every line past the admitted prefix holds with that cause |
| `badBlock_local`, `badBlock_clean` | a block hold names a failed block one of the payment's lines reads; a payment that reads no failed block has none |
| `causeId_inj`, `items_once` | equal cause ids are equal causes or a collision; one staff item per cause |
| `verify_eq` | the verifier's recompute over its own state equals the engine's output |
| `retry3_fresh`, `retry3_other`, `retry3_serve` | §9 |
| `payOutcomeG_eq` | the grouped payment outcome equals `payOutcome` |
| `fitsLine_fitsLine2` | a line that fits the revision 1 widths fits revision 2's |
| `lineBytes2_size` | a line at revision 2 store widths is 245 bytes |
| `rowX_same_iff` | two fitting lines have equal store bytes exactly when they are equal: no payment or line id merges |
| `rowX_exactEq_iff`, `rowX_nearEq_iff`, `rowX_idEq_iff` | the store-byte compares are equality of `exactKey`, `nearKey`, `idKey` |
| `rowX_lt_eq` | the store-byte order is the rules' line order (`lineLe`) |
| `redoW_mem_iff` | a fitting row's payment is in the redo words exactly when it is in the redo list, for every payment number, including those of 2^64 and above |
| `decideRowsX_eq` (with the exact rows) | the fixed-row decider over exact rows decides as `decideBatchIdx` on revision 2 widths |
| `payIdx_eq` | on a decoded frame, grouping lines by request position is grouping by `Line.pay` |
| `putLine_getLine`, `kbytes_inj`, `kbOfRow_key` | a fitting line reads back from its 245 bytes; key bytes are one to one; a row's key bytes are its line's key |
| `feedOrder_decode`, `pinInputW_eq`, `feedW_eq`, `feedW_at_eq` | §19 |
| `frameV2Pre_inj`, `contextPre_inj`, `paymentPre_inj`, `inputV6Pre_inj`, `batchInputPre_inj` | §17-§18: injective preimages; equal digests mean equal fields or a named SHA3-512 collision (the four §18 ones proved) |
| `decodeAns_leafCount`, `bd_of_records` | §17: an answer whose leaves are not one per request is refused; the host's rebuilt rows are the engine's |
| `treeSet_root` | the state tree updated at install and reclaim has the root of the whole tree |
| `install_leaf_eq`, `install_leaf_sound` | §10 step 5 |

Not stated in Lean: the window and batch byte caps (enforced by the admission bounds, measured by the build branch), the
byte codecs of rows, pages and frames, and the timing of the threads.

The statements carry two hypotheses the table leaves implicit: chunk numbers below `2^cBits` where a directory slot
must encode its chunk (§3: chunk numbers are below 2^18), and distinct input positions where a hold is matched to its
line by position.

## 16. Deletion list

What the engine of this document replaces. Each item is deleted (git keeps it) in the change that lands its
replacement, not before; line counts are at this document's commit. Paths under `lean/` are relative to
`lean/BlindLedger/Gate/` unless written in full.

Lean, whole files:

| Path | Lines | What it is | Replaced by |
|---|---|---|---|
| `Flat/StoreLog.lean` | 2,121 | log v2 store: frames, writing, loading, reach; 8 unproved statements | §6 frame, log and load; `retry3`. Keep and move lines 1066-1122 (`foldl_pres`, `put_ok`, `inserts_ok`, `rebuild_ok`, `erase_ok`: the directory keeps its shape) and 1301-1334 (row order, `sortRows_equiv`) into `Flat/StoreTheorems.lean` |
| `Flat/StoreIndex.lean` | 929 | page marks of a chunk and the row window a lookup scans | §3 block fences and page headers |
| `Flat/StoreTombs.lean` | 487 | tombstones in metadata v2 and `BInv` | §3 metadata tombstones, `Fs3.dead` |
| `Flat/ChunkIo.lean` | 639 | byte-array chunk path and its log files (bench) | the engine's byte code for §3 and §6 |
| `Flat/ChunkIoEq.lean` | 830 | that code stated equal to the list model | the same statements for the engine's byte code |
| `Flat/ChunkIoWin.lean` | 713 | the lookup window's binary search on bytes | the same, for block fences |
| `Flat/Worker.lean` | 336 | the text frame worker: `flat init`, `flat open`, `commit` | `run3` behind the binary frame of `FRAME_V1.md` |
| `Flat/PayTheorems.lean` | 1,030 | what each `RULES_PAY` text line of a flat commit says | the record of §8 and `payOutcomeG_eq` |
| `Rules/RulesMain.lean`, `RulesShip.lean`, `RulesCrashtest.lean` | 32, 4, 10 | the text vector runner over the flat worker and its source hash | the engine executable on binary frames |

Lean, in part:

| Path | Lines | Deleted | Kept | Replaced by |
|---|---|---|---|---|
| `Flat/Store.lean` | 368 | `skey` (36-37); lines 147-234 and 238-367: `Fs`, `layout`, `isDead`, `kill`, `ixs`, `liveHash`, `liveHashes`, `hits`, `sealGet`, `lookup`, `view`, `changed`, `killRow`, `apply`, `sealWindow`, `freeNum`, `bornDead`, `place`, `regrow`, `load`, `install`, `reclaim`, `Book`, `current`, `deadOf`, `seqOf`, `applyTombs`, `placeTombs`, `reclaimBook`, `BInv`, `Live`, `KeyInv`, `liveItems`, `FInv` (220 lines) | `Dir` and its slot arithmetic (1-146), `sget`, `sortRows` | `sk`, `Fs3`, `hits3`, `lookup3`, `view3`, `changed3`, `apply3`, `seal3`, `freeNum3`, `install3`, `reclaim3`, `rebuild3`, `growSeg`, `Live3`, `KeyInv3`, `PinInv`, `DirInv` |
| `Flat/StoreTheorems.lean` | 1,445 | keys 17-34, rows to steps 386-1058, install 1172-1445 (965 lines) | directory 35-385, sorting a window 1059-1171 | §15 statements |
| `Flat/Chunk.lean` | 321 | row codec, 4 KB row pages, metadata v1 and v2, metadata read-back, commit record: lines 31-77, 91-205, 255-321 (229 lines) | `Row`, `bytesLt`, `rowLt`, `sortedB`, the whole-state tree 206-254 | §3 fixed rows, blocks, pages and metadata; §6 trailer, `Root4`, head |
| `Flat/ChunkTheorems.lean` | 318 | rows, pages, chunks 13-185 (173 lines) | the whole-state tree 186-318 | not stated in Lean (§15): codec tests on the build branch |
| `Rules/Run.lean` | 761 | the text directive layer: `parse`, `parseLine`, and `step` to `serve` (658-761) | the context, pins and admission at commit (472-657), called from the frame decoder | the `FRAME_V1.md` decoder |
| `Engine/OneProc.lean` | 89 | the tag 3 branch (vector text over the flat index) | the u32 frame loop and the tag 1 PUBLISH check | a tag for the binary frame, answered by `run3` |

Build targets (`lean/lakefile.toml`): executables `gate_rules` and `gate_rules_crashtest`, library `gate_rules_main`
and its nine input files; `gate_engine` stays and is rebuilt on the new engine. Pins and axiom lists drop the deleted
statements: `lean/BlindLedger/Gate/AxiomCheck.lean`, `tools/gate_print_axioms.lean`, `tools/STMT_PIN.txt`,
`tools/STATEMENTS`.

Host and tests:

| Path | Lines | Change | Replaced by |
|---|---|---|---|
| `app/right_rail_gate_decide.py` | 349 | the text frame: `RulesWorker` tag 3, `_flat_head`, the `flat init`/`flat open` and `req` lines of `decide` | the binary request and answer frames |
| `app/right_rail_gate_chain.py` | 102 | the chunk store description and the old head step; CHAIN/v1 stays | §6 head |
| `tests/test_flat_chunk_store.py` | 244 | deleted | load, torn tail and bit-flip tests of §6 and §13 |
| `tests/test_flat_worker.py` | 456 | deleted | crash and `BLOCK` hold tests of the engine |
| `tests/test_flat_host.py` | 749 | the tag 3 adapter tests (`FlatHostTests`, from line 80); the CHAIN/v1 codec tests stay | adapter tests on binary frames |
| `tests/test_gate_rules_vectors.py` | 180 | the text runner; the vectors stay | the vectors run through binary frames |
| `tests/test_gate_authority_frames.py` | 255 | done: the golden text file is gone and the test runs binary frames | |
| `tests/gate_bench.py`, `tests/test_gate_throughput.py` | 371, 163 | stage timings of the text path | the same benches on the engine |
| `conformance/FLAT_V1.md` | 194 | §5-7 (lines 78-194) | this document; §1-4 stay |

Kept, whatever the engine: Blind Ledger itself (`lean/BlindLedger/Financial/`, the correction transition), Mirror and
its continuity segments (`SEGMENT_V1.md`), the staff workspace, the provider app, the decision rules
(`Flat/Model.lean`, `Flat/Theorems.lean`, `Flat/Signed.lean`, `Rules/Spec.lean`, `Fast.lean`, `FastEq.lean`,
`Theorems.lean`, `OnepIndex.lean`), SHA3 and ML-DSA-87, `Flat/Io.lean`, `Flat/Bin.lean`, the payer, producer, verifier
and batch modules, `Engine/FrameLaws.lean`, `tests/test_gate_rules_worker.py`, `tests/_gate_shards.py`, and every
end-state design.

## 17. Request and answer, version 2

These replace, for this engine, `FRAME_V1.md` §2's digest field and feed rows and §4's extension.

Request header: `magic RRDQ ‖ version u16 = 2 ‖ shard u32 ‖ batch u64 ‖ digest 64`, 82 bytes, where

    rd_i   = H(request_i)                       the plain SHA3-512 of request blob i, which begins with its own domain
    digest = H("RR/GATE/FRAME/v2" 0 ‖ body′ ‖ rd_1 ‖ … ‖ rd_n)

`body′` is the body with each request blob replaced by its `u32` length, and `n` is the authority section's request
count. The engine hashes each request once, checks `digest` before it reads any other body byte (`DIGEST` otherwise),
and reuses each `rd_i` in the bypass check (`b.request == rd_i`). The preimage has a fixed layout with every length
kept, so it is one to one (`frameV2Pre_inj`). `rq` in the trailer and in Root4 is the batch identity of §18, not this
digest (§24). The body is `FRAME_V1.md` §2's with the feed rows of §19.

Answer header: `FRAME_V1.md` §4's. Extension, after `head` and `root` (§25):

    hold 16 ‖ grant id 64 ‖ notes u32, each blob2 ‖ leaves u32, each:
        outcome u8 ‖ reasons u64 ‖ authority u8 ‖ bypass flag u8 ‖ (bypass id 64) ‖ input 64     75 or 139 bytes
    ‖ adds u32, each blob2

Leaf `i` is request `i`'s. A rule reason is at bit `Reason.idx`; bits 62 (UNENCODABLE_PAYMENT) and 63 (SCOPE) are
leaf-only codes (`Frame.leafUnencodable`, `Frame.leafScope`). The grant id is carried once, all zero when there is none. The bypass flag is 0 when no
bypass released the payment and 1 when one did; 1 is followed by that bypass's id, which is not all zero, and any other
flag refuses the answer. The leaf copies no request field: the host takes tenant, program, payment, member, payee,
period, flow and cents from the request it sent, computes the lines root and `input` (§18) from those bytes, and
refuses the answer when a leaf's `input` differs from its own or the leaves are not one per request
(`right_rail_gate_decide._answer`). The token leaf is then built from the host's fields, the answer leaf and the grant
id, byte for byte as before. The appended rows stay in the answer, and the host checks `bd` from them, until the batch
digest moves to the records after the cosignature; then the host rebuilds them from the records and its request
(`rows_of_records`, `bd_of_records`) and the Lean decoder states the leaf count (`decodeAns_leafCount`, not yet
written). `an = H(dom ANSWER2 ‖ answer bytes before its head and root)` (§6).

## 18. Input commitment INPUT/v6

    ctx      = H(dom CONTEXT ‖ the request body before its request count)
    rd       = H(dom PAYMENT ‖ lp32 head ‖ lines root ‖ tail)
    input    = H("RR/GATE/INPUT/v6" 0 ‖ ctx ‖ rd)
    identity = H(dom BATCH-INPUT ‖ ctx ‖ input_1 ‖ … ‖ input_n)

`lp32` is a 4-byte big-endian length and then the bytes. The context is every body byte before the request count: today,
the head the batch follows, the feeds with their pins, the redone payments, the key-set pin, the grant floor, the signed
grant, key set and key-set steps, the signed bypasses and the engine release (`Gate.context`, `Frame.ctxBytes`). It is
hashed once per batch. For each request, `head` is its bytes before its lines (the domain, the payment's fields and the
line count, `Gate.requestHead`) and `tail` its bytes after them (the evidence count and references,
`Gate.requestTail`); the lines are hashed once, as the leaves of their root, so every request byte is hashed once
(`Gate.payDigest`). `input` is a token's input commitment (`Gate.inputV6`) and costs one permutation more per payment.
The batch's identity (`Frame.ident`, `Gate.batchInput`) is the trailer's and Root4's `rq`: the retry and pending checks
compare it, so a retry with the same payments and the same context (today, head, feeds, grant, key set, release) has the
same identity (III.3). Each preimage is one to one
(`contextPre_inj`, `paymentPre_inj`, `inputV6Pre_inj`, `batchInputPre_inj`, all proved), so equal values mean equal
fields or a SHA3-512 collision. `input` binds the request and the context, not the engine's outcome and not the bypass
id: which bypass released a payment depends on the decisions before it, so it is not a function of the request and the
signed bypasses (INPUT/v6 carries no bypass id). The host therefore checks each leaf's bypass id against the signed
bypasses it sent (the id is the SHA3-512 of the bypass document, for that payment's program and payment) and the grant
id against its grant, and refuses the answer otherwise (`_answer`, `_approval`); it refuses an answer with no leaves for
a batch with requests. The outcome it takes from the engine. An auditor rebuilds every other value from the request
frame alone. `identFast_eq` (the engine's byte computation is `Frame.ident`) is proved.

## 19. Feed facts as row words, and the order of feed rows

Feed rows in the request body (replacing `FRAME_V1.md` §2 item 2), little-endian, ids at the row widths of §1 so that a
feed id and a row field are the same bytes:

| Feed | Row | Bytes |
|---|---|---|
| DMF | `member 32 ‖ date u32` (`n33`, `0x01` implied) | 36 |
| Provider death | `id 21 ‖ date u32` | 25 |
| Exclusion | `id 21 ‖ start u32 ‖ stop u32` | 29 |
| Enrollment span | `member 32 ‖ plan 21 ‖ start u32 ‖ stop u32` | 61 |

Order rule: within each feed the rows are non-decreasing, compared field by field in the order listed, each field as a
number. The decoder checks the order in one pass and refuses the frame `RECORD` otherwise (`feedOrder_decode`). This is
the order `pinInput` sorts into, so the SNAPSHOT/v1 pin, whose format does not change, is computed over the rows as sent
(`pinInputW_eq`). A feed with an id of `256^21` or more cannot be sent: the host marks the feed state 2 (missing), as for
any row it cannot encode.

The engine keeps each feed as its byte range in the request, at fixed stride. A lookup reads the key as machine words
(member 4 words, an id 3 words) and binary-searches the range for the run of rows with that key; the result is the run's
start, `min(run, capN)` and whether the run exceeds `capN`. A row carries the same words read from its line bytes, so
deaths, exclusions and spans (with the CAP plan compared against the payee) are found by word compares. No number type,
no hash map and no copy is on this path. The model's feeds (`Feeds`, keyed by numbers, built by `feedsOf`) stay as the
view the proofs use: `feedW_eq` says the view of the decoded bytes is `feedsOf` of the request's context, and
`feedW_at_eq` says a word lookup gives that view's facts for the line's field.

## 20. Order of the steps that implement revision 2

Each step changes the code, its statements and its tests together, and leaves the build green.

1. Exact rows in the decision step, on the revision 1 widths: rows compared as store bytes or their words, payments
   named by request position, the redo set as exact payment words. This step lands before step 2: widening the widths
   while the decision step truncates would merge payments again.
2. Store widths and layouts (§1-§3), key bytes (`KEY2`), `STORE/BLOCK2`, `STORE/PAGE4`, `STORE/CHUNK2`, frames `RRF4`.
3. Feed rows and the feed words (§19).
4. Request version 2 (§17).
5. INPUT/v6 (§18).
6. Answer version 2 (§17).
7. The state tree kept in memory and updated at install and reclaim (`treeSet_root`); the root does not change.
8. The verifier's chunk rebuild at install (§10 step 5).

Steps 3-6 change the frame codec that the old and new engines share, so both move together and their decisions stay
comparable on the same frames.

## 21. Protected change record (Constitution XI.2): exact identifier widths and version 2 frames

- Exact predicate: revision 1 of §1-§3 (113-byte lines with `id` n33, `pay`, `payee`, `rendering` and `proc` in 8
  bytes; 4,096-byte pages; `KEY`, `STORE/BLOCK`, `STORE/PAGE3`, `STORE/CHUNK`, `STORE/FRAME3`, `RRF3`, `ANSWER`), the
  request digest `H(dom FRAME ‖ body)` and the 8-byte feed ids of `FRAME_V1.md` §2, the answer extension of
  `FRAME_V1.md` §4, INPUT/v5 of `FLAT_V1.md` §2, and the decision step's `Row` (`Flat/DecideRows.lean` `Row.of`, which
  keeps the low 8 bytes of `pay`, `payee`, `rendering` and `proc`, and the redo set filtered below `2^64`), with the
  statements `decideRows_eq`, `inputV5_inj` and `decode_encode` as they bind those formats.
- Invariant and failure it protects: III.3, canonical payment and line identity (no two payments or lines merge); II
  and III.5, fail closed (no feed fact silently missing, no truncation); every released token and answer byte bound to
  the signed head.
- Evidence it is unsuitable: a payment number of a real program and payment pair (`medicaid-ffs`, `pay-P1`) is 177
  bits; stored in 8 bytes, two payments that agree in their low 64 bits are one payment to the store and the decision
  step; every real line was held `FIELD_WIDTH`, so the store held only synthetic lines; feed provider ids and the
  enrollment plan are 8 bytes on the wire, so a real provider id cannot be sent; a request hashes its request blobs
  twice and each input commitment hashes the shared context again (82 + 0.056 N SHA3-512 permutations per line); the
  answer repeats request fields the host already holds; and the verifier did not rebuild a chunk's leaf at install.
- Disposition: replace.
- Replacement control: §1-§3 and §17-§19 of this document; the statements of §15 for them (`rowX_same_iff`,
  `redoW_mem_iff`, `decideRowsX_eq`, `kbytes_inj`, `frameV2Pre_inj`, `inputV6_bind`, `decodeAns_leafCount`,
  `feedOrder_decode`, `feedW_eq`, `install_leaf_sound`); the `FIELD_WIDTH` hold above the widths; the verifier's
  chunk-leaf rebuild (§10 step 5); and revision 1 stores refused at load.
- Scope and duration: the engine store of this document and the binary frames, from the build branch that implements
  each step of §20; permanent.
- Claims withdrawn: a line is 113 bytes; `id` is n33; every key digest is one permutation; the 4,096-byte page; the
  answer carries the appended rows and copies of request fields; INPUT/v5 is the token input commitment; "the body
  hashes to `digest`" in its version 1 form. No assurance is inherited: each replacement statement is unproved until
  it is proved.
- Ruling of 2026-10-31, "512": block, page, chunk, frame and root digests are SHA3-512 (`HB = H`, `hb = 64`); only the
  key digest `kd` stays SHA3-256, because a lookup digest is checked against the stored bytes and commits nothing.

## 22. Protected change record: diagnostic verifier results (2026-10-31)

- Exact predicate: `gate_verify3` previously returned exit 0 and printed `VERIFIED` after completing a run with
  `RR_V3_SKIP=answer`, `leaf`, or `file`, even though the named checks did not run.
- Invariant and failure: acceptance requires every verifier check. A successful diagnostic experiment must not
  authorize a release or stand in for complete verification (Constitution III.5 and VI.1).
- Evidence: `VerifyMain.main` passed the environment's skip list to `Verify.Ctx`, then unconditionally called
  `report` and returned 0. The three tamper tests in `test_engine3_verify.py` expected this incomplete success.
- Disposition: retain fault-injection checks for tests, relabel their completion, and make it nonzero.
- Replacement control: strict runs still execute every check and alone may return 0 with `VERIFIED`.
  Valid skip settings produce `DIAGNOSTIC_INCOMPLETE` and exit 2; malformed settings return 64 before opening a store.
  A detected mismatch remains exit 3. Tamper tests retain both their strict rejection and diagnostic controls;
  recovery tests assert that all skip labels and invalid settings cannot produce a verification claim.
- Scope and duration: the unpinned Engine3 verifier executable, permanently. Formats, digest domains, theorem
  statements, pinned production artifacts and the strict acceptance predicate are unchanged.
- Update 2026-11-06: only `answer` remains a valid skip; `leaf` and `file` belonged to the chunk-store modes and are now
  malformed settings (exit 64).
- Claims withdrawn: exit 0 / `VERIFIED` from an earlier run with skips is not verification evidence. Diagnostic
  output does not inherit strict-run assurance. This correction does not discharge the branch's existing proof debt.

## 23. The comparison of the old and the new engine

`tests/engine3_compare.py` sends the same batches to `gate_engine` and `gate_hist3` and compares, line by line, the
outcome, the rule and the reasons, and that each answer has the same lines. It does not compare where a counterpart is
stored (chunk and row): the layouts differ by design, and an entry still in a window has no place in this engine
(`Step.lean:9`). The old engine's place with none in the new one is therefore no difference; a place only the new engine
reports is. Head, root and the engines' own input commitments are not compared either; the verifier checks those.

Why this is enough: on the golden vectors (16 lines) and on the 100000-line mixed corpus (6137 lines) the only difference
between the engines was a place the old engine gave and the new one did not; outcome, rule, reasons and the set of lines
agreed everywhere. The answers carry a counterpart only as a place, never as a key or line, so which earlier entry a
line matched is not observable in them and is covered by the reasons alone.

## 24. Protected change record (Constitution XI.2): the payment commitments and the batch identity (2026-11-04)

- Exact predicate: INPUT/v5 of `FLAT_V1.md` §2 (`Gate.inputV5` over the whole request, the head, facts, today, grant id,
  bypass id, key-set digest and release, with `inputV5_inj`), revision 2's INPUT-CTX/v1 and INPUT/v6 over `ctx ‖ rd ‖
  bypass id` with `rd = H(request)` (§18 as of 2026-10-31), and the request frame digest `H(dom FRAME ‖ body)` as the
  logged `rq`, the retry key and the pending check (`Frame.serve`, `serve_conflict`, `serve_log`).
- Invariant and failure it protects: III.3, one request, one answer (a retry is served the logged answer, another
  request under the same batch number is refused); every token's input names everything its decision read (gate K2).
- Evidence it is unsuitable: each payment re-hashed its whole request with the batch's shared fields (about 12
  permutations a payment, 37-38 us/line of answer wait on the bench); `rd = H(request)` hashes the lines a second
  time after their root; and the frame digest keys retry on raw bytes, not on the payments.
- Disposition: replace.
- Replacement control: §18 (`Gate.context`, `Gate.payDigest`, `Gate.inputV6`, `Gate.batchInput`, `Frame.ident`); the
  proved statements `contextPre_inj`, `paymentPre_inj`, `inputV6Pre_inj` and `batchInputPre_inj`; `serve_retry`,
  `serve_conflict` and `serve_log` restated over `Frame.ident`; the spec vectors `context`, `pay-digest`, `input6` and
  `batch-input` in `tests/gate_vectors/gate_v1.vectors`, checked by `gate_vectors`; the retry, replay and crash tests of
  the worker and the history engine.
- Scope and duration: the token input commitment and the logged batch identity of `gate_engine` and
  `gate_hist3`, from commit 4b56a94c; permanent. The request frame still carries and checks its digest field.
- Claims withdrawn: INPUT/v5 is the token input commitment; `inputV5_inj`; the logged `rq` is the request frame digest.
  `identFast_eq` (the engine's byte identity equals `Frame.ident`) is proved; the tests and vectors check the engines'
  identity as well.
- Stored format: a store written before commit 4b56a94c logs the request frame digest as `rq`. It is not migrated
  (synthetic stores only). A load that replays one of its frames is refused with REPLAY and `STORE_FORMAT` on stderr
  (`staleFormat`); a retry of its last committed batch, which replays nothing, is answered CONFLICT.

## 25. Protected change record (Constitution XI.2): the answer leaf (2026-11-04)

- Exact predicate: `FRAME_V1.md` §4's answer leaf `outcome ‖ reasons ‖ authority ‖ flow ‖ cents ‖ grant id ‖ bypass ‖
  root ‖ input ‖` six request fields (about 370 bytes a payment), which the host decoded and turned into the token leaf,
  checking only the order of the payment ids against its request; and the engine's second, runtime decision of every batch with its list
  prefetch.
- Invariant and failure it protects: every token names the payment it decides and everything its decision read (gate
  K2); the host never trusts a field it can compute (H1); the fast decision equals the spec decision.
- Evidence it is unsuitable: the leaf repeats request fields the host already holds and the grant id once per payment;
  together with the per-payment hashing of §24 the answer wait was 37-38 us/line on the bench; the second decision
  doubles the decision CPU, and `decideRows_eq` already proves the two equal.
- Disposition: replace.
- Replacement control: §17's leaf of 71 or 135 bytes and the grant id once in the extension (`Frame.encLeaf`,
  `Frame.decLeaf`, `Frame.Fast.putLeaf`); the host computes the lines root and INPUT/v6 from its own request bytes and
  refuses an answer whose leaf input differs or whose leaves are not one per request (`app/right_rail_gate_decide.py`
  `_answer`, `app/right_rail_gate_codec.py` `payment_input`); the token leaf bytes are unchanged, checked by the spec
  vectors in `tests/test_flat_host.py` and `tests/test_flat_worker.py`; `decideRows_eq` (proved); the comparison of
  an answer with its encoding over the spec's leaves (`leavesMatch`, tested by `leaf_check`); the checker (`gate_verify3`)
  decides every frame with `decideRows` over its own reads (§10).
- Scope and duration: the answer of `gate_engine` and `gate_hist3` and the host decoder, from the
  commit that lands this record; permanent. The appended rows and `bd` stay in the answer until the batch digest moves
  to the records after the cosignature.
- Claims withdrawn: the answer leaf carries the payment's fields; every engine batch is decided twice. The host's `rq`
  check binds each leaf to its payment and context; it is not a recomputation, and `publishOk` recomputes nothing. Open:
  the history engine does not yet run the spec decision on 1 in 64 batches (its step has no spec store), and
  `decodeAns_leafCount` is not written, so the leaf count is checked by the host only.
