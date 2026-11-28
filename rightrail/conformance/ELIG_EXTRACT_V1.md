# Eligibility system extract, synthetic state layout v1

The file a state eligibility system sends with its eligibility determinations, in the layout of the repository's
synthetic state, and the eligibility fact rows (kind 1) a reader makes from it. Another state's extract is another
layout table and its own golden vectors; the rules below about refusal, identity and output stay the same.
Reader `app/right_rail_reader_elig.py` on `app/right_rail_reader_fixed.py`; independent verifier
`app/right_rail_reader_elig_independent.py` on `app/right_rail_reader_fixed_independent.py`; vectors
`tests/elig_vectors/`; test `tests/test_reader_elig.py`.

## 1. Framing

- ASCII bytes. Every record is exactly 120 bytes followed by one line feed (`0x0A`). There is no byte-order mark, no
  carriage return and nothing after the last line feed.
- The first record is the header (`H`), the last is the trailer (`T`), and every record between them is a detail row
  (`D`). A file with no detail rows is allowed.
- Positions below are zero-based, end-exclusive. Bytes after a record's last field, up to 120, are spaces.
- Field types:
  - text: printable ASCII without spaces (`0x21`-`0x7E`), left-aligned, padded with spaces; never empty. Its value is
    the text without the padding.
  - number: ASCII digits only, the full width.
  - date: `yyyymmdd`, a real calendar day with a year from 1 to 9999. `99991231` is the open end.
  - code: one byte from the field's list.

## 2. Records

Header:

| Field | Bytes | Type | Meaning |
|---|---|---|---|
| type | 0-1 | `H` | |
| layout | 1-9 | text | `RRELIG01` |
| sender | 9-29 | text | the trading partner (receipt `sender`) |
| fseq | 29-41 | number | the source's own file counter (registry `fseq` rule 2) |
| asof | 41-49 | date | the file's as-of date |
| cover | 49-50 | code | `F` full file (receipt `cover` 1), `C` change file (2) |
| scope | 50-70 | text | what a full file covers (receipt `scope`) |

Detail row:

| Field | Bytes | Type | Meaning |
|---|---|---|---|
| type | 0-1 | `D` | |
| member | 1-21 | text | the state's member id |
| segment | 21-41 | text | the state's key for this eligibility segment |
| status | 41-42 | code | `E` eligible 1, `N` not eligible 2, `P` pending 3, `R` presumptive 4 |
| basis | 42-43 | code | `G` regular 1, `R` retroactive 2, `P` presumptive 3, `C` continuous 4 |
| program | 43-63 | text | the program |
| aid | 63-73 | text | the aid category |
| start | 73-81 | date | first covered day |
| end | 81-89 | date | last covered day, inclusive; `99991231` when open |
| determined | 89-97 | date | the day the state made the determination |
| notice | 97-105 | date | the day of the notice to the member; required, because a fact row stores only valid dates |

Trailer:

| Field | Bytes | Type | Meaning |
|---|---|---|---|
| type | 0-1 | `T` | |
| count | 1-10 | number | the number of detail rows |

## 3. Refusal

The rows of this layout are not independent: a file is read whole or refused whole, with one named cause, and nothing
is guessed. A file with several faults is refused with the cause of one of them. The causes:

| Cause | When |
|---|---|
| `file_too_large` | more than 2^30 bytes |
| `unterminated_record` | the file does not end with a line feed (an empty file included) |
| `bad_record_length` | a record is not exactly 120 bytes (a carriage return makes it 121) |
| `no_header` | the first record is not `H` |
| `no_trailer` | the file ends before a `T` record |
| `unknown_record_type` | a record after the header is neither `D` nor `T`, or any record follows the trailer |
| `unknown_layout` | the header's layout field is not `RRELIG01` |
| `bad_text`, `bad_number`, `bad_date`, `unknown_code` | a field breaks its type |
| `bad_filler` | a byte after a record's last field is not a space |
| `span_backwards` | a detail row's start is after its end |
| `determined_after_as_of` | a detail row's determination date is after the header's as-of date (the notice date may be later) |
| `duplicate_key` | two detail rows have one statement identity |
| `count_mismatch` | the trailer's count differs from the number of detail rows |
| `bad_entry` | the registry entry breaks the registry's rule for an entry (`app/right_rail_fact_registry.py` `entry_ok`), for example a kind named twice, which would leave the identity rule ambiguous |
| `kind_not_registered` | the registry entry lists no identity for kind 1 |
| `unknown_identity_field` | the registry entry names an identity code this layout does not define |

## 4. Output

One fact row per detail row, in file order, encoded by `app/right_rail_fact_codec.py`:
- `kind` 1, `op` 0 (this layout states determinations; it has no void and the reader never writes an end).
- `subject`: the member key, `member_key(tenant secret, member)` of `app/right_rail_gate_ffs.py`, the key claim lines
  carry.
- `sid`: SHA3-256 of `RR/GATE/SID/v1`, a zero byte, `src` (u16), the kind (u8), then each identity field the registry
  entry lists for kind 1, in its order, as a u16 length and its bytes (all little-endian). Identity codes: 1 the member
  key (32 bytes), 2 the segment text. The raw member id never enters an identity.
- `vstart` start, `vstop` end, `until` `99991231`, `receipt` 0 (the engine sets it), `roff` the record's line number
  counted from 0 (the header is 0, so the first detail row is 1).
- `value`: status, basis, program and aid as 21-byte identifier blocks, determined, notice.

One receipt (tag `0x40`) for the file as one shard: `src` from the registry entry; `cover` from the header; `asof`;
`cfrom` the as-of date for a full file (0 when the registry's `cfromRule` is 1) and 0 for a change file; `fseq`; `file`
the SHA3-512 of the file bytes; `sender` and `scope` as 21-byte identifier blocks; `channel`, `key` and `reader` as the
caller gives them (the transport and the reader release are not in the file); `rows` and `frows` the number of detail
rows; `kb`, `reread`, `admitted`, `same` and `quar` 0. Splitting rows by shard, admission and ends are the engine's.

## 5. Streaming and memory

A reader takes the file as a stream and holds one record at a time. It hands each fact row to the caller as it is made
and returns the receipt only after the trailer, the end of the file and every check have passed. The trailer's count
and repeated identities are known only at the end, so the rows handed over belong to the file only when the receipt
is returned; on a refusal the caller drops all of them, and no part of a refused file is ever accepted.

The one set that grows with the file, the statement identities met so far, lives on disk under a scratch directory the
caller gives (the reader: an SQLite file with a fixed page cache; the verifier: an external merge sort with fixed run
size and fan-in), and is removed when the read ends. Memory therefore has a fixed bound whatever the row count; the
scratch directory is what grows (the verifier: at most 96 bytes per row, the identities, their sorted runs and one
merge's output).

The bound: a peak working set under 64 MB for either implementation, the Python interpreter included. Measured on
generated extracts, each size in its own process (peak working set; about 27 MB before the read starts):

| Rows | File | Reader | Verifier |
|---|---|---|---|
| 100,000 | 12 MB | 30.9 MB | 40.8 MB |
| 300,000 | 36 MB | | 44.1 MB |
| 1,000,000 | 121 MB | 31.2 MB | 47.5 MB |
| 2,000,000 | 242 MB | | 47.5 MB |

The verifier levels off once a file fills two sort runs (131,072 rows): one sorted run is held while the next is
sorted.
