# Exclusion lists v1

The provider exclusion lists and the exclusion fact rows (kind 3) a reader makes from them. `list` in a fact's value
names the list: 1 the federal exclusion list (the HHS-OIG List of Excluded Individuals/Entities), 2 a state's own
exclusion list. Federal debarment (list 3) is not read yet. Readers `app/right_rail_reader_state_exclusion.py` and
`app/right_rail_reader_federal_exclusion.py`; independent verifiers `app/right_rail_reader_state_exclusion_independent.py`
and `app/right_rail_reader_federal_exclusion_independent.py`; vectors `tests/excl_vectors/`; test
`tests/test_reader_exclusion.py`.

Both lists make the same fact row:
- `kind` 3, `op` 0, `until` `99991231`, `receipt` 0, `roff` the row's line number counted from 0 (the header is 0).
- `subject`: the provider's NPI as a 21-byte identifier block (a length byte, the ten digits, zeros), then 11 zero bytes.
- `vstart`, `vstop`: the days the provider is excluded, both included; `vstop` `99991231` when there is no end.
- `value`: `list`; `type`, the exclusion authority as the file writes it, as a 9-byte identifier block (the fact codec
  takes no space padding); `waiver`, 1 when a waiver lets the provider's claims in this program be paid, else 0.
- `sid`: the eligibility extract's rule ([ELIG_EXTRACT_V1.md](ELIG_EXTRACT_V1.md) §4) with kind 3. Identity codes: 1
  the NPI's ten digits, 2 the type's text (empty when it did not read), 3 `vstart` and 4 `vstop` as eight digits.

## 1. State exclusion list, synthetic state layout

Framing, field types, the header's first six fields, the trailer, refusal, statement identity, streaming, memory and the
receipt are those of the eligibility system extract (ELIG_EXTRACT_V1.md §1, §3, §4 and §5), with layout `RRSEXC01`
and no further header field (bytes 70-120 are filler). Detail row:

| Field | Bytes | Type | Meaning |
|---|---|---|---|
| type | 0-1 | `D` | |
| npi | 1-11 | text | the provider's NPI: ten digits whose Luhn sum with the prefix 80840 is a multiple of ten |
| authority | 11-19 | text | the state's exclusion authority (no space inside) |
| start | 19-27 | date | the first day excluded |
| reinstated | 27-35 | date | the day the provider is reinstated; `99991231` when not reinstated |

Added causes, checked in this order after the field types:

| Cause | When |
|---|---|
| `bad_npi` | the NPI is not ten digits passing its check |
| `excluded_after_as_of` | the start is after the header's as-of date |
| `reinstated_after_as_of` | a reinstatement (not `99991231`) after the as-of date |
| `span_backwards` | the reinstatement is on or before the start |
| `duplicate_key` | two rows have one statement identity |

Fact row: `list` 2, `vstart` the start, `vstop` the day before the reinstatement (`99991231` when not reinstated),
`type` the authority, `waiver` 0 (a state's own list has no waiver). Memory: §2.4.

## 2. Federal exclusion list

The file is the list's CSV as published, the full list or a monthly supplement; its columns are those of
`app/right_rail_reader_leie.py` (`LEIE_COLUMNS`), and every field is read there, so a field reads here exactly as it
does on the claim path. The file states nothing of its own coverage, so the caller gives the as-of date (yyyymmdd),
`cover` (1 the full list, 2 a supplement), `fseq`, `sender` and `scope` (1 to 20 printable ASCII characters, no space),
and the program's state (two capital letters), whose waivers count. Anything else is `bad_coverage`.

### 2.1 Framing and refusal

Lines end with LF or CR LF. A leading byte-order mark, a header in any case and blank lines are taken (a blank line
holds no row). The first line is the header; every later non-blank line is one row. The whole file is refused, with
the first cause met in file order, only for:

| Cause | When |
|---|---|
| `bad_coverage` | a caller argument above is missing or out of range |
| `bad_entry` | the registry entry breaks the registry's rule for an entry (ELIG_EXTRACT_V1.md §3), for example kind 3 named twice |
| `kind_not_registered` | the registry entry lists no identity for kind 3 |
| `unknown_identity_field` | it lists an identity code other than 1-4 |
| `file_too_large` | more than 1 GiB |
| `line_too_long` | a line longer than 65,536 bytes before its line end |
| `unterminated_record` | the file does not end with a line feed |
| `no_header` | an empty file, or a header that is not UTF-8 or does not parse as CSV |
| `bad_header` | a column named twice, or one of the read columns missing |
| `not_utf8` | a row that is not UTF-8 |
| `unparseable` | a row that does not parse as one CSV record (strict quoting) |
| `column_count` | a row with a cell count other than the header's |
| `unholdable_row` | a row with no name whose NPI is there but does not read: no fact and no name can hold it |
| `no_rows` | no row with a name, in a full list or in a supplement that has rows |
| `identity_merges_npis` | two rows with an NPI have one statement identity but not one NPI (an identity rule without code 1 can do this); found once the whole file is read |

The claim path takes the list as absent for each of these. Every other fault stays in its row (2.2).

### 2.2 Rows

A field that does not read (`app/right_rail_reader_leie.py`: text over 256 characters or with control characters, an
NPI that fails its check, an exclusion type of no known shape, a date on no calendar day) is taken as missing; its row
is kept. A row's name is its last name, else its business name. Then:
- With an NPI that reads, the row is a fact (list 1).
- Otherwise it is an entry of the set-aside list, with why: 1 no NPI; 2 an NPI that does not read; 3 no NPI and a blank
  exclusion type; 4 no name and no NPI. The claim path holds claims by name for 2 and 3, as it does today.
- A fact whose statement identity an earlier row of the file has, with the same NPI, is not made again (with another
  NPI the file is refused, 2.1): the row is a set-aside entry with
  why 5, and the first row's fact takes the most restrictive reading of all the rows with that identity: the earliest
  start, the latest end (no end when any row has none) and waiver 0 when any row has 0. It keeps the first row's line
  number, statement identity and exclusion type.

A fact's span is the claim path's. The row is not trusted when it has no name, its exclusion type is blank, its
exclusion or reinstatement date is after the as-of date, or it has a reinstatement on or before its exclusion date
(0001-01-01 when it has none). An untrusted row is excluded from 0001-01-01 with no end. A trusted row runs from its
exclusion date (0001-01-01 when it has none) to the day before its reinstatement (no end when it has none). `type` is
the exclusion type, empty when it did not read.

`waiver` is 1 only when the row is trusted, its exclusion type, exclusion date, reinstatement date, waiver date and
waiver state all read (a field there but not read gives 0), its waiver state is the caller's state, and it has a
waiver date and an exclusion date with the waiver on or before the exclusion date. A waiver dated later stays 0: the claims hold. The claim
path applies no waiver today.

A set-aside entry, in file order: the line number (u40), why (u8), the exclusion type as a 9-byte identifier block,
then the last, first, middle and business names, each a u16 length and its UTF-8 bytes (length 0 when blank or not
read). Both implementations must give the same entries, byte for byte.

### 2.3 Receipt

As the eligibility extract's, with the caller's `cover`, `asof`, `fseq`, `sender` and `scope`: `frows` the number of
rows, `rows` the facts, `quar` the set-aside entries, so `rows + quar = frows`.

### 2.4 Streaming and memory

As the eligibility extract's §5: one line is held at a time, and fact rows and set-aside entries each reach the caller
in file order and belong to the file only when the receipt is returned. Since a later repeat can narrow a fact, facts
are handed over only after the whole file has passed. The reader keeps the facts in an SQLite file under the caller's
scratch directory and hands set-aside entries over as it meets them; the verifier writes each row's output and identity to scratch,
sorts the identities on disk, and hands the output over after the whole file has passed. The bound is the eligibility
extract's: a peak working set under 64 MB. Measured on generated lists (the federal ones with 1 row in 100 set aside),
each size in its own process:

| List | Rows | File | Reader | Verifier |
|---|---|---|---|---|
| state | 100,000 | 12 MB | 28.1 MB | 39.2 MB |
| state | 1,000,000 | 121 MB | 28.2 MB | 39.5 MB |
| federal | 100,000 | 12 MB | 29.8 MB | 41.9 MB |
| federal | 1,000,000 | 123 MB | 29.7 MB | 42.7 MB |

## 3. Not read yet

- Federal debarment (list 3).
- A waiver that starts after the exclusion: the exclusion would hold before the waiver and not after it. One fact
  cannot say that; such a row has waiver 0 and holds throughout.
- A field that does not read in a row that is a fact is not counted in the receipt; the fact carries the safe value
  (a missing date widens the span, a missing type is empty, a missing waiver is 0).
