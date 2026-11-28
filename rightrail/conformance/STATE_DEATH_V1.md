# State death file, synthetic state layout v1

The file a state sends with the deaths it knows, from its vital records or from its eligibility system, in the layout
of the repository's synthetic state, and the death fact rows (kind 2) a reader makes from it. Both state sources use
this one layout; the header says which one sent the file. Reader `app/right_rail_reader_state_death.py`; independent
verifier `app/right_rail_reader_state_death_independent.py`; vectors `tests/death_vectors/`; test
`tests/test_reader_state_death.py`.

Framing, field types, the header's first six fields, the trailer, refusal, statement identity, streaming and the
receipt are those of the eligibility system extract ([ELIG_EXTRACT_V1.md](ELIG_EXTRACT_V1.md) §1, §3, §4 and §5), with
this layout's name and records. The federal death file (keyed by Social Security number, with partial dates) is not
this layout.

## 1. Records

Header: the eligibility extract's header (bytes 0-70) with layout `RRDETH01`, then:

| Field | Bytes | Type | Meaning |
|---|---|---|---|
| proof | 70-71 | code | `V` state vital records (proof 1), `E` state eligibility system (proof 2) |

Detail row:

| Field | Bytes | Type | Meaning |
|---|---|---|---|
| type | 0-1 | `D` | |
| member | 1-21 | text | the state's member id |
| death | 21-29 | date | the date of death, a full calendar day |

Trailer: as the eligibility extract's.

## 2. Refusal

The eligibility extract's causes, with `unknown_layout` meaning a layout field other than `RRDETH01`, and:

| Cause | When |
|---|---|
| `bad_date` | also a partial date of death (a month or day of `00`): a death fact needs a full day |
| `unknown_code` | also a proof other than `V` or `E` |
| `death_after_as_of` | a date of death after the header's as-of date |
| `duplicate_key` | two detail rows have one statement identity (with identity code 1 alone: one member twice) |

## 3. Output

One fact row per detail row, in file order:
- `kind` 2, `op` 0, `subject` the member key (as the eligibility extract's), `vstart` the date of death, `vstop` and
  `until` `99991231`, `receipt` 0, `roff` the record's line number counted from 0.
- `sid`: the eligibility extract's rule with kind 2. Identity code: 1 the member key.
- `value`: `proof` from the header (1 or 2), then `record`, a keyed hash of the detail record keyed as the member key
  is: SHA3-512 of the tenant secret's length (u16, big-endian), the secret, `RR/GATE/DEATH-RECORD/v1` and a zero byte,
  then the record's 120 bytes without its line feed. The state keeps the record, so the tenant can recompute it; no
  one without the secret can match the record by hashing guessed member ids.

The receipt's `file`, a plain SHA3-512 of the whole file, does not hide the member ids. In a file of one row every
other byte is in the receipt and the fact row (sender, sequence, dates, cover, scope, proof, date of death, count), so
hashing candidate files with guessed member ids finds the member; each further row multiplies the guesses by the
roster. `file` must become a keyed digest for files that carry member ids before files of real members are read.

## 4. Memory

The eligibility extract's streaming and its bound (§5 there): a peak working set under 64 MB for either
implementation. Measured on generated death files, each size in its own process:

| Rows | File | Reader | Verifier |
|---|---|---|---|
| 100,000 | 12 MB | 31.3 MB | 41.9 MB |
| 1,000,000 | 121 MB | 31.6 MB | 47.5 MB |
