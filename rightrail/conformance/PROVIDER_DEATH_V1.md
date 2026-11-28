# Provider death list, synthetic state layout v1

The file a state sends with the providers its provider enrollment system knows died, in the layout of the repository's
synthetic state, and the provider death fact rows (kind 4) a reader makes from it. Reader
`app/right_rail_reader_provider_death.py`; independent verifier `app/right_rail_reader_provider_death_independent.py`;
vectors `tests/provdeath_vectors/`; test `tests/test_reader_provider_death.py`.

Framing, field types, the header's first six fields, the trailer, refusal, statement identity, streaming, memory and the
receipt are those of the eligibility system extract ([ELIG_EXTRACT_V1.md](ELIG_EXTRACT_V1.md) §1, §3, §4 and §5), with
this layout's name and records. The layout is the state exclusion list's ([EXCLUSION_V1.md](EXCLUSION_V1.md) §1) with a
date of death in place of the exclusion fields.

An NPI is a public identifier of a provider, not member data: nothing in this layout is keyed and the subject is the NPI
itself.

## 1. Records

Header: the eligibility extract's header (bytes 0-70) with layout `RRPDTH01`; bytes 70-120 are filler. Detail row:

| Field | Bytes | Type | Meaning |
|---|---|---|---|
| type | 0-1 | `D` | |
| npi | 1-11 | text | the provider's NPI: ten digits whose Luhn sum with the prefix 80840 is a multiple of ten |
| death | 11-19 | date | the date of death, a full calendar day |

Trailer: as the eligibility extract's.

## 2. Refusal

The eligibility extract's causes, with `unknown_layout` meaning a layout field other than `RRPDTH01`, and:

| Cause | When |
|---|---|
| `bad_date` | also a partial date of death (a month or day of `00`): a death needs a full day |
| `bad_npi` | the NPI is not ten digits passing its check (checked after the field types) |
| `death_after_as_of` | a date of death after the header's as-of date |
| `change_file` | `read_provider_deaths` only: the header's cover is `C`, so the file is not the whole list (§3) |
| `duplicate_key` | two detail rows have one statement identity, so one NPI twice, with the same date or two: the file is refused, as the state death file refuses one member twice. Nothing picks one of two dates. |

## 3. Output

One fact row per detail row, in file order:
- `kind` 4, `op` 0, `subject` the NPI as a 21-byte identifier block (a length byte, the ten digits, zeros) then 11 zero
  bytes, `vstart` the date of death, `vstop` and `until` `99991231`, `receipt` 0, `roff` the record's line number counted
  from 0.
- `sid`: the eligibility extract's rule with kind 4. Identity code: 1 the NPI's ten digits.
- `value`: `proof` 1, the state's provider enrollment system.

The feed list is the same rows as the gate takes them (`right_rail_gate_ffs.feeds`, `provider_deaths`): the header's
as-of date and `[(NPI, date of death), ...]` in file order, dates `YYYY-MM-DD`. `feed_of` in the reader makes it from the
fact rows and the receipt; the receipt's `asof` is the header's.

- **Only a full file gives a list.** The rules read a present, fresh, non-empty provider death feed as the whole list of
  the dead, so a list made from a change file (cover `C`) would pass a provider who died earlier and is not in it.
  `read_provider_deaths` therefore refuses a change file with `change_file`, after the file's own checks; the caller then
  sends the absent feed, as `feeds` does for a federal exclusion supplement, which says nothing of who is not on it. A
  change file still reads into fact rows (`read_provider_death`), as the state death file's do.
- **An empty full list is accepted** and gives a feed of 0 rows. The rules require a feed with at least one row, so the
  engine reviews every line: a state that reports no deaths cannot let a line pass on this feed.

## 4. Memory

`read_provider_death` streams as the eligibility extract does ([ELIG_EXTRACT_V1.md](ELIG_EXTRACT_V1.md) §5). The feed
list holds every row, so `read_provider_deaths` keeps the file's fact rows in memory and its memory grows with the file.
