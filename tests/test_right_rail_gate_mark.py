"""The checked mark helper (``app/right_rail_gate_mark.py``): the read rules both adapters share.  Synthetic, non-PHI."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from app import right_rail_gate_mark as marks

DOMAIN, BODY, KEY = b"d|", 10, 2  # a 10-byte body whose first two bytes are its key
SIZE = BODY + marks.CHECK


def rec(key: int) -> bytes:
    return marks._record(DOMAIN, key.to_bytes(KEY, "big") + bytes(BODY - KEY))


def bad(record: bytes) -> bytes:
    return record[:3] + bytes([record[3] ^ 1]) + record[4:]


class MarkReadTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "m.mark"

    def read(self, data: bytes | None):
        if data is not None:
            self.path.write_bytes(data)
        return marks.read(self.path, DOMAIN, BODY, KEY)

    def test_no_file_empty_file_or_a_torn_first_record_is_no_mark(self) -> None:
        self.assertEqual(self.read(None), (None, 0, False))
        for data in (b"", rec(1)[:20], rec(1)[:-10] + bytes(10), bad(rec(1))):  # nothing, short, half-written, damaged
            self.assertEqual(self.read(data), (None, 0, False))
        marks.append(self.path, DOMAIN, 0, rec(1)[:BODY])  # the first write over the torn one repairs it
        self.assertEqual(self.read(None), (rec(1)[:BODY], SIZE, False))

    def test_a_torn_tail_falls_back_to_the_record_before_and_the_next_append_repairs_it(self) -> None:
        whole = rec(1) + rec(2)
        for torn in (rec(1) + rec(2)[:20], rec(1) + rec(2)[:-10] + bytes(10)):  # cut short; second page never written
            self.assertEqual(self.read(torn), (rec(1)[:BODY], SIZE, True))
            marks.append(self.path, DOMAIN, SIZE, rec(2)[:BODY])
            self.assertEqual(self.path.read_bytes(), whole)  # the torn bytes gone, the record written again
        self.assertEqual(self.read(whole), (rec(2)[:BODY], 2 * SIZE, False))  # whole records: no torn tail
        self.assertEqual(self.read(whole + bytes(7)), (rec(2)[:BODY], 2 * SIZE, True))  # bytes after the last whole one

    def test_both_of_the_last_two_records_bad_or_keys_not_rising_is_corrupt(self) -> None:
        for data in (rec(1) + bad(rec(2)) + bad(rec(3)), rec(2) + rec(1), rec(2) + rec(2)):  # both bad; falling; equal
            with self.assertRaises(marks.MarkCorrupt):
                self.read(data)

    def test_a_bad_record_deeper_in_the_file_is_not_read(self) -> None:
        body, end, fell = self.read(bad(rec(1)) + rec(2) + rec(3) + rec(4))
        self.assertEqual((body, end, fell), (rec(4)[:BODY], 4 * SIZE, False))

    def test_the_directory_is_synced_when_the_mark_is_written_from_nothing_only(self) -> None:
        with mock.patch.object(marks.os, "open", side_effect=PermissionError) as opened:  # a failed sync is ignored
            marks.append(self.path, DOMAIN, 0, rec(1)[:BODY])  # new file
            marks.append(self.path, DOMAIN, 0, rec(1)[:BODY])  # empty or torn-only at read (end 0)
            marks.append(self.path, DOMAIN, SIZE, rec(2)[:BODY])
        self.assertEqual(opened.call_args_list, [mock.call(self.path.parent, marks.os.O_RDONLY)] * 2)

    def test_a_mark_read_costs_the_same_however_long_the_file(self) -> None:
        got = []

        class Counting:  # records each read's size over a real handle
            def __init__(self, handle) -> None:
                self.handle = handle

            def __enter__(self):
                return self

            def __exit__(self, *exc) -> None:
                self.handle.close()

            def seek(self, *args):
                return self.handle.seek(*args)

            def read(self, size):
                got.append(size)
                return self.handle.read(size)

        for count in (3, 10_000):
            self.path.write_bytes(b"".join(rec(i) for i in range(count)))
            got.append(count)
            with mock.patch.object(marks, "open", lambda path, mode: Counting(open(path, mode)), create=True):
                tail, end, _ = marks.read(self.path, DOMAIN, BODY, KEY)
            self.assertEqual((int.from_bytes(tail[:KEY], "big"), end), (count - 1, count * SIZE))
        self.assertEqual(got, [3, SIZE, SIZE, 10_000, SIZE, SIZE])  # two records read, whatever the length


if __name__ == "__main__":
    unittest.main()
