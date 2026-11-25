"""X12 envelope layer on synthetic files: pairing, counts, control numbers, repairs, delimiters, quarantine units."""

import io
import unittest

from app import right_rail_x12 as x12


def isa(control="000000001", es="*", sub=":", rep="^", term="~"):
    parts = ["ISA", "00", " " * 10, "00", " " * 10, "ZZ", "STATE".ljust(15), "ZZ", "PLAN".ljust(15), "260101", "1200", rep, "00501",
             control, "0", "P", sub]
    return es.join(parts) + term


def file_of(sets, *, es="*", sub=":", term="~", control="000000001", gs_date="20260102", gs_time="0930", kind="834",
            se_count=None, se_control=None, ge_count=None, ge_control=None, iea_count=None, iea_control=None, groups=None):
    """sets: list of lists of body segments written with * and : ; counts and controls are right unless overridden."""
    def fix(text):
        return text.replace("*", es).replace(":", sub)
    groups = groups or [sets]
    out = [isa(control, es, sub, "^", term)]
    for g, group_sets in enumerate(groups, 1):
        out.append(fix(f"GS*HP*STATE*PLAN*{gs_date}*{gs_time}*{g}*X*005010X220A1") + term)
        for n, body in enumerate(group_sets, 1):
            st = f"{n:04d}"
            out.append(fix(f"ST*{kind}*{st}") + term)
            out.extend(fix(b) + term for b in body)
            count = len(body) + 2 if se_count is None else se_count
            out.append(fix(f"SE*{count}*{st if se_control is None else se_control}") + term)
        out.append(fix(f"GE*{len(group_sets) if ge_count is None else ge_count}*{g if ge_control is None else ge_control}") + term)
    out.append(fix(f"IEA*{len(groups) if iea_count is None else iea_count}*{control if iea_control is None else iea_control}") + term)
    return "".join(out).encode("latin-1")


BODY = ["BGN*00*REF1*20260102*0930", "REF*0F*M1", "UNK*x"]


class EnvelopeTests(unittest.TestCase):
    def causes(self, parsed):
        return [(q.unit, q.cause) for q in parsed.quarantines]

    def test_clean_file_and_offsets(self):
        data = file_of([BODY, BODY])
        parsed = x12.parse(data)
        self.assertEqual((parsed.refused, parsed.quarantines, parsed.repairs), ("", (), ()))
        self.assertEqual([s.control for s in parsed.sets], ["0001", "0002"])
        self.assertEqual(parsed.sets[0].file_at, "2026-01-02T09:30:00")
        self.assertEqual(len(parsed.sha3_512), 128)
        for ts in parsed.sets:
            for seg in ts.segments:
                self.assertTrue(data[seg.offset:].startswith(seg.id.encode() + b"*"))
        self.assertEqual(parsed.sets[0].segments[1].elements, (("0F",), ("M1",)))

    def test_numbers_are_bounded(self):
        for places in (2, 3):
            self.assertEqual(x12.scaled("9" * 15, places), int("9" * 15) * 10 ** places)
            self.assertEqual(x12.scaled("0" * 5000 + "7", places), 7 * 10 ** places)
            self.assertEqual(x12.scaled("0" * 5000, places), 0)
            for text in ("9" * 5000, "9" * 40, "9" * 16, "-" + "9" * 16, "1" + "0" * 5000 + ".5"):
                self.assertIsNone(x12.scaled(text, places), text[:8])

    def test_sub_elements_split(self):
        parsed = x12.parse(file_of([["HD*021**HLT*PLAN:A"]]))
        seg = parsed.sets[0].segments[0]
        self.assertEqual(seg.elements[3], ("PLAN", "A"))
        self.assertEqual((x12.element(seg, 4, 2), x12.element(seg, 9)), ("A", ""))

    def test_count_and_control_faults_quarantine_the_smallest_unit(self):
        for kwargs, unit, cause in (
            ({"se_count": 99}, "set", "se_count_mismatch"), ({"se_control": "7777"}, "set", "se_control_mismatch"),
            ({"ge_count": 5}, "group", "ge_count_mismatch"), ({"ge_control": "9"}, "group", "ge_control_mismatch"),
            ({"iea_count": 2}, "interchange", "iea_count_mismatch"), ({"iea_control": "000000002"}, "interchange", "iea_control_mismatch"),
        ):
            parsed = x12.parse(file_of([BODY], **kwargs))
            self.assertEqual(parsed.sets, (), kwargs)
            self.assertEqual(self.causes(parsed), [(unit, cause)], kwargs)

    def test_one_bad_set_leaves_its_neighbours(self):
        parsed = x12.parse(file_of([BODY, BODY, BODY]).replace(b"SE*5*0002", b"SE*6*0002"))
        self.assertEqual([s.control for s in parsed.sets], ["0001", "0003"])
        self.assertEqual(self.causes(parsed), [("set", "se_count_mismatch")])

    def test_one_bad_group_leaves_the_other(self):
        parsed = x12.parse(file_of(None, groups=[[BODY], [BODY]]).replace(b"GE*1*2", b"GE*3*2"))
        self.assertEqual(len(parsed.sets), 1)
        self.assertEqual(self.causes(parsed), [("group", "ge_count_mismatch")])

    def test_truncated_last_segment_and_missing_closers(self):
        data = file_of([BODY])
        parsed = x12.parse(data[:data.rindex(b"IEA") + 3])  # cut in its last line: the set its SE closed is whole and kept
        self.assertEqual((len(parsed.sets), parsed.refused), (1, ""))
        self.assertEqual(self.causes(parsed), [("segment", "unterminated_segment"), ("interchange", "iea_missing")])
        parsed = x12.parse(data[:data.index(b"SE*")])
        self.assertEqual(parsed.sets, ())
        self.assertEqual(self.causes(parsed), [("set", "set_unclosed"), ("group", "group_unclosed"), ("interchange", "iea_missing")])
        self.assertEqual(parsed.refused, "iea_missing")  # nothing was read, so the file says why
        two = file_of([], groups=[[BODY], [BODY, BODY[:2]]])
        parsed = x12.parse(two[:two.rindex(b"SE*")])  # a closed group, a closed set in the open group, and the set the file ends in
        self.assertEqual(([s.offset for s in parsed.sets], parsed.refused), ([two.index(b"ST*"), two.index(b"ST*", two.index(b"GE*"))], ""))
        self.assertEqual(self.causes(parsed), [("set", "set_unclosed"), ("group", "group_unclosed"), ("interchange", "iea_missing")])
        parsed = x12.parse(file_of([BODY]) + data[:data.index(b"SE*")].replace(b"000000001", b"000000002"))
        self.assertEqual((len(parsed.sets), parsed.refused), (1, ""))

    def test_isa_inside_an_open_interchange_starts_a_new_one(self):
        first = file_of([BODY]).replace(b"IEA*1*000000001~", b"I?A*1*000000001~")
        parsed = x12.parse(first + file_of([BODY, BODY], control="000000002"))
        self.assertEqual(self.causes(parsed), [("segment", "bad_segment_id"), ("interchange", "iea_missing")])
        self.assertEqual([s.control for s in parsed.sets], ["0001", "0002"])

    def test_repeated_control_numbers_set_the_later_copy_aside(self):
        twice = x12.parse(file_of([BODY]) + file_of([BODY, BODY]))
        self.assertEqual((len(twice.sets), self.causes(twice)), (1, [("interchange", "duplicate_control")]))
        groups = file_of(None, groups=[[BODY], [BODY]]).replace(b"PLAN*20260102*0930*2*", b"PLAN*20260102*0930*1*").replace(b"GE*1*2", b"GE*1*1")
        parsed = x12.parse(groups)
        self.assertEqual((len(parsed.sets), self.causes(parsed)), (1, [("group", "duplicate_control")]))
        sets = file_of([BODY, BODY]).replace(b"ST*834*0002", b"ST*834*0001").replace(b"SE*5*0002", b"SE*5*0001")
        parsed = x12.parse(sets)
        self.assertEqual((len(parsed.sets), self.causes(parsed)), (1, [("set", "duplicate_control")]))

    def test_empty_control_numbers_do_not_match(self):
        gs = file_of([BODY]).replace(b"0930*1*", b"0930**").replace(b"GE*1*1", b"GE*1*")
        parsed = x12.parse(gs)
        self.assertEqual((parsed.sets, self.causes(parsed)), ((), [("group", "ge_control_mismatch")]))
        st = file_of([BODY]).replace(b"ST*834*0001", b"ST*834*").replace(b"SE*5*0001", b"SE*5*")
        parsed = x12.parse(st)
        self.assertEqual((parsed.sets, self.causes(parsed)), ((), [("set", "se_control_mismatch")]))

    def test_bom_crlf_and_padding_are_repaired_and_logged(self):
        clean = x12.parse(file_of([BODY]))
        data = file_of([BODY]).replace(b"~", b"~\r\n")
        data = b"\xef\xbb\xbf  \n" + data.replace(b"REF*0F*M1", b"  REF*0F*M1 ") + b"  \r\n\n"
        parsed = x12.parse(data)
        self.assertEqual(parsed.quarantines, ())
        self.assertEqual([s.elements for s in parsed.sets[0].segments], [s.elements for s in clean.sets[0].segments])
        self.assertEqual(len(parsed.repairs), 2)  # one count per cause, not one entry per line
        self.assertEqual(dict(parsed.repairs)["bom"], 1)
        self.assertGreater(dict(parsed.repairs)["whitespace"], 5)
        for seg in parsed.sets[0].segments:
            self.assertTrue(data[seg.offset:].startswith(seg.id.encode()))
        self.assertNotEqual(parsed.sha3_512, clean.sha3_512)  # the receipt is of the bytes as they arrived

    def test_line_feed_terminator(self):
        for data in (file_of([BODY], term="\n"), file_of([BODY], term="\r").replace(b"\r", b"\r\n"),
                     file_of([BODY], term="\n").replace(b"\n", b"\r\n")):
            parsed = x12.parse(data)
            self.assertEqual((parsed.quarantines, len(parsed.sets)), ((), 1), data[100:110])

    def test_other_delimiters_and_mixed_interchanges(self):
        one = file_of([BODY], es="|", sub=">", term="!", control="000000005")
        two = file_of([BODY, BODY], control="000000006")
        parsed = x12.parse(b"\xef\xbb\xbf" + one + two)
        self.assertEqual(parsed.quarantines, ())
        self.assertEqual([s.control for s in parsed.sets], ["0001", "0001", "0002"])
        self.assertEqual(parsed.sets[0].segments[1].elements, (("0F",), ("M1",)))

    def test_wrong_delimiter_inside_a_segment_quarantines_that_segment_only(self):
        parsed = x12.parse(file_of([["REF*0F*M1", "REF|0F|M2", "REF*0F*M3"]]))
        self.assertEqual(self.causes(parsed), [("segment", "bad_segment_id")])
        self.assertEqual([x12.element(s, 2) for s in parsed.sets[0].segments], ["M1", "M3"])

    def test_untrusted_files_are_refused_whole(self):
        for empty in (b"", b" \r\n "):
            self.assertEqual(x12.parse(empty).refused, "no_interchange")
        for data in (b"hello", b"ISA*short~", file_of([BODY])[1:], b"ISA" + b"*" * 200,
                     file_of([BODY]).replace(b"000000001", b"0000X0001", 1)):
            parsed = x12.parse(data)
            self.assertEqual((parsed.refused, parsed.sets), ("isa_unframed", ()), data[:20])

    def test_a_non_ascii_separator_is_an_untrusted_header(self):
        parsed = x12.parse(file_of([BODY], es="§"))
        self.assertEqual((parsed.refused, parsed.sets), ("isa_unframed", ()))

    def test_bad_utf8_is_counted_only_on_a_kept_segment(self):
        stray = file_of([BODY]).replace(b"GE*", b"REF*0F*X" + bytes([0xE9]) + b"~GE*")
        self.assertEqual((self.causes(x12.parse(stray))[0], x12.parse(stray).repairs), (("segment", "segment_outside_set"), ()))
        kept = x12.parse(file_of([["REF*0F*X"]]).replace(b"REF*0F*X", b"REF*0F*X" + bytes([0xE9])))
        self.assertEqual(kept.repairs, (("bad_utf8", 1),))

    def test_a_file_that_changes_while_it_is_read_is_refused(self):
        class Changing(io.BytesIO):
            seeks = 0

            def seek(self, *args):
                self.seeks += 1
                if self.seeks == 2:  # the first pass is over: the file is now another one
                    self.truncate(0)
                    super().seek(0)
                    self.write(file_of([BODY]).replace(b"M1", b"M9"))
                return super().seek(*args)

        sink = x12.Collector()
        sha, refused = x12.run(Changing(file_of([BODY])), sink, lambda _, ts: sink.add(ts, "set", ts._replace(segments=tuple(ts.segments))))
        self.assertEqual((refused, sink.get("set"), [q.cause for q in sink.envelope]), ("file_changed", (), ["file_changed"]))

    def test_bad_second_header_keeps_the_first_interchange(self):
        parsed = x12.parse(file_of([BODY]) + b"ISA*junk")
        self.assertEqual(len(parsed.sets), 1)
        self.assertEqual(self.causes(parsed), [("file", "isa_unframed")])

    def test_group_date_and_stray_segments(self):
        for kwargs in ({"gs_date": "20261340"}, {"gs_time": "2561"}):
            parsed = x12.parse(file_of([BODY], **kwargs))
            self.assertEqual((parsed.sets, self.causes(parsed)), ((), [("group", "bad_file_datetime")]))
        parsed = x12.parse(file_of([BODY]).replace(b"GE*", b"REF*0F*X~GE*"))
        self.assertEqual(self.causes(parsed)[0], ("segment", "segment_outside_set"))

    def test_isa_date_time_and_repetition_separator_are_checked(self):
        for old, new in ((b"*260101*1200*", b"*261301*1200*"), (b"*260101*1200*", b"*260101*2560*")):
            parsed = x12.parse(file_of([BODY]).replace(old, new))
            self.assertEqual((len(parsed.sets), self.causes(parsed), parsed.repairs), (1, [], (("bad_isa_stamp", 1),)), new)
        for sep in (b"A", b":"):  # not a separator of its own: no repetition separator, the data is still read
            parsed = x12.parse(file_of([["REF*0F*M^1"]]).replace(b"*1200*^*00501*", b"*1200*" + sep + b"*00501*"))
            self.assertEqual((len(parsed.sets), self.causes(parsed), parsed.repairs), (1, [], ()), sep)
        parsed = x12.parse(file_of([BODY, ["REF*0F*M^1", "REF*0F*M2"]]))
        self.assertEqual(self.causes(parsed), [("segment", "repeated_element")])
        self.assertEqual([x12.element(s, 2) for s in parsed.sets[1].segments], ["M2"])

    def test_quarantine_details_carry_no_file_text(self):
        parsed = x12.parse(file_of([["a*1"]]))
        self.assertEqual([(q.cause, q.detail) for q in parsed.quarantines], [("bad_segment_id", "")])
        parsed = x12.parse(file_of([BODY], se_control="7777", ge_control="9"))
        self.assertEqual([(q.cause, q.detail) for q in parsed.quarantines], [("se_control_mismatch", ""), ("ge_control_mismatch", "")])

    def test_bad_segment_id_is_counted_by_the_sender(self):
        parsed = x12.parse(file_of([["a*1"]]))
        self.assertEqual(self.causes(parsed), [("segment", "bad_segment_id")])
        self.assertEqual(len(parsed.sets), 1)  # SE counted it, so the set still matches; only the segment is lost
        self.assertEqual(parsed.sets[0].segments, ())


if __name__ == "__main__":
    unittest.main()
