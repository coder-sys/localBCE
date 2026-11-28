"""The fast X12 reader's stream (`x12_read stream FILE OUT`, lean/BlindLedger/X12/Stream.lean) against its whole-file
read (`x12_read 837 FILE 1 OUT`), on small files made here.

For every file and every setting the stream's units must cover the file in order, and put together they must be the
whole read word by word: each word is the whole read's, or differs from it by the unit's start at bit 0, 16 or 24, or by
the length of the side text before the unit at bit 24 (where words pack offsets).  The side text and the closing bytes
must be the same, and the stream must be the same bytes whatever the number of units read at once (X12PAR 1 and 4).
The files: interchanges with different terminators whose elements hold the text of a header, interchanges without their
IEA (every fifth, and also placed where a unit that is read again ends next), control numbers at the ends of their range
and repeated, files cut short, an empty file, and headers on either side of the place where the stream reads its next
block.  Malformed settings and an OUT that is FILE are refused without writing anything."""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "lean" / ".lake" / "build" / "bin" / ("x12_read.exe" if os.name == "nt" else "x12_read")
BLOCK = 1048576  # the stream reads the file this many bytes at a time (Main.lean)
ENV = {k: v for k, v in os.environ.items() if not k.startswith("X12")}


def isa(ctl, sep="*", sub=":", term="~", rep="^"):
    fields = ["ISA", "00", " " * 10, "00", " " * 10, "ZZ", "SENDER         ", "ZZ", "RECEIVER       ", "260101", "1200",
              rep, "00501", ctl if isinstance(ctl, str) else "%09d" % ctl, "0", "P", sub]
    text = sep.join(fields) + term
    assert len(text) == 106, len(text)
    return text


# a terminator byte and then a header with other delimiters, as the text of an element
HEADER_TILDE = "~" + isa(999999999, "*", ":", "~", "U")
HEADER_QUOTE = "'" + isa(999999998, "*", ":", "'", "U")


def ichg(ctl, claims=2, sep="*", sub=":", term="~", rep="^", payload=None, isa_name=False, iea=True):
    j = lambda *xs: sep.join(xs)
    body = [j("BHT", "0019", "00", "1", "20260101", "1200", "CH"), j("HL", "1", "", "20", "1"),
            j("NM1", "85", "2", "CLINIC OF EXAMPLES", "", "", "", "", "XX", "1234567893")]
    key = (int.from_bytes(ctl.encode("latin-1"), "big") if isinstance(ctl, str) else ctl) % 10**6
    for k in range(claims):
        body += [j("HL", str(k + 2), "1", "22", "0"), j("SBR", "P", "18", "", "", "", "", "", "", "CI"),
                 j("NM1", "IL", "1", "ISA" if isa_name else "DOE", "JANE", "", "", "", "MI", "M%06d%04d" % (key, k)),
                 j("CLM", "C%06d%04d" % (key, k), "200", "", "", sub.join(["11", "B", "1"]), "Y", "A", "Y", "Y"),
                 j("HI", sub.join(["ABK", "E119"]))]
        if payload is not None and k == claims - 1:
            body.append(j("NTE", "ADD", payload))
        for ln in (1, 2):
            body += [j("LX", str(ln)), j("SV1", sub.join(["HC", "99213"]), "100", "UN", "1", "", "", "1"),
                     j("DTP", "472", "D8", "20260101")]
    segs = [j("ST", "837", "0001", "005010X222A1")] + body
    segs.append(j("SE", str(len(segs) + 1), "0001"))
    tail = [j("GE", "1", "1")] + ([j("IEA", "1", ctl if isinstance(ctl, str) else "%09d" % ctl)] if iea else [])
    allsegs = [j("GS", "XX", "SENDER", "RECEIVER", "20260101", "1200", "1", "X", "005010X222A1")] + segs + tail
    return isa(ctl, sep, sub, term, rep) + term.join(allsegs) + term


def mixed(n):
    """`n` interchanges in turn ended by ~, a newline and ', each with the header text of another terminator."""
    out = []
    for i in range(n):
        sep, term, rep = (("*", "~", "^"), ("|", "\n", "!"), ("*", "'", "!"))[i % 3]
        out.append(ichg(10 + i, 2 + i % 4, sep, ":", term, rep, payload=HEADER_QUOTE if i % 3 == 0 else HEADER_TILDE,
                        isa_name=i % 2 == 0) + ("\r\n" if i % 4 == 0 else ""))
    return "".join(out)


def every5x(n, low, cap):
    """Every fifth interchange without its IEA, and also the one that holds the place a unit read again ends next: at
    `low`, then twice the end of that interchange, up to `cap` (so every candidate cut in reach follows an open one)."""
    out, pos, dbl = [], 0, low
    for i in range(n):
        text = ichg(1000 + i)
        body = text[:text.rfind("IEA*")]
        missing = i % 5 == 4
        if dbl <= cap and pos < dbl <= pos + len(body):
            missing, dbl = True, 2 * (pos + len(body))
        text = body if missing else text
        out.append(text)
        pos += len(text)
    return "".join(out)


def spread(n):
    """Interchanges with no group whose controls fall one per page of the control set (32,768 controls), and every
    37th repeats a control from long before."""
    ctl = lambda i: (i * 32771) % 999999937
    return "".join(isa(ctl(i - 300 if i % 37 == 36 else i)) + "IEA*0*%09d~\n" % ctl(i - 300 if i % 37 == 36 else i)
                   for i in range(n))


def straddle(k):
    """A first interchange and white space up to `k` bytes before the end of the first block read, then a second
    interchange whose header starts there."""
    first = ichg(1, 3000)
    assert len(first) < BLOCK - 200
    return first + "\n" * (BLOCK - k - len(first)) + ichg(2) + ichg(3)


def corpus():
    """(name, bytes, X12LOW values in KiB, places where a unit must start)."""
    small = ("0", "1", "4", "512")
    three = ichg(1) + ichg(2, 3) + ichg(3)
    yield "mixed", mixed(40).encode("latin-1"), small, ()
    yield "mixed_bom", b"\xef\xbb\xbf  \r\n" + mixed(9).encode("latin-1") + b"JUNK AFTER THE LAST IEA~" + b"x" * 300, small, ()
    yield "every5", "".join(ichg(100 + i, iea=i % 5 != 4) for i in range(120)).encode("latin-1"), small, ()
    yield "every5x", every5x(200, 1024, 64 * 1024).encode("latin-1"), ("0", "1"), ()
    yield "no_iea", "".join(ichg(100 + i, iea=False) for i in range(30)).encode("latin-1"), small, ()
    yield "ctl_ends", "".join(ichg(c) for c in (0, 999999999, 32767, 32768, 0, 999999999, 1, 32768)).encode("latin-1"), small, ()
    yield "ctl_repeated", "".join(ichg(c, 1) for c in [7] * 3 + list(range(20, 80)) + [7, 20, 79]).encode("latin-1"), small, ()
    yield "ctl_not_digits", "".join(ichg(c) for c in ("ABCDEFGHI", "12345678 ", "000000001", "ABCDEFGHI")).encode("latin-1"), small, ()
    yield "ctl_spread", spread(3000).encode("latin-1"), ("0", "1", "4"), ()
    yield "cut_in_header", (three + isa(4)[:50]).encode("latin-1"), small, ()
    yield "cut_in_segment", three.encode("latin-1")[:-40], small, ()
    yield "cut_before_iea", three[:three.rfind("IEA*")].encode("latin-1"), small, ()
    yield "cut_in_iea", three.encode("latin-1")[:-3], small, ()
    yield "empty", b"", small, ()
    yield "not_x12", b"NOT AN INTERCHANGE~" * 40, small, ()
    for k in (106, 105, 50, 1):
        yield "straddle_%d" % k, straddle(k).encode("latin-1"), ("1",), (BLOCK - k,)
    yield "one_ichg", ichg(5, 9000).encode("latin-1"), ("1",), ()


def run(args, env=None, cwd=None):
    return subprocess.run([str(EXE)] + [str(a) for a in args], capture_output=True, text=True, timeout=120,
                          env=dict(ENV, **(env or {})), cwd=cwd)


def blocks(data):
    """The unit blocks (start, length, event bytes, side text) and the closing bytes after them."""
    i, units = 0, []
    while i < len(data):
        if struct.unpack_from("<Q", data, i)[0] != 7:
            return units, data[i:]
        _, base, ln, evn, sn = struct.unpack_from("<5Q", data, i)
        i += 40
        units.append((base, ln, data[i:i + evn], data[i + evn:i + evn + sn]))
        i += evn + sn
    return units, b""


class X12StreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not EXE.exists():
            raise AssertionError(f"the Lean build has no x12_read program at {EXE}")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        cls.files = []
        for name, data, lows, cuts in corpus():
            path = cls.dir / (name + ".x12")
            path.write_bytes(data)
            cls.files.append((name, path, lows, cuts))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def stream(self, path, low, par, out=None):
        out = out or path.with_name(f"{path.stem}.l{low}.p{par}.out")
        r = run(["stream", path, out], {"X12LOW": low, "X12PAR": str(par)})
        self.assertEqual(r.returncode, 0, f"{path.name} low {low} par {par}: {r.stderr}")
        return out.read_bytes()

    def assert_same_read(self, name, size, whole, stream):
        (wu, wtail), (su, stail) = blocks(whole), blocks(stream)
        self.assertEqual(len(wu), 1, name)
        self.assertEqual(wu[0][:2], (0, size), name)
        self.assertTrue(wtail, f"{name}: the whole read has no closing bytes")
        self.assertEqual(stail, wtail, f"{name}: closing bytes")
        at = 0
        for base, ln, _, _ in su:
            self.assertEqual(base, at, f"{name}: a unit does not start where the one before ended")
            at += ln
        self.assertEqual(at, size, f"{name}: the units do not end at the end of the file")
        self.assertEqual(b"".join(u[3] for u in su), wu[0][3], f"{name}: side text")
        wev = wu[0][2]
        self.assertEqual(sum(len(u[2]) for u in su), len(wev), f"{name}: event bytes")
        pos = side = bad = 0
        for base, _, ev, sd in su:
            for k in range(0, len(ev), 8):
                diff = struct.unpack_from("<Q", wev, pos + k)[0] - struct.unpack_from("<Q", ev, k)[0]
                bad += diff not in (0, base, base << 16, base << 24, side << 24)
            pos += len(ev)
            side += len(sd)
        self.assertEqual(bad, 0, f"{name}: {bad} words differ from the whole read")

    def test_stream_is_the_whole_read_at_every_setting(self) -> None:
        for name, path, lows, cuts in self.files:
            wout = path.with_name(path.stem + ".whole.out")
            r = run(["837", path, "1", wout])
            self.assertEqual(r.returncode, 0, r.stderr)
            whole = wout.read_bytes()
            for low in lows:
                with self.subTest(file=name, low=low):
                    one, four = self.stream(path, low, 1), self.stream(path, low, 4)
                    self.assertEqual(one, four, f"{name} low {low}: par 1 and par 4 differ")
                    self.assert_same_read(name, path.stat().st_size, whole, one)
                    starts = {u[0] for u in blocks(one)[0]}
                    self.assertEqual([c for c in cuts if c not in starts], [], f"{name} low {low}: missed cuts")

    def test_empty_file_gives_the_whole_reads_bytes(self) -> None:
        path = self.dir / "empty.x12"
        wout = self.dir / "empty.whole2.out"
        self.assertEqual(run(["837", path, "1", wout]).returncode, 0)
        self.assertEqual(self.stream(path, "512", 1), wout.read_bytes())

    def test_malformed_settings_are_refused_and_write_nothing(self) -> None:
        src = self.files[0][1]
        cases = [("X12LOW", v) for v in ("abc", "16MB", "", "-1", "1.5")] + \
                [("X12PAR", v) for v in ("x", "-1", "4 ", "0", "")]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                out = self.dir / "refused.out"
                if out.exists():
                    out.unlink()
                r = run(["stream", src, out], {key: value})
                self.assertNotEqual(r.returncode, 0)
                self.assertFalse(out.exists())

    def test_wrong_arguments_are_refused(self) -> None:
        src = self.files[0][1]
        cwd = self.dir / "cwd"
        cwd.mkdir(exist_ok=True)
        for args in (["stream", src], ["stream", src, "a.out", "b.out"], ["stream"]):
            with self.subTest(args=args[1:]):
                r = run(args, cwd=cwd)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(os.listdir(cwd), [])

    def test_out_that_is_file_is_refused_and_file_is_kept(self) -> None:
        src = self.dir / "self.x12"
        data = mixed(6).encode("latin-1")
        src.write_bytes(data)
        link = self.dir / "self_link.x12"
        os.link(src, link)
        names = [src, src.name, os.path.join(str(self.dir), ".", src.name), link]
        if os.name == "nt":
            names.append(Path(str(src).upper()))
        for out in names:
            with self.subTest(out=str(out)):
                r = run(["stream", src, out], cwd=self.dir)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(src.read_bytes(), data)

    def test_an_existing_out_is_replaced_whole(self) -> None:
        path = self.files[0][1]
        expect = self.stream(path, "512", 1)
        out = self.dir / "old.out"
        out.write_bytes(b"\xff" * (len(expect) + 5000))
        self.assertEqual(self.stream(path, "512", 1, out), expect)


if __name__ == "__main__":
    unittest.main()
