"""Streaming synthetic claim history for the speed bench (test-only; synthetic, non-PHI, nonpayment; moves no money).

``lines(seed, start, count, span)`` yields claim lines ``start .. start+count-1`` of one large state's five-year history, one
at a time.  Line ``i`` is a pure function of ``(seed, i)``, so nothing is held in memory, any stretch can be regenerated (a long
seed resumes where it stopped) and a run is reproducible.  ``span`` is the number of lines that fill the five years (the
dates run from five years before the batch date up to it).

The mix is an assumption, not a measurement; it is a plain-English guess at a state fee-for-service stream, to be replaced
by real shares when an agency shares them.  Of every 1,000 lines: 900 are new claims; 30 are retries (the same claim id and
the same content sent again); 35 are true duplicates (a new id, the same member, provider, date, procedure, units and amount:
the exact key); 20 are near-duplicates (a different billing provider and amount for the same member, rendering provider, date
and procedure: the near key); 15 are corrections (the same claim with the amount changed and a new id).  A repeat points at an
earlier new claim: 7 in 10 within the last 50,000 lines, the rest anywhere earlier, so repeats keep reaching into old history.
Members are 3,000,000 with heavy users (square-law skew), providers 60,000, rendering providers 90,000, 40 procedure codes
weighted to a few common ones, 1 to 4 units, amounts fixed per code and unit.  Every line carries three keys (exact, near, id)."""

import datetime

M64 = (1 << 64) - 1
MEMBERS, PAYEES, RENDERERS, RECENT, DAYS = 3_000_000, 60_000, 90_000, 50_000, 1826
ID0 = 100_000_000
CODES = [99213 + 7 * j for j in range(40)]
CENTS = [4500 + 650 * j for j in range(40)]
# cumulative per-thousand: new, retry, exact duplicate, near-duplicate, correction
KINDS = (("new", 900), ("retry", 930), ("duplicate", 965), ("near", 985), ("correction", 1000))
ASOF = datetime.date(2027, 3, 15)


def mix(x: int) -> int:
    """SplitMix64: a fixed, fast, well-spread integer hash."""
    x = (x + 0x9E3779B97F4A7C15) & M64
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & M64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & M64
    return x ^ (x >> 31)


def draw(seed: int, i: int, k: int) -> int:
    return mix(mix(seed * 0x2545F4914F6CDD1D ^ i) + k)


def kind(seed: int, i: int) -> str:
    if i == 0:
        return "new"
    t = draw(seed, i, 0) % 1000
    return next(name for name, top in KINDS if t < top)


def target(seed: int, i: int) -> int:
    """The earlier new claim that line ``i`` repeats."""
    r = draw(seed, i, 7)
    k = i - 1 - (r >> 8) % min(i, RECENT) if r % 10 < 7 else (r >> 8) % i
    while kind(seed, k) != "new":
        k -= 1
    return k


def day(k: int, span: int) -> int:
    d = ASOF - datetime.timedelta(days=DAYS - min(DAYS, k * DAYS // max(span, 1)))
    return d.year * 10000 + d.month * 100 + d.day


def claim(seed: int, k: int, span: int) -> tuple:
    """(member, payee, rendering, date, code, units, cents) of the new claim at index ``k``."""
    u = lambda n, s: (draw(seed, k, s) % 1_000_003) ** 2 * n // 1_000_003 ** 2
    p = u(40, 5)
    n = 1 + draw(seed, k, 6) % 4
    return (1 + u(MEMBERS, 1), 1 + draw(seed, k, 2) % PAYEES, 1 + draw(seed, k, 3) % RENDERERS, day(k, span), CODES[p], n, CENTS[p] * n)


def line(seed: int, i: int, span: int) -> str:
    what = kind(seed, i)
    c = claim(seed, i if what == "new" else target(seed, i), span)
    if what == "new" or what == "duplicate":
        pass
    elif what == "retry":
        i = target(seed, i)
    elif what == "near":
        c = (c[0], 1 + (c[1] + draw(seed, i, 8)) % PAYEES, c[2], c[3], c[4], c[5], c[6] + 100 + draw(seed, i, 9) % 900)
    else:
        c = (*c[:6], c[6] + 100 + draw(seed, i, 9) % 900)
    return f"{ID0 + i}:{ID0 + i} FFS_CLAIM {c[0]} {c[1]} {c[2]} {c[3]} {c[4]} {c[5]} {c[6]}"


def lines(seed: int, start: int, count: int, span: int):
    for i in range(start, start + count):
        yield line(seed, i, span)
