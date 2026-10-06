"""Deployment slots (founder D7; hold-release r4.2 section 10): the one registry and the one reader.

A slot is a table of (key, leaf) pairs the state signs into the Control Pack.  A slot the pack does not author reads as
its registered strictest value, with a log line, and activation is refused until every slot is authored.  The reader
is the only way to a value, and a pack that fails any check below never becomes a ``Slots``.  Synthetic, non-PHI.
"""

from __future__ import annotations

import logging
from types import MappingProxyType

SENTINEL = 2 ** 63 - 1  # the cycle end of a time no calendar covers
_log = logging.getLogger("rightrail.slots")


class SlotError(ValueError):
    """args[0] is the refusal code."""


def _text(x: object) -> bool:
    return type(x) is str and x != ""


def _cents(x: object) -> bool:
    return type(x) is int and 0 <= x < SENTINEL


def _freeze(x: object) -> object:
    return tuple(map(_freeze, x)) if type(x) in (list, tuple) else x


# id: (question, decider, source, strictest leaf, leaf check(key, leaf)).  A key the table lacks reads the same
# strictest leaf: no channel, no feed, no budget, a threshold every act reaches (two signers), no calendar cycle.
SLOTS = {
    "SENDER_CHANNELS": ("Which channel carries which payer's files, and of what kind?", "state payment authority", "Control Pack",
                        None, lambda k, v: _text(k) and type(v) is tuple and len(v) == 4 and _text(v[0]) and v[1] in ("835", "cash", "gate") and _text(v[2]) and _text(v[3])),
    "DEPOSIT_FEED": ("Which feed channel reports real deposits, for which 835 senders?", "state payment authority", "Control Pack",
                     (), lambda k, v: _text(k) and type(v) is tuple and all(map(_text, v))),
    "CHANNEL_BUDGET": ("How many cents may a sender's machine release per cycle?", "state payment authority", "Control Pack",
                       0, lambda k, v: _text(k) and _cents(v)),
    "THRESH": ("At what cents per program do two employees sign?", "state payment authority", "Control Pack",
               0, lambda k, v: _text(k) and _cents(v)),
    "CHECKWRITE_CALENDAR": ("Which cycles (start, end in ms) reset the cumulative window?", "state payment authority", "Control Pack",
                            SENTINEL, lambda k, v: _cents(k) and _cents(v) and k < v),
}


class Slots:
    """The slot values of one validated pack: ``pack`` maps a slot id to its (key, leaf) pairs; an id absent from it is unauthored."""

    def __init__(self, pack: dict) -> None:
        if set(pack) - set(SLOTS):
            raise SlotError("slot_unknown")
        tables = {}
        for sid, pairs in pack.items():
            table, pairs = {}, _freeze(pairs)
            for pair in pairs if type(pairs) is tuple else (None,):
                if type(pair) is not tuple or len(pair) != 2 or not SLOTS[sid][4](*pair) or pair[0] in table:
                    raise SlotError("slot_value", sid)
                table[pair[0]] = pair[1]
            tables[sid] = MappingProxyType(table)
        self._tables = tables
        self.authored = frozenset(tables)
        self._cross_checks()
        for sid in self.empty():
            _log.warning("DEPLOYMENT_SLOT_EMPTY id=%s decider=%s", sid, SLOTS[sid][1])

    def _cross_checks(self) -> None:
        channels = self._tables.get("SENDER_CHANNELS", {}).values()
        for code, pick in (("sender_two_kinds", lambda c: c[0]), ("program_two_kinds", lambda c: c[2:])):
            kinds = {}
            for c in channels:
                if kinds.setdefault(pick(c), c[1]) != c[1]:
                    raise SlotError(code)
        senders835 = {c[0] for c in channels if c[1] == "835"}
        feeds = self._tables.get("DEPOSIT_FEED", {})
        if "DEPOSIT_FEED" in self.authored and not feeds and senders835:
            raise SlotError("feed_empty_with_835")
        covered = [s for ids in feeds.values() for s in ids]
        if feeds.keys() & self._tables.get("SENDER_CHANNELS", {}).keys():
            raise SlotError("feed_is_sender_channel")
        if not set(covered) <= senders835 or len(covered) != len(set(covered)):
            raise SlotError("feed_covers_bad_sender")
        spans = sorted(self._tables.get("CHECKWRITE_CALENDAR", {}).items())
        if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
            raise SlotError("calendar_overlap")

    def empty(self) -> list[str]:
        return sorted(set(SLOTS) - self.authored)

    def read(self, sid: str, key: object) -> object:
        """The leaf the pack authored for ``key`` in slot ``sid``, else the slot's strictest leaf."""
        return self._tables.get(sid, {}).get(key, SLOTS[sid][3])

    def cycle(self, now: int) -> tuple[int, int]:
        """(start, end) of the calendar cycle holding ``now``; (0, SENTINEL) where none does."""
        return next(((s, e) for s, e in self._tables.get("CHECKWRITE_CALENDAR", {}).items() if s <= now < e), (0, SENTINEL))

    def require_active(self) -> None:
        """Activation is refused while any slot is unauthored."""
        if self.empty():
            raise SlotError("slots_unauthored", "DEPLOYMENT SLOTS EMPTY, strictest values in force: " + ", ".join(self.empty()))
