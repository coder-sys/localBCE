"""Deployment slots (D7): an unauthored slot reads strictest and loud, activation needs all five, bad packs are refused."""

from __future__ import annotations

import unittest

from app.right_rail_deployment_slots import SENTINEL, SLOTS, SlotError, Slots

CHANNELS = [["ch-a", ["S1", "835", "P1", "prog"]], ["ch-b", ["S2", "cash", "P1", "prog2"]]]
FULL = {
    "SENDER_CHANNELS": CHANNELS,
    "DEPOSIT_FEED": [["feed-1", ["S1"]]],
    "CHANNEL_BUDGET": [["S1", 500]],
    "THRESH": [["prog", 10_000]],
    "CHECKWRITE_CALENDAR": [[100, 200], [200, 300]],
}


class DeploymentSlotsTest(unittest.TestCase):
    def refused(self, **changes) -> str:
        with self.assertRaises(SlotError) as caught:
            Slots({**FULL, **changes})
        return caught.exception.args[0]

    def test_unauthored_slots_read_strictest_and_loud(self):
        with self.assertLogs("rightrail.slots", "WARNING") as logs:
            slots = Slots({})
        self.assertEqual(sorted(line.split()[1] for line in logs.output), sorted(f"id={s}" for s in SLOTS))
        self.assertTrue(all("decider=state payment authority" in line for line in logs.output))
        self.assertEqual(slots.empty(), sorted(SLOTS))
        self.assertIsNone(slots.read("SENDER_CHANNELS", "ch-a"))
        self.assertEqual(slots.read("DEPOSIT_FEED", "feed-1"), ())
        self.assertEqual(slots.read("CHANNEL_BUDGET", "S1"), 0)
        self.assertEqual(slots.read("THRESH", "prog"), 0)  # every act reaches it: two signers
        self.assertEqual(slots.cycle(150), (0, SENTINEL))
        with self.assertRaises(SlotError) as caught:
            slots.require_active()
        self.assertEqual(caught.exception.args[0], "slots_unauthored")
        self.assertIn("THRESH", caught.exception.args[1])

    def test_filled_slot_reads_its_value_quietly_and_a_missing_key_stays_strict(self):
        with self.assertNoLogs("rightrail.slots", "WARNING"):
            slots = Slots(FULL)
        slots.require_active()
        self.assertEqual(slots.read("SENDER_CHANNELS", "ch-a"), ("S1", "835", "P1", "prog"))
        self.assertEqual(slots.read("DEPOSIT_FEED", "feed-1"), ("S1",))
        self.assertEqual(slots.read("CHANNEL_BUDGET", "S1"), 500)
        self.assertEqual(slots.read("CHANNEL_BUDGET", "S2"), 0)
        self.assertEqual(slots.read("THRESH", "other"), 0)
        self.assertEqual(slots.cycle(150), (100, 200))
        self.assertEqual(slots.cycle(200), (200, 300))
        self.assertEqual(slots.cycle(300), (0, SENTINEL))

    def test_one_unauthored_slot_keeps_activation_refused(self):
        for sid in SLOTS:
            with self.subTest(sid), self.assertLogs("rightrail.slots", "WARNING"):
                slots = Slots({k: v for k, v in {**FULL, "DEPOSIT_FEED": []}.items() if k != sid} if sid == "SENDER_CHANNELS"
                              else {k: v for k, v in FULL.items() if k != sid})
            self.assertEqual(slots.empty(), [sid])
            with self.assertRaises(SlotError):
                slots.require_active()

    def test_authored_values_are_frozen_at_read_time(self):
        pack = {**FULL, "CHANNEL_BUDGET": [["S1", 500]]}
        slots = Slots(pack)
        pack["CHANNEL_BUDGET"][0][1] = 10 ** 9
        self.assertEqual(slots.read("CHANNEL_BUDGET", "S1"), 500)
        with self.assertRaises(TypeError):
            slots._tables["CHANNEL_BUDGET"]["S1"] = 1

    def test_bad_packs_are_refused_with_their_own_code(self):
        two = lambda *rows: [*CHANNELS, *rows]  # noqa: E731
        cases = {
            "slot_unknown": {"BOGUS": []},
            "slot_value": {"CHANNEL_BUDGET": [["S1", -1]]},
            "sender_two_kinds": {"SENDER_CHANNELS": two(["ch-c", ["S1", "cash", "P9", "prog9"]])},
            "program_two_kinds": {"SENDER_CHANNELS": two(["ch-c", ["S3", "cash", "P1", "prog"]])},
            "feed_is_sender_channel": {"DEPOSIT_FEED": [["ch-a", ["S1"]]]},
            "feed_covers_bad_sender": {"DEPOSIT_FEED": [["feed-1", ["S2"]]]},
            "feed_empty_with_835": {"DEPOSIT_FEED": []},
            "calendar_overlap": {"CHECKWRITE_CALENDAR": [[100, 250], [200, 300]]},
        }
        for code, change in cases.items():
            with self.subTest(code):
                self.assertEqual(self.refused(**change), code)
        for sid, bad in (("CHANNEL_BUDGET", [["S1", True]]), ("CHANNEL_BUDGET", [["S1", 5], ["S1", 6]]), ("CHANNEL_BUDGET", "ab"),
                         ("SENDER_CHANNELS", [["ch", ["S", "pigeon", "P", "g"]]]), ("THRESH", [[{"a": 1}, 5]]),
                         ("CHECKWRITE_CALENDAR", [[5, 5]]), ("DEPOSIT_FEED", [["f", "S1"]])):
            with self.subTest(sid, bad=bad):
                self.assertEqual(self.refused(**{sid: bad}), "slot_value")
        with self.subTest("two feeds cover one sender"):
            self.assertEqual(self.refused(DEPOSIT_FEED=[["f1", ["S1"]], ["f2", ["S1"]]]), "feed_covers_bad_sender")

    def test_authored_empty_feed_is_allowed_without_an_835_channel(self):
        Slots({**FULL, "SENDER_CHANNELS": [CHANNELS[1]], "DEPOSIT_FEED": []})


if __name__ == "__main__":
    unittest.main()
