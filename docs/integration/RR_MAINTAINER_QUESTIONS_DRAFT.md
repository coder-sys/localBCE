# Draft: questions for the RightRail maintainer before the trunk move

Draft for the owner to send, 2026-11-23. Not sent by Claude. Whether it was sent is recorded in `LOG.md`.

Background: `TRUNK_MOVE_ASSESSMENT.md` and `TRUNK_MOVE_ASSESSMENT_REVIEW.md`. Questions 1 to 5 block the move.

---

Got the signer, thanks. The hash matches the pin. I also fetched rightrail-main (af4c7c52) and checked what moving onto it does to my work. You're right that I should move first. Before I replay my changes I need your call on a few things, because they touch your formats:

**1. Which commit should I move onto?** af4c7c52, or a later one where the pins and TCB report are regenerated? A lot of the last week is marked WIP (signed rule sets, fact frames), and I don't want to rebase onto something that's about to change shape.

**2. Answer version number.** I built a decision answer "version 3" with u64 reason masks and 20-byte records. You've since used answer version 3 for the fact answer (RRDA), and Engine3 tells them apart by that number. What number should the widened decision answer take? Or do you want decision answers to stay version 1 with u32 masks? Note I need 29 rule reasons after the eligibility rule and 32 after share of cost, plus the two leaf-only codes, so u32 runs out at that point.

**3. Leaf-only bits.** My five eligibility reasons sit at idx 24-28, but your leaf-only codes are at bits 24 and 25 with leaves bounded at 2^26. Should I number mine above yours, or do the leaf-only codes move (I had them at 62/63)?

**4. How should the eligibility rule get its data?** I planned two extra per-request snapshot feeds: kind 7 eligibility and kind 8 share of cost, both still free in your tree. You now have the ELIG fact intake, but no rule reads it yet, and rule sets still read the four feeds. Which do you want: a fifth and sixth feed, or the rule reading belief from the fact store? If it's the fact store: the ELIG value has no benefit level and there's nothing for share of cost. Are those planned?

**5. `pack1_fires`.** Adding my rule to `Rules.fires` makes that theorem false. Should the eligibility rule go into `coreFires` as fixed Lean, or become a rule-set source and pack?

Smaller ones, no rush:

- Are you going to build the section 19 sorted 32-byte-member rows soon? It changes the strides of any six-feed frame.
- You keep amending GATE_RULES_V1 in place; I renamed to V2 and deleted v1. Which do you want?
- If masks widen, can the links-file tail (4-byte reasons) and the 16-byte record stride in HLinks change?
- OK if localBCE carries the newer RightRail history and I send changes back as PRs? I have a small FLAT_V1 doc fix ready as a first one.
- The fact-record design doc cited in the Lean headers isn't in the tree. Can you share it?
