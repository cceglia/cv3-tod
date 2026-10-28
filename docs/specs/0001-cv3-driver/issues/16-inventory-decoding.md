# 16: Inventory decoding

**What to build:** the sensor's template inventory is decoded and enrolling a finger reveals which id
the sensor assigned to it — the fact that unlocks listing, deletion and true revocation.

**Blocked by:** 06 (enrolment)

**Status:** ready-for-human

Time box: **three hardware sessions or one calendar week, whichever comes first.** Reaching it without a
decoded format is a legitimate outcome: record what the replies look like and stop.

- [ ] `cvctl inventory` dumps the sensor's template list, decoded rather than as raw bytes
- [ ] Taking the inventory around an enrolment identifies the id the sensor assigned to the new template
- [ ] The decoded reply format is written down next to the command, so the next reader does not have to
      repeat the work
- [ ] If the format is not decoded within the box, the observed replies and the failed hypotheses are
      recorded and the outcome is stated as undecoded
