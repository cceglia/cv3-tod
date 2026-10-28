# 16: Inventory decoding

**What to build:** whether `0x2F` is the sensor's template inventory is settled, and if it is, its reply
is decoded so that enrolling a finger reveals which id the sensor assigned to it.

**Blocked by:** 06 (enrolment)

**Status:** ready-for-human

Time box: **three hardware sessions or one calendar week, whichever comes first.** Reaching it without a
decoded format is a legitimate outcome: record what the replies look like and stop. Tickets 17, 18 and
21 then close with that finding rather than being silently abandoned.

- [ ] `cvctl inventory` sends the query and dumps its reply, decoded as far as the format allows
- [ ] Whether the command reports anything about stored templates at all is established, not assumed
- [ ] Taking the inventory around an enrolment identifies the id the sensor assigned to the new template,
      if the reply supports it
- [ ] The decoded reply format is written into the project's own protocol notes
- [ ] If the format is not decoded within the box, the observed replies and the failed hypotheses are
      recorded and the outcome is stated as undecoded
