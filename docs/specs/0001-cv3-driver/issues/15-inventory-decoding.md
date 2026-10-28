# 15: Inventory decoding

**What to build:** the sensor's template inventory is decoded and enrolling a finger reveals which id
the sensor assigned to it — the fact that unlocks listing, deletion and identification.

**Blocked by:** 06 (enrolment)

**Status:** ready-for-agent

This is a time-boxed investigation, not an open-ended one. The box is **two focused sessions**. Reaching
the box without a decoded format is a legitimate outcome: stop, write down what the replies look like,
and let the device-stored tickets close as unsupported.

- [ ] `cvctl inventory` dumps the sensor's template list, decoded rather than as raw bytes
- [ ] Taking the inventory around an enrolment identifies the id the sensor assigned to the new
      template
- [ ] The decoded reply format is written down next to the command, so the next reader does not have
      to repeat the work
- [ ] If the format is not decoded within the box, the observed replies and the failed hypotheses are
      recorded and the outcome is stated as undecoded
