# 13: Inventory decoding

**What to build:** the sensor's template inventory is decoded, and enrolling a finger reveals which
id the sensor assigned to it — the fact that unlocks listing, deletion and true revocation.

**Blocked by:** 05 (enrolment)

**Status:** ready-for-agent

- [ ] `cvctl inventory` dumps the sensor's template list, decoded rather than as raw bytes
- [ ] Taking the inventory around an enrolment identifies the id the sensor assigned to the new
      template
- [ ] The decoded reply format is written down next to the command, so the next reader does not have
      to repeat the work
- [ ] When the format cannot be decoded within a reasonable effort, the outcome is recorded and the
      driver reports storage operations as unsupported rather than guessing
