# 17: Device-stored listing and identification

**What to build:** `fprintd-list` shows the templates that actually exist on the sensor, and the login
screen can match without being told which finger to expect.

**Blocked by:** 16 (inventory decoding), 10 (id binding), 14 (enrol through fprintd)

**Status:** ready-for-agent

- [ ] `fprintd-list` shows the templates that exist on the sensor, matched to the stored prints
- [ ] Identification returns the print that actually matched, not merely that some print matched
- [ ] Identification succeeds for an enrolled finger and fails for an unenrolled one
- [ ] The driver declares list and storage features only when the inventory was decoded, and identify
      only when prints are bound
- [ ] If ticket 16 closed as undecoded, this ticket records that outcome and its listing criteria are
      explicitly abandoned rather than left unmet
