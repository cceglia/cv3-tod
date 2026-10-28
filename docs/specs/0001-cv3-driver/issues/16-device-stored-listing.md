# 16: Device-stored listing and identification

**What to build:** `fprintd-list` shows the templates that actually exist on the sensor, and the
login screen can match without being told which finger to expect.

**Blocked by:** 15 (inventory decoding), 13 (enrol through fprintd)

**Status:** ready-for-agent

- [ ] `fprintd-list` shows the templates that exist on the sensor, and matches them to the stored
      prints
- [ ] Identification succeeds for an enrolled finger and fails for an unenrolled one
- [ ] The driver declares storage and identify features only when the inventory was decoded, and
      declares neither when it was not
- [ ] A store diff taken around an enrolment maps the new template to the new print
- [ ] If ticket 15 closed as undecoded, this ticket records that outcome and its remaining criteria are
      explicitly abandoned rather than left unmet
