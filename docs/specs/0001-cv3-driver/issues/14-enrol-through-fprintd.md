# 14: Enrol through fprintd

**What to build:** a finger can be enrolled from the desktop settings or `fprintd-enroll`, and the
print persists across a `fprintd` restart.

**Blocked by:** 13 (verify through fprintd), 06 (enrolment)

**Status:** ready-for-agent

- [ ] `fprintd-enroll` completes all thirteen declared stages — twelve samples and the binding
      confirmation — and reports progress to the client
- [ ] The enrolled print survives a `fprintd` restart and verifies afterwards
- [ ] The persisted print carries the enrolment id (or the sample hash used in its place) and the
      match id; an unknown payload version is rejected rather than guessed
- [ ] A failed or skipped confirmation fails the enrolment and stores no print, and the driver reports
      that a template may remain on the sensor
- [ ] A cancelled enrolment leaves no stored print, and says the same about the sensor
