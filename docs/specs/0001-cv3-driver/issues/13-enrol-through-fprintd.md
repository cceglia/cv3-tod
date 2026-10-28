# 13: Enrol through fprintd

**What to build:** a finger can be enrolled from the desktop settings or `fprintd-enroll`, and the print
persists across a `fprintd` restart.

**Blocked by:** 12 (session through fprintd), 06 (enrolment)

**Status:** ready-for-agent

- [ ] `fprintd-enroll` completes an enrolment end to end, reporting up to thirteen declared stages: the
      samples the sensor accepts plus the binding confirmation, fewer when the sensor completes early
- [ ] The enrolled print survives a `fprintd` restart
- [ ] The persisted print carries the enrolment id (or the sample hash used in its place) and the match
      id; an unknown payload version is rejected rather than guessed
- [ ] A failed or skipped confirmation fails the enrolment and stores no print, and the driver reports
      that a template may remain on the sensor
- [ ] A cancelled enrolment leaves no stored print, and says the same about the sensor
