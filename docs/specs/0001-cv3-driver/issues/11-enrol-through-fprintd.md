# 11: Enrol through fprintd

**What to build:** a finger can be enrolled from GNOME Settings or `fprintd-enroll`, and the print
persists across a `fprintd` restart.

**Blocked by:** 10 (verify through fprintd), 05 (enrolment)

**Status:** ready-for-agent

- [ ] `fprintd-enroll` completes all twelve stages and reports progress to the client
- [ ] The enrolled print survives a `fprintd` restart and verifies afterwards
- [ ] The persisted print carries a versioned record of the ids the driver needs, and an unknown
      version is rejected rather than guessed
- [ ] A cancelled enrolment leaves no half-built print behind
