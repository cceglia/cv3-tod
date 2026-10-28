# 13: Enrol through fprintd

**What to build:** a finger can be enrolled from the desktop settings or `fprintd-enroll`, and the
print persists across a `fprintd` restart.

**Blocked by:** 12 (verify through fprintd), 06 (enrolment)

**Status:** ready-for-agent

- [ ] `fprintd-enroll` completes all thirteen stages — twelve samples and the binding confirmation —
      and reports progress to the client
- [ ] The enrolled print survives a `fprintd` restart and verifies afterwards
- [ ] The persisted print carries the enrolment id and, when binding succeeded, the match id; an
      unknown payload version is rejected rather than guessed
- [ ] A cancelled enrolment leaves no half-built print behind
- [ ] A skipped or failed confirmation touch leaves a print that enrols successfully and verifies in
      the declared degraded mode
