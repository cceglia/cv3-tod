# 07: Id binding

**What to build:** a verification succeeds only for the finger that was enrolled for that print, not
merely for any finger the sensor happens to hold — closing the hole where one user's finger
satisfies another user's prompt, and where a tampered reply can forge a match.

**Blocked by:** 05 (enrolment)

**Status:** ready-for-agent

- [ ] Enrolment records the sensor's match id for the enrolled finger and reports whether it could
- [ ] Verification requires the returned match id to equal the recorded one
- [ ] A different finger that is enrolled on the same sensor does not satisfy verification for this
      print
- [ ] A reply whose match id does not match the recorded one fails with a distinct reason, even when
      the sensor reported a match
- [ ] A print with no recorded match id verifies in a degraded mode that is announced, never silent
- [ ] The stability of the match id across separate sessions is measured and recorded; if it is
      unstable, the degraded mode becomes the documented default
