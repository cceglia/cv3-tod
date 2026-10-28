# 05: Enrolment

**What to build:** `cvctl enroll` takes a finger through a complete enrolment — discard any pending
attempt, start, collect samples until the sensor is satisfied, and commit the template.

**Blocked by:** 04 (verification)

**Status:** ready-for-agent

- [ ] `cvctl enroll` completes an enrolment and reports progress after each accepted sample
- [ ] A sample the sensor rejects for quality is re-requested, and the attempt continues
- [ ] When the sensor signals it has enough samples, collection stops instead of over-collecting
- [ ] Committing with fewer accepted samples than required fails with a clear message and does not
      store a template
- [ ] A failed commit is reported as such, and a following enrolment starts from a discarded state
