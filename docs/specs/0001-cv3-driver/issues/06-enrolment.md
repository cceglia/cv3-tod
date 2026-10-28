# 06: Enrolment

**What to build:** `cvctl enroll` takes a finger through a complete enrolment — discard any pending
attempt, start, collect samples until the sensor is satisfied, and commit the template.

**Blocked by:** 05 (capture)

**Status:** ready-for-agent

- [ ] `cvctl enroll` completes an enrolment and reports progress after each accepted sample
- [ ] A sample the sensor rejects for quality is re-requested, and the attempt continues
- [ ] Collection stops when the sensor reports it has enough samples, recognised by the enrolment id
      arriving distinct from the sample hash, or by the sensor's "no more samples" reply — and the
      sensor may complete before twelve samples
- [ ] If the sensor never signals completion, the driver commits at twelve accepted samples and records
      that it used the last sample hash as the template id
- [ ] Without a completion signal, committing with fewer than twelve accepted samples fails with a clear
      message and stores no template
- [ ] A failed commit is reported as such, and a following enrolment starts from a discarded state
- [ ] A finger that never arrives fails cleanly, and the driver reports that a pending enrolment may
      remain on the sensor until the next discard
