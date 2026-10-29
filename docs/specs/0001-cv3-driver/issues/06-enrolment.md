# 06: Enrolment

**What to build:** `cvctl enroll` takes a finger through a complete enrolment — discard any pending
attempt, start, collect samples until the sensor is satisfied, and commit the template.

**Blocked by:** 05 (capture)

**Status:** ready-for-human

- [x] `cvctl enroll` completes an enrolment and reports progress after each accepted sample
      (measured 2026-10-29: `sample N accepted` lines).
- [x] A sample the sensor rejects for quality is re-requested, and the attempt continues (measured:
      `sample rejected; place the finger again` between accepted samples).
- [x] Collection stops when the sensor reports it has enough samples, recognised by the enrolment id
      arriving distinct from the sample hash, or by the sensor's "no more samples" reply — and the
      sensor may complete before twelve samples (measured at twelve samples with a sensor enrolment
      id; completing before twelve remains unmeasured).
- [ ] If the sensor never signals completion, the driver commits at twelve accepted samples and records
      that it used the last sample hash as the template id
- [ ] Without a completion signal, committing with fewer than twelve accepted samples fails with a clear
      message and stores no template
- [ ] A failed commit is reported as such, and a following enrolment starts from a discarded state
- [x] A finger that never arrives fails cleanly, and the driver reports that a pending enrolment may
      remain on the sensor until the next discard (measured: exit 8 and the message naming the
      pending enrolment).

## Comments

Implemented in aab811b; review fixes in 810eacb, 45669c3, 04b9e66, 458d7e2. Scripted tests cover
the full `0x6D` → `0x8A` → `0x66`/`0x6C` → `0x6E` flow, rescan, early completion, the twelve-sample
fallback, commit failure and the next run's discard. Progress is a query on the operation;
`cvctl enroll` prints one line per accepted sample.

Hardware: `sudo ./target/debug/cvctl enroll`, including a run with a rejected sample and one where
the sensor never signals completion. The printed template id source (enrolment id or last sample
hash) must be recorded from the real run.

The boxes for "the sensor never signals completion", "committing with fewer than twelve" and "a
failed commit" stay unticked: they need a sensor that does not complete or an injected commit
failure. The forced `--commit-sample-hash` path is covered by scripted tests; no extra template was
written to the sensor for them.
