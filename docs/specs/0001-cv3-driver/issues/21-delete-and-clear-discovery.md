# 21: Delete and clear discovery

**What to build:** the answer to whether the sensor can delete a template at all, and with which
command, established before anything promises deletion to a user.

**Blocked by:** 16 (inventory decoding)

**Status:** ready-for-human

Time box: **two hardware sessions.** A negative result is as useful as a positive one and closes ticket
18 cleanly.

- [ ] Candidate delete and clear commands are tried against a disposable enrolment, with the instruction
      encodings recorded
- [ ] A successful delete is confirmed by verification: the finger no longer matches afterwards
- [ ] A successful clear is confirmed the same way for every enrolled finger
- [ ] If nothing works, the attempted encodings and their replies are written into the project's
      protocol notes and the outcome is stated as unsupported
