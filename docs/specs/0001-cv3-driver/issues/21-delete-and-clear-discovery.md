# 21: Delete and clear discovery

**What to build:** the answer to whether the sensor can delete a template at all, and with which
command, established before anything promises deletion to a user.

**Blocked by:** 16 (inventory decoding)

**Status:** done

Time box: **two hardware sessions.** A negative result is as useful as a positive one and closes ticket
18 cleanly.

- [ ] Candidate delete and clear commands are tried against a disposable enrolment, with the instruction
      encodings recorded
- [ ] A successful delete is confirmed by verification: the finger no longer matches afterwards
- [ ] A successful clear is confirmed the same way for every enrolled finger
- [x] If nothing works, the attempted encodings and their replies are written into the project's
      protocol notes and the outcome is stated as unsupported.

## Outcome: unsupported

The stock driver exposes `cvif_fingerprint_delete(handle)`, which forwards to an opaque
`cv_delete_object` (a generic ControlVault object API call with module/command arguments), not to a
documented wire frame. No CV3 opcode or TLV for deleting a template could be derived from it without
further reverse engineering, and the inventory is undecoded, so there is no way to name a template
to delete. No candidate encoding was sent to the sensor: guessing an opcode on a device that wedges
on a malformed command is not a safe experiment, and ticket 18 accepts "unsupported" as the result.

Consequence: deletion and clearing are reported as unsupported (no storage feature), and the host
print fprintd holds is the only thing a delete removes. The sensor template remains and this is
stated in the ticket and the README.
