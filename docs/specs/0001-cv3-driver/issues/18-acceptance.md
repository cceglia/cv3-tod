# 18: Acceptance

**What to build:** the driver is usable for real — `sudo` and the lock screen accept a finger,
cancelling behaves, and removing the driver is one file — for the first release, which does not
include listing or deletion.

**Blocked by:** 13 (enrol through fprintd), 14 (cancel through fprintd)

**Status:** ready-for-agent

- [ ] `sudo` authenticates with a fingerprint through `pam_fprintd`, with the password still available
      as fallback
- [ ] The lock screen unlocks with a fingerprint
- [ ] A verification cancelled mid-capture is followed by a successful one
- [ ] Uninstalling is documented and verified to be a single file removal, leaving `fprintd` working
      as it did before
- [ ] The README states plainly what a match proves and what it does not, including that the channel
      authenticates neither side and that the MAC is not authentication
- [ ] The first-release acceptance criteria from the spec are recorded as met, with the hardware and
      software versions they were met on
