# 19: Acceptance

**What to build:** the driver is usable for real — `sudo` and the lock screen accept a finger,
cancelling behaves, binding holds, and removing the driver is one file — for the first release, which
does not include listing, deletion or identification.

**Blocked by:** 14 (verify through fprintd), 15 (cancel through fprintd)

**Status:** ready-for-human

- [x] `sudo` authenticates with a fingerprint through `pam_fprintd`, with the password still available
      as fallback
- [x] The lock screen unlocks with a fingerprint
- [x] A verification cancelled mid-capture is followed by a successful one (measured in ticket 15:
      Ctrl+C returns at once and the next verify matches).
- [x] A finger enrolled by a second account does not authenticate the first account
- [x] The probe demonstrates the binding end to end on hardware, so the guarantee is shown working
      outside `fprintd` as well as inside it (ticket 10/14: `verify --handle` accepted finger A and
      rejected finger B with exit 9; `fprintd-verify` accepted A and refused B).
- [x] Uninstalling is documented and verified to be a single file removal, leaving `fprintd` working as
      it did before
- [x] The README states plainly what a match proves and what it does not, including that the channel
      authenticates neither side, that the MAC is not authentication, and that binding does not defeat
      replay (the "What a match proves" section).
- [x] The first-release acceptance criteria from the spec are recorded as met, with the hardware and
      software versions they were met on (see the Comments).

## Comments

First-release acceptance, measured 2026-10-29/30 on:

- Dell Latitude with the Broadcom ControlVault 3, `0a5c:5843`, bus 3 port 8;
- kernel `7.2.6-070206-generic`;
- libfprint TOD `1.95.1+tod1`;
- fprintd `1.94.5-4`.

`sudo` and the KDE lock screen both accepted the enrolled right index. The system PAM configuration
was changed to use `pam_fprintd` (the old `pam_pin.so` prompt was commented out of
`/etc/pam.d/sudo` and replaced in `/etc/pam.d/kscreenlocker`); `common-auth` stays after the
`sufficient` line, so the password remains available. Ctrl+C at the fingerprint prompt falls back to
the password; Esc does not cancel `pam_fprintd` 1.94.5.

Uninstalling removed the one shared object, fprintd stayed active and reported no device; the same
one file restored the reader. The PAM lines are separate system configuration and are not part of
the driver's install.
