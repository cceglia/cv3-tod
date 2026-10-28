# 20: Identification

**What to build:** the login screen can match a finger without being told which account or finger to
expect, using the match ids every stored print already carries.

**Blocked by:** 14 (verify through fprintd), 10 (id binding)

**Status:** ready-for-agent

- [ ] Identification returns the print that actually matched, not merely that some print matched
- [ ] It succeeds for an enrolled finger and fails for an unenrolled one
- [ ] With two users enrolled, a finger identifies its own user's print and no other
- [ ] The identify feature is declared only when prints are bound, and is independent of whether the
      sensor's inventory was decoded
- [ ] A candidate list containing only unbound or foreign prints produces no match rather than a false
      one
