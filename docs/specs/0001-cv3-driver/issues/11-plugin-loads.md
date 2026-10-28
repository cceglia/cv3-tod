# 11: Plugin loads

**What to build:** the sensor appears to `fprintd` as a reader, driven by the same core the probe uses,
through the C shim — enumeration only, no session yet.

**Blocked by:** 03 (secure session)

**Status:** ready-for-agent

- [ ] The shim builds against the distribution's `libfprint` TOD headers and links the versioned
      symbols; the build fails loudly rather than binding the legacy compatibility thunk
- [ ] `fprintd` reports the reader
- [ ] The shim contains no parsing, no length arithmetic and no cryptography; it forwards to the core
      and performs transfers
- [ ] The plugin is installed and removed by adding or deleting a single shared object, with no change
      to `libfprint` or `fprintd` configuration
- [ ] A failed probe leaves `fprintd` running and the device available to the next attempt
