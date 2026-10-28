# 08: Recorded sessions

**What to build:** a session captured once on hardware can be replayed offline, so every later
ticket has a test that runs without the sensor.

**Blocked by:** 04 (verification)

**Status:** ready-for-agent

- [ ] `cvctl` can record a session to a file and replay it, reproducing the same outcome with no
      hardware attached
- [ ] Replay drives the engine through the transport contract, so the recorded path and the real path
      share one code path
- [ ] The frame parser has a fuzz target that finds no panics across random and structured buffers
- [ ] Fixtures committed to the repository are synthetic and contain no real sensor material
