# 04: Offline harness

**What to build:** a session seen once on hardware becomes a test that runs anywhere: recording,
replay, and a scripted sensor that can produce any reply sequence.

**Blocked by:** 03 (secure session)

**Status:** ready-for-agent

- [ ] `cvctl` records a session to a file and replays it, reproducing the same outcome with no
      hardware attached
- [ ] A scripted-sensor transport can drive the engine through an arbitrary reply sequence, finger
      event, cancellation and transport failure, and is used by the engine tests
- [ ] Replay and the scripted transport go through the same transport contract as the real one, so
      the recorded path and the real path share one code path
- [ ] The frame parser has a fuzz target that finds no panics across random and structured buffers
- [ ] Fixtures committed to the repository are synthetic and contain no real sensor material; raw
      captures stay out of version control
