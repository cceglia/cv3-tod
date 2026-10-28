# 12: Cancel through fprintd

**What to build:** cancelling a prompt stops the capture immediately and the sensor stays healthy —
the case a screen locker hits every time it times out.

**Blocked by:** 11 (enrol through fprintd)

**Status:** ready-for-agent

- [ ] Cancelling a verification through fprintd returns promptly instead of waiting for the finger
      timeout
- [ ] The sensor is usable immediately afterwards: the next verification succeeds without needing a
      restart or a power cycle
- [ ] Ten consecutive cancel-then-verify cycles leave the sensor healthy
- [ ] A cancel that arrives while a command transfer is in flight does not abort that transfer
