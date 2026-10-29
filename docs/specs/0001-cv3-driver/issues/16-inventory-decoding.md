# 16: Inventory decoding

**What to build:** whether `0x2F` is the sensor's template inventory is settled, and if it is, its reply
is decoded so that enrolling a finger reveals which id the sensor assigned to it.

**Blocked by:** 06 (enrolment)

**Status:** ready-for-human

Time box: **three hardware sessions or one calendar week, whichever comes first.** Reaching it without a
decoded format is a legitimate outcome: record what the replies look like and stop. Tickets 17, 18 and
21 then close with that finding rather than being silently abandoned.

- [x] `cvctl inventory` sends the query and dumps its reply, decoded as far as the format allows
      (`reply length`, plaintext hex, best-effort TLV scan).
- [x] Whether the command reports anything about stored templates at all is established, not assumed:
      with the vendor identify TLV and the session handle the sensor answers status `0x0E` and a
      44-byte body that does not decrypt; the stock driver's `list` vfunc is a no-op
      (`fpi_device_list_complete(device, NULL, NULL)` in the vendor blob).
- [ ] Taking the inventory around an enrolment identifies the id the sensor assigned to the new template,
      if the reply supports it
- [ ] The decoded reply format is written into the project's own protocol notes
- [x] If the format is not decoded within the box, the observed replies and the failed hypotheses are
      recorded and the outcome is stated as undecoded.

## Outcome: undecoded

Measured 2026-10-29, one hardware session:

```text
$ sudo ./target/release/cvctl inventory
cvctl: inventory failed: sensor rejected the 0x2f inventory query with status 0x0e (raw reply 44
bytes); the body did not decrypt
```

The same answer came before and after a complete `cvctl enroll` (template id
`f29a5b25c8204a0910e2268e00f4faa487011acd`). The failed hypothesis: `0x2F`, attr `0x42`, the
identify parameter block `(0,4,handle)(0,4,0x48)(0,4,0x53e2)(0,4,0)(2,0)` wrapped at the session's
sequence. Status `0x0E` means the sensor rejected the parameter set; the 44-byte body is a
header-only reply.

The vendor blob agrees with the negative reading: its `list` vfunc only logs and calls
`fpi_device_list_complete(device, NULL, NULL)`, i.e. it reports no templates at all. No decoded
inventory is therefore available, and tickets 17 and 18 close with the host-stored fallback.
