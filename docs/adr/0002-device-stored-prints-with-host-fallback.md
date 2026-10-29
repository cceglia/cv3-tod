# Device-stored prints, with host-side binding as fallback

The sensor matches fingerprints against templates it stores itself, so the driver treats that store
as the source of truth: it maps templates to `fprintd` prints with a store diff on the inventory
query (`0x2F`), learning each template's id by comparing the inventory before and after an
enrolment. Where that query cannot be decoded, the driver keeps prints host-side instead and declares
no storage features, so `fprintd` never offers an operation the sensor cannot honour.

## Considered Options

- **Host-stored prints only**, as the existing C driver does: rejected — deletion never reaches the
  sensor, and any enrolled finger satisfies any user on the machine.
- **Identifying prints by the match id**, using it as the key for `list` and `identify`: rejected —
  the inventory and a match report ids from different spaces, so a store diff is the only reliable
  way to learn which template belongs to which print.

## Consequences

- `list` reflects the sensor and `delete` is honest; if no delete command exists, delete is declared
  unsupported rather than emulated by overwriting.
- The match id still matters, but for a different job: binding a verification to the print that was
  enrolled, not for identifying prints. It is obtained from a confirmation touch after the commit,
  because enrolment itself never receives one.
- The fallback is not a configuration switch. The intended design decides the model at open time by
  whether the inventory query was decoded on this sensor, and exposes it in the features the driver
  reports.
- **As shipped, the query is undecoded** (ticket 16: status `0x0E`, and the stock driver's `list`
  vfunc is a no-op). There is therefore no open-time branch and no store-diff code: the host-stored
  fallback is unconditional, and the driver declares no storage feature. The branch described above
  remains the design for a sensor whose inventory is decoded later; both paths are not implemented
  today, because the second one cannot be written without the format.
