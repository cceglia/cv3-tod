# Device-stored prints, with host-side binding as fallback

The sensor matches fingerprints against templates it stores itself, so the driver treats that store
as the source of truth: it maps templates to `fprintd` prints with a store diff on the inventory
query (`0x2F`), learning each template's id by comparing the inventory before and after an
enrolment. If `0x2F` cannot be decoded, the driver degrades to host-stored prints with a match id
recorded at enrolment, which still binds a print to the finger that enrolled it.

## Considered Options

- **Host-stored prints only**, as the existing C driver does: rejected — deletion never reaches the
  sensor, and any enrolled finger satisfies any user on the machine.
- **Identifying prints by the match id alone**, without a store mapping: rejected — that id is not
  comparable with the enrolment id, so verify cannot tell which stored print matched.

## Consequences

- `list` reflects the sensor and `delete` is honest; if no delete command exists, delete is
  declared unsupported rather than emulated by overwriting.
- Both paths must remain selectable at runtime, so the fallback cannot rot: it is the only
  behaviour available until `0x2F` is decoded, and it is what keeps the plugin shippable if it is
  never decoded.
- The print payload carries a version so the two models can coexist in one `fprintd` database.
