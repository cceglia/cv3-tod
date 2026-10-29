# 17: Device-stored listing

**What to build:** `fprintd-list` shows the templates that actually exist on the sensor, matched to the
prints fprintd holds.

**Blocked by:** 16 (inventory decoding), 13 (enrol through fprintd)

**Status:** done

- [ ] `fprintd-list` shows the templates that exist on the sensor, matched to the stored prints
      (not possible: the inventory is undecoded, ticket 16).
- [ ] A print enrolled before the sensor's inventory was readable still appears once its template is
      mapped
- [x] The driver declares the storage and list features only when the query was decoded: it never
      declares them, because the query was not decoded. `fprintd-list` shows the host-stored prints,
      which is the fallback the SPEC names.
- [ ] A store diff taken around an enrolment maps the new template to the new print

## Outcome: host-stored fallback

Ticket 16 ended undecoded (status `0x0E`, vendor list vfunc a no-op). The driver therefore keeps the
host-stored model: it declares no `STORAGE`, `STORAGE_LIST`, `STORAGE_DELETE` or `STORAGE_CLEAR`
feature and implements none of those vfuncs. `fprintd-list` reports the prints fprintd stores on the
host, matched to the fingerprints they were enrolled as; it does not claim to read the sensor's
store. The two remaining boxes (mapping a store diff, showing a pre-inventory print) depend on the
undecoded query and cannot be met.
