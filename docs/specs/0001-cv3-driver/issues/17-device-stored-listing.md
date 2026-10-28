# 17: Device-stored listing

**What to build:** `fprintd-list` shows the templates that actually exist on the sensor, matched to the
prints fprintd holds.

**Blocked by:** 16 (inventory decoding), 13 (enrol through fprintd)

**Status:** ready-for-agent

- [ ] `fprintd-list` shows the templates that exist on the sensor, matched to the stored prints
- [ ] A print enrolled before the sensor's inventory was readable still appears once its template is
      mapped
- [ ] The driver declares the storage and list features only when the query was decoded
- [ ] A store diff taken around an enrolment maps the new template to the new print
