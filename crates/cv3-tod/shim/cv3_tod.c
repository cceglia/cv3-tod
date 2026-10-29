/*
 * libfprint TOD plugin for the Dell/Broadcom ControlVault 3 fingerprint sensor (0a5c:5843).
 *
 * GObject plumbing only: the FpDevice subclass, its class info and a probe vfunc. There is no
 * protocol code, no length arithmetic, no cryptography and no session state here, and no state
 * beyond what the interface requires. Later tickets add vfuncs that forward to cv3-core and a
 * transfer binding that performs what the core asks; the core keeps the state.
 *
 * This is the enumeration milestone: probe completes without touching USB.
 */
#include "drivers_api.h"

typedef struct _FpiDeviceCv3
{
  FpDevice parent;
} FpiDeviceCv3;

typedef struct _FpiDeviceCv3Class
{
  FpDeviceClass parent_class;
} FpiDeviceCv3Class;

/* Called by the exported entry point in Rust (src/ffi.rs). */
GType cv3_tod_shim_get_type (void);

G_DEFINE_TYPE (FpiDeviceCv3, cv3_tod_shim, FP_TYPE_DEVICE)

static const FpIdEntry cv3_tod_id_table[] = {
  { .vid = 0x0a5c, .pid = 0x5843 },
  { .vid = 0, .pid = 0 },
};

static void
cv3_tod_probe (FpDevice *device)
{
  /* Enumeration only: the session, when it exists, is opened by the open vfunc, not here.
   *
   * libfprint asserts in fp_device_constructed that a device class advertises some feature, and
   * this milestone implements no operation at all. The class therefore starts from the capability
   * the sensor physically has and withdraws it here, before the probe completes: fprintd is told
   * about a reader that supports nothing yet, instead of being offered a capture that cannot run.
   */
  fpi_device_update_features (device, FP_DEVICE_FEATURE_CAPTURE, FP_DEVICE_FEATURE_NONE);
  fpi_device_probe_complete (device, NULL, "Dell/Broadcom ControlVault 3", NULL);
}

static void
cv3_tod_shim_class_init (FpiDeviceCv3Class *klass)
{
  FpDeviceClass *device_class = FP_DEVICE_CLASS (klass);

  device_class->id = "cv3";
  device_class->full_name = "Dell/Broadcom ControlVault 3 fingerprint";
  device_class->type = FP_DEVICE_TYPE_USB;
  device_class->id_table = cv3_tod_id_table;
  device_class->scan_type = FP_SCAN_TYPE_PRESS;
  /* Placeholder, withdrawn by probe: libfprint refuses to construct a class with no feature. */
  device_class->features = FP_DEVICE_FEATURE_CAPTURE;
  device_class->probe = cv3_tod_probe;
}

static void
cv3_tod_shim_init (FpiDeviceCv3 *self)
{
  (void) self;
}
