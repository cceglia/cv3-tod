/*
 * libfprint TOD plugin for the Dell/Broadcom ControlVault 3 fingerprint sensor (0a5c:5843).
 *
 * GObject plumbing only: the FpDevice subclass, its class info and the vfuncs libfprint requires.
 * There is no protocol code, no length arithmetic, no cryptography, no session state and no state
 * beyond what the interface requires. Later tickets make these vfuncs forward to cv3-core and add a
 * transfer binding that performs what the core asks; the core keeps the state.
 *
 * This is the enumeration milestone: probe completes without touching USB, and every vfunc that
 * libfprint calls through the class pointer without a NULL check fails cleanly, so a Claim reports
 * an error and fprintd stays up instead of dereferencing NULL as root.
 */
#include "drivers_api.h"

#include "cv3_tod_identity.h"

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
cv3_tod_open (FpDevice *device)
{
  /* libfprint calls this pointer without a NULL check from fp_device_open, which is the path
   * fprintd's Claim takes. Without a body here that dereference is NULL and fprintd dies as root;
   * failing the open cleanly reports the error to the client and leaves fprintd and the reader
   * listed. The session, and with it a successful open, arrives with ticket 12.
   */
  fpi_device_open_complete (device,
                            fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                      "cv3: opening the sensor needs the session (ticket 12)"));
}

static void
cv3_tod_close (FpDevice *device)
{
  /* Also called without a NULL check. Close must always succeed: this milestone holds nothing. */
  fpi_device_close_complete (device, NULL);
}

static void
cv3_tod_enroll (FpDevice *device)
{
  /* libfprint calls this pointer without a NULL check once a template print is supplied. The
   * withdrawn features mean fprintd never asks, so this is defence in depth against a caller
   * driving libfprint directly.
   */
  fpi_device_enroll_complete (device, NULL,
                              fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                        "cv3: enrolment is not implemented yet"));
}

static void
cv3_tod_shim_class_init (FpiDeviceCv3Class *klass)
{
  FpDeviceClass *device_class = FP_DEVICE_CLASS (klass);

  device_class->id = CV3_TOD_CLASS_ID;
  device_class->full_name = CV3_TOD_FULL_NAME;
  device_class->type = FP_DEVICE_TYPE_USB;
  device_class->id_table = cv3_tod_id_table;
  device_class->scan_type = FP_SCAN_TYPE_PRESS;
  /* Placeholder, withdrawn by probe: libfprint refuses to construct a class with no feature. */
  device_class->features = FP_DEVICE_FEATURE_CAPTURE;
  device_class->probe = cv3_tod_probe;
  /* These three are dereferenced without a NULL check; the rest are feature-guarded by libfprint
   * and stay NULL until a later ticket can honour them.
   */
  device_class->open = cv3_tod_open;
  device_class->close = cv3_tod_close;
  device_class->enroll = cv3_tod_enroll;
}

static void
cv3_tod_shim_init (FpiDeviceCv3 *self)
{
  (void) self;
}
