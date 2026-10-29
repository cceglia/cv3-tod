/*
 * libfprint TOD plugin for the Dell/Broadcom ControlVault 3 fingerprint sensor (0a5c:5843).
 *
 * GObject plumbing and USB transfers only: the FpDevice subclass, its class info, the vfuncs
 * libfprint requires, and the asynchronous transfers the Rust core asks for. There is no protocol
 * code here — no parsing, no length arithmetic, no cryptography and no session state. One opaque
 * Cv3Tod (src/plugin.rs, src/ffi.rs) owns all of that; this file receives an action, performs it
 * with libfprint's USB API, and hands the outcome back.
 *
 * The Rust half returns a Cv3Action for every step: OUT / INTERRUPT_IN / BULK_IN / CONTROL /
 * WAIT_FINGER, or FINISH with a status, an error kind and a message. The finger event is the one
 * transfer submitted with libfprint's cancellable; command transfers never are. Buffers always
 * belong to Rust; this file only passes them to fpi_usb_transfer_fill_*_full with a NULL free
 * function. Enrolment progress and the bound print record are taken through two small accessors,
 * and verification hands Rust the print's stored bytes as a pointer and a length, so no protocol
 * length or stage arithmetic lives here.
 */
#include "drivers_api.h"

#include "cv3_tod_identity.h"

/* The sensor's one interface, claimed for the life of an open. */
#define CV3_INTERFACE 0

/* ---- The Rust boundary, defined in src/ffi.rs. -------------------------------------------- */

typedef struct _Cv3Tod Cv3Tod;

typedef enum
{
  CV3_ACTION_OUT = 0,
  CV3_ACTION_INTERRUPT_IN = 1,
  CV3_ACTION_BULK_IN = 2,
  CV3_ACTION_CONTROL = 3,
  CV3_ACTION_FINISH = 4,
  /* The finger event: an interrupt read, and the only transfer submitted cancellable. */
  CV3_ACTION_WAIT_FINGER = 5,
} Cv3ActionKind;

typedef enum
{
  CV3_IO_COMPLETED = 0,
  CV3_IO_DATA = 1,
  CV3_IO_FAILED = 2,
} Cv3IoResult;

typedef enum
{
  CV3_IO_ERROR_TIMEOUT = 0,
  CV3_IO_ERROR_DISCONNECTED = 1,
  CV3_IO_ERROR_CANCELLED = 2,
  CV3_IO_ERROR_BUSY = 3,
  CV3_IO_ERROR_STALL = 4,
  CV3_IO_ERROR_OTHER = 5,
} Cv3IoError;

/* Matches cv3_tod::plugin::OutcomeKind. */
typedef enum
{
  CV3_FINISH_OK = 0,
  CV3_FINISH_GENERAL = 1,
  CV3_FINISH_PROTO = 2,
  CV3_FINISH_BUSY = 3,
  CV3_FINISH_REMOVED = 4,
  /* The sensor answered a verdict, but not a match for the print asked about. */
  CV3_FINISH_NO_MATCH = 5,
  /* No finger arrived: libfprint carries this as a retry, not a device error. */
  CV3_FINISH_RETRY = 6,
  /* The operation's cancellable was cancelled; libfprint's task already knows. */
  CV3_FINISH_CANCELLED = 7,
  CV3_FINISH_DATA_INVALID = 8,
  CV3_FINISH_DATA_NOT_FOUND = 9,
} Cv3FinishKind;

/* Must match cv3_tod::ffi::Cv3Action, which static-asserts the same size and offsets. */
typedef struct
{
  guint32  kind;
  guint8   endpoint;
  guint8   request_type;
  guint8   request;
  /* One when this transfer must be submitted with the action's cancellable. */
  guint8   cancellable;
  guint16  value;
  guint16  index;
  guint32  timeout_ms;
  guint8  *buffer;
  gsize    length;
  gint32   status;
  gint32   error_code;
  char     message[256];
} Cv3Action;

_Static_assert (sizeof (Cv3Action) == 296,
                "Cv3Action must match cv3-tod's #[repr(C)] layout");
_Static_assert (G_STRUCT_OFFSET (Cv3Action, cancellable) == 7,
                "Cv3Action.cancellable must stay at offset 7");
_Static_assert (G_STRUCT_OFFSET (Cv3Action, message) == 40,
                "Cv3Action.message must stay at offset 40");

Cv3Tod *cv3_tod_create (void);
void cv3_tod_destroy (Cv3Tod *tod);
Cv3Action cv3_tod_open_start (Cv3Tod *tod);
Cv3Action cv3_tod_on_transfer (Cv3Tod *tod,
                               guint32 result,
                               guint32 error,
                               gsize   actual_length);
Cv3Action cv3_tod_close_start (Cv3Tod *tod);
gint32 cv3_tod_enrol_stages (void);
Cv3Action cv3_tod_enrol_start (Cv3Tod *tod);
gint32 cv3_tod_take_progress (Cv3Tod *tod, gint32 *completed);
gsize cv3_tod_take_payload (Cv3Tod *tod, guint8 *destination, gsize capacity);
Cv3Action cv3_tod_verify_start (Cv3Tod *tod, const guint8 *payload, gsize length);

/* ---- The device --------------------------------------------------------------------------- */

typedef struct _FpiDeviceCv3
{
  FpDevice parent;

  /* The Rust session state for one open; NULL while closed and after a failed open. */
  Cv3Tod  *tod;
  gboolean interface_claimed;
  gboolean opening;
  gboolean closing;
  gboolean enrolling;
  gboolean verifying;
  /* The template print libfprint handed to the enroll vfunc; borrowed for the action only. */
  FpPrint *enroll_print;
} FpiDeviceCv3;

typedef struct _FpiDeviceCv3Class
{
  FpDeviceClass parent_class;
} FpiDeviceCv3Class;

/* Called by the exported entry point in Rust (src/ffi.rs). */
GType cv3_tod_shim_get_type (void);

#define CV3_TYPE_TOD_DEVICE (cv3_tod_shim_get_type ())
#define CV3_TOD_DEVICE(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CV3_TYPE_TOD_DEVICE, FpiDeviceCv3))

G_DEFINE_TYPE (FpiDeviceCv3, cv3_tod_shim, FP_TYPE_DEVICE)

static const FpIdEntry cv3_tod_id_table[] = {
  { .vid = 0x0a5c, .pid = 0x5843 },
  { .vid = 0, .pid = 0 },
};

static void
cv3_tod_probe (FpDevice *device)
{
  /* Nothing to discover that the class does not already declare, and this probe does not touch
   * USB. Enrolment needs no feature bit in this ABI: libfprint 1.95 has no
   * FP_DEVICE_FEATURE_ENROLL, so `fprintd` gates EnrollStart on the non-zero
   * fp_device_get_nr_enroll_stages() the class sets from the core. Verification is the class's
   * one feature bit. The probe therefore withdraws nothing. */
  fpi_device_probe_complete (device, NULL, CV3_TOD_DEVICE_NAME, NULL);
}

/* Maps the core's finish kind onto libfprint's device errors. */
static FpDeviceError
cv3_tod_error_for (gint32 kind)
{
  switch (kind)
    {
    case CV3_FINISH_PROTO:
      return FP_DEVICE_ERROR_PROTO;
    case CV3_FINISH_BUSY:
      return FP_DEVICE_ERROR_BUSY;
    case CV3_FINISH_REMOVED:
      return FP_DEVICE_ERROR_REMOVED;
    case CV3_FINISH_DATA_INVALID:
      return FP_DEVICE_ERROR_DATA_INVALID;
    case CV3_FINISH_DATA_NOT_FOUND:
      return FP_DEVICE_ERROR_DATA_NOT_FOUND;
    /* A verification's no-match, retry and cancel are reported through the match callback and
     * never reach here; naming them keeps the switch exhaustive without inventing an error. */
    case CV3_FINISH_NO_MATCH:
    case CV3_FINISH_RETRY:
    case CV3_FINISH_CANCELLED:
    case CV3_FINISH_GENERAL:
    default:
      return FP_DEVICE_ERROR_GENERAL;
    }
}

/* Classifies a transfer error into the small enum Rust understands. */
static Cv3IoError
cv3_tod_io_error_for (const GError *error)
{
  if (error == NULL)
    return CV3_IO_ERROR_OTHER;

  if (error->domain == G_USB_DEVICE_ERROR)
    {
      switch (error->code)
        {
        case G_USB_DEVICE_ERROR_TIMED_OUT:
          return CV3_IO_ERROR_TIMEOUT;
        case G_USB_DEVICE_ERROR_NO_DEVICE:
        case G_USB_DEVICE_ERROR_NOT_OPEN:
          return CV3_IO_ERROR_DISCONNECTED;
        case G_USB_DEVICE_ERROR_CANCELLED:
          return CV3_IO_ERROR_CANCELLED;
        case G_USB_DEVICE_ERROR_BUSY:
          return CV3_IO_ERROR_BUSY;
        default:
          return CV3_IO_ERROR_OTHER;
        }
    }

  if (error->domain == G_IO_ERROR)
    {
      switch (error->code)
        {
        case G_IO_ERROR_TIMED_OUT:
          return CV3_IO_ERROR_TIMEOUT;
        case G_IO_ERROR_CANCELLED:
          return CV3_IO_ERROR_CANCELLED;
        default:
          return CV3_IO_ERROR_OTHER;
        }
    }

  return CV3_IO_ERROR_OTHER;
}

static FpDeviceError
cv3_tod_claim_error_for (const GError *error)
{
  if (error != NULL && error->domain == G_USB_DEVICE_ERROR)
    {
      switch (error->code)
        {
        case G_USB_DEVICE_ERROR_BUSY:
          return FP_DEVICE_ERROR_BUSY;
        case G_USB_DEVICE_ERROR_NO_DEVICE:
          return FP_DEVICE_ERROR_REMOVED;
        default:
          break;
        }
    }
  return FP_DEVICE_ERROR_GENERAL;
}

static void
cv3_tod_release_interface (FpDevice *device)
{
  FpiDeviceCv3 *self = CV3_TOD_DEVICE (device);
  GUsbDevice *usb = fpi_device_get_usb_device (device);
  GError *error = NULL;

  if (!self->interface_claimed || usb == NULL)
    return;

  /* Best effort: a release failure cannot be repaired here, and the close must still complete. */
  if (!g_usb_device_release_interface (usb, CV3_INTERFACE, 0, &error))
    {
      g_warning ("cv3: releasing interface %d failed: %s", CV3_INTERFACE,
                 error != NULL ? error->message : "unknown error");
      g_clear_error (&error);
    }
  self->interface_claimed = FALSE;
}

/* Ends a failed open: no capture can be pending, so nothing is cancelled. The interface and the
 * GUsb handle are released and the Rust state destroyed, so the next Claim starts clean and the
 * sensor has no handle left. */
static void
cv3_tod_open_failed (FpDevice *device, gint32 kind, const gchar *message)
{
  FpiDeviceCv3 *self = CV3_TOD_DEVICE (device);
  GUsbDevice *usb = fpi_device_get_usb_device (device);
  GError *error = fpi_device_error_new_msg (cv3_tod_error_for (kind), "%s", message);

  self->opening = FALSE;
  cv3_tod_release_interface (device);

  /* fpi_device_open_complete does not close the handle libfprint opened before the vfunc, and
   * fprintd does not close a device whose open failed; leaving it open makes every later Claim
   * fail with "Device is already open". */
  if (usb != NULL)
    g_usb_device_close (usb, NULL);

  if (self->tod != NULL)
    {
      cv3_tod_destroy (self->tod);
      self->tod = NULL;
    }

  fpi_device_open_complete (device, error);
}

/* Ends a close, always successfully. The interface is released and the session state destroyed;
 * the GUsb handle is closed by fpi_device_close_complete, which libfprint owns. */
static void
cv3_tod_close_finished (FpDevice *device)
{
  FpiDeviceCv3 *self = CV3_TOD_DEVICE (device);

  self->closing = FALSE;
  cv3_tod_release_interface (device);

  if (self->tod != NULL)
    {
      cv3_tod_destroy (self->tod);
      self->tod = NULL;
    }

  fpi_device_close_complete (device, NULL);
}

/* Ends a verification: reports the match result and completes.
 *
 * A match, a no-match and a cancelled run are reported with no error, which is what `fprintd` turns
 * into `verify-match` and `verify-no-match`; a cancelled run's task still returns the cancellation
 * to its caller. A retry is reported as FPI_MATCH_ERROR carrying libfprint's retry error, which is
 * the only shape libfprint accepts with an error: an error next to a match result is itself a
 * driver bug it warns about. libfprint takes ownership of that error. Every other finish completes
 * with the mapped device error.
 */
static void
cv3_tod_verify_finished (FpDevice *device, const Cv3Action *action)
{
  GError *error = NULL;

  switch (action->error_code)
    {
    case CV3_FINISH_OK:
      fpi_device_verify_report (device, FPI_MATCH_SUCCESS, NULL, NULL);
      break;
    case CV3_FINISH_NO_MATCH:
      fpi_device_verify_report (device, FPI_MATCH_FAIL, NULL, NULL);
      break;
    case CV3_FINISH_RETRY:
      /* FPI_MATCH_ERROR with a retry-domain error is libfprint's retry shape: the client is told to
       * scan again instead of seeing a device error. */
      fpi_device_verify_report (device, FPI_MATCH_ERROR, NULL,
                                fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL, "%s",
                                                          action->message));
      break;
    case CV3_FINISH_CANCELLED:
      /* A cancelled run found no match: the report keeps the match decision explicit, and
       * libfprint's cancelled task still returns the cancellation to its caller. */
      fpi_device_verify_report (device, FPI_MATCH_FAIL, NULL, NULL);
      break;
    default:
      error = fpi_device_error_new_msg (cv3_tod_error_for (action->error_code), "%s",
                                        action->message);
      break;
    }

  fpi_device_verify_complete (device, error);
}

static void
cv3_tod_dispatch (FpDevice *device, Cv3Action action);

/* Reports every stage or rejected sample the core has queued since the last call.
 *
 * libfprint's progress callback is synchronous, so this runs before the next transfer is submitted:
 * the client hears about stage N before the driver waits for the next touch. A rejected sample is
 * reported with FP_DEVICE_RETRY_GENERAL, which fprintd turns into `enroll-retry-scan`: the stage
 * count does not advance, and the next capture is already armed.
 */
static void
cv3_tod_report_progress (FpDevice *device)
{
  FpiDeviceCv3 *self = CV3_TOD_DEVICE (device);
  gint32 completed = 0;
  gint32 kind;

  if (self->tod == NULL)
    return;

  while ((kind = cv3_tod_take_progress (self->tod, &completed)) != 0)
    {
      GError *retry = NULL;

      if (kind == 2)
        retry = fpi_device_retry_new_msg (
          FP_DEVICE_RETRY_GENERAL,
          "cv3: the sensor could not use that sample; place the finger again");
      /* libfprint takes ownership of the error and clears it itself, and it rejects a print
       * supplied together with an error (the retry must carry none). Clearing the error here as
       * well is a double free: the daemon aborts with `free(): invalid pointer`. */
      fpi_device_enroll_progress (device, completed, retry != NULL ? NULL : self->enroll_print,
                                  retry);
    }
}

/* Stores the bound print record in the FpPrint libfprint will persist.
 *
 * `fpi-data` is a GVariant of type `ay`, 30 bytes of the core's fixed CV3P record, and `fpi-type`
 * is FPI_PRINT_RAW so libfprint stores and returns the bytes verbatim. The bytes come from Rust;
 * this file only copies them into the variant. The finger, username and description libfprint put
 * on the template are left untouched.
 */
static void
cv3_tod_set_print_payload (FpPrint *print, const guint8 *bytes, gsize len)
{
  g_object_set (print, "fpi-type", FPI_PRINT_RAW, NULL);
  g_object_set (print, "fpi-data",
                g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, bytes, len, sizeof (guint8)),
                NULL);
}

static void
cv3_tod_transfer_cb (FpiUsbTransfer *transfer,
                     FpDevice       *device,
                     gpointer        user_data,
                     GError         *error)
{
  FpiDeviceCv3 *self = CV3_TOD_DEVICE (device);
  Cv3Action action;
  guint32 result;
  guint32 code = CV3_IO_ERROR_OTHER;
  gsize actual_length = 0;
  gint action_kind = GPOINTER_TO_INT (user_data);

  if (error != NULL)
    {
      result = CV3_IO_FAILED;
      code = cv3_tod_io_error_for (error);
    }
  else if (action_kind == CV3_ACTION_INTERRUPT_IN
           || action_kind == CV3_ACTION_BULK_IN
           || action_kind == CV3_ACTION_WAIT_FINGER)
    {
      result = CV3_IO_DATA;
      actual_length = transfer->actual_length > 0 ? (gsize) transfer->actual_length : 0;
    }
  else
    {
      result = CV3_IO_COMPLETED;
    }

  if (self->tod == NULL)
    {
      /* The state is gone (a close overtook the transfer); there is nothing to feed. */
      return;
    }

  /* The reference `fpi_usb_transfer_submit` consumed is dropped by libfprint's own completion
   * wrapper, which runs after this callback returns: the transfer is still alive here and must not
   * be unrefed. */
  action = cv3_tod_on_transfer (self->tod, result, code, actual_length);
  cv3_tod_dispatch (device, action);
}

/* Performs the transfer or finishes the operation.
 *
 * The timeout is not chosen here: the action carries the core's own constant (5 s to write a
 * command, 60 s for a reply announcement or body, 3 s for a teardown frame, 1 s for the host
 * timestamp control request, 30 s for the finger wait). Only the finger wait is submitted with
 * libfprint's cancellable; every command transfer gets NULL and is never cancelled, because
 * aborting one mid-flight is what deep-wedges this sensor.
 *
 * Transfer ownership: `fpi_usb_transfer_new` returns one reference and `fpi_usb_transfer_submit`
 * consumes it, so a submitted transfer is never unrefed here or in the callback. libfprint's
 * completion wrapper drops that reference after the callback returns. See the note at the submit.
 */
static void
cv3_tod_dispatch (FpDevice *device, Cv3Action action)
{
  FpiDeviceCv3 *self = CV3_TOD_DEVICE (device);
  FpiUsbTransfer *transfer;
  GCancellable *cancellable = NULL;

  /* Progress goes out before the next transfer: the client hears about a completed stage or a
   * rejected sample while the driver has not yet started the next read. */
  if (self->enrolling)
    cv3_tod_report_progress (device);

  if (action.kind == CV3_ACTION_FINISH)
    {
      if (self->opening)
        {
          if (action.status == 0)
            {
              self->opening = FALSE;
              fpi_device_open_complete (device, NULL);
            }
          else
            {
              cv3_tod_open_failed (device, action.error_code, action.message);
            }
        }
      else if (self->enrolling)
        {
          FpPrint *print = self->enroll_print;

          self->enrolling = FALSE;
          self->enroll_print = NULL;
          if (action.status == 0)
            {
              guint8 payload[64];
              gsize len;

              if (self->tod == NULL
                  || print == NULL
                  || (len = cv3_tod_take_payload (self->tod, payload,
                                                  sizeof payload)) == 0)
                {
                  fpi_device_enroll_complete (
                    device, NULL,
                    fpi_device_error_new_msg (
                      FP_DEVICE_ERROR_GENERAL,
                      "cv3: the enrolment finished without a bound print"));
                  return;
                }
              cv3_tod_set_print_payload (print, payload, len);
              /* `fpi_device_get_enroll_data` hands back a borrowed print (transfer none), while
               * `fpi_device_enroll_complete` takes ownership (transfer full). Passing the borrowed
               * pointer makes the completion consume the task's reference, and the task frees it
               * again when the operation ends: a double unref, SEGV in fprintd. libfprint's own
               * drivers pass `g_object_ref (print)` here for the same reason. */
              fpi_device_enroll_complete (device, g_object_ref (print), NULL);
            }
          else
            {
              fpi_device_enroll_complete (
                device, NULL,
                fpi_device_error_new_msg (cv3_tod_error_for (action.error_code), "%s",
                                          action.message));
            }
        }
      else if (self->verifying)
        {
          self->verifying = FALSE;
          cv3_tod_verify_finished (device, &action);
        }
      else if (self->closing)
        {
          /* A close is best effort: a failed 0x04 is logged, then the interface and handle are
           * released regardless and the close still completes successfully. */
          if (action.message[0] != '\0')
            g_warning ("%s", action.message);
          cv3_tod_close_finished (device);
        }
      else
        {
          g_warning ("cv3: a finished action arrived with no operation in progress");
        }
      return;
    }

  if (action.kind != CV3_ACTION_CONTROL && action.buffer == NULL)
    {
      g_warning ("cv3: a transfer action without a buffer");
      if (self->opening)
        cv3_tod_open_failed (device, CV3_FINISH_GENERAL,
                             "cv3: a transfer action carried no buffer");
      else if (self->enrolling)
        {
          self->enrolling = FALSE;
          self->enroll_print = NULL;
          fpi_device_enroll_complete (
            device, NULL,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                      "cv3: a transfer action carried no buffer"));
        }
      else if (self->verifying)
        {
          self->verifying = FALSE;
          fpi_device_verify_complete (
            device,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                      "cv3: a transfer action carried no buffer"));
        }
      else if (self->closing)
        cv3_tod_close_finished (device);
      return;
    }

  transfer = fpi_usb_transfer_new (device);

  switch (action.kind)
    {
    case CV3_ACTION_OUT:
      fpi_usb_transfer_fill_bulk_full (transfer, action.endpoint, action.buffer,
                                       action.length, NULL);
      break;
    case CV3_ACTION_BULK_IN:
      fpi_usb_transfer_fill_bulk_full (transfer, action.endpoint, action.buffer,
                                       action.length, NULL);
      break;
    case CV3_ACTION_INTERRUPT_IN:
      fpi_usb_transfer_fill_interrupt_full (transfer, action.endpoint, action.buffer,
                                            action.length, NULL);
      break;
    case CV3_ACTION_WAIT_FINGER:
      fpi_usb_transfer_fill_interrupt_full (transfer, action.endpoint, action.buffer,
                                            action.length, NULL);
      break;
    case CV3_ACTION_CONTROL:
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     action.request,
                                     action.value,
                                     action.index,
                                     0);
      break;
    default:
      /* A kind this shim does not know cannot be performed; fail the operation rather than
       * aborting the root daemon. This transfer is never submitted, so it is ours to free. */
      g_warning ("cv3: unknown action kind %u", action.kind);
      fpi_usb_transfer_unref (transfer);
      if (self->opening)
        cv3_tod_open_failed (device, CV3_FINISH_GENERAL,
                             "cv3: the core returned an unknown action");
      else if (self->verifying)
        {
          self->verifying = FALSE;
          fpi_device_verify_complete (
            device,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                      "cv3: the core returned an unknown action"));
        }
      else if (self->closing)
        cv3_tod_close_finished (device);
      return;
    }

  /* Only the action that carries `cancellable` gets libfprint's cancellable. That is the finger
   * wait and nothing else: aborting a command transfer mid-flight deep-wedges this sensor. */
  if (action.cancellable)
    cancellable = fpi_device_get_cancellable (device);

  fpi_usb_transfer_submit (transfer, action.timeout_ms, cancellable, cv3_tod_transfer_cb,
                           GINT_TO_POINTER (action.kind));

  /* OWNERSHIP: `fpi_usb_transfer_submit` CONSUMES the reference `fpi_usb_transfer_new` returned;
   * it does not take a reference of its own. The asynchronous operation owns the transfer from
   * here, and libfprint's completion wrapper unrefs it after it has called cv3_tod_transfer_cb.
   * Unrefing here too (which this shim used to do) frees the transfer while the URB is in flight:
   * the completion then reads a freed `transfer->device` and fprintd segfaults in the callback.
   * The unknown-kind branch above is the only unref in this function because it never submits. */
}

static void
cv3_tod_open (FpDevice *device)
{
  FpiDeviceCv3 *self = CV3_TOD_DEVICE (device);
  GUsbDevice *usb = fpi_device_get_usb_device (device);
  GError *error = NULL;

  if (usb == NULL)
    {
      fpi_device_open_complete (device,
                                fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                          "cv3: the device has no USB handle"));
      return;
    }

  /* libgusb has no asynchronous claim; this is a configuration ioctl, not a protocol transfer,
   * and it is what upstream libfprint drivers do here too. */
  if (!g_usb_device_claim_interface (usb, CV3_INTERFACE, 0, &error))
    {
      FpDeviceError code = cv3_tod_claim_error_for (error);
      GError *completion =
        fpi_device_error_new_msg (code, "cv3: cannot claim the sensor's interface: %s",
                                  error != NULL ? error->message : "unknown error");
      g_clear_error (&error);
      g_usb_device_close (usb, NULL);
      fpi_device_open_complete (device, completion);
      return;
    }

  self->interface_claimed = TRUE;
  self->opening = TRUE;
  self->closing = FALSE;
  self->enrolling = FALSE;
  self->verifying = FALSE;
  self->enroll_print = NULL;
  if (self->tod != NULL)
    cv3_tod_destroy (self->tod);
  self->tod = cv3_tod_create ();
  cv3_tod_dispatch (device, cv3_tod_open_start (self->tod));
}

static void
cv3_tod_close (FpDevice *device)
{
  FpiDeviceCv3 *self = CV3_TOD_DEVICE (device);

  self->opening = FALSE;
  self->closing = TRUE;
  self->enrolling = FALSE;
  self->verifying = FALSE;
  self->enroll_print = NULL;

  if (self->tod == NULL)
    {
      cv3_tod_close_finished (device);
      return;
    }

  cv3_tod_dispatch (device, cv3_tod_close_start (self->tod));
}

/* One whole enrolment on the session the open left behind.
 *
 * The template print comes from libfprint and keeps the finger, username and description fprintd
 * supplied. The Rust core drives the samples, the commit and the confirmation touch and hands back
 * the 30-byte bound record; on any failure it returns a message that names the template that may
 * remain on the sensor. Enrolment never opens or closes the session: a success leaves it usable for
 * the next operation.
 */
static void
cv3_tod_enroll (FpDevice *device)
{
  FpiDeviceCv3 *self = CV3_TOD_DEVICE (device);
  FpPrint *print = NULL;

  if (self->tod == NULL || self->opening || self->closing || self->enrolling)
    {
      fpi_device_enroll_complete (
        device, NULL,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_OPEN,
                                  "cv3: the sensor session is not open"));
      return;
    }

  fpi_device_get_enroll_data (device, &print);
  if (print == NULL)
    {
      fpi_device_enroll_complete (
        device, NULL,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                  "cv3: libfprint supplied no template print"));
      return;
    }

  self->enroll_print = print;
  self->enrolling = TRUE;
  cv3_tod_dispatch (device, cv3_tod_enrol_start (self->tod));
}

/* One verification of the print fprintd asks about.
 *
 * The print's `fpi-data` is the bound record enrolment stored: this function finds the bytes and
 * hands them, with their length, to Rust, which decodes the record and decides which match id the
 * sensor is asked about. No field of the record is read here. A print without that byte array is
 * FP_DEVICE_ERROR_DATA_NOT_FOUND and a variant of another type FP_DEVICE_ERROR_DATA_INVALID, both
 * before any transfer: neither is a failed match.
 *
 * Verification never opens or closes the session; the core drives the capture arm, the finger wait
 * and the `0x2F` match on the session the open left behind.
 */
static void
cv3_tod_verify (FpDevice *device)
{
  FpiDeviceCv3 *self = CV3_TOD_DEVICE (device);
  FpPrint *print = NULL;
  GVariant *data = NULL;
  const guint8 *payload;
  gsize length = 0;

  if (self->tod == NULL || self->opening || self->closing || self->enrolling
      || self->verifying)
    {
      fpi_device_verify_complete (
        device, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_OPEN,
                                          "cv3: the sensor session is not open"));
      return;
    }

  fpi_device_get_verify_data (device, &print);
  if (print == NULL)
    {
      fpi_device_verify_complete (
        device,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_NOT_FOUND,
                                  "cv3: libfprint supplied no print to verify"));
      return;
    }

  g_object_get (print, "fpi-data", &data, NULL);
  if (data == NULL)
    {
      fpi_device_verify_complete (
        device, fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_NOT_FOUND,
                                          "cv3: the print carries no stored record"));
      return;
    }
  if (!g_variant_is_of_type (data, G_VARIANT_TYPE ("ay")))
    {
      g_variant_unref (data);
      fpi_device_verify_complete (
        device, fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                          "cv3: the print's fpi-data is not a byte array"));
      return;
    }

  payload = g_variant_get_fixed_array (data, &length, 1);

  self->verifying = TRUE;
  /* Rust decodes the bytes synchronously inside this call and keeps no pointer, so the variant is
   * released as soon as the first action comes back. */
  cv3_tod_dispatch (device, cv3_tod_verify_start (self->tod, payload, length));
  g_variant_unref (data);
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
  /* Exactly the features this driver implements. libfprint 1.95 requires a class to advertise
   * something and has no ENROLL flag, so enrolment rides on nr_enroll_stages below and VERIFY is
   * the one bit here. This driver cannot capture an image, identify against several prints, or
   * list, delete and clear the sensor's store, so those bits stay clear and the matching vfuncs
   * stay NULL. */
  device_class->features = FP_DEVICE_FEATURE_VERIFY;
  /* Up to twelve accepted samples plus the confirmation touch; the sensor may complete early. The
   * number comes from the core, so the class and the progress reports cannot disagree. */
  device_class->nr_enroll_stages = cv3_tod_enrol_stages ();
  device_class->probe = cv3_tod_probe;
  /* These four are dereferenced without a NULL check; the rest are feature-guarded by libfprint
   * and stay NULL until a later ticket can honour them.
   */
  device_class->open = cv3_tod_open;
  device_class->close = cv3_tod_close;
  device_class->enroll = cv3_tod_enroll;
  device_class->verify = cv3_tod_verify;
}

static void
cv3_tod_shim_init (FpiDeviceCv3 *self)
{
  self->tod = NULL;
  self->interface_claimed = FALSE;
  self->opening = FALSE;
  self->closing = FALSE;
  self->enrolling = FALSE;
  self->verifying = FALSE;
  self->enroll_print = NULL;
}
