/*
 * Stand-in for libgusb's handle state and for libfprint's transfer submission, linked into the
 * TOD class/open harness (tests/tod_class_open.c).
 *
 * The harness must exercise a real handshake and a real wrapped open without a sensor, root or
 * USB. It therefore scripts the sensor at the one seam the shim uses: fpi_usb_transfer_submit.
 * The shim still allocates and fills every transfer; this fake only completes it, with the body
 * the script names for the command that was just written, on a GLib idle callback so the plugin's
 * asynchronous structure is preserved.
 *
 * g_usb_device_open/close model libgusb's own state exactly: opening an open handle fails with
 * ALREADY_OPEN, closing a closed one fails with NOT_OPEN, and close must receive the handle that
 * was opened. The claim/release pair is recorded, so the harness can prove the interface is
 * released on both the failed-open and the close paths.
 *
 * Transfer ownership is libfprint's: `fpi_usb_transfer_new` returns one reference, submit consumes
 * it, and the completion drops it after the callback. This fake keeps exactly that model — no
 * extra reference at submit — so a caller that unrefs a submitted transfer aborts the harness on a
 * use-after-free / double free instead of leaking quietly.
 */

#include <drivers_api.h>
#include <gusb.h>

static gboolean opened;
static GUsbDevice *opened_device;
static guint opens;
static guint closes;

static gboolean claimed;
static guint claims;
static guint releases;

#define FAKE_MAX_STEPS 16
#define FAKE_MAX_BODY 256

typedef struct
{
  guint32 status;
  gsize   len;
  /* When set, the interrupt read fails with NO_DEVICE instead of announcing a reply. */
  gboolean fails;
  guint8  body[FAKE_MAX_BODY];
} FakeStep;

static FakeStep steps[FAKE_MAX_STEPS];
static guint step_count;
static guint step_index;
/* The step the last command write selected; the interrupt and body reads that follow use it. */
static guint current_step;

static guint16 out_commands[FAKE_MAX_STEPS];
static guint out_count;

static void
put_le32 (guint8 *p, guint32 value)
{
  p[0] = value & 0xff;
  p[1] = (value >> 8) & 0xff;
  p[2] = (value >> 16) & 0xff;
  p[3] = (value >> 24) & 0xff;
}

/* The core's fixture: RFC 5903 section 8.1's responder public key, a valid P-256 point. It only
 * has to be a point the host can multiply; the sensor's identity is not checked by the handshake. */
static const guint8 device_public[64] = {
  0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8,
  0x12, 0x08, 0xb7, 0x02, 0x70, 0x39, 0x8c, 0x34,
  0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc, 0xb7, 0x4c,
  0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf, 0x63,
  0x56, 0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e,
  0x81, 0x57, 0x85, 0x4c, 0x13, 0xc5, 0x8d, 0x6a,
  0xac, 0x23, 0xf0, 0x46, 0xad, 0xa3, 0x0f, 0x83,
  0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72, 0xab,
};

static const guint8 device_nonce[20] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
};

/* Builds a plain reply frame into `out` and returns its length. */
static gsize
build_reply (guint8 *out, guint16 cmd, guint8 attr, guint8 encoding,
             guint32 handle, guint32 status, const guint8 *param, gsize param_len)
{
  gsize total = 44 + param_len;

  g_assert (total <= FAKE_MAX_BODY);
  memset (out, 0, total);
  put_le32 (out + 0, 1);
  put_le32 (out + 4, (guint32) total);
  out[8] = cmd & 0xff;
  out[9] = (cmd >> 8) & 0xff;
  out[10] = attr;
  out[11] = encoding;
  put_le32 (out + 12, 2);
  put_le32 (out + 16, handle);
  put_le32 (out + 20, status);
  put_le32 (out + 40, (guint32) param_len);
  if (param_len != 0)
    memcpy (out + 44, param, param_len);
  return total;
}

static void
add_step (guint32 status, gsize len, const guint8 *body)
{
  g_assert (step_count < FAKE_MAX_STEPS);
  g_assert (len <= FAKE_MAX_BODY);
  steps[step_count].status = status;
  steps[step_count].len = len;
  steps[step_count].fails = FALSE;
  if (len != 0)
    memcpy (steps[step_count].body, body, len);
  step_count++;
}

static void
add_challenge_reply (void)
{
  guint8 param[148];
  guint8 body[FAKE_MAX_BODY];

  memset (param, 0, sizeof param);
  memcpy (param, device_public, sizeof device_public);
  memcpy (param + 128, device_nonce, sizeof device_nonce);
  add_step (2, build_reply (body, 0x23, 0x41, 0x00, 0x11223344, 0,
                            param, sizeof param),
            body);
}

static void
add_response_reply (guint32 status)
{
  guint8 body[FAKE_MAX_BODY];

  add_step (2, build_reply (body, 0x24, 0x01, 0x00, 0x11223344, status, NULL, 0),
            body);
}

static void
add_open_reply (void)
{
  guint8 body[FAKE_MAX_BODY];

  add_step (2, build_reply (body, 0x02, 0x45, 0x03, 0x11223344, 0, NULL, 0), body);
}

static void
add_empty_reply (void)
{
  add_step (2, 0, NULL);
}

static void
add_vanished_device (void)
{
  add_step (2, 0, NULL);
  steps[step_count - 1].fails = TRUE;
}

/* Resets every bit of fake state and selects the script the harness runs. */
void
fake_gusb_reset (void)
{
  opened = FALSE;
  opened_device = NULL;
  opens = 0;
  closes = 0;
  claimed = FALSE;
  claims = 0;
  releases = 0;
  step_count = 0;
  step_index = 0;
  current_step = 0;
  out_count = 0;
  memset (steps, 0, sizeof steps);
  memset (out_commands, 0, sizeof out_commands);
}

/*
 * The whole session the harness drives:
 *   1. open:   0x23, 0x24 (status 0x09: refused), 0x04 (the handle release)
 *   2. open:   0x23, 0x24, 0x02 (success)
 *   3. close:  0x04
 */
/* The sensor leaves the bus instead of announcing the 0x23 reply. */
void
fake_gusb_plan_vanishing (void)
{
  fake_gusb_reset ();
  add_vanished_device ();
}

/* A successful open whose 0x04 close gets no announcement: the sensor answers nothing. */
void
fake_gusb_plan_close_failure (void)
{
  fake_gusb_reset ();
  add_challenge_reply ();
  add_response_reply (0x00);
  add_open_reply ();
  add_vanished_device ();
}

void
fake_gusb_plan_session (void)
{
  fake_gusb_reset ();
  add_challenge_reply ();
  add_response_reply (0x09);
  add_empty_reply ();
  add_challenge_reply ();
  add_response_reply (0x00);
  add_open_reply ();
  add_empty_reply ();
}

/* A successful open followed by a sensor that leaves the bus when the enrolment's first command
 * is answered: the vfunc reaches the core, which fails the enrolment and runs its teardown. */
void
fake_gusb_plan_enrol (void)
{
  fake_gusb_reset ();
  add_challenge_reply ();
  add_response_reply (0x00);
  add_open_reply ();
  add_vanished_device ();
}

/* A successful open followed by a sensor that answers nothing more: the verification's arm reaches
 * the core, whose capture fails and whose best-effort teardown follows. A *successful* verify needs
 * wrapped replies the fake cannot fabricate (it holds no session key), so the accepted match and the
 * no-match are covered by the Rust tests and by the hardware run. */
void
fake_gusb_plan_verify (void)
{
  fake_gusb_reset ();
  add_challenge_reply ();
  add_response_reply (0x00);
  add_open_reply ();
}

guint
fake_gusb_out_count (void)
{
  return out_count;
}

guint16
fake_gusb_out_command (guint index)
{
  g_assert (index < out_count);
  return out_commands[index];
}

gboolean
fake_gusb_is_open (void)
{
  return opened;
}

gboolean
fake_gusb_interface_claimed (void)
{
  return claimed;
}

guint
fake_gusb_opens (void)
{
  return opens;
}

guint
fake_gusb_closes (void)
{
  return closes;
}

guint
fake_gusb_claims (void)
{
  return claims;
}

guint
fake_gusb_releases (void)
{
  return releases;
}

gboolean
g_usb_device_open (GUsbDevice *device, GError **error)
{
  if (opened)
    {
      g_set_error_literal (error, G_USB_DEVICE_ERROR,
                           G_USB_DEVICE_ERROR_ALREADY_OPEN,
                           "Device 0a5c:5843 is already open");
      g_printerr ("fake gusb: open refused, the handle is still open\n");
      return FALSE;
    }

  opened = TRUE;
  opened_device = device;
  opens++;
  return TRUE;
}

gboolean
g_usb_device_close (GUsbDevice *device, GError **error)
{
  if (!opened)
    {
      g_set_error_literal (error, G_USB_DEVICE_ERROR,
                           G_USB_DEVICE_ERROR_NOT_OPEN,
                           "Device is not open");
      return FALSE;
    }

  if (device != opened_device)
    {
      g_set_error_literal (error, G_USB_DEVICE_ERROR,
                           G_USB_DEVICE_ERROR_NOT_OPEN,
                           "The wrong device handle is being closed");
      g_printerr ("fake gusb: close refused, wrong handle\n");
      return FALSE;
    }

  opened = FALSE;
  opened_device = NULL;
  closes++;
  return TRUE;
}

gboolean
g_usb_device_claim_interface (GUsbDevice *device,
                              gint        iface,
                              GUsbDeviceClaimInterfaceFlags flags,
                              GError    **error)
{
  (void) device;
  (void) flags;
  (void) error;

  if (iface != 0)
    return FALSE;
  if (claimed)
    {
      g_set_error_literal (error, G_USB_DEVICE_ERROR,
                           G_USB_DEVICE_ERROR_BUSY,
                           "Interface 0 is already claimed");
      return FALSE;
    }

  claimed = TRUE;
  claims++;
  return TRUE;
}

gboolean
g_usb_device_release_interface (GUsbDevice *device,
                                gint        iface,
                                GUsbDeviceClaimInterfaceFlags flags,
                                GError    **error)
{
  (void) device;
  (void) flags;
  (void) error;

  if (iface != 0 || !claimed)
    return FALSE;

  claimed = FALSE;
  releases++;
  return TRUE;
}

typedef struct
{
  FpiUsbTransfer *transfer;
  gpointer        user_data;
} PendingTransfer;

static gboolean
complete_transfer (gpointer data)
{
  PendingTransfer *pending = data;
  FpiUsbTransfer *transfer = pending->transfer;
  GError *error = NULL;
  gsize actual = 0;

  /* libfprint's completion runs while holding the one reference submit consumed. A refcount of 0
   * here means the caller unrefed a transfer it had already submitted: this memory is freed and
   * every read below is a use-after-free. Failing here names the bug instead of letting the
   * allocator's free list feed the callback a garbage `transfer->device`. */
  g_assert (transfer->ref_count == 1);

  if (transfer->type == FP_TRANSFER_BULK && !(transfer->endpoint & FPI_USB_ENDPOINT_IN))
    {
      /* A command write. Record it and attach it to the next scripted reply. */
      if (transfer->length < 10)
        {
          g_set_error_literal (&error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO,
                               "fake gusb: command shorter than a header");
        }
      else
        {
          if (out_count < FAKE_MAX_STEPS)
            out_commands[out_count] =
              (guint16) (transfer->buffer[8] | (transfer->buffer[9] << 8));
          out_count++;
          if (step_index >= step_count)
            g_set_error_literal (&error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO,
                                 "fake gusb: no scripted reply for this command");
          else
            current_step = step_index++;
          actual = transfer->length;
        }
    }
  else if (transfer->type == FP_TRANSFER_INTERRUPT)
    {
      const FakeStep *step = &steps[current_step];

      if (step->fails)
        {
          g_set_error_literal (&error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_NO_DEVICE,
                               "fake gusb: the sensor left the bus");
        }
      else
        {
          guint8 announcement[8];

          put_le32 (announcement + 0, step->status);
          put_le32 (announcement + 4, (guint32) step->len);
          memcpy (transfer->buffer, announcement, sizeof announcement);
          actual = sizeof announcement;
        }
    }
  else if (transfer->type == FP_TRANSFER_BULK && (transfer->endpoint & FPI_USB_ENDPOINT_IN))
    {
      const FakeStep *step = &steps[current_step];
      gsize len = MIN (step->len, (gsize) transfer->length);

      memcpy (transfer->buffer, step->body, len);
      actual = len;
    }
  else if (transfer->type == FP_TRANSFER_CONTROL)
    {
      actual = 0;
    }
  else
    {
      g_set_error_literal (&error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO,
                           "fake gusb: unsupported transfer type");
    }

  transfer->actual_length = (gssize) actual;
  transfer->callback (transfer, transfer->device, pending->user_data, error);
  g_clear_error (&error);

  /* Ownership, as in libfprint 1.95.1: submit consumed the reference `fpi_usb_transfer_new` gave
   * the caller, and the completion drops it after the callback has returned. Nothing else unrefs a
   * submitted transfer; the transfer is freed here, not by the caller. */
  fpi_usb_transfer_unref (transfer);
  g_free (pending);
  return G_SOURCE_REMOVE;
}

void
fpi_usb_transfer_submit (FpiUsbTransfer        *transfer,
                         guint                  timeout_ms,
                         GCancellable          *cancellable,
                         FpiUsbTransferCallback callback,
                         gpointer               user_data)
{
  PendingTransfer *pending = g_new0 (PendingTransfer, 1);

  (void) timeout_ms;
  (void) cancellable;

  /* `fpi_usb_transfer_submit` takes no reference of its own: it consumes the single reference
   * `fpi_usb_transfer_new` returned. Checking it here catches a caller that already dropped that
   * reference (which would leave the freeing to whoever decrements next) or took another one
   * (which would leak the transfer once the completion drops only one). */
  g_assert (transfer->ref_count == 1);

  transfer->callback = callback;
  transfer->user_data = user_data;
  /* The submitted transfer's own reference; complete_transfer drops it. Deliberately not refed
   * again: a second reference here would hide a caller that unrefs after submitting. */
  pending->transfer = transfer;
  pending->user_data = user_data;
  g_idle_add (complete_transfer, pending);
}
