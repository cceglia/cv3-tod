/*
 * The C-side cancellation property, with the Rust plugin's boundary stubbed out.
 *
 * The class/open harness cannot reach the finger wait: the fake holds no session key, so it cannot
 * fabricate the wrapped `0x66` reply that precedes the wait. This harness therefore keeps the real
 * shim (loaded from the built plugin) and the real libfprint task/cancellation machinery, but
 * replaces the `cv3_tod_*` entry points with a tiny script:
 *
 *   verify_start  -> a bulk OUT command (a stand-in for any command transfer)
 *   on_transfer   -> the finger wait, submitted with libfprint's cancellable
 *   on_transfer   -> a cancelled finish, after the wait's transfer completes
 *
 * The fake cancels the external GCancellable fprintd would cancel when the finger wait is
 * submitted, and completes that one transfer with G_USB_DEVICE_ERROR_CANCELLED. What this proves:
 *
 *  - command transfers are submitted with a NULL GCancellable;
 *  - the finger wait is submitted with libfprint's own per-action GCancellable, not a second
 *    source;
 *  - the action does not finish before the command's transfer result arrives: the wait is only
 *    produced by the `on_transfer` callback;
 *  - a cancelled finger wait completes the action with G_IO_ERROR_CANCELLED and never delivers a
 *    match callback (no no-match and no retry verdict);
 *  - the shim clears its `verifying` flag, so the next operation reaches the vfunc again.
 *
 * The Rust plugin's part — the `0x68`/`0x04` teardown before the finish, no stored print and a
 * fresh open afterwards — is covered by the scripted tests in plugin.rs. What neither can show is
 * the sensor: the hardware run remains the confirmation that the real wait stops immediately and
 * that the next Claim succeeds.
 */

#include <fprint.h>
#include <drivers_api.h>
#include <gmodule.h>

#include "cv3_tod.h"

/* tests/fake_gusb.c, linked into this executable so its symbols interpose for the plugin. */
void fake_gusb_plan_dispatch (GCancellable *task_cancellable);
guint fake_gusb_submit_count (void);
gboolean fake_gusb_submit_cancellable (guint index);
FpiTransferType fake_gusb_submit_type (guint index);

static int failures;

#define check(cond, ...)                                     \
  do                                                         \
    {                                                        \
      if (!(cond))                                           \
        {                                                    \
          g_printerr ("FAIL: ");                             \
          g_printerr (__VA_ARGS__);                          \
          g_printerr ("\n");                                 \
          failures++;                                        \
        }                                                    \
      else                                                   \
        {                                                    \
          g_printerr ("ok: ");                               \
          g_printerr (__VA_ARGS__);                          \
          g_printerr ("\n");                                 \
        }                                                    \
    }                                                        \
  while (0)

/* ---- The stubbed Rust boundary ------------------------------------------------------------- */

static int verify_starts;
static int transfer_results;
static int enrol_starts;
static int enrol_results;
static gboolean in_enrol;
static guint8 command_buffer[16];
static guint8 finger_buffer[64];
/* When set, the wait's completion is a successful result (a match that finished after the client
 * cancelled). The shim must suppress it rather than report a verdict. */
static gboolean finish_after_wait_is_ok;

static void
reset_stub (void)
{
  verify_starts = 0;
  transfer_results = 0;
  enrol_starts = 0;
  enrol_results = 0;
  in_enrol = FALSE;
  finish_after_wait_is_ok = FALSE;
}

static Cv3Action
empty_action (void)
{
  Cv3Action action;

  memset (&action, 0, sizeof action);
  action.kind = CV3_ACTION_FINISH;
  return action;
}

static Cv3Action
finish_action (gint32 code, const char *message)
{
  Cv3Action action = empty_action ();

  action.kind = CV3_ACTION_FINISH;
  action.status = code == CV3_FINISH_OK ? 0 : 1;
  action.error_code = code;
  g_strlcpy (action.message, message, sizeof action.message);
  return action;
}

static Cv3Action command_action (void);
static Cv3Action finger_wait_action (void);

Cv3Tod *
cv3_tod_create (void)
{
  /* The shim only checks for NULL; the stop leaves no handle to release. */
  return (Cv3Tod *) (gpointer) 1;
}

void
cv3_tod_destroy (Cv3Tod *tod)
{
  (void) tod;
}

Cv3Action
cv3_tod_open_start (Cv3Tod *tod)
{
  (void) tod;
  return finish_action (CV3_FINISH_OK, "");
}

Cv3Action
cv3_tod_close_start (Cv3Tod *tod)
{
  (void) tod;
  return finish_action (CV3_FINISH_OK, "");
}

gint32
cv3_tod_enrol_stages (void)
{
  return 13;
}

Cv3Action
cv3_tod_enrol_start (Cv3Tod *tod)
{
  (void) tod;

  in_enrol = TRUE;
  enrol_starts++;
  if (enrol_starts == 1)
    return finger_wait_action ();
  /* The second call proves the shim did not leave `enrolling` set after the cancellation; the
   * missing payload makes this run fail, which is not what this check is about. */
  return finish_action (CV3_FINISH_OK, "");
}

gint32
cv3_tod_take_progress (Cv3Tod *tod, gint32 *completed)
{
  (void) tod;
  (void) completed;
  return 0;
}

gsize
cv3_tod_take_payload (Cv3Tod *tod, guint8 *destination, gsize capacity)
{
  (void) tod;
  (void) destination;
  (void) capacity;
  return 0;
}

static Cv3Action
command_action (void)
{
  Cv3Action action = empty_action ();

  action.kind = CV3_ACTION_OUT;
  action.endpoint = 0x01;
  action.timeout_ms = 5000;
  action.buffer = command_buffer;
  action.length = sizeof command_buffer;
  /* A command transfer is never cancellable. */
  action.cancellable = 0;
  return action;
}

static Cv3Action
finger_wait_action (void)
{
  Cv3Action action = empty_action ();

  action.kind = CV3_ACTION_WAIT_FINGER;
  action.endpoint = 0x85;
  action.timeout_ms = 30000;
  action.buffer = finger_buffer;
  action.length = sizeof finger_buffer;
  action.cancellable = 1;
  return action;
}

Cv3Action
cv3_tod_verify_start (Cv3Tod *tod, const guint8 *payload, gsize length)
{
  (void) tod;
  (void) payload;
  (void) length;

  in_enrol = FALSE;
  verify_starts++;
  if (verify_starts == 1)
    return command_action ();
  /* The second call proves the shim did not leave `verifying` set after the cancellation. */
  return finish_action (CV3_FINISH_OK, "");
}

Cv3Action
cv3_tod_on_transfer (Cv3Tod *tod, guint32 result, guint32 error, gsize actual_length)
{
  (void) tod;
  (void) result;
  (void) error;
  (void) actual_length;

  if (in_enrol)
    {
      enrol_results++;
      return finish_action (CV3_FINISH_CANCELLED, "cv3: the enrolment was cancelled");
    }

  transfer_results++;
  if (transfer_results == 1)
    return finger_wait_action ();
  if (finish_after_wait_is_ok)
    return finish_action (CV3_FINISH_OK, "");
  return finish_action (CV3_FINISH_CANCELLED, "cv3: the verification was cancelled");
}

/* ---- The harness --------------------------------------------------------------------------- */

static void
match_cb (FpDevice *device, FpPrint *match, FpPrint *print, gpointer user_data, GError *error)
{
  int *calls = user_data;

  (void) device;
  (void) match;
  (void) print;
  (void) error;
  (*calls)++;
}

static void
check_cancelled_verify (GType type, FpDeviceClass *klass)
{
  static const guint8 record[30] = {
    'C', 'V', '3', 'P', 1, 1,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0x1f, 0x36, 0xf2, 0x00,
  };
  FpDevice *device = g_object_new (type, NULL);
  GUsbDevice *usb = g_object_new (G_USB_TYPE_DEVICE, NULL);
  GTypeClass *base_class = g_type_class_ref (FP_TYPE_DEVICE);
  gint private_offset = g_type_class_get_instance_private_offset (base_class);
  GCancellable *task_cancellable = g_cancellable_new ();
  GError *error = NULL;
  FpPrint *print;
  FpPrint *matched_print = NULL;
  gboolean matched = TRUE;
  int match_calls = 0;
  gboolean verified;

  check (klass->cancel == NULL,
         "the class has no cancel vfunc; the GCancellable is the only cancel source");

  reset_stub ();
  g_object_ref (usb);
  *(GUsbDevice **) ((char *) device + private_offset + 8) = usb;
  g_type_class_unref (base_class);

  /* Plan before the open: the plan resets the fake's GUsb state, and the stubbed open submits no
   * transfers, so the plan survives until the verification. */
  fake_gusb_plan_dispatch (task_cancellable);

  check (fp_device_open_sync (device, NULL, &error),
         "the open before the cancelled verification succeeds (got error `%s`)",
         error ? error->message : "-");
  g_clear_error (&error);

  print = fp_print_new (device);
  g_object_set (print, "fpi-type", FPI_PRINT_RAW, NULL);
  g_object_set (print, "fpi-data",
                g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, record, sizeof record, 1),
                NULL);

  verified = fp_device_verify_sync (device, print, task_cancellable, match_cb, &match_calls,
                                    &matched, &matched_print, &error);

  check (!verified, "a cancelled verification does not report success");
  check (error != NULL && error->domain == G_IO_ERROR && error->code == G_IO_ERROR_CANCELLED,
         "a cancelled verification returns G_IO_ERROR_CANCELLED (got %s `%s`)",
         error ? g_quark_to_string (error->domain) : "-",
         error ? error->message : "-");
  g_clear_error (&error);
  check (matched_print == NULL, "a cancelled verification yields no print");
  check (match_calls == 0,
         "no match callback is delivered for a cancellation (no no-match or retry verdict)");

  check (verify_starts == 1, "the verify vfunc ran once (got %d)", verify_starts);
  check (transfer_results == 2,
         "the action finished only after both transfer results (got %d)", transfer_results);
  check (fake_gusb_submit_count () == 2,
         "two transfers were submitted: the command, then the wait (got %u)",
         fake_gusb_submit_count ());
  if (fake_gusb_submit_count () == 2)
    {
      check (fake_gusb_submit_type (0) == FP_TRANSFER_BULK
             && !fake_gusb_submit_cancellable (0),
             "the command was a bulk transfer submitted with a NULL cancellable");
      check (fake_gusb_submit_type (1) == FP_TRANSFER_INTERRUPT
             && fake_gusb_submit_cancellable (1),
             "the finger wait was submitted with libfprint's cancellable");
    }

  /* The flag is clear: the next operation reaches the vfunc again instead of being refused as
   * "already verifying". */
  matched = FALSE;
  matched_print = NULL;
  verified = fp_device_verify_sync (device, print, NULL, NULL, NULL, &matched, &matched_print,
                                    &error);
  g_clear_error (&error);
  check (verify_starts == 2,
         "a second verification reaches the vfunc, so `verifying` was cleared (got %d starts)",
         verify_starts);
  (void) verified;

  g_object_unref (print);

  check (fp_device_close_sync (device, NULL, &error),
         "the device closes after the cancelled verification (got error `%s`)",
         error ? error->message : "-");
  g_clear_error (&error);

  g_object_unref (task_cancellable);
  g_object_unref (device);
  g_object_unref (usb);
}

/* A match that completed even though the client cancelled — the cancellation landed while the match
 * command was on the bus, and that command is deliberately not cancellable. The shim must complete
 * with the cancellation, not hand libfprint a match report. */
static void
check_cancelled_match_is_not_reported (GType type)
{
  static const guint8 record[30] = {
    'C', 'V', '3', 'P', 1, 1,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0x1f, 0x36, 0xf2, 0x00,
  };
  FpDevice *device = g_object_new (type, NULL);
  GUsbDevice *usb = g_object_new (G_USB_TYPE_DEVICE, NULL);
  GTypeClass *base_class = g_type_class_ref (FP_TYPE_DEVICE);
  gint private_offset = g_type_class_get_instance_private_offset (base_class);
  GCancellable *task_cancellable = g_cancellable_new ();
  GError *error = NULL;
  FpPrint *print;
  FpPrint *matched_print = NULL;
  gboolean matched = FALSE;
  int match_calls = 0;
  gboolean verified;

  g_object_ref (usb);
  *(GUsbDevice **) ((char *) device + private_offset + 8) = usb;
  g_type_class_unref (base_class);

  reset_stub ();
  finish_after_wait_is_ok = TRUE;
  fake_gusb_plan_dispatch (task_cancellable);

  check (fp_device_open_sync (device, NULL, &error),
         "the open before the cancelled match succeeds (got error `%s`)",
         error ? error->message : "-");
  g_clear_error (&error);

  print = fp_print_new (device);
  g_object_set (print, "fpi-type", FPI_PRINT_RAW, NULL);
  g_object_set (print, "fpi-data",
                g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, record, sizeof record, 1),
                NULL);

  verified = fp_device_verify_sync (device, print, task_cancellable, match_cb, &match_calls,
                                    &matched, &matched_print, &error);
  check (!verified && error != NULL && error->domain == G_IO_ERROR
         && error->code == G_IO_ERROR_CANCELLED,
         "a match completed after cancellation still returns G_IO_ERROR_CANCELLED");
  g_clear_error (&error);
  check (match_calls == 0,
         "that match is not reported through the match callback");
  check (matched_print == NULL, "that match yields no print");
  check (transfer_results == 2,
         "the shim saw the successful finish and suppressed it (got %d results)",
         transfer_results);

  g_object_unref (print);
  check (fp_device_close_sync (device, NULL, &error),
         "the device closes after the suppressed match (got error `%s`)",
         error ? error->message : "-");
  g_clear_error (&error);
  g_object_unref (task_cancellable);
  g_object_unref (device);
  g_object_unref (usb);
}

/* A cancelled enrolment must clear `enrolling`, complete with the cancellation, store no print,
 * and let a later enrolment reach the vfunc again. */
static void
check_cancelled_enrolment (GType type)
{
  FpDevice *device = g_object_new (type, NULL);
  GUsbDevice *usb = g_object_new (G_USB_TYPE_DEVICE, NULL);
  GTypeClass *base_class = g_type_class_ref (FP_TYPE_DEVICE);
  gint private_offset = g_type_class_get_instance_private_offset (base_class);
  GCancellable *task_cancellable = g_cancellable_new ();
  GError *error = NULL;
  FpPrint *template_print;
  FpPrint *enrolled;

  g_object_ref (usb);
  *(GUsbDevice **) ((char *) device + private_offset + 8) = usb;
  g_type_class_unref (base_class);

  reset_stub ();
  fake_gusb_plan_dispatch (task_cancellable);

  check (fp_device_open_sync (device, NULL, &error),
         "the open before the cancelled enrolment succeeds (got error `%s`)",
         error ? error->message : "-");
  g_clear_error (&error);

  template_print = fp_print_new (device);
  fp_print_set_finger (template_print, FP_FINGER_LEFT_INDEX);
  fp_print_set_username (template_print, "harness");

  enrolled = fp_device_enroll_sync (device, template_print, task_cancellable, NULL, NULL, &error);
  check (enrolled == NULL, "a cancelled enrolment stores no print");
  check (error != NULL && error->domain == G_IO_ERROR && error->code == G_IO_ERROR_CANCELLED,
         "a cancelled enrolment returns G_IO_ERROR_CANCELLED (got %s `%s`)",
         error ? g_quark_to_string (error->domain) : "-",
         error ? error->message : "-");
  g_clear_error (&error);
  check (enrol_results == 1,
         "the enrolment's cancelled wait completed (got %d results)", enrol_results);

  /* The next enrolment reaches the vfunc: `enrolling` was cleared. It fails only because this
   * stub hands back no payload. */
  template_print = fp_print_new (device);
  fp_print_set_finger (template_print, FP_FINGER_LEFT_INDEX);
  fp_print_set_username (template_print, "harness");
  enrolled = fp_device_enroll_sync (device, template_print, NULL, NULL, NULL, &error);
  g_clear_error (&error);
  (void) enrolled;
  check (enrol_starts == 2,
         "a second enrolment reaches the vfunc, so `enrolling` was cleared (got %d starts)",
         enrol_starts);

  check (fp_device_close_sync (device, NULL, &error),
         "the device closes after the cancelled enrolment (got error `%s`)",
         error ? error->message : "-");
  g_clear_error (&error);

  g_object_unref (task_cancellable);
  g_object_unref (device);
  g_object_unref (usb);
}

int
main (int argc, char **argv)
{
  const gchar *path = argc > 1 ? argv[1] : "target/release/libcv3_tod.so";
  GModule *module;
  GType (*get_type) (void);
  GType type;
  FpDeviceClass *klass;

  module = g_module_open (path, G_MODULE_BIND_LAZY);
  if (module == NULL)
    {
      g_printerr ("error: cannot load %s: %s\n", path, g_module_error ());
      return 1;
    }

  if (!g_module_symbol (module, "fpi_tod_shared_driver_get_type", (gpointer *) &get_type))
    {
      g_printerr ("error: %s does not export fpi_tod_shared_driver_get_type: %s\n",
                  path, g_module_error ());
      return 1;
    }

  type = get_type ();
  klass = g_type_class_ref (type);
  check_cancelled_verify (type, klass);
  check_cancelled_match_is_not_reported (type);
  check_cancelled_enrolment (type);
  g_type_class_unref (klass);
  g_module_close (module);

  if (failures != 0)
    {
      g_printerr ("TOD shim dispatch check FAILED: %d problem(s)\n", failures);
      return 1;
    }

  g_printerr ("TOD shim dispatch check passed\n");
  return 0;
}
