/*
 * Loads the built TOD plugin the way libfprint's loader does and checks the class libfprint and
 * fprintd dereference, then drives fprintd's Claim and Release through a whole session.
 *
 * Built and run by scripts/check-tod-class.sh together with tests/fake_gusb.c: the fake scripts
 * the sensor's replies at fpi_usb_transfer_submit and models libgusb's open/close/claim state, so
 * no root, sensor or USB are needed.
 *
 * What it proves, and why each part matters:
 *  - the exported entry point resolves and returns a class carrying the identity and the id table
 *    the SPEC names;
 *  - every vfunc libfprint calls through the class pointer without a NULL guard (`open`, `close`,
 *    `enroll`, `verify`) is non-NULL: a NULL there is a segfault inside fprintd, which runs as
 *    root; the vfuncs for the features this driver does not declare stay NULL;
 *  - a first Claim whose 0x24 reply is refused fails with FP_DEVICE_ERROR_PROTO, and before it
 *    reports the failure it writes the plain 0x04 that releases the handle the 0x23 reply named,
 *    releases interface 0 and closes the GUsb handle libfprint opened: no handle is left on the
 *    sensor and the next Claim is not refused as "Device is already open";
 *  - a SECOND Claim on the same device succeeds: the driver sends 0x23, 0x24 and the wrapped 0x02
 *    and completes; a failed open leaves nothing behind that stops the next one;
 *  - Release sends the plain 0x04, releases the interface and completes successfully; a further
 *    Release is refused by libfprint with NOT_OPEN and nothing crashes.
 *  - a verification of a print with no record fails with DATA_NOT_FOUND and of one with an unknown
 *    record version with DATA_INVALID, both before any frame; the real record reaches the core.
 *
 * The scripted replies are real frames the Rust core parses and cryptographically accepts; the
 * fake fabricates nothing the core would reject. The fake also enforces libfprint's transfer
 * ownership (submit consumes the reference `fpi_usb_transfer_new` returned), so a shim that unrefs
 * a submitted transfer aborts this harness rather than segfaulting fprintd on a real Claim.
 */

#include <fprint.h>
#include <drivers_api.h>
#include <gmodule.h>

/* tests/fake_gusb.c, linked into this executable so its symbols interpose for the plugin. */
void fake_gusb_plan_session (void);
void fake_gusb_plan_enrol (void);
void fake_gusb_plan_verify (void);
void fake_gusb_plan_vanishing (void);
void fake_gusb_plan_close_failure (void);
guint fake_gusb_out_count (void);
guint16 fake_gusb_out_command (guint index);
gboolean fake_gusb_is_open (void);
gboolean fake_gusb_interface_claimed (void);
guint fake_gusb_opens (void);
guint fake_gusb_closes (void);
guint fake_gusb_claims (void);
guint fake_gusb_releases (void);

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

typedef GType (*GetTypeFunc) (void);

static void
expect_commands (const guint16 *expected, guint count, const char *stage)
{
  guint actual = fake_gusb_out_count ();

  check (actual == count, "%s wrote %u frame(s) (got %u)", stage, count, actual);
  for (guint i = 0; i < count && i < actual; i++)
    {
      guint16 command = fake_gusb_out_command (i);
      check (command == expected[i], "%s frame %u is 0x%02x (got 0x%02x)",
             stage, i + 1, expected[i], command);
    }
}

static void
check_identity (FpDeviceClass *klass)
{
  check (g_strcmp0 (klass->id, "cv3") == 0,
         "class id is `cv3` (got `%s`)", klass->id ? klass->id : "(null)");
  check (g_strcmp0 (klass->full_name, "Dell/Broadcom ControlVault 3 fingerprint") == 0,
         "class full name names the sensor (got `%s`)",
         klass->full_name ? klass->full_name : "(null)");
  check (klass->type == FP_DEVICE_TYPE_USB, "class type is USB (got %d)", klass->type);
  check (klass->scan_type == FP_SCAN_TYPE_PRESS,
         "scan type is press (got %d)", klass->scan_type);

  /* Enrolment is advertised by the stage count, not by a feature bit: libfprint 1.95 has no
   * FP_DEVICE_FEATURE_ENROLL. The class must still carry one feature for construction, and the one
   * this driver implements is VERIFY. */
  check (klass->nr_enroll_stages == 13,
         "the class declares thirteen enrolment stages (got %d)", klass->nr_enroll_stages);
  check (klass->features == FP_DEVICE_FEATURE_VERIFY,
         "the class declares VERIFY and nothing else (got 0x%02x)", klass->features);

  check (klass->id_table != NULL, "the class has an id table");
  if (klass->id_table != NULL)
    {
      check (klass->id_table[0].vid == 0x0a5c && klass->id_table[0].pid == 0x5843,
             "the id table claims 0a5c:5843 (got %04x:%04x)",
             klass->id_table[0].vid, klass->id_table[0].pid);
      check (klass->id_table[1].vid == 0 && klass->id_table[1].pid == 0,
             "the id table is terminated");
    }
}

static void
check_unconditional_vfuncs (FpDeviceClass *klass)
{
  /* libfprint 1.95 dereferences these four through the class pointer without testing for NULL. */
  check (klass->open != NULL, "open is set");
  check (klass->close != NULL, "close is set");
  check (klass->enroll != NULL, "enroll is set");
  check (klass->verify != NULL, "verify is set");
}

/* The features this driver does not declare must stay NULL, or libfprint would offer an operation
 * that cannot work and dereference a missing vfunc. */
static void
check_undeclared_vfuncs (FpDeviceClass *klass)
{
  check (klass->capture == NULL, "capture is not offered");
  check (klass->identify == NULL, "identify is not offered");
  check (klass->list == NULL, "list is not offered");
  check (klass->delete == NULL, "delete is not offered");
  check (klass->clear_storage == NULL, "clear_storage is not offered");
}

static void
check_session (GType type)
{
  FpDevice *device = g_object_new (type, NULL);
  GUsbDevice *usb = g_object_new (G_USB_TYPE_DEVICE, NULL);
  GTypeClass *base_class = g_type_class_ref (FP_TYPE_DEVICE);
  gint private_offset = g_type_class_get_instance_private_offset (base_class);

  /* The device takes ownership of its USB handle and unrefs it when it finalizes; keep our own
   * reference so the handle outlives the device here. */
  g_object_ref (usb);

  /* libfprint takes the GUsbDevice from FpDevice's instance-private data, which neither the public
   * API nor the TOD headers expose a setter for. The block's offset comes from the class, the same
   * call libfprint's own accessors make; the field follows the device type. Writing it and reading
   * it back through fpi_device_get_usb_device() makes a layout change fail here, loudly, instead of
   * making the open path silently skip the close. */
  *(GUsbDevice **) ((char *) device + private_offset + 8) = usb;
  if (fpi_device_get_usb_device (device) != usb)
    {
      g_printerr ("error: cannot attach a GUsbDevice to the FpDevice; libfprint's private layout "
                  "changed and this harness needs updating\n");
      failures++;
      g_type_class_unref (base_class);
      g_object_unref (device);
      g_object_unref (usb);
      return;
    }
  g_type_class_unref (base_class);

  fake_gusb_plan_session ();

  /* ---- Claim 1: the sensor refuses the 0x24 response; the handle must still be released. ---- */
  {
    const guint16 expected[] = { 0x23, 0x24, 0x04 };
    GError *error = NULL;
    gboolean opened = fp_device_open_sync (device, NULL, &error);

    check (!opened, "the first open fails");
    check (error != NULL, "the first open reports an error");
    if (error != NULL)
      {
        check (error->domain == FP_DEVICE_ERROR,
               "the first open fails in the fp-device domain (got `%s`)",
               g_quark_to_string (error->domain));
        check (error->code == FP_DEVICE_ERROR_PROTO,
               "the first open reports PROTO (got %d)", error->code);
        check (g_strstr_len (error->message, -1, "already open") == NULL,
               "the first open is not refused as \"already open\" (got `%s`)",
               error->message);
        check (g_strstr_len (error->message, -1, "cv3") != NULL,
               "the first open names the driver (got `%s`)", error->message);
        check (g_strstr_len (error->message, -1, "0x09") != NULL,
               "the first open reports the sensor's status (got `%s`)", error->message);
      }
    g_clear_error (&error);

    expect_commands (expected, G_N_ELEMENTS (expected), "the failed open");
    check (!fake_gusb_is_open (),
           "the failed open closed the GUsb handle libfprint opened");
    check (!fake_gusb_interface_claimed (),
           "the failed open released interface 0");
  }

  /* ---- Claim 2: a second Claim on the same device completes the whole session. ---- */
  {
    const guint16 expected[] = { 0x23, 0x24, 0x02 };
    GError *error = NULL;
    gboolean opened = fp_device_open_sync (device, NULL, &error);

    check (opened, "the second open succeeds (got error `%s`)",
           error ? error->message : "-");
    check (error == NULL, "the second open reports no error");
    g_clear_error (&error);

    check (fake_gusb_out_count () == 6,
           "the second open wrote three more frames (total %u)",
           fake_gusb_out_count ());
    for (guint i = 0; i < G_N_ELEMENTS (expected) && 3 + i < fake_gusb_out_count (); i++)
      {
        guint16 command = fake_gusb_out_command (3 + i);
        check (command == expected[i], "the second open frame %u is 0x%02x (got 0x%02x)",
               i + 1, expected[i], command);
      }
    check (fake_gusb_opens () == 2, "libfprint opened the GUsb handle twice (got %u)",
           fake_gusb_opens ());
    check (fake_gusb_is_open (), "the successful open leaves the GUsb handle open");
    check (fake_gusb_interface_claimed (), "the successful open claims interface 0");
    check (fake_gusb_claims () == 2, "both claims reached gusb (got %u)",
           fake_gusb_claims ());
  }

  /* ---- Release: the plain 0x04, the interface release, and a clean completion. ---- */
  {
    const guint16 expected[] = { 0x04 };
    GError *error = NULL;
    gboolean closed = fp_device_close_sync (device, NULL, &error);

    check (closed, "close succeeds (got error `%s`)", error ? error->message : "-");
    check (error == NULL, "close reports no error");
    g_clear_error (&error);

    check (fake_gusb_out_count () == 7, "close wrote one more frame (total %u)",
           fake_gusb_out_count ());
    if (fake_gusb_out_count () == 7)
      check (fake_gusb_out_command (6) == expected[0],
             "close sends the plain 0x04 (got 0x%02x)", fake_gusb_out_command (6));

    check (!fake_gusb_interface_claimed (), "close released interface 0");
    check (!fake_gusb_is_open (), "close closed the GUsb handle");
    check (fake_gusb_releases () == 2, "both releases reached gusb (got %u)",
           fake_gusb_releases ());
    check (fake_gusb_closes () == 2, "libfprint closed the GUsb handle on both paths (got %u)",
           fake_gusb_closes ());
  }

  /* A second Release is libfprint's own NOT_OPEN answer, not a crash. */
  {
    GError *error = NULL;
    gboolean closed = fp_device_close_sync (device, NULL, &error);

    check (!closed && error != NULL && error->domain == FP_DEVICE_ERROR
             && error->code == FP_DEVICE_ERROR_NOT_OPEN,
           "a second close refuses with NOT_OPEN (got %s `%s`)",
           closed ? "success" : "an error", error ? error->message : "-");
    g_clear_error (&error);
  }

  g_object_unref (device);
  g_object_unref (usb);
}

/* A sensor that leaves the bus before announcing its 0x23 reply: the Claim must complete with
 * REMOVED, not hang, and must leave the interface and the GUsb handle free. */
static void
check_vanished_device (GType type)
{
  FpDevice *device = g_object_new (type, NULL);
  GUsbDevice *usb = g_object_new (G_USB_TYPE_DEVICE, NULL);
  GTypeClass *base_class = g_type_class_ref (FP_TYPE_DEVICE);
  gint private_offset = g_type_class_get_instance_private_offset (base_class);
  GError *error = NULL;
  gboolean opened;

  g_object_ref (usb);
  *(GUsbDevice **) ((char *) device + private_offset + 8) = usb;
  g_type_class_unref (base_class);

  fake_gusb_plan_vanishing ();
  opened = fp_device_open_sync (device, NULL, &error);

  check (!opened, "an open on a vanished sensor fails");
  check (error != NULL, "the vanished device reports an error");
  if (error != NULL)
    {
      check (error->domain == FP_DEVICE_ERROR,
             "the vanished device fails in the fp-device domain (got `%s`)",
             g_quark_to_string (error->domain));
      check (error->code == FP_DEVICE_ERROR_REMOVED,
             "the vanished device reports REMOVED (got %d)", error->code);
      check (g_strstr_len (error->message, -1, "cv3") != NULL,
             "the vanished device error names the driver (got `%s`)", error->message);
    }
  g_clear_error (&error);

  check (fake_gusb_out_count () == 1,
         "only the 0x23 command was written before the sensor left (got %u)",
         fake_gusb_out_count ());
  check (!fake_gusb_interface_claimed (),
         "the vanished-device open released interface 0");
  check (!fake_gusb_is_open (),
         "the vanished-device open closed the GUsb handle");

  g_object_unref (device);
  g_object_unref (usb);
}

/* A close whose 0x04 transfer fails must still complete successfully: libfprint's Release is not
 * allowed to fail because the sensor did not answer the teardown. */
static void
check_close_transfer_failure (GType type)
{
  FpDevice *device = g_object_new (type, NULL);
  GUsbDevice *usb = g_object_new (G_USB_TYPE_DEVICE, NULL);
  GTypeClass *base_class = g_type_class_ref (FP_TYPE_DEVICE);
  gint private_offset = g_type_class_get_instance_private_offset (base_class);
  GError *error = NULL;
  gboolean opened;
  gboolean closed;

  g_object_ref (usb);
  *(GUsbDevice **) ((char *) device + private_offset + 8) = usb;
  g_type_class_unref (base_class);

  fake_gusb_plan_close_failure ();

  opened = fp_device_open_sync (device, NULL, &error);
  check (opened && error == NULL, "the open before the failing close succeeds");
  g_clear_error (&error);

  closed = fp_device_close_sync (device, NULL, &error);
  check (closed, "close completes even when the 0x04 transfer fails (got error `%s`)",
         error ? error->message : "-");
  check (error == NULL, "the failing close reports no error");
  g_clear_error (&error);

  check (fake_gusb_out_count () == 4, "the failing close still wrote the 0x04 (got %u frames)",
         fake_gusb_out_count ());
  if (fake_gusb_out_count () == 4)
    check (fake_gusb_out_command (3) == 0x04,
           "the failing close frame is 0x04 (got 0x%02x)", fake_gusb_out_command (3));
  check (!fake_gusb_interface_claimed (), "the failing close released interface 0");
  check (!fake_gusb_is_open (), "the failing close closed the GUsb handle");

  g_object_unref (device);
  g_object_unref (usb);
}

/* One enrolment on an open session whose first command the fake cannot answer: the vfunc must
 * reach the core, report the failure as an FP_DEVICE_ERROR naming the driver, store nothing, and
 * leave the device closable. A successful enrolment needs wrapped replies the fake cannot
 * fabricate (it holds no session key), so the success path and the payload are covered by the
 * Rust tests and by the hardware run. */
static void
check_enrol_failure (GType type)
{
  FpDevice *device = g_object_new (type, NULL);
  GUsbDevice *usb = g_object_new (G_USB_TYPE_DEVICE, NULL);
  GTypeClass *base_class = g_type_class_ref (FP_TYPE_DEVICE);
  gint private_offset = g_type_class_get_instance_private_offset (base_class);
  GError *error = NULL;
  FpPrint *template_print;
  FpPrint *enrolled;

  g_object_ref (usb);
  *(GUsbDevice **) ((char *) device + private_offset + 8) = usb;
  g_type_class_unref (base_class);

  fake_gusb_plan_enrol ();
  check (fp_device_open_sync (device, NULL, &error),
         "the open before the enrolment succeeds (got error `%s`)",
         error ? error->message : "-");
  g_clear_error (&error);

  template_print = fp_print_new (device);
  fp_print_set_finger (template_print, FP_FINGER_LEFT_INDEX);
  fp_print_set_username (template_print, "harness");

  enrolled = fp_device_enroll_sync (device, template_print, NULL, NULL, NULL, &error);
  check (enrolled == NULL, "an enrolment the fake cannot answer fails");
  check (error != NULL, "the failed enrolment reports an error");
  if (error != NULL)
    {
      check (error->domain == FP_DEVICE_ERROR,
             "the failed enrolment fails in the fp-device domain (got `%s`)",
             g_quark_to_string (error->domain));
      check (g_strstr_len (error->message, -1, "cv3") != NULL,
             "the failed enrolment names the driver (got `%s`)", error->message);
      check (g_strstr_len (error->message, -1, "enrolment failed") != NULL,
             "the failed enrolment says it was the enrolment (got `%s`)", error->message);
      check (g_strstr_len (error->message, -1, "template") != NULL,
             "the failed enrolment says what may remain (got `%s`)", error->message);
    }
  g_clear_error (&error);
  /* fp_device_enroll_sync took the template print (floating ownership), so it is not unrefed
   * here. */

  /* The vfunc reached the core: the discard, then the best-effort teardown the core runs. */
  expect_commands ((const guint16[]) { 0x23, 0x24, 0x02, 0x6D, 0x68, 0x04 }, 6,
                   "the failed enrolment");
  check (fake_gusb_is_open (), "the failed enrolment leaves the device open");
  check (fake_gusb_interface_claimed (), "the failed enrolment keeps interface 0 claimed");

  check (fp_device_close_sync (device, NULL, &error),
         "the device closes after a failed enrolment (got error `%s`)",
         error ? error->message : "-");
  g_clear_error (&error);
  check (!fake_gusb_interface_claimed (), "the close after a failed enrolment released interface 0");

  g_object_unref (device);
  g_object_unref (usb);
}

/* Verification on an open session, for the three things the fake can honestly show:
 *
 *  - a print with no `fpi-data` is refused with FP_DEVICE_ERROR_DATA_NOT_FOUND and nothing is
 *    written — the driver never guesses a match id;
 *  - a print whose record this driver does not know (another version) is refused with
 *    FP_DEVICE_ERROR_DATA_INVALID, also before any transfer;
 *  - the real record reaches the core, which writes the `0x66` capture arm, fails on the sensor the
 *    fake does not answer, and runs its best-effort teardown.
 *
 * The accepted match and the no-match themselves need wrapped replies, which the fake cannot
 * fabricate without the session key; the Rust tests cover them and the hardware run confirms them.
 */
static void
check_verify (GType type)
{
  static const guint8 record[30] = {
    'C', 'V', '3', 'P', 1, 1,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0x1f, 0x36, 0xf2, 0x00,
  };
  guint8 unknown_version[sizeof record];
  FpDevice *device = g_object_new (type, NULL);
  GUsbDevice *usb = g_object_new (G_USB_TYPE_DEVICE, NULL);
  GTypeClass *base_class = g_type_class_ref (FP_TYPE_DEVICE);
  gint private_offset = g_type_class_get_instance_private_offset (base_class);
  GError *error = NULL;
  FpPrint *print;
  gboolean matched = TRUE;

  g_object_ref (usb);
  *(GUsbDevice **) ((char *) device + private_offset + 8) = usb;
  g_type_class_unref (base_class);

  fake_gusb_plan_verify ();
  check (fp_device_open_sync (device, NULL, &error),
         "the open before a verification succeeds (got error `%s`)",
         error ? error->message : "-");
  g_clear_error (&error);

  /* No stored record: DATA_NOT_FOUND, and no frame is written. */
  print = fp_print_new (device);
  check (!fp_device_verify_sync (device, print, NULL, NULL, NULL, &matched, NULL, &error),
         "a print without a record does not verify");
  check (error != NULL && error->domain == FP_DEVICE_ERROR
           && error->code == FP_DEVICE_ERROR_DATA_NOT_FOUND,
         "a print without a record reports DATA_NOT_FOUND (got %d `%s`)",
         error ? error->code : -1, error ? error->message : "-");
  check (error != NULL && g_strstr_len (error->message, -1, "cv3") != NULL,
         "the DATA_NOT_FOUND error names the driver (got `%s`)",
         error ? error->message : "-");
  g_clear_error (&error);
  g_object_unref (print);
  check (fake_gusb_out_count () == 3,
         "a print without a record wrote no frame (got %u)", fake_gusb_out_count ());

  /* A record of an unknown version: DATA_INVALID, and still no frame. */
  memcpy (unknown_version, record, sizeof record);
  unknown_version[4] = 2;
  print = fp_print_new (device);
  g_object_set (print, "fpi-type", FPI_PRINT_RAW, NULL);
  g_object_set (print, "fpi-data",
                g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, unknown_version,
                                           sizeof unknown_version, 1),
                NULL);
  check (!fp_device_verify_sync (device, print, NULL, NULL, NULL, &matched, NULL, &error),
         "a print with an unknown record version does not verify");
  check (error != NULL && error->domain == FP_DEVICE_ERROR
           && error->code == FP_DEVICE_ERROR_DATA_INVALID,
         "an unknown record version reports DATA_INVALID (got %d `%s`)",
         error ? error->code : -1, error ? error->message : "-");
  g_clear_error (&error);
  g_object_unref (print);
  check (fake_gusb_out_count () == 3,
         "an unknown record version wrote no frame (got %u)", fake_gusb_out_count ());

  /* The real record: the core arms the capture and the unanswered sensor fails the run. */
  print = fp_print_new (device);
  g_object_set (print, "fpi-type", FPI_PRINT_RAW, NULL);
  g_object_set (print, "fpi-data",
                g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, record, sizeof record, 1),
                NULL);
  check (!fp_device_verify_sync (device, print, NULL, NULL, NULL, &matched, NULL, &error),
         "a verification the sensor does not answer fails");
  check (error != NULL && error->domain == FP_DEVICE_ERROR,
         "the failed verification fails in the fp-device domain (got `%s`)",
         error ? g_quark_to_string (error->domain) : "-");
  check (error != NULL && g_strstr_len (error->message, -1, "verification failed") != NULL,
         "the failed verification says it was the verification (got `%s`)",
         error ? error->message : "-");
  g_clear_error (&error);
  g_object_unref (print);

  expect_commands ((const guint16[]) { 0x23, 0x24, 0x02, 0x66, 0x68, 0x04 }, 6,
                   "the failed verification");
  check (fake_gusb_is_open (), "the failed verification leaves the device open");
  check (fake_gusb_interface_claimed (),
         "the failed verification keeps interface 0 claimed");

  check (fp_device_close_sync (device, NULL, &error),
         "the device closes after a failed verification (got error `%s`)",
         error ? error->message : "-");
  g_clear_error (&error);
  check (!fake_gusb_interface_claimed (),
         "the close after a failed verification released interface 0");

  g_object_unref (device);
  g_object_unref (usb);
}

/* The bound record is stored as a GVariant of type `ay` under `fpi-data`, with `fpi-type` RAW.
 * Pin that this libfprint round-trips it through fp_print_serialize/fp_print_deserialize: the
 * driver's success path relies on exactly this representation, which no Rust test can check. */
static void
check_print_payload_round_trip (GType type)
{
  static const guint8 payload[30] = {
    'C', 'V', '3', 'P', 1, 1,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
    0x1f, 0x36, 0xf2, 0x00,
  };
  FpDevice *device = g_object_new (type, NULL);
  GError *error = NULL;
  FpPrint *print = fp_print_new (device);
  FpPrint *copy;
  GVariant *stored = NULL;
  guchar *serialized = NULL;
  gsize length = 0;
  gsize payload_len = 0;
  const guint8 *payload_bytes;

  fp_print_set_finger (print, FP_FINGER_LEFT_INDEX);
  fp_print_set_username (print, "harness");
  g_object_set (print, "fpi-type", FPI_PRINT_RAW, NULL);
  g_object_set (print, "fpi-data",
                g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, payload,
                                           sizeof payload, 1),
                NULL);

  check (fp_print_serialize (print, &serialized, &length, &error),
         "a print with the bound payload serializes (got error `%s`)",
         error ? error->message : "-");
  g_clear_error (&error);
  if (serialized != NULL)
    {
      copy = fp_print_deserialize (serialized, length, &error);
      check (copy != NULL, "the serialized print deserializes (got error `%s`)",
             error ? error->message : "-");
      g_clear_error (&error);
      if (copy != NULL)
        {
          g_object_get (copy, "fpi-data", &stored, NULL);
          check (stored != NULL && g_variant_is_of_type (stored, G_VARIANT_TYPE ("ay")),
                 "the round-tripped print carries a byte-array fpi-data");
          if (stored != NULL && g_variant_is_of_type (stored, G_VARIANT_TYPE ("ay")))
            {
              payload_bytes = g_variant_get_fixed_array (stored, &payload_len, 1);
              check (payload_len == sizeof payload,
                     "the round-tripped payload is %zu bytes (got %zu)",
                     sizeof payload, payload_len);
              check (payload_len == sizeof payload
                     && memcmp (payload_bytes, payload, sizeof payload) == 0,
                     "the round-tripped payload is the same 30 bytes");
            }
          g_clear_pointer (&stored, g_variant_unref);
          g_object_unref (copy);
        }
      g_free (serialized);
    }
  g_object_unref (print);
  g_object_unref (device);
}

int
main (int argc, char **argv)
{
  const gchar *path = argc > 1 ? argv[1] : "target/release/libcv3_tod.so";
  GModule *module;
  GetTypeFunc get_type;
  GType type;
  FpDeviceClass *klass;

  module = g_module_open (path, G_MODULE_BIND_LAZY);
  if (module == NULL)
    {
      g_printerr ("error: cannot load %s: %s\n", path, g_module_error ());
      return 1;
    }

  if (!g_module_symbol (module, "fpi_tod_shared_driver_get_type",
                        (gpointer *) &get_type))
    {
      g_printerr ("error: %s does not export fpi_tod_shared_driver_get_type: %s\n",
                  path, g_module_error ());
      return 1;
    }

  type = get_type ();
  check (type != G_TYPE_INVALID, "the entry point returns a GType");
  if (!g_type_is_a (type, FP_TYPE_DEVICE))
    {
      g_printerr ("error: the entry point returned %s, which is not an FpDevice subclass\n",
                  g_type_name (type));
      return 1;
    }

  klass = g_type_class_ref (type);
  check_identity (klass);
  check_unconditional_vfuncs (klass);
  check_undeclared_vfuncs (klass);
  check_session (type);
  check_enrol_failure (type);
  check_verify (type);
  check_print_payload_round_trip (type);
  check_vanished_device (type);
  check_close_transfer_failure (type);
  g_type_class_unref (klass);

  g_module_close (module);

  if (failures != 0)
    {
      g_printerr ("TOD class/open check FAILED: %d problem(s)\n", failures);
      return 1;
    }

  g_printerr ("TOD class/open check passed\n");
  return 0;
}
