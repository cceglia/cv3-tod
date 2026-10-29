/*
 * Loads the built TOD plugin the way libfprint's loader does and checks the class libfprint and
 * fprintd dereference, then exercises the open path fprintd's Claim takes.
 *
 * Built and run by scripts/check-tod-class.sh under an LD_PRELOAD fake for g_usb_device_open and
 * g_usb_device_close (tests/fake_gusb.c): no root, no sensor and no USB are needed.
 *
 * What it proves, and why each part matters:
 *  - the exported entry point resolves and returns a class carrying the identity and the id table
 *    the SPEC names;
 *  - every vfunc libfprint calls through the class pointer without a NULL guard (`open`, `close`,
 *    `enroll`) is non-NULL: a NULL there is a segfault inside fprintd, which runs as root;
 *  - two consecutive fp_device_open_sync calls both report FP_DEVICE_ERROR_NOT_SUPPORTED and
 *    neither reports "already open": libfprint opens the GUsb device before the vfunc and does not
 *    close it when the vfunc fails, so a failed Claim that does not release the handle makes every
 *    later Claim fail with "Device is already open";
 *  - fp_device_close_sync after those failures is safe.
 *
 * The fake models gusb's own open/close state, so the buggy plugin fails here exactly as it fails
 * under fprintd.
 */

#include <fprint.h>
#include <drivers_api.h>
#include <gmodule.h>

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
  /* libfprint 1.95 dereferences these three through the class pointer without testing for NULL. */
  check (klass->open != NULL, "open is set");
  check (klass->close != NULL, "close is set");
  check (klass->enroll != NULL, "enroll is set");
}

static void
check_open_path (GType type)
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

  for (guint i = 0; i < 2; i++)
    {
      GError *error = NULL;
      gboolean opened = fp_device_open_sync (device, NULL, &error);

      check (!opened, "open %u fails", i + 1);
      check (error != NULL, "open %u reports an error", i + 1);
      if (error != NULL)
        {
          check (error->domain == FP_DEVICE_ERROR,
                 "open %u fails in the fp-device domain (got `%s`)", i + 1,
                 g_quark_to_string (error->domain));
          check (error->code == FP_DEVICE_ERROR_NOT_SUPPORTED,
                 "open %u reports NOT_SUPPORTED (got %d)", i + 1, error->code);
          check (g_strstr_len (error->message, -1, "already open") == NULL,
                 "open %u is not refused as \"already open\" (got `%s`)", i + 1,
                 error->message);
          check (g_strstr_len (error->message, -1, "cv3") != NULL,
                 "open %u names the driver (got `%s`)", i + 1, error->message);
        }
      g_clear_error (&error);
    }

  for (guint i = 0; i < 2; i++)
    {
      GError *error = NULL;
      gboolean closed = fp_device_close_sync (device, NULL, &error);

      /* Close after a failed open is expected to refuse (libfprint thinks nothing is open); what
       * matters is that it returns instead of crashing or wedging the handle. */
      check (error == NULL || g_strstr_len (error->message, -1, "already open") == NULL,
             "close %u is safe (got %s `%s`)", i + 1, closed ? "success" : "an error",
             error ? error->message : "-");
      g_clear_error (&error);
    }

  g_object_unref (device);
  g_object_unref (usb);
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
  check_open_path (type);
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
