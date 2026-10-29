/*
 * Hardware harness for identification at the libfprint level.
 *
 * `fprintd` 1.94 has no identification call (its D-Bus interface offers VerifyStart and EnrollStart
 * only), so one-to-many matching cannot be exercised through the daemon on this machine. This
 * program drives the plugin the way libfprint does: it enumerates the sensor through FpContext,
 * opens it, calls fp_device_identify_sync() with a gallery of FpPrints and prints the print that
 * matched, or "no match".
 *
 * The gallery comes from fprintd's stored prints (the same serialized files it loads, through
 * fp_print_deserialize) and/or from a CV3P payload printed by `cvctl enroll-then-verify`:
 *
 *   --user NAME        load every CV3P print under /var/lib/fprint/NAME (recursively)
 *   --print FILE       load one serialized print file (fp_print_deserialize)
 *   --payload HEX      build an FpPrint from a 30-byte CV3P payload, fpi-type RAW and fpi-data
 *
 * The plugin is found through FP_TOD_DRIVERS_DIR, which the loader reads; scripts/identify-hardware.sh
 * stages the built plugin in a directory with only that driver and prints the exact root command.
 * Run as root with fprintd stopped: this program claims the USB interface directly and must not
 * race the daemon for it. It never resets the device.
 */

#include <fprint.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

/* FPI_PRINT_RAW from libfprint's TOD `fpi-print.h`. The public header does not expose the
 * `fpi-type` enum, but the property value is this small integer and `fprintd` stores it verbatim. */
#define CV3_PRINT_RAW 1

static void
usage (const char *program)
{
  g_printerr (
    "usage: %s [--user NAME] [--print FILE]... [--payload HEX]...\n"
    "\n"
    "  --user NAME    load the stored prints under /var/lib/fprint/NAME\n"
    "  --print FILE   load one serialized print (fp_print_deserialize)\n"
    "  --payload HEX  build a print from a CV3P payload (`cvctl enroll-then-verify`)\n"
    "\n"
    "Set FP_TOD_DRIVERS_DIR to the directory holding the plugin and run as root with fprintd\n"
    "stopped. scripts/identify-hardware.sh builds this program and prints that command.\n",
    program);
}

static const char *
finger_name (FpFinger finger)
{
  switch (finger)
    {
    case FP_FINGER_LEFT_THUMB:
      return "left-thumb";
    case FP_FINGER_LEFT_INDEX:
      return "left-index-finger";
    case FP_FINGER_LEFT_MIDDLE:
      return "left-middle-finger";
    case FP_FINGER_LEFT_RING:
      return "left-ring-finger";
    case FP_FINGER_LEFT_LITTLE:
      return "left-little-finger";
    case FP_FINGER_RIGHT_THUMB:
      return "right-thumb";
    case FP_FINGER_RIGHT_INDEX:
      return "right-index-finger";
    case FP_FINGER_RIGHT_MIDDLE:
      return "right-middle-finger";
    case FP_FINGER_RIGHT_RING:
      return "right-ring-finger";
    case FP_FINGER_RIGHT_LITTLE:
      return "right-little-finger";
    default:
      return "unknown";
    }
}

/* Parses a hex string, allowing whitespace and an optional 0x prefix. Returns NULL on bad input. */
static guint8 *
parse_hex (const gchar *text, gsize *length)
{
  GString *digits = g_string_new (NULL);
  gsize pairs;
  guint8 *bytes;
  const gchar *cursor = text;

  while (*cursor != '\0' && g_ascii_isspace (*cursor))
    cursor++;
  if (cursor[0] == '0' && (cursor[1] == 'x' || cursor[1] == 'X'))
    cursor += 2;

  for (; *cursor != '\0'; cursor++)
    {
      if (g_ascii_isspace (*cursor))
        continue;
      if (!g_ascii_isxdigit (*cursor))
        {
          g_string_free (digits, TRUE);
          return NULL;
        }
      g_string_append_c (digits, *cursor);
    }
  if (digits->len == 0 || digits->len % 2 != 0)
    {
      g_string_free (digits, TRUE);
      return NULL;
    }

  pairs = digits->len / 2;
  bytes = g_malloc (pairs);
  for (gsize i = 0; i < pairs; i++)
    {
      gchar pair[3] = { digits->str[2 * i], digits->str[2 * i + 1], '\0' };

      bytes[i] = (guint8) g_ascii_strtoull (pair, NULL, 16);
    }
  g_string_free (digits, TRUE);
  *length = pairs;
  return bytes;
}

static FpPrint *
print_from_payload (FpDevice *device, const guint8 *payload, gsize length)
{
  FpPrint *print = fp_print_new (device);

  g_object_set (print, "fpi-type", CV3_PRINT_RAW, NULL);
  g_object_set (print, "fpi-data",
                g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, payload, length, 1),
                NULL);
  fp_print_set_description (print, "cvctl payload");
  return print;
}

static void
add_serialized_print (const gchar *path, GPtrArray *gallery)
{
  gchar *contents = NULL;
  gsize length = 0;
  GError *error = NULL;
  FpPrint *print;

  if (!g_file_get_contents (path, &contents, &length, &error))
    {
      g_printerr ("warning: cannot read %s: %s\n", path,
                  error != NULL ? error->message : "unknown error");
      g_clear_error (&error);
      return;
    }

  print = fp_print_deserialize ((const guchar *) contents, length, &error);
  if (print == NULL)
    {
      g_printerr ("warning: %s is not a serialized print: %s\n", path,
                  error != NULL ? error->message : "unknown error");
      g_clear_error (&error);
      g_free (contents);
      return;
    }
  g_free (contents);

  if (g_strcmp0 (fp_print_get_driver (print), "cv3") != 0)
    {
      g_printerr ("warning: %s belongs to driver `%s`, not cv3; skipping\n", path,
                  fp_print_get_driver (print) != NULL ? fp_print_get_driver (print) : "(none)");
      g_object_unref (print);
      return;
    }
  g_ptr_array_add (gallery, print);
}

/* fprintd stores one print per file under /var/lib/fprint/<user>/<driver>/<device>/<finger>.
 * Recursing means this works whatever device id the driver advertised. */
static void
add_stored_prints (const gchar *directory, GPtrArray *gallery)
{
  GDir *dir = g_dir_open (directory, 0, NULL);
  const gchar *name;

  if (dir == NULL)
    {
      g_printerr ("warning: cannot read %s; no stored prints from there\n", directory);
      return;
    }

  while ((name = g_dir_read_name (dir)) != NULL)
    {
      gchar *path = g_build_filename (directory, name, NULL);

      if (g_file_test (path, G_FILE_TEST_IS_DIR))
        add_stored_prints (path, gallery);
      else if (g_file_test (path, G_FILE_TEST_IS_REGULAR))
        add_serialized_print (path, gallery);
      g_free (path);
    }
  g_dir_close (dir);
}

static FpDevice *
pick_device (FpContext *context)
{
  GPtrArray *devices = fp_context_get_devices (context);
  FpDevice *fallback = NULL;

  if (devices == NULL)
    return NULL;
  for (guint i = 0; i < devices->len; i++)
    {
      FpDevice *device = g_ptr_array_index (devices, i);

      if (fallback == NULL)
        fallback = device;
      if (g_strcmp0 (fp_device_get_driver (device), "cv3") == 0)
        return device;
    }
  return fallback;
}

static void
describe_print (guint index, FpPrint *print)
{
  const gchar *username = fp_print_get_username (print);
  const gchar *description = fp_print_get_description (print);

  g_printerr ("  [%u] finger=%s username=%s description=%s\n", index,
              finger_name (fp_print_get_finger (print)),
              username != NULL ? username : "(none)",
              description != NULL ? description : "(none)");
}

int
main (int argc, char **argv)
{
  GPtrArray *files = g_ptr_array_new_with_free_func (g_free);
  GPtrArray *payloads = g_ptr_array_new_with_free_func (g_free);
  const gchar *user = NULL;
  FpContext *context;
  FpDevice *device;
  GPtrArray *gallery = NULL;
  FpPrint *match = NULL;
  GError *error = NULL;
  gboolean identified;
  int status = 0;

  for (int i = 1; i < argc; i++)
    {
      if (g_strcmp0 (argv[i], "--user") == 0 && i + 1 < argc)
        user = argv[++i];
      else if (g_strcmp0 (argv[i], "--print") == 0 && i + 1 < argc)
        g_ptr_array_add (files, g_strdup (argv[++i]));
      else if (g_strcmp0 (argv[i], "--payload") == 0 && i + 1 < argc)
        g_ptr_array_add (payloads, g_strdup (argv[++i]));
      else
        {
          usage (argv[0]);
          return 1;
        }
    }

  context = fp_context_new ();
  fp_context_enumerate (context);
  device = pick_device (context);
  if (device == NULL)
    {
      g_printerr ("error: libfprint found no device. Is FP_TOD_DRIVERS_DIR pointing at the "
                  "directory holding libfprint-2-tod-1-cv3.so, and fprintd stopped?\n");
      status = 2;
      goto out_context;
    }
  g_printerr ("device: %s (driver %s)\n", fp_device_get_name (device),
              fp_device_get_driver (device));

  gallery = g_ptr_array_new_with_free_func (g_object_unref);

  if (user != NULL)
    {
      gchar *directory = g_build_filename ("/var/lib/fprint", user, NULL);

      add_stored_prints (directory, gallery);
      g_free (directory);
    }
  for (guint i = 0; i < files->len; i++)
    add_serialized_print (g_ptr_array_index (files, i), gallery);
  for (guint i = 0; i < payloads->len; i++)
    {
      gsize length = 0;
      guint8 *bytes = parse_hex (g_ptr_array_index (payloads, i), &length);

      if (bytes == NULL)
        {
          g_printerr ("error: --payload is not an even-length hex string\n");
          status = 1;
          goto out_gallery;
        }
      g_ptr_array_add (gallery, print_from_payload (device, bytes, length));
      g_free (bytes);
    }

  g_printerr ("gallery: %u print(s)\n", gallery->len);
  for (guint i = 0; i < gallery->len; i++)
    describe_print (i, g_ptr_array_index (gallery, i));
  if (gallery->len == 0)
    {
      g_printerr ("error: the gallery is empty; pass --user, --print or --payload\n");
      status = 1;
      goto out_gallery;
    }

  if (!fp_device_open_sync (device, NULL, &error))
    {
      g_printerr ("error: cannot open the sensor: %s\n",
                  error != NULL ? error->message : "unknown error");
      g_clear_error (&error);
      status = 3;
      goto out_gallery;
    }

  identified = fp_device_identify_sync (device, gallery, NULL, NULL, NULL, &match, NULL, &error);
  if (!identified)
    {
      g_printerr ("error: identification failed: %s\n",
                  error != NULL ? error->message : "unknown error");
      g_clear_error (&error);
      status = 4;
    }
  else if (match == NULL)
    {
      g_printerr ("no match\n");
    }
  else
    {
      guint index = 0;

      for (guint i = 0; i < gallery->len; i++)
        if (g_ptr_array_index (gallery, i) == match)
          index = i;
      g_printerr ("matched: [%u] finger=%s username=%s description=%s\n", index,
                  finger_name (fp_print_get_finger (match)),
                  fp_print_get_username (match) != NULL ? fp_print_get_username (match)
                                                        : "(none)",
                  fp_print_get_description (match) != NULL ? fp_print_get_description (match)
                                                           : "(none)");
    }
  g_clear_object (&match);

  if (!fp_device_close_sync (device, NULL, &error))
    {
      g_printerr ("warning: close failed: %s\n",
                  error != NULL ? error->message : "unknown error");
      g_clear_error (&error);
    }

out_gallery:
  g_clear_pointer (&gallery, g_ptr_array_unref);
out_context:
  g_ptr_array_unref (files);
  g_ptr_array_unref (payloads);
  g_object_unref (context);
  return status;
}
