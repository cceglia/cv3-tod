/*
 * Stand-in for libgusb's handle state, preloaded into the TOD class/open harness.
 *
 * libfprint calls g_usb_device_open before a driver's open vfunc and g_usb_device_close from
 * fpi_device_close_complete, so this fake models exactly that: opening an open handle fails with
 * G_USB_DEVICE_ERROR_ALREADY_OPEN, and closing a closed one fails with NOT_OPEN. That is what the
 * real library does, and it is what makes the "second Claim says already open" bug observable
 * without a sensor, root or USB.
 *
 * The pointer is ignored: fp_device_open passes the device's GUsbDevice field straight through, and
 * a harness has no way to install a real one. If a future libfprint starts testing that field, the
 * harness fails loudly instead of passing silently.
 */

#include <gusb.h>

static gboolean opened;
static guint opens;
static guint closes;

gboolean
g_usb_device_open (GUsbDevice *device, GError **error)
{
  (void) device;

  if (opened)
    {
      g_set_error_literal (error, G_USB_DEVICE_ERROR,
                           G_USB_DEVICE_ERROR_ALREADY_OPEN,
                           "Device is already open");
      g_printerr ("fake gusb: open refused, the handle is still open\n");
      return FALSE;
    }

  opened = TRUE;
  opens++;
  g_printerr ("fake gusb: open %u\n", opens);
  return TRUE;
}

gboolean
g_usb_device_close (GUsbDevice *device, GError **error)
{
  (void) device;

  if (!opened)
    {
      g_set_error_literal (error, G_USB_DEVICE_ERROR,
                           G_USB_DEVICE_ERROR_NOT_OPEN,
                           "Device is not open");
      return FALSE;
    }

  opened = FALSE;
  closes++;
  g_printerr ("fake gusb: close %u\n", closes);
  return TRUE;
}
