#!/bin/sh
# Loads the built plugin the way libfprint's TOD loader does and checks what fprintd then sees.
#
# The unit tests in crates/cv3-tod/src/lib.rs can only read the C source as text, and text cannot
# tell a class that is safe from one that only looks safe. This script checks the real object:
#
#   1. g_module_open()s it, resolves `fpi_tod_shared_driver_get_type` and reads the class: identity,
#      id table, and the vfuncs libfprint dereferences without a NULL test (`open`, `close`,
#      `enroll`) — a NULL in any of those is a segfault inside fprintd, which runs as root.
#   2. With an LD_PRELOAD fake for g_usb_device_open/close (crates/cv3-tod/tests/fake_gusb.c) so no
#      root, sensor or USB is needed, calls fp_device_open_sync twice: libfprint opens the GUsb
#      handle *before* the driver's open vfunc and fpi_device_open_complete does not close it, so a
#      failed Claim that leaks the handle makes the second open fail with GUsb's "Device is already
#      open". Both opens must report FP_DEVICE_ERROR_NOT_SUPPORTED, and neither may say
#      "already open". fp_device_close_sync is then called twice to show it stays safe.
#
# Usage: scripts/check-tod-class.sh [path/to/plugin.so]
#   default path: target/release/libcv3_tod.so
# A relative path is resolved against the directory the script is run from, not the repository.
# Run by scripts/build-plugin.sh, and therefore by CI.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tests=$root/crates/cv3-tod/tests
caller_dir=$(pwd)

if [ "${1:-}" != "" ]; then
    case $1 in
    /*) plugin=$1 ;;
    *) plugin=$caller_dir/$1 ;;
    esac
else
    plugin=$root/target/release/libcv3_tod.so
fi

if [ ! -f "$plugin" ]; then
    echo "error: $plugin not found; run ./scripts/build-plugin.sh first" >&2
    exit 1
fi

# The TOD headers define FpDeviceClass, which the public API keeps opaque; the harness needs the
# struct to read the class's vfunc slots.
if ! pkg-config --exists libfprint-2-tod-1 libfprint-2 gusb gmodule-2.0; then
    echo "error: missing libfprint-2-tod-dev, libgusb-dev or glib development files" >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cc -shared -fPIC -o "$work/fake-gusb.so" "$tests/fake_gusb.c" \
    $(pkg-config --cflags --libs gusb)
cc -o "$work/tod-class-open" "$tests/tod_class_open.c" \
    $(pkg-config --cflags libfprint-2-tod-1 gmodule-2.0) \
    $(pkg-config --libs libfprint-2-tod-1 libfprint-2 gusb gmodule-2.0)

# The fake must be preloaded, not linked: it replaces the library's symbols for libfprint and for
# the plugin alike.
LD_PRELOAD="$work/fake-gusb.so" "$work/tod-class-open" "$plugin"

echo "TOD class/open check passed for $plugin"
