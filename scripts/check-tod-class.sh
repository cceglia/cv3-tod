#!/bin/sh
# Loads the built plugin the way libfprint's TOD loader does and checks what fprintd then sees.
#
# The unit tests in crates/cv3-tod can only check the Rust session machine, not the C boundary or
# what libfprint actually calls. This script checks the real object:
#
#   1. g_module_open()s it, resolves `fpi_tod_shared_driver_get_type` and reads the class: identity,
#      id table, and the vfuncs libfprint dereferences without a NULL test (`open`, `close`,
#      `enroll`) — a NULL in any of those is a segfault inside fprintd, which runs as root.
#   2. Drives fprintd's Claim/Release on that class with tests/fake_gusb.c linked into the harness
#      (`-Wl,--export-dynamic` so its symbols interpose for the plugin). The fake scripts the
#      sensor's reply frames at fpi_usb_transfer_submit and models libgusb's open/close/claim
#      state, so no root, sensor or USB is needed.
#
# The session the harness runs:
#   - a first Claim whose 0x24 reply is refused fails with FP_DEVICE_ERROR_PROTO, after writing the
#     plain 0x04 that releases the handle and releasing both interface 0 and the GUsb handle;
#   - a second Claim on the same device sends 0x23, 0x24 and the wrapped 0x02 and succeeds, so a
#     failed open leaves nothing that turns the next Claim into "Device is already open";
#   - Release sends the plain 0x04, releases the interface and completes successfully;
#   - an open whose sensor leaves the bus before the 0x23 announcement completes with
#     FP_DEVICE_ERROR_REMOVED instead of hanging;
#   - a Release whose 0x04 gets no announcement still completes successfully, with the failure
#     logged and the interface and handle released.
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
# struct to read the class's vfunc slots and FpiUsbTransfer to complete a transfer.
if ! pkg-config --exists libfprint-2-tod-1 libfprint-2 gusb gmodule-2.0; then
    echo "error: missing libfprint-2-tod-dev, libgusb-dev or glib development files" >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cc -o "$work/tod-class-open" "$tests/tod_class_open.c" "$tests/fake_gusb.c" \
    $(pkg-config --cflags libfprint-2-tod-1 gmodule-2.0) \
    $(pkg-config --libs libfprint-2-tod-1 libfprint-2 gusb gmodule-2.0) \
    -Wl,--export-dynamic

"$work/tod-class-open" "$plugin"

echo "TOD class/open check passed for $plugin"
