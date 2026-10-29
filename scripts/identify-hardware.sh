#!/bin/sh
# Builds the libfprint-level identification harness and prints the exact root command.
#
# fprintd 1.94 has no identification method on its D-Bus interface, so one-to-many matching cannot
# be exercised through the daemon. scripts/identify-hardware.c drives the plugin the way libfprint
# does: FpContext, an open, then fp_device_identify_sync() with a gallery of stored prints (or a
# CV3P payload from `cvctl enroll-then-verify`). This script stages the built plugin in a directory
# of its own and passes that as FP_TOD_DRIVERS_DIR, so the harness loads this driver and no other.
#
# It never runs sudo. As root it runs the harness; otherwise it prints the commands to paste.
#
# Usage: scripts/identify-hardware.sh [--user NAME | --print FILE | --payload HEX]...

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
plugin=$root/target/release/libcv3_tod.so
stage=$root/target/identify-tod
harness=$root/target/identify-hardware

if [ ! -f "$plugin" ]; then
    echo "error: $plugin not found; run ./scripts/build-plugin.sh first" >&2
    exit 1
fi

if ! pkg-config --exists libfprint-2 glib-2.0; then
    echo "error: missing libfprint-2-dev or glib development files" >&2
    exit 1
fi

cc -std=gnu11 -Wall -Wextra -Werror -O2 \
    -o "$harness" "$root/scripts/identify-hardware.c" \
    $(pkg-config --cflags --libs libfprint-2 glib-2.0)

# The loader scans FP_TOD_DRIVERS_DIR for TOD drivers; staging one file makes the choice explicit.
mkdir -p "$stage"
cp "$plugin" "$stage/libfprint-2-tod-1-cv3.so"
echo "built $harness"
echo "staged the plugin in $stage"

if [ "$(id -u)" -ne 0 ]; then
    account=$(id -un)
    cat <<EOF

Run as root with fprintd stopped (this script never calls sudo):

    sudo systemctl stop fprintd
    sudo FP_TOD_DRIVERS_DIR=$stage $harness --user $account

Or identify against a CV3P payload printed by \`cvctl enroll-then-verify\` (the
"print payload <hex>" line; 30 bytes):

    sudo FP_TOD_DRIVERS_DIR=$stage $harness --payload <hex>

A serialized print file also works:

    sudo FP_TOD_DRIVERS_DIR=$stage $harness --print /var/lib/fprint/$account/cv3/DEVICE/2

The harness prints the matched print's finger, username and description, or "no match".
Restart the daemon afterwards: sudo systemctl start fprintd
EOF
    exit 0
fi

if pgrep -x fprintd >/dev/null 2>&1; then
    echo "error: fprintd is running; stop it first: systemctl stop fprintd" >&2
    exit 1
fi

echo "running as root with FP_TOD_DRIVERS_DIR=$stage"
exec env FP_TOD_DRIVERS_DIR="$stage" "$harness" "$@"
