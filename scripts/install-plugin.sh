#!/bin/sh
# Installs the plugin as one shared object in libfprint's TOD drivers directory.
#
# This script never runs sudo. Without write access it prints the exact command to run as root,
# and the removal command for uninstalling. Nothing else on the system changes: no libfprint or
# fprintd configuration is touched, and uninstalling deletes the one file.
#
# Usage: scripts/install-plugin.sh
# Override the destination directory with CV3_TOD_DIR.

set -eu

cd "$(dirname "$0")/.."

./scripts/build-plugin.sh

tod_dir=${CV3_TOD_DIR:-"$(pkg-config --variable=libdir libfprint-2-tod-1)/libfprint-2/tod-1"}
plugin=$(pwd)/target/release/libcv3_tod.so
installed=$tod_dir/libfprint-2-tod-1-cv3.so

if [ ! -d "$tod_dir" ]; then
    echo "error: $tod_dir does not exist; create it and install as root:" >&2
    printf '  sudo install -d %s\n  sudo install -m 0644 %s %s\n' \
        "$tod_dir" "$plugin" "$installed" >&2
    exit 1
fi

if [ ! -w "$tod_dir" ]; then
    echo "error: $tod_dir is not writable; install as root:" >&2
    printf '  sudo install -m 0644 %s %s\n' "$plugin" "$installed" >&2
    exit 1
fi

install -m 0644 "$plugin" "$installed"
echo "installed $installed"
echo "remove it with: rm -f $installed"
