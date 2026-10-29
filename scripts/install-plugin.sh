#!/bin/sh
# Installs the plugin as one shared object in libfprint's TOD drivers directory.
#
# This script never runs sudo. Without write access it prints the exact command to run as root,
# with the paths quoted for pasting, and the removal command for uninstalling. Nothing else on the
# system changes: no libfprint or fprintd configuration is touched, and uninstalling deletes the
# one file.
#
# Usage: scripts/install-plugin.sh
# Override the destination directory with CV3_TOD_DIR; a relative value is resolved against the
# directory you run the script from.

set -eu

# The caller's directory, before the script changes its own working directory.
caller_dir=$(pwd)
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/tod-lib.sh"

cd "$script_dir/.."

./scripts/build-plugin.sh

driver_dir=$(tod_dir)
plugin=$(pwd)/target/release/libcv3_tod.so
installed=$driver_dir/$tod_plugin_name

if [ ! -d "$driver_dir" ]; then
    echo "error: $driver_dir does not exist; create it and install as root:" >&2
    printf '  sudo install -d %s\n  sudo install -m 0644 %s %s\n' \
        "$(quote "$driver_dir")" "$(quote "$plugin")" "$(quote "$installed")" >&2
    exit 1
fi

if [ ! -w "$driver_dir" ]; then
    echo "error: $driver_dir is not writable; install as root:" >&2
    printf '  sudo install -m 0644 %s %s\n' \
        "$(quote "$plugin")" "$(quote "$installed")" >&2
    exit 1
fi

install -m 0644 "$plugin" "$installed"
echo "installed $installed"
echo "remove it with: rm -f $(quote "$installed")"
