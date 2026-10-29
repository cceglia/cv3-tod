#!/bin/sh
# Removes the plugin: one shared object, nothing else.
#
# This script never runs sudo. Without write access to the TOD drivers directory it prints the
# exact command to run as root, with the path quoted for pasting.
#
# Usage: scripts/uninstall-plugin.sh
# Override the destination directory with CV3_TOD_DIR; a relative value is resolved against the
# directory you run the script from.

set -eu

caller_dir=$(pwd)
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/tod-lib.sh"

driver_dir=$(tod_dir)
installed=$driver_dir/$tod_plugin_name

if [ ! -e "$installed" ]; then
    echo "not installed: $installed"
    exit 0
fi

if [ ! -w "$driver_dir" ]; then
    echo "error: $driver_dir is not writable; remove it as root:" >&2
    printf '  sudo rm -f %s\n' "$(quote "$installed")" >&2
    exit 1
fi

rm -f "$installed"
echo "removed $installed"
