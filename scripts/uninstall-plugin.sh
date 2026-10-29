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

tod_dir=${CV3_TOD_DIR:-"$(pkg-config --variable=libdir libfprint-2-tod-1)/libfprint-2/tod-1"}
case $tod_dir in
/*) ;;
*) tod_dir=$(pwd)/$tod_dir ;;
esac
installed=$tod_dir/libfprint-2-tod-1-cv3.so

# Prints an argument shell-quoted, for a command the reader pastes into a root shell.
quote() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

if [ ! -e "$installed" ]; then
    echo "not installed: $installed"
    exit 0
fi

if [ ! -w "$tod_dir" ]; then
    echo "error: $tod_dir is not writable; remove it as root:" >&2
    printf '  sudo rm -f %s\n' "$(quote "$installed")" >&2
    exit 1
fi

rm -f "$installed"
echo "removed $installed"
