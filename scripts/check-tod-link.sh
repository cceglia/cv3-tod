#!/bin/sh
# Fails when the plugin binds a TOD symbol to the wrong version.
#
# glibc resolves an unversioned undefined reference to a symbol's *base* version. libfprint's
# versioned exports make that a trap: `fpi_ssm_new_full` has a legacy 4-argument definition at
# @LIBFPRINT_TOD_1.0.0 and the modern 5-argument one at @@LIBFPRINT_TOD_1_1.92, and a plugin that
# silently binds the legacy thunk calls `g_strdup ((char *) 4)` inside `fp_device_open` — a segfault
# in fprintd before any driver code runs. A plugin must therefore LINK against `libfprint-2-tod`
# (`pkg-config --libs libfprint-2-tod-1`, which crates/cv3-tod/build.rs does) rather than only use
# its include path, and the result must be checked.
#
# For every `fpi_*` symbol the plugin imports, this script requires the exact version the library
# exports as its default: unversioned is a failure, and so is any older version such as the legacy
# `@LIBFPRINT_TOD_1.0.0` thunk. It also requires the exported TOD entry point.
#
# Usage: scripts/check-tod-link.sh [path/to/plugin.so]
#   default path: target/release/libcv3_tod.so

set -eu

cd "$(dirname "$0")/.."

plugin=${1:-target/release/libcv3_tod.so}

if [ ! -f "$plugin" ]; then
    echo "error: $plugin not found; run ./scripts/build-plugin.sh first" >&2
    exit 1
fi

libdir=$(pkg-config --variable=libdir libfprint-2-tod-1)
library="$libdir/libfprint-2-tod.so.1"

if [ ! -f "$library" ]; then
    echo "error: $library not found; install libfprint-2-tod1" >&2
    exit 1
fi

if ! nm -D --defined-only "$plugin" | grep -q ' fpi_tod_shared_driver_get_type$'; then
    echo "error: $plugin does not export fpi_tod_shared_driver_get_type" >&2
    nm -D --defined-only "$plugin" >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Only the dynamic symbol table: the static one repeats the same references without a version
# index, and that is not what the loader binds.
dynsyms() {
    readelf -sW "$1" | awk '/Symbol table .*\.dynsym/{dyn=1; next} /^Symbol table/{dyn=0} dyn'
}
dynsyms "$library" > "$work/library"
dynsyms "$plugin" > "$work/plugin"

# `readelf -sW` columns: Num: Value Size Type Bind Vis Ndx Name. Undefined entries have Ndx UND
# and their Name carries the version, as `symbol@LIBFPRINT_TOD_1_1.92`; a default definition in
# the library carries `symbol@@version`.
if ! awk -v plugin="$plugin" '
    FNR == NR {
        # First file: the library. Record the default version of each exported TOD symbol.
        if ($7 == "UND" || $8 !~ /^fpi_/)
            next
        name = $8
        version = ""
        is_default = 0
        if (index($8, "@@") > 0) {
            split($8, parts, "@@")
            name = parts[1]
            version = parts[2]
            is_default = 1
        } else if (index($8, "@") > 0) {
            split($8, parts, "@")
            name = parts[1]
            version = parts[2]
        } else {
            next
        }
        if (is_default || !(name in expected))
            expected[name] = version
        next
    }
    $7 == "UND" && $8 ~ /^fpi_/ {
        name = $8
        version = ""
        if (index($8, "@") > 0) {
            split($8, parts, "@")
            name = parts[1]
            version = parts[2]
        }
        if (!(name in expected)) {
            printf "error: %s imports %s, which libfprint-2-tod does not define\n", plugin, name > "/dev/stderr"
            failed = 1
        } else if (version == "") {
            printf "error: %s imports %s unversioned; want @%s\n", plugin, $8, expected[name] > "/dev/stderr"
            failed = 1
        } else if (version != expected[name]) {
            printf "error: %s binds %s@%s; want @%s (legacy thunk)\n", plugin, name, version, expected[name] > "/dev/stderr"
            failed = 1
        }
        next
    }
    END { exit failed }
' "$work/library" "$work/plugin"; then
    exit 1
fi

echo "TOD link check passed for $plugin"
# The versioned references, for the record.
dynsyms "$plugin" | awk '$7 == "UND" && $8 ~ /^fpi_/ { print "  " $8 }'
