#!/bin/sh
# Mechanical checks for the I/O-free, unsafe-free protocol core (SPEC "Dependencies").
#
# The core may depend only on the pinned pure-Rust crypto set listed below, and its source may
# contain no `unsafe` token other than the crate-level `forbid` attribute. Both are compile-time
# claims in the SPEC, so they are checked here rather than assumed.

set -eu

cd "$(dirname "$0")/.."

expected_deps='aes
cbc
hmac
p256
sha1
sha2
zeroize'

actual_deps=$(
    cargo tree -p cv3-core --edges normal --depth 1 --prefix none \
        | tail -n +2 \
        | cut -d' ' -f1 \
        | LC_ALL=C sort
)

if [ "$actual_deps" != "$expected_deps" ]; then
    printf '%s\n' \
        "error: cv3-core's direct dependencies are not the pinned crypto set" \
        "expected:" "$expected_deps" \
        "actual:" "$actual_deps" >&2
    exit 1
fi

normal_tree=$(cargo tree -p cv3-core --edges normal --prefix none)
transport_deps=$(
    printf '%s\n' "$normal_tree" \
        | grep -E '^(nusb|rusb|libusb|usb|serialport|nix) v' \
        | cut -d' ' -f1 \
        | LC_ALL=C sort -u \
        || true
)

if [ -n "$transport_deps" ]; then
    printf '%s\n' \
        "error: cv3-core's normal dependency tree contains a transport crate:" \
        "$transport_deps" >&2
    exit 1
fi

# Strip // line and doc comments before looking for the token, so prose that mentions `unsafe`
# does not fail the check. The crate-level attribute is allowed; anything else is not.
unsafe_tokens=$(
    grep -RIn --include='*.rs' '' crates/cv3-core/src \
        | sed 's://.*::' \
        | grep -E '(^|[^[:alnum:]_])unsafe([^[:alnum:]_]|$)' \
        | grep -v ':#!\[forbid(unsafe_code)\]$' \
        || true
)

if [ -n "$unsafe_tokens" ]; then
    printf '%s\n' \
        "error: unsafe code in crates/cv3-core/src (only #![forbid(unsafe_code)] is allowed):" \
        "$unsafe_tokens" >&2
    exit 1
fi

printf '%s\n' "core checks passed"
