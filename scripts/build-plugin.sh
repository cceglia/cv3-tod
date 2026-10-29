#!/bin/sh
# Builds the libfprint TOD plugin and checks that it bound the versioned TOD symbols.
#
# Needs the distribution's TOD headers and library (`libfprint-2-tod-dev`) and a C compiler.
# Run from anywhere; this script finds the repository itself. No root needed.

set -eu

cd "$(dirname "$0")/.."

cargo build -p cv3-tod --release
./scripts/check-tod-link.sh target/release/libcv3_tod.so
