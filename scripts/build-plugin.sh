#!/bin/sh
# Builds the libfprint TOD plugin, checks that it bound the versioned TOD symbols, and exercises the
# class and open path libfprint and fprintd dereference.
#
# Needs the distribution's TOD headers and library (`libfprint-2-tod-dev`), `libgusb-dev` and a C
# compiler. Run from anywhere; this script finds the repository itself. No root needed.

set -eu

cd "$(dirname "$0")/.."

cargo build -p cv3-tod --release
./scripts/check-tod-link.sh target/release/libcv3_tod.so
./scripts/check-tod-class.sh target/release/libcv3_tod.so
