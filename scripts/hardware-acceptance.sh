#!/usr/bin/env bash
#
# Hardware acceptance for tickets 01-08 of spec 0001-cv3-driver.
#
# Run as root, with the sensor free (stop fprintd first):
#
#     sudo ./scripts/hardware-acceptance.sh
#
# Every step prints PASS or FAIL against the exit code the ticket expects. The full transcript is
# written under target/, so it can be attached to the ticket comments. Nothing here resets the USB
# device, writes the port's disable knob, or touches fprintd's configuration.

set -u

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN="$REPO_ROOT/target/debug/cvctl"
LOG="$REPO_ROOT/target/hardware-acceptance-$(date +%Y%m%d-%H%M%S).log"

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo $0" >&2
    exit 1
fi
if [ ! -x "$BIN" ]; then
    echo "build the probe first: cargo build" >&2
    exit 1
fi

mkdir -p "$REPO_ROOT/target"
exec > >(tee -a "$LOG") 2>&1

pass=0
fail=0
failures=()

say() { printf '\n== %s\n' "$*"; }
pause() {
    printf '\n%s\nPress Enter when ready... ' "$*"
    read -r _
}

run() { # name expected-exit args...
    local name=$1 expected=$2
    shift 2
    say "$name"
    "$BIN" "$@"
    local code=$?
    if [ "$code" -eq "$expected" ]; then
        printf 'PASS %s (exit %d)\n' "$name" "$code"
        pass=$((pass + 1))
    else
        printf 'FAIL %s (exit %d, expected %d)\n' "$name" "$code" "$expected"
        fail=$((fail + 1))
        failures+=("$name")
    fi
}

printf 'cv3 hardware acceptance\nbinary: %s\nlog:    %s\n' "$BIN" "$LOG"

if systemctl is-active --quiet fprintd 2>/dev/null; then
    say "fprintd is running"
    printf 'Stop it before the probe can claim the sensor: sudo systemctl stop fprintd\n'
    printf 'The devices step below should then report busy (exit 3); the rest need it stopped.\n'
    pause "Press Enter once fprintd is stopped, or to run the steps anyway"
else
    say "fprintd is not running (good)"
fi

# --- 01: discovery, layout, release -----------------------------------------------------------
run "01 devices (sensor present)" 0 devices

# --- 02: handshake, fresh keypair -------------------------------------------------------------
say "02 handshake twice: the host public key must differ"
h1=$("$BIN" handshake 2>&1)
c1=$?
h2=$("$BIN" handshake 2>&1)
c2=$?
printf '%s\n' "$h1" "$h2"
k1=$(printf '%s\n' "$h1" | awk '/^host public key /{print $4}')
k2=$(printf '%s\n' "$h2" | awk '/^host public key /{print $4}')
if [ "$c1" -eq 0 ] && [ "$c2" -eq 0 ] && [ -n "$k1" ] && [ "$k1" != "$k2" ]; then
    printf 'PASS 02 handshake twice, fresh host key (exit 0/0)\n'
    pass=$((pass + 1))
else
    printf 'FAIL 02 handshake twice (exit %d/%d, keys %s/%s)\n' "$c1" "$c2" "${k1:-missing}" "${k2:-missing}"
    fail=$((fail + 1))
    failures+=("02 handshake twice")
fi
run "02 handshake --show-key" 0 handshake --show-key

# --- 03: open and close -----------------------------------------------------------------------
run "03 open" 0 open
run "03 close" 0 close
run "03 open after close (not 'already open')" 0 open
run "03 open --bad-sequence (sequence error)" 5 open --bad-sequence

# --- 05: capture ------------------------------------------------------------------------------
pause "05 capture: TOUCH the sensor once it starts waiting"
run "05 capture with a finger (sample hash)" 0 capture

say "05 capture timeout: do NOT touch the sensor; this waits for the finger timeout"
pause "Press Enter, then keep away from the sensor"
run "05 capture without a finger (finger timeout)" 8 capture

# --- 06: enrolment ----------------------------------------------------------------------------
say "06 enroll: this stores a real template. Touch the sensor each time it asks."
pause "Press Enter, then follow the progress lines"
run "06 enroll" 0 enroll

# --- 07: verification -------------------------------------------------------------------------
pause "07 verify: place the ENROLLED finger on the sensor"
run "07 verify enrolled finger (match)" 0 verify

pause "07 verify: place an UNENROLLED finger on the sensor"
run "07 verify unenrolled finger (no match)" 9 verify

# --- 08: cancel then verify, and signal cancellation -----------------------------------------
pause "08 cancel-then-verify: the run arms and cancels a capture, then asks for the enrolled finger"
run "08 cancel-then-verify" 0 cancel-then-verify

say "08 SIGINT during the finger wait: do NOT touch the sensor"
"$BIN" capture &
pid=$!
sleep 2
kill -INT "$pid" 2>/dev/null
wait "$pid"
code=$?
if [ "$code" -eq 130 ]; then
    printf 'PASS 08 SIGINT during capture (exit 130)\n'
    pass=$((pass + 1))
else
    printf 'FAIL 08 SIGINT during capture (exit %d, expected 130)\n' "$code"
    fail=$((fail + 1))
    failures+=("08 SIGINT during capture")
fi
run "08 devices after the interrupted capture (sensor usable)" 0 devices

# --- 09 tooling: enrol, then confirm and match in the same session -----------------------------
if "$BIN" 2>&1 | grep -q "enroll-then-verify"; then
    pause "09 enroll-then-verify: touch through enrolment, then the confirmation touch"
    run "09 enroll-then-verify" 0 enroll-then-verify
else
    say "09 enroll-then-verify is not in this build; skipped"
fi

# --- summary ----------------------------------------------------------------------------------
printf '\n==================== summary ====================\n'
printf 'passed: %d\nfailed: %d\n' "$pass" "$fail"
if [ "$fail" -ne 0 ]; then
    printf 'failed steps:\n'
    printf '  - %s\n' "${failures[@]}"
fi
printf 'transcript: %s\n' "$LOG"

if [ "$fail" -ne 0 ]; then
    exit 1
fi
