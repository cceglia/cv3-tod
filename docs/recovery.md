# Recovering a wedged sensor

The command interface can be left stuck by an interrupted run. This page is the operator's ladder.
It has one repair step and then stops: the USB `authorized` toggle is the only recovery this
project sanctions. Anything stronger is how a light wedge becomes a deep one.

## Light wedge vs deep wedge

A **light wedge** is a sensor that still enumerates on USB but refuses commands: the bulk-OUT
transfer times out at the start of a session (`0x23`), while EP0 and enumeration are fine. A bulk
endpoint is stuck; the USB stack is healthy.

A **deep wedge** is a sensor that no longer enumerates. The kernel reports it as
`unable to enumerate USB device`, and nothing in software brings it back.

The distinction is the whole reason for this page: the `authorized` toggle repairs a light wedge,
while a reset turns it into a deep wedge, and a deep wedge costs a full power-down.

## The ladder

### 1. The USB `authorized` toggle

This re-enumerates the device without a port reset. Find the sensor's sysfs node first (bus 3,
port 8 on the reference machine; the stable location `cvctl devices` prints is
`vendor 0a5c product 5843 bus 3 port 8`):

```sh
lsusb -d 0a5c:5843
ls /sys/bus/usb/devices/
# expected here: 3-8
```

Then toggle `authorized` off and on:

```sh
echo 0 | sudo tee /sys/bus/usb/devices/3-8/authorized
sleep 2
echo 1 | sudo tee /sys/bus/usb/devices/3-8/authorized
```

Wait for the device to come back (`lsusb -d 0a5c:5843`) and try the command again.

Measured on 2026-09-01 at 17:32:09: the toggle re-enumerated the device fine, with EP0 healthy and
only a bulk endpoint stuck. The evidence is recorded in the project's reference notes; it has not
been re-measured by this driver.

### 2. Nothing stronger — then a power cycle

There is no second command-level step. A wedged-but-enumerating chip recovers on its own once
nothing is driving it. If the toggle does not help, leave it alone and, if it is still stuck,
power the machine fully down. Do not escalate to a port reset or any other USB recovery request:
the SPEC allows the `authorized` toggle and nothing stronger, and this project sanctions only the
toggle.

## Never

- **Never use the port `disable` knob.** `/sys/bus/usb/devices/<port>/disable` is a port reset by
  another name.
- **Never reset the USB device.** No `libusb_reset_device()`, no `usbreset`, no unbind/rebind of
  the port, no `usb_modeswitch` reset.

Measured 2026-09-01, recorded in the project's reference notes: the `authorized` toggle at 17:32:09
re-enumerated the device fine; `libusb_reset_device()` at 17:32:17 killed the BCM58200's USB stack
outright. From 17:32:23 every enumeration returned
`device descriptor read/64, error -110`; the kernel's own `usb usb3-port8: attempt power cycle`
did nothing; by 17:35:07 the port reported `unable to enumerate USB device`. The chip is a soldered
internal device fed from a mainboard rail rather than switchable port VBUS, so nothing but a full
system power-down re-runs its firmware. That is what every "needs a cold boot" has actually been.
These observations are the reference notes', not newly measured here.

## What the driver does on failure

On any failure the core cancels a pending capture with the sessionless `0x68` and then closes the
session handle with the plain `0x04`, before it reports the error. It never resets the USB device
and never touches the port's `disable` knob. A catchable signal during the finger wait takes the
same path: the finger transfer is cancelled, the session is torn down, and `cvctl` exits with the
shell's `128 + signal` status.

What it cannot prevent: an uncatchable `kill -9` mid-capture leaves a capture armed, and a lost
transfer can still wedge the interface. Those are the cases the ladder above is for.
