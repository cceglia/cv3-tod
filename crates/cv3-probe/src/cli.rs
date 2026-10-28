//! `cvctl`'s command line: argument handling, output streams and exit status.
//!
//! The command is deliberately small: it parses one subcommand, runs the probe and maps the
//! outcome onto the documented exit codes. Everything observable is a return value or a line on
//! one of the two streams, which is what the tests assert.

use std::io::Write;

use cv3_core::handshake::Handshake;

use crate::discovery::{ProbeError, UsbBackend, open_for_command, probe};
use crate::driver::{NoFingerWait, run as drive};
use crate::random::RunSecrets;
use crate::signals::Shutdown;

/// The sensor was found, opened and released.
pub const EXIT_OK: u8 = 0;
/// Any error without its own code, including a bad usage line.
pub const EXIT_OTHER: u8 = 1;

const USAGE: &str = "usage: cvctl devices
       cvctl handshake [--show-key]";

/// Runs one invocation and returns its exit status.
///
/// The caller supplies the streams, so tests see exactly what a user would.
pub fn run(
    args: &[String],
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    match args {
        [command] if command == "devices" => match probe(backend, shutdown) {
            Ok(outcome) => {
                let _ = writeln!(out, "{}", outcome.sensor.location());
                EXIT_OK
            }
            Err(error) => {
                report(&error, err);
                error.exit_code()
            }
        },
        [command] if command == "handshake" => handshake(backend, shutdown, false, out, err),
        [command, flag] if command == "handshake" && flag == "--show-key" => {
            handshake(backend, shutdown, true, out, err)
        }
        _ => {
            let _ = writeln!(err, "{USAGE}");
            EXIT_OTHER
        }
    }
}

/// Runs one `0x23` / `0x24` handshake and prints what it learned.
fn handshake(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    show_key: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let mut channel = match open_for_command(backend, shutdown) {
        Ok(channel) => channel,
        Err(error) => {
            report(&error, err);
            return error.exit_code();
        }
    };

    // The host keypair is fresh for every invocation and is never stored.
    let secrets = match RunSecrets::generate() {
        Ok(secrets) => secrets,
        Err(error) => {
            let _ = writeln!(err, "cvctl: {error}");
            return EXIT_OTHER;
        }
    };

    let host_public = secrets.host_key.public_key();
    let mut operation = Handshake::new(secrets.client_nonce, secrets.host_key, secrets.host_nonce);
    let outcome = {
        let mut exchange = channel.exchange();
        drive(&mut exchange, &mut operation, &mut NoFingerWait)
    };

    match outcome {
        Ok(session) => {
            let _ = writeln!(out, "handle {:#010x}", session.handle);
            let _ = writeln!(out, "client nonce {} bytes", session.client_nonce_len);
            let _ = writeln!(out, "device nonce {} bytes", session.device_nonce_len);
            let _ = writeln!(out, "host nonce {} bytes", session.host_nonce_len);
            let _ = writeln!(out, "host public key {}", hex(&host_public));
            let _ = writeln!(out, "key fingerprint {}", hex(&session.key().fingerprint()));
            if show_key {
                let _ = writeln!(out, "key {}", hex(session.key().as_bytes()));
            }
            EXIT_OK
        }
        Err(error) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            EXIT_OTHER
        }
    }
}

/// Formats bytes as lowercase hex without pulling in a formatting dependency.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Formats a probe failure on stderr. Its status decides the exit code.
fn report(error: &ProbeError, err: &mut dyn Write) {
    let _ = writeln!(err, "cvctl: {error}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use cv3_core::frame;
    use cv3_core::proto::{attr, cmd};

    use crate::discovery::UsbError;
    use crate::layout::{EndpointDescriptor, TransferType};
    use crate::signals::SignalFlag;
    use crate::testing::{FakeUsb, TEST_HANDLE, sensor};

    fn run_with(args: &[&str], usb: &mut FakeUsb, shutdown: &dyn Shutdown) -> (u8, String, String) {
        let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args, usb, shutdown, &mut out, &mut err);
        (
            code,
            String::from_utf8(out).expect("stdout is UTF-8"),
            String::from_utf8(err).expect("stderr is UTF-8"),
        )
    }

    fn command(frame: &[u8]) -> u16 {
        u16::from_le_bytes([frame[8], frame[9]])
    }

    fn sent_command(usb: &FakeUsb, wanted: u16) -> Option<Vec<u8>> {
        usb.sent
            .borrow()
            .iter()
            .find(|frame| command(frame) == wanted)
            .cloned()
    }

    fn host_public_key(usb: &FakeUsb) -> Vec<u8> {
        let frame = sent_command(usb, cmd::CHALLENGE_RESPONSE).expect("0x24 was sent");
        frame[44 + 20..44 + 84].to_vec()
    }

    #[test]
    fn devices_prints_one_stable_line_and_succeeds() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["devices"], &mut usb, &shutdown);

        assert_eq!(code, 0);
        assert_eq!(out, "vendor 0a5c product 5843 bus 3 port 8\n");
        assert_eq!(err, "");
        assert_eq!(out.lines().count(), 1, "exactly one line");
    }

    #[test]
    fn an_absent_sensor_is_reported_as_not_found_and_exits_two() {
        let mut usb = FakeUsb::default();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["devices"], &mut usb, &shutdown);

        assert_eq!(code, 2);
        assert_eq!(out, "");
        assert_eq!(err, "cvctl: sensor 0a5c:5843 not found\n");
    }

    #[test]
    fn a_held_sensor_is_reported_as_busy_with_its_own_code() {
        let mut usb = FakeUsb::with_sensor();
        usb.claim_error = Some(UsbError::Busy);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["devices"], &mut usb, &shutdown);

        assert_eq!(code, 3);
        assert_eq!(out, "");
        assert!(err.contains("busy"), "message names the busy state: {err}");
        assert_eq!(
            usb.calls(),
            ["enumerate", "open", "claim", "close"],
            "a failed claim is never released or probed further"
        );
    }

    #[test]
    fn a_permission_failure_is_distinct_from_busy_and_exits_four() {
        let mut usb = FakeUsb::with_sensor();
        usb.open_error = Some(UsbError::PermissionDenied);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["devices"], &mut usb, &shutdown);

        assert_eq!(code, 4);
        assert_eq!(out, "");
        assert!(
            err.contains("permission denied"),
            "message names the permission problem: {err}"
        );
        assert_eq!(
            usb.calls(),
            ["enumerate", "open"],
            "nothing is claimed when opening is refused"
        );

        let mut busy = FakeUsb::with_sensor();
        busy.claim_error = Some(UsbError::Busy);
        let (_, _, busy_err) = run_with(&["devices"], &mut busy, &shutdown);
        assert_ne!(err, busy_err, "busy and permission are told apart");
    }

    #[test]
    fn a_wrong_descriptor_is_an_ordinary_error_with_a_clear_message() {
        let mut usb = FakeUsb::with_sensor();
        usb.descriptor.endpoints.push(EndpointDescriptor {
            address: 0x02,
            transfer: TransferType::Bulk,
        });
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["devices"], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(
            err.contains("unexpected interface layout"),
            "message names the layout problem: {err}"
        );
        assert_eq!(
            usb.calls(),
            [
                "enumerate",
                "open",
                "claim",
                "descriptor",
                "release",
                "close"
            ]
        );
    }

    #[test]
    fn two_sensors_are_reported_rather_than_one_chosen_silently() {
        let mut usb = FakeUsb::with_sensor();
        usb.devices.push(sensor());
        let shutdown = SignalFlag::new();

        let (code, _, err) = run_with(&["devices"], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert!(err.contains("expected exactly one"), "{err}");
    }

    #[test]
    fn an_interrupt_releases_and_exits_with_the_signal_status() {
        let mut usb = FakeUsb::with_sensor();
        let flag = SignalFlag::new();
        usb.signal_after_descriptor = Some(flag.clone());

        let (code, out, err) = run_with(&["devices"], &mut usb, &flag);

        assert_eq!(code, 130, "SIGINT follows the shell convention");
        assert_eq!(out, "");
        assert!(err.contains("interrupted by signal 2"), "{err}");
        assert_eq!(
            usb.calls(),
            [
                "enumerate",
                "open",
                "claim",
                "descriptor",
                "release",
                "close"
            ]
        );
    }

    #[test]
    fn an_unknown_subcommand_prints_usage_and_fails() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enrol"], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert_eq!(err, format!("{USAGE}\n"));
        assert!(usb.calls().is_empty(), "nothing touches the sensor");
    }

    #[test]
    fn a_missing_subcommand_prints_usage_and_fails() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&[], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert_eq!(err, format!("{USAGE}\n"));
    }

    #[test]
    fn a_trailing_argument_is_rejected_rather_than_ignored() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, _, err) = run_with(&["devices", "now"], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(err, format!("{USAGE}\n"));
    }

    #[test]
    fn handshake_prints_the_handle_nonce_lengths_and_key_fingerprint() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["handshake"], &mut usb, &shutdown);

        assert_eq!(code, 0, "{err}");
        assert_eq!(err, "");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 6, "no raw key without the flag: {out}");
        assert_eq!(lines[0], format!("handle {TEST_HANDLE:#010x}"));
        assert_eq!(lines[1], "client nonce 20 bytes");
        assert_eq!(lines[2], "device nonce 20 bytes");
        assert_eq!(lines[3], "host nonce 20 bytes");
        let host = lines[4]
            .strip_prefix("host public key ")
            .expect("host public key line");
        assert_eq!(host.len(), 128, "uncompressed P-256 public key in hex");
        assert!(host.bytes().all(|b| b.is_ascii_hexdigit()));
        let fingerprint = lines[5]
            .strip_prefix("key fingerprint ")
            .expect("fingerprint line");
        assert_eq!(fingerprint.len(), 16);
        assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));

        let close = sent_command(&usb, cmd::CLOSE_SESSION).expect("success closes the handle");
        assert_eq!(close[11], 0x04, "close encoding");
        assert_eq!(
            &close[44..],
            &[0, 0, 0, 0, 4, 0, 0, 0, 0x44, 0x33, 0x22, 0x11]
        );
    }

    #[test]
    fn the_raw_key_is_printed_only_with_the_explicit_flag() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["handshake", "--show-key"], &mut usb, &shutdown);

        assert_eq!(code, 0, "{err}");
        assert_eq!(err, "");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 7);
        let raw = lines[6].strip_prefix("key ").expect("raw key line");
        assert_eq!(raw.len(), 32);
        assert!(raw.bytes().all(|b| b.is_ascii_hexdigit()));
        let fingerprint = lines[5]
            .strip_prefix("key fingerprint ")
            .expect("fingerprint");
        assert_ne!(fingerprint, raw, "the fingerprint is not the key");
    }

    #[test]
    fn each_run_generates_a_fresh_host_keypair() {
        let shutdown = SignalFlag::new();
        let mut first = FakeUsb::with_sensor();
        let mut second = FakeUsb::with_sensor();

        let (first_code, first_out, _) = run_with(&["handshake"], &mut first, &shutdown);
        let (second_code, second_out, _) = run_with(&["handshake"], &mut second, &shutdown);
        assert_eq!(first_code, 0, "first run");
        assert_eq!(second_code, 0, "second run");

        let printed = |text: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix("host public key "))
                .expect("host public key line")
                .to_owned()
        };
        assert_ne!(
            printed(&first_out),
            printed(&second_out),
            "the probe prints a different host key every run"
        );
        assert_ne!(
            host_public_key(&first),
            host_public_key(&second),
            "the sensor accepts a fresh ephemeral host key every run"
        );
        assert_eq!(host_public_key(&first).len(), 64);
    }

    #[test]
    fn a_rejected_challenge_is_reported_as_its_own_failure() {
        let mut usb = FakeUsb::with_sensor();
        usb.challenge_status = 0x0c;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["handshake"], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.contains("0x23 challenge"), "{err}");
        assert!(err.contains("0x0c"), "{err}");
        assert!(
            sent_command(&usb, cmd::CLOSE_SESSION).is_none(),
            "no handle was learned, so there is nothing to close"
        );
    }

    #[test]
    fn a_short_challenge_reply_is_reported_as_its_own_failure() {
        let mut usb = FakeUsb::with_sensor();
        usb.challenge_body = Some(frame::build_plain(
            cmd::CHALLENGE,
            attr::CHALLENGE,
            TEST_HANDLE,
            &[],
        ));
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["handshake"], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.contains("reply is 44 bytes, needs 192"), "{err}");
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_none());
    }

    #[test]
    fn a_status_error_on_the_response_is_reported_and_the_handle_closed() {
        let mut usb = FakeUsb::with_sensor();
        usb.response_status = 0x0a;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["handshake"], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.contains("0x24 response"), "{err}");
        assert!(err.contains("0x0a"), "{err}");
        assert!(
            sent_command(&usb, cmd::CLOSE_SESSION).is_some(),
            "the allocated handle is released before reporting the failure"
        );
    }
}
