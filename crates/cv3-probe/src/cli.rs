//! `cvctl`'s command line: argument handling, output streams and exit status.
//!
//! The command is deliberately small: it parses one subcommand, runs the probe and maps the
//! outcome onto the documented exit codes. Everything observable is a return value or a line on
//! one of the two streams, which is what the tests assert.
//!
//! Recording wraps the same transport an ordinary run uses, so a real session becomes a transcript
//! file with no second code path. Replay drives a fresh operation over that transcript with no
//! hardware at all.

use std::io::Write;

use cv3_core::handshake::{Handshake, HandshakeError};
use cv3_core::session::{CloseError, CloseSession, OpenError, OpenSession, Session};
use cv3_core::transcript::{RecordingTransport, ReplayTransport, Transcript};
use cv3_core::transport::{Transport, run as drive};

use crate::discovery::{CommandSession, ProbeError, UsbBackend, open_for_command, probe};
use crate::random::{RandomError, RunSecrets, random_iv};
use crate::signals::Shutdown;

/// The sensor was found, opened and released.
pub const EXIT_OK: u8 = 0;
/// Any error without its own code, including a bad usage line.
pub const EXIT_OTHER: u8 = 1;
/// The sensor refused the wrap sequence (`0x0F`); distinct so a probe run can tell it apart.
pub const EXIT_SEQUENCE: u8 = 5;
/// A replay stopped matching its transcript; distinct from a replay that reproduced a failure.
pub const EXIT_DIVERGED: u8 = 6;

const USAGE: &str = "usage: cvctl devices
       cvctl handshake [--show-key] [--record <file>]
       cvctl open [--bad-sequence] [--record <file>]
       cvctl close [--record <file>]
       cvctl replay <file>";

/// One parsed invocation.
enum Command<'a> {
    Devices,
    Handshake {
        show_key: bool,
        record: Option<&'a str>,
    },
    Open {
        bad_sequence: bool,
        record: Option<&'a str>,
    },
    Close {
        record: Option<&'a str>,
    },
    Replay {
        file: &'a str,
    },
}

/// The flags one subcommand accepts.
struct Flags<'a> {
    show_key: bool,
    bad_sequence: bool,
    record: Option<&'a str>,
}

/// Parses the command line by hand: no dependency, and every unknown or repeated flag is a usage
/// error rather than something silently ignored.
fn parse(args: &[String]) -> Option<Command<'_>> {
    let (command, rest) = args.split_first()?;
    match command.as_str() {
        "devices" if rest.is_empty() => Some(Command::Devices),
        "handshake" => {
            let flags = parse_flags(rest, true, false, true)?;
            Some(Command::Handshake {
                show_key: flags.show_key,
                record: flags.record,
            })
        }
        "open" => {
            let flags = parse_flags(rest, false, true, true)?;
            Some(Command::Open {
                bad_sequence: flags.bad_sequence,
                record: flags.record,
            })
        }
        "close" => {
            let flags = parse_flags(rest, false, false, true)?;
            Some(Command::Close {
                record: flags.record,
            })
        }
        "replay" => match rest {
            [file] => Some(Command::Replay { file }),
            _ => None,
        },
        _ => None,
    }
}

fn parse_flags<'a>(
    args: &'a [String],
    allow_show_key: bool,
    allow_bad_sequence: bool,
    allow_record: bool,
) -> Option<Flags<'a>> {
    let mut flags = Flags {
        show_key: false,
        bad_sequence: false,
        record: None,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--show-key" if allow_show_key && !flags.show_key => flags.show_key = true,
            "--bad-sequence" if allow_bad_sequence && !flags.bad_sequence => {
                flags.bad_sequence = true;
            }
            "--record" if allow_record && flags.record.is_none() => {
                index += 1;
                flags.record = Some(args.get(index)?.as_str());
            }
            _ => return None,
        }
        index += 1;
    }
    Some(flags)
}

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
    match parse(args) {
        Some(Command::Devices) => devices(backend, shutdown, out, err),
        Some(Command::Handshake { show_key, record }) => {
            handshake(backend, shutdown, show_key, record, out, err)
        }
        Some(Command::Open {
            bad_sequence,
            record,
        }) => open(backend, shutdown, bad_sequence, record, out, err),
        Some(Command::Close { record }) => close(backend, shutdown, record, out, err),
        Some(Command::Replay { file }) => replay(file, out, err),
        None => {
            let _ = writeln!(err, "{USAGE}");
            EXIT_OTHER
        }
    }
}

fn devices(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    match probe(backend, shutdown) {
        Ok(outcome) => {
            let _ = writeln!(out, "{}", outcome.sensor.location());
            EXIT_OK
        }
        Err(error) => {
            report(&error, err);
            error.exit_code()
        }
    }
}

/// A completed handshake and the derivative the caller prints.
struct HandshakeRun {
    session: Session,
    host_public: [u8; 64],
}

/// Runs the handshake over any transport, keeping the handle only when asked.
fn handshake_over(
    transport: &mut dyn Transport,
    secrets: RunSecrets,
    keep_handle: bool,
) -> Result<HandshakeRun, HandshakeError> {
    let host_public = secrets.host_key.public_key();
    let mut operation = Handshake::new(secrets.client_nonce, secrets.host_key, secrets.host_nonce);
    if keep_handle {
        operation = operation.keeping_handle();
    }
    let session = drive(&mut operation, transport)?;
    Ok(HandshakeRun {
        session,
        host_public,
    })
}

/// Where an open run stopped.
enum OpenFailure {
    Handshake(HandshakeError),
    Open(OpenError),
}

/// Opens the wrapped session and closes it again, exactly as one `cvctl open` invocation does.
fn open_over(
    transport: &mut dyn Transport,
    secrets: RunSecrets,
    iv: [u8; cv3_core::crypto::BLOCK_LEN],
    bad_sequence: bool,
) -> Result<(u32, Result<(), CloseError>), OpenFailure> {
    let run = handshake_over(transport, secrets, true).map_err(OpenFailure::Handshake)?;
    let mut operation = OpenSession::new(run.session, iv);
    if bad_sequence {
        operation = operation.at_sequence(1);
    }
    match drive(&mut operation, transport) {
        Ok(session) => {
            let handle = session.handle;
            drop(session);
            let mut close = CloseSession::new(handle);
            Ok((handle, drive(&mut close, transport)))
        }
        Err(error) => Err(OpenFailure::Open(error)),
    }
}

/// Where a close run stopped.
enum CloseFailure {
    Handshake(HandshakeError),
    Close(CloseError),
}

/// Runs the handshake, keeps its handle, then closes that handle.
fn close_over(transport: &mut dyn Transport, secrets: RunSecrets) -> Result<(), CloseFailure> {
    let run = handshake_over(transport, secrets, true).map_err(CloseFailure::Handshake)?;
    let mut operation = CloseSession::new(run.session.handle);
    drop(run.session);
    drive(&mut operation, transport).map_err(CloseFailure::Close)
}

/// Wraps the probe's exchange in a recording transport when `record` asks for one.
///
/// The same operation runs either way. A write failure is returned to the caller rather than
/// swallowed: the user asked for a transcript, and a missing one must be visible.
fn with_transport<R>(
    channel: &mut CommandSession,
    command: &str,
    record: Option<&str>,
    run_operation: impl FnOnce(&mut dyn Transport) -> R,
) -> (R, Option<std::io::Error>) {
    match record {
        Some(path) => {
            let mut transport = RecordingTransport::new(channel.exchange(), command);
            let result = run_operation(&mut transport);
            let transcript = transport.into_transcript();
            let error = std::fs::write(path, transcript.to_bytes()).err();
            (result, error)
        }
        None => {
            let mut transport = channel.exchange();
            (run_operation(&mut transport), None)
        }
    }
}

fn finish_recording(error: Option<std::io::Error>, err: &mut dyn Write, code: u8) -> u8 {
    match error {
        Some(error) => {
            let _ = writeln!(err, "cvctl: writing the transcript failed: {error}");
            EXIT_OTHER
        }
        None => code,
    }
}

/// Runs one `0x23` / `0x24` handshake and prints what it learned.
fn handshake(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    show_key: bool,
    record: Option<&str>,
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
    let secrets = match RunSecrets::generate() {
        Ok(secrets) => secrets,
        Err(error) => {
            let _ = writeln!(err, "cvctl: {error}");
            return EXIT_OTHER;
        }
    };

    let (outcome, record_error) = with_transport(&mut channel, "handshake", record, |transport| {
        handshake_over(transport, secrets, false)
    });

    let code = match outcome {
        Ok(run) => {
            let session = run.session;
            let _ = writeln!(out, "handle {:#010x}", session.handle);
            let _ = writeln!(out, "client nonce {} bytes", session.client_nonce_len);
            let _ = writeln!(out, "device nonce {} bytes", session.device_nonce_len);
            let _ = writeln!(out, "host nonce {} bytes", session.host_nonce_len);
            let _ = writeln!(out, "host public key {}", hex(&run.host_public));
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
    };
    finish_recording(record_error, err, code)
}

/// Opens the wrapped `0x02` session, prints the handle, then closes it before exiting.
fn open(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    bad_sequence: bool,
    record: Option<&str>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let iv = match random_iv() {
        Ok(iv) => iv,
        Err(error) => {
            let _ = writeln!(err, "cvctl: {error}");
            return EXIT_OTHER;
        }
    };
    let mut channel = match open_for_command(backend, shutdown) {
        Ok(channel) => channel,
        Err(error) => {
            report(&error, err);
            return error.exit_code();
        }
    };
    let secrets = match RunSecrets::generate() {
        Ok(secrets) => secrets,
        Err(error) => {
            let _ = writeln!(err, "cvctl: {error}");
            return EXIT_OTHER;
        }
    };

    let (outcome, record_error) = with_transport(&mut channel, "open", record, |transport| {
        open_over(transport, secrets, iv, bad_sequence)
    });

    let code = match outcome {
        Ok((handle, closed)) => {
            let _ = writeln!(out, "handle {handle:#010x}");
            let _ = writeln!(out, "secure session open");
            if let Err(error) = closed {
                let _ = writeln!(err, "cvctl: {error}");
            }
            EXIT_OK
        }
        Err(OpenFailure::Handshake(error)) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            EXIT_OTHER
        }
        Err(OpenFailure::Open(error)) => {
            let _ = writeln!(err, "cvctl: {error}");
            if matches!(error, OpenError::WrongSequence) {
                EXIT_SEQUENCE
            } else {
                EXIT_OTHER
            }
        }
    };
    finish_recording(record_error, err, code)
}

/// Closes the secure session the handshake kept open.
fn close(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    record: Option<&str>,
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
    let secrets = match RunSecrets::generate() {
        Ok(secrets) => secrets,
        Err(error) => {
            let _ = writeln!(err, "cvctl: {error}");
            return EXIT_OTHER;
        }
    };

    let (outcome, record_error) = with_transport(&mut channel, "close", record, |transport| {
        close_over(transport, secrets)
    });

    let code = match outcome {
        Ok(()) => {
            let _ = writeln!(out, "secure session closed");
            EXIT_OK
        }
        Err(CloseFailure::Handshake(error)) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            EXIT_OTHER
        }
        Err(CloseFailure::Close(error)) => {
            let _ = writeln!(err, "cvctl: {error}");
            EXIT_OTHER
        }
    };
    finish_recording(record_error, err, code)
}

/// What a replay run produced.
enum ReplayOutcome {
    Random(RandomError),
    Handshake(Result<Session, HandshakeError>),
    Open(Result<(u32, Result<(), CloseError>), OpenFailure>),
    Close(Result<(), CloseFailure>),
}

fn replay_handshake(transport: &mut ReplayTransport) -> ReplayOutcome {
    match RunSecrets::generate() {
        Ok(secrets) => ReplayOutcome::Handshake(
            handshake_over(transport, secrets, false).map(|run| run.session),
        ),
        Err(error) => ReplayOutcome::Random(error),
    }
}

fn replay_open(transport: &mut ReplayTransport) -> ReplayOutcome {
    let secrets = match RunSecrets::generate() {
        Ok(secrets) => secrets,
        Err(error) => return ReplayOutcome::Random(error),
    };
    let iv = match random_iv() {
        Ok(iv) => iv,
        Err(error) => return ReplayOutcome::Random(error),
    };
    ReplayOutcome::Open(open_over(transport, secrets, iv, false))
}

fn replay_close(transport: &mut ReplayTransport) -> ReplayOutcome {
    match RunSecrets::generate() {
        Ok(secrets) => ReplayOutcome::Close(close_over(transport, secrets)),
        Err(error) => ReplayOutcome::Random(error),
    }
}

/// Replays a recorded invocation with no hardware.
fn replay(file: &str, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let bytes = match std::fs::read(file) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = writeln!(err, "cvctl: cannot read transcript {file}: {error}");
            return EXIT_OTHER;
        }
    };
    let transcript = match Transcript::from_bytes(&bytes) {
        Ok(transcript) => transcript,
        Err(error) => {
            let _ = writeln!(err, "cvctl: invalid transcript {file}: {error}");
            return EXIT_OTHER;
        }
    };

    let command = transcript.command().to_owned();
    let mut transport = ReplayTransport::new(transcript);
    let outcome = match command.as_str() {
        "handshake" => replay_handshake(&mut transport),
        "open" => replay_open(&mut transport),
        "close" => replay_close(&mut transport),
        other => {
            let _ = writeln!(err, "cvctl: transcript records unknown command {other:?}");
            return EXIT_OTHER;
        }
    };

    // Divergence wins over the operation's own result: the operation ran against bytes that did
    // not match the recording, so its answer is not a replay of anything.
    if let Err(divergence) = transport.finish() {
        let _ = writeln!(
            err,
            "cvctl: replay diverged from the transcript: {divergence}"
        );
        return EXIT_DIVERGED;
    }

    report_replay(outcome, out, err)
}

fn report_replay(outcome: ReplayOutcome, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    match outcome {
        ReplayOutcome::Random(error) => {
            let _ = writeln!(err, "cvctl: {error}");
            EXIT_OTHER
        }
        ReplayOutcome::Handshake(Ok(session)) => {
            let _ = writeln!(out, "handle {:#010x}", session.handle);
            let _ = writeln!(out, "client nonce {} bytes", session.client_nonce_len);
            let _ = writeln!(out, "device nonce {} bytes", session.device_nonce_len);
            let _ = writeln!(out, "host nonce {} bytes", session.host_nonce_len);
            let _ = writeln!(
                out,
                "note: replay uses a fresh host keypair; the session key fingerprint differs from \
                 the recording"
            );
            EXIT_OK
        }
        ReplayOutcome::Handshake(Err(error)) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            EXIT_OTHER
        }
        ReplayOutcome::Open(Ok((handle, closed))) => {
            let _ = writeln!(out, "handle {handle:#010x}");
            let _ = writeln!(out, "secure session open");
            if let Err(error) = closed {
                let _ = writeln!(err, "cvctl: {error}");
            }
            EXIT_OK
        }
        ReplayOutcome::Open(Err(OpenFailure::Handshake(error))) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            EXIT_OTHER
        }
        ReplayOutcome::Open(Err(OpenFailure::Open(error))) => {
            let _ = writeln!(err, "cvctl: {error}");
            if matches!(error, OpenError::WrongSequence) {
                EXIT_SEQUENCE
            } else {
                EXIT_OTHER
            }
        }
        ReplayOutcome::Close(Ok(())) => {
            let _ = writeln!(out, "secure session closed");
            EXIT_OK
        }
        ReplayOutcome::Close(Err(CloseFailure::Handshake(error))) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            EXIT_OTHER
        }
        ReplayOutcome::Close(Err(CloseFailure::Close(error))) => {
            let _ = writeln!(err, "cvctl: {error}");
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
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use cv3_core::frame;
    use cv3_core::proto::{attr, cmd};
    use cv3_core::transcript::TranscriptRecord;

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

    /// A unique, not-yet-created path under the system temporary directory.
    struct TempRecord(PathBuf);

    impl TempRecord {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let count = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "cv3-{label}-{}-{count}-{nanos}.cvrec",
                std::process::id()
            ));
            Self(path)
        }

        fn path(&self) -> &str {
            self.0.to_str().expect("the temporary path is UTF-8")
        }

        fn write(&self, bytes: &[u8]) {
            std::fs::write(&self.0, bytes).expect("the temporary transcript is writable");
        }

        fn exists(&self) -> bool {
            Path::exists(&self.0)
        }
    }

    impl Drop for TempRecord {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
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
    fn a_record_flag_without_a_path_is_a_usage_error() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["handshake", "--record"], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert_eq!(err, format!("{USAGE}\n"));
        assert!(usb.calls().is_empty());
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

    #[test]
    fn open_prints_the_handle_opens_the_session_and_closes_it() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["open"], &mut usb, &shutdown);

        assert_eq!(code, 0, "{err}");
        assert_eq!(err, "");
        assert_eq!(
            out,
            format!("handle {TEST_HANDLE:#010x}\nsecure session open\n")
        );

        let open = sent_command(&usb, cmd::OPEN_SESSION).expect("0x02 was sent");
        assert_eq!(open[11], 0x02, "the open command is wrapped");
        assert_eq!(open[10], attr::SESSION);
        assert_eq!(
            u32::from_le_bytes(open[16..20].try_into().expect("handle field")),
            TEST_HANDLE
        );
        assert_eq!(
            u32::from_le_bytes(open[40..44].try_into().expect("declared length")),
            36,
            "the wrapped open declares its 36-byte TLV block"
        );

        assert!(
            sent_command(&usb, cmd::CLOSE_SESSION).is_some(),
            "the probe closes the session before exiting"
        );
    }

    #[test]
    fn open_reports_a_non_zero_status_and_closes_the_handle() {
        let mut usb = FakeUsb::with_sensor();
        usb.open_status = 0x0c;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["open"], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.contains("0x0c"), "{err}");
        assert!(
            sent_command(&usb, cmd::CLOSE_SESSION).is_some(),
            "the failed open releases the handle before reporting"
        );

        usb.open_status = 0;
        let (code, out, err) = run_with(&["open"], &mut usb, &shutdown);
        assert_eq!(
            code, 0,
            "the next open is not told the session is already open: {err}"
        );
        assert!(out.contains("secure session open"), "{out}");
    }

    #[test]
    fn a_deliberately_wrong_wrap_sequence_is_its_own_failure() {
        let mut usb = FakeUsb::with_sensor();
        usb.open_status = 0x0f;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["open", "--bad-sequence"], &mut usb, &shutdown);

        assert_eq!(code, 5, "the sequence failure has its own exit status");
        assert_eq!(out, "");
        assert!(err.contains("wrap sequence"), "{err}");
        assert!(err.contains("0x0f"), "{err}");
        assert!(
            sent_command(&usb, cmd::CLOSE_SESSION).is_some(),
            "even a rejected open leaves no handle behind"
        );
    }

    #[test]
    fn close_prints_and_a_following_open_succeeds() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["close"], &mut usb, &shutdown);

        assert_eq!(code, 0, "{err}");
        assert_eq!(out, "secure session closed\n");
        assert_eq!(err, "");
        assert!(
            sent_command(&usb, cmd::CLOSE_SESSION).is_some(),
            "0x04 was sent"
        );

        let (code, out, err) = run_with(&["open"], &mut usb, &shutdown);
        assert_eq!(code, 0, "a following open succeeds: {err}");
        assert!(out.contains("secure session open"), "{out}");
    }

    #[test]
    fn an_open_transport_failure_is_reported_and_the_handle_closed() {
        let mut usb = FakeUsb::with_sensor();
        usb.open_command_error = Some(UsbError::Timeout);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["open"], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.contains("timed out"), "{err}");
        assert!(
            sent_command(&usb, cmd::CLOSE_SESSION).is_some(),
            "the core closes a handle learned by the handshake"
        );
    }

    #[test]
    fn close_accepts_a_reply_body_as_closed() {
        let mut usb = FakeUsb::with_sensor();
        usb.close_body = Some(frame::build_plain_reply(
            cmd::CLOSE_SESSION,
            attr::CLOSE_SESSION,
            TEST_HANDLE,
            0,
            &[],
        ));
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["close"], &mut usb, &shutdown);

        assert_eq!(code, 0, "{err}");
        assert_eq!(out, "secure session closed\n");
        assert_eq!(err, "");
    }

    #[test]
    fn a_close_transport_failure_is_reported_but_the_session_is_locally_closed() {
        let mut usb = FakeUsb::with_sensor();
        usb.close_command_error = Some(UsbError::Disconnected);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["close"], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.contains("disconnected"), "{err}");
        assert!(err.contains("closed locally"), "{err}");
    }

    #[test]
    fn a_recorded_handshake_replays_without_hardware() {
        let record = TempRecord::new("handshake-replay");
        let shutdown = SignalFlag::new();
        let mut usb = FakeUsb::with_sensor();

        let (code, out, err) = run_with(
            &["handshake", "--record", record.path()],
            &mut usb,
            &shutdown,
        );
        assert_eq!(code, 0, "{err}");
        assert_eq!(err, "");
        assert!(out.contains(&format!("handle {TEST_HANDLE:#010x}")));
        assert!(record.exists(), "the recording was written");

        let mut replay_usb = FakeUsb::default();
        let (code, out, err) = run_with(&["replay", record.path()], &mut replay_usb, &shutdown);

        assert_eq!(code, 0, "{err}");
        assert_eq!(err, "");
        assert!(out.starts_with(&format!("handle {TEST_HANDLE:#010x}\n")));
        assert!(out.contains("client nonce 20 bytes"), "{out}");
        assert!(out.contains("device nonce 20 bytes"), "{out}");
        assert!(out.contains("host nonce 20 bytes"), "{out}");
        assert!(
            out.contains("fresh host keypair"),
            "the replay says the derived key differs: {out}"
        );
        assert!(
            replay_usb.calls().is_empty(),
            "replay never touches a USB backend"
        );
    }

    #[test]
    fn a_recorded_failed_open_replays_the_same_error() {
        let record = TempRecord::new("open-replay");
        let shutdown = SignalFlag::new();
        let mut usb = FakeUsb::with_sensor();
        usb.open_status = 0x0c;

        let (record_code, record_out, record_err) =
            run_with(&["open", "--record", record.path()], &mut usb, &shutdown);
        assert_eq!(record_code, 1);
        assert_eq!(record_out, "");
        assert!(record_err.contains("0x0c"), "{record_err}");
        assert!(record.exists());

        let mut replay_usb = FakeUsb::default();
        let (code, out, err) = run_with(&["replay", record.path()], &mut replay_usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert_eq!(err, record_err, "the same failure and message replay");
        assert!(replay_usb.calls().is_empty());
    }

    #[test]
    fn replay_rejects_a_missing_file() {
        let missing = TempRecord::new("missing");
        let mut usb = FakeUsb::default();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["replay", missing.path()], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.contains("cannot read transcript"), "{err}");
        assert!(usb.calls().is_empty());
    }

    #[test]
    fn replay_rejects_a_corrupt_file() {
        let record = TempRecord::new("corrupt");
        record.write(b"this is not a transcript");
        let mut usb = FakeUsb::default();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["replay", record.path()], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.contains("invalid transcript"), "{err}");
        assert!(usb.calls().is_empty());
    }

    #[test]
    fn replay_reports_a_divergent_transcript() {
        let record = TempRecord::new("divergent");
        let mut transcript = Transcript::new("handshake");
        transcript.push(TranscriptRecord::HostFrame(frame::build_plain(
            cmd::CHALLENGE_RESPONSE,
            attr::CHALLENGE_RESPONSE,
            0,
            &[],
        )));
        transcript.push(TranscriptRecord::ReplyWithoutBody);
        record.write(&transcript.to_bytes());

        let mut usb = FakeUsb::default();
        let shutdown = SignalFlag::new();
        let (code, out, err) = run_with(&["replay", record.path()], &mut usb, &shutdown);

        assert_eq!(code, EXIT_DIVERGED);
        assert_eq!(out, "");
        assert!(err.contains("diverged"), "{err}");
        assert!(usb.calls().is_empty());
    }

    #[test]
    fn replay_rejects_a_transcript_for_an_unknown_command() {
        let record = TempRecord::new("unknown-command");
        record.write(&Transcript::new("enrol").to_bytes());
        let mut usb = FakeUsb::default();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["replay", record.path()], &mut usb, &shutdown);

        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.contains("unknown command"), "{err}");
    }
}
