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

use cv3_core::cancel::{CancelCapture, CancelError};
use cv3_core::capture::{
    ArmCapture, ArmOutcome, Capture, CaptureError, CapturedSample, SAMPLE_HASH_LEN,
};
use cv3_core::crypto::BLOCK_LEN;
use cv3_core::enrol::{Enrol, EnrolError, EnrolledTemplate, MAX_ACCEPTED_SAMPLES, TemplateSource};
use cv3_core::handshake::{Handshake, HandshakeError};
use cv3_core::session::{
    CloseError, CloseSession, OpenError, OpenSession, Session, Teardown, TeardownError,
};
use cv3_core::transcript::{RecordingTransport, ReplayTransport, Transcript};
use cv3_core::transport::{Transport, run as drive};
use cv3_core::verify::{
    MatchError, VERDICT_MATCH, VERDICT_NO_MATCH, Verdict, Verification, Verify, VerifyError,
};
use cv3_core::{Action, Operation};

use crate::discovery::{CommandSession, ProbeError, UsbBackend, open_for_command, probe};
use crate::hexdump::HexTransport;
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
/// `capture` found a capture already armed on the sensor (`0x85`); distinct so a hardware run can
/// tell it apart from a failed or timed-out one. The session is torn down either way.
pub const EXIT_CAPTURE_PENDING: u8 = 7;
/// `capture` waited for the finger and the wait timed out; distinct from a transport failure.
pub const EXIT_FINGER_TIMEOUT: u8 = 8;
/// `verify` completed and the sensor reported a genuine no-match. This is a result, not an error:
/// a script can tell it apart from every failure code.
pub const EXIT_NO_MATCH: u8 = 9;
/// A transport failure during a command operation; distinct from a finger timeout.
pub const EXIT_TRANSPORT: u8 = 10;

const USAGE: &str = "usage: cvctl devices
       cvctl handshake [--show-key] [--hex] [--record <file>]
       cvctl open [--bad-sequence] [--hex] [--record <file>]
       cvctl close [--hex] [--record <file>]
       cvctl capture [--hex]
       cvctl enroll [--hex]
       cvctl verify [--hex]
       cvctl cancel-then-verify [--hex]
       cvctl replay <file>";

/// One parsed invocation.
enum Command<'a> {
    Devices,
    Handshake {
        show_key: bool,
        hex: bool,
        record: Option<&'a str>,
    },
    Open {
        bad_sequence: bool,
        hex: bool,
        record: Option<&'a str>,
    },
    Close {
        hex: bool,
        record: Option<&'a str>,
    },
    Capture {
        hex: bool,
    },
    Enroll {
        hex: bool,
    },
    Verify {
        hex: bool,
    },
    CancelThenVerify {
        hex: bool,
    },
    Replay {
        file: &'a str,
    },
}

/// The flags one subcommand accepts.
struct Flags<'a> {
    show_key: bool,
    bad_sequence: bool,
    hex: bool,
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
                hex: flags.hex,
                record: flags.record,
            })
        }
        "open" => {
            let flags = parse_flags(rest, false, true, true)?;
            Some(Command::Open {
                bad_sequence: flags.bad_sequence,
                hex: flags.hex,
                record: flags.record,
            })
        }
        "close" => {
            let flags = parse_flags(rest, false, false, true)?;
            Some(Command::Close {
                hex: flags.hex,
                record: flags.record,
            })
        }
        "capture" => {
            let flags = parse_flags(rest, false, false, false)?;
            Some(Command::Capture { hex: flags.hex })
        }
        "enroll" => {
            let flags = parse_flags(rest, false, false, false)?;
            Some(Command::Enroll { hex: flags.hex })
        }
        "verify" => {
            let flags = parse_flags(rest, false, false, false)?;
            Some(Command::Verify { hex: flags.hex })
        }
        "cancel-then-verify" => {
            let flags = parse_flags(rest, false, false, false)?;
            Some(Command::CancelThenVerify { hex: flags.hex })
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
        hex: false,
        record: None,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--show-key" if allow_show_key && !flags.show_key => flags.show_key = true,
            "--bad-sequence" if allow_bad_sequence && !flags.bad_sequence => {
                flags.bad_sequence = true;
            }
            "--hex" if !flags.hex => flags.hex = true,
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
        Some(Command::Handshake {
            show_key,
            hex,
            record,
        }) => handshake(backend, shutdown, show_key, hex, record, out, err),
        Some(Command::Open {
            bad_sequence,
            hex,
            record,
        }) => open(backend, shutdown, bad_sequence, hex, record, out, err),
        Some(Command::Close { hex, record }) => close(backend, shutdown, hex, record, out, err),
        Some(Command::Capture { hex }) => capture(backend, shutdown, hex, out, err),
        Some(Command::Enroll { hex }) => enroll(backend, shutdown, hex, out, err),
        Some(Command::Verify { hex }) => verify(backend, shutdown, hex, out, err),
        Some(Command::CancelThenVerify { hex }) => {
            cancel_then_verify(backend, shutdown, hex, out, err)
        }
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
            signalled_exit(shutdown, err, EXIT_OK)
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

/// Where a capture run stopped.
enum CaptureFailure {
    Handshake(HandshakeError),
    Open(OpenError),
    Capture(CaptureError),
}

/// Opens the secure session, arms one capture, waits for the finger, then tears the session down.
///
/// A successful capture returns the sample hash and the teardown's own best-effort result; a
/// failure is returned as it happened, because the capture operation already ran the teardown on
/// every failure path.
fn capture_over(
    transport: &mut dyn Transport,
    secrets: RunSecrets,
    open_iv: [u8; cv3_core::crypto::BLOCK_LEN],
    capture_iv: [u8; cv3_core::crypto::BLOCK_LEN],
) -> Result<([u8; SAMPLE_HASH_LEN], Result<(), TeardownError>), CaptureFailure> {
    let run = handshake_over(transport, secrets, true).map_err(CaptureFailure::Handshake)?;
    let mut open = OpenSession::new(run.session, open_iv);
    let session = drive(&mut open, transport).map_err(CaptureFailure::Open)?;

    let mut capture = Capture::new(session, capture_iv);
    match drive(&mut capture, transport) {
        Ok(CapturedSample {
            sample_hash,
            session,
        }) => {
            let mut teardown = Teardown::new(session.handle);
            drop(session);
            Ok((sample_hash, drive(&mut teardown, transport)))
        }
        Err(error) => Err(CaptureFailure::Capture(error)),
    }
}

/// Wraps the probe's exchange in a recording and/or hex-dumping transport when asked.
///
/// The same operation runs whichever wrappers are present. A write failure is returned to the
/// caller rather than swallowed: the user asked for a transcript, and a missing one must be
/// visible. The transcript is wire-only, so replay uses fresh ephemeral keys.
fn with_transport<R>(
    channel: &mut CommandSession,
    command: &str,
    record: Option<&str>,
    dump_hex: bool,
    err: &mut dyn Write,
    run_operation: impl FnOnce(&mut dyn Transport) -> R,
) -> (R, Option<std::io::Error>) {
    match record {
        Some(path) => {
            let recording = RecordingTransport::new(channel.exchange(), command);
            let (result, recording) = run_through(recording, dump_hex, err, run_operation);
            let transcript = recording.into_transcript();
            let error = std::fs::write(path, transcript.to_bytes()).err();
            (result, error)
        }
        None => {
            let (result, _) = run_through(channel.exchange(), dump_hex, err, run_operation);
            (result, None)
        }
    }
}

/// Runs one operation over `inner`, adding the hex dump as the outermost transport when asked.
///
/// Returns the inner transport too, so a recording wrapper underneath can still produce its
/// transcript after the operation finishes.
fn run_through<T: Transport, R>(
    inner: T,
    dump_hex: bool,
    err: &mut dyn Write,
    run_operation: impl FnOnce(&mut dyn Transport) -> R,
) -> (R, T) {
    if dump_hex {
        let mut transport = HexTransport::new(inner, err);
        let result = run_operation(&mut transport);
        (result, transport.into_inner())
    } else {
        let mut transport = inner;
        let result = run_operation(&mut transport);
        (result, transport)
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

/// After an operation has returned, a shutdown signal decides the exit status.
///
/// The core has already torn the session down by the time this runs: a cancelled capture sends the
/// sessionless `0x68` and then the `0x04` close. Mapping the run onto the shell's `128 + signal`
/// is therefore the last thing the probe does, never a substitute for the teardown.
fn signalled_exit(shutdown: &dyn Shutdown, err: &mut dyn Write, code: u8) -> u8 {
    match shutdown.signalled() {
        Some(signal) => {
            let _ = writeln!(err, "cvctl: interrupted by signal {signal}");
            u8::try_from(128 + signal).unwrap_or(code)
        }
        None => code,
    }
}

/// Runs one `0x23` / `0x24` handshake and prints what it learned.
fn handshake(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    show_key: bool,
    dump_hex: bool,
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

    let (outcome, record_error) = with_transport(
        &mut channel,
        "handshake",
        record,
        dump_hex,
        err,
        |transport| handshake_over(transport, secrets, false),
    );

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
            handshake_error_code(&error)
        }
    };
    let code = signalled_exit(shutdown, err, code);
    finish_recording(record_error, err, code)
}

/// Opens the wrapped `0x02` session, prints the handle, then closes it before exiting.
fn open(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    bad_sequence: bool,
    dump_hex: bool,
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

    let (outcome, record_error) =
        with_transport(&mut channel, "open", record, dump_hex, err, |transport| {
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
            handshake_error_code(&error)
        }
        Err(OpenFailure::Open(error)) => {
            let _ = writeln!(err, "cvctl: {error}");
            open_error_code(&error)
        }
    };
    let code = signalled_exit(shutdown, err, code);
    finish_recording(record_error, err, code)
}

/// Closes the secure session the handshake kept open.
fn close(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    dump_hex: bool,
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

    let (outcome, record_error) =
        with_transport(&mut channel, "close", record, dump_hex, err, |transport| {
            close_over(transport, secrets)
        });

    let code = match outcome {
        Ok(()) => {
            let _ = writeln!(out, "secure session closed");
            EXIT_OK
        }
        Err(CloseFailure::Handshake(error)) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            handshake_error_code(&error)
        }
        Err(CloseFailure::Close(error)) => {
            let _ = writeln!(err, "cvctl: {error}");
            close_error_code(&error)
        }
    };
    let code = signalled_exit(shutdown, err, code);
    finish_recording(record_error, err, code)
}

/// Opens the session, arms one capture, waits for the finger, prints the hash, then tears down.
fn capture(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    dump_hex: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let open_iv = match random_iv() {
        Ok(iv) => iv,
        Err(error) => {
            let _ = writeln!(err, "cvctl: {error}");
            return EXIT_OTHER;
        }
    };
    let capture_iv = match random_iv() {
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

    let (outcome, _) = with_transport(&mut channel, "capture", None, dump_hex, err, |transport| {
        capture_over(transport, secrets, open_iv, capture_iv)
    });

    let code = match outcome {
        Ok((sample_hash, teardown)) => {
            let _ = writeln!(out, "sample hash {}", hex(&sample_hash));
            if let Err(error) = teardown {
                let _ = writeln!(err, "cvctl: {error}");
            }
            EXIT_OK
        }
        Err(CaptureFailure::Handshake(error)) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            handshake_error_code(&error)
        }
        Err(CaptureFailure::Open(error)) => {
            let _ = writeln!(err, "cvctl: {error}");
            open_error_code(&error)
        }
        Err(CaptureFailure::Capture(error)) => {
            let _ = writeln!(err, "cvctl: capture failed: {error}");
            capture_error_code(&error)
        }
    };
    signalled_exit(shutdown, err, code)
}

/// Where an enrolment run stopped.
enum EnrolFailure {
    Handshake(HandshakeError),
    Open(OpenError),
    Enrol(EnrolError),
}

/// The committed identifiers an enrolment run reports.
struct EnrolReport {
    template_id: [u8; SAMPLE_HASH_LEN],
    source: TemplateSource,
}

/// Opens the secure session, runs a whole enrolment, prints progress as samples are accepted and
/// tears the session down afterwards.
///
/// The operation is driven one event at a time rather than through [`drive`] so its
/// [`Enrol::progress`] can be read between steps and printed. The core stays callback-free.
/// A failed enrolment has already torn the session down; a successful one is torn down here,
/// because the probe does not perform the binding confirmation.
fn enrol_over(
    transport: &mut dyn Transport,
    secrets: RunSecrets,
    open_iv: [u8; cv3_core::crypto::BLOCK_LEN],
    base_iv: [u8; cv3_core::crypto::BLOCK_LEN],
    progress_out: &mut dyn Write,
) -> Result<(EnrolReport, Result<(), TeardownError>), EnrolFailure> {
    let run = handshake_over(transport, secrets, true).map_err(EnrolFailure::Handshake)?;
    let mut open = OpenSession::new(run.session, open_iv);
    let session = drive(&mut open, transport).map_err(EnrolFailure::Open)?;

    let mut enrol = Enrol::new(session, base_iv);
    let mut action = enrol.start();
    let mut shown_accepted = 0usize;
    let mut shown_rejected = 0usize;
    let outcome = loop {
        match action {
            Action::Send(frame) => action = enrol.step(transport.command(&frame)),
            Action::WaitFinger => action = enrol.step(transport.wait_finger()),
            Action::Finish(result) => break result,
        }

        let progress = enrol.progress();
        while shown_accepted < progress.accepted_samples {
            shown_accepted += 1;
            let _ = writeln!(
                progress_out,
                "sample {shown_accepted} accepted ({shown_accepted}/{MAX_ACCEPTED_SAMPLES})"
            );
        }
        while shown_rejected < progress.rejected_samples {
            shown_rejected += 1;
            let _ = writeln!(progress_out, "sample rejected; place the finger again");
        }
    };

    match outcome {
        Ok(EnrolledTemplate {
            template_id,
            source,
            session,
            ..
        }) => {
            let mut teardown = Teardown::new(session.handle);
            drop(session);
            let closed = drive(&mut teardown, transport);
            Ok((
                EnrolReport {
                    template_id,
                    source,
                },
                closed,
            ))
        }
        Err(error) => Err(EnrolFailure::Enrol(error)),
    }
}

/// Runs a whole enrolment and reports the committed template id, or a distinct failure.
fn enroll(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    dump_hex: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let open_iv = match random_iv() {
        Ok(iv) => iv,
        Err(error) => {
            let _ = writeln!(err, "cvctl: {error}");
            return EXIT_OTHER;
        }
    };
    let base_iv = match random_iv() {
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

    let (outcome, _) = with_transport(&mut channel, "enroll", None, dump_hex, err, |transport| {
        enrol_over(transport, secrets, open_iv, base_iv, out)
    });
    let code = match outcome {
        Ok((report, teardown)) => {
            let _ = writeln!(
                out,
                "template id {} ({})",
                hex(&report.template_id),
                report.source
            );
            if let Err(error) = teardown {
                let _ = writeln!(err, "cvctl: {error}");
            }
            EXIT_OK
        }
        Err(EnrolFailure::Handshake(error)) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            handshake_error_code(&error)
        }
        Err(EnrolFailure::Open(error)) => {
            let _ = writeln!(err, "cvctl: {error}");
            open_error_code(&error)
        }
        Err(EnrolFailure::Enrol(error)) => {
            let _ = writeln!(err, "cvctl: enrolment failed: {error}");
            enrol_error_code(&error)
        }
    };
    signalled_exit(shutdown, err, code)
}

/// Where a verification run stopped.
enum VerifyFailure {
    Handshake(HandshakeError),
    Open(OpenError),
    Verify(VerifyError),
}

/// Opens the secure session, runs capture then match, and tears the session down afterwards.
///
/// A capture or match failure has already torn the session down; a successful verification is
/// torn down here because the probe does not keep a session between invocations. The verdict is
/// returned with the teardown's own best-effort result.
fn verify_over(
    transport: &mut dyn Transport,
    secrets: RunSecrets,
    open_iv: [u8; cv3_core::crypto::BLOCK_LEN],
    capture_iv: [u8; cv3_core::crypto::BLOCK_LEN],
    match_iv: [u8; cv3_core::crypto::BLOCK_LEN],
) -> Result<(Verdict, Result<(), TeardownError>), VerifyFailure> {
    let run = handshake_over(transport, secrets, true).map_err(VerifyFailure::Handshake)?;
    let mut open = OpenSession::new(run.session, open_iv);
    let session = drive(&mut open, transport).map_err(VerifyFailure::Open)?;

    let mut verify = Verify::new(session, capture_iv, match_iv);
    match drive(&mut verify, transport) {
        Ok(Verification { verdict, session }) => {
            let mut teardown = Teardown::new(session.handle);
            drop(session);
            Ok((verdict, drive(&mut teardown, transport)))
        }
        Err(error) => Err(VerifyFailure::Verify(error)),
    }
}

/// Prints the decoded verdict word, the 20-byte value (or its absence) and both lengths.
fn print_verdict(verdict: &Verdict, out: &mut dyn Write) {
    let meaning = match verdict.word {
        VERDICT_MATCH => "match",
        VERDICT_NO_MATCH => "no match",
        _ => "no match, unexpected word",
    };
    let _ = writeln!(out, "verdict {} ({meaning})", verdict.word);
    match &verdict.value {
        Some(value) => {
            let _ = writeln!(out, "value {}", hex(value));
        }
        None => {
            let _ = writeln!(out, "value absent");
        }
    }
    let _ = writeln!(out, "reply length {}", verdict.reply_len);
    let _ = writeln!(out, "plaintext length {}", verdict.plaintext_len);
}

/// Maps the `0x23` / `0x24` handshake failure onto the probe's documented exit codes.
///
/// The handshake runs before every session command, so a transport failure there is still a
/// transport failure during a command operation rather than a generic error.
fn handshake_error_code(error: &HandshakeError) -> u8 {
    match error {
        HandshakeError::Transport(_) => EXIT_TRANSPORT,
        _ => EXIT_OTHER,
    }
}

/// Maps the wrapped `0x02` open failure onto the probe's documented exit codes.
///
/// Every session command starts here, so a wrong sequence and a transport failure get the same
/// codes whether they happen during the open or later in the operation.
fn open_error_code(error: &OpenError) -> u8 {
    match error {
        OpenError::WrongSequence => EXIT_SEQUENCE,
        OpenError::Transport(_) => EXIT_TRANSPORT,
        _ => EXIT_OTHER,
    }
}

/// Maps a plain `0x04` close failure onto the probe's documented exit codes.
fn close_error_code(error: &CloseError) -> u8 {
    match error {
        CloseError::Transport(_) => EXIT_TRANSPORT,
        _ => EXIT_OTHER,
    }
}

/// Maps a capture failure onto the probe's documented exit codes.
fn capture_error_code(error: &CaptureError) -> u8 {
    use cv3_core::proto::status;

    match error {
        CaptureError::AlreadyPending => EXIT_CAPTURE_PENDING,
        CaptureError::FingerTimeout => EXIT_FINGER_TIMEOUT,
        CaptureError::Transport(_) => EXIT_TRANSPORT,
        CaptureError::SensorStatus(code) if *code == status::BAD_SEQUENCE => EXIT_SEQUENCE,
        CaptureError::SensorStatus(code) if *code == status::CAPTURE_PENDING => {
            EXIT_CAPTURE_PENDING
        }
        _ => EXIT_OTHER,
    }
}

/// Maps a verification failure onto the probe's documented exit codes.
fn verify_error_code(error: &VerifyError) -> u8 {
    use cv3_core::proto::status;

    match error {
        VerifyError::Capture(error) => capture_error_code(error),
        VerifyError::Match(MatchError::WrongSequence) => EXIT_SEQUENCE,
        VerifyError::Match(MatchError::Transport(_)) => EXIT_TRANSPORT,
        VerifyError::Match(MatchError::SensorStatus(code)) if *code == status::BAD_SEQUENCE => {
            EXIT_SEQUENCE
        }
        VerifyError::Match(MatchError::SensorStatus(code)) if *code == status::CAPTURE_PENDING => {
            EXIT_CAPTURE_PENDING
        }
        _ => EXIT_OTHER,
    }
}

/// Maps a mid-session cancel failure onto the probe's documented exit codes.
fn cancel_error_code(error: &CancelError) -> u8 {
    use cv3_core::proto::status;

    match error {
        CancelError::Transport(_) => EXIT_TRANSPORT,
        CancelError::SensorStatus(code) if *code == status::BAD_SEQUENCE => EXIT_SEQUENCE,
        _ => EXIT_OTHER,
    }
}

/// Maps an enrolment failure onto the probe's documented exit codes.
///
/// The capture it composes keeps its own codes, and the update and commit stages report a rejected
/// sequence as [`EnrolError::UpdateRejected`] or [`EnrolError::CommitRejected`], so both are read
/// through this helper rather than falling through to [`EXIT_OTHER`].
fn enrol_error_code(error: &EnrolError) -> u8 {
    use cv3_core::proto::status;

    match error {
        EnrolError::Capture(error) => capture_error_code(error),
        EnrolError::Transport { .. } => EXIT_TRANSPORT,
        EnrolError::UpdateRejected { status: code, .. }
        | EnrolError::CommitRejected { status: code }
            if *code == status::BAD_SEQUENCE =>
        {
            EXIT_SEQUENCE
        }
        _ => EXIT_OTHER,
    }
}

/// Opens the session, captures a finger, matches it and reports the verdict.
fn verify(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    dump_hex: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let open_iv = match random_iv() {
        Ok(iv) => iv,
        Err(error) => {
            let _ = writeln!(err, "cvctl: {error}");
            return EXIT_OTHER;
        }
    };
    let capture_iv = match random_iv() {
        Ok(iv) => iv,
        Err(error) => {
            let _ = writeln!(err, "cvctl: {error}");
            return EXIT_OTHER;
        }
    };
    let match_iv = match random_iv() {
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
    let (outcome, _) = with_transport(&mut channel, "verify", None, dump_hex, err, |transport| {
        verify_over(transport, secrets, open_iv, capture_iv, match_iv)
    });

    let code = match outcome {
        Ok((verdict, teardown)) => {
            print_verdict(&verdict, out);
            if let Err(error) = teardown {
                let _ = writeln!(err, "cvctl: {error}");
            }
            if verdict.matched {
                EXIT_OK
            } else {
                EXIT_NO_MATCH
            }
        }
        Err(VerifyFailure::Handshake(error)) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            handshake_error_code(&error)
        }
        Err(VerifyFailure::Open(error)) => {
            let _ = writeln!(err, "cvctl: {error}");
            open_error_code(&error)
        }
        Err(VerifyFailure::Verify(error)) => {
            let _ = writeln!(err, "cvctl: verification failed: {error}");
            verify_error_code(&error)
        }
    };
    signalled_exit(shutdown, err, code)
}

/// Where a cancel-then-verify run stopped.
enum CancelThenVerifyFailure {
    Handshake(HandshakeError),
    Open(OpenError),
    /// The first, arm-only capture failed; its own teardown has run.
    Capture(CaptureError),
    /// The mid-session cancel failed; it ran the teardown before reporting.
    Cancel(CancelError),
    /// The verification failed; its capture or match teardown has run.
    Verify(VerifyError),
}

/// Opens **one** session, arms a capture, cancels it before any finger, then verifies in it.
///
/// The wire order is `0x02`, `0x66`, the mid-session `0x68`, `0x66`, the finger event and `0x73`.
/// The mid-session cancel is plain and leaves the wrap sequence where the first arm reply put it,
/// which is what makes this run the experiment for the capture-pending rule as well: the second
/// arm carries the reference reading's number. The caller tears the one session down afterwards.
fn cancel_then_verify_over(
    transport: &mut dyn Transport,
    secrets: RunSecrets,
    open_iv: [u8; BLOCK_LEN],
    arm_iv: [u8; BLOCK_LEN],
    capture_iv: [u8; BLOCK_LEN],
    match_iv: [u8; BLOCK_LEN],
) -> Result<(Verdict, Result<(), TeardownError>), CancelThenVerifyFailure> {
    let run =
        handshake_over(transport, secrets, true).map_err(CancelThenVerifyFailure::Handshake)?;
    let mut open = OpenSession::new(run.session, open_iv);
    let session = drive(&mut open, transport).map_err(CancelThenVerifyFailure::Open)?;

    // Arm only: consume the 0x66 reply and keep the session, without waiting for a finger. A
    // 0x85 reply is an outcome, not a failure: the stale capture is cancelled next, and the
    // re-arm inside the verification then carries the sequence the two readings disagree about.
    let mut arm = ArmCapture::new(session, arm_iv);
    let session = match drive(&mut arm, transport).map_err(CancelThenVerifyFailure::Capture)? {
        ArmOutcome::Armed(CapturedSample { session, .. }) => session,
        ArmOutcome::AlreadyPending(session) => session,
    };

    // Clear the armed capture with the session-scoped cancel, which leaves the session open.
    let mut cancel = CancelCapture::new(session);
    let session = drive(&mut cancel, transport).map_err(CancelThenVerifyFailure::Cancel)?;

    let mut verify = Verify::new(session, capture_iv, match_iv);
    match drive(&mut verify, transport) {
        Ok(Verification { verdict, session }) => {
            let mut teardown = Teardown::new(session.handle);
            drop(session);
            Ok((verdict, drive(&mut teardown, transport)))
        }
        Err(error) => Err(CancelThenVerifyFailure::Verify(error)),
    }
}

/// Runs the one-session experiment `cancel-then-verify` exists for and prints the verify detail.
fn cancel_then_verify(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    dump_hex: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let mut ivs = [[0u8; BLOCK_LEN]; 4];
    for slot in &mut ivs {
        *slot = match random_iv() {
            Ok(iv) => iv,
            Err(error) => {
                let _ = writeln!(err, "cvctl: {error}");
                return EXIT_OTHER;
            }
        };
    }
    let [open_iv, arm_iv, capture_iv, match_iv] = ivs;

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

    let (outcome, _) = with_transport(
        &mut channel,
        "cancel-then-verify",
        None,
        dump_hex,
        err,
        |transport| {
            cancel_then_verify_over(transport, secrets, open_iv, arm_iv, capture_iv, match_iv)
        },
    );

    let code = match outcome {
        Ok((verdict, teardown)) => {
            print_verdict(&verdict, out);
            if let Err(error) = teardown {
                let _ = writeln!(err, "cvctl: {error}");
            }
            if verdict.matched {
                EXIT_OK
            } else {
                EXIT_NO_MATCH
            }
        }
        Err(CancelThenVerifyFailure::Handshake(error)) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            handshake_error_code(&error)
        }
        Err(CancelThenVerifyFailure::Open(error)) => {
            let _ = writeln!(err, "cvctl: {error}");
            open_error_code(&error)
        }
        Err(CancelThenVerifyFailure::Capture(error)) => {
            let _ = writeln!(err, "cvctl: the first capture failed: {error}");
            capture_error_code(&error)
        }
        Err(CancelThenVerifyFailure::Cancel(error)) => {
            let _ = writeln!(err, "cvctl: the mid-session cancel failed: {error}");
            cancel_error_code(&error)
        }
        Err(CancelThenVerifyFailure::Verify(error)) => {
            let _ = writeln!(err, "cvctl: verification failed: {error}");
            verify_error_code(&error)
        }
    };
    signalled_exit(shutdown, err, code)
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
            handshake_error_code(&error)
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
            handshake_error_code(&error)
        }
        ReplayOutcome::Open(Err(OpenFailure::Open(error))) => {
            let _ = writeln!(err, "cvctl: {error}");
            open_error_code(&error)
        }
        ReplayOutcome::Close(Ok(())) => {
            let _ = writeln!(out, "secure session closed");
            EXIT_OK
        }
        ReplayOutcome::Close(Err(CloseFailure::Handshake(error))) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            handshake_error_code(&error)
        }
        ReplayOutcome::Close(Err(CloseFailure::Close(error))) => {
            let _ = writeln!(err, "cvctl: {error}");
            close_error_code(&error)
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
    use crate::testing::{
        DEVICE_NONCE, DEVICE_PUBLIC, ENROLMENT_ID, FakeUsb, MATCH_VALUE, SAMPLE_HASH, TEST_HANDLE,
        sensor,
    };

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

        let (code, out, err) = run_with(&["inventory"], &mut usb, &shutdown);

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
    fn hex_is_accepted_on_every_hardware_subcommand_and_nowhere_else() {
        for args in [
            vec!["handshake", "--hex"],
            vec!["open", "--hex"],
            vec!["close", "--hex"],
            vec!["capture", "--hex"],
            vec!["enroll", "--hex"],
            vec!["verify", "--hex"],
            vec!["cancel-then-verify", "--hex"],
        ] {
            let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            assert!(parse(&args).is_some(), "{args:?} should accept --hex");
        }

        for args in [vec!["devices", "--hex"], vec!["replay", "file", "--hex"]] {
            let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            assert!(parse(&args).is_none(), "{args:?} should reject --hex");
        }
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
    fn hex_dumps_both_directions_to_stderr_and_leaves_stdout_unchanged() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["handshake", "--hex"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(
            out.lines().count(),
            6,
            "stdout is the ordinary report: {out}"
        );
        assert!(
            !out.contains("> ") && !out.contains("< "),
            "the hex dump never reaches stdout: {out}"
        );

        let sent = usb.sent.borrow();
        let host: Vec<&str> = err.lines().filter(|line| line.starts_with("> ")).collect();
        let device: Vec<&str> = err.lines().filter(|line| line.starts_with("< ")).collect();

        assert_eq!(host.len(), sent.len(), "one host line per frame: {err}");
        for (line, frame) in host.iter().zip(sent.iter()) {
            assert_eq!(*line, format!("> {}", hex(frame)));
        }

        assert_eq!(device.len(), sent.len(), "one device line per reply: {err}");

        // The scripted sensor's replies are deterministic, so the device direction can be
        // asserted exactly: the 0x23 parameter block, the empty 0x24 body, then the empty close.
        let mut challenge_param = [0u8; 148];
        challenge_param[..64].copy_from_slice(&DEVICE_PUBLIC);
        challenge_param[64..128].fill(0xcc);
        challenge_param[128..].copy_from_slice(&DEVICE_NONCE);
        let expected_device = [
            frame::build_plain_reply(
                cmd::CHALLENGE,
                attr::CHALLENGE,
                TEST_HANDLE,
                0,
                &challenge_param,
            ),
            frame::build_plain_reply(
                cmd::CHALLENGE_RESPONSE,
                attr::CHALLENGE_RESPONSE,
                TEST_HANDLE,
                0,
                &[],
            ),
        ];
        assert_eq!(device[0], format!("< {}", hex(&expected_device[0])));
        assert_eq!(device[1], format!("< {}", hex(&expected_device[1])));
        assert_eq!(device[2], "< empty");

        assert_eq!(
            err.lines().count(),
            sent.len() * 2,
            "each frame has one line in each direction: {err}"
        );
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

        assert_eq!(code, EXIT_TRANSPORT);
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

        assert_eq!(code, EXIT_TRANSPORT);
        assert_eq!(out, "");
        assert!(err.contains("disconnected"), "{err}");
        assert!(err.contains("closed locally"), "{err}");
    }

    #[test]
    fn a_handshake_transport_failure_exits_with_the_transport_code() {
        let mut usb = FakeUsb::with_sensor();
        usb.challenge_command_error = Some(UsbError::Timeout);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["handshake"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_TRANSPORT);
        assert_ne!(code, EXIT_OTHER);
        assert_eq!(out, "");
        assert!(err.contains("handshake failed"), "{err}");
        assert!(err.contains("timed out"), "{err}");
        assert!(
            sent_command(&usb, cmd::CLOSE_SESSION).is_none(),
            "no handle was learned, so there is nothing to close"
        );
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

    fn sent_commands(usb: &FakeUsb) -> Vec<u16> {
        usb.sent
            .borrow()
            .iter()
            .map(|frame| command(frame))
            .collect()
    }

    fn le32(frame: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(
            frame[offset..offset + 4]
                .try_into()
                .expect("four bytes for a word"),
        )
    }

    #[test]
    fn capture_prints_the_sample_hash_and_tears_the_session_down() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["capture"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert_eq!(out, format!("sample hash {}\n", hex(&SAMPLE_HASH)));
        assert_eq!(
            sent_commands(&usb),
            [
                cmd::CHALLENGE,
                cmd::CHALLENGE_RESPONSE,
                cmd::OPEN_SESSION,
                cmd::ARM_CAPTURE,
                cmd::CANCEL_CAPTURE,
                cmd::CLOSE_SESSION,
            ],
            "the arm is followed by the cancel-then-close teardown"
        );

        let arm = sent_command(&usb, cmd::ARM_CAPTURE).expect("0x66 was sent");
        assert_eq!(arm[10], attr::CAPTURE);
        assert_eq!(arm[11], 0x02, "the arm is wrapped");
        assert_eq!(le32(&arm, 16), TEST_HANDLE);
        assert_eq!(le32(&arm, 40), 36, "the 36-byte TLV block");
        assert_eq!(arm.len(), 140, "80 plaintext bytes plus padding");

        let cancel = sent_command(&usb, cmd::CANCEL_CAPTURE).expect("0x68 was sent");
        assert_eq!(cancel.len(), 56);
        assert_eq!(cancel[10], attr::CANCEL_SESSIONLESS);
        assert_eq!(cancel[11], 0x00, "the cancel is plain");
        assert_eq!(le32(&cancel, 16), 0, "sessionless header");
        assert_eq!(le32(&cancel, 40), 12);
        assert_eq!(
            &cancel[44..],
            &[0, 0, 0, 0, 4, 0, 0, 0, 0x44, 0x33, 0x22, 0x11]
        );
        assert_eq!(
            sent_command(&usb, cmd::CLOSE_SESSION),
            Some(frame::build_close_handle(TEST_HANDLE)),
            "the handle is released after the cancel"
        );
    }

    #[test]
    fn capture_pending_is_its_own_exit_code_and_tears_down() {
        let mut usb = FakeUsb::with_sensor();
        usb.arm_status = 0x85;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["capture"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_CAPTURE_PENDING);
        assert_ne!(code, EXIT_OTHER);
        assert_eq!(out, "", "a pending capture is never reported as a hash");
        assert!(err.contains("already armed"), "{err}");
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn a_finger_timeout_is_its_own_exit_code_and_tears_down() {
        let mut usb = FakeUsb::with_sensor();
        usb.finger_event = Some(Err(UsbError::Timeout));
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["capture"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_FINGER_TIMEOUT);
        assert_ne!(code, EXIT_CAPTURE_PENDING);
        assert_ne!(code, EXIT_OTHER);
        assert_eq!(out, "");
        assert!(err.contains("finger timeout"), "{err}");
        assert_ne!(
            err, "",
            "a finger timeout is not confused with a transport failure"
        );
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn a_zero_status_reply_without_a_sample_hash_has_its_own_message() {
        let mut usb = FakeUsb::with_sensor();
        usb.arm_plaintext = Some(vec![0u8; 28]);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["capture"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OTHER);
        assert_eq!(out, "");
        assert!(err.contains("no 20-byte sample hash"), "{err}");
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn a_sensor_status_error_is_reported_and_tears_down() {
        let mut usb = FakeUsb::with_sensor();
        usb.arm_status = 0x0c;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["capture"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OTHER);
        assert_eq!(out, "");
        assert!(err.contains("0x0c"), "{err}");
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn enroll_prints_progress_and_the_committed_template_id() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "sample 1 accepted (1/12)");
        assert_eq!(lines[1], "sample 2 accepted (2/12)");
        assert_eq!(
            lines[2],
            format!("template id {} (sensor enrolment id)", hex(&ENROLMENT_ID))
        );
        assert_eq!(lines.len(), 3, "one progress line per accepted sample");
        assert_eq!(
            sent_commands(&usb),
            [
                cmd::CHALLENGE,
                cmd::CHALLENGE_RESPONSE,
                cmd::OPEN_SESSION,
                cmd::DISCARD_ENROLMENT,
                cmd::START_ENROLMENT,
                cmd::ARM_CAPTURE,
                cmd::UPDATE_ENROLMENT,
                cmd::ARM_CAPTURE,
                cmd::UPDATE_ENROLMENT,
                cmd::COMMIT_ENROLMENT,
                cmd::CANCEL_CAPTURE,
                cmd::CLOSE_SESSION,
            ],
            "the probe discards, starts, samples, commits, then tears the session down"
        );

        let discard = sent_command(&usb, cmd::DISCARD_ENROLMENT).expect("0x6d was sent");
        assert_eq!(discard[10], attr::SESSION);
        assert_eq!(discard[11], 0x02, "the discard is wrapped");
        assert_eq!(le32(&discard, 16), TEST_HANDLE);

        let start = sent_command(&usb, cmd::START_ENROLMENT).expect("0x8a was sent");
        assert_eq!(start[10], 0x44);
        assert_eq!(start[11], 0x00, "the start is plain");
        assert_eq!(le32(&start, 16), 0);

        let update = sent_command(&usb, cmd::UPDATE_ENROLMENT).expect("0x6c was sent");
        assert_eq!(update[10], attr::SESSION);
        assert_eq!(update[11], 0x02, "the update is wrapped");
        assert_eq!(le32(&update, 40), 48, "the 48-byte TLV block");

        let commit = sent_command(&usb, cmd::COMMIT_ENROLMENT).expect("0x6e was sent");
        assert_eq!(commit[10], attr::SESSION);
        assert_eq!(commit[11], 0x02, "the commit is wrapped");
        assert_eq!(le32(&commit, 40), 64, "the 64-byte TLV block");
    }

    #[test]
    fn enroll_prints_a_retry_line_when_a_sample_is_rejected() {
        let mut usb = FakeUsb::with_sensor();
        usb.update_statuses = vec![0xa4];
        usb.completion_after = Some(2);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert!(
            out.contains("sample rejected; place the finger again"),
            "the rejected sample is reported: {out}"
        );
        assert_eq!(
            out.lines()
                .filter(|line| line.starts_with("sample 1 accepted"))
                .count(),
            1,
            "the rejected sample is not counted: {out}"
        );
        assert!(out.contains("sample 2 accepted (2/12)"), "{out}");
        assert!(out.contains("sensor enrolment id"), "{out}");
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|command| **command == cmd::ARM_CAPTURE)
                .count(),
            3,
            "the rejected sample is requested again"
        );
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|command| **command == cmd::UPDATE_ENROLMENT)
                .count(),
            3
        );
    }

    #[test]
    fn enroll_without_completion_commits_at_twelve_and_labels_the_sample_hash() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert_eq!(
            out.lines()
                .filter(|line| line.starts_with("sample ") && line.contains(" accepted "))
                .count(),
            12,
            "one progress line per accepted sample: {out}"
        );
        assert!(out.contains("sample 12 accepted (12/12)"), "{out}");
        assert_eq!(
            out.lines().last(),
            Some(format!("template id {} (last sample hash)", hex(&SAMPLE_HASH)).as_str()),
            "{out}"
        );
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|command| **command == cmd::ARM_CAPTURE)
                .count(),
            12,
            "twelve samples, no extra capture"
        );
    }

    #[test]
    fn a_failed_enrol_prints_the_pending_warning_and_exits_non_zero() {
        let mut usb = FakeUsb::with_sensor();
        usb.finger_event = Some(Err(UsbError::Timeout));
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_FINGER_TIMEOUT);
        assert_eq!(out, "", "no template id is printed");
        assert!(err.contains("enrolment failed"), "{err}");
        assert!(err.contains("pending enrolment may remain"), "{err}");
        assert!(err.contains("next discard"), "{err}");
        assert!(err.contains("no template was stored"), "{err}");
        assert!(
            sent_command(&usb, cmd::CANCEL_CAPTURE).is_some(),
            "the failure tears down the session"
        );
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
        assert!(
            sent_command(&usb, cmd::COMMIT_ENROLMENT).is_none(),
            "a failure before the commit stores nothing"
        );
    }

    #[test]
    fn a_rejected_commit_is_reported_and_says_a_template_may_exist() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(1);
        usb.commit_status = 0x0c;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OTHER);
        assert_eq!(out, "sample 1 accepted (1/12)\n");
        assert!(err.contains("0x0c"), "{err}");
        assert!(err.contains("may exist"), "{err}");
        assert!(
            sent_command(&usb, cmd::CANCEL_CAPTURE).is_some(),
            "the failed commit still tears the session down"
        );
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn a_transport_failure_at_the_arm_is_reported_and_tears_down() {
        let mut usb = FakeUsb::with_sensor();
        usb.arm_command_error = Some(UsbError::Timeout);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["capture"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_TRANSPORT);
        assert_ne!(code, EXIT_FINGER_TIMEOUT);
        assert_eq!(out, "");
        assert!(err.contains("capture failed"), "{err}");
        assert!(err.contains("timed out"), "{err}");
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn capture_reports_a_sequence_rejection_with_the_sequence_code() {
        let mut usb = FakeUsb::with_sensor();
        usb.arm_status = 0x0f;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["capture"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_SEQUENCE);
        assert_ne!(code, EXIT_OTHER);
        assert_eq!(out, "");
        assert!(err.contains("0x0f"), "{err}");
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn enroll_transport_failures_at_every_stage_exit_with_the_transport_code() {
        type Configure = fn(&mut FakeUsb);

        let stages: [(&str, Configure); 5] = [
            ("0x6d discard", |usb| {
                usb.discard_command_error = Some(UsbError::Timeout);
            }),
            ("0x8a start", |usb| {
                usb.start_command_error = Some(UsbError::Disconnected);
            }),
            ("0x66 capture", |usb| {
                usb.arm_command_error = Some(UsbError::Disconnected);
            }),
            ("0x6c update", |usb| {
                usb.update_command_error = Some(UsbError::Timeout);
            }),
            ("0x6e commit", |usb| {
                usb.completion_after = Some(1);
                usb.commit_command_error = Some(UsbError::Stall);
            }),
        ];
        let shutdown = SignalFlag::new();

        for (stage, configure) in stages {
            let mut usb = FakeUsb::with_sensor();
            configure(&mut usb);

            let (code, out, err) = run_with(&["enroll"], &mut usb, &shutdown);

            assert_eq!(code, EXIT_TRANSPORT, "{stage}: {err}");
            assert!(
                !out.contains("template id"),
                "{stage}: no template id is printed: {out}"
            );
            assert!(
                err.contains("transport failed"),
                "{stage} names the transport: {err}"
            );
            assert!(
                sent_command(&usb, cmd::CLOSE_SESSION).is_some(),
                "{stage} still tears the session down"
            );
        }
    }

    #[test]
    fn enroll_reports_a_sequence_rejection_at_update_or_commit_with_the_sequence_code() {
        let shutdown = SignalFlag::new();

        let mut update = FakeUsb::with_sensor();
        update.update_statuses = vec![0x0f];
        let (code, out, err) = run_with(&["enroll"], &mut update, &shutdown);
        assert_eq!(code, EXIT_SEQUENCE, "the 0x6c update: {err}");
        assert_ne!(code, EXIT_OTHER);
        assert_eq!(out, "", "no template id is printed");
        assert!(err.contains("0x0f"), "{err}");
        assert!(sent_command(&update, cmd::CLOSE_SESSION).is_some());

        let mut commit = FakeUsb::with_sensor();
        commit.completion_after = Some(1);
        commit.commit_status = 0x0f;
        let (code, out, err) = run_with(&["enroll"], &mut commit, &shutdown);
        assert_eq!(code, EXIT_SEQUENCE, "the 0x6e commit: {err}");
        assert_eq!(out, "sample 1 accepted (1/12)\n");
        assert!(err.contains("0x0f"), "{err}");
        assert!(sent_command(&commit, cmd::CLOSE_SESSION).is_some());
    }

    fn match_plaintext(word: u32, value: Option<&[u8; 20]>) -> Vec<u8> {
        let len = if value.is_some() { 52 } else { 28 };
        let mut plaintext = vec![0u8; len];
        plaintext[8..12].copy_from_slice(&word.to_le_bytes());
        if let Some(value) = value {
            plaintext[32..52].copy_from_slice(value);
        }
        plaintext
    }

    fn verify_output(
        word: u32,
        value: Option<&[u8; 20]>,
        reply: usize,
        plaintext: usize,
    ) -> String {
        let meaning = match word {
            VERDICT_MATCH => "match",
            VERDICT_NO_MATCH => "no match",
            _ => "no match, unexpected word",
        };
        let value = match value {
            Some(value) => format!("value {}", hex(value)),
            None => "value absent".to_owned(),
        };
        format!(
            "verdict {word} ({meaning})\n{value}\nreply length {reply}\nplaintext length \
             {plaintext}\n"
        )
    }

    #[test]
    fn cancel_then_verify_owns_one_session_and_prints_the_verdict() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["cancel-then-verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert_eq!(
            out,
            verify_output(VERDICT_MATCH, Some(&MATCH_VALUE), 108, 52),
            "the verdict, value and lengths are printed exactly as verify prints them"
        );
        assert_eq!(
            sent_commands(&usb),
            [
                cmd::CHALLENGE,
                cmd::CHALLENGE_RESPONSE,
                cmd::OPEN_SESSION,
                cmd::ARM_CAPTURE,
                cmd::CANCEL_CAPTURE,
                cmd::ARM_CAPTURE,
                cmd::MATCH,
                cmd::CANCEL_CAPTURE,
                cmd::CLOSE_SESSION,
            ],
            "one 0x02, then arm, mid-cancel, re-arm, match, teardown"
        );
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|command| **command == cmd::OPEN_SESSION)
                .count(),
            1,
            "the whole run owns one session"
        );
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|command| **command == cmd::CLOSE_SESSION)
                .count(),
            1
        );
        assert_eq!(
            usb.calls()
                .iter()
                .filter(|call| **call == "open-command")
                .count(),
            1,
            "the command channel is opened once"
        );

        let cancels: Vec<Vec<u8>> = usb
            .sent
            .borrow()
            .iter()
            .filter(|frame| command(frame) == cmd::CANCEL_CAPTURE)
            .cloned()
            .collect();
        assert_eq!(
            cancels.len(),
            2,
            "the mid-session cancel and the teardown one"
        );

        let mid = &cancels[0];
        assert_eq!(mid.len(), 56);
        assert_eq!(&mid[8..10], &[0x68, 0x00], "0x68");
        assert_eq!(mid[10], attr::CANCEL_SESSION, "mid-session attribute 0x40");
        assert_eq!(mid[11], 0x00, "the mid-session cancel is plain");
        assert_eq!(le32(mid, 16), TEST_HANDLE, "header handle is the session");
        assert_eq!(le32(mid, 40), 12, "declared parameter length");
        assert_eq!(
            &mid[44..],
            &[0, 0, 0, 0, 4, 0, 0, 0, 0x44, 0x33, 0x22, 0x11],
            "TLV (0,4,handle)"
        );

        let sessionless = &cancels[1];
        assert_eq!(sessionless[10], attr::CANCEL_SESSIONLESS);
        assert_eq!(
            le32(sessionless, 16),
            0,
            "the teardown cancel is sessionless"
        );

        assert_eq!(
            sent_command(&usb, cmd::MATCH).expect("0x73 was sent").len(),
            172,
            "the match is the same 112-plaintext frame verify sends"
        );
    }

    #[test]
    fn cancel_then_verify_survives_a_pending_first_arm_and_still_verifies() {
        // The first arm answers 0x85: a capture was already armed. The run consumes that reply,
        // cancels the stale capture at mid-session, and re-arms inside the same session. This is
        // the reference's capture-pending retry path, and the re-arm's sequence is the one the
        // two readings disagree about.
        let mut usb = FakeUsb::with_sensor();
        usb.arm_statuses = vec![0x85];
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["cancel-then-verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert_eq!(
            out,
            verify_output(VERDICT_MATCH, Some(&MATCH_VALUE), 108, 52)
        );
        assert_eq!(
            sent_commands(&usb),
            [
                cmd::CHALLENGE,
                cmd::CHALLENGE_RESPONSE,
                cmd::OPEN_SESSION,
                cmd::ARM_CAPTURE,
                cmd::CANCEL_CAPTURE,
                cmd::ARM_CAPTURE,
                cmd::MATCH,
                cmd::CANCEL_CAPTURE,
                cmd::CLOSE_SESSION,
            ],
            "the pending first arm does not tear the session down"
        );
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|command| **command == cmd::OPEN_SESSION)
                .count(),
            1
        );
    }

    #[test]
    fn cancel_then_verify_reports_a_no_match_with_its_own_exit_code() {
        let mut usb = FakeUsb::with_sensor();
        usb.match_plaintext = Some(match_plaintext(0, Some(&MATCH_VALUE)));
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["cancel-then-verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_NO_MATCH);
        assert_eq!(err, "");
        assert_eq!(
            out,
            verify_output(VERDICT_NO_MATCH, Some(&MATCH_VALUE), 108, 52)
        );
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn cancel_then_verify_tears_down_when_the_finger_never_arrives() {
        let mut usb = FakeUsb::with_sensor();
        usb.finger_event = Some(Err(UsbError::Timeout));
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["cancel-then-verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_FINGER_TIMEOUT);
        assert_eq!(out, "");
        assert!(err.contains("finger timeout"), "{err}");
        assert_eq!(
            sent_commands(&usb),
            [
                cmd::CHALLENGE,
                cmd::CHALLENGE_RESPONSE,
                cmd::OPEN_SESSION,
                cmd::ARM_CAPTURE,
                cmd::CANCEL_CAPTURE,
                cmd::ARM_CAPTURE,
                cmd::CANCEL_CAPTURE,
                cmd::CLOSE_SESSION,
            ],
            "the failed verification tears the one session down"
        );
    }

    #[test]
    fn cancel_then_verify_tears_down_when_the_mid_session_cancel_fails() {
        let mut usb = FakeUsb::with_sensor();
        usb.cancel_command_error = Some(UsbError::Disconnected);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["cancel-then-verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_TRANSPORT);
        assert_eq!(out, "");
        assert!(err.contains("mid-session cancel failed"), "{err}");
        assert!(err.contains("disconnected"), "{err}");
        assert!(
            sent_command(&usb, cmd::CLOSE_SESSION).is_some(),
            "the handle is released even when the cancel fails"
        );
    }

    #[test]
    fn a_signal_during_the_finger_wait_tears_capture_down_and_exits_128_plus_the_signal() {
        let flag = SignalFlag::new();
        let mut usb = FakeUsb::with_sensor();
        usb.signal_during_finger = Some(flag.clone());

        let (code, out, err) = run_with(&["capture"], &mut usb, &flag);

        assert_eq!(code, 130, "SIGINT follows the shell convention");
        assert_eq!(out, "");
        assert!(err.contains("capture cancelled"), "{err}");
        assert!(err.contains("interrupted by signal 2"), "{err}");
        let sent = sent_commands(&usb);
        assert_eq!(
            &sent[sent.len() - 2..],
            &[cmd::CANCEL_CAPTURE, cmd::CLOSE_SESSION],
            "the core cancels the capture and closes the handle before the signal status"
        );
        assert_eq!(sent.iter().filter(|c| **c == cmd::CLOSE_SESSION).count(), 1);
    }

    #[test]
    fn a_signal_during_verify_tears_down_and_exits_128_plus_the_signal() {
        let flag = SignalFlag::new();
        let mut usb = FakeUsb::with_sensor();
        usb.signal_during_finger = Some(flag.clone());

        let (code, out, err) = run_with(&["verify"], &mut usb, &flag);

        assert_eq!(code, 130);
        assert_eq!(out, "");
        assert!(err.contains("verification failed"), "{err}");
        assert!(err.contains("interrupted by signal 2"), "{err}");
        let sent = sent_commands(&usb);
        assert_eq!(
            &sent[sent.len() - 2..],
            &[cmd::CANCEL_CAPTURE, cmd::CLOSE_SESSION]
        );
    }

    #[test]
    fn a_signal_during_cancel_then_verify_tears_down_and_exits_128_plus_the_signal() {
        let flag = SignalFlag::new();
        let mut usb = FakeUsb::with_sensor();
        usb.signal_during_finger = Some(flag.clone());

        let (code, out, err) = run_with(&["cancel-then-verify"], &mut usb, &flag);

        assert_eq!(code, 130);
        assert_eq!(out, "");
        assert!(err.contains("interrupted by signal 2"), "{err}");
        let sent = sent_commands(&usb);
        assert_eq!(
            &sent[sent.len() - 2..],
            &[cmd::CANCEL_CAPTURE, cmd::CLOSE_SESSION],
            "the second capture was cancelled and the one session closed"
        );
    }

    #[test]
    fn a_signal_during_a_command_transfer_is_not_a_cancelled_transfer() {
        let flag = SignalFlag::new();
        let mut usb = FakeUsb::with_sensor();
        usb.signal_during_command = Some(flag.clone());

        // The signal is raised while the 0x24 response is in flight. The handshake still finishes
        // and releases the handle: only the exit status remembers the interruption.
        let (code, out, err) = run_with(&["handshake"], &mut usb, &flag);

        assert_eq!(code, 130);
        assert_eq!(err, "cvctl: interrupted by signal 2\n");
        assert!(
            out.contains(&format!("handle {TEST_HANDLE:#010x}")),
            "{out}"
        );
        assert!(out.contains("client nonce 20 bytes"), "{out}");
        assert_eq!(
            sent_commands(&usb),
            [cmd::CHALLENGE, cmd::CHALLENGE_RESPONSE, cmd::CLOSE_SESSION,],
            "the command after the signal was still sent: the transfer was never cancelled"
        );
    }

    #[test]
    fn verify_prints_the_verdict_value_and_lengths_then_tears_down() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert_eq!(
            out,
            verify_output(VERDICT_MATCH, Some(&MATCH_VALUE), 108, 52),
            "the verdict, the value and both lengths"
        );
        assert_eq!(
            sent_commands(&usb),
            [
                cmd::CHALLENGE,
                cmd::CHALLENGE_RESPONSE,
                cmd::OPEN_SESSION,
                cmd::ARM_CAPTURE,
                cmd::MATCH,
                cmd::CANCEL_CAPTURE,
                cmd::CLOSE_SESSION,
            ],
            "a successful verify tears down with 0x68 then 0x04 before exiting"
        );

        let match_frame = sent_command(&usb, cmd::MATCH).expect("0x73 was sent");
        assert_eq!(match_frame[10], attr::CAPTURE);
        assert_eq!(match_frame[11], 0x02, "the match is wrapped");
        assert_eq!(le32(&match_frame, 16), TEST_HANDLE);
        assert_eq!(
            le32(&match_frame, 40),
            68,
            "the firmware-shaped 68-byte TLV"
        );
        assert_eq!(match_frame.len(), 172, "112 plaintext bytes plus padding");
    }

    #[test]
    fn verify_reports_a_no_match_with_its_own_exit_code_and_the_same_detail() {
        let mut usb = FakeUsb::with_sensor();
        usb.match_plaintext = Some(match_plaintext(0, Some(&MATCH_VALUE)));
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_NO_MATCH);
        assert_ne!(code, EXIT_OTHER);
        assert_ne!(code, EXIT_TRANSPORT);
        assert_eq!(err, "");
        assert_eq!(
            out,
            verify_output(VERDICT_NO_MATCH, Some(&MATCH_VALUE), 108, 52),
            "a no-match carries the value when the reply supplies it"
        );
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn verify_reports_a_no_match_without_a_value_as_absent() {
        let mut usb = FakeUsb::with_sensor();
        usb.match_plaintext = Some(match_plaintext(0, None));
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_NO_MATCH);
        assert_eq!(err, "");
        assert_eq!(out, verify_output(VERDICT_NO_MATCH, None, 76, 28));
        assert!(out.contains("value absent"), "{out}");
    }

    #[test]
    fn a_short_match_reply_is_malformed_not_a_no_match() {
        let mut usb = FakeUsb::with_sensor();
        // Eleven bytes: enough to unwrap, too short for the verdict word at +8.
        let mut plaintext = vec![0u8; 11];
        plaintext[8..11].copy_from_slice(&[0, 0, 0]);
        usb.match_plaintext = Some(plaintext);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OTHER);
        assert_eq!(out, "", "a malformed reply is never printed as a no-match");
        assert!(err.contains("too short for the verdict word"), "{err}");
        assert!(err.contains("not a no-match"), "{err}");
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn verify_capture_timeout_and_transport_error_are_distinct() {
        let shutdown = SignalFlag::new();

        let mut timeout = FakeUsb::with_sensor();
        timeout.finger_event = Some(Err(UsbError::Timeout));
        let (timeout_code, timeout_out, timeout_err) =
            run_with(&["verify"], &mut timeout, &shutdown);
        assert_eq!(timeout_code, EXIT_FINGER_TIMEOUT);
        assert_eq!(timeout_out, "");
        assert!(timeout_err.contains("finger timeout"), "{timeout_err}");
        assert!(sent_command(&timeout, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&timeout, cmd::CLOSE_SESSION).is_some());

        let mut transport = FakeUsb::with_sensor();
        transport.match_command_error = Some(UsbError::Timeout);
        let (transport_code, transport_out, transport_err) =
            run_with(&["verify"], &mut transport, &shutdown);
        assert_eq!(transport_code, EXIT_TRANSPORT);
        assert_ne!(transport_code, timeout_code);
        assert_eq!(transport_out, "");
        assert!(
            transport_err.contains("transport failed"),
            "a transport failure names itself: {transport_err}"
        );
        assert_ne!(transport_err, timeout_err, "the messages are distinct");
        assert!(sent_command(&transport, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&transport, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn verify_with_a_match_transport_error_is_not_a_finger_timeout() {
        let mut usb = FakeUsb::with_sensor();
        usb.arm_command_error = Some(UsbError::Disconnected);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_TRANSPORT);
        assert_eq!(out, "");
        assert!(err.contains("transport failed"), "{err}");
        assert!(err.contains("disconnected"), "{err}");
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn verify_reports_capture_pending_with_its_own_exit_code_and_tears_down() {
        let mut usb = FakeUsb::with_sensor();
        usb.arm_status = 0x85;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_CAPTURE_PENDING);
        assert_eq!(out, "");
        assert!(err.contains("already armed"), "{err}");
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn verify_reports_a_match_sequence_failure_with_the_sequence_code() {
        let mut usb = FakeUsb::with_sensor();
        usb.match_status = 0x0f;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_SEQUENCE);
        assert_eq!(out, "");
        assert!(err.contains("wrap sequence"), "{err}");
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn verify_prints_an_unexpected_verdict_word_and_still_exits_no_match() {
        let mut usb = FakeUsb::with_sensor();
        usb.match_plaintext = Some(match_plaintext(2, Some(&MATCH_VALUE)));
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_NO_MATCH);
        assert_eq!(err, "");
        assert_eq!(
            out,
            verify_output(2, Some(&MATCH_VALUE), 108, 52),
            "an undefined word is printed raw and never treated as a match"
        );
    }

    #[test]
    fn verify_rejects_record_because_recordings_are_wire_only() {
        let record = TempRecord::new("verify-record");
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) =
            run_with(&["verify", "--record", record.path()], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OTHER);
        assert_eq!(out, "");
        assert_eq!(err, format!("{USAGE}\n"));
        assert!(!record.exists(), "no transcript is written");
        assert!(usb.calls().is_empty(), "nothing touches the sensor");
    }

    #[test]
    fn replay_rejects_a_verify_transcript_as_unknown() {
        let record = TempRecord::new("verify-unknown");
        record.write(&Transcript::new("verify").to_bytes());
        let mut usb = FakeUsb::default();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["replay", record.path()], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OTHER);
        assert_eq!(out, "");
        assert!(err.contains("unknown command"), "{err}");
        assert!(usb.calls().is_empty());
    }

    #[test]
    fn replay_rejects_an_unknown_transcript_version() {
        let record = TempRecord::new("unknown-version");
        let mut bytes = Transcript::new("handshake").to_bytes();
        bytes[8..10].copy_from_slice(&99u16.to_le_bytes());
        record.write(&bytes);
        let mut usb = FakeUsb::default();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["replay", record.path()], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OTHER);
        assert_eq!(out, "");
        assert!(err.contains("invalid transcript"), "{err}");
        assert!(err.contains("version 99"), "{err}");
        assert!(usb.calls().is_empty());
    }
}
