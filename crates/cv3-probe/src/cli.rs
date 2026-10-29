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
use cv3_core::inventory::{Inventory, InventoryError, InventoryReply, scan_tlv};
use cv3_core::proto::cmd;
use cv3_core::session::{
    CloseError, CloseSession, OpenError, OpenSession, Session, Teardown, TeardownError,
};
use cv3_core::transcript::{RecordingTransport, ReplayTransport, Transcript};
use cv3_core::transport::{Transport, run as drive};
use cv3_core::verify::{
    MATCH_VALUE_LEN, MatchError, VALUE_OFFSET, VERDICT_MATCH, VERDICT_NO_MATCH, VERDICT_OFFSET,
    Verdict, Verification, Verify, VerifyError,
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
       cvctl inventory [--hex]
       cvctl enroll [--commit-sample-hash] [--show-commit] [--hex]
       cvctl enroll-then-verify [--commit-sample-hash] [--show-commit] [--command <2f|72|73>] [--handle <u32>]... [--hex]
       cvctl verify [--template <40 hex>] [--handle <u32>]... [--command <2f|72|73>] [--hex]
       cvctl cancel-then-verify [--retry-next] [--hex]
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
    Inventory {
        hex: bool,
    },
    Enroll {
        hex: bool,
        commit_sample_hash: bool,
        show_commit: bool,
    },
    EnrollThenVerify {
        hex: bool,
        commit_sample_hash: bool,
        show_commit: bool,
        /// The match request's command; the default depends on the arguments.
        command: u16,
        /// `u32` template handles for the request's type-2 array, in order.
        handles: Vec<u32>,
    },
    Verify {
        hex: bool,
        template: Option<[u8; cv3_core::verify::MATCH_VALUE_LEN]>,
        /// `u32` template handles for the request's type-2 array, in order.
        handles: Vec<u32>,
        /// The match request's command; the default depends on the arguments.
        command: u16,
    },
    CancelThenVerify {
        hex: bool,
        retry_next: bool,
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
    template: Option<[u8; cv3_core::verify::MATCH_VALUE_LEN]>,
    retry_next: bool,
    commit_sample_hash: bool,
    show_commit: bool,
    handles: Vec<u32>,
    command: Option<u16>,
}

/// Which optional flags a subcommand accepts. Every one defaults to refused, so a flag on the
/// wrong command is a usage error rather than silently ignored.
#[derive(Clone, Copy, Default)]
struct Accepted {
    show_key: bool,
    bad_sequence: bool,
    record: bool,
    template: bool,
    retry_next: bool,
    commit_sample_hash: bool,
    show_commit: bool,
    handle: bool,
    command: bool,
}

/// Parses the command line by hand: no dependency, and every unknown or repeated flag is a usage
/// error rather than something silently ignored.
fn parse(args: &[String]) -> Option<Command<'_>> {
    let (command, rest) = args.split_first()?;
    match command.as_str() {
        "devices" if rest.is_empty() => Some(Command::Devices),
        "handshake" => {
            let flags = parse_flags(
                rest,
                Accepted {
                    show_key: true,
                    record: true,
                    ..Accepted::default()
                },
            )?;
            Some(Command::Handshake {
                show_key: flags.show_key,
                hex: flags.hex,
                record: flags.record,
            })
        }
        "open" => {
            let flags = parse_flags(
                rest,
                Accepted {
                    bad_sequence: true,
                    record: true,
                    ..Accepted::default()
                },
            )?;
            Some(Command::Open {
                bad_sequence: flags.bad_sequence,
                hex: flags.hex,
                record: flags.record,
            })
        }
        "close" => {
            let flags = parse_flags(
                rest,
                Accepted {
                    record: true,
                    ..Accepted::default()
                },
            )?;
            Some(Command::Close {
                hex: flags.hex,
                record: flags.record,
            })
        }
        "capture" => {
            let flags = parse_flags(rest, Accepted::default())?;
            Some(Command::Capture { hex: flags.hex })
        }
        "inventory" => {
            let flags = parse_flags(rest, Accepted::default())?;
            Some(Command::Inventory { hex: flags.hex })
        }
        "enroll" => {
            let flags = parse_flags(
                rest,
                Accepted {
                    commit_sample_hash: true,
                    show_commit: true,
                    ..Accepted::default()
                },
            )?;
            Some(Command::Enroll {
                hex: flags.hex,
                commit_sample_hash: flags.commit_sample_hash,
                show_commit: flags.show_commit,
            })
        }
        "enroll-then-verify" => {
            let flags = parse_flags(
                rest,
                Accepted {
                    commit_sample_hash: true,
                    show_commit: true,
                    handle: true,
                    command: true,
                    ..Accepted::default()
                },
            )?;
            Some(Command::EnrollThenVerify {
                hex: flags.hex,
                commit_sample_hash: flags.commit_sample_hash,
                show_commit: flags.show_commit,
                command: flags.command.unwrap_or(if flags.handles.is_empty() {
                    cmd::IDENTIFY
                } else {
                    cmd::IDENTIFY_HANDLES
                }),
                handles: flags.handles,
            })
        }
        "verify" => {
            let flags = parse_flags(
                rest,
                Accepted {
                    template: true,
                    handle: true,
                    command: true,
                    ..Accepted::default()
                },
            )?;
            Some(Command::Verify {
                hex: flags.hex,
                template: flags.template,
                command: flags.command.unwrap_or(if flags.template.is_some() {
                    cmd::IDENTIFY
                } else {
                    cmd::IDENTIFY_HANDLES
                }),
                handles: flags.handles,
            })
        }
        "cancel-then-verify" => {
            let flags = parse_flags(
                rest,
                Accepted {
                    retry_next: true,
                    ..Accepted::default()
                },
            )?;
            Some(Command::CancelThenVerify {
                hex: flags.hex,
                retry_next: flags.retry_next,
            })
        }
        "replay" => match rest {
            [file] => Some(Command::Replay { file }),
            _ => None,
        },
        _ => None,
    }
}

fn parse_flags<'a>(args: &'a [String], accepted: Accepted) -> Option<Flags<'a>> {
    let mut flags = Flags {
        show_key: false,
        bad_sequence: false,
        hex: false,
        record: None,
        template: None,
        retry_next: false,
        commit_sample_hash: false,
        show_commit: false,
        handles: Vec::new(),
        command: None,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--show-key" if accepted.show_key && !flags.show_key => flags.show_key = true,
            "--bad-sequence" if accepted.bad_sequence && !flags.bad_sequence => {
                flags.bad_sequence = true;
            }
            "--commit-sample-hash" if accepted.commit_sample_hash && !flags.commit_sample_hash => {
                flags.commit_sample_hash = true;
            }
            "--show-commit" if accepted.show_commit && !flags.show_commit => {
                flags.show_commit = true;
            }
            "--hex" if !flags.hex => flags.hex = true,
            "--record" if accepted.record && flags.record.is_none() => {
                index += 1;
                flags.record = Some(args.get(index)?.as_str());
            }
            "--template" if accepted.template && flags.template.is_none() => {
                index += 1;
                flags.template = Some(parse_template(args.get(index)?)?);
            }
            "--retry-next" if accepted.retry_next && !flags.retry_next => {
                flags.retry_next = true;
            }
            "--handle" if accepted.handle => {
                index += 1;
                for text in args.get(index)?.split(',') {
                    flags.handles.push(parse_handle(text)?);
                }
            }
            "--command" if accepted.command && flags.command.is_none() => {
                index += 1;
                flags.command = Some(parse_command(args.get(index)?)?);
            }
            _ => return None,
        }
        index += 1;
    }
    Some(flags)
}

/// Parses exactly forty hex digits into the 20-byte template id a verify request names.
fn parse_template(text: &str) -> Option<[u8; cv3_core::verify::MATCH_VALUE_LEN]> {
    if text.len() != 40 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut id = [0u8; cv3_core::verify::MATCH_VALUE_LEN];
    for (index, slot) in id.iter_mut().enumerate() {
        let high = (text.as_bytes()[2 * index] as char).to_digit(16)? as u8;
        let low = (text.as_bytes()[2 * index + 1] as char).to_digit(16)? as u8;
        *slot = (high << 4) | low;
    }
    Some(id)
}

/// Parses one `--handle` value: decimal, or hexadecimal with a `0x` prefix.
///
/// Each value becomes one `u32` entry in the request's type-2 template-handle array.
fn parse_handle(text: &str) -> Option<u32> {
    let (digits, radix) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (text, 10),
    };
    if digits.is_empty() {
        return None;
    }
    u32::from_str_radix(digits, radix).ok()
}

/// Parses the probe's `--command` selector into the match request's command word.
///
/// `73` is identify, the vendor's one-to-many match and the probe's default. `72` is the
/// one-to-one verify, kept so a hardware run can compare the two commands.
fn parse_command(text: &str) -> Option<u16> {
    match text {
        "72" => Some(cmd::VERIFY),
        "73" => Some(cmd::IDENTIFY),
        "2f" => Some(cmd::IDENTIFY_HANDLES),
        _ => None,
    }
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
        Some(Command::Inventory { hex }) => inventory(backend, shutdown, hex, out, err),
        Some(Command::Enroll {
            hex,
            commit_sample_hash,
            show_commit,
        }) => enroll(
            backend,
            shutdown,
            hex,
            commit_sample_hash,
            show_commit,
            out,
            err,
        ),
        Some(Command::EnrollThenVerify {
            hex,
            commit_sample_hash,
            show_commit,
            command,
            handles,
        }) => {
            let flags = EnrollThenVerifyFlags {
                commit_sample_hash,
                show_commit,
                command,
                handles: &handles,
            };
            enroll_then_verify(backend, shutdown, hex, flags, out, err)
        }
        Some(Command::Verify {
            hex,
            template,
            handles,
            command,
        }) => {
            let flags = MatchFlags {
                template,
                handles: &handles,
                command,
            };
            verify(backend, shutdown, hex, flags, out, err)
        }
        Some(Command::CancelThenVerify { hex, retry_next }) => {
            cancel_then_verify(backend, shutdown, hex, retry_next, out, err)
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

/// What one whole capture produced: the sample hash, the decrypted arm reply and the teardown.
type CaptureRun = ([u8; SAMPLE_HASH_LEN], Vec<u8>, Result<(), TeardownError>);

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
) -> Result<CaptureRun, CaptureFailure> {
    let run = handshake_over(transport, secrets, true).map_err(CaptureFailure::Handshake)?;
    let mut open = OpenSession::new(run.session, open_iv);
    let session = drive(&mut open, transport).map_err(CaptureFailure::Open)?;

    let mut capture = Capture::new(session, capture_iv);
    match drive(&mut capture, transport) {
        Ok(CapturedSample {
            sample_hash,
            plaintext,
            session,
        }) => {
            let mut teardown = Teardown::new(session.handle);
            drop(session);
            Ok((sample_hash, plaintext, drive(&mut teardown, transport)))
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
    // The session sends no timestamp at open: the transport answers a type-5 event when the
    // sensor raises it, below the transport seam, so the dump shows those after the operation.
    let outcome = match record {
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
    };
    dump_timestamps(channel, dump_hex, err);
    outcome
}

/// Writes the timestamp syncs sent since the last call as host-side control lines.
///
/// They have no bulk frame, so they do not share the `> ` prefix; `* ` marks a host control
/// transfer in the same dump. Without `--hex` nothing is written.
fn dump_timestamps(channel: &mut CommandSession, dump_hex: bool, err: &mut dyn Write) {
    if !dump_hex {
        return;
    }
    for packed in channel.take_timestamps() {
        let _ = writeln!(err, "* timestamp {packed:08x}");
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
    let mut channel = match open_for_command(backend, shutdown, err) {
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
    let mut channel = match open_for_command(backend, shutdown, err) {
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
    let mut channel = match open_for_command(backend, shutdown, err) {
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
    let mut channel = match open_for_command(backend, shutdown, err) {
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
        Ok((sample_hash, plaintext, teardown)) => {
            let _ = writeln!(out, "sample hash {}", hex(&sample_hash));
            if dump_hex {
                let _ = writeln!(out, "capture plaintext length {}", plaintext.len());
                print_plaintext_dump(&plaintext, out);
            }
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

/// Where an inventory run stopped.
enum InventoryFailure {
    Handshake(HandshakeError),
    Open(OpenError),
    Inventory(InventoryError),
}

/// The reply an inventory run reports, after its session has been torn down.
struct InventoryDump {
    reply_len: usize,
    plaintext: Vec<u8>,
}

/// Opens the secure session, sends the wrapped `0x2F` query, tears the session down and returns
/// the reply lengths and plaintext.
///
/// An inventory failure has already torn the session down; a successful query is torn down here
/// because the probe keeps no session between invocations.
fn inventory_over(
    transport: &mut dyn Transport,
    secrets: RunSecrets,
    open_iv: [u8; BLOCK_LEN],
    inventory_iv: [u8; BLOCK_LEN],
) -> Result<(InventoryDump, Result<(), TeardownError>), InventoryFailure> {
    let run = handshake_over(transport, secrets, true).map_err(InventoryFailure::Handshake)?;
    let mut open = OpenSession::new(run.session, open_iv);
    let session = drive(&mut open, transport).map_err(InventoryFailure::Open)?;

    let mut inventory = Inventory::new(session, inventory_iv);
    match drive(&mut inventory, transport) {
        Ok(InventoryReply {
            reply_len,
            plaintext,
            session,
        }) => {
            let mut teardown = Teardown::new(session.handle);
            drop(session);
            Ok((
                InventoryDump {
                    reply_len,
                    plaintext,
                },
                drive(&mut teardown, transport),
            ))
        }
        Err(error) => Err(InventoryFailure::Inventory(error)),
    }
}

/// Prints both lengths, the plaintext in 16-byte rows and a best-effort TLV scan of it.
///
/// Nothing here decodes what the entries mean: whether `0x2F` reports stored templates at all is
/// ticket 16's question, and this command only shows what the sensor sent.
fn print_inventory_dump(dump: &InventoryDump, out: &mut dyn Write) {
    let _ = writeln!(out, "reply length {}", dump.reply_len);
    let _ = writeln!(out, "plaintext length {}", dump.plaintext.len());
    let _ = writeln!(out, "plaintext:");
    for (row, chunk) in dump.plaintext.chunks(16).enumerate() {
        let _ = write!(out, "{:04x}:", row * 16);
        for byte in chunk {
            let _ = write!(out, " {byte:02x}");
        }
        let _ = writeln!(out);
    }

    let scan = scan_tlv(&dump.plaintext);
    if scan.entries.is_empty() {
        let _ = writeln!(out, "tlv: no entries");
    } else {
        let _ = writeln!(out, "tlv:");
        for entry in &scan.entries {
            let _ = write!(
                out,
                "+{:04x} tag {} length {}",
                entry.offset, entry.tag, entry.declared_len
            );
            if entry.value.is_empty() {
                let _ = write!(out, " value -");
            } else {
                let _ = write!(out, " value {}", hex(entry.value));
            }
            if entry.is_truncated() {
                let _ = write!(
                    out,
                    " (truncated: {} of {} bytes present)",
                    entry.value.len(),
                    entry.declared_len
                );
            }
            let _ = writeln!(out);
        }
    }
    if scan.trailing > 0 {
        let _ = writeln!(out, "trailing {} bytes", scan.trailing);
    }
}

/// Runs the ticket-16 measurement: handshake, open, inventory query, dump, teardown.
fn inventory(
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
    let inventory_iv = match random_iv() {
        Ok(iv) => iv,
        Err(error) => {
            let _ = writeln!(err, "cvctl: {error}");
            return EXIT_OTHER;
        }
    };
    let mut channel = match open_for_command(backend, shutdown, err) {
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
        "inventory",
        None,
        dump_hex,
        err,
        |transport| inventory_over(transport, secrets, open_iv, inventory_iv),
    );

    let code = match outcome {
        Ok((dump, teardown)) => {
            print_inventory_dump(&dump, out);
            if let Err(error) = teardown {
                let _ = writeln!(err, "cvctl: {error}");
            }
            EXIT_OK
        }
        Err(InventoryFailure::Handshake(error)) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            handshake_error_code(&error)
        }
        Err(InventoryFailure::Open(error)) => {
            let _ = writeln!(err, "cvctl: {error}");
            open_error_code(&error)
        }
        Err(InventoryFailure::Inventory(error)) => {
            let _ = writeln!(err, "cvctl: inventory failed: {error}");
            inventory_error_code(&error)
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
    /// The decrypted `0x6E` reply, printed only with `--show-commit`.
    commit_plaintext: Vec<u8>,
    /// The raw wrapped `0x6E` reply length, header included.
    commit_reply_len: usize,
}

/// Drives a whole enrolment over an open session and returns the committed template **with the
/// session still open**, printing progress as samples are accepted or rejected.
///
/// The operation is driven one event at a time rather than through [`drive`] so its
/// [`Enrol::progress`] can be read between steps and printed. The core stays callback-free.
/// The caller owns the teardown: `cvctl enroll` tears down straight away, while
/// `cvctl enroll-then-verify` keeps the session for the confirmation touch.
fn enrol_session(
    transport: &mut dyn Transport,
    session: Session,
    base_iv: [u8; BLOCK_LEN],
    commit_sample_hash: bool,
    progress_out: &mut dyn Write,
) -> Result<EnrolledTemplate, EnrolError> {
    let mut enrol = Enrol::new(session, base_iv);
    if commit_sample_hash {
        enrol = enrol.with_commit_sample_hash();
    }
    let mut action = enrol.start();
    let mut shown_accepted = 0usize;
    let mut shown_rejected = 0usize;
    loop {
        match action {
            Action::Send(frame) => action = enrol.step(transport.command(&frame)),
            Action::WaitFinger => action = enrol.step(transport.wait_finger()),
            Action::Finish(result) => return result,
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
    }
}

/// Opens the secure session, runs a whole enrolment, prints progress as samples are accepted and
/// tears the session down afterwards.
///
/// A failed enrolment has already torn the session down; a successful one is torn down here,
/// because `cvctl enroll` does not perform the binding confirmation.
fn enrol_over(
    transport: &mut dyn Transport,
    secrets: RunSecrets,
    open_iv: [u8; BLOCK_LEN],
    base_iv: [u8; BLOCK_LEN],
    commit_sample_hash: bool,
    progress_out: &mut dyn Write,
) -> Result<(EnrolReport, Result<(), TeardownError>), EnrolFailure> {
    let run = handshake_over(transport, secrets, true).map_err(EnrolFailure::Handshake)?;
    let mut open = OpenSession::new(run.session, open_iv);
    let session = drive(&mut open, transport).map_err(EnrolFailure::Open)?;

    match enrol_session(
        transport,
        session,
        base_iv,
        commit_sample_hash,
        progress_out,
    ) {
        Ok(EnrolledTemplate {
            template_id,
            source,
            commit_plaintext,
            commit_reply_len,
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
                    commit_plaintext,
                    commit_reply_len,
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
    commit_sample_hash: bool,
    show_commit: bool,
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
    let mut channel = match open_for_command(backend, shutdown, err) {
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
        enrol_over(
            transport,
            secrets,
            open_iv,
            base_iv,
            commit_sample_hash,
            out,
        )
    });
    let code = match outcome {
        Ok((report, teardown)) => {
            print_template(out, &report.template_id, report.source);
            if show_commit {
                print_commit_dump(&report, out);
            }
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

/// Where an enrol-then-verify run stopped.
enum EnrollThenVerifyFailure {
    Handshake(HandshakeError),
    Open(OpenError),
    /// The enrolment failed; its own teardown has run.
    Enrol(EnrolError),
    /// The confirmation capture or match failed; verification's own teardown has run.
    Verify(VerifyError),
}

/// The measurement flags `verify` accepts: an optional hash entry and the type-2 handle array.
#[derive(Clone, Copy)]
struct MatchFlags<'a> {
    template: Option<[u8; cv3_core::verify::MATCH_VALUE_LEN]>,
    handles: &'a [u32],
    command: u16,
}

/// The measurement flags `enroll-then-verify` accepts.
#[derive(Clone, Copy)]
struct EnrollThenVerifyFlags<'a> {
    commit_sample_hash: bool,
    show_commit: bool,
    command: u16,
    handles: &'a [u32],
}

/// The IVs and measurement variants one enrol-then-verify run uses.
///
/// One IV per wrapped request, because CBC needs a distinct IV for every frame, plus the
/// `--commit-sample-hash` and `--show-commit` flags, the confirmation request's command and its
/// `u32` template handles.
#[derive(Clone, Copy)]
struct EnrollThenVerifyOptions<'a> {
    open_iv: [u8; BLOCK_LEN],
    enrol_iv: [u8; BLOCK_LEN],
    capture_iv: [u8; BLOCK_LEN],
    match_iv: [u8; BLOCK_LEN],
    commit_sample_hash: bool,
    show_commit: bool,
    match_command: u16,
    handles: &'a [u32],
}

/// Opens **one** session, enrols and commits in it, then takes the confirmation touch and verifies
/// it in that same session.
///
/// The wire order is `0x02`, `0x6D`, `0x8A`, (`0x66`, `0x6C`) once per sample, `0x6E`, one more
/// `0x66`, then the match request (`0x73` identify by default, `0x72` with `--command 72`),
/// followed by the cancel-then-close teardown. The template id is printed before the confirmation
/// so a failed confirmation still reports what was committed. This is ticket 09's measurement tool:
/// it reports the value the verdict returns but never compares it with the enrolment id, because
/// ticket 10 owns binding.
fn enroll_then_verify_over(
    transport: &mut dyn Transport,
    secrets: RunSecrets,
    options: EnrollThenVerifyOptions<'_>,
    out: &mut dyn Write,
) -> Result<(Verdict, Result<(), TeardownError>), EnrollThenVerifyFailure> {
    let EnrollThenVerifyOptions {
        open_iv,
        enrol_iv,
        capture_iv,
        match_iv,
        commit_sample_hash,
        show_commit,
        match_command,
        handles,
    } = options;
    let run =
        handshake_over(transport, secrets, true).map_err(EnrollThenVerifyFailure::Handshake)?;
    let mut open = OpenSession::new(run.session, open_iv);
    let session = drive(&mut open, transport).map_err(EnrollThenVerifyFailure::Open)?;

    let EnrolledTemplate {
        template_id,
        source,
        commit_plaintext,
        commit_reply_len,
        session,
        ..
    } = enrol_session(transport, session, enrol_iv, commit_sample_hash, out)
        .map_err(EnrollThenVerifyFailure::Enrol)?;
    print_template(out, &template_id, source);
    if show_commit {
        let report = EnrolReport {
            template_id,
            source,
            commit_plaintext,
            commit_reply_len,
        };
        print_commit_dump(&report, out);
    }
    let _ = writeln!(out, "match template id {}", hex(&template_id));

    let mut verify = Verify::new(session, capture_iv, match_iv)
        .with_template_id(Some(template_id))
        .with_command(match_command);
    for handle in handles {
        verify = verify.with_template_handle(*handle);
    }
    match drive(&mut verify, transport) {
        Ok(Verification { verdict, session }) => {
            let mut teardown = Teardown::new(session.handle);
            drop(session);
            Ok((verdict, drive(&mut teardown, transport)))
        }
        Err(error) => Err(EnrollThenVerifyFailure::Verify(error)),
    }
}

/// Runs the ticket-09 measurement: enrol, commit, confirmation touch and match in one session.
fn enroll_then_verify(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    dump_hex: bool,
    flags: EnrollThenVerifyFlags<'_>,
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
    let [open_iv, enrol_iv, capture_iv, match_iv] = ivs;
    let options = EnrollThenVerifyOptions {
        open_iv,
        enrol_iv,
        capture_iv,
        match_iv,
        commit_sample_hash: flags.commit_sample_hash,
        show_commit: flags.show_commit,
        match_command: flags.command,
        handles: flags.handles,
    };

    let mut channel = match open_for_command(backend, shutdown, err) {
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
        "enroll-then-verify",
        None,
        dump_hex,
        err,
        |transport| enroll_then_verify_over(transport, secrets, options, out),
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
        Err(EnrollThenVerifyFailure::Handshake(error)) => {
            let _ = writeln!(err, "cvctl: handshake failed: {error}");
            handshake_error_code(&error)
        }
        Err(EnrollThenVerifyFailure::Open(error)) => {
            let _ = writeln!(err, "cvctl: {error}");
            open_error_code(&error)
        }
        Err(EnrollThenVerifyFailure::Enrol(error)) => {
            let _ = writeln!(err, "cvctl: enrolment failed: {error}");
            enrol_error_code(&error)
        }
        Err(EnrollThenVerifyFailure::Verify(error)) => {
            print_match_failure(&error, out);
            let _ = writeln!(err, "cvctl: verification failed: {error}");
            verify_error_code(&error)
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

/// Opens the secure session, captures a finger, then sends the verify request, and tears the
/// session down afterwards.
///
/// A capture or verify failure has already torn the session down; a successful verification is
/// torn down here because the probe does not keep a session between invocations. The verdict is
/// returned with the teardown's own best-effort result.
fn verify_over(
    transport: &mut dyn Transport,
    secrets: RunSecrets,
    open_iv: [u8; cv3_core::crypto::BLOCK_LEN],
    capture_iv: [u8; cv3_core::crypto::BLOCK_LEN],
    match_iv: [u8; cv3_core::crypto::BLOCK_LEN],
    flags: MatchFlags<'_>,
) -> Result<(Verdict, Result<(), TeardownError>), VerifyFailure> {
    let run = handshake_over(transport, secrets, true).map_err(VerifyFailure::Handshake)?;
    let mut open = OpenSession::new(run.session, open_iv);
    let session = drive(&mut open, transport).map_err(VerifyFailure::Open)?;

    let mut verify = Verify::new(session, capture_iv, match_iv)
        .with_template_id(flags.template)
        .with_command(flags.command);
    for handle in flags.handles {
        verify = verify.with_template_handle(*handle);
    }
    match drive(&mut verify, transport) {
        Ok(Verification { verdict, session }) => {
            let mut teardown = Teardown::new(session.handle);
            drop(session);
            Ok((verdict, drive(&mut teardown, transport)))
        }
        Err(error) => Err(VerifyFailure::Verify(error)),
    }
}

/// Prints a decrypted plaintext in 16-byte hex rows with offsets, then its TLV scan.
///
/// The rows are the inventory dump's style. The scan is best effort and never panics on device
/// bytes; an empty or too-short plaintext prints `tlv: none`.
fn print_plaintext_dump(plaintext: &[u8], out: &mut dyn Write) {
    let _ = writeln!(out, "plaintext:");
    for (row, chunk) in plaintext.chunks(16).enumerate() {
        let _ = write!(out, "{:04x}:", row * 16);
        for byte in chunk {
            let _ = write!(out, " {byte:02x}");
        }
        let _ = writeln!(out);
    }

    let scan = scan_tlv(plaintext);
    if scan.entries.is_empty() {
        let _ = writeln!(out, "tlv: none");
        return;
    }
    let _ = writeln!(out, "tlv:");
    for entry in &scan.entries {
        let _ = write!(out, "type={} len={}", entry.tag, entry.declared_len);
        if entry.value.is_empty() {
            let _ = write!(out, " value=-");
        } else {
            let _ = write!(out, " value={}", hex(entry.value));
        }
        if entry.is_truncated() {
            let _ = write!(
                out,
                " (truncated: {} of {} bytes present)",
                entry.value.len(),
                entry.declared_len
            );
        }
        let _ = writeln!(out);
    }
}

/// Prints the decrypted `0x6E` commit reply for `--show-commit`.
///
/// The vendor's commit reply is saved through an out list of a type-3 blob and a type-0 `u32`;
/// that `u32` is the template handle identify later names. This dump is how the next hardware run
/// measures it, so it uses the same rows and scan as the match reply.
fn print_commit_dump(report: &EnrolReport, out: &mut dyn Write) {
    let _ = writeln!(out, "commit reply length {}", report.commit_reply_len);
    let _ = writeln!(
        out,
        "commit plaintext length {}",
        report.commit_plaintext.len()
    );
    print_plaintext_dump(&report.commit_plaintext, out);
}

/// Prints the command, status and reply detail of a refused match request.
///
/// A refusal can still carry a decryptable body, so the same fields the success path prints are
/// derived from it when it is long enough. The word is reported raw; a refusal is never treated as
/// a match, and `plaintext absent` says the body did not decrypt.
fn print_status_diagnostics(
    command: u16,
    status: u32,
    reply_len: usize,
    plaintext: Option<&[u8]>,
    out: &mut dyn Write,
) {
    let _ = writeln!(out, "command 0x{command:02x}");
    let _ = writeln!(out, "status 0x{status:02x}");
    if let Some(bytes) = plaintext.filter(|bytes| bytes.len() >= VERDICT_OFFSET + 4) {
        let _ = writeln!(out, "{}", verdict_line(le32(bytes, VERDICT_OFFSET)));
        match value_at(bytes) {
            Some(value) => {
                let _ = writeln!(out, "value {}", hex(&value));
            }
            None => {
                let _ = writeln!(out, "value absent");
            }
        }
    }
    let _ = writeln!(out, "reply length {reply_len}");
    match plaintext {
        Some(bytes) => {
            let _ = writeln!(out, "plaintext length {}", bytes.len());
            print_plaintext_dump(bytes, out);
        }
        None => {
            let _ = writeln!(out, "plaintext absent");
        }
    }
}

/// The `verdict <word> (<meaning>)` line both the success and refusal dumps print.
fn verdict_line(word: u32) -> String {
    let meaning = match word {
        VERDICT_MATCH => "match",
        VERDICT_NO_MATCH => "no match",
        _ => "no match, unexpected word",
    };
    format!("verdict {word} ({meaning})")
}

/// The twenty bytes at plaintext `+32`, when the plaintext carries them.
fn value_at(plaintext: &[u8]) -> Option<[u8; MATCH_VALUE_LEN]> {
    if plaintext.len() < VALUE_OFFSET + MATCH_VALUE_LEN {
        return None;
    }
    let mut value = [0u8; MATCH_VALUE_LEN];
    value.copy_from_slice(&plaintext[VALUE_OFFSET..VALUE_OFFSET + MATCH_VALUE_LEN]);
    Some(value)
}

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Prints the status diagnostics of a refused composed match, before its error line.
fn print_match_failure(error: &VerifyError, out: &mut dyn Write) {
    if let VerifyError::Match(MatchError::SensorStatus {
        command,
        status,
        reply_len,
        plaintext,
    }) = error
    {
        print_status_diagnostics(*command, *status, *reply_len, plaintext.as_deref(), out);
    }
}

/// Prints the command sent, the raw reply status, the decoded verdict word, the 20-byte value (or
/// its absence), both lengths, and the decrypted plaintext with its TLV scan.
///
/// The command comes from the verdict, so the line is what went on the wire rather than what the
/// caller meant to send. The status is printed raw because it is the measurement: `0x00` and the
/// vendor-special-cased `0x89` are both answered, and only a hardware run settles which one a match
/// carries.
fn print_verdict(verdict: &Verdict, out: &mut dyn Write) {
    let _ = writeln!(out, "command 0x{:02x}", verdict.command);
    let _ = writeln!(out, "status 0x{:02x}", verdict.status);
    let _ = writeln!(out, "{}", verdict_line(verdict.word));
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
    if let Some(plaintext) = &verdict.plaintext {
        print_plaintext_dump(plaintext, out);
    }
}

/// Prints the committed template id and its source.
///
/// When `--commit-sample-hash` overrode an enrolment id the sensor sent, an explicit line says so:
/// the point of the flag is to make that measurement visible in the output.
fn print_template(
    out: &mut dyn Write,
    template_id: &[u8; SAMPLE_HASH_LEN],
    source: TemplateSource,
) {
    if source == TemplateSource::ForcedSampleHash {
        let _ = writeln!(out, "--commit-sample-hash forced the sample hash");
    }
    let _ = writeln!(out, "template id {} ({source})", hex(template_id));
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
        VerifyError::Match(MatchError::SensorStatus { status, .. })
            if *status == status::BAD_SEQUENCE =>
        {
            EXIT_SEQUENCE
        }
        VerifyError::Match(MatchError::SensorStatus { status, .. })
            if *status == status::CAPTURE_PENDING =>
        {
            EXIT_CAPTURE_PENDING
        }
        _ => EXIT_OTHER,
    }
}

/// Maps an inventory failure onto the probe's documented exit codes.
fn inventory_error_code(error: &InventoryError) -> u8 {
    match error {
        InventoryError::WrongSequence => EXIT_SEQUENCE,
        InventoryError::Transport(_) => EXIT_TRANSPORT,
        InventoryError::SensorStatus { status, .. }
            if *status == cv3_core::proto::status::BAD_SEQUENCE =>
        {
            EXIT_SEQUENCE
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

/// Opens the session, captures a finger, sends the verify request and reports the verdict.
fn verify(
    backend: &mut dyn UsbBackend,
    shutdown: &dyn Shutdown,
    dump_hex: bool,
    flags: MatchFlags<'_>,
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
    let mut channel = match open_for_command(backend, shutdown, err) {
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
        verify_over(transport, secrets, open_iv, capture_iv, match_iv, flags)
    });

    let code = match outcome {
        Ok((verdict, teardown)) => {
            if let Some(template_id) = flags.template {
                let _ = writeln!(out, "match template id {}", hex(&template_id));
            }
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
            print_match_failure(&error, out);
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

/// One IV per wrapped command in the cancel-then-verify run.
struct CancelIvs {
    open: [u8; BLOCK_LEN],
    arm: [u8; BLOCK_LEN],
    capture: [u8; BLOCK_LEN],
    match_iv: [u8; BLOCK_LEN],
}

/// Opens **one** session, arms a capture, cancels it before any finger, then verifies in it.
///
/// The wire order is `0x02`, `0x66`, the mid-session `0x68`, `0x66`, the finger event and the
/// verify request (`0x72`).
/// The first arm's status and the sequence each `0x66` carries are printed, because the re-arm's
/// sequence is the experiment. The default rewinds the counter to the first arm's sequence, which
/// is what this sensor was measured to require after a cancel; `retry_next` instead keeps the
/// reference reading and re-arms at N+1. The caller tears the one session down afterwards.
fn cancel_then_verify_over(
    transport: &mut dyn Transport,
    secrets: RunSecrets,
    ivs: CancelIvs,
    retry_next: bool,
    out: &mut dyn Write,
) -> Result<(Verdict, Result<(), TeardownError>), CancelThenVerifyFailure> {
    let run =
        handshake_over(transport, secrets, true).map_err(CancelThenVerifyFailure::Handshake)?;
    let mut open = OpenSession::new(run.session, ivs.open);
    let session = drive(&mut open, transport).map_err(CancelThenVerifyFailure::Open)?;

    // Arm only: consume the 0x66 reply and keep the session, without waiting for a finger. A
    // 0x85 reply is an outcome, not a failure: the stale capture is cancelled next, and the
    // re-arm inside the verification then carries the sequence the two readings disagree about.
    let first_arm_sequence = session.next_sequence();
    let mut arm = ArmCapture::new(session, ivs.arm);
    let (session, first_arm_status) =
        match drive(&mut arm, transport).map_err(CancelThenVerifyFailure::Capture)? {
            ArmOutcome::Armed(CapturedSample { session, .. }) => (session, 0x00),
            ArmOutcome::AlreadyPending(session) => (session, 0x85),
        };
    let _ = writeln!(out, "first arm status {first_arm_status:#04x}");
    let _ = writeln!(out, "arm sequence {first_arm_sequence}");

    // Clear the armed capture with the session-scoped cancel, which leaves the session open.
    let mut cancel = CancelCapture::new(session);
    let mut session = drive(&mut cancel, transport).map_err(CancelThenVerifyFailure::Cancel)?;

    // The measured behaviour: the sensor still expects the arm at the first arm's sequence, so
    // the default rewinds the counter. `--retry-next` keeps the reference reading for comparison.
    if !retry_next {
        session.rewind_sequence();
    }
    let _ = writeln!(out, "re-arm sequence {}", session.next_sequence());

    // The one-to-one verify is this experiment's control: the sequence question is independent of
    // the identify request, so the command is named here rather than left to a core default.
    let mut verify = Verify::new(session, ivs.capture, ivs.match_iv).with_command(cmd::VERIFY);
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
    retry_next: bool,
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
    let [open, arm, capture, match_iv] = ivs;
    let ivs = CancelIvs {
        open,
        arm,
        capture,
        match_iv,
    };

    let mut channel = match open_for_command(backend, shutdown, err) {
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
        |transport| cancel_then_verify_over(transport, secrets, ivs, retry_next, out),
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
    use cv3_core::proto::{attr, cmd, interrupt};
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

        let (code, out, err) = run_with(&["list"], &mut usb, &shutdown);

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
            vec!["inventory", "--hex"],
            vec!["enroll", "--hex"],
            vec!["enroll-then-verify", "--hex"],
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

        let timestamps = err
            .lines()
            .filter(|line| line.starts_with("* timestamp "))
            .count();
        assert_eq!(
            timestamps, 0,
            "no timestamp is sent at session start: {err}"
        );
        assert_eq!(
            err.lines().count(),
            sent.len() * 2 + timestamps,
            "each frame has one line in each direction, plus the host control line: {err}"
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
    fn capture_hex_dumps_the_decrypted_arm_reply() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["capture", "--hex"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(
            out.lines().next(),
            Some(format!("sample hash {}", hex(&SAMPLE_HASH)).as_str())
        );
        assert!(out.contains("capture plaintext length 28"), "{out}");
        assert!(out.contains("plaintext:\n"), "{out}");
        assert!(out.contains("type=0 len=20"), "{out}");
        assert!(
            out.contains(&hex(&SAMPLE_HASH)),
            "the arm reply's own value is in the dump: {out}"
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
    fn inventory_prints_both_lengths_the_plaintext_and_a_tlv_dump() {
        let mut usb = FakeUsb::with_sensor();
        usb.inventory_plaintext = Some(vec![
            0, 0, 0, 0, 4, 0, 0, 0, 0x11, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["inventory"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert_eq!(
            out,
            "reply length 76\n\
             plaintext length 20\n\
             plaintext:\n\
             0000: 00 00 00 00 04 00 00 00 11 00 00 00 02 00 00 00\n\
             0010: 00 00 00 00\n\
             tlv:\n\
             +0000 tag 0 length 4 value 11000000\n\
             +000c tag 2 length 0 value -\n"
        );
        assert_eq!(
            sent_commands(&usb),
            [
                cmd::CHALLENGE,
                cmd::CHALLENGE_RESPONSE,
                cmd::OPEN_SESSION,
                cmd::INVENTORY,
                cmd::CANCEL_CAPTURE,
                cmd::CLOSE_SESSION,
            ],
            "the query runs in its own session and tears it down"
        );

        let frame = sent_command(&usb, cmd::INVENTORY).expect("0x2f was sent");
        assert_eq!(
            frame.len(),
            140,
            "44-byte header plus six ciphertext blocks"
        );
        assert_eq!(frame[10], attr::INVENTORY);
        assert_eq!(frame[11], 0x02, "the query is wrapped");
        assert_eq!(le32(&frame, 16), TEST_HANDLE);
        assert_eq!(le32(&frame, 40), 56, "the 56-byte TLV block");

        let tlvs = usb.inventory_tlvs.borrow();
        assert_eq!(tlvs.len(), 1, "one 0x2f request");
        assert_eq!(tlvs[0].len(), 56);
        assert_eq!(&tlvs[0][0..4], &0u32.to_le_bytes());
        assert_eq!(&tlvs[0][4..8], &4u32.to_le_bytes());
        assert_eq!(&tlvs[0][8..12], &TEST_HANDLE.to_le_bytes());
        assert_eq!(&tlvs[0][20..24], &0x48u32.to_le_bytes());
        assert_eq!(&tlvs[0][32..36], &0x53e2u32.to_le_bytes());
        assert_eq!(&tlvs[0][44..48], &0u32.to_le_bytes());
        assert_eq!(&tlvs[0][48..52], &2u32.to_le_bytes());
        assert_eq!(&tlvs[0][52..56], &0u32.to_le_bytes());
    }

    #[test]
    fn inventory_failures_are_distinct_and_tear_down() {
        type Configure = fn(&mut FakeUsb);
        let cases: [(&str, Configure, u8, &str); 5] = [
            (
                "a short plaintext",
                |usb| usb.inventory_plaintext = Some(vec![1, 2, 3, 4]),
                EXIT_OTHER,
                "too short",
            ),
            (
                "a bodyless reply",
                |usb| usb.inventory_body = Some(Vec::new()),
                EXIT_OTHER,
                "without a body",
            ),
            (
                "a sensor status",
                |usb| {
                    usb.inventory_status = 0x0e;
                    usb.inventory_plaintext = Some(vec![0u8; 32]);
                },
                EXIT_OTHER,
                "0x0e",
            ),
            (
                "a sequence rejection",
                |usb| usb.inventory_status = 0x0f,
                EXIT_SEQUENCE,
                "0x0f",
            ),
            (
                "a transport failure",
                |usb| usb.inventory_command_error = Some(UsbError::Timeout),
                EXIT_TRANSPORT,
                "transport failed",
            ),
        ];

        for (name, configure, expected_code, needle) in cases {
            let mut usb = FakeUsb::with_sensor();
            configure(&mut usb);
            let shutdown = SignalFlag::new();

            let (code, out, err) = run_with(&["inventory"], &mut usb, &shutdown);

            assert_eq!(code, expected_code, "{name}: {err}");
            assert_eq!(out, "", "{name}: no dump is printed");
            assert!(err.contains(needle), "{name}: {err}");
            assert!(err.contains("inventory failed"), "{name}: {err}");
            assert!(
                sent_command(&usb, cmd::CANCEL_CAPTURE).is_some(),
                "{name}: the failure tears the session down"
            );
            assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some(), "{name}");
        }
    }

    #[test]
    fn inventory_prints_a_truncated_entry() {
        let mut usb = FakeUsb::with_sensor();
        let mut plaintext = vec![0u8; 13];
        plaintext[4..8].copy_from_slice(&20u32.to_le_bytes());
        plaintext[8..13].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        usb.inventory_plaintext = Some(plaintext);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["inventory"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert!(
            out.contains(
                "+0000 tag 0 length 20 value aabbccddee (truncated: 5 of 20 bytes present)"
            ),
            "{out}"
        );
    }

    #[test]
    fn enroll_commit_sample_hash_forces_the_last_sample_hash() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll", "--commit-sample-hash"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines,
            [
                "sample 1 accepted (1/12)",
                "sample 2 accepted (2/12)",
                "--commit-sample-hash forced the sample hash",
                &format!(
                    "template id {} (last sample hash, forced by --commit-sample-hash)",
                    hex(&SAMPLE_HASH)
                ),
            ],
            "the flag overrides the sensor's enrolment id and says so"
        );
        assert!(
            !out.contains(&hex(&ENROLMENT_ID)),
            "the enrolment id is not committed: {out}"
        );
        assert!(sent_command(&usb, cmd::COMMIT_ENROLMENT).is_some());
    }

    #[test]
    fn enroll_then_verify_commit_sample_hash_matches_with_the_sample_hash() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(
            &["enroll-then-verify", "--commit-sample-hash"],
            &mut usb,
            &shutdown,
        );

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert!(
            out.contains("--commit-sample-hash forced the sample hash"),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "template id {} (last sample hash, forced by --commit-sample-hash)",
                hex(&SAMPLE_HASH)
            )),
            "{out}"
        );
        assert!(
            out.contains(&format!("match template id {}", hex(&SAMPLE_HASH))),
            "the confirmation match names the forced id: {out}"
        );
        assert!(
            out.contains(&verify_output(
                cmd::IDENTIFY,
                0,
                VERDICT_MATCH,
                Some(&MATCH_VALUE),
                108,
                52
            )),
            "{out}"
        );

        let tlvs = usb.match_tlvs.borrow();
        assert_eq!(tlvs.len(), 1, "one match request");
        assert_eq!(&tlvs[0][64..84], &SAMPLE_HASH);
    }

    #[test]
    fn commit_sample_hash_is_accepted_only_by_the_enrol_commands() {
        let shutdown = SignalFlag::new();
        for command in ["capture", "inventory", "verify"] {
            let mut usb = FakeUsb::with_sensor();
            let (code, out, err) =
                run_with(&[command, "--commit-sample-hash"], &mut usb, &shutdown);

            assert_eq!(code, EXIT_OTHER, "{command}");
            assert_eq!(out, "", "{command}");
            assert_eq!(err, format!("{USAGE}\n"), "{command}");
            assert!(usb.calls().is_empty(), "{command} touches nothing");
        }
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

    #[test]
    fn enroll_then_verify_runs_the_whole_measurement_in_one_session() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        let shutdown = SignalFlag::new();

        let (code, _out, err) = run_with(&["enroll-then-verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
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
                cmd::ARM_CAPTURE,
                cmd::IDENTIFY,
                cmd::CANCEL_CAPTURE,
                cmd::CLOSE_SESSION,
            ],
            "one session: 0x02, the enrolment, then the confirmation capture and 0x73, then teardown"
        );
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|command| **command == cmd::OPEN_SESSION)
                .count(),
            1,
            "the confirmation touch happens in the enrolment's session"
        );
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|command| **command == cmd::CLOSE_SESSION)
                .count(),
            1
        );
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|command| **command == cmd::ARM_CAPTURE)
                .count(),
            3,
            "two enrolment samples and one confirmation capture"
        );
    }

    #[test]
    fn enroll_then_verify_prints_progress_template_id_then_the_verdict() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll-then-verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        let expected = format!(
            "sample 1 accepted (1/12)\n\
             sample 2 accepted (2/12)\n\
             template id {} (sensor enrolment id)\n\
             match template id {}\n\
             {}",
            hex(&ENROLMENT_ID),
            hex(&ENROLMENT_ID),
            verify_output(cmd::IDENTIFY, 0, VERDICT_MATCH, Some(&MATCH_VALUE), 108, 52)
        );
        assert_eq!(
            out, expected,
            "progress, the template id and the id the match used, then the verdict detail"
        );
    }

    #[test]
    fn enroll_then_verify_sends_the_committed_enrolment_id_in_the_match_tlv() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        let shutdown = SignalFlag::new();

        let (code, _out, err) = run_with(&["enroll-then-verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert!(
            sent_command(&usb, cmd::VERIFY).is_none(),
            "the default is the vendor's 0x73 identify, not 0x72"
        );
        assert_eq!(
            sent_command(&usb, cmd::IDENTIFY)
                .expect("0x73 was sent")
                .get(8..10),
            Some(&[0x73u8, 0x00][..]),
            "the confirmation request is 0x73"
        );
        let tlvs = usb.match_tlvs.borrow();
        assert_eq!(tlvs.len(), 1, "one match request");
        assert_eq!(tlvs[0].len(), 84, "the fixed entries plus the hash entry");
        assert_eq!(&tlvs[0][56..60], &3u32.to_le_bytes(), "type 3");
        assert_eq!(&tlvs[0][60..64], &20u32.to_le_bytes(), "length 20");
        assert_eq!(
            &tlvs[0][64..84],
            &ENROLMENT_ID,
            "the request names the enrolment id the commit returned"
        );
    }

    #[test]
    fn enroll_then_verify_command_seventy_two_sends_the_one_to_one_verify() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        let shutdown = SignalFlag::new();

        let (code, _out, err) = run_with(
            &["enroll-then-verify", "--command", "72"],
            &mut usb,
            &shutdown,
        );

        assert_eq!(code, EXIT_OK, "{err}");
        assert!(
            sent_command(&usb, cmd::IDENTIFY).is_none(),
            "0x72 replaces the default"
        );
        assert!(
            sent_command(&usb, cmd::VERIFY).is_some(),
            "the probe sends the one-to-one verify"
        );
        let tlvs = usb.match_tlvs.borrow();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(
            &tlvs[0][64..84],
            &ENROLMENT_ID,
            "the verify probe names the same committed hash"
        );
    }

    #[test]
    fn verify_template_sends_the_callers_id_and_prints_it() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();
        let template = hex(&ENROLMENT_ID);

        let (code, out, err) = run_with(&["verify", "--template", &template], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert_eq!(
            out,
            format!(
                "match template id {template}\n{}",
                verify_output(cmd::IDENTIFY, 0, VERDICT_MATCH, Some(&MATCH_VALUE), 108, 52)
            )
        );
        let tlvs = usb.match_tlvs.borrow();
        assert_eq!(&tlvs[0][64..84], &ENROLMENT_ID);
    }

    #[test]
    fn verify_without_a_template_sends_an_empty_type_two_array() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert!(!out.contains("match template id"), "{out}");
        let tlvs = usb.match_tlvs.borrow();
        assert_eq!(tlvs[0].len(), 56, "four fixed entries and (2,0)");
        assert_eq!(&tlvs[0][48..52], &2u32.to_le_bytes(), "type 2");
        assert_eq!(
            &tlvs[0][52..56],
            &0u32.to_le_bytes(),
            "no handle means a zero-size array, one-to-many"
        );
        assert!(
            !tlvs[0].windows(4).any(|word| word == 3u32.to_le_bytes()),
            "no hash entry is emitted"
        );
    }

    #[test]
    fn verify_handle_is_repeatable_and_becomes_the_type_two_array() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, _out, err) = run_with(
            &["verify", "--handle", "0x11223344", "--handle", "7"],
            &mut usb,
            &shutdown,
        );

        assert_eq!(code, EXIT_OK, "{err}");
        let tlvs = usb.match_tlvs.borrow();
        assert_eq!(tlvs[0].len(), 64, "56 plus two four-byte handles");
        assert_eq!(&tlvs[0][48..52], &2u32.to_le_bytes(), "type 2");
        assert_eq!(&tlvs[0][52..56], &8u32.to_le_bytes(), "two handles");
        assert_eq!(&tlvs[0][56..60], &0x1122_3344u32.to_le_bytes());
        assert_eq!(&tlvs[0][60..64], &7u32.to_le_bytes());
    }

    #[test]
    fn verify_handle_accepts_decimal_and_a_comma_list() {
        let shutdown = SignalFlag::new();

        let mut single = FakeUsb::with_sensor();
        let (code, _, err) = run_with(&["verify", "--handle", "287454020"], &mut single, &shutdown);
        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(
            &single.match_tlvs.borrow()[0][56..60],
            &0x1122_3344u32.to_le_bytes(),
            "decimal 287454020 is 0x11223344"
        );

        let mut list = FakeUsb::with_sensor();
        let (code, _, err) = run_with(
            &["verify", "--handle", "0x11223344,7"],
            &mut list,
            &shutdown,
        );
        assert_eq!(code, EXIT_OK, "{err}");

        let mut repeated = FakeUsb::with_sensor();
        let (code, _, err) = run_with(
            &["verify", "--handle", "0x11223344", "--handle", "7"],
            &mut repeated,
            &shutdown,
        );
        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(
            list.match_tlvs.borrow()[0],
            repeated.match_tlvs.borrow()[0],
            "a comma list is the same as repeating the flag"
        );
    }

    #[test]
    fn a_malformed_handle_flag_is_a_usage_error() {
        let shutdown = SignalFlag::new();
        for handle in ["", "0x", "0xgg", "abc", "-1", "1,,2", "4294967296"] {
            let mut usb = FakeUsb::with_sensor();
            let (code, out, err) = run_with(&["verify", "--handle", handle], &mut usb, &shutdown);

            assert_eq!(code, EXIT_OTHER, "{handle:?}");
            assert_eq!(out, "", "{handle:?}");
            assert_eq!(err, format!("{USAGE}\n"), "{handle:?}");
            assert!(usb.calls().is_empty(), "{handle:?} touches nothing");
        }
    }

    #[test]
    fn handle_is_accepted_only_by_the_two_match_commands() {
        let shutdown = SignalFlag::new();
        for subcommand in [
            "handshake",
            "open",
            "close",
            "capture",
            "inventory",
            "enroll",
            "cancel-then-verify",
        ] {
            let mut usb = FakeUsb::with_sensor();
            let (code, out, err) = run_with(&[subcommand, "--handle", "7"], &mut usb, &shutdown);

            assert_eq!(code, EXIT_OTHER, "{subcommand}");
            assert_eq!(out, "", "{subcommand}");
            assert_eq!(err, format!("{USAGE}\n"), "{subcommand}");
            assert!(usb.calls().is_empty(), "{subcommand} touches nothing");
        }
    }

    #[test]
    fn the_default_command_follows_the_hash() {
        // The vendor sends 0x73 only when it has a 20-byte hash; without one it sends 0x2F with
        // the same parameter list. The probe mirrors that choice instead of picking one command.
        for (args, expected) in [
            (vec!["verify"], cmd::IDENTIFY_HANDLES),
            (vec!["verify", "--handle", "7"], cmd::IDENTIFY_HANDLES),
            (
                vec!["verify", "--template", &hex(&ENROLMENT_ID)],
                cmd::IDENTIFY,
            ),
            (vec!["enroll-then-verify"], cmd::IDENTIFY),
            (
                vec!["enroll-then-verify", "--handle", "7"],
                cmd::IDENTIFY_HANDLES,
            ),
        ] {
            let owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            match parse(&owned) {
                Some(Command::Verify { command, .. })
                | Some(Command::EnrollThenVerify { command, .. }) => {
                    assert_eq!(command, expected, "{args:?}");
                }
                _ => panic!("{args:?} did not parse"),
            }
        }
    }

    #[test]
    fn command_2f_sends_the_identify_without_a_hash() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify", "--command", "2f"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert!(out.contains("command 0x2f"), "{out}");
        assert_eq!(
            sent_command(&usb, cmd::IDENTIFY_HANDLES)
                .expect("0x2f was sent")
                .get(8..10),
            Some(&[0x2fu8, 0x00][..])
        );
        assert!(sent_command(&usb, cmd::IDENTIFY).is_none());
    }

    #[test]
    fn verify_with_a_hash_defaults_to_0x73() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(
            &["verify", "--template", &hex(&ENROLMENT_ID)],
            &mut usb,
            &shutdown,
        );

        assert_eq!(code, EXIT_OK, "{err}");
        assert!(out.contains("command 0x73"), "{out}");
        assert!(sent_command(&usb, cmd::IDENTIFY_HANDLES).is_none());
    }

    #[test]
    fn enroll_show_commit_prints_the_decrypted_commit_reply() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        usb.commit_plaintext = Some(vec![
            3, 0, 0, 0, 4, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd, //
            0, 0, 0, 0, 4, 0, 0, 0, 0x44, 0x33, 0x22, 0x11,
        ]);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll", "--show-commit"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert!(out.contains("commit reply length 76"), "{out}");
        assert!(out.contains("commit plaintext length 24"), "{out}");
        assert!(out.contains("plaintext:"), "{out}");
        assert!(out.contains("type=3 len=4 value=aabbccdd"), "{out}");
        assert!(out.contains("type=0 len=4 value=44332211"), "{out}");
        assert_eq!(
            out.lines().filter(|line| *line == "plaintext:").count(),
            1,
            "one dump: {out}"
        );
    }

    #[test]
    fn enroll_without_show_commit_prints_no_commit_plaintext() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert!(!out.contains("commit reply length"), "{out}");
        assert!(!out.contains("commit plaintext length"), "{out}");
        assert!(!out.contains("plaintext:"), "{out}");
    }

    #[test]
    fn enroll_show_commit_with_an_empty_body_still_dumps_nothing() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll", "--show-commit"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert!(out.contains("commit reply length 60"), "{out}");
        assert!(out.contains("commit plaintext length 0"), "{out}");
        assert!(out.contains("tlv: none"), "{out}");
    }

    #[test]
    fn enroll_then_verify_show_commit_prints_the_same_dump() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        usb.commit_plaintext = Some(vec![
            3, 0, 0, 0, 4, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd, //
            0, 0, 0, 0, 4, 0, 0, 0, 0x44, 0x33, 0x22, 0x11,
        ]);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(
            &["enroll-then-verify", "--show-commit"],
            &mut usb,
            &shutdown,
        );

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert!(out.contains("commit reply length 76"), "{out}");
        assert!(out.contains("type=0 len=4 value=44332211"), "{out}");
        assert!(out.contains("match template id"), "{out}");
    }

    #[test]
    fn handle_is_composed_into_the_enrol_then_verify_match() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        let shutdown = SignalFlag::new();

        let (code, _out, err) = run_with(
            &["enroll-then-verify", "--handle", "9"],
            &mut usb,
            &shutdown,
        );

        assert_eq!(code, EXIT_OK, "{err}");
        let tlvs = usb.match_tlvs.borrow();
        assert_eq!(&tlvs[0][48..52], &2u32.to_le_bytes(), "type 2");
        assert_eq!(&tlvs[0][52..56], &4u32.to_le_bytes(), "one handle");
        assert_eq!(&tlvs[0][56..60], &9u32.to_le_bytes());
        assert_eq!(&tlvs[0][60..64], &3u32.to_le_bytes(), "then the hash entry");
        assert_eq!(&tlvs[0][68..88], &ENROLMENT_ID, "the committed hash");
    }

    #[test]
    fn a_malformed_template_flag_is_a_usage_error() {
        let shutdown = SignalFlag::new();
        for template in ["00", &"0".repeat(39), &"z".repeat(40)] {
            let mut usb = FakeUsb::with_sensor();
            let (code, out, err) =
                run_with(&["verify", "--template", template], &mut usb, &shutdown);

            assert_eq!(code, EXIT_OTHER, "{template}");
            assert_eq!(out, "");
            assert_eq!(err, format!("{USAGE}\n"), "{template}");
            assert!(usb.calls().is_empty(), "nothing touches the sensor");
        }
    }

    #[test]
    fn retry_next_is_accepted_only_by_cancel_then_verify() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();
        let (code, out, err) =
            run_with(&["cancel-then-verify", "--retry-next"], &mut usb, &shutdown);
        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(out.lines().next(), Some("first arm status 0x00"));

        let mut usb = FakeUsb::with_sensor();
        let (code, out, err) = run_with(&["verify", "--retry-next"], &mut usb, &shutdown);
        assert_eq!(code, EXIT_OTHER);
        assert_eq!(out, "");
        assert_eq!(err, format!("{USAGE}\n"));
        assert!(usb.calls().is_empty());
    }

    #[test]
    fn verify_reports_the_measured_0x59_with_the_reply_length_and_plaintext() {
        let mut usb = FakeUsb::with_sensor();
        let plaintext = match_plaintext(0, Some(&MATCH_VALUE));
        usb.match_status = 0x59;
        usb.match_plaintext = Some(plaintext.clone());
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OTHER);
        assert!(out.contains("command 0x2f"), "{out}");
        assert!(out.contains("status 0x59"), "{out}");
        assert!(out.contains("reply length 108"), "{out}");
        assert!(out.contains("plaintext length 52"), "{out}");
        assert_eq!(
            out,
            format!(
                "command 0x2f\nstatus 0x59\n{}\nvalue {}\nreply length 108\nplaintext length 52\n{}",
                verdict_line(0),
                hex(&MATCH_VALUE),
                plaintext_dump(&plaintext)
            ),
            "a refusal is dumped with the raw word, never decoded as a match"
        );
        assert!(err.contains("status 0x59"), "{err}");
        assert!(
            err.contains(&format!("raw reply {} bytes", frame::HEADER_LEN + 64)),
            "the raw reply length is visible: {err}"
        );
        assert!(
            err.contains("decrypted plaintext 52 bytes"),
            "the decrypted length is visible: {err}"
        );
        assert!(
            err.contains(&hex(&plaintext)),
            "the plaintext is visible: {err}"
        );
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn verify_reports_a_zero_e_zero_refusal_with_the_plaintext_and_tlv_dump() {
        let mut usb = FakeUsb::with_sensor();
        let plaintext = vec![
            0, 0, 0, 0, 4, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 2, 0, 0, 0, 0, 0, 0, 0,
        ];
        usb.match_status = 0x0e;
        usb.match_plaintext = Some(plaintext.clone());
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OTHER);
        assert!(out.contains("status 0x0e"), "{out}");
        assert!(out.contains("plaintext length 20"), "{out}");
        assert!(out.contains("type=0 len=4 value=44332211"), "{out}");
        assert!(out.contains("type=2 len=0 value=-"), "{out}");
        assert_eq!(
            out,
            format!(
                "command 0x2f\nstatus 0x0e\n{}\nvalue absent\nreply length 76\nplaintext length 20\n{}",
                verdict_line(0x1122_3344),
                plaintext_dump(&plaintext)
            )
        );
        assert!(err.contains("status 0x0e"), "{err}");
        assert!(sent_command(&usb, cmd::CANCEL_CAPTURE).is_some());
        assert!(sent_command(&usb, cmd::CLOSE_SESSION).is_some());
    }

    #[test]
    fn enroll_then_verify_reports_a_no_match_after_naming_the_template_and_tears_down() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        usb.match_plaintext = Some(match_plaintext(VERDICT_NO_MATCH, Some(&MATCH_VALUE)));
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll-then-verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_NO_MATCH);
        assert_ne!(code, EXIT_OTHER);
        assert_eq!(err, "");
        assert!(
            out.contains(&format!(
                "template id {} (sensor enrolment id)",
                hex(&ENROLMENT_ID)
            )),
            "the template id is printed before the confirmation: {out}"
        );
        assert!(out.ends_with(&verify_output(
            cmd::IDENTIFY,
            0,
            VERDICT_NO_MATCH,
            Some(&MATCH_VALUE),
            108,
            52
        )));
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|c| **c == cmd::CANCEL_CAPTURE)
                .count(),
            1,
            "the successful no-match run tears the session down once"
        );
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|c| **c == cmd::CLOSE_SESSION)
                .count(),
            1
        );
    }

    #[test]
    fn enroll_then_verify_tears_down_when_the_confirmation_finger_never_arrives() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        let finger = Ok(interrupt::FINGER.to_le_bytes().to_vec());
        usb.finger_events = vec![finger.clone(), finger, Err(UsbError::Timeout)];
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll-then-verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_FINGER_TIMEOUT);
        assert_ne!(code, EXIT_TRANSPORT);
        assert!(
            out.contains(&format!(
                "template id {} (sensor enrolment id)",
                hex(&ENROLMENT_ID)
            )),
            "the committed template is still reported: {out}"
        );
        assert!(err.contains("verification failed"), "{err}");
        assert!(err.contains("finger timeout"), "{err}");
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|c| **c == cmd::CANCEL_CAPTURE)
                .count(),
            1,
            "the failed confirmation tears the session down once"
        );
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|c| **c == cmd::CLOSE_SESSION)
                .count(),
            1
        );
        assert!(
            sent_command(&usb, cmd::IDENTIFY).is_none(),
            "the match is never attempted without the confirmation touch"
        );
    }

    #[test]
    fn enroll_then_verify_stops_at_a_rejected_commit_and_never_matches() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(1);
        usb.commit_status = 0x0c;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll-then-verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OTHER);
        assert_eq!(
            out, "sample 1 accepted (1/12)\n",
            "no template id is printed"
        );
        assert!(err.contains("enrolment failed"), "{err}");
        assert!(err.contains("0x0c"), "{err}");
        assert!(err.contains("may exist"), "{err}");
        assert!(
            sent_command(&usb, cmd::IDENTIFY).is_none(),
            "a failed enrolment does not attempt the confirmation match"
        );
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|c| **c == cmd::CANCEL_CAPTURE)
                .count(),
            1,
            "the enrolment's own teardown is not repeated"
        );
        assert_eq!(
            sent_commands(&usb)
                .iter()
                .filter(|c| **c == cmd::CLOSE_SESSION)
                .count(),
            1
        );
    }

    #[test]
    fn enroll_then_verify_hex_dumps_the_enrolment_and_confirmation_frames_to_stderr() {
        let mut usb = FakeUsb::with_sensor();
        usb.completion_after = Some(2);
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["enroll-then-verify", "--hex"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert!(
            !out.contains("> ") && !out.contains("< "),
            "the hex dump never reaches stdout: {out}"
        );
        assert!(
            out.contains(&format!(
                "template id {} (sensor enrolment id)",
                hex(&ENROLMENT_ID)
            )),
            "stdout keeps the decoded lines: {out}"
        );
        assert!(out.contains("verdict 1 (match)"), "{out}");

        let sent = usb.sent.borrow();
        let host: Vec<&str> = err.lines().filter(|line| line.starts_with("> ")).collect();
        assert_eq!(host.len(), sent.len(), "one host line per frame: {err}");
        for (line, frame) in host.iter().zip(sent.iter()) {
            assert_eq!(*line, format!("> {}", hex(frame)));
        }

        for wanted in [cmd::DISCARD_ENROLMENT, cmd::COMMIT_ENROLMENT, cmd::IDENTIFY] {
            let frame = sent
                .iter()
                .find(|frame| command(frame) == wanted)
                .unwrap_or_else(|| panic!("{wanted:#04x} was sent"));
            assert!(
                err.contains(&format!("> {}", hex(frame))),
                "the {wanted:#04x} frame is in the dump: {err}"
            );
        }

        let last_arm = sent
            .iter()
            .rev()
            .find(|frame| command(frame) == cmd::ARM_CAPTURE)
            .expect("the confirmation arm was sent");
        assert!(
            err.contains(&format!("> {}", hex(last_arm))),
            "the confirmation capture is in the dump: {err}"
        );
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

    /// The three experiment lines `cancel-then-verify` prints before its verdict.
    fn cancel_probe_lines(first_status: u32, arm_sequence: u32, rearm_sequence: u32) -> String {
        format!(
            "first arm status {first_status:#04x}\narm sequence {arm_sequence}\nre-arm sequence \
             {rearm_sequence}\n"
        )
    }

    /// The `plaintext:` rows and `tlv:` scan the diagnostics print for `plaintext`.
    fn plaintext_dump(plaintext: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut text = String::from("plaintext:\n");
        for (row, chunk) in plaintext.chunks(16).enumerate() {
            let _ = write!(text, "{:04x}:", row * 16);
            for byte in chunk {
                let _ = write!(text, " {byte:02x}");
            }
            text.push('\n');
        }

        let scan = scan_tlv(plaintext);
        if scan.entries.is_empty() {
            text.push_str("tlv: none\n");
            return text;
        }
        text.push_str("tlv:\n");
        for entry in &scan.entries {
            let _ = write!(text, "type={} len={}", entry.tag, entry.declared_len);
            if entry.value.is_empty() {
                text.push_str(" value=-");
            } else {
                let _ = write!(text, " value={}", hex(entry.value));
            }
            if entry.is_truncated() {
                let _ = write!(
                    text,
                    " (truncated: {} of {} bytes present)",
                    entry.value.len(),
                    entry.declared_len
                );
            }
            text.push('\n');
        }
        text
    }

    fn verify_output(
        command: u16,
        status: u32,
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
        let bytes = match_plaintext(word, value);
        assert_eq!(bytes.len(), plaintext, "the fixture length matches");
        let value = match value {
            Some(value) => format!("value {}", hex(value)),
            None => "value absent".to_owned(),
        };
        format!(
            "command 0x{command:02x}\nstatus 0x{status:02x}\nverdict {word} ({meaning})\n{value}\n\
             reply length {reply}\nplaintext length {plaintext}\n{}",
            plaintext_dump(&bytes)
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
            format!(
                "{}{}",
                cancel_probe_lines(0x00, 1, 1),
                verify_output(cmd::VERIFY, 0, VERDICT_MATCH, Some(&MATCH_VALUE), 108, 52)
            ),
            "the experiment lines, then the verdict, value and lengths"
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
                cmd::VERIFY,
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
            sent_command(&usb, cmd::VERIFY)
                .expect("0x72 was sent")
                .len(),
            156,
            "the match is the 56-byte request at a 96-byte plaintext"
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
            format!(
                "{}{}",
                cancel_probe_lines(0x85, 1, 1),
                verify_output(cmd::VERIFY, 0, VERDICT_MATCH, Some(&MATCH_VALUE), 108, 52)
            ),
            "the first arm's 0x85 is printed, and the default re-arms at the same sequence"
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
                cmd::VERIFY,
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
    fn cancel_then_verify_retry_next_re_arms_at_n_plus_one() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, out, err) =
            run_with(&["cancel-then-verify", "--retry-next"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert_eq!(
            out,
            format!(
                "{}{}",
                cancel_probe_lines(0x00, 1, 2),
                verify_output(cmd::VERIFY, 0, VERDICT_MATCH, Some(&MATCH_VALUE), 108, 52)
            ),
            "the older reading keeps the counter and re-arms at N+1"
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
                cmd::VERIFY,
                cmd::CANCEL_CAPTURE,
                cmd::CLOSE_SESSION,
            ]
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
            format!(
                "{}{}",
                cancel_probe_lines(0x00, 1, 1),
                verify_output(
                    cmd::VERIFY,
                    0,
                    VERDICT_NO_MATCH,
                    Some(&MATCH_VALUE),
                    108,
                    52
                )
            )
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
        assert_eq!(
            out,
            cancel_probe_lines(0x00, 1, 1),
            "the experiment lines are printed before the finger wait"
        );
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
        assert_eq!(
            out, "first arm status 0x00\narm sequence 1\n",
            "the first arm's status and sequence are reported before the cancel fails"
        );
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
        assert_eq!(
            out,
            cancel_probe_lines(0x00, 1, 1),
            "the experiment lines are printed before the interrupted finger wait"
        );
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
            verify_output(
                cmd::IDENTIFY_HANDLES,
                0,
                VERDICT_MATCH,
                Some(&MATCH_VALUE),
                108,
                52
            ),
            "the verdict, the value and both lengths"
        );
        assert_eq!(
            sent_commands(&usb),
            [
                cmd::CHALLENGE,
                cmd::CHALLENGE_RESPONSE,
                cmd::OPEN_SESSION,
                cmd::ARM_CAPTURE,
                cmd::IDENTIFY_HANDLES,
                cmd::CANCEL_CAPTURE,
                cmd::CLOSE_SESSION,
            ],
            "a successful verify tears down with 0x68 then 0x04 before exiting"
        );

        let request = sent_command(&usb, cmd::IDENTIFY_HANDLES).expect("0x2f was sent");
        assert_eq!(
            &request[8..10],
            &[0x2f, 0x00],
            "without a hash the default is the vendor's identify-by-handles"
        );
        assert_eq!(request[10], attr::CAPTURE);
        assert_eq!(request[11], 0x02, "the request is wrapped");
        assert_eq!(le32(&request, 16), TEST_HANDLE);
        assert_eq!(
            le32(&request, 40),
            56,
            "four fixed entries and an empty type-2 array"
        );
        assert_eq!(request.len(), 156, "96 plaintext bytes plus padding");
    }

    #[test]
    fn verify_command_seventy_two_sends_the_one_to_one_verify_with_the_same_request_body() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();
        let template = hex(&ENROLMENT_ID);

        let (code, out, err) = run_with(
            &["verify", "--template", &template, "--command", "72"],
            &mut usb,
            &shutdown,
        );

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "");
        assert_eq!(
            out,
            format!(
                "match template id {template}\n{}",
                verify_output(cmd::VERIFY, 0, VERDICT_MATCH, Some(&MATCH_VALUE), 108, 52)
            ),
            "the decode names the command that went on the wire"
        );
        assert!(
            sent_command(&usb, cmd::IDENTIFY).is_none(),
            "0x73 is replaced, not added"
        );
        let request = sent_command(&usb, cmd::VERIFY).expect("0x72 was sent");
        assert_eq!(&request[8..10], &[0x72, 0x00], "0x72 is the verify");
        assert_eq!(
            request.len(),
            188,
            "the 84-byte TLV needs a 128-byte plaintext"
        );
        assert_eq!(le32(&request, 40), 84, "the same parameter list");

        let tlvs = usb.match_tlvs.borrow();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(&tlvs[0][64..84], &ENROLMENT_ID, "the same hash");
    }

    #[test]
    fn a_malformed_command_flag_is_a_usage_error() {
        let shutdown = SignalFlag::new();
        for command in ["71", "74", "0x72", "72 ", ""] {
            let mut usb = FakeUsb::with_sensor();
            let (code, out, err) = run_with(&["verify", "--command", command], &mut usb, &shutdown);

            assert_eq!(code, EXIT_OTHER, "{command:?}");
            assert_eq!(out, "", "{command:?}");
            assert_eq!(err, format!("{USAGE}\n"), "{command:?}");
            assert!(usb.calls().is_empty(), "nothing touches the sensor");
        }
    }

    #[test]
    fn command_is_accepted_only_by_the_two_verify_commands() {
        let shutdown = SignalFlag::new();
        for subcommand in [
            "handshake",
            "open",
            "close",
            "capture",
            "inventory",
            "enroll",
            "cancel-then-verify",
        ] {
            let mut usb = FakeUsb::with_sensor();
            let (code, out, err) = run_with(&[subcommand, "--command", "72"], &mut usb, &shutdown);

            assert_eq!(code, EXIT_OTHER, "{subcommand}");
            assert_eq!(out, "", "{subcommand}");
            assert_eq!(err, format!("{USAGE}\n"), "{subcommand}");
            assert!(usb.calls().is_empty(), "{subcommand} touches nothing");
        }

        let mut usb = FakeUsb::with_sensor();
        let (code, _out, err) = run_with(&["verify", "--command", "72"], &mut usb, &shutdown);
        assert_eq!(code, EXIT_OK, "{err}");
    }

    #[test]
    fn verify_reports_the_special_cased_0x89_status_with_a_matched_verdict() {
        let mut usb = FakeUsb::with_sensor();
        usb.match_status = 0x89;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "", "0x89 with a verdict body is not a refusal");
        assert_eq!(
            out,
            verify_output(
                cmd::IDENTIFY_HANDLES,
                0x89,
                VERDICT_MATCH,
                Some(&MATCH_VALUE),
                108,
                52
            ),
            "the raw status and the decoded verdict are both printed"
        );
        assert_eq!(
            sent_commands(&usb),
            [
                cmd::CHALLENGE,
                cmd::CHALLENGE_RESPONSE,
                cmd::OPEN_SESSION,
                cmd::ARM_CAPTURE,
                cmd::IDENTIFY_HANDLES,
                cmd::CANCEL_CAPTURE,
                cmd::CLOSE_SESSION,
            ],
            "an answered status still tears the session down before exiting"
        );
    }

    #[test]
    fn verify_reports_the_special_cased_0x89_status_with_a_zero_verdict_as_no_match() {
        let mut usb = FakeUsb::with_sensor();
        usb.match_status = 0x89;
        usb.match_plaintext = Some(match_plaintext(VERDICT_NO_MATCH, Some(&MATCH_VALUE)));
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_NO_MATCH, "{err}");
        assert_ne!(code, EXIT_OTHER);
        assert_eq!(err, "");
        assert_eq!(
            out,
            verify_output(
                cmd::IDENTIFY_HANDLES,
                0x89,
                VERDICT_NO_MATCH,
                Some(&MATCH_VALUE),
                108,
                52
            ),
            "the verdict comes from the body, not from the status"
        );
    }

    #[test]
    fn a_command_session_sends_no_timestamp_sync_on_open() {
        let mut usb = FakeUsb::with_sensor();
        let shutdown = SignalFlag::new();

        let (code, _out, err) = run_with(&["handshake"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "", "{err}");
        assert!(
            usb.syncs.borrow().is_empty(),
            "the sensor asks for the clock; the host does not volunteer it"
        );
    }

    #[test]
    fn a_host_timestamp_request_before_an_announcement_is_answered_and_verify_completes() {
        let mut usb = FakeUsb::with_sensor();
        usb.timestamp_before_announcement = true;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "", "the request is answered silently");
        assert_eq!(
            out,
            verify_output(
                cmd::IDENTIFY_HANDLES,
                0,
                VERDICT_MATCH,
                Some(&MATCH_VALUE),
                108,
                52
            ),
            "the real announcement still drives the reply"
        );
        assert_eq!(
            usb.syncs.borrow().len(),
            1,
            "the type-5 event is answered once"
        );
    }

    #[test]
    fn a_host_timestamp_request_during_the_finger_wait_is_answered_and_verify_completes() {
        let mut usb = FakeUsb::with_sensor();
        usb.timestamp_before_finger = true;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(err, "", "the request is answered silently");
        assert_eq!(
            out,
            verify_output(
                cmd::IDENTIFY_HANDLES,
                0,
                VERDICT_MATCH,
                Some(&MATCH_VALUE),
                108,
                52
            ),
            "the real finger event still drives the match"
        );
        assert_eq!(
            usb.syncs.borrow().len(),
            1,
            "the type-5 event is answered once"
        );
    }

    #[test]
    fn a_failed_timestamp_sync_for_a_type_5_event_is_a_transport_error() {
        let mut usb = FakeUsb::with_sensor();
        usb.timestamp_before_announcement = true;
        usb.sync_error = Some(UsbError::Stall);
        let shutdown = SignalFlag::new();

        let (code, _out, err) = run_with(&["handshake"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_TRANSPORT, "{err}");
        assert!(err.contains("handshake failed"), "{err}");
        assert!(err.contains("endpoint stalled"), "{err}");
    }

    #[test]
    fn hex_shows_a_type_5_timestamp_as_a_host_control_line() {
        let mut usb = FakeUsb::with_sensor();
        usb.timestamp_before_announcement = true;
        let shutdown = SignalFlag::new();

        let (code, out, err) = run_with(&["verify", "--hex"], &mut usb, &shutdown);

        assert_eq!(code, EXIT_OK, "{err}");
        assert_eq!(
            out,
            verify_output(
                cmd::IDENTIFY_HANDLES,
                0,
                VERDICT_MATCH,
                Some(&MATCH_VALUE),
                108,
                52
            ),
            "the decoded stdout is unchanged by the diagnostic line"
        );
        let packed = err
            .lines()
            .find_map(|line| line.strip_prefix("* timestamp "))
            .unwrap_or_else(|| panic!("the sync line is in the dump: {err}"));
        assert_eq!(packed.len(), 8, "the packed value is eight hex digits");
        assert!(packed.chars().all(|digit| digit.is_ascii_hexdigit()));
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
            verify_output(
                cmd::IDENTIFY_HANDLES,
                0,
                VERDICT_NO_MATCH,
                Some(&MATCH_VALUE),
                108,
                52
            ),
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
        assert_eq!(
            out,
            verify_output(cmd::IDENTIFY_HANDLES, 0, VERDICT_NO_MATCH, None, 76, 28)
        );
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
            verify_output(cmd::IDENTIFY_HANDLES, 0, 2, Some(&MATCH_VALUE), 108, 52),
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
