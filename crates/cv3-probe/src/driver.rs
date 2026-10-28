//! The probe's transport: one USB exchange, mapped onto the core's transport contract.
//!
//! The driver loop itself lives in the core ([`cv3_core::transport::run`]); this module only turns
//! [`Exchange`] over [`NusbIo`](crate::nusb_backend::NusbIo) into the events an operation consumes.
//! A command's reply becomes [`Event::Reply`] with the status from the reply frame header (never
//! the interrupt announcement's status word), an empty announcement becomes
//! [`Event::ReplyWithoutBody`], and a USB failure becomes [`Event::Transport`].
//!
//! The finger wait reads the interrupt endpoint separately from a command's announcement: the
//! event value `0x03` becomes [`Event::Finger`], any other value is a typed unexpected-event
//! transport failure, and a timeout is [`Event::Transport`] carrying [`TransportError::Timeout`].
//! A finger wait abandoned because the probe was asked to stop is [`UsbError::Cancelled`], which
//! becomes [`Event::Cancelled`] rather than a transport error, so the core tears the session down.
//! That is the only transfer the probe cancels; a command transfer never is, and a cancellation
//! error from one is still reported as cancellation rather than retried.

use cv3_core::frame::Header;
use cv3_core::proto::interrupt;
use cv3_core::transport::Transport;
use cv3_core::{Event, TransportError};

use crate::exchange::{Exchange, ExchangeError, Reply};
use crate::usb::UsbError;

impl Transport for Exchange<'_> {
    fn command(&mut self, frame: &[u8]) -> Event {
        match Exchange::command(self, frame) {
            Ok(reply) => event_from_reply(reply),
            Err(error) => failure_event(error),
        }
    }

    fn wait_finger(&mut self) -> Event {
        match Exchange::wait_finger(self) {
            Ok(interrupt::FINGER) => Event::Finger,
            Ok(other) => Event::Transport(TransportError::Other(format!(
                "unexpected interrupt event {other:#04x} where a finger event was expected"
            ))),
            Err(error) => failure_event(error),
        }
    }
}

/// Maps an exchange reply onto the core event the operation expects.
///
/// A body that is too short to carry a header still reaches the core, with status zero: the core
/// validates the frame first, so it reports the malformed body rather than trusting a status that
/// was never on the wire.
fn event_from_reply(reply: Reply) -> Event {
    if reply.body.is_empty() {
        return Event::ReplyWithoutBody;
    }
    let status = Header::parse(&reply.body).map_or(0, |header| header.status);
    Event::Reply {
        status,
        body: reply.body,
    }
}

/// Maps an exchange failure onto a core event.
///
/// [`UsbError::Cancelled`] is a cancellation, not a transport failure, so an operation tears down
/// and reports it as one. A command transfer never produces it; if one ever does, it still means
/// the operation was asked to stop.
fn failure_event(error: ExchangeError) -> Event {
    match &error {
        ExchangeError::Out(UsbError::Cancelled)
        | ExchangeError::Interrupt(UsbError::Cancelled)
        | ExchangeError::Bulk(UsbError::Cancelled)
        | ExchangeError::Finger(UsbError::Cancelled) => Event::Cancelled,
        _ => Event::Transport(transport_error(error)),
    }
}

/// Maps a transport failure onto the core's own type.
pub fn transport_error(error: ExchangeError) -> TransportError {
    match error {
        ExchangeError::Out(error)
        | ExchangeError::Interrupt(error)
        | ExchangeError::Bulk(error)
        | ExchangeError::Finger(error) => map_usb(error),
        other => TransportError::Other(other.to_string()),
    }
}

fn map_usb(error: UsbError) -> TransportError {
    match error {
        UsbError::Timeout => TransportError::Timeout,
        UsbError::Disconnected => TransportError::Disconnected,
        UsbError::Stall => TransportError::Stall,
        other => TransportError::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::time::Duration;

    use cv3_core::frame;
    use cv3_core::proto::{attr, cmd};
    use cv3_core::transport::run;
    use cv3_core::{Action, Operation};

    use crate::exchange::ANNOUNCEMENT_LEN;
    use crate::signals::SignalFlag;

    /// A transport that answers each command with the next scripted reply.
    struct ScriptedIo {
        replies: VecDeque<Result<Reply, ExchangeError>>,
        finger: Option<Result<Vec<u8>, UsbError>>,
        current: Option<Reply>,
        signal_on_out: Option<SignalFlag>,
    }

    impl ScriptedIo {
        fn replies(replies: Vec<Result<Reply, ExchangeError>>) -> Self {
            Self {
                replies: replies.into(),
                finger: None,
                current: None,
                signal_on_out: None,
            }
        }

        fn with_finger(mut self, finger: Result<Vec<u8>, UsbError>) -> Self {
            self.finger = Some(finger);
            self
        }

        fn with_signal_on_out(mut self, flag: SignalFlag) -> Self {
            self.signal_on_out = Some(flag);
            self
        }
    }

    impl crate::exchange::UsbIo for ScriptedIo {
        fn out(&mut self, _frame: &[u8]) -> Result<(), UsbError> {
            if let Some(flag) = &self.signal_on_out {
                flag.raise(signal_hook::consts::signal::SIGINT);
            }
            match self.replies.pop_front() {
                Some(Ok(reply)) => {
                    self.current = Some(reply);
                    Ok(())
                }
                Some(Err(ExchangeError::Out(error) | ExchangeError::Interrupt(error))) => {
                    Err(error)
                }
                Some(Err(error)) => Err(UsbError::Other(error.to_string())),
                None => Err(UsbError::Other("no scripted reply".to_owned())),
            }
        }

        fn read_interrupt(&mut self, _timeout: Duration) -> Result<Vec<u8>, UsbError> {
            let reply = self.current.as_ref().expect("out ran first");
            let mut announcement = [0u8; ANNOUNCEMENT_LEN];
            announcement[..4].copy_from_slice(&reply.status.to_le_bytes());
            announcement[4..].copy_from_slice(&(reply.body.len() as u32).to_le_bytes());
            Ok(announcement.to_vec())
        }

        fn read_bulk(&mut self, _len: usize, _timeout: Duration) -> Result<Vec<u8>, UsbError> {
            Ok(self.current.as_ref().expect("out ran first").body.clone())
        }

        fn read_finger(&mut self, _timeout: Duration) -> Result<Vec<u8>, UsbError> {
            self.finger
                .clone()
                .unwrap_or_else(|| Ok(interrupt::FINGER.to_le_bytes().to_vec()))
        }

        fn sync_timestamp(&mut self, _packed: u32) -> Result<(), UsbError> {
            Ok(())
        }
    }

    /// Sends one frame, then reports the event it received.
    struct SingleStep;

    impl Operation for SingleStep {
        type Output = Event;

        fn start(&mut self) -> Action<Event> {
            Action::Send(vec![0x23, 0x00])
        }

        fn step(&mut self, event: Event) -> Action<Event> {
            Action::Finish(event)
        }
    }

    fn drive(io: &mut ScriptedIo) -> Event {
        let mut exchange = Exchange::new(io);
        run(&mut SingleStep, &mut exchange)
    }

    /// An operation whose only action is the finger wait; it reports the event it receives.
    struct FingerWaitOnly;

    impl Operation for FingerWaitOnly {
        type Output = Event;

        fn start(&mut self) -> Action<Event> {
            Action::WaitFinger
        }

        fn step(&mut self, event: Event) -> Action<Event> {
            Action::Finish(event)
        }
    }

    fn drive_finger_wait(io: &mut ScriptedIo) -> Event {
        run(&mut FingerWaitOnly, &mut Exchange::new(io))
    }

    fn body_with_status(status: u32) -> Vec<u8> {
        frame::build_plain_reply(cmd::MATCH, attr::CAPTURE, 7, status, &[0u8; 32])
    }

    #[test]
    fn the_reply_status_comes_from_the_frame_header_not_the_announcement() {
        let body = body_with_status(0x0f);
        let mut io = ScriptedIo::replies(vec![Ok(Reply {
            status: 0x0000_0002,
            body,
        })]);

        assert_eq!(
            drive(&mut io),
            Event::Reply {
                status: 0x0f,
                body: body_with_status(0x0f),
            }
        );
    }

    #[test]
    fn an_empty_announcement_becomes_the_no_body_event() {
        let mut io = ScriptedIo::replies(vec![Ok(Reply {
            status: 0x0000_0002,
            body: Vec::new(),
        })]);

        assert_eq!(drive(&mut io), Event::ReplyWithoutBody);
    }

    #[test]
    fn a_transport_failure_becomes_the_core_transport_event() {
        let mut io = ScriptedIo::replies(vec![Err(ExchangeError::Out(UsbError::Timeout))]);

        assert_eq!(drive(&mut io), Event::Transport(TransportError::Timeout));
    }

    #[test]
    fn a_disconnect_and_a_stall_keep_their_meaning() {
        for (error, expected) in [
            (UsbError::Disconnected, TransportError::Disconnected),
            (UsbError::Stall, TransportError::Stall),
        ] {
            let mut io = ScriptedIo::replies(vec![Err(ExchangeError::Interrupt(error))]);

            assert_eq!(drive(&mut io), Event::Transport(expected));
        }
    }

    #[test]
    fn a_body_transfer_failure_keeps_its_meaning_too() {
        assert_eq!(
            transport_error(ExchangeError::Bulk(UsbError::Disconnected)),
            TransportError::Disconnected
        );
        assert_eq!(
            transport_error(ExchangeError::Bulk(UsbError::Stall)),
            TransportError::Stall
        );
    }

    #[test]
    fn a_short_body_reaches_the_core_with_no_trusted_status() {
        let mut io = ScriptedIo::replies(vec![Ok(Reply {
            status: 0x0000_0002,
            body: vec![0u8; 10],
        })]);

        assert_eq!(
            drive(&mut io),
            Event::Reply {
                status: 0,
                body: vec![0u8; 10],
            }
        );
    }

    #[test]
    fn a_finger_event_becomes_the_core_finger_event() {
        let mut io = ScriptedIo::replies(Vec::new());
        assert_eq!(drive_finger_wait(&mut io), Event::Finger);
    }

    #[test]
    fn another_interrupt_value_is_a_typed_unexpected_event() {
        let mut io =
            ScriptedIo::replies(Vec::new()).with_finger(Ok(0x07u32.to_le_bytes().to_vec()));

        match drive_finger_wait(&mut io) {
            Event::Transport(TransportError::Other(message)) => {
                assert!(message.contains("0x07"), "{message}");
                assert!(message.contains("finger"), "{message}");
            }
            other => panic!("expected a typed transport error, got {other:?}"),
        }
    }

    #[test]
    fn a_finger_timeout_is_the_transport_timeout_event() {
        let mut io = ScriptedIo::replies(Vec::new()).with_finger(Err(UsbError::Timeout));

        assert_eq!(
            drive_finger_wait(&mut io),
            Event::Transport(TransportError::Timeout)
        );
    }

    #[test]
    fn a_cancelled_finger_wait_is_the_core_cancellation_event() {
        let mut io = ScriptedIo::replies(Vec::new()).with_finger(Err(UsbError::Cancelled));

        assert_eq!(drive_finger_wait(&mut io), Event::Cancelled);
    }

    #[test]
    fn a_cancelled_command_is_reported_as_cancellation_not_a_transport_error() {
        let mut io = ScriptedIo::replies(vec![Err(ExchangeError::Out(UsbError::Cancelled))]);

        assert_eq!(drive(&mut io), Event::Cancelled);
    }

    #[test]
    fn a_signal_during_a_command_transfer_does_not_cancel_it() {
        // The flag is raised inside `out`, so the signal arrives while the command is in flight.
        let flag = SignalFlag::new();
        let mut io = ScriptedIo::replies(vec![Ok(Reply {
            status: 0x0000_0002,
            body: body_with_status(0),
        })])
        .with_signal_on_out(flag.clone());

        assert_eq!(
            drive(&mut io),
            Event::Reply {
                status: 0,
                body: body_with_status(0),
            },
            "the command transfer completed even though the signal was already raised"
        );
        assert_eq!(flag.get(), Some(signal_hook::consts::signal::SIGINT));
    }

    #[test]
    fn a_short_finger_event_is_reported_not_panicked() {
        let mut io = ScriptedIo::replies(Vec::new()).with_finger(Ok(vec![0x03, 0x00]));

        match drive_finger_wait(&mut io) {
            Event::Transport(TransportError::Other(message)) => {
                assert!(message.contains("finger event"), "{message}");
            }
            other => panic!("expected a typed transport error, got {other:?}"),
        }
    }
}
