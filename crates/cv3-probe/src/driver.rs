//! Drives one core operation to completion over the command exchange.
//!
//! The loop only maps transport facts to core events: a command's reply becomes
//! [`Event::Reply`] with the status from the reply frame header (never the interrupt
//! announcement's status word), an empty announcement becomes [`Event::ReplyWithoutBody`], and a
//! USB failure becomes [`Event::Transport`]. Every `cvctl` subcommand uses this same loop.
//!
//! The finger wait is the one action the handshake never asks for. It is a separate trait so the
//! capture ticket can supply the real interrupt wait without changing the loop's shape; until then
//! [`NoFingerWait`] treats an unexpected wait as cancellation, which makes the core tear down.

use cv3_core::frame::Header;
use cv3_core::{Action, Event, Operation, TransportError};

use crate::exchange::{Exchange, ExchangeError, Reply};
use crate::usb::UsbError;

/// Waits for the sensor's finger event and returns the core event that describes it.
pub trait FingerWait {
    fn wait(&mut self) -> Event;
}

/// The handshake never arms a capture, so it never waits for a finger.
pub struct NoFingerWait;

impl FingerWait for NoFingerWait {
    fn wait(&mut self) -> Event {
        Event::Cancelled
    }
}

/// Runs `operation` until it finishes, performing each action on `exchange`.
pub fn run<O: Operation>(
    exchange: &mut Exchange<'_>,
    operation: &mut O,
    finger: &mut dyn FingerWait,
) -> O::Output {
    let mut action = operation.start();
    loop {
        match action {
            Action::Send(frame) => {
                let event = match exchange.command(&frame) {
                    Ok(reply) => event_from_reply(reply),
                    Err(error) => Event::Transport(transport_error(error)),
                };
                action = operation.step(event);
            }
            Action::WaitFinger => {
                let event = finger.wait();
                action = operation.step(event);
            }
            Action::Finish(result) => return result,
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

/// Maps a transport failure onto the core's own type.
pub fn transport_error(error: ExchangeError) -> TransportError {
    match error {
        ExchangeError::Out(error)
        | ExchangeError::Interrupt(error)
        | ExchangeError::Bulk(error) => map_usb(error),
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

    use crate::exchange::ANNOUNCEMENT_LEN;

    /// A transport that answers each command with the next scripted reply.
    struct ScriptedIo {
        replies: VecDeque<Result<Reply, ExchangeError>>,
        current: Option<Reply>,
    }

    impl ScriptedIo {
        fn replies(replies: Vec<Result<Reply, ExchangeError>>) -> Self {
            Self {
                replies: replies.into(),
                current: None,
            }
        }
    }

    impl crate::exchange::UsbIo for ScriptedIo {
        fn out(&mut self, _frame: &[u8]) -> Result<(), UsbError> {
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

        fn cancel_finger_wait(&mut self) {}
    }

    /// Sends one frame, then reports the event it received.
    struct SingleStep;

    impl SingleStep {
        fn new() -> Self {
            Self
        }
    }

    impl Operation for SingleStep {
        type Output = Event;

        fn start(&mut self) -> Action<Event> {
            Action::Send(vec![0x23, 0x00])
        }

        fn step(&mut self, event: Event) -> Action<Event> {
            Action::Finish(event)
        }
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
        let mut operation = SingleStep::new();

        let event = run(
            &mut Exchange::new(&mut io),
            &mut operation,
            &mut NoFingerWait,
        );

        assert_eq!(
            event,
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

        assert_eq!(
            run(
                &mut Exchange::new(&mut io),
                &mut SingleStep::new(),
                &mut NoFingerWait
            ),
            Event::ReplyWithoutBody
        );
    }

    #[test]
    fn a_transport_failure_becomes_the_core_transport_event() {
        let mut io = ScriptedIo::replies(vec![Err(ExchangeError::Out(UsbError::Timeout))]);

        assert_eq!(
            run(
                &mut Exchange::new(&mut io),
                &mut SingleStep::new(),
                &mut NoFingerWait
            ),
            Event::Transport(TransportError::Timeout)
        );
    }

    #[test]
    fn a_disconnect_and_a_stall_keep_their_meaning() {
        for (error, expected) in [
            (UsbError::Disconnected, TransportError::Disconnected),
            (UsbError::Stall, TransportError::Stall),
        ] {
            let mut io = ScriptedIo::replies(vec![Err(ExchangeError::Interrupt(error))]);

            assert_eq!(
                run(
                    &mut Exchange::new(&mut io),
                    &mut SingleStep::new(),
                    &mut NoFingerWait
                ),
                Event::Transport(expected)
            );
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
            run(
                &mut Exchange::new(&mut io),
                &mut SingleStep::new(),
                &mut NoFingerWait
            ),
            Event::Reply {
                status: 0,
                body: vec![0u8; 10],
            }
        );
    }
}
