//! `--hex`: dumps both transport directions for protocol work.
//!
//! [`HexTransport`] wraps any core [`Transport`] and writes each host frame and each device reply
//! body to a sink as lowercase hex. The operation and the core do not know it is there; this is
//! the same layering the recording wrapper in [`cv3_core::transcript`] uses. The probe points the
//! sink at stderr, so stdout keeps exactly the decoded fields it prints without the flag.

use std::io::Write;

use cv3_core::{Event, Transport};

/// Wraps a transport and dumps both directions as it runs.
pub struct HexTransport<'a, T> {
    inner: T,
    out: &'a mut dyn Write,
}

impl<'a, T> HexTransport<'a, T> {
    /// Dumps the traffic of `inner` to `out`.
    pub fn new(inner: T, out: &'a mut dyn Write) -> Self {
        Self { inner, out }
    }

    /// Returns the wrapped transport, for a recording layer underneath.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: Transport> Transport for HexTransport<'_, T> {
    fn command(&mut self, frame: &[u8]) -> Event {
        write_hex_line(self.out, "> ", frame);
        let event = self.inner.command(frame);
        match &event {
            Event::Reply { body, .. } => {
                if body.is_empty() {
                    let _ = writeln!(self.out, "< empty");
                } else {
                    write_hex_line(self.out, "< ", body);
                }
            }
            Event::ReplyWithoutBody => {
                let _ = writeln!(self.out, "< empty");
            }
            // A finger event, a transport failure and a cancellation carry no reply body.
            Event::Finger | Event::Transport(_) | Event::Cancelled => {}
        }
        event
    }

    fn wait_finger(&mut self) -> Event {
        self.inner.wait_finger()
    }
}

fn write_hex_line(out: &mut dyn Write, prefix: &str, bytes: &[u8]) {
    let _ = write!(out, "{prefix}");
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    let _ = writeln!(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use cv3_core::{ScriptedOutcome, ScriptedTransport};

    #[test]
    fn dumps_each_host_frame_and_reply_body_in_lowercase_hex() {
        let mut out = Vec::new();
        let mut transport = HexTransport::new(
            ScriptedTransport::new([
                ScriptedOutcome::Reply {
                    status: 3,
                    body: vec![0xab, 0xcd],
                },
                ScriptedOutcome::Finger,
                ScriptedOutcome::ReplyWithoutBody,
            ]),
            &mut out,
        );

        assert_eq!(
            transport.command(&[0x01, 0xfe]),
            Event::Reply {
                status: 3,
                body: vec![0xab, 0xcd],
            }
        );
        assert_eq!(transport.wait_finger(), Event::Finger);
        assert_eq!(transport.command(&[0x04]), Event::ReplyWithoutBody);
        drop(transport);

        let text = String::from_utf8(out).expect("the dump is UTF-8");
        assert_eq!(text, "> 01fe\n< abcd\n> 04\n< empty\n");
    }
}
