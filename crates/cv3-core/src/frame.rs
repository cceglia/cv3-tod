//! Frame layout: a fixed 44-byte header followed by parameters.
//!
//! ```text
//! +0   u32  magic = 1
//! +4   u32  total frame length, header included
//! +8   u16  command
//! +10  u8   attribute
//! +11  u8   encoding
//! +12  u32  kind = 2
//! +16  u32  session handle
//! +20  u32  status (replies only, plaintext even inside wrapped frames)
//! +24  16B  IV (wrapped frames)
//! +40  u32  declared parameter length
//! +44  ...  parameters
//! ```
//!
//! Two lengths coexist on purpose. `total_len` counts the bytes on the wire; the length at
//! [`PARAM_LEN_OFFSET`] counts only the leading parameter block, before the MAC token and padding
//! that a wrapped frame adds inside the encryption. A wrapped frame therefore has a declared
//! length smaller than its parameter area, which is why [`build_wrapped`] takes it explicitly.

use std::fmt;

use crate::proto::Encoding;

pub const HEADER_LEN: usize = 44;
pub const IV_OFFSET: usize = 24;
pub const PARAM_LEN_OFFSET: usize = 40;

const MAGIC: u32 = 1;
const KIND: u32 = 2;
const STATUS_OFFSET: usize = 20;

/// The parts of a frame the core needs to route a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Bytes on the wire, header included.
    pub total_len: u32,
    pub cmd: u16,
    pub attr: u8,
    pub encoding: u8,
    pub handle: u32,
    /// Sensor status word; `0` is success. Meaningless on host → sensor frames.
    pub status: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer bytes than a header.
    Short { got: usize, need: usize },
    /// First word is not [`MAGIC`].
    BadMagic(u32),
    /// The declared total length disagrees with the buffer.
    LengthMismatch { declared: u32, actual: usize },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short { got, need } => {
                write!(f, "frame is {got} bytes, a header needs {need}")
            }
            Self::BadMagic(word) => write!(f, "bad magic {word:#x}"),
            Self::LengthMismatch { declared, actual } => {
                write!(f, "frame declares {declared} bytes but is {actual}")
            }
        }
    }
}

impl std::error::Error for FrameError {}

impl Header {
    /// Reads a header from the first [`HEADER_LEN`] bytes of `buf`, without checking that the rest
    /// of the buffer agrees with the declared length.
    pub fn parse(buf: &[u8]) -> Result<Self, FrameError> {
        if buf.len() < HEADER_LEN {
            return Err(FrameError::Short {
                got: buf.len(),
                need: HEADER_LEN,
            });
        }

        let magic = le32(buf, 0);
        if magic != MAGIC {
            return Err(FrameError::BadMagic(magic));
        }

        Ok(Self {
            total_len: le32(buf, 4),
            cmd: u16::from_le_bytes([buf[8], buf[9]]),
            attr: buf[10],
            encoding: buf[11],
            handle: le32(buf, 16),
            status: le32(buf, STATUS_OFFSET),
        })
    }

    /// Bytes after the header, as declared. Saturates rather than trusting the sensor.
    pub fn parameter_len(&self) -> usize {
        (self.total_len as usize).saturating_sub(HEADER_LEN)
    }
}

/// Parses a header and checks the declared length against the buffer, which is what a reply must
/// satisfy before its parameters are interpreted.
pub fn validate(buf: &[u8]) -> Result<Header, FrameError> {
    let header = Header::parse(buf)?;
    if header.total_len as usize != buf.len() {
        return Err(FrameError::LengthMismatch {
            declared: header.total_len,
            actual: buf.len(),
        });
    }
    Ok(header)
}

/// Builds an unwrapped frame: the declared parameter length is the parameter length.
pub fn build_plain(cmd: u16, attr: u8, handle: u32, param: &[u8]) -> Vec<u8> {
    build(
        Encoding::Plain,
        cmd,
        attr,
        handle,
        param.len() as u32,
        param,
    )
}

/// Builds a plain frame carrying an explicit status word, as a reply does.
///
/// Host → sensor commands carry status zero; this constructor exists so fixtures and the scripted
/// transport build replies through the same codec as the parser, rather than by poking offsets.
pub fn build_plain_reply(cmd: u16, attr: u8, handle: u32, status: u32, param: &[u8]) -> Vec<u8> {
    let mut frame = build_plain(cmd, attr, handle, param);
    put32(&mut frame, STATUS_OFFSET, status);
    frame
}

/// Builds the close-session frame that releases a session handle.
///
/// `cmd 0x04`, attr `0x40`, encoding `CloseHandle` (0x04), header handle zero, and a 12-byte
/// parameter block `[u32 0, u32 4, u32 handle]`. This is the frame the sensor needs before the
/// host forgets a handle it learned during the handshake.
pub fn build_close_handle(handle: u32) -> Vec<u8> {
    let mut param = [0u8; 12];
    put32(&mut param, 0, 0);
    put32(&mut param, 4, 4);
    put32(&mut param, 8, handle);
    build(
        Encoding::CloseHandle,
        crate::proto::cmd::CLOSE_SESSION,
        crate::proto::attr::CLOSE_SESSION,
        0,
        12,
        &param,
    )
}

/// Builds the sessionless cancel-capture frame.
///
/// `cmd 0x68`, attr `0x44`, plain encoding, header handle zero, and the same 12-byte
/// `[u32 0, u32 4, u32 handle]` parameter block as the close. Teardown sends this before the close
/// so a capture armed on the sensor cannot outlive the session.
pub fn build_cancel_capture(handle: u32) -> Vec<u8> {
    let mut param = [0u8; 12];
    put32(&mut param, 0, 0);
    put32(&mut param, 4, 4);
    put32(&mut param, 8, handle);
    build_plain(
        crate::proto::cmd::CANCEL_CAPTURE,
        crate::proto::attr::CANCEL_SESSIONLESS,
        0,
        &param,
    )
}

/// Builds the mid-session cancel-capture frame.
///
/// `cmd 0x68`, attr `0x40`, plain encoding, the **live session handle in the header**, and the
/// same 12-byte `[u32 0, u32 4, u32 handle]` parameter block as the close. It is the cancel the
/// reference sends when a capture is already armed but the session is still usable; unlike the
/// sessionless cancel a teardown sends, this frame leaves the session open. Being plain, it does
/// not advance the wrap sequence.
pub fn build_cancel_capture_mid(handle: u32) -> Vec<u8> {
    let mut param = [0u8; 12];
    put32(&mut param, 0, 0);
    put32(&mut param, 4, 4);
    put32(&mut param, 8, handle);
    build_plain(
        crate::proto::cmd::CANCEL_CAPTURE,
        crate::proto::attr::CANCEL_SESSION,
        handle,
        &param,
    )
}

/// Builds a wrapped frame from already-encrypted parameters.
///
/// `declared_len` is the length of the leading parameter block that the MAC covers, not the
/// ciphertext length; `ciphertext` is placed at [`HEADER_LEN`] and `iv` at [`IV_OFFSET`].
pub fn build_wrapped(
    cmd: u16,
    attr: u8,
    handle: u32,
    iv: &[u8; 16],
    declared_len: u32,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut frame = build(
        Encoding::Wrapped,
        cmd,
        attr,
        handle,
        declared_len,
        ciphertext,
    );
    frame[IV_OFFSET..IV_OFFSET + 16].copy_from_slice(iv);
    frame
}

fn build(
    encoding: Encoding,
    cmd: u16,
    attr: u8,
    handle: u32,
    declared_len: u32,
    param: &[u8],
) -> Vec<u8> {
    let total = HEADER_LEN + param.len();
    let mut frame = vec![0u8; total];

    put32(&mut frame, 0, MAGIC);
    put32(&mut frame, 4, total as u32);
    frame[8..10].copy_from_slice(&cmd.to_le_bytes());
    frame[10] = attr;
    frame[11] = encoding as u8;
    put32(&mut frame, 12, KIND);
    put32(&mut frame, 16, handle);
    put32(&mut frame, PARAM_LEN_OFFSET, declared_len);
    frame[HEADER_LEN..].copy_from_slice(param);

    frame
}

fn le32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn put32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{attr, cmd};

    fn challenge_param() -> [u8; 24] {
        let mut param = [0u8; 24];
        param[..20].fill(0xAB);
        param[20..].copy_from_slice(&1u32.to_le_bytes());
        param
    }

    #[test]
    fn challenge_frame_matches_the_observed_layout() {
        let param = challenge_param();
        let frame = build_plain(cmd::CHALLENGE, attr::CHALLENGE, 0, &param);

        assert_eq!(frame.len(), 68);
        assert_eq!(le32(&frame, 0), 1, "magic");
        assert_eq!(le32(&frame, 4), 68, "total length");
        assert_eq!(&frame[8..10], &[0x23u8, 0x00], "command");
        assert_eq!(frame[10], 0x41, "attribute");
        assert_eq!(frame[11], Encoding::Plain as u8, "encoding");
        assert_eq!(le32(&frame, 12), 2, "kind");
        assert_eq!(le32(&frame, 16), 0, "handle");
        assert_eq!(le32(&frame, 20), 0, "status is zero on the wire");
        assert_eq!(le32(&frame, PARAM_LEN_OFFSET), 24, "declared length");
        assert_eq!(&frame[HEADER_LEN..], &param);
    }

    #[test]
    fn wrapped_frame_carries_iv_and_declared_length() {
        let iv = [0x11u8; 16];
        let ciphertext = [0x22u8; 96];
        let frame = build_wrapped(
            cmd::OPEN_SESSION,
            attr::SESSION,
            0x1234_5678,
            &iv,
            36,
            &ciphertext,
        );

        assert_eq!(frame.len(), HEADER_LEN + 96);
        assert_eq!(frame[11], Encoding::Wrapped as u8);
        assert_eq!(&frame[IV_OFFSET..IV_OFFSET + 16], &iv);
        assert_eq!(le32(&frame, PARAM_LEN_OFFSET), 36);
        assert_eq!(&frame[HEADER_LEN..], &ciphertext);

        let header = validate(&frame).expect("frame validates");
        assert_eq!(header.handle, 0x1234_5678);
        assert_eq!(header.cmd, cmd::OPEN_SESSION);
        assert_eq!(header.parameter_len(), 96);
    }

    #[test]
    fn reply_status_is_read_from_offset_20() {
        let mut frame = build_plain(cmd::VERIFY, attr::CAPTURE, 7, &[0u8; 32]);
        put32(&mut frame, STATUS_OFFSET, 0x85);

        let header = validate(&frame).expect("frame validates");
        assert_eq!(header.status, 0x85);
        assert_eq!(header.attr, attr::CAPTURE);
    }

    #[test]
    fn a_plain_reply_carries_its_status_through_the_codec() {
        let frame = build_plain_reply(cmd::CHALLENGE, attr::CHALLENGE, 7, 0x8c, &[0u8; 148]);

        assert_eq!(le32(&frame, STATUS_OFFSET), 0x8c);
        let header = validate(&frame).expect("frame validates");
        assert_eq!(header.status, 0x8c);
        assert_eq!(header.handle, 7);
        assert_eq!(header.total_len as usize, HEADER_LEN + 148);
    }

    #[test]
    fn the_close_handle_frame_matches_the_wire_layout() {
        let frame = build_close_handle(0x1122_3344);

        assert_eq!(frame.len(), 56);
        assert_eq!(le32(&frame, 0), 1, "magic");
        assert_eq!(le32(&frame, 4), 56, "total length");
        assert_eq!(&frame[8..10], &[0x04, 0x00], "close-session command");
        assert_eq!(frame[10], 0x40, "attribute");
        assert_eq!(frame[11], Encoding::CloseHandle as u8, "encoding");
        assert_eq!(le32(&frame, 16), 0, "header handle is zero");
        assert_eq!(le32(&frame, PARAM_LEN_OFFSET), 12, "declared length");
        assert_eq!(le32(&frame, HEADER_LEN), 0, "tag");
        assert_eq!(le32(&frame, HEADER_LEN + 4), 4, "value length");
        assert_eq!(le32(&frame, HEADER_LEN + 8), 0x1122_3344, "handle");
    }

    #[test]
    fn the_cancel_capture_frame_matches_the_wire_layout() {
        let frame = build_cancel_capture(0x1122_3344);

        assert_eq!(frame.len(), 56);
        assert_eq!(le32(&frame, 0), 1, "magic");
        assert_eq!(le32(&frame, 4), 56, "total length");
        assert_eq!(&frame[8..10], &[0x68, 0x00], "cancel-capture command");
        assert_eq!(frame[10], 0x44, "sessionless attribute");
        assert_eq!(frame[11], Encoding::Plain as u8, "plain encoding");
        assert_eq!(le32(&frame, 16), 0, "header handle is zero");
        assert_eq!(le32(&frame, PARAM_LEN_OFFSET), 12, "declared length");
        assert_eq!(le32(&frame, HEADER_LEN), 0, "tag");
        assert_eq!(le32(&frame, HEADER_LEN + 4), 4, "value length");
        assert_eq!(le32(&frame, HEADER_LEN + 8), 0x1122_3344, "handle");
    }

    #[test]
    fn the_mid_session_cancel_frame_is_plain_and_carries_the_live_handle() {
        let frame = build_cancel_capture_mid(0x1122_3344);

        assert_eq!(frame.len(), 56);
        assert_eq!(le32(&frame, 0), 1, "magic");
        assert_eq!(le32(&frame, 4), 56, "total length");
        assert_eq!(&frame[8..10], &[0x68, 0x00], "cancel-capture command");
        assert_eq!(frame[10], 0x40, "session-scoped attribute");
        assert_eq!(frame[11], Encoding::Plain as u8, "plain encoding");
        assert_eq!(
            le32(&frame, 16),
            0x1122_3344,
            "header handle is the session"
        );
        assert_eq!(le32(&frame, PARAM_LEN_OFFSET), 12, "declared length");
        assert_eq!(le32(&frame, HEADER_LEN), 0, "tag");
        assert_eq!(le32(&frame, HEADER_LEN + 4), 4, "value length");
        assert_eq!(le32(&frame, HEADER_LEN + 8), 0x1122_3344, "handle");
    }

    #[test]
    fn short_and_bad_magic_are_rejected() {
        assert!(matches!(
            Header::parse(&[0u8; HEADER_LEN - 1]),
            Err(FrameError::Short { got: 43, need: 44 })
        ));

        let mut frame = build_plain(cmd::CHALLENGE, attr::CHALLENGE, 0, &[0u8; 24]);
        frame[0] = 9;
        assert_eq!(Header::parse(&frame), Err(FrameError::BadMagic(9)));
    }

    #[test]
    fn a_buffer_that_disagrees_with_its_declared_length_is_rejected() {
        let frame = build_plain(cmd::CHALLENGE, attr::CHALLENGE, 0, &[0u8; 24]);

        let mut longer = frame.clone();
        longer.push(0);
        assert!(matches!(
            validate(&longer),
            Err(FrameError::LengthMismatch {
                declared: 68,
                actual: 69
            })
        ));

        assert!(matches!(
            validate(&frame[..HEADER_LEN - 1]),
            Err(FrameError::Short { .. })
        ));
    }
}
