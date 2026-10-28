//! The transport error type shared by discovery and the command exchange.

use core::fmt;

/// A failure of the USB layer, already classified by what the caller can do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsbError {
    NotFound,
    Busy,
    PermissionDenied,
    Disconnected,
    Timeout,
    Stall,
    Other(String),
}

impl fmt::Display for UsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("device not found"),
            Self::Busy => f.write_str("interface is already claimed by another process"),
            Self::PermissionDenied => f.write_str("permission denied"),
            Self::Disconnected => f.write_str("device disconnected"),
            Self::Timeout => f.write_str("transfer timed out"),
            Self::Stall => f.write_str("endpoint stalled"),
            Self::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for UsbError {}
