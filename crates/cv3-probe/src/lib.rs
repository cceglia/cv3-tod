//! Probe-side plumbing for the ControlVault 3 fingerprint sensor.

pub mod cli;
pub mod discovery;
pub mod driver;
pub mod exchange;
pub mod layout;
pub mod nusb_backend;
pub mod random;
pub mod signals;
pub mod usb;

#[cfg(test)]
mod testing;
