//! OS randomness for the probe.
//!
//! The core never generates randomness: the probe makes the fresh host keypair and both nonces,
//! then passes them in. Nothing here is stored.

use std::fmt;

use cv3_core::crypto::{BLOCK_LEN, HostKey};
use cv3_core::handshake::NONCE_LEN;

/// The fresh key material for one handshake.
pub struct RunSecrets {
    pub host_key: HostKey,
    pub client_nonce: [u8; NONCE_LEN],
    pub host_nonce: [u8; NONCE_LEN],
}

impl RunSecrets {
    /// Draws a keypair and both nonces from the operating system.
    ///
    /// A random 32-byte string is not always a valid P-256 scalar (it must be below the curve
    /// order and non-zero), so the draw is repeated until the core accepts it. The retry rate is
    /// below 2^-32.
    pub fn generate() -> Result<Self, RandomError> {
        let host_key = loop {
            let bytes = random_bytes::<32>()?;
            if let Ok(key) = HostKey::from_bytes(&bytes) {
                break key;
            }
        };
        Ok(Self {
            host_key,
            client_nonce: random_bytes()?,
            host_nonce: random_bytes()?,
        })
    }
}

/// Draws a fresh AES-CBC IV for a wrapped command from the operating system.
pub fn random_iv() -> Result<[u8; BLOCK_LEN], RandomError> {
    random_bytes()
}

/// The operating system refused to supply randomness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RandomError(pub String);

impl fmt::Display for RandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot read OS randomness: {}", self.0)
    }
}

impl std::error::Error for RandomError {}

fn random_bytes<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).map_err(|error| RandomError(error.to_string()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_runs_use_different_host_keys_and_nonces() {
        let first = RunSecrets::generate().expect("OS randomness");
        let second = RunSecrets::generate().expect("OS randomness");

        assert_ne!(first.host_key.public_key(), second.host_key.public_key());
        assert_ne!(first.client_nonce, second.client_nonce);
        assert_ne!(first.host_nonce, second.host_nonce);
    }

    #[test]
    fn two_wrapped_commands_use_different_ivs() {
        assert_ne!(
            random_iv().expect("OS randomness"),
            random_iv().expect("OS randomness")
        );
    }
}
