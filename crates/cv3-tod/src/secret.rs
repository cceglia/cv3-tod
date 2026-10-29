//! Fresh key material for one secure session.
//!
//! The core never generates randomness: it takes the host keypair, both nonces and the wrapped
//! open's IV from its caller. The plugin draws them from the operating system per open and stores
//! nothing; the core zeroes the derived key when the session closes.

use std::fmt;

use cv3_core::crypto::{BLOCK_LEN, HostKey};
use cv3_core::handshake::NONCE_LEN;

/// Everything one open needs that must be fresh per session.
pub struct Secrets {
    pub host_key: HostKey,
    pub client_nonce: [u8; NONCE_LEN],
    pub host_nonce: [u8; NONCE_LEN],
    pub open_iv: [u8; BLOCK_LEN],
}

impl Secrets {
    /// Draws a keypair, both nonces and the IV from the operating system.
    ///
    /// A random 32-byte string is not always a valid P-256 scalar (it must be below the curve order
    /// and non-zero), so the draw is repeated until the core accepts it. The retry rate is below
    /// 2^-32.
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
            open_iv: random_bytes()?,
        })
    }
}

/// The three IVs one enrolment needs.
///
/// The core generates no randomness: the enrolment derives one IV per wrapped frame from
/// [`Self::enrol`], and the confirmation touch uses the other two for its capture arm and its match
/// request. They are drawn fresh for every enrolment so no two CBC frames share an IV.
pub struct EnrolIvs {
    pub enrol: [u8; BLOCK_LEN],
    pub confirmation_capture: [u8; BLOCK_LEN],
    pub matching: [u8; BLOCK_LEN],
}

impl EnrolIvs {
    /// Draws the three IVs from the operating system.
    pub fn generate() -> Result<Self, RandomError> {
        Ok(Self {
            enrol: random_bytes()?,
            confirmation_capture: random_bytes()?,
            matching: random_bytes()?,
        })
    }
}

/// The two IVs one verification needs.
///
/// The core generates no randomness: the capture arm and the match request each take a fresh IV.
/// They are drawn per verification so no two CBC frames share one.
pub struct VerifyIvs {
    pub capture: [u8; BLOCK_LEN],
    pub matching: [u8; BLOCK_LEN],
}

impl VerifyIvs {
    /// Draws the two IVs from the operating system.
    pub fn generate() -> Result<Self, RandomError> {
        Ok(Self {
            capture: random_bytes()?,
            matching: random_bytes()?,
        })
    }
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
    fn two_opens_use_different_key_material() {
        let first = Secrets::generate().expect("OS randomness");
        let second = Secrets::generate().expect("OS randomness");

        assert_ne!(first.host_key.public_key(), second.host_key.public_key());
        assert_ne!(first.client_nonce, second.client_nonce);
        assert_ne!(first.host_nonce, second.host_nonce);
        assert_ne!(first.open_iv, second.open_iv);
    }

    #[test]
    fn an_enrolment_uses_three_fresh_different_ivs() {
        let ivs = EnrolIvs::generate().expect("OS randomness");
        let again = EnrolIvs::generate().expect("OS randomness");

        assert_ne!(ivs.enrol, ivs.confirmation_capture);
        assert_ne!(ivs.enrol, ivs.matching);
        assert_ne!(ivs.confirmation_capture, ivs.matching);
        assert_ne!(ivs.enrol, again.enrol);
    }

    #[test]
    fn a_verification_uses_two_fresh_different_ivs() {
        let ivs = VerifyIvs::generate().expect("OS randomness");
        let again = VerifyIvs::generate().expect("OS randomness");

        assert_ne!(ivs.capture, ivs.matching);
        assert_ne!(ivs.capture, again.capture);
    }
}
