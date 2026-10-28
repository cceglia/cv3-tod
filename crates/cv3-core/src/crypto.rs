//! The cryptographic primitives the sensor's protocol needs.
//!
//! Four primitives, each pinned by a known-answer vector from a public standard:
//!
//! * AES-128-CBC with PKCS#7 — the secure channel's encryption.
//! * HMAC-SHA-256 — the wrapped-frame integrity token (its key is a protocol constant, so the
//!   token proves protocol knowledge, not authenticity).
//! * SHA-1 — the handshake key schedule.
//! * P-256 ECDH — the handshake's shared secret.
//!
//! Nothing here generates randomness or reads the clock: the probe supplies the host secret key
//! and both nonces, which keeps the core free of I/O and of an RNG dependency.

use std::fmt;

use aes::Aes128;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};
use sha2::Sha256;

/// AES block size, and the size of the frames' IV field.
pub const BLOCK_LEN: usize = 16;
/// Length of the session key (AES-128).
pub const SESSION_KEY_LEN: usize = 16;
/// SHA-1 digest length, which is also the length of the handshake's `master` value.
pub const SHA1_LEN: usize = 20;

/// A cryptographic operation that failed on device-supplied input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Ciphertext is not a whole number of AES blocks.
    BadLength { got: usize },
    /// PKCS#7 padding is absent or inconsistent.
    BadPadding,
    /// The host secret is not a valid P-256 scalar.
    InvalidSecretKey,
    /// The device's public key is not a valid P-256 point.
    InvalidPublicKey,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength { got } => {
                write!(f, "ciphertext is {got} bytes, not a whole number of blocks")
            }
            Self::BadPadding => f.write_str("invalid PKCS#7 padding"),
            Self::InvalidSecretKey => f.write_str("invalid P-256 secret key"),
            Self::InvalidPublicKey => f.write_str("invalid P-256 public key"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Pads `data` to a whole number of blocks with PKCS#7.
///
/// A complete block always adds another full block of padding, so unpadding is unambiguous.
pub fn pad_pkcs7(data: &[u8]) -> Vec<u8> {
    let pad = BLOCK_LEN - (data.len() % BLOCK_LEN);
    let mut padded = Vec::with_capacity(data.len() + pad);
    padded.extend_from_slice(data);
    padded.extend(std::iter::repeat_n(pad as u8, pad));
    padded
}

/// Removes and validates PKCS#7 padding.
pub fn unpad_pkcs7(data: &[u8]) -> Result<&[u8], CryptoError> {
    if data.is_empty() || !data.len().is_multiple_of(BLOCK_LEN) {
        return Err(CryptoError::BadPadding);
    }
    let pad = *data.last().expect("not empty") as usize;
    if pad == 0 || pad > BLOCK_LEN || pad > data.len() {
        return Err(CryptoError::BadPadding);
    }
    let split = data.len() - pad;
    if data[split..].iter().any(|byte| *byte as usize != pad) {
        return Err(CryptoError::BadPadding);
    }
    Ok(&data[..split])
}

/// Encrypts with AES-128-CBC and PKCS#7 padding.
pub fn encrypt_cbc(key: &[u8; SESSION_KEY_LEN], iv: &[u8; BLOCK_LEN], plaintext: &[u8]) -> Vec<u8> {
    let padded = pad_pkcs7(plaintext);
    encrypt_cbc_raw(key, iv, &padded).expect("PKCS#7 output is block aligned")
}

/// Decrypts AES-128-CBC and removes its PKCS#7 padding.
pub fn decrypt_cbc(
    key: &[u8; SESSION_KEY_LEN],
    iv: &[u8; BLOCK_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut plain = decrypt_cbc_raw(key, iv, ciphertext)?;
    let len = unpad_pkcs7(&plain)?.len();
    plain.truncate(len);
    Ok(plain)
}

/// Encrypts whole blocks with no padding. Exposed for the NIST vector and for callers that carry
/// their own padding inside the plaintext.
pub fn encrypt_cbc_raw(
    key: &[u8; SESSION_KEY_LEN],
    iv: &[u8; BLOCK_LEN],
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if !data.len().is_multiple_of(BLOCK_LEN) {
        return Err(CryptoError::BadLength { got: data.len() });
    }
    Ok(cbc::Encryptor::<Aes128>::new(key.into(), iv.into())
        .encrypt_padded_vec_mut::<NoPadding>(data))
}

/// Decrypts whole blocks with no padding.
pub fn decrypt_cbc_raw(
    key: &[u8; SESSION_KEY_LEN],
    iv: &[u8; BLOCK_LEN],
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if data.is_empty() || !data.len().is_multiple_of(BLOCK_LEN) {
        return Err(CryptoError::BadLength { got: data.len() });
    }
    cbc::Decryptor::<Aes128>::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<NoPadding>(data)
        .map_err(|_| CryptoError::BadLength { got: data.len() })
}

/// HMAC-SHA-256 over `data` under `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// SHA-1 over `data`.
pub fn sha1(data: &[u8]) -> [u8; SHA1_LEN] {
    let digest = Sha1::digest(data);
    let mut out = [0u8; SHA1_LEN];
    out.copy_from_slice(&digest);
    out
}

/// SHA-256 over `data`.
///
/// The secure session's MAC key is `SHA-256` of a published seed, so this hash is protocol
/// material rather than only a fingerprinting helper.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// A host P-256 keypair.
///
/// The sensor does not authenticate the host, so the probe generates one per run and never stores
/// it. The wrapped `p256::SecretKey` zeroes its scalar on drop.
pub struct HostKey(p256::SecretKey);

impl HostKey {
    /// Parses a 32-byte big-endian scalar.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        p256::SecretKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidSecretKey)
    }

    /// The uncompressed public key as `X || Y`, the 64 bytes the sensor's `0x24` frame carries.
    pub fn public_key(&self) -> [u8; 64] {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let point = self.0.public_key().to_encoded_point(false);
        let encoded = point.as_bytes();
        debug_assert_eq!(encoded.len(), 65, "uncompressed P-256 point");
        let mut out = [0u8; 64];
        out.copy_from_slice(&encoded[1..]);
        out
    }

    /// ECDH with the device's `X || Y` public key, returning the 32-byte X coordinate.
    pub fn ecdh(&self, peer: &[u8; 64]) -> Result<[u8; 32], CryptoError> {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(peer);
        let public =
            p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| CryptoError::InvalidPublicKey)?;

        let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), public.as_affine());
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        assert_eq!(digits.len() % 2, 0, "hex string has whole bytes");
        digits
            .chunks(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).expect("hex digit") as u8;
                let low = (pair[1] as char).to_digit(16).expect("hex digit") as u8;
                (high << 4) | low
            })
            .collect()
    }

    fn array<const N: usize>(text: &str) -> [u8; N] {
        let bytes = unhex(text);
        assert_eq!(bytes.len(), N, "vector has {N} bytes");
        bytes.try_into().expect("length checked")
    }

    // NIST SP 800-38A, F.2.1 "CBC-AES128.Encrypt".
    #[test]
    fn aes_cbc_matches_nist_sp_800_38a_f2_1() {
        let key = array::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = array::<16>("000102030405060708090a0b0c0d0e0f");
        let plaintext = unhex(
            "6bc1bee22e409f96e93d7e117393172a
             ae2d8a571e03ac9c9eb76fac45af8e51
             30c81c46a35ce411e5fbc1191a0a52ef
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let expected = unhex(
            "7649abac8119b246cee98e9b12e9197d
             5086cb9b507219ee95db113a917678b2
             73bed6b8e3c1743b7116e69e22229516
             3ff1caa1681fac09120eca307586e1a7",
        );

        let ciphertext = encrypt_cbc_raw(&key, &iv, &plaintext).expect("whole blocks");
        assert_eq!(ciphertext, expected);
        assert_eq!(
            decrypt_cbc_raw(&key, &iv, &ciphertext).expect("whole blocks"),
            plaintext
        );
    }

    #[test]
    fn pkcs7_padding_is_unambiguous_and_rejects_bad_input() {
        assert_eq!(pad_pkcs7(b""), [0x10; 16]);
        assert_eq!(pad_pkcs7(b"abc")[3..], [0x0d; 13]);
        assert_eq!(unpad_pkcs7(&pad_pkcs7(b"abc")).expect("valid"), b"abc");
        assert_eq!(unpad_pkcs7(&pad_pkcs7(b"")).expect("valid"), b"");

        assert_eq!(unpad_pkcs7(&[]), Err(CryptoError::BadPadding));
        assert_eq!(unpad_pkcs7(&[0x00; 16]), Err(CryptoError::BadPadding));
        assert_eq!(unpad_pkcs7(&[0x11; 16]), Err(CryptoError::BadPadding));
        let mut inconsistent = [0x02; 16];
        inconsistent[15] = 0x02;
        inconsistent[14] = 0x03;
        assert_eq!(unpad_pkcs7(&inconsistent), Err(CryptoError::BadPadding));
        assert_eq!(
            unpad_pkcs7(&[0x01; 15]),
            Err(CryptoError::BadPadding),
            "not a whole block"
        );
    }

    #[test]
    fn aes_cbc_with_pkcs7_round_trips_a_partial_block() {
        let key = [0x42; 16];
        let iv = [0x24; 16];

        for length in [0, 1, 15, 16, 17, 31, 32, 33] {
            let plaintext: Vec<u8> = (0..length).map(|byte| byte as u8).collect();
            let ciphertext = encrypt_cbc(&key, &iv, &plaintext);
            assert_eq!(ciphertext.len() % 16, 0);
            assert!(ciphertext.len() > plaintext.len());
            assert_eq!(
                decrypt_cbc(&key, &iv, &ciphertext).expect("valid"),
                plaintext
            );
        }
    }

    // RFC 4231, test case 2.
    #[test]
    fn hmac_sha256_matches_rfc_4231_case_2() {
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
            array::<32>(
                "5bdcc146bf60754e6a042426089575c7
                 5a003f089d2739839dec58b964ec3843"
            )
        );
    }

    // RFC 4231, test case 1.
    #[test]
    fn hmac_sha256_matches_rfc_4231_case_1() {
        assert_eq!(
            hmac_sha256(&[0x0b; 20], b"Hi There"),
            array::<32>(
                "b0344c61d8db38535ca8afceaf0bf12b
                 881dc200c9833da726e9376c2e32cff7"
            )
        );
    }

    // FIPS 180-2, appendix A ("abc") and the empty-message value from the same SHA-1 definition.
    #[test]
    fn sha1_matches_fips_180_2() {
        assert_eq!(
            sha1(b"abc"),
            array::<20>("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            sha1(b""),
            array::<20>("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_eq!(
            sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            array::<20>("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        );
    }

    // FIPS 180-2, appendix B.1 ("abc") and the empty-message value from the same definition.
    #[test]
    fn sha256_matches_fips_180_2() {
        assert_eq!(
            sha256(b"abc"),
            array::<32>(
                "ba7816bf8f01cfea414140de5dae2223
                 b00361a396177a9cb410ff61f20015ad"
            )
        );
        assert_eq!(
            sha256(b""),
            array::<32>(
                "e3b0c44298fc1c149afbf4c8996fb924
                 27ae41e4649b934ca495991b7852b855"
            )
        );
    }

    // RFC 5903, section 8.1 (NIST P-256), initiator i and responder r.
    #[test]
    fn ecdh_matches_rfc_5903_vector() {
        let host_secret = array::<32>(
            "c88f01f510d9ac3f70a292daa2316de5
             44e9aab8afe84049c62a9c57862d1433",
        );
        let host_public = array::<64>(
            "dad0b65394221cf9b051e1feca5787d0
             98dfe637fc90b9ef945d0c3772581180
             5271a0461cdb8252d61f1c456fa3e59a
             b1f45b33accf5f58389e0577b8990bb3",
        );
        let device_public = array::<64>(
            "d12dfb5289c8d4f81208b70270398c34
             2296970a0bccb74c736fc7554494bf63
             56fbf3ca366cc23e8157854c13c58d6a
             ac23f046ada30f8353e74f33039872ab",
        );
        let shared = array::<32>(
            "d6840f6b42f6edafd13116e0e1256520
             2fef8e9ece7dce03812464d04b9442de",
        );

        let host = HostKey::from_bytes(&host_secret).expect("RFC scalar is valid");
        assert_eq!(host.public_key(), host_public, "g^i");
        assert_eq!(host.ecdh(&device_public).expect("valid point"), shared);
    }

    #[test]
    fn an_invalid_scalar_or_point_is_rejected() {
        assert_eq!(
            HostKey::from_bytes(&[0u8; 32]).err(),
            Some(CryptoError::InvalidSecretKey),
            "zero is not a scalar"
        );
        // The curve order itself is zero modulo the order, so it is not a secret key.
        let order = array::<32>(
            "ffffffff00000000ffffffffffffffff
             bce6faada7179e84f3b9cac2fc632551",
        );
        assert_eq!(
            HostKey::from_bytes(&order).err(),
            Some(CryptoError::InvalidSecretKey)
        );

        let host = HostKey::from_bytes(&[1u8; 32]).expect("valid");
        assert_eq!(
            host.ecdh(&[0u8; 64]).err(),
            Some(CryptoError::InvalidPublicKey)
        );
    }
}
