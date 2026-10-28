//! Synthetic fixtures shared by the core's integration tests.
//!
//! Every value comes from the protocol description or a public standard; nothing here was captured
//! from a sensor.

#![allow(dead_code)]

use cv3_core::crypto::HostKey;
use cv3_core::frame;
use cv3_core::proto::{attr, cmd};

pub const HANDLE: u32 = 0x1122_3344;

pub fn unhex<const N: usize>(text: &str) -> [u8; N] {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let bytes: Vec<u8> = digits
        .chunks(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex digit") as u8;
            let low = (pair[1] as char).to_digit(16).expect("hex digit") as u8;
            (high << 4) | low
        })
        .collect();
    assert_eq!(bytes.len(), N);
    bytes.try_into().expect("length checked")
}

/// RFC 5903, section 8.1: the initiator's scalar.
pub fn host_secret() -> [u8; 32] {
    unhex("c88f01f510d9ac3f70a292daa2316de5 44e9aab8afe84049c62a9c57862d1433")
}

/// RFC 5903, section 8.1: the initiator's public key (`g^i`).
pub fn host_public() -> [u8; 64] {
    unhex(
        "dad0b65394221cf9b051e1feca5787d0 98dfe637fc90b9ef945d0c3772581180 \
         5271a0461cdb8252d61f1c456fa3e59a b1f45b33accf5f58389e0577b8990bb3",
    )
}

/// RFC 5903, section 8.1: the responder's public key, used as the device's.
pub fn device_public() -> [u8; 64] {
    unhex(
        "d12dfb5289c8d4f81208b70270398c34 2296970a0bccb74c736fc7554494bf63 \
         56fbf3ca366cc23e8157854c13c58d6a ac23f046ada30f8353e74f33039872ab",
    )
}

pub fn device_nonce() -> [u8; 20] {
    unhex("000102030405060708090a0b0c0d0e0f10111213")
}

pub fn host_nonce() -> [u8; 20] {
    unhex("202122232425262728292a2b2c2d2e2f30313233")
}

pub fn client_nonce() -> [u8; 20] {
    unhex("404142434445464748494a4b4c4d4e4f50515253")
}

pub fn host_key() -> HostKey {
    HostKey::from_bytes(&host_secret()).expect("the RFC scalar is valid")
}

pub fn challenge_reply(status: u32) -> Vec<u8> {
    let mut param = [0u8; 148];
    param[..64].copy_from_slice(&device_public());
    param[64..128].fill(0xcc);
    param[128..].copy_from_slice(&device_nonce());
    frame::build_plain_reply(cmd::CHALLENGE, attr::CHALLENGE, HANDLE, status, &param)
}

pub fn response_reply(status: u32) -> Vec<u8> {
    frame::build_plain_reply(
        cmd::CHALLENGE_RESPONSE,
        attr::CHALLENGE_RESPONSE,
        HANDLE,
        status,
        &[],
    )
}

pub fn open_reply(status: u32) -> Vec<u8> {
    frame::build_plain_reply(cmd::OPEN_SESSION, attr::SESSION, HANDLE, status, &[])
}

pub fn challenge_frame() -> Vec<u8> {
    let mut param = [0u8; 24];
    param[..20].copy_from_slice(&client_nonce());
    param[20..].copy_from_slice(&1u32.to_le_bytes());
    frame::build_plain(cmd::CHALLENGE, attr::CHALLENGE, 0, &param)
}

pub fn response_frame() -> Vec<u8> {
    let mut param = [0u8; 84];
    param[..20].copy_from_slice(&host_nonce());
    param[20..].copy_from_slice(&host_public());
    frame::build_plain(
        cmd::CHALLENGE_RESPONSE,
        attr::CHALLENGE_RESPONSE,
        HANDLE,
        &param,
    )
}

pub fn fixed_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    for (index, byte) in iv.iter_mut().enumerate() {
        *byte = 0x10 + index as u8;
    }
    iv
}
