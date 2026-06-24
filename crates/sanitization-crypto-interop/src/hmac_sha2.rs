//! HMAC-SHA2 helpers with explicit scratch-buffer sanitization.
//!
//! Prefer these helpers over manually hashing `key || message` with raw SHA-2.
//! Raw SHA-2 keyed constructions are vulnerable to length-extension and other
//! misuse patterns. HMAC is the standard MAC construction for SHA-2.

use sanitization::sanitize_bytes;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::sha2::{sha256_digest, sha384_digest, sha512_digest};

/// Compute HMAC-SHA256.
///
/// The caller remains responsible for clearing `key` after use if it is stored
/// outside a `sanitization` secret container.
///
/// The returned tag is ordinary caller-owned memory. If the tag is sensitive,
/// clear it with `sanitization::sanitize_bytes` after use or move it directly
/// into a secret container.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > key_block.len() {
        let mut hashed_key = sha256_digest(key);
        key_block[..hashed_key.len()].copy_from_slice(&hashed_key);
        sanitize_bytes(&mut hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    xor_key_block_64(&key_block, &mut inner_pad, &mut outer_pad);

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let mut inner_hash: [u8; 32] = inner.finalize().into();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    let tag = outer.finalize().into();

    sanitize_bytes(&mut key_block);
    sanitize_bytes(&mut inner_pad);
    sanitize_bytes(&mut outer_pad);
    sanitize_bytes(&mut inner_hash);
    tag
}

/// Compute HMAC-SHA384.
///
/// The caller remains responsible for clearing `key` after use if it is stored
/// outside a `sanitization` secret container.
///
/// The returned tag is ordinary caller-owned memory. If the tag is sensitive,
/// clear it with `sanitization::sanitize_bytes` after use or move it directly
/// into a secret container.
#[must_use]
pub fn hmac_sha384(key: &[u8], message: &[u8]) -> [u8; 48] {
    let mut key_block = [0u8; 128];
    if key.len() > key_block.len() {
        let mut hashed_key = sha384_digest(key);
        key_block[..hashed_key.len()].copy_from_slice(&hashed_key);
        sanitize_bytes(&mut hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; 128];
    let mut outer_pad = [0x5cu8; 128];
    xor_key_block_128(&key_block, &mut inner_pad, &mut outer_pad);

    let mut inner = Sha384::new();
    inner.update(inner_pad);
    inner.update(message);
    let mut inner_hash: [u8; 48] = inner.finalize().into();

    let mut outer = Sha384::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    let tag = outer.finalize().into();

    sanitize_bytes(&mut key_block);
    sanitize_bytes(&mut inner_pad);
    sanitize_bytes(&mut outer_pad);
    sanitize_bytes(&mut inner_hash);
    tag
}

/// Compute HMAC-SHA512.
///
/// The caller remains responsible for clearing `key` after use if it is stored
/// outside a `sanitization` secret container.
///
/// The returned tag is ordinary caller-owned memory. If the tag is sensitive,
/// clear it with `sanitization::sanitize_bytes` after use or move it directly
/// into a secret container.
#[must_use]
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let mut key_block = [0u8; 128];
    if key.len() > key_block.len() {
        let mut hashed_key = sha512_digest(key);
        key_block[..hashed_key.len()].copy_from_slice(&hashed_key);
        sanitize_bytes(&mut hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; 128];
    let mut outer_pad = [0x5cu8; 128];
    xor_key_block_128(&key_block, &mut inner_pad, &mut outer_pad);

    let mut inner = Sha512::new();
    inner.update(inner_pad);
    inner.update(message);
    let mut inner_hash: [u8; 64] = inner.finalize().into();

    let mut outer = Sha512::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    let tag = outer.finalize().into();

    sanitize_bytes(&mut key_block);
    sanitize_bytes(&mut inner_pad);
    sanitize_bytes(&mut outer_pad);
    sanitize_bytes(&mut inner_hash);
    tag
}

#[inline]
fn xor_key_block_64(key_block: &[u8; 64], inner_pad: &mut [u8; 64], outer_pad: &mut [u8; 64]) {
    let mut index = 0;
    while index < key_block.len() {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
        index += 1;
    }
}

#[inline]
fn xor_key_block_128(key_block: &[u8; 128], inner_pad: &mut [u8; 128], outer_pad: &mut [u8; 128]) {
    let mut index = 0;
    while index < key_block.len() {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_1() {
        let tag = hmac_sha256(&[0x0b; 20], b"Hi There");

        assert_eq!(
            tag,
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ]
        );
    }

    #[test]
    fn hmac_sha512_returns_expected_size() {
        let tag = hmac_sha512(b"key", b"message");
        assert_eq!(tag.len(), 64);
    }
}
