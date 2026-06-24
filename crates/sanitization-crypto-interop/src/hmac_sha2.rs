//! HMAC-SHA2 helpers with upstream HMAC zeroization enabled.
//!
//! Prefer these helpers over manually hashing `key || message` with raw SHA-2.
//! Raw SHA-2 keyed constructions are vulnerable to length-extension and other
//! misuse patterns. HMAC is the standard MAC construction for SHA-2.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

/// Error returned when an HMAC key is rejected by the upstream implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidHmacKey;

/// Compute HMAC-SHA256.
///
/// The returned tag is ordinary caller-owned memory. If the tag is sensitive,
/// clear it with `sanitization::sanitize_bytes` after use or move it directly
/// into a secret container.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; 32], InvalidHmacKey> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| InvalidHmacKey)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

/// Compute HMAC-SHA384.
///
/// The returned tag is ordinary caller-owned memory. If the tag is sensitive,
/// clear it with `sanitization::sanitize_bytes` after use or move it directly
/// into a secret container.
pub fn hmac_sha384(key: &[u8], message: &[u8]) -> Result<[u8; 48], InvalidHmacKey> {
    let mut mac = HmacSha384::new_from_slice(key).map_err(|_| InvalidHmacKey)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

/// Compute HMAC-SHA512.
///
/// The returned tag is ordinary caller-owned memory. If the tag is sensitive,
/// clear it with `sanitization::sanitize_bytes` after use or move it directly
/// into a secret container.
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> Result<[u8; 64], InvalidHmacKey> {
    let mut mac = HmacSha512::new_from_slice(key).map_err(|_| InvalidHmacKey)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_1() {
        let tag = hmac_sha256(&[0x0b; 20], b"Hi There").unwrap();

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
        let tag = hmac_sha512(b"key", b"message").unwrap();
        assert_eq!(tag.len(), 64);
    }
}
