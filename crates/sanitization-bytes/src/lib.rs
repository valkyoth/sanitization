#![no_std]
#![deny(unsafe_code)]

//! `bytes` integration wrappers for `sanitization`.
//!
//! This crate deliberately uses wrapper types instead of trait impls for
//! external types. Rust's orphan rules prevent implementing
//! `sanitization::SecureSanitize` directly for `bytes::BytesMut` here.

use bytes::BytesMut;
use core::fmt;
use sanitization::{sanitize_bytes, SecureSanitize};

#[cfg(test)]
extern crate std;

/// Clear-on-drop wrapper around [`BytesMut`].
///
/// Clearing expands the buffer to its reported capacity, volatile-clears that
/// initialized view, then resets the length to zero. This covers the owned
/// capacity exposed by `BytesMut`; it does not make claims about allocator
/// internals outside that buffer.
pub struct SecretBytesMut {
    inner: BytesMut,
}

impl SecretBytesMut {
    /// Create an empty secret byte buffer.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: BytesMut::new(),
        }
    }

    /// Allocate secret byte storage with at least `capacity` bytes.
    #[must_use]
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: BytesMut::with_capacity(capacity),
        }
    }

    /// Copy a slice into a new secret byte buffer.
    #[must_use]
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut inner = BytesMut::with_capacity(bytes.len());
        inner.extend_from_slice(bytes);
        Self { inner }
    }

    /// Wrap an existing [`BytesMut`].
    #[must_use]
    #[inline]
    pub fn from_bytes_mut(inner: BytesMut) -> Self {
        Self { inner }
    }

    /// Number of initialized bytes.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when there are no initialized bytes.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Reported capacity of the underlying [`BytesMut`].
    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Append bytes to the secret buffer.
    #[inline]
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.inner.extend_from_slice(bytes);
    }

    /// Borrow initialized bytes.
    #[must_use]
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_ref()
    }

    /// Run a closure with read-only access to initialized bytes.
    #[inline]
    pub fn with_secret<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> R {
        inspect(self.as_slice())
    }

    /// Run a closure with mutable access to initialized bytes.
    #[inline]
    pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut [u8]) -> R) -> R {
        edit(self.inner.as_mut())
    }

    /// Sanitize the reported capacity and clear the buffer.
    #[inline]
    pub fn clear_secret(&mut self) {
        let capacity = self.inner.capacity();
        self.inner.resize(capacity, 0);
        sanitize_bytes(self.inner.as_mut());
        self.inner.clear();
    }

    /// Consume after first sanitizing all accessible capacity.
    #[inline]
    pub fn into_cleared(mut self) {
        self.clear_secret();
    }
}

impl Default for SecretBytesMut {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl SecureSanitize for SecretBytesMut {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

impl Drop for SecretBytesMut {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
    }
}

impl fmt::Debug for SecretBytesMut {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytesMut")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_mut_wrapper_round_trip_and_clear() {
        let mut secret = SecretBytesMut::from_slice(b"token");

        secret.extend_from_slice(b"-v2");

        assert_eq!(secret.len(), 8);
        assert_eq!(secret.with_secret(|bytes| bytes[0]), b't');

        secret.with_secret_mut(|bytes| bytes[0] = b'T');
        assert_eq!(secret.with_secret(|bytes| bytes[0]), b'T');

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[test]
    fn bytes_mut_wrapper_debug_is_redacted() {
        let secret = SecretBytesMut::from_slice(b"token");
        let rendered = std::format!("{secret:?}");

        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("token"));
    }
}
