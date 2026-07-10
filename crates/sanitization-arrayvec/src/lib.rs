#![no_std]
#![deny(unsafe_code)]

//! `arrayvec` integration wrappers for `sanitization`.
//!
//! This crate deliberately uses wrapper types instead of trait impls for
//! external types. Rust's orphan rules prevent implementing
//! `sanitization::SecureSanitize` directly for `arrayvec::ArrayVec` here.

use arrayvec::{ArrayVec, CapacityError};
use core::fmt;
use sanitization::SecureSanitize;

#[cfg(test)]
extern crate std;

/// Clear-on-drop wrapper around [`ArrayVec`].
///
/// Live elements are sanitized before the vector is cleared. Spare uninitialized
/// storage is not treated as secret material because it has never held a `T`.
pub struct SecretArrayVec<T: SecureSanitize, const CAP: usize> {
    inner: ArrayVec<T, CAP>,
}

impl<T: SecureSanitize, const CAP: usize> SecretArrayVec<T, CAP> {
    /// Create an empty secret array vector.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            inner: ArrayVec::new_const(),
        }
    }

    /// Wrap an existing [`ArrayVec`].
    #[must_use]
    #[inline]
    pub const fn from_arrayvec(inner: ArrayVec<T, CAP>) -> Self {
        Self { inner }
    }

    /// Number of initialized elements.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Maximum number of elements.
    #[must_use]
    #[inline]
    pub const fn capacity(&self) -> usize {
        CAP
    }

    /// Returns true when there are no initialized elements.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Push one sanitizable element.
    ///
    /// If the vector is full, the rejected element is sanitized before it is
    /// returned inside [`CapacityError`].
    #[inline]
    pub fn push(&mut self, value: T) -> Result<(), CapacityError<T>> {
        match self.inner.try_push(value) {
            Ok(()) => Ok(()),
            Err(error) => {
                let mut rejected = error.element();
                rejected.secure_sanitize();
                Err(CapacityError::new(rejected))
            }
        }
    }

    /// Borrow initialized elements.
    #[must_use]
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.inner.as_slice()
    }

    /// Mutably borrow initialized elements.
    #[must_use]
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.inner.as_mut_slice()
    }

    /// Run a closure with read-only access to initialized elements.
    #[inline]
    pub fn with_secret<R>(&self, inspect: impl FnOnce(&[T]) -> R) -> R {
        inspect(self.as_slice())
    }

    /// Run a closure with mutable access to initialized elements.
    #[inline]
    pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut [T]) -> R) -> R {
        edit(self.as_mut_slice())
    }

    /// Sanitize all live elements and clear the vector.
    #[inline]
    pub fn clear_secret(&mut self) {
        self.inner.as_mut_slice().secure_sanitize();
        self.inner.clear();
    }

    /// Consume after first sanitizing all live elements.
    #[inline]
    pub fn into_cleared(mut self) {
        self.clear_secret();
    }
}

impl<T: SecureSanitize, const CAP: usize> Default for SecretArrayVec<T, CAP> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T: SecureSanitize, const CAP: usize> SecureSanitize for SecretArrayVec<T, CAP> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

impl<T: SecureSanitize, const CAP: usize> Drop for SecretArrayVec<T, CAP> {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
    }
}

impl<T: SecureSanitize, const CAP: usize> fmt::Debug for SecretArrayVec<T, CAP> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretArrayVec")
            .field("len", &self.len())
            .field("capacity", &CAP)
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sanitization::SecretBytes;

    #[test]
    fn arrayvec_wrapper_clears_live_elements() {
        let mut secrets = SecretArrayVec::<SecretBytes<4>, 2>::new();

        secrets.push(SecretBytes::from_array([1, 2, 3, 4])).unwrap();
        secrets.push(SecretBytes::from_array([5, 6, 7, 8])).unwrap();

        assert_eq!(secrets.len(), 2);
        assert!(secrets.with_secret(|items| items[0].constant_time_eq(&[1, 2, 3, 4])));

        secrets.clear_secret();

        assert!(secrets.is_empty());
    }

    #[test]
    fn arrayvec_wrapper_debug_is_redacted() {
        let mut secrets = SecretArrayVec::<SecretBytes<4>, 2>::new();
        secrets.push(SecretBytes::from_array([1, 2, 3, 4])).unwrap();

        let rendered = std::format!("{secrets:?}");

        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("1, 2, 3, 4"));
    }

    #[test]
    fn arrayvec_wrapper_sanitizes_rejected_elements() {
        let mut secrets = SecretArrayVec::<[u8; 4], 0>::new();

        let error = secrets.push([1, 2, 3, 4]).unwrap_err();

        assert_eq!(error.element(), [0; 4]);
    }
}
