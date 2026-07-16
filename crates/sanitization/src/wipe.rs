//! Safe direct wiping helpers for ordinary owned buffers.
//!
//! Every helper routes through the crate's private volatile-write backend.
//! The backend retains compiler and hardware `SeqCst` fence boundaries around
//! each pass. Multi-pass helpers are compliance-oriented and do not claim
//! stronger security for ordinary volatile RAM.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

/// Values supported by [`WipeOnDrop`].
pub trait Wipe {
    /// Clear the reachable bytes owned by this value.
    fn wipe(&mut self);
}

/// Clear a mutable byte slice.
#[inline(never)]
pub fn bytes(bytes: &mut [u8]) {
    crate::wipe_backend::erase(bytes.as_mut_ptr(), bytes.len());
}

/// Clear a fixed-size byte array.
#[inline(never)]
pub fn array<const N: usize>(bytes: &mut [u8; N]) {
    self::bytes(bytes);
}

/// Clear a mutable byte slice using an explicit zero, `0xFF`, zero pattern.
///
/// This helper is available with `multi-pass-clear` for policy and audit
/// compatibility. It is not claimed to improve erasure of ordinary volatile
/// RAM over [`bytes`].
#[cfg(feature = "multi-pass-clear")]
#[inline(never)]
pub fn bytes_multi_pass(bytes: &mut [u8]) {
    crate::wipe_backend::erase_multi_pass(bytes.as_mut_ptr(), bytes.len());
}

/// Clear a fixed-size byte array using an explicit three-pass pattern.
#[cfg(feature = "multi-pass-clear")]
#[inline(never)]
pub fn array_multi_pass<const N: usize>(bytes: &mut [u8; N]) {
    self::bytes_multi_pass(bytes);
}

/// Clear a `Vec<u8>` allocation's complete capacity, then set its length to
/// zero.
#[cfg(feature = "alloc")]
#[inline(never)]
pub fn vec(bytes: &mut Vec<u8>) {
    crate::wipe_backend::erase(bytes.as_mut_ptr(), bytes.capacity());
    bytes.clear();
}

/// Clear a `Vec<u8>` allocation's complete capacity with three passes, then
/// set its length to zero.
#[cfg(all(feature = "alloc", feature = "multi-pass-clear"))]
#[inline(never)]
pub fn vec_multi_pass(bytes: &mut Vec<u8>) {
    crate::wipe_backend::erase_multi_pass(bytes.as_mut_ptr(), bytes.capacity());
    bytes.clear();
}

/// Clear a `String` allocation's complete capacity, then set its length to
/// zero.
///
/// Zero bytes are valid UTF-8, so the initialized string remains valid while
/// the allocation is cleared.
#[cfg(feature = "alloc")]
#[inline(never)]
pub fn string(text: &mut String) {
    crate::wipe_backend::erase(text.as_mut_ptr(), text.capacity());
    text.clear();
}

/// Clear a `String` allocation's complete capacity with three passes, then set
/// its length to zero.
#[cfg(all(feature = "alloc", feature = "multi-pass-clear"))]
#[inline(never)]
pub fn string_multi_pass(text: &mut String) {
    crate::wipe_backend::erase_multi_pass(text.as_mut_ptr(), text.capacity());
    text.clear();
}

impl Wipe for [u8] {
    #[inline(never)]
    fn wipe(&mut self) {
        bytes(self);
    }
}

impl<const N: usize> Wipe for [u8; N] {
    #[inline(never)]
    fn wipe(&mut self) {
        array(self);
    }
}

#[cfg(feature = "alloc")]
impl Wipe for Vec<u8> {
    #[inline(never)]
    fn wipe(&mut self) {
        vec(self);
    }
}

#[cfg(feature = "alloc")]
impl Wipe for String {
    #[inline(never)]
    fn wipe(&mut self) {
        string(self);
    }
}

/// Clear-on-drop wrapper for values implementing [`Wipe`].
pub struct WipeOnDrop<T: Wipe> {
    inner: T,
}

impl<T: Wipe> WipeOnDrop<T> {
    /// Wrap a value for automatic clearing on drop.
    #[must_use]
    #[inline]
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Run a closure with read-only access to the wrapped value.
    #[inline]
    pub fn with_secret<R>(&self, inspect: impl FnOnce(&T) -> R) -> R {
        inspect(&self.inner)
    }

    /// Run a closure with mutable access to the wrapped value.
    #[inline]
    pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut T) -> R) -> R {
        edit(&mut self.inner)
    }

    /// Consume the wrapper after first clearing the wrapped value.
    #[inline]
    pub fn into_cleared(mut self) {
        self.inner.wipe();
    }
}

impl<T: Wipe> Drop for WipeOnDrop<T> {
    #[inline]
    fn drop(&mut self) {
        self.inner.wipe();
    }
}

impl<T: Wipe> core::fmt::Debug for WipeOnDrop<T> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WipeOnDrop")
            .field("contents", &"<redacted>")
            .finish()
    }
}
