#[cfg(target_arch = "wasm32")]
use core::hint::black_box;
use core::{
    ptr,
    sync::atomic::{compiler_fence, fence, Ordering},
};

#[cfg(not(target_arch = "wasm32"))]
#[inline(never)]
pub(crate) fn volatile_wipe(ptr: *mut u8, len: usize) {
    compiler_fence(Ordering::SeqCst);

    let mut offset = 0;
    while offset < len {
        // SAFETY: Callers pass a pointer and length from either a live
        // mutable byte slice or the full capacity of an owned contiguous
        // allocation. Each computed address is allocated and writable for a
        // single byte, including spare capacity, and is never read through
        // this pointer.
        unsafe {
            ptr::write_volatile(ptr.add(offset), 0);
        }
        offset += 1;
    }

    compiler_fence(Ordering::SeqCst);
    // Retain the hardware fence as a defense-in-depth ordering boundary
    // for callers that clear secrets immediately before handing memory to
    // lower-level or platform-specific code.
    fence(Ordering::SeqCst);
}

#[cfg(target_arch = "wasm32")]
#[inline(never)]
pub(crate) fn volatile_wipe(ptr: *mut u8, len: usize) {
    compiler_fence(Ordering::SeqCst);
    let wipe: fn(*mut u8, usize) = wasm_volatile_wipe_impl;
    black_box(wipe)(ptr, len);
    compiler_fence(Ordering::SeqCst);
    fence(Ordering::SeqCst);
}

#[cfg(target_arch = "wasm32")]
#[inline(never)]
fn wasm_volatile_wipe_impl(ptr: *mut u8, len: usize) {
    let mut offset = 0;
    while offset < len {
        // SAFETY: Same pointer validity contract as `volatile_wipe`.
        unsafe {
            ptr::write_volatile(ptr.add(offset), 0);
        }
        offset += 1;
    }
}

#[cfg(feature = "multi-pass-clear")]
#[cfg(not(target_arch = "wasm32"))]
#[inline(never)]
pub(crate) fn volatile_fill(ptr: *mut u8, len: usize, value: u8) {
    compiler_fence(Ordering::SeqCst);

    let mut offset = 0;
    while offset < len {
        // SAFETY: Same pointer validity contract as `volatile_wipe`; this
        // helper only changes the byte pattern written.
        unsafe {
            ptr::write_volatile(ptr.add(offset), value);
        }
        offset += 1;
    }

    compiler_fence(Ordering::SeqCst);
    fence(Ordering::SeqCst);
}

#[cfg(all(feature = "multi-pass-clear", target_arch = "wasm32"))]
#[inline(never)]
pub(crate) fn volatile_fill(ptr: *mut u8, len: usize, value: u8) {
    compiler_fence(Ordering::SeqCst);
    let fill: fn(*mut u8, usize, u8) = wasm_volatile_fill_impl;
    black_box(fill)(ptr, len, value);
    compiler_fence(Ordering::SeqCst);
    fence(Ordering::SeqCst);
}

#[cfg(all(feature = "multi-pass-clear", target_arch = "wasm32"))]
#[inline(never)]
fn wasm_volatile_fill_impl(ptr: *mut u8, len: usize, value: u8) {
    let mut offset = 0;
    while offset < len {
        // SAFETY: Same pointer validity contract as `volatile_wipe`; this
        // helper only changes the byte pattern written.
        unsafe {
            ptr::write_volatile(ptr.add(offset), value);
        }
        offset += 1;
    }
}

#[cfg(feature = "multi-pass-clear")]
#[inline(never)]
pub(crate) fn volatile_multi_pass_clear(ptr: *mut u8, len: usize) {
    volatile_wipe(ptr, len);
    volatile_fill(ptr, len, 0xFF);
    volatile_wipe(ptr, len);
}

/// Explicit volatile-write backend for ordinary mutable buffers.
///
/// This module is kept as a named integration boundary for callers that need to
/// clear ordinary buffers directly. The unsafe implementation details live in a
/// private internal module; these APIs are safe wrappers around that backend.
pub mod unsafe_wipe {
    #[cfg(feature = "alloc")]
    use alloc::{string::String, vec::Vec};

    /// Trait for values that should be cleared with volatile byte writes.
    pub trait VolatileSanitize {
        /// Clear this value using volatile byte stores where possible.
        fn volatile_sanitize(&mut self);
    }

    /// Clear a mutable byte slice using volatile writes.
    #[inline(never)]
    pub fn volatile_sanitize_bytes(bytes: &mut [u8]) {
        crate::wipe::volatile_wipe(bytes.as_mut_ptr(), bytes.len());
    }

    /// Clear a mutable byte slice using an explicit three-pass volatile
    /// pattern.
    ///
    /// Available with the `multi-pass-clear` feature.
    #[cfg(feature = "multi-pass-clear")]
    #[inline(never)]
    pub fn volatile_sanitize_bytes_multi_pass(bytes: &mut [u8]) {
        crate::wipe::volatile_multi_pass_clear(bytes.as_mut_ptr(), bytes.len());
    }

    /// Clear a fixed-size byte array using volatile writes.
    #[inline(never)]
    pub fn volatile_sanitize_array<const N: usize>(bytes: &mut [u8; N]) {
        volatile_sanitize_bytes(bytes);
    }

    /// Clear a fixed-size byte array using an explicit three-pass volatile
    /// pattern.
    ///
    /// Available with the `multi-pass-clear` feature.
    #[cfg(feature = "multi-pass-clear")]
    #[inline(never)]
    pub fn volatile_sanitize_array_multi_pass<const N: usize>(bytes: &mut [u8; N]) {
        volatile_sanitize_bytes_multi_pass(bytes);
    }

    /// Clear a `Vec<u8>` using volatile writes, then set its length to zero.
    #[cfg(feature = "alloc")]
    #[inline(never)]
    pub fn volatile_sanitize_vec(bytes: &mut Vec<u8>) {
        crate::wipe::volatile_wipe(bytes.as_mut_ptr(), bytes.capacity());
        bytes.clear();
    }

    /// Clear a `Vec<u8>` using an explicit three-pass volatile pattern, then
    /// set its length to zero.
    ///
    /// Available with the `alloc` and `multi-pass-clear` features.
    #[cfg(all(feature = "alloc", feature = "multi-pass-clear"))]
    #[inline(never)]
    pub fn volatile_sanitize_vec_multi_pass(bytes: &mut Vec<u8>) {
        crate::wipe::volatile_multi_pass_clear(bytes.as_mut_ptr(), bytes.capacity());
        bytes.clear();
    }

    /// Clear a `String` using volatile writes, then set its length to zero.
    ///
    /// Zero bytes are valid UTF-8, so the string remains valid during clearing.
    /// The full allocation capacity is wiped, including spare capacity beyond
    /// the current string length.
    #[cfg(feature = "alloc")]
    #[inline(never)]
    pub fn volatile_sanitize_string(text: &mut String) {
        crate::wipe::volatile_wipe(text.as_mut_ptr(), text.capacity());
        text.clear();
    }

    /// Clear a `String` using an explicit three-pass volatile pattern, then set
    /// its length to zero.
    ///
    /// Available with the `alloc` and `multi-pass-clear` features. Zero bytes
    /// are valid UTF-8, so the string remains valid during clearing.
    #[cfg(all(feature = "alloc", feature = "multi-pass-clear"))]
    #[inline(never)]
    pub fn volatile_sanitize_string_multi_pass(text: &mut String) {
        crate::wipe::volatile_multi_pass_clear(text.as_mut_ptr(), text.capacity());
        text.clear();
    }

    impl VolatileSanitize for [u8] {
        #[inline(never)]
        fn volatile_sanitize(&mut self) {
            volatile_sanitize_bytes(self);
        }
    }

    impl<const N: usize> VolatileSanitize for [u8; N] {
        #[inline(never)]
        fn volatile_sanitize(&mut self) {
            volatile_sanitize_array(self);
        }
    }

    #[cfg(feature = "alloc")]
    impl VolatileSanitize for Vec<u8> {
        #[inline(never)]
        fn volatile_sanitize(&mut self) {
            volatile_sanitize_vec(self);
        }
    }

    #[cfg(feature = "alloc")]
    impl VolatileSanitize for String {
        #[inline(never)]
        fn volatile_sanitize(&mut self) {
            volatile_sanitize_string(self);
        }
    }

    /// Clear-on-drop wrapper using the volatile backend.
    ///
    /// This wrapper is intentionally only available inside the `unsafe_wipe`
    /// module so call sites have to opt in explicitly.
    pub struct VolatileOnDrop<T: VolatileSanitize> {
        inner: T,
    }

    impl<T: VolatileSanitize> VolatileOnDrop<T> {
        /// Wrap a value that implements [`VolatileSanitize`].
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

        /// Consume the wrapper after first volatile-clearing the wrapped value.
        #[inline]
        pub fn into_cleared(mut self) {
            self.inner.volatile_sanitize();
        }
    }

    impl<T: VolatileSanitize> Drop for VolatileOnDrop<T> {
        #[inline]
        fn drop(&mut self) {
            self.inner.volatile_sanitize();
        }
    }

    impl<T: VolatileSanitize> core::fmt::Debug for VolatileOnDrop<T> {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("VolatileOnDrop")
                .field("contents", &"<redacted>")
                .finish()
        }
    }
}
