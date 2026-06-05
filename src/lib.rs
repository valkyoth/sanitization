#![no_std]
#![cfg_attr(not(feature = "unsafe-wipe"), forbid(unsafe_code))]
#![cfg_attr(feature = "unsafe-wipe", deny(unsafe_code))]
#![cfg_attr(feature = "unsafe-wipe", deny(unsafe_op_in_unsafe_fn))]

//! Dependency-free secret memory sanitization for `no_std` Rust.
//!
//! Default builds contain no unsafe code. The primary type is [`SecretBytes`],
//! a fixed-size clear-on-drop container designed for secrets that are controlled
//! from creation through destruction.
//!
//! The optional `unsafe-wipe` feature exposes [`unsafe_wipe`], an explicit
//! volatile-write backend for ordinary mutable buffers. It is not enabled by
//! default and is not wired into [`SecureSanitize`] implicitly; call sites must
//! opt in by module and function name.
//!
//! Important limits:
//! - Safe Rust cannot perform volatile writes to arbitrary `&mut [u8]`.
//! - Safe Rust cannot soundly scrub old stack frames created by prior moves.
//! - Cache flush instructions, SIMD stores, memory locking, and assembly need
//!   target-specific unsafe code and platform policy.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(test)]
extern crate std;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};
#[cfg(not(target_has_atomic = "8"))]
use core::cell::Cell;
#[cfg(feature = "alloc")]
use core::str::Utf8Error;
#[cfg(target_has_atomic = "8")]
use core::sync::atomic::{fence, AtomicU8};
use core::{
    fmt,
    hint::black_box,
    sync::atomic::{compiler_fence, Ordering},
};

/// Error returned when a caller provides a buffer with the wrong length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LengthError {
    /// Number of bytes required by the operation.
    pub expected: usize,
    /// Number of bytes provided by the caller.
    pub actual: usize,
}

/// Shared trait for values that can clear their own sensitive contents.
pub trait SecureSanitize {
    /// Clear the sensitive bytes owned by this value.
    fn secure_sanitize(&mut self);
}

/// Best-effort clearing for ordinary mutable byte slices.
///
/// This function exists for safe-only integration edges. It cannot provide the
/// same optimizer resistance as volatile writes because safe Rust has no
/// volatile slice-write primitive. Prefer [`SecretBytes`] for new secret
/// storage. If you need volatile clearing for ordinary memory, enable the
/// `unsafe-wipe` feature and call [`unsafe_wipe::volatile_sanitize_bytes`].
#[inline(never)]
pub fn sanitize_bytes_best_effort(bytes: &mut [u8]) {
    compiler_fence(Ordering::SeqCst);
    bytes.fill(0);
    black_box(bytes);
    compiler_fence(Ordering::SeqCst);
}

impl SecureSanitize for [u8] {
    #[inline(never)]
    fn secure_sanitize(&mut self) {
        sanitize_bytes_best_effort(self);
    }
}

impl<const N: usize> SecureSanitize for [u8; N] {
    #[inline(never)]
    fn secure_sanitize(&mut self) {
        sanitize_bytes_best_effort(self);
    }
}

struct TemporaryBytes<'a, const N: usize> {
    bytes: &'a mut [u8; N],
}

impl<const N: usize> Drop for TemporaryBytes<'_, N> {
    #[inline]
    fn drop(&mut self) {
        sanitize_bytes_best_effort(self.bytes);
    }
}

/// Fixed-size secret byte storage with automatic sanitization on drop.
///
/// On targets with 8-bit atomics, each byte is stored as an [`AtomicU8`].
/// Atomic stores are observable side effects, giving a safe, dependency-free
/// clear path without raw pointers or volatile writes. On targets without
/// 8-bit atomics the type remains available through safe [`core::cell::Cell`]
/// storage, but clearing cannot claim the same optimizer resistance as the
/// atomic path.
///
/// The type deliberately does not implement `Clone`, `Copy`, `Deref`,
/// `AsRef<[u8]>`, `PartialEq`, or secret-printing `Debug`.
pub struct SecretBytes<const N: usize> {
    #[cfg(target_has_atomic = "8")]
    bytes: [AtomicU8; N],
    #[cfg(not(target_has_atomic = "8"))]
    bytes: [Cell<u8>; N],
}

impl<const N: usize> SecretBytes<N> {
    /// Create an all-zero secret buffer.
    #[must_use]
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            #[cfg(target_has_atomic = "8")]
            bytes: [const { AtomicU8::new(0) }; N],
            #[cfg(not(target_has_atomic = "8"))]
            bytes: [const { Cell::new(0) }; N],
        }
    }

    /// Create a secret from an array, then best-effort clear the input array.
    ///
    /// For the strongest move hygiene, prefer [`SecretBytes::from_fn`] or
    /// [`SecretBytes::copy_from_slice`] so callers can avoid building a normal
    /// byte array first.
    #[must_use]
    #[inline]
    pub fn from_array(mut bytes: [u8; N]) -> Self {
        let secret = Self::zeroed();
        for (index, byte) in bytes.iter().copied().enumerate() {
            secret.store(index, byte);
        }
        secret.after_secret_write();
        sanitize_bytes_best_effort(&mut bytes);
        secret
    }

    /// Create a secret by producing each byte directly.
    ///
    /// This avoids requiring a full temporary `[u8; N]` at the call boundary.
    #[must_use]
    #[inline]
    pub fn from_fn(mut make_byte: impl FnMut(usize) -> u8) -> Self {
        let secret = Self::zeroed();
        let mut index = 0;
        while index < N {
            secret.store(index, make_byte(index));
            index += 1;
        }
        secret.after_secret_write();
        secret
    }

    /// Number of bytes stored in this secret.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns true when the secret has zero length.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Replace all bytes from a same-length slice.
    #[inline]
    pub fn copy_from_slice(&self, source: &[u8]) -> Result<(), LengthError> {
        if source.len() != N {
            return Err(LengthError {
                expected: N,
                actual: source.len(),
            });
        }

        for (index, byte) in source.iter().copied().enumerate() {
            self.store(index, byte);
        }
        self.after_secret_write();
        Ok(())
    }

    /// Fill a caller-provided destination with a temporary copy of the secret.
    #[inline]
    pub fn copy_to_slice(&self, destination: &mut [u8]) -> Result<(), LengthError> {
        if destination.len() != N {
            return Err(LengthError {
                expected: N,
                actual: destination.len(),
            });
        }

        for (index, byte) in destination.iter_mut().enumerate() {
            *byte = self.load(index);
        }
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Read one byte without exposing the whole secret.
    #[must_use]
    #[inline]
    pub fn read_byte(&self, index: usize) -> Option<u8> {
        if index < N {
            Some(self.load(index))
        } else {
            None
        }
    }

    /// Replace one byte.
    #[inline]
    pub fn write_byte(&self, index: usize, value: u8) -> Result<(), LengthError> {
        if index >= N {
            return Err(LengthError {
                expected: N,
                actual: index.saturating_add(1),
            });
        }

        self.store(index, value);
        self.after_secret_write();
        Ok(())
    }

    /// Call a closure with a temporary array copy, then clear that copy.
    ///
    /// This is the narrowest safe way to interoperate with APIs requiring
    /// `&[u8]`. The closure must not retain or return references to the
    /// temporary array; Rust's borrow checker enforces that part. The closure can
    /// still intentionally copy bytes elsewhere, so use it only at true
    /// cryptographic or protocol boundaries.
    #[inline]
    pub fn expose_secret<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        let mut temporary = [0; N];
        let mut index = 0;
        while index < N {
            temporary[index] = self.load(index);
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        let guard = TemporaryBytes {
            bytes: &mut temporary,
        };
        inspect(guard.bytes)
    }

    /// Compare against a slice without early exit.
    ///
    /// Runtime is fixed by `N`; the provided slice length is treated as public
    /// metadata. Prefer fixed-size inputs where possible.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        let mut diff = N ^ other.len();
        let mut index = 0;
        while index < N {
            let right = if index < other.len() { other[index] } else { 0 };
            diff |= usize::from(self.load(index) ^ right);
            index += 1;
        }
        diff == 0
    }

    /// Compare against another secret without early exit.
    #[must_use]
    #[inline]
    pub fn constant_time_eq_secret(&self, other: &Self) -> bool {
        let mut diff = 0usize;
        let mut index = 0;
        while index < N {
            diff |= usize::from(self.load(index) ^ other.load(index));
            index += 1;
        }
        diff == 0
    }

    /// Clear all bytes now. This is also called from `Drop`.
    #[inline(never)]
    pub fn secure_clear(&self) {
        compiler_fence(Ordering::SeqCst);

        #[cfg(target_has_atomic = "8")]
        {
            for byte in &self.bytes {
                byte.store(0, Ordering::SeqCst);
            }
            fence(Ordering::SeqCst);
        }

        #[cfg(not(target_has_atomic = "8"))]
        {
            for byte in &self.bytes {
                byte.set(0);
            }
        }

        compiler_fence(Ordering::SeqCst);
    }

    #[inline]
    fn load(&self, index: usize) -> u8 {
        #[cfg(target_has_atomic = "8")]
        {
            self.bytes[index].load(Ordering::SeqCst)
        }

        #[cfg(not(target_has_atomic = "8"))]
        {
            self.bytes[index].get()
        }
    }

    #[inline]
    fn store(&self, index: usize, value: u8) {
        #[cfg(target_has_atomic = "8")]
        {
            self.bytes[index].store(value, Ordering::SeqCst);
        }

        #[cfg(not(target_has_atomic = "8"))]
        {
            self.bytes[index].set(value);
        }
    }

    #[inline]
    fn after_secret_write(&self) {
        #[cfg(target_has_atomic = "8")]
        fence(Ordering::SeqCst);

        compiler_fence(Ordering::SeqCst);
    }
}

impl<const N: usize> Default for SecretBytes<N> {
    #[inline]
    fn default() -> Self {
        Self::zeroed()
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    #[inline]
    fn drop(&mut self) {
        self.secure_clear();
    }
}

impl<const N: usize> SecureSanitize for SecretBytes<N> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.secure_clear();
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("len", &N)
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeapWipeMode {
    BestEffort,
    #[cfg(feature = "unsafe-wipe")]
    Volatile,
}

/// Heap-allocated secret bytes with clear-on-drop behavior.
///
/// This type is available with the `alloc` feature. It is intended for
/// integration boundaries where the secret length is dynamic, such as decoded
/// tokens or PEM/DER material. The default constructor uses safe best-effort
/// clearing. With the `unsafe-wipe` feature, [`SecretVec::new_volatile`] opts
/// this specific value into volatile clearing on drop.
#[cfg(feature = "alloc")]
pub struct SecretVec {
    inner: Vec<u8>,
    wipe: HeapWipeMode,
}

#[cfg(feature = "alloc")]
impl SecretVec {
    /// Wrap a vector using safe best-effort clearing on drop.
    #[must_use]
    #[inline]
    pub const fn new(inner: Vec<u8>) -> Self {
        Self {
            inner,
            wipe: HeapWipeMode::BestEffort,
        }
    }

    /// Wrap a vector using volatile clearing on drop.
    ///
    /// Requires the `unsafe-wipe` feature.
    #[cfg(feature = "unsafe-wipe")]
    #[must_use]
    #[inline]
    pub const fn new_volatile(inner: Vec<u8>) -> Self {
        Self {
            inner,
            wipe: HeapWipeMode::Volatile,
        }
    }

    /// Create an empty secret vector.
    #[must_use]
    #[inline]
    pub const fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Create an empty secret vector with at least the requested capacity.
    #[must_use]
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::new(Vec::with_capacity(capacity))
    }

    /// Create an empty volatile-wiping secret vector with at least the
    /// requested capacity.
    ///
    /// Requires the `unsafe-wipe` feature.
    #[cfg(feature = "unsafe-wipe")]
    #[must_use]
    #[inline]
    pub fn with_capacity_volatile(capacity: usize) -> Self {
        Self::new_volatile(Vec::with_capacity(capacity))
    }

    /// Create a secret vector by copying bytes from a slice.
    #[must_use]
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(Vec::from(bytes))
    }

    /// Create a volatile-wiping secret vector by copying bytes from a slice.
    ///
    /// Requires the `unsafe-wipe` feature.
    #[cfg(feature = "unsafe-wipe")]
    #[must_use]
    #[inline]
    pub fn from_slice_volatile(bytes: &[u8]) -> Self {
        Self::new_volatile(Vec::from(bytes))
    }

    /// Number of bytes currently held.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when no bytes are held.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Run a closure with read-only access to the secret bytes.
    #[inline]
    pub fn with_secret<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> R {
        inspect(self.inner.as_slice())
    }

    /// Run a closure with mutable access to the secret bytes.
    #[inline]
    pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut [u8]) -> R) -> R {
        edit(self.inner.as_mut_slice())
    }

    /// Append bytes to the secret vector.
    ///
    /// If capacity must grow, the previous allocation is wiped before it is
    /// dropped. Prefer constructing with enough capacity in callers that append
    /// repeatedly.
    #[inline]
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.grow_for(bytes.len());
        self.inner.extend_from_slice(bytes);
    }

    /// Clear this value immediately using its configured wipe mode.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        match self.wipe {
            HeapWipeMode::BestEffort => {
                sanitize_bytes_best_effort(self.inner.as_mut_slice());
                self.inner.clear();
            }
            #[cfg(feature = "unsafe-wipe")]
            HeapWipeMode::Volatile => {
                crate::unsafe_wipe::volatile_sanitize_vec(&mut self.inner);
            }
        }
    }

    /// Consume the wrapper after first clearing the wrapped bytes.
    #[inline]
    pub fn into_cleared(mut self) {
        self.clear_secret();
    }

    fn grow_for(&mut self, additional: usize) {
        let required = self.inner.len().saturating_add(additional);
        if required <= self.inner.capacity() {
            return;
        }

        let mut replacement = Vec::with_capacity(required);
        replacement.extend_from_slice(self.inner.as_slice());
        self.clear_secret();
        self.inner = replacement;
    }
}

#[cfg(feature = "alloc")]
impl Drop for SecretVec {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "alloc")]
impl SecureSanitize for SecretVec {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "alloc")]
impl fmt::Debug for SecretVec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretVec")
            .field("len", &self.inner.len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Heap-allocated secret UTF-8 text with clear-on-drop behavior.
///
/// This type is available with the `alloc` feature. Use it for bearer tokens,
/// passphrases, and textual secrets that must cross APIs as UTF-8. The default
/// constructor uses safe best-effort clearing. With the `unsafe-wipe` feature,
/// [`SecretString::new_volatile`] opts this specific value into volatile
/// clearing on drop.
#[cfg(feature = "alloc")]
pub struct SecretString {
    inner: Vec<u8>,
    wipe: HeapWipeMode,
}

#[cfg(feature = "alloc")]
impl SecretString {
    /// Wrap a string using safe best-effort clearing on drop.
    #[must_use]
    #[inline]
    pub fn new(inner: String) -> Self {
        Self {
            inner: inner.into_bytes(),
            wipe: HeapWipeMode::BestEffort,
        }
    }

    /// Wrap a string using volatile clearing on drop.
    ///
    /// Requires the `unsafe-wipe` feature.
    #[cfg(feature = "unsafe-wipe")]
    #[must_use]
    #[inline]
    pub fn new_volatile(inner: String) -> Self {
        Self {
            inner: inner.into_bytes(),
            wipe: HeapWipeMode::Volatile,
        }
    }

    /// Create an empty secret string.
    #[must_use]
    #[inline]
    pub const fn empty() -> Self {
        Self {
            inner: Vec::new(),
            wipe: HeapWipeMode::BestEffort,
        }
    }

    /// Create an empty secret string with at least the requested byte capacity.
    #[must_use]
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
            wipe: HeapWipeMode::BestEffort,
        }
    }

    /// Create an empty volatile-wiping secret string with at least the requested
    /// byte capacity.
    ///
    /// Requires the `unsafe-wipe` feature.
    #[cfg(feature = "unsafe-wipe")]
    #[must_use]
    #[inline]
    pub fn with_capacity_volatile(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
            wipe: HeapWipeMode::Volatile,
        }
    }

    /// Create a secret string by copying from a string slice.
    #[must_use]
    #[inline]
    pub fn from_secret_str(text: &str) -> Self {
        Self {
            inner: Vec::from(text.as_bytes()),
            wipe: HeapWipeMode::BestEffort,
        }
    }

    /// Create a volatile-wiping secret string by copying from a string slice.
    ///
    /// Requires the `unsafe-wipe` feature.
    #[cfg(feature = "unsafe-wipe")]
    #[must_use]
    #[inline]
    pub fn from_secret_str_volatile(text: &str) -> Self {
        Self {
            inner: Vec::from(text.as_bytes()),
            wipe: HeapWipeMode::Volatile,
        }
    }

    /// Number of bytes currently held.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when no text is held.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Run a closure with read-only access to the secret text.
    ///
    /// The result is fallible because the text is stored internally as bytes to
    /// keep clearing safe without `String::as_mut_vec`.
    #[inline]
    pub fn try_with_secret<R>(&self, inspect: impl FnOnce(&str) -> R) -> Result<R, Utf8Error> {
        core::str::from_utf8(self.inner.as_slice()).map(inspect)
    }

    /// Run a closure with read-only access to the secret bytes.
    #[inline]
    pub fn with_secret_bytes<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> R {
        inspect(self.inner.as_slice())
    }

    /// Append text to the secret string.
    ///
    /// If capacity must grow, the previous allocation is wiped before it is
    /// dropped. Prefer constructing with enough capacity in callers that append
    /// repeatedly.
    #[inline]
    pub fn push_str(&mut self, text: &str) {
        self.grow_for(text.len());
        self.inner.extend_from_slice(text.as_bytes());
    }

    /// Clear this value immediately using its configured wipe mode.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        match self.wipe {
            HeapWipeMode::BestEffort => {
                sanitize_bytes_best_effort(self.inner.as_mut_slice());
                self.inner.clear();
            }
            #[cfg(feature = "unsafe-wipe")]
            HeapWipeMode::Volatile => {
                crate::unsafe_wipe::volatile_sanitize_vec(&mut self.inner);
            }
        }
    }

    /// Consume the wrapper after first clearing the wrapped string.
    #[inline]
    pub fn into_cleared(mut self) {
        self.clear_secret();
    }

    fn grow_for(&mut self, additional: usize) {
        let required = self.inner.len().saturating_add(additional);
        if required <= self.inner.capacity() {
            return;
        }

        let mut replacement = Vec::with_capacity(required);
        replacement.extend_from_slice(self.inner.as_slice());
        self.clear_secret();
        self.inner = replacement;
    }
}

#[cfg(feature = "alloc")]
impl Drop for SecretString {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "alloc")]
impl SecureSanitize for SecretString {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "alloc")]
impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretString")
            .field("len", &self.inner.len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Clear-on-drop wrapper for non-byte secret types.
///
/// This is useful for structs that implement [`SecureSanitize`] by clearing
/// their sensitive fields. Like [`SecretBytes`], this wrapper intentionally does
/// not implement `Clone`, `Copy`, or secret-printing `Debug`.
pub struct Secret<T: SecureSanitize> {
    inner: T,
}

impl<T: SecureSanitize> Secret<T> {
    /// Wrap a sanitizable value.
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
        self.inner.secure_sanitize();
    }
}

impl<T: SecureSanitize> Drop for Secret<T> {
    #[inline]
    fn drop(&mut self) {
        self.inner.secure_sanitize();
    }
}

impl<T: SecureSanitize> fmt::Debug for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Secret")
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Explicit volatile-write backend for ordinary mutable buffers.
///
/// This module only exists with the `unsafe-wipe` feature. It contains the
/// crate's unsafe implementation details and leaves the default safe API
/// unchanged. Use it at integration boundaries where secrets already live in
/// ordinary memory and best-effort safe clearing is not sufficient.
#[cfg(feature = "unsafe-wipe")]
#[allow(unsafe_code)]
pub mod unsafe_wipe {
    use core::{
        ptr,
        sync::atomic::{compiler_fence, fence, Ordering},
    };

    #[cfg(feature = "alloc")]
    use alloc::{string::String, vec::Vec};

    /// Trait for values that should be cleared with volatile byte writes.
    ///
    /// This trait is intentionally separate from [`crate::SecureSanitize`] so
    /// enabling `unsafe-wipe` cannot silently alter ordinary safe sanitization.
    pub trait VolatileSanitize {
        /// Clear this value using volatile byte stores where possible.
        fn volatile_sanitize(&mut self);
    }

    /// Clear a mutable byte slice using volatile writes.
    #[inline(never)]
    pub fn volatile_sanitize_bytes(bytes: &mut [u8]) {
        volatile_wipe_raw(bytes.as_mut_ptr(), bytes.len());
    }

    /// Clear a fixed-size byte array using volatile writes.
    #[inline(never)]
    pub fn volatile_sanitize_array<const N: usize>(bytes: &mut [u8; N]) {
        volatile_sanitize_bytes(bytes);
    }

    /// Clear a `Vec<u8>` using volatile writes, then set its length to zero.
    ///
    /// Requires the `alloc` feature in addition to `unsafe-wipe`.
    #[cfg(feature = "alloc")]
    #[inline(never)]
    pub fn volatile_sanitize_vec(bytes: &mut Vec<u8>) {
        volatile_sanitize_bytes(bytes.as_mut_slice());
        bytes.clear();
    }

    /// Clear a `String` using volatile writes, then set its length to zero.
    ///
    /// Zero bytes are valid UTF-8, so the string remains valid during clearing.
    /// Requires the `alloc` feature in addition to `unsafe-wipe`.
    #[cfg(feature = "alloc")]
    #[inline(never)]
    pub fn volatile_sanitize_string(text: &mut String) {
        // SAFETY: The bytes are overwritten with `0`, which is valid UTF-8.
        // The function does not expose the temporary mutable bytes elsewhere.
        let bytes = unsafe { text.as_bytes_mut() };
        volatile_sanitize_bytes(bytes);
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

    #[inline(never)]
    fn volatile_wipe_raw(ptr: *mut u8, len: usize) {
        compiler_fence(Ordering::SeqCst);

        let mut offset = 0;
        while offset < len {
            // SAFETY: The pointer and length come from a live mutable slice or
            // owned contiguous buffer. Each computed address is in-bounds for a
            // single byte write and is never read through this raw pointer.
            unsafe {
                ptr::write_volatile(ptr.add(offset), 0);
            }
            offset += 1;
        }

        compiler_fence(Ordering::SeqCst);
        fence(Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_round_trip_and_clear() {
        let secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);
        let mut out = [0; 4];

        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [1, 2, 3, 4]);

        secret.secure_clear();
        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [0, 0, 0, 0]);
    }

    #[test]
    fn length_errors_are_explicit() {
        let secret = SecretBytes::<4>::zeroed();

        assert_eq!(
            secret.copy_from_slice(&[1, 2]).err(),
            Some(LengthError {
                expected: 4,
                actual: 2
            })
        );
    }

    #[test]
    fn equality_does_not_short_circuit_on_first_byte() {
        let left = SecretBytes::<4>::from_array([9, 8, 7, 6]);
        let same = SecretBytes::<4>::from_array([9, 8, 7, 6]);
        let different = SecretBytes::<4>::from_array([0, 8, 7, 6]);

        assert!(left.constant_time_eq(&[9, 8, 7, 6]));
        assert!(!left.constant_time_eq(&[9, 8, 7]));
        assert!(left.constant_time_eq_secret(&same));
        assert!(!left.constant_time_eq_secret(&different));
    }

    #[test]
    fn debug_output_is_redacted() {
        let secret = SecretBytes::<3>::from_array([b'a', b'b', b'c']);
        let rendered = std::format!("{secret:?}");

        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("abc"));
    }

    #[test]
    fn generic_secret_uses_closure_access() {
        let mut secret = Secret::new([1, 2, 3, 4]);

        assert_eq!(secret.with_secret(|bytes| bytes[0]), 1);
        secret.with_secret_mut(|bytes| bytes[0] = 9);
        assert_eq!(secret.with_secret(|bytes| bytes[0]), 9);

        secret.into_cleared();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_round_trip_and_clear() {
        let mut secret = SecretVec::from_slice(&[1, 2, 3]);

        assert_eq!(secret.with_secret(|bytes| bytes.len()), 3);
        secret.extend_from_slice(&[4]);
        assert_eq!(secret.with_secret(|bytes| bytes[3]), 4);

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_string_round_trip_and_clear() {
        let mut secret = SecretString::from_secret_str("secret");

        assert_eq!(secret.try_with_secret(|text| text.len()), Ok(6));
        secret.push_str("-token");
        assert_eq!(
            secret.try_with_secret(|text| text.ends_with("token")),
            Ok(true)
        );

        let rendered = std::format!("{secret:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("secret-token"));

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(feature = "unsafe-wipe")]
    #[test]
    fn volatile_wipe_clears_slice_when_feature_enabled() {
        let mut bytes = [0xA5; 16];

        crate::unsafe_wipe::volatile_sanitize_bytes(&mut bytes);

        assert_eq!(bytes, [0; 16]);
    }

    #[cfg(all(feature = "unsafe-wipe", feature = "alloc"))]
    #[test]
    fn volatile_wipe_clears_alloc_types_when_enabled() {
        let mut bytes = std::vec![0xBB; 8];
        let mut text = std::string::String::from("secret");

        crate::unsafe_wipe::volatile_sanitize_vec(&mut bytes);
        crate::unsafe_wipe::volatile_sanitize_string(&mut text);

        assert!(bytes.is_empty());
        assert!(text.is_empty());
    }

    #[cfg(feature = "unsafe-wipe")]
    #[test]
    fn volatile_on_drop_wrapper_is_explicit() {
        let mut secret = crate::unsafe_wipe::VolatileOnDrop::new([1, 2, 3, 4]);

        assert_eq!(secret.with_secret(|bytes| bytes[2]), 3);
        secret.with_secret_mut(|bytes| bytes[2] = 9);
        assert_eq!(secret.with_secret(|bytes| bytes[2]), 9);

        secret.into_cleared();
    }

    #[cfg(all(feature = "unsafe-wipe", feature = "alloc"))]
    #[test]
    fn heap_secrets_can_opt_into_volatile_mode() {
        let mut bytes = SecretVec::from_slice_volatile(&[1, 2, 3]);
        let mut text = SecretString::from_secret_str_volatile("secret");

        assert_eq!(bytes.with_secret(|secret| secret[0]), 1);
        assert_eq!(text.try_with_secret(|secret| secret.len()), Ok(6));

        bytes.clear_secret();
        text.clear_secret();

        assert!(bytes.is_empty());
        assert!(text.is_empty());
    }
}
