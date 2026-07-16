#[cfg(feature = "alloc")]
#[allow(unused_imports)]
use alloc::string::String;
#[allow(unused_imports)]
use core::fmt;

#[cfg(feature = "alloc")]
#[allow(unused_imports)]
use crate::SecretString;
#[allow(unused_imports)]
use crate::{ct, SecureSanitize};

#[cfg(all(
    feature = "memory-lock",
    feature = "wasm-compat",
    target_arch = "wasm32"
))]
#[allow(unsafe_code)]
#[path = "mapped/memory_lock_wasm.rs"]
mod memory_lock;

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
#[allow(unsafe_code)]
#[path = "mapped/memory_lock_native.rs"]
mod memory_lock;

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        all(target_arch = "wasm32", feature = "wasm-compat"),
    )
))]
pub use memory_lock::{
    LockedSecretBytes, LockedSecretBytesError, LockedSecretBytesGenerateError, MemoryLockError,
    MemoryLockOperation, SecretPool, SecretPoolSlot,
};

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
pub use memory_lock::{LockedSecretVec, LockedSecretVecFillError, LockedSecretVecGenerateError};

#[cfg(all(
    feature = "canary-check",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        all(target_arch = "wasm32", feature = "wasm-compat"),
    )
))]
pub use memory_lock::{CanaryCorruptedError, LockedSecretBytesCheckedCopyError};

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
#[allow(unsafe_code)]
#[path = "mapped/guard_pages.rs"]
mod guard_pages;

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
pub use guard_pages::{
    GuardPageError, GuardPageOperation, GuardedSecretVec, GuardedSecretVecGenerateError,
};

/// Error returned when checked secret-text exposure detects corruption or
/// invalid UTF-8.
#[cfg(feature = "canary-check")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretTextIntegrityError {
    /// Prefix or suffix canary verification failed.
    Canary(CanaryCorruptedError),
    /// The payload bytes were not valid UTF-8.
    Utf8(core::str::Utf8Error),
}

#[cfg(feature = "canary-check")]
impl fmt::Display for SecretTextIntegrityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canary(error) => error.fmt(formatter),
            Self::Utf8(error) => error.fmt(formatter),
        }
    }
}

#[cfg(all(feature = "canary-check", feature = "std"))]
impl std::error::Error for SecretTextIntegrityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canary(error) => Some(error),
            Self::Utf8(error) => Some(error),
        }
    }
}

/// UTF-8 text stored in a private platform mapping locked against paging.
///
/// This wrapper delegates allocation, locking, dump/fork exclusion, canary
/// handling, growth, clearing, unlocking, and unmapping to [`LockedSecretVec`].
/// It exposes only `str`/`mut str` access, so safe Rust cannot invalidate UTF-8.
#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
pub struct LockedSecretString {
    pub(crate) inner: LockedSecretVec,
}

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
impl LockedSecretString {
    /// Allocate empty locked text storage with at least `capacity` UTF-8 bytes.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Result<Self, MemoryLockError> {
        LockedSecretVec::with_capacity(capacity).map(|inner| Self { inner })
    }

    /// Copy UTF-8 text directly into a locked platform mapping.
    #[inline]
    pub fn from_secret_str(text: &str) -> Result<Self, MemoryLockError> {
        LockedSecretVec::from_slice(text.as_bytes()).map(|inner| Self { inner })
    }

    /// Move an owned string through clear-on-drop staging into locked storage.
    ///
    /// The original string allocation is volatile-cleared whether mapping setup
    /// succeeds or fails. The locked mapping necessarily receives a copy
    /// because it does not use the Rust global allocator.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn from_string(text: String) -> Result<Self, MemoryLockError> {
        let source = SecretString::from_string(text);
        LockedSecretVec::from_slice(source.inner.as_slice()).map(|inner| Self { inner })
    }

    /// Wrap existing locked bytes without reallocating after UTF-8 validation.
    ///
    /// Invalid input is cleared before [`core::str::Utf8Error`] is returned.
    #[inline]
    pub fn from_locked_secret_vec(
        mut inner: LockedSecretVec,
    ) -> Result<Self, core::str::Utf8Error> {
        let valid = inner.with_secret(|bytes| core::str::from_utf8(bytes).map(|_| ()));
        if let Err(error) = valid {
            inner.clear_secret();
            return Err(error);
        }
        Ok(Self { inner })
    }

    /// Number of initialized UTF-8 bytes.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when no text is held.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Payload capacity in UTF-8 bytes.
    #[must_use]
    #[inline]
    pub const fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Length of the underlying locked mapping.
    #[must_use]
    #[inline]
    pub const fn locked_len(&self) -> usize {
        self.inner.locked_len()
    }

    /// Run a closure with read-only access to the locked secret text.
    #[inline]
    pub fn try_with_secret<R>(
        &self,
        inspect: impl FnOnce(&str) -> R,
    ) -> Result<R, core::str::Utf8Error> {
        self.inner
            .with_secret(|bytes| core::str::from_utf8(bytes).map(inspect))
    }

    /// Run a closure with mutable access to the locked secret text.
    #[inline]
    pub fn try_with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut str) -> R,
    ) -> Result<R, core::str::Utf8Error> {
        self.inner
            .with_secret_mut(|bytes| core::str::from_utf8_mut(bytes).map(edit))
    }

    /// Verify canaries and UTF-8 before exposing locked secret text.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn expose_secret_checked<R>(
        &self,
        inspect: impl FnOnce(&str) -> R,
    ) -> Result<R, SecretTextIntegrityError> {
        self.inner
            .expose_secret_checked(|bytes| core::str::from_utf8(bytes).map(inspect))
            .map_err(SecretTextIntegrityError::Canary)?
            .map_err(SecretTextIntegrityError::Utf8)
    }

    /// Append UTF-8 text, preserving locked storage across growth.
    #[inline]
    pub fn push_str(&mut self, text: &str) -> Result<(), MemoryLockError> {
        self.inner.extend_from_slice(text.as_bytes())
    }

    /// Replace all text while preserving locked-storage semantics.
    #[inline]
    pub fn replace_from_secret_str(&mut self, text: &str) -> Result<(), MemoryLockError> {
        self.inner.replace_from_slice(text.as_bytes())
    }

    /// Replace all text from an owned string and clear the source allocation.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn replace_from_string(&mut self, text: String) -> Result<(), MemoryLockError> {
        let mut replacement = Self::from_string(text)?;
        self.clear_secret();
        core::mem::swap(&mut self.inner, &mut replacement.inner);
        Ok(())
    }

    /// Clear the full locked mapping and reset the text length.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        self.inner.clear_secret();
    }

    /// Clear the locked mapping, then flush its cache lines.
    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    #[inline(never)]
    pub fn clear_secret_and_flush(&mut self) {
        self.inner.clear_secret_and_flush();
    }

    /// Compare against UTF-8 text without early exit for equal-length inputs.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &str) -> bool {
        self.inner.constant_time_eq(other.as_bytes())
    }

    /// Verify the underlying locked mapping canaries.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        self.inner.verify_integrity()
    }

    /// Return the locked byte container without reallocating.
    #[must_use]
    #[inline]
    pub fn into_locked_secret_vec(self) -> LockedSecretVec {
        self.inner
    }
}

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
impl TryFrom<LockedSecretVec> for LockedSecretString {
    type Error = core::str::Utf8Error;

    #[inline]
    fn try_from(secret: LockedSecretVec) -> Result<Self, Self::Error> {
        Self::from_locked_secret_vec(secret)
    }
}

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
impl From<LockedSecretString> for LockedSecretVec {
    #[inline]
    fn from(secret: LockedSecretString) -> Self {
        secret.into_locked_secret_vec()
    }
}

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
impl SecureSanitize for LockedSecretString {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
impl fmt::Debug for LockedSecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedSecretString")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .field("locked_len", &self.locked_len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// UTF-8 text stored between inaccessible platform guard pages.
///
/// This wrapper delegates guarded mapping ownership, optional memory locking,
/// canary handling, growth, clearing, and unmapping to [`GuardedSecretVec`].
/// It exposes only `str`/`mut str` access.
#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
pub struct GuardedSecretString {
    pub(crate) inner: GuardedSecretVec,
}

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
impl GuardedSecretString {
    /// Allocate empty guarded text storage with at least `capacity` UTF-8 bytes.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Result<Self, GuardPageError> {
        GuardedSecretVec::with_capacity(capacity).map(|inner| Self { inner })
    }

    /// Copy UTF-8 text directly into a guarded platform mapping.
    #[inline]
    pub fn from_secret_str(text: &str) -> Result<Self, GuardPageError> {
        GuardedSecretVec::from_slice(text.as_bytes()).map(|inner| Self { inner })
    }

    /// Move an owned string through clear-on-drop staging into guarded storage.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn from_string(text: String) -> Result<Self, GuardPageError> {
        let source = SecretString::from_string(text);
        GuardedSecretVec::from_slice(source.inner.as_slice()).map(|inner| Self { inner })
    }

    /// Copy UTF-8 text into a guarded and memory-locked mapping.
    #[cfg(feature = "memory-lock")]
    #[inline]
    pub fn locked_from_secret_str(text: &str) -> Result<Self, GuardPageError> {
        GuardedSecretVec::locked_from_slice(text.as_bytes()).map(|inner| Self { inner })
    }

    /// Move an owned string through clear-on-drop staging into a guarded and
    /// memory-locked mapping.
    #[cfg(all(feature = "alloc", feature = "memory-lock"))]
    #[inline]
    pub fn locked_from_string(text: String) -> Result<Self, GuardPageError> {
        let source = SecretString::from_string(text);
        GuardedSecretVec::locked_from_slice(source.inner.as_slice()).map(|inner| Self { inner })
    }

    /// Wrap existing guarded bytes without reallocating after UTF-8 validation.
    ///
    /// Invalid input is cleared before [`core::str::Utf8Error`] is returned.
    #[inline]
    pub fn from_guarded_secret_vec(
        mut inner: GuardedSecretVec,
    ) -> Result<Self, core::str::Utf8Error> {
        let valid = inner.with_secret(|bytes| core::str::from_utf8(bytes).map(|_| ()));
        if let Err(error) = valid {
            inner.clear_secret();
            return Err(error);
        }
        Ok(Self { inner })
    }

    /// Number of initialized UTF-8 bytes.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when no text is held.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Payload capacity in UTF-8 bytes.
    #[must_use]
    #[inline]
    pub const fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Returns true when the writable guarded pages are memory locked.
    #[must_use]
    #[inline]
    pub const fn is_memory_locked(&self) -> bool {
        self.inner.is_memory_locked()
    }

    /// Run a closure with read-only access to the guarded secret text.
    #[inline]
    pub fn try_with_secret<R>(
        &self,
        inspect: impl FnOnce(&str) -> R,
    ) -> Result<R, core::str::Utf8Error> {
        self.inner
            .with_secret(|bytes| core::str::from_utf8(bytes).map(inspect))
    }

    /// Run a closure with mutable access to the guarded secret text.
    #[inline]
    pub fn try_with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut str) -> R,
    ) -> Result<R, core::str::Utf8Error> {
        self.inner
            .with_secret_mut(|bytes| core::str::from_utf8_mut(bytes).map(edit))
    }

    /// Verify canaries and UTF-8 before exposing guarded secret text.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn expose_secret_checked<R>(
        &self,
        inspect: impl FnOnce(&str) -> R,
    ) -> Result<R, SecretTextIntegrityError> {
        self.inner
            .expose_secret_checked(|bytes| core::str::from_utf8(bytes).map(inspect))
            .map_err(SecretTextIntegrityError::Canary)?
            .map_err(SecretTextIntegrityError::Utf8)
    }

    /// Append UTF-8 text, preserving guarded and lock-state semantics.
    #[inline]
    pub fn push_str(&mut self, text: &str) -> Result<(), GuardPageError> {
        self.inner.extend_from_slice(text.as_bytes())
    }

    /// Replace all text while preserving guarded and lock-state semantics.
    #[inline]
    pub fn replace_from_secret_str(&mut self, text: &str) -> Result<(), GuardPageError> {
        self.inner.replace_from_slice(text.as_bytes())
    }

    /// Replace all text from an owned string and clear the source allocation.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn replace_from_string(&mut self, text: String) -> Result<(), GuardPageError> {
        let source = SecretString::from_string(text);
        self.inner.replace_from_slice(source.inner.as_slice())
    }

    /// Clear the full writable guarded region and reset the text length.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        self.inner.clear_secret();
    }

    /// Clear the writable guarded region, then flush its cache lines.
    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    #[inline(never)]
    pub fn clear_secret_and_flush(&mut self) {
        self.inner.clear_secret_and_flush();
    }

    /// Compare against UTF-8 text without early exit for equal-length inputs.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &str) -> bool {
        self.inner.constant_time_eq(other.as_bytes())
    }

    /// Verify the guarded mapping canaries.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        self.inner.verify_integrity()
    }

    /// Return the guarded byte container without reallocating.
    #[must_use]
    #[inline]
    pub fn into_guarded_secret_vec(self) -> GuardedSecretVec {
        self.inner
    }
}

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
impl TryFrom<GuardedSecretVec> for GuardedSecretString {
    type Error = core::str::Utf8Error;

    #[inline]
    fn try_from(secret: GuardedSecretVec) -> Result<Self, Self::Error> {
        Self::from_guarded_secret_vec(secret)
    }
}

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
impl From<GuardedSecretString> for GuardedSecretVec {
    #[inline]
    fn from(secret: GuardedSecretString) -> Self {
        secret.into_guarded_secret_vec()
    }
}

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
impl SecureSanitize for GuardedSecretString {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
impl fmt::Debug for GuardedSecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuardedSecretString")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .field("memory_locked", &self.is_memory_locked())
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        all(target_arch = "wasm32", feature = "wasm-compat"),
    )
))]
mod native_ct_memory_lock_impls {
    use super::*;

    impl<const N: usize> ct::ConstantTimeEq for LockedSecretBytes<N> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            self.expose_secret(|left| other.expose_secret(|right| ct::eq_fixed(left, right)))
        }
    }

    impl<const N: usize> ct::ConstantTimeEq<[u8]> for LockedSecretBytes<N> {
        #[inline]
        fn ct_eq(&self, other: &[u8]) -> ct::Choice {
            self.expose_secret(|left| ct::eq_public_len(left, other))
        }
    }

    impl<'pool, const N: usize, const SLOTS: usize> ct::ConstantTimeEq
        for SecretPoolSlot<'pool, N, SLOTS>
    {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            self.expose_secret(|left| other.expose_secret(|right| ct::eq_fixed(left, right)))
        }
    }

    impl<'pool, const N: usize, const SLOTS: usize> ct::ConstantTimeEq<[u8]>
        for SecretPoolSlot<'pool, N, SLOTS>
    {
        #[inline]
        fn ct_eq(&self, other: &[u8]) -> ct::Choice {
            self.expose_secret(|left| ct::eq_public_len(left, other))
        }
    }

    #[cfg(all(not(target_arch = "wasm32"), not(miri)))]
    impl ct::ConstantTimeEq for LockedSecretVec {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            self.with_secret(|left| other.with_secret(|right| ct::eq_public_len(left, right)))
        }
    }

    #[cfg(all(not(target_arch = "wasm32"), not(miri)))]
    impl ct::ConstantTimeEq<[u8]> for LockedSecretVec {
        #[inline]
        fn ct_eq(&self, other: &[u8]) -> ct::Choice {
            self.with_secret(|left| ct::eq_public_len(left, other))
        }
    }

    #[cfg(all(not(target_arch = "wasm32"), not(miri)))]
    impl ct::ConstantTimeEq for LockedSecretString {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            self.inner.ct_eq(&other.inner)
        }
    }

    #[cfg(all(not(target_arch = "wasm32"), not(miri)))]
    impl ct::ConstantTimeEq<str> for LockedSecretString {
        #[inline]
        fn ct_eq(&self, other: &str) -> ct::Choice {
            self.inner.ct_eq(other.as_bytes())
        }
    }
}

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
mod native_ct_guard_page_impls {
    use super::*;

    impl ct::ConstantTimeEq for GuardedSecretVec {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            self.with_secret(|left| other.with_secret(|right| ct::eq_public_len(left, right)))
        }
    }

    impl ct::ConstantTimeEq<[u8]> for GuardedSecretVec {
        #[inline]
        fn ct_eq(&self, other: &[u8]) -> ct::Choice {
            self.with_secret(|left| ct::eq_public_len(left, other))
        }
    }

    impl ct::ConstantTimeEq for GuardedSecretString {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            self.inner.ct_eq(&other.inner)
        }
    }

    impl ct::ConstantTimeEq<str> for GuardedSecretString {
        #[inline]
        fn ct_eq(&self, other: &str) -> ct::Choice {
            self.inner.ct_eq(other.as_bytes())
        }
    }
}
