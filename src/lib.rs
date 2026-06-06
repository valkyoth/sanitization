#![no_std]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Dependency-free secret memory sanitization for `no_std` Rust.
//!
//! The primary type is [`SecretBytes`], a fixed-size clear-on-drop container
//! designed for secrets that are controlled from creation through destruction.
//!
//! Clearing routes through a small internal volatile-write backend. That backend
//! uses one isolated unsafe boundary so the optimizer cannot remove secret
//! clearing as a dead store.
//!
//! Important limits:
//! - Safe Rust cannot soundly scrub old stack frames created by prior moves.
//! - Process abort prevents destructors and post-closure cleanup from running.
//! - SIMD stores, broad memory policy, and target-specific hardening need
//!   target-specific unsafe code and platform policy.
//! - Linux memory locking is available only through the explicit
//!   `memory-lock` feature on supported architectures.
//! - x86_64 assembly-backed comparison is available only through the explicit
//!   `asm-compare` feature.
//! - x86_64 cache-line eviction is available only through the explicit
//!   `cache-flush` feature.
//! - Fixed-size lifetime enforcement is available only through the `std`
//!   feature and [`ExpiringSecretBytes`].
//! - Linux guard-page allocation is available only through the explicit
//!   `guard-pages` feature on supported architectures.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};
#[cfg(feature = "alloc")]
use core::str::Utf8Error;
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

/// Declare a struct and generate [`SecureSanitize`] for all fields.
///
/// This is a dependency-free alternative to a derive macro. Each field type
/// must implement [`SecureSanitize`]. The macro does not implement [`Drop`], so
/// use this form when the type needs custom drop behavior or is wrapped in
/// [`Secret`].
///
/// ```
/// use sanitization::{secure_sanitize_struct, SecretBytes, SecureSanitize};
///
/// secure_sanitize_struct! {
///     struct Credentials {
///         key: SecretBytes<32>,
///         nonce: SecretBytes<12>,
///     }
/// }
///
/// let mut credentials = Credentials {
///     key: SecretBytes::from_array([1; 32]),
///     nonce: SecretBytes::from_array([2; 12]),
/// };
///
/// credentials.secure_sanitize();
/// ```
#[macro_export]
macro_rules! secure_sanitize_struct {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_attr:meta])*
                $field_vis:vis $field:ident: $field_ty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$attr])*
        $vis struct $name {
            $(
                $(#[$field_attr])*
                $field_vis $field: $field_ty,
            )*
        }

        impl $crate::SecureSanitize for $name {
            #[inline]
            fn secure_sanitize(&mut self) {
                $(
                    $crate::SecureSanitize::secure_sanitize(&mut self.$field);
                )*
            }
        }
    };
}

/// Declare a struct and generate [`SecureSanitize`] plus [`Drop`].
///
/// This macro owns the type's [`Drop`] implementation. Use
/// [`secure_sanitize_struct!`] instead when custom drop behavior is required.
///
/// ```
/// use sanitization::{secure_drop_struct, SecretBytes};
///
/// secure_drop_struct! {
///     struct Credentials {
///         key: SecretBytes<32>,
///         nonce: SecretBytes<12>,
///     }
/// }
/// ```
#[macro_export]
macro_rules! secure_drop_struct {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_attr:meta])*
                $field_vis:vis $field:ident: $field_ty:ty
            ),* $(,)?
        }
    ) => {
        $crate::secure_sanitize_struct! {
            $(#[$attr])*
            $vis struct $name {
                $(
                    $(#[$field_attr])*
                    $field_vis $field: $field_ty,
                )*
            }
        }

        impl Drop for $name {
            #[inline]
            fn drop(&mut self) {
                $crate::SecureSanitize::secure_sanitize(self);
            }
        }
    };
}

#[allow(unsafe_code)]
mod wipe {
    use core::{
        ptr,
        sync::atomic::{compiler_fence, fence, Ordering},
    };

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
        fence(Ordering::SeqCst);
    }
}

/// Clear ordinary mutable bytes with volatile writes.
///
/// This is the default clearing primitive used by this crate. It uses a small
/// internal unsafe boundary around [`core::ptr::write_volatile`] so the
/// optimizer cannot remove clearing as a dead store.
#[inline(never)]
pub fn sanitize_bytes(bytes: &mut [u8]) {
    wipe::volatile_wipe(bytes.as_mut_ptr(), bytes.len());
}

/// Compatibility alias for [`sanitize_bytes`].
///
/// Older release candidates exposed this function as a safe best-effort clear.
/// It now uses the same volatile clear backend as the rest of the crate.
#[inline(never)]
pub fn sanitize_bytes_best_effort(bytes: &mut [u8]) {
    sanitize_bytes(bytes);
}

#[cfg(feature = "alloc")]
#[inline(never)]
fn sanitize_vec_capacity(bytes: &mut Vec<u8>) {
    wipe::volatile_wipe(bytes.as_mut_ptr(), bytes.capacity());
    bytes.clear();
}

#[cfg(feature = "alloc")]
#[inline]
fn next_secret_capacity(current: usize, required: usize) -> usize {
    current.saturating_mul(2).max(required).max(8)
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[allow(unsafe_code)]
mod memory_lock {
    use core::{
        arch::asm,
        fmt,
        ptr::NonNull,
        sync::atomic::{compiler_fence, Ordering},
    };

    const FALLBACK_PAGE_SIZE: usize = 4096;
    const PROT_READ: usize = 0x1;
    const PROT_WRITE: usize = 0x2;
    const MAP_PRIVATE: usize = 0x02;
    const MAP_ANONYMOUS: usize = 0x20;

    #[cfg(target_arch = "x86_64")]
    const SYS_MMAP: usize = 9;
    #[cfg(target_arch = "x86_64")]
    const SYS_MUNMAP: usize = 11;
    #[cfg(target_arch = "x86_64")]
    const SYS_MLOCK: usize = 149;
    #[cfg(target_arch = "x86_64")]
    const SYS_MUNLOCK: usize = 150;

    #[cfg(target_arch = "aarch64")]
    const SYS_MMAP: usize = 222;
    #[cfg(target_arch = "aarch64")]
    const SYS_MUNMAP: usize = 215;
    #[cfg(target_arch = "aarch64")]
    const SYS_MLOCK: usize = 228;
    #[cfg(target_arch = "aarch64")]
    const SYS_MUNLOCK: usize = 229;

    /// Linux memory-locking operation that failed.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum MemoryLockOperation {
        /// The requested mapping length overflowed.
        Length,
        /// Anonymous mapping creation failed.
        Map,
        /// Page locking failed.
        Lock,
        /// Page unlocking failed.
        Unlock,
        /// Anonymous mapping release failed.
        Unmap,
    }

    /// Error returned by Linux memory-locking operations.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct MemoryLockError {
        /// Operation that failed.
        pub operation: MemoryLockOperation,
        /// Positive Linux errno value when the kernel returned one.
        ///
        /// This is `0` for local arithmetic failures before a syscall.
        pub errno: i32,
    }

    impl fmt::Display for MemoryLockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "memory lock operation {:?} failed with errno {}",
                self.operation, self.errno
            )
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for MemoryLockError {}

    /// Fixed-size secret bytes stored in a private locked Linux mapping.
    ///
    /// This type is available with the `memory-lock` feature on Linux
    /// `x86_64` and `aarch64`. It allocates a private anonymous mapping with
    /// `mmap`, locks it with `mlock`, volatile-clears the full mapping on drop,
    /// then calls `munlock` and `munmap`.
    ///
    /// The secret bytes are not stored inline in the Rust value. Moving this
    /// type only moves pointer metadata, so ordinary Rust moves do not copy the
    /// secret byte array itself.
    pub struct LockedSecretBytes<const N: usize> {
        ptr: NonNull<u8>,
        map_len: usize,
    }

    impl<const N: usize> LockedSecretBytes<N> {
        /// Allocate locked zeroed storage for `N` bytes.
        #[inline]
        pub fn zeroed() -> Result<Self, MemoryLockError> {
            if N == 0 {
                return Ok(Self {
                    ptr: NonNull::dangling(),
                    map_len: 0,
                });
            }

            let map_len = rounded_mapping_len(N)?;
            let ptr = map_private(map_len)?;

            if let Err(error) = lock_mapping(ptr, map_len) {
                let _ = unmap_private(ptr, map_len);
                return Err(error);
            }

            Ok(Self { ptr, map_len })
        }

        /// Allocate locked storage, copy an array into it, then clear the input
        /// array with the crate's volatile wipe backend.
        #[inline]
        pub fn from_array(mut bytes: [u8; N]) -> Result<Self, MemoryLockError> {
            let mut secret = match Self::zeroed() {
                Ok(secret) => secret,
                Err(error) => {
                    crate::sanitize_bytes(&mut bytes);
                    return Err(error);
                }
            };

            let _ = secret.copy_from_slice(&bytes);
            crate::sanitize_bytes(&mut bytes);
            Ok(secret)
        }

        /// Number of secret bytes stored in the locked mapping.
        #[must_use]
        #[inline]
        pub const fn len(&self) -> usize {
            N
        }

        /// Returns true when the locked secret has zero length.
        #[must_use]
        #[inline]
        pub const fn is_empty(&self) -> bool {
            N == 0
        }

        /// Replace all secret bytes from a same-length slice.
        #[inline]
        pub fn copy_from_slice(&mut self, source: &[u8]) -> Result<(), crate::LengthError> {
            if source.len() != N {
                return Err(crate::LengthError {
                    expected: N,
                    actual: source.len(),
                });
            }

            self.as_mut_slice().copy_from_slice(source);
            compiler_fence(Ordering::SeqCst);
            Ok(())
        }

        /// Fill a caller-provided destination with a copy of the secret bytes.
        #[inline]
        pub fn copy_to_slice(&self, destination: &mut [u8]) -> Result<(), crate::LengthError> {
            if destination.len() != N {
                return Err(crate::LengthError {
                    expected: N,
                    actual: destination.len(),
                });
            }

            destination.copy_from_slice(self.as_slice());
            compiler_fence(Ordering::SeqCst);
            core::hint::black_box(destination);
            Ok(())
        }

        /// Run a closure with read-only access to the locked secret bytes.
        ///
        /// The closure can still copy bytes elsewhere. Keep usage limited to
        /// cryptographic or protocol boundaries that genuinely need raw bytes.
        #[inline]
        pub fn with_secret<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
            inspect(self.as_array())
        }

        /// Compare against a slice without early exit for equal-length inputs.
        ///
        /// Length mismatch returns immediately because the provided slice length
        /// is treated as public metadata.
        #[must_use]
        #[inline]
        pub fn constant_time_eq(&self, other: &[u8]) -> bool {
            crate::constant_time_eq_slices(self.as_slice(), other)
        }

        /// Clear the full private mapping with volatile writes.
        #[inline(never)]
        pub fn secure_clear(&mut self) {
            if self.map_len != 0 {
                crate::wipe::volatile_wipe(self.ptr.as_ptr(), self.map_len);
            }
        }

        /// Clear the full private mapping with volatile writes, then flush the
        /// cache lines covering that mapping.
        #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
        #[inline(never)]
        pub fn secure_clear_and_flush(&mut self) {
            self.secure_clear();
            crate::cache_flush::flush_cache_lines(self.as_mapping_slice());
        }

        #[inline]
        fn as_slice(&self) -> &[u8] {
            // SAFETY: `ptr` either points to a live mapping of at least `N`
            // bytes owned by this value, or is dangling with `N == 0`.
            unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), N) }
        }

        #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
        #[inline]
        fn as_mapping_slice(&self) -> &[u8] {
            // SAFETY: `ptr` either points to a live mapping of `map_len` bytes
            // owned by this value, or is dangling with `map_len == 0`.
            unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.map_len) }
        }

        #[inline]
        fn as_mut_slice(&mut self) -> &mut [u8] {
            // SAFETY: `&mut self` gives exclusive access to the live mapping,
            // and the mapping is at least `N` bytes long when `N > 0`.
            unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), N) }
        }

        #[inline]
        fn as_array(&self) -> &[u8; N] {
            // SAFETY: `as_slice` is exactly `N` bytes long, and the pointer is
            // valid for a `[u8; N]` reference for the duration of `&self`.
            unsafe { &*(self.ptr.as_ptr() as *const [u8; N]) }
        }
    }

    impl<const N: usize> Drop for LockedSecretBytes<N> {
        #[inline]
        fn drop(&mut self) {
            self.secure_clear();

            if self.map_len != 0 {
                let _ = unlock_mapping(self.ptr, self.map_len);
                let _ = unmap_private(self.ptr, self.map_len);
            }
        }
    }

    impl<const N: usize> crate::SecureSanitize for LockedSecretBytes<N> {
        #[inline]
        fn secure_sanitize(&mut self) {
            self.secure_clear();
        }
    }

    impl<const N: usize> fmt::Debug for LockedSecretBytes<N> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("LockedSecretBytes")
                .field("len", &N)
                .field("contents", &"<redacted>")
                .finish()
        }
    }

    fn rounded_mapping_len(len: usize) -> Result<usize, MemoryLockError> {
        len.checked_add(FALLBACK_PAGE_SIZE - 1)
            .map(|value| value & !(FALLBACK_PAGE_SIZE - 1))
            .ok_or(MemoryLockError {
                operation: MemoryLockOperation::Length,
                errno: 0,
            })
    }

    fn syscall_failed(ret: isize) -> bool {
        (-4095..=-1).contains(&ret)
    }

    fn syscall_error(operation: MemoryLockOperation, ret: isize) -> MemoryLockError {
        MemoryLockError {
            operation,
            errno: (-ret) as i32,
        }
    }

    fn map_private(len: usize) -> Result<NonNull<u8>, MemoryLockError> {
        let ret = raw_syscall6(
            SYS_MMAP,
            0,
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            usize::MAX,
            0,
        );

        if syscall_failed(ret) {
            return Err(syscall_error(MemoryLockOperation::Map, ret));
        }

        NonNull::new(ret as *mut u8).ok_or(MemoryLockError {
            operation: MemoryLockOperation::Map,
            errno: 0,
        })
    }

    fn lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
        let ret = raw_syscall2(SYS_MLOCK, ptr.as_ptr() as usize, len);
        if syscall_failed(ret) {
            Err(syscall_error(MemoryLockOperation::Lock, ret))
        } else {
            Ok(())
        }
    }

    fn unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
        let ret = raw_syscall2(SYS_MUNLOCK, ptr.as_ptr() as usize, len);
        if syscall_failed(ret) {
            Err(syscall_error(MemoryLockOperation::Unlock, ret))
        } else {
            Ok(())
        }
    }

    fn unmap_private(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
        let ret = raw_syscall2(SYS_MUNMAP, ptr.as_ptr() as usize, len);
        if syscall_failed(ret) {
            Err(syscall_error(MemoryLockOperation::Unmap, ret))
        } else {
            Ok(())
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn raw_syscall2(number: usize, arg1: usize, arg2: usize) -> isize {
        raw_syscall6(number, arg1, arg2, 0, 0, 0, 0)
    }

    #[cfg(target_arch = "x86_64")]
    fn raw_syscall6(
        number: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
    ) -> isize {
        let ret: isize;

        // SAFETY: Registers follow the Linux x86_64 syscall ABI. The syscall
        // number and arguments are fixed by the caller wrappers above.
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") number as isize => ret,
                in("rdi") arg1,
                in("rsi") arg2,
                in("rdx") arg3,
                in("r10") arg4,
                in("r8") arg5,
                in("r9") arg6,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack)
            );
        }

        ret
    }

    #[cfg(target_arch = "aarch64")]
    fn raw_syscall2(number: usize, arg1: usize, arg2: usize) -> isize {
        raw_syscall6(number, arg1, arg2, 0, 0, 0, 0)
    }

    #[cfg(target_arch = "aarch64")]
    fn raw_syscall6(
        number: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
    ) -> isize {
        let ret: isize;

        // SAFETY: Registers follow the Linux aarch64 syscall ABI. The syscall
        // number and arguments are fixed by the caller wrappers above.
        unsafe {
            asm!(
                "svc 0",
                inlateout("x0") arg1 as isize => ret,
                in("x1") arg2,
                in("x2") arg3,
                in("x3") arg4,
                in("x4") arg5,
                in("x5") arg6,
                in("x8") number,
                options(nostack)
            );
        }

        ret
    }
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use memory_lock::{LockedSecretBytes, MemoryLockError, MemoryLockOperation};

#[cfg(all(feature = "asm-compare", target_arch = "x86_64", not(miri)))]
#[allow(unsafe_code)]
mod compare_asm {
    use core::arch::asm;

    #[inline(never)]
    pub(crate) fn constant_time_eq_equal_len(left: &[u8], right: &[u8]) -> bool {
        debug_assert_eq!(left.len(), right.len());

        let mut left_ptr = left.as_ptr();
        let mut right_ptr = right.as_ptr();
        let mut remaining = left.len();
        let diff: usize;
        let tmp: usize;

        // SAFETY: The public caller checks that both slices have the same
        // length. The loop reads exactly `remaining` bytes from each valid
        // slice, never writes memory, and does not expose the raw pointers.
        unsafe {
            asm!(
                "xor {diff:e}, {diff:e}",
                "xor {tmp:e}, {tmp:e}",
                "test {remaining}, {remaining}",
                "je 3f",
                "2:",
                "movzx {tmp:e}, byte ptr [{left_ptr}]",
                "xor {tmp:l}, byte ptr [{right_ptr}]",
                "or {diff:l}, {tmp:l}",
                "inc {left_ptr}",
                "inc {right_ptr}",
                "dec {remaining}",
                "jne 2b",
                "3:",
                left_ptr = inout(reg) left_ptr,
                right_ptr = inout(reg) right_ptr,
                remaining = inout(reg) remaining,
                diff = lateout(reg) diff,
                tmp = lateout(reg) tmp,
                options(nostack, readonly)
            );
        }

        let _ = (left_ptr, right_ptr, remaining, tmp);
        core::hint::black_box(diff) == 0
    }
}

#[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
#[allow(unsafe_code)]
pub mod cache_flush {
    #[cfg(feature = "alloc")]
    use alloc::{string::String, vec::Vec};
    use core::{
        arch::asm,
        sync::atomic::{compiler_fence, Ordering},
    };

    const CACHE_LINE_SIZE: usize = 64;

    /// Trait for values that should be cleared with volatile byte writes and
    /// then evicted from x86_64 cache lines.
    pub trait CacheFlushSanitize {
        /// Clear this value and flush the cache lines covering its storage.
        fn cache_flush_sanitize(&mut self);
    }

    /// Flush the cache lines covering a byte slice.
    ///
    /// This does not clear memory by itself. Prefer
    /// [`cache_flush_sanitize_bytes`] for secret clearing.
    #[inline(never)]
    pub fn flush_cache_lines(bytes: &[u8]) {
        flush_raw(bytes.as_ptr(), bytes.len());
    }

    /// Clear a mutable byte slice with volatile writes, then flush its cache
    /// lines.
    #[inline(never)]
    pub fn cache_flush_sanitize_bytes(bytes: &mut [u8]) {
        crate::sanitize_bytes(bytes);
        flush_raw(bytes.as_ptr(), bytes.len());
    }

    /// Clear a fixed-size byte array with volatile writes, then flush its cache
    /// lines.
    #[inline(never)]
    pub fn cache_flush_sanitize_array<const N: usize>(bytes: &mut [u8; N]) {
        cache_flush_sanitize_bytes(bytes);
    }

    /// Clear a `Vec<u8>` allocation capacity with volatile writes, then flush
    /// the cache lines covering the allocation.
    #[cfg(feature = "alloc")]
    #[inline(never)]
    pub fn cache_flush_sanitize_vec(bytes: &mut Vec<u8>) {
        let ptr = bytes.as_ptr();
        let len = bytes.capacity();
        crate::unsafe_wipe::volatile_sanitize_vec(bytes);
        flush_raw(ptr, len);
    }

    /// Clear a `String` allocation capacity with volatile writes, then flush
    /// the cache lines covering the allocation.
    #[cfg(feature = "alloc")]
    #[inline(never)]
    pub fn cache_flush_sanitize_string(text: &mut String) {
        let ptr = text.as_ptr();
        let len = text.capacity();
        crate::unsafe_wipe::volatile_sanitize_string(text);
        flush_raw(ptr, len);
    }

    impl CacheFlushSanitize for [u8] {
        #[inline(never)]
        fn cache_flush_sanitize(&mut self) {
            cache_flush_sanitize_bytes(self);
        }
    }

    impl<const N: usize> CacheFlushSanitize for [u8; N] {
        #[inline(never)]
        fn cache_flush_sanitize(&mut self) {
            cache_flush_sanitize_array(self);
        }
    }

    #[cfg(feature = "alloc")]
    impl CacheFlushSanitize for Vec<u8> {
        #[inline(never)]
        fn cache_flush_sanitize(&mut self) {
            cache_flush_sanitize_vec(self);
        }
    }

    #[cfg(feature = "alloc")]
    impl CacheFlushSanitize for String {
        #[inline(never)]
        fn cache_flush_sanitize(&mut self) {
            cache_flush_sanitize_string(self);
        }
    }

    /// Clear-on-drop wrapper using volatile writes followed by x86_64 cache
    /// line eviction.
    pub struct CacheFlushOnDrop<T: CacheFlushSanitize> {
        inner: T,
    }

    impl<T: CacheFlushSanitize> CacheFlushOnDrop<T> {
        /// Wrap a value that implements [`CacheFlushSanitize`].
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

        /// Consume the wrapper after first clearing and flushing the wrapped
        /// value.
        #[inline]
        pub fn into_cleared(mut self) {
            self.inner.cache_flush_sanitize();
        }
    }

    impl<T: CacheFlushSanitize> Drop for CacheFlushOnDrop<T> {
        #[inline]
        fn drop(&mut self) {
            self.inner.cache_flush_sanitize();
        }
    }

    impl<T: CacheFlushSanitize> core::fmt::Debug for CacheFlushOnDrop<T> {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("CacheFlushOnDrop")
                .field("contents", &"<redacted>")
                .finish()
        }
    }

    #[inline(never)]
    fn flush_raw(ptr: *const u8, len: usize) {
        if len == 0 {
            return;
        }

        compiler_fence(Ordering::SeqCst);

        let start = ptr as usize;
        let end = start.saturating_add(len.saturating_sub(1));
        let mut current = start & !(CACHE_LINE_SIZE - 1);
        let end_line = end & !(CACHE_LINE_SIZE - 1);

        while current <= end_line {
            // SAFETY: `clflush` accepts any virtual address. Callers provide a
            // pointer range derived from a live slice or owned allocation, and
            // this function does not read or write through the pointer.
            unsafe {
                asm!(
                    "clflush [{address}]",
                    address = in(reg) current as *const u8,
                    options(nostack, preserves_flags)
                );
            }

            match current.checked_add(CACHE_LINE_SIZE) {
                Some(next) => current = next,
                None => break,
            }
        }

        // SAFETY: `mfence` orders prior cache flushes before later memory
        // operations and does not access memory itself.
        unsafe {
            asm!("mfence", options(nostack, preserves_flags));
        }

        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[allow(unsafe_code)]
mod guard_pages {
    use core::{
        arch::asm,
        fmt,
        ptr::NonNull,
        sync::atomic::{compiler_fence, Ordering},
    };

    const PAGE_SIZE: usize = 4096;
    const PROT_NONE: usize = 0x0;
    const PROT_READ: usize = 0x1;
    const PROT_WRITE: usize = 0x2;
    const MAP_PRIVATE: usize = 0x02;
    const MAP_ANONYMOUS: usize = 0x20;

    #[cfg(target_arch = "x86_64")]
    const SYS_MMAP: usize = 9;
    #[cfg(target_arch = "x86_64")]
    const SYS_MPROTECT: usize = 10;
    #[cfg(target_arch = "x86_64")]
    const SYS_MUNMAP: usize = 11;

    #[cfg(target_arch = "aarch64")]
    const SYS_MMAP: usize = 222;
    #[cfg(target_arch = "aarch64")]
    const SYS_MPROTECT: usize = 226;
    #[cfg(target_arch = "aarch64")]
    const SYS_MUNMAP: usize = 215;

    /// Linux guard-page operation that failed.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum GuardPageOperation {
        /// Requested length arithmetic overflowed.
        Length,
        /// Anonymous mapping creation failed.
        Map,
        /// Data-page protection update failed.
        Protect,
        /// Anonymous mapping release failed.
        Unmap,
    }

    /// Error returned by guarded secret allocation operations.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct GuardPageError {
        /// Operation that failed.
        pub operation: GuardPageOperation,
        /// Positive Linux errno value when the kernel returned one.
        ///
        /// This is `0` for local arithmetic failures before a syscall.
        pub errno: i32,
    }

    impl fmt::Display for GuardPageError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "guard page operation {:?} failed with errno {}",
                self.operation, self.errno
            )
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for GuardPageError {}

    /// Dynamic secret bytes stored between inaccessible Linux guard pages.
    ///
    /// This type is available with the `guard-pages` feature on Linux `x86_64`
    /// and `aarch64`. Secret bytes live in private anonymous mapped pages. The
    /// pages immediately before and after the writable data region remain
    /// `PROT_NONE`, so linear overreads or overwrites past the mapped data
    /// region fault instead of reaching unrelated memory.
    ///
    /// The secret bytes are not allocated with the Rust global allocator.
    pub struct GuardedSecretVec {
        base: NonNull<u8>,
        data: NonNull<u8>,
        map_len: usize,
        data_capacity: usize,
        len: usize,
    }

    impl GuardedSecretVec {
        /// Create an empty guarded secret buffer with at least `capacity` bytes
        /// of writable data space.
        pub fn with_capacity(capacity: usize) -> Result<Self, GuardPageError> {
            let data_capacity = rounded_data_len(capacity)?;
            let total_len = data_capacity
                .checked_add(PAGE_SIZE)
                .and_then(|value| value.checked_add(PAGE_SIZE))
                .ok_or(GuardPageError {
                    operation: GuardPageOperation::Length,
                    errno: 0,
                })?;

            let base = map_guarded(total_len)?;
            let data_addr =
                (base.as_ptr() as usize)
                    .checked_add(PAGE_SIZE)
                    .ok_or(GuardPageError {
                        operation: GuardPageOperation::Length,
                        errno: 0,
                    })?;
            let data = NonNull::new(data_addr as *mut u8).ok_or(GuardPageError {
                operation: GuardPageOperation::Map,
                errno: 0,
            })?;

            if let Err(error) = protect_data(data, data_capacity) {
                let _ = unmap_guarded(base, total_len);
                return Err(error);
            }

            Ok(Self {
                base,
                data,
                map_len: total_len,
                data_capacity,
                len: 0,
            })
        }

        /// Create a guarded secret buffer by copying bytes from a slice.
        pub fn from_slice(bytes: &[u8]) -> Result<Self, GuardPageError> {
            let mut secret = Self::with_capacity(bytes.len())?;
            secret.as_mut_capacity_slice()[..bytes.len()].copy_from_slice(bytes);
            secret.len = bytes.len();
            compiler_fence(Ordering::SeqCst);
            Ok(secret)
        }

        /// Number of initialized secret bytes.
        #[must_use]
        #[inline]
        pub const fn len(&self) -> usize {
            self.len
        }

        /// Returns true when no bytes are held.
        #[must_use]
        #[inline]
        pub const fn is_empty(&self) -> bool {
            self.len == 0
        }

        /// Writable data capacity between the guard pages.
        #[must_use]
        #[inline]
        pub const fn capacity(&self) -> usize {
            self.data_capacity
        }

        /// Run a closure with read-only access to initialized secret bytes.
        #[inline]
        pub fn with_secret<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> R {
            inspect(self.as_slice())
        }

        /// Run a closure with mutable access to initialized secret bytes.
        #[inline]
        pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut [u8]) -> R) -> R {
            edit(self.as_mut_slice())
        }

        /// Append bytes, growing into a new guarded mapping if needed.
        pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), GuardPageError> {
            let required = self.len.checked_add(bytes.len()).ok_or(GuardPageError {
                operation: GuardPageOperation::Length,
                errno: 0,
            })?;

            if required > self.data_capacity {
                self.grow_to(required)?;
            }

            let start = self.len;
            let end = required;
            self.as_mut_capacity_slice()[start..end].copy_from_slice(bytes);
            self.len = required;
            compiler_fence(Ordering::SeqCst);
            Ok(())
        }

        /// Clear the full writable data region and reset initialized length.
        #[inline(never)]
        pub fn clear_secret(&mut self) {
            crate::wipe::volatile_wipe(self.data.as_ptr(), self.data_capacity);
            self.len = 0;
        }

        /// Compare against a byte slice without early exit for equal-length
        /// inputs.
        ///
        /// Length mismatch returns immediately because the provided slice length
        /// is treated as public metadata.
        #[must_use]
        #[inline]
        pub fn constant_time_eq(&self, other: &[u8]) -> bool {
            crate::constant_time_eq_slices(self.as_slice(), other)
        }

        fn grow_to(&mut self, required: usize) -> Result<(), GuardPageError> {
            let next_capacity = self
                .data_capacity
                .saturating_mul(2)
                .max(required)
                .max(PAGE_SIZE);
            let mut replacement = Self::with_capacity(next_capacity)?;
            replacement.as_mut_capacity_slice()[..self.len].copy_from_slice(self.as_slice());
            replacement.len = self.len;

            self.clear_secret();
            core::mem::swap(self, &mut replacement);
            Ok(())
        }

        #[inline]
        fn as_slice(&self) -> &[u8] {
            // SAFETY: `data` points to `data_capacity` writable bytes owned by
            // this value, and `len <= data_capacity`.
            unsafe { core::slice::from_raw_parts(self.data.as_ptr(), self.len) }
        }

        #[inline]
        fn as_mut_slice(&mut self) -> &mut [u8] {
            // SAFETY: `&mut self` gives exclusive access and `len <=
            // data_capacity`.
            unsafe { core::slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
        }

        #[inline]
        fn as_mut_capacity_slice(&mut self) -> &mut [u8] {
            // SAFETY: `&mut self` gives exclusive access to the full writable
            // data region between guard pages.
            unsafe { core::slice::from_raw_parts_mut(self.data.as_ptr(), self.data_capacity) }
        }
    }

    impl Drop for GuardedSecretVec {
        #[inline]
        fn drop(&mut self) {
            self.clear_secret();
            let _ = unmap_guarded(self.base, self.map_len);
        }
    }

    impl crate::SecureSanitize for GuardedSecretVec {
        #[inline]
        fn secure_sanitize(&mut self) {
            self.clear_secret();
        }
    }

    impl fmt::Debug for GuardedSecretVec {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("GuardedSecretVec")
                .field("len", &self.len)
                .field("capacity", &self.data_capacity)
                .field("contents", &"<redacted>")
                .finish()
        }
    }

    fn rounded_data_len(len: usize) -> Result<usize, GuardPageError> {
        len.max(1)
            .checked_add(PAGE_SIZE - 1)
            .map(|value| value & !(PAGE_SIZE - 1))
            .ok_or(GuardPageError {
                operation: GuardPageOperation::Length,
                errno: 0,
            })
    }

    fn syscall_failed(ret: isize) -> bool {
        (-4095..=-1).contains(&ret)
    }

    fn syscall_error(operation: GuardPageOperation, ret: isize) -> GuardPageError {
        GuardPageError {
            operation,
            errno: (-ret) as i32,
        }
    }

    fn map_guarded(len: usize) -> Result<NonNull<u8>, GuardPageError> {
        let ret = raw_syscall6(
            SYS_MMAP,
            0,
            len,
            PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            usize::MAX,
            0,
        );

        if syscall_failed(ret) {
            return Err(syscall_error(GuardPageOperation::Map, ret));
        }

        NonNull::new(ret as *mut u8).ok_or(GuardPageError {
            operation: GuardPageOperation::Map,
            errno: 0,
        })
    }

    fn protect_data(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        let ret = raw_syscall3(
            SYS_MPROTECT,
            ptr.as_ptr() as usize,
            len,
            PROT_READ | PROT_WRITE,
        );
        if syscall_failed(ret) {
            Err(syscall_error(GuardPageOperation::Protect, ret))
        } else {
            Ok(())
        }
    }

    fn unmap_guarded(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        let ret = raw_syscall2(SYS_MUNMAP, ptr.as_ptr() as usize, len);
        if syscall_failed(ret) {
            Err(syscall_error(GuardPageOperation::Unmap, ret))
        } else {
            Ok(())
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn raw_syscall2(number: usize, arg1: usize, arg2: usize) -> isize {
        raw_syscall6(number, arg1, arg2, 0, 0, 0, 0)
    }

    #[cfg(target_arch = "x86_64")]
    fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
        raw_syscall6(number, arg1, arg2, arg3, 0, 0, 0)
    }

    #[cfg(target_arch = "x86_64")]
    fn raw_syscall6(
        number: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
    ) -> isize {
        let ret: isize;

        // SAFETY: Registers follow the Linux x86_64 syscall ABI. The syscall
        // number and arguments are fixed by the caller wrappers above.
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") number as isize => ret,
                in("rdi") arg1,
                in("rsi") arg2,
                in("rdx") arg3,
                in("r10") arg4,
                in("r8") arg5,
                in("r9") arg6,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack)
            );
        }

        ret
    }

    #[cfg(target_arch = "aarch64")]
    fn raw_syscall2(number: usize, arg1: usize, arg2: usize) -> isize {
        raw_syscall6(number, arg1, arg2, 0, 0, 0, 0)
    }

    #[cfg(target_arch = "aarch64")]
    fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
        raw_syscall6(number, arg1, arg2, arg3, 0, 0, 0)
    }

    #[cfg(target_arch = "aarch64")]
    fn raw_syscall6(
        number: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
    ) -> isize {
        let ret: isize;

        // SAFETY: Registers follow the Linux aarch64 syscall ABI. The syscall
        // number and arguments are fixed by the caller wrappers above.
        unsafe {
            asm!(
                "svc 0",
                inlateout("x0") arg1 as isize => ret,
                in("x1") arg2,
                in("x2") arg3,
                in("x3") arg4,
                in("x4") arg5,
                in("x5") arg6,
                in("x8") number,
                options(nostack)
            );
        }

        ret
    }
}

#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
pub use guard_pages::{GuardPageError, GuardPageOperation, GuardedSecretVec};

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

#[inline]
fn constant_time_eq_slices(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    constant_time_eq_equal_len(left, right)
}

#[inline]
fn constant_time_eq_equal_len(left: &[u8], right: &[u8]) -> bool {
    debug_assert_eq!(left.len(), right.len());

    #[cfg(all(feature = "asm-compare", target_arch = "x86_64", not(miri)))]
    {
        compare_asm::constant_time_eq_equal_len(left, right)
    }

    #[cfg(not(all(feature = "asm-compare", target_arch = "x86_64", not(miri))))]
    {
        portable_constant_time_eq_equal_len(left, right)
    }
}

#[inline]
#[cfg_attr(
    all(feature = "asm-compare", target_arch = "x86_64", not(miri)),
    allow(dead_code)
)]
fn portable_constant_time_eq_equal_len(left: &[u8], right: &[u8]) -> bool {
    debug_assert_eq!(left.len(), right.len());

    let mut diff = 0usize;
    let mut index = 0;
    while index < left.len() {
        diff = black_box(diff | usize::from(left[index] ^ right[index]));
        index += 1;
    }
    black_box(diff) == 0
}

#[cfg(kani)]
mod kani_verification {
    use super::*;

    #[kani::proof]
    fn prove_sanitize_bytes_clears_fixed_buffer() {
        let mut bytes: [u8; 4] = kani::any();

        sanitize_bytes(&mut bytes);

        assert_eq!(bytes, [0; 4]);
    }

    #[kani::proof]
    fn prove_secret_bytes_clear_erases_visible_contents() {
        let source: [u8; 4] = kani::any();
        let mut secret = SecretBytes::<4>::from_array(source);
        let mut output = [0xA5; 4];

        secret.secure_clear();
        assert!(secret.copy_to_slice(&mut output).is_ok());

        assert_eq!(output, [0; 4]);
    }

    #[kani::proof]
    fn prove_secret_bytes_constant_time_eq_matches_byte_equality() {
        let left: [u8; 4] = kani::any();
        let right: [u8; 4] = kani::any();
        let secret = SecretBytes::<4>::from_array(left);

        let mut expected = true;
        let mut index = 0;
        while index < 4 {
            expected &= left[index] == right[index];
            index += 1;
        }

        assert_eq!(secret.constant_time_eq(&right), expected);
    }

    #[kani::proof]
    fn prove_constant_time_eq_rejects_length_mismatch() {
        let left: [u8; 4] = kani::any();
        let right: [u8; 3] = kani::any();

        assert!(!constant_time_eq_slices(&left, &right));
    }

    #[kani::proof]
    #[cfg(feature = "alloc")]
    fn prove_next_secret_capacity_never_under_allocates() {
        let current: usize = kani::any();
        let required: usize = kani::any();

        let capacity = next_secret_capacity(current, required);

        assert!(capacity >= required);
        assert!(capacity >= 8);
    }
}

struct TemporaryBytes<'a, const N: usize> {
    bytes: &'a mut [u8; N],
}

impl<const N: usize> Drop for TemporaryBytes<'_, N> {
    #[inline]
    fn drop(&mut self) {
        sanitize_bytes(self.bytes);
    }
}

struct VolatileTemporaryBytes<'a, const N: usize> {
    bytes: &'a mut [u8; N],
}

impl<const N: usize> Drop for VolatileTemporaryBytes<'_, N> {
    #[inline]
    fn drop(&mut self) {
        crate::unsafe_wipe::volatile_sanitize_array(self.bytes);
    }
}

/// Fixed-size secret byte storage with automatic sanitization on drop.
///
/// Bytes are stored in a plain `[u8; N]` and all clearing routes through the
/// crate's internal volatile wipe backend. This gives the same clearing behavior
/// on targets with and without native byte atomics.
///
/// # Platform Notes
///
/// This type is `Sync` because it contains only plain bytes. Mutating and
/// clearing operations require `&mut self` to prevent partially-cleared
/// multi-byte observations through shared references.
///
/// The type deliberately does not implement `Clone`, `Copy`, `Deref`,
/// `AsRef<[u8]>`, `PartialEq`, or secret-printing `Debug`.
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    /// Create an all-zero secret buffer.
    #[must_use]
    #[inline]
    pub const fn zeroed() -> Self {
        Self { bytes: [0; N] }
    }

    /// Create a secret from an array, then volatile-clear the input array.
    ///
    /// For the strongest move hygiene, prefer [`SecretBytes::from_fn`] or
    /// [`SecretBytes::copy_from_slice`] so callers can avoid building a normal
    /// byte array first.
    #[must_use]
    #[inline]
    pub fn from_array(mut bytes: [u8; N]) -> Self {
        let mut secret = Self::zeroed();
        for (index, byte) in bytes.iter().copied().enumerate() {
            secret.store(index, byte);
        }
        secret.after_secret_write();
        sanitize_bytes(&mut bytes);
        secret
    }

    /// Create a secret by producing each byte directly.
    ///
    /// This avoids requiring a full temporary `[u8; N]` at the call boundary.
    #[must_use]
    #[inline]
    pub fn from_fn(mut make_byte: impl FnMut(usize) -> u8) -> Self {
        let mut secret = Self::zeroed();
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
    pub fn copy_from_slice(&mut self, source: &[u8]) -> Result<(), LengthError> {
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
        black_box(destination);
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
    pub fn write_byte(&mut self, index: usize, value: u8) -> Result<(), LengthError> {
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
    ///
    /// If the closure aborts the process, for example under `panic = "abort"`,
    /// Rust destructors do not run and the temporary stack copy cannot be
    /// cleared. On the normal return path the temporary is cleared eagerly
    /// before this method returns; on unwinding panic paths the RAII guard
    /// clears it during unwinding.
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
        let result = inspect(guard.bytes);
        // Eagerly clear before returning; the guard also clears on normal
        // return and unwind paths as defense in depth.
        sanitize_bytes_best_effort(guard.bytes);
        result
    }

    /// Call a closure with a temporary array copy, then volatile-clear that copy.
    ///
    /// The temporary stack copy is cleared with volatile writes on normal return
    /// and during unwinding. Like all destructor-based cleanup, it cannot run if
    /// the process aborts, including `panic = "abort"`.
    #[inline]
    pub fn expose_secret_volatile<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        let mut temporary = [0; N];
        let mut index = 0;
        while index < N {
            temporary[index] = self.load(index);
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        let guard = VolatileTemporaryBytes {
            bytes: &mut temporary,
        };
        let result = inspect(guard.bytes);
        crate::unsafe_wipe::volatile_sanitize_array(guard.bytes);
        result
    }

    /// Compare against a slice without early exit for equal-length inputs.
    ///
    /// Length mismatch returns immediately because the provided slice length is
    /// treated as public metadata. Prefer fixed-size inputs where possible.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        constant_time_eq_slices(self.bytes.as_slice(), other)
    }

    /// Compare against another secret without early exit.
    #[must_use]
    #[inline]
    pub fn constant_time_eq_secret(&self, other: &Self) -> bool {
        constant_time_eq_equal_len(self.bytes.as_slice(), other.bytes.as_slice())
    }

    /// Clear all bytes now. This is also called from `Drop`.
    #[inline(never)]
    pub fn secure_clear(&mut self) {
        wipe::volatile_wipe(self.bytes.as_mut_ptr(), N);
    }

    /// Clear all bytes now with volatile writes, then flush the cache lines
    /// covering the fixed-size storage.
    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    #[inline(never)]
    pub fn secure_clear_and_flush(&mut self) {
        crate::cache_flush::cache_flush_sanitize_bytes(self.bytes.as_mut_slice());
    }

    #[inline]
    fn load(&self, index: usize) -> u8 {
        self.bytes[index]
    }

    #[inline]
    fn store(&mut self, index: usize, value: u8) {
        self.bytes[index] = value;
    }

    #[inline]
    fn after_secret_write(&self) {
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

/// Error returned when an expiring secret has exceeded its configured lifetime.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretExpiredError;

#[cfg(feature = "std")]
impl fmt::Display for SecretExpiredError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret has expired")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SecretExpiredError {}

/// Error returned by [`ExpiringSecretBytes`] operations.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpiringSecretError {
    /// The secret has exceeded its configured lifetime.
    Expired(SecretExpiredError),
    /// The caller provided a buffer with the wrong length.
    Length(LengthError),
}

#[cfg(feature = "std")]
impl fmt::Display for ExpiringSecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired(error) => error.fmt(formatter),
            Self::Length(error) => write!(
                formatter,
                "length mismatch: expected {} bytes, got {} bytes",
                error.expected, error.actual
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExpiringSecretError {}

#[cfg(feature = "std")]
impl From<SecretExpiredError> for ExpiringSecretError {
    #[inline]
    fn from(error: SecretExpiredError) -> Self {
        Self::Expired(error)
    }
}

#[cfg(feature = "std")]
impl From<LengthError> for ExpiringSecretError {
    #[inline]
    fn from(error: LengthError) -> Self {
        Self::Length(error)
    }
}

/// Fixed-size secret bytes with `std` lifetime enforcement.
///
/// This type is available with the `std` feature. It wraps [`SecretBytes<N>`],
/// tracks creation time with [`std::time::Instant`], and rejects exposure after
/// the configured maximum age. On expiration, fallible read/exposure/comparison
/// methods clear the wrapped secret before returning [`SecretExpiredError`].
///
/// There is no background task. Expiration is checked only when a method is
/// called.
#[cfg(feature = "std")]
pub struct ExpiringSecretBytes<const N: usize> {
    inner: SecretBytes<N>,
    created_at: std::time::Instant,
    max_age: std::time::Duration,
}

#[cfg(feature = "std")]
impl<const N: usize> ExpiringSecretBytes<N> {
    /// Create an all-zero expiring secret.
    #[must_use]
    #[inline]
    pub fn zeroed(max_age: std::time::Duration) -> Self {
        Self {
            inner: SecretBytes::zeroed(),
            created_at: std::time::Instant::now(),
            max_age,
        }
    }

    /// Create an expiring secret from an array, then volatile-clear the input
    /// array.
    #[must_use]
    #[inline]
    pub fn from_array(bytes: [u8; N], max_age: std::time::Duration) -> Self {
        Self {
            inner: SecretBytes::from_array(bytes),
            created_at: std::time::Instant::now(),
            max_age,
        }
    }

    /// Create an expiring secret by producing each byte directly.
    #[must_use]
    #[inline]
    pub fn from_fn(max_age: std::time::Duration, make_byte: impl FnMut(usize) -> u8) -> Self {
        Self {
            inner: SecretBytes::from_fn(make_byte),
            created_at: std::time::Instant::now(),
            max_age,
        }
    }

    /// Wrap an existing [`SecretBytes<N>`] and start a new lifetime window.
    #[must_use]
    #[inline]
    pub fn from_secret(secret: SecretBytes<N>, max_age: std::time::Duration) -> Self {
        Self {
            inner: secret,
            created_at: std::time::Instant::now(),
            max_age,
        }
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

    /// Configured maximum age for the current secret value.
    #[must_use]
    #[inline]
    pub const fn max_age(&self) -> std::time::Duration {
        self.max_age
    }

    /// Elapsed lifetime of the current secret value.
    #[must_use]
    #[inline]
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Returns true when the current secret value has expired.
    #[must_use]
    #[inline]
    pub fn is_expired(&self) -> bool {
        self.age() >= self.max_age
    }

    /// Replace all bytes and restart the lifetime window.
    ///
    /// If the previous value has already expired, it is cleared before the new
    /// value is copied in.
    #[inline]
    pub fn replace_from_slice(&mut self, source: &[u8]) -> Result<(), LengthError> {
        if self.is_expired() {
            self.inner.secure_clear();
        }

        self.inner.copy_from_slice(source)?;
        self.created_at = std::time::Instant::now();
        Ok(())
    }

    /// Fill a caller-provided destination with a copy of the secret bytes if
    /// the secret has not expired.
    #[inline]
    pub fn try_copy_to_slice(&mut self, destination: &mut [u8]) -> Result<(), ExpiringSecretError> {
        self.enforce_live()?;
        self.inner.copy_to_slice(destination).map_err(Into::into)
    }

    /// Run a closure with a temporary array copy if the secret has not expired.
    #[inline]
    pub fn try_expose_secret<R>(
        &mut self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, SecretExpiredError> {
        self.enforce_live()?;
        Ok(self.inner.expose_secret(inspect))
    }

    /// Compare against a slice if the secret has not expired.
    ///
    /// Length mismatch remains public metadata and returns `Ok(false)`.
    #[inline]
    pub fn try_constant_time_eq(&mut self, other: &[u8]) -> Result<bool, SecretExpiredError> {
        self.enforce_live()?;
        Ok(self.inner.constant_time_eq(other))
    }

    /// Clear the wrapped secret immediately.
    #[inline(never)]
    pub fn secure_clear(&mut self) {
        self.inner.secure_clear();
    }

    #[inline]
    fn enforce_live(&mut self) -> Result<(), SecretExpiredError> {
        if self.is_expired() {
            self.inner.secure_clear();
            Err(SecretExpiredError)
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "std")]
impl<const N: usize> Drop for ExpiringSecretBytes<N> {
    #[inline]
    fn drop(&mut self) {
        self.secure_clear();
    }
}

#[cfg(feature = "std")]
impl<const N: usize> SecureSanitize for ExpiringSecretBytes<N> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.secure_clear();
    }
}

#[cfg(feature = "std")]
impl<const N: usize> fmt::Debug for ExpiringSecretBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpiringSecretBytes")
            .field("len", &N)
            .field("max_age", &self.max_age)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Heap-allocated secret bytes with clear-on-drop behavior.
///
/// This type is available with the `alloc` feature. It is intended for
/// integration boundaries where the secret length is dynamic, such as decoded
/// tokens or PEM/DER material. Clearing uses volatile writes over the full
/// allocation capacity before the vector length is set to zero.
#[cfg(feature = "alloc")]
pub struct SecretVec {
    inner: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl SecretVec {
    /// Wrap a vector using volatile clearing on drop.
    #[must_use]
    #[inline]
    pub const fn new(inner: Vec<u8>) -> Self {
        Self { inner }
    }

    /// Compatibility alias for [`SecretVec::new`].
    #[must_use]
    #[inline]
    pub const fn new_volatile(inner: Vec<u8>) -> Self {
        Self::new(inner)
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

    /// Compatibility alias for [`SecretVec::with_capacity`].
    #[must_use]
    #[inline]
    pub fn with_capacity_volatile(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }

    /// Create a secret vector by copying bytes from a slice.
    #[must_use]
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(Vec::from(bytes))
    }

    /// Compatibility alias for [`SecretVec::from_slice`].
    #[must_use]
    #[inline]
    pub fn from_slice_volatile(bytes: &[u8]) -> Self {
        Self::from_slice(bytes)
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

    /// Clear this value immediately with volatile writes.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        sanitize_vec_capacity(&mut self.inner);
    }

    /// Clear this value immediately with volatile writes, then flush the cache
    /// lines covering the heap allocation.
    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    #[inline(never)]
    pub fn clear_secret_and_flush(&mut self) {
        crate::cache_flush::cache_flush_sanitize_vec(&mut self.inner);
    }

    /// Compare against a byte slice without early exit for equal-length inputs.
    ///
    /// Length mismatch returns immediately because the provided slice length is
    /// treated as public metadata.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        constant_time_eq_slices(self.inner.as_slice(), other)
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

        let new_capacity = next_secret_capacity(self.inner.capacity(), required);
        let mut replacement = Vec::with_capacity(new_capacity);
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
/// passphrases, and textual secrets that must cross APIs as UTF-8. Clearing
/// uses volatile writes over the full allocation capacity before the internal
/// byte vector length is set to zero.
#[cfg(feature = "alloc")]
pub struct SecretString {
    inner: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl SecretString {
    /// Wrap a string using volatile clearing on drop.
    #[must_use]
    #[inline]
    pub fn new(inner: String) -> Self {
        Self {
            inner: inner.into_bytes(),
        }
    }

    /// Compatibility alias for [`SecretString::new`].
    #[must_use]
    #[inline]
    pub fn new_volatile(inner: String) -> Self {
        Self::new(inner)
    }

    /// Create an empty secret string.
    #[must_use]
    #[inline]
    pub const fn empty() -> Self {
        Self { inner: Vec::new() }
    }

    /// Create an empty secret string with at least the requested byte capacity.
    #[must_use]
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    /// Compatibility alias for [`SecretString::with_capacity`].
    #[must_use]
    #[inline]
    pub fn with_capacity_volatile(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }

    /// Create a secret string by copying from a string slice.
    #[must_use]
    #[inline]
    pub fn from_secret_str(text: &str) -> Self {
        Self {
            inner: Vec::from(text.as_bytes()),
        }
    }

    /// Compatibility alias for [`SecretString::from_secret_str`].
    #[must_use]
    #[inline]
    pub fn from_secret_str_volatile(text: &str) -> Self {
        Self::from_secret_str(text)
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

    /// Clear this value immediately with volatile writes.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        sanitize_vec_capacity(&mut self.inner);
    }

    /// Clear this value immediately with volatile writes, then flush the cache
    /// lines covering the heap allocation.
    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    #[inline(never)]
    pub fn clear_secret_and_flush(&mut self) {
        crate::cache_flush::cache_flush_sanitize_vec(&mut self.inner);
    }

    /// Compare against UTF-8 text without early exit for equal-length inputs.
    ///
    /// Length mismatch returns immediately because the provided string length
    /// is treated as public metadata.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &str) -> bool {
        constant_time_eq_slices(self.inner.as_slice(), other.as_bytes())
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

        let new_capacity = next_secret_capacity(self.inner.capacity(), required);
        let mut replacement = Vec::with_capacity(new_capacity);
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
///
/// # Clearing Strength
///
/// When `T = [u8; N]`, this wrapper clears through [`SecureSanitize`] for byte
/// arrays, which uses the same volatile byte clearing primitive as the rest of
/// the crate. For fixed-size byte secrets, still prefer [`SecretBytes<N>`],
/// which avoids implementing `Clone`, `Copy`, `Deref`, `AsRef<[u8]>`, or
/// secret-printing `Debug`.
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

    /// Clear a fixed-size byte array using volatile writes.
    #[inline(never)]
    pub fn volatile_sanitize_array<const N: usize>(bytes: &mut [u8; N]) {
        volatile_sanitize_bytes(bytes);
    }

    /// Clear a `Vec<u8>` using volatile writes, then set its length to zero.
    #[cfg(feature = "alloc")]
    #[inline(never)]
    pub fn volatile_sanitize_vec(bytes: &mut Vec<u8>) {
        crate::wipe::volatile_wipe(bytes.as_mut_ptr(), bytes.capacity());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_round_trip_and_clear() {
        let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);
        let mut out = [0; 4];

        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [1, 2, 3, 4]);

        secret.secure_clear();
        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [0, 0, 0, 0]);
    }

    #[test]
    fn length_errors_are_explicit() {
        let mut secret = SecretBytes::<4>::zeroed();

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
        assert!(!left.constant_time_eq(&[0, 8, 7, 6]));
        assert!(left.constant_time_eq_secret(&same));
        assert!(!left.constant_time_eq_secret(&different));
    }

    #[cfg(all(feature = "asm-compare", target_arch = "x86_64", not(miri)))]
    #[test]
    fn assembly_comparison_matches_portable_path() {
        let left = [1_u8, 2, 3, 4, 5, 6, 7, 8];
        let same = [1_u8, 2, 3, 4, 5, 6, 7, 8];
        let different = [1_u8, 2, 3, 4, 5, 6, 7, 0];
        let empty: [u8; 0] = [];

        assert_eq!(
            compare_asm::constant_time_eq_equal_len(&left, &same),
            portable_constant_time_eq_equal_len(&left, &same)
        );
        assert_eq!(
            compare_asm::constant_time_eq_equal_len(&left, &different),
            portable_constant_time_eq_equal_len(&left, &different)
        );
        assert_eq!(
            compare_asm::constant_time_eq_equal_len(&empty, &empty),
            portable_constant_time_eq_equal_len(&empty, &empty)
        );
    }

    #[test]
    fn volatile_exposure_returns_closure_result() {
        let secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);

        let sum = secret.expose_secret_volatile(|bytes| {
            bytes
                .iter()
                .copied()
                .fold(0_u8, |total, byte| total.wrapping_add(byte))
        });

        assert_eq!(sum, 10);
    }

    #[cfg(feature = "std")]
    #[test]
    fn expiring_secret_allows_access_before_expiration() {
        let mut secret =
            ExpiringSecretBytes::<4>::from_array([1, 2, 3, 4], std::time::Duration::from_secs(60));
        let mut out = [0; 4];

        assert!(secret.try_copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(
            secret.try_expose_secret(|bytes| bytes[0].wrapping_add(bytes[3])),
            Ok(5)
        );
        assert_eq!(secret.try_constant_time_eq(&[1, 2, 3, 4]), Ok(true));
    }

    #[cfg(feature = "std")]
    #[test]
    fn expiring_secret_clears_and_rejects_after_expiration() {
        let mut secret =
            ExpiringSecretBytes::<4>::from_array([1, 2, 3, 4], std::time::Duration::ZERO);
        let mut out = [9; 4];

        assert_eq!(
            secret.try_expose_secret(|bytes| bytes[0]),
            Err(SecretExpiredError)
        );
        assert_eq!(
            secret.try_copy_to_slice(&mut out),
            Err(ExpiringSecretError::Expired(SecretExpiredError))
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn expiring_secret_replacement_restarts_lifetime() {
        let mut secret =
            ExpiringSecretBytes::<4>::from_array([1, 2, 3, 4], std::time::Duration::from_secs(60));
        let mut out = [0; 4];

        secret.replace_from_slice(&[5, 6, 7, 8]).unwrap();
        assert_eq!(secret.try_copy_to_slice(&mut out), Ok(()));
        assert_eq!(out, [5, 6, 7, 8]);
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

    #[test]
    fn secure_sanitize_struct_macro_covers_all_fields() {
        crate::secure_sanitize_struct! {
            struct MacroCredentials {
                private_key: SecretBytes<4>,
                nonce: SecretBytes<2>,
            }
        }

        let mut credentials = MacroCredentials {
            private_key: SecretBytes::from_array([1, 2, 3, 4]),
            nonce: SecretBytes::from_array([5, 6]),
        };

        credentials.secure_sanitize();

        assert!(credentials.private_key.constant_time_eq(&[0, 0, 0, 0]));
        assert!(credentials.nonce.constant_time_eq(&[0, 0]));
    }

    #[test]
    fn secure_drop_struct_macro_generates_sanitize_and_drop() {
        crate::secure_drop_struct! {
            struct DropCredentials {
                private_key: SecretBytes<4>,
                nonce: SecretBytes<2>,
            }
        }

        let mut credentials = DropCredentials {
            private_key: SecretBytes::from_array([1, 2, 3, 4]),
            nonce: SecretBytes::from_array([5, 6]),
        };

        credentials.secure_sanitize();

        assert!(credentials.private_key.constant_time_eq(&[0, 0, 0, 0]));
        assert!(credentials.nonce.constant_time_eq(&[0, 0]));

        {
            let credentials = DropCredentials {
                private_key: SecretBytes::from_array([1, 2, 3, 4]),
                nonce: SecretBytes::from_array([5, 6]),
            };

            let _ = &credentials;
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_round_trip_and_clear() {
        let mut secret = SecretVec::from_slice(&[1, 2, 3]);

        assert_eq!(secret.with_secret(|bytes| bytes.len()), 3);
        assert!(secret.constant_time_eq(&[1, 2, 3]));
        assert!(!secret.constant_time_eq(&[1, 2]));
        secret.extend_from_slice(&[4]);
        assert_eq!(secret.with_secret(|bytes| bytes[3]), 4);

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_grows_exponentially() {
        let mut secret = SecretVec::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let initial_capacity = secret.inner.capacity();

        secret.extend_from_slice(&[9]);

        assert!(secret.inner.capacity() >= initial_capacity.saturating_mul(2));
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
        assert!(secret.constant_time_eq("secret-token"));
        assert!(!secret.constant_time_eq("secret"));

        let rendered = std::format!("{secret:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("secret-token"));

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_string_grows_exponentially() {
        let mut secret = SecretString::from_secret_str("abcdefgh");
        let initial_capacity = secret.inner.capacity();

        secret.push_str("i");

        assert!(secret.inner.capacity() >= initial_capacity.saturating_mul(2));
    }

    #[test]
    fn volatile_wipe_clears_slice() {
        let mut bytes = [0xA5; 16];

        crate::unsafe_wipe::volatile_sanitize_bytes(&mut bytes);

        assert_eq!(bytes, [0; 16]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn volatile_wipe_clears_alloc_types_when_enabled() {
        let mut bytes = std::vec![0xBB; 8];
        let mut text = std::string::String::from("secret");

        crate::unsafe_wipe::volatile_sanitize_vec(&mut bytes);
        crate::unsafe_wipe::volatile_sanitize_string(&mut text);

        assert!(bytes.is_empty());
        assert!(text.is_empty());
    }

    #[test]
    fn volatile_on_drop_wrapper_is_explicit() {
        let mut secret = crate::unsafe_wipe::VolatileOnDrop::new([1, 2, 3, 4]);

        assert_eq!(secret.with_secret(|bytes| bytes[2]), 3);
        secret.with_secret_mut(|bytes| bytes[2] = 9);
        assert_eq!(secret.with_secret(|bytes| bytes[2]), 9);

        secret.into_cleared();
    }

    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    #[test]
    fn cache_flush_sanitize_clears_slice_and_secret_bytes() {
        let mut bytes = [0xA5; 16];
        crate::cache_flush::cache_flush_sanitize_array(&mut bytes);
        assert_eq!(bytes, [0; 16]);

        let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);
        secret.secure_clear_and_flush();
        assert!(secret.constant_time_eq(&[0, 0, 0, 0]));

        let mut wrapped = crate::cache_flush::CacheFlushOnDrop::new([1, 2, 3, 4]);
        wrapped.with_secret_mut(|value| value[0] = 9);
        assert_eq!(wrapped.with_secret(|value| value[0]), 9);
        wrapped.into_cleared();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn volatile_constructor_aliases_still_work() {
        let mut bytes = SecretVec::from_slice_volatile(&[1, 2, 3]);
        let mut text = SecretString::from_secret_str_volatile("secret");

        assert_eq!(bytes.with_secret(|secret| secret[0]), 1);
        assert_eq!(text.try_with_secret(|secret| secret.len()), Ok(6));

        bytes.clear_secret();
        text.clear_secret();

        assert!(bytes.is_empty());
        assert!(text.is_empty());
    }

    #[cfg(all(
        feature = "cache-flush",
        feature = "alloc",
        target_arch = "x86_64",
        not(miri)
    ))]
    #[test]
    fn cache_flush_sanitize_clears_alloc_types() {
        let mut bytes = SecretVec::from_slice(&[1, 2, 3]);
        let mut text = SecretString::from_secret_str("secret");

        bytes.clear_secret_and_flush();
        text.clear_secret_and_flush();

        assert!(bytes.is_empty());
        assert!(text.is_empty());
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn locked_secret_bytes_round_trip_and_clear() {
        let mut secret = LockedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();
        let mut out = [0; 4];

        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [1, 2, 3, 4]);
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));
        assert!(!secret.constant_time_eq(&[1, 2, 3]));

        secret.secure_clear();
        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [0, 0, 0, 0]);
    }

    #[cfg(all(
        feature = "memory-lock",
        feature = "cache-flush",
        target_os = "linux",
        target_arch = "x86_64",
        not(miri)
    ))]
    #[test]
    fn locked_secret_bytes_can_clear_and_flush() {
        let mut secret = LockedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();
        let mut out = [0; 4];

        secret.secure_clear_and_flush();

        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [0, 0, 0, 0]);
    }

    #[cfg(all(
        feature = "guard-pages",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn guarded_secret_vec_round_trip_grow_and_clear() {
        let mut secret = GuardedSecretVec::from_slice(&[1, 2, 3]).unwrap();

        assert_eq!(secret.len(), 3);
        assert!(secret.capacity() >= 3);
        assert_eq!(secret.with_secret(|bytes| bytes[0]), 1);
        assert!(secret.constant_time_eq(&[1, 2, 3]));
        assert!(!secret.constant_time_eq(&[1, 2]));

        secret.with_secret_mut(|bytes| bytes[0] = 9);
        let original_capacity = secret.capacity();
        let extra = [4_u8; 5000];
        secret.extend_from_slice(&extra).unwrap();

        assert!(secret.capacity() > original_capacity);
        assert_eq!(secret.len(), 5003);
        assert_eq!(
            secret.with_secret(|bytes| (bytes[0], bytes[2], bytes[5002])),
            (9, 3, 4)
        );

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(all(
        feature = "guard-pages",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn guarded_secret_vec_debug_is_redacted_and_sanitizable() {
        let mut secret = GuardedSecretVec::from_slice(b"secret").unwrap();
        let rendered = std::format!("{secret:?}");

        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("secret"));

        secret.secure_sanitize();
        assert!(secret.is_empty());
    }
}
