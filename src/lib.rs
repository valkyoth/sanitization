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
//! - Platform memory locking is available only through the explicit
//!   `memory-lock` feature on supported Linux, macOS, Windows, and BSD targets.
//! - x86_64 assembly-backed comparison is available only through the explicit
//!   `asm-compare` feature.
//! - x86_64 cache-line eviction is available only through the explicit
//!   `cache-flush` feature.
//! - Fixed-size lifetime enforcement is available only through the `std`
//!   feature and [`ExpiringSecretBytes`].
//! - Guard-page allocation is available only through the explicit
//!   `guard-pages` feature on supported Linux, macOS, Windows, and BSD targets.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};
#[cfg(feature = "alloc")]
use core::str::Utf8Error;
use core::{
    fmt,
    hint::black_box,
    mem,
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

impl fmt::Display for LengthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "length mismatch: expected {} bytes, got {} bytes",
            self.expected, self.actual
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LengthError {}

/// Shared trait for values that can clear their own sensitive contents.
///
/// The crate implements this trait for common scalar types, arrays, slices,
/// `Option<T>`, `Result<T, E>`, and, with `alloc`, `Box<T>`, `Vec<T>`, and
/// `String`. Opaque third-party types cannot be implemented here without
/// taking dependencies on them; wrap those values in a local newtype and
/// implement this trait there.
pub trait SecureSanitize {
    /// Clear the sensitive bytes owned by this value.
    fn secure_sanitize(&mut self);
}

#[inline(never)]
fn sanitize_plain_value<T>(value: &mut T) {
    wipe::volatile_wipe((value as *mut T).cast::<u8>(), mem::size_of::<T>());
}

macro_rules! impl_secure_sanitize_scalar {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl SecureSanitize for $ty {
                #[inline(never)]
                fn secure_sanitize(&mut self) {
                    sanitize_plain_value(self);
                }
            }
        )+
    };
}

impl_secure_sanitize_scalar!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, bool, char, f32, f64,
);

/// Declare a struct and generate [`SecureSanitize`] for all fields.
///
/// This is a dependency-free alternative to a derive macro. Each field type
/// must implement [`SecureSanitize`]. The macro does not implement [`Drop`], so
/// use this form when the type needs custom drop behavior or is wrapped in
/// [`Secret`].
///
/// This macro intentionally supports named-field structs without generics or
/// `where` clauses. For generic structs, implement [`SecureSanitize`] manually
/// so the impl generics and bounds stay explicit.
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
/// This macro intentionally supports named-field structs without generics or
/// `where` clauses. For generic structs, implement [`SecureSanitize`] and
/// [`Drop`] manually so the impl generics and bounds stay explicit.
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
        // Retain the hardware fence as a defense-in-depth ordering boundary
        // for callers that clear secrets immediately before handing memory to
        // lower-level or platform-specific code.
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

#[cfg(feature = "alloc")]
#[inline]
fn max_utf8_capacity(char_count: usize) -> usize {
    char_count.saturating_mul(4)
}

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
#[allow(unsafe_code)]
mod memory_lock {
    use core::{
        fmt,
        ptr::NonNull,
        sync::atomic::{compiler_fence, Ordering},
    };

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    use core::arch::asm;
    #[cfg(not(target_os = "linux"))]
    use core::ffi::c_void;
    #[cfg(target_os = "windows")]
    use core::mem::MaybeUninit;

    // Linux exposes page size at runtime rather than through a direct syscall.
    // Use a conservative architecture granule so requested mappings are page
    // multiples on supported kernels without depending on libc.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const LINUX_PAGE_GRANULE: usize = 4096;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const LINUX_PAGE_GRANULE: usize = 65_536;

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    const UNIX_FALLBACK_PAGE_GRANULE: usize = 4096;

    #[cfg(target_os = "windows")]
    const WINDOWS_FALLBACK_PAGE_GRANULE: usize = 4096;

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    const PROT_READ: usize = 0x1;
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    const PROT_WRITE: usize = 0x2;
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    const MAP_PRIVATE: usize = 0x02;
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    const MAP_ANONYMOUS: usize = 0x1000;

    #[cfg(target_os = "linux")]
    const PROT_READ: usize = 0x1;
    #[cfg(target_os = "linux")]
    const PROT_WRITE: usize = 0x2;
    #[cfg(target_os = "linux")]
    const MAP_PRIVATE: usize = 0x02;
    #[cfg(target_os = "linux")]
    const MAP_ANONYMOUS: usize = 0x20;
    #[cfg(target_os = "linux")]
    const MADV_DONTFORK: usize = 10;
    #[cfg(target_os = "linux")]
    const MADV_DONTDUMP: usize = 16;

    #[cfg(target_os = "windows")]
    const MEM_COMMIT: u32 = 0x1000;
    #[cfg(target_os = "windows")]
    const MEM_RESERVE: u32 = 0x2000;
    #[cfg(target_os = "windows")]
    const MEM_RELEASE: u32 = 0x8000;
    #[cfg(target_os = "windows")]
    const PAGE_READWRITE: u32 = 0x04;

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const SYS_MMAP: usize = 9;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const SYS_MUNMAP: usize = 11;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const SYS_MADVISE: usize = 28;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const SYS_MLOCK: usize = 149;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const SYS_MUNLOCK: usize = 150;

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const SYS_MMAP: usize = 222;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const SYS_MUNMAP: usize = 215;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const SYS_MADVISE: usize = 233;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const SYS_MLOCK: usize = 228;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const SYS_MUNLOCK: usize = 229;

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    unsafe extern "C" {
        fn getpagesize() -> i32;
        fn mmap(
            addr: *mut c_void,
            len: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: isize,
        ) -> *mut c_void;
        fn munmap(addr: *mut c_void, len: usize) -> i32;
        fn mlock(addr: *const c_void, len: usize) -> i32;
        fn munlock(addr: *const c_void, len: usize) -> i32;
    }

    #[cfg(target_os = "windows")]
    #[repr(C)]
    struct SystemInfo {
        processor_architecture: u16,
        reserved: u16,
        page_size: u32,
        minimum_application_address: *mut c_void,
        maximum_application_address: *mut c_void,
        active_processor_mask: usize,
        number_of_processors: u32,
        processor_type: u32,
        allocation_granularity: u32,
        processor_level: u16,
        processor_revision: u16,
    }

    #[cfg(target_os = "windows")]
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLastError() -> u32;
        fn GetSystemInfo(system_info: *mut SystemInfo);
        fn VirtualAlloc(
            address: *mut c_void,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut c_void;
        fn VirtualFree(address: *mut c_void, size: usize, free_type: u32) -> i32;
        fn VirtualLock(address: *mut c_void, size: usize) -> i32;
        fn VirtualUnlock(address: *mut c_void, size: usize) -> i32;
    }

    /// Platform memory-locking operation that failed.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum MemoryLockOperation {
        /// The requested mapping length overflowed.
        Length,
        /// Anonymous mapping creation failed.
        Map,
        /// Core-dump exclusion failed.
        DontDump,
        /// Fork inheritance exclusion failed.
        DontFork,
        /// Page locking failed.
        Lock,
        /// Page unlocking failed.
        Unlock,
        /// Anonymous mapping release failed.
        Unmap,
    }

    /// Error returned by platform memory-locking operations.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct MemoryLockError {
        /// Operation that failed.
        pub operation: MemoryLockOperation,
        /// Positive errno or Windows `GetLastError` value when available.
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

    /// Error returned when constructing [`LockedSecretBytes`] from a slice.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum LockedSecretBytesError {
        /// The caller provided a slice with the wrong length.
        Length(crate::LengthError),
        /// Platform mapping, core-dump exclusion, locking, unlocking, or
        /// unmapping failed.
        Memory(MemoryLockError),
    }

    impl fmt::Display for LockedSecretBytesError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Length(error) => error.fmt(formatter),
                Self::Memory(error) => error.fmt(formatter),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for LockedSecretBytesError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Length(error) => Some(error),
                Self::Memory(error) => Some(error),
            }
        }
    }

    /// Error returned when fallible locked secret byte generation fails.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum LockedSecretBytesGenerateError<E> {
        /// Platform mapping, core-dump exclusion, locking, unlocking, or
        /// unmapping failed before generation completed.
        Memory(MemoryLockError),
        /// The caller-provided byte generator failed.
        Generate(E),
    }

    impl<E: fmt::Display> fmt::Display for LockedSecretBytesGenerateError<E> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Memory(error) => error.fmt(formatter),
                Self::Generate(error) => error.fmt(formatter),
            }
        }
    }

    #[cfg(feature = "std")]
    impl<E> std::error::Error for LockedSecretBytesGenerateError<E>
    where
        E: std::error::Error + 'static,
    {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Memory(error) => Some(error),
                Self::Generate(error) => Some(error),
            }
        }
    }

    impl From<crate::LengthError> for LockedSecretBytesError {
        #[inline]
        fn from(error: crate::LengthError) -> Self {
            Self::Length(error)
        }
    }

    impl From<MemoryLockError> for LockedSecretBytesError {
        #[inline]
        fn from(error: MemoryLockError) -> Self {
            Self::Memory(error)
        }
    }

    impl<E> From<MemoryLockError> for LockedSecretBytesGenerateError<E> {
        #[inline]
        fn from(error: MemoryLockError) -> Self {
            Self::Memory(error)
        }
    }

    /// Fixed-size secret bytes stored in a private locked platform mapping.
    ///
    /// This type is available with the `memory-lock` feature on supported
    /// Linux, macOS, Windows, and BSD targets. Linux uses raw syscalls with
    /// `mmap`, `MADV_DONTDUMP`, `MADV_DONTFORK`, and `mlock`. macOS and BSD
    /// use system `mmap`/`mlock` entry points. Windows uses
    /// `VirtualAlloc`/`VirtualLock`. Every backend volatile-clears the full
    /// mapping before unlocking and releasing it.
    ///
    /// The secret bytes are not stored inline in the Rust value. Moving this
    /// type only moves pointer metadata, so ordinary Rust moves do not copy the
    /// secret byte array itself.
    pub struct LockedSecretBytes<const N: usize> {
        ptr: NonNull<u8>,
        map_len: usize,
    }

    // SAFETY: The value exclusively owns a private mapping. Moving ownership to
    // another thread does not invalidate the mapping, and mutation/clearing
    // still requires `&mut self`. `Sync` is intentionally not implemented.
    unsafe impl<const N: usize> Send for LockedSecretBytes<N> {}

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

            if let Err(error) = mark_dontdump(ptr, map_len) {
                let _ = unmap_private(ptr, map_len);
                return Err(error);
            }

            if let Err(error) = mark_dontfork(ptr, map_len) {
                let _ = unmap_private(ptr, map_len);
                return Err(error);
            }

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

        /// Allocate locked storage and copy bytes from a same-length slice.
        ///
        /// This is the preferred constructor when the secret is already held in
        /// a runtime buffer. It creates the private mapping, applies
        /// OS-specific dump or fork-exclusion policies are applied where the
        /// backend supports them, and the mapping is locked before copying
        /// bytes into it. The source slice is borrowed and cannot be cleared by
        /// this function.
        #[inline]
        pub fn from_slice(source: &[u8]) -> Result<Self, LockedSecretBytesError> {
            if source.len() != N {
                return Err(crate::LengthError {
                    expected: N,
                    actual: source.len(),
                }
                .into());
            }

            let mut secret = Self::zeroed()?;
            secret.as_mut_slice().copy_from_slice(source);
            compiler_fence(Ordering::SeqCst);
            Ok(secret)
        }

        /// Allocate locked storage and produce each byte directly into it.
        ///
        /// This avoids requiring a full temporary `[u8; N]` or input slice at
        /// the call boundary. The private mapping is created, marked with
        /// locked before `make_byte` is called.
        #[inline]
        pub fn from_fn(mut make_byte: impl FnMut(usize) -> u8) -> Result<Self, MemoryLockError> {
            let mut secret = Self::zeroed()?;
            let mut index = 0;
            while index < N {
                secret.as_mut_slice()[index] = make_byte(index);
                index += 1;
            }
            compiler_fence(Ordering::SeqCst);
            Ok(secret)
        }

        /// Allocate locked storage and fallibly produce each byte directly into
        /// it.
        ///
        /// The private mapping is created, dump-excluded, fork-excluded, and
        /// locked before `make_byte` is called. If generation fails, partial
        /// bytes already written into the mapping are cleared before the error
        /// is returned.
        #[inline]
        pub fn try_from_fn<E>(
            mut make_byte: impl FnMut(usize) -> Result<u8, E>,
        ) -> Result<Self, LockedSecretBytesGenerateError<E>> {
            let mut secret = Self::zeroed()?;
            let mut index = 0;
            while index < N {
                match make_byte(index) {
                    Ok(byte) => secret.as_mut_slice()[index] = byte,
                    Err(error) => return Err(LockedSecretBytesGenerateError::Generate(error)),
                }
                index += 1;
            }
            compiler_fence(Ordering::SeqCst);
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

        /// Replace all secret bytes from a same-length slice.
        ///
        /// The replacement bytes are copied into a fresh locked mapping before
        /// the old mapping is cleared and swapped out. If mapping setup fails,
        /// the old locked value remains unchanged.
        #[inline]
        pub fn replace_from_slice(&mut self, source: &[u8]) -> Result<(), LockedSecretBytesError> {
            let mut replacement = Self::from_slice(source)?;
            self.secure_clear();
            core::mem::swap(self, &mut replacement);
            Ok(())
        }

        /// Replace all secret bytes from an owned array, then volatile-clear
        /// that input array.
        ///
        /// The replacement bytes are copied into a fresh locked mapping before
        /// the old mapping is cleared and swapped out. If mapping setup fails,
        /// the owned input array is still cleared and the old locked value
        /// remains unchanged.
        #[inline]
        pub fn replace_from_array(&mut self, bytes: [u8; N]) -> Result<(), MemoryLockError> {
            let mut replacement = Self::from_array(bytes)?;
            self.secure_clear();
            core::mem::swap(self, &mut replacement);
            Ok(())
        }

        /// Replace all secret bytes with generated bytes.
        ///
        /// The replacement bytes are generated into a fresh locked mapping
        /// before the old mapping is cleared and swapped out. If `make_byte`
        /// panics, the old locked value remains unchanged and partial generated
        /// bytes are cleared during unwinding.
        #[inline]
        pub fn replace_from_fn(
            &mut self,
            make_byte: impl FnMut(usize) -> u8,
        ) -> Result<(), MemoryLockError> {
            let mut replacement = Self::from_fn(make_byte)?;
            self.secure_clear();
            core::mem::swap(self, &mut replacement);
            Ok(())
        }

        /// Replace all secret bytes with fallibly generated bytes.
        ///
        /// The replacement bytes are generated into a fresh locked mapping
        /// before the old mapping is cleared and swapped out. If mapping setup
        /// or generation fails, the old locked value remains unchanged and
        /// partial generated bytes are cleared before the error is returned.
        #[inline]
        pub fn try_replace_from_fn<E>(
            &mut self,
            make_byte: impl FnMut(usize) -> Result<u8, E>,
        ) -> Result<(), LockedSecretBytesGenerateError<E>> {
            let mut replacement = Self::try_from_fn(make_byte)?;
            self.secure_clear();
            core::mem::swap(self, &mut replacement);
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
        ///
        /// The portable fallback is intended to avoid data-dependent early
        /// exit, but it is not a formal hardware-level constant-time
        /// guarantee. On x86_64, enable `asm-compare` for a stronger compiler
        /// boundary.
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

        /// Consume this value after first clearing the full private mapping.
        ///
        /// Drop still runs after this method returns, so the mapping is
        /// unlocked and unmapped normally.
        #[inline]
        pub fn into_cleared(mut self) {
            self.secure_clear();
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
        let page_granule = platform_page_granule();
        len.checked_add(page_granule - 1)
            .map(|value| value & !(page_granule - 1))
            .ok_or(MemoryLockError {
                operation: MemoryLockOperation::Length,
                errno: 0,
            })
    }

    #[cfg(target_os = "linux")]
    #[inline]
    const fn platform_page_granule() -> usize {
        LINUX_PAGE_GRANULE
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    #[inline]
    fn platform_page_granule() -> usize {
        // SAFETY: `getpagesize` takes no arguments and returns the process page
        // size according to the platform C ABI.
        let page_size = unsafe { getpagesize() };
        if page_size > 0 && (page_size as usize).is_power_of_two() {
            page_size as usize
        } else {
            UNIX_FALLBACK_PAGE_GRANULE
        }
    }

    #[cfg(target_os = "windows")]
    #[inline]
    fn platform_page_granule() -> usize {
        let mut info = MaybeUninit::<SystemInfo>::zeroed();
        // SAFETY: `GetSystemInfo` initializes the provided `SYSTEM_INFO`
        // structure according to the Windows ABI.
        unsafe {
            GetSystemInfo(info.as_mut_ptr());
            let page_size = info.assume_init().page_size as usize;
            if page_size != 0 && page_size.is_power_of_two() {
                page_size
            } else {
                WINDOWS_FALLBACK_PAGE_GRANULE
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn syscall_failed(ret: isize) -> bool {
        (-4095..=-1).contains(&ret)
    }

    #[cfg(target_os = "linux")]
    fn syscall_error(operation: MemoryLockOperation, ret: isize) -> MemoryLockError {
        MemoryLockError {
            operation,
            errno: (-ret) as i32,
        }
    }

    #[cfg(target_os = "windows")]
    fn windows_error(operation: MemoryLockOperation) -> MemoryLockError {
        // SAFETY: `GetLastError` takes no arguments and returns the calling
        // thread's last-error code.
        let errno = unsafe { GetLastError() } as i32;
        MemoryLockError { operation, errno }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    const fn unix_error(operation: MemoryLockOperation) -> MemoryLockError {
        MemoryLockError {
            operation,
            errno: 0,
        }
    }

    #[cfg(target_os = "linux")]
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

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    fn map_private(len: usize) -> Result<NonNull<u8>, MemoryLockError> {
        // SAFETY: Arguments request a new private anonymous read/write mapping.
        let ptr = unsafe {
            mmap(
                core::ptr::null_mut(),
                len,
                (PROT_READ | PROT_WRITE) as i32,
                (MAP_PRIVATE | MAP_ANONYMOUS) as i32,
                -1,
                0,
            )
        };

        if ptr as isize == -1 {
            return Err(unix_error(MemoryLockOperation::Map));
        }

        NonNull::new(ptr.cast::<u8>()).ok_or(MemoryLockError {
            operation: MemoryLockOperation::Map,
            errno: 0,
        })
    }

    #[cfg(target_os = "windows")]
    fn map_private(len: usize) -> Result<NonNull<u8>, MemoryLockError> {
        // SAFETY: Arguments request a new private committed/reserved read/write
        // region owned by this process.
        let ptr = unsafe {
            VirtualAlloc(
                core::ptr::null_mut(),
                len,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        NonNull::new(ptr.cast::<u8>()).ok_or_else(|| windows_error(MemoryLockOperation::Map))
    }

    #[cfg(target_os = "linux")]
    fn lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
        let ret = raw_syscall2(SYS_MLOCK, ptr.as_ptr() as usize, len);
        if syscall_failed(ret) {
            Err(syscall_error(MemoryLockOperation::Lock, ret))
        } else {
            Ok(())
        }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    fn lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
        // SAFETY: `ptr` and `len` describe a live mapping owned by this value.
        let ret = unsafe { mlock(ptr.as_ptr().cast::<c_void>(), len) };
        if ret != 0 {
            Err(unix_error(MemoryLockOperation::Lock))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "windows")]
    fn lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
        // SAFETY: `ptr` and `len` describe a live region owned by this value.
        let ret = unsafe { VirtualLock(ptr.as_ptr().cast::<c_void>(), len) };
        if ret == 0 {
            Err(windows_error(MemoryLockOperation::Lock))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn mark_dontdump(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
        let ret = raw_syscall3(SYS_MADVISE, ptr.as_ptr() as usize, len, MADV_DONTDUMP);
        if syscall_failed(ret) {
            Err(syscall_error(MemoryLockOperation::DontDump, ret))
        } else {
            Ok(())
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[inline]
    fn mark_dontdump(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn mark_dontfork(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
        let ret = raw_syscall3(SYS_MADVISE, ptr.as_ptr() as usize, len, MADV_DONTFORK);
        if syscall_failed(ret) {
            Err(syscall_error(MemoryLockOperation::DontFork, ret))
        } else {
            Ok(())
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[inline]
    fn mark_dontfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
        let ret = raw_syscall2(SYS_MUNLOCK, ptr.as_ptr() as usize, len);
        if syscall_failed(ret) {
            Err(syscall_error(MemoryLockOperation::Unlock, ret))
        } else {
            Ok(())
        }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    fn unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
        // SAFETY: `ptr` and `len` describe a live mapping owned by this value.
        let ret = unsafe { munlock(ptr.as_ptr().cast::<c_void>(), len) };
        if ret != 0 {
            Err(unix_error(MemoryLockOperation::Unlock))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "windows")]
    fn unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
        // SAFETY: `ptr` and `len` describe a live region owned by this value.
        let ret = unsafe { VirtualUnlock(ptr.as_ptr().cast::<c_void>(), len) };
        if ret == 0 {
            Err(windows_error(MemoryLockOperation::Unlock))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn unmap_private(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
        let ret = raw_syscall2(SYS_MUNMAP, ptr.as_ptr() as usize, len);
        if syscall_failed(ret) {
            Err(syscall_error(MemoryLockOperation::Unmap, ret))
        } else {
            Ok(())
        }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    fn unmap_private(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
        // SAFETY: `ptr` and `len` describe a live mapping owned by this value.
        let ret = unsafe { munmap(ptr.as_ptr().cast::<c_void>(), len) };
        if ret != 0 {
            Err(unix_error(MemoryLockOperation::Unmap))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "windows")]
    fn unmap_private(ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
        // SAFETY: `ptr` points to a region allocated by `VirtualAlloc`.
        let ret = unsafe { VirtualFree(ptr.as_ptr().cast::<c_void>(), 0, MEM_RELEASE) };
        if ret == 0 {
            Err(windows_error(MemoryLockOperation::Unmap))
        } else {
            Ok(())
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn raw_syscall2(number: usize, arg1: usize, arg2: usize) -> isize {
        raw_syscall6(number, arg1, arg2, 0, 0, 0, 0)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
        raw_syscall6(number, arg1, arg2, arg3, 0, 0, 0)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
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

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    fn raw_syscall2(number: usize, arg1: usize, arg2: usize) -> isize {
        raw_syscall6(number, arg1, arg2, 0, 0, 0, 0)
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
        raw_syscall6(number, arg1, arg2, arg3, 0, 0, 0)
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
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
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
pub use memory_lock::{
    LockedSecretBytes, LockedSecretBytesError, LockedSecretBytesGenerateError, MemoryLockError,
    MemoryLockOperation,
};

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
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
#[allow(unsafe_code)]
mod guard_pages {
    use core::{
        fmt,
        ptr::NonNull,
        sync::atomic::{compiler_fence, Ordering},
    };

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    use core::arch::asm;
    #[cfg(not(target_os = "linux"))]
    use core::ffi::c_void;
    #[cfg(target_os = "windows")]
    use core::mem::MaybeUninit;

    // Guard layout must place the writable region on a kernel page boundary.
    // x86_64 Linux uses 4 KiB base pages; aarch64 Linux commonly supports
    // 4 KiB, 16 KiB, and 64 KiB kernels, so 64 KiB is the conservative granule.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const LINUX_PAGE_GRANULE: usize = 4096;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const LINUX_PAGE_GRANULE: usize = 65_536;

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    const UNIX_FALLBACK_PAGE_GRANULE: usize = 4096;

    #[cfg(target_os = "windows")]
    const WINDOWS_FALLBACK_PAGE_GRANULE: usize = 4096;

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    const PROT_NONE: usize = 0x0;
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    const PROT_READ: usize = 0x1;
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    const PROT_WRITE: usize = 0x2;
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    const MAP_PRIVATE: usize = 0x02;
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    const MAP_ANONYMOUS: usize = 0x1000;

    #[cfg(target_os = "linux")]
    const PROT_NONE: usize = 0x0;
    #[cfg(target_os = "linux")]
    const PROT_READ: usize = 0x1;
    #[cfg(target_os = "linux")]
    const PROT_WRITE: usize = 0x2;
    #[cfg(target_os = "linux")]
    const MAP_PRIVATE: usize = 0x02;
    #[cfg(target_os = "linux")]
    const MAP_ANONYMOUS: usize = 0x20;
    #[cfg(feature = "memory-lock")]
    #[cfg(target_os = "linux")]
    const MADV_DONTFORK: usize = 10;
    #[cfg(feature = "memory-lock")]
    #[cfg(target_os = "linux")]
    const MADV_DONTDUMP: usize = 16;

    #[cfg(target_os = "windows")]
    const MEM_COMMIT: u32 = 0x1000;
    #[cfg(target_os = "windows")]
    const MEM_RESERVE: u32 = 0x2000;
    #[cfg(target_os = "windows")]
    const MEM_RELEASE: u32 = 0x8000;
    #[cfg(target_os = "windows")]
    const PAGE_NOACCESS: u32 = 0x01;
    #[cfg(target_os = "windows")]
    const PAGE_READWRITE: u32 = 0x04;

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const SYS_MMAP: usize = 9;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const SYS_MPROTECT: usize = 10;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const SYS_MUNMAP: usize = 11;
    #[cfg(all(feature = "memory-lock", target_os = "linux", target_arch = "x86_64"))]
    const SYS_MADVISE: usize = 28;
    #[cfg(all(feature = "memory-lock", target_os = "linux", target_arch = "x86_64"))]
    const SYS_MLOCK: usize = 149;
    #[cfg(all(feature = "memory-lock", target_os = "linux", target_arch = "x86_64"))]
    const SYS_MUNLOCK: usize = 150;

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const SYS_MMAP: usize = 222;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const SYS_MPROTECT: usize = 226;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const SYS_MUNMAP: usize = 215;
    #[cfg(all(feature = "memory-lock", target_os = "linux", target_arch = "aarch64"))]
    const SYS_MADVISE: usize = 233;
    #[cfg(all(feature = "memory-lock", target_os = "linux", target_arch = "aarch64"))]
    const SYS_MLOCK: usize = 228;
    #[cfg(all(feature = "memory-lock", target_os = "linux", target_arch = "aarch64"))]
    const SYS_MUNLOCK: usize = 229;

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    unsafe extern "C" {
        fn getpagesize() -> i32;
        fn mmap(
            addr: *mut c_void,
            len: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: isize,
        ) -> *mut c_void;
        fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
        fn munmap(addr: *mut c_void, len: usize) -> i32;
        #[cfg(feature = "memory-lock")]
        fn mlock(addr: *const c_void, len: usize) -> i32;
        #[cfg(feature = "memory-lock")]
        fn munlock(addr: *const c_void, len: usize) -> i32;
    }

    #[cfg(target_os = "windows")]
    #[repr(C)]
    struct SystemInfo {
        processor_architecture: u16,
        reserved: u16,
        page_size: u32,
        minimum_application_address: *mut c_void,
        maximum_application_address: *mut c_void,
        active_processor_mask: usize,
        number_of_processors: u32,
        processor_type: u32,
        allocation_granularity: u32,
        processor_level: u16,
        processor_revision: u16,
    }

    #[cfg(target_os = "windows")]
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLastError() -> u32;
        fn GetSystemInfo(system_info: *mut SystemInfo);
        fn VirtualAlloc(
            address: *mut c_void,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut c_void;
        fn VirtualFree(address: *mut c_void, size: usize, free_type: u32) -> i32;
        fn VirtualProtect(
            address: *mut c_void,
            size: usize,
            new_protect: u32,
            old_protect: *mut u32,
        ) -> i32;
        #[cfg(feature = "memory-lock")]
        fn VirtualLock(address: *mut c_void, size: usize) -> i32;
        #[cfg(feature = "memory-lock")]
        fn VirtualUnlock(address: *mut c_void, size: usize) -> i32;
    }

    /// Platform guard-page operation that failed.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum GuardPageOperation {
        /// Requested length arithmetic overflowed.
        Length,
        /// Anonymous mapping creation failed.
        Map,
        /// Data-page protection update failed.
        Protect,
        /// Core-dump exclusion failed.
        DontDump,
        /// Fork inheritance exclusion failed.
        DontFork,
        /// Page locking failed.
        Lock,
        /// Page unlocking failed.
        Unlock,
        /// Anonymous mapping release failed.
        Unmap,
    }

    /// Error returned by guarded secret allocation operations.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct GuardPageError {
        /// Operation that failed.
        pub operation: GuardPageOperation,
        /// Positive errno or Windows `GetLastError` value when available.
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

    /// Error returned when fallible guarded byte generation fails.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum GuardedSecretVecGenerateError<E> {
        /// Guarded mapping setup, protection, locking, unlocking, or unmapping
        /// failed before generation completed.
        Guard(GuardPageError),
        /// The caller-provided byte generator failed.
        Generate(E),
    }

    impl<E: fmt::Display> fmt::Display for GuardedSecretVecGenerateError<E> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Guard(error) => error.fmt(formatter),
                Self::Generate(error) => error.fmt(formatter),
            }
        }
    }

    #[cfg(feature = "std")]
    impl<E> std::error::Error for GuardedSecretVecGenerateError<E>
    where
        E: std::error::Error + 'static,
    {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Guard(error) => Some(error),
                Self::Generate(error) => Some(error),
            }
        }
    }

    impl<E> From<GuardPageError> for GuardedSecretVecGenerateError<E> {
        #[inline]
        fn from(error: GuardPageError) -> Self {
            Self::Guard(error)
        }
    }

    /// Dynamic secret bytes stored between inaccessible platform guard pages.
    ///
    /// This type is available with the `guard-pages` feature on supported
    /// Linux, macOS, Windows, and BSD targets. Secret bytes live in private
    /// platform mappings. The pages immediately before and after the writable
    /// data region remain inaccessible, so linear overreads or overwrites past
    /// the mapped data region fault instead of reaching unrelated memory.
    ///
    /// The secret bytes are not allocated with the Rust global allocator.
    pub struct GuardedSecretVec {
        base: NonNull<u8>,
        data: NonNull<u8>,
        map_len: usize,
        data_capacity: usize,
        len: usize,
        locked: bool,
    }

    // SAFETY: The value exclusively owns a private guarded mapping. Moving
    // ownership to another thread does not invalidate the mapping, and
    // mutation/clearing still requires `&mut self`. `Sync` is intentionally not
    // implemented.
    unsafe impl Send for GuardedSecretVec {}

    impl GuardedSecretVec {
        /// Create an empty guarded secret buffer with at least `capacity` bytes
        /// of writable data space.
        pub fn with_capacity(capacity: usize) -> Result<Self, GuardPageError> {
            Self::with_capacity_locked_state(capacity, false)
        }

        /// Create an empty guarded secret buffer and lock its writable data
        /// pages with the platform memory-locking backend.
        ///
        /// This constructor is available when both `guard-pages` and
        /// `memory-lock` are enabled. Locking can fail due to operating-system
        /// resource limits or policy. Core-dump and fork-inheritance exclusion
        /// can fail if the kernel rejects the requested `madvise` policies. On
        /// failure, the mapping is unmapped before the error is returned. Guard
        /// pages are not locked because they never contain secret bytes.
        #[cfg(feature = "memory-lock")]
        pub fn locked_with_capacity(capacity: usize) -> Result<Self, GuardPageError> {
            Self::with_capacity_locked_state(capacity, true)
        }

        fn with_capacity_locked_state(
            capacity: usize,
            locked: bool,
        ) -> Result<Self, GuardPageError> {
            let page_granule = platform_page_granule();
            let data_capacity = rounded_data_len(capacity)?;
            let total_len = data_capacity
                .checked_add(page_granule)
                .and_then(|value| value.checked_add(page_granule))
                .ok_or(GuardPageError {
                    operation: GuardPageOperation::Length,
                    errno: 0,
                })?;

            let base = map_guarded(total_len)?;
            let data_addr = match (base.as_ptr() as usize).checked_add(page_granule) {
                Some(address) => address,
                None => {
                    let _ = unmap_guarded(base, total_len);
                    return Err(GuardPageError {
                        operation: GuardPageOperation::Length,
                        errno: 0,
                    });
                }
            };
            let data = match NonNull::new(data_addr as *mut u8) {
                Some(data) => data,
                None => {
                    let _ = unmap_guarded(base, total_len);
                    return Err(GuardPageError {
                        operation: GuardPageOperation::Map,
                        errno: 0,
                    });
                }
            };

            if let Err(error) = protect_data(data, data_capacity) {
                let _ = unmap_guarded(base, total_len);
                return Err(error);
            }

            #[cfg(feature = "memory-lock")]
            if locked {
                if let Err(error) = mark_dontdump(data, data_capacity) {
                    let _ = unmap_guarded(base, total_len);
                    return Err(error);
                }

                if let Err(error) = mark_dontfork(data, data_capacity) {
                    let _ = unmap_guarded(base, total_len);
                    return Err(error);
                }

                if let Err(error) = lock_mapping(data, data_capacity) {
                    let _ = unmap_guarded(base, total_len);
                    return Err(error);
                }
            }

            Ok(Self {
                base,
                data,
                map_len: total_len,
                data_capacity,
                len: 0,
                locked,
            })
        }

        /// Create a guarded secret buffer by copying bytes from a slice.
        pub fn from_slice(bytes: &[u8]) -> Result<Self, GuardPageError> {
            let mut secret = Self::with_capacity(bytes.len())?;
            secret.as_mut_capacity_slice()[..bytes.len()].copy_from_slice(bytes);
            secret.finish_initialization(bytes.len());
            Ok(secret)
        }

        /// Create a guarded secret buffer by writing generated bytes directly
        /// into the guarded mapping.
        ///
        /// This avoids staging dynamically generated secret bytes in an
        /// ordinary intermediate allocation before they enter guarded storage.
        pub fn from_fn(
            len: usize,
            mut make_byte: impl FnMut(usize) -> u8,
        ) -> Result<Self, GuardPageError> {
            let mut secret = Self::with_capacity(len)?;
            secret.fill_from_fn(len, &mut make_byte);
            Ok(secret)
        }

        /// Create a guarded secret buffer by fallibly writing generated bytes
        /// directly into the guarded mapping.
        ///
        /// If generation fails, any bytes already written into the guarded
        /// mapping are cleared before the error is returned.
        pub fn try_from_fn<E>(
            len: usize,
            mut make_byte: impl FnMut(usize) -> Result<u8, E>,
        ) -> Result<Self, GuardedSecretVecGenerateError<E>> {
            let mut secret = Self::with_capacity(len)?;
            secret
                .fill_from_try_fn(len, &mut make_byte)
                .map_err(GuardedSecretVecGenerateError::Generate)?;
            Ok(secret)
        }

        /// Create a guarded and memory-locked secret buffer by copying bytes
        /// from a slice.
        ///
        /// The writable data pages are locked before bytes are copied into
        /// them. OS-specific dump or fork-exclusion policies are applied where
        /// the backend supports them.
        #[cfg(feature = "memory-lock")]
        pub fn locked_from_slice(bytes: &[u8]) -> Result<Self, GuardPageError> {
            let mut secret = Self::locked_with_capacity(bytes.len())?;
            secret.as_mut_capacity_slice()[..bytes.len()].copy_from_slice(bytes);
            secret.finish_initialization(bytes.len());
            Ok(secret)
        }

        /// Create a guarded and memory-locked secret buffer by writing
        /// generated bytes directly into the locked guarded mapping.
        ///
        /// The writable data pages are locked before bytes are generated into
        /// them. OS-specific dump or fork-exclusion policies are applied where
        /// the backend supports them.
        #[cfg(feature = "memory-lock")]
        pub fn locked_from_fn(
            len: usize,
            mut make_byte: impl FnMut(usize) -> u8,
        ) -> Result<Self, GuardPageError> {
            let mut secret = Self::locked_with_capacity(len)?;
            secret.fill_from_fn(len, &mut make_byte);
            Ok(secret)
        }

        /// Create a guarded and memory-locked secret buffer by fallibly writing
        /// generated bytes directly into the locked guarded mapping.
        ///
        /// OS-specific dump or fork-exclusion policies are applied where the
        /// backend supports them. If generation fails, partial bytes are
        /// cleared before the error is returned.
        #[cfg(feature = "memory-lock")]
        pub fn locked_try_from_fn<E>(
            len: usize,
            mut make_byte: impl FnMut(usize) -> Result<u8, E>,
        ) -> Result<Self, GuardedSecretVecGenerateError<E>> {
            let mut secret = Self::locked_with_capacity(len)?;
            secret
                .fill_from_try_fn(len, &mut make_byte)
                .map_err(GuardedSecretVecGenerateError::Generate)?;
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

        /// Returns true when this guarded mapping was locked with `mlock`.
        #[must_use]
        #[inline]
        pub const fn is_memory_locked(&self) -> bool {
            self.locked
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

        /// Replace all initialized secret bytes with a new slice.
        ///
        /// If the current guarded mapping is large enough, the old writable
        /// region is cleared before the new bytes are copied in. If the new
        /// value requires a larger mapping, a replacement mapping is allocated
        /// with the same lock state, populated with the new bytes, and then the
        /// old mapping is cleared before it is unmapped.
        pub fn replace_from_slice(&mut self, bytes: &[u8]) -> Result<(), GuardPageError> {
            if bytes.len() > self.data_capacity {
                let mut replacement = Self::with_capacity_locked_state(bytes.len(), self.locked)?;
                replacement.as_mut_capacity_slice()[..bytes.len()].copy_from_slice(bytes);
                replacement.finish_initialization(bytes.len());

                self.clear_secret();
                core::mem::swap(self, &mut replacement);
                return Ok(());
            }

            self.clear_secret();
            self.as_mut_capacity_slice()[..bytes.len()].copy_from_slice(bytes);
            self.finish_initialization(bytes.len());
            Ok(())
        }

        /// Replace all initialized secret bytes with generated bytes.
        ///
        /// A replacement mapping is allocated with the same lock state and
        /// populated before the old mapping is cleared and swapped out.
        pub fn replace_from_fn(
            &mut self,
            len: usize,
            mut make_byte: impl FnMut(usize) -> u8,
        ) -> Result<(), GuardPageError> {
            let mut replacement = Self::with_capacity_locked_state(len, self.locked)?;
            replacement.fill_from_fn(len, &mut make_byte);

            self.clear_secret();
            core::mem::swap(self, &mut replacement);
            Ok(())
        }

        /// Replace all initialized secret bytes with fallibly generated bytes.
        ///
        /// The old guarded value remains unchanged if mapping setup or
        /// generation fails. Any partial generated bytes are cleared when the
        /// replacement mapping is dropped.
        pub fn try_replace_from_fn<E>(
            &mut self,
            len: usize,
            mut make_byte: impl FnMut(usize) -> Result<u8, E>,
        ) -> Result<(), GuardedSecretVecGenerateError<E>> {
            let mut replacement = Self::with_capacity_locked_state(len, self.locked)?;
            replacement
                .fill_from_try_fn(len, &mut make_byte)
                .map_err(GuardedSecretVecGenerateError::Generate)?;

            self.clear_secret();
            core::mem::swap(self, &mut replacement);
            Ok(())
        }

        /// Clear the full writable data region and reset initialized length.
        #[inline(never)]
        pub fn clear_secret(&mut self) {
            crate::wipe::volatile_wipe(self.data.as_ptr(), self.data_capacity);
            self.len = 0;
        }

        /// Consume this value after first clearing the full writable data
        /// region.
        ///
        /// Drop still runs after this method returns, so locked mappings are
        /// unlocked and the guarded mapping is unmapped normally.
        #[inline]
        pub fn into_cleared(mut self) {
            self.clear_secret();
        }

        /// Clear the full writable data region with volatile writes, flush the
        /// cache lines covering that region, and reset initialized length.
        #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
        #[inline(never)]
        pub fn clear_secret_and_flush(&mut self) {
            self.clear_secret();
            crate::cache_flush::flush_cache_lines(self.as_capacity_slice());
        }

        /// Compare against a byte slice without early exit for equal-length
        /// inputs.
        ///
        /// Length mismatch returns immediately because the provided slice length
        /// is treated as public metadata.
        ///
        /// The portable fallback is intended to avoid data-dependent early
        /// exit, but it is not a formal hardware-level constant-time
        /// guarantee. On x86_64, enable `asm-compare` for a stronger compiler
        /// boundary.
        #[must_use]
        #[inline]
        pub fn constant_time_eq(&self, other: &[u8]) -> bool {
            crate::constant_time_eq_slices(self.as_slice(), other)
        }

        fn grow_to(&mut self, required: usize) -> Result<(), GuardPageError> {
            let page_granule = platform_page_granule();
            let next_capacity = self
                .data_capacity
                .saturating_mul(2)
                .max(required)
                .max(page_granule);
            let mut replacement = Self::with_capacity_locked_state(next_capacity, self.locked)?;
            replacement.as_mut_capacity_slice()[..self.len].copy_from_slice(self.as_slice());
            replacement.len = self.len;

            self.clear_secret();
            core::mem::swap(self, &mut replacement);
            Ok(())
        }

        fn fill_from_fn(&mut self, len: usize, make_byte: &mut impl FnMut(usize) -> u8) {
            debug_assert!(len <= self.data_capacity);

            let capacity = self.as_mut_capacity_slice();
            let mut index = 0;
            while index < len {
                capacity[index] = make_byte(index);
                index += 1;
            }

            self.finish_initialization(len);
        }

        fn fill_from_try_fn<E>(
            &mut self,
            len: usize,
            make_byte: &mut impl FnMut(usize) -> Result<u8, E>,
        ) -> Result<(), E> {
            debug_assert!(len <= self.data_capacity);

            let capacity = self.as_mut_capacity_slice();
            let mut index = 0;
            while index < len {
                capacity[index] = make_byte(index)?;
                index += 1;
            }

            self.finish_initialization(len);
            Ok(())
        }

        #[inline]
        fn finish_initialization(&mut self, len: usize) {
            debug_assert!(len <= self.data_capacity);
            self.len = len;
            compiler_fence(Ordering::SeqCst);
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

        #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
        #[inline]
        fn as_capacity_slice(&self) -> &[u8] {
            // SAFETY: `data` points to the live writable data region between
            // guard pages for the duration of `&self`.
            unsafe { core::slice::from_raw_parts(self.data.as_ptr(), self.data_capacity) }
        }
    }

    impl Drop for GuardedSecretVec {
        #[inline]
        fn drop(&mut self) {
            self.clear_secret();
            #[cfg(feature = "memory-lock")]
            if self.locked {
                let _ = unlock_mapping(self.data, self.data_capacity);
            }
            let _ = unmap_guarded(self.base, self.map_len);
        }
    }

    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    impl crate::cache_flush::CacheFlushSanitize for GuardedSecretVec {
        #[inline(never)]
        fn cache_flush_sanitize(&mut self) {
            self.clear_secret_and_flush();
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
                .field("memory_locked", &self.locked)
                .field("contents", &"<redacted>")
                .finish()
        }
    }

    fn rounded_data_len(len: usize) -> Result<usize, GuardPageError> {
        let page_granule = platform_page_granule();
        len.max(1)
            .checked_add(page_granule - 1)
            .map(|value| value & !(page_granule - 1))
            .ok_or(GuardPageError {
                operation: GuardPageOperation::Length,
                errno: 0,
            })
    }

    #[cfg(target_os = "linux")]
    #[inline]
    const fn platform_page_granule() -> usize {
        LINUX_PAGE_GRANULE
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    #[inline]
    fn platform_page_granule() -> usize {
        // SAFETY: `getpagesize` takes no arguments and returns the process page
        // size according to the platform C ABI.
        let page_size = unsafe { getpagesize() };
        if page_size > 0 && (page_size as usize).is_power_of_two() {
            page_size as usize
        } else {
            UNIX_FALLBACK_PAGE_GRANULE
        }
    }

    #[cfg(target_os = "windows")]
    #[inline]
    fn platform_page_granule() -> usize {
        let mut info = MaybeUninit::<SystemInfo>::zeroed();
        // SAFETY: `GetSystemInfo` initializes the provided `SYSTEM_INFO`
        // structure according to the Windows ABI.
        unsafe {
            GetSystemInfo(info.as_mut_ptr());
            let page_size = info.assume_init().page_size as usize;
            if page_size != 0 && page_size.is_power_of_two() {
                page_size
            } else {
                WINDOWS_FALLBACK_PAGE_GRANULE
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn syscall_failed(ret: isize) -> bool {
        (-4095..=-1).contains(&ret)
    }

    #[cfg(target_os = "linux")]
    fn syscall_error(operation: GuardPageOperation, ret: isize) -> GuardPageError {
        GuardPageError {
            operation,
            errno: (-ret) as i32,
        }
    }

    #[cfg(target_os = "windows")]
    fn windows_error(operation: GuardPageOperation) -> GuardPageError {
        // SAFETY: `GetLastError` takes no arguments and returns the calling
        // thread's last-error code.
        let errno = unsafe { GetLastError() } as i32;
        GuardPageError { operation, errno }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    const fn unix_error(operation: GuardPageOperation) -> GuardPageError {
        GuardPageError {
            operation,
            errno: 0,
        }
    }

    #[cfg(target_os = "linux")]
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

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    fn map_guarded(len: usize) -> Result<NonNull<u8>, GuardPageError> {
        // SAFETY: Arguments request a new private anonymous no-access mapping.
        let ptr = unsafe {
            mmap(
                core::ptr::null_mut(),
                len,
                PROT_NONE as i32,
                (MAP_PRIVATE | MAP_ANONYMOUS) as i32,
                -1,
                0,
            )
        };

        if ptr as isize == -1 {
            return Err(unix_error(GuardPageOperation::Map));
        }

        NonNull::new(ptr.cast::<u8>()).ok_or(GuardPageError {
            operation: GuardPageOperation::Map,
            errno: 0,
        })
    }

    #[cfg(target_os = "windows")]
    fn map_guarded(len: usize) -> Result<NonNull<u8>, GuardPageError> {
        // SAFETY: Arguments request a new private committed/reserved no-access
        // region owned by this process.
        let ptr = unsafe {
            VirtualAlloc(
                core::ptr::null_mut(),
                len,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_NOACCESS,
            )
        };

        NonNull::new(ptr.cast::<u8>()).ok_or_else(|| windows_error(GuardPageOperation::Map))
    }

    #[cfg(target_os = "linux")]
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

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    fn protect_data(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        // SAFETY: `ptr` and `len` describe the data region inside a live
        // no-access mapping owned by this value.
        let ret = unsafe {
            mprotect(
                ptr.as_ptr().cast::<c_void>(),
                len,
                (PROT_READ | PROT_WRITE) as i32,
            )
        };
        if ret != 0 {
            Err(unix_error(GuardPageOperation::Protect))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "windows")]
    fn protect_data(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        let mut old_protect = 0_u32;
        // SAFETY: `ptr` and `len` describe the data region inside a live
        // no-access mapping owned by this value.
        let ret = unsafe {
            VirtualProtect(
                ptr.as_ptr().cast::<c_void>(),
                len,
                PAGE_READWRITE,
                &mut old_protect,
            )
        };
        if ret == 0 {
            Err(windows_error(GuardPageOperation::Protect))
        } else {
            Ok(())
        }
    }

    #[cfg(all(feature = "memory-lock", target_os = "linux"))]
    fn lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        let ret = raw_syscall2(SYS_MLOCK, ptr.as_ptr() as usize, len);
        if syscall_failed(ret) {
            Err(syscall_error(GuardPageOperation::Lock, ret))
        } else {
            Ok(())
        }
    }

    #[cfg(all(
        feature = "memory-lock",
        any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
        )
    ))]
    fn lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        // SAFETY: `ptr` and `len` describe a live mapping owned by this value.
        let ret = unsafe { mlock(ptr.as_ptr().cast::<c_void>(), len) };
        if ret != 0 {
            Err(unix_error(GuardPageOperation::Lock))
        } else {
            Ok(())
        }
    }

    #[cfg(all(feature = "memory-lock", target_os = "windows"))]
    fn lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        // SAFETY: `ptr` and `len` describe a live region owned by this value.
        let ret = unsafe { VirtualLock(ptr.as_ptr().cast::<c_void>(), len) };
        if ret == 0 {
            Err(windows_error(GuardPageOperation::Lock))
        } else {
            Ok(())
        }
    }

    #[cfg(all(feature = "memory-lock", target_os = "linux"))]
    fn mark_dontdump(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        let ret = raw_syscall3(SYS_MADVISE, ptr.as_ptr() as usize, len, MADV_DONTDUMP);
        if syscall_failed(ret) {
            Err(syscall_error(GuardPageOperation::DontDump, ret))
        } else {
            Ok(())
        }
    }

    #[cfg(all(feature = "memory-lock", not(target_os = "linux")))]
    #[inline]
    fn mark_dontdump(_ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
        Ok(())
    }

    #[cfg(all(feature = "memory-lock", target_os = "linux"))]
    fn mark_dontfork(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        let ret = raw_syscall3(SYS_MADVISE, ptr.as_ptr() as usize, len, MADV_DONTFORK);
        if syscall_failed(ret) {
            Err(syscall_error(GuardPageOperation::DontFork, ret))
        } else {
            Ok(())
        }
    }

    #[cfg(all(feature = "memory-lock", not(target_os = "linux")))]
    #[inline]
    fn mark_dontfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
        Ok(())
    }

    #[cfg(all(feature = "memory-lock", target_os = "linux"))]
    fn unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        let ret = raw_syscall2(SYS_MUNLOCK, ptr.as_ptr() as usize, len);
        if syscall_failed(ret) {
            Err(syscall_error(GuardPageOperation::Unlock, ret))
        } else {
            Ok(())
        }
    }

    #[cfg(all(
        feature = "memory-lock",
        any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
        )
    ))]
    fn unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        // SAFETY: `ptr` and `len` describe a live mapping owned by this value.
        let ret = unsafe { munlock(ptr.as_ptr().cast::<c_void>(), len) };
        if ret != 0 {
            Err(unix_error(GuardPageOperation::Unlock))
        } else {
            Ok(())
        }
    }

    #[cfg(all(feature = "memory-lock", target_os = "windows"))]
    fn unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        // SAFETY: `ptr` and `len` describe a live region owned by this value.
        let ret = unsafe { VirtualUnlock(ptr.as_ptr().cast::<c_void>(), len) };
        if ret == 0 {
            Err(windows_error(GuardPageOperation::Unlock))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn unmap_guarded(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        let ret = raw_syscall2(SYS_MUNMAP, ptr.as_ptr() as usize, len);
        if syscall_failed(ret) {
            Err(syscall_error(GuardPageOperation::Unmap, ret))
        } else {
            Ok(())
        }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    fn unmap_guarded(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
        // SAFETY: `ptr` and `len` describe a live mapping owned by this value.
        let ret = unsafe { munmap(ptr.as_ptr().cast::<c_void>(), len) };
        if ret != 0 {
            Err(unix_error(GuardPageOperation::Unmap))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "windows")]
    fn unmap_guarded(ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
        // SAFETY: `ptr` points to a region allocated by `VirtualAlloc`.
        let ret = unsafe { VirtualFree(ptr.as_ptr().cast::<c_void>(), 0, MEM_RELEASE) };
        if ret == 0 {
            Err(windows_error(GuardPageOperation::Unmap))
        } else {
            Ok(())
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn raw_syscall2(number: usize, arg1: usize, arg2: usize) -> isize {
        raw_syscall6(number, arg1, arg2, 0, 0, 0, 0)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
        raw_syscall6(number, arg1, arg2, arg3, 0, 0, 0)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
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

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    fn raw_syscall2(number: usize, arg1: usize, arg2: usize) -> isize {
        raw_syscall6(number, arg1, arg2, 0, 0, 0, 0)
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
        raw_syscall6(number, arg1, arg2, arg3, 0, 0, 0)
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
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
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
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

impl<T: SecureSanitize> SecureSanitize for [T] {
    #[inline(never)]
    fn secure_sanitize(&mut self) {
        for item in self.iter_mut() {
            item.secure_sanitize();
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T: SecureSanitize, const N: usize> SecureSanitize for [T; N] {
    #[inline(never)]
    fn secure_sanitize(&mut self) {
        self.as_mut_slice().secure_sanitize();
    }
}

impl<T: SecureSanitize> SecureSanitize for Option<T> {
    #[inline]
    fn secure_sanitize(&mut self) {
        if let Some(value) = self.as_mut() {
            value.secure_sanitize();
        }
        *self = None;
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T: SecureSanitize, E: SecureSanitize> SecureSanitize for Result<T, E> {
    #[inline]
    fn secure_sanitize(&mut self) {
        match self {
            Ok(value) => value.secure_sanitize(),
            Err(error) => error.secure_sanitize(),
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(feature = "alloc")]
impl<T: SecureSanitize + ?Sized> SecureSanitize for Box<T> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.as_mut().secure_sanitize();
    }
}

#[cfg(feature = "alloc")]
impl<T: SecureSanitize> SecureSanitize for Vec<T> {
    #[inline]
    fn secure_sanitize(&mut self) {
        for item in self.iter_mut() {
            item.secure_sanitize();
        }
        self.clear();
        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(feature = "alloc")]
impl SecureSanitize for String {
    #[inline(never)]
    fn secure_sanitize(&mut self) {
        wipe::volatile_wipe(self.as_mut_ptr(), self.capacity());
        self.clear();
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
/// `SecretBytes<N>` stores `N` bytes inline. Closure exposure methods create an
/// additional `N`-byte stack copy, so embedded targets and small thread stacks
/// should choose `N` well below the available stack budget.
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

    /// Create a secret by producing each byte directly with a fallible
    /// generator.
    ///
    /// If `make_byte` returns an error, any bytes generated before the error
    /// are cleared before the error is returned.
    #[inline]
    pub fn try_from_fn<E>(mut make_byte: impl FnMut(usize) -> Result<u8, E>) -> Result<Self, E> {
        let mut secret = Self::zeroed();
        let mut index = 0;
        while index < N {
            match make_byte(index) {
                Ok(byte) => secret.store(index, byte),
                Err(error) => return Err(error),
            }
            index += 1;
        }
        secret.after_secret_write();
        Ok(secret)
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

    /// Replace all bytes from an owned array, then volatile-clear that input
    /// array.
    ///
    /// Prefer this over [`SecretBytes::copy_from_slice`] when the caller has an
    /// owned `[u8; N]` that should be wiped after rotation.
    #[inline]
    pub fn replace_from_array(&mut self, mut bytes: [u8; N]) {
        for (index, byte) in bytes.iter().copied().enumerate() {
            self.store(index, byte);
        }
        self.after_secret_write();
        sanitize_bytes(&mut bytes);
    }

    /// Replace all bytes with generated bytes.
    ///
    /// The new bytes are generated into a fresh clear-on-drop value before the
    /// old value is cleared and replaced. If `make_byte` panics, the old value
    /// remains unchanged and partial generated bytes are cleared during
    /// unwinding.
    #[inline]
    pub fn replace_from_fn(&mut self, make_byte: impl FnMut(usize) -> u8) {
        let mut replacement = Self::from_fn(make_byte);
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
    }

    /// Replace all bytes with generated bytes from a fallible generator.
    ///
    /// The new bytes are generated into a fresh clear-on-drop value before the
    /// old value is cleared and replaced. If `make_byte` returns an error, the
    /// old value remains unchanged and partial generated bytes are cleared
    /// before the error is returned.
    #[inline]
    pub fn try_replace_from_fn<E>(
        &mut self,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), E> {
        let mut replacement = Self::try_from_fn(make_byte)?;
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Mutate the secret bytes in place without creating the additional
    /// stack-copy used by [`SecretBytes::expose_secret`].
    ///
    /// The closure receives direct mutable access to the fixed-size storage
    /// owned by this container. It can still intentionally copy bytes
    /// elsewhere, so keep this API at cryptographic transformation boundaries
    /// such as key derivation, masking, or protocol-specific normalization.
    #[inline]
    pub fn transform(&mut self, edit: impl FnOnce(&mut [u8; N])) {
        edit(&mut self.bytes);
        self.after_secret_write();
    }

    /// Fallible variant of [`SecretBytes::transform`].
    ///
    /// If the closure returns an error after partially mutating the value,
    /// those mutations remain in place. Use [`SecretBytes::try_replace_from_fn`]
    /// when the old value must remain unchanged on error.
    #[inline]
    pub fn try_transform<E>(
        &mut self,
        edit: impl FnOnce(&mut [u8; N]) -> Result<(), E>,
    ) -> Result<(), E> {
        edit(&mut self.bytes)?;
        self.after_secret_write();
        Ok(())
    }

    /// Derive a new fixed-size secret without exposing either buffer through a
    /// temporary stack copy.
    ///
    /// The closure receives read-only access to this secret's storage and
    /// mutable access to the new output secret's storage. This is intended for
    /// KDFs, key hierarchy expansion, and similar operations where the output
    /// should be written directly into a clear-on-drop container.
    #[must_use]
    #[inline]
    pub fn derive<const M: usize>(
        &self,
        derive: impl FnOnce(&[u8; N], &mut [u8; M]),
    ) -> SecretBytes<M> {
        let mut output = SecretBytes::<M>::zeroed();
        derive(&self.bytes, &mut output.bytes);
        output.after_secret_write();
        output
    }

    /// Fallible variant of [`SecretBytes::derive`].
    ///
    /// If derivation fails, the partially written output is dropped and
    /// volatile-cleared before the error is returned.
    #[inline]
    pub fn try_derive<const M: usize, E>(
        &self,
        derive: impl FnOnce(&[u8; N], &mut [u8; M]) -> Result<(), E>,
    ) -> Result<SecretBytes<M>, E> {
        let mut output = SecretBytes::<M>::zeroed();
        derive(&self.bytes, &mut output.bytes)?;
        output.after_secret_write();
        Ok(output)
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
    /// This method creates an additional `N`-byte stack copy. On embedded,
    /// RTOS, or small-thread-stack targets, keep `N` well below the available
    /// stack size or use heap-backed secret containers instead.
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
    ///
    /// Like [`SecretBytes::expose_secret`], this method creates an additional
    /// `N`-byte stack copy.
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
    ///
    /// The portable fallback is intended to avoid data-dependent early exit, but
    /// it is not a formal hardware-level constant-time guarantee. On x86_64,
    /// enable `asm-compare` for a stronger compiler boundary. Use a dedicated
    /// constant-time comparison crate if your protocol requires externally
    /// audited timing guarantees.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        constant_time_eq_slices(self.bytes.as_slice(), other)
    }

    /// Compare against another secret without early exit.
    ///
    /// See [`SecretBytes::constant_time_eq`] for the portable fallback timing
    /// limits.
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

    /// Consume this value after first clearing the fixed-size storage.
    ///
    /// Drop still runs after this method returns, so the storage is cleared a
    /// second time on the normal path.
    #[inline]
    pub fn into_cleared(mut self) {
        self.secure_clear();
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
            Self::Length(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExpiringSecretError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Expired(error) => Some(error),
            Self::Length(error) => Some(error),
        }
    }
}

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

    /// Create an expiring secret by fallibly producing each byte directly.
    ///
    /// If `make_byte` returns an error, any bytes generated before the error
    /// are cleared before the error is returned.
    #[inline]
    pub fn try_from_fn<E>(
        max_age: std::time::Duration,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, E> {
        Ok(Self {
            inner: SecretBytes::try_from_fn(make_byte)?,
            created_at: std::time::Instant::now(),
            max_age,
        })
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

    /// Replace all bytes from an owned array, clear that input array, and
    /// restart the lifetime window.
    ///
    /// If the previous value has already expired, it is cleared before the new
    /// value is copied in.
    #[inline]
    pub fn replace_from_array(&mut self, bytes: [u8; N]) {
        if self.is_expired() {
            self.inner.secure_clear();
        }

        self.inner.replace_from_array(bytes);
        self.created_at = std::time::Instant::now();
    }

    /// Replace all bytes from a generator and restart the lifetime window.
    ///
    /// If the previous value has already expired, it is cleared before the new
    /// value is generated. If `make_byte` panics and the old value was still
    /// live, the old value remains unchanged.
    #[inline]
    pub fn replace_from_fn(&mut self, make_byte: impl FnMut(usize) -> u8) {
        let expired = self.is_expired();
        if expired {
            self.inner.secure_clear();
        }

        let replacement = SecretBytes::from_fn(make_byte);
        if !expired {
            self.inner.secure_clear();
        }
        self.inner = replacement;
        self.created_at = std::time::Instant::now();
    }

    /// Replace all bytes from a fallible generator and restart the lifetime
    /// window.
    ///
    /// If the old value is still live and generation fails, the old value
    /// remains unchanged. If the old value has already expired, it is cleared
    /// before generation and remains cleared if generation fails.
    #[inline]
    pub fn try_replace_from_fn<E>(
        &mut self,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), E> {
        let expired = self.is_expired();
        if expired {
            self.inner.secure_clear();
        }

        let replacement = SecretBytes::try_from_fn(make_byte)?;
        if !expired {
            self.inner.secure_clear();
        }
        self.inner = replacement;
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

    /// Run a closure with a temporary array copy if the secret has not expired.
    ///
    /// This is the expiring variant of [`SecretBytes::expose_secret_volatile`].
    #[inline]
    pub fn try_expose_secret_volatile<R>(
        &mut self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, SecretExpiredError> {
        self.enforce_live()?;
        Ok(self.inner.expose_secret_volatile(inspect))
    }

    /// Compare against a slice if the secret has not expired.
    ///
    /// Length mismatch remains public metadata and returns `Ok(false)`.
    ///
    /// This delegates to [`SecretBytes::constant_time_eq`]; see that method for
    /// portable fallback timing limits.
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

    /// Consume this value after first clearing the wrapped secret.
    ///
    /// Drop still runs after this method returns, so the wrapped storage is
    /// cleared a second time on the normal path.
    #[inline]
    pub fn into_cleared(mut self) {
        self.secure_clear();
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

    /// Wrap an existing vector using volatile clearing on drop.
    ///
    /// This is an explicit ownership-taking alias for [`SecretVec::new`]. The
    /// vector is not copied; its full capacity will be volatile-cleared when
    /// this `SecretVec` is cleared or dropped.
    #[must_use]
    #[inline]
    pub const fn from_vec(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
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

    /// Create a secret vector by generating each byte directly into a
    /// clear-on-drop allocation.
    ///
    /// If `make_byte` panics, any bytes generated before the panic are still
    /// owned by a `SecretVec` local and are cleared during unwinding.
    #[must_use]
    #[inline]
    pub fn from_fn(len: usize, mut make_byte: impl FnMut(usize) -> u8) -> Self {
        let mut secret = Self::with_capacity(len);
        let mut index = 0;
        while index < len {
            secret.inner.push(make_byte(index));
            index += 1;
        }
        secret
    }

    /// Create a secret vector by generating each byte with a fallible
    /// generator.
    ///
    /// If `make_byte` returns an error, any bytes generated before the error
    /// are cleared before the error is returned.
    #[inline]
    pub fn try_from_fn<E>(
        len: usize,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, E> {
        let mut secret = Self::with_capacity(len);
        let mut index = 0;
        while index < len {
            match make_byte(index) {
                Ok(byte) => secret.inner.push(byte),
                Err(error) => return Err(error),
            }
            index += 1;
        }
        Ok(secret)
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

    /// Current allocation capacity in bytes.
    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
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

    /// Replace all bytes with a new slice.
    ///
    /// If capacity must grow, the old allocation is wiped before it is dropped
    /// and the old secret bytes are not copied into the replacement allocation.
    #[inline]
    pub fn replace_from_slice(&mut self, bytes: &[u8]) {
        if bytes.len() > self.inner.capacity() {
            let new_capacity = next_secret_capacity(self.inner.capacity(), bytes.len());
            let mut replacement = Vec::with_capacity(new_capacity);
            replacement.extend_from_slice(bytes);
            self.clear_secret();
            self.inner = replacement;
            return;
        }

        self.clear_secret();
        self.inner.extend_from_slice(bytes);
    }

    /// Replace all bytes by taking ownership of an existing vector.
    ///
    /// The old allocation is cleared before the provided vector becomes the
    /// secret storage. The provided vector is not copied; its full capacity will
    /// be volatile-cleared when this `SecretVec` is later cleared or dropped.
    #[inline]
    pub fn replace_from_vec(&mut self, bytes: Vec<u8>) {
        self.clear_secret();
        self.inner = bytes;
    }

    /// Replace all bytes with generated bytes.
    ///
    /// The new bytes are generated into a fresh clear-on-drop allocation before
    /// the old value is cleared and replaced. If `make_byte` panics, the old
    /// value remains unchanged and partial generated bytes are cleared during
    /// unwinding.
    #[inline]
    pub fn replace_from_fn(&mut self, len: usize, make_byte: impl FnMut(usize) -> u8) {
        let mut replacement = Self::from_fn(len, make_byte);
        self.clear_secret();
        core::mem::swap(&mut self.inner, &mut replacement.inner);
    }

    /// Replace all bytes with generated bytes from a fallible generator.
    ///
    /// The new bytes are generated into a fresh clear-on-drop allocation before
    /// the old value is cleared and replaced. If `make_byte` returns an error,
    /// the old value remains unchanged and partial generated bytes are cleared
    /// before the error is returned.
    #[inline]
    pub fn try_replace_from_fn<E>(
        &mut self,
        len: usize,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), E> {
        let mut replacement = Self::try_from_fn(len, make_byte)?;
        self.clear_secret();
        core::mem::swap(&mut self.inner, &mut replacement.inner);
        Ok(())
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
    ///
    /// The portable fallback is intended to avoid data-dependent early exit, but
    /// it is not a formal hardware-level constant-time guarantee. On x86_64,
    /// enable `asm-compare` for a stronger compiler boundary. Use a dedicated
    /// constant-time comparison crate if your protocol requires externally
    /// audited timing guarantees.
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
impl Default for SecretVec {
    #[inline]
    fn default() -> Self {
        Self::empty()
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

    /// Wrap an existing string using volatile clearing on drop.
    ///
    /// This is an explicit ownership-taking alias for [`SecretString::new`].
    /// The string allocation is not copied; its full capacity will be
    /// volatile-cleared when this `SecretString` is cleared or dropped.
    #[must_use]
    #[inline]
    pub fn from_string(text: String) -> Self {
        Self::new(text)
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

    /// Create a secret string by generating UTF-8 scalar values directly.
    ///
    /// `char_count` is the number of generated `char` values, not the final
    /// byte length. Each generated character is encoded into the secret heap
    /// allocation and the small stack encoding buffer is immediately cleared.
    #[must_use]
    #[inline]
    pub fn from_chars(char_count: usize, mut make_char: impl FnMut(usize) -> char) -> Self {
        let mut secret = Self::with_capacity(max_utf8_capacity(char_count));
        let mut index = 0;
        while index < char_count {
            secret.push_secret_char(make_char(index));
            index += 1;
        }
        secret
    }

    /// Create a secret string by fallibly generating UTF-8 scalar values
    /// directly.
    ///
    /// If `make_char` returns an error, any text generated before the error is
    /// cleared before the error is returned.
    #[inline]
    pub fn try_from_chars<E>(
        char_count: usize,
        mut make_char: impl FnMut(usize) -> Result<char, E>,
    ) -> Result<Self, E> {
        let mut secret = Self::with_capacity(max_utf8_capacity(char_count));
        let mut index = 0;
        while index < char_count {
            match make_char(index) {
                Ok(character) => secret.push_secret_char(character),
                Err(error) => return Err(error),
            }
            index += 1;
        }
        Ok(secret)
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

    /// Current allocation capacity in bytes.
    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Run a closure with read-only access to the secret text.
    ///
    /// The result is fallible because the text is stored internally as bytes to
    /// keep clearing safe without `String::as_mut_vec`.
    #[inline]
    pub fn try_with_secret<R>(&self, inspect: impl FnOnce(&str) -> R) -> Result<R, Utf8Error> {
        core::str::from_utf8(self.inner.as_slice()).map(inspect)
    }

    /// Run a closure with mutable access to the secret text.
    ///
    /// The result is fallible because the text is stored internally as bytes to
    /// keep clearing safe without `String::as_mut_vec`. The closure receives
    /// `&mut str`, so safe Rust cannot invalidate UTF-8.
    #[inline]
    pub fn try_with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut str) -> R,
    ) -> Result<R, Utf8Error> {
        core::str::from_utf8_mut(self.inner.as_mut_slice()).map(edit)
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

    /// Replace all text with a new string slice.
    ///
    /// If capacity must grow, the old allocation is wiped before it is dropped
    /// and the old secret bytes are not copied into the replacement allocation.
    #[inline]
    pub fn replace_from_secret_str(&mut self, text: &str) {
        if text.len() > self.inner.capacity() {
            let new_capacity = next_secret_capacity(self.inner.capacity(), text.len());
            let mut replacement = Vec::with_capacity(new_capacity);
            replacement.extend_from_slice(text.as_bytes());
            self.clear_secret();
            self.inner = replacement;
            return;
        }

        self.clear_secret();
        self.inner.extend_from_slice(text.as_bytes());
    }

    /// Replace all text by taking ownership of an existing string.
    ///
    /// The old allocation is cleared before the provided string allocation
    /// becomes the secret storage. The provided string is not copied; its full
    /// capacity will be volatile-cleared when this `SecretString` is later
    /// cleared or dropped.
    #[inline]
    pub fn replace_from_string(&mut self, text: String) {
        let replacement = text.into_bytes();
        self.clear_secret();
        self.inner = replacement;
    }

    /// Replace all text with generated UTF-8 scalar values.
    ///
    /// The replacement text is generated into a fresh clear-on-drop allocation
    /// before the old value is cleared and replaced. If `make_char` panics, the
    /// old value remains unchanged and partial generated text is cleared during
    /// unwinding.
    #[inline]
    pub fn replace_from_chars(&mut self, char_count: usize, make_char: impl FnMut(usize) -> char) {
        let mut replacement = Self::from_chars(char_count, make_char);
        self.clear_secret();
        core::mem::swap(&mut self.inner, &mut replacement.inner);
    }

    /// Replace all text with fallibly generated UTF-8 scalar values.
    ///
    /// The replacement text is generated into a fresh clear-on-drop allocation
    /// before the old value is cleared and replaced. If `make_char` returns an
    /// error, the old value remains unchanged and partial generated text is
    /// cleared before the error is returned.
    #[inline]
    pub fn try_replace_from_chars<E>(
        &mut self,
        char_count: usize,
        make_char: impl FnMut(usize) -> Result<char, E>,
    ) -> Result<(), E> {
        let mut replacement = Self::try_from_chars(char_count, make_char)?;
        self.clear_secret();
        core::mem::swap(&mut self.inner, &mut replacement.inner);
        Ok(())
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
    ///
    /// The portable fallback is intended to avoid data-dependent early exit, but
    /// it is not a formal hardware-level constant-time guarantee. On x86_64,
    /// enable `asm-compare` for a stronger compiler boundary. Use a dedicated
    /// constant-time comparison crate if your protocol requires externally
    /// audited timing guarantees.
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

    fn push_secret_char(&mut self, character: char) {
        let mut encoded = [0; 4];
        let text = character.encode_utf8(&mut encoded);
        self.inner.extend_from_slice(text.as_bytes());
        sanitize_bytes(&mut encoded);
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
impl Default for SecretString {
    #[inline]
    fn default() -> Self {
        Self::empty()
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
///
/// Scalar values such as `u64`, arrays of sanitizable values, `Option<T>`, and
/// `Result<T, E>` implement [`SecureSanitize`] directly. With `alloc`, `Box<T>`,
/// `Vec<T>`, and `String` are supported as well.
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

impl<T: SecureSanitize + Default> Default for Secret<T> {
    #[inline]
    fn default() -> Self {
        Self::new(T::default())
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

/// Clear-on-drop wrapper that can be consumed exactly once.
///
/// Unlike [`Secret<T>`], the primary accessors take ownership of `self`. That
/// makes repeated reads impossible in safe Rust because the wrapper is moved
/// into the consume method. The wrapped value is cleared immediately after the
/// closure returns, and `Drop` still clears during unwinding or if the wrapper
/// is never consumed.
pub struct ReadOnceSecret<T: SecureSanitize> {
    inner: T,
}

impl<T: SecureSanitize> ReadOnceSecret<T> {
    /// Wrap a sanitizable value for one-time consumption.
    #[must_use]
    #[inline]
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Run a closure with read-only access, then clear the wrapped value.
    ///
    /// This method consumes the wrapper, so the same `ReadOnceSecret` cannot be
    /// accessed again. If the closure unwinds, `Drop` still clears the wrapped
    /// value during unwinding. As with all destructor-based cleanup, process
    /// abort prevents cleanup from running.
    #[inline]
    pub fn consume<R>(mut self, inspect: impl FnOnce(&T) -> R) -> R {
        let result = inspect(&self.inner);
        self.inner.secure_sanitize();
        result
    }

    /// Run a closure with mutable access, then clear the wrapped value.
    ///
    /// This is useful for one-time protocol values that need final in-place
    /// normalization or decoding at the access boundary.
    #[inline]
    pub fn consume_mut<R>(mut self, edit: impl FnOnce(&mut T) -> R) -> R {
        let result = edit(&mut self.inner);
        self.inner.secure_sanitize();
        result
    }

    /// Consume the wrapper after first clearing the wrapped value.
    #[inline]
    pub fn into_cleared(mut self) {
        self.inner.secure_sanitize();
    }
}

impl<T: SecureSanitize> Drop for ReadOnceSecret<T> {
    #[inline]
    fn drop(&mut self) {
        self.inner.secure_sanitize();
    }
}

impl<T: SecureSanitize + Default> Default for ReadOnceSecret<T> {
    #[inline]
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: SecureSanitize> SecureSanitize for ReadOnceSecret<T> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.inner.secure_sanitize();
    }
}

impl<T: SecureSanitize> fmt::Debug for ReadOnceSecret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadOnceSecret")
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
    fn length_error_formats_clearly() {
        let error = LengthError {
            expected: 4,
            actual: 2,
        };

        assert_eq!(
            std::format!("{error}"),
            "length mismatch: expected 4 bytes, got 2 bytes"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn expiring_error_exposes_source() {
        let error = ExpiringSecretError::Length(LengthError {
            expected: 4,
            actual: 2,
        });

        assert!(std::error::Error::source(&error).is_some());
    }

    #[cfg(all(
        feature = "std",
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn locked_secret_errors_expose_sources() {
        let length = LockedSecretBytesError::Length(LengthError {
            expected: 4,
            actual: 2,
        });
        let memory = LockedSecretBytesError::Memory(MemoryLockError {
            operation: MemoryLockOperation::Lock,
            errno: 12,
        });
        let generated: LockedSecretBytesGenerateError<std::io::Error> =
            LockedSecretBytesGenerateError::Generate(std::io::Error::other("generation failed"));

        assert!(std::error::Error::source(&length).is_some());
        assert!(std::error::Error::source(&memory).is_some());
        assert!(std::error::Error::source(&generated).is_some());
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn locked_secret_bytes_is_send() {
        fn assert_send<T: Send>() {}

        assert_send::<LockedSecretBytes<4>>();
    }

    #[cfg(all(
        feature = "std",
        feature = "guard-pages",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn guarded_secret_errors_expose_sources() {
        let guarded: GuardedSecretVecGenerateError<std::io::Error> =
            GuardedSecretVecGenerateError::Guard(GuardPageError {
                operation: GuardPageOperation::Protect,
                errno: 13,
            });
        let generated: GuardedSecretVecGenerateError<std::io::Error> =
            GuardedSecretVecGenerateError::Generate(std::io::Error::other("generation failed"));

        assert!(std::error::Error::source(&guarded).is_some());
        assert!(std::error::Error::source(&generated).is_some());
    }

    #[cfg(all(
        feature = "guard-pages",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn guarded_secret_vec_is_send() {
        fn assert_send<T: Send>() {}

        assert_send::<GuardedSecretVec>();
    }

    #[test]
    fn secret_bytes_round_trip_and_clear() {
        let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);
        let mut out = [0; 4];

        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [1, 2, 3, 4]);

        secret.secure_clear();
        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [0, 0, 0, 0]);

        secret.into_cleared();
    }

    #[test]
    fn secret_bytes_can_initialize_from_fallible_fn() {
        let mut secret =
            SecretBytes::<4>::try_from_fn(|index| Ok::<u8, &'static str>((index as u8) + 1))
                .unwrap();

        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));
        assert_eq!(
            SecretBytes::<4>::try_from_fn(|index| {
                if index == 2 {
                    Err("generation failed")
                } else {
                    Ok(index as u8)
                }
            })
            .err(),
            Some("generation failed")
        );

        secret.secure_clear();
        assert!(secret.constant_time_eq(&[0, 0, 0, 0]));
    }

    #[test]
    fn secret_bytes_can_replace_from_fn() {
        let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);

        secret.replace_from_array([4, 3, 2, 1]);
        assert!(secret.constant_time_eq(&[4, 3, 2, 1]));

        secret.replace_from_fn(|index| (index as u8) + 7);
        assert!(secret.constant_time_eq(&[7, 8, 9, 10]));

        assert_eq!(
            secret.try_replace_from_fn(|index| {
                if index == 2 {
                    Err("generation failed")
                } else {
                    Ok(index as u8)
                }
            }),
            Err("generation failed")
        );
        assert!(secret.constant_time_eq(&[7, 8, 9, 10]));

        secret
            .try_replace_from_fn(|index| Ok::<u8, &'static str>((index as u8) + 1))
            .unwrap();
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        secret.secure_clear();
    }

    #[test]
    fn secret_bytes_can_transform_in_place() {
        let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);

        secret.transform(|bytes| {
            for byte in bytes.iter_mut() {
                *byte ^= 0xFF;
            }
        });

        assert!(secret.constant_time_eq(&[254, 253, 252, 251]));

        assert_eq!(
            secret.try_transform(|bytes| {
                bytes[0] = 7;
                Ok::<(), &'static str>(())
            }),
            Ok(())
        );
        assert!(secret.constant_time_eq(&[7, 253, 252, 251]));
    }

    #[test]
    fn secret_bytes_can_derive_new_secret() {
        let secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);

        let derived = secret.derive::<8>(|input, output| {
            output[..4].copy_from_slice(input);
            output[4..].copy_from_slice(input);
        });

        assert!(derived.constant_time_eq(&[1, 2, 3, 4, 1, 2, 3, 4]));

        let fallible = secret
            .try_derive::<2, _>(|input, output| {
                output.copy_from_slice(&input[..2]);
                Ok::<(), &'static str>(())
            })
            .unwrap();

        assert!(fallible.constant_time_eq(&[1, 2]));
        assert_eq!(
            secret
                .try_derive::<2, _>(|_input, output| {
                    output[0] = 9;
                    Err::<(), &'static str>("derive failed")
                })
                .err(),
            Some("derive failed")
        );
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
        assert_eq!(
            secret.try_expose_secret_volatile(|bytes| bytes[1].wrapping_add(bytes[2])),
            Ok(5)
        );
        assert_eq!(secret.try_constant_time_eq(&[1, 2, 3, 4]), Ok(true));

        secret.into_cleared();
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

        secret.replace_from_array([8, 7, 6, 5]);
        assert_eq!(secret.try_copy_to_slice(&mut out), Ok(()));
        assert_eq!(out, [8, 7, 6, 5]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn expiring_secret_can_initialize_from_fallible_fn() {
        let mut secret =
            ExpiringSecretBytes::<4>::try_from_fn(std::time::Duration::from_secs(60), |index| {
                Ok::<u8, &'static str>((index as u8) + 1)
            })
            .unwrap();
        let mut out = [0; 4];

        assert_eq!(secret.try_copy_to_slice(&mut out), Ok(()));
        assert_eq!(out, [1, 2, 3, 4]);

        assert_eq!(
            ExpiringSecretBytes::<4>::try_from_fn(std::time::Duration::from_secs(60), |index| {
                if index == 2 {
                    Err("generation failed")
                } else {
                    Ok(index as u8)
                }
            })
            .err(),
            Some("generation failed")
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn expiring_secret_can_replace_from_fn() {
        let mut secret =
            ExpiringSecretBytes::<4>::from_array([1, 2, 3, 4], std::time::Duration::from_secs(60));
        let mut out = [0; 4];

        secret.replace_from_fn(|index| (index as u8) + 7);
        assert_eq!(secret.try_copy_to_slice(&mut out), Ok(()));
        assert_eq!(out, [7, 8, 9, 10]);

        assert_eq!(
            secret.try_replace_from_fn(|index| {
                if index == 2 {
                    Err("generation failed")
                } else {
                    Ok(index as u8)
                }
            }),
            Err("generation failed")
        );
        assert_eq!(secret.try_copy_to_slice(&mut out), Ok(()));
        assert_eq!(out, [7, 8, 9, 10]);

        secret
            .try_replace_from_fn(|index| Ok::<u8, &'static str>((index as u8) + 1))
            .unwrap();
        assert_eq!(secret.try_copy_to_slice(&mut out), Ok(()));
        assert_eq!(out, [1, 2, 3, 4]);
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
    fn generic_secret_default_wraps_default_value() {
        let mut secret = Secret::<[u8; 4]>::default();

        assert_eq!(secret.with_secret(|bytes| *bytes), [0; 4]);
        secret.with_secret_mut(|bytes| bytes[0] = 7);
        assert_eq!(secret.with_secret(|bytes| bytes[0]), 7);
    }

    #[test]
    fn read_once_secret_consumes_by_value() {
        let secret = ReadOnceSecret::new(SecretBytes::<4>::from_array([1, 2, 3, 4]));

        let sum = secret.consume(|bytes| {
            let mut out = [0; 4];
            bytes.copy_to_slice(&mut out).unwrap();
            out.iter().copied().fold(0_u8, u8::wrapping_add)
        });

        assert_eq!(sum, 10);
    }

    #[test]
    fn read_once_secret_allows_mutable_finalization() {
        let secret = ReadOnceSecret::new([1_u8, 2, 3, 4]);

        let first = secret.consume_mut(|bytes| {
            bytes[0] = 9;
            bytes[0]
        });

        assert_eq!(first, 9);
    }

    #[test]
    fn read_once_secret_default_and_debug_are_safe() {
        let secret = ReadOnceSecret::<[u8; 4]>::default();
        let rendered = std::format!("{secret:?}");

        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("[0, 0, 0, 0]"));
    }

    #[test]
    fn scalar_values_implement_secure_sanitize() {
        let mut unsigned = Secret::new(0xDEAD_BEEF_u64);
        let mut signed = Secret::new(-42_i32);
        let mut flag = Secret::new(true);
        let mut float = Secret::new(12.5_f64);

        unsigned.with_secret_mut(SecureSanitize::secure_sanitize);
        signed.with_secret_mut(SecureSanitize::secure_sanitize);
        flag.with_secret_mut(SecureSanitize::secure_sanitize);
        float.with_secret_mut(SecureSanitize::secure_sanitize);

        assert_eq!(unsigned.with_secret(|value| *value), 0);
        assert_eq!(signed.with_secret(|value| *value), 0);
        assert!(!flag.with_secret(|value| *value));
        assert_eq!(float.with_secret(|value| value.to_bits()), 0);
    }

    #[test]
    fn compound_standard_types_implement_secure_sanitize() {
        let mut array = [1_u64, 2, 3, 4];
        let mut optional = Some([9_u8, 8, 7, 6]);
        let mut result = Ok::<[u8; 2], [u8; 2]>([5, 4]);

        array.secure_sanitize();
        optional.secure_sanitize();
        result.secure_sanitize();

        assert_eq!(array, [0; 4]);
        assert_eq!(optional, None);
        assert_eq!(result, Ok([0, 0]));
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
        let mut secret = SecretVec::from_vec(std::vec![1, 2, 3]);

        assert_eq!(secret.with_secret(|bytes| bytes.len()), 3);
        assert!(secret.constant_time_eq(&[1, 2, 3]));
        assert!(!secret.constant_time_eq(&[1, 2]));
        secret.extend_from_slice(&[4]);
        assert_eq!(secret.with_secret(|bytes| bytes[3]), 4);

        secret.clear_secret();
        assert!(secret.is_empty());

        secret.into_cleared();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_default_is_empty() {
        let mut secret = SecretVec::default();

        assert!(secret.is_empty());
        secret.extend_from_slice(&[1, 2, 3]);
        assert!(secret.constant_time_eq(&[1, 2, 3]));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_can_initialize_from_fn() {
        let mut secret = SecretVec::from_fn(4, |index| (index as u8) + 1);

        assert_eq!(secret.len(), 4);
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        secret.clear_secret();
        assert!(secret.is_empty());

        secret.into_cleared();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_can_initialize_from_fallible_fn() {
        let mut secret =
            SecretVec::try_from_fn(4, |index| Ok::<u8, &'static str>((index as u8) + 1)).unwrap();

        assert_eq!(secret.len(), 4);
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));
        assert_eq!(
            SecretVec::try_from_fn(4, |index| {
                if index == 2 {
                    Err("generation failed")
                } else {
                    Ok(index as u8)
                }
            })
            .err(),
            Some("generation failed")
        );

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_can_replace_secret() {
        let mut secret = SecretVec::with_capacity(8);
        secret.extend_from_slice(&[1, 2, 3, 4]);

        assert!(secret.capacity() >= 8);

        secret.replace_from_slice(&[9, 8]);

        assert_eq!(secret.len(), 2);
        assert!(secret.constant_time_eq(&[9, 8]));

        let larger = [7_u8; 64];
        secret.replace_from_slice(&larger);

        assert_eq!(secret.len(), larger.len());
        assert_eq!(secret.with_secret(|bytes| (bytes[0], bytes[63])), (7, 7));

        secret.replace_from_vec(std::vec![4, 5, 6]);
        assert_eq!(secret.len(), 3);
        assert!(secret.constant_time_eq(&[4, 5, 6]));

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_can_replace_from_fn() {
        let mut secret = SecretVec::from_slice(&[1, 2, 3, 4]);

        secret.replace_from_fn(3, |index| (index as u8) + 7);

        assert_eq!(secret.len(), 3);
        assert!(secret.constant_time_eq(&[7, 8, 9]));

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            secret.replace_from_fn(4, |index| {
                if index == 2 {
                    panic!("intentional generator panic");
                }
                index as u8
            });
        }));

        assert!(result.is_err());
        assert!(secret.constant_time_eq(&[7, 8, 9]));

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_try_replace_from_fn_preserves_old_secret_on_error() {
        let mut secret = SecretVec::from_slice(&[1, 2, 3, 4]);

        secret
            .try_replace_from_fn(3, |index| Ok::<u8, &'static str>((index as u8) + 7))
            .unwrap();

        assert!(secret.constant_time_eq(&[7, 8, 9]));
        assert_eq!(
            secret
                .try_replace_from_fn(4, |index| {
                    if index == 2 {
                        Err("generation failed")
                    } else {
                        Ok(index as u8)
                    }
                })
                .err(),
            Some("generation failed")
        );
        assert!(secret.constant_time_eq(&[7, 8, 9]));

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
        let mut secret = SecretString::from_string(std::string::String::from("secret"));

        assert_eq!(secret.try_with_secret(|text| text.len()), Ok(6));
        secret.push_str("-token");
        assert_eq!(
            secret.try_with_secret(|text| text.ends_with("token")),
            Ok(true)
        );
        assert_eq!(
            secret.try_with_secret_mut(|text| text.make_ascii_uppercase()),
            Ok(())
        );
        assert!(secret.constant_time_eq("SECRET-TOKEN"));
        assert!(!secret.constant_time_eq("secret-token"));
        assert_eq!(
            secret.try_with_secret_mut(|text| text.make_ascii_lowercase()),
            Ok(())
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
    fn secret_string_default_is_empty() {
        let mut secret = SecretString::default();

        assert!(secret.is_empty());
        secret.push_str("secret");
        assert!(secret.constant_time_eq("secret"));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_string_can_replace_secret() {
        let mut secret = SecretString::with_capacity(8);
        secret.push_str("secret");

        assert!(secret.capacity() >= 8);

        secret.replace_from_secret_str("rotated");

        assert_eq!(secret.len(), 7);
        assert!(secret.constant_time_eq("rotated"));

        let larger = "larger-rotated-secret";
        secret.replace_from_secret_str(larger);

        assert_eq!(secret.len(), larger.len());
        assert_eq!(secret.try_with_secret(|text| text == larger), Ok(true));

        secret.replace_from_string(std::string::String::from("owned-token"));
        assert_eq!(
            secret.try_with_secret(|text| text == "owned-token"),
            Ok(true)
        );

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_string_can_initialize_from_chars() {
        let mut secret = SecretString::from_chars(4, |index| match index {
            0 => 's',
            1 => 'e',
            2 => 'c',
            _ => '\u{1F512}',
        });

        assert_eq!(
            secret.try_with_secret(|text| text == "sec\u{1F512}"),
            Ok(true)
        );
        assert_eq!(secret.len(), "sec\u{1F512}".len());

        assert_eq!(
            SecretString::try_from_chars(4, |index| {
                if index == 2 {
                    Err("generation failed")
                } else {
                    Ok('x')
                }
            })
            .err(),
            Some("generation failed")
        );

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_string_can_replace_from_chars() {
        let mut secret = SecretString::from_secret_str("secret");

        secret.replace_from_chars(3, |index| match index {
            0 => 'k',
            1 => 'e',
            _ => 'y',
        });
        assert!(secret.constant_time_eq("key"));

        assert_eq!(
            secret
                .try_replace_from_chars(4, |index| {
                    if index == 2 {
                        Err("generation failed")
                    } else {
                        Ok('z')
                    }
                })
                .err(),
            Some("generation failed")
        );
        assert!(secret.constant_time_eq("key"));

        secret
            .try_replace_from_chars(2, |index| {
                Ok::<char, &'static str>(if index == 0 { '\u{00F8}' } else { 'k' })
            })
            .unwrap();
        assert_eq!(secret.try_with_secret(|text| text == "\u{00F8}k"), Ok(true));

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

    #[cfg(feature = "alloc")]
    #[test]
    fn alloc_standard_types_implement_secure_sanitize() {
        let mut boxed = std::boxed::Box::new([1_u64, 2, 3]);
        let mut values = std::vec![7_u32, 8, 9];
        let mut text = std::string::String::from("secret");

        boxed.secure_sanitize();
        values.secure_sanitize();
        text.secure_sanitize();

        assert_eq!(*boxed, [0; 3]);
        assert!(values.is_empty());
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

        secret.into_cleared();
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn locked_secret_bytes_can_load_from_slice() {
        let mut secret = LockedSecretBytes::<4>::from_slice(&[1, 2, 3, 4]).unwrap();
        let mut out = [0; 4];

        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [1, 2, 3, 4]);
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        assert_eq!(
            LockedSecretBytes::<4>::from_slice(&[1, 2]).err(),
            Some(LockedSecretBytesError::Length(LengthError {
                expected: 4,
                actual: 2,
            }))
        );

        secret.secure_clear();
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn locked_secret_bytes_can_initialize_from_fn() {
        let mut secret = LockedSecretBytes::<4>::from_fn(|index| (index as u8) + 1).unwrap();
        let mut out = [0; 4];

        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [1, 2, 3, 4]);
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        secret.secure_clear();
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn locked_secret_bytes_can_initialize_from_fallible_fn() {
        let mut secret = match LockedSecretBytes::<4>::try_from_fn(|index| {
            Ok::<u8, &'static str>((index as u8) + 1)
        }) {
            Ok(secret) => secret,
            Err(LockedSecretBytesGenerateError::Memory(_)) => return,
            Err(LockedSecretBytesGenerateError::Generate(error)) => {
                panic!("unexpected generator error: {error}")
            }
        };
        let mut out = [0; 4];

        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [1, 2, 3, 4]);
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        match LockedSecretBytes::<4>::try_from_fn(|index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        }) {
            Ok(_) => panic!("generation should have failed"),
            Err(LockedSecretBytesGenerateError::Memory(_)) => return,
            Err(LockedSecretBytesGenerateError::Generate(error)) => {
                assert_eq!(error, "generation failed");
            }
        }

        secret.secure_clear();
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn locked_secret_bytes_can_replace_secret() {
        let mut secret = match LockedSecretBytes::<4>::from_array([1, 2, 3, 4]) {
            Ok(secret) => secret,
            Err(_) => return,
        };
        let mut out = [0; 4];

        if let Err(LockedSecretBytesError::Memory(_)) = secret.replace_from_slice(&[9, 8, 7, 6]) {
            return;
        }
        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [9, 8, 7, 6]);

        if secret.replace_from_array([6, 7, 8, 9]).is_err() {
            return;
        }
        assert!(secret.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [6, 7, 8, 9]);

        assert_eq!(
            secret.replace_from_slice(&[1, 2]).err(),
            Some(LockedSecretBytesError::Length(LengthError {
                expected: 4,
                actual: 2,
            }))
        );
        assert!(secret.constant_time_eq(&[6, 7, 8, 9]));

        if secret.replace_from_fn(|index| (index as u8) + 1).is_err() {
            return;
        }
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        match secret.try_replace_from_fn(|index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        }) {
            Ok(_) => panic!("generation should have failed"),
            Err(LockedSecretBytesGenerateError::Memory(_)) => return,
            Err(LockedSecretBytesGenerateError::Generate(error)) => {
                assert_eq!(error, "generation failed");
            }
        }
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        match secret.try_replace_from_fn(|index| Ok::<u8, &'static str>((index as u8) + 7)) {
            Ok(()) => {}
            Err(LockedSecretBytesGenerateError::Memory(_)) => return,
            Err(LockedSecretBytesGenerateError::Generate(error)) => {
                panic!("unexpected generator error: {error}")
            }
        }
        assert!(secret.constant_time_eq(&[7, 8, 9, 10]));

        secret.secure_clear();
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
        assert!(!secret.is_memory_locked());
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

        secret.into_cleared();
    }

    #[cfg(all(
        feature = "guard-pages",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn guarded_secret_vec_can_replace_secret() {
        let mut secret = GuardedSecretVec::from_slice(&[1, 2, 3, 4]).unwrap();
        let original_capacity = secret.capacity();

        secret.replace_from_slice(&[9, 8]).unwrap();

        assert_eq!(secret.len(), 2);
        assert_eq!(secret.capacity(), original_capacity);
        assert!(secret.constant_time_eq(&[9, 8]));

        let larger = [7_u8; 70_000];
        secret.replace_from_slice(&larger).unwrap();

        assert_eq!(secret.len(), larger.len());
        assert!(secret.capacity() >= larger.len());
        assert_eq!(
            secret.with_secret(|bytes| (bytes[0], bytes[69_999])),
            (7, 7)
        );

        secret.clear_secret();
    }

    #[cfg(all(
        feature = "guard-pages",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn guarded_secret_vec_can_replace_from_fn() {
        let mut secret = GuardedSecretVec::from_slice(&[1, 2, 3, 4]).unwrap();

        secret
            .replace_from_fn(3, |index| (index as u8) + 7)
            .unwrap();

        assert_eq!(secret.len(), 3);
        assert!(secret.constant_time_eq(&[7, 8, 9]));

        assert_eq!(
            secret
                .try_replace_from_fn(4, |index| {
                    if index == 2 {
                        Err("generation failed")
                    } else {
                        Ok(index as u8)
                    }
                })
                .err(),
            Some(GuardedSecretVecGenerateError::Generate("generation failed"))
        );
        assert!(secret.constant_time_eq(&[7, 8, 9]));

        secret
            .try_replace_from_fn(4, |index| Ok::<u8, &'static str>((index as u8) + 1))
            .unwrap();

        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(all(
        feature = "guard-pages",
        feature = "cache-flush",
        target_os = "linux",
        target_arch = "x86_64",
        not(miri)
    ))]
    #[test]
    fn guarded_secret_vec_can_clear_and_flush() {
        let mut secret = GuardedSecretVec::from_slice(&[1, 2, 3, 4]).unwrap();

        secret.clear_secret_and_flush();

        assert!(secret.is_empty());
        assert_eq!(secret.with_secret(|bytes| bytes.len()), 0);

        let wrapped = crate::cache_flush::CacheFlushOnDrop::new(
            GuardedSecretVec::from_slice(&[5, 6, 7, 8]).unwrap(),
        );
        assert_eq!(wrapped.with_secret(|secret| secret.len()), 4);
        wrapped.into_cleared();
    }

    #[cfg(all(
        feature = "guard-pages",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn guarded_secret_vec_can_initialize_from_fn() {
        let mut secret = GuardedSecretVec::from_fn(4, |index| (index as u8) + 1).unwrap();

        assert_eq!(secret.len(), 4);
        assert!(!secret.is_memory_locked());
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));
        assert_eq!(secret.with_secret(|bytes| (bytes[0], bytes[3])), (1, 4));

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
    fn guarded_secret_vec_can_initialize_from_fallible_fn() {
        let mut secret =
            GuardedSecretVec::try_from_fn(4, |index| Ok::<u8, &'static str>((index as u8) + 1))
                .unwrap();

        assert_eq!(secret.len(), 4);
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));
        assert_eq!(
            GuardedSecretVec::try_from_fn(4, |index| {
                if index == 2 {
                    Err("generation failed")
                } else {
                    Ok(index as u8)
                }
            })
            .err(),
            Some(GuardedSecretVecGenerateError::Generate("generation failed"))
        );

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(all(
        feature = "guard-pages",
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn guarded_secret_vec_can_be_memory_locked() {
        let mut secret = match GuardedSecretVec::locked_from_slice(&[1, 2, 3]) {
            Ok(secret) => secret,
            Err(GuardPageError {
                operation:
                    GuardPageOperation::DontDump
                    | GuardPageOperation::DontFork
                    | GuardPageOperation::Lock,
                ..
            }) => return,
            Err(error) => panic!("unexpected guarded lock error: {error:?}"),
        };

        assert!(secret.is_memory_locked());
        assert!(secret.constant_time_eq(&[1, 2, 3]));

        secret.extend_from_slice(&[4]).unwrap();

        assert!(secret.is_memory_locked());
        assert_eq!(secret.with_secret(|bytes| (bytes[0], bytes[3])), (1, 4));

        let larger = [9_u8; 5000];
        secret.replace_from_slice(&larger).unwrap();

        assert!(secret.is_memory_locked());
        assert_eq!(secret.len(), larger.len());
        assert_eq!(secret.with_secret(|bytes| (bytes[0], bytes[4999])), (9, 9));

        secret
            .replace_from_fn(4, |index| (index as u8) + 1)
            .unwrap();

        assert!(secret.is_memory_locked());
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        match secret.try_replace_from_fn(4, |index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        }) {
            Ok(_) => panic!("generation should have failed"),
            Err(GuardedSecretVecGenerateError::Generate(error)) => {
                assert_eq!(error, "generation failed");
            }
            Err(GuardedSecretVecGenerateError::Guard(error)) => {
                panic!("unexpected guarded setup error: {error:?}")
            }
        }

        assert!(secret.is_memory_locked());
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(all(
        feature = "guard-pages",
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn guarded_secret_vec_can_initialize_locked_from_fn() {
        let mut secret = match GuardedSecretVec::locked_from_fn(4, |index| (index as u8) + 1) {
            Ok(secret) => secret,
            Err(GuardPageError {
                operation:
                    GuardPageOperation::DontDump
                    | GuardPageOperation::DontFork
                    | GuardPageOperation::Lock,
                ..
            }) => return,
            Err(error) => panic!("unexpected guarded lock error: {error:?}"),
        };

        assert!(secret.is_memory_locked());
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));
        assert_eq!(secret.with_secret(|bytes| (bytes[0], bytes[3])), (1, 4));

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[cfg(all(
        feature = "guard-pages",
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn guarded_secret_vec_can_initialize_locked_from_fallible_fn() {
        let mut secret = match GuardedSecretVec::locked_try_from_fn(4, |index| {
            Ok::<u8, &'static str>((index as u8) + 1)
        }) {
            Ok(secret) => secret,
            Err(GuardedSecretVecGenerateError::Guard(GuardPageError {
                operation:
                    GuardPageOperation::DontDump
                    | GuardPageOperation::DontFork
                    | GuardPageOperation::Lock,
                ..
            })) => return,
            Err(error) => panic!("unexpected guarded generation error: {error:?}"),
        };

        assert!(secret.is_memory_locked());
        assert_eq!(secret.len(), 4);
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        match GuardedSecretVec::locked_try_from_fn(4, |index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        }) {
            Ok(_) => panic!("generation should have failed"),
            Err(GuardedSecretVecGenerateError::Guard(GuardPageError {
                operation:
                    GuardPageOperation::DontDump
                    | GuardPageOperation::DontFork
                    | GuardPageOperation::Lock,
                ..
            })) => return,
            Err(GuardedSecretVecGenerateError::Guard(error)) => {
                panic!("unexpected guarded setup error: {error:?}")
            }
            Err(GuardedSecretVecGenerateError::Generate(error)) => {
                assert_eq!(error, "generation failed");
            }
        }

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
