use core::{
    fmt,
    ptr::NonNull,
    sync::atomic::{compiler_fence, AtomicBool, Ordering},
};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use core::arch::asm;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
use core::ffi::c_int;
#[cfg(not(target_os = "linux"))]
use core::ffi::c_void;
#[cfg(target_os = "windows")]
use core::mem::MaybeUninit;

// Linux x86_64 has 4 KiB base pages for supported targets. Linux aarch64
// is detected at runtime from auxv and falls back to 64 KiB.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const LINUX_PAGE_GRANULE: usize = 4096;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
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
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const PROT_READ: usize = 0x1;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const PROT_WRITE: usize = 0x2;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const MAP_PRIVATE: usize = 0x02;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const MAP_ANONYMOUS: usize = 0x1000;
#[cfg(target_os = "android")]
const MAP_ANONYMOUS: usize = 0x20;
#[cfg(target_os = "freebsd")]
const MADV_NOCORE: i32 = 8;

#[cfg(target_os = "linux")]
const PROT_READ: usize = 0x1;
#[cfg(target_os = "linux")]
const PROT_WRITE: usize = 0x2;
#[cfg(target_os = "linux")]
const MAP_PRIVATE: usize = 0x02;
#[cfg(target_os = "linux")]
const MAP_ANONYMOUS: usize = 0x20;
#[cfg(target_os = "linux")]
const MAP_FD_ANONYMOUS: usize = (-1isize) as usize;
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

#[cfg(feature = "canary-check")]
const CANARY_SIZE: usize = 8;
#[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
const CANARY_MASK: u64 = 0xDEAD_BEEF_CAFE_BABE;

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
    target_os = "ios",
    target_os = "android",
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
    #[cfg(target_os = "freebsd")]
    fn madvise(addr: *mut c_void, len: usize, advice: i32) -> i32;

    #[cfg_attr(
        any(target_os = "macos", target_os = "ios", target_os = "freebsd"),
        link_name = "__error"
    )]
    #[cfg_attr(
        any(target_os = "android", target_os = "openbsd", target_os = "netbsd"),
        link_name = "__errno"
    )]
    #[cfg_attr(target_os = "dragonfly", link_name = "__errno_location")]
    fn errno_location() -> *mut c_int;
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
    /// Operating-system random canary generation failed.
    Random,
}

/// Error returned by platform memory-locking operations.
///
/// If setup and the subsequent cleanup unmap both fail, the returned error
/// reports `Unmap`. A mapping that may still be live takes diagnostic
/// precedence over the original setup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryLockError {
    /// Operation that failed.
    pub operation: MemoryLockOperation,
    /// Positive errno or Windows `GetLastError` value when available.
    ///
    /// This is `0` for local arithmetic failures before a syscall.
    /// Negative values are crate-internal sentinel failures, such as an
    /// unsupported random-canary backend or a random backend that made no
    /// progress.
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

/// Error returned when a checked locked secret detects canary corruption.
#[cfg(feature = "canary-check")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanaryCorruptedError;

#[cfg(feature = "canary-check")]
impl fmt::Display for CanaryCorruptedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("locked secret canary corrupted")
    }
}

#[cfg(all(feature = "canary-check", feature = "std"))]
impl std::error::Error for CanaryCorruptedError {}

/// Error returned by checked locked-secret copy operations.
#[cfg(feature = "canary-check")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockedSecretBytesCheckedCopyError {
    /// The caller provided a destination with the wrong length.
    Length(crate::LengthError),
    /// Prefix or suffix canary verification failed.
    Canary(CanaryCorruptedError),
}

#[cfg(feature = "canary-check")]
impl fmt::Display for LockedSecretBytesCheckedCopyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(error) => error.fmt(formatter),
            Self::Canary(error) => error.fmt(formatter),
        }
    }
}

#[cfg(all(feature = "canary-check", feature = "std"))]
impl std::error::Error for LockedSecretBytesCheckedCopyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Length(error) => Some(error),
            Self::Canary(error) => Some(error),
        }
    }
}

#[cfg(feature = "canary-check")]
impl From<crate::LengthError> for LockedSecretBytesCheckedCopyError {
    #[inline]
    fn from(error: crate::LengthError) -> Self {
        Self::Length(error)
    }
}

#[cfg(feature = "canary-check")]
impl From<CanaryCorruptedError> for LockedSecretBytesCheckedCopyError {
    #[inline]
    fn from(error: CanaryCorruptedError) -> Self {
        Self::Canary(error)
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
/// Linux, Android, macOS, iOS, Windows, and BSD targets. Linux uses raw
/// syscalls with `mmap`, `MADV_DONTDUMP`, `MADV_DONTFORK`, and `mlock`.
/// Android, macOS, iOS, and BSD use system `mmap`/`mlock` entry points.
/// Windows uses `VirtualAlloc`/`VirtualLock`. Every backend volatile-clears
/// the full mapping before unlocking and releasing it.
///
/// With the `canary-check` feature enabled, non-empty locked mappings store
/// an 8-byte prefix canary and 8-byte suffix canary around the secret data.
/// Existing exposure APIs verify those canaries before use and fail closed
/// by clearing the mapping and panicking if corruption is detected. Checked
/// APIs return [`CanaryCorruptedError`] instead.
///
/// The secret bytes are not stored inline in the Rust value. Moving this
/// type only moves pointer metadata, so ordinary Rust moves do not copy the
/// secret byte array itself.
pub struct LockedSecretBytes<const N: usize> {
    ptr: NonNull<u8>,
    map_len: usize,
    #[cfg(feature = "random-canary")]
    canary: [u8; CANARY_SIZE],
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
                #[cfg(feature = "random-canary")]
                canary: [0; CANARY_SIZE],
            });
        }

        #[cfg(feature = "random-canary")]
        let canary = random_canary_value()?;

        let map_len = rounded_mapping_len(Self::mapping_payload_len()?)?;
        let ptr = map_private(map_len)?;

        if let Err(error) = mark_dontdump(ptr, map_len) {
            return Err(unmap_after_setup_error(ptr, map_len, error));
        }

        if let Err(error) = mark_dontfork(ptr, map_len) {
            return Err(unmap_after_setup_error(ptr, map_len, error));
        }

        if let Err(error) = lock_mapping(ptr, map_len) {
            return Err(unmap_after_setup_error(ptr, map_len, error));
        }

        let mut secret = Self {
            ptr,
            map_len,
            #[cfg(feature = "random-canary")]
            canary,
        };
        secret.write_canaries();
        Ok(secret)
    }

    /// Allocate locked storage, copy an array into it, then clear the input
    /// array with the crate's volatile wipe backend.
    #[inline]
    pub fn from_array(mut bytes: [u8; N]) -> Result<Self, MemoryLockError> {
        let mut secret = match Self::zeroed() {
            Ok(secret) => secret,
            Err(error) => {
                crate::wipe::bytes(&mut bytes);
                return Err(error);
            }
        };

        let _ = secret.copy_from_slice(&bytes);
        crate::wipe::bytes(&mut bytes);
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
        compiler_fence(Ordering::SeqCst);
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
        compiler_fence(Ordering::SeqCst);
        let mut index = 0;
        while index < N {
            match make_byte(index) {
                Ok(byte) => secret.as_mut_slice()[index] = byte,
                Err(error) => {
                    secret.secure_clear();
                    return Err(LockedSecretBytesGenerateError::Generate(error));
                }
            }
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        Ok(secret)
    }

    /// Allocate locked storage and fill the full fixed-size payload in
    /// place.
    ///
    /// This is intended for decoder, KDF, RNG, or protocol APIs that can
    /// write into a caller-provided output buffer. The private mapping is
    /// created, dump-excluded, fork-excluded where supported, and locked
    /// before `fill` receives the mutable payload. No intermediate
    /// unlocked `Vec` or stack array is required by this API.
    #[inline]
    pub fn from_fill(fill: impl FnOnce(&mut [u8; N])) -> Result<Self, MemoryLockError> {
        let mut secret = Self::zeroed()?;
        compiler_fence(Ordering::SeqCst);
        fill(secret.as_mut_array());
        compiler_fence(Ordering::SeqCst);
        Ok(secret)
    }

    /// Fallible variant of [`LockedSecretBytes::from_fill`].
    ///
    /// If `fill` returns an error, partial bytes already written into the
    /// locked mapping are volatile-cleared before the error is returned.
    #[inline]
    pub fn try_from_fill<E>(
        fill: impl FnOnce(&mut [u8; N]) -> Result<(), E>,
    ) -> Result<Self, LockedSecretBytesGenerateError<E>> {
        let mut secret = Self::zeroed()?;
        compiler_fence(Ordering::SeqCst);
        if let Err(error) = fill(secret.as_mut_array()) {
            secret.secure_clear();
            return Err(LockedSecretBytesGenerateError::Generate(error));
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

        self.assert_canaries_intact();
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
        self.assert_canaries_intact();
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
        self.assert_canaries_intact();
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
        self.assert_canaries_intact();
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
        self.assert_canaries_intact();
        let mut replacement = Self::try_from_fn(make_byte)?;
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all secret bytes by filling a fresh locked mapping in
    /// place.
    ///
    /// The old locked value remains unchanged if mapping setup fails. If
    /// `fill` panics, the old value also remains unchanged and partial
    /// replacement bytes are cleared during unwinding.
    #[inline]
    pub fn replace_from_fill(
        &mut self,
        fill: impl FnOnce(&mut [u8; N]),
    ) -> Result<(), MemoryLockError> {
        self.assert_canaries_intact();
        let mut replacement = Self::from_fill(fill)?;
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Fallible variant of [`LockedSecretBytes::replace_from_fill`].
    ///
    /// The old locked value remains unchanged if mapping setup or `fill`
    /// fails. Partial replacement bytes are cleared before the error is
    /// returned.
    #[inline]
    pub fn try_replace_from_fill<E>(
        &mut self,
        fill: impl FnOnce(&mut [u8; N]) -> Result<(), E>,
    ) -> Result<(), LockedSecretBytesGenerateError<E>> {
        self.assert_canaries_intact();
        let mut replacement = Self::try_from_fill(fill)?;
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

        self.assert_canaries_intact();
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
    pub fn expose_secret<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.assert_canaries_intact();
        inspect(self.as_array())
    }

    /// Verify integrity, copy into temporary stack storage, and expose the copy.
    ///
    /// The temporary is volatile-cleared on normal return and unwinding. It
    /// cannot be cleared if the process aborts.
    #[inline]
    pub fn expose_secret_copy<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.assert_canaries_intact();
        crate::owned::expose_array_copy(self.as_array(), inspect)
    }

    /// Verify canary integrity before exposing the locked secret bytes.
    ///
    /// This method is available with `canary-check`. If either canary was
    /// corrupted, the full mapping is volatile-cleared before
    /// [`CanaryCorruptedError`] is returned.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn expose_secret_checked<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(inspect(self.as_array()))
    }

    /// Verify canary integrity before exposing a temporary plaintext copy.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn expose_secret_copy_checked<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::owned::expose_array_copy(self.as_array(), inspect))
    }

    /// Verify canary integrity before copying secret bytes out.
    ///
    /// Length mismatch is still reported as [`crate::LengthError`].
    /// Canary corruption is reported separately after the destination length
    /// has been validated.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn copy_to_slice_checked(
        &self,
        destination: &mut [u8],
    ) -> Result<(), LockedSecretBytesCheckedCopyError> {
        if destination.len() != N {
            return Err(crate::LengthError {
                expected: N,
                actual: destination.len(),
            }
            .into());
        }

        self.verify_integrity()?;
        destination.copy_from_slice(self.as_slice());
        compiler_fence(Ordering::SeqCst);
        core::hint::black_box(destination);
        Ok(())
    }

    /// Verify canary integrity before comparing secret bytes.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn constant_time_eq_checked(&self, other: &[u8]) -> Result<bool, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::constant_time_eq_slices(self.as_slice(), other))
    }

    /// Verify locked mapping canaries.
    ///
    /// If corruption is detected, the full mapping is immediately
    /// volatile-cleared because the secret can no longer be trusted.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        if self.canaries_intact() {
            Ok(())
        } else {
            self.clear_after_canary_failure();
            Err(CanaryCorruptedError)
        }
    }

    /// Compare against a slice without early exit for equal-length inputs.
    ///
    /// Length mismatch returns immediately because the provided slice length
    /// is treated as public metadata.
    ///
    /// The portable fallback is intended to avoid data-dependent early
    /// exit, but it is not a formal hardware-level constant-time
    /// guarantee. On x86_64 or AArch64, enable `asm-compare` for a
    /// stronger compiler boundary.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        self.assert_canaries_intact();
        crate::constant_time_eq_slices(self.as_slice(), other)
    }

    /// Clear the full private mapping with volatile writes.
    #[inline(never)]
    pub fn secure_clear(&mut self) {
        if self.map_len != 0 {
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.map_len);
        }
        self.write_canaries();
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
        // SAFETY: `data_ptr` either points to `N` live secret bytes owned
        // by this value, or is dangling with `N == 0`.
        unsafe { core::slice::from_raw_parts(self.data_ptr(), N) }
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
        unsafe { core::slice::from_raw_parts_mut(self.data_ptr(), N) }
    }

    #[inline]
    fn as_mut_array(&mut self) -> &mut [u8; N] {
        // SAFETY: `data_ptr` is valid for exactly `N` payload bytes owned
        // by this value for the duration of `&mut self`.
        unsafe { &mut *(self.data_ptr() as *mut [u8; N]) }
    }

    #[inline]
    fn as_array(&self) -> &[u8; N] {
        // SAFETY: `as_slice` is exactly `N` bytes long, and the pointer is
        // valid for a `[u8; N]` reference for the duration of `&self`.
        unsafe { &*(self.data_ptr() as *const [u8; N]) }
    }

    #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
    #[inline]
    fn canary_value(&self) -> [u8; CANARY_SIZE] {
        ((self.ptr.as_ptr() as u64) ^ CANARY_MASK).to_ne_bytes()
    }

    #[cfg(feature = "random-canary")]
    #[inline]
    fn canary_value(&self) -> [u8; CANARY_SIZE] {
        self.canary
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn canaries_intact(&self) -> bool {
        if self.map_len == 0 {
            return true;
        }

        let Some(suffix_offset) = Self::suffix_offset() else {
            return false;
        };
        let expected = self.canary_value();

        // SAFETY: With `map_len != 0`, construction allocated at least
        // `CANARY_SIZE + N + CANARY_SIZE` bytes before page rounding.
        let prefix = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), CANARY_SIZE) };
        // SAFETY: `suffix_offset` was checked from the same payload layout,
        // so the suffix canary is inside the live mapping.
        let suffix = unsafe {
            core::slice::from_raw_parts(self.ptr.as_ptr().add(suffix_offset), CANARY_SIZE)
        };

        crate::constant_time_eq_slices(prefix, &expected)
            & crate::constant_time_eq_slices(suffix, &expected)
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn write_canaries(&mut self) {
        if self.map_len == 0 {
            return;
        }

        let Some(suffix_offset) = Self::suffix_offset() else {
            return;
        };
        let canary = self.canary_value();

        // SAFETY: With `map_len != 0`, construction allocated at least
        // `CANARY_SIZE + N + CANARY_SIZE` bytes before page rounding.
        unsafe {
            core::ptr::copy_nonoverlapping(canary.as_ptr(), self.ptr.as_ptr(), CANARY_SIZE);
            core::ptr::copy_nonoverlapping(
                canary.as_ptr(),
                self.ptr.as_ptr().add(suffix_offset),
                CANARY_SIZE,
            );
        }
        compiler_fence(Ordering::SeqCst);
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn write_canaries(&mut self) {}

    #[cfg(feature = "canary-check")]
    #[inline]
    fn assert_canaries_intact(&self) {
        if self.verify_integrity().is_err() {
            panic!("locked secret canary corrupted");
        }
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn assert_canaries_intact(&self) {}

    #[cfg(feature = "canary-check")]
    #[inline]
    fn clear_after_canary_failure(&self) {
        if self.map_len != 0 {
            // Fail-closed clearing intentionally mutates the owned mapping
            // through `&self`. `LockedSecretBytes` is `Send` but not
            // `Sync`, so safe code cannot run this concurrently through
            // shared references.
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.map_len);
        }
    }

    #[inline]
    fn data_ptr(&self) -> *mut u8 {
        // SAFETY: `data_offset` is either zero or `CANARY_SIZE`; non-empty
        // canary-checked mappings are allocated with that prefix included.
        unsafe { self.ptr.as_ptr().add(Self::data_offset()) }
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    const fn data_offset() -> usize {
        if N == 0 {
            0
        } else {
            CANARY_SIZE
        }
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    const fn data_offset() -> usize {
        0
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    const fn suffix_offset() -> Option<usize> {
        match CANARY_SIZE.checked_add(N) {
            Some(offset) if N != 0 => Some(offset),
            _ => None,
        }
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn mapping_payload_len() -> Result<usize, MemoryLockError> {
        if N == 0 {
            return Ok(0);
        }

        N.checked_add(CANARY_SIZE.saturating_mul(2))
            .ok_or(MemoryLockError {
                operation: MemoryLockOperation::Length,
                errno: 0,
            })
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn mapping_payload_len() -> Result<usize, MemoryLockError> {
        Ok(N)
    }

    #[cfg(all(test, feature = "canary-check", feature = "std"))]
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn corrupt_prefix_canary_for_test(&mut self) {
        if self.map_len == 0 {
            return;
        }

        // SAFETY: `map_len != 0` means `ptr` points to the live mapping.
        unsafe {
            let byte = self.ptr.as_ptr();
            core::ptr::write(byte, core::ptr::read(byte) ^ 0xFF);
        }
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

impl<const N: usize> crate::StableSharedSecretStorage for LockedSecretBytes<N> {}
impl<const N: usize> crate::StableMutableSecretStorage for LockedSecretBytes<N> {}

impl<const N: usize> fmt::Debug for LockedSecretBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedSecretBytes")
            .field("len", &N)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Dynamic secret bytes stored in a private locked platform mapping.
///
/// Error returned when fallible locked dynamic byte generation fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockedSecretVecGenerateError<E> {
    /// Platform mapping, core-dump exclusion, locking, unlocking, or
    /// unmapping failed before generation completed.
    Memory(MemoryLockError),
    /// The caller-provided byte generator failed.
    Generate(E),
}

impl<E: fmt::Display> fmt::Display for LockedSecretVecGenerateError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(error) => error.fmt(formatter),
            Self::Generate(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for LockedSecretVecGenerateError<E>
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

impl<E> From<MemoryLockError> for LockedSecretVecGenerateError<E> {
    #[inline]
    fn from(error: MemoryLockError) -> Self {
        Self::Memory(error)
    }
}

/// Error returned when in-place locked dynamic byte filling fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockedSecretVecFillError<E> {
    /// Platform memory-locking or mapping setup failed.
    Memory(MemoryLockError),
    /// The fill closure returned an error.
    Fill(E),
    /// The fill closure reported more initialized bytes than capacity.
    Length(crate::LengthError),
}

impl<E: fmt::Display> fmt::Display for LockedSecretVecFillError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(error) => write!(formatter, "{error}"),
            Self::Fill(error) => {
                write!(formatter, "locked dynamic secret fill failed: {error}")
            }
            Self::Length(error) => write!(formatter, "{error}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for LockedSecretVecFillError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::Fill(error) => Some(error),
            Self::Length(error) => Some(error),
        }
    }
}

impl<E> From<MemoryLockError> for LockedSecretVecFillError<E> {
    #[inline]
    fn from(error: MemoryLockError) -> Self {
        Self::Memory(error)
    }
}

impl<E> From<crate::LengthError> for LockedSecretVecFillError<E> {
    #[inline]
    fn from(error: crate::LengthError) -> Self {
        Self::Length(error)
    }
}

/// `LockedSecretVec` fills the gap between [`crate::SecretVec`] and
/// [`crate::GuardedSecretVec`]. It supports runtime-length secret bytes in
/// platform-locked memory without adding guard pages, which keeps memory
/// overhead lower for large PEM/DER material, tokens, or generated secrets
/// where page-fence protection is not required.
pub struct LockedSecretVec {
    ptr: NonNull<u8>,
    map_len: usize,
    data_capacity: usize,
    len: usize,
    #[cfg(feature = "random-canary")]
    canary: [u8; CANARY_SIZE],
}

// SAFETY: The value exclusively owns a private mapping. Moving ownership to
// another thread does not invalidate the mapping, and mutation/clearing
// still requires `&mut self`. `Sync` is intentionally not implemented.
unsafe impl Send for LockedSecretVec {}

impl LockedSecretVec {
    /// Allocate locked dynamic storage with at least `capacity` bytes.
    pub fn with_capacity(capacity: usize) -> Result<Self, MemoryLockError> {
        if capacity == 0 {
            return Ok(Self {
                ptr: NonNull::dangling(),
                map_len: 0,
                data_capacity: 0,
                len: 0,
                #[cfg(feature = "random-canary")]
                canary: [0; CANARY_SIZE],
            });
        }

        #[cfg(feature = "random-canary")]
        let canary = random_canary_value()?;

        let map_len = rounded_mapping_len(Self::mapping_payload_len(capacity)?)?;
        let ptr = map_private(map_len)?;

        if let Err(error) = mark_dontdump(ptr, map_len) {
            return Err(unmap_after_setup_error(ptr, map_len, error));
        }

        if let Err(error) = mark_dontfork(ptr, map_len) {
            return Err(unmap_after_setup_error(ptr, map_len, error));
        }

        if let Err(error) = lock_mapping(ptr, map_len) {
            return Err(unmap_after_setup_error(ptr, map_len, error));
        }

        let mut secret = Self {
            ptr,
            map_len,
            data_capacity: capacity,
            len: 0,
            #[cfg(feature = "random-canary")]
            canary,
        };
        secret.write_canaries();
        Ok(secret)
    }

    /// Create locked dynamic storage by copying bytes from a slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, MemoryLockError> {
        let mut secret = Self::with_capacity(bytes.len())?;
        secret.as_mut_capacity_slice()[..bytes.len()].copy_from_slice(bytes);
        secret.finish_initialization(bytes.len());
        Ok(secret)
    }

    /// Create locked dynamic storage by generating bytes directly into it.
    pub fn from_fn(
        len: usize,
        mut make_byte: impl FnMut(usize) -> u8,
    ) -> Result<Self, MemoryLockError> {
        let mut secret = Self::with_capacity(len)?;
        secret.fill_from_fn(len, &mut make_byte);
        Ok(secret)
    }

    /// Create locked dynamic storage with a fallible byte generator.
    pub fn try_from_fn<E>(
        len: usize,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, LockedSecretVecGenerateError<E>> {
        let mut secret = Self::with_capacity(len)?;
        secret
            .fill_from_try_fn(len, &mut make_byte)
            .map_err(LockedSecretVecGenerateError::Generate)?;
        Ok(secret)
    }

    /// Create locked dynamic storage and fill an exact-length payload in
    /// place.
    ///
    /// This is intended for decoders, KDFs, RNGs, and protocol APIs that
    /// can write into a caller-provided output buffer. The mapping is
    /// created, dump-excluded, fork-excluded where supported, and locked
    /// before `fill` receives the mutable payload. No intermediate
    /// unlocked `Vec` is required by this API.
    pub fn from_exact_len(
        len: usize,
        fill: impl FnOnce(&mut [u8]),
    ) -> Result<Self, MemoryLockError> {
        let mut secret = Self::with_capacity(len)?;
        compiler_fence(Ordering::SeqCst);
        fill(&mut secret.as_mut_capacity_slice()[..len]);
        secret.finish_initialization(len);
        Ok(secret)
    }

    /// Fallible variant of [`LockedSecretVec::from_exact_len`].
    ///
    /// If `fill` returns an error, partial bytes already written into the
    /// locked mapping are volatile-cleared before the error is returned.
    pub fn try_from_exact_len<E>(
        len: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, LockedSecretVecGenerateError<E>> {
        let mut secret = Self::with_capacity(len)?;
        compiler_fence(Ordering::SeqCst);
        if let Err(error) = fill(&mut secret.as_mut_capacity_slice()[..len]) {
            secret.clear_secret();
            return Err(LockedSecretVecGenerateError::Generate(error));
        }
        secret.finish_initialization(len);
        Ok(secret)
    }

    /// Create locked dynamic storage with `capacity` bytes and fill it in
    /// place, returning the number of initialized bytes.
    ///
    /// This is the preferred constructor for base64 or protocol decoders
    /// that can compute a maximum output size before decoding, but only
    /// learn the exact decoded length after writing. If `fill` reports a
    /// length greater than `capacity`, the mapping is cleared and
    /// [`LockedSecretVecFillError::Length`] is returned.
    pub fn from_capacity(
        capacity: usize,
        fill: impl FnOnce(&mut [u8]) -> usize,
    ) -> Result<Self, LockedSecretVecFillError<core::convert::Infallible>> {
        Self::try_from_capacity(capacity, |output| {
            Ok::<usize, core::convert::Infallible>(fill(output))
        })
    }

    /// Fallible variant of [`LockedSecretVec::from_capacity`].
    ///
    /// If `fill` returns an error or reports too many initialized bytes,
    /// partial bytes already written into the locked mapping are
    /// volatile-cleared before the error is returned.
    pub fn try_from_capacity<E>(
        capacity: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, LockedSecretVecFillError<E>> {
        let mut secret = Self::with_capacity(capacity)?;
        compiler_fence(Ordering::SeqCst);
        let len = match fill(secret.as_mut_capacity_slice()) {
            Ok(len) => len,
            Err(error) => {
                secret.clear_secret();
                return Err(LockedSecretVecFillError::Fill(error));
            }
        };
        if len > capacity {
            // Explicit pre-return clear; Drop also wipes on return.
            secret.clear_secret();
            return Err(crate::LengthError {
                expected: capacity,
                actual: len,
            }
            .into());
        }

        if len < capacity {
            let spare = &mut secret.as_mut_capacity_slice()[len..capacity];
            crate::wipe_backend::erase(spare.as_mut_ptr(), spare.len());
        }
        secret.finish_initialization(len);
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

    /// Dynamic payload capacity, excluding canary bytes.
    #[must_use]
    #[inline]
    pub const fn capacity(&self) -> usize {
        self.data_capacity
    }

    /// Length of the underlying locked mapping.
    #[must_use]
    #[inline]
    pub const fn locked_len(&self) -> usize {
        self.map_len
    }

    /// Run a closure with read-only access to initialized secret bytes.
    #[inline]
    pub fn with_secret<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> R {
        self.assert_canaries_intact();
        inspect(self.as_slice())
    }

    /// Run a closure with mutable access to initialized secret bytes.
    #[inline]
    pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut [u8]) -> R) -> R {
        self.assert_canaries_intact();
        edit(self.as_mut_slice())
    }

    /// Verify canary integrity before exposing locked dynamic bytes.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn expose_secret_checked<R>(
        &self,
        inspect: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(inspect(self.as_slice()))
    }

    /// Append bytes, growing into a new locked mapping if needed.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), MemoryLockError> {
        self.assert_canaries_intact();
        let required = self.len.checked_add(bytes.len()).ok_or(MemoryLockError {
            operation: MemoryLockOperation::Length,
            errno: 0,
        })?;

        if required > self.data_capacity {
            self.grow_to(required)?;
        }

        let start = self.len;
        self.as_mut_capacity_slice()[start..required].copy_from_slice(bytes);
        self.finish_initialization(required);
        Ok(())
    }

    /// Replace all initialized bytes from a slice.
    pub fn replace_from_slice(&mut self, bytes: &[u8]) -> Result<(), MemoryLockError> {
        self.assert_canaries_intact();

        if bytes.len() > self.data_capacity {
            let mut replacement = Self::with_capacity(bytes.len())?;
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

    /// Replace all initialized bytes with generated bytes.
    pub fn replace_from_fn(
        &mut self,
        len: usize,
        mut make_byte: impl FnMut(usize) -> u8,
    ) -> Result<(), MemoryLockError> {
        self.assert_canaries_intact();
        let mut replacement = Self::with_capacity(len)?;
        replacement.fill_from_fn(len, &mut make_byte);
        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all initialized bytes with fallibly generated bytes.
    pub fn try_replace_from_fn<E>(
        &mut self,
        len: usize,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), LockedSecretVecGenerateError<E>> {
        self.assert_canaries_intact();
        let mut replacement = Self::with_capacity(len)?;
        replacement
            .fill_from_try_fn(len, &mut make_byte)
            .map_err(LockedSecretVecGenerateError::Generate)?;
        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all initialized bytes by filling an exact-length fresh
    /// locked mapping in place.
    ///
    /// The old locked value remains unchanged if mapping setup fails. If
    /// `fill` panics, the old value also remains unchanged and partial
    /// replacement bytes are cleared during unwinding.
    pub fn replace_from_exact_len(
        &mut self,
        len: usize,
        fill: impl FnOnce(&mut [u8]),
    ) -> Result<(), MemoryLockError> {
        self.assert_canaries_intact();
        let mut replacement = Self::from_exact_len(len, fill)?;
        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Fallible variant of [`LockedSecretVec::replace_from_exact_len`].
    ///
    /// The old locked value remains unchanged if mapping setup or `fill`
    /// fails. Partial replacement bytes are cleared before the error is
    /// returned.
    pub fn try_replace_from_exact_len<E>(
        &mut self,
        len: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<(), LockedSecretVecGenerateError<E>> {
        self.assert_canaries_intact();
        let mut replacement = Self::try_from_exact_len(len, fill)?;
        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all initialized bytes by filling a fresh locked mapping
    /// with `capacity` bytes and returning the actual initialized length.
    ///
    /// The old locked value remains unchanged if mapping setup fails or if
    /// `fill` reports a length greater than `capacity`.
    pub fn replace_from_capacity(
        &mut self,
        capacity: usize,
        fill: impl FnOnce(&mut [u8]) -> usize,
    ) -> Result<(), LockedSecretVecFillError<core::convert::Infallible>> {
        self.try_replace_from_capacity(capacity, |output| {
            Ok::<usize, core::convert::Infallible>(fill(output))
        })
    }

    /// Fallible variant of [`LockedSecretVec::replace_from_capacity`].
    ///
    /// The old locked value remains unchanged if mapping setup, filling, or
    /// length validation fails. Partial replacement bytes are cleared
    /// before the error is returned.
    pub fn try_replace_from_capacity<E>(
        &mut self,
        capacity: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<(), LockedSecretVecFillError<E>> {
        self.assert_canaries_intact();
        let mut replacement = Self::try_from_capacity(capacity, fill)?;
        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Clear the full locked mapping and reset initialized length.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        if self.map_len != 0 {
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.map_len);
        }
        self.len = 0;
        self.write_canaries();
    }

    /// Consume this value after first clearing the full locked mapping.
    #[inline]
    pub fn into_cleared(mut self) {
        self.clear_secret();
    }

    /// Clear the full locked mapping, then flush its cache lines.
    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    #[inline(never)]
    pub fn clear_secret_and_flush(&mut self) {
        self.clear_secret();
        crate::cache_flush::flush_cache_lines(self.as_mapping_slice());
    }

    /// Compare against a byte slice without early exit for equal-length
    /// inputs.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        self.assert_canaries_intact();
        crate::constant_time_eq_slices(self.as_slice(), other)
    }

    /// Verify canary integrity before comparing locked dynamic bytes.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn constant_time_eq_checked(&self, other: &[u8]) -> Result<bool, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::constant_time_eq_slices(self.as_slice(), other))
    }

    /// Verify locked dynamic mapping canaries.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        if self.canaries_intact() {
            Ok(())
        } else {
            self.clear_after_canary_failure();
            Err(CanaryCorruptedError)
        }
    }

    fn grow_to(&mut self, required: usize) -> Result<(), MemoryLockError> {
        self.assert_canaries_intact();
        let next_capacity = self.data_capacity.saturating_mul(2).max(required).max(1);
        let mut replacement = Self::with_capacity(next_capacity)?;
        replacement.as_mut_capacity_slice()[..self.len].copy_from_slice(self.as_slice());
        replacement.finish_initialization(self.len);
        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    fn fill_from_fn(&mut self, len: usize, make_byte: &mut impl FnMut(usize) -> u8) {
        assert!(
            len <= self.data_capacity,
            "locked dynamic secret length exceeds capacity"
        );
        compiler_fence(Ordering::SeqCst);
        let capacity = self.as_mut_capacity_slice();
        let mut index = 0;
        while index < len {
            capacity[index] = make_byte(index);
            index += 1;
        }
        self.finish_initialization(len);
    }

    /// Fill a fresh or throwaway dynamic mapping.
    ///
    /// On error, clears all bytes written so far and resets the mapping
    /// before returning. Callers that propagate the error may still run
    /// `Drop`, causing a harmless second clear of already-zeroed storage.
    fn fill_from_try_fn<E>(
        &mut self,
        len: usize,
        make_byte: &mut impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), E> {
        assert!(
            len <= self.data_capacity,
            "locked dynamic secret length exceeds capacity"
        );
        compiler_fence(Ordering::SeqCst);
        let mut index = 0;
        while index < len {
            let byte = match make_byte(index) {
                Ok(byte) => byte,
                Err(error) => {
                    self.clear_secret();
                    return Err(error);
                }
            };
            self.as_mut_capacity_slice()[index] = byte;
            index += 1;
        }
        self.finish_initialization(len);
        Ok(())
    }

    #[inline]
    fn finish_initialization(&mut self, len: usize) {
        assert!(
            len <= self.data_capacity,
            "locked dynamic secret length exceeds capacity"
        );
        self.len = len;
        self.write_canaries();
        compiler_fence(Ordering::SeqCst);
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        // SAFETY: `payload_ptr` points to `data_capacity` writable payload
        // bytes owned by this value, and `len <= data_capacity`.
        unsafe { core::slice::from_raw_parts(self.payload_ptr(), self.len) }
    }

    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` gives exclusive access and `len <=
        // data_capacity`.
        unsafe { core::slice::from_raw_parts_mut(self.payload_ptr(), self.len) }
    }

    #[inline]
    fn as_mut_capacity_slice(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` gives exclusive access to the full payload
        // capacity inside the locked mapping.
        unsafe { core::slice::from_raw_parts_mut(self.payload_ptr(), self.data_capacity) }
    }

    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    #[inline]
    fn as_mapping_slice(&self) -> &[u8] {
        // SAFETY: `ptr` points to this value's live mapping, or is
        // dangling with `map_len == 0`.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.map_len) }
    }

    #[inline]
    fn payload_ptr(&self) -> *mut u8 {
        if self.map_len == 0 {
            return self.ptr.as_ptr();
        }

        // SAFETY: `payload_offset` is zero or the prefix canary size and
        // remains inside non-empty mappings.
        unsafe { self.ptr.as_ptr().add(Self::payload_offset()) }
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    const fn payload_offset() -> usize {
        CANARY_SIZE
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    const fn payload_offset() -> usize {
        0
    }

    #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
    #[inline]
    fn canary_value(&self) -> [u8; CANARY_SIZE] {
        ((self.ptr.as_ptr() as u64) ^ CANARY_MASK).to_ne_bytes()
    }

    #[cfg(feature = "random-canary")]
    #[inline]
    fn canary_value(&self) -> [u8; CANARY_SIZE] {
        self.canary
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn canaries_intact(&self) -> bool {
        if self.map_len == 0 {
            return true;
        }

        let expected = self.canary_value();
        // SAFETY: non-empty canary-checked dynamic mappings reserve prefix
        // and suffix canary regions around initialized bytes.
        let prefix = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), CANARY_SIZE) };
        // SAFETY: `len <= data_capacity`, so the suffix at prefix + len is
        // inside the allocated payload plus suffix region.
        let suffix = unsafe {
            core::slice::from_raw_parts(self.ptr.as_ptr().add(CANARY_SIZE + self.len), CANARY_SIZE)
        };

        crate::constant_time_eq_slices(prefix, &expected)
            & crate::constant_time_eq_slices(suffix, &expected)
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn write_canaries(&mut self) {
        if self.map_len == 0 {
            return;
        }

        let canary = self.canary_value();
        // SAFETY: non-empty canary-checked dynamic mappings reserve prefix
        // and suffix canary regions around initialized bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(canary.as_ptr(), self.ptr.as_ptr(), CANARY_SIZE);
            core::ptr::copy_nonoverlapping(
                canary.as_ptr(),
                self.ptr.as_ptr().add(CANARY_SIZE + self.len),
                CANARY_SIZE,
            );
        }
        compiler_fence(Ordering::SeqCst);
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn write_canaries(&mut self) {}

    #[cfg(feature = "canary-check")]
    #[inline]
    fn assert_canaries_intact(&self) {
        if self.verify_integrity().is_err() {
            panic!("locked dynamic secret canary corrupted");
        }
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn assert_canaries_intact(&self) {}

    #[cfg(feature = "canary-check")]
    #[inline]
    fn clear_after_canary_failure(&self) {
        if self.map_len != 0 {
            // Fail-closed clearing intentionally mutates the owned mapping
            // through `&self`. `LockedSecretVec` is `Send` but not `Sync`.
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.map_len);
        }
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn mapping_payload_len(capacity: usize) -> Result<usize, MemoryLockError> {
        capacity
            .checked_add(CANARY_SIZE.saturating_mul(2))
            .ok_or(MemoryLockError {
                operation: MemoryLockOperation::Length,
                errno: 0,
            })
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn mapping_payload_len(capacity: usize) -> Result<usize, MemoryLockError> {
        Ok(capacity)
    }

    #[cfg(all(test, feature = "canary-check", feature = "std"))]
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn corrupt_prefix_canary_for_test(&mut self) {
        if self.map_len == 0 {
            return;
        }

        // SAFETY: `map_len != 0` means `ptr` points to the live mapping.
        unsafe {
            let byte = self.ptr.as_ptr();
            core::ptr::write(byte, core::ptr::read(byte) ^ 0xFF);
        }
    }
}

impl Drop for LockedSecretVec {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
        if self.map_len != 0 {
            let _ = unlock_mapping(self.ptr, self.map_len);
            let _ = unmap_private(self.ptr, self.map_len);
        }
    }
}

impl crate::SecureSanitize for LockedSecretVec {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

impl fmt::Debug for LockedSecretVec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedSecretVec")
            .field("len", &self.len)
            .field("capacity", &self.data_capacity)
            .field("locked_len", &self.map_len)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Fixed-slot arena for many same-size secrets inside one locked mapping.
///
/// `SecretPool<N, SLOTS>` amortizes platform memory-locking overhead when
/// an application needs many fixed-size secrets at once. Instead of using
/// one locked page-backed mapping per secret, the pool creates one private
/// locked mapping large enough for `SLOTS` slots of `N` bytes and hands out
/// lifetime-bound [`SecretPoolSlot`] handles.
///
/// Slots borrow the pool, so Rust prevents the pool from being dropped
/// while a slot is still live. Dropping a slot volatile-clears exactly that
/// slot and returns it to the pool. Dropping the pool volatile-clears the
/// full mapping before unlocking and releasing it.
pub struct SecretPool<const N: usize, const SLOTS: usize> {
    base: NonNull<u8>,
    map_len: usize,
    slot_stride: usize,
    used: [AtomicBool; SLOTS],
}

/// A live fixed-size secret slot allocated from a [`SecretPool`].
///
/// The slot gives controlled access to one `N`-byte region inside the
/// parent pool. Moving the slot moves only pointer metadata; the secret
/// bytes stay inside the locked pool mapping.
pub struct SecretPoolSlot<'pool, const N: usize, const SLOTS: usize> {
    ptr: NonNull<u8>,
    slot_index: usize,
    pool: &'pool SecretPool<N, SLOTS>,
    #[cfg(feature = "random-canary")]
    canary: [u8; CANARY_SIZE],
}

// SAFETY: The pool owns one private mapping. Slot allocation state is
// coordinated with atomics, and mutable byte access is possible only
// through a uniquely-owned slot handle or `&mut self`.
unsafe impl<const N: usize, const SLOTS: usize> Send for SecretPool<N, SLOTS> {}
// SAFETY: Shared pool references may allocate different slots concurrently.
// The atomic bitmap prevents two live safe handles for the same slot.
unsafe impl<const N: usize, const SLOTS: usize> Sync for SecretPool<N, SLOTS> {}
// SAFETY: Moving a slot to another thread transfers the unique live handle
// for that slot. The borrowed pool remains live for the slot lifetime.
unsafe impl<'pool, const N: usize, const SLOTS: usize> Send for SecretPoolSlot<'pool, N, SLOTS> {}

impl<const N: usize, const SLOTS: usize> SecretPool<N, SLOTS> {
    /// Create a locked pool with `SLOTS` fixed-size slots of `N` bytes.
    ///
    /// This performs one platform mapping and one platform lock operation
    /// for the whole arena. The requested mapping length is rounded to the
    /// platform page granule, so the pool also clears padding bytes on
    /// drop.
    #[inline]
    pub fn new() -> Result<Self, MemoryLockError> {
        let used = core::array::from_fn(|_| AtomicBool::new(false));
        let slot_stride = Self::slot_stride()?;
        let total_bytes = slot_stride.checked_mul(SLOTS).ok_or(MemoryLockError {
            operation: MemoryLockOperation::Length,
            errno: 0,
        })?;

        if total_bytes == 0 {
            return Ok(Self {
                base: NonNull::dangling(),
                map_len: 0,
                slot_stride,
                used,
            });
        }

        let map_len = rounded_mapping_len(total_bytes)?;
        let base = map_private(map_len)?;

        if let Err(error) = mark_dontdump(base, map_len) {
            return Err(unmap_after_setup_error(base, map_len, error));
        }

        if let Err(error) = mark_dontfork(base, map_len) {
            return Err(unmap_after_setup_error(base, map_len, error));
        }

        if let Err(error) = lock_mapping(base, map_len) {
            return Err(unmap_after_setup_error(base, map_len, error));
        }

        Ok(Self {
            base,
            map_len,
            slot_stride,
            used,
        })
    }

    /// Number of bytes in each slot.
    #[must_use]
    #[inline]
    pub const fn slot_size(&self) -> usize {
        N
    }

    /// Number of slots in the pool.
    #[must_use]
    #[inline]
    pub const fn capacity_slots(&self) -> usize {
        SLOTS
    }

    /// Returns true when the pool cannot hold any secret bytes.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0 || SLOTS == 0
    }

    /// Rounded platform mapping length locked by this pool.
    #[must_use]
    #[inline]
    pub const fn locked_len(&self) -> usize {
        self.map_len
    }

    /// Count slots that are currently available.
    ///
    /// This is a point-in-time observation. Other threads may allocate or
    /// release slots immediately after this method returns.
    #[must_use]
    #[inline]
    pub fn available_slots(&self) -> usize {
        self.used
            .iter()
            .filter(|used| !used.load(Ordering::Acquire))
            .count()
    }

    /// Allocate one unused slot from the pool.
    ///
    /// Returns `None` when every slot is currently allocated. The returned
    /// slot starts zeroed if it has never been used before, or freshly
    /// zeroed from the previous slot drop.
    ///
    /// With `random-canary`, operating-system CSPRNG failure is also
    /// reported as `None`. Use [`SecretPool::try_allocate`] when the caller
    /// needs to distinguish pool exhaustion from random-canary setup
    /// failure.
    #[must_use = "CSPRNG failure also returns None; use try_allocate() to distinguish failures from exhaustion"]
    #[inline]
    pub fn allocate(&self) -> Option<SecretPoolSlot<'_, N, SLOTS>> {
        self.try_allocate().unwrap_or_default()
    }

    /// Allocate one unused slot from the pool and report random-canary
    /// setup errors explicitly.
    ///
    /// This is equivalent to [`SecretPool::allocate`] unless the
    /// `random-canary` feature is enabled. With `random-canary`, operating
    /// system CSPRNG failure is returned as [`MemoryLockError`] instead of
    /// panicking.
    #[inline]
    pub fn try_allocate(&self) -> Result<Option<SecretPoolSlot<'_, N, SLOTS>>, MemoryLockError> {
        for (slot_index, flag) in self.used.iter().enumerate() {
            if flag
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                let ptr = match self.slot_ptr(slot_index) {
                    Some(ptr) => ptr,
                    None => {
                        flag.store(false, Ordering::Release);
                        continue;
                    }
                };
                let mut slot = SecretPoolSlot {
                    ptr,
                    slot_index,
                    pool: self,
                    #[cfg(feature = "random-canary")]
                    canary: [0; CANARY_SIZE],
                };
                if let Err(error) = slot.initialize_canaries() {
                    drop(slot);
                    return Err(error);
                }
                return Ok(Some(slot));
            }
        }

        Ok(None)
    }

    /// Allocate a slot and copy bytes from a same-length slice.
    ///
    /// Returns `Ok(None)` when the pool is full. A length mismatch returns
    /// an error without allocating a slot.
    #[inline]
    pub fn allocate_from_slice(
        &self,
        source: &[u8],
    ) -> Result<Option<SecretPoolSlot<'_, N, SLOTS>>, crate::LengthError> {
        if source.len() != N {
            return Err(crate::LengthError {
                expected: N,
                actual: source.len(),
            });
        }

        let Some(mut slot) = self.allocate() else {
            return Ok(None);
        };

        let _ = slot.copy_from_slice(source);
        Ok(Some(slot))
    }

    /// Allocate a slot, copy an owned array into it, then clear the input
    /// array with the crate's volatile wipe backend.
    #[inline]
    pub fn allocate_from_array(&self, mut bytes: [u8; N]) -> Option<SecretPoolSlot<'_, N, SLOTS>> {
        let slot = match self.allocate() {
            Some(mut slot) => {
                let _ = slot.copy_from_slice(&bytes);
                Some(slot)
            }
            None => None,
        };

        crate::wipe::bytes(&mut bytes);
        slot
    }

    /// Allocate a slot and generate each byte directly inside it.
    #[inline]
    pub fn allocate_from_fn(
        &self,
        mut make_byte: impl FnMut(usize) -> u8,
    ) -> Option<SecretPoolSlot<'_, N, SLOTS>> {
        let mut slot = self.allocate()?;
        let mut index = 0;
        while index < N {
            slot.as_mut_slice()[index] = make_byte(index);
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        Some(slot)
    }

    /// Allocate a slot and fallibly generate each byte directly inside it.
    ///
    /// If generation fails, the partially initialized slot is
    /// volatile-cleared and returned to the pool before the error is
    /// returned.
    #[inline]
    pub fn try_allocate_from_fn<E>(
        &self,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Option<SecretPoolSlot<'_, N, SLOTS>>, E> {
        let Some(mut slot) = self.allocate() else {
            return Ok(None);
        };

        let mut index = 0;
        while index < N {
            let byte = make_byte(index)?;
            slot.as_mut_slice()[index] = byte;
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        Ok(Some(slot))
    }

    /// Clear the full locked mapping and mark every slot available.
    ///
    /// This requires `&mut self`, so Rust prevents it while any live slot
    /// handle still borrows the pool.
    #[inline(never)]
    pub fn secure_clear(&mut self) {
        if self.map_len != 0 {
            crate::wipe_backend::erase(self.base.as_ptr(), self.map_len);
        }

        for flag in self.used.iter() {
            flag.store(false, Ordering::Release);
        }
        compiler_fence(Ordering::SeqCst);
    }

    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    #[inline(never)]
    pub fn secure_clear_and_flush(&mut self) {
        self.secure_clear();
        crate::cache_flush::flush_cache_lines(self.as_mapping_slice());
    }

    #[inline]
    fn slot_ptr(&self, slot_index: usize) -> Option<NonNull<u8>> {
        if N == 0 {
            return Some(NonNull::dangling());
        }

        let offset = slot_index.checked_mul(self.slot_stride)?;
        // SAFETY: `slot_index < SLOTS`, construction checked the total
        // slot-stride size, and `map_len` is rounded up from that total.
        // Therefore `offset` is inside the live mapping for all allocated
        // non-zero slots.
        NonNull::new(unsafe { self.base.as_ptr().add(offset) })
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn slot_stride() -> Result<usize, MemoryLockError> {
        if N == 0 {
            return Ok(0);
        }

        N.checked_add(CANARY_SIZE.saturating_mul(2))
            .ok_or(MemoryLockError {
                operation: MemoryLockOperation::Length,
                errno: 0,
            })
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn slot_stride() -> Result<usize, MemoryLockError> {
        Ok(N)
    }

    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    #[inline]
    fn as_mapping_slice(&self) -> &[u8] {
        // SAFETY: `base` either points to a live mapping of `map_len` bytes
        // owned by this pool, or is dangling with `map_len == 0`.
        unsafe { core::slice::from_raw_parts(self.base.as_ptr(), self.map_len) }
    }
}

impl<'pool, const N: usize, const SLOTS: usize> SecretPoolSlot<'pool, N, SLOTS> {
    /// Number of secret bytes stored in this slot.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns true when this slot stores zero bytes.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Index of this slot inside the parent pool.
    #[must_use]
    #[inline]
    pub const fn slot_index(&self) -> usize {
        self.slot_index
    }

    /// Replace all slot bytes from a same-length slice.
    #[inline]
    pub fn copy_from_slice(&mut self, source: &[u8]) -> Result<(), crate::LengthError> {
        if source.len() != N {
            return Err(crate::LengthError {
                expected: N,
                actual: source.len(),
            });
        }

        self.assert_canaries_intact();
        self.as_mut_slice().copy_from_slice(source);
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Compatibility alias for [`SecretPoolSlot::copy_from_slice`].
    #[inline]
    pub fn replace_from_slice(&mut self, source: &[u8]) -> Result<(), crate::LengthError> {
        self.copy_from_slice(source)
    }

    /// Replace all slot bytes from an owned array, then volatile-clear the
    /// input array.
    #[inline]
    pub fn replace_from_array(&mut self, mut bytes: [u8; N]) {
        self.assert_canaries_intact();
        self.as_mut_slice().copy_from_slice(&bytes);
        compiler_fence(Ordering::SeqCst);
        crate::wipe::bytes(&mut bytes);
    }

    /// Replace all slot bytes with generated bytes.
    #[inline]
    pub fn replace_from_fn(&mut self, mut make_byte: impl FnMut(usize) -> u8) {
        self.assert_canaries_intact();
        let mut index = 0;
        while index < N {
            self.as_mut_slice()[index] = make_byte(index);
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// Replace all slot bytes with fallibly generated bytes.
    ///
    /// If generation fails, bytes already written by this call are cleared
    /// before the error is returned.
    #[inline]
    pub fn try_replace_from_fn<E>(
        &mut self,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), E> {
        self.assert_canaries_intact();
        let mut index = 0;
        while index < N {
            match make_byte(index) {
                Ok(byte) => self.as_mut_slice()[index] = byte,
                Err(error) => {
                    self.secure_clear();
                    return Err(error);
                }
            }
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Fill a caller-provided destination with a copy of the slot bytes.
    #[inline]
    pub fn copy_to_slice(&self, destination: &mut [u8]) -> Result<(), crate::LengthError> {
        if destination.len() != N {
            return Err(crate::LengthError {
                expected: N,
                actual: destination.len(),
            });
        }

        self.assert_canaries_intact();
        destination.copy_from_slice(self.as_slice());
        compiler_fence(Ordering::SeqCst);
        core::hint::black_box(destination);
        Ok(())
    }

    /// Run a closure with read-only access to the slot bytes.
    ///
    /// The closure can copy the secret elsewhere. Keep usage limited to
    /// protocol or cryptographic boundaries that genuinely need raw bytes.
    #[inline]
    pub fn expose_secret<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.assert_canaries_intact();
        inspect(self.as_array())
    }

    /// Verify integrity, copy into temporary stack storage, and expose the copy.
    ///
    /// The temporary is volatile-cleared on normal return and unwinding. It
    /// cannot be cleared if the process aborts.
    #[inline]
    pub fn expose_secret_copy<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.assert_canaries_intact();
        crate::owned::expose_array_copy(self.as_array(), inspect)
    }

    /// Run a closure with mutable access to the slot bytes.
    #[inline]
    pub fn with_secret_mut<R>(&mut self, inspect: impl FnOnce(&mut [u8; N]) -> R) -> R {
        self.assert_canaries_intact();
        inspect(self.as_array_mut())
    }

    /// Verify canary integrity before exposing the pooled slot bytes.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn expose_secret_checked<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(inspect(self.as_array()))
    }

    /// Verify canary integrity before exposing a temporary plaintext copy.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn expose_secret_copy_checked<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::owned::expose_array_copy(self.as_array(), inspect))
    }

    /// Verify canary integrity before comparing pooled slot bytes.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn constant_time_eq_checked(&self, other: &[u8]) -> Result<bool, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::constant_time_eq_slices(self.as_slice(), other))
    }

    /// Verify this slot's canaries.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        if self.canaries_intact() {
            Ok(())
        } else {
            self.clear_after_canary_failure();
            Err(CanaryCorruptedError)
        }
    }

    /// Compare against a slice without early exit for equal-length inputs.
    ///
    /// Length mismatch returns immediately because the provided slice
    /// length is treated as public metadata.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        self.assert_canaries_intact();
        crate::constant_time_eq_slices(self.as_slice(), other)
    }

    /// Clear only this slot with volatile writes.
    #[inline(never)]
    pub fn secure_clear(&mut self) {
        if N != 0 {
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.slot_stride());
        }
        self.write_canaries();
    }

    /// Consume this slot after clearing it, then return it to the pool.
    #[inline]
    pub fn into_cleared(mut self) {
        self.secure_clear();
    }

    /// Clear this slot with volatile writes, then flush its cache lines.
    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    #[inline(never)]
    pub fn secure_clear_and_flush(&mut self) {
        self.secure_clear();
        crate::cache_flush::flush_cache_lines(self.as_slot_slice());
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        // SAFETY: `data_ptr` points to this live slot's `N` bytes in the
        // parent pool mapping, or is dangling with `N == 0`.
        unsafe { core::slice::from_raw_parts(self.data_ptr(), N) }
    }

    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` gives exclusive access to this live slot, and
        // the pool bitmap prevents another live safe handle for the same
        // slot until this value drops.
        unsafe { core::slice::from_raw_parts_mut(self.data_ptr(), N) }
    }

    #[inline]
    fn as_array(&self) -> &[u8; N] {
        // SAFETY: `as_slice` is exactly `N` bytes long, and the pointer is
        // valid for a `[u8; N]` reference for the duration of `&self`.
        unsafe { &*(self.data_ptr() as *const [u8; N]) }
    }

    #[inline]
    fn as_array_mut(&mut self) -> &mut [u8; N] {
        // SAFETY: `as_mut_slice` is exactly `N` bytes long, and `&mut self`
        // provides exclusive access to this slot for the returned borrow.
        unsafe { &mut *(self.data_ptr() as *mut [u8; N]) }
    }

    #[inline]
    fn data_ptr(&self) -> *mut u8 {
        // SAFETY: non-empty canary-checked slots reserve an 8-byte prefix.
        unsafe { self.ptr.as_ptr().add(Self::data_offset()) }
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    const fn data_offset() -> usize {
        if N == 0 {
            0
        } else {
            CANARY_SIZE
        }
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    const fn data_offset() -> usize {
        0
    }

    #[inline]
    fn slot_stride(&self) -> usize {
        self.pool.slot_stride
    }

    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    #[inline]
    fn as_slot_slice(&self) -> &[u8] {
        // SAFETY: `ptr` points to this live slot's full stride, or is
        // dangling with zero stride.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.slot_stride()) }
    }

    #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
    #[inline]
    fn canary_value(&self) -> [u8; CANARY_SIZE] {
        ((self.ptr.as_ptr() as u64) ^ CANARY_MASK).to_ne_bytes()
    }

    #[cfg(feature = "random-canary")]
    #[inline]
    fn canary_value(&self) -> [u8; CANARY_SIZE] {
        self.canary
    }

    #[cfg(feature = "random-canary")]
    #[inline]
    fn initialize_canaries(&mut self) -> Result<(), MemoryLockError> {
        if N == 0 {
            return Ok(());
        }

        self.canary = random_canary_value()?;
        self.write_canaries();
        Ok(())
    }

    #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
    #[inline]
    fn initialize_canaries(&mut self) -> Result<(), MemoryLockError> {
        self.write_canaries();
        Ok(())
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn initialize_canaries(&mut self) -> Result<(), MemoryLockError> {
        Ok(())
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn canaries_intact(&self) -> bool {
        if N == 0 {
            return true;
        }

        let expected = self.canary_value();
        // SAFETY: non-empty canary-checked slots reserve prefix and suffix
        // canary regions inside the slot stride.
        let prefix = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), CANARY_SIZE) };
        // SAFETY: the suffix follows exactly `CANARY_SIZE + N` bytes after
        // the slot base and remains inside the checked stride.
        let suffix = unsafe {
            core::slice::from_raw_parts(self.ptr.as_ptr().add(CANARY_SIZE + N), CANARY_SIZE)
        };

        crate::constant_time_eq_slices(prefix, &expected)
            & crate::constant_time_eq_slices(suffix, &expected)
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn write_canaries(&mut self) {
        if N == 0 {
            return;
        }

        let canary = self.canary_value();
        // SAFETY: non-empty canary-checked slots reserve prefix and suffix
        // canary regions inside the slot stride.
        unsafe {
            core::ptr::copy_nonoverlapping(canary.as_ptr(), self.ptr.as_ptr(), CANARY_SIZE);
            core::ptr::copy_nonoverlapping(
                canary.as_ptr(),
                self.ptr.as_ptr().add(CANARY_SIZE + N),
                CANARY_SIZE,
            );
        }
        compiler_fence(Ordering::SeqCst);
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn write_canaries(&mut self) {}

    #[cfg(feature = "canary-check")]
    #[inline]
    fn assert_canaries_intact(&self) {
        if self.verify_integrity().is_err() {
            panic!("pooled secret slot canary corrupted");
        }
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn assert_canaries_intact(&self) {}

    #[cfg(feature = "canary-check")]
    #[inline]
    fn clear_after_canary_failure(&self) {
        if N != 0 {
            // Fail-closed clearing intentionally mutates the uniquely owned
            // slot mapping through `&self`. Slot handles are `Send` but not
            // `Sync`, and the parent bitmap prevents a second safe handle
            // for this slot.
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.slot_stride());
        }
    }

    #[cfg(all(test, feature = "canary-check", feature = "std"))]
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn corrupt_prefix_canary_for_test(&mut self) {
        if N == 0 {
            return;
        }

        // SAFETY: non-empty canary-checked slots start with a live prefix
        // canary byte.
        unsafe {
            let byte = self.ptr.as_ptr();
            core::ptr::write(byte, core::ptr::read(byte) ^ 0xFF);
        }
    }
}

impl<const N: usize, const SLOTS: usize> Drop for SecretPool<N, SLOTS> {
    #[inline]
    fn drop(&mut self) {
        self.secure_clear();

        if self.map_len != 0 {
            let _ = unlock_mapping(self.base, self.map_len);
            let _ = unmap_private(self.base, self.map_len);
        }
    }
}

impl<'pool, const N: usize, const SLOTS: usize> Drop for SecretPoolSlot<'pool, N, SLOTS> {
    #[inline]
    fn drop(&mut self) {
        self.secure_clear();
        self.pool.used[self.slot_index].store(false, Ordering::Release);
    }
}

impl<const N: usize, const SLOTS: usize> crate::SecureSanitize for SecretPool<N, SLOTS> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.secure_clear();
    }
}

impl<const N: usize, const SLOTS: usize> crate::StableSharedSecretStorage for SecretPool<N, SLOTS> {}

impl<const N: usize, const SLOTS: usize> crate::StableMutableSecretStorage
    for SecretPool<N, SLOTS>
{
}

impl<'pool, const N: usize, const SLOTS: usize> crate::SecureSanitize
    for SecretPoolSlot<'pool, N, SLOTS>
{
    #[inline]
    fn secure_sanitize(&mut self) {
        self.secure_clear();
    }
}

impl<'pool, const N: usize, const SLOTS: usize> crate::StableSharedSecretStorage
    for SecretPoolSlot<'pool, N, SLOTS>
{
}

impl<'pool, const N: usize, const SLOTS: usize> crate::StableMutableSecretStorage
    for SecretPoolSlot<'pool, N, SLOTS>
{
}

impl<const N: usize, const SLOTS: usize> fmt::Debug for SecretPool<N, SLOTS> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretPool")
            .field("slot_size", &N)
            .field("capacity_slots", &SLOTS)
            .field("locked_len", &self.map_len)
            .field("contents", &"<redacted>")
            .finish()
    }
}

impl<'pool, const N: usize, const SLOTS: usize> fmt::Debug for SecretPoolSlot<'pool, N, SLOTS> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretPoolSlot")
            .field("len", &N)
            .field("slot_index", &self.slot_index)
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "random-canary")]
fn random_canary_value() -> Result<[u8; CANARY_SIZE], MemoryLockError> {
    let mut canary = [0; CANARY_SIZE];
    crate::canary::fill(&mut canary).map_err(|errno| MemoryLockError {
        operation: MemoryLockOperation::Random,
        errno,
    })?;
    Ok(canary)
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline]
const fn platform_page_granule() -> usize {
    LINUX_PAGE_GRANULE
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[inline]
fn platform_page_granule() -> usize {
    crate::platform::linux_aarch64_page_size::detect_page_granule()
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
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
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
fn unix_error(operation: MemoryLockOperation) -> MemoryLockError {
    MemoryLockError {
        operation,
        errno: unix_errno(),
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
fn unix_errno() -> i32 {
    // SAFETY: `errno_location` returns a pointer to the calling thread's
    // errno according to the target C ABI.
    unsafe { *errno_location() as i32 }
}

#[cfg(target_os = "linux")]
fn map_private(len: usize) -> Result<NonNull<u8>, MemoryLockError> {
    let ret = raw_syscall6(
        SYS_MMAP,
        0,
        len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        MAP_FD_ANONYMOUS,
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
    target_os = "ios",
    target_os = "android",
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
    target_os = "ios",
    target_os = "android",
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

#[cfg(all(not(target_os = "linux"), not(target_os = "freebsd")))]
#[inline]
fn mark_dontdump(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn mark_dontdump(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    // SAFETY: `ptr` and `len` describe a live private mapping owned by this
    // value, and `MADV_NOCORE` requests core-dump exclusion for it.
    let ret = unsafe { madvise(ptr.as_ptr().cast::<c_void>(), len, MADV_NOCORE) };
    if ret != 0 {
        Err(unix_error(MemoryLockOperation::DontDump))
    } else {
        Ok(())
    }
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

#[cfg(all(not(target_os = "linux"), not(feature = "require-fork-exclusion")))]
#[inline]
fn mark_dontfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
    Ok(())
}

#[cfg(all(not(target_os = "linux"), feature = "require-fork-exclusion"))]
#[inline]
fn mark_dontfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
    Err(MemoryLockError {
        operation: MemoryLockOperation::DontFork,
        errno: 0,
    })
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
    target_os = "ios",
    target_os = "android",
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
    target_os = "ios",
    target_os = "android",
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

#[inline]
fn unmap_after_setup_error(
    ptr: NonNull<u8>,
    len: usize,
    setup_error: MemoryLockError,
) -> MemoryLockError {
    // A failed unmap can leave a live mapping behind, so it takes
    // precedence over the setup error. Carrying both would require a
    // breaking change to the public two-field error representation.
    match unmap_private(ptr, len) {
        Ok(()) => setup_error,
        Err(unmap_error) => unmap_error,
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
