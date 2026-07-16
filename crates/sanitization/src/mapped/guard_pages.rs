use core::{
    fmt,
    ptr::NonNull,
    sync::atomic::{compiler_fence, Ordering},
};

use super::{
    ProtectionControl, ProtectionError, ProtectionFailure, ProtectionReport, ProtectionRequest,
    ProtectionState, Requirement, RollbackReport, RollbackState,
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

// Guard layout must place the writable region on a kernel page boundary.
// Linux x86_64 uses 4 KiB. Linux aarch64 is detected at runtime from auxv
// and falls back to 64 KiB if detection fails.
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
const PROT_NONE: usize = 0x0;
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
#[cfg(all(feature = "memory-lock", target_os = "freebsd"))]
const MADV_NOCORE: i32 = 8;

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
#[cfg(target_os = "linux")]
const MAP_FD_ANONYMOUS: usize = (-1isize) as usize;
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

#[cfg(feature = "canary-check")]
const CANARY_SIZE: usize = 8;
#[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
const CANARY_MASK: u64 = 0xA11C_E5AF_EC0D_EC0D;

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
    fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
    #[cfg(all(feature = "memory-lock", target_os = "freebsd"))]
    fn madvise(addr: *mut c_void, len: usize, advice: i32) -> i32;
    #[cfg(feature = "memory-lock")]
    fn mlock(addr: *const c_void, len: usize) -> i32;
    #[cfg(feature = "memory-lock")]
    fn munlock(addr: *const c_void, len: usize) -> i32;

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
    /// Operating-system random canary generation failed.
    Random,
}

/// Error returned by guarded secret allocation operations.
///
/// If setup and the subsequent cleanup unmap both fail, the returned error
/// reports `Unmap`. A mapping that may still be live takes diagnostic
/// precedence over the original setup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardPageError {
    /// Operation that failed.
    pub operation: GuardPageOperation,
    /// Positive errno or Windows `GetLastError` value when available.
    ///
    /// This is `0` for local arithmetic failures before a syscall.
    /// Negative values are crate-internal sentinel failures, such as an
    /// unsupported random-canary backend or a random backend that made no
    /// progress.
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
/// Linux, Android, macOS, iOS, Windows, and BSD targets. Secret bytes live
/// in private platform mappings. The pages immediately before and after
/// the writable data region remain inaccessible, so linear overreads or
/// overwrites past the mapped data region fault instead of reaching
/// unrelated memory.
///
/// The secret bytes are not allocated with the Rust global allocator.
pub struct GuardedSecretVec {
    base: NonNull<u8>,
    data: NonNull<u8>,
    map_len: usize,
    writable_len: usize,
    data_capacity: usize,
    len: usize,
    locked: bool,
    request: ProtectionRequest,
    report: ProtectionReport,
    #[cfg(feature = "random-canary")]
    canary: [u8; CANARY_SIZE],
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
        Self::with_capacity_with_protection(capacity, ProtectionRequest::guarded())
            .map_err(protection_error_as_guard_page)
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
        Self::with_capacity_with_protection(capacity, ProtectionRequest::locked_guarded())
            .map_err(protection_error_as_guard_page)
    }

    /// Create guarded storage under an explicit runtime protection policy.
    ///
    /// Guard pages are intrinsic to this type and are always required.
    /// Preferred lock, dump, or fork controls may fail while construction
    /// succeeds with an explicit reduced-protection report.
    pub fn with_capacity_with_protection(
        capacity: usize,
        request: ProtectionRequest,
    ) -> Result<Self, ProtectionError> {
        #[cfg(feature = "random-canary")]
        let canary = random_canary_value().map_err(|error| {
            guard_pre_mapping_error(request, capacity, ProtectionControl::Canary, error.errno)
        })?;

        let page_granule = platform_page_granule();
        let mut report = ProtectionReport::pending(request, capacity, page_granule);
        report.canary = resolve_guard_canary(request.canary, &report)?;
        report.cache_policy = resolve_guard_unavailable(
            request.cache_policy,
            ProtectionControl::CachePolicy,
            &report,
        )?;

        let data_capacity = guarded_payload_capacity(capacity).map_err(|error| {
            guard_pre_mapping_error(request, capacity, ProtectionControl::Mapping, error.errno)
        })?;
        let writable_len = guarded_writable_len(data_capacity).map_err(|error| {
            guard_pre_mapping_error(request, capacity, ProtectionControl::Mapping, error.errno)
        })?;
        let total_len = writable_len
            .checked_add(page_granule)
            .and_then(|value| value.checked_add(page_granule))
            .ok_or_else(|| {
                guard_pre_mapping_error(request, capacity, ProtectionControl::Mapping, 0)
            })?;

        let base = match map_guarded(total_len) {
            Ok(base) => base,
            Err(error) => {
                report.mapping = ProtectionState::Failed { code: error.errno };
                return Err(ProtectionError {
                    failure: ProtectionFailure {
                        control: ProtectionControl::Mapping,
                        code: error.errno,
                    },
                    partial_report: report,
                    rollback: RollbackReport::not_needed(),
                });
            }
        };
        report.mapping = ProtectionState::Established;
        report.mapped_bytes = total_len;
        let data_addr = match (base.as_ptr() as usize).checked_add(page_granule) {
            Some(address) => address,
            None => {
                report.guard_pages = ProtectionState::Failed { code: 0 };
                return Err(guard_required_error(
                    base,
                    total_len,
                    ProtectionControl::GuardPages,
                    0,
                    report,
                ));
            }
        };
        let data = match NonNull::new(data_addr as *mut u8) {
            Some(data) => data,
            None => {
                report.guard_pages = ProtectionState::Failed { code: 0 };
                return Err(guard_required_error(
                    base,
                    total_len,
                    ProtectionControl::GuardPages,
                    0,
                    report,
                ));
            }
        };

        if let Err(error) = protect_data(data, writable_len) {
            report.guard_pages = ProtectionState::Failed { code: error.errno };
            return Err(guard_required_error(
                base,
                total_len,
                ProtectionControl::GuardPages,
                error.errno,
                report,
            ));
        }
        report.guard_pages = ProtectionState::Established;

        report.dump_exclusion = apply_guard_control(
            request.dump_exclusion,
            dump_exclusion_supported(),
            ProtectionControl::DumpExclusion,
            &mut report,
            base,
            total_len,
            data,
            writable_len,
            guard_mark_dontdump,
        )?;
        report.fork_exclusion = apply_guard_control(
            request.fork_exclusion,
            fork_exclusion_supported(),
            ProtectionControl::ForkExclusion,
            &mut report,
            base,
            total_len,
            data,
            writable_len,
            guard_mark_dontfork,
        )?;
        report.memory_lock = apply_guard_control(
            request.memory_lock,
            cfg!(feature = "memory-lock"),
            ProtectionControl::MemoryLock,
            &mut report,
            base,
            total_len,
            data,
            writable_len,
            guard_lock_mapping,
        )?;
        let locked = report.memory_lock == ProtectionState::Established;
        if locked {
            report.locked_bytes = writable_len;
        }

        let mut secret = Self {
            base,
            data,
            map_len: total_len,
            writable_len,
            data_capacity,
            len: 0,
            locked,
            request,
            report,
            #[cfg(feature = "random-canary")]
            canary,
        };
        secret.write_canaries();
        Ok(secret)
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

    /// Actual runtime protections established for the current mapping.
    #[must_use]
    #[inline]
    pub const fn protection_report(&self) -> &ProtectionReport {
        &self.report
    }

    /// Runtime protection policy requested for the current mapping.
    #[must_use]
    #[inline]
    pub const fn protection_request(&self) -> ProtectionRequest {
        self.request
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

    /// Verify canary integrity before exposing guarded secret bytes.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn expose_secret_checked<R>(
        &self,
        inspect: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, crate::CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(inspect(self.as_slice()))
    }

    /// Append bytes, growing into a new guarded mapping if needed.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), GuardPageError> {
        self.assert_canaries_intact();
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
        self.finish_initialization(required);
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
        self.assert_canaries_intact();

        if bytes.len() > self.data_capacity {
            let mut replacement = Self::with_capacity_with_protection(bytes.len(), self.request)
                .map_err(protection_error_as_guard_page)?;
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
        self.assert_canaries_intact();
        let mut replacement = Self::with_capacity_with_protection(len, self.request)
            .map_err(protection_error_as_guard_page)?;
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
        self.assert_canaries_intact();
        let mut replacement = Self::with_capacity_with_protection(len, self.request)
            .map_err(protection_error_as_guard_page)?;
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
        crate::wipe_backend::erase(self.data.as_ptr(), self.writable_len);
        self.len = 0;
        self.write_canaries();
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
    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn clear_secret_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        self.clear_secret();
        crate::cache_flush::flush_cache_lines(self.as_capacity_slice())
    }

    /// Compare against a byte slice without early exit for equal-length
    /// inputs.
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

    /// Verify canary integrity before comparing guarded secret bytes.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn constant_time_eq_checked(
        &self,
        other: &[u8],
    ) -> Result<bool, crate::CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::constant_time_eq_slices(self.as_slice(), other))
    }

    /// Verify guarded mapping canaries.
    #[cfg(feature = "canary-check")]
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), crate::CanaryCorruptedError> {
        if self.canaries_intact() {
            Ok(())
        } else {
            self.clear_after_canary_failure();
            Err(crate::CanaryCorruptedError)
        }
    }

    fn grow_to(&mut self, required: usize) -> Result<(), GuardPageError> {
        self.assert_canaries_intact();
        let page_granule = platform_page_granule();
        let next_capacity = self
            .data_capacity
            .saturating_mul(2)
            .max(required)
            .max(page_granule);
        let mut replacement = Self::with_capacity_with_protection(next_capacity, self.request)
            .map_err(protection_error_as_guard_page)?;
        replacement.as_mut_capacity_slice()[..self.len].copy_from_slice(self.as_slice());
        replacement.finish_initialization(self.len);

        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    fn fill_from_fn(&mut self, len: usize, make_byte: &mut impl FnMut(usize) -> u8) {
        assert!(
            len <= self.data_capacity,
            "guarded secret length exceeds capacity"
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

    /// Fill a fresh or throwaway guarded mapping.
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
            "guarded secret length exceeds capacity"
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
            "guarded secret length exceeds capacity"
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
        // capacity inside the writable region between guard pages.
        unsafe { core::slice::from_raw_parts_mut(self.payload_ptr(), self.data_capacity) }
    }

    #[cfg(feature = "cache-flush")]
    #[inline]
    fn as_capacity_slice(&self) -> &[u8] {
        // SAFETY: `data` points to the live writable data region between
        // guard pages for the duration of `&self`.
        unsafe { core::slice::from_raw_parts(self.data.as_ptr(), self.writable_len) }
    }

    #[inline]
    fn payload_ptr(&self) -> *mut u8 {
        // SAFETY: canary-checked guarded mappings reserve an 8-byte prefix.
        unsafe { self.data.as_ptr().add(Self::payload_offset()) }
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
        ((self.data.as_ptr() as u64) ^ CANARY_MASK).to_ne_bytes()
    }

    #[cfg(feature = "random-canary")]
    #[inline]
    fn canary_value(&self) -> [u8; CANARY_SIZE] {
        self.canary
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn canaries_intact(&self) -> bool {
        let expected = self.canary_value();
        // SAFETY: canary-checked guarded mappings reserve prefix and suffix
        // canary regions inside the writable data area.
        let prefix = unsafe { core::slice::from_raw_parts(self.data.as_ptr(), CANARY_SIZE) };
        // SAFETY: `len <= data_capacity`, so suffix at prefix + len stays
        // inside the writable data area.
        let suffix = unsafe {
            core::slice::from_raw_parts(self.data.as_ptr().add(CANARY_SIZE + self.len), CANARY_SIZE)
        };

        crate::constant_time_eq_slices(prefix, &expected)
            & crate::constant_time_eq_slices(suffix, &expected)
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn write_canaries(&mut self) {
        let canary = self.canary_value();
        // SAFETY: canary-checked guarded mappings reserve prefix and suffix
        // canary regions inside the writable data area.
        unsafe {
            core::ptr::copy_nonoverlapping(canary.as_ptr(), self.data.as_ptr(), CANARY_SIZE);
            core::ptr::copy_nonoverlapping(
                canary.as_ptr(),
                self.data.as_ptr().add(CANARY_SIZE + self.len),
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
            panic!("guarded secret canary corrupted");
        }
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn assert_canaries_intact(&self) {}

    #[cfg(feature = "canary-check")]
    #[inline]
    fn clear_after_canary_failure(&self) {
        // Fail-closed clearing intentionally mutates the owned guarded
        // mapping through `&self`. `GuardedSecretVec` is `Send` but not
        // `Sync`, so safe code cannot run this concurrently through shared
        // references.
        crate::wipe_backend::erase(self.data.as_ptr(), self.writable_len);
    }

    #[cfg(all(test, feature = "canary-check", feature = "std"))]
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn corrupt_suffix_canary_for_test(&mut self) {
        // SAFETY: canary-checked guarded mappings reserve a suffix canary
        // immediately after the initialized payload.
        unsafe {
            let byte = self.data.as_ptr().add(CANARY_SIZE + self.len);
            core::ptr::write(byte, core::ptr::read(byte) ^ 0xFF);
        }
    }
}

impl Drop for GuardedSecretVec {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
        #[cfg(feature = "memory-lock")]
        if self.locked {
            let _ = unlock_mapping(self.data, self.writable_len);
        }
        let _ = unmap_guarded(self.base, self.map_len);
    }
}

#[cfg(feature = "cache-flush")]
impl crate::cache_flush::CacheFlushSanitize for GuardedSecretVec {
    #[inline(never)]
    fn cache_flush_sanitize(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        self.clear_secret_and_flush()
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
            .field("writable_len", &self.writable_len)
            .field("memory_locked", &self.locked)
            .field("contents", &"<redacted>")
            .finish()
    }
}

fn resolve_guard_unavailable(
    requirement: Requirement,
    control: ProtectionControl,
    report: &ProtectionReport,
) -> Result<ProtectionState, ProtectionError> {
    match super::protection::unavailable_state(requirement) {
        Ok(state) => Ok(state),
        Err(()) => Err(ProtectionError {
            failure: ProtectionFailure { control, code: 0 },
            partial_report: *report,
            rollback: RollbackReport::not_needed(),
        }),
    }
}

fn resolve_guard_canary(
    requirement: Requirement,
    report: &ProtectionReport,
) -> Result<ProtectionState, ProtectionError> {
    #[cfg(feature = "canary-check")]
    {
        let _ = requirement;
        let _ = report;
        Ok(ProtectionState::Established)
    }
    #[cfg(not(feature = "canary-check"))]
    {
        resolve_guard_unavailable(requirement, ProtectionControl::Canary, report)
    }
}

fn guard_pre_mapping_error(
    request: ProtectionRequest,
    requested_bytes: usize,
    control: ProtectionControl,
    code: i32,
) -> ProtectionError {
    let mut report = ProtectionReport::pending(request, requested_bytes, platform_page_granule());
    set_guard_failed_state(&mut report, control, code);
    ProtectionError {
        failure: ProtectionFailure { control, code },
        partial_report: report,
        rollback: RollbackReport::not_needed(),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_guard_control(
    requirement: Requirement,
    supported: bool,
    control: ProtectionControl,
    report: &mut ProtectionReport,
    base: NonNull<u8>,
    total_len: usize,
    data: NonNull<u8>,
    writable_len: usize,
    apply: fn(NonNull<u8>, usize) -> Result<(), GuardPageError>,
) -> Result<ProtectionState, ProtectionError> {
    if requirement == Requirement::NotRequested {
        return Ok(ProtectionState::NotRequested);
    }
    if !supported {
        if requirement == Requirement::Preferred {
            return Ok(ProtectionState::Unsupported);
        }
        set_guard_failed_state(report, control, 0);
        return Err(guard_required_error(base, total_len, control, 0, *report));
    }

    match apply(data, writable_len) {
        Ok(()) => Ok(ProtectionState::Established),
        Err(error) => {
            if control == ProtectionControl::MemoryLock {
                report.lock_quota_likely = lock_quota_likely(error.errno);
            }
            if requirement == Requirement::Preferred {
                return Ok(ProtectionState::Failed { code: error.errno });
            }
            set_guard_failed_state(report, control, error.errno);
            Err(guard_required_error(
                base,
                total_len,
                control,
                error.errno,
                *report,
            ))
        }
    }
}

fn guard_required_error(
    base: NonNull<u8>,
    total_len: usize,
    control: ProtectionControl,
    code: i32,
    report: ProtectionReport,
) -> ProtectionError {
    ProtectionError {
        failure: ProtectionFailure { control, code },
        partial_report: report,
        rollback: rollback_guarded_mapping(base, total_len),
    }
}

fn rollback_guarded_mapping(base: NonNull<u8>, total_len: usize) -> RollbackReport {
    // Locking is deliberately the final setup operation, so no later setup
    // step can fail after a successful lock.
    let unlock = RollbackState::NotNeeded;
    let unmap = match unmap_guarded(base, total_len) {
        Ok(()) => RollbackState::Completed,
        Err(error) => RollbackState::Failed(ProtectionFailure {
            control: ProtectionControl::Mapping,
            code: error.errno,
        }),
    };
    RollbackReport { unlock, unmap }
}

fn set_guard_failed_state(report: &mut ProtectionReport, control: ProtectionControl, code: i32) {
    let state = ProtectionState::Failed { code };
    match control {
        ProtectionControl::Mapping => report.mapping = state,
        ProtectionControl::MemoryLock => report.memory_lock = state,
        ProtectionControl::DumpExclusion => report.dump_exclusion = state,
        ProtectionControl::ForkExclusion => report.fork_exclusion = state,
        ProtectionControl::GuardPages => report.guard_pages = state,
        ProtectionControl::Canary => report.canary = state,
        ProtectionControl::CachePolicy => report.cache_policy = state,
    }
}

fn protection_error_as_guard_page(error: ProtectionError) -> GuardPageError {
    if let RollbackState::Failed(failure) = error.rollback.unmap {
        return GuardPageError {
            operation: GuardPageOperation::Unmap,
            errno: failure.code,
        };
    }
    if let RollbackState::Failed(failure) = error.rollback.unlock {
        return GuardPageError {
            operation: GuardPageOperation::Unlock,
            errno: failure.code,
        };
    }

    GuardPageError {
        operation: match error.failure.control {
            ProtectionControl::Mapping => GuardPageOperation::Map,
            ProtectionControl::MemoryLock => GuardPageOperation::Lock,
            ProtectionControl::DumpExclusion => GuardPageOperation::DontDump,
            ProtectionControl::ForkExclusion => GuardPageOperation::DontFork,
            ProtectionControl::GuardPages => GuardPageOperation::Protect,
            ProtectionControl::Canary => GuardPageOperation::Random,
            ProtectionControl::CachePolicy => GuardPageOperation::Protect,
        },
        errno: error.failure.code,
    }
}

#[inline]
const fn lock_quota_likely(code: i32) -> bool {
    matches!(code, 11 | 12 | 1453)
}

#[inline]
const fn dump_exclusion_supported() -> bool {
    cfg!(all(
        feature = "memory-lock",
        any(target_os = "linux", target_os = "freebsd")
    ))
}

#[inline]
const fn fork_exclusion_supported() -> bool {
    cfg!(all(feature = "memory-lock", target_os = "linux"))
}

#[cfg(feature = "memory-lock")]
fn guard_lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    lock_mapping(ptr, len)
}

#[cfg(not(feature = "memory-lock"))]
fn guard_lock_mapping(_ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
    Err(GuardPageError {
        operation: GuardPageOperation::Lock,
        errno: 0,
    })
}

#[cfg(feature = "memory-lock")]
fn guard_mark_dontdump(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    mark_dontdump(ptr, len)
}

#[cfg(not(feature = "memory-lock"))]
fn guard_mark_dontdump(_ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
    Err(GuardPageError {
        operation: GuardPageOperation::DontDump,
        errno: 0,
    })
}

#[cfg(feature = "memory-lock")]
fn guard_mark_dontfork(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    mark_dontfork(ptr, len)
}

#[cfg(not(feature = "memory-lock"))]
fn guard_mark_dontfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
    Err(GuardPageError {
        operation: GuardPageOperation::DontFork,
        errno: 0,
    })
}

#[cfg(feature = "random-canary")]
fn random_canary_value() -> Result<[u8; CANARY_SIZE], GuardPageError> {
    let mut canary = [0; CANARY_SIZE];
    crate::canary::fill(&mut canary).map_err(|errno| GuardPageError {
        operation: GuardPageOperation::Random,
        errno,
    })?;
    Ok(canary)
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

#[cfg(feature = "canary-check")]
fn guarded_payload_capacity(requested: usize) -> Result<usize, GuardPageError> {
    let requested_with_canaries =
        requested
            .checked_add(guarded_extra_len())
            .ok_or(GuardPageError {
                operation: GuardPageOperation::Length,
                errno: 0,
            })?;
    rounded_data_len(requested_with_canaries).map(|writable_len| {
        writable_len
            .saturating_sub(guarded_extra_len())
            .max(requested)
    })
}

#[cfg(not(feature = "canary-check"))]
fn guarded_payload_capacity(requested: usize) -> Result<usize, GuardPageError> {
    rounded_data_len(requested)
}

#[cfg(feature = "canary-check")]
fn guarded_writable_len(payload_capacity: usize) -> Result<usize, GuardPageError> {
    payload_capacity
        .checked_add(guarded_extra_len())
        .ok_or(GuardPageError {
            operation: GuardPageOperation::Length,
            errno: 0,
        })
}

#[cfg(not(feature = "canary-check"))]
fn guarded_writable_len(payload_capacity: usize) -> Result<usize, GuardPageError> {
    Ok(payload_capacity)
}

#[cfg(feature = "canary-check")]
#[inline]
const fn guarded_extra_len() -> usize {
    CANARY_SIZE * 2
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
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
fn unix_error(operation: GuardPageOperation) -> GuardPageError {
    GuardPageError {
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
fn map_guarded(len: usize) -> Result<NonNull<u8>, GuardPageError> {
    let ret = raw_syscall6(
        SYS_MMAP,
        0,
        len,
        PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        MAP_FD_ANONYMOUS,
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
    target_os = "ios",
    target_os = "android",
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
    target_os = "ios",
    target_os = "android",
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
        target_os = "ios",
        target_os = "android",
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

#[cfg(all(
    feature = "memory-lock",
    not(target_os = "linux"),
    not(target_os = "freebsd")
))]
#[inline]
fn mark_dontdump(_ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
    Ok(())
}

#[cfg(all(feature = "memory-lock", target_os = "freebsd"))]
fn mark_dontdump(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    // SAFETY: `ptr` and `len` describe the live writable data region owned
    // by this value, and `MADV_NOCORE` requests core-dump exclusion for it.
    let ret = unsafe { madvise(ptr.as_ptr().cast::<c_void>(), len, MADV_NOCORE) };
    if ret != 0 {
        Err(unix_error(GuardPageOperation::DontDump))
    } else {
        Ok(())
    }
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

#[cfg(all(
    feature = "memory-lock",
    not(target_os = "linux"),
    not(feature = "require-fork-exclusion")
))]
#[inline]
fn mark_dontfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
    Ok(())
}

#[cfg(all(
    feature = "memory-lock",
    not(target_os = "linux"),
    feature = "require-fork-exclusion"
))]
#[inline]
fn mark_dontfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
    Err(GuardPageError {
        operation: GuardPageOperation::DontFork,
        errno: 0,
    })
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
        target_os = "ios",
        target_os = "android",
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
    target_os = "ios",
    target_os = "android",
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
