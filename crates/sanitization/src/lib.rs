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
//! The [`ct`] module provides dependency-free data-oblivious primitives such as
//! [`ct::Choice`], [`ct::ConstantTimeEq`], and explicit
//! [`ct::Choice::declassify`] boundaries. Its claim is no secret-dependent
//! control flow or memory access under documented conditions, not identical
//! wall-clock timing on every target.
//!
//! Important limits:
//! - Safe Rust cannot soundly scrub old stack frames created by prior moves.
//! - Process abort prevents destructors and post-closure cleanup from running.
//! - SIMD stores, broad memory policy, and target-specific hardening need
//!   target-specific unsafe code and platform policy.
//! - Platform memory locking is available only through the explicit
//!   `memory-lock` feature on supported Linux, Android, macOS, iOS, Windows,
//!   and BSD targets. On WASM, `memory-lock` must be paired with `wasm-compat`
//!   to expose volatile-only compatibility types without host memory locking.
//!   The same feature also enables pooled slots with [`SecretPool`] on
//!   supported targets.
//! - Locked, pooled, and guarded canary integrity checks are available only
//!   through the explicit `canary-check` feature on supported targets.
//! - OS-CSPRNG canary generation is available only through the explicit
//!   `random-canary` feature.
//! - x86_64/AArch64 assembly-backed comparison is available only through the explicit
//!   `asm-compare` feature.
//! - High-assurance fail-closed profiles are available through `strict-ct`,
//!   `strict-canary-check`, and `require-fork-exclusion`.
//! - x86_64 cache-line eviction is available only through the explicit
//!   `cache-flush` feature.
//! - Proc-macro derives are available only through the explicit `derive`
//!   feature. The default build remains dependency-free.
//! - `zeroize`, `subtle`, and `serde` integration are available only through
//!   explicit `zeroize-interop`, `subtle-interop`, and `serde` features. They
//!   are off by default.
//! - Fixed-size lifetime enforcement is available only through the `std`
//!   feature and [`ExpiringSecretBytes`].
//! - Guard-page allocation is available only through the explicit
//!   `guard-pages` feature on supported Linux, Android, macOS, iOS, Windows,
//!   and BSD targets.
//! - WASM has no kernel page table, `mlock`, `mprotect`, or native volatile
//!   semantics. Base secret containers compile on WASM. `memory-lock` exposes
//!   volatile-only compatibility types on WASM only when `wasm-compat` is also
//!   enabled, so callers explicitly acknowledge the reduced guarantees.
//!   `guard-pages` is rejected at compile time on WASM.

#[cfg(all(
    feature = "memory-lock",
    target_arch = "wasm32",
    not(feature = "wasm-compat")
))]
compile_error!(
    "sanitization: memory-lock on wasm32 requires the wasm-compat feature; WASM has no mlock/mprotect, so this is an explicit reduced-guarantee compatibility backend"
);

#[cfg(all(feature = "guard-pages", target_arch = "wasm32"))]
compile_error!(
    "sanitization: the guard-pages feature is not supported on wasm32 because WASM linear memory has no page protection or mprotect equivalent"
);

#[cfg(all(
    feature = "canary-check",
    not(feature = "random-canary"),
    target_arch = "wasm32"
))]
compile_error!(
    "sanitization: canary-check on wasm32 requires random-canary because deterministic WASM canaries have no ASLR-backed entropy"
);

#[cfg(all(
    feature = "strict-ct",
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    not(miri)
))]
compile_error!(
    "sanitization: strict-ct requires an assembly comparison backend; currently supported on x86_64 and aarch64"
);

#[cfg(all(feature = "require-fork-exclusion", target_arch = "wasm32"))]
compile_error!(
    "sanitization: require-fork-exclusion is not supported on wasm32 because WASM has no fork inheritance policy"
);

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
    marker::PhantomData,
    mem,
    sync::atomic::{compiler_fence, Ordering},
};

#[cfg(feature = "derive")]
pub use sanitization_derive::{
    ConditionallySelectable, ConstantTimeEq, SecureSanitize, SecureSanitizeOnDrop,
};

#[cfg(feature = "random-canary")]
#[allow(unsafe_code)]
mod canary_random {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "windows",
    ))]
    use core::ffi::c_void;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    use core::arch::asm;

    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "x86_64"
    ))]
    const SYS_GETRANDOM: usize = 318;
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    ))]
    const SYS_GETRANDOM: usize = 278;

    #[cfg(target_os = "windows")]
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    const ERRNO_NO_PROGRESS: i32 = -2;
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    const EINTR: i32 = 4;
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    const EAGAIN: i32 = 11;
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    const MAX_GETRANDOM_RETRIES: usize = 16;

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    unsafe extern "C" {
        fn arc4random_buf(buf: *mut c_void, nbytes: usize);
    }

    #[cfg(target_os = "windows")]
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut c_void,
            buffer: *mut u8,
            buffer_len: u32,
            flags: u32,
        ) -> i32;
    }

    #[cfg(all(target_os = "wasi", target_env = "p1"))]
    #[link(wasm_import_module = "wasi_snapshot_preview1")]
    unsafe extern "C" {
        #[link_name = "random_get"]
        fn wasi_random_get(buf: *mut u8, buf_len: usize) -> u16;
    }

    pub(crate) fn fill(bytes: &mut [u8]) -> Result<(), i32> {
        if bytes.is_empty() {
            return Ok(());
        }

        fill_inner(bytes)
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn fill_inner(bytes: &mut [u8]) -> Result<(), i32> {
        fill_with_getrandom_syscall(bytes)
    }

    #[cfg(all(
        target_os = "android",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn fill_inner(bytes: &mut [u8]) -> Result<(), i32> {
        fill_with_getrandom_syscall(bytes)
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    fn fill_inner(bytes: &mut [u8]) -> Result<(), i32> {
        // SAFETY: `bytes` is a live mutable byte slice, and `arc4random_buf`
        // fills exactly the provided byte range without additional
        // initialization requirements.
        unsafe { arc4random_buf(bytes.as_mut_ptr().cast::<c_void>(), bytes.len()) };
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn fill_inner(bytes: &mut [u8]) -> Result<(), i32> {
        for chunk in bytes.chunks_mut(u32::MAX as usize) {
            // SAFETY: `chunk` is a live mutable byte slice. A null algorithm
            // handle with `BCRYPT_USE_SYSTEM_PREFERRED_RNG` requests the
            // system-preferred CSPRNG.
            let status = unsafe {
                BCryptGenRandom(
                    core::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status != 0 {
                return Err(status);
            }
        }
        Ok(())
    }

    #[cfg(all(target_os = "wasi", target_env = "p1"))]
    fn fill_inner(bytes: &mut [u8]) -> Result<(), i32> {
        // SAFETY: `bytes` is a live mutable byte slice. WASI preview1
        // `random_get` writes exactly the requested byte range or returns an
        // errno without retaining the pointer.
        let errno = unsafe { wasi_random_get(bytes.as_mut_ptr(), bytes.len()) };
        if errno == 0 {
            Ok(())
        } else {
            Err(errno as i32)
        }
    }

    #[cfg(not(any(
        all(
            any(target_os = "linux", target_os = "android"),
            target_arch = "x86_64"
        ),
        all(
            any(target_os = "linux", target_os = "android"),
            target_arch = "aarch64"
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "windows",
        all(target_os = "wasi", target_env = "p1"),
    )))]
    fn fill_inner(_bytes: &mut [u8]) -> Result<(), i32> {
        const ERRNO_UNSUPPORTED_PLATFORM: i32 = -1;
        Err(ERRNO_UNSUPPORTED_PLATFORM)
    }

    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn fill_with_getrandom_syscall(bytes: &mut [u8]) -> Result<(), i32> {
        let mut filled = 0;
        let mut retries = 0;
        while filled < bytes.len() {
            let ptr = bytes[filled..].as_mut_ptr() as usize;
            let len = bytes.len() - filled;
            let ret = raw_syscall3(SYS_GETRANDOM, ptr, len, 0);
            if syscall_failed(ret) {
                let errno = (-ret) as i32;
                if errno == EINTR || errno == EAGAIN {
                    retries += 1;
                    if retries > MAX_GETRANDOM_RETRIES {
                        return Err(errno);
                    }
                    continue;
                }

                return Err(errno);
            }

            if ret == 0 {
                return Err(ERRNO_NO_PROGRESS);
            }

            retries = 0;
            filled += ret as usize;
        }

        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn syscall_failed(ret: isize) -> bool {
        (-4095..=-1).contains(&ret)
    }

    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "x86_64"
    ))]
    fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
        let ret: isize;

        // SAFETY: Registers follow the Linux x86_64 syscall ABI. The caller
        // supplies the `getrandom` syscall number and pointer/length args.
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") number as isize => ret,
                in("rdi") arg1,
                in("rsi") arg2,
                in("rdx") arg3,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack)
            );
        }

        ret
    }

    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    ))]
    fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
        let ret: isize;

        // SAFETY: Registers follow the Linux aarch64 syscall ABI. The caller
        // supplies the `getrandom` syscall number and pointer/length args.
        unsafe {
            asm!(
                "svc 0",
                inlateout("x0") arg1 as isize => ret,
                in("x1") arg2,
                in("x2") arg3,
                in("x8") number,
                options(nostack)
            );
        }

        ret
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "aarch64",
    not(miri),
    any(feature = "memory-lock", feature = "guard-pages")
))]
#[allow(unsafe_code)]
mod linux_aarch64_page_size {
    use core::{
        arch::asm,
        sync::atomic::{AtomicUsize, Ordering},
    };

    const AT_NULL: usize = 0;
    const AT_PAGESZ: usize = 6;
    const AUXV_ENTRY_SIZE: usize = core::mem::size_of::<usize>() * 2;
    const CONSERVATIVE_PAGE_GRANULE: usize = 65_536;
    const MIN_PAGE_GRANULE: usize = 4096;

    const AT_FDCWD: usize = usize::MAX - 99;
    const O_RDONLY: usize = 0;
    const SYS_OPENAT: usize = 56;
    const SYS_CLOSE: usize = 57;
    const SYS_READ: usize = 63;
    const EINTR_RET: isize = -4;

    static DETECTED_PAGE_GRANULE: AtomicUsize = AtomicUsize::new(0);

    pub(crate) fn detect_page_granule() -> usize {
        let cached = DETECTED_PAGE_GRANULE.load(Ordering::Acquire);
        if cached != 0 {
            return cached;
        }

        let detected = read_auxv_page_size().unwrap_or(CONSERVATIVE_PAGE_GRANULE);
        DETECTED_PAGE_GRANULE.store(detected, Ordering::Release);
        detected
    }

    fn read_auxv_page_size() -> Option<usize> {
        let path = b"/proc/self/auxv\0";
        let fd = raw_syscall4(SYS_OPENAT, AT_FDCWD, path.as_ptr() as usize, O_RDONLY, 0);
        if syscall_failed(fd) {
            return None;
        }

        let fd = fd as usize;
        let mut pending = [0_u8; AUXV_ENTRY_SIZE];
        let mut pending_len = 0;
        let mut buffer = [0_u8; 256];

        loop {
            let read = raw_syscall3(SYS_READ, fd, buffer.as_mut_ptr() as usize, buffer.len());
            if read == EINTR_RET {
                continue;
            }

            if syscall_failed(read) || read == 0 {
                let _ = raw_syscall1(SYS_CLOSE, fd);
                return None;
            }

            for byte in buffer[..read as usize].iter().copied() {
                pending[pending_len] = byte;
                pending_len += 1;

                if pending_len == AUXV_ENTRY_SIZE {
                    let (key, value) = parse_auxv_entry(&pending);
                    pending_len = 0;

                    if key == AT_PAGESZ {
                        let _ = raw_syscall1(SYS_CLOSE, fd);
                        return valid_page_granule(value).then_some(value);
                    }

                    if key == AT_NULL {
                        let _ = raw_syscall1(SYS_CLOSE, fd);
                        return None;
                    }
                }
            }
        }
    }

    fn parse_auxv_entry(entry: &[u8; AUXV_ENTRY_SIZE]) -> (usize, usize) {
        let mut key = [0_u8; core::mem::size_of::<usize>()];
        let mut value = [0_u8; core::mem::size_of::<usize>()];
        key.copy_from_slice(&entry[..core::mem::size_of::<usize>()]);
        value.copy_from_slice(&entry[core::mem::size_of::<usize>()..]);
        (usize::from_ne_bytes(key), usize::from_ne_bytes(value))
    }

    fn valid_page_granule(value: usize) -> bool {
        (MIN_PAGE_GRANULE..=CONSERVATIVE_PAGE_GRANULE).contains(&value) && value.is_power_of_two()
    }

    fn syscall_failed(ret: isize) -> bool {
        (-4095..=-1).contains(&ret)
    }

    fn raw_syscall1(number: usize, arg1: usize) -> isize {
        raw_syscall6(number, arg1, 0, 0, 0, 0, 0)
    }

    fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
        raw_syscall6(number, arg1, arg2, arg3, 0, 0, 0)
    }

    fn raw_syscall4(number: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> isize {
        raw_syscall6(number, arg1, arg2, arg3, arg4, 0, 0)
    }

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
        // number and arguments are fixed by the wrappers above.
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

/// Sanitize a value before replacing it.
///
/// This is the safe replacement pattern for values whose previous contents may
/// hold secrets, especially enums that move from a secret-bearing variant to a
/// non-secret variant. `SecureSanitize` for derived enums can only clear the
/// currently active variant. Calling `secure_sanitize` after assigning a unit
/// or empty variant is too late; use `secure_replace` to clear first.
#[inline]
pub fn secure_replace<T: SecureSanitize>(slot: &mut T, replacement: T) {
    slot.secure_sanitize();
    *slot = replacement;
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

/// Clear ordinary mutable bytes with an explicit three-pass volatile pattern.
///
/// This API is available with the `multi-pass-clear` feature. It writes zeros,
/// then `0xFF`, then zeros again. For ordinary volatile RAM, the default
/// single-pass volatile zeroing is the normal security boundary; this helper is
/// provided for environments that need multi-pass overwrite evidence for policy
/// or audit compatibility.
#[cfg(feature = "multi-pass-clear")]
#[inline(never)]
pub fn sanitize_bytes_multi_pass(bytes: &mut [u8]) {
    wipe::volatile_multi_pass_clear(bytes.as_mut_ptr(), bytes.len());
}

#[cfg(feature = "alloc")]
#[inline(never)]
fn sanitize_vec_capacity(bytes: &mut Vec<u8>) {
    wipe::volatile_wipe(bytes.as_mut_ptr(), bytes.capacity());
    bytes.clear();
}

#[cfg(all(feature = "alloc", feature = "multi-pass-clear"))]
#[inline(never)]
fn sanitize_vec_capacity_multi_pass(bytes: &mut Vec<u8>) {
    wipe::volatile_multi_pass_clear(bytes.as_mut_ptr(), bytes.capacity());
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
    feature = "wasm-compat",
    target_arch = "wasm32"
))]
#[allow(unsafe_code)]
mod memory_lock {
    use core::{
        cell::UnsafeCell,
        fmt,
        sync::atomic::{compiler_fence, AtomicBool, Ordering},
    };

    #[cfg(feature = "canary-check")]
    const CANARY_SIZE: usize = 8;
    #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
    const CANARY_MASK: u64 = 0xDEAD_BEEF_CAFE_BABE;

    /// Platform memory-locking operation that failed.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum MemoryLockOperation {
        /// The requested storage length overflowed.
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
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct MemoryLockError {
        /// Operation that failed.
        pub operation: MemoryLockOperation,
        /// Positive errno or platform error value when available.
        ///
        /// This is `0` for local failures before a host operation. Negative
        /// values are crate-internal sentinel failures, such as an unsupported
        /// random-canary backend or a random backend that made no progress.
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
        /// Platform mapping, memory-policy, or random-canary setup failed.
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
        /// Platform mapping, memory-policy, or random-canary setup failed.
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

    struct WasmLockedStorage<const N: usize> {
        #[cfg(feature = "canary-check")]
        prefix: [u8; CANARY_SIZE],
        bytes: [u8; N],
        #[cfg(feature = "canary-check")]
        suffix: [u8; CANARY_SIZE],
    }

    impl<const N: usize> WasmLockedStorage<N> {
        #[inline]
        fn zeroed() -> Self {
            Self {
                #[cfg(feature = "canary-check")]
                prefix: [0; CANARY_SIZE],
                bytes: [0; N],
                #[cfg(feature = "canary-check")]
                suffix: [0; CANARY_SIZE],
            }
        }

        #[inline(never)]
        fn clear_all(&mut self) {
            #[cfg(feature = "canary-check")]
            crate::wipe::volatile_wipe(self.prefix.as_mut_ptr(), CANARY_SIZE);
            crate::wipe::volatile_wipe(self.bytes.as_mut_ptr(), N);
            #[cfg(feature = "canary-check")]
            crate::wipe::volatile_wipe(self.suffix.as_mut_ptr(), CANARY_SIZE);
        }
    }

    /// Fixed-size secret bytes using a WASM volatile-only compatibility backend.
    ///
    /// WASM exposes no `mlock`, `mmap`, `mprotect`, dump exclusion, or page-table
    /// control to the module. This type is therefore API-compatible with
    /// `LockedSecretBytes<N>` on native targets, but it does not actually pin
    /// memory or prevent host-runtime copies, swapping, snapshots, or dumps.
    pub struct LockedSecretBytes<const N: usize> {
        storage: UnsafeCell<WasmLockedStorage<N>>,
        #[cfg(feature = "random-canary")]
        canary: [u8; CANARY_SIZE],
    }

    // SAFETY: The value owns its inline WASM storage. Moving ownership to
    // another thread transfers that storage, and mutation/clearing requires
    // `&mut self`. `Sync` is intentionally not implemented.
    unsafe impl<const N: usize> Send for LockedSecretBytes<N> {}

    impl<const N: usize> LockedSecretBytes<N> {
        /// Allocate zeroed WASM storage for `N` bytes.
        #[inline]
        pub fn zeroed() -> Result<Self, MemoryLockError> {
            let mut secret = Self {
                storage: UnsafeCell::new(WasmLockedStorage::zeroed()),
                #[cfg(feature = "random-canary")]
                canary: random_canary_value()?,
            };
            secret.write_canaries();
            Ok(secret)
        }

        /// Returns false on WASM because no host memory lock is applied.
        #[must_use]
        #[inline]
        pub const fn is_memory_locked(&self) -> bool {
            false
        }

        /// Allocate storage, copy an array into it, then clear the input array.
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

        /// Allocate storage and copy bytes from a same-length slice.
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

        /// Allocate storage and produce each byte directly into it.
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

        /// Allocate storage and fallibly produce each byte directly into it.
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

        /// Allocate WASM-owned storage and fill the fixed-size payload in
        /// place.
        #[inline]
        pub fn from_fill(fill: impl FnOnce(&mut [u8; N])) -> Result<Self, MemoryLockError> {
            let mut secret = Self::zeroed()?;
            compiler_fence(Ordering::SeqCst);
            fill(secret.as_mut_array());
            compiler_fence(Ordering::SeqCst);
            Ok(secret)
        }

        /// Fallible variant of [`LockedSecretBytes::from_fill`].
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

        /// Number of secret bytes stored.
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
        #[inline]
        pub fn replace_from_slice(&mut self, source: &[u8]) -> Result<(), LockedSecretBytesError> {
            self.assert_canaries_intact();
            let mut replacement = Self::from_slice(source)?;
            self.secure_clear();
            core::mem::swap(self, &mut replacement);
            Ok(())
        }

        /// Replace all secret bytes from an owned array, then clear the input.
        #[inline]
        pub fn replace_from_array(&mut self, bytes: [u8; N]) -> Result<(), MemoryLockError> {
            self.assert_canaries_intact();
            let mut replacement = Self::from_array(bytes)?;
            self.secure_clear();
            core::mem::swap(self, &mut replacement);
            Ok(())
        }

        /// Replace all secret bytes with generated bytes.
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

        /// Replace all secret bytes by filling fresh WASM-owned storage.
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

        /// Run a closure with read-only access to the secret bytes.
        #[inline]
        pub fn with_secret<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
            self.assert_canaries_intact();
            inspect(self.as_array())
        }

        /// Verify canary integrity before exposing the secret bytes.
        #[cfg(feature = "canary-check")]
        #[inline]
        pub fn expose_secret_checked<R>(
            &self,
            inspect: impl FnOnce(&[u8; N]) -> R,
        ) -> Result<R, CanaryCorruptedError> {
            self.verify_integrity()?;
            Ok(inspect(self.as_array()))
        }

        /// Verify canary integrity before copying secret bytes out.
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

        /// Verify canaries.
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
        #[must_use]
        #[inline]
        pub fn constant_time_eq(&self, other: &[u8]) -> bool {
            self.assert_canaries_intact();
            crate::constant_time_eq_slices(self.as_slice(), other)
        }

        /// Clear the full WASM-owned storage with volatile writes.
        #[inline(never)]
        pub fn secure_clear(&mut self) {
            self.storage.get_mut().clear_all();
            self.write_canaries();
        }

        /// Consume this value after first clearing its storage.
        #[inline]
        pub fn into_cleared(mut self) {
            self.secure_clear();
        }

        #[inline]
        fn storage(&self) -> &WasmLockedStorage<N> {
            // SAFETY: Shared access only returns shared references. Mutation
            // through this cell is limited to explicit clear-on-corruption
            // paths which do not hand out aliases to callers.
            unsafe { &*self.storage.get() }
        }

        #[inline]
        fn as_slice(&self) -> &[u8] {
            &self.storage().bytes
        }

        #[inline]
        fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.storage.get_mut().bytes
        }

        #[inline]
        fn as_mut_array(&mut self) -> &mut [u8; N] {
            &mut self.storage.get_mut().bytes
        }

        #[inline]
        fn as_array(&self) -> &[u8; N] {
            &self.storage().bytes
        }

        #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
        #[inline]
        fn canary_value(&self) -> [u8; CANARY_SIZE] {
            CANARY_MASK.to_ne_bytes()
        }

        #[cfg(feature = "random-canary")]
        #[inline]
        fn canary_value(&self) -> [u8; CANARY_SIZE] {
            self.canary
        }

        #[cfg(feature = "canary-check")]
        #[inline]
        fn canaries_intact(&self) -> bool {
            if N == 0 {
                return true;
            }

            let expected = self.canary_value();
            crate::constant_time_eq_slices(&self.storage().prefix, &expected)
                & crate::constant_time_eq_slices(&self.storage().suffix, &expected)
        }

        #[cfg(feature = "canary-check")]
        #[inline]
        fn write_canaries(&mut self) {
            if N == 0 {
                return;
            }

            let canary = self.canary_value();
            self.storage.get_mut().prefix.copy_from_slice(&canary);
            self.storage.get_mut().suffix.copy_from_slice(&canary);
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
            // Fail-closed clearing intentionally mutates secret storage through
            // `&self`. This type is `Send` but deliberately not `Sync`, so safe
            // code cannot run this concurrently through shared references.
            // SAFETY: This path fail-closes the value and does not expose any
            // reference into the storage while mutating through `&self`.
            unsafe { (&mut *self.storage.get()).clear_all() };
        }

        #[cfg(all(test, feature = "canary-check", feature = "std"))]
        #[allow(dead_code)]
        #[inline]
        pub(crate) fn corrupt_prefix_canary_for_test(&mut self) {
            if N != 0 {
                self.storage.get_mut().prefix[0] ^= 0xFF;
            }
        }
    }

    impl<const N: usize> Drop for LockedSecretBytes<N> {
        #[inline]
        fn drop(&mut self) {
            self.secure_clear();
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
                .field("memory_locked", &false)
                .field("contents", &"<redacted>")
                .finish()
        }
    }

    struct WasmPoolSlotStorage<const N: usize> {
        #[cfg(feature = "canary-check")]
        prefix: [u8; CANARY_SIZE],
        bytes: [u8; N],
        #[cfg(feature = "canary-check")]
        suffix: [u8; CANARY_SIZE],
    }

    impl<const N: usize> WasmPoolSlotStorage<N> {
        #[inline]
        fn zeroed() -> Self {
            Self {
                #[cfg(feature = "canary-check")]
                prefix: [0; CANARY_SIZE],
                bytes: [0; N],
                #[cfg(feature = "canary-check")]
                suffix: [0; CANARY_SIZE],
            }
        }

        #[inline(never)]
        fn clear_all(&mut self) {
            #[cfg(feature = "canary-check")]
            crate::wipe::volatile_wipe(self.prefix.as_mut_ptr(), CANARY_SIZE);
            crate::wipe::volatile_wipe(self.bytes.as_mut_ptr(), N);
            #[cfg(feature = "canary-check")]
            crate::wipe::volatile_wipe(self.suffix.as_mut_ptr(), CANARY_SIZE);
        }
    }

    /// Fixed-slot arena for many same-size WASM-owned secrets.
    ///
    /// This mirrors the native `SecretPool<N, SLOTS>` API, but no WASM memory
    /// can be locked against host swapping, snapshots, or dumps.
    pub struct SecretPool<const N: usize, const SLOTS: usize> {
        slots: [UnsafeCell<WasmPoolSlotStorage<N>>; SLOTS],
        used: [AtomicBool; SLOTS],
    }

    /// A live fixed-size secret slot allocated from a [`SecretPool`].
    pub struct SecretPoolSlot<'pool, const N: usize, const SLOTS: usize> {
        slot_index: usize,
        pool: &'pool SecretPool<N, SLOTS>,
        #[cfg(feature = "random-canary")]
        canary: [u8; CANARY_SIZE],
    }

    // SAFETY: The pool uses an atomic bitmap to ensure only one safe live slot
    // handle exists for each `UnsafeCell` at a time.
    unsafe impl<const N: usize, const SLOTS: usize> Send for SecretPool<N, SLOTS> {}
    // SAFETY: Shared pool allocation is coordinated by the atomic bitmap.
    unsafe impl<const N: usize, const SLOTS: usize> Sync for SecretPool<N, SLOTS> {}
    // SAFETY: Moving a slot transfers the unique live handle for that slot.
    unsafe impl<'pool, const N: usize, const SLOTS: usize> Send for SecretPoolSlot<'pool, N, SLOTS> {}

    impl<const N: usize, const SLOTS: usize> SecretPool<N, SLOTS> {
        /// Create a WASM volatile-only pool with `SLOTS` slots of `N` bytes.
        #[inline]
        pub fn new() -> Result<Self, MemoryLockError> {
            Ok(Self {
                slots: core::array::from_fn(|_| UnsafeCell::new(WasmPoolSlotStorage::zeroed())),
                used: core::array::from_fn(|_| AtomicBool::new(false)),
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

        /// Returns zero on WASM because no host memory lock is applied.
        #[must_use]
        #[inline]
        pub const fn locked_len(&self) -> usize {
            0
        }

        /// Count slots that are currently available.
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
        /// With `random-canary`, operating-system CSPRNG failure is reported as
        /// `None`. Use [`SecretPool::try_allocate`] when the caller needs to
        /// distinguish pool exhaustion from random-canary setup failure.
        #[must_use = "CSPRNG failure also returns None; use try_allocate() to distinguish failures from exhaustion"]
        #[inline]
        pub fn allocate(&self) -> Option<SecretPoolSlot<'_, N, SLOTS>> {
            self.try_allocate().unwrap_or_default()
        }

        /// Allocate one unused slot and report random-canary setup errors.
        #[inline]
        pub fn try_allocate(
            &self,
        ) -> Result<Option<SecretPoolSlot<'_, N, SLOTS>>, MemoryLockError> {
            for (slot_index, flag) in self.used.iter().enumerate() {
                if flag
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    let mut slot = SecretPoolSlot {
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

        /// Allocate a slot, copy an owned array into it, then clear the input.
        #[inline]
        pub fn allocate_from_array(
            &self,
            mut bytes: [u8; N],
        ) -> Option<SecretPoolSlot<'_, N, SLOTS>> {
            let slot = match self.allocate() {
                Some(mut slot) => {
                    let _ = slot.copy_from_slice(&bytes);
                    Some(slot)
                }
                None => None,
            };

            crate::sanitize_bytes(&mut bytes);
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
                match make_byte(index) {
                    Ok(byte) => slot.as_mut_slice()[index] = byte,
                    Err(error) => return Err(error),
                }
                index += 1;
            }
            compiler_fence(Ordering::SeqCst);
            Ok(Some(slot))
        }

        /// Clear every slot and mark all slots available.
        #[inline(never)]
        pub fn secure_clear(&mut self) {
            for slot in self.slots.iter_mut() {
                slot.get_mut().clear_all();
            }

            for flag in self.used.iter() {
                flag.store(false, Ordering::Release);
            }
            compiler_fence(Ordering::SeqCst);
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

        /// Replace all slot bytes from an owned array, then clear the input.
        #[inline]
        pub fn replace_from_array(&mut self, mut bytes: [u8; N]) {
            self.assert_canaries_intact();
            self.as_mut_slice().copy_from_slice(&bytes);
            compiler_fence(Ordering::SeqCst);
            crate::sanitize_bytes(&mut bytes);
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
        #[inline]
        pub fn with_secret<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
            self.assert_canaries_intact();
            inspect(self.as_array())
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
        #[must_use]
        #[inline]
        pub fn constant_time_eq(&self, other: &[u8]) -> bool {
            self.assert_canaries_intact();
            crate::constant_time_eq_slices(self.as_slice(), other)
        }

        /// Clear only this slot with volatile writes.
        #[inline(never)]
        pub fn secure_clear(&mut self) {
            self.storage_mut().clear_all();
            self.write_canaries();
        }

        /// Consume this slot after clearing it, then return it to the pool.
        #[inline]
        pub fn into_cleared(mut self) {
            self.secure_clear();
        }

        #[inline]
        fn storage(&self) -> &WasmPoolSlotStorage<N> {
            // SAFETY: A live slot means this handle owns the only safe access
            // to the selected cell until Drop releases the bitmap flag.
            unsafe { &*self.pool.slots[self.slot_index].get() }
        }

        #[inline]
        fn storage_mut(&mut self) -> &mut WasmPoolSlotStorage<N> {
            // SAFETY: `&mut self` gives exclusive access to the live slot
            // handle, and the pool bitmap prevents another handle for the same
            // slot.
            unsafe { &mut *self.pool.slots[self.slot_index].get() }
        }

        #[inline]
        fn as_slice(&self) -> &[u8] {
            &self.storage().bytes
        }

        #[inline]
        fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.storage_mut().bytes
        }

        #[inline]
        fn as_array(&self) -> &[u8; N] {
            &self.storage().bytes
        }

        #[inline]
        fn as_array_mut(&mut self) -> &mut [u8; N] {
            &mut self.storage_mut().bytes
        }

        #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
        #[inline]
        fn canary_value(&self) -> [u8; CANARY_SIZE] {
            ((self.storage().bytes.as_ptr() as u64) ^ CANARY_MASK).to_ne_bytes()
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
            crate::constant_time_eq_slices(&self.storage().prefix, &expected)
                & crate::constant_time_eq_slices(&self.storage().suffix, &expected)
        }

        #[cfg(feature = "canary-check")]
        #[inline]
        fn write_canaries(&mut self) {
            if N == 0 {
                return;
            }

            let canary = self.canary_value();
            self.storage_mut().prefix.copy_from_slice(&canary);
            self.storage_mut().suffix.copy_from_slice(&canary);
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
            // Fail-closed clearing intentionally mutates slot storage through
            // `&self`. Slot handles are `Send` but deliberately not `Sync`, and
            // the parent bitmap prevents a second safe handle for this slot.
            // SAFETY: This path fail-closes the slot and does not expose any
            // reference into the storage while mutating through `&self`.
            unsafe { (&mut *self.pool.slots[self.slot_index].get()).clear_all() };
        }

        #[cfg(all(test, feature = "canary-check", feature = "std"))]
        #[allow(dead_code)]
        #[inline]
        pub(crate) fn corrupt_prefix_canary_for_test(&mut self) {
            if N != 0 {
                self.storage_mut().prefix[0] ^= 0xFF;
            }
        }
    }

    impl<const N: usize, const SLOTS: usize> Drop for SecretPool<N, SLOTS> {
        #[inline]
        fn drop(&mut self) {
            self.secure_clear();
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

    impl<'pool, const N: usize, const SLOTS: usize> crate::SecureSanitize
        for SecretPoolSlot<'pool, N, SLOTS>
    {
        #[inline]
        fn secure_sanitize(&mut self) {
            self.secure_clear();
        }
    }

    impl<const N: usize, const SLOTS: usize> fmt::Debug for SecretPool<N, SLOTS> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SecretPool")
                .field("slot_size", &N)
                .field("capacity_slots", &SLOTS)
                .field("locked_len", &0)
                .field("memory_locked", &false)
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
        crate::canary_random::fill(&mut canary).map_err(|errno| MemoryLockError {
            operation: MemoryLockOperation::Random,
            errno,
        })?;
        Ok(canary)
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
    )
))]
#[allow(unsafe_code)]
mod memory_lock {
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
        pub fn with_secret<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
            self.assert_canaries_intact();
            inspect(self.as_array())
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
                crate::wipe::volatile_wipe(self.ptr.as_ptr(), self.map_len);
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
                crate::wipe::volatile_wipe(self.ptr.as_ptr(), self.map_len);
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
                crate::wipe::volatile_wipe(spare.as_mut_ptr(), spare.len());
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
                crate::wipe::volatile_wipe(self.ptr.as_ptr(), self.map_len);
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
            let mut index = 0;
            while index < len {
                self.as_mut_capacity_slice()[index] = make_byte(index);
                index += 1;
            }
            self.finish_initialization(len);
        }

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
                core::slice::from_raw_parts(
                    self.ptr.as_ptr().add(CANARY_SIZE + self.len),
                    CANARY_SIZE,
                )
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
                crate::wipe::volatile_wipe(self.ptr.as_ptr(), self.map_len);
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
                    used,
                });
            }

            let map_len = rounded_mapping_len(total_bytes)?;
            let base = map_private(map_len)?;

            if let Err(error) = mark_dontdump(base, map_len) {
                let _ = unmap_private(base, map_len);
                return Err(error);
            }

            if let Err(error) = mark_dontfork(base, map_len) {
                let _ = unmap_private(base, map_len);
                return Err(error);
            }

            if let Err(error) = lock_mapping(base, map_len) {
                let _ = unmap_private(base, map_len);
                return Err(error);
            }

            Ok(Self {
                base,
                map_len,
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
        pub fn try_allocate(
            &self,
        ) -> Result<Option<SecretPoolSlot<'_, N, SLOTS>>, MemoryLockError> {
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
        pub fn allocate_from_array(
            &self,
            mut bytes: [u8; N],
        ) -> Option<SecretPoolSlot<'_, N, SLOTS>> {
            let slot = match self.allocate() {
                Some(mut slot) => {
                    let _ = slot.copy_from_slice(&bytes);
                    Some(slot)
                }
                None => None,
            };

            crate::sanitize_bytes(&mut bytes);
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
                match make_byte(index) {
                    Ok(byte) => slot.as_mut_slice()[index] = byte,
                    Err(error) => return Err(error),
                }
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
                crate::wipe::volatile_wipe(self.base.as_ptr(), self.map_len);
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

            let offset = slot_index.checked_mul(Self::slot_stride().ok()?)?;
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
            crate::sanitize_bytes(&mut bytes);
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
        pub fn with_secret<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
            self.assert_canaries_intact();
            inspect(self.as_array())
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
                crate::wipe::volatile_wipe(self.ptr.as_ptr(), self.slot_stride());
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
            Self::slot_stride_static().unwrap_or(0)
        }

        #[cfg(feature = "canary-check")]
        #[inline]
        fn slot_stride_static() -> Result<usize, MemoryLockError> {
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
        fn slot_stride_static() -> Result<usize, MemoryLockError> {
            Ok(N)
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
                crate::wipe::volatile_wipe(self.ptr.as_ptr(), self.slot_stride());
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

    impl<'pool, const N: usize, const SLOTS: usize> crate::SecureSanitize
        for SecretPoolSlot<'pool, N, SLOTS>
    {
        #[inline]
        fn secure_sanitize(&mut self) {
            self.secure_clear();
        }
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
        crate::canary_random::fill(&mut canary).map_err(|errno| MemoryLockError {
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
        crate::linux_aarch64_page_size::detect_page_granule()
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
    feature = "asm-compare",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[allow(unsafe_code)]
mod compare_asm {
    use core::arch::asm;

    #[inline(never)]
    pub(crate) fn constant_time_eq_equal_len(left: &[u8], right: &[u8]) -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            constant_time_eq_equal_len_x86_64(left, right)
        }

        #[cfg(target_arch = "aarch64")]
        {
            constant_time_eq_equal_len_aarch64(left, right)
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(never)]
    fn constant_time_eq_equal_len_x86_64(left: &[u8], right: &[u8]) -> bool {
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
        // The assembly loop ORs byte differences into the low accumulator byte.
        // Mask explicitly so the observable Rust contract does not depend on
        // readers inferring that the full register was zeroed before the loop.
        core::hint::black_box(diff & 0xFF) == 0
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(never)]
    fn constant_time_eq_equal_len_aarch64(left: &[u8], right: &[u8]) -> bool {
        debug_assert_eq!(left.len(), right.len());

        let mut left_ptr = left.as_ptr();
        let mut right_ptr = right.as_ptr();
        let mut remaining = left.len();
        let mut diff: u32 = 0;
        let tmp_left: u32;
        let tmp_right: u32;

        // SAFETY: The public caller checks that both slices have the same
        // length. The loop reads exactly `remaining` bytes from each valid
        // slice, never writes memory, and does not expose the raw pointers.
        unsafe {
            asm!(
                "cbz {remaining}, 3f",
                "2:",
                "ldrb {tmp_left:w}, [{left_ptr}], #1",
                "ldrb {tmp_right:w}, [{right_ptr}], #1",
                "eor {tmp_left:w}, {tmp_left:w}, {tmp_right:w}",
                "orr {diff:w}, {diff:w}, {tmp_left:w}",
                "subs {remaining}, {remaining}, #1",
                "b.ne 2b",
                "3:",
                left_ptr = inout(reg) left_ptr,
                right_ptr = inout(reg) right_ptr,
                remaining = inout(reg) remaining,
                diff = inout(reg) diff,
                tmp_left = lateout(reg) tmp_left,
                tmp_right = lateout(reg) tmp_right,
                options(nostack, readonly)
            );
        }

        let _ = (left_ptr, right_ptr, remaining, tmp_left, tmp_right);
        core::hint::black_box(diff & 0xFF) == 0
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

/// Architecture-specific register scrubbing helpers.
///
/// This module is available with the `register-scrub` feature. It is an
/// explicit best-effort boundary for code that wants to clear caller-saved SIMD
/// registers after cryptographic routines. It does not and cannot clear
/// registers saved by the compiler, callee-saved vector state,
/// kernel context-switch buffers, or registers owned by other threads.
#[cfg(feature = "register-scrub")]
#[allow(unsafe_code)]
pub mod register_scrub {
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    use core::sync::atomic::AtomicU8;
    use core::sync::atomic::{compiler_fence, Ordering};

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    const AVX_UNKNOWN: u8 = 0;
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    const AVX_SUPPORTED: u8 = 1;
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    const AVX_NOT_SUPPORTED: u8 = 2;

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    static AVX_STATE: AtomicU8 = AtomicU8::new(AVX_UNKNOWN);

    /// Best-effort scrub of architecture SIMD/vector registers supported by
    /// this crate.
    ///
    /// On unsupported architectures this is a fenced no-op. On x86_64 it
    /// clears caller-saved XMM0-XMM5 and, when AVX OS support is detected,
    /// clears AVX upper register state. Non-Windows x86_64 targets use
    /// `vzeroall` when AVX is available; Windows x64 uses `vzeroupper` to avoid
    /// clobbering ABI-preserved XMM6-XMM15 lower halves. On AArch64 it clears
    /// caller-saved V0-V7 and V16-V31. Call this immediately after a
    /// cryptographic routine that may have left key material in vector
    /// registers.
    ///
    /// This is not complete register-file erasure. AVX-512 opmask registers
    /// and ZMM16-ZMM31 are not scrubbed, and AArch64 V8-V15 upper halves are
    /// intentionally not modified because Rust inline assembly cannot express
    /// that partial-register clobber safely.
    #[inline(never)]
    pub fn scrub_simd_registers() {
        compiler_fence(Ordering::SeqCst);

        #[cfg(all(target_arch = "x86_64", not(miri)))]
        scrub_x86_64_simd_registers();

        #[cfg(all(target_arch = "aarch64", not(miri)))]
        scrub_aarch64_neon_registers();

        compiler_fence(Ordering::SeqCst);
    }

    /// Clear x86_64 XMM registers with zeroing instructions.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[inline(never)]
    pub fn scrub_x86_64_simd_registers() {
        if avx_os_supported() {
            scrub_x86_64_avx_registers();
        } else {
            scrub_x86_64_sse_registers();
        }
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[inline(never)]
    fn scrub_x86_64_sse_registers() {
        // SAFETY: These instructions write only caller-saved architectural
        // SIMD registers in the current thread. They do not read or write
        // memory.
        unsafe {
            core::arch::asm!(
                "pxor xmm0, xmm0",
                "pxor xmm1, xmm1",
                "pxor xmm2, xmm2",
                "pxor xmm3, xmm3",
                "pxor xmm4, xmm4",
                "pxor xmm5, xmm5",
                out("xmm0") _,
                out("xmm1") _,
                out("xmm2") _,
                out("xmm3") _,
                out("xmm4") _,
                out("xmm5") _,
                options(nostack, nomem, preserves_flags)
            );
        }
    }

    #[cfg(all(target_arch = "x86_64", not(target_os = "windows"), not(miri)))]
    #[inline(never)]
    fn scrub_x86_64_avx_registers() {
        // SAFETY: `avx_os_supported` verified AVX and XMM/YMM OS save support.
        // On non-Windows x86_64 ABIs, XMM/YMM registers are caller-saved. The
        // instruction does not read or write memory.
        unsafe {
            core::arch::asm!(
                "vzeroall",
                out("xmm0") _,
                out("xmm1") _,
                out("xmm2") _,
                out("xmm3") _,
                out("xmm4") _,
                out("xmm5") _,
                out("xmm6") _,
                out("xmm7") _,
                out("xmm8") _,
                out("xmm9") _,
                out("xmm10") _,
                out("xmm11") _,
                out("xmm12") _,
                out("xmm13") _,
                out("xmm14") _,
                out("xmm15") _,
                options(nostack, nomem, preserves_flags)
            );
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "windows", not(miri)))]
    #[inline(never)]
    fn scrub_x86_64_avx_registers() {
        scrub_x86_64_sse_registers();
        // SAFETY: `avx_os_supported` verified AVX and XMM/YMM OS save support.
        // `vzeroupper` clears the upper vector state without clobbering the
        // ABI-preserved lower halves of XMM6-XMM15 on Windows x64.
        unsafe {
            core::arch::asm!("vzeroupper", options(nostack, nomem, preserves_flags));
        }
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[inline]
    fn avx_os_supported() -> bool {
        let cached = AVX_STATE.load(Ordering::Relaxed);
        if cached != AVX_UNKNOWN {
            return cached == AVX_SUPPORTED;
        }

        // Benign init race: `detect_avx_os_support` is pure and idempotent.
        // Concurrent first callers may repeat CPUID/XGETBV detection, but all
        // writers store the same value and no other state depends on ordering.
        let detected = detect_avx_os_support();
        AVX_STATE.store(
            if detected {
                AVX_SUPPORTED
            } else {
                AVX_NOT_SUPPORTED
            },
            Ordering::Relaxed,
        );
        detected
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[inline]
    fn detect_avx_os_support() -> bool {
        const CPUID_1_ECX_OSXSAVE: u32 = 1 << 27;
        const CPUID_1_ECX_AVX: u32 = 1 << 28;
        const XCR0_XMM: u64 = 1 << 1;
        const XCR0_YMM: u64 = 1 << 2;

        // SAFETY: `cpuid` and `xgetbv` query CPU/OS feature state and do not
        // access memory. `_xgetbv(0)` is executed only when CPUID reports
        // OSXSAVE support.
        unsafe {
            let cpuid = core::arch::x86_64::__cpuid_count(1, 0);
            if (cpuid.ecx & (CPUID_1_ECX_OSXSAVE | CPUID_1_ECX_AVX))
                != (CPUID_1_ECX_OSXSAVE | CPUID_1_ECX_AVX)
            {
                return false;
            }

            let xcr0 = core::arch::x86_64::_xgetbv(0);
            (xcr0 & (XCR0_XMM | XCR0_YMM)) == (XCR0_XMM | XCR0_YMM)
        }
    }

    /// Clear AArch64 NEON vector registers with zeroing instructions.
    #[cfg(all(target_arch = "aarch64", not(miri)))]
    #[inline(never)]
    pub fn scrub_aarch64_neon_registers() {
        // SAFETY: These instructions write only architectural vector registers
        // in the current thread. They do not read or write memory.
        unsafe {
            core::arch::asm!(
                "eor v0.16b, v0.16b, v0.16b",
                "eor v1.16b, v1.16b, v1.16b",
                "eor v2.16b, v2.16b, v2.16b",
                "eor v3.16b, v3.16b, v3.16b",
                "eor v4.16b, v4.16b, v4.16b",
                "eor v5.16b, v5.16b, v5.16b",
                "eor v6.16b, v6.16b, v6.16b",
                "eor v7.16b, v7.16b, v7.16b",
                "eor v16.16b, v16.16b, v16.16b",
                "eor v17.16b, v17.16b, v17.16b",
                "eor v18.16b, v18.16b, v18.16b",
                "eor v19.16b, v19.16b, v19.16b",
                "eor v20.16b, v20.16b, v20.16b",
                "eor v21.16b, v21.16b, v21.16b",
                "eor v22.16b, v22.16b, v22.16b",
                "eor v23.16b, v23.16b, v23.16b",
                "eor v24.16b, v24.16b, v24.16b",
                "eor v25.16b, v25.16b, v25.16b",
                "eor v26.16b, v26.16b, v26.16b",
                "eor v27.16b, v27.16b, v27.16b",
                "eor v28.16b, v28.16b, v28.16b",
                "eor v29.16b, v29.16b, v29.16b",
                "eor v30.16b, v30.16b, v30.16b",
                "eor v31.16b, v31.16b, v31.16b",
                out("v0") _,
                out("v1") _,
                out("v2") _,
                out("v3") _,
                out("v4") _,
                out("v5") _,
                out("v6") _,
                out("v7") _,
                out("v16") _,
                out("v17") _,
                out("v18") _,
                out("v19") _,
                out("v20") _,
                out("v21") _,
                out("v22") _,
                out("v23") _,
                out("v24") _,
                out("v25") _,
                out("v26") _,
                out("v27") _,
                out("v28") _,
                out("v29") _,
                out("v30") _,
                out("v31") _,
                options(nostack, nomem)
            );
        }
    }
}

/// Traits for integrating external hardware-backed secret providers.
///
/// This module is available with the `hardware-secrets` feature. It deliberately
/// defines only trait surfaces and small error types; it does not claim built-in
/// SGX, Nitro, TPM, HSM, or enclave support. Backend crates can implement these
/// traits while keeping vendor SDKs and platform dependencies out of the main
/// crate.
#[cfg(feature = "hardware-secrets")]
pub mod hardware {
    use core::fmt;

    /// Broad class of hardware-backed provider failure.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum HardwareSecretErrorKind {
        /// The backend is unavailable on this host.
        Unavailable,
        /// The backend denied access to the requested secret.
        AccessDenied,
        /// The caller provided an invalid or stale handle.
        InvalidHandle,
        /// The caller-provided output buffer is too small.
        OutputTooSmall,
        /// Backend-specific failure.
        Backend,
    }

    /// Small dependency-free error type for hardware-backed secret providers.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct HardwareSecretError {
        /// Failure class.
        pub kind: HardwareSecretErrorKind,
        /// Optional platform or backend error code. `0` means unavailable.
        pub code: i32,
    }

    impl fmt::Display for HardwareSecretError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "hardware secret operation {:?} failed with code {}",
                self.kind, self.code
            )
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for HardwareSecretError {}

    /// Marker trait for opaque handles owned by a hardware-backed provider.
    pub trait HardwareSecretHandle {}

    /// Provider interface for secrets that live outside ordinary process
    /// memory until deliberately exposed through a closure.
    pub trait HardwareSecretProvider {
        /// Opaque backend-owned handle type.
        type Handle: HardwareSecretHandle;
        /// Backend-specific error type.
        type Error;

        /// Seal or import a byte slice into the backend and return a handle.
        fn seal_from_slice(&self, secret: &[u8]) -> Result<Self::Handle, Self::Error>;

        /// Expose a backend secret for the duration of a closure.
        fn expose_secret<R, F: FnOnce(&[u8]) -> R>(
            &self,
            handle: &Self::Handle,
            inspect: F,
        ) -> Result<R, Self::Error>;

        /// Replace the value behind an existing backend handle.
        fn rotate_from_slice(
            &self,
            handle: &mut Self::Handle,
            secret: &[u8],
        ) -> Result<(), Self::Error>;

        /// Destroy a backend handle if the provider has an explicit deletion
        /// operation. Providers without one may make this a no-op.
        fn destroy(&self, handle: Self::Handle) -> Result<(), Self::Error>;
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
            #[cfg(feature = "random-canary")]
            let canary = random_canary_value().map_err(|error| GuardPageError {
                operation: error.operation,
                errno: error.errno,
            })?;

            let page_granule = platform_page_granule();
            let data_capacity = guarded_payload_capacity(capacity)?;
            let writable_len = guarded_writable_len(data_capacity)?;
            let total_len = writable_len
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

            if let Err(error) = protect_data(data, writable_len) {
                let _ = unmap_guarded(base, total_len);
                return Err(error);
            }

            #[cfg(feature = "memory-lock")]
            if locked {
                if let Err(error) = mark_dontdump(data, writable_len) {
                    let _ = unmap_guarded(base, total_len);
                    return Err(error);
                }

                if let Err(error) = mark_dontfork(data, writable_len) {
                    let _ = unmap_guarded(base, total_len);
                    return Err(error);
                }

                if let Err(error) = lock_mapping(data, writable_len) {
                    let _ = unmap_guarded(base, total_len);
                    return Err(error);
                }
            }

            let mut secret = Self {
                base,
                data,
                map_len: total_len,
                writable_len,
                data_capacity,
                len: 0,
                locked,
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
            self.assert_canaries_intact();
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
            self.assert_canaries_intact();
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
            crate::wipe::volatile_wipe(self.data.as_ptr(), self.writable_len);
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
            let mut replacement = Self::with_capacity_locked_state(next_capacity, self.locked)?;
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

            let mut index = 0;
            while index < len {
                self.as_mut_capacity_slice()[index] = make_byte(index);
                index += 1;
            }

            self.finish_initialization(len);
        }

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

        #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
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
                core::slice::from_raw_parts(
                    self.data.as_ptr().add(CANARY_SIZE + self.len),
                    CANARY_SIZE,
                )
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
            crate::wipe::volatile_wipe(self.data.as_ptr(), self.writable_len);
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
                .field("writable_len", &self.writable_len)
                .field("memory_locked", &self.locked)
                .field("contents", &"<redacted>")
                .finish()
        }
    }

    #[cfg(feature = "random-canary")]
    fn random_canary_value() -> Result<[u8; CANARY_SIZE], GuardPageError> {
        let mut canary = [0; CANARY_SIZE];
        crate::canary_random::fill(&mut canary).map_err(|errno| GuardPageError {
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
        crate::linux_aarch64_page_size::detect_page_granule()
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

impl<T> SecureSanitize for PhantomData<T> {
    #[inline]
    fn secure_sanitize(&mut self) {}
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
        wipe::volatile_wipe(
            self.as_mut_ptr().cast::<u8>(),
            self.capacity().saturating_mul(core::mem::size_of::<T>()),
        );
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

/// Data-oblivious primitives for secret-handling code.
///
/// This module intentionally uses the familiar `ct` name, but its documented
/// claim is narrower than "identical wall-clock time": APIs here are designed
/// to avoid secret-dependent control flow and secret-dependent memory access
/// under documented compiler, target, feature, and release-profile conditions.
///
/// Lengths, allocation behavior, panics, page faults, scheduling, and the final
/// decision to branch on a secret-derived result are public effects. Use
/// [`ct::Choice::declassify`] at that boundary so reviewers can search for it.
pub mod ct {
    use core::{cmp::Ordering, fmt, hint::black_box, marker::PhantomData, ops};

    /// Opaque normalized 0/1 value used by data-oblivious operations.
    ///
    /// `Choice` is for secret-derived booleans that should remain branchless
    /// while they are combined, selected on, or carried through `CtOption` and
    /// `CtResult`. Turning a `Choice` into a normal `bool` is declassification
    /// and should happen only through [`Choice::declassify`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Default, Eq, PartialEq)]
    pub struct Choice(u8);

    impl Choice {
        /// Public false choice.
        pub const FALSE: Self = Self(0);

        /// Public true choice.
        pub const TRUE: Self = Self(1);

        /// Normalize any non-zero byte into `1` and zero into `0`.
        #[inline]
        pub const fn from_u8(value: u8) -> Self {
            Self(((value | value.wrapping_neg()) >> 7) & 1)
        }

        /// Convert a public boolean into a `Choice`.
        ///
        /// This is safe for public control values. Do not use normal `bool`
        /// values for secret-derived decisions before they have been explicitly
        /// declassified.
        #[inline]
        pub const fn from_public_bool(value: bool) -> Self {
            Self(value as u8)
        }

        /// Return the normalized 0/1 byte without converting to a branchable
        /// `bool`.
        #[inline]
        pub fn unwrap_u8(self) -> u8 {
            black_box(self.0 & 1)
        }

        /// Explicitly convert this choice into a public boolean.
        ///
        /// The `reason` string is intentionally required so security reviews
        /// can search for every declassification boundary and check that the
        /// branch result is meant to be public, such as an authentication
        /// accept/reject decision.
        #[inline]
        pub fn declassify(self, reason: &'static str) -> bool {
            black_box(reason);
            self.unwrap_u8() == 1
        }

        /// Branchless logical AND.
        #[inline]
        pub fn and(self, other: Self) -> Self {
            Self((self.unwrap_u8() & other.unwrap_u8()) & 1)
        }

        /// Branchless logical OR.
        #[inline]
        pub fn or(self, other: Self) -> Self {
            Self((self.unwrap_u8() | other.unwrap_u8()) & 1)
        }

        /// Branchless logical XOR.
        #[inline]
        pub fn xor(self, other: Self) -> Self {
            Self((self.unwrap_u8() ^ other.unwrap_u8()) & 1)
        }

        /// Branchless logical NOT.
        #[inline]
        pub fn not_choice(self) -> Self {
            Self(self.unwrap_u8() ^ 1)
        }
    }

    impl fmt::Debug for Choice {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("Choice(..)")
        }
    }

    impl From<u8> for Choice {
        #[inline]
        fn from(value: u8) -> Self {
            Self::from_u8(value)
        }
    }

    impl ops::BitAnd for Choice {
        type Output = Self;

        #[inline]
        fn bitand(self, rhs: Self) -> Self::Output {
            self.and(rhs)
        }
    }

    impl ops::BitOr for Choice {
        type Output = Self;

        #[inline]
        fn bitor(self, rhs: Self) -> Self::Output {
            self.or(rhs)
        }
    }

    impl ops::BitXor for Choice {
        type Output = Self;

        #[inline]
        fn bitxor(self, rhs: Self) -> Self::Output {
            self.xor(rhs)
        }
    }

    impl ops::Not for Choice {
        type Output = Self;

        #[inline]
        fn not(self) -> Self::Output {
            self.not_choice()
        }
    }

    impl ConditionallySelectable for Choice {
        #[inline]
        fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
            Self(u8::conditional_select(&left.0, &right.0, choice) & 1)
        }
    }

    /// Native data-oblivious equality trait.
    ///
    /// For slices, length is public: length mismatch may return immediately,
    /// while equal-length inputs must compare all elements.
    pub trait ConstantTimeEq<Rhs: ?Sized = Self> {
        /// Compare without secret-dependent early exit.
        fn ct_eq(&self, other: &Rhs) -> Choice;

        /// Negated [`ConstantTimeEq::ct_eq`].
        #[inline]
        fn ct_ne(&self, other: &Rhs) -> Choice {
            !self.ct_eq(other)
        }
    }

    /// Branchless selection between two values.
    pub trait ConditionallySelectable: Sized {
        /// Return `left` when `choice` is false and `right` when it is true.
        fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self;
    }

    /// Branchless assignment under a [`Choice`].
    pub trait ConditionallyAssignable: ConditionallySelectable {
        /// Assign `other` to `self` when `choice` is true.
        #[inline]
        fn conditional_assign(&mut self, other: &Self, choice: Choice) {
            *self = Self::conditional_select(self, other, choice);
        }
    }

    impl<T: ConditionallySelectable> ConditionallyAssignable for T {}

    /// Data-oblivious ordering result.
    ///
    /// Exactly one of the three choices should be true. Converting the result
    /// into [`Ordering`] is a public branch boundary and must go through
    /// [`CtOrdering::declassify`].
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct CtOrdering {
        less: Choice,
        equal: Choice,
        greater: Choice,
    }

    impl CtOrdering {
        /// Equal ordering.
        pub const EQUAL: Self = Self {
            less: Choice::FALSE,
            equal: Choice::TRUE,
            greater: Choice::FALSE,
        };

        /// Less-than ordering.
        pub const LESS: Self = Self {
            less: Choice::TRUE,
            equal: Choice::FALSE,
            greater: Choice::FALSE,
        };

        /// Greater-than ordering.
        pub const GREATER: Self = Self {
            less: Choice::FALSE,
            equal: Choice::FALSE,
            greater: Choice::TRUE,
        };

        /// Construct an ordering from hidden choice bits.
        ///
        /// If multiple bits are supplied, the value is normalized to one
        /// public ordering using `less`, then `greater`, then `equal`
        /// precedence. If no bit is supplied, the value normalizes to
        /// [`CtOrdering::EQUAL`].
        #[inline]
        pub const fn new(less: Choice, _equal: Choice, greater: Choice) -> Self {
            if less.0 & 1 == 1 {
                Self::LESS
            } else if greater.0 & 1 == 1 {
                Self::GREATER
            } else {
                Self::EQUAL
            }
        }

        /// Construct an ordering from already-normalized internal bits.
        ///
        /// Callers must provide exactly one true bit. This preserves hidden
        /// accumulators from internal comparison routines without passing them
        /// through the public lossy normalizing constructor.
        #[inline]
        const fn from_normalized_bits(less: Choice, equal: Choice, greater: Choice) -> Self {
            debug_assert!(
                (less.0 & 1) + (equal.0 & 1) + (greater.0 & 1) == 1,
                "from_normalized_bits: caller must supply exactly one true bit"
            );
            Self {
                less,
                equal,
                greater,
            }
        }

        /// Return the hidden less-than bit.
        #[inline]
        pub const fn is_less(&self) -> Choice {
            self.less
        }

        /// Return the hidden equality bit.
        #[inline]
        pub const fn is_equal(&self) -> Choice {
            self.equal
        }

        /// Return the hidden greater-than bit.
        #[inline]
        pub const fn is_greater(&self) -> Choice {
            self.greater
        }

        /// Explicitly convert this ordering into a public [`Ordering`].
        ///
        /// The `reason` string is intentionally required so security reviews
        /// can search for every comparison declassification boundary.
        #[inline]
        pub fn declassify(self, reason: &'static str) -> Ordering {
            black_box(reason);
            // Fields are private and constructors normalize today. Keep this
            // as a future-refactor guard for any internal constructors.
            debug_assert_eq!(
                (self.less.0 & 1) + (self.equal.0 & 1) + (self.greater.0 & 1),
                1,
                "CtOrdering must have exactly one bit set"
            );
            if self.less.unwrap_u8() == 1 {
                Ordering::Less
            } else if self.greater.unwrap_u8() == 1 {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        }
    }

    /// Native data-oblivious ordering trait.
    ///
    /// Implementations avoid secret-dependent early exit. For variable-length
    /// inputs, length remains public metadata unless a specific API states
    /// otherwise.
    pub trait ConstantTimeOrd<Rhs: ?Sized = Self> {
        /// Compare without secret-dependent early exit.
        fn ct_cmp(&self, other: &Rhs) -> CtOrdering;

        /// Hidden less-than bit.
        #[inline]
        fn ct_lt(&self, other: &Rhs) -> Choice {
            self.ct_cmp(other).is_less()
        }

        /// Hidden less-than-or-equal bit.
        #[inline]
        fn ct_le(&self, other: &Rhs) -> Choice {
            let ordering = self.ct_cmp(other);
            ordering.is_less() | ordering.is_equal()
        }

        /// Hidden greater-than bit.
        #[inline]
        fn ct_gt(&self, other: &Rhs) -> Choice {
            self.ct_cmp(other).is_greater()
        }

        /// Hidden greater-than-or-equal bit.
        #[inline]
        fn ct_ge(&self, other: &Rhs) -> Choice {
            let ordering = self.ct_cmp(other);
            ordering.is_greater() | ordering.is_equal()
        }
    }

    /// All-zero/all-one mask value for branchless operations.
    #[repr(transparent)]
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub struct Mask<T> {
        value: T,
    }

    impl<T: Copy> Mask<T> {
        /// Return the underlying mask value.
        #[inline]
        pub const fn expose(self) -> T {
            self.value
        }
    }

    impl<T: fmt::Debug> fmt::Debug for Mask<T> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("Mask(..)")
        }
    }

    /// Marker wrapper for values that are public by contract.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Public<T>(T);

    impl<T> Public<T> {
        /// Wrap a public value.
        #[inline]
        pub const fn new(value: T) -> Self {
            Self(value)
        }

        /// Unwrap a public value.
        #[inline]
        pub fn into_inner(self) -> T {
            self.0
        }

        /// Borrow the public value.
        #[inline]
        pub const fn expose(&self) -> &T {
            &self.0
        }
    }

    /// Marker wrapper for values that must not drive ordinary control flow or
    /// memory access without an oblivious API.
    #[repr(transparent)]
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub struct Secret<T>(T);

    impl<T> Secret<T> {
        /// Wrap a secret-controlled value.
        #[inline]
        pub const fn new(value: T) -> Self {
            Self(value)
        }

        /// Borrow the secret-controlled value for data-oblivious operations.
        #[inline]
        pub const fn expose_secret(&self) -> &T {
            &self.0
        }
    }

    impl<T> fmt::Debug for Secret<T> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("Secret(..)")
        }
    }

    /// Optional value with a hidden presence bit.
    ///
    /// `CtOption` stores a value regardless of whether it is logically present.
    /// Callers should combine or select on the [`Choice`] returned by
    /// [`CtOption::is_some`] and declassify only at a public boundary.
    #[derive(Clone, Copy, Debug)]
    pub struct CtOption<T> {
        value: T,
        is_some: Choice,
    }

    impl<T> CtOption<T> {
        /// Construct a `CtOption`.
        #[inline]
        pub const fn new(value: T, is_some: Choice) -> Self {
            Self { value, is_some }
        }

        /// Construct a logically present value.
        #[inline]
        pub const fn some(value: T) -> Self {
            Self {
                value,
                is_some: Choice::TRUE,
            }
        }

        /// Construct a logically absent value with a dummy backing value.
        #[inline]
        pub const fn none(dummy: T) -> Self {
            Self {
                value: dummy,
                is_some: Choice::FALSE,
            }
        }

        /// Return the hidden presence bit.
        #[inline]
        pub const fn is_some(&self) -> Choice {
            self.is_some
        }

        /// Return the hidden absence bit.
        #[inline]
        pub fn is_none(&self) -> Choice {
            !self.is_some
        }

        /// Borrow the backing value. Its logical validity is controlled by
        /// [`CtOption::is_some`].
        #[inline]
        pub const fn value(&self) -> &T {
            &self.value
        }

        /// Select the backing value or `fallback` without branching on
        /// presence.
        #[inline]
        pub fn unwrap_or(&self, fallback: &T) -> T
        where
            T: ConditionallySelectable,
        {
            T::conditional_select(fallback, &self.value, self.is_some)
        }

        /// Transform the backing value without declassifying the presence bit.
        ///
        /// The closure is always called, even when this value is logically
        /// absent. If the backing value is secret-derived, the closure must
        /// avoid secret-dependent control flow and secret-dependent memory
        /// access.
        #[inline]
        pub fn map<U>(self, transform: impl FnOnce(T) -> U) -> CtOption<U> {
            CtOption {
                value: transform(self.value),
                is_some: self.is_some,
            }
        }

        /// Combine two optional values, keeping the result logically present
        /// only when both inputs are present.
        ///
        /// The backing value from `other` is retained regardless of presence.
        #[inline]
        pub fn and<U>(self, other: CtOption<U>) -> CtOption<U> {
            CtOption {
                value: other.value,
                is_some: self.is_some & other.is_some,
            }
        }

        /// Select `self` when present and `other` otherwise without branching
        /// on the hidden presence bit.
        ///
        /// The result is present when either input is present.
        #[inline]
        pub fn or(self, other: Self) -> Self
        where
            T: ConditionallySelectable,
        {
            Self {
                value: T::conditional_select(&other.value, &self.value, self.is_some),
                is_some: self.is_some | other.is_some,
            }
        }

        /// Explicitly declassify the presence bit and convert into a normal
        /// [`Option`].
        ///
        /// This is a public branch boundary. The `reason` must explain why the
        /// caller is allowed to reveal the presence/absence decision.
        #[inline]
        pub fn declassify(self, reason: &'static str) -> Option<T> {
            if self.is_some.declassify(reason) {
                Some(self.value)
            } else {
                None
            }
        }
    }

    impl<T> ConditionallySelectable for CtOption<T>
    where
        T: ConditionallySelectable,
    {
        #[inline]
        fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
            Self {
                value: T::conditional_select(&left.value, &right.value, choice),
                is_some: Choice::conditional_select(&left.is_some, &right.is_some, choice),
            }
        }
    }

    /// Result-like value with a hidden success bit.
    #[derive(Clone, Copy, Debug)]
    pub struct CtResult<T, E> {
        value: T,
        error: E,
        is_ok: Choice,
    }

    impl<T, E> CtResult<T, E> {
        /// Construct a `CtResult` from both backing values and a success bit.
        #[inline]
        pub const fn new(value: T, error: E, is_ok: Choice) -> Self {
            Self {
                value,
                error,
                is_ok,
            }
        }

        /// Return the hidden success bit.
        #[inline]
        pub const fn is_ok(&self) -> Choice {
            self.is_ok
        }

        /// Return the hidden error bit.
        #[inline]
        pub fn is_err(&self) -> Choice {
            !self.is_ok
        }

        /// Borrow the success backing value.
        #[inline]
        pub const fn value(&self) -> &T {
            &self.value
        }

        /// Borrow the error backing value.
        #[inline]
        pub const fn error(&self) -> &E {
            &self.error
        }

        /// Select the success backing value or `fallback` without branching on
        /// the success bit.
        #[inline]
        pub fn unwrap_or(&self, fallback: &T) -> T
        where
            T: ConditionallySelectable,
        {
            T::conditional_select(fallback, &self.value, self.is_ok)
        }

        /// Transform the success backing value without declassifying the
        /// success bit.
        ///
        /// The closure is always called, even when this value is logically an
        /// error. If the backing value is secret-derived, the closure must
        /// avoid secret-dependent control flow and secret-dependent memory
        /// access.
        #[inline]
        pub fn map<U>(self, transform: impl FnOnce(T) -> U) -> CtResult<U, E> {
            CtResult {
                value: transform(self.value),
                error: self.error,
                is_ok: self.is_ok,
            }
        }

        /// Transform the error backing value without declassifying the success
        /// bit.
        ///
        /// The closure is always called, even when this value is logically
        /// successful. If the backing error is secret-derived, the closure must
        /// avoid secret-dependent control flow and secret-dependent memory
        /// access.
        #[inline]
        pub fn map_err<F>(self, transform: impl FnOnce(E) -> F) -> CtResult<T, F> {
            CtResult {
                value: self.value,
                error: transform(self.error),
                is_ok: self.is_ok,
            }
        }

        /// Explicitly declassify the success bit and convert into a normal
        /// [`Result`].
        ///
        /// This is a public branch boundary. The `reason` must explain why the
        /// caller is allowed to reveal the success/error decision.
        #[inline]
        pub fn declassify(self, reason: &'static str) -> Result<T, E> {
            if self.is_ok.declassify(reason) {
                Ok(self.value)
            } else {
                Err(self.error)
            }
        }
    }

    impl<T, E> ConditionallySelectable for CtResult<T, E>
    where
        T: ConditionallySelectable,
        E: ConditionallySelectable,
    {
        #[inline]
        fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
            Self {
                value: T::conditional_select(&left.value, &right.value, choice),
                error: E::conditional_select(&left.error, &right.error, choice),
                is_ok: Choice::conditional_select(&left.is_ok, &right.is_ok, choice),
            }
        }
    }

    macro_rules! impl_unsigned_ct {
        ($($ty:ty),* $(,)?) => {
            $(
                impl Mask<$ty> {
                    /// Return an all-zero mask when `choice` is false and an
                    /// all-one mask when it is true.
                    #[inline]
                    pub fn from_choice(choice: Choice) -> Self {
                        Self {
                            value: (0 as $ty).wrapping_sub(choice.unwrap_u8() as $ty),
                        }
                    }
                }

                impl ConstantTimeEq for $ty {
                    #[inline]
                    fn ct_eq(&self, other: &Self) -> Choice {
                        let diff = black_box(*self ^ *other);
                        let nonzero = ((diff | diff.wrapping_neg()) >> (<$ty>::BITS - 1)) as u8;
                        Choice::from_u8(nonzero ^ 1)
                    }
                }

                impl ConditionallySelectable for $ty {
                    #[inline]
                    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
                        let mask = (0 as $ty).wrapping_sub(choice.unwrap_u8() as $ty);
                        black_box((*left & !mask) | (*right & mask))
                    }
                }

                impl ConstantTimeOrd for $ty {
                    #[inline]
                    fn ct_cmp(&self, other: &Self) -> CtOrdering {
                        ct_cmp_be_bytes(&self.to_be_bytes(), &other.to_be_bytes())
                    }
                }
            )*
        };
    }

    macro_rules! impl_signed_ct {
        ($(($signed:ty, $unsigned:ty)),* $(,)?) => {
            $(
                impl ConstantTimeEq for $signed {
                    #[inline]
                    fn ct_eq(&self, other: &Self) -> Choice {
                        (*self as $unsigned).ct_eq(&(*other as $unsigned))
                    }
                }

                impl ConditionallySelectable for $signed {
                    #[inline]
                    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
                        <$unsigned as ConditionallySelectable>::conditional_select(
                            &(*left as $unsigned),
                            &(*right as $unsigned),
                            choice,
                        ) as $signed
                    }
                }

                impl ConstantTimeOrd for $signed {
                    #[inline]
                    fn ct_cmp(&self, other: &Self) -> CtOrdering {
                        let sign_bit = 1 as $unsigned << (<$unsigned>::BITS - 1);
                        let left = ((*self as $unsigned) ^ sign_bit).to_be_bytes();
                        let right = ((*other as $unsigned) ^ sign_bit).to_be_bytes();
                        ct_cmp_be_bytes(&left, &right)
                    }
                }
            )*
        };
    }

    impl_unsigned_ct!(u8, u16, u32, u64, u128, usize);
    impl_signed_ct!(
        (i8, u8),
        (i16, u16),
        (i32, u32),
        (i64, u64),
        (i128, u128),
        (isize, usize),
    );

    impl ConstantTimeEq for bool {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            (*self as u8).ct_eq(&(*other as u8))
        }
    }

    impl ConditionallySelectable for bool {
        #[inline]
        fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
            u8::conditional_select(&(*left as u8), &(*right as u8), choice) == 1
        }
    }

    /// Compare fixed-size byte arrays without leaking the first difference.
    #[inline]
    pub fn eq_fixed<const N: usize>(left: &[u8; N], right: &[u8; N]) -> Choice {
        bytes_eq_equal_len(left, right)
    }

    /// Compare fixed-size byte arrays in lexicographic byte order without
    /// leaking the first differing byte.
    #[inline]
    pub fn cmp_fixed<const N: usize>(left: &[u8; N], right: &[u8; N]) -> CtOrdering {
        ct_cmp_be_bytes(left, right)
    }

    /// Compare byte slices where length is explicitly public.
    #[inline]
    pub fn eq_public_len(left: &[u8], right: &[u8]) -> Choice {
        if left.len() != right.len() {
            return Choice::FALSE;
        }

        bytes_eq_equal_len(left, right)
    }

    /// Look up one table entry by a secret index using a full-table scan.
    ///
    /// The table length is public. Every table entry is visited exactly once
    /// for the public length, and an out-of-range secret index returns
    /// `fallback`.
    ///
    /// The returned value is selected by a secret index. If the value remains
    /// secret-controlled, prefer [`oblivious_lookup_secret`] so the type system
    /// keeps that boundary visible to reviewers.
    #[inline(never)]
    pub fn oblivious_lookup<T>(table: &[T], secret_index: Secret<usize>, fallback: &T) -> T
    where
        T: ConditionallySelectable,
    {
        // Initialize through the same selection trait required by the loop.
        // This avoids adding `Clone`/`Copy` bounds to `T` while making the
        // fallback behavior explicit.
        let mut output = T::conditional_select(fallback, fallback, Choice::FALSE);
        let wanted = black_box(*secret_index.expose_secret());
        let mut index = 0usize;
        while index < table.len() {
            let selected = wanted.ct_eq(&index);
            output = T::conditional_select(&output, &table[index], selected);
            index += 1;
        }
        black_box(output)
    }

    /// Look up one table entry by a secret index and keep the selected value
    /// wrapped as secret-controlled.
    ///
    /// This is the audit-friendly variant of [`oblivious_lookup`] for call
    /// sites where the selected value must not immediately drive ordinary
    /// control flow or memory access.
    #[inline(never)]
    pub fn oblivious_lookup_secret<T>(
        table: &[T],
        secret_index: Secret<usize>,
        fallback: &T,
    ) -> Secret<T>
    where
        T: ConditionallySelectable,
    {
        Secret::new(oblivious_lookup(table, secret_index, fallback))
    }

    /// Conditionally copy `source` into `destination`.
    ///
    /// Lengths are public metadata. When `choice` is false, `destination` is
    /// rewritten with its existing bytes; when true, it is rewritten with
    /// `source`.
    #[inline(never)]
    pub fn conditional_copy(
        destination: &mut [u8],
        source: &[u8],
        choice: Choice,
    ) -> Result<(), crate::LengthError> {
        if destination.len() != source.len() {
            return Err(crate::LengthError {
                expected: destination.len(),
                actual: source.len(),
            });
        }

        let mut index = 0usize;
        while index < destination.len() {
            destination[index] =
                u8::conditional_select(&destination[index], &source[index], choice);
            index += 1;
        }
        Ok(())
    }

    /// Conditionally swap two equal-length byte slices.
    ///
    /// Lengths are public metadata. Both slices are visited for the full public
    /// length regardless of `choice`.
    #[inline(never)]
    pub fn conditional_swap(
        left: &mut [u8],
        right: &mut [u8],
        choice: Choice,
    ) -> Result<(), crate::LengthError> {
        if left.len() != right.len() {
            return Err(crate::LengthError {
                expected: left.len(),
                actual: right.len(),
            });
        }

        let mask = black_box(Mask::<u8>::from_choice(choice).expose());
        let mut index = 0usize;
        while index < left.len() {
            let swap = (left[index] ^ right[index]) & mask;
            left[index] ^= swap;
            right[index] ^= swap;
            index += 1;
        }
        Ok(())
    }

    /// Select between two equal-length source slices into `destination`.
    ///
    /// Lengths are public metadata. All three slices must have the same public
    /// length. Every byte is selected without branching on `choice`.
    #[inline(never)]
    pub fn select_slice(
        destination: &mut [u8],
        left: &[u8],
        right: &[u8],
        choice: Choice,
    ) -> Result<(), crate::LengthError> {
        if left.len() != right.len() {
            return Err(crate::LengthError {
                expected: left.len(),
                actual: right.len(),
            });
        }
        if destination.len() != left.len() {
            return Err(crate::LengthError {
                expected: left.len(),
                actual: destination.len(),
            });
        }

        let mut index = 0usize;
        while index < destination.len() {
            destination[index] = u8::conditional_select(&left[index], &right[index], choice);
            index += 1;
        }
        Ok(())
    }

    #[inline]
    fn bytes_eq_equal_len(left: &[u8], right: &[u8]) -> Choice {
        debug_assert_eq!(left.len(), right.len());

        let mut diff = 0u8;
        let mut index = 0usize;
        while index < left.len() {
            diff = black_box(diff | (left[index] ^ right[index]));
            index += 1;
        }

        !Choice::from_u8(black_box(diff))
    }

    #[inline]
    fn byte_lt_bit(left: u8, right: u8) -> u8 {
        ((left as u16).wrapping_sub(right as u16) >> 8) as u8
    }

    #[inline]
    fn byte_eq_bit(left: u8, right: u8) -> u8 {
        let diff = left ^ right;
        (((diff | diff.wrapping_neg()) >> 7) ^ 1) & 1
    }

    #[inline]
    fn ct_cmp_be_bytes(left: &[u8], right: &[u8]) -> CtOrdering {
        debug_assert_eq!(left.len(), right.len());

        let mut less = 0u8;
        let mut greater = 0u8;
        let mut equal_so_far = 1u8;
        let mut index = 0usize;
        while index < left.len() {
            let left_byte = black_box(left[index]);
            let right_byte = black_box(right[index]);
            let left_less = byte_lt_bit(left_byte, right_byte);
            let right_less = byte_lt_bit(right_byte, left_byte);
            less = black_box(less | (equal_so_far & left_less));
            greater = black_box(greater | (equal_so_far & right_less));
            equal_so_far = black_box(equal_so_far & byte_eq_bit(left_byte, right_byte));
            index += 1;
        }

        CtOrdering::from_normalized_bits(
            Choice(black_box(less & 1)),
            Choice(black_box(equal_so_far & 1)),
            Choice(black_box(greater & 1)),
        )
    }

    impl<const N: usize> ConstantTimeEq for [u8; N] {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            eq_fixed(self, other)
        }
    }

    impl<const N: usize> ConstantTimeOrd for [u8; N] {
        #[inline]
        fn ct_cmp(&self, other: &Self) -> CtOrdering {
            cmp_fixed(self, other)
        }
    }

    impl ConstantTimeEq for [u8] {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            eq_public_len(self, other)
        }
    }

    impl<const N: usize> ConditionallySelectable for [u8; N] {
        #[inline]
        fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
            let mut output = [0u8; N];
            let mut index = 0usize;
            while index < N {
                output[index] = u8::conditional_select(&left[index], &right[index], choice);
                index += 1;
            }
            output
        }
    }

    impl<T> Public<PhantomData<T>> {
        /// Construct a public marker value.
        #[inline]
        pub const fn marker() -> Self {
            Self(PhantomData)
        }
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

    #[cfg(all(
        feature = "asm-compare",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    {
        compare_asm::constant_time_eq_equal_len(left, right)
    }

    #[cfg(not(all(
        feature = "asm-compare",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    )))]
    {
        portable_constant_time_eq_equal_len(left, right)
    }
}

#[inline]
#[cfg_attr(
    all(
        feature = "asm-compare",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ),
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
    use core::cmp::Ordering;

    fn assert_ct_ordering_matches(ordering: ct::CtOrdering, expected: Ordering) {
        match expected {
            Ordering::Less => {
                assert_eq!(ordering.is_less().unwrap_u8(), 1);
                assert_eq!(ordering.is_equal().unwrap_u8(), 0);
                assert_eq!(ordering.is_greater().unwrap_u8(), 0);
            }
            Ordering::Equal => {
                assert_eq!(ordering.is_less().unwrap_u8(), 0);
                assert_eq!(ordering.is_equal().unwrap_u8(), 1);
                assert_eq!(ordering.is_greater().unwrap_u8(), 0);
            }
            Ordering::Greater => {
                assert_eq!(ordering.is_less().unwrap_u8(), 0);
                assert_eq!(ordering.is_equal().unwrap_u8(), 0);
                assert_eq!(ordering.is_greater().unwrap_u8(), 1);
            }
        }
    }

    fn lexicographic_cmp_4(left: &[u8; 4], right: &[u8; 4]) -> Ordering {
        let mut index = 0;
        while index < 4 {
            if left[index] < right[index] {
                return Ordering::Less;
            }
            if left[index] > right[index] {
                return Ordering::Greater;
            }
            index += 1;
        }
        Ordering::Equal
    }

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
    fn prove_ct_choice_is_normalized() {
        let value: u8 = kani::any();
        let choice = ct::Choice::from_u8(value);
        let unwrapped = choice.unwrap_u8();

        assert!(unwrapped == 0 || unwrapped == 1);
    }

    #[kani::proof]
    fn prove_ct_choice_boolean_algebra_matches_public_bits() {
        let left_byte: u8 = kani::any();
        let right_byte: u8 = kani::any();
        let left = ct::Choice::from_u8(left_byte);
        let right = ct::Choice::from_u8(right_byte);
        let left_bit = left.unwrap_u8();
        let right_bit = right.unwrap_u8();

        assert_eq!((left & right).unwrap_u8(), left_bit & right_bit);
        assert_eq!((left | right).unwrap_u8(), left_bit | right_bit);
        assert_eq!((left ^ right).unwrap_u8(), left_bit ^ right_bit);
        assert_eq!((!left).unwrap_u8(), left_bit ^ 1);
    }

    #[kani::proof]
    fn prove_ct_fixed_equality_matches_byte_equality() {
        let left: [u8; 4] = kani::any();
        let right: [u8; 4] = kani::any();

        let mut expected = true;
        let mut index = 0;
        while index < 4 {
            expected &= left[index] == right[index];
            index += 1;
        }

        assert_eq!(ct::eq_fixed(&left, &right).unwrap_u8() == 1, expected);
    }

    #[kani::proof]
    fn prove_ct_public_length_equality_rejects_mismatch() {
        let left: [u8; 4] = kani::any();
        let right: [u8; 3] = kani::any();

        assert_eq!(ct::eq_public_len(&left, &right).unwrap_u8(), 0);
    }

    #[kani::proof]
    fn prove_ct_fixed_ordering_matches_lexicographic_ordering() {
        let left: [u8; 4] = kani::any();
        let right: [u8; 4] = kani::any();

        assert_ct_ordering_matches(
            ct::cmp_fixed(&left, &right),
            lexicographic_cmp_4(&left, &right),
        );
    }

    #[kani::proof]
    fn prove_ct_unsigned_ordering_matches_rust_ordering() {
        let left: u16 = kani::any();
        let right: u16 = kani::any();

        assert_ct_ordering_matches(
            <u16 as ct::ConstantTimeOrd>::ct_cmp(&left, &right),
            left.cmp(&right),
        );
    }

    #[kani::proof]
    fn prove_ct_signed_ordering_matches_rust_ordering() {
        let left: i16 = kani::any();
        let right: i16 = kani::any();

        assert_ct_ordering_matches(
            <i16 as ct::ConstantTimeOrd>::ct_cmp(&left, &right),
            left.cmp(&right),
        );
    }

    #[kani::proof]
    fn prove_ct_conditional_copy_matches_choice() {
        let initial: [u8; 4] = kani::any();
        let source: [u8; 4] = kani::any();
        let choice_byte: u8 = kani::any();
        let choice = ct::Choice::from_u8(choice_byte);
        let mut destination = initial;

        assert!(ct::conditional_copy(&mut destination, &source, choice).is_ok());

        if choice.unwrap_u8() == 1 {
            assert_eq!(destination, source);
        } else {
            assert_eq!(destination, initial);
        }
    }

    #[kani::proof]
    fn prove_ct_conditional_swap_matches_choice() {
        let initial_left: [u8; 4] = kani::any();
        let initial_right: [u8; 4] = kani::any();
        let choice_byte: u8 = kani::any();
        let choice = ct::Choice::from_u8(choice_byte);
        let mut left = initial_left;
        let mut right = initial_right;

        assert!(ct::conditional_swap(&mut left, &mut right, choice).is_ok());

        if choice.unwrap_u8() == 1 {
            assert_eq!(left, initial_right);
            assert_eq!(right, initial_left);
        } else {
            assert_eq!(left, initial_left);
            assert_eq!(right, initial_right);
        }
    }

    #[kani::proof]
    fn prove_ct_oblivious_lookup_matches_public_index() {
        let table: [u8; 4] = kani::any();
        let fallback: u8 = kani::any();
        let index: usize = kani::any();

        let selected = ct::oblivious_lookup(&table, ct::Secret::new(index), &fallback);

        if index < 4 {
            assert_eq!(selected, table[index]);
        } else {
            assert_eq!(selected, fallback);
        }
    }

    #[kani::proof]
    fn prove_ct_select_slice_matches_choice() {
        let left: [u8; 4] = kani::any();
        let right: [u8; 4] = kani::any();
        let choice_byte: u8 = kani::any();
        let choice = ct::Choice::from_u8(choice_byte);
        let mut destination = [0u8; 4];

        assert!(ct::select_slice(&mut destination, &left, &right, choice).is_ok());

        if choice.unwrap_u8() == 1 {
            assert_eq!(destination, right);
        } else {
            assert_eq!(destination, left);
        }
    }

    #[kani::proof]
    fn prove_ct_option_unwrap_or_matches_presence() {
        let value: u8 = kani::any();
        let fallback: u8 = kani::any();
        let presence_byte: u8 = kani::any();
        let presence = ct::Choice::from_u8(presence_byte);
        let option = ct::CtOption::new(value, presence);

        let selected = option.unwrap_or(&fallback);

        if presence.unwrap_u8() == 1 {
            assert_eq!(selected, value);
        } else {
            assert_eq!(selected, fallback);
        }
    }

    #[kani::proof]
    fn prove_ct_option_and_or_match_presence_bits() {
        let left_value: u8 = kani::any();
        let right_value: u8 = kani::any();
        let fallback: u8 = kani::any();
        let left_presence_byte: u8 = kani::any();
        let right_presence_byte: u8 = kani::any();
        let left_presence = ct::Choice::from_u8(left_presence_byte);
        let right_presence = ct::Choice::from_u8(right_presence_byte);
        let left = ct::CtOption::new(left_value, left_presence);
        let right = ct::CtOption::new(right_value, right_presence);

        let and_selected = left.and(right).unwrap_or(&fallback);
        let or_selected = left.or(right).unwrap_or(&fallback);

        if left_presence.unwrap_u8() == 1 && right_presence.unwrap_u8() == 1 {
            assert_eq!(and_selected, right_value);
        } else {
            assert_eq!(and_selected, fallback);
        }

        if left_presence.unwrap_u8() == 1 {
            assert_eq!(or_selected, left_value);
        } else if right_presence.unwrap_u8() == 1 {
            assert_eq!(or_selected, right_value);
        } else {
            assert_eq!(or_selected, fallback);
        }
    }

    #[kani::proof]
    fn prove_ct_result_unwrap_or_and_maps_match_success_bit() {
        let value: u8 = kani::any();
        let error: u8 = kani::any();
        let fallback: u8 = kani::any();
        let success_byte: u8 = kani::any();
        let success = ct::Choice::from_u8(success_byte);
        let result = ct::CtResult::new(value, error, success);

        let selected = result.unwrap_or(&fallback);
        let mapped = result.map(|inner| inner.wrapping_add(1));
        let mapped_error = result.map_err(|inner| inner.wrapping_add(1));

        if success.unwrap_u8() == 1 {
            assert_eq!(selected, value);
            assert_eq!(
                mapped.declassify("Kani exposes mapped success bit"),
                Ok(value.wrapping_add(1))
            );
            assert_eq!(
                mapped_error.declassify("Kani exposes mapped success bit"),
                Ok(value)
            );
        } else {
            assert_eq!(selected, fallback);
            assert_eq!(
                mapped.declassify("Kani exposes mapped error bit"),
                Err(error)
            );
            assert_eq!(
                mapped_error.declassify("Kani exposes mapped error bit"),
                Err(error.wrapping_add(1))
            );
        }
    }

    #[kani::proof]
    fn prove_ct_option_and_result_conditional_select_match_choice() {
        let left_value: u8 = kani::any();
        let right_value: u8 = kani::any();
        let choice_byte: u8 = kani::any();
        let choice = ct::Choice::from_u8(choice_byte);
        let left_option = ct::CtOption::some(left_value);
        let right_option = ct::CtOption::some(right_value);
        let left_result = ct::CtResult::new(left_value, 11u8, ct::Choice::TRUE);
        let right_result = ct::CtResult::new(right_value, 22u8, ct::Choice::TRUE);

        let selected_option = <ct::CtOption<u8> as ct::ConditionallySelectable>::conditional_select(
            &left_option,
            &right_option,
            choice,
        );
        let selected_result =
            <ct::CtResult<u8, u8> as ct::ConditionallySelectable>::conditional_select(
                &left_result,
                &right_result,
                choice,
            );

        if choice.unwrap_u8() == 1 {
            assert_eq!(selected_option.unwrap_or(&0), right_value);
            assert_eq!(selected_result.unwrap_or(&0), right_value);
        } else {
            assert_eq!(selected_option.unwrap_or(&0), left_value);
            assert_eq!(selected_result.unwrap_or(&0), left_value);
        }
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

    /// Clear all bytes now with an explicit three-pass volatile pattern.
    ///
    /// Available with the `multi-pass-clear` feature. This is intended for
    /// policy or audit compatibility; for volatile RAM, the default
    /// [`SecretBytes::secure_clear`] remains the normal security boundary.
    #[cfg(feature = "multi-pass-clear")]
    #[inline(never)]
    pub fn secure_clear_multi_pass(&mut self) {
        wipe::volatile_multi_pass_clear(self.bytes.as_mut_ptr(), N);
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

impl<const N: usize> ct::ConstantTimeEq for SecretBytes<N> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> ct::Choice {
        ct::eq_fixed(&self.bytes, &other.bytes)
    }
}

impl<const N: usize> ct::ConstantTimeEq<[u8]> for SecretBytes<N> {
    #[inline]
    fn ct_eq(&self, other: &[u8]) -> ct::Choice {
        ct::eq_public_len(self.bytes.as_slice(), other)
    }
}

impl<const N: usize> ct::ConditionallySelectable for SecretBytes<N> {
    #[inline]
    fn conditional_select(left: &Self, right: &Self, choice: ct::Choice) -> Self {
        let mut output = Self::zeroed();
        let mut index = 0usize;
        while index < N {
            output.bytes[index] = <u8 as ct::ConditionallySelectable>::conditional_select(
                &left.bytes[index],
                &right.bytes[index],
                choice,
            );
            index += 1;
        }
        output.after_secret_write();
        output
    }
}

/// Error returned by split-secret construction.
#[cfg(feature = "split-secret")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplitSecretError {
    /// XOR split storage requires at least two shares.
    TooFewShares,
    /// The generated mask shares were trivially constant.
    ///
    /// This usually means the caller passed a stub, deterministic test
    /// generator, all-zero generator, or otherwise unsuitable random source.
    TrivialMask,
}

#[cfg(feature = "split-secret")]
impl fmt::Display for SplitSecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewShares => formatter.write_str("split secrets require at least two shares"),
            Self::TrivialMask => formatter.write_str(
                "split-secret mask shares are trivially constant; use cryptographically random mask bytes",
            ),
        }
    }
}

#[cfg(all(feature = "split-secret", feature = "std"))]
impl std::error::Error for SplitSecretError {}

/// Fixed-size N-of-N XOR split secret storage.
///
/// This type is available with the `split-secret` feature. It stores a secret
/// as `SHARES` independent-looking fixed-size shares where XORing every share
/// reconstructs the original bytes. It is not threshold secret sharing: all
/// shares are required, and the caller must provide cryptographically random
/// bytes for every mask share through the generator closure.
///
/// # Security
///
/// The generator is trusted. Passing a deterministic, low-entropy, or reused
/// generator can make the split provide no confidentiality. Construction
/// rejects trivially constant mask shares in all build profiles, but that cheap
/// heuristic is not a substitute for a CSPRNG.
#[cfg(feature = "split-secret")]
pub struct SplitSecretBytes<const N: usize, const SHARES: usize> {
    shares: [SecretBytes<N>; SHARES],
}

#[cfg(feature = "split-secret")]
impl<const N: usize, const SHARES: usize> SplitSecretBytes<N, SHARES> {
    /// Split an owned secret array into `SHARES` XOR shares, then clear the
    /// input array.
    ///
    /// `make_mask_byte(share_index, byte_index)` is called for shares
    /// `0..SHARES - 1`. It must return cryptographically random mask bytes for
    /// the split to provide meaningful protection.
    pub fn from_array_with_generator(
        mut secret: [u8; N],
        mut make_mask_byte: impl FnMut(usize, usize) -> u8,
    ) -> Result<Self, SplitSecretError> {
        let guard = TemporaryBytes { bytes: &mut secret };

        if SHARES < 2 {
            return Err(SplitSecretError::TooFewShares);
        }

        let split = Self::from_secret_bytes_with_generator(guard.bytes, &mut make_mask_byte)?;
        sanitize_bytes(guard.bytes);
        Ok(split)
    }

    /// Split an existing [`SecretBytes`] value into `SHARES` XOR shares.
    ///
    /// The source secret is not cleared by this method. Use
    /// [`SecretBytes::secure_clear`] afterwards if ownership policy requires
    /// moving the secret exclusively into the split representation.
    pub fn from_secret_with_generator(
        secret: &SecretBytes<N>,
        mut make_mask_byte: impl FnMut(usize, usize) -> u8,
    ) -> Result<Self, SplitSecretError> {
        if SHARES < 2 {
            return Err(SplitSecretError::TooFewShares);
        }

        Self::from_secret_bytes_with_generator(&secret.bytes, &mut make_mask_byte)
    }

    /// Split an owned [`SecretBytes`] value into `SHARES` XOR shares, then clear
    /// the source secret before returning.
    pub fn from_secret_consuming_with_generator(
        mut secret: SecretBytes<N>,
        mut make_mask_byte: impl FnMut(usize, usize) -> u8,
    ) -> Result<Self, SplitSecretError> {
        let split = Self::from_secret_bytes_with_generator(&secret.bytes, &mut make_mask_byte)?;
        secret.secure_clear();
        Ok(split)
    }

    /// Reconstruct all shares into a new [`SecretBytes`] value.
    #[must_use]
    pub fn reconstruct(&self) -> SecretBytes<N> {
        let mut output = SecretBytes::<N>::zeroed();
        let mut byte_index = 0;
        while byte_index < N {
            let mut value = 0;
            let mut share_index = 0;
            while share_index < SHARES {
                value ^= self.shares[share_index].load(byte_index);
                share_index += 1;
            }
            output.store(byte_index, value);
            byte_index += 1;
        }
        output.after_secret_write();
        output
    }

    /// Borrow all shares.
    #[must_use]
    #[inline]
    pub const fn shares(&self) -> &[SecretBytes<N>; SHARES] {
        &self.shares
    }

    /// Borrow one share by index.
    #[must_use]
    #[inline]
    pub fn share(&self, index: usize) -> Option<&SecretBytes<N>> {
        self.shares.get(index)
    }

    /// Consume the split storage and return the underlying shares.
    #[must_use]
    #[inline]
    pub fn into_shares(self) -> [SecretBytes<N>; SHARES] {
        self.shares
    }

    fn from_secret_bytes_with_generator(
        secret: &[u8; N],
        make_mask_byte: &mut impl FnMut(usize, usize) -> u8,
    ) -> Result<Self, SplitSecretError> {
        if SHARES < 2 {
            return Err(SplitSecretError::TooFewShares);
        }

        let mut shares = core::array::from_fn(|_| SecretBytes::<N>::zeroed());

        let mut byte_index = 0;
        while byte_index < N {
            let mut accumulator = 0;
            let mut share_index = 0;
            while share_index + 1 < SHARES {
                let mask = make_mask_byte(share_index, byte_index);
                shares[share_index].store(byte_index, mask);
                accumulator ^= mask;
                share_index += 1;
            }

            shares[SHARES - 1].store(byte_index, secret[byte_index] ^ accumulator);
            byte_index += 1;
        }

        let trivial_mask = u8::from(Self::mask_shares_are_trivially_constant(&shares))
            | u8::from(Self::mask_accumulator_is_trivial(&shares));
        if trivial_mask != 0 {
            shares.secure_sanitize();
            return Err(SplitSecretError::TrivialMask);
        }

        for share in shares.iter() {
            share.after_secret_write();
        }

        Ok(Self { shares })
    }

    #[inline]
    fn mask_shares_are_trivially_constant(shares: &[SecretBytes<N>; SHARES]) -> bool {
        if N < 2 {
            return false;
        }

        let mut any_trivial = false;
        let mut share_index = 0;
        while share_index + 1 < SHARES {
            let first = shares[share_index].load(0);
            let mut byte_index = 1;
            let mut all_same = true;
            while byte_index < N {
                let diff = shares[share_index].load(byte_index) ^ first;
                all_same &= diff == 0;
                byte_index += 1;
            }

            any_trivial |= all_same;
            share_index += 1;
        }

        any_trivial
    }

    #[inline]
    fn mask_accumulator_is_trivial(shares: &[SecretBytes<N>; SHARES]) -> bool {
        if N == 0 || SHARES < 2 {
            return false;
        }

        let mut any_nonzero = false;
        let mut byte_index = 0;
        while byte_index < N {
            let mut accumulator = 0u8;
            let mut share_index = 0;
            while share_index + 1 < SHARES {
                accumulator ^= shares[share_index].load(byte_index);
                share_index += 1;
            }

            any_nonzero |= accumulator != 0;
            byte_index += 1;
        }

        !any_nonzero
    }
}

#[cfg(feature = "split-secret")]
impl<const N: usize, const SHARES: usize> SecureSanitize for SplitSecretBytes<N, SHARES> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.shares.secure_sanitize();
    }
}

#[cfg(feature = "split-secret")]
impl<const N: usize, const SHARES: usize> fmt::Debug for SplitSecretBytes<N, SHARES> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SplitSecretBytes")
            .field("len", &N)
            .field("shares", &SHARES)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Error returned when an expiring secret has exceeded its configured lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretExpiredError;

impl fmt::Display for SecretExpiredError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret has expired")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SecretExpiredError {}

/// Error returned by expiring secret operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpiringSecretError {
    /// The secret has exceeded its configured lifetime.
    Expired(SecretExpiredError),
    /// The caller provided a buffer with the wrong length.
    Length(LengthError),
}

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

impl From<SecretExpiredError> for ExpiringSecretError {
    #[inline]
    fn from(error: SecretExpiredError) -> Self {
        Self::Expired(error)
    }
}

impl From<LengthError> for ExpiringSecretError {
    #[inline]
    fn from(error: LengthError) -> Self {
        Self::Length(error)
    }
}

/// Caller-provided monotonic tick source for no-`std` expiring secrets.
///
/// The unit is intentionally application-defined: milliseconds, RTOS ticks,
/// counter increments, or another monotonic unit. Implementations must not move
/// backward for a given secret lifetime window.
pub trait MonotonicClock {
    /// Return the current monotonic tick value.
    fn now(&self) -> u64;
}

impl<C: MonotonicClock + ?Sized> MonotonicClock for &C {
    #[inline]
    fn now(&self) -> u64 {
        (**self).now()
    }
}

/// Fixed-size secret bytes with caller-provided monotonic lifetime enforcement.
///
/// This is the `no_std` counterpart to [`ExpiringSecretBytes`]. It wraps
/// [`SecretBytes<N>`], stores a caller-provided [`MonotonicClock`], and rejects
/// exposure after `max_age` ticks. On expiration, fallible
/// read/exposure/comparison methods clear the wrapped secret before returning
/// [`SecretExpiredError`].
///
/// `max_age` is measured in caller-defined ticks. A value of `0` means the
/// secret is immediately expired: access methods clear the value and return
/// [`SecretExpiredError`]. Use a large policy value, such as `u64::MAX`, when a
/// deployment needs an expiration window that should not be reached in normal
/// operation.
///
/// The clock must not move backward for a live value. If a caller-provided tick
/// counter wraps so that `now < created_at`, [`Self::age_ticks`] returns `0`
/// through saturating arithmetic and the secret appears freshly created.
/// Callers using short-period hardware counters must extend or normalize their
/// clock before passing it to this type.
///
/// There is no background task. Expiration is checked only when a method is
/// called.
pub struct MonotonicExpiringSecretBytes<const N: usize, C: MonotonicClock> {
    inner: SecretBytes<N>,
    clock: C,
    created_at: u64,
    max_age: u64,
}

impl<const N: usize, C: MonotonicClock> MonotonicExpiringSecretBytes<N, C> {
    /// Create an all-zero expiring secret.
    ///
    /// `max_age == 0` creates a secret that is expired immediately on first
    /// access. If the caller-provided clock wraps backward, age calculation
    /// saturates to `0`; wraparound must be handled by the clock
    /// implementation.
    #[must_use]
    #[inline]
    pub fn zeroed(clock: C, max_age: u64) -> Self {
        let created_at = clock.now();
        Self {
            inner: SecretBytes::zeroed(),
            clock,
            created_at,
            max_age,
        }
    }

    /// Create an expiring secret from an array, then volatile-clear the input
    /// array.
    #[must_use]
    #[inline]
    pub fn from_array(bytes: [u8; N], clock: C, max_age: u64) -> Self {
        let created_at = clock.now();
        Self {
            inner: SecretBytes::from_array(bytes),
            clock,
            created_at,
            max_age,
        }
    }

    /// Create an expiring secret by producing each byte directly.
    #[must_use]
    #[inline]
    pub fn from_fn(clock: C, max_age: u64, make_byte: impl FnMut(usize) -> u8) -> Self {
        let created_at = clock.now();
        Self {
            inner: SecretBytes::from_fn(make_byte),
            clock,
            created_at,
            max_age,
        }
    }

    /// Create an expiring secret by fallibly producing each byte directly.
    ///
    /// If `make_byte` returns an error, any bytes generated before the error
    /// are cleared before the error is returned.
    #[inline]
    pub fn try_from_fn<E>(
        clock: C,
        max_age: u64,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, E> {
        let created_at = clock.now();
        Ok(Self {
            inner: SecretBytes::try_from_fn(make_byte)?,
            clock,
            created_at,
            max_age,
        })
    }

    /// Wrap an existing [`SecretBytes<N>`] and start a new lifetime window.
    #[must_use]
    #[inline]
    pub fn from_secret(secret: SecretBytes<N>, clock: C, max_age: u64) -> Self {
        let created_at = clock.now();
        Self {
            inner: secret,
            clock,
            created_at,
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

    /// Configured maximum age in caller-defined clock ticks.
    ///
    /// A value of `0` means immediate expiry.
    #[must_use]
    #[inline]
    pub const fn max_age_ticks(&self) -> u64 {
        self.max_age
    }

    /// Elapsed lifetime in caller-defined clock ticks.
    ///
    /// If the caller-provided clock has moved backward or wrapped around, this
    /// returns `0` through saturating arithmetic.
    #[must_use]
    #[inline]
    pub fn age_ticks(&self) -> u64 {
        self.clock.now().saturating_sub(self.created_at)
    }

    /// Returns true when the current secret value has expired.
    #[must_use]
    #[inline]
    pub fn is_expired(&self) -> bool {
        self.age_ticks() >= self.max_age
    }

    /// Borrow the monotonic clock stored by this value.
    #[must_use]
    #[inline]
    pub const fn clock(&self) -> &C {
        &self.clock
    }

    /// Replace all bytes and restart the lifetime window.
    ///
    /// The replacement is validated and staged first. The old value is then
    /// volatile-cleared before the replacement is installed.
    #[inline]
    pub fn replace_from_slice(&mut self, source: &[u8]) -> Result<(), LengthError> {
        if source.len() != N {
            if self.is_expired() {
                self.inner.secure_clear();
            }
            return Err(LengthError {
                expected: N,
                actual: source.len(),
            });
        }

        let mut replacement = SecretBytes::<N>::zeroed();
        replacement.copy_from_slice(source)?;
        self.inner.secure_clear();
        self.inner = replacement;
        self.created_at = self.clock.now();
        Ok(())
    }

    /// Replace all bytes from an owned array, clear that input array, and
    /// restart the lifetime window.
    #[inline]
    pub fn replace_from_array(&mut self, bytes: [u8; N]) {
        let replacement = SecretBytes::from_array(bytes);
        self.inner.secure_clear();
        self.inner = replacement;
        self.created_at = self.clock.now();
    }

    /// Replace all bytes from a generator and restart the lifetime window.
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
        self.created_at = self.clock.now();
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
        self.created_at = self.clock.now();
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
    /// This is the monotonic-clock variant of
    /// [`SecretBytes::expose_secret_volatile`].
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

impl<const N: usize, C: MonotonicClock> Drop for MonotonicExpiringSecretBytes<N, C> {
    #[inline]
    fn drop(&mut self) {
        self.secure_clear();
    }
}

impl<const N: usize, C: MonotonicClock> SecureSanitize for MonotonicExpiringSecretBytes<N, C> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.secure_clear();
    }
}

impl<const N: usize, C: MonotonicClock> fmt::Debug for MonotonicExpiringSecretBytes<N, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonotonicExpiringSecretBytes")
            .field("len", &N)
            .field("age_ticks", &self.age_ticks())
            .field("max_age_ticks", &self.max_age)
            .field("contents", &"<redacted>")
            .finish()
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
    /// The replacement is validated and staged first. The old value is then
    /// volatile-cleared before the replacement is installed.
    #[inline]
    pub fn replace_from_slice(&mut self, source: &[u8]) -> Result<(), LengthError> {
        if source.len() != N {
            if self.is_expired() {
                self.inner.secure_clear();
            }
            return Err(LengthError {
                expected: N,
                actual: source.len(),
            });
        }

        let mut replacement = SecretBytes::<N>::zeroed();
        replacement.copy_from_slice(source)?;
        self.inner.secure_clear();
        self.inner = replacement;
        self.created_at = std::time::Instant::now();
        Ok(())
    }

    /// Replace all bytes from an owned array, clear that input array, and
    /// restart the lifetime window.
    ///
    /// The replacement is staged first. The old value is then volatile-cleared
    /// before the replacement is installed.
    #[inline]
    pub fn replace_from_array(&mut self, bytes: [u8; N]) {
        let replacement = SecretBytes::from_array(bytes);
        self.inner.secure_clear();
        self.inner = replacement;
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

    /// Clear this value immediately with an explicit three-pass volatile
    /// pattern over the full allocation capacity.
    ///
    /// Available with the `multi-pass-clear` feature. This is intended for
    /// policy or audit compatibility; for volatile RAM, the default
    /// [`SecretVec::clear_secret`] remains the normal security boundary.
    #[cfg(feature = "multi-pass-clear")]
    #[inline(never)]
    pub fn clear_secret_multi_pass(&mut self) {
        sanitize_vec_capacity_multi_pass(&mut self.inner);
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

#[cfg(feature = "alloc")]
impl ct::ConstantTimeEq for SecretVec {
    #[inline]
    fn ct_eq(&self, other: &Self) -> ct::Choice {
        ct::eq_public_len(self.inner.as_slice(), other.inner.as_slice())
    }
}

#[cfg(feature = "alloc")]
impl ct::ConstantTimeEq<[u8]> for SecretVec {
    #[inline]
    fn ct_eq(&self, other: &[u8]) -> ct::Choice {
        ct::eq_public_len(self.inner.as_slice(), other)
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

    /// Clear this value immediately with an explicit three-pass volatile
    /// pattern over the full allocation capacity.
    ///
    /// Available with the `multi-pass-clear` feature. This is intended for
    /// policy or audit compatibility; for volatile RAM, the default
    /// [`SecretString::clear_secret`] remains the normal security boundary.
    #[cfg(feature = "multi-pass-clear")]
    #[inline(never)]
    pub fn clear_secret_multi_pass(&mut self) {
        sanitize_vec_capacity_multi_pass(&mut self.inner);
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

#[cfg(feature = "alloc")]
impl ct::ConstantTimeEq for SecretString {
    #[inline]
    fn ct_eq(&self, other: &Self) -> ct::Choice {
        ct::eq_public_len(self.inner.as_slice(), other.inner.as_slice())
    }
}

#[cfg(feature = "alloc")]
impl ct::ConstantTimeEq<str> for SecretString {
    #[inline]
    fn ct_eq(&self, other: &str) -> ct::Choice {
        ct::eq_public_len(self.inner.as_slice(), other.as_bytes())
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
///
/// For byte vectors, prefer [`SecretVec`] over `Secret<Vec<u8>>`. `Vec<T>` is
/// supported for generic sanitizable containers and clears the raw allocation
/// capacity after dropping live elements, but [`SecretVec`] provides a
/// byte-focused API with whole-value rotation helpers and fewer generic-type
/// edge cases.
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

#[allow(unsafe_code)]
mod read_once {
    use super::{fmt, SecureSanitize};
    use core::{
        cell::UnsafeCell,
        sync::atomic::{AtomicBool, Ordering},
    };

    /// Error returned after a [`ReadOnceSecret`] has already been consumed.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct AlreadyConsumedError;

    impl fmt::Display for AlreadyConsumedError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("read-once secret already consumed")
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for AlreadyConsumedError {}

    /// Clear-on-drop wrapper that can be consumed exactly once.
    ///
    /// `ReadOnceSecret<T>` uses an atomic consumed flag, so repeated access is
    /// rejected even when callers hold multiple shared references to the same
    /// wrapper. The wrapped value is cleared immediately after the first
    /// successful closure returns, and `Drop` still clears during unwinding or
    /// if the wrapper is never consumed.
    pub struct ReadOnceSecret<T: SecureSanitize> {
        inner: UnsafeCell<T>,
        consumed: AtomicBool,
    }

    // SAFETY: Moving the wrapper to another thread transfers ownership of the
    // inner value and atomic flag. Access to the inner value is still mediated
    // by the consumed flag.
    unsafe impl<T: SecureSanitize + Send> Send for ReadOnceSecret<T> {}

    // SAFETY: Shared references may race to consume the value, but the atomic
    // swap permits exactly one successful accessor. That accessor has exclusive
    // logical access until it clears the inner value before returning.
    unsafe impl<T: SecureSanitize + Send> Sync for ReadOnceSecret<T> {}

    impl<T: SecureSanitize> ReadOnceSecret<T> {
        /// Wrap a sanitizable value for one-time consumption.
        #[must_use]
        #[inline]
        pub const fn new(inner: T) -> Self {
            Self {
                inner: UnsafeCell::new(inner),
                consumed: AtomicBool::new(false),
            }
        }

        /// Run a closure with read-only access exactly once, then clear the
        /// wrapped value.
        ///
        /// The first caller wins by atomically setting the consumed flag. Any
        /// later caller receives [`AlreadyConsumedError`]. If the closure
        /// unwinds, `Drop` still clears the wrapped value during unwinding. As
        /// with all destructor-based cleanup, process abort prevents cleanup
        /// from running.
        #[inline]
        pub fn consume<R>(&self, inspect: impl FnOnce(&T) -> R) -> Result<R, AlreadyConsumedError> {
            self.claim()?;
            // SAFETY: `claim` permits exactly one successful accessor. No other
            // safe method can access `inner` after the consumed flag is set.
            let result = inspect(unsafe { &*self.inner.get() });
            self.clear_inner();
            Ok(result)
        }

        /// Run a closure with mutable access exactly once, then clear the
        /// wrapped value.
        ///
        /// This is useful for one-time protocol values that need final in-place
        /// normalization or decoding at the access boundary.
        #[inline]
        pub fn consume_mut<R>(
            &self,
            edit: impl FnOnce(&mut T) -> R,
        ) -> Result<R, AlreadyConsumedError> {
            self.claim()?;
            // SAFETY: `claim` permits exactly one successful accessor. The
            // successful caller therefore has exclusive logical access.
            let result = edit(unsafe { &mut *self.inner.get() });
            self.clear_inner();
            Ok(result)
        }

        /// Consume the wrapper after first clearing the wrapped value.
        #[inline]
        pub fn into_cleared(mut self) {
            self.consumed.store(true, Ordering::Release);
            self.inner.get_mut().secure_sanitize();
        }

        /// Returns true after the one successful consume attempt, after manual
        /// sanitization, or after [`ReadOnceSecret::into_cleared`].
        #[must_use]
        #[inline]
        pub fn is_consumed(&self) -> bool {
            self.consumed.load(Ordering::Acquire)
        }

        #[inline]
        fn claim(&self) -> Result<(), AlreadyConsumedError> {
            if self.consumed.swap(true, Ordering::AcqRel) {
                Err(AlreadyConsumedError)
            } else {
                Ok(())
            }
        }

        #[inline]
        fn clear_inner(&self) {
            // SAFETY: `clear_inner` is called only after `claim` succeeds or
            // from contexts holding `&mut self`.
            unsafe { (&mut *self.inner.get()).secure_sanitize() };
        }
    }

    impl<T: SecureSanitize> Drop for ReadOnceSecret<T> {
        #[inline]
        fn drop(&mut self) {
            self.inner.get_mut().secure_sanitize();
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
            self.consumed.store(true, Ordering::Release);
            self.inner.get_mut().secure_sanitize();
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
}

pub use read_once::{AlreadyConsumedError, ReadOnceSecret};

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
            self.with_secret(|left| other.with_secret(|right| ct::eq_fixed(left, right)))
        }
    }

    impl<const N: usize> ct::ConstantTimeEq<[u8]> for LockedSecretBytes<N> {
        #[inline]
        fn ct_eq(&self, other: &[u8]) -> ct::Choice {
            self.with_secret(|left| ct::eq_public_len(left, other))
        }
    }

    impl<'pool, const N: usize, const SLOTS: usize> ct::ConstantTimeEq
        for SecretPoolSlot<'pool, N, SLOTS>
    {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            self.with_secret(|left| other.with_secret(|right| ct::eq_fixed(left, right)))
        }
    }

    impl<'pool, const N: usize, const SLOTS: usize> ct::ConstantTimeEq<[u8]>
        for SecretPoolSlot<'pool, N, SLOTS>
    {
        #[inline]
        fn ct_eq(&self, other: &[u8]) -> ct::Choice {
            self.with_secret(|left| ct::eq_public_len(left, other))
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
}

#[cfg(feature = "zeroize-interop")]
mod zeroize_interop {
    use super::*;

    impl<const N: usize> zeroize::Zeroize for SecretBytes<N> {
        #[inline]
        fn zeroize(&mut self) {
            self.secure_clear();
        }
    }

    impl<const N: usize> zeroize::ZeroizeOnDrop for SecretBytes<N> {}

    #[cfg(feature = "alloc")]
    impl zeroize::Zeroize for SecretVec {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(feature = "alloc")]
    impl zeroize::ZeroizeOnDrop for SecretVec {}

    #[cfg(feature = "alloc")]
    impl zeroize::Zeroize for SecretString {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(feature = "alloc")]
    impl zeroize::ZeroizeOnDrop for SecretString {}

    impl<T: SecureSanitize> zeroize::Zeroize for Secret<T> {
        #[inline]
        fn zeroize(&mut self) {
            self.inner.secure_sanitize();
        }
    }

    impl<T: SecureSanitize> zeroize::ZeroizeOnDrop for Secret<T> {}

    impl<T: SecureSanitize> zeroize::Zeroize for ReadOnceSecret<T> {
        #[inline]
        fn zeroize(&mut self) {
            self.secure_sanitize();
        }
    }

    impl<T: SecureSanitize> zeroize::ZeroizeOnDrop for ReadOnceSecret<T> {}

    #[cfg(feature = "split-secret")]
    impl<const N: usize, const SHARES: usize> zeroize::Zeroize for SplitSecretBytes<N, SHARES> {
        #[inline]
        fn zeroize(&mut self) {
            self.secure_sanitize();
        }
    }

    #[cfg(feature = "split-secret")]
    impl<const N: usize, const SHARES: usize> zeroize::ZeroizeOnDrop for SplitSecretBytes<N, SHARES> {}

    #[cfg(feature = "memory-lock")]
    impl<const N: usize> zeroize::Zeroize for LockedSecretBytes<N> {
        #[inline]
        fn zeroize(&mut self) {
            self.secure_clear();
        }
    }

    #[cfg(feature = "memory-lock")]
    impl<const N: usize> zeroize::ZeroizeOnDrop for LockedSecretBytes<N> {}

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32"), not(miri)))]
    impl zeroize::Zeroize for LockedSecretVec {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32"), not(miri)))]
    impl zeroize::ZeroizeOnDrop for LockedSecretVec {}

    #[cfg(all(feature = "guard-pages", not(miri)))]
    impl zeroize::Zeroize for GuardedSecretVec {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(all(feature = "guard-pages", not(miri)))]
    impl zeroize::ZeroizeOnDrop for GuardedSecretVec {}
}

#[cfg(feature = "subtle-interop")]
mod subtle_interop {
    use super::*;
    use subtle::{Choice, ConstantTimeEq};

    impl<const N: usize> ConstantTimeEq for SecretBytes<N> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            Choice::from(self.constant_time_eq_secret(other) as u8)
        }
    }

    #[cfg(feature = "alloc")]
    impl ConstantTimeEq for SecretVec {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            Choice::from(
                self.with_secret(|left| {
                    other.with_secret(|right| constant_time_eq_slices(left, right))
                }) as u8,
            )
        }
    }

    #[cfg(feature = "alloc")]
    impl ConstantTimeEq for SecretString {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            Choice::from(constant_time_eq_slices(&self.inner, &other.inner) as u8)
        }
    }

    #[cfg(feature = "memory-lock")]
    impl<const N: usize> ConstantTimeEq for LockedSecretBytes<N> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            Choice::from(other.with_secret(|bytes| self.constant_time_eq(bytes)) as u8)
        }
    }

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32"), not(miri)))]
    impl ConstantTimeEq for LockedSecretVec {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            Choice::from(other.with_secret(|bytes| self.constant_time_eq(bytes)) as u8)
        }
    }

    #[cfg(all(feature = "guard-pages", not(miri)))]
    impl ConstantTimeEq for GuardedSecretVec {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            Choice::from(other.with_secret(|bytes| self.constant_time_eq(bytes)) as u8)
        }
    }
}

#[cfg(feature = "serde")]
mod serde_impls {
    use super::*;
    use serde::{
        de::{Error as DeError, IgnoredAny, SeqAccess, Visitor},
        Deserialize, Deserializer, Serialize, Serializer,
    };

    const REDACTED: &str = "<redacted>";

    impl<const N: usize> Serialize for SecretBytes<N> {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(REDACTED)
        }
    }

    impl<'de, const N: usize> Deserialize<'de> for SecretBytes<N> {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(SecretBytesVisitor::<N>)
        }
    }

    struct SecretBytesVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for SecretBytesVisitor<N> {
        type Value = SecretBytes<N>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "exactly {N} secret bytes")
        }

        fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            if bytes.len() != N {
                return Err(E::invalid_length(bytes.len(), &self));
            }

            let mut secret = SecretBytes::<N>::zeroed();
            secret.copy_from_slice(bytes).map_err(E::custom)?;
            Ok(secret)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut secret = SecretBytes::<N>::zeroed();
            let mut index = 0;
            while index < N {
                let Some(byte) = sequence.next_element::<u8>()? else {
                    return Err(A::Error::invalid_length(index, &self));
                };
                secret.store(index, byte);
                index += 1;
            }

            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::invalid_length(N.saturating_add(1), &self));
            }

            secret.after_secret_write();
            Ok(secret)
        }
    }

    #[cfg(feature = "alloc")]
    impl Serialize for SecretVec {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(REDACTED)
        }
    }

    #[cfg(feature = "alloc")]
    impl<'de> Deserialize<'de> for SecretVec {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(SecretVecVisitor)
        }
    }

    #[cfg(feature = "alloc")]
    struct SecretVecVisitor;

    #[cfg(feature = "alloc")]
    impl<'de> Visitor<'de> for SecretVecVisitor {
        type Value = SecretVec;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("secret bytes")
        }

        fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            Ok(SecretVec::from_slice(bytes))
        }

        fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            Ok(SecretVec::from_vec(bytes))
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or(0);
            let mut secret = SecretVec::with_capacity(capacity);
            while let Some(byte) = sequence.next_element::<u8>()? {
                secret.extend_from_slice(&[byte]);
            }
            Ok(secret)
        }
    }

    #[cfg(feature = "alloc")]
    impl Serialize for SecretString {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(REDACTED)
        }
    }

    #[cfg(feature = "alloc")]
    impl<'de> Deserialize<'de> for SecretString {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_string(SecretStringVisitor)
        }
    }

    #[cfg(feature = "alloc")]
    struct SecretStringVisitor;

    #[cfg(feature = "alloc")]
    impl<'de> Visitor<'de> for SecretStringVisitor {
        type Value = SecretString;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("secret UTF-8 text")
        }

        fn visit_str<E>(self, text: &str) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            Ok(SecretString::from_secret_str(text))
        }

        fn visit_string<E>(self, text: String) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            Ok(SecretString::from_string(text))
        }
    }

    impl<T> Serialize for Secret<T>
    where
        T: SecureSanitize,
    {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(REDACTED)
        }
    }

    impl<'de, T> Deserialize<'de> for Secret<T>
    where
        T: SecureSanitize + Deserialize<'de>,
    {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            T::deserialize(deserializer).map(Secret::new)
        }
    }

    impl<T> Serialize for ReadOnceSecret<T>
    where
        T: SecureSanitize,
    {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(REDACTED)
        }
    }

    impl<'de, T> Deserialize<'de> for ReadOnceSecret<T>
    where
        T: SecureSanitize + Deserialize<'de>,
    {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            T::deserialize(deserializer).map(ReadOnceSecret::new)
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    struct TestClock<'a>(&'a core::cell::Cell<u64>);

    impl MonotonicClock for TestClock<'_> {
        #[inline]
        fn now(&self) -> u64 {
            self.0.get()
        }
    }

    #[test]
    fn ct_choice_normalizes_and_declassifies_explicitly() {
        let false_choice = ct::Choice::from_u8(0);
        let true_choice = ct::Choice::from_u8(7);

        assert_eq!(false_choice.unwrap_u8(), 0);
        assert_eq!(true_choice.unwrap_u8(), 1);
        assert_eq!((true_choice & false_choice).unwrap_u8(), 0);
        assert_eq!((true_choice | false_choice).unwrap_u8(), 1);
        assert_eq!((true_choice ^ ct::Choice::TRUE).unwrap_u8(), 0);
        assert_eq!((!false_choice).unwrap_u8(), 1);
        assert!(true_choice.declassify("test assertion"));
        assert!(!false_choice.declassify("test assertion"));
    }

    #[test]
    fn ct_primitives_compare_and_select() {
        use ct::{
            ConditionallyAssignable, ConditionallySelectable, ConstantTimeEq, ConstantTimeOrd,
        };

        assert_eq!(7u8.ct_eq(&7).unwrap_u8(), 1);
        assert_eq!(7u8.ct_eq(&8).unwrap_u8(), 0);
        assert_eq!((-3i32).ct_eq(&-3).unwrap_u8(), 1);
        assert_eq!((-3i32).ct_ne(&4).unwrap_u8(), 1);
        assert_eq!(3u8.ct_cmp(&9).is_less().unwrap_u8(), 1);
        assert_eq!(9u16.ct_cmp(&3).is_greater().unwrap_u8(), 1);
        assert_eq!(5usize.ct_cmp(&5).is_equal().unwrap_u8(), 1);
        assert_eq!((-9i32).ct_lt(&-3).unwrap_u8(), 1);
        assert_eq!(3i32.ct_gt(&-9).unwrap_u8(), 1);
        assert_eq!(
            3u8.ct_cmp(&9).declassify("test exposes primitive ordering"),
            core::cmp::Ordering::Less
        );

        let selected = u32::conditional_select(&11, &22, ct::Choice::TRUE);
        assert_eq!(selected, 22);

        let mut assigned = 11u32;
        assigned.conditional_assign(&22, ct::Choice::FALSE);
        assert_eq!(assigned, 11);
        assigned.conditional_assign(&22, ct::Choice::TRUE);
        assert_eq!(assigned, 22);
    }

    #[test]
    fn ct_ordering_constructor_normalizes_invalid_states() {
        assert_eq!(
            ct::CtOrdering::new(ct::Choice::TRUE, ct::Choice::TRUE, ct::Choice::FALSE),
            ct::CtOrdering::LESS
        );
        assert_eq!(
            ct::CtOrdering::new(ct::Choice::FALSE, ct::Choice::TRUE, ct::Choice::TRUE),
            ct::CtOrdering::GREATER
        );
        assert_eq!(
            ct::CtOrdering::new(ct::Choice::FALSE, ct::Choice::FALSE, ct::Choice::FALSE),
            ct::CtOrdering::EQUAL
        );
    }

    #[test]
    fn ct_arrays_and_public_len_slices_compare() {
        use ct::{ConditionallySelectable, ConstantTimeEq, ConstantTimeOrd};

        let left = [1u8, 2, 3, 4];
        let same = [1u8, 2, 3, 4];
        let different = [1u8, 2, 3, 9];

        assert_eq!(ct::eq_fixed(&left, &same).unwrap_u8(), 1);
        assert_eq!(left.ct_eq(&different).unwrap_u8(), 0);
        assert_eq!(ct::cmp_fixed(&left, &different).is_less().unwrap_u8(), 1);
        assert_eq!(different.ct_cmp(&left).is_greater().unwrap_u8(), 1);
        assert_eq!(same.ct_cmp(&left).is_equal().unwrap_u8(), 1);
        assert_eq!(ct::eq_public_len(&left, &[1, 2, 3]).unwrap_u8(), 0);

        let selected = <[u8; 4]>::conditional_select(&left, &different, ct::Choice::TRUE);
        assert_eq!(selected, different);
    }

    #[test]
    fn ct_oblivious_lookup_scans_public_table() {
        let table = [10u8, 20, 30, 40];

        let selected = ct::oblivious_lookup(&table, ct::Secret::new(2usize), &99);
        assert_eq!(selected, 30);

        let fallback = ct::oblivious_lookup(&table, ct::Secret::new(7usize), &99);
        assert_eq!(fallback, 99);

        let secret_selected = ct::oblivious_lookup_secret(&table, ct::Secret::new(1usize), &99);
        assert_eq!(*secret_selected.expose_secret(), 20);
    }

    #[test]
    fn ct_conditional_copy_swap_and_select_slice() {
        let mut destination = [1u8, 2, 3, 4];
        let source = [9u8, 8, 7, 6];

        ct::conditional_copy(&mut destination, &source, ct::Choice::FALSE).unwrap();
        assert_eq!(destination, [1, 2, 3, 4]);

        ct::conditional_copy(&mut destination, &source, ct::Choice::TRUE).unwrap();
        assert_eq!(destination, source);

        let mut left = [1u8, 2, 3];
        let mut right = [7u8, 8, 9];
        ct::conditional_swap(&mut left, &mut right, ct::Choice::FALSE).unwrap();
        assert_eq!(left, [1, 2, 3]);
        assert_eq!(right, [7, 8, 9]);

        ct::conditional_swap(&mut left, &mut right, ct::Choice::TRUE).unwrap();
        assert_eq!(left, [7, 8, 9]);
        assert_eq!(right, [1, 2, 3]);

        let mut selected = [0u8; 3];
        ct::select_slice(&mut selected, &left, &right, ct::Choice::FALSE).unwrap();
        assert_eq!(selected, left);
        ct::select_slice(&mut selected, &left, &right, ct::Choice::TRUE).unwrap();
        assert_eq!(selected, right);
    }

    #[test]
    fn ct_memory_helpers_report_public_length_errors() {
        let mut destination = [0u8; 4];
        assert_eq!(
            ct::conditional_copy(&mut destination, &[1, 2], ct::Choice::TRUE),
            Err(LengthError {
                expected: 4,
                actual: 2,
            })
        );

        let mut left = [1u8, 2, 3];
        let mut right = [4u8, 5];
        assert_eq!(
            ct::conditional_swap(&mut left, &mut right, ct::Choice::TRUE),
            Err(LengthError {
                expected: 3,
                actual: 2,
            })
        );

        assert_eq!(
            ct::select_slice(&mut destination, &[1, 2, 3], &[4, 5], ct::Choice::TRUE),
            Err(LengthError {
                expected: 3,
                actual: 2,
            })
        );
    }

    #[test]
    fn ct_secret_containers_expose_native_traits() {
        use ct::{ConditionallySelectable, ConstantTimeEq};

        let left = SecretBytes::from_array([1u8, 2, 3, 4]);
        let same = SecretBytes::from_array([1u8, 2, 3, 4]);
        let different = SecretBytes::from_array([9u8, 8, 7, 6]);

        assert_eq!(left.ct_eq(&same).unwrap_u8(), 1);
        assert_eq!(left.ct_eq(&different).unwrap_u8(), 0);
        assert_eq!(left.ct_eq([1u8, 2, 3, 4].as_slice()).unwrap_u8(), 1);

        let selected = SecretBytes::conditional_select(&left, &different, ct::Choice::TRUE);
        assert!(selected.constant_time_eq(&[9, 8, 7, 6]));

        #[cfg(feature = "alloc")]
        {
            let vec_left = SecretVec::from_slice(b"token");
            let vec_same = SecretVec::from_slice(b"token");
            let vec_different = SecretVec::from_slice(b"other");
            assert_eq!(vec_left.ct_eq(&vec_same).unwrap_u8(), 1);
            assert_eq!(vec_left.ct_eq(&vec_different).unwrap_u8(), 0);
            assert_eq!(vec_left.ct_eq(b"token".as_slice()).unwrap_u8(), 1);

            let string_left = SecretString::from_secret_str("token");
            let string_same = SecretString::from_secret_str("token");
            let string_different = SecretString::from_secret_str("other");
            assert_eq!(string_left.ct_eq(&string_same).unwrap_u8(), 1);
            assert_eq!(string_left.ct_eq(&string_different).unwrap_u8(), 0);
            assert_eq!(string_left.ct_eq("token").unwrap_u8(), 1);
        }

        #[cfg(all(
            feature = "memory-lock",
            not(miri),
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
        {
            let (locked_left, locked_same, locked_different) = match (
                LockedSecretBytes::from_array([1u8, 2, 3, 4]),
                LockedSecretBytes::from_array([1u8, 2, 3, 4]),
                LockedSecretBytes::from_array([9u8, 8, 7, 6]),
            ) {
                (Ok(left), Ok(same), Ok(different)) => (left, same, different),
                _ => return,
            };
            assert_eq!(locked_left.ct_eq(&locked_same).unwrap_u8(), 1);
            assert_eq!(locked_left.ct_eq(&locked_different).unwrap_u8(), 0);
            assert_eq!(locked_left.ct_eq([1u8, 2, 3, 4].as_slice()).unwrap_u8(), 1);

            let pool = match SecretPool::<4, 2>::new() {
                Ok(pool) => pool,
                Err(_) => return,
            };
            let pooled_left = pool.allocate_from_array([1u8, 2, 3, 4]).unwrap();
            let pooled_same = pool.allocate_from_array([1u8, 2, 3, 4]).unwrap();
            assert_eq!(pooled_left.ct_eq(&pooled_same).unwrap_u8(), 1);
            assert_eq!(pooled_left.ct_eq([1u8, 2, 3, 4].as_slice()).unwrap_u8(), 1);
        }

        #[cfg(all(
            feature = "memory-lock",
            not(target_arch = "wasm32"),
            not(miri),
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
        {
            let (locked_vec_left, locked_vec_same, locked_vec_different) = match (
                LockedSecretVec::from_slice(b"token"),
                LockedSecretVec::from_slice(b"token"),
                LockedSecretVec::from_slice(b"other"),
            ) {
                (Ok(left), Ok(same), Ok(different)) => (left, same, different),
                _ => return,
            };
            assert_eq!(locked_vec_left.ct_eq(&locked_vec_same).unwrap_u8(), 1);
            assert_eq!(locked_vec_left.ct_eq(&locked_vec_different).unwrap_u8(), 0);
            assert_eq!(locked_vec_left.ct_eq(b"token".as_slice()).unwrap_u8(), 1);
        }

        #[cfg(all(
            feature = "guard-pages",
            not(miri),
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
        {
            let (guarded_left, guarded_same, guarded_different) = match (
                GuardedSecretVec::from_slice(b"token"),
                GuardedSecretVec::from_slice(b"token"),
                GuardedSecretVec::from_slice(b"other"),
            ) {
                (Ok(left), Ok(same), Ok(different)) => (left, same, different),
                _ => return,
            };
            assert_eq!(guarded_left.ct_eq(&guarded_same).unwrap_u8(), 1);
            assert_eq!(guarded_left.ct_eq(&guarded_different).unwrap_u8(), 0);
            assert_eq!(guarded_left.ct_eq(b"token".as_slice()).unwrap_u8(), 1);
        }
    }

    #[test]
    fn ct_option_keeps_presence_as_choice() {
        use ct::ConditionallySelectable;

        let present = ct::CtOption::some(9u8);
        let absent = ct::CtOption::none(3u8);

        assert_eq!(present.is_some().unwrap_u8(), 1);
        assert_eq!(absent.is_none().unwrap_u8(), 1);
        assert_eq!(present.unwrap_or(&1), 9);
        assert_eq!(absent.unwrap_or(&1), 1);
        assert_eq!(present.map(|value| value.wrapping_add(1)).unwrap_or(&0), 10);
        assert_eq!(
            absent
                .map(|value| value.wrapping_add(1))
                .declassify("test exposes mapped optional absence"),
            None
        );
        assert_eq!(present.and(ct::CtOption::some(4u8)).unwrap_or(&0), 4);
        assert_eq!(present.and(ct::CtOption::none(4u8)).unwrap_or(&0), 0);
        assert_eq!(present.or(ct::CtOption::some(4u8)).unwrap_or(&0), 9);
        assert_eq!(absent.or(ct::CtOption::some(4u8)).unwrap_or(&0), 4);
        let selected =
            ct::CtOption::conditional_select(&present, &ct::CtOption::some(11), ct::Choice::TRUE);
        assert_eq!(selected.unwrap_or(&0), 11);
        assert_eq!(present.declassify("test exposes optional success"), Some(9));
        assert_eq!(absent.declassify("test exposes optional absence"), None);
    }

    #[test]
    fn ct_result_keeps_success_as_choice() {
        use ct::ConditionallySelectable;

        let ok = ct::CtResult::new(7u8, 99u8, ct::Choice::TRUE);
        let err = ct::CtResult::new(7u8, 99u8, ct::Choice::FALSE);

        assert_eq!(ok.is_ok().unwrap_u8(), 1);
        assert_eq!(ok.is_err().unwrap_u8(), 0);
        assert_eq!(err.is_ok().unwrap_u8(), 0);
        assert_eq!(err.is_err().unwrap_u8(), 1);
        assert_eq!(ok.unwrap_or(&1), 7);
        assert_eq!(err.unwrap_or(&1), 1);
        assert_eq!(ok.map(|value| value.wrapping_add(1)).unwrap_or(&0), 8);
        assert_eq!(
            err.map(|value| value.wrapping_add(1))
                .declassify("test exposes mapped result error"),
            Err(99)
        );
        assert_eq!(
            ok.map_err(|error| error.wrapping_add(1))
                .declassify("test exposes mapped result success"),
            Ok(7)
        );
        assert_eq!(
            err.map_err(|error| error.wrapping_add(1))
                .declassify("test exposes mapped result error"),
            Err(100)
        );
        let selected = ct::CtResult::conditional_select(
            &ok,
            &ct::CtResult::new(42u8, 1u8, ct::Choice::TRUE),
            ct::Choice::TRUE,
        );
        assert_eq!(selected.unwrap_or(&0), 42);
        assert_eq!(ok.declassify("test exposes result success"), Ok(7));
        assert_eq!(err.declassify("test exposes result error"), Err(99));
    }

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

    #[cfg(feature = "zeroize-interop")]
    #[test]
    fn zeroize_interop_clears_secret_bytes() {
        use zeroize::Zeroize;

        let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);
        secret.zeroize();

        assert_eq!(secret.expose_secret(|bytes| *bytes), [0; 4]);
    }

    #[cfg(feature = "subtle-interop")]
    #[test]
    fn subtle_interop_compares_secret_bytes() {
        use subtle::ConstantTimeEq;

        let left = SecretBytes::<4>::from_array([1, 2, 3, 4]);
        let same = SecretBytes::<4>::from_array([1, 2, 3, 4]);
        let different = SecretBytes::<4>::from_array([1, 2, 3, 0]);

        assert_eq!(left.ct_eq(&same).unwrap_u8(), 1);
        assert_eq!(left.ct_eq(&different).unwrap_u8(), 0);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_interop_loads_fixed_secret_bytes_and_redacts_output() {
        let secret: SecretBytes<4> = serde_json::from_str("[1,2,3,4]").unwrap();

        assert_eq!(secret.expose_secret(|bytes| *bytes), [1, 2, 3, 4]);
        assert_eq!(serde_json::to_string(&secret).unwrap(), "\"<redacted>\"");
    }

    #[cfg(all(feature = "serde", feature = "alloc"))]
    #[test]
    fn serde_interop_loads_alloc_secrets_and_redacts_output() {
        let bytes: SecretVec = serde_json::from_str("[1,2,3,4]").unwrap();
        let text: SecretString = serde_json::from_str("\"token\"").unwrap();

        assert_eq!(bytes.with_secret(|secret| secret.len()), 4);
        assert_eq!(text.try_with_secret(str::len), Ok(5));
        assert_eq!(serde_json::to_string(&bytes).unwrap(), "\"<redacted>\"");
        assert_eq!(serde_json::to_string(&text).unwrap(), "\"<redacted>\"");
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
        fn assert_sync<T: Sync>() {}

        assert_send::<LockedSecretBytes<4>>();
        assert_send::<SecretPool<4, 2>>();
        assert_sync::<SecretPool<4, 2>>();
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

    #[cfg(feature = "multi-pass-clear")]
    #[test]
    fn secret_bytes_can_clear_multi_pass() {
        let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);

        secret.secure_clear_multi_pass();

        assert!(secret.constant_time_eq(&[0, 0, 0, 0]));
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

    #[cfg(all(
        feature = "asm-compare",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
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
    fn monotonic_expiring_secret_allows_access_before_expiration() {
        let ticks = core::cell::Cell::new(10);
        let mut secret =
            MonotonicExpiringSecretBytes::<4, _>::from_array([1, 2, 3, 4], TestClock(&ticks), 5);
        let mut out = [0; 4];

        ticks.set(14);

        assert_eq!(secret.age_ticks(), 4);
        assert!(!secret.is_expired());
        assert_eq!(secret.try_copy_to_slice(&mut out), Ok(()));
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(secret.try_constant_time_eq(&[1, 2, 3, 4]), Ok(true));
    }

    #[test]
    fn monotonic_expiring_secret_clears_and_rejects_after_expiration() {
        let ticks = core::cell::Cell::new(10);
        let mut secret =
            MonotonicExpiringSecretBytes::<4, _>::from_array([1, 2, 3, 4], TestClock(&ticks), 5);
        let mut out = [9; 4];

        ticks.set(15);

        assert!(secret.is_expired());
        assert_eq!(
            secret.try_copy_to_slice(&mut out),
            Err(ExpiringSecretError::Expired(SecretExpiredError))
        );
        assert_eq!(
            secret.try_expose_secret(|bytes| bytes[0]),
            Err(SecretExpiredError)
        );
    }

    #[test]
    fn monotonic_expiring_secret_zero_max_age_expires_immediately() {
        let ticks = core::cell::Cell::new(10);
        let mut secret =
            MonotonicExpiringSecretBytes::<4, _>::from_array([1, 2, 3, 4], TestClock(&ticks), 0);

        assert_eq!(secret.age_ticks(), 0);
        assert!(secret.is_expired());
        assert_eq!(
            secret.try_expose_secret(|bytes| bytes[0]),
            Err(SecretExpiredError)
        );
    }

    #[test]
    fn monotonic_expiring_secret_replacement_restarts_lifetime() {
        let ticks = core::cell::Cell::new(10);
        let mut secret =
            MonotonicExpiringSecretBytes::<4, _>::from_array([1, 2, 3, 4], TestClock(&ticks), 5);
        let mut out = [0; 4];

        ticks.set(15);
        secret.replace_from_array([5, 6, 7, 8]);

        assert_eq!(secret.age_ticks(), 0);
        assert_eq!(secret.try_copy_to_slice(&mut out), Ok(()));
        assert_eq!(out, [5, 6, 7, 8]);

        ticks.set(17);
        secret.replace_from_slice(&[8, 7, 6, 5]).unwrap();
        assert_eq!(secret.age_ticks(), 0);
        assert_eq!(secret.try_copy_to_slice(&mut out), Ok(()));
        assert_eq!(out, [8, 7, 6, 5]);
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
    fn read_once_secret_consumes_once_by_shared_reference() {
        let secret = ReadOnceSecret::new(SecretBytes::<4>::from_array([1, 2, 3, 4]));

        let sum = secret.consume(|bytes| {
            let mut out = [0; 4];
            bytes.copy_to_slice(&mut out).unwrap();
            out.iter().copied().fold(0_u8, u8::wrapping_add)
        });

        assert_eq!(sum, Ok(10));
        assert_eq!(
            secret.consume(|_| unreachable!()),
            Err(AlreadyConsumedError)
        );
        assert!(secret.is_consumed());
    }

    #[test]
    fn read_once_secret_allows_mutable_finalization() {
        let secret = ReadOnceSecret::new([1_u8, 2, 3, 4]);

        let first = secret.consume_mut(|bytes| {
            bytes[0] = 9;
            bytes[0]
        });

        assert_eq!(first, Ok(9));
        assert_eq!(
            secret.consume_mut(|_| unreachable!()),
            Err(AlreadyConsumedError)
        );
    }

    #[test]
    fn read_once_secret_allows_only_one_shared_consumer() {
        let secret = std::sync::Arc::new(ReadOnceSecret::new([1_u8, 2, 3, 4]));
        let worker_secret = std::sync::Arc::clone(&secret);
        let start = std::sync::Arc::new(std::sync::Barrier::new(2));
        let worker_start = std::sync::Arc::clone(&start);

        let worker = std::thread::spawn(move || {
            worker_start.wait();
            worker_secret.consume(|bytes| bytes[0])
        });

        start.wait();
        let main_result = secret.consume(|bytes| bytes[0]);
        let worker_result = worker.join().unwrap();

        let successes = usize::from(main_result.is_ok()) + usize::from(worker_result.is_ok());
        let failures = usize::from(main_result == Err(AlreadyConsumedError))
            + usize::from(worker_result == Err(AlreadyConsumedError));

        assert_eq!(successes, 1);
        assert_eq!(failures, 1);
    }

    #[test]
    fn read_once_secret_default_and_debug_are_safe() {
        let secret = ReadOnceSecret::<[u8; 4]>::default();
        let rendered = std::format!("{secret:?}");

        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("consumed"));
        assert!(!rendered.contains("[0, 0, 0, 0]"));
    }

    #[cfg(feature = "split-secret")]
    #[test]
    fn split_secret_reconstructs_with_all_shares() {
        let split =
            SplitSecretBytes::<4, 3>::from_array_with_generator([9, 8, 7, 6], |share, index| {
                ((share as u8) << 4) ^ (index as u8)
            })
            .unwrap();

        assert_eq!(split.shares().len(), 3);
        assert!(split
            .reconstruct()
            .constant_time_eq_secret(&SecretBytes::from_array([9, 8, 7, 6])));
        assert!(std::format!("{split:?}").contains("redacted"));
    }

    #[cfg(feature = "split-secret")]
    #[test]
    fn split_secret_rejects_trivially_constant_masks() {
        assert!(matches!(
            SplitSecretBytes::<4, 3>::from_array_with_generator([9, 8, 7, 6], |_, _| 0),
            Err(SplitSecretError::TrivialMask)
        ));
    }

    #[cfg(feature = "split-secret")]
    #[test]
    fn split_secret_rejects_canceling_mask_accumulator() {
        assert!(matches!(
            SplitSecretBytes::<4, 3>::from_array_with_generator([9, 8, 7, 6], |_, index| {
                [1, 2, 3, 4][index]
            }),
            Err(SplitSecretError::TrivialMask)
        ));
    }

    #[cfg(feature = "split-secret")]
    #[test]
    fn split_secret_can_consume_source_secret() {
        let secret = SecretBytes::from_array([9, 8, 7, 6]);
        let split = SplitSecretBytes::<4, 3>::from_secret_consuming_with_generator(
            secret,
            |share, index| ((share as u8) << 4) ^ (index as u8),
        )
        .unwrap();

        assert!(split
            .reconstruct()
            .constant_time_eq_secret(&SecretBytes::from_array([9, 8, 7, 6])));
    }

    #[cfg(feature = "split-secret")]
    #[test]
    fn split_secret_requires_multiple_shares() {
        assert!(matches!(
            SplitSecretBytes::<4, 1>::from_array_with_generator([1, 2, 3, 4], |_, _| 0),
            Err(SplitSecretError::TooFewShares)
        ));
    }

    #[cfg(feature = "hardware-secrets")]
    #[test]
    fn hardware_secret_error_is_displayable() {
        let error = hardware::HardwareSecretError {
            kind: hardware::HardwareSecretErrorKind::Unavailable,
            code: 0,
        };

        assert!(std::format!("{error}").contains("Unavailable"));
    }

    #[cfg(feature = "register-scrub")]
    #[test]
    fn register_scrub_api_is_callable() {
        register_scrub::scrub_simd_registers();
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

    #[cfg(feature = "multi-pass-clear")]
    #[test]
    fn multi_pass_wipe_clears_slice() {
        let mut bytes = [0xA5; 16];

        sanitize_bytes_multi_pass(&mut bytes);

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

    #[cfg(all(feature = "alloc", feature = "multi-pass-clear"))]
    #[test]
    fn multi_pass_wipe_clears_alloc_types_when_enabled() {
        let mut bytes = SecretVec::from_slice(&[1, 2, 3]);
        let mut text = SecretString::from_secret_str("secret");
        let mut ordinary = std::vec![0xBB; 8];
        let mut ordinary_text = std::string::String::from("secret");

        bytes.clear_secret_multi_pass();
        text.clear_secret_multi_pass();
        crate::unsafe_wipe::volatile_sanitize_vec_multi_pass(&mut ordinary);
        crate::unsafe_wipe::volatile_sanitize_string_multi_pass(&mut ordinary_text);

        assert!(bytes.is_empty());
        assert!(text.is_empty());
        assert!(ordinary.is_empty());
        assert!(ordinary_text.is_empty());
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
        #[cfg(feature = "canary-check")]
        {
            assert_eq!(secret.verify_integrity(), Ok(()));
            assert!(secret.copy_to_slice(&mut out).is_ok());
            assert_eq!(out, [0, 0, 0, 0]);
            assert!(secret.copy_from_slice(&[9, 8, 7, 6]).is_ok());
            assert!(secret.constant_time_eq(&[9, 8, 7, 6]));
        }
        #[cfg(not(feature = "canary-check"))]
        {
            assert!(secret.copy_to_slice(&mut out).is_ok());
            assert_eq!(out, [0, 0, 0, 0]);
        }

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
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn locked_secret_bytes_can_fill_in_place() {
        let mut secret = match LockedSecretBytes::<4>::from_fill(|output| {
            output.copy_from_slice(&[1, 2, 3, 4]);
        }) {
            Ok(secret) => secret,
            Err(_) => return,
        };

        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        match LockedSecretBytes::<4>::try_from_fill(|output| {
            output[..2].copy_from_slice(&[9, 8]);
            Err("decode failed")
        }) {
            Ok(_) => panic!("fill should have failed"),
            Err(LockedSecretBytesGenerateError::Memory(_)) => return,
            Err(LockedSecretBytesGenerateError::Generate(error)) => {
                assert_eq!(error, "decode failed");
            }
        }

        secret
            .replace_from_fill(|output| output.copy_from_slice(&[5, 6, 7, 8]))
            .unwrap();
        assert!(secret.constant_time_eq(&[5, 6, 7, 8]));

        assert_eq!(
            secret.try_replace_from_fill(|output| {
                output[0] = 0;
                Err("decode failed")
            }),
            Err(LockedSecretBytesGenerateError::Generate("decode failed"))
        );
        assert!(secret.constant_time_eq(&[5, 6, 7, 8]));
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn locked_secret_vec_round_trip_grow_replace_and_clear() {
        let mut secret = match LockedSecretVec::from_slice(b"key") {
            Ok(secret) => secret,
            Err(_) => return,
        };

        assert_eq!(secret.len(), 3);
        assert!(secret.capacity() >= 3);
        assert!(secret.locked_len() >= 3);
        assert_eq!(secret.with_secret(|bytes| bytes[0]), b'k');
        assert!(secret.constant_time_eq(b"key"));
        assert!(!secret.constant_time_eq(b"ke"));

        secret.extend_from_slice(b"-material").unwrap();
        assert!(secret.constant_time_eq(b"key-material"));

        secret
            .replace_from_fn(4, |index| (index as u8) + 1)
            .unwrap();
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        assert_eq!(
            secret.try_replace_from_fn(4, |index| {
                if index == 2 {
                    Err("generation failed")
                } else {
                    Ok(index as u8)
                }
            }),
            Err(LockedSecretVecGenerateError::Generate("generation failed"))
        );
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

        secret.with_secret_mut(|bytes| bytes[0] = 9);
        assert!(secret.constant_time_eq(&[9, 2, 3, 4]));

        secret.clear_secret();
        assert!(secret.is_empty());
        #[cfg(feature = "canary-check")]
        assert_eq!(secret.verify_integrity(), Ok(()));

        secret.extend_from_slice(b"next").unwrap();
        assert!(secret.constant_time_eq(b"next"));
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn locked_secret_vec_can_fill_in_place() {
        let mut exact = match LockedSecretVec::from_exact_len(4, |output| {
            output.copy_from_slice(&[1, 2, 3, 4]);
        }) {
            Ok(secret) => secret,
            Err(_) => return,
        };
        assert!(exact.constant_time_eq(&[1, 2, 3, 4]));

        match LockedSecretVec::try_from_exact_len(4, |output| {
            output[..2].copy_from_slice(&[9, 8]);
            Err("decode failed")
        }) {
            Ok(_) => panic!("fill should have failed"),
            Err(LockedSecretVecGenerateError::Memory(_)) => return,
            Err(LockedSecretVecGenerateError::Generate(error)) => {
                assert_eq!(error, "decode failed");
            }
        }

        let mut bounded = match LockedSecretVec::from_capacity(8, |output| {
            output[..5].copy_from_slice(b"token");
            output[5..8].copy_from_slice(b"old");
            5
        }) {
            Ok(secret) => secret,
            Err(LockedSecretVecFillError::Memory(_)) => return,
            Err(error) => panic!("unexpected capacity fill error: {error}"),
        };
        assert_eq!(bounded.len(), 5);
        assert!(bounded.capacity() >= 8);
        assert!(bounded.constant_time_eq(b"token"));

        match LockedSecretVec::try_from_capacity(4, |output| {
            output.copy_from_slice(b"abcd");
            Ok::<usize, &'static str>(5)
        }) {
            Ok(_) => panic!("reported length should have failed"),
            Err(LockedSecretVecFillError::Memory(_)) => return,
            Err(error) => assert_eq!(
                error,
                LockedSecretVecFillError::Length(LengthError {
                    expected: 4,
                    actual: 5,
                })
            ),
        }

        exact
            .replace_from_exact_len(3, |output| output.copy_from_slice(b"key"))
            .unwrap();
        assert!(exact.constant_time_eq(b"key"));

        assert_eq!(
            exact.try_replace_from_exact_len(4, |output| {
                output[..2].copy_from_slice(&[9, 8]);
                Err("decode failed")
            }),
            Err(LockedSecretVecGenerateError::Generate("decode failed"))
        );
        assert!(exact.constant_time_eq(b"key"));

        assert_eq!(
            exact.try_replace_from_exact_len(4, |output| {
                output.copy_from_slice(b"fail");
                Err("decode failed")
            }),
            Err(LockedSecretVecGenerateError::Generate("decode failed"))
        );
        assert!(exact.constant_time_eq(b"key"));

        bounded
            .replace_from_capacity(8, |output| {
                output[..6].copy_from_slice(b"secret");
                6
            })
            .unwrap();
        assert!(bounded.constant_time_eq(b"secret"));

        assert_eq!(
            bounded.try_replace_from_capacity(4, |output| {
                output.copy_from_slice(b"abcd");
                Ok::<usize, &'static str>(5)
            }),
            Err(LockedSecretVecFillError::Length(LengthError {
                expected: 4,
                actual: 5,
            }))
        );
        assert!(bounded.constant_time_eq(b"secret"));
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn locked_secret_vec_zero_capacity_is_reusable() {
        let mut secret = LockedSecretVec::with_capacity(0).unwrap();

        assert!(secret.is_empty());
        assert_eq!(secret.capacity(), 0);
        assert_eq!(secret.locked_len(), 0);
        secret.clear_secret();
        #[cfg(feature = "canary-check")]
        assert_eq!(secret.verify_integrity(), Ok(()));

        if secret.extend_from_slice(b"x").is_err() {
            return;
        }
        assert!(secret.constant_time_eq(b"x"));
    }

    #[cfg(all(
        feature = "std",
        feature = "canary-check",
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn locked_secret_vec_canaries_detect_corruption() {
        let mut secret = match LockedSecretVec::from_slice(b"secret") {
            Ok(secret) => secret,
            Err(_) => return,
        };

        assert_eq!(secret.verify_integrity(), Ok(()));
        assert_eq!(secret.expose_secret_checked(|bytes| bytes[0]), Ok(b's'));
        assert_eq!(secret.constant_time_eq_checked(b"secret"), Ok(true));

        secret.corrupt_prefix_canary_for_test();

        assert_eq!(
            secret.expose_secret_checked(|bytes| bytes[0]),
            Err(CanaryCorruptedError)
        );
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
        #[cfg(not(feature = "canary-check"))]
        let mut out = [0; 4];

        secret.secure_clear_and_flush();

        #[cfg(feature = "canary-check")]
        assert_eq!(secret.verify_integrity(), Ok(()));
        #[cfg(not(feature = "canary-check"))]
        {
            assert!(secret.copy_to_slice(&mut out).is_ok());
            assert_eq!(out, [0, 0, 0, 0]);
        }
    }

    #[cfg(all(
        feature = "std",
        feature = "canary-check",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn locked_secret_canary_checked_apis_detect_corruption() {
        let mut secret = match LockedSecretBytes::<4>::from_array([1, 2, 3, 4]) {
            Ok(secret) => secret,
            Err(_) => return,
        };
        let mut out = [0; 4];

        assert_eq!(secret.verify_integrity(), Ok(()));
        assert_eq!(secret.expose_secret_checked(|bytes| bytes[0]), Ok(1));
        assert_eq!(secret.copy_to_slice_checked(&mut out), Ok(()));
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(secret.constant_time_eq_checked(&[1, 2, 3, 4]), Ok(true));
        assert_eq!(
            secret.copy_to_slice_checked(&mut [0; 2]),
            Err(LockedSecretBytesCheckedCopyError::Length(LengthError {
                expected: 4,
                actual: 2,
            }))
        );

        secret.corrupt_prefix_canary_for_test();

        assert_eq!(
            secret.expose_secret_checked(|bytes| bytes[0]),
            Err(CanaryCorruptedError)
        );
    }

    #[cfg(all(
        feature = "std",
        feature = "canary-check",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn locked_secret_canary_legacy_exposure_fails_closed() {
        let mut secret = match LockedSecretBytes::<4>::from_array([1, 2, 3, 4]) {
            Ok(secret) => secret,
            Err(_) => return,
        };

        secret.corrupt_prefix_canary_for_test();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = secret.with_secret(|bytes| bytes[0]);
        }));

        assert!(result.is_err());
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn secret_pool_allocates_reuses_and_clears_slots() {
        let pool = match SecretPool::<4, 2>::new() {
            Ok(pool) => pool,
            Err(_) => return,
        };

        assert_eq!(pool.slot_size(), 4);
        assert_eq!(pool.capacity_slots(), 2);
        assert!(pool.locked_len() >= 8);
        assert_eq!(pool.available_slots(), 2);

        let mut first = pool.allocate_from_array([1, 2, 3, 4]).unwrap();
        let mut second = pool.allocate_from_fn(|index| (index as u8) + 5).unwrap();
        let mut out = [0; 4];

        assert_eq!(pool.available_slots(), 0);
        assert!(pool.allocate().is_none());
        assert!(pool.try_allocate().unwrap().is_none());
        assert!(first.constant_time_eq(&[1, 2, 3, 4]));
        assert!(second.copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [5, 6, 7, 8]);

        first.with_secret_mut(|bytes| bytes[0] = 9);
        assert!(first.constant_time_eq(&[9, 2, 3, 4]));
        first.secure_clear();
        #[cfg(feature = "canary-check")]
        assert_eq!(first.verify_integrity(), Ok(()));
        assert!(first.constant_time_eq(&[0, 0, 0, 0]));
        first.copy_from_slice(&[4, 3, 2, 1]).unwrap();
        assert!(first.constant_time_eq(&[4, 3, 2, 1]));
        first.secure_clear();
        assert!(first.constant_time_eq(&[0, 0, 0, 0]));

        let freed_index = first.slot_index();
        drop(first);
        assert_eq!(pool.available_slots(), 1);

        let reused = pool.allocate_from_slice(&[7, 7, 7, 7]).unwrap().unwrap();
        assert_eq!(reused.slot_index(), freed_index);
        assert!(reused.constant_time_eq(&[7, 7, 7, 7]));

        second.replace_from_array([8, 8, 8, 8]);
        assert!(second.constant_time_eq(&[8, 8, 8, 8]));
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn secret_pool_handles_generation_and_zero_slot_cases() {
        let pool = match SecretPool::<4, 1>::new() {
            Ok(pool) => pool,
            Err(_) => return,
        };

        let mut slot = match pool
            .try_allocate_from_fn(|index| Ok::<u8, &'static str>((index as u8).wrapping_add(1)))
        {
            Ok(Some(slot)) => slot,
            Ok(None) => panic!("pool should have one available slot"),
            Err(error) => panic!("unexpected generator error: {error}"),
        };

        assert!(slot.constant_time_eq(&[1, 2, 3, 4]));
        assert_eq!(
            slot.try_replace_from_fn(|index| {
                if index == 2 {
                    Err("generation failed")
                } else {
                    Ok(index as u8)
                }
            }),
            Err("generation failed")
        );
        #[cfg(feature = "canary-check")]
        assert_eq!(slot.verify_integrity(), Ok(()));
        assert!(slot.constant_time_eq(&[0, 0, 0, 0]));
        slot.copy_from_slice(&[9, 9, 9, 9]).unwrap();
        assert!(slot.constant_time_eq(&[9, 9, 9, 9]));
        drop(slot);

        match pool.try_allocate_from_fn(|index| {
            if index == 1 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        }) {
            Ok(_) => panic!("generation should have failed"),
            Err(error) => assert_eq!(error, "generation failed"),
        }
        assert_eq!(pool.available_slots(), 1);

        let empty = SecretPool::<0, 2>::new().unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.locked_len(), 0);
        let slot = empty.allocate().unwrap();
        assert!(slot.is_empty());
    }

    #[cfg(all(
        feature = "std",
        feature = "canary-check",
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn secret_pool_slot_canaries_detect_corruption() {
        let pool = match SecretPool::<4, 1>::new() {
            Ok(pool) => pool,
            Err(_) => return,
        };
        let mut slot = pool.allocate_from_array([1, 2, 3, 4]).unwrap();

        assert_eq!(slot.verify_integrity(), Ok(()));
        assert_eq!(slot.expose_secret_checked(|bytes| bytes[0]), Ok(1));
        assert_eq!(slot.constant_time_eq_checked(&[1, 2, 3, 4]), Ok(true));

        slot.corrupt_prefix_canary_for_test();

        assert_eq!(
            slot.expose_secret_checked(|bytes| bytes[0]),
            Err(CanaryCorruptedError)
        );
    }

    #[cfg(all(
        feature = "std",
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn secret_pool_concurrent_allocation_gets_distinct_slots() {
        let pool = match SecretPool::<4, 2>::new() {
            Ok(pool) => std::sync::Arc::new(pool),
            Err(_) => return,
        };
        let worker_pool = std::sync::Arc::clone(&pool);
        let start = std::sync::Arc::new(std::sync::Barrier::new(2));
        let finish = std::sync::Arc::new(std::sync::Barrier::new(2));
        let worker_start = std::sync::Arc::clone(&start);
        let worker_finish = std::sync::Arc::clone(&finish);

        let worker = std::thread::spawn(move || {
            worker_start.wait();
            let slot = worker_pool.allocate();
            let index = slot.as_ref().map(|slot| slot.slot_index());
            worker_finish.wait();
            index
        });

        start.wait();
        let slot = pool.allocate();
        let main_index = slot.as_ref().map(|slot| slot.slot_index());
        finish.wait();
        let worker_index = worker.join().unwrap();

        if let (Some(left), Some(right)) = (main_index, worker_index) {
            assert_ne!(left, right);
        }
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
        #[cfg(feature = "canary-check")]
        assert_eq!(secret.verify_integrity(), Ok(()));
        secret.extend_from_slice(b"world").unwrap();
        assert!(secret.constant_time_eq(b"world"));

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
        #[cfg(feature = "canary-check")]
        assert_eq!(secret.verify_integrity(), Ok(()));
        #[cfg(not(feature = "canary-check"))]
        assert_eq!(secret.with_secret(|bytes| bytes.len()), 0);

        let wrapped = crate::cache_flush::CacheFlushOnDrop::new(
            GuardedSecretVec::from_slice(&[5, 6, 7, 8]).unwrap(),
        );
        assert_eq!(wrapped.with_secret(|secret| secret.len()), 4);
        wrapped.into_cleared();
    }

    #[cfg(all(
        feature = "std",
        feature = "guard-pages",
        feature = "canary-check",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[test]
    fn guarded_secret_vec_canaries_detect_corruption() {
        let mut secret = GuardedSecretVec::from_slice(&[1, 2, 3, 4]).unwrap();

        assert_eq!(secret.verify_integrity(), Ok(()));
        assert_eq!(secret.expose_secret_checked(|bytes| bytes[0]), Ok(1));
        assert_eq!(secret.constant_time_eq_checked(&[1, 2, 3, 4]), Ok(true));

        secret.extend_from_slice(&[5, 6]).unwrap();
        assert_eq!(secret.expose_secret_checked(|bytes| bytes[5]), Ok(6));

        secret.corrupt_suffix_canary_for_test();

        assert_eq!(
            secret.expose_secret_checked(|bytes| bytes[0]),
            Err(CanaryCorruptedError)
        );
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
