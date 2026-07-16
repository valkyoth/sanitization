use core::{
    cell::UnsafeCell,
    fmt,
    sync::atomic::{compiler_fence, AtomicBool, Ordering},
};

use super::{
    CanaryCorruptedError, ForkPolicy, ProtectionControl, ProtectionError, ProtectionFailure,
    ProtectionReport, ProtectionRequest, ProtectionState, Requirement, RollbackReport,
    SecretIntegrityError,
};

#[cfg(feature = "canary-check")]
const CANARY_SIZE: usize = 8;
#[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
const CANARY_MASK: u64 = 0x9E37_79B9_7F4A_7C15;

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
    /// Child-process wipe-on-fork policy failed.
    WipeOnFork,
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

type LockedSecretBytesCheckedCopyError = SecretIntegrityError<crate::LengthError>;

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
        crate::wipe_backend::erase(self.prefix.as_mut_ptr(), CANARY_SIZE);
        crate::wipe_backend::erase(self.bytes.as_mut_ptr(), N);
        #[cfg(feature = "canary-check")]
        crate::wipe_backend::erase(self.suffix.as_mut_ptr(), CANARY_SIZE);
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
    request: ProtectionRequest,
    report: ProtectionReport,
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
        Self::zeroed_with_protection(ProtectionRequest::wasm_compatibility())
            .map_err(protection_error_as_memory_lock)
    }

    /// Allocate WASM compatibility storage under an explicit policy.
    ///
    /// Required native controls fail because a WASM module cannot establish
    /// host page locking, dump exclusion, or fork policy.
    #[inline]
    pub fn zeroed_with_protection(request: ProtectionRequest) -> Result<Self, ProtectionError> {
        let report = wasm_protection_report(request, N)?;
        let mut secret = Self {
            storage: UnsafeCell::new(WasmLockedStorage::zeroed()),
            request,
            report,
            #[cfg(feature = "random-canary")]
            canary: random_canary_value().map_err(|error| {
                let mut partial_report = report;
                partial_report.canary = ProtectionState::Failed { code: error.errno };
                ProtectionError {
                    failure: ProtectionFailure {
                        control: ProtectionControl::Canary,
                        code: error.errno,
                    },
                    partial_report,
                    rollback: RollbackReport::not_needed(),
                }
            })?,
        };
        secret.write_canaries();
        Ok(secret)
    }

    /// Actual compatibility protections for this WASM-owned storage.
    #[must_use]
    #[inline]
    pub const fn protection_report(&self) -> &ProtectionReport {
        &self.report
    }

    /// Runtime protection policy requested for this storage.
    #[must_use]
    #[inline]
    pub const fn protection_request(&self) -> ProtectionRequest {
        self.request
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
                crate::wipe::bytes(&mut bytes);
                return Err(error);
            }
        };

        let _ = secret.copy_from_slice(&bytes);
        crate::wipe::bytes(&mut bytes);
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
    pub fn copy_from_slice(
        &mut self,
        source: &[u8],
    ) -> Result<(), SecretIntegrityError<crate::LengthError>> {
        if source.len() != N {
            return Err(SecretIntegrityError::Operation(crate::LengthError {
                expected: N,
                actual: source.len(),
            }));
        }

        self.verify_integrity()?;
        self.as_mut_slice().copy_from_slice(source);
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Replace all secret bytes from a same-length slice.
    #[inline]
    pub fn replace_from_slice(
        &mut self,
        source: &[u8],
    ) -> Result<(), SecretIntegrityError<LockedSecretBytesError>> {
        self.verify_integrity()?;
        if source.len() != N {
            return Err(SecretIntegrityError::Operation(
                crate::LengthError {
                    expected: N,
                    actual: source.len(),
                }
                .into(),
            ));
        }
        let mut replacement = self
            .replacement_zeroed()
            .map_err(LockedSecretBytesError::Memory)
            .map_err(SecretIntegrityError::Operation)?;
        replacement.as_mut_slice().copy_from_slice(source);
        compiler_fence(Ordering::SeqCst);
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all secret bytes from an owned array, then clear the input.
    #[inline]
    pub fn replace_from_array(
        &mut self,
        mut bytes: [u8; N],
    ) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        if let Err(error) = self.verify_integrity() {
            crate::wipe::bytes(&mut bytes);
            return Err(error.into());
        }
        let mut replacement = match self.replacement_zeroed() {
            Ok(replacement) => replacement,
            Err(error) => {
                crate::wipe::bytes(&mut bytes);
                return Err(SecretIntegrityError::Operation(error));
            }
        };
        replacement.as_mut_slice().copy_from_slice(&bytes);
        crate::wipe::bytes(&mut bytes);
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all secret bytes with generated bytes.
    #[inline]
    pub fn replace_from_fn(
        &mut self,
        make_byte: impl FnMut(usize) -> u8,
    ) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_zeroed()
            .map_err(SecretIntegrityError::Operation)?;
        let mut make_byte = make_byte;
        let mut index = 0;
        while index < N {
            replacement.as_mut_slice()[index] = make_byte(index);
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all secret bytes with fallibly generated bytes.
    #[inline]
    pub fn try_replace_from_fn<E>(
        &mut self,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), SecretIntegrityError<LockedSecretBytesGenerateError<E>>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_zeroed()
            .map_err(LockedSecretBytesGenerateError::Memory)
            .map_err(SecretIntegrityError::Operation)?;
        let mut make_byte = make_byte;
        let mut index = 0;
        while index < N {
            match make_byte(index) {
                Ok(byte) => replacement.as_mut_slice()[index] = byte,
                Err(error) => {
                    replacement.secure_clear();
                    return Err(SecretIntegrityError::Operation(
                        LockedSecretBytesGenerateError::Generate(error),
                    ));
                }
            }
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all secret bytes by filling fresh WASM-owned storage.
    #[inline]
    pub fn replace_from_fill(
        &mut self,
        fill: impl FnOnce(&mut [u8; N]),
    ) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_zeroed()
            .map_err(SecretIntegrityError::Operation)?;
        compiler_fence(Ordering::SeqCst);
        fill(replacement.as_mut_array());
        compiler_fence(Ordering::SeqCst);
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Fallible variant of [`LockedSecretBytes::replace_from_fill`].
    #[inline]
    pub fn try_replace_from_fill<E>(
        &mut self,
        fill: impl FnOnce(&mut [u8; N]) -> Result<(), E>,
    ) -> Result<(), SecretIntegrityError<LockedSecretBytesGenerateError<E>>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_zeroed()
            .map_err(LockedSecretBytesGenerateError::Memory)
            .map_err(SecretIntegrityError::Operation)?;
        compiler_fence(Ordering::SeqCst);
        if let Err(error) = fill(replacement.as_mut_array()) {
            replacement.secure_clear();
            return Err(SecretIntegrityError::Operation(
                LockedSecretBytesGenerateError::Generate(error),
            ));
        }
        compiler_fence(Ordering::SeqCst);
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    fn replacement_zeroed(&self) -> Result<Self, MemoryLockError> {
        Self::zeroed_with_protection(self.request).map_err(protection_error_as_memory_lock)
    }

    /// Fill a caller-provided destination with a copy of the secret bytes.
    #[inline]
    pub fn copy_to_slice(
        &self,
        destination: &mut [u8],
    ) -> Result<(), LockedSecretBytesCheckedCopyError> {
        if destination.len() != N {
            return Err(SecretIntegrityError::Operation(crate::LengthError {
                expected: N,
                actual: destination.len(),
            }));
        }

        self.verify_integrity()?;
        destination.copy_from_slice(self.as_slice());
        compiler_fence(Ordering::SeqCst);
        core::hint::black_box(destination);
        Ok(())
    }

    /// Run a closure with read-only access to the secret bytes.
    #[inline]
    pub fn expose_secret<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(inspect(self.as_array()))
    }

    /// Verify integrity, copy into temporary stack storage, and expose the copy.
    ///
    /// The temporary is volatile-cleared on normal return and unwinding. It
    /// cannot be cleared if the WASM instance aborts or traps without unwinding.
    #[inline]
    pub fn expose_secret_copy<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::owned::expose_array_copy(self.as_array(), inspect))
    }

    /// Compatibility alias for [`LockedSecretBytes::expose_secret`].
    #[inline]
    pub fn expose_secret_checked<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.expose_secret(inspect)
    }

    /// Compatibility alias for [`LockedSecretBytes::expose_secret_copy`].
    #[inline]
    pub fn expose_secret_copy_checked<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.expose_secret_copy(inspect)
    }

    /// Compatibility alias for [`LockedSecretBytes::copy_to_slice`].
    #[inline]
    pub fn copy_to_slice_checked(
        &self,
        destination: &mut [u8],
    ) -> Result<(), LockedSecretBytesCheckedCopyError> {
        if destination.len() != N {
            return Err(SecretIntegrityError::Operation(crate::LengthError {
                expected: N,
                actual: destination.len(),
            }));
        }

        self.verify_integrity()?;
        destination.copy_from_slice(self.as_slice());
        compiler_fence(Ordering::SeqCst);
        core::hint::black_box(destination);
        Ok(())
    }

    /// Compatibility alias for [`LockedSecretBytes::constant_time_eq`].
    #[inline]
    pub fn constant_time_eq_checked(&self, other: &[u8]) -> Result<bool, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::constant_time_eq_slices(self.as_slice(), other))
    }

    /// Verify canaries.
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        #[cfg(not(feature = "canary-check"))]
        {
            return Ok(());
        }
        #[cfg(feature = "canary-check")]
        if self.canaries_intact() {
            Ok(())
        } else {
            self.clear_after_canary_failure();
            Err(CanaryCorruptedError)
        }
    }

    /// Compare against a slice without early exit for equal-length inputs.
    #[inline]
    pub fn constant_time_eq(&self, other: &[u8]) -> Result<bool, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::constant_time_eq_slices(self.as_slice(), other))
    }

    /// Clear the full WASM-owned storage with volatile writes.
    #[inline(never)]
    pub fn secure_clear(&mut self) {
        self.storage.get_mut().clear_all();
        self.write_canaries();
    }

    /// Clear the WASM-owned storage, then report that native cache eviction is
    /// unavailable.
    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn secure_clear_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        self.secure_clear();
        crate::cache_flush::flush_cache_lines(self.as_slice())
    }

    /// Consume this value after first clearing its storage.
    #[inline]
    pub fn into_cleared(mut self) {
        self.secure_clear();
    }

    /// Run a closure with read-only access, panicking on canary corruption.
    #[inline]
    pub fn expose_secret_or_panic<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.expose_secret(inspect)
            .unwrap_or_else(|_| panic!("locked secret canary corrupted"))
    }

    /// Expose a temporary copy, panicking on canary corruption.
    #[inline]
    pub fn expose_secret_copy_or_panic<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.expose_secret_copy(inspect)
            .unwrap_or_else(|_| panic!("locked secret canary corrupted"))
    }

    /// Compare, panicking on canary corruption.
    #[must_use]
    #[inline]
    pub fn constant_time_eq_or_panic(&self, other: &[u8]) -> bool {
        self.constant_time_eq(other)
            .unwrap_or_else(|_| panic!("locked secret canary corrupted"))
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

impl<const N: usize> crate::StableSharedSecretStorage for LockedSecretBytes<N> {}
impl<const N: usize> crate::StableMutableSecretStorage for LockedSecretBytes<N> {}

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
        crate::wipe_backend::erase(self.prefix.as_mut_ptr(), CANARY_SIZE);
        crate::wipe_backend::erase(self.bytes.as_mut_ptr(), N);
        #[cfg(feature = "canary-check")]
        crate::wipe_backend::erase(self.suffix.as_mut_ptr(), CANARY_SIZE);
    }
}

/// Fixed-slot arena for many same-size WASM-owned secrets.
///
/// This mirrors the native `SecretPool<N, SLOTS>` API, but no WASM memory
/// can be locked against host swapping, snapshots, or dumps.
pub struct SecretPool<const N: usize, const SLOTS: usize> {
    slots: [UnsafeCell<WasmPoolSlotStorage<N>>; SLOTS],
    used: [AtomicBool; SLOTS],
    request: ProtectionRequest,
    report: ProtectionReport,
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
        Self::new_with_protection(ProtectionRequest::wasm_compatibility())
            .map_err(protection_error_as_memory_lock)
    }

    /// Create a WASM compatibility pool under an explicit policy.
    #[inline]
    pub fn new_with_protection(request: ProtectionRequest) -> Result<Self, ProtectionError> {
        let requested_bytes = N.checked_mul(SLOTS).ok_or_else(|| ProtectionError {
            failure: ProtectionFailure {
                control: ProtectionControl::Mapping,
                code: 0,
            },
            partial_report: ProtectionReport::pending(request, usize::MAX, 0),
            rollback: RollbackReport::not_needed(),
        })?;
        let report = wasm_protection_report(request, requested_bytes)?;
        Ok(Self {
            slots: core::array::from_fn(|_| UnsafeCell::new(WasmPoolSlotStorage::zeroed())),
            used: core::array::from_fn(|_| AtomicBool::new(false)),
            request,
            report,
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

    /// Actual compatibility protections for the pool storage.
    #[must_use]
    #[inline]
    pub const fn protection_report(&self) -> &ProtectionReport {
        &self.report
    }

    /// Runtime protection policy requested for the pool storage.
    #[must_use]
    #[inline]
    pub const fn protection_request(&self) -> ProtectionRequest {
        self.request
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
    pub fn try_allocate(&self) -> Result<Option<SecretPoolSlot<'_, N, SLOTS>>, MemoryLockError> {
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

    /// Clear every WASM-owned slot, then report that native cache eviction is
    /// unavailable.
    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn secure_clear_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        self.secure_clear();
        crate::cache_flush::flush_cache_lines(&[])
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
    pub fn copy_from_slice(
        &mut self,
        source: &[u8],
    ) -> Result<(), SecretIntegrityError<crate::LengthError>> {
        if source.len() != N {
            return Err(SecretIntegrityError::Operation(crate::LengthError {
                expected: N,
                actual: source.len(),
            }));
        }

        self.verify_integrity()?;
        self.as_mut_slice().copy_from_slice(source);
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Compatibility alias for [`SecretPoolSlot::copy_from_slice`].
    #[inline]
    pub fn replace_from_slice(
        &mut self,
        source: &[u8],
    ) -> Result<(), SecretIntegrityError<crate::LengthError>> {
        self.copy_from_slice(source)
    }

    /// Replace all slot bytes from an owned array, then clear the input.
    #[inline]
    pub fn replace_from_array(&mut self, mut bytes: [u8; N]) -> Result<(), CanaryCorruptedError> {
        if let Err(error) = self.verify_integrity() {
            crate::wipe::bytes(&mut bytes);
            return Err(error);
        }
        self.as_mut_slice().copy_from_slice(&bytes);
        compiler_fence(Ordering::SeqCst);
        crate::wipe::bytes(&mut bytes);
        Ok(())
    }

    /// Replace all slot bytes with generated bytes.
    #[inline]
    pub fn replace_from_fn(
        &mut self,
        mut make_byte: impl FnMut(usize) -> u8,
    ) -> Result<(), CanaryCorruptedError> {
        self.verify_integrity()?;
        let mut index = 0;
        while index < N {
            self.as_mut_slice()[index] = make_byte(index);
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Replace all slot bytes with fallibly generated bytes.
    #[inline]
    pub fn try_replace_from_fn<E>(
        &mut self,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), SecretIntegrityError<E>> {
        self.verify_integrity()?;
        let mut index = 0;
        while index < N {
            match make_byte(index) {
                Ok(byte) => self.as_mut_slice()[index] = byte,
                Err(error) => {
                    self.secure_clear();
                    return Err(SecretIntegrityError::Operation(error));
                }
            }
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Fill a caller-provided destination with a copy of the slot bytes.
    #[inline]
    pub fn copy_to_slice(
        &self,
        destination: &mut [u8],
    ) -> Result<(), SecretIntegrityError<crate::LengthError>> {
        if destination.len() != N {
            return Err(SecretIntegrityError::Operation(crate::LengthError {
                expected: N,
                actual: destination.len(),
            }));
        }

        self.verify_integrity()?;
        destination.copy_from_slice(self.as_slice());
        compiler_fence(Ordering::SeqCst);
        core::hint::black_box(destination);
        Ok(())
    }

    /// Run a closure with read-only access to the slot bytes.
    #[inline]
    pub fn expose_secret<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(inspect(self.as_array()))
    }

    /// Verify integrity, copy into temporary stack storage, and expose the copy.
    ///
    /// The temporary is volatile-cleared on normal return and unwinding. It
    /// cannot be cleared if the WASM instance aborts or traps without unwinding.
    #[inline]
    pub fn expose_secret_copy<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::owned::expose_array_copy(self.as_array(), inspect))
    }

    /// Run a closure with mutable access to the slot bytes.
    #[inline]
    pub fn with_secret_mut<R>(
        &mut self,
        inspect: impl FnOnce(&mut [u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(inspect(self.as_array_mut()))
    }

    /// Compatibility alias for [`SecretPoolSlot::expose_secret`].
    #[inline]
    pub fn expose_secret_checked<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.expose_secret(inspect)
    }

    /// Compatibility alias for [`SecretPoolSlot::expose_secret_copy`].
    #[inline]
    pub fn expose_secret_copy_checked<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.expose_secret_copy(inspect)
    }

    /// Compatibility alias for [`SecretPoolSlot::constant_time_eq`].
    #[inline]
    pub fn constant_time_eq_checked(&self, other: &[u8]) -> Result<bool, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::constant_time_eq_slices(self.as_slice(), other))
    }

    /// Verify this slot's canaries.
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        #[cfg(not(feature = "canary-check"))]
        {
            return Ok(());
        }
        #[cfg(feature = "canary-check")]
        if self.canaries_intact() {
            Ok(())
        } else {
            self.clear_after_canary_failure();
            Err(CanaryCorruptedError)
        }
    }

    /// Compare against a slice without early exit for equal-length inputs.
    #[inline]
    pub fn constant_time_eq(&self, other: &[u8]) -> Result<bool, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::constant_time_eq_slices(self.as_slice(), other))
    }

    /// Clear only this slot with volatile writes.
    #[inline(never)]
    pub fn secure_clear(&mut self) {
        self.storage_mut().clear_all();
        self.write_canaries();
    }

    /// Clear this WASM-owned slot, then report that native cache eviction is
    /// unavailable.
    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn secure_clear_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        self.secure_clear();
        crate::cache_flush::flush_cache_lines(&[])
    }

    /// Consume this slot after clearing it, then return it to the pool.
    #[inline]
    pub fn into_cleared(mut self) {
        self.secure_clear();
    }

    /// Run a closure with shared access, panicking on canary corruption.
    #[inline]
    pub fn expose_secret_or_panic<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.expose_secret(inspect)
            .unwrap_or_else(|_| panic!("pooled secret slot canary corrupted"))
    }

    /// Expose a temporary copy, panicking on canary corruption.
    #[inline]
    pub fn expose_secret_copy_or_panic<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.expose_secret_copy(inspect)
            .unwrap_or_else(|_| panic!("pooled secret slot canary corrupted"))
    }

    /// Run a closure with mutable access, panicking on canary corruption.
    #[inline]
    pub fn with_secret_mut_or_panic<R>(&mut self, inspect: impl FnOnce(&mut [u8; N]) -> R) -> R {
        self.with_secret_mut(inspect)
            .unwrap_or_else(|_| panic!("pooled secret slot canary corrupted"))
    }

    /// Compare, panicking on canary corruption.
    #[must_use]
    #[inline]
    pub fn constant_time_eq_or_panic(&self, other: &[u8]) -> bool {
        self.constant_time_eq(other)
            .unwrap_or_else(|_| panic!("pooled secret slot canary corrupted"))
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

fn wasm_protection_report(
    request: ProtectionRequest,
    requested_bytes: usize,
) -> Result<ProtectionReport, ProtectionError> {
    let mut report = ProtectionReport::pending(request, requested_bytes, 0);
    report.mapping = ProtectionState::CompatibilityOnly;
    report.memory_lock =
        wasm_compatibility_state(request.memory_lock, ProtectionControl::MemoryLock, &report)?;
    report.dump_exclusion = wasm_compatibility_state(
        request.dump_exclusion,
        ProtectionControl::DumpExclusion,
        &report,
    )?;
    report.fork.state = match request.fork.policy {
        ForkPolicy::Inherit => ProtectionState::NotApplicable,
        ForkPolicy::Exclude | ForkPolicy::WipeChild => wasm_compatibility_state(
            request.fork.requirement,
            ProtectionControl::ForkPolicy,
            &report,
        )?,
    };
    report.guard_pages =
        wasm_unavailable_state(request.guard_pages, ProtectionControl::GuardPages, &report)?;
    report.cache_policy = wasm_unavailable_state(
        request.cache_policy,
        ProtectionControl::CachePolicy,
        &report,
    )?;
    report.canary = wasm_canary_state(request.canary, &report)?;
    Ok(report)
}

fn wasm_compatibility_state(
    requirement: Requirement,
    control: ProtectionControl,
    report: &ProtectionReport,
) -> Result<ProtectionState, ProtectionError> {
    match requirement {
        Requirement::NotRequested => Ok(ProtectionState::NotRequested),
        Requirement::Preferred => Ok(ProtectionState::CompatibilityOnly),
        Requirement::Required => Err(wasm_required_error(control, *report)),
    }
}

fn wasm_unavailable_state(
    requirement: Requirement,
    control: ProtectionControl,
    report: &ProtectionReport,
) -> Result<ProtectionState, ProtectionError> {
    match requirement {
        Requirement::NotRequested => Ok(ProtectionState::NotRequested),
        Requirement::Preferred => Ok(ProtectionState::Unsupported),
        Requirement::Required => Err(wasm_required_error(control, *report)),
    }
}

fn wasm_canary_state(
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
        wasm_unavailable_state(requirement, ProtectionControl::Canary, report)
    }
}

fn wasm_required_error(
    control: ProtectionControl,
    mut report: ProtectionReport,
) -> ProtectionError {
    let failed = ProtectionState::Failed { code: 0 };
    match control {
        ProtectionControl::Mapping => report.mapping = failed,
        ProtectionControl::MemoryLock => report.memory_lock = failed,
        ProtectionControl::DumpExclusion => report.dump_exclusion = failed,
        ProtectionControl::ForkPolicy => report.fork.state = failed,
        ProtectionControl::GuardPages => report.guard_pages = failed,
        ProtectionControl::Canary => report.canary = failed,
        ProtectionControl::CachePolicy => report.cache_policy = failed,
    }
    ProtectionError {
        failure: ProtectionFailure { control, code: 0 },
        partial_report: report,
        rollback: RollbackReport::not_needed(),
    }
}

fn protection_error_as_memory_lock(error: ProtectionError) -> MemoryLockError {
    MemoryLockError {
        operation: match error.failure.control {
            ProtectionControl::Mapping => MemoryLockOperation::Map,
            ProtectionControl::MemoryLock => MemoryLockOperation::Lock,
            ProtectionControl::DumpExclusion => MemoryLockOperation::DontDump,
            ProtectionControl::ForkPolicy => match error.partial_report.fork.policy {
                ForkPolicy::WipeChild => MemoryLockOperation::WipeOnFork,
                ForkPolicy::Inherit | ForkPolicy::Exclude => MemoryLockOperation::DontFork,
            },
            ProtectionControl::GuardPages | ProtectionControl::CachePolicy => {
                MemoryLockOperation::Map
            }
            ProtectionControl::Canary => MemoryLockOperation::Random,
        },
        errno: error.failure.code,
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
