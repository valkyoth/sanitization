use core::{
    cell::UnsafeCell,
    fmt,
    sync::atomic::{compiler_fence, AtomicBool, Ordering},
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
    pub fn expose_secret<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.assert_canaries_intact();
        inspect(self.as_array())
    }

    /// Verify integrity, copy into temporary stack storage, and expose the copy.
    ///
    /// The temporary is volatile-cleared on normal return and unwinding. It
    /// cannot be cleared if the WASM instance aborts or traps without unwinding.
    #[inline]
    pub fn expose_secret_copy<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.assert_canaries_intact();
        crate::owned::expose_array_copy(self.as_array(), inspect)
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
    pub fn expose_secret<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.assert_canaries_intact();
        inspect(self.as_array())
    }

    /// Verify integrity, copy into temporary stack storage, and expose the copy.
    ///
    /// The temporary is volatile-cleared on normal return and unwinding. It
    /// cannot be cleared if the WASM instance aborts or traps without unwinding.
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

#[cfg(feature = "random-canary")]
fn random_canary_value() -> Result<[u8; CANARY_SIZE], MemoryLockError> {
    let mut canary = [0; CANARY_SIZE];
    crate::canary::fill(&mut canary).map_err(|errno| MemoryLockError {
        operation: MemoryLockOperation::Random,
        errno,
    })?;
    Ok(canary)
}
