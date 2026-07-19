use core::fmt;

/// Error returned when a mapped secret's integrity canaries are corrupted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanaryCorruptedError;

impl fmt::Display for CanaryCorruptedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("mapped secret canary corrupted")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CanaryCorruptedError {}

/// Error returned by an operation that checks mapped-secret integrity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretIntegrityError<E> {
    /// Prefix or suffix canary verification failed.
    Canary(CanaryCorruptedError),
    /// The requested operation failed for a non-integrity reason.
    Operation(E),
}

/// Result alias for mapped operations that distinguish integrity corruption
/// from an operation-specific failure.
pub type SecretIntegrityResult<T, E> = Result<T, SecretIntegrityError<E>>;

impl<E> SecretIntegrityError<E> {
    /// Returns `true` when integrity-canary verification failed.
    #[must_use]
    pub const fn is_canary(&self) -> bool {
        matches!(self, Self::Canary(_))
    }

    /// Returns `true` when the requested operation failed after integrity
    /// verification succeeded.
    #[must_use]
    pub const fn is_operation(&self) -> bool {
        matches!(self, Self::Operation(_))
    }

    /// Borrows the operation-specific error, when present.
    #[must_use]
    pub const fn operation(&self) -> Option<&E> {
        match self {
            Self::Canary(_) => None,
            Self::Operation(error) => Some(error),
        }
    }

    /// Maps only the operation-specific error while preserving integrity
    /// corruption as a separate variant.
    pub fn map_operation<O>(self, map: impl FnOnce(E) -> O) -> SecretIntegrityError<O> {
        match self {
            Self::Canary(error) => SecretIntegrityError::Canary(error),
            Self::Operation(error) => SecretIntegrityError::Operation(map(error)),
        }
    }
}

/// Flattens a fallible mapped-secret exposure closure without losing the
/// distinction between integrity corruption and the closure's own error.
///
/// Mapped byte exposure methods return `Result<R, CanaryCorruptedError>`. If
/// the closure itself returns `Result<T, E>`, importing this trait permits:
///
/// ```rust,no_run
/// # #[cfg(feature = "memory-lock")]
/// # fn example() -> sanitization::SecretIntegrityResult<(), &'static str> {
/// use sanitization::{LockedSecretBytes, SecretIntegrityResultExt};
///
/// let key = LockedSecretBytes::<4>::from_array([1, 2, 3, 4])
///     .expect("test environment permits memory locking");
/// let parsed = key
///     .try_expose_secret(|bytes| bytes.first().copied().ok_or("empty key"))
///     .flatten_secret_integrity()?;
/// assert_eq!(parsed, 1);
/// # Ok(())
/// # }
/// ```
pub trait SecretIntegrityResultExt<T, E> {
    /// Converts the outer canary error to [`SecretIntegrityError::Canary`] and
    /// the closure error to [`SecretIntegrityError::Operation`].
    fn flatten_secret_integrity(self) -> SecretIntegrityResult<T, E>;
}

impl<T, E> SecretIntegrityResultExt<T, E> for Result<Result<T, E>, CanaryCorruptedError> {
    #[inline]
    fn flatten_secret_integrity(self) -> SecretIntegrityResult<T, E> {
        match self {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(SecretIntegrityError::Operation(error)),
            Err(error) => Err(SecretIntegrityError::Canary(error)),
        }
    }
}

impl<E: fmt::Display> fmt::Display for SecretIntegrityError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canary(error) => error.fmt(formatter),
            Self::Operation(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for SecretIntegrityError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canary(error) => Some(error),
            Self::Operation(error) => Some(error),
        }
    }
}

impl<E> From<CanaryCorruptedError> for SecretIntegrityError<E> {
    #[inline]
    fn from(error: CanaryCorruptedError) -> Self {
        Self::Canary(error)
    }
}

/// Stable identity of one live allocation from a fixed-size secret pool.
///
/// The slot index may be reused after a handle drops. The generation changes
/// on each successful claim, so retained identifiers can distinguish later
/// occupants of the same slot. This is diagnostic identity only; it does not
/// grant access to slot storage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecretPoolSlotId {
    /// Slot index inside the parent pool.
    pub index: usize,
    /// Non-zero allocation generation assigned after the slot is claimed.
    pub generation: usize,
}

/// Point-in-time capacity and lock-efficiency report for a fixed-size pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretPoolReport {
    /// Secret payload bytes in one slot.
    pub slot_size: usize,
    /// Storage bytes reserved per slot, including integrity metadata.
    pub slot_stride: usize,
    /// Total fixed slot count.
    pub capacity_slots: usize,
    /// Slots with a live handle when the report was captured.
    pub live_slots: usize,
    /// Maximum secret payload bytes across all slots.
    pub payload_capacity_bytes: usize,
    /// Slot storage bytes before platform page rounding.
    pub reserved_bytes: usize,
    /// Bytes in the native mapping, or zero for compatibility storage.
    pub mapped_bytes: usize,
    /// Bytes successfully locked against ordinary paging.
    pub locked_bytes: usize,
    /// Mapping bytes beyond fixed slot storage, normally page-rounding waste.
    pub mapping_overhead_bytes: usize,
    /// Locked bytes beyond secret payload capacity, including canaries and
    /// page-rounding waste.
    pub locked_overhead_bytes: usize,
    /// Page granule used by the backend, or zero for compatibility storage.
    pub page_granule: usize,
    /// Whether the underlying protection report associated a failure with
    /// likely platform lock-quota pressure.
    pub lock_quota_likely: bool,
}

impl SecretPoolReport {
    /// Payload density inside the fixed slot storage, in basis points.
    ///
    /// `10_000` means every reserved byte is payload. Zero-sized pools return
    /// `None`.
    #[must_use]
    pub const fn storage_efficiency_basis_points(&self) -> Option<u16> {
        efficiency_basis_points(self.payload_capacity_bytes, self.reserved_bytes)
    }

    /// Payload density inside the native mapping, in basis points.
    ///
    /// Compatibility backends without a native mapping return `None`.
    #[must_use]
    pub const fn mapping_efficiency_basis_points(&self) -> Option<u16> {
        efficiency_basis_points(self.payload_capacity_bytes, self.mapped_bytes)
    }

    /// Payload density inside bytes locked against ordinary paging.
    ///
    /// Unlocked and compatibility backends return `None`.
    #[must_use]
    pub const fn lock_efficiency_basis_points(&self) -> Option<u16> {
        efficiency_basis_points(self.payload_capacity_bytes, self.locked_bytes)
    }
}

const fn efficiency_basis_points(payload: usize, total: usize) -> Option<u16> {
    if total == 0 {
        return None;
    }

    let value = ((payload as u128) * 10_000) / (total as u128);
    Some(if value > 10_000 { 10_000 } else { value as u16 })
}

/// Whether a runtime memory-protection control is mandatory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Requirement {
    /// Construction must fail if the control cannot be established.
    Required,
    /// Construction may continue with an explicit reduced-protection report.
    Preferred,
    /// The control is not requested.
    NotRequested,
}

/// Desired treatment of secret mappings across process fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkPolicy {
    /// Allow the child process to inherit the mapping.
    Inherit,
    /// Exclude the mapping from the child process.
    Exclude,
    /// Replace the child process's inherited mapping contents with zeroes.
    WipeChild,
}

/// Fork behavior requested for a mapped secret allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkProtectionRequest {
    /// Desired fork behavior.
    pub policy: ForkPolicy,
    /// Whether construction may continue when the behavior is unavailable.
    pub requirement: Requirement,
}

impl ForkProtectionRequest {
    /// Explicitly allow ordinary fork inheritance.
    #[must_use]
    pub const fn inherit() -> Self {
        Self {
            policy: ForkPolicy::Inherit,
            requirement: Requirement::NotRequested,
        }
    }

    /// Request exclusion from child processes.
    #[must_use]
    pub const fn exclude(requirement: Requirement) -> Self {
        Self {
            policy: ForkPolicy::Exclude,
            requirement,
        }
    }

    /// Request zero-filled contents in child processes.
    #[must_use]
    pub const fn wipe_child(requirement: Requirement) -> Self {
        Self {
            policy: ForkPolicy::WipeChild,
            requirement,
        }
    }
}

/// Runtime protections requested for a mapped secret allocation.
///
/// Cargo features determine which backends are compiled. They do not prove
/// that a requested operating-system control was established at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionRequest {
    /// Pin secret-bearing pages against ordinary paging.
    pub memory_lock: Requirement,
    /// Request exclusion from supported process core dumps.
    pub dump_exclusion: Requirement,
    /// Requested process-fork behavior.
    pub fork: ForkProtectionRequest,
    /// Require inaccessible pages around writable secret storage.
    pub guard_pages: Requirement,
    /// Require integrity canaries around secret storage.
    pub canary: Requirement,
    /// Request a persistent cache-eviction policy.
    ///
    /// The current mapped containers expose checked explicit cache flushing,
    /// but do not install an automatic persistent policy. Requesting this as
    /// `Required` therefore fails closed.
    pub cache_policy: Requirement,
}

impl ProtectionRequest {
    /// Policy used by the existing locked-storage constructors.
    ///
    /// Memory locking is required. Dump and fork exclusion are preferred
    /// because not every supported native platform exposes those controls.
    #[must_use]
    pub const fn locked() -> Self {
        Self {
            memory_lock: Requirement::Required,
            dump_exclusion: Requirement::Preferred,
            fork: ForkProtectionRequest::exclude(compiled_fork_requirement()),
            guard_pages: Requirement::NotRequested,
            canary: compiled_canary_requirement(),
            cache_policy: Requirement::NotRequested,
        }
    }

    /// Policy used by guarded storage without page locking.
    #[must_use]
    pub const fn guarded() -> Self {
        Self {
            memory_lock: Requirement::NotRequested,
            dump_exclusion: Requirement::NotRequested,
            fork: ForkProtectionRequest::inherit(),
            guard_pages: Requirement::Required,
            canary: compiled_canary_requirement(),
            cache_policy: Requirement::NotRequested,
        }
    }

    /// Fail-closed policy used by default page-sealed storage.
    ///
    /// Linux must establish `MADV_WIPEONFORK` so a fork during an exposed
    /// access window cannot leave readable secret bytes in the child. Windows
    /// does not clone the process address space during process creation.
    /// Other targets currently report the required fork policy as unsupported,
    /// so callers must use an explicit policy only after reviewing that risk.
    #[cfg(feature = "page-seal")]
    #[must_use]
    pub const fn page_sealed() -> Self {
        Self {
            memory_lock: Requirement::NotRequested,
            dump_exclusion: Requirement::NotRequested,
            fork: page_sealed_fork_request(),
            guard_pages: Requirement::Required,
            canary: compiled_canary_requirement(),
            cache_policy: Requirement::NotRequested,
        }
    }

    /// Policy used by guarded and page-locked storage.
    #[must_use]
    pub const fn locked_guarded() -> Self {
        Self {
            memory_lock: Requirement::Required,
            dump_exclusion: Requirement::Preferred,
            fork: ForkProtectionRequest::exclude(compiled_fork_requirement()),
            guard_pages: Requirement::Required,
            canary: compiled_canary_requirement(),
            cache_policy: Requirement::NotRequested,
        }
    }

    /// Policy represented by the `profile-hardened-native` feature.
    ///
    /// Memory locking and random integrity canaries are required. Dump and
    /// fork exclusion remain preferred because the named profile spans native
    /// operating systems with different process-policy controls.
    #[cfg(feature = "profile-hardened-native")]
    #[must_use]
    pub const fn profile_hardened_native() -> Self {
        Self {
            memory_lock: Requirement::Required,
            dump_exclusion: Requirement::Preferred,
            fork: ForkProtectionRequest::exclude(Requirement::Preferred),
            guard_pages: Requirement::NotRequested,
            canary: Requirement::Required,
            cache_policy: Requirement::NotRequested,
        }
    }

    /// Policy represented by the `profile-guarded-native` feature.
    #[cfg(feature = "profile-guarded-native")]
    #[must_use]
    pub const fn profile_guarded_native() -> Self {
        Self {
            guard_pages: Requirement::Required,
            ..Self::profile_hardened_native()
        }
    }

    /// Policy represented by the Linux-specific hardened profile.
    ///
    /// Linux fork exclusion is required by this profile. Dump exclusion
    /// remains preferred because runtime kernel or sandbox policy can reject
    /// the request and callers must inspect the resulting report.
    #[cfg(feature = "profile-hardened-linux")]
    #[must_use]
    pub const fn profile_hardened_linux() -> Self {
        Self {
            fork: ForkProtectionRequest::exclude(Requirement::Required),
            ..Self::profile_hardened_native()
        }
    }

    /// Explicit reduced-guarantee policy for WASM compatibility storage.
    #[must_use]
    pub const fn wasm_compatibility() -> Self {
        Self {
            memory_lock: Requirement::Preferred,
            dump_exclusion: Requirement::Preferred,
            fork: ForkProtectionRequest::exclude(Requirement::Preferred),
            guard_pages: Requirement::NotRequested,
            canary: compiled_canary_requirement(),
            cache_policy: Requirement::NotRequested,
        }
    }
}

#[cfg(all(feature = "page-seal", target_os = "linux"))]
const fn page_sealed_fork_request() -> ForkProtectionRequest {
    ForkProtectionRequest::wipe_child(Requirement::Required)
}

#[cfg(all(feature = "page-seal", target_os = "windows"))]
const fn page_sealed_fork_request() -> ForkProtectionRequest {
    ForkProtectionRequest::inherit()
}

#[cfg(all(
    feature = "page-seal",
    not(any(target_os = "linux", target_os = "windows"))
))]
const fn page_sealed_fork_request() -> ForkProtectionRequest {
    ForkProtectionRequest::wipe_child(Requirement::Required)
}

#[cfg(feature = "canary-check")]
const fn compiled_canary_requirement() -> Requirement {
    Requirement::Required
}

#[cfg(not(feature = "canary-check"))]
const fn compiled_canary_requirement() -> Requirement {
    Requirement::NotRequested
}

#[cfg(feature = "require-fork-exclusion")]
const fn compiled_fork_requirement() -> Requirement {
    Requirement::Required
}

#[cfg(not(feature = "require-fork-exclusion"))]
const fn compiled_fork_requirement() -> Requirement {
    Requirement::Preferred
}

/// Actual outcome of one requested runtime protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionState {
    /// The control was established for the current storage.
    Established,
    /// The control was not requested and was not attempted.
    NotRequested,
    /// The control does not apply, such as locking an empty mapping.
    NotApplicable,
    /// The target or compiled backend does not support the control.
    Unsupported,
    /// A preferred control was attempted but failed.
    Failed {
        /// Positive platform error code when available.
        code: i32,
    },
    /// The API is present only for compatibility and the native control is
    /// outside the module's authority, as on WASM.
    CompatibilityOnly,
}

impl ProtectionState {
    /// Returns whether this outcome fulfills a requested control.
    ///
    /// `NotApplicable` fulfills a request because there is no live storage on
    /// which to establish the control. `NotRequested` requirements are always
    /// fulfilled and do not imply that a control was attempted.
    #[must_use]
    pub const fn satisfies(self, requirement: Requirement) -> bool {
        match requirement {
            Requirement::NotRequested => true,
            Requirement::Required | Requirement::Preferred => {
                matches!(self, Self::Established | Self::NotApplicable)
            }
        }
    }
}

/// Actual outcome of the requested process-fork behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkProtectionReport {
    /// Fork behavior requested by the caller.
    pub policy: ForkPolicy,
    /// Whether that behavior was established.
    pub state: ProtectionState,
}

/// Runtime report retained by a mapped secret container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionReport {
    /// Private mapping or compatibility storage outcome.
    pub mapping: ProtectionState,
    /// Page-lock outcome.
    pub memory_lock: ProtectionState,
    /// Core-dump exclusion outcome.
    pub dump_exclusion: ProtectionState,
    /// Process-fork behavior outcome.
    pub fork: ForkProtectionReport,
    /// Guard-page outcome.
    pub guard_pages: ProtectionState,
    /// Canary integrity outcome.
    pub canary: ProtectionState,
    /// Persistent cache-policy outcome.
    pub cache_policy: ProtectionState,
    /// Secret payload bytes requested by the caller.
    pub requested_bytes: usize,
    /// Bytes in the owned platform mapping.
    pub mapped_bytes: usize,
    /// Bytes successfully locked against ordinary paging.
    pub locked_bytes: usize,
    /// Page granule used for mapping arithmetic, or zero for compatibility
    /// storage without host page control.
    pub page_granule: usize,
    /// Whether a lock failure code is commonly associated with a lock quota
    /// or working-set limit.
    pub lock_quota_likely: bool,
}

impl ProtectionReport {
    /// Returns whether every requested control was established or did not
    /// apply to empty storage.
    ///
    /// This is stricter than construction success: a failed or unsupported
    /// `Preferred` control returns `false`, even though construction may
    /// legitimately have returned a live reduced-protection container.
    /// Controls marked [`Requirement::NotRequested`] are ignored.
    #[must_use]
    pub fn all_requested_controls_established(&self, request: ProtectionRequest) -> bool {
        self.memory_lock.satisfies(request.memory_lock)
            && self.dump_exclusion.satisfies(request.dump_exclusion)
            && self.fork.policy == request.fork.policy
            && self.fork.state.satisfies(request.fork.requirement)
            && self.guard_pages.satisfies(request.guard_pages)
            && self.canary.satisfies(request.canary)
            && self.cache_policy.satisfies(request.cache_policy)
    }

    #[allow(dead_code)]
    pub(crate) const fn pending(
        request: ProtectionRequest,
        requested_bytes: usize,
        page_granule: usize,
    ) -> Self {
        Self {
            mapping: ProtectionState::NotRequested,
            memory_lock: initial_state(request.memory_lock),
            dump_exclusion: initial_state(request.dump_exclusion),
            fork: ForkProtectionReport {
                policy: request.fork.policy,
                state: initial_fork_state(request.fork),
            },
            guard_pages: initial_state(request.guard_pages),
            canary: initial_state(request.canary),
            cache_policy: initial_state(request.cache_policy),
            requested_bytes,
            mapped_bytes: 0,
            locked_bytes: 0,
            page_granule,
            lock_quota_likely: false,
        }
    }
}

#[allow(dead_code)]
const fn initial_state(requirement: Requirement) -> ProtectionState {
    match requirement {
        Requirement::NotRequested => ProtectionState::NotRequested,
        Requirement::Required | Requirement::Preferred => ProtectionState::Unsupported,
    }
}

#[allow(dead_code)]
const fn initial_fork_state(request: ForkProtectionRequest) -> ProtectionState {
    match request.policy {
        ForkPolicy::Inherit => ProtectionState::Established,
        ForkPolicy::Exclude | ForkPolicy::WipeChild => initial_state(request.requirement),
    }
}

/// Runtime control that failed during protected allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionControl {
    /// Length or mapping setup.
    Mapping,
    /// Page locking.
    MemoryLock,
    /// Core-dump exclusion.
    DumpExclusion,
    /// Process-fork behavior.
    ForkPolicy,
    /// Guard-page establishment.
    GuardPages,
    /// Canary generation or establishment.
    Canary,
    /// Persistent cache policy.
    CachePolicy,
}

/// Non-secret description of a failed protection operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionFailure {
    /// Control that failed.
    pub control: ProtectionControl,
    /// Positive platform error code when available.
    pub code: i32,
}

/// Result of one cleanup operation after failed construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackState {
    /// The cleanup operation was unnecessary.
    NotNeeded,
    /// Cleanup completed successfully.
    Completed,
    /// Cleanup failed and storage may remain live.
    Failed(ProtectionFailure),
}

/// Cleanup results after a required protection could not be established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackReport {
    /// Page-unlock outcome.
    pub unlock: RollbackState,
    /// Mapping-release outcome.
    pub unmap: RollbackState,
}

impl RollbackReport {
    #[allow(dead_code)]
    pub(crate) const fn not_needed() -> Self {
        Self {
            unlock: RollbackState::NotNeeded,
            unmap: RollbackState::NotNeeded,
        }
    }
}

/// Error returned when a required runtime protection cannot be established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionError {
    /// Original control failure.
    pub failure: ProtectionFailure,
    /// State reached before rollback began.
    pub partial_report: ProtectionReport,
    /// Explicit cleanup outcome.
    pub rollback: RollbackReport,
}

impl fmt::Display for ProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "required protection {:?} failed with code {}; rollback: {:?}",
            self.failure.control, self.failure.code, self.rollback
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProtectionError {}

#[allow(dead_code)]
pub(crate) const fn unavailable_state(requirement: Requirement) -> Result<ProtectionState, ()> {
    match requirement {
        Requirement::Required => Err(()),
        Requirement::Preferred => Ok(ProtectionState::Unsupported),
        Requirement::NotRequested => Ok(ProtectionState::NotRequested),
    }
}

#[cfg(kani)]
pub(crate) const fn failed_state(
    requirement: Requirement,
    code: i32,
) -> Result<ProtectionState, ()> {
    match requirement {
        Requirement::Required => Err(()),
        Requirement::Preferred => Ok(ProtectionState::Failed { code }),
        Requirement::NotRequested => Ok(ProtectionState::NotRequested),
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn required_unavailable_never_degrades_to_success() {
        assert!(unavailable_state(Requirement::Required).is_err());
    }

    #[kani::proof]
    fn preferred_failure_is_reported_as_failed() {
        let code: i32 = kani::any();
        assert_eq!(
            failed_state(Requirement::Preferred, code),
            Ok(ProtectionState::Failed { code })
        );
    }

    #[kani::proof]
    fn not_requested_is_never_reported_established() {
        assert_eq!(
            unavailable_state(Requirement::NotRequested),
            Ok(ProtectionState::NotRequested)
        );
        assert_eq!(
            failed_state(Requirement::NotRequested, 7),
            Ok(ProtectionState::NotRequested)
        );
    }

    #[kani::proof]
    fn inherit_policy_is_explicitly_established() {
        assert_eq!(
            initial_fork_state(ForkProtectionRequest::inherit()),
            ProtectionState::Established
        );
    }
}
