use core::fmt;

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
    /// Request exclusion from fork inheritance where supported.
    pub fork_exclusion: Requirement,
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
            fork_exclusion: compiled_fork_requirement(),
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
            fork_exclusion: Requirement::NotRequested,
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
            fork_exclusion: compiled_fork_requirement(),
            guard_pages: Requirement::Required,
            canary: compiled_canary_requirement(),
            cache_policy: Requirement::NotRequested,
        }
    }

    /// Explicit reduced-guarantee policy for WASM compatibility storage.
    #[must_use]
    pub const fn wasm_compatibility() -> Self {
        Self {
            memory_lock: Requirement::Preferred,
            dump_exclusion: Requirement::Preferred,
            fork_exclusion: Requirement::Preferred,
            guard_pages: Requirement::NotRequested,
            canary: compiled_canary_requirement(),
            cache_policy: Requirement::NotRequested,
        }
    }
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

/// Runtime report retained by a mapped secret container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionReport {
    /// Private mapping or compatibility storage outcome.
    pub mapping: ProtectionState,
    /// Page-lock outcome.
    pub memory_lock: ProtectionState,
    /// Core-dump exclusion outcome.
    pub dump_exclusion: ProtectionState,
    /// Fork-inheritance exclusion outcome.
    pub fork_exclusion: ProtectionState,
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
            fork_exclusion: initial_state(request.fork_exclusion),
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

/// Runtime control that failed during protected allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionControl {
    /// Length or mapping setup.
    Mapping,
    /// Page locking.
    MemoryLock,
    /// Core-dump exclusion.
    DumpExclusion,
    /// Fork inheritance exclusion.
    ForkExclusion,
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
}
