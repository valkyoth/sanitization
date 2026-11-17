#![no_std]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

//! Compatibility-oriented secret wrappers backed by [`sanitization`].
//!
//! This crate provides the familiar `SecretBox`, `SecretSlice`,
//! `SecretString`, `ExposeSecret`, and `ExposeSecretMut` API shape for projects
//! migrating from `secrecy` 0.10. It deliberately keeps reference-returning
//! exposure, cloning, and plaintext serialization out of the hardened
//! `sanitization` containers.
//!
//! The compatibility wrapper provides redacted formatting and sanitizes its
//! currently boxed value on drop. It does not provide memory locking, guard
//! pages, storage-history recovery, or the scoped-exposure guarantees of the
//! native `sanitization` container families.
//!
//! Reference exposure requires the core storage-stability contracts under
//! every feature combination. The `hazmat-unrestricted-exposure` feature adds
//! a visibly distinct [`UnrestrictedSecretBox`] for legacy types that cannot
//! satisfy those contracts; it never broadens [`SecretBox`].

extern crate alloc;

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    any, fmt,
    mem::{size_of, MaybeUninit},
};
use sanitization::{ct, SecureSanitize};

#[cfg(feature = "serde")]
use serde::{de, ser, Deserialize, Serialize};

/// The `zeroize` API used by `secrecy` callers, available through the default
/// `zeroize-interop` compatibility feature.
#[cfg(feature = "zeroize-interop")]
pub use zeroize;

/// A boxed secret value with explicit reference exposure and clearing on drop.
///
/// This compatibility type intentionally exposes references through
/// [`ExposeSecret`] and [`ExposeSecretMut`], with stable-storage bounds by
/// default. Prefer native `sanitization` containers when scoped closure
/// exposure, memory locking, canaries, or guard pages are required.
pub struct SecretBox<S: SecureSanitize + ?Sized> {
    inner_secret: Box<S>,
}

impl<S: SecureSanitize + ?Sized> SecretBox<S> {
    /// Wrap an already boxed secret without copying it.
    #[must_use]
    #[inline]
    pub const fn new(boxed_secret: Box<S>) -> Self {
        Self {
            inner_secret: boxed_secret,
        }
    }

    /// Sanitize the currently boxed value while retaining its allocation.
    #[inline]
    pub fn clear_secret(&mut self) {
        self.inner_secret.secure_sanitize();
    }

    /// Consume this wrapper after sanitizing its value.
    #[inline]
    pub fn into_cleared(self) {
        drop(self);
    }
}

impl<S: sanitization::StableMutableSecretStorage + Default> SecretBox<S> {
    /// Allocate a default value and initialize it directly through a mutable
    /// reference.
    ///
    /// If `initialize` panics, the partially initialized boxed value is
    /// sanitized during unwinding.
    #[must_use]
    #[inline]
    pub fn init_with_mut(initialize: impl FnOnce(&mut S)) -> Self {
        let mut secret = Self::default();
        initialize(secret.expose_secret_mut());
        secret
    }

    /// Fallible in-place initialization of the final boxed value.
    ///
    /// Returning an error or unwinding sanitizes the partially initialized
    /// value before its allocation is released. Allocation failure can still
    /// abort and is not represented by `E`.
    #[inline]
    pub fn try_init_with_mut<E>(
        initialize: impl FnOnce(&mut S) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut secret = Self::default();
        initialize(secret.expose_secret_mut())?;
        Ok(secret)
    }
}

impl<S: CloneableSecret> SecretBox<S> {
    /// Construct a value, clone it into its final allocation, and sanitize the
    /// temporary value.
    ///
    /// Prefer [`SecretBox::new`] or [`SecretBox::init_with_mut`] because this
    /// operation necessarily creates a temporary copy. The temporary is also
    /// sanitized if cloning panics and Rust unwinds. Cleanup is not guaranteed
    /// after an abort, including an allocation failure handled by aborting.
    /// `CloneableSecret` requires custom clone implementations to sanitize
    /// secret-bearing partial destination state if cloning unwinds; this
    /// wrapper cannot recover state discarded inside arbitrary `Clone` code.
    #[must_use]
    #[inline]
    pub fn init_with(construct: impl FnOnce() -> S) -> Self {
        let temporary = TemporarySecret::new(construct());
        Self::new(Box::new(temporary.value().clone()))
    }

    /// Fallible form of [`SecretBox::init_with`].
    ///
    /// Generator errors are returned directly. A successfully generated
    /// temporary is sanitized on success and during panic unwinding. Allocation
    /// failure and a panic from `S::clone` are not represented by `E`.
    ///
    /// `CloneableSecret` is an explicit security contract: if `S::clone`
    /// unwinds after constructing secret-bearing destination state, that
    /// partial state must sanitize itself during ordinary destruction. This
    /// wrapper can sanitize the complete source temporary, but Rust does not
    /// expose an arbitrary clone's discarded partial destination to it.
    #[inline]
    pub fn try_init_with<E>(construct: impl FnOnce() -> Result<S, E>) -> Result<Self, E> {
        let temporary = TemporarySecret::new(construct()?);
        Ok(Self::new(Box::new(temporary.value().clone())))
    }
}

impl<S: SecureSanitize + ?Sized> From<Box<S>> for SecretBox<S> {
    #[inline]
    fn from(source: Box<S>) -> Self {
        Self::new(source)
    }
}

impl<S: SecureSanitize + Default> Default for SecretBox<S> {
    #[inline]
    fn default() -> Self {
        Self::new(Box::<S>::default())
    }
}

impl<S: SecureSanitize + ?Sized> SecureSanitize for SecretBox<S> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "zeroize-interop")]
impl<S: SecureSanitize + ?Sized> zeroize::Zeroize for SecretBox<S> {
    #[inline]
    fn zeroize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "zeroize-interop")]
impl<S: SecureSanitize + ?Sized> zeroize::ZeroizeOnDrop for SecretBox<S> {}

impl<S: SecureSanitize + ?Sized> Drop for SecretBox<S> {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
    }
}

impl<S: SecureSanitize + ?Sized> fmt::Debug for SecretBox<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SecretBox<{}>([REDACTED])",
            any::type_name::<S>()
        )
    }
}

impl<S: SecureSanitize + ct::ConstantTimeEq + ?Sized> SecretBox<S> {
    /// Compare two wrapped values without secret-dependent early exit.
    ///
    /// For dynamically sized values, length is public. The returned choice
    /// must be explicitly declassified before it can control normal program
    /// flow. Prefer this method over comparing exposed references with `==`.
    #[must_use]
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> ct::Choice {
        ct::ConstantTimeEq::ct_eq(self.inner_secret.as_ref(), other.inner_secret.as_ref())
    }
}

impl<S: CloneableSecret> Clone for SecretBox<S> {
    #[inline]
    fn clone(&self) -> Self {
        Self::new(self.inner_secret.clone())
    }
}

impl<S: sanitization::StableSharedSecretStorage + ?Sized> ExposeSecret<S> for SecretBox<S> {
    #[inline]
    fn expose_secret(&self) -> &S {
        self.inner_secret.as_ref()
    }
}

impl<S: sanitization::StableMutableSecretStorage + ?Sized> ExposeSecretMut<S> for SecretBox<S> {
    #[inline]
    fn expose_secret_mut(&mut self) -> &mut S {
        self.inner_secret.as_mut()
    }
}

/// Explicit reduced-assurance wrapper for legacy unrestricted exposure.
///
/// This type is available only with `hazmat-unrestricted-exposure`. Unlike
/// [`SecretBox`], it does not require storage-stability attestations before
/// returning references or invoking mutable initialization callbacks. Safe
/// methods reached through those references can therefore replace or release
/// secret-bearing storage without clearing historical allocations first.
///
/// Cargo feature unification can make this type available transitively, but it
/// cannot change any method or trait implementation on [`SecretBox`]. A caller
/// must name and construct `UnrestrictedSecretBox` explicitly.
#[cfg(feature = "hazmat-unrestricted-exposure")]
pub struct UnrestrictedSecretBox<S: SecureSanitize + ?Sized> {
    inner: SecretBox<S>,
}

#[cfg(feature = "hazmat-unrestricted-exposure")]
impl<S: SecureSanitize + ?Sized> UnrestrictedSecretBox<S> {
    /// Wrap an already boxed secret without copying it.
    #[must_use]
    #[inline]
    pub const fn new(boxed_secret: Box<S>) -> Self {
        Self {
            inner: SecretBox::new(boxed_secret),
        }
    }

    /// Sanitize the currently boxed value while retaining its allocation.
    #[inline]
    pub fn clear_secret(&mut self) {
        self.inner.clear_secret();
    }

    /// Convert to the storage-gated wrapper without copying the secret.
    #[must_use]
    #[inline]
    pub fn into_restricted(self) -> SecretBox<S> {
        self.inner
    }

    /// Consume this wrapper after sanitizing its value.
    #[inline]
    pub fn into_cleared(self) {
        drop(self);
    }
}

#[cfg(feature = "hazmat-unrestricted-exposure")]
impl<S: SecureSanitize + Default> UnrestrictedSecretBox<S> {
    /// Allocate a default value and initialize it through an unrestricted
    /// mutable reference.
    ///
    /// If the callback reallocates or replaces owned storage, this wrapper
    /// cannot recover and sanitize the released allocation.
    #[must_use]
    #[inline]
    pub fn init_with_mut(initialize: impl FnOnce(&mut S)) -> Self {
        let mut secret = Self::default();
        initialize(secret.inner.inner_secret.as_mut());
        secret
    }

    /// Fallible unrestricted initialization of the final boxed value.
    ///
    /// Returning an error or unwinding sanitizes the currently owned value,
    /// but cannot recover storage released by the callback.
    #[inline]
    pub fn try_init_with_mut<E>(
        initialize: impl FnOnce(&mut S) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut secret = Self::default();
        initialize(secret.inner.inner_secret.as_mut())?;
        Ok(secret)
    }
}

#[cfg(feature = "hazmat-unrestricted-exposure")]
impl<S: SecureSanitize + ?Sized> From<Box<S>> for UnrestrictedSecretBox<S> {
    #[inline]
    fn from(source: Box<S>) -> Self {
        Self::new(source)
    }
}

#[cfg(feature = "hazmat-unrestricted-exposure")]
impl<S: SecureSanitize + Default> Default for UnrestrictedSecretBox<S> {
    #[inline]
    fn default() -> Self {
        Self {
            inner: SecretBox::default(),
        }
    }
}

#[cfg(feature = "hazmat-unrestricted-exposure")]
impl<S: SecureSanitize + ?Sized> SecureSanitize for UnrestrictedSecretBox<S> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(all(feature = "hazmat-unrestricted-exposure", feature = "zeroize-interop"))]
impl<S: SecureSanitize + ?Sized> zeroize::Zeroize for UnrestrictedSecretBox<S> {
    #[inline]
    fn zeroize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(all(feature = "hazmat-unrestricted-exposure", feature = "zeroize-interop"))]
impl<S: SecureSanitize + ?Sized> zeroize::ZeroizeOnDrop for UnrestrictedSecretBox<S> {}

#[cfg(feature = "hazmat-unrestricted-exposure")]
impl<S: SecureSanitize + ?Sized> fmt::Debug for UnrestrictedSecretBox<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "UnrestrictedSecretBox<{}>([REDACTED])",
            any::type_name::<S>()
        )
    }
}

#[cfg(feature = "hazmat-unrestricted-exposure")]
impl<S: SecureSanitize + ct::ConstantTimeEq + ?Sized> UnrestrictedSecretBox<S> {
    /// Compare two wrapped values without secret-dependent early exit.
    #[must_use]
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> ct::Choice {
        self.inner.ct_eq(&other.inner)
    }
}

#[cfg(feature = "hazmat-unrestricted-exposure")]
impl<S: CloneableSecret> Clone for UnrestrictedSecretBox<S> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(feature = "hazmat-unrestricted-exposure")]
impl<S: SecureSanitize + ?Sized> ExposeSecret<S> for UnrestrictedSecretBox<S> {
    #[inline]
    fn expose_secret(&self) -> &S {
        self.inner.inner_secret.as_ref()
    }
}

#[cfg(feature = "hazmat-unrestricted-exposure")]
impl<S: SecureSanitize + ?Sized> ExposeSecretMut<S> for UnrestrictedSecretBox<S> {
    #[inline]
    fn expose_secret_mut(&mut self) -> &mut S {
        self.inner.inner_secret.as_mut()
    }
}

/// A boxed secret slice.
pub type SecretSlice<S> = SecretBox<[S]>;

/// Error returned when a no-copy vector transfer would discard capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretSliceCapacityError {
    /// Number of initialized elements.
    pub length: usize,
    /// Number of elements in the source allocation.
    pub capacity: usize,
}

impl fmt::Display for SecretSliceCapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "secret slice source has length {} but capacity {}; no-copy boxing would discard secret-bearing capacity",
            self.length, self.capacity
        )
    }
}

impl<S: SecureSanitize> SecretSlice<S> {
    /// Transfer a vector without copying when its allocation is already exact.
    ///
    /// A non-zero-sized vector with excess capacity is sanitized and rejected
    /// before `into_boxed_slice` can release that allocation. Do not call
    /// `shrink_to_fit` on secret-bearing input to satisfy this precondition;
    /// construct it with exact capacity or use the cloning [`From<Vec<S>>`]
    /// implementation when `S` implements [`CloneableSecret`].
    #[inline]
    pub fn try_from_vec_exact(mut source: Vec<S>) -> Result<Self, SecretSliceCapacityError> {
        let length = source.len();
        let capacity = source.capacity();
        if size_of::<S>() != 0 && capacity != length {
            source.secure_sanitize();
            return Err(SecretSliceCapacityError { length, capacity });
        }

        Ok(Self::new(source.into_boxed_slice()))
    }
}

impl SecretSlice<u8> {
    /// Allocate a zero-filled byte slice and initialize its final boxed storage.
    ///
    /// `length` must be trusted and bounded. Allocation failure may abort.
    #[must_use]
    #[inline]
    pub fn init_with_len(length: usize, initialize: impl FnOnce(&mut [u8])) -> Self {
        let mut secret = Self::new(alloc::vec![0_u8; length].into_boxed_slice());
        initialize(secret.expose_secret_mut());
        secret
    }

    /// Fallible allocation and initialization of a runtime-length byte slice.
    ///
    /// A returned error or unwind sanitizes the final boxed byte allocation.
    /// Allocation refusal and initializer failure remain distinguishable. This
    /// method does not enforce an application limit; use
    /// [`SecretSlice::try_init_with_len_bounded`] at untrusted length
    /// boundaries.
    #[inline]
    pub fn try_init_with_len<E>(
        length: usize,
        initialize: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, SecretSliceInitError<E>> {
        let mut secret =
            try_allocate_exact_zeroed_slice(length).map_err(SecretSliceInitError::Build)?;
        initialize(secret.expose_secret_mut()).map_err(SecretSliceInitError::Initialize)?;
        Ok(secret)
    }

    /// Fallibly allocate and initialize a byte slice under a compile-time
    /// public length ceiling.
    ///
    /// Oversized lengths are rejected before allocation and before
    /// `initialize` runs. Allocation refusal, a non-exact allocator capacity,
    /// and initializer failure remain distinct typed outcomes.
    #[inline]
    pub fn try_init_with_len_bounded<const MAX: usize, E>(
        length: usize,
        initialize: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, SecretSliceInitError<E>> {
        if length > MAX {
            return Err(SecretSliceInitError::Build(
                SecretSliceAllocationError::TooLong {
                    maximum: MAX,
                    actual: length,
                },
            ));
        }

        Self::try_init_with_len(length, initialize)
    }
}

/// Error returned while allocating final storage for a runtime-length secret
/// slice.
#[derive(Debug)]
pub enum SecretSliceAllocationError {
    /// The requested public length exceeded the compile-time maximum.
    TooLong {
        /// Maximum accepted byte length.
        maximum: usize,
        /// Rejected requested byte length.
        actual: usize,
    },
    /// The allocator could not reserve the requested byte length.
    Allocation(alloc::collections::TryReserveError),
    /// The allocator exposed more logical capacity than requested.
    ///
    /// The allocation is released before it receives secret input.
    NonExactCapacity {
        /// Requested byte length.
        requested: usize,
        /// Capacity returned by the allocator.
        actual: usize,
    },
}

impl fmt::Display for SecretSliceAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { maximum, actual } => write!(
                formatter,
                "secret slice length exceeds limit: maximum {maximum} bytes, got {actual} bytes"
            ),
            Self::Allocation(error) => write!(formatter, "secret slice allocation failed: {error}"),
            Self::NonExactCapacity { requested, actual } => write!(
                formatter,
                "secret slice allocator returned capacity {actual} for requested length {requested}"
            ),
        }
    }
}

impl core::error::Error for SecretSliceAllocationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Allocation(error) => Some(error),
            Self::TooLong { .. } | Self::NonExactCapacity { .. } => None,
        }
    }
}

/// Error returned by fallible runtime-length secret-slice initialization.
#[derive(Debug)]
pub enum SecretSliceInitError<E> {
    /// Public-length validation or allocation failed before initialization.
    Build(SecretSliceAllocationError),
    /// The caller's initializer returned an error.
    Initialize(E),
}

impl<E> From<SecretSliceAllocationError> for SecretSliceInitError<E> {
    #[inline]
    fn from(error: SecretSliceAllocationError) -> Self {
        Self::Build(error)
    }
}

impl<E: fmt::Display> fmt::Display for SecretSliceInitError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(error) => error.fmt(formatter),
            Self::Initialize(error) => {
                write!(formatter, "secret slice initialization failed: {error}")
            }
        }
    }
}

impl<E> core::error::Error for SecretSliceInitError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Build(error) => Some(error),
            Self::Initialize(error) => Some(error),
        }
    }
}

fn try_allocate_exact_zeroed_slice(
    length: usize,
) -> Result<SecretSlice<u8>, SecretSliceAllocationError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(SecretSliceAllocationError::Allocation)?;

    if bytes.capacity() != length {
        return Err(SecretSliceAllocationError::NonExactCapacity {
            requested: length,
            actual: bytes.capacity(),
        });
    }

    bytes.resize(length, 0);
    Ok(SecretSlice::new(bytes.into_boxed_slice()))
}

impl<S: CloneableSecret> From<Vec<S>> for SecretSlice<S> {
    /// Clone into guarded destination storage, then sanitize the source vector.
    ///
    /// This intentionally copies the live elements so the source allocation,
    /// including excess capacity, can be cleared before release. Completed
    /// destination elements are also sanitized if a later clone panics.
    #[inline]
    fn from(source: Vec<S>) -> Self {
        let source = TemporarySecret::new(source);
        Self::new(clone_slice_into_box(source.value()))
    }
}

impl<S: CloneableSecret> Clone for SecretSlice<S> {
    #[inline]
    fn clone(&self) -> Self {
        Self::new(clone_slice_into_box(self.inner_secret.as_ref()))
    }
}

impl<S: SecureSanitize> Default for SecretSlice<S> {
    #[inline]
    fn default() -> Self {
        Self::new(Vec::new().into_boxed_slice())
    }
}

/// A boxed UTF-8 secret string.
pub type SecretString = SecretBox<str>;

/// Byte-limit and exact-allocation errors for boxed UTF-8 text.
pub type SecretStringBuildError = SecretSliceAllocationError;

impl SecretString {
    /// Copy owned UTF-8 text into final boxed storage under a public byte limit.
    ///
    /// The source allocation, including spare capacity, is sanitized on success,
    /// on any returned error, and during unwinding. The limit applies to the
    /// source length in bytes. Excess length is rejected before reserving the box.
    ///
    /// ```
    /// use sanitization_secrecy::{ExposeSecret, SecretString};
    ///
    /// let token = SecretString::try_from_string_bounded::<64>(String::from("token"))?;
    /// assert_eq!(token.expose_secret(), "token");
    /// # Ok::<(), sanitization_secrecy::SecretStringBuildError>(())
    /// ```
    pub fn try_from_string_bounded<const MAX: usize>(
        source: String,
    ) -> Result<Self, SecretStringBuildError> {
        let source = TemporarySecret::new(source);
        Self::try_from_str_bounded::<MAX>(source.value())
    }

    /// Fallibly copy borrowed UTF-8 text into a box of at most `MAX` bytes.
    /// The caller retains responsibility for the borrowed source.
    pub fn try_from_str_bounded<const MAX: usize>(
        source: &str,
    ) -> Result<Self, SecretStringBuildError> {
        let len = source.len();
        if len > MAX {
            return Err(SecretStringBuildError::TooLong {
                maximum: MAX,
                actual: len,
            });
        }
        let mut text = String::new();
        text.try_reserve_exact(len)
            .map_err(SecretStringBuildError::Allocation)?;
        // Boxing can shrink excess capacity. Reject it while the buffer is empty.
        if text.capacity() != len {
            return Err(SecretStringBuildError::NonExactCapacity {
                requested: len,
                actual: text.capacity(),
            });
        }
        text.push_str(source);
        Ok(Self::new(text.into_boxed_str()))
    }
}

impl From<String> for SecretString {
    /// Copy into final boxed string storage and sanitize the source allocation.
    ///
    /// Copying is intentional: it permits the complete source capacity to be
    /// cleared before release instead of asking `String::into_boxed_str` to
    /// discard excess capacity without sanitizing it.
    #[inline]
    fn from(source: String) -> Self {
        let source = TemporarySecret::new(source);
        Self::new(Box::<str>::from(source.value().as_str()))
    }
}

impl From<&str> for SecretString {
    /// Copy a borrowed string into compatibility storage.
    ///
    /// The source remains outside this wrapper's ownership and clearing
    /// guarantee.
    #[inline]
    fn from(source: &str) -> Self {
        Self::new(Box::<str>::from(source))
    }
}

/// Compatibility exception: `SecretString` is always cloneable to match
/// `secrecy` 0.10. Other generic `SecretBox<S>` values require
/// [`CloneableSecret`].
impl Clone for SecretString {
    #[inline]
    fn clone(&self) -> Self {
        Self::new(self.inner_secret.clone())
    }
}

impl Default for SecretString {
    #[inline]
    fn default() -> Self {
        String::new().into()
    }
}

/// Marker for secret values whose owners explicitly permit duplication.
///
/// Types do not become cloneable merely by implementing [`SecureSanitize`]:
/// `SecretString` is the intentional compatibility exception and remains
/// unconditionally cloneable to match `secrecy` 0.10.
///
/// ```compile_fail
/// use sanitization::SecureSanitize;
/// use sanitization_secrecy::SecretBox;
///
/// #[derive(Clone)]
/// struct RequiresOptIn(u8);
/// impl SecureSanitize for RequiresOptIn {
///     fn secure_sanitize(&mut self) {
///         self.0.secure_sanitize();
///     }
/// }
///
/// let secret = SecretBox::new(Box::new(RequiresOptIn(7)));
/// let duplicate = secret.clone();
/// # let _ = duplicate;
/// ```
///
/// Implementors are responsible for ensuring that partially cloned owned
/// state is sanitized if their `Clone` implementation unwinds. The wrapper can
/// guard completed slice elements, but it cannot inspect partial state inside
/// an arbitrary `S::clone()` implementation.
///
/// This crate implements the marker for reviewed integer primitives, `String`,
/// and arrays whose elements are those integer primitives. A custom `Copy`
/// implementation does not authorize its array automatically because `Copy`
/// does not prevent a separate manually implemented `Clone` from panicking.
pub trait CloneableSecret: Clone + SecureSanitize {}

macro_rules! impl_cloneable_secret {
    ($($type:ty),+ $(,)?) => {
        $(impl CloneableSecret for $type {})+
    };
}

impl_cloneable_secret!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize,);

impl CloneableSecret for String {}

macro_rules! impl_cloneable_secret_arrays {
    ($($type:ty),+ $(,)?) => {
        $(impl<const N: usize> CloneableSecret for [$type; N] {})+
    };
}

impl_cloneable_secret_arrays!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize,);

/// Expose a shared reference to an inner secret.
///
/// The returned reference can remain live for the full borrow of `self`. By
/// default, `SecretBox` implements this trait only for
/// [`sanitization::StableSharedSecretStorage`]. The
/// `hazmat-unrestricted-exposure` feature adds [`UnrestrictedSecretBox`]
/// rather than weakening this implementation.
pub trait ExposeSecret<S: ?Sized> {
    /// Borrow the secret value.
    fn expose_secret(&self) -> &S;
}

/// Expose a mutable reference to an inner secret.
///
/// `SecretBox` implements this trait only for
/// [`sanitization::StableMutableSecretStorage`]. The
/// `hazmat-unrestricted-exposure` feature adds [`UnrestrictedSecretBox`]
/// rather than weakening this implementation.
pub trait ExposeSecretMut<S: ?Sized> {
    /// Mutably borrow the secret value.
    fn expose_secret_mut(&mut self) -> &mut S;
}

/// Marker for secret values whose owners explicitly permit plaintext Serde
/// serialization.
///
/// Implementing this trait is an exfiltration decision. Serialized output and
/// serializer-owned intermediate buffers are outside this crate's clearing
/// guarantees.
///
/// Serialization is unavailable without an explicit implementation:
///
/// ```compile_fail
/// use sanitization_secrecy::SecretBox;
///
/// let secret = SecretBox::new(Box::new(String::from("token")));
/// let encoded = serde_json::to_string(&secret).unwrap();
/// # let _ = encoded;
/// ```
#[cfg(feature = "serde")]
pub trait SerializableSecret: Serialize {}

#[cfg(feature = "serde-compat-unbounded")]
impl<'de, T> Deserialize<'de> for SecretBox<T>
where
    T: CloneableSecret + de::DeserializeOwned + Sized,
{
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Self::try_init_with(|| T::deserialize(deserializer))
    }
}

#[cfg(all(
    feature = "serde-compat-unbounded",
    feature = "hazmat-unrestricted-exposure"
))]
impl<'de, T> Deserialize<'de> for UnrestrictedSecretBox<T>
where
    T: CloneableSecret + de::DeserializeOwned + Sized,
{
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        SecretBox::deserialize(deserializer).map(|inner| Self { inner })
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SecretString {
    /// Deserialize with the core crate's default 1 MiB UTF-8 byte ceiling.
    ///
    /// This limit is checked when the deserializer invokes the visitor. Enforce
    /// a separate transport or parser limit because parser-owned buffers may
    /// already exist by then. Use `sanitization::BoundedSecretString` when the
    /// storage type must enforce a smaller permanent maximum.
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_string(SecretStringVisitor)
    }
}

#[cfg(feature = "serde")]
struct SecretStringVisitor;

#[cfg(feature = "serde")]
impl<'de> de::Visitor<'de> for SecretStringVisitor {
    type Value = SecretString;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "at most {} UTF-8 bytes of secret text",
            sanitization::DEFAULT_SECRET_STRING_SERDE_MAX_LEN
        )
    }

    fn visit_str<E>(self, text: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        SecretString::try_from_str_bounded::<{ sanitization::DEFAULT_SECRET_STRING_SERDE_MAX_LEN }>(
            text,
        )
        .map_err(|error| self.build_error(error))
    }

    fn visit_string<E>(self, text: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        SecretString::try_from_string_bounded::<{ sanitization::DEFAULT_SECRET_STRING_SERDE_MAX_LEN }>(text)
            .map_err(|error| self.build_error(error))
    }
}

#[cfg(feature = "serde")]
impl SecretStringVisitor {
    fn build_error<E: de::Error>(&self, error: SecretStringBuildError) -> E {
        match error {
            SecretStringBuildError::TooLong { actual, .. } => E::invalid_length(actual, self),
            other => E::custom(other),
        }
    }
}

#[cfg(feature = "serde")]
impl<T> Serialize for SecretBox<T>
where
    T: sanitization::StableSharedSecretStorage + SerializableSecret + Serialize + Sized,
{
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.expose_secret().serialize(serializer)
    }
}

#[cfg(all(feature = "serde", feature = "hazmat-unrestricted-exposure"))]
impl<T> Serialize for UnrestrictedSecretBox<T>
where
    T: SecureSanitize + SerializableSecret + Serialize + Sized,
{
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.inner.inner_secret.as_ref().serialize(serializer)
    }
}

struct TemporarySecret<T: SecureSanitize>(T);

impl<T: SecureSanitize> TemporarySecret<T> {
    #[inline]
    const fn new(value: T) -> Self {
        Self(value)
    }

    #[inline]
    const fn value(&self) -> &T {
        &self.0
    }
}

fn clone_slice_into_box<S: CloneableSecret>(source: &[S]) -> Box<[S]> {
    let mut pending = PendingCloneSlice::new(source.len());
    for item in source {
        pending.push(item.clone());
    }
    pending.into_box()
}

struct PendingCloneSlice<S: SecureSanitize> {
    storage: Option<Box<[MaybeUninit<S>]>>,
    initialized: usize,
}

impl<S: SecureSanitize> PendingCloneSlice<S> {
    fn new(length: usize) -> Self {
        Self {
            storage: Some(Box::<[S]>::new_uninit_slice(length)),
            initialized: 0,
        }
    }

    fn push(&mut self, value: S) {
        let storage = self.storage.as_mut().expect("pending clone storage");
        storage[self.initialized].write(value);
        self.initialized += 1;
    }

    #[allow(unsafe_code)]
    fn into_box(mut self) -> Box<[S]> {
        let expected = self.storage.as_ref().expect("pending clone storage").len();
        assert_eq!(
            self.initialized, expected,
            "pending clone slice is not fully initialized"
        );
        let storage = self.storage.take().expect("pending clone storage");
        // SAFETY: the mandatory check above proves that `push` initialized
        // every slot in the consecutive prefix before the guard was disarmed.
        unsafe { storage.assume_init() }
    }
}

impl<S: SecureSanitize> Drop for PendingCloneSlice<S> {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        let Some(storage) = self.storage.as_mut() else {
            return;
        };

        for slot in &mut storage[..self.initialized] {
            // SAFETY: only the consecutive prefix counted by `initialized`
            // has been written. Each value is sanitized before its destructor
            // runs, and `MaybeUninit` prevents a second automatic drop.
            unsafe {
                slot.assume_init_mut().secure_sanitize();
                slot.assume_init_drop();
            }
        }
    }
}

impl<T: SecureSanitize> Drop for TemporarySecret<T> {
    #[inline]
    fn drop(&mut self) {
        self.0.secure_sanitize();
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::{
        format, panic,
        sync::{Arc, Mutex},
    };

    static DEFAULT_VALUE_CLEARED: AtomicBool = AtomicBool::new(false);
    static DEFAULT_VALUE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(feature = "serde")]
    impl SerializableSecret for [u8; 4] {}

    #[cfg(all(feature = "serde", feature = "hazmat-unrestricted-exposure"))]
    impl SerializableSecret for String {}

    #[test]
    fn string_and_slice_round_trip() {
        let mut source = String::with_capacity(64);
        source.push_str("token");
        let mut text = SecretString::from(source);
        assert_eq!(text.expose_secret(), "token");
        text.expose_secret_mut().make_ascii_uppercase();
        assert_eq!(text.expose_secret(), "TOKEN");
        text.clear_secret();
        assert_eq!(text.expose_secret().as_bytes(), &[0; 5]);

        let bytes = SecretSlice::from(vec![1_u8, 2, 3]);
        assert_eq!(bytes.expose_secret(), &[1, 2, 3]);
    }

    #[cfg(feature = "hazmat-unrestricted-exposure")]
    #[test]
    fn hazmat_newtype_provides_explicit_unrestricted_string_exposure() {
        let mut secret =
            UnrestrictedSecretBox::<String>::init_with_mut(|text| text.push_str("token"));
        secret.expose_secret_mut().push_str("-rotated");
        assert_eq!(secret.expose_secret(), "token-rotated");

        let restricted = secret.into_restricted();
        assert_eq!(restricted.inner_secret.as_ref(), "token-rotated");
    }

    #[test]
    fn exact_vector_transfer_rejects_and_sanitizes_excess_capacity() {
        struct NonCloneable {
            cleared: Arc<AtomicBool>,
            byte: u8,
        }

        impl SecureSanitize for NonCloneable {
            fn secure_sanitize(&mut self) {
                self.byte = 0;
                self.cleared.store(true, Ordering::SeqCst);
            }
        }

        let cleared = Arc::new(AtomicBool::new(false));
        let mut source = Vec::with_capacity(8);
        source.push(NonCloneable {
            cleared: Arc::clone(&cleared),
            byte: 23,
        });

        let error = SecretSlice::try_from_vec_exact(source).unwrap_err();
        assert_eq!(error.length, 1);
        assert_eq!(error.capacity, 8);
        assert!(cleared.load(Ordering::SeqCst));
    }

    #[test]
    fn exact_vector_transfer_preserves_live_elements() {
        let mut source = Vec::with_capacity(4);
        source.extend_from_slice(&[3_u8, 5, 7, 11]);
        assert_eq!(source.len(), source.capacity());

        let secret = SecretSlice::try_from_vec_exact(source).unwrap();
        assert_eq!(secret.expose_secret(), &[3, 5, 7, 11]);
    }

    #[test]
    fn vector_conversion_clears_source_with_excess_capacity() {
        let cleared = Arc::new(AtomicBool::new(false));
        let mut source = Vec::with_capacity(8);
        source.push(TrackedSecret {
            cleared: Arc::clone(&cleared),
            byte: 31,
        });

        let secret = SecretSlice::from(source);
        assert!(cleared.load(Ordering::SeqCst));
        assert_eq!(secret.expose_secret()[0].byte, 31);
    }

    #[test]
    fn debug_is_redacted() {
        let secret = SecretString::from("do-not-print");
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("do-not-print"));
    }

    #[test]
    fn init_with_mut_writes_final_allocation() {
        let secret = SecretBox::<[u8; 4]>::init_with_mut(|bytes| {
            bytes.copy_from_slice(b"test");
        });
        assert_eq!(secret.expose_secret(), b"test");
    }

    #[test]
    fn runtime_slice_initializer_uses_final_length_and_propagates_errors() {
        let secret = SecretSlice::<u8>::init_with_len(5, |bytes| {
            assert_eq!(bytes.len(), 5);
            bytes.copy_from_slice(b"token");
        });
        assert_eq!(secret.expose_secret(), b"token");

        let result = SecretSlice::<u8>::try_init_with_len(4, |bytes| {
            bytes[0] = 17;
            Err::<(), _>("injected initialization failure")
        });
        assert!(matches!(
            result,
            Err(SecretSliceInitError::Initialize(
                "injected initialization failure"
            ))
        ));
    }

    #[test]
    fn bounded_runtime_slice_rejects_length_before_initialization() {
        let initializer_called = AtomicBool::new(false);
        let result = SecretSlice::<u8>::try_init_with_len_bounded::<4, &str>(5, |_| {
            initializer_called.store(true, Ordering::SeqCst);
            Ok(())
        });

        assert!(matches!(
            result,
            Err(SecretSliceInitError::Build(
                SecretSliceAllocationError::TooLong {
                    maximum: 4,
                    actual: 5
                }
            ))
        ));
        assert!(!initializer_called.load(Ordering::SeqCst));
    }

    #[test]
    fn runtime_slice_reports_capacity_overflow_as_allocation_failure() {
        let result = SecretSlice::<u8>::try_init_with_len(usize::MAX, |_| Ok::<(), &str>(()));
        assert!(matches!(
            result,
            Err(SecretSliceInitError::Build(
                SecretSliceAllocationError::Allocation(_)
            ))
        ));
    }

    #[test]
    fn reviewed_primitive_arrays_are_cloneable_secrets() {
        fn assert_cloneable<T: CloneableSecret>() {}

        assert_cloneable::<[u8; 32]>();
        assert_cloneable::<[i128; 2]>();
    }

    #[derive(Clone)]
    struct TrackedSecret {
        cleared: Arc<AtomicBool>,
        byte: u8,
    }

    impl SecureSanitize for TrackedSecret {
        fn secure_sanitize(&mut self) {
            self.byte = 0;
            self.cleared.store(true, Ordering::SeqCst);
        }
    }

    // STORAGE CONTRACT: all secret bytes are inline; shared and mutable
    // operations in this test type neither replace nor release storage.
    impl sanitization::StableSharedSecretStorage for TrackedSecret {}
    impl sanitization::StableMutableSecretStorage for TrackedSecret {}

    impl CloneableSecret for TrackedSecret {}

    #[derive(Default)]
    struct DefaultTrackedSecret(u8);

    impl SecureSanitize for DefaultTrackedSecret {
        fn secure_sanitize(&mut self) {
            self.0 = 0;
            DEFAULT_VALUE_CLEARED.store(true, Ordering::SeqCst);
        }
    }

    // STORAGE CONTRACT: the only storage is one inline byte.
    impl sanitization::StableSharedSecretStorage for DefaultTrackedSecret {}
    impl sanitization::StableMutableSecretStorage for DefaultTrackedSecret {}

    #[test]
    fn drop_sanitizes_boxed_value() {
        let cleared = Arc::new(AtomicBool::new(false));
        let secret = SecretBox::new(Box::new(TrackedSecret {
            cleared: Arc::clone(&cleared),
            byte: 42,
        }));

        drop(secret);
        assert!(cleared.load(Ordering::SeqCst));
    }

    #[test]
    fn cloned_secret_is_independent() {
        let source = SecretBox::new(Box::new(7_u32));
        let mut duplicate = source.clone();
        *duplicate.expose_secret_mut() = 9;

        assert_eq!(*source.expose_secret(), 7);
        assert_eq!(*duplicate.expose_secret(), 9);
    }

    #[test]
    fn custom_clone_marker_is_the_positive_opt_in() {
        let cleared = Arc::new(AtomicBool::new(false));
        let source = SecretBox::new(Box::new(TrackedSecret { cleared, byte: 19 }));
        let duplicate = source.clone();
        assert_eq!(duplicate.expose_secret().byte, 19);
    }

    #[test]
    fn completed_slice_clones_are_sanitized_when_a_later_clone_panics() {
        struct PanicCloneElement {
            byte: u8,
            clone_attempts: Arc<AtomicUsize>,
            leaked_on_drop: Arc<AtomicBool>,
            cloned: bool,
        }

        impl Clone for PanicCloneElement {
            fn clone(&self) -> Self {
                if self.clone_attempts.fetch_add(1, Ordering::SeqCst) == 1 {
                    panic!("injected element clone panic");
                }
                Self {
                    byte: self.byte,
                    clone_attempts: Arc::clone(&self.clone_attempts),
                    leaked_on_drop: Arc::clone(&self.leaked_on_drop),
                    cloned: true,
                }
            }
        }

        impl SecureSanitize for PanicCloneElement {
            fn secure_sanitize(&mut self) {
                self.byte = 0;
            }
        }

        impl CloneableSecret for PanicCloneElement {}

        impl Drop for PanicCloneElement {
            fn drop(&mut self) {
                if self.cloned && self.byte != 0 {
                    self.leaked_on_drop.store(true, Ordering::SeqCst);
                }
            }
        }

        let clone_attempts = Arc::new(AtomicUsize::new(0));
        let leaked_on_drop = Arc::new(AtomicBool::new(false));
        let source = SecretBox::new(
            vec![
                PanicCloneElement {
                    byte: 11,
                    clone_attempts: Arc::clone(&clone_attempts),
                    leaked_on_drop: Arc::clone(&leaked_on_drop),
                    cloned: false,
                },
                PanicCloneElement {
                    byte: 13,
                    clone_attempts,
                    leaked_on_drop: Arc::clone(&leaked_on_drop),
                    cloned: false,
                },
            ]
            .into_boxed_slice(),
        );

        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _ = source.clone();
        }));
        assert!(result.is_err());
        assert!(!leaked_on_drop.load(Ordering::SeqCst));
    }

    #[test]
    fn incomplete_pending_clone_keeps_cleanup_guard_armed() {
        let cleared = Arc::new(AtomicBool::new(false));
        let mut pending = PendingCloneSlice::new(2);
        pending.push(TrackedSecret {
            cleared: Arc::clone(&cleared),
            byte: 47,
        });

        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _ = pending.into_box();
        }));

        assert!(result.is_err());
        assert!(cleared.load(Ordering::SeqCst));
    }

    #[test]
    fn compatibility_comparison_uses_explicit_declassification() {
        let left = SecretString::from("same-token");
        let equal = SecretString::from("same-token");
        let different = SecretString::from("other-token");

        assert!(left
            .ct_eq(&equal)
            .declassify("authentication token equality is intentionally public"));
        assert!(!left
            .ct_eq(&different)
            .declassify("authentication token inequality is intentionally public"));
    }

    #[test]
    fn init_temporary_is_sanitized_on_success() {
        let cleared = Arc::new(AtomicBool::new(false));
        let secret = SecretBox::init_with(|| TrackedSecret {
            cleared: Arc::clone(&cleared),
            byte: 42,
        });

        assert!(cleared.load(Ordering::SeqCst));
        assert_eq!(secret.expose_secret().byte, 42);
    }

    #[test]
    fn init_temporary_is_sanitized_when_clone_panics() {
        #[derive(Default)]
        struct PanicClone {
            cleared: Arc<AtomicBool>,
        }

        impl Clone for PanicClone {
            fn clone(&self) -> Self {
                panic!("injected clone panic")
            }
        }

        impl SecureSanitize for PanicClone {
            fn secure_sanitize(&mut self) {
                self.cleared.store(true, Ordering::SeqCst);
            }
        }

        impl CloneableSecret for PanicClone {}

        let cleared = Arc::new(AtomicBool::new(false));
        let result = panic::catch_unwind({
            let cleared = Arc::clone(&cleared);
            move || {
                let _ = SecretBox::init_with(|| PanicClone { cleared });
            }
        });

        assert!(result.is_err());
        assert!(cleared.load(Ordering::SeqCst));
    }

    #[test]
    fn init_with_mut_sanitizes_partial_value_during_unwind() {
        let _test_guard = DEFAULT_VALUE_TEST_LOCK
            .lock()
            .expect("default-value cleanup test lock");
        DEFAULT_VALUE_CLEARED.store(false, Ordering::SeqCst);
        let result = panic::catch_unwind(|| {
            let _ = SecretBox::<DefaultTrackedSecret>::init_with_mut(|secret| {
                secret.0 = 42;
                panic!("injected initializer panic");
            });
        });

        assert!(result.is_err());
        assert!(DEFAULT_VALUE_CLEARED.load(Ordering::SeqCst));
    }

    #[test]
    fn try_init_with_mut_sanitizes_partial_value_on_error() {
        let _test_guard = DEFAULT_VALUE_TEST_LOCK
            .lock()
            .expect("default-value cleanup test lock");
        DEFAULT_VALUE_CLEARED.store(false, Ordering::SeqCst);
        let result = SecretBox::<DefaultTrackedSecret>::try_init_with_mut(|secret| {
            secret.0 = 29;
            Err::<(), _>("injected initialization failure")
        });

        assert_eq!(result.unwrap_err(), "injected initialization failure");
        assert!(DEFAULT_VALUE_CLEARED.load(Ordering::SeqCst));
    }

    #[test]
    fn into_cleared_sanitizes_exactly_once() {
        struct CountedClear(Arc<AtomicUsize>);

        impl SecureSanitize for CountedClear {
            fn secure_sanitize(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let clear_count = Arc::new(AtomicUsize::new(0));
        SecretBox::new(Box::new(CountedClear(Arc::clone(&clear_count)))).into_cleared();
        assert_eq!(clear_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fallible_constructor_preserves_generator_error() {
        let result = SecretBox::<[u8; 4]>::try_init_with(|| Err::<[u8; 4], _>("failure"));
        assert_eq!(result.unwrap_err(), "failure");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_plaintext_requires_explicit_marker() {
        let secret = SecretBox::new(Box::new([1_u8, 2, 3, 4]));
        assert_eq!(secret.expose_secret(), &[1, 2, 3, 4]);
        assert_eq!(serde_json::to_string(&secret).unwrap(), "[1,2,3,4]");
    }

    #[cfg(feature = "serde")]
    #[test]
    #[cfg_attr(
        miri,
        ignore = "large JSON boundary fixture is covered natively; small byte limits are tested under Miri"
    )]
    fn serde_secret_string_enforces_default_input_ceiling() {
        let accepted_json = format!(
            "\"{}\"",
            "a".repeat(sanitization::DEFAULT_SECRET_STRING_SERDE_MAX_LEN)
        );
        let accepted: SecretString = serde_json::from_str(&accepted_json).unwrap();
        assert_eq!(
            accepted.expose_secret().len(),
            sanitization::DEFAULT_SECRET_STRING_SERDE_MAX_LEN
        );

        let rejected_json = format!(
            "\"{}\"",
            "b".repeat(sanitization::DEFAULT_SECRET_STRING_SERDE_MAX_LEN + 1)
        );
        assert!(serde_json::from_str::<SecretString>(&rejected_json).is_err());
        use serde::de::Visitor;
        let oversized = "b".repeat(sanitization::DEFAULT_SECRET_STRING_SERDE_MAX_LEN + 1);
        let error = SecretStringVisitor
            .visit_string::<de::value::Error>(oversized)
            .unwrap_err();
        assert!(format!("{error}").contains("invalid length"));
    }

    #[test]
    fn bounded_string_constructors_measure_utf8_bytes() {
        let two_bytes = "\u{e9}";
        assert_eq!(
            SecretString::try_from_string_bounded::<2>(two_bytes.into())
                .unwrap()
                .expose_secret(),
            two_bytes
        );
        assert!(matches!(
            SecretString::try_from_str_bounded::<1>(two_bytes),
            Err(SecretStringBuildError::TooLong {
                actual: 2,
                maximum: 1
            })
        ));
        assert_eq!(
            SecretString::try_from_str_bounded::<0>("")
                .unwrap()
                .expose_secret(),
            ""
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_owned_string_preserves_text() {
        use serde::de::Visitor;
        let secret = SecretStringVisitor
            .visit_string::<de::value::Error>("token".into())
            .unwrap();
        assert_eq!(secret.expose_secret(), "token");
    }

    #[cfg(feature = "serde-compat-unbounded")]
    #[test]
    fn generic_serde_deserialization_requires_unbounded_compatibility_opt_in() {
        let secret: SecretBox<String> = serde_json::from_str("\"token\"").unwrap();
        assert_eq!(secret.inner_secret.as_ref(), "token");
    }

    #[cfg(all(
        feature = "serde-compat-unbounded",
        feature = "hazmat-unrestricted-exposure"
    ))]
    #[test]
    fn unrestricted_newtype_serde_requires_both_explicit_features() {
        let secret: UnrestrictedSecretBox<String> = serde_json::from_str("\"token\"").unwrap();
        assert_eq!(secret.expose_secret(), "token");
        assert_eq!(serde_json::to_string(&secret).unwrap(), "\"token\"");
    }
}
