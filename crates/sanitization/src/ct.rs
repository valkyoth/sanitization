//! Data-oblivious primitives for secret-handling code.
//!
//! APIs here are designed to avoid secret-dependent control flow and
//! secret-dependent memory access under documented compiler, target, feature,
//! and release-profile conditions. This is not a claim of identical wall-clock
//! timing on every target.

use core::{cmp::Ordering, fmt, hint::black_box, marker::PhantomData, ops};

/// Opaque normalized 0/1 value used by data-oblivious operations.
///
/// `Choice` is for secret-derived booleans that should remain branchless
/// while they are combined, selected on, or carried through `CtOption` and
/// `CtResult`. Turning a `Choice` into a normal `bool` is declassification
/// and should happen only through [`Choice::declassify`].
#[repr(transparent)]
#[derive(Clone, Copy, Default)]
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

    /// Explicitly convert this choice into a public normalized byte.
    ///
    /// The `reason` string is intentionally required so security reviews can
    /// search for every raw-bit declassification boundary. Most callers
    /// should prefer [`Choice::declassify`].
    #[inline]
    pub fn declassify_u8(self, reason: &'static str) -> u8 {
        black_box(reason);
        self.bit()
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
        self.bit() == 1
    }

    /// Branchless logical AND.
    #[inline]
    pub fn and(self, other: Self) -> Self {
        Self((self.bit() & other.bit()) & 1)
    }

    /// Branchless logical OR.
    #[inline]
    pub fn or(self, other: Self) -> Self {
        Self((self.bit() | other.bit()) & 1)
    }

    /// Branchless logical XOR.
    #[inline]
    pub fn xor(self, other: Self) -> Self {
        Self((self.bit() ^ other.bit()) & 1)
    }

    /// Branchless logical NOT.
    #[inline]
    pub fn not_choice(self) -> Self {
        Self(self.bit() ^ 1)
    }

    #[inline]
    fn bit(self) -> u8 {
        black_box(self.0 & 1)
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
#[derive(Clone, Copy)]
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
        let less_bit = less.0 & 1;
        let greater_bit = (greater.0 & 1) & (less_bit ^ 1);
        let equal_bit = (less_bit | greater_bit) ^ 1;

        Self::from_normalized_bits(Choice(less_bit), Choice(equal_bit), Choice(greater_bit))
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
        if self.less.bit() == 1 {
            Ordering::Less
        } else if self.greater.bit() == 1 {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

impl fmt::Debug for CtOrdering {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CtOrdering(..)")
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
#[derive(Clone, Copy)]
pub struct Mask<T> {
    value: T,
}

impl<T: Copy> Mask<T> {
    /// Explicitly convert this mask into a public raw value.
    ///
    /// The `reason` string is intentionally required so security reviews can
    /// search for every mask declassification boundary. Data-oblivious helpers
    /// inside this module use the private raw accessor instead.
    #[inline]
    pub fn declassify(self, reason: &'static str) -> T {
        black_box(reason);
        self.raw()
    }

    #[inline]
    const fn raw(self) -> T {
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
                            value: (0 as $ty).wrapping_sub(choice.bit() as $ty),
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
                        let mask = (0 as $ty).wrapping_sub(choice.bit() as $ty);
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
        destination[index] = u8::conditional_select(&destination[index], &source[index], choice);
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

    let mask = black_box(Mask::<u8>::from_choice(choice).raw());
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
