#![cfg(feature = "derive")]

use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};
use sanitization::ct::{
    Choice, ConditionallySelectable as CtConditionallySelectable,
    ConstantTimeEq as CtConstantTimeEq,
};
use sanitization::{
    secure_replace, ConditionallySelectable, ConstantTimeEq, SecretBytes, SecureSanitize,
    SecureSanitizeOnDrop,
};

#[allow(dead_code)]
struct NotSanitizable;

#[derive(SecureSanitize)]
struct DerivedCredentials {
    key: SecretBytes<4>,
    token: [u8; 4],
}

#[derive(SecureSanitize)]
#[sanitization(crate = "::sanitization")]
struct CratePathCredentials {
    key: SecretBytes<4>,
}

#[derive(SecureSanitize)]
struct TupleCredentials(SecretBytes<4>, [u8; 2]);

#[derive(ConstantTimeEq, ConditionallySelectable)]
struct DerivedCtToken {
    key: [u8; 4],
    counter: u32,
}

#[derive(ConstantTimeEq)]
struct DerivedCtPublicLabel {
    key: [u8; 4],
    #[sanitization(skip)]
    #[allow(dead_code)]
    label: u8,
}

#[derive(ConstantTimeEq, ConditionallySelectable)]
struct DerivedCtTuple([u8; 2], u16);

#[derive(ConstantTimeEq)]
#[sanitization(crate = "::sanitization")]
struct DerivedCtCratePath {
    key: [u8; 4],
}

#[derive(ConstantTimeEq, ConditionallySelectable)]
struct DerivedCtGeneric<T> {
    inner: T,
}

#[derive(SecureSanitize)]
#[sanitization(enum_inactive_variant_bytes = "acknowledged")]
enum DerivedMaterial {
    Symmetric(SecretBytes<4>),
    Pair {
        private: SecretBytes<2>,
        #[sanitization(skip)]
        #[allow(dead_code)]
        public_label: NotSanitizable,
    },
    Empty,
}

#[derive(SecureSanitize)]
struct TaggedSecret<T> {
    key: SecretBytes<4>,
    marker: PhantomData<T>,
}

#[derive(SecureSanitize)]
struct SkippedTaggedSecret<T> {
    key: SecretBytes<4>,
    #[sanitization(skip)]
    marker: PhantomData<T>,
}

#[derive(SecureSanitize, SecureSanitizeOnDrop)]
struct DropSecret {
    key: DropProbe,
}

#[derive(SecureSanitize)]
#[sanitization(enum_inactive_variant_bytes = "acknowledged")]
enum ReplaceMaterial {
    Key(DropProbe),
    Empty,
}

static DROP_PROBE_SANITIZED: AtomicBool = AtomicBool::new(false);
static DROP_PROBE_DROPPED_ZEROED: AtomicBool = AtomicBool::new(false);

struct DropProbe(u8);

impl SecureSanitize for DropProbe {
    fn secure_sanitize(&mut self) {
        self.0 = 0;
        DROP_PROBE_SANITIZED.store(true, Ordering::SeqCst);
    }
}

impl Drop for DropProbe {
    fn drop(&mut self) {
        if self.0 == 0 {
            DROP_PROBE_DROPPED_ZEROED.store(true, Ordering::SeqCst);
        }
    }
}

#[test]
fn derive_secure_sanitize_clears_struct_fields() {
    let mut credentials = DerivedCredentials {
        key: SecretBytes::from_array([1, 2, 3, 4]),
        token: [5, 6, 7, 8],
    };

    credentials.secure_sanitize();

    assert!(credentials.key.constant_time_eq(&[0, 0, 0, 0]));
    assert_eq!(credentials.token, [0, 0, 0, 0]);
}

#[test]
fn derive_secure_sanitize_supports_tuple_structs() {
    let mut credentials = TupleCredentials(SecretBytes::from_array([1, 2, 3, 4]), [5, 6]);

    credentials.secure_sanitize();

    assert!(credentials.0.constant_time_eq(&[0, 0, 0, 0]));
    assert_eq!(credentials.1, [0, 0]);
}

#[test]
fn derive_secure_sanitize_supports_crate_path_override() {
    let mut credentials = CratePathCredentials {
        key: SecretBytes::from_array([1, 2, 3, 4]),
    };

    credentials.secure_sanitize();

    assert!(credentials.key.constant_time_eq(&[0, 0, 0, 0]));
}

#[test]
fn derive_secure_sanitize_covers_enum_variants() {
    let mut symmetric = DerivedMaterial::Symmetric(SecretBytes::from_array([1, 2, 3, 4]));
    symmetric.secure_sanitize();
    match symmetric {
        DerivedMaterial::Symmetric(secret) => assert!(secret.constant_time_eq(&[0, 0, 0, 0])),
        _ => panic!("unexpected variant"),
    }

    let mut pair = DerivedMaterial::Pair {
        private: SecretBytes::from_array([9, 8]),
        public_label: NotSanitizable,
    };
    pair.secure_sanitize();
    match pair {
        DerivedMaterial::Pair { private, .. } => assert!(private.constant_time_eq(&[0, 0])),
        _ => panic!("unexpected variant"),
    }

    let mut empty = DerivedMaterial::Empty;
    empty.secure_sanitize();
}

#[test]
fn derive_secure_sanitize_does_not_force_phantom_type_bounds() {
    let mut tagged = TaggedSecret::<NotSanitizable> {
        key: SecretBytes::from_array([1, 2, 3, 4]),
        marker: PhantomData,
    };
    tagged.secure_sanitize();
    assert!(tagged.key.constant_time_eq(&[0, 0, 0, 0]));

    let mut skipped = SkippedTaggedSecret::<NotSanitizable> {
        key: SecretBytes::from_array([4, 3, 2, 1]),
        marker: PhantomData,
    };
    skipped.secure_sanitize();
    assert!(skipped.key.constant_time_eq(&[0, 0, 0, 0]));
}

#[test]
fn derive_secure_sanitize_on_drop_compiles_and_runs() {
    DROP_PROBE_SANITIZED.store(false, Ordering::SeqCst);
    DROP_PROBE_DROPPED_ZEROED.store(false, Ordering::SeqCst);

    {
        let secret = DropSecret { key: DropProbe(7) };
        assert_eq!(secret.key.0, 7);
    }

    assert!(DROP_PROBE_SANITIZED.load(Ordering::SeqCst));
    assert!(DROP_PROBE_DROPPED_ZEROED.load(Ordering::SeqCst));
}

#[test]
fn secure_replace_clears_enum_active_variant_before_replacement() {
    DROP_PROBE_SANITIZED.store(false, Ordering::SeqCst);
    DROP_PROBE_DROPPED_ZEROED.store(false, Ordering::SeqCst);

    let mut material = ReplaceMaterial::Key(DropProbe(7));
    secure_replace(&mut material, ReplaceMaterial::Empty);

    assert!(DROP_PROBE_SANITIZED.load(Ordering::SeqCst));
    assert!(DROP_PROBE_DROPPED_ZEROED.load(Ordering::SeqCst));
    assert!(matches!(material, ReplaceMaterial::Empty));
}

#[test]
fn derive_constant_time_eq_compares_struct_fields() {
    let left = DerivedCtToken {
        key: [1, 2, 3, 4],
        counter: 7,
    };
    let same = DerivedCtToken {
        key: [1, 2, 3, 4],
        counter: 7,
    };
    let different_key = DerivedCtToken {
        key: [1, 2, 3, 9],
        counter: 7,
    };
    let different_counter = DerivedCtToken {
        key: [1, 2, 3, 4],
        counter: 9,
    };

    assert_eq!(left.ct_eq(&same).unwrap_u8(), 1);
    assert_eq!(left.ct_eq(&different_key).unwrap_u8(), 0);
    assert_eq!(left.ct_eq(&different_counter).unwrap_u8(), 0);
}

#[test]
fn derive_constant_time_eq_supports_skipped_public_fields() {
    let left = DerivedCtPublicLabel {
        key: [1, 2, 3, 4],
        label: 1,
    };
    let same_secret_different_label = DerivedCtPublicLabel {
        key: [1, 2, 3, 4],
        label: 9,
    };
    let different_secret = DerivedCtPublicLabel {
        key: [1, 2, 3, 9],
        label: 1,
    };

    assert_eq!(left.ct_eq(&same_secret_different_label).unwrap_u8(), 1);
    assert_eq!(left.ct_eq(&different_secret).unwrap_u8(), 0);
}

#[test]
fn derive_conditionally_selectable_selects_struct_fields() {
    let left = DerivedCtToken {
        key: [1, 2, 3, 4],
        counter: 7,
    };
    let right = DerivedCtToken {
        key: [9, 8, 7, 6],
        counter: 11,
    };

    let selected_left = DerivedCtToken::conditional_select(&left, &right, Choice::FALSE);
    assert_eq!(selected_left.key, left.key);
    assert_eq!(selected_left.counter, left.counter);

    let selected_right = DerivedCtToken::conditional_select(&left, &right, Choice::TRUE);
    assert_eq!(selected_right.key, right.key);
    assert_eq!(selected_right.counter, right.counter);
}

#[test]
fn derive_ct_traits_support_tuple_structs_and_crate_path_override() {
    let tuple_left = DerivedCtTuple([1, 2], 3);
    let tuple_right = DerivedCtTuple([9, 8], 7);
    assert_eq!(tuple_left.ct_eq(&tuple_left).unwrap_u8(), 1);
    assert_eq!(tuple_left.ct_eq(&tuple_right).unwrap_u8(), 0);
    let selected = DerivedCtTuple::conditional_select(&tuple_left, &tuple_right, Choice::TRUE);
    assert_eq!(selected.0, [9, 8]);
    assert_eq!(selected.1, 7);

    let crate_path = DerivedCtCratePath { key: [1, 2, 3, 4] };
    assert_eq!(crate_path.ct_eq(&crate_path).unwrap_u8(), 1);
}

#[test]
fn derive_ct_traits_support_generic_fields() {
    let left = DerivedCtGeneric { inner: 1u32 };
    let right = DerivedCtGeneric { inner: 2u32 };

    assert_eq!(left.ct_eq(&left).unwrap_u8(), 1);
    assert_eq!(left.ct_eq(&right).unwrap_u8(), 0);
    assert_eq!(
        DerivedCtGeneric::conditional_select(&left, &right, Choice::TRUE).inner,
        2
    );
}
