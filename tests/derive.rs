#![cfg(feature = "derive")]

use core::marker::PhantomData;
use sanitization::{SecretBytes, SecureSanitize, SecureSanitizeOnDrop};

#[allow(dead_code)]
struct NotSanitizable;

#[derive(SecureSanitize)]
struct DerivedCredentials {
    key: SecretBytes<4>,
    token: [u8; 4],
}

#[derive(SecureSanitize)]
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
    key: SecretBytes<4>,
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
    {
        let secret = DropSecret {
            key: SecretBytes::from_array([1, 2, 3, 4]),
        };
        assert!(secret.key.constant_time_eq(&[1, 2, 3, 4]));
    }
}
