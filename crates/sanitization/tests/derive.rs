#![cfg(feature = "derive")]

use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};
use sanitization::{secure_replace, SecretBytes, SecureSanitize, SecureSanitizeOnDrop};

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
