use sanitization::{
    SecretBytes, SecureSanitize, StableMutableSecretStorage, StableSharedSecretStorage,
};

struct FixedCredentials {
    key: SecretBytes<32>,
    nonce: [u8; 12],
}

impl SecureSanitize for FixedCredentials {
    fn secure_sanitize(&mut self) {
        self.key.secure_sanitize();
        self.nonce.secure_sanitize();
    }
}

// STORAGE CONTRACT: all secret storage is inline and fixed-size. Shared methods
// only inspect fields; mutable methods overwrite fields in place.
impl StableSharedSecretStorage for FixedCredentials {}
impl StableMutableSecretStorage for FixedCredentials {}

fn require_stable_storage<T: StableMutableSecretStorage>(value: &mut T) {
    value.secure_sanitize();
}

fn main() {
    let mut credentials = FixedCredentials {
        key: SecretBytes::from_array([7; 32]),
        nonce: [9; 12],
    };

    require_stable_storage(&mut credentials);
}
