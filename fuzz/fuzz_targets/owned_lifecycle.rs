#![no_main]

use libfuzzer_sys::fuzz_target;
use sanitization::{
    secure_replace, BoundedSecretVec, SecretBytes, SecretString, SecretVec, SecureSanitize,
};

#[derive(SecureSanitize)]
#[sanitization(enum_inactive_variant_bytes = "acknowledged")]
enum State {
    Bytes(SecretBytes<32>),
    Dynamic(SecretVec),
    Empty,
}

fuzz_target!(|data: &[u8]| {
    let mut secret = SecretVec::default();
    for chunk in data.chunks(17) {
        secret.extend_from_slice(chunk);
    }
    secret.replace_from_slice(data);

    let mut text = SecretString::default();
    let decoded = String::from_utf8_lossy(data);
    text.push_str(&decoded);
    text.replace_from_secret_str(&decoded);

    let _ = BoundedSecretVec::<256>::from_slice(data);
    let _ = serde_json::from_slice::<BoundedSecretVec<256>>(data);

    let mut fixed = [0_u8; 32];
    let copied = data.len().min(fixed.len());
    fixed[..copied].copy_from_slice(&data[..copied]);
    let mut state = State::Bytes(SecretBytes::from_array(fixed));
    secure_replace(&mut state, State::Dynamic(SecretVec::from_slice(data)));
    secure_replace(&mut state, State::Empty);
    state.secure_sanitize();
});
