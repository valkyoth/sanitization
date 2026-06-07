use sanitization::unsafe_wipe::{volatile_sanitize_bytes, VolatileOnDrop};

fn main() {
    let mut bytes = [0xA5; 32];
    volatile_sanitize_bytes(&mut bytes);
    assert_eq!(bytes, [0; 32]);

    let secret = VolatileOnDrop::new([1_u8, 2, 3, 4]);
    assert_eq!(secret.with_secret(|bytes| bytes.len()), 4);
}
