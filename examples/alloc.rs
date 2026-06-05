#[cfg(feature = "alloc")]
use sanitization::{SecretString, SecretVec};

fn main() {
    #[cfg(feature = "alloc")]
    {
        let mut token = SecretString::with_capacity(32);
        token.push_str("bearer-token");
        assert_eq!(token.try_with_secret(str::len), Ok(12));

        let mut bytes = SecretVec::with_capacity(16);
        bytes.extend_from_slice(b"secret");
        assert_eq!(bytes.with_secret(|value| value.len()), 6);
    }
}
