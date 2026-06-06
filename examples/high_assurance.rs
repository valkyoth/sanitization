#[cfg(feature = "std")]
use sanitization::ExpiringSecretBytes;
#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
use sanitization::GuardedSecretVec;
#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use sanitization::LockedSecretBytes;
#[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
use sanitization::{cache_flush::cache_flush_sanitize_bytes, SecretBytes};

fn main() {
    #[cfg(feature = "std")]
    {
        let mut key =
            ExpiringSecretBytes::<32>::from_array([7; 32], std::time::Duration::from_secs(300));
        assert_eq!(key.try_constant_time_eq(&[7; 32]), Ok(true));
        key.replace_from_array([8; 32]);
        key.try_replace_from_fn(|_| Ok::<u8, &'static str>(9))
            .unwrap();
        assert_eq!(key.try_constant_time_eq(&[9; 32]), Ok(true));
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let mut key = LockedSecretBytes::<32>::from_fn(|_| 9).unwrap();
        assert!(key.constant_time_eq(&[9; 32]));
        key.replace_from_array([8; 32]).unwrap();
        key.try_replace_from_fn(|_| Ok::<u8, &'static str>(7))
            .unwrap();
        assert!(key.constant_time_eq(&[7; 32]));
        key.into_cleared();
    }

    #[cfg(all(feature = "cache-flush", target_arch = "x86_64", not(miri)))]
    {
        let mut scratch = [0xA5; 32];
        cache_flush_sanitize_bytes(&mut scratch);
        assert_eq!(scratch, [0; 32]);

        let mut key = SecretBytes::<32>::from_array([1; 32]);
        key.secure_clear_and_flush();
        assert!(key.constant_time_eq(&[0; 32]));
    }

    #[cfg(all(
        feature = "guard-pages",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    {
        let mut token = GuardedSecretVec::from_slice(b"session-key").unwrap();
        token.extend_from_slice(b"-v2").unwrap();
        assert_eq!(token.with_secret(|bytes| bytes.len()), 14);
        token
            .replace_from_fn(11, |index| b"session-key"[index])
            .unwrap();
        token
            .try_replace_from_fn(12, |index| Ok::<u8, &'static str>(b"session-key!"[index]))
            .unwrap();
        assert!(token.constant_time_eq(b"session-key!"));
        token.into_cleared();
    }

    #[cfg(all(
        feature = "guard-pages",
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    {
        let mut token =
            GuardedSecretVec::locked_from_fn(11, |index| b"session-key"[index]).unwrap();
        assert!(token.is_memory_locked());
        assert!(token.constant_time_eq(b"session-key"));
        token
            .try_replace_from_fn(12, |index| Ok::<u8, &'static str>(b"session-key!"[index]))
            .unwrap();
        assert!(token.is_memory_locked());
        assert!(token.constant_time_eq(b"session-key!"));
    }
}
