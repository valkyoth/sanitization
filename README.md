# sanitization

Dependency-free `no_std` secret memory sanitization for Rust.

Default builds use `#![forbid(unsafe_code)]`. The intended path is to store new
fixed-size secrets in `SecretBytes<N>` from creation, avoiding accidental
`Copy`, `Clone`, slice exposure, and secret-printing `Debug`.

With the `alloc` feature, dynamic heap secrets are available through
`SecretVec` and `SecretString`. These types wipe on drop and expose contents
through closure-based APIs.

For integration boundaries that must wipe ordinary buffers, enable the explicit
unsafe-backed feature:

```bash
cargo test --features unsafe-wipe
```

Then call APIs under `sanitization::unsafe_wipe`, such as
`unsafe_wipe::volatile_sanitize_bytes(&mut bytes)`. Enabling the feature does
not change the default `SecureSanitize` implementation for ordinary `[u8]`;
call sites must opt into the volatile backend by name.

## Examples

```rust
use sanitization::SecretBytes;

let key = SecretBytes::<32>::from_fn(|index| index as u8);
let ok = key.expose_secret(|bytes| bytes.len() == 32);
assert!(ok);
```

```rust
#[cfg(feature = "alloc")]
use sanitization::SecretVec;

#[cfg(feature = "alloc")]
let token = SecretVec::from_slice(b"bearer-token");
```

```rust
#[cfg(feature = "unsafe-wipe")]
{
    let mut bytes = [0xA5; 32];
    sanitization::unsafe_wipe::volatile_sanitize_bytes(&mut bytes);
}
```

For custom structs, use the dependency-free declarative macros:

```rust
use sanitization::{secure_drop_struct, SecretBytes};

secure_drop_struct! {
    struct SessionCredentials {
        private_key: SecretBytes<32>,
        nonce: SecretBytes<12>,
    }
}
```

Use `secure_sanitize_struct!` instead when you need to provide your own `Drop`
implementation.

## Feature Matrix

- `default`: `no_std`, no external dependencies, no unsafe code.
- `alloc`: adds `SecretVec` and `SecretString`.
- `std`: currently aliases `alloc` for downstream convenience.
- `unsafe-wipe`: exposes the explicit volatile-write backend.

## Checks

Run the local matrix before changing release-sensitive code:

```bash
bash scripts/checks.sh
```

See `THREAT_MODEL.md` and `SAFETY.md` before extending the unsafe backend.

## Limits

- Safe Rust cannot volatile-wipe arbitrary existing memory.
- Safe Rust cannot soundly scrub old stack frames from previous moves.
- CPU cache flushes, SIMD clearing, platform memory locking, and inline
  assembly require more target-specific unsafe code and are intentionally not
  part of the default API.
