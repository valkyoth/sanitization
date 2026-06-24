# sanitization-crypto-interop

Optional crypto crate integration helpers for
[`sanitization`](https://crates.io/crates/sanitization).

This crate exists for projects migrating from direct `zeroize` usage to
`sanitization` while still depending on third-party hash implementations whose
internal state is only clearable through those crates' own `zeroize` features.

The core `sanitization` crate remains dependency-free by default. This sister
crate is explicitly opt-in and feature-gated per backend.
The optional `std` feature only adds standard error trait integration and
forwards to `sanitization/std`; it is disabled by default.

```toml
[dependencies]
sanitization-crypto-interop = { version = "1.2.2", features = ["sha2", "blake3"] }
```

## SHA-2

The `sha2` feature enables `sha2`'s own `zeroize` support so hasher state is
cleared by the upstream implementation when the hasher is dropped.
The incremental wrapper types also implement `sanitization::SecureSanitize`.

The digest helper functions return ordinary arrays. If a digest is sensitive,
clear it after use with `sanitization::sanitize_bytes` or move it directly into
a `sanitization` secret container.

```rust
use sanitization_crypto_interop::sha2::sha512_digest;

let digest = sha512_digest(b"input");
```

## BLAKE3

The `blake3` feature enables `blake3`'s own `zeroize` support and explicitly
clears both the `Hasher` and XOF `OutputReader` after digest extraction.
The incremental wrapper type also implements `sanitization::SecureSanitize`.

```rust
use sanitization_crypto_interop::blake3::blake3_xof_64;

let digest = blake3_xof_64(b"input");
```

Keyed BLAKE3 helpers are also available:

```rust
use sanitization_crypto_interop::blake3::blake3_keyed_xof_64;

let key = [7u8; 32];
let digest = blake3_keyed_xof_64(&key, b"input");
```

The caller remains responsible for clearing key material stored outside a
`sanitization` secret container.

## HMAC-SHA2

The `hmac-sha2` feature enables HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512
helpers built directly on SHA-2 with explicit sanitization of key-block, pad,
and inner-digest scratch buffers.
Prefer these helpers over manually building keyed SHA-2 by hashing
`key || message`.

```toml
[dependencies]
sanitization-crypto-interop = { version = "1.2.2", features = ["hmac-sha2"] }
```

```rust
use sanitization_crypto_interop::hmac_sha2::hmac_sha256;

let tag = hmac_sha256(b"key", b"message");
```

Like digest helpers, returned tags are ordinary arrays and remain the caller's
responsibility to clear if treated as sensitive.
The caller also remains responsible for clearing HMAC key bytes held outside a
`sanitization` secret container.

## HKDF

HKDF helpers are intentionally not exposed yet. The current upstream `hkdf`
crate stores PRK/HMAC state internally, and this crate will only wrap it after
the cleanup path can be made explicit and tested the same way as the SHA-2,
BLAKE3, and HMAC helpers.

## Scope

This crate does not implement clearing for arbitrary opaque crypto types. It
only wraps third-party crates that expose their own clearing hooks or provides
purpose-built helpers where scratch buffers are owned and cleared locally. If a
crypto crate does not expose a zeroization API or feature, this crate cannot
safely clear that crate's private internal buffers.
