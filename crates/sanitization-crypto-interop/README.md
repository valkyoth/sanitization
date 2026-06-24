# sanitization-crypto-interop

Optional crypto crate integration helpers for
[`sanitization`](https://crates.io/crates/sanitization).

This crate exists for projects migrating from direct `zeroize` usage to
`sanitization` while still depending on third-party hash implementations whose
internal state is only clearable through those crates' own `zeroize` features.

The core `sanitization` crate remains dependency-free by default. This sister
crate is explicitly opt-in and feature-gated per backend.

```toml
[dependencies]
sanitization-crypto-interop = { version = "1.2.2", features = ["sha2", "blake3"] }
```

## SHA-2

The `sha2` feature enables `sha2`'s own `zeroize` support so hasher state is
cleared by the upstream implementation when the hasher is dropped.
The incremental wrapper types also implement `sanitization::SecureSanitize`.

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

## Scope

This crate does not implement clearing for arbitrary opaque crypto types. It
only wraps third-party crates that expose their own clearing hooks. If a crypto
crate does not expose a zeroization API or feature, this crate cannot safely
clear that crate's private internal buffers.
