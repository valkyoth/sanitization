<p align="center">
  <b>Dependency-free, no_std-first secret memory sanitization for Rust.</b><br>
  Redacted secret containers, safe defaults, explicit volatile wiping, and no proc-macro dependency.
</p>

<div align="center">
  <a href="https://docs.rs/sanitization">Docs.rs</a>
  |
  <a href="THREAT_MODEL.md">Threat Model</a>
  |
  <a href="SAFETY.md">Safety</a>
  |
  <a href="SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/sanitization-rust-crate">
    <img src="https://raw.githubusercontent.com/valkyoth/sanitization-rust-crate/main/.github/images/sanitization.webp" alt="sanitization Rust crate overview">
  </a>
</p>

# sanitization

Dependency-free, `no_std`-first secret memory sanitization for Rust.

`sanitization` is for projects that want a small secret-container layer without
pulling in `zeroize` or a proc-macro dependency by default. The main design is
architectural: keep secrets inside redacted, non-`Copy`, non-`Clone`,
clear-on-drop containers from creation, and use explicit opt-in APIs when an
ordinary buffer must be wiped.

## Current Status

The crate is published as a release candidate on crates.io. The current
candidate is intended for downstream integration testing before the stable
`1.0.0` release.

Implemented now:

- `no_std` default build.
- zero runtime dependencies.
- no unsafe code in default builds.
- `SecretBytes<N>` for fixed-size secrets.
- `Secret<T>` for custom sanitizable values.
- `secure_sanitize_struct!` and `secure_drop_struct!` helper macros.
- optional `alloc` support with `SecretVec` and `SecretString`.
- optional `unsafe-wipe` volatile backend for existing ordinary buffers.
- redacted `Debug` for secret-owning wrapper types.
- clear-on-drop behavior for crate-owned secret containers.
- local CI/check script and GitHub workflow.
- threat model and unsafe-boundary documentation.

## Trust Dashboard

| Area | Status |
| --- | --- |
| License | `MIT OR Apache-2.0` |
| MSRV | Rust `1.90.0` |
| Default target | `no_std` |
| Runtime dependencies | zero external crates |
| Default unsafe policy | `#![forbid(unsafe_code)]` |
| Optional unsafe | only behind `unsafe-wipe`, isolated in `unsafe_wipe` |
| Heap support | `alloc` feature |
| Proc macros | none |
| Main guarantee | narrow ownership, redaction, and clear-on-drop hygiene |
| Out of scope | stack-history wiping, cache flushing, OS memory locking, dumps/swap |

Read [THREAT_MODEL.md](THREAT_MODEL.md) and [SAFETY.md](SAFETY.md) before
using this crate for high-assurance secret handling.

## Rust Version Support

The minimum supported Rust version is Rust `1.90.0`. New deployments should
prefer the latest stable Rust.

Compatibility evidence:

| Rust | Local Evidence |
| --- | --- |
| `1.90.0` | full check gate |
| `1.91.0` | `cargo check --all-features` |
| `1.92.0` | `cargo check --all-features` |
| `1.93.0` | `cargo check --all-features` |
| `1.94.0` | `cargo check --all-features` |
| `1.95.0` | `cargo check --all-features` |
| `1.96.0` | `cargo check --all-features` |

## Install

```toml
[dependencies]
sanitization = "1.0.0-rc.4"
```

For heap-backed secret containers:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.4", features = ["alloc"] }
```

For explicit volatile wiping of ordinary buffers:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.4", features = ["unsafe-wipe"] }
```

For heap containers plus volatile wiping:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.4", features = ["alloc", "unsafe-wipe"] }
```

## Features

| Feature | Default | Purpose |
| --- | --- | --- |
| `alloc` | no | Enables `SecretVec` and `SecretString`. |
| `std` | no | Currently aliases `alloc` for downstream convenience. |
| `unsafe-wipe` | no | Enables explicit volatile wiping APIs for ordinary buffers. |

Default builds are dependency-free, `no_std`, and forbid unsafe code.

## Fixed-Size Secrets

Use `SecretBytes<N>` for keys, tokens, nonces, salts, or other fixed-size
secret byte arrays that you control from creation.

```rust
use sanitization::SecretBytes;

let key = SecretBytes::<32>::from_fn(|index| index as u8);

assert_eq!(key.len(), 32);
assert!(key.constant_time_eq(&[
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31,
]));
```

The type intentionally does not implement `Clone`, `Copy`, `Deref`,
`AsRef<[u8]>`, or secret-printing `Debug`.

## Copying Secrets Into External APIs

Some cryptographic or protocol APIs require `&[u8]`. Use `expose_secret` for
short-lived closure access. The temporary copy is cleared on the normal return
path and during unwinding, but cannot be cleared if the process aborts.

```rust
use sanitization::SecretBytes;

let key = SecretBytes::<32>::from_array([7; 32]);

let first_byte = key.expose_secret(|bytes| {
    // Call the external API here.
    bytes[0]
});

assert_eq!(first_byte, 7);
```

With `unsafe-wipe`, `expose_secret_volatile` uses volatile writes for the
temporary stack copy on normal return and unwinding paths. It still cannot clear
the copy if the process aborts.

```rust
use sanitization::SecretBytes;

let key = SecretBytes::<32>::from_array([7; 32]);
let first_byte = key.expose_secret_volatile(|bytes| bytes[0]);

assert_eq!(first_byte, 7);
```

## Updating and Clearing Fixed-Size Secrets

Multi-byte mutation and clearing require `&mut self`, so shared references
cannot observe partially-cleared multi-byte writes.

```rust
use sanitization::SecretBytes;

let mut key = SecretBytes::<32>::zeroed();

key.copy_from_slice(&[9; 32]).unwrap();
assert!(key.constant_time_eq(&[9; 32]));

key.write_byte(0, 1).unwrap();
assert_eq!(key.read_byte(0), Some(1));

key.secure_clear();
assert!(key.constant_time_eq(&[0; 32]));
```

## Heap Secrets

Enable `alloc` for dynamic secret bytes and secret UTF-8 text.

```rust
use sanitization::{SecretString, SecretVec};

let mut token = SecretString::from_secret_str("bearer-token");
assert_eq!(token.try_with_secret(str::len), Ok(12));
assert!(token.constant_time_eq("bearer-token"));

token.push_str("-v2");
assert_eq!(token.try_with_secret(|text| text.ends_with("-v2")), Ok(true));

let mut bytes = SecretVec::from_slice(b"session-key");
assert_eq!(bytes.with_secret(|value| value.len()), 11);
assert!(bytes.constant_time_eq(b"session-key"));

bytes.with_secret_mut(|value| value[0] = b'S');
```

`SecretVec` and `SecretString` wipe initialized bytes and spare heap capacity
before freeing their allocations. They expose contents through closures and
redact `Debug`.

## Custom Structs Without Proc Macros

Use `secure_drop_struct!` when the macro should own `Drop` and clear every
field on drop:

```rust
use sanitization::{secure_drop_struct, SecretBytes};

secure_drop_struct! {
    struct SessionCredentials {
        private_key: SecretBytes<32>,
        nonce: SecretBytes<12>,
    }
}

let credentials = SessionCredentials {
    private_key: SecretBytes::from_array([1; 32]),
    nonce: SecretBytes::from_array([2; 12]),
};

assert!(credentials.private_key.constant_time_eq(&[1; 32]));
```

Use `secure_sanitize_struct!` when you need to write a custom `Drop`
implementation yourself:

```rust
use sanitization::{secure_sanitize_struct, SecretBytes, SecureSanitize};

secure_sanitize_struct! {
    struct Credentials {
        private_key: SecretBytes<32>,
        nonce: SecretBytes<12>,
    }
}

let mut credentials = Credentials {
    private_key: SecretBytes::from_array([1; 32]),
    nonce: SecretBytes::from_array([2; 12]),
};

credentials.secure_sanitize();
```

These macros are declarative `macro_rules!` macros. They do not require `syn`,
`quote`, `proc-macro2`, or any compile-time code-generation dependency.

## Generic Secret Wrapper

Use `Secret<T>` when you already have a type that implements `SecureSanitize`
and you want clear-on-drop plus redacted `Debug`.

```rust
use sanitization::{Secret, SecureSanitize};

struct Pair {
    left: [u8; 16],
    right: [u8; 16],
}

impl SecureSanitize for Pair {
    fn secure_sanitize(&mut self) {
        self.left.secure_sanitize();
        self.right.secure_sanitize();
    }
}

let mut pair = Secret::new(Pair {
    left: [1; 16],
    right: [2; 16],
});

pair.with_secret_mut(|value| value.left[0] = 9);
```

## Explicit Volatile Wiping

Safe Rust cannot volatile-wipe arbitrary existing memory. If a secret already
lives in an ordinary buffer, enable `unsafe-wipe` and call the volatile backend
explicitly.

```rust
use sanitization::unsafe_wipe::volatile_sanitize_bytes;

let mut bytes = [0xA5; 32];
volatile_sanitize_bytes(&mut bytes);
assert_eq!(bytes, [0; 32]);
```

With `alloc` and `unsafe-wipe`, `Vec<u8>` and `String` helpers are available:

```rust
use sanitization::unsafe_wipe::{volatile_sanitize_string, volatile_sanitize_vec};

let mut bytes = vec![0xBB; 16];
volatile_sanitize_vec(&mut bytes);
assert!(bytes.is_empty());

let mut token = String::from("secret-token");
volatile_sanitize_string(&mut token);
assert!(token.is_empty());
```

For clear-on-drop volatile behavior, use `VolatileOnDrop`:

```rust
use sanitization::unsafe_wipe::VolatileOnDrop;

let secret = VolatileOnDrop::new([1_u8, 2, 3, 4]);
assert_eq!(secret.with_secret(|bytes| bytes.len()), 4);
```

## Choosing the Right API

| Use case | Recommended API |
| --- | --- |
| Fixed-size key or token | `SecretBytes<N>` |
| Dynamic secret bytes | `SecretVec` with `alloc` |
| Secret UTF-8 text | `SecretString` with `alloc` |
| Custom struct, macro-owned drop | `secure_drop_struct!` |
| Custom struct, custom drop | `secure_sanitize_struct!` |
| Existing ordinary buffer | `unsafe_wipe::volatile_sanitize_*` |
| Generic clear-on-drop wrapper | `Secret<T>` |

## Relationship to `zeroize`

`zeroize` is broader and more ergonomic for retrofitting existing types,
especially with `#[derive(Zeroize, ZeroizeOnDrop)]`. This crate deliberately
does not ship a proc-macro derive in the core crate because that would add
compile-time dependencies and supply-chain surface.

The intended trade-off:

- use wrapper types from the start for stronger ownership discipline;
- use dependency-free declarative macros for custom structs;
- use explicit volatile APIs only where ordinary memory must be wiped.

## Local Checks

Run the local matrix before changing release-sensitive code:

```bash
bash scripts/checks.sh
```

The check script covers formatting, feature-matrix tests, examples, clippy, docs
with warnings denied, and package listing.

## Limits

This crate reduces accidental retention and accidental exposure. It does not
provide complete process-memory secrecy.

Important limits:

- Safe Rust cannot volatile-wipe arbitrary existing memory.
- Safe Rust cannot soundly scrub old stack frames from previous moves.
- `panic = "abort"` prevents destructors from running and prevents closure
  helpers from clearing temporary stack copies after a panic.
- Whole-program optimization and LTO can weaken best-effort safe cleanup. Use
  the explicit `unsafe-wipe` feature when optimizer-resistant clearing of
  ordinary memory is required.
- CPU cache flushes, SIMD clearing, platform memory locking, guard pages, and
  inline assembly require target-specific unsafe code and are intentionally not
  part of the default API.
- It does not protect against swap, hibernation, core dumps, debugger access,
  `/proc/<pid>/mem`, kernel compromise, DMA, firmware compromise, or copies made
  by third-party libraries.

See [THREAT_MODEL.md](THREAT_MODEL.md), [SAFETY.md](SAFETY.md), and
[SECURITY.md](SECURITY.md) for the security model and maintenance policy.
