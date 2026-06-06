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
Every crate clearing path uses volatile writes by default through one audited
internal unsafe boundary.

## Current Status

The crate is published as a release candidate on crates.io. The current
candidate is intended for downstream integration testing before the stable
`1.0.0` release.

Implemented now:

- `no_std` default build.
- zero runtime dependencies.
- one audited internal unsafe boundary for volatile clearing.
- `SecretBytes<N>` for fixed-size secrets.
- `Secret<T>` for custom sanitizable values.
- `secure_sanitize_struct!` and `secure_drop_struct!` helper macros.
- optional `alloc` support with `SecretVec` and `SecretString`.
- optional Linux memory locking and core-dump exclusion with
  `LockedSecretBytes<N>`.
- optional x86_64 assembly-backed equal-length comparison.
- optional x86_64 volatile-clear plus cache-line eviction helpers.
- optional `std` lifetime enforcement with `ExpiringSecretBytes<N>`.
- optional Linux guard-page dynamic byte storage with `GuardedSecretVec`.
- explicit volatile helper APIs for existing ordinary buffers.
- redacted `Debug` for secret-owning wrapper types.
- clear-on-drop behavior for crate-owned secret containers.
- local CI/check script and GitHub workflows.
- optional bounded Kani proof harnesses for core fixed-size properties.
- threat model and unsafe-boundary documentation.

## Trust Dashboard

| Area | Status |
| --- | --- |
| License | `MIT OR Apache-2.0` |
| MSRV | Rust `1.90.0` |
| Default target | `no_std` |
| Runtime dependencies | zero external crates |
| Unsafe policy | `#![deny(unsafe_code)]` at crate root, one audited wipe module |
| Clear primitive | volatile writes by default |
| Heap support | `alloc` feature |
| Proc macros | none |
| Formal verification | optional bounded Kani harnesses for core properties |
| Main guarantee | narrow ownership, redaction, and clear-on-drop hygiene |
| Out of scope | stack-history wiping, global cache secrecy, crash dumps, privileged reads |

Read [THREAT_MODEL.md](THREAT_MODEL.md) and [SAFETY.md](SAFETY.md) before
using this crate for high-assurance secret handling.

Read [ROADMAP.md](ROADMAP.md) for the pre-`1.0.0` architecture plan and the
remaining high-assurance feature work.

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
sanitization = "1.0.0-rc.5"
```

For heap-backed secret containers:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.5", features = ["alloc"] }
```

The `unsafe-wipe` feature is kept as a no-op compatibility flag for older
release-candidate dependency declarations. Volatile clearing is now the default.

For Linux memory-locked fixed-size secrets on supported architectures:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.5", features = ["memory-lock"] }
```

## Features

| Feature | Default | Purpose |
| --- | --- | --- |
| `alloc` | no | Enables `SecretVec` and `SecretString`. |
| `std` | no | Enables `alloc` plus `ExpiringSecretBytes<N>` lifetime enforcement. |
| `memory-lock` | no | Enables Linux `LockedSecretBytes<N>` and locked guarded mappings on `x86_64` and `aarch64`. |
| `asm-compare` | no | Uses an x86_64 inline-assembly loop for equal-length byte comparison. |
| `cache-flush` | no | Enables explicit x86_64 clear-and-cache-line-evict helpers. |
| `guard-pages` | no | Enables Linux `GuardedSecretVec` on `x86_64` and `aarch64`. |
| `unsafe-wipe` | no | Compatibility no-op; volatile wiping is default. |

Default builds are dependency-free and `no_std`.

## Fixed-Size Secrets

Use `SecretBytes<N>` for keys, tokens, nonces, salts, or other fixed-size
secret byte arrays that you control from creation.

```rust
use sanitization::SecretBytes;

let key = SecretBytes::<32>::from_fn(|index| index as u8);
let fallible_key =
    SecretBytes::<32>::try_from_fn(|index| Ok::<u8, &'static str>(index as u8)).unwrap();

assert_eq!(key.len(), 32);
assert_eq!(fallible_key.len(), 32);
assert!(key.constant_time_eq(&[
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31,
]));
```

The type intentionally does not implement `Clone`, `Copy`, `Deref`,
`AsRef<[u8]>`, or secret-printing `Debug`.

## Expiring Secrets

Enable `std` when fixed-size secrets should reject access after a configured
maximum age:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.5", features = ["std"] }
```

```rust
use sanitization::ExpiringSecretBytes;
use std::time::Duration;

let mut key = ExpiringSecretBytes::<32>::from_array([7; 32], Duration::from_secs(300));

assert_eq!(key.try_constant_time_eq(&[7; 32]), Ok(true));

key.try_expose_secret(|bytes| {
    assert_eq!(bytes.len(), 32);
}).unwrap();
```

There is no background timer. Expiration is checked when a fallible access
method is called. If the value has expired, the wrapped secret is cleared before
returning `SecretExpiredError`. Full replacement with `replace_from_slice`
restarts the lifetime window for the new value.

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

`expose_secret_volatile` is an explicit alias for callers that want the
volatile-clearing behavior visible at the call site. Like `expose_secret`, it
cannot clear the temporary stack copy if the process aborts.

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
token.replace_from_secret_str("rotated-token");

let mut bytes = SecretVec::from_slice(b"session-key");
assert_eq!(bytes.with_secret(|value| value.len()), 11);
assert!(bytes.constant_time_eq(b"session-key"));

bytes.with_secret_mut(|value| value[0] = b'S');
bytes.replace_from_slice(b"rotated-session-key");
bytes.replace_from_fn(16, |index| index as u8);
bytes
    .try_replace_from_fn(16, |index| Ok::<u8, &'static str>(index as u8))
    .unwrap();
```

`SecretVec` and `SecretString` wipe initialized bytes and spare heap capacity
before freeing their allocations. Use `replace_from_slice` and
`replace_from_secret_str` when rotating entire dynamic values. Use
`SecretVec::from_fn`, `try_from_fn`, `replace_from_fn`, or
`try_replace_from_fn` when dynamic bytes can be generated directly into
clear-on-drop storage. Fallible generation clears partial output on error. They
expose contents through closures and redact `Debug`.

## Memory-Locked Secrets

Enable `memory-lock` on Linux `x86_64` or `aarch64` for fixed-size secrets
stored in a private anonymous mapping excluded from ordinary Linux core dumps
and fork inheritance, then locked with `mlock`.

```rust
use sanitization::LockedSecretBytes;

let mut key = LockedSecretBytes::<32>::from_fn(|_| 7).unwrap();
let fallible_key =
    LockedSecretBytes::<32>::try_from_fn(|_| Ok::<u8, &'static str>(7)).unwrap();

assert!(key.constant_time_eq(&[7; 32]));
assert!(fallible_key.constant_time_eq(&[7; 32]));

key.with_secret(|bytes| {
    assert_eq!(bytes.len(), 32);
});

key.secure_clear();
assert!(key.constant_time_eq(&[0; 32]));
```

`LockedSecretBytes<N>` does not use the Rust global allocator for the secret
bytes. It creates a private Linux mapping with `mmap`, marks that mapping with
`MADV_DONTDUMP` and `MADV_DONTFORK`, locks it with `mlock`, volatile-clears the
full mapping on drop, then calls `munlock` and `munmap`.
Use `from_fn` when bytes can be generated directly into locked storage. Use
`try_from_fn` for fallible generators such as RNG or KDF APIs. Use `from_slice`
when loading bytes from an existing runtime buffer. `from_array` is still
available for fixed arrays and clears its owned input array before returning.

This feature is explicit because OS memory locking has platform limits. It can
fail due to resource limits or policy. `MADV_DONTDUMP` reduces ordinary Linux
core-dump exposure and `MADV_DONTFORK` reduces accidental fork inheritance for
the mapping, but they do not protect against all crash dump mechanisms,
hibernation, debuggers, privileged process reads, DMA, malicious firmware, or
copies made before data enters the locked container.

## Guarded Heap Secrets

Enable `guard-pages` on Linux `x86_64` or `aarch64` for dynamic byte secrets
stored between inaccessible guard pages:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.5", features = ["guard-pages"] }
```

```rust
use sanitization::GuardedSecretVec;

let mut token = GuardedSecretVec::from_slice(b"session-key").unwrap();
let generated = GuardedSecretVec::try_from_fn(11, |index| {
    Ok::<u8, &'static str>(b"session-key"[index])
})
.unwrap();

assert!(token.constant_time_eq(b"session-key"));
assert!(generated.constant_time_eq(b"session-key"));
token.extend_from_slice(b"-v2").unwrap();
assert_eq!(token.with_secret(|bytes| bytes.len()), 14);
token.replace_from_slice(b"rotated-session-key").unwrap();

token.clear_secret();
assert!(token.is_empty());
```

`GuardedSecretVec` uses a private Linux mapping, leaves the pages before and
after the writable data region inaccessible, volatile-clears the full writable
region on drop, and then unmaps the allocation. It does not use the Rust global
allocator for the secret bytes. Use `GuardedSecretVec::from_fn` when bytes can
be generated directly into the guarded mapping; use `try_from_fn` for fallible
generators. Use `from_slice` when loading bytes from an existing runtime buffer.
Use `replace_from_slice` when rotating or replacing the entire guarded value.
Guarded mappings use a 4 KiB page granule on `x86_64` and a conservative 64 KiB
granule on `aarch64` to support 4 KiB, 16 KiB, and 64 KiB Linux kernels without
a libc dependency.

When both `guard-pages` and `memory-lock` are enabled, guarded dynamic secrets
can also mark their writable data pages with `MADV_DONTDUMP` and
`MADV_DONTFORK`, then lock those pages with `mlock`:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.5", features = ["guard-pages", "memory-lock"] }
```

```rust
use sanitization::GuardedSecretVec;

let token = GuardedSecretVec::locked_from_slice(b"session-key").unwrap();

assert!(token.is_memory_locked());
assert!(token.constant_time_eq(b"session-key"));
```

Locked guarded mappings preserve the lock state when they grow. Guard pages are
not dump-excluded or locked because they never contain secret bytes. Core-dump
exclusion, fork-inheritance exclusion, and locking can fail due to OS resource
limits or policy, and this does not change the broader memory-lock limits
described above. `GuardedSecretVec::locked_from_fn` is available for direct byte
generation after the writable data pages are dump-excluded, fork-excluded, and
locked. Use `locked_try_from_fn` for fallible generation into locked guarded
storage.

Guard pages are a fault-detection mechanism for crossing outside the mapped
data pages. They do not catch logical overreads that stay inside the writable
data capacity, and they do not protect external copies made before data enters
the guarded container.

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

If a secret already lives in an ordinary buffer, call the volatile helper
directly.

```rust
use sanitization::unsafe_wipe::volatile_sanitize_bytes;

let mut bytes = [0xA5; 32];
volatile_sanitize_bytes(&mut bytes);
assert_eq!(bytes, [0; 32]);
```

With `alloc`, `Vec<u8>` and `String` helpers are available:

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

## Cache Flush Sanitization

Enable `cache-flush` on x86_64 when a call site explicitly needs volatile
clearing followed by `clflush`/`mfence` over the affected cache lines:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.5", features = ["cache-flush"] }
```

```rust
use sanitization::{cache_flush::cache_flush_sanitize_bytes, SecretBytes};

let mut scratch = [0xA5; 32];
cache_flush_sanitize_bytes(&mut scratch);
assert_eq!(scratch, [0; 32]);

let mut key = SecretBytes::<32>::from_array([7; 32]);
key.secure_clear_and_flush();
assert!(key.constant_time_eq(&[0; 32]));
```

With `alloc`, `cache_flush_sanitize_vec` and `cache_flush_sanitize_string`
clear the full allocation capacity before flushing the allocation's cache
lines. With both `guard-pages` and `cache-flush`, `GuardedSecretVec` also
provides `clear_secret_and_flush` for its full writable data region. Unsupported
targets, Miri, and builds without `cache-flush` do not expose the `cache_flush`
module.

## Assembly Comparison

Enable `asm-compare` on x86_64 when you want equal-length secret comparisons to
cross an explicit compiler boundary:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.5", features = ["asm-compare"] }
```

The public API does not change. `SecretBytes<N>`, `SecretVec`, `SecretString`,
and `LockedSecretBytes<N>` still use their normal `constant_time_eq` methods.
Length mismatch remains public metadata and returns immediately. Unsupported
targets, Miri, and builds without `asm-compare` use the portable Rust fallback.

## Choosing the Right API

| Use case | Recommended API |
| --- | --- |
| Fixed-size key or token | `SecretBytes<N>` |
| Fixed-size key with access expiry | `ExpiringSecretBytes<N>` with `std` |
| Fixed-size key that should avoid swap on supported Linux | `LockedSecretBytes<N>` with `memory-lock` |
| Dynamic secret bytes | `SecretVec` with `alloc` |
| Dynamic bytes with Linux guard pages | `GuardedSecretVec` with `guard-pages` |
| Secret UTF-8 text | `SecretString` with `alloc` |
| Custom struct, macro-owned drop | `secure_drop_struct!` |
| Custom struct, custom drop | `secure_sanitize_struct!` |
| Existing ordinary buffer | `unsafe_wipe::volatile_sanitize_*` |
| Generic clear-on-drop wrapper | `Secret<T>` |
| Explicit x86_64 comparison compiler boundary | `asm-compare` feature |
| Explicit x86_64 cache-line eviction after clearing | `cache-flush` feature |

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

The check script covers formatting, feature-matrix tests, examples, clippy,
release LLVM IR/assembly verification, optional bounded Kani verification when
`cargo-kani` is installed, docs with warnings denied, and package listing.

When a nightly toolchain with Miri is available, run the interpreter-based
unsafe-boundary check separately:

```bash
scripts/verify-miri.sh
```

To run the bounded formal harnesses directly:

```bash
scripts/verify-kani.sh
```

These harnesses prove selected fixed-size properties for the volatile clearing
path, secret clearing visibility, constant-time equality correctness, and
capacity arithmetic. They are not a replacement for external review.

## Limits

This crate reduces accidental retention and accidental exposure. It does not
provide complete process-memory secrecy.

Important limits:

- Volatile wiping requires the crate's internal unsafe boundary; safe Rust alone
  cannot express volatile byte stores.
- Safe Rust cannot soundly scrub old stack frames from previous moves.
- `panic = "abort"` prevents destructors from running and prevents closure
  helpers from clearing temporary stack copies after a panic.
- Volatile writes prevent the intended clear operation from being optimized away,
  but cannot clear copies made elsewhere before data enters the container.
- CPU cache flushes, SIMD clearing, platform memory locking, guard pages, and
  inline assembly require target-specific unsafe code and are intentionally not
  part of the default API.
- It does not protect against swap, hibernation, core dumps, debugger access,
  `/proc/<pid>/mem`, kernel compromise, DMA, firmware compromise, or copies made
  by third-party libraries.

See [THREAT_MODEL.md](THREAT_MODEL.md), [SAFETY.md](SAFETY.md), and
[SECURITY.md](SECURITY.md) for the security model and maintenance policy.
