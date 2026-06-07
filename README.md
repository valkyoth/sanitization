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
- one audited internal unsafe boundary for default volatile clearing.
- explicit feature-gated unsafe modules for platform hardening, documented in
  `SAFETY.md`.
- `SecretBytes<N>` for fixed-size secrets.
- `Secret<T>` for custom sanitizable values.
- `secure_sanitize_struct!` and `secure_drop_struct!` helper macros.
- optional `alloc` support with `SecretVec` and `SecretString`.
- optional platform memory locking with `LockedSecretBytes<N>` on supported
  Linux, Android, macOS, iOS, Windows, and BSD targets.
- optional pooled locked-memory arenas with `SecretPool<N, SLOTS>` for many
  same-size fixed secrets under one memory-lock operation.
- optional locked, pooled, and guarded canary integrity checks with
  `canary-check`.
- optional OS-CSPRNG canary words with `random-canary`.
- optional x86_64 assembly-backed equal-length comparison.
- optional x86_64 volatile-clear plus cache-line eviction helpers.
- optional explicit multi-pass volatile clear helpers.
- no-`std` fixed-size lifetime enforcement with caller-provided monotonic
  clocks.
- optional `std` lifetime enforcement with `ExpiringSecretBytes<N>`.
- optional guard-page dynamic byte storage with `GuardedSecretVec` on supported
  Linux, Android, macOS, iOS, Windows, and BSD targets.
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
| Unsafe policy | `#![deny(unsafe_code)]` at crate root, isolated `#[allow(unsafe_code)]` modules documented in `SAFETY.md` |
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

For memory-locked fixed-size secrets on supported platforms:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.5", features = ["memory-lock"] }
```

## Features

| Feature | Default | Purpose |
| --- | --- | --- |
| `alloc` | no | Enables `SecretVec` and `SecretString`. |
| `std` | no | Enables `alloc` plus `ExpiringSecretBytes<N>` lifetime enforcement. |
| `memory-lock` | no | Enables `LockedSecretBytes<N>`, `SecretPool<N, SLOTS>`, and locked guarded mappings on supported native targets. On WASM this exposes a volatile-only compatibility backend with no actual memory locking. |
| `canary-check` | no | Enables `memory-lock` plus prefix/suffix canary checks for non-empty locked byte mappings, pooled slots, and guarded dynamic mappings. |
| `random-canary` | no | Enables `canary-check` and generates canary words from the OS CSPRNG instead of deriving them from mapping addresses. WASI preview1 uses `random_get`; other bare WASM targets report random generation failure. |
| `asm-compare` | no | Uses an x86_64 inline-assembly loop for equal-length byte comparison. |
| `cache-flush` | no | Enables explicit x86_64 clear-and-cache-line-evict helpers. |
| `guard-pages` | no | Enables `GuardedSecretVec` on supported Linux, Android, macOS, iOS, Windows, and BSD targets. This feature is rejected at compile time on WASM. |
| `multi-pass-clear` | no | Enables explicit three-pass volatile overwrite helpers for policy or audit compatibility. |
| `unsafe-wipe` | no | Compatibility no-op; volatile wiping is default. |

Default builds are dependency-free and `no_std`.

## WASM Support

The base containers (`SecretBytes`, `Secret`, `ReadOnceSecret`, and with
`alloc`, `SecretVec` and `SecretString`) compile on `wasm32` targets.
`memory-lock` also compiles on WASM as an API-compatible volatile-only backend:
`LockedSecretBytes<N>` and `SecretPool<N, SLOTS>` own storage inside WASM
linear memory and clear it on drop, but no `mlock`, `mmap`, `mprotect`,
`MADV_DONTDUMP`, or page locking is applied because WASM modules cannot call
those host-kernel facilities directly.

`guard-pages` is rejected at compile time on WASM. WASM linear memory has no
per-page protection API available to the module, so a guard-page-less
`GuardedSecretVec` would be misleading.

`random-canary` uses WASI preview1 `random_get` when targeting
`wasm32-wasip1`. Bare `wasm32-unknown-unknown`, Emscripten-style WASM, and
WASI preview2 currently return a `Random` operation error for random canary
setup in this dependency-free implementation.

One caveat matters for all WASM targets: Rust volatile writes survive LLVM
lowering to WASM, but the WASM specification has no volatile memory operation.
The crate uses an `#[inline(never)]` function-pointer boundary on WASM as a
best-effort barrier against runtime dead-store removal, but this is weaker than
native volatile semantics. Treat WASM clearing as best-effort unless your
runtime/deployment gives stronger guarantees, such as atomics/shared-memory
support and a runtime that preserves those stores as observable effects.

## Fixed-Size Secrets

Use `SecretBytes<N>` for keys, tokens, nonces, salts, or other fixed-size
secret byte arrays that you control from creation.

```rust
use sanitization::SecretBytes;

let mut key = SecretBytes::<32>::from_fn(|index| index as u8);
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

key.replace_from_fn(|index| 31 - index as u8);
key.try_replace_from_fn(|index| Ok::<u8, &'static str>(index as u8))
    .unwrap();
key.replace_from_array([9; 32]);

key.transform(|bytes| {
    for byte in bytes.iter_mut() {
        *byte ^= 0xA5;
    }
});

let subkey = key.derive::<16>(|input, output| {
    output.copy_from_slice(&input[..16]);
});
assert_eq!(subkey.len(), 16);

key.into_cleared();
```

The type intentionally does not implement `Clone`, `Copy`, `Deref`,
`AsRef<[u8]>`, or secret-printing `Debug`.
`SecretBytes<N>` stores `N` bytes inline, and `expose_secret` creates an
additional `N`-byte stack copy. On embedded targets or small thread stacks,
choose `N` well below the available stack budget or use heap-backed containers.
For key derivation, masking, or normalization logic that can operate inside the
container, prefer `transform`, `try_transform`, `derive`, or `try_derive` so the
operation does not need an extra `expose_secret` stack copy.

## Expiring Secrets

Use `MonotonicExpiringSecretBytes<N, C>` when fixed-size secrets should reject
access after a caller-defined number of monotonic ticks without requiring
`std`:

```rust
use sanitization::{MonotonicClock, MonotonicExpiringSecretBytes};

struct CounterClock(u64);

impl MonotonicClock for CounterClock {
    fn now(&self) -> u64 {
        self.0
    }
}

let mut key =
    MonotonicExpiringSecretBytes::<32, _>::from_array([7; 32], CounterClock(10), 300);

assert_eq!(key.try_constant_time_eq(&[7; 32]), Ok(true));
assert_eq!(key.max_age_ticks(), 300);
```

The tick unit is application-defined: milliseconds, RTOS ticks, hardware
counter increments, or another monotonic unit. The clock must not move backward
within a secret lifetime window.

Enable `std` when you want the convenience wrapper backed by
`std::time::Instant`:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.5", features = ["std"] }
```

```rust
use sanitization::ExpiringSecretBytes;
use std::time::Duration;

let mut key = ExpiringSecretBytes::<32>::from_array([7; 32], Duration::from_secs(300));
let mut generated =
    ExpiringSecretBytes::<32>::try_from_fn(Duration::from_secs(300), |_| {
        Ok::<u8, &'static str>(7)
    })
    .unwrap();

assert_eq!(key.try_constant_time_eq(&[7; 32]), Ok(true));
assert_eq!(generated.try_constant_time_eq(&[7; 32]), Ok(true));

key.try_expose_secret(|bytes| {
    assert_eq!(bytes.len(), 32);
}).unwrap();
key.try_expose_secret_volatile(|bytes| {
    assert_eq!(bytes[0], 7);
}).unwrap();

key.replace_from_fn(|index| index as u8);
key.try_replace_from_fn(|index| Ok::<u8, &'static str>(index as u8))
    .unwrap();
key.into_cleared();
```

There is no background timer. Expiration is checked when a fallible access
method is called. If the value has expired, the wrapped secret is cleared before
returning `SecretExpiredError`. Full replacement with `replace_from_slice`,
`replace_from_fn`, or `try_replace_from_fn` restarts the lifetime window for the
new value. Fallible generated replacement keeps a still-live old value unchanged
on generator error.

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

let mut token = SecretString::from_string(String::from("bearer-token"));
assert_eq!(token.try_with_secret(str::len), Ok(12));
assert!(token.constant_time_eq("bearer-token"));

let empty_text = SecretString::default();
assert!(empty_text.is_empty());

token.push_str("-v2");
assert_eq!(token.try_with_secret(|text| text.ends_with("-v2")), Ok(true));
token.try_with_secret_mut(|text| text.make_ascii_uppercase())
    .unwrap();
token.replace_from_secret_str("rotated-token");
token.replace_from_string(String::from("owned-token"));
token.replace_from_chars(5, |index| ['t', 'o', 'k', 'e', 'n'][index]);
token
    .try_replace_from_chars(5, |index| {
        Ok::<char, &'static str>(['t', 'o', 'k', 'e', 'n'][index])
    })
    .unwrap();

let mut bytes = SecretVec::from_vec(vec![115, 101, 115, 115, 105, 111, 110]);
bytes.extend_from_slice(b"-key");
assert_eq!(bytes.with_secret(|value| value.len()), 11);
assert!(bytes.capacity() >= bytes.len());
assert!(bytes.constant_time_eq(b"session-key"));

let empty_bytes = SecretVec::default();
assert!(empty_bytes.is_empty());

bytes.with_secret_mut(|value| value[0] = b'S');
bytes.replace_from_slice(b"rotated-session-key");
bytes.replace_from_vec(vec![1, 2, 3, 4]);
bytes.replace_from_fn(16, |index| index as u8);
bytes
    .try_replace_from_fn(16, |index| Ok::<u8, &'static str>(index as u8))
    .unwrap();
```

`SecretVec` and `SecretString` wipe initialized bytes and spare heap capacity
before freeing their allocations. Use `from_slice` and `from_secret_str` when
loading borrowed data. Use `from_vec`, `from_string`, `replace_from_vec`, and
`replace_from_string` to take ownership of existing heap allocations without
copying; those allocations become clear-on-drop secret storage. Use
`replace_from_slice` and `replace_from_secret_str` when rotating from borrowed
data. Use `SecretVec::from_fn`, `try_from_fn`, `replace_from_fn`, or
`try_replace_from_fn` when dynamic bytes can be generated directly into
clear-on-drop storage. Use `SecretString::from_chars`, `try_from_chars`,
`replace_from_chars`, or `try_replace_from_chars` when secret UTF-8 text can be
generated as `char` values. Fallible generation clears partial output on error.
`SecretString::try_with_secret_mut` exposes mutable `&mut str` access without
allowing safe Rust to invalidate UTF-8. They expose contents through closures
and redact `Debug`. `capacity()` exposes allocation size metadata for callers
that need to size append-heavy flows. `Default` creates an empty heap secret
container.

## Memory-Locked Secrets

Enable `memory-lock` for fixed-size secrets stored in private platform memory
and locked with the operating system's resident-memory API.

| Platform | Backend | Extra policy |
| --- | --- | --- |
| Linux `x86_64`/`aarch64` | raw `mmap`/`mlock` syscalls | `MADV_DONTDUMP` and `MADV_DONTFORK` |
| Android | system `mmap`/`mlock` ABI | no crate-level dump/fork exclusion |
| macOS/iOS | system `mmap`/`mlock` ABI | no crate-level dump/fork exclusion |
| FreeBSD | system `mmap`/`mlock` ABI | `MADV_NOCORE`, no fork exclusion |
| OpenBSD/NetBSD/DragonFly BSD | system `mmap`/`mlock` ABI | no crate-level dump/fork exclusion |
| Windows | `VirtualAlloc`/`VirtualLock` | no crate-level dump/fork exclusion |
| WASM `wasm32-*` | inline WASM-owned storage | API compatibility only; no host memory lock, dump exclusion, or page protection |

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

key.replace_from_slice(&[8; 32]).unwrap();
key.replace_from_array([9; 32]).unwrap();
key.replace_from_fn(|index| index as u8).unwrap();
key.try_replace_from_fn(|index| Ok::<u8, &'static str>(index as u8))
    .unwrap();

key.secure_clear();
assert!(key.constant_time_eq(&[0; 32]));
key.into_cleared();
```

`LockedSecretBytes<N>` does not use the Rust global allocator for the secret
bytes. It creates a private platform mapping, applies platform hardening policy
where supported by the backend, locks the mapping, volatile-clears the full
mapping on drop, then unlocks and releases it.
On WASM, there is no kernel mapping or memory-lock syscall available to the
module. `LockedSecretBytes<N>` and `SecretPool<N, SLOTS>` therefore compile as
volatile-only compatibility containers in WASM linear memory. This preserves
API-level portability for shared code, but it does not prevent host-runtime
copies, swapping, snapshots, browser memory inspection, or crash dumps.
Use `from_fn` when bytes can be generated directly into locked storage. Use
`try_from_fn` for fallible generators such as RNG or KDF APIs. Use `from_slice`
when loading bytes from an existing runtime buffer. `from_array` is still
available for fixed arrays and clears its owned input array before returning.
Use `replace_from_array`, `replace_from_slice`, `replace_from_fn`, or
`try_replace_from_fn` when rotating the whole locked value. Array replacement
clears its owned input array. Fallible generated replacement keeps the old
locked value unchanged on generator error.

Enable `canary-check` when locked or guarded secrets should detect corruption
that reaches either side of the secret data while staying inside the writable
mapping or pooled slot.

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.5", features = ["canary-check"] }
```

```rust
use sanitization::LockedSecretBytes;

let key = LockedSecretBytes::<32>::from_array([7; 32]).unwrap();

let first = key
    .expose_secret_checked(|bytes| bytes[0])
    .unwrap();

assert_eq!(first, 7);
assert_eq!(key.constant_time_eq_checked(&[7; 32]), Ok(true));
```

With `canary-check`, non-empty `LockedSecretBytes<N>` mappings and
`SecretPool<N, SLOTS>` slots use this layout:

```text
[ 8-byte canary ][ N-byte secret ][ 8-byte canary ]
```

Existing exposure APIs such as `with_secret`, `copy_to_slice`, and
`constant_time_eq` verify the canaries before reading secret bytes. If
corruption is detected, the full mapping or slot is volatile-cleared and those
legacy APIs panic with a fixed message. Use `expose_secret_checked`,
`copy_to_slice_checked`, `constant_time_eq_checked`, or `verify_integrity` on
`LockedSecretBytes<N>`, and `expose_secret_checked`,
`constant_time_eq_checked`, or `verify_integrity` on pool slots, when callers
need explicit error handling with `CanaryCorruptedError`.

Canaries are derived from the mapping or slot address and a fixed mask on
native mapped backends, so they require no RNG or dependency. On WASM, the
fallback canary is deterministic because inline storage can move with the Rust
value and cannot safely use a stable mapping address. They detect overwrites
that reach the canary
words; they do not detect corruption entirely inside the secret bytes,
historical copies, or external copies. `secure_clear` still wipes the full
mapping or slot, including the canary words, so a canary-checked locked value
or live pool slot should be treated as terminal after manual clearing. Dropping
a cleared pool slot returns it to the pool; the next allocation writes fresh
slot canaries.

Enable `random-canary` when the canary word should come from the operating
system CSPRNG instead of the deterministic address-derived fallback:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.5", features = ["random-canary"] }
```

`random-canary` uses direct platform backends without additional crates: Linux
and Android `getrandom`, macOS/iOS/BSD `arc4random_buf`, Windows
`BCryptGenRandom`, and WASI preview1 `random_get`. Bare
`wasm32-unknown-unknown`, Emscripten-style WASM, and WASI preview2 currently
have no dependency-free crate-level random import here, so random-canary
construction returns a `Random` operation error on those targets unless a
future backend is added. If OS random generation fails during construction,
locked and guarded constructors return a `Random` operation error. For pooled
slots, use `SecretPool::try_allocate` when callers need explicit RNG error
handling; legacy pool allocation helpers panic on RNG failure rather than
silently falling back to deterministic canaries.

For many same-size locked secrets, use `SecretPool<N, SLOTS>` to amortize
page-granule memory-locking overhead. This is useful on systems with small
`RLIMIT_MEMLOCK`/`VirtualLock` quotas because one locked mapping can hold many
slots.

```rust
use sanitization::SecretPool;

let pool = SecretPool::<32, 64>::new().unwrap();

let mut first = pool.allocate_from_array([7; 32]).unwrap();
let second = pool.allocate_from_fn(|index| index as u8).unwrap();

assert_eq!(pool.capacity_slots(), 64);
assert!(first.constant_time_eq(&[7; 32]));
assert_eq!(second.with_secret(|bytes| bytes[0]), 0);

first.replace_from_slice(&[8; 32]).unwrap();
first.secure_clear();

drop(first); // clears this slot and returns it to the pool
```

`SecretPool<N, SLOTS>` stores all slots inside one private locked mapping and
tracks live slots with an atomic bitmap. A slot borrows the pool, so the pool
cannot be dropped while slots are live. Dropping a slot volatile-clears that
slot before marking it reusable. Dropping the pool volatile-clears the full
mapping before unlocking and releasing it.

With `canary-check`, each non-empty pool slot has its own prefix and suffix
canary. Slot exposure, copying, mutation, and comparison verify those canaries
before accessing the payload. Checked slot APIs return `CanaryCorruptedError`;
legacy APIs clear the slot and panic.

This feature is explicit because OS memory locking has platform limits. It can
fail due to resource limits or policy. Linux `MADV_DONTDUMP` reduces ordinary
Linux core-dump exposure and `MADV_DONTFORK` reduces accidental fork
inheritance for the mapping. FreeBSD uses `MADV_NOCORE` for core-dump
exclusion, but still does not provide fork exclusion. Other non-Linux backends
currently only lock the pages and release them on drop. None of these APIs
protect against all crash dump mechanisms, hibernation, debuggers, privileged
process reads, DMA, malicious firmware, or copies made before data enters the
locked container.

## Guarded Heap Secrets

Enable `guard-pages` for dynamic byte secrets stored between inaccessible guard
pages on supported Linux, Android, macOS, iOS, Windows, and BSD targets:

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
token.replace_from_fn(16, |index| index as u8).unwrap();
token
    .try_replace_from_fn(16, |index| Ok::<u8, &'static str>(index as u8))
    .unwrap();

token.clear_secret();
assert!(token.is_empty());
token.into_cleared();
```

`GuardedSecretVec` uses a private platform mapping, leaves the pages before and
after the writable data region inaccessible, volatile-clears the full writable
region on drop, and then releases the allocation. It does not use the Rust
global allocator for the secret bytes. Use `GuardedSecretVec::from_fn` when
bytes can be generated directly into the guarded mapping; use `try_from_fn` for
fallible generators. Use `from_slice` when loading bytes from an existing
runtime buffer.
Use `replace_from_slice`, `replace_from_fn`, or `try_replace_from_fn` when
rotating or replacing the entire guarded value. Fallible generated replacement
keeps the old value unchanged on generator error. Linux guarded mappings keep
the no-libc page granules used by the raw syscall backend: 4 KiB on `x86_64`
and runtime `AT_PAGESZ` detection from `/proc/self/auxv` on `aarch64`, falling
back to 64 KiB if detection fails. Android, macOS, iOS, and BSD use
`getpagesize`; Windows uses `GetSystemInfo`.

With `canary-check`, `GuardedSecretVec` reserves an 8-byte canary before the
initialized payload and another immediately after it. This catches in-region
overwrites that guard pages cannot catch, such as writes that overrun the
initialized length but stay inside the writable capacity. Exposure, mutation,
growth, replacement, and comparison verify canaries first. Use
`expose_secret_checked`, `constant_time_eq_checked`, or `verify_integrity` when
callers need explicit `CanaryCorruptedError` handling.

When both `guard-pages` and `memory-lock` are enabled, guarded dynamic secrets
can also lock their writable data pages:

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
not locked because they never contain secret bytes. On Linux, writable data
pages are also marked with `MADV_DONTDUMP` and `MADV_DONTFORK` before locking;
FreeBSD writable data pages are marked with `MADV_NOCORE` before locking.
Other non-Linux backends currently lock the writable pages without crate-level
dump or fork policy. Locking can fail due to OS resource limits or policy, and
this does not change the broader memory-lock limits described above.
`GuardedSecretVec::locked_from_fn` is available for direct byte generation after
the writable data pages have been prepared and locked. Use `locked_try_from_fn`
for fallible generation into locked guarded storage.

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
`quote`, `proc-macro2`, or any compile-time code-generation dependency. They
currently support named-field structs without generics or `where` clauses; for
generic structs, write the `SecureSanitize` and `Drop` impls manually so bounds
stay explicit.

## Generic Secret Wrapper

Use `Secret<T>` when you already have a type that implements `SecureSanitize`
and you want clear-on-drop plus redacted `Debug`.

```rust
use sanitization::{Secret, SecureSanitize};

#[derive(Default)]
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

let mut empty_pair = Secret::<Pair>::default();
empty_pair.with_secret_mut(|value| value.right[0] = 7);
```

`SecureSanitize` is also implemented for common scalar and standard-library
container shapes:

- integer types: `u8` through `u128`, `usize`, signed integer equivalents, and
  `isize`.
- `bool`, `char`, `f32`, and `f64`.
- arrays and slices whose element type implements `SecureSanitize`.
- `Option<T>` and `Result<T, E>` when their contents implement
  `SecureSanitize`.
- with `alloc`: `Box<T>`, `Vec<T>`, and `String`.

```rust
use sanitization::{Secret, SecureSanitize};

let mut exponent = Secret::new(0xDEAD_BEEF_u64);
exponent.with_secret_mut(SecureSanitize::secure_sanitize);

let mut scalar_words = Secret::new([1_u64, 2, 3, 4]);
scalar_words.with_secret_mut(SecureSanitize::secure_sanitize);

let mut maybe_key = Secret::new(Some([7_u8; 32]));
maybe_key.with_secret_mut(SecureSanitize::secure_sanitize);
```

For `Vec<T>`, the generic implementation sanitizes initialized elements and
then clears the vector. It does not wipe arbitrary spare capacity for every
possible `T`, because spare capacity does not necessarily contain valid `T`
values. For dynamic byte secrets where full allocation capacity matters, use
`SecretVec`.

Opaque third-party numeric types such as `BigUint` cannot be implemented by
this crate without taking a dependency on that type. Wrap them in a local
newtype and implement `SecureSanitize` for the newtype, or convert the secret
material into `SecretBytes<N>`/`SecretVec` at the boundary where possible.

## Read-Once Secrets

Use `ReadOnceSecret<T>` when a value should be accessed once and then cleared.
The consume methods take `&self` and atomically mark the wrapper as consumed,
so repeated access through shared references returns `AlreadyConsumedError`.

```rust
use sanitization::{AlreadyConsumedError, ReadOnceSecret, SecretBytes};

let token = ReadOnceSecret::new(SecretBytes::<4>::from_array([1, 2, 3, 4]));

let sum = token.consume(|secret| {
    let mut out = [0; 4];
    secret.copy_to_slice(&mut out).unwrap();
    out.iter().copied().fold(0_u8, u8::wrapping_add)
}).unwrap();

assert_eq!(sum, 10);
assert_eq!(token.consume(|_| unreachable!()), Err(AlreadyConsumedError));
```

The wrapped value is cleared immediately after the first successful closure
returns. If the closure unwinds, `Drop` clears during unwinding. Like all
destructor-based cleanup, this cannot run if the process aborts.

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

## Multi-Pass Clearing

Enable `multi-pass-clear` when a policy requires explicit multi-pass overwrite
evidence:

```toml
[dependencies]
sanitization = { version = "1.0.0-rc.5", features = ["multi-pass-clear"] }
```

```rust
use sanitization::{sanitize_bytes_multi_pass, SecretBytes};

let mut bytes = [0xA5; 32];
sanitize_bytes_multi_pass(&mut bytes);
assert_eq!(bytes, [0; 32]);

let mut key = SecretBytes::<32>::from_array([7; 32]);
key.secure_clear_multi_pass();
assert!(key.constant_time_eq(&[0; 32]));
```

The pattern is zeros, then `0xFF`, then zeros again, all through volatile
writes. For ordinary volatile RAM, the default single-pass volatile zeroing is
the normal security boundary; multi-pass clearing is provided for compliance
language and audit compatibility, not because modern DRAM needs it.

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
The portable fallback is designed to avoid data-dependent early exit, but it is
not a formal hardware-level constant-time guarantee. Use `asm-compare` where it
is available, or pair this crate with a dedicated constant-time comparison
library when a protocol requires externally audited timing guarantees.

## Choosing the Right API

| Use case | Recommended API |
| --- | --- |
| Fixed-size key or token | `SecretBytes<N>` |
| Fixed-size key with no-`std` tick expiry | `MonotonicExpiringSecretBytes<N, C>` |
| Fixed-size key with access expiry | `ExpiringSecretBytes<N>` with `std` |
| Fixed-size key that should avoid swap/pagefiles on supported platforms | `LockedSecretBytes<N>` with `memory-lock` |
| Fixed-size locked key with prefix/suffix corruption checks | `LockedSecretBytes<N>` with `canary-check` |
| Fixed-size locked key with OS-random canary words | `LockedSecretBytes<N>` with `random-canary` |
| Many same-size fixed keys under memory-lock quotas | `SecretPool<N, SLOTS>` with `memory-lock` |
| Many same-size fixed keys with pooled canary checks | `SecretPool<N, SLOTS>` with `canary-check` |
| Dynamic secret bytes | `SecretVec` with `alloc` |
| Dynamic bytes with platform guard pages | `GuardedSecretVec` with `guard-pages` |
| Guarded dynamic bytes with in-region corruption checks | `GuardedSecretVec` with `guard-pages` and `canary-check` |
| Secret UTF-8 text | `SecretString` with `alloc` |
| Secret scalar such as `u64` | `Secret<u64>` |
| Standard compound value | `Secret<T>` where `T: SecureSanitize` |
| One-time access secret | `ReadOnceSecret<T>` |
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

- Volatile wiping requires the crate's internal wipe unsafe boundary; safe Rust
  alone cannot express volatile byte stores.
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
