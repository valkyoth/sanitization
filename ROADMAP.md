# Roadmap

This crate is still in release-candidate status. We will use that window to fix
the architecture before `1.0.0`, even if that means making breaking changes
while adoption is still low.

The goal is not to be a drop-in replacement for `zeroize`. The goal is to be a
zero-dependency secret lifecycle crate for new projects: redacted containers,
narrow exposure APIs, constant-time equality for crate-owned secrets, and one
audited memory clearing path.

## Ecosystem Position

`zeroize` is deliberately minimal: one trait, one optimizer-resistant clearing
primitive, and an optional derive macro. That design is valuable because it
keeps the crate focused. The broader Rust secret-handling ecosystem usually
combines multiple crates to cover lifecycle concerns:

- `zeroize` for memory clearing;
- `secrecy` for controlled secret exposure;
- `subtle` for constant-time equality;
- older or less-maintained crates for memory locking, guard pages, and platform
  memory protection.

This crate should not clone every `zeroize` capability. Its stronger position is
to be a dependency-free secret lifecycle crate: storage, controlled exposure,
comparison, and destruction under one coherent threat model.

The opportunity is to keep that lifecycle scope while adding the high-assurance
pieces that are currently hard to get from maintained, dependency-light Rust
crates.

## Non-Negotiables

- Keep zero external runtime dependencies.
- Keep `no_std` as the default.
- Keep proc macros out of the core crate.
- Prefer small, explicit unsafe internals over broad safe APIs with weaker
  security properties.
- Document limits instead of implying complete process-memory secrecy.

## Pre-1.0 Architecture Direction

### 1. Make Volatile Wiping the Default Clear Path

Status: implemented in `1.0.0-rc.5`.

Earlier release candidates had two clearing tiers:

- default safe best-effort clearing;
- opt-in volatile clearing.

That split was honest, but it was easy for users to miss. The crate now uses
optimizer-resistant volatile clearing as the normal clear path for secret-owned
memory and ordinary byte-slice sanitization.

Expected shape:

- The volatile wipe backend lives in one small internal module.
- Unsafe code remains isolated and audited.
- Byte-slice, heap-capacity, and temporary-copy clearing route through that
  backend where applicable.
- `unsafe-wipe` remains as a no-op compatibility feature for older
  release-candidate dependency declarations.

### 2. Simplify `SecretBytes<N>` Storage

Status: implemented in `1.0.0-rc.5`.

Earlier release candidates used atomic byte storage on targets with 8-bit
atomics and fell back on non-atomic storage elsewhere. That was defensible, but
surprising and target-dependent.

Planned direction:

- Fixed-size bytes are stored as `[u8; N]`.
- Mutation remains behind `&mut self`.
- Clearing uses the same internal volatile wipe path as other byte buffers.
- `Sync` follows from plain byte storage instead of interior mutability.

This should make behavior easier to audit and more consistent across embedded
and server targets.

### 3. Keep Secret Lifecycle APIs

The crate should keep focusing on lifecycle management rather than becoming a
large blanket trait implementation crate.

Keep and harden:

- `SecretBytes<N>`;
- `SecretVec`;
- `SecretString`;
- `Secret<T>`;
- closure-based exposure;
- redacted `Debug`;
- dependency-free struct macros.

Avoid before `1.0.0`:

- broad blanket impls for every primitive and container;
- proc-macro derives in the core crate;
- compatibility layers that make the security model harder to explain.

### 4. Add Stronger Verification

Status: partially implemented in `1.0.0-rc.5`.

Before stable `1.0.0`, add or evaluate:

- Miri runs for the unsafe boundary where target support allows it.
- Release LLVM IR inspection for volatile wipe codegen.
- Feature-matrix checks after removing or changing `unsafe-wipe`.
- External review focused on unsafe clearing, drop behavior, and API misuse.

Implemented now:

- `scripts/verify-codegen.sh` builds release LLVM IR and checks that the wipe
  backend contains volatile byte-zero stores.
- `scripts/checks.sh` runs the codegen verification as part of the local gate.
- `scripts/verify-miri.sh` runs default, `alloc`, and all-features tests under
  Miri when a nightly toolchain with Miri is available.

Property-based or timing-distribution tests can live outside the published
crate if keeping dev dependencies out of the repository remains preferred.

### 5. Evaluate Memory Locking as a High-Assurance Feature

Status: partially implemented for fixed-size Linux secrets behind the
`memory-lock` feature.

`mlock`, `VirtualLock`, guard pages, and platform-specific memory policies are
important for high-assurance deployments. Memory locking is the biggest
ecosystem gap because it prevents secret pages from being swapped to disk,
pagefiles, or hibernation images.

Current implementation:

- `LockedSecretBytes<N>` is available on Linux `x86_64` and `aarch64` when the
  `memory-lock` feature is enabled.
- Secret bytes live in a private anonymous `mmap` allocation rather than the
  Rust global allocator.
- The mapping is locked with `mlock`, volatile-cleared in full on drop, then
  released with `munlock` and `munmap`.
- Moving the Rust value copies only pointer metadata, not the secret byte
  allocation.

Remaining stance:

- Keep memory locking out of the default API.
- Extend only after target-specific review.
- Pair every lock operation with automatic unlock on drop.
- Document OS limits clearly: resource limits, privileges, page alignment,
  partial failures, crash dumps, hibernation policy, and platform differences.

Implemented API shape:

```rust
let key = LockedSecretBytes::<32>::zeroed()?;
```

This must continue to be reviewed carefully. `VirtualLock`, broader platform
support, exact runtime page-size handling, guard pages, and allocator-sensitive
dynamic containers all need platform-specific tests and review.

## Candidate Differentiators

These are not promises for the first stable release. They are candidate
directions that could make the crate meaningfully stronger than a clearing-only
crate once the core architecture is solid.

### 1. Memory Locking

Priority: highest high-assurance feature.

Goal:

- prevent secret allocations from reaching swap or pagefiles where the platform
  supports it;
- keep the implementation dependency-free;
- make failures explicit;
- unlock automatically on drop.

Constraints:

- Linux, macOS, Windows, and embedded targets need different implementations;
- direct syscalls avoid a `libc` dependency but increase audit burden;
- `mlock` does not protect against hibernation, crash dumps, privileged reads,
  DMA, or firmware compromise by itself.

### 2. Formal Verification

Priority: high trust signal.

Evaluate Kani or a similar model-checking workflow for properties regular tests
cannot prove:

- wipe loops visit every byte;
- comparison loops execute the expected number of iterations for equal-length
  inputs;
- length mismatch behavior stays explicit and public;
- capacity-growth arithmetic does not overflow into unsound behavior.

Kani itself does not need to become a crate dependency. Proof harnesses can live
behind CI-only tooling or an external verification directory if that preserves
the published crate's dependency posture.

### 3. Architecture-Specific Cache Eviction

Priority: optional, target-specific hardening.

After memory is zeroed, old values can still exist transiently in CPU caches.
Some targets provide cache-line flush instructions such as x86/x86_64 `clflush`.

This should only be considered as an explicit feature after the core volatile
wipe path is stable because:

- instructions and guarantees differ by architecture;
- cache-line size detection matters;
- the operation is not universally available;
- cache eviction does not solve all side channels;
- it can be expensive and surprising as a default.

### 4. Assembly-Backed Constant-Time Comparison

Status: implemented for x86_64 behind the `asm-compare` feature.

Priority: optional hardening for major targets.

The current Rust comparison path remains the portable fallback. A target-specific
assembly implementation provides a stronger compiler boundary for equal-length
comparisons on x86_64 when the `asm-compare` feature is enabled.

Design requirements:

- safe public API: implemented with no API change;
- strict fallback to the portable implementation on unsupported targets:
  implemented;
- independent review of inline assembly constraints: still recommended before
  stable;
- tests that prove fallback and target paths agree: implemented for x86_64;
- documentation that length remains public metadata: implemented.

### 5. Secret Lifetime Enforcement

Priority: policy feature, likely `std` only.

Some systems need secrets to expire after a fixed time. A future `std` feature
could track creation time and reject exposure after a configured maximum age.

Candidate API shape:

```rust
let key = SecretBytes::<32>::from_array([0; 32]).with_max_age(duration);
```

Design constraints:

- keep `no_std` defaults untouched;
- avoid hidden background work;
- decide whether expiration clears immediately or only prevents exposure;
- account for clock behavior and testability.

### 6. Guard-Page Heap Allocations

Priority: complex, post-core.

Guard pages around heap secrets can turn some overreads and overwrites into
immediate faults. This is potentially valuable for high-assurance builds but is
platform-specific and allocator-sensitive.

This should be considered only after memory locking and volatile clearing are
settled. It likely belongs behind an explicit feature or companion crate rather
than the default API.

## Priority Order

If resources are limited, the implementation order should be:

1. Add stronger verification around the unsafe wipe and comparison paths.
2. Evaluate dependency-free memory locking.
3. Evaluate assembly-backed comparison on major targets.
4. Evaluate cache eviction and guard pages as explicit hardening features.
5. Evaluate secret lifetime enforcement as a `std` policy feature.

## Stable Release Bar

Do not tag `1.0.0` until:

- the volatile default clearing architecture remains implemented and documented;
- `SecretBytes<N>` storage behavior remains settled;
- the `unsafe-wipe` compatibility feature remains clearly documented;
- README, SAFETY, SECURITY, and THREAT_MODEL match the final design;
- the roadmap clearly marks post-`1.0.0` high-assurance features as optional
  rather than stable guarantees;
- the local check matrix passes;
- at least one external reviewer has looked at the unsafe boundary and secret
  lifecycle API;
- downstream testing has not found API friction that would require immediate
  breaking changes.
