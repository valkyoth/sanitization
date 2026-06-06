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

The current `unsafe-wipe` feature creates two clearing tiers:

- default safe best-effort clearing;
- opt-in volatile clearing.

That split is honest, but it is easy for users to miss. Before `1.0.0`, the
planned direction is to make optimizer-resistant volatile clearing the normal
clear path for secret-owned memory.

Expected shape:

- Move the volatile wipe backend into one small internal module.
- Keep the unsafe code isolated and audited.
- Route byte-slice, heap-capacity, and temporary-copy clearing through that
  backend where applicable.
- Remove or repurpose `unsafe-wipe` so users do not need to opt in for serious
  clearing.

### 2. Simplify `SecretBytes<N>` Storage

`SecretBytes<N>` currently uses atomic byte storage on targets with 8-bit
atomics and falls back on non-atomic storage elsewhere. That is defensible, but
it is surprising and creates target-dependent clearing behavior.

Planned direction:

- Store fixed-size bytes as `[u8; N]`.
- Keep mutation behind `&mut self`.
- Clear with the same internal volatile wipe path used by other byte buffers.
- Re-evaluate `Sync` explicitly during the implementation.

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

Before stable `1.0.0`, add or evaluate:

- Miri runs for the unsafe boundary where target support allows it.
- Assembly or IR inspection notes for the wipe backend.
- Feature-matrix checks after removing or changing `unsafe-wipe`.
- External review focused on unsafe clearing, drop behavior, and API misuse.

Property-based or timing-distribution tests can live outside the published
crate if keeping dev dependencies out of the repository remains preferred.

### 5. Evaluate Memory Locking as a High-Assurance Feature

`mlock`, `VirtualLock`, guard pages, and platform-specific memory policies are
important for high-assurance deployments. Memory locking is the biggest
ecosystem gap because it prevents secret pages from being swapped to disk,
pagefiles, or hibernation images.

Planned stance:

- Keep memory locking out of the default API until the volatile clear path is
  settled.
- Evaluate a feature-gated, zero-dependency implementation using direct
  platform calls where practical.
- Pair any lock operation with automatic unlock on drop.
- Document OS limits clearly: resource limits, privileges, page alignment,
  partial failures, crash dumps, hibernation policy, and platform differences.

Candidate API shape:

```rust
let key = SecretBytes::<32>::locked()?;
```

This must not be rushed. Raw syscalls, `VirtualLock`, `mlock`, `munlock`, page
rounding, and allocator interactions all need platform-specific tests and
review.

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

Priority: optional hardening for major targets.

The current Rust comparison path should remain conservative and auditable. A
target-specific assembly implementation could provide a stronger compiler
boundary for equal-length comparisons on targets such as x86_64.

Design requirements:

- safe public API;
- strict fallback to the portable implementation on unsupported targets;
- independent review of inline assembly constraints;
- tests that prove fallback and target paths agree;
- documentation that length remains public metadata.

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

1. Make volatile clearing the default path.
2. Simplify `SecretBytes<N>` storage and clearing.
3. Rework or remove the `unsafe-wipe` feature split.
4. Add stronger verification around the unsafe wipe and comparison paths.
5. Evaluate dependency-free memory locking.
6. Evaluate assembly-backed comparison on major targets.
7. Evaluate cache eviction and guard pages as explicit hardening features.
8. Evaluate secret lifetime enforcement as a `std` policy feature.

## Stable Release Bar

Do not tag `1.0.0` until:

- the volatile default clearing architecture is implemented;
- `SecretBytes<N>` storage behavior is settled;
- the `unsafe-wipe` feature split is removed, renamed, or clearly justified;
- README, SAFETY, SECURITY, and THREAT_MODEL match the final design;
- the roadmap clearly marks post-`1.0.0` high-assurance features as optional
  rather than stable guarantees;
- the local check matrix passes;
- at least one external reviewer has looked at the unsafe boundary and secret
  lifecycle API;
- downstream testing has not found API friction that would require immediate
  breaking changes.
