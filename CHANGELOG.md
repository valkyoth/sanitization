# Changelog

## 1.0.0-rc.5

- Made volatile clearing the default clear path through one internal audited
  unsafe backend.
- Simplified `SecretBytes<N>` storage from atomic/`Cell` byte storage to plain
  `[u8; N]` with volatile clearing on drop.
- Changed `SecretVec`, `SecretString`, `Secret<T>`, byte slices, and byte arrays
  to use volatile clearing by default.
- Added `SecretVec::replace_from_slice` and
  `SecretString::replace_from_secret_str` for whole-value rotation without
  copying previous dynamic secrets during growth.
- Added `SecretVec::from_fn` and `SecretVec::replace_from_fn` for direct
  dynamic byte generation into clear-on-drop storage.
- Added `SecretBytes::try_from_fn`, `SecretVec::try_from_fn`, and
  `SecretVec::try_replace_from_fn` for fallible direct byte generation with
  partial-output clearing on error.
- Kept the `unsafe-wipe` feature as a no-op compatibility flag for older
  release-candidate dependency declarations.
- Kept `unsafe_wipe` public helper APIs available for explicit ordinary-buffer
  wiping.
- Added a release LLVM IR codegen check for volatile byte-zero stores.
- Expanded release codegen checks to verify x86_64 assembly comparison and
  cache-flush instruction paths.
- Added optional bounded Kani proof harnesses for selected fixed-size clearing,
  equality, and capacity properties.
- Added a dedicated GitHub workflow for the bounded Kani harness matrix.
- Added an optional Miri verification script for the wipe boundary and feature
  matrix.
- Added the optional Linux `memory-lock` feature with `LockedSecretBytes<N>` for
  fixed-size secrets backed by private `mmap` storage and `mlock`.
- Added `MADV_DONTDUMP` setup for Linux memory-locked secret mappings.
- Added `MADV_DONTFORK` setup for Linux memory-locked secret mappings.
- Added `LockedSecretBytes::from_slice` for direct runtime-buffer loading.
- Added `LockedSecretBytes::from_fn` for direct byte generation inside locked
  storage.
- Added the optional x86_64 `asm-compare` feature for assembly-backed
  equal-length byte comparison with portable fallback elsewhere.
- Added the optional x86_64 `cache-flush` feature for explicit volatile-clear
  plus `clflush`/`mfence` cache-line eviction helpers.
- Added `std`-only `ExpiringSecretBytes<N>` for fixed-size secret lifetime
  enforcement.
- Added the optional Linux `guard-pages` feature with `GuardedSecretVec` for
  dynamic byte secrets stored between inaccessible pages.
- Added `GuardedSecretVec` locked constructors when both `guard-pages` and
  `memory-lock` are enabled.
- Added `GuardedSecretVec::from_fn` and `GuardedSecretVec::locked_from_fn` for
  direct byte generation inside guarded mappings.
- Added `GuardedSecretVec::replace_from_slice` for whole-value rotation without
  copying the previous guarded bytes during growth.
- Added `GuardedSecretVec::clear_secret_and_flush` and `CacheFlushSanitize`
  support when both `guard-pages` and x86_64 `cache-flush` are enabled.
- Changed Linux mapping length rounding to use a conservative 64 KiB granule on
  `aarch64`, keeping guarded and locked mappings compatible with 4 KiB, 16 KiB,
  and 64 KiB Linux kernels without a libc dependency.
- Expanded the local check matrix and examples for optional high-assurance
  features.
- Updated README, safety notes, and threat model for the new clearing model.

## 1.0.0-rc.4

- Hardened equal-length comparison accumulators against optimizer-introduced
  short-circuiting.
- Added `SecretBytes::expose_secret_volatile` behind `unsafe-wipe` for volatile
  clearing of temporary stack copies on normal and unwind paths.
- Switched `SecretVec` and `SecretString` growth to exponential capacity
  growth to avoid repeated exact reallocations.
- Updated safety, threat model, and README documentation for volatile string
  wiping, best-effort clearing limits, and abort behavior.

## 1.0.0-rc.3

- Added crates.io homepage and repository metadata for the GitHub project.
- Updated README installation examples to `1.0.0-rc.3`.

## 1.0.0-rc.2

- Updated crates.io-facing README installation examples and release status.

## 1.0.0-rc.1

- Release candidate for downstream integration testing.
- Added dependency-free `secure_sanitize_struct!` and `secure_drop_struct!`
  macros.
- Hardened equal-length constant-time comparisons by removing short-input
  per-index branches.
- Aligned best-effort and volatile heap clearing to wipe allocation capacity
  where available.
- Expanded README examples, Rust version support notes, GitHub CI defaults, and
  crate packaging metadata.

## 0.1.0

- Initial unpublished crate layout.
- Added safe `no_std` fixed-size `SecretBytes<N>`.
- Added `alloc` heap containers `SecretVec` and `SecretString`.
- Added explicit `unsafe-wipe` volatile backend and `VolatileOnDrop<T>`.
- Added threat model, unsafe audit notes, CI, and local check script.
