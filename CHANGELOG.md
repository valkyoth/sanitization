# Changelog

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
