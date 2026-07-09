# Barrier Strategy

This document explains the optimizer and backend barriers used by the crate.
It does not turn any one primitive into a universal cryptographic guarantee.
The guarantees are the combination of API shape, implementation discipline,
target-specific codegen, and release evidence.

## Clearing Barriers

Memory clearing uses a single audited volatile wipe boundary:

- volatile byte writes prevent native LLVM dead-store elimination of the clear;
- `compiler_fence(Ordering::SeqCst)` prevents compiler reordering around the
  wipe boundary;
- `fence(Ordering::SeqCst)` provides a hardware ordering boundary where the
  target supports it;
- the wipe function is kept behind a non-inlined boundary for easier codegen
  inspection.

On WASM, volatile writes survive Rust-to-WASM lowering, but the WASM memory
model does not encode volatility. The crate uses a non-inlined function-pointer
style boundary as a best-effort mitigation, and documents WASM as a weaker
target tier.

## Data-Oblivious Barriers

The native `ct` module starts with source-level data-oblivious structure:

- branchless bitwise and arithmetic operations;
- public fixed loop bounds;
- no secret-dependent indexing inside the provided primitives;
- explicit `declassify(reason)` when a secret-derived value becomes public.

`core::hint::black_box` may be used to reduce optimizer visibility, but it is
not treated as a cryptographic primitive. Release evidence must still inspect
the generated code shape for reviewed targets.

## Assembly Backends

The `asm-compare` feature enables target-specific equal-length comparison
backends where available. The `strict-ct` feature fails closed on unsupported
targets instead of silently falling back.

Assembly backends are useful because they reduce compiler freedom in the most
sensitive comparison loop. They still do not prove complete hardware timing
behavior, and they do not protect arbitrary caller code around the comparison.

## Cache And Register Helpers

`cache-flush` and `register-scrub` are explicit hardening helpers:

- cache flush helpers zero first, then evict affected x86_64 cache lines;
- register scrub helpers clear a documented subset of SIMD/vector state.

These helpers reduce post-use residency. They are not defenses against an
attacker who already has cache-timing, register-save-area, or privileged
observation during the secret's active lifetime.

## Release Evidence

For release candidates that change barriers, comparison code, unsafe code, or
target support, run and record:

```bash
scripts/checks.sh
scripts/verify-codegen.sh
scripts/verify-miri.sh
scripts/verify-kani.sh
scripts/verify-evidence.py
```

`scripts/verify-codegen.sh` is a regression gate. It checks that important
symbols and instruction patterns remain present, but it is not a replacement
for manual review of release artifacts.

