# Leakage Testing

This document describes the leakage-test expectations for the native
`sanitization::ct` work. The repository does not currently ship a dudect-style
statistical timing harness. Until it does, target tiers must not imply measured
hardware constant-time behavior.

## Claim Under Test

The crate's data-oblivious claim is:

> No secret-dependent control flow or secret-dependent memory access inside the
> provided primitives, under documented compiler, target, feature, and release
> profile conditions.

Leakage testing should try to falsify that claim on specific target machines.
It should not be described as proof of identical wall-clock timing.

## Required Inputs

A leakage-test run should record:

- crate version or commit hash;
- rustc version and LLVM version where available;
- target triple;
- CPU model and relevant CPU features;
- OS and kernel version;
- Cargo profile and optimization settings;
- enabled crate features;
- whether `asm-compare`, `strict-ct`, `cache-flush`, or `register-scrub` were
  enabled;
- number of samples and statistical threshold;
- whether CPU frequency scaling, turbo boost, SMT, and scheduler affinity were
  controlled.

Without this metadata, timing results are useful for local debugging but should
not promote a target tier.

## Initial Harness Scope

The first leakage harness should focus on fixed-size primitives where inputs
can be randomized cleanly:

- `ct::Choice` normalization and boolean operations;
- `ct::eq_fixed` for `[u8; 16]`, `[u8; 32]`, and `[u8; 64]`;
- `ct::cmp_fixed` for fixed byte arrays;
- `ct::ConstantTimeEq` for `SecretBytes<N>`;
- `ct::ConstantTimeOrd` for integer primitives;
- `ct::oblivious_lookup` with fixed public table length and secret index;
- `ct::conditional_copy`, `ct::conditional_swap`, and `ct::select_slice` with
  fixed public lengths.

Tests should compare distributions such as:

- all bytes equal vs. first byte different;
- all bytes equal vs. last byte different;
- low secret index vs. high secret index;
- true `Choice` vs. false `Choice`;
- success `CtOption`/`CtResult` vs. failure `CtOption`/`CtResult`.

## Out Of Scope For Leakage Harnesses

The initial harness should not claim to cover:

- arbitrary user closures passed to exposure or transform APIs;
- third-party cryptographic implementations;
- deserialization or formatting code;
- OS memory locking behavior;
- guard-page fault behavior;
- WASM browser or Node JIT behavior;
- hardware attacks outside normal userspace timing collection.

## Release Policy

Before a target moves to Tier A for the native `ct` claim, the release should
include either:

- a checked-in leakage harness with a recorded passing run for that target; or
- an explicit rationale explaining why the target is Tier A based on other
  release evidence.

Until then, keep the target at Tier B or Tier C and document the missing
measurement in `EVIDENCE.md` and `ct-evidence.json`.

## Future Tooling

A future `scripts/verify-leakage.sh` or dedicated test crate should:

- build in release mode with the exact feature set under review;
- pin the benchmark process to a CPU where the OS supports it;
- collect enough samples for dudect-style Welch's t-test analysis;
- fail closed when the configured threshold is exceeded;
- emit a machine-readable result that can be referenced from
  `ct-evidence.json`.

This tooling should remain optional for ordinary users. It is release evidence,
not a runtime dependency.

