# Evidence

This document records the current verification evidence for the `sanitization`
crate. It is not a blanket claim of identical wall-clock timing or complete
microarchitectural side-channel resistance.

The same information is also summarized in machine-readable form in
`ct-evidence.json`. That file is a draft until a release candidate attaches
exact CI run URLs, rustc versions, target triples, and feature sets.

## Scope

The 1.2 development line adds a native `sanitization::ct` module. Its claim is:

- no secret-dependent control flow inside the provided primitives;
- no secret-dependent memory access inside the provided primitives;
- public length and allocation metadata may affect control flow;
- explicit declassification is required through `ct::Choice::declassify`;
- stronger assembly comparison backends are available only on documented
  targets and features.

The crate does not claim:

- identical wall-clock timing on every CPU;
- protection against all cache, branch predictor, SMT, transient-execution, or
  power side channels;
- constant-time behavior for arbitrary caller closures;
- browser or Node WASM JIT constant-time behavior;
- protection for copies made outside crate-owned containers.

## Target Tiers

`ct-evidence.json` mirrors these tiers for tooling and release review.

| Target/profile | Tier | Evidence |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu`, release, `asm-compare`/`strict-ct` | Tier A draft | CI feature tests, release LLVM IR/assembly scan, x86_64 asm comparison backend, Kani harnesses when available |
| `aarch64-unknown-linux-gnu`, release, `asm-compare`/`strict-ct` | Tier B draft | Target compile check when installed, AArch64 asm comparison backend, Kani source-level harnesses |
| Native targets without `asm-compare` | Tier B | Portable source-level data-oblivious structure and tests, no target-specific timing evidence |
| Embedded/no-`std` targets | Tier B/C | `no_std` compile checks where targets are installed; no device-level leakage tests |
| WASM `wasm32-*` | Tier C | API compatibility checks and documented reduced volatile/memory-lock guarantees; no strong JIT timing claim |

Tier A draft means the repository has automated evidence hooks, but a stable
release should still include the exact rustc version, target triple, feature
set, and CI run that produced the evidence.

## Automated Checks

Run the local release-sensitive matrix:

```bash
scripts/checks.sh
```

This script runs formatting, feature-matrix tests, examples, clippy, target
checks for installed targets, release codegen checks, optional Kani proofs,
documentation with warnings denied, and package listing.

Run Miri separately when a nightly toolchain with Miri is installed:

```bash
scripts/verify-miri.sh
```

Run Kani proofs directly when `cargo-kani` is installed:

```bash
scripts/verify-kani.sh
```

Latest local run while preparing the 1.2 alpha evidence slice:

- Kani version: `Kani Rust Verifier 0.67.0`;
- result: all configured `scripts/verify-kani.sh` harnesses passed for
  `no-default-features`, `alloc`, and `std` runs.

Run release codegen checks directly:

```bash
scripts/verify-codegen.sh
```

Validate the machine-readable evidence draft directly:

```bash
scripts/verify-evidence.py
```

This verifies that `ct-evidence.json` has the expected schema and that its
listed Kani proof names match the proof harnesses in `src/lib.rs`.

## Kani Harnesses

The crate includes bounded proof harnesses behind `#[cfg(kani)]`. They are not
compiled into normal crate builds.

Current proof scope:

- volatile byte clearing zeroes a fixed buffer;
- `SecretBytes<N>::secure_clear` erases visible fixed-size contents;
- legacy `constant_time_eq` matches byte equality for bounded fixed arrays;
- public length mismatch is rejected;
- `ct::Choice` normalizes to `0` or `1`;
- `ct::eq_fixed` matches byte equality for bounded fixed arrays;
- `ct::cmp_fixed` matches lexicographic ordering for bounded fixed arrays;
- `ct::ConstantTimeOrd` matches Rust ordering for bounded signed and unsigned
  primitive integer harnesses;
- `ct::eq_public_len` rejects public length mismatch;
- `ct::conditional_copy` matches the public interpretation of the `Choice`;
- `ct::select_slice` matches the public interpretation of the `Choice`;
- allocation growth arithmetic does not under-allocate for the bounded harness.

These proofs are functional correctness checks over bounded inputs. They do not
prove hardware timing, compiler backend behavior, or absence of every
microarchitectural leak.

## Release Codegen Checks

`scripts/verify-codegen.sh` emits release LLVM IR and assembly for the
`sanitization` library with all features enabled.

The script checks:

- the volatile wipe function is present in LLVM IR;
- volatile byte-zero stores are present in LLVM IR;
- the compatibility clear alias remains present;
- on x86_64 hosts, the assembly comparison symbol and byte-load instructions
  are present;
- on x86_64 hosts, cache-flush instructions and fences are present.

This is a regression check, not a formal proof. Manual review should still be
performed for release candidates that change unsafe code, comparison backends,
or compiler/toolchain versions.

## Documentation Evidence

Permanent documentation that constrains the claims:

- `README.md`: API examples, feature table, target behavior, release checks;
- `THREAT_MODEL.md`: guarantees, residual risks, WASM limits, canary limits;
- `SAFETY.md`: unsafe boundaries and invariants;
- `ROADMAP.md`: 1.2 target tiers and release checkpoint gates.

## Open Evidence Gaps

- No dudect or equivalent leakage-test harness is shipped yet.
- AArch64 release assembly is compile-checked when the target is installed, but
  is not yet scanned by `scripts/verify-codegen.sh` on non-AArch64 hosts.
- WASM JIT behavior remains a documented non-guarantee.
- Target tiers are draft until attached to specific CI runs for a stable
  release candidate.
