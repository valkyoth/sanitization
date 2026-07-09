# Target Tiers

This document classifies target support for the high-assurance and native
`ct` features. The machine-readable form is `docs/ct-evidence.json`.

## Tier Definitions

| Tier | Meaning |
| --- | --- |
| Tier A | CI-covered release evidence plus target-specific codegen or proof evidence for the listed feature set. |
| Tier B | Source-level discipline and tests, but no complete target-specific timing evidence. |
| Tier C | API compatibility only, with reduced or no strong data-oblivious timing claim. |
| Forbidden | Known-bad or intentionally rejected target/feature combination. |

Tier names are evidence labels, not security certifications.

## Current Target Position

| Target/profile | Tier | Notes |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu`, release, `asm-compare`/`strict-ct` | Tier A draft | x86_64 assembly comparison backend, release codegen checks, Kani harnesses where available. |
| `aarch64-unknown-linux-gnu`, release, `asm-compare`/`strict-ct` | Tier B draft | AArch64 assembly comparison backend and compile checks when installed; release assembly scanning still needs native or cross-runner evidence. |
| Native targets without `asm-compare` | Tier B | Portable data-oblivious source structure and tests; no target-specific timing evidence. |
| Embedded/no-`std` targets | Tier B/C | Core APIs are `no_std`; hardware timing depends on device-specific review. |
| `wasm32-*` | Tier C | API compatibility and best-effort clearing only; no strong browser/Node JIT timing or native memory-lock claim. |

## Feature Availability

| Feature area | Native Linux/Android | macOS/iOS/BSD | Windows | WASM |
| --- | --- | --- | --- | --- |
| Default volatile clearing | Yes | Yes | Yes | Best effort, reduced claim |
| `alloc` containers | Yes | Yes | Yes | Yes with allocator |
| `memory-lock` | Yes | Yes where backend supports it | Yes | Only with `wasm-compat`, no host lock |
| `guard-pages` | Yes | Yes where backend supports it | Yes | No |
| `canary-check` | Yes | Yes | Yes | Yes for compat backends where exposed |
| `random-canary` | OS CSPRNG | OS CSPRNG | OS CSPRNG | WASI where host random exists; unsupported otherwise |
| `asm-compare` | x86_64/AArch64 where implemented | x86_64/AArch64 where implemented | x86_64/AArch64 where ABI-safe | No strong JIT claim |
| `cache-flush` | x86_64 | x86_64 | x86_64 | No |
| `register-scrub` | x86_64/AArch64 best effort | x86_64/AArch64 best effort | x86_64/AArch64 best effort | No |

## Release-Candidate Requirements

A stable `1.2.0` candidate should attach or cite:

- exact rustc version;
- exact target triple;
- exact feature set;
- CI run URL or local command transcript;
- `docs/ct-evidence.json` validation result;
- release codegen check result;
- Kani result when available;
- Miri result when available;
- any known target-specific residual risks.

Use `scripts/evidence-report.py` to capture the local commit, rustc host,
installed targets, and optional Kani/Miri tool availability for this evidence.

Targets without this evidence should remain Tier B or Tier C rather than being
promoted by assumption.
