# Feature Profiles And Crate Boundaries

This document defines the named feature profiles introduced for sanitization
2.0 and the ownership boundary between the core crate and its companions.

## Capability, Policy, And Result

These are separate concepts:

1. Cargo features compile capabilities into the program.
2. `ProtectionRequest` states whether each runtime control is required,
   preferred, or not requested.
3. `ProtectionReport` records which controls were actually established.

A profile name is not proof that the operating system accepted memory locking,
dump exclusion, fork exclusion, or guard-page setup. Required failures return a
structured error. Preferred failures may return a container only when its
report records the reduced result.

The normative request, failure, rollback, and report semantics are documented
in `docs/PROTECTION_REPORT.md`.

## Named Native Profiles

| Profile | Compiled capabilities | Matching request policy |
| --- | --- | --- |
| `profile-hardened-native` | `memory-lock`, OS-random canaries, strict canary checks, assembly-backed strict equality | Memory lock and canary required; dump and fork exclusion preferred |
| `profile-guarded-native` | `profile-hardened-native` plus guard pages | Hardened-native policy plus guard pages required |
| `profile-hardened-linux` | `profile-hardened-native` plus required fork exclusion | Hardened-native policy with Linux fork exclusion required |

The matching constructors are:

```rust
use sanitization::ProtectionRequest;

let native = ProtectionRequest::profile_hardened_native();
let guarded = ProtectionRequest::profile_guarded_native();
let linux = ProtectionRequest::profile_hardened_linux();
```

Each constructor is available only when its profile feature is enabled.

`strict-compare` is intentionally narrower than a general constant-time
profile. It strengthens equal-length byte equality on reviewed x86_64 and
AArch64 assembly backends. It does not strengthen ordering, lookup, selection,
allocation, text validation, or caller code.

## Target Rejection

Known-incompatible combinations fail at compile time:

- every native hardening profile is rejected on `wasm32`;
- `profile-hardened-linux` is rejected on non-Linux targets;
- native profiles are rejected where no reviewed native memory-lock backend
  exists;
- `strict-compare` rejects non-Miri architectures without a reviewed assembly
  comparison backend.

This keeps strict profile names from silently degrading into compatibility
behavior.

## WASM Compatibility

WASM remains an explicit reduced-guarantee target:

```toml
sanitization = {
    version = "2",
    features = ["memory-lock", "wasm-compat", "random-canary"],
}
```

WASM compatibility containers preserve API shape and clear their owned linear
memory on drop. They do not provide host `mlock`, dump exclusion, fork policy,
guard pages, or a native volatile-store guarantee across a JIT boundary.
`ProtectionRequest::wasm_compatibility()` and the resulting report make those
outcomes explicit.

## Companion Ownership

The core `sanitization` crate owns the volatile clearing backend. Companion
crates integrate external representations without duplicating that primitive.

| Crate | Boundary |
| --- | --- |
| `sanitization-derive` | Generates calls to core traits; it has no runtime dependency on the core crate |
| `sanitization-arrayvec` | Exposes `arrayvec` storage and delegates clearing to `sanitization::wipe` |
| `sanitization-bytes` | Enforces fixed-capacity `BytesMut` use and delegates clearing to `sanitization::wipe` |
| `sanitization-crypto-interop` | Uses upstream hasher cleanup traits and core secret containers; it does not define a second memory-wipe backend |

Every companion dependency on `sanitization` sets `default-features = false`.
The proc-macro crate intentionally does not depend on the runtime crate.

## Default Core Graph

The default core feature set is empty. All third-party runtime dependencies are
optional, so:

```bash
cargo tree -p sanitization --no-default-features --edges normal
```

must contain only the core crate itself.

`scripts/verify-feature-profiles.py` enforces the profile expansion, package
metadata, default dependency policy, and companion clearing boundary.
