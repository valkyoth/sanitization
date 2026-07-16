# CP-01 Behavior-Preserving Module Split

Status: implementation comparison record

Baseline: `v1.2.5`

Checkpoint: `CP-01`

This checkpoint separates the core crate implementation before any 2.0
behavioral or API changes. Public paths, feature selection, target selection,
drop behavior, and unsafe invariants remain unchanged.

## Module Map

- `lib.rs`: crate attributes, compile-time feature guards, module declarations,
  and root re-exports.
- `wipe_backend.rs`: volatile write backend and the public `unsafe_wipe` module.
- `owned.rs`: sanitization traits, owned containers, expiration, split storage,
  read-once storage, and Kani harnesses.
- `ct.rs`: data-oblivious primitives and their public traits.
- `mapped.rs`: mapped-container public integration and mapped text wrappers.
- `mapped/memory_lock_native.rs`: native locked mappings and pooled slots.
- `mapped/memory_lock_wasm.rs`: explicit reduced-guarantee WASM compatibility
  storage.
- `mapped/guard_pages.rs`: native guarded mappings.
- `platform.rs`: page-size detection, assembly comparison, cache flushing,
  register scrubbing, and hardware-provider traits.
- `canary.rs`: operating-system CSPRNG adapters for random canaries.
- `interop.rs`: zeroize, subtle, and serde feature bridges.
- `tests.rs`: the existing core unit tests.

## Mechanical Differences

The source-level public declaration inventory differs only because:

- `ct` changed from an inline module declaration to `pub mod ct;`;
- private implementation modules are re-exported from the crate root to keep
  existing public paths;
- rustfmt folded four previously multi-line `SecretPool` method declarations
  onto one line.

The semantic public surface is unchanged. The normalized declaration verifier
accounts only for those structural differences.

The package file list for `sanitization` now contains the module files above.
All other workspace package file lists remain identical to the 1.2.5 baseline.

The unsafe source inventory remains exactly 125 normalized lines across the
workspace, including 122 in the core crate and three compile-time derive error
messages. Unsafe code was moved, not added.

Private symbols necessarily acquired new module-qualified names. In
particular, `sanitization::wipe::volatile_wipe` is now
`sanitization::wipe_backend::volatile_wipe`. The codegen gate checks the new
private symbol while retaining all existing volatile-store, optimizer-barrier,
mask-generation, assembly-comparison, cache-flush, and memcmp/bcmp-absence
checks.

## Verification

Run the checkpoint-specific structural comparison:

```bash
scripts/verify-2.0-module-split.py
```

Run the normal source and codegen checks:

```bash
scripts/capture-2.0-baseline.py --check
scripts/verify-codegen.sh
cargo test -p sanitization --all-features
```

Cross-target compilation covers the existing native, WASM, and bare-metal
feature selections. No target or feature support is intentionally changed by
this checkpoint.
