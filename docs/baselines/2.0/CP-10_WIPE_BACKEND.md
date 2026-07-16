# CP-10 Canonical Wipe Backend

Status: implementation review record

Base commit: `be1cbbb`

Checkpoint: `CP-10`

CP-10 establishes one safe direct-wipe API and one private backend architecture.

## Public API

`sanitization::wipe` is the only direct-wipe namespace. It provides:

- `bytes` and `array` in every build;
- `vec` and `string` with `alloc`;
- compliance-oriented multi-pass variants with `multi-pass-clear`;
- the `Wipe` trait for supported ordinary buffers; and
- `WipeOnDrop<T>` for explicit clear-on-drop ownership.

The old `unsafe_wipe`, `volatile_sanitize_*`, best-effort aliases, volatile
constructor aliases, and no-op `unsafe-wipe` feature were removed. Those names
did not select distinct implementations or guarantees.

## Private Backend

All public helpers and crate-owned containers dispatch through
`wipe_backend::erase`. The backend uses a private sealed `ErasureBackend`
implemented only by the crate's `VolatileRam` backend. Downstream code cannot
inject a weaker implementation or select a backend through public API.

Native clearing uses one volatile byte store per address. WASM retains the
existing non-inlined function-pointer boundary as a best-effort mitigation and
keeps its documented reduced target guarantee.

## Fence Policy

This checkpoint does not weaken ordering. Every pass retains:

1. a compiler `SeqCst` fence before the volatile loop;
2. a compiler `SeqCst` fence after the loop; and
3. a hardware `SeqCst` fence after completion.

Reducing the hardware fence requires separate target-specific codegen, native
evidence, and external review. Multi-pass clearing remains policy/compliance
behavior rather than a stronger ordinary-DRAM security claim.

## Verification

The codegen gate checks the canonical backend symbol, volatile stores, both
compiler fences, the hardware fence, and one backend dispatch from
`SecretBoxBytes::clear_secret`. It also rejects reintroduction of the removed
best-effort alias.
