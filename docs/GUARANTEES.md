# Guarantees

This document defines the security claims this repository is willing to make.
It should be read together with `docs/NON_GUARANTEES.md`, `docs/THREAT_MODEL.md`,
`docs/SAFETY.md`, `docs/BARRIERS.md`, `docs/TARGETS.md`, and `docs/EVIDENCE.md`.

The short version: `sanitization` provides dependency-free secret ownership,
optimizer-resistant clearing, and data-oblivious primitives under documented
target and feature conditions. It does not claim identical wall-clock timing or
complete protection against every process, OS, hardware, compiler, or runtime
side channel.

## Secret Ownership

For crate-owned secret containers, the crate guarantees:

- secret-owning containers do not implement `Copy`;
- secret-owning containers do not expose raw secret references through `Debug`;
- container `Debug` output is redacted;
- ordinary equality for secret containers is avoided in favor of explicit
  comparison APIs;
- public exposure goes through narrow closure-based APIs where practical;
- drop-time clearing is installed for the crate-owned secret containers.

These guarantees apply to bytes owned by the crate. They do not revoke copies
that were already created by caller code, external libraries, deserializers,
formatters, syscalls, kernels, runtimes, debuggers, or hardware.

## Clearing

All default clearing paths bottom out in volatile byte writes through the
audited wipe boundary. This is the crate's primary clearing guarantee:

- clearing stores are emitted as volatile operations on native targets;
- compiler fences and hardware fences are used around the wipe boundary;
- heap containers wipe initialized bytes and spare capacity that the crate can
  reach before releasing the allocation;
- replacement helpers clear the old value before installing the new value where
  the API can do so safely;
- explicit volatile helper functions are available for ordinary byte buffers.

The guarantee is about bytes reachable through the current allocation or
container. It does not cover allocator metadata, stale copies from earlier
Rust moves, prior stack frames, external buffers, or allocations already freed
before they entered a crate-owned type.

## Locked And Guarded Storage

When `memory-lock` is enabled on supported native targets, locked containers
attempt to keep their owned secret storage out of swap/pagefile paths using the
platform's memory-locking facility. On Linux-family targets, supported
constructors also request `MADV_DONTDUMP`, and when available they request
`MADV_DONTFORK` unless the platform-specific backend documents otherwise.

The stronger native storage types guarantee:

- locked mappings are cleared before unlock/unmap on drop;
- failed constructors do not intentionally leak successfully created mappings;
- canary-enabled mappings verify prefix/suffix integrity before exposure;
- guarded dynamic storage places inaccessible guard pages around the writable
  region on supported native targets.

When `require-fork-exclusion` is enabled, native locked constructors fail
closed on platforms where fork-inheritance exclusion is unavailable.

On WASM, `memory-lock` is available only with `wasm-compat` and is an
API-compatibility backend. It guarantees owned WASM storage and drop-time
clearing, not host OS memory locking.

## Data-Oblivious Primitives

The native `sanitization::ct` module is designed around this claim:

> No secret-dependent control flow or secret-dependent memory access inside
> the provided primitives, under the documented compiler, target, feature, and
> release-profile conditions.

The data-oblivious guarantees apply to the crate's own primitives:

- `ct::Choice` and masks normalize secret-derived boolean-like values;
- fixed-size equality and ordering scan every public element;
- public-length equality treats length as public metadata and rejects length
  mismatch without claiming the length is secret;
- `ct::CtOption` and `ct::CtResult` keep success/failure state inside the CT
  domain until explicit declassification;
- `ct::oblivious_lookup` scans the full public table length instead of indexing
  directly by a secret index;
- conditional copy, swap, and slice selection operate over public lengths.

Turning a secret-derived value into normal control flow must happen through an
explicit `declassify(reason)` boundary. The reason string is not a runtime
security mechanism; it exists to make public-branch decisions searchable and
reviewable.

## Evidence

The repository carries release evidence in two forms:

- human-readable evidence in `docs/EVIDENCE.md`;
- machine-readable evidence in `docs/ct-evidence.json`, validated by
  `scripts/verify-evidence.py`.

The current evidence includes unit tests, release codegen checks, Miri where
available, and bounded Kani proof harnesses for selected wipe, comparison,
ordering, selection, and allocation-arithmetic properties. These are evidence
for specific claims, not blanket proof of all timing behavior on all targets.

