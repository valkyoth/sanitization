# CP-05 Fixed Allocation And Aggregate Guidance

Status: implementation review record

Base commit: `e3a5cc9`

Checkpoint: `CP-05`

CP-05 adds a runtime-length secret byte container whose backing allocation
cannot grow or shrink after construction. It also corrects aggregate guidance
around generic boxes and vectors.

## `SecretBoxBytes`

`SecretBoxBytes` owns one `Box<[u8]>` and is available with `alloc`.

The public lifecycle includes:

- zeroed, boxed-slice, borrowed-slice, infallible generator, and fallible
  generator constructors;
- direct shared and mutable slice exposure;
- same-length slice, boxed-slice, infallible generator, and fallible generator
  replacement;
- explicit copying into a same-length caller buffer;
- immediate clear, clear-on-drop, and consuming clear;
- native public-length CT equality;
- optional serde, zeroize, and subtle interop.

The type does not implement growth, truncation, append, ownership extraction,
ordinary equality, dereference traits, cloning, copying, or value-printing
debug output.

## Replacement Invariant

Every replacement requires the original public length. A complete
clear-on-drop replacement is constructed before the old allocation is cleared.
Only then are the boxed allocations exchanged. Generator failure or panic
leaves the old value unchanged and clears partial replacement storage.

A rejected boxed-slice replacement is first wrapped in `SecretBoxBytes`, so the
rejected allocation is cleared before the length error is returned.

## Serde Ingestion

Borrowed byte inputs copy directly into a fixed box. Owned byte buffers are
copied and then have their full vector capacity cleared. Sequence inputs use
`SecretVec` as a managed-growth temporary, copy once into the final fixed box,
and clear the temporary on drop. The existing public 1 MiB default byte limit
applies.

This protects crate-owned intermediates. A serializer implementation may have
created ordinary buffers before invoking the visitor.

## Aggregate Guidance

The documentation now distinguishes:

- `SecretBoxBytes` for a fixed runtime length;
- `SecretVec` and `SecretString` for managed wipe-before-grow storage;
- mapped locked and guarded containers for native platform protection.

Generic `Vec<T>` sanitization clears live elements and the current allocation
capacity but cannot recover historical allocations already released by
caller-controlled operations. Generic `Box<T>` sanitization is field-wise and
does not claim to clear unknown representation padding.

## Verification

The checkpoint includes:

- fixed-allocation ownership, exposure, copy, clear, and CT tests;
- same-length replacement and length-rejection tests;
- panic and fallible-generator preservation tests;
- serde redaction and ingestion coverage;
- native storage-contract, zeroize, and subtle interop coverage;
- codegen checks that `SecretBoxBytes::clear_secret` dispatches once to the
  audited wipe path and that compiler/hardware fences remain outside the
  per-byte wipe loop;
- normal repository checks and the Rust 1.90.0 MSRV check.
