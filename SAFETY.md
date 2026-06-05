# Unsafe Boundary

Default builds use `#![forbid(unsafe_code)]`.

When the `unsafe-wipe` feature is enabled, unsafe code remains denied at the
crate root and is allowed only inside `src/lib.rs` module `unsafe_wipe`.

## Unsafe Operations

### `ptr::write_volatile`

Location: `unsafe_wipe::volatile_wipe_raw`

Purpose: force one byte store per address so clearing ordinary mutable buffers
is not optimized away as dead memory writes.

Invariant:

- The raw pointer and length must come from a live mutable slice or owned
  contiguous buffer.
- Every computed pointer is in bounds for exactly one byte write.
- The function never reads through the raw pointer.
- The caller-facing APIs provide exclusive mutable access while wiping.
- For `Vec<u8>`, the pointer and length passed to the raw wipe cover the full
  allocation capacity, not only the initialized length. This writes zero bytes
  into allocated but possibly uninitialized spare capacity without reading it.

### `String::as_bytes_mut`

Location: `unsafe_wipe::volatile_sanitize_string`

Purpose: access a `String` as mutable bytes so its allocation can be zeroed
before calling `clear()`.

Invariant:

- Every byte is overwritten with `0`.
- `0` is valid UTF-8, so the `String` remains valid during and after wiping.
- The mutable byte slice is not exposed to the caller.

## Non-Goals

This unsafe boundary intentionally does not implement stack scanning, cache
flushes, SIMD clearing, memory locking, guard pages, or platform syscalls. Those
features need separate target-specific designs and tests.
