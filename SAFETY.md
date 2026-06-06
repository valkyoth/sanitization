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

- The raw pointer and length must come from a live mutable slice or the full
  capacity of an owned contiguous allocation.
- Every computed pointer is allocated and writable for exactly one byte write,
  including spare capacity that is not initialized.
- The function never reads through the raw pointer.
- The caller-facing APIs provide exclusive mutable access while wiping.
- For `Vec<u8>` and `String`, the pointer and length passed to the raw wipe
  cover the full allocation capacity, not only the initialized length. This
  writes zero bytes into allocated but possibly uninitialized spare capacity
  without reading it.

### `String::as_mut_ptr`

Location: `unsafe_wipe::volatile_sanitize_string`

Purpose: obtain a raw pointer to the `String` allocation so its full capacity
can be zeroed with volatile writes before calling `clear()`.

Invariant:

- `text.as_mut_ptr()` provides a pointer valid for `text.capacity()` bytes.
- Every byte in the allocation capacity is overwritten with `0`.
- `0` is valid UTF-8, so initialized string contents remain valid during and
  after wiping.
- Exclusive `&mut String` access prevents concurrent reads or writes while the
  allocation is wiped.
- The raw pointer is not exposed to the caller.

## Non-Goals

This unsafe boundary intentionally does not implement stack scanning, cache
flushes, SIMD clearing, memory locking, guard pages, or platform syscalls. Those
features need separate target-specific designs and tests.
