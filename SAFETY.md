# Unsafe Boundary

The crate root uses `#![deny(unsafe_code)]` and
`#![deny(unsafe_op_in_unsafe_fn)]`.

Unsafe code is allowed only inside the private `src/lib.rs` module `wipe`.
Public APIs, including `unsafe_wipe`, are safe wrappers around that internal
backend.

## Unsafe Operations

### `ptr::write_volatile`

Location: `wipe::volatile_wipe`

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
can be passed to `wipe::volatile_wipe` before calling `clear()`.

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
