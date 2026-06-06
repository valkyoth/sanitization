# Unsafe Boundary

The crate root uses `#![deny(unsafe_code)]` and
`#![deny(unsafe_op_in_unsafe_fn)]`.

Unsafe code is allowed only inside narrow `src/lib.rs` modules:

- `wipe`, the default volatile clear backend;
- `memory_lock`, available only with the `memory-lock` feature on supported
  Linux targets.

Public APIs, including `unsafe_wipe`, are safe wrappers around those internal
backends.

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

### Linux raw syscalls and mapped-memory references

Location: `memory_lock`

Purpose: provide dependency-free Linux memory locking for
`LockedSecretBytes<N>` without routing secret bytes through the Rust global
allocator.

Operations:

- `mmap` creates a private anonymous read/write mapping.
- `mlock` asks the kernel to keep that mapping resident instead of swapping it.
- `munlock` releases the lock during drop.
- `munmap` releases the mapping during drop.
- raw pointers from the mapping are converted to byte slices and fixed-size
  byte-array references while the mapping is live.

Invariant:

- The module is compiled only for Linux `x86_64` and `aarch64` with the
  `memory-lock` feature enabled.
- Syscall register assignments follow the Linux syscall ABI for the target
  architecture.
- The mapped pointer is non-null and owned by exactly one
  `LockedSecretBytes<N>` value.
- The Rust value stores only pointer metadata, so moving it does not move or
  copy the secret byte allocation.
- The mapping length is at least `N` bytes when `N > 0`.
- `&mut self` is required for mutation and clearing.
- Drop volatile-clears the full mapping before attempting `munlock` and
  `munmap`.
- Drop ignores unlock/unmap errors because destructors cannot report failure.

## Non-Goals

This unsafe boundary intentionally does not implement stack scanning, cache
flushes, SIMD clearing, guard pages, or broad platform memory policy. Memory
locking is explicit, Linux-only, feature-gated, and still does not protect
against crash dumps, hibernation, privileged reads, DMA, or external copies.
