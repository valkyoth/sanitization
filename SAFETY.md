# Unsafe Boundary

The crate root uses `#![deny(unsafe_code)]` and
`#![deny(unsafe_op_in_unsafe_fn)]`.

Unsafe code is allowed only inside narrow `src/lib.rs` modules:

- `wipe`, the default volatile clear backend;
- `memory_lock`, available only with the `memory-lock` feature on supported
  Linux, Android, macOS, iOS, Windows, and BSD targets.
- `compare_asm`, available only with the `asm-compare` feature on x86_64
  outside Miri.
- `cache_flush`, available only with the `cache-flush` feature on x86_64
  outside Miri.
- `guard_pages`, available only with the `guard-pages` feature on supported
  Linux, Android, macOS, iOS, Windows, and BSD targets outside Miri.

Public APIs, including `unsafe_wipe`, are safe wrappers around those internal
backends.

## Unsafe Operations

### `ptr::write_volatile`

Location: `wipe::volatile_wipe`, `wipe::volatile_fill`

Purpose: force one byte store per address so clearing ordinary mutable buffers
is not optimized away as dead memory writes. With `multi-pass-clear`,
`volatile_fill` uses the same primitive to write a caller-provided byte pattern
between zeroing passes.

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
- With `multi-pass-clear`, the same pointer validity rules apply to all three
  passes: zero, `0xFF`, zero.

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

### Platform memory-lock mappings and mapped-memory references

Location: `memory_lock`

Purpose: provide dependency-free platform memory locking for
`LockedSecretBytes<N>` and pooled `SecretPool<N, SLOTS>` slots without routing
secret bytes through the Rust global allocator. Linux uses raw syscalls;
Android, macOS, iOS, and BSD use system C ABI entry points; Windows uses
Kernel32 virtual memory APIs.

Operations:

- Linux: `mmap` creates a private anonymous read/write mapping,
  `madvise(MADV_DONTDUMP)` asks the kernel to exclude that mapping from
  ordinary Linux core dumps, `madvise(MADV_DONTFORK)` asks the kernel to
  prevent accidental fork inheritance, `mlock` locks the mapping, and
  `munlock`/`munmap` release it.
- Android, macOS, iOS, and BSD: system `mmap` creates a private anonymous
  read/write mapping, `mlock` locks it, and `munlock`/`munmap` release it.
  FreeBSD additionally requests core-dump exclusion with `MADV_NOCORE`.
  Non-Linux Unix targets do not apply fork-inheritance exclusion.
- Windows: `VirtualAlloc` creates a private read/write region, `VirtualLock`
  locks it, and `VirtualUnlock`/`VirtualFree` release it.
- raw pointers from the mapping are converted to byte slices and fixed-size
  byte-array references while the mapping is live.

Invariant:

- The module is compiled only for supported OS targets with the `memory-lock`
  feature enabled. Linux support is limited to `x86_64` and `aarch64` raw
  syscall ABIs.
- Linux syscall register assignments follow the Linux syscall ABI for the
  target architecture.
- Non-Linux Unix targets use C ABI declarations without adding a Rust `libc`
  crate dependency.
- Windows targets use Kernel32 ABI declarations without adding a Rust Windows
  bindings dependency.
- The mapped pointer is non-null and owned by exactly one
  `LockedSecretBytes<N>` value.
- The Rust value stores only pointer metadata, so moving it does not move or
  copy the secret byte allocation.
- The mapping length is at least `N` bytes when `N > 0`.
- With `canary-check`, non-empty `LockedSecretBytes<N>` mappings reserve an
  8-byte prefix canary and 8-byte suffix canary around the `N` secret bytes.
  The checked payload length is `N + 16`, rounded to the platform page
  granule. The public data pointer is offset past the prefix canary.
- With `canary-check`, non-empty `SecretPool<N, SLOTS>` slots reserve the same
  8-byte prefix and suffix canaries inside each slot stride. Allocation writes
  fresh canaries before returning a slot handle, and slot drop clears the full
  stride before releasing the atomic bitmap flag.
- `canary-check` derives the expected canary from the mapping base address and
  a fixed mask, or from the pool slot base address for pooled slots. This avoids
  RNG and dependency requirements while making the canary value mapping-specific
  under ASLR.
- With `random-canary`, the expected canary is generated once from the
  operating-system CSPRNG and stored in the Rust owner or slot metadata. The
  prefix and suffix copies remain in the locked or guarded mapping beside the
  secret bytes. Random generation failure is reported as a `Random` platform
  operation error where the API can return one; `SecretPool` also provides
  `try_allocate` for explicit slot-allocation error handling.
- Canary writes happen only after platform mapping setup and locking succeed.
- Canary verification compares both prefix and suffix with the expected value
  using the crate constant-time slice comparison helper and boolean `&`, so both
  canaries are checked without data-dependent early exit at this layer.
- If canary verification fails, the full mapping is volatile-cleared before the
  checked API returns `CanaryCorruptedError` or the legacy API panics.
- Secret bytes are not copied into the mapping until platform setup succeeds:
  Linux dump exclusion, fork exclusion, and `mlock`;
  FreeBSD core-dump exclusion and `mlock`; Android/macOS/iOS/other-BSD
  `mlock`; Windows `VirtualLock`.
- Fallible direct generation writes only after mapping setup succeeds; partial
  generated bytes are owned by `LockedSecretBytes<N>` and are volatile-cleared
  on error return.
- Replacement helpers stage the new value in a fresh locked mapping before
  clearing and swapping out the old mapping. If mapping setup or generation
  fails, the old locked value remains unchanged.
- `&mut self` is required for mutation and clearing.
- Drop volatile-clears the full mapping before attempting platform unlock and
  release.
- Drop ignores unlock/unmap errors because destructors cannot report failure.
- `SecretPool<N, SLOTS>` owns exactly one locked mapping. `N * SLOTS` is
  checked for overflow before mapping, then rounded to the platform page
  granule.
- The pool tracks live slots with `[AtomicBool; SLOTS]`. Slot allocation uses a
  compare-exchange from unused to used, preventing two live safe handles for the
  same slot.
- Each `SecretPoolSlot` carries a lifetime-bound shared borrow of the pool, so
  Rust prevents the pool from being dropped or mutably cleared while slots are
  live.
- Slot pointer arithmetic is constrained to `slot_index * N`, where
  `slot_index < SLOTS` and construction already checked the total size.
- Slot mutation requires `&mut SecretPoolSlot`; read-only exposure uses
  closure-based access.
- Dropping a slot volatile-clears exactly that slot before marking it available
  again with release ordering.
- Dropping the pool requires no live slots, volatile-clears the full mapping,
  then unlocks and releases it with the same platform backend as
  `LockedSecretBytes<N>`.

### x86_64 inline assembly comparison

Location: `compare_asm`

Purpose: provide an optional compiler boundary for equal-length byte comparison
on x86_64.

Operation:

- The public comparison helper checks length equality before calling the
  assembly path.
- The assembly loop reads one byte from each slice, XORs them, ORs the result
  into an accumulator, then advances both pointers.
- The loop count is the already-checked public slice length.
- Unsupported targets, Miri, and builds without `asm-compare` use the portable
  Rust fallback.

Invariant:

- Both slices are valid for the same number of readable bytes.
- The assembly loop does not write memory.
- The zero-length path does not dereference either pointer.
- All output registers are initialized on every branch path.
- Length remains public metadata and mismatched lengths return before the
  assembly path.

### x86_64 cache-line flush instructions

Location: `cache_flush`

Purpose: provide explicit volatile-clear plus cache-line eviction helpers for
call sites that need x86_64 cache hardening.

Operation:

- Public sanitization helpers first route through the crate's volatile wipe
  backend.
- The module aligns the provided address range down to 64-byte cache-line
  boundaries.
- The module executes `clflush` for every covered cache line, followed by
  `mfence`.
- `GuardedSecretVec::clear_secret_and_flush` clears the full writable data
  region before flushing the cache lines covering that same region.
- Unsupported targets, Miri, and builds without `cache-flush` do not expose the
  module.

Invariant:

- The pointer and length come from a live slice or owned contiguous allocation.
- The zero-length path does not execute `clflush`.
- `clflush` does not read or write through the Rust pointer; it asks the CPU to
  evict the addressed cache line.
- The module assumes 64-byte x86_64 cache-line stepping. This can over-flush
  adjacent bytes in the same cache line but does not read or write them through
  Rust references.
- `mfence` orders the flush operations before later memory operations.

### Platform guard-page mappings

Location: `guard_pages`

Purpose: provide dynamic byte storage between inaccessible pages without using
the Rust global allocator for secret bytes.

Operations:

- Linux/Android/macOS/iOS/BSD: `mmap(PROT_NONE)` creates one private
  anonymous mapping containing a leading guard page, writable data pages, and a
  trailing guard page. `mprotect(PROT_READ | PROT_WRITE)` enables access only
  for the middle data pages.
- Windows: `VirtualAlloc(PAGE_NOACCESS)` creates one private region containing
  leading guard pages, writable data pages, and trailing guard pages.
  `VirtualProtect(PAGE_READWRITE)` enables access only for the middle data
  pages.
- Raw pointers from the writable middle region are converted into slices for
  initialized length or full writable capacity.
- When `memory-lock` is also enabled, locked constructors apply supported
  platform memory-lock policies on the writable data pages before copying
  secret bytes into them. Linux also applies `MADV_DONTDUMP` and
  `MADV_DONTFORK`; FreeBSD also applies `MADV_NOCORE`.
- `from_fn` constructors generate bytes directly into the writable data pages
  after mapping setup and optional lock policies have succeeded.
- `try_from_fn` constructors generate bytes directly into the writable data
  pages and clear the full writable region on generator errors.
- With `canary-check`, guarded mappings reserve an 8-byte prefix canary before
  the payload and an 8-byte suffix canary immediately after the initialized
  payload. Public payload pointers are offset past the prefix canary. Exposure,
  mutation, growth, replacement, and comparison verify both canaries before
  reading or modifying the secret payload.
- `replace_from_slice` either clears the current writable region before
  in-place replacement, or creates a new guarded mapping with the same lock
  state and clears the old mapping before it is unmapped.
- Generated replacement creates a new guarded mapping with the same lock state
  before clearing the old mapping. Fallible generated replacement leaves the
  old mapping unchanged if setup or generation fails.
- Growth allocates a new guarded mapping, copies initialized bytes into it,
  volatile-clears the old writable region, swaps metadata, and lets the old
  mapping unlock and unmap during drop. Locked mappings grow into locked
  replacement mappings.
- Drop volatile-clears the full writable region, unlocks locked mappings, and
  then releases the platform mapping.

Invariant:

- The module is compiled only for supported OS targets with the `guard-pages`
  feature enabled outside Miri. Linux support is limited to `x86_64` and
  `aarch64` raw syscall ABIs.
- Linux syscall register assignments follow the Linux syscall ABI for the
  target architecture.
- The base mapping pointer is owned by exactly one `GuardedSecretVec`.
- The writable data pointer is one platform page granule after the mapping
  base.
- The writable data length is rounded to a platform page granule. Linux uses
  4 KiB on `x86_64`. Linux `aarch64` reads `AT_PAGESZ` from
  `/proc/self/auxv` with raw syscalls, caches the result, and falls back to
  64 KiB if detection fails or returns an invalid value. Android/macOS/iOS/BSD
  use `getpagesize`; Windows uses `GetSystemInfo`.
- `len <= data_capacity` is preserved before any slice is created.
- The `locked` flag is set only after platform lock setup succeeds. On Linux
  this includes `MADV_DONTDUMP`, `MADV_DONTFORK`, and `mlock`.
  On FreeBSD this includes `MADV_NOCORE` and `mlock`. Other non-Linux Unix
  targets currently apply `mlock` only.
- Guard pages are not locked because they never contain secret bytes.
- `&mut self` is required for mutation and clearing.
- Drop ignores unlock and unmap/free errors because destructors cannot report
  failure.

## Read-Once Secrets

`ReadOnceSecret<T>` uses an `AtomicBool` consumed flag and an `UnsafeCell<T>`.
The unsafe boundary is intentionally small:

- `consume` and `consume_mut` first claim access with
  `AtomicBool::swap(true, Ordering::AcqRel)`.
- Only the caller that observes the previous value as `false` receives access
  to the inner `T`; every later caller receives `AlreadyConsumedError`.
- The successful caller clears the inner value immediately after the closure
  returns. If the closure unwinds, `Drop` still clears the inner value.
- `ReadOnceSecret<T>` is `Sync` when `T: Send`, following the same runtime
  exclusivity principle as lock-like containers: shared references may race to
  claim the value, but only one can access it.
- `secure_sanitize` and `into_cleared` mark the value consumed before clearing
  it, so later consume attempts fail closed.

## Safe Temporary Buffers

`SecretBytes::replace_from_array`, `ExpiringSecretBytes::replace_from_array`,
and `LockedSecretBytes::replace_from_array` take ownership of a `[u8; N]`,
copy it into the target secret storage, and clear the owned input array with
the volatile wipe backend. Locked array replacement uses a fresh locked mapping;
if mapping setup fails, the owned input array is still cleared and the old
locked value remains unchanged.

`SecretBytes::replace_from_fn` and `try_replace_from_fn` stage generated bytes
inside a fresh clear-on-drop `SecretBytes<N>` value before clearing and swapping
out the old value. If generation returns an error or unwinds, the old value
remains unchanged and partial generated bytes are cleared.

`SecretVec::from_vec`, `SecretString::from_string`,
`SecretVec::replace_from_vec`, and `SecretString::replace_from_string` take
ownership of an existing heap allocation without copying the new bytes. For
replacement, the old allocation is cleared first. In all cases, the transferred
allocation becomes owned by the secret container, so its full capacity is
covered by later clear/drop operations.

`SecretString::from_chars`, `try_from_chars`, `replace_from_chars`, and
`try_replace_from_chars` generate valid UTF-8 by accepting `char` values. Each
character is encoded through a four-byte stack buffer, copied into the secret
heap allocation, and then the stack buffer is immediately cleared with the same
volatile wipe backend used elsewhere in the crate. Fallible generation keeps
partial text inside a clear-on-drop `SecretString` local, so generated heap
bytes are cleared if the generator returns an error or unwinds.

`SecretString::try_with_secret_mut` exposes mutable text as `&mut str` rather
than mutable bytes. This keeps UTF-8 validity enforced by safe Rust while still
allowing in-place text edits through closure-scoped access.

## Non-Goals

This unsafe boundary intentionally does not implement stack scanning, cache
flushes for non-x86_64 targets, SIMD clearing, or broad platform memory
policy. Memory locking is explicit, feature-gated, platform-limited, and still
does not protect against crash dumps, hibernation, privileged reads, DMA, or
external copies.
Assembly-backed comparison is x86_64-only and does not make length private.
Cache-line eviction is explicit, x86_64-only, and does not prove full CPU-cache
or microarchitectural side-channel secrecy.
Guard pages are feature-gated, platform-limited, and detect crossings outside
the writable mapped data pages; they do not catch logical overreads that remain
inside capacity.

## Thread Safety

`LockedSecretBytes<N>` and `GuardedSecretVec` explicitly implement `Send`
because each value exclusively owns its private platform mapping. Moving the
Rust value to another thread moves only pointer metadata; it does not move or
copy the mapped secret bytes. Mutation and clearing still require `&mut self`.

These mapped containers intentionally do not implement `Sync`. Concurrent
shared access should be provided by caller-owned synchronization such as
`Mutex<T>` when cross-thread sharing is required.
