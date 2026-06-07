# Threat Model

This crate focuses on reducing secret lifetime and accidental disclosure inside
Rust applications.

## In Scope

- Clear-on-drop containers for fixed-size and heap-allocated secrets.
- Avoiding accidental `Copy`, `Clone`, direct slice exposure, equality, and
  secret-printing `Debug` implementations for crate-owned secret types.
- Closure-based accessors that keep normal use sites narrow.
- Volatile clearing for ordinary mutable byte slices.
- Volatile clearing of `SecretVec` and `SecretString` initialized bytes and
  spare heap capacity before freeing their allocations.
- Explicit volatile helper APIs for existing ordinary buffers.
- Optional platform memory locking for `LockedSecretBytes<N>` when the
  `memory-lock` feature is enabled on supported Linux, Android, macOS, iOS,
  Windows, and BSD targets.
- Optional Linux `MADV_DONTDUMP` on locked secret mappings to reduce ordinary
  core-dump exposure.
- Optional Linux `MADV_DONTFORK` on locked secret mappings to reduce accidental
  inheritance across `fork`.
- Optional x86_64 assembly-backed equal-length comparison when the
  `asm-compare` feature is enabled.
- Optional x86_64 volatile-clear plus cache-line eviction when the
  `cache-flush` feature is enabled.
- Optional `std` lifetime enforcement for fixed-size secrets with
  `ExpiringSecretBytes<N>`.
- Optional platform guard-page storage for dynamic byte secrets with
  `GuardedSecretVec` on supported Linux, Android, macOS, iOS, Windows, and BSD
  targets.
- Optional platform memory locking for `GuardedSecretVec` when both
  `guard-pages` and `memory-lock` are enabled.

## Out of Scope

- Preventing secrets from entering hibernation files, crash dumps, logs, tracing
  systems, or external libraries.
- Preventing swap/pagefile exposure on unsupported targets or for values not
  stored inside `LockedSecretBytes<N>`.
- Preventing disclosure through a debugger, `/proc/<pid>/mem`, ptrace, kernel
  compromise, DMA, malicious firmware, or privileged co-tenants.
- Revoking external copies after a secret has already been exposed to caller
  code or third-party libraries.
- Soundly scrubbing old stack frames, prior Rust move copies, CPU registers,
  unrelated CPU cache lines, SIMD registers, allocator metadata, or third-party
  library copies.
- Clearing temporary stack copies after process abort. Closure helpers clear
  their temporaries on normal return and unwinding paths only; `panic = "abort"`
  and other abort paths skip destructors and post-closure cleanup.
- Cache-line flushing outside x86_64.

## Design Position

The default API tries to avoid creating hard-to-clear copies in the first place.
`SecretBytes<N>` is the strongest default path because the storage is controlled
by this crate from initialization to drop. `SecretVec` and `SecretString` are
more practical for dynamic integration boundaries but still cannot control
copies made before data enters the container.

Volatile byte writes improve clearing resistance against compiler optimization,
but they do not solve broader process, OS, hardware, or allocator threats.

With the `memory-lock` feature on supported Linux, Android, macOS, iOS,
Windows, and BSD targets, `LockedSecretBytes<N>` uses a private platform
mapping and memory locking to reduce the chance that the secret's storage
reaches swap or pagefiles. Linux also applies `MADV_DONTDUMP` and
`MADV_DONTFORK` to reduce ordinary core-dump exposure and accidental
inheritance across `fork`. This is a high-assurance building block, not a
complete OS secrecy guarantee. Resource
limits or policy can make setup fail, and locked memory can still be exposed
through hibernation, nonstandard crash dump mechanisms, debuggers, privileged
reads, DMA, malicious firmware, or copies made before data enters the locked
container.

With the `asm-compare` feature on x86_64, equal-length comparisons use an
inline-assembly loop. This gives the comparison body a stronger compiler
boundary, but it does not hide length metadata and does not claim protection
against all microarchitectural side channels.

With the `cache-flush` feature on x86_64, explicit clear-and-flush helpers
volatile-clear the target storage and then execute `clflush` over the covered
cache lines. This can evict the addressed lines from CPU caches, but it does not
prove all historical copies are gone and does not solve general
microarchitectural side channels. When combined with `guard-pages`,
`GuardedSecretVec` can explicitly clear and flush its full writable data region.

With the `std` feature, `ExpiringSecretBytes<N>` checks a configured maximum age
at access time. Expired values are cleared before access is rejected. This is an
API-level policy control; it does not revoke bytes that callers copied out
before expiration and does not run in the background.

With the `guard-pages` feature on supported Linux, Android, macOS, iOS,
Windows, and BSD targets, `GuardedSecretVec` stores dynamic secret bytes
between inaccessible pages. This can turn linear overreads or overwrites beyond
the mapped data pages into faults, but it does not catch logical overreads
inside the writable capacity and does not protect copies made before data
enters the guarded container.

When both `guard-pages` and `memory-lock` are enabled, `GuardedSecretVec`
locked constructors also lock the writable data pages. Linux additionally calls
`MADV_DONTDUMP` and `MADV_DONTFORK`. This combines guard-page fault isolation
with swap/pagefile reduction for dynamic secrets, but all memory-lock limits
still apply.

`SecretBytes::expose_secret_volatile` makes the volatile temporary-copy cleanup
explicit at the call site. It clears on normal return and unwinding paths, but
it is still not a solution for aborting processes.
