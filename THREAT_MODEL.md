# Threat Model

This crate focuses on reducing secret lifetime and accidental disclosure inside
Rust applications.

## In Scope

- Clear-on-drop containers for fixed-size and heap-allocated secrets.
- Avoiding accidental `Copy`, `Clone`, direct slice exposure, equality, and
  secret-printing `Debug` implementations for crate-owned secret types.
- Closure-based accessors that keep normal use sites narrow.
- Best-effort safe clearing for ordinary mutable byte slices.
- Best-effort clearing of `SecretVec` and `SecretString` initialized bytes and
  spare heap capacity before freeing their allocations.
- Optional volatile byte clearing for existing ordinary buffers when the
  `unsafe-wipe` feature is explicitly enabled and called.

## Out of Scope

- Preventing secrets from entering swap, hibernation files, crash dumps, logs,
  tracing systems, or external libraries.
- Preventing disclosure through a debugger, `/proc/<pid>/mem`, ptrace, kernel
  compromise, DMA, malicious firmware, or privileged co-tenants.
- Soundly scrubbing old stack frames, prior Rust move copies, CPU registers, CPU
  caches, SIMD registers, allocator metadata, or third-party library copies.
- Clearing temporary stack copies after process abort. Closure helpers clear
  their temporaries on normal return and unwinding paths only; `panic = "abort"`
  and other abort paths skip destructors and post-closure cleanup.
- Memory locking, guard pages, cache-line flushing, platform syscalls, and
  assembly-level hardening.

## Design Position

The default API tries to avoid creating hard-to-clear copies in the first place.
`SecretBytes<N>` is the strongest default path because the storage is controlled
by this crate from initialization to drop. `SecretVec` and `SecretString` are
more practical for dynamic integration boundaries but still cannot control
copies made before data enters the container.

The `unsafe-wipe` feature is for existing ordinary memory. It improves clearing
resistance against compiler optimization by using volatile byte writes, but it
does not solve broader process, OS, hardware, or allocator threats.

Safe best-effort clearing can still be weakened by aggressive whole-program
optimization. Use the explicit `unsafe-wipe` APIs when optimizer-resistant
clearing of ordinary buffers is required.

With `unsafe-wipe`, `SecretBytes::expose_secret_volatile` uses volatile writes
for its temporary stack copy on normal return and unwinding paths. It is still
not a solution for aborting processes.
