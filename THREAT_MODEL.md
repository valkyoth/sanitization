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
- Optional Linux memory locking for `LockedSecretBytes<N>` when the
  `memory-lock` feature is enabled on supported architectures.

## Out of Scope

- Preventing secrets from entering hibernation files, crash dumps, logs, tracing
  systems, or external libraries.
- Preventing swap/pagefile exposure on unsupported targets or for values not
  stored inside `LockedSecretBytes<N>`.
- Preventing disclosure through a debugger, `/proc/<pid>/mem`, ptrace, kernel
  compromise, DMA, malicious firmware, or privileged co-tenants.
- Soundly scrubbing old stack frames, prior Rust move copies, CPU registers, CPU
  caches, SIMD registers, allocator metadata, or third-party library copies.
- Clearing temporary stack copies after process abort. Closure helpers clear
  their temporaries on normal return and unwinding paths only; `panic = "abort"`
  and other abort paths skip destructors and post-closure cleanup.
- Guard pages, cache-line flushing, and assembly-level hardening.

## Design Position

The default API tries to avoid creating hard-to-clear copies in the first place.
`SecretBytes<N>` is the strongest default path because the storage is controlled
by this crate from initialization to drop. `SecretVec` and `SecretString` are
more practical for dynamic integration boundaries but still cannot control
copies made before data enters the container.

Volatile byte writes improve clearing resistance against compiler optimization,
but they do not solve broader process, OS, hardware, or allocator threats.

With the `memory-lock` feature on supported Linux targets,
`LockedSecretBytes<N>` uses a private anonymous mapping and `mlock` to reduce
the chance that the secret's storage reaches swap. This is a high-assurance
building block, not a complete OS secrecy guarantee. Resource limits can make
locking fail, and locked memory can still be exposed through hibernation, crash
dumps, debuggers, privileged reads, DMA, malicious firmware, or copies made
before data enters the locked container.

`SecretBytes::expose_secret_volatile` makes the volatile temporary-copy cleanup
explicit at the call site. It clears on normal return and unwinding paths, but
it is still not a solution for aborting processes.
