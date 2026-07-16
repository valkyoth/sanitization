# Non-Guarantees

This document states what `sanitization` does not claim. These limits are part
of the security model, not fine print.

## Timing And Microarchitecture

The crate does not guarantee exact identical wall-clock timing. It also does
not guarantee complete protection against every microarchitectural channel,
including:

- cache contention during the secret's active lifetime;
- branch predictor effects outside the provided primitives;
- SMT sibling observation;
- transient execution attacks;
- power, EM, thermal, or frequency side channels;
- hardware instructions with data-dependent latency on targets where that has
  not been reviewed.

The stronger claim for the native `ct` module is narrower: the provided
primitives try to avoid secret-dependent control flow and secret-dependent
memory access under documented target, feature, compiler, and release-profile
conditions.

UTF-8 validation, serde size-limit rejection, and variable-length mismatch
handling are not included in that claim. UTF-8 validators may stop at the first
invalid byte, and length checks may return immediately. Text validity and
variable lengths must therefore be public metadata. Protocols that need to hide
those properties should use a fixed-size representation and perform any
necessary validation outside the secret-dependent path.

## Arbitrary Caller Code

The crate cannot make arbitrary closures or third-party cryptographic
implementations data-oblivious. If caller code branches, indexes, allocates,
formats, panics, divides, performs floating-point operations, or calls external
APIs based on secret data, that behavior is outside the crate's guarantee.

Exposure closures are a boundary of responsibility. Keep them small and avoid:

- branching on secret bytes;
- indexing by secret bytes;
- early returns from secret-derived failure;
- secret-dependent allocation sizes or iterator lengths;
- formatting/logging/debug printing secrets;
- panics whose path depends on secret data;
- floating point on secrets;
- division/modulo on secrets unless the target has been reviewed.

## Compiler, Profile, And Runtime Limits

The crate's strongest data-oblivious claims are for documented release
profiles and targets. Debug builds may introduce instrumentation, overflow
checks, assertions, or code shape that is not representative of release
behavior.

`core::hint::black_box` is a useful optimizer barrier but is not a
cryptographic guarantee. The crate treats it as one component of a broader
barrier and evidence strategy, not as proof by itself.

Miri cannot execute or validate the native OS facilities behind memory locking,
private mappings, page protection, dump/fork policy, or guard pages. Native
tests are required to exercise those platform paths.

Kani performs bounded functional verification and treats configured harnesses
sequentially. It does not model real thread scheduling, concurrent atomic
interleavings, or concurrent kernel behavior. A passing Kani run is not a proof
of concurrency correctness.

WASM has special limits. Rust/LLVM preserves volatile writes while emitting
WASM, but the WASM specification has no volatile-memory instruction. Browser
and Node JIT runtimes may optimize the generated native code again. For WASM,
the crate provides API compatibility and best-effort clearing, not strong
native-equivalent clearing or timing claims.

## Process, OS, And Hardware Limits

The crate does not protect against:

- privileged reads such as debuggers, `ptrace`, `/proc/<pid>/mem`, kernel
  compromise, hypervisor compromise, or administrative crash dump tools;
- DMA, malicious firmware, physical bus probing, or cold-boot attacks after the
  platform has already exposed memory;
- hibernation files or platform snapshots outside the crate's control;
- host runtime copies of WASM linear memory;
- logs, tracing systems, telemetry, panic messages, or formatters that receive
  secret bytes;
- external copies made before data enters a crate-owned container.

Memory locking reduces swap/pagefile exposure for the crate's owned locked
storage when the OS accepts the lock. It does not make RAM unreadable to the OS
or to privileged attackers.

A compiled feature or successful mapping allocation does not prove that every
requested control was established. Callers must inspect `ProtectionReport`.
Even a report showing established locking, dump exclusion, an exclude or
wipe-child fork policy, and guard pages does not cover hibernation, privileged
reads, hypervisor snapshots, DMA, firmware, or every platform-specific
crash-dump mechanism.

## Rust Move And Stack History

Rust moves may copy bytes. The crate tries to reduce avoidable copies by using
owned containers, closure exposure, in-place transforms, and replacement APIs,
but it does not soundly scrub old stack frames or all historical move copies.

For the highest assurance, construct secrets directly inside crate-owned
containers, use in-place APIs, keep exposure closures small, and avoid passing
secret material through ordinary temporary arrays, strings, or vectors.

## Serialization And Interop

Serde support serializes secret-owning types as redacted strings. Deserializing
into the crate's own leaf secret types keeps ingestion on the secret-aware path.
For generic `Secret<T>` or `ReadOnceSecret<T>`, secrecy during deserialization
depends on `T`'s own `Deserialize` implementation and any intermediate buffers
it creates.
`SecretVec` and `SecretString` use 1 MiB default serde ceilings.
Use `BoundedSecretVec<MAX>` or `BoundedSecretString<MAX>` at untrusted dynamic
boundaries that require a protocol-specific limit, while retaining transport
and parser limits. The crate's limit takes effect only when the deserializer
calls its visitor; a parser may already have allocated or copied the input.

Moving an owned `String` into `SecretString` transfers that allocation without
copying, but it cannot clear JSON input buffers, parser scratch allocations, or
other copies created before the string reaches the secret container.

Optional `zeroize`, `subtle`, `arrayvec`, and `bytes` interop is feature-gated
and exists to fit existing ecosystems. It does not extend this crate's
guarantees to the internals of those third-party crates.
