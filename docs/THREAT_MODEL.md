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
- Const-generic `BoundedSecretVec<MAX>` enforcement for dynamic secret input
  whose length must be limited at an application trust boundary.
- Explicit volatile helper APIs for existing ordinary buffers.
- Optional platform memory locking for `LockedSecretBytes<N>` when the
  `memory-lock` feature is enabled on supported Linux, Android, macOS, iOS,
  Windows, and BSD targets.
- Optional dynamic platform memory locking for `LockedSecretVec` when the
  `memory-lock` feature is enabled on supported native targets.
- Optional pooled platform memory locking for many same-size fixed secrets with
  `SecretPool<N, SLOTS>` when the `memory-lock` feature is enabled on supported
  targets.
- Explicit WASM API compatibility for `LockedSecretBytes<N>` and
  `SecretPool<N, SLOTS>` when both `memory-lock` and `wasm-compat` are enabled
  on `wasm32`, using volatile-only WASM-owned storage without claiming host
  memory locking.
- Optional prefix/suffix canary integrity checks for non-empty
  `LockedSecretBytes<N>` mappings, pooled slots, and guarded dynamic mappings
  when the `canary-check` feature is enabled.
- Optional Linux `MADV_DONTDUMP` on locked secret mappings to reduce ordinary
  core-dump exposure.
- Optional Linux `MADV_DONTFORK` on locked secret mappings to reduce accidental
  inheritance across `fork`.
- Optional x86_64 assembly-backed equal-length comparison when the
  `asm-compare` feature is enabled.
- Optional x86_64 volatile-clear plus cache-line eviction when the
  `cache-flush` feature is enabled.
- Optional best-effort SIMD/vector register scrubbing on x86_64 and AArch64
  when the `register-scrub` feature is enabled.
- Optional explicit three-pass volatile overwrite helpers when the
  `multi-pass-clear` feature is enabled.
- Optional N-of-N XOR split fixed-size storage when the `split-secret` feature
  is enabled.
- Optional hardware-backed provider traits when the `hardware-secrets` feature
  is enabled.
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
  stored inside native `LockedSecretBytes<N>`, `LockedSecretVec`, `SecretPool`,
  or locked `GuardedSecretVec` storage.
- Preventing host-runtime copies, swapping, snapshots, dumps, or browser memory
  inspection for WASM linear memory.
- Preventing disclosure through a debugger, `/proc/<pid>/mem`, ptrace, kernel
  compromise, DMA, malicious firmware, or privileged co-tenants.
- Revoking external copies after a secret has already been exposed to caller
  code or third-party libraries.
- Limiting `SecretVec` deserialization when callers deliberately choose the
  unbounded type, or preventing a deserializer/transport from allocating its
  own input before `BoundedSecretVec<MAX>` receives visitor control.
- Soundly scrubbing old stack frames, prior Rust move copies, all CPU
  registers, unrelated CPU cache lines, allocator metadata, or third-party
  library copies. The `register-scrub` feature is only an explicit best-effort
  current-thread SIMD/vector register clearing boundary.
- Clearing temporary stack copies after process abort. Closure helpers clear
  their temporaries on normal return and unwinding paths only; `panic = "abort"`
  and other abort paths skip destructors and post-closure cleanup.
- Cache-line flushing outside x86_64.
- Detecting corruption that changes only the secret bytes and does not reach a
  canary word.

## Design Position

The default API tries to avoid creating hard-to-clear copies in the first place.
`SecretBytes<N>` is the strongest default path because the storage is controlled
by this crate from initialization to drop. `SecretVec` and `SecretString` are
more practical for dynamic integration boundaries but still cannot control
copies made before data enters the container.

Volatile byte writes improve clearing resistance against compiler optimization,
but they do not solve broader process, OS, hardware, or allocator threats.
On WASM, this guarantee is weaker than on native targets: Rust/LLVM preserves
`ptr::write_volatile` while emitting WASM, but the WASM specification has no
volatile-memory operation. A runtime JIT or AOT compiler sees ordinary WASM
stores. The crate uses an `#[inline(never)]` function-pointer boundary on
WASM as a best-effort optimizer barrier, but this is not equivalent to native
volatile semantics. Building with WASM atomics/shared-memory support can give
runtimes stronger observable side effects, but that is a deployment property
outside this crate.

With the `multi-pass-clear` feature, the crate exposes explicit three-pass
volatile overwrite helpers using zero, `0xFF`, and zero patterns. For ordinary
volatile RAM, single-pass volatile zeroing is the normal security boundary and
is consistent with modern sanitization guidance for DRAM. Multi-pass clearing
is provided for policy, audit, or legacy compliance language such as
DoD 5220.22-M-style overwrite procedures; it should not be interpreted as
meaningfully stronger protection for live process memory.

With the `memory-lock` feature on supported Linux, Android, macOS, iOS,
Windows, and BSD targets, `LockedSecretBytes<N>` and native `LockedSecretVec`
use private platform mappings and memory locking to reduce the chance that
secret storage reaches swap or pagefiles. `SecretPool<N, SLOTS>` uses the same
backend but sub-allocates many fixed-size slots from one locked mapping,
reducing page-granule quota overhead for applications that keep many same-size
secrets. Linux also applies `MADV_DONTDUMP` and `MADV_DONTFORK` to reduce
ordinary core-dump exposure and accidental inheritance across `fork`. This is a
high-assurance building block, not a complete OS secrecy guarantee. Resource
limits or policy can make setup fail, and locked memory can still be exposed
through hibernation, nonstandard crash dump mechanisms, debuggers, privileged
reads, DMA, malicious firmware, or copies made before data enters the locked
container. Leaking a slot with `core::mem::forget` also leaks that slot's
allocation state and skips its drop-time clearing, just as leaking any
secret-owning value skips its destructor.

With both `memory-lock` and `wasm-compat` on WASM targets,
`LockedSecretBytes<N>` and `SecretPool<N, SLOTS>` are exposed as volatile-only
compatibility containers. They keep API-level code portable and still clear
their owned WASM storage on drop, but they do not call `mlock`, do not create
protected mappings, do not exclude host dumps or snapshots, and cannot prevent
the runtime from copying or moving linear memory. `memory-lock` without
`wasm-compat` is rejected at compile time on WASM to avoid silently degrading
native memory-lock expectations. `SecretPool::locked_len()` returns `0` on WASM
to avoid misrepresenting host memory as pinned. `guard-pages` is not available
on WASM because WASM linear memory has no `mprotect`-style page protection
available to the module.

With the `canary-check` feature, non-empty `LockedSecretBytes<N>` mappings,
`LockedSecretVec` mappings, and `SecretPool<N, SLOTS>` slots place an 8-byte
canary before and after the secret bytes. `GuardedSecretVec` places one canary
before the payload and one immediately after the initialized payload. Exposure,
mutation, replacement, and comparison APIs verify both canaries before reading
or modifying the secret; checked APIs return `CanaryCorruptedError`, while
legacy APIs clear the mapping or slot and panic. This can detect overwrites
that stay inside the writable mapping but reach the canary words, including
some overrun/underrun cases that do not reach a guard page. It does not detect
corruption entirely inside the secret bytes and does not provide authenticity
against an attacker who can read and rewrite the full process memory image.

By default, canary words are derived from mapping or slot addresses and a fixed
mask. This deterministic mode assumes ASLR or otherwise unpredictable mapping
addresses and is intended for blind-overwrite resistance. Disclosure of one
deterministic canary value reveals the expected value for that mapping or slot
because the mask is fixed, so an attacker who can both read and write memory can
forge the canary. Use `random-canary` when ASLR is disabled, weakened, canary
disclosure is in scope, or deterministic canaries are not acceptable for the
threat model. With `random-canary`, canaries are generated from the
operating-system CSPRNG using dependency-free platform backends. Random canaries
improve blind overwrite detection and audit posture, but they still do not
authenticate memory against an attacker who can read and rewrite both the owner
metadata and mapped canary bytes.
`strict-canary-check` is a named profile for environments where deterministic
canaries are not acceptable; it enables `random-canary` and therefore fails
construction on targets without a supported dependency-free random backend
instead of falling back to address-derived canaries.
On WASM, deterministic canaries are rejected at compile time because fallback
storage lives inline with the Rust value or pool and has no ASLR-backed mapping
address. `canary-check` on WASM must be paired with both `wasm-compat` and
`random-canary`. WASI preview1 uses `random_get`; bare
`wasm32-unknown-unknown`, Emscripten-style WASM, and WASI preview2 currently
return a `Random` operation error for random canary generation in this
dependency-free implementation.

With the `asm-compare` feature on x86_64 and AArch64, equal-length comparisons
use an inline-assembly loop. This gives the comparison body a stronger compiler
boundary, but it does not hide length metadata and does not claim protection
against all microarchitectural side channels. With `strict-ct`, unsupported
non-Miri targets fail at compile time instead of using the portable Rust
fallback. The portable fallback remains available without `strict-ct`, but it
relies on source-level data-oblivious structure plus optimizer barriers rather
than a target-specific assembly boundary.

With the `cache-flush` feature on x86_64, explicit clear-and-flush helpers
volatile-clear the target storage and then execute `clflush` over the covered
cache lines. This can evict the addressed lines from CPU caches, but it does not
prove all historical copies are gone and does not solve general
microarchitectural side channels. When combined with `guard-pages`,
`GuardedSecretVec` can explicitly clear and flush its full writable data region.
`clflush` itself is an unprivileged instruction commonly used in cache-timing
attacks such as Flush+Reload; this feature reduces post-use residency but does
not protect against an attacker who can observe cache timing while the secret is
live.

With the `register-scrub` feature, explicit helpers clear selected
current-thread SIMD/vector registers on x86_64 and AArch64. This is a local
post-crypto hygiene boundary, not proof that all register, stack, spill, kernel,
or other-thread copies have been removed. AVX-512 opmask registers, ZMM16-ZMM31,
and AArch64 V8-V15 upper halves remain outside the implemented scrub path.

With the `split-secret` feature, `SplitSecretBytes<N, SHARES>` stores a
fixed-size secret as N-of-N XOR shares. This can reduce the impact of a single
contiguous memory disclosure only when shares are placed and protected
separately by the application. It is not threshold cryptography, not Shamir
secret sharing, and depends on the caller supplying cryptographically random
mask bytes. Construction rejects trivially constant mask shares in all build
profiles, but that is only a misuse guardrail and does not validate entropy.

With the `hardware-secrets` feature, the crate exposes traits for backend
crates that integrate HSMs, TEEs, platform keystores, enclaves, or similar
providers. The core crate does not implement or certify any hardware backend.

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

On non-Linux Unix targets, locked mappings do not apply fork-inheritance
exclusion. Secret mappings are inherited by child processes after `fork`.
Applications using prefork servers or worker pools must clear secrets before
forking, isolate secret-owning work into processes created before secrets are
loaded, or use Linux if `MADV_DONTFORK`-style fork isolation is required.
FreeBSD requests core-dump exclusion with `MADV_NOCORE`; Android, macOS, iOS,
OpenBSD, NetBSD, and DragonFly BSD currently only lock resident memory and do
not apply crate-level dump exclusion.
With `require-fork-exclusion`, locked native constructors and locked guarded
constructors return a `DontFork` platform error on non-Linux targets instead of
accepting this reduced guarantee. This feature is intended for deployments
where accidental fork inheritance is an audit blocker.

`SecretBytes::expose_secret_volatile` makes the volatile temporary-copy cleanup
explicit at the call site. It clears on normal return and unwinding paths, but
it is still not a solution for aborting processes.
