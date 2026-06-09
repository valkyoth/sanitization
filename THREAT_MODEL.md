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
- Optional pooled platform memory locking for many same-size fixed secrets with
  `SecretPool<N, SLOTS>` when the `memory-lock` feature is enabled on supported
  targets.
- WASM API compatibility for `LockedSecretBytes<N>` and
  `SecretPool<N, SLOTS>` when `memory-lock` is enabled on `wasm32`, using
  volatile-only WASM-owned storage without claiming host memory locking.
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
- Optional explicit three-pass volatile overwrite helpers when the
  `multi-pass-clear` feature is enabled.
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
- Preventing host-runtime copies, swapping, snapshots, dumps, or browser memory
  inspection for WASM linear memory.
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
Windows, and BSD targets, `LockedSecretBytes<N>` uses a private platform
mapping and memory locking to reduce the chance that the secret's storage
reaches swap or pagefiles. `SecretPool<N, SLOTS>` uses the same backend but
sub-allocates many fixed-size slots from one locked mapping, reducing
page-granule quota overhead for applications that keep many same-size secrets.
Linux also applies `MADV_DONTDUMP` and `MADV_DONTFORK` to reduce ordinary
core-dump exposure and accidental inheritance across `fork`. This is a
high-assurance building block, not a complete OS secrecy guarantee. Resource
limits or policy can make setup fail, and locked memory can still be exposed
through hibernation, nonstandard crash dump mechanisms, debuggers, privileged
reads, DMA, malicious firmware, or copies made before data enters the locked
container. Leaking a slot with `core::mem::forget` also leaks that slot's
allocation state and skips its drop-time clearing, just as leaking any
secret-owning value skips its destructor.

With the `memory-lock` feature on WASM targets, `LockedSecretBytes<N>` and
`SecretPool<N, SLOTS>` are exposed as volatile-only compatibility containers.
They keep API-level code portable and still clear their owned WASM storage on
drop, but they do not call `mlock`, do not create protected mappings, do not
exclude host dumps or snapshots, and cannot prevent the runtime from copying or
moving linear memory. `SecretPool::locked_len()` returns `0` on WASM to avoid
misrepresenting host memory as pinned. `guard-pages` is not available on WASM
because WASM linear memory has no `mprotect`-style page protection available to
the module.

With the `canary-check` feature, non-empty `LockedSecretBytes<N>` mappings and
`SecretPool<N, SLOTS>` slots place an 8-byte canary before and after the secret
bytes. `GuardedSecretVec` places one canary before the payload and one
immediately after the initialized payload. Exposure, mutation, replacement, and
comparison APIs verify both canaries before reading or modifying the secret;
checked APIs return `CanaryCorruptedError`, while legacy APIs clear the mapping
or slot and panic. This can detect overwrites that stay inside the writable
mapping but reach the canary words, including some overrun/underrun cases that
do not reach a guard page. It does not detect corruption entirely inside the
secret bytes and does not provide authenticity against an attacker who can read
and rewrite the full process memory image.

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
On WASM, deterministic canaries are rejected at compile time because fallback
storage lives inline with the Rust value or pool and has no ASLR-backed mapping
address. `canary-check` on WASM must be paired with `random-canary`. WASI
preview1 uses `random_get`; bare `wasm32-unknown-unknown`, Emscripten-style
WASM, and WASI preview2 currently return a `Random` operation error for random
canary generation in this dependency-free implementation.

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

On non-Linux Unix targets, locked mappings do not apply fork-inheritance
exclusion. Secret mappings are inherited by child processes after `fork`.
Applications using prefork servers or worker pools must clear secrets before
forking, isolate secret-owning work into processes created before secrets are
loaded, or use Linux if `MADV_DONTFORK`-style fork isolation is required.
FreeBSD requests core-dump exclusion with `MADV_NOCORE`; Android, macOS, iOS,
OpenBSD, NetBSD, and DragonFly BSD currently only lock resident memory and do
not apply crate-level dump exclusion.

`SecretBytes::expose_secret_volatile` makes the volatile temporary-copy cleanup
explicit at the call site. It clears on normal return and unwinding paths, but
it is still not a solution for aborting processes.
