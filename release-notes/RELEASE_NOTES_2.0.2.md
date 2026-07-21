# sanitization 2.0.2

This patch release improves Miri compatibility and strengthens mapped-memory
teardown without changing the public API.

## Miri lifecycle coverage

- Native locked containers use a private aligned-allocation model only under
  `cfg(all(miri, test))`, in the core crate's own unit-test build, instead of
  executing unsupported syscall inline assembly.
- The model covers fixed, dynamic, and UTF-8 locked storage, pool allocation
  and reuse, random-canary ownership, integrity failure, quarantine, rollback,
  growth, replacement, and drop.
- Every simulated mapping is checked to be entirely zero before deallocation.

Miri does not execute or validate real `mmap`, `mlock`, dump/fork policy,
CSPRNG, page-protection, or guard-page operations. Simulated successful report
states are test state only; native target evidence remains required. A normal
build with `--cfg miri` does not select the simulator. Downstream Miri tests
that execute native mapped constructors remain unsupported and should
target-gate those paths.

The same condition now protects every production comparison, AArch64
page-size, cache-flush, register-scrub, guard-page, and interop cfg boundary. A
release gate statically rejects Miri behavior switches without `test` and
compiles a normal release library with a manually supplied `--cfg miri` to
guard against recurrence.

The full Miri workflow runs all-feature mapped lifecycle coverage as core
library unit tests and runs derive and companion integrations with portable
comparison features. This preserves their interpreter coverage without making
native production dependencies select a simulator.

## Teardown hardening

`LockedSecretBytes`, `LockedSecretVec`, and `SecretPool` now clear the complete
mapping immediately before unlock and unmap. This includes mapping padding and
integrity metadata in addition to the secret payload.

`SealedSecretBytes` no longer unmaps pages when cleanup cannot confirm that
every page is writable and erased. It retains the poisoned mapping and any
established lock for checked retry; `Drop` deliberately leaves that mapping to
process teardown rather than returning unwiped physical pages to the operating
system.

Mapped native and `subtle` equality traits now fail closed with a false choice
on integrity failure instead of selecting an implicit panic policy. Checked
`try_constant_time_eq` remains the API for distinguishing canary corruption
from ordinary inequality. Miri now compiles and exercises the locked dynamic
and UTF-8 zeroize/subtle interop implementations.

All five workspace crates are released together at `2.0.2`, with the derive
crate exact-pinned to the matching runtime version.

The fuzz-only NCSA exception for `libfuzzer-sys 0.4.13` is now held in a
fuzz-specific cargo-deny configuration, avoiding unmatched exceptions in the
runtime and tooling dependency graphs.
