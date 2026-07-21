# sanitization 2.0.2

This patch release improves Miri compatibility and strengthens mapped-memory
teardown without changing the public API.

## Miri lifecycle coverage

- Native locked containers use a private aligned-allocation model under
  `cfg(miri)` instead of executing unsupported syscall inline assembly.
- The model covers fixed, dynamic, and UTF-8 locked storage, pool allocation
  and reuse, random-canary ownership, integrity failure, quarantine, rollback,
  growth, replacement, and drop.
- Every simulated mapping is checked to be entirely zero before deallocation.

Miri does not execute or validate real `mmap`, `mlock`, dump/fork policy,
CSPRNG, page-protection, or guard-page operations. Simulated successful report
states are test state only; native target evidence remains required.

## Teardown hardening

`LockedSecretBytes`, `LockedSecretVec`, and `SecretPool` now clear the complete
mapping immediately before unlock and unmap. This includes mapping padding and
integrity metadata in addition to the secret payload.

All five workspace crates are released together at `2.0.2`, with the derive
crate exact-pinned to the matching runtime version.
