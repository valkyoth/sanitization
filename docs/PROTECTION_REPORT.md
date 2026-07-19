# Protection Requests And Reports

Mapped secret storage separates three facts that must not be conflated:

1. Cargo features compile a platform capability.
2. `ProtectionRequest` states the caller's runtime policy.
3. `ProtectionReport` records what the runtime actually established.

A feature name or successful allocation is not evidence that the operating
system accepted memory locking, dump exclusion, fork handling, guard pages, or
integrity canaries.

## Requirements

Each requested control is classified as:

- `Requirement::Required`: construction fails if unavailable or unsuccessful;
- `Requirement::Preferred`: construction may return a container with a reduced
  outcome recorded in its report; or
- `Requirement::NotRequested`: the control is intentionally omitted.

Fork handling uses `ForkProtectionRequest` because it also selects a policy:
ordinary inheritance, exclusion from the child, or zero-filled child pages.

```rust
use sanitization::{
    ForkProtectionRequest, ProtectionRequest, Requirement,
};

let request = ProtectionRequest {
    memory_lock: Requirement::Required,
    dump_exclusion: Requirement::Preferred,
    fork: ForkProtectionRequest::exclude(Requirement::Preferred),
    guard_pages: Requirement::NotRequested,
    canary: Requirement::Preferred,
    cache_policy: Requirement::NotRequested,
};
```

The predefined `locked`, `guarded`, page-sealed, profile, and WASM requests
encode documented policies. They remain requests, not runtime results.

## Construction Outcomes

Mapped constructors that accept a request return either:

- a live container retaining a `ProtectionReport`; or
- `ProtectionError`, including the failed control, structured platform error,
  and a partial report describing setup and rollback.

Failure of a required control never returns reduced live storage. Failure of a
preferred control can return storage only when the reduced outcome is visible
in its report. Callers should reject any report state their deployment policy
does not accept.

Applications that require every preferred control to have succeeded can use
`ProtectionReport::all_requested_controls_established(request)` once after
construction. The method returns `false` for failed, unsupported, or
compatibility-only preferred controls. `NotApplicable` satisfies a request for
empty storage. Applications that accept selected reduced outcomes should still
inspect the relevant report fields explicitly.

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::{LockedSecretBytes, ProtectionRequest, ProtectionState};

let secret = LockedSecretBytes::<32>::zeroed_with_protection(
    ProtectionRequest::locked(),
)?;
let report = secret.protection_report();

if report.memory_lock != ProtectionState::Established {
    return Err("deployment requires an established memory lock".into());
}
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

`ProtectionReport` contains public operational metadata only. It does not
contain secret bytes, canary values, or mapping addresses.

## Integrity Failures

With canaries enabled, ordinary mapped operations verify integrity before
exposure, mutation, copying, replacement, and comparison. A mismatch clears or
retires the affected storage and returns `CanaryCorruptedError` or
`SecretIntegrityError<E>`. Explicit `*_or_panic` helpers exist only for callers
that deliberately choose fail-stop behavior.

Do not catch an integrity error and continue using the value as if the check
were advisory. Treat the storage as untrusted and follow the method's documented
retirement or clearing behavior.

## Profiles And WASM

`profile-hardened-native`, `profile-guarded-native`, and
`profile-hardened-linux` bundle compiled capabilities and provide matching
request constructors. Their names do not certify runtime establishment.

On WASM, `wasm-compat` preserves compatible ownership APIs but cannot provide
host `mlock`, native guard pages, dump exclusion, fork policy, or native
volatile semantics across a JIT boundary. The compatibility report exposes
those reduced outcomes rather than pretending native protection succeeded.

See `docs/FEATURE_PROFILES.md`, `docs/TARGETS.md`,
`docs/NON_GUARANTEES.md`, and `docs/THREAT_MODEL.md` for the complete platform
claim. See `docs/ERROR_HANDLING.md` for concise checked-call composition.
