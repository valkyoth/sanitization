# Advanced Usage

This guide is level 3 of the user journey. Start with the ordinary containers
and recommended locked constructors in the project README. Use the facilities
below only when a threat model or deployment policy requires them.

Read [`GUARANTEES.md`](GUARANTEES.md),
[`NON_GUARANTEES.md`](NON_GUARANTEES.md), and
[`THREAT_MODEL.md`](THREAT_MODEL.md) before selecting platform hardening.

## Custom Protection Policy

Cargo features compile capabilities. `ProtectionRequest` declares policy, and
`ProtectionReport` records the achieved runtime outcome.

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::{
    ForkProtectionRequest, LockedSecretBytes, ProtectionRequest, Requirement,
};

let request = ProtectionRequest {
    memory_lock: Requirement::Required,
    dump_exclusion: Requirement::Preferred,
    fork: ForkProtectionRequest::exclude(Requirement::Preferred),
    guard_pages: Requirement::NotRequested,
    canary: Requirement::Preferred,
    cache_policy: Requirement::NotRequested,
};

let key = LockedSecretBytes::<32>::zeroed_with_protection(request)?;
if !key.protection_report().satisfies(request) {
    return Err("deployment protection policy was not achieved".into());
}
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

Use named profile constructors when their policy matches the deployment. Use a
custom request only when required/preferred controls genuinely differ. See
[`PROTECTION_REPORT.md`](PROTECTION_REPORT.md) and
[`ERROR_HANDLING.md`](ERROR_HANDLING.md).

## Guard Pages

`GuardedSecretVec` and `GuardedSecretString` place inaccessible pages around a
private native mapping. Guard pages detect accesses crossing the mapped data
region; they do not detect every in-capacity overwrite or protect copies made
outside the container.

```rust,no_run
# #[cfg(feature = "profile-guarded-native")]
# {
use sanitization::GuardedSecretVec;

let mut token = GuardedSecretVec::with_capacity_guarded_native(4096)?;
token.try_extend_from_slice(b"session-key")?;
assert_eq!(token.try_constant_time_eq(b"session-key"), Ok(true));

if token.protection_report().is_degraded() {
    return Err("guarded deployment policy was not achieved".into());
}
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

Enable `canary-check` or `random-canary` when in-region prefix/suffix overwrite
detection is also required.

## Page-Sealed Fixed Secrets

`SealedSecretBytes<N>` is a review-candidate mapping whose data pages are
inaccessible between scoped accesses. Every access is fallible and requires
`&mut self`; failures may retire or poison the value.

```rust,no_run
# #[cfg(feature = "page-seal")]
# {
use sanitization::SealedSecretBytes;

let mut key = SealedSecretBytes::<32>::from_array([7; 32])?;
let first = key.try_with_secret(|bytes| bytes[0])?;
assert_eq!(first, 7);
assert!(key.is_sealed());
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

Fork policy, partial protection transitions, signal handlers, process abort,
and privileged remapping require particular review. See
[`SAFETY.md`](SAFETY.md) and [`TARGETS.md`](TARGETS.md).

## Secret CT Ownership

Use `PublicCtOption` and `PublicCtResult` only for public backing values. Use
`SecretValue`, `SecretCtOption`, and `SecretCtResult` when dummy or unselected
backing values are secret and must be cleared before declassification.

```rust
use sanitization::ct::{Choice, SecretCtOption, SecretValue};

let state = SecretCtOption::secret([7u8; 32], Choice::TRUE);
let selected = state.declassify("authenticated key selection is public");
assert_eq!(selected, Some([7u8; 32]));
```

Reason strings are searchable review labels, not runtime authorization. Run
`scripts/lint-declassification-reasons.py` in high-assurance downstream CI.

## Cache And Register Controls

`cache-flush` adds checked x86_64 cache-line eviction after volatile clearing.
It reduces post-use residency; it does not stop an attacker who can observe
cache timing while the secret is live.

`register-scrub` clears a documented architecture-specific subset of vector
registers and returns a `RegisterScrubReport`. It cannot clear compiler spills,
all callee-saved state, interrupt frames, other threads, or every AVX-512 state
component.

See [`BARRIERS.md`](BARRIERS.md) for the exact scope and
[`LEAKAGE_TESTS.md`](LEAKAGE_TESTS.md) for target timing evidence.

## Other Specialized APIs

| Requirement | API |
| --- | --- |
| Many same-size locked values under one lock quota | `SecretPool<N, SLOTS>` |
| One successful scoped access | `ConsumeOnceSecret<T>` |
| no-std expiry from application ticks | `MonotonicExpiringSecretBytes<N, C>` |
| std wall-clock-style expiry | `ExpiringSecretBytes<N>` |
| N-of-N XOR shares | `SplitSecretBytes<N, SHARES>` |
| External HSM/TEE/enclave integration | `hardware-secrets` provider traits |
| Existing RustCrypto bounds | `zeroize-interop` and `subtle-interop` |

These facilities solve different threat-model problems. Combining features is
not automatically stronger; the request/report result and target evidence must
match the deployment's actual requirements.
