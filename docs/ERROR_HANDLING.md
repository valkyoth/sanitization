# Checked Error Handling

Mapped secret APIs keep one checked shape across feature combinations. An
integrity check may compile to a no-op when canaries are disabled, but exposure,
mutation, replacement, comparison, and cache operations still return `Result`.
This prevents enabling a hardening feature from changing downstream function
signatures.

These checked operations use a `try_*` prefix. Explicit `*_or_panic` helpers
encode a deliberate fail-stop application policy; libraries should normally
propagate or map the checked result. Constructors retain conventional Rust
names such as `from_slice` and `zeroed` even though platform setup can fail.

The crate deliberately does not combine integrity, capacity, UTF-8, generator,
mapping, and cache failures into one global error enum. Those errors have
different recovery policies and not every application enables every facility.
Libraries should normally map them into their own domain error at the boundary.

## Fallible Exposure Closures

A mapped byte exposure whose closure also returns `Result<T, E>` would normally
produce `Result<Result<T, E>, CanaryCorruptedError>`. Import
`SecretIntegrityResultExt` to flatten it while preserving both error classes:

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::{
    LockedSecretBytes, SecretIntegrityError, SecretIntegrityResult,
    SecretIntegrityResultExt,
};

fn parse_key(bytes: &[u8; 32]) -> Result<u8, &'static str> {
    bytes.first().copied().ok_or("empty key")
}

fn read_key(
    key: &LockedSecretBytes<32>,
) -> SecretIntegrityResult<u8, &'static str> {
    key.try_expose_secret(parse_key).flatten_secret_integrity()
}

let key = LockedSecretBytes::<32>::from_array([7; 32])?;
match read_key(&key) {
    Ok(value) => assert_eq!(value, 7),
    Err(SecretIntegrityError::Canary(_)) => {
        // Fail closed: the mapped value has been cleared or retired.
    }
    Err(SecretIntegrityError::Operation(error)) => {
        // Apply the parser's ordinary error policy.
        eprintln!("{error}");
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

`SecretIntegrityError::map_operation` maps only the operation error into an
application error while preserving canary corruption. `is_canary`,
`is_operation`, and `operation` support policy checks without nested matches.

Mapped text exposure has an outer `SecretTextIntegrityError`, because invalid
UTF-8 is an integrity condition specific to text. Map the two layers explicitly
at the application boundary:

```rust,ignore
let parsed = text
    .try_with_secret(parse_text)
    .map_err(AppError::SecretText)?
    .map_err(AppError::Parse)?;
```

This is intentionally explicit: an invalid mapped string and a parser rejection
should not silently become the same failure.

## Protection Reports

Use `Requirement::Required` for controls that must exist. Constructors then
fail instead of returning reduced-protection storage, so the report does not
need to be revalidated at every operation.

When a request contains `Preferred` controls, inspect the report once after
construction and retain the resulting application state. The convenience
method `ProtectionReport::all_requested_controls_established(request)` returns
`false` for failed or unsupported preferred controls and treats empty-storage
`NotApplicable` outcomes as fulfilled.

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::{LockedSecretBytes, ProtectionRequest};

let request = ProtectionRequest::locked();
let key = LockedSecretBytes::<32>::zeroed_with_protection(request)?;
if !key
    .protection_report()
    .all_requested_controls_established(request)
{
    return Err("a preferred runtime protection was unavailable".into());
}
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

Applications that permit reduced protection should inspect the individual
public report fields once and record the accepted deployment mode. Cargo
features only describe compiled capability; they do not replace this runtime
decision.

## Fail-Stop Helpers

Explicitly named `*_or_panic` methods remain available for binaries with a
reviewed fail-stop policy. Reusable libraries should propagate checked errors
instead. A panic can abort the current control flow, but it is not a substitute
for a process-level response policy, crash-dump controls, or monitoring.

Cache-flush errors remain separate from integrity errors because cache eviction
is an optional post-use mitigation with target-specific availability. Do not
erase that distinction merely to shorten a call site.
