# sanitization-derive

Optional derive macros for the `sanitization` crate.

Use through the main crate:

```toml
sanitization = { version = "1.1.1", features = ["derive"] }
```

The derive crate only generates calls to `sanitization::SecureSanitize`; it does
not implement memory wiping itself.

## Enum Derives

Derived enum sanitization only clears the currently active variant. If code
changes a secret-bearing enum to a non-secret variant and only then calls
`secure_sanitize`, the old inactive variant bytes are outside the derive's safe
reach. Prefer struct wrappers for high-assurance state machines, or call
`sanitization::secure_replace(&mut value, replacement)` so the active variant is
sanitized before replacement.

The optional `strict-enum-derive` feature rejects enum derives unless the enum
explicitly acknowledges this limitation:

```rust
use sanitization::SecureSanitize;

#[derive(SecureSanitize)]
#[sanitization(enum_inactive_variant_bytes = "acknowledged")]
enum KeyMaterial {
    Key([u8; 32]),
    Empty,
}
```

## Generic `SecureSanitizeOnDrop`

For structs with type parameters that hold sanitizable data, put the
`SecureSanitize` bound on the struct declaration:

```rust
use sanitization::{SecureSanitize, SecureSanitizeOnDrop};

#[derive(SecureSanitize, SecureSanitizeOnDrop)]
struct Wrapper<T: SecureSanitize> {
    inner: T,
}
```

The generated `Drop` impl cannot add a stricter bound than the struct itself.
