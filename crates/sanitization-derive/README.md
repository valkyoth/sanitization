# sanitization-derive

Optional derive macros for the `sanitization` crate.

Use through the main crate:

```toml
sanitization = { version = "1.0.0", features = ["derive"] }
```

The derive crate only generates calls to `sanitization::SecureSanitize`; it does
not implement memory wiping itself.

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
