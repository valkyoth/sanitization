<p align="center">
  <b>Conservative derive macros for sanitization.</b><br>
  Field-wise sanitize and native ct derives without adding dependencies to the default crate.
</p>

<div align="center">
  <a href="https://crates.io/crates/sanitization">sanitization crate</a>
  |
  <a href="https://docs.rs/sanitization-derive">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/docs/SAFETY.md">Safety</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/sanitization">
    <img src="https://raw.githubusercontent.com/valkyoth/sanitization/main/.github/images/sanitization.webp" alt="sanitization Rust crate overview">
  </a>
</p>

# sanitization-derive

Optional derive macros for the `sanitization` crate.

Use through the main crate:

```toml
sanitization = { version = "1.2.3", features = ["derive"] }
```

The derive crate only generates calls to traits from `sanitization`; it does
not implement memory wiping, comparison, or selection logic itself.

Available derives:

- `SecureSanitize`
- `SecureSanitizeOnDrop`
- `ConstantTimeEq`
- `ConditionallySelectable`

`ConstantTimeEq` and `ConditionallySelectable` are conservative field-wise
derives for structs. They never compare raw struct bytes, so they do not read
padding or representation details.

```rust
use sanitization::ct::{ConditionallySelectable as _, ConstantTimeEq as _};
use sanitization::{ConditionallySelectable, ConstantTimeEq};

#[derive(ConstantTimeEq, ConditionallySelectable)]
struct Tag {
    left: [u8; 16],
    right: [u8; 16],
}
```

`#[sanitization(skip)]` is supported for `ConstantTimeEq` when a field is public
or intentionally ignored. It is rejected for `ConditionallySelectable` because
constructing the selected output requires every field.

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

`ConstantTimeEq` and `ConditionallySelectable` reject enums. Use explicit struct
wrappers or a hand-written implementation when active-variant semantics are
intentional and reviewed.

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
