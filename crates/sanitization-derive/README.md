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
  <a href="https://github.com/valkyoth/sanitization/blob/main/docs/MIGRATION_2.0.md">2.0 Migration</a>
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
sanitization = { version = "2.0.0", features = ["derive"] }
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

`#[sanitization(skip, reason = "...")]` is supported for `SecureSanitize` and
`ConstantTimeEq` when a field is public or intentionally ignored. The reason
must be non-empty. Skips are rejected for `ConditionallySelectable` because
constructing the selected output requires every field.

## Enums

All derives reject enums. Safe generated code can reach only the active variant
and cannot clear bytes retained from a previously active, larger variant. Use a
struct with stable secret storage and an explicit public state tag. A reviewed
manual enum implementation must call
`sanitization::secure_replace(&mut value, replacement)` before every transition.

Duplicate, malformed, empty, and misplaced helper options are rejected.
`reason` is valid only together with `skip`. Enums and unions are rejected.

## Generic `SecureSanitizeOnDrop`

For structs with type parameters that hold sanitizable data, put the
`SecureSanitize + Unpin` bounds on the struct declaration:

```rust
use sanitization::{SecureSanitize, SecureSanitizeOnDrop};

#[derive(SecureSanitize, SecureSanitizeOnDrop)]
struct Wrapper<T: SecureSanitize + Unpin> {
    inner: T,
}
```

The generated `Drop` impl cannot add a stricter bound than the struct itself.
It requires the complete struct to be `Unpin` because a destructor may receive
a logically pinned value. The destructor sanitizes non-skipped fields directly
and never invokes a manual whole-value `SecureSanitize` implementation, which
prevents self-replacement from recursively entering `Drop`.
