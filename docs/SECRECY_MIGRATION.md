# Migrating From `secrecy` 0.10

`sanitization-secrecy` provides a source-compatible subset of the familiar
`secrecy` 0.10 API while routing final owned-value cleanup through
`sanitization::SecureSanitize`.

## Release Objective

The 2.1.0 objective is deliberately finite: existing applications can alias
this package as `secrecy`, retain the boxed-secret types and exposure traits
listed below, and move cleanup ownership to `sanitization` without adding
reference-returning APIs to the hardened core containers.

This objective is complete when the compatibility surface:

- builds with and without its default `zeroize` bridge;
- supports the documented optional Serde behavior;
- clears the current boxed value on explicit clearing, unwinding, and drop;
- is exercised through a downstream Cargo package alias; and
- participates in workspace checks, Miri, archive verification, and release
  ordering.

It is not a goal to reproduce undocumented internals, support every historical
`secrecy` release, accept custom types that only implement `Zeroize`, or add
memory locking and scoped exposure to this compatibility wrapper. Those uses
belong to native `sanitization` containers or a separately scoped future
change.

## Cargo Alias

Existing `secrecy::...` imports can remain unchanged by aliasing the package:

```toml
[dependencies]
secrecy = { package = "sanitization-secrecy", version = "2.1.1" }
```

This alias changes only the dependency's local name. It does not make
`sanitization-secrecy` types interchangeable with upstream `secrecy` types in
another dependency's public signatures.

If an existing generic secret type cannot implement the stable-storage
contracts, enable the explicit unrestricted newtype only for that migration:

```toml
[dependencies]
secrecy = {
    package = "sanitization-secrecy",
    version = "2.1.1",
    features = ["hazmat-unrestricted-exposure"],
}
```

That feature does not alter `SecretBox`. Change each affected use site to
`UnrestrictedSecretBox`; safe methods reached through its returned references
may release historical storage without clearing it.

Enable plaintext serialization only where it is an explicit protocol
requirement:

```toml
[dependencies]
secrecy = {
    package = "sanitization-secrecy",
    version = "2.1.1",
    features = ["serde"],
}
```

## Supported API

| `secrecy` 0.10 API | Compatibility status |
| --- | --- |
| `SecretBox<S>` | Supported with a `SecureSanitize` bound |
| `SecretSlice<S>` | Supported |
| `SecretString` | Supported |
| `ExposeSecret` | `SecretBox` requires `StableSharedSecretStorage`; `UnrestrictedSecretBox` is available behind `hazmat-unrestricted-exposure` |
| `ExposeSecretMut` | `SecretBox` requires `StableMutableSecretStorage`; `UnrestrictedSecretBox` is available behind `hazmat-unrestricted-exposure` |
| `UnrestrictedSecretBox<S>` | Explicit reduced-assurance newtype behind `hazmat-unrestricted-exposure`; feature activation never broadens `SecretBox` |
| `CloneableSecret` | Supported with a `SecureSanitize` bound |
| `SerializableSecret` | Supported behind `serde`; `SecretString` loading has a 1 MiB default ceiling and generic loading requires `serde-compat-unbounded` |
| `new`, `init_with_mut`, `try_init_with_mut`, `init_with`, `try_init_with` | Supported |
| Runtime-length byte-slice initialization | `SecretSlice::<u8>::init_with_len`, allocation-fallible `try_init_with_len`, and const-bounded `try_init_with_len_bounded::<MAX, _>` |
| `From<Vec<S>> for SecretSlice<S>` | Supported when `S: CloneableSecret`; copies into final storage and sanitizes the source |
| Exact-capacity `Vec<S>` transfer | `SecretSlice::try_from_vec_exact`; sanitizes and rejects excess capacity |
| Data-oblivious equality | `ct_eq` returning `Choice`; declassification requires a reason literal at the call site |
| `secrecy::zeroize` re-export | Supported by the default `zeroize-interop` feature |
| `Zeroize` and `ZeroizeOnDrop` for `SecretBox` | Supported by `zeroize-interop`; delegates to `SecureSanitize` |

## Required Source Changes

The generic value bound changes from `zeroize::Zeroize` to
`sanitization::SecureSanitize`. Primitive values, arrays, slices, `String`,
`Vec`, and other built-in sanitizable values work directly. Custom types that
only implement `Zeroize` must derive or manually implement `SecureSanitize`.
`SecretBox` reference exposure additionally requires the reviewed
`StableSharedSecretStorage` or `StableMutableSecretStorage` contract. Legacy
generic code that cannot provide that attestation can explicitly enable
`hazmat-unrestricted-exposure` and migrate affected values to
`UnrestrictedSecretBox`, accepting that safe interior or mutable operations
may release uncleared allocations. Because this is a separate type, Cargo
feature unification cannot downgrade `SecretBox` elsewhere in the graph.

Enable the derive macro when using the derived form shown below:

```toml
[dependencies]
sanitization = { version = "2.1.1", features = ["derive"] }
secrecy = { package = "sanitization-secrecy", version = "2.1.1" }
```

```rust
use sanitization::SecureSanitize;
use secrecy::{ExposeSecret, SecretBox};

#[derive(SecureSanitize)]
struct Credentials {
    token: [u8; 32],
}

let secret = SecretBox::new(Box::new(Credentials { token: [7; 32] }));
let credentials = secret.expose_secret();
let first = credentials.token[0];
# let _ = first;
```

`ExposeSecret::expose_secret` returns an ordinary reference rather than
running a closure. Existing closure-based calls must therefore be changed to a
borrow, while code that already used the `secrecy` trait shape remains the
same.

Do not replace an upstream comparison with ordinary equality over exposed
references. The compatibility wrappers expose the core data-oblivious path:

```rust
use secrecy::SecretString;

let expected = SecretString::from("token");
let received = SecretString::from("token");
let accepted = expected
    .ct_eq(&received)
    .declassify("authentication result is public");
assert!(accepted);
```

## Security Classification

The compatibility wrapper guarantees redacted `Debug` and sanitization of its
currently boxed value on explicit clearing and drop. `SecretBox` exposure also
requires the matching stable-storage contract under every feature combination.
It does not guarantee:

- closure-confined exposure;
- containment of deliberate copies or exports made through an exposed
  reference;
- wipe-before-growth for operations reached through
  `UnrestrictedSecretBox`;
- cleanup of allocations released before the value entered companion-owned
  construction;
- memory locking, dump/fork exclusion, canaries, guard pages, or page sealing;
- cleanup of clones or serialized plaintext after they leave the wrapper.

`init_with_mut`, `try_init_with_mut`, `SecretSlice::<u8>::init_with_len`, and
`try_init_with_len` initialize final boxed storage and are preferred.
Use `try_init_with_len_bounded::<MAX, _>` whenever the runtime length crosses
an untrusted boundary: it rejects an oversized length before allocation and
distinguishes public-length/allocation failures from initializer failures.
`try_init_with_len` reports allocation refusal but deliberately has no policy
ceiling; `init_with_len` is for trusted, already-bounded lengths only.
`init_with` and `try_init_with` necessarily clone a temporary and therefore
require `CloneableSecret`; the temporary is held in a sanitizing unwind guard
in this implementation. The marker is a security contract: a custom clone
must sanitize any partially constructed destination state if cloning unwinds,
because the wrapper cannot recover state discarded inside arbitrary `Clone`
code. Prefer the final-allocation mutable initializers for aggregate secrets.
`try_init_with` and the other fallible initializers report callback errors;
they do not generally convert allocation failure into `Result`. The runtime
slice `try_init_with_len` family is the explicit exception and reports its
allocation outcomes through `SecretSliceInitError`.

Owned `String` conversion copies into final boxed storage and sanitizes the
source's complete allocation capacity. `From<Vec<S>>` uses the same guarded
copy strategy and therefore requires `S: CloneableSecret`; completed clones
are sanitized if a later clone unwinds. A custom `CloneableSecret`
implementation remains responsible for partial secret state created inside
its own panicking `Clone` implementation. `try_from_vec_exact` provides a
no-copy path for any `S: SecureSanitize` and sanitizes then rejects a
non-exact-capacity source.

`SecretString` remains unconditionally cloneable for source compatibility;
this is an intentional exception to the generic `CloneableSecret` opt-in.
Automatic `CloneableSecret` array implementations are limited to arrays of
reviewed integer primitives. A custom `Copy` implementation can still contain
a manually panicking `Clone`, so authorizing a custom element does not
implicitly authorize its array representation.

The optional Serde implementation limits `SecretString` to the core crate's
1 MiB default ceiling. Apply transport/parser limits before deserialization:
parser buffers created before the visitor hands over its completed `String`
remain outside this wrapper's ownership. Prefer native
`BoundedSecretString<MAX>` when the secret storage type must enforce a smaller
permanent byte ceiling. Generic `SecretBox<T>` deserialization cannot enforce a
universal size policy and is available only through the explicit
`serde-compat-unbounded` compatibility feature.

For new code, prefer native `sanitization` containers. Use this companion when
incremental source migration or an existing `ExposeSecret` trait bound is the
primary requirement.
