<p align="center">
  <b>Secrecy-style compatibility wrappers backed by sanitization.</b><br>
  Familiar boxed-secret APIs for incremental migration without weakening the hardened core.
</p>

<div align="center">
  <a href="https://crates.io/crates/sanitization">sanitization crate</a>
  |
  <a href="https://docs.rs/sanitization-secrecy">Docs.rs</a>
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

# sanitization-secrecy

`sanitization-secrecy` provides a migration-compatible subset of the familiar
`secrecy` 0.10 API while delegating owned-value clearing to
[`sanitization`](https://crates.io/crates/sanitization).

```toml
[dependencies]
sanitization-secrecy = "2.1.1"
```

Applications can preserve `secrecy::...` import paths with a Cargo package
alias:

```toml
[dependencies]
secrecy = { package = "sanitization-secrecy", version = "2.1.1" }
```

Legacy generic types that cannot attest stable storage can request the
explicit reduced-assurance newtype:

```toml
[dependencies]
secrecy = {
    package = "sanitization-secrecy",
    version = "2.1.1",
    features = ["hazmat-unrestricted-exposure"],
}
```

Feature activation does not weaken `SecretBox`; callers must replace it with
`UnrestrictedSecretBox` at each reduced-assurance use site.

```rust
use secrecy::{ExposeSecret, SecretString};

let token = SecretString::from("bearer-token");
assert_eq!(token.expose_secret(), "bearer-token");
```

## Supported surface

- `SecretBox<S>`
- `SecretSlice<S>` and `SecretString`
- `ExposeSecret` and `ExposeSecretMut`
- stable-storage bounds on `SecretBox` reference exposure and mutable
  initialization under every feature combination; `hazmat-unrestricted-exposure`
  adds the explicit reduced-assurance `UnrestrictedSecretBox` newtype
- `CloneableSecret`
- `SerializableSecret` behind `serde`
- bounded-by-default `SecretString` deserialization behind `serde`; generic
  `SecretBox<T>` deserialization requires the explicit
  `serde-compat-unbounded` compatibility feature
- the `secrecy::zeroize` re-export and `Zeroize`/`ZeroizeOnDrop` wrapper
  implementations through the default `zeroize-interop` feature
- `new`, `init_with_mut`, `try_init_with_mut`, `init_with`, and `try_init_with`
- final-allocation byte-slice initialization with `init_with_len`, allocation-
  fallible `try_init_with_len`, and const-bounded
  `try_init_with_len_bounded::<MAX, _>`
- data-oblivious comparison with `ct_eq`, returning a `Choice` that requires
  explicit reason-bearing declassification at the call site
- redacted `Debug` and sanitization on drop

The generic bound is `sanitization::SecureSanitize`, not
`zeroize::Zeroize`. Custom migrated types must derive or implement
`SecureSanitize`. To expose a custom type through the default build, also
implement `StableSharedSecretStorage` and, for mutable exposure or
initialization, `StableMutableSecretStorage` after reviewing all safe methods,
including interior mutation.

The clone-based `init_with` and `try_init_with` constructors additionally
require `CloneableSecret`. This is a review boundary: a custom clone must
sanitize any partially constructed destination state if cloning unwinds.
Prefer the final-allocation `init_with_mut` forms for aggregate secrets.
Automatic array authorization is restricted to arrays of the reviewed integer
primitives; a custom `Copy + CloneableSecret` element does not automatically
authorize cloning an array of that element.

For an owned `String`, conversion copies into the final box and sanitizes the
complete source capacity. `From<Vec<S>> for SecretSlice<S>` does the same for
types that explicitly implement `CloneableSecret`, including cleanup of
completed destination clones during unwinding. Use `try_from_vec_exact` for a
no-copy transfer of an exact-capacity vector whose elements are not cloneable;
an excess-capacity source is sanitized and rejected.

`SecretString` remains unconditionally cloneable for `secrecy` 0.10 source
compatibility. This is the documented exception to the `CloneableSecret`
opt-in used by other generic values.

```rust
use sanitization_secrecy::SecretString;

let expected = SecretString::from("bearer-token");
let received = SecretString::from("bearer-token");
assert!(expected
    .ct_eq(&received)
    .declassify("authentication token equality is public"));
```

## Security boundary

This is intentionally a compatibility API. Returning `&S` or `&mut S` permits
the caller to retain a borrow for its full Rust lifetime and deliberately copy
or export data. The default implementations require the corresponding core
storage-stability contract, preventing safe methods on the exposed value from
silently releasing uncleared historical storage. Enabling
`hazmat-unrestricted-exposure` only adds `UnrestrictedSecretBox`; Cargo feature
unification cannot weaken an existing `SecretBox`. The unrestricted newtype
supports arbitrary `SecureSanitize` types but can expose historical-allocation
remanence. Cloning creates another secret copy.
Implementing `SerializableSecret` explicitly permits plaintext serialization
and places serializer buffers outside this crate's clearing guarantee.

The Cargo package alias only preserves local import spelling. It does not make
these types identical to `secrecy` types named in another dependency's public
API. `SecretString` deserialization rejects values above the core crate's
1 MiB default ceiling, but that check occurs when the parser invokes the Serde
visitor; enforce parser and transport limits before allocation. Generic
`SecretBox<T>` deserialization is inherently unbounded and is therefore
available only through the plainly named `serde-compat-unbounded` feature.
Generic `try_init_with` and `try_init_with_mut` report callback errors, not
allocation failure. For runtime byte slices, `try_init_with_len` additionally
reports allocation and exact-capacity failures, while
`try_init_with_len_bounded::<MAX, _>` rejects an oversized public length before
allocation or callback execution. The infallible `init_with_len` remains only
for trusted, already-bounded lengths.

For new high-assurance code, prefer the native `sanitization` containers. They
provide scoped exposure, fixed and bounded storage, wipe-before-growth,
memory-locking policy, canaries, guard pages, and structured protection
reporting that this compatibility wrapper does not claim.
